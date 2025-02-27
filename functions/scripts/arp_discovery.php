<?php

/**
 * This script does the following:
 *              - fetches all subnets that are marked for discovering new hosts
 *              - Scans each subnet with SNMP for new hosts
 *              - If new host is discovered it will be added to database with mac address and it will update existing hosts 
 *

 *

 *
 *      Script must be run from cron, here is a crontab example, 1x/day should be enough:
 *              0 1 * * *  /usr/local/bin/php /<sitepath>/functions/scripts/arp_discovery.php > /dev/null 2>&1
 *
 *
 *      In case of problems set reset_debugging to true
 *
 *      If running from a remote agent machine, pass "agent" as the only arg to this script; in this case it will fetch
 *      the agent ID of the configured agent (as identified by the key configured in config.php) and use that in subsequent
 *      calls. If omitted, the localhost agent (ID 1) is used.
 * 
 *      Original credit for this goes to zmilicevic from the following post:
 * 
 *      https://github.com/phpipam/phpipam/issues/2378#issuecomment-821066449
 * 
 *      Modified by David Willis, June 2024.
 */

# include required scripts
require_once(dirname(__FILE__) . '/../functions.php');

if ((!isset($argv[1])) || ((isset($argv[1])) && ($argv[1] != "agent"))) {
	# Only needed for the full phpIPAM, not the agent
	require(dirname(__FILE__) . '/../classes/class.Thread.php');
}

/*
 * Discover new hosts with snmp
 *******************************/

# set class
$Snmp = new phpipamSNMP();

// no errors
error_reporting(E_ERROR);
// for debugging
//error_reporting(E_ALL);

print "error reporting set!\n";

# initialize objects
$Database       = new Database_PDO;
$Subnets        = new Subnets($Database);
$Addresses      = new Addresses($Database);
$Tools          = new Tools($Database);
$Scan           = new Scan($Database);
$DNS            = new DNS($Database);
$Result         = new Result();

if ((isset($argv[1])) && ($argv[1] == "agent")) {
	// agent mode was specified, so fetch the agent ID
	// initialize and make default checks
	$phpipam_agent = new phpipamAgent($Database);

	// validate connection and fetch agent ID
	$phpipam_agent->mysql_init();
	$agentId = $phpipam_agent->agent_details->id;
	print "Agent ID set! Operating with remote agent ID {$agentId}...\n";
} else {
	// running in localhost mode; use agent ID 1
	$agentId = 1;
	print "Agent ID set! Operating with localhost agent ID 1...\n";
}

print "objects initialized!\n";

// for debugging
//$Scan->set_debugging(true);

// change scan type?
if (@$config['discovery_check_method'])
	$Scan->reset_scan_method($config['discovery_check_method']);

# Check if scanning has been disabled
if ($Scan->icmp_type == "none") {
	$Result->show("danger", _('Scanning disabled') . ' (scanPingType=None)', true, true);
}

// set ping statuses
$statuses = explode(";", $Scan->settings->pingStatus);
// set mail override flag
if (!isset($config['discovery_check_send_mail'])) {
	$config['discovery_check_send_mail'] = true;
}

// set now for whole script
$now     = time();
$nowdate = date("Y-m-d H:i:s");

// response for mailing
$address_change = array();                      // Array with differences, can be used to email to admins
$hostnames      = array();                      // Array with detected hostnames


print "fetching subnets...\n";


//first fetch all subnets to be scanned
$scan_subnets = $Subnets->fetch_all_subnets_for_discoveryCheck($agentId);
//set addresses
if ($scan_subnets !== false) {
	// initial array
	$addresses_tmp = array();
	// loop
	foreach ($scan_subnets as $i => $s) {
		// if subnet has slaves dont check it
		if ($Subnets->has_slaves($s->id) === false) {
			$addresses_tmp[$s->id] = $Scan->prepare_addresses_to_scan("discovery", $s->id, false);
			// save discovery time
			$Scan->update_subnet_discoverytime($s->id, $nowdate);
		} else {
			unset($scan_subnets[$i]);
		}
	}

	//reindex
	if (sizeof($addresses_tmp) > 0) {
		foreach ($addresses_tmp as $s_id => $a) {
			foreach ($a as $ip) {
				$addresses[] = array("subnetId" => $s_id, "ip_addr" => $ip);
			}
		}
	}
}

//if($Scan->get_debugging()==true)                                { print_r($scan_subnets); }
if ($scan_subnets === false || !count($scan_subnets)) {
	die("No subnets are marked for new hosts checking\n");
}

$z = 0;                 //addresses array index

// let's just reindex the subnets array to save future issues
$scan_subnets   = array_values($scan_subnets);
$size_subnets   = count($scan_subnets);
$size_addresses = max(array_keys($addresses));

# reinitialize objects
$Database       = new Database_PDO;
$Admin          = new Admin($Database, false);
$Addresses      = new Addresses($Database);
$Subnets        = new Subnets($Database);
$DNS            = new DNS($Database);
$Scan           = new Scan($Database);
$Result         = new Result();

foreach ($scan_subnets as $s) {
	// fetch subnet
	//$Scan->set_debugging(true);

	$subnet = $Subnets->fetch_subnet("id", $s->id);

	// fetch all hosts to be scanned
	$all_subnet_hosts = (array) $Addresses->fetch_subnet_addresses($s->id);
	//if($Scan->get_debugging()==true)                                { print_r($all_subnet_hosts); }
	// execute only if some exist
	//if (sizeof($all_subnet_hosts)>0) {
	// set default statuses
	foreach ($all_subnet_hosts as $h) {
		$result[$h->ip_addr] = (array) $h;
		$result[$h->ip_addr]['code'] = 1;
		$result[$h->ip_addr]['status'] = "Offline";
	}

	# fetch devices that use get_routing_table query
	$devices_used = array();
	$devices_used = $Tools->fetch_multiple_objects("devices", "snmp_queries", "%get_arp_table%", "id", true, true);

	# filter out not in this section

	$permitted_devices = array();

	if ($devices_used !== false) {
		foreach ($devices_used as $d) {
			// get possible sections
			$permitted_sections = explode(";", $d->sections);
			// check
			if (in_array($subnet->sectionId, $permitted_sections)) {
				$permitted_devices[] = $d;
			}
		}
	}

	// if none set die
	if (!isset($permitted_devices)) {
		$Result->show("danger", "No devices for SNMP ARP query available", true);
	}
	//if($Scan->get_debugging()==true)                                { print_r($permitted_devices); }
	// ok, we have devices, connect to each device and do query
	foreach ($permitted_devices as $d) {
		// Subnet details can be obtained via $subnet and device details via $d after this point.
		// All DB fields are valid fields to reference.
		// init
		//$Scan->set_debugging(true);
		$Snmp->set_snmp_device($d);
		print "Scanning subnet {$subnet->description} ({$Subnets->transform_address($subnet->subnet, "dotted")}/{$subnet->mask}) on device {$d->hostname}...\n";
		// execute
		try {
			$res = $Snmp->get_query("get_arp_table");
			//if($Scan->get_debugging()==true)                                { print_r($res); }
			// remove those not in subnet
			if (is_array($res) && sizeof($res) > 0) {
				// save for debug
				//$debug[$d->hostname]["get_arp_table"] = $res;
				$tblSize = sizeof($res);
				print "Found {$tblSize} hosts in the ARP table to evaluate...\n";
				// check
				foreach ($res as $kr => $r) {
					if ($Subnets->is_subnet_inside_subnet($r['ip'] . "/32", $Subnets->transform_address($subnet->subnet, "dotted") . "/" . $subnet->mask) === true) {
						if (array_key_exists($Subnets->transform_address($r['ip'], "decimal"), $result)) {
							// existing hosts
							print "Found existing host {$r['ip']} in subnet {$subnet->description} (MAC address: {$r['mac']}); updating status...\n";

							// for debugging only
							//$Scan->set_debugging(true);
							//if($Scan->get_debugging()==true)                                { print "Old IP:"; }
							//if($Scan->get_debugging()==true)                                { print_r($r['ip']); }
							//if($Scan->get_debugging()==true)                                { print "\n"; }
							// end debugging

							// add to alive
							$result[$Subnets->transform_address($r['ip'], "decimal")]['code'] = 0;
							$result[$Subnets->transform_address($r['ip'], "decimal")]['status'] = "Online";

							// for debugging only
							//if($Scan->get_debugging()==true)                               { print "MAC:"; }
							//if($Scan->get_debugging()==true)                               { print_r($r['mac']); }
							//if($Scan->get_debugging()==true)                                { print "\n"; }
							// end debugging

							// update alive time
							// We use the original function here instead of the new one because we have the patch from
							// myrandor installed that implements saving the MAC via ping_update_lastseen().
							@$Scan->ping_update_lastseen($result[$Subnets->transform_address($r['ip'], "decimal")]['id'], null, $r['mac']);
							// Added per nbartokos, update MAC addresses
							//@$Scan->ping_update_mac($result[$Subnets->transform_address($r['ip'], "decimal")]['id'], $r['mac']);
						} else {
							// insert new hosts with mac address
							print "Found new host {$r['ip']} in subnet {$subnet->description} (MAC address: {$r['mac']}); adding...\n";
							$result[$Subnets->transform_address($r['ip'], "decimal")]['code'] = 0;
							$result[$Subnets->transform_address($r['ip'], "decimal")]['status'] = "Online";
							// Need to save the ID of the newly-inserted row so we can use it to retrieve the value later;
							// we modified insert_mac() to return this ID so we can store it here.
							$newId = 0;
							$newId = @$Scan->insert_mac(($Subnets->transform_address($r['ip'], "decimal")), $r['mac'], $s->id);
							//@$Scan->ping_update_lastseen($result[$Subnets->transform_address($r['ip'], "decimal")]['id'], null, $r['mac']);
							@$Scan->ping_update_lastseen($newId, null, $r['mac']);
							
							// for debugging
							//if($Scan->get_debugging()==true)                                { print "New IP:"; }
							//if($Scan->get_debugging()==true)                                { print_r($r['ip']); }
							//if($Scan->get_debugging()==true)                                { print "\n"; }
							//if($Scan->get_debugging()==true)                               { print "MAC:"; }
							//if($Scan->get_debugging()==true)                               { print_r($r['mac']); }
							//if($Scan->get_debugging()==true)                                { print "\n"; }
							// end debugging
						}
					}
				}
			}
			$found[$d->id] = $res;
		} catch (Exception $e) {
			$Result->show("danger", "<pre>" . _("Error") . ": " . $e . "</pre>", false);
			//die();
			// continue on error; don't die
			print "Error scanning device {$d->hostname}; skipping...\n";
			continue;
		}
	}

	//}    

	# Update subnet scan time
	$Scan->update_subnet_scantime($s->id, $nowdate);
}

# update scan time
$Scan->ping_update_scanagent_checktime($agentId, $nowdate);
