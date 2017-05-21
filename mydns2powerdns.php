<?PHP
/*

	Simple script for migrating MyDNS Data to PowerDNS
	(c) 2015 Tomas Simek <tomas@simek.info>
	
	This stuff is Released under GPLv2 License


*/
function read_config($path) {
	$cfgs=file_get_contents($path);
	if(!$cfgs) die("config file $path unreadable or empty\n");
	eval($cfgs);
	if (!isset($cfg)) die("parse of config file failed\n");
	return($cfg);
}
$cfg=read_config("config-inc.php");

echo "opening src mydns db...\n";
if (!$cfg['mydns_host'] && !$cfg['mydns_user'] && !$cfg['mydns_pass'] && !$cfg['mydns_db']) die ("one of mydns_host, mydns_user, mydns_pass, mydns_db not in config file");
if (!$cfg['pdns_host'] && !$cfg['pdns_user'] && !$cfg['pdns_pass'] && !$cfg['pdns_db']) die ("one of pdns_host, pdns_user, pdns_pass, pdns_db not in config file");

$mytp=$cfg['mydns_tbl_prefix'];
$ptp=$cfg['pdns_tbl_prefix'];



$md = mysqli_connect($cfg['mydns_host'], $cfg['mydns_user'], $cfg['mydns_pass'], $cfg['mydns_db']);
if (!$md) die("mydns db could not be open");

$pd = mysqli_connect($cfg['pdns_host'], $cfg['pdns_user'], $cfg['pdns_pass'], $cfg['pdns_db']);
if (!$pd) die("powerdns db could not be open");


echo "storing SOA records...\n";
if (!$soas=$md->query("SELECT * FROM $mytp"."soa ORDER BY id")) die("unable to fetch domains: $md->error\n");
while ($soa=$soas->fetch_object()) {
	$soa->origin=preg_replace("/\.$/", '',  $soa->origin);
	$sql="INSERT INTO domains SET id=$soa->id, name='$soa->origin';";
	echo "$sql\n";
	if (!$pd->query($sql)) die("can't store domain ID record $soa->origin: $pd->error\n");
	$sql="INSERT INTO records SET domain_id=$soa->id, name='$soa->origin', type='SOA', content='$soa->ns $soa->mbox $soa->serial $soa->refresh $soa->retry $soa->expire $soa->ttl';";
	echo "$sql\n";
	if (!$pd->query($sql)) die("can't store domain SOA data $soa->origin: $pd->error\n");	
}

echo "storing RR records\n";
if (!$rrs=$md->query("SELECT $mytp"."rr.*, $mytp"."soa.origin FROM $mytp"."rr LEFT JOIN $mytp"."soa ON $mytp"."rr.zone=$mytp"."soa.id ORDER BY zone,id")) 
	die("unable to fetch rr: $md->error\n");
while ($rr=$rrs->fetch_object()) {
//print_r($rr);
	$rr->origin=preg_replace("/\.$/", '',  $rr->origin);
	$rr->name=preg_replace("/\.$/", '',  $rr->name);
	if ($rr->name) $rr->name.=".$rr->origin"; else $rr->name="$rr->origin";
//print_r($rr);	
	switch ($rr->type) {
		case 'TXT':
			$rr->data="\"$rr->data\"";
			break;
		case 'CNAME':
		case 'MX':
		case 'NS':
		case 'SRV':
			if (!preg_match("/\.$/", $rr->data))
				$rr->data.='.'.$rr->origin;
			break;
	}

	$sql="INSERT INTO records SET domain_id=$rr->zone, name='$rr->name', type='$rr->type', content='$rr->data', ttl=$rr->ttl, prio='$rr->aux', change_date=UNIX_TIMESTAMP();";
	echo "$sql\n";
	if (!$pd->query($sql)) die("can't store domain SOA data $soa->origin: $pd->error\n");	
}
echo "all done\n";

?>
