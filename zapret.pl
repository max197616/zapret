#!/usr/bin/perl -w

use strict;
use warnings;
use File::Basename 'dirname';
use File::Spec;
use lib join '/',File::Spec->splitdir(dirname(__FILE__));
use Zapret;
use SOAP::Lite;
use DBI;
use Data::Dumper;
use MIME::Base64;
use utf8;
use XML::Simple qw(:strict);
use URI 1.69;
use NetAddr::IP;
use Digest::MD5 qw(md5_hex);
use Encode qw(encode_utf8);
use Net::SMTP;
use POSIX;
use POSIX qw(strftime);
use Config::Simple;
use File::Basename;
use Net::IP qw(:PROC);
use AnyEvent;
use AnyEvent::DNS;
use Log::Log4perl;
use Getopt::Long;
use URI::UTF8::Punycode;
use File::Path qw(make_path);
use File::Copy;
use Email::MIME;

$XML::Simple::PREFERRED_PARSER = 'XML::Parser';

binmode(STDOUT,':utf8');
binmode(STDERR,':utf8');


######## Config #########

my $openssl_bin_path="/usr/local/gost-ssl/bin";

my $dir = File::Basename::dirname($0);
my $Config = {};

my $config_file=$dir.'/zapret.conf';
my $force_load='';
my $log_file=$dir."/zapret_log.conf";

GetOptions("force_load" => \$force_load,
	    "log=s" => \$log_file,
	    "config=s" => \$config_file) or die "Error no command line arguments\n";

Config::Simple->import_from($config_file, $Config) or die "Can't open ".$config_file." for reading!\n";

Log::Log4perl::init( $log_file );

my $logger=Log::Log4perl->get_logger();

my $api_url = $Config->{'API.url'} || die "API.url not defined.";
my $req_file = $Config->{'PATH.req_file'} || die "PATH.req_file not defined.";
$req_file = $dir."/".$req_file;
my $sig_file = $Config->{'PATH.sig_file'} || die "PATH.sig_file not defined.";
$sig_file = $dir."/".$sig_file;
my $template_file = $Config->{'PATH.template_file'} || die "PATH.template_file not defined.";
$template_file = $dir."/".$template_file;
my $archive_path = $Config->{'PATH.archive'} || "";

my $db_host = $Config->{'DB.host'} || die "DB.host not defined.";
my $db_user = $Config->{'DB.user'} || die "DB.user not defined.";
my $db_pass = $Config->{'DB.password'} || die "DB.password not defined.";
my $db_name = $Config->{'DB.name'} || die "DB.name not defined.";

my $soap = new Zapret($api_url);

my $resolve = $Config->{'NS.resolve'} || 0;

my @resolvers = $Config->{'NS.resolvers'} || ();


my @resolvers_new;

foreach my $n (@{$resolvers[0]})
{
	push(@resolvers_new,AnyEvent::Socket::parse_address($n));
}

my $ipv6_nslookup = $Config->{'NS.ipv6_support'} || 0;
if(lc($ipv6_nslookup) eq "true" || lc($ipv6_nslookup) eq "yes")
{
	$ipv6_nslookup=1;
} else {
	$ipv6_nslookup=0;
}

my $keep_resolved = $Config->{'NS.keep_resolved'} || 0;
if(lc($keep_resolved) eq "yes" || lc($keep_resolved) eq "true")
{
	$keep_resolved=1;
} else {
	$keep_resolved=0;
}

my $dns_timeout = $Config->{'NS.timeout'} || 1;
$dns_timeout = int($dns_timeout) if($dns_timeout);


my $mail_send = $Config->{'MAIL.send'} || 0;

my $mails_to = $Config->{'MAIL.to'} || die "MAIL.to not defined.";
my @mail_to;
if(ref($mails_to) ne "ARRAY")
{
	push(@mail_to, $mails_to);
} else {
	@mail_to = @{$mails_to};
}
my $smtp_auth = $Config->{'MAIL.auth'} || 0;
my $smtp_from = $Config->{'MAIL.from'} || die "MAIL.from not defined.";
my $smtp_host = $Config->{'MAIL.server'} || die "MAIL.server not defined.";
my $smtp_port = $Config->{'MAIL.port'} || die "MAIL.port not defined.";
my $smtp_login = $Config->{'MAIL.login'} || "";
my $smtp_password = $Config->{'MAIL.password'} || "";

my $mail_excludes = $Config->{'MAIL.excludes'} || 0;
my $mail_new = $Config->{'MAIL.new'} || 0;
my $mail_new_ips = $Config->{'MAIL.new_ips'} || 0;
my $mail_removed = $Config->{'MAIL.removed'} || 0;
my $mail_removed_ips = $Config->{'MAIL.removed_ips'} || 0;
my $mail_alone = $Config->{'MAIL.alone'} || 0;

my $form_request = $Config->{'API.form_request'} || 0;

my $our_blacklist = $Config->{'PATH.our_blacklist'} || "";

my $ldd_iterations = 0;

######## End config #####

my $DBH;
my ($lastDumpDateOld, $lastAction, $lastCode, $lastResult);
dbConnect();
getParams();

my %NEW = ();
my %OLD = ();
my %OLD_ONLY_IPS = ();
my %OLD_DOMAINS = ();
my %OLD_URLS = ();
my %OLD_SUBNETS = ();
my %OLD_TRUE = ();
my %OLD_TRUE_ONLY_IPS = ();
my %OLD_TRUE_DOMAINS = ();
my %OLD_TRUE_URLS = ();
my %OLD_TRUE_SUBNETS = ();
my %EX_IPS = ();
my %EX_DOMAINS = ();
my %EX_SUBNETS = ();

my %ZAP_OLD_IPS;
my %ZAP_OLD_TRUE_IPS;

my %resolver_cache;

my $MAILTEXT = '';
my $MAIL_ADDED = '';
my $MAIL_ADDED_IPS = '';
my $MAIL_REMOVED = '';
my $MAIL_REMOVED_IPS = '';
my $MAIL_EXCLUDES = '';
my $MAIL_ALONE = '';


my $resolved_domains_ipv4=0;
my $resolved_domains_ipv6=0;
my $deleted_old_domains=0;
my $deleted_old_urls=0;
my $deleted_old_ips=0;
my $deleted_old_only_ips=0;
my $deleted_old_subnets=0;
my $deleted_old_records=0;
my $added_ipv4_ips=0;
my $added_ipv6_ips=0;
my $added_domains=0;
my $added_urls=0;
my $added_subnets=0;
my $added_records=0;

$logger->debug("Last dump date:\t".$lastDumpDateOld);
$logger->debug("Last action:\t".$lastAction);
$logger->debug("Last code:\t".$lastCode);
$logger->debug("Last result:\t".$lastResult);

#############################################################

my $start_time=localtime();

$logger->info("Starting RKN at ".$start_time);

if( $lastResult eq 'send' )
{
	$logger->info("Last request is send, waiting for the data...");
	while (getResult())
	{
		$logger->info("Reestr not yet ready. Waiting...");
		sleep(10);
	}
	$logger->info("Stopping RKN at ".(localtime()));
	exit 0;
}

if(checkDumpDate())
{
	sendRequest();

	while (getResult())
	{
		$logger->info("Reestr not yet ready. Waiting...");
		sleep(5);
	}
}

$logger->info("Stopping RKN at ".(localtime()));

exit 0;

sub getResult
{
	$logger->debug("Getting result...");

	my @result;
	eval
	{
		@result = $soap->getResult( $lastCode );
	};

	if( $@ )
	{
		$logger->fatal("Error while getResult(): ".$@);
		exit;
	}

	if( !@result )
	{
		$logger->fatal("Result not defined!");
		$logger->error( Dumper( @result ));
		exit;
	}

	if( !($result[0] eq 'true' ) )
	{
		# Some error
		my $comment = $result[1];
		$logger->error("Can not get result: ".$comment);
		# This is utf-8:
		if( $result[2] == 0 )
		{
			return 1;
		} else {
			set('lastResult', 'err');
			set('lastAction', 'getResult');
			exit;
		}
	} else {
		unlink $dir.'/dump.xml';
		unlink $dir.'/dump.xml.sig';
		my $zip = decode_base64($result[1]);

		my $file = "arch.zip";
		my $tm=time();
		if($archive_path)
		{
			$file = strftime "arch-%Y-%m-%d-%H_%M_%S.zip", localtime($tm);
		}

		open F, '>'.$dir."/".$file || die "Can't open $dir/$file for writing!\n".$! ;
		binmode F;
		print F $zip;
		close F;
		`unzip -o $dir/$file -d $dir/`;
		if($archive_path)
		{
			my $apath = strftime "$archive_path/%Y/%Y-%m/%Y-%m-%d", localtime($tm);
			make_path($apath);
			copy($dir."/".$file,$apath."/".$file);
			unlink $dir."/".$file;
		}

		$logger->debug("Got result, parsing dump.");

		set('lasltAction', 'getResult');
		set('lastResult', 'got');
		set('lastDumpDate', time);

		parseDump($dir.'/dump.xml');
		# статистика
		$logger->info("Load iterations: ".$ldd_iterations.", resolved domains ipv4: ".$resolved_domains_ipv4.", resolved domains ipv6: ".$resolved_domains_ipv6);
		$logger->info("Added: domains: ".$added_domains.", urls: ".$added_urls.", IPv4 ips: ".$added_ipv4_ips.", IPv6 ips: ".$added_ipv6_ips.", subnets: ".$added_subnets.", records: ".$added_records);
		$logger->info("Deleted: old domains: ".$deleted_old_domains.", old urls: ".$deleted_old_urls.", old ips: ".$deleted_old_ips.", old only ips: ".$deleted_old_only_ips.", old subnets: ".$deleted_old_subnets.", old records: ".$deleted_old_records);
	}
	return 0;
}


sub checkDumpDate
{
	$logger->debug("Checking dump date...");
	my $lastDumpDate = getLastDumpDate();
	$logger->debug("RKN last dump date: ".$lastDumpDate);
	if( $lastDumpDateOld eq '' || $lastDumpDate > $lastDumpDateOld || $force_load)
	{
		$logger->debug("lastDumpDate > prev. dump date. Working now.");
		return 1;
	}
	$logger->info("lastDumpDate <= prev. dump date. Exiting.");
	return 0;
}

sub getLastDumpDate
{
	$ldd_iterations++;
	my @result;
	eval {
		@result=$soap->getLastDumpDateEx();
	};
	if( $@ ) {
		$logger->error("Error while getLastDumpDate: ".$@);
		if( $ldd_iterations < 4 ) {
			$logger->info("Retrying...");
			return getLastDumpDate();
		} else {
			$logger->fatal("3 attempts failed, giving up");
			exit;
		}
	}

	if( !@result ) {
		$logger->error("Soap result not defined, retrying...");
		if( $ldd_iterations < 4 ) {
			return getLastDumpDate();
		} else {
			$logger->fatal("3 attempts failed, giving up.");
			exit;
		}
	}

	if( !defined($result[0]) || $result[0] !~ /^(\d+)$/ ) {
		$logger->error("Can't get lastDumpDateEx!");
		$logger->error(print Dumper(@result));
		if( $ldd_iterations < 4 ) {
			$logger->info("Retrying...");
			return getLastDumpDate();
		} else {
			$logger->fatal("3 attempts failed, giving up.");
			exit;
		}
	} else {
		my $stamp = $result[0] / 1000;
		return $stamp;
	}
}

sub formRequest
{
	my $now = time();
	my $tz = strftime("%z", localtime($now));
	$tz =~ s/(\d{2})(\d{2})/$1:$2/;
	my $dt = strftime("%Y-%m-%dT%H:%M:%S", localtime($now)) . $tz;
	
	my $buf = '';
	my $new = '';
	open TMPL, "<", $template_file or die "Can't open ".$template_file." for reading!\n";
	while( <TMPL> ) {
		my $line = $_;
		$line =~ s/\{\{TIME\}\}/$dt/g;
		$new .= $line;
	}
	close TMPL;
	
	open REQ, ">", $req_file;
	print REQ $new;
	close REQ;
	
	`$openssl_bin_path/openssl smime -sign -in $req_file -out $sig_file -binary -signer $dir/cert.pem -outform DER`;
}

sub sendRequest
{
	$logger->debug( "Sending request...");

	if( $form_request == 1 )
	{
		formRequest();
	}

	my @result = $soap->sendRequest($req_file,$sig_file);

	my $res = $result[0];
	if( $res eq 'true' ) {
		# Everyhing OK
		$lastCode = $result[2];
		$logger->debug("Got code: ".$lastCode);
		set('lastCode', $lastCode);
		set('lastAction', 'sendRequest');
		set('lastActionDate', time );
		set('lastResult', 'send');
		return 1;
	} else {
		# Something goes wrong
		my $code = $result[1];
		$logger->debug("ERROR while sending request: ".$code);
		set('lastResult', 'err');
		die;
	}
}


sub dbConnect
{
	$DBH = DBI->connect_cached("DBI:mysql:database=".$db_name.";host=".$db_host, $db_user, $db_pass,{mysql_enable_utf8 => 1}) or die DBI->errstr;
	$DBH->do("set names utf8");
}

sub set
{
	my $param = shift;
	my $value = shift;
	my $sth = $DBH->prepare("UPDATE zap2_settings SET value = ? WHERE param = ?");
	$sth->bind_param(1, $value);
	$sth->bind_param(2, $param);
	$sth->execute or die DBI->errstr;
}

sub getParams
{
	my $sth = $DBH->prepare("SELECT param,value FROM zap2_settings");
	$sth->execute or die DBI->errstr;
	while( my $ips = $sth->fetchrow_hashref() )
	{
		my $param=$ips->{param};
		my $value=$ips->{value};
		if($param eq 'lastDumpDate')
		{
			$lastDumpDateOld = $value;
		}
		if($param eq 'lastAction')
		{
			$lastAction = $value;
		}
		if($param eq 'lastCode')
		{
			$lastCode = $value;
		}
		if($param eq 'lastResult' )
		{
			$lastResult = $value;
		}
	}
}

sub parseContent
{
	my $content = shift;
	my ( $decision_number, $decision_org, $decision_date, $entry_type, $include_time, $block_type );
	$decision_number = $decision_org = $decision_date = $entry_type = '';
	my $decision_id = $content->{id};
	$entry_type = '';

	$decision_number = $content->{decision}->{number} if defined( $content->{decision}->{number} );
	$decision_org = $content->{decision}->{org} if defined( $content->{decision}->{org} );
	$decision_date = $content->{decision}->{date} if defined( $content->{decision}->{org} );
	$entry_type = $content->{entryType} if defined( $content->{entryType} );
	$include_time = $content->{includeTime} if defined( $content->{includeTime} );

	$block_type = $content->{blockType} if(defined($content->{blockType}));

	my %item = (
		'entry_type'	=> $entry_type,
		'decision_num'	=> $decision_number,
		'decision_id'	=> $decision_id,
		'decision_date'	=> $decision_date,
		'decision_org'	=> $decision_org,
		'include_time'	=> $include_time,
		'block_type'	=> $block_type
	);

	my @domains = ();
	my @urls = ();
	my @ips = ();
	my @subnets = ();
	my $blockType=defined($content->{blockType}) ? $content->{blockType} : "default";
	# Domains
	if( defined( $content->{domain} ) )
	{
		if(ref($content->{domain}) eq 'ARRAY')
		{
			foreach my $domain (@{$content->{domain}})
			{
				if(ref($domain) eq 'HASH')
				{
					push @domains, $domain->{content};
				} else {
					push @domains, $domain;
				}
			}
		} elsif (ref($content->{domain}) eq 'HASH')
		{
			push @domains, $content->{domain}->{content};
		} else {
			push @domains, $content->{domain};
		}
	}
	$item{'domains'} = \@domains;

	# URLs
	if( defined( $content->{url} ) )
	{
		if( ref($content->{url}) eq 'ARRAY' )
		{
			foreach my $url (@{$content->{url}})
			{
				if(ref($url) eq 'HASH')
				{
					push @urls, $url->{content};
				} else {
					push @urls, $url;
				}
			}
		} elsif (ref($content->{url}) eq 'HASH')
		{
			push @urls, $content->{url}->{content};
		} else {
			push @urls, $content->{url};
		}
	}
	$item{'urls'} = \@urls;

	# IPs
	if( defined( $content->{ip} ) )
	{
		if( ref($content->{ip}) eq 'ARRAY' )
		{
			foreach my $ip (@{$content->{ip}})
			{
				if(ref($ip) eq 'HASH')
				{
					push @ips, $ip->{content};
				} else {
					push @ips, $ip;
				}
			}
		} elsif(ref($content->{ip}) eq 'HASH')
		{
			push @ips, $content->{ip}->{content};
		} else {
			push @ips, $content->{ip};
		}
	}
	$item{'ips'} = \@ips;

	# Subnets
	if( defined( $content->{ipSubnet} ) )
	{
		if( ref($content->{ipSubnet}) eq 'ARRAY' )
		{
			foreach my $subnet ( @{$content->{ipSubnet}} )
			{
				if(ref($subnet) eq 'HASH')
				{
					push @subnets, $subnet->{content};
				} else {
					push @subnets, $subnet;
				}
			}
		} elsif (ref($content->{ipSubnet}) eq 'HASH')
		{
			push @subnets, $content->{ipSubnet}->{content};
		} else {
			push @subnets, $content->{ipSubnet};
		}
	}
	$item{'subnets'} = \@subnets;

	$NEW{$decision_id} = \%item;
}

sub parseDump
{
	my $xml_file = shift;
	$logger->debug("Parsing dump from file '$xml_file'...");

	my $xml = new XML::Simple;
	my $data = $xml->XMLin($xml_file, ForceArray=> 0, KeyAttr => {});

	if($data->{formatVersion} ne $RKN_DUMP_VERSION)
	{
		$logger->error("Incompatible dump version $data->{formatVersion}. Exiting");
		Mail("Incompatible dump version $data->{formatVersion}", "zapret alert!");
		exit 1;
	}
	my $ref_type = ref($data->{content});
	eval {
		if($ref_type eq 'ARRAY')
		{
			foreach my $arr (@{$data->{content}})
			{
				parseContent($arr);
			}
		} elsif ($ref_type eq 'HASH')
		{
			parseContent($data->{content});
		}
	};
	$logger->error("Eval error: ".$@) if $@;

	# Dump parsed.
	# Get old data from DB
	getOld();

	my $resolver = AnyEvent::DNS->new(timeout => [$dns_timeout], max_outstanding => 50, server => \@resolvers_new); # создаём резолвер с нужными параметрами

	my $cv = AnyEvent->condvar;

	processNew($resolver,$cv);

	proceedOurBlacklist($resolver,$cv) if($our_blacklist ne "");

	if($resolve == 1)
	{
		$logger->debug("Wait while all resolvers finished");

		$cv->recv;
	}

	clearOld();
	processMail();
	
	set('lastAction', 'getResult');
	set('lastResult', 'got');
	set('lastDumpDate', time() );
}

# Cleanup old entries
sub clearOld
{
	foreach my $domain ( keys %OLD_TRUE_DOMAINS ) {
			delDomain( $OLD_TRUE_DOMAINS{$domain}[0], $OLD_TRUE_DOMAINS{$domain}[1] );
			$deleted_old_domains++;
#			$logger->debug("Deleting domain id ".$OLD_TRUE_DOMAINS{$domain}[0]." ( ".$OLD_TRUE_DOMAINS{$domain}[1]." )");
	}
	foreach my $url ( keys %OLD_TRUE_URLS ) {
			$deleted_old_urls++;
			delUrl( $OLD_TRUE_URLS{$url}[0], $OLD_TRUE_URLS{$url}[1] );
#			$logger->debug("Deleting url id ".$OLD_TRUE_URLS{$url}[0]." (".$OLD_TRUE_URLS{$url}[1].")");
	}

	foreach my $record_id (keys %ZAP_OLD_TRUE_IPS)
	{
		foreach my $ip ( keys %{$ZAP_OLD_TRUE_IPS{$record_id}} )
		{
			$deleted_old_ips++;
			$logger->debug("Deleting ip $ip for record_id $record_id with id ".$ZAP_OLD_TRUE_IPS{$record_id}{$ip});
			delIp($ZAP_OLD_TRUE_IPS{$record_id}{$ip}, $ip);
		}
	}

	foreach my $ip ( keys %OLD_TRUE_ONLY_IPS ) {
			$deleted_old_only_ips++;
			delIpOnly( $OLD_TRUE_ONLY_IPS{$ip}[0], $OLD_TRUE_ONLY_IPS{$ip}[1] );
	}

	foreach my $net ( keys %OLD_TRUE_SUBNETS ) {
			$deleted_old_subnets++;
			delSubnet( $OLD_TRUE_SUBNETS{$net}[0], $OLD_TRUE_SUBNETS{$net}[1] );
	}

	foreach my $item ( keys %OLD_TRUE ) {
			$deleted_old_records++;
			#print $OLD_TRUE{$item}->{id};
#			$logger->debug("Deleting decision record of id ".$OLD_TRUE{$item}->{id});
			delRecord($OLD_TRUE{$item}->{id});
	}
}

sub processNew {
	my $resolver = shift;
	my $cv = shift;
	my $sth;
    eval {
	# Content items:
	foreach my $d_id ( keys %NEW ) {
		
		my $record_id = 0;
		if( !defined( $OLD{$d_id} ) )
		{
			# New record
			$sth = $DBH->prepare("INSERT INTO zap2_records(decision_id,decision_date,decision_num,decision_org,include_time,entry_type) VALUES(?,?,?,?,?,?)");
			$sth->bind_param(1, $d_id );
			$sth->bind_param(2, $NEW{$d_id}->{decision_date} );
			$sth->bind_param(3, $NEW{$d_id}->{decision_num} );
			$sth->bind_param(4, $NEW{$d_id}->{decision_org} );
			$sth->bind_param(5, $NEW{$d_id}->{include_time} );
			$sth->bind_param(6, $NEW{$d_id}->{entry_type} );
			$sth->execute;
			$record_id = $sth->{mysql_insertid};
			$OLD{$d_id} = $record_id;
			$MAIL_ADDED .= "Added new content: id ".$record_id."\n";
			$logger->debug("Added new content: id ".$record_id);
			$added_records++;
		} else {
			delete $OLD_TRUE{$d_id};
			$record_id = $OLD{$d_id}->{id};
		}

		# URLs
		my $processed_urls=0;
		if( ref($NEW{$d_id}->{urls}) eq 'ARRAY' )
		{
			foreach my $url ( @{$NEW{$d_id}->{urls}} )
			{
				$processed_urls++;
				# Check for ex. domain
				my $uri = URI->new($url);
				my $scheme = $uri->scheme();
				if($scheme ne "http" && $scheme ne "https")
				{
					$logger->warn("Unsupported scheme in the url: $url");
				} else {
					my $url_domain = $uri->host();
					#my @res = ( $url =~ m!^(?:http://|https://)?([^(/|\?)]+)!i );
					#my $url_domain = $res[0];
					if( defined( $EX_DOMAINS{$url_domain} ) ) {
	#					binmode(STDOUT, ':utf8');
	#					print "EXCLUDE DOMAIN ".$url_domain." (URL ".$url.")\n";
						$MAIL_EXCLUDES .= "Excluding URL (caused by excluded domain ".$url_domain."): ".$url."\n";
						next;
					}
					Resolve( $url_domain, $record_id, $resolver, $cv) if($resolve == 1);
				}
				
				
				if( !defined( $OLD_URLS{md5_hex(encode_utf8($url))} ) ) {
#				    binmode(STDOUT, ':utf8');
#				    print "New URL: ".encode_utf8($url)."\n";
#				    print "MD5 hex: ".md5_hex(encode_utf8($url))."\n";
				    $sth = $DBH->prepare("INSERT INTO zap2_urls(record_id, url) VALUES(?,?)");
				    $sth->bind_param(1, $record_id);
				    $sth->bind_param(2, $url);
				    $sth->execute;
				    $OLD_URLS{md5_hex(encode_utf8($url))} = 1;
				    $MAIL_ADDED .= "Added new URL: ".$url."\n";
				    $logger->debug("Added new URL: ".$url);
				    $added_urls++;
				} else {
					# delete from old_true_urls
					delete $OLD_TRUE_URLS{md5_hex(encode_utf8($url))};
				}
			}
		}
		my $need_to_block_domain=0;
		if(!$processed_urls)
		{
			$logger->debug("Item $d_id hasn't defined URL, must block by DOMAIN");
			$need_to_block_domain=1;
		}
		
		my $processed_domains=0;
		# Domain items:
		if( ref($NEW{$d_id}->{domains}) eq 'ARRAY' && $need_to_block_domain)
		{
			foreach my $domain( @{$NEW{$d_id}->{domains}} )
			{
				# Check for excludes
				if( defined( $EX_DOMAINS{$domain} ) ) {
	#				print "EXCLUDE DOMAIN: ".$domain."\n";
					$MAIL_EXCLUDES .= "Excluding domain: ".$domain."\n";
					$logger->debug("Excluding domain: ".$domain);
					next;
				}
				$processed_domains++;
				if($resolve == 1)
				{
					if($domain =~ /^\*\./)
					{
						$logger->info("Skip to resolve domain '$domain' because it masked");
					} else {
						Resolve( $domain, $record_id, $resolver, $cv );
					}
				}
				if( !defined( $OLD_DOMAINS{md5_hex(encode_utf8($domain))} ) )
				{
#					print "New domain: ".$domain."\n";
					$sth = $DBH->prepare("INSERT INTO zap2_domains(record_id, domain) VALUES(?,?)");
					$sth->bind_param(1, $record_id);
					$sth->bind_param(2, $domain);
					$sth->execute;
					$OLD_DOMAINS{md5_hex(encode_utf8($domain))} = 1;
					$MAIL_ADDED .= "Added new domain: ".$domain."\n";
					$logger->debug("Added new domain: ".$domain);
					$added_domains++;
				} else {
					delete $OLD_TRUE_DOMAINS{md5_hex(encode_utf8($domain))};
				}
			}
		}
		my $need_to_block_ip=0;
		if(!$processed_urls && !$processed_domains)
		{
			$logger->debug("Item $d_id hasn't url and domain, need to block by IP");
			$need_to_block_ip=1;
		}

		# IPS
		if( ref($NEW{$d_id}->{ips}) eq 'ARRAY' )
		{
			foreach my $ip ( @{$NEW{$d_id}->{ips}} )
			{
				if($need_to_block_ip)
				{
					if( !defined( $OLD_ONLY_IPS{$ip} ) )
					{
						my $ipa = new Net::IP($ip);
						my $ip_packed=pack("B*",$ipa->binip());
						$sth = $DBH->prepare("INSERT INTO zap2_only_ips(record_id, ip) VALUES(?,?)");
						$sth->bind_param(1, $record_id);
						$sth->bind_param(2, $ip_packed);
						$sth->execute;
						$OLD_ONLY_IPS{$ipa->ip()} = 1;
						$MAIL_ADDED_IPS .= "Added new ONLY IP: ".$ipa->ip()."\n";
						$logger->debug("New ONLY ip: ".$ipa->ip());
					} else {
						delete $OLD_TRUE_ONLY_IPS{$ip};
					}
					next;
				}
				my $exclude = 0;
				# Check excluded nets
				for my $subnet (keys %EX_SUBNETS) {
					my $ipadr = NetAddr::IP->new( $ip );
					my $net = NetAddr::IP->new( $subnet );
					if( $ipadr && $net ) {
						if( $ipadr->within($net) ) {
#							print "Excluding ip ".$ip.": overlaps with excluded subnet ".$subnet."\n";
							$MAIL_EXCLUDES .= "Excluding ip ".$ip.": overlaps with excluded subnet ".$subnet."\n";
							$logger->debug("Excluding ip ".$ip);
							$exclude = 1;
							last;
						}
					}
				}
				next if( $exclude == 1 );
				
				# Check for ex. ip
				if( defined($EX_IPS{$ip}) )
				{
#					print "Excluding ip ".$ip.": match excluded ip in DB.\n";
					$MAIL_EXCLUDES .= "Excluding ip ".$ip.": match excluded ip in DB.\n";
					$logger->debug("Excluding ip ".$ip);
					next;
				}
				
				if( !defined( $ZAP_OLD_IPS{$record_id}{$ip} ) )
				{
#					print "New ip: ".$ip."\n";
					my $ipa = new Net::IP($ip);
					my $ip_packed=pack("B*",$ipa->binip());
					$sth = $DBH->prepare("INSERT INTO zap2_ips(record_id, ip, resolved) VALUES(?,?,0)");
					$sth->bind_param(1, $record_id);
					$sth->bind_param(2, $ip_packed);
					$sth->execute;
					$ZAP_OLD_IPS{$record_id}{$ipa->ip()} = 1;
					$MAIL_ADDED_IPS .= "Added new IP: ".$ipa->ip()." for id $record_id\n";
					$logger->debug("New ip: ".$ipa->ip());
					if($ipa->version() == 4)
					{
						$added_ipv4_ips++;
					} else {
						$added_ipv6_ips++;
					}
				} else {
					delete $ZAP_OLD_TRUE_IPS{$record_id}{$ip};
				}
			}
		}

		# Subnets
		if( ref($NEW{$d_id}->{subnets}) eq 'ARRAY' )
		{
			foreach my $subnet ( @{$NEW{$d_id}->{subnets}} )
			{
				my $exclude = 0;
				# Check for excludes. Ips:
				for my $ip (keys %EX_IPS)
				{
#					print $ip."\n";
					my $ipadr = NetAddr::IP->new( $ip );
					my $net = NetAddr::IP->new( $subnet );
					if( $ipadr && $net ) {
						if( $ipadr->within($net) ) {
#							print "Exclude subnet ".$subnet.": contains excluded IP ".$ip."\n";
							$MAIL_EXCLUDES .= "Excluding subnet ".$subnet.": contains excluded ip ".$ip."\n";
							$logger->debug("Excluding subnet ".$subnet);
							$exclude = 1;
						}
					}
				}
				# And nets:
				for my $net (keys %EX_SUBNETS)
				{
					my $net1 = NetAddr::IP->new( $net );
					my $net2 = NetAddr::IP->new( $subnet );
					if( $net1 && $net2 ) {
						if( $net1->within( $net2 ) || $net2->within( $net1 ) ) {
#							print "Exclude subnet ".$subnet.": overlaps with excluded net ".$net."\n";
							$MAIL_EXCLUDES .= "Excluding subnet ".$subnet.": overlaps with excluded net ".$net."\n";
							$exclude = 1;
							$logger->debug("Excluding subnet ".$subnet);
							last;
						}
					}
				}
				
				if( $exclude == 1 ) {
					next;
				}
				
				if( !defined( $OLD_SUBNETS{$subnet} ) )
				{
#					print "New subnet: ".$subnet."\n";
					$sth = $DBH->prepare("INSERT INTO zap2_subnets(record_id, subnet) VALUES(?,?)");
					$sth->bind_param(1, $record_id);
					$sth->bind_param(2, $subnet);
					$sth->execute;
					$OLD_SUBNETS{$subnet} = 1;
					$MAIL_ADDED .= "Added new subnet: ".$subnet."\n";
					$logger->debug("Added new subnet: ".$subnet);

					# Check, if there no any othere parameters in this content
					if(
						( !defined($NEW{$d_id}->{domains}) || ref($NEW{$d_id}->{domains}) ne 'ARRAY' || scalar(@{$NEW{$d_id}->{domains}}) == 0 )
						&&
						( !defined($NEW{$d_id}->{urls}) || ref($NEW{$d_id}->{urls}) ne 'ARRAY' || scalar(@{$NEW{$d_id}->{urls}}) == 0 )
					) {
						$MAIL_ALONE .= "Alert! Subnet ".$subnet." added without any domain/url!\n";
					}
					$added_subnets++;
				} else {
					delete $OLD_TRUE_SUBNETS{$subnet};
				}
			}
		}
		
	}
    };
	$logger->error("Eval: ".$@) if $@;
}

sub proceedOurBlacklist
{
	my $resolver = shift;
	my $cv = shift;
	my %OLD_BLACKLIST;
	my %OLD_BLACKLIST_DEL;
	my $sth;
	eval {
		# filling old records...
		$sth = $DBH->prepare("SELECT id,decision_num FROM zap2_records WHERE decision_id = 0 ORDER BY date_add");
		$sth->execute or die DBI->errstr;
		while( my $ips = $sth->fetchrow_hashref() )
		{
			$OLD_BLACKLIST{$ips->{decision_num}}=$ips->{id};
			$OLD_BLACKLIST_DEL{$ips->{decision_num}}=$ips->{id};
		}

		my $record_id;

		open (my $fh, $our_blacklist);
		while (my $url = <$fh>)
		{
			chomp $url;
			my $md_hex=md5_hex(encode_utf8($url));
			if(defined $OLD_BLACKLIST{$md_hex})
			{
				$record_id=$OLD_BLACKLIST{$md_hex};
				delete $OLD_BLACKLIST_DEL{$md_hex};
			} else {
				$sth = $DBH->prepare("INSERT INTO zap2_records(decision_num,decision_org,decision_id) VALUES(?,?,?)");
				$sth->bind_param(1,$md_hex);
				$sth->bind_param(2,"our_blacklist");
				$sth->bind_param(3,0);
				$sth->execute;
				$record_id = $sth->{mysql_insertid};
				$OLD_BLACKLIST{$md_hex}=$record_id;
				$MAIL_ADDED .= "Added new content from our blacklist: id ".$record_id."\n";
				$logger->debug("Added new content from our blacklist: id ".$record_id);
				$added_records++;
			}
			my $uri = URI->new($url);
			my $scheme = $uri->scheme();
			if($scheme ne "http" && $scheme ne "https")
			{
				$logger->error("Unsupported scheme in url: $url for resolving.");
			} else {
				my $url_domain = $uri->host();
				if( defined( $EX_DOMAINS{$url_domain} ) )
				{
					$MAIL_EXCLUDES .= "Excluding URL (caused by excluded domain ".$url_domain."): ".$url."\n";
					next;
				}
				Resolve( $url_domain, $record_id, $resolver, $cv);
			}
			if( !defined( $OLD_URLS{md5_hex(encode_utf8($url))} ) ) {
				$sth = $DBH->prepare("INSERT INTO zap2_urls(record_id, url) VALUES(?,?)");
				$sth->bind_param(1, $record_id);
				$sth->bind_param(2, $url);
				$sth->execute;
				$OLD_URLS{md5_hex(encode_utf8($url))} = 1;
				$MAIL_ADDED .= "Added new URL: ".$url."\n";
				$logger->debug("Added new URL: ".$url);
				$added_urls++;
			} else {
				# delete from old_true_urls
				delete $OLD_TRUE_URLS{md5_hex(encode_utf8($url))};
			}
		}
		close $fh;

		# delete old records..
		foreach my $key (keys %OLD_BLACKLIST_DEL)
		{
			$deleted_old_records++;
			delRecord($OLD_BLACKLIST_DEL{$key});
		}
	};
	$logger->error("proceedOurBlackkist: ".$@) if $@;
}

sub getOld {
	%OLD = ();
	%OLD_ONLY_IPS = ();
	%OLD_DOMAINS = ();
	%OLD_SUBNETS = ();
	%OLD_URLS = ();
	%OLD_TRUE = ();
	%OLD_TRUE_ONLY_IPS = ();
	%OLD_TRUE_DOMAINS = ();
	%OLD_TRUE_SUBNETS = ();
	%OLD_TRUE_URLS = ();

	# Contents
	my $sth = $DBH->prepare("SELECT id,date_add,decision_id,decision_date,decision_num,decision_org,include_time FROM zap2_records WHERE decision_id > 0 ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		my %item = (
			'id' => $$ref[0],
			'date_add' => $$ref[1],
			'decision_id' => $$ref[2],
			'decision_date' => $$ref[3],
			'decision_num' => $$ref[4],
			'decision_org' => $$ref[5],
			'include_time' => $$ref[6]
		);
		$OLD{$$ref[2]} = \%item;
		$OLD_TRUE{$$ref[2]} = \%item;
	}
	
	# Domains
	$sth = $DBH->prepare("SELECT record_id, domain, id FROM zap2_domains ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_DOMAINS{md5_hex(encode_utf8($$ref[1]))} = $$ref[0];
		@{$OLD_TRUE_DOMAINS{md5_hex(encode_utf8($$ref[1]))}} = ( $$ref[2], $$ref[1], $$ref[0] );
	}
	
	# URLs
	$sth = $DBH->prepare("SELECT id,record_id,url FROM zap2_urls ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_URLS{md5_hex(encode_utf8($$ref[2]))} = $$ref[0];
		@{$OLD_TRUE_URLS{md5_hex(encode_utf8($$ref[2]))}} = ( $$ref[0], $$ref[2], $$ref[1] );
	}
	
	# Subnets
	$sth = $DBH->prepare("SELECT record_id, subnet, id FROM zap2_subnets ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_SUBNETS{$$ref[1]} = $$ref[0];
		@{$OLD_TRUE_SUBNETS{$$ref[1]}} = ( $$ref[2], $$ref[1] );
	}
	
	# Ips
	$sth = $DBH->prepare("SELECT ip, record_id, id, resolved FROM zap2_ips ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ips = $sth->fetchrow_hashref() )
	{
		my $old_ip=get_ip($ips->{ip});
		$ZAP_OLD_IPS{$ips->{record_id}}{$old_ip}=$ips->{id};
		next if($keep_resolved == 1 && $ips->{resolved} eq "1"); # skeep to delete resolved ips
		$ZAP_OLD_TRUE_IPS{$ips->{record_id}}{$old_ip}=$ips->{id};
	}

	# ONLY ips
	$sth = $DBH->prepare("SELECT ip, record_id, id FROM zap2_only_ips ORDER BY date_add");
	# todo добавить поддержку ipv6
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref )
	{
		my $old_ip=get_ip($$ref[0]);
		$OLD_ONLY_IPS{$old_ip} = $$ref[1];
		@{$OLD_TRUE_ONLY_IPS{$old_ip}} = ( $$ref[2], $old_ip );
	}
	
	# Excludes
	$sth = $DBH->prepare("SELECT subnet FROM zap2_ex_nets");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_SUBNETS{$$ref[0]} = 1;
	}
	$sth = $DBH->prepare("SELECT inet_ntoa(ip) FROM zap2_ex_ips");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_IPS{$$ref[0]} = 1;
	}
	$sth = $DBH->prepare("SELECT domain FROM zap2_ex_domains");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_DOMAINS{$$ref[0]} = 1;
	}
}

sub Resolve
{
	my $domain = shift;
	my $record_id = shift;
	my $resolvera = shift || undef;
	my $cv=shift || undef;

	if( $resolve != 1 ) {
		return;
	}

	if(defined $resolver_cache{md5_hex(encode_utf8($domain))})
	{
		$logger->debug("Domain $domain already resolved");
		return;
	}
	$resolver_cache{md5_hex(encode_utf8($domain))}=1;
	resolve_async($cv,$domain,$resolvera,$record_id);
}

sub Mail
{
	my $text = shift;
	my $subj = shift || "zapret update!";
	foreach (@mail_to)
	{
		eval {
			my $to = $_;
			my $smtp = Net::SMTP->new($smtp_host.':'.$smtp_port, Debug => 0) or do { $logger->error( "Can't connect to the SMTP server: $!"); return; };
	
			eval {
			    require MIME::Base64;
			    require Authen::SASL;
			} or do { $logger->error( "Need MIME::Base64 and Authen::SASL to do smtp auth."); return; };
			
			
			if( $smtp_auth eq '1' )
			{
				if( $smtp_login eq '' || $smtp_password eq '' )
				{
					$logger->debug("ERROR! SMTP Auth is enabled, but no login and password defined!");
					return;
				}
				$smtp->auth($smtp_login, $smtp_password) or do {$logger->error( "Can't auth on smtp server: $!"); return; };
			}
			$smtp->mail( $smtp_from );
			$smtp->recipient( $to );
			my $email = Email::MIME->create(
				header_str => [ From => $smtp_from, To => $to, Subject => $subj],
				attributes => {
					content_type => "text/plain",
					charset      => "UTF-8",
					encoding     => "quoted-printable"
				},
				body_str => $text
			);
			$smtp->data();
			$smtp->datasend($email->as_string());
			$smtp->dataend();
			$smtp->quit;
		};
		$logger->error("Email send error: $@") if $@;
	}
}

sub delDomain {
	my $id = shift;
	my $domain = shift;
	
	$logger->debug("Removing domain ".$domain." (id ".$id.")");
	$MAIL_REMOVED .= "Removed domain ".$domain." (id ".$id.")\n";
	
	my $sth = $DBH->prepare("DELETE FROM zap2_domains WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub delUrl {
	my $id = shift;
	my $url = shift;

	$logger->debug("Removing URL ".$url." (id ".$id.")");
	$MAIL_REMOVED .= "Removed URL ".$url." (id ".$id.")\n";
	
	my $sth = $DBH->prepare("DELETE FROM zap2_urls WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub delIp
{
	my $id = shift;
	my $ip = shift;
	
	$logger->debug("Removing IP ".$ip." (id ".$id.")");
	$MAIL_REMOVED_IPS .= "Removed IP ".$ip." (id ".$id.")\n";
	
	my $sth = $DBH->prepare("DELETE FROM zap2_ips WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub delIpOnly {
	my $id = shift;
	my $ip = shift;
	
	$logger->debug("Removing ONLY IP ".$ip." (id ".$id.")");
	$MAIL_REMOVED_IPS .= "Removed ONLY IP ".$ip." (id ".$id.")\n";
	
	my $sth = $DBH->prepare("DELETE FROM zap2_only_ips WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub delSubnet {
	my $id = shift;
	my $subnet = shift;

	$logger->debug("Removing subnet ".$subnet." (id ".$id.")");
	$MAIL_REMOVED .= "Removed subnet ".$subnet." (id ".$id.")\n";
	
	my $sth = $DBH->prepare("DELETE FROM zap2_subnets WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub delRecord {
	my $id = shift;
	
#	$logger->debug("Removing record ".$id);
	$MAIL_REMOVED .= "Removed record ".$id."\n";
	
	my $sth = $DBH->prepare("DELETE FROM zap2_records WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub processMail {
	if( $mail_alone == 1 && $MAIL_ALONE ne '' ) {
		$MAILTEXT .= "\n\n---- Standalone subnets! ----\n\n";
		$MAILTEXT .= $MAIL_ALONE;
	}
	if( $mail_excludes == 1 && $MAIL_EXCLUDES ne '' ) {
		$MAILTEXT .= "\n\n---- Excludes! ----\n\n";
		$MAILTEXT .= $MAIL_EXCLUDES;
	}
	if( $mail_removed == 1 &&  $MAIL_REMOVED ne '' ) {
		$MAILTEXT .= "\n\n--- Removed items: ---\n\n";
		$MAILTEXT .= $MAIL_REMOVED;
	}
	if( $mail_removed_ips == 1 && $MAIL_REMOVED_IPS ne '' ) {
		$MAILTEXT .= "\n\n--- Removed IPS: ---\n\n";
		$MAILTEXT .= $MAIL_REMOVED_IPS;
	}
	
	if( $mail_new == 1 && $MAIL_ADDED ne '' ) {
		$MAILTEXT .= "\n\n--- Added items: ---\n\n";
		$MAILTEXT .= $MAIL_ADDED;
	}
	if( $mail_new_ips == 1 && $MAIL_ADDED_IPS ne '' ) {
		$MAILTEXT .= "\n\n--- Added new ips: ---\n\n";
		$MAILTEXT .= $MAIL_ADDED_IPS;
	}

	
	if(  $MAILTEXT ne '' ) {
#		print "\n\n".$MAILTEXT."\n\n";
		Mail( $MAILTEXT );
	}
	
}

sub get_ip
{
	my $ip_address=shift;
	my $d_size=length($ip_address);
	my $result;
	if($d_size == 4)
	{
		$result=ip_bintoip(unpack("B*",$ip_address),4);
	} else {
		$result=ip_bintoip(unpack("B*",$ip_address),6);
	}
	return $result;
}

sub resolve_async
{
	my $cv=shift;
	my $host=shift;
	my $resolver=shift;
	my $record_id=shift;
	if($host =~ m/([А-Яа-я]+)/gi )
	{
		$host=puny_enc($host);
	}
	$cv->begin;
	$resolver->resolve($host, "a", accept => ["a"], sub {
		$resolved_domains_ipv4++;
		for my $record (@_) {
			my $nr=scalar(@$record);
			my $ipa = new Net::IP($record->[$nr-1]);
			if(!defined($ipa))
			{
				$logger->error( "Invalid ip address ".$record->[$nr-1]." for domain $host");
				next;
			}
			my $ip=$ipa->ip();
			if( defined( $ZAP_OLD_IPS{$record_id}{$ip} ) )
			{
				# delete from old, because we have it.
				delete $ZAP_OLD_TRUE_IPS{$record_id}{$ip} if(defined $ZAP_OLD_TRUE_IPS{$record_id}{$ip});
				next;
			}
			if ($ipa->iptype() ne "PUBLIC" && $ipa->iptype() ne "GLOBAL-UNICAST")
			{
				$logger->info("Bad ip type: ".$ipa->iptype()." for ip $ip host $host");
				next;
			}
			my $exclude = 0;
			for my $subnet (keys %EX_SUBNETS)
			{
				my $ipadr = NetAddr::IP->new( $ip );
				my $net = NetAddr::IP->new( $subnet );
				if( $ipadr && $net ) {
					if( $ipadr->within($net) ) {
						#print "Excluding ip ".$ip.": overlaps with excluded subnet ".$subnet."\n";
						$logger->debug("Excluding ip ".$ip);
						$MAIL_EXCLUDES .= "Excluding new ip: ".$ip."\n";
						$exclude = 1;
						last;
					}
				}
			}
			if( defined($EX_IPS{$ip}) )
			{
				$logger->debug("Excluding ip ".$ip);
				$exclude = 1;
			}
		
			if( $exclude == 1 ) {
				next;
			}
			if($ipa->version() == 4)
			{
				$added_ipv4_ips++;
			} else {
				$added_ipv6_ips++;
			}
			my $ip_packed=pack("B*",$ipa->binip());
			# Not in old ips, not in excludes...
			my $sth = $DBH->prepare("INSERT INTO zap2_ips(record_id, ip, resolved, domain) VALUES(?,?,1,?)");
			$sth->bind_param(1, $record_id);
			$sth->bind_param(2, $ip_packed);
			$sth->bind_param(3, $host);
			$sth->execute;
			$logger->debug("New resolved ip: ".$ipa->ip()." for domain ".$host." record_id: ".$record_id);
			$MAIL_ADDED_IPS .= "New resolved IP: ".$ipa->ip()." for domain ".$host." record_id: ".$record_id." \n";
			$ZAP_OLD_IPS{$record_id}{$ipa->ip()} = 1;
		}
		$cv->end;
	});

	if($ipv6_nslookup)
	{
		$cv->begin;
		$resolver->resolve($host, "aaaa", accept => ["aaaa"], sub {
		$resolved_domains_ipv6++;
		for my $record (@_) {
			my $nr=scalar(@$record);
			my $ipa = new Net::IP($record->[$nr-1]);
			if(!defined($ipa))
			{
				$logger->error( "Invalid ip address ".$record->[$nr-1]." for domain $host");
				next;
			}
			my $ip=$ipa->ip();
			if( defined( $ZAP_OLD_IPS{$record_id}{$ip} ) )
			{
				# delete from old, because we have it.
				delete $ZAP_OLD_TRUE_IPS{$record_id}{$ip} if(defined $ZAP_OLD_TRUE_IPS{$record_id}{$ip});
				next;
			}
			if ($ipa->iptype() ne "PUBLIC" && $ipa->iptype() ne "GLOBAL-UNICAST")
			{
				$logger->info("Bad ip type: ".$ipa->iptype()." for ip $ip host $host");
				next;
			}
			my $exclude = 0;
			for my $subnet (keys %EX_SUBNETS)
			{
				my $ipadr = NetAddr::IP->new( $ip );
				my $net = NetAddr::IP->new( $subnet );
				if( $ipadr && $net ) {
					if( $ipadr->within($net) ) {
						#print "Excluding ip ".$ip.": overlaps with excluded subnet ".$subnet."\n";
						$logger->debug("Excluding ip ".$ip);
						$MAIL_EXCLUDES .= "Excluding new ip: ".$ip."\n";
						$exclude = 1;
						last;
					}
				}
			}
			if( defined($EX_IPS{$ip}) )
			{
				$logger->debug("Excluding ip ".$ip);
				$exclude = 1;
			}
		
			if( $exclude == 1 ) {
				next;
			}
			if($ipa->version() == 4)
			{
				$added_ipv4_ips++;
			} else {
				$added_ipv6_ips++;
			}
			my $ip_packed=pack("B*",$ipa->binip());
			# Not in old ips, not in excludes...
			my $sth = $DBH->prepare("INSERT INTO zap2_ips(record_id, ip, resolved, domain) VALUES(?,?,1,?)");
			$sth->bind_param(1, $record_id);
			$sth->bind_param(2, $ip_packed);
			$sth->bind_param(3, $host);
			$sth->execute;
			$logger->debug("New resolved ip: ".$ipa->ip()." for domain ".$host." record_id: ".$record_id);
			$MAIL_ADDED_IPS .= "New resolved IP: ".$ipa->ip()." for domain ".$host." record_id: ".$record_id." \n";
			$ZAP_OLD_IPS{$record_id}{$ipa->ip()} = 1;
		}
		$cv->end;
		});
	}

}

