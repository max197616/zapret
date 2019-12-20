#!/usr/bin/perl

use strict;
use warnings;

use utf8;
use XML::LibXML::Reader;
use DBI;
use File::Basename 'dirname';
use File::Spec;
use lib join '/',File::Spec->splitdir(dirname(__FILE__));
use Zapret;
use Config::Simple;
use File::Basename;
use Getopt::Long;
use Log::Log4perl;
use Net::IP qw(:PROC);
use Net::SMTP;
use Email::MIME;
use PerlIO::gzip;
use POSIX qw(strftime);
use MIME::Base64;
use File::Path qw(make_path);
use File::Copy;
use Digest::MD5 qw (md5_hex);
use Fcntl qw(LOCK_EX LOCK_NB);

use Data::Dumper;
use Devel::Size qw(size total_size);

binmode(STDOUT,':utf8');
binmode(STDERR,':utf8');

use constant
{
	URL_TABLE => "zap2_urls",
	URL_COL_NAME => "url",

	IP_TABLE => "zap2_ips",
	IP_COL_NAME => "ip",


	IP_ONLY_TABLE => "zap2_only_ips",
	IP_ONLY_COL_NAME => "ip",

	DOMAIN_TABLE => "zap2_domains",
	DOMAIN_COL_NAME => "domain",

	SUBNET_TABLE => "zap2_subnets",
	SUBNET_COL_NAME => "subnet",

	SUPPORTED_DUMP_VERSION => 2.4
};



######## Config #########

my $openssl_bin_path="/usr/local/gost-ssl-new/bin";

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


#my $mail_send = $Config->{'MAIL.send'} || 0;

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
my $mail_stat = $Config->{'MAIL.stat'} || 0;
my $mail_max_entries = $Config->{'MAIL.max_entries'} || 150;
my $mail_check_report = $Config->{'MAIL.check_report'} || 0;
my $mail_nofresh_report = $Config->{'MAIL.nofresh_report'} || 0;
my $mail_subject = $Config->{'MAIL.subject'} || "zapret update!";

my $form_request = $Config->{'API.form_request'} || 0;

my $our_blacklist = $Config->{'PATH.our_blacklist'} || "";

my $tmp_path = $Config->{'PATH.tmp_path'} || "/tmp";

my $ldd_iterations = 0;
my $check_iterations = 0;

my $max_check_iterations = $Config->{'API.max_check_iterations'} || 3;
my $max_download_interval = $Config->{'API.max_download_interval'} || 60*60;
my $max_result_iterations = $Config->{'API.max_result_iterations'} || 10;
my $get_result_sleep_interval = $Config->{'API.get_result_sleep_interval'} || 60;

######## End config #####

my $start_work_time = time();

my $DBH;
my ($lastDumpDateOld, $lastAction, $lastCode, $lastResult, $lastDocVersion);


dbConnect();
getParams();

my $MAILTEXT = '';
my $MAIL_ADDED = '';
my $MAIL_ADDED_IPS = '';
my $MAIL_REMOVED = '';
my $MAIL_REMOVED_IPS = '';
my $MAIL_EXCLUDES = '';
my $MAIL_ALONE = '';


my $deleted_old_domains=0;
my $deleted_old_urls=0;
my $deleted_old_ips=0;
my $deleted_old_only_ips=0;
my $deleted_old_subnets=0;
my $deleted_old_records=0;
my $added_ipv4_ips=0;
my $added_ipv6_ips=0;
my $added_only_ipv4_ips=0;
my $added_only_ipv6_ips=0;
my $added_domains=0;
my $added_urls=0;
my $added_subnets=0;
my $added_records=0;


my @mail_add_urls; # if (entries > $mail_max_entries), then count $skiped_mail_add_urls
my @mail_del_urls;

my @mail_add_ips;
my @mail_del_ips;
my @mail_add_only_ips;
my @mail_del_only_ips;
my @mail_add_domains;
my @mail_del_domains;
my @mail_add_subnets;
my @mail_del_subnets;
my @mail_add_contents;
my @mail_del_contents;

my $mail_add_url_skipped = 0;
my $mail_del_url_skipped = 0;

my $mail_add_ip_skipped = 0;
my $mail_del_ip_skipped = 0;
my $mail_add_only_ip_skipped = 0;
my $mail_del_only_ip_skipped = 0;
my $mail_add_domain_skipped = 0;
my $mail_del_domain_skipped = 0;
my $mail_add_subnet_skipped = 0;
my $mail_del_subnet_skipped = 0;
my $mail_add_content_skipped = 0;
my $mail_del_content_skipped = 0;

my %all_records; # $all_records{$ips->{decision_id}} = $ips->{id};

$logger->debug("Last dump date:\t".$lastDumpDateOld);
$logger->debug("Last action:\t".$lastAction);
$logger->debug("Last code:\t".$lastCode);
$logger->debug("Last result:\t".$lastResult);

#############################################################

my $start_time = time();
my $register_processed = 0;

$logger->info("Starting RKN at ".$start_time);

eval
{
	flock(DATA,LOCK_EX|LOCK_NB) or die "This script ($0) is already running!";
	if(checkDumpDate())
	{
		sendRequest();
		my $files = getDumpFile(getResult($lastCode));
		getAllContent();
		parseFiles($files);
		parseOurBlacklist($our_blacklist) if($our_blacklist);
		analyzeOldContent();
		$register_processed = 1;
		setParam('lastActionDate', time);
	} else {
		parseOurBlacklist($our_blacklist) if($our_blacklist);
	}
};
if($@)
{
	$MAILTEXT .= "Error occured while working with registry: ".$@;
	$logger->error("Error occured while working with registry: ".$@);
	$mail_subject = "Zapret error!";
	processMail();
	exit 1;
}

processMail();

# статистика
$logger->info("Check iterations: ".$check_iterations);
if($ldd_iterations)
{
	$logger->info("Registry processing time: ".(parseDuration(time()-$start_time))." (wait time: ".(parseDuration($ldd_iterations*$get_result_sleep_interval)).")");
	$logger->info("Load iterations: ".$ldd_iterations);
	$logger->info("Added: domains: ".$added_domains.", urls: ".$added_urls.", IPv4 ips: ".$added_ipv4_ips.", IPv6 ips: ".$added_ipv6_ips." IPv4 only IPs: ".$added_only_ipv4_ips.", IPv6 only IPs: ".$added_only_ipv6_ips.", subnets: ".$added_subnets.", records: ".$added_records);
	$logger->info("Deleted: old domains: ".$deleted_old_domains.", old urls: ".$deleted_old_urls.", old ips: ".$deleted_old_ips.", old only ips: ".$deleted_old_only_ips.", old subnets: ".$deleted_old_subnets.", old records: ".$deleted_old_records);
}
$logger->info("Stopping RKN at ".(localtime()));

exit 0;


sub dbConnect
{
	$DBH = DBI->connect_cached("DBI:mysql:database=".$db_name.";host=".$db_host, $db_user, $db_pass,{mysql_enable_utf8 => 1, RaiseError => 1}) or die DBI->errstr;
	$DBH->do("set names utf8");
}

sub isSomeDone
{
	return 1 if($added_domains || $added_urls || $added_ipv4_ips || $added_ipv6_ips || $added_only_ipv4_ips || $added_only_ipv6_ips || $added_subnets || $added_records);
	return 1 if($deleted_old_domains || $deleted_old_urls || $deleted_old_ips || $deleted_old_only_ips || $deleted_old_subnets || $deleted_old_records);
	return 0;
}

sub processMail
{
	if($mail_stat && $register_processed && isSomeDone())
	{
		$MAILTEXT .= "\n\nRegistry processing time: ".(parseDuration(time()-$start_time))." (wait time: ".(parseDuration($ldd_iterations*$get_result_sleep_interval)).")\n";
	}
	if($mail_check_report && $check_iterations)
	{
		$MAILTEXT .= "\n\n--- Registry check statistics ---\n";
		$MAILTEXT .= "Check iterations: ".$check_iterations."\n";
	}
	if($mail_stat && isSomeDone())
	{
		$MAILTEXT .= "\n\n--- Registry processing statistics ---\n";
		$MAILTEXT .= "Load iterations: ".$ldd_iterations."\n";
		$MAILTEXT .= "Added: domains: ".$added_domains.", urls: ".$added_urls.", IPv4 ips: ".$added_ipv4_ips.", IPv6 ips: ".$added_ipv6_ips." IPv4 only IPs: ".$added_only_ipv4_ips.", IPv6 only IPs: ".$added_only_ipv6_ips.", subnets: ".$added_subnets.", records: ".$added_records."\n";
		$MAILTEXT .= "Deleted: old domains: ".$deleted_old_domains.", old urls: ".$deleted_old_urls.", old ips: ".$deleted_old_ips.", old only ips: ".$deleted_old_only_ips.", old subnets: ".$deleted_old_subnets.", old records: ".$deleted_old_records."\n";
	}
	if($mail_new)
	{
		if(@mail_add_contents)
		{
			$MAILTEXT .= "\n\n--- Added contents ---\n";
			foreach my $cont (@mail_add_contents)
			{
				$MAILTEXT .= "Content: ".$cont->{value}." for id: ".$cont->{id}."\n";
			}
			if($mail_add_content_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_add_content_skipped." contents\n";
			}
		}
		if(@mail_add_urls)
		{
			$MAILTEXT .= "\n\n--- Added URLs ---\n";
			foreach my $url (@mail_add_urls)
			{
				$MAILTEXT .= "URL: ".$url->{value}." for id: ".$url->{id}."\n";
			}
			if($mail_add_url_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_add_url_skipped." urls\n";
			}
		}
		if(@mail_add_domains)
		{
			$MAILTEXT .= "\n\n--- Added domains ---\n";
			foreach my $domain (@mail_add_domains)
			{
				$MAILTEXT .= "Domain: ".$domain->{value}." for id: ".$domain->{id}."\n";
			}
			if($mail_add_domain_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_add_domain_skipped." domains\n";
			}

		}
		if(@mail_add_ips)
		{
			$MAILTEXT .= "\n\n--- Added IPs ---\n";
			foreach my $ip (@mail_add_ips)
			{
				$MAILTEXT .= "IP: ".$ip->{value}." for id: ".$ip->{id}."\n";
			}
			if($mail_add_ip_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_add_ip_skipped." IPs\n";
			}

		}

		if(@mail_add_only_ips)
		{
			$MAILTEXT .= "\n\n--- Added only IPs ---\n";
			foreach my $ip (@mail_add_only_ips)
			{
				$MAILTEXT .= "Only IP: ".$ip->{value}." for id: ".$ip->{id}."\n";
			}
			if($mail_add_only_ip_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_add_only_ip_skipped." only IPs\n";
			}
		}

		if(@mail_add_subnets)
		{
			$MAILTEXT .= "\n\n--- Added subnets ---\n";
			foreach my $subnet (@mail_add_subnets)
			{
				$MAILTEXT .= "Subnet: ".$subnet->{value}." for id: ".$subnet->{id}."\n";
			}
			if($mail_add_subnet_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_add_subnet_skipped." subnets\n";
			}
		}

	}
	if($mail_removed)
	{
		if(@mail_del_contents)
		{
			$MAILTEXT .= "\n\n--- Removed contents ---\n";
			foreach my $cont (@mail_del_contents)
			{
				$MAILTEXT .= "Content: ".$cont->{value}." for id: ".$cont->{id}."\n";
			}
			if($mail_del_content_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_del_content_skipped." records\n";
			}
		}
		if(@mail_del_urls)
		{
			$MAILTEXT .= "\n\n--- Removed URLs ---\n";
			foreach my $url (@mail_del_urls)
			{
				$MAILTEXT .= "URL: ".$url->{value}." for id: ".$url->{id}."\n";
			}
			if($mail_del_url_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_del_url_skipped." urls\n";
			}
		}
		if(@mail_del_ips)
		{
			$MAILTEXT .= "\n\n--- Removed IPs ---\n";
			foreach my $ip (@mail_del_ips)
			{
				$MAILTEXT .= "IP: ".$ip->{value}." for id: ".$ip->{id}."\n";
			}
			if($mail_del_ip_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_del_ip_skipped." ips\n";
			}
		}
		if(@mail_del_only_ips)
		{
			$MAILTEXT .= "\n\n--- Removed only IPs ---\n";
			foreach my $ip (@mail_del_only_ips)
			{
				$MAILTEXT .= "Only IP: ".$ip->{value}." for id: ".$ip->{id}."\n";
			}
			if($mail_del_only_ip_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_del_only_ip_skipped." only ips\n";
			}
		}
		if(@mail_del_domains)
		{
			$MAILTEXT .= "\n\n--- Removed domains ---\n";
			foreach my $domain (@mail_del_domains)
			{
				$MAILTEXT .= "Domain: ".$domain->{value}." for id: ".$domain->{id}."\n";
			}
			if($mail_del_domain_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_del_domain_skipped." domains\n";
			}
		}

		if(@mail_del_subnets)
		{
			$MAILTEXT .= "\n\n--- Removed subnets ---\n";
			foreach my $subnet (@mail_del_subnets)
			{
				$MAILTEXT .= "Subnet: ".$subnet->{value}." for id: ".$subnet->{id}."\n";
			}
			if($mail_del_subnet_skipped > 0)
			{
				$MAILTEXT .= "... and additionaly ".$mail_del_subnet_skipped." subnets\n";
			}
		}
	}
	Mail($MAILTEXT, $mail_subject) if($MAILTEXT);
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


sub mail_add_url
{
	my $url = shift;
	my $id = shift;
	if(scalar @mail_add_urls > $mail_max_entries)
	{
		$mail_add_url_skipped++;
	} else {
		push(@mail_add_urls, { value => $url, id => $id});
	}
}

sub mail_add_ip
{
	my $ip = shift;
	my $id = shift;
	if(scalar @mail_add_ips > $mail_max_entries)
	{
		$mail_add_ip_skipped++;
	} else {
		push(@mail_add_ips, { value => $ip, id => $id});
	}
}

sub mail_add_only_ip
{
	my $ip = shift;
	my $id = shift;
	if(scalar @mail_add_only_ips > $mail_max_entries)
	{
		$mail_add_only_ip_skipped++;
	} else {
		push(@mail_add_only_ips, { value => $ip, id => $id});
	}
}

sub mail_add_domain
{
	my $domain = shift;
	my $id = shift;
	if(scalar @mail_add_domains > $mail_max_entries)
	{
		$mail_add_domain_skipped++;
	} else {
		push(@mail_add_domains, { value => $domain, id => $id});
	}
}

sub mail_add_subnet
{
	my $subnet = shift;
	my $id = shift;
	if(scalar @mail_add_subnets > $mail_max_entries)
	{
		$mail_add_subnet_skipped++;
	} else {
		push(@mail_add_subnets, { value => $subnet, id => $id});
	}
}

sub mail_add_content
{
	my $content = shift;
	if(scalar @mail_add_contents > $mail_max_entries)
	{
		$mail_add_content_skipped++;
	} else {
		push(@mail_add_contents, { value => "includeTime: ".$content->{includeTime}.", blockType: ".$content->{blockType}, id => $content->{id}});
	}
}

sub mail_del_ip
{
	my $ip = shift;
	my $id = shift;
	if(scalar @mail_del_ips > $mail_max_entries)
	{
		$mail_del_ip_skipped++;
	} else {
		push(@mail_del_ips, { value => $ip, id => $id });
	}
}

sub mail_del_only_ip
{
	my $ip = shift;
	my $id = shift;
	if(scalar @mail_del_only_ips > $mail_max_entries)
	{
		$mail_del_only_ip_skipped++;
	} else {
		push(@mail_del_only_ips, { value => $ip, id => $id });
	}
}

sub mail_del_domain
{
	my $domain = shift;
	my $id = shift;
	if(scalar @mail_del_domains > $mail_max_entries)
	{
		$mail_del_domain_skipped++;
	} else {
		push(@mail_del_domains, { value => $domain, id => $id});
	}
}

sub mail_del_subnet
{
	my $subnet = shift;
	my $id = shift;
	if(scalar @mail_del_subnets > $mail_max_entries)
	{
		$mail_del_subnet_skipped++;
	} else {
		push(@mail_del_subnets, { value => $subnet, id => $id});
	}
}

sub mail_del_url
{
	my $url = shift;
	my $id = shift;
	if(scalar @mail_del_urls > $mail_max_entries)
	{
		$mail_del_url_skipped++;
	} else {
		push(@mail_del_urls, { value => $url, id => $id });
	}
}

sub mail_del_content
{
	my $content = shift;
	if(scalar @mail_del_contents > $mail_max_entries)
	{
		$mail_del_content_skipped++;
	} else {
		push(@mail_del_contents, { value => "record id: ".$content->{id}, id => $content->{decision_id}});
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


sub getData
{
	my $record_id = shift;
	my $table = shift;
	my $name = shift;
	my @values;
	my $sth = $DBH->prepare("SELECT * FROM $table WHERE record_id = $record_id");
	$sth->execute or die DBI->errstr;
	while(my $ips = $sth->fetchrow_hashref())
	{
		my $value = $ips->{$name} || "";
		if($value)
		{
			if($name =~ /ip/)
			{
				push(@values, {value => get_ip($value), id => $ips->{id}});
			} else {
				push(@values, {value => $value, id => $ips->{id}});
			}
		}
	}
	$sth->finish();
	return @values;
}

sub getContentByID
{
	my $id = shift;
	my %content;
	my $sth = $DBH->prepare("SELECT * FROM zap2_records WHERE decision_id = $id");
	$sth->execute();
	while(my $ips = $sth->fetchrow_hashref())
	{
		my $record_id = $ips->{id};
		my @domains = getData($record_id, DOMAIN_TABLE, DOMAIN_COL_NAME);
		if(@domains)
		{
			$content{domain} = \@domains;
		}
		my @urls = getData($record_id, URL_TABLE, URL_COL_NAME);
		if(@urls)
		{
			$content{url} = \@urls;
		}
		my @subnets = getData($record_id, SUBNET_TABLE, SUBNET_COL_NAME);
		if(@subnets)
		{
			$content{ipSubnet} = \@subnets;
		}
		my @ips = getData($record_id, IP_TABLE, IP_COL_NAME);
		if(@ips)
		{
			$content{ip} = \@ips;
		}
		my @only_ips = getData($record_id, IP_ONLY_TABLE, IP_ONLY_COL_NAME);
		if(@only_ips)
		{
			$content{only_ip} = \@only_ips;
		}
		$content{hash} = $ips->{hash} || undef;
		$content{id} = $ips->{id};
		$content{decision_id} = $id;
	}
	$sth->finish();
	return %content;
}

sub getAllContent
{
	my $sth = $DBH->prepare("SELECT id, decision_id, hash FROM zap2_records");
	$sth->execute();
	while(my $ips = $sth->fetchrow_hashref())
	{
		$all_records{$ips->{decision_id}} = { id => $ips->{id}, hash => (defined $ips->{hash} ? $ips->{hash} : undef) };
	}
	$sth->finish();
}

sub checkData
{
	my $c_array = shift;
	my $db_array = shift;
	my %c_array = map { $_ => 1 } @$c_array;
	my @add_entries;

	foreach my $entry (@$db_array)
	{
		if(exists $c_array{$entry->{value}})
		{
			delete $entry->{id};
			delete $c_array{$entry->{value}};
		}
	}
	@add_entries = keys %c_array;
	return @add_entries;
}

=pod
sub checkData
{
	my $c_array = shift;
	my $db_array = shift;
	my @add_entries;
	foreach my $val (@{$c_array})
	{
		my $found_db = 0;
		foreach my $entry (@{$db_array})
		{
			if($val eq $entry->{value})
			{
				$found_db = 1;
				delete $entry->{id};
				last;
			}
		}
		if(!$found_db)
		{
			push(@add_entries, $val);
		}
	}
	return @add_entries;
}
=cut

sub insertEntry
{
	my $table = shift;
	my $col_name = shift;
	my $record_id = shift;
	my $value = shift;
	my $sth = $DBH->prepare("INSERT INTO $table (record_id, $col_name) VALUES(?,?)");
	$sth->bind_param(1, $record_id);
	$sth->bind_param(2, $value);
	$sth->execute();
}

sub removeEntry
{
	my $table = shift;
	my $id = shift;
	my $sth = $DBH->prepare("DELETE FROM $table WHERE id=?");
	$sth->bind_param(1, $id );
	$sth->execute();
}

sub insertContent
{
	my $content = shift;
	my $sth = $DBH->prepare("INSERT INTO zap2_records (decision_id,decision_date,decision_num,decision_org,include_time,entry_type,hash) VALUES(?,?,?,?,?,?,?)");
	$sth->bind_param(1, $content->{id});
	$sth->bind_param(2, $content->{decision}{date});
	$sth->bind_param(3, $content->{decision}{number});
	$sth->bind_param(4, $content->{decision}{org});
	$sth->bind_param(5, $content->{includeTime});
	$sth->bind_param(6, $content->{entryType});
	$sth->bind_param(7, $content->{hash});
	$sth->execute();
	return $sth->{mysql_insertid};
}

sub updateHash
{
	my $content = shift;
	my $hash = shift;
	my $sth = $DBH->prepare("UPDATE zap2_records SET hash = ? WHERE id = ?");
	$sth->bind_param(1, $hash);
	$sth->bind_param(2, $content->{id});
	$sth->execute();
}

sub removeOldURL
{
	my $db_content = shift;
	foreach my $del_url (@{$db_content->{url}})
	{
		if(exists $del_url->{id})
		{
			$logger->debug("Removing URL ".$del_url->{value}." (id ".$del_url->{id}.")");
			mail_del_url($del_url->{value}, $db_content->{decision_id});
			removeEntry(URL_TABLE, $del_url->{id});
			$deleted_old_urls++;
		}
	}
}

sub processURL
{
	my $content = shift;
	my $db_content = shift;
	my $record_id = $db_content->{id};
	if(@{$content->{url}{value}})
	{
		my @urls = @{$content->{url}{value}};
		my @add_urls = checkData(\@urls, $db_content->{url});
		if(@add_urls)
		{
			foreach my $url(@add_urls)
			{
				insertEntry(URL_TABLE, URL_COL_NAME, $record_id, $url);
				mail_add_url($url, $db_content->{decision_id});
#				$MAIL_ADDED .= "Added new URL: ".$url." for $db_content{decision_id} \n";
				$logger->debug("Added new URL: ".$url);
				$added_urls++;
			}
		}
#		print "in the url add array: ", Dumper(\@add_urls), "\n";
	}
}

sub removeOldIP
{
	my $db_content = shift;
	foreach my $del_ip (@{$db_content->{ip}})
	{
		if(exists $del_ip->{id})
		{
			$logger->debug("Removing IP ".$del_ip->{value}." (id ".$del_ip->{id}.")");
			mail_del_ip($del_ip->{value}, $db_content->{decision_id});
			removeEntry(IP_TABLE, $del_ip->{id});
			$deleted_old_ips++;
		}
	}
}

sub removeOldSubnet
{
	my $db_content = shift;
	foreach my $del_subnet (@{$db_content->{ipSubnet}})
	{
		if(exists $del_subnet->{id})
		{
			$logger->debug("Removing subnet ".$del_subnet->{value}." (id ".$del_subnet->{id}.")");
			mail_del_subnet($del_subnet->{value}, $db_content->{decision_id});
			removeEntry(SUBNET_TABLE, $del_subnet->{id});
			$deleted_old_subnets++;
		}
	}
}

sub removeOldDomain
{
	my $db_content = shift;
	foreach my $del_domain (@{$db_content->{domain}})
	{
		if(exists $del_domain->{id})
		{
			$logger->debug("Removing Domain ".$del_domain->{value}." (id ".$del_domain->{id}.")");
			mail_del_domain($del_domain->{value}, $db_content->{decision_id});
			removeEntry(DOMAIN_TABLE, $del_domain->{id});
			$deleted_old_domains++;
		}
	}
}

sub removeOldOnlyIP
{
	my $db_content = shift;
	foreach my $del_ip (@{$db_content->{only_ip}})
	{
		if(exists $del_ip->{id})
		{
			$logger->debug("Removing Only IP ".$del_ip->{value}." (id ".$del_ip->{id}.")");
			mail_del_only_ip($del_ip->{value}, $db_content->{decision_id});
			removeEntry(IP_ONLY_TABLE, $del_ip->{id});
			$deleted_old_only_ips++;
		}
	}
}

sub removeContent
{
	my $record_id = shift;
	my $sth = $DBH->prepare("DELETE FROM zap2_records WHERE id = ?");
	$sth->bind_param(1, $record_id);
	$sth->execute();
	my @tables = ( URL_TABLE, IP_TABLE, IP_ONLY_TABLE, DOMAIN_TABLE, SUBNET_TABLE );
	foreach my $table (@tables)
	{
		$sth = $DBH->prepare("DELETE FROM $table WHERE record_id = ?");
		$sth->bind_param(1, $record_id);
		$sth->execute();
	}
}

sub processIP
{
	my $content = shift;
	my $db_content = shift;
	my $record_id = $db_content->{id};
	my @ips;
	push(@ips, @{$content->{ip}{value}}) if(defined $content->{ip}{value});
	if(defined $content->{ipv6}{value})
	{
		my @ipv6 = @{$content->{ipv6}{value}};
		convertIPv6(\@ipv6);
		push(@ips, @ipv6);
	}
	if(@ips)
	{
		my @add_ips = checkData(\@ips, $db_content->{ip});
		if(@add_ips)
		{
			foreach my $ip (@add_ips)
			{
				my $ipa = new Net::IP($ip);
				my $ip_packed=pack("B*",$ipa->binip());
				insertEntry(IP_TABLE, IP_COL_NAME, $record_id, $ip_packed);
				mail_add_ip($ip, $db_content->{decision_id});
				$logger->debug("Added new IP: ".$ip);
				if($ipa->version() == 4)
				{
					$added_ipv4_ips++;
				} else {
					$added_ipv6_ips++;
				}
			}
		}
#		print "in the ips add array: ", Dumper(\@add_ips), "\n";
	}
}

sub processDomain
{
	my $content = shift;
	my $db_content = shift;
	my $record_id = $db_content->{id};
	if(@{$content->{domain}{value}})
	{
		my @domains = @{$content->{domain}{value}};
		my @add_domains = checkData(\@domains, $db_content->{domain});
		if(@add_domains)
		{
			foreach my $domain (@add_domains)
			{
				insertEntry(DOMAIN_TABLE, DOMAIN_COL_NAME, $record_id, $domain);
				mail_add_domain($domain, $db_content->{decision_id});
				$logger->debug("Added new Domain: ".$domain);
				$added_domains++;
			}
		}
#		print "in the domains add array: ", Dumper(\@add_domains), "\n";
	}
}

sub processOnlyIP
{
	my $content = shift;
	my $db_content = shift;
	my $record_id = $db_content->{id};
	my @ips;
	push(@ips, @{$content->{ip}{value}}) if(defined $content->{ip}{value});
	if(defined $content->{ipv6}{value})
	{
		my @ipv6 = @{$content->{ipv6}{value}};
		convertIPv6(\@ipv6);
		push(@ips, @ipv6);
	}
	if(@ips)
	{
		my @add_ips = checkData(\@ips, $db_content->{only_ip});
		if(@add_ips)
		{
			foreach my $ip (@add_ips)
			{
				my $ipa = new Net::IP($ip);
				my $ip_packed=pack("B*",$ipa->binip());
				insertEntry(IP_ONLY_TABLE, IP_ONLY_COL_NAME, $record_id, $ip_packed);
				mail_add_only_ip($ip, $db_content->{decision_id});
				$logger->debug("Added new only IP: ".$ip);
				if($ipa->version() == 4)
				{
					$added_only_ipv4_ips++;
				} else {
					$added_only_ipv6_ips++;
				}
			}
		}
#		print "in the only ips add array: ", Dumper(\@add_ips), "\n";
	}
}

sub processSubnet
{
	my $content = shift;
	my $db_content = shift;
	my $record_id = $db_content->{id};
	my @subnets;
	push(@subnets, @{$content->{ipSubnet}{value}}) if (defined $content->{ipSubnet}{value});
	push(@subnets, @{$content->{ipv6Subnet}{value}}) if (defined $content->{ipv6Subnet}{value});
	if(@subnets)
	{
		my @add_subnets = checkData(\@subnets, $db_content->{ipSubnet});
		if(@add_subnets)
		{
			foreach my $subnet (@add_subnets)
			{
				insertEntry(SUBNET_TABLE, SUBNET_COL_NAME, $record_id, $subnet);
				mail_add_subnet($subnet, $db_content->{decision_id});
				$logger->debug("Added new subnet: ".$subnet);
				$added_subnets++;
			}
		}
	}
}

sub processContent
{
	my $content = shift;
	my $db_content = shift;
	if($content->{blockType} eq "default")
	{
		if(defined $content->{url}{value})
		{
			processURL($content, $db_content);
		} elsif(defined $content->{domain}{value})
		{
			processDomain($content, $db_content);
		}
		if(!defined $content->{url}{value} && !defined $content->{domain}{value} && (defined $content->{ip}{value} || defined $content->{ipv6}{value}))
		{
			processOnlyIP($content, $db_content);
		} else {
			if(defined $content->{ip}{value} || defined $content->{ipv6}{value})
			{
				processIP($content, $db_content);
			}
		}
		if(defined $content->{ipSubnet}{value} || defined $content->{ipv6Subnet}{value})
		{
			processSubnet($content, $db_content);
		}
	} elsif ($content->{blockType} eq "custom")
	{
		if(defined $content->{url}{value})
		{
			processURL($content, $db_content);
		}
		if(defined $content->{domain}{value})
		{
			processDomain($content, $db_content);
		}
		if(defined $content->{ip}{value} || defined $content->{ipv6}{value})
		{
			processOnlyIP($content, $db_content);
		}
		if(defined $content->{ipSubnet}{value} || defined $content->{ipv6Subnet}{value})
		{
			processSubnet($content, $db_content);
		}
	} else {
		if($content->{blockType} eq "domain" || $content->{blockType} eq "domain-mask")
		{
			# block by domain
			if(defined $content->{domain}{value})
			{
				processDomain($content, $db_content);
			} else {
				$logger->error("Not found domain node for the entry $content->{id}, but blockType is domain");
			}
			if(defined $content->{ip}{value} || defined $content->{ipv6}{value})
			{
				processIP($content, $db_content);
			}
		} elsif ($content->{blockType} eq "ip")
		{
			# block by ip
			if(defined $content->{ip}{value} || defined $content->{ipv6}{value})
			{
				processOnlyIP($content, $db_content);
			}
			if(defined $content->{ipSubnet}{value} || $content->{ipv6Subnet}{value})
			{
				processSubnet($content, $db_content);
			}
			if(!defined $content->{ip}{value} && !defined $content->{ipSubnet}{value} && !defined $content->{ipv6Subnet}{value} && !defined $content->{ipv6}{value})
			{
				$logger->error("Not found ip node or subnet for the entry $content->{id}, but blockType is ip");
			}
		} else {
			$logger->error("Unknown blockType in content id ".$content->{id});
		}
	}
	if(defined $db_content->{url})
	{
		removeOldURL($db_content);
	}
	if(defined $db_content->{domain})
	{
		removeOldDomain($db_content);
	}
	if((!defined $content->{url}{value} && !defined $content->{domain}{value} && defined $db_content->{only_ip}) || ($content->{blockType} eq "ip" && defined $db_content->{only_ip}))
	{
		removeOldOnlyIP($db_content);
	} elsif (defined $db_content->{ip})
	{
		removeOldIP($db_content);
	}
	if(defined $db_content->{ipSubnet})
	{
		removeOldSubnet($db_content);
	}
}

sub parseContent
{
	my $content = shift;
	$content->{blockType} = 'default' if(!exists $content->{blockType});
	if(exists $all_records{$content->{id}})
	{
		if(!defined $all_records{$content->{id}}{hash} || $all_records{$content->{id}}{hash} ne $content->{hash})
		{
			my %db_content = getContentByID($content->{id});
			processContent($content, \%db_content);
			updateHash(\%db_content, $content->{hash});
		}
	} else {
		my %db_content;
		$db_content{id} = insertContent($content);
		$db_content{decision_id} = $content->{id};
		processContent($content, \%db_content);
		mail_add_content($content);
		$added_records++;
	}
	delete $all_records{$content->{id}} if(exists $all_records{$content->{id}});
}

sub analyzeOldContent
{
	foreach my $record (keys %all_records)
	{
		my %content;
		$content{decision_id} = $record;
		$content{id} = $all_records{$record}{id};
		my %db_content = getContentByID($record);
		if(defined $db_content{url})
		{
			removeOldURL(\%db_content);
		}
		if(defined $db_content{domain})
		{
			removeOldDomain(\%db_content);
		}
		if(defined $db_content{only_ip})
		{
			removeOldOnlyIP(\%db_content);
		} elsif (defined $db_content{ip})
		{
			removeOldIP(\%db_content);
		}
		if(defined $db_content{ipSubnet})
		{
			removeOldSubnet(\%db_content);
		}
		mail_del_content(\%content);
		removeContent($all_records{$record}{id});
		$deleted_old_records++;
	}
}

sub parseDump
{
	my $xml_file = shift;
	my $reader = XML::LibXML::Reader->new(location => $xml_file) or die "Can't process xml file '$xml_file': ".$!."\n";
	my $do_content = 0;
	my %register;
	my $doc_pattern = XML::LibXML::Pattern->new('./content');
	my $z = 0;
	while ($reader->read)
	{
		next unless $reader->nodeType() == XML_READER_TYPE_ELEMENT;
		if($reader->name() eq 'reg:register')
		{
			my $reg = $reader->document()->documentElement();
			for my $attr ($reg->attributes)
			{
				$register{$attr->getName()} = $attr->getValue();
			}
		}
		if($z == 0)
		{
			if(!keys %register)
			{
				$reader->close();
				print "not found register!\n";
				return -2;
			}
			if(!defined $register{formatVersion})
			{
				$reader->close();
				print "Not found attribute formatVersion!\n";
				return -3;
			}
			my $format_version = $register{formatVersion};
			$format_version += 0.0;
			if($format_version > SUPPORTED_DUMP_VERSION)
			{
				$reader->close();
				print "Found unsupported format version $format_version\n";
				return -4;
			}
		}
		next unless $reader->matchesPattern($doc_pattern);
		my $xml = $reader->readOuterXml;
		my $doc = XML::LibXML->load_xml(string => $xml);
		my $element = $doc->documentElement();
		my %content;
		for my $attr ($element->attributes)
		{
			$content{$attr->getName()} = $attr->getValue();
		}
		foreach my $node ($element->childNodes())
		{
		
			my $node_name = $node->nodeName() || "";
			if($node_name ne "#text")
			{
				for my $attr ($node->attributes)
				{
					$content{$node_name}{$attr->getName()} = $attr->getValue();
				}
				my $text = $node->textContent() || "";
				$text =~ s/^\s*//;
				$text =~ s/\s*$//;
				if($text)
				{
					push(@{$content{$node_name}{value}}, $text);
				}
			}
		}
		if(keys %content)
		{
			parseContent(\%content);
		}
		$reader->nextPatternMatch($doc_pattern);
		$z++;
	}
}

sub getMD5Sum
{
	my $file=shift;
	open(my $MFILE, $file) or return "";
	binmode($MFILE);
	my $hash=Digest::MD5->new->addfile(*$MFILE)->hexdigest;
	close($MFILE);
	return $hash;
}


sub rndStr{ join'', @_[ map{ rand @_ } 1 .. shift ] }

sub parseOurBlacklist
{
	my $filename = shift;
	my %content;
	$content{hash} = getMD5Sum($filename);
	$content{id} = "0";
	$content{includeTime} = '';
	$content{blockType} = 'custom';
	if(!defined $all_records{$content{id}})
	{
		my %db_content = getContentByID($content{id});
		if(keys %db_content)
		{
			return if($db_content{hash} eq $content{hash});
			$all_records{$content{id}}{hash} = $db_content{hash};
		}
	}
	$ldd_iterations++ if($ldd_iterations == 0);
	open (my $fh, $filename) or die "Could not open file '$filename' $!";
	my $line = 1;
	while (my $url = <$fh>)
	{
		chomp $url;
		my $store_in_table;
		if($url =~ /^http\:\/\// || $url =~ /^https\:\/\//)
		{
			push(@{$content{url}{value}}, $url);
		} elsif ($url =~ /^ip\:\/\//)
		{
			my $ip = $url;
			$ip =~ s/^ip\:\/\///;
			push(@{$content{ip}{value}}, $ip);
		} elsif ($url =~ /^ipv6\:\/\//)
		{
			my $ip = $url;
			$ip =~ s/^ipv6\:\/\///;
			push(@{$content{ipv6}{value}}, $ip);
		} elsif ($url =~ /^subnet\:\/\//)
		{
			my $subnet = $url;
			$subnet =~ s/^subnet\:\/\///;
			push(@{$content{ipSubnet}{value}}, $subnet);
		} else {
			if($url =~ /^\*\./ || $url !~ /\//)
			{
				push (@{$content{domain}{value}}, $url);
			} else {
				push(@{$content{url}{value}}, "http://".$url);
			}
		}
		$line++;
	}
	close $fh;
	parseContent(\%content);
}

sub getLastDumpDate
{
	my $result;
	while(!keys %{$result} && $check_iterations < $max_check_iterations)
	{
		eval {
			$result = $soap->getLastDumpDateEx();
		};
		if($@)
		{
			$logger->error("Error while getLastDumpDateEx: ".$@);
			$logger->info("Retrying...");
		}
		$check_iterations++;
	}
	if(!keys %{$result})
	{
		if($check_iterations == $max_check_iterations)
		{
			$logger->fatal("Exceeded number of check iterations");
			die "Exceeded number of check iterations";
		}
		$logger->fatal("Empty result of getLastDumpDateEx()");
		die "Empty result of getLastDumpDateEx()";
	}
	return $result;
}


sub checkDumpDate
{
	$logger->debug("Checking dump date...");
	my $lastDumpDateEx = getLastDumpDate();
	my $dump_version = $lastDumpDateEx->{dumpFormatVersion};
	$dump_version += 0.0;
	if($dump_version > SUPPORTED_DUMP_VERSION)
	{
		die "Dump version mismatch. Supported ".SUPPORTED_DUMP_VERSION." is lower than in the dump $lastDumpDateEx->{dumpFormatVersion}\n";
	}
	if(defined $lastDocVersion && $lastDumpDateEx->{docVersion} ne $lastDocVersion)
	{
		$MAILTEXT .= "Warning! Documentation changed from version $lastDocVersion to $lastDumpDateEx->{docVersion}\n";
		$logger->warn("Documentation changed from version $lastDocVersion to $lastDumpDateEx->{docVersion}");
	}
	my $lastDumpDateUrgently = $lastDumpDateEx->{lastDumpDateUrgently} / 1000;
	my $lastDumpDate = $lastDumpDateEx->{lastDumpDate} / 1000;
	$logger->debug("RKN last dump date: ".$lastDumpDateUrgently);

	if(!defined $lastDumpDateOld || $force_load || $lastDumpDateUrgently > $lastDumpDateOld || (time()-$lastDumpDateOld) > $max_download_interval)
	{
		$logger->debug("lastDumpDateUrgently > prev. dump date. Working now.");
		return 1;
	}
	$logger->info("Registry has not changed since the last download at ".(scalar localtime $lastDumpDateOld).". lastDumpDateUrgently in the registry is ".(scalar localtime $lastDumpDateUrgently));

	$MAILTEXT .= "Registry has not changed since the last download at ".(scalar localtime $lastDumpDateOld).". lastDumpDateUrgently in the registry is ".(scalar localtime $lastDumpDateUrgently)."\n" if($mail_nofresh_report);

	return 0;
}

sub getParams
{
	my $sth = $DBH->prepare("SELECT param, value FROM zap2_settings");
	$sth->execute or die DBI->errstr;
	while(my $ips = $sth->fetchrow_hashref())
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
		if($param eq 'lastDocVersion')
		{
			$lastDocVersion = $value;
		}
	}
	$sth->finish();
}

sub getParam
{
	my $param = shift;
	my $sth = $DBH->prepare("SELECT param, value FROM zap2_settings WHERE param = ?");
	$sth->bind_param(1, $param);
	$sth->execute or die DBI->errstr;
	my $res;
	while(my $ips = $sth->fetchrow_hashref())
	{
		$res = $ips->{value};
	}
	$sth->finish();
	return $res;
}

sub setParam
{
	my $param = shift;
	my $value = shift;
	my $sth = $DBH->prepare("INSERT INTO zap2_settings (param, value) VALUES(?, ?) ON DUPLICATE KEY UPDATE value = ?");
	$sth->bind_param(1, $param);
	$sth->bind_param(2, $value);
	$sth->bind_param(3, $value);
	$sth->execute() or die DBI->errstr;
}

sub getResult
{
	my $code = shift;
	my $result = 0;
	my $res;
	while(!$result && $ldd_iterations < $max_result_iterations)
	{
		sleep($get_result_sleep_interval);
		$res = $soap->getResult($code);
		$result = int($res->{resultCode});
		$ldd_iterations++;
	}
	if($result != 1)
	{
		die "Too many getResult iterations ($ldd_iterations). Error: $res->{resultComment}\n" if($ldd_iterations >= $max_result_iterations);
		die "getResult error: $res->{resultComment}\n";
	}
	my $dump_version = $res->{dumpFormatVersion};
	$dump_version += 0.0;
	if($dump_version > SUPPORTED_DUMP_VERSION)
	{
		die "Dump version $res->{dumpFormatVersion} in the dump is higher than supported ".SUPPORTED_DUMP_VERSION."\n";
	}
	return decode_base64($res->{registerZipArchive});
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

	formRequest() if($form_request == 1 );

	my $res = $soap->sendRequest($req_file, $sig_file);

	if($res->{result} ne 'true')
	{
		die "Can't get request result: ".$res->{resultComment}."\n";
	}
	$lastCode = $res->{code};
	setParam('lastCode', $lastCode);
	setParam('lastAction', 'sendRequest');
	setParam('lastResult', 'send');
}

sub getDumpFile
{
	my $data = shift;
	unlink $dir.'/dump.xml';
	unlink $dir.'/dump.xml.sig';
	my $file = "arch.zip";
	unless(mkdir($tmp_path))
	{
		if ($! != 17)
		{
			die("Can't create a temp directory: ".$!);
		}
	}
	my $tm=time();
	if($archive_path)
	{
		$file = strftime "arch-%Y-%m-%d-%H_%M_%S.zip", localtime($tm);
	}

	open F, '>'.$tmp_path."/".$file || die "Can't open $dir/$file for writing: ".$!;
	binmode F;
	print F $data;
	close F;
	`unzip -o $tmp_path/$file -d $tmp_path/`;
	if($archive_path)
	{
		my $apath = strftime "$archive_path/%Y/%Y-%m/%Y-%m-%d", localtime($tm);
		make_path($apath);
		copy($tmp_path."/".$file,$apath."/".$file);
		unlink $tmp_path."/".$file;
	}
	$logger->debug("Got result...");
	setParam('lasltAction', 'getResult');
	setParam('lastResult', 'got');
	setParam('lastDumpDate', time());
	my @files = glob($tmp_path."/*.xml");
	return \@files;
}

sub parseFiles
{
	my $files = shift;
	foreach my $file (@{$files})
	{
		parseDump($file);
	}
}

sub parseDuration
{
	my $duration = int(shift || 0);
	return sprintf("%02d:%02d:%02d", $duration/3600, $duration/60%60, $duration%60);
}

sub convertIPv6
{
	my $arr = shift;
	foreach my $ip (@{$arr})
	{
		my @octs = split(/\:/, $ip);
		$ip =~ s/\:\:$/\:0/g if(scalar(@octs) > 6);
		my $ipa = new Net::IP($ip);
		$ip = $ipa->ip();
	}
}

__END__
