package Zapret;

require Exporter;

@ISA = qw/Exporter/;
@EXPORT = qw/$RKN_DUMP_VERSION/;

use utf8;
use strict;
use SOAP::Lite;
use MIME::Base64;

our $RKN_DUMP_VERSION = "2.3";
my $VERSION='0.01';

sub new
{
	my $class=shift;
	my $URL=shift || die("URL not defined");
	my $self={
		service => SOAP::Lite->service($URL)
	};
	bless $self,$class;
	return $self;
}

sub getLastDumpDate
{
	my $this=shift;
	return $this->{service}->getLastDumpDate;
}

sub getLastDumpDateEx
{
	my $this=shift;
	return $this->{service}->getLastDumpDateEx;
}

sub sendRequest
{
	my $this=shift;
	my $requestFile=shift;
	my $signatureFile=shift;
	open XMLREQ, $requestFile;
	my $xmlreq = do { local $/ = undef; <XMLREQ>; };
	close XMLREQ;
	open XMLREQSIG, $signatureFile;
	my $xmlreqsig = do { local $/ = undef; <XMLREQSIG>; };
	close XMLREQSIG;
	return $this->{service}->sendRequest(
		$xmlreq,
		$xmlreqsig,
		$RKN_DUMP_VERSION
	);
}

sub getResult
{
	my $this=shift;
	my $code=shift;
	return $this->{service}->getResult($code);
}

1;
