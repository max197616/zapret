package Zapret;

require Exporter;

@ISA = qw/Exporter/;
@EXPORT = qw/$RKN_DUMP_VERSION/;

use utf8;
use strict;
use SOAP::Lite;
use MIME::Base64;

our $RKN_DUMP_VERSION = "2.3";
my $VERSION='0.02';

sub new
{
	my $class = shift;
	my $wsdl = shift || die("WSDL not defined!\n");
	my $ns = shift || 'http://vigruzki.rkn.gov.ru/OperatorRequest/';
	my $self={
		service => SOAP::Lite->new(proxy => $wsdl, ns => $ns)
	};
	bless $self, $class;
	return $self;
}

sub getLastDumpDateEx
{
	my $this=shift;
	my $res = $this->{service}->call("getLastDumpDateEx");
	die("getLastDumpDateEx: soap error: ".$res->faultcode().": ".$res->faultstring()."(".$res->faultdetail().")") if ($res->fault());
	my $resp = $res->valueof("Body/getLastDumpDateExResponse");
	die("getLastDumpDateEx: Response is empty!") if (!defined($resp));
	return $resp;
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
	my $res = $this->{service}->call('sendRequest',
		SOAP::Data->name("requestFile" => $xmlreq)->type("base64Binary"),
		SOAP::Data->name("signatureFile" => $xmlreqsig)->type("base64Binary"),
		SOAP::Data->name("dumpFormatVersion" => $RKN_DUMP_VERSION)->type("string")
	);
	die("sendRequest: soap error: ".$res->faultcode().": ".$res->faultstring()."(".$res->faultdetail().")") if($res->fault());
	my $resp = $res->valueof("Body/sendRequestResponse");
	die("sendRequest: Response is empty!") if (!defined($resp));
	die("sendRequest: result error: ".$resp->{resultComment}) if ($resp->{result} ne 'true');
	return $resp;
}

sub getResult
{
	my $this=shift;
	my $code=shift;
	my $res;
	eval {
		$res = $this->{service}->call("getResult", SOAP::Data->name("code" => $code));
	};
	die("getResult: soap exception: ".$@) if ($@);
	die("getResult: soap error: ".$res->faultcode().": ".$res->faultstring()."(".$res->faultdetail().")") if ($res->fault());
	my $resp = $res->valueof("Body/getResultResponse");
	die("geResult: Response is empty!") if (!defined($resp));
	return $resp;
}

1;
