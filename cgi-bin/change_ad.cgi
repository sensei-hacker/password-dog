#!/usr/bin/perl

use CGI::Lite;
use Net::LDAP;
use Data::Dumper;

use lib './lib';
use Net::LDAP::Extra qw(AD);
require './searchldap.pl';



my $cgi = CGI::Lite->new();
$cgi->deny_uploads(1);
my $param = $cgi->parse_form_data('POST');

my $domain      = $param->{'domain'};
my $oldpasswd   = $param->{'oldpassword'};
my $newpasswd   = $param->{'newpassword'};
my $dn          = $param->{'user'} . '@' . $param->{'domain'};


print "Content-type: text/plain\n\n";

($ldap, $users) = &search_refer({
    domain => $domain,
    dn => $dn,
    password => $oldpasswd,
    base =>  upn_domain_to_base($domain),
    filter => "(userPrincipalName=" . $dn . ")",
    scope => "sub",
    attrs => ['*','entrydn']
});

if (scalar @{$users} > 1) {
    print("More than one user found, not changing password.");
    exit;
}

if (scalar @{$users} < 1) {
    print("No DN found, not changing password.");
    exit;
}

$dn = $users->[0]->{'distinguishedName'}[0];
if ($ldap->is_AD || $ldap->is_ADAM) {
  $mesg = $ldap->change_ADpassword($dn, $oldpasswd, $newpasswd);
}
if ($mesg->code() != 0) {
    warn($mesg->error());
}
if ( $mesg->{'resultCode'} == 19 && $mesg->error() =~ m/CONSTRAINT_ATT_TYPE/ ) {
    print "New password was not accepted by the server.\n";
    exit;
}

print "Changed password for " .  $users->[0]->{'distinguishedName'}[0], "\n";

sub upn_domain_to_base {
    my $base = shift();
    return 'dc=interalname,dc=com' if ( ( $base  eq 'mycompany.com' ) || ($base eq 'sub.mycompany.com') );
    $base =~ s/\./,dc=/g;
    $base =~ s/^/dc=/g;
    return $base;
}

END {
    eval { $ldap->unbind(); };
}

