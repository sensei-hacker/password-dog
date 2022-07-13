#!/usr/bin/perl

use LWP::UserAgent       ();

my $ua  = LWP::UserAgent->new();

my $r = $ua->get('http://localhost:8080/?' . $ENV{'QUERY_STRING'});
# my $r = $ua->get('http://localhost:8080/?newpassword=rayrayray');


if ($r->is_success) {
    print "Content-type: text/plain\r\n\r\n";
    print ($r->content);
    # print $r->decoded_content, "\n";
} else {
    die $r->status_line;
}

