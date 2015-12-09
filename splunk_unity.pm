package OutputPlugins::splunk_unity;

use strict;
use warnings;

use Data::Dumper;
use SFStreamer;
use XML::Simple;
$Data::Dumper::Indent = 1;

my $info = {
    init => \&init,
    output => \&output,
    description => "Prints IDS events in Splunk (key=value) format",
    #flags => $FLAG_IDS | $FLAG_PKTS | $FLAG_METADATA_4 | $FLAG_POLICY_EVENTS_5 | $FLAG_RUA | $FLAG_RNA_EVENTS_5 | $FLAG_SEND_ARCHIVE_TIMESTAMP,
    flags => $FLAG_IDS | $FLAG_METADATA_4 | $FLAG_SEND_ARCHIVE_TIMESTAMP,
};

my $TSharkLocation; # The location of tshark binary (e.g. /usr/sbin/tshark, /usr/local/bin/tshark)

sub register{
    return $info;
}

sub init{
    my ($opts) = @_;

    # redirect output or use STDOUT
    if($opts->{filename}){
        if($opts->{compress}){
            open OUT, "| /bin/gzip -c > $opts->{filename}.gz" or die "Unable to open gzip file $opts->{filename} for writing: $!";
            autoflush OUT 1;
        }else{
            open OUT, ">", $opts->{filename} or die "Unable to open $opts->{filename} for writing: $!";
            autoflush OUT 1;
        }
    }else{
          *OUT = *STDOUT;
    }
    # if they requested host info, don't request events.  Instead only get metadata records.
    if($opts->{host}){
          $info->{flags} = $FLAG_METADATA_4;
    }
    if($opts->{pcap}) {
        $info->{flags} = $FLAG_IDS | $FLAG_PKTS | $FLAG_METADATA_4 | $FLAG_SEND_ARCHIVE_TIMESTAMP;
    }
    if($opts->{tshark} && !($opts->{pcap})) {
        die "Splunk Unity cannot use tshark without pcap flag";
    }
    if($opts->{tshark}){
        $TSharkLocation = $opts->{tshark}
    }
}

sub tshark_process{
  # take in tv_sec, tv_usec, pktlen, packet_data and return pdml xml
  my ($sec, $usec, $pktlen, $packet_data) = @_;
  my $pcap_file = "tmp.pcap";
  open OUT_PCAP, ">", $pcap_file or die "Unable to open $pcap_file for writing: $!\n";
  # pcap_header is: magic number, major version, minor version, timezone, timestamp accuracy, snaplen, data link type
  my $pcap_header = pack("L",hex("a1b2c3d4")).pack("S",2).pack("S",4).pack("L",0).pack("L",0).pack("L",hex("1ffff")).pack("L",1);
  # packet header is: tv_sec, tv_usec, caplen, pktlen
  my $packet_header = pack("L",$sec).pack("L",$usec).pack("L",$pktlen).pack("L",$pktlen);
  print OUT_PCAP $pcap_header . $packet_header . $packet_data;
  close OUT_PCAP;
  open (TSHARK, '-|', "$TSharkLocation -T pdml -r $pcap_file -l") or die "Cannot open tshark: $!\n";
  my $pdml;
  while (<TSHARK>) { $pdml .= $_ }
  close TSHARK;
  my $simple = XML::Simple->new(ForceArray => 1);
  my $pdml_data = $simple->XMLin($pdml);
  return $pdml_data;
}

sub string_hex{
  my $string = shift;
  my @strarray = unpack('C*', $string);
  my @strhex;
  foreach my $char (@strarray) {
    push @strhex, sprintf("%02X", $char);
  }
  return join("", @strhex);
}

sub string_printable{
  my $string = shift;
  my @strarray = unpack('C*', $string);
  my $strprint = "";
  foreach my $char (@strarray) {
    my $ichar = sprintf("%c", $char);
    if ($ichar =~ m/[[:print:]]/) {
      $strprint .= $ichar;
    } else {
      $strprint .= ".";
    }
  }
  $strprint =~ s/"/%22/g;
  $strprint =~ s/\|/%7C/g;
  $strprint =~ s/=/%3D/g;
  return $strprint;
}

# Parsing Event Data from eStreamer
my %rule_meta = ();
my %sensor_meta = ();
my %priority_meta = ();
my %class_meta = ();
my %events = ();
my $timestamp;

sub output{
    my ($rec) = @_;
    return unless exists $SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}};
    # print OUT Dumper($rec);

    # globals
    my @fields;
    $timestamp = time;
    my $uuid = "";

    # flush events past time limit (only way to get packet data)
    my $eventuuid;
    foreach $eventuuid (keys %events) {
      if (($timestamp - $events{$eventuuid}{eventreceipttime}) > 10) {
        if ($events{$eventuuid}{haspackets}) {
          my $packetsec = $events{$eventuuid}{secs}[0];
          my $packetdata;
          my $packethex;
          my $packetprintable;
          for my $i (0 .. $#{$events{$eventuuid}{packets}}) {
            $packetdata .= $events{$eventuuid}{packets}[$i];
          }
          $packethex = string_hex($packetdata);
          $packetprintable = string_printable($packetdata);
          print OUT $events{$eventuuid}{eventmessage} . "|packet_ascii=$packetprintable|packet_hex=$packethex|first_pkt_sec=$packetsec\n";
        } else {
          print OUT $events{$eventuuid}{eventmessage};
        }
        delete $events{$eventuuid};
      }
    }

    if ($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "RULE") {
      my $sid = $rec->{'signature_id'};
      my $gen = $rec->{'generator_id'};
      foreach my $key (@{$rec->{'order'}}) {
        $rule_meta{$gen.":".$sid}{$key} = $rec->{$key};
      }
      return;
    } elsif ($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "DETECTION ENGINE") {
      if ($rec->{'name_string_length'} > 0) {
        $sensor_meta{$rec->{'id'}}{'sensor_name'} = $rec->{'name_string_data'}
      } else {
        $sensor_meta{$rec->{'id'}}{'sensor_name'} = "null"
      }
      if ($rec->{'desc_string_length'} > 0) {
        $sensor_meta{$rec->{'id'}}{'sensor_desc'} = $rec->{'desc_string_data'}
      } else {
        $sensor_meta{$rec->{'id'}}{'sensor_desc'} = "null"
      }
      return;
    # PRIORITY record type (meta)
    } elsif ($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "PRIORITY") {
      if ($rec->{'name_length'} > 0) {
        $priority_meta{$rec->{'priority_id'}} = $rec->{'name'};
      } else {
        $priority_meta{$rec->{'priority_id'}} = "null";
      }
      return;
    # CLASSIFICATION record type (meta)
    } elsif ($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "CLASSIFICATION") {
      if ($rec->{'name_length'} > 0) {
        $class_meta{$rec->{'class_id'}}{'name'} = $rec->{'name'}
      } else {
        $class_meta{$rec->{'class_id'}}{'name'} = "null"
      }
      if ($rec->{'desc_length'} > 0) {
        $class_meta{$rec->{'class_id'}}{'desc'} = $rec->{'desc'}
      } else {
        $class_meta{$rec->{'class_id'}}{'desc'} = "null"
      }
      return;
    # EVENT record type
    } elsif ($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "EVENT") {
      # get UUID
      $uuid = $rec->{'sensor_id'}.":".$rec->{'event_id'}.":".$rec->{'event_sec'};
      # add timestamps
      push @fields, scalar(localtime($rec->{event_sec}));
      push @fields, "archive_timestamp=$rec->{header}{archive_timestamp}";
      # add EVENT key=value pairs
      foreach my $key (@{$rec->{'order'}}){
        push @fields, "$key=".$rec->{$key} unless $key eq "pad";
      }
      # add RULE meta
      my $sid = $rec->{'sid'};
      my $gen = $rec->{'gen'};
      foreach my $key (keys %{$rule_meta{$gen.":".$sid}}) {
        push @fields, "$key=".$rule_meta{$gen.":".$sid}->{$key} unless $key eq "pad";
      }
      # add DETECTION ENGINE meta
      push @fields, "sensor_name=".$sensor_meta{$rec->{'sensor_id'}}{'sensor_name'};
      push @fields, "sensor_desc=".$sensor_meta{$rec->{'sensor_id'}}{'sensor_desc'};
      # add PRIORITY meta
      push @fields, "priority_name=".$priority_meta{$rec->{'priority'}};
      # add CLASS meta
      push @fields, "class_name=".$class_meta{$rec->{'class'}}{'name'};
      push @fields, "class_desc=".$class_meta{$rec->{'class'}}{'desc'};
      # print the EVENT
      #print OUT join("|", @fields)."\n";
      #autoflush OUT 1;
      $events{$uuid}{eventmessage} = join("|", @fields)."|uuid=$uuid";
      $events{$uuid}{eventreceipttime} = $timestamp;
      return;
    } elsif ($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "PACKET") {
      $uuid = $rec->{'sensor_id'}.":".$rec->{'event_id'}.":".$rec->{'event_sec'};
      return unless exists $events{$uuid};
      $events{$uuid}{haspackets} = 1;
      push @{$events{$uuid}{packets}}, $rec->{"packet_data"};
      push @{$events{$uuid}{secs}}, $rec->{"packet_sec"};
      push @{$events{$uuid}{usecs}}, $rec->{"packet_usec"};
      push @{$events{$uuid}{lens}}, $rec->{"packet_len"};
      return;
    }
}

1;
