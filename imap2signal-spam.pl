#!/usr/bin/perl
# @author Bruno Ethvignot <bruno@tlk.biz>
# @created 2008-03-27
# @date 2008-03-29
# http://code.google.com/p/imap2signal-spam/source/checkout
#
# copyright (c) 2008 TLK Games all rights reserved
# $Id$
#
# imap2signal-spam is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# imap2signal-spam is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.
#/
use strict;
use LWP::UserAgent;
use Mail::IMAPClient;
use IO::Socket::SSL;
use MIME::Base64;
use Data::Dumper;
use List::Util qw( first );
use Config::General;
use Getopt::Std;
use Time::Local 'timelocal';
$Getopt::Std::STANDARD_HELP_VERSION = 1;

my $agent_ref;
my %mailboxes = ();
my $signalSpamURL;
my %accounts = ();
my $defaultAccount;
my $configFileName = 'imap2signal-spam.conf';
my $isVerbose      = 0;
my $isDebug        = 0;
my $isTest         = 0;
my $boxIdFilter;
my $client;
my $user_agent;
my %month = (
    'Jan' => 1,
    'Feb' => 2,
    'Mar' => 3,
    'Apr' => 4,
    'May' => 5,
    'Jun' => 6,
    'Jul' => 7,
    'Aug' => 8,
    'Sep' => 9,
    'Oct' => 10,
    'Nov' => 11,
    'Dec' => 12
);

print STDOUT "imap2signal-spam.pl";
init();
run();

## @method void END()
sub END {
    closeBox();
}

## @method void run()
sub run {
    foreach my $id ( keys %mailboxes ) {
        next if defined $boxIdFilter and $boxIdFilter ne $id;
        print "read $id\n";
        my $mailbox_ref = $mailboxes{$id};
        next if !$mailbox_ref->{'enabled'};
        my $account
            = exists $mailbox_ref->{'singal-spam-account'}
            ? $mailbox_ref->{'singal-spam-account'}
            : $defaultAccount;
        die "(!) run() '$account' not found" if !exists $accounts{$account};

        openBox($mailbox_ref);
        messagesProcess( $accounts{$account}, $mailbox_ref->{'delay'} );
    }

}

## @method messagesProcess($account_ref)
# @param $account_ref
sub messagesProcess {
    my ( $account_ref, $delay ) = @_;
    my @messages = $client->messages();
    print STDOUT "- messagesProcess() "
        . scalar(@messages)
        . " message(s) found\n"
        if $isVerbose;
    my $count = 0;
    foreach my $msgId (@messages) {
        my @flagHash = $client->flags($msgId);
        next if first { $_ eq '\\Deleted' } @flagHash;
        $count++;
        my $hashref = $client->parse_headers( $msgId, 'Subject' )
            or die "parse_headers failed: $@\n";
        my $subject = $hashref->{'Subject'}->[0];
        my $date    = $client->internaldate($msgId)
            or die "Could not internaldate: $@\n";
        print STDOUT sprintf( "%04d $date / $subject \n", $count )
            if $isVerbose;

        # check 09 Jul 1999 13:10:55 -0000 date format
        die "bad date format: $date"
            if $date !~ m/^(\d{2})\-        #$1 = day of the month       
                          ([a-zA-Z]{3})\-  #$2 = month
                          (\d{4})\         #$3 = year
                          (\d{2}):         #$4 = hour
                          (\d{2}):         #$5 = minute
                          (\d{2})\         #$6 = second
                          (\+|\-)\d{4}$/xms;
        die "Bad month format: $2" if !exists $month{$2};

        #timelocal($sec,$min,$hour,$mday,$mon,$year);

        my $mailTime = timelocal( $6, $5, $4, $1, $month{$2} - 1, $3 - 1900 );
        my $delta = time - $mailTime;
        if ( $delta < $delay ) {
            print STDOUT "messagesProcess() The email is ignored for "
                . "the moment: $delta < $delay\n"
                if $isVerbose;
            next;
        }
        my $string = $client->message_string($msgId)
            or die "Could not message_string: $@\n";

        next if $isTest;
        post( $string, $account_ref );
        $client->delete_message($msgId)
            or die "Could not delete_message: $@\n";
        print STDOUT "messagesProcess() The email has been deleted\n"
            if $isVerbose;
    }
}

## @method void post($msg, account_ref)
# @param $msg
# @param $account_ref
sub post {
    my ( $msg, $account_ref ) = @_;

    $msg = 'message=' . encode_base64($msg);
    my $req = HTTP::Request->new( 'POST' => $account_ref->{'url'} );
    die "'Can't create HTTP::Request object!" if !defined $req;
    $req->content_type('application/x-www-form-urlencoded');
    $req->authorization_basic( $account_ref->{'username'},
        $account_ref->{'password'} );
    $req->content($msg);
    my $response = $user_agent->request($req);
    if ( !$response->is_success() ) {
        my $message = $response->status_line();
        die $message;
    }
    print $response->content;

}

## @method void openBox($mailbox_ref)
# @params $mailbox_ref
sub openBox {
    my ($mailbox_ref) = @_;

    my $socket = IO::Socket::SSL->new(
        'PeerAddr' => $mailbox_ref->{'server'},
        'PeerPort' => $mailbox_ref->{'port'},
    ) or die "socket(): $@";

    my $greeting = <$socket>;
    print STDOUT $greeting
        if $isVerbose;
    my ( $id, $answer ) = split /\s+/, $greeting;
    die "problems logging in: $greeting" if $answer ne 'OK';

    $client = Mail::IMAPClient->new(
        'Socket'   => $socket,
        'User'     => $mailbox_ref->{'username'},
        'Password' => $mailbox_ref->{'password'},
    ) or die "new(): $@";

    #$client->Debug(1);
    $client->State( Mail::IMAPClient::Connected() );
    $client->login() or die 'login(): ' . $client->LastError();

    if ($isDebug) {
        my @folders = $client->folders();
        print STDOUT join( "\n* ", 'Folders:', @folders ), "\n";
    }

    $client->select( $mailbox_ref->{'junk'} ) or die $client->LastError();

}

## @method void closeBox()
sub closeBox {
    if ( defined $client and $client->IsAuthenticated() ) {
        print "(*) logout\n";
        $client->logout();
        undef($client);
    }
}

## @method void init()
sub init {
    getOptions();
    readConfig();
    print Dumper \%mailboxes;
    $user_agent = LWP::UserAgent->new(
        'agent'   => $agent_ref->{'agent'},
        'timeout' => $agent_ref->{'timeout'}
    );
}

## @method void readConfig()
sub readConfig {
    foreach my $pathname ( '.', '~./.imap2signal-spam', '/etc' ) {
        my $filename = $pathname . '/' . $configFileName;
        next if !-e $filename;
        my %config = Config::General->new($filename)->getall();

        #print Dumper ( \%config );

        die "(!) readConfig(): 'user-agent' entry not found! "
            if !exists $config{'user-agent'};
        $agent_ref = $config{'user-agent'};
        die "(!) readConfig(): agent string  not found! "
            if !exists $agent_ref->{'agent'};
        die "(!) readConfig(): agent timeout not found! "
            if !exists $agent_ref->{'timeout'};
        die "(!) readConfig(): bad format for agent timeout ! "
            if $agent_ref->{'timeout'} !~ m{^\d+$};

        # read signal spam account(s)
        die "(!) readConfig(): 'signal-spam' entry not found! "
            if !exists $config{'signal-spam'};
        my $signal_ref = $config{'signal-spam'};
        die "(!) readConfig(): signal-spam URL not found! "
            if !exists $signal_ref->{'url'};
        $signalSpamURL = $signal_ref->{'url'};
        die "(!) readConfig(): 'account' entry not found! "
            if !exists $signal_ref->{'account'};
        if ( ref( $signal_ref->{'account'} ) eq 'ARRAY' ) {
            foreach my $account_ref ( @{ $signal_ref->{'account'} } ) {
                putAccount($account_ref);
            }
        }
        elsif ( ref( $signal_ref->{'account'} ) eq 'HASH' ) {
            putAccount( $signal_ref->{'account'} );
        }
        else {
            die "Bad statement of the 'mailbox' section";
        }

        # read IMAP box(es)
        die "(!) readConfig(): 'mailbox' entry not found! "
            if !exists $config{'mailbox'};
        if ( ref( $config{'mailbox'} ) eq 'ARRAY' ) {
            foreach my $mailbox_ref ( @{ $config{'mailbox'} } ) {
                putMailbox($mailbox_ref);
            }
        }
        elsif ( ref( $config{'mailbox'} ) eq 'HASH' ) {
            putMailbox( $config{'mailbox'} );
        }
        else {
            die "Bad statement of the 'mailbox' section";
        }
    }
}

## @method void putMailbox($mailbox_ref)
# @param $mailbox_ref
sub putMailbox {
    my ($mailbox_ref) = @_;
    die "(!)putMailbox() mailbox has not 'id'"
        if !exists $mailbox_ref->{'id'};
    my $id = $mailbox_ref->{'id'};
    delete $mailbox_ref->{'id'};
    die "(!)putMailbox() duplicate mailbox '$id' id"
        if exists $mailboxes{$id};
    $mailboxes{$id} = $mailbox_ref;
    $mailbox_ref->{'enabled'} = 1
        if !exists $mailbox_ref->{'enabled'};
    if ( !exists( $mailbox_ref->{'delay'} ) ) {
        $mailbox_ref->{'delay'} = 0;
    }
    else {
        my $delay = $mailbox_ref->{'delay'};
        if ( $delay =~ m{^(\d+)s?$} ) {
            $mailbox_ref->{'delay'} = $1;
        }
        elsif ( $delay =~ m{^(\d+)m$} ) {
            $mailbox_ref->{'delay'} = $1 * 60;
        }
        elsif ( $delay =~ m{^(\d+)h$} ) {
            $mailbox_ref->{'delay'} = $1 * 3600;
        }
        elsif ( $delay =~ m{^(\d+)d$} ) {
            $mailbox_ref->{'delay'} = $1 * 86400;
        }
        else {
            die "bad delay format: $delay. "
                . "Format excepted: 60, 60s, 60m, 24h or 15d";
        }
    }
}

## @method void putAccount($account_ref)
# @param $account_ref
sub putAccount {
    my ($account_ref) = @_;
    die "(!)putAccount() account has not 'username'"
        if !exists $account_ref->{'username'};
    my $username = $account_ref->{'username'};
    $defaultAccount = $username if !defined $defaultAccount;
    die "(!)putAccount() duplicate '$username' username"
        if exists $accounts{$username};
    $accounts{$username} = $account_ref;
    $account_ref->{'url'} = $signalSpamURL
        if !exists $account_ref->{'url'};
}

## @method void getOptions()
sub getOptions {
    my %opt;
    getopts( 'dvtb:', \%opt ) || HELP_MESSAGE();
    $isVerbose   = 1         if exists $opt{'v'} and defined $opt{'v'};
    $isTest      = 1         if exists $opt{'t'} and defined $opt{'t'};
    $isDebug     = 1         if exists $opt{'d'} and defined $opt{'d'};
    $boxIdFilter = $opt{'b'} if exists $opt{'b'} and defined $opt{'b'};
    print "isTest = $isTest" if $isTest;
}

## @method void HELP_MESSAGE()
# Display help message
sub HELP_MESSAGE {
    print <<ENDTXT;
Usage: 
 imap2signal-spam.pl [-v -b boxId -t] 
  -v verbose mode
  -d debug mode
  -b boxId
  -t mode test 
ENDTXT
    exit 0;
}

