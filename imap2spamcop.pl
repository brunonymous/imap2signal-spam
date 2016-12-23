#!/usr/bin/perl
# @author Bruno Ethvignot <bruno at tlk.biz>
# @created 2013-08-05
# @date 2016-12-23
# https://github.com/brunonymous/imap2signal-spam
#
# copyright (c) 2013-2016 TLK Games all rights reserved
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
#
use strict;
use warnings;
use Config::General;
use Date::Parse;
use Data::Dumper;
use FindBin qw( $Bin $Script );
use Getopt::Std;
use IO::Socket::SSL;
use List::Util qw( first );
use MIME::Base64;
use Mail::IMAPClient;
use Mail::Internet;
use Sys::Syslog;
use Time::Local 'timelocal';
use WWW::Mechanize;
use HTTP::Cookies;
use Carp;
my $agent_ref;
my $isVerbose          = 0;
my $isDebug            = 0;
my $isTest             = 0;
my $lastError          = '';
my $ignoreDelay        = 0;
my $spamCounter        = 0;
my $spamIgnoredCounter = 0;
my $spamTooOldCounter  = 0;
my $sysLog_ref;
my %mailboxes = ();
my %accounts  = ();
my $boxIdFilter;
my $spamcopURL;
my $defaultAccount;
my $client;
my $mech;

init();
run();

#eval {
#    init();
#    run();
#};
#if ($@) {
#    sayError($lastError);
#    sayError("(!) $Script was failed!");
#    confess $lastError;
#}

sub END {
    closeBox();
    Sys::Syslog::closelog();
}

sub run {
    foreach my $id ( keys %mailboxes ) {
        next if defined $boxIdFilter and $boxIdFilter ne $id;
        my $mailbox_ref = $mailboxes{$id};
        if ( !$mailbox_ref->{'enabled'} ) {
            sayInfo("(*) '$id' box is disabled");
            next;
        }
        sayInfo('------------------------------------------------------');
        sayInfo("(*) process '$id' box");
        my $account
            = exists $mailbox_ref->{'spamcop-account'}
            ? $mailbox_ref->{'spamcop-account'}
            : $defaultAccount;
        die sayError("(!) run() '$account' not found")
            if !exists $accounts{$account};
        my $subjectRegex;
        if ( exists $mailbox_ref->{'subject-regex'} ) {
            $subjectRegex = $mailbox_ref->{'subject-regex'};
        }
        eval {
            openBox($mailbox_ref);
            messagesProcess(
                $accounts{$account},
                $mailbox_ref->{'delay'},
                $mailbox_ref->{'target-folder'},
                $subjectRegex
            );
        };
        if ($@) {
            sayError($@);
            next;
        }
    }
    sayInfo("(*) total number of message(s) reported: $spamCounter");
    sayInfo("(*) total number of message(s) ignored: $spamIgnoredCounter");
    sayInfo("(*) total number of message(s) too old: $spamTooOldCounter");
}

sub messagesProcess {
    my ( $account_ref, $delay, $targetFolder, $subjectRegex ) = @_;
    spamcopLogin($account_ref);
    my @messages = $client->messages();

    sayInfo(
        "- messagesProcess() " . scalar(@messages) . " message(s) found" );
    my $count                 = 0;
    my $boxSpamCounter        = 0;
    my $boxSpamIgnoredCounter = 0;
MESSAGESLOOP:
    foreach my $msgId (@messages) {
        sayDebug("- messagesProcess() flag($msgId)");

        my @flagHash = $client->flags($msgId);
        next if first { $_ eq '\\Deleted' } @flagHash;
        $count++;

        sayDebug("- messagesProcess() parse_headers($msgId)");
        my $hashref = $client->parse_headers( $msgId, 'Subject' )
            or die sayError("parse_headers failed: $@");
        my $subject = $hashref->{'Subject'}->[0];
        my $date    = $client->internaldate($msgId)
            or die sayError("Could not internaldate: $@");
        sayInfo( sprintf( "%04d", $count ) . "$date / $subject" );

        #next;
        my $mailTime = str2time($date);

        if ( defined $mailTime ) {
            my $delta = time - $mailTime;
            if ( $delay > 0 and $delta < $delay ) {
                sayInfo(  "messagesProcess() The email is ignored for "
                        . "the moment: $delta < $delay" );
                $spamIgnoredCounter++;
                $boxSpamIgnoredCounter++;
                next;
            }
        }
        else {
            sayError("messagesProcess() $date not valid");
        }

        my $string = $client->message_string($msgId)
            or die sayError("Could not message_string: $@");

        # Message is larger than maximum size, 50,000 bytes.  Truncate it.
        $string = substr( $string, 0, 49999 );
        next if $isTest;
        my $tryCount = 3;
        my $res      = '';
    SPAMCOPTRY:
        while ( $tryCount > 1 ) {
            sayDebug("Try $tryCount");
            eval { $res = spamcomProcess($string); };
            if ($@) {
                sayError($@);
                next MESSAGESLOOP;
            }
            if ( $res eq 'No data / Too much data' ) {
                spamcopLogout($account_ref);
                spamcopLogin($account_ref);
                $tryCount--;
            }
            else {
                last SPAMCOPTRY;
            }
        }
        die $res if $tryCount == 0;
        my $oldUid = $client->Uid();
        $client->Uid(1);
        $client->move( $targetFolder, $msgId )
            or die sayError("Could not move: $@");
        $client->Uid($oldUid);
        sayInfo("messagesProcess() The email has been moved.");
        $boxSpamCounter++;
    }
    $client->expunge();
    sayInfo(" - $boxSpamCounter message(s) were reported");
    sayInfo(" - $boxSpamIgnoredCounter message(s) were ignored");
    spamcopLogout($account_ref);
}

sub spamcopLogin {
    my ($account_ref) = @_;
    my $response = $mech->get( $account_ref->{'url'} );
    die sayError("WWW::Mechanize:get($account_ref->{url}) was failed")
        if !defined $response;
    if ( !$response->is_success() ) {
        my $message = $response->status_line();
        die sayError($message);
    }
    $mech->form_number(1);
    $mech->field( 'username', $account_ref->{'username'} );
    $mech->field( 'password', $account_ref->{'password'} );
    $response = $mech->click();
    die sayError("WWW::Mechanize:click was failed") if !defined $response;
    if ( !$response->is_success() ) {
        my $message = $response->status_line();
        die sayError($message);
    }
    my $content = $response->content();
    if ($isDebug) {
        if ($content =~ m{</div><div\ id="login">[\r\n]
        <form\ method="post"\ action="https://www\.spamcop\.net/sc">[\r\n]
        <div>[\r\n]
        (.*)[\r\n]
        &nbsp;.*$}xs
            )
        {
            my $name = $1;
            sayDebug("Welcome $name!");
        }
        else {
            print $content;
            sayError("Display name was not found!");
        }
    }
    sayDebug( 'The authentication of the '
            . $account_ref->{'username'}
            . ' user was successful!' );
}

sub spamcopLogout {
    my ($account_ref) = @_;
    my $form = $mech->form_number(1);
    if ( !defined $form ) {
        my $str = $mech->content();
        print STDERR $str;
        die sayError("WWW::Mechanize::form_number(1) was failed");
    }
    my $response = $mech->click();
    die sayError("WWW::Mechanize::click() was failed") if !defined $response;
    if ( !$response->is_success() ) {
        my $message = $response->status_line();
        die sayError($message);
    }
    #my $content = $response->content();
    sayDebug( 'The logout of the '
            . $account_ref->{'username'}
            . ' user was successful!' );
}

sub spamcomProcess {
    my ($spam) = @_;
    sayDebug( 'Size of spam: ' . length($spam) . ' bytes.' );
    my $timestart = time;

    my $form = $mech->form_number(2);
    if ( !defined $form ) {
        my $str = $mech->content();
        if ( $str =~ m{<strong>(No data / Too much data)</strong>} ) {
            my $err = $1;
            sayError($err);
            return $err;
        }
        else {
            die sayError("WWW::Mechanize::form_number(2) was failed");
        }
    }
    $mech->field( 'spam', $spam );
    sayDebug('Click on "Process Spam" button');
    sayDebug( 'Form action: ' . $form->action() );
    my $response = $mech->click();
    die sayError("WWW::Mechanize::click() was failed") if !defined $response;
    if ( !$response->is_success() ) {
        my $message = $response->status_line();
        die sayError($message);
    }
    my $content = $response->content();
    return if isEmailTooOld($content);

WAITREFRESH:
    while (1) {
        if ($content =~ m{\(or\ click\ reload\ if\ this\ page
                        \ does\ not\ refresh\ automatically\ in\s+
                        .(\d+)\ seconds\.\)}xs
            )
        {
            my $seconds = $1;
            my $uri     = $mech->uri();
            sayDebug("You must wait $seconds seconds.");
            sleep $seconds;
            $response = $mech->get($uri);
            if ( !$response->is_success() ) {
                my $message = $response->status_line();
                die sayError($message);
            }
            $content = $response->content();
        }
        else {
            last WAITREFRESH;
        }
    }
    return '' if isEmailTooOld($content);

    $form = $mech->form_number(2);
    if ( !defined $form ) {
        sayDebug($content);
        die sayError("WWW::Mechanize::form_number(2) was failed");
    }
    sayDebug('Click on "Send Spam Report(s) Now"');
    sayDebug( 'Form action: ' . $form->action() );
    $response = $mech->click();
    die sayError("WWW::Mechanize::click() was failed") if !defined $response;
    if ( !$response->is_success() ) {
        my $message = $response->status_line();
        die sayError($message);
    }
    $content = $response->content();

    if ( $content =~ m{^(Welcome,\s.*\.\s+You\shave\s.*\savailable\.)$}xms ) {
        my $welcome = $1;
        $welcome =~ s{\s{2,}}{ }g;
        sayInfo($welcome);
    }
    if ($content =~ m{(Your\s<a\s[^>]+>\n
                  average\sreporting\stime</a>\s
                  is:\s+.*;\nGreat!\n)}xms
        )
    {
        my $average = $1;
        $average =~ s{\n}{ }g;
        $average =~ s{</?a[^>]*>}{}g;
        $average =~ s{\s{2,}}{ }g;
        sayInfo($average);
    }
    $spamCounter++;
    sayInfo( 'Processing time spam: ' . ( time - $timestart ) . ' seconds' );
    return '';
}

sub isEmailTooOld {
    my ($content) = @_;
    if ($content =~ m{<div\ class="error">(Sorry,\ this\ email\ is\ too
        \ old\ to\ file\ a\ spam\ report\.\ \ You\ must
        \ report\ spam\ within\ 2\ days\ of\ receipt\.
        \ \ This\ mail\ was\ received\ on[^<]+)</div>}xms
        )
    {
        my $error = $1;
        $error =~ s{\s{2,}}{ }g;
        sayError($error);
        $spamTooOldCounter++;
        return 1;
    }
    return 0;
}

sub openBox {
    my ($mailbox_ref) = @_;
    my $port          = $mailbox_ref->{'port'};
    my $username      = $mailbox_ref->{'username'};
    my $socket;

    # IMAP over SSL
    if ( $port == 993 ) {
        $socket = IO::Socket::SSL->new(
            'Proto'    => 'tcp',
            'PeerAddr' => $mailbox_ref->{'server'},
            'PeerPort' => $port
            )
            or die sayError(
            "openBox($username) new IO::Socket::SSLsocket() failed: $@");
        my $greeting = <$socket>;
        sayInfo($greeting);
        my ( $id, $answer ) = split /\s+/, $greeting;
        die sayError("problems logging in: $greeting") if $answer ne 'OK';
        $client = Mail::IMAPClient->new(
            'Socket'   => $socket,
            'User'     => $username,
            'Password' => $mailbox_ref->{'password'},
            'Debug'    => 0,
            'Server'   => $mailbox_ref->{'server'},
            'Uid'      => 1,
            'Fast_IO'  => 1,
            'Peek'     => 1,

            #'Timeout'  => 60
            )
            or die sayError(
            "openBox($username) new Mail::IMAPClient() failed: $@");
        $client->login()
            or die sayError( "openBox($username): "
                . "login() failed "
                . $client->LastError() );
    }
    else {

        # IMAP
        $client = Mail::IMAPClient->new(
            'User'     => $username,
            'Password' => $mailbox_ref->{'password'},
            'Timeout'  => 60,
            'Debug'    => 0,
            'Server'   => $mailbox_ref->{'server'},
            )
            or die sayError(
            "openBox($username) new Mail::IMAPClient() failed: $@");
    }

    $client->State( Mail::IMAPClient::Connected() );

    #$client->Socket($socket);

    if ($isDebug) {
        my @folders = $client->folders();
        sayDebug( join( "\n* ", 'Folders:', @folders ), "\n" );
    }

    $client->select( $mailbox_ref->{'junk'} )
        or die sayError( "openBox($username) "
            . "Mail::IMAPClient::select($mailbox_ref->{'junk'}) "
            . "failed: "
            . $client->LastError() );
}

sub closeBox {
    if ( defined $client and $client->IsAuthenticated() ) {
        sayInfo("(*) logout");
        $client->logout();
        undef($client);
    }
}

sub init {
    getOptions();
    print STDOUT '$Script $Revision$' . "\n"
        if $isVerbose;
    readConfig();
    if ( defined $sysLog_ref ) {
        Sys::Syslog::setlogsock( $sysLog_ref->{'sock_type'} );
        my $ident = $main::0;
        $ident =~ s,^.*/([^/]*)$,$1,;
        Sys::Syslog::openlog(
            $ident,
            "ndelay,$sysLog_ref->{'logopt'}",
            $sysLog_ref->{'facility'}
        );
    }

    $mech = WWW::Mechanize->new(
        'agent'      => $agent_ref->{'agent'},
        'cookie_jar' => HTTP::Cookies->new(
            file           => $ENV{'HOME'} . '/.' . $Script . '.cookie',
            autosave       => 0,
            ignore_discard => 0
        )
    );
}

sub readConfig {
    my $confFound      = 0;
    my $configFileName = $Script;
    $configFileName =~ s{\.pl$}{\.conf};

    foreach my $pathname ( '.', '/etc', $ENV{'HOME'} . '/.imap2signal-spam' )
    {
        my $filename = $pathname . '/' . $configFileName;
        next if !-e $filename;
        $confFound = 1;
        my %config = Config::General->new($filename)->getall();

        readAgentSection( $config{'user-agent'} )
            if exists $config{'user-agent'};

        # read signal spam account(s)
        readSpamcopSection( $config{'spamcop'} )
            if exists $config{'spamcop'};

        # read IMAP box(es)
        readMailboxSections( $config{'mailbox'} )
            if exists $config{'mailbox'};

        if ( exists $config{'syslog'} ) {
            $sysLog_ref = $config{'syslog'};
            die sayError("(!) readConfig(): 'logopt' not found")
                if !exists $sysLog_ref->{'logopt'};
            die sayError("(!) readConfig(): 'facility' not found")
                if !exists $sysLog_ref->{'facility'};
            die sayError("(!) readConfig(): 'sock_type' not found")
                if !exists $sysLog_ref->{'sock_type'};
        }
        $confFound = 1;
    }
    die sayError("(!) readConfig(): no configuration file has been found!")
        if !$confFound;
    die sayError("(!) readConfig(): 'user-agent' section not found! ")
        if !defined $agent_ref;
    die sayError("(!) readConfig(): 'spamcop' entry not found! ")
        if scalar( keys %accounts ) == 0;
    die sayError("(!) readConfig(): 'mailbox' entry not found! ")
        if scalar( keys %mailboxes ) == 0;
}

sub readAgentSection {
    my ($ua_ref) = @_;
    die sayError("(!) readAgentSecion(): agent string  not found! ")
        if !exists $ua_ref->{'agent'};
    die sayError("(!) readAgentSecion(): agent timeout not found! ")
        if !exists $ua_ref->{'timeout'};
    die sayError("(!) readAgentSecion(): bad format for agent timeout! ")
        if $ua_ref->{'timeout'} !~ m{^\d+$};
    $agent_ref = $ua_ref;
}

sub readSpamcopSection {
    my ($spamcop_ref) = @_;
    die sayError("(!) readSpamcopSection(): signal-spam URL not found! ")
        if !exists $spamcop_ref->{'url'};
    $spamcopURL = $spamcop_ref->{'url'};
    die sayError("(!) readSpamcopSection(): 'account' entry not found! ")
        if !exists $spamcop_ref->{'account'};
    if ( ref( $spamcop_ref->{'account'} ) eq 'ARRAY' ) {
        foreach my $account_ref ( @{ $spamcop_ref->{'account'} } ) {
            putAccount($account_ref);
        }
    }
    elsif ( ref( $spamcop_ref->{'account'} ) eq 'HASH' ) {
        putAccount( $spamcop_ref->{'account'} );
    }
    else {
        die sayError( "(!) readSpamcopSection bad statement"
                . " of the 'signal-spam' section" );
    }
}

sub putAccount {
    my ($account_ref) = @_;
    die sayError("(!)putAccount() account has not 'username'")
        if !exists $account_ref->{'username'};
    my $username = $account_ref->{'username'};
    $defaultAccount = $username if !defined $defaultAccount;
    die sayError("(!)putAccount() duplicate '$username' username")
        if exists $accounts{$username};
    $accounts{$username} = $account_ref;
    $account_ref->{'url'} = $spamcopURL
        if !exists $account_ref->{'url'};
}

sub readMailboxSections {
    my ($mailboxes_ref) = @_;
    if ( ref($mailboxes_ref) eq 'ARRAY' ) {
        foreach my $mailbox_ref ( @{$mailboxes_ref} ) {
            putMailbox($mailbox_ref);
        }
    }
    elsif ( ref($mailboxes_ref) eq 'HASH' ) {
        putMailbox($mailboxes_ref);
    }
    else {
        die sayError( "readMailboxSections() bad statement "
                . "of the 'mailbox' section" );
    }
}

sub putMailbox {
    my ($mailbox_ref) = @_;
    die sayError("(!)putMailbox() mailbox has not 'id'")
        if !exists $mailbox_ref->{'id'};
    my $id = $mailbox_ref->{'id'};
    delete $mailbox_ref->{'id'};
    confess sayError("(!)putMailbox() duplicate mailbox '$id' id")
        if exists $mailboxes{$id};
    $mailboxes{$id} = $mailbox_ref;
    $mailbox_ref->{'enabled'} = 1
        if !exists $mailbox_ref->{'enabled'};
    if ( !exists( $mailbox_ref->{'delay'} ) ) {
        $mailbox_ref->{'delay'} = 0;
    }
    else {
        my $delay = $mailbox_ref->{'delay'};
        $delay = 0 if $ignoreDelay;
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
            die sayError( "bad delay format: $delay. "
                    . "Format excepted: 60, 60s, 60m, 24h or 15d" );
        }
    }
}

sub sayError {
    my ($message) = @_;
    $message =~ s{(\n|\r)}{}g;
    setlog( 'info', $message );
    print STDERR $message . "\n"
        if $isVerbose;
    $lastError = $message;
    return $message;
}

sub sayInfo {
    my ($message) = @_;
    $message =~ s{(\n|\r)}{}g;
    setlog( 'info', $message );
    print STDOUT $message . "\n"
        if $isVerbose;
}

sub sayDebug {
    return if !$isDebug;
    my ($message) = @_;
    $message =~ s{(\n|\r)}{}g;
    setlog( 'info', $message );
    print STDOUT $message . "\n"
        if $isVerbose;
}

sub setlog {
    my ( $priorite, $message ) = @_;
    return if !defined $sysLog_ref;
    Sys::Syslog::syslog( $priorite, '%s', $message );
}

sub getOptions {
    my %opt;
    getopts( 'idvtb:', \%opt ) || HELP_MESSAGE();
    $isVerbose   = 1         if exists $opt{'v'} and defined $opt{'v'};
    $isTest      = 1         if exists $opt{'t'} and defined $opt{'t'};
    $isDebug     = 1         if exists $opt{'d'} and defined $opt{'d'};
    $ignoreDelay = 1         if exists $opt{'i'} and defined $opt{'i'};
    $boxIdFilter = $opt{'b'} if exists $opt{'b'} and defined $opt{'b'};
    print STDOUT "isTest = $isTest\n" if $isTest;
}

sub HELP_MESSAGE {
    print <<ENDTXT;
Usage: 
 $Script [-i -d -v -b boxId -t] 
  -v verbose mode
  -d debug mode
  -b boxId
  -t mode test 
  -i ignore delay
ENDTXT
    exit 0;
}

