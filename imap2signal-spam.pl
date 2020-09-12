#!/usr/bin/perl
# @author Bruno Ethvignot <bruno at tlk.biz>
# @created 2008-03-27
# @date 2020-09-12
# https://github.com/brunonymous/imap2signal-spam
#
# copyright (c) 2008-2020 TLK Games all rights reserved
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
use utf8;
use Carp;
use Config::General;
use Data::Dumper;
use FindBin qw( $Bin $Script );
use Getopt::Std;
use HTTP::Cookies;
use IO::Socket::SSL;
use List::Util qw( first );
use Mail::IMAPClient;
use Mail::Internet;
use MIME::Base64;
use Sys::Syslog;
use Time::Local 'timelocal';
use WWW::Mechanize;
use vars qw($VERSION);
$VERSION                            = '1.5.1';
$Getopt::Std::STANDARD_HELP_VERSION = 1;

my %userAgent = ();
my %mailboxes = ();
my $signalSpamURL;
my $signalSpamLoginURL;
my %accounts = ();
my $sysLog_ref;
my $defaultAccount;
my $configFileName = 'imap2signal-spam.conf';
my $isVerbose      = 0;
my $isDebug        = 0;
my $isTest         = 0;
my $ignoreDelay    = 0;
my $boxIdFilter;
my $mech;
my $client;
my $cookie_jar;

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
my $spamCounter        = 0;
my $spamIgnoredCounter = 0;

eval {
    init();
    run();
};
if ($@) {
    sayError($@);
    sayError("(!) imap2signal-spam.pl failed!");
    die $@;
}

#** @function END()
#*
sub END {
    closeBox();
    Sys::Syslog::closelog();
}

#** @function public run()
#*
sub run {
    foreach my $id ( keys %mailboxes ) {
        next if defined $boxIdFilter and $boxIdFilter ne $id;
        my $mailbox_ref = $mailboxes{$id};
        if ( !$mailbox_ref->{'enabled'} ) {
            sayInfo("(*) '$id' box is disabled\n");
            next;
        }
        sayInfo("(*) process '$id' box\n");
        my $account
            = exists $mailbox_ref->{'singal-spam-account'}
            ? $mailbox_ref->{'singal-spam-account'}
            : $defaultAccount;
        die "(!) run() '$account' not found" if !exists $accounts{$account};
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
    sayInfo("(*) total number of message(s) reported: $spamCounter\n");
    sayInfo("(*) total number of message(s) ignored: $spamIgnoredCounter\n");
}

#** @function public messagesProcess($account_ref)
# @param account_ref - required hashref
#*
sub messagesProcess {
    my ( $account_ref, $delay, $targetFolder, $subjectRegex ) = @_;
    signalSpamLogin($account_ref);
    my @messages      = $client->messages();
    my $totalMessages = scalar(@messages);
    sayInfo(
        "- messagesProcess() " . $totalMessages . " message(s) found\n" );
    my $count                 = 0;
    my $boxSpamCounter        = 0;
    my $boxSpamIgnoredCounter = 0;

    foreach my $msgId (@messages) {
        sayDebug('======================================');
        sayDebug("- messagesProcess() flag($msgId)\n");

        my @flagHash = $client->flags($msgId);
        next if first { $_ eq '\\Deleted' } @flagHash;
        $count++;

        sayDebug( $count . '/'
                . $totalMessages
                . ") messagesProcess() parse_headers($msgId)\n" );
        my $hashref = $client->parse_headers( $msgId, 'Subject' )
            or die "parse_headers failed: $@\n";
        my $subject = $hashref->{'Subject'}->[0];
        $subject = '' if !defined $subject;
        my $date = $client->internaldate($msgId)
            or die "Could not internaldate: $@\n";
        sayInfo( sprintf( "%04d", $count ) . "$date / $subject \n" );

        # check 09 Jul 1999 13:10:55 -0000 date format
        die "bad date format: $date"
            if $date !~ m/^(\d{2})\-       #$1 = day of the month       
                          ([a-zA-Z]{3})\-  #$2 = month
                          (\d{4})\         #$3 = year
                          (\d{2}):         #$4 = hour
                          (\d{2}):         #$5 = minute
                          (\d{2})\         #$6 = second
                          (\+|\-)\d{4}$/xms;
        die "messagesProcess()  bad month format: $2" if !exists $month{$2};

        #timelocal($sec,$min,$hour,$mday,$mon,$year);

        my $mailTime;
        eval {
            $mailTime
                = timelocal( $6, $5, $4, $1, $month{$2} - 1, $3 - 1900 );
        };
        if ( defined $mailTime ) {
            my $delta = time - $mailTime;
            if ( $delay > 0 and $delta < $delay ) {
                sayInfo(  "messagesProcess() The email is ignored for "
                        . "the moment: $delta < $delay\n" );
                $spamIgnoredCounter++;
                $boxSpamIgnoredCounter++;
                next;
            }
        }
        else {
            sayError("messagesProcess() $date not valid\n");
        }
        my $string = $client->message_string($msgId)
            or die "Could not message_string: $@\n";

        # FIXME try to remove the "*****SPAM*****" string ,
        # but Mail::Intenet modify the original e-mail :-(
        if ( defined $subjectRegex ) {
            my @arrayMail = split( /\n/, $string );
            my $email = Mail::Internet->new( \@arrayMail );
            $subject = $email->get('Subject');
            $subject =~ s{(\n|\r)}{}g;
            $subject =~ s{$subjectRegex}{$1};
            $email->replace( 'Subject' => $subject );
            $subject = $email->get('Subject');
            $string  = $email->as_string();
        }

        #"print $string;
        next if $isTest;
        next if !signalSpamReporting( $string, $account_ref );
        if ( defined $targetFolder and length($targetFolder) > 0 ) {
            croak sayError( 'Could not move: ' . $@ )
                if !$client->move( $targetFolder, $msgId );
            sayInfo('The email has been moved.');
        }
        else {
            croak sayError( 'Could not delete_message: ' . $@ )
                if !$client->delete_message($msgId);
            sayInfo("messagesProcess() The email has been deleted\n");
        }
        $spamCounter++;
        $boxSpamCounter++;
    }
    sayInfo(" - $boxSpamCounter message(s) were reported\n");
    sayInfo(" - $boxSpamIgnoredCounter message(s) were ignored\n");

}

#** @function public signalSpamReporting($msg, account_ref)
# @brief Posts the spam in the Signal Spam form
# @param msg - required string
# @param account_ref - required hashref
#*
sub signalSpamReporting {
    my ( $msg, $account_ref ) = @_;

    # Return a HTTP::Response object
    my $response = mechanizeGet( $account_ref->{'url'} );
    my $form     = $mech->form_number(1);
    die sayError('WWW::Mechanize::form_number(1) was failed')
        if !defined $form;
    $mech->field( 'reporting[raw_email]', $msg );
    $response = mechanizeClick();

    #Votre signalement a été enregistré
    my $content = $response->decoded_content();
    if ( $content
        !~ m{^.*<p>Votre\ signalement\ a\ été\ enregistré</p>.*$}xms )
    {
        writeFile( 'signal-spam-response.txt', $content );
        sayError('Spam doesn\'t seem to have been accepted.');
        return 0;
    }

    #sayInfo("Your spam report has been recorded.");
    sayInfo(  'The email was submitted with the "'
            . $account_ref->{'username'}
            . ' account.' );
    return 1;
}

#** function public signalSpamLogin($account_ref)
# @brief Authentifcates th user on the https://signalants.signal-spam.fr website
# @param account_ref - required hashref
#*
sub signalSpamLogin {
    my ($account_ref) = @_;
    my $content;

    # Return a HTTP::Response object
    my $response = mechanizeGet( $account_ref->{'login-url'} );
    $content = $response->decoded_content();

    # Get HTML::Form object
    my $form = $mech->form_number(1);
    croak sayError('WWW::Mechanize::form_number(1) was failed')
        if !defined $form;
    $mech->field( 'user[email_or_login]', $account_ref->{'username'} );
    $mech->field( 'user[password]',       $account_ref->{'password'} );
    $mech->field( 'user[remember_me]',    0 );
    $response = mechanizeClick();
    $content  = $response->decoded_content();

    if ( $content
        =~ m{Nom\ d&#39;utilisateur\ ou\ mot\ de\ passe\ incorrect\.}xms )
    {
        die sayError('Incorrect username or password');

    }
    sayDebug( 'The authentication of the '
            . $account_ref->{'username'}
            . ' user was successful!' );
}

sub signalSpamLogout {
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

#** @function public mechanizeGet ($url)
# @brief Given a URL, fetches it.
# @param url - required string (URL)
# @retval response - HTTP::Response object
#*
sub mechanizeGet {
    my ($url) = @_;
    sayDebug( 'WWW::Mechanize:get(' . $url . ')' );

    # Return a HTTP::Response object
    my $response = $mech->get($url);
    croak sayError("WWW::Mechanize:get($url) was failed")
        if !defined $response;
    if ( !$response->is_success() ) {
        my $message = $response->status_line();
        croak sayError($message);
    }
    my $request = $response->request();
    my $referer = $request->header('Referer');
    sayDebug( 'Referer: ' . $referer ) if defined $referer;
    my $title = $mech->title();
    $title =~ s{[^a-zA-Z0-9 -]}{}g;
    sayDebug( 'Page title: ' . $title );
    return $response;
}

#** @function public mechanizeClick ()
# @brief Has the effect of clicking a button on the current form
# @retval response - HTTP::Response object
#*
sub mechanizeClick {
    sayDebug('WWW::Mechanize::clic()');
    my $response = $mech->click();
    croak sayError("WWW::Mechanize:click was failed") if !defined $response;
    if ( !$response->is_success() ) {
        my $message = $response->status_line();
        croak sayError($message);
    }
    my $title = $mech->title();
    $title =~ s{[^a-zA-Z0-9 -]}{}g;
    sayDebug( 'Page title: ' . $title );
    return $response;
}

sub displayCookie {
    my ($response) = @_;
    my $host       = $response->request()->{_uri_canonical}->host();
    my $cookie_ref = $cookie_jar->get_cookies($host);
    foreach my $name ( keys %$cookie_ref ) {
        sayDebug( $name . ': ' . $cookie_ref->{$name} );
    }
}

## @method void openBox($mailbox_ref)
# @params $mailbox_ref
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
            or die
            "openBox($username) new IO::Socket::SSLsocket() failed: $@";
        my $greeting = <$socket>;
        sayInfo($greeting);
        my ( $id, $answer ) = split /\s+/, $greeting;
        die "problems logging in: $greeting" if $answer ne 'OK';
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
        ) or die "openBox($username) new Mail::IMAPClient() failed: $@";
        $client->login()
            or die "openBox($username): "
            . "login() failed "
            . $client->LastError();
    }
    else {

        # IMAP
        $client = Mail::IMAPClient->new(
            'User'     => $username,
            'Password' => $mailbox_ref->{'password'},
            'Timeout'  => 60,
            'Debug'    => 0,
            'Server'   => $mailbox_ref->{'server'},
        ) or die "openBox($username) new Mail::IMAPClient() failed: $@";
    }

    $client->State( Mail::IMAPClient::Connected() );

    #$client->Socket($socket);

    if ($isDebug) {
        my @folders = $client->folders();
        sayDebug( join( "\n* ", 'Folders:', @folders ), "\n" );
    }

    $client->select( $mailbox_ref->{'junk'} )
        or die "openBox($username) "
        . "Mail::IMAPClient::select($mailbox_ref->{'junk'}) "
        . "failed: "
        . $client->LastError();
}

## @method void closeBox()
sub closeBox {
    if ( defined $client and $client->IsAuthenticated() ) {
        sayInfo("(*) logout\n");
        $client->logout();
        undef($client);
    }
}

#** function public init()
# @brief Perfom some initializations
#*
sub init {
    getOptions();
    print STDOUT 'imap2signal-spam.pl ' . $VERSION . "\n"
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
    $cookie_jar = HTTP::Cookies->new(
        'file'           => $ENV{'HOME'} . '/.' . $Script . '.cookie',
        'autosave'       => 0,
        'ignore_discard' => 0
    );

    $mech = WWW::Mechanize->new(
        'agent'      => $userAgent{'agent'},
        'cookie_jar' => $cookie_jar
    );

}

#** @function public readConfig ()
# @brief Reads ans parses the "imap2signal-spam.conf" file
#*
sub readConfig {
    my $confFound = 0;
    foreach my $pathname ( '.', '/etc', $ENV{'HOME'} . '/.imap2signal-spam' )
    {
        my $filename = $pathname . '/' . $configFileName;
        next if !-e $filename;
        $confFound = 1;
        my %config = Config::General->new($filename)->getall();

        # Reads "user-agent" section
        my $ua_ref = isHash( \%config, 'user-agent' );
        $userAgent{'agent'} = isString( $ua_ref, 'agent' );
        $userAgent{'timeout'} = isInteger( $ua_ref, 'timeout' );

        # Reads "signal-spams" section
        my $signal_ref = isHash( \%config, 'signal-spam' );
        $signalSpamURL      = isString( $signal_ref, 'url' );
        $signalSpamLoginURL = isString( $signal_ref, 'login-url' );
        my $accounts_ref = isArrayOfHash( $signal_ref, 'account' );
        foreach my $account_ref (@$accounts_ref) {
            readAccountSections($account_ref);
        }

        # Reads IMAP box(es)
        my $mailboxes_ref = isArrayOfHash( \%config, 'mailbox' );
        foreach my $mailbox_ref ( @{$mailboxes_ref} ) {
            readMailboxSection($mailbox_ref);
        }
        if ( exists $config{'syslog'} ) {
            $sysLog_ref = isHash( \%config, 'syslog' );
            isString( $sysLog_ref, 'logopt' );
            isString( $sysLog_ref, 'facility' );
            isString( $sysLog_ref, 'sock_type' );
        }
        $confFound = 1;
    }
    die "(!) readConfig(): no configuration file has been found!"
        if !$confFound;
    die "(!) readConfig(): 'user-agent' section not found! "
        if scalar( keys %userAgent ) == 0;
    die "(!) readConfig(): 'signal-spam' entry not found! "
        if scalar( keys %accounts ) == 0;
    die "(!) readConfig(): 'mailbox' entry not found! "
        if scalar( keys %mailboxes ) == 0;
}

#** @function public isString( $hash_ref, $key, $default )
# @brief Returns the value of key, if it exists
# @param hash_ref - required hashref (hash with key-value pairs)
# @param key - required string (Name of the key)
# @param default - optional string (Value returned if the key does not exists)
# @retval value - string (Value of the key)
#*
sub isString {
    my ( $hash_ref, $key, $default ) = @_;
    return $default if !exists $hash_ref->{$key} and defined $default;
    croak sayError("'$key' string not found or wrong")
        if !exists( $hash_ref->{$key} )
        or ref( $hash_ref->{$key} )
        or $hash_ref->{$key} !~ m{^.+$}m;
    return $hash_ref->{$key};
}

#** @function public isInteger( $hash_ref, $key )
# @brief Returns the integer value of key, if it exists
# @param hash_ref - required hashref (hash with key-value pairs)
# @param key - required string (Name of the key)
# @param default - optional integer (Value returned if the key does not exists)
# @retval value - integer (Value of the key)
#*
sub isInteger {
    my ( $hash_ref, $key, $default ) = @_;
    return $default if !exists $hash_ref->{$key} and defined $default;
    croak sayError("'$key' integer not found or wrong")
        if !exists( $hash_ref->{$key} )
        or ref( $hash_ref->{$key} )
        or $hash_ref->{$key} !~ m{^-?\d+$};
    return $hash_ref->{$key};
}

#** @function public isBool( $hash_ref, $key )
# @brief Returns the boolean value of key, if it exists
# @param hash_ref - required hashref (hash with key-value pairs)
# @param key - required string (Name of the key)
# @retval value - boolean (Bolean value of the key, either 0 or 1)
#*
sub isBool {
    my ( $hash_ref, $key ) = @_;
    croak sayError("'$key' boolean not found or wrong")
        if !exists( $hash_ref->{$key} )
        or ref( $hash_ref->{$key} )
        or $hash_ref->{$key} !~ m{^(0|1|true|false)$};
    if ( $hash_ref->{$key} eq 'false' ) {
        $hash_ref->{$key} = 0;
    }
    elsif ( $hash_ref->{$key} eq 'true' ) {
        $hash_ref->{$key} = 1;
    }
    return $hash_ref->{$key};
}

#** @function public isHash( $hash_ref, $key )
# @brief Returns the hashref of key, if it exists
# @param hash_ref - required hashref (hash with key-value pairs)
# @param key - required string (Name of the key)
# @retval hash_ref - hashref (hashref of the key)
#*
sub isHash {
    my ( $hash_ref, $key ) = @_;
    croak sayError("'$key' hash not found or wrong")
        if !exists( $hash_ref->{$key} )
        or ref( $hash_ref->{$key} ) ne 'HASH';
    return $hash_ref->{$key};
}

#** @function public isArrayOfHash( $hash_ref, $key )
# @brief Returns the arrayref of key, if it exists
# @param hash_ref - required hashref (hash with key-value pairs)
# @param key - required string (Name of the key)
# @retval array_ref - arrayref (arrayref of the key)
#*
sub isArrayOfHash {
    my ( $hash_ref, $key ) = @_;
    croak sayError("'$key' array not found or wrong")
        if !exists $hash_ref->{$key};
    my $value_ref = $hash_ref->{$key};
    my $array_ref = [];
    if ( ref($value_ref) eq 'HASH' ) {
        $array_ref = [$value_ref];
    }
    elsif ( ref($value_ref) eq 'ARRAY' ) {
        $array_ref = $value_ref;
    }
    else {
        croak sayError("'$key' value is bad");
    }
    return $array_ref;
}

sub getId {
    my ( $pack, $file, $line, $function );
    ( $pack, $file, $line, $function ) = caller(2);
    ( $pack, $file, $line ) = caller(1);
    my $id = '';
    $function = '?' if !defined $function;
    $id = "[$function; line: $line] ";
    return $id;
}

## @method void sayError($message)
# @param message Error message
sub sayError {
    my ($message) = @_;
    $message =~ s{(\n|\r)}{}g;
    $message = $message . ' ' . getId();
    setlog( 'info', $message );
    print STDERR $message . "\n"
        if $isVerbose;
    return $message;
}

## @method void sayInfo($message)
# @param message Info message
sub sayInfo {
    my ($message) = @_;
    $message =~ s{(\n|\r)}{}g;
    $message = $message . ' ' . getId();
    setlog( 'info', $message );
    print STDOUT $message . "\n"
        if $isVerbose;
}

## @method void sayDebug($message)
# @param message Debug message
sub sayDebug {
    return if !$isDebug;
    my ($message) = @_;
    $message =~ s{(\n|\r)}{}g;
    $message = $message . ' ' . getId();
    setlog( 'info', $message );
    print STDOUT $message . "\n"
        if $isVerbose;
}

## @method void setlog($priorite, $message)
# @param priorite Level: 'info', 'error', 'debug' or 'warning'
sub setlog {
    my ( $priorite, $message ) = @_;
    return if !defined $sysLog_ref;
    Sys::Syslog::syslog( $priorite, '%s', $message );
}

#** @function public readAccountSections($account_ref)
# @brief Reads an "account" section from configuration file
# @param account_ref - required hashref ("account" section configuration)
#*
sub readAccountSections {
    my ($account_ref) = @_;
    my $username = isString( $account_ref, 'username' );
    $defaultAccount = $username if !defined $defaultAccount;
    croak "Duplicate '$username' username!"
        if exists $accounts{$username};
    $accounts{$username} = $account_ref;
    $accounts{$username} = {
        'username' => $username,
        'password' => isString( $account_ref, 'password' ),
        'url'      => isString( $account_ref, 'url', $signalSpamURL ),
        'login-url' =>
            isString( $account_ref, 'login-url', $signalSpamLoginURL )
    };
}

#** @function public readMailboxSection($mailbox_ref)
# @brief Reads an "mailbox" section from configuration file
# @param mailbox_ref - required hashref ("mailbox" section from configration file)
#*
sub readMailboxSection {
    my ($mailbox_ref) = @_;
    my $id = isString( $mailbox_ref, 'id' );
    croak sayError( 'Duplicate mailbox "' . $id . ' "id' )
        if exists $mailboxes{$id};
    $mailboxes{$id} = {
        'enabled'  => isBool( $mailbox_ref, 'enabled' ),
        'username' => isString( $mailbox_ref, 'username' ),
        'password' => isString( $mailbox_ref, 'password' ),
        'server'   => isString( $mailbox_ref, 'server' ),
        'port'     => isInteger( $mailbox_ref, 'port' ),
        'junk'     => isString( $mailbox_ref, 'junk' ),
        'singal-spam-account' =>
            isString( $mailbox_ref, 'singal-spam-account' ),
        'is-reported-spam-deleted' =>
            isBool( $mailbox_ref, 'is-reported-spam-deleted' ),
    };
    if ( $mailboxes{$id}->{'is-reported-spam-deleted'} ) {
        $mailboxes{$id}->{'target-folder'} = '';
    }
    else {
        $mailboxes{$id}->{'target-folder'}
            = isString( $mailbox_ref, 'target-folder' );
    }
    my $delay = isString( $mailbox_ref, 'delay', '0' );
    $delay = 0 if $ignoreDelay;
    if ( $delay =~ m{^(\d+)s?$} ) {
        $delay = $1;
    }
    elsif ( $delay =~ m{^(\d+)m$} ) {
        $delay = $1 * 60;
    }
    elsif ( $delay =~ m{^(\d+)h$} ) {
        $delay = $1 * 3600;
    }
    elsif ( $delay =~ m{^(\d+)d$} ) {
        $delay = $1 * 86400;
    }
    else {
        croak sayError( "bad delay format: $delay. "
                . "Format excepted: 60, 60s, 60m, 24h or 15d" );
    }
    $mailboxes{$id}->{'delay'} = $delay;
}

#** @function public getOptions()
# @brief Reads command line options
#*
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

## @function public writeFile( $filename, $string )
# @bref Writes a string to a file (Used for debugging purposes)
# @param filename - required string (a filename)
# @param string - required string (a string)
#*
sub writeFile {
    my ( $filename, $string ) = @_;
    my $fh;
    if ( !open( $fh, '>', $filename ) ) {
        sayError("$!");
        return;
    }
    print $fh $string;
    close $fh;
}

#** @function public HELP_MESSAGE ()
# @brief  Display help message
#*
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

sub VERSION_MESSAGE {
    print STDOUT <<ENDTXT;
    $Script $VERSION (2020-09-12)
    Copyright (C) 2008-2020 TLK Games
    Written by Bruno Ethvignot.
ENDTXT
}

