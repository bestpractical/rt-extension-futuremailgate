# BEGIN BPS TAGGED BLOCK {{{
#
# COPYRIGHT:
#
# This software is Copyright (c) 1996-2014 Best Practical Solutions, LLC
#                                          <sales@bestpractical.com>
#
# (Except where explicitly superseded by other copyright notices)
#
#
# LICENSE:
#
# This work is made available to you under the terms of Version 2 of
# the GNU General Public License. A copy of that license should have
# been provided with this software, but in any event can be snarfed
# from www.gnu.org.
#
# This work is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 or visit their web page on the internet at
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.html.
#
#
# CONTRIBUTION SUBMISSION POLICY:
#
# (The following paragraph is not intended to limit the rights granted
# to you to modify and distribute this software under the terms of
# the GNU General Public License and is only of importance to you if
# you choose to contribute your changes and enhancements to the
# community by submitting them to Best Practical Solutions, LLC.)
#
# By intentionally submitting any modifications, corrections or
# derivatives to this work, or any other work intended for use with
# Request Tracker, to Best Practical Solutions, LLC, you confirm that
# you are the copyright holder for those contributions and you grant
# Best Practical Solutions,  LLC a nonexclusive, worldwide, irrevocable,
# royalty-free, perpetual, license to use, copy, create derivative
# works based on those contributions, and sublicense and distribute
# those contributions and any derivatives thereof.
#
# END BPS TAGGED BLOCK }}}

package RT::Interface::Email;

use strict;
use warnings;
no warnings 'redefine';

use Email::Address;
use MIME::Entity;
use RT::EmailParser;
use File::Temp;
use UNIVERSAL::require;
use Mail::Mailer ();
use Text::ParseWords qw/shellwords/;
use MIME::Words ();
use Scope::Upper qw/unwind HERE/;
use 5.010_001;

=head1 NAME

  RT::Interface::Email - helper functions for parsing and sending email

=head1 METHODS

=head2 RECEIVING MAIL

=head3 Gateway ARGSREF

Takes parameters:

=over

=item C<action>

A C<-> separated list of actions to run.  Standard actions, as detailed
in L<bin/rt-mailgate>, are C<comment> and C<correspond>.  The
L<RT::Interface::Email::Actions::Take> and
L<RT::Interface::Email::Actions::Resolve> plugins can be added to
L<RT_Config/@MailPlugins> to provide C<take> and C<resolve> actions,
respectively.

=item C<queue>

The queue that tickets should be created in, if no ticket id is found on
the message.  Can be either a name or an id; defaults to 1.

=item C<message>

The content of the message, as obtained from the MTA.

=item C<ticket>

Optional; this ticket id overrides any ticket number derived from the
subject.

=back

Secrypts and verifies the message, decodes the transfer encoding,
determines the user that the mail was sent from, and performs the given
actions.

Returns a list of C<(status, message, ticket)>.  The C<status> is -75
for a temporary failure (to be retried later bt the MTA), 0 for a
permanent failure which did not result in a ticket, and 1 for a ticket
that was found and acted on.

=cut

my $SCOPE;
sub TMPFAIL { unwind (-75,     $_[0], undef, => $SCOPE) }
sub FAILURE { unwind (  0,     $_[0], $_[1], => $SCOPE) }
sub SUCCESS { unwind (  1, "Success", $_[0], => $SCOPE) }

sub Gateway {
    my $argsref = shift;
    my %args    = (
        action  => 'correspond',
        queue   => '1',
        ticket  => undef,
        message => undef,
        %$argsref
    );

    # Set the scope to return from with TMPFAIL/FAILURE/SUCCESS
    $SCOPE = HERE;

    # Validate the actions
    my @actions = grep $_, split /-/, $args{action};
    for my $action (@actions) {
        TMPFAIL( "Invalid 'action' parameter $action for queue $args{queue}" )
            unless Plugins(Method => "Handle" . ucfirst($action));
    }

    my $parser = RT::EmailParser->new();
    $parser->SmartParseMIMEEntityFromScalar(
        Message => $args{'message'},
        Decode => 0,
        Exact => 1,
    );

    my $Message = $parser->Entity();
    unless ($Message) {
        MailError(
            Subject     => "RT Bounce: Unparseable message",
            Explanation => "RT couldn't process the message below",
            Attach      => $args{'message'},
            FAILURE     => 1,
        );
    }

    #Set up a queue object
    my $SystemQueueObj = RT::Queue->new( RT->SystemUser );
    $SystemQueueObj->Load( $args{'queue'} );

    for my $Code ( Plugins(Method => "BeforeDecrypt") ) {
        $Code->(
            Message       => $Message,
            RawMessageRef => \$args{'message'},
            Queue         => $SystemQueueObj,
            Actions       => \@actions,
        );
    }

    RT::Interface::Email::Crypt::VerifyDecrypt(
        Message       => $Message,
        RawMessageRef => \$args{'message'},
        Queue         => $SystemQueueObj,
    );

    for my $Code ( Plugins(Method => "BeforeDecode") ) {
        $Code->(
            Message       => $Message,
            RawMessageRef => \$args{'message'},
            Queue         => $SystemQueueObj,
            Actions       => \@actions,
        );
    }

    $parser->_DecodeBodies;
    $parser->RescueOutlook;
    $parser->_PostProcessNewEntity;

    my $head = $Message->head;
    my $From = Encode::decode( "UTF-8", $head->get("From") );
    chomp $From if defined $From;

    #Pull apart the subject line
    my $Subject = Encode::decode( "UTF-8", $head->get('Subject') || '');
    chomp $Subject;

    # Lets check for mail loops of various sorts.
    my $ErrorsTo = ParseErrorsToAddressFromHead( $head );
    $ErrorsTo = RT->Config->Get('OwnerEmail')
        if IsMachineGeneratedMail(
            Message   => $Message,
            Subject   => $Subject,
        );

    # Make all errors from here on out bounce back to $ErrorsTo
    my $bare_MailError = \&MailError;
    no warnings 'redefine';
    local *MailError = sub {
        $bare_MailError->(To => $ErrorsTo, MIMEObj => $Message, @_)
    };

    $args{'ticket'} ||= ExtractTicketId( $Message );

    my $SystemTicket = RT::Ticket->new( RT->SystemUser );
    $SystemTicket->Load( $args{'ticket'} ) if ( $args{'ticket'} ) ;

    # We can safely have no queue of we have a known-good ticket
    TMPFAIL("RT couldn't find the queue: " . $args{'queue'})
        unless $SystemTicket->id || $SystemQueueObj->id;

    my $CurrentUser = GetCurrentUser(
        Message       => $Message,
        RawMessageRef => \$args{message},
        Ticket        => $SystemTicket,
        Queue         => $SystemQueueObj,
    );

    # We only care about ACLs on the _first_ action, as later actions
    # may have gotten rights by the time they happen.
    CheckACL(
        Action        => $actions[0],
        Message       => $Message,
        CurrentUser   => $CurrentUser,
        Ticket        => $SystemTicket,
        Queue         => $SystemQueueObj,
    );

    my $Ticket = RT::Ticket->new($CurrentUser);
    $Ticket->Load( $SystemTicket->Id );

    for my $action (@actions) {
        HandleAction(
            Action      => $action,
            Subject     => $Subject,
            Message     => $Message,
            Ticket      => $Ticket,
            TicketId    => $args{ticket},
            Queue       => $SystemQueueObj,
        );
    }
    SUCCESS( $Ticket );
}

=head3 Plugins Method => C<name>, Code => 0

Returns the list of subroutine references for the given method C<name>
from the configured L<RT_Config/@MailPlugins>.  If C<Code> is passed a
true value, includes anonymous subroutines found in C<@MailPlugins>.

=cut

sub Plugins {
    my %args = (
        Add => undef,
        Code => 0,
        Method => undef,
        @_
    );
    state $INIT;
    state @PLUGINS;

    if ($args{Add} or !$INIT) {
        my @mail_plugins = $INIT ? () : RT->Config->Get('MailPlugins');
        push @mail_plugins, @{$args{Add}} if $args{Add};

        foreach my $plugin (@mail_plugins) {
            if ( ref($plugin) eq "CODE" ) {
                push @PLUGINS, $plugin;
            } elsif ( !ref $plugin ) {
                my $Class = $plugin;
                $Class = "RT::Interface::Email::" . $Class
                    unless $Class =~ /^RT::/;
                $Class->require or
                    do { $RT::Logger->error("Couldn't load $Class: $@"); next };

                unless ( $Class->DOES( "RT::Interface::Email::Role" ) ) {
                    $RT::Logger->crit( "$Class is not an RT::Interface::Email::Role");
                    next;
                }
                push @PLUGINS, $Class;
            } else {
                $RT::Logger->crit( "$plugin - is not class name or code reference");
            }
        }
        $INIT = 1;
    }

    my @list = @PLUGINS;
    @list = grep {not ref} @list unless $args{Code};
    @list = grep {$_} map {ref $_ ? $_ : $_->can($args{Method})} @list if $args{Method};
    return @list;
}

=head3 GetCurrentUser Message => C<message>, Ticket => C<ticket>, Queue => C<queue>

Dispatches to the C<@MailPlugins> to find one the provides
C<GetCurrentUser> that recognizes the current user.  Mail plugins are
tried one at a time, and stops after the first to return a current user.
Anonymous subroutine references found in C<@MailPlugins> are treated as
C<GetCurrentUser> methods.

The default GetCurrentUser authenticator simply looks at the From:
address, and loads or creates a user accordingly; see
L<RT::Interface::Email::Auth::MailFrom>.

Returns the current user; on failure of any plugin to do so, stops
processing with a permanent failure and sends a generic "Permission
Denied" mail to the user.

=cut

sub GetCurrentUser {
    my %args = (
        Message       => undef,
        RawMessageRef => undef,
        Ticket        => undef,
        Queue         => undef,
        @_,
    );

    # Since this needs loading, no matter what
    for my $Code ( Plugins(Code => 1, Method => "GetCurrentUser") ) {
        my $CurrentUser = $Code->(
            Message       => $args{Message},
            RawMessageRef => $args{RawMessageRef},
            Ticket        => $args{Ticket},
            Queue         => $args{Queue},
        );
        return $CurrentUser if $CurrentUser and $CurrentUser->id;
    }

    # None of the GetCurrentUser plugins found a user.  This is
    # rare; some non-Auth::MailFrom authentication plugin which
    # doesn't always return a current user?
    MailError(
        Subject     => "Permission Denied",
        Explanation => "You do not have permission to communicate with RT",
        FAILURE     => 1,
    );
}

=head3 CheckACL Action => C<action>, CurrentUser => C<user>, Ticket => C<ticket>, Queue => C<queue>

Checks that the currentuser can perform a particular action.  While RT's
standard permission controls apply, this allows a better error message,
or more limited restrictions on the email gateway.

Each plugin in C<@MailPlugins> which provides C<CheckACL> is given a
chance to allow the action.  If any returns a true value, it
short-circuits all later plugins.  Note that plugins may short-circuit
and abort with failure of their own accord.

Aborts processing, sending a "Permission Denied" mail to the user with
the last plugin's failure message, on failure.

=cut

sub CheckACL {
    my %args = (
        Action        => undef,
        Message       => undef,
        CurrentUser   => undef,
        Ticket        => undef,
        Queue         => undef,
        @_,
    );

    for my $Code ( Plugins( Method => "CheckACL" ) ) {
        return if $Code->(
            Message       => $args{Message},
            CurrentUser   => $args{CurrentUser},
            Action        => $args{Action},
            Ticket        => $args{Ticket},
            Queue         => $args{Queue},
        );
    }

    # Nobody said yes, and nobody said FAILURE; fail closed
    MailError(
        Subject     => "Permission Denied",
        Explanation => "You have no permission to $args{Action}",
        FAILURE     => 1,
    );
}

=head3 HandleAction Action => C<action>, Message => C<message>, Ticket => C<ticket>, Queue => C<queue>

Dispatches to the first plugin in C<@MailPlugins> which provides a
C<HandleFoo> where C<Foo> is C<ucfirst(action)>.

=cut

sub HandleAction {
    my %args = (
        Action   => undef,
        Subject  => undef,
        Message  => undef,
        Ticket   => undef,
        TicketId => undef,
        Queue    => undef,
        @_
    );

    my $action = delete $args{Action};
    my ($code) = Plugins(Method => "Handle" . ucfirst($action));
    TMPFAIL( "Invalid 'action' parameter $action for queue ".$args{Queue}->Name )
        unless $code;

    $code->(%args);
}


=head3 ParseSenderAddressFromHead HEAD

Takes a L<MIME::Header> object. Returns a list of (email address,
friendly name, errors) where the address and name are the first address
found in C<Reply-To>, C<From>, or C<Sender>.

A list of error messages may be returned even when an address is found,
since it could be a parse error for another (checked earlier) sender
field. In this case, the errors aren't fatal, but may be useful to
investigate the parse failure.

=cut

sub ParseSenderAddressFromHead {
    my $head = shift;
    my @errors;  # Accumulate any errors

    foreach my $header ( 'Reply-To', 'From', 'Sender' ) {
        my $addr_line = Encode::decode( "UTF-8", $head->get($header) ) || next;
        my ($addr) = RT::EmailParser->ParseEmailAddress( $addr_line );
        return ($addr->address, $addr->phrase, @errors) if $addr;

        chomp $addr_line;
        push @errors, "$header: $addr_line";
    }

    return (undef, undef, @errors);
}

=head3 ParseErrorsToAddressFromHead HEAD

Takes a L<MIME::Header> object. Returns the first email address found in
C<Return-path>, C<Errors-To>, C<Reply-To>, C<From>, or C<Sender>.

=cut

sub ParseErrorsToAddressFromHead {
    my $head = shift;

    foreach my $header ( 'Errors-To', 'Reply-To', 'From', 'Sender' ) {
        my $value = Encode::decode( "UTF-8", $head->get($header) );
        next unless $value;

        my ( $email ) = RT::EmailParser->ParseEmailAddress($value);
        return $email->address if $email;
    }
}

=head3 IsMachineGeneratedMail Message => C<message>

Checks if the mail is machine-generated (via a bounce, mail headers,

=cut

sub IsMachineGeneratedMail {
    my %args = (
        Message => undef,
        Subject => undef,
        @_
    );
    my $head = $args{'Message'}->head;

    my $IsAutoGenerated = CheckForAutoGenerated($head);
    my $IsALoop = CheckForLoops($head);

    my $owner_mail = RT->Config->Get('OwnerEmail');

    # Don't let the user stuff the RT-Squelch-Replies-To header.
    $head->delete('RT-Squelch-Replies-To');

    # If the message is autogenerated, we need to know, so we can not
    # send mail to the sender
    return unless $IsAutoGenerated || $IsALoop;

    # Warn someone if it's a loop, before we drop it on the ground
    if ($IsALoop) {
        my $MessageId = Encode::decode( "UTF-8", $head->get('Message-ID') );
        $RT::Logger->crit("RT Received mail ($MessageId) from itself.");

        #Should we mail it to RTOwner?
        if ( RT->Config->Get('LoopsToRTOwner') ) {
            MailError(
                To          => $owner_mail,
                Subject     => "RT Bounce: ".$args{'Subject'},
                Explanation => "RT thinks this message may be a bounce",
            );
        }

        #Do we actually want to store it?
        FAILURE( "Message is a bounce" ) unless RT->Config->Get('StoreLoops');
    }

    # Squelch replies to the sender, and also leave a clue to
    # allow us to squelch ALL outbound messages. This way we
    # can punt the logic of "what to do when we get a bounce"
    # to the scrip. We might want to notify nobody. Or just
    # the RT Owner. Or maybe all Privileged watchers.
    my ( $Sender ) = ParseSenderAddressFromHead($head);
    $head->replace( 'RT-Squelch-Replies-To',    Encode::encode("UTF-8", $Sender ) );
    $head->replace( 'RT-DetectedAutoGenerated', 'true' );

    return 1;
}

=head3 CheckForLoops HEAD

Takes a L<MIME::Head> object and returns true if the message was sent by
this RT instance, by checking the C<X-RT-Loop-Prevention> header.

=cut

sub CheckForLoops {
    my $head = shift;

    # If this instance of RT sent it our, we don't want to take it in
    my $RTLoop = Encode::decode( "UTF-8", $head->get("X-RT-Loop-Prevention") || "" );
    chomp ($RTLoop); # remove that newline
    if ( $RTLoop eq RT->Config->Get('rtname') ) {
        return 1;
    }

    # TODO: We might not trap the case where RT instance A sends a mail
    # to RT instance B which sends a mail to ...
    return undef;
}

=head3 CheckForAutoGenerated HEAD

Takes a HEAD object of L<MIME::Head> class and returns true if message
is autogenerated.  This includes bounces, RFC3834 C<Auto-Submitted>
headers, as well as heuristics including C<Precedence> and
C<X-FC-Machinegenerated> headers.

=cut

sub CheckForAutoGenerated {
    my $head = shift;

    # Bounces, via return-path
    my $ReturnPath = $head->get("Return-path") || "";
    return 1 if $ReturnPath =~ /<>/;

    # Bounces, via mailer-daemon or postmaster
    my ( $From ) = ParseSenderAddressFromHead($head);
    return 1 if defined $From and $From =~ /^mailer-daemon\@/i;
    return 1 if defined $From and $From =~ /^postmaster\@/i;
    return 1 if defined $From and $From eq "";

    # Bulk or junk messages are auto-generated
    my $Precedence = $head->get("Precedence") || "";
    return 1 if $Precedence =~ /^(bulk|junk)/i;

    # Per RFC3834, any Auto-Submitted header which is not "no" means
    # it is auto-generated.
    my $AutoSubmitted = $head->get("Auto-Submitted") || "";
    return 1 if length $AutoSubmitted and $AutoSubmitted ne "no";

    # First Class mailer uses this as a clue.
    my $FCJunk = $head->get("X-FC-Machinegenerated") || "";
    return 1 if $FCJunk =~ /^true/i;

    return 0;
}

=head3 ExtractTicketId

Passed a L<MIME::Entity> object, and returns a either ticket id or undef
to signal 'new ticket'.

This is a great entry point if you need to customize how ticket ids are
handled for your site. L<RT::Extension::RepliesToResolved> demonstrates
one possible use for this extension.

If the Subject of the L<MIME::Entity> is modified, the updated subject
will be used during ticket creation.

=cut

sub ExtractTicketId {
    my $entity = shift;

    my $subject = Encode::decode( "UTF-8", $entity->head->get('Subject') || '' );
    chomp $subject;
    return ParseTicketId( $subject );
}

=head3 ParseTicketId

Takes a string and searches for [subjecttag #id]

Returns the id if a match is found.  Otherwise returns undef.

=cut

sub ParseTicketId {
    my $Subject = shift;

    my $rtname = RT->Config->Get('rtname');
    my $test_name = RT->Config->Get('EmailSubjectTagRegex') || qr/\Q$rtname\E/i;

    # We use @captures and pull out the last capture value to guard against
    # someone using (...) instead of (?:...) in $EmailSubjectTagRegex.
    my $id;
    if ( my @captures = $Subject =~ /\[$test_name\s+\#(\d+)\s*\]/i ) {
        $id = $captures[-1];
    } else {
        foreach my $tag ( RT->System->SubjectTag ) {
            next unless my @captures = $Subject =~ /\[\Q$tag\E\s+\#(\d+)\s*\]/i;
            $id = $captures[-1];
            last;
        }
    }
    return undef unless $id;

    $RT::Logger->debug("Found a ticket ID. It's $id");
    return $id;
}

=head3 MailError PARAM HASH

Sends an error message. Takes a param hash:

=over 4

=item From

Sender's address, defaults to L<RT_Config/$CorrespondAddress>;

=item To

Recipient, defaults to L<RT_Config/$OwnerEmail>;

=item Subject

Subject of the message, defaults to C<There has been an error>;

=item Explanation

Main content of the error, default value is C<Unexplained error>;

=item MIMEObj

Optional L<MIME::Entity> that is attached to the error mail.
Additionally, the C<In-Reply-To> header will point to this message.

=item Attach

Optional text that attached to the error as a C<message/rfc822> part.

=item LogLevel

Log level the subject and explanation is written to the log; defaults to
C<critical>.

=back

=cut

sub MailError {
    my %args = (
        To          => RT->Config->Get('OwnerEmail'),
        From        => RT->Config->Get('CorrespondAddress'),
        Subject     => 'There has been an error',
        Explanation => 'Unexplained error',
        MIMEObj     => undef,
        Attach      => undef,
        LogLevel    => 'crit',
        FAILURE     => 0,
        @_
    );

    $RT::Logger->log(
        level   => $args{'LogLevel'},
        message => "$args{Subject}: $args{'Explanation'}",
    ) if $args{'LogLevel'};

    # the colons are necessary to make ->build include non-standard headers
    my %entity_args = (
        Type                    => "multipart/mixed",
        From                    => Encode::encode( "UTF-8", $args{'From'} ),
        To                      => Encode::encode( "UTF-8", $args{'To'} ),
        Subject                 => EncodeToMIME( String => $args{'Subject'} ),
        'X-RT-Loop-Prevention:' => Encode::encode( "UTF-8", RT->Config->Get('rtname') ),
    );

    # only set precedence if the sysadmin wants us to
    if (defined(RT->Config->Get('DefaultErrorMailPrecedence'))) {
        $entity_args{'Precedence:'} =
            Encode::encode( "UTF-8", RT->Config->Get('DefaultErrorMailPrecedence') );
    }

    my $entity = MIME::Entity->build(%entity_args);
    SetInReplyTo( Message => $entity, InReplyTo => $args{'MIMEObj'} );

    $entity->attach(
        Type    => "text/plain",
        Charset => "UTF-8",
        Data    => Encode::encode( "UTF-8", $args{'Explanation'} . "\n" ),
    );

    if ( $args{'MIMEObj'} ) {
        $args{'MIMEObj'}->sync_headers;
        $entity->add_part( $args{'MIMEObj'} );
    }

    if ( $args{'Attach'} ) {
        $entity->attach( Data => Encode::encode( "UTF-8", $args{'Attach'} ), Type => 'message/rfc822' );

    }

    SendEmail( Entity => $entity, Bounce => 1 );

    FAILURE( "$args{Subject}: $args{Explanation}" ) if $args{FAILURE};
}

1;
