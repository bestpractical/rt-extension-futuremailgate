use strict;
use warnings;
package RT::Extension::FutureMailgate;
use 5.010_001;

our $VERSION = '0.02';

=head1 NAME

RT-Extension-FutureMailgate - Backport of the server side of RT 4.4's mail gateway

=head1 DESCRIPTION

This extension provides the flexibility of RT 4.4's email plugin
infrastructure, on earlier versions of RT.

=cut


require RT::Config;
my $postload = $RT::Config::META{MailPlugins}{PostLoadCheck};
$RT::Config::META{MailPlugins}{PostLoadCheck} = sub {
    return unless RT::Interface::Email->can("Plugins");
    RT::Interface::Email::Plugins(Add => ["Authz::Default", "Action::Defaults"]);
    RT::Interface::Email::Plugins(Add => ["Auth::MailFrom"])
        unless RT::Interface::Email::Plugins(Code => 1, Method => "GetCurrentUser");
    $postload->(@_) if $postload;
};

sub RT::Interface::Email::Crypt::VerifyDecrypt {} # no-op

require RT::EmailParser;
no warnings 'redefine';
my $parseemail = \&RT::EmailParser::ParseEmailAddress;
*RT::EmailParser::ParseEmailAddress = sub {
    my $self = shift;

    my $address_string = shift;

    # Some broken mailers send:  ""Vincent, Jesse"" <jesse@fsck.com>. Hate
    $address_string =~ s/\"\"(.*?)\"\"/\"$1\"/g;

    return $parseemail->($self, $address_string);
};

require RT::User;
no warnings 'redefine';
sub RT::User::LoadOrCreateByEmail {
    my $self = shift;

    my %create;
    if (@_ > 1) {
        %create = (@_);
    } elsif ( UNIVERSAL::isa( $_[0] => 'Email::Address' ) ) {
        @create{'EmailAddress','RealName'} = ($_[0]->address, $_[0]->phrase);
    } else {
        my ($addr) = RT::EmailParser->ParseEmailAddress( $_[0] );
        @create{'EmailAddress','RealName'} = $addr ? ($addr->address, $addr->phrase) : (undef, undef);
    }

    $self->LoadByEmail( $create{EmailAddress} );
    $self->Load( $create{EmailAddress} ) unless $self->Id;

    return wantarray ? ($self->Id, $self->loc("User loaded")) : $self->Id
        if $self->Id;

    $create{Name}       ||= $create{EmailAddress};
    $create{Privileged} ||= 0;
    $create{Comments}   //= 'Autocreated when added as a watcher';

    my ($val, $message) = $self->Create( %create );
    return wantarray ? ($self->Id, $self->loc("User loaded")) : $self->Id
        if $self->Id;

    # Deal with the race condition of two account creations at once
    $self->LoadByEmail( $create{EmailAddress} );
    unless ( $self->Id ) {
        sleep 5;
        $self->LoadByEmail( $create{EmailAddress} );
    }

    if ( $self->Id ) {
        $RT::Logger->error("Recovered from creation failure due to race condition");
        return wantarray ? ($self->Id, $self->loc("User loaded")) : $self->Id;
    } else {
        $RT::Logger->crit("Failed to create user $create{EmailAddress}: $message");
        return wantarray ? (0, $message) : 0 unless $self->id;
    }
}


=head1 RT VERSION

Works with RT 4.0 and 4.2.  It is unnecessary on RT 4.4.

=head1 INSTALLATION

=over

=item C<perl Makefile.PL>

=item C<make>

=item C<make install>

May need root permissions

=item Edit your F</opt/rt4/etc/RT_SiteConfig.pm>

If you are using RT 4.2 or greater, add this line:

    Plugin('RT::Extension::FutureMailgate');

For RT 4.0, add this line:

    Set(@Plugins, qw(RT::Extension::FutureMailgate));

or add C<RT::Extension::FutureMailgate> to your existing C<@Plugins> line.

=item Restart your webserver

=back

=head1 AUTHOR

Best Practical Solutions, LLC E<lt>modules@bestpractical.comE<gt>

=head1 BUGS

All bugs should be reported via email to

    L<bug-RT-Extension-FutureMailgate@rt.cpan.org|mailto:bug-RT-Extension-FutureMailgate@rt.cpan.org>

or via the web at

    L<rt.cpan.org|http://rt.cpan.org/Public/Dist/Display.html?Name=RT-Extension-FutureMailgate>.

=head1 COPYRIGHT

This extension is Copyright (C) 2015 Best Practical Solutions, LLC.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991

=cut

1;
