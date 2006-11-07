package ParaDNS;

# This is the query class - it is really just an encapsulation of the
# hosts you want to query, plus the callback. All the hard work is done
# in ParaDNS::Resolver.

our $VERSION = '1.1';
our $TIMEOUT = 10;

use fields qw(client hosts num_hosts callback finished results start);
use strict;

use ParaDNS::Resolver;

my $resolver;

sub trace {
    my $level = shift;
    return unless $ENV{PARADNS_DEBUG};
    print STDERR ("$ENV{PARADNS_DEBUG}/$level [$$] dns lookup: @_") if $ENV{PARADNS_DEBUG} >= $level;
}

sub new {
    my ParaDNS $self = shift;
    my %options = @_;

    $resolver ||= ParaDNS::Resolver->new();
    
    my $client = $options{client};
    $client->pause_read() if $client;
    
    $self = fields::new($self) unless ref $self;

    $self->{hosts} = $options{hosts} ? $options{hosts} : [ $options{host} ];
    $self->{num_hosts} = scalar(@{$self->{hosts}}) || "No hosts supplied";
    $self->{client} = $client;
    $self->{callback} = $options{callback} || die "No callback given";
    $self->{finished} = $options{finished};
    $self->{results} = {};
    $self->{start} = time;

    if ($options{type}) {
        if ( ($options{type} eq 'A') || ($options{type} eq 'PTR') ) {
            if (!$resolver->query($self, @{$self->{hosts}})) {
                $client->continue_read() if $client;
                return;
            }
        }
        else {
            if (!$resolver->query_type($self, $options{type}, @{$self->{hosts}})) {
                $client->continue_read() if $client;
                return;
            }
            # die "Unsupported DNS query type: $options{type}";
        }
    }
    else {
        if (!$resolver->query($self, @{$self->{hosts}})) {
            $client->continue_read() if $client;
            return;
        }
    }
    
    return $self;
}

sub run_callback {
    my ParaDNS $self = shift;
    my ($result, $query) = @_;
    $self->{results}{$query} = $result;
    trace(2, "got $query => $result\n");
    eval {
        $self->{callback}->($result, $query);
    };
    if ($@) {
        warn($@);
    }
}

sub DESTROY {
    my ParaDNS $self = shift;
    my $now = time;
    foreach my $host (@{$self->{hosts}}) {
        if (!exists($self->{results}{$host})) {
            print STDERR "DNS timeout (presumably) looking for $host after " . ($now - $self->{start}) . " secs\n";
            $self->{callback}->("NXDOMAIN", $host);
        }
    }
    $self->{client}->continue_read() if $self->{client};
    if ($self->{finished}) {
        $self->{finished}->();
    }
}

1;

=head1 NAME

ParaDNS - a DNS lookup class for the Danga::Socket framework

=head1 SYNOPSIS

  ParaDNS->new(
    callback => sub { print "Got result $_[0] for query $_[1]\n" },
    host     => 'google.com',
  );

=head1 DESCRIPTION

This module performs asynchronous DNS lookups, making use of a single UDP
socket (unlike Net::DNS's bgsend/bgread combination). It uses the Danga::Socket
framework for high performance.

Currently this module will only perform A or PTR lookups. A rDNS (PTR) lookup
will be performed if the host matches the regexp: C</^\d+\.\d+\.\d+.\d+$/>.

The lookups time out after 15 seconds.

=head1 API

=head2 C<< ParaDNS->new( %options ) >>

Create a new DNS query. You do not need to store the resulting object as this
class is all done with callbacks.

Example:

  ParaDNS->new(
    callback => sub { print "Got result: $_[0]\n" },
    host => 'google.com',
    );

=over 4

=item B<[required]> C<callback>

The callback to call when results come in. This should be a reference to a
subroutine. The callback receives two parameters - the result of the DNS lookup
and the host that was looked up.

=item C<host>

A host name to lookup. Note that if the hostname is a dotted quad of numbers then
a reverse DNS (PTR) lookup is performend.

=item C<hosts>

An array-ref list of hosts to lookup.

B<NOTE:> One of either C<host> or C<hosts> is B<required>.

=item C<client>

It is possible to specify a client object which you wish to "pause" for reading
until your DNS result returns. The client will be issued the C<< ->pause_read >>
method when the query is issued, and the C<< ->continue_read >> method when the
query returns.

This is used in Qpsmtpd where we want to wait until the DNS query returns before
accepting more data from the client.

=item C<type>

You can specify one of: I<"A">, I<"AAAA">, I<"PTR">, I<"CNAME">, I<"NS"> or
I<"TXT"> here. Other types may be supported in the future. See C<%type_to_host>
in C<Resolver.pm> for details, though more complex queries (e.g. SRV) may
require a slightly more complex solution.

A PTR query is automatically issued if the host looks like an IP address.

=back

=head1 Stand-alone Use

Normal usage of ParaDNS is within another application that already uses the
Danga::Socket framework. However if you wish to use this as a script to just
issue thousands of DNS queries then you need to add the following to exit
the event loop when all the DNS queries are done:

    Danga::Socket->SetPostLoopCallback(
        sub {
            my $dmap = shift;
            for my $fd (keys %$dmap) {
                my $pob = $dmap->{$fd};
                if ($pob->isa('ParaDNS::Resolver')) {
                    return 1 if $pob->pending;
                }
            }
            return 0; # causes EventLoop to exit
        });

=head1 LICENSE

This module is licensed under the same terms as perl itself.

=head1 AUTHOR

Matt Sergeant, <matt@sergeant.org>.

=cut
