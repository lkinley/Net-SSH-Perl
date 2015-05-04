# $Id: Kex.pm,v 1.24 2009/02/02 01:18:27 turnstep Exp $

package Net::SSH::Perl::Kex;
use strict;

use Net::SSH::Perl::Kex::DH1;
use Net::SSH::Perl::Cipher;
use Net::SSH::Perl::Mac;
use Net::SSH::Perl::Comp;
use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Constants qw(
    :msg2
    :kex
    :proposal
    :protocol
    SSH_COMPAT_BUG_HMAC );

use Carp qw( croak );
use Digest::SHA1 qw( sha1 );
use Scalar::Util qw(weaken);

use vars qw( @PROPOSAL );
@PROPOSAL = (
    KEX_DEFAULT_KEX,
    KEX_DEFAULT_PK_ALG,
    KEX_DEFAULT_ENCRYPT,
    KEX_DEFAULT_ENCRYPT,
    KEX_DEFAULT_MAC,
    KEX_DEFAULT_MAC,
    KEX_DEFAULT_COMP,
    KEX_DEFAULT_COMP,
    KEX_DEFAULT_LANG,
    KEX_DEFAULT_LANG,
);

sub new {
    my $class = shift;
    my $ssh = shift;
    my $kex = bless { ssh => $ssh }, $class;
    weaken $kex->{ssh};
    $kex;
}

sub client_kexinit { $_[0]->{client_kexinit} }
sub server_kexinit { $_[0]->{server_kexinit} }

sub send_cipher { $_[0]->{ciph}[1] }
sub send_mac    { $_[0]->{mac} [1] }
sub send_comp   { $_[0]->{comp}[1] }

sub receive_cipher { $_[0]->{ciph}[0] }
sub receive_mac    { $_[0]->{mac} [0] }
sub receive_comp   { $_[0]->{comp}[0] }

sub exchange {
    my $kex = shift;
    my $ssh = $kex->{ssh};
    my $packet = shift;

    my @proposal = @PROPOSAL;
    if (!$ssh->config->get('ciphers')) {
        if (my $c = $ssh->config->get('cipher')) {
            $ssh->config->set('ciphers', $c);
        }
    }
    if (my $cs = $ssh->config->get('ciphers')) {
        # SSH2 cipher names are different; for compatibility, we'll map
        # valid SSH1 ciphers to the SSH2 equivalent names
        if($ssh->protocol eq PROTOCOL_SSH2) {
            my %ssh2_cipher = reverse %Net::SSH::Perl::Cipher::CIPHERS_SSH2;
            $cs = join ',', map $ssh2_cipher{$_} || $_, split(/,/, $cs);
        }
        $proposal[ PROPOSAL_CIPH_ALGS_CTOS ] =
        $proposal[ PROPOSAL_CIPH_ALGS_STOC ] = $cs;
    }
    if ($ssh->config->get('compression')) {
        $proposal[ PROPOSAL_COMP_ALGS_CTOS ] =
        $proposal[ PROPOSAL_COMP_ALGS_STOC ] = "zlib";
    }
    else {
        $proposal[ PROPOSAL_COMP_ALGS_CTOS ] =
        $proposal[ PROPOSAL_COMP_ALGS_STOC ] = "none";
    }
    if ($ssh->config->get('host_key_algorithms')) {
        $proposal[ PROPOSAL_SERVER_HOST_KEY_ALGS ] =
            $ssh->config->get('host_key_algorithms');
    }

    $kex->{client_kexinit} = $kex->kexinit(\@proposal);
    my($sprop) = $kex->exchange_kexinit($packet);

    $kex->choose_conf(\@proposal, $sprop);
    $ssh->debug("Algorithms, c->s: " .
        "$kex->{ciph_name}[0] $kex->{mac_name}[0] $kex->{comp_name}[0]");
    $ssh->debug("Algorithms, s->c: " .
        "$kex->{ciph_name}[1] $kex->{mac_name}[1] $kex->{comp_name}[1]");

    bless $kex, $kex->{class_name};
    $kex->exchange;

    $ssh->debug("Waiting for NEWKEYS message.");
    $packet = Net::SSH::Perl::Packet->read_expect($ssh, SSH2_MSG_NEWKEYS);

    $ssh->debug("Send NEWKEYS.");
    $packet = $ssh->packet_start(SSH2_MSG_NEWKEYS);
    $packet->send;

    $ssh->debug("Enabling encryption/MAC/compression.");
    $ssh->{kex} = $kex;
    for my $att (qw( mac ciph comp )) {
        $kex->{$att}[0]->enable if $kex->{$att}[0];
        $kex->{$att}[1]->enable if $kex->{$att}[1];
    }
}

sub kexinit {
    my $kex = shift;
    my($proposal) = @_;

    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    my $cookie = join '', map chr rand 255, 1..16;
    $b->put_chars($cookie);
    $b->put_str($_) for @$proposal;
    $b->put_int8(0);
    $b->put_int32(0);
    $b;
}

sub exchange_kexinit {
    my $kex = shift;
    my $ssh = $kex->{ssh};
    my $received_packet = shift;
    my $packet;

    $packet = $ssh->packet_start(SSH2_MSG_KEXINIT);
    $packet->put_chars($kex->client_kexinit->bytes);
    $packet->send;

    if ( defined $received_packet ) {
	$ssh->debug("Received key-exchange init (KEXINIT), sent response.");
	$packet = $received_packet;
    }
    else {
	$ssh->debug("Sent key-exchange init (KEXINIT), wait response.");
	$packet = Net::SSH::Perl::Packet->read_expect($ssh, SSH2_MSG_KEXINIT);
    }
    $kex->{server_kexinit} = $packet->data;

    $packet->get_char for 1..16;
    my @s_props = map $packet->get_str, 1..10;
    $packet->get_int8;
    $packet->get_int32;

    \@s_props;
}

sub derive_keys {
    my $kex = shift;
    my($hash, $shared_secret, $session_id) = @_;
    my @keys;
    for my $i (0..5) {
        push @keys, derive_key(ord('A')+$i, $kex->{we_need}, $hash,
			       $shared_secret, $session_id);
    }
    my $is_ssh2 = $kex->{ssh}->protocol == PROTOCOL_SSH2;
    for my $mode (0, 1) {
        my $ctos = $mode == 1;
        $kex->{ciph}[$mode]->init($keys[$ctos ? 2 : 3], $keys[$ctos ? 0 : 1],
            $is_ssh2);
        $kex->{mac}[$mode]->init($keys[$ctos ? 4 : 5]);
        $kex->{comp}[$mode]->init(6) if $kex->{comp}[$mode];
    }
}

sub derive_key {
    my($id, $need, $hash, $shared_secret, $session_id) = @_;
    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->put_mp_int($shared_secret);
    my $digest = sha1($b->bytes, $hash, chr($id), $session_id);
    for (my $have = 20; $need > $have; $have += 20) {
        $digest .= sha1($b->bytes, $hash, $digest);
    }
    $digest;
}

sub choose_conf {
    my $kex = shift;
    my($cprop, $sprop) = @_;
    for my $mode (0, 1) {
        my $ctos = $mode == 1;
        my $nciph = $ctos ? PROPOSAL_CIPH_ALGS_CTOS : PROPOSAL_CIPH_ALGS_STOC;
        my $nmac  = $ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
        my $ncomp = $ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
        $kex->choose_ciph($mode, $cprop->[$nciph], $sprop->[$nciph]);
        $kex->choose_mac ($mode, $cprop->[$nmac],  $sprop->[$nmac]);
        $kex->choose_comp($mode, $cprop->[$ncomp], $sprop->[$ncomp]);
    }
    $kex->choose_kex($cprop->[PROPOSAL_KEX_ALGS], $sprop->[PROPOSAL_KEX_ALGS]);
    $kex->choose_hostkeyalg($cprop->[PROPOSAL_SERVER_HOST_KEY_ALGS],
        $sprop->[PROPOSAL_SERVER_HOST_KEY_ALGS]);

    my $need = 0;
    for my $mode (0, 1) {
        $need = $kex->{ciph}[$mode]->keysize
            if $need < $kex->{ciph}[$mode]->keysize;
        $need = $kex->{ciph}[$mode]->blocksize
            if $need < $kex->{ciph}[$mode]->blocksize;
        $need = $kex->{mac}[$mode]->len
            if $need < $kex->{mac}[$mode]->len;
    }
    $kex->{we_need} = $need;
}

sub choose_kex {
    my $kex = shift;
    my $name = _get_match(@_);
    croak "No kex algorithm" unless $name;
    $kex->{algorithm} = $name;
    if ($name eq KEX_DH1) {
        $kex->{class_name} = __PACKAGE__ . "::DH1";
    }
    else {
        croak "Bad kex algorithm $name";
    }
}

sub choose_hostkeyalg {
    my $kex = shift;
    my $name = _get_match(@_);
    croak "No hostkey algorithm" unless $name;
    $kex->{hostkeyalg} = $name;
}

sub choose_ciph {
    my $kex = shift;
    my $mode = shift;
    my $name = _get_match(@_);
    croak "No matching cipher found: client ", $_[0], " server ", $_[1]
        unless $name;
    $kex->{ciph_name}[$mode] = $name;
    $kex->{ciph}[$mode] = Net::SSH::Perl::Cipher->new($name);
}

sub choose_mac {
    my $kex = shift;
    my $mode = shift;
    my $name = _get_match(@_);
    croak "No matching mac found: client ", $_[0], " server ", $_[1]
        unless $name;
    $kex->{mac_name}[$mode] = $name;
    my $mac = $kex->{mac}[$mode] = Net::SSH::Perl::Mac->new($name);
    $mac->key_len(
        $kex->{ssh}->{datafellows} & SSH_COMPAT_BUG_HMAC ? 16 : $mac->len);
}

sub choose_comp {
    my $kex = shift;
    my $mode = shift;
    my $name = _get_match(@_);
    croak "No matching comp found: client ", $_[0], " server ", $_[1]
        unless $name;
    $kex->{comp_name}[$mode] = $name;
    $kex->{comp}[$mode] = Net::SSH::Perl::Comp->new($name);
}

sub _get_match {
    my($c, $s) = @_;
    my %sprop = map { $_ => 1 } split /,/, $s;
    for my $cp (split /,/, $c) {
        return $cp if $sprop{$cp};
    }
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Kex - SSH2 Key Exchange

=head1 SYNOPSIS

    use Net::SSH::Perl::Kex;
    my $kex = Net::SSH::Perl::Kex->new($ssh);
    $kex->exchange;

=head1 DESCRIPTION

I<Net::SSH::Perl::Kex> implements base functionality for SSH2
key exchange. The basic idea is this: Kex itself initializes
the client algorithm proposal, sends it to the server, then
waits for the server's proposal. From these proposals Kex
chooses the algorithms that will be used in the communications
between client and server (eg. encryption algorithm, MAC
algorithm, etc.). Different algorithms can be used in each
direction; for example, client to server communications could
be encrypted using 3DES, and server to client could be encrypted
using RC4.

The algorithm negotiation phase, as described above, includes
negotiation for the key-exchange algorithm to be used.
Currently, the only supported algorithm is Diffie-Hellman
Group 1 key exchange, implemented in I<Net::SSH::Perl::Kex::DH1>.
After algorithm negotiation, the Kex object is reblessed into
the key exchange class (eg. 'Net::SSH::Perl::Kex::DH1'), and
then the subclass's I<exchange> method is called to perform
the key exchange.

Once control returns to Kex::exchange, the client waits for
the I<SSH_MSG_NEWKEYS> message; once received, the client
turns on its incoming encryption/MAC/compression algorithms,
then sends an I<SSH_MSG_NEWKEYS> message to the server.
Finally, it turns on its outgoing encryption/MAC/compression
algorithms.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
