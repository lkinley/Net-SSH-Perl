package Net::SSH::Perl::Kex::DHGEX256;
use strict;

use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Constants qw( :msg2 :kex );
use Net::SSH::Perl::Key;
use Net::SSH::Perl::Util qw( bitsize );

use Carp qw( croak );
use Crypt::DH;
use Math::Pari;
use Digest::SHA2;
use Scalar::Util qw(weaken);

use Net::SSH::Perl::Kex;
use base qw( Net::SSH::Perl::Kex );

sub new {
    my $class = shift;
    my $ssh = shift;
    my $kex = bless { ssh => $ssh }, $class;
    weaken $kex->{ssh};
    $kex;
}

sub min_bits { 1024 }
sub want_bits { 2048 }
sub max_bits { 8192 }

sub exchange {
    my $kex = shift;
    my $ssh = $kex->{ssh};
    my $packet;

    # step 1 in rfc 4419
    $ssh->debug('Entering Diffie-Hellman Group Exchange.');
    $packet = $ssh->packet_start(SSH2_MSG_KEX_DH_GEX_REQUEST);
    $packet->put_int32($kex->min_bits);
    $packet->put_int32($kex->want_bits);
    $packet->put_int32($kex->max_bits);
    $packet->send;

    # step 2 in rfc 4419
    $ssh->debug('Sent DH Group Exchange request, waiting for reply.');
    $packet = Net::SSH::Perl::Packet->read_expect($ssh,
        SSH2_MSG_KEX_DH_GEX_GROUP);
    my $p = $packet->get_mp_int;
    my $g = $packet->get_mp_int;
    # range check on p
    my $p_bits = bitsize($p);
    if ($p_bits < $kex->min_bits || $p_bits > $kex->max_bits) {
        $ssh->fatal_disconnect('DH Group Exchange reply out of range');
    }
    $ssh->debug("Received DH Group Exchange reply.");

    # step 3 in rfc 4419
    $ssh->debug('Generating new Diffie-Hellman keys.');
    my $dh = $kex->_dh_new_group($p,$g);

    $ssh->debug('Entering Diffie-Hellman key exchange.');
    $packet = $ssh->packet_start(SSH2_MSG_KEX_DH_GEX_INIT);
    $packet->put_mp_int($dh->pub_key);
    $packet->send;
    $ssh->debug('Sent DH public key, waiting for reply.');

    # step 4 in rfc 4419
    $packet = Net::SSH::Perl::Packet->read_expect($ssh,
        SSH2_MSG_KEX_DH_GEX_REPLY);

    my $host_key_blob = $packet->get_str;
    my $s_host_key = Net::SSH::Perl::Key->new_from_blob($host_key_blob,
        \$ssh->{datafellows});
    $ssh->debug("Received host key, type '" . $s_host_key->ssh_name . "'.");

    # step 5 in rfc 4419
    $ssh->check_host_key($s_host_key);

    my $dh_server_pub = $packet->get_mp_int;
    my $signature = $packet->get_str;

    $ssh->fatal_disconnect("Bad server public DH value")
        unless _pub_is_valid($dh, $dh_server_pub);

    my $shared_secret = $dh->compute_key($dh_server_pub);

    my $hash = $kex->kex_hash(
        $ssh->client_version_string,
        $ssh->server_version_string,
        $kex->client_kexinit,
        $kex->server_kexinit,
        $host_key_blob,
        $p, $g,
        $dh->pub_key,
        $dh_server_pub,
        $shared_secret);

    $ssh->debug("Verifying server signature.");
    croak "Key verification failed for server host key"
        unless $s_host_key->verify($signature, $hash);

    $ssh->session_id($hash);

    $kex->derive_keys($hash, $shared_secret, $ssh->session_id);
}

sub kex_hash {
    my $kex = shift;
    my($c_vs, $s_vs, $c_kexinit, $s_kexinit, $s_host_key_blob,
       $p, $g, $c_dh_pub, $s_dh_pub, $shared_secret) = @_;
    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    # version strings (V_C, V_S)
    $b->put_str($c_vs);
    $b->put_str($s_vs);
    # client,server payload of SSH_MSG_KEXINIT (I_C, I_S)
    $b->put_int32($c_kexinit->length + 1);
    $b->put_int8(SSH2_MSG_KEXINIT);
    $b->put_chars($c_kexinit->bytes);
    $b->put_int32($s_kexinit->length + 1);
    $b->put_int8(SSH2_MSG_KEXINIT);
    $b->put_chars($s_kexinit->bytes);
    # host key (K_S)
    $b->put_str($s_host_key_blob);
    # min, n, max
    $b->put_int32($kex->min_bits);
    $b->put_int32($kex->want_bits);
    $b->put_int32($kex->max_bits);
    # p, g
    $b->put_mp_int($p);
    $b->put_mp_int($g);
    # e, f, K
    $b->put_mp_int($c_dh_pub);
    $b->put_mp_int($s_dh_pub);
    $b->put_mp_int($shared_secret);

    my $sha2 = Digest::SHA2->new(256) or return;
    $sha2->add($b->bytes);
    $sha2->digest;
}

sub derive_key {
    my($kex, $id, $need, $hash, $shared_secret, $session_id) = @_;
    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->put_mp_int($shared_secret);
    my $sha2 = Digest::SHA2->new(256) or return;
    $sha2->add($b->bytes, $hash, chr($id), $session_id);
    my $digest = $sha2->digest;
    for (my $have = 20; $need > $have; $have += 20) {
        $sha2->reset;
        $sha2->add($b->bytes, $hash, $digest);
        $digest .= $sha2->digest;
    }
    $digest;
}

sub _pub_is_valid {
    my($dh, $dh_pub) = @_;
    return if $dh_pub < 0;

    my $bits_set = 0;
    my $n = bitsize($dh_pub);
    for my $i (0..$n) {
	$bits_set++ if $dh_pub & (PARI(1) << PARI($i));
        last if $bits_set > 1;
    }

    $bits_set > 1 && $dh_pub < ($dh->p-1);
}

sub _gen_key {
    my $kex = shift;
    my $dh = shift;
    my $tries = 0;
    {
	$dh->generate_keys;
	last if _pub_is_valid($dh, $dh->pub_key);
	croak "Too many bad keys: giving up" if $tries++ > 10;
    }
}

sub _dh_new_group {
    my $kex = shift;
    my ($p,$g) = @_;
    my $dh = Crypt::DH->new;
    $dh->g($g);
    $dh->p($p);

    $kex->_gen_key($dh);
    $dh;
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Kex::DHGEX256 - Diffie-Hellman Group Exchange
using SHA256 hashing.

=head1 SYNOPSIS

    use Net::SSH::Perl::Kex;
    my $kex = Net::SSH::Perl::Kex->new;
    my $dh = bless $kex, 'Net::SSH::Perl::Kex::DHGEX256';

    $dh->exchange;

=head1 DESCRIPTION

I<Net::SSH::Perl::Kex::DHGEX256> implements Diffie-Hellman Group
Exchange for I<Net::SSH::Perl>. It is a subclass of
I<Net::SSH::Perl::Kex>.

=head1 AUTHOR & COPYRIGHTS

Lance Kinley E<lkinley@loyaltymethods.com>

Copyright (c) 2015 Loyalty Methods, Inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut
