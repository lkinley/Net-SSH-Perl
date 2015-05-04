# $Id: DH1.pm,v 1.19 2009/01/26 01:00:25 turnstep Exp $

package Net::SSH::Perl::Kex::DH1;
use strict;

use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Constants qw( :msg2 :kex );
use Net::SSH::Perl::Key;
use Net::SSH::Perl::Util qw( bitsize );

use Carp qw( croak );
use Crypt::DH;
use Math::Pari;
use Digest::SHA1 qw( sha1 );
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

sub exchange {
    my $kex = shift;
    my $ssh = $kex->{ssh};
    my $packet;
    my $dh = _dh_new_group1();

    $ssh->debug("Entering Diffie-Hellman Group 1 key exchange.");
    $packet = $ssh->packet_start(SSH2_MSG_KEXDH_INIT);
    $packet->put_mp_int($dh->pub_key);
    $packet->send;

    $ssh->debug("Sent DH public key, waiting for reply.");
    $packet = Net::SSH::Perl::Packet->read_expect($ssh,
        SSH2_MSG_KEXDH_REPLY);

    my $host_key_blob = $packet->get_str;
    my $s_host_key = Net::SSH::Perl::Key->new_from_blob($host_key_blob,
        \$ssh->{datafellows});
    $ssh->debug("Received host key, type '" . $s_host_key->ssh_name . "'.");

    $ssh->check_host_key($s_host_key);

    my $dh_server_pub = $packet->get_mp_int;
    my $signature = $packet->get_str;

    $ssh->fatal_disconnect("Bad server public DH value")
        unless _pub_is_valid($dh, $dh_server_pub);

    $ssh->debug("Computing shared secret key.");
    my $shared_secret = $dh->compute_key($dh_server_pub);

    my $hash = $kex->kex_hash(
        $ssh->client_version_string,
        $ssh->server_version_string,
        $kex->client_kexinit,
        $kex->server_kexinit,
        $host_key_blob,
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
       $c_dh_pub, $s_dh_pub, $shared_secret) = @_;
    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->put_str($c_vs);
    $b->put_str($s_vs);

    $b->put_int32($c_kexinit->length + 1);
    $b->put_int8(SSH2_MSG_KEXINIT);
    $b->put_chars($c_kexinit->bytes);
    $b->put_int32($s_kexinit->length + 1);
    $b->put_int8(SSH2_MSG_KEXINIT);
    $b->put_chars($s_kexinit->bytes);

    $b->put_str($s_host_key_blob);
    $b->put_mp_int($c_dh_pub);
    $b->put_mp_int($s_dh_pub);
    $b->put_mp_int($shared_secret);

    sha1($b->bytes);
}

sub _dh_new_group1 {
    my $dh = Crypt::DH->new;
    $dh->g(2);
    $dh->p("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF");
    _gen_key($dh);
    $dh;
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

    $bits_set > 1 && $dh_pub < $dh->p;
}

sub _gen_key {
    my $dh = shift;
    my $tries = 0;
    {
	$dh->generate_keys;
	last if _pub_is_valid($dh, $dh->pub_key);
	croak "Too many bad keys: giving up" if $tries++ > 10;
    }
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Kex::DH1 - Diffie-Hellman Group 1 Key Exchange

=head1 SYNOPSIS

    use Net::SSH::Perl::Kex;
    my $kex = Net::SSH::Perl::Kex->new;
    my $dh1 = bless $kex, 'Net::SSH::Perl::Kex::DH1';

    $dh1->exchange;

=head1 DESCRIPTION

I<Net::SSH::Perl::Kex::DH1> implements Diffie-Hellman Group 1 Key
Exchange for I<Net::SSH::Perl>. It is a subclass of
I<Net::SSH::Perl::Kex>.

Group 1 Key Exchange uses the Diffie-Hellman key exchange algorithm
to produce a shared secret key between client and server, without
ever sending the shared secret over the insecure network. All that is
sent are the client and server public keys.

I<Net::SSH::Perl::Kex::DH1> uses I<Crypt::DH> for the Diffie-Hellman
implementation. The I<p> value is set to

      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
      FFFFFFFF FFFFFFFF

And the generator I<g> is set to I<2>.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright, and
license information.

=cut
