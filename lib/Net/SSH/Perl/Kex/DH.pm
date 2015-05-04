package Net::SSH::Perl::Kex::DH;
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

    $ssh->debug('Generating new Diffie-Hellman Group ' . $kex->group . ' keys');
    my $dh = $kex->_dh_new_group();

    $ssh->debug('Entering Diffie-Hellman Group ' . $kex->group . ' key exchange.');
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

sub derive_key {
    my($kex, $id, $need, $hash, $shared_secret, $session_id) = @_;
    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->put_mp_int($shared_secret);
    my $digest = sha1($b->bytes, $hash, chr($id), $session_id);
    for (my $have = 20; $need > $have; $have += 20) {
        $digest .= sha1($b->bytes, $hash, $digest);
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

    $bits_set > 1 && $dh_pub < $dh->p;
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

1;
__END__

=head1 NAME

Net::SSH::Perl::Kex::DH - Diffie-Hellman Key Exchange Base Class

=head1 SYNOPSIS

    use Net::SSH::Perl::Kex;
    my $kex = Net::SSH::Perl::Kex->new;
    my $dh1 = bless $kex, 'Net::SSH::Perl::Kex::DH1';

    $dh1->exchange;

or

    use Net::SSH::Perl::Kex;
    my $kex = Net::SSH::Perl::Kex->new;
    my $dh14 = bless $kex, 'Net::SSH::Perl::Kex::DH14';

    $dh1->exchange;

=head1 DESCRIPTION

I<Net::SSH::Perl::Kex::DH> implements Diffie-Hellman Key
Exchange for I<Net::SSH::Perl>. It is a subclass of
I<Net::SSH::Perl::Kex>.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright, and
license information.

Modifications for enabling DH Group 14 support and DH Group Exchange
by Lance Kinley E<lkinley@loyaltymethods.com>

=cut
