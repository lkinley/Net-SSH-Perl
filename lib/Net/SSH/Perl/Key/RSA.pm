# $Id: RSA.pm,v 1.10 2009/01/26 01:12:28 turnstep Exp $

package Net::SSH::Perl::Key::RSA;
use strict;

use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Constants qw( SSH_COMPAT_BUG_RSASIGMD5 );
use Net::SSH::Perl::Util qw( :ssh2mp );

use Net::SSH::Perl::Key;

use Math::Pari qw( PARI );
use MIME::Base64;
use Crypt::RSA;
use Crypt::RSA::Primitives;
use Crypt::RSA::Key;
use Crypt::RSA::Key::Private;
use Crypt::RSA::Key::Public;
use Crypt::RSA::SS::PKCS1v15;
use base qw( Net::SSH::Perl::Key );
use Convert::PEM;
use Carp qw( croak );
use Digest::SHA1 qw( sha1 );

use constant INTBLOB_LEN => 20;

sub ssh_name { 'ssh-rsa' }

sub init {
    my $key = shift;
    $key->{rsa_priv} = Crypt::RSA::Key::Private->new(Password => 'ssh');
    $key->{rsa_pub} = Crypt::RSA::Key::Public->new;

    my($blob, $datafellows) = @_;

    if ($blob) {
        my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
        $b->append($blob);
        my $ktype = $b->get_str;
        croak __PACKAGE__, "->init: cannot handle type '$ktype'"
            unless $ktype eq $key->ssh_name;
        $key->{rsa_pub}->e( $b->get_mp_int );
        $key->{rsa_pub}->n( $b->get_mp_int );
    }

    if ($datafellows) {
        $key->{datafellows} = $datafellows;
    }
}

sub keygen {
    my $class = shift;
    my($bits, $datafellows) = @_;
    my $rsa = Crypt::RSA->new;
    my $key = $class->new(undef, $datafellows);
    ($key->{rsa_pub}, $key->{rsa_priv}) = $rsa->keygen(
                     Size      => $bits,
                     Password  => 'ssh',
                     Verbosity => 1,
                     Identity  => 'Net::SSH::Perl',
           );
    die $rsa->errstr unless $key->{rsa_pub} && $key->{rsa_priv};

    $key;
}

sub size { bitsize($_[0]->{rsa_pub}->n) }

sub read_private {
    my $class = shift;
    my($key_file, $passphrase, $datafellows) = @_;

    my $key = $class->new(undef, $datafellows);
    my $pem = $key->_pem;
    my $pkey = $pem->read(
                  Filename => $key_file,
                  Password => $passphrase
             );
    return unless $pkey;

    for my $m (qw( n e )) {
        $key->{rsa_pub}->$m( $pkey->{RSAPrivateKey}->{$m} );
    }
    ## Don't use iqmp from the keyfile; let Crypt::RSA compute
    ## it on its own, because the parameters in Crypt::RSA CRT
    ## differ from those in OpenSSL, and we need to use ipmq,
    ## not iqmp.
    for my $m (qw( n d p q dp dq )) {
        $key->{rsa_priv}->$m( $pkey->{RSAPrivateKey}->{$m} );
    }

    $key;
}

sub write_private {
    my $key = shift;
    my($key_file, $passphrase) = @_;

    my $pem = $key->_pem;
    my $pkey = { RSAPrivateKey => { } };

    $pkey->{RSAPrivateKey}->{version} = 0;
    $pkey->{RSAPrivateKey}->{e} = $key->{rsa_pub}->e;
    for my $m (qw( n d p q dp dq )) {
        $pkey->{RSAPrivateKey}->{$m} = $key->{rsa_priv}->$m();
    }

    ## Force generation of 'iqmp', which is inverse of q mod p.
    ## Crypt::RSA calculates ipmq (inverse of p mod q), which is
    ## incompatible with OpenSSL.
    $pkey->{RSAPrivateKey}->{iqmp} =
        mod_inverse($key->{rsa_priv}->q, $key->{rsa_priv}->p);

    unless ($pem->write(
                    Filename => $key_file,
                    Password => $passphrase,
                    Content  => $pkey
           )) {
        die $pem->errstr;
    }
}

sub _pem {
    my $key = shift;
    unless (defined $key->{__pem}) {
        my $pem = Convert::PEM->new(
              Name => 'RSA PRIVATE KEY',
              ASN  => qq(
                  RSAPrivateKey SEQUENCE {
                      version INTEGER,
                      n INTEGER,
                      e INTEGER,
                      d INTEGER,
                      p INTEGER,
                      q INTEGER,
                      dp INTEGER,
                      dq INTEGER,
                      iqmp INTEGER
                  }
           ));
        $pem->asn->configure( decode => { bigint => 'Math::Pari' },
                              encode => { bigint => 'Math::Pari' } );
        $key->{__pem} = $pem;
    }
    $key->{__pem};
}

sub dump_public { $_[0]->ssh_name . ' ' . encode_base64( $_[0]->as_blob, '' ) }

sub sign {
    my $key = shift;
    my($data) = @_;
    my $dgst = ${ $key->{datafellows} } & SSH_COMPAT_BUG_RSASIGMD5
		? 'MD5' : 'SHA1';
    my $rsa = Crypt::RSA::SS::PKCS1v15->new( Digest => $dgst );
    my $sig = $rsa->sign(
                 Digest  => $dgst,
                 Message => $data,
                 Key     => $key->{rsa_priv}
           );
    croak $rsa->errstr unless $sig;

    my $buf = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $buf->put_str($key->ssh_name);
    $buf->put_str($sig);
    $buf->bytes;
}

sub verify {
    my $key = shift;
    my($signature, $data) = @_;

    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->append($signature);
    my $ktype = $b->get_str;
    croak "Can't verify type ", $ktype unless $ktype eq $key->ssh_name;
    my $sigblob = $b->get_str;

    my $dgst = ${ $key->{datafellows} } & SSH_COMPAT_BUG_RSASIGMD5 ?
        'MD5' : 'SHA1';

    my $rsa = Crypt::RSA::SS::PKCS1v15->new( Digest => $dgst );
    $rsa->verify(
                 Key       => $key->{rsa_pub},
                 Digest    => $dgst,
                 Message   => $data,
                 Signature => $sigblob
           );
}

sub equal {
    my($keyA, $keyB) = @_;
    $keyA->{rsa_pub} && $keyB->{rsa_pub} &&
    $keyA->{rsa_pub}->e == $keyB->{rsa_pub}->e &&
    $keyA->{rsa_pub}->n == $keyB->{rsa_pub}->n;
}

sub as_blob {
    my $key = shift;
    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->put_str($key->ssh_name);
    $b->put_mp_int($key->{rsa_pub}->e);
    $b->put_mp_int($key->{rsa_pub}->n);
    $b->bytes;
}

sub fingerprint_raw { $_[0]->as_blob }

1;
__END__

=head1 NAME

Net::SSH::Perl::Key::RSA - RSA key object

=head1 SYNOPSIS

    use Net::SSH::Perl::Key;
    my $key = Net::SSH::Perl::Key->new('RSA');

=head1 DESCRIPTION

I<Net::SSH::Perl::Key::RSA> subclasses I<Net::SSH::Perl::Key>
to implement a key object, SSH style. This object provides all
of the methods needed for a RSA key object; the underlying
implementation is provided by I<Crypt::RSA>, and this class
wraps around that module to provide SSH-specific functionality
(eg. taking in a I<Net::SSH::Perl::Buffer> blob and transforming
it into a key object).

=head1 USAGE

I<Net::SSH::Perl::Key::RSA> implements the interface described in
the documentation for I<Net::SSH::Perl::Key>. Any differences or
additions are described here.

=head2 $key->sign($data)

Wraps around I<Crypt::RSA::SS::PKCS1v15::sign> to sign I<$data>
using the private key portions of I<$key>, then encodes that
signature into an SSH-compatible signature blob.

Returns the signature blob.

=head2 $key->verify($signature, $data)

Given a signature blob I<$signature> and the original signed data
I<$data>, attempts to verify the signature using the public key
portion of I<$key>. This wraps around
I<Crypt::RSA::SS::PKCS1v15::verify> to perform the core verification.

I<$signature> should be an SSH-compatible signature blob, as
returned from I<sign>; I<$data> should be a string of data, as
passed to I<sign>.

Returns true if the verification succeeds, false otherwise.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
