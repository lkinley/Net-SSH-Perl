# $Id: DSA.pm,v 1.24 2008/10/02 18:51:15 turnstep Exp $

package Net::SSH::Perl::Key::DSA;
use strict;

use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Constants qw( SSH_COMPAT_BUG_SIGBLOB );
use Net::SSH::Perl::Util qw( :ssh2mp );

use Net::SSH::Perl::Key;
use base qw( Net::SSH::Perl::Key );

use MIME::Base64;
use Crypt::DSA;
use Crypt::DSA::Key;
use Crypt::DSA::Signature;
use Carp qw( croak );
use Digest::SHA1 qw( sha1 );

use constant INTBLOB_LEN => 20;

sub ssh_name { 'ssh-dss' }

sub init {
    my $key = shift;
    $key->{dsa} = Crypt::DSA::Key->new;

    my($blob, $datafellows) = @_;

    if ($blob) {
        my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
        $b->append($blob);
        my $ktype = $b->get_str;
        croak __PACKAGE__, "->init: cannot handle type '$ktype'"
            unless $ktype eq $key->ssh_name;
        my $dsa = $key->{dsa};
        $dsa->p( $b->get_mp_int );
        $dsa->q( $b->get_mp_int );
        $dsa->g( $b->get_mp_int );
        $dsa->pub_key( $b->get_mp_int );
    }

    if ($datafellows) {
        $key->{datafellows} = $datafellows;
    }
}

sub keygen {
    my $class = shift;
    my($bits, $datafellows) = @_;
    my $dsa = Crypt::DSA->new;
    my $key = $class->new(undef, $datafellows);
    $key->{dsa} = $dsa->keygen(Size => $bits, Verbosity => 1);
    $key;
}

sub size { $_[0]->{dsa}->size }

sub read_private {
    my $class = shift;
    my($key_file, $passphrase, $datafellows, $keytype) = @_;
    $keytype ||= 'PEM';

    my $key = $class->new(undef, $datafellows);
    $key->{dsa} = Crypt::DSA::Key->new(
                     Filename => $key_file,
                     Type     => $keytype,
                     Password => $passphrase
            );
    return unless $key->{dsa};

    $key;
}

sub write_private {
    my $key = shift;
    my($key_file, $passphrase) = @_;

    $key->{dsa}->write(
                    Filename => $key_file,
                    Type     => 'PEM',
                    Password => $passphrase
            );
}

sub dump_public { $_[0]->ssh_name . ' ' . encode_base64( $_[0]->as_blob, '' ) }

sub sign {
    my $key = shift;
    my($data) = @_;
    my $dsa = Crypt::DSA->new;
    my $sig = $dsa->sign(Digest => sha1($data), Key => $key->{dsa});
    my $sigblob = '';
    $sigblob .= mp2bin($sig->r, INTBLOB_LEN);
    $sigblob .= mp2bin($sig->s, INTBLOB_LEN);

    if (${$key->{datafellows}} & SSH_COMPAT_BUG_SIGBLOB) {
        return $sigblob;
    }
    else {
        my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
        $b->put_str($key->ssh_name);
        $b->put_str($sigblob);
        $b->bytes;
    }
}

sub verify {
    my $key = shift;
    my($signature, $data) = @_;
    my $sigblob;

    if (${$key->{datafellows}} & SSH_COMPAT_BUG_SIGBLOB) {
        $sigblob = $signature;
    }
    else {
        my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
        $b->append($signature);
        my $ktype = $b->get_str;
        croak "Can't verify type ", $ktype unless $ktype eq $key->ssh_name;
        $sigblob = $b->get_str;
    }

    my $sig = Crypt::DSA::Signature->new;
    $sig->r( bin2mp(substr $sigblob, 0, INTBLOB_LEN) );
    $sig->s( bin2mp(substr $sigblob, INTBLOB_LEN) );

    my $digest = sha1($data);
    my $dsa = Crypt::DSA->new;
    $dsa->verify( Key => $key->{dsa}, Digest => $digest, Signature => $sig );
}

sub equal {
    my($keyA, $keyB) = @_;
    $keyA->{dsa} && $keyB->{dsa} &&
    $keyA->{dsa}->p == $keyB->{dsa}->p &&
    $keyA->{dsa}->q == $keyB->{dsa}->q &&
    $keyA->{dsa}->g == $keyB->{dsa}->g &&
    $keyA->{dsa}->pub_key == $keyB->{dsa}->pub_key;
}

sub as_blob {
    my $key = shift;
    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->put_str($key->ssh_name);
    $b->put_mp_int($key->{dsa}->p);
    $b->put_mp_int($key->{dsa}->q);
    $b->put_mp_int($key->{dsa}->g);
    $b->put_mp_int($key->{dsa}->pub_key);
    $b->bytes;
}

sub fingerprint_raw { $_[0]->as_blob }

1;
__END__

=head1 NAME

Net::SSH::Perl::Key::DSA - DSA key object

=head1 SYNOPSIS

    use Net::SSH::Perl::Key;
    my $key = Net::SSH::Perl::Key->new('DSA');

=head1 DESCRIPTION

I<Net::SSH::Perl::Key::DSA> subclasses I<Net::SSH::Perl::Key>
to implement a key object, SSH style. This object provides all
of the methods needed for a DSA key object; the underlying
implementation is provided by I<Crypt::DSA>, and this class
wraps around that module to provide SSH-specific functionality
(eg. taking in a I<Net::SSH::Perl::Buffer> blob and transforming
it into a key object).

=head1 USAGE

I<Net::SSH::Perl::Key::DSA> implements the interface described in
the documentation for I<Net::SSH::Perl::Key>. Any differences or
additions are described here.

=head2 $key->sign($data)

Wraps around I<Crypt::DSA::sign> to sign I<$data> using the private
key portions of I<$key>, then encodes that signature into an
SSH-compatible signature blob.

Returns the signature blob.

=head2 $key->verify($signature, $data)

Given a signature blob I<$signature> and the original signed data
I<$data>, attempts to verify the signature using the public key
portion of I<$key>. This wraps around I<Crypt::DSA::verify> to
perform the core verification.

I<$signature> should be an SSH-compatible signature blob, as
returned from I<sign>; I<$data> should be a string of data, as
passed to I<sign>.

Returns true if the verification succeeds, false otherwise.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
