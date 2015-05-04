# $Id: SSH2MP.pm,v 1.4 2005/01/16 21:05:18 dbrobins Exp $

package Net::SSH::Perl::Util::SSH2MP;
use strict;

use Math::Pari qw( PARI floor pari2num Mod lift );

sub bitsize {
    return pari2num(floor(Math::Pari::log($_[0])/Math::Pari::log(2)) + 1);
}

sub bin2mp {
    my $s = shift;
    my $p = PARI(0);
    my $base = PARI(256);
    for my $b (split //, $s) {
        $p = $p * $base + ord $b;
    }
    $p;
}

sub mp2bin {
    my($p, $l) = @_;
    $l ||= 0;
    my $base = PARI(256);
    my $res = '';
    {
        my $r = $p % $base;
        my $d = PARI($p-$r) / $base;
        $res = chr($r) . $res;
        if ($d >= $base) {
            $p = $d;
            redo;
        }
        elsif ($d != 0) {
            $res = chr($d) . $res;
        }
    }
    $res = "\0" x ($l-length($res)) . $res
        if length($res) < $l;
    $res;
}

sub mod_inverse {
    my($a, $n) = @_;
    my $m = Mod(1, $n);
    lift($m / $a);
}

1;
