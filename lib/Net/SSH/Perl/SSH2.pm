# $Id: SSH2.pm,v 1.47 2009/01/26 01:50:38 turnstep Exp $

package Net::SSH::Perl::SSH2;
use strict;
use warnings;

use Net::SSH::Perl::Kex;
use Net::SSH::Perl::ChannelMgr;
use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Constants qw( :protocol :msg2
                                  CHAN_INPUT_CLOSED CHAN_INPUT_WAIT_DRAIN );
use Net::SSH::Perl::Cipher;
use Net::SSH::Perl::AuthMgr;
use Net::SSH::Perl::Comp;
use Net::SSH::Perl::Util qw( :hosts :win32 );

use base qw( Net::SSH::Perl );

use Carp qw( croak );
use File::Spec::Functions qw( catfile );
use File::HomeDir ();

use Errno;

use vars qw( $VERSION $CONFIG $HOSTNAME );
$VERSION = $Net::SSH::Perl::VERSION;

sub select_class { 'IO::Select' }

sub _dup {
    my($fh, $mode) = @_;

    if ( $^O eq 'MSWin32' ) {
        #
        # On Windows platform select() is working only for sockets.
        #
        my ( $r, $w ) = _socketpair()
            or die "Could not create socketpair: $!\n";

        # TODO: full support (e.g. stdin)

        return ( $mode eq '>' ) ? $w : $r;
    }

    my $dup = Symbol::gensym;
    my $str = "${mode}&$fh";
    open ($dup, $str) or die "Could not dupe: $!\n"; ## no critic
    $dup;
}

sub version_string {
    my $class = shift;
    sprintf "Net::SSH::Perl Version %s, protocol version %s.%s.",
        $class->VERSION, PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2;
}

sub _proto_init {
    my $ssh = shift;
    my $home = File::HomeDir->my_home;
    my $config = $ssh->{config};

    unless ($config->get('user_known_hosts')) {
        defined $home or croak "Cannot determine home directory, please set the environment variable HOME";
        $config->set('user_known_hosts', catfile($home, '.ssh', 'known_hosts2'));
    }
    unless ($config->get('global_known_hosts')) {
        my $glob_known_hosts = $^O eq 'MSWin32'
          ? catfile( $ENV{WINDIR}, 'ssh_known_hosts2' )
          : '/etc/ssh_known_hosts2';
        $config->set('global_known_hosts', $glob_known_hosts);
    }
    unless (my $if = $config->get('identity_files')) {
        defined $home or croak "Cannot determine home directory, please set the environment variable HOME";
        $config->set('identity_files', [ catfile($home, '.ssh', 'id_dsa') ]);
    }

    for my $a (qw( password dsa kbd_interactive )) {
        $config->set("auth_$a", 1)
            unless defined $config->get("auth_$a");
    }
}

sub kex { $_[0]->{kex} }

sub register_handler {
    my($ssh, $type, $sub, @extra) = @_;
    $ssh->{client_handlers}{$type} = { code => $sub, extra => \@extra };
}

sub login {
    my $ssh = shift;
    $ssh->SUPER::login(@_);
    my $suppress_shell = $_[2];
    $ssh->_login or $ssh->fatal_disconnect("Permission denied");

    $ssh->debug("Login completed, opening dummy shell channel.");
    my $cmgr = $ssh->channel_mgr;
    my $channel = $cmgr->new_channel(
        ctype => 'session', local_window => 0,
        local_maxpacket => 0, remote_name => 'client-session');
    $channel->open;

    my $packet = Net::SSH::Perl::Packet->read_expect($ssh,
        SSH2_MSG_CHANNEL_OPEN_CONFIRMATION);
    $cmgr->input_open_confirmation($packet);

    unless ($suppress_shell) {
        $ssh->debug("Got channel open confirmation, requesting shell.");
        $channel->request("shell", 0);
    }
}

sub _login {
    my $ssh = shift;

    my $kex = Net::SSH::Perl::Kex->new($ssh);
    $kex->exchange;

    my $amgr = Net::SSH::Perl::AuthMgr->new($ssh);
    $amgr->authenticate;
}

sub _session_channel {
    my $ssh = shift;
    my $cmgr = $ssh->channel_mgr;

    my $channel = $cmgr->new_channel(
        ctype => 'session', local_window => 32*1024,
        local_maxpacket => 16*1024, remote_name => 'client-session',
        rfd => _dup('STDIN', '<'), wfd => _dup('STDOUT', '>'),
        efd => _dup('STDERR', '>'));

    $channel;
}

sub _make_input_channel_req {
    my($r_exit) = @_;
    return sub {
        my($channel, $packet) = @_;
        my $rtype = $packet->get_str;
        my $reply = $packet->get_int8;
        $channel->{ssh}->debug("input_channel_request: rtype $rtype reply $reply");
        if ($rtype eq "exit-status") {
            $$r_exit = $packet->get_int32;
        }
        if ($reply) {
            my $r_packet = $channel->{ssh}->packet_start(SSH2_MSG_CHANNEL_SUCCESS);
            $r_packet->put_int($channel->{remote_id});
            $r_packet->send;
        }
    };
}

sub cmd {
    my $ssh = shift;
    my($cmd, $stdin) = @_;
    my $cmgr = $ssh->channel_mgr;
    my $channel = $ssh->_session_channel;
    $channel->open;

    $channel->register_handler(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, sub {
        my($channel, $packet) = @_;

                ## Experimental pty support:
                if ($ssh->{config}->get('use_pty')) {
			$ssh->debug("Requesting pty.");

			my $packet = $channel->request_start('pty-req', 0);

			my($term) = $ENV{TERM} =~ /(\w+)/;
			$packet->put_str($term);
			my $foundsize = 0;
			if (eval "require Term::ReadKey") {
				my @sz = Term::ReadKey::GetTerminalSize($ssh->sock);
				if (defined $sz[0]) {
					$foundsize = 1;
					$packet->put_int32($sz[1]); # height
					$packet->put_int32($sz[0]); # width
					$packet->put_int32($sz[2]); # xpix
					$packet->put_int32($sz[3]); # ypix
				}
			}
			if (!$foundsize) {
				$packet->put_int32(0) for 1..4;
			}

            # Array used to build Pseudo-tty terminal modes; fat commas separate opcodes from values for clarity.

            my $terminal_mode_string;
            if(!defined($ssh->{config}->get('terminal_mode_string'))) {
                my @terminal_modes = (
                   5 => 0,0,0,4,      # VEOF => 0x04 (^d)
                   0                  # string must end with a 0 opcode
                );
                for my $char (@terminal_modes) {
                    $terminal_mode_string .= chr($char);
                }
            }
            else {
                $terminal_mode_string = $ssh->{config}->get('terminal_mode_string');
            }
            $packet->put_str($terminal_mode_string);
            $packet->send;
        }

        my $r_packet = $channel->request_start("exec", 0);
        $r_packet->put_str($cmd);
        $r_packet->send;

        if (defined $stdin) {
            if($ssh->{config}->get('use_pty') && !$ssh->{config}->get('no_append_veof')) {
                my $append_string = $ssh->{config}->get('stdin_append');
                if(!defined($append_string)) {
                    $append_string = chr(4) . chr(4);
                }
                $stdin .= $append_string;
            }
            $channel->send_data($stdin);

            $channel->drain_outgoing;
            $channel->{istate} = CHAN_INPUT_WAIT_DRAIN;
            $channel->send_eof;
            $channel->{istate} = CHAN_INPUT_CLOSED;
        }
    });

    my($exit);
    $channel->register_handler(SSH2_MSG_CHANNEL_REQUEST,
        _make_input_channel_req(\$exit));

    my $h = $ssh->{client_handlers};
    my($stdout, $stderr);
    if (my $r = $h->{stdout}) {
        $channel->register_handler("_output_buffer",
            $r->{code}, @{ $r->{extra} });
    }
    else {
        $channel->register_handler("_output_buffer", sub {
            $stdout .= $_[1]->bytes;
        });
    }
    if (my $r = $h->{stderr}) {
        $channel->register_handler("_extended_buffer",
            $r->{code}, @{ $r->{extra} });
    }
    else {
        $channel->register_handler("_extended_buffer", sub {
            $stderr .= $_[1]->bytes;
        });
    }

    $ssh->debug("Entering interactive session.");
    $ssh->client_loop;

    ($stdout, $stderr, $exit);
}

sub shell {
    my $ssh = shift;
    my $cmgr = $ssh->channel_mgr;
    my $channel = $ssh->_session_channel;
    $channel->open;

    $channel->register_handler(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, sub {
        my($channel, $packet) = @_;
        my $r_packet = $channel->request_start('pty-req', 0);
        my($term) = $ENV{TERM} =~ /(\S+)/;
        $r_packet->put_str($term);
        my $foundsize = 0;
        if (eval "require Term::ReadKey") {
            my @sz = Term::ReadKey::GetTerminalSize($ssh->sock);
            if (defined $sz[0]) {
                $foundsize = 1;
                $r_packet->put_int32($sz[0]); # width
                $r_packet->put_int32($sz[1]); # height
                $r_packet->put_int32($sz[2]); # xpix
                $r_packet->put_int32($sz[3]); # ypix
            }
        }
        if (!$foundsize) {
            $r_packet->put_int32(0) for 1..4;
        }
        $r_packet->put_str("");
        $r_packet->send;
        $channel->{ssh}->debug("Requesting shell.");
        $channel->request("shell", 0);
    });

    my($exit);
    $channel->register_handler(SSH2_MSG_CHANNEL_REQUEST,
        _make_input_channel_req(\$exit));

    $channel->register_handler("_output_buffer", sub {
        syswrite STDOUT, $_[1]->bytes;
    });
    $channel->register_handler("_extended_buffer", sub {
        syswrite STDERR, $_[1]->bytes;
    });

    $ssh->debug("Entering interactive session.");
    $ssh->client_loop;
}

sub open2 {
    my $ssh = shift;
    my($cmd) = @_;

    require Net::SSH::Perl::Handle::SSH2;

    my $cmgr = $ssh->channel_mgr;
    my $channel = $ssh->_session_channel;
    $channel->open;

    $channel->register_handler(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, sub {
        my($channel, $packet) = @_;
        $channel->{ssh}->debug("Sending command: $cmd");
        my $r_packet = $channel->request_start("exec", 1);
        $r_packet->put_str($cmd);
        $r_packet->send;
    });

    my $exit;
    $channel->register_handler(SSH2_MSG_CHANNEL_REQUEST, sub {
    my($channel, $packet) = @_;
    my $rtype = $packet->get_str;
    my $reply = $packet->get_int8;
    $channel->{ssh}->debug("input_channel_request: rtype $rtype reply $reply");
    if ($rtype eq "exit-status") {
        $exit = $packet->get_int32;
    }
    if ($reply) {
        my $r_packet = $channel->{ssh}->packet_start(SSH2_MSG_CHANNEL_SUCCESS);
        $r_packet->put_int($channel->{remote_id});
        $r_packet->send;
    }
    });

    my $reply = sub {
        my($channel, $packet) = @_;
        if ($packet->type == SSH2_MSG_CHANNEL_FAILURE) {
            $channel->{ssh}->fatal_disconnect("Request for " .
                "exec failed on channel '" . $packet->get_int32 . "'");
        }
        $channel->{ssh}->break_client_loop;
    };

    $cmgr->register_handler(SSH2_MSG_CHANNEL_FAILURE, $reply);
    $cmgr->register_handler(SSH2_MSG_CHANNEL_SUCCESS, $reply);

    $ssh->client_loop;

    my $read = Symbol::gensym;
    my $write = Symbol::gensym;
    tie *$read, 'Net::SSH::Perl::Handle::SSH2', 'r', $channel, \$exit;
    tie *$write, 'Net::SSH::Perl::Handle::SSH2', 'w', $channel, \$exit;

    return ($read, $write);
}

sub break_client_loop { $_[0]->{_cl_quit_pending} = 1 }
sub restore_client_loop { $_[0]->{_cl_quit_pending} = 0 }
sub _quit_pending { $_[0]->{_cl_quit_pending} }

sub client_loop {
    my $ssh = shift;
    my $cmgr = $ssh->channel_mgr;

    my $h = $cmgr->handlers;
    my $select_class = $ssh->select_class;

    CLOOP:
    $ssh->{_cl_quit_pending} = 0;
    while (!$ssh->_quit_pending) {
        while (my $packet = Net::SSH::Perl::Packet->read_poll($ssh)) {
            if (my $code = $h->{ $packet->type }) {
                $code->($cmgr, $packet);
            }
            else {
                $ssh->debug("Warning: ignore packet type " . $packet->type);
            }
        }
        last if $ssh->_quit_pending;

        $cmgr->process_output_packets;

        my $rb = $select_class->new;
        my $wb = $select_class->new;
        $rb->add($ssh->sock);
        $cmgr->prepare_channels($rb, $wb);

        #last unless $cmgr->any_open_channels;
        my $oc = grep { defined } @{ $cmgr->{channels} };
        last unless $oc > 1;

        my($rready, $wready) = $select_class->select($rb, $wb);
        unless (defined $rready or defined $wready) {
            next if ( $!{EAGAIN} || $!{EINTR} );
            die "select: $!";
        }

        $cmgr->process_input_packets($rready, $wready);

        for my $ab (@$rready) {
            if ($ab == $ssh->{session}{sock}) {
                my $buf;
                my $len = sysread $ab, $buf, 8192;
				if (! defined $len) {
					croak "Connection failed: $!\n";
				}
                $ssh->break_client_loop if $len == 0;
                ($buf) = $buf =~ /(.*)/s;  ## Untaint data. Anything allowed.
                $ssh->incoming_data->append($buf);
            }
        }
    }
}

sub channel_mgr {
    my $ssh = shift;
    unless (defined $ssh->{channel_mgr}) {
        $ssh->{channel_mgr} = Net::SSH::Perl::ChannelMgr->new($ssh);
    }
    $ssh->{channel_mgr};
}

1;
__END__

=head1 NAME

Net::SSH::Perl::SSH2 - SSH2 implementation

=head1 SYNOPSIS

    use Net::SSH::Perl;
    my $ssh = Net::SSH::Perl->new($host, protocol => 2);

=head1 DESCRIPTION

I<Net::SSH::Perl::SSH2> implements the SSH2 protocol. It is a
subclass of I<Net::SSH::Perl>, and implements the interface
described in the documentation for that module. In fact, your
usage of this module should be completely transparent; simply
specify the proper I<protocol> value (C<2>) when creating your
I<Net::SSH::Perl> object, and the SSH2 implementation will be
loaded automatically.

NOTE: Of course, this is still subject to protocol negotiation
with the server; if the server doesn't support SSH2, there's
not much the client can do, and you'll get a fatal error if
you use the above I<protocol> specification (C<2>).

=head2 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
