package otr;

use strict;
use warnings;
use base 'ZNC::Module';
use Crypt::OTR;
use constant FRAGMENT_SIZE => 300;

sub description { "OTR module for ZNC"; }
sub module_types { $ZNC::CModInfo::UserModule; }

sub OnLoad
{
	my $self = shift;

	Crypt::OTR->init;

	my $otr = new Crypt::OTR(
		account_name     => $self->GetUser->GetNick,
		protocol         => 'irc',
		max_message_size => FRAGMENT_SIZE
	);

	my $wrap_callback = sub
	{
		my $callback = shift;
		return sub { return &$callback($self, @_); };
	};

	$otr->set_callback('inject'     => &$wrap_callback(\&otr_inject));
	$otr->set_callback('unverified' => &$wrap_callback(\&otr_unverified));
	$self->{otr} = $otr;

	$self->{nickmasks} = {};

	return 1;
}

sub OnPrivMsg
{
	my $self = shift;
	my $otr = $self->{otr};
	my ($user, $message) = @_;

	my ($plaintext, $should_discard) = $otr->decrypt($user->GetNick, $message);
	if ($plaintext)
	{
		$self->PutUser(':' . $user->GetNickMask . ' PRIVMSG ' . $self->GetUser->GetNick . ' :' . $plaintext);
	}
	elsif (! $should_discard)
	{
		$self->PutUser(':' . $user->GetNickMask . ' PRIVMSG ' . $self->GetUser->GetNick . ' :' . $message);
	}
	
	$self->{nickmasks}->{$user->GetNick} = $user->GetNickMask;

	return $ZNC::HALT;
}

sub OnUserMsg
{
	my $self = shift;
	my $otr = $self->{otr};
	my ($target, $message) = @_;

	if ($target !~ /^#/)
	{
		if ($message eq 'otr')
		{
			$otr->establish($target);
		}
		else
		{
			if (my $ciphertext = $otr->encrypt($target, $message))
			{
				$self->PutIRC("PRIVMSG " . $target . " :" . $ciphertext);
			}
			else
			{
				$self->PutModule("Your message was not sent - no encrypted conversation is established");
			}
		}
		return $ZNC::HALT;
	}
	else
	{
		return $ZNC::CONTINUE;
	}
}

sub otr_inject
{
	my $plugin = shift;
	my $self = shift;

	my ($account_name, $protocol, $dest_account, $message) = @_;

	foreach my $line (split /^/, $message)
	{
		if (length($line) > FRAGMENT_SIZE && $line =~ /^\?OTR[^,]/)
		{
			my @fragments = ($line =~ /(.{1,@{[ FRAGMENT_SIZE ]}})/g);
			my $n = 1;
			foreach (@fragments)
			{
				my $temp = sprintf "?OTR,%hu,%hu,%s,", $n, scalar @fragments, $_;
				$plugin->PutIRC("PRIVMSG " . $dest_account . " :" . $temp);
				$n++;
			}
		}
		else
		{
			$plugin->PutIRC("PRIVMSG " . $dest_account . " :" . $line);
		}
	}
}

sub otr_unverified
{
	my $plugin = shift;
	my $self = shift;

	my $from_account = shift;
	my $from_nickmask = $plugin->{nickmasks}->{$from_account};

	$plugin->PutUser(":$from_nickmask PRIVMSG " . $plugin->GetUser->GetNick . " :\x02Started unverified conversation with $from_account\x02");
}

1;