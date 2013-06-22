znc-otr
=======

znc-otr is a plugin for the [ZNC IRC bouncer](http://znc.in/) which adds support for [Off-the-Record encryption](http://www.cypherpunks.ca/otr/) in private messages

Installation
------------

These instructions are for debian but the process is probably similar on other distros

* `aptitude install znc-perl`
* `aptitude install libotr2-dev`
* `cpan Digest::SHA1`
    * unfortunately this package isn't included in `libdigest-sha-perl` so we have to get it from CPAN
* `cpan Crypt::OTR`
    * requires a working C compiler and `make` - the easiest way to get these is to install `build-essential`
* copy `otr.pm` to `~/.znc/modules/otr.pm`

Loading in ZNC
--------------

* `loadmodule modperl`
* `loadmodule otr`
    * if this causes Crypt::OTR to complain about taint then do `mkdir ~/.otr` and try again

Usage
-----

* when the module is loaded, outgoing PMs will use whitespace marking to announce that you support OTR
* to forcibly initiate an OTR session, send the message `otr` on its own to the recipient

Notes
-----

* encryption is done on the server-side so you need to connect to your bouncer over SSL otherwise this is pointless
* initial key generation requires a lot of entropy. `/dev/srandom` may block on headless servers - installing [haveged](http://www.issihosts.com/haveged/) may help
* this does not support OTR verification
* this does not encrypt DCC
* there's no way to end an OTR conversation yet other than unloading the module