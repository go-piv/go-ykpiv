Qurks of ykpiv
==============

ykpiv.Yubikey.Slot
------------------

Slots which have private keys backing them but were not generated on the
Yubikey are unable to be loaded unless a public certificate has already
been set. If an attestation key exists, and an attestation certificate
can be loaded for the slot, the public key will be available. These slots
will however not have a valid x509 certificate available for authentication.

Basically, the only way to get a Slot with a nil Certificate is to call
the Generation code, where we are actually able to pull the Public Key
material out, and allow for bootstrapping. The advisable workflow would be
to generate the key, then sign a CSR to import the Certificate later
when we have one, or to Self Sign a Certificate, then import it.

ykpiv.Slot.Update
-----------------

Because the Certificate is hanging off the Slot object, there is a tradeoff in
terms of number of times we read the Certificate off the Key, and the ability
to get updated Certificates when they are pushed in.

There have been no attempts to be clever here, so it is *not* advisable to keep
a `Slot` around for long-running processes, if you can avoid it. If it becomes
strictly needed, at least understand your Certificate may become out of sync
if another process Updates it.

ykpiv.Options / ykpiv.Yubikey.ChangePIN
---------------------------------------

Changing the PIN does not touch the Options entries, and attempts to Login
after ChangePIN will use the old PIN.
