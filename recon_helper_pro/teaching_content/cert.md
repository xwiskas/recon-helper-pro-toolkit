# TLS certificate inspection

## before
This is the first step that actually touches the target. A TLS handshake is a
connection to the host, so its contact mode is `direct-read`: it is scope-checked,
rate-limited, counted against your budget, and it will appear in the target's
logs.

What we do is minimal and read-only: connect, complete the handshake, read the
certificate the server presents, and disconnect. No request is sent.

## after
Four things are worth your attention.

**Validity dates.** An expired certificate breaks the site for every visitor, so
it is usually an availability incident rather than an attacker's foothold. A
short remaining life is normal - Let's Encrypt certificates last 90 days.

**Subject Alternative Names.** One certificate typically covers several
hostnames, and those names are now recorded as assets. They were not contacted.

**Whether the chain validated.** If it did not, the reason matters: a missing
intermediate, a name mismatch and a self-signed certificate are three different
situations. Self-signed is normal on a lab box and wrong on a public site.

**The signature algorithm and protocol version.** SHA-1 signatures and anything
below TLS 1.2 are deprecated. Note that we only see the version *we* negotiated -
this is not a protocol enumeration.

## next
- Add any SAN hostname you are authorized to test to your scope.
- Move on to HTTP headers now that you know the host answers on 443.
- If validation failed, open the site in a browser and see what a real client says.
