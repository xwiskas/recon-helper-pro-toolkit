# HTTP header analysis

## before
This step sends one request - a plain GET of the homepage - and reads the headers
that come back. Contact mode is `direct-read`. HTTPS is tried first, with HTTP as
a fallback.

Response headers carry two useful kinds of information: what the server tells
browsers to enforce (the security headers), and what the server accidentally tells
you about itself (software and versions).

## after
The single most important habit to learn here: **a missing security header is not
a vulnerability.** It is a missing layer of defence. Content-Security-Policy
limits the damage of a cross-site scripting bug; its absence does not create one.
X-Frame-Options prevents clickjacking; its absence only matters if the page has
something worth clickjacking.

This is why every finding in this section carries limitations and a
context-dependent severity hint rather than a score. Reporting "no CSP" as a
high-severity vulnerability is one of the fastest ways to lose credibility.

Version banners are the same story in reverse. `Server: Apache/2.4.29` does not
mean the host is exploitable; it means an attacker does not have to guess. Check
the patch level before you conclude anything, and never report a CVE from a
banner alone.

Cookies are worth a careful look. `Secure`, `HttpOnly` and `SameSite` matter a
great deal on a session cookie and not at all on one holding a theme preference.
The cookie's value is redacted before storage, so you will need to work out which
kind it is yourself.

## next
- Fingerprint the technology stack to give the banners context.
- Check the published files, which often reveal how the site is organised.
- For anything that looks like a real gap, verify it by hand in a browser.
