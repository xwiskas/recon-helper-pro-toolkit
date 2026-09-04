# DNS records

## before
DNS is the phone book of the internet: it turns names into addresses and carries
a surprising amount of infrastructure detail along the way.

This step asks a resolver - again, a third party - for the records attached to
the name. The target is not contacted. A resolver may have the answer cached, in
which case not even the authoritative name server hears from us.

Record types you will see:

- **A / AAAA** - the IPv4 / IPv6 addresses the name points to.
- **MX** - where mail for this domain is delivered.
- **NS** - the authoritative name servers.
- **TXT** - free-form text, which is where SPF, domain verification tokens and
  various provider proofs live.
- **CNAME** - an alias pointing at another name.
- **SOA** - administrative metadata for the zone.

## after
Start with A/AAAA. If the address belongs to a CDN or cloud provider, remember
that everything you observe over HTTP afterwards may describe the CDN rather than
the origin server.

MX records tell you the mail provider. TXT records often give away which SaaS
products an organisation uses, because each one asks for a verification string.
That is attack surface information, not a weakness.

The SPF and DMARC checks in this module describe *mail* security, not web
security. A missing DMARC record does not make a website vulnerable; it makes the
domain easier to spoof in email. Keep those two ideas separate in your report.

## next
- Run reverse DNS on the addresses you found to see who owns the network.
- If you see a CNAME to a third-party service, note it: dangling CNAMEs are a
  real class of issue, though confirming one takes more than a DNS lookup.
- Move on to certificate transparency to find hostnames DNS did not reveal.
