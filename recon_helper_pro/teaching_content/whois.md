# Registration data (RDAP / WHOIS)

## before
Every domain name is rented, not owned, and the rental record is public. RDAP is
the modern, structured version of that record; WHOIS is the older plain-text one.

This step asks a registry - a third party - what it knows about the name. The
target's own servers are never contacted, so nothing appears in their logs. That
is why this is a good first step: it is free information with zero footprint.

What you are looking for: who the registrar is, when the domain was created and
when it expires, which name servers are authoritative, and (rarely, these days)
who registered it.

## after
Read the dates first. A creation date from years ago tells you this is an
established name; one from last week tells you something very different.

The registrant is usually redacted - GDPR and registrar privacy services removed
most personal data from these records around 2018. An empty registrant field is
normal and is not a finding.

The name servers matter more than people expect. They tell you who runs DNS for
the domain, which is often a hosting provider or a CDN, and that shapes what the
rest of your recon will see.

Status values like `clientTransferProhibited` are registry locks. Their absence
is worth a question, not an accusation - many registries simply do not publish
status values.

## next
- Run the DNS module to see where the name actually points.
- Look at the name servers: do they belong to the organisation, or to a provider?
- If the expiry date is close, note it as an availability risk, not a vulnerability.
