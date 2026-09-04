# Glossary

## asn
Autonomous System Number. An identifier for a network that announces routes on
the internet - typically an ISP, a hosting provider or a large organisation.
Knowing the ASN tells you whose network an address sits on.

## artifact
Raw material kept as evidence behind an observation: a robots.txt, a certificate,
a block of WHOIS text. Artifacts are redacted before storage and pruned after the
retention window.

## certificate transparency
A public, append-only log of every certificate issued by a publicly trusted
authority. Created so mis-issuance can be detected; useful in recon because it
lists hostnames.

## cidr
A way of writing an address range, such as `192.0.2.0/24`. The number after the
slash says how many leading bits are fixed.

## confidence
How much the tool trusts a specific result: low, medium or high. Confidence is
about the strength of the evidence, not the seriousness of the issue.

## contact mode
Which of three categories a module falls into: `third-party` (the target is never
contacted), `direct-read` (a few read-only requests), or `enumerative` (several
requests to check a fixed list of resources).

## cors
Cross-Origin Resource Sharing. The rules that decide whether a page on one origin
may read a response from another. A permissive CORS policy only matters when the
endpoint returns something private.

## csp
Content-Security-Policy. A response header restricting where a page may load
scripts and other resources from. It limits the damage of a cross-site scripting
bug; it does not prevent one from existing.

## dmarc
A DNS policy saying what receivers should do with mail that fails SPF and DKIM
checks, and where to send reports. Concerns email, not the website.

## direct-read
A contact mode: a small number of read-only requests are sent to the target. The
target can see them in its logs.

## enumerative
A contact mode: several requests are sent to check a list of resources. Budgeted
and rate-limited.

## finding
An interpretation of one or more observations, always carrying confidence and
limitations. In Recon Helper Pro a finding is never a confirmed vulnerability.

## hsts
HTTP Strict-Transport-Security. A header telling browsers to refuse plain HTTP
for this host in future.

## observation
A raw fact that was collected, recorded with its source, timestamp, module and
module version. Observations are the evidence findings are built from.

## provenance
The record of where a piece of data came from: which provider, when, via which
module and version. Without provenance a report cannot be defended.

## rdap
Registration Data Access Protocol. The structured, JSON replacement for WHOIS.

## resolve-once-then-pin
The safety technique this tool uses for every request: resolve the hostname a
single time, check that address, then connect to that exact address. It closes
the DNS-rebinding window in which a name could pass a check and then point
somewhere else.

## scope
Your declaration of what you are authorized to test. A bare hostname authorizes
that host only; subdomains, addresses and ranges must be added deliberately.

## severity hint
A context-aware suggestion of how much something might matter. It is not a score
and is never assigned just because a header is absent.

## spf
Sender Policy Framework. A DNS TXT record listing which hosts may send mail for a
domain.

## security.txt
A file at `/.well-known/security.txt` telling researchers how to report security
issues. Read it before reporting anything.

## third-party
A contact mode: the data comes from a resolver or public provider and the target
is never contacted.

## wildcard certificate
A certificate covering `*.example.com`. Convenient for the operator, and it hides
the specific hostnames from certificate transparency searches.
