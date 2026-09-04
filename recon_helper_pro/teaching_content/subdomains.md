# Hostname discovery from Certificate Transparency

## before
Every certificate issued by a publicly trusted authority is written to a public,
append-only log. That system exists so mis-issued certificates can be spotted -
and as a side effect, it is a searchable index of hostnames.

This step queries crt.sh, a free search interface over those logs. It is entirely
passive: the target is never contacted, and the organisation cannot tell that you
looked.

**Everything found here is recorded as an asset and nothing more.** Recon Helper
Pro will not send a single request to a discovered hostname. If you want to look
at one, you add it to your scope deliberately, and only if your authorization
covers it.

## after
Look for names that suggest environments rather than pages: `staging`, `dev`,
`vpn`, `admin`, `jenkins`, `internal`. Non-production systems are often less
hardened, which is why they are interesting - and why they are frequently out of
scope in a bug bounty. Read the programme rules before touching any of them.

Two important limits. First, a name in a certificate log may not resolve any
more; certificates outlive the hosts they were issued for. Second, wildcard
certificates (`*.example.com`) hide the specific names behind them, so a domain
using wildcards will look emptier here than it really is.

## next
- Check the programme scope or your authorization letter before adding any of
  these names.
- Run the DNS module against an interesting name to see whether it still resolves.
- Add anything you are authorized to test with `rhp scope add <host>`.
