# Technology fingerprint (lite)

## before
This step fetches the homepage once (`direct-read`) and compares the headers,
cookies and HTML against a small bundled set of signatures.

"Lite" is deliberate. A large signature database would match more, but you could
not see why it matched. Here every match records the exact evidence that produced
it, which is the point in a learning tool.

## after
Read the evidence column, not just the technology name. A match on
`Server: nginx` is strong; a match on the string `data-reactroot` in the HTML is
weaker, because a page can contain that for many reasons. The confidence value
reflects exactly this.

Remember what a CDN does to fingerprinting: if Cloudflare or a similar service
sits in front, most of what you see describes the CDN, and the origin server stays
invisible.

No match at all is a common and uninformative result. The v1 signature set is
small on purpose - absence of a match says nothing about what the site runs.

## next
- Use the identified stack to decide what is worth checking next.
- Where a version number appeared, check whether it is current - but do not report
  a CVE from a banner.
- Run the published-files check to see what the site publishes about itself.
