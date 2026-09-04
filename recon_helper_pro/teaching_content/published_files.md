# Standard published-file discovery

## before
This is the only `enumerative` module in v1, meaning it sends several requests
rather than one. It is still narrow by design: a fixed list of files that sites
publish deliberately - `robots.txt`, `sitemap.xml`, `security.txt`, a couple of
`.well-known` paths.

It is **not** a directory brute-forcer. It does not guess names, it does not
follow links, and it stops at the request budget.

robots.txt is fetched first, and paths it disallows are skipped by default. That
is courtesy, not law: robots.txt is a crawler convention, never an authorization
boundary and never a security control. You can opt in to checking disallowed
paths, and if you do, that is a decision you are making with your authorization
behind it.

## after
robots.txt is often the most interesting file on the list, for an ironic reason:
to hide a path from search engines you must name it publicly. A `Disallow:
/admin-backup/` line advertises the very thing it conceals. That is a pointer
worth noting - not evidence that anything is exposed. This module does not
request those paths.

security.txt is the file you actually want to find. It tells you where to report
what you discover, and reading it before reporting is basic professionalism.

sitemap.xml gives you the site's own map of itself. The URLs in it are recorded as
assets and are not requested.

If a response looks like a generated file index, that is flagged as a possible
directory listing. Confirm it in a browser - the pattern match is not proof.

## next
- Read security.txt if it exists, and follow its instructions when reporting.
- Note interesting robots.txt entries for manual review within your authorization.
- Generate the report with `rhp report`.
