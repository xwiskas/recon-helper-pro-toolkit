# Interpreted hints

## before
This step sends nothing anywhere. It reads what has already been collected for
this engagement and looks for patterns that only appear when several facts sit
side by side.

The purpose is to show you how findings are assembled from evidence. Everything it
produces is explicitly a hypothesis.

## after
Treat every hint here as a question to investigate, not an answer. "Little
hardening appears to have been applied" is a reasonable thing to suspect when four
security headers are missing and the server still advertises its version - and it
is also exactly what a well-defended site behind a CDN can look like.

Notice that hints carry lower confidence than the observations behind them. That
is correct: an interpretation can never be more reliable than its evidence, and
combining facts adds inference, not certainty.

If nothing stood out, that is a normal result and worth recording. A report that
says "this was checked and nothing followed from it" is more useful than one that
is silent.

## next
- Pick the single most interesting hint and verify it by hand.
- Generate the report with `rhp report` and read the "How to read this report"
  section before sending it to anyone.
