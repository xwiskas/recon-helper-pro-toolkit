# Reverse DNS and network context

## before
Forward DNS answers "where does this name point?". Reverse DNS answers "what name
does this address claim?", and the network context lookup answers "whose network
is this address on?".

Both come from third parties: PTR records from a resolver, and the network/ASN
data from Team Cymru's free public service, which answers over DNS. The target is
not contacted.

## after
A PTR record usually names the hosting provider, not the site owner - something
like `ec2-203-0-113-10.compute-1.amazonaws.com`. That is still useful: it tells
you where the infrastructure lives.

The ASN and announced prefix tell you which organisation routes the address. If
the ASN belongs to a cloud or CDN provider, the host you are looking at is
probably shared infrastructure, and anything you infer about "the server" may be
about the provider instead.

Be careful with the inverse: many addresses have no PTR record at all. That is
normal and means nothing.

## next
- Compare the ASN against the organisation you are assessing. A mismatch usually
  means a hosting provider or CDN sits in front.
- If the address is in a range you were authorized to test, consider adding the
  CIDR to your scope explicitly.
