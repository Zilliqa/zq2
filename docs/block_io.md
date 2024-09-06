# Block I/O

Sometimes, we need blocks. We want those blocks to come from peers that have them.

We will, in general, not know which blocks exist in a given view range
(some views will have been skipped), and so we advertise - and
respond - based on views, not blocks.

This has the side-effect that we cannot tell when a peer has satisfied a request, so
we keep a cache and simply time out requests.

In order to do this we need to know:

 - Who has what views
 - (when there is a choice) from whom to request them.

## Block request scheduling

This is a bit of a horrid problem.

We start off with a request for blocks in a range and our mission is
to dispatch requests that will make this happen.

We store a list of requests in progress; we regard these as already
being in flight and remove them from the set of blocks we're looking
for.

We then start looking through our peers from a clock index.

For each peer, we decide which blocks it can give us. We then start
asking for blocks from the lowest-scoring (see later) peer.

The intuition behind this is that as peers slow down, we will ask for
fewer and fewer blocks from them.

## Routing around unresponsive peers

When a request is issued to a peer, it's recorded in the open requests
list with an issue time.

When blocks come in, these are recorded against the open request and
the time they come in is noted.

We then compute `(delay / blocks_supplied)` as a metric for how well
the node is doing. This gets AIMD'd into a score for the node - the
lower the better.

## Availability adverts

When we want to send a block request, and a peer has an empty list of
available blocks, we will send a request for an availability list.

When we receive a block request, we always reply with an availability
list, even if we don't have those blocks.

This hopefully keeps us in sync at least on the second try.

(`unserviceable_requests` will then get filled when
`request_missing_blocks()` is next called)

## Data structures

This is a bit horrid. There is definitely a better way to do this, but
we're short on time, so we use offset bitmaps for a lot of this.

