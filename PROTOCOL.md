# How our UDP file transfer talks to itself

Hey team — this is the shared contract so all four of our sender/receiver combos
actually work together. If your bytes match what's in here, your program will talk to
mine (and everyone else's) no matter the language.

Quick mental model: the **data packets** (the file itself) are already the same for all
of us — that's why a basic transfer has always worked across languages. The new part is
the little **control messages** the receiver sends back. Those are what make a transfer
survive packet loss and run fast. You don't strictly *need* them for a clean-network
demo, but you do need them for the "fehlerfrei" requirement, and they have to match.

Everything on the wire is **big-endian** (network byte order). If you forget that, things
break in really confusing ways, so double-check it first.

## The data packets (sender → receiver)

There's no "type" field — which packet it is comes from the **sequence number**:

- **Init** (`seq = 0`): `trans_id(2) | seq(4)=0 | max_seq(4) | filename(1..2048)`
  Kicks things off: a random `trans_id` for the session, `max_seq` = how many data
  packets are coming, and the filename (UTF-8, no path).
- **Data** (`seq = 1 .. max_seq`): `trans_id(2) | seq(4) | payload(up to 1400 bytes)`
- **Final** (`seq = max_seq + 1`): `trans_id(2) | seq(4) | md5(16)`
  The 16-byte MD5 of the whole file so the receiver can verify it.

A couple of things that will bite you if you get them wrong:

- **Payload is max 1400 bytes. Use exactly 1400 everywhere.** I literally lost an hour to
  this — one of our files had it at 1450 and the receiver silently rejected every single
  data packet. `max_seq` is just `ceil(filesize / 1400)`.
- UDP can deliver packets **out of order**, so the receiver has to stash data packets by
  their sequence number and reassemble at the end, not just append as they arrive.

## The control messages (receiver → sender)

Same little header on all of them: `trans_id(2) | type(1) | count(2)`, then a body that
depends on the type:

- **NAK** (`type = 0`): followed by `count` missing sequence numbers (4 bytes each).
  Means "please resend these, then resend the final packet." A NAK with `count = 0` is a
  handy shorthand for "I've got all the data, just resend the final/MD5."
- **COMPLETE** (`type = 1`): empty body. "Got everything, MD5 checks out, you can stop."
- **ACK** (`type = 2`): followed by `ack_base(4)`. It's cumulative — "I have everything
  below `ack_base` in order." This is what lets the sender slide a window.

One practical note: keep a single NAK inside one datagram. I cap the missing list around
350 entries (that's ~1405 bytes) and just let the next round mop up whatever's left.

## How the two sides should behave

This is the part that actually makes it interoperate, so it's worth matching:

On the **receiver** side —
- Send an ACK the moment you get the init packet. That ACK does double duty: it tells the
  sender "I speak the control protocol," which is how it decides to turn on windowing.
- Keep sending a cumulative ACK as data comes in.
- When the **final** packet shows up but you're still missing data, reply with a NAK
  listing the gaps. Do this **only in response to the final packet** — don't fire a NAK
  for every data packet you receive. I tried that and it caused a nasty retransmit storm,
  plus a livelock where the sender's repeated finals kept resetting my timer so I never
  actually NAK'd. Answering the final is the sweet spot.
- Once you've got everything and the MD5 matches, save the file and send COMPLETE.

On the **sender** side —
- After you've blasted init + data + final, don't just quit — listen for control packets.
- NAK → resend those seqs and the final. ACK → slide your window. COMPLETE → you're done.
- Only turn on the sliding window **if you actually see ACKs.** If none ever come back,
  fall back to the simpler "send everything, then repair on NAK" path (or plain
  fire-and-forget) and exit cleanly. Whatever you do, don't hang waiting forever.

## Stuff you can do however you like

Window size, retransmit timeout, socket timeouts, retry counts — all of that is your own
call and doesn't need to match anyone. Mine happen to be a window of 64 and a 100 ms RTO,
but pick whatever works for you.

## If you don't implement the control messages yet

No drama — it still works, just in a reduced way. My sender will probe, get no ACK, and
drop back to the simple path; my receiver will still answer NAK/COMPLETE and send ACKs
you can ignore. So a basic transfer goes through fine. The catch is that **lost packets
only get repaired when both sides speak the control protocol**, so a clean network is
fine but a lossy one needs both ends on board. Either way nothing hangs.

## Two gotchas worth flagging

- **If you're on Windows:** turn off `SIO_UDP_CONNRESET` on your UDP socket right after you
  create it. Otherwise a single ICMP "port unreachable" makes every later `recvfrom` blow
  up with error 10054 and the socket basically spins. One `WSAIoctl` call fixes it.
- **Big-endian, everywhere, including the control packets.** Easy to remember for the data
  side and then forget for the ACK — that's the sneaky one.

## When you test

Please test your program against mine **both directions** — your sender to my receiver and
my sender to your receiver — not just your own pair. Throw some packet loss at it (drop a
chunk of the data packets) and confirm the received file's MD5 still matches the original.
And check that it behaves when the other side doesn't talk back, so nobody ends up hanging
during the live demo.
