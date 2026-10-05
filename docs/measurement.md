# Measurement method and proposed gates

## Baseline question

Does a representative application spend enough of its critical path in reducible transport/queueing to justify an isolated Homa/RPC trial? Start with application elapsed-time distributions and RPC counts, then use this toolkit to describe visible operation mix, spans and TCP symptoms. Pair those observations with approved client/server counters or request traces where available. No campus conditions or improvement are assumed.

Use a private experiment manifest with NFS version/security, client/server/software, mount options, topology/RTT/link constraints, load, observation point, clock quality, workload shape (path depth/fanout/order), offered concurrency, interval and cache preparation. A passive capture alone does not establish most of these inputs. Avoid publishing real hostnames, paths or employer topology.

## Cache and parallelism matrix

| Case | What to hold/document | Interpretation |
| --- | --- | --- |
| Warm metadata stat | Stable client name/attribute caches, ordinary mount semantics | Many calls can finish locally with no RPC; wire counts are not application counts |
| Client miss, warm server | Explicit evidence of client misses; server state held steady | Visible RPC cost still combines network/transport and server work |
| Client/server miss-heavy | Separate evidence of client, server and lower storage cache states | Backend metadata may dominate; namespace size does not prove coldness |
| Directory walk plus stat | Same tree/order/attributes, record READDIR family and follow-up RPCs | Enumeration may provide attributes and reduce later calls |
| Parallel stat scan | Record offered concurrency, outstanding work, CPU/load and overlapping RPCs | Dependencies and overlapping spans cannot be summed as serial work |

Do not drop caches or disable mount caching on shared production hosts. Use separately authorized isolated fixtures for cache manipulation. Primary baselines retain ordinary semantics; forced revalidation is a different diagnostic experiment. Repeat bounded comparable intervals and keep warm, miss-heavy, sequential and parallel results separate. Report sample counts: a tiny synthetic/real sample cannot establish p99 stability.

## Operation and timing interpretation

NFSv3 GETATTR, LOOKUP, READDIR and READDIRPLUS are distinct procedures. READDIRPLUS may carry attributes/handles and affect subsequent traffic. NFSv4 COMPOUND groups operations into one RPC; READDIR can request attributes, and NFSv4 has no separate wire READDIRPLUS operation. Decode the actual call sequence; one stat is not necessarily one GETATTR, nor is every pathname component necessarily a separate RTT. [NFSv3 specification](https://datatracker.ietf.org/doc/html/rfc1813), [NFSv4 specification](https://datatracker.ietf.org/doc/html/rfc7530)

This toolkit's completion-frame span includes transit, host transport, server queues/execution and capture/reassembly effects. It cannot isolate server processing. TCP ACK RTT is not RPC service time: delayed ACKs, ACK direction, capture placement and offloads matter. Do not subtract p95/p99 values from different distributions, sum component quantiles, or interpret retransmission-free records as transport-free overhead. Use synchronized paired endpoints only after quantifying clock error; this MVP does not join clocks. ONC RPC XIDs identify exchanges within a conversation, not globally. [ONC RPC specification](https://datatracker.ietf.org/doc/html/rfc5531)

Report unmatched calls/replies, retries, truncated/malformed/decode records, input cap, capture drops and ring completeness alongside quantiles. Encryption (TLS, IPsec, RPCSEC_GSS privacy) can prevent operation decoding; do not introduce keys or export payload to work around it. Bias toward competing explanations when coverage is limited. Apparent TCP loss/out-of-order is a decoder heuristic, not proof of congestion on a particular switch.

## Proposed gates (no observed passes yet)

1. **Baseline → laboratory design.** Establish repeatable application/visible RPC distributions and adequate bidirectional coverage. Identify ordinary cache effects and a plausible transport/queueing contribution with supporting host/network evidence. Choose the smallest useful application improvement and maximum regression before a trial. High RPC RTT alone does not pass this gate.
2. **Laboratory design → isolated RPC comparison.** Measure the candidate campus path against Homa's deployment assumptions; review endpoint compatibility, queue/priority policy and support. Compare TCP/UDP/Homa on equivalent message sizes, concurrency and a bounded representative path in a separately authorized lab. Pin transport revisions and hold workload/server service constant. Predefine tail, CPU, loss/recovery and security criteria.
3. **Isolated RPC → NFS adapter feasibility.** Proceed only after a repeatable benefit exceeds the predefined useful threshold with acceptable regressions. Review RPC semantics, security, failure handling and real integration cost. An adapter/proxy prototype is separate work; retain the original NFS baseline and ordinary cache behavior as the control.

Homa's manual targets physically close machines with RTT no more than a few tens of microseconds and a different message socket API. It is not a drop-in installed-NFS transport. Transport gains must be translated into the reducible fraction of the application's critical path, not applied as a multiplier to total NFS latency. Campus RTT/priority support and integration remain unmeasured inputs. [Official Homa manual](https://github.com/PlatformLab/HomaModule/blob/main/man/homa.7)

The prior 12-page Homa/NFS assessment (5 October 2026) supplies this staged design context. It is not included in the repository, and none of its proposed gates are presented as measured results here.
