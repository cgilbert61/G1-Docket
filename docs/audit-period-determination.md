# How Long Should the Audit Run?

**G1 DOCKET — DATA ATTESTATION FOR YOUR GATEWAY AND YOUR AI**  
*G1163RT Security Labs · ops@g1163rt.ai · G1 Docket — AUDIT Period Determination*

> 📄 **Downloadable Whitepaper**: [`G1-Docket-Audit-Period.pdf`](whitepapers/G1-Docket-Audit-Period.pdf)

---

G1 Docket deploys in **AUDIT** first: it attests the estate, evaluates every request your AI makes, and logs what it *would* deny — while blocking nothing. The flip to **ENFORCE** is the moment of commitment, so the audit period is the one number every deployment plan has to get right. It is usually guessed. It can instead be determined — from the figures measured by the G1 Docket benchmark suite.

| MID-SIZE | LARGE ENTERPRISE | HYPERSCALE | MEGA / SOVEREIGN |
| :--- | :--- | :--- | :--- |
| **30 days** | **60 days** | **90 days** | **90–180 days** |
| 100K – 1M objects | 1M – 10M objects | 10M – 100M objects | 100M – 1B objects |

> **Every figure is coverage-gated, not calendar-gated:** the run ends when the exit criteria below are met. The day counts are what the numbers below predict it takes to meet them.

---

## Compute Doesn't Set the Period. Observation Does.

Start with what the scan itself costs. At the measured attestation scan rate (record evaluation across the in-memory snapshot), the entire estate is attested on day one — at every scale Docket is deployed at:

| Estate (Attested Objects) | First Full Sweep | Snapshot Load & Verify | In-Memory Footprint | Full Re-Sweeps / Day |
| :--- | :--- | :--- | :--- | :--- |
| **100K** *(mid-market)* | 6.3 seconds | 95 ms | ~35 MB | 13,700 |
| **1M** *(enterprise)* | 63 seconds | 850 ms | ~360 MB | 1,370 |
| **10M** *(hyperscale)* | 10.5 minutes | 7.8 sec | ~3.6 GB | 137 |
| **100M** *(multi-cloud)* | ~105 minutes | ~80 sec | ~35 GB | ~14 |
| **1B** *(sovereign)* | ~17.5 hours | ~13 min | ~350 GB | delta-driven |

Change never catches up either: an estate churning 5% of its objects daily re-attests in 0.3 seconds at mid-market scale, 31 seconds at ten million objects, about five minutes at a hundred million, and under an hour at a billion. The scanner is never the long pole. What takes time is **watching how the data actually moves** — and that is a property of your firm, not of the machine. *(Above ten million objects the figures are linear extrapolations of the measured per-record rates; the snapshot is sharded across prevalidator nodes, each holding its segment, and re-verification runs on deltas rather than full sweeps.)*

> **What counts as an object:** a governed data object in scope for AI use — a document, a record, a dataset, a source file in a codebase Docket papers. Not every file on every disk: operating systems, dependency trees, and caches are not attested — the lockfile that names the dependencies is.

---

## What Actually Sets the Period

1. **The window must contain the firm's periodic data.** Month-end closes, payroll runs, board packs, the report someone builds once a month from a restricted spreadsheet — the most sensitive data in most firms is also the least frequently touched. Any audit window shorter than 30 days can miss month-end entirely, depending on the day it starts. Thirty days is the floor that guarantees one full monthly cycle is inside the window.

2. **Coverage follows a long tail.** Enforcement is only safe when the data your AI actually uses is attested. Most of it appears in real traffic within days; the tail — quarterly artifacts, annual filings — arrives over weeks. The correct end-point is therefore a coverage threshold: **at least 99% of the objects observed in live AI traffic carrying valid, unexpired attestations.**

3. **The would-deny log has to burn down — and prove it stayed down.** AUDIT's real output is the denial forecast: every request ENFORCE would have refused, with its reason (unattested, expired, insufficient clearance, egress). Each one gets triaged — attest the data, correct a tier, or accept the denial. A mid-size estate works its log down inside one cycle; a large estate, its business units closing on staggered schedules, needs a second cycle to prove the first cycle's fixes held.

---

## The Determination

| Firm Scale | Estate (Attested Objects) | Recommended AUDIT Period | The Window Must Contain |
| :--- | :--- | :--- | :--- |
| **Mid-size firm** | 100,000 – 1,000,000 | **30 days** | One full month-end close |
| **Large enterprise** | 1,000,000 – 10,000,000 | **60 days** | Two month-end closes on live production traffic |
| **Hyperscale / multi-cloud** | 10,000,000 – 100,000,000 | **90 days** | Full quarter-end close (Q-end) across distributed BUs |
| **Global mega-scale / sovereign data** | 100,000,000 – 1,000,000,000 | **90 – 180 days** | Full quarter-end + semi-annual / annual reporting cycle |

### Why the Periods Lengthen
Nothing about the machine changes — even a billion-object sweep is a 17.5-hour event, inside a single day. What lengthens is the calendar of the firm itself: the larger the estate, the slower its reporting heartbeat, and the window has to contain the slowest cycle that moves sensitive data. Mega-scale and sovereign estates answer to semi-annual and annual cycles too; a window that closes before those cycles fire has not watched the estate — only a sample of it.

---

## Exit Criteria — When to Flip to ENFORCE

The transition from audit mode to inline enforcement must satisfy three empirical criteria:

- [x] **Coverage:** $\ge$ 99% of objects observed in live AI traffic hold valid, unexpired attestation records.
- [x] **Stability:** The daily would-deny rate has been flat for seven consecutive days — no new categories of denial appearing.
- [x] **Triage Complete:** Every logged would-deny has a disposition — data attested, tier corrected, or denial accepted as correct.

Meet the criteria early and you flip early — the day count is the expectation, not the sentence. What the audit period buys is **certainty**: on enforcement day, every denial is one you have already seen, reviewed, and accepted. There are no surprises left to have.

---

## Operational Zero-Disruption Guarantee

During the run, everything is scanned — the full estate, every change within a day of it happening, every request your AI makes — each evaluated in memory at **159 µs on average** (p99 1.6 ms, inside a 5 ms budget) and logged either way. AUDIT costs the firm nothing in disruption. It costs the data nowhere to hide.

---

*Figures are from the G1 Docket benchmark suite (in-memory snapshot model; attestation scan rate = record evaluation across the snapshot). G1 Docket is open source — the engine first, the prevalidator in front of the gateway you already run.*

---

*Companion sheets: [Core Architectural Principles](core-architecture.md); [Data Sizing, Memory Footprint & Throughput Benchmarks](benchmarks-sizing.md); [Doesn't Microsoft Purview Do the Same Thing?](purview-comparison.md). G1 Docket is open source: [github.com/cgilbert61/G1-Docket](https://github.com/cgilbert61/G1-Docket).*
