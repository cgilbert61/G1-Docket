# How Long Should the Audit Run?

**G1 DOCKET — DATA ATTESTATION FOR YOUR GATEWAY AND YOUR AI**  
*G1163RT Security Labs · ops@g1163rt.ai · G1 Docket — AUDIT Period Determination*

---

G1 Docket deploys in **AUDIT** first: it attests the estate, evaluates every request your AI makes, and logs what it *would* deny — while blocking nothing. The flip to **ENFORCE** is the moment of commitment, so the audit period is the one number every deployment plan has to get right. It is usually guessed. It can instead be determined — from the throughput, sizing, and latency figures measured across production attestation workloads.

| Firm Size | Governed Estate | Recommended AUDIT Period | The Window Must Contain |
| :--- | :--- | :--- | :--- |
| **Mid-size** | 100k – 1M objects | **30 days** | One full month-end close |
| **Large** | 1M – 10M objects | **60 days** | Two month-end closes, on real traffic |
| **Global Enterprise** | 10M – 100M objects | **90 days** | Full fiscal quarter-end close & staggered BU closes |
| **Planetary / Sovereign** | 100M – 1B objects | **90 – 180 days** | Two quarters + annual audit / SEC filing cycle |

> **Both figures are coverage-gated, not calendar-gated:** the run ends when the exit criteria below are met. The day counts are what the numbers predict it takes to meet them.

---

## Compute Doesn't Set the Period. Observation Does.

Start with what the scan itself costs. At the measured attestation scan rate (record evaluation across the in-memory snapshot), the entire estate is attested on day one — across every scale from mid-market to 1 Billion objects:

| Estate (Attested Objects) | First Full Sweep | Snapshot Load & Verify | In-Memory Footprint | Full Re-Sweeps / Day | 5% Daily Churn Re-Attest |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **100,000** *(mid-market)* | 6.3 seconds | 95 ms | ~35 MB | 13,700 | 0.3 seconds |
| **1,000,000** *(enterprise)* | 63 seconds | 850 ms | ~360 MB | 1,370 | 3.1 seconds |
| **10,000,000** *(hyperscale)* | 10.5 minutes | 7.8 sec | ~3.6 GB | 137 | 31.5 seconds |
| **100,000,000** *(global)* | 1.75 hours | 78 seconds | ~36 GB | 13.7 | 5.25 minutes |
| **1,000,000,000** *(planetary)* | 17.5 hours | 13.0 minutes | ~360 GB | 1.37 | 52.5 minutes |

Change never catches up either: an estate churning 5% of its objects daily re-attests in 0.3 seconds at mid-market scale, 31 seconds at 10M objects, and under 53 minutes at 1 Billion objects (50 million modified objects). The scanner is never the long pole. What takes time is **watching how the data actually moves** — and that is a property of your firm, not of the machine.

> **What counts as an object:** a governed data object in scope for AI use — a document, a record, a dataset, a vector embedding chunk parent, or a source file in a codebase Docket papers. Operating systems, dependency trees, and ephemeral caches are not attested — the cryptographically signed lockfile or artifact ledger that names them is.

---

## What Actually Sets the Period

1. **The window must contain the firm's periodic data.** Month-end closes, payroll runs, board packs, the report someone builds once a month from a restricted spreadsheet — the most sensitive data in most firms is also the least frequently touched. Any audit window shorter than 30 days can miss month-end entirely, depending on the day it starts. Thirty days is the floor that guarantees one full monthly cycle is inside the window.
2. **Coverage follows a long tail.** Enforcement is only safe when the data your AI actually uses is attested. Most of it appears in real traffic within days; the tail — quarterly artifacts, annual filings, the archive someone queries twice a year — arrives over weeks. The correct end-point is therefore a coverage threshold: **at least 99% of the objects observed in live AI traffic carrying valid, unexpired attestations.**
3. **The would-deny log has to burn down — and prove it stayed down.** AUDIT's real output is the denial forecast: every request ENFORCE would have refused, with its reason (unattested, expired, insufficient clearance, egress). Each one gets triaged — attest the data, correct a tier, or accept the denial. A mid-size estate works its log down inside one cycle. A large estate, with business units closing on staggered schedules, needs a second cycle to show the first cycle's fixes held and to separate routine denials from periodic ones.
4. **Planetary estates (100M – 1B objects) require staggered multi-subsidiary observation.** Across hundreds of subsidiaries and heterogeneous vector stores, audit runs must span at least two quarterly closes (or one full annual audit cycle: 90 – 180 days) to prevent locking out legacy retrieval patterns or high-tier financial consolidations that only trigger on fiscal year boundaries.

---

## The Determination

| Firm Size | Governed Estate | Recommended AUDIT Period | The Window Must Contain |
| :--- | :--- | :--- | :--- |
| **Mid-size** | 100k – 1M objects | **30 days** | One full month-end close |
| **Large** | 1M – 10M objects | **60 days** | Two month-end closes, on real traffic |
| **Global Enterprise** | 10M – 100M objects | **90 days** | Full fiscal quarter-end close & staggered BU closes |
| **Planetary / Sovereign** | 100M – 1B objects | **90 – 180 days** | Two quarters + annual audit / SEC filing cycle |

> **Quarterly and Annual Extensions:** if an estate feeds quarterly reporting, extend the run to span a quarter-end — **up to 90 days**. For planetary estates crossing fiscal year-end boundaries, extend to **180 days**. A window that never sees the quarter-end or year-end data has not watched the estate; it has watched a sample of it.

---

## Exit Criteria — When to Flip to ENFORCE

The transition from audit mode to inline enforcement must satisfy three empirical criteria:

- [x] **Coverage:** $\ge$ 99% of objects observed in live AI traffic hold valid, unexpired attestation records.
- [x] **Stability:** The daily would-deny rate has been flat for seven consecutive days — no new categories of denial appearing.
- [x] **Triage Complete:** Every logged would-deny has a disposition — data attested, tier corrected, or denial accepted as correct.

Meet the criteria early and you flip early — the day count is the expectation, not the sentence. What the audit period buys is **certainty**: on enforcement day, every denial is one you have already seen, reviewed, and accepted. There are no surprises left to have.

---

## Operational Zero-Disruption Guarantee

During the run, everything is scanned: the full estate on day one, every change within a day of it happening, and every request your AI makes — evaluated in memory at an average of **159 µs per decision** (p99 1.6 ms, inside a 5 ms budget), and logged either way. AUDIT costs the firm nothing in disruption. It costs the data nowhere to hide.

---

*Figures are from the G1 Docket benchmark suite (in-memory snapshot model; attestation scan rate = record evaluation across the snapshot). G1 Docket is open source — the engine first, the prevalidator in front of the gateway you already run.*
