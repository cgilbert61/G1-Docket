# Doesn't Microsoft Purview Do the Same Thing?

**G1 DOCKET — DATA ATTESTATION FOR YOUR GATEWAY AND YOUR AI**  
*G1163RT Security Labs · ops@g1163rt.ai · G1 Docket vs Microsoft Purview*

> 📄 **Downloadable Whitepaper**: [`G1-Docket-vs-Purview.pdf`](whitepapers/G1-Docket-vs-Purview.pdf)

---

Yes and no. Purview attempts to address pieces of this — but there is a fundamental architectural gap between how Purview works and how modern AI chat and autonomous agents actually consume data. **Purview protects the file. AI consumes chunks, embeddings, and prompt payloads — assembled by headless agents that never touch an endpoint.** That is where the label stops working, and it is the ground G1 Docket was built for.

---

## 1 · What Purview actually does today

- **Inside Microsoft 365 Copilot, it works well — a closed garden.** If a Word document or SharePoint folder is tagged Secret with Rights Management (RMS), Copilot inherits that user's ACLs and will not ground responses on files the user cannot decrypt.
- **For consumer and web AI chat (ChatGPT, Claude on the web), it works at the endpoint.** Endpoint DLP — the Windows Defender agent on the laptop — and Defender for Cloud Apps (CASB) intercept an employee pasting clipboard text or dragging a labeled file into chatgpt.com in Edge or Chrome, and block the upload.
- **For Azure OpenAI, it watches — afterwards.** Purview DSPM for AI monitors activity logs and runs asynchronous classifiers to report who sent sensitive data to an Azure model *after the fact*.

---

## 2 · Where it fails for AI chat & autonomous agents

### A. The chunking & context-injection blind spot (RAG)
A RAG pipeline or agent reads a document, extracts the raw text, chunks it into paragraphs, stores the chunks as vector embeddings, and injects the relevant snippets into the LLM prompt. The moment text leaves the `.docx` or `.pdf`, Purview's file metadata and RMS headers are stripped. To Purview's network scanners the outgoing prompt is an anonymous JSON blob over TLS — unless it catches an exact regex match (a credit card, an SSN), it has no idea paragraph three came from the Board Strategy document marked Secret.

### B. Autonomous agents don't use browsers or endpoints
Agents built on LangGraph, CrewAI, AutoGen, or Claude Computer Use run headless in Kubernetes, Docker, or VPC microservices. There is no Windows Defender Endpoint DLP in the container. They pull data across enterprise stores — S3, Snowflake, BigQuery, local shares — via APIs, and send payloads directly to upstream model endpoints. Purview has zero inline visibility or enforcement on those execution loops.

### C. Inspection latency: seconds vs microseconds
Calling Purview's cloud classification / DLP API on an active prompt means an external round-trip to Microsoft's cloud — typically 250 ms to 1.5 s per call. Doing that on every agent reasoning step or streaming token kills inference throughput. G1 Docket was built specifically because of this: it evaluates in-memory cryptographic DSSE snapshots in an **average of 159 microseconds**, without a single database or cloud API call.

---

## The comparison

| Capability | Microsoft Purview | G1 Docket |
| :--- | :--- | :--- |
| **M365 Copilot office apps** | Native & seamless | Labels consumed at ingest via the Docket connector |
| **Pasting files into browser chat** | Blocked via Endpoint DLP / CASB | N/A — the endpoint tier is not Docket's layer |
| **Headless AI agents (Python / K8s / APIs)** | Blind — no endpoint agent in the container | Inline proxy gateway (`:18082`) |
| **RAG prompt chunks & synthesized context** | Blind once text is extracted from the file | Object- and chunk-level SHA-256 attestation |
| **Multi-cloud / local LLMs (Ollama, LM Studio)** | No support — focused on Azure / M365 | OpenAI / Anthropic protocols |
| **Decision latency on the inference hot path** | 250 ms – 1.5 s (cloud API call) | **159 µs** (in-memory snapshot) |
| **Verification method** | Heuristic / regex matching | Cryptographic Ed25519 DSSE signature |

---

> **In short:** Purview protects the file on the employee's laptop or in SharePoint. G1 Docket protects the gateway and the headless agent runtimes where data is chopped up, embedded, and fed into LLM prompts. That is why Docket integrates with Purview labels on ingest — then papers the data cryptographically, so it cannot leak through prompts or RAG.
>
> ### **Purview gives data a label. G1 Docket gives it papers.**

---

*Latency note: Docket's 159 µs is the measured average decision time from the G1 Docket benchmark suite (in-memory snapshot evaluation, no database round-trip). Purview's range is the typical cloud classification / DLP API round-trip in deployed use, not a Microsoft-published SLA. Docket's Purview connector is an ingest input: Purview labels inform classification; the fingerprint, signature, expiry, and enforcement are Docket's. G1 Docket is open source and runs in front of the gateway you already have.*

---

*Companion sheets: [Core Architectural Principles](core-architecture.md); [Data Sizing, Memory Footprint & Throughput Benchmarks](benchmarks-sizing.md); [How Long Should the Audit Run?](audit-period-determination.md). G1 Docket is open source: [github.com/cgilbert61/G1-Docket](https://github.com/cgilbert61/G1-Docket).*
