# G1 Docket Python SDK Documentation (`v0.1`)

The **G1 Docket Python SDK** (`docket` / `sdk`) provides high-performance, typed synchronous and asynchronous client interfaces for the G1 Docket Data Attestation Framework, Prevalidator Proxy, Authoritative Registry, and Signed Snapshot Publisher.

It enables any Python application, AI agent, RAG pipeline, or backend microservice to programmatically enforce data attestation policies, prevalidate local and cloud directories, interact with the authoritative catalog, and route OpenAI- and Anthropic-compatible requests with zero Registry database overhead in the request path.

---

## 1. Installation

Install in your active Python virtual environment:

```bash
# In the G1-Docket repository
pip install -e .

# Or install with optional dependencies
pip install -e ".[full]"
```

Verify the installation:
```python
from docket import DocketClient, AsyncDocketClient
```

---

## 2. Quickstart

### Basic Synchronous Client
```python
from docket import DocketClient, PolicyDenialError

with DocketClient(base_url="http://localhost:18082") as client:
    # 1. Health check & active snapshot sequence
    health = client.get_health()
    print("Prevalidator Mode:", health["mode"])
    print("Snapshot Sequence:", health["snapshot_sequence"])

    # 2. Submit an OpenAI-compatible request through the Prevalidator
    try:
        response = client.chat_completions(
            messages=[
                {"role": "system", "content": "You are a secure assistant."},
                {"role": "user", "content": "What are our company core values?"}
            ],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("Reply:", response["choices"][0]["message"]["content"])
    except PolicyDenialError as exc:
        print(f"Request blocked by attestation policy (HTTP {exc.status_code}):", exc.response_body)
```

---

## 3. Polling & Snapshot Convergence Loop

When newly published snapshots or background directory attestations are issued, downstream consumers (or tests) should poll until the Prevalidator has loaded the updated monotonic snapshot sequence into memory:

### Using the Built-In `wait_for_sync()` Method
```python
from docket import DocketClient

with DocketClient() as client:
    # Block until the Prevalidator has synchronized at least snapshot sequence 10
    client.wait_for_sync(min_sequence=10, timeout_sec=30)
    print("Prevalidator in-memory snapshot is up to date!")
```

### Custom Polling Loop Pattern
```python
import time
from docket import DocketClient, DocketError

def wait_for_prevalidator_sync(client: DocketClient, min_sequence: int = 1, timeout_sec: int = 60) -> bool:
    """Poll the Prevalidator until it loads at least `min_sequence` snapshot in memory."""
    start_time = time.time()
    while time.time() - start_time < timeout_sec:
        try:
            health = client.get_health()
            seq = health.get("snapshot_sequence", 0)
            if health.get("status") == "ok" and seq >= min_sequence:
                print(f"[+] In-memory snapshot synchronized (Sequence: {seq})")
                return True
        except DocketError:
            pass
        print("Waiting for snapshot convergence...")
        time.sleep(2)
    raise TimeoutError(f"Prevalidator failed to reach sequence {min_sequence} within {timeout_sec}s")
```

---

## 4. Inline `<pod:object>` Tagging & Policy Enforcement

When sending context or retrieved documents to an LLM, wrap the segments in `<pod:object>` tags using `DocketClient.wrap_object()`:

```python
from docket import DocketClient, PolicyDenialError

client = DocketClient()

# Construct attested context
locator = "file://estate/fileshare/product_overview_public.md"
raw_document = "G1 Docket Architecture Overview..."
context_block = DocketClient.wrap_object(locator=locator, content=raw_document)

prompt = f"Please summarize the following document:\n{context_block}"

try:
    response = client.chat_completions(
        messages=[{"role": "user", "content": prompt}],
        model="gpt-4o",
        caller_key="pod-key-public",
    )
    print("Clean Response:", response["choices"][0]["message"]["content"])
except PolicyDenialError as err:
    # Raised automatically on HTTP 403 (Restricted, Unattested, or Clearance Mismatch)
    print("Access Denied:", err)
```

### Policy Enforcement Outcomes

| Outcome | Trigger | Prevalidator Action |
| :--- | :--- | :--- |
| **`allow`** | Object tier $\le$ Caller clearance and AI eligibility is `allow` | Wrapper tags stripped, inner content passed to LLM cleanly. |
| **`strip`** | Object is marked `Confidential` or eligibility is `strip` | Entire `<pod:object>` block replaced with `[POD:STRIPPED]`. Remainder of prompt forwarded. |
| **`deny`** | Object is `Restricted`, `unattested`, `expired`, `revoked`, hash mismatch, or ABAC violation | Uniform **`HTTP 403 Forbidden`** returned. LLM gateway never contacted. |

### ABAC, Departmental Isolation & Sovereign Boundaries

The SDK supports fine-grained Attribute-Based Access Control (ABAC) and data sovereignty claims directly in `chat_completions()` and `messages()`:

```python
# 1. Enforce Departmental Isolation (Finance only)
response = client.chat_completions(
    messages=[{"role": "user", "content": prompt}],
    model="gpt-4o",
    caller_key="pod-key-confidential",
    caller_dept="Finance",  # Transmits X-POD-Caller-Dept header
)

# 2. Enforce Sovereign Data Residency (EU GDPR Enclave)
response = client.chat_completions(
    messages=[{"role": "user", "content": prompt}],
    model="gpt-4o",
    caller_key="pod-key-public",
    target_region="eu-central-1",  # Transmits X-POD-Target-Region header
)
```

---

## 5. AI Agent & RAG Framework Integrations

G1 Docket provides first-class primitives for modern AI agent frameworks (**LangChain**, **LlamaIndex**, **AutoGen**, **CrewAI**, and custom tool-calling agents) in `docket.integrations`:

### A. Wrapping Retrieved Context Chunks (`wrap_rag_documents`)
Automatically wraps retrieved chunks, LangChain `Document` objects, LlamaIndex `NodeWithScore` instances, or dictionaries into canonical `<pod:object>` tokens:

```python
from docket.integrations import wrap_rag_documents, format_rag_prompt

# Supports heterogeneous inputs: LangChain docs, LlamaIndex nodes, or dicts
chunks = [
    {"source": "s3://corp-lake/annual_report.pdf", "page_content": "Annual recurring revenue: $42M"},
    {"locator": "snowflake://acme.snowflakecomputing.com/FINANCE/PUBLIC/Q3", "content": "Q3 Margin: 68%"},
]

prompt = format_rag_prompt(
    prompt_template="Answer the question using only attested facts:\n\n{context}\n\nQuestion: {question}",
    documents=chunks,
)
```

### B. Agent Tool-Calling Decorator (`@attested_tool`)
Decorate database, search, or retrieval tools so their outputs are automatically wrapped in tamper-proof attestation tokens:

```python
from docket.integrations import attested_tool

@attested_tool("snowflake://analytics.snowflakecomputing.com/MART/REVENUE", auto_hash=True)
def query_quarterly_revenue(quarter: str) -> str:
    # Tool output is automatically enclosed in <pod:object locator="..." sha256="...">...</pod:object>
    return f"{quarter} ARR: $42.5M, Growth: 32%"

# Dynamic locators based on function arguments
@attested_tool(lambda table_name: f"snowflake://prod/{table_name}", auto_hash=True)
def run_dynamic_query(table_name: str) -> str:
    return "Query result rows..."
```

### C. Extracting Locators from Prompts (`extract_prompt_locators`)
Inspect prompts before dispatch to audit which data assets are referenced:

```python
from docket.integrations import extract_prompt_locators

locators = extract_prompt_locators(prompt)
print("Data assets referenced in prompt:", locators)
# Output: ['s3://corp-lake/annual_report.pdf', 'snowflake://acme.snowflakecomputing.com/FINANCE/PUBLIC/Q3']
```

### D. LangChain & LlamaIndex Pipeline Components

#### LangChain Pipeline Transformer
Use `DocketDocumentTransformer` directly in LangChain retrieval pipelines to automatically wrap retrieved documents:

```python
from docket.integrations import DocketDocumentTransformer

transformer = DocketDocumentTransformer(default_locator_key="source", auto_hash=True)
attested_docs = transformer.transform_documents(retrieved_docs)
```

#### LlamaIndex Node Postprocessor
Plug `DocketLlamaIndexPostprocessor` directly into any LlamaIndex query engine or retriever:

```python
from docket.integrations import DocketLlamaIndexPostprocessor

postprocessor = DocketLlamaIndexPostprocessor(default_locator_key="file_path", auto_hash=True)
# Add to query engine:
# query_engine = index.as_query_engine(node_postprocessors=[postprocessor])
attested_nodes = postprocessor.postprocess_nodes(retrieved_nodes)
```

---

## 6. Directory Prevalidation & Scanning

Prevalidate local directory shares or batch files before indexing into vector databases or passing to LLMs:

```python
from docket import DocketClient

client = DocketClient()

# 1. Prevalidate a directory
scan_result = client.prevalidate_directory(
    directory_path="D:/attestation/pc_demo_folder",
    caller_key="pod-key-confidential",
    model="local-model",
)

print(f"Total Scanned: {scan_result['total_files']}")
print(f"Passed: {scan_result['passed_files']}")
print(f"Failed: {scan_result['failed_files']}")
print(f"Unattested: {scan_result['unattested_files']}")

# 2. Trigger automated discovery and attestation crawl
crawl_summary = client.attest_directory(directory_path="D:/attestation/pc_demo_folder")
print("Attested Files Count:", len(crawl_summary.get("attested_records", [])))
```

---

## 7. Authoritative Registry & Catalog Governance

Interact directly with the Registry service (port `18080`) for cryptographic record lookups, lifecycle operations, and review queue approvals:

```python
from docket import DocketClient

client = DocketClient(registry_url="http://localhost:18080", admin_key="pod-dev-admin-key")

# 1. Look up an attestation record by canonical locator
record = client.lookup_record("file://estate/fileshare/product_overview_public.md")
print("Object Tier:", record["tier"])
print("Content SHA-256:", record["content_sha256"])
print("Expires At:", record["expires_at"])

# 2. List records expiring within 30 days
expiring = client.list_expiring_records(within_days=30)
print(f"Records needing renewal: {len(expiring)}")

# 3. Immediately raise classification tier
client.raise_tier(
    locator="file://estate/fileshare/product_overview_public.md",
    new_tier="Confidential",
)

# 4. Lower tier (requires dual approvers)
client.lower_tier(
    locator="file://estate/fileshare/product_overview_public.md",
    new_tier="Internal",
    approvals=[
        {"approver_id": "sec-ops@company.org", "rationale": "Declassification approved"},
        {"approver_id": "ciso@company.org", "rationale": "Review completed"},
    ],
)

# 5. Renew record on unchanged hash
sha256 = DocketClient.hash_file("D:/data/product_overview_public.md")
client.renew_record(
    locator="file://estate/fileshare/product_overview_public.md",
    observed_content_sha256=sha256,
)

# 6. Governance Review Queue
pending_reviews = client.list_reviews(status="PENDING_REVIEW")
for review in pending_reviews:
    print(f"Review ID: {review['id']}, Finding Tier: {review['provisional_tier']}")
    # Approve review item
    client.approve_review(
        review_id=review["id"],
        approver_id="security-lead@company.org",
        confirmed_tier="Confidential",
    )
```

---

## 8. Signed Snapshot Publisher

Fetch the active monotonic DSSE-signed snapshot:

```python
from docket import DocketClient

client = DocketClient(snapshot_url="http://localhost:18081")

# Fetch latest signed snapshot
snapshot = client.get_latest_snapshot()
payload_type = snapshot["payloadType"]
signatures = snapshot["signatures"]

print("Payload Type:", payload_type)
print(f"Key ID: {signatures[0]['keyid']}")
```

---

## 9. Asynchronous Client (`AsyncDocketClient`)

For high-throughput `asyncio`, FastAPI, or Starlette applications:

```python
import asyncio
from docket import AsyncDocketClient, PolicyDenialError


async def main():
    async with AsyncDocketClient() as client:
        # Prevalidator health
        health = await client.get_health()
        print("Async Status:", health["status"])

        # Wait for sync
        await client.wait_for_sync(min_sequence=1, timeout_sec=30)

        # OpenAI chat completion
        try:
            resp = await client.chat_completions(
                messages=[{"role": "user", "content": "Summarize architecture."}],
                model="gpt-4o",
            )
            print("Response:", resp["choices"][0]["message"]["content"])
        except PolicyDenialError as err:
            print("Denied:", err)

        # Directory prevalidation
        scan = await client.prevalidate_directory("D:/attestation/pc_demo_folder")
        print("Scanned files:", scan["total_files"])


if __name__ == "__main__":
    asyncio.run(main())
```

---

## 10. Client Initialization Options

`DocketClient` and `AsyncDocketClient` accept the following configuration parameters:

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `base_url` | `str` | `http://localhost:18082` | URL of the Prevalidator proxy service |
| `registry_url` | `str` | `http://localhost:18080` | URL of the Authoritative Registry service |
| `snapshot_url` | `str` | `http://localhost:18081` | URL of the Signed Snapshot Publisher service |
| `admin_key` | `str` | `pod-dev-admin-key` | Secret key sent in `X-POD-Admin-Key` header |
| `default_caller_key`| `str` | `pod-key-public` | Default caller credential for `/v1/chat/completions` |
| `timeout` | `float` | `30.0` | Global HTTP request timeout in seconds |

---

## 11. Error Reference

All SDK errors inherit from `DocketError`:

```python
from docket import DocketError, PolicyDenialError

try:
    client.chat_completions(...)
except PolicyDenialError as exc:
    # HTTP 403: Specific data attestation policy denial
    print(exc.status_code)      # 403
    print(exc.response_body)     # Denial details, reason code, and violation metadata
except DocketError as exc:
    # Other API errors (400, 404, 500, etc.)
    print(exc.status_code)
    print(exc.response_body)
```
