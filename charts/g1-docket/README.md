# G1 Docket Helm Chart

Official production Helm chart for deploying **G1 Docket** — Cryptographic Data Attestation Framework & Zero-DB-Call AI Gateway Prevalidator.

---

## Quickstart

### 1. Add and Install Chart
```bash
# From the repository root:
helm install g1-docket ./charts/g1-docket \
  --namespace g1-docket \
  --create-namespace
```

### 2. Verify Deployment
```bash
helm status g1-docket -n g1-docket
kubectl get pods -n g1-docket
```

---

## Configuration Reference

| Parameter | Description | Default |
| :--- | :--- | :--- |
| `gateway.mode` | Operational state (`"enforce"` or `"observe"`) | `"enforce"` |
| `abac.dataResidency.enabled` | Enable regional sovereign boundary enforcement (GDPR) | `true` |
| `abac.departmentalIsolation.enabled` | Enable departmental compartmentalization | `true` |
| `gateway.strictInlineHash` | Live SHA-256 fingerprint verification of `<pod:object>` tokens | `true` |
| `gateway.upstreamGatewayUrl` | Upstream model gateway (LiteLLM, vLLM, Bedrock, OpenAI) | `"http://litellm-gateway:14000"` |
| `prevalidator.replicaCount` | Number of Prevalidator stateless proxy pods | `3` |
| `prevalidator.resources.requests.cpu` | Requested CPU for Prevalidator | `"250m"` |
| `prevalidator.resources.requests.memory` | Requested memory for Prevalidator | `"256Mi"` |
| `governance.replicaCount` | Number of Governance / WORM audit pods | `2` |
