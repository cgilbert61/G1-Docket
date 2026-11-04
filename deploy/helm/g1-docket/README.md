# G1 Docket Kubernetes Helm Chart

Production-grade Helm chart for deploying the **G1 Docket Zero-Trust AI Data Attestation & Admission Control Suite** on Kubernetes.

## Architecture

The chart deploys the following microservices:

1. **Prevalidator Admission Gateway** (`:18082`):
   - High-throughput, sub-millisecond ($< 1\text{ ms}$) in-memory inline admission proxy for LLM inference calls (`/v1/chat/completions`).
   - Supports Horizontal Pod Autoscaling (HPA) targeting CPU and memory utilization thresholds.
   - Operates in either `enforce` (blocking) or `observe` (audit-only) modes.
2. **HITL Governance Console & SIEM** (`:18084`):
   - Cryptographic Four-Eyes override approval workflow, quarantine resolution, and tamper-evident append-only WORM Merkle audit log.
   - Backed by persistent volume claim (PVC) for audit durability.
3. **Attestation & DLP Engine** (`:18083`):
   - Distributed multi-store crawlers (`s3://`, `azblob://`, `gs://`, `snowflake://`, `iceberg://`, `bigquery://`, `postgres://`).
   - Microsoft Presidio DLP entity classification, sensitivity mapping, and content digest computation.
4. **Authoritative Snapshot Publisher** (`:18081`):
   - Signs point-in-time in-toto DSSE v1 attestation envelopes using RSA/Ed25519 keyrings.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- StorageClass for WORM audit persistence (e.g. `gp3`, `standard`, `managed-csi`)

## Quickstart Installation

```bash
# Add or clone repository
cd deploy/helm

# Lint chart syntax
helm lint g1-docket

# Install chart into 'docket' namespace
helm upgrade --install g1-docket ./g1-docket \
  --namespace docket \
  --create-namespace \
  --set prevalidator.mode=enforce \
  --set secrets.adminApiKey="YOUR_SECURE_ADMIN_API_KEY" \
  --set secrets.jwtSecret="YOUR_SECURE_JWT_SECRET_32_BYTES"
```

## Configuration Parameters

| Parameter | Description | Default |
| :--- | :--- | :--- |
| `prevalidator.replicaCount` | Replicas when HPA is disabled | `3` |
| `prevalidator.autoscaling.enabled` | Enable Horizontal Pod Autoscaling | `true` |
| `prevalidator.autoscaling.minReplicas` | Minimum prevalidator pod replicas | `2` |
| `prevalidator.autoscaling.maxReplicas` | Maximum prevalidator pod replicas | `10` |
| `prevalidator.mode` | Gateway enforcement posture (`enforce` or `observe`) | `"enforce"` |
| `prevalidator.strictInlineHash` | Verify `<pod:object sha256="...">` inline hashes | `true` |
| `prevalidator.enablePresidioFallback`| Fallback entity scanning for unclassified text | `true` |
| `governance.persistence.enabled` | Enable persistent volume for WORM Merkle audit logs | `true` |
| `governance.persistence.size` | Storage capacity for WORM audit logs | `20Gi` |
| `ingress.enabled` | Enable Kubernetes Ingress resource | `true` |
| `ingress.className` | Ingress controller class name | `"nginx"` |

## Port Forwarding & Verification

```bash
# Port-forward Prevalidator Gateway
kubectl port-forward svc/g1-docket-prevalidator 18082:18082 -n docket

# Port-forward HITL Governance Console
kubectl port-forward svc/g1-docket-governance 18084:18084 -n docket

# Test health
curl http://localhost:18082/healthz
```
