# G1 Docket — Kubernetes Deployment & Edge Sidecar Architecture

This directory provides production-ready Kubernetes manifests for deploying **G1 Docket** across AWS EKS, Google GKE, Azure AKS, or on-premise Kubernetes clusters.

---

## 1. Architecture Overview

G1 Docket supports two primary Kubernetes deployment topologies:

### Topology A: Edge Sidecar Pattern (Recommended for Inference Pods)
* **Design**: Deploy `docket-prevalidator` as a localhost sidecar (`127.0.0.1:18082`) within the same pod as your AI Agent, LangChain orchestrator, or vLLM container.
* **Benefits**:
  - Direct in-memory lookup via shared `/dev/shm` emptyDir volume.
  - Zero cross-pod network hops ($< 150\ \mu\text{s}$ decision latency).
  - Works natively with standard OpenAI client SDKs by configuring `base_url="http://127.0.0.1:18082/v1"`.

See [`sidecar-pattern.yaml`](file:///d:/attestation/deploy/k8s/sidecar-pattern.yaml).

### Topology B: Central Ingress Cluster Proxy
* **Design**: Deploy `g1-docket-prevalidator` as a horizontally scalable microservice deployment with an internal ClusterIP Service.
* **Benefits**:
  - Centralized gateway endpoint for an entire namespace or cluster.
  - Horizontally auto-scalable with standard Kubernetes HPA based on request rate.

See [`prevalidator-deployment.yaml`](file:///d:/attestation/deploy/k8s/prevalidator-deployment.yaml).

---

## 2. Quickstart Deployment

Apply the manifests in sequence:

```bash
# 1. Create dedicated namespace
kubectl apply -f namespace.yaml

# 2. Apply shared configuration
kubectl apply -f configmap.yaml

# 3. Deploy Prevalidator Gateway Cluster
kubectl apply -f prevalidator-deployment.yaml

# 4. Deploy Governance Console & WORM Audit Ledger
kubectl apply -f governance-deployment.yaml
```

Verify deployment health:
```bash
kubectl get pods -n g1-docket
kubectl get svc -n g1-docket
```

---

## 3. Port Mapping Reference

| Service | Port | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| **Prevalidator Gateway** | `18082` | HTTP | OpenAI (`/v1/chat/completions`) & Anthropic (`/v1/messages`) reverse proxy |
| **Governance & Triage** | `18084` | HTTP | Four-Eyes Dual Key console, WORM audit ledger, SIEM forwarder hub |
| **Snapshot Publisher** | `18081` | HTTP | Monotonic DSSE snapshot distributor |
| **Attestation Engine** | `18083` | HTTP | Continuous background delta crawler & catalog scanner |
| **Registry API** | `18080` | HTTP | Central authoritative PostgreSQL attestation record registry |
| **PostgreSQL** | `15432` | TCP | Central metadata & cryptographic record store |
