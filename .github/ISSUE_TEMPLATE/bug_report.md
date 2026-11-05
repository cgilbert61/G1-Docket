---
name: Bug Report
about: Create a report to help us reproduce and fix an issue in G1 Docket
title: "[BUG]: "
labels: ["bug", "triage"]
assignees: []
---

## Description
A clear and concise description of what the bug is.

## Component Affected
Please select the component where the issue occurs:
- [ ] Prevalidator Admission Gateway (:18082)
- [ ] Attestation Engine (:18083)
- [ ] Governance & HITL Triage Hub (:18084)
- [ ] Authoritative Registry (:18080)
- [ ] Snapshot Publisher (:8081)
- [ ] Docket Client Python SDK (`docket.*`)
- [ ] CLI (`pod-attest` / `pod-preval`)
- [ ] UI / Dashboard (:18082 or :18084)
- [ ] Other

## Steps to Reproduce
Steps to reproduce the behavior:
1. Run command '...'
2. Send request to endpoint '...'
3. See error

## Expected Behavior
A clear and concise description of what you expected to happen.

## Actual Behavior / Error Logs
Include terminal output, stack traces, or relevant HTTP response status/bodies:
```text
(Paste logs here)
```

## Environment Details
- **G1 Docket Version / Commit**: (e.g. `0.2.0`, commit `ff236cf`)
- **Deployment Mode**: (e.g. Docker Compose, Kubernetes sidecar, Bare metal / Virtualenv)
- **Operating System**: (e.g. Ubuntu 22.04, Windows 11, macOS 14)
- **Python Version**: (e.g. 3.11.8)

## Additional Context
Add any other context about the problem here (e.g. snapshot size, clearance level, volume of objects).
