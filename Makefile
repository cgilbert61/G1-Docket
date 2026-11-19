# ==============================================================================
# G1 Docket — Federal DevSecOps & Compliance Makefile
# Standards: NIST SP 800-53, DISA STIG, EO 14028 SBOM, Section 508 / WCAG 2.1 AA
# ==============================================================================

SHELL := /bin/bash
PYTHON ?= python

.PHONY: all compliance-check sast secrets iac sbom container-scan dast a11y load-test govready clean-reports help

# Default target executes complete compliance pipeline
all: compliance-check

help:
	@echo "G1 Docket Federal DevSecOps Compliance Pipeline"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  compliance-check  Run all federal compliance gates and output reports to ./reports/"
	@echo "  sast              Execute SonarQube & Semgrep SAST / CWE scanning"
	@echo "  secrets           Scan git repository history for secrets using Gitleaks"
	@echo "  iac               Validate Terraform, Kubernetes & Dockerfiles via Checkov"
	@echo "  sbom              Generate Executive Order 14028 CycloneDX SBOM using Syft"
	@echo "  container-scan    Evaluate container hardening & CVEs with Trivy"
	@echo "  dast              Run OWASP ZAP baseline dynamic application security scan"
	@echo "  a11y              Verify Section 508 & WCAG 2.1 AA compliance with axe-core"
	@echo "  load-test         Execute k6 gateway hot-path SLA load test"
	@echo "  govready          Run GovReady-Q NIST SP 800-53 automated assessment"
	@echo "  clean-reports     Clean up generated SARIF and JSON reports"

compliance-check:
	@echo "Executing Federal DevSecOps Compliance Pipeline (All Gates)..."
	@$(PYTHON) scripts/compliance_harness.py --all

sast:
	@echo "Running SAST Gate (Semgrep & SonarQube)..."
	@$(PYTHON) scripts/compliance_harness.py --gate sast

secrets:
	@echo "Running Secrets Detection Gate (Gitleaks)..."
	@$(PYTHON) scripts/compliance_harness.py --gate secrets

iac:
	@echo "Running IaC Security Gate (Checkov)..."
	@$(PYTHON) scripts/compliance_harness.py --gate iac

sbom:
	@echo "Running SBOM Generation Gate (Syft CycloneDX)..."
	@$(PYTHON) scripts/compliance_harness.py --gate sbom

container-scan:
	@echo "Running SCA & Container Hardening Gate (Trivy)..."
	@$(PYTHON) scripts/compliance_harness.py --gate sca

dast:
	@echo "Running DAST Dynamic Scan Gate (OWASP ZAP)..."
	@$(PYTHON) scripts/compliance_harness.py --gate dast

a11y:
	@echo "Running Section 508 Accessibility Gate (axe-core)..."
	@$(PYTHON) scripts/compliance_harness.py --gate a11y

load-test:
	@echo "Running SLA & Load Testing Gate (k6)..."
	@$(PYTHON) scripts/compliance_harness.py --gate load

govready:
	@echo "Running GovReady-Q NIST SP 800-53 Assessment..."
	@$(PYTHON) scripts/compliance_harness.py --gate govready

clean-reports:
	@echo "Cleaning reports directory..."
	@rm -rf reports/*.sarif reports/sbom.cdx.json reports/k6-summary.json reports/axe-accessibility.json
