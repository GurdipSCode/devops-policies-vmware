# Terraform OPA Policies for VMware vSphere

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OPA](https://img.shields.io/badge/OPA-v0.68.0-blue?logo=openpolicyagent&logoColor=white)](https://www.openpolicyagent.org/)
[![Rego](https://img.shields.io/badge/Rego-v1-blueviolet)](https://www.openpolicyagent.org/docs/latest/policy-language/)
[![Terraform](https://img.shields.io/badge/Terraform-%3E%3D1.0-purple?logo=terraform&logoColor=white)](https://www.terraform.io/)
[![VMware](https://img.shields.io/badge/VMware-vSphere-607078?logo=vmware&logoColor=white)](https://registry.terraform.io/providers/hashicorp/vsphere)
[![CI](https://github.com/{owner}/{repo}/actions/workflows/ci.yml/badge.svg)](https://github.com/{owner}/{repo}/actions/workflows/ci.yml)
[![CodeRabbit](https://img.shields.io/badge/CodeRabbit-AI%20Review-orange?logo=rabbitmq&logoColor=white)](https://coderabbit.ai/)
[![GitGuardian](https://img.shields.io/badge/GitGuardian-Secured-success?logo=gitguardian&logoColor=white)](https://www.gitguardian.com/)
[![Regal](https://img.shields.io/badge/Regal-Linted-green?logo=openpolicyagent&logoColor=white)](https://github.com/StyraInc/regal)

---

Open Policy Agent (OPA) policies for validating Terraform configurations using the **VMware vSphere** provider.

## Overview

This repository contains Rego policies designed to enforce security, compliance, and best practices for Terraform resources managed by the [VMware vSphere Terraform provider](https://registry.terraform.io/providers/hashicorp/vsphere).

## ✨ Features

- 🔒 **Security Policies** — VM encryption, network isolation, secure boot, credential management
- ✅ **Compliance Validation** — Resource allocation, tagging, cluster policies
- 📋 **Naming Conventions** — Consistent VM, datastore, and network naming
- 🧪 **Fully Tested** — Comprehensive test coverage
- 🚀 **CI/CD Ready** — Buildkite/GitHub Actions workflows included

## 📦 Installation

```bash
git clone https://github.com/{owner}/terraform-opa-vmware.git
cd terraform-opa-vmware
```

## 🚀 Usage

### With Conftest

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
conftest test tfplan.json -p policies/
```

### With OPA

```bash
opa eval --data policies/ --input tfplan.json "data.vmware.deny"
```

## 📁 Policy Structure

```
policies/
├── vmware/
│   ├── security.rego      # Security-related policies
│   ├── compliance.rego    # Compliance policies
│   └── naming.rego        # Naming convention policies
└── lib/
    └── helpers.rego       # Shared helper functions

tests/
└── security_test.rego     # Policy unit tests
```

## 🧪 Testing

```bash
opa test policies/ tests/ -v
```

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
