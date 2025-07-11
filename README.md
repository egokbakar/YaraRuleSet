# RAT Builder Analysis Package

This repository contains YARA rules and detailed static analysis reports for a collection of Remote Access Trojan (RAT) builders.  

## 📁 Folder Structure

Each folder represents a different RAT builder and contains:

- `Builder.yara` – Variant-specific YARA detection rule.
- `CAPA/` – Static analysis results (JSON format) for the builder sample.
- `DIE/` – PE structure and metadata (JSON format) for the builder sample.

⚠️ **NOTE:**  
For security reasons, the original malware samples are **NOT included** in this repository. Instead, their **MD5 hashes** are used as filenames in the `CAPA` and `DIE` reports to identify which sample was analyzed.

## 🔐 Sample Exclusion

The actual builder binaries have been excluded to avoid misuse. Reports and rules were generated from verified samples in a controlled environment.  

---

© 2025 egokbakar. All rights reserved.
