# Patch Compliance & Risk Assessment Tracker

A Python‑based tool for analyzing patch compliance across a 20‑host enterprise environment. The tracker calculates days since last patch, performs multi‑factor risk scoring, identifies high‑risk hosts, and generates JSON, text, and HTML reports suitable for SOC analysts and IT management.

---

## 📌 1. Overview

Unpatched systems remain one of the most common causes of cybersecurity breaches. Attackers frequently exploit vulnerabilities that already have available patches, sometimes released months prior. This tool provides a structured way to identify outdated systems, prioritize remediation, and support compliance with industry frameworks such as CIS, PCI‑DSS, and HIPAA.

The Patch Tracker:

- Loads system inventory from JSON  
- Calculates days since last patch  
- Performs a multi‑factor risk score (0–100)  
- Assigns risk levels (critical, high, medium, low)  
- Identifies high‑risk hosts  
- Generates three report formats (JSON, text, HTML)

---

## ▶️ 2. Usage

Make sure the project folder contains:

