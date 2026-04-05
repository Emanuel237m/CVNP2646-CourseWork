# User Account & Permissions Auditor

## Overview

The **User Account & Permissions Auditor** is a Python-based Identity and Access Management (IAM) auditing tool designed to simulate real-world security reviews performed by Security Operations Centers (SOC).

The tool analyzes user account data and role assignments to detect security policy violations, generate compliance reports, and highlight high-risk users prior to audits such as **SOC 2**, **ISO 27001**, and **PCI-DSS**.

This project demonstrates practical skills in:
- Data joining using unique IDs
- Python set operations for anomaly detection
- Security rule development
- Risk prioritization
- Compliance-focused reporting

---

## Why IAM Auditing Matters

Identity is one of the most common attack paths in modern breaches. Many security incidents occur due to:

- Disabled accounts retaining access  
- Stale or forgotten user accounts  
- Excessive permissions (privilege creep)  
- Unauthorized administrative privileges  

Regular IAM audits are required by security frameworks including:
- **SOC 2**
- **ISO 27001**
- **PCI-DSS**

This tool helps identify these issues before they become security incidents.

---

## Project Features

### Core Capabilities

- Load user and role data from JSON files
- Join datasets using `user_id`
- Use dictionaries for constant-time lookups
- Use sets for efficient membership testing
- Detect multiple IAM security violations
- Generate structured compliance reports

### Enhanced Features

- User risk scoring system
- Top-risk user prioritization
- Department-level risk analysis
- CSV export for auditors

---

## Detection Rules Implemented

| Rule | Description | Severity |
|---|---|---|
| Disabled Users with Roles | Disabled accounts still have role access | CRITICAL |
| Unauthorized Admin Access | Admin roles outside IT/Security | HIGH |
| Stale Accounts | No login activity for 90+ days | MEDIUM |
| Conflicting Roles | Separation of duties violations | CRITICAL |
| Excessive Permissions | More than allowed number of roles | MEDIUM |
| Orphaned Roles | Roles assigned to nonexistent users | HIGH |

---

## AI Usage Disclosure

**AI Tool Used:** ChatGPT (OpenAI)

**Prompt Used:**
> “I’m building a user account and permissions auditor. I already detect disabled users with roles, unauthorized admin access, and stale accounts. What additional IAM security anomalies should I look for?”

**AI-Suggested Rules Implemented:**
- Conflicting roles
- Excessive permissions
- Orphaned role assignments

The AI-generated ideas were reviewed, simplified, and adjusted to align with SOC best practices.

---

## Data Structure

### users.json

Each user record includes:
- `user_id`
- `username`
- `status` (active or disabled)
- `department`
- `last_login`

### roles.json

Each role assignment includes:
- `user_id`
- `role`
- `assigned_date`

The datasets are joined using the `user_id` field.

---

## Risk Scoring Method

Each violation adds points to a user’s risk score:

| Severity | Points |
|--------|--------|
| CRITICAL | 10 |
| HIGH | 5 |
| MEDIUM | 3 |
| LOW | 1 |

This allows quick identification of users requiring urgent remediation.

---

## Reports Generated

### JSON Report (`audit_report.json`)
- Designed for SIEM tools and automation
