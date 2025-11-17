# Azure Cybersecurity Posture Assessment (ACPA)

![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-blue?logo=powershell)
![Azure](https://img.shields.io/badge/Microsoft_Azure-0089D6?logo=microsoftazure&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

A **client-ready**, **automated PowerShell script** that performs a **comprehensive cybersecurity assessment** of Azure environments — covering **Identity (Entra ID), IaaS, PaaS, Network, Defender for Cloud, and Governance** — and generates a **professional HTML report**.

Perfect for:
- Security consultants
- Cloud architects
- Internal audit teams
- Pre-engagement gap analysis

> ✅ **No changes to your environment** — runs with **Reader + Microsoft Graph Reader** permissions only.

---

## 🚀 Features

- 🔐 **Zero-impact assessment** (read-only)
- 🖥️ **Fully automatic** — no manual input needed (auto-discovers Log Analytics workspaces)
- 📊 **HTML report** with color-coded risk levels (High/Medium/Low)
- 🧩 Covers **6 security domains**:
  1. **Identity & Access** (Entra ID: MFA, guest users, legacy auth)
  2. **Compute** (VM encryption, backup, patching)
  3. **Platform Services** (Storage, SQL, Key Vault)
  4. **Network** (Public IPs, DDoS, NSGs)
  5. **Defender for Cloud** (Security assessments)
  6. **Governance** (Policy compliance, diagnostic logs)
- 🔍 Uses **modern Azure PowerShell (`Az`)** and **Microsoft Graph**
- 🌐 Works across **any Azure subscription**

---

## 🛠️ Prerequisites

### 1. **PowerShell 7+ (Required)**
> ⚠️ **Does NOT work reliably in Windows PowerShell 5.1** due to Microsoft Graph SDK limitations.

- Install **PowerShell 7.4+** from:  
  👉 [https://aka.ms/powershell-release](https://aka.ms/powershell-release)

### 2. **Required Permissions**
Your account must have:
- **Reader** role on the target Azure subscription
- **Microsoft Graph Reader** permissions (via PIM or direct assignment):
  - `AuditLog.Read.All`
  - `Directory.Read.All`
  - `Policy.Read.All`

> 💡 These are **read-only** and safe for client engagements.

### 3. **Install PowerShell Modules**
Open **PowerShell 7** as your user and run:

```powershell
Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -AllowClobber

📥 Usage
Step 1: Clone or Download
bash


1
2
git clone https://github.com/your-username/azure-cybersecurity-assessment.git
cd azure-cybersecurity-assessment
Step 2: Run the Script
powershell


1
2
3
.\Azure-Cybersecurity-Assessment.ps1 `
  -SubscriptionId "your-subscription-id" `
  -TenantId "your-tenant-id"
🔍 Find your: 

Subscription ID: Azure Portal → Subscriptions → Copy ID
Tenant ID: Azure Portal → Microsoft Entra ID → Overview → "Tenant ID"
Step 3: Review the Report
A file named Azure-Cybersecurity-Assessment-YYYYMMDD-HHMM.html is generated
Open it in any browser to view the interactive, color-coded report
