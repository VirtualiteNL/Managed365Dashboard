# 📊 Managed 365 Dashboard – Risk & Compliance Analyzer

![License: BY-NC-SA 4.0](https://img.shields.io/badge/license-BY--NC--SA%204.0-yellow.svg)

A modular PowerShell reporting framework for Microsoft 365, focusing on risk indicators, identity hygiene, and compliance across Microsoft 365 tenants.

---

## 📦 Description

This dashboard connects to a Microsoft 365 tenant and collects key audit and security insights.  
It generates a complete Fluent UI-style HTML report containing:

- 🔐 Expired or expiring client secrets and certificates
- ⚠️ Risky users with detailed IOC analysis
- 💻 Non-compliant Intune devices
- 📝 Optional logging per tenant
- 🖥 Local filtering and navigation via JavaScript

---

## 🚀 Requirements

### 🔧 PowerShell Version

- PowerShell **7.2 or later** recommended  
- PowerShell 5.1 is supported with reduced compatibility

### 📦 Required PowerShell Modules

| Module                          | Install command                                         |
|---------------------------------|---------------------------------------------------------|
### 🔐 Required Microsoft Graph API Permissions

The following **Microsoft Graph Permissions** are required for full functionality of the Managed 365 Dashboard:

| Scope                                             | Purpose                                                                |
|---------------------------------------------------|-------------------------------------------------------------------------|
| `Application.Read.All`                            | Detect inactive apps, secrets, certificates                             |
| `Directory.Read.All`                              | Retrieve users, groups, roles, devices, compliance                      |
| `User.Read.All`                                   | Resolve UPNs, names, sign-in relationships                              |
| `RoleManagement.Read.Directory`                   | Detect privileged role assignments                                      |
| `ServiceHealth.Read.All`                          | Read current service health status                                      |
| `ServiceMessage.Read.All`                         | Retrieve service announcements                                          |
| `Policy.Read.All`                                 | Read Conditional Access and other policy settings                       |
| `DeviceManagementConfiguration.Read.All`          | Analyze configuration profiles (classic Intune)                         |
| `DeviceManagementManagedDevices.Read.All`         | Check device compliance and non-compliant states                        |
| `DeviceManagementApps.Read.All`                   | Detect Apple MDM Push certificate status                                |
| `DeviceManagementServiceConfig.ReadWrite.All`     | Needed to access fallback MDM settings via Graph (read is insufficient) |
| `AuditLog.Read.All`                               | Retrieve sign-in events, password resets, directory audit logs          |
| `IdentityRiskEvent.Read.All`                      | Risky user detection and identity protection alerts                     |
| `UserAuthenticationMethod.Read.All`               | Detect registered MFA methods per user                                  |
| `DeviceManagementConfiguration.ReadWrite.All`     | Required for modern settings fallback in config profile checks          |
| `Reports.Read.All`                                | Used for sign-in reports and high-level tenant summaries                |


> Make sure to `Connect-MgGraph` with required scopes or use App Registration with permissions.

---

## 📁 Folder Structure

```
Managed365Dashboard/
├─ Managed365Dashboard.ps1         # Main entry point per tenant
├─ modules/
│   ├─ connect.ps1                 # Connect to Microsoft Graph
│   ├─ secrets.ps1                 # Expiring secrets and certs
│   ├─ riskyusers.ps1              # Risky user HTML + details
│   ├─ userrisk.ps1                # IOC detection per user
│   ├─ otherchecks.ps1             # Other checks (Apple MDM Certificate and Config profile errors.)
│   ├─ noncompliant.ps1            # Non-compliant device detection
│   ├─ htmlbuilder.ps1             # Report output formatting
|   ├─ summary.ps1                 # Generates plain-text summary per tenant
│   └─ logger.ps1                  # Logging utilities
└─ reports/                        # Generated HTML reports
```

---

## 🔎 Indicators of Compromise (IOC)

### 🛡️ UserRisk IOC 1 – Admin roles assigned
Detects if the user has directory-level admin privileges (e.g. Global Admin).  
🔸 **Risk**: Elevated rights increase exposure and abuse potential.

### 🧪 UserRisk IOC 2 – OAuth consents in last 30 days
Checks whether the user recently granted OAuth consent to applications.  
🔸 **Risk**: Unverified apps may have access to mail, files, or directory data.

### 🔐 UserRisk IOC 3 – Recent changes to authentication methods
Identifies if the user has changed or removed any MFA methods in the last 30 days.  
🔸 **Risk**: Could indicate account takeover attempts or MFA evasion.  
ℹ️ **Note**: Audit events may take up to 30 minutes to appear.

### ✅ UserRisk IOC 4 – No MFA registered
Detects if the user has no multi-factor authentication method registered.  
🔸 **Risk**: Account is more vulnerable to password-based attacks.

### 🔑 UserRisk IOC 5 – Password reset in last 30 days
Lists all password reset events triggered for the user within the past 30 days.  
🔸 **Risk**: Unexpected or repeated resets could indicate account compromise.

### 🕓 UserRisk IOC 6 – Recently created accounts  
Detects if the user account is less than 7 days old.  
🔸 **Risk**: Newly created accounts may indicate staging for future abuse or misconfiguration.

### 🛡️ UserRisk IOC 7 – Not protected by Conditional Access
Checks if the user is covered by at least one active Conditional Access policy that enforces MFA, compliant devices, domain-joined devices, or authentication strength.
It also evaluates whether the policy targets the user directly, via group or role membership, and warns if the policy does not apply to all cloud apps.
🔸 **Risk**: Users not protected by strong Conditional Access policies are more vulnerable to phishing, session hijacking, or access from unmanaged devices.

> More IOC modules can be added in `userrisk.ps1`.

---

## 🖥 Sections in the HTML Dashboard

| Section             | Description                                                                                 |
|---------------------|---------------------------------------------------------------------------------------------|
| **🔐 Secrets**       | Lists expiring client secrets and certificates                                              |
| **⚠️ Risky Users**   | Displays users flagged by Entra ID as risky, with popups showing all IOC findings           |
| **💻 Devices**       | Shows devices that are non-compliant based on Intune compliance policies                    |
| **📱 Other checks**  | Includes additional tenant health checks, such as Apple MDM certificate expiration and configuration profile deployment errors (≥25%) with modern profile fallback logic |

Each section supports:
- collapsible panels  
- dynamic dark mode  
- local filtering  
- interactive details via JavaScript

---

## 📝 Logging

- Each run produces a `.txt` log file next to the `.html` report
- Logging is categorized: `Alert`, `OK`, `Information`, `Error`

---

## 📦 Example Usage

1. Start `Managed365Dashboard.ps1`.
2. Sign in with an account that has sufficient privileges to consent to the required Microsoft Graph permissions for the tenant.
3. Once the script completes, open the generated HTML report located in the `reports` folder.

---

## 📜 License Summary

This project is licensed under the [Creative Commons BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) license.  
You may use, adapt, and share it for non-commercial purposes, provided that:

- You do not remove the Virtualite branding, styling, or script headers
- You publish all modifications publicly (e.g., on GitHub)

📧 For commercial use, custom branding, or feature requests, contact [danny@virtualite.nl](mailto:danny@virtualite.nl)

---

© 2025 Virtualite.nl – All rights reserved.