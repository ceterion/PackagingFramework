# ceterion Packaging Framework (cPF)

> Enterprise-ready PowerShell framework for standardized, automated, and platform-agnostic software packaging and deployment integration.


![Version](https://img.shields.io/badge/version-26.6.1.0-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![License](https://img.shields.io/badge/license-GPLv3-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

---

## 🚀 Quick Start

```powershell
Import-Module PackagingFramework
Initialize-Script
New-Package -Path C:\Temp -Name 'MyApp_1.0'
```

---

## 💡 Why cPF?

- Standardize and scale your **enterprise packaging process**
- Automate packaging with a **modular PowerShell framework**
- Integrate seamlessly with **modern deployment platforms (MECM, Intune, Workspace ONE, XOAP, Recast)**
- Extend into full **end-to-end deployment workflows (cDF)**
- Leverage **Winget, XOAP, and enterprise service integrations**

---

# ceterion Packaging Framework 2606 (26.6.1.0)

## Overview

The **ceterion Packaging Framework (cPF)** is a modular PowerShell-based framework for standardized, automated, and enterprise-ready software packaging.

Since 2019, the framework has been continuously evolved and architecturally expanded across more than 40 iterations.

It enables organizations to build, manage, and deploy application packages in a consistent, scalable, and maintainable way across modern endpoint management platforms.

## Key Features

- Modular PowerShell architecture (fully refactored from script-based approach)
- Standardized packaging methodology for enterprise environments
- Integration-ready for modern deployment solutions (e.g. MECM, Intune, Workspace ONE)
- Seamless integration with the ceterion Deployment Framework (cDF) enabling end-to-end automation from packaging to deployment
- Native integration with Recast Application Workspace for enhanced application management and user experience
- Package integrity sealing with automatic install-time validation (`New-PackageSeal` / `Test-PackageSeal`)
- Built-in logging, error handling, and user interaction handling
- Highly customizable via central configuration (`PackagingFramework.json`)
- Designed for automation and CI/CD scenarios

## Packaging Lifecycle

The framework supports a structured end-to-end packaging and deployment lifecycle:

Create → Configure → Package → Test → Deploy → Maintain

**Roles & Technologies:**

- **Create / Configure / Package / Test**
  - **cPF (ceterion Packaging Framework)** – Standardized packaging, configuration, validation, and testing

- **Deploy**
  - Any deployment mechanism (including custom scripts such as CMD/PowerShell)
  - **Tools (Endpoint Management)**
    - **Microsoft Intune** – Endpoint management platform
    - **Microsoft MECM (SCCM)** – Endpoint management platform
    - **Omnissa Workspace ONE** – Endpoint management platform
  - **Frameworks**
    - **cDF (ceterion Deployment Framework)** – Optional deployment orchestration and automation layer
  - **Platforms / Experience Layer**
    - **XOAP** – Integration, package management, and Infrastructure-as-a-Service (IaaS) enablement
    - **Recast Application Workspace** – Application delivery and user experience layer

- **Maintain**
  - **cPF / cDF** – Lifecycle updates, versioning, and operational management

This ensures a seamless transition from packaging to enterprise deployment workflows.

## Technology Base

The framework integrates selected components of the **PowerShell App Deployment Toolkit (PSAppDeployToolkit v3.7.0)**.

These components have been:
- Refactored
- Extended
- Stabilized

…and embedded into a modular architecture to meet real-world enterprise requirements.

## What’s New in 2606 (26.6.1.0)

- **Package integrity sealing** — seal a package’s `Files` folder with per-file MD5 hashes and a top-level aggregate manifest hash via **`New-PackageSeal`**, embedded as a collapsible `#region` block inside the package script. The seal is validated automatically at install time (**`Test-PackageSeal`**, invoked by `Invoke-PackageStart`); a changed, missing, or added file aborts the package before any payload runs. Sealing removes any existing Authenticode signature so packages can be re-signed afterwards (seal, then sign).

### Previously in 2604 (26.4.0.0)

- Localization extended to **25 supported languages (23 newly added)**:
  - Newly added: Arabic, Chinese (Simplified), Chinese (Traditional), Czech, Danish, Dutch (Netherlands), Finnish, French, Hebrew, Hungarian, Italian, Japanese, Korean, Norwegian (Bokmål), Polish, Portuguese, Portuguese (Brazil), Russian, Slovak, Spanish, Swedish, Turkish, Ukrainian

*Previously supported languages: German, English*

- Added **XOAP support** for integration, deployment, and management of Packaging Framework packages in XOAP environments
- Updated internal parameter handling (`ServiceURL` replaces `WebserverURL`)

## Optional Extensions & Toolsets

Extended capabilities are available on request:

- **Migration Converters**
  - Ivanti / DSM / NetInstall / HEAT / FrontRange → PowerShell
  - Wise Script → PowerShell
  - NSIS → PowerShell

- **Workspace ONE UEM Extension**
  - Automation cmdlets for package import and task handling

- **SCCM / MECM / Intune Toolset**
  - Collection management
  - Parameter inheritance
  - Deployment automation

- **Template Libraries**
  - 270+ Application package templates
  - 100+ OS configuration templates
  - Citrix templates (PVS, XenApp, XenDesktop)

- **Winget Repository Integration**
  - Automated integration of Winget package repositories
  - Enterprise-ready consumption of public repositories with standardized packaging integration

- **Packaging as a Service (PaaS)**
  - Outsourced and scalable application packaging services by ceterion
  - Standardized, high-quality package delivery aligned with enterprise requirements

- **Professional & Support Services**
  - Implementation and customization
  - Integration into existing environments
  - Trainings and workshops
  - Technical support
  - SLA-based enterprise support

## Installation

Run:

```
PackagingFrameworkSetup.exe
```

## Usage

### Requirements

- PowerShell with administrative privileges
- Execution policy allowing script execution:

```
Set-ExecutionPolicy RemoteSigned
```

### Import Module

```
Import-Module PackagingFramework
```

### Initialize Runtime

```
Initialize-Script
```

### Discover Commands

```
Get-Command -Module PackagingFramework
```

### Help

```
Get-Help [Command]
Get-Command -Module PackagingFramework | Get-Help
Show-HelpConsole
```

### Runtime Variables

```
Get-Variable | Out-GridView
```

### Create a Package (Example)

```
New-Package -Path C:\Temp -Name 'Microsoft_Office_16.0_EN_01.00'
```

### Configuration

Central configuration file:

```
%ProgramFiles%\WindowsPowerShell\Modules\PackagingFramework\PackagingFramework.json
```

### Example Packages

```
%MyDocuments%\Packaging Framework Examples
```

## Support & Contact

- Email: packagingframework@ceterion.com
- GitHub Issues: https://github.com/ceterion/PackagingFramework/issues

## License

Licensed under the **GNU General Public License v3.0**.

See `/LICENSE.txt` for details.
