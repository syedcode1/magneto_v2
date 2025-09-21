# MAGNETO - Stealth Attack Simulator
## Professional Documentation

**Version:** 2  
**Author:** Syed Hasan Rizvi  
**Last Updated:** September 16, 2025  
**Purpose:** Enterprise-Grade MITRE ATT&CK Simulation for Exabeam UEBA

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Installation & Requirements](#installation--requirements)
4. [Core Features](#core-features)
5. [Usage Guide](#usage-guide)
6. [Execution Modes](#execution-modes)
7. [Parameter Reference](#parameter-reference)
8. [MITRE ATT&CK Coverage](#mitre-attck-coverage)
9. [Best Practices](#best-practices)
10. [Security Considerations](#security-considerations)
11. [Troubleshooting](#troubleshooting)
12. [Appendix](#appendix)

---

## Executive Summary

### Overview
MAGNETO is an advanced, PowerShell-based attack simulation framework designed specifically for validating and demonstrating Exabeam User and Entity Behavior Analytics (UEBA) detection capabilities. The tool simulates real-world cyber attacks using native Windows binaries (LOLBins) to generate authentic security events without introducing actual malware into the environment.

### Key Value Propositions
- **MITRE ATT&CK Aligned**: Full mapping to enterprise attack framework
- **Native Execution**: Uses only Windows-native binaries for maximum stealth
- **UEBA-Optimized**: Specifically crafted to trigger behavioral analytics alerts
- **Safe Simulation**: Controlled execution with comprehensive cleanup capabilities
- **Randomization Engine**: Daily variance to prevent ML baseline pollution

### Target Audience
- Security Operations Centers (SOCs)
- UEBA/SIEM Engineers
- Security Architects
- Penetration Testing Teams
- Compliance Auditors

---

## System Architecture

### Components Overview

```
┌─────────────────────────────────────────────────┐
│              MAGNETO Framework                   │
├─────────────────────────────────────────────────┤
│                                                  │
│  ┌───────────────┐     ┌──────────────────┐    │
│  │ Configuration │────▶│ Technique Engine │    │
│  │    Engine     │     └──────────────────┘    │
│  └───────────────┘              │               │
│                                 ▼               │
│  ┌───────────────┐     ┌──────────────────┐    │
│  │ Randomization │────▶│    Execution     │    │
│  │    Engine     │     │    Controller    │    │
│  └───────────────┘     └──────────────────┘    │
│                                 │               │
│                                 ▼               │
│  ┌───────────────┐     ┌──────────────────┐    │
│  │   Validation  │────▶│ LOLBin Executor  │    │
│  │    Engine     │     └──────────────────┘    │
│  └───────────────┘              │               │
│                                 ▼               │
│  ┌───────────────┐     ┌──────────────────┐    │
│  │   Cleanup     │────▶│  Logging Engine  │    │
│  │    Manager    │     └──────────────────┘    │
│  └───────────────┘                              │
│                                                  │
└─────────────────────────────────────────────────┘
```

### Technical Stack
- **Language**: PowerShell 5.1+
- **Platform**: Windows Server 2016+ / Windows 10+
- **Dependencies**: Native Windows utilities only
- **Output**: Structured logs, Windows Event Log entries

---

## Installation & Requirements

### System Requirements

#### Minimum Requirements
- Windows 10 / Server 2016 or later
- PowerShell 5.1 or later
- 4 GB RAM
- 100 MB available disk space

#### Recommended Requirements
- Windows 11 / Server 2022
- PowerShell 7.0+
- 8 GB RAM
- Administrator privileges (for full technique coverage)
- Domain-joined system (for complete simulation)

### Installation Steps

1. **Download the Framework**
   ```powershell
   # Clone from repository
   git clone https://github.com/syedcode1/magneto_v2.git
   
   # Or download directly - Not working at the moment.
   Invoke-WebRequest -Uri "https://example.com/magneto/MAGNETO.ps1" -OutFile "C:\Tools\MAGNETO.ps1"
   ```

2. **Verify Installation**
   ```powershell
   # Check script integrity
   Get-FileHash -Path "C:\Tools\MAGNETO.ps1" -Algorithm SHA256
   
   # Test basic functionality
   .\MAGNETO.ps1 -Help
   ```

3. **Configure Execution Policy** (if needed)
   ```powershell
   # For current user
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   
   # Or run with bypass
   powershell.exe -ExecutionPolicy Bypass -File "MAGNETO.ps1"
   ```

### Quick Start

```powershell
# Basic execution with cleanup
.\MAGNETO.ps1 -TechniqueCount 5 -Cleanup

# Using the batch launcher
.\Run_MAGNETO.bat
```

---

## Core Features

### 1. MITRE ATT&CK Implementation
- **25+ Techniques**: Comprehensive coverage across 9 tactics
- **Real-world Alignment**: Based on actual threat actor TTPs
- **Contextual Metadata**: Each technique includes detection rationale

### 2. Intelligent Randomization
- **Daily Seed Generation**: Prevents UEBA baseline pollution
- **Controlled Chaos**: Reproducible with custom seeds
- **Smart Selection**: Tactic-aware technique selection

### 3. Execution Control
- **Multiple Modes**: Random, Chain, or comprehensive execution
- **Granular Filtering**: Include/exclude specific tactics or techniques
- **Rate Limiting**: Configurable delays between executions

### 4. Safety Mechanisms
- **Validation Engine**: Pre-execution requirement checks
- **Cleanup System**: Automated artifact removal
- **Non-destructive**: Simulations without actual compromise

### 5. Comprehensive Logging
- **Detailed Tracking**: Command-level logging
- **MITRE Mapping**: Full ATT&CK framework correlation
- **Export Formats**: Text logs with structured data

---

## Usage Guide

### Basic Usage Patterns

#### 1. Standard Simulation
```powershell
# Run 7 random techniques with cleanup
.\MAGNETO.ps1 -TechniqueCount 7 -Cleanup
```

#### 2. Targeted Testing
```powershell
# Test specific discovery techniques
.\MAGNETO.ps1 -IncludeTactics @('Discovery', 'Execution') -TechniqueCount 5
```

#### 3. Comprehensive Assessment
```powershell
# Run all techniques with delays
.\MAGNETO.ps1 -RunAll -DelayBetweenTechniques 5 -Cleanup
```

#### 4. Specific Technique Testing
```powershell
# Test only network discovery techniques
.\MAGNETO.ps1 -IncludeTechniques @('T1046', 'T1049', 'T1016')
```

### Interactive Mode Selection

When run without mode-specific parameters, MAGNETO presents an interactive menu:

```
Select attack mode:
 (R)andomize techniques
 (C)hain attack simulation (follows attack lifecycle)
```

- **Random Mode**: Selects techniques randomly up to TechniqueCount
- **Chain Mode**: Follows realistic attack progression through tactics

---

## Execution Modes

### 1. Random Mode
**Description**: Randomly selects and executes techniques from the filtered pool.

**Use Cases**:
- General UEBA validation
- Baseline noise generation
- Quick detection tests

**Example**:
```powershell
.\MAGNETO.ps1 -TechniqueCount 10
```

### 2. Chain Mode
**Description**: Executes techniques in attack lifecycle order, simulating realistic breach progression.

**Attack Lifecycle**:
1. Discovery
2. Execution
3. Persistence
4. Privilege Escalation
5. Defense Evasion
6. Credential Access
7. Lateral Movement
8. Command and Control
9. Exfiltration

**Example**:
```powershell
# Interactive selection of Chain mode
.\MAGNETO.ps1
# Then select 'C' when prompted
```

### 3. RunAll Mode
**Description**: Executes all available techniques in the framework.

**Considerations**:
- Generates significant log volume
- Requires extended execution time
- Comprehensive coverage testing

**Example**:
```powershell
.\MAGNETO.ps1 -RunAll -DelayBetweenTechniques 3
```

### 4. Tactic-Specific Mode
**Description**: Executes all techniques within specified tactics.

**Example**:
```powershell
# All Discovery and Execution techniques
.\MAGNETO.ps1 -IncludeTactics @('Discovery', 'Execution') -RunAllForTactics
```

---

## Parameter Reference

### Core Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-TechniqueCount` | Int | 10 | Number of techniques to execute (Random mode) |
| `-RandomSeed` | Int | DayOfYear | Seed for randomization engine |
| `-Cleanup` | Switch | False | Enable post-execution cleanup |
| `-DelayBetweenTechniques` | Int | 2 | Seconds between technique execution |

### Filtering Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-IncludeTechniques` | String[] | Whitelist specific technique IDs |
| `-ExcludeTechniques` | String[] | Blacklist specific technique IDs |
| `-IncludeTactics` | String[] | Whitelist specific tactics |
| `-ExcludeTactics` | String[] | Blacklist specific tactics |

### Execution Control

| Parameter | Type | Description |
|-----------|------|-------------|
| `-RunAll` | Switch | Execute all available techniques |
| `-RunAllForTactics` | Switch | Execute all techniques in selected tactics |

### Information Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-ListTechniques` | Switch | Display all available techniques |
| `-ListTactics` | Switch | Display all available tactics |
| `-CheckForUpdates` | Switch | Check for framework updates |
| `-Help` | Switch | Display comprehensive help |

### Parameter Precedence

1. `-IncludeTechniques` (highest priority)
2. `-RunAll`
3. `-IncludeTactics` with `-RunAllForTactics`
4. `-IncludeTactics` without `-RunAllForTactics`
5. `-ExcludeTactics`/`-ExcludeTechniques`
6. Interactive mode selection (lowest priority)

---

## MITRE ATT&CK Coverage

### Tactics Distribution

| Tactic | Technique Count | Requirements |
|--------|----------------|--------------|
| Discovery | 6 | None |
| Execution | 4 | None |
| Persistence | 4 | Admin (3), Domain (0) |
| Privilege Escalation | 2 | None |
| Defense Evasion | 5 | Admin (1) |
| Credential Access | 3 | Admin (1), Domain (1) |
| Lateral Movement | 1 | None |
| Command and Control | 1 | None |
| Exfiltration | 1 | None |

### Key Techniques Implemented

#### High-Priority Detections
- **T1003.003**: OS Credential Dumping (NTDS)
- **T1136.001**: Create Account (Local)
- **T1543.003**: Create or Modify System Process
- **T1562.001**: Impair Defenses

#### Common Attack Patterns
- **T1046**: Network Service Discovery
- **T1059.001**: PowerShell Execution
- **T1087.001**: Account Discovery
- **T1033**: System Owner/User Discovery

### Detection Rationale

Each technique includes:
- **WhyTrack**: UEBA detection importance
- **RealWorldUsage**: Threat actor examples
- **Expected Alerts**: Anticipated SIEM responses

---

## Best Practices

### 1. Pre-Execution Checklist
- [ ] Verify test environment isolation
- [ ] Confirm SIEM/UEBA connectivity
- [ ] Document baseline metrics
- [ ] Notify SOC team of testing
- [ ] Enable audit logging

### 2. Execution Guidelines

#### For POC Environments
```powershell
# Start with limited scope
.\MAGNETO.ps1 -TechniqueCount 3 -Cleanup

# Gradually increase complexity
.\MAGNETO.ps1 -IncludeTactics @('Discovery') -RunAllForTactics

# Full validation
.\MAGNETO.ps1 -RunAll -Cleanup
```

#### For Production Testing
```powershell
# Use specific techniques only
.\MAGNETO.ps1 -IncludeTechniques @('T1046', 'T1087.001') -Cleanup

# Always enable cleanup
.\MAGNETO.ps1 -TechniqueCount 5 -Cleanup -DelayBetweenTechniques 10
```

### 3. Post-Execution Validation

1. **Review Generated Logs**
   - Check `MAGNETO_AttackLog_[timestamp].txt`
   - Verify technique execution status
   - Document any failures

2. **SIEM/UEBA Validation**
   - Confirm alert generation
   - Verify detection accuracy
   - Check correlation rules

3. **Cleanup Verification**
   - Review cleanup report
   - Manually verify artifact removal
   - Check for residual changes

### 4. Scheduling Recommendations

#### Daily Testing
```powershell
# Scheduled task for daily variance
schtasks /create /tn "MAGNETO_Daily" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Tools\MAGNETO.ps1 -TechniqueCount 5 -Cleanup" /sc daily /st 02:00
```

#### Weekly Comprehensive
```powershell
# Weekly full spectrum test
.\MAGNETO.ps1 -IncludeTactics @('Discovery', 'Execution', 'Persistence') -RunAllForTactics -Cleanup
```

---

## Security Considerations

### Risk Assessment

| Risk Level | Description | Mitigation |
|------------|-------------|------------|
| **Low** | Temporary file creation | Automatic cleanup |
| **Medium** | Registry modifications | Cleanup procedures |
| **Medium** | Service creation | Admin-only, reversible |
| **High** | User account creation | Requires admin, tracked |

### Safety Mechanisms

1. **Non-Destructive Operations**
   - No actual malware deployment
   - No data exfiltration
   - No system compromise

2. **Controlled Execution**
   - Validation prerequisites
   - Admin requirement flags
   - Domain membership checks

3. **Audit Trail**
   - Comprehensive logging
   - Windows Event Log entries
   - Cleanup reporting

### Compliance Considerations

- **Authorization Required**: Obtain written approval before production use
- **Change Management**: Follow organizational change procedures
- **Documentation**: Maintain execution records for audit purposes
- **Scope Limitation**: Test only on authorized systems

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Execution Policy Restrictions
**Problem**: Script blocked by execution policy

**Solution**:
```powershell
# Option 1: Bypass for single execution
powershell.exe -ExecutionPolicy Bypass -File "MAGNETO.ps1"

# Option 2: Set policy for user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### 2. Administrator Privilege Requirements
**Problem**: Techniques skipped due to insufficient privileges

**Solution**:
```powershell
# Run PowerShell as Administrator
Start-Process powershell -Verb RunAs

# Then execute MAGNETO
.\MAGNETO.ps1 -Cleanup
```

#### 3. Domain-Joined Requirements
**Problem**: Domain-specific techniques failing

**Solution**:
- Run on domain-joined systems only
- Or exclude domain techniques:
```powershell
.\MAGNETO.ps1 -ExcludeTechniques @('T1003.003')
```

#### 4. Cleanup Failures
**Problem**: Artifacts not properly removed

**Solution**:
```powershell
# Manual cleanup for specific artifacts
# Services
Get-Service -Name "StealthSvc_*" | Stop-Service -Force
Get-Service -Name "StealthSvc_*" | ForEach-Object { sc.exe delete $_.Name }

# Registry keys
Remove-Item "HKCU:\Software\SimKey_*" -Force -Recurse

# Files
Remove-Item "C:\Temp\sim_*" -Force
```

### Performance Optimization

#### For Large-Scale Testing
```powershell
# Optimize for performance
$PSDefaultParameterValues = @{
    'MAGNETO.ps1:DelayBetweenTechniques' = 1
}

# Run with minimal delays
.\MAGNETO.ps1 -RunAll -DelayBetweenTechniques 1
```

#### For Resource-Constrained Systems
```powershell
# Limit concurrent operations
.\MAGNETO.ps1 -TechniqueCount 3 -DelayBetweenTechniques 5
```

### Debugging Options

#### Verbose Execution
```powershell
# Enable verbose output
$VerbosePreference = "Continue"
.\MAGNETO.ps1 -TechniqueCount 5
```

#### Technique Testing
```powershell
# Test individual techniques
.\MAGNETO.ps1 -IncludeTechniques @('T1046') -Cleanup
```

---

## Appendix

### A. Technique Quick Reference

| ID | Name | Tactic | Admin | Domain |
|----|------|--------|-------|--------|
| T1046 | Network Service Discovery | Discovery | No | No |
| T1087.001 | Account Discovery: Local | Discovery | No | No |
| T1059.001 | PowerShell Execution | Execution | No | No |
| T1543.003 | Windows Service Creation | Persistence | Yes | No |
| T1562.001 | Defender Exclusion Modification | Defense Evasion | Yes | No |
| T1070.004 | File Deletion | Defense Evasion | No | No |
| T1003.003 | OS Credential Dumping: NTDS | Credential Access | Yes | Yes |
| T1049 | System Network Connections | Discovery | No | No |
| T1016 | Network Configuration Discovery | Discovery | No | No |
| T1033 | System Owner/User Discovery | Discovery | No | No |
| T1053.005 | Scheduled Task | Persistence | Yes | No |
| T1574.002 | DLL Side-Loading | Execution | No | No |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | No | No |
| T1550.002 | Pass the Hash | Credential Access | No | No |
| T1112 | Modify Registry | Defense Evasion | No | No |
| T1136.001 | Create Local Account | Persistence | Yes | No |
| T1027 | Obfuscated Files/Information | Defense Evasion | No | No |
| T1548.002 | UAC Bypass | Privilege Escalation | No | No |
| T1134.001 | Token Impersonation | Privilege Escalation | No | No |
| T1547.010 | Port Monitors | Persistence | Yes | No |
| T1557.001 | LLMNR/NBT-NS Poisoning | Credential Access | No | No |
| T1202 | Indirect Command Execution | Execution | No | No |
| T1105 | Ingress Tool Transfer | Command and Control | No | No |
| T1218.011 | Rundll32 Proxy Execution | Defense Evasion | No | No |
| T1041 | Exfiltration Over C2 | Exfiltration | No | No |

### B. Event Log Correlation

#### Key Windows Event IDs Generated

| Event ID | Description | Technique Examples |
|----------|-------------|-------------------|
| 4624 | Account Logon | T1136.001 |
| 4720 | User Account Created | T1136.001 |
| 4697 | Service Installed | T1543.003 |
| 4698 | Scheduled Task Created | T1053.005 |
| 4688 | Process Creation | T1059.001, T1202 |
| 5140 | Network Share Access | T1021.002 |
| 4657 | Registry Value Modified | T1112 |

### C. Integration Examples

#### Exabeam Integration
```powershell
# Generate specific anomalies for Exabeam
.\MAGNETO.ps1 -IncludeTechniques @('T1087.001', 'T1046', 'T1033') -Cleanup

# Expected Exabeam Notable Events:
# - Abnormal Account Enumeration
# - Suspicious Network Discovery
# - Unusual Process Execution Patterns
```

### D. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.3 | Sep 16, 2025 | Added tactic filtering, RunAllForTactics mode |
| 1.2 | Sep 15, 2025 | Enhanced cleanup, added ListTechniques |
| 1.1 | Sep 14, 2025 | Initial release with 25 techniques |

### E. References

1. **MITRE ATT&CK Framework**
   - https://attack.mitre.org/

2. **Exabeam UEBA Documentation**
   - https://docs.exabeam.com/

3. **Windows Security Auditing**
   - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/

4. **LOLBins Project**
   - https://lolbas-project.github.io/

---

## Support and Contact

**GitHub Repository**: https://github.com/syedcode1/magneto_v2  
**Documentation**: https://github.com/syedcode1/magneto/blob/main/README.md  
**Author**: Syed Hasan Rizvi  

### License
This tool is provided for legitimate security testing purposes only. Use of this tool must comply with all applicable laws and regulations. The author assumes no liability for misuse or damage caused by this tool.

### Disclaimer
MAGNETO is designed for authorized security testing in controlled environments only. Never use this tool on systems you do not own or have explicit permission to test. Always follow responsible disclosure practices and organizational security policies.

---

*End of Documentation - Version 2*
