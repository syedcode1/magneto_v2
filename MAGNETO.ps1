<#
.SYNOPSIS
    MAGNETO - Exabeam Stealth Attack Simulator - Elite Hacker Edition
    Simulate real-world MITRE-aligned attacks using native Windows LOLBins.
    Designed for Exabeam UEBA PoC and Demo Labs to trigger anomaly detections.

.DESCRIPTION
    This PowerShell tool automates stealthy cyberattack simulations on Windows servers.
    It follows the MITRE ATT&CK framework, emphasizing hard-to-detect techniques that blend into normal activity.
    Attacks are randomized daily to evade ML-based learning in UEBA systems:
    - Random MITRE techniques selected from Recon, Initial Access, Execution, Persistence, etc.
    - Randomized usernames, IPs, and tactics for each run.
    - Uses only native Windows binaries for evasion (LOLBins).
    - Generates anomalous event logs for UEBA/SIEM alerting without actual compromise.
    - Hacker vibe: Dark terminal aesthetics, progress indicators, and dramatic outputs.
    - Modes: Random techniques or Chain attack simulation following hacker lifecycle.

    WARNING: Run ONLY in controlled demo environments. May modify system (e.g., temp users/services). Use -Cleanup to revert changes.

.PARAMETER RandomSeed
    Optional seed for randomization (defaults to current day for daily variance).

.PARAMETER TechniqueCount
    Number of random techniques to execute in Random mode (default: 5). Ignored in Chain mode.

.PARAMETER Cleanup
    Switch to clean up artifacts after simulation (recommended for demos).

.PARAMETER ExcludeTactics
    Array of tactics to exclude from simulation (e.g., @('Exfiltration', 'Impact'))
    When used with -RunAllForTactics, excludes these tactics entirely.

.PARAMETER IncludeTactics
    Array of tactics to specifically include. When specified with -RunAllForTactics, runs ALL techniques from these tactics.
    Takes precedence over ExcludeTactics. (e.g., @('Discovery', 'Execution', 'Persistence'))

.PARAMETER ExcludeTechniques
    Array of technique IDs to exclude from simulation (e.g., @('T1003.003', 'T1136.001'))

.PARAMETER IncludeTechniques
    Array of technique IDs to specifically include. When specified, ONLY these techniques will run.
    Takes precedence over ExcludeTechniques and tactic filters. (e.g., @('T1046', 'T1087.001', 'T1059.001'))

.PARAMETER RunAll
    Switch to run ALL available techniques (ignoring TechniqueCount). Use with caution!

.PARAMETER RunAllForTactics
    Switch to run ALL techniques for selected/included tactics instead of random selection.

.PARAMETER DelayBetweenTechniques
    Delay in seconds between technique executions (default: 2). Helps avoid overwhelming SIEM.

.PARAMETER CheckForUpdates
    Check for script updates from configured update source.

.PARAMETER ListTechniques
    List all available techniques with their IDs and tactics. Useful for selecting techniques to include/exclude.

.PARAMETER ListTactics
    List all available tactics and the count of techniques in each.

.PARAMETER Help
    Display comprehensive help information about all parameters and usage examples.

.EXAMPLE
    .\MAGNETO.ps1 --Help
    Display detailed help information.

.EXAMPLE
    .\MAGNETO.ps1 -TechniqueCount 7 -Cleanup
    Runs 7 random techniques with cleanup.

.EXAMPLE
    .\MAGNETO.ps1 -ExcludeTactics @('Exfiltration') -DelayBetweenTechniques 5
    Runs simulation excluding exfiltration tactics with 5-second delays.

.EXAMPLE
    .\MAGNETO.ps1 -IncludeTechniques @('T1046', 'T1087.001', 'T1059.001') -Cleanup
    Runs ONLY the specified techniques with cleanup.

.EXAMPLE
    .\MAGNETO.ps1 -RunAll -DelayBetweenTechniques 3
    Runs ALL available techniques with 3-second delays between each.

.EXAMPLE
    .\MAGNETO.ps1 -IncludeTactics @('Discovery', 'Execution') -RunAllForTactics
    Runs ALL techniques from Discovery and Execution tactics.

.EXAMPLE
    .\MAGNETO.ps1 -ExcludeTactics @('Exfiltration', 'Impact') -RunAllForTactics
    Runs ALL techniques except those in Exfiltration and Impact tactics.

.EXAMPLE
    .\MAGNETO.ps1 -ListTactics
    Lists all available tactics and their technique counts.

.NOTES
    Author: Syed Hasan Rizvi
    Version: 1.1
    Date: September 15, 2025
    MITRE Mapping: Techniques align with ATT&CK Enterprise Matrix.
    Stealth Focus: Anomalous behaviors like unusual command chains, rare binary usage, odd timings.
    Randomization: Ensures UEBA doesn't baseline malicious as normal over time.
#>

param (
    [int]$RandomSeed = (Get-Date).DayOfYear,  # Daily randomization
    [int]$TechniqueCount = 15,
    [switch]$Cleanup,
    [string[]]$ExcludeTactics = @(),
    [string[]]$IncludeTactics = @(),  # New parameter for tactic inclusion
    [string[]]$ExcludeTechniques = @(),
    [string[]]$IncludeTechniques = @(),  # Parameter for technique inclusion
    [switch]$RunAll,  # Run all techniques
    [switch]$RunAllForTactics,  # New switch to run all techniques in selected tactics
    [int]$DelayBetweenTechniques = 2,
    [switch]$CheckForUpdates,
    [switch]$ListTechniques,  # List available techniques
    [switch]$ListTactics,  # New parameter to list available tactics
    [switch]$Help  # New parameter to show help
)

# Script Version Info
$scriptVersion = "1.3"  # Updated version for tactic features
$scriptDate = "September 16, 2025"
$updateCheckUrl = "https://github.com/syedcode1/magneto_v2/blob/main/MAGNETO.ps1"  # Replace with actual URL

# Check for help using various common formats
if ($Help -or $PSBoundParameters.ContainsKey('?') -or 
    ($args -contains '--help') -or ($args -contains '-h') -or 
    ($args -contains '/?') -or ($args -contains '-?')) {
    
    # Clear any previous output for clean display
    Clear-Host
    
    Write-Host @"

MAGNETO - Exabeam Stealth Attack Simulator v$scriptVersion
========================================================
Simulate real-world MITRE ATT&CK techniques using native Windows LOLBins.
Designed for Exabeam UEBA PoC and Demo Labs to trigger anomaly detections.

USAGE:
    .\MAGNETO.ps1 [parameters]
    .\MAGNETO.ps1 --help
    .\MAGNETO.ps1 -Help

EXECUTION MODES:
    Default         : Interactive mode selection (Random or Chain)
    -RunAll         : Run ALL available techniques
    -RunAllForTactics : Run ALL techniques in selected/filtered tactics
    
FILTERING PARAMETERS:
    -IncludeTechniques @('T1046','T1087.001')
        Run ONLY specified technique IDs (highest priority)
        
    -ExcludeTechniques @('T1003.003','T1136.001')
        Exclude specific technique IDs from execution
        
    -IncludeTactics @('Discovery','Execution')
        Include only techniques from specified tactics
        
    -ExcludeTactics @('Exfiltration','Impact')
        Exclude all techniques from specified tactics
        
    -TechniqueCount <int> (default: 7)
        Number of random techniques to execute (Random mode only)

EXECUTION CONTROL:
    -DelayBetweenTechniques <int> (default: 2)
        Seconds to wait between technique executions
        
    -RandomSeed <int> (default: DayOfYear)
        Seed for randomization (for reproducible runs)
        
    -Cleanup
        Clean up artifacts after simulation (recommended)

INFORMATION PARAMETERS:
    -ListTechniques
        Display all available techniques grouped by tactic
        
    -ListTactics
        Display all available tactics with technique counts
        
    -CheckForUpdates
        Check for script updates before running
        
    -Help, --help, -h
        Display this help message

EXAMPLES:
    # Run 7 random techniques with cleanup
    .\MAGNETO.ps1 -TechniqueCount 7 -Cleanup
    
    # Run specific techniques only
    .\MAGNETO.ps1 -IncludeTechniques @('T1046','T1087.001','T1059.001')
    
    # Run all Discovery techniques
    .\MAGNETO.ps1 -IncludeTactics @('Discovery') -RunAllForTactics
    
    # Exclude dangerous tactics
    .\MAGNETO.ps1 -ExcludeTactics @('Credential Access','Exfiltration')
    
    # Run all techniques except specific ones
    .\MAGNETO.ps1 -RunAll -ExcludeTechniques @('T1003.003','T1136.001')
    
    # Chain mode with all techniques per tactic
    .\MAGNETO.ps1 -RunAllForTactics
    (Then select Chain mode when prompted)
    
    # List available options
    .\MAGNETO.ps1 -ListTactics
    .\MAGNETO.ps1 -ListTechniques
    
    # Run 5 random techniques from specific tactics
    .\MAGNETO.ps1 -IncludeTactics @('Discovery','Execution') -TechniqueCount 5
    
    # Run with custom delay and specific seed
    .\MAGNETO.ps1 -DelayBetweenTechniques 5 -RandomSeed 42

MODES EXPLAINED:
    Random Mode (R):
        Randomly selects techniques up to TechniqueCount
        Respects tactic/technique filters
        Default for most parameter combinations
        
    Chain Mode (C):
        Executes techniques in attack lifecycle order
        Default: One technique per tactic
        With -RunAllForTactics: All techniques per tactic
        Follows realistic attack progression

PRECEDENCE ORDER:
    1. -IncludeTechniques (highest priority)
    2. -RunAll
    3. -IncludeTactics with -RunAllForTactics
    4. -IncludeTactics without -RunAllForTactics
    5. -ExcludeTactics/-ExcludeTechniques
    6. Interactive mode selection (lowest priority)

FILTER COMBINATIONS:
    Include + Exclude:
        -IncludeTechniques overrides all other filters
        -IncludeTactics overrides -ExcludeTactics
        Warnings displayed for overridden parameters
    
    RunAll + Filters:
        -RunAll cannot be combined with Include/Exclude
        Use -RunAllForTactics for filtered "all" execution

SPECIAL REQUIREMENTS:
    [ADMIN]  - Technique requires Administrator privileges
    [DOMAIN] - Technique requires domain-joined system
    
    Use -ListTechniques to see which techniques have requirements

WARNINGS:
    ⚠ Run ONLY in controlled demo environments
    ⚠ Some techniques require Administrator privileges
    ⚠ Some techniques require domain-joined systems
    ⚠ May modify system (creates temp users/services)
    ⚠ Always use -Cleanup in production demos
    ⚠ Techniques >15 will prompt for confirmation

LOGGING:
    - Generates detailed log file: MAGNETO_AttackLog_[timestamp].txt
    - Includes MITRE ATT&CK mapping for each technique
    - Documents why each technique triggers UEBA alerts
    - Shows real-world usage examples

AUTHOR: Syed Hasan Rizvi
VERSION: $scriptVersion
DATE: $scriptDate
MITRE: Aligned with ATT&CK Enterprise Matrix

For more information or updates:
    GitHub: https://github.com/syedcode1/magneto
    Docs: https://github.com/syedcode1/magneto/blob/main/README.md

"@ -ForegroundColor Cyan
    
    Write-Host "TIP: Use '.\MAGNETO.ps1 -ListTactics' to see available tactics" -ForegroundColor Yellow
    Write-Host "TIP: Use '.\MAGNETO.ps1 -ListTechniques' to see all techniques" -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

# Parameter validation
if ($RunAll -and $IncludeTechniques.Count -gt 0) {
    Write-Host "ERROR: Cannot use -RunAll and -IncludeTechniques together. Choose one." -ForegroundColor Red
    exit 1
}

if ($RunAll -and $IncludeTactics.Count -gt 0) {
    Write-Host "ERROR: Cannot use -RunAll and -IncludeTactics together. RunAll means ALL techniques." -ForegroundColor Red
    exit 1
}

if ($RunAll -and ($ExcludeTactics.Count -gt 0 -or $ExcludeTechniques.Count -gt 0)) {
    Write-Host "ERROR: Cannot use -RunAll with exclusion parameters. RunAll means ALL techniques." -ForegroundColor Red
    exit 1
}

if ($IncludeTechniques.Count -gt 0 -and $IncludeTactics.Count -gt 0) {
    Write-Host "WARNING: -IncludeTechniques takes precedence over -IncludeTactics. Tactic filter will be ignored." -ForegroundColor Yellow
}

if ($IncludeTactics.Count -gt 0 -and $ExcludeTactics.Count -gt 0) {
    Write-Host "WARNING: -IncludeTactics takes precedence over -ExcludeTactics. Exclusion will be ignored." -ForegroundColor Yellow
}

if ($IncludeTechniques.Count -gt 0 -and ($ExcludeTactics.Count -gt 0 -or $ExcludeTechniques.Count -gt 0)) {
    Write-Host "WARNING: -IncludeTechniques takes precedence. All exclusion parameters will be ignored." -ForegroundColor Yellow
}

# Version Checking Function
function Check-ForUpdates {
    param([string]$CurrentVersion)
    
    Write-Host "Checking for updates..." -ForegroundColor Cyan
    try {
        # In production, this would check against a real endpoint
        # For demo purposes, we'll simulate the check
        $latestVersion = "1.1"  # This would be fetched from $updateCheckUrl
        
        if ([version]$latestVersion -gt [version]$CurrentVersion) {
            Write-Host "New version available: $latestVersion (Current: $CurrentVersion)" -ForegroundColor Yellow
            Write-Host "Download from: https://example.com/magneto/download" -ForegroundColor Yellow
            $response = Read-Host "Continue with current version? (Y/N)"
            if ($response -ne 'Y' -and $response -ne 'y') {
                exit 0
            }
        } else {
            Write-Host "You are running the latest version ($CurrentVersion)" -ForegroundColor Green
        }
    } catch {
        Write-Host "Could not check for updates. Continuing with current version." -ForegroundColor Yellow
    }
    Start-Sleep -Seconds 2
}

# Check for updates if requested
if ($CheckForUpdates) {
    Check-ForUpdates -CurrentVersion $scriptVersion
}

# Seed random for reproducibility per day
$random = New-Object System.Random($RandomSeed)

# Initialize tracking arrays
$global:logCommands = @()
$global:cleanupReport = New-Object System.Collections.ArrayList
$global:executionResults = New-Object System.Collections.ArrayList
$global:actuallyExecutedTechniqueIDs = New-Object System.Collections.ArrayList

# Helper Functions
function Log-AttackStep {
    param ([string]$Message, [string]$MITREID)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [$MITREID] $Message" -ForegroundColor Yellow
    $global:logCommands += "[$(Get-Date -Format 'HH:mm:ss')] [$MITREID] $Message"
    Start-Sleep -Milliseconds (500 + $random.Next(1500))  # Random delays for realism
}

function Show-BlinkEffect {
    param ([string]$Message = "EXECUTED.")
    for ($i = 0; $i -lt 3; $i++) {
        Write-Host $Message -ForegroundColor Red -NoNewline
        Start-Sleep -Milliseconds 200
        Write-Host "`r" -NoNewline
        Write-Host " " * $Message.Length -NoNewline
        Write-Host "`r" -NoNewline
        Start-Sleep -Milliseconds 200
    }
    Write-Host $Message -ForegroundColor Red
    Start-Sleep -Seconds (1 + $random.Next(2))  # Dramatic pause after blinking
}

function Generate-RandomUser {
    $adjectives = @("Shadow", "Ghost", "Phantom", "Rogue", "Ninja", "Cipher", "Viper", "Hawk", "Raven", "Wolf")
    $nouns = @("Hacker", "Intruder", "Agent", "Spy", "Operative", "Ghost", "Phantom", "Shadow", "Rogue", "Ninja")
    $user = "$($adjectives[$random.Next($adjectives.Count)])_$($nouns[$random.Next($nouns.Count)])_$($random.Next(1000))"
    return $user
}

function Generate-RandomIP {
    $ip = "$($random.Next(1,256)).$($random.Next(256)).$($random.Next(256)).$($random.Next(256))"
    return $ip
}

# Validation Functions for Specific Techniques
function Test-DomainJoined {
    return ($env:USERDOMAIN -ne $env:COMPUTERNAME)
}

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ServiceExists {
    param([string]$ServiceName)
    return (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -ne $null
}

# Ensure Temp directory exists
if (!(Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null }

# MITRE-Aligned Techniques Pool (Stealthy, LOLBin-focused, Anomalous)
$techniques = @(
    @{
        ID = 'T1046'
        Name = 'Network Service Discovery'
        Tactic = 'Discovery'
        ValidationRequired = $null
        Action = { try { netstat -ano | Out-Null; Log-AttackStep "Command: netstat -ano" "T1046"; $null = $global:executionResults.Add(@{ID="T1046"; Success=$true}) } catch { $null = $global:executionResults.Add(@{ID="T1046"; Success=$false; Error=$_.Exception.Message}) } }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Generates unusual network scanning patterns, detectable as reconnaissance by UEBA."
            RealWorldUsage = "Hackers use netstat to map open ports/services, often in initial network recon (e.g., APT28 scans for vulnerabilities)."
        }
    },
    @{
        ID = 'T1087.001'
        Name = 'Account Discovery: Local Account'
        Tactic = 'Discovery'
        ValidationRequired = $null
        Action = { try { net user | Out-Null; Log-AttackStep "Command: net user" "T1087.001"; $null = $global:executionResults.Add(@{ID="T1087.001"; Success=$true}) } catch { $null = $global:executionResults.Add(@{ID="T1087.001"; Success=$false; Error=$_.Exception.Message}) } }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Enumerating local accounts can indicate attacker intent to identify targets for privilege escalation."
            RealWorldUsage = "Used in ransomware (e.g., Ryuk) to find admin accounts for lateral movement."
        }
    },
    @{
        ID = 'T1059.001'
        Name = 'Command and Scripting Interpreter: PowerShell'
        Tactic = 'Execution'
        ValidationRequired = $null
        Action = { try { powershell.exe -Command "Get-Process" | Out-Null; Log-AttackStep "Command: powershell.exe -Command Get-Process" "T1059.001"; $null = $global:executionResults.Add(@{ID="T1059.001"; Success=$true}) } catch { $null = $global:executionResults.Add(@{ID="T1059.001"; Success=$false; Error=$_.Exception.Message}) } }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Unusual PowerShell execution patterns (e.g., nested calls) are common in fileless attacks, detectable by UEBA."
            RealWorldUsage = "PowerShell is used in fileless malware (e.g., Emotet) to execute payloads without disk artifacts."
        }
    },
    @{
        ID = 'T1543.003'
        Name = 'Create or Modify System Process: Windows Service'
        Tactic = 'Persistence'
        ValidationRequired = { Test-AdminPrivileges }
        Action = { 
            $svcName = "StealthSvc_$($random.Next(1000))"
            $script:svcName = $svcName  # Store for cleanup
            try { 
                sc.exe create $svcName binPath= "cmd.exe /c echo Simulated Service" | Out-Null
                Log-AttackStep "Command: sc.exe create $svcName binPath= cmd.exe /c echo Simulated Service" "T1543.003"
                $null = $global:executionResults.Add(@{ID="T1543.003"; Success=$true; ServiceName=$svcName})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1543.003"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = { 
            if ($script:svcName) {
                try { 
                    sc.exe delete $script:svcName | Out-Null
                    $null = $global:cleanupReport.Add(@{ID="T1543.003"; Status="Success"; Details="Removed service $script:svcName"})
                } catch { 
                    $null = $global:cleanupReport.Add(@{ID="T1543.003"; Status="Failed"; Error=$_.Exception.Message})
                }
            }
        }
        Description = @{
            WhyTrack = "Creating rogue services generates suspicious system changes, detectable as persistence attempts."
            RealWorldUsage = "Attackers (e.g., TrickBot) install malicious services to maintain access post-compromise."
        }
    },
    @{
        ID = 'T1562.001'
        Name = 'Impair Defenses: Modify Defender Exclusion'
        Tactic = 'Defense Evasion'
        ValidationRequired = { Test-AdminPrivileges }
        Action = { 
            $exclPath = "C:\Temp\sim_excl_$($random.Next(1000))"
            $script:exclPath = $exclPath  # Store for cleanup
            try { 
                New-Item -Path $exclPath -ItemType Directory -Force | Out-Null
                Set-MpPreference -ExclusionPath $exclPath -ErrorAction SilentlyContinue | Out-Null
                Log-AttackStep "Command: Set-MpPreference -ExclusionPath $exclPath" "T1562.001"
                $null = $global:executionResults.Add(@{ID="T1562.001"; Success=$true; ExclusionPath=$exclPath})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1562.001"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = { 
            if ($script:exclPath) {
                try { 
                    Remove-MpPreference -ExclusionPath $script:exclPath -ErrorAction SilentlyContinue | Out-Null
                    Remove-Item $script:exclPath -Force -ErrorAction SilentlyContinue | Out-Null
                    $null = $global:cleanupReport.Add(@{ID="T1562.001"; Status="Success"; Details="Removed exclusion $script:exclPath"})
                } catch { 
                    $null = $global:cleanupReport.Add(@{ID="T1562.001"; Status="Failed"; Error=$_.Exception.Message})
                }
            }
        }
        Description = @{
            WhyTrack = "Modifying Defender exclusions creates anomalous config changes, a subtle evasion tactic detectable by UEBA."
            RealWorldUsage = "Ransomware (e.g., Conti) adds exclusions to bypass AV scans for malicious payloads."
        }
    },
    @{
        ID = 'T1070.004'
        Name = 'Indicator Removal: File Deletion'
        Tactic = 'Defense Evasion'
        ValidationRequired = $null
        Action = { 
            $tempFile = "C:\Temp\sim_$($random.Next(1000)).txt"
            try { 
                New-Item $tempFile -ItemType File -Force | Out-Null
                Remove-Item $tempFile -Force | Out-Null
                Log-AttackStep "Command: New-Item $tempFile; Remove-Item $tempFile" "T1070.004"
                $null = $global:executionResults.Add(@{ID="T1070.004"; Success=$true})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1070.004"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Rapid file creation/deletion in temp directories can indicate cleanup to hide malicious activity."
            RealWorldUsage = "Malware (e.g., WannaCry) deletes temporary files to erase traces of execution."
        }
    },
    @{
        ID = 'T1003.003'
        Name = 'OS Credential Dumping: NTDS'
        Tactic = 'Credential Access'
        ValidationRequired = { Test-DomainJoined -and Test-AdminPrivileges }
        Action = { 
            try { 
                if (Get-Command ntdsutil.exe -ErrorAction SilentlyContinue) {
                    # Note: This simulates the command but doesn't actually dump NTDS
                    Log-AttackStep "Command: ntdsutil.exe ac i ntds ifm create full c:\temp q q (simulated)" "T1003.003"
                    $null = $global:executionResults.Add(@{ID="T1003.003"; Success=$true; Method="ntdsutil"})
                } else {
                    Get-ChildItem "C:\Windows\NTDS" -ErrorAction SilentlyContinue | Out-Null
                    Log-AttackStep "Command: Get-ChildItem C:\Windows\NTDS" "T1003.003"
                    $null = $global:executionResults.Add(@{ID="T1003.003"; Success=$true; Method="directory_enum"})
                }
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1003.003"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Attempts to access NTDS files signal credential theft, a high-priority alert for UEBA/SIEM."
            RealWorldUsage = "APT groups (e.g., APT29) use ntdsutil to dump Active Directory credentials for lateral movement."
        }
    },
    @{
        ID = 'T1049'
        Name = 'System Network Connections Discovery'
        Tactic = 'Discovery'
        ValidationRequired = $null
        Action = { try { ipconfig /displaydns | Out-Null; Log-AttackStep "Command: ipconfig /displaydns" "T1049"; $null = $global:executionResults.Add(@{ID="T1049"; Success=$true}) } catch { $null = $global:executionResults.Add(@{ID="T1049"; Success=$false; Error=$_.Exception.Message}) } }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Probing DNS cache can indicate network mapping, a precursor to lateral movement."
            RealWorldUsage = "Hackers (e.g., Cobalt Strike) use this to identify network connections for pivoting."
        }
    },
    @{
        ID = 'T1016'
        Name = 'System Network Configuration Discovery'
        Tactic = 'Discovery'
        ValidationRequired = $null
        Action = { try { route print | Out-Null; Log-AttackStep "Command: route print" "T1016"; $null = $global:executionResults.Add(@{ID="T1016"; Success=$true}) } catch { $null = $global:executionResults.Add(@{ID="T1016"; Success=$false; Error=$_.Exception.Message}) } }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Accessing routing tables can reveal network topology, detectable as recon activity."
            RealWorldUsage = "Used in initial recon by attackers (e.g., FIN7) to plan network traversal."
        }
    },
    @{
        ID = 'T1033'
        Name = 'System Owner/User Discovery'
        Tactic = 'Discovery'
        ValidationRequired = $null
        Action = { try { whoami /all | Out-Null; Log-AttackStep "Command: whoami /all" "T1033"; $null = $global:executionResults.Add(@{ID="T1033"; Success=$true}) } catch { $null = $global:executionResults.Add(@{ID="T1033"; Success=$false; Error=$_.Exception.Message}) } }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Enumerating user details can indicate attacker intent to identify privileged accounts."
            RealWorldUsage = "Common in ransomware (e.g., LockBit) to target admin users for escalation."
        }
    },
    @{
        ID = 'T1053.005'
        Name = 'Scheduled Task/Job: Scheduled Task'
        Tactic = 'Persistence'
        ValidationRequired = { Test-AdminPrivileges }
        Action = { 
            $taskName = "ShadowTask_$($random.Next(1000))"
            $script:taskName = $taskName  # Store for cleanup
            $futureTime = (Get-Date).AddMinutes(5).ToString("HH:mm")
            try { 
                schtasks /create /tn $taskName /tr "cmd.exe /c echo Simulated Task" /sc once /st $futureTime /f | Out-Null
                Log-AttackStep "Command: schtasks /create /tn $taskName /tr cmd.exe /c echo Simulated Task /sc once /st $futureTime" "T1053.005"
                $null = $global:executionResults.Add(@{ID="T1053.005"; Success=$true; TaskName=$taskName})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1053.005"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = { 
            if ($script:taskName) {
                try { 
                    schtasks /delete /tn $script:taskName /f | Out-Null
                    $null = $global:cleanupReport.Add(@{ID="T1053.005"; Status="Success"; Details="Removed task $script:taskName"})
                } catch { 
                    $null = $global:cleanupReport.Add(@{ID="T1053.005"; Status="Failed"; Error=$_.Exception.Message})
                }
            }
        }
        Description = @{
            WhyTrack = "Creating scheduled tasks for persistence generates suspicious system changes."
            RealWorldUsage = "Malware (e.g., Dridex) uses scheduled tasks to maintain access after reboots."
        }
    },
    @{
        ID = 'T1574.002'
        Name = 'Hijack Execution Flow: DLL Side-Loading'
        Tactic = 'Execution'
        ValidationRequired = $null
        Action = { try { rundll32.exe shell32.dll,Control_RunDLL | Out-Null; Log-AttackStep "Command: rundll32.exe shell32.dll,Control_RunDLL" "T1574.002"; $null = $global:executionResults.Add(@{ID="T1574.002"; Success=$true}) } catch { $null = $global:executionResults.Add(@{ID="T1574.002"; Success=$false; Error=$_.Exception.Message}) } }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Anomalous rundll32 calls can indicate DLL side-loading, a stealthy execution method."
            RealWorldUsage = "Used by APTs (e.g., APT41) to load malicious DLLs via trusted binaries."
        }
    },
    @{
        ID = 'T1021.002'
        Name = 'Remote Services: SMB/Windows Admin Shares'
        Tactic = 'Lateral Movement'
        ValidationRequired = $null
        Action = { 
            $script:randIP = Generate-RandomIP
            try { 
                net use \\$script:randIP\IPC$ /user:Guest guest 2>&1 | Out-Null
                Log-AttackStep "Command: net use \\$script:randIP\IPC$ /user:Guest guest" "T1021.002"
                $null = $global:executionResults.Add(@{ID="T1021.002"; Success=$true; TargetIP=$script:randIP})
            } catch { 
                Log-AttackStep "Failed SMB connection attempt to $script:randIP (expected, logs generated)" "T1021.002"
                $null = $global:executionResults.Add(@{ID="T1021.002"; Success=$false; Note="Expected failure - for log generation"})
            }
        }
        CleanupAction = { 
            if ($script:randIP) {
                try { 
                    $connection = net use | Select-String $script:randIP
                    if ($connection) { 
                        net use \\$script:randIP\IPC$ /delete 2>&1 | Out-Null
                        Log-AttackStep "Command: net use \\$script:randIP\IPC$ /delete" "T1021.002"
                        $null = $global:cleanupReport.Add(@{ID="T1021.002"; Status="Success"; Details="Removed connection to $script:randIP"})
                    }
                } catch { 
                    $null = $global:cleanupReport.Add(@{ID="T1021.002"; Status="N/A"; Details="No cleanup needed"})
                }
            }
        }
        Description = @{
            WhyTrack = "SMB connection attempts to random IPs signal lateral movement, a key UEBA alert."
            RealWorldUsage = "Used in ransomware (e.g., Ryuk) to move laterally via admin shares."
        }
    },
    @{
        ID = 'T1550.002'
        Name = 'Use Alternate Authentication Material: Pass the Hash'
        Tactic = 'Credential Access'
        ValidationRequired = $null
        Action = { 
            try { 
                if (Get-Command wmic.exe -ErrorAction SilentlyContinue) {
                    wmic /node:localhost process call create "cmd.exe /c echo PtH Sim" 2>&1 | Out-Null
                    Log-AttackStep "Command: wmic /node:localhost process call create cmd.exe /c echo PtH Sim" "T1550.002"
                    $null = $global:executionResults.Add(@{ID="T1550.002"; Success=$true; Method="wmic"})
                } else {
                    Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c echo PtH Sim"} | Out-Null
                    Log-AttackStep "Command: Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=cmd.exe /c echo PtH Sim}" "T1550.002"
                    $null = $global:executionResults.Add(@{ID="T1550.002"; Success=$true; Method="CIM"})
                }
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1550.002"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Unusual WMIC/CIM calls to spawn processes can indicate pass-the-hash attempts."
            RealWorldUsage = "Used by APTs (e.g., APT29) to authenticate with stolen hashes for lateral movement."
        }
    },
    @{
        ID = 'T1112'
        Name = 'Modify Registry'
        Tactic = 'Defense Evasion'
        ValidationRequired = $null
        Action = { 
            $key = "HKCU:\Software\SimKey_$($random.Next(1000))"
            $script:regKey = $key  # Store for cleanup
            try { 
                New-Item $key -Force | Out-Null
                Set-ItemProperty $key -Name "Value" -Value "SimData"
                Log-AttackStep "Command: New-Item $key; Set-ItemProperty $key -Name Value -Value SimData" "T1112"
                $null = $global:executionResults.Add(@{ID="T1112"; Success=$true; RegistryKey=$key})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1112"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = { 
            if ($script:regKey) {
                try { 
                    Remove-Item $script:regKey -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
                    $null = $global:cleanupReport.Add(@{ID="T1112"; Status="Success"; Details="Removed registry key $script:regKey"})
                } catch { 
                    $null = $global:cleanupReport.Add(@{ID="T1112"; Status="Failed"; Error=$_.Exception.Message})
                }
            }
        }
        Description = @{
            WhyTrack = "Registry modifications in unusual keys can signal persistence or evasion attempts."
            RealWorldUsage = "Malware (e.g., REvil) modifies registry for persistence or to disable security features."
        }
    },
    @{
        ID = 'T1136.001'
        Name = 'Create Account: Local Account'
        Tactic = 'Persistence'
        ValidationRequired = { Test-AdminPrivileges }
        Action = { 
            $randUser = Generate-RandomUser
            $script:createdUser = $randUser  # Store for cleanup
            $pass = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
            try { 
                New-LocalUser -Name $randUser -Password $pass -NoPasswordExpiration -ErrorAction Stop | Out-Null
                net localgroup "Administrators" $randUser /add | Out-Null
                Log-AttackStep "Command: New-LocalUser -Name $randUser -Password [REDACTED] -NoPasswordExpiration; net localgroup Administrators $randUser /add" "T1136.001"
                $null = $global:executionResults.Add(@{ID="T1136.001"; Success=$true; Username=$randUser})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1136.001"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = { 
            if ($script:createdUser) {
                try { 
                    Remove-LocalUser -Name $script:createdUser -ErrorAction SilentlyContinue | Out-Null
                    $null = $global:cleanupReport.Add(@{ID="T1136.001"; Status="Success"; Details="Removed user $script:createdUser"})
                } catch { 
                    $null = $global:cleanupReport.Add(@{ID="T1136.001"; Status="Failed"; Error=$_.Exception.Message})
                }
            }
        }
        Description = @{
            WhyTrack = "Creating new admin accounts is a strong indicator of persistence, easily detected by UEBA."
            RealWorldUsage = "Ransomware (e.g., LockBit) creates backdoor accounts for repeated access."
        }
    },
    @{
        ID = 'T1027'
        Name = 'Obfuscated Files or Information: Base64 Command Execution'
        Tactic = 'Defense Evasion'
        ValidationRequired = $null
        Action = { 
            $commands = @("Get-Date", "whoami", "net user", "ipconfig")
            $randCommand = $commands[$random.Next($commands.Count)]
            $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($randCommand))
            $tempScript = "C:\Temp\sim_script_$($random.Next(1000)).ps1"
            $script:tempScript = $tempScript  # Store for cleanup
            try { 
                "powershell -EncodedCommand $encodedCommand" | Out-File $tempScript -Encoding ASCII
                powershell -File $tempScript | Out-Null
                Log-AttackStep "Command: powershell -EncodedCommand $encodedCommand (decoded: $randCommand)" "T1027"
                $null = $global:executionResults.Add(@{ID="T1027"; Success=$true; DecodedCommand=$randCommand})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1027"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = { 
            try { 
                Remove-Item "C:\Temp\sim_script_*.ps1" -Force -ErrorAction SilentlyContinue | Out-Null
                $null = $global:cleanupReport.Add(@{ID="T1027"; Status="Success"; Details="Removed obfuscated scripts"})
            } catch { 
                $null = $global:cleanupReport.Add(@{ID="T1027"; Status="Failed"; Error=$_.Exception.Message})
            }
        }
        Description = @{
            WhyTrack = "Base64-encoded commands in PowerShell logs indicate obfuscation, a common evasion tactic."
            RealWorldUsage = "Used in fileless attacks (e.g., Emotet) to hide malicious commands from AV."
        }
    },
    @{
        ID = 'T1548.002'
        Name = 'Abuse Elevation Control Mechanism: Bypass User Account Control'
        Tactic = 'Privilege Escalation'
        ValidationRequired = $null
        Action = { try { cmd /c fodhelper.exe | Out-Null; Log-AttackStep "Command: cmd /c fodhelper.exe" "T1548.002"; $null = $global:executionResults.Add(@{ID="T1548.002"; Success=$true}) } catch { $null = $global:executionResults.Add(@{ID="T1548.002"; Success=$false; Error=$_.Exception.Message}) } }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Fodhelper.exe usage without UAC prompts signals potential privilege escalation."
            RealWorldUsage = "Used in ransomware (e.g., Sodinokibi) to gain SYSTEM privileges silently."
        }
    },
    @{
        ID = 'T1134.001'
        Name = 'Access Token Manipulation: Token Impersonation/Theft'
        Tactic = 'Privilege Escalation'
        ValidationRequired = $null
        Action = { try { rundll32.exe advapi32.dll,DuplicateTokenEx | Out-Null; Log-AttackStep "Command: rundll32.exe advapi32.dll,DuplicateTokenEx" "T1134.001"; $null = $global:executionResults.Add(@{ID="T1134.001"; Success=$true}) } catch { $null = $global:executionResults.Add(@{ID="T1134.001"; Success=$false; Error=$_.Exception.Message}) } }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Token manipulation attempts indicate privilege escalation or lateral movement."
            RealWorldUsage = "APTs (e.g., Turla) use token theft to impersonate users for access to restricted resources."
        }
    },
    @{
        ID = 'T1547.010'
        Name = 'Boot or Logon Autostart Execution: Port Monitors'
        Tactic = 'Persistence'
        ValidationRequired = { Test-AdminPrivileges }
        Action = { 
            $dllPath = "C:\Temp\sim_dll_$($random.Next(1000)).dll"
            $script:dllPath = $dllPath  # Store for cleanup
            try { 
                New-Item $dllPath -ItemType File -Force | Out-Null
                reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\SimMonitor" /v Driver /t REG_SZ /d $dllPath /f | Out-Null
                Log-AttackStep "Command: New-Item $dllPath; reg add HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\SimMonitor /v Driver /t REG_SZ /d $dllPath /f" "T1547.010"
                $null = $global:executionResults.Add(@{ID="T1547.010"; Success=$true; DllPath=$dllPath})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1547.010"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = { 
            if ($script:dllPath) {
                try { 
                    reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\SimMonitor" /f | Out-Null
                    Remove-Item $script:dllPath -Force | Out-Null
                    $null = $global:cleanupReport.Add(@{ID="T1547.010"; Status="Success"; Details="Removed port monitor and DLL"})
                } catch { 
                    $null = $global:cleanupReport.Add(@{ID="T1547.010"; Status="Failed"; Error=$_.Exception.Message})
                }
            }
        }
        Description = @{
            WhyTrack = "Adding port monitors creates persistent registry changes, a subtle persistence method."
            RealWorldUsage = "Used by APTs (e.g., APT28) to load malicious DLLs via spoolsv.exe for persistence."
        }
    },
    @{
        ID = 'T1557.001'
        Name = 'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay'
        Tactic = 'Credential Access'
        ValidationRequired = $null
        Action = { 
            $targetIP = Generate-RandomIP
            try { 
                nbtstat -A $targetIP | Out-Null
                Log-AttackStep "Command: nbtstat -A $targetIP" "T1557.001"
                $null = $global:executionResults.Add(@{ID="T1557.001"; Success=$true; TargetIP=$targetIP})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1557.001"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Probing random IPs via nbtstat can indicate credential harvesting attempts."
            RealWorldUsage = "Used in SMB relay attacks (e.g., Responder toolkit) to capture NTLM hashes."
        }
    },
    @{
        ID = 'T1202'
        Name = 'Indirect Command Execution'
        Tactic = 'Execution'
        ValidationRequired = $null
        Action = { try { forfiles /p c:\windows\system32 /c "cmd /c echo Simulated Indirect Exec" | Out-Null; Log-AttackStep "Command: forfiles /p c:\windows\system32 /c cmd /c echo Simulated Indirect Exec" "T1202"; $null = $global:executionResults.Add(@{ID="T1202"; Success=$true}) } catch { $null = $global:executionResults.Add(@{ID="T1202"; Success=$false; Error=$_.Exception.Message}) } }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Indirect execution via forfiles bypasses command restrictions, detectable as unusual."
            RealWorldUsage = "Used in fileless attacks (e.g., PowerShell Empire) to execute commands stealthily."
        }
    },
    @{
        ID = 'T1105'
        Name = 'Ingress Tool Transfer'
        Tactic = 'Command and Control'
        ValidationRequired = $null
        Action = { 
            $payloadFile = "C:\Temp\sim_payload_$($random.Next(1000)).txt"
            $script:payloadFile = $payloadFile  # Store for cleanup
            try { 
                $mockContent = "Simulated payload data from C2"
                $mockContent | Out-File $payloadFile -Encoding UTF8
                Log-AttackStep "Command: Out-File $payloadFile (simulated payload write)" "T1105"
                $null = $global:executionResults.Add(@{ID="T1105"; Success=$true; PayloadFile=$payloadFile})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1105"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = { 
            try { 
                Remove-Item "C:\Temp\sim_payload_*.txt" -Force | Out-Null
                $null = $global:cleanupReport.Add(@{ID="T1105"; Status="Success"; Details="Removed simulated payloads"})
            } catch { 
                $null = $global:cleanupReport.Add(@{ID="T1105"; Status="Failed"; Error=$_.Exception.Message})
            }
        }
        Description = @{
            WhyTrack = "Writing mock payloads to temp directories mimics C2 downloads, detectable by UEBA."
            RealWorldUsage = "Used by malware (e.g., TrickBot) to stage payloads for execution."
        }
    },
    @{
        ID = 'T1218.011'
        Name = 'System Binary Proxy Execution: Rundll32'
        Tactic = 'Defense Evasion'
        ValidationRequired = $null
        Action = { 
            $targetIP = Generate-RandomIP
            try { 
                rundll32.exe url.dll,OpenURL "http://$targetIP" | Out-Null
                Log-AttackStep "Command: rundll32.exe url.dll,OpenURL http://$targetIP" "T1218.011"
                $null = $global:executionResults.Add(@{ID="T1218.011"; Success=$true; TargetURL="http://$targetIP"})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1218.011"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = $null
        Description = @{
            WhyTrack = "Anomalous rundll32 calls to random URLs signal proxy execution attempts."
            RealWorldUsage = "Used by malware (e.g., Qakbot) to execute malicious code via trusted binaries."
        }
    },
    @{
        ID = 'T1041'
        Name = 'Exfiltration Over C2 Channel'
        Tactic = 'Exfiltration'
        ValidationRequired = $null
        Action = { 
            $tempFile = "C:\Temp\sim_data_$($random.Next(1000)).txt"
            $encodedFile = "C:\Temp\encoded_$($random.Next(1000)).txt"
            $script:exfilFiles = @($tempFile, $encodedFile)  # Store for cleanup
            try { 
                "Simulated exfil data" | Out-File $tempFile -Encoding UTF8
                $encodedData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content $tempFile)))
                $encodedData | Out-File $encodedFile -Encoding UTF8
                Log-AttackStep "Command: Out-File $tempFile; [Convert]::ToBase64String(...); Out-File $encodedFile" "T1041"
                $null = $global:executionResults.Add(@{ID="T1041"; Success=$true; Files=@($tempFile, $encodedFile)})
            } catch { 
                $null = $global:executionResults.Add(@{ID="T1041"; Success=$false; Error=$_.Exception.Message})
            }
        }
        CleanupAction = { 
            try { 
                Remove-Item "C:\Temp\encoded_*.txt", "C:\Temp\sim_data_*.txt" -Force | Out-Null
                $null = $global:cleanupReport.Add(@{ID="T1041"; Status="Success"; Details="Removed exfiltration simulation files"})
            } catch { 
                $null = $global:cleanupReport.Add(@{ID="T1041"; Status="Failed"; Error=$_.Exception.Message})
            }
        }
        Description = @{
            WhyTrack = "Encoding and writing data to temp files mimics exfiltration, detectable as suspicious."
            RealWorldUsage = "Used by APTs (e.g., APT32) to encode and exfiltrate stolen data via C2 channels."
        }
    }
)

# Check for ListTactics or ListTechniques BEFORE showing banner
if ($ListTactics -or $ListTechniques) {
    if ($ListTactics) {
        Write-Host "`nAvailable MITRE ATT&CK Tactics in MAGNETO:" -ForegroundColor Cyan
        Write-Host "=" * 80 -ForegroundColor DarkGray
        
        # Get unique tactics and count techniques
        $tacticStats = $techniques | Group-Object -Property { $_.Tactic } | Sort-Object Name | ForEach-Object {
            [PSCustomObject]@{
                Tactic = $_.Name
                Count = $_.Count
                AdminRequired = ($_.Group | Where-Object { $_.ValidationRequired -and $_.ValidationRequired.ToString() -match "Test-AdminPrivileges" }).Count
                DomainRequired = ($_.Group | Where-Object { $_.ValidationRequired -and $_.ValidationRequired.ToString() -match "Test-DomainJoined" }).Count
            }
        }
        
        foreach ($stat in $tacticStats) {
            $specialReqs = @()
            if ($stat.AdminRequired -gt 0) { $specialReqs += "$($stat.AdminRequired) require admin" }
            if ($stat.DomainRequired -gt 0) { $specialReqs += "$($stat.DomainRequired) require domain" }
            $reqString = if ($specialReqs.Count -gt 0) { " ($($specialReqs -join ', '))" } else { "" }
            
            Write-Host ("  {0,-25} : {1,2} techniques{2}" -f $stat.Tactic, $stat.Count, $reqString) -ForegroundColor Yellow
        }
        
        Write-Host "`nTotal tactics: $($tacticStats.Count)" -ForegroundColor Green
        Write-Host "Total techniques: $($techniques.Count)" -ForegroundColor Green
        
        Write-Host "`nUsage examples:" -ForegroundColor Cyan
        Write-Host "  .\MAGNETO.ps1 -IncludeTactics @('Discovery', 'Execution') -RunAllForTactics" -ForegroundColor Gray
        Write-Host "  .\MAGNETO.ps1 -ExcludeTactics @('Exfiltration', 'Impact') -RunAllForTactics" -ForegroundColor Gray
        Write-Host "  .\MAGNETO.ps1 -IncludeTactics @('Persistence') -TechniqueCount 3" -ForegroundColor Gray
    }
    
    # If ListTechniques is specified, display all techniques
    if ($ListTechniques) {
        Write-Host "`nAvailable MITRE ATT&CK Techniques in MAGNETO:" -ForegroundColor Cyan
        Write-Host "=" * 80 -ForegroundColor DarkGray
        
        # Group techniques by tactic
        $tacticGroups = $techniques | Group-Object -Property { $_.Tactic } | Sort-Object Name
        
        foreach ($group in $tacticGroups) {
            Write-Host "`n[$($group.Name)]" -ForegroundColor Magenta
            foreach ($tech in $group.Group | Sort-Object ID) {
                $adminReq = if ($tech.ValidationRequired -and $tech.ValidationRequired.ToString() -match "Test-AdminPrivileges") { " [ADMIN]" } else { "" }
                $domainReq = if ($tech.ValidationRequired -and $tech.ValidationRequired.ToString() -match "Test-DomainJoined") { " [DOMAIN]" } else { "" }
                Write-Host "  $($tech.ID): $($tech.Name)$adminReq$domainReq" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`nTotal techniques: $($techniques.Count)" -ForegroundColor Green
        Write-Host "`nLegend:" -ForegroundColor Cyan
        Write-Host "  [ADMIN]  - Requires Administrator privileges" -ForegroundColor Gray
        Write-Host "  [DOMAIN] - Requires domain-joined system" -ForegroundColor Gray
        Write-Host "`nUsage examples:" -ForegroundColor Cyan
        Write-Host "  .\MAGNETO.ps1 -IncludeTechniques @('T1046', 'T1087.001')" -ForegroundColor Gray
        Write-Host "  .\MAGNETO.ps1 -ExcludeTechniques @('T1003.003', 'T1136.001')" -ForegroundColor Gray
    }
    exit 0
}

# Set console encoding to UTF-8 for better ASCII art rendering
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Set hacker vibe: Dark mode colors
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "Green"
Clear-Host

# MAGNETO Hacker Banner (ASCII Art as provided)
Write-Host @"
  __  __    _    ____ _   _ _____ _____ ___
 |  \/  |  / \  / ___| \ | | ____|_   _/ _ \
 | \  / | / _ \| |  _|  \| |  _|   | || | | |
 | |\/| |/ ___ \ |_| | |\  | |___  | || |_| |
 |_|  |_/_/   \_\____|_| \_|_____| |_| \___/
                                                            
  Stealth Attack Simulator v$scriptVersion - Powered by Elite Ethical Hacking
  Breach. Evade. Exfil. All Native. All Stealth.
  MITRE-Aligned Chaos for Exabeam UEBA Demos.
"@ -ForegroundColor Red

Write-Host "Initializing MAGNETO simulation... Random Seed: $RandomSeed" -ForegroundColor Cyan

# Display active filters/modes
if ($RunAll) {
    Write-Host "Mode: RUN ALL TECHNIQUES" -ForegroundColor Magenta
} elseif ($IncludeTechniques.Count -gt 0) {
    Write-Host "Mode: INCLUDE ONLY specific techniques" -ForegroundColor Magenta
    Write-Host "Including only techniques: $($IncludeTechniques -join ', ')" -ForegroundColor Yellow
} elseif ($IncludeTactics.Count -gt 0) {
    Write-Host "Mode: INCLUDE TACTICS" -ForegroundColor Magenta
    Write-Host "Including tactics: $($IncludeTactics -join ', ')" -ForegroundColor Yellow
    if ($RunAllForTactics) {
        Write-Host "Running ALL techniques in selected tactics" -ForegroundColor Yellow
    }
} else {
    if ($ExcludeTactics.Count -gt 0) {
        Write-Host "Excluding tactics: $($ExcludeTactics -join ', ')" -ForegroundColor Yellow
        if ($RunAllForTactics) {
            Write-Host "Running ALL techniques in non-excluded tactics" -ForegroundColor Yellow
        }
    }
    if ($ExcludeTechniques.Count -gt 0) {
        Write-Host "Excluding techniques: $($ExcludeTechniques -join ', ')" -ForegroundColor Yellow
    }
}

Write-Host "Delay between techniques: $DelayBetweenTechniques seconds" -ForegroundColor Cyan
Start-Sleep -Seconds 2  # Dramatic pause

# Mode Selection - Skip if RunAll, IncludeTechniques, or tactic-specific modes are specified
if ($RunAll -or $IncludeTechniques.Count -gt 0 -or ($RunAllForTactics -and ($IncludeTactics.Count -gt 0 -or $ExcludeTactics.Count -gt 0))) {
    if ($RunAll) {
        $mode = 'RunAll'
    } elseif ($IncludeTechniques.Count -gt 0) {
        $mode = 'IncludeTechniques'
    } elseif ($RunAllForTactics) {
        $mode = 'TacticAll'
    }
    Write-Host "Mode auto-selected based on parameters: $mode" -ForegroundColor Cyan
} else {
    Write-Host "Select attack mode:" -ForegroundColor Magenta
    Write-Host " (R)andomize techniques" -ForegroundColor Yellow
    Write-Host " (C)hain attack simulation (follows attack lifecycle)" -ForegroundColor Yellow
    $modeInput = Read-Host "Enter R or C"
    $mode = if ($modeInput -eq 'R' -or $modeInput -eq 'r') { 'Random' } elseif ($modeInput -eq 'C' -or $modeInput -eq 'c') { 'Chain' } else { 'Random' }  # Default to Random if invalid
    Write-Host "Mode selected: $mode" -ForegroundColor Cyan
}
Start-Sleep -Seconds 1

# Handle different filtering modes
if ($IncludeTechniques.Count -gt 0) {
    # Include specific techniques mode - highest priority
    $filteredTechniques = $techniques | Where-Object {
        $_.ID -in $IncludeTechniques
    }
    if ($filteredTechniques.Count -eq 0) {
        Write-Host "ERROR: None of the specified techniques were found. Available techniques:" -ForegroundColor Red
        $techniques | ForEach-Object { Write-Host "  $($_.ID): $($_.Name)" -ForegroundColor Yellow }
        exit 1
    }
    Write-Host "Filtered to $($filteredTechniques.Count) specifically included techniques" -ForegroundColor Green
} elseif ($RunAll) {
    # Run all mode - no filtering
    $filteredTechniques = $techniques
    Write-Host "Running ALL $($filteredTechniques.Count) available techniques!" -ForegroundColor Magenta
} elseif ($IncludeTactics.Count -gt 0) {
    # Include specific tactics mode
    $filteredTechniques = $techniques | Where-Object {
        $_.Tactic -in $IncludeTactics
    }
    if ($filteredTechniques.Count -eq 0) {
        Write-Host "ERROR: None of the specified tactics were found. Available tactics:" -ForegroundColor Red
        $techniques | Select-Object -ExpandProperty Tactic -Unique | Sort-Object | ForEach-Object { 
            Write-Host "  $_" -ForegroundColor Yellow 
        }
        exit 1
    }
    Write-Host "Filtered to $($filteredTechniques.Count) techniques from included tactics: $($IncludeTactics -join ', ')" -ForegroundColor Green
} else {
    # Normal exclusion mode
    $filteredTechniques = $techniques | Where-Object {
        $_.Tactic -notin $ExcludeTactics -and $_.ID -notin $ExcludeTechniques
    }
    if ($filteredTechniques.Count -eq 0) {
        Write-Host "ERROR: All techniques filtered out. Adjust your exclusion parameters." -ForegroundColor Red
        exit 1
    }
    Write-Host "Available techniques after filtering: $($filteredTechniques.Count)" -ForegroundColor Green
}

# Select Techniques Based on Mode
if ($mode -eq 'RunAll') {
    # Run all available techniques
    $selectedTechniques = $filteredTechniques
    Write-Host "RunAll mode: Executing ALL $($selectedTechniques.Count) techniques." -ForegroundColor Cyan
    Write-Host "WARNING: This may take a while and generate significant logs!" -ForegroundColor Yellow
} elseif ($mode -eq 'IncludeTechniques') {
    # Include specific techniques mode
    $selectedTechniques = $filteredTechniques
    Write-Host "Include mode: Executing $($selectedTechniques.Count) specified techniques." -ForegroundColor Cyan
} elseif ($mode -eq 'TacticAll') {
    # Run all techniques for selected tactics
    $selectedTechniques = $filteredTechniques
    if ($IncludeTactics.Count -gt 0) {
        Write-Host "TacticAll mode: Executing ALL $($selectedTechniques.Count) techniques from tactics: $($IncludeTactics -join ', ')" -ForegroundColor Cyan
    } else {
        $excludedTacticsMsg = if ($ExcludeTactics.Count -gt 0) { " (excluding: $($ExcludeTactics -join ', '))" } else { "" }
        Write-Host "TacticAll mode: Executing ALL $($selectedTechniques.Count) techniques$excludedTacticsMsg" -ForegroundColor Cyan
    }
} elseif ($mode -eq 'Random') {
    # Random mode - apply tactic filters if specified
    if ($IncludeTactics.Count -gt 0 -and -not $RunAllForTactics) {
        # Filter to included tactics first, then randomize
        $tacticFiltered = $filteredTechniques | Where-Object { $_.Tactic -in $IncludeTactics }
        $actualCount = [Math]::Min($TechniqueCount, $tacticFiltered.Count)
        $selectedTechniques = $tacticFiltered | Get-Random -Count $actualCount
        Write-Host "Random mode: Executing $($selectedTechniques.Count) random techniques from tactics: $($IncludeTactics -join ', ')" -ForegroundColor Cyan
    } else {
        $actualCount = [Math]::Min($TechniqueCount, $filteredTechniques.Count)
        $selectedTechniques = $filteredTechniques | Get-Random -Count $actualCount
        Write-Host "Random mode: Executing $($selectedTechniques.Count) random techniques." -ForegroundColor Cyan
    }
} else {
    # Chain mode - one technique per tactic in lifecycle order
    $tacticsOrder = @('Discovery', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Lateral Movement', 'Command and Control', 'Exfiltration')
    
    # Apply tactic inclusion filter if specified
    if ($IncludeTactics.Count -gt 0) {
        $tacticsOrder = $tacticsOrder | Where-Object { $_ -in $IncludeTactics }
    } else {
        $tacticsOrder = $tacticsOrder | Where-Object { $_ -notin $ExcludeTactics }
    }
    
    $selectedTechniques = @()
    foreach ($tac in $tacticsOrder) {
        $candidates = $filteredTechniques | Where-Object { $_.Tactic -eq $tac }
        if ($candidates.Count -gt 0) {
            if ($RunAllForTactics) {
                # Add all techniques from this tactic
                $selectedTechniques += $candidates
            } else {
                # Add one random technique from this tactic
                $selectedTechniques += $candidates | Get-Random -Count 1
            }
        }
    }
    
    if ($RunAllForTactics) {
        Write-Host "Chain mode with RunAllForTactics: Executing ALL $($selectedTechniques.Count) techniques in lifecycle order." -ForegroundColor Cyan
    } else {
        Write-Host "Chain mode: Executing $($selectedTechniques.Count) techniques in lifecycle order (one per tactic)." -ForegroundColor Cyan
    }
}

# Display selected techniques if in certain modes
if ($mode -in @('IncludeTechniques', 'RunAll', 'TacticAll') -or ($RunAllForTactics -and $selectedTechniques.Count -gt 10)) {
    Write-Host "`nTechniques to be executed:" -ForegroundColor Cyan
    
    # Group by tactic for better display
    $groupedTechniques = $selectedTechniques | Group-Object -Property { $_.Tactic } | Sort-Object Name
    foreach ($group in $groupedTechniques) {
        Write-Host "  [$($group.Name)]" -ForegroundColor Magenta
        foreach ($tech in $group.Group | Sort-Object ID) {
            Write-Host "    - $($tech.ID): $($tech.Name)" -ForegroundColor Gray
        }
    }
    Write-Host ""
    
    # Add confirmation for large sets
    if ($selectedTechniques.Count -gt 15) {
        $confirm = Read-Host "Are you sure you want to run $($selectedTechniques.Count) techniques? (Y/N)"
        if ($confirm -ne 'Y' -and $confirm -ne 'y') {
            Write-Host "Simulation cancelled." -ForegroundColor Yellow
            exit 0
        }
    }
}

# Check for admin privileges if needed
$needsAdmin = @()
$needsDomain = @()
foreach ($tech in $selectedTechniques) {
    if ($tech.ValidationRequired) {
        if ($tech.ValidationRequired.ToString() -match "Test-AdminPrivileges") {
            $needsAdmin += $tech.ID
        }
        if ($tech.ValidationRequired.ToString() -match "Test-DomainJoined") {
            $needsDomain += $tech.ID
        }
    }
}

if ($needsAdmin.Count -gt 0 -and -not (Test-AdminPrivileges)) {
    Write-Host "WARNING: $($needsAdmin.Count) techniques require admin privileges and will be skipped:" -ForegroundColor Yellow
    Write-Host "  $($needsAdmin -join ', ')" -ForegroundColor Yellow
}

if ($needsDomain.Count -gt 0 -and -not (Test-DomainJoined)) {
    Write-Host "WARNING: $($needsDomain.Count) techniques require domain membership and will be skipped:" -ForegroundColor Yellow
    Write-Host "  $($needsDomain -join ', ')" -ForegroundColor Yellow
}

if ($needsAdmin.Count -gt 0 -or $needsDomain.Count -gt 0) {
    Start-Sleep -Seconds 3
}

# Execute Attack Chain with Progress Tracking
Write-Host "Commencing Breach Simulation... Stay Low, Move Fast." -ForegroundColor Magenta
$counter = 0
$totalTechniques = $selectedTechniques.Count

foreach ($tech in $selectedTechniques) {
    $counter++
    $percentComplete = ($counter / $totalTechniques) * 100
    
    # Progress bar
    Write-Progress -Activity "Executing MITRE Techniques" `
                   -Status "[$counter/$totalTechniques] $($tech.ID): $($tech.Name)" `
                   -PercentComplete $percentComplete `
                   -CurrentOperation "Tactic: $($tech.Tactic)"
    
    # Validation check
    $canExecute = $true
    if ($tech.ValidationRequired) {
        $validationResult = & $tech.ValidationRequired
        if (-not $validationResult) {
            Write-Host "[$($tech.ID)] Skipping - validation failed (may require admin/domain)" -ForegroundColor Yellow
            $null = $global:executionResults.Add(@{
                ID = $tech.ID
                Success = $false
                Reason = "Validation failed - requires admin privileges or domain membership"
                Skipped = $true
            })
            $canExecute = $false
        }
    }
    
    if ($canExecute) {
        Log-AttackStep "Executing: $($tech.Name)" $tech.ID
        $null = $global:actuallyExecutedTechniqueIDs.Add($tech.ID)  # Track that we're executing this
        & $tech.Action
        Show-BlinkEffect  # Add blinking effect and dramatic pause after each technique
    }
    
    # Rate limiting delay
    if ($counter -lt $totalTechniques) {
        Write-Host "Waiting $DelayBetweenTechniques seconds before next technique..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $DelayBetweenTechniques
    }
}

Write-Progress -Activity "Executing MITRE Techniques" -Completed

# Optional Cleanup with Verification
if ($Cleanup) {
    Write-Host "Initiating Evasion Cleanup... Leaving No Trace." -ForegroundColor Cyan
    
    # Get list of successfully executed technique IDs
    $successfulTechniqueIDs = @()
    foreach ($result in $global:executionResults) {
        if ($result.Success -eq $true) {
            $successfulTechniqueIDs += $result.ID
        }
    }
    
    # Only get techniques that were successfully executed AND have cleanup actions
    $techniquesWithCleanup = @()
    foreach ($tech in $selectedTechniques) {
        if ($tech.CleanupAction -and ($tech.ID -in $successfulTechniqueIDs)) {
            $techniquesWithCleanup += $tech
        }
    }
    
    if ($techniquesWithCleanup.Count -gt 0) {
        Write-Host "Found $($techniquesWithCleanup.Count) techniques requiring cleanup" -ForegroundColor Cyan
        $cleanupCounter = 0
        
        foreach ($tech in $techniquesWithCleanup) {
            $cleanupCounter++
            $percentComplete = ($cleanupCounter / $techniquesWithCleanup.Count) * 100
            
            Write-Progress -Activity "Cleaning Up Artifacts" `
                           -Status "[$cleanupCounter/$($techniquesWithCleanup.Count)] Cleaning $($tech.ID): $($tech.Name)" `
                           -PercentComplete $percentComplete
            
            Log-AttackStep "Cleaning: $($tech.Name)" $tech.ID
            & $tech.CleanupAction
            Show-BlinkEffect "CLEANED."
        }
        
        Write-Progress -Activity "Cleaning Up Artifacts" -Completed
    } else {
        Write-Host "No artifacts to clean up (no techniques with cleanup were successfully executed)" -ForegroundColor Yellow
    }
    
    # Display cleanup report
    Write-Host "`nCleanup Report:" -ForegroundColor Cyan
    foreach ($item in $global:cleanupReport) {
        $color = if ($item.Status -eq "Success") { "Green" } elseif ($item.Status -eq "Failed") { "Red" } else { "Gray" }
        Write-Host "  [$($item.ID)] $($item.Status): $($item.Details)" -ForegroundColor $color
    }
}

# Generate Execution Summary
Write-Host "`nExecution Summary:" -ForegroundColor Cyan
$successCount = ($global:executionResults | Where-Object { $_.Success }).Count
$skippedCount = ($global:executionResults | Where-Object { $_.Skipped }).Count
$failCount = ($global:executionResults | Where-Object { -not $_.Success -and -not $_.Skipped }).Count
Write-Host "  Successful: $successCount" -ForegroundColor Green
Write-Host "  Skipped (validation): $skippedCount" -ForegroundColor Yellow
Write-Host "  Failed: $failCount" -ForegroundColor Red

# Generate and Open Log File
$logFile = "MAGNETO_AttackLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$logContent = @("MAGNETO Stealth Attack Log")
$logContent += "Version: $scriptVersion"
$logContent += "Run on: $(Get-Date)"
$logContent += "Author: Syed Hasan Rizvi"
$logContent += ""
$logContent += "Configuration:"
$logContent += "  Mode: $mode"
$logContent += "  Random Seed: $RandomSeed"
$logContent += "  Delay Between Techniques: $DelayBetweenTechniques seconds"
$logContent += "  Excluded Tactics: $($ExcludeTactics -join ', ')"
$logContent += "  Excluded Techniques: $($ExcludeTechniques -join ', ')"
$logContent += ""
$logContent += "Execution Summary:"
$logContent += "  Total Attempted: $($global:executionResults.Count)"
$logContent += "  Successful: $successCount"
$logContent += "  Skipped (validation): $skippedCount"
$logContent += "  Failed: $failCount"
$logContent += ""
$logContent += "TTPs Covered (MITRE ATT&CK):"
foreach ($tech in $selectedTechniques) {
    $result = $global:executionResults | Where-Object { $_.ID -eq $tech.ID }
    
    # Determine status
    if (-not $result) {
        # This technique wasn't in execution results at all - shouldn't happen
        $logContent += "  $($tech.ID): $($tech.Name) [Tactic: $($tech.Tactic)] - NOT EXECUTED"
        $logContent += "    ERROR: Technique was selected but not found in execution results"
        $logContent += ""
        continue
    }
    
    $status = if ($result.Success -eq $true) { 
        "SUCCESS" 
    } elseif ($result.Skipped -eq $true) { 
        "SKIPPED (Validation)" 
    } else { 
        "FAILED" 
    }
    
    $logContent += "  $($tech.ID): $($tech.Name) [Tactic: $($tech.Tactic)] - $status"
    
    # For skipped techniques - minimal output
    if ($result.Skipped -eq $true) {
        $logContent += "    Why Track: $($tech.Description.WhyTrack)"
        $logContent += "    Real-World Usage: $($tech.Description.RealWorldUsage)"
        if ($result.Reason) {
            $logContent += "    Reason: $($result.Reason)"
        }
    }
    # For executed techniques
    else {
        # Show execution commands (should exist for any attempted technique)
        $execCommands = $global:logCommands | Where-Object { 
            $_ -match "\[$($tech.ID)\]" -and $_ -notmatch "Cleaning:"
        }
        if ($execCommands) {
            $logContent += "    Execution Commands: $($execCommands -join '; ')"
        }
        
        # Only show cleanup for successful techniques where cleanup was performed
        if ($result.Success -eq $true -and $Cleanup) {
            $cleanupCommands = $global:logCommands | Where-Object { 
                $_ -match "\[$($tech.ID)\]" -and $_ -match "Cleaning:"
            }
            if ($cleanupCommands) {
                $logContent += "    Cleanup Commands: $($cleanupCommands -join '; ')"
                
                $cleanupInfo = $global:cleanupReport | Where-Object { $_.ID -eq $tech.ID }
                if ($cleanupInfo) {
                    $logContent += "    Cleanup Result: $($cleanupInfo.Status) - $($cleanupInfo.Details)"
                }
            }
        }
        
        $logContent += "    Why Track: $($tech.Description.WhyTrack)"
        $logContent += "    Real-World Usage: $($tech.Description.RealWorldUsage)"
        
        # Show error if failed
        if (-not $result.Success -and $result.Error) {
            $logContent += "    Error: $($result.Error)"
        }
    }
    
    $logContent += ""
}

if ($Cleanup -and $global:cleanupReport.Count -gt 0) {
    $logContent += "Cleanup Report:"
    foreach ($item in $global:cleanupReport) {
        $logContent += "  [$($item.ID)] $($item.Status): $($item.Details)"
    }
    $logContent += ""
}

# Commands executed section at the end of log
$logContent += "Detailed Command Log:"
foreach ($cmd in $global:logCommands) {
    # Only include commands for techniques that were actually executed
    $techID = if ($cmd -match '\[([T0-9.]+)\]') { $matches[1] } else { $null }
    if ($techID) {
        $wasExecuted = $techID -in $global:actuallyExecutedTechniqueIDs
        if ($wasExecuted -or (-not ($cmd -match "Cleaning:"))) {
            $logContent += $cmd
        }
    } else {
        $logContent += $cmd
    }
}

$logContent | Out-File -FilePath $logFile -Encoding UTF8
Write-Host "Log generated: $logFile" -ForegroundColor Green
Start-Sleep -Seconds 1
notepad.exe $logFile

Write-Host "Simulation Complete. Check Exabeam Threat Center - Alerts for Anomalies Triggered." -ForegroundColor Green

Write-Host "Exfil Complete. Ghost Out." -ForegroundColor Red
