#Requires -Version 5.0
<#
.SYNOPSIS
    RMM Detector - Windows Remote Monitoring & Management Software Scanner

.DESCRIPTION
    Scans a Windows system for installed or running RMM (Remote Monitoring & Management)
    software, remote access tools, and hidden monitoring agents.

    Detection Methods:
    - Running process inspection
    - Installed software registry scan
    - Windows service enumeration
    - Startup entry analysis
    - Scheduled task inspection
    - Network connection analysis
    - File system presence checks

    This tool is for DETECTION ONLY. It will not remove any software.

.PARAMETER Silent
    Only output findings (suppress informational messages).

.PARAMETER Json
    Output results in JSON format.

.PARAMETER OutputFile
    Path to save the text report (default: rmm_report.txt).

.PARAMETER SignaturesFile
    Path to signatures.json database (default: same directory as script).

.EXAMPLE
    .\detector.ps1
    .\detector.ps1 -Silent
    .\detector.ps1 -Json
    .\detector.ps1 -OutputFile "C:\Temp\my_report.txt"

.NOTES
    Run as Administrator for complete results.
    Compatible with Windows 10, Windows 11, and Windows Server.
#>

[CmdletBinding()]
param(
    [switch]$Silent,
    [switch]$Json,
    [string]$OutputFile = "rmm_report.txt",
    [string]$SignaturesFile = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ─── Load Signatures ─────────────────────────────────────────────────────────

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($ScriptDir)) { $ScriptDir = Get-Location }

if ([string]::IsNullOrEmpty($SignaturesFile)) {
    $SignaturesFile = Join-Path $ScriptDir "signatures.json"
}

$Signatures = $null
if (Test-Path $SignaturesFile) {
    try {
        $Signatures = Get-Content $SignaturesFile -Raw | ConvertFrom-Json
    } catch {
        # Fall back to built-in signatures
    }
}

# Built-in fallback signatures (subset)
$BuiltinProcesses = @(
    "teamviewer.exe","teamviewer_service.exe","anydesk.exe",
    "screenconnect.clientservice.exe","screenconnect.windowsclient.exe",
    "connectwisecontrol.clientservice.exe",
    "ninjarmmagent.exe","ninjarmm-agent.exe","ninjaone.exe",
    "dattobackup.exe","centrastage.exe","datto-rmm-agent.exe",
    "kaseya.agent.exe","kagent.exe","kaseyaremotecontrol.exe",
    "ateraagent.exe","atera.agent.exe",
    "splashtopremote.exe","splashtopstreamer.exe","srtservice.exe",
    "meshagent.exe","meshcentral.exe",
    "pulsewayagent.exe","pulseway.exe",
    "gotoassist.exe","g2ax_comm_expert.exe","g2ax_user.exe",
    "logmein.exe","logmeinrescue.exe","lmir.exe",
    "rustdesk.exe","tacticalrmm.exe","simplehelp.exe",
    "zohoassist.exe","zoho_assist.exe",
    "remotepc.exe","remotepcclient.exe","remotepcservice.exe",
    "syncroservice.exe","kabutoservice.exe",
    "n_able.exe","ncentral.agent.exe","ncentralagent.exe",
    "superops.exe","action1.exe","action1agent.exe",
    "level.exe","levelrmm.exe","addigy.exe","addigyagent.exe",
    "dameware.exe","dwrcs.exe","beyondtrust.exe","bomgar.exe",
    "manageengine.exe","desktopcentral.exe",
    "islonline.exe","isllight.exe",
    "tacticalagent.exe","osquery.exe"
)

$BuiltinServices = @(
    "TeamViewer","TeamViewer7","TeamViewer8","TeamViewer9","TeamViewer10",
    "TeamViewer11","TeamViewer12","TeamViewer13","TeamViewer14","TeamViewer15",
    "AnyDesk","ScreenConnect Client","ScreenConnect","ConnectWiseControl",
    "ConnectWiseControlClient","NinjaRMMAgent","NinjaOne","NinjaRMM",
    "Datto RMM","CentraStage","DattoRMM","Kaseya Agent","KaseyaAgent","VSAAgent",
    "AteraAgent","Atera Agent","Splashtop Remote Service","SplashtopRemoteService",
    "SRTService","Mesh Agent","MeshAgent","MeshCentralAgent","Pulseway",
    "PulsewayAgent","MMSoftPulseway","GoToAssist","GoTo Resolve","LogMeIn",
    "LogMeIn Rescue","RustDesk","TacticalRMM","Syncro RMM","SyncroRMM",
    "KabutoService","N-able Agent","SolarWindsN-central","SuperOps","Action1",
    "LevelRMM","Addigy","DameWare","DameWareRemoteSupport","BeyondTrust","Bomgar",
    "ManageEngine","DesktopCentral","ISLOnline","ISLLight","RemotePC","ZohoAssist"
)

$BuiltinRegistryKeys = @(
    "TeamViewer","AnyDesk","ScreenConnect","ConnectWise","NinjaRMM","NinjaOne",
    "Datto RMM","CentraStage","Kaseya","Atera","Splashtop","MeshCentral",
    "Pulseway","GoToAssist","LogMeIn","RustDesk","TacticalRMM","Syncro","Kabuto",
    "N-able","SolarWindsMSP","N-central","SuperOps","Action1","Addigy","DameWare",
    "BeyondTrust","Bomgar","ManageEngine","ISLOnline","RemotePC","ZohoAssist","SimpleHelp"
)

$BuiltinFolders = @(
    "TeamViewer","AnyDesk","ScreenConnect","ConnectWise Control","NinjaRMM","NinjaOne",
    "Datto RMM","CentraStage","Kaseya","Kaseya Agent","Kaseya VSA","Atera","AteraAgent",
    "Splashtop","Splashtop Remote","MeshCentral","Mesh Agent","Pulseway","GoToAssist",
    "LogMeIn","RustDesk","TacticalRMM","Syncro","Kabuto","N-able","SolarWindsMSP",
    "SuperOps","Action1","Addigy","DameWare","BeyondTrust","Bomgar","ManageEngine",
    "Desktop Central","ISL Online","RemotePC","ZohoAssist","SimpleHelp"
)

$BuiltinTaskKeywords = @(
    "TeamViewer","AnyDesk","ScreenConnect","NinjaRMM","NinjaOne","Datto","Kaseya",
    "Atera","Splashtop","MeshCentral","Mesh Agent","Pulseway","GoToAssist","LogMeIn",
    "RustDesk","TacticalRMM","Syncro","Action1","SuperOps","ManageEngine","ZohoAssist",
    "RemotePC","BeyondTrust","Bomgar","SimpleHelp","ISLOnline"
)

# Merge with loaded signatures if available
$KnownProcesses    = if ($Signatures -and $Signatures.processes)            { $Signatures.processes }            else { $BuiltinProcesses }
$KnownServices     = if ($Signatures -and $Signatures.services)             { $Signatures.services }             else { $BuiltinServices }
$KnownRegKeys      = if ($Signatures -and $Signatures.registry_keys)        { $Signatures.registry_keys }        else { $BuiltinRegistryKeys }
$KnownFolders      = if ($Signatures -and $Signatures.install_folders)      { $Signatures.install_folders }      else { $BuiltinFolders }
$KnownTaskKeywords = if ($Signatures -and $Signatures.scheduled_task_keywords) { $Signatures.scheduled_task_keywords } else { $BuiltinTaskKeywords }
$HeuristicProcs    = if ($Signatures -and $Signatures.heuristic_process_names) { $Signatures.heuristic_process_names } else { @("agent.exe","rmm-agent.exe","clientservice.exe","remoteservice.exe") }

# ─── Helpers ──────────────────────────────────────────────────────────────────

function Write-Status {
    param([string]$Message)
    if (-not $Silent -and -not $Json) {
        Write-Host $Message
    }
}

function Write-Finding {
    param([string]$Category, [string]$Item)
    if (-not $Json) {
        Write-Host "[FOUND] $Item" -ForegroundColor Yellow
    }
}

# ─── Detection Functions ──────────────────────────────────────────────────────

function Get-RMMProcesses {
    Write-Status "`nScanning Running Processes..."
    $found = @()
    $runningProcesses = Get-Process | Select-Object -ExpandProperty Name

    foreach ($proc in $runningProcesses) {
        $procLower = $proc.ToLower() + ".exe"
        foreach ($knownProc in $KnownProcesses) {
            if ($procLower -eq $knownProc.ToLower() -or $proc.ToLower() -eq $knownProc.ToLower().TrimEnd('.exe')) {
                $entry = "$proc.exe"
                if ($found -notcontains $entry) {
                    $found += $entry
                    Write-Finding "Process" $entry
                }
            }
        }
        # Heuristic check
        foreach ($heuristic in $HeuristicProcs) {
            if ($procLower -eq $heuristic.ToLower() -or $proc.ToLower() -eq $heuristic.ToLower().TrimEnd('.exe')) {
                $entry = "$proc.exe (heuristic match)"
                if ($found -notcontains $entry) {
                    $found += $entry
                    if (-not $Json) {
                        Write-Host "[SUSPECT] $entry" -ForegroundColor Cyan
                    }
                }
            }
        }
    }

    if ($found.Count -eq 0) { Write-Status "  No known RMM processes found." }
    return $found
}

function Get-RMMInstalledSoftware {
    Write-Status "`nScanning Installed Software..."
    $found = @()

    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $regPaths) {
        $items = Get-ItemProperty $path 2>$null | Where-Object { $_.DisplayName }
        foreach ($item in $items) {
            $name = $item.DisplayName
            foreach ($key in $KnownRegKeys) {
                if ($name -match [regex]::Escape($key)) {
                    $entry = $name
                    if ($found -notcontains $entry) {
                        $found += $entry
                        Write-Finding "Software" $entry
                    }
                }
            }
        }
    }

    if ($found.Count -eq 0) { Write-Status "  No known RMM software found in registry." }
    return $found
}

function Get-RMMServices {
    Write-Status "`nScanning Services..."
    $found = @()

    $services = Get-Service 2>$null
    foreach ($svc in $services) {
        $svcName    = $svc.Name
        $svcDisplay = $svc.DisplayName

        foreach ($knownSvc in $KnownServices) {
            if ($svcName -match [regex]::Escape($knownSvc) -or $svcDisplay -match [regex]::Escape($knownSvc)) {
                $entry = "$svcDisplay ($svcName) - Status: $($svc.Status)"
                if ($found -notcontains $entry) {
                    $found += $entry
                    Write-Finding "Service" $entry
                }
            }
        }
    }

    if ($found.Count -eq 0) { Write-Status "  No known RMM services found." }
    return $found
}

function Get-RMMStartupEntries {
    Write-Status "`nScanning Startup Entries..."
    $found = @()

    $startupPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $entries = Get-ItemProperty $path 2>$null
            if ($entries) {
                $entries.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                    $valueName = $_.Name
                    $valueData = $_.Value

                    foreach ($key in $KnownRegKeys) {
                        if ($valueName -match [regex]::Escape($key) -or $valueData -match [regex]::Escape($key)) {
                            $entry = "[$($path.Split('\')[-1])] $valueName = $($valueData.ToString().Substring(0, [Math]::Min(80, $valueData.ToString().Length)))"
                            if ($found -notcontains $entry) {
                                $found += $entry
                                Write-Finding "Startup" $entry
                            }
                        }
                    }
                }
            }
        }
    }

    if ($found.Count -eq 0) { Write-Status "  No known RMM startup entries found." }
    return $found
}

function Get-RMMScheduledTasks {
    Write-Status "`nScanning Scheduled Tasks..."
    $found = @()

    try {
        $tasks = Get-ScheduledTask 2>$null
        foreach ($task in $tasks) {
            $taskName = $task.TaskName
            $taskPath = $task.TaskPath
            $actions  = $task.Actions | ForEach-Object { $_.Execute } | Where-Object { $_ }

            $combined = "$taskName $taskPath $($actions -join ' ')"

            foreach ($keyword in $KnownTaskKeywords) {
                if ($combined -match [regex]::Escape($keyword)) {
                    $entry = "$taskPath$taskName"
                    if ($found -notcontains $entry) {
                        $found += $entry
                        Write-Finding "Task" $entry
                    }
                }
            }
        }
    } catch {
        Write-Status "  Could not enumerate scheduled tasks (run as Administrator)."
    }

    if ($found.Count -eq 0) { Write-Status "  No known RMM scheduled tasks found." }
    return $found
}

function Get-RMMNetworkConnections {
    Write-Status "`nScanning Network Connections..."
    $found = @()

    $rmmPorts = @(5938, 7070, 21115, 21116, 21117, 21118, 21119, 8040, 4343, 9000, 9001, 6129, 55510, 8200, 21121)

    try {
        $connections = Get-NetTCPConnection -State Established,Listen 2>$null
        foreach ($conn in $connections) {
            $remotePort = $conn.RemotePort
            $localPort  = $conn.LocalPort
            $remoteAddr = $conn.RemoteAddress
            $state      = $conn.State

            if ($rmmPorts -contains $remotePort) {
                $portInfo = switch ($remotePort) {
                    5938  { "TeamViewer" }
                    7070  { "ScreenConnect/ConnectWise Control" }
                    21116 { "AnyDesk" }
                    21115 { "AnyDesk" }
                    21117 { "AnyDesk" }
                    21118 { "AnyDesk" }
                    21119 { "AnyDesk" }
                    8040  { "MeshCentral" }
                    4343  { "MeshCentral" }
                    9000  { "SimpleHelp" }
                    9001  { "SimpleHelp/TacticalRMM" }
                    6129  { "DameWare" }
                    55510 { "GoToAssist" }
                    8200  { "RustDesk" }
                    21121 { "RustDesk" }
                    default { "RMM Port" }
                }

                $entry = "Port $remotePort ($portInfo) -> $remoteAddr [$state]"
                if ($found -notcontains $entry) {
                    $found += $entry
                    Write-Finding "Network" $entry
                }
            }
        }
    } catch {
        Write-Status "  Could not enumerate network connections (run as Administrator)."
    }

    if ($found.Count -eq 0) { Write-Status "  No suspicious RMM network connections found." }
    return $found
}

function Get-RMMInstalledFiles {
    Write-Status "`nScanning Installation Directories..."
    $found = @()

    $searchRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        "$env:LOCALAPPDATA",
        "$env:APPDATA"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $searchRoots) {
        foreach ($folder in $KnownFolders) {
            $candidate = Join-Path $root $folder
            if (Test-Path $candidate) {
                $entry = $candidate
                if ($found -notcontains $entry) {
                    $found += $entry
                    Write-Finding "Directory" $entry
                }
            }
        }
    }

    if ($found.Count -eq 0) { Write-Status "  No known RMM installation directories found." }
    return $found
}

# ─── Main ─────────────────────────────────────────────────────────────────────

$Banner = @"
  ██████╗ ███╗   ███╗███╗   ███╗
  ██╔══██╗████╗ ████║████╗ ████║
  ██████╔╝██╔████╔██║██╔████╔██║
  ██╔═══╝ ██║╚██╔╝██║██║╚██╔╝██║
  ██║     ██║ ╚═╝ ██║██║ ╚═╝ ██║
  ╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝

  RMM DETECTOR v1.0
  Remote Monitoring Detection Tool
"@

if (-not $Silent -and -not $Json) {
    Write-Host $Banner -ForegroundColor Cyan
    Write-Host ("=" * 50) -ForegroundColor DarkGray
    Write-Host "  RMM DETECTOR SECURITY SCAN" -ForegroundColor White
    Write-Host ("=" * 50) -ForegroundColor DarkGray
}

$ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ComputerName = $env:COMPUTERNAME
$UserName     = $env:USERNAME

# Run all detection modules
$FoundProcesses  = Get-RMMProcesses
$FoundSoftware   = Get-RMMInstalledSoftware
$FoundServices   = Get-RMMServices
$FoundStartup    = Get-RMMStartupEntries
$FoundTasks      = Get-RMMScheduledTasks
$FoundNetwork    = Get-RMMNetworkConnections
$FoundFiles      = Get-RMMInstalledFiles

$TotalFindings = $FoundProcesses.Count + $FoundSoftware.Count + $FoundServices.Count +
                 $FoundStartup.Count + $FoundTasks.Count + $FoundNetwork.Count + $FoundFiles.Count

# ─── Output ───────────────────────────────────────────────────────────────────

if ($Json) {
    # JSON output
    $output = [ordered]@{
        scan_time    = $ScanTime
        computer     = $ComputerName
        user         = $UserName
        total        = $TotalFindings
        processes    = $FoundProcesses
        software     = $FoundSoftware
        services     = $FoundServices
        startup      = $FoundStartup
        tasks        = $FoundTasks
        network      = $FoundNetwork
        files        = $FoundFiles
    }
    $output | ConvertTo-Json -Depth 5
} else {
    # Human-readable summary
    if (-not $Silent) {
        Write-Host ""
        Write-Host ("-" * 50) -ForegroundColor DarkGray
    }

    if ($TotalFindings -gt 0) {
        Write-Host ""
        Write-Host "  WARNING: Remote Management Software Detected" -ForegroundColor Red
        Write-Host ""
        if ($FoundProcesses.Count -gt 0)  { Write-Host "  $($FoundProcesses.Count) Running Process(es)" -ForegroundColor Yellow }
        if ($FoundSoftware.Count -gt 0)   { Write-Host "  $($FoundSoftware.Count) Installed Program(s)" -ForegroundColor Yellow }
        if ($FoundServices.Count -gt 0)   { Write-Host "  $($FoundServices.Count) Service(s)" -ForegroundColor Yellow }
        if ($FoundStartup.Count -gt 0)    { Write-Host "  $($FoundStartup.Count) Startup Entr(ies)" -ForegroundColor Yellow }
        if ($FoundTasks.Count -gt 0)      { Write-Host "  $($FoundTasks.Count) Scheduled Task(s)" -ForegroundColor Yellow }
        if ($FoundNetwork.Count -gt 0)    { Write-Host "  $($FoundNetwork.Count) Network Connection(s)" -ForegroundColor Yellow }
        if ($FoundFiles.Count -gt 0)      { Write-Host "  $($FoundFiles.Count) Installation Directory/ies" -ForegroundColor Yellow }
    } else {
        Write-Host ""
        Write-Host "  No RMM software detected." -ForegroundColor Green
    }

    if (-not $Silent) {
        Write-Host ""
        Write-Host ("-" * 50) -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "Recommendation:" -ForegroundColor White
        Write-Host "  Verify whether these tools were installed by your IT provider."
        Write-Host "  Unauthorized RMM software may indicate a compromised system."
        Write-Host ""
    }

    # Write text report
    $ReportLines = @()
    $ReportLines += "=" * 60
    $ReportLines += "  RMM DETECTOR SECURITY SCAN REPORT"
    $ReportLines += "=" * 60
    $ReportLines += "Scan Time : $ScanTime"
    $ReportLines += "Computer  : $ComputerName"
    $ReportLines += "User      : $UserName"
    $ReportLines += ""

    if ($FoundProcesses.Count -gt 0) {
        $ReportLines += "RUNNING PROCESSES ($($FoundProcesses.Count) found):"
        $FoundProcesses | ForEach-Object { $ReportLines += "  [FOUND] $_" }
        $ReportLines += ""
    }

    if ($FoundSoftware.Count -gt 0) {
        $ReportLines += "INSTALLED SOFTWARE ($($FoundSoftware.Count) found):"
        $FoundSoftware | ForEach-Object { $ReportLines += "  [FOUND] $_" }
        $ReportLines += ""
    }

    if ($FoundServices.Count -gt 0) {
        $ReportLines += "SERVICES ($($FoundServices.Count) found):"
        $FoundServices | ForEach-Object { $ReportLines += "  [FOUND] $_" }
        $ReportLines += ""
    }

    if ($FoundStartup.Count -gt 0) {
        $ReportLines += "STARTUP ENTRIES ($($FoundStartup.Count) found):"
        $FoundStartup | ForEach-Object { $ReportLines += "  [FOUND] $_" }
        $ReportLines += ""
    }

    if ($FoundTasks.Count -gt 0) {
        $ReportLines += "SCHEDULED TASKS ($($FoundTasks.Count) found):"
        $FoundTasks | ForEach-Object { $ReportLines += "  [FOUND] $_" }
        $ReportLines += ""
    }

    if ($FoundNetwork.Count -gt 0) {
        $ReportLines += "NETWORK CONNECTIONS ($($FoundNetwork.Count) found):"
        $FoundNetwork | ForEach-Object { $ReportLines += "  [FOUND] $_" }
        $ReportLines += ""
    }

    if ($FoundFiles.Count -gt 0) {
        $ReportLines += "INSTALLATION DIRECTORIES ($($FoundFiles.Count) found):"
        $FoundFiles | ForEach-Object { $ReportLines += "  [FOUND] $_" }
        $ReportLines += ""
    }

    $ReportLines += "-" * 60
    if ($TotalFindings -gt 0) {
        $ReportLines += "SUMMARY: $TotalFindings finding(s) detected."
        $ReportLines += "WARNING: Verify whether these tools were installed by your IT provider."
        $ReportLines += "         Unauthorized RMM software may indicate a compromised system."
    } else {
        $ReportLines += "SUMMARY: No RMM software detected."
    }
    $ReportLines += "-" * 60

    try {
        $ReportLines | Out-File -FilePath $OutputFile -Encoding UTF8
        if (-not $Silent -and -not $Json) {
            Write-Host "Report saved to: $OutputFile" -ForegroundColor Green
        }
    } catch {
        if (-not $Silent -and -not $Json) {
            Write-Host "Could not save report to $OutputFile" -ForegroundColor Red
        }
    }
}
