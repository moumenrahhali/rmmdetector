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

.PARAMETER Notify
    Show a Windows notification popup when RMM activity is detected.
    In regular scan mode: notifies if any active (ESTABLISHED) RMM connections are found.
    In monitor mode: notifies each time a new active connection is detected.

.PARAMETER Monitor
    Enable continuous monitoring mode. Polls for active RMM connections at the
    specified interval and immediately shows a notification popup when a new
    connection is detected. Press Ctrl+C to stop.

.PARAMETER MonitorInterval
    Seconds between checks in monitor mode (default: 10).

.EXAMPLE
    .\detector.ps1
    .\detector.ps1 -Silent
    .\detector.ps1 -Json
    .\detector.ps1 -OutputFile "C:\Temp\my_report.txt"
    .\detector.ps1 -Notify
    .\detector.ps1 -Monitor
    .\detector.ps1 -Monitor -MonitorInterval 5

.NOTES
    Run as Administrator for complete results.
    Compatible with Windows 10, Windows 11, and Windows Server.
#>

[CmdletBinding()]
param(
    [switch]$Silent,
    [switch]$Json,
    [string]$OutputFile = "rmm_report.txt",
    [string]$SignaturesFile = "",
    [switch]$Notify,
    [switch]$Monitor,
    [int]$MonitorInterval = 10
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

# ─── Notification ─────────────────────────────────────────────────────────────

function Send-WindowsNotification {
    <#
    .SYNOPSIS
        Show a Windows notification popup. Tries Toast notifications first
        (Windows 10+), then falls back to a system-tray balloon tip.
    #>
    param(
        [string]$Title   = "RMM Detector Alert",
        [string]$Message = "RMM activity detected."
    )

    $notified = $false

    # Method 1: Windows Toast Notification (Windows 10 / Server 2019+)
    try {
        [void][Windows.UI.Notifications.ToastNotificationManager,
               Windows.UI.Notifications, ContentType = WindowsRuntime]
        [void][Windows.Data.Xml.Dom.XmlDocument,
               Windows.Data.Xml.Dom, ContentType = WindowsRuntime]

        $titleEsc   = [System.Security.SecurityElement]::Escape($Title)
        $messageEsc = [System.Security.SecurityElement]::Escape($Message)
        $toastXml   = "<toast><visual><binding template='ToastGeneric'>" +
                      "<text>$titleEsc</text>" +
                      "<text>$messageEsc</text>" +
                      "</binding></visual></toast>"

        $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xmlDoc.LoadXml($toastXml)
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xmlDoc)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(
            'RMM Detector').Show($toast)
        $notified = $true
    } catch {}

    # Method 2: Fallback – system-tray balloon tip via Windows Forms
    if (-not $notified) {
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            Add-Type -AssemblyName System.Drawing      -ErrorAction Stop

            $balloon = New-Object System.Windows.Forms.NotifyIcon
            $balloon.Icon              = [System.Drawing.SystemIcons]::Warning
            $balloon.BalloonTipIcon    = [System.Windows.Forms.ToolTipIcon]::Warning
            $balloon.BalloonTipTitle   = $Title
            $balloon.BalloonTipText    = $Message
            $balloon.Visible           = $true
            $balloon.ShowBalloonTip(10000)
            Start-Sleep -Milliseconds 500
            $balloon.Dispose()
            $notified = $true
        } catch {}
    }

    if (-not $notified -and -not $Silent -and -not $Json) {
        Write-Host "[NOTIFY] $Title - $Message" -ForegroundColor Magenta
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

# Returns only ESTABLISHED connections – used to determine if a session is
# actively in progress (someone is currently connected).
function Get-ActiveRMMConnections {
    $found     = [System.Collections.Generic.HashSet[string]]::new()
    $rmmPorts  = @(5938, 7070, 21115, 21116, 21117, 21118, 21119, 8040, 4343,
                   9000, 9001, 6129, 55510, 8200, 21121)

    try {
        $connections = Get-NetTCPConnection -State Established 2>$null |
                       Where-Object { $_.RemoteAddress -notin @('0.0.0.0', '::', '127.0.0.1', '::1') }

        foreach ($conn in $connections) {
            if ($rmmPorts -contains $conn.RemotePort) {
                $portInfo = switch ($conn.RemotePort) {
                    5938  { "TeamViewer" }
                    7070  { "ScreenConnect/ConnectWise Control" }
                    21115 { "AnyDesk" }
                    21116 { "AnyDesk" }
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

                [void]$found.Add("Port $($conn.RemotePort) ($portInfo) -> $($conn.RemoteAddress) [ESTABLISHED]")
            }
        }
    } catch {}

    return [string[]]$found
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

    # ── Notification after regular scan ──────────────────────────────────────
    # If -Notify is specified, check for active (ESTABLISHED) connections and
    # immediately show a popup to alert the user that someone is connected now.
    if ($Notify) {
        $ActiveConns = Get-ActiveRMMConnections
        if ($ActiveConns.Count -gt 0) {
            $connList = $ActiveConns -join "`n"
            Send-WindowsNotification `
                -Title   "⚠ RMM ALERT: Active Connection Detected!" `
                -Message "Someone is actively connected via RMM on $ComputerName.`n$connList"
        } elseif ($TotalFindings -gt 0) {
            Send-WindowsNotification `
                -Title   "RMM Detector: Software Found" `
                -Message "$TotalFindings RMM finding(s) detected on $ComputerName. No active session right now."
        }
    }
}

# ─── Monitor Mode ─────────────────────────────────────────────────────────────
# Run AFTER the regular scan block so the full scan still executes first when
# -Monitor is combined with a regular run.

if ($Monitor) {
    if (-not $Silent -and -not $Json) {
        Write-Host ""
        Write-Host ("=" * 50) -ForegroundColor Cyan
        Write-Host "  ACTIVE CONNECTION MONITOR" -ForegroundColor Cyan
        Write-Host ("=" * 50) -ForegroundColor Cyan
        Write-Host "  Watching for active RMM sessions every $MonitorInterval second(s)."
        Write-Host "  A notification popup will appear instantly when"
        Write-Host "  someone connects via a known RMM tool."
        Write-Host "  Press Ctrl+C to stop monitoring."
        Write-Host ("=" * 50) -ForegroundColor Cyan
        Write-Host ""
    }

    $PreviousConnections = [System.Collections.Generic.HashSet[string]]::new()

    while ($true) {
        $CurrentConnections = [System.Collections.Generic.HashSet[string]]::new(
            [string[]](Get-ActiveRMMConnections),
            [System.StringComparer]::OrdinalIgnoreCase
        )

        # Find newly-established connections not seen in the previous check
        $NewConnections = $CurrentConnections | Where-Object { -not $PreviousConnections.Contains($_) }

        if ($NewConnections.Count -gt 0) {
            $timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $connList   = $NewConnections -join "`n"

            if (-not $Silent -and -not $Json) {
                Write-Host ""
                Write-Host "[ALERT] $timestamp  New active RMM connection(s) detected on $ComputerName!" `
                    -ForegroundColor Red
                $NewConnections | ForEach-Object {
                    Write-Host "  >> $_" -ForegroundColor Yellow
                }
            }

            # Always fire the popup in monitor mode (regardless of -Notify flag)
            Send-WindowsNotification `
                -Title   "⚠ RMM ALERT: Someone Is Connected!" `
                -Message "Active RMM session on $ComputerName ($timestamp)`n$connList"
        }

        # Also report dropped connections
        $DroppedConnections = $PreviousConnections | Where-Object { -not $CurrentConnections.Contains($_) }
        if ($DroppedConnections.Count -gt 0 -and -not $Silent -and -not $Json) {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host ""
            Write-Host "[INFO]  $timestamp  RMM connection(s) ended:" -ForegroundColor Gray
            $DroppedConnections | ForEach-Object {
                Write-Host "  -- $_" -ForegroundColor DarkGray
            }
        }

        $PreviousConnections = $CurrentConnections

        if ($CurrentConnections.Count -gt 0 -and -not $Silent -and -not $Json) {
            Write-Host "  [ACTIVE] $($CurrentConnections.Count) RMM session(s) in progress..." `
                -ForegroundColor Red
        }

        Start-Sleep -Seconds $MonitorInterval
    }
}
