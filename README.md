# RMM Detector

> **Detect Remote Monitoring & Management (RMM) software on Windows systems and web portals.**

```
  ██████╗ ███╗   ███╗███╗   ███╗
  ██╔══██╗████╗ ████║████╗ ████║
  ██████╔╝██╔████╔██║██╔████╔██║
  ██╔═══╝ ██║╚██╔╝██║██║╚██╔╝██║
  ██║     ██║ ╚═╝ ██║██║ ╚═╝ ██║
  ╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝

  RMM DETECTOR v1.0
  Remote Monitoring Detection Tool
```

---

## What is RMM Software?

**Remote Monitoring & Management (RMM)** tools are used by IT Managed Service Providers (MSPs) to remotely manage and monitor client systems. Legitimate uses include:

- Patch management and software updates
- Remote troubleshooting and support
- System health monitoring
- Security and compliance scanning

## Why Attackers Abuse RMM Tools

Threat actors increasingly abuse legitimate RMM tools because:

- They are **trusted and signed** by operating systems, bypassing endpoint security controls
- They provide **persistent, stealthy remote access** to compromised systems
- Network traffic appears as **normal IT management activity**
- They can be used for **lateral movement**, data exfiltration, and ransomware deployment
- The software is **free to download** and widely available

Notable campaigns: CISA has warned about threat actors using tools like AnyDesk, ScreenConnect, Atera, and others to maintain access to government and critical infrastructure networks.

## How MSPs Legitimately Use RMM Tools

Authorized MSPs deploy RMM agents to:
- Monitor system health, disk, CPU, and memory
- Push patches and software updates remotely
- Respond to alerts and automate remediation
- Provide remote desktop support to end users
- Back up data and enforce security policies

**The key difference:** Legitimate RMM software is deployed with the knowledge and consent of the system owner. If you did not authorize it, treat it as a potential security incident.

---

## Repository Structure

```
rmm-detector/
├── rmm_detector.bat      # Windows launcher (BAT)
├── detector.ps1          # PowerShell detection engine
├── signatures.json       # RMM signatures database
├── rmmdetector.py        # Python web/URL scanner
├── example_report.txt    # Sample scan output
└── README.md
```

---

## Windows RMM Detector

### Requirements

- Windows 10, Windows 11, or Windows Server
- PowerShell 5.0 or later (built into all modern Windows)
- No external dependencies required
- **Recommended:** Run as Administrator for complete results

### Usage

**Standard scan (interactive):**
```batch
rmm_detector.bat
```

**Silent mode** – only show findings, suppress informational output:
```batch
rmm_detector.bat /silent
```

**JSON output** – machine-readable format:
```batch
rmm_detector.bat /json
```

**CSV export** – export a structured CSV alongside the text report:
```batch
rmm_detector.bat /csv
```

**Custom report path:**
```batch
rmm_detector.bat /output C:\Temp\my_report.txt
```

**Notify mode** – show a Windows popup if an active RMM session is detected right now:
```batch
rmm_detector.bat /notify
```

**Monitor mode** – run continuously and show an **instant popup** the moment someone connects:
```batch
rmm_detector.bat /monitor
rmm_detector.bat /monitor /interval 5
```

**Allowlist** – skip tools that your organisation has authorised:
```batch
rmm_detector.bat /allowlist C:\Config\approved_rmm.txt
rmm_detector.bat /allow "TeamViewer,NinjaRMM"
```

**Windows Event Log** – write findings to the Application log for SIEM integration:
```batch
rmm_detector.bat /eventlog
```

**Run PowerShell directly:**
```powershell
.\detector.ps1
.\detector.ps1 -Silent
.\detector.ps1 -Json
.\detector.ps1 -Csv
.\detector.ps1 -OutputFile "C:\Temp\report.txt"
.\detector.ps1 -Notify
.\detector.ps1 -Monitor
.\detector.ps1 -Monitor -MonitorInterval 5
.\detector.ps1 -AllowListFile "C:\Config\approved_rmm.txt"
.\detector.ps1 -AllowList "TeamViewer,NinjaRMM" -EventLog
```

### Windows Notification Popup

RMM Detector can alert you with a **Windows notification popup** when RMM activity is detected.

#### One-time scan with notification (`-Notify` / `/notify`)

After a full scan, if any active (ESTABLISHED) RMM network connections are found—meaning someone
is actively watching your screen **right now**—a popup appears immediately:

```
┌──────────────────────────────────────────────┐
│ ⚠ RMM ALERT: Active Connection Detected!     │
│                                              │
│ Someone is actively connected via RMM on     │
│ WORKSTATION-01.                              │
│ Port 5938 (TeamViewer) -> 203.0.113.5        │
└──────────────────────────────────────────────┘
```

If RMM software is installed but there is no live session, a lower-priority informational popup
is shown instead.

#### Continuous monitor mode (`-Monitor` / `/monitor`)

Run the monitor in the background and get notified **the instant** a new RMM connection is
established—without needing to run a manual scan:

```powershell
.\detector.ps1 -Monitor              # check every 10 seconds (default)
.\detector.ps1 -Monitor -MonitorInterval 5   # check every 5 seconds
```

```batch
rmm_detector.bat /monitor
rmm_detector.bat /monitor /interval 5
```

The tool polls for ESTABLISHED TCP connections on known RMM ports. When a new connection
appears, a Windows Toast notification (or system-tray balloon tip on older Windows) fires
immediately. The console also logs connection-established and connection-dropped events with
timestamps. Press **Ctrl+C** to stop monitoring.

> **Tip:** You can run monitor mode minimized or from a scheduled task at login so it runs
> silently in the background. Pair with `/silent` to suppress all console output.

### Detection Methods

| Method | Description |
|--------|-------------|
| **Running Processes** | Scans all active processes against known RMM agent names |
| **Installed Software** | Queries registry uninstall keys for known RMM products |
| **Windows Services** | Checks running/stopped services against known RMM service names |
| **Startup Entries** | Scans Run/RunOnce registry keys for RMM persistence |
| **Scheduled Tasks** | Enumerates tasks for known RMM keywords |
| **Network Connections** | Flags active connections on known RMM ports (5938, 7070, 21116, etc.) |
| **File System** | Checks Program Files and ProgramData for known installation directories |
| **Active Session Monitor** | Continuously watches for ESTABLISHED RMM connections and fires instant popups |

### Enterprise Features

#### Risk Scoring

Every finding is assigned a risk level:

| Risk | Condition | Console colour |
|------|-----------|----------------|
| **Critical** | Active ESTABLISHED network connection | 🔴 Red |
| **High** | Running process, or high-risk vendor | 🟡 Yellow |
| **Medium** | Installed service or software | 🔵 Cyan |
| **Low** | Registry key, scheduled task, or installation directory only | ⚫ Grey |

Risk levels are persisted in the text report, CSV export, and Windows Event Log entries.

#### Allowlist (Authorised Tools)

Exclude known-good RMM tools from triggering alerts, keeping results focused on
**unauthorised** software only.

**Via command line:**
```powershell
.\detector.ps1 -AllowList "TeamViewer,NinjaRMM"
```
```batch
rmm_detector.bat /allow "TeamViewer,NinjaRMM"
```

**Via file (one name per line or JSON array):**

`C:\Config\approved_rmm.txt`
```
# Lines starting with # are ignored
TeamViewer
NinjaRMM
```

```powershell
.\detector.ps1 -AllowListFile "C:\Config\approved_rmm.txt"
```
```batch
rmm_detector.bat /allowlist C:\Config\approved_rmm.txt
```

Allowlisted items appear in the scan output as `[ALLOWED]` and are excluded from
the total count and exit code evaluation.

#### Windows Event Log Integration

Write scan findings to the **Windows Application Event Log** (Source: `RMMDetector`) for
forwarding to a SIEM or log management platform:

```powershell
.\detector.ps1 -EventLog
```
```batch
rmm_detector.bat /eventlog
```

| Event ID | Entry Type | Trigger |
|----------|-----------|---------|
| 1000 | Information | Scan completed – no unauthorised findings |
| 1001 | Warning | Unauthorised RMM finding(s) detected |
| 1002 | Warning | Monitor mode – new active connection detected |

#### CSV Export

Export a machine-readable CSV alongside the text report for aggregation or ticketing:

```powershell
.\detector.ps1 -Csv
```
```batch
rmm_detector.bat /csv
```

Columns: `ScanTime`, `Computer`, `User`, `Type`, `Item`, `Risk`, `Authorized`

#### Exit Codes

The script returns a meaningful exit code, enabling use in automation pipelines, CI/CD
checks, or scheduled tasks:

| Exit Code | Meaning |
|-----------|---------|
| `0` | No unauthorised findings |
| `1` | Unauthorised findings detected (Medium or Low risk) |
| `2` | High or Critical risk findings detected |

```powershell
.\detector.ps1 -Silent
if ($LASTEXITCODE -ge 2) { Send-Alert "Critical RMM finding!" }
```

#### JSON Output (Enhanced)

The `-Json` output now includes risk levels, allowlist status, and signatures version:

```json
{
  "scan_time": "2024-01-15 14:32:07",
  "computer": "WORKSTATION-01",
  "user": "jsmith",
  "signatures_ver": "2.0.0",
  "total": 2,
  "total_authorized": 1,
  "highest_risk": "High",
  "findings": [
    { "type": "Process", "item": "TeamViewer.exe", "risk": "High" },
    { "type": "Service", "item": "Mesh Agent (MeshAgent) - Status: Running", "risk": "Medium" }
  ],
  "authorized": [
    { "type": "Process", "item": "NinjaRMMAgent.exe" }
  ]
}
```

### Detected Software (Windows)

**RMM Agents:** NinjaOne, Datto RMM, Kaseya VSA, Atera, Pulseway, Action1, Level, N-able, SuperOps, Addigy, TacticalRMM, MeshCentral

**Remote Access:** TeamViewer, AnyDesk, ConnectWise Control (ScreenConnect), Splashtop, GoTo Resolve, LogMeIn, BeyondTrust, Bomgar, RustDesk, SimpleHelp, RemotePC, Zoho Assist, ISL Online, DameWare

**PSA/ITSM:** ConnectWise Manage, Autotask, Kaseya BMS, Syncro, ManageEngine, Accelo

### Example Output

```
====================================================
  RMM DETECTOR SECURITY SCAN
====================================================

Scanning Running Processes...

[FOUND] TeamViewer.exe
[FOUND] NinjaRMMAgent.exe

Scanning Installed Software...

[FOUND] ConnectWise Control (ScreenConnect) 23.4.1

Scanning Services...

[FOUND] TeamViewer (TeamViewer14) - Status: Running
[FOUND] Mesh Agent (MeshAgent) - Status: Running

----------------------------------------------------

  WARNING: Remote Management Software Detected

  2 Running Process(es)
  1 Installed Program(s)
  2 Service(s)

----------------------------------------------------

Recommendation:
  Verify whether these tools were installed by your IT provider.
  Unauthorized RMM software may indicate a compromised system.
```

### JSON Output Example

```json
{
  "scan_time": "2024-01-15 14:32:07",
  "computer": "WORKSTATION-01",
  "user": "jsmith",
  "total": 5,
  "processes": ["TeamViewer.exe", "NinjaRMMAgent.exe"],
  "software": ["ConnectWise Control (ScreenConnect) 23.4.1"],
  "services": ["TeamViewer (TeamViewer14) - Status: Running", "Mesh Agent (MeshAgent) - Status: Running"],
  "startup": [],
  "tasks": ["\\NinjaRMM\\NinjaRMMAgent_Update"],
  "network": [],
  "files": []
}
```

---

## Python Web/URL Scanner (`rmmdetector.py`)

Detects RMM, PSA, and Helpdesk software by scanning a list of company URLs. Useful for MSP partner audits, threat intelligence, and asset discovery.

### Requirements

```bash
pip install requests dnspython beautifulsoup4 urllib3
# Optional: pip install mmh3  (for Shodan-compatible favicon hashing)
```

### Usage

**Input as CSV:**
```bash
python rmmdetector.py companies.csv results.csv
python rmmdetector.py companies.csv results.csv --column "Website"
```

**Input as TXT (one URL per line, first line is header):**
```bash
python rmmdetector.py urls.txt results.csv
```

**Multi-threaded scan:**
```bash
python rmmdetector.py companies.csv results.csv --threads 20
```

**JSON output format:**
```bash
python rmmdetector.py companies.csv results.json --format json
```

**Retry configuration:**
```bash
python rmmdetector.py companies.csv results.csv --retries 3
```

### Web Detection Methods

| Method | Description |
|--------|-------------|
| **DNS CNAME** | Resolves CNAME records to detect vendor hosting |
| **DNS TXT** | Checks TXT records for vendor verification strings |
| **URL Pattern** | Matches domain against known vendor domains |
| **HTTP Redirect** | Follows redirects to vendor-controlled domains |
| **HTTP Headers** | Inspects response headers for vendor fingerprints |
| **Cookies** | Matches cookie names against vendor signatures |
| **Favicon Hash** | Calculates MMH3 hash for Shodan-compatible matching |
| **HTML Source** | Regex scanning of page source for vendor patterns |
| **Asset Paths** | Inspects JS/CSS file paths for vendor CDNs |
| **Meta Tags** | Checks generator and application-name meta tags |
| **Form Analysis** | Fingerprints form fields and IDs |
| **Portal Discovery** | Crawls homepage links to find support/client portals |

### Output

Results are written to a CSV or JSON file with columns/fields:
- `Input URL` – Original URL from input
- `Detected Software` – Identified platform (or "Not Detected")
- `Category` – PSA / RMM / Remote Access / Helpdesk/ITSM
- `Method` – Detection method used
- `Confidence` – Detection confidence score (1=Low, 2=Medium, 3=High)
- `Evidence` – Specific indicator that triggered detection

**Exit codes:**
- `0` – No platforms detected
- `1` – One or more platforms detected

---

## Security Warning

> ⚠️ **This tool is for DETECTION ONLY.**
>
> It will **never** remove, disable, or modify any software.
>
> If you detect unauthorized RMM software:
> 1. **Do not** remove it yourself before consulting a security professional
> 2. **Preserve evidence** – take screenshots and save the report
> 3. **Isolate the system** from the network if active intrusion is suspected
> 4. **Contact** your IT security team or a trusted incident response provider

---

## License

MIT License – See LICENSE file for details.
