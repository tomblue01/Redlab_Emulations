# EDR Testing Script - Attack Techniques Summary

**✅ VERIFIED FROM SOURCE:** This summary has been verified against the actual Atomic Red Team repository at https://github.com/redcanaryco/atomic-red-team/tree/master/atomics

All test numbers, technique IDs, task names, and manually-coded attacks have been confirmed against source code.

---

## 1. EXECUTION (T1059.005 - Visual Basic)
**What it does:**
- Creates and executes a VBScript file (`temp-recon.vbs`)
- VBScript launches `cmd.exe` to run `whoami` and `hostname`

**EDR should detect:**
- `cscript.exe` spawning `cmd.exe`
- File creation in script directory (`.vbs` file)
- Command-line parameters with reconnaissance commands

---

## 2. PERSISTENCE (T1053.005 - Scheduled Task)
**What it does:**
- Uses Atomic Test #2 to create a scheduled task named "spawn"
- Task is created using PowerShell with XML configuration
- Uses `Invoke-CimMethod` for task registration

**EDR should detect:**
- PowerShell execution with `Invoke-CimMethod` or `Register-ScheduledTask` cmdlets
- CIM/WMI queries to `PS_ScheduledTask` namespace
- New scheduled task creation (task name: "spawn")
- Task parameters and execution path
- Registry modifications: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`

---

## 3. PRIVILEGE ESCALATION (T1548.002 - UAC Bypass via Fodhelper)
**What it does:**
- Uses Atomic Test #3 - "Bypass UAC using Fodhelper"
- Creates registry entries:
  - `HKCU\Software\Classes\.pwn\Shell\Open\command` (sets calc.exe)
  - `HKCU\Software\Classes\ms-settings\CurVer` (points to .pwn)
- Launches `fodhelper.exe` which auto-elevates and executes the registry command

**EDR should detect:**
- Registry modifications under `HKCU\Software\Classes\`
- Specifically: `.pwn`, `ms-settings\CurVer` keys
- `fodhelper.exe` execution (legitimate Windows binary)
- `fodhelper.exe` spawning unusual child process (like calc.exe or cmd.exe)
- Process spawning from auto-elevated context without UAC prompt

---

## 4. DEFENSE EVASION

### T1562.001 - Disable Windows Defender
**What it does:**
- Uses Atomic Test #17 - "Tamper with Windows Defender Command Prompt"
- Executes via command prompt (not PowerShell):
  - `sc stop WinDefend` - Stops the Windows Defender service
  - `sc config WinDefend start=disabled` - Disables auto-start
  - `sc query WinDefend` - Queries service status
- **NOTE:** These commands require SYSTEM privileges, will typically fail as Admin

**EDR should detect:**
- `sc.exe` or `cmd.exe` attempting to stop/disable WinDefend service
- Service control commands targeting Windows Defender
- Registry changes in:
  - Service configuration keys for WinDefend
- Multiple attempts to modify Defender service state
- Commands like `sc stop WinDefend`, `sc config WinDefend start=disabled`

### T1027 - Obfuscated Commands
**What it does:**
- Executes Base64-encoded PowerShell command
- Command: `powershell.exe -EncodedCommand <base64>`

**EDR should detect:**
- PowerShell with `-EncodedCommand` parameter
- Encoded command string in command line
- Decoded command content (if EDR has decoding capability)

### T1105 - Ingress Tool Transfer (certutil)
**What it does:**
- Uses `certutil.exe -urlcache` to download file from internet
- Common LOLBin (Living Off the Land Binary) technique

**EDR should detect:**
- `certutil.exe` with `-urlcache` or `-verifyctl` parameters
- Network connections from certutil
- File downloads to suspicious locations

### T1036.003 - Masquerading
**What it does:**
- Copies `powershell.exe` to `%TEMP%\svchost.exe`
- Executes the renamed binary

**EDR should detect:**
- File copy operations creating executables in temp directories
- Known legitimate binary (PowerShell) running from unusual path
- Process with trusted name (`svchost.exe`) from wrong location
- Missing digital signature verification

---

## 5. CREDENTIAL ACCESS (T1003.001 - LSASS Dump)
**What it does:**
- Downloads SysInternals Suite
- Uses `procdump64.exe` to dump LSASS process memory
- Creates `lsass.dmp` file

**EDR should detect (and BLOCK):**
- Download of Sysinternals tools
- `procdump64.exe` execution
- Process handle requests to `lsass.exe`
- `PROCESS_VM_READ` access to LSASS
- `.dmp` file creation containing LSASS memory
- **This should be BLOCKED by any decent EDR**

---

## 6. DISCOVERY

### Multiple Discovery Techniques
**What it does:**
- T1082 Test #1: System Information Discovery (systeminfo, hostname, ver commands)
- T1057 Test #2: Process Discovery (tasklist or Get-Process)
- T1049 Test #1: System Network Connections Discovery (netstat)

**EDR should detect:**
- Rapid succession of reconnaissance commands
- `systeminfo.exe`, `hostname.exe` execution
- `tasklist.exe` or PowerShell `Get-Process`
- `netstat.exe` with parameters
- Multiple info-gathering commands in short timeframe

### T1018 - Remote System Discovery  
**What it does:**
- Executes `arp -a` to enumerate network neighbors
- Saves output to `network_recon.txt` in script directory
- Identifies other systems on the local network

**EDR should detect:**
- `arp.exe` execution with `-a` parameter
- ARP table enumeration
- File creation with reconnaissance data in script directory

---

## 7. COMMAND AND CONTROL

### T1105 - Tool Transfer (PowerShell)
**What it does:**
- Uses `Invoke-WebRequest` to download from https://www.bing.com/robots.txt
- Saves to `%TEMP%\c2_payload.txt`
- Simulates downloading external payload

**EDR should detect:**
- `powershell.exe` with `Invoke-WebRequest` or `IWR` cmdlet
- Outbound HTTPS connection to bing.com from PowerShell
- File download to temp directory
- Network connection initiating from scripting engine

### T1197 - BITS Jobs
**What it does:**
- Uses Atomic Test #2 - PowerShell version of BITS job creation
- Creates Background Intelligent Transfer Service job for file download
- More stealthy than direct downloads

**EDR should detect:**
- PowerShell executing BITS-related cmdlets (`Start-BitsTransfer`)
- New BITS transfer job creation
- BITS service activity (`bitsadmin.exe` or PowerShell BITS cmdlets)
- Network connections associated with BITS service
- Downloaded files through BITS cache

---

## 8. IMPACT (T1490 - Inhibit System Recovery)
**What it does:**
- Uses Atomic Test #9 - "Disable System Restore Through Registry"
- Modifies registry: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\DisableSR` = 1
- Prevents Windows System Restore functionality
- No prerequisites needed (pure registry modification)

**EDR should detect:**
- Registry write to SystemRestore key
- `DisableSR` value being set to 1
- PowerShell or reg.exe modifying system recovery settings
- Changes to backup/recovery registry keys
- Potential correlation with other ransomware-like behavior

---

## Summary of Critical EDR Alerts Expected

### **HIGH SEVERITY (Should be BLOCKED):**
1. **LSASS memory access/dumping** - Any attempt to read LSASS memory
2. **Windows Defender disablement** - Registry or service modifications
3. **UAC bypass attempts** - Fodhelper abuse via registry
4. **Credential dumping tool execution** - Procdump with LSASS target

### **MEDIUM SEVERITY (Should be ALERTED):**
1. **Scheduled task creation for persistence** - Task named "spawn"
2. **Script execution** - VBScript and encoded PowerShell
3. **LOLBin abuse** - certutil, BITS for downloads
4. **Process masquerading** - svchost.exe from %TEMP%
5. **System recovery inhibition** - DisableSR registry modification
6. **Multiple reconnaissance commands** - Discovery technique chaining

### **LOW/INFO SEVERITY:**
1. **Network/system reconnaissance commands** - systeminfo, netstat, arp
2. **Process enumeration** - tasklist execution
3. **Web downloads via PowerShell** - Invoke-WebRequest usage

---

## Important Notes About Test Execution

### Cleanup Behavior
The script includes **automatic cleanup before each test** to prevent "already exists" errors. However, if the script is interrupted, you should manually run the cleanup commands displayed at the end of execution.

### Expected Test Outcomes
- **LSASS Dump (T1003.001)**: Should FAIL with "Access Denied" - this is correct behavior
- **Defender Tampering (T1562.001)**: May be partially blocked or logged
- **UAC Bypass (T1548.002)**: May succeed on systems with default UAC settings
- **Masquerading (T1036.003)**: Should trigger alerts but will execute
- **Reconnaissance (T1082, T1057, etc.)**: Will succeed but should be logged

---

## Files Created During Testing
- `Attack-Simulation-Log.txt` - Script execution log in script directory
- `Atomic-Execution-Log.csv` - Atomic test execution details in script directory
- `temp-recon.vbs` - VBScript file (auto-cleaned after execution)
- `network_recon.txt` - ARP scan results in script directory
- `lsass.dmp` - LSASS memory dump in script directory (if not blocked by EDR)
- `%TEMP%\svchost.exe` - Masqueraded PowerShell copy
- `%TEMP%\c2_payload.txt` - Downloaded test file (robots.txt from bing.com)
- `%TEMP%\SysinternalsSuite.zip` - Downloaded Sysinternals tools
- `%TEMP%\SysinternalsSuite\*` - Extracted tools including procdump64.exe

---

## Expected EDR Log Patterns

**Process Chains to Watch For:**
```
powershell.exe [running script] → cscript.exe → cmd.exe → whoami.exe / hostname.exe
powershell.exe → Invoke-CimMethod (scheduled task creation)
powershell.exe → reg.exe (UAC bypass registry modifications)
fodhelper.exe → cmd.exe / calc.exe (from wrong parent, indicates UAC bypass)
powershell.exe → certutil.exe (file download via LOLBin)
%TEMP%\svchost.exe [masqueraded PowerShell]
powershell.exe → procdump64.exe → lsass.exe (LSASS dump attempt)
powershell.exe → arp.exe
powershell.exe → Invoke-WebRequest (C2 download)
powershell.exe → Start-BitsTransfer (BITS job)
```

**Command-Line Indicators:**
- `-EncodedCommand` (Base64 encoded PowerShell)
- `-urlcache` or `-verifyctl` (certutil downloading)
- `Invoke-CimMethod -ClassName PS_ScheduledTask` (task creation)
- `reg add "HKCU\Software\Classes\.pwn"` (UAC bypass)
- `start fodhelper.exe` (UAC bypass trigger)
- `-accepteula -ma lsass.exe` (procdump LSASS dump)
- `Set-MpPreference -Disable*` (Defender tampering - may vary by test)
- `DisableSR` (System Restore disabling)
- `Invoke-WebRequest -Uri` (web downloads)
- `Start-BitsTransfer` (BITS transfers)
- `arp -a` (network reconnaissance)
- `Copy-Item` to `%TEMP%\svchost.exe` (masquerading)

**Network Activity:**
- Downloads from raw.githubusercontent.com (Atomic Red Team test files)
- Downloads from download.sysinternals.com (Sysinternals Suite)
- HTTPS to bing.com/robots.txt (C2 simulation download)
- HTTPS requests from PowerShell process
- HTTP requests from certutil.exe (Atomic test #7 for T1105)
- BITS service network transfers

---

## Testing Recommendations

✅ **Good EDR should:**
- Block LSASS access completely
- Alert on all Defender tampering attempts
- Detect and flag UAC bypass techniques
- Identify LOLBin abuse patterns
- Correlate multiple reconnaissance commands
- Flag masqueraded executables

⚠️ **If these succeed without alerts, investigate:**
- EDR configuration/tuning
- Rule coverage gaps
- Process monitoring depth
- Memory protection capabilities
