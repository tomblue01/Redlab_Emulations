# EDR Testing Script - Attack Techniques Summary

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
- Creates a scheduled task named "spawn"
- Task configured to execute malicious payload at specified intervals

**EDR should detect:**
- `schtasks.exe` execution or PowerShell calls to ScheduledTasks module
- New scheduled task creation
- Task parameters and execution path
- Registry modifications: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`

---

## 3. PRIVILEGE ESCALATION (T1548.002 - UAC Bypass via Fodhelper)
**What it does:**
- Modifies registry to abuse Windows Fodhelper.exe auto-elevation
- Creates registry key: `HKCU\Software\Classes\ms-settings\shell\open\command`
- Launches fodhelper.exe which triggers the bypass

**EDR should detect:**
- Registry modifications under `HKCU\Software\Classes\`
- `fodhelper.exe` execution with suspicious parent process
- Process spawning from auto-elevated context

---

## 4. DEFENSE EVASION

### T1562.001 - Disable Windows Defender
**What it does:**
- Executes commands to disable/tamper with Windows Defender
- Typically uses `Set-MpPreference` or registry modifications

**EDR should detect:**
- `powershell.exe` with Defender-related cmdlets
- Registry changes: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
- Service tampering attempts
- Defender feature modifications (real-time protection, cloud protection, etc.)

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

### T1082 - System Information Discovery
**What it does:**
- Executes `systeminfo`, `wmic`, or registry queries
- Gathers OS version, patches, hardware info

**EDR should detect:**
- Native Windows reconnaissance binaries
- Multiple info-gathering commands in sequence
- WMIC queries for system data

### T1057 - Process Discovery
**What it does:**
- Runs `tasklist`, `Get-Process`, or `wmic process`
- Enumerates running processes

**EDR should detect:**
- Process enumeration APIs
- Tasklist execution
- WMIC process queries

### T1049 - System Network Connections Discovery
**What it does:**
- Executes `netstat -ano` or similar
- Discovers active network connections

**EDR should detect:**
- `netstat.exe` execution
- Network enumeration commands

### T1018 - Remote System Discovery
**What it does:**
- Runs `arp -a` command
- Saves network reconnaissance to `network_recon.txt`

**EDR should detect:**
- Network scanning commands
- ARP table enumeration
- File creation with recon data

---

## 7. COMMAND AND CONTROL

### T1105 - Tool Transfer (PowerShell)
**What it does:**
- Uses `Invoke-WebRequest` to download file from internet
- Downloads to `%TEMP%\c2_payload.txt`

**EDR should detect:**
- PowerShell with web request cmdlets
- Outbound HTTP/HTTPS connections from PowerShell
- File downloads to temp directories
- Suspicious user-agent strings

### T1197 - BITS Jobs
**What it does:**
- Creates Background Intelligent Transfer Service (BITS) job
- Uses BITS for stealthy file download

**EDR should detect:**
- BITS job creation via `bitsadmin.exe` or PowerShell
- New BITS transfer jobs
- Network connections associated with BITS
- Downloaded files from BITS cache

---

## 8. IMPACT (T1490 - Inhibit System Recovery)
**What it does:**
- Disables Windows System Restore via registry modification
- Modifies: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\DisableSR`

**EDR should detect:**
- Registry modifications disabling recovery features
- Changes to System Restore settings
- `vssadmin.exe` if shadow copies are deleted
- Suspicious registry writes to backup/recovery keys

---

## Summary of Critical EDR Alerts Expected

### **HIGH SEVERITY (Should be BLOCKED):**
1. LSASS memory access/dumping
2. Windows Defender disablement
3. UAC bypass attempts
4. Credential dumping tool execution

### **MEDIUM SEVERITY (Should be ALERTED):**
1. Scheduled task creation for persistence
2. Script execution (VBScript, encoded PowerShell)
3. LOLBin abuse (certutil, BITS)
4. Masquerading executables
5. System recovery inhibition

### **LOW/INFO SEVERITY:**
1. Network/system reconnaissance commands
2. Process enumeration
3. Web downloads via PowerShell

---

## Files Created During Testing
- `Attack-Simulation-Log.txt` - Script execution log
- `Atomic-Execution-Log.csv` - Atomic test execution details
- `temp-recon.vbs` - VBScript file (auto-cleaned)
- `network_recon.txt` - ARP scan results
- `lsass.dmp` - LSASS memory dump (if not blocked)
- `%TEMP%\svchost.exe` - Masqueraded PowerShell
- `%TEMP%\c2_payload.txt` - Downloaded file
- `%TEMP%\SysinternalsSuite\*` - Downloaded tools

---

## Expected EDR Log Patterns

**Process Chains to Watch For:**
```
powershell.exe → cscript.exe → cmd.exe
powershell.exe → fodhelper.exe
powershell.exe → schtasks.exe
powershell.exe → certutil.exe
powershell.exe → bitsadmin.exe
procdump64.exe → lsass.exe (handle request)
svchost.exe [from wrong path]
```

**Command-Line Indicators:**
- `-EncodedCommand`
- `-urlcache`
- `/create /tn`
- `-accepteula -ma lsass.exe`
- `Set-MpPreference -Disable*`
- `DisableSR`

**Network Activity:**
- Downloads from raw.githubusercontent.com
- Downloads from sysinternals.com
- HTTP requests from PowerShell/certutil
- BITS transfers

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
