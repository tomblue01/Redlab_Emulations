# Attack Chain Emulation Script - attackchain.ps1

A comprehensive PowerShell script for testing security systems using MITRE ATT&CK techniques via the Atomic Red Team framework.

## ⚠️ WARNING - AUTHORIZED USE ONLY

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║  ⚠️  THIS SCRIPT EXECUTES REAL ATTACK TECHNIQUES  ⚠️                     ║
║                                                                           ║
║  ❌ DO NOT RUN ON PRODUCTION SYSTEMS                                     ║
║  ❌ DO NOT RUN WITHOUT EXPLICIT AUTHORIZATION                            ║
║  ❌ DO NOT RUN ON NETWORKS YOU DON'T OWN                                 ║
║                                                                           ║
║  ✅ FOR AUTHORIZED SECURITY TESTING ONLY                                 ║
║  ✅ USE ONLY IN ISOLATED LAB ENVIRONMENTS                                ║
║  ✅ OBTAIN WRITTEN PERMISSION BEFORE USE                                 ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

**UNAUTHORIZED USE OF THIS SCRIPT MAY:**
- Violate computer fraud and abuse laws
- Trigger security incidents and investigations
- Cause system instability or data loss
- Result in civil and criminal penalties
- Lead to termination of employment

**YOU ARE RESPONSIBLE** for ensuring you have proper authorization before running this script.

## 🎯 Overview

This script (v1.8.2) automates the execution of adversary tactics and techniques to test security system detection capabilities. It chains together multiple MITRE ATT&CK techniques across the attack lifecycle, from initial execution to impact, simulating realistic adversary behavior.

### What This Script Does

The script executes a sequential chain of attack techniques organized by MITRE ATT&CK tactics:

1. **Execution** - VBScript execution for reconnaissance
2. **Persistence** - Scheduled task creation
3. **Privilege Escalation** - UAC bypass attempts
4. **Defense Evasion** - Defender tampering, encoded commands, file masquerading, ingress tool transfer
5. **Credential Access** - LSASS memory dumping attempts
6. **Discovery** - System and network reconnaissance
7. **Command & Control** - File downloads and BITS jobs
8. **Impact** - System recovery inhibition

### Key Features

✅ **Automatic Prerequisites Check** - Verifies PowerShell version, admin rights, disk space, and network connectivity  
✅ **GitHub Installation** - Automatically installs Invoke-AtomicRedTeam from official Red Canary GitHub  
✅ **Windows Version Detection** - Detects Windows 10 vs 11 and adjusts expectations accordingly  
✅ **Automatic Cleanup** - Removes artifacts from previous runs before starting  
✅ **Robust Error Handling** - Continues execution even if individual tests fail  
✅ **Network Retry Logic** - Automatically retries failed downloads  
✅ **Detailed Logging** - Creates comprehensive execution logs (CSV and text)  
✅ **Non-Interactive** - Runs without user prompts or hangs  
✅ **Idempotent Design** - Can be safely run multiple times

## 🔧 Requirements

### System Requirements
- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or higher (automatically verified)
- **Privileges**: **Administrator rights required** (automatically verified)
- **Internet Connection**: Required for initial Atomic Red Team download
- **Disk Space**: ~200MB minimum, ~500MB recommended (automatically verified)

### Software Dependencies
- PowerShell Execution Policy must allow script execution (`RemoteSigned` or less restrictive)
- .NET Framework 4.5 or higher
- TLS 1.2 capable system (automatically configured)

**Note**: The script will automatically install the Invoke-AtomicRedTeam module from GitHub if not present.

## 🛡️ Windows Defender Exclusions (REQUIRED)

**⚠️ CRITICAL: You MUST configure Windows Defender exclusions BEFORE running the script.**

### Why Exclusions Are Needed

This script contains legitimate attack simulation code that Windows Defender and AMSI (Antimalware Scan Interface) will flag as malicious. This is expected behavior - the script executes real attack techniques for testing purposes.

**Common Error Without Exclusions:**
```
This script contains malicious content and has been blocked by your antivirus software.
CategoryInfo: ParserError: (:) [], ParseException
FullyQualifiedErrorId: ScriptContainedMaliciousContent
```

### Windows 11 vs Windows 10 Differences

**Windows 11:**
- Tamper Protection is typically **enabled by default**
- You may need to disable Tamper Protection before adding exclusions
- Stricter default security settings

**Windows 10:**
- Tamper Protection often **not enabled by default** (varies by build)
- Generally easier to configure exclusions
- Less restrictive default configuration

**Note**
If Windows Defender Service is not running, you will NOT need exclusions. You can test by running the following in Powershell: 

```Get-Service WinDefend | Select Status, StartType```

If status is "Stopped", exclusions are not required (and the following commands will probably error out at any rate). 

### Step 1: Add Required Exclusions

**IMPORTANT:** Run these commands in PowerShell as Administrator **BEFORE** running the attack simulation script.

#### Run These PowerShell Commands 

```powershell
# Add folder exclusions for script and atomics locations
Add-MpPreference -ExclusionPath "C:\shared"
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"

# Optional: Add PowerShell process exclusion for more comprehensive testing
Add-MpPreference -ExclusionProcess "powershell.exe"

# Verify exclusions were added successfully
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess
```

**Note:** Adjust the path `C:\shared` if your script is located elsewhere.

### Step 2: Optional: Verify Configuration

After adding exclusions, verify they're active:

```powershell
# Verify exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

## 📋 Installation

### Quick Start

1. **Open PowerShell as Administrator**
   - Right-click PowerShell and select **"Run as Administrator"**

2. **Set Execution Policy (if needed)**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Download the Script**
   ```powershell
   # Option 1: Clone repository
   git clone https://github.com/tomblue01/Redlab_Emulations.git
   cd edr-attack-simulation
   
   # Option 2: Direct download
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yourusername/edr-attack-simulation/main/attackchain.ps1" -OutFile "attackchain.ps1"
   ```

4. **Run the Script**
   ```powershell
   .\attackchain.ps1
   ```

## 🚀 Usage

### Running the Script

```powershell
# Navigate to script directory
cd C:\path\to\script

# Run the script
.\attackchain.ps1
```

### What Happens During Execution

**Phase 1: Prerequisites (1-5 minutes first run, <30 seconds subsequent runs)**
- Detects Windows version and PowerShell version
- Checks for administrator privileges
- Verifies execution policy
- Tests network connectivity
- Checks available disk space
- Downloads and installs Invoke-AtomicRedTeam module from GitHub (first run only)
- Downloads Atomic Red Team test library (first run only)

**Phase 2: Initial Cleanup (<10 seconds)**
- Removes any artifacts from previous script runs

**Phase 3: Attack Chain Execution (5-10 minutes)**
- Executes 8 MITRE ATT&CK tactics sequentially
- Each tactic runs cleanup before execution to prevent conflicts
- All actions are logged to both text and CSV files

**Phase 4: Completion**
- Displays cleanup commands for manual artifact removal
- Shows log file locations

### Expected Runtime

- **First run**: 10-15 minutes (includes module installation and atomic library download)
- **Subsequent runs**: 5-10 minutes

### Script Output

The script provides color-coded console output:
- **WHITE** - Informational messages
- **YELLOW** - Warnings
- **RED** - Errors
- **GREEN** - Success messages

## 📊 MITRE ATT&CK Techniques Executed

| Tactic | Technique ID | Technique Name | Test Description |
|--------|--------------|----------------|------------------|
| Execution | T1059.005 | VBScript | CScript execution for reconnaissance |
| Persistence | T1053.005 | Scheduled Task | Local scheduled task creation (test #2) |
| Privilege Escalation | T1548.002 | Bypass UAC | Fodhelper UAC bypass (test #3) |
| Defense Evasion | T1562.001 | Impair Defenses | Windows Defender command prompt tampering (test #17) |
| Defense Evasion | T1027 | Obfuscated Files | Base64 encoded PowerShell commands |
| Defense Evasion | T1105 | Ingress Tool Transfer | File download via certutil (test #7) |
| Defense Evasion | T1036.003 | Masquerading | Process masquerading (svchost.exe) |
| Credential Access | T1003.001 | LSASS Memory | ProcDump LSASS memory dumping attempt |
| Discovery | T1082 | System Information | System enumeration (test #1) |
| Discovery | T1057 | Process Discovery | Process list enumeration (test #2) |
| Discovery | T1049 | Network Connections | Network connection enumeration (test #1) |
| Discovery | T1018 | Remote System Discovery | ARP table enumeration |
| Command & Control | T1105 | Ingress Tool Transfer | File download via Invoke-WebRequest |
| Command & Control | T1197 | BITS Jobs | BITS download job (test #2) |
| Impact | T1490 | Inhibit System Recovery | Disable system restore via registry (test #9) |

## 📝 Output Files

The script generates several files in the script directory:

### Log Files
- **Attack-Simulation-Log.txt** - Detailed timestamped log of all script actions
  - Contains INFO, WARN, ERROR, and SUCCESS messages
  - Use for troubleshooting and detailed analysis
  
- **Atomic-Execution-Log.csv** - CSV format log of Atomic Red Team test executions
  - Contains: Execution Time (UTC/Local), Technique ID, Test Number, Test Name, Hostname, IP Address, Username, GUID, ProcessId, ExitCode
  - Use for analysis, reporting, and correlation with security tool alerts

### Artifact Files (Created During Tests)
- **network_recon.txt** - ARP table output from T1018 discovery
- **lsass.dmp** - LSASS dump file (only if dump succeeds - typically blocked)
- **temp-recon.vbs** - Temporary VBScript file (auto-cleaned)

## 🔍 Analyzing Logs

### View All Logs
```powershell
# View full text log
Get-Content .\Attack-Simulation-Log.txt

# View CSV log as table
Import-Csv .\Atomic-Execution-Log.csv | Format-Table -AutoSize
```

### Filter for Errors Only
```powershell
# Extract all ERROR messages
Get-Content .\Attack-Simulation-Log.txt | Where-Object { $_ -match "\[ERROR\]" }

# Save errors to separate file
Get-Content .\Attack-Simulation-Log.txt | Where-Object { $_ -match "\[ERROR\]" } | Out-File "Errors-Only.txt"
```

### Filter for Warnings and Errors
```powershell
# Extract WARN and ERROR messages
Get-Content .\Attack-Simulation-Log.txt | Where-Object { $_ -match "\[(ERROR|WARN)\]" }
```

### Count Test Results
```powershell
# Count successful tests
(Get-Content .\Attack-Simulation-Log.txt | Where-Object { $_ -match "\[SUCCESS\]" }).Count

# Count failed tests
(Get-Content .\Attack-Simulation-Log.txt | Where-Object { $_ -match "\[ERROR\]" }).Count
```

### Analyze CSV by Technique
```powershell
# Group tests by technique
Import-Csv .\Atomic-Execution-Log.csv | Group-Object -Property Technique | Format-Table Count, Name

# View specific technique details
Import-Csv .\Atomic-Execution-Log.csv | Where-Object { $_.Technique -eq "T1053.005" } | Format-List
```

## 🧹 Cleanup

### Automatic Cleanup

The script automatically performs cleanup:
- **Before script execution**: Removes artifacts from any previous runs
- **Before each test**: Runs cleanup for that specific test to prevent conflicts

### Manual Cleanup

If needed, cleanup commands are displayed at the end of each script run. To manually cleanup:

```powershell
# Remove scheduled tasks
schtasks /delete /tn "spawn" /f

# Remove temporary files
Remove-Item (Join-Path $env:TEMP 'svchost.exe') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:TEMP 'c2_payload.txt') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:TEMP 'SysinternalsSuite.zip') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:TEMP 'SysinternalsSuite') -Recurse -Force -ErrorAction SilentlyContinue

# Remove script artifacts
Remove-Item .\lsass.dmp -Force -ErrorAction SilentlyContinue
Remove-Item .\network_recon.txt -Force -ErrorAction SilentlyContinue
Remove-Item .\temp-recon.vbs -Force -ErrorAction SilentlyContinue

# Run Atomic test cleanup commands
Invoke-AtomicTest T1053.005 -TestNumbers 2 -Cleanup
Invoke-AtomicTest T1548.002 -TestNumbers 3 -Cleanup
Invoke-AtomicTest T1562.001 -TestNumbers 17 -Cleanup
Invoke-AtomicTest T1105 -TestNumbers 7 -Cleanup
Invoke-AtomicTest T1197 -TestNumbers 2 -Cleanup
Invoke-AtomicTest T1490 -TestNumbers 9 -Cleanup
```

### Complete System Cleanup

To completely remove Atomic Red Team (optional):
```powershell
Remove-Item C:\AtomicRedTeam -Recurse -Force
```

## 🛠️ Troubleshooting

### Prerequisites Issues

#### Script Blocked by Windows Defender / AMSI

**Symptom**: Error message "This script contains malicious content and has been blocked by your antivirus software"

**Full Error:**
```
At C:\shared\attackchain.ps1:1 char:1
+ <#
+ ~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParseException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

**Cause**: Windows Defender or AMSI is blocking the script because it contains attack simulation code

**Solution**: 
1. **Add exclusions BEFORE running the script** (see [Windows Defender Exclusions](#️-windows-defender-exclusions-required))
2. Verify exclusions were added:
   ```powershell
   Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
   ```
3. If exclusions don't work, check Tamper Protection status:
   ```powershell
   Get-MpComputerStatus | Select-Object IsTamperProtected
   ```
4. Disable Tamper Protection if enabled (via Windows Security GUI)
5. Re-add exclusions and try again

#### Script Requires Administrator Rights

**Symptom**: Error message "This script must be run with Administrator privileges"

**Solution**: 
1. Close PowerShell
2. Right-click PowerShell icon
3. Select "Run as Administrator"
4. Navigate back to script directory and run again

#### Execution Policy Restrictions

**Symptom**: Error "cannot be loaded because running scripts is disabled on this system"

**Solution**:
```powershell
# Check current policy
Get-ExecutionPolicy

# Set to allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Verify change
Get-ExecutionPolicy
```

#### PowerShell Version Too Old

**Symptom**: Error "PowerShell 5.0 or higher is required"

**Solution**: Update Windows Management Framework:
- Windows 10/11: Already includes PowerShell 5.1+
- Windows Server 2012 R2/2016: Install [WMF 5.1](https://www.microsoft.com/en-us/download/details.aspx?id=54616)

### Installation Issues

#### Module Installation Fails - Network Error

**Symptom**: "Failed to install from GitHub" with network-related errors

**Solution**:
1. Verify internet connectivity:
   ```powershell
   Test-NetConnection raw.githubusercontent.com -Port 443
   ```
2. Check firewall/proxy settings
3. Manually install:
   ```powershell
   IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -GetAtomics
   ```

#### Module Installation Fails - TLS Error

**Symptom**: Error about SSL/TLS secure channel

**Solution**:
```powershell
# Enable TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Then run installation manually
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -GetAtomics
```

#### Module Commands Not Available

**Symptom**: "Failed to load 'Invoke-AtomicRedTeam' module commands"

**Solution**:
1. Check if module files exist:
   ```powershell
   Test-Path "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
   ```
2. If missing, delete and reinstall:
   ```powershell
   Remove-Item C:\AtomicRedTeam -Recurse -Force
   # Then run attackchain.ps1 again
   ```
3. Manually import module:
   ```powershell
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
   ```

#### Atomics Library Download Fails

**Symptom**: "Failed to download the Atomics library"

**Solution**:
1. Verify 500MB+ free disk space
2. Check internet connectivity to GitHub
3. Manually download:
   ```powershell
   Install-AtomicRedTeam -GetAtomics -Force
   ```

### Execution Issues

#### Test Hangs or Times Out

**Symptom**: Script appears frozen on a specific test

**Cause**: Previous test artifacts may be causing prompts

**Solution**:
1. Press Ctrl+C to stop script
2. Run manual cleanup (see Cleanup section)
3. Run script again - automatic cleanup should handle it

#### Individual Tests Fail

**Symptom**: Specific techniques show [ERROR] in logs

**Expected Behavior**: Some tests are EXPECTED to fail:
- T1562.001 (Defender tampering) - Often blocked by Tamper Protection
- T1003.001 (LSASS dump) - Should be blocked by security controls

**Investigation**:
1. Check Attack-Simulation-Log.txt for specific error message
2. Extract all errors:
   ```powershell
   Get-Content .\Attack-Simulation-Log.txt | Select-String "ERROR"
   ```
3. Common causes:
   - Security software blocking the test (expected)
   - Missing prerequisites (script should auto-install)
   - Test-specific requirements not met

#### All Tests Fail After Prerequisites

**Symptom**: Prerequisites pass but every test fails

**Solution**:
1. Verify module loaded:
   ```powershell
   Get-Command Invoke-AtomicTest
   ```
2. Check for module errors in log:
   ```powershell
   Get-Content .\Attack-Simulation-Log.txt | Select-String "module"
   ```
3. Try importing module manually and re-running script

### Windows-Specific Issues

#### Windows 11 Specific Behavior

**Note**: Windows 11 has enhanced security that may cause certain tests to behave differently:
- Tamper Protection is typically enabled by default (blocks T1562.001)
- Credential Guard may be enabled (blocks T1003.001)
- These are EXPECTED and indicate good security posture

**Script Behavior**: The script detects Windows 11 and logs warnings about expected differences

#### Windows Server Behavior

**Note**: Windows Server may have different default security settings:
- UAC may be configured differently
- Windows Defender may not be present (Server Core)
- Some tests may require adjustment

### Log Analysis Issues

#### CSV File Won't Open

**Symptom**: Excel shows garbled data or won't open CSV

**Solution**:
```powershell
# View in PowerShell instead
Import-Csv .\Atomic-Execution-Log.csv | Out-GridView

# Or export with proper formatting
Import-Csv .\Atomic-Execution-Log.csv | Export-Csv .\Formatted-Log.csv -NoTypeInformation
```

#### Missing Tests in CSV

**Note**: The CSV only logs tests executed via `Invoke-AtomicTest`. Custom implementations (like VBScript, encoded PowerShell, etc.) appear only in the text log.

**To see all activities**:
```powershell
Get-Content .\Attack-Simulation-Log.txt
```

### Performance Issues

#### Script Runs Very Slowly

**Causes**:
- First run includes large downloads (~500MB atomics library)
- Security software may be scanning each test
- Network latency on downloads

**Solutions**:
- Subsequent runs are much faster
- Temporarily disable antivirus scanning (if authorized)
- Run on system with good network connectivity

#### Disk Space Warnings

**Symptom**: "Low disk space" warning in logs

**Solution**:
1. Free up at least 500MB disk space
2. Consider running on a different drive:
   ```powershell
   # Move script to D: drive (if available)
   Copy-Item .\attackchain.ps1 D:\
   cd D:\
   .\attackchain.ps1
   ```

## 📊 Understanding Test Results

### Exit Codes in CSV

The `Atomic-Execution-Log.csv` contains an `ExitCode` column:
- **0** = Success (test executed successfully)
- **Non-zero** = Test encountered an error

### Log Levels in Text Log

The `Attack-Simulation-Log.txt` uses four log levels:
- **[INFO]** = Informational message
- **[SUCCESS]** = Action completed successfully
- **[WARN]** = Warning - not necessarily an error
- **[ERROR]** = Test or action failed

### Success Criteria

A successful script run means:
✅ All prerequisites passed  
✅ Module and atomics library loaded  
✅ Script completed execution (even if some tests failed)  
✅ Logs were generated  

**Note**: Individual test failures do not mean script failure. Many tests are expected to be blocked by security controls.

## 📚 Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Invoke-AtomicRedTeam Documentation](https://github.com/redcanaryco/invoke-atomicredteam/wiki)
- [Atomic Red Team Testing Guide](https://github.com/redcanaryco/atomic-red-team/wiki/Testing-Guidance)

## ⚖️ Legal Disclaimer

This script is provided for **EDUCATIONAL and AUTHORIZED SECURITY TESTING purposes ONLY**.

**By using this script, you acknowledge that:**

- You have explicit written authorization to test the target system
- You understand the script executes real attack techniques
- You will use this script only in controlled lab environments
- You are responsible for any damage or legal consequences
- The authors assume no liability for misuse or unauthorized use
- You will comply with all applicable laws and regulations

**Misuse of this script may violate:**
- Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030
- Stored Communications Act - 18 U.S.C. § 2701
- State and local computer crime laws
- Organization security policies
- Employment agreements

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [Red Canary](https://redcanary.com/) - Atomic Red Team framework
- [MITRE Corporation](https://www.mitre.org/) - ATT&CK framework
- Security community contributors

---

**Version**: 1.8.2 
**Last Updated**: October 2025

**Remember**: Always test responsibly in authorized lab environments only.
