# Attack Chain Emulation Script - attackchain.ps1

This Script is an emulation script leverating powershell and Atomic RedTeam tools. 

USE AT YOUR OWN RISK!!! 

This script is not meant for production systems!!

USE IN A LAB ENVIRONMENT! 

The script is designed to emulate a complete attack chain and can be used to create events and logs for various security systems like enpoint security and EDR. 

The Author assumes NO Responsibility for the use or misuse of this script.

# EDR Attack Simulation Script

A comprehensive PowerShell script for testing Endpoint Detection and Response (EDR) solutions using MITRE ATT&CK techniques via the Atomic Red Team framework.

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

This script automates the execution of adversary tactics and techniques to test EDR detection capabilities. It chains together multiple MITRE ATT&CK techniques across the attack lifecycle, from initial execution to impact, simulating realistic adversary behavior.

### What This Script Does

The script executes a sequential chain of attack techniques organized by MITRE ATT&CK tactics:

1. **Execution** - VBScript execution for reconnaissance
2. **Persistence** - Scheduled task creation
3. **Privilege Escalation** - UAC bypass attempts
4. **Defense Evasion** - Defender tampering, encoded commands, file masquerading
5. **Credential Access** - LSASS memory dumping attempts
6. **Discovery** - System and network reconnaissance
7. **Command & Control** - File downloads and BITS jobs
8. **Impact** - System recovery inhibition

### Key Features

✅ **Automatic Cleanup** - Removes artifacts from previous runs before starting  
✅ **Idempotent Design** - Can be safely run multiple times  
✅ **Detailed Logging** - Creates comprehensive execution logs (CSV and text)  
✅ **Non-Interactive** - Runs without user prompts or hangs  
✅ **EDR-Focused** - Tests detection capabilities, not exploitation  
✅ **MITRE ATT&CK Aligned** - Uses techniques from the MITRE ATT&CK framework

## 🔧 Requirements

### System Requirements
- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Privileges**: **Administrator rights required**
- **Internet Connection**: Required for initial Atomic Red Team download
- **Disk Space**: ~500MB for Atomic Red Team library

### Software Dependencies
- PowerShell Execution Policy must allow script execution
- .NET Framework 4.5 or higher
- Windows Management Framework 5.1+

**Note**: The script will automatically install the Invoke-AtomicRedTeam module if not present.

## 📋 Installation

### 1. Clone the Repository

```powershell
git clone https://github.com/yourusername/edr-attack-simulation.git
cd edr-attack-simulation
```

### 2. Set Execution Policy (if needed)

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 3. Verify Administrator Privileges

Right-click PowerShell and select **"Run as Administrator"**

## 🚀 Usage

### Basic Execution

```powershell
# Navigate to script directory
cd C:\path\to\script

# Run the script
.\attackchain.ps1
```

### What to Expect

The script will:
1. Check prerequisites and install required modules
2. Download Atomic Red Team library (first run only)
3. Clean up artifacts from previous runs
4. Execute each tactic sequentially with detailed output
5. Generate execution logs in the script directory

### Expected Runtime

- **First run**: 10-15 minutes (includes downloads)
- **Subsequent runs**: 5-8 minutes

## 📊 MITRE ATT&CK Techniques Tested

| Tactic | Technique ID | Technique Name | Test Description |
|--------|--------------|----------------|------------------|
| Execution | T1059.005 | VBScript | CScript execution for recon |
| Persistence | T1053.005 | Scheduled Task | Local scheduled task creation |
| Privilege Escalation | T1548.002 | Bypass UAC | Fodhelper UAC bypass |
| Defense Evasion | T1562.001 | Impair Defenses | Windows Defender tampering |
| Defense Evasion | T1027 | Obfuscated Files | Base64 encoded commands |
| Defense Evasion | T1105 | Ingress Tool Transfer | File download via certutil |
| Defense Evasion | T1036.003 | Masquerading | Process masquerading |
| Credential Access | T1003.001 | LSASS Memory | ProcDump LSASS dumping |
| Discovery | T1082 | System Information | System enumeration |
| Discovery | T1057 | Process Discovery | Process enumeration |
| Discovery | T1049 | Network Connections | Network connection enumeration |
| Discovery | T1018 | Remote System Discovery | ARP table enumeration |
| Command & Control | T1105 | Ingress Tool Transfer | File download simulation |
| Command & Control | T1197 | BITS Jobs | BITS download |
| Impact | T1490 | Inhibit System Recovery | Disable system restore |

## 📝 Output Files

The script generates several log files in the script directory:

- **Attack-Simulation-Log.txt** - Detailed text log with timestamps
- **Atomic-Execution-Log.csv** - CSV log for analysis and reporting
- **network_recon.txt** - ARP table output
- **lsass.dmp** - LSASS dump (if successful - should be blocked by EDR)

## 🧹 Cleanup

### Automatic Cleanup

The script automatically cleans up before each test run. If you need to perform manual cleanup:

```powershell
# Remove scheduled task
schtasks /delete /tn "spawn" /f

# Remove masqueraded files
Remove-Item $env:TEMP\svchost.exe -Force -ErrorAction SilentlyContinue

# Remove downloaded payloads
Remove-Item $env:TEMP\c2_payload.txt -Force -ErrorAction SilentlyContinue

# Remove LSASS dump (if created)
Remove-Item .\lsass.dmp -Force -ErrorAction SilentlyContinue

# Run Atomic cleanup commands (displayed at end of script)
Invoke-AtomicTest T1053.005 -TestNumbers 2 -Cleanup
Invoke-AtomicTest T1548.002 -TestNumbers 3 -Cleanup
Invoke-AtomicTest T1562.001 -TestNumbers 17 -Cleanup
# ... (see full list in script output)
```

## 🛡️ Expected EDR Behavior

### What Should Trigger Alerts

Your EDR solution should detect and alert on:

✅ **Scheduled task creation** for persistence  
✅ **UAC bypass attempts** using fodhelper  
✅ **Defender tampering attempts** (will be blocked)  
✅ **Process masquerading** (legitimate binary copied to suspicious name)  
✅ **LSASS access attempts** (should be blocked)  
✅ **Suspicious command-line activity**  
✅ **Encoded PowerShell commands**  
✅ **certutil used for file downloads**  
✅ **System recovery inhibition attempts**

### Expected Blocks/Failures

Some techniques should **FAIL** - this indicates security controls are working:

❌ **T1562.001** - Defender tampering (Access Denied - GOOD!)  
❌ **T1003.001** - LSASS dumping (Access Denied - GOOD!)

These failures are **SUCCESS indicators** for your security posture.

## 🔍 Analyzing Results

### Check Your EDR Console

After running the script, review your EDR console for:

1. **Detection Coverage** - Which techniques were detected?
2. **Alert Quality** - Are alerts clear and actionable?
3. **Response Actions** - Did the EDR block malicious actions?
4. **False Positives** - Any legitimate activity flagged?
5. **Blind Spots** - Which techniques went undetected?

### Review Log Files

```powershell
# View text log
Get-Content .\Attack-Simulation-Log.txt

# Analyze CSV log
Import-Csv .\Atomic-Execution-Log.csv | Format-Table

# Check for failed tests
Get-Content .\Attack-Simulation-Log.txt | Select-String "ERROR"
```

## ⚙️ Troubleshooting

### Script Requires Administrator Rights

**Error**: "This script must be run with Administrator privileges"

**Solution**: Right-click PowerShell and select "Run as Administrator"

### Execution Policy Restrictions

**Error**: "Cannot be loaded because running scripts is disabled"

**Solution**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Module Installation Fails

**Error**: "Failed to install 'Invoke-AtomicRedTeam' module"

**Solution**:
```powershell
# Manually install module
Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser -Force
```

### Tests Timeout or Hang

The script includes automatic cleanup to prevent hanging on prompts. If tests still timeout:

1. Ensure all previous artifacts are cleaned up
2. Check for antivirus blocking test execution
3. Review the execution log for specific errors

### Network Download Failures

If atomic downloads fail, ensure:
- Internet connection is active
- Firewall allows PowerShell to access GitHub
- Proxy settings are configured (if applicable)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test thoroughly in a lab environment
4. Submit a pull request with clear description

## 📚 Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Invoke-AtomicRedTeam Documentation](https://github.com/redcanaryco/invoke-atomicredteam)
- [Purple Team Exercise Framework](https://www.scythe.io/library/purple-teaming-framework)

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

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Authors

- **Your Name** - Initial work

## 🙏 Acknowledgments

- [Red Canary](https://redcanary.com/) - Atomic Red Team framework
- [MITRE Corporation](https://www.mitre.org/) - ATT&CK framework
- Security community contributors

---

**Remember**: Always test responsibly. With great power comes great responsibility. 🦸‍♂️

**Questions or Issues?** Open an issue in this repository or contact the security team.

**Last Updated**: October 2025
