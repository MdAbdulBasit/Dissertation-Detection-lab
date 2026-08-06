<#
.SYNOPSIS
    Runs an Atomic Red Team detonation or a benign mirroring session, bracketed with UTC timestamps,
    and emits a ready-to-paste row for data/detonation_log.csv.

.DESCRIPTION
    Exists to remove hand-typed commands from the lab loop. Pasting PowerShell through a chat client
    corrupted commands twice on 2026-08-05 (underscores stripped from $_, and chat timestamps injected
    mid-script), which silently prevented an atomic from running at all. Running a version-controlled
    script instead removes that failure mode entirely.

    Records windows in UTC. Windows local time is UTC+1 during BST while Wazuh writes UTC — recording
    local time would place every window an hour after its own alerts and label the whole positive
    class as benign. See LABELLING_SCHEME.md.

.PARAMETER Type
    'attack' runs the atomic test. 'benign' runs legitimate commands that mirror the same technique,
    to generate the confusable negative class.

.PARAMETER TechniqueId
    ATT&CK technique ID, e.g. T1087.001

.PARAMETER TestNumbers
    Atomic test numbers to run. Enumerate them first - they are global within a technique and do not
    start at 1. Omit this parameter to have the script list the applicable tests and exit.

.PARAMETER Repeat
    Number of separate detonation windows to run. Each gets its own UTC-bracketed window and its own
    CSV row. Needed for ML sample size: a single run of T1087.001 yielded only ~10 alerts (~5 after
    deduplicating the net.exe/net1.exe pairing), which is far too few to train and evaluate on.

.PARAMETER MinGapSeconds
.PARAMETER MaxGapSeconds
    Randomised idle gap between repeat runs. Must exceed the window_end + 30 s label buffer in
    LABELLING_SCHEME.md or consecutive windows contaminate each other's classes. Randomised so the
    model cannot learn a fixed detonation cadence as a shortcut feature.

.EXAMPLE
    .\Invoke-LabRun.ps1 -Type attack -TechniqueId T1087.001                     # enumerate tests only
    .\Invoke-LabRun.ps1 -Type attack -TechniqueId T1087.001 -TestNumbers 8,9,10 -Repeat 5
    .\Invoke-LabRun.ps1 -Type benign -TechniqueId T1087.001 -Repeat 5
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('attack','benign')][string]$Type,
    [Parameter(Mandatory)][string]$TechniqueId,
    # Deliberately [string], not [int[]]. When invoked via `powershell.exe -File`, every argument is
    # passed as a literal string, so "8,9,10" never binds to an int array and the script dies with a
    # transformation error. Taking a string and splitting it here makes -File and in-session calls
    # behave identically. Accepts commas, semicolons or spaces.
    [string]$TestNumbers,
    [int]$Repeat = 1,
    # Raised from 60/120 on 2026-08-06. Measured Sysmon -> agent -> manager forwarding lag reached
    # p99 111s and max 169s, so the labelling buffer had to go to 120s - and the gap MUST exceed the
    # buffer or consecutive windows overlap and contaminate each other's classes.
    [int]$MinGapSeconds = 180,
    [int]$MaxGapSeconds = 300,
    [string]$OutFile
)

$ErrorActionPreference = 'Continue'

function Get-UtcStamp { (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') }

# Resolve the log path in the BODY, not in a param default. $PSScriptRoot can be empty when a param
# default is evaluated under `powershell.exe -File \\UNC\path\script.ps1`: on 2026-08-06 that produced
# "\..\data\detonation_log_rows.csv", which silently wrote five detonation rows to the endpoint's own
# C:\data instead of the repo over the share. The rows were only recoverable from console scrollback.
if (-not $OutFile) {
    $scriptDir = if ($PSCommandPath) { Split-Path -Parent $PSCommandPath }
                 elseif ($PSScriptRoot) { $PSScriptRoot }
                 else { (Get-Location).Path }
    $OutFile = Join-Path $scriptDir '..\data\detonation_log_rows.csv'
}
Write-Host "Log file: $OutFile" -ForegroundColor DarkGray

# Normalise -TestNumbers into a real int array regardless of how the script was invoked.
$TestNumberList = @()
if ($TestNumbers) {
    $TestNumberList = $TestNumbers -split '[,;\s]+' |
        Where-Object { $_ -ne '' } |
        ForEach-Object { [int]$_ }
}

# =====================================================================================================
# ⚠️ CRITICAL — WHY EVERY NATIVE COMMAND BELOW GOES THROUGH cmd.exe /c
#
# Measured 2026-08-06. T1082 produced 146 attack alerts and *1* benign alert, and that single benign
# alert (rule 60702, VSS idle timeout) was unrelated ambient noise. The mirror had generated ZERO
# technique-relevant alerts. Cause:
#
#   Atomic Red Team executes command_prompt tests as  cmd.exe /c "<command>"
#   The mirror was running the same commands directly from powershell.exe
#
# The two default rules that fired both key on cmd.exe lineage, not on the discovery behaviour:
#   92032  parentImage = cmd.EXE  AND  parentCommandLine contains " /C "
#   92052  originalFileName = cmd.EXE  AND  parentImage NOT (explorer|cmd).EXE
#
# So the classes were perfectly separable on "was cmd.exe involved" — an artefact of the test
# harness's execution wrapper, nothing to do with attacker behaviour. A classifier trained on that
# scores ~100% by learning Atomic Red Team, and the false-positive reduction claim becomes vacuous.
# Attack-side parent images confirmed the split: 75 cmd.exe, 70 powershell.exe, benign 0 cmd.exe.
#
# Therefore: mirror the attack set's PROCESS LINEAGE, not just its commands. Native CLI tools go
# through cmd.exe /c exactly as ART invokes them; PowerShell cmdlets stay as cmdlets, because the
# attack set contains cmdlet-based tests too (T1082-37, T1082-38).
# See BENIGN_ACTIVITY_PROTOCOL.md section 2.
# =====================================================================================================

function Invoke-ViaCmd {
    param([Parameter(Mandatory)][string]$CommandLine)
    # Must match ART's command_prompt executor in FORM, not merely in effect.
    #
    # Round 1 of this fix used `& cmd.exe /c $CommandLine`. That routed the commands through cmd.exe
    # correctly - benign alerts went from 1 to 30 and rule 92032 started firing in both classes - but
    # PowerShell's call operator RESOLVES THE FULL PATH, so Sysmon recorded:
    #     benign:  "C:\Windows\system32\cmd.exe" /c systeminfo
    #     attack:  "cmd.exe" /c systeminfo & reg query HKLM\...
    # Different command-line form means a different rule matched: benign fired 92004 ("Powershell
    # process spawned Windows command shell instance") and attack fired 92052 ("Windows command prompt
    # started by an abnormal process"), 25 vs 67 with ZERO overlap. Rule ID alone still separated the
    # classes perfectly, so the artefact had only moved, not gone.
    #
    # Start-Process with a bare FilePath reproduces ART's `"cmd.exe" /c ...` form.
    #
    # ROUND 2 RESULT: it does NOT. PowerShell still resolved the path, recording
    #     "C:\Windows\system32\cmd.exe" /c systeminfo & hostname
    # so 92004 kept firing in benign (10 obs.) and 92052 stayed attack-only (65 obs.). The & chaining
    # DID work and 92032 now fires in both classes (15 benign / 75 attack), so this is still the right
    # invocation - the residual path-form difference is intrinsic to ART vs PowerShell and is normalised
    # out at feature-extraction time instead. See export_labelled_alerts.py normalise_cmdline() and
    # RULE_CANONICAL, and BENIGN_ACTIVITY_PROTOCOL.md section 2a.
    Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $CommandLine" -NoNewWindow -Wait
}

function Invoke-ViaPowerShell {
    param([Parameter(Mandatory)][string]$CommandLine)
    # Mirrors ART's powershell executor, which spawns a CHILD powershell.exe. Running cmdlets inline
    # instead leaves rule 92027 ("Powershell process spawned powershell instance") attack-only.
    Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile', '-Command', $CommandLine -NoNewWindow -Wait
}

$BenignMirror = @{
    # Commands are CHAINED WITH & inside one cmd.exe, matching how ART's atomics are written
    # (e.g. T1087.001-8 is literally: net user & dir c:\Users\ & cmdkey.exe /list & net localgroup ...).
    # One command per cmd.exe would leave a different child-process fan-out from the attack class.
    'T1087.001' = { Invoke-ViaCmd 'net user & net localgroup administrators' }
    # Cmdlets go through a CHILD powershell.exe, not inline. ART's powershell executor spawns
    # powershell from powershell, which fires rule 92027 ("Powershell process spawned powershell
    # instance"). Running them inline left 92027 attack-only (5 obs. in T1082, 1 in T1087.001) -
    # a smaller version of the same harness-fingerprint problem. Verified attack-only on 2026-08-06.
    'T1082'     = { Invoke-ViaCmd 'systeminfo & hostname'; Start-Sleep 4; Invoke-ViaCmd 'wmic os get Caption,Version,BuildNumber /value & reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName'; Start-Sleep 3; Invoke-ViaPowerShell 'Get-WinSystemLocale; Get-PSDrive -PSProvider FileSystem' }
    'T1033'     = { Invoke-ViaCmd 'whoami & whoami /groups' }
    'T1016'     = { Invoke-ViaCmd 'ipconfig /all & route print & arp -a' }
    'T1059.001' = { Invoke-ViaPowerShell 'Get-ChildItem C:\Windows\System32 | Select-Object -First 5; Test-NetConnection 10.10.10.10 -InformationLevel Quiet' }
    'T1059.003' = { Invoke-ViaCmd 'dir C:\Windows'; Start-Sleep 3; Invoke-ViaCmd 'tasklist' }
    'T1053.005' = { Invoke-ViaCmd 'schtasks /query /fo LIST' }
    'T1070.004' = { $t = "$env:TEMP\labtest.txt"; "x" | Out-File $t; Invoke-ViaCmd "del `"$t`"" }
    'T1560.001' = { $s = "$env:TEMP\labzip"; New-Item -ItemType Directory -Path $s -Force | Out-Null; "x" | Out-File "$s\a.txt"; Compress-Archive -Path "$s\a.txt" -DestinationPath "$env:TEMP\lab.zip" -Force; Remove-Item "$env:TEMP\lab.zip","$s" -Recurse -Force }
}

# --- Preflight -----------------------------------------------------------------
$mp = Get-MpComputerStatus
if ($mp.RealTimeProtectionEnabled) {
    Write-Warning "Defender real-time protection is ON."
    Write-Warning "  attack runs: atomics may be blocked and will fail for the wrong reason."
    Write-Warning "  benign runs: this is a CLASS-CORRELATED CONFOUND. If the paired attack runs were"
    Write-Warning "  captured with Defender off and the benign runs with it on, the environment differs"
    Write-Warning "  BETWEEN classes, and Defender's own activity does generate alerts here (227"
    Write-Warning "  MsMpEng platform-update DLL drops were observed on 2026-08-06). Both classes must"
    Write-Warning "  be captured under identical conditions or the comparison is not clean."
    Write-Warning "Fix: Set-MpPreference -DisableRealtimeMonitoring `$true  (Tamper Protection off first)"
    # Prompt for BOTH types. It previously prompted only for attack runs, which let ten benign windows
    # be captured on 2026-08-06 with Defender on while their paired attack windows had it off.
    $go = Read-Host "Continue anyway? (y/N)"
    if ($go -ne 'y') { return }
}
$defenderOff = -not $mp.RealTimeProtectionEnabled

$sysmon = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if (-not $sysmon -or $sysmon.Status -ne 'Running') {
    Write-Error "Sysmon64 is not running. No telemetry will be produced. Aborting."
    return
}

# --- Test-number guard ----------------------------------------------------------
# Atomic test numbers are GLOBAL within a technique, across all platforms — they do NOT start at 1
# per technique. T1087.001 lists 8,9,10,11 under windows (11 targets ESXi - exclude it, this lab has
# no ESXi host); tests 1-7 are Linux/macOS. Passing
# "-TestNumbers 1" therefore selects a non-Windows test and returns
# "Found 0 atomic tests applicable to windows platform" — which looks exactly like a broken install.
# Cost an investigation on 2026-08-05. Never assume test numbers; always enumerate first.
if ($Type -eq 'attack') {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

    if ($TestNumberList.Count -eq 0) {
        Write-Host "`nNo -TestNumbers given. Applicable Windows tests for $TechniqueId :`n" -ForegroundColor Yellow
        Invoke-AtomicTest $TechniqueId -ShowDetailsBrief
        Write-Host "`nRe-run with the numbers you want, e.g. -TestNumbers 8,9,10" -ForegroundColor Yellow
        Write-Host "Exclude tests for other hypervisors/platforms (ESXi, Azure, AWS) - they will fail for" -ForegroundColor Yellow
        Write-Host "environmental reasons and must not be recorded as detection failures." -ForegroundColor Yellow
        return
    }
}

# --- Validate before looping (fail fast, not halfway through run 3) --------------
if ($Type -eq 'benign' -and -not $BenignMirror.ContainsKey($TechniqueId)) {
    Write-Error "No benign mirror defined for $TechniqueId. Add one to this script before relying on it."
    return
}

# The inter-run gap MUST exceed the window_end + 30 s label buffer in LABELLING_SCHEME.md. Runs closer
# together than that bleed into each other's classes: on 2026-08-06 a benign mirror typed seconds after
# an attack window landed inside the buffer and would have been labelled as attack, silently.
if ($Repeat -gt 1 -and $MinGapSeconds -lt 150) {
    Write-Warning "MinGapSeconds=$MinGapSeconds is under the 120 s label buffer plus margin. Windows may"
    Write-Warning "contaminate each other. Measured forwarding lag on 2026-08-06: p99 111s, max 169s."
}

# --- CSV header ------------------------------------------------------------------
$dir = Split-Path $OutFile -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
if (-not (Test-Path $OutFile)) {
    'session_id,type,technique_id,technique_name,atomic_test_numbers,window_start,window_end,operator_context,defender_realtime_off,notes' |
        Out-File $OutFile -Encoding utf8
}

# --- Run (one labelled window per iteration) -------------------------------------
for ($i = 1; $i -le $Repeat; $i++) {

    # UTC, so session_id and the window columns agree. Local time here made row IDs look an hour
    # ahead of their own windows during BST.
    $sessionId = "$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))-$Type-r$i"
    Write-Host "`n=== $Type : $TechniqueId  (run $i of $Repeat) ===" -ForegroundColor Cyan

    $start = Get-UtcStamp
    Write-Host "WINDOW START (UTC): $start" -ForegroundColor Yellow

    if ($Type -eq 'attack') {
        Invoke-AtomicTest $TechniqueId -TestNumbers $TestNumberList
        $context = "atomic-red-team"
    }
    else {
        Write-Host "Running legitimate mirror commands as an ordinary admin would..." -ForegroundColor Gray
        & $BenignMirror[$TechniqueId] | Out-Host
        $context = "interactive-admin"
    }

    Start-Sleep 3
    $end = Get-UtcStamp
    Write-Host "WINDOW END   (UTC): $end" -ForegroundColor Yellow

    $row = '{0},{1},{2},{3},"{4}",{5},{6},{7},{8},' -f `
        $sessionId, $Type, $TechniqueId, '', ($TestNumberList -join ';'), $start, $end, $context, $defenderOff

    $row | Out-File $OutFile -Append -Encoding utf8
    Write-Host $row -ForegroundColor Green

    if ($i -lt $Repeat) {
        $gap = Get-Random -Minimum $MinGapSeconds -Maximum ($MaxGapSeconds + 1)
        Write-Host "Idle $gap s before run $($i + 1) - randomised so windows stay separable and the model cannot learn a fixed cadence..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $gap
    }
}

Write-Host "`n$Repeat window(s) appended to: $OutFile" -ForegroundColor Green
Write-Host "Next: verify on Blue that the expected rule fired inside each window." -ForegroundColor Cyan
Write-Host "IMPORTANT: do not type anything on this endpoint for 30 s - the last window's label buffer is still open." -ForegroundColor Yellow
