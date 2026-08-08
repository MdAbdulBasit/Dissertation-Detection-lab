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
    # 'baseline' = this technique's own custom rules are NOT yet deployed, so the run measures DEFAULT
    # detection (the 'Default detected?' column). 'custom' = they are deployed ('Detected after?').
    # Recorded per row so the export can split counts by phase without hand-patching the CSV.
    # REQUIRED for Persistence techniques. Atomics that create named, persistent artefacts (scheduled
    # tasks, registry run keys, local accounts) collide with themselves on repeat: run 1 creates the
    # object, runs 2-5 then measure FAILED creation, which is a different behaviour with different
    # telemetry. Observed on T1053.005 (2026-08-07): run 1 clean, run 2 returned 0xC0000142, blocked on
    # an interactive "task already exists, replace? (Y/N)" prompt for 120s, and Register-ScheduledTask
    # failed with "Cannot create a file when that file already exists".
    #
    # Cleanup is scheduled to land in genuine DEAD TIME - after the previous window's +120s label buffer
    # expires and before the next window opens - so the deletion telemetry is attributed to no window.
    # This forces a gap wider than the buffer, so 45-90s gaps cannot be used with it.
    [switch]$CleanupBetweenRuns,
    [ValidateSet('baseline','custom')][string]$RulesetPhase = 'custom',
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
    #
    # ⚠️ FIXED 2026-08-08, mid-run, during T1547.001's benign phase.
    #
    # The previous form passed the command as a bare third array element:
    #     -ArgumentList '-NoProfile', '-Command', $CommandLine
    # Start-Process joins ArgumentList with spaces and does NOT re-quote elements, and Windows
    # command-line parsing then CONSUMES double quotes as grouping delimiters rather than passing them
    # through. So this command:
    #     $s = $w.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk")
    # reached the child PowerShell with its quotes stripped, split at the space in "Start Menu", and
    # failed with "Missing ')' in method call".
    #
    # Every earlier mirror survived this by luck: none of them contained a SPACE INSIDE A QUOTED STRING.
    # Quotes were still being stripped in T1082, T1033, T1016 and T1136.001 - it just happened not to
    # matter, because `-Path HKCU:\Software\...` is valid PowerShell with or without quotes. A latent
    # bug that only manifests when an argument contains a space is exactly the kind that surfaces late.
    #
    # Fix: escape inner quotes as \" and wrap the whole command in one quoted argument, so Windows
    # parsing hands the child a single intact string.
    #
    # ⚠️ Rejected alternative: -EncodedCommand. It is immune to all quoting problems, but it would make
    # EVERY benign mirror emit a base64 command line, which trips rule 92057 ("powershell executed a
    # base64 encoded command"). Encoding would become a benign-class marker - a class-correlated
    # confound, and a worse problem than the one being fixed.
    #
    # ⚠️ Known limitation: a $CommandLine ending in a backslash would escape the closing quote. None do,
    # and none should - if one ever needs to, append a space.
    $escaped = $CommandLine -replace '"', '\"'
    Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile', '-Command', "`"$escaped`"" -NoNewWindow -Wait
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
    # Widened 2026-08-07. The whoami-only mirror left custom rule 100241 (PowerShell identity
    # enumeration) firing in the ATTACK class only - 10 alerts, zero benign - because the atomic set
    # covers both the native and the cmdlet path while the mirror covered only the native one. A rule
    # exclusive to one class is a discriminator the model can exploit without learning any behaviour.
    # An administrator reading %USERNAME% or calling WindowsIdentity in a script is entirely ordinary,
    # so both paths belong in the mirror.
    # NOTE: T1033's recorded data was captured with the NARROW mirror; 100241 is attack-only there and
    # that is documented as a limitation in COVERAGE_TABLE.md rather than retrofitted.
    'T1033'     = { Invoke-ViaCmd 'whoami & whoami /groups'; Start-Sleep 3; Invoke-ViaPowerShell '[Security.Principal.WindowsIdentity]::GetCurrent().Name; $env:USERNAME; $env:USERDOMAIN' }
    # Widened 2026-08-07 for the same reason as T1033: the narrow mirror left custom rules 100251
    # (netsh enumeration) and 100252 (net config) firing in the ATTACK class only, because the atomics
    # cover netsh and net config while the mirror did not. Checking firewall rules and workstation
    # network config is ordinary administration and belongs in the mirror.
    # NOTE: T1016's recorded data used the NARROW mirror; 100251/100252 are attack-only there and that
    # is documented as scope, not a result, in COVERAGE_TABLE.md.
    'T1016'     = { Invoke-ViaCmd 'ipconfig /all & route print & arp -a'; Start-Sleep 3; Invoke-ViaCmd 'net config workstation & netsh advfirewall firewall show rule name=all' }
    # Widened 2026-08-07. The narrow mirror produced FIVE alerts against 61 real attack alerts, and
    # covered neither -Command nor -EncodedCommand - the two paths the atomics exercise most.
    #
    # ⚠️ -EncodedCommand is in the mirror ON PURPOSE, and it is the most important line in this table.
    # Base64-encoded PowerShell is treated as a hallmark of attack, but it is also routine in legitimate
    # automation: scheduled tasks, SCCM and deployment scripts encode commands to avoid quoting problems.
    # If the benign class never encodes anything, a model separates the classes on base64 alone and
    # learns nothing about behaviour. Including it makes the classes confusable on the single strongest
    # indicator, which is exactly what the triage layer has to resolve.
    'T1059.001' = {
        Invoke-ViaPowerShell 'Get-ChildItem C:\Windows\System32 | Select-Object -First 5 | Out-String'
        Start-Sleep 3
        Invoke-ViaPowerShell 'Get-Service | Select-Object -First 3 | Out-String'
        Start-Sleep 3
        # An administrator invoking an encoded command from an automation script.
        $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host "scheduled inventory task"'))
        Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-EncodedCommand',$b64 -NoNewWindow -Wait
    }
    'T1059.003' = { Invoke-ViaCmd 'dir C:\Windows'; Start-Sleep 3; Invoke-ViaCmd 'tasklist' }
    # Widened 2026-08-07 BEFORE the first run, learning from T1033 and T1016 where a mirror narrower than
    # the attack set left custom rules firing in one class only. The atomics CREATE scheduled tasks; a
    # query-only mirror would have made creation a free discriminator. Creating a scheduled task is
    # completely ordinary administration, so creation belongs in the mirror.
    # Self-cleaning: the task is deleted in the same invocation, so the benign side leaves no drift.
    'T1053.005' = {
        Invoke-ViaCmd 'schtasks /query /fo LIST'
        Start-Sleep 3
        Invoke-ViaCmd 'schtasks /create /tn LabBenignInventory /tr cmd.exe /sc daily /st 09:00 /f & schtasks /delete /tn LabBenignInventory /f'
        Start-Sleep 3
        Invoke-ViaPowerShell 'Get-ScheduledTask | Select-Object -First 3 | Out-String'
    }
    # T1136.001 creates a LOCAL USER ACCOUNT. An administrator provisioning a service account is entirely
    # ordinary, so the mirror creates one and removes it. Self-cleaning, so no -CleanupBetweenRuns needed
    # on the benign side.
    # ⚠️ A password is supplied deliberately: `net user X /add` with no password can prompt, which would
    # hang the run the way the T1053.005 "replace? (Y/N)" prompt did.
    'T1136.001' = { Invoke-ViaCmd 'net user LabBenignSvc Lab#Benign2026 /add & net user LabBenignSvc /delete' }
    # T1547.001 Registry Run Keys / Startup Folder. Mirrors all FOUR mechanisms in the selected atomic
    # set, because the recurring lesson from 100241, 100251, 100271 and 100282 is that any mechanism the
    # mirror omits becomes a free discriminator and has to be thrown out of the separability analysis:
    #
    #   atomics 1, 2  reg.exe  -> ...\CurrentVersion\Run and \RunOnce
    #   atomic  3     PowerShell Set-ItemProperty -> ...\CurrentVersion\RunOnce
    #   atomic  7     .lnk dropped into the Startup folder            (Sysmon EID 11, not 13)
    #   atomic  12    PowerShell -> ...\CurrentVersion\Policies\Explorer\Run
    #
    # Registering an application to start at logon is routine administration - installers, updaters and
    # sync agents all do it - so every one of these has a legitimate counterpart.
    #
    # ⚠️ NOT self-cleaning, unlike the T1053.005 and T1136.001 mirrors, and that is deliberate. Deleting a
    # Run value emits its own EID 13 (eventType DeleteValue) which rule 92300 matches just as readily as a
    # write. The ATTACK phase does not delete inside its windows - cleanup runs after the phase - so a
    # self-cleaning mirror would give the benign class extra registry events the attack class never has.
    # Both phases are therefore cleaned the same way, once, after the phase completes.
    #
    # ⚠️ No quotes and no spaces in the reg.exe arguments. Invoke-ViaCmd builds a single "/c <string>"
    # argument for Start-Process, and embedded quotes are the fragile part of that; C:\ProgramData\... is
    # used instead of C:\Program Files\... purely to avoid needing them.
    'T1547.001' = {
        Invoke-ViaCmd 'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v LabBenignUpdater /t REG_SZ /d C:\ProgramData\LabBenign\updater.exe /f'
        Start-Sleep 3
        Invoke-ViaPowerShell 'Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name LabBenignFirstRun -Value "C:\ProgramData\LabBenign\firstrun.exe"'
        Start-Sleep 3
        Invoke-ViaPowerShell '$w = New-Object -ComObject WScript.Shell; $s = $w.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\LabBenignAgent.lnk"); $s.TargetPath = "C:\Windows\System32\notepad.exe"; $s.Save()'
        Start-Sleep 3
        # Both key levels created explicitly. The registry provider's New-Item does not reliably create
        # missing intermediate keys, and assuming Policies\Explorer already exists would make the benign
        # phase silently depend on the attack phase having run first - an ordering dependency between
        # classes is exactly the kind of hidden coupling that invalidates a comparison.
        Invoke-ViaPowerShell 'New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null; New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Force | Out-Null; Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name LabBenignPolicy -Value "C:\Windows\System32\notepad.exe"'
        Start-Sleep 3
        # ⚠️ Fifth command added 2026-08-08 after designing rule 100290, BEFORE the custom phase ran.
        #
        # The four commands above all register a plain .exe path. Rule 100290 keys on the VALUE CONTENT -
        # interpreters, encoded commands, temp paths, URLs - and ART's atomic 3 payload is
        # `powershell.exe "IEX (New-Object Net.WebClient).DownloadString(...)"`. So 100290 would have come
        # out attack-only, and for a reason that is not a real discriminator: an adversary can point a Run
        # key at a plain .exe, and plenty of legitimate software registers an interpreter at logon.
        #
        # This is the FIFTH time a mirror narrower than the attack set would have manufactured a fake
        # discriminator (see 100241, 100251, 100271, 100282) - but the first where the gap is the value's
        # CONTENT rather than the MECHANISM. Mechanism gaps are visible when you list the atomics; content
        # gaps only surface when you read your own rule's regex against your own mirror's data. Worth
        # adding to the pre-run checklist: for every custom rule, ask which class can possibly match it.
        #
        # A management agent registering a PowerShell maintenance script at logon is entirely ordinary, so
        # this belongs in the benign class on its merits, not merely to balance the numbers.
        Invoke-ViaPowerShell 'Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name LabBenignSync -Value "powershell.exe -NoProfile -File C:\ProgramData\LabBenign\sync.ps1"'
    }
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

# Cleanup must fall in dead time, which is impossible if the gap is narrower than the label buffer.
$CLEANUP_DELAY = 130      # > the 120 s POST_BUFFER in export_labelled_alerts.py
if ($CleanupBetweenRuns -and $Repeat -gt 1 -and $MinGapSeconds -lt ($CLEANUP_DELAY + 20)) {
    Write-Error "-CleanupBetweenRuns needs -MinGapSeconds at least $($CLEANUP_DELAY + 20) so the cleanup"
    Write-Error "lands AFTER the previous window's 120 s label buffer expires. Otherwise the deletion"
    Write-Error "telemetry is labelled as part of the attack class. Re-run with -MinGapSeconds 180"
    Write-Error "-MaxGapSeconds 300."
    return
}

# Clear any artefacts left by an earlier phase BEFORE the first window opens, so run 1 measures creation
# rather than collision.
if ($CleanupBetweenRuns -and $Type -eq 'attack') {
    Write-Host "Pre-run cleanup (before any window opens)..." -ForegroundColor DarkGray
    Invoke-AtomicTest $TechniqueId -TestNumbers $TestNumberList -Cleanup
    Start-Sleep 5
}

# --- CSV header ------------------------------------------------------------------
$dir = Split-Path $OutFile -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
if (-not (Test-Path $OutFile)) {
    'session_id,type,technique_id,technique_name,atomic_test_numbers,window_start,window_end,ruleset_phase,operator_context,defender_realtime_off,notes' |
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

    $row = '{0},{1},{2},{3},"{4}",{5},{6},{7},{8},{9},' -f `
        $sessionId, $Type, $TechniqueId, '', ($TestNumberList -join ';'), $start, $end, $RulesetPhase, $context, $defenderOff

    $row | Out-File $OutFile -Append -Encoding utf8
    Write-Host $row -ForegroundColor Green

    if ($i -lt $Repeat) {
        $gap = Get-Random -Minimum $MinGapSeconds -Maximum ($MaxGapSeconds + 1)

        # ⚠️ The `-and $Type -eq 'attack'` guard was MISSING until 2026-08-08 and it caused real
        # contamination. Both the pre-run block and the final block were already guarded; this one was
        # not. The effect: a BENIGN run launched with -CleanupBetweenRuns executed
        # `Invoke-AtomicTest <id> -Cleanup` between its runs, i.e. it ran the ATOMIC's cleanup commands
        # inside the benign phase. For T1136.001 those commands delete T1136.001_CMD and
        # T1136.001_Admin, so ART account names appeared in benign-class telemetry.
        #
        # Two of the 72 benign alerts in the T1136.001 baseline referenced those names. I first
        # attributed that to attack-phase cleanup telemetry arriving late - WRONG, the timings rule it
        # out (run 5's cleanup fired ~04:20:51, the first benign window opened 04:25:44, far beyond the
        # p99 lag of 111 s). The cause was this missing guard.
        #
        # Benign mirrors are self-cleaning by construction (see the $BenignMirror note above), so they
        # never need the flag. Guarding here means passing it by mistake is harmless rather than
        # silently poisoning the negative class - which is the more dangerous direction, because a
        # contaminated benign class teaches the triage model that attack artefacts are normal.
        if ($CleanupBetweenRuns -and $Type -eq 'attack') {
            # Wait out the previous window's label buffer FIRST, so the cleanup's deletion telemetry is
            # attributed to no window at all, then restore a clean state for the next run.
            Write-Host "Idle $CLEANUP_DELAY s so run $i's label buffer expires before cleanup..." -ForegroundColor DarkGray
            Start-Sleep -Seconds $CLEANUP_DELAY
            Write-Host "Cleanup in dead time (attributed to no window)..." -ForegroundColor DarkGray
            Invoke-AtomicTest $TechniqueId -TestNumbers $TestNumberList -Cleanup
            $remaining = [Math]::Max(20, $gap - $CLEANUP_DELAY)
            Write-Host "Idle $remaining s before run $($i + 1)..." -ForegroundColor DarkGray
            Start-Sleep -Seconds $remaining
        }
        else {
            Write-Host "Idle $gap s before run $($i + 1) - randomised so windows stay separable and the model cannot learn a fixed cadence..." -ForegroundColor DarkGray
            Start-Sleep -Seconds $gap
        }
    }
}

# Leave the endpoint clean: the last run's artefacts are still present at this point.
if ($CleanupBetweenRuns -and $Type -eq 'attack') {
    Write-Host "`nFinal cleanup after run $Repeat..." -ForegroundColor DarkGray
    Start-Sleep -Seconds $CLEANUP_DELAY
    Invoke-AtomicTest $TechniqueId -TestNumbers $TestNumberList -Cleanup
    Write-Host "Verify nothing was left behind, e.g.:" -ForegroundColor DarkGray
    Write-Host '  schtasks /query /fo LIST | findstr /i "TaskName" | findstr /v /i "Microsoft Google OneDrive"' -ForegroundColor DarkGray
}

Write-Host "`n$Repeat window(s) appended to: $OutFile" -ForegroundColor Green
Write-Host "Next: verify on Blue that the expected rule fired inside each window." -ForegroundColor Cyan
Write-Host "IMPORTANT: do not type anything on this endpoint for 30 s - the last window's label buffer is still open." -ForegroundColor Yellow
