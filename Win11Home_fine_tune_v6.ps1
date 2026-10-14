<#
.SYNOPSIS
    Windows 11 Home System Tuning & GPO Policy Automation Engine (Production Edition v5).

.DESCRIPTION
    Manifest-driven engine. Every tweak lives as data in Win11Home_tuning_manifest.psd1; this
    script validates it, gates each item by edition/build/prerequisite, captures exact state,
    applies with verification, journals crash-safe and emits an exact LIFO rollback.

    Modes:
      Apply                (default) evaluate -> restore point -> apply -> verify -> rollback
      Audit                read-only drift report (+ JSON); exit 3 on drift; -Notify pops a dialog
      RegisterAuditTask    elevated logon task that audits from a hardened engine snapshot
      UnregisterAuditTask  removes that task

    Runs identically on Windows PowerShell 5.1 and PowerShell 7.x (64-bit host required).

    CARRIED FORWARD (v2-v4):
    -----------------------------------------------------------------------------------------------------
    FIX-1  Dry-run without rollback I/O           FIX-14 ASCII source, BOM+CRLF artifacts
    FIX-2  Per-item error isolation               FIX-15 CIM restore point, 24h throttle lifted, verified
    FIX-3  sudo forced to forceNewWindow          FIX-16 Exact kind + raw-data state capture, read-back verify
    FIX-4  Honest post-change verification        FIX-17 Created keys pruned only while empty (no -Recurse)
    FIX-5  Type-exact rollback literals           FIX-18 ExecutionPolicy via its 5.1 store (no false failure)
    FIX-6  HKCU hive ownership                    FIX-19 sudo via backing value, gated on inbox sudo.exe
    FIX-7  Medium-integrity Explorer respawn      FIX-20 Service state from registry, sc.exe exact rollback
    FIX-8  Telemetry task neutralization          FIX-21 Hardened backup dir (anti-LPE), no link following
    FIX-9  LIFO rollback + crash-safe journal     FIX-22 Desktop-owner SID check (OTS elevation stop)
    FIX-10 TaskPath normalization (root-safe)     FIX-23 Session-scoped shell refresh, polled respawn
    FIX-11 AutoRestartShell probe                 FIX-24 64-bit host guard
    FIX-12 Search suggestions via Policies hive   FIX-25 Transcript, per-step rollback status, exit codes
    FIX-13 (superseded by FIX-20)                 FIX-26 Policy accuracy corrections

    v5 ENHANCEMENTS:
    -----------------------------------------------------------------------------------------------------
    [FIX-27] Declarative manifest: data-only .psd1 (no code execution) with strict schema validation
            BEFORE any action - unknown keys, wrong types, duplicate Ids, duplicate Path+Name, and a
            character whitelist for every value that reaches a native command line. Tag filtering
            via -Include / -Exclude. Manifest SHA256 recorded in transcript, rollback and run record.

    [FIX-28] Audit & drift detection: -Mode Audit is read-only, reports Compliant / Drift / N/A per
            item, writes Audit_<ts>.json (newest 30 kept), flags a feature update since the last
            apply, lists the rollback chain, and exits 3 on drift. -Notify raises a dialog.
            RegisterAuditTask runs this at logon, elevated, from a byte-verified snapshot of engine +
            manifest inside the hardened folder - never from a user-writable path.

    [FIX-29] Edition / build / prerequisite gating: EditionID tier (Home < Pro < Enterprise), MinBuild,
            RequiresPath. Items the SKU ignores are reported N/A instead of [APPLIED];
            -ApplyIneffective writes them anyway for GPO parity.

    [FIX-30] Registry layer on .NET RegistryKey with an explicit 64-bit view (OpenBaseKey Registry64),
            shared verbatim by tuning and rollback; supports the unnamed (default) value.

    [FIX-31] Evaluate-first apply: with zero drift there is no restore point, journal, rollback or
            Explorer restart. Explorer restarts only when a shell-affecting change was applied.

    [FIX-32] Rollback preview & evidence: generated scripts support -WhatIf, carry a 64-bit guard, and
            their SHA256 lands in the transcript and Run_<ts>.json. Rollback scripts are never
            auto-deleted (they form the chain back to the pristine state).

    [FIX-33] New item kinds: Service, Feature (DISM, exit 0/3010, never auto-reboots), NetAdapter
            advanced property (only if the driver exposes the keyword AND lists the value as valid,
            -NoRestart, keyed by InterfaceDescription), NetAdapterPower (AllowComputerToTurnOffDevice).

    v6 ENHANCEMENTS (Defender false-alarm remediation - NEVER disables protection):
    -----------------------------------------------------------------------------------------------------
    [FIX-34] Three Defender item kinds, all via supported Set-/Add-MpPreference cmdlets, each with an
            exact Remove-/restore rollback. These target FALSE POSITIVES only; the engine refuses, by
            construction, to disable real-time/cloud/behaviour/IOAV protection, to set any threat
            default action to Allow, or to add a drive-root or system-wide exclusion:
              - MpExclusion     : add an ExclusionPath / ExclusionProcess / ExclusionExtension for a
                                  user-owned tool path. Rollback removes exactly what this run added
                                  (a pre-existing exclusion is detected up front and left in place).
              - MpThreatAllow   : set ThreatIDDefaultAction = Allow for ONE detection the user has
                                  confirmed is a false positive (e.g. a self-built exe or Cheat Engine),
                                  scoped to a single ThreatID, never a severity tier.
              - MpPreference    : a whitelisted, non-protection-weakening preference. Only PUAProtection
                                  (Enabled/AuditMode/Disabled) and SubmitSamplesConsent are permitted;
                                  every protection-disabling preference name is rejected at validation.
            Tamper Protection does not block these cmdlets (it blocks only protection-disabling changes),
            so they apply on a stock Home box. Non-critical "scan finished / file blocked" toast spam is
            handled separately as ordinary Registry items under the Defender notification keys, leaving
            real threat alerts on. Defender items are OFF by default: they carry the Defender tag and run
            only with -Include Defender. Get-MpComputerStatus gates the whole class as N/A when Defender
            is not the active AV.

    [FIX-35] -Mode Rollback: run the newest rollback script, or the whole chain newest -> oldest with
            -All, without having to locate the file by hand. Each target is re-parsed and, where a Run
            record exists, SHA256-verified against the hash it was generated with; a parse failure or
            hash mismatch blocks the whole operation unless -Force is given. -WhatIf lists and checks the
            targets without running them. Scripts run in-process (already elevated + 64-bit).

.PARAMETER Mode
    Apply (default) | Audit | Rollback | RegisterAuditTask | UnregisterAuditTask.

.PARAMETER ManifestPath
    Manifest to load. Default: Win11Home_tuning_manifest.psd1 next to this script.

.PARAMETER Include
    Only items carrying at least one of these tags (comma-separated works with -File).

.PARAMETER Exclude
    Drop items carrying any of these tags.

.PARAMETER ApplyIneffective
    Also write items the current edition does not honor (GPO parity).

.PARAMETER Notify
    Audit mode: show a dialog when drift or a feature update is detected.

.PARAMETER SkipRestorePoint
    Apply mode: bypass Volume Shadow Copy restore point creation.

.PARAMETER All
    Rollback mode: run the WHOLE chain newest -> oldest (revert to the pristine baseline) instead of
    only the most recent rollback.

.PARAMETER Force
    Apply mode, non-interactive: suppress the HKCU ownership prompt, override the over-the-shoulder
    elevation stop, and continue without a verified restore point.
    Rollback mode: skip the confirmation prompt and run even scripts that failed the integrity check.

.PARAMETER WhatIf
    Apply mode dry run: current state is read, pending changes are listed as [PLANNED].
    Rollback mode: list and integrity-check the target scripts without executing them.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Win11Home_fine_tune_v6.ps1 -WhatIf
    First run on a stock Home install (Windows PowerShell defaults to the Restricted policy).

.EXAMPLE
    .\Win11Home_fine_tune_v6.ps1 -Exclude Network,Legacy

.EXAMPLE
    .\Win11Home_fine_tune_v6.ps1 -Mode Audit

.EXAMPLE
    .\Win11Home_fine_tune_v6.ps1 -Include Defender -WhatIf
    Preview only the Defender false-alarm items (off in a normal apply).

.EXAMPLE
    .\Win11Home_fine_tune_v6.ps1 -Mode Rollback
    Undo the most recent apply (integrity-checked against its Run record first).

.EXAMPLE
    .\Win11Home_fine_tune_v6.ps1 -Mode Rollback -All
    Revert the entire chain, newest -> oldest, back to the pristine baseline.

.EXAMPLE
    .\Win11Home_fine_tune_v6.ps1 -Mode RegisterAuditTask -Exclude Legacy

.NOTES
    Exit codes: 0 = clean | 1 = aborted (pre-flight, manifest or fatal) | 2 = completed with warnings
                3 = audit found drift
    Multiple runs form a chain: -Mode Rollback undoes the newest, -Mode Rollback -All reverts all.
#>

#Requires -RunAsAdministrator
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive console tool: colour-coded Write-Host output is the UI and is captured by the transcript.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Helpers run only behind the caller''s ShouldProcess gate, or unattended inside the generated rollback.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'All',
    Justification = 'Read in Invoke-RollbackMode via script scope; the analyzer does not trace cross-function script-scoped reads.')]
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Apply', 'Audit', 'Rollback', 'RegisterAuditTask', 'UnregisterAuditTask')]
    [string]$Mode = 'Apply',
    [string]$ManifestPath = (Join-Path -Path $PSScriptRoot -ChildPath 'Win11Home_tuning_manifest.psd1'),
    [string[]]$Include,
    [string[]]$Exclude,
    [switch]$ApplyIneffective,
    [switch]$Notify,
    [switch]$SkipRestorePoint,
    [switch]$All,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# ==============================================================================
# EXECUTION METADATA & STATE
# ==============================================================================
$ScriptVersion   = 'v6'
$ScriptTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$BackupRootDir   = Join-Path -Path $env:SystemDrive -ChildPath 'Win11Tuning_Backups'
$RollbackScript  = Join-Path -Path $BackupRootDir -ChildPath "Rollback_$ScriptTimestamp.ps1"
$JournalScript   = Join-Path -Path $BackupRootDir -ChildPath "Rollback_$ScriptTimestamp.journal.ps1"
$TranscriptLog   = Join-Path -Path $BackupRootDir -ChildPath "Tuning_$ScriptTimestamp.log"
$RunRecordPath   = Join-Path -Path $BackupRootDir -ChildPath "Run_$ScriptTimestamp.json"
$AuditRecordPath = Join-Path -Path $BackupRootDir -ChildPath "Audit_$ScriptTimestamp.json"
$AuditTaskPath   = '\Win11Tuning\'
$AuditTaskName   = 'DriftAudit'
$AuditKeep       = 30

$script:Results          = New-Object System.Collections.ArrayList
$script:QuietResults     = $false
$script:ExtraFailures    = 0                                                   # failures outside manifest items
$script:RollbackSteps    = New-Object System.Collections.ArrayList             # [FIX-9] emitted LIFO at finalization
$script:CreatedKeys      = New-Object System.Collections.Generic.List[string]  # [FIX-17] key levels created by this run
$script:TranscriptOn     = $false
$script:RestorePointNote = 'None (skipped or unverified)'
$script:EthernetCache    = $null
$script:DefenderStatus   = $null
$script:Utf8Bom          = New-Object System.Text.UTF8Encoding -ArgumentList $true    # [FIX-14] .ps1 artifacts
$script:Utf8NoBom        = New-Object System.Text.UTF8Encoding -ArgumentList $false   # JSON (RFC 8259: no BOM)
$TierRank                = @{ Home = 0; Pro = 1; Enterprise = 2; Unknown = 99 }

$IsDryRun  = [bool]$WhatIfPreference -and $Mode -eq 'Apply'
$SessionId = (Get-Process -Id $PID).SessionId

# -File passes "a,b" as one string: split so -Include/-Exclude behave the same from any launcher.
$Include = @($Include | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$Exclude = @($Exclude | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# ==============================================================================
# CORE HELPERS
# ==============================================================================

function Exit-Tuning {
    param([int]$Code = 0)
    if ($Mode -eq 'Apply' -and -not $IsDryRun -and $script:RollbackSteps.Count -eq 0 -and (Test-Path -LiteralPath $JournalScript)) {
        Remove-Item -LiteralPath $JournalScript -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false
    }
    if ($script:TranscriptOn) {
        $script:TranscriptOn = $false
        try { Stop-Transcript | Out-Null } catch { Write-Verbose 'Transcript was already stopped.' }
    }
    exit $Code
}

trap {
    Write-Host "`nFATAL: Unhandled error - $($_.Exception.Message)" -ForegroundColor Red
    if ($script:RollbackSteps.Count -gt 0) {
        Write-Host "Revert the $($script:RollbackSteps.Count) change(s) made so far with: $JournalScript" -ForegroundColor Yellow
    }
    Exit-Tuning 1
}

function ConvertTo-PSQuoted {
    param([AllowEmptyString()][string]$Text)
    # PowerShell also treats U+2018..U+201B as single-quote characters.
    return "'" + ($Text -replace "[\u0027\u2018\u2019\u201A\u201B]", '$0$0') + "'"
}

# [FIX-5/16] Parenthesised, type-exact PowerShell literal for a captured registry value.
function ConvertTo-PSLiteral {
    param([AllowNull()][object]$Value, [Microsoft.Win32.RegistryValueKind]$Kind)
    switch ($Kind) {
        'String'       { return '(' + (ConvertTo-PSQuoted "$Value") + ')' }
        'ExpandString' { return '(' + (ConvertTo-PSQuoted "$Value") + ')' }
        'MultiString'  { return '([string[]]@(' + ((@($Value) | ForEach-Object { ConvertTo-PSQuoted "$_" }) -join ', ') + '))' }
        'Binary'       { return '([byte[]]@(' + ((@($Value) | ForEach-Object { '0x{0:X2}' -f [byte]$_ }) -join ',') + '))' }
        'DWord'        { return '([int]' + [int]$Value + ')' }
        'QWord'        { return '([long]' + [long]$Value + ')' }
        default        { throw "Unsupported registry value kind '$Kind': exact rollback cannot be guaranteed, change refused." }
    }
}

function Format-DisplayValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '<absent>' }
    if ($Value -is [array]) { return '[' + (@($Value) -join ',') + ']' }
    if ($Value -is [string] -and $Value -eq '') { return "''" }
    return "$Value"
}

function Write-Utf8BomFile {
    param([Parameter(Mandatory = $true)][string]$Path, [AllowEmptyString()][string]$Content = '', [switch]$Append)
    $text = $Content -replace "`r?`n", "`r`n"
    if (-not $text.EndsWith("`r`n")) { $text += "`r`n" }
    if ($Append) { [System.IO.File]::AppendAllText($Path, $text, $script:Utf8Bom) }
    else         { [System.IO.File]::WriteAllText($Path, $text, $script:Utf8Bom) }
}

function Write-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][object]$InputObject)
    [System.IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $InputObject -Depth 6), $script:Utf8NoBom)
}

# ------------------------------------------------------------------------------
# ROLLBACK RUNTIME. Executed here AND serialized verbatim into the generated
# journal/rollback scripts (single source of truth). Keep self-contained.
# ------------------------------------------------------------------------------

# [FIX-30] Explicit 64-bit registry view; HKLM:\ and HKCU:\ only. Caller closes the returned key.
function Open-RegKey {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$Writable, [switch]$Create)
    if ($Path -notmatch '^(HKLM|HKCU):\\?(.*)$') { throw "Unsupported registry path '$Path' (HKLM:\ or HKCU:\ only)." }
    $hive = if ($Matches[1] -eq 'HKLM') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
    $sub  = $Matches[2].Trim('\')
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
    if (-not $sub) { return $base }
    try {
        if ($Create) { return $base.CreateSubKey($sub) }
        return $base.OpenSubKey($sub, [bool]$Writable)
    } finally {
        $base.Close()
    }
}

function ConvertTo-RegData {
    param([AllowNull()][AllowEmptyString()][AllowEmptyCollection()][object]$Value, [Parameter(Mandatory = $true)][string]$Kind)
    switch ($Kind) {
        'DWord'       { $n = [long]$Value; if ($n -gt [int]::MaxValue) { $n -= 4294967296 }; return [int]$n }
        'QWord'       { return [long]$Value }
        'MultiString' { return , ([string[]]@($Value)) }
        'Binary'      { return , ([byte[]]@($Value)) }
        default       { return [string]$Value }
    }
}

function Set-RegData {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name,
        [AllowNull()][AllowEmptyString()][AllowEmptyCollection()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Kind
    )
    $key = Open-RegKey -Path $Path -Create
    try {
        $key.SetValue($Name, (ConvertTo-RegData -Value $Value -Kind $Kind), [Microsoft.Win32.RegistryValueKind]$Kind)
    } finally {
        $key.Close()
    }
}

function Invoke-RbStep {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Label, [Parameter(Mandatory = $true)][scriptblock]$Action)
    if (-not $PSCmdlet.ShouldProcess($Label, 'Rollback step')) { $script:RbSkipped++; return }
    try {
        & $Action
        $script:RbOk++
        Write-Host "  [ROLLBACK] $Label" -ForegroundColor Cyan
    } catch {
        $script:RbFail++
        Write-Warning "[ROLLBACK FAILED] $Label : $($_.Exception.Message)"
    }
}

function Restore-RbValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowEmptyCollection()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Kind
    )
    Set-RegData -Path $Path -Name $Name -Value $Value -Kind $Kind
}

function Remove-RbValue {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name)
    $key = Open-RegKey -Path $Path -Writable
    if ($null -eq $key) { return }
    try {
        if ($key.GetValueNames() -contains $Name) { $key.DeleteValue($Name) }
    } finally {
        $key.Close()
    }
}

# [FIX-17] Prunes key levels created by the tuning run, deepest first, only while they are empty.
function Remove-RbEmptyKey {
    param([Parameter(Mandatory = $true)][string[]]$Path)
    foreach ($p in $Path) {
        $key = Open-RegKey -Path $p
        if ($null -eq $key) { continue }
        $isEmpty = ($key.SubKeyCount -eq 0 -and $key.ValueCount -eq 0)
        $key.Close()
        if (-not $isEmpty) { return }   # a non-empty level shields every ancestor above it
        $cut    = $p.LastIndexOf('\')
        $parent = Open-RegKey -Path $p.Substring(0, $cut) -Writable
        try { $parent.DeleteSubKey($p.Substring($cut + 1), $false) } finally { $parent.Close() }
    }
}

# [FIX-7/11/23] Session-scoped shell refresh preferring Winlogon's medium-integrity respawn.
# Returns 'Respawned' | 'Fallback' (started from this, possibly elevated, process) | 'Dead'.
function Restart-RbShell {
    param([int]$WaitSeconds = 6)
    $sid    = (Get-Process -Id $PID).SessionId
    $old    = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $sid })
    $oldIds = @($old | ForEach-Object { $_.Id })
    if ($old.Count -gt 0) {
        $old | Stop-Process -Force -ErrorAction SilentlyContinue -Confirm:$false
        $old | Wait-Process -Timeout 3 -ErrorAction SilentlyContinue
    }
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    do {
        Start-Sleep -Milliseconds 250
        $alive = @(Get-Process -Name explorer -ErrorAction SilentlyContinue |
            Where-Object { $_.SessionId -eq $sid -and $oldIds -notcontains $_.Id }).Count -gt 0
    } until ($alive -or (Get-Date) -ge $deadline)
    if ($alive) { return 'Respawned' }

    Start-Process -FilePath (Join-Path -Path $env:SystemRoot -ChildPath 'explorer.exe')
    Start-Sleep -Milliseconds 1500
    if (@(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $sid }).Count -gt 0) {
        return 'Fallback'
    }
    return 'Dead'
}

# ------------------------------------------------------------------------------
# REGISTRY STATE (tuning side)
# ------------------------------------------------------------------------------

function Get-RegistryValueState {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name)
    $key = Open-RegKey -Path $Path
    if ($null -eq $key) { return $null }
    try {
        if ($key.GetValueNames() -notcontains $Name) { return $null }
        return [pscustomobject]@{
            Kind  = $key.GetValueKind($Name)
            Value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
    } finally {
        $key.Close()
    }
}

function Test-RegKey {
    param([Parameter(Mandatory = $true)][string]$Path)
    $key = Open-RegKey -Path $Path
    if ($null -eq $key) { return $false }
    $key.Close()
    return $true
}

function Test-RegistryValueEqual {
    param([AllowNull()][object]$State, [AllowNull()][object]$Value, [string]$Type)
    if ($null -eq $State -or "$($State.Kind)" -ne $Type) { return $false }
    switch ($Type) {
        'MultiString'  { return ((@($State.Value) -join "`0") -ceq (@($Value) -join "`0")) }
        'Binary'       { return ((@($State.Value) -join ',') -eq (@($Value) -join ',')) }
        'String'       { return ("$($State.Value)" -ceq "$Value") }
        'ExpandString' { return ("$($State.Value)" -ceq "$Value") }
        default        { return ([long]$State.Value -eq [long]$Value) }
    }
}

function Get-ServiceStartMode {
    param([Parameter(Mandatory = $true)][string]$Name)
    $key   = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $start = Get-RegistryValueState -Path $key -Name 'Start'
    if ($null -eq $start) { return $null }
    $delayed = Get-RegistryValueState -Path $key -Name 'DelayedAutostart'
    switch ([int]$start.Value) {
        2       { if ($null -ne $delayed -and [int]$delayed.Value -eq 1) { return 'delayed-auto' }; return 'auto' }
        3       { return 'demand' }
        4       { return 'disabled' }
        default { return $null }   # boot/system drivers: never touched
    }
}

# ------------------------------------------------------------------------------
# ROLLBACK COMPOSITION
# ------------------------------------------------------------------------------

function Get-RollbackPrelude {
    $lines = @(
        "`$ErrorActionPreference = 'Stop'",
        '$script:RbOk = 0; $script:RbFail = 0; $script:RbSkipped = 0',
        "if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { throw 'Run this rollback from 64-bit PowerShell.' }",
        ''
    )
    foreach ($fn in 'Open-RegKey', 'ConvertTo-RegData', 'Set-RegData', 'Invoke-RbStep', 'Restore-RbValue', 'Remove-RbValue', 'Remove-RbEmptyKey', 'Restart-RbShell') {
        $lines += "function $fn {" + (Get-Item -LiteralPath "function:$fn").ScriptBlock.ToString() + '}'
        $lines += ''
    }
    return ($lines -join "`r`n")
}

# [FIX-9] Write-ahead: buffered for the LIFO script AND appended to the journal BEFORE the mutation.
function Add-RollbackStep {
    param([Parameter(Mandatory = $true)][string]$Label, [Parameter(Mandatory = $true)][string]$Action, [string]$Comment = '')
    if ($IsDryRun) { return }
    $note  = ($Comment -replace '[\r\n]+', ' ').Trim()
    $block = "# $note`r`nInvoke-RbStep -Label $(ConvertTo-PSQuoted $Label) -Action { $Action }`r`n"
    [void]$script:RollbackSteps.Add($block)
    Write-Utf8BomFile -Path $JournalScript -Content $block -Append
}

# ------------------------------------------------------------------------------
# STORAGE, RESTORE POINT, IDENTITY
# ------------------------------------------------------------------------------

# [FIX-21] Backup directory only SYSTEM/Administrators can write: its rollback scripts run elevated.
function Initialize-SecureBackupDir {
    param([Parameter(Mandatory = $true)][string]$Path)
    $reparse = [System.IO.FileAttributes]::ReparsePoint
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band $reparse)) {
            throw "$Path exists but is not a plain directory (file, junction or symlink). Refusing to use it."
        }
    } else {
        New-Item -Path $Path -ItemType Directory -Force -WhatIf:$false -Confirm:$false | Out-Null
    }

    $admins  = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none    = [System.Security.AccessControl.PropagationFlags]::None
    $acl     = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($ace in @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'), @('S-1-5-32-545', 'ReadAndExecute'))) {
        $sid  = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $ace[0]
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
            $sid, [System.Security.AccessControl.FileSystemRights]$ace[1], $inherit, $none, 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -WhatIf:$false -Confirm:$false

    Get-ChildItem -LiteralPath $Path -Force -File |
        Where-Object { -not ($_.Attributes -band $reparse) } |
        ForEach-Object {
            $fileAcl = New-Object System.Security.AccessControl.FileSecurity
            $fileAcl.SetOwner($admins)
            $fileAcl.SetAccessRuleProtection($false, $false)
            Set-Acl -LiteralPath $_.FullName -AclObject $fileAcl -WhatIf:$false -Confirm:$false
        }
}

# [FIX-15] CIM restore point (5.1 and 7), throttle lifted for one call, verified by description.
function New-VerifiedRestorePoint {
    param([Parameter(Mandatory = $true)][string]$Description)
    $srKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $freq  = 'SystemRestorePointCreationFrequency'
    $saved = Get-RegistryValueState -Path $srKey -Name $freq
    try {
        try {
            [void](Invoke-CimMethod -Namespace 'root/default' -ClassName 'SystemRestore' -MethodName 'Enable' `
                -Arguments @{ Drive = "$env:SystemDrive\" })
        } catch {
            Write-Verbose "SystemRestore.Enable: $($_.Exception.Message)"
        }
        # CreateRestorePoint returns S_OK even when it silently skips inside the 24h window.
        Set-RegData -Path $srKey -Name $freq -Value 0 -Kind 'DWord'
        $result = Invoke-CimMethod -Namespace 'root/default' -ClassName 'SystemRestore' -MethodName 'CreateRestorePoint' `
            -Arguments @{ Description = $Description; RestorePointType = [uint32]12; EventType = [uint32]100 }
        if ($result.ReturnValue -ne 0) { throw ('CreateRestorePoint returned 0x{0:X8}' -f $result.ReturnValue) }
        return (@(Get-CimInstance -Namespace 'root/default' -ClassName 'SystemRestore' |
            Where-Object { $_.Description -eq $Description }) | Select-Object -Last 1)
    } finally {
        if ($null -eq $saved) { Remove-RbValue -Path $srKey -Name $freq }
        else { Set-RegData -Path $srKey -Name $freq -Value $saved.Value -Kind "$($saved.Kind)" }
    }
}

# [FIX-6/22] The elevated token must belong to the interactive desktop owner, or HKCU lands in the wrong hive.
function Confirm-HkcuTarget {
    param([switch]$WarnOnly)
    Write-Host "  Running as : $($script:Identity.Name)" -ForegroundColor White
    Write-Host "  HKCU hive  : SID $($script:MySid)" -ForegroundColor White
    $owners = @()
    try {
        $owners = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe' AND SessionId=$SessionId" |
            ForEach-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid } |
            Where-Object { $_ } | Select-Object -Unique)
    } catch {
        Write-Verbose "Shell owner query failed: $($_.Exception.Message)"
    }

    if ($owners -contains $script:MySid) {
        Write-Host '  [VERIFIED] Elevated token belongs to the interactive desktop owner. HKCU target is correct.' -ForegroundColor Green
        return
    }
    if ($owners.Count -gt 0) {
        Write-Host '  CRITICAL: Over-the-shoulder elevation detected.' -ForegroundColor Red
        Write-Host "            Desktop owner SID : $($owners -join ', ')" -ForegroundColor Red
        Write-Host "            This process SID  : $($script:MySid)" -ForegroundColor Red
        Write-Host '            HKCU items would target the WRONG profile. Sign in as the target account and re-run.' -ForegroundColor Red
        if ($WarnOnly -or $IsDryRun) { Write-Host '  [WARN-ONLY] Continuing (read-only run).' -ForegroundColor DarkYellow; return }
        if (-not $Force) { Exit-Tuning 1 }
        Write-Host '  [OVERRIDE] Continuing (-Force).' -ForegroundColor DarkYellow
        return
    }
    Write-Host "  [UNVERIFIED] No Explorer shell in session $SessionId; desktop owner cannot be auto-verified." -ForegroundColor DarkYellow
    if ($WarnOnly -or $IsDryRun -or $Force) { return }
    $answer = Read-Host "  Apply HKCU items to $($script:Identity.Name)? (Y/N)"
    if ($answer -notmatch '^[Yy]') {
        Write-Host '  Aborted by user. Re-run from the target account, or use -Force to bypass.' -ForegroundColor Red
        Exit-Tuning 1
    }
}

# ------------------------------------------------------------------------------
# [FIX-27] MANIFEST LOAD & VALIDATION
# ------------------------------------------------------------------------------

function Import-TuningManifest {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Manifest not found: $Path" }
    $data   = Import-PowerShellDataFile -LiteralPath $Path
    $errors = New-Object System.Collections.Generic.List[string]
    if ($data.SchemaVersion -ne 1) { $errors.Add("SchemaVersion must be 1 (found '$($data.SchemaVersion)').") }

    $common   = 'Id', 'Kind', 'Group', 'Tags', 'Description', 'Edition', 'MinBuild', 'RequiresPath', 'Reboot', 'RestartShell'
    $kindKeys = @{
        Registry        = @{ Required = @('Path', 'Name', 'Value'); Optional = @('Type') }
        Task            = @{ Required = @('TaskPath', 'TaskName'); Optional = @() }
        Service         = @{ Required = @('Name', 'StartMode'); Optional = @('Stop') }
        Feature         = @{ Required = @('FeatureName'); Optional = @() }
        NetAdapter      = @{ Required = @('Keyword', 'Value'); Optional = @() }
        NetAdapterPower = @{ Required = @('Property', 'Value'); Optional = @() }
        MpExclusion     = @{ Required = @('ExclusionType', 'Value'); Optional = @() }
        MpThreatAllow   = @{ Required = @('ThreatId'); Optional = @() }
        MpPreference    = @{ Required = @('Preference', 'Value'); Optional = @() }
    }
    $regTypes = 'DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary'
    $isInt    = { param($v) $v -is [int] -or $v -is [long] }
    $ids      = @{}
    $regSeen  = @{}
    $items    = New-Object System.Collections.Generic.List[hashtable]
    $index    = 0

    foreach ($raw in @($data.Items)) {
        $index++
        if ($raw -isnot [hashtable]) { $errors.Add("Item #$index is not a hashtable."); continue }
        $where = if ($raw.Id) { "Item '$($raw.Id)'" } else { "Item #$index" }
        $before = $errors.Count

        foreach ($k in 'Id', 'Kind', 'Group', 'Tags', 'Description') {
            if (-not $raw.ContainsKey($k) -or [string]::IsNullOrWhiteSpace([string]$raw[$k])) { $errors.Add("$where : missing '$k'.") }
        }
        $kind = [string]$raw.Kind
        if (-not $kindKeys.ContainsKey($kind)) { $errors.Add("$where : unknown Kind '$kind'."); continue }
        foreach ($k in $kindKeys[$kind].Required) { if (-not $raw.ContainsKey($k)) { $errors.Add("$where : Kind $kind requires '$k'.") } }
        $allowed = $common + $kindKeys[$kind].Required + $kindKeys[$kind].Optional
        foreach ($k in $raw.Keys) { if ($allowed -notcontains $k) { $errors.Add("$where : unknown key '$k'.") } }
        if ($errors.Count -gt $before) { continue }

        $id = [string]$raw.Id
        if ($id -cnotmatch '^[a-z0-9][a-z0-9._-]*$') { $errors.Add("$where : Id must match ^[a-z0-9][a-z0-9._-]*$.") }
        if ($ids.ContainsKey($id)) { $errors.Add("$where : duplicate Id.") } else { $ids[$id] = $true }

        $tags = @($raw.Tags | ForEach-Object { [string]$_ })
        if ($tags.Count -eq 0 -or @($tags | Where-Object { $_ -notmatch '^[A-Za-z0-9_-]+$' }).Count -gt 0) {
            $errors.Add("$where : Tags must be one or more [A-Za-z0-9_-] words.")
        }
        $edition = if ($raw.ContainsKey('Edition')) { [string]$raw.Edition } else { 'Home' }
        if ('Home', 'Pro', 'Enterprise' -notcontains $edition) { $errors.Add("$where : Edition must be Home, Pro or Enterprise.") }
        $minBuild = 0
        if ($raw.ContainsKey('MinBuild')) {
            if (& $isInt $raw.MinBuild) { $minBuild = [int]$raw.MinBuild } else { $errors.Add("$where : MinBuild must be an integer.") }
        }
        foreach ($b in 'Reboot', 'RestartShell', 'Stop') {
            if ($raw.ContainsKey($b) -and $raw[$b] -isnot [bool]) { $errors.Add("$where : $b must be `$true or `$false.") }
        }

        $norm = @{
            Id = $id; Kind = $kind; Group = [string]$raw.Group; Tags = [string[]]$tags; Description = [string]$raw.Description
            Edition = $edition; MinBuild = $minBuild; RequiresPath = [string]$raw.RequiresPath
            Reboot = [bool]$raw.Reboot; RestartShell = [bool]$raw.RestartShell
        }

        switch ($kind) {
            'Registry' {
                $type = if ($raw.ContainsKey('Type')) { [string]$raw.Type } else { 'DWord' }
                $regPath = [string]$raw.Path
                $regName = [string]$raw.Name
                if ($regTypes -notcontains $type) { $errors.Add("$where : Type must be one of $($regTypes -join ', ').") }
                if ($regPath -notmatch '^(HKLM|HKCU):\\[^\\]' -or $regPath.EndsWith('\') -or $regPath.Contains('\\')) {
                    $errors.Add("$where : Path must be a canonical HKLM:\... or HKCU:\... key path.")
                }
                $value = $raw.Value
                switch ($type) {
                    'DWord'        { if (-not (& $isInt $value) -or [long]$value -lt [int]::MinValue -or [long]$value -gt [uint32]::MaxValue) { $errors.Add("$where : DWord Value must be a 32-bit integer.") } }
                    'QWord'        { if (-not (& $isInt $value)) { $errors.Add("$where : QWord Value must be an integer.") } }
                    'String'       { if ($value -isnot [string]) { $errors.Add("$where : String Value must be a string.") } }
                    'ExpandString' { if ($value -isnot [string]) { $errors.Add("$where : ExpandString Value must be a string.") } }
                    'MultiString'  {
                        if (@($value | Where-Object { $_ -isnot [string] }).Count -gt 0) { $errors.Add("$where : MultiString Value must be string(s).") }
                        else { $value = [string[]]@($value) }
                    }
                    'Binary'       {
                        if (@($value | Where-Object { -not (& $isInt $_) -or $_ -lt 0 -or $_ -gt 255 }).Count -gt 0) { $errors.Add("$where : Binary Value must be bytes 0-255.") }
                        else { $value = [byte[]]@($value) }
                    }
                }
                $regKey = "$regPath|$regName".ToLowerInvariant()
                if ($regSeen.ContainsKey($regKey)) { $errors.Add("$where : duplicate Path+Name with '$($regSeen[$regKey])' (breaks journal ordering).") }
                else { $regSeen[$regKey] = $id }
                $norm.Path = $regPath; $norm.Name = $regName; $norm.Value = $value; $norm.Type = $type
            }
            'Task' {
                $norm.TaskPath = [string]$raw.TaskPath; $norm.TaskName = [string]$raw.TaskName
                if (-not $norm.TaskName) { $errors.Add("$where : TaskName is empty.") }
            }
            'Service' {
                $norm.Name = [string]$raw.Name; $norm.StartMode = [string]$raw.StartMode; $norm.Stop = [bool]$raw.Stop
                if ($norm.Name -notmatch '^[A-Za-z0-9_.-]+$') { $errors.Add("$where : Service Name contains unsafe characters.") }
                if ('auto', 'delayed-auto', 'demand', 'disabled' -notcontains $norm.StartMode) { $errors.Add("$where : StartMode must be auto, delayed-auto, demand or disabled.") }
            }
            'Feature' {
                $norm.FeatureName = [string]$raw.FeatureName
                if ($norm.FeatureName -notmatch '^[A-Za-z0-9_.-]+$') { $errors.Add("$where : FeatureName contains unsafe characters.") }
            }
            'NetAdapter' {
                $norm.Keyword = [string]$raw.Keyword; $norm.Value = [string]$raw.Value
                if ($norm.Keyword -notmatch '^\*?[A-Za-z0-9_.-]+$') { $errors.Add("$where : Keyword contains unsafe characters.") }
                if ($norm.Value -notmatch '^[A-Za-z0-9_.-]+$') { $errors.Add("$where : Value contains unsafe characters.") }
            }
            'NetAdapterPower' {
                $norm.Property = [string]$raw.Property; $norm.Value = [string]$raw.Value
                if ($norm.Property -ne 'AllowComputerToTurnOffDevice') { $errors.Add("$where : only Property 'AllowComputerToTurnOffDevice' is supported.") }
                if ('Disabled', 'Enabled' -notcontains $norm.Value) { $errors.Add("$where : Value must be Disabled or Enabled.") }
            }
            'MpExclusion' {
                $norm.ExclusionType = [string]$raw.ExclusionType; $norm.Value = [string]$raw.Value
                # Refuse system-wide / drive-root exclusions: those are protection gaps, not false-alarm fixes.
                if ('Path', 'Process', 'Extension' -notcontains $norm.ExclusionType) { $errors.Add("$where : ExclusionType must be Path, Process or Extension.") }
                elseif ([string]::IsNullOrWhiteSpace($norm.Value)) { $errors.Add("$where : exclusion Value is empty.") }
                elseif ($norm.Value -match '["|<>]' -or $norm.Value -match '[\x00-\x1f]') { $errors.Add("$where : exclusion Value contains illegal characters.") }
                elseif ($norm.ExclusionType -in 'Path', 'Process') {
                    $expanded    = [Environment]::ExpandEnvironmentVariables($norm.Value)
                    $startsEnv   = $norm.Value -match '^%[A-Za-z0-9_()]+%[\\/]+[^\\/]'        # %ProgramFiles%\Tool (has a leaf)
                    $startsDrive = $norm.Value -match '^[A-Za-z]:\\+[^\\]'                     # C:\Tool (has a leaf)
                    $rootLike    = '^([A-Za-z]:|%[A-Za-z0-9_()]+%)[\\/]*\**$'                  # drive or %ENV% with only slashes/stars after
                    if ($norm.Value -eq '*' -or $norm.Value -match $rootLike -or $expanded -match '^[A-Za-z]:[\\/]*\**$') {
                        $errors.Add("$where : refusing a drive-root or whole-system exclusion.")
                    } elseif (-not ($startsEnv -or $startsDrive)) {
                        $errors.Add("$where : exclusion must be an absolute path to a specific folder (drive letter or %ENV% prefix, with a subfolder).")
                    }
                }
                elseif ($norm.ExclusionType -eq 'Extension' -and $norm.Value -notmatch '^\.?[A-Za-z0-9_]{1,16}$') { $errors.Add("$where : Extension must be a bare file extension (e.g. .tmp).") }
            }
            'MpThreatAllow' {
                # ThreatID is a detection identifier from Get-MpThreat.
                if ("$($raw.ThreatId)" -notmatch '^[0-9]{1,20}$') { $errors.Add("$where : ThreatId must be a positive integer (see Get-MpThreat).") }
                else { $norm.ThreatId = [string]$raw.ThreatId }
            }
            'MpPreference' {
                $norm.Preference = [string]$raw.Preference; $norm.Value = [string]$raw.Value
                # WHITELIST only. Any preference that could turn OFF a protection layer
                # (DisableRealtimeMonitoring, *ThreatDefaultAction = Allow, MAPSReporting = 0, ...) is
                # intentionally absent and therefore rejected below.
                $allowedPref = [ordered]@{
                    PUAProtection        = @('Disabled', 'Enabled', 'AuditMode')
                    SubmitSamplesConsent = @('AlwaysPrompt', 'SendSafeSamples', 'NeverSend', 'SendAllSamples')
                }
                if (-not $allowedPref.Contains($norm.Preference)) { $errors.Add("$where : Preference '$($norm.Preference)' is not allowed ($(($allowedPref.Keys) -join ', ')). Protection-disabling preferences are refused.") }
                elseif ($allowedPref[$norm.Preference] -notcontains $norm.Value) { $errors.Add("$where : $($norm.Preference) Value must be one of $($allowedPref[$norm.Preference] -join ', ').") }
            }
        }
        $items.Add($norm)
    }
    if ($index -eq 0) { $errors.Add('Manifest contains no Items.') }
    if ($errors.Count -gt 0) { throw ("Manifest validation failed ($($errors.Count) error(s)):`n  - " + ($errors -join "`n  - ")) }

    return [pscustomobject]@{
        Path  = (Resolve-Path -LiteralPath $Path).ProviderPath
        Hash  = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        Items = $items.ToArray()
    }
}

function Select-ManifestItem {
    param([Parameter(Mandatory = $true)][hashtable[]]$Items)
    foreach ($item in $Items) {
        if ($Include.Count -gt 0 -and @($item.Tags | Where-Object { $Include -contains $_ }).Count -eq 0) { continue }
        if ($Exclude.Count -gt 0 -and @($item.Tags | Where-Object { $Exclude -contains $_ }).Count -gt 0) { continue }
        $item
    }
}

function Get-MachineProfile {
    $cv  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $get = { param($n) $s = Get-RegistryValueState -Path $cv -Name $n; if ($null -ne $s) { $s.Value } }
    $edition = [string](& $get 'EditionID')
    $tier = switch -Regex ($edition) {
        '^(Enterprise|Education|ProfessionalEducation|IoTEnterprise|Server)' { 'Enterprise'; break }
        '^Professional' { 'Pro'; break }
        '^Core'         { 'Home'; break }
        default         { 'Unknown' }
    }
    return [pscustomobject]@{
        EditionID      = $edition
        Tier           = $tier
        Build          = [int](& $get 'CurrentBuild')
        UBR            = [int](& $get 'UBR')
        DisplayVersion = [string](& $get 'DisplayVersion')
    }
}

# [FIX-29] Returns $null when the item applies to this machine, otherwise the reason it does not.
function Get-ItemGateReason {
    param([Parameter(Mandatory = $true)][hashtable]$Item)
    if ($Item.MinBuild -gt 0 -and $script:Machine.Build -lt $Item.MinBuild) {
        return "requires build $($Item.MinBuild)+ (this: $($script:Machine.Build))"
    }
    if ($Item.RequiresPath -and -not (Test-Path -LiteralPath ([Environment]::ExpandEnvironmentVariables($Item.RequiresPath)))) {
        return "prerequisite missing: $($Item.RequiresPath)"
    }
    if (-not $ApplyIneffective -and $TierRank[$script:Machine.Tier] -lt $TierRank[$Item.Edition]) {
        return "honored only on $($Item.Edition)+ editions (this: $($script:Machine.EditionID)); -ApplyIneffective writes it anyway"
    }
    return $null
}

function Get-ItemTarget {
    param([Parameter(Mandatory = $true)][hashtable]$Item)
    switch ($Item.Kind) {
        'Registry'        { return "$($Item.Path)\$(if ($Item.Name -eq '') { '(default)' } else { $Item.Name })" }
        'Task'            { return "Task $($Item.TaskPath)$($Item.TaskName)" }
        'Service'         { return "Service $($Item.Name)" }
        'Feature'         { return "Feature $($Item.FeatureName)" }
        'NetAdapter'      { return "Ethernet * $($Item.Keyword)" }
        'NetAdapterPower' { return "Ethernet * $($Item.Property)" }
        'MpExclusion'     { return "Defender Exclusion$($Item.ExclusionType) '$($Item.Value)'" }
        'MpThreatAllow'   { return "Defender ThreatID $($Item.ThreatId) -> Allow" }
        'MpPreference'    { return "Defender $($Item.Preference) = $($Item.Value)" }
    }
}

# ------------------------------------------------------------------------------
# RESULT RECORDING
# ------------------------------------------------------------------------------

function Add-Result {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Item,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][ValidateSet('Applied', 'Compliant', 'Drift', 'Planned', 'NA', 'Failed')][string]$Outcome,
        [string]$Current = '', [string]$Desired = '', [string]$Detail = ''
    )
    [void]$script:Results.Add([pscustomobject]@{
        Id = $Item.Id; Kind = $Item.Kind; Target = $Target; Outcome = $Outcome
        Current = $Current; Desired = $Desired; Detail = $Detail
        Reboot = $Item.Reboot; RestartShell = $Item.RestartShell
    })
    if ($script:QuietResults) { return }
    switch ($Outcome) {
        'Applied'   { Write-Host "  [APPLIED] $Target = $Desired  ($($Item.Description))$(if ($Detail) { " - $Detail" })" -ForegroundColor Green }
        'Compliant' { Write-Host "  [OK] $Target = $Desired  ($($Item.Description))" -ForegroundColor DarkGray }
        'Drift'     { Write-Host "  [DRIFT] $Target : $Current -> $Desired  ($($Item.Description))" -ForegroundColor Yellow }
        'Planned'   { Write-Host "  [PLANNED] $Target : $Current -> $Desired  ($($Item.Description))" -ForegroundColor Cyan }
        'NA'        { Write-Host "  [N/A] $Target : $Detail" -ForegroundColor DarkGray }
        'Failed'    { Write-Warning "[FAILED] $Target : $Detail" }
    }
}

# Shared tail of every handler: evaluate / dry-run / confirm gate. Returns $true when the caller should mutate.
function Test-MutationGate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '',
        Justification = 'Delegated gate: ShouldProcess runs on the calling handler''s $PSCmdlet, which declares SupportsShouldProcess.')]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Item, [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Phase, [string]$Current, [string]$Desired,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCmdlet]$Cmdlet
    )
    if ($Phase -eq 'Evaluate') { Add-Result -Item $Item -Target $Target -Outcome Drift -Current $Current -Desired $Desired; return $false }
    if ($IsDryRun)            { Add-Result -Item $Item -Target $Target -Outcome Planned -Current $Current -Desired $Desired; return $false }
    if (-not $Cmdlet.ShouldProcess($Target, "Set $Desired - $($Item.Description)")) {
        Add-Result -Item $Item -Target $Target -Outcome NA -Current $Current -Desired $Desired -Detail 'declined at -Confirm prompt'
        return $false
    }
    return $true
}

# ------------------------------------------------------------------------------
# ITEM HANDLERS (capture -> compliance -> gate -> write-ahead rollback -> mutate -> verify)
# ------------------------------------------------------------------------------

function Invoke-RegistryItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$Item, [Parameter(Mandatory = $true)][ValidateSet('Evaluate', 'Apply')][string]$Phase)
    $path    = $Item.Path
    $name    = $Item.Name
    $target  = Get-ItemTarget -Item $Item
    $desired = Format-DisplayValue $Item.Value
    try {
        $before  = Get-RegistryValueState -Path $path -Name $name
        $current = if ($null -eq $before) { '<absent>' } else { "$(Format-DisplayValue $before.Value) ($($before.Kind))" }
        if (Test-RegistryValueEqual -State $before -Value $Item.Value -Type $Item.Type) {
            Add-Result -Item $Item -Target $target -Outcome Compliant -Current $current -Desired $desired
            return
        }
        # [FIX-16] Original kind + raw data rendered first: an unsupported kind aborts before any write.
        $literal = if ($null -ne $before) { ConvertTo-PSLiteral -Value $before.Value -Kind $before.Kind } else { $null }
    } catch {
        Add-Result -Item $Item -Target $target -Outcome Failed -Detail "state capture - $($_.Exception.Message)"
        return
    }
    if (-not (Test-MutationGate -Item $Item -Target $target -Phase $Phase -Current $current -Desired $desired -Cmdlet $PSCmdlet)) { return }

    try {
        if (-not (Test-RegKey -Path $path)) {
            $missing = New-Object System.Collections.Generic.List[string]
            $probe   = $path
            while ($probe -match '^(HKLM|HKCU):\\.+' -and -not (Test-RegKey -Path $probe)) {
                $missing.Add($probe)
                $probe = $probe.Substring(0, $probe.LastIndexOf('\'))
            }
            (Open-RegKey -Path $path -Create).Close()
            $script:CreatedKeys.AddRange($missing)
        }
        $prune = @($script:CreatedKeys |
            Where-Object { $path -eq $_ -or $path.StartsWith("$_\", [System.StringComparison]::OrdinalIgnoreCase) } |
            Sort-Object -Property Length -Descending)

        $pathQ = ConvertTo-PSQuoted $path
        $nameQ = ConvertTo-PSQuoted $name
        if ($null -ne $before) {
            $action = "Restore-RbValue -Path $pathQ -Name $nameQ -Value $literal -Kind '$($before.Kind)'"
            $label  = "Restore $target ($($before.Kind))"
        } else {
            $action = "Remove-RbValue -Path $pathQ -Name $nameQ"
            $label  = "Remove $target"
        }
        if ($prune.Count -gt 0) {
            $action += '; Remove-RbEmptyKey -Path @(' + (($prune | ForEach-Object { ConvertTo-PSQuoted $_ }) -join ', ') + ')'
        }
        Add-RollbackStep -Label $label -Action $action -Comment "[$($Item.Id)] $($Item.Description)"

        Set-RegData -Path $path -Name $name -Value $Item.Value -Kind $Item.Type
        if (-not (Test-RegistryValueEqual -State (Get-RegistryValueState -Path $path -Name $name) -Value $Item.Value -Type $Item.Type)) {
            throw 'read-back verification failed: stored value differs from the value written'
        }
        Add-Result -Item $Item -Target $target -Outcome Applied -Current $current -Desired $desired
    } catch {
        Add-Result -Item $Item -Target $target -Outcome Failed -Current $current -Desired $desired -Detail $_.Exception.Message
    }
}

function Invoke-TaskItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$Item, [Parameter(Mandatory = $true)][ValidateSet('Evaluate', 'Apply')][string]$Phase)
    # [FIX-10] Canonical "\Folder\Sub\"; the root folder stays "\".
    $inner    = $Item.TaskPath.Trim('\')
    $taskPath = if ($inner) { "\$inner\" } else { '\' }
    $target   = "Task $taskPath$($Item.TaskName)"
    try { $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $Item.TaskName -ErrorAction SilentlyContinue } catch { $task = $null }
    if ($null -eq $task) { Add-Result -Item $Item -Target $target -Outcome NA -Detail 'task not present on this build'; return }
    $current = "$($task.State)"
    if ($current -eq 'Disabled') { Add-Result -Item $Item -Target $target -Outcome Compliant -Current $current -Desired 'Disabled'; return }
    if (-not (Test-MutationGate -Item $Item -Target $target -Phase $Phase -Current $current -Desired 'Disabled' -Cmdlet $PSCmdlet)) { return }

    try {
        $action = 'Enable-ScheduledTask -TaskPath {0} -TaskName {1} | Out-Null' -f (ConvertTo-PSQuoted $taskPath), (ConvertTo-PSQuoted $Item.TaskName)
        Add-RollbackStep -Label "Re-enable $target" -Action $action -Comment "[$($Item.Id)] $($Item.Description)"
        Disable-ScheduledTask -TaskPath $taskPath -TaskName $Item.TaskName -ErrorAction Stop | Out-Null
        $verify = Get-ScheduledTask -TaskPath $taskPath -TaskName $Item.TaskName -ErrorAction SilentlyContinue
        if ($null -eq $verify -or "$($verify.State)" -ne 'Disabled') { throw "task still reports State=$(if ($verify) { $verify.State } else { 'unknown' })" }
        Add-Result -Item $Item -Target $target -Outcome Applied -Current $current -Desired 'Disabled'
    } catch {
        # Some Application Experience tasks are TrustedInstaller-protected on recent builds: soft failure.
        Add-Result -Item $Item -Target $target -Outcome Failed -Current $current -Desired 'Disabled' -Detail $_.Exception.Message
    }
}

function Invoke-ServiceItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$Item, [Parameter(Mandatory = $true)][ValidateSet('Evaluate', 'Apply')][string]$Phase)
    $svcName = $Item.Name
    $target  = "Service $svcName"
    $svc     = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Add-Result -Item $Item -Target $target -Outcome NA -Detail 'service not installed'; return }

    $mode = Get-ServiceStartMode -Name $svcName
    $desired = $Item.StartMode + $(if ($Item.Stop) { '/Stopped' } else { '' })
    if ($null -eq $mode) {
        Add-Result -Item $Item -Target $target -Outcome Failed -Desired $desired -Detail 'startup mode undeterminable; refusing to change it without an exact rollback'
        return
    }
    $current   = "$mode/$($svc.Status)"
    $needsStop = $Item.Stop -and "$($svc.Status)" -ne 'Stopped'
    if ($mode -eq $Item.StartMode -and -not $needsStop) { Add-Result -Item $Item -Target $target -Outcome Compliant -Current $current -Desired $desired; return }
    if (-not (Test-MutationGate -Item $Item -Target $target -Phase $Phase -Current $current -Desired $desired -Cmdlet $PSCmdlet)) { return }

    try {
        if ($mode -ne $Item.StartMode) {
            $restart = if ($mode -like '*auto') { '; Start-Service -Name {0}' -f $svcName } else { '' }
            $action  = '$null = & sc.exe config {0} start= {1}; if ($LASTEXITCODE) {{ throw "sc.exe exit code $LASTEXITCODE" }}{2}' -f $svcName, $mode, $restart
            Add-RollbackStep -Label "Restore $target start=$mode" -Action $action -Comment "[$($Item.Id)] $($Item.Description)"
            # Mode change first, then stop: no window in which a trigger can restart the service.
            $null = & sc.exe config $svcName start= $Item.StartMode
            if ($LASTEXITCODE) { throw "sc.exe config exit code $LASTEXITCODE" }
        }
        if ($Item.Stop) { Stop-Service -Name $svcName -Force -Confirm:$false }

        $nowMode   = Get-ServiceStartMode -Name $svcName
        $nowStatus = "$((Get-Service -Name $svcName).Status)"
        if ($nowMode -ne $Item.StartMode -or ($Item.Stop -and $nowStatus -ne 'Stopped')) { throw "post-check mode=$nowMode status=$nowStatus" }
        Add-Result -Item $Item -Target $target -Outcome Applied -Current $current -Desired $desired
    } catch {
        Add-Result -Item $Item -Target $target -Outcome Failed -Current $current -Desired $desired -Detail $_.Exception.Message
    }
}

function Invoke-FeatureItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$Item, [Parameter(Mandatory = $true)][ValidateSet('Evaluate', 'Apply')][string]$Phase)
    $feature = $Item.FeatureName
    $target  = "Feature $feature"
    try {
        $f = Get-CimInstance -ClassName Win32_OptionalFeature -Filter "Name='$feature'" -ErrorAction Stop
    } catch {
        Add-Result -Item $Item -Target $target -Outcome Failed -Detail "CIM query failed - $($_.Exception.Message)"
        return
    }
    if ($null -eq $f) { Add-Result -Item $Item -Target $target -Outcome NA -Detail 'feature not offered on this SKU/build'; return }
    $current = switch ([int]$f.InstallState) { 1 { 'Enabled' } 2 { 'Disabled' } 3 { 'Absent' } default { 'Unknown' } }
    if ($current -eq 'Enabled') { Add-Result -Item $Item -Target $target -Outcome Compliant -Current $current -Desired 'Enabled'; return }
    if (-not (Test-MutationGate -Item $Item -Target $target -Phase $Phase -Current $current -Desired 'Enabled' -Cmdlet $PSCmdlet)) { return }

    try {
        $action = '$null = & dism.exe /online /disable-feature /featurename:{0} /quiet /norestart; if ($LASTEXITCODE -notin 0, 3010) {{ throw "dism.exe exit code $LASTEXITCODE" }}' -f $feature
        Add-RollbackStep -Label "Disable $target (reboot to complete)" -Action $action -Comment "[$($Item.Id)] $($Item.Description)"
        # /norestart is mandatory with /quiet: otherwise DISM reboots on its own when required.
        $null = & dism.exe /online /enable-feature "/featurename:$feature" /all /quiet /norestart
        $code = $LASTEXITCODE
        if ($code -notin 0, 3010) { throw "dism.exe exit code $code" }
        Add-Result -Item $Item -Target $target -Outcome Applied -Current $current -Desired 'Enabled' -Detail 'reboot required to complete'
    } catch {
        Add-Result -Item $Item -Target $target -Outcome Failed -Current $current -Desired 'Enabled' -Detail $_.Exception.Message
    }
}

function Get-PhysicalEthernet {
    if ($null -eq $script:EthernetCache) {
        $script:EthernetCache = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { "$($_.PhysicalMediaType)" -eq '802.3' })
    }
    return , $script:EthernetCache
}

function Invoke-NetAdapterItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$Item, [Parameter(Mandatory = $true)][ValidateSet('Evaluate', 'Apply')][string]$Phase)
    $adapters = Get-PhysicalEthernet
    if ($adapters.Count -eq 0) { Add-Result -Item $Item -Target (Get-ItemTarget -Item $Item) -Outcome NA -Detail 'no physical Ethernet adapter'; return }
    $keyword = $Item.Keyword
    $desired = $Item.Value
    $exposed = 0
    foreach ($a in $adapters) {
        $target = "NIC '$($a.Name)' [$($a.InterfaceDescription)] $keyword"
        $prop = Get-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword $keyword -ErrorAction SilentlyContinue
        if ($null -eq $prop) { continue }
        $exposed++
        $current = [string](@($prop.RegistryValue)[0])
        $valid   = @($prop.ValidRegistryValues | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
        if ($valid.Count -gt 0 -and $valid -notcontains $desired) {
            Add-Result -Item $Item -Target $target -Outcome NA -Current $current -Detail "driver does not accept '$desired' (valid: $($valid -join ','))"
            continue
        }
        if ($current -eq $desired) { Add-Result -Item $Item -Target $target -Outcome Compliant -Current $current -Desired $desired; continue }
        if (-not (Test-MutationGate -Item $Item -Target $target -Phase $Phase -Current $current -Desired $desired -Cmdlet $PSCmdlet)) { continue }
        try {
            $action = 'Set-NetAdapterAdvancedProperty -InterfaceDescription {0} -RegistryKeyword {1} -RegistryValue {2} -NoRestart' -f `
                (ConvertTo-PSQuoted $a.InterfaceDescription), (ConvertTo-PSQuoted $keyword), (ConvertTo-PSQuoted $current)
            Add-RollbackStep -Label "Restore $target = $current" -Action $action -Comment "[$($Item.Id)] $($Item.Description)"
            Set-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword $keyword -RegistryValue $desired -NoRestart
            $now = [string](@((Get-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword $keyword).RegistryValue)[0])
            if ($now -ne $desired) { throw "read-back $now" }
            Add-Result -Item $Item -Target $target -Outcome Applied -Current $current -Desired $desired -Detail 'effective after adapter restart or reboot'
        } catch {
            Add-Result -Item $Item -Target $target -Outcome Failed -Current $current -Desired $desired -Detail $_.Exception.Message
        }
    }
    if ($exposed -eq 0) { Add-Result -Item $Item -Target (Get-ItemTarget -Item $Item) -Outcome NA -Detail "no Ethernet driver exposes '$keyword'" }
}

function Invoke-NetAdapterPowerItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$Item, [Parameter(Mandatory = $true)][ValidateSet('Evaluate', 'Apply')][string]$Phase)
    $adapters = Get-PhysicalEthernet
    if ($adapters.Count -eq 0) { Add-Result -Item $Item -Target (Get-ItemTarget -Item $Item) -Outcome NA -Detail 'no physical Ethernet adapter'; return }
    $desired = $Item.Value
    foreach ($a in $adapters) {
        $target = "NIC '$($a.Name)' [$($a.InterfaceDescription)] AllowComputerToTurnOffDevice"
        $pm = Get-NetAdapterPowerManagement -Name $a.Name -ErrorAction SilentlyContinue
        $current = if ($pm) { "$($pm.AllowComputerToTurnOffDevice)" } else { '' }
        if (-not $current -or $current -eq 'Unsupported') { Add-Result -Item $Item -Target $target -Outcome NA -Detail 'not supported by this adapter'; continue }
        if ($current -eq $desired) { Add-Result -Item $Item -Target $target -Outcome Compliant -Current $current -Desired $desired; continue }
        if (-not (Test-MutationGate -Item $Item -Target $target -Phase $Phase -Current $current -Desired $desired -Cmdlet $PSCmdlet)) { continue }
        try {
            $action = '$pm = Get-NetAdapterPowerManagement -InterfaceDescription {0}; $pm.AllowComputerToTurnOffDevice = {1}; $pm | Set-NetAdapterPowerManagement' -f `
                (ConvertTo-PSQuoted $a.InterfaceDescription), (ConvertTo-PSQuoted $current)
            Add-RollbackStep -Label "Restore $target = $current" -Action $action -Comment "[$($Item.Id)] $($Item.Description)"
            $pm.AllowComputerToTurnOffDevice = $desired
            $pm | Set-NetAdapterPowerManagement
            $now = "$((Get-NetAdapterPowerManagement -Name $a.Name).AllowComputerToTurnOffDevice)"
            if ($now -ne $desired) { throw "read-back $now" }
            Add-Result -Item $Item -Target $target -Outcome Applied -Current $current -Desired $desired -Detail 'adapter was reset; link may have dropped briefly'
        } catch {
            Add-Result -Item $Item -Target $target -Outcome Failed -Current $current -Desired $desired -Detail $_.Exception.Message
        }
    }
}

# ------------------------------------------------------------------------------
# [FIX-34] DEFENDER FALSE-ALARM REMEDIATION
# All three handlers go through supported *-MpPreference cmdlets and emit an exact
# inverse rollback. None of them can disable a protection layer: the manifest
# validator rejects any such preference, and these handlers never call one.
# ------------------------------------------------------------------------------

# Defender class gate: cached Get-MpComputerStatus. Returns $null when Defender is the
# active AV (so items may run), otherwise the reason the whole class is N/A.
function Get-DefenderGateReason {
    if ($null -eq $script:DefenderStatus) {
        try { $script:DefenderStatus = Get-MpComputerStatus -ErrorAction Stop }
        catch { $script:DefenderStatus = $false }
    }
    if ($script:DefenderStatus -eq $false) { return 'Microsoft Defender cmdlets unavailable (Get-MpComputerStatus failed); is Defender present?' }
    if ($script:DefenderStatus.PSObject.Properties['AMRunningMode'] -and "$($script:DefenderStatus.AMRunningMode)" -notin 'Normal', 'SxS Passive Mode') {
        return "Defender is not the active AV (AMRunningMode=$($script:DefenderStatus.AMRunningMode)); another product owns exclusions"
    }
    return $null
}

function Get-MpPref { Get-MpPreference -ErrorAction Stop }

function Invoke-MpExclusionItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$Item, [Parameter(Mandatory = $true)][ValidateSet('Evaluate', 'Apply')][string]$Phase)
    $target = Get-ItemTarget -Item $Item
    $gate = Get-DefenderGateReason
    if ($gate) { Add-Result -Item $Item -Target $target -Outcome NA -Detail $gate; return }
    $prop = "Exclusion$($Item.ExclusionType)"   # ExclusionPath | ExclusionProcess | ExclusionExtension
    $want = $Item.Value
    try {
        $existing = @((Get-MpPref).$prop | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    } catch {
        Add-Result -Item $Item -Target $target -Outcome Failed -Detail "Get-MpPreference failed - $($_.Exception.Message)"; return
    }
    # Case-insensitive compare; Defender stores paths verbatim.
    if (@($existing | Where-Object { $_ -eq $want }).Count -gt 0) {
        Add-Result -Item $Item -Target $target -Outcome Compliant -Current 'present' -Desired 'present'
        return
    }
    if (-not (Test-MutationGate -Item $Item -Target $target -Phase $Phase -Current 'absent' -Desired 'present' -Cmdlet $PSCmdlet)) { return }
    try {
        # Rollback removes ONLY what we add, and only this exact value - never touches pre-existing ones.
        $action = 'Remove-MpPreference -{0} {1} -ErrorAction SilentlyContinue' -f $prop, (ConvertTo-PSQuoted $want)
        Add-RollbackStep -Label "Remove Defender $prop $want" -Action $action -Comment "[$($Item.Id)] $($Item.Description)"
        $addSplat = @{ $prop = $want; ErrorAction = 'Stop' }
        Add-MpPreference @addSplat
        $now = @((Get-MpPref).$prop | ForEach-Object { [string]$_ })
        if (@($now | Where-Object { $_ -eq $want }).Count -eq 0) { throw 'read-back: exclusion not present after Add-MpPreference' }
        Add-Result -Item $Item -Target $target -Outcome Applied -Current 'absent' -Desired 'present'
    } catch {
        Add-Result -Item $Item -Target $target -Outcome Failed -Current 'absent' -Desired 'present' -Detail $_.Exception.Message
    }
}

function Invoke-MpThreatAllowItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$Item, [Parameter(Mandatory = $true)][ValidateSet('Evaluate', 'Apply')][string]$Phase)
    $target = Get-ItemTarget -Item $Item
    $gate = Get-DefenderGateReason
    if ($gate) { Add-Result -Item $Item -Target $target -Outcome NA -Detail $gate; return }
    $id = $Item.ThreatId
    try {
        $pref     = Get-MpPref
        $ids      = @($pref.ThreatIDDefaultAction_Ids   | ForEach-Object { [string]$_ })
        $actions  = @($pref.ThreatIDDefaultAction_Actions | ForEach-Object { [string]$_ })
    } catch {
        Add-Result -Item $Item -Target $target -Outcome Failed -Detail "Get-MpPreference failed - $($_.Exception.Message)"; return
    }
    $idx = [array]::IndexOf($ids, $id)
    # Action 6 = Allow in the MSFT_MpThreat default-action enumeration.
    $currentAction = if ($idx -ge 0) { $actions[$idx] } else { '<none>' }
    if ($idx -ge 0 -and $currentAction -in 'Allow', '6') {
        Add-Result -Item $Item -Target $target -Outcome Compliant -Current 'Allow' -Desired 'Allow'
        return
    }
    if (-not (Test-MutationGate -Item $Item -Target $target -Phase $Phase -Current $currentAction -Desired 'Allow' -Cmdlet $PSCmdlet)) { return }
    try {
        if ($idx -ge 0) {
            # A prior rule for this ID exists with a different action: restore that exact action.
            $action = 'Set-MpPreference -ThreatIDDefaultAction_Ids {0} -ThreatIDDefaultAction_Actions {1}' -f (ConvertTo-PSQuoted $id), (ConvertTo-PSQuoted $currentAction)
            $label  = "Restore Defender ThreatID $id action to $currentAction"
        } else {
            # We are introducing this ID: rollback removes the per-ID rule entirely.
            $action = 'Remove-MpPreference -ThreatIDDefaultAction_Ids {0} -ErrorAction SilentlyContinue' -f (ConvertTo-PSQuoted $id)
            $label  = "Remove Defender ThreatID $id default-action rule"
        }
        Add-RollbackStep -Label $label -Action $action -Comment "[$($Item.Id)] $($Item.Description)"
        Set-MpPreference -ThreatIDDefaultAction_Ids $id -ThreatIDDefaultAction_Actions Allow -ErrorAction Stop
        $vp  = Get-MpPref
        $vIx = [array]::IndexOf(@($vp.ThreatIDDefaultAction_Ids | ForEach-Object { [string]$_ }), $id)
        $vAc = if ($vIx -ge 0) { [string]@($vp.ThreatIDDefaultAction_Actions)[$vIx] } else { '<none>' }
        if ($vAc -notin 'Allow', '6') { throw "read-back action=$vAc" }
        Add-Result -Item $Item -Target $target -Outcome Applied -Current $currentAction -Desired 'Allow'
    } catch {
        Add-Result -Item $Item -Target $target -Outcome Failed -Current $currentAction -Desired 'Allow' -Detail $_.Exception.Message
    }
}

function Invoke-MpPreferenceItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$Item, [Parameter(Mandatory = $true)][ValidateSet('Evaluate', 'Apply')][string]$Phase)
    $target = Get-ItemTarget -Item $Item
    $gate = Get-DefenderGateReason
    if ($gate) { Add-Result -Item $Item -Target $target -Outcome NA -Detail $gate; return }
    $name = $Item.Preference
    $want = $Item.Value
    try { $current = [string]((Get-MpPref).$name) } catch { Add-Result -Item $Item -Target $target -Outcome Failed -Detail "Get-MpPreference failed - $($_.Exception.Message)"; return }
    # Normalize enum spellings (cmdlet accepts names or the backing int).
    $norm = @{ '0' = 'Disabled'; '1' = 'Enabled'; '2' = 'AuditMode' }
    $curName = if ($norm.ContainsKey($current)) { $norm[$current] } else { $current }
    if ($curName -eq $want) { Add-Result -Item $Item -Target $target -Outcome Compliant -Current $curName -Desired $want; return }
    if (-not (Test-MutationGate -Item $Item -Target $target -Phase $Phase -Current $curName -Desired $want -Cmdlet $PSCmdlet)) { return }
    try {
        $action = 'Set-MpPreference -{0} {1}' -f $name, (ConvertTo-PSQuoted $curName)
        Add-RollbackStep -Label "Restore Defender $name = $curName" -Action $action -Comment "[$($Item.Id)] $($Item.Description)"
        $setSplat = @{ $name = $want; ErrorAction = 'Stop' }
        Set-MpPreference @setSplat
        $verify = [string]((Get-MpPref).$name)
        $vName  = if ($norm.ContainsKey($verify)) { $norm[$verify] } else { $verify }
        if ($vName -ne $want) { throw "read-back $vName" }
        Add-Result -Item $Item -Target $target -Outcome Applied -Current $curName -Desired $want
    } catch {
        Add-Result -Item $Item -Target $target -Outcome Failed -Current $curName -Desired $want -Detail $_.Exception.Message
    }
}

function Invoke-Manifest {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][hashtable[]]$Items, [ValidateSet('Evaluate', 'Apply')][string]$Phase = 'Apply')
    $groups = @($Items | ForEach-Object { $_.Group } | Select-Object -Unique)
    $currentGroup = $null
    foreach ($item in $Items) {
        if ($item.Group -ne $currentGroup) {
            $currentGroup = $item.Group
            if (-not $script:QuietResults) {
                Write-Host "`n[$([array]::IndexOf($groups, $currentGroup) + 1)/$($groups.Count)] $currentGroup" -ForegroundColor Yellow
            }
        }
        $gate = Get-ItemGateReason -Item $item
        if ($gate) { Add-Result -Item $item -Target (Get-ItemTarget -Item $item) -Outcome NA -Detail $gate; continue }
        switch ($item.Kind) {
            'Registry'        { Invoke-RegistryItem        -Item $item -Phase $Phase }
            'Task'            { Invoke-TaskItem            -Item $item -Phase $Phase }
            'Service'         { Invoke-ServiceItem         -Item $item -Phase $Phase }
            'Feature'         { Invoke-FeatureItem         -Item $item -Phase $Phase }
            'NetAdapter'      { Invoke-NetAdapterItem      -Item $item -Phase $Phase }
            'NetAdapterPower' { Invoke-NetAdapterPowerItem -Item $item -Phase $Phase }
            'MpExclusion'     { Invoke-MpExclusionItem     -Item $item -Phase $Phase }
            'MpThreatAllow'   { Invoke-MpThreatAllowItem   -Item $item -Phase $Phase }
            'MpPreference'    { Invoke-MpPreferenceItem    -Item $item -Phase $Phase }
        }
    }
}

# [FIX-7/11/23/31] Only when a shell-affecting change was actually applied.
function Invoke-ShellRefresh {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Host "`n[Shell] Explorer refresh" -ForegroundColor Yellow
    $pending = @($script:Results | Where-Object { $_.RestartShell -and $_.Outcome -in 'Applied', 'Planned' })
    if ($pending.Count -eq 0) { Write-Host '  [SKIPPED] No shell-affecting change was applied.' -ForegroundColor DarkGray; return }
    if ($IsDryRun) { Write-Host "  [PLANNED] Explorer restart for $($pending.Count) shell-affecting change(s)." -ForegroundColor Cyan; return }
    if (-not $PSCmdlet.ShouldProcess("Windows Explorer (session $SessionId)", 'Terminate and allow Winlogon respawn')) { return }
    try {
        $autoRestartShell = 1
        $state = Get-RegistryValueState -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoRestartShell'
        if ($null -ne $state) { try { $autoRestartShell = [int]$state.Value } catch { $autoRestartShell = 1 } }
        if ($autoRestartShell -ne 1) {
            Write-Warning "Winlogon AutoRestartShell = $autoRestartShell (auto-respawn disabled on this image); skipping the grace period."
        }
        switch (Restart-RbShell -WaitSeconds $(if ($autoRestartShell -eq 1) { 6 } else { 0 })) {
            'Respawned' { Write-Host '  [OK] Explorer respawned by Winlogon at normal integrity. Shell settings loaded.' -ForegroundColor Green }
            'Fallback'  {
                Write-Host '  [OK] Explorer restarted via fallback launch.' -ForegroundColor Green
                Write-Warning 'Explorer was started from an elevated session and may run at HIGH integrity; sign out and back in if drag-and-drop misbehaves.'
            }
            default {
                Write-Warning "Explorer did not revive. Ctrl+Shift+Esc -> Run new task -> 'explorer.exe'."
                $script:ExtraFailures++
            }
        }
    } catch {
        Write-Warning "Explorer restart routine failed: $($_.Exception.Message)"
        $script:ExtraFailures++
    }
}

function Get-RollbackChain {
    return @(Get-ChildItem -LiteralPath $BackupRootDir -Filter 'Rollback_*.ps1' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike '*.journal.ps1' -and -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) } |
        Sort-Object -Property Name -Descending)
}

# For a rollback script, find the Run_*.json that recorded it and return the SHA256 it was born with.
function Get-RecordedRollbackHash {
    param([Parameter(Mandatory = $true)][string]$RollbackPath)
    $leaf = Split-Path -Path $RollbackPath -Leaf
    foreach ($rec in Get-ChildItem -LiteralPath $BackupRootDir -Filter 'Run_*.json' -File -ErrorAction SilentlyContinue) {
        try {
            $json = Get-Content -LiteralPath $rec.FullName -Raw | ConvertFrom-Json
            if ($json.RollbackScript -and (Split-Path -Path $json.RollbackScript -Leaf) -eq $leaf) { return $json.RollbackSha256 }
        } catch {
            Write-Verbose "Run record unreadable: $($rec.Name)"
        }
    }
    return $null
}

# [FIX-35] -Mode Rollback: run the newest rollback (default) or the whole chain newest -> oldest (-All).
# Each script is re-parsed and, when a Run record exists, SHA256-verified before it is sourced; an edited
# or truncated rollback is refused. We are already elevated + 64-bit, so scripts run in-process.
function Invoke-RollbackMode {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $chain = @(Get-RollbackChain)
    if ($chain.Count -eq 0) {
        Write-Host "  [N/A] No Rollback_*.ps1 found in $BackupRootDir. Nothing to undo." -ForegroundColor DarkYellow
        Exit-Tuning 0
    }
    $targets = if ($All) { $chain } else { @($chain[0]) }
    Write-Host "  Backup store : $BackupRootDir" -ForegroundColor White
    Write-Host "  Chain        : $($chain.Count) rollback script(s) on disk." -ForegroundColor White
    if ($All) { Write-Host "  Scope        : ALL $($targets.Count), newest -> oldest (full revert to pristine)." -ForegroundColor White }
    else      { Write-Host "  Scope        : newest only ($($targets[0].Name)). Use -All for the whole chain." -ForegroundColor White }

    # Integrity gate first: refuse the whole operation if any target fails to parse or mismatches its record.
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($t in $targets) {
        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($t.FullName, [ref]$null, [ref]$parseErrors)
        $live     = (Get-FileHash -LiteralPath $t.FullName -Algorithm SHA256).Hash
        $recorded = Get-RecordedRollbackHash -RollbackPath $t.FullName
        $status = if (@($parseErrors).Count -gt 0) { 'PARSE-FAIL' }
                  elseif ($null -eq $recorded)     { 'NO-RECORD' }
                  elseif ($recorded -ne $live)     { 'HASH-MISMATCH' }
                  else                             { 'VERIFIED' }
        $plan.Add([pscustomobject]@{ Name = $t.Name; Path = $t.FullName; Status = $status })
        $col = switch ($status) { 'VERIFIED' { 'Green' } 'NO-RECORD' { 'DarkYellow' } default { 'Red' } }
        Write-Host "    [$status] $($t.Name)" -ForegroundColor $col
    }
    $blocked = @($plan | Where-Object { $_.Status -in 'PARSE-FAIL', 'HASH-MISMATCH' })
    if ($blocked.Count -gt 0 -and -not $Force) {
        Write-Host "  CRITICAL: $($blocked.Count) rollback script(s) failed integrity (parse error or SHA256 mismatch)." -ForegroundColor Red
        Write-Host '           They may have been edited or corrupted. Inspect them, or pass -Force to run anyway.' -ForegroundColor Red
        Exit-Tuning 1
    }
    if ($IsDryRun) {
        Write-Host "`n  [PLANNED] Would run $($targets.Count) rollback script(s). Preview each with its own -WhatIf." -ForegroundColor Cyan
        Exit-Tuning 0
    }
    if (-not $Force) {
        $answer = Read-Host "  Run $($targets.Count) rollback script(s) now? (Y/N)"
        if ($answer -notmatch '^[Yy]') { Write-Host '  Aborted.' -ForegroundColor Red; Exit-Tuning 1 }
    }

    $ran = 0; $failed = 0
    foreach ($p in $plan) {
        if (-not $PSCmdlet.ShouldProcess($p.Name, 'Execute rollback script')) { continue }
        Write-Host "`n  >> $($p.Name)" -ForegroundColor Yellow
        try {
            & $p.Path
            if ($LASTEXITCODE -eq 2) { $failed++; Write-Warning "$($p.Name): one or more steps failed (exit 2)." }
            else { $ran++ }
        } catch {
            $failed++
            Write-Warning "$($p.Name) threw: $($_.Exception.Message)"
        }
    }
    $color = if ($failed -gt 0) { 'DarkYellow' } else { 'Green' }
    Write-Host "`n==================================================================" -ForegroundColor $color
    Write-Host " ROLLBACK MODE DONE: $ran script(s) OK, $failed with failures." -ForegroundColor $color
    if (-not $All -and $chain.Count -gt 1) { Write-Host " $($chain.Count - 1) older rollback(s) remain. Use -All to revert the whole chain." -ForegroundColor White }
    Write-Host ' Reboot recommended (policy cache, optional features, NIC properties).' -ForegroundColor $color
    Write-Host '==================================================================' -ForegroundColor $color
    Exit-Tuning $(if ($failed -gt 0) { 2 } else { 0 })
}

# ------------------------------------------------------------------------------
# MODES: AUDIT TASK REGISTRATION
# ------------------------------------------------------------------------------

function Register-DriftAuditTask {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if (-not $PSCmdlet.ShouldProcess("$AuditTaskPath$AuditTaskName", 'Register elevated logon drift audit')) { return }
    Initialize-SecureBackupDir -Path $BackupRootDir
    # A fresh directory created after hardening inherits the protected DACL; New-Item fails if it already exists.
    $engineDir = Join-Path -Path $BackupRootDir -ChildPath "engine_$ScriptTimestamp"
    New-Item -Path $engineDir -ItemType Directory -WhatIf:$false -Confirm:$false | Out-Null
    $engineScript   = Join-Path -Path $engineDir -ChildPath (Split-Path -Path $PSCommandPath -Leaf)
    $engineManifest = Join-Path -Path $engineDir -ChildPath (Split-Path -Path $script:Manifest.Path -Leaf)
    Copy-Item -LiteralPath $PSCommandPath -Destination $engineScript -WhatIf:$false -Confirm:$false
    Copy-Item -LiteralPath $script:Manifest.Path -Destination $engineManifest -WhatIf:$false -Confirm:$false
    if ((Get-FileHash -LiteralPath $engineManifest -Algorithm SHA256).Hash -ne $script:Manifest.Hash) { throw 'Manifest snapshot hash mismatch.' }
    if ((Get-FileHash -LiteralPath $engineScript -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash) { throw 'Engine snapshot hash mismatch.' }

    $filterArgs = ''
    if ($Include.Count -gt 0) { $filterArgs += ' -Include ' + ($Include -join ',') }
    if ($Exclude.Count -gt 0) { $filterArgs += ' -Exclude ' + ($Exclude -join ',') }
    if ($ApplyIneffective)    { $filterArgs += ' -ApplyIneffective' }
    $exe      = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $taskArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$engineScript`" -Mode Audit -Notify -ManifestPath `"$engineManifest`"$filterArgs"

    $action    = New-ScheduledTaskAction -Execute $exe -Argument $taskArgs
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $script:Identity.Name
    $trigger.Delay = 'PT2M'
    $principal = New-ScheduledTaskPrincipal -UserId $script:Identity.Name -LogonType Interactive -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    Register-ScheduledTask -TaskPath $AuditTaskPath -TaskName $AuditTaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force `
        -Description "Win11Home tuning drift audit ($ScriptVersion). Engine snapshot: $engineDir" | Out-Null

    Write-Host "  [REGISTERED] $AuditTaskPath$AuditTaskName : at logon of $($script:Identity.Name) (+2 min), elevated." -ForegroundColor Green
    Write-Host "  [SNAPSHOT]   $engineDir (SHA256-verified engine + manifest)" -ForegroundColor Green
    Write-Host '  Re-run -Mode RegisterAuditTask after editing the manifest; the task never reads your working copy.' -ForegroundColor DarkGray
}

function Unregister-DriftAuditTask {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $task = Get-ScheduledTask -TaskPath $AuditTaskPath -TaskName $AuditTaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) { Write-Host "  [N/A] $AuditTaskPath$AuditTaskName is not registered." -ForegroundColor DarkGray; return }
    if (-not $PSCmdlet.ShouldProcess("$AuditTaskPath$AuditTaskName", 'Unregister drift audit task')) { return }
    Unregister-ScheduledTask -TaskPath $AuditTaskPath -TaskName $AuditTaskName -Confirm:$false
    try {
        $scheduler = New-Object -ComObject Schedule.Service
        $scheduler.Connect()
        $scheduler.GetFolder('\').DeleteFolder($AuditTaskPath.Trim('\'), 0)
    } catch {
        Write-Verbose "Task folder kept: $($_.Exception.Message)"
    }
    Write-Host "  [REMOVED] $AuditTaskPath$AuditTaskName. Engine snapshots remain in $BackupRootDir (admin-only)." -ForegroundColor Green
}

# ==============================================================================
# MAIN
# ==============================================================================
Write-Host '==================================================================' -ForegroundColor Cyan
Write-Host " Windows 11 Home Tuning & Direct GPO Automation Engine ($ScriptVersion)" -ForegroundColor Cyan
Write-Host " Mode: $Mode$(if ($IsDryRun) { ' (SIMULATION -WhatIf)' })" -ForegroundColor Cyan
Write-Host '==================================================================' -ForegroundColor Cyan

# --- Pre-flight 1: elevation + [FIX-24] host bitness ---
Write-Host "`n[Pre-Flight] Privileges & host" -ForegroundColor Yellow
$script:Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:MySid    = $script:Identity.User.Value
$principal       = New-Object Security.Principal.WindowsPrincipal -ArgumentList $script:Identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'CRITICAL: This script must be executed in an elevated (Administrator) PowerShell session.' -ForegroundColor Red
    Exit-Tuning 1
}
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Write-Host 'CRITICAL: 32-bit PowerShell host on 64-bit Windows (WOW64 redirection). Re-run from 64-bit PowerShell.' -ForegroundColor Red
    Exit-Tuning 1
}
Write-Host "  [VERIFIED] Elevated, 64-bit, PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))." -ForegroundColor Green

# --- Rollback mode: needs neither the manifest nor the HKCU target check; the rollback scripts are self-contained. ---
if ($Mode -eq 'Rollback') { Write-Host "`n[Rollback]" -ForegroundColor Yellow; Invoke-RollbackMode; Exit-Tuning 0 }

# --- Pre-flight 2: [FIX-27] manifest + [FIX-29] machine profile ---
Write-Host "`n[Pre-Flight] Manifest & machine profile" -ForegroundColor Yellow
try {
    $script:Manifest = Import-TuningManifest -Path $ManifestPath
} catch {
    Write-Host "CRITICAL: $($_.Exception.Message)" -ForegroundColor Red
    Exit-Tuning 1
}
foreach ($tag in @($Include + $Exclude)) {
    if ($tag -notmatch '^[A-Za-z0-9_-]+$') { Write-Host "CRITICAL: invalid tag '$tag'." -ForegroundColor Red; Exit-Tuning 1 }
}
$script:Machine = Get-MachineProfile
$selected       = @(Select-ManifestItem -Items $script:Manifest.Items)
Write-Host "  Manifest : $($script:Manifest.Path)" -ForegroundColor White
Write-Host "  SHA256   : $($script:Manifest.Hash)" -ForegroundColor White
Write-Host "  Items    : $($selected.Count) selected of $($script:Manifest.Items.Count)$(if ($Include.Count) { "  Include=$($Include -join ',')" })$(if ($Exclude.Count) { "  Exclude=$($Exclude -join ',')" })" -ForegroundColor White
Write-Host "  Machine  : $($script:Machine.EditionID) [$($script:Machine.Tier)] $($script:Machine.DisplayVersion) build $($script:Machine.Build).$($script:Machine.UBR)" -ForegroundColor White
if ($selected.Count -eq 0) { Write-Host '  Nothing selected. Check -Include/-Exclude tags.' -ForegroundColor DarkYellow; Exit-Tuning 0 }

# --- Task registration modes ---
if ($Mode -eq 'RegisterAuditTask')   { Write-Host "`n[Audit Task]" -ForegroundColor Yellow; Register-DriftAuditTask; Exit-Tuning 0 }
if ($Mode -eq 'UnregisterAuditTask') { Write-Host "`n[Audit Task]" -ForegroundColor Yellow; Unregister-DriftAuditTask; Exit-Tuning 0 }

# --- Pre-flight 3: [FIX-6/22] HKCU target ---
Write-Host "`n[Pre-Flight] User profile target" -ForegroundColor Yellow
Confirm-HkcuTarget -WarnOnly:($Mode -eq 'Audit')

# ==============================================================================
# [FIX-28] AUDIT MODE
# ==============================================================================
if ($Mode -eq 'Audit') {
    Invoke-Manifest -Items $selected -Phase Evaluate
    $drift     = @($script:Results | Where-Object { $_.Outcome -eq 'Drift' })
    $failed    = @($script:Results | Where-Object { $_.Outcome -eq 'Failed' })
    $compliant = @($script:Results | Where-Object { $_.Outcome -eq 'Compliant' }).Count
    $na        = @($script:Results | Where-Object { $_.Outcome -eq 'NA' }).Count

    $featureUpdate = $null
    $lastRun = Get-ChildItem -LiteralPath $BackupRootDir -Filter 'Run_*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object -Property Name -Descending | Select-Object -First 1
    if ($lastRun) {
        try {
            $last = Get-Content -LiteralPath $lastRun.FullName -Raw | ConvertFrom-Json
            if ([int]$last.Machine.Build -ne $script:Machine.Build) {
                $featureUpdate = "$($last.Machine.DisplayVersion) ($($last.Machine.Build)) -> $($script:Machine.DisplayVersion) ($($script:Machine.Build))"
            }
        } catch {
            Write-Verbose "Last run record unreadable: $($_.Exception.Message)"
        }
    }
    $chain = @(Get-RollbackChain)

    $reportWritten = $false
    try {
        Initialize-SecureBackupDir -Path $BackupRootDir
        Write-JsonFile -Path $AuditRecordPath -InputObject ([ordered]@{
            Engine = "Win11Home_fine_tune_$ScriptVersion"; Timestamp = (Get-Date).ToString('o')
            Host = $env:COMPUTERNAME; Account = $script:Identity.Name; Sid = $script:MySid; Machine = $script:Machine
            Manifest = [ordered]@{ Path = $script:Manifest.Path; Sha256 = $script:Manifest.Hash }
            Filters = [ordered]@{ Include = $Include; Exclude = $Exclude; ApplyIneffective = [bool]$ApplyIneffective }
            FeatureUpdateSinceLastApply = $featureUpdate
            Summary = [ordered]@{ Compliant = $compliant; Drift = $drift.Count; NotApplicable = $na; Failed = $failed.Count }
            RollbackChain = @($chain | ForEach-Object { $_.FullName })
            Results = $script:Results
        })
        $reportWritten = $true
        Get-ChildItem -LiteralPath $BackupRootDir -Filter 'Audit_*.json' -File |
            Where-Object { -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) } |
            Sort-Object -Property Name -Descending | Select-Object -Skip $AuditKeep |
            Remove-Item -Force -WhatIf:$false -Confirm:$false
    } catch {
        Write-Warning "Audit report not written: $($_.Exception.Message)"
    }

    $color = if ($drift.Count -or $failed.Count) { 'DarkYellow' } else { 'Green' }
    Write-Host "`n==================================================================" -ForegroundColor $color
    Write-Host " AUDIT: $compliant compliant, $($drift.Count) drift, $na N/A, $($failed.Count) unreadable." -ForegroundColor $color
    if ($featureUpdate) { Write-Host " Feature update since last apply: $featureUpdate" -ForegroundColor Yellow }
    if ($drift.Count)   { Write-Host " Drifted: $(@($drift | ForEach-Object { $_.Id } | Select-Object -Unique) -join ', ')" -ForegroundColor Yellow }
    if ($reportWritten) { Write-Host " Report : $AuditRecordPath" -ForegroundColor White }
    Write-Host " Rollback chain: $($chain.Count) script(s)$(if ($chain.Count) { "; newest $($chain[0].FullName) (run newest -> oldest)" })" -ForegroundColor White
    Write-Host '==================================================================' -ForegroundColor $color

    if ($Notify -and ($drift.Count -gt 0 -or $featureUpdate)) {
        $lines = @("Drift: $($drift.Count) item(s).")
        if ($featureUpdate) { $lines += "Feature update since last apply: $featureUpdate" }
        if ($drift.Count)   { $lines += "Items: $(@($drift | ForEach-Object { $_.Id } | Select-Object -Unique | Select-Object -First 12) -join ', ')" }
        $lines += "Re-apply from an elevated prompt: $PSCommandPath"
        try {
            [void](New-Object -ComObject WScript.Shell).Popup(($lines -join "`n`n"), 600, 'Win11 Tuning - Drift Audit', 0x30)
        } catch {
            Write-Verbose "Notification failed: $($_.Exception.Message)"
        }
    }
    Exit-Tuning $(if ($drift.Count -gt 0) { 3 } elseif ($failed.Count -gt 0) { 2 } else { 0 })
}

# ==============================================================================
# APPLY MODE
# ==============================================================================

# [FIX-31] Evaluate first: zero drift means no restore point, journal, rollback or shell restart.
if (-not $IsDryRun) {
    $script:QuietResults = $true
    Invoke-Manifest -Items $selected -Phase Evaluate
    $script:QuietResults = $false
    $pendingCount = @($script:Results | Where-Object { $_.Outcome -eq 'Drift' }).Count
    $failedPre    = @($script:Results | Where-Object { $_.Outcome -eq 'Failed' })
    $compliantPre = @($script:Results | Where-Object { $_.Outcome -eq 'Compliant' }).Count
    $naPre        = @($script:Results | Where-Object { $_.Outcome -eq 'NA' }).Count
    $script:Results.Clear()
    Write-Host "`n[Pre-Flight] Evaluation: $pendingCount to change, $compliantPre compliant, $naPre N/A, $($failedPre.Count) unreadable." -ForegroundColor Yellow
    if ($pendingCount -eq 0) {
        if ($failedPre.Count -gt 0) {
            Write-Host "  [WARNING] Nothing to apply, but these could not be evaluated: $(@($failedPre | ForEach-Object { $_.Id }) -join ', ')" -ForegroundColor DarkYellow
            Write-Host '            Run -Mode Audit for details.' -ForegroundColor DarkYellow
            Exit-Tuning 2
        }
        Write-Host '  [OK] System already matches the manifest. Nothing to do.' -ForegroundColor Green
        Exit-Tuning 0
    }

    # --- Pre-flight 4: [FIX-21] storage, [FIX-25] transcript, [FIX-9] journal ---
    Write-Host "`n[Pre-Flight] Secure rollback storage" -ForegroundColor Yellow
    try {
        Initialize-SecureBackupDir -Path $BackupRootDir
        Write-Host "  [SECURED] $BackupRootDir : owner Administrators; SYSTEM/Admins Full, Users Read." -ForegroundColor Green
    } catch {
        Write-Host "CRITICAL: Rollback storage could not be secured: $($_.Exception.Message)" -ForegroundColor Red
        Exit-Tuning 1
    }
    try {
        Start-Transcript -LiteralPath $TranscriptLog -Force -Confirm:$false | Out-Null
        $script:TranscriptOn = $true
        Write-Host "  [AUDIT] Transcript: $TranscriptLog  (manifest SHA256 $($script:Manifest.Hash))" -ForegroundColor Green
    } catch {
        Write-Warning "Transcript unavailable: $($_.Exception.Message)"
    }

    $journalHeader = @'
<#
.SYNOPSIS
    CRASH-SAFE ROLLBACK JOURNAL (chronological order) - Win11Home_fine_tune_{VER}.ps1, run {TS}.
.DESCRIPTION
    Appended step by step while the tuning script runs. If that run completed, use
    Rollback_{TS}.ps1 instead (same steps, LIFO order). Use this journal ONLY if the run
    aborted before finalization. Steps are idempotent and key pruning converges in either
    order. Supports -WhatIf. Sign out and back in afterwards to reload the shell.
.NOTES
    Run elevated: powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<this file>" [-WhatIf]
#>
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param()
'@
    $journalHeader = $journalHeader.Replace('{VER}', $ScriptVersion).Replace('{TS}', $ScriptTimestamp)
    $journalBanner = "Write-Host 'Executing CHRONOLOGICAL rollback journal (fallback mode)...' -ForegroundColor Yellow"
    Write-Utf8BomFile -Path $JournalScript -Content ($journalHeader + "`r`n" + (Get-RollbackPrelude) + "`r`n" + $journalBanner + "`r`n")
    Write-Host "  [STORAGE] Rollback journal armed: $JournalScript" -ForegroundColor Green

    # --- Pre-flight 5: [FIX-4/15] restore point ---
    Write-Host "`n[Pre-Flight] System restore point" -ForegroundColor Yellow
    $rpDescription = "PreTuning_$ScriptTimestamp"
    if ($SkipRestorePoint) {
        Write-Host '  [SKIPPED] -SkipRestorePoint specified by user.' -ForegroundColor DarkGray
    } else {
        $restorePoint = $null
        $rpError      = $null
        try { $restorePoint = New-VerifiedRestorePoint -Description $rpDescription } catch { $rpError = $_.Exception.Message }
        if ($restorePoint) {
            Write-Host "  [SNAPSHOT] Restore point VERIFIED: '$rpDescription' (Seq: $($restorePoint.SequenceNumber))" -ForegroundColor Green
            $script:RestorePointNote = "'$rpDescription' (Seq $($restorePoint.SequenceNumber))"
        } else {
            Write-Host '  [WARNING] NO verified restore point exists for this run.' -ForegroundColor Red
            if ($rpError) { Write-Host "            Error: $rpError" -ForegroundColor Red }
            Write-Host "            Typical causes: System Protection off for $env:SystemDrive, VSS disabled, no shadow storage." -ForegroundColor Red
            Write-Host '            The generated rollback script is your primary recovery mechanism.' -ForegroundColor Red
            if (-not $Force) {
                $rpAnswer = Read-Host '  Continue without a verified restore point? (Y/N)'
                if ($rpAnswer -notmatch '^[Yy]') { Write-Host '  Aborted.' -ForegroundColor Red; Exit-Tuning 1 }
            }
        }
    }
}

# --- Apply (or plan, under -WhatIf) ---
Invoke-Manifest -Items $selected -Phase Apply
Invoke-ShellRefresh

$applied   = @($script:Results | Where-Object { $_.Outcome -eq 'Applied' })
$planned   = @($script:Results | Where-Object { $_.Outcome -eq 'Planned' })
$compliant = @($script:Results | Where-Object { $_.Outcome -eq 'Compliant' }).Count
$na        = @($script:Results | Where-Object { $_.Outcome -eq 'NA' }).Count
$failures  = @($script:Results | Where-Object { $_.Outcome -eq 'Failed' }).Count + $script:ExtraFailures
$reboot    = @($applied | Where-Object { $_.Reboot } | ForEach-Object { $_.Id } | Select-Object -Unique)

# ==============================================================================
# FINALIZATION - [FIX-9] LIFO ROLLBACK, [FIX-32] HASHES, RUN RECORD
# ==============================================================================
$rollbackHash = $null
if (-not $IsDryRun) {
    if ($script:RollbackSteps.Count -eq 0) {
        Write-Host "`n  [ROLLBACK] No changes were applied - no rollback script needed." -ForegroundColor DarkGray
        Remove-Item -LiteralPath $JournalScript -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false
        $RollbackScript = $null
    } else {
        try {
            $rollbackHeader = @'
<#
.SYNOPSIS
    Automated rollback generated by Win11Home_fine_tune_{VER}.ps1 (run {TS}).
.DESCRIPTION
    Restores registry values (exact original kind and raw data), scheduled tasks, services,
    optional features and NIC properties to the baseline captured at {TS}. Steps run in LIFO
    order. Keys created by the tuning run are pruned only while empty, so data written later
    by other software is never deleted. Preview with -WhatIf.
.NOTES
    Generated     : {GEN}
    Host          : {HOST}
    Account       : {ACCT} ({SID})
    Machine       : {MACHINE}
    Manifest      : {MANIFEST} (SHA256 {MHASH})
    Steps         : {COUNT}
    Restore point : {RP}
    Transcript    : {LOG}
    HKCU entries restore into the hive of whichever account runs THIS script - use the same account.
    Chain         : earlier runs have their own rollback; run them newest -> oldest.
    Run elevated  : powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<this file>" [-WhatIf]
    Exit codes    : 0 = all steps OK | 2 = one or more steps failed
#>
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param()
'@
            $rollbackBanner = @'
Write-Host '==================================================================' -ForegroundColor Yellow
Write-Host ' Rolling back to pre-tuning baseline {TS} ({COUNT} step(s), LIFO order)' -ForegroundColor Yellow
Write-Host '==================================================================' -ForegroundColor Yellow
'@
            $rollbackFooter = @'

if ($WhatIfPreference) {
    Write-Host "`n Preview complete: $($script:RbSkipped) step(s) would run. Nothing was changed." -ForegroundColor Cyan
    exit 0
}
Write-Host "`nRefreshing Windows Explorer shell..." -ForegroundColor Yellow
try {
    switch (Restart-RbShell) {
        'Respawned' { Write-Host '  [OK] Explorer respawned by Winlogon.' -ForegroundColor Green }
        'Fallback'  { Write-Warning 'Explorer was started from this elevated session; sign out and back in if drag-and-drop misbehaves.' }
        default     { Write-Warning 'Explorer did not revive. Ctrl+Shift+Esc -> Run new task -> explorer.exe' }
    }
} catch {
    Write-Warning "Shell refresh failed: $($_.Exception.Message)"
}

$rbColor = if ($script:RbFail -gt 0) { 'DarkYellow' } else { 'Green' }
Write-Host "`n==================================================================" -ForegroundColor $rbColor
Write-Host " Rollback finished: $($script:RbOk) step(s) OK, $($script:RbFail) failed." -ForegroundColor $rbColor
Write-Host ' Reboot recommended (registry policy cache, optional features, NIC properties).' -ForegroundColor $rbColor
Write-Host '==================================================================' -ForegroundColor $rbColor
if ($script:RbFail -gt 0) { exit 2 }
'@
            $tokens = [ordered]@{
                '{VER}'      = $ScriptVersion
                '{TS}'       = $ScriptTimestamp
                '{GEN}'      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                '{HOST}'     = $env:COMPUTERNAME
                '{ACCT}'     = $script:Identity.Name
                '{SID}'      = $script:MySid
                '{MACHINE}'  = "$($script:Machine.EditionID) $($script:Machine.DisplayVersion) build $($script:Machine.Build).$($script:Machine.UBR)"
                '{MANIFEST}' = $script:Manifest.Path
                '{MHASH}'    = $script:Manifest.Hash
                '{COUNT}'    = $script:RollbackSteps.Count
                '{RP}'       = $script:RestorePointNote
                '{LOG}'      = $(if ($script:TranscriptOn) { $TranscriptLog } else { 'not recorded' })
            }
            foreach ($token in $tokens.Keys) {
                $rollbackHeader = $rollbackHeader.Replace($token, [string]$tokens[$token])
                $rollbackBanner = $rollbackBanner.Replace($token, [string]$tokens[$token])
            }

            $orderedSteps = @($script:RollbackSteps)
            [array]::Reverse($orderedSteps)
            Write-Utf8BomFile -Path $RollbackScript -Content (
                $rollbackHeader + "`r`n" + (Get-RollbackPrelude) + "`r`n" + $rollbackBanner + "`r`n" +
                ($orderedSteps -join "`r`n") + $rollbackFooter)

            $parseTokens = $null
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($RollbackScript, [ref]$parseTokens, [ref]$parseErrors)
            if (@($parseErrors).Count -gt 0) { throw "generated rollback failed to parse: $($parseErrors[0].Message)" }
            $rollbackHash = (Get-FileHash -LiteralPath $RollbackScript -Algorithm SHA256).Hash

            Write-Host "`n  [ROLLBACK] Written and parse-verified: $($script:RollbackSteps.Count) step(s), LIFO order." -ForegroundColor Green
            Write-Host "  [ROLLBACK] SHA256 $rollbackHash" -ForegroundColor Green
            if ($failures -eq 0) {
                Remove-Item -LiteralPath $JournalScript -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false
            } else {
                Write-Host "  [ROLLBACK] Chronological journal retained for inspection: $JournalScript" -ForegroundColor DarkYellow
            }
        } catch {
            Write-Warning "Failed to compose the final rollback script: $($_.Exception.Message)"
            Write-Warning "USE THE CHRONOLOGICAL JOURNAL INSTEAD: $JournalScript"
            $RollbackScript = $JournalScript
            $failures++
        }
    }

    try {
        Write-JsonFile -Path $RunRecordPath -InputObject ([ordered]@{
            Engine = "Win11Home_fine_tune_$ScriptVersion"; Timestamp = (Get-Date).ToString('o')
            Host = $env:COMPUTERNAME; Account = $script:Identity.Name; Sid = $script:MySid; Machine = $script:Machine
            Manifest = [ordered]@{ Path = $script:Manifest.Path; Sha256 = $script:Manifest.Hash }
            Filters = [ordered]@{ Include = $Include; Exclude = $Exclude; ApplyIneffective = [bool]$ApplyIneffective }
            RollbackScript = $RollbackScript; RollbackSha256 = $rollbackHash
            RestorePoint = $script:RestorePointNote; Transcript = $(if ($script:TranscriptOn) { $TranscriptLog })
            Summary = [ordered]@{ Applied = $applied.Count; Compliant = $compliant; NotApplicable = $na; Failed = $failures }
            RebootRequired = $reboot
            Results = $script:Results
        })
        Write-Host "  [RECORD] $RunRecordPath" -ForegroundColor Green
    } catch {
        Write-Warning "Run record not written: $($_.Exception.Message)"
    }
}

$summary = "$($applied.Count) applied, $compliant compliant, $na N/A, $failures issue(s)"
Write-Host ''
if ($IsDryRun) {
    Write-Host '==================================================================' -ForegroundColor Cyan
    Write-Host " DRY RUN COMPLETE: $($planned.Count) planned, $compliant compliant, $na N/A. Nothing was changed." -ForegroundColor Cyan
    Write-Host ' Re-run without -WhatIf to apply.' -ForegroundColor Cyan
    Write-Host '==================================================================' -ForegroundColor Cyan
    Exit-Tuning 0
}
$color = if ($failures -eq 0) { 'Green' } else { 'DarkYellow' }
Write-Host '==================================================================' -ForegroundColor $color
Write-Host " $(if ($failures -eq 0) { 'COMPLETED' } else { 'COMPLETED WITH WARNINGS' }): $summary." -ForegroundColor $color
if ($failures -gt 0) { Write-Host ' Review the warning output above before relying on these settings.' -ForegroundColor $color }
if ($RollbackScript) {
    Write-Host ' Rollback (preview with -WhatIf):' -ForegroundColor Cyan
    Write-Host " >> $RollbackScript" -ForegroundColor White
}
if ($reboot.Count -gt 0) { Write-Host " Reboot required for: $($reboot -join ', ')" -ForegroundColor Yellow }
if (@($applied | Where-Object { $_.Id -eq 'wsl.vmp' }).Count -gt 0) {
    Write-Host ' WSL2: after reboot, as your user run: wsl --install --no-distribution' -ForegroundColor Yellow
}
Write-Host '==================================================================' -ForegroundColor $color
Exit-Tuning $(if ($failures -eq 0) { 0 } else { 2 })
