<#
.SYNOPSIS
  Redmi K40 Pro (haydn) 黑屏救援：TWRP 注入 ADB -> 開機 -> scrcpy 控制
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\k40pro_recovery.ps1
  powershell -ExecutionPolicy Bypass -File .\k40pro_recovery.ps1 -TcpPort 5555
  powershell -ExecutionPolicy Bypass -File .\k40pro_recovery.ps1 -NoAuth
.NOTES
  -NoAuth   開機時 ro.adb.secure=0 (免授權)。金鑰被拒時的保底；插線即可存取，用完以選項 5 移除。
  -TcpPort  開機自動開 Wi-Fi ADB (例：5555)，可走 Tailscale 遠端 scrcpy。0 = 關閉。
  -TwrpImg  卡在 Fastboot 時，用此映像 fastboot boot 臨時進 TWRP。
  -Uhid     scrcpy 改用 UHID 鍵鼠 (模擬實體裝置)，MIUI 擋注入時的備援。
#>
[CmdletBinding()]
param(
    [switch]$NoAuth,
    [int]$TcpPort = 0,
    [string]$TwrpImg,
    [switch]$Uhid
)

[Console]::OutputEncoding = [Text.Encoding]::UTF8
$Script:Serial   = $null
$Script:Pin      = $null
$Script:PinAsked = $false

# ==============================================================================
# 裝置端腳本 (推送時自動轉 LF)
# ==============================================================================

# TWRP 端：注入 adb_keys + 安裝 root 開機腳本
$Sh_Inject = @'
K=/tmp/k40_adbkey.pub
D=/data/misc/adb
F=$D/adb_keys

[ -d /data/misc ] || { echo "ERR:NODATA"; exit 1; }
mkdir -p $D && touch $F
# 既有檔案補換行，避免兩把 key 黏成一行
[ -s $F ] && [ -n "$(tail -c1 $F)" ] && echo >> $F
FP=$(cut -d' ' -f1 $K)
if grep -qF "$FP" $F; then echo "KEY:EXISTS"; else cat $K >> $F; echo "KEY:ADDED"; fi
chown 1000:2000 $D $F
chmod 2750 $D
chmod 0640 $F
if chcon u:object_r:adb_keys_file:s0 $D $F 2>/dev/null; then echo "SELINUX:OK"; else echo "SELINUX:FAIL"; fi

ROOT=none
{ [ -d /data/adb/magisk ] || [ -f /data/adb/magisk.db ]; } && ROOT=magisk
[ -f /data/adb/ksud ] && ROOT=kernelsu
[ -f /data/adb/apd ]  && ROOT=apatch
echo "ROOT:$ROOT"
if [ "$ROOT" != none ]; then
  for s in post-fs-data service; do
    mkdir -p /data/adb/$s.d
    cp /tmp/k40_$s.sh /data/adb/$s.d/k40_rescue.sh
    chmod 0755 /data/adb/$s.d/k40_rescue.sh
  done
  echo "BOOT:OK"
fi
rm -f /tmp/k40_*
'@

# 開機早期 (post-fs-data)：USB 預設含 adb；-NoAuth 時關閉授權
$Sh_PostFs = @'
#!/system/bin/sh
# k40_rescue: post-fs-data
NOAUTH=__NOAUTH__
RP=
for c in resetprop /data/adb/ksu/bin/resetprop /data/adb/ap/bin/resetprop; do
  command -v "$c" >/dev/null 2>&1 && { RP=$c; break; }
done
[ -z "$RP" ] && [ -x /data/adb/magisk/magisk ] && RP="/data/adb/magisk/magisk resetprop"

if [ -n "$RP" ]; then $RP -p persist.sys.usb.config mtp,adb; else setprop persist.sys.usb.config mtp,adb; fi
# ro.adb.secure 僅在 BL 已解鎖 (verifiedbootstate=orange) 時被 adbd 採用
[ "$NOAUTH" = 1 ] && [ -n "$RP" ] && $RP ro.adb.secure 0
'@

# 開機完成 (service)：強制開 USB 調試 + MIUI 注入權限 + 可選 Wi-Fi ADB
$Sh_Service = @'
#!/system/bin/sh
# k40_rescue: late_start service
until [ "$(getprop sys.boot_completed)" = 1 ]; do sleep 2; done
settings put global development_settings_enabled 1
settings put global adb_enabled 1
# MIUI「USB 偵錯（安全設定）」：允許 adb 注入觸控/按鍵，scrcpy 控制必需
setprop persist.security.adbinput 1
setprop persist.security.adbinstall 1
PORT=__TCPPORT__
if [ "$PORT" -gt 0 ]; then
  setprop service.adb.tcp.port $PORT
  setprop ctl.restart adbd
fi
echo "$(date '+%F %T') adb_enabled=$(settings get global adb_enabled) adbinput=$(getprop persist.security.adbinput) tcp=$PORT" >> /data/local/tmp/k40_rescue.log
'@

# ==============================================================================
# 輸出 / ADB 包裝
# ==============================================================================
function Info($m) { Write-Host "[*] $m" -ForegroundColor Yellow }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor DarkYellow }
function Fail($m) { Write-Host "[x] $m" -ForegroundColor Red }

# 顯示輸出 (push / pull 進度)
function Adbs {
    if ($Script:Serial) { & adb -s $Script:Serial @args } else { & adb @args }
}
# 靜默取值 (stdout 字串，丟棄 stderr)
function AdbQ {
    $o = if ($Script:Serial) { & adb -s $Script:Serial @args 2>$null } else { & adb @args 2>$null }
    ($o | Out-String).Trim()
}

function Push-Text([string]$Content, [string]$Remote) {
    $tmp = [IO.Path]::GetTempFileName()
    [IO.File]::WriteAllText($tmp, ($Content -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
    AdbQ push $tmp $Remote | Out-Null
    Remove-Item $tmp -Force
}

# ==============================================================================
# 裝置狀態
# ==============================================================================
function Get-DeviceState {
    $list = @()
    foreach ($l in (& adb devices 2>$null)) {
        if ($l -match '^(\S+)\s+(device|recovery|unauthorized|sideload|offline|rescue)\s*$') {
            $list += [pscustomobject]@{ Serial = $Matches[1]; State = $Matches[2] }
        }
    }
    if ($Script:HasFastboot) {
        foreach ($l in (& fastboot devices 2>$null)) {
            if ($l -match '^(\S+)\s+fastboot') {
                $list += [pscustomobject]@{ Serial = $Matches[1]; State = 'fastboot' }
            }
        }
    }
    if ($list.Count -eq 0) { return $null }
    $hit = $list | Where-Object { $_.Serial -eq $Script:Serial } | Select-Object -First 1
    if ($hit) { return $hit } else { return $list[0] }
}

function Wait-State {
    param([string[]]$Want, [int]$Timeout = 300)
    $sw = [Diagnostics.Stopwatch]::StartNew(); $last = ''
    while ($sw.Elapsed.TotalSeconds -lt $Timeout) {
        $d   = Get-DeviceState
        $now = if ($d) { $d.State } else { 'none' }
        if ($now -ne $last) { Write-Host "    狀態: $now" -ForegroundColor DarkGray; $last = $now }
        if ($d -and ($Want -contains $d.State)) { $Script:Serial = $d.Serial; return $d.State }
        Start-Sleep -Seconds 1
    }
    return $null
}

function Enter-Recovery {
    Info '等待 TWRP... (黑屏：長按 電源 + 音量上 約 10-15 秒，震動後放開)'
    $want = @('recovery', 'device', 'unauthorized', 'fastboot', 'sideload')
    while ($true) {
        $st = Wait-State -Want $want -Timeout 600
        switch ($st) {
            'recovery' {
                Ok "已進入 TWRP ($Script:Serial)"
                Start-Sleep -Seconds 2   # 等 TWRP 完成自動掛載/解密
                return $true
            }
            'device' {
                Info '系統 ADB 已授權 -> adb reboot recovery'
                AdbQ reboot recovery | Out-Null
                $want = @('recovery', 'fastboot')
            }
            'unauthorized' {
                Warn '系統 ADB 未授權 (黑屏無法按允許) -> 請長按 電源 + 音量上 強制重啟進 TWRP'
                $want = @('recovery', 'fastboot', 'device')
            }
            'sideload' {
                AdbQ reboot recovery | Out-Null
                $want = @('recovery')
            }
            'fastboot' {
                if ($TwrpImg -and (Test-Path $TwrpImg)) {
                    Info "fastboot boot $TwrpImg"
                    & fastboot -s $Script:Serial boot $TwrpImg
                } else {
                    Info 'fastboot reboot recovery (無效則改用 -TwrpImg 或按鍵)'
                    & fastboot -s $Script:Serial reboot recovery
                }
                $want = @('recovery')
            }
            default { Fail '等待逾時 (TWRP 未被偵測：檢查 USB 驅動 / 換線 / 換 USB 2.0 口)'; return $false }
        }
    }
}

# ==============================================================================
# TWRP：解密 + 注入
# ==============================================================================
function Get-Pin {
    if (-not $Script:PinAsked) {
        $Script:PinAsked = $true
        $sec = Read-Host '鎖屏 PIN/密碼 (圖案鎖：3x3 左上=1 轉數字；無則 Enter)' -AsSecureString
        if ($sec.Length -gt 0) {
            $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            try     { $Script:Pin = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
        }
    }
    return $Script:Pin
}

function Test-DataReady { (AdbQ shell 'test -d /data/misc && echo OK') -eq 'OK' }
function Test-CeReady   { (AdbQ shell 'test -d /data/media/0/Android && echo OK') -eq 'OK' }

function Unlock-Data {
    AdbQ shell 'mount /data' | Out-Null
    if (-not (Test-CeReady)) {
        $pin = Get-Pin
        if ($pin) {
            Info 'twrp decrypt ...'
            $o = AdbQ shell "twrp decrypt '$pin'"
            if ($o) { Write-Host "    $o" -ForegroundColor DarkGray }
        }
    }
    if (Test-CeReady) { Ok 'CE 已解密 (內部儲存可讀)' }
    else { Warn 'CE 未解密：不影響金鑰注入，只影響備份' }

    if (Test-DataReady) { Ok '/data/misc 可寫'; return $true }
    Fail '/data 無法掛載 -> 此 TWRP 不支援目前 ROM 的加密，請換支援該 Android 版本的 TWRP/OrangeFox'
    return $false
}

function Get-AdbPubKey {
    $dir = Join-Path $env:USERPROFILE '.android'
    $pub = Join-Path $dir 'adbkey.pub'
    if (-not (Test-Path $pub)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Info '產生本機 ADB 金鑰對'
        & adb keygen (Join-Path $dir 'adbkey') 2>$null | Out-Null
        & adb kill-server 2>$null | Out-Null   # 讓 server 載入新金鑰
        & adb start-server 2>$null | Out-Null
    }
    if (Test-Path $pub) { return $pub }
    Fail "無法產生 $pub"; return $null
}

function Install-Rescue {
    $pub = Get-AdbPubKey
    if (-not $pub) { return $false }
    $noauth = if ($NoAuth) { '1' } else { '0' }

    Push-Text (((Get-Content $pub -Raw).Trim()) + "`n")         '/tmp/k40_adbkey.pub'
    Push-Text ($Sh_PostFs.Replace('__NOAUTH__', $noauth))         '/tmp/k40_post-fs-data.sh'
    Push-Text ($Sh_Service.Replace('__TCPPORT__', [string]$TcpPort)) '/tmp/k40_service.sh'
    Push-Text $Sh_Inject                                           '/tmp/k40_inject.sh'

    $r = AdbQ shell 'sh /tmp/k40_inject.sh'
    $r -split '\r?\n' | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

    if ($r -notmatch 'KEY:(ADDED|EXISTS)') { Fail '金鑰注入失敗'; return $false }
    Ok '本機公鑰已寫入 /data/misc/adb/adb_keys'
    if ($r -match 'SELINUX:FAIL') { Warn 'SELinux context 設定失敗；開機後若 unauthorized 請改用 -NoAuth' }
    if ($r -match 'ROOT:none') {
        Warn '未偵測到 Magisk/KernelSU/APatch：無法強制開 USB 調試與 MIUI 注入權限'
        Warn '只有黑屏前已開啟 USB 調試才可能成功'
    } else {
        Ok "開機腳本已安裝 ($([regex]::Match($r, 'ROOT:(\w+)').Groups[1].Value)) | NoAuth=$noauth | TcpPort=$TcpPort"
    }
    return $true
}

function Remove-Rescue {
    if (-not (Enter-Recovery)) { return }
    AdbQ shell 'mount /data' | Out-Null
    $r = AdbQ shell 'rm -f /data/adb/post-fs-data.d/k40_rescue.sh /data/adb/service.d/k40_rescue.sh && echo DONE'
    if ($r -match 'DONE') { Ok '已移除開機腳本 (adb_keys 保留；ro.adb.secure 重啟後恢復預設)' }
    else { Fail "移除失敗: $r" }
}

# ==============================================================================
# 系統：開機等待 / 解鎖 / 投屏
# ==============================================================================
function Wait-Boot {
    Info '等待 Android 開機 + ADB 上線 (首次約 1-2 分鐘)...'
    $st = Wait-State -Want 'device', 'unauthorized' -Timeout 240
    if ($st -eq 'unauthorized') { $st = Wait-State -Want 'device' -Timeout 20 }
    if ($st -ne 'device') {
        if ((Get-DeviceState).State -eq 'unauthorized') { Fail '金鑰被拒 (unauthorized) -> 用 -NoAuth 重跑選項 1' }
        else { Fail 'ADB 未上線 -> 確認 root 正常、上方 ROOT: 非 none' }
        return $false
    }
    Ok "系統 ADB 已連線 ($Script:Serial)"

    for ($i = 0; $i -lt 120; $i++) {
        if ((AdbQ shell getprop sys.boot_completed) -eq '1') { break }
        Start-Sleep -Seconds 1
    }
    for ($i = 0; $i -lt 40; $i++) {
        if ((AdbQ shell getprop persist.security.adbinput) -eq '1') { Ok 'MIUI 輸入注入已開啟'; return $true }
        Start-Sleep -Seconds 1
    }
    Warn 'persist.security.adbinput 未生效 -> scrcpy 可能只能看不能點，改加 -Uhid 或再重啟一次'
    return $true
}

function Unlock-Screen {
    $w = 1080; $h = 2400
    $m = [regex]::Matches((AdbQ shell wm size), '(\d+)x(\d+)')
    if ($m.Count -gt 0) { $w = [int]$m[$m.Count - 1].Groups[1].Value; $h = [int]$m[$m.Count - 1].Groups[2].Value }

    AdbQ shell input keyevent KEYCODE_WAKEUP | Out-Null
    Start-Sleep -Milliseconds 400
    AdbQ shell input swipe ([int]($w / 2)) ([int]($h * 0.85)) ([int]($w / 2)) ([int]($h * 0.3)) 250 | Out-Null

    $pin = Get-Pin
    if ($pin) {
        Start-Sleep -Milliseconds 700
        AdbQ shell input text $pin | Out-Null
        AdbQ shell input keyevent KEYCODE_ENTER | Out-Null
        Info '已自動輸入 PIN'
    }
}

function Show-WifiHint {
    if ($TcpPort -le 0) { return }
    $ips = (AdbQ shell 'ip -4 -o addr show') -split '\r?\n' | ForEach-Object {
        if ($_ -match '^\d+:\s+(\S+)\s+inet\s+([\d.]+)' -and $Matches[1] -ne 'lo') { "$($Matches[2])|$($Matches[1])" }
    }
    if (-not $ips) { Warn 'Wi-Fi ADB 已開，但尚未取得 IP (未連 Wi-Fi?)'; return }
    Ok "Wi-Fi ADB :$TcpPort 可用 (拔線後)："
    foreach ($e in $ips) {
        $ip, $nic = $e -split '\|'
        Write-Host ("    scrcpy --tcpip={0}:{1}   # {2}" -f $ip, $TcpPort, $nic) -ForegroundColor Cyan
    }
}

function Start-Scrcpy {
    if (-not $Script:HasScrcpy) { Fail '找不到 scrcpy (加入 PATH 後跑選項 3)'; return }
    $a = @('-s', $Script:Serial, '--turn-screen-off', '--stay-awake', '--window-title=K40Pro')
    if ($Uhid) { $a += @('--keyboard=uhid', '--mouse=uhid') }
    Info "scrcpy $($a -join ' ')"
    Start-Process scrcpy -ArgumentList $a
    Ok '投屏視窗已啟動 (鎖屏可直接用電腦鍵盤輸入 PIN)'
}

# ==============================================================================
# 流程
# ==============================================================================
function Invoke-Full {
    $d = Get-DeviceState
    if ($d -and $d.State -eq 'device') {
        $Script:Serial = $d.Serial
        if ((AdbQ shell getprop persist.security.adbinput) -eq '1') {
            Ok '系統 ADB 與 MIUI 注入權限皆已就緒 -> 直接投屏'
            Unlock-Screen; Start-Scrcpy; return
        }
        Info '系統 ADB 已授權但 MIUI 注入權限未開 -> 進 TWRP 安裝開機腳本'
    }
    if (-not (Enter-Recovery)) { return }
    if (-not (Unlock-Data))    { return }
    if (-not (Install-Rescue)) { return }

    Info '重啟進入 Android...'
    AdbQ reboot | Out-Null
    Start-Sleep -Seconds 5
    if (-not (Wait-Boot)) { return }
    Show-WifiHint
    Unlock-Screen
    Start-Scrcpy
}

function Backup-Storage {
    $st = Wait-State -Want 'recovery', 'device' -Timeout 60
    if (-not $st) { Fail '未偵測到 TWRP 或已授權的系統'; return }
    if ($st -eq 'recovery') {
        if (-not (Unlock-Data)) { return }
        if (-not (Test-CeReady)) { Fail 'CE 未解密，無法讀內部儲存'; return }
        $src = '/data/media/0/'
    } else {
        $src = '/sdcard/'
    }
    $dest = Read-Host '儲存目錄 (Enter = 腳本目錄\backup_k40pro_日期)'
    if ([string]::IsNullOrWhiteSpace($dest)) { $dest = Join-Path $Base "backup_k40pro_$(Get-Date -Format yyyyMMdd_HHmm)" }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Info "adb pull $src -> $dest (勿拔線)"
    Adbs pull -a $src $dest
    if ($LASTEXITCODE -eq 0) { Ok '備份完成' }
    else { Warn "pull 有錯誤 (exit $LASTEXITCODE)；常見原因：Windows 不允許的檔名字元" }
}

function Show-Menu {
    Write-Host ''
    Write-Host '========================================================' -ForegroundColor Cyan
    Write-Host '  Redmi K40 Pro (haydn) 黑屏救援 + scrcpy' -ForegroundColor Yellow
    Write-Host ("  NoAuth={0}  TcpPort={1}  Uhid={2}" -f [bool]$NoAuth, $TcpPort, [bool]$Uhid) -ForegroundColor DarkGray
    Write-Host '========================================================' -ForegroundColor Cyan
    Write-Host '1. 全自動：TWRP -> 解密 -> 注入 -> 開機 -> scrcpy' -ForegroundColor Cyan
    Write-Host '2. 僅 TWRP 注入 (不重啟)'
    Write-Host '3. 啟動 scrcpy (系統已連線)'
    Write-Host '4. 備份內部儲存 (TWRP / 系統皆可)'
    Write-Host '5. 移除開機腳本 (換螢幕後 / 關閉 NoAuth)'
    Write-Host '0. 離開' -ForegroundColor DarkGray
}

# ==============================================================================
# Main
# ==============================================================================
$Base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) { Fail '找不到 adb，請將 platform-tools 加入 PATH'; exit 1 }
$Script:HasScrcpy   = [bool](Get-Command scrcpy   -ErrorAction SilentlyContinue)
$Script:HasFastboot = [bool](Get-Command fastboot -ErrorAction SilentlyContinue)
if (-not $Script:HasScrcpy) { Warn '找不到 scrcpy，投屏步驟會略過' }

$logDir = Join-Path $Base 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
try { Start-Transcript -Path (Join-Path $logDir "k40_$(Get-Date -Format yyyyMMdd_HHmmss).log") | Out-Null } catch {}
& adb start-server 2>$null | Out-Null

try {
    while ($true) {
        Show-Menu
        switch (Read-Host "`n選項") {
            '1' { Invoke-Full }
            '2' { if (Enter-Recovery) { if (Unlock-Data) { [void](Install-Rescue) } } }
            '3' {
                if (Wait-State -Want 'device' -Timeout 30) { Unlock-Screen; Start-Scrcpy }
                else { Fail '系統 ADB 未連線 -> 先跑選項 1' }
            }
            '4' { Backup-Storage }
            '5' { Remove-Rescue }
            '0' { return }
            default { Warn '無效選項' }
        }
    }
} finally {
    try { Stop-Transcript | Out-Null } catch {}
}
