# ==============================================================================
# Win11Home tuning manifest - consumed by Win11Home_fine_tune_v5.ps1
# ------------------------------------------------------------------------------
# Data only (Import-PowerShellDataFile): no expressions, casts or variables.
# Items are processed in file order; Group controls the console section headers.
#
# Common keys : Id, Kind, Group, Tags, Description            (required)
#               Edition      Home | Pro | Enterprise  - lowest SKU tier that honors it (default Home)
#               MinBuild     int                      - minimum OS build (default 0)
#               RequiresPath string, %ENV% expanded   - item applies only if this path exists
#               Reboot       bool                     - change needs a reboot to take effect
#               RestartShell bool                     - change needs an Explorer restart
# Registry    : Path (HKLM:\ or HKCU:\), Name ('' = unnamed default value), Value, Type (default DWord)
#               Type: DWord | QWord | String | ExpandString | MultiString | Binary (Binary = @(0..255,...))
# Task        : TaskPath, TaskName                  -> desired state Disabled
# Service     : Name, StartMode (auto | delayed-auto | demand | disabled), Stop (bool)
# Feature     : FeatureName                         -> desired state Enabled (DISM, no auto-reboot)
# NetAdapter  : Keyword, Value (string)             -> advanced property on physical 802.3 adapters,
#               applied only where the driver exposes the keyword AND lists the value as valid
# NetAdapterPower : Property (AllowComputerToTurnOffDevice), Value (Disabled | Enabled)
# MpExclusion : ExclusionType (Path|Process|Extension), Value  -> add a Defender exclusion (false positives only; no drive roots)
# MpThreatAllow : ThreatId (from Get-MpThreat)              -> set that one detection's default action to Allow
# MpPreference : Preference (PUAProtection|SubmitSamplesConsent), Value  -> whitelisted, never disables protection
#
# Filter at run time:  -Include Privacy,DevUX   /   -Exclude TelemetryTask,Network
# ==============================================================================
@{
    SchemaVersion = 1

    Items = @(
        # ---------------------------------------------------------------- Developer
        @{
            Id = 'dev.longpaths'; Kind = 'Registry'; Group = 'Developer Privileges, Long Paths & sudo'; Tags = @('Dev')
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'; Name = 'LongPathsEnabled'; Value = 1
            Description = 'Enable Win32 long paths (>260 chars) for deep Git/Node/Docker trees'; Reboot = $true
        }
        @{
            Id = 'dev.devmode'; Kind = 'Registry'; Group = 'Developer Privileges, Long Paths & sudo'; Tags = @('Dev')
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'; Name = 'AllowDevelopmentWithoutDevLicense'; Value = 1
            Description = 'Developer Mode: unprivileged symlink creation (mklink) without UAC'
        }
        @{
            # Inline mode shares a console with the unprivileged parent (elevated-child hijack vector).
            Id = 'dev.sudo'; Kind = 'Registry'; Group = 'Developer Privileges, Long Paths & sudo'; Tags = @('Dev')
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo'; Name = 'Enabled'; Value = 1
            RequiresPath = '%SystemRoot%\System32\sudo.exe'
            Description = 'Native sudo = forceNewWindow (0 off | 1 new window | 2 input disabled | 3 inline)'
        }
        @{
            # Windows PowerShell 5.1 CurrentUser store; pwsh 7 already defaults to RemoteSigned on Windows.
            Id = 'dev.psexecpolicy'; Kind = 'Registry'; Group = 'Developer Privileges, Long Paths & sudo'; Tags = @('Dev', 'PowerShell')
            Path = 'HKCU:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'; Name = 'ExecutionPolicy'; Value = 'RemoteSigned'; Type = 'String'
            Description = 'Windows PowerShell CurrentUser ExecutionPolicy = RemoteSigned'
        }

        # ---------------------------------------------------------------- Windows Update
        @{
            Id = 'wu.noautoreboot'; Kind = 'Registry'; Group = 'Windows Update Control'; Tags = @('Update')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name = 'NoAutoRebootWithLoggedOnUsers'; Value = 1
            Description = 'No forced auto-reboot while a user is signed in'; Reboot = $true
        }
        @{
            Id = 'wu.noautoupdate'; Kind = 'Registry'; Group = 'Windows Update Control'; Tags = @('Update')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name = 'NoAutoUpdate'; Value = 0
            Description = 'Configure Automatic Updates = Enabled (gpedit footprint for AUOptions)'; Reboot = $true
        }
        @{
            Id = 'wu.auoptions'; Kind = 'Registry'; Group = 'Windows Update Control'; Tags = @('Update')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name = 'AUOptions'; Value = 2
            Description = 'Notify before download and install [best-effort on Home]'; Reboot = $true
        }
        @{
            Id = 'wu.nodrivers'; Kind = 'Registry'; Group = 'Windows Update Control'; Tags = @('Update')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name = 'ExcludeWUDriversInQualityUpdate'; Value = 1
            Description = 'Exclude hardware drivers from quality updates'; Reboot = $true
        }

        # ---------------------------------------------------------------- Search & Copilot
        @{
            Id = 'search.noweb'; Kind = 'Registry'; Group = 'Start Menu Search & Copilot'; Tags = @('Search', 'BestEffort')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'DisableWebSearch'; Value = 1
            Description = 'Disable web query integration in Windows Search [best-effort on Win11]'
        }
        @{
            Id = 'search.noconnectedweb'; Kind = 'Registry'; Group = 'Start Menu Search & Copilot'; Tags = @('Search', 'BestEffort')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'ConnectedSearchUseWeb'; Value = 0
            Description = 'No outbound web queries from Windows Search [best-effort on Win11]'
        }
        @{
            Id = 'search.nocortana'; Kind = 'Registry'; Group = 'Start Menu Search & Copilot'; Tags = @('Search', 'Legacy')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'AllowCortana'; Value = 0
            Description = 'Disable legacy Cortana subsystem [legacy - Cortana app retired]'
        }
        @{
            # Effective Win11 control (FIX-12). HKCU\...\CurrentVersion\Search is SearchHost-owned and rejects writes.
            Id = 'search.nosuggest.user'; Kind = 'Registry'; Group = 'Start Menu Search & Copilot'; Tags = @('Search')
            Path = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer'; Name = 'DisableSearchBoxSuggestions'; Value = 1
            Description = 'Disable web/Bing suggestions in the search box (current user)'; RestartShell = $true
        }
        @{
            Id = 'search.nosuggest.machine'; Kind = 'Registry'; Group = 'Start Menu Search & Copilot'; Tags = @('Search')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = 'DisableSearchBoxSuggestions'; Value = 1
            Description = 'Disable web/Bing suggestions in the search box (all users)'; RestartShell = $true
        }
        @{
            # Deprecated: governs the legacy sidebar only; does not remove or block the Copilot app.
            Id = 'copilot.sidebar.machine'; Kind = 'Registry'; Group = 'Start Menu Search & Copilot'; Tags = @('Copilot', 'Legacy')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; Name = 'TurnOffWindowsCopilot'; Value = 1
            Description = 'Disable legacy Windows Copilot sidebar (machine) [deprecated policy]'
        }
        @{
            Id = 'copilot.sidebar.user'; Kind = 'Registry'; Group = 'Start Menu Search & Copilot'; Tags = @('Copilot', 'Legacy')
            Path = 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot'; Name = 'TurnOffWindowsCopilot'; Value = 1
            Description = 'Disable legacy Windows Copilot sidebar (user) [deprecated policy]'
        }

        # ---------------------------------------------------------------- Consumer content
        @{
            Id = 'cloud.consumerfeatures'; Kind = 'Registry'; Group = 'Consumer Content & Suggestions'; Tags = @('Bloat'); Edition = 'Enterprise'
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableWindowsConsumerFeatures'; Value = 1
            Description = 'Turn off Microsoft consumer experiences'
        }
        @{
            Id = 'cloud.softlanding'; Kind = 'Registry'; Group = 'Consumer Content & Suggestions'; Tags = @('Bloat'); Edition = 'Enterprise'
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableSoftLanding'; Value = 1
            Description = 'Do not show Windows tips'
        }
        @{
            Id = 'cdm.silentinstall'; Kind = 'Registry'; Group = 'Consumer Content & Suggestions'; Tags = @('Bloat')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SilentInstalledAppsEnabled'; Value = 0
            Description = 'Block silent sponsored app installs [Home equivalent of DisableWindowsConsumerFeatures]'
        }
        @{
            Id = 'cdm.tips'; Kind = 'Registry'; Group = 'Consumer Content & Suggestions'; Tags = @('Bloat')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-338389Enabled'; Value = 0
            Description = 'No tips and suggestions while using Windows [Home equivalent of DisableSoftLanding]'
        }
        @{
            Id = 'cdm.lockscreen'; Kind = 'Registry'; Group = 'Consumer Content & Suggestions'; Tags = @('Bloat')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-338387Enabled'; Value = 0
            Description = 'No lock screen fun facts, tips and tricks'
        }
        @{
            Id = 'cdm.welcome'; Kind = 'Registry'; Group = 'Consumer Content & Suggestions'; Tags = @('Bloat')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-310093Enabled'; Value = 0
            Description = 'No Windows welcome experience after updates'
        }
        @{
            Id = 'cdm.settings.1'; Kind = 'Registry'; Group = 'Consumer Content & Suggestions'; Tags = @('Bloat')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-338393Enabled'; Value = 0
            Description = 'No suggested content in Settings (1/3)'
        }
        @{
            Id = 'cdm.settings.2'; Kind = 'Registry'; Group = 'Consumer Content & Suggestions'; Tags = @('Bloat')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-353694Enabled'; Value = 0
            Description = 'No suggested content in Settings (2/3)'
        }
        @{
            Id = 'cdm.settings.3'; Kind = 'Registry'; Group = 'Consumer Content & Suggestions'; Tags = @('Bloat')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-353696Enabled'; Value = 0
            Description = 'No suggested content in Settings (3/3)'
        }
        @{
            Id = 'explorer.syncprovider'; Kind = 'Registry'; Group = 'Consumer Content & Suggestions'; Tags = @('Bloat')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'ShowSyncProviderNotifications'; Value = 0
            Description = 'No promotional sync-provider banners in File Explorer'; RestartShell = $true
        }

        # ---------------------------------------------------------------- Privacy
        @{
            Id = 'privacy.adid.user'; Kind = 'Registry'; Group = 'Privacy'; Tags = @('Privacy')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Name = 'Enabled'; Value = 0
            Description = 'Advertising ID off (current user)'
        }
        @{
            Id = 'privacy.adid.policy'; Kind = 'Registry'; Group = 'Privacy'; Tags = @('Privacy')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'; Name = 'DisabledByGroupPolicy'; Value = 1
            Description = 'Advertising ID off (machine policy)'
        }
        @{
            Id = 'privacy.tailored'; Kind = 'Registry'; Group = 'Privacy'; Tags = @('Privacy')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'; Name = 'TailoredExperiencesWithDiagnosticDataEnabled'; Value = 0
            Description = 'No tailored experiences from diagnostic data'
        }
        @{
            Id = 'privacy.activity.publish'; Kind = 'Registry'; Group = 'Privacy'; Tags = @('Privacy')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'PublishUserActivities'; Value = 0
            Description = 'Activity history: do not record user activities'
        }
        @{
            Id = 'privacy.activity.upload'; Kind = 'Registry'; Group = 'Privacy'; Tags = @('Privacy')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'UploadUserActivities'; Value = 0
            Description = 'Activity history: do not upload user activities'
        }
        @{
            Id = 'privacy.activity.feed'; Kind = 'Registry'; Group = 'Privacy'; Tags = @('Privacy')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnableActivityFeed'; Value = 0
            Description = 'Activity history: disable activity feed'
        }
        @{
            Id = 'start.recommendations'; Kind = 'Registry'; Group = 'Privacy'; Tags = @('Privacy', 'Bloat')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'Start_IrisRecommendations'; Value = 0
            Description = 'Start: no recommendations for tips, shortcuts and new apps'; RestartShell = $true
        }
        @{
            Id = 'start.accountnotifications'; Kind = 'Registry'; Group = 'Privacy'; Tags = @('Privacy', 'Bloat')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'Start_AccountNotifications'; Value = 0
            Description = 'Start: no account-related notifications'; RestartShell = $true
        }
        @{
            Id = 'widgets.off'; Kind = 'Registry'; Group = 'Privacy'; Tags = @('Privacy', 'Bloat')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'; Name = 'AllowNewsAndInterests'; Value = 0
            Description = 'Widgets board off (policy; steadier than HKCU TaskbarDa)'; RestartShell = $true
        }

        # ---------------------------------------------------------------- Telemetry
        @{
            # Home clamps AllowTelemetry to Required (1); 0 is the floor request, not a guarantee.
            Id = 'telemetry.level'; Kind = 'Registry'; Group = 'Diagnostic Telemetry'; Tags = @('Telemetry')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Value = 0
            Description = 'Minimize telemetry [Home clamps to Required - partial effect]'
        }
        @{
            Id = 'telemetry.feedback'; Kind = 'Registry'; Group = 'Diagnostic Telemetry'; Tags = @('Telemetry')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'DoNotShowFeedbackNotifications'; Value = 1
            Description = 'No periodic feedback prompts'
        }
        @{
            Id = 'svc.diagtrack'; Kind = 'Service'; Group = 'Diagnostic Telemetry'; Tags = @('Telemetry')
            Name = 'DiagTrack'; StartMode = 'disabled'; Stop = $true
            Description = 'Connected User Experiences and Telemetry service'
        }
        @{
            Id = 'task.appraiser'; Kind = 'Task'; Group = 'Diagnostic Telemetry'; Tags = @('Telemetry', 'TelemetryTask')
            TaskPath = '\Microsoft\Windows\Application Experience\'; TaskName = 'Microsoft Compatibility Appraiser'
            Description = 'Compatibility inventory scan and upload'
        }
        @{
            Id = 'task.programdataupdater'; Kind = 'Task'; Group = 'Diagnostic Telemetry'; Tags = @('Telemetry', 'TelemetryTask')
            TaskPath = '\Microsoft\Windows\Application Experience\'; TaskName = 'ProgramDataUpdater'
            Description = 'Application inventory data collection'
        }
        @{
            Id = 'task.pcapatchdb'; Kind = 'Task'; Group = 'Diagnostic Telemetry'; Tags = @('Telemetry', 'TelemetryTask')
            TaskPath = '\Microsoft\Windows\Application Experience\'; TaskName = 'PcaPatchDbTask'
            Description = 'Program Compatibility Assistant database patching'
        }
        @{
            Id = 'task.ceip.consolidator'; Kind = 'Task'; Group = 'Diagnostic Telemetry'; Tags = @('Telemetry', 'TelemetryTask')
            TaskPath = '\Microsoft\Windows\Customer Experience Improvement Program\'; TaskName = 'Consolidator'
            Description = 'CEIP data consolidation and upload'
        }
        @{
            Id = 'task.ceip.usb'; Kind = 'Task'; Group = 'Diagnostic Telemetry'; Tags = @('Telemetry', 'TelemetryTask')
            TaskPath = '\Microsoft\Windows\Customer Experience Improvement Program\'; TaskName = 'UsbCeip'
            Description = 'USB device usage telemetry'
        }
        @{
            Id = 'task.ceip.kernel'; Kind = 'Task'; Group = 'Diagnostic Telemetry'; Tags = @('Telemetry', 'TelemetryTask')
            TaskPath = '\Microsoft\Windows\Customer Experience Improvement Program\'; TaskName = 'KernelCeipTask'
            Description = 'Kernel CEIP data collection (legacy builds)'
        }
        @{
            Id = 'task.autochk.proxy'; Kind = 'Task'; Group = 'Diagnostic Telemetry'; Tags = @('Telemetry', 'TelemetryTask')
            TaskPath = '\Microsoft\Windows\Autochk\'; TaskName = 'Proxy'
            Description = 'CEIP proxy data collection'
        }

        # ---------------------------------------------------------------- Developer experience
        @{
            Id = 'devux.fileext'; Kind = 'Registry'; Group = 'Developer Experience'; Tags = @('DevUX')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'HideFileExt'; Value = 0
            Description = 'Explorer: show file extensions'; RestartShell = $true
        }
        @{
            Id = 'devux.hidden'; Kind = 'Registry'; Group = 'Developer Experience'; Tags = @('DevUX')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'Hidden'; Value = 1
            Description = 'Explorer: show hidden files'; RestartShell = $true
        }
        @{
            Id = 'devux.launchto'; Kind = 'Registry'; Group = 'Developer Experience'; Tags = @('DevUX')
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'LaunchTo'; Value = 1
            Description = 'Explorer: open to This PC'; RestartShell = $true
        }
        @{
            Id = 'devux.endtask'; Kind = 'Registry'; Group = 'Developer Experience'; Tags = @('DevUX'); MinBuild = 22631
            Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings'; Name = 'TaskbarEndTask'; Value = 1
            Description = 'Taskbar: End task on right-click'; RestartShell = $true
        }
        @{
            # The unnamed default value must be an EMPTY STRING; "(value not set)" does not work.
            Id = 'devux.classicmenu'; Kind = 'Registry'; Group = 'Developer Experience'; Tags = @('DevUX')
            Path = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'; Name = ''; Value = ''; Type = 'String'
            Description = 'Classic (full) context menu by default'; RestartShell = $true
        }

        # ---------------------------------------------------------------- Power & network
        @{
            # "Shut down" with Fast Startup is a hybrid hibernate: interferes with WOL, dual-boot and NIC re-init.
            Id = 'power.nofaststartup'; Kind = 'Registry'; Group = 'Power & Wired Network'; Tags = @('Power')
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'; Name = 'HiberbootEnabled'; Value = 0
            Description = 'Disable Fast Startup (clean cold boot on shutdown)'; Reboot = $true
        }
        @{
            # 0 = HTTP only (no peering) | 1 = LAN peers only | 3 = LAN + Internet peers
            Id = 'net.deliveryoptimization'; Kind = 'Registry'; Group = 'Power & Wired Network'; Tags = @('Network')
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Name = 'DODownloadMode'; Value = 1
            Description = 'Delivery Optimization: LAN peers only (no Internet upload)'
        }
        @{
            Id = 'nic.eee'; Kind = 'NetAdapter'; Group = 'Power & Wired Network'; Tags = @('Network')
            Keyword = '*EEE'; Value = '0'
            Description = 'Energy Efficient Ethernet off'; Reboot = $true
        }
        @{
            Id = 'nic.eee.intel'; Kind = 'NetAdapter'; Group = 'Power & Wired Network'; Tags = @('Network')
            Keyword = 'EEELinkAdvertisement'; Value = '0'
            Description = 'Energy Efficient Ethernet off (Intel driver keyword)'; Reboot = $true
        }
        @{
            Id = 'nic.eee.realtek.advanced'; Kind = 'NetAdapter'; Group = 'Power & Wired Network'; Tags = @('Network')
            Keyword = 'AdvancedEEE'; Value = '0'
            Description = 'Advanced EEE off (Realtek driver keyword)'; Reboot = $true
        }
        @{
            Id = 'nic.greenethernet'; Kind = 'NetAdapter'; Group = 'Power & Wired Network'; Tags = @('Network')
            Keyword = 'EnableGreenEthernet'; Value = '0'
            Description = 'Green Ethernet off (Realtek driver keyword)'; Reboot = $true
        }
        @{
            # Applying this resets the adapter: expect a brief link drop (remote sessions reconnect).
            Id = 'nic.powermanagement'; Kind = 'NetAdapterPower'; Group = 'Power & Wired Network'; Tags = @('Network')
            Property = 'AllowComputerToTurnOffDevice'; Value = 'Disabled'
            Description = 'Do not let Windows power off wired adapters'
        }

        # ---------------------------------------------------------------- Defender notifications (toast spam)
        # These three only silence the non-critical "scan finished / file blocked / no action needed"
        # toasts. Real threat alerts (CRITICAL / threat found / ransomware) are a separate channel and
        # stay ON. Registry items, so they work regardless of the active AV.
        @{
            Id = 'defender.notify.summary'; Kind = 'Registry'; Group = 'Defender False-Alarm Remediation'; Tags = @('Defender', 'Notifications')
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection'; Name = 'SummaryNotificationDisabled'; Value = 1
            Description = 'Silence periodic "scan finished, no threats" summary toast'
        }
        @{
            Id = 'defender.notify.noaction'; Kind = 'Registry'; Group = 'Defender False-Alarm Remediation'; Tags = @('Defender', 'Notifications')
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection'; Name = 'NoActionNotificationDisabled'; Value = 1
            Description = 'Silence informational "no action needed" toast'
        }
        @{
            Id = 'defender.notify.filesblocked'; Kind = 'Registry'; Group = 'Defender False-Alarm Remediation'; Tags = @('Defender', 'Notifications')
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection'; Name = 'FilesBlockedNotificationDisabled'; Value = 1
            Description = 'Silence non-critical "files blocked" toast (true detections still alert)'
        }

        # ---------------------------------------------------------------- Defender false-positive handling
        # EVERY item below is OFF by default (Defender tag; runs only with -Include Defender) and does
        # NOT weaken protection. FILL IN YOUR OWN VALUES from Get-MpThreat / Get-MpThreatDetection, then
        # run:  .\Win11Home_fine_tune_v6.ps1 -Include Defender -WhatIf
        # Scan engines, real-time protection, cloud protection and tamper protection are untouched.

        # PUA (potentially unwanted app) heuristic re-tags some dev tools. AuditMode = log, do not block;
        # it does NOT reduce malware protection. Use 'Enabled' to keep PUA blocking, 'Disabled' to turn
        # the PUA class off entirely (still not a malware-protection change).
        @{
            Id = 'defender.pua.audit'; Kind = 'MpPreference'; Group = 'Defender False-Alarm Remediation'; Tags = @('Defender', 'PUA')
            Preference = 'PUAProtection'; Value = 'AuditMode'
            Description = 'PUA protection to audit-only (log, do not block) - malware protection unaffected'
        }

        # EXAMPLE exclusions - EDIT THE PATHS to your own tool folders, then enable with -Include Defender.
        # Never a drive root or %TEMP% / Downloads (the validator refuses the former).
        # @{
        #     Id = 'defender.excl.cheatengine'; Kind = 'MpExclusion'; Group = 'Defender False-Alarm Remediation'; Tags = @('Defender', 'Exclusion')
        #     ExclusionType = 'Path'; Value = 'D:\Tools\CheatEngine'
        #     Description = 'Exclude the Cheat Engine install folder (user-managed HackTool false positive)'
        # }
        # @{
        #     Id = 'defender.excl.devbuild'; Kind = 'MpExclusion'; Group = 'Defender False-Alarm Remediation'; Tags = @('Defender', 'Exclusion')
        #     ExclusionType = 'Process'; Value = 'D:\Dev\build\robotctl.exe'
        #     Description = 'Exclude self-built deployment binary from real-time scan'
        # }

        # EXAMPLE per-ID allow - COPY A ThreatID FROM Get-MpThreat FOR A CONFIRMED FALSE POSITIVE.
        # Scoped to one detection only; this is not a severity-tier allow.
        # @{
        #     Id = 'defender.allow.sample'; Kind = 'MpThreatAllow'; Group = 'Defender False-Alarm Remediation'; Tags = @('Defender', 'ThreatAllow')
        #     ThreatId = '2147735507'
        #     Description = 'Allow a specific HackTool detection confirmed as a false positive'
        # }

        # ---------------------------------------------------------------- WSL2
        @{
            # Store/package WSL2 needs only VirtualMachinePlatform; the legacy component is WSL1-only.
            # After reboot, as your user: wsl --install --no-distribution   (or: wsl --update)
            Id = 'wsl.vmp'; Kind = 'Feature'; Group = 'WSL2 Platform'; Tags = @('WSL')
            FeatureName = 'VirtualMachinePlatform'
            Description = 'Virtual Machine Platform (WSL2 runtime prerequisite)'; Reboot = $true
        }
    )
}
