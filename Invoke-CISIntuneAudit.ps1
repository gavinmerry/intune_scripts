#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    CIS Microsoft Intune for Windows 11 Benchmark v4.0.0 - L1 Automated Audit
.DESCRIPTION
    Queries Microsoft Graph API to evaluate Intune tenant configuration against
    213 CIS Level 1 benchmark checks. Pulls Settings Catalog policies, Device
    Configuration profiles, and Endpoint Security policies, then evaluates each
    check and produces an HTML report + CSV export.
.PARAMETER TenantId
    Azure AD tenant ID. If omitted, uses the current Graph session.
.PARAMETER OutputPath
    Directory for report output. If omitted, you will be prompted interactively (defaults to current directory).
.PARAMETER ExportCsv
    Also export results to CSV.
.PARAMETER SkipAuth
    Skip authentication (use existing Graph session).
.EXAMPLE
    .\Invoke-CISIntuneAudit.ps1 -TenantId "contoso.onmicrosoft.com" -OutputPath .\results
.NOTES
    Requires: Microsoft.Graph.Authentication module
    Permissions: DeviceManagementConfiguration.Read.All (delegated or application)
    Author: CIS Intune Audit Script
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputPath,
    [switch]$ExportCsv,
    [switch]$SkipAuth
)

$ErrorActionPreference = 'Stop'
$script:GraphBaseUri = 'https://graph.microsoft.com/beta'
$script:Timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$script:Results = [System.Collections.Generic.List[PSObject]]::new()

#region Authentication
function Connect-CISGraph {
    if ($SkipAuth) {
        try {
            $ctx = Get-MgContext
            if (-not $ctx) { throw "No active Graph session" }
            Write-Host "[+] Using existing Graph session: $($ctx.Account)" -ForegroundColor Green
        } catch {
            throw "No active Graph session. Run Connect-MgGraph first or omit -SkipAuth."
        }
        return
    }

    $scopes = @(
        'DeviceManagementConfiguration.Read.All',
        'DeviceManagementManagedDevices.Read.All'
    )

    $connectParams = @{ Scopes = $scopes; NoWelcome = $true }
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }

    Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph @connectParams
    $ctx = Get-MgContext
    Write-Host "[+] Connected as: $($ctx.Account) | Tenant: $($ctx.TenantId)" -ForegroundColor Green
}
#endregion

#region Graph API Helpers
function Invoke-GraphRequest {
    param([string]$Uri, [int]$MaxRetries = 3)

    $allResults = [System.Collections.Generic.List[PSObject]]::new()
    $currentUri = if ($Uri.StartsWith('http')) { $Uri } else { "$script:GraphBaseUri/$Uri" }

    do {
        $attempt = 0
        $response = $null
        while ($attempt -lt $MaxRetries) {
            try {
                $response = Invoke-MgGraphRequest -Method GET -Uri $currentUri -OutputType PSObject
                break
            } catch {
                $attempt++
                if ($attempt -ge $MaxRetries) { throw }
                if ($_.Exception.Message -match '429|throttl') {
                    $wait = [math]::Pow(2, $attempt) * 2
                    Write-Warning "Throttled. Waiting ${wait}s..."
                    Start-Sleep -Seconds $wait
                } else { throw }
            }
        }

        if ($response.value) {
            $allResults.AddRange([PSObject[]]$response.value)
        } elseif ($response -and -not $response.'@odata.nextLink') {
            $allResults.Add($response)
        }

        $currentUri = $response.'@odata.nextLink'
    } while ($currentUri)

    return $allResults
}
#endregion

#region Data Collection
function Get-AllIntuneSettings {
    Write-Host "`n[*] Collecting Intune configuration data..." -ForegroundColor Cyan
    $script:AllSettings = @{}

    # 1. Settings Catalog policies
    Write-Host "    Fetching Settings Catalog policies..." -ForegroundColor Gray
    $catalogPolicies = Invoke-GraphRequest -Uri 'deviceManagement/configurationPolicies?$top=200'
    $script:CatalogPolicyCount = ($catalogPolicies | Measure-Object).Count
    Write-Host "    Found $($script:CatalogPolicyCount) Settings Catalog policies" -ForegroundColor Gray

    foreach ($policy in $catalogPolicies) {
        $settings = Invoke-GraphRequest -Uri "deviceManagement/configurationPolicies/$($policy.id)/settings?`$top=1000"
        foreach ($setting in $settings) {
            $si = $setting.settingInstance
            if (-not $si) { continue }
            $defId = $si.settingDefinitionId
            if (-not $defId) { continue }

            $value = $null
            switch ($si.'@odata.type') {
                '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance' {
                    $value = $si.choiceSettingValue.value
                    # Also capture children for grouped settings
                    if ($si.choiceSettingValue.children) {
                        foreach ($child in $si.choiceSettingValue.children) {
                            $childId = $child.settingDefinitionId
                            $childVal = $null
                            switch ($child.'@odata.type') {
                                '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance' {
                                    $childVal = $child.choiceSettingValue.value
                                }
                                '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance' {
                                    $childVal = $child.simpleSettingValue.value
                                }
                            }
                            if ($childId -and $null -ne $childVal) {
                                $script:AllSettings[$childId] = @{
                                    Value      = $childVal
                                    PolicyName = $policy.name
                                    PolicyId   = $policy.id
                                    Source      = 'SettingsCatalog'
                                }
                            }
                        }
                    }
                }
                '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance' {
                    $value = $si.simpleSettingValue.value
                }
                '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance' {
                    $value = ($si.simpleSettingCollectionValue | ForEach-Object { $_.value }) -join '; '
                }
                '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance' {
                    # ASR rules and similar grouped collections
                    foreach ($group in $si.groupSettingCollectionValue) {
                        foreach ($child in $group.children) {
                            $childId = $child.settingDefinitionId
                            $childVal = $null
                            switch ($child.'@odata.type') {
                                '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance' {
                                    $childVal = $child.choiceSettingValue.value
                                }
                                '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance' {
                                    $childVal = $child.simpleSettingValue.value
                                }
                            }
                            if ($childId -and $null -ne $childVal) {
                                # For ASR rules, key by the rule GUID value
                                $ruleKey = $childId
                                if (-not $script:AllSettings.ContainsKey($ruleKey)) {
                                    $script:AllSettings[$ruleKey] = @{
                                        Value      = $childVal
                                        PolicyName = $policy.name
                                        PolicyId   = $policy.id
                                        Source      = 'SettingsCatalog'
                                    }
                                }
                            }
                        }
                    }
                    $value = 'GroupCollection'
                }
            }

            if ($null -ne $value) {
                $script:AllSettings[$defId] = @{
                    Value      = $value
                    PolicyName = $policy.name
                    PolicyId   = $policy.id
                    Source      = 'SettingsCatalog'
                }
            }
        }
    }

    # 2. Device Configuration profiles (OMA-URI custom, etc.)
    Write-Host "    Fetching Device Configuration profiles..." -ForegroundColor Gray
    $deviceConfigs = Invoke-GraphRequest -Uri 'deviceManagement/deviceConfigurations?$top=200'
    $script:DeviceConfigCount = ($deviceConfigs | Measure-Object).Count
    Write-Host "    Found $($script:DeviceConfigCount) Device Configuration profiles" -ForegroundColor Gray

    foreach ($config in $deviceConfigs) {
        $omaType = $config.'@odata.type'
        if ($omaType -eq '#microsoft.graph.windows10CustomConfiguration') {
            foreach ($oma in $config.omaSettings) {
                $omaUri = $oma.omaUri
                $script:AllSettings[$omaUri] = @{
                    Value      = $oma.value
                    PolicyName = $config.displayName
                    PolicyId   = $config.id
                    Source      = 'OMA-URI'
                }
            }
        }
        # For template-based profiles, store by odata type + setting name
        if ($config.settings) {
            foreach ($s in $config.settings) {
                if ($s.settingDefinitionId) {
                    $script:AllSettings[$s.settingDefinitionId] = @{
                        Value      = $s.value
                        PolicyName = $config.displayName
                        PolicyId   = $config.id
                        Source      = 'DeviceConfig'
                    }
                }
            }
        }
    }

    # 3. Endpoint Security policies (Antivirus, Firewall, ASR, etc.)
    Write-Host "    Fetching Endpoint Security intents..." -ForegroundColor Gray
    $intents = Invoke-GraphRequest -Uri 'deviceManagement/intents?$top=200'
    $script:IntentCount = ($intents | Measure-Object).Count
    Write-Host "    Found $($script:IntentCount) Endpoint Security policies" -ForegroundColor Gray

    foreach ($intent in $intents) {
        $categories = Invoke-GraphRequest -Uri "deviceManagement/intents/$($intent.id)/categories"
        foreach ($cat in $categories) {
            $catSettings = Invoke-GraphRequest -Uri "deviceManagement/intents/$($intent.id)/categories/$($cat.id)/settings"
            foreach ($s in $catSettings) {
                $sDefId = $s.definitionId
                if ($sDefId) {
                    $script:AllSettings[$sDefId] = @{
                        Value      = $s.value ?? $s.valueJson
                        PolicyName = $intent.displayName
                        PolicyId   = $intent.id
                        Source      = 'EndpointSecurity'
                    }
                }
            }
        }
    }

    $totalSettings = $script:AllSettings.Count
    Write-Host "[+] Collected $totalSettings unique settings from Intune" -ForegroundColor Green
}
#endregion


#region Check Definitions
# Each check: CIS ID, Description, one or more setting identifiers to search for,
# expected value, comparison operator, and CIS section.
# Setting IDs use the Settings Catalog definitionId naming convention (lowercase, underscores).
# Multiple IDs per check allow matching across Settings Catalog, OMA-URI, and Endpoint Security.

$script:CISChecks = @(
    # ── Section 1: Above Lock ──
    @{ Id='1.1'; Sec='Above Lock'; Name='Allow Cortana Above Lock'; Settings=@('device_vendor_msft_policy_config_abovelock_allowcortanaabovelock'); Expected=0; Op='eq' }

    # ── Section 4.1: Control Panel - Personalization ──
    @{ Id='4.1.3.1'; Sec='Admin Templates'; Name='Prevent enabling lock screen camera'; Settings=@('device_vendor_msft_policy_config_devicelock_preventlockscreencamera','device_vendor_msft_policy_config_admx_controlpaneldisplay_cpl_personalization_nolockscreencamera'); Expected=1; Op='eq' }
    @{ Id='4.1.3.2'; Sec='Admin Templates'; Name='Prevent enabling lock screen slide show'; Settings=@('device_vendor_msft_policy_config_devicelock_preventlockscreenslideshow','device_vendor_msft_policy_config_admx_controlpaneldisplay_cpl_personalization_nolockscreenslideshow'); Expected=1; Op='eq' }

    # ── Section 4.4: MS Security Guide ──
    @{ Id='4.4.1'; Sec='MS Security Guide'; Name='Apply UAC restrictions to local accounts on network logons'; Settings=@('device_vendor_msft_policy_config_mssecurityguide_applyuacrestrictionstolocalaccountsonnetworklogon'); Expected=1; Op='eq' }
    @{ Id='4.4.2'; Sec='MS Security Guide'; Name='Configure SMB v1 client driver - Disable driver'; Settings=@('device_vendor_msft_policy_config_mssecurityguide_configuresmbv1clientdriver'); Expected=4; Op='eq' }
    @{ Id='4.4.3'; Sec='MS Security Guide'; Name='Configure SMB v1 server - Disabled'; Settings=@('device_vendor_msft_policy_config_mssecurityguide_configuresmbv1server'); Expected=0; Op='eq' }
    @{ Id='4.4.4'; Sec='MS Security Guide'; Name='Enable SEHOP'; Settings=@('device_vendor_msft_policy_config_mssecurityguide_enablestructuredexceptionhandlingoverwriteprotection'); Expected=1; Op='eq' }
    @{ Id='4.4.5'; Sec='MS Security Guide'; Name='WDigest Authentication - Disabled'; Settings=@('device_vendor_msft_policy_config_mssecurityguide_waborwdigestauthentication'); Expected=0; Op='eq' }

    # ── Section 4.5: MSS (Legacy) ──
    @{ Id='4.5.1'; Sec='MSS Legacy'; Name='AutoAdminLogon - Disabled'; Settings=@('device_vendor_msft_policy_config_msslegacy_autoadminlogon'); Expected=0; Op='eq' }
    @{ Id='4.5.2'; Sec='MSS Legacy'; Name='DisableIPSourceRouting IPv6 - Highest protection'; Settings=@('device_vendor_msft_policy_config_msslegacy_ipv6sourceroutingprotectionlevel','device_vendor_msft_policy_config_msslegacy_disableipsourceroutingipv6'); Expected=2; Op='eq' }
    @{ Id='4.5.3'; Sec='MSS Legacy'; Name='DisableIPSourceRouting - Highest protection'; Settings=@('device_vendor_msft_policy_config_msslegacy_ipsourceroutingprotectionlevel','device_vendor_msft_policy_config_msslegacy_disableipsourcerouting'); Expected=2; Op='eq' }
    @{ Id='4.5.5'; Sec='MSS Legacy'; Name='EnableICMPRedirect - Disabled'; Settings=@('device_vendor_msft_policy_config_msslegacy_allowicmpredirectstooverrideospfgeneratedroutes','device_vendor_msft_policy_config_msslegacy_enableicmpredirect'); Expected=0; Op='eq' }
    @{ Id='4.5.7'; Sec='MSS Legacy'; Name='NoNameReleaseOnDemand - Enabled'; Settings=@('device_vendor_msft_policy_config_msslegacy_allownamereleaseondemand','device_vendor_msft_policy_config_msslegacy_nonamereleaseondemand'); Expected=1; Op='eq' }
    @{ Id='4.5.9'; Sec='MSS Legacy'; Name='SafeDllSearchMode - Enabled'; Settings=@('device_vendor_msft_policy_config_msslegacy_safedllsearchmode'); Expected=1; Op='eq' }
    @{ Id='4.5.10'; Sec='MSS Legacy'; Name='ScreenSaverGracePeriod - 5 or fewer seconds'; Settings=@('device_vendor_msft_policy_config_msslegacy_screensavergraceperiod'); Expected=5; Op='le' }
    @{ Id='4.5.13'; Sec='MSS Legacy'; Name='WarningLevel - 90% or less'; Settings=@('device_vendor_msft_policy_config_msslegacy_warninglevel'); Expected=90; Op='le' }

    # ── Section 4.6: Network ──
    @{ Id='4.6.4.1'; Sec='Network'; Name='Turn off multicast name resolution (LLMNR)'; Settings=@('device_vendor_msft_policy_config_admx_dnsclient_turn_off_multicast','device_vendor_msft_policy_config_admx_dnsclient_enablemulticast'); Expected=0; Op='eq' }
    @{ Id='4.6.9.1'; Sec='Network'; Name='Prohibit installation of Network Bridge'; Settings=@('device_vendor_msft_policy_config_admx_networkconnections_nc_allownetbridge_nla'); Expected=0; Op='eq' }
    @{ Id='4.6.9.2'; Sec='Network'; Name='Prohibit use of Internet Connection Sharing'; Settings=@('device_vendor_msft_policy_config_admx_networkconnections_nc_showsharedaccessui'); Expected=0; Op='eq' }
    @{ Id='4.6.9.3'; Sec='Network'; Name='Require domain users to elevate when setting network location'; Settings=@('device_vendor_msft_policy_config_admx_networkconnections_nc_stddomainusersetlocation'); Expected=1; Op='eq' }
    @{ Id='4.6.11.1'; Sec='Network'; Name='Hardened UNC Paths'; Settings=@('device_vendor_msft_policy_config_admx_networkprovider_pol_hardenedpaths'); Expected='RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1'; Op='contains_all' }
    @{ Id='4.6.18.1'; Sec='Network'; Name='Minimize simultaneous connections to Internet or Domain'; Settings=@('device_vendor_msft_policy_config_admx_wifinetworkmanager_wifisettings_minimizeconnections','device_vendor_msft_policy_config_admx_networkconnections_nc_minimizeconnections'); Expected=3; Op='eq' }
    @{ Id='4.6.18.2'; Sec='Network'; Name='Prohibit connection to non-domain networks when connected to domain'; Settings=@('device_vendor_msft_policy_config_admx_networkconnections_nc_blocknondomainnetworks'); Expected=1; Op='eq' }

    # ── Section 4.7: Printers ──
    @{ Id='4.7.1'; Sec='Printers'; Name='Allow Print Spooler to accept client connections - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_printing_printspooler_allowremoteaccess','device_vendor_msft_policy_config_printers_allowprintspoolertoaccept'); Expected=0; Op='eq' }
    @{ Id='4.7.2'; Sec='Printers'; Name='Configure Redirection Guard - Enabled'; Settings=@('device_vendor_msft_policy_config_printers_configureredirectionguard'); Expected=1; Op='eq' }
    @{ Id='4.7.3'; Sec='Printers'; Name='RPC outgoing connections - RPC over TCP'; Settings=@('device_vendor_msft_policy_config_printers_configurerpcconnectionsettings_rpcconnectionprotocol'); Expected=0; Op='eq' }
    @{ Id='4.7.4'; Sec='Printers'; Name='RPC outgoing auth - Default'; Settings=@('device_vendor_msft_policy_config_printers_configurerpcconnectionsettings_rpcauthenticationprotocol'); Expected=0; Op='eq' }
    @{ Id='4.7.5'; Sec='Printers'; Name='RPC listener auth - Negotiate or higher'; Settings=@('device_vendor_msft_policy_config_printers_configurerpclistenersettings_rpclistenerauthenticationprotocol'); Expected=1; Op='ge' }
    @{ Id='4.7.6'; Sec='Printers'; Name='RPC listener protocols - RPC over TCP'; Settings=@('device_vendor_msft_policy_config_printers_configurerpclistenersettings_rpclistenerprotocols'); Expected=0; Op='eq' }
    @{ Id='4.7.7'; Sec='Printers'; Name='RPC over TCP port - 0'; Settings=@('device_vendor_msft_policy_config_printers_configurerpcovertcpport'); Expected=0; Op='eq' }
    @{ Id='4.7.8'; Sec='Printers'; Name='Limits print driver installation to Administrators'; Settings=@('device_vendor_msft_policy_config_printers_restrictdriverinstallationtoadministrators','device_vendor_msft_policy_config_admx_printing_restrictdriverinstallationtoadministrators'); Expected=1; Op='eq' }
    @{ Id='4.7.9'; Sec='Printers'; Name='Manage processing of Queue-specific files'; Settings=@('device_vendor_msft_policy_config_printers_manageprocessingofqueuespecificfiles'); Expected=0; Op='eq' }
    @{ Id='4.7.10'; Sec='Printers'; Name='Point and Print - new connection: Show warning and elevation prompt'; Settings=@('device_vendor_msft_policy_config_printers_pointandprintrestrictions_pointandprintrestrictions_nowarningnoelevationnewconnection'); Expected=0; Op='eq' }
    @{ Id='4.7.11'; Sec='Printers'; Name='Point and Print - update: Show warning and elevation prompt'; Settings=@('device_vendor_msft_policy_config_printers_pointandprintrestrictions_pointandprintrestrictions_nowarningnoelevationupdateconnection'); Expected=0; Op='eq' }

    # ── Section 4.9: Start Menu / Notifications ──
    @{ Id='4.9.1.1'; Sec='Notifications'; Name='Turn off toast notifications on lock screen (User)'; Settings=@('user_vendor_msft_policy_config_admx_wpn_notoastnotificationonlockscreen','device_vendor_msft_policy_config_admx_wpn_notoastnotificationonlockscreen'); Expected=1; Op='eq' }

    # ── Section 4.10: System ──
    @{ Id='4.10.4.1'; Sec='System'; Name='Include command line in process creation events'; Settings=@('device_vendor_msft_policy_config_admx_auditsettings_includecommandline'); Expected=1; Op='eq' }
    @{ Id='4.10.5.1'; Sec='System'; Name='Encryption Oracle Remediation - Force Updated Clients'; Settings=@('device_vendor_msft_policy_config_admx_credssp_allowencryptionoracle'); Expected=0; Op='eq' }
    @{ Id='4.10.5.2'; Sec='System'; Name='Remote host allows delegation of non-exportable credentials'; Settings=@('device_vendor_msft_policy_config_admx_credentialsdelegation_allowdefcredentialswhenntlmonly','device_vendor_msft_policy_config_credentialsdelegation_remotehostallowsdelegationofnonexportablecredentials'); Expected=1; Op='eq' }
    @{ Id='4.10.9.2'; Sec='System'; Name='Prevent device metadata retrieval from Internet'; Settings=@('device_vendor_msft_policy_config_admx_deviceinstallation_devicemetadatapreventdevicemetadatafromnetwork'); Expected=1; Op='eq' }
    @{ Id='4.10.13.1'; Sec='System'; Name='Boot-Start Driver Initialization Policy'; Settings=@('device_vendor_msft_policy_config_admx_earlylaunchantimalware_pol_enableearlylaunchantimalware'); Expected=3; Op='eq' }
    @{ Id='4.10.19.1'; Sec='System'; Name='Continue experiences on this device - Disabled'; Settings=@('device_vendor_msft_policy_config_experience_allowcrossdeviceclipboard','device_vendor_msft_policy_config_admx_grouppolicy_enablecdp'); Expected=0; Op='eq' }
    @{ Id='4.10.19.2'; Sec='System'; Name='Turn off background refresh of Group Policy - Disabled (not configured)'; Settings=@('device_vendor_msft_policy_config_admx_grouppolicy_disablebkgndgrouppolicy'); Expected=0; Op='eq' }
    @{ Id='4.10.20.1.2'; Sec='System'; Name='Turn off downloading of print drivers over HTTP'; Settings=@('device_vendor_msft_policy_config_admx_icm_disablewebpnpdownload'); Expected=1; Op='eq' }
    @{ Id='4.10.20.1.5'; Sec='System'; Name='Turn off Internet download for Web publishing and online ordering wizards'; Settings=@('device_vendor_msft_policy_config_admx_icm_disablehttpprinting'); Expected=1; Op='eq' }
    @{ Id='4.10.26.1'; Sec='System'; Name='Block user from showing account details on sign-in'; Settings=@('device_vendor_msft_policy_config_admx_logon_blockuserfromshowingaccountdetailsonsignin'); Expected=1; Op='eq' }
    @{ Id='4.10.26.2'; Sec='System'; Name='Do not display network selection UI'; Settings=@('device_vendor_msft_policy_config_windowslogon_dontdisplaynetworkselectionui'); Expected=1; Op='eq' }
    @{ Id='4.10.26.3'; Sec='System'; Name='Do not enumerate connected users on domain-joined computers'; Settings=@('device_vendor_msft_policy_config_windowslogon_donotenumerateconnectedusers','device_vendor_msft_policy_config_admx_logon_donotenumerateconnectedusers'); Expected=1; Op='eq' }
    @{ Id='4.10.26.4'; Sec='System'; Name='Enumerate local users on domain-joined computers - Disabled'; Settings=@('device_vendor_msft_policy_config_windowslogon_enumeratelocalusersondomainjoinedcomputers'); Expected=0; Op='eq' }
    @{ Id='4.10.26.5'; Sec='System'; Name='Turn off app notifications on the lock screen'; Settings=@('device_vendor_msft_policy_config_abovelock_allowtoasts','device_vendor_msft_policy_config_windowslogon_disablelockscreenappnotifications'); Expected=0; Op='eq' }
    @{ Id='4.10.26.6'; Sec='System'; Name='Turn off picture password sign-in'; Settings=@('device_vendor_msft_policy_config_credentialsproviders_disablepicturepictureprovider','device_vendor_msft_policy_config_admx_credentialproviders_blockpicturepassword'); Expected=1; Op='eq' }
    @{ Id='4.10.26.7'; Sec='System'; Name='Turn on convenience PIN sign-in - Disabled'; Settings=@('device_vendor_msft_policy_config_credentialsproviders_allowpinlogon','device_vendor_msft_policy_config_admx_credentialproviders_turnoffpicturepasswordsignin'); Expected=0; Op='eq' }
    @{ Id='4.10.29.5.1'; Sec='System'; Name='Require password when computer wakes (on battery)'; Settings=@('device_vendor_msft_policy_config_admx_power_acpromptforpasswordonresume_2','device_vendor_msft_policy_config_power_requirepasswordwhencomputerwakesonbattery'); Expected=1; Op='eq' }
    @{ Id='4.10.29.5.2'; Sec='System'; Name='Require password when computer wakes (plugged in)'; Settings=@('device_vendor_msft_policy_config_admx_power_acpromptforpasswordonresume_1','device_vendor_msft_policy_config_power_requirepasswordwhencomputerwakespluggedin'); Expected=1; Op='eq' }
    @{ Id='4.10.30.1'; Sec='System'; Name='Configure Offer Remote Assistance - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_remoteassistance_ra_unsolicit'); Expected=0; Op='eq' }
    @{ Id='4.10.30.2'; Sec='System'; Name='Configure Solicited Remote Assistance - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_remoteassistance_ra_solicit'); Expected=0; Op='eq' }
    @{ Id='4.10.31.1'; Sec='System'; Name='Enable RPC Endpoint Mapper Client Authentication'; Settings=@('device_vendor_msft_policy_config_remoteprocedurecall_rpcendpointmapperclientauthentication'); Expected=1; Op='eq' }
    @{ Id='4.10.31.2'; Sec='System'; Name='Restrict Unauthenticated RPC clients - Authenticated'; Settings=@('device_vendor_msft_policy_config_remoteprocedurecall_restrictunauthenticatedrpcclients'); Expected=1; Op='eq' }
    @{ Id='4.10.44.1.1'; Sec='System'; Name='Enable Windows NTP Client'; Settings=@('device_vendor_msft_policy_config_admx_w32time_w32time_policy_enable_ntpclient'); Expected=1; Op='eq' }
    @{ Id='4.10.44.1.2'; Sec='System'; Name='Enable Windows NTP Server - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_w32time_w32time_policy_enable_ntpserver'); Expected=0; Op='eq' }
)

$script:CISChecks += @(
    # ── Section 4.11: Windows Components ──
    @{ Id='4.11.3.1'; Sec='Windows Components'; Name='Allow Microsoft accounts to be optional'; Settings=@('device_vendor_msft_policy_config_appruntime_allowmicrosoftaccountstobeoptional'); Expected=1; Op='eq' }
    @{ Id='4.11.5.1'; Sec='Windows Components'; Name='Do not preserve zone information in file attachments (User) - Disabled'; Settings=@('user_vendor_msft_policy_config_admx_attachmentmanager_defaultfilename','device_vendor_msft_policy_config_admx_attachmentmanager_savezoneinformation'); Expected=2; Op='eq' }
    @{ Id='4.11.5.2'; Sec='Windows Components'; Name='Notify antivirus programs when opening attachments (User)'; Settings=@('user_vendor_msft_policy_config_admx_attachmentmanager_scanwithantivirus','device_vendor_msft_policy_config_admx_attachmentmanager_notifyantivirusprograms'); Expected=3; Op='eq' }
    @{ Id='4.11.6.1'; Sec='Windows Components'; Name='Disallow Autoplay for non-volume devices'; Settings=@('device_vendor_msft_policy_config_autoplay_disallowautoplayfornonvolumedevices'); Expected=1; Op='eq' }
    @{ Id='4.11.6.2'; Sec='Windows Components'; Name='Set default behavior for AutoRun - Do not execute'; Settings=@('device_vendor_msft_policy_config_autoplay_setdefaultautorunbehavior'); Expected=1; Op='eq' }
    @{ Id='4.11.6.3'; Sec='Windows Components'; Name='Turn off Autoplay - All drives'; Settings=@('device_vendor_msft_policy_config_autoplay_turnoffautoplay'); Expected=255; Op='eq' }
    @{ Id='4.11.8.1'; Sec='Windows Components'; Name='Do not display the password reveal button'; Settings=@('device_vendor_msft_policy_config_credentialsui_donotdisplaythepasswordrevealbutton','device_vendor_msft_policy_config_admx_credentialui_disablepasswordreveal'); Expected=1; Op='eq' }
    @{ Id='4.11.8.2'; Sec='Windows Components'; Name='Enumerate administrator accounts on elevation - Disabled'; Settings=@('device_vendor_msft_policy_config_credentialsui_enumerateadministrators','device_vendor_msft_policy_config_admx_credentialui_enumerateadministrators'); Expected=0; Op='eq' }
    @{ Id='4.11.8.3'; Sec='Windows Components'; Name='Prevent use of security questions for local accounts'; Settings=@('device_vendor_msft_policy_config_admx_credentialui_nosecurityquestions','device_vendor_msft_policy_config_credentialsui_preventtheuseofquestionsforlocal'); Expected=1; Op='eq' }
    @{ Id='4.11.10.1'; Sec='Windows Components'; Name='Enable App Installer Experimental Features - Disabled'; Settings=@('device_vendor_msft_policy_config_desktopappinstaller_enableexperimentalfeatures'); Expected=0; Op='eq' }
    @{ Id='4.11.10.2'; Sec='Windows Components'; Name='Enable App Installer Hash Override - Disabled'; Settings=@('device_vendor_msft_policy_config_desktopappinstaller_enablehashoverride'); Expected=0; Op='eq' }
    @{ Id='4.11.10.3'; Sec='Windows Components'; Name='Enable App Installer ms-appinstaller protocol - Disabled'; Settings=@('device_vendor_msft_policy_config_desktopappinstaller_enablemsappinstallerprotocol'); Expected=0; Op='eq' }

    # Event Log Service
    @{ Id='4.11.15.1.1'; Sec='Event Log'; Name='Application log: Control behavior when max size - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_eventlog_channel_logretention_1'); Expected=0; Op='eq' }
    @{ Id='4.11.15.1.2'; Sec='Event Log'; Name='Application log: Max size >= 32768 KB'; Settings=@('device_vendor_msft_policy_config_admx_eventlog_channel_logmaxsize_1','device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizeapplicationlog'); Expected=32768; Op='ge' }
    @{ Id='4.11.15.2.1'; Sec='Event Log'; Name='Security log: Control behavior when max size - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_eventlog_channel_logretention_2'); Expected=0; Op='eq' }
    @{ Id='4.11.15.2.2'; Sec='Event Log'; Name='Security log: Max size >= 196608 KB'; Settings=@('device_vendor_msft_policy_config_admx_eventlog_channel_logmaxsize_2','device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizesecuritylog'); Expected=196608; Op='ge' }
    @{ Id='4.11.15.3.1'; Sec='Event Log'; Name='Setup log: Control behavior when max size - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_eventlog_channel_logretention_3'); Expected=0; Op='eq' }
    @{ Id='4.11.15.3.2'; Sec='Event Log'; Name='Setup log: Max size >= 32768 KB'; Settings=@('device_vendor_msft_policy_config_admx_eventlog_channel_logmaxsize_3','device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizesetuplog'); Expected=32768; Op='ge' }
    @{ Id='4.11.15.4.1'; Sec='Event Log'; Name='System log: Control behavior when max size - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_eventlog_channel_logretention_4'); Expected=0; Op='eq' }
    @{ Id='4.11.15.4.2'; Sec='Event Log'; Name='System log: Max size >= 32768 KB'; Settings=@('device_vendor_msft_policy_config_admx_eventlog_channel_logmaxsize_4','device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizesystemlog'); Expected=32768; Op='ge' }

    # File Explorer
    @{ Id='4.11.18.1'; Sec='File Explorer'; Name='Configure Windows Defender SmartScreen - Warn and prevent bypass'; Settings=@('device_vendor_msft_policy_config_admx_windowsexplorer_enablesmartscreen'); Expected=1; Op='eq' }
    @{ Id='4.11.18.2'; Sec='File Explorer'; Name='Turn off DEP for Explorer - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_fileexplorer_turnoffdataexecutionpreventionforexplorer'); Expected=0; Op='eq' }
    @{ Id='4.11.18.3'; Sec='File Explorer'; Name='Turn off heap termination on corruption - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_fileexplorer_turnoffheapterminationoncorruption'); Expected=0; Op='eq' }
    @{ Id='4.11.18.4'; Sec='File Explorer'; Name='Turn off shell protocol protected mode - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_windowsexplorer_shellprotocolprotectedmode'); Expected=0; Op='eq' }

    # Microsoft Account
    @{ Id='4.11.27.1'; Sec='Windows Components'; Name='Block all consumer Microsoft account user authentication'; Settings=@('device_vendor_msft_policy_config_admx_microsoftaccount_microsoftaccount_disableuserauth'); Expected=1; Op='eq' }

    # Defender MAPS
    @{ Id='4.11.28.3.1'; Sec='Defender MAPS'; Name='Configure local setting override for reporting to MAPS - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_microsoftdefenderantivirus_spynet_localsettingoverridespynetreporting'); Expected=0; Op='eq' }

    # Network Sharing
    @{ Id='4.11.31.1'; Sec='Network Sharing'; Name='Prevent users from sharing files within their profile (User)'; Settings=@('user_vendor_msft_policy_config_admx_sharing_noinplacesharing','device_vendor_msft_policy_config_admx_sharing_noinplacesharing'); Expected=1; Op='eq' }

    # Remote Desktop Services
    @{ Id='4.11.36.3.2'; Sec='RDS Client'; Name='Do not allow passwords to be saved'; Settings=@('device_vendor_msft_policy_config_admx_terminalserver_ts_client_disablepasswordsaving'); Expected=1; Op='eq' }
    @{ Id='4.11.36.4.3.2'; Sec='RDS Redirection'; Name='Do not allow drive redirection'; Settings=@('device_vendor_msft_policy_config_admx_terminalserver_ts_client_nodrives','device_vendor_msft_policy_config_remotedesktopservices_donotallowdriveredirection'); Expected=1; Op='eq' }
    @{ Id='4.11.36.4.9.1'; Sec='RDS Security'; Name='Always prompt for password upon connection'; Settings=@('device_vendor_msft_policy_config_admx_terminalserver_ts_password','device_vendor_msft_policy_config_remotedesktopservices_clientconnectionencryptionlevel_promptforpassworduponconnection'); Expected=1; Op='eq' }
    @{ Id='4.11.36.4.9.2'; Sec='RDS Security'; Name='Require secure RPC communication'; Settings=@('device_vendor_msft_policy_config_admx_terminalserver_ts_rpc_encryption','device_vendor_msft_policy_config_remotedesktopservices_requiresecurerpccommunication'); Expected=1; Op='eq' }
    @{ Id='4.11.36.4.9.3'; Sec='RDS Security'; Name='Require specific security layer - SSL'; Settings=@('device_vendor_msft_policy_config_admx_terminalserver_ts_securitylayer','device_vendor_msft_policy_config_remotedesktopservices_securitylayer'); Expected=2; Op='eq' }
    @{ Id='4.11.36.4.9.4'; Sec='RDS Security'; Name='Require NLA for remote connections'; Settings=@('device_vendor_msft_policy_config_admx_terminalserver_ts_user_authentication_policy','device_vendor_msft_policy_config_remotedesktopservices_requirenlaauthentication'); Expected=1; Op='eq' }
    @{ Id='4.11.36.4.9.5'; Sec='RDS Security'; Name='Set client connection encryption level - High'; Settings=@('device_vendor_msft_policy_config_admx_terminalserver_ts_encryption_level','device_vendor_msft_policy_config_remotedesktopservices_clientconnectionencryptionlevel'); Expected=3; Op='eq' }
    @{ Id='4.11.36.4.11.1'; Sec='RDS Temp'; Name='Do not delete temp folders upon exit - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_terminalserver_ts_notempdirsonexit'); Expected=0; Op='eq' }

    # RSS Feeds
    @{ Id='4.11.37.1'; Sec='RSS Feeds'; Name='Prevent downloading of enclosures'; Settings=@('device_vendor_msft_policy_config_admx_rss_disableenclosuredownload'); Expected=1; Op='eq' }

    # Store
    @{ Id='4.11.42.1'; Sec='Store'; Name='Turn off offer to update to latest version of Windows'; Settings=@('device_vendor_msft_policy_config_admx_store_disableosupgrade'); Expected=1; Op='eq' }

    # Windows Logon Options
    @{ Id='4.11.50.1'; Sec='Logon Options'; Name='Enable MPR notifications for the system - Disabled'; Settings=@('device_vendor_msft_policy_config_windowslogon_enablemprnotifications'); Expected=0; Op='eq' }
    @{ Id='4.11.50.2'; Sec='Logon Options'; Name='Sign-in and lock last interactive user automatically after restart - Disabled'; Settings=@('device_vendor_msft_policy_config_windowslogon_signinandlocklastinteractiveuser','device_vendor_msft_policy_config_admx_winlogon_automaticrestartsignon'); Expected=0; Op='eq' }

    # WinRM Client
    @{ Id='4.11.55.1.1'; Sec='WinRM Client'; Name='Allow Basic authentication - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_winrm_allowbasic_1','device_vendor_msft_policy_config_remotemanagement_allowbasicauthentication_client'); Expected=0; Op='eq' }
    @{ Id='4.11.55.1.2'; Sec='WinRM Client'; Name='Allow unencrypted traffic - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_winrm_allowunencrypted_1','device_vendor_msft_policy_config_remotemanagement_allowunencryptedtraffic_client'); Expected=0; Op='eq' }
    @{ Id='4.11.55.1.3'; Sec='WinRM Client'; Name='Disallow Digest authentication'; Settings=@('device_vendor_msft_policy_config_admx_winrm_disallowdigest','device_vendor_msft_policy_config_remotemanagement_disallowdigestauthentication'); Expected=1; Op='eq' }

    # WinRM Service
    @{ Id='4.11.55.2.1'; Sec='WinRM Service'; Name='Allow Basic authentication - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_winrm_allowbasic_2','device_vendor_msft_policy_config_remotemanagement_allowbasicauthentication_service'); Expected=0; Op='eq' }
    @{ Id='4.11.55.2.3'; Sec='WinRM Service'; Name='Allow unencrypted traffic - Disabled'; Settings=@('device_vendor_msft_policy_config_admx_winrm_allowunencrypted_2','device_vendor_msft_policy_config_remotemanagement_allowunencryptedtraffic_service'); Expected=0; Op='eq' }
    @{ Id='4.11.55.2.4'; Sec='WinRM Service'; Name='Disallow WinRM from storing RunAs credentials'; Settings=@('device_vendor_msft_policy_config_admx_winrm_disallowrunascredentials','device_vendor_msft_policy_config_remotemanagement_disallowstoringofrunascredentials'); Expected=1; Op='eq' }
)

$script:CISChecks += @(
    # ── Section 6: Auditing ──
    @{ Id='6.1'; Sec='Auditing'; Name='Audit Credential Validation - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_accountlogon_auditcredentialvalidation'); Expected=3; Op='eq' }
    @{ Id='6.2'; Sec='Auditing'; Name='Audit Account Lockout - includes Failure'; Settings=@('device_vendor_msft_policy_config_audit_accountlogonlogoff_auditaccountlockout'); Expected=2; Op='bitmask' }
    @{ Id='6.3'; Sec='Auditing'; Name='Audit Group Membership - includes Success'; Settings=@('device_vendor_msft_policy_config_audit_accountlogonlogoff_auditgroupmembership'); Expected=1; Op='bitmask' }
    @{ Id='6.4'; Sec='Auditing'; Name='Audit Logoff - includes Success'; Settings=@('device_vendor_msft_policy_config_audit_accountlogonlogoff_auditlogoff'); Expected=1; Op='bitmask' }
    @{ Id='6.5'; Sec='Auditing'; Name='Audit Logon - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_accountlogonlogoff_auditlogon'); Expected=3; Op='eq' }
    @{ Id='6.6'; Sec='Auditing'; Name='Audit Application Group Management - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_accountmanagement_auditapplicationgroupmanagement'); Expected=3; Op='eq' }
    @{ Id='6.7'; Sec='Auditing'; Name='Audit Authentication Policy Change - includes Success'; Settings=@('device_vendor_msft_policy_config_audit_policychange_auditauthenticationpolicychange'); Expected=1; Op='bitmask' }
    @{ Id='6.8'; Sec='Auditing'; Name='Audit Authorization Policy Change - includes Success'; Settings=@('device_vendor_msft_policy_config_audit_policychange_auditauthorizationpolicychange'); Expected=1; Op='bitmask' }
    @{ Id='6.9'; Sec='Auditing'; Name='Audit Changes to Audit Policy - includes Success'; Settings=@('device_vendor_msft_policy_config_audit_policychange_auditpolicychange'); Expected=1; Op='bitmask' }
    @{ Id='6.10'; Sec='Auditing'; Name='Audit File Share Access - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_objectaccess_auditfileshare'); Expected=3; Op='eq' }
    @{ Id='6.11'; Sec='Auditing'; Name='Audit Other Logon Logoff Events - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_accountlogonlogoff_auditotherlogonlogoffevents'); Expected=3; Op='eq' }
    @{ Id='6.12'; Sec='Auditing'; Name='Audit Security Group Management - includes Success'; Settings=@('device_vendor_msft_policy_config_audit_accountmanagement_auditsecuritygroupmanagement'); Expected=1; Op='bitmask' }
    @{ Id='6.13'; Sec='Auditing'; Name='Audit Security System Extension - includes Success'; Settings=@('device_vendor_msft_policy_config_audit_system_auditsecuritysystemextension'); Expected=1; Op='bitmask' }
    @{ Id='6.14'; Sec='Auditing'; Name='Audit Special Logon - includes Success'; Settings=@('device_vendor_msft_policy_config_audit_accountlogonlogoff_auditspeciallogon'); Expected=1; Op='bitmask' }
    @{ Id='6.15'; Sec='Auditing'; Name='Audit User Account Management - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_accountmanagement_audituseraccountmanagement'); Expected=3; Op='eq' }
    @{ Id='6.16'; Sec='Auditing'; Name='Audit PNP Activity - includes Success'; Settings=@('device_vendor_msft_policy_config_audit_detailedtracking_auditpnpactivity'); Expected=1; Op='bitmask' }
    @{ Id='6.17'; Sec='Auditing'; Name='Audit Process Creation - includes Success'; Settings=@('device_vendor_msft_policy_config_audit_detailedtracking_auditprocesscreation'); Expected=1; Op='bitmask' }
    @{ Id='6.18'; Sec='Auditing'; Name='Audit Detailed File Share - includes Failure'; Settings=@('device_vendor_msft_policy_config_audit_objectaccess_auditdetailedfileshare'); Expected=2; Op='bitmask' }
    @{ Id='6.19'; Sec='Auditing'; Name='Audit Other Object Access Events - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_objectaccess_auditotherobjectaccessevents'); Expected=3; Op='eq' }
    @{ Id='6.20'; Sec='Auditing'; Name='Audit Removable Storage - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_objectaccess_auditremovablestorage'); Expected=3; Op='eq' }
    @{ Id='6.21'; Sec='Auditing'; Name='Audit MPSSVC Rule Level Policy Change - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_policychange_auditmpssvcrulelevelpolicychange'); Expected=3; Op='eq' }
    @{ Id='6.22'; Sec='Auditing'; Name='Audit Other Policy Change Events - includes Failure'; Settings=@('device_vendor_msft_policy_config_audit_policychange_auditotherpolicychangeevents'); Expected=2; Op='bitmask' }
    @{ Id='6.23'; Sec='Auditing'; Name='Audit Sensitive Privilege Use - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_privilegeuse_auditsensitiveprivilegeuse'); Expected=3; Op='eq' }
    @{ Id='6.24'; Sec='Auditing'; Name='Audit IPsec Driver - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_system_auditipsecdriver'); Expected=3; Op='eq' }
    @{ Id='6.25'; Sec='Auditing'; Name='Audit Other System Events - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_system_auditothersystemevents'); Expected=3; Op='eq' }
    @{ Id='6.26'; Sec='Auditing'; Name='Audit Security State Change - includes Success'; Settings=@('device_vendor_msft_policy_config_audit_system_auditsecuritystatechange'); Expected=1; Op='bitmask' }
    @{ Id='6.27'; Sec='Auditing'; Name='Audit System Integrity - Success and Failure'; Settings=@('device_vendor_msft_policy_config_audit_system_auditsystemintegrity'); Expected=3; Op='eq' }

    # ── Section 15: Config Refresh ──
    @{ Id='15.1'; Sec='Config Refresh'; Name='Config Refresh - Enabled'; Settings=@('device_vendor_msft_policy_config_configrefresh_enabled','device_vendor_msft_policy_config_dmclient_provider_configrefresh_enabled'); Expected=1; Op='eq' }
    @{ Id='15.2'; Sec='Config Refresh'; Name='Refresh cadence - 90 minutes or less'; Settings=@('device_vendor_msft_policy_config_configrefresh_cadence','device_vendor_msft_policy_config_dmclient_provider_configrefresh_cadence'); Expected=90; Op='le' }
)

$script:CISChecks += @(
    # ── Section 22: Defender ──
    @{ Id='22.1'; Sec='Defender'; Name='Allow Behavior Monitoring - Allowed'; Settings=@('device_vendor_msft_policy_config_defender_allowbehaviormonitoring'); Expected=1; Op='eq' }
    @{ Id='22.2'; Sec='Defender'; Name='Allow Email Scanning - Allowed'; Settings=@('device_vendor_msft_policy_config_defender_allowemailscanning'); Expected=1; Op='eq' }
    @{ Id='22.3'; Sec='Defender'; Name='Allow Full Scan Removable Drive Scanning - Allowed'; Settings=@('device_vendor_msft_policy_config_defender_allowfullscanremovabledrivescanning'); Expected=1; Op='eq' }
    @{ Id='22.4'; Sec='Defender'; Name='Allow Realtime Monitoring - Allowed'; Settings=@('device_vendor_msft_policy_config_defender_allowrealtimemonitoring'); Expected=1; Op='eq' }
    @{ Id='22.5'; Sec='Defender'; Name='Allow scanning of all downloaded files and attachments - Allowed'; Settings=@('device_vendor_msft_policy_config_defender_allowioavprotection'); Expected=1; Op='eq' }
    @{ Id='22.6'; Sec='Defender'; Name='Allow Script Scanning - Allowed'; Settings=@('device_vendor_msft_policy_config_defender_allowscriptscanning'); Expected=1; Op='eq' }
    @{ Id='22.7'; Sec='Defender'; Name='ASR: Block abuse of exploited vulnerable signed drivers'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers'); Expected='block'; Op='eq' }
    @{ Id='22.8'; Sec='Defender'; Name='ASR: Block Adobe Reader from creating child processes'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses'); Expected='block'; Op='eq' }
    @{ Id='22.9'; Sec='Defender'; Name='ASR: Block all Office apps from creating child processes'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses'); Expected='audit'; Op='ge_asr' }
    @{ Id='22.10'; Sec='Defender'; Name='ASR: Block credential stealing from LSASS'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem'); Expected='block'; Op='eq' }
    @{ Id='22.11'; Sec='Defender'; Name='ASR: Block executable content from email client and webmail'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail'); Expected='block'; Op='eq' }
    @{ Id='22.12'; Sec='Defender'; Name='ASR: Block executable files unless they meet prevalence/age/trusted list'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablefilesunlesstheymeetprevalenceagetrustedlistcriterion'); Expected='audit'; Op='ge_asr' }
    @{ Id='22.13'; Sec='Defender'; Name='ASR: Block execution of potentially obfuscated scripts'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts'); Expected='audit'; Op='ge_asr' }
    @{ Id='22.14'; Sec='Defender'; Name='ASR: Block JavaScript or VBScript from launching downloaded executable content'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent'); Expected='block'; Op='eq' }
    @{ Id='22.15'; Sec='Defender'; Name='ASR: Block Office apps from creating executable content'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent'); Expected='block'; Op='eq' }
    @{ Id='22.16'; Sec='Defender'; Name='ASR: Block Office apps from injecting code into other processes'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingchildprocesses_injectingcode'); Expected='block'; Op='eq' }
    @{ Id='22.17'; Sec='Defender'; Name='ASR: Block Office communication app from creating child processes'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficecommunicationappfromcreatingchildprocesses'); Expected='audit'; Op='ge_asr' }
    @{ Id='22.18'; Sec='Defender'; Name='ASR: Block persistence through WMI event subscription'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockpersistencethroughwmieventsubscription'); Expected='block'; Op='eq' }
    @{ Id='22.19'; Sec='Defender'; Name='ASR: Block process creations from PSExec and WMI commands'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockprocesscreationsfrompsexecandwmicommands'); Expected='audit'; Op='ge_asr' }
    @{ Id='22.20'; Sec='Defender'; Name='ASR: Block untrusted and unsigned processes that run from USB'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuntrustedandunsignedprocessesthatrunfromusb'); Expected='block'; Op='eq' }
    @{ Id='22.21'; Sec='Defender'; Name='ASR: Block Win32 API calls from Office macros'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros'); Expected='block'; Op='eq' }
    @{ Id='22.22'; Sec='Defender'; Name='ASR: Use advanced protection against ransomware'; Settings=@('device_vendor_msft_policy_config_defender_attacksurfacereductionrules_useadvancedprotectionagainstransomware'); Expected='audit'; Op='ge_asr' }
    @{ Id='22.23'; Sec='Defender'; Name='Days Until Aggressive Catchup Quick Scan - 7 or fewer'; Settings=@('device_vendor_msft_policy_config_defender_daysuntilaggressivecatchupquickscan'); Expected=7; Op='le' }
    @{ Id='22.26'; Sec='Defender'; Name='Enable Network Protection - Block mode'; Settings=@('device_vendor_msft_policy_config_defender_enablenetworkprotection'); Expected=1; Op='eq' }
    @{ Id='22.27'; Sec='Defender'; Name='Hide Exclusions From Local Users - Enabled'; Settings=@('device_vendor_msft_policy_config_defender_hideexclusionsfromlocalusers'); Expected=1; Op='eq' }
    @{ Id='22.28'; Sec='Defender'; Name='Oobe Enable Rtp And Sig Update - Enabled'; Settings=@('device_vendor_msft_policy_config_defender_oobeenablertpandsigupdate'); Expected=1; Op='eq' }
    @{ Id='22.29'; Sec='Defender'; Name='PUA Protection - PUA Protection on'; Settings=@('device_vendor_msft_policy_config_defender_puaprotection'); Expected=1; Op='eq' }
    @{ Id='22.30'; Sec='Defender'; Name='Quick Scan Include Exclusions - 1'; Settings=@('device_vendor_msft_policy_config_defender_quickscanincludeexclusions'); Expected=1; Op='eq' }
    @{ Id='22.32'; Sec='Defender'; Name='Remote Encryption Protection - Audit or higher'; Settings=@('device_vendor_msft_policy_config_defender_remoteencryptionprotectionconfiguredstate'); Expected=2; Op='ge' }
)

$script:CISChecks += @(
    # ── Section 23: Delivery Optimization ──
    @{ Id='23.1'; Sec='Delivery Optimization'; Name='DO Download Mode - NOT Internet Peering (3)'; Settings=@('device_vendor_msft_policy_config_deliveryoptimization_dodownloadmode'); Expected=3; Op='ne' }

    # ── Section 24: Device Guard ──
    @{ Id='24.1'; Sec='Device Guard'; Name='Configure System Guard Launch'; Settings=@('device_vendor_msft_policy_config_deviceguard_configuresystemguardlaunch'); Expected=1; Op='eq' }
    @{ Id='24.2'; Sec='Device Guard'; Name='Credential Guard - Enabled with UEFI lock'; Settings=@('device_vendor_msft_policy_config_deviceguard_lsacfgflags'); Expected=1; Op='eq' }
    @{ Id='24.3'; Sec='Device Guard'; Name='Enable Virtualization Based Security'; Settings=@('device_vendor_msft_policy_config_deviceguard_enablevirtualizationbasedsecurity'); Expected=1; Op='eq' }
    @{ Id='24.4'; Sec='Device Guard'; Name='Require Platform Security Features - Secure Boot or higher'; Settings=@('device_vendor_msft_policy_config_deviceguard_requireplatformsecurityfeatures'); Expected=1; Op='ge' }

    # ── Section 26: Device Lock ──
    @{ Id='26.1'; Sec='Device Lock'; Name='Device Password Enabled'; Settings=@('device_vendor_msft_policy_config_devicelock_devicepasswordenabled'); Expected=0; Op='eq' }
    @{ Id='26.2'; Sec='Device Lock'; Name='Alphanumeric Device Password Required'; Settings=@('device_vendor_msft_policy_config_devicelock_alphanumericdevicepasswordrequired'); Expected=0; Op='eq' }
    @{ Id='26.3'; Sec='Device Lock'; Name='Min Device Password Complex Characters'; Settings=@('device_vendor_msft_policy_config_devicelock_mindevicepasswordcomplexcharacters'); Expected=2; Op='ge' }
    @{ Id='26.4'; Sec='Device Lock'; Name='Device Password Expiration - 365 or fewer (not 0)'; Settings=@('device_vendor_msft_policy_config_devicelock_devicepasswordexpiration'); Expected=365; Op='le_nz' }
    @{ Id='26.5'; Sec='Device Lock'; Name='Device Password History - 24 or more'; Settings=@('device_vendor_msft_policy_config_devicelock_devicepasswordhistory'); Expected=24; Op='ge' }
    @{ Id='26.6'; Sec='Device Lock'; Name='Max Failed Attempts - 5 or fewer (not 0)'; Settings=@('device_vendor_msft_policy_config_devicelock_maxdevicepasswordfailedattempts'); Expected=5; Op='le_nz' }
    @{ Id='26.7'; Sec='Device Lock'; Name='Max Inactivity Time Device Lock - 15 or fewer (not 0)'; Settings=@('device_vendor_msft_policy_config_devicelock_maxinactivitytimedevicelock'); Expected=15; Op='le_nz' }
    @{ Id='26.8'; Sec='Device Lock'; Name='Min Device Password Length - 14 or more'; Settings=@('device_vendor_msft_policy_config_devicelock_mindevicepasswordlength'); Expected=14; Op='ge' }
    @{ Id='26.9'; Sec='Device Lock'; Name='Minimum Password Age - 1 or more day(s)'; Settings=@('device_vendor_msft_policy_config_devicelock_minimumpasswordage'); Expected=1; Op='ge' }

    # ── Section 34: Experience ──
    @{ Id='34.1'; Sec='Experience'; Name='Allow Cortana - Block'; Settings=@('device_vendor_msft_policy_config_experience_allowcortana'); Expected=0; Op='eq' }
    @{ Id='34.2'; Sec='Experience'; Name='Allow Spotlight Collection (User) - 0'; Settings=@('user_vendor_msft_policy_config_experience_allowspotlightcollection','device_vendor_msft_policy_config_experience_allowwindowsspotlight'); Expected=0; Op='eq' }
    @{ Id='34.4'; Sec='Experience'; Name='Disable Consumer Account State Content - Enabled'; Settings=@('device_vendor_msft_policy_config_experience_disableconsumeraccountstatecontent'); Expected=1; Op='eq' }
    @{ Id='34.5'; Sec='Experience'; Name='Do not show feedback notifications - Disabled'; Settings=@('device_vendor_msft_policy_config_experience_donotshowfeedbacknotifications'); Expected=1; Op='eq' }

    # ── Section 38: Firewall ──
    # Domain
    @{ Id='38.1'; Sec='Firewall'; Name='Enable Domain Network Firewall'; Settings=@('device_vendor_msft_firewall_mdmstore_domainprofile_enablefirewall'); Expected='true'; Op='eq_bool' }
    @{ Id='38.2'; Sec='Firewall'; Name='Domain: Default Inbound Action - Block'; Settings=@('device_vendor_msft_firewall_mdmstore_domainprofile_defaultinboundaction'); Expected=1; Op='eq' }
    @{ Id='38.3'; Sec='Firewall'; Name='Domain: Disable Inbound Notifications'; Settings=@('device_vendor_msft_firewall_mdmstore_domainprofile_disableinboundnotifications'); Expected='true'; Op='eq_bool' }
    @{ Id='38.4'; Sec='Firewall'; Name='Domain: Enable Log Dropped Packets'; Settings=@('device_vendor_msft_firewall_mdmstore_domainprofile_enablelogdroppedpackets'); Expected='true'; Op='eq_bool' }
    @{ Id='38.5'; Sec='Firewall'; Name='Domain: Enable Log Success Connections'; Settings=@('device_vendor_msft_firewall_mdmstore_domainprofile_enablelogsuccessconnections'); Expected='true'; Op='eq_bool' }
    @{ Id='38.6'; Sec='Firewall'; Name='Domain: Log File Path'; Settings=@('device_vendor_msft_firewall_mdmstore_domainprofile_logfilepath'); Expected='%SystemRoot%\System32\logfiles\firewall\domainfw.log'; Op='eq_str' }
    @{ Id='38.7'; Sec='Firewall'; Name='Domain: Log Max File Size >= 16384 KB'; Settings=@('device_vendor_msft_firewall_mdmstore_domainprofile_logmaxfilesize'); Expected=16384; Op='ge' }
    # Private
    @{ Id='38.8'; Sec='Firewall'; Name='Enable Private Network Firewall'; Settings=@('device_vendor_msft_firewall_mdmstore_privateprofile_enablefirewall'); Expected='true'; Op='eq_bool' }
    @{ Id='38.9'; Sec='Firewall'; Name='Private: Default Inbound Action - Block'; Settings=@('device_vendor_msft_firewall_mdmstore_privateprofile_defaultinboundaction'); Expected=1; Op='eq' }
    @{ Id='38.10'; Sec='Firewall'; Name='Private: Disable Inbound Notifications'; Settings=@('device_vendor_msft_firewall_mdmstore_privateprofile_disableinboundnotifications'); Expected='true'; Op='eq_bool' }
    @{ Id='38.11'; Sec='Firewall'; Name='Private: Enable Log Success Connections'; Settings=@('device_vendor_msft_firewall_mdmstore_privateprofile_enablelogsuccessconnections'); Expected='true'; Op='eq_bool' }
    @{ Id='38.12'; Sec='Firewall'; Name='Private: Enable Log Dropped Packets'; Settings=@('device_vendor_msft_firewall_mdmstore_privateprofile_enablelogdroppedpackets'); Expected='true'; Op='eq_bool' }
    @{ Id='38.13'; Sec='Firewall'; Name='Private: Log File Path'; Settings=@('device_vendor_msft_firewall_mdmstore_privateprofile_logfilepath'); Expected='%SystemRoot%\System32\logfiles\firewall\privatefw.log'; Op='eq_str' }
    @{ Id='38.14'; Sec='Firewall'; Name='Private: Log Max File Size >= 16384 KB'; Settings=@('device_vendor_msft_firewall_mdmstore_privateprofile_logmaxfilesize'); Expected=16384; Op='ge' }
    # Public
    @{ Id='38.15'; Sec='Firewall'; Name='Enable Public Network Firewall'; Settings=@('device_vendor_msft_firewall_mdmstore_publicprofile_enablefirewall'); Expected='true'; Op='eq_bool' }
    @{ Id='38.16'; Sec='Firewall'; Name='Public: Allow Local IPsec Policy Merge - False'; Settings=@('device_vendor_msft_firewall_mdmstore_publicprofile_allowlocalipsecpolicymerge'); Expected='false'; Op='eq_bool' }
    @{ Id='38.17'; Sec='Firewall'; Name='Public: Allow Local Policy Merge - False'; Settings=@('device_vendor_msft_firewall_mdmstore_publicprofile_allowlocalpolicymerge'); Expected='false'; Op='eq_bool' }
    @{ Id='38.18'; Sec='Firewall'; Name='Public: Default Inbound Action - Block'; Settings=@('device_vendor_msft_firewall_mdmstore_publicprofile_defaultinboundaction'); Expected=1; Op='eq' }
    @{ Id='38.19'; Sec='Firewall'; Name='Public: Disable Inbound Notifications'; Settings=@('device_vendor_msft_firewall_mdmstore_publicprofile_disableinboundnotifications'); Expected='true'; Op='eq_bool' }
    @{ Id='38.20'; Sec='Firewall'; Name='Public: Enable Log Dropped Packets'; Settings=@('device_vendor_msft_firewall_mdmstore_publicprofile_enablelogdroppedpackets'); Expected='true'; Op='eq_bool' }
    @{ Id='38.21'; Sec='Firewall'; Name='Public: Enable Log Success Connections'; Settings=@('device_vendor_msft_firewall_mdmstore_publicprofile_enablelogsuccessconnections'); Expected='true'; Op='eq_bool' }
    @{ Id='38.22'; Sec='Firewall'; Name='Public: Log File Path'; Settings=@('device_vendor_msft_firewall_mdmstore_publicprofile_logfilepath'); Expected='%SystemRoot%\System32\logfiles\firewall\publicfw.log'; Op='eq_str' }
    @{ Id='38.23'; Sec='Firewall'; Name='Public: Log Max File Size >= 16384 KB'; Settings=@('device_vendor_msft_firewall_mdmstore_publicprofile_logmaxfilesize'); Expected=16384; Op='ge' }

    # ── Section 46: Lanman Workstation ──
    @{ Id='46.1'; Sec='Lanman Workstation'; Name='Enable insecure guest logons - Disabled'; Settings=@('device_vendor_msft_policy_config_lanmanworkstation_enableinsecureguestlogons'); Expected=0; Op='eq' }
)

$script:CISChecks += @(
    # ── Section 49: Local Policies Security Options ──
    @{ Id='49.1'; Sec='Local Security'; Name='Guest account status - Disabled'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_enableguestaccountstatus'); Expected=0; Op='eq' }
    @{ Id='49.2'; Sec='Local Security'; Name='Limit blank passwords to console logon only'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_limitlocalaccountuseofblankpasswordstoconsolelogononly'); Expected=1; Op='eq' }
    @{ Id='49.3'; Sec='Local Security'; Name='Rename administrator account'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_renameadministratoraccount'); Expected='Administrator'; Op='ne_str' }
    @{ Id='49.4'; Sec='Local Security'; Name='Rename guest account'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_renameguestaccount'); Expected='Guest'; Op='ne_str' }
    @{ Id='49.6'; Sec='Local Security'; Name='Do not display last signed-in'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_donotdisplaylastsignedin'); Expected=1; Op='eq' }
    @{ Id='49.7'; Sec='Local Security'; Name='Do not require CTRL+ALT+DEL - Disabled'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_donotrequirectrlaltdel'); Expected=0; Op='eq' }
    @{ Id='49.8'; Sec='Local Security'; Name='Machine inactivity limit - 900 or fewer (not 0)'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_machineinactivitylimit'); Expected=900; Op='le_nz' }
    @{ Id='49.9'; Sec='Local Security'; Name='Message text for users attempting to log on (configured)'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_messagetextforusersattemptingtologon'); Expected=''; Op='not_empty' }
    @{ Id='49.10'; Sec='Local Security'; Name='Message title for users attempting to log on (configured)'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_messagetitleforusersattemptingtologon'); Expected=''; Op='not_empty' }
    @{ Id='49.11'; Sec='Local Security'; Name='Smart card removal behavior - Lock Workstation or higher'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_smartcardremovalbehavior'); Expected=1; Op='ge' }
    @{ Id='49.12'; Sec='Local Security'; Name='MS network client: Digitally sign communications (always)'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_digitallysigncommunicationsalways'); Expected=1; Op='eq' }
    @{ Id='49.13'; Sec='Local Security'; Name='MS network client: Digitally sign communications (if server agrees)'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_digitallysigncommunicationsifserveragrees'); Expected=1; Op='eq' }
    @{ Id='49.14'; Sec='Local Security'; Name='MS network client: Send unencrypted password to SMB servers - Disabled'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_sendunencryptedpasswordtothirdpartysmbservers'); Expected=0; Op='eq' }
    @{ Id='49.15'; Sec='Local Security'; Name='MS network server: Digitally sign communications (always)'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkserver_digitallysigncommunicationsalways'); Expected=1; Op='eq' }
    @{ Id='49.16'; Sec='Local Security'; Name='MS network server: Digitally sign communications (if client agrees)'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkserver_digitallysigncommunicationsifclientagrees'); Expected=1; Op='eq' }
    @{ Id='49.17'; Sec='Local Security'; Name='Do not allow anonymous enumeration of SAM accounts'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_donotallowanonymousenumerationofsamaccounts'); Expected=1; Op='eq' }
    @{ Id='49.18'; Sec='Local Security'; Name='Do not allow anonymous enumeration of SAM accounts and shares'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_donotallowanonymousenumerationofsamaccountsandshares'); Expected=1; Op='eq' }
    @{ Id='49.19'; Sec='Local Security'; Name='Restrict anonymous access to Named Pipes and Shares'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_restrictanonymousaccesstonamedpipesandshares'); Expected=1; Op='eq' }
    @{ Id='49.20'; Sec='Local Security'; Name='Restrict clients allowed to make remote calls to SAM'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_restrictclientsallowedtomakeremotecallstosam'); Expected='O:BAG:BAD:(A;;RC;;;BA)'; Op='contains' }
    @{ Id='49.21'; Sec='Local Security'; Name='Allow Local System to use computer identity for NTLM'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_allowlocalsystemtousecomputeridentityforntlm'); Expected=1; Op='eq' }
    @{ Id='49.22'; Sec='Local Security'; Name='Allow PKU2U authentication requests - Block'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_allowpku2uauthenticationrequests'); Expected=0; Op='eq' }
    @{ Id='49.23'; Sec='Local Security'; Name='Do not store LAN Manager hash value on next password change'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_donotstorelanmanagerhashvalueonnextpasswordchange'); Expected=1; Op='eq' }
    @{ Id='49.24'; Sec='Local Security'; Name='LAN Manager authentication level - NTLMv2 only, refuse LM and NTLM'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_lanmanagerauthenticationlevel'); Expected=5; Op='eq' }
    @{ Id='49.25'; Sec='Local Security'; Name='Min Session Security For NTLMSSP Clients'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_minimumsessionsecurityforntlmsspbasedclients'); Expected=537395200; Op='eq' }
    @{ Id='49.26'; Sec='Local Security'; Name='Min Session Security For NTLMSSP Servers'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_minimumsessionsecurityforntlmsspbasedservers'); Expected=537395200; Op='eq' }
    @{ Id='49.27'; Sec='Local Security'; Name='Restrict NTLM: Audit Incoming NTLM Traffic'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_restrictntlm_auditincomingntlmtraffic'); Expected=2; Op='eq' }
    @{ Id='49.28'; Sec='Local Security'; Name='UAC: Behavior of elevation prompt for administrators'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_behavioroftheelevationpromptforadministrators'); Expected=2; Op='le' }
    @{ Id='49.29'; Sec='Local Security'; Name='UAC: Behavior of elevation prompt for standard users - Auto deny'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_behavioroftheelevationpromptforstandardusers'); Expected=0; Op='eq' }
    @{ Id='49.30'; Sec='Local Security'; Name='UAC: Detect application installations and prompt for elevation'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_detectapplicationinstallationsandpromptforelevation'); Expected=1; Op='eq' }
    @{ Id='49.31'; Sec='Local Security'; Name='UAC: Only elevate UIAccess apps installed in secure locations'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_onlyelevateui'); Expected=1; Op='eq' }
    @{ Id='49.32'; Sec='Local Security'; Name='UAC: Use Admin Approval Mode'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_useadminapprovalmode'); Expected=1; Op='eq' }
    @{ Id='49.33'; Sec='Local Security'; Name='UAC: Switch to secure desktop when prompting for elevation'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_switchtothesecuredesktopwhenpromptingforelevation'); Expected=1; Op='eq' }
    @{ Id='49.34'; Sec='Local Security'; Name='UAC: Run all administrators in Admin Approval Mode'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_runalladministratorsinadminapprovalmode'); Expected=1; Op='eq' }
    @{ Id='49.35'; Sec='Local Security'; Name='UAC: Virtualize file and registry write failures'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_virtualizefileandregistrywritefailurestoperuserlocations'); Expected=1; Op='eq' }

    # ── Section 50: Local Security Authority ──
    @{ Id='50.1'; Sec='LSA'; Name='Configure Lsa Protected Process - Enabled with UEFI Lock'; Settings=@('device_vendor_msft_policy_config_localsecurityauthority_configurelsaprotectedprocess'); Expected=1; Op='eq' }

    # ── Section 55: Microsoft App Store ──
    @{ Id='55.1'; Sec='App Store'; Name='Allow apps from MS app store to auto update'; Settings=@('device_vendor_msft_policy_config_applicationmanagement_allowappstoreautoupdate'); Expected=1; Op='eq' }
    @{ Id='55.4'; Sec='App Store'; Name='Block Non Admin User Install'; Settings=@('device_vendor_msft_policy_config_applicationmanagement_blocknonadminuserinstall'); Expected=1; Op='eq' }
    @{ Id='55.6'; Sec='App Store'; Name='MSI Allow user control over installs - Disabled'; Settings=@('device_vendor_msft_policy_config_applicationmanagement_msiallowusercontroloverinstall'); Expected=0; Op='eq' }
    @{ Id='55.7'; Sec='App Store'; Name='MSI Always install with elevated privileges - Disabled'; Settings=@('device_vendor_msft_policy_config_applicationmanagement_msialwaysinstallwithelevatedprivileges'); Expected=0; Op='eq' }
    @{ Id='55.8'; Sec='App Store'; Name='MSI Always install with elevated privileges (User) - Disabled'; Settings=@('user_vendor_msft_policy_config_applicationmanagement_msialwaysinstallwithelevatedprivileges'); Expected=0; Op='eq' }
)

$script:CISChecks += @(
    # ── Section 68: Privacy ──
    @{ Id='68.2'; Sec='Privacy'; Name='Allow Input Personalization - Block'; Settings=@('device_vendor_msft_policy_config_privacy_allowinputpersonalization'); Expected=0; Op='eq' }
    @{ Id='68.4'; Sec='Privacy'; Name='Let Apps Activate With Voice Above Lock - Force Deny'; Settings=@('device_vendor_msft_policy_config_privacy_letappsactivatewithvoiceabovelock'); Expected=2; Op='eq' }
    @{ Id='68.5'; Sec='Privacy'; Name='Upload User Activities - Disabled'; Settings=@('device_vendor_msft_policy_config_privacy_uploaduseractivities'); Expected=0; Op='eq' }

    # ── Section 72: Search ──
    @{ Id='72.2'; Sec='Search'; Name='Allow Indexing Encrypted Stores Or Items - Block'; Settings=@('device_vendor_msft_policy_config_search_allowindexingencryptedstoresoritems'); Expected=0; Op='eq' }
    @{ Id='72.3'; Sec='Search'; Name='Allow Search To Use Location - Block'; Settings=@('device_vendor_msft_policy_config_search_allowsearchtouselocation'); Expected=0; Op='eq' }

    # ── Section 76: Smart Screen - Enhanced Phishing Protection ──
    @{ Id='76.1.1'; Sec='SmartScreen'; Name='Notify Malicious - Enabled'; Settings=@('device_vendor_msft_policy_config_webthreatdefense_notifymalicious'); Expected=1; Op='eq' }
    @{ Id='76.1.2'; Sec='SmartScreen'; Name='Notify Password Reuse - Enabled'; Settings=@('device_vendor_msft_policy_config_webthreatdefense_notifypasswordreuse'); Expected=1; Op='eq' }
    @{ Id='76.1.3'; Sec='SmartScreen'; Name='Notify Unsafe App - Enabled'; Settings=@('device_vendor_msft_policy_config_webthreatdefense_notifyunsafeapp'); Expected=1; Op='eq' }
    @{ Id='76.1.4'; Sec='SmartScreen'; Name='Service Enabled - Enabled'; Settings=@('device_vendor_msft_policy_config_webthreatdefense_serviceenabled'); Expected=1; Op='eq' }

    # ── Section 79: Sudo ──
    @{ Id='79.1'; Sec='Sudo'; Name='Enable Sudo - Disabled'; Settings=@('device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_enablesudo'); Expected=0; Op='eq' }

    # ── Section 80: System (Telemetry) ──
    @{ Id='80.3'; Sec='System'; Name='Allow Telemetry - Basic (1)'; Settings=@('device_vendor_msft_policy_config_system_allowtelemetry'); Expected=1; Op='le' }
    @{ Id='80.6'; Sec='System'; Name='Enable OneSettings Auditing'; Settings=@('device_vendor_msft_policy_config_system_enableonesettingsauditing'); Expected=1; Op='eq' }
    @{ Id='80.7'; Sec='System'; Name='Limit Diagnostic Log Collection'; Settings=@('device_vendor_msft_policy_config_system_limitdiagnosticlogcollection'); Expected=1; Op='eq' }
    @{ Id='80.8'; Sec='System'; Name='Limit Dump Collection'; Settings=@('device_vendor_msft_policy_config_system_limitdumpcollection'); Expected=1; Op='eq' }

    # ── Section 81: System Services ──
    @{ Id='81.3'; Sec='System Services'; Name='Computer Browser (Browser) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configurebrowserservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.7'; Sec='System Services'; Name='IIS Admin Service (IISADMIN) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configureiisadminservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.8'; Sec='System Services'; Name='Infrared monitor service (irmon) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configureirmonservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.10'; Sec='System Services'; Name='LxssManager - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configurelxssmanagerservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.11'; Sec='System Services'; Name='Microsoft FTP Service (FTPSVC) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configureftpsvcservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.13'; Sec='System Services'; Name='OpenSSH SSH Server (sshd) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configuresshservicestartupmode','device_vendor_msft_policy_config_systemservices_configuresshdservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.20'; Sec='System Services'; Name='RPC Locator (RpcLocator) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configurerpclocatorservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.22'; Sec='System Services'; Name='Routing and Remote Access (RemoteAccess) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configureremoteaccessservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.24'; Sec='System Services'; Name='Simple TCP/IP Services (simptcp) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configuresimptcpservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.26'; Sec='System Services'; Name='Special Admin Console Helper (sacsvr) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configuresacsvrservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.27'; Sec='System Services'; Name='SSDP Discovery (SSDPSRV) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configuressdpsrvservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.28'; Sec='System Services'; Name='UPnP Device Host (upnphost) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configureupnphostservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.29'; Sec='System Services'; Name='Web Management Service (WMSvc) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configurewmsvcservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.32'; Sec='System Services'; Name='Windows Media Player Network Sharing (WMPNetworkSvc) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configurewmpnetworksvcservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.33'; Sec='System Services'; Name='Windows Mobile Hotspot Service (icssvc) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configureicssvcservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.38'; Sec='System Services'; Name='World Wide Web Publishing Service (W3SVC) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configurew3svcservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.39'; Sec='System Services'; Name='Xbox Accessory Management (XboxGipSvc) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configurexboxgipsvcservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.40'; Sec='System Services'; Name='Xbox Live Auth Manager (XblAuthManager) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configurexblauthmanagerservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.41'; Sec='System Services'; Name='Xbox Live Game Save (XblGameSave) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configurexblgamesaveservicestartupmode'); Expected=4; Op='eq' }
    @{ Id='81.42'; Sec='System Services'; Name='Xbox Live Networking (XboxNetApiSvc) - Disabled'; Settings=@('device_vendor_msft_policy_config_systemservices_configurexboxnetapisvcservicestartupmode'); Expected=4; Op='eq' }
)

$script:CISChecks += @(
    # ── Section 89: User Rights ──
    @{ Id='89.1'; Sec='User Rights'; Name='Access Credential Manager As Trusted Caller - No One'; Settings=@('device_vendor_msft_policy_config_userrights_accesscredentialmanagerastrustedcaller'); Expected=''; Op='empty_or_none' }
    @{ Id='89.2'; Sec='User Rights'; Name='Access From Network - Administrators, Remote Desktop Users'; Settings=@('device_vendor_msft_policy_config_userrights_accessfromnetwork'); Expected='Administrators,Remote Desktop Users'; Op='contains_all_list' }
    @{ Id='89.3'; Sec='User Rights'; Name='Act As Part Of The Operating System - No One'; Settings=@('device_vendor_msft_policy_config_userrights_actaspartoftheoperatingsystem'); Expected=''; Op='empty_or_none' }
    @{ Id='89.4'; Sec='User Rights'; Name='Allow Local Log On - Administrators, Users'; Settings=@('device_vendor_msft_policy_config_userrights_allowlocallogon'); Expected='Administrators,Users'; Op='contains_all_list' }
    @{ Id='89.5'; Sec='User Rights'; Name='Backup Files And Directories - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_backupfilesanddirectories'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.6'; Sec='User Rights'; Name='Change System Time - Administrators, LOCAL SERVICE'; Settings=@('device_vendor_msft_policy_config_userrights_changesystemtime'); Expected='Administrators,LOCAL SERVICE'; Op='contains_all_list' }
    @{ Id='89.7'; Sec='User Rights'; Name='Create Global Objects'; Settings=@('device_vendor_msft_policy_config_userrights_createglobalobjects'); Expected='Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE'; Op='contains_all_list' }
    @{ Id='89.8'; Sec='User Rights'; Name='Create Page File - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_createpagefile'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.9'; Sec='User Rights'; Name='Create Permanent Shared Objects - No One'; Settings=@('device_vendor_msft_policy_config_userrights_createpermanentsharedobjects'); Expected=''; Op='empty_or_none' }
    @{ Id='89.10'; Sec='User Rights'; Name='Create Symbolic Links - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_createsymboliclinks'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.11'; Sec='User Rights'; Name='Create Token - No One'; Settings=@('device_vendor_msft_policy_config_userrights_createtoken'); Expected=''; Op='empty_or_none' }
    @{ Id='89.12'; Sec='User Rights'; Name='Debug Programs - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_debugprograms'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.13'; Sec='User Rights'; Name='Deny Access From Network - includes Guests, Local account'; Settings=@('device_vendor_msft_policy_config_userrights_denyaccessfromnetwork'); Expected='Guests,Local account'; Op='contains_all_list' }
    @{ Id='89.14'; Sec='User Rights'; Name='Deny Local Log On - includes Guests'; Settings=@('device_vendor_msft_policy_config_userrights_denylocallogon'); Expected='Guests'; Op='contains_all_list' }
    @{ Id='89.15'; Sec='User Rights'; Name='Deny Log On As Batch Job - includes Guests'; Settings=@('device_vendor_msft_policy_config_userrights_denylogonasservice'); Expected='Guests'; Op='contains_all_list' }
    @{ Id='89.16'; Sec='User Rights'; Name='Deny Log On As Service Job - includes Guests'; Settings=@('device_vendor_msft_policy_config_userrights_denylogonasservice_service'); Expected='Guests'; Op='contains_all_list' }
    @{ Id='89.17'; Sec='User Rights'; Name='Deny Remote Desktop Services Log On - includes Guests, Local account'; Settings=@('device_vendor_msft_policy_config_userrights_denyremotedesktopserviceslogon'); Expected='Guests,Local account'; Op='contains_all_list' }
    @{ Id='89.18'; Sec='User Rights'; Name='Enable Delegation - No One'; Settings=@('device_vendor_msft_policy_config_userrights_enabledelegation'); Expected=''; Op='empty_or_none' }
    @{ Id='89.19'; Sec='User Rights'; Name='Generate Security Audits - LOCAL SERVICE, NETWORK SERVICE'; Settings=@('device_vendor_msft_policy_config_userrights_generatesecurityaudits'); Expected='LOCAL SERVICE,NETWORK SERVICE'; Op='contains_all_list' }
    @{ Id='89.20'; Sec='User Rights'; Name='Impersonate Client'; Settings=@('device_vendor_msft_policy_config_userrights_impersonateclient'); Expected='Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE'; Op='contains_all_list' }
    @{ Id='89.21'; Sec='User Rights'; Name='Increase Scheduling Priority - Administrators, Window Manager Group'; Settings=@('device_vendor_msft_policy_config_userrights_increaseschedulingpriority'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.22'; Sec='User Rights'; Name='Load Unload Device Drivers - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_loadunloaddevicedrivers'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.23'; Sec='User Rights'; Name='Lock Memory - No One'; Settings=@('device_vendor_msft_policy_config_userrights_lockmemory'); Expected=''; Op='empty_or_none' }
    @{ Id='89.25'; Sec='User Rights'; Name='Manage auditing and security log - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_manageauditingandsecuritylog'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.26'; Sec='User Rights'; Name='Manage Volume - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_managevolume'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.27'; Sec='User Rights'; Name='Modify Firmware Environment - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_modifyfirmwareenvironment'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.28'; Sec='User Rights'; Name='Modify Object Label - No One'; Settings=@('device_vendor_msft_policy_config_userrights_modifyobjectlabel'); Expected=''; Op='empty_or_none' }
    @{ Id='89.29'; Sec='User Rights'; Name='Profile Single Process - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_profilesingleprocess'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.30'; Sec='User Rights'; Name='Profile System Performance'; Settings=@('device_vendor_msft_policy_config_userrights_profilesystemperformance'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.31'; Sec='User Rights'; Name='Remote Shutdown - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_remoteshutdown'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.32'; Sec='User Rights'; Name='Replace Process Level Token - LOCAL SERVICE, NETWORK SERVICE'; Settings=@('device_vendor_msft_policy_config_userrights_replaceprocessleveltoken'); Expected='LOCAL SERVICE,NETWORK SERVICE'; Op='contains_all_list' }
    @{ Id='89.33'; Sec='User Rights'; Name='Restore Files And Directories - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_restorefilesanddirectories'); Expected='Administrators'; Op='contains_all_list' }
    @{ Id='89.34'; Sec='User Rights'; Name='Shut Down The System - Administrators, Users'; Settings=@('device_vendor_msft_policy_config_userrights_shutdownthesystem'); Expected='Administrators,Users'; Op='contains_all_list' }
    @{ Id='89.35'; Sec='User Rights'; Name='Take Ownership - Administrators'; Settings=@('device_vendor_msft_policy_config_userrights_takeownership'); Expected='Administrators'; Op='contains_all_list' }

    # ── Section 90: Virtualization Based Technology ──
    @{ Id='90.1'; Sec='VBS'; Name='Hypervisor Enforced Code Integrity - Enabled with UEFI lock'; Settings=@('device_vendor_msft_policy_config_virtualizationbasedtechnology_hypervisorenforcedcodeintegrity'); Expected=1; Op='eq' }
    @{ Id='90.2'; Sec='VBS'; Name='Require UEFI Memory Attributes Table'; Settings=@('device_vendor_msft_policy_config_virtualizationbasedtechnology_requireuefimemoryattributestable'); Expected=1; Op='eq' }

    # ── Section 93: Wi-Fi Settings ──
    @{ Id='93.1'; Sec='WiFi'; Name='Allow Auto Connect To Wi-Fi Sense Hotspots - Block'; Settings=@('device_vendor_msft_policy_config_wifi_allowautoconnecttowifisensehotspots'); Expected=0; Op='eq' }

    # ── Section 94: Widgets ──
    @{ Id='94.1'; Sec='Widgets'; Name='Allow widgets - Not allowed'; Settings=@('device_vendor_msft_policy_config_newsandinterests_allowwidgets','device_vendor_msft_policy_config_newsandinterests_allownewsandinterests'); Expected=0; Op='eq' }

    # ── Section 96: Windows Defender Security Center ──
    @{ Id='96.1'; Sec='WDSC'; Name='Disallow Exploit Protection Override - Enable'; Settings=@('device_vendor_msft_policy_config_windowsdefendersecuritycenter_disallowexploitprotectionoverride'); Expected=1; Op='eq' }

    # ── Section 97: Windows Hello For Business ──
    @{ Id='97.1'; Sec='WHfB'; Name='Enable ESS with Supported Peripherals'; Settings=@('device_vendor_msft_passportforwork_biometrics_enableesswithsupportedperipherals'); Expected=1; Op='eq' }
    @{ Id='97.2'; Sec='WHfB'; Name='Facial Features Use Enhanced Anti Spoofing'; Settings=@('device_vendor_msft_passportforwork_biometrics_facialfeaturesuseenhancedantispoofing'); Expected='true'; Op='eq_bool' }
    @{ Id='97.3'; Sec='WHfB'; Name='Minimum PIN Length - 6 or more'; Settings=@('device_vendor_msft_passportforwork_pinlength_minimum','device_vendor_msft_passportforwork_pincomplexity_minimumpinlength'); Expected=6; Op='ge' }
    @{ Id='97.4'; Sec='WHfB'; Name='Require Security Device'; Settings=@('device_vendor_msft_passportforwork_requiresecuritydevice'); Expected='true'; Op='eq_bool' }

    # ── Section 98: Windows Ink Workspace ──
    @{ Id='98.2'; Sec='Windows Ink'; Name='Allow Windows Ink Workspace - Disabled or no access above lock'; Settings=@('device_vendor_msft_policy_config_windowsinkworkspace_allowwindowsinkworkspace'); Expected=1; Op='le' }

    # ── Section 101: Windows Sandbox ──
    @{ Id='101.1'; Sec='Sandbox'; Name='Allow Clipboard Redirection - Not allowed'; Settings=@('device_vendor_msft_policy_config_windowssandbox_allowclipboardredirection'); Expected=0; Op='eq' }
    @{ Id='101.2'; Sec='Sandbox'; Name='Allow Networking - Not allowed'; Settings=@('device_vendor_msft_policy_config_windowssandbox_allownetworking'); Expected=0; Op='eq' }

    # ── Section 103: Windows Update for Business ──
    @{ Id='103.1'; Sec='Windows Update'; Name='Allow Auto Update - Enabled'; Settings=@('device_vendor_msft_policy_config_update_allowautoupdate'); Expected=1; Op='ge' }
    @{ Id='103.2'; Sec='Windows Update'; Name='Defer Feature Updates Period - 180 or more days'; Settings=@('device_vendor_msft_policy_config_update_deferfeatureupdatesperiodindays'); Expected=180; Op='ge' }
    @{ Id='103.3'; Sec='Windows Update'; Name='Defer Quality Updates Period - 0 days'; Settings=@('device_vendor_msft_policy_config_update_deferqualityupdatesperiodindays'); Expected=0; Op='eq' }
    @{ Id='103.4'; Sec='Windows Update'; Name='Manage preview builds - Disable'; Settings=@('device_vendor_msft_policy_config_update_managepreviewbuilds'); Expected=1; Op='eq' }
    @{ Id='103.5'; Sec='Windows Update'; Name='Scheduled Install Day - Every day (0)'; Settings=@('device_vendor_msft_policy_config_update_scheduledinstallday'); Expected=0; Op='eq' }
    @{ Id='103.6'; Sec='Windows Update'; Name='Block Pause Updates ability'; Settings=@('device_vendor_msft_policy_config_update_setdisablepauseuxaccess'); Expected=1; Op='eq' }

    # ── Section 104: Wireless Display ──
    @{ Id='104.1'; Sec='Wireless Display'; Name='Require PIN For Pairing'; Settings=@('device_vendor_msft_policy_config_wirelessdisplay_requirepinforpairing'); Expected=1; Op='ge' }

    # ── Section 105: Windows LAPS ──
    @{ Id='105.1'; Sec='LAPS'; Name='Backup Directory - Azure AD only'; Settings=@('device_vendor_msft_laps_policies_backupdirectory'); Expected=1; Op='eq' }
    @{ Id='105.2'; Sec='LAPS'; Name='Password Age Days - 30 or fewer'; Settings=@('device_vendor_msft_laps_policies_passwordagedays'); Expected=30; Op='le' }
    @{ Id='105.3'; Sec='LAPS'; Name='Password Complexity - Large+small+numbers+special'; Settings=@('device_vendor_msft_laps_policies_passwordcomplexity'); Expected=4; Op='eq' }
    @{ Id='105.4'; Sec='LAPS'; Name='Password Length - 15 or more'; Settings=@('device_vendor_msft_laps_policies_passwordlength'); Expected=15; Op='ge' }
    @{ Id='105.5'; Sec='LAPS'; Name='Post-authentication actions - Reset and logoff or higher'; Settings=@('device_vendor_msft_laps_policies_postauthenticationactions'); Expected=3; Op='ge' }
    @{ Id='105.6'; Sec='LAPS'; Name='Post Authentication Reset Delay - 8 or fewer hours (not 0)'; Settings=@('device_vendor_msft_laps_policies_postauthenticationresetdelay'); Expected=8; Op='le_nz' }
)
#endregion

#region Evaluation Engine
function Find-SettingValue {
    param([string[]]$SettingIds)
    foreach ($id in $SettingIds) {
        # Exact match first
        if ($script:AllSettings.ContainsKey($id)) {
            return $script:AllSettings[$id]
        }
        # Case-insensitive search
        $match = $script:AllSettings.Keys | Where-Object { $_ -ieq $id } | Select-Object -First 1
        if ($match) { return $script:AllSettings[$match] }
        # Partial/suffix match (handles varying prefixes in Settings Catalog)
        $suffix = ($id -split '_' | Select-Object -Last 3) -join '_'
        $match = $script:AllSettings.Keys | Where-Object { $_ -like "*$suffix" } | Select-Object -First 1
        if ($match) { return $script:AllSettings[$match] }
    }
    return $null
}

function Test-CheckResult {
    param($Check, $FoundSetting)

    if ($null -eq $FoundSetting) {
        return @{ Status = 'NOT CONFIGURED'; ActualValue = 'Not found in any policy'; Pass = $false }
    }

    $actual = $FoundSetting.Value
    $expected = $Check.Expected
    $op = $Check.Op
    $pass = $false

    # Normalise choice setting values (Settings Catalog returns full definition path for choices)
    if ($actual -is [string] -and $actual -match '_(\d+)$') {
        $numericSuffix = [int]$Matches[1]
    } else {
        $numericSuffix = $null
    }

    # Try to coerce actual to numeric if expected is numeric
    $actualNum = $null
    if ($expected -is [int] -or $expected -is [long]) {
        if ($actual -is [int] -or $actual -is [long]) {
            $actualNum = [long]$actual
        } elseif ($actual -is [string]) {
            if ($actual -match '^\d+$') {
                $actualNum = [long]$actual
            } elseif ($null -ne $numericSuffix) {
                $actualNum = $numericSuffix
            }
        }
    }

    switch ($op) {
        'eq' {
            if ($null -ne $actualNum) { $pass = $actualNum -eq [long]$expected }
            elseif ($actual -is [string] -and $expected -is [string]) { $pass = $actual -ieq $expected }
            elseif ($actual -is [string] -and $actual -match [regex]::Escape("_$expected")) { $pass = $true }
            else { $pass = "$actual" -eq "$expected" }
        }
        'ne' {
            if ($null -ne $actualNum) { $pass = $actualNum -ne [long]$expected }
            else { $pass = "$actual" -ne "$expected" }
        }
        'ge' {
            if ($null -ne $actualNum) { $pass = $actualNum -ge [long]$expected }
        }
        'le' {
            if ($null -ne $actualNum) { $pass = $actualNum -le [long]$expected }
        }
        'le_nz' {
            # Less than or equal, but not zero
            if ($null -ne $actualNum) { $pass = ($actualNum -le [long]$expected) -and ($actualNum -ne 0) }
        }
        'bitmask' {
            # Audit policies: 1=Success, 2=Failure, 3=Both
            if ($null -ne $actualNum) { $pass = ($actualNum -band [long]$expected) -eq [long]$expected }
        }
        'eq_bool' {
            $actualBool = "$actual".ToLower() -in @('true','1','yes')
            $expectedBool = "$expected".ToLower() -in @('true','1','yes')
            $pass = $actualBool -eq $expectedBool
        }
        'eq_str' {
            $pass = "$actual" -ieq "$expected"
        }
        'ne_str' {
            # Pass if the value is configured AND is not the default name
            $pass = (-not [string]::IsNullOrWhiteSpace("$actual")) -and ("$actual" -ine "$expected")
        }
        'contains' {
            $pass = "$actual" -imatch [regex]::Escape("$expected")
        }
        'contains_all' {
            $parts = "$expected" -split ','
            $pass = $true
            foreach ($p in $parts) {
                if ("$actual" -inotmatch [regex]::Escape($p.Trim())) { $pass = $false; break }
            }
        }
        'contains_all_list' {
            # User Rights: actual may be semicolon or comma-separated SIDs/names
            $actualList = ("$actual" -replace '\s*;\s*', ',' -replace '\s*\x00\s*', ',').Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            $expectedList = "$expected" -split ',' | ForEach-Object { $_.Trim() }
            if ($expectedList.Count -eq 0 -or ($expectedList.Count -eq 1 -and $expectedList[0] -eq '')) {
                $pass = $actualList.Count -eq 0
            } else {
                $pass = $true
                foreach ($e in $expectedList) {
                    if ($e -notin $actualList -and $actualList -notcontains $e) {
                        # Also check case-insensitively
                        $found = $actualList | Where-Object { $_ -ieq $e }
                        if (-not $found) { $pass = $false; break }
                    }
                }
            }
        }
        'not_empty' {
            $pass = -not [string]::IsNullOrWhiteSpace("$actual")
        }
        'empty_or_none' {
            $pass = [string]::IsNullOrWhiteSpace("$actual") -or "$actual" -ieq 'none' -or "$actual" -eq ''
        }
        'ge_asr' {
            # ASR rules: 'audit' >= audit, 'block' > audit
            $asrLevels = @{ 'off' = 0; 'audit' = 1; 'warn' = 2; 'block' = 3 }
            $actualLevel = 0; $expectedLevel = 0
            $actualStr = "$actual".ToLower()
            # Handle numeric ASR values: 0=off, 1=block, 2=audit, 6=warn
            if ($actualStr -match '^\d+$') {
                switch ([int]$actualStr) { 0 { $actualStr = 'off' } 1 { $actualStr = 'block' } 2 { $actualStr = 'audit' } 6 { $actualStr = 'warn' } }
            }
            if ($actualStr -match '_(\w+)$') { $actualStr = $Matches[1] }
            $expectedStr = "$expected".ToLower()
            if ($asrLevels.ContainsKey($actualStr)) { $actualLevel = $asrLevels[$actualStr] }
            if ($asrLevels.ContainsKey($expectedStr)) { $expectedLevel = $asrLevels[$expectedStr] }
            $pass = $actualLevel -ge $expectedLevel
        }
        default { $pass = "$actual" -eq "$expected" }
    }

    $status = if ($pass) { 'PASS' } else { 'FAIL' }
    return @{ Status = $status; ActualValue = $actual; Pass = $pass }
}

function Invoke-CISAudit {
    Write-Host "`n[*] Evaluating $($script:CISChecks.Count) CIS L1 checks..." -ForegroundColor Cyan

    $passCount = 0; $failCount = 0; $ncCount = 0

    foreach ($check in $script:CISChecks) {
        $found = Find-SettingValue -SettingIds $check.Settings
        $result = Test-CheckResult -Check $check -FoundSetting $found

        $policyName = if ($found) { $found.PolicyName } else { 'N/A' }
        $source = if ($found) { $found.Source } else { 'N/A' }

        $obj = [PSCustomObject]@{
            CIS_ID       = $check.Id
            Section      = $check.Sec
            CheckName    = $check.Name
            Status       = $result.Status
            Expected     = $check.Expected
            Actual       = $result.ActualValue
            PolicyName   = $policyName
            Source       = $source
        }
        $script:Results.Add($obj)

        switch ($result.Status) {
            'PASS'           { $passCount++; $color = 'Green' }
            'FAIL'           { $failCount++; $color = 'Red' }
            'NOT CONFIGURED' { $ncCount++;   $color = 'Yellow' }
        }

        $statusPad = $result.Status.PadRight(14)
        Write-Host "    [$statusPad] $($check.Id) - $($check.Name)" -ForegroundColor $color
    }

    Write-Host "`n[=] Results Summary" -ForegroundColor Cyan
    Write-Host "    Total Checks : $($script:CISChecks.Count)" -ForegroundColor White
    Write-Host "    PASS         : $passCount" -ForegroundColor Green
    Write-Host "    FAIL         : $failCount" -ForegroundColor Red
    Write-Host "    NOT CONFIGURED: $ncCount" -ForegroundColor Yellow
    Write-Host "    Pass Rate    : $([math]::Round(($passCount / $script:CISChecks.Count) * 100, 1))%" -ForegroundColor White
}
#endregion

#region Reporting
function Export-HtmlReport {
    $reportFile = Join-Path $OutputPath "CIS_Intune_L1_Audit_$($script:Timestamp).html"
    $totalChecks = $script:Results.Count
    $passCount = ($script:Results | Where-Object Status -eq 'PASS').Count
    $failCount = ($script:Results | Where-Object Status -eq 'FAIL').Count
    $ncCount = ($script:Results | Where-Object Status -eq 'NOT CONFIGURED').Count
    $passRate = [math]::Round(($passCount / $totalChecks) * 100, 1)

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CIS Intune L1 Audit - $($script:Timestamp)</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
  h1 { color: #e94560; margin-bottom: 5px; }
  .subtitle { color: #888; margin-bottom: 20px; }
  .summary { display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }
  .card { background: #16213e; border-radius: 8px; padding: 15px 25px; min-width: 140px; }
  .card .num { font-size: 2em; font-weight: bold; }
  .card .lbl { color: #888; font-size: 0.85em; }
  .card.pass .num { color: #0f3; }
  .card.fail .num { color: #e94560; }
  .card.nc .num { color: #f0a500; }
  .card.total .num { color: #4ea8de; }
  .filters { margin-bottom: 15px; }
  .filters button { background: #16213e; color: #eee; border: 1px solid #333; padding: 6px 14px; border-radius: 4px; cursor: pointer; margin-right: 5px; }
  .filters button.active { background: #e94560; border-color: #e94560; }
  .filters input { background: #16213e; color: #eee; border: 1px solid #333; padding: 6px 12px; border-radius: 4px; width: 250px; }
  table { width: 100%; border-collapse: collapse; background: #16213e; border-radius: 8px; overflow: hidden; }
  th { background: #0f3460; padding: 10px 12px; text-align: left; font-size: 0.85em; position: sticky; top: 0; }
  td { padding: 8px 12px; border-top: 1px solid #1a1a2e; font-size: 0.85em; }
  tr:hover { background: #1a1a3e; }
  .status-pass { color: #0f3; font-weight: bold; }
  .status-fail { color: #e94560; font-weight: bold; }
  .status-nc { color: #f0a500; font-weight: bold; }
  .progress-bar { background: #333; border-radius: 10px; height: 20px; overflow: hidden; width: 200px; display: inline-block; vertical-align: middle; }
  .progress-fill { height: 100%; border-radius: 10px; }
</style>
</head>
<body>
<h1>CIS Microsoft Intune for Windows 11 L1 Audit</h1>
<p class="subtitle">Benchmark v4.0.0 | Generated: $(Get-Date -Format 'dd MMM yyyy HH:mm')</p>

<div class="summary">
  <div class="card total"><div class="num">$totalChecks</div><div class="lbl">Total Checks</div></div>
  <div class="card pass"><div class="num">$passCount</div><div class="lbl">Pass</div></div>
  <div class="card fail"><div class="num">$failCount</div><div class="lbl">Fail</div></div>
  <div class="card nc"><div class="num">$ncCount</div><div class="lbl">Not Configured</div></div>
  <div class="card"><div class="num">$passRate%</div><div class="lbl">Pass Rate</div>
    <div class="progress-bar"><div class="progress-fill" style="width:${passRate}%;background:$(if($passRate -ge 80){'#0f3'}elseif($passRate -ge 50){'#f0a500'}else{'#e94560'})"></div></div>
  </div>
</div>

<div class="filters">
  <button class="active" onclick="filterTable('all',this)">All</button>
  <button onclick="filterTable('FAIL',this)">Fail</button>
  <button onclick="filterTable('NOT CONFIGURED',this)">Not Configured</button>
  <button onclick="filterTable('PASS',this)">Pass</button>
  <input type="text" id="search" placeholder="Search checks..." oninput="searchTable(this.value)">
</div>

<table id="results">
<thead><tr><th>CIS ID</th><th>Section</th><th>Check</th><th>Status</th><th>Expected</th><th>Actual</th><th>Policy</th></tr></thead>
<tbody>
"@

    foreach ($r in $script:Results) {
        $statusClass = switch ($r.Status) { 'PASS' { 'status-pass' }; 'FAIL' { 'status-fail' }; default { 'status-nc' } }
        $actualDisplay = if ("$($r.Actual)".Length -gt 80) { "$($r.Actual)".Substring(0,77) + '...' } else { $r.Actual }
        $html += "<tr data-status=`"$($r.Status)`"><td>$($r.CIS_ID)</td><td>$($r.Section)</td><td>$($r.CheckName)</td><td class=`"$statusClass`">$($r.Status)</td><td>$($r.Expected)</td><td>$actualDisplay</td><td>$($r.PolicyName)</td></tr>`n"
    }

    $html += @"
</tbody></table>
<script>
function filterTable(status, btn) {
  document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#results tbody tr').forEach(r => {
    r.style.display = (status === 'all' || r.dataset.status === status) ? '' : 'none';
  });
}
function searchTable(q) {
  q = q.toLowerCase();
  document.querySelectorAll('#results tbody tr').forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
</script>
<p style="margin-top:20px;color:#555;font-size:0.8em;">CIS Microsoft Intune for Windows 11 Benchmark v4.0.0 - Automated L1 Audit</p>
</body></html>
"@

    $html | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "[+] HTML report: $reportFile" -ForegroundColor Green
    return $reportFile
}

function Export-CsvReport {
    $csvFile = Join-Path $OutputPath "CIS_Intune_L1_Audit_$($script:Timestamp).csv"
    $script:Results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV report: $csvFile" -ForegroundColor Green
}
#endregion

#region Main Execution
function Main {
    Write-Host @"

  ╔══════════════════════════════════════════════════════════════╗
  ║  CIS Microsoft Intune for Windows 11 Benchmark v4.0.0      ║
  ║  Level 1 Automated Audit                                    ║
  ║  Automated Audit                                             ║
  ╚══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    # Prompt for output path if not provided
    if (-not $OutputPath) {
        $OutputPath = Read-Host "[?] Enter output directory path (default: current directory)"
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $OutputPath = (Get-Location).Path
        }
    }

    # Ensure output path exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Connect and collect
    Connect-CISGraph
    Get-AllIntuneSettings

    # Run audit
    Invoke-CISAudit

    # Generate reports
    $reportPath = Export-HtmlReport
    if ($ExportCsv) { Export-CsvReport }

    Write-Host "`n[*] Audit complete. Open the HTML report for interactive filtering." -ForegroundColor Cyan

    # Return results for pipeline use
    return $script:Results
}

# Run
$results = Main
#endregion
