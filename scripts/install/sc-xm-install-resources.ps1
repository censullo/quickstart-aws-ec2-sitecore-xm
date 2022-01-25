[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateSet(
        'DbResources',
        'IdentityServer',
        'CM',
        'CD'
    )]
    [string]
    $Role,
    [Parameter(Mandatory)]
    $SCQSPrefix,
    [Parameter(Mandatory)]
    $Region,
    $StackName
)
If (![Environment]::Is64BitProcess) {
    Write-Host "Please run 64-bit PowerShell" -foregroundcolor "yellow"
    return
}
Import-Module SitecoreInstallFramework

$DNSSuffix = (Get-SSMParameter -Name "/$SCQSPrefix/service/internaldns").Value

# region Role Mapping
$roleMapping = @{
    'IdentityServer'               = "identity"
    # 'Collection'                   = "coll"
    # 'CollectionSearch'             = "collsearch"
    # 'ReferenceData'                = "refdata"
    # 'MarketingAutomation'          = "mktauto"
    # 'MarketingAutomationReporting' = "mktautorep"
    # 'CortexProcessing'             = "cortexproc"
    # 'CortexReporting'              = "cortexrep"
    'CM'                           = "contentmgmt"
    'CD'                           = "contentdel"
    # 'Prc'                          = "proc"
    # 'Rep'                          = "rep"
}
# endregion

# region Parameter Values
$parameters = @{
    SCPrefix                      = (Get-SSMParameter -Name "/$SCQSPrefix/user/sitecoreprefix").Value
    SCInstallRoot                 = (Get-SSMParameter -Name "/$SCQSPrefix/user/localresourcespath").Value
    PasswordRecoveryUrl           = (Get-SSMParameter -Name "/$SCQSPrefix/service/passwordrecoveryurl").Value
    allowedCorsOrigins            = (Get-SSMParameter -Name "/$SCQSPrefix/service/allowedCorsOrigins").Value
    Environment                   = (Get-SSMParameter -Name "/$SCQSPrefix/user/environment").Value
    LogLevel                      = (Get-SSMParameter -Name "/$SCQSPrefix/user/logLevel").Value
    SolrCorePrefix                = (Get-SSMParameter -Name "/$SCQSPrefix/user/solrcoreprefix").Value
    SolrUrl                       = (Get-SSMParameter -Name "/$SCQSPrefix/user/solruri").Value
    InstanceCertificateThumbPrint = (Get-SSMParameter -Name "/$SCQSPrefix/cert/instance/thumbprint").Value
    # xConnectCertificateThumbPrint = (Get-SSMParameter -Name "/$SCQSPrefix/cert/xconnect/thumbprint").Value
    SQLServer                     = (Get-SSMParameter -Name "/$SCQSPrefix/sql/server").Value
}
# endregion

$DNSNames = @{
    IdentityServerDNS               = (Get-SSMParameter -Name "/$SCQSPrefix/service/isdns").Value #$roleMapping.IdentityServer + '.' + $DNSSuffix
    CMDNS                           = (Get-SSMParameter -Name "/$SCQSPrefix/service/cmdns").Value 
    CDDNS                           = (Get-SSMParameter -Name "/$SCQSPrefix/service/cddns").Value 
}

$ServiceURLs = @{
    PasswordRecoveryUrl                  = (Get-SSMParameter -Name "/$SCQSPrefix/service/passwordrecoveryurl").Value  # https:// (Host name of CM instance) "https://" + $DNSNames.CMDNS
    SitecoreIdentityAuthority            = "https://" + $DNSNames.IdentityServerDNS                 # https://SitecoreIdentityServerHost
}

# region Secrets Manager Values
$secrets = @{
    SitecoreIdentitySecret         = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sitecoreidentitysecret").SecretString).secret
    SitecoreAdminPassword          = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sitecoreadmin").SecretString).password
    ReportingServiceApiKey         = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-reportingserviceapikey").SecretString).apikey
    ClientSecret                   = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-clientsecret").SecretString).secret
    SqlAdminUser                   = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqladmin").SecretString).username
    SqlAdminPassword               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqladmin").SecretString).password
    SqlSecurityUser                = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlsecurity").SecretString).username
    SqlSecurityPassword            = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlsecurity").SecretString).password
    SqlCoreUser                    = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlcore").SecretString).username
    SqlCorePassword                = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlcore").SecretString).password
    SqlMainUser                  = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlmain").SecretString).username
    SqlMainPassword              = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlmain").SecretString).password
    SqlWebUser                     = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlweb").SecretString).username
    SqlWebPassword                 = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlweb").SecretString).password
    SqlFormsUser                   = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlforms").SecretString).username
    SqlFormsPassword               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlforms").SecretString).password
}

# Endregion

# Region local values
$local = @{
    ComputerName            = $(Invoke-RestMethod -uri http://169.254.169.254/latest/meta-data/hostname)
    SiteName                = "$($parameters.SCPrefix).$Role"
    Package                 = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$Role.scwdp.zip").FullName
    jsonPath                = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$Role.json").FullName
    # jsonPathCustom          = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)/aws-custom" -Filter "*$Role.json").FullName
    CustomConfigurationFile = "$Role.json"
    LicenseFile             = "$($parameters.SCInstallRoot)\license.xml"
    SkipDBInstallOnRoles    = $true
}
# Endregion

# CW Logging
$localLogPath = "$($parameters.SCInstallRoot)\logs" # Path on the instance where the log files will be located
$LogGroupName = "$SCQSPrefix-$Role"
$LogStreamName = "$Role-RoleInstallation-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )

If (!(test-path $localLogPath)) {
    New-Item -ItemType Directory -Force -Path $localLogPath
}


$skip = @()

switch ($Role) {
    'DbResources' {
        $dbRoles = @(
            #'Collection'
            #'ReferenceData'
            #'CortexProcessing'
            #'CortexReporting'
            'CM'
            #'Prc'
        )
        foreach ($dbRole in $dbRoles) {
            $local.SiteName = "$($parameters.SCPrefix).$dbRole"
            $local.Package = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$DbRole.scwdp.zip").FullName
            $local.jsonPath = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$DbRole.json").FullName
            $appCmd = "C:\windows\system32\inetsrv\appcmd.exe"
            switch ($dbRole) {
                'CM' {
                    $DeploymentParameters = @{
                        Package                  = $($local.Package)
                        LicenseFile              = $($local.LicenseFile)
                        SiteName                 = $($local.SiteName)
                        SSLCert                  = $($parameters.InstanceCertificateThumbPrint)
                        #XConnectCert             = $($parameters.xConnectCertificateThumbPrint)
                        SqlDbPrefix              = $($parameters.SCPrefix)
                        SqlServer                = $($parameters.SQLServer)
                        SitecoreAdminPassword    = $($secrets.SitecoreAdminPassword)
                        SqlAdminUser             = $($secrets.SqlAdminUser)
                        SqlAdminPassword         = $($secrets.SqlAdminPassword)
                        SqlCoreUser              = $($secrets.SqlCoreUser)
                        SqlCorePassword          = $($secrets.SqlCorePassword)
                        SqlSecurityUser          = $($secrets.SqlSecurityUser)
                        SqlSecurityPassword      = $($secrets.SqlSecurityPassword)
                        SqlMasterUser            = $($secrets.SqlMainUser)
                        SqlMasterPassword        = $($secrets.SqlMainPassword)
                        SqlWebUser               = $($secrets.SqlWebUser)
                        SqlWebPassword           = $($secrets.SqlWebPassword)
                        SqlFormsUser             = $($secrets.SqlFormsUser)
                        SqlFormsPassword         = $($secrets.SqlFormsPassword)
                    }
                    $skip = @(
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'CreateHostHeader'
                        'SetPermissions'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'SetLicense'
                        'StartAppPool'
                        'StartWebsite'
                        'UpdateSolrSchema'
                        # 'DisplayPassword'
                    )
                }
                Default { }
            }

            Push-Location $($parameters.SCInstallRoot)
            Install-SitecoreConfiguration @DeploymentParameters -Path $($local.jsonPath) -Skip $skip -Verbose *>&1 | Tee-Object "$localLogPath\db-$DbRole.log"
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\db-$DbRole.log" -raw)
            & $appcmd delete site $($local.SiteName)
            & $appcmd delete apppool$($local.SiteName)
            Pop-Location
        }
    }
    'IdentityServer' {
        $DeploymentParameters = @{
            Package                 = $($local.Package)
            SitecoreIdentityCert    = $($parameters.InstanceCertificateThumbPrint)
            LicenseFile             = $($local.LicenseFile)
            SiteName                = $($local.SiteName)
            SqlServer               = $($parameters.SQLServer)
            SqlDbPrefix             = $($parameters.SCPrefix)
            SqlSecurityPassword     = $($secrets.SqlSecurityPassword)
            PasswordRecoveryUrl     = $($ServiceURLs.PasswordRecoveryUrl)
            AllowedCorsOrigins      = $($parameters.allowedCorsOrigins)
            ClientSecret            = $($secrets.ClientSecret)
            CustomConfigurationFile = $($local.CustomConfigurationFile)
            HostMappingName         = $($DNSNames.IdentityServerDNS)
            DnsName                 = $($DNSNames.IdentityServerDNS)
            SqlSecurityUser         = $($secrets.SqlSecurityUser)
        }
    }
    'CM' {
        $DeploymentParameters = @{
            Package                              = $($local.Package)
            LicenseFile                          = $($local.LicenseFile)
            SqlDbPrefix                          = $($parameters.SCPrefix)
            SolrCorePrefix                       = $($parameters.SolrCorePrefix)
            SSLCert                              = $($parameters.InstanceCertificateThumbPrint)
            # XConnectCert                         = $($parameters.xConnectCertificateThumbPrint)
            SiteName                             = $($local.SiteName)
            # SitePhysicalRoot
            SitecoreAdminPassword                = $($secrets.SitecoreAdminPassword)
            SqlAdminUser                         = $($secrets.SqlAdminUser)
            SqlAdminPassword                     = $($secrets.SqlAdminPassword)
            SqlCoreUser                          = $($secrets.SqlCoreUser)
            SqlCorePassword                      = $($secrets.SqlCorePassword)
            SqlSecurityUser                      = $($secrets.SqlSecurityUser)
            SqlSecurityPassword                  = $($secrets.SqlSecurityPassword)
            SqlMasterUser                        = $($secrets.SqlMainUser)
            SqlMasterPassword                    = $($secrets.SqlMainPassword)
            SqlWebUser                           = $($secrets.SqlWebUser)
            SqlWebPassword                       = $($secrets.SqlWebPassword)
            SqlFormsUser                         = $($secrets.SqlFormsUser)
            SqlFormsPassword                     = $($secrets.SqlFormsPassword)
            SqlServer                            = $($parameters.SQLServer)
            # ExmEdsProvider
            SolrUrl                              = $($parameters.SolrUrl)
            SitecoreIdentityAuthority            = $($ServiceURLs.SitecoreIdentityAuthority)
            SitecoreIdentitySecret               = $($secrets.SitecoreIdentitySecret)
            # TelerikEncryptionKey
            HostMappingName                      = $($DNSNames.CMDNS)
            DnsName                              = $($DNSNames.CMDNS)
            SkipDatabaseInstallation             = $($local.SkipDBInstallOnRoles)
            # PackagesTempLocation
            # DownloadLocations
        }
        $skip = @(
            # 'DownloadWDP'
            # 'CreatePaths'
            # 'CreateAppPool'
            # 'CreateWebsite'
            # 'StopWebsite'
            # 'StopAppPool'
            # 'RemoveDefaultBinding' 
            # 'CreateBindingsWithThumbprint'
            # 'CreateHostHeader'
            # 'SetPermissions'
            # 'SetCertStorePermissions'
            # 'InstallWDP'
            # 'CreateBindingsWithDevelopmentThumbprint'
            # 'SetLicense'
            # 'StartAppPool'
            # 'StartWebsite'
            'UpdateSolrSchema'
            'DisplayPassword'
        )
    }
    'CD' {
        $DeploymentParameters = @{
            Package                              = $($local.Package)
            LicenseFile                          = $($local.LicenseFile)
            SqlDbPrefix                          = $($parameters.SCPrefix)
            SolrCorePrefix                       = $($parameters.SolrCorePrefix)
            # XConnectCert                         = $($parameters.xConnectCertificateThumbPrint)
            SiteName                             = $($local.SiteName)
            # SitePhysicalRoot
            SolrUrl                              = $($parameters.SolrUrl)
            SitecoreIdentityAuthority            = $($ServiceURLs.SitecoreIdentityAuthority)
            SqlServer                            = $($parameters.SQLServer)
            SqlSecurityUser                      = $($secrets.SqlSecurityUser)
            SqlSecurityPassword                  = $($secrets.SqlSecurityPassword)
            SqlWebUser                           = $($secrets.SqlWebUser)
            SqlWebPassword                       = $($secrets.SqlWebPassword)
            SqlFormsUser                         = $($secrets.SqlFormsUser)
            SqlFormsPassword                     = $($secrets.SqlFormsPassword)
            HostMappingName                      = $($DNSNames.CDDNS)
            DnsName                              = $($DNSNames.CDDNS)
            # PackagesTempLocation
            # DownloadLocations
        }
    }
}

If ($Role -ne 'DbResources') {
    Push-Location $($parameters.SCInstallRoot)
    $internalDNSType = (Get-SSMParameter -Name "/$SCQSPrefix/user/InternalPrivateDNS").Value
    if ($Role -eq 'MarketingAutomation' -And $internalDNSType -eq 'True') {
        New-AWSQuickStartResourceSignal -Stack $StackName -Region $Region -Resource "MarketingAutomationASG"
        Write-AWSQuickStartStatus
    }
    Install-SitecoreConfiguration @DeploymentParameters -Path $($local.jsonPath) -Skip $skip -Verbose *>&1 | Tee-Object "$localLogPath\$Role.log"
    $LogGroupName = "$SCQSPrefix-$Role"
    $LogStreamName = "$Role-RoleInstallation-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\$Role.log" -raw)
    # Setting permissions for AppPool Identity in Administrators
    $AppPoolSiteName = $DeploymentParameters.SiteName
    Add-LocalGroupMember -Group "Administrators" -Member "IIS AppPool\$AppPoolSiteName"
    
    $Site = Get-Website -Name $DeploymentParameters.SiteName
    $AppPool = Get-ItemProperty ("IIS:\AppPools\$AppPoolSiteName")
    # Configure Application Pool StartMode
    $CurrentStratMode = $AppPool.startMode
    if($CurrentStratMode -ne "AlwaysRunning")
        {
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Current StartMode: $CurrentStratMode"
            $AppPool | Set-ItemProperty -name "startMode" -Value "AlwaysRunning"
            $AppPool = Get-ChildItem IIS:\AppPools\ | Where-Object { $_.Name -eq $Site.applicationPool }
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "StartMode set to $CurrentStratMode"
        } 
        else 
        {
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "StartMode is : $CurrentStratMode. No update required"
        }

    #Configure Application Pool Idle Timeout value
    $currentIdleTimeout = Get-ItemProperty ("IIS:\AppPools\$AppPoolSiteName") -Name processModel.idleTimeout.value
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Idle Timeout value is : $currentIdleTimeout"
    # Set to 30 min
    $SitecoreIdleTimeout = '0'
    $SitecoreIdleTimeoutAction = 'Suspend'
    $userProfile = "True"
    $maxProcesses = 1
    Set-ItemProperty ("IIS:\AppPools\$AppPoolSiteName") -Name processModel.idleTimeout -value ( [TimeSpan]::FromMinutes($SitecoreIdleTimeout))
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Idle Timeout value updated to : $SitecoreIdleTimeout"

    Set-ItemProperty ("IIS:\AppPools\$AppPoolSiteName") processModel.idleTimeoutAction -Value $SitecoreIdleTimeoutAction
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Idle Timeout Action updated to : $SitecoreIdleTimeoutAction"

    Set-ItemProperty ("IIS:\AppPools\$AppPoolSiteName") processModel.loadUserProfile -Value $userProfile
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Load user profile updated to : $userProfile"

    Set-ItemProperty ("IIS:\AppPools\$AppPoolSiteName") processModel.maxProcesses -Value $maxProcesses
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "MaxProcess updated to : $maxProcesses"

    $currentSitePreload = (Get-ItemProperty "IIS:\Sites\$AppPoolSiteName" -Name applicationDefaults.preloadEnabled).Value
    # Enable Preload
    if(!(Get-ItemProperty "IIS:\Sites\$AppPoolSiteName" -Name applicationDefaults.preloadEnabled).Value) 
        {
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Current Site Preload : $currentSitePreload"
            Set-ItemProperty "IIS:\Sites\$AppPoolSiteName" -Name applicationDefaults.preloadEnabled -Value True
            $newSitePreload = (Get-ItemProperty "IIS:\Sites\$AppPoolSiteName" -Name applicationDefaults.preloadEnabled).Value
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Site Preload update to: $newSitePreload"
        } 
        else
        {
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Site Preload is : $CurrentStratMode. No update required"
        }
    Pop-Location
} 
