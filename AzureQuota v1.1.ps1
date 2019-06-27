#Credit to Original Solution: https://blogs.msdn.microsoft.com/tomholl/2017/06/11/get-alerts-as-you-approach-your-azure-resource-quotas/

Param(
 [string]$omsWorkspaceId,
 [string]$omsSharedKey,
 [string[]]$Subscriptions,
 [string[]]$locations
)


$connectionName = "AzureRunAsConnection"
try
{
    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection = Get-AutomationConnection -Name $connectionName        
 
    "Logging in to Azure..."
    Add-AzAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint   $servicePrincipalConnection.CertificateThumbprint 
}
catch {
    if (!$servicePrincipalConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

$LogType = "AzureQuota"
 
$json = ''
 
# Credit: s_lapointe  https://gallery.technet.microsoft.com/scriptcenter/Easily-obtain-AccessToken-3ba6e593
function Get-AzCachedAccessToken()
{
    $ErrorActionPreference = 'Stop'
  
    if(-not (Get-Module Az.Accounts)) {
        Import-Module Az.Accounts
    }
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    if(-not $azProfile.Accounts.Count) {
        Write-Error "Ensure you have logged in before calling this function."    
    }
  
    $currentAzureContext = Get-AzContext
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
    Write-Debug ("Getting access token for tenant" + $currentAzureContext.Tenant.TenantId)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Tenant.TenantId)
    $token.AccessToken
}
 
# Network Usage not currently exposed through PowerShell, so need to call REST API
function Get-AzNetworkUsage($location, $SubscriptionId) 
{
    $token = Get-AzCachedAccessToken
    $authHeader = @{
    'Content-Type'='application\json'
    'Authorization'="Bearer $token"
    }
 
    $result = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Network/locations/$location/usages?api-version=2017-03-01" -Method Get -Headers $authHeader
    return $result.value
}

# for each subscription get the quota data
foreach ($SubscriptionId in $Subscriptions)
{
Set-AzContext -SubscriptionId $SubscriptionId
$azureContext = Get-AzContext
$SubscriptionName = $azureContext.Subscription.Name

# Get VM quotas
foreach ($location in $locations)
{
    $vmQuotas = Get-AzVMUsage -Location $location
    foreach($vmQuota in $vmQuotas)
    {
        $usage = 0
        if ($vmQuota.Limit -gt 0) { $usage = $vmQuota.CurrentValue / $vmQuota.Limit }
        $json += @"
{ "SubscriptionId":"$SubscriptionId", "Subscription":"$SubscriptionName", "Name":"$($vmQuota.Name.LocalizedValue)", "Category":"Compute", "Location":"$location", "CurrentValue":$($vmQuota.CurrentValue), "Limit":$($vmQuota.Limit),"Usage":$usage },
"@
    }
}

# Get Network Quota
foreach ($location in $locations)
{
    $networkQuotas = Get-AzNetworkUsage -location $location -SubscriptionId $SubscriptionId
    foreach ($networkQuota in $networkQuotas)
    {
        $usage = 0
        if ($networkQuota.limit -gt 0) { $usage = $networkQuota.currentValue / $networkQuota.limit }
         $json += @"
{ "SubscriptionId":"$SubscriptionId", "Subscription":"$SubscriptionName", "Name":"$($networkQuota.name.localizedValue)", "Category":"Network", "Location":"$location", "CurrentValue":$($networkQuota.currentValue), "Limit":$($networkQuota.limit),"Usage":$usage },
"@
    }
 
}

# Get Storage Quota
foreach ($location in $locations)
{
    $storageQuota = Get-AzStorageUsage -Location $location
    $usage = 0
    if ($storageQuota.Limit -gt 0) { $usage = $storageQuota.CurrentValue / $storageQuota.Limit }
    $json += @"
{ "SubscriptionId":"$SubscriptionId", "Subscription":"$SubscriptionName", "Name":"$($storageQuota.LocalizedName)", "Location":"$location", "Category":"Storage", "CurrentValue":$($storageQuota.CurrentValue), "Limit":$($storageQuota.Limit),"Usage":$usage }
"@
 
}
}

# Wrap in an array
$json = "[$json]"
 
# Create the function to create the authorization signature
Function Build-Signature ($omsWorkspaceId, $omsSharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
 
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($omsSharedKey)
 
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $omsWorkspaceId,$encodedHash
    return $authorization
}
 
 
# Create the function to create and post the request
Function Post-OMSData($omsWorkspaceId, $omsSharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -omsWorkspaceId $omsWorkspaceId `
        -omsSharedKey $omsSharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -fileName $fileName `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $omsWorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
 
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
    }
 
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
 
}
 
# Submit the data to the API endpoint
Post-OMSData -omsWorkspaceId $omsWorkspaceId -omsSharedKey $omsSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType