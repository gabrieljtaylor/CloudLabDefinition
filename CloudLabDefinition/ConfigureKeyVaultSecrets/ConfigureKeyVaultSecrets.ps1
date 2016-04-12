#
# ConfigureKeyVaultSecrets.ps1
# This script is used to populate an Azure keyvault with secrets to be used by the CloudLab deployment
# 
# This script is designed to have the secret values passed in via parameter to avoid having any confidential information contained within.
# DO NOT COMMIT THIS FILE WITH ANY SECRET VALUES PRESENT!!! Your secrets will be exposed to the internet and it will completely defeat the point of this exercise!
#

#Requires -Version 3.0
#Requires -Module AzureRM.Resources
#Requires -Module Azure.Storage

#region parameters
[CmdletBinding()]
param (
    [string]$SubscriptionName = 'Visual Studio Premium with MSDN',
    [string]$NamingPrefix = 'GJT-CloudLab-',
    [parameter()]
    [ValidateSet("Brazil South",
        "Central US",
        "East Asia",
        "East US",
        "East US 2",
        "Japan East",
        "Japan West",
        "North Central US",
        "North Europe",
        "South Central US",
        "Southeast Asia",
        "West Europe",
        "West US")]
    [string]$Location = "East US",
    [string]$SecretValue_DomainAdminPW,
    [string]$SecretValue_DefaultUserPW,
    [string]$SecretValue_OMSWorkspaceId,
    [string]$SecretValue_OMSWorkspaceKey
)
#endregion

#region Variables
## Object Names
$KeyVault_ResourceGroupName = $NamingPrefix + "KeyVault"
$KeyVault_VaultName = $NamingPrefix + "KeyVault"
#endregion

#region Functions

#endregion

#region Connect to Azure
## Connect to Azure
try {
    ## Prompt for credentials and connect to Azure
    $AzureProfile = Add-AzureRmAccount -SubscriptionName $SubscriptionName -ErrorAction Stop
}
catch {
    Write-Error -Message "Failed to connect to Azure; exception: $($Error[0].Exception.Message)"
}
#endregion

#region Configure Resource Group
$ResourceGroup = New-AzureRmResourceGroup -Name $KeyVault_ResourceGroupName -Location $Location -Force
#endregion

#region Configure Vault
try {
    ## Try to query the existing vault
    $KeyVault = Get-AzureRmKeyVault -VaultName $KeyVault_VaultName
}
catch [System.ArgumentException] {
    $ErrorObj = $Error[0]

    ## If the vault doesn't exist, create it
    if ($ErrorObj.Exception.Message -like "*Cannot find vault `'$KeyVault_VaultName`'*") {
        ## No vault present, create it
        $KeyVault = New-AzureRmKeyVault -VaultName $KeyVault_VaultName -ResourceGroupName $KeyVault_ResourceGroupName -Location $Location -EnabledForTemplateDeployment
    }
    else {
        throw $ErrorObj
    }
}
#endregion

#region Create Secrets
Set-AzureKeyVaultSecret -VaultName $KeyVault.VaultName -Name ($NamingPrefix + "AdminPW") -SecretValue (ConvertTo-SecureString -String $SecretValue_DomainAdminPW -AsPlainText -Force)
Set-AzureKeyVaultSecret -VaultName $KeyVault.VaultName -Name ($NamingPrefix + "DefaultUserPW") -SecretValue (ConvertTo-SecureString -String $SecretValue_DefaultUserPW -AsPlainText -Force)
Set-AzureKeyVaultSecret -VaultName $KeyVault.VaultName -Name ($NamingPrefix + "OMSWorkspaceId") -SecretValue (ConvertTo-SecureString -String $SecretValue_OMSWorkspaceId -AsPlainText -Force)
Set-AzureKeyVaultSecret -VaultName $KeyVault.VaultName -Name ($NamingPrefix + "OMSWorkspaceKey") -SecretValue (ConvertTo-SecureString -String $SecretValue_OMSWorkspaceKey -AsPlainText -Force)
#endregion

#region Wrap Up

#endregion