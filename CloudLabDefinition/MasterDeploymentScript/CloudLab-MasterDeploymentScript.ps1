#
# CloudLab-MasterDeploymentScript.ps1
# This script is the master script which is used to deploy the collection of resources groups that comprise the cloud lab.
# Each separate resource group is named here, but defined within RM templates and parameter files.
# This script is used to deploy those templates to Azure, enabling a full or piecemeal deployment of the various lab components.
#

#Requires -Version 3.0
#Requires -Module AzureRM.Resources
#Requires -Module Azure.Storage

#region parameters
[CmdletBinding()]
param (
    [System.Management.Automation.PSCredential]$AzureCredential,
    [string]$SubscriptionName = 'Visual Studio Premium with MSDN',
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
    [string]$Location = "East US 2"
)
#endregion

#region Variables
## Resource Group Names
[string]$RGName_Prefix = 'GJT-'
[string]$RGName_CoreInfra = 'CloudLab-CoreInfra'
[string]$RGName_ADDS = 'CloudLab-ADDS'

## Asset location root
[string]$AssetPathRoot = 'https://raw.githubusercontent.com/gabrieljtaylor/CloudLabDefinition/master/CloudLabDefinition/'
[string]$TemplatePathSuffix = '/Templates/azuredeploy.json'
[string]$ParameterFilePathSuffix = '/Templates/azuredeploy.parameters.json'
#endregion

#region Functions
function Deploy-RGCoreInfra {
    [CmdletBinding()]
    param(
        [string]$DeploymentMode = 'Incremental',    
        [string]$ResourceGroupName,
        [string]$ResourceGroupNamePrefix,
        [string]$ResourceGroupLocation,
        [string]$AssetPathRoot,
        [string]$TemplatePathSuffix,
        [string]$ParameterFilePathSuffix,
        [string]$AssetPathSuffix,
        [string]$ScriptPathSuffix
    )

    begin {
        ## Format the variables used in the deployment
        $DeploymentName = $ResourceGroupNamePrefix + $ResourceGroupName + '-Deployment-' + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')
        $FullResourceGroupName = $ResourceGroupNamePrefix + $ResourceGroupName
        $TemplateUri = $AssetPathRoot + $ResourceGroupName + $TemplatePathSuffix
        $ParameterUri = $AssetPathRoot + $ResourceGroupName + $ParameterFilePathSuffix
    }

    process {
        try {
            ## Create or update the resource group
            New-AzureRmResourceGroup -Name $FullResourceGroupName -Location $ResourceGroupLocation -Verbose -Force -ErrorAction Stop 

            ## Deploy the resource group template
            New-AzureRmResourceGroupDeployment -Name $DeploymentName `
                -ResourceGroupName $FullResourceGroupName `
                -Mode $DeploymentMode `
                -TemplateUri $TemplateUri `
                -TemplateParameterUri $ParameterUri
        }
        catch {
            Write-Error -Message "An error occured while deploying resource group $FullResourceGroupName; exception: $($Error[0].Exception.Message)"
        }
    }

    end {

    }
}

#endregion

#region Validate Inputs

#endregion

#region Connect to Azure
## Connect to Azure
try {
    if (!$AzureCredential) {
        ## If no credential was provided, then prompt for one and connect to Azure
        $AzureProfile = Add-AzureRmAccount -SubscriptionName $SubscriptionName -ErrorAction Stop
    }
    else {
        $AzureProfile = Login-AzureRmAccount -Credential $AzureCredential -SubscriptionName $SubscriptionName -ErrorAction Stop
    }
}
catch {
    Write-Error -Message "Failed to connect to Azure; exception: $($Error[0].Exception.Message)"
}
#endregion

#region Deploy Resource Groups
## Deploy the CoreInfra resource group
Deploy-RGCoreInfra -DeploymentMode Incremental `
    -ResourceGroupName $RGName_CoreInfra `
    -ResourceGroupNamePrefix $RGName_Prefix `
    -ResourceGroupLocation $Location `
    -AssetPathRoot $AssetPathRoot `
    -TemplatePathSuffix $TemplatePathSuffix `
    -ParameterFilePathSuffix $ParameterFilePathSuffix `
    -Verbose
#endregion

#region Wrap Up

#endregion