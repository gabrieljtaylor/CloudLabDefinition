#
# ConfigureADObjects.ps1
# This script is intended to validate a preconfigured list of users, groups, and OUs against an Active Directory environment.
# If the specified objects are not found in the domain, the script will create them
# In this way, it can populate a fresh install of AD with a default set of users, groups, and OUs.
# The goal is also to include GPOs in that configuration, but we'll see what we can do.
#

#region Parameters
[CmdletBinding()]
param(
    $CSVDataUrl,
    $DefaultPassword,
    $DomainAdminUsername,
    $DomainAdminPassword
)
#endregion

#region Variables
$StartTime = Get-Date
#endregion

#region Functions
function Test-Credential {
    [CmdletBinding()]
    [OutputType([Bool])]
    Param (
        # Credential, Type PSCredential, The PSCredential Object to test.
        [Parameter(Mandatory=$true,
            Position = 0,
            ValueFromPipeline = $true)]
        [PSCredential]$Credential,

        # Domain, Type String, The domain name to test PSCredential Object against.
        [Parameter(Position = 1)]
        [String]$Domain = $env:USERDOMAIN
    )
 
    Begin {
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.AccountManagement")
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain)
    }
 
    Process {
        ## Isolate the network credentials
        $networkCredential = $Credential.GetNetworkCredential()

        ## Return the validation
        return $principalContext.ValidateCredentials($networkCredential.UserName,$networkCredential.Password,'Negotiate')
    }

    End {
        $principalContext.Dispose()
    }
}
#endregion

#region Script Blocks
[scriptblock]$configureDNSSuffix = {
    ## Check whether or not Active Directory PowerShell module has been imported and, if not, import it
    $ExistingModules = (get-module | %{$_.name}) -join " "
    if (!$ExistingModules.Contains("ActiveDirectory")) {
        Import-Module "ActiveDirectory" -Force | Out-Null
    }

    ## Get the current domain information
    $Domain = Get-ADDomain

    ## Generate a new DNS suffix that is just the domainname.tld
    $DNSSuffix = ($Domain.DNSRoot -split "\." | Select-Object -Last 2 ) -join "."

    ## If the generated suffix does not match the DNS root, and it isn't already an allowed suffix, add it as an allowed suffix
    if ($DNSSuffix -notmatch $Domain.DNSRoot -and $Domain.AllowedDNSSuffixes -notcontains $DNSSuffix) {
        Set-ADDomain -Identity $Domain -AllowedDNSSuffixes @{Add=$DNSSuffix} | Out-Null
    }

    ## Return the DNS Suffix to the parent session
    $DNSSuffix
}

[scriptblock]$configureOUs = {
    ## Save the input arguments as variables
    $CSVURL = $args[0]

    ## Define functions
    function Test-ADOUExists {
        [CmdletBinding()]
        param(
            [parameter(Mandatory=$true,ValueFromPipeline=$true)]
            [string]$OUName,
            [parameter(Mandatory=$true)]
            [string]$ParentDistinguishedName
        )

        $OUDistinguishedName = "OU=" + $OUName + "," + $ParentDistinguishedName
        if (([adsisearcher]"distinguishedName=$OUDistinguishedName").FindAll().Count -gt 0) {
            $exists = $true
        }
        else {
            $exists = $false
        }
        $exists
    }

    ## Check whether or not Active Directory PowerShell module has been imported and, if not, import it
    $ExistingModules = (Get-Module | %{$_.name}) -join " "
    if (!$ExistingModules.Contains("ActiveDirectory")) {
        Import-Module "ActiveDirectory" -Force | Out-Null
    }

    ## Get the current domain information
    $Domain = Get-ADDomain

    ## Retrieve the CSV data from the web and sort it
    [array]$CSVData = Invoke-WebRequest -Uri $CSVURL |
        Select-Object -ExpandProperty Content |
        ConvertFrom-Csv |
        Sort-Object -Property CanonicalName

    ## Validate and create OUs based on the CSV data
    $ProcessedOUs = @()
    [int]$LoopCount = 0
    [int]$MaxLoopCount = 10
    do {
        $LoopCount++
        [array]$InProcessingOUs = $CSVData | ?{$ProcessedOUs -notcontains $_}
        foreach ($OU in $InProcessingOUs) {
            try {
                ## Define the object path and distinguished name
                [string]$Path = $OU.LocationPath + "," + $Domain.DistinguishedName

                ## If the OU doesn't exist, create it
                if ((Test-ADOUExists -OUName $OU.Name -ParentDistinguishedName $Path) -eq $false) {
                    ## Create a hash of the properties to use for splatting
                    $SplatHash = @{
                        Name = $OU.Name
                        DisplayName = $OU.Name
                        Path = $Path
                        ProtectFromAccidentalDeletion = $true
                        ErrorAction = 'Stop'
                        PassThru = $true
                    }

                    ## If other properties were supplied and are allowed by the cmdlet (sans 'OtherAttributes'), add them to the hash
                    $AllowedProperties = "City","Country","Description","ManagedBy","PostalCode","State","StreetAddress"
                    foreach ($Property in ($OU | Get-Member -MemberType NoteProperty)) {
                        if ($AllowedProperties -contains $Property.Name -and $OU.$($Property.Name) -notmatch '^$') {
                            $SplatHash.Add($Property.Name,$OU.$($Property.Name))
                        }
                    }

                    ## Create the OU
                    $ADOU = New-ADOrganizationalUnit @SplatHash
                }

                ## If the OU is specified as a Computer or User default location, configure that
                if ($OU.DefaultComputerOU -eq $true) {
                    redircmp.exe $Path
                }
                if ($OU.DefaultUserOU -eq $true) {
                    redirusr.exe $Path
                }

                ## Add the OU to the list of processed OUs
                $ProcessedOUs += $OU
            }
            catch {
                ## This Catch block is entered if the OU couldn't be created
                ## This prevents the OU from being added to the ProcessedOUs array
                ## We don't need to do anything else here right now
            }
        }
    }
    until ($ProcessedOUs.Count -eq $CSVData.Count -or
        $LoopCount -ge $MaxLoopCount)
}

[scriptblock]$configureGroups = {
    ## Save the input arguments as variables
    $CSVURL = $args[0]

    ## Define functions
    gunction Test-ADsAMAccountNameExists {
        [CmdletBinding()]
        param(
            [parameter(Mandatory=$true,ValueFromPipeline=$true)]
            [string]$sAMAccountName
        )

        if (([adsisearcher]"sAMAccountName=$sAMAccountName").FindAll().Count -gt 0) {
            $exists = $true
        }
        else {
            $exists = $false
        }
        $exists
    }

    ## Check whether or not Active Directory PowerShell module has been imported and, if not, import it
    $ExistingModules = (Get-Module | %{$_.name}) -join " "
    if (!$ExistingModules.Contains("ActiveDirectory")) {
        Import-Module "ActiveDirectory" -Force | Out-Null
    }

    ## Get the current domain information
    $Domain = Get-ADDomain

    ## Retrieve the CSV data from the web
    [array]$CSVData = Invoke-WebRequest -Uri $CSVURL |
        Select-Object -ExpandProperty Content |
        ConvertFrom-Csv

    ## Validate and create Groups based on the CSV data
    $ProcessedGroups = @()
    foreach ($Group in $CSVData) {
        try {
            ## Define the object path and distinguished name
            [string]$Path = $Group.LocationPath + "," + $Domain.DistinguishedName

            ## If the Group doesn't exist, create it
            if ((Test-ADsAMAccountNameExists -sAMAccountName $Group.Name) -eq $false) {
                ## Create a hash of the properties to use for splatting
                $SplatHash = @{
                    Name = $Group.Name
                    DisplayName = $Group.Name
                    Path = $Path
                    GroupScope = $Group.GroupScope
                    GroupCategory = $Group.GroupCategory
                    ErrorAction = 'Stop'
                    PassThru = $true
                }

                ## If other properties were supplied and are allowed by the cmdlet (sans 'OtherAttributes'), add them to the hash
                $AllowedProperties = "Description","HomePage","ManagedBy"
                foreach ($Property in ($OU | Get-Member -MemberType NoteProperty)) {
                    if ($AllowedProperties -contains $Property.Name -and $Group.$($Property.Name) -notmatch '^$') {
                        $SplatHash.Add($Property.Name,$Group.$($Property.Name))
                    }
                }

                ## Create the Group
                $ADGroup = New-ADGroup @SplatHash
            }

            ## Add a property to the group object with the list of groups it should be a member of
            $Group | Add-Member -MemberType NoteProperty -Name "ADGroupObj" -Value $ADGroup

            ## Add the Group to the list of processed Groups
            $ProcessedGroups += $Group
        }
        catch {
            ## This Catch block is entered if the Group couldn't be created
            ## This prevents the Group from being added to the ProcessedGroups array
            ## We don't need to do anything else here right now
        }
    }

    ## Add processed groups as a member of groups specified in the CSV data
    foreach ($Group in $ProcessedGroups) {
        ## Split the specified group membership data into an array of group names
        [string[]]$MemberOfGroups = $Group.MemberOf -split ';'

        ## Retrieve the existing group memberships
        $ExistingGroupMemberships = $Group.ADGroupObj.MemberOf | %{Get-ADGroup -Identity $_}

        ## Validate the group names and add the group to the validated groups
        foreach ($MGroup in $MemberOfGroups) {
            if ($ExistingGroupMemberships.Name -notcontains $MGroup) {
                ## If the group being processed is not already a member of the specified group
                if ((Test-ADsAMAccountNameExists -sAMAccountName $MGroup) -eq $false) {
                    ## If the specified group exists, add the group being processed to the specified group
                    Add-ADGroupMember -Identity $MGroup -Members $Group.Name
                }
            }
        }
    }
}

[scriptblock]$configureUsers = {
    ## Save the input arguments as variables
    $CSVURL = $args[0]
    $DNSSuffix = $args[1]
    $DefaultPassword = (ConvertTo-SecureString -String $args[2] -AsPlainText -Force)

    ## Define functions
    function Test-ADsAMAccountNameExists {
        [CmdletBinding()]
        param(
            [parameter(Mandatory=$true,ValueFromPipeline=$true)]
            [string]$sAMAccountName
        )

        if (([adsisearcher]"sAMAccountName=$sAMAccountName").FindAll().Count -gt 0) {
            $exists = $true
        }
        else {
            $exists = $false
        }
        $exists
    }

    function Test-ADUserDisplayNameExists {
        [CmdletBinding()]
        param(
            [parameter(Mandatory=$true,ValueFromPipeline=$true)]
            [string]$UserDisplayName
        )

        if (([adsisearcher]"(&(objectCategory=person)(objectClass=user)(DisplayName=$UserDisplayName))").FindAll().Count -gt 0) {
            $exists = $true
        }
        else {
            $exists = $false
        }
        $exists
    }

    function Generate-NewADUserName {
        [CmdletBinding()]
        param(
            [parameter(Mandatory=$true)][string]$GivenName,
            [parameter(Mandatory=$true)][string]$Surname,
            [ValidatePattern('[^"\[\]:;\|=\+*\?<>/\\,]')][string]$Separator = ".",
            [int]$GivenNameMaxChars = 20,
            [int]$SurnameMaxChars = 20,
            [bool]$AdminAccount = $false,
            [bool]$ServiceAccount = $false
        )

        [int]$UserNameMaxLength = 20

        ## if the user account is an admin account, append "a_" to the beginning of the given name.
        if ($AdminAccount) {
            $GivenName = "a_" + $GivenName
        }

        ## if the user account is a service account, append "s_" to the beginning of the given name.
        if ($ServiceAccount) {
            $GivenName = "s_" + $GivenName
        }

        ## Remove non-alphanumeric characters from the input Given Name, limiting length to the specified max characters
        if ($GivenName.Length -gt $GivenNameMaxChars) {
            [string]$PreSeparator = ($GivenName -replace "[^a-zA-Z]").Substring(0,$GivenNameMaxChars)
        }
        else {
            [string]$PreSeparator = $GivenName -replace "[^a-zA-Z]"
        }

        ## Same for the Surname and its specified max characters
        if ($Surname.Length -gt $SurnameMaxChars) {
            [string]$PostSeparator = ($Surname -replace "[^a-zA-Z]").Substring(0,$SurnameMaxChars)
        }
        else {
            [string]$PostSeparator = $Surname -replace "[^a-zA-Z]"
        }

        ## Generate the new username and validate it against AD, incrementing the result as needed
        [string]$NewUserName = ($PreSeparator + $Separator + $PostSeparator).ToLower()
        if ($NewUserName.Length -gt $UserNameMaxLength) {
            $NewUserName = $NewUserName.Substring(0,$UserNameMaxLength)
        }

        if ((Test-ADsAMAccountNameExists -sAMAccountName $NewUserName) -eq $true) {
            if ($NewUserName.Length -gt ($UserNameMaxLength - 2)) {
                $NewUserName = $NewUserName.Substring(0,($UserNameMaxLength - 2))
            }

            [int]$Incrementer = 0
            do {
                $Incrementer = $Incrementer + 1
                $NewUserName = ($NewUserName -replace "[^a-zA-Z$Separator]") + ($Incrementer.ToString("00"))
            }
            until ((Test-ADsAMAccountNameExists -sAMAccountName $NewUserName) -eq $false)
        }

        $NewUserName
    }

    ## Check whether or not Active Directory PowerShell module has been imported and, if not, import it
    $ExistingModules = (Get-Module | %{$_.name}) -join " "
    if (!$ExistingModules.Contains("ActiveDirectory")) {
        Import-Module "ActiveDirectory" -Force | Out-Null
    }

    ## Get the current domain information
    $Domain = Get-ADDomain

    ## Retrieve the CSV data from the web
    [array]$CSVData = Invoke-WebRequest -Uri $CSVURL |
        Select-Object -ExpandProperty Content |
        ConvertFrom-Csv |
        Sort-Object -Property CanonicalName

    ## Validate and create Users based on the CSV data
    $ProcessedUsers = @()
    foreach ($User in $CSVData) {
        try {
            ## If a user with a matching DisplayName doesn't exist, create it
            if ((Test-ADUserDisplayNameExists -UserDisplayName $User.Name) -eq $false) {
                ## Generate a sAMAccountName for the user
                $UserName = Generate-NewADUserName -GivenName $User.GivenName `
                    -Surname $User.Surname `
                    -GivenNameMaxChars 20 `
                    -SurnameMaxChars 20

                ## Define the object path and distinguished name
                [string]$Path = $User.LocationPath + "," + $Domain.DistinguishedName

                ## Define the UPN for the user
                $UserUPN = $UserName + "@" + $DNSSuffix

                ## Create a hash of the properties to use for splatting
                $SplatHash = @{
                    SamAccountName = $UserName
                    Path = $Path
                    UserPrincipalName = $UserUPN
                    AccountPassword = $User.Surname
                    Name = $User.Name
                    DisplayName = $User.Name
                    ErrorAction = 'Stop'
                    PassThru = $true
                }

                ## If other properties were supplied and are allowed by the cmdlet (sans 'OtherAttributes'), add them to the hash
                $AllowedProperties = "AccountExpirationDate","AccountNotDelegated","AllowReversiblePasswordEncryption","CannotChangePassword",
                    "ChangePasswordAtLogon","City","Company","Country","Department","Description","Division","EmailAddress","EmployeeID","EmployeeNumber",
                    "Enabled","Fax","GivenName","HomeDirectory","HomeDrive","HomePage","HomePhone","Initials","MobilePhone","Office","OfficePhone",
                    "Organization","OtherName","PasswordNeverExpires","POBox","PostalCode","ProfilePath","ScriptPath","SmartcardLogonRequired","State",
                    "StreetAddress","Surname","Title","TrustedForDelegation"

                foreach ($Property in ($OU | Get-Member -MemberType NoteProperty)) {
                    if ($AllowedProperties -contains $Property.Name -and $User.$($Property.Name) -notmatch '^$') {
                        $SplatHash.Add($Property.Name,$User.$($Property.Name))
                    }
                }

                ## If key properties aren't defined by the CSV, add default values
                if ($SplatHash.Keys -notcontains "ChangePasswordAtLogon") {
                    $SplatHash.Add("ChangePasswordAtLogon",$false)
                }
                if ($SplatHash.Keys -notcontains "Enabled") {
                    $SplatHash.Add("Enabled",$true)
                }
                if ($SplatHash.Keys -notcontains "PasswordNeverExpires") {
                    $SplatHash.Add("PasswordNeverExpires",$true)
                }

                ## Create the User
                $ADUser = New-ADUser @SplatHash
            }

            ## Add a property to the User object with the list of Users it should be a member of
            $User | Add-Member -MemberType NoteProperty -Name "ADUserObj" -Value $ADUser

            ## Add the User to the list of processed Users
            $ProcessedUsers += $User
        }
        catch {
            ## This Catch block is entered if the User couldn't be created
            ## This prevents the User from being added to the ProcessedUsers array
            ## We don't need to do anything else here right now
        }
    }

    ## Configure Managers and group memberships for processed Users based on the CSV data
    foreach ($User in $ProcessedUsers) {
        ## Retrieve the ADobject for the user's manager
        $Manager = Get-ADUser -Filter "DisplayName -eq $($User.ManagerDN)"

        ## If a user was returned, add them as the manager of the user being processed
        Set-ADUser -Identity $User.ADuserObj.SamAccountName -Manager $Manager.DistinguishedName

        ## Split the specified group membership data into an array of group names
        [string[]]$MemberOfGroups = $User.MemberOf -split ';'

        ## Retrieve the existing group memberships
        $ExistingGroupMemberships = $User.ADUserObj.MemberOf | %{Get-ADGroup -Identity $_}

        ## Validate the group names and add the User to the validated groups
        foreach ($MGroup in $MemberOfGroups) {
            if ($ExistingGroupMemberships.Name -notcontains $MGroup) {
                ## If the User being processed is not already a member of the specified group
                if ((Test-ADsAMAccountNameExists -sAMAccountName $MGroup) -eq $false) {
                    ## If the specified group exists, add the User being processed to the specified group
                    Add-ADGroupMember -Identity $MGroup -Members $User.ADUserObj.SamAccountName
                }
            }
        }
    }
}

[scriptblock]$configureGPOs = {
    ## I'll fill this out at a later point
}
#endregion

#region Data Validation
## Identify the domain name
$DomainName = $env:USERDOMAIN

## Build a credential object for the supplied domain admin credentials
$DomainCreds = New-Object System.Management.Automation.PSCredential (
    "$DomainName\$DomainAdminUsername",
    (ConvertTo-SecureString @"
$DomainAdminPassword
"@ -AsPlainText -Force))

## Test the supplied domain admin credentials
if ((Test-Credential -Credential $DomainCreds) -eq $false) {
    ## Log the account validation failure
    Write-Verbose -Verbose -Message "The supplied credentials for $($DomainName) failed to be validated; the process will be unable to inventory the servers in that domain."
    Write-Verbose -Verbose -Message "The credential validation failed for the account $($DomainCreds); please confirm account status and password accuracy, then update the Orchestrator variables."
    Write-Verbose -Verbose -Message "The script will now exit."
    exit
    }
else {
    Write-Verbose -Verbose -Message "The supplied credentials for $DomainName were validated successfully."
}

## Form the URLs for the CSVs
$CSVDataUrl = $CSVDataUrl.TrimEnd('/')
$OUDataUrl = $CSVDataUrl + "/ADDefaultObjects-OUs.csv"
$GroupDataUrl = $CSVDataUrl + "/ADDefaultObjects-Groups.csv"
$UserDataUrl = $CSVDataUrl + "/ADDefaultObjects-Users.csv"
#endregion

#region Process AD DNS Suffixes
try {
    Write-Verbose -Verbose -Message "Configuring allowed DNS suffixes ..."
    $DNSSuffix = Invoke-Command -Credential $DomainCreds -ComputerName $env:COMPUTERNAME -ScriptBlock $configureDNSSuffix
    Write-Verbose -Verbose -Message "Allowed DNS suffixes configured successfully."
}
catch {
    Write-Verbose -Verbose -Message "An error occurred while configuring allowed DNS suffixes."
    Write-Verbose -Verbose -Message "Exception: $($Error[0].Exception.Message)"
    Write-Verbose -Verbose -Message "The script will now exit."
    exit
}
#endregion

#region Process OUs
try {
    Write-Verbose -Verbose -Message "Configuring Organizational Units ..."
    Invoke-Command -Credential $DomainCreds -ComputerName $env:COMPUTERNAME -ScriptBlock $configureOUs -ArgumentList $OUDataUrl
    Write-Verbose -Verbose -Message "Organizational Units configured successfully."
}
catch {
    Write-Verbose -Verbose -Message "An error occurred while configuring Organizational Units."
    Write-Verbose -Verbose -Message "Exception: $($Error[0].Exception.Message)"
    Write-Verbose -Verbose -Message "The script will now exit."
    exit
}
#endregion

#region Process Groups
try {
    Write-Verbose -Verbose -Message "Configuring AD groups ..."
    Invoke-Command -Credential $DomainCreds -ComputerName $env:COMPUTERNAME -ScriptBlock $configureGroups -ArgumentList $GroupDataUrl
    Write-Verbose -Verbose -Message "AD groups configured successfully."
}
catch {
    Write-Verbose -Verbose -Message "An error occurred while configuring AD groups."
    Write-Verbose -Verbose -Message "Exception: $($Error[0].Exception.Message)"
    Write-Verbose -Verbose -Message "The script will now exit."
    exit
}
#endregion

#region Process Users
try {
    Write-Verbose -Verbose -Message "Configuring AD users ..."
    Invoke-Command -Credential $DomainCreds -ComputerName $env:COMPUTERNAME -ScriptBlock $configureUsers -ArgumentList $UserDataUrl,$DNSSuffix,$DefaultPassword
    Write-Verbose -Verbose -Message "AD users configured successfully."
}
catch {
    Write-Verbose -Verbose -Message "An error occurred while configuring AD users."
    Write-Verbose -Verbose -Message "Exception: $($Error[0].Exception.Message)"
    Write-Verbose -Verbose -Message "The script will now exit."
    exit
}
#endregion

#region Process GPOs

#endregion

#region Wrap Up
Write-Verbose -Verbose -Message "AD Object configuration complete."
Write-Verbose -Verbose -Message "Processing Time: $(New-TimeSpan -Start $StartTime -End (Get-Date))"
#endregion
