Function Convert-SSToString([System.Security.SecureString]$ObsPass){
    return [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ObsPass))
}
function Create-OctoSecret{
    param(
         [parameter(Mandatory=$true)][String]$SecretName,
         [parameter(Mandatory=$true)][String]$ServiceName,
         [parameter(Mandatory=$true)][String]$Username,
         [parameter(Mandatory=$true)][String]$UPN,
         [parameter(Mandatory=$true)][String]$token,
         [parameter(Mandatory=$true)][ValidateSet("A" , "B")][String]$HA,
         [String]$Notes
    )
    switch ($HA){
        'A'{$folderId = 238}
        'B'{$folderId = 239}
    }
    $Domain = "domain.local" #Domain is always coyo
    #$folderId = 233 #Folder for the Test OctoActs
    $templateId = 6046 #Template for OctoActs w/ SAM
    $secretItemFields =  $proxy.GetSecretTemplateFields($token, $templateId).fields.id
    #order is Domain, Service, Username, UserPrincipal, Pass, Notes
    $secretItemValues = ($Domain,$ServiceName,$Username,$UPN, $proxy.GeneratePassword($token, 279).GeneratedPassword, $Notes)
    #to add a whole secret
    $proxy.AddSecret($token, $templateId, $secretName, $secretItemFields, $secretItemValues, $folderId)
}
function Get-Token{
param(
[String]$RSAToken, 
[PSCredential]$cred
)
    $result = $proxy.AuthenticateRADIUS($cred.UserName, (Convert-SSToString $cred.Password), '', 'domain', $RSAToken)
    if ($result.Errors.length -gt 0){
        throw $result.Errors[0]
    } 
    else 
    {
        return $result.Token    
    }
}
function Create-Dependency{
    param(
        [parameter(Mandatory=$true)][int]$SecretID,
        [parameter(Mandatory=$true)][ValidateSet("Octopus")][String]$DependencyType
    )
    
    #make a new dependency
    $NewDependency = [SecretServer.Dependency]::new()
    $NewDependency.AdditionalInfo = [SecretServer.AdditionalDependencyInfoJson]::new()
    switch($DependencyType){
        'Octopus'{
        #set fields for octo
            $NewDependency.SecretId = $SecretID
            $NewDependency.SecretDependencyTypeId = 7
            $NewDependency.MachineName = "Octopus"
            $NewDependency.ServiceName = "OctoService"
            $NewDependency.PrivilegedAccountSecretId = 1003
            $NewDependency.Active = $true
            $NewDependency.RestartOnPasswordChange = $false
            $NewDependency.Description = "Octopus Update Script"
            $NewDependency.ScriptId = 1010
            $NewDependency.AdditionalInfo.PowershellArguments = '$UserPrincipal $Service $Password'
        }
    }
    $result = $proxy.AddDependency($token, $NewDependency)

    if($result.Errors -gt 0){
        throw $result.Errors[0]
    }
}
function Check-UsernameExists{
    param(
    [String]$Username,
    [String]$token
    )
    #Returns whether or not the AD username is somewhere else in SS
    return ($proxy.SearchSecretsByFieldValue($token, "Username", $Username, $false, $true).secretsummaries.count -gt 0)
}

#initialize token for api

$url = 'https://[SS Host]/webservices/sswebservice.asmx'
if($proxy -eq $null){
    $proxy = New-WebServiceProxy -uri $url -Namespace "SecretServer"
}
$cred = Get-Credential "$env:USERNAME"
$radiusPassword = (Read-Host -Prompt "RSA Pass")
try{
    $token = Get-Token -RSAToken $radiusPassword -cred $cred
}catch{
    write-host $Error[0]
    exit
    }

#Grab Secret Objects
#import objects via csv
$secrets = import-csv "[pathToCSV]"
#converts to UPN for compatability
$secrets | %{$_ | Add-Member –MemberType NoteProperty –Name SAM –Value ($_.UPN[0..19] -join '')}
#arrays for storing results
$ErrorActs =  New-Object System.Collections.ArrayList
$Successes =  New-Object System.Collections.ArrayList

foreach($s in $secrets){
    if(-not (Check-UsernameExists -Username $s.SAM -token $token)){
        try{
            $createdSecret = Create-OctoSecret -SecretName $s.SAM -Username $s.SAM -ServiceName $s.Service -UPN $s.UPN -Notes '' -token $token -HA $s.SAM.ToUpper()[0]
            Create-Dependency -SecretID $createdSecret.Secret.ID -DependencyType Octopus
            $Successes.Add($s.SAM) | out-null
        }catch{

        $ErrorActs.Add((New-Object -TypeName PSObject -Property @{'Account' = $s.SAM; 'Error' = $Error[0]})) | out-null

        }
    }else{
        $ErrorActs.Add((New-Object -TypeName PSObject -Property @{'Account' = $s.SAM; 'Error' = "Account Already Exists"})) | out-null
    }
}

$Successes.count
$ErrorActs.count