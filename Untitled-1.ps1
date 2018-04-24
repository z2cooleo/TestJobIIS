
[CmdletBinding()]
Param (
    [parameter(Mandatory = $false, Position = 0)]
	[alias("namePC")]
	[string]$VMToRun = 'win12x64-6.my.net',

	[parameter(Mandatory = $false, Position = 0)]
	[alias("User")]
	[string]$VMUser = 'my\admin',

	[parameter(Mandatory = $false, Position = 0)]
	[alias("Pass")]
    [string]$VMPass = 'Aa147963'
)

$ErrorActionPreference = "Stop"

New-Variable -Name 'pathToRootOfProj' -Value ([string](Split-Path -Parent $PSCommandPath)) `
	-Option Constant,AllScope -Description 'It is path to root of project'
New-Variable -Name 'pathToFiles' -Value "$pathToRootOfProj\Files" `
	-Option Constant,AllScope -Description 'It is path to all of files of project'
New-Variable -Name 'pathToLog' -Value "$pathToRootOfProj\Log" `
	-Option Constant,AllScope -Description 'It is path to all of files of project'
New-Variable -Name 'quantityOfRemotePsConnectionAttempts' -Value ([int]30) -Option Constant `
	-Description 'Quantity of attempts to connect to remote VM via PS session'
New-Variable -Name 'pathRemoteLocateSite' -Value "C:\inetpub\wwwroot" -Option Constant
New-Variable -Name 'port' -Value 80 -Option Constant
New-Variable -Name 'webPoolName' -Value "WebAppPool"
New-Variable -Name 'webSiteName' -Value "MyWebApp"
New-Variable -Name "GitHubUrlToSite" -Value "https://github.com/TargetProcess/DevOpsTaskJunior/archive/master.zip"
New-Variable -Name 'LinkForDownloadDotNetInstaller' -Value  "https://download.microsoft.com/download/3/5/9/35980F81-60F4-4DE3-88FC-8F962B97253B/NDP461-KB3102438-Web.exe"


. "$pathToRootOfProj\AllFunction.ps1"
. "$pathToRootOfProj\Print.ps1"
. "$pathToRootOfProj\File.ps1"

Print-INFO "************"
Print-INFO "Start script"
Print-INFO "************"

createRemotePsSession -vmName $VMToRun -vmUser $VMUser -vmPass $VMPass `
	-outVarNameForSession 'psSession'
# Install Role IIS
[Array]$roleList = @("Web-Server", "web-mgmt-console", "Web-ASP", "Web-Asp-Net45")
install_IIS_Role -psSession $psSession -arrayListRole $roleList
# Set pool for IIS
Check-Existence_IIS_pool -psSession $psSession -webPoolName $webPoolName -outBool "boolIsNeedSetPool"
if($boolIsNeedSetPool){
	Set-IIS_pool -psSession $psSession -webPoolName $webPoolName
}
elseif([array]::indexof($outListPool.name, "WebAppPool") -eq -1 ){
	Set-IIS_pool -psSession $psSession -webPoolName $webPoolName 
}
# Set Site into pool
Get-IIS_site -psSession $psSession -webSiteName $webSiteName -outBool "boolIsNeedSetSite"
if($boolIsNeedSetSite)
{
	Add-IIS_site -psSession $psSession -webSiteName $webSiteName -port $port -pathLocateSite $pathRemoteLocateSite -poolName $webPoolName
}
# Download site from GitHub
if(Test-Path -Path "$pathToFiles\master.zip"){
	Remove-Item -Path "$pathToFiles\master.zip"
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $GitHubUrlToSite -OutFile "$pathToFiles\master.zip"
Check-IsNeedUpdate -path "$pathToFiles\master.zip" -pathToDB "$pathToFiles\hash.hs" -outIsNeedUpgrade "isNeedUpgrade"

#install site to VM
if($isNeedUpgrade) {
	Install-Site -psSession $psSession -uri $GitHubUrlToSite -strPathToLocalStorageFileSite "$pathToFiles\master.zip" `
			 -strPathToRemotePCSitePlace $pathRemoteLocateSite
}

# Check Site
try{
	$stat = Invoke-WebRequest $VMToRun
}
Catch{
	Print-Failed "$_.Exception.Message"
}

# Send report
if($stat.StatusCode -eq 200){
	$hookUri = "https://hooks.slack.com/services/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"

	$payload = @{
		"text" = "!!!Success!!!"		
	}	
	Invoke-WebRequest -Method POST -Body (ConvertTo-Json -Compress -InputObject $payload) -UseBasicParsing -Uri $hookUri | Out-Null
	$payload = @{
		"text" = " GitHub - https://github.com/z2cooleo/TestJobIIS/archive/master.zip"		
	}	
	Invoke-WebRequest -Method POST -Body (ConvertTo-Json -Compress -InputObject $payload) -UseBasicParsing -Uri $hookUri | Out-Null 
	$payload = @{
		"text" = " eMail: Z2.cooleo@gmail.com"		
	}	
	Invoke-WebRequest -Method POST -Body (ConvertTo-Json -Compress -InputObject $payload) -UseBasicParsing -Uri $hookUri | Out-Null 
	$payload = @{
		"text" = " Creator: Makhortov Denis"		
	}	
	Invoke-WebRequest -Method POST -Body (ConvertTo-Json -Compress -InputObject $payload) -UseBasicParsing -Uri $hookUri | Out-Null
}



Remove-Variable -Name 'pathToRootOfProj' -Force
Remove-Variable -Name 'pathToFiles'  -Force
Remove-Variable -Name 'pathToLog'  -Force
Remove-Variable -Name 'quantityOfRemotePsConnectionAttempts'  -Force
Remove-Variable -Name 'pathToDotNetOfflineInstaller'  -Force
Remove-Variable -Name 'pathRemoteLocateSite' -Force
Remove-Variable -Name 'port'  -Force
Remove-Variable -Name 'webPoolName' -Force
Remove-Variable -Name 'webSiteName' -Force
Remove-Variable -Name "GitHubUrlToSite"  -Force
Remove-Variable -Name 'LinkForDownloadDotNetInstaller' -Force