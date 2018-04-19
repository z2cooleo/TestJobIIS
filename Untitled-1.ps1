
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
try{
	New-Variable -Name 'pathToRootOfProj' -Value ([string](Split-Path -Parent $PSCommandPath)) `
		-Option Constant,AllScope -Description 'It is path to root of project'
	New-Variable -Name 'pathToFiles' -Value "$pathToRootOfProj\Files" `
		-Option Constant,AllScope -Description 'It is path to all of files of project'
	New-Variable -Name 'pathToLog' -Value "$pathToRootOfProj\Log" `
		-Option Constant,AllScope -Description 'It is path to all of files of project'
	New-Variable -Name 'quantityOfRemotePsConnectionAttempts' -Value ([int]30) -Option Constant `
		-Description 'Quantity of attempts to connect to remote VM via PS session'
	New-Variable -Name 'pathToDotNetOfflineInstaller' -Value "$pathToFiles\NDP452.exe" -Option Constant
	New-Variable -Name 'pathLocateSite' -Value "C:\inetpub\wwwroot" -Option Constant
	New-Variable -Name 'LinkForDownloadDotNetInstaller' -Value  "https://download.microsoft.com/download/3/5/9/35980F81-60F4-4DE3-88FC-8F962B97253B/NDP461-KB3102438-Web.exe"
}
catch{}

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
# Install .Net 4.5.2
install_dotNET -psSession $psSession -path $pathToDotNetOfflineInstaller -pathdownloaded "c:\tmp\1.exe" `
 -Link $LinkForDownloadDotNetInstaller -vmUser $VMUser -vmPass $VMPass
# Set pool for IIS
if(Get-Existence_IIS_pool -psSession $psSession -webPoolName "WebAppPool"){
	Set-IIS_pool -psSession $psSession -webPoolName "WebAppPool" 
}
elseif([array]::indexof($outListPool.name, "WebAppPool") -eq -1 ){
	Set-IIS_pool -psSession $psSession -webPoolName "WebAppPool" 
}
# Set Site into pool
if(Get-IIS_site -psSession $psSession -webSiteName "WebAppSite")
{
	Add-IIS_site -psSession $psSession -webSiteName "WebAppSite" 
}
elseif([array]::indexof($outListSite.name, "WebAppSite") -eq -1 ){
	Add-IIS_site -psSession $psSession -webSiteName "WebAppSite"
}
# Download site from GitHub
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri https://github.com/TargetProcess/DevOpsTaskJunior/archive/master.zip -OutFile "$pathToFiles\master.zip"
$isNeedUpgrade = Check-IsNeedUpdate -path "$pathToFiles\master.zip" -pathToDB "$pathToFiles\hash.zip"

#install site to VM
if($isNeedUpgrade) {
	Install-Site -psSession $psSession -strPathToFileSite "c:\inetpub\wwwroot" -strPathToSitePlace "c:\inetpub\wwwroot"
}

# Check Site
$siteName = "192.168.74.6:82"
$stat = Invoke-WebRequest $siteName

# Send report
curl -X POST -H 'Content-type: application/json' --data '{"text":"Hello, World!"}' https://hooks.slack.com/services/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

