
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
	New-Variable -Name 'pathToFile' -Value "$pathToRootOfProj\File" `
		-Option Constant,AllScope -Description 'It is path to all of files of project'
	New-Variable -Name 'pathTolog' -Value "$pathToRootOfProj\Log" `
		-Option Constant,AllScope -Description 'It is path to all of files of project'
	New-Variable -Name 'quantityOfRemotePsConnectionAttempts' -Value ([int]30) -Option Constant `
		-Description 'Quantity of attempts to connect to remote VM via PS session'
}
catch{}

. "$pathToRootOfProj\AllFunction.ps1"
. "$pathToRootOfProj\Print.ps1"
. "$pathToRootOfProj\File.ps1"

createRemotePsSession -vmName $VMToRun -vmUser $VMUser -vmPass $VMPass `
	-outVarNameForSession 'psSession'
# Install Role IIS
[Array]$roleList = @("Web-Server", "web-mgmt-console", "Web-ASP", "Web-Asp-Net45")
install_IIS_Role -psSession $psSession -arrayListRole $roleList
# Install .Net 4.5.2
$path=$pathToRootOfProj+"\NDP452.exe"
install_dotNET -psSession $psSession -path $path
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
Invoke-WebRequest -Uri https://github.com/TargetProcess/DevOpsTaskJunior/archive/master.zip -OutFile "$pathToFile\master.zip"
$isNeedUpgrade = Check-IsNeedUpdate -path "$pathToFile\master.zip" -pathToDB "$pathToFile\hash.zip"

#install site to VM


# Check Site
$siteName = "192.168.74.6:82"
$stat = Invoke-WebRequest $siteName

# Send report
if($stat.StatusCode -eq 200){
	curl -X POST -H 'Content-type: application/json' --data '{"text":"Hello, World!"}' https://hooks.slack.com/services/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
}
else{

}

# Get the work of my dreams :)