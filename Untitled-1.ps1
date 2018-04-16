<#
https://4sysops.com/archives/create-web-apps-and-application-pools-in-iis-with-powershell/
https://gist.github.com/ifrahim/9231677
#>

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
begin{
	$ErrorActionPreference = "Stop"
	try{
		New-Variable -Name 'pathToRootOfProj' -Value ([string](Split-Path -Parent $PSCommandPath)) `
			-Option Constant,AllScope -Description 'It is path to root of project'
		New-Variable -Name 'quantityOfRemotePsConnectionAttempts' -Value ([int]30) -Option Constant `
			-Description 'Quantity of attempts to connect to remote VM via PS session'
		New-Variable -Name 'pathToFile' -Value $pathToRootOfProj/Files -Option Constant `
			-Description 'It is path where save all of files'
	}
	catch{
	
	}
}
PROCESS{
. "$pathToRootOfProj\AllFunction.ps1"
. "$pathToRootOfProj\Print.ps1"

createRemotePsSession -vmName $VMToRun -vmUser $VMUser -vmPass $VMPass `
	-outVarNameForSession 'psSession'

[Array]$roleList = @("Web-Server", "web-mgmt-console", "Web-ASP", "Web-Asp-Net45")
install_IIS_Role -psSession $psSession -arrayListRole $roleList

$path=$pathToRootOfProj+"\NDP452.exe"
install_dotNET -psSession $psSession -path $path

if(Get-Existence_IIS_pool -psSession $psSession -webPoolName "WebAppPool"){
	Set-IIS_pool -psSession $psSession -webPoolName "WebAppPool" 
}
elseif([array]::indexof($outListPool.name, "WebAppPool") -eq -1 ){
	Set-IIS_pool -psSession $psSession -webPoolName "WebAppPool" 
}

if(Get-IIS_site -psSession $psSession -webSiteName "WebAppSite")
{
	Add-IIS_site -psSession $psSession -webSiteName "WebAppSite" 
}
elseif([array]::indexof($outListSite.name, "WebAppSite") -eq -1 ){
	Add-IIS_site -psSession $psSession -webSiteName "WebAppSite"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri https://github.com/TargetProcess/DevOpsTaskJunior/archive/master.zip -OutFile "$pathToRootOfProj\master.zip"
}