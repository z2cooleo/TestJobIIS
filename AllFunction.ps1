
function Exit-AfterError {
	Param(
		[Parameter(Mandatory=$True)]
		$msg
	)
	PROCESS{
		Print-Failed $msg
		throw "$ST_AUTOTEST_ERROR_EXCEPTION $msg"
	}
}


function wait {
	Param (
		[Parameter(Mandatory=$True)]
		[int]$intSeconds
	)
	PROCESS{
		Print-INFO "Wait for '$intSeconds' seconds..."
		sleep -Seconds $intSeconds
	}
}
function initialRemotePsSessionConfig {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession
	)
	PROCESS {
		Write-Debug ($MyInvocation.MyCommand.Name + ': FINISH')
        Set-Variable -Name 'psSession' -Option ReadOnly,Private

		invoke-command -Session $psSession `
			-scriptBlock `
			{
				New-Variable -Name 'REMOTE_ERROR' -Value ([string]'REMOTE_ERROR ') -Option Constant `
					-Description 'Uses in catch code blocks'
				New-Variable -Name 'LOG_TAB' -Value ([string]'    ') -Option Constant `
					-Description 'It is indent'

				$RPS_SETTING = 'REMOTE_PS_SESSION_SETTING:'
				$ErrorActionPreference = 'Stop'
				Write-Output "$RPS_SETTING `$ErrorActionPreference is '$ErrorActionPreference'"
				Write-Output "$RPS_SETTING `$DebugPreference is '$DebugPreference'"
			}

		Write-Debug ($MyInvocation.MyCommand.Name + ': START' )
	}
}
function CreateRemotePsSession{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[string]$vmName,

		[Parameter(Mandatory=$True)]
		[string]$vmUser,

		[Parameter(Mandatory=$True)]
		[string]$vmPass,

		[Parameter(Mandatory=$True)]
		[string]$outVarNameForSession
	)
	PROCESS {
		Print-INFO "CreateRemotePsSession: start"
        Set-Variable -Name 'vmName' -Option ReadOnly,Private
        Set-Variable -Name 'vmUser' -Option ReadOnly,Private
        Set-Variable -Name 'vmPass' -Option ReadOnly,Private
        Set-Variable -Name 'outVarNameForSession' -Option ReadOnly,Private

		New-Variable -Name 'pw' -Option Private
		New-Variable -Name 'cred' -Option Private
		New-Variable -Name 'i' -Option Private
		New-Variable -Name 'session' -Option Private

		$pw = ConvertTo-SecureString -AsPlainText -Force -String $vmPass
		$cred = new-object -typeName System.Management.Automation.PSCredential -argumentList $vmUser,$pw
		[int]$i = 1
		do { 
			Print-INFO "Try to establish remote connection with '$vmName' comp. Attempt number '$i'"
			try {
				[System.Management.Automation.Runspaces.PSSession]$session = 
							 New-PSSession -ComputerName $vmName -Credential $cred
			} 
			catch [NetworkPathNotFound]{################
				Write-Host "213"
			}
			catch [LogonFailure]{
				Write-Host "213"
			}
			catch {
				Print-INFO "Attempt number '$i' is failure"
			}
			if ($session -ne $null) {
				break
			}
			if ($i -eq $p_quantityOfRemotePsConnectionAttempts) {
				Exit-AfterError "PowerShell remote connection with '$vmName' is not established `
					after '$p_quantityOfRemotePsConnectionAttempts' attempts."
			}

			wait 10
			$i++
		} while ($true)
		Print-INFO "Remote connection with '$vmName' comp is established"
		
		initialRemotePsSessionConfig -psSession $session

		Set-Variable -Name $outVarNameForSession -Value $session -Scope 1
		Print-INFO "$MyInvocation.MyCommand.Name + ': finish'"
	}
}
function install_IIS_Role {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[Array]$arrayListRole
	)
	PROCESS {
		$listRole = Invoke-Command -Session $psSession -ScriptBlock { Get-WindowsFeature -Name web* }
		$listForInstall = @()
		foreach($item in $arrayListRole)
		{
			$r = $listRole | Where-Object {$_.name -eq $item}
			if($r.InstallState -eq "Available")
			{
				$listForInstall += $item
			}
		}
		foreach($i in $listForInstall)
		{
			$resultInstallRole = Invoke-Command -Session $psSession -ScriptBlock { 
				Param($roleName)
				Add-WindowsFeature -Name $roleName
			} -ArgumentList $i
		}
    }
}
function install_dotNET {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[Alias('path')]
		[String]$pathToFile
	)
	Begin{
		New-Variable -Name file -Value [io.file]::ReadAllBytes($pathToFile)
	}
	PROCESS {
		$var = Invoke-Command -Session $psSession -ScriptBlock { 
			Get-ItemProperty -Path "hklm:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" 
		}
		if($var.Release -ge 379893) {}
		else{
			$sriptBlock = {
				Param(
					[Parameter(Mandatory=$true)]
					[io.file]$file
				)
				function Test-PendingReboot
				{
					if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
					if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
					if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true }
					try { 
						$util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
						$status = $util.DetermineIfRebootPending()
						if(($status -ne $null) -and $status.RebootPending){ return $true }
					}
					catch{}					
					return $false
				}
				[Io.file]::WriteAllBytes("%temp%\dotnet.exe", $file)
				Unblock-File -LiteralPath "%temp%\dotnet.exe"
				Start-Process -FilePath "%temp%\dotnet.exe" -ArgumentList "/norestart"
				}				
			$var = Invoke-Command -Session $psSession -ScriptBlock $sriptBlock -ArgumentList $file
			if([string]$var -eq "True"){
				Restart-Computer -ComputerName $psSession.ComputerName -Credential $psSession -Wait -For PowerShell -Timeout 300 -Delay 2 -Force 
			}	
		}		
    }
}
function Check-Existence_IIS_Role {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$strProcessName,

		[Parameter(Mandatory=$True)]
		[bool]$boolExpectedExistenceState,

		[Parameter(Mandatory=$True)]
		[int]$intTimeoutInSeconds,

		[Parameter(Mandatory=$false)]
		[string]$strAddOnFailMsg = ' '
	)
    BEGIN {

    }
	PROCESS {

    }
    END {
        
    }
}
function Get-Existence_IIS_pool {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$webPoolName,
		
		[Parameter(Mandatory=$false)]
		$outListpool,

		[Parameter(Mandatory=$false)]
		$isNeedSetPool
	)
	PROCESS {
		$listPool = Invoke-Command -Session $psSession -ScriptBlock { 
			Param($webPoolName)
			Import-Module WebAdministration
			Get-ChildItem -Path "IIS:\AppPools"
		} -ArgumentList $webPoolName

		if([string]::IsNullOrEmpty($listPool)) { 
			$True
		}
		else{ 
			Set-Variable -Name outListPool -Value $listPool -Scope global
			$false
		}		
    }
}

function Set-IIS_pool {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$webPoolName
	)
	PROCESS {
		Invoke-Command -Session $psSession -ScriptBlock {
			Param($webPoolName)
			New-WebAppPool -name $webPoolName -force
		} -ArgumentList $webPoolName
    }
}
function Get-IIS_site {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$webSiteName,
		
		[Parameter(Mandatory=$false)]
		$outListSite,

		[Parameter(Mandatory=$false)]
		$isNeedSetSite
	)
	PROCESS {
		$listSite = Invoke-Command -Session $psSession -ScriptBlock {
			Get-ChildItem -Path IIS:\Sites
		}

		if([string]::IsNullOrEmpty($listSite)) { 
			$True
		}
		else { 
			Set-Variable -Name outListSite -Value $listSite -Scope global
			$false
		}		
    }
}
function Add-IIS_site {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$webSiteName
	)
	PROCESS {
		Invoke-Command -Session $psSession -ScriptBlock {
			Param($webSiteName)
			New-WebSite -Name $webSiteName -ApplicationPool "WebAppPool" -Port 82 -PhysicalPath "C:\inetpub\wwwroot"
		} -ArgumentList $webSiteName
    }
}
function Attach-SiteToPool {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$strPathToTestedBuild,

		[Parameter(Mandatory=$True)]
		[string]$strComponents
	)
    BEGIN {

    }
	PROCESS {

    }
    END {
        
    }
}
function Check-IsNeedUpdate {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[alias("Path")]
		[string]$strPathToZipFile,

		[Parameter(Mandatory=$True)]
		[alias("PathToDB")]
		[string]$PathtoStorageDB
	)
    PROCESS {
		if(Test-Path -Path $PathtoStorageDB){
			$hashOldSite = Import-Clixml -Path $PathtoStorageDB
			Remove-Item -Path $PathtoStorageDB
		}
		else {
			$hashOldSite = @{}
		}		
		$hashNewSite = Get-FileHash -Path $strPathToZipFile -Algorithm SHA256
		if($hashOldSite -eq $hashNewSite) {
			$hashNewSite | Export-Clixml -Path $PathtoStorageDB
			return $false
		}
		else{
			$hashNewSite | Export-Clixml -Path $PathtoStorageDB
			return $true			
		}
    }
}

function Install-Site {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$strPathToFileSite,

		[Parameter(Mandatory=$True)]
		[string]$strPathToSitePlace
	)
	PROCESS {
		New-Variable -Name file -Value [io.file]::ReadAllBytes($strPathToFileSite)
		$sriptBlock = {
			Param(
				[Parameter(Mandatory=$true)]
				[io.file]$file
			)
			[Io.file]::WriteAllBytes("$strPathToSitePlace\master.zip", $file)
			Get-ChildItem "$strPathToSitePlace\master.zip" | Expand-Archive -DestinationPath $strPathToSitePlace
			$acl = Get-Acl $strPathToSitePlace
			$a = "IIS","FullControl","Allow"
			$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($a)
			$acl.SetAccessRule($accessRule)
			$acl | Set-Acl $strPathToSitePlace
		}
    }
}
function Check-IsRun_IIS {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$strPathToTestedBuild,

		[Parameter(Mandatory=$True)]
		[string]$strComponents
	)
    BEGIN {

    }
	PROCESS {

    }
    END {
        
    }
}
function Run-IIS_Server {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$strPathToTestedBuild,

		[Parameter(Mandatory=$True)]
		[string]$strComponents
	)
    BEGIN {

    }
	PROCESS {

    }
    END {
        
    }
}
