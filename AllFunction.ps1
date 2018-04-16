<# ======================= Print ======================= #>
function Print-Failed {
	Param(
		[Parameter(Mandatory=$True)]
		$msg
	)
	PROCESS {
		New-Variable -Name 'dt' -Option Private

		$dt = Get-Date -Format "yyyy.MM.dd HH:mm:ss"
		Write-Output "[$dt] FAILED: $msg"

		Remove-Variable -Name 'dt'
	}
}
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

function Print-INFO {
	Param(
		[Parameter(Mandatory=$True)]
		$msg
	)
	PROCESS {
		New-Variable -Name 'dt' -Option Private

		$dt = Get-Date -Format "yyyy.MM.dd HH:mm:ss"
		write-output "[$dt] INFO: $msg"

		Remove-Variable -Name 'dt'
	}
}
function Print-PASSED {
	Param(
		[Parameter(Mandatory=$True)]
		$msg
	)
	PROCESS {
		New-Variable -Name 'dt' -Option Private

		$dt = Get-Date -Format "yyyy.MM.dd HH:mm:ss"
		Write-Output "[$dt] PASSED: $msg"

		Remove-Variable -Name 'dt'
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
		[Array]$pathToFile
	)
	PROCESS {
		$var = Invoke-Command -Session $psSession -ScriptBlock { 
			Get-ItemProperty -Path "hklm:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" 
		}
		if($var.Release -ge 379893) {}
		else{

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
function Check-NeedUpdateFromGit {
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
function Set-SiteFromGit {
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
function Set-RightToSite {
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
function Check-IsRunSite {
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