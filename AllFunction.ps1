

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
	Begin{
		Write-Debug ($MyInvocation.MyCommand.Name + ': FINISH')
        Set-Variable -Name 'psSession' -Option ReadOnly,Private
	}
	PROCESS {
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
	Begin{
		Print-INFO "CreateRemotePsSession: start"
        Set-Variable -Name 'vmName' -Option ReadOnly,Private
        Set-Variable -Name 'vmUser' -Option ReadOnly,Private
        Set-Variable -Name 'vmPass' -Option ReadOnly,Private
        Set-Variable -Name 'outVarNameForSession' -Option ReadOnly,Private

		New-Variable -Name 'pw' -Option Private
		New-Variable -Name 'cred' -Option Private
		New-Variable -Name 'i' -Option Private
		New-Variable -Name 'session' -Option Private
	}
	PROCESS {
		$pw = ConvertTo-SecureString -AsPlainText -Force -String $vmPass
		$cred = new-object -typeName System.Management.Automation.PSCredential -argumentList $vmUser,$pw
		[int]$i = 1
		do { 
			Print-INFO "Try to establish remote connection with '$vmName' comp. Attempt number '$i'"
			try {
				[System.Management.Automation.Runspaces.PSSession]$session = 
							 New-PSSession -ComputerName $vmName -Credential $cred
			} 
			catch {
				Print-INFO "Attempt number '$i' is failure"
				Print-INFO "$_.Exception.Message"		
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
	end{
		Remove-Variable -Name 'vmName' -force
        Remove-Variable -Name 'vmUser' -force
        Remove-Variable -Name 'vmPass' -force

		Remove-Variable -Name 'pw' -force
		Remove-Variable -Name 'cred' -force
		Remove-Variable -Name 'i' -force
		Remove-Variable -Name 'session' -force
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
		Print-INFO "installing the necessary windows components"
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
		Print-INFO "Components for installation: $listForInstall"
		foreach($i in $listForInstall)
		{
			Print-INFO "installing $i"
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
		[Alias('path', 'pathToDotNetOfflineInstaller')]
		[String]$pathToFile,

		[Parameter(Mandatory=$True)]
		[String]$pathdownloaded,

		[Parameter(Mandatory=$True)]
		[string]$vmUser,

		[Parameter(Mandatory=$True)]
		[string]$vmPass,

		[Parameter(Mandatory=$True)]
		[String]$link
	)
	Begin{
		New-Variable -Name file 
		try{
			invoke-webrequest $link -DisableKeepAlive -UseBasicParsing -Method head
		}
		catch{
			Exit-AfterError $_
		}
	}
	PROCESS {
		Print-INFO "Check for updating .Net"
		$var = Invoke-Command -Session $psSession -ScriptBlock { 
			Get-ItemProperty -Path "hklm:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" 
		}
		if($var.Release -ge 379893) {
			Print-INFO "Updating .Net is not requred"
		}
		else{
			Print-INFO "Updating .Net requred"
			$sriptBlockInstall = {
				Param(
					[Parameter(Mandatory=$true)]
					[string]$link,
					[Parameter(Mandatory=$true)]
					[string]$pathdownloaded
				)						
				Invoke-WebRequest -Uri $link -OutFile $pathdownloaded
				Start-Process -FilePath $pathdownloaded -ArgumentList "/q /norestart /SkipMSUInstall /log c:\tmp\txt.txt" -Wait				
				Remove-Item -Path $pathdownloaded
			}	
			$scriptblockCheckRebootPending = {
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
				Test-PendingReboot
			}
			try{
				$var = Invoke-Command -Session $psSession -ScriptBlock $scriptblockCheckRebootPending		
				if([string]$var -eq "True"){ #todo
					New-Variable -Name 'pw' -Option Private
					$pw = ConvertTo-SecureString -AsPlainText -Force -String $vmPass
					$cred = new-object -typeName System.Management.Automation.PSCredential -argumentList $vmUser,$pw
					Restart-Computer -ComputerName $psSession.ComputerName -Credential $cred -Wait -For PowerShell -Timeout 300 -Delay 2 -Force 
				}	
				Invoke-Command -Session $psSession -ScriptBlock $sriptBlockInstall -ArgumentList $link, $pathdownloaded
				$var = Invoke-Command -Session $psSession -ScriptBlock $scriptblockCheckRebootPending			
				if([string]$var -eq "True"){
					New-Variable -Name 'pw' -Option Private
					$pw = ConvertTo-SecureString -AsPlainText -Force -String $vmPass
					$cred = new-object -typeName System.Management.Automation.PSCredential -argumentList $vmUser,$pw
					Restart-Computer -ComputerName $psSession.ComputerName -Credential $cred -Wait -For PowerShell -Timeout 300 -Delay 2 -Force 
				}
			}
			catch{
				Exit-AfterError $_
			}
		}		
	}
	End{
		Remove-Variable -Name file
	}
}
function New-StepVar {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[string]$Name,

		[Parameter(Mandatory=$false)]
		$Value,

		[Parameter(Mandatory=$false)]
		[int]$Scope = 2
	)
	PROCESS {
		Set-Variable -Name 'Name' -Option Private,ReadOnly
		Set-Variable -Name 'Value' -Option Private,ReadOnly
		Set-Variable -Name 'Scope' -Option Private,ReadOnly

		if (Get-Variable -Name $Name -Scope $Scope -ErrorAction SilentlyContinue) {
			# $true # Variable is present
			Clear-Variable -Name $Name -Scope $Scope
		} else {
			# $false # Variable is absent
			New-Variable -Name $Name -Option Private -Scope $Scope
		}

		if ($Value -ne $null) {
			Set-Variable -Name $Name -Value $Value -Scope $Scope
		}
	}
 }
function Check-Existence_IIS_pool {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$webPoolName,

		[Parameter(Mandatory=$False)]
		$outBool
	)
	PROCESS {
		Print-INFO "Get current exist POOL"		

		$listPool = Invoke-Command -Session $psSession -ScriptBlock { 
			Param($webPoolName)
			Import-Module WebAdministration
			Get-ChildItem -Path "IIS:\AppPools"
		} -ArgumentList $webPoolName
		Print-INFO $listPool.name
		if([string]::IsNullOrEmpty($listPool) ) { 
			Print-INFO "List of pool is NULL"
			New-StepVar -Name $outBool -Value $True # Requared set pool
		}
		elseif(!($listPool.name -contains $webPoolName)){ 
			Print-INFO "List of pool is not contain $webPoolName"
			Set-Variable -Name outListPool -Value $listPool -Scope global
			New-StepVar -Name $outBool -Value $True # Requared set pool
		}
		else{
			Print-INFO "List of pool is contain $webPoolName"
			Set-Variable -Name outListPool -Value $listPool -Scope global
			New-StepVar -Name $outBool -Value $False
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
		Print-Info "Set Pool: $webPoolName"
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
		$outBool
	)
	PROCESS {
		Print-INFO "Check current site"
		$listSite = Invoke-Command -Session $psSession -ScriptBlock {
			Get-ChildItem -Path IIS:\Sites
		}
		Print-INFO "Exist site:" 
		Print-INFO $listSite.name

		if([string]::IsNullOrEmpty($listSite)) { 
			New-StepVar -Name $outBool -Value $True # Requared set the Site
		}
		elseif($listSite.name -notcontains $webSiteName){
			Set-Variable -Name outListSite -Value $listSite -Scope global
			New-StepVar -Name $outBool -Value $True # Requared set the Site
		}
		else { 
			Set-Variable -Name outListSite -Value $listSite -Scope global
			New-StepVar -Name $outBool -Value $false
		}		
    }
}
function Add-IIS_site {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$pathLocateSite,

		[Parameter(Mandatory=$True)]
		[string]$webSiteName,
		
		[Parameter(Mandatory=$True)]
		[string]$port,

		[Parameter(Mandatory=$True)]
		[string]$poolName		
	)
	PROCESS {
		Print-INFO "Add site to IIS"

		Invoke-Command -Session $psSession -ScriptBlock {
			Param($webSiteName, $pathLocateSite, $port, $poolName)
			New-WebSite -Name $webSiteName -ApplicationPool $poolName -Port $port -PhysicalPath "$pathLocateSite\DevOpsTaskJunior-master"
		} -ArgumentList $webSiteName, $pathLocateSite, $port, $poolName

		Print-INFO "Start site"

		$res = Invoke-Command -Session $psSession -ScriptBlock {
			Param($webSiteName)
			Remove-Website -Name "Default Web Site"
			Start-WebSite -Name $webSiteName 
		} -ArgumentList $webSiteName
		
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
		[string]$PathtoStorageDB,

		[Parameter(Mandatory=$True)]
		$outIsNeedUpgrade
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
		if($hashOldSite.Hash -eq $hashNewSite.Hash) {
			$hashNewSite | Export-Clixml -Path $PathtoStorageDB
			New-StepVar -Name $outIsNeedUpgrade -Value $false
		}
		else{
			$hashNewSite | Export-Clixml -Path $PathtoStorageDB
			New-StepVar -Name $outIsNeedUpgrade -Value $true			
		}
    }
}

function Install-Site {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.Runspaces.PSSession]$psSession,

		[Parameter(Mandatory=$True)]
		[string]$strPathToLocalStorageFileSite,

		[Parameter(Mandatory=$True)]
		[string]$uri,

		[Parameter(Mandatory=$True)]
		[string]$strPathToRemotePCSitePlace
	)
	PROCESS {
		$sriptBlock = {
			Param(
				[Parameter(Mandatory=$true)]
				[string]$uri,

				[Parameter(Mandatory=$True)]
				[string]$strPathToRemotePCSitePlace
			)
			Remove-Item "C:\inetpub\wwwroot\DevOpsTaskJunior-master" -Recurse

			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			Invoke-WebRequest -Uri $uri -OutFile "$strPathToRemotePCSitePlace\master.zip"
			Add-Type -assembly "system.io.compression.filesystem"
			[System.IO.Compression.ZipFile]::ExtractToDirectory("$strPathToRemotePCSitePlace\master.zip", "$strPathToRemotePCSitePlace")
			<#
			$acl = Get-Acl $strPathToRemotePCSitePlace
			$a = "IIS","FullControl","Allow"
			$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($a)
			$acl.SetAccessRule($accessRule)
			$acl | Set-Acl $strPathToRemotePCSitePlace #>
		}
		Invoke-Command -Session $psSession -ScriptBlock $sriptBlock -ArgumentList $uri, $strPathToRemotePCSitePlace
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
