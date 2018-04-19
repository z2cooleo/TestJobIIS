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
		Write-Logfile -text "[$dt] INFO: $msg"
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
		throw "$IIS_ERROR_EXCEPTION $msg"
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
		Write-Logfile -text "[$dt] INFO: $msg"
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
		Write-Logfile -text "[$dt] INFO: $msg"
		Remove-Variable -Name 'dt'
	}
}

