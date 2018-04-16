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