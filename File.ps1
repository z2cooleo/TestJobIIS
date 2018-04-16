function Print-INFO {
	Param(
		[Parameter(Mandatory=$True)]
        $Path,
        [Parameter(Mandatory=$false)]
        $

	)
	PROCESS {
		New-Variable -Name 'dt' -Option Private

		$dt = Get-Date -Format "yyyy.MM.dd HH:mm:ss"
		write-output "[$dt] INFO: $msg"

		Remove-Variable -Name 'dt'
	}
}