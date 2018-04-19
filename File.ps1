function Write-Logfile{
    param(
        [Parameter(Mandatory=$false)]
        $fileName,
        
        [Parameter(Mandatory=$false)]
        $path = $pathTolog,

        [Parameter(Mandatory=$true)]
        $text
    )
    Begin{
        Set-Variable -name fileName -Value (Get-Date -UFormat "%Y%m%d.log")
    }
    Process{
        Out-File "$path\$fileName" -InputObject $text -Append
    }
    End{
        Remove-Variable -Name fileName
    }
}