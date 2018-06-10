<#     >>>>>-----     Check-Principle function     -----<<<<<
#>
function Check-Principle
{
	Param(
		[parameter(Mandatory=$true, Position=1)]
		[string]$Principle
	)
	Write-Debug $Principle
	$test = New-Object System.Security.AccessControl.FileSecurity
	try {
		$test.SetOwner( (New-Object System.Security.Principal.NTAccount("$Principle")) )
	} catch {
		Write-Verbose "Unable to resolve Principle: $Principle"
		Return $false
	}
	Return $true
}
