<#     >>>>>-----     Check-Principle function     -----<<<<<
#>
function Check-Principle
{
	Param(
		[parameter(Mandatory=$true, Position=1)]
		[string]$Principle
	)
	Write-Debug $Principle
	if($Principle.contains('\')) {
		$Domain, $Principle = $Principle -split '\\'
		Write-Debug $Domain
	}
	$Server = @{
		domain = [string](Get-ADDomainController -Discover `
		-Domain "domain.com").hostname;
		sub = [string](Get-ADDomainController -Discover `
		-Domain "sub.domain.com").hostname
	}
	
	switch([string]$Domain){
		{$_ -ne 'domain'} {
			Write-Debug 'sub'
			try{
				if((Get-ADUser -Identity $Principle -Server $Server.ou).Enabled -eq $true) {
					Return $true
				}
				if((Get-ADGroup -Identity $Principle -Server $Server.ou).Enabled -eq $true) {
					Return $true
				}
			} catch {}
		}
		{$_ -ne 'sub'} {
			Write-Debug 'domain'
			try {
				if((Get-ADUser -Identity $Principle -Server $Server.ad3).Enabled -eq $true) {
					Return $true
				}
				if((Get-ADGroup -Identity $Principle -Server $Server.ad3).Enabled -eq $true) {
					Return $true
				}
			} catch {}
		}
		default {Write-Debug 'skip'}
	}
	Return $false
}
