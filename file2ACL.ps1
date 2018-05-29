Param(
	[Parameter(Position=0)]
		[string]$Verb,
	[Parameter(Position=1)]
		[string]$File,
	[Parameter(Position=2)]
		[string]$Path,
	[Parameter()]
		[int]$MaxThread = 3,
	[Parameter()]
		[switch]$WriteAll,
	[Parameter()]
		[switch]$Replace
	#[switch]$thing
)

$Help ='
     >>>>>-----     MBP-ManageACL     -----<<<<<

ManageACL is a tool that allows for the documentation and management of file and
folder ACLs via an XML file.

USAGE
.\MBP-ManageACL.ps1 Save <XML File> <Start/Root Path>
.\MBP-ManageACL.ps1 [Set|Compare] <XML File>
_____
Save		Save all ACLs starting from the given path.

-MaxThread	Set the number threads to be used when saving ACLs to file.
		Default=3
_____
Set		Set all ACLs listed in the provided file starting at the root path in the
		file. By default ACLs without changes are not set.

-WriteAll	Set all ACLs even if no changes are to be made.

-Replace	Replace child ACLs with inherited ACLs from parents. Only ACLs listed
		in the provied file will be left.
_____
Compare		Compare ACLs listed in the provided file to the ACLs that exist at the
		paths listed in the file.
'


<#     >>>>>-----     Check-Principle function     -----<<<<<
#>
. .\CheckPrinciple.ps1}


<#     >>>>>-----     Save-XML function     -----<<<<<
#>
function Save-XML
{
	Param (
		[parameter(Mandatory=$true, Position=0)]
		[System.Object]$ACL,
		[parameter(Mandatory=$true, Position=1)]
		[AllowNull()]
		[System.Xml.XmlTextWriter]$xmlWriter,
		[parameter(Mandatory=$true, Position=2)]
		[Bool]$IsFolder,
		[parameter(Mandatory=$false)]
		[Switch]$IsRoot = $false
	)
	
	if ($IsRoot) {$xmlWriter.WriteStartElement('RootPath')}
	else {$xmlWriter.WriteStartElement('SubPath')}
	
	$xmlWriter.WriteAttributeString('IsFolder', $IsFolder)
	$xmlWriter.WriteAttributeString('Path', ($ACL.Path -split '::')[1])
	$xmlWriter.WriteStartElement('AccessControlList')
	$xmlWriter.WriteAttributeString('Owner', $ACL.Owner)
	$xmlWriter.WriteAttributeString('Group', $ACL.Group)
	
	ForEach ($ace in $ACL.Access){
		# Ignore Inherited ACEs unless at "root" folder
		if (($ace.IsInherited -eq $false) -or $IsRoot) {
			$xmlWriter.WriteStartElement('AccessControlEntry')
			$xmlWriter.WriteAttributeString('IsInherited', $ace.IsInherited)
			$xmlWriter.WriteElementString('Description', 'ACE collected from raw ACL')
			$xmlWriter.WriteElementString('AccessControlType', $ace.AccessControlType)
			$xmlWriter.WriteElementString('IdentityReference', $ace.IdentityReference)
			$xmlWriter.WriteElementString('FileSystemRights', $ace.FileSystemRights)
			$xmlWriter.WriteElementString('InHeritanceFlags', $ace.InHeritanceFlags)
			$xmlWriter.WriteElementString('PropagationFlags', $ace.PropagationFlags)
			$xmlWriter.WriteEndElement()
		}
	}
	$xmlWriter.WriteEndElement()
	if (-not $IsRoot) {$xmlWriter.WriteEndElement()}
}


<#     >>>>>-----     Read-XML function     -----<<<<<
#>
function Read-XML
{
	Param(
		[parameter(Mandatory=$true, Position=0)]
		[System.Xml.XmlElement]$xmlACL,
		[parameter(Mandatory=$false, Position=1)]
		[Boolean]$IsFolder,
		[parameter(Mandatory=$false)]
		[Switch]$IsRoot = $false
	)
	Write-Debug $xmlACL
	
	if ($IsFolder) {
		$acl = New-Object System.Security.AccessControl.DirectorySecurity
	}
	else {
		$acl = New-Object System.Security.AccessControl.FileSecurity
	}
	$acl.SetOwner( (New-Object System.Security.Principal.NTAccount($xmlACL.Owner)) )
	$acl.SetGroup( (New-Object System.Security.Principal.NTAccount($xmlACL.Group)) )
	ForEach ($ace in ($xmlACL.AccessControlEntry |`
				Where-Object IsInherited -eq $false)) {
		$ID = New-Object System.Security.Principal.NTAccount($ace.IdentityReference)
		$Rights = [System.Security.AccessControl.FileSystemRights]$ace.FileSystemRights
		$InHeritance = [System.Security.AccessControl.InheritanceFlags]$ace.InHeritanceFlags
		$Propagation = [System.Security.AccessControl.PropagationFlags]$ace.PropagationFlags
		$Type = [System.Security.AccessControl.AccessControlType]$ace.AccessControlType
		$Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(`
				$ID, $Rights, $InHeritance, $Propagation, $Type)
		$acl.AddAccessRule($Rule)
	}
	# protects ACL from inherited permissions
	# (second param is ignored if first param is false)
	$acl.SetAccessRuleProtection($false,$true)
	Return $acl
}


<#     >>>>>-----     Check-XML function     -----<<<<<
#>
function Check-XML
{
	Param(
		[parameter(Mandatory=$true, Position=0)]
		[System.Xml.XmlElement]$xmlACL<#,
		[parameter(Mandatory=$false, Position=1)]
		[Boolean]$IsFolder,
		[parameter(Mandatory=$false)]
		[Switch]$IsRoot = $false#>
	)
	Write-Debug $xmlACL
	
	if(-not (Check-Principle $xmlACL.Owner)) {Return $false}
	if(-not (Check-Principle $xmlACL.Group)) {Return $false}
	ForEach ($ace in ($xmlACL.AccessControlEntry |`
				Where-Object IsInherited -eq $false)) {
		if(-not (Check-Principle $ace.IdentityReference)) {Return $false}
	}
	Return $true
}


<#     >>>>>-----     Format-SideBySide function     -----<<<<<
#>
function Format-SideBySide
{
	Param(
		[parameter(Mandatory=$true, Position=0)]
		[AllowNull()]
		$Left,
		[parameter(Mandatory=$true, Position=1)]
		[AllowNull()]
		$Right
	)
	$LeftProperties = $Left | Get-Member -MemberType NoteProperty, Property `
			-ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
	$RightProperties = $Right | Get-Member -MemberType NoteProperty, Property `
			-ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
	$CombinedProperties = ($LeftProperties + $RightProperties) | Sort-Object -Unique
	
	$CombinedProperties | ForEach-Object {
		$properties = @{'Property' = $_;}

		if ($LeftProperties -Contains $_) {
			$properties['Left'] = $Left | Select-Object -ExpandProperty $_;
		}

		if ($RightProperties -Contains $_) {
			$properties['Right'] = $Right | Select-Object -ExpandProperty $_;
		}

		New-Object PSObject -Property $properties
	}
}


<#     >>>>>-----     Compare-ACE function     -----<<<<<
#>
function Compare-ACE
{
	Param(
		[parameter(Mandatory=$true, Position=0)]
		$AccessLeft,
		[parameter(Mandatory=$true, Position=1)]
		$AccessRight,
		[parameter(Mandatory=$False)]
		[switch]$Diff=$false
	)
	if(($AccessLeft.GetType().name -ne 'FileSystemAccessRule') -and`
			($AccessLeft.GetType().name -ne 'AuthorizationRuleCollection')) {
		Write-Error "Function: Compare-ACE `r`nError: AccessLeft is not of an allowed data type"
		Return $false
	}
	if(($AccessRight.GetType().name -ne 'FileSystemAccessRule') -and`
			($AccessRight.GetType().name -ne 'AuthorizationRuleCollection')) {
		Write-Error "Function: Compare-ACE `r`nError: AccessRight is not of an allowed data type"
		Return $false
	}
	$AccessLeft = $AccessLeft | Sort-Object `
		AccessControlType, IdentityReference, FileSystemRights, InheritanceFlags, PropagationFlags
	$AccessRight = $AccessRight | Sort-Object `
		AccessControlType, IdentityReference, FileSystemRights, InheritanceFlags, PropagationFlags
	if($AccessLeft.count -ne $AccessRight.count) {
		if($Diff) {
			if($AccessLeft.count -gt $AccessRight.count) {
				$max = $AccessLeft.count
			} else {$max = $AccessRight.count}
			for($ndx=0; $ndx -lt $max; $ndx++) {
				Write-Output (Format-SideBySide $AccessLeft[$ndx] $AccessRight[$ndx])
			}
		}
		Return $false
	}
	else {
		for($ndx=0; $ndx -lt $AccessLeft.count; $ndx++) {
			if(($AccessLeft[$ndx].AccessControlType -ne $AccessRight[$ndx].AccessControlType)`
					-or ($AccessLeft[$ndx].FileSystemRights -ne $AccessRight[$ndx].FileSystemRights)`
					-or ($AccessLeft[$ndx].IdentityReference -ne $AccessRight[$ndx].IdentityReference)`
					-or ($AccessLeft[$ndx].InheritanceFlags -ne $AccessRight[$ndx].InheritanceFlags)`
					-or ($AccessLeft[$ndx].PropagationFlags -ne $AccessRight[$ndx].PropagationFlags)) {
				if($Diff) {
					Write-Output (Format-SideBySide $AccessLeft[$ndx] $AccessRight[$ndx])
				}
				Return $false
			}
		}
	}
	Return $true
}


<#     >>>>>-----     EnqueueTree Script Block (function)     -----<<<<<
#>
$EnqueueTree = {
	Param (
		[parameter(Mandatory=$False, Position=0)]
		[int]$Index = 0,
		[parameter(Mandatory=$False)]
		[Switch]$IsRoot = $False
	)
	
	# below statement prevents "[ref] cannot be applied to a varible that doesn't exist"
	$Path = " "
	do {
		if ( $PathQueue.TryDequeue(([ref]$Path)) ) {
			$KillSwitch[$Index] = $false
			
			$ACL = Get-Acl -LiteralPath $Path
			$IsFolder = (Get-Item -LiteralPath `
						($ACL.Path -split '::')[1]).PSIsContainer
			
			if ($IsFolder){
				ForEach ($Item in (Get-ChildItem -LiteralPath `
								($ACL.Path -split '::')[1])) {
					$PathQueue.Enqueue( ($Item.PSPath -split '::')[1] )
					#Write-Output ($Item.PSPath -split '::')[1] #>> pathLog.txt
				}
			}
			if (($ACL.Access.IsInherited -contains $false) -or $IsRoot) {
				$aclQueue.Enqueue(@{ACL=$ACL; IsFolder=$IsFolder})
			}
		} else {
			$KillSwitch[$Index] = $true
			Start-Sleep -Milliseconds 10
		}
	}
	While ((-not $IsRoot) -and ($KillSwitch -contains $false))
}


<#     >>>>>-----     SetACL Script Block (function)     -----<<<<<
#>
$SetACL = {
	Param(
		[parameter(Mandatory=$true, Position=0)]
		[System.Object]$readACL,
		[parameter(Mandatory=$true, Position=1)]
		[string]$Path,
		[parameter(Mandatory=$false, Position=2)]
		[bool]$SetAll = $false,
		[parameter(Mandatory=$false, Position=3)]
		[bool]$Replace = $false
	)
	Write-Verbose ("" + $Path)
	try {
		$rawACEs = (Get-ACL -LiteralPath $Path).Access | where{$_.IsInherited -eq $false}
	} catch [System.UnauthorizedAccessException] {
		throw "Unable to Access raw ACL. File/Folder access denied"
	}
	$Result = Compare-ACE $readACL.Access $rawACEs -Diff
	if($Result[-1] -eq $false){
		Set-ACL -LiteralPath $Path -AclObject $readACL
		Write-Verbose ("Differences between file and raw ACL:" `
						+ $Result[0..($Result.Count-2)])
	} elseif($WriteAll) {
		Set-ACL -LiteralPath $Path -AclObject $readACL
	}
	if($Replace) {
		ForEach ($Item in (Get-ChildItem -LiteralPath $Path)) {
			(icacls $Item /reset /t /c /l) | ForEach {Write-verbose $_}
		}
	}
}


<#     >>>>>-----     Script Body     -----<<<<<
#>
Switch ([string]$Verb){
	'save' {
		try {		# if processing path isn't give assume current working directory
			if ($Path -eq '') {$Path = (get-item -LiteralPath (Get-Location)).PSpath}
			else {$Path = (Get-Item -LiteralPath $Path).PSPath}		# ensure path is valid
		} catch {throw "Invalid path provided"}
		# Correct Path for long paths
		$Path = ($Path -split '::')[1]
		$Path = "\\?\" + ($Path -replace "^\\\\", "UNC\")
		
		# To correct for execution path vs working path differences
		# if path is not a full path assume path is relative to working directory
		if(Test-Path -LiteralPath $File) {
			throw "File alread exists or is a directory. Please use 'update'."
		} elseif (-not [System.IO.Path]::IsPathRooted($File)) {
			$File = [System.IO.Path]::GetFullPath( (Join-Path (Get-Location) $File) )
		}
		$File = "\\?\" + ($File -replace "^\\\\", "UNC\")
		
		try {		# setup XML writing
			$xmlWriter = New-Object System.XML.XmlTextWriter($File,$Null)
			$xmlWriter.Formatting = 'Indented'
			$xmlWriter.Indentation = 1
			$xmlWriter.IndentChar = "`t"		# Indent Using Tab char (`t)
			$xmlWriter.WriteStartDocument()
		} catch {
			$xmlWriter.Flush()
			$xmlWriter.Close()
			$xmlWriter.Dispose()
			throw "Unable to write to provided file path."
		}
		
		# create shared variables used to coordinate worker processes
		$PathQueue = New-Object System.Collections.Concurrent.ConcurrentQueue[psobject]
		$aclQueue = New-Object System.Collections.Concurrent.ConcurrentQueue[psobject]
		$KillSwitch = for($i=0; $i -lt $MaxThread; $i++){$true}
		
		$PathQueue.Enqueue($Path)
		Write-output ("`r`n`r`nMBP-ManageACL Save Started " +`
						(get-date -Format 'dddd, MMMM dd, yyyy HH:mm:ss') +`
						' on:') $Path "`r`n"
		Write-Debug ("Verb: save `r`nXML file path: " + $File)
		Write-Debug ("Verb: save `r`nRootPath: " + $Path)
		
		# call script block "Enqueue-Tree" to add initial path values to path queue
		& $EnqueueTree -IsRoot
		
		# write root path ACLs
		# below statement prevents "[ref] cannot be applied to a varible that doesn't exist"
		$aclHold = $null
		if ($aclQueue.TryDequeue([ref]$aclHold)){
			Save-XML $aclHold.ACL $xmlWriter $aclHold.IsFolder -IsRoot
			Write-output ((get-date -Format HH:mm:ss) +`
						' - Unless error above, ACL Saved for:')`
						($aclHold.ACL.Path -split '::')[1]
		}
		
		# Setup initial session state for RunSpacePool to include a shared variables
		$InitialSessionState =`
			[System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
		$InitialSessionState.Variables.Add(
			(New-object System.Management.Automation.Runspaces.SessionStateVariableEntry `
			-ArgumentList 'PathQueue',$PathQueue,$Null)
		)
		$InitialSessionState.Variables.Add(
			(New-object System.Management.Automation.Runspaces.SessionStateVariableEntry `
			-ArgumentList 'aclQueue',$aclQueue,$Null)
		)
		$InitialSessionState.Variables.Add(
			(New-object System.Management.Automation.Runspaces.SessionStateVariableEntry `
			-ArgumentList 'KillSwitch',$KillSwitch,$Null)
		)
		
		# Create the runspacepool using the defined sessionstate variable
		$RunspacePool = [runspacefactory]::CreateRunspacePool($InitialSessionState)
		if (-not $RunspacePool.SetMaxRunspaces($MaxThread) ) {
				Write-Warning 'Failed to set max run spaces.'
		}
		$RunspacePool.Open()
		
		# Add process to run space pool
		$Workers = @()
		for ($i=0; $i -lt $MaxThread; $i++){
			$Shell = [powershell]::Create()
			$Shell.Runspacepool = $RunspacePool
			$null = $Shell.AddScript($EnqueueTree)
			$null = $Shell.AddArgument($i)
			$Workers += [PSCustomObject]@{Handle=$Shell.BeginInvoke(); Shell=$Shell}
			Start-Sleep -Milliseconds 100
		}
		Write-Verbose ('Verb: save `r`nActive Worker Count: ' +`
					($Workers.Handle | Where-Object IsCompleted -eq $false).count)
		
		do{		# Write ACL to XML file if there are ACLs queued
			if ($aclQueue.TryDequeue([ref]$aclHold)){
				Save-XML $aclHold.ACL $xmlWriter $aclHold.IsFolder
				Write-output ((get-date -Format HH:mm:ss) +`
							' - Unless error above, ACL Saved for:')`
							($aclHold.ACL.Path -split '::')[1]
			}
			# wait half a second before checking ACL queue again
			else {Start-Sleep -Milliseconds 500}
		} While (($Workers.Handle.IsCompleted -contains $False) -or ($aclQueue.count -gt 0))
		
		# Cleanup all Completed processes
		ForEach ($Worker in $Workers) {
			# EndInvoke method retrieves the results of the asynchronous call
			# end process and write worker output to Debug stream
			$Worker.Shell.EndInvoke($Worker.Handle) | Write-Debug
			$Worker.Shell.Dispose()
		}

		$RunspacePool.Close() 
		$RunspacePool.Dispose()
		Write-output ('MBP-ManageACL Save Ended ' +`
					(get-date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')`
					+ ' on:') $Path
		$xmlWriter.WriteEndElement()
		$xmlWriter.WriteEndDocument()
		$xmlWriter.Flush()
		$xmlWriter.Close()
		$xmlWriter.Dispose()
	}
	{'set','compare' -contains $_} {
		try {		# Check is file exists and get rooted path
			$File = Get-Item -LiteralPath $File
			Write-Debug "Get-Item result: $File"
			if($File.PSIsContainer) {
				throw "File path provied refers to a directory."
			}
		} catch {throw "Config file not found"}
		try {		# load config file into an XML object
			$xmlRead = New-Object -TypeName XML
			$xmlRead.Load($File)
			Write-Debug "Config file loaded for $($xmlRead.rootpath.path)"		# debug output
		} catch {throw "Unable to load config file."}
	}
	'set' {
		$readACL = Read-XML $xmlRead.rootpath.AccessControlList `
							($xmlRead.rootpath.IsFolder -eq "True")
		& $SetACL $readACL $xmlRead.rootpath.path $WriteAll $Replace
        
		<# for multi threading control
		$TreeDepth = [regex]::Matches($xmlRead.RootPath.Path, "\\").count
		$MaxDepth = [regex]::Matches( `
				($xmlRead.RootPath.SubPath | Sort-Object -Property {$_.Path.Length})[-1].Path, "\\").count
		#>
		ForEach ($subpath in $xmlRead.rootpath.subpath){
			$readACL = Read-XML $subpath.AccessControlList ($subpath.IsFolder -eq "True")
			& $SetACL $readACL $subpath.path $WriteAll $Replace
		}
		
		#$xmlRead.Close()
		#$xmlRead.Dispose()
	}
	'compare' {
		Write-Output "" $xmlRead.rootpath.path
		$xmlACEs = (Read-XML $xmlRead.rootpath.AccessControlList ($xmlRead.rootpath.IsFolder -eq "True")).Access
		try {
			$rawACEs = (Get-ACL -LiteralPath $xmlRead.rootpath.path).Access | where{$_.IsInherited -eq $false}
		} catch [System.UnauthorizedAccessException] {
			throw "Unable to Access raw ACL. File/Folder access denied"
		}
		$Result = Compare-ACE $xmlACEs $rawACEs -Diff
		Write-Output ('Raw ACL matchs file: ' + $Result[-1])
		if($Result[-1] -eq $false){
			Write-Output "Differences between file and raw ACL:" $Result[0..($Result.Count-2)]
		}
		
		ForEach ($subpath in $xmlRead.rootpath.subpath){
			$Result=$null		# clear previous results
			Write-Output "" $subpath.path
			$xmlACEs = (Read-XML $subpath.AccessControlList ($subpath.IsFolder -eq "True")).Access
			try {
				$rawACEs = (Get-Acl -LiteralPath $subpath.path).Access | where{$_.IsInherited -eq $false}
			} catch [System.UnauthorizedAccessException] {
				throw "Unable to Access raw ACL. File/Folder access denied"
			}
			$Result = Compare-ACE $xmlACEs $rawACEs -Diff
			Write-Output ('Raw ACL matchs file: ' + $Result[-1])
			if($Result[-1] -eq $false){
				Write-Output "Differences between file and raw ACL:" $Result[0..($Result.Count-2)]
			}
		}
		Write-Output "" "Files and folders NOT listed in the config file were NOT checked for explicite ACEs"
	}
	default {
		Write-Output $Help
		cmd /c pause
		Exit
	}
}


<#   >>>---   Notes   ---<<<
icacls /reset /t /c /l
ForEach($sid in $acl.Access.identityreference) {$acl.PurgeAccessRules($sid)}
$xml.RootPath.SubPath | Sort-Object -Property {$_.Path.Length}
[regex]::Matches($file, "\\").count
$xml.RootPath.SubPath | Sort-Object -Property {$_.Path.Length} | Where-Object {[regex]::Matches($_.Path, "\\").count -eq 5}
[regex]::Matches(($xml.RootPath.SubPath | Sort-Object -Property {$_.Path.Length})[-1].Path, "\\").count

$acl1 = Get-Acl -Path .\Test_Folder -AllCentralAccessPolicies #| Format-List
$acl2 = Get-Acl -Path .\Test_Folder\Test_File.docx #).Sddl[2] # | Format-List
$acl | Get-Member
Diff $acl1 $acl2

$Right = [System.Security.AccessControl.FileSystemRights]"AppendData"

(Get-Acl .\Test_Folder\Test_File.docx).Access | where{$_.IsInherited -eq $false}

#>
