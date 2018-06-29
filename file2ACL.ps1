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
		[switch]$Replace,
	[Parameter()]
		[switch]$icacls,
	[Parameter()]
		[switch]$SaveAll
)


<#     >>>>>-----     Initial Variables     -----<<<<<
#>
$ScriptFolder = ''
$HelpMSG = . { @'
     >>>>>-----     file2ACL     -----<<<<<

file2ACL is a tool that allows for the documentation and management of file and
folder ACLs via an XML file.

USAGE
.\file2ACL.ps1 Save <XML File> <Start/Root Path> [-SaveAll] [-MaxThread]
.\file2ACL.ps1 Update <XML File> [-SaveAll] [-MaxThread #]
.\file2ACL.ps1 Set <XML File> [-WriteAll] [-Replace] [-icacls] [-MaxThread #]
.\file2ACL.ps1 Compare <XML File>
.\file2ACL.ps1 Check <XML File>
_____
Save		Save ACLs starting from the given path.

Update		Save current XML file as a backup and Write a new XML file.

Set		Set all ACLs listed in the provided file starting at the root path in the
		file. By default ACLs without changes are not set.

Compare		Compare ACLs listed in the provided file to the ACLs that exist at the
		paths listed in the file.  Does not check full tree; use save/update and
		diff the files to achive this.

Check		Check XML file for "security principles" that are invalid.

-SaveAll	Ignore invalid  security principles and save all ACLs and ACEs

-MaxThread	Set the number threads to be used when saving ACLs to file (Default=3).
		High thread counts are very helpful with save, but of very limited help
		with set. This is due to the layered queueing used to prevent worker
		proccess collition.

-WriteAll	Set all ACLs even if no changes are to be made.

-Replace	Replace child ACLs with inherited ACLs from parents. Only ACLs listed
		in the provied file will be left.

-icacls		Use icacls.exe instead of Set-ACL. Only needed/recomended for use
		with Samba implementations that don't work as expected with Set-ACL.
		Using icacls will not set ownership; broken for domain usage.
'@
}


<#     >>>>>-----     Check-Principle function     -----<<<<<
#>
. .\CheckPrinciple.ps1


<#     >>>>>-----     ACLtoXML function     -----<<<<<
#>
function ACLtoXML {
	Param (
		[parameter(Mandatory=$true, Position=0)]
			[System.Object]$ACL,
		[parameter(Mandatory=$true, Position=1)]
		[AllowNull()]
			[System.Xml.XmlTextWriter]$xmlWriter,
		[parameter(Mandatory=$true, Position=2)]
			[Bool]$IsFolder,
		[Parameter()]
			[Bool]$SaveAll,
		[parameter()]
			[Switch]$IsRoot
	)
	$Path = ($ACL.Path -split '::')[1]
	
	if( (-not (Check-Principle $ACL.Owner)) `
			-or (-not (Check-Principle $ACL.Group)) ) {
		Write-Warning "Invalid owner or group: $($Path)"
		if(-not ($SaveAll -or $IsRoot)) {
			Write-Warning "ACL not saved; use -SaveAll to ignore Invalid owner/group"
			Return
		}
	}
	
	if ($IsRoot) {$xmlWriter.WriteStartElement('RootPath')}
	else {$xmlWriter.WriteStartElement('SubPath')}
	
	$xmlWriter.WriteAttributeString('IsFolder', $IsFolder)
	$xmlWriter.WriteAttributeString('Path', $Path)
	$xmlWriter.WriteStartElement('AccessControlList')
	$xmlWriter.WriteAttributeString('Owner', $ACL.Owner)
	$xmlWriter.WriteAttributeString('Group', $ACL.Group)
	
	ForEach ($ace in $ACL.Access){
		if(-not (Check-Principle $ace.IdentityReference)) {
			Write-Warning "Invalid identity reference: $($Path)"
			if(-not ($SaveAll -or $IsRoot)) {
				Write-Warning "ACE not saved; use -SaveAll to ignore Invalid identity reference"
				Continue		# break one iteration of loop; skip to next iteration
			}
		}		# Ignore Inherited ACEs unless at "root" folder
		if(($ace.IsInherited -eq $false) -or $IsRoot) {
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


<#     >>>>>-----     XMLtoACL function     -----<<<<<
#>
function XMLtoACL {
	Param(
		[parameter(Mandatory=$true, Position=0)]
			[System.Xml.XmlElement]$xml
	)
	Write-Debug $xml
	
	if ($xml.IsFolder) {
		$acl = New-Object System.Security.AccessControl.DirectorySecurity
	}
	else {
		$acl = New-Object System.Security.AccessControl.FileSecurity
	}
	$acl.SetOwner( (New-Object System.Security.Principal.NTAccount($xml.AccessControlList.Owner)) )
	$acl.SetGroup( (New-Object System.Security.Principal.NTAccount($xml.AccessControlList.Group)) )
	ForEach ($ace in ($xml.AccessControlList.AccessControlEntry |`
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
	Return @{ACL=$acl; Path=$xml.Path}
}


<#     >>>>>-----     XMLtoICACLS function     -----<<<<<
#>
function XMLtoICACLS {
	Param(
		[parameter(Mandatory=$true, Position=0)]
			[System.Xml.XmlElement]$xml
	)
	Write-Debug $xml
	$acl = "/inheritance:e"
	#$acl += " /setowner `"$($xml.AccessControlList.Owner)`""		# Doesn't seem to work
	
	ForEach ($ace in ($xml.AccessControlList.AccessControlEntry |`
				Where-Object IsInherited -eq $false)) {
		$ID = $ace.IdentityReference
		$Rights = ''
		Switch -Regex ($ace.FileSystemRights) {
			'\bFullControl\b' {$Rights += 'F,'}
			'\bModify\b' {$Rights += 'M,'}
			'\bRead\b' {$Rights += 'R,'}
			'\bReadAndExecute\b' {$Rights += 'RX,'}
			'\bWrite\b' {$Rights += 'W,'}
			'\b(AppendData|CreateDirectories)\b' {$Rights += 'AD,'}
			'\bReadPermissions\b' {$Rights += 'AS,'}
			'\bDelete\b' {$Rights += 'D,'}
			'\bDeleteSubdirectoriesAndFiles\b' {$Rights += 'DC,'}
			'\bReadAttributes\b' {$Rights += 'RA,'}
			'\b(ReadData|ListDirectory)\b' {$Rights += 'RD,'}
			'\bReadExtendedAttributes\b' {$Rights += 'REA,'}
			'\bSynchronize\b' {$Rights += 'S,'}
			'\bWriteAttributes\b' {$Rights += 'WA,'}
			'\b(WriteData|CreateFiles)\b' {$Rights += 'WD,'}
			'\bChangePermissions\b' {$Rights += 'WDAC,'}
			'\bWriteExtendedAttributes\b' {$Rights += 'WEA,'}
			'\bTakeOwnership\b' {$Rights += 'WO,'}
			'\b(ExecuteFile|Traverse)\b' {$Rights += 'X,'}
		}
		$Rights = $Rights -replace ".$",""
		$InHeritance = ''
		Switch -Regex ($ace.InHeritanceFlags) {
			'\bContainerInherit\b' {$InHeritance += '(CI)'}
			'\bObjectInherit\b' {$InHeritance += '(OI)'}
		}
		$Propagation = ''
		Switch -Regex ($ace.PropagationFlags) {
			'\bInheritOnly\b' {$Propagation += '(IO)'}
			'\bNoPropagateInherit\b' {$Propagation += '(NP)'}
		}
		Switch($ace.AccessControlType) {
			'Allow' {$Type = '/grant:r'}
			'Deny' {$Type = '/deny'}
		}
		$acl += " $Type `"$ID`:$InHeritance$Propagation($Rights)`""
	}
	Return @{ACL=$acl; Path = $xml.Path -replace "\\$",""}
}


<#     >>>>>-----     Check-XML function     -----<<<<<
#>
function Check-XML {
	Param(
		[parameter(Mandatory=$true, Position=0)]
			[System.Xml.XmlElement]$xmlACL
	)
	Write-Debug $xmlACL
	$BadPrinciple = 0
	if(-not (Check-Principle $xmlACL.Owner)) {$BadPrinciple++}
	if(-not (Check-Principle $xmlACL.Group)) {$BadPrinciple++}
	ForEach ($ace in ($xmlACL.AccessControlEntry |`
				Where-Object IsInherited -eq $false)) {
		if(-not (Check-Principle $ace.IdentityReference)) {$BadPrinciple++}
	}
	if($BadPrinciple -gt 0) {return $false}
	else {Return $true}
}


<#     >>>>>-----     Format-SideBySide function     -----<<<<<
#>
function Format-SideBySide {
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
function Compare-ACE {
	Param(
		[parameter(Mandatory=$true, Position=0)]
		[AllowNull()]
			$AccessLeft,
		[parameter(Mandatory=$true, Position=1)]
		[AllowNull()]
			$AccessRight,
		[parameter(Mandatory=$False)]
			[switch]$Diff=$false
	)
	if(($AccessLeft -eq $null) -and ($AccessRight -eq $null)) {
		Write-Error "No point in comparing two null valued ACE lists."
		Return $false
	} elseif($AccessLeft -eq $null) {
		Write-Output (Format-SideBySide $null $AccessRight)
		Return $false
	} elseif($AccessRight -eq $null) {
		Write-Output (Format-SideBySide $AccessLeft $null)
		Return $false
	}
	if(($AccessLeft[0].GetType().name -ne 'FileSystemAccessRule') -and `
			($AccessLeft[0].GetType().name -ne 'AuthorizationRuleCollection')) {
		Write-Error "Function: Compare-ACE `r`nError: AccessLeft is not of an allowed data type"
		Return $false
	}
	if(($AccessRight[0].GetType().name -ne 'FileSystemAccessRule') -and `
			($AccessRight[0].GetType().name -ne 'AuthorizationRuleCollection')) {
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
		[parameter(Mandatory=$True, Position=0)]
			[int]$Index = 0,
		[parameter(Mandatory=$False)]
			[Switch]$IsRoot
	)
	Write-Output "Log for Worker $Index`:"
	# below statement prevents "[ref] cannot be applied to a variable that doesn't exist"
	$Path = " "
	do{
		if ( $PathQueue.TryDequeue(([ref]$Path)) ) {
			$Idle[$Index] = $false
			$ACL = Get-Acl -LiteralPath $Path
			$IsFolder = (Get-Item -LiteralPath `
						($ACL.Path -split '::')[1]).PSIsContainer
			
			if ($IsFolder){
				ForEach ($Item in (Get-ChildItem -LiteralPath `
								($ACL.Path -split '::')[1])) {
					$PathQueue.Enqueue( ($Item.PSPath -split '::')[1] )
				}
			}
			if (($ACL.Access.IsInherited -contains $false) -or $IsRoot) {
				$aclQueue.Enqueue(@{ACL=$ACL; IsFolder=$IsFolder})
			}
		} else {
			$Idle[$Index] = $true
			Start-Sleep -Milliseconds 100
		}
	}While((-not $IsRoot) -and ($Idle -contains $false))
}


<#     >>>>>-----     SetACL Script Block (function)     -----<<<<<
#>
$SetACL = {
	Param(		# SetACL $readACL.ACL $readACL.Path $WriteAll $Replace
		<#[parameter(Mandatory=$true, Position=0)]
			[System.Object]$readACL,
		[parameter(Mandatory=$true, Position=1)]
			[string]$Path,#>
		[parameter(Mandatory=$True, Position=0)]
			[int]$Index = 0,
		[parameter(Mandatory=$false, Position=1)]
			[bool]$Replace = $false
	)
	Write-Output "Log for Worker $Index`:"
	# below statement prevents "[ref] cannot be applied to a variable that doesn't exist"
	$Job = $null
	do{
		if($aclQueue.TryDequeue([ref]$Job)) {
			$Idle[$Index] = $false
			if( ('DirectorySecurity','FileSecurity') -contains $Job.ACL.GetType().name) {
				Set-ACL -LiteralPath $Job.Path -AclObject $Job.ACL
				if(-not $?) {Write-Output "Set-ACL failed on $($Job.Path)"}
			} elseif($Job.ACL.GetType().name -eq 'String') {
				Write-Output $Job.Path
				icacls $Job.Path /reset /C /L *>&1 | Write-Output
				Write-Output $Job.ACL
				icacls $Job.Path ($Job.ACL -split ' ') /C /L *>&1 | Write-Output
				<#
				foreach($ACE in $Job.ACL) {
					Write-Output $ACE
					icacls $Job.Path ($ACE -split ' ') /C /L *>&1 | Write-Output
				}#>
			} else {Write-Output "mal-formed ACL object for $($Job.Path)"}
			if($Replace) {
				ForEach ($Item in (Get-ChildItem -LiteralPath $Job.Path)) {
					(icacls $Item /reset /T /C /L /Q) | ForEach {Write-Output $_}
				}
			}
		} else {
			$Idle[$Index] = $True
			Start-Sleep -Milliseconds 500
		}
	}While($Idle -contains $false)
}


Switch ([string]$Verb){
	<#   >>>---   Parameter Validation and Initialization   ---<<<
	#>
	{'save','set','compare','check','update' -contains $_} {
		Write-Debug "Validating Parameters"
		Write-Debug "Config File: $File"
		Write-Debug "Working Path: $Path"
		# validate config file path
		if(($Verb -eq 'save') -and (Test-Path -LiteralPath $File)) {
			throw "File already exists or is a directory. Please use 'update'."
		} elseif( (-not (Test-Path -LiteralPath $File) -and ($Verb -ne 'save')) ) {
			throw "Configuration file not found"
		} elseif(Test-Path -LiteralPath $File -PathType Container) {
			throw "File path provided refers to a directory."
		} elseif( -not [System.IO.Path]::IsPathRooted($File)) {
			$File = [System.IO.Path]::GetFullPath((Join-Path (Get-Location | Convert-Path) $File))
		}
		if( -not $File.Contains('\\?\')) {
			$File = "\\?\" + ($File -replace "^\\\\", "UNC\")
		}
		
		if ($Path -eq '') {
			$Path = (get-item -LiteralPath (Get-Location)).PSpath
		}
		if(Test-Path -LiteralPath $Path -PathType Container) {
			$Path = Convert-Path -LiteralPath $Path
		} else {throw "Invalid path provided"}
		# Correct Path for long paths
		if( -not $Path.Contains('\\?\')) {
			$Path = "\\?\" + ($Path -replace "^\\\\", "UNC\")
		}
		#Return $File, $Path
	}
	<#			>>>---   Load config file   ---<<<
	#>
	{'set','compare','check','update' -contains $_} {
		Write-Debug "Loading config file from path: $File"
		try {		# load config file into an XML object
			$xmlRead = New-Object -TypeName XML
			$xmlRead.LoadXml( (Get-Content -LiteralPath $File) )
			Write-Debug "Config file loaded for $($xmlRead.rootpath.path) from $File"
		} catch {throw "Unable to load config file."}
		
		# Pull path from config file
		$Path = $xmlRead.rootpath.path
	}	{'save','update' -contains $_} {		#---IF save or update---<<<
		if($verb -eq 'update') {
			Write-Debug "Backing up old config file"
			Remove-Variable xmlRead
			Move-Item $File "$File replaced-$(Get-Date -format 'yyyy-MM-dd_HH.mm').xml"
		}
		Write-Debug "Writing to config file: $File"
		try {		# setup XML writing
			$xmlWriter = New-Object System.XML.XmlTextWriter($File,$Null)
			$xmlWriter.Formatting = 'Indented'
			$xmlWriter.Indentation = 1
			$xmlWriter.IndentChar = "`t"		# Indent Using Tab char (`t)
			$xmlWriter.WriteStartDocument()
		} catch {
			if($xmlWriter -ne $null) {
				$xmlWriter.Flush()
				$xmlWriter.Close()
				$xmlWriter.Dispose()
			}
			throw "Unable to write to provided file path."
		}
	}
	<#			>>>---   Check config file   ---<<<
	check for invalid security principles
	#>
	{'set','compare','check' -contains $_} {
		Write-Debug "Checking config file security principles"
		$PrincipleErrorCount = 0
		if(-not (Check-XML $xmlRead.rootpath.AccessControlList)) {
			Write-Warning "Bad user or group for $($xmlRead.rootpath.path)`r`n`r`n"#in $File"
			$PrincipleErrorCount++
		}
		ForEach ($subpath in $xmlRead.rootpath.subpath){
			if(-not (Check-XML $subpath.AccessControlList)) {
				Write-Warning "Bad user or group for $($subpath.path)`r`n`r`n"#in $File"
				$PrincipleErrorCount++
			}
		}
	}
	<#			>>>---   Multiple Thread Setup   ---<<<
	#>
	{'save','update','set' -contains $_} {
		Write-Debug "Setting up RunspacePool"
		# create shared variables used to coordinate worker processes
		$PathQueue = New-Object System.Collections.Concurrent.ConcurrentQueue[psobject]
		$aclQueue = New-Object System.Collections.Concurrent.ConcurrentQueue[psobject]
		$Idle = for($i=0; $i -lt $MaxThread+1; $i++){$False}
		
		# Setup initial session state for RunSpacePool to include a shared variables
		$InitialSessionState = `
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
			-ArgumentList 'Idle',$Idle,$Null)
		)
		
		# Create the runspacepool using the defined sessionstate variable
		$RunspacePool = [runspacefactory]::CreateRunspacePool($InitialSessionState)
		if (-not $RunspacePool.SetMaxRunspaces($MaxThread) ) {
				throw "Failed to set max run spaces."
		}
		$RunspacePool.Open()
	}
	<#			>>>---   Compare config file with file/folder ACLs    ---<<<
	#>
	'compare' {
		<#if($PrincipleErrorCount -gt 0) {
			throw "Unable to compare: Config file contains $PrincipleErrorCount principle errors."
		}#>
		Write-Output "" $xmlRead.rootpath.path
		$xmlACEs = (XMLtoACL $xmlRead.rootpath).ACL.Access
		try {
			$rawACEs = (Get-ACL -LiteralPath $xmlRead.rootpath.path).Access | `
						Where-Object {$_.IsInherited -eq $false}
		} catch [System.UnauthorizedAccessException] {
			throw "Unable to Access raw ACL. File/Folder access denied"
		}
		$Result = Compare-ACE $xmlACEs $rawACEs -Diff
		Write-Output ('Raw ACL matchs file: ' + $Result[-1])
		if($Result[-1] -eq $false){
			Write-Output "Differences between config file and raw ACL (Left = file Right = raw):"
			$Result[0..($Result.Count-2)] | Out-String -stream | Write-Output
		}
		
		ForEach ($subpath in $xmlRead.rootpath.subpath){
			$Result=$null		# clear previous results
			Write-Output "" $subpath.path
			$xmlACEs = (XMLtoACL $subpath).ACL.Access
			try {
				$rawACEs = (Get-Acl -LiteralPath $subpath.path).Access | `
							Where-Object {$_.IsInherited -eq $false}
			} catch [System.UnauthorizedAccessException] {
				throw "Unable to Access raw ACL. File/Folder access denied"
			}
			$Result = Compare-ACE $xmlACEs $rawACEs -Diff
			Write-Output ('Raw ACL matchs file: ' + $Result[-1])
			if($Result[-1] -eq $false){
				Write-Output "Differences between config file and raw ACL (Left = file Right = raw):"
				$Result[0..($Result.Count-2)] | Out-String -stream | Write-Output
			}
		}
		Write-Output "" "Files and folders NOT listed in the config file were NOT checked for explicite ACEs"
	}
	<#			>>>---   Save/Update config file from file/folder ACLs   ---<<<
	#>
	{'save','update' -contains $_} {
		$PathQueue.Enqueue($Path)
		Write-output "`r`n`r`nSave Started $(get-date -Format 'dddd, MMMM dd, yyyy HH:mm:ss') on:" `
				$Path "`r`n"
		Write-Debug "updating/saving configuration file: $File"
		
		# call script block "Enqueue-Tree" to add initial path values to path queue
		& $EnqueueTree 0 -IsRoot | Write-Verbose
		
		# write root path ACLs
		# below statement prevents "[ref] cannot be applied to a varible that doesn't exist"
		$aclHold = $null
		if ($aclQueue.TryDequeue([ref]$aclHold)){
			ACLtoXML $aclHold.ACL $xmlWriter $aclHold.IsFolder -IsRoot
			Write-output "$(get-date -Format HH:mm:ss) - Errors above, ACL processed: "`
						($aclHold.ACL.Path -split '::')[1]
		}
		
		# Add process to run space pool
		$Workers = @()
		for ($i=0; $i -lt $MaxThread; $i++){
			$Shell = [powershell]::Create()
			$Shell.Runspacepool = $RunspacePool
			$null = $Shell.AddScript($EnqueueTree)
			$null = $Shell.AddArgument($i+1)
			$Workers += [PSCustomObject]@{Handle=$Shell.BeginInvoke(); Shell=$Shell}
			Start-Sleep -Milliseconds 100
		}
		Write-Verbose ("Active Worker Count: " + `
					($Workers.Handle | Where-Object IsCompleted -eq $false).count)
		
		do{		# Write ACL to XML file if there are ACLs queued
			if($aclQueue.TryDequeue([ref]$aclHold)) {
				ACLtoXML $aclHold.ACL $xmlWriter $aclHold.IsFolder -SaveAll $SaveAll
				Write-output "$(get-date -Format HH:mm:ss) - Errors above, ACL processed: " `
							($aclHold.ACL.Path -split '::')[1]
			} else {		# wait half a second before checking ACL queue again
				$Idle[0] = $True
				Start-Sleep -Milliseconds 500
			}
		} While (($Workers.Handle.IsCompleted -contains $False) -or ($aclQueue.count -gt 0))
		
		Write-output "`r`n`r`nSave Ended $(get-date -Format 'dddd, MMMM dd, yyyy HH:mm:ss') on: " $Path
		$xmlWriter.WriteEndElement()
		$xmlWriter.WriteEndDocument()
		$xmlWriter.Flush()
		$xmlWriter.Close()
		$xmlWriter.Dispose()
	}
	<#			>>>---   Set file/folder ACLs from config file   ---<<<
	#>
	'set' {
		if($PrincipleErrorCount -gt 0) {
			throw "Unable to set: Config file contains $PrincipleErrorCount principle errors."
		}
		Write-Debug "Setting ACLs from config file: $File"
		
		# for multi threading control
		$TotalPaths = $xmlRead.RootPath.SubPath.Path.count +1
		$TreeDepth = [regex]::Matches($xmlRead.RootPath.Path, "\\").count
		if($xmlRead.RootPath.SubPath[-1] -eq $null){
			$MaxDepth = [regex]::Matches( `
					($xmlRead.RootPath.SubPath | Sort-Object -Property {$_.Path.Length}).Path, "\\").count
		} else {
			$MaxDepth = [regex]::Matches( `
					($xmlRead.RootPath.SubPath | Sort-Object -Property {$_.Path.Length})[-1].Path, "\\").count
		}
		
		$Job = XMLtoACL $xmlRead.RootPath
		Write-Output "Processing $($Job.Path)"
		try {
			$rawACEs = (Get-ACL -LiteralPath $Job.Path).Access | `
						Where-Object {$_.IsInherited -eq $false}
		} catch [System.UnauthorizedAccessException] {
			throw "Unable to Access raw ACL at $($Job.Path). File/Folder access denied"
		}
		$Result = Compare-ACE $Job.ACL.Access $rawACEs -Diff
		if($icacls) {$Job = XMLtoICACLS $xmlRead.RootPath}
		if($Result[-1] -eq $false){
			$aclQueue.Enqueue($Job)
			Write-Verbose "Differences between config file and raw ACL (Left = file Right = raw):"
			$Result[0..($Result.Count-2)] | Out-String -stream | Write-Verbose
		} elseif($WriteAll) {
			$aclQueue.Enqueue($Job)
		}
		
		$Workers = @()
		for ($i=0; $i -lt $MaxThread; $i++){
			$Shell = [powershell]::Create()
			$Shell.Runspacepool = $RunspacePool
			$null = $Shell.AddScript($SetACL)
			$null = $Shell.AddArgument($i+1)
			$null = $Shell.AddArgument($Replace)
			$Workers += [PSCustomObject]@{Handle=$Shell.BeginInvoke(); Shell=$Shell}
			Start-Sleep -Milliseconds 100
		}
		
		# multi thread logic mostly here
		Write-Debug "Tree depth: $TreeDepth `r`nMax depth: $MaxDepth"
		for($i=$TreeDepth; $i -lt $MaxDepth+1; $i++) {
			Write-Debug "Folder Depth: $i"
			$PathsInLayer = 0
			ForEach ($subpath in $xmlRead.RootPath.SubPath) {
				if([regex]::Matches($subpath.Path, "\\").count -eq $i) {
					$PathsInLayer++
					$Job = XMLtoACL $subpath
					Write-Output "Processing $($Job.Path)"
					try {
						$rawACEs = (Get-ACL -LiteralPath $Job.Path).Access | `
									Where-Object {$_.IsInherited -eq $false}
					} catch [System.UnauthorizedAccessException] {
						throw "Unable to Access raw ACL at $($Job.Path). File/Folder access denied"
					}
					$Result = Compare-ACE $Job.ACL.Access $rawACEs -Diff
					if($icacls) {$Job = XMLtoICACLS $subpath}
					if($Result[-1] -eq $false){
						$aclQueue.Enqueue($Job)
						Write-Verbose "Differences between config file and raw ACL (Left = file Right = raw):"
						$Result[0..($Result.Count-2)] | Out-String -stream | Write-Verbose
					} elseif($WriteAll) {
						$aclQueue.Enqueue($Job)
					}
				}
			}
			Write-Debug "Paths at folder depth: $PathsInLayer"
			do{
				Start-Sleep -Seconds 5
			}while(($Idle[1..$MaxThread] -contains $false) -or ($aclQueue.count -gt 0))
		}
		$Idle[0] = $True
	}
	<#			>>>---   Cleanup Multiple Thread setup   ---<<<
	#>
	{'save','update','set' -contains $_} {
		Write-Debug "Cleaning up all Completed processes"
		ForEach ($Worker in $Workers) {
			# EndInvoke method retrieves the results of the asynchronous call
			# end process and write worker output to Debug stream
			$Worker.Shell.EndInvoke($Worker.Handle) | Write-Verbose
			$Worker.Shell.Dispose()
		}
		$RunspacePool.Dispose()
		$RunspacePool.Close() 
	}
	default {
		Write-Output $HelpMSG
	}
}
