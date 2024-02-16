
Write-Host "DDDD    CCCC     CCCC" -ForegroundColor Cyan
Write-Host "D    D  C    C  C    C" -ForegroundColor Cyan
Write-Host "D     D C       C" -ForegroundColor Cyan
Write-Host "D     D C       C" -ForegroundColor Cyan
Write-Host "D     D C       C" -ForegroundColor Cyan
Write-Host "D    D  C    C  C    C" -ForegroundColor Cyan
Write-Host "DDDD    CCCC     CCCC" -ForegroundColor Cyan

# Get the host name of the computer where the script is executed
$hostName = $env:COMPUTERNAME

# Define the output file name based on the host name of the computer
$REPORT_FILE = "$hostName-HardeningReport.txt"

# Function to print the header with company name, host name, server name, version, and date
function Print-Header {
    param(
        [string]$companyName,
        [string]$hostName,
        [string]$serverName,
        [string]$serverVersion,
        [string]$date
    )

    Add-Content -Path $REPORT_FILE -Value "Company: $companyName"
    Add-Content -Path $REPORT_FILE -Value "Host Name: $hostName"
    Add-Content -Path $REPORT_FILE -Value "Server Name: $serverName"
    Add-Content -Path $REPORT_FILE -Value "Server Version: $serverVersion"
    Add-Content -Path $REPORT_FILE -Value "Date: $date"
    Add-Content -Path $REPORT_FILE -Value ""
}



#FUNCTION 

$reverveCommand = Get-Command | where { $_.name -match "Get-WSManInstance"}
if($reverveCommand -ne $null){
 $reverseCommandExist= $true
}else{
 $reverseCommandExist= $false
}

# Function to reverse SID from SecPol
Function Reverse-SID ($chaineSID) {

 $chaineSID = $chaineSID -creplace '^[^\\]*=', ''
 $chaineSID = $chaineSID.replace("*", "")
 $chaineSID = $chaineSID.replace(" ", "")
 if ( $chaineSID -ne $null){
 $tableau = @()
 $tableau = $chaineSID.Split(",") 
 ForEach ($ligne in $tableau) { 
  $sid = $null
  if ($ligne -like "S-*") {
   if($reverseCommandExist -eq $true){
   $sid = Get-WSManInstance -ResourceURI "wmicimv2/Win32_SID" -SelectorSet @{SID="$ligne"}|Select-Object AccountName
   $sid = $sid.AccountName
   }
if ( $sid -eq $null) {
    $objSID = New-Object System.Security.Principal.SecurityIdentifier ("$ligne")
    $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
    $sid=$objUser.Value
    if ( $sid -eq $null){
    $objUser = New-Object System.Security.Principal.NTAccount("$ligne") 
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    $sid=$strSID.Value
}
   $outpuReverseSid += $sid + "|"

  }else{
   $outpuReverseSid += $ligne + "|"
  }
 }
 
 }
 return $outpuReverseSid
}else {
$outpuReverseSid += No One 
 return $outpuReverseSid

}
}

# convert Stringarray to comma separated list
function StringArrayToList($StringArray) {
 if ($StringArray) {
  $Result = ""
  Foreach ($Value In $StringArray) {
   if ($Result -ne "") { $Result += "," }
   $Result += $Value
  }
  return $Result
 }
 else {
  return ""
 }
}
#Get Intel On the machine

$OSInfo = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory, NumberOfUsers, BootDevice


$OSversion = $OSInfo.Caption
$OSName = $OSInfo.CSName
$OSArchi = $OSInfo.OSArchitecture


#Get the date
$Date = Get-Date -U %d%m%Y

$nomfichier = "audit" + $date + "-" + $OSName +".txt"

Write-Host "#########>Create Audit directory<#########" -ForegroundColor DarkGreen

$nomdossier = "Audit_CONF_" + $OSName + "_" + $date


New-Item -ItemType Directory -Name $nomdossier

Set-Location $nomdossier
#Insert result in audit file
Write-Host "#########>Take Server Information<#########" -ForegroundColor DarkGreen
"#########INFO MACHINE#########" > $nomfichier
"Os version: $OSversion " >> $nomfichier
"Machine name : $OSName " >> $nomfichier
"Machine architecture : $OSArchi" >> $nomfichier
#Start Test 
"#########AUDIT MACHINE#########" >> $nomfichier
$indextest = 1
$chaine = $null
$traitement = $null


#Get usefull files
Write-Host "#########>Take File to analyse<#########" -ForegroundColor DarkGreen
$seceditfile = "./secpol" + "-" + "$OSName" + ".cfg"
secedit /export /cfg $seceditfile 
#Second command in case of emergency
$gpofile = "./gpo" + "-" + "$OSName" + ".txt"
gpresult /r /V > $gpofile
$gpofile = "./gpo" + "-" + "$OSName" + ".html"
gpresult /h $gpofile /f | out-null

$auditconfigfile = "./auditpolicy" + "-" + "$OSName" + ".txt"

auditpol.exe /get /Category:* > $auditconfigfile


#Dump some Windows registry 
Write-Host "#########>Dump Windows Registry <#########" -ForegroundColor DarkGreen
$auditregHKLM= "./auditregistry-HKLMicrosoft" + "-" + "$OSName" + ".txt"
reg export "HKLM\SOFTWARE\Microsoft\" "$auditregHKLM"
$auditregHKLM= "./auditregistry-HKLMCUrrentControlSet" + "-" + "$OSName" + ".txt"
reg export "HKLM\SYSTEM\CurrentControlSet" "$auditregHKLM"
$auditregHKLM= "./auditregistry-HKLMPolicies" + "-" + "$OSName" + ".txt"
reg export "HKLM\SOFTWARE\Policies" "$auditregHKLM"

Write-Host "#########>Take local Firewall Rules Information<#########" -ForegroundColor DarkGreen
$CSVFile = "./firewall-rules-" + "$OSName" + ".csv"
# read firewall rules
$FirewallRules = Get-NetFirewallRule -PolicyStore "ActiveStore"

# start array of rules
$FirewallRuleSet = @()
ForEach ($Rule In $FirewallRules) {
 # iterate throug rules
 # Retrieve addresses,
 $AdressFilter = $Rule | Get-NetFirewallAddressFilter
 # ports,
 $PortFilter = $Rule | Get-NetFirewallPortFilter
 # application,
 $ApplicationFilter = $Rule | Get-NetFirewallApplicationFilter
 # service,
 $ServiceFilter = $Rule | Get-NetFirewallServiceFilter
 # interface,
 $InterfaceFilter = $Rule | Get-NetFirewallInterfaceFilter
 # interfacetype
 $InterfaceTypeFilter = $Rule | Get-NetFirewallInterfaceTypeFilter
 # and security settings
 $SecurityFilter = $Rule | Get-NetFirewallSecurityFilter

 # generate sorted Hashtable
 $HashProps = [PSCustomObject]@{
  Name    = $Rule.Name
  DisplayName   = $Rule.DisplayName
  Description   = $Rule.Description
  Group    = $Rule.Group
  Enabled    = $Rule.Enabled
  Profile    = $Rule.Profile
  Platform   = StringArrayToList $Rule.Platform
  Direction   = $Rule.Direction
  Action    = $Rule.Action
  EdgeTraversalPolicy = $Rule.EdgeTraversalPolicy
  LooseSourceMapping = $Rule.LooseSourceMapping
  LocalOnlyMapping = $Rule.LocalOnlyMapping
  Owner    = $Rule.Owner
  LocalAddress  = StringArrayToList $AdressFilter.LocalAddress
  RemoteAddress  = StringArrayToList $AdressFilter.RemoteAddress
  Protocol   = $PortFilter.Protocol
  LocalPort   = StringArrayToList $PortFilter.LocalPort
  RemotePort   = StringArrayToList $PortFilter.RemotePort
  IcmpType   = StringArrayToList $PortFilter.IcmpType
  DynamicTarget  = $PortFilter.DynamicTarget
  Program    = $ApplicationFilter.Program -Replace "$($ENV:SystemRoot.Replace("\","\\"))\\", "%SystemRoot%\" -Replace "$(${ENV:ProgramFiles(x86)}.Replace("\","\\").Replace("(","\(").Replace(")","\)"))\\", "%ProgramFiles(x86)%\" -Replace "$($ENV:ProgramFiles.Replace("\","\\"))\\", "%ProgramFiles%\"
  Package    = $ApplicationFilter.Package
  Service    = $ServiceFilter.Service
  InterfaceAlias  = StringArrayToList $InterfaceFilter.InterfaceAlias
  InterfaceType  = $InterfaceTypeFilter.InterfaceType
  LocalUser   = $SecurityFilter.LocalUser
  RemoteUser   = $SecurityFilter.RemoteUser
  RemoteMachine  = $SecurityFilter.RemoteMachine
  Authentication  = $SecurityFilter.Authentication
  Encryption   = $SecurityFilter.Encryption
  OverrideBlockRules = $SecurityFilter.OverrideBlockRules
 }

 # add to array with rules
 $FirewallRuleSet += $HashProps
}

$FirewallRuleSet | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $CSVFile

#Take Protection software information 
Write-Host "#########>Take Antivirus Information<#########" -ForegroundColor DarkGreen

$testAntivirus = Get-WmiObject -Namespace "root\SecurityCenter" -Query "SELECT * FROM AntiVirusProduct" |Select-Object displayName, pathToSignedProductExe, pathToSignedReportingExe, timestamp

if ($null -eq $testAntivirus ) {

 $testAntivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct" |Select-Object displayName, pathToSignedProductExe, pathToSignedReportingExe, timestamp

 if ( $null -eq $testAntivirus) {
  Write-Host "Antivirus software not detected , please check manualy" -ForegroundColor Red
 }
} 

$CSVFileAntivirus = "./Antivirus-" + "$OSName" + ".csv"
$testAntivirus | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $CSVFileAntivirus

#Audit share present on the server 

Write-Host "#########>Take Share Information<#########" -ForegroundColor DarkGreen
$nomfichierShare = "./SHARE " + "$OSName" + ".csv"
 
function addShare {
 param([string]$NS, [string]$CS, [string]$US, [string]$TS, [string]$NDS)
 $d = New-Object PSObject
 $d | Add-Member -Name "Share Name" -MemberType NoteProperty -Value $NS
 $d | Add-Member -Name "Share Path "-MemberType NoteProperty -Value $CS
 $d | Add-Member -Name "AccountName "-MemberType NoteProperty -Value $US
 $d | Add-Member -Name "AccessControlType"-MemberType NoteProperty -Value $TS
 $d | Add-Member -Name "AccessRight"-MemberType NoteProperty -Value $NDS
 return $d
}
$tableauShare = @()
  
$listShare = Get-SmbShare 
 
 
foreach ( $share in $listShare) {
 
 $droits = Get-SmbShareAccess $share.name
 
 foreach ( $droit in $droits) {

 
  $tableauShare += addShare -NS $share.name -CS $share.path -US $droit.AccountName -TS $droit.AccessControlType -NDS $droit.AccessRight
 
 
 }
}

$tableauShare | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $nomfichierShare

#Audit Appdata 
Write-Host "#########>Take Appdata Information<#########" -ForegroundColor DarkGreen
$cheminProfils = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows' 'NT\CurrentVersion\ProfileList\).ProfilesDirectory
  
$profilpresent = Get-ChildItem $cheminProfils 
  
$resultAPP = @()
$nomfichierAPP = "./APPDATA" + "$OSName" + ".csv"
  
  
foreach ( $profil in $profilpresent) {
  
  $verifAppdata = Test-Path $cheminProfils\$profil\Appdata
  
  if ($verifAppdata -eq $true) {
  
    $resultat = Get-ChildItem $cheminProfils\$profil\Appdata -Recurse -Include *.bat, *.exe, *.ps1, *.ps1xml, *.PS2, *.PS2XML, *.psc1, *.PSC2, *.msi, *.py, *.pif, *.MSP , *.COM, *.SCR, *.hta, *.CPL, *.MSC, *.JAR, *.VB, *.VBS, *.VBE, *.JS, *.JSE, *.WS, *.wsf, *.wsc, *.wsh, *.msh, *.MSH1, *.MSH2, *.MSHXML, *.MSH1XML, *.MSH2XML, *.scf, *.REG, *.INF   | Select-Object Name, Directory, Fullname 
  
  foreach ($riskyfile in $resultat) {

$signature = Get-FileHash -Algorithm SHA256 $riskyfile.Fullname -ErrorAction SilentlyContinue



  $resultApptemp = [PSCustomObject]@{
                            Name  = $riskyfile.Name
                            Directory = $riskyfile.Directory
                            Path = $riskyfile.Fullname
							              Signature = $signature.Hash
                            Profil= $profil.name
							
                        }

$resultAPP +=$resultApptemp


  }
  }
}
 
    $resulatCount = $resultAPP |Measure-Object 
    $resulatCount = $resulatCount.Count
  
  
  
    if ( $resulatCount -gt 0) {
      $resultAPP | Export-Csv -NoTypeInformation $nomfichierAPP
  
      
    }

#Microsoft Update Liste 
Write-Host "#########>Take Update Information<#########" -ForegroundColor DarkGreen
$nomfichierUpdate = "./systemUpdate- " + "$OSName" + ".html"
wmic qfe list brief /format:htable > $nomfichierUpdate


#Check installed Service
Write-Host "#########>Take Service Information<#########" -ForegroundColor DarkGreen
$nomfichierservice = "./Service- " + "$OSName" + ".csv"

Get-WmiObject win32_service | Select-Object Name, DisplayName, State, StartName, StartMode, PathName |Export-Csv -Delimiter ";" $nomfichierservice -NoTypeInformation

#Check Scheduled task
Write-Host "#########>Take Scheduled task Information<#########" -ForegroundColor DarkGreen
$nomfichierttache = "./Scheduled-task- " + "$OSName" + ".csv"
$tabletache = Get-ScheduledTask |Select-Object -Property *
$resultTask= @()
foreach ($tache in $tabletache) {
$taskactions = Get-ScheduledTask $tache.Taskname |Select-Object -ExpandProperty Actions

 foreach ( $taskaction in $taskactions ) {


$resultTasktemp = [PSCustomObject]@{
                            Task_name = $tache.Taskname
                            Task_URI = $tache.URI
                            Task_state = $tache.State
                            Task_Author = $tache.Author
							Task_Description = $tache.Description
                            Task_action = $taskaction.Execute 
                            Task_action_Argument = $taskaction.Arguments
                            Task_Action_WorkingDirectory = $taskaction.WorkingDirectory
							
                        }

$resultTask += $resultTasktemp

 }
  }
  



$resultTask | Export-Csv -NoTypeInformation $nomfichierttache

#check net accounts intel
Write-Host "#########>Take Accounts Policy Information<#########" -ForegroundColor DarkGreen
$nomfichierNetAccount = "./AccountsPolicy- " + "$OSName" + ".txt"
net accounts > $nomfichierNetAccount

#Check listen port 
Write-Host "#########>Take Port listening Information<#########" -ForegroundColor DarkGreen
$nomfichierPort = "./Listen-port- " + "$OSName" + ".csv"
$listport = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, State, OwningProcess
"LocalAddress;LocalPort;State;OwningProcess;Path" > $nomfichierPort

foreach ($port in $listport) {
 $exepath = Get-Process -PID $port.OwningProcess |Select-Object Path
 $port.LocalAddress + ";" + $port.LocalPort + ";" + $port.State + ";" + $exepath.path >> $nomfichierPort
}

#List all local user 

$listlocaluser = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"

foreach ( $user in $listlocaluser) {


 if ( $user.sid -like "*-500") {

  $nomcompteadmin = $user.Name

  $statutcompteadmin = $user.Disabled
  if ($statutcompteadmin -eq $true) {
   $adminstate = "disable"
  }
  else {
   $adminstate = "enable"
  }
 }
 elseif ( $user.sid -like "*-501") {
  $nomcompteguest = $user.Name
  $statutcompteguest = $user.Disabled
  if ($statutcompteguest -eq $true) {
   $gueststate = "disable"
  }
  else {
   $gueststate = "enable"
  }

 }

}

$listlocaluser > "localuser-$OSName.txt"

Write-Host "#########>Begin CIS audit<#########" -ForegroundColor Green
#Check password Policy
Write-Host "#########>Begin password policy audit<#########" -ForegroundColor DarkGreen
#Check Enforce password history
$id = "PP" + "$indextest"
$chaine = $id + ";" + "(L1)Ensure 'Enforce password history' is set to '24 or more password(s)" + ";"
$traitement = Get-Content $seceditfile |Select-String "PasswordHistorySize"

$chaine += $traitement

$chaine>> $nomfichier
#Check Maximum password age 
$indextest += 1
$id = "PP" + "$indextest"
$chaine = $null
$traitement = $null

$chaine = "$id" + ";" + "(L1)Maximum password age is set to 60 or fewer days, but not 0" + ";"
$traitement = Get-Content $seceditfile |Select-String "MaximumPasswordAge" |select-object -First 1

$chaine += $traitement
$chaine>> $nomfichier

#Check Minimum password age
$indextest += 1
$id = "PP" + "$indextest"
$chaine = $null
$traitement = $null

$chaine = "$id" + ";" + "(L1)Minimum password age is set to 1 or more day(s)" + ";"
$traitement = Get-Content $seceditfile |Select-String "MinimumPasswordAge"

$chaine += $traitement
$chaine>> $nomfichier

# Check Minimum password length
$indextest += 1
$id = "PP" + "$indextest"
$chaine = $null
$traitement = $null

$chaine = "$id" + ";" + "(L1)Minimum password length is set to 14 or more character(s)" + ";"
$traitement = Get-Content $seceditfile |Select-String "MinimumPasswordLength"

$chaine += $traitement
$chaine>> $nomfichier

#Check Password must meet complexity requirements
$indextest += 1
$chaine = $null
$traitement = $null
$id = "PP" + "$indextest"
$chaine = "$indextest" + ";" + "(L1)Password must meet complexity requirements is set to Enabled, value must be 1" + ";"
$traitement = Get-Content $seceditfile |Select-String "PasswordComplexity"

$chaine += $traitement
$chaine>> $nomfichier

#Check Store passwords using reversible encryption
$indextest += 1
$chaine = $null
$traitement = $null
$id = "PP" + "$indextest"
$chaine = "$id" + ";" + "(L1)Store passwords using reversible encryption is set to Disabled, value must be 0" + ";"
$traitement = Get-Content $seceditfile |Select-String "ClearTextPassword"

$chaine += $traitement
$chaine>> $nomfichier

#Check lock out policy
Write-Host "#########>Begin account lockout policy audit<#########" -ForegroundColor DarkGreen

#Check Account lockout duration
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ALP" + "$indextest"

$chaine = "$id" + ";" + "(L1)Account lockout duration is set to 15 or more minute(s)" + ";"
$traitement = Get-Content $nomfichierNetAccount |Select-String -pattern '(Durée du verrouillage)|(Lockout duration)'
$chaine += $traitement
$chaine>> $nomfichier
#Check Account lockout threshold
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ALP" + "$indextest"

$chaine = "$id" + ";" + "(L1)Ensure Account lockout threshold is set to 10 or fewer invalid logon attempt(s), but not 0" + ";"
$traitement = Get-Content $nomfichierNetAccount |Select-String -pattern '(Seuil de verrouillage)|(Lockout threshold)'
$chaine += $traitement
$chaine>> $nomfichier

#Check Reset account lockout 
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ALP" + "$indextest"
$chaine = "$id" + ";" + "(L1)Reset account lockout counter after is set to 15 or more minute(s)" + ";"
$traitement = Get-Content $nomfichierNetAccount |Select-String -pattern "(Fenêtre d'observation du verrouillage)|(Lockout observation window)"


$chaine += $traitement
$chaine>> $nomfichier


#Check user rights assignment
Write-Host "#########>Begin user rights assignment audit<#########" -ForegroundColor DarkGreen

#Check Access Credential Manager 
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Acess Credential Manager as a trusted caller is set to No One , value must be empty" + ";"
$traitement = Get-Content $seceditfile |Select-String "SeTrustedCredManAccessPrivilege"

$chaine += $traitement
$chaine>> $nomfichier

#Check Access this computer from the network
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Access this computer from the network, Only Administrators, Remote Desktop Users " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeNetworkLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeNetworkLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier


#Check Act as part of the operating system
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Act as part of the operating system' , Must be empty " + ";"
$test = Get-Content $seceditfile |Select-String "SeTcbPrivilege"
$chaineSID = $chaineSID.line
$traitement = "SeTcbPrivilege" + ":"

$traitement += Reverse-SID $test

$chaine += $traitement
$chaine>> $nomfichier


#Allow log on through Remote Desktop Services
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Allow log on through Remote Desktop Services, Only Administrators, Remote Desktop Users. If Remote Apps or CItrix authentificated users" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeRemoteInteractiveLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeRemoteInteractiveLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

#Ensure Back up files and directories


$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Back up files and directories, Only Administrators," + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeBackupPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeBackupPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier



#Debug programs

$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Debug programs is set to Administrators " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeDebugPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeDebugPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier


#Deny access to this computer from the network

$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Deny access to this computer from the network,Guest Local Account and member of Domain admin " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyNetworkLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeDenyNetworkLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

#Deny log on through Remote Desktop Services'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Deny log on through Remote Desktop Services, Guest, Local account and member of Domain admin' " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyRemoteInteractiveLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeDenyRemoteInteractiveLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier


#Enable computer and user accounts to be trusted for delegation
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Enable computer and user accounts to be trusted for delegation,No one " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeEnableDelegationPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeEnableDelegationPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

#Generate security audits'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Generate security audits is set to LOCAL SERVICE, NETWORK SERVICE " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeAuditPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeAuditPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

#Impersonate a client after authentication
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Impersonate a client after authentication , Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeImpersonatePrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeImpersonatePrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

#Manage auditing and security log
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Manage auditing and security log,Administrators" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeSecurityPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeSecurityPrivilege" + ":"
$traitement += Reverse-SID $chaineSID
$chaine += $traitement
$chaine>> $nomfichier
#Accounts: Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Accounts: Limit local account use of blank passwords to console logon only is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object LimitBlankPasswordUse
 $traitement = $traitement.LimitBlankPasswordUse
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Write-Host "#########>Begin audit policy audit<#########" -ForegroundColor DarkGreen

#Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "APA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object SCENoApplyLegacyAuditPolicy
 $traitement = $traitement.SCENoApplyLegacyAuditPolicy
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

#Checking Domain member Audit
Write-Host "#########>Begin Domain member policy audit<#########" -ForegroundColor DarkGreen

#Domain member: Digitally encrypt or sign secure channel data (always) is set to Enable
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DMP" + "$indextest"
$chaine = "$id" + ";" + "(L1)Domain member: Digitally encrypt or sign secure channel data (always) is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object RequireSignOrSeal
 $traitement = $traitement.RequireSignOrSeal
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier

#Domain member: Disable machine account password changes
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DMP" + "$indextest"
$chaine = "$id" + ";" + "(L1)Domain member: Disable machine account password changes is set to Disabled, Value must be 0 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
				$traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object DisablePasswordChange
 $traitement = $traitement.DisablePasswordChange
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

#Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DMP" + "$indextest"
$chaine = "$id" + ";" + "(L1)Domain member: Maximum machine account password age is set to 30 or fewer days, but not 0 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
				$traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object MaximumPasswordAge
 $traitement = $traitement.MaximumPasswordAge
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
#'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DMP" + "$indextest"
$chaine = "$id" + ";" + "(L1)Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled,value must 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object RequireStrongKey
 $traitement = $traitement.RequireStrongKey
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

#Checking Interactive logon
Write-Host "#########>Begin Interactive logon audit<#########" -ForegroundColor DarkGreen

#Ensure Interactive logon: Do not display last user name is set to Enabled

$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "IL" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Interactive logon: Do not display last user name is set to Enabled,value must 1 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object DontDisplayLastUserName
 $traitement = $traitement.DontDisplayLastUserName
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


#Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'

$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "IL" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Interactive logon: Do not require CTRL+ALT+DEL' is set to Disabled,value must 0 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object DisableCAD
 $traitement = $traitement.DisableCAD
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier


#Ensure 'Interactive logon: Prompt user to change password before expiration

$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null

$id = "IL" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Interactive logon: Prompt user to change password before expiration is set to between 5 and 14 days " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |Select-Object PasswordExpiryWarning
 $traitement = $traitement.PasswordExpiryWarning
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier



#Checking Interactive logon
Write-Host "#########>Begin Microsoft network client audit<#########" -ForegroundColor DarkGreen

#Microsoft network client: Digitally sign communications (always)

$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNC" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Microsoft network client: Digitally sign communications (always) is set to Enabled,value must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" |Select-Object RequireSecuritySignature
 $traitement = $traitement.RequireSecuritySignature
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

#'Microsoft network client: Digitally sign communications (if server agrees

$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNC" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Microsoft network client: Digitally sign communications (if server agrees) is set to Enabled,value must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" |Select-Object EnableSecuritySignature
 $traitement = $traitement.EnableSecuritySignature
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

#Microsoft network client: Send unencrypted password to third-party SMB servers

$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNC" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Microsoft network client: Send unencrypted password to third-party SMB servers is set to Disabled,value must be 0 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" |Select-Object EnablePlainTextPassword
 $traitement = $traitement.EnablePlainTextPassword
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier

#Checking Microsoft network server 
Write-Host "#########>Begin Microsoft network server audit<#########" -ForegroundColor DarkGreen

#Microsoft network server: Amount of idle time required before suspending session
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNS" + "$indextest"
$chaine = "$id" + ";" + "(L1)Microsoft network server: Amount of idle time required before suspending session is set to 15 or fewer minute(s) but not 0, " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object AutoDisconnect
 $traitement = $traitement.AutoDisconnect
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


#Ensure 'Microsoft network server: Digitally sign communications (always
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNS" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Microsoft network server: Digitally sign communications (always) is set to Enabled,must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object RequireSecuritySignature
 $traitement = $traitement.RequireSecuritySignature
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

# Microsoft network server: Disconnect clients when logon hours expire'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNS" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Microsoft network server: Disconnect clients when logon hours expire is set to Enabled,must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object EnableForcedLogoff
 $traitement = $traitement.EnableForcedLogoff
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

#Checking Microsoft network server
Write-Host "#########>Begin Network access audit<#########" -ForegroundColor DarkGreen

# Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Network access: Allow anonymous SID/Name translation is set to Disabled,must be 0 " + ";"
$exist = Test-Path HKLM:\System\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object AnonymousNameLookup
 $traitement = $traitement.AnonymousNameLookup
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

# Network access: Do not allow anonymous enumeration of SAM accounts'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "NA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Network access: Do not allow anonymous enumeration of SAM accounts is set to Enabled,must be 1 " + ";"
$traitement = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object RestrictAnonymousSAM
$traitement = $traitement.RestrictAnonymousSAM
$chaine += $traitement
$chaine>> $nomfichier
# Network access: Do not allow anonymous enumeration of SAM accounts and shares'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "NA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled',must be 1 " + ";"
$traitement = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object RestrictAnonymous
$traitement = $traitement.RestrictAnonymous
$chaine += $traitement
$chaine>> $nomfichier
# Network access: Do not allow storage of passwords and credentials for network authentication
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Network access: Do not allow storage of passwords and credentials for network authentication is set to Enabled,must be 1 " + ";"
$exist = Test-Path HKLM:\System\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object DisableDomainCreds
 $traitement = $traitement.DisableDomainCreds
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
# Network access: Let Everyone permissions apply to anonymous user
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Network access: Let Everyone permissions apply to anonymous users is set to Disabled,must be 0 " + ";"
$exist = Test-Path HKLM:\System\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object EveryoneIncludesAnonymous
 $traitement = $traitement.EveryoneIncludesAnonymous
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
#Checking Microsoft network server 

Write-Host "#########>Begin User Account Control(UAC) audit<#########" -ForegroundColor DarkGreen
#User Account Control: Admin Approval Mode for the Built-in Administrator account
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "UAC" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure User Account Control: Admin Approval Mode for the Built-in Administrator account is set to Enabled,value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object FilterAdministratorToken
 $traitement = $traitement.FilterAdministratorToken
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier


#Remote Desktop Services (TermService)'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "SS" + "$indextest"
$chaine = "$id" + ";" + "(L2)Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TermService"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier


#Windows Firewall: Private: Inbound connections
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPRIP" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default, value must be Block" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" |Select-Object DefaultInboundAction
$traitement = $traitement.DefaultInboundAction
$chaine += $traitement
$chaine>> $nomfichier

#Windows Firewall: Private: Outbound connections'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPRIP" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)', value must be Allow but if it's block it s fucking badass" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" |Select-Object DefaultOutboundAction
$traitement = $traitement.DefaultOutboundAction
$chaine += $traitement
$chaine>> $nomfichier
#Windows Firewall: Private: Settings: Display a notification'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPRIP" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No, value must false " + ";"
$traitement = Get-NetFirewallProfile -Name "Private" |Select-Object NotifyOnListen
$traitement = $traitement.NotifyOnListen
$chaine += $traitement
$chaine>> $nomfichier

Write-Host "#########>Begin Playback audit<#########" -ForegroundColor DarkGreen

#Prevent Codec Download'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "PLB" + "$indextest"
$chaine = "$id" + ";" + "(L2)Ensure 'Prevent Codec Download' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" |Select-Object PreventCodecDownload
 $traitement = $traitement.PreventCodecDownload

}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Write-Host "#########>END Audit<#########" -ForegroundColor DarkGreen