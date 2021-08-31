---
layout: single
title: Azure Sentinel
date: 2021-08-31
classes: wide
header:
  teaser: /assets/images/security.jpg
categories:
  - Blue Team
  - infosec
tags:
  - Blue Team

---


   
## Search
```
SecurityEvent 
| search "example"
--------------------
SecurityAlert #Search in diferent tables
| search in (SecurityEvent, SecurityAlert, Event) "example.adm"
--------------------
SecurityEvent
| search IpAddress == "example"
```
## Where
```
SecurityEvent
| where TimeGenerated >= ago(1h) #Go back one hour. now(-15m) 
  and Computer contains "example"
--------------------
d - days
h - hours
m - minutes
s - seconds
ms - milliseconds
microsecond - microseconds
--------------------
SecurityAlert
| where * has "example" # * = All  # has and contains behave the same.
--------------------
#Search between time ranges
| where TimeGenerated between (datetime("2020-02-23 00:00:01") .. datetime("2020-03-08 23:59:99")
```
## The_Equality_and_relational_Operators
```
==      equal to
!=      not equal to
>       greater than
>=      greater than or equal to
<       less than
<=      less than or equal to
```
## Take
```
SecurityEvent
| take 5 
--------------------
SecurityAlert
| where TimeGenerated >= ago(1h)
  and Computer contains "example"
| take 10
```
## Count
```
SecurityAlert
| count
--------------------
SecurityAlert
| where TimeGenerated >= ago(1h)
  and Computer contains "example"
| count
```
## Summarize
```
SecurityEvent #Resume
| where TimeGenerated >= ago(1h)
  and Account contains "example"
| summarize by TimeGenerated, IpAddress, WorkstationName
```
## Project
```
SecurityAlert
| where TimeGenerated >= ago(1h)
| project Account,
          Computer,
          example,
          example,
```
## Distinct
```
SecurityEvent
| where TimeGenerated >= ago(1h)
| distinct example, example
--------------------
Event
| where Account contains "example"
| distinct example, example
```
## Print
```
print now() #ActualTime
print 120*80
```
## Union
```
SophosXG_CL
| where TimeGenerated >= ago(60d)
| union (SecurityAlert)
| project url_s
         , AlertName
```
## ADAccountsLockouts
Detects Active Directory account lockouts.
```
let timeframe = 7d;
  SecurityEvent
  | where TimeGenerated >= ago(timeframe)
  | where EventID == 4740
  | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), LockoutsCount = count() by Activity, Account, TargetSid, TargetDomainName, SourceComputerId, SourceDomainController = Computer
  | extend timestamp = StartTime, AccountCustomEntity = Account, HostCustomEntity = TargetDomainName
```
## PowerShell_Download
Finds PowerShell execution events that could involve a download.
```
let timeframe = 1d;
  let ProcessCreationEvents=() {
  let processEvents=SecurityEvent
  | where EventID==4688
  | project  TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName,        AccountDomain=SubjectDomainName,
    FileName=tostring(split(NewProcessName, '\\')[-1]),
  ProcessCommandLine = CommandLine, 
  InitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine="",InitiatingProcessParentFileName="";
  processEvents};
  ProcessCreationEvents
  | where TimeGenerated >= ago(timeframe) 
  | where FileName in~ ("powershell.exe", "powershell_ise.exe")
  | where ProcessCommandLine has "Net.WebClient"
     or ProcessCommandLine has "DownloadFile"
     or ProcessCommandLine has "Invoke-WebRequest"
     or ProcessCommandLine has "Invoke-Shellcode"
     or ProcessCommandLine contains "http:"
  | project TimeGenerated, ComputerName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
  | top 100 by TimeGenerated
  | extend timestamp = TimeGenerated, HostCustomEntity = ComputerName, AccountCustomEntity = AccountName
  ```
## New_sharepoint_downloads_by_IP
Shows volume of documents uploaded to or downloaded from Sharepoint by new IP addresses. In stable environments such connections by new IPs may be unauthorized, especially if associated with spikes in volume which could be associated with large-scale document exfiltration.'
```
let starttime = 14d;
  let endtime = 1d;
  let historicalActivity=
  OfficeActivity
  | where  RecordType == "SharePointFileOperation"
  | where Operation in ("FileDownloaded", "FileUploaded")
  | where TimeGenerated between(ago(starttime)..ago(endtime))
  | summarize historicalCount=count() by ClientIP;
  let recentActivity = OfficeActivity
  | where  RecordType == "SharePointFileOperation"
  | where Operation in ("FileDownloaded", "FileUploaded")
  | where TimeGenerated > ago(endtime) 
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), recentCount=count() by ClientIP;
  recentActivity | join kind= leftanti (
     historicalActivity 
  ) on ClientIP 
  | extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP
  ```
  ## Failed_logons
  
  A summary of failed logons can be used to infer lateral movement with the intention of discovering credentials and sensitive data.
  ```
  let timeframe = 1d;
  SecurityEvent
  | where TimeGenerated >= ago(timeframe)
  | where AccountType == 'User' and EventID == 4625
  | extend Reason = case(
  SubStatus == '0xc000005e', 'No logon servers available to service the logon request',
  SubStatus == '0xc0000062', 'Account name is not properly formatted',
  SubStatus == '0xc0000064', 'Account name does not exist',
  SubStatus == '0xc000006a', 'Incorrect password',    SubStatus == '0xc000006d', 'Bad user name or password',
  SubStatus == '0xc000006f', 'User logon blocked by account restriction',
  SubStatus == '0xc000006f', 'User logon outside of restricted logon hours',
  SubStatus == '0xc0000070', 'User logon blocked by workstation restriction',
  SubStatus == '0xc0000071', 'Password has expired',
  SubStatus == '0xc0000072', 'Account is disabled',
  SubStatus == '0xc0000133', 'Clocks between DC and other computer too far out of sync',
  SubStatus == '0xc000015b', 'The user has not been granted the requested logon right at this machine',
  SubStatus == '0xc0000193', 'Account has expirated',
  SubStatus == '0xc0000224', 'User is required to change password at next logon',
  SubStatus == '0xc0000234', 'Account is currently locked out',
  strcat('Unknown reason substatus: ', SubStatus))
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by Reason
  | extend timestamp = StartTimeUtc
  ```
  ## Hosts_with_new_logons
  Shows new accounts that have logged onto a host for the first time - this may clearly be benign activity but an account 
  logging onto multiple hosts for the first time can also be used to look for evidence of that account being used to move 
  laterally across a network.
  
```
  let starttime = 7d;
  let endtime = 1d;
  let LogonEvents=() { 
  let logonSuccess=SecurityEvent 
  | where EventID==4624 
  | project TimeGenerated, ComputerName=Computer, AccountName=TargetUserName, AccountDomain=TargetDomainName, IpAddress, ActionType='Logon';
  let logonFail=SecurityEvent 
  | where EventID==4625 
  | project TimeGenerated, ComputerName=Computer, AccountName=TargetUserName, AccountDomain=TargetDomainName, IpAddress, ActionType='LogonFailure';
  logonFail 
  | union logonSuccess
  };
  LogonEvents 
  | where TimeGenerated > ago(endtime) 
  | where ActionType == 'Logon' 
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by ComputerName, AccountName 
  | join kind=leftanti ( 
  LogonEvents 
  | where TimeGenerated between(ago(starttime)..ago(endtime)) 
  | where ActionType == 'Logon' 
  | summarize count() by ComputerName, AccountName 
  ) on ComputerName, AccountName 
  | summarize StartTimeUtc = min(StartTimeUtc), EndTimeUtc = max(EndTimeUtc), HostCount=dcount(ComputerName), HostSet=makeset(ComputerName, 10)  by AccountName, ComputerName
  | extend timestamp = StartTimeUtc, AccountCustomEntity = AccountName
```
## Process_entropy

Entropy calculation used to help identify Hosts where they have a high variety of processes(a high entropy process list on a given Host over time).
This helps us identify rare processes on a given Host. Rare here means a process shows up on the Host relatively few times in the the last 7days.
The Weight is calculated based on the Entropy, Process Count and Distinct Hosts with that Process. The lower the Weight/ProcessEntropy the, more interesting.
The Weight calculation increases the Weight if the process executes more than once on the Host or has executed on more than 1 Hosts.
In general, this should identify processes on a Host that are rare and rare for the environment.
References: https://medium.com/udacity/shannon-entropy-information-gain-and-picking-balls-from-buckets-5810d35d54b4.
https://en.wiktionary.org/wiki/Shannon_entropy.

```
let end = startofday(now());
  let start = end - 7d;
  let Exclude = SecurityEvent
  // Timeframe is set so that results do not change during the same day (UTC time)
  | where TimeGenerated >= start and TimeGenerated <= end
  | where EventID == 4688
  | summarize ExcludeCompCount = dcount(Computer),  ExcludeProcCount = count() by Process 
  // Removing noisy processes for an environment, adjust as needed
  | where ExcludeProcCount >= 2000 and ExcludeCompCount > 2
  ;
  let AllSecEvents = SecurityEvent
  | where TimeGenerated >= start and TimeGenerated <= end
  | where EventID == 4688
  // excluding well known processes
  | where NewProcessName !endswith ':\\Windows\\System32\\conhost.exe' and ParentProcessName !endswith ':\\Windows\\System32\\conhost.exe'
  | where ParentProcessName !endswith ":\\Windows\\System32\\wuauclt.exe" and NewProcessName !startswith "C:\\Windows\\SoftwareDistribution\\Download\\Install\\AM_Delta_Patch_"
  | where ParentProcessName !has ":\\WindowsAzure\\GuestAgent_" and NewProcessName !has ":\\WindowsAzure\\GuestAgent_"
  | where ParentProcessName !has ":\\WindowsAzure\\WindowsAzureNetAgent_" and NewProcessName !has ":\\WindowsAzure\\WindowsAzureNetAgent_"
  | where ParentProcessName !has ":\\ProgramData\\Microsoft\\Windows Defender\\platform\\" and ParentProcessName !endswith "\\MpCmdRun.exe" 
  | project Computer, Process;
  // Removing noisy process from full list
  let Include = Exclude | join kind= rightanti (
  AllSecEvents
  ) on Process;
  // Identifying prevalence for a given process in the environment
  let DCwPC = Include | summarize DistinctComputersWithProcessCount = dcount(Computer) by Process
  | join kind=inner (
  Include 
  ) on Process
  | distinct Computer, Process, DistinctComputersWithProcessCount;
  // Getting the Total process count on each host to use as the denominator in the entropy calc
  let TPCoH = Include | summarize TotalProcessCountOnHost = count(Process) by Computer
  | join kind=inner (
  Include 
  ) on Computer
  | distinct Computer, Process, TotalProcessCountOnHost
  //Getting a decimal value for later computation
  | extend TPCoHValue = todecimal(TotalProcessCountOnHost);
  // Need the count of each class in my bucket or also said as count of ProcName(Class) per Host(Bucket) for use in the entropy calc
  let PCoH = Include | summarize ProcessCountOnHost = count(Process) by Computer, Process
  | join kind=inner (
  Include
  ) on Computer,Process
  | distinct Computer, Process, ProcessCountOnHost
  //Getting a decimal value for later computation
  | extend PCoHValue = todecimal(ProcessCountOnHost);
  let Combined = DCwPC | join ( TPCoH ) on Computer, Process | join ( PCoH ) on Computer, Process; 
  let Results = Combined
  // Entropy calculation
  | extend ProcessEntropy = -log2(PCoHValue/TPCoHValue)*(PCoHValue/TPCoHValue)
  | extend AdjustedProcessEntropy = toreal(ProcessEntropy*10000)
  // Calculating Weight, see details in description
  | extend Weight = toreal((ProcessEntropy*10000)*ProcessCountOnHost*DistinctComputersWithProcessCount)
  // Remove or increase value to see processes with low entropy, meaning more common.
  | where Weight <= 75
  | project Computer, Process, Weight , ProcessEntropy, TotalProcessCountOnHost, ProcessCountOnHost, DistinctComputersWithProcessCount, AdjustedProcessEntropy;
  // Join back full entry
  Results | join kind= inner (
      SecurityEvent
      | where TimeGenerated >= start and TimeGenerated <= end
      | where EventID == 4688
      // excluding well known processes
      | where NewProcessName !endswith ':\\Windows\\System32\\conhost.exe' and ParentProcessName !endswith ':\\Windows\\System32\\conhost.exe'
      | where ParentProcessName !endswith ":\\Windows\\System32\\wuauclt.exe" and NewProcessName !startswith "C:\\Windows\\SoftwareDistribution\\Download\\Install\\AM_Delta_Patch_"
      | where ParentProcessName !has ":\\WindowsAzure\\GuestAgent_" and NewProcessName !has ":\\WindowsAzure\\GuestAgent_"
      | where ParentProcessName !has ":\\WindowsAzure\\WindowsAzureNetAgent_" and NewProcessName !has ":\\WindowsAzure\\WindowsAzureNetAgent_"
      | where ParentProcessName !has ":\\ProgramData\\Microsoft\\Windows Defender\\platform\\" and ParentProcessName !endswith "\\MpCmdRun.exe" 
      | project TimeGenerated, EventID, Computer, SubjectUserSid, Account, AccountType, Process, NewProcessName, CommandLine, ParentProcessName
  ) on Computer, Process
  | project TimeGenerated, EventID, Computer, SubjectUserSid, Account, Weight, AdjustedProcessEntropy, FullDecimalProcessEntropy = ProcessEntropy, Process, NewProcessName, CommandLine, ParentProcessName, TotalProcessCountOnHost, ProcessCountOnHost, DistinctComputersWithProcessCount
  | sort by Weight asc, AdjustedProcessEntropy asc, NewProcessName asc
  | extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account
```

## Logons_by_type
Comparing succesful and nonsuccessful logon attempts can be used to identify attempts to move laterally within the 
environment with the intention of discovering credentials and sensitive data.
```
let timeframe = 1d;
  SecurityEvent
  | where TimeGenerated >= ago(timeframe)
  | where EventID in (4624, 4625)
  | where AccountType == 'User' 
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Amount = count() by LogonTypeName
  | extend timestamp = StartTimeUtc
  ```
## User_created_deleted
User account created and then deleted within 10 minutes across last 14 days.
```
 // TimeFrame is the number of lookback days, default is last 14 days
  let timeframe = 14d;
  // TimeDelta is the difference between when the account was created and when it was deleted, default is set to 10min or less
  let timedelta = 10m;
  SecurityEvent 
  | where TimeGenerated > ago(timeframe) 
  // A user account was created
  | where EventID == "4720"
  | where AccountType == "User"
  | project creationTime = TimeGenerated, CreateEventID = EventID, Activity, Computer, TargetUserName, UserPrincipalName, 
  AccountUsedToCreate = SubjectUserName, TargetSid, SubjectUserSid 
  | join kind= inner (
     SecurityEvent
     | where TimeGenerated > ago(timeframe) 
     // A user account was deleted 
     | where EventID == "4726" 
  | where AccountType == "User"
  | project deletionTime = TimeGenerated, DeleteEventID = EventID, Activity, Computer, TargetUserName, UserPrincipalName, 
  AccountUsedToDelete = SubjectUserName, TargetSid, SubjectUserSid 
  ) on Computer, TargetUserName
  | where deletionTime - creationTime < timedelta
  | extend TimeDelta = deletionTime - creationTime
  | where tolong(TimeDelta) >= 0
  | project TimeDelta, creationTime, CreateEventID, Computer, TargetUserName, UserPrincipalName, AccountUsedToCreate, 
  deletionTime, DeleteEventID, AccountUsedToDelete
  | extend timestamp = creationTime, HostCustomEntity = Computer, AccountCustomEntity = UserPrincipalName
  ```
  ## Enumeration_users_groups
  Finds attempts to list users or groups using the built-in Windows 'net' tool.
  ```
  let timeframe = 1d;
  let ProcessCreationEvents=() {
  let processEvents=SecurityEvent
  | where EventID==4688
  | project TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName,        AccountDomain=SubjectDomainName,
  FileName=tostring(split(NewProcessName, '\\')[-1]),
  ProcessCommandLine = CommandLine, 
  FolderPath = "",
  InitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine="",InitiatingProcessParentFileName="";
  processEvents};
  ProcessCreationEvents
  | where TimeGenerated >= ago(timeframe)
  | where FileName == 'net.exe' and AccountName != "" and ProcessCommandLine !contains '\\'  and ProcessCommandLine !contains '/add' 
  | where (ProcessCommandLine contains ' user ' or ProcessCommandLine contains ' group ') and (ProcessCommandLine endswith ' /do' or ProcessCommandLine endswith ' /domain') 
  | extend Target = extract("(?i)[user|group] (\"*[a-zA-Z0-9-_ ]+\"*)", 1, ProcessCommandLine) | filter Target  != '' 
  | summarize minTimeGenerated=min(TimeGenerated), maxTimeGenerated=max(TimeGenerated), count() by AccountName, Target, ProcessCommandLine, ComputerName
  | project minTimeGenerated, maxTimeGenerated, count_, AccountName, Target, ProcessCommandLine, ComputerName
  | sort by AccountName, Target
  | extend timestamp = minTimeGenerated, AccountCustomEntity = AccountName, HostCustomEntity = ComputerName
  ```
  ## New_processes_24h
  These new processes could be benign new programs installed on hosts; however, especially in normally stable environments, 
  these new processes could provide an indication of an unauthorized/malicious binary that has been installed and run. 
  Reviewing the wider context of the logon sessions in which these binaries ran can provide a good starting point for identifying     possible attacks.
  ```
  let starttime = 14d;
  let endtime = 1d;
  let ProcessCreationEvents=() {
  let processEvents=SecurityEvent
  | where EventID==4688
  | where TimeGenerated >= ago(starttime) 
  | project TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName, AccountDomain=SubjectDomainName, FileName=tostring(split(NewProcessName, @'')[(-1)]), ProcessCommandLine = CommandLine, InitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine='',InitiatingProcessParentFileName='';
  processEvents};
  ProcessCreationEvents
  | where TimeGenerated >= ago(starttime) and TimeGenerated < ago(endtime)
  | summarize HostCount=dcount(ComputerName) by tostring(FileName)
  | join kind=rightanti (
      ProcessCreationEvents
      | where TimeGenerated >= ago(endtime)
      | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Computers = makeset(ComputerName) , HostCount=dcount(ComputerName) by tostring(FileName)
  ) on FileName
  | project StartTimeUtc, Computers, HostCount, FileName
  | extend timestamp = StartTimeUtc
  ```
  ## Persistence_create_account
  Summarizes uses of uncommon & undocumented commandline switches to create persistence
  User accounts may be created to achieve persistence on a machine.
  Read more here: https://attack.mitre.org/wiki/Technique/T1136
  Query for users being created using "net user" command
  "net user" commands are noisy, so needs to be joined with another signal 
  e.g. in this example we look for some undocumented variations (e.g. /ad instead of /ad
  d).
  ```
  let timeframe = 1d;
  SecurityEvent
  | where TimeGenerated >= ago(timeframe) 
  | where EventID==4688
  | project TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName, 
      AccountDomain=SubjectDomainName, FileName=tostring(split(NewProcessName, '\\')[-1]), 
      ProcessCommandLine = CommandLine, 
      FolderPath = "", InitiatingProcessFileName=ParentProcessName,
      InitiatingProcessCommandLine="",InitiatingProcessParentFileName=""
  | where FileName in~ ("net.exe", "net1.exe")
  | parse kind=regex flags=iU ProcessCommandLine with * "user " CreatedUser " " * "/ad"
  | where not(FileName =~ "net1.exe" and InitiatingProcessFileName =~ "net.exe" and replace("net", "net1", InitiatingProcessCommandLine) =~ ProcessCommandLine)
  | extend CreatedOnLocalMachine=(ProcessCommandLine !contains "/do")
  | where ProcessCommandLine contains "/add" or (CreatedOnLocalMachine == 0 and ProcessCommandLine !contains "/domain")
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), MachineCount=dcount(ComputerName) by CreatedUser, CreatedOnLocalMachine, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
  | extend timestamp = StartTimeUtc, AccountCustomEntity = CreatedUser
  ```
 - # SecurityAlert
 
 ## Alerts_for_IP
 Any Alerts that fired related to a given IpAddress during the range of +6h and -3d.
 ```
   let GetAllAlertsWithIp = (suspiciousEventTime:datetime, v_ipAddress:string){
  //-3d and +6h as some alerts fire after accumulation of events
  let v_StartTime = suspiciousEventTime-3d;
  let v_EndTime = suspiciousEventTime+6h;
  SecurityAlert
  | where TimeGenerated between (v_StartTime .. v_EndTime)
  // expand JSON properties
  | where ExtendedProperties contains v_ipAddress or Entities contains v_ipAddress
  | extend Extprop = parsejson(ExtendedProperties)
  | extend Computer = iff(isnotempty(toupper(tostring(Extprop["Compromised Host"]))), toupper(tostring(Extprop["Compromised Host"])), tostring(parse_json(Entities)[0].HostName))
  | extend Account = iff(isnotempty(tolower(tostring(Extprop["User Name"]))), tolower(tostring(Extprop["User Name"])), tolower(tostring(Extprop["user name"])))
  | extend IpAddress = tostring(parse_json(ExtendedProperties).["Client Address"]) 
  | project StartTimeUtc = StartTime, EndTimeUtc = EndTime, AlertName, Computer, Account, IpAddress, ExtendedProperties, Entities
  | extend timestamp = StartTimeUtc, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
  };
  // change datetime value and <ipaddress> value below
  GetAllAlertsWithIp(datetime('2019-02-05T10:02:51.000'), ("<ipaddress>"))
  ```
  ## Alerts_for_USER
  Any Alerts that fired related to a given account during the range of +6h and -3d.
  ```
  let GetAllAlertsForUser = (suspiciousEventTime:datetime, v_User:string){
  //-3d and +6h as some alerts fire after accumulation of events
  let v_StartTime = suspiciousEventTime-3d;
  let v_EndTime = suspiciousEventTime+6h;
  SecurityAlert
  | where TimeGenerated between (v_StartTime .. v_EndTime)
  | where Account contains v_User
  // expand JSON properties
  | extend Extprop = parsejson(ExtendedProperties)
  | extend Computer = iff(isnotempty(toupper(tostring(Extprop["Compromised Host"]))), toupper(tostring(Extprop["Compromised Host"])), tostring(parse_json(Entities)[0].HostName))
  | extend Account = iff(isnotempty(tolower(tostring(Extprop["User Name"]))), tolower(tostring(Extprop["User Name"])), tolower(tostring(Extprop["user name"])))
  | extend IpAddress = tostring(parse_json(ExtendedProperties).["Client Address"]) 
  | project TimeGenerated, AlertName, Computer, Account, IpAddress, ExtendedProperties 
  | extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
  };
  // change datetime value and username value below
  GetAllAlertsForUser(datetime('2019-01-20T10:02:51.000'), toupper("<username>"))
  ```
  ## Alerts_for_HOST
 Any Alerts that fired on a given host during the range of +6h and -3d.
  ```
  let GetAllAlertsOnHost = (suspiciousEventTime:datetime, v_Host:string){
  //-3d and +6h as some alerts fire after accumulation of events
  let v_StartTime = suspiciousEventTime-3d;
  let v_EndTime = suspiciousEventTime+6h;
  SecurityAlert
  | where TimeGenerated between (v_StartTime .. v_EndTime)
  | where Computer contains v_Host
  // expand JSON properties
  | extend Extprop = parsejson(ExtendedProperties)
  | extend Computer = iff(isnotempty(toupper(tostring(Extprop["Compromised Host"]))), toupper(tostring(Extprop["Compromised Host"])), tostring(parse_json(Entities)[0].HostName))
  | extend Account = iff(isnotempty(tolower(tostring(Extprop["User Name"]))), tolower(tostring(Extprop["User Name"])), tolower(tostring(Extprop["user name"])))
  | extend IpAddress = tostring(parse_json(ExtendedProperties).["Client Address"]) 
  | project TimeGenerated, AlertName, Computer, Account, IpAddress, ExtendedProperties
  | extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
  };
  // change datetime value and hostname value below
  GetAllAlertsOnHost(datetime('2019-01-20T10:02:51.000'), toupper("<hostname>"))
  ```
  
 - # OfficeActivity
  
  ## Office_Mail_Forwarding
Adversaries often abuse email-forwarding rules to monitor activities of a victim, steal information and further gain intelligence on victim or victim's organization.This query over Office Activity data highlights cases where user mail is being forwarded and shows if it is being forwarded to external domains as well.
```
let timeframe = 14d;
  OfficeActivity
  | where TimeGenerated >= ago(timeframe)
  | where (Operation =~ "Set-Mailbox" and Parameters contains 'ForwardingSmtpAddress') 
  or (Operation =~ 'New-InboxRule' and Parameters contains 'ForwardTo')
  | extend parsed=parse_json(Parameters)
  | extend fwdingDestination_initial = (iif(Operation=~"Set-Mailbox", tostring(parsed[1].Value), tostring(parsed[2].Value)))
  | where isnotempty(fwdingDestination_initial)
  | extend fwdingDestination = iff(fwdingDestination_initial has "smtp", (split(fwdingDestination_initial,":")[1]), fwdingDestination_initial )
  | parse fwdingDestination with * '@' ForwardedtoDomain 
  | parse UserId with *'@' UserDomain
  | extend subDomain = ((split(strcat(tostring(split(UserDomain, '.')[-2]),'.',tostring(split(UserDomain, '.')[-1])), '.') [0]))
  | where ForwardedtoDomain !contains subDomain
  | extend Result = iff( ForwardedtoDomain != UserDomain ,"Mailbox rule created to forward to External Domain", "Forward rule for Internal domain")
  | extend ClientIPAddress = case( ClientIP has ".", tostring(split(ClientIP,":")[0]), ClientIP has "[", tostring(trim_start(@'[[]',tostring(split(ClientIP,"]")[0]))), ClientIP )
  | extend Port = case(
  ClientIP has ".", (split(ClientIP,":")[1]),
  ClientIP has "[", tostring(split(ClientIP,"]:")[1]),
  ClientIP
  )
  | project TimeGenerated, UserId, UserDomain, subDomain, Operation, ForwardedtoDomain, ClientIPAddress, Result, Port, OriginatingServer, OfficeObjectId, fwdingDestination
  | extend timestamp = TimeGenerated, AccountCustomEntity = UserId, IPCustomEntity = ClientIPAddress, HostCustomEntity =  OriginatingServer 
  ```
  ## Teams_Files_uploaded
  Provides a summary of files uploaded to teams chats and extracts 
  the users and IP addresses that have accessed them.
  ```
  OfficeActivity 
  | where RecordType =~ "SharePointFileOperation" 
  | where UserId != "app@sharepoint"
  | where SourceRelativeUrl contains "Microsoft Teams Chat Files" 
  | where Operation =~ "FileUploaded" 
  | join kind= leftouter ( 
     OfficeActivity 
      | where RecordType =~ "SharePointFileOperation"
      | where UserId != "app@sharepoint"
      | where SourceRelativeUrl contains "Microsoft Teams Chat Files" 
      | where Operation =~ "FileDownloaded" or Operation =~ "FileAccessed" 
  ) on OfficeObjectId 
  | extend userBag = pack(UserId1, ClientIP1) 
  | summarize makeset(UserId1), make_bag(userBag) by TimeGenerated, UserId, OfficeObjectId, SourceFileName 
  | extend NumberUsers = array_length(bag_keys(bag_userBag))
  | project timestamp=TimeGenerated, AccountCustomEntity=UserId, FileLocation=OfficeObjectId, FileName=SourceFileName, AccessedBy=bag_userBag, NumberOfUsersAccessed=NumberUsers
  ```
  ## Double_file_ext_exes
  Provides a summary of executable files with double file extensions in SharePoint 
  and the users and IP addresses that have accessed them.
  ```
  let timeframe = 14d;
  let known_ext = dynamic(["lnk","log","option","config", "manifest", "partial"]);
  let excluded_users = dynamic(["app@sharepoint"]);
  OfficeActivity
  | where TimeGenerated > ago(timeframe)
  | where RecordType =~ "SharePointFileOperation" and isnotempty(SourceFileName)
  | where OfficeObjectId has ".exe." and SourceFileExtension !in~ (known_ext)
  | extend Extension = extract("[^.]*.[^.]*$",0, OfficeObjectId)
  | join kind= leftouter ( 
    OfficeActivity
      | where TimeGenerated > ago(timeframe)
      | where RecordType =~ "SharePointFileOperation" and (Operation =~ "FileDownloaded" or Operation =~ "FileAccessed") 
      | where SourceFileExtension !in~ (known_ext)
  ) on OfficeObjectId 
  | where UserId1 !in~ (excluded_users)
  | extend userBag = pack(UserId1, ClientIP1) 
  | summarize makeset(UserId1), make_bag(userBag), Start=max(TimeGenerated), End=min(TimeGenerated) by UserId, OfficeObjectId, SourceFileName, Extension 
  | extend NumberOfUsers = array_length(bag_keys(bag_userBag))
  | project UploadTime=Start, Uploader=UserId, FileLocation=OfficeObjectId, FileName=SourceFileName, AccessedBy=bag_userBag, Extension, NumberOfUsers
  | extend timestamp = UploadTime, AccountCustomEntity = Uploader
  ```
  ## New_Admin_account
  This will help you discover any new admin account activity which was seen and were not seen historically. 
  Any new accounts seen in the results can be validated and investigated for any suspicious activities.
  ```
  let starttime = 14d;
  let endtime = 1d;
  let historicalActivity=
  OfficeActivity
  | where TimeGenerated between(ago(starttime)..ago(endtime))
  | where RecordType=="ExchangeAdmin" and UserType in ("Admin","DcAdmin")
  | summarize historicalCount=count() by UserId;
  let recentActivity = OfficeActivity
  | where TimeGenerated > ago(endtime)
  | where UserType in ("Admin","DcAdmin")
  | summarize recentCount=count() by UserId;
  recentActivity | join kind = leftanti (
     historicalActivity
  ) on UserId
  | project UserId,recentCount
  | order by recentCount asc, UserId
  | join kind = rightsemi 
  (OfficeActivity 
  | where TimeGenerated >= ago(endtime) 
  | where RecordType == "ExchangeAdmin" | where UserType in ("Admin","DcAdmin")) 
  on UserId
  | summarize count(), min(TimeGenerated), max(TimeGenerated) by RecordType, Operation, UserType, UserId, OriginatingServer, ResultStatus
  | extend timestamp = min_TimeGenerated, AccountCustomEntity = UserId
  ```
  ## New_sharepoint_downloads_by_IP
  Shows volume of documents uploaded to or downloaded from Sharepoint by new IP addresses. 
  In stable environments such connections by new IPs may be unauthorized, especially if associated with 
  spikes in volume which could be associated with large-scale document exfiltration.
  ```
  let starttime = 14d;
  let endtime = 1d;
  let historicalActivity=
  OfficeActivity
  | where  RecordType == "SharePointFileOperation"
  | where Operation in ("FileDownloaded", "FileUploaded")
  | where TimeGenerated between(ago(starttime)..ago(endtime))
  | summarize historicalCount=count() by ClientIP;
  let recentActivity = OfficeActivity
  | where  RecordType == "SharePointFileOperation"
  | where Operation in ("FileDownloaded", "FileUploaded")
  | where TimeGenerated > ago(endtime) 
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), recentCount=count() by ClientIP;
  recentActivity | join kind= leftanti (
     historicalActivity 
  ) on ClientIP 
  | extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP
  
  ```
  ## New_sharepoint_downloads_USERAGENT
  Tracking via user agent is one way to differentiate between types of connecting device. 
  In homogeneous enterprise environments the user agent associated with an attacker device may stand out as unusual.
  ```
  let starttime = 14d;
  let endtime = 1d;
  let historicalActivity=
  OfficeActivity
  | where  RecordType == "SharePointFileOperation"
  | where Operation in ("FileDownloaded", "FileUploaded")
  | where TimeGenerated between(ago(starttime)..ago(endtime))
  | summarize historicalCount=count() by UserAgent, RecordType;
  let recentActivity = OfficeActivity
  | where  RecordType == "SharePointFileOperation"
  | where Operation in ("FileDownloaded", "FileUploaded")
  | where TimeGenerated > ago(endtime) 
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), recentCount=count() by UserAgent, RecordType;
  recentActivity | join kind = leftanti (
     historicalActivity 
  ) on UserAgent, RecordType
  | order by recentCount asc, UserAgent
  | extend timestamp = StartTimeUtc

  ```
  ## Sharepoint_downloads
  New user agents associated with a clientIP for sharepoint file uploads/downloads.
  ```
  let starttime = 14d;
  let endtime = 1d;
  let historicalUA=
  OfficeActivity
  | where  RecordType == "SharePointFileOperation"
  | where Operation in ("FileDownloaded", "FileUploaded")
  | where TimeGenerated between(ago(starttime)..ago(endtime))
  | summarize by ClientIP, UserAgent;
  let recentUA = OfficeActivity
  | where  RecordType == "SharePointFileOperation"
  | where Operation in ("FileDownloaded", "FileUploaded")
  | where TimeGenerated > ago(endtime) 
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by ClientIP, UserAgent;
  recentUA | join kind=leftanti (
     historicalUA 
  ) on ClientIP, UserAgent
  // Some OfficeActivity records do not contain ClientIP information - exclude these for fewer results:
  | where not(isempty(ClientIP)) 
  | extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP 
  ```
- # SigninLogs
## DisabledAccountSigninAttempts
Failed attempts to sign in to disabled accounts summarized by account name.
```
  let timeRange = 14d;
  SigninLogs 
  | where TimeGenerated >= ago(timeRange)
  | where ResultType == "50057" 
  | where ResultDescription == "User account is disabled. The account has been disabled by an administrator." 
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by AppDisplayName, UserPrincipalName
  | extend timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName
  | order by count_ desc
  
```
## Inactive_Accounts
Query for accounts seen signing in for the first time - these could be associated
with stale/inactive accounts that ought to have been deleted but weren't - and have 
subseuqently been compromised. 
Results for user accounts created in the last 7 days are filtered out.
```
//Inactive accounts that sign in - first-time logins for accounts created in last 7 days are filtered out
  let starttime = 14d;
  let midtime = 7d;
  let endtime = 1d;
  SigninLogs
  | where TimeGenerated >= ago(endtime)
  // successful sign-in
  | where ResultType == 0
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), loginCountToday=count() by UserPrincipalName, Identity
  | join kind=leftanti (
     SigninLogs
     // historical successful sign-in
     | where TimeGenerated < ago(endtime)
     | where TimeGenerated >= ago(starttime)
     | where ResultType == 0
     | summarize by UserPrincipalName, Identity
  ) on UserPrincipalName 
  | join kind= leftanti (
     // filter out newly created user accounts
     AuditLogs
     | where TimeGenerated >= ago(midtime)
     | where OperationName == "Add user" 
     // Normalize to lower case in order to match against equivalent UPN in Signin logs
     | extend NewUserPrincipalName = tolower(extractjson("$.userPrincipalName", tostring(TargetResources[0]), typeof(string)))
  ) on $left.UserPrincipalName == $right.NewUserPrincipalName 
  | extend timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName
  ````
  ## MFA_Login_Attempt_Blocked_USER
An account could be blocked if there are too many failed authentication attempts in a row. This hunting query identifies if a MFA user account that is set to blocked tries to login to Azure AD.
```
 let timeRange = 1d;
  let lookBack = 7d;
  let isGUID = "[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}";
  let MFABlocked = SigninLogs
  | where TimeGenerated >= ago(timeRange)
  | where ResultType != "0" 
  | extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails), Status = strcat(ResultType, ": ", ResultDescription)
  | where StatusDetails =~ "MFA denied; user is blocked"
  | extend Unresolved = iff(Identity matches regex isGUID, true, false);
  // Lookup up resolved identities from last 7 days
  let identityLookup = SigninLogs
  | where TimeGenerated >= ago(lookBack)
  | where not(Identity matches regex isGUID)
  | summarize by UserId, lu_UserDisplayName = UserDisplayName, lu_UserPrincipalName = UserPrincipalName;
  // Join resolved names to unresolved list from MFABlocked signins
  let unresolvedNames = MFABlocked | where Unresolved == true | join kind= inner (
   identityLookup 
  ) on UserId
  | extend UserDisplayName = lu_UserDisplayName, UserPrincipalName = lu_UserPrincipalName
  | project-away lu_UserDisplayName, lu_UserPrincipalName;
  // Join Signins that had resolved names with list of unresolved that now have a resolved name
  let u_MFABlocked = MFABlocked | where Unresolved == false | union unresolvedNames;
  u_MFABlocked 
  | extend OS = tostring(DeviceDetail.operatingSystem), Browser = tostring(DeviceDetail.browser)
  | extend FullLocation = strcat(Location,'|', LocationDetails.state, '|', LocationDetails.city)
  | summarize TimeGenerated = makelist(TimeGenerated), Status = makelist(Status), IPAddresses = makelist(IPAddress), IPAddressCount = dcount(IPAddress), 
    AttemptCount = count() by UserPrincipalName, UserId, UserDisplayName, AppDisplayName, Browser, OS, FullLocation , CorrelationId 
  | mvexpand TimeGenerated, IPAddresses, Status
  | extend TimeGenerated = todatetime(tostring(TimeGenerated)), IPAddress = tostring(IPAddresses), Status = tostring(Status)
  | project-away IPAddresses
  | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserPrincipalName, UserId, UserDisplayName, Status,  IPAddress, IPAddressCount, AppDisplayName, Browser, OS, FullLocation
  | extend timestamp = StartTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
```
## SuccessThenFail_SameUserDiffApp
This identifies when a user account successfully logs onto a given App and within 1 minute fails to logon to a different App.
This may indicate a malicious attempt at accessing disallowed Apps for discovery or potential lateral movement.
```
let timeFrame = ago(1d);
  let logonDiff = 1m;
  let Success = SigninLogs 
  | where TimeGenerated >= timeFrame 
  | where ResultType == "0" 
  | where AppDisplayName !in ("Office 365 Exchange Online", "Skype for Business Online", "Office 365 SharePoint Online")
  | project SuccessLogonTime = TimeGenerated, UserPrincipalName, IPAddress , SuccessAppDisplayName = AppDisplayName;
  let Fail = SigninLogs 
  | where TimeGenerated >= timeFrame 
  | where ResultType !in ("0", "50140") 
  | where ResultDescription !~ "Other" 
  | where AppDisplayName !in ("Office 365 Exchange Online", "Skype for Business Online", "Office 365 SharePoint Online")
  | project FailedLogonTime = TimeGenerated, UserPrincipalName, IPAddress , FailedAppDisplayName = AppDisplayName, ResultType, ResultDescription;
  let InitialDataSet = 
  Success | join kind= inner (
  Fail
  ) on UserPrincipalName, IPAddress 
  | where isnotempty(FailedAppDisplayName)
  | where SuccessLogonTime < FailedLogonTime and FailedLogonTime - SuccessLogonTime <= logonDiff and SuccessAppDisplayName != FailedAppDisplayName;
  let InitialHits = 
  InitialDataSet
  | summarize FailedLogonTime = min(FailedLogonTime), SuccessLogonTime = min(SuccessLogonTime) 
  by UserPrincipalName, SuccessAppDisplayName, FailedAppDisplayName, IPAddress, ResultType, ResultDescription;
  // Only take hits where there is 5 or less distinct AppDisplayNames on the success side as this limits highly active applications where failures occur more regularly
  let Distribution =
  InitialDataSet
  | summarize count(SuccessAppDisplayName) by SuccessAppDisplayName, ResultType
  | where count_SuccessAppDisplayName <= 5;
  InitialHits | join (
     Distribution 
  ) on SuccessAppDisplayName, ResultType
  | project UserPrincipalName, SuccessLogonTime, IPAddress, SuccessAppDisplayName, FailedLogonTime, FailedAppDisplayName, ResultType, ResultDescription 
  | extend timestamp = SuccessLogonTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
```
## Failed_attempt_azurePortal
Access attempts to Azure Portal from an unauthorized user.  Either invalid password or the user account does not exist.
```
let timeRange=ago(7d);
  SigninLogs
  | where TimeGenerated >= timeRange
  | where AppDisplayName contains "Azure Portal"
  // 50126 - Invalid username or password, or invalid on-premises username or password.
  // 50020? - The user doesn't exist in the tenant.
  | where ResultType in ( "50126" , "50020")
  | extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
  | extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
  | extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), IPAddresses = makeset(IPAddress), DistinctIPCount = dcount(IPAddress), 
  makeset(OS), makeset(Browser), makeset(City), AttemptCount = count() 
  by UserDisplayName, UserPrincipalName, AppDisplayName, ResultType, ResultDescription, StatusCode, StatusDetails, Location, State
  | extend timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName
  | sort by AttemptCount
  ```
  ## New_locations_azure_signin
  New Azure Active Directory signin locations today versus historical Azure Active Directory signin data
  In the case of password spraying or brute force attacks one might see authentication attempts for many 
  accounts from a new location.
  ```
  let starttime = 14d;
  let endtime = 1d;
  let countThreshold = 1;
  SigninLogs
  | where TimeGenerated >= ago(endtime)
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), perIdentityAuthCount = count() 
  by Identity, locationString = strcat(tostring(LocationDetails["countryOrRegion"]), "/", tostring(LocationDetails["state"]), "/", 
  tostring(LocationDetails["city"]), ";" , tostring(LocationDetails["geoCoordinates"]))
  | summarize StartTimeUtc = min(StartTimeUtc), EndTimeUtc = max(EndTimeUtc), distinctAccountCount = count(), identityList=makeset(Identity) by locationString
  | extend identityList = iff(distinctAccountCount<10, identityList, "multiple (>10)")
  | join kind= anti (
  SigninLogs
    | where TimeGenerated >= ago(starttime) and TimeGenerated < ago(endtime)
    | project locationString= strcat(tostring(LocationDetails["countryOrRegion"]), "/", tostring(LocationDetails["state"]), "/", 
    tostring(LocationDetails["city"]), ";" , tostring(LocationDetails["geoCoordinates"]))
    | summarize priorCount = count() by locationString
  ) 
  on locationString
  // select threshold above which #new accounts from a new location is deemed suspicious
  | where distinctAccountCount > countThreshold
  | extend timestamp = StartTimeUtc
  ```
  ## SigninBurstFromMultipleLocations
  This query over Azure Active Directory sign-in activity highlights accounts associated
  with multiple authentications from different geographical locations in a short space of time.
  ```
  let timeRange = ago(10d);
  let signIns = SigninLogs
  | where TimeGenerated >= timeRange
  | extend locationString= strcat(tostring(LocationDetails["countryOrRegion"]), "/",
   tostring(LocationDetails["state"]), "/", tostring(LocationDetails["city"]))
  | where locationString != "//" 
  // filter out signins associated with top 100 signin locations 
  | join kind=anti (
  SigninLogs
    | extend locationString= strcat(tostring(LocationDetails["countryOrRegion"]), "/", 
    tostring(LocationDetails["state"]), "/", tostring(LocationDetails["city"]))
    | where locationString != "//"
    | summarize count() by locationString
    | order by count_ desc
    | take 100) on locationString ; // TODO - make this threshold percentage-based
  // We will perform a time window join to identify signins from multiple locations within a 10-minute period
  let lookupWindow = 10m;
  let lookupBin = lookupWindow / 2.0; // lookup bin = equal to 1/2 of the lookup window
  signIns 
  | project-rename Start=TimeGenerated 
  | extend TimeKey = bin(Start, lookupBin)
  | join kind = inner (
  signIns 
  | project-rename End=TimeGenerated, EndLocationString=locationString 
    // TimeKey on the right side of the join - emulates this authentication appearing several times
    | extend TimeKey = range(bin(End - lookupWindow, lookupBin),
    bin(End, lookupBin), lookupBin)
    | mvexpand TimeKey to typeof(datetime) // translate TimeKey arrange range to a column
  ) on Identity, TimeKey
  | where End > Start
  | project timeSpan = End - Start, Identity, locationString, EndLocationString,tostring(Start), tostring(End), UserPrincipalName
  | where locationString != EndLocationString
  | summarize by timeSpan, Identity, locationString, EndLocationString, Start, End, UserPrincipalName
  | extend timestamp = Start, AccountCustomEntity = UserPrincipalName 
  | order by Identity
  ```
  ## Log_Events_ID
  ```
  1100	The event logging service has shut down.
  1101	Audit events have been dropped by the transport.
  1102	The audit log was cleared.
  1104	The security Log is now full.
  1105	Event log automatic backup.
  1108	The event logging service encountered an error.
  4608	Windows is starting up.
  4609	Windows is shutting down.
  4610	An authentication package has been loaded by the Local Security Authority
  4611	A trusted logon process has been registered with the Local Security Authority
  4612	Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.
  4614	A notification package has been loaded by the Security Account Manager.
  4615	Invalid use of LPC port.
  4616	The system time was changed.
  4618	A monitored security event pattern has occurred.
  4621	Administrator recovered system from CrashOnAuditFail.
  4622	A security package has been loaded by the Local Security Authority.
  4624	An account was successfully logged on.
  4625	An account failed to log on.
  4626	User/Device claims information.
  4627	Group membership information.
  4634	An account was logged off.
  4646	IKE DoS-prevention mode started.
  4647	User initiated logoff.
  4648	A logon was attempted using explicit credentials.
  4649	A replay attack was detected.
  4650	An IPsec Main Mode security association was established.
  4651	An IPsec Main Mode security association was established.
  4652	An IPsec Main Mode negotiation failed.
  4653	An IPsec Main Mode negotiation failed.
  4654	An IPsec Quick Mode negotiation failed.
  4655	An IPsec Main Mode security association ended.
  4656	A handle to an object was requested.
  4657	A registry value was modified.
  4658	The handle to an object was closed.
  4659	A handle to an object was requested with intent to delete.
  4660	An object was deleted.
  4661	A handle to an object was requested.
  4662	An operation was performed on an object.
  4663	An attempt was made to access an object.
  4664	An attempt was made to create a hard link.
  4665	An attempt was made to create an application client context.
  4666	An application attempted an operation.
  4667	An application client context was deleted.
  4668	An application was initialized.
  4670	Permissions on an object were changed.
  4671	An application attempted to access a blocked ordinal through the TBS.
  4672	Special privileges assigned to new logon.
  4673	A privileged service was called.
  4674	An operation was attempted on a privileged object.
  4675	SIDs were filtered.
  4688	A new process has been created.
  4689	A process has exited.
  4690	An attempt was made to duplicate a handle to an object.
  4691	Indirect access to an object was requested.
  4692	Backup of data protection master key was attempted.
  4693	Recovery of data protection master key was attempted
  4694	Protection of auditable protected data was attempted
  4695	Unprotection of auditable protected data was attempted
  4696	A primary token was assigned to process
  4697	A service was installed in the system
  4698	A scheduled task was created
  4699	A scheduled task was deleted
  4700	A scheduled task was enabled
  4701	A scheduled task was disabled
  4702	A scheduled task was updated
  4703	A token right was adjusted
  4704	A user right was assigned
  4705	A user right was removed
4706	A new trust was created to a domain
4707	A trust to a domain was removed
4709	IPsec Services was started
4710	IPsec Services was disabled
4711	PAStore Engine (1%)
4712	IPsec Services encountered a potentially serious failure
4713	Kerberos policy was changed
4714	Encrypted data recovery policy was changed
4715	The audit policy (SACL) on an object was changed
4716	Trusted domain information was modified
4717	System security access was granted to an account
4718	System security access was removed from an account
4719	System audit policy was changed
4720	A user account was created
4722	A user account was enabled
4723	An attempt was made to change an account's password
4724	An attempt was made to reset an accounts password
4725	A user account was disabled
4726	A user account was deleted
4727	A security-enabled global group was created
4728	A member was added to a security-enabled global group
4729	A member was removed from a security-enabled global group
4730	A security-enabled global group was deleted
4731	A security-enabled local group was created
4732	A member was added to a security-enabled local group
4733	A member was removed from a security-enabled local group
4734	A security-enabled local group was deleted
4735	A security-enabled local group was changed
4737	A security-enabled global group was changed
4738	A user account was changed
4739	Domain Policy was changed
4740	A user account was locked out
4741	A computer account was created
4742	A computer account was changed
4743	A computer account was deleted
4744	A security-disabled local group was created
4745	A security-disabled local group was changed
4746	A member was added to a security-disabled local group
4747	A member was removed from a security-disabled local group
4748	A security-disabled local group was deleted
4749	A security-disabled global group was created
4750	A security-disabled global group was changed
4751	A member was added to a security-disabled global group
4752	A member was removed from a security-disabled global group
4753	A security-disabled global group was deleted
4754	A security-enabled universal group was created
4755	A security-enabled universal group was changed
4756	A member was added to a security-enabled universal group
4757	A member was removed from a security-enabled universal group
4758	A security-enabled universal group was deleted
4759	A security-disabled universal group was created
4760	A security-disabled universal group was changed
4761	A member was added to a security-disabled universal group
4762	A member was removed from a security-disabled universal group
4763	A security-disabled universal group was deleted
4764	A groups type was changed
4765	SID History was added to an account
4766	An attempt to add SID History to an account failed
4767	A user account was unlocked
4768	A Kerberos authentication ticket (TGT) was requested
4769	A Kerberos service ticket was requested
4770	A Kerberos service ticket was renewed
4771	Kerberos pre-authentication failed
4772	A Kerberos authentication ticket request failed
4773	A Kerberos service ticket request failed
4774	An account was mapped for logon
4775	An account could not be mapped for logon
4776	The domain controller attempted to validate the credentials for an account
4777	The domain controller failed to validate the credentials for an account
4778	A session was reconnected to a Window Station
4779	A session was disconnected from a Window Station
4780	The ACL was set on accounts which are members of administrators groups
4781	The name of an account was changed
4782	The password hash an account was accessed
4783	A basic application group was created
4784	A basic application group was changed
4785	A member was added to a basic application group
4786	A member was removed from a basic application group
4787	A non-member was added to a basic application group
4788	A non-member was removed from a basic application group..
4789	A basic application group was deleted
4790	An LDAP query group was created
4791	A basic application group was changed
4792	An LDAP query group was deleted
4793	The Password Policy Checking API was called
4794	An attempt was made to set the Directory Services Restore Mode administrator password
4797	An attempt was made to query the existence of a blank password for an account
4798	A user's local group membership was enumerated.
4799	A security-enabled local group membership was enumerated
4800	The workstation was locked
4801	The workstation was unlocked
4802	The screen saver was invoked
4803	The screen saver was dismissed
4816	RPC detected an integrity violation while decrypting an incoming message
4817	Auditing settings on object were changed.
4818	Proposed Central Access Policy does not grant the same access permissions as the current Central Access Policy
4819	Central Access Policies on the machine have been changed
4820	A Kerberos Ticket-granting-ticket (TGT) was denied because the device does not meet the access control restrictions
4821	A Kerberos service ticket was denied because the user, device, or both does not meet the access control restrictions
4822	NTLM authentication failed because the account was a member of the Protected User group
4823	NTLM authentication failed because access control restrictions are required
4824	Kerberos preauthentication by using DES or RC4 failed because the account was a member of the Protected User group
4825	A user was denied the access to Remote Desktop. By default, users are allowed to connect only if they are members of the Remote Desktop Users group or Administrators group
4826	Boot Configuration Data loaded
4830	SID History was removed from an account
4864	A namespace collision was detected
4865	A trusted forest information entry was added
4866	A trusted forest information entry was removed
4867	A trusted forest information entry was modified
4868	The certificate manager denied a pending certificate request
4869	Certificate Services received a resubmitted certificate request
4870	Certificate Services revoked a certificate
4871	Certificate Services received a request to publish the certificate revocation list (CRL)
4872	Certificate Services published the certificate revocation list (CRL)
4873	A certificate request extension changed
4874	One or more certificate request attributes changed.
4875	Certificate Services received a request to shut down
4876	Certificate Services backup started
4877	Certificate Services backup completed
4878	Certificate Services restore started
4879	Certificate Services restore completed
4880	Certificate Services started
4881	Certificate Services stopped
4882	The security permissions for Certificate Services changed
4883	Certificate Services retrieved an archived key
4884	Certificate Services imported a certificate into its database
4885	The audit filter for Certificate Services changed
4886	Certificate Services received a certificate request
4887	Certificate Services approved a certificate request and issued a certificate
4888	Certificate Services denied a certificate request
4889	Certificate Services set the status of a certificate request to pending
4890	The certificate manager settings for Certificate Services changed.
4891	A configuration entry changed in Certificate Services
4892	A property of Certificate Services changed
4893	Certificate Services archived a key
4894	Certificate Services imported and archived a key
4895	Certificate Services published the CA certificate to Active Directory Domain Services
4896	One or more rows have been deleted from the certificate database
4897	Role separation enabled
4898	Certificate Services loaded a template
4899	A Certificate Services template was updated
4900	Certificate Services template security was updated
4902	The Per-user audit policy table was created
4904	An attempt was made to register a security event source
4905	An attempt was made to unregister a security event source
4906	The CrashOnAuditFail value has changed
4907	Auditing settings on object were changed
4908	Special Groups Logon table modified
4909	The local policy settings for the TBS were changed
4910	The group policy settings for the TBS were changed
4911	Resource attributes of the object were changed
4912	Per User Audit Policy was changed
4913	Central Access Policy on the object was changed
4928	An Active Directory replica source naming context was established
4929	An Active Directory replica source naming context was removed
4930	An Active Directory replica source naming context was modified
4931	An Active Directory replica destination naming context was modified
4932	Synchronization of a replica of an Active Directory naming context has begun
4933	Synchronization of a replica of an Active Directory naming context has ended
4934	Attributes of an Active Directory object were replicated
4935	Replication failure begins
4936	Replication failure ends
4937	A lingering object was removed from a replica
4944	The following policy was active when the  Firewall started
4945	A rule was listed when the  Firewall started
4946	A change has been made to  Firewall exception list. A rule was added
4947	A change has been made to  Firewall exception list. A rule was modified
4948	A change has been made to  Firewall exception list. A rule was deleted
4949	Firewall settings were restored to the default values
4950	A  Firewall setting has changed
4951	A rule has been ignored because its major version number was not recognized by  Firewall
4952	Parts of a rule have been ignored because its minor version number was not recognized by  Firewall
4953	A rule has been ignored by  Firewall because it could not parse the rule
4954	Firewall Group Policy settings has changed. The new settings have been applied
4956	Firewall has changed the active profile
4957	Firewall did not apply the following rule
4958	Firewall did not apply the following rule because the rule referred to items not configured on this computer
4960	IPsec dropped an inbound packet that failed an integrity check
4961	IPsec dropped an inbound packet that failed a replay check
4962	IPsec dropped an inbound packet that failed a replay check
4963	IPsec dropped an inbound clear text packet that should have been secured
4964	Special groups have been assigned to a new logon
4965	IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI).
4976	During Main Mode negotiation, IPsec received an invalid negotiation packet.
4977	During Quick Mode negotiation, IPsec received an invalid negotiation packet.
4978	During Extended Mode negotiation, IPsec received an invalid negotiation packet.
4979	IPsec Main Mode and Extended Mode security associations were established.
4980	IPsec Main Mode and Extended Mode security associations were established
4981	IPsec Main Mode and Extended Mode security associations were established
4982	IPsec Main Mode and Extended Mode security associations were established
4983	An IPsec Extended Mode negotiation failed
4984	An IPsec Extended Mode negotiation failed
4985	The state of a transaction has changed
5024	The  Firewall Service has started successfully
5025	The  Firewall Service has been stopped
5027	The  Firewall Service was unable to retrieve the security policy from the local storage
5028	The  Firewall Service was unable to parse the new security policy.
5029	The  Firewall Service failed to initialize the driver
5030	The  Firewall Service failed to start
5031	The  Firewall Service blocked an application from accepting incoming connections on the network.
5032	Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network
5033	The  Firewall Driver has started successfully
5034	The  Firewall Driver has been stopped
5035	The  Firewall Driver failed to start
5037	The  Firewall Driver detected critical runtime error. Terminating
5038	Code integrity determined that the image hash of a file is not valid
5039	A registry key was virtualized.
5040	A change has been made to IPsec settings. An Authentication Set was added.
5041	A change has been made to IPsec settings. An Authentication Set was modified
5042	A change has been made to IPsec settings. An Authentication Set was deleted
5043	A change has been made to IPsec settings. A Connection Security Rule was added
5044	A change has been made to IPsec settings. A Connection Security Rule was modified
5045	A change has been made to IPsec settings. A Connection Security Rule was deleted
5046	A change has been made to IPsec settings. A Crypto Set was added
5047	A change has been made to IPsec settings. A Crypto Set was modified
5048	A change has been made to IPsec settings. A Crypto Set was deleted
5049	An IPsec Security Association was deleted
5050	An attempt to programmatically disable the  Firewall using a call to INetFwProfile.FirewallEnabled(FALSE
5051	A file was virtualized
5056	A cryptographic self test was performed
5057	A cryptographic primitive operation failed
5058	Key file operation
5059	Key migration operation
5060	Verification operation failed
5061	Cryptographic operation
5062	A kernel-mode cryptographic self test was performed
5063	A cryptographic provider operation was attempted
5064	A cryptographic context operation was attempted
5065	A cryptographic context modification was attempted
5066	A cryptographic function operation was attempted
5067	A cryptographic function modification was attempted
5068	A cryptographic function provider operation was attempted
5069	A cryptographic function property operation was attempted
5070	A cryptographic function property operation was attempted
5071	Key access denied by Microsoft key distribution service
5120	OCSP Responder Service Started
5121	OCSP Responder Service Stopped
5122	A Configuration entry changed in the OCSP Responder Service
5123	A configuration entry changed in the OCSP Responder Service
5124	A security setting was updated on OCSP Responder Service
5125	A request was submitted to OCSP Responder Service
5126	Signing Certificate was automatically updated by the OCSP Responder Service
5127	The OCSP Revocation Provider successfully updated the revocation information
5136	A directory service object was modified
5137	A directory service object was created
5138	A directory service object was undeleted
5139	A directory service object was moved
5140	A network share object was accessed
5141	A directory service object was deleted
5142	A network share object was added.
5143	A network share object was modified
5144	A network share object was deleted.
5145	A network share object was checked to see whether client can be granted desired access
5146	The  Filtering Platform has blocked a packet
5147	A more restrictive  Filtering Platform filter has blocked a packet
5148	The  Filtering Platform has detected a DoS attack and entered a defensive mode; packets associated with this attack will be discarded.
5149	The DoS attack has subsided and normal processing is being resumed.
5150	The  Filtering Platform has blocked a packet.
5151	A more restrictive  Filtering Platform filter has blocked a packet.
5152	The  Filtering Platform blocked a packet
5153	A more restrictive  Filtering Platform filter has blocked a packet
5154	The  Filtering Platform has permitted an application or service to listen on a port for incoming connections
5155	The  Filtering Platform has blocked an application or service from listening on a port for incoming connections
5156	The  Filtering Platform has allowed a connection
5157	The  Filtering Platform has blocked a connection
5158	The  Filtering Platform has permitted a bind to a local port
5159	The  Filtering Platform has blocked a bind to a local port
5168	Spn check for SMB/SMB2 fails.
5169	A directory service object was modified
5170	A directory service object was modified during a background cleanup task
5376	Credential Manager credentials were backed up
5377	Credential Manager credentials were restored from a backup
5378	The requested credentials delegation was disallowed by policy
5379	Credential Manager credentials were read
5380	Vault Find Credential
5381	Vault credentials were read
5382	Vault credentials were read
5440	The following callout was present when the  Filtering Platform Base Filtering Engine started
5441	The following filter was present when the  Filtering Platform Base Filtering Engine started
5442	The following provider was present when the  Filtering Platform Base Filtering Engine started
5443	The following provider context was present when the  Filtering Platform Base Filtering Engine started
5444	The following sub-layer was present when the  Filtering Platform Base Filtering Engine started
5446	A  Filtering Platform callout has been changed
5447	A  Filtering Platform filter has been changed
5448	A  Filtering Platform provider has been changed
5449	A  Filtering Platform provider context has been changed
5450	A  Filtering Platform sub-layer has been changed
5451	An IPsec Quick Mode security association was established
5452	An IPsec Quick Mode security association ended
5453	An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec Keying Modules (IKEEXT) service is not started
5456	PAStore Engine applied Active Directory storage IPsec policy on the computer
5457	PAStore Engine failed to apply Active Directory storage IPsec policy on the computer
5458	PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer
5459	PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer
5460	PAStore Engine applied local registry storage IPsec policy on the computer
5461	PAStore Engine failed to apply local registry storage IPsec policy on the computer
5462	PAStore Engine failed to apply some rules of the active IPsec policy on the computer
5463	PAStore Engine polled for changes to the active IPsec policy and detected no changes
5464	PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them to IPsec Services
5465	PAStore Engine received a control for forced reloading of IPsec policy and processed the control successfully
5466	PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory cannot be reached, and will use the cached copy of the Active Directory IPsec policy instead
5467	PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, and found no changes to the policy
5468	PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, found changes to the policy, and applied those changes
5471	PAStore Engine loaded local storage IPsec policy on the computer
5472	PAStore Engine failed to load local storage IPsec policy on the computer
5473	PAStore Engine loaded directory storage IPsec policy on the computer
5474	PAStore Engine failed to load directory storage IPsec policy on the computer
5477	PAStore Engine failed to add quick mode filter
5478	IPsec Services has started successfully
5479	IPsec Services has been shut down successfully
5480	IPsec Services failed to get the complete list of network interfaces on the computer
5483	IPsec Services failed to initialize RPC server. IPsec Services could not be started
5484	IPsec Services has experienced a critical failure and has been shut down
5485	IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces
5632	A request was made to authenticate to a wireless network
5633	A request was made to authenticate to a wired network
5712	A Remote Procedure Call (RPC) was attempted
5888	An object in the COM+ Catalog was modified
5889	An object was deleted from the COM+ Catalog
5890	An object was added to the COM+ Catalog
6144	Security policy in the group policy objects has been applied successfully
6145	One or more errors occured while processing security policy in the group policy objects
6272	Network Policy Server granted access to a user
6273	Network Policy Server denied access to a user
6274	Network Policy Server discarded the request for a user
6275	Network Policy Server discarded the accounting request for a user
6276	Network Policy Server quarantined a user
6277	Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy
6278	Network Policy Server granted full access to a user because the host met the defined health policy
6279	Network Policy Server locked the user account due to repeated failed authentication attempts
6280	Network Policy Server unlocked the user account
6281	Code Integrity determined that the page hashes of an image file are not valid...
6400	BranchCache: Received an incorrectly formatted response while discovering availability of content.
6401	BranchCache: Received invalid data from a peer. Data discarded.
6402	BranchCache: The message to the hosted cache offering it data is incorrectly formatted.
6403	BranchCache: The hosted cache sent an incorrectly formatted response to the client's message to offer it data.
6404	BranchCache: Hosted cache could not be authenticated using the provisioned SSL certificate.
6405	BranchCache: %2 instance(s) of event id %1 occurred.
6406	%1 registered to  Firewall to control filtering for the following:
6407	%1
6408	Registered product %1 failed and  Firewall is now controlling the filtering for %2.
6409	BranchCache: A service connection point object could not be parsed
6410	Code integrity determined that a file does not meet the security requirements to load into a process. This could be due to the use of shared sections or other issues
6416	A new external device was recognized by the system.
6417	The FIPS mode crypto selftests succeeded
6418	The FIPS mode crypto selftests failed
6419	A request was made to disable a device
6420	A device was disabled
6421	A request was made to enable a device
6422	A device was enabled
6423	The installation of this device is forbidden by system policy
6424	The installation of this device was allowed, after having previously been forbidden by policy
8191	Highest System-Defined Audit Message Value
  ```
## SIDS
Todas las versiones de Windows utilizan los siguientes SID conocidos.
| SID | Nombre | Descripción |
| --- | ------ | ----------- |
| S-1-0 | Entidad nula | entidad de identificador |
S-1-0-0 | Nadie | ningún principal de seguridad |
S-1-1 | Entidad mundial | entidad de identificador |
S-1-1-0 | Todos | Grupo que incluye todos los usuarios, incluso los anónimos e invitados. Los miembros son controlados por el sistema operativo |
S-1-2 | Entidad local | Entidad de identificador | 
S-1-2-0 | Local | Grupo que incluye todos los usuarios que han iniciado la sesión localmente |
S-1-3 | Creator Authority | entidad de identificador |
S-1-3-0 | Creator Owner | Marcador de posición en una entrada de control de acceso heredable (ACE). Cuando la ACE se hereda, el sistema sustituye este SID por el SID del creador del objeto |
S-1-3-1 | Creator Group | Marcador de posición en una ACE heredable. Cuando la ACE se hereda, el sistema sustituye este SID por el SID del grupo principal del creador del objeto. El grupo principal sólo lo utiliza el subsistema POSIX |
S-1-3-4 | Derechos de propietario | Grupo que representa al propietario actual del objeto. Cuando una ACE que lleva el SID se aplica a un objeto, el sistema omite los permisos implícitos READ_CONTROL y WRITE_DAC del propietario del objeto |
S-1-4 | Entidad no única | Entidad de identificador |
S-1-5 | NT Authority | Entidad de identificador |
S-1-5-1 | Acceso telefónico | Grupo que incluye todos los usuarios que han iniciado la sesión a través de una conexión de acceso telefónico. Los miembros son controlados por el sistema operativo |
S-1-5-2 | Red | Grupo que incluye todos los usuarios que han iniciado sesión a través de una conexión de red. Los miembros son controlados por el sistema operativo |
S-1-5-3 | Lote | Grupo que incluye todos los usuarios que han iniciado sesión a través de un sistema de cola de procesamiento por lotes. La pertenencia es controlada por el sistema operativo |
S-1-5-4 | Interactivo | Grupo que incluye todos los usuarios que han iniciado sesión interactivamente. Los miembros son controlados por el sistema operativo |
S-1-5-5-X-Y | Sesión de inicio	| Sesión de inicio. Los valores X e Y de estos SID son diferentes para cada sesión |
S-1-5-6 | Servicio | Grupo que incluye todos los principales de seguridad que han iniciado la sesión como un servicio. Los miembros son controlados por el sistema operativo |
S-1-5-7 | Anónimo | Grupo que incluye todos los usuarios que han iniciado sesión anónimamente. Los miembros son controlados por el sistema operativo |
S-1-5-9 | Controladores de dominio empresariales | Grupo que incluye todos los controladores de dominio de un bosque que utilizan un servicio de directorio de Active Directory. Los miembros son controlados por el sistema operativo |
S-1-5-10 | Self principal | Marcador de posición en una ACE heredable en un objeto de cuenta u de grupo en Active Directory. Cuando la ACE se hereda, el sistema sustituye este SID por el SID del principal de seguridad que posee la cuenta |
S-1-5-11 | Usuarios autenticados | Grupo que incluye todos los usuarios cuyas identidades se autenticaron cuando iniciaron la sesión. Los miembros son controlados por el sistema operativo |
S-1-5-12 | Código restringido | este SID está reservado para uso futuro. |
S-1-5-13 | Usuarios de Terminal Server | Grupo que incluye todos los usuarios que han iniciado sesión en un servidor de servicios de Terminal Server. Los miembros son controlados por el sistema operativo. |
S-1-5-14 | Inicio de sesión interactivo remoto | Grupo que incluye todos los usuarios que han iniciado la sesión a través de un inicio de sesión de servicios de Terminal Server |
S-1-5-17 | Esta organización | Cuenta utilizada por el usuario predeterminado de servicios de Internet Information Server (IIS) |
S-1-5-18 | Sistema local | Cuenta de servicio utilizada por el sistema operativo |
S-1-5-19 | NT Authority | Servicio local |
S-1-5-20 | NT Authority | Servicio de red |
S-1-5-21dominio-500 | Administrador | Cuenta de usuario del administrador del sistema. De forma predeterminada, es la única cuenta de usuario a la que se le da control total sobre el sistema |
S-1-5-21dominio-501 | Invitado | Cuenta de usuario para las personas que no tienen cuentas individuales. Esta cuenta de usuario no requiere una contraseña. De forma predeterminada, la cuenta de invitado está deshabilitada |
S-1-5-21dominio-502 | KRBTGT | Cuenta de servicio que utiliza el servicio de centro de distribución de claves (KDC) |
S-1-5-21dominio-512 | Administradores de dominio | grupo global cuyos miembros están autorizados para administrar el dominio. De forma predeterminada, el grupo Admins. del dominio es miembro del grupo Administradores en todos los equipos que se han unido a un dominio, incluidos los controladores de dominio. Admins. del dominio es el propietario predeterminado de cualquier objeto creado por cualquier miembro del grupo |
S-1-5-21dominio-513 | Usuarios del dominio | Grupo global que, de forma predeterminada, incluye todas las cuentas de usuario de un dominio. Cuando crea una cuenta de usuario en un dominio, se agrega de forma predeterminada a este grupo |
S-1-5-21dominio-514 | Invitados de dominio | Grupo global que, de forma predeterminada, tiene sólo un miembro, la cuenta de invitado integrada del dominio |
S-1-5-21dominio-515 | Equipos de dominio | Grupo global que incluye todos los clientes y servidores se han unido al dominio |
S-1-5-21dominio-516 | Controladores de dominio | Grupo global que incluye todos los controladores de dominio del dominio. De forma predeterminada, se agregan nuevos controladores de dominio a este grupo |
S-1-5-21dominio-517 | Publicadores de certificados	| Grupo global que incluye todos los equipos que ejecutan una entidad de certificación de empresa. Los publicadores de certificados están autorizados para publicar certificados para objetos de usuario en Active Directory |
S-1-5-21dominio | raíz-518 Administradores de esquema | Grupo universal de un dominio en modo nativo; un grupo global de un dominio en modo mixto. El grupo está autorizado para realizar cambios de esquema en Active Directory. De forma predeterminada, el único miembro del grupo es la cuenta Administrador en el dominio raíz del bosque |
S-1-5-21dominio | raíz-519 Administradores de organización | Grupo universal de un dominio en modo nativo; un grupo global de un dominio en modo mixto. El grupo está autorizado para realizar cambios en todo el bosque en Active Directory, como agregar dominios secundarios. De forma predeterminada, el único miembro del grupo es la cuenta Administrador en el dominio raíz del bosque |
S-1-5-21dominio-520 | Propietarios del creador de directivas de grupo | Grupo global que está autorizado para crear nuevos objetos de directiva de grupo en Active Directory. De forma predeterminada, el único miembro del grupo es Administrador |
S-1-5-21dominio-526 | Administradores clave | Un grupo de seguridad. La intención para este grupo es tener acceso de escritura delegado solo en el atributo msdsKeyCredentialLink. El grupo se destina a su uso en escenarios donde autoridades externas de confianza (por ejemplo, los servicios de federación de Active Directory) son responsables de modificar este atributo. Solo se deben incluir como miembros de este grupo a administradores de confianza |
S-1-5-21dominio-527 | Administradores de empresa clave | Un grupo de seguridad. La intención para este grupo es tener acceso de escritura delegado solo en el atributo msdsKeyCredentialLink. El grupo se destina a su uso en escenarios donde autoridades externas de confianza (por ejemplo, los servicios de federación de Active Directory) son responsables de modificar este atributo. Solo se deben incluir como miembros de este grupo a administradores de confianza |
S-1-5-21dominio-553 | Servidores RAS e IAS | Grupo local de dominio. De forma predeterminada, este grupo no tiene miembros. Los servidores de este grupo tienen acceso con restricciones de lectura de cuentas y de la información de inicio de sesión a objetos de usuario del grupo local de dominio de Active Directory |
S-1-5-32-544 | Administradores | Grupo integrado. Después de la instalación inicial del sistema operativo, el único miembro del grupo es la cuenta de administrador. Cuando un equipo se une a un dominio, el grupo Admins. del dominio se agrega al grupo Administradores. Cuando un servidor se convierte en un controlador de dominio, el grupo Administradores de empresa también se agrega al grupo Administradores |
S-1-5-32-545 | Users | Grupo integrado. Después de la instalación inicial del sistema operativo, el único miembro es el grupo Usuarios autenticados. Cuando un equipo se une a un dominio, el grupo Admins. del dominio se agrega al grupo Usuarios del equipo | 
S-1-5-32-546 | Guests (Invitados)	| Grupo integrado. De forma predeterminada, el único miembro es la cuenta de invitado. El grupo Invitados permite a los usuarios ocasionales iniciar sesión con privilegios limitados en una cuenta de invitado integrada del equipo |
S-1-5-32-547 | Usuarios avanzados	| Grupo integrado. De forma predeterminada, este grupo no tiene miembros. Los usuarios avanzados crean usuarios y grupos locales, modifican y eliminan cuentas que han creado y eliminan usuarios de los grupos Usuarios avanzados, Usuarios e Invitados. Los usuarios avanzados también pueden instalar programas, crear, administrar y eliminar impresoras locales y crear y eliminar recursos compartidos de archivos |
S-1-5-32-548 | Operadores de cuentas | Grupo integrado que existe sólo en controladores de dominio. De forma predeterminada, este grupo no tiene miembros. De forma predeterminada, los operadores de cuentas tienen permiso para crear, modificar y eliminar cuentas de usuarios, grupos y equipos de todos los contenedores y unidades organizativas de Active Directory, excepto el contenedor Builtin y las unidades organizativas de Controladores de dominio. Los Operadores de cuentas no tienen permiso para modificar los grupos Administradores y Admins. del dominio, ni para modificar las cuentas de los miembros de esos grupos |
S-1-5-32-549 | Operadores de servidores | Grupo integrado que existe sólo en controladores de dominio. De forma predeterminada, este grupo no tiene miembros. Los Operadores de servidor pueden iniciar la sesión en un servidor de forma interactiva, crear y eliminar recursos compartidos de red, iniciar y detener servicios, hacer copia de seguridad y restaurar archivos, formatear el disco duro del equipo y apagar el equipo | 
S-1-5-32-550 | Operadores de impresión | Grupo integrado que existe sólo en controladores de dominio. De forma predeterminada, el único miembro es el grupo Usuarios del dominio. Los Operadores de impresión pueden administrar impresoras y colas de documentos |
S-1-5-32-551 | Operadores de copia de seguridad | Grupo integrado. De forma predeterminada, este grupo no tiene miembros. Los Operadores de copia de seguridad pueden realizar copias de seguridad y recuperar todos los archivos de un equipo, con independencia de los permisos que protejan esos archivos. Los operadores de copia de seguridad también pueden iniciar sesión en el equipo y apagarlo |
S-1-5-32-552 | Replicadores | Grupo integrado que utiliza el servicio de replicación de archivos en los controladores de dominio. De forma predeterminada, este grupo no tiene miembros. No agregue usuarios a este grupo |
S-1-5-32-582 | Administradores de réplicas de almacenamiento	| Un grupo integrado que concede acceso completo y sin restricciones a todas las características de réplica de almacenamiento |
S-1-5-64-10 | Autenticación NTLM | SID que se utiliza cuando el paquete de autenticación NTLM autentica al cliente |
S-1-5-64-14 | Autenticación SChannel | SID que se utiliza cuando el paquete de autenticación SChannel autentica al cliente |
S-1-5-64-21 | Autenticación de texto implícita | SID que se utiliza cuando el paquete de autenticación Digest autentica al cliente |
S-1-5-80 | Servicio NT	| Un prefijo de cuenta de servicio de NT |

## SID agregados por Windows Server 2003 y versiones posteriores
Cuando se agrega a un dominio un controlador de dominio que se ejecute en Windows Server 2003 o en una versión posterior, Active Directory agrega las entidades de seguridad de la tabla siguiente.
| SID | Nombre | Descripción |
| --- | ------ | ----------- |
S-1-3-2 | Creator Owner Server | Este SID no se utiliza en Windows 2000 |
S-1-3-3 | Creator Group Server | Este SID no se utiliza en Windows 2000 |
S-1-5-8 | Proxy | este SID no se utiliza en Windows 2000 |
S-1-5-15 | Esta organización | Grupo que incluye todos los usuarios de la misma organización. Sólo se incluye con las cuentas de Active Directory y sólo se agrega con Windows Server 2003 o un controlador de dominio posterior |
S-1-5-32-554 | Builtin\Acceso compatible con versiones previas a Windows 2000 | Un alias que agrega Windows 2000. Grupo de compatibilidad con versiones anteriores que permite acceso de lectura en todos los usuarios y grupos del dominio.
S-1-5-32-555 | Builtin\Usuarios de escritorio remoto | Un alias. A los miembros de este grupo se les concede el derecho de iniciar sesión de forma remota |
S-1-5-32-556 | Builtin\Operadores de configuración de red | Un alias. Los miembros de este grupo pueden tener algunos privilegios administrativos para administrar la configuración de características de red |
S-1-5-32-557 | Builtin\Creadores de confianza de bosque entrante | Un alias. Los miembros de este grupo pueden crear confianzas entrantes, unidireccionales para este bosque |
S-1-5-32-558 | Builtin\Usuarios del monitor de rendimiento | Un alias. Los miembros de este grupo tienen acceso remoto para supervisar este equipo | 
S-1-5-32-559 | Builtin\Usuarios del registro de rendimiento | Un alias. Los miembros de este grupo tienen acceso remoto para programar el registro de contadores de rendimiento en este equipo |
S-1-5-32-560 | Builtin\Grupo de acceso de autorización de Windows | un alias. Los miembros de este grupo tienen acceso al atributo tokenGroupsGlobalAndUniversal calculado en objetos de usuario |
S-1-5-32-561 | Builtin\Servidores de licencias de Terminal Server | un alias. grupo de servidores de licencias de Terminal Server. Cuando está instalado Windows Server 2003 Service Pack 1, se crea un nuevo grupo local | 
S-1-5-32-562 | Builtin\Usuarios COM distribuidos | Un alias. grupo para COM que proporciona controles de acceso en todo el equipo que rigen el acceso a todas las solicitudes de llamada, activación o inicio en el equipo | 

## SID_agregados_por_Windows_Server_2008_y_versiones_posteriores
Cuando se agrega a un dominio un controlador de dominio que se ejecute en Windows Server 2008 o una versión posterior, Active Directory agrega las entidades de seguridad de la tabla siguiente.
| SID | Nombre | Descripción |
| --- | ------ | ----------- |
S-1-2-1	| Inicio de sesión en la consola	| Grupo que incluye los usuarios que han iniciado sesión en la consola física |
S-1-5-21dominio-498 | Controladores de dominio de sólo lectura de empresa | Un grupo universal. Los miembros de este grupo son los controladores de dominio de solo lectura en la empresa | 
S-1-5-21dominio-521 | Controladores de dominio de sólo lectura | Un grupo global. Los miembros de este grupo son los controladores de dominio de solo lectura en el dominio | 
S-1-5-21dominio-571 | Grupo de replicación de contraseña RODC permitida | Grupo local de dominio. Los miembros de este grupo pueden replicar sus contraseñas en todos los controladores de dominio de sólo lectura del dominio |
S-1-5-21dominio-572 | Grupo de replicación de contraseña RODC denegada | Grupo local de dominio. Los miembros de este grupo no pueden replicar sus contraseñas en ningún controlador de dominio de solo lectura del dominio |
S-1-5-32-569 | Builtin\Operadores criptográficos | 	Un grupo local integrado. Los miembros están autorizados a realizar operaciones criptográficas |
S-1-5-32-573 | Builtin\Lectores del registro de eventos | Un grupo local integrado. Los miembros de este grupo pueden leer registros de eventos desde el equipo local |
S-1-5-32-574 | Builtin\Acceso DCOM a Serv. de certificado | Un grupo local integrado. Los miembros de este grupo pueden conectarse a las entidades de certificación de la empresa | 
S-1-5-80-0 | Servicios NT\Todos los servicios | Grupo que incluye todos los procesos de servicios que están configurados en el sistema. La pertenencia es controlada por el sistema operativo |
S-1-5-80-0 | Todos los servicios | Un grupo que incluye todos los procesos de servicios configurados en el sistema. La pertenencia es controlada por el sistema operativo |
S-1-5-83-0 | Máquina Virtual NT\Máquinas virtuales | grupo integrado. El grupo se crea cuando se instala la función Hyper-V. El servicio de administración de Hyper-V (VMMS) conserva la pertenencia del grupo. Este grupo necesita el derecho Crear vínculos simbólicos (SeCreateSymbolicLinkPrivilege) y también el derecho Iniciar sesión como servicio (SeServiceLogonRight) | 
S-1-5-90-0 | Administrador de Windows\Grupo de administradores de Windows | Un grupo integrado que usa el Administrador de ventanas de escritorio (DWM). DWM es un servicio de Windows que administra la visualización de información en las aplicaciones de Windows | 
S-1-16-0 | Nivel obligatorio de no confianza | nivel de integridad que no es de confianza |
S-1-16-4096 | Nivel obligatorio bajo | Nivel de integridad baja | 
S-1-16-8192 | Nivel obligatorio medio | Nivel de integridad media |
S-1-16-8448 | Nivel obligatorio medio alto | Nivel de integridad media alta |  
S-1-16-12288 | Nivel obligatorio alto | Nivel de integridad alto |
S-1-16-16384 | Nivel obligatorio del sistema | Nivel de integridad del sistema |
S-1-16-20480 | Nivel obligatorio de proceso protegido | Nivel de integridad de proceso protegido | 
S-1-16-20480 | Nivel obligatorio de proceso protegido | Nivel de integridad de proceso protegido | 
S-1-16-28672 | Nivel obligatorio de proceso seguro	| nivel de integridad de proceso seguro |
## SID agregados por Windows Server 2012 y versiones posteriores
Cuando se agrega a un dominio un controlador de dominio que se ejecute en Windows Server 2012 o en una versión posterior, Active Directory agrega las entidades de seguridad de la tabla siguiente.
| SID | Nombre | Descripción |
| --- | ------ | ----------- |
S-1-5-21-dominio-522 | Controladores de dominio clonables	| 	Un grupo global. Los miembros de este grupo que son controladores de dominio pueden clonarse |
S-1-5-32-575 | Builtin\Servidores de acceso remoto RDS	| Un grupo local integrado. Los servidores en este grupo habilitan a los usuarios de programas RemoteApp y acceso a escritorios virtuales personales a estos recursos. En implementaciones con conexión a Internet, estos servidores suelen implementarse en una red perimetral. Este grupo debe estar constituido en servidores que ejecutan Agentes de conexión a Escritorio remoto. Los servidores de puertas de enlace de Escritorio remoto y los servidores de acceso web de Escritorio remoto utilizados en la implementación deben encontrarse en este grupo | 
S-1-5-32-576 | Builtin\Servidores de punto de conexión RDS | 	Un grupo local integrado. Los servidores en este grupo ejecutan máquinas virtuales y hospedan sesiones donde se ejecutan los programas RemoteApp de los usuarios y los escritorios virtuales personales. Este grupo debe estar constituido en servidores que ejecutan Agentes de conexión a Escritorio remoto. Los servidores de host de sesión de Escritorio Remoto y los servidores de host de virtualización de Escritorio Remoto utilizados en la implementación deben encontrarse en este grupo | 
S-1-5-32-577 | Builtin\Servidores de administración RDS | Un grupo local integrado. Los servidores en este grupo pueden llevar a cabo medidas administrativas de rutina en servidores que ejecutan Servicios de Escritorio remoto. Este grupo debe estar constituido en todos los servidores en una implementación de Servicios de Escritorio remoto. Los servidores que ejecutan el servicio de Administración central de RDS deben estar incluidos en este grupo |
S-1-5-32-578 | Builtin\Administradores de Hyper-V | Un grupo local integrado. Los miembros de este grupo tienen acceso total e ilimitado a todas las características de Hyper-V |
S-1-5-32-579 | Builtin\Operadores de asistencia de control de acceso | Un grupo local integrado. Los miembros de este grupo pueden consultar de forma remota atributos y permisos de autorización para recursos en este equipo |
S-1-5-32-580 | Builtin\Usuarios de administración remota | Un grupo local integrado. Los miembros de este grupo pueden acceder a recursos de WMI mediante protocolos de administración (como WS-Management a través del servicio de administración remota de Windows). Esto solo se aplica a espacios de nombre WMI que conceden acceso al usuario |
