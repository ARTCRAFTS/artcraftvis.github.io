---
layout: single
title: Powershell
date: 2021-08-31
classes: wide
header:
  teaser: /assets/images/security.jpg
categories:
  - Blue Team
  - infosec
tags:
  - Blue Team
  - Red Team
---

There are several PowerShell scripts useful in penetration tests, such as PowerView and Nishang; however, please remember these two points about them;

1) They are detected by most antivirus software

2) They are detected by most antivirus software

So, if you dream of connecting to a target machine on a corporate network and instantly being able to fire up PowerSploit or Nishang, this might not always be the case. There will, of course, be situations where these scripts will run and be very useful, but do not take them for granted.

On the other hand, being able to use PowerShell will give you the power of an object-oriented programming language readily available on the target platform.

# Manipulating files

The "Start-Process" command can be used to start a process. You can see an example below for notepad.exe.

![image](https://user-images.githubusercontent.com/89842187/133701244-0553a660-7210-4293-8a2d-39c6aedbe740.png)
Get-Process


Get-Process is useful to list all running processes.

It can also be used with the “-name” parameter to filter for a specific process name.

![image](https://user-images.githubusercontent.com/89842187/133701255-cd604244-87df-4817-9ec5-35fa8786c542.png)

Especially with command outputs that may be difficult to read or need further processing appending the “Export-Csv” command will create a CSV file with the output of the first command.

![image](https://user-images.githubusercontent.com/89842187/133701264-8eac6fcf-5982-4a96-8634-e54324ab36bd.png)

Get-Content



Similar to “cat” on Linux and “type” on the Windows command-line, “Get-Content” can be used to display the content of a file.

![image](https://user-images.githubusercontent.com/89842187/133701281-03f1d7c8-0904-4dd4-bc3f-2f51bea484b4.png)

Copy-Item

Files can be copied and moved with “Copy-Item” and “Move-Item”, respectively.
![image](https://user-images.githubusercontent.com/89842187/133701297-5383e5fe-143b-4737-8358-2db20ad39cf6.png)

Get-FileHash


Although not directly related to penetration tests, hashes are handy to compare files or search for malware samples on platforms such as VirusTotal. The built-in “Get-FileHash” command can be used to obtain hashes on most formats.

![image](https://user-images.githubusercontent.com/89842187/133701316-9d55a68f-91f0-4ca8-9844-b686ab53c3a1.png)

#  Downloading files

There are numerous ways to download files from a remote server using PowerShell. One of the quickest ways can be seen below. This will connect to the remote host (10.0.2.8 in this case) and download themeterpreter-64.ps1. The file is saved as “meterpreter.ps1”.



The screenshot below shows a sample lab setup used with Kali running a Python HTTP server on port 8888 (python3 -m http.server 8888).

![image](https://user-images.githubusercontent.com/89842187/133701555-5dcb1c42-993c-4fd9-948a-bbeabd192802.png)

Once the script has been downloaded, you may run into the first related to PowerShell: ExecutionPolicy. It is important to note that, as Microsoft clearly states in the related documentation, “ExecutionPolicy” is NOT a security feature. It merely functions as an added safety measure and can be bypassed by the user.

![image](https://user-images.githubusercontent.com/89842187/133701573-819bdbf2-247e-4384-a3ba-a89738b39045.png)

The current state of the ExecutionPolicy configuration can be seen using “Get-ExecutionPolicy -list”


Execution policies can have seven different values;


AllSigned: Scripts can run but require all scripts to be signed by a trusted publisher.
  - Bypass: All scripts can run, and no warnings or prompts will be displayed.
  - Default: This refers to “restricted” for Windows clients and “RemoteSigned” for Windows servers.
  - RemoteSigned: Scripts can run, and this does not require local scripts to be digitally signed.
  - Restricted: The default configuration for Windows clients. Allows individual commands to run, does not allow scripts.
  - Undefined: This shows that no specific execution policy was set. This means default execution policies will be enforced.
  - Unrestricted: Most scripts will run.

As mentioned earlier, ExecutionPolicy is not a security feature and can be bypassed by users. The user has several alternatives to bypass the ExecutionPolicy; however, some methods may require the user to have administrator account privileges.


The most common way to bypass execution policy can be seen below:

![image](https://user-images.githubusercontent.com/89842187/133701617-fbab2dcc-3f19-4782-ad8f-449c61b99930.png)

Another option could be to use “Set-ExecutionPolicy Bypass” with the scope set for the process. The “-scope” parameter will set the execution policy only for the current PowerShell session and will go back to the initial settings once the PowerShell session is closed.

![image](https://user-images.githubusercontent.com/89842187/133701626-2a6c10f7-aa98-45c8-ada6-349d93722ea6.png)

Another easy way to download files from a remote server is to use the “Invoke-WebRequest” command.

![image](https://user-images.githubusercontent.com/89842187/133701633-20b1c15d-4b01-4cbd-b2fc-450f150d1d4e.png)


# System Reconnaissance


While several PowerShell scripts are readily available for reconnaissance, these may be flagged by the antivirus installed on the target system.


Finding Missing Patches



The patch level of the target system will have an impact on the steps following the initial compromise. Having an idea about the potentially missing patches could help the red teamer identify a possible privilege escalation path or even provide further information about the target system.



The “Get-Hotfix” command can be used to enumerate already installed patches.

![image](https://user-images.githubusercontent.com/89842187/133701695-f3805870-bee8-4fad-bd44-07ad3f2d156d.png)

To make things easier, we could output the result of the Get-Hotfix command in a list format and grep it further using the “findstr” command. The example below shows how the installation date of patches could be listed to have a better idea about update cycles on the target.


![image](https://user-images.githubusercontent.com/89842187/133701723-d9b21c16-2e7e-4d97-86d2-70fb25d58a7d.png)

By default, the “Get-HotFix” command will show the output in a table format. This table can be useful to list only data provided in a column without the need to use “findstr” using “Format-Table” followed by the name of the column we are interested in. The example below shows the output listing only HotFixIDs.

![image](https://user-images.githubusercontent.com/89842187/133701732-2efff995-b54d-47e9-9bcc-ae113159e23c.png)

“Format-List” can also be used to gather more information about objects. Below are three examples using a simple “dir” command.

![image](https://user-images.githubusercontent.com/89842187/133701748-0f3d5537-9975-4274-b3f4-0a188c0e90f0.png)

![image](https://user-images.githubusercontent.com/89842187/133701753-536dc2ff-7fad-4d01-8e42-cf8d2166064d.png)

![image](https://user-images.githubusercontent.com/89842187/133701759-193e7112-7da6-4ad2-b9b0-851a957ac093.png)

As you can see, we can access even more information about the file (such as the CreationTime, Last AccessTime, LastWriteTime)using a wildcard after “Format-List” to show all available information.

At any stage, “Out-File” can be used to save the output to a file for further use.

![image](https://user-images.githubusercontent.com/89842187/133701773-2fa266be-0804-4d47-898d-a4d93d78aee1.png)

“Get-Content” could also be used to read the file's content just as “type” shown in the example above. Several other output formats are available, including the beautiful GridView option.

![image](https://user-images.githubusercontent.com/89842187/133701780-b3cfe3ea-37b4-4951-ac52-1de04f336d05.png)

The GridView option provides a nice GUI with sortable columns for any output that can be overwhelming on the CLI.

![image](https://user-images.githubusercontent.com/89842187/133701789-faad5948-607f-400a-a239-77cdfe04d25e.png)

# Network Reconnaissance

The following command can be used to ping a given IP range. In this example, we will ping the IP addresses from 10.0.2.1 to 10.0.2.15

![image](https://user-images.githubusercontent.com/89842187/133701932-620feb3d-0671-412b-9be5-8a1fa1a1caa6.png)

The first part of the command, delimited by the "|" character, sets the range for the last octet. The second part generates and prints the IP address to be used and pipes it to the command line. Finally, the last part greps lines that include the “TTL” string.


A similar command can be built using the existing socket and TCP client functions. In the example below, we scan the first 1024 TCP ports of the target. Note that the “2>$null” sends any error to null, providing us with a cleaner output.

![image](https://user-images.githubusercontent.com/89842187/133701943-16596aad-471c-404d-99b7-23f05824ab13.png)

#  Using PowerView

PowerView is one of the most effective ways to gather information on the domain. The module can be downloaded from https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1


Remember that you may need to bypass the execution policy to be able to run the script.

![image](https://user-images.githubusercontent.com/89842187/133701979-ff7b6ac2-792d-4b5b-b222-70955f136c73.png)

We can now use PowerView.ps1 to obtain more information on the domain configuration and users.


Get-NetDomainController


This command will collect information on the domain controller.

![image](https://user-images.githubusercontent.com/89842187/133701992-e8fe7468-7361-47fd-be21-ef961ee5169c.png)

Knowing the IP address of the domain controller will be useful to conduct man-in-the-middle attacks and to focus our efforts on high-value targets.

Get-NetUser


This command will provide a list of domain users. The output can be intimidating, so you may consider exporting the output to a .csv file or use the out-gridviewoptio
![image](https://user-images.githubusercontent.com/89842187/133702051-fc4d9842-d160-4a11-9a98-fc3327983337.png)

The output can also be limited by providing the name of the criteria we are interested in.
![image](https://user-images.githubusercontent.com/89842187/133702070-c580e380-489e-4034-aa26-8fe1068dbd56.png)

Values for a specific property can be listed. For example, if we wanted to list users' last logon dates and times we could use the "Get-NetUser | select -ExpandProperty lastlogon" command.

![image](https://user-images.githubusercontent.com/89842187/133702085-3229d8ef-167e-435c-b6f2-a528b25fe342.png)

The same command can be modified to select the "description" field instead of "lastlogon" to see if any description was added to accounts.

Get-NetComputer



This command is useful to enumerate systems connected to the domain. This command can also be used with the “-ping” parameter to enumerate the systems that are currently online.

![image](https://user-images.githubusercontent.com/89842187/133702104-89619dc3-346f-4adc-8d97-3f382c2c4d49.png)

As you can see in the screenshot above, there are four systems on the domain, but only two of them are online.

Get-NetGroup



Some accounts can be members of important groups, such as domain admins. Knowing which accounts have useful privileges or are a member of groups of interest will be useful for lateral movement and privilege escalation. The “Get-NetGroup” command will help us enumerate existing groups.

![image](https://user-images.githubusercontent.com/89842187/133702115-ae06b81d-7ac3-41c5-9991-3709e2e12b1e.png)

This will be used to enumerate members of the group using “Get-NetGroupMember” followed by "Domain Admins".

![image](https://user-images.githubusercontent.com/89842187/133702133-0cc14c26-163e-4ba8-b351-8fcdb93eced1.png)

Finding shares


“Find-DomainShare” will list available shares. Please note we have added the "-CheckShareAccess" option to list only readable shares

![image](https://user-images.githubusercontent.com/89842187/133702150-44a9c868-98fe-441a-bc3f-98fd48ae1c3c.png)

Enumerate Group Policy



Group Policy is used to configure computers connected to the domain. The “Get-NetGPO” command will gather information on enforced policies.

![image](https://user-images.githubusercontent.com/89842187/133702159-39f4f403-0ec0-4180-b71f-d563d2092a0b.png)


Spending some time understanding what policies are set can provide potential attack vectors (is Windows Defender disabled? Is the firewall disabled? Etc.)


The domain you are testing can have a trust relationship with another domain. If this is the case, you may be able to extend the scope of the reconnaissance to that domain. The “Get-NetDomainTrust” command will list any domain you may access. For most of the PowerView commands, all you need to do is to add the “-Domain” parameter followed by the name of the other domain (e.g. Get-NetUsers -Domain infra.munn.local)

User Enumeration


Knowing which systems the current user can access with local administrator privileges can facilitate lateral movement. The “Find-LocalAdminAccess” command will list systems in the domain you may access as a local administrator.

![image](https://user-images.githubusercontent.com/89842187/133702190-3ae8b7d6-ad9d-4e8e-86ca-59790b9b9e2c.png)

https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview


![tattoo-binarycode2](https://user-images.githubusercontent.com/89842187/139294870-bacf18e1-1636-4e8a-a87d-c9f538620319.jpg)




