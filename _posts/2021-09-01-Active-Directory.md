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
