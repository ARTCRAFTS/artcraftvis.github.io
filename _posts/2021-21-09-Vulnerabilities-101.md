---
layout: single
title: Identify Vulnerabilities
date: 2021-08-31
classes: wide
header:
  teaser: /assets/images/security.jpg
categories:
  - Blue Team
  - infosec
  - Red Team
tags:
  - Blue Team
  - Red Team
---

#  Introduction

Cybersecurity is big business in the modern-day world. The hacks that we hear about in newspapers are from exploiting vulnerabilities. In this room, we're going to explain exactly what a vulnerability is, the types of vulnerabilities and how we can exploit these for success in our penetration testing endeavours.

An enormous part of penetration testing is knowing the skills and resources for whatever situation you face. This room is going to introduce you to some resources that are essential when researching vulnerabilities, specifically, you are going to be introduced to:

- What vulnerabilities are
- Why they're worthy of learning about
- How are vulnerabilities rated
- Databases for vulnerability research
- A showcase of how vulnerability research is used on ACKme's engagement

## Introduction to Vulnerabilities

A vulnerability in cybersecurity is defined as a weakness or flaw in the design, implementation or behaviours of a system or application. An attacker can exploit these weaknesses to gain access to unauthorised information or perform unauthorised actions. The term “vulnerability” has many definitions by cybersecurity bodies. However, there is minimal variation between them all.

For example, NIST defines a vulnerability as “weakness in an information system, system security procedures, internal controls, or implementation that could be exploited or triggered by a threat source”.

Vulnerabilities can originate from many factors, including a poor design of an application or an oversight of the intended actions from a user.

We will come on to discuss the various types of vulnerabilities in a later room. However, for now, we should know that there are arguably five main categories of vulnerabilities:

![image](https://user-images.githubusercontent.com/89842187/134151564-cc2c9266-1f91-4271-86a7-798f9ca38b3c.png)

As a cybersecurity researcher, you will be assessing applications and systems - using vulnerabilities against these targets in day-to-day life, so it is crucial to become familiar with this discovery and exploitation process.

# Scoring Vulnerabilities (CVSS & VPR)

Vulnerability management is the process of evaluating, categorising and ultimately remediating threats (vulnerabilities) faced by an organisation.
It is arguably impossible to patch and remedy every single vulnerability in a network or computer system and sometimes a waste of resources.

After all, only approximately 2% of vulnerabilities only ever end up being exploited (Kenna security., 2020). Instead, it is all about addressing the most dangerous vulnerabilities and reducing the likelihood of an attack vector being used to exploit a system.

This is where vulnerability scoring comes into play. Vulnerability scoring serves a vital role in vulnerability management and is used to determine the potential risk and impact a vulnerability may have on a network or computer system. For example, the popular Common Vulnerability Scoring System (CVSS) awards points to a vulnerability based upon its features, availability, and reproducibility.

Of course, as always in the world of IT, there is never just one framework or proposed idea. Let’s explore two of the more common frameworks and analyse how they differ.

## Common Vulnerability Scoring System

First introduced in 2005, the Common Vulnerability Scoring System (or CVSS) is a very popular framework for vulnerability scoring and has three major iterations. As it stands, the current version is CVSSv3.1 (with version 4.0 currently in draft) a score is essentially determined by some of the following factors (but many more):

  1. How easy is it to exploit the vulnerability?

  2. Do exploits exist for this?

  3. How does this vulnerability interfere with the CIA triad?
In fact, there are so many variables that you have to use a calculator to figure out the score using this framework. A vulnerability is given a classification (out of five) depending on the score that is has been assigned. I have put the Qualitative Severity Rating Scale and their score ranges into the table below. 

![image](https://user-images.githubusercontent.com/89842187/134261021-1529d850-7fb6-474e-aa34-b9fe0a567f3d.png)

## Vulnerability Priority Rating (VPR)

The VPR framework is a much more modern framework in vulnerability management - developed by Tenable, an industry solutions provider for vulnerability management. This framework is considered to be risk-driven; meaning that vulnerabilities are given a score with a heavy focus on the risk a vulnerability poses to the organisation itself, rather than factors such as impact (like with CVSS).

Unlike CVSS, VPR scoring takes into account the relevancy of a vulnerability. For example, no risk is considered regarding a vulnerability if that vulnerability does not apply to the organisation (i.e. they do not use the software that is vulnerable). VPR is also considerably dynamic in its scoring, where the risk that a vulnerability may pose can change almost daily as it ages.

VPR uses a similar scoring range as CVSS, which I have also put into the table below. However, two notable differences are that VPR does not have a "None/Informational" category, and because VPR uses a different scoring method, the same vulnerability will have a different score using VPR than when using CVSS.

![image](https://user-images.githubusercontent.com/89842187/134261036-7f02f253-296c-4bcf-a77d-9762a6c8a620.png)

Let's recap some of the advantages and disadvantages of using the VPR framework in the table below.

![image](https://user-images.githubusercontent.com/89842187/134261059-7efe917e-662e-46c2-8800-151eae45cb0c.png)

# Vulnerability Databases

Throughout your journey in cybersecurity, you will often come across a magnitude of different applications and services. For example, a CMS whilst they all have the same purpose, often have very different designs and behaviours (and, in turn, potentially different vulnerabilities).

Thankfully for us, there are resources on the internet that keep track of vulnerabilities for all sorts of software, operating systems and more! This room will showcase two databases that we can use to look up existing vulnerabilities for applications discovered in our infosec journey, specifically the following websites: 

1. NVD (National Vulnerability Database) https://nvd.nist.gov/vuln/full-listing

2. Exploit-DB https://www.exploit-db.com/

Before we dive into these two resources, let's ensure that our understanding of some fundamental key terms is on the same page:

![image](https://user-images.githubusercontent.com/89842187/134261361-a673bc81-5b7c-46f5-8a34-a0c5f77766a5.png)

## NVD – National Vulnerability Database
The National Vulnerability Database is a website that lists all publically categorised vulnerabilities. In cybersecurity, vulnerabilities are classified under “Common Vulnerabilities and Exposures” (Or CVE for short).

These CVEs have the formatting of CVE-YEAR-IDNUMBER. For example, the vulnerability that the famous malware WannaCry used was CVE-2017-0144.

NVD allows you to see all the CVEs that have been confirmed, using filters by category and month of submission. For example, it is three days into August; there have already been 223 new CVEs submitted to this database.

![image](https://user-images.githubusercontent.com/89842187/134261375-d509019e-9641-4fd6-b5a3-a976367cab2d.png)

While this website helps keep track of new vulnerabilities, it is not great when searching for vulnerabilities for a specific application or scenario.
## Exploit-DB
Exploit-DB is a resource that we, as hackers, will find much more helpful during an assessment. Exploit-DB retains exploits for software and applications stored under the name, author and version of the software or application.

We can use Exploit-DB to look for snippets of code (known as Proof of Concepts) that are used to exploit a specific vulnerability.

![image](https://user-images.githubusercontent.com/89842187/134261416-3293700c-d04e-41f5-a019-41df534e5e62.png)

# An Example of Finding a Vulnerability

In this task, I’m going to demonstrate the process of finding one minor vulnerability, coupled with some research of the vulnerability databases leading to a much more valuable vulnerability and exploit ultimately.

Throughout an assessment, you will often combine multiple vulnerabilities to get results. For example, in this task, we will leverage the “Version Disclosure” vulnerability to find out the version of an application. With this version, we can then use Exploit-DB to search for any exploits that work with that specific version. 

Applications and software usually have a version number. This information is usually left with good intentions; for example, the author can support multiple versions of the software and the likes. Or sometimes, left unintentionally.

For example, in the screenshot below, we can see that the name and version number of this application is “Apache Tomcat 9.0.17”

![image](https://user-images.githubusercontent.com/89842187/134261526-2bd52008-9c7c-469a-a6dd-736a3d58c503.png)

With this information in hand, let’s use the search filter on Exploit-DB to look for any exploits that may apply to “Apache Tomcat 9.0.17”.

![image](https://user-images.githubusercontent.com/89842187/134261539-844bb3ad-974d-40b5-b85f-8bc3771ba8ce.png)




# Automated Vs. Manual Vulnerability Research

There is a myriad of tools and services available in cybersecurity for vulnerability scanning. Ranging from being commercial (and footing a heavy bill) to open-source and free, vulnerability scanners are convenient means of quickly canvassing an application for flaws.

For example, the vulnerability scanner Nessus has both a free (community) edition and commercial. The commercial version costing thousands of pounds for a year's license will likely be used in organisations providing penetration testing services or audits. If you’d like to know more about Nessus, check out the TryHackMe room dedicated to it.

I have detailed some of the advantages and disadvantages of using a vulnerability scanner in the table below:

![image](https://user-images.githubusercontent.com/89842187/134261892-6cce41f8-3915-4a26-906a-507a210221c1.png)


Frameworks such as Metasploit often have vulnerability scanners for some modules, this is something you will come onto learn about in a further module in this pathway.

Manual scanning for vulnerabilities is often the weapon of choice by a penetration tester when testing individual applications or programs. In fact, manual scanning will involve searching for the same vulnerabilities and uses similar techniques as automated scanning.

Ultimately, both techniques involve testing an application or program for vulnerabilities. These vulnerabilities include:

![image](https://user-images.githubusercontent.com/89842187/134261950-f447ea09-8895-44f4-b0a0-69b5063f724f.png)

# Finding Manual Exploits

## Rapid7 https://www.rapid7.com/db/
Much like other services such as Exploit DB and NVE, Rapid7 is a vulnerability research database. The only difference being that this database also acts as an exploit database. Using this service, you can filter by type of vulnerability (I.e. application and operating system).


Additionally, the database contains instructions for exploiting applications using the popular Metasploit tool (you will learn about this tool in-depth later in the path). For example, this entry on Rapid7 is for “Wordpress Plugin SP Project & Document”; where we can see instructions on how to use an exploit module to abuse this vulnerability.

## GitHub https://github.com/

GitHub is a popular web service designed for software developers. The site is used to host and share the source code of applications to allow a collaborative effort. However, security researchers have taken to this platform because of the aforementioned reasons as well. Security researchers store & share PoC’s on GitHub, turning it into an exploit database in this context.

GitHub is extremely useful in finding rare or fresh exploits because anyone can create an account and upload – there is no formal verification process like there is with alternative exploit databases. With that said, there is also a downside in that PoC’s may not work where little to no support will be provided.

![image](https://user-images.githubusercontent.com/89842187/134262134-9c1a750f-2340-43a3-8ec2-99f73f79e63f.png)

GitHub uses a tagging and keyword system, meaning that we can search GitHub by keywords such as “PoC” “vulnerability” and many more. At the time of writing, there are 9,682 repositories with the keyword “cve”. We are also able to filter the results by programming language.

## Searchsploit

earchsploit is a tool that is available on popular pentesting distributions such as Kali Linux. It is also available on the TryHackMe AttackBox. This tool is an offline copy of Exploit-DB, containing copies of exploits on your system. 

You are able to search searchsploit by application name and/or vulnerability type. For example, in the snippet below, we are searching searchsploit for exploits relating to Wordpress that we can use – no downloading necessary!

# Example of Manual Exploitation

We can use the information gathered from task 2 in this room to exploit the vulnerable service. Ultimately, one of the most effective vulnerabilities that we can exploit is the ability to execute commands on the target that is running the vulnerable application or service.

For example, being able to execute commands on the target that is running the vulnerable application or service will allow us to read files or execute commands that we previously wouldn’t be able to perform using the application or service alone. Additionally, we can abuse this to gain what is known as a foothold to the machine. A foothold is access to the vulnerable machine’s console, where we can then begin to exploit other applications or machines on the network.

We are going to use an exploit to perform remote code execution on the application from task 2 to be able to remotely execute commands on the vulnerable machine.

Before we start, it is important to note that exploits rarely come out of the box and ready to be used. They often require some configuration before they will work for our environment or target. The level of configuration will vary upon the exploit, so you will often find multiple exploits for the same vulnerability on an application. It is up to you to figure out which exploit is the most appropriate or useful to you.

For example, in the snippet below, we can see that a few options have been changed to reflect the IP address of the machine that we are attacking from.

Once we have configured the exploit correctly, let’s further read this exploit to understand how to use it. In the snippet below, we can see that we need to provide two arguments when running the exploit:

With this information in mind, we are now ready to use this exploit on the vulnerable machine. We are going to do the following:

Use the exploit to upload a malicious file to the vulnerable application containing whatever command we wish to execute, where the web server will run this malicious file to execute the code.
The file will first contain a basic command that we will use to verify that the exploit has worked.
Then we are going to read the contents of a file located on the vulnerable machine.



