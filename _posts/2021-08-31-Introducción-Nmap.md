---
layout: single
title: Introducción NMAP
excerpt: "Nmap es un programa de código abierto que sirve para efectuar rastreo de puertos escrito originalmente por Gordon Lyon y cuyo desarrollo se encuentra hoy a cargo de una comunidad."
date: 2021-08-31
classes: wide

categories:
  - Blue Team
  - Red Team
  - infosec
tags:
  - Blue Team
  - Red Team

---


# Introducción a Nmap

## Check if any WAF

```
https://github.com/EnableSecurity/wafw00f
wafw00f ip
https://github.com/Ekultek/WhatWaf.git
https://nmap.org/nsedoc/scripts/http-waf-detect.html
```

- Tipos.
```
Full scan #SYN > SYN / ACK > ACK + RST = OPEN / SYN > RST = CLOSED
Half-open #SYN > SYN / ACK > RST = OPEN / SYN > RST = CLOSED
Xmas Scans #Not on windows. #FIN, URG, PUSH > noting = OPEN / RST = CLOSED
FIN Scans #FIN > No response = port is OPEN / RST ACK = CLOSED
NULL Scans #Not on windows. #NULL Packet > no response = port OPEN / NULL > RST/ACK = CLOSED
UDP SCANS #Is port 31 open? > no response = CLOSED / ICMP Port unreachable = CLOSED
IDLESCAN #TCP Spoof "source address", Requieres a zombie / SYN + ACK > RST /IPID=2001 / RST = CLOSED
```
![image](https://user-images.githubusercontent.com/64669644/88861481-579c9780-d1fe-11ea-845d-b3e381862c6d.png)

### First, how do you access the help menu?
```
-h
```
### Stealth_Scan
```
-sS
```
### UDP_Scan
```
-sU
```
### OS_Detection
```
-O
```
### Service_version 
```
-sV
```
### Verbose_very_verbose
```
-v
-VV
```
### Output_XMLFormat
```
-oX
```
### Aggresive
```
-A
```
### Timing 
```
-T1
-T2
-T3
-T4
-T5
```
### Specific_port
```
-p
```
### Every_port
```
-p-
```
### Specific_script
```
--script <example>
```
### Vuln_script
```
--script vuln
```
### Not_ping
```
-Pn
```
### Default_Scripts
```
-sC
```
### Reason
```
--reason
```

### Firewall Detection (ACK Probing)

Firewall Detection (ACK Probing)

```
root@kali:/home/slowkep# nmap -sA 192.168.21.129 --reason
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-12 02:46 CEST
Nmap scan report for 192.168.21.129
Host is up, received arp-response (0.00016s latency).
All 1000 scanned ports on 192.168.21.129 are unfiltered because of 1000 resets 

```

![image](https://user-images.githubusercontent.com/89842187/131547991-bf84797e-241a-4d8f-ad23-2ad3b77d83c8.png)

Firewall Activado (NO RST)

```
root@kali:/home/slowkep# nmap -sA 192.168.21.129 --reason
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-12 02:48 CEST
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing ACK Scan
ACK Scan Timing: About 87.90% done; ETC: 02:49 (0:00:02 remaining)
Nmap scan report for 192.168.21.129
Host is up, received arp-response (0.00032s latency).
All 1000 scanned ports on 192.168.21.129 are filtered because of 1000 no-responses


Nmap done: 1 IP address (1 host up) scanned in 21.41 seconds
```
![image](https://user-images.githubusercontent.com/89842187/131548095-64f8132a-d64b-460c-a857-b2fde43299c6.png)



![image](https://user-images.githubusercontent.com/89842187/131548182-1fd1621f-570e-4f3f-a004-01f7061313ed.png)
