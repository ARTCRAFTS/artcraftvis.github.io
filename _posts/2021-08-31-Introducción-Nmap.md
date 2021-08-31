# Introducción a Nmap
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
