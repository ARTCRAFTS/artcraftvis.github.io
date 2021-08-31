---
layout: single
title: FTPEnumeration & Exploiting
excerpt: "File Transfer Protocol (FTP) is, as the name suggests , a protocol used to allow remote transfer of files over a network. It uses a client-server model to do this, and- as we'll come on to later- relays commands and data in a very efficient way."
date: 2021-08-31
classes: wide
categories:
  - Red Team
  - infosec
tags:
  - Red Team

---


# What is FTP?

- File Transfer Protocol (FTP) is, as the name suggests , a protocol used to allow remote transfer of files over a network. It uses a client-server model to do this, and- as we'll come on to later- relays commands and data in a very efficient way.

## How does FTP work?

- A typical FTP session operates using two channels:
a command (sometimes called the control) channel
a data channel.
As their names imply, the command channel is used for transmitting commands as well as replies to those commands, while the data channel is used for transferring data.

- FTP operates using a client-server protocol. The client initiates a connection with the server, the server validates whatever login credentials are provided and then opens the session. While the session is open, the client may execute FTP commands on the server.

## Active vs Passive

- The FTP server may support either Active or Passive connections, or both. 

- In an Active FTP connection, the client opens a port and listens. The server is required to actively connect to it. 
- In a Passive FTP connection, the server opens a port and listens (passively) and the client connects to it. 
- This separation of command information and data into separate channels is a way of being able to send commands to the server without having to wait for the current data transfer to finish. If both channels were interlinked, you could only enter commands in between data transfers, which wouldn't be efficient for either large file transfers, or slow internet connections.
More Details:

- You can find more details on the technical function, and implementation of, FTP on the Internet Engineering Task Force website: https://www.ietf.org/rfc/rfc959.txt. The IETF is one of a number of standards agencies, who define and regulate internet standards.

# Enumeration
```
ls /usr/share/nmap/scripts/ftp*
Nos conectamos con: ftp <ip>
Podemos subir archivos con: put fun.py
A veces es necesario entrar en modo pasivo con: pass
Luego un simple: enter
ftp://anonymous:anonymous@target
telnet 10.10.27.148 21
nc -v 10.10.27.148

Comandos para descargar archivos de ftp.
wget -m ftp://anonymous:anonymous@target
wget -m --no-pasive ftp://anonymous:anonymous@target

Brute Force

hydra -t 4 -l username -P /usr/share/wordlists/rockyou.txt -vV <ip> ftp
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX ftp -V

![652502879b8f94eef10ba9946bd15dd2.png](:/7dd98b7d1b4d421596ce2ff247867d95)

Examine Files
ftpusers
ftp.conf
proftpd.conf
```


Method
We're going to be exploiting an anonymous FTP login, to see what files we can access- and if they contain any information that might allow us to pop a shell on the system. This is a common pathway in CTF challenges, and mimics a real-life careless implementation of FTP servers.

Resources

As we're going to be logging in to an FTP server, we're going to need to make sure therre is an ftp client installed on the system. There should be one installed by default on most Linux operating systems, such as Kali or Parrot OS. You can test if there is one by typing "ftp" into the console. If you're bought to a prompt that says: "ftp>" Then you have a working FTP client on your system. If not, it's a simple matter of using "sudo apt install ftp" to install one.

Alternative Enumeration Methods
It's worth noting  that some vulnerable versions of in.ftpd and some other FTP server variants return different responses to the "cwd" command for home directories which exist and those that don’t. This can be exploited because you can issue cwd commands before authentication, and if there's a home directory- there is more than likely a user account to go with it. While this bug is found mainly within legacy systems, it's worth knowing about, as a way to exploit FTP.

This vulnerability is documented at: https://www.exploit-db.com/exploits/20745 


# Types of FTP Exploit

Similarly to Telnet, when using FTP both the command and data channels are unencrypted. Any data sent over these channels can be intercepted and read.

With data from FTP being sent in plaintext, if a man-in-the-middle attack took place an attacker could reveal anything sent through this protocol (such as passwords). An article written by JSCape https://www.jscape.com/blog/bid/91906/Countering-Packet-Sniffers-Using-Encrypted-FTP  demonstrates and explains this process using APR-Poisoning to trick a victim into sending sensitive information to an attacker, rather than a legitimate source.

When looking at an FTP server from the position we find ourselves in for this machine, an avenue we can exploit is weak or default password configurations.

Method Breakdown

So, from our enumeration stage, we know:

    - There is an FTP server running on this machine

    - We have a possible username

Using this information, let's try and bruteforce the password of the FTP Server.

## Hydra

Hydra is a very fast online password cracking tool, which can perform rapid dictionary attacks against more than 50 Protocols, including Telnet, RDP, SSH, FTP, HTTP, HTTPS, SMB, several databases and much more. Hydra comes by default on both Parrot and Kali, however if you need it, you can find the GitHub here.
The syntax for the command we're going to use to find the passwords is this:

```
hydra -t 4 -l dale -P /usr/share/wordlists/rockyou.txt -vV 10.10.10.6 ftp
```
Let's break it down:

SECTION             FUNCTION

hydra                   Runs the hydra tool

-t 4                    Number of parallel connections per target

-l [user]               Points to the user who's account you're trying to compromise

-P [path to dictionary] Points to the file containing the list of possible passwords

-vV                     Sets verbose mode to very verbose, shows the login+pass combination for each attempt

[machine IP]            The IP address of the target machine

ftp / protocol          Sets the protocol
