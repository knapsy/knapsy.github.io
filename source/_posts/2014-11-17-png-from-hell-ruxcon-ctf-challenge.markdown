---
layout: post
title: "PNG from hell - Ruxcon CTF challenge"
date: 2014-11-17 11:43:20 +1100
comments: true
categories: png, ctf, ruxcon, python, quoted printable
---

Some time ago now I was lucky enough to take part in [Ruxcon CTF](https://ruxcon.org.au/events/ctf/), which was absolutely awesome - learnt bunch of new things and met heaps of cool people!

There was a wide variety of different challenges, but this particular one REALLY did my head in. I spent way too much time on it during the CTF and unfortunately didn't manage to break it. Then recently, I decided to take a look at it again and, with a lot less hassle than I thought, I nailed it!

Let me introduce you to my most hated PNG of all times...

<!-- more -->


Introduction
------------

Alright, let's get started, the goal is to find the flag in the following [packet capture](/images/posts/2014-11-17-png-from-hell-ruxcon-ctf-challenge/oubliette.pcap).

Before we get to it, I owe a huge shout-out to [TheColonial](https://twitter.com/TheColonial) for directing me onto the right path when solving this one... simply, sometimes it's best to write your own tools!


Diving into packet capture
--------------------------

Looking at the packet capture, we can quickly see that it's an SMTP traffic. Let's have a closer look at the TCP stream (right click on any packet of interest -> Follow TCP Stream).

![TCP stream](/images/posts/2014-11-17-png-from-hell-ruxcon-ctf-challenge/tcp_stream.png)

Looks like the transmitted email message will be of the most interest to us - let's extract it:

* Select to show packets going one way only (to the server)
* Save as *raw* data extract

![Raw email](/images/posts/2014-11-17-png-from-hell-ruxcon-ctf-challenge/raw_email.png)


Raw email
---------

Ok, so we have extracted email from the packet capture. Looking at the email, we can see that there's not much of useful plaintext information in the email (subject is just some gibberish), but there's an attachment that we'll need to focus on.

Few things on the attachment looking at the MIME headers and the attachment itself:

* it's encoded as quoted-printable
* it looks like a PNG file (looking at first few bytes of the attachment)

Let's remove all email relevant lines from the file and leave only quoted-printable PNG, making it look like this:

```
root@kali:~/data/ctf/ruxcon2014# cat email_raw
=89PNG
=1A
IHDR=00=00=01@=00=00=00=1E=10=02=00=00=00=82=91=8C=8D=00=00=18zID=
ATx=DA=ED=9Dy\L=EB=1B=C0=9F=D9g=9A=D6I=A5$EIRYn=A5,=85=BA=EAR=B2=C4=CF=BD=

... truncated ...

=F8O=87=A0u=FB=18.=12M@k=E7=D0.R=AB=88~=1B=05=FA=EB=EE=1Dw.=D53I=B2,=11\l=
=E9:=12=FC=13=C2k=04=04=04m=03b=11=16=01=01=01=01=01A=0B=F0=9F~=03&=20=20=
=20=20=20h)=FE=0F=EF=91=EEe=FB=80=FE=9E=00=00=00=00IEND=AEB`=82
```

Cool, so we have a quoted-printable PNG file. There's a problem though - there are carriage returns added before every meaningful new line (part of quoted-printable encoding)! They're easily visible when you open it up, for example, in ```vim```.

![Vim](/images/posts/2014-11-17-png-from-hell-ruxcon-ctf-challenge/vim.png)

Right... let's keep that in mind, it's something we'll need to get rid of.


Plan of attack
--------------

There are couple things we already know about the attachment, so we can have some sort of a plan of attack. Seems that we'll need to do the following:

* decode quoted-printable file
* get rid of CRs before new lines
* ensure we haven't corrupted PNG file header

Seems pretty straight forward!

And that's exactly what I was also trying to do during the CTF, however, I was using pre-made tools for everything! I found some website that was accepting quoted printable files and spitting out decoded version, then I was using ```vim``` with ```xxd``` to get rid of CRs and manually playing with PNG file header.

It was all resulting in a corrupted PNG throwing all kinds of different errors. After lots of research, frustration and talking to [OJ](http://buffered.io), I have decided to write my own tool to do it all for me.


Quoted-Printable
----------------

Before we start, few words on [Quoted-Printable](http://en.wikipedia.org/wiki/Quoted-printable) encoding. There are couple of rules that we'll need to keep in mind:

* any 8 bit value may be encoded with 3 characters: ```=```, followed by two hex digits representing the byte's numberic value
* all printable ASCII characters are represented as themselves (no ```=``` required)
* all lines cannot be longer than 76 characters, soft line breaks may be added (```=``` at the end of the line) to allow encoding very long lines without line breaks

 
PNG header
----------

Also, it's important to understand how [PNG header](http://www.libpng.org/pub/png/spec/1.2/PNG-Rationale.html#R.PNG-file-signature) looks like and why.

```
   (hexadecimal)           89  50  4e  47  0d  0a  1a  0a
   (ASCII C notation)    \211   P   N   G  \r  \n \032 \n
```

* First two bytes distinguish PNG files on systems that expect the first two bytes to identify the file type. It also catches bad file transfers that clear bit 7.
* The next 3 bytes represent name of the format
* The CR-LF sequence (```0d 0a```) catches bad file transfers that alter new line sequences
* ```1a``` stops file display under MS-DOS
* The final LF checks for the inverse of the CR-LF translation problem


Writing own decoder
-------------------

Okay, so now we have a good understanding of the theory behind it all, so let's code something up!

Again, recapping, what we'll need to do is:

* decode quoted printable, following basic rules listed above and ensuring to handle soft line breaks properly (i.e. omit decoding of them)
* get rid of CRs from CR-LF sequences, *except* the one from the PNG header

The following Python code does it all.

{% codeblock lang:Python %}
#!/usr/bin/python

raw_file = open("email_raw", "rb")
output_png = open("output.png", "w")

# Read in all lines and save in one long stream of chars
content = ''.join(raw_file.readlines())

i = 0
while i < len(content):
    # Part of quoted printable, 2 characters following '=' are a hex
    # representation of a symbol. Decode it and write to the output file.
    if content[i] == "=":
        # If they're not /r/n (soft line break of quoted printable),
        # write them in, otherwise ignore
        if content[i+1] != '\r' and content[i+2] != '\n':
            output_png.write((content[i+1] + content[i+2]).decode('hex'))
        i = i + 2   # increment counter by 2 (read 2 characters already)
    else:
        # Also part of quoted printable, characters that can be
        # represented in ASCII are kept as themselves.
        #
        # if the character is '\r' followed by '\n' - ignore,  write
        # '\n' only, unless it's a part of the PNG header (7th byte)
        if content[i] == '\r' and content[i+1] == '\n' and i != 6:
            output_png.write(content[i+1])
            i = i + 1   # increment counter by 1 (wrote \n)
        else:
            output_png.write(content[i])
    i = i + 1   # increment counter by 1 (moving on to the next character)

raw_file.close()
output_png.close()
{% endcodeblock %}

Run it on the previously extracted raw email file.

```
root@kali:~/data/ctf/ruxcon2014# python decode.py
```

And open up ```output.png``` file.

![Output PNG](/images/posts/2014-11-17-png-from-hell-ruxcon-ctf-challenge/output.png)

That's it!


Summary
-------

It was actually a lot easier than I thought... once you know the theory behind it all, understand what's the actual problem we're facing here (CR-LF conversion issue) and write your own tool to do it (not sure why all of the tools I tried didn't do it properly), it's actually not that hard... and only handful of people managed to complete it at the CTF!

Looking back at it, it was pretty frustrating, but I didn't take time to properly read through all the basics during the CTF and I was trying to quickly hack some ad-hoc solution, which didn't work well at all. I guess the time pressure and the thought that *"there are so many other challenges to hack to get points"* sometimes takes over calm, logical thinking. Next time I'll try to take a step back and really ask myself *"what are we trying to solve here"*.

I'm so glad I managed to finish it, it was really doing my head in and, in the end, I learnt a lot from it!
