---
layout: post
title: "OSCP - Thoughts and tips"
date: 2015-03-29 18:18:03 +1100
comments: true
categories: [oscp, offensive security, pentesting]
---

I've been pretty quiet on here for the last couple months as I've been really busy taking [Penetration testing with Kali Linux (PWK)](https://www.offensive-security.com/information-security-training/penetration-testing-with-kali-linux/) training course, followed by the [Offensive Security Certified Professional (OSCP)](https://www.offensive-security.com/information-security-certifications/oscp-offensive-security-certified-professional/) exam.

You'll find tons of other blog posts and reviews about the course and exam itself, so I won't be repeating what you should be able to find elsewhere, instead, I'll just try to give you a brief overview of what it is, how did I find it and some simple tips and tricks that will help you prepare for it.

<!-- more -->

Overview
--------

So, what PWK really is? In simple terms, it's a bunch of vulnerable VMs (around 50-ish) in a specially crafted network that is supposed to simulate real corporate environment.

You've got various different subnets, variety of machines (Windows, Linux, FreeBSD, you name it) with heaps of different vulnerabilities. The goal is to hack into as many of them as you can and obtain the highest privilege access (either Administrator/SYSTEM or root).

You can buy access to the lab for 30, 60 or 90 days and keep extending it for another 30 days.

What's OSCP? It's a certification that you get after you pass the exam, which is again, smaller number of vulnerable VMs that you need to break into. The trick is that you only have 24 hours to do so.


Labs
----

First of all, you shouldn't really treat this as a typical certification, where you study a bit, pass the exam and forget most of the stuff you've done in the next couple weeks.

It's a learning process where you'll be able to figure out a lot of things all by yourself, find methodology that works best, develop your own scripts/tools to assist you with your work in the long run (and not only during the labs/exam), build up your knowledge base on known vulnerabilities and exploits plus a whole lot more.

> "It's all about the journey, not the destination"

You gonna spend a lot of time researching, failing and researching more during your time in the labs. It may be quite annoying at times, you may feel inadequate, angry, but then you'll figure it out, move on to the next machine and the process starts again. Sounds annoying, but in the long run, it's very rewarding!

What you also need to know that it's VERY time consuming. If you can't dedicate regular time to it (at least couple hours every day), you're not going to benefit from it and enjoy it.

All failed exploits, research and enumeration is also a learning process, but it does take time... a lot of time! There will be days where you will go with no machines compromised and a lot of failed attempts and then there will be days where you'll get 4 machines in a single day (that you probably wouldn't if you didn't fail earlier on!). 

The labs will teach you numerous things, but most importantly, it'll put you in a right mindset to think like a hacker. As soon as you stop thinking like a good guy, you'll begin to succeed. It happened to me! I was trying to follow a process, be quite formal about it all and... I wasn't going too far very quickly. As soon as I started thinking like a bad guy and asking myself "how can I benefit from it?" about almost everything I came across, I started moving forward... quickly! It all starts with mentality.

Then, methodology - you'll figure out on your own what approach works best, how to track and document everything, how to keep notes, what steps to take with every machine, how to find yourself amongst a large number of machines and vulnerabilities. 

And then there's technical part. Without spoiling, you'll learn a lot about Windows and Unix privilege escalation, web vulnerabilities, a bit on exploit development (basics), you'll come across bad and default configurations, weak passwords, silly users and more!

There's no real goal, it's all about learning and... personal achievements :) Some people want to break into every single machine, some want to get to the administrative domain, some want to get a 'big 3' - machines called pain, sufference and humble. At the end of the day, it's all about learning! Do as much as you need to learn and feel comfortable tackling new and unknown challenges.


Exam
----

Exam is, well, intense. You've got 5 machines and you'll need to break into at least 4 of them to pass.

The difficulty is not the machines themselves though, it's the time constraint! Given that you only have 24 hours, there's not much time to sleep. The machines are quite similar to those in the labs, but of course, not exactly the same. As long as you've done majority of the machines in the labs, you should have seen enough to be able to relatively comfortably tackle the exam.

Again, it's all about the approach and methodology, I can't say when you're ready or not, you will find it out yourself as you'll be going through the labs.


Tips
----

I want to list couple things that I think helped me preparing to take the course and what I found useful over the course of the labs and exam:

 * [vulnhub.com](https://vulnhub.com) - if you haven't checked that out yet, stop reading and go there NOW! Bunch of awesome VMs that were created to be hacked. Variety of different difficulties, vulnerabilities and great community to be a part of, I cannot recommend it enough!
 * attend some CTFs in your area or online, you'll meet bunch of awesome people and learn new things as you go
 * familiarise yourself with at least 1 or 2 scripting languages - probably Python and Unix shell scripting, creating your own tools, automating tasks and reading and understanding exploits will be a lot easier
 * Enumerate, enumerate, enumerate... oh, did I mention enumerating? Yeah, enumerate! That's really what pentesting/hacking is all about, you want to find out as much as you can about your target and as you're doing it, any potential vulnerabilities and security holes will eventually jump out to you. Exploitation is just a tiny part of it, finding the way in is what takes time, knowledge and experience
 * If needed, slow down or stop and try to UNDERSTAND why the things don't work or behave a certain way. Don't fire off bunch of different exploits onto services if you don't know what do they do, how do they work, what version they are etc. etc. Remember, it's all about the journey (learning), not the destination (just passing the exam)
 * If some tools don't work - try to figure out why, find new versions or alternative tools that are being continually developed. If needed, create your own! :)
 * Learn to keep good notes, document every step you've taken, every exploit you used and take screenshots along the way, maybe even develop a cheatsheet of things that you frequently do (e.g. ```hydra``` or ```wfuzz``` common syntax, take note of useful Windows and Linux kernel exploits etc.)


Summary
-------
I loved every single moment of the PWK and would definitely recommend it to everyone!

Few things to keep in mind:

 * you need to be able to dedicate quite significant amount of time to it if you want to be successful
 * you have to be genuinely interested and willing to learn new things
 * you cannot be affraid of failure - you will be failing multiple times throughout the course of labs
 * it will teach you many cool things, but will also teach you to learn - how to look for information and approach problems
 * get some quality sleep before exam - you won't get much of it during the 24h challenge
 * set yourself a goal and work towards it - wether it's get all machines in the labs or break into the "big 3", whatever to keep you motivated. Of course aim to get as many machines as you can, every single one will teach you something new
 * enumerate, enumerate, enumerate
 * go through the provided notes and exercises before starting the lab - it will be helpful down the track
 * it is HEAPS of fun!

If you have any questions, feel free to hit me up on Twitter [@TheKnapsy](https://twitter.com/TheKnapsy) or IRC on one of the channels I usually hang out at - #vulnhub or #offsec on [Freenode](https://freenode.net/).
