# Introduction

If you’re making a website or web app, that means people can connect to it. Anything on the internet, whether it’s a web app or even a mobile app that connects to a server, needs security. Here are some important security concepts to be aware of. 

Some people work exclusively in security. Other people are primarily software developers. But even if your job title isn’t something like “security analyst,” you still need to know a thing or two about information security, especially if you want to become a web developer. This chapter primarily focuses on security concepts that are related to web development. 

## Clearing up some common misconceptions

Can a website be malicious? Yes.
Can JavaScript be malicious? Yes.
Can email attachments be malicious? Yes.
Can a word document be malicious? Yes.
Can a PDF be malicious? Yes.
Is hacking illegal? Yes.
Is it legal to attempt to hack a server because “I’m just testing the security”? No.
Do laws against hacking stop people from doing it? No.
Is a security researcher the same thing as a malicious hacker? No.
Can clicking a link get you hacked? Yes.
Can users of your site hack you by submitting comments, forms, or uploading files? Yes.
Can someone hack your site even if you yourself can’t figure out how it’s hackable? Yes.
Can something get hacked even with no user interaction? Yes.
Is there malware for Linux? Yes.
Does restarting a computer get rid of malware? No, except in some very rare cases of non-persistent malware, but that’s the exception, not the rule.
If I went to a malicious website but then closed it quickly, does that mean I’m safe? No.
Does all hacking involve zero-day exploits? No.
Do most hackers take the path of least resistance and try easy stuff first? Yes.
Are executable files (such as .exes) the only kind of malicious files? No.
Are Linux and macOS infallible when it comes to security? No.
Does someone need to be a super genius in order to hack? No.
Is antivirus software perfect? No.
Is antivirus software worth using? Yes.
Do people make money from hacking? Yes.
Is malware only a problem for Windows? No.
If I make a website, will people attempt to hack it? Yes.
Are all hacks done manually, like there’s an actual person attempting it? No.
If I install this one thing, will it make me unhackable? No.
If I set up this one security box on my network, will it make my network 100% secure? No.
Is there such a thing as perfect security? No.
Can software run on a computer even without a window? Yes.
Can phones have security problems? Yes.
Will people only hack me if they know me personally? No.
Will all hacked websites say “this site was hacked” (a phenomenon called web defacement)? No.
Will security always be a problem? Yes.
Is security ever “done”? No.
If I’m a web developer, can I just ignore security because “I’m not a security person”? No!!!
If someone is a security researcher, should I ask them “hey, can you hack my friend’s Facebook?” No!!!

## Vulnerabilities and exploits
A vulnerability is a security weakness in software. An exploit is a program that makes use of a vulnerability in order to hack it.

Let’s say someone designs a padlock. The lock has a design flaw that makes it easy to unlock. The vulnerability would be that it can be opened without a key. The exploit would be instructions for how to open it without a key.

All it takes is one bad line of code. For example, Apple had an SSL security issue for iOS in 2014 because they accidentally wrote the same line of code twice instead of just once. It was “goto fail;” and they must have been copying and pasting and accidentally just pasted it twice. 

## Patching
When a developer finds out that there is a security issue in their code, they will change their code to fix the issue, and then users can install that fix if they install software updates. A software update is also known as a patch.
