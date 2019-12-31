# Section 3: Miscellaneous Security Concepts


## In-band patching vs. out-of-band patching

Because installing software updates is always important, it’s good to have a schedule. Scheduled maintenance and software updates are called “in band.” Software updates are also called patches, so a routine update is called in-band patching. Microsoft has a consistent schedule of releasing updates on the second Tuesday of the month. They call it “Patch Tuesday.”

On Linux, it’s easy to install software updates – just use your package manager to install updates for your OS and packages. Of course, it can get slightly more difficult if you’re using software that you didn’t install via a package manager. It can also be challenging to migrate from one version of something to another when there’s a huge update that breaks compatibility with older stuff – for example, going from PHP 5.6 to PHP 7. But in any case, routine software updates are what you do based on a schedule. 

However, sometimes there are security issues that are so urgent that you can’t just wait until your next scheduled time to patch. Emergency updates that have to happen ASAP are called “out of band.” For example, if there’s a known remote code execution vulnerability that is actively being exploited, and there’s a patch for it, you might just want to patch it as soon as you can, even if it’s 2am. I’ve even heard of a time when people developed an in-house, unofficial mitigation to a security issue before an official patch was released, but that’s not the norm.

Some people in IT and security are paid to respond to these kinds of things. Sometimes they are called “ops,” which is short for operations. They might be on something called “pager duty,” which means they have to respond to alerts, whenever they may happen. Of course, this is less important for personal projects and learning, and more about what companies do. Developers don’t usually do this kind of stuff, but with DevOps, the difference between development and operations is blurring. PagerDuty is also the name of a company, which is named after the same concept (on-call operations and incident response). 

**Trusting third party code** – if you were a hacker, would you go after lots of individuals, or maybe just developers who write software that plenty of people already have installed? Sometimes, it’s not as simple as using a <script> tag on a page. Other times, you have software installed on your server, like a CMS that supports plugins. Wordpress is often customized using plugins, to extend the functionality of the site and also make it feel more unique instead of cookie cutter. But the problem with plugins is that you’re at the mercy of the person who made the plugin. You not only have to trust them to not directly do anything malicious, but you also have to trust that they’re secure enough to not get hacked and have someone else push malicious updates to their plugin. 

**Unnecessary services, unnecessary open ports, unnecessary packages installed** – if you don’t need it, don’t use it. It might make your server less secure. On a home computer, you can install whatever and not really care. But on a server or work computer, you have to be more careful about what you install, maybe even using a test VM on a test VLAN and using Wireshark to monitor what it’s doing over a network. Even if something isn’t malicious, it could just be another way for you to get hacked. The more stuff you have installed, the greater your attack surface. The greater your attack surface, the more likely you are to have a security incident.

**Security through obscurity** – some people think that making something obscure or hidden means it’s secure. For example, iOS is closed source and Apple is very clandestine about how it runs under the hood. However, this is not true security. This is called security through obscurity. Once someone finds out what something is, it’s not obscure anymore, and the illusion of security is gone. Proprietary software can be considered security through obscurity, and another example could be how a professor of mine for an introductory CS class said he thinks it’s more secure to hide login links on websites (which does very little in the grand scheme of things). Not having a link to your login page from the index.html page doesn’t make it more secure. Anyone can easily find it with Dirbuster or just manually guessing where it might be (for example, pretty much all Wordpress sites have a login page at example.com/wp-login.php). Hiding the link to the login page doesn’t make the login page inherently secure, and it’s not that hard to find it, and then test it for various security vulnerabilities.  

Security through obscurity is not security at all. That being said, don’t confuse security through obscurity with file permissions for sensitive data. Sensitive data should not be publicly exposed. That’s not the same as security through obscurity. 

**Account recovery** – this is less technical, but if you have an account on a website, and the recovery question is something like “what is the name of your dog?” and you post about your dog on Instagram, that’s not secure. Treat recovery questions like second passwords. It doesn’t matter if you pour a lot of effort into making your server secure, immune to SQL injection, CSRF, XSS, and more, if people make simple mistakes like posting their recovery question answers on social media where anyone can see them.

On that topic, what often happens when someone says an “account was hacked,” such as on social media (“my Facebook was hacked”), it doesn’t mean Facebook’s servers had a compromise. It means the owner of the account had their details leaked personally, such as from falling for a scam, or posting too much personal information publicly that allowed people to recover the account. 

**Social engineering** – if you are gullible, people will take advantage of you. Many methods of hacking and cybercrime are very low-effort and non-technical. Instead of trying to hack your site directly, a scammer might just call you or email you and try to trick you with their words instead of with code or hacking tools. 

A relative of mine once fell for a scam where someone pretended to be from Microsoft, and they said he had a virus, so he needed to install remote access software to let them fix his computer. For some reason, he completely fell for this and did everything they told him to! Don’t do that. Or even just let your phone go to voicemail and then google the phone number to see if it’s a reported scammer.

I even asked him why he was complying with the scammers’ demands, and he said he didn’t know, and he said it sounded sketchy but he did it anyway. If someone over the phone demands that you do something, you can just hang up. Many scams try to make it seem like there’s a sense of urgency, and you need to act now, because they know that the longer you think about it, the more likely you are to realize that it’s a scam. So they want you to act now before you realize you’re being scammed. 

Another component of scams is trying to scare you. The prefrontal cortex is the part of the brain that performs decision-making, and the fight-or-flight anxiety response disrupts the decision-making abilities of the prefrontal cortex. Your computer has a terrible virus! Your account has been compromised! Quick, act now to fix your computer! Act now to secure your account! If you don’t act now, bad things will happen!

Even if you are a tech-savvy software developer, your friends and family might not be as tech-savvy, and as such, they might fall for scams. That’s why it’s important to not necessarily trust links that they send you, because you don’t know if they were the ones who sent it, or if someone who compromised their account sent it.

**Banner grabbing** – to understand banner grabbing, you must first understand login banners. A login banner is the text banner you see when you try to remotely log in to something, such as with SSH, telnet, and other CLI-based remote login things. 

It might look something like this:

```
###############################
#                             #
#    Cool Company, Inc        #
#                             #
#    Unauthorized access      #
#    is not allowed.          #
#                             #
###############################
```

A banner might also be called an MOTD or banner MOTD. MOTD stands for Message Of The Day. Sometimes, there are messages that are specific to a certain day, but much of the time, there’s just a login banner that stays the same most of the time. Back when I was taking IT classes (before switching to computer science), we learned about setting up banners for Cisco IOS, which is the operating system that runs on a lot of enterprise routers and switches (not to be confused with home consumer devices, which are different). I remember a professor of mine mentioning that it’s a good idea to have a banner that says that unauthorized access is prohibited, because of some legal reason, otherwise someone might not know that they’re not allowed to try and log into something. I’m not sure if that’s actually true or not, but the point is that many login banners say what it is and that unauthorized access is prohibited. Not that hackers care. Criminals will break the law. But although it’s not much of a deterrent, it does let hackers know about the existence of something that a person can attempt to log in to, sometimes containing information that is useful to an attacker. 

Banner grabbing is the act of using different CLI-based remote login programs to send requests to different servers in an attempt to see what the login banners are. If you see a login banner, that confirms that there is indeed a server at that address, and it can potentially be remotely logged into, even though you don’t have the login information. But it’s a way to enumerate assets, which may or may not be valuable for hacking. And if the banner says any information about what’s running on the server, that can make it easier to figure out how to hack it.

**Google dorking** – searching for stuff on Google. Many things are made public when they really shouldn’t be. Instead of trying to do port scanning or banner grabbing, you can just google something.

Here are some basics of google dorking:

**inurl:** to specify something that’s in the url

**filetype:** to search for only a specific type of file

**intitle:** to search for text within a title

**intext:** to search for text within a page

**site:** to only show results on a certain website

***:** is wildcard, meaning any

**"":**  to search with exact matching rather than rough matching

Here’s an example of google dorking, for finding spreadsheets hosted in AWS S3 buckets:

```
site:s3.amazonaws.com filetype:xls
```

If you search for the above google dorking term, I suggest not actually clicking any of the results, because many of them are files that weren’t intended to be made public. Here’s the thing: people make mistakes all the time. When someone puts something in the cloud, they might accidentally click or type the wrong thing, meaning it will be publicly accessible by anyone even though they meant to make it private. 

Here’s another example of google dorking, for finding file directories:

```
intitle:"index of" intext:modified
```

Again, don’t click the links, because these might not be things you’re supposed to see.

Here’s another one I came up with, which lets you find hacked sites that have web shells on them:

```
filetype:php uname user php hdd cwd
```

Don’t click the links for these kinds of google dorking searches. They might either be hacked sites, malware, or honeypots that look like hacked sites. 

You can use other kinds of google dorks queries to find things like network cameras, login pages, and software that is accidentally made to require no login, even when it should.

Again: do not click the results of google dorks queries. You might get in trouble if you do.

I’m only including this information to prove that people make mistakes, and google can index things that it probably shouldn’t. And keep in mind: if you click on a link on a website, the server owner or administrator can look through logs to see IP addresses of visitors.

That all being said, Shodan is a more effective way to find servers. You can search Shodan for servers based on the software that’s running on them, such as if  you want to find servers that have an old and vulnerable version of software on them. But again, use it with caution.

**User awareness** – at a company, you need more than secure code. You need educated employees who are conscious of security issues, including scams, phishing, and things like that. 

**Copying and pasting untrusted code from the internet** – rather than figuring out a coding issue yourself, it’s very easy to just google it and then copy and paste code that someone else wrote, which presumably does what you want to do. But this is not secure. Can you really trust the code written by some random stranger? What if the code is not secure? Maybe the person who wrote it isn’t malicious, but instead just made a mistake. Nobody’s perfect. There are problems with copying code from dubious sources. It’s one thing to copy code from official documentation. For example, it should be okay to use code from the official PHP documentation website: https://www.php.net/docs.php

Just be careful about the section that says “User Contributed Notes” because that’s not official.

If you copy code from the Oracle API, it should be fine: https://docs.oracle.com/javase/8/docs/api/

But make sure you’re looking up documentation for the correct version of Java.

Vendor documentation and vendor code examples can be trusted, but user-posted content, such as on Stack Overflow or even the “User Contributed Notes” section on the PHP documentation site, can’t be trusted as much. 

**Port knocking** – a way to open seemingly closed ports.

**Ping sweep** – a way of enumerating lots of things within a network. 

**IP range scanning** – instead of port scanning a single device, someone might scan an entire range of devices, such as many different servers in the cloud. Some people even scan every single IPv4 address. There are about 4.3 billion addresses, and as such, scanning them all takes a while. To scan all IPv4 addresses is called scanning the entire address space. Some people say port scanning is legal, but I’d say it’s best not to do it because you could potentially get in trouble for it. 

And even though 4.3 billion sounds like a lot, there are even more IPv6 addresses, to the point that it’s not practical to try and scan all of them. IP addresses are numeric and separated into four octets, such as 123.45.6.7, but IPv6 is hexadecimal, with bytes delimited by colons, such as d96:a874:61e7:751:744e:867f:5738:d170. 

**Covert channel** – a less obvious way of exfiltrating data or communicating for nefarious purposes, such as for botnet command & control.

**Insider threats** – not all hackers are from far off places. Sometimes, a disgruntled employee will hack their own workplace. Maybe they got passed up for a promotion. Maybe they didn’t get a raise. Maybe their boss is mean to them. There are many reasons why an employee can become upset with their place of work. Maybe they just got fired but their remote work account hasn’t been deactivated yet. Maybe they’re a janitor. Maybe they’re in accounting. Maybe they’re the system administrator who has access to almost everything. 

An employee who attacks their own company is called an insider threat. Because of this, corporate infrastructure can’t even trust employees. This is why things like data loss prevention software, logging, monitoring, the principle of least privilege, and network segmentation are important. 

**Similarly named packages** – example: <https://www.zdnet.com/article/two-malicious-python-libraries-removed-from-pypi/>

There might be a package in a package manager that you like, but there might also be another package with a similar name that is malicious. 

**Reputation hijacking** – you trust your friend, but do you trust your friend’s accounts? Well, probably, you do. But if your friend’s account is compromised, then the attacker might send you a link or scam email, and you will be more likely to fall for it, because they’re pretending to be your friend.

**Penetration testing a.k.a. pen testing** – testing the security of something. A company might get a pen test from a security professional who will attempt to hack the company (but in a non-malicious way, just testing their security). There are certain regulatory compliance standards that require organizations to get pen tests.

**Shoulder surfing** – when someone watches you type in a password to try and see what it is. This might happen in a place such as a coffee shop, ATM, library, or even a workplace. Because someone can watch from behind and look over your shoulder, it’s called shoulder surfing.

**Attacks against remote access software** – remote access is very important for many things. It can be especially important for businesses and IT admins. Some examples of remote access software include Virtual Network Clients (VNCs), Remote Desktop Protocol (RDP), Secure Shell (SSH), TeamViewer, LogMeIn, and Chrome Remote Desktop. If you use remote access software, you need to make sure that you understand how to set it up securely, common mistakes people make, how to keep it updated, and making sure you use strong passwords.

Also, although there are many legitimate uses for remote desktop software, sometimes scammers or hackers will use them too. A scammer might tell someone to install TeamViewer on their computer and then let them control it. 

**Fork bombs** – a program that recursively runs more instances of itself indefinitely. It goes from one program running, to two, then four, then eight, 16, 32, 64, 128… using up resources exponentially until the computer slows down and either crashes or just stops responding. 

Here is a widely-used example of a very compact fork bomb for Linux/Unix:

```
:(){ :|:& };:
```

But that’s hard to read. So here is another example of a bash fork bomb:

```
#!/bin/bash
forkbomb() {
    forkbomb | forkbomb &
};
forkbomb
```

In the above example, it’s a shell script which first starts by defining a function. After the function is defined, it’s invoked. The function itself runs itself, and pipes the output of the function to the function again, using & to run it as a background process. 

Don’t run the above code on your computer. It will make it very hot and crash.

A fork bomb can be considered a type of denial of service attack, although someone would need to be able to execute code before they could do it. 

sudo rm -rf --no-preserve-root / and :(){ :|:& };: are sometimes used by pranksters online to trick people who are new to Linux. Because it’s not obvious what :(){ :|:& };: does, if a Linux beginner posts a topic on a Linux-related message board and asks “how do I do XYZ in Linux?” then a mean-spirited person might post something like “run this in a terminal: :(){ :|:& };:” and then the beginner will run the fork bomb, which will crash their computer. It’s a good example of why you shouldn’t copy and paste code from the internet.

Some people say that a fork bomb is a security issue, but if it requires authentication or a remote code execution vulnerability in order to run, meaning that someone who can run a fork bomb can also run much worse stuff – wget for malware, exfiltrating data, HTTP bots, and so on. If someone hacks a server, running a fork bomb would not be very useful for them. There are far more valuable things that a hacker can do with a compromised server, aside from just crashing it.

But if someone’s only goal was to simply crash a server, what they could do to make it more effective would be to make a cron job that would run the fork bomb after the server starts up, which would lead to the server crashing over and over again, being unusable. 

To make a cron job that runs when Linux starts up, you could use this command to edit your cron jobs:

```
sudo crontab -e
```

Then write this:

```
@reboot ~/forkbomb.sh
```

Then save and quit the editor.

That being said, a hacker would probably prefer to create a cron job for something like a bind shell or reverse shell instead. That way, they could have persistent remote access to a machine.

**Packet injection** – putting new packets into someone else’s network connection. It’s a type of man-in-the-middle attack

**Format string attack** – when user input gets evaluated by string-formatting functions, like printf(). In printf, you can use special placeholders (called type specifiers), like so:

```
printf("Hello, %s!", name);
```

printf() in languages like C or C++ allows you to use specifiers, like %s for string, %d for numeric (decimal) variables, etc.

Basically, trusting user input without sanitizing and validating it, and then sending the user input to printf() can be dangerous. A format string attack can be used to do things like code execution or reading private things that are in RAM.

You’ll notice that there are many kinds of attacks that are mostly for C and C++. This is because these are “unsafe” languages. The more memory-related stuff a language lets you do, the easier it is to write insecure code in it.

People who use C or C++ might blame the developer, but the fact of the matter is that these languages make it far too easy to write unsafe code.

**Bitsquatting** – typosquatting is when someone types the wrong domain name, like goggle.com instead of google.com because someone accidentally typed it wrong. Bitsquatting is a somewhat similar concept, but for memory corruption rather than human typos. An ASCII value stored in RAM is a sequence of 1s and 0s. If your program connects to example.com, the e in the string example.com is the following sequences of 1s and 0s: 01100101. But if there’s a problem with the RAM, one of the bits could change, and it could be something like this instead: 01100100. The last bit changed because of a memory error, which is rare but possible. Instead of being e, 01100100 is actually d. So instead of trying to connect to example.com, the program would try to go to dxample.com. This is called a bit error. 

Bitsquatting is when an attacker registers domain names that have characters that are one bit off of a legitimate domain. If someone wanted to do bitsquatting for google.com, they could use the domain foogle.com, because it’s one bit off. A bitsquatting domain will either steal data from a user, such as login information, or maybe give them malware. 

**Local admin password reuse** – if a local admin password is reused across multiple workstations in the same organization, then getting the password from one workstation can mean being able to compromise many. Mimikatz can be used to get passwords from a machine once you have a shell on it, such as a reverse Meterpreter shell. 

**Numeric overflow** – when a numeric type variable (such as int or short) reaches its maximum value, and then gets incremented, it actually becomes a negative value. In a 32-bit signed int, it can go from being positive 2.1 billion to negative 2.1 billion. 

Here are the exact values:

What is 2147483647 + 1?

In math, it would be 2147483648.

But in computing, 2147483647 + 1 = -2147483648. It went from being the biggest 32-bit int to being the smallest. 

2147483647 + 2 = -2147483647

2147483647 + 3 = -2147483646

2147483647 is the biggest signed 32-bit integer, and -2147483648 is the lowest. 

**Numeric underflow** – the opposite of an overflow. A numeric underflow, such as an integer underflow, is when a super low negative number has its value decreased beyond the lowest negative value possible, and then it ends up becoming a huge positive number. 

-2147483648 - 1 = 2147483647… at least on a computer, in a situation where something is vulnerable to an underflow.

-2147483648 - 2 = 2147483646

-2147483648 - 3 = 2147483645

This math seems silly, but it unfortunately makes sense on computers.

The way to deal with numeric overflows and underflows is with bounds checking. Bounds checking means checking to make sure something is going to be an acceptable value. Instead of allowing something to wrap around from positive to negative or vice versa, you might want to throw an exception or just not accept the change.

Bounds checking for numeric overflows and underflows is referred to as range checking. Bounds checking can also be used for things like array indices. If you have an array of size 5, and try to access array element 999, that’s out of bounds.

Keep in mind that numeric overflows are not the same as things like buffer overflows.

**Buffer overflow** – when you run a program, your program is allowed to edit its own memory, but not other stuff. A buffer overflow is when you’re able to write more than the length of what your program has, meaning it can then edit the memory of other programs. 

Here’s a very simple demonstration:

Thing1 is yours. You’re allowed to change it. But thing2 is off-limits for you. They are both next to each other in RAM:
 
![buffer overflow image 1](https://github.com/0x416c616e/intro_to_security/blob/master/03_miscellaneous_security/buffer_overflow_1.png)

Then your program decides that it wants to write a value to thing1. But it’s a very long value:
 
![buffer overflow image 2](https://github.com/0x416c616e/intro_to_security/blob/master/03_miscellaneous_security/buffer_overflow_2.png)

Now, both thing1 and thing2 have been changed, even though you’re not supposed to be able to edit thing2’s RAM, because thing2 isn’t yours:

![buffer overflow image 3](https://github.com/0x416c616e/intro_to_security/blob/master/03_miscellaneous_security/buffer_overflow_3.png)
 
But you were never directly editing thing2. You were just editing thing1 with a very long amount of data, and the end of it spilled over into thing2. That spillover is called an overflow. In the above example, 010 is the overflow. Imagine if thing2 is being run with elevated privileges. If you craft your buffer overflow just right, you can use it to get things like code execution or privilege escalation.

Buffer overflows are often used in hacking.

Buffer overflows, like most other memory-related security issues, are mostly related to lower-level languages. In C and C++, you deal with a lot of manual memory stuff. These kinds of things are not quite as feasible in a language like Python or JavaScript, as they take away a lot of memory-related features and instead do auto allocation, garbage collection, and other stuff that puts the computer in charge of memory rather than the developer.

**Hard-coded passwords** – sometimes, a developer will store credentials as a config file, and might code in a feature that lets a user change a password for something. But sometimes, passwords in software are hard-coded, meaning they are within the program itself rather than an external config file, and they will always be the same and unable to be changed to something else. As bad as it sounds, people really do it. Maybe a developer is lazy, or maybe a deadline is approaching. Hard-coded passwords are bad, but people might use them when they don’t have much time to develop a better alternative. The problem with a hard-coded password is that an attacker can find out what it is.

Hard-coded passwords are often reused. If there’s a hard-coded account on a device, and the username is admin and the password is 06437564, it might be the exact same for all other devices of the same make and model. 

One problem with hard-coded passwords is that you might think a device lets you change passwords, but there might be multiple different accounts or logins on a device, and maybe you can only change some of them. But even one hard-coded password/reused is bad.

**Predictable passwords** – some devices don’t have identical passwords, but might base them off of something that is easy to find. For example, some modems have been known to have admin passwords that are based on the serial number or MAC address, which can be found on the bottom of the device. 

It was common, not too long ago, for home routers to have a default username and password of admin. You could set the wireless key, but many devices would have a web interface with an administrative account, which wasn’t made immediately obvious to home users. So you ended up with many less tech-savvy home users changing only their wireless key, but leaving the admin account password at its default value. So anyone on their WLAN would be able to log in and then change settings on it. Nowadays, it seems that some companies are getting better about this, and many routers have more complicated and seemingly one-off passwords. 

The problem with default passwords is that an attacker can just google to find them. Oh, you have an X500 router from Cool Tech, Inc? Someone can just google “Cool Tech Inc X500 default password” and find it.  All default passwords need to be changed.

**SEO poisoning** – if someone is a criminal, it can be hard to get people to visit your malicious site. Maybe they have a site that will give someone ransomware when they click on it. But the criminal still needs to convince people to click on it. Common methods of getting victims to click on malicious links include email spam and social media messages. But another method is called SEO poisoning. SEO, or Search Engine Optimization, means optimizing your website to have keywords that search engines like. SEO will help you get more visitors on your site. This is true for legitimate and malicious websites. SEO poisoning is when a malicious web page has a lot of keywords that people typically search for in a search engine. Then, when you search for something, such as on google, you might see the malicious pages in the results. If you click the link, you could get malware, like ransomware, a keylogger, etc.

**Lack of security hardening** – it can be easy to just set up a server and an app and think “I’m done now!” But you should really consider doing security hardening. Security hardening involves changing settings and disabling unnecessary features to make something more secure. Uninstall packages you don’t need. Delete user accounts that are no longer used. Disable features that you’re not using. Close ports you don’t need to be open. Things like that.

**Full disk encryption (FDE)** – a way to keep data secure when it’s offline is with full disk encryption. Then, if a device gets stolen, the thief can’t see what’s on it, because they don’t have the decryption key. FDE will decrypt the drive when you boot up the OS, so it’s not more secure when it’s powered on. FDE makes data secure when it’s powered off. Linux distros might let you enable this when you install them. File encryption is different from drive encryption. A file can still be encrypted even when the computer is turned on. FDE is mostly for securing against device theft.

A login password alone is not the same thing. You can use password recovery software to get past a sign-on password for a computer. Disk encryption is different.

If you use disk encryption, make sure you won’t forget the decryption key! I once used disk encryption on a laptop and then forgot the password. I was unable to recover any of the data on it. It could be good to use it with a password manager. If you don’t trust cloud-based ones, you can always use an offline password manager on another device. But of course, you’d still have to remember the password manager’s master password.

**Widespread use of encryption** – encryption didn’t used to be as widely used as it is now. And many years ago, if you mentioned encryption, someone might say “well I have nothing to hide, so I don’t need it.” Or they might say “it seems like too much effort to set up.” But now, it’s built into a lot of technology. All major OSes support encryption. When you go to a website, it’s using encryption to securely connect you to the site. When you use an app, it’s using encryption for communicating with the cloud. You can encrypt your phone. You can encrypt your laptop. Every now and then, you will encounter a website where it only uses HTTP instead of HTTPS. But this is getting less common each and every day.

**IMSI catching** – cell tower spoofing. Instead of connecting to a legitimate carrier’s cell tower, like for AT&T, T-Mobile, or Vodafone, your phone could be connecting to a malicious fake device pretending to be a real cell tower. IMSI catchers are illegal for the average person to use, but law enforcement in some countries use them. For example, the FBI uses devices called “Stingrays,” which are IMSI catchers. If you ever go to a security event, such as a hacker convention like Defcon, you might encounter an IMSI catcher.

**Uninitialized variables** – in languages that don’t require a variable to be initialized, and don’t give some sort of null/blank/zero default initialization, an uninitialized variable can have any contents in it. If you have an uninitialized int variable, it could be any integer (of size of an int, of course). But what this means is that code in lower-level languages like C or C++ with an uninitialized variable can sometimes have unpredictable behavior, especially if something is used before it’s initialized. An uninitialized variable can cause bugs. Some bugs can cause security problems. A security vulnerability is basically just a software bug – unintended, incorrect, or unpredictable behavior of a program.

**Evil twin access point** – when you connect to a wireless network, do you know that it’s legitimate? Just because you go to a coffee shop and see a wifi network called “coffee shop wifi” doesn’t mean that’s the real one. Something an attacker can do is set up their own wifi network that is meant to look like a legitimate one. You might be able to connect to it and use the internet, but the attacker might be capturing all the packets on the network so they can try and find valuable information in it. 

**MAC address spoofing** –  some networks use MAC address filtering, meaning only devices with certain MAC addresses can use it. A MAC address is a unique 48-bit address, meaning there are 248 total addresses. No two devices are supposed to have the same MAC address. So if an attacker wanted to get on a network with MAC address filtering, they would have a 1 in 281 trillion change of guessing a particular MAC address. However, an attacker might not need to guess if they can just find out the MAC address of approved devices, such as if there is a device with the MAC address listed on it.

A device’s IP address can change pretty often, but its MAC address never changes, unless someone specifically uses software to spoof it. 

You can look up the different ranges of MAC addresses that different manufacturers use, so you can either identify a product based on its MAC address, or you can spoof your MAC address to a particular address (not completely random) so that it will look like a specific kind of device.

**Juice jacking** – malicious phone chargers that, rather than just charging your phone, can take private data from it. One way to protect against juice jacking is to use a power-only USB cable, which can’t accept data. In a USB cable, there are separate wires for power and data. A power-only one doesn’t have the data ones. Some USB power-only devices are called data blockers.

**AAA** – Authentication, Authorization, and Accounting. A framework for network access for the purposes of security and management.

**Traffic sniffing** – looking at traffic, such as traffic for other devices.

**Wifi security** – there are many different types of wireless encryption, such as WEP, WPA, WPA2, and now WPA3. They are not all equally secure. WEP is very old and insecure. Oddly enough, even though WPA 3 is newer, some security flaws have been discovered in it. 

New software attempts to solve old problems, like security issues. But it can sometimes introduce new security issues. That being said, WPA 2 is far from perfect, as it’s possible to brute force a WPA 2 key.

**Checksum collisions** – two files can have the same checksum. It’s rare, but possible. This can mean that an attacker could get past checksum verification by making a modified file that has the same checksum as an unmodified one. However, it takes way too much time and effort for the average person to attempt this, especially if you’re using more secure hashing algorithms rather than something fast and insecure like md5. 

**Sideloading APKs in Android** – on iOS, unless you jailbreak your device, you can’t really install apps that aren’t in Apple’s app store. On Android, you can sideload APKs, meaning you can install apps that aren’t in the Google Play store. However, sideloading is a double-edged sword: it offers greater flexibility and the ability to install apps that aren’t in an app store, but it also means that you can get tricked into installing malicious apps. 

Sideloading is common on devices that don’t support Google Play. There are many Android devices that have alternative app stores, often with inferior app selections. As such, people on cheap Android devices without proper app store support might download APKs from shady APK sites, which might put malware in the APKs, so you get the app and a trojan that hides itself but does bad things.

**Export laws and cryptography** – in the US, encryption is treated as a munition, and as such, exporting encryption to other countries is restricted by law. Of course, it’s kind of silly to treat encryption as a weapon, when clearly there are plenty of practical civilian uses. You couldn’t securely log into your bank account without encryption. You can’t make secure payments without encryption. Over the years, crypto export laws have become more relaxed, but some restrictions still apply. I only know this because of using Cisco IOS routers and switches which explicitly point this out. 

**VM escape** – when a user in a virtual machine is able to break out of the virtual machine and affect the host OS or hypervisor, or perhaps see or mess with the other VMs on the same machine, it’s called a VM escape vulnerability. Sometimes they’re also called VM breakout vulnerabilities. This is a concern for public cloud computing, because when you have a virtual machine, other customers have VMs running on the same server. If another customer in a different VM on the same server could find and exploit a VM escape vulnerability, they might be able to do things on your VM, like code execution or data exfiltration. That being said, these kinds of vulnerabilities aren’t common, and they’re very complex to exploit. Not only that, but because a cloud provider has people’s payment information, if your VM “neighbor” were to hack you, the cloud provider would be able to see it, and to see the payment info of the person who did it. In reality, SQL injection and XSS are probably a billion times more likely to be exploited than VM escape.

But rather than for websites and cloud computing, one area where it might be more of a concern is malware analysis. You have a computer and you set up a VM dedicated for analyzing malware. If the malware can break out of the analysis VM, it could infect your host OS, which is bad. But even then, it’s not super common.

**ARP spoofing** – ARP, or Address Resolution Protocol, is when a device on a network says “hey, I have data for XYZ. Who is XYZ?” and then a device responds with “I’m XYZ, give it to me.” ARP spoofing is when your make your computer lie in response to ARP broadcasts. ARP spoofing, also known as ARP poisoning, can be used to steal network traffic that is intended for another device.

**Switch CAM table overflow** – switches use a CAM table, or Content Addressable Memory table, to build up a list of which port corresponds to which MAC address. In order to understand a CAM table overflow, you must first understand switching.

A hub is a layer 1 networking device. It has multiple ports. You can use it to connect multiple devices on a network. Neither a hub nor a switch deal with IP addresses. But if you want more ports  for more wired devices, you could use a hub or a switch. It also helps to know about frames. If you’re not familiar with frames, they’re a layer 2 protocol data unit (PDU). They are concerned with source and destination MAC addresses. For every layer 2 hop, a new frame will be created. PDUs encapsulate data that is sent over a network. More people are familiar with packets. A packet is a layer 3 PDU concerned with source and destination IP addresses. But for switches, they are layer 2 devices, and as such, only care about source and destination MAC addresses. Layer 1 is the physical layer, layer 2 is the data link layer, and layer 3 is the network layer. There are 7 layers in the OSI model

When you want to send data through a hub, it blasts it out all ports, because it’s a simple device which lacks the capability to figure out where it needs to go. A problem with a hub is that it makes it easy for people to get data that is intended for someone else. So a solution to the hub issue is the use a switch instead, which is better for performance and privacy/security.

Unlike a hub, a switch can figure out where to send something. When a switch deals with a frame for a device it’s never seen before (since its last reset), it will blast it out on all ports, called a broadcast frame, which is intended to figure out where to send frames that are intended for a given destination MAC address. Keep in mind I am talking about physical ports here, not TCP/IP ports. Then once the switch knows where to send something, it will put it in its CAM table. 

A CAM table will show which MAC address is on each port. 
Here is a simplified example:

```
MAC			Port
A:B:C		1
A:A:A		4
B:B:B		3
C:C:C		6
```

A CAM table overflow is when an attacker changes their MAC address tons of times. When they use the switch, they will fill it up with bogus entries. Eventually, the CAM table only be full of bogus entries from the attacker. When a CAM table overflow occurs, a switch functions basically the same way a hub does. Then the attacker can read network traffic that is intended for other recipients.

**Airgaps** – an airgap is when a computer is not connected to a network. There are real airgaps and pseudo-airgaps. If you’re constantly plugging flash drives into a non-networked computer, then it’s not really airgapped. Something truly airgapped would be a computer that is never connected to a network and never has any sort of removable media added to it. It can’t have any sort of wireless functionality either. Many people say “airgap” when “semi-airgapped” might be more appropriate. Airgaps are supposedly more secure, but I’d argue that they have some flaws: firstly, not all airgaps are true airgaps, and secondly, a lack of networking means it’s bound to have really old and insecure software on it. So if something is airgapped, it had better have good physical security as well, otherwise there could be some sort of local security issues which could be exploited by plugging devices into it. There can be things like lock screen bypasses, issues with USB devices being plugged in, and that kind of thing.

**Misconceptions about incognito/private browsing** – I’ve seen posts on social media where people seem to not understand private browsing modes in browsers. All it means is that your browser isn’t saving that stuff to your hard drive. It doesn’t mean there’s no log of it elsewhere. Your ISP know what you’re doing. The websites you’re visiting in incognito mode still know you visited them. All it means is that, rather than saving it to your browser profile, which will be persistent across reboots, it’s only keeping it in RAM. But aside from your device, there’s the network you’re on, your ISP and/or company, and the servers you’re connecting to. Whether you have incognito mode or not, they will still log what you’re doing. 

**Data Loss Prevention** – when you think of “data loss,” you might think of a hard drive dying, and losing the files that were on it. But in the context of security, “data loss” means someone taking private data out of a company. Companies have all sorts of private data. Patient records, patents, unfinished projects, customer payment information, designs, proprietary code, secret sauce recipes, intellectual property, and more. What if an employee shows up to work with a flash drive and decides that they want to copy private company data onto it? That’s where data loss prevention (DLP) software comes in. 

**Not disabling accounts of former employees** – when someone gets fired, they should not be able to access any company resources anymore. Employees who are fired might be mad and spiteful. If you fire a system administrator without revoking their ability to remotely access IT assets in the company, they could do some damage.

**WONTFIX** – if you submit a bug report for an open source project, and the maintainers of said project don’t think it’s an issue or don’t want to spend time on it, they will close it as “WONTFIX” because they’re not going to fix it. If they deem a bug to be insignificant, or debate about something being a bug or not (“it’s not a bug, it’s a feature”), then they’ll leave it in.

**VLAN double tagging/VLAN hopping** – a way for an attacker to get into a VLAN that they’re not allowed to be in. VLANs are Virtual Local Area Networks, and the purpose of them is to allow for networks to be separated into smaller networks that have rules about traffic. For example, a company might have many different departments, and they will not be allowed to access each other’s network resources. This is important for internal reasons, as well as security. When networks are segmented, they are broken into smaller pieces, as opposed to a “flat” network topology where everything is in the same subnet and all devices can talk to all other devices. Segmentation limits how much damage an attacker can do. However, clever hackers can do VLAN double tagging, meaning putting two VLAN tags on their traffic, which will allow them to get from one VLAN to another. It’s complicated, but it means that an attacker can get from a network they’re allowed to be on to a network they’re not allowed to be on.

**Perimeter** – the on-premises assets of a company that the IT department can secure. The problem with a traditional IT perimeter is inflexibility. Maybe a developer needs a new server for a project, but the IT department either won’t let them have one, or are just taking too long. 

**Shadow IT** – if a developer can’t convince the IT department to give them the resources they need, they might just circumvent the IT department’s process entirely and just go for cloud resources instead. Can’t get the system administrator to set up a server for you quickly? Just use a web browser to spin up an AWS EC2 instance in a matter of minutes. 

Of course, while cloud computing is very convenient for developers, this also makes security more complicated, and makes it hard to figure out what a company needs to secure and keep track of. An IT department will generally be good about securing and updating the assets that the organization owns, but it can be harder when employees get their own stuff in the cloud.

Because the IT department might not even know about this stuff, it’s called shadow IT, because many people in the company who should know about it don’t know that it’s being used. 

Shadow IT is tech that is used in a company without the knowledge or permission of the IT staff. It’s a bigger threat to security than stuff within the traditional perimeter.

The solution here is for IT to embrace cloud more, and for developers to communicate more with operations teams (hence DevOps), so that people can get the resources they need while also keeping track of things and making sure that processes for security and compliance and whatnot aren’t ignored. 

**BYOD** – Bring Your Own Device. This makes security harder because you have employees bringing in their own stuff, meaning security is much more difficult.

**Weak wifi password** – if your wifi password is weak, people can easily brute force it. Then they can get on your network, do ping sweeps to enumerate devices, do port/service scans, find vulnerabilities, etc. Of course, this is limited to people who are close to your, such as your neighbors. But every now and then, someone might try to get on someone else’s wireless network, so wifi security is important.

**War driving** – driving around while scanning for wireless networks, hoping to find ones that aren’t secure. If someone wanted to do something bad, like make a threat online, they might do it from someone else’s wifi network rather than their own, in order to avoid getting caught.

**Bluesnarfing** – a way to steal information from devices that use Bluetooth.

**Type confusion** – when something takes an object without verifying the object’s type, it can lead to a problem called type confusion, where code is expecting one kind of type but it got another. I’ve seen type confusion mentioned in articles about Adobe Flash security, where flash on a web page can use a type confusion exploit to gain the ability to execute arbitrary code. It’s used with exploit kits for delivering ransomware, though not as many people use Flash anymore.

**Deadlines and cutting corners** – some software developers have to work on tight schedules. Sometimes they’re not even given enough time. As a result, they have to cut corners. When there are security issues as a result of corner-cutting, people might blame software developers or IT staff, when instead the real issue might be managers who want to rush a project. In my personal experiences, people who don’t code vastly underestimate how time-consuming it really is. 

**Lock screen bypass** – you might think that your phone is secure if you have a lock screen code, but every now and then someone finds a lock screen bypass bug. Of course, newer versions of Android and iOS fix them relatively quickly, but one issue is that people with old phones, especially Android ones, don’t get updates, meaning they can still be vulnerable even after it’s been fixed in the latest version.

**Stunt hacking** – doing a silly but attention-grabbing security stunt in order to get media attention. It’s often for an edge-case thing that isn’t common. Most hacking isn’t that interesting or accessible to non-technical people. XSS, CVEs, etc. The general public would rather hear cool or outlandish stuff, like someone hacking cars to disable their brakes. That’s happened, but that’s not the reality of day-to-day security stuff. Stunt hacking is about doing weird things to get notoriety. It can lead to sensationalist headlines and fear, uncertainty, and doubt.

**Removable media autorunning** – it’s bad to have autorun enabled for removable media.

**Change management** – tech change in an organization needs to be managed. 

**Empty catch block** – when you’re writing code, if there’s something that might cause a problem, you use exception handling. Some languages, like Java, might force exception handling, giving compiler errors if you don’t. But other languages are more permissive. In any case, regardless of the language you use, it’s possible to handle an exception in a very lazy way. Maybe you don’t want to deal with the error, so you have an empty catch block, which means do nothing in the event of an error. That’s bad. The whole point of exception handling is to do something when something goes wrong. An empty catch block defeats the purpose of it. It can also be bad for security. 

**Inventory and asset management** – in order for an organization to be secure, they need to know what they have. As infrastructure grows over time, and organizations have many servers and workstations, you need to keep track of things. 

**Double file extensions** – on Windows, the default is to hide file extensions. So if someone makes a file called photo.jpg.exe, it will show up as photo.jpg. This is bad. Fortunately, you can enable full file extensions. In an Explorer window, click the View tab at the upper left, then check the box that says “File name extensions.”  

**Junk hacking** – you can just buy some cheap smart device, router, or network camera on Amazon, port and service scan it, and eventually find vulnerabilities and ways to exploit it. That’s because there’s just a bunch of cheap garbage out there. By the time you by it, it already has super old software on it, like a really old version of Linux. It’ll have default passwords, sometimes on accounts that the manual won’t tell the user about. It might have hard-coded passwords. It might have a remote code execution vulnerability. Maybe it has a web server so that the user can configure it via a web interface, and the web stack it’s using is outdated and has vulnerabilities. There are so many ways a cheap smart or network-related device can be hacked. 

It's called junk hacking, because these devices are junk. It’s not very difficult to do, because these cheap devices were not designed with security in mind.

**Lack of encryption** – encryption is important. Even if someone can do SQL injection or code execution, if they can’t decrypt important stuff, then it’s not as bad as if it was unencrypted. The two main kinds of encryption are data in motion (encryption when something is travelling on a network, like from one device to another) and data at rest (encryption on a hard drive or SSD).

**Software development life cycle** – the cycle of how software is created and deployed. It involves planning, analysis, design, implementation, testing and integration, maintenance, and then repeating the process all over again. However, I would argue that there is an additional step: possibly sunsetting the application once it’s older, harder to support, worse than competing products, being replaced by something newer, etc. 

**Application sunsetting** – retiring old tech because it’s no longer support or secure.

**Dumpster diving** – if your company gets rid of old tech without doing proper data destruction, then someone can just look in the dumpster at your building, take the dead computers/drives that are thrown out, and then recover private company data from them.

**Enterprise security software** – to see a list of the kinds of security software that gets used in an enterprise environment (such as at a college or business), see the last part of Appendix E.

**CTF** – Capture The Flag. A non-malicious hacking event, where you’re on a team to find a security issue with a server (which was set up to be insecure), such as to find a key file, which is just a text file with a random string in it, which is proof that you were able to compromise the server. It’s an event which is both social and educational. 

**IOC** – Indicator Of Compromise.

**PoC** – proof of concept. If someone finds a security issue, they might code a proof of concept in order to demonstrate it.

**0-day or zero-day** – a new security issue which people haven’t encountered before, and as such, have zero days to react to it. Unlike a CVE, which is well known, a zero-day is previously unknown by anyone except the attacker, or maybe a very small group of people. Zero-day exploits aren’t commonly used. For one thing, you can usually just hack with just CVEs or OWASP top 10 categories alone, with no need for fancy 0-days. For another thing, once someone uses a 0-day, they might be able to hack something, but then that organization has logs that they can analyze to learn about the 0-day. So once a 0-day is used, it might be found out, and then it won’t be a zero-day anymore. Maybe nation-state attacks will involve 0-days, but the vast majority of hacking does not. Most hackers don’t even know how to find security vulnerabilities on their own, and most hacking is just people scanning for well-known types of attacks and CVEs. But “zero-day” sounds cool, so people tend to overuse it.

**Zero Day Initiative, Zerodium, BugCrowd, and HackerOne** – bug bounty platforms.

**Google Project Zero** – Google’s security research division.

**Names and logos** – some people make a name, logo, and even a website for a security vulnerability that they find. Most security issues only have CVE numbers, such as CVE-2019-1010298. But even if something has a catchy name, it will also have a CVE number. For example, BlueKeep (cool name) is CVE-2019-0708 (technical CVE number). CVEs have a score, using something called CVSS: Common Vulnerability Scoring System. High CVSS CVEs need to be taken seriously, especially if your app or website uses the thing with a CVE (for example, a CVE for the Apache HTTP Server, or something like that).

Most CVEs have cryptic CVE numbers, which are CVE-Year-Number. But some security researchers want to also be marketers, so they make cool-sounding names, scary-looking logos, and websites to advertise the vulnerability. Some people say that people who do this are doing so because they want to advance their career as a security researcher, and so they want to raise awareness for the vulnerability just to gain notoriety, especially because their website often has a very non-technical explanation of the vulnerability, in order to get as many people as possible to talk about it. But some people think it’s a good thing for people to increase security awareness. 

But regardless of how you feel about name/logo vulnerabilities, the fact of the matter is that there are tons of severe security vulnerabilities that you need to pay attention to that don’t have cool names or logos. Just to put things in perspective, there are only a few vulnerabilities with names and logos. But according to cvedetails.com, there were over new 12,000 CVEs in 2019 alone.

Go to the previous section:
<https://github.com/0x416c616e/intro_to_security/blob/master/02_web_security/web_security.md>

Go to the next section:
<https://github.com/0x416c616e/intro_to_security/blob/master/04_tools/tools.md>

Some additional stuff you might want to look into:

Additional topics to look up:

- ROP -- return-oriented programming
- Use-after-free and double free
- nop slide
- Memory corruption
- Heap spraying
- DLL injection createremotethread rtldecompressbuffer
- Replay attacks
- Certificate pinning
- RASP -- Runtime Application Self-Protection
- credentialed vs. non-credentialed scans
- Hacker convention/conference -- blackhat and defcon
- stack canaries
- stack canary brute forcing
- password spraying
- packet-in-packet
- dns cache poisoning
- dns sinkholing
- dns rebinding
- DNS hijacking
- sybil attack against distributed systems
- form grabbing
- driver shim
- iterator invalidation
- Update spoofing, i.e. flame
- Insecure Direct Object Reference
- Session hijacking
- Server-side request forgery (SSRF)
- broken access control
- broken authentication
- Same origin policy
- same-origin bypass
- Cross-origin resource sharing (CORS)
