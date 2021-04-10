# Well-known security vulnerabilities

## Named security vulnerabilities

Recall that CVEs are Common Vulnerabilities and Exposures, meaning security flaws in software that are made public. 

**MS08-067** – it doesn’t have a name or logo, but it’s very well known, despite being really old (from 2008). You’ll notice that it says MS instead of CVE. Microsoft uses their own naming scheme for vulnerabilities, starting with MS, the year, and then the CVE number. MS08-067 is a remote code execution vulnerability for Windows. However, the fact that it’s from 2008 means most Windows machines are no longer vulnerable to this. 

**EternalBlue (CVE-2017-0144)** – EternalBlue is actually not a vulnerability, but rather an exploit made to use CVE-2017-0144, which is an SMB remote code execution vulnerability. EternalBlue is an exploit that was developed by the NSA and was stolen and released by a hacker group called The Shadow Brokers. Since its public release, it has been used by ransomware developers to spread their ransomware.

**Heartbleed (CVE-2014-0160)** – an OpenSSL vulnerability which an attacker can use to steal private information.

**Shellshock (CVE-2014-7169)** – a Bash remote code execution vulnerability.

**Spectre-V1 (CVE-2017-5753)** – a flaw in Intel CPUs that allows a hacker to steal private information from a computer. 

**Spectre-V2 (CVE- 2017-5715)** – a single vulnerability can have multiple CVEs assigned to it. You might think you’ve gotten rid of it, but it’s possible for a security “fix” to only partially fix a problem. Like you can make your code immune to a very specific type of SQL injection attack, but then it’s still vulnerable to a different kind of SQL injection. Spectre has nothing to do with SQL, but I’m just saying you can easily make a patch that doesn’t fix a problem entirely. 

**Meltdown (CVE-2017-5754)** – another Intel CPU issue, kind of similar to Spectre.

**Rowhammer (CVE-2015-0565)** – a bit-flipping attack, where changing values in RAM quickly can change values in nearby RAM bits. This is a physics-based attack, because of the properties of electricity at small scales, and RAM is very dense these days, so that’s why this is possible. 

**POODLE (CVE-2014-3566)** – Padding Oracle On Downgraded Legacy Encryption. It’s an SSL MITM issue.

**BEAST (CVE-2011-3389)** – another SSL security issue.

**ROBOT (CVE-2018-5762)** – Return Of Bleichenbacher's Oracle Threat. It’s another SSL issue.

**Dirty COW (CVE-2016-5195)** – Copy On Write. It’s a local privilege escalation vulnerability in Linux. Keep in mind that this, and other CVEs listed here, have been patched, and so these attacks won’t work on computers with updated software. Dirty COW, on older versions of Linux, would let you go from being a normal user to root without knowing the root password. I’ve used Dirty COW in some pen test labs before, because you can get a reverse shell that’s a normal user account, but in order to complete a lab you’d need root.

**Stagefright (tons of CVE numbers, including CVE-2015-3864)** – an Android security issue that would allow a maliciously-crafted video file to give an attacker remote code execution.

**Double Kill (CVE-2018-8174)** – an Internet Explorer security issue… that was found in 2018. I’m surprised people still use IE at all. Double Kill lets an attacker do arbitrary code execution if a victim goes to a maliciously-crafted website that makes use of the Double Kill vulnerability… but only if they’re visiting the site with Internet Explorer.

**Badlock (CVE-2016-2118)** – a security issue affecting Security Account Manager and Local Security Authority (Domain Policy). These are used with Samba. Samba, or SMB, is used for file sharing, such as network-mapped drives in an organization. 

**Ghost (CVE-2015–0235)** – a security issue in Linux’s GNU C library.

**Venom (CVE-2015-3456)** – a virual machine security issue that would allow someone to break out of a virtual machine and do stuff on the host machine. VM escape bugs are why it might be a good idea to not do malware analysis on your main computer, even if you think the VM is set up to not be able to interact with your main OS. 

**DROWN (CVE-2016-0800)** – another SSL/TLS security issue. HTTPS has a lot of issues, apparently. 

**BREACH (CVE-2013-3587)** – Browser Reconnaissance & Exfiltration via Adaptive Compression of Hypertext. What a silly name. Another SSL issue. 

**EFAIL (CVE-2017-17688 and CVE-2017-17689)** – an email security issue which lets encrypted content be decrypted even when it’s not supposed to be.

**CCS Injection (CVE-2014-0224)** – another SSL security issue. Contrary to all the names and logos, not all security issues are SSL-related. There are plenty of other issues that have nothing to do with HTTP or HTTPS.

**Foreshadow (CVE-2018-3615)** – a security issue on Intel CPUs relating to Intel’s “speculative execution” feature. Speculative execution is when the processor tries to guess what it should do next. Foreshadow meant that private data could be stolen.

**httpoxy (CVE-2016-6287)** – a security issue for CGI (Common Gateway Interface) code that lets an attacker proxy traffic to other systems, like opening connections to some other device.

**KRACK (CVE-2017-13077)** – a wifi security issue.

**RAMBleed (CVE-2019-0174)** – a side channel attack that can result in a malicious process being able to access data that doesn’t belong to it. Programs are supposed to be separated, and unable to read each other’s memory.

**SockPuppet (CVE-2019-8605)** – privilege escalation for the XNU kernel, which is used in both iOS and macOS. As such, this single issue affects Macs, iPhones, and iPads. Also, in case you’ve never heard of XNU before: it’s a Unix-like kernel used in macOS and iOS, and it stands for X is Not Unix, just like how GNU stands for GNU is Not Unix. 

**Blueborne (CVE-2017-14315)** – a Bluetooth security issue.

**CRIME (CVE-2012-4929)** – a security issue involving cookies and HTTPS.

**Sweet32 (CVE-2016–2183 and CVE-2016–6329)** – a weakness in certain types of encryption.

**Fallout (CVE-2018-12126), RIDL (CVE-2018-12127), and ZombieLoad (CVE-2018-12130)** – related Intel CPU security issues that all fall under the category of MDS: Microarchitectural Data Sampling. More Intel speculative execution problems.

**Spoiler (CVE-2019-0162)** – another speculative execution issue for Intel processors. Keep in mind: CPUs run code too. In fact, a lot of Intel CPUs have their own embedded/hidden installation of Minix, a microkernel Unix-like OS. It’s not a good year to own an Intel processor. AMD CPUs aren’t vulnerable to this stuff.

There’s so much code running on a single computer. You’ve got all the complicated proprietary weirdness of CPU code, a BIOS or UEFI, a bootloader, a master boot record, device firmware, a video card BIOS (yes, GPUs have BIOSes too!), an operating system, kernel, device drivers, shell, userland programs… a single flaw in any of it can make it insecure. Not only that, but malware has so many different places it can hide. 

Security is hard, and the more complicated our technology becomes, the more security issues there will be. You can either have security or breadth of features, but not both. But everyone wants a zillion new features. 

I have a feeling that security is going to get worse before it gets better (if it ever does get better).

If we really wanted things to be secure, we’d take what we know now and redesign everything from the ground up – new networking stack (not TCP/IP), new hardware designs, new OS, new kernel, new shell, new everything – all designed with security in mind. Our current tech ecosystem is full of problems, and a software update here and there won’t change the fact that everything we do is building off of complicated and insecure code. There could be a million undiscovered security vulnerabilities in the code your device is using. But redoing everything from the ground up would set us back a few decades, cost a lot of money, and be very expensive and time-consuming. So instead, we’re just going to keep on using our barely-function-and-not-secure pile of garbage code that allows us to make and do cool stuff, albeit in an insecure way. 

People sometimes say things like “we’re standing on the shoulders of giants” to imply that the people before us made computer advancements that have allowed us to do what we can do now. So we’re working on top of the successes of what other people made before us, in terms of creating computer hardware and software. But here’s the thing – we’re not just building off of the successful stuff of technological advancements. We’re also dealing with decades and decades of mistakes that are still in the tech we use today. Every generation of computer tech has had flaws, and every subsequent generation builds off of previous generations. So we’re just adding more and more flaws to an already massive heap of flaws. If we don’t change this, information security will be impossible. Everything will be hackable forever.

I’ve said it before and I’ll say it again: hacking is easy. Security is hard.

That's all for this short online book project.

If you found this repo to be useful, please star it!

Go to the previous section:
<https://github.com/0x416c616e/intro_to_security/blob/master/06_malware/malware.md>
