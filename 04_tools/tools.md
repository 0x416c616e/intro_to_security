## Tools

**Decompilers** – tools for taking a compiled executable and then attempting to decompile it. The point of a decompiler is to make it so that you can see what software does. This is achieved by taking unreadable compiled code and then converting it into something that a software developer can read and analyze. It’s used for things like keygens and malware analysis. A decompiler will take machine code and then convert it to assembly, and then try to represent it as something like C. The NSA made a cool free and open source tool called Ghidra which can be used for decompiling. Some other tools to look into include Radare2, OllyDbg, ImmunityDebugger, x64dbg, and IDA Pro. Some reverse engineering tools will only display stuff as assembly though, not C. Another semi-related tool that can be useful is a memory forensics tool called Volatility. 

In some cases, decompiling might be illegal, especially if you’re trying to reverse engineer a copyrighted program. But I don’t think there’s a problem with trying to reverse engineer malware.

If someone wants to perform malware analysis, it’ll typically be done in a virtual machine (for safety), using a decompiler or disassembler, and other analysis tools, such as Volatility for memory forensics, Process Explorer, Wireshark, and more.

**strings analysis** – a very basic form of malware analysis. Strings is a Unix command line program which will display the strings that are in a binary file, such as a compiled executable. Strings is useful for rudimentary malware analysis, though more sophisticated malware might use string randomization to thwart this simple type of analysis. 

There are two main categories of malware analysis: active and static. Static malware analysis is looking at the malware executable without running it. strings can be considered a static malware analysis tool. Active malware analysis involves actively running the malware, which means you need to take extra safety precautions, like sandboxing, or maybe even a dedicated offline or VLANed/firewalled off malware analysis computer. Static malware analysis is safer and simpler, but less fruitful. Active malware analysis involves things like disassemblers/decompilers, as well as additional analysis tools. Unlike running a program regularly, running a program in a disassembler or decompiler allows you to create breakpoints and to run the program much slower than normal. This is getting a little off-topic for the security section. But if this interests you, just know that malware analysis is a career! If this sounds more interesting than web development to you, maybe consider getting into malware analysis and reverse engineering instead. 


**nmap** – a tool for port scanning.

**Kali Linux** – a Linux distro with a lot of hacking tools preinstalled. If you use Kali Linux, change the root password immediately. I don’t recommend using Kali as your primary OS, because it’s actually not very secure. It’s best to either run it “live” (meaning booting it up from a flash drive without installing it), or running it in a virtual machine, which is what I do. You might have a Windows or macOS computer, or even a computer running a Linux distro, such as Debian. But you’d want to only have Kali in a VM, and you only have it running when you’re using it for a security lab, such as Virtual Hacking Labs, HackTheBox, DVWA, Mutillidae, Metasploitable, etc.

**DVWA** – an intentionally-insecure web app that you can set up in a VM so that you can test out your hacking skills on it.

**Metasploitable** – another intentionally insecure VM.

**Mutillidae** – similar to DVWA and Metasploitable, it’s an insecure web app that lets you learn about attacks against web servers. 

**WebGoat** – yet another intentionally insecure web app. 

**OWASP ZAP** – a web security tool made by OWASP.

**Metasploit** – a widely-used security tool.

**Parrot OS** – an alternative to Kali Linux.

**SSL Labs** – a site for testing and analyzing SSL. 

**Maltrieve** – a tool for retrieving malware samples for malware analysis.

**Cuckoo Sandbox** – a tool for malware analysis.

**SparkFun Skimmer Scanner** – a tool for finding gas pump Bluetooth credit card skimmers.

**Kippo honeypot** – an SSH honeypot.

**VBoxHardenedLoader** – a tool for making it harder for malware to detect that it’s in a virtual machine, for use with Virtualbox VMs.

**exiftool** – a tool for viewing or editing photo metadata. 

**Nexpose** –a vulnerability scanner made by Rapid7, the same company behind Metasploit.

**Recuva** – a tool for recovering deleted files. Someone who sells a computer on craigslist could have their identity stolen because someone could use file recovery software on the hard drive/SSD and then see their personal files. 

**DBAN** – Darik’s Boot and Nuke. It lets you make sure that data on a drive can’t be recovered. It achieves this by writing random data on a drive over and over again to make sure that whatever used to be there can’t be recovered. If you’re throwing out a computer, or just selling it to someone, like on craigslist, then you should use DBAN first and then just reinstall the OS. You can make a bootable flash drive for either Windows or macOS and then reinstall it after running DBAN. 

**Firesheep** – an old packet sniffing tool for Firefox. It demonstrates why it’s important for sites to use HTTPS rather than HTTP. However, HTTPS adoption has increased dramatically in recent years, so this isn’t as big of an issue as it used to be.

**BeEF** – Browser Exploitation Framework, a pen testing tool for browsers.

**BFF** – Basic Fuzzing Framework. A tool for doing fuzzing, which is putting random data into a program and seeing if it crashes or gets privilege escalation or whatever.

**FOCA** – a tool for gathering metadata from a website. 

**Aircrack-ng** – wifi security tool.

**Scapy** – a program for manipulating packets, written in Python.

**w3af** – a web application security scanner. There are many different tools in each category. W3af isn’t the only web app scanning tool.

**Bluescanner** – a Bluetooth device scanner.

**Spectrum analyzers** – WiSpy Chanalyzer, WiFi Explorer, RTL-SDR devices, etc. Tools for analyzing wireless spectrums. You can do things like discover hidden networks, wireless devices, and things like that.

Some people wrongly think that hiding their wifi network’s SSID (Service Set Identifier) means that nobody can see it. But with a tool like WiFi Explorer for macOS, you can easily see even hidden networks.

**Cain and Abel** – password recovery tool which can do things like hash cracking, brute forcing, and packet sniffing.

**tcpdump** – a command line packet analysis tool.

**zenmap** – like nmap, but with a GUI. nmap is command line. 

**Armitage** – a GUI for Metasploit, which is a command-line program.

**Cobalt Strike** – a tool for simulating attacks and doing security assessments. It costs a lot of money, so it’s best to use free tools first. Maybe if your job is security research or penetration testing, it could be good to have. But for beginners or web developers who just want to make their web app more secure, this isn’t worth the money. 

**Kismet** – a tool for wireless security stuff, such as packet sniffing and network detection.

**Reaver** – a wifi brute forcing tool.

**Bloodhound** – a security tool for Active Directory.

**sqlmap and sqlninja** – SQL injection tools.

**Nessus** – a vulnerability scanner. It costs money, so just stick with nmap.

**UPX** – The Ultimate Packer for eXecutables. A tool used for “packing” malware. More on malware in the malware section.

**BinDiff** – a “diff” tool is used for finding differences between files. diff is commonly used for version control systems, like git, so that you can see the modifications of a file from one commit to the next. BinDiff is a diff tool for compiled binaries. 

**SSLStrip** – a tool for man-in-the-middle attacks.

**Responder** – a Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NetBIOS Name Service) hacking tool.

**l0phtcrack** – a password cracking tool.

**Burp Suite** – a suite combining many different web security tools into a single program. It’s very useful for web developers who want to test their site against web-related attacks.

**Wireshark** – a tool for monitoring network traffic or doing packet captures, also known as pcaps. A packet capture is when your device listens to traffic on a network and records it. If something is being transmitted over a network without encryption, you might be able to see what it is. So you can use Wireshark to find credentials. Wireshark has a wide variety of uses.

**Nikto** – a web server scanner.

**WPscan** – a Wordpress vulnerability scanner. It can be used to find security weaknesses in Wordpress sites.

**Exploit DB** – a website with lots of security exploits that you can use. The DB stands for database. If you search for a very specific version of a program, you can find an exploit that applies to that version. Instead of searching for “Apache” which will just show lots of results that don’t apply (because exploits don’t work with each and every version of a program), you’d be better off searching for “Apache 2.2” or something like that. 

**THC Hydra** – a tool that can be used to brute force logins. Tools like THC Hydra are why rate limiting is important. 

**Netcat (nc)** – a “TCP/IP Swiss Army Knife.” It has many uses, but the main way I’ve used it is for listeners for reverse shells. 

**Ettercap** – a tool for man-in-the-middle attacks.

**Sniffly2** – a tool for sniffing browser history using HSTS, which stands for HTTP Strict Transport Security. It’s a way for a web page to figure out other websites you’ve already been to.

**Hopper** – a disassembler/decompiler tool for macOS and Linux.

**Fiddler** – a tool for capturing and saving web traffic.

**dnscat/dnscat2** – sort of like netcat, but for DNS. It allows for command and control via DNS, which is weird. But that’s the entire point – people are less likely to suspect DNS traffic as being malicious. 

**Snort** – an Intrusion Detection System and Intrusion Prevention System. An alternative to Snort is Suricata.

**GNU MAC Changer** – a tool that lets you change your computer’s MAC address.

**Powershell Empire** – a post-exploitation framework for PowerShell. Once a machine is compromised, an attacker might think, “okay, now what should I do?” And that’s where a post-exploitation framework comes into play. 

**Archive sites for OSINT** – if you want to research ad adversary before doing any offensive stuff, then archive sites might have information that could help you learn more about what to do. OSINT, or open source intelligence, is an important of reconnaissance. If someone deletes something on a website or social media, it might still exist in an archive somewhere. If you google something, click the ▼ at the end of the link and click “Cached” to see an older version of it. Another archive is The Wayback Machine, which is at https://archive.org/web/.

**Creepy** – a GEOINT tool written in Python. GEOINT means geolocation intelligence. It can be used to figure out where someone is or where they’ve been, using data from social media.

**Maltego** – an OSINT tool for finding info about relationships between people.

**setoolkit** – the social-engineer toolkit. Used for phishing.

**Mimikatz** – a Windows security tool that can be used for finding passwords, hashes, and stuff related to Windows domains and authentication, such as Kerberos.

**PSExec** – a tool for remotely executing programs.

**Pass The Hash** – using a password hash to log in rather than using a password. This is a Windows-centric security issue because it involves something called NTLM hashes. This is a useful concept to learn if you want to get into penetration testing, but it’s not really useful for web security. If you want to learn about hacking a company, then you’ll have to get into Active Directory and Windows accounts/authentication stuff. 

For a list of tools and other security concepts, check out this repo:

<https://github.com/0x416c616e/securityconcepts>

Go to the previous section:

<https://github.com/0x416c616e/intro_to_security/blob/master/03_miscellaneous_security/miscellaneous_security.md>

Go to the next section:

<>
