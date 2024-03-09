<h1>Penetration Test and Report Project (web applications, Linux Servers, and Windows machines)


<h2>Description</h2>
For this project, We at District-5 ( UofT Bootcamp ) conducted a PenTest against Rekall's network infrastructure and scored all the vulnerabilities using the CVSS scoring system. We targeted their Apache web server, as well as their Windows and Linux servers. We categorized these vulnerabilities by considering both Exploitation Likelihood and Potential Impact. The purpose of this engagement was to assess the networks’ and systems’ security and identify potential security flaws by utilizing industry-accepted
testing methodology and best practices  


<h2>Utilities Used</h2>

- <b>MITRE ATT&CK: choosing proper techniques to conduct the exploit</b> 
- <b>OSINT Framework and Google: for Passive Reconnaissance</b>
- <b>Shodan.io and Recon-ng: for Active Reconnaissance</b>
- <b>Nmap and Zenmap: for scanning opened ports and services on targeted CIDR</b>
- <b>SearchSploit and Exploit-DB: for choosing the exploit</b>
- <b>Metasploit C2 Framework: for Active Reconnaissance</b>
  
<h2>Environments Used </h2>

- <b>Kali Linux and internet</b> 

<h2>Assessment Objective</h2>
The primary goal of this assessment was to analyze the security flaws present in Rekall’s
web applications, networks, and systems. This assessment was conducted to identify exploitable
vulnerabilities and provide actionable recommendations on how to remediate the vulnerabilities to
provide a greater level of security for the environment.
We used the proven vulnerability testing methodology to assess all relevant web applications,
networks, and systems in scope.
<br />
<br />
outlined objectives:
<br />
<img src="https://i.imgur.com/4nbUBI8.png" height="80%" width="80%" alt="Table 1: Defined Objectives"/>
<br />
<br />
<br />
<br />
<h2>Penetration Testing Methodology</h2>

<p align="center">
  
📜Reconnaissance: 
<br />
<br />
The internal team did assessments by checking for any passive (open source) data through leveraging OSINT platform and Google. And the Active Recon has been conducted by using tools
such as Zenmap, Shodan.io, and Recon-ng. We opted out this step since UofT Bootcamp provided us for all the necessary information- this was an example of "White Box" PenTest.
<img src="https://i.imgur.com/dCEpYeF.png" height="80%" width="80%" />
<br />
<br />
📜Identification of Vulnerabilities and Services: <br/>
<br />
Weused custom, private, and public tools such as Metasploit, hashcat, and Nmap to gain perspective
of the network security from a hacker’s point of view. These methods provide Rekall with an
understanding of the risks that threaten its information, and also the strengths and weaknesses of
the current controls protecting those systems. The results were achieved by mapping the network
architecture, identifying hosts and services, enumerating network and system-level vulnerabilities,
attempting to discover unexpected hosts within the environment, and eliminating false positives that
might have arisen from scanning.
<br />
<br />
📜Vulnerability Exploitation: <br/>
<br />
My normal process was to both manually test each identified vulnerability and use automated tools to
exploit these issues. Exploitation of a vulnerability was defined as any action we performed that gave me
unauthorized access to the system or the sensitive data.<br />
<br />
📜Reporting: <br/>
<br />
Once exploitation is completed and the assessors have completed their objectives, or have done
everything possible within the allotted time, the assessment team writes the report, which is the final
deliverable to the customer.<br />
<br />
📜Scope: <br/>
<br />
Prior to any assessment activities, Rekall and the assessment team will identify targeted systems
with a defined range or list of network IP addresses. 
In-scope and excluded IP addresses and ranges are listed below.
<br />
<br />

Prior to any assessment activities, Rekall and the assessment team will identify targeted systems
with a defined range or list of network IP addresses. The assessment team will work directly with the
Rekall POC to determine which network ranges are in-scope for the scheduled assessment.
It is Rekall’s responsibility to ensure that IP addresses identified as in-scope are actually controlled
by Rekall and are hosted in Rekall-owned facilities (i.e., are not hosted by an external organization).
In-scope and excluded IP addresses and ranges are listed below.
<br />
<br />
📜Grading Methodology: 
<br />
<br />
Each finding was classified according to its severity, reflecting the risk each such vulnerability may
pose to the business processes implemented by the application, based on the following criteria:
Critical: Immediate threat to key business processes.
<br />
- High: Indirect threat to key business processes/threat to secondary business processes.
<br />

- Medium: Indirect or partial threat to business processes.
<br />

- Low: No direct threat exists; vulnerability may be leveraged with other vulnerabilities.
<br />

- Informational: No threat; however, it is data that may be used in a future attack.
<br />
✒️As the following grid shows, each threat is assessed in terms of both its potential impact on the
business and the likelihood of exploitation:<br />
👌<img src="https://i.imgur.com/3UgBNed.png" height="80%" width="80%" />
<br />
<br />
📜Summary of Strengths: <br/>
<br />
Inspite of several vulnerabilities, I also recognized
several strengths within Rekall’s environment. These positives highlight the effective countermeasures
and defenses that successfully prevented, detected, or denied an attack technique or tactic from
occurring.
<br />
<br />

- DDOS mitigation strategy in place to improve network availability

- Some input fields in the web application were well-secured against basic XSS attacks and
required thorough testing to identify any vulnerabilities.

- Attempts to perform SQL injections on the web page were unsuccessful.

- Certain areas of the web application had basic security measures in place, which made it more
challenging to successfully execute exploits such as Local File Inclusion and, in some cases,
XSS scripting.

- A number of input fields in the web application had appropriate input validation measures in
place.

- Network architecture mapping mitigates open source data penetrations

- Penetration testing measure instituted to improve posture
<br />
<br />
📜Summary of Weaknesses: <br/>
<br />
We successfully found several critical vulnerabilities that should be immediately addressed in order to
prevent an adversary from compromising the network. These findings are not specific to a software
version but are more general and systemic vulnerabilities.
<br />
<br />

- Open ports allow for enumeration and unauthorized access : Basic nmap scans revealed several
open ports throughout Rekall’s network, which could potentially expose vulnerabilities.

- Credentials available upon investigation i.e. IP LOOKUP & Insecure storage of credentials - i.e.
HTML source code : Sensitive data was exposed on both Linux and Windows machines, making
important information easily accessible to threat actors who may have compromised the system.

- It is essential to have robust security measures in place to prevent unauthorized access to
systems. This includes implementing strong passwords and multi-factor authentication
improvements are recommended, including implementation of 2FA.

- Using Kiwi, attackers were able to retrieve several important users’ credentials and crack their
passwords.

- Open source intelligence tools can reveal information such as ‘WHOIS’ data, which adversaries
can use to scan the network further and identify vulnerabilities.

- Vulnerabilities to XSS and SQL injections found : The web application is susceptible to various
attacks, including XSS scripting, Local File Inclusion, and Command Injection. These
vulnerabilities can allow a threat actor to access sensitive data easily. Additionally, the web
application has the potential to store malicious scripts uploaded by attackers on Rekall’s servers.

- The Windows and Linux machines had several old vulnerabilities, including Shellshock, SLMail
pop3d, and Apache Tomcat Remote Code Execution.
<br />
<br />
📜Executive Summary of Findings: <br/>
<br />
District_5 was engaged to perform penetration testing for Rekall and report findings. District_5 was able
to identify several vulnerabilities which include critical vulnerabilities which have a potential to have a
negative impact on the operations and reputation of Rekall.
The penetration testing was performed in three stages, Web Applications, Linux environment and then
Microsoft environment.
During the assessment of the web applications, it was discovered that there are vulnerabilities to XSS
reflection, local file inclusion, XSS stored vulnerability, command injection and SQL injection
vulnerabilities.
<br />
<br />

- Exposed open-source data

OSINT techniques reveal open source data is exposed. Additionally, login credentials are insecure, and
stored in HTML source code. Efforts were able to discover the ‘WHOIS’ information for ‘totalrekall.xyz’
using Open Source Intelligence Tools (OSINT). This information helped us with our testing by providing
the IP Address of our target website.

- Reflected XSS Exploit (Flags 1, 2, 3, 5)

Efforts focused on finding vulnerabilities in Rekall’s web application that could be exploited. Attempting to
find any XSS vulnerabilities, resulting in the successful implementation of a reflected XSS script on the
‘Welcome’ page, which created an alert.

Next, we searched for more reflected XSS scripts that could work across different pages on
the web application. Our efforts discovered that our exploit was also successful on the ‘VR Planner’ web page.

Another XSS vulnerability was found in the ‘comments’ page/section. This vulnerability is particularly
dangerous since a malicious actor could store harmful content on the host server.

- Local File Inclusion Exploit: (Flag 6)
  
Efforts were made to find a sensitive data exposure on the ‘Login.php’ page. The page source contained
the username and password of a user with valid credentials, which allowed us to log in.

- Sensitive data exposure exploit. (Flag 8)

Testing discovered a vulnerability on the ‘networking.php’ page. The webpage contained text revealing
the existence of a ‘vendors.txt’ file that contained a list of Rekall’s top-secret networking tools. Further
investigation revealed a command injection vulnerability in the ‘DNS Check’ tool. We were able to exploit
this vulnerability to access the contents of the ‘vendors.txt’ file.

- Command injection exploit (Flag 10)
  
District_5 was able to exploit another field called ‘MX Record Checker’ located just below the ‘DNS
Check’ field. Although this field had better protections against basic attacks, it was still compromised
relatively quickly.

- Command Injection exploit (Flag 11)

Server 127.0.0.11 Address 127.0.0.11 #53 Non-authoritative answer:
www.splunk.com canonical name = splunk.com edgekey.net. www.splunk.com.edgekey.net canonical
name = e25346.a.akamaledge.net
Authoritative answers can be found from: Congrats, flag 11 is opshdkasy78s

✒️ During our day two efforts during our reconnaissance, we ran a Zenmap map scan against the target IP
address along with the subnet /24 to scan across 256 host machines. However, we found that several
hosts were excluded from our scan. To address this, we ran another Zenmap scan with the options -A to
run an aggressive scan against the target IP. Through this scan, we discovered a host machine running
Drupal located at 192.168.13.13, along with other host machines.

- Exposed open source data (insert nmap-T4-A-v 192.168.13.13) confirm IP
  
© 2022 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 10
Rekall Corp Penetration Test Report
Nessus scans were run for one of the host machines (192.168.13.12) found during our Zenmap scan and
discovered a critical vulnerability for Apache Struts.
Using Metasploit to search for vulnerabilities to exploit on the target machine (192.168.13.10), referring to
the Zenmap scan was done earlier. After testing several exploits, we discovered an ‘Apache Tomcat Remote
Code Execution Vulnerability (CVE-2017-12617) and successfully exploited it to gain a Meterpreter
session.
<br />
<br />
<h2>Summary Vulnerability Overview</h2>
<br />
<br />
<img src="https://i.imgur.com/wZjPyfZ.png" height="80%" width="80%" />
<br />
<br />
<h2>The following summary tables represent an overview of the assessment findings for this penetration
test:</h2>
<br />
<br />
<img src="https://i.imgur.com/RGGkg4R.png" height="80%" width="80%" />
<br />
<h1>Vulnerability Findings:</h1>
<br />
<br />
<h2>⬇️⬇️⬇️ Web App Vulnerabilities</h2>
<br />
<br />
<img src="https://i.imgur.com/KI9Gbnv.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/tC0njG6.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/GNZ2e5C.png" height="80%" width="80%" />
<img src="https://i.imgur.com/mMQ3EkB.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/unnDKsP.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/GL3T7GY.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/KE6LpLC.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/VOJAhSV.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/iVjI3C0.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/Yq0uv4w.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/CR6eGDe.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/hBtuhgK.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/e87RWHS.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/Rn6a0V4.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/dxGC2XQ.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/fmWpbxe.png" height="80%" width="80%" />
<br />
<br />
<h2>⬇️⬇️⬇️ Vulnerability Findings Linux OS</h2>
<br />
<br />
<img src="https://i.imgur.com/oQtOncO.png" height="80%" width="80%" />
<img src="https://i.imgur.com/egNFIdh.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/ozra6fg.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/g821eKP.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/fFtLGGa.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/ARdQ810.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/e09irRL.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/6DxDTkq.png" height="80%" width="80%" />
<img src="https://i.imgur.com/QFiNrTK.png" height="80%" width="80%" />
<img src="https://i.imgur.com/74KTMpE.png" height="80%" width="80%" />
<img src="https://i.imgur.com/TCLOeab.png" height="80%" width="80%" />
<img src="https://i.imgur.com/eMRHktX.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/uQAxNda.png" height="80%" width="80%" />
<img src="https://i.imgur.com/MVj9vRJ.png" height="80%" width="80%" />
<img src="" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/I86pyJY.png" height="80%" width="80%" />
<img src="https://i.imgur.com/cTTiTmB.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/VDrQCsM.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/XyM6bAU.png" height="80%" width="80%" />
<img src="https://i.imgur.com/6PGtulX.png" height="80%" width="80%" />
<br />
<br />
<img src="https://i.imgur.com/9Rp9bsH.png" height="80%" width="80%" />
<br />
<br />
<h2>⬇️⬇️⬇️ Vulnerability Findings Windows OS</h2>
<br />
<br />


</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
