# WiFi Tests

## Access to internal network through MAC cloning

Clone the MAC address of the AP:
```
sudo macchanger -m a4:00:4e:73:19:c4 eth0

Current MAC: 50:7b:9d:d6:f0:95 (unknown)
Permanent MAC: 50:7b:9d:d6:f0:95 (unknown)
New MAC: a4:00:4e:73:19:c4 (unknown)
```

Get IP address through DHCP:
```
┌──2024/07/04─11:28:39──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ sudo dhclient eth0
┌──2024/07/04─11:29:11──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ ifconfig eth0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
inet 10.18.224.2 netmask 255.255.255.192 broadcast 10.c.c.c
inet6 fe80::a600:4eff:fe73:19c4 prefixlen 64 scopeid 0x20<link>
ether a4:00:4e:73:19:c4 txqueuelen 1000 (Ethernet)
RX packets 127 bytes 17719 (17.3 KiB)
RX errors 0 dropped 0 overruns 0 frame 0
TX packets 51 bytes 5281 (5.1 KiB)
TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0
device interrupt 16 memory 0xf1200000-f1220000

┌──2024/07/04─11:29:24──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ ip route
default via 10.z.z.z dev eth0
10.18.224.0/26 dev eth0 proto kernel scope link src 10.z.z.z
┌──2024/07/04─11:29:33──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ cat /etc/resolv.conf
domain <domain>.net
search <domain>.net
nameserver 10.x.x.x (here you should have the primary DNS server)
nameserver 10.x.x.x (here you should have the secondary DNS server)
```

Connection to Internet:
```
┌──2024/07/04─11:30:19──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ traceroute 1.1.1.1
traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 60 byte packets
1 r10-x-x-x.<domain>.net (10.x.x.x) 0.371 ms 0.244 ms 0.211 ms
2 10.y.y.y (10.y.y.y) 0.265 ms 0.274 ms 0.211 ms
3 10.z.z.z (10.z.z.z) 8.217 ms 8.151 ms 8.084 ms
4 138.a.a.a (138.a.a.a) 9.141 ms 9.075 ms 9.619 ms
5 100.b.b.b (100.b.b.b) 11.418 ms 11.354 ms 11.290 ms
6 100.b.b.b (100.b.b.b) 11.224 ms 9.600 ms 9.759 ms
7 one.one.one.one (1.1.1.1) 8.178 ms 8.155 ms 8.165 ms
┌──2024/07/04─11:32:00──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ curl heise.de -v
* Host heise.de:80 was resolved.
* IPv6: 2a02:2e0:3fe:1001:302::
* IPv4: 193.x.x.x
* Trying 193.x.x.x:80...
* connect to 193.x.x.x port 80 from 10.y.y.y port 42166 failed: Connection refused
* Trying [2a02:2e0:3fe:1001:302::]:80...
* Immediate connect fail for 2a02:2e0:3fe:1001:302::: Network is unreachable
* Failed to connect to heise.de port 80 after 18 ms: Couldn't connect to server
* Closing connection
curl: (7) Failed to connect to heise.de port 80 after 18 ms: Couldn't connect to server
```

Connection to internal network:
```
┌──2024/07/04─11:32:58──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ dig +short bsctintra.net
10.x.x.x
10.x.x.y

┌──2024/07/04─11:34:33──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ smbclient -L 10.x.x.x
Password for [WORKGROUP\sysop]:
session setup failed: NT_STATUS_NOT_SUPPORTED
curl: (7) Failed to connect to heise.de port 80 after 18 ms: Couldn't connect to server
```

Trying to access to a SMB share:
```
┌──2024/07/04─11:35:48──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ smbclient -L 10.x.x.x -U <username>
Password for [WORKGROUP\<username>]:

Sharename Type Comment
--------- ---- -------
ADMIN$ Disk Remote Admin
C$ Disk Default share
Common Disk
D$ Disk Default share
E$ Disk Default share
IPC$ IPC Remote IPC
NETLOGON Disk Logon server share
SYSVOL Disk Logon server share

Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.x.x.x failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available.
```

## Sniffing traffic from all around antennas

First, terminate all the processes that can make issues:
```
airmon-ng check kill
```
Enable our wireless interface to work in "monitor mode":
```
airmon-ng start wlan1
```
The output should contain a string like `monitor mode enable`. In this manner, the interface `wlan1` is in monitor mode, so it will sniff the information around and cannot be intercepted because it is only receiving but not transmitting any data. Indeed, by opening Wireshark, we would see only incoming data. Useful information could be inside "beacon frames" where you can check if there are security mechanisms like OWE, 802.1e and so on. So, beacon frames could provide several information.

Now we must dump traffic in a cap file:
```
airodump-ng --band abg wlan1 --essid "Contoso-Corporate" -w <outfile>
```
The command dumps the traffic from all networks on the a, b and g bands. If you don't specify `-w` argument, it will save files by using a default name.

The first section of the running command shows the access points with "Contoso-Corporate".
The second section contains the list of clients connected to the access points. The clients are specified under the "STATION" column, while the BSSID is the MAC address of the access point). If we get some `not associated`, it means that it is a client with a wireless card that is not connected to any access point. We see that because, even if a client is not connected to anything, if it has the WiFi enabled, it still transmits data.

By the way, from the last command above, we must identify on which channels the "Contoso-Corporate" is working on. We retrieve this information from the first section. Depending on the antenna you are using to sniff, the sniffer might work on a lot of channels (just see the `CH` string on top-left side of the running command), while an access point, when active, generally is fixed on a specific channel, unless of particular events like collisions. Let's guess our  Then you can run:
```
airodump-ng --band abg wlan1 --channel 1 --essid "Contoso-Corporate" --bssid <MAC-address-access-point> -w <outfile>
```
By this command, we sniff only on the channel 1 of "Contoso-Corporate".

Now, if we want to capture for example the 4-Way Handshaking, we can now connect a client to the rogue access point. The sniffer will capture the traffic and store it in the cap file.

For further checks, you can open the cap file by Wireshark and analyse it. The first EAP calls are in cleartext and cannot be encrypted, because they are needed to exchange the certificate.

## Network segmentation verified from Guest WiFi to Corporate WiFi

```
┌──2024/07/04─12:02:47──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ ifconfig wlan0
wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
inet 10.x.x.x netmask 255.255.252.0 broadcast 10.x.x.x
inet6 fe80::4252:4839:5dce:5b14 prefixlen 64 scopeid 0x20<link>
ether 44:85:00:73:76:c5 txqueuelen 1000 (Ethernet)
RX packets 53581 bytes 68644408 (65.4 MiB)
RX errors 0 dropped 0 overruns 0 frame 0
TX packets 11695 bytes 1729846 (1.6 MiB)
TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0

┌──2024/07/04─12:02:57──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ ip route
default via 10.x.x.x dev wlan0 proto dhcp src 10.x.x.x metric 600
10.x.x.x/22 dev wlan0 proto kernel scope link src 10.x.x.x metric 600

┌──2024/07/04─12:03:03──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ cat /etc/resolv.conf
# Generated by NetworkManager
search pwlan.ch
nameserver 193.x.x.x
nameserver 193.x.x.x

┌──2024/07/04─12:06:28──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ smbclient -L 10.x.x.x -U <username>
do_connect: Connection to 10.x.x.x failed (Error NT_STATUS_IO_TIMEOUT)
An attempt has been made to spoof the IP address:
┌──2024/07/04─12:31:06──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ sudo ip route del default dev wlan0
┌──2024/07/04─12:31:20──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ sudo ip route add default via 10.y.y.y dev wlan0
┌──2024/07/04─12:31:53──(sysop@xka)-[~/Downloads/EAP_buster]
└─$ ping 10.y.y.y
PING 10.y.y.y (10.y.y.y) 56(84) bytes of data.
^C
--- 10.y.y.y ping statistics ---
8 packets transmitted, 0 received, 100% packet loss, time 7157ms
┌──2024/07/04─12:32:17──(sysop@xka)-[~/Downloads/EAP_buster]
└─$
```
In the example above, it was not possible to reach (ping) internal resources.
