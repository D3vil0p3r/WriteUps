# Basic Toolset

# OSINT activities

## WHOIS

We can consider WHOIS as the "white pages" for domain names. It is a TCP-based transaction-oriented query/response protocol listening on TCP port 43 by default. We can use it for querying databases containing domain names, IP addresses, or autonomous systems and provide information services to Internet users.

The WHOIS domain lookups allow us to retrieve information about the domain name of an already registered domain. The Internet Corporation of Assigned Names and Numbers (ICANN) requires that accredited registrars enter the holder's contact information, the domain's creation, and expiration dates, and other information in the Whois database immediately after registering a domain. In simple terms, the Whois database is a searchable list of all domains currently registered worldwide.
```
whois facebook.com
```
From the output, we have gathered the following information:

| Field | Value |
| ----- | ----- |
| Organisation | Facebook, Inc. |
| Locations | US, 94025 Menlo Park, CA, 1601 Willo Rd |
| Domain Email address | domain@fb.com |
| Registrar Email address | abusecomplaints@registrarsafe.com |
| Phone number | +1.6505434800 |
| Language | English (US) |
| Registrar | RegistrarSafe, LLC |
| New Domain | fb.com |
| DNSSEC | unsigned |
| Name servers | A.NS.FACEBOOK.COM |
|  | B.NS.FACEBOOK.COM |
|  | C.NS.FACEBOOK.COM |
|  | D.NS.FACEBOOK.COM |

## DNS

Resource record of DNS query is composed of:

| Field | Description |
| ----- | ----------- |
| Resource Record | A domain name, usually a fully qualified domain name, is the first part of a Resource Record. If you don't use a fully qualified domain name, the zone's name where the record is located will be appended to the end of the name. |
| TTL | In seconds, the Time-To-Live (TTL) defaults to the minimum value specified in the SOA record. |
| Record Class | Internet, Hesiod, or Chaos |
| Start Of Authority (SOA) | It should be first in a zone file because it indicates the start of a zone. Each zone can only have one SOA record, and additionally, it contains the zone's values, such as a serial number and multiple expiration timeouts. |
| Name Servers (NS) | The distributed database is bound together by NS Records. They are in charge of a zone's authoritative name server and the authority for a child zone to a name server. |
| IPv4 Addresses (A) | The A record is only a mapping between a hostname and an IP address. 'Forward' zones are those with A records. |
| Pointer (PTR) | The PTR record is a mapping between an IP address and a hostname. 'Reverse' zones are those that have PTR records. |
| Canonical Name (CNAME) | An alias hostname is mapped to an A record hostname using the CNAME record. |
| Mail Exchange (MX) | The MX record identifies a host that will accept emails for a specific host. A priority value has been assigned to the specified host. Multiple MX records can exist on the same host, and a prioritized list is made consisting of the records for a specific host. |

We will use `nslookup` and `DIG` tools.

Let us assume that a customer requested us to perform an external penetration test. Therefore, we first need to familiarize ourselves with their infrastructure and identify which hosts are publicly accessible. We can find this out using different types of DNS requests. With Nslookup, we can search for domain name servers on the Internet and ask them for information about hosts and domains. Although the tool has two modes, interactive and non-interactive, we will mainly focus on the non-interactive module.

Note: on `dig` we must look for the `;; ANSWER SECTION` in the output for identifying the information we asked.

### Querying: A Records
```
nslookup facebook.com

    Server:		1.1.1.1
    Address:	1.1.1.1#53

    Non-authoritative answer:
    Name:	facebook.com
    Address: 31.13.92.36
    Name:	facebook.com
    Address: 2a03:2880:f11c:8083:face:b00c:0:25de
```
We can also specify a nameserver if needed by adding `@<nameserver/IP>` to the command. Unlike nslookup, DIG shows us some more information that can be of importance.
```
dig facebook.com @1.1.1.1

    ; <<>> DiG 9.16.1-Ubuntu <<>> facebook.com @1.1.1.1
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58899
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 1232
    ;; QUESTION SECTION:
    ;facebook.com.                  IN      A

    ;; ANSWER SECTION:
    facebook.com.           169     IN      A       31.13.92.36

    ;; Query time: 20 msec
    ;; SERVER: 1.1.1.1#53(1.1.1.1)
    ;; WHEN: Mo Okt 18 16:03:17 CEST 2021
    ;; MSG SIZE  rcvd: 57
```
The entry starts with the complete domain name, including the final dot. The entry may be held in the cache for 169 seconds before the information must be requested again. The class 1.1.1.1 is understandably the Internet (IN). I can also use @8.8.8.8 (Google DNS server).

### Querying: A Records for a subdomain
```
nslookup -query=A www.facebook.com

    Server:		1.1.1.1
    Address:	1.1.1.1#53

    Non-authoritative answer:
    www.facebook.com	canonical name = star-mini.c10r.facebook.com.
    Name:	star-mini.c10r.facebook.com
    Address: 31.13.92.36
```
or
```
dig a www.facebook.com @1.1.1.1

    ; <<>> DiG 9.16.1-Ubuntu <<>> a www.facebook.com @1.1.1.1
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15596
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 1232
    ;; QUESTION SECTION:
    ;www.facebook.com.              IN      A

    ;; ANSWER SECTION:
    www.facebook.com.       3585    IN      CNAME   star-mini.c10r.facebook.com.
    star-mini.c10r.facebook.com. 45 IN      A       31.13.92.36

    ;; Query time: 16 msec
    ;; SERVER: 1.1.1.1#53(1.1.1.1)
    ;; WHEN: Mo Okt 18 16:11:48 CEST 2021
    ;; MSG SIZE  rcvd: 90
```
### Querying: PTR Records for an IP Address
```
nslookup -query=PTR 31.13.92.36

    Server:		1.1.1.1
    Address:	1.1.1.1#53

    Non-authoritative answer:
    36.92.13.31.in-addr.arpa	name = edge-star-mini-shv-01-frt3.facebook.com.

    Authoritative answers can be found from:
```
or
```
dig -x 31.13.92.36 @1.1.1.1

    ; <<>> DiG 9.16.1-Ubuntu <<>> -x 31.13.92.36 @1.1.1.1
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51730
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 1232
    ;; QUESTION SECTION:
    ;36.92.13.31.in-addr.arpa.      IN      PTR

    ;; ANSWER SECTION:
    36.92.13.31.in-addr.arpa. 1028  IN      PTR     edge-star-mini-shv-01-frt3.facebook.com.

    ;; Query time: 16 msec
    ;; SERVER: 1.1.1.1#53(1.1.1.1)
    ;; WHEN: Mo Okt 18 16:14:20 CEST 2021
    ;; MSG SIZE  rcvd: 106
```
### Querying: ANY Existing Records
```
nslookup -query=ANY google.com

    Server:		10.100.0.1
    Address:	10.100.0.1#53

    Non-authoritative answer:
    Name:	google.com
    Address: 172.217.16.142
    Name:	google.com
    Address: 2a00:1450:4001:808::200e
    google.com	text = "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
    google.com	text = "docusign=1b0a6754-49b1-4db5-8540-d2c12664b289"
    google.com	text = "v=spf1 include:_spf.google.com ~all"
    google.com	text = "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB"
    google.com	text = "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8="
    google.com	text = "apple-domain-verification=30afIBcvSuDV2PLX"
    google.com	text = "google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o"
    google.com	text = "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"
    google.com	text = "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ"
    google.com	nameserver = ns3.google.com.
    google.com	nameserver = ns2.google.com.
    google.com	nameserver = ns1.google.com.
    google.com	nameserver = ns4.google.com.
    google.com	mail exchanger = 10 aspmx.l.google.com.
    google.com	mail exchanger = 40 alt3.aspmx.l.google.com.
    google.com	mail exchanger = 20 alt1.aspmx.l.google.com.
    google.com	mail exchanger = 30 alt2.aspmx.l.google.com.
    google.com	mail exchanger = 50 alt4.aspmx.l.google.com.
    google.com
    	origin = ns1.google.com
    	mail addr = dns-admin.google.com
    	serial = 398195569
    	refresh = 900
    	retry = 900
    	expire = 1800
    	minimum = 60
    google.com	rdata_257 = 0 issue "pki.goog"

    Authoritative answers can be found from:
```
or
```
dig any google.com @8.8.8.8

    ; <<>> DiG 9.16.1-Ubuntu <<>> any google.com @8.8.8.8
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49154
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 22, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 512
    ;; QUESTION SECTION:
    ;google.com.                    IN      ANY

    ;; ANSWER SECTION:
    google.com.             249     IN      A       142.250.184.206
    google.com.             249     IN      AAAA    2a00:1450:4001:830::200e
    google.com.             549     IN      MX      10 aspmx.l.google.com.
    google.com.             3549    IN      TXT     "apple-domain-verification=30afIBcvSuDV2PLX"
    google.com.             3549    IN      TXT     "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"
    google.com.             549     IN      MX      20 alt1.aspmx.l.google.com.
    google.com.             3549    IN      TXT     "docusign=1b0a6754-49b1-4db5-8540-d2c12664b289"
    google.com.             3549    IN      TXT     "v=spf1 include:_spf.google.com ~all"
    google.com.             3549    IN      TXT     "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8="
    google.com.             3549    IN      TXT     "google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o"
    google.com.             9       IN      SOA     ns1.google.com. dns-admin.google.com. 403730046 900 900 1800 60
    google.com.             21549   IN      NS      ns1.google.com.
    google.com.             21549   IN      NS      ns3.google.com.
    google.com.             549     IN      MX      50 alt4.aspmx.l.google.com.
    google.com.             3549    IN      TXT     "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
    google.com.             549     IN      MX      30 alt2.aspmx.l.google.com.
    google.com.             21549   IN      NS      ns2.google.com.
    google.com.             21549   IN      NS      ns4.google.com.
    google.com.             549     IN      MX      40 alt3.aspmx.l.google.com.
    google.com.             3549    IN      TXT     "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB"
    google.com.             3549    IN      TXT     "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ"
    google.com.             21549   IN      CAA     0 issue "pki.goog"

    ;; Query time: 16 msec
    ;; SERVER: 8.8.8.8#53(8.8.8.8)
    ;; WHEN: Mo Okt 18 16:15:22 CEST 2021
    ;; MSG SIZE  rcvd: 922
```
The more recent [RFC8482](https://tools.ietf.org/html/rfc8482) specified that ANY DNS requests be abolished. Therefore, we may not receive a response to our ANY request from the DNS server or get a reference to the said RFC8482.
```
dig any cloudflare.com @8.8.8.8

    ; <<>> DiG 9.16.1-Ubuntu <<>> any cloudflare.com @8.8.8.8
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 22509
    ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 512
    ;; QUESTION SECTION:
    ;cloudflare.com.                        IN      ANY

    ;; ANSWER SECTION:
    cloudflare.com.         2747    IN      HINFO   "RFC8482" ""
    cloudflare.com.         2747    IN      RRSIG   HINFO 13 2 3789 20211019145905 20211017125905 34505 cloudflare.com. 4/  Bq8xUN96SrOhuH0bj2W6s2pXRdv5L5NWsgyTAGLAjEwwEF4y4TQuXo yGtvD3B13jr5KhdXo1VtrLLMy4OR8Q==

    ;; Query time: 16 msec
    ;; SERVER: 8.8.8.8#53(8.8.8.8)
    ;; WHEN: Mo Okt 18 16:16:27 CEST 2021
    ;; MSG SIZE  rcvd: 174

Tip: in case query ANY returns few information, don't use @1.1.1.1 but try @8.8.8.8 or another DNS server (maybe of the company itself).
```
### Querying: TXT Records
```
nslookup -query=TXT facebook.com

    Server:		1.1.1.1
    Address:	1.1.1.1#53

    Non-authoritative answer:
    facebook.com	text = "v=spf1 redirect=_spf.facebook.com"
    facebook.com	text = "google-site-verification=A2WZWCNQHrGV_TWwKh6KHY90tY0SHZo_RnyMJoDaG0s"
    facebook.com	text = "google-site-verification=wdH5DTJTc9AYNwVunSVFeK0hYDGUIEOGb-RReU6pJlY"

    Authoritative answers can be found from:
```
or
```
dig txt facebook.com @1.1.1.1

    ; <<>> DiG 9.16.1-Ubuntu <<>> txt facebook.com @1.1.1.1
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63771
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 1232
    ;; QUESTION SECTION:
    ;facebook.com.                  IN      TXT

    ;; ANSWER SECTION:
    facebook.com.           86400   IN      TXT     "v=spf1 redirect=_spf.facebook.com"
    facebook.com.           7200    IN      TXT     "google-site-verification=A2WZWCNQHrGV_TWwKh6KHY90tY0SHZo_RnyMJoDaG0s"
    facebook.com.           7200    IN      TXT     "google-site-verification=wdH5DTJTc9AYNwVunSVFeK0hYDGUIEOGb-RReU6pJlY"

    ;; Query time: 24 msec
    ;; SERVER: 1.1.1.1#53(1.1.1.1)
    ;; WHEN: Mo Okt 18 16:17:46 CEST 2021
    ;; MSG SIZE  rcvd: 249
```
Tip: if I want to search for all possible TXT records in the environment I'm analyzing, I can get all the content from the DNS server and query TXT for each A record I get. For example:
```
dig axfr inlanefreight.htb @10.129.42.195

    ; <<>> DiG 9.16.15-Debian <<>> axfr inlanefreight.htb @10.129.42.195
    ;; global options: +cmd
    inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
    inlanefreight.htb.	604800	IN	NS	ns.inlanefreight.htb.
    admin.inlanefreight.htb. 604800	IN	A	10.10.34.2
    ftp.admin.inlanefreight.htb. 604800 IN	A	10.10.34.2
    careers.inlanefreight.htb. 604800 IN	A	10.10.34.50
    dc1.inlanefreight.htb.	604800	IN	A	10.10.34.16
    dc2.inlanefreight.htb.	604800	IN	A	10.10.34.11
    internal.inlanefreight.htb. 604800 IN	A	127.0.0.1
    admin.internal.inlanefreight.htb. 604800 IN A	10.10.1.11
    <SNIP>
```
or
```
dig txt admin.inlanefreight.htb @10.129.42.195

    No answer returned.
```
or
```
dig txt internal.inlanefreight.htb @10.129.42.195

    <SNIP>
    ;; ANSWER SECTION:
    internal.inlanefreight.htb. 604800 IN	TXT	"ZONE_TRANSFER{87o2z3cno7zsoiedznxoi82z3o47xzhoi}"
    <SNIP>
```
Note: as DNS server to query I used `@10.129.42.195` because in this exercise the servers are internal in a company, so I don't expect the Google DNS server or other public DNS server contain the DNS information about this company resource.

### Querying: MX Records
```
nslookup -query=MX facebook.com

    Server:		1.1.1.1
    Address:	1.1.1.1#53

    Non-authoritative answer:
    facebook.com	mail exchanger = 10 smtpin.vvv.facebook.com.

    Authoritative answers can be found from:
```
or
```
dig mx facebook.com @1.1.1.1

    ; <<>> DiG 9.16.1-Ubuntu <<>> mx facebook.com @1.1.1.1
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9392
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 1232
    ;; QUESTION SECTION:
    ;facebook.com.                  IN      MX

    ;; ANSWER SECTION:
    facebook.com.           3600    IN      MX      10 smtpin.vvv.facebook.com.

    ;; Query time: 40 msec
    ;; SERVER: 1.1.1.1#53(1.1.1.1)
    ;; WHEN: Mo Okt 18 16:18:22 CEST 2021
    ;; MSG SIZE  rcvd: 68
```
### IP Addresses ownership

So far, we have gathered A, NS, MX, and CNAME records with the nslookup and dig commands. Organizations are given IP addresses on the Internet, but they aren't always their owners. They might rely on ISPs and hosting provides that lease smaller netblocks to them.

We can combine some of the results gathered via nslookup with the whois database to determine if our target organization uses hosting providers. This combination looks like the following example:
```
nslookup facebook.com

    Server:		1.1.1.1
    Address:	1.1.1.1#53

    Non-authoritative answer:
    Name:	facebook.com
    Address: 157.240.199.35
    Name:	facebook.com
    Address: 2a03:2880:f15e:83:face:b00c:0:25de
```
then
```
whois 157.240.199.35

    NetRange:       157.240.0.0 - 157.240.255.255
    CIDR:           157.240.0.0/16
    NetName:        THEFA-3
    NetHandle:      NET-157-240-0-0-1
    Parent:         NET157 (NET-157-0-0-0-0)
    NetType:        Direct Assignment
    OriginAS:
    Organization:   Facebook, Inc. (THEFA-3)
    RegDate:        2015-05-14
    Updated:        2015-05-14
    Ref:            https://rdap.arin.net/registry/ip/157.240.0.0



    OrgName:        Facebook, Inc.
    OrgId:          THEFA-3
    Address:        1601 Willow Rd.
    City:           Menlo Park
    StateProv:      CA
    PostalCode:     94025
    Country:        US
    RegDate:        2004-08-11
    Updated:        2012-04-17
    Ref:            https://rdap.arin.net/registry/entity/THEFA-3


    OrgAbuseHandle: OPERA82-ARIN
    OrgAbuseName:   Operations
    OrgAbusePhone:  +1-650-543-4800
    OrgAbuseEmail:  domain@facebook.com
    OrgAbuseRef:    https://rdap.arin.net/registry/entity/OPERA82-ARIN

    OrgTechHandle: OPERA82-ARIN
    OrgTechName:   Operations
    OrgTechPhone:  +1-650-543-4800
    OrgTechEmail:  domain@facebook.com
    OrgTechRef:    https://rdap.arin.net/registry/entity/OPERA82-ARIN
```
It proves that 157.240.199.35 IP address belongs to Facebook company. 

### Notes

In case we are testing an internal network, and we try to get the nameservers of a domain (i.e., `inlanefreight.htb` associated to `10.129.42.195` IP address on `/etc/hosts`), we can get an error like this:
```
nslookup -type=NS inlanefreight.htb
    Server:		1.1.1.1
    Address:	1.1.1.1#53

    ** server can't find inlanefreight.htb: NXDOMAIN
```
instead, using `dig ns inlanefreight.htb` can return the NS field with no values.

It happens because the DNS server we are contacting (`1.1.1.1` or also `8.8.8.8`) does not contain NS information (mostly because our server is internal). For finding useful information, instead of `1.1.1.1`, we can try to contact the IP address containing this information, that could be also the IP address of the domain, so we can retrieve NS information by using:
```
dig ns inlanefreight.htb @10.129.42.195
```
If we want to use `nslookup` tool for this purpose, we must insert `10.129.42.195` at the end of the command (or edit `/etc/resolv.conf` file).


## Passive Subdomain Enumeration

It increases our attack surface and may uncover hidden management backend panels or intranet web applications that network administrators expected to keep hidden using the "security by obscurity" strategy. At this point, we will only perform passive subdomain enumeration using third-party services or publicly available information. Still, we will expand the information we gather in future active subdomain enumeration activities.

### VirusTotal

VirusTotal maintains its DNS replication service, which is developed by preserving DNS resolutions made when users visit URLs given by them. To receive information about a domain, type the domain name into the search bar and click on the "Relations" tab. Then, search for "Subdomains" section and you can look the subdomains.

### Project Sonar

Rapid7's Project Sonar is a security research project that conducts internet-wide surveys across various services and protocols to gather insight into worldwide vulnerability exposure. The information collected is made public to facilitate security research. We can use this project to discover subdomains and other domains used by our target organization by visiting the URL https://sonar.omnisint.io or using the curl command. Currently, by using cURL, we can reach the following API endpoints according to the documentation:

| API | Description |
| --- | ----------- |
| https://sonar.omnisint.io/subdomains/{domain} | All subdomains for a given domain |
| https://sonar.omnisint.io/tlds/{domain} | All tlds found for a given domain |
| https://sonar.omnisint.io/all/{domain}  | All results across all tlds for a given domain |
| https://sonar.omnisint.io/reverse/{ip} | Reverse DNS lookup on IP address |
| https://sonar.omnisint.io/reverse/{ip}/{mask} | Reverse DNS lookup of a CIDR range |

Some example queries we can use are:
* Find all subdomains
  ```
  curl -s https://sonar.omnisint.io/subdomains/facebook.com | jq -r '.[]' | sort -u
  ```
* Find other TLDs
  ```
  curl -s https://sonar.omnisint.io/tlds/facebook.com | jq -r '.[]' | sort -u
  ```
* Find Results Across all TLDs
  ```
  curl -s https://sonar.omnisint.io/all/facebook.com | jq -r '.[]' | sort -u`
  ```

We can pipe the output from these commands to a file for later processing. For example:
```
curl -s https://sonar.omnisint.io/subdomains/facebook.com | jq -r '.[]' | sort -u > "facebook.com_omnisint.txt"
```
This will create the file facebook.com_omnisint.txt containing the results. Then, we go to look for the first 20 rows of the output file:
```
head -n20 facebook.com_omnisint.txt
```
We can learn our target organization naming patterns from the results. These patterns will be handy for further discovery activities. Some examples we can observe are:
```
atlas-pp-shv-{NUMBER}-sin6.facebook.com

    atlas-pp-shv-01-sin6.facebook.com
    atlas-pp-shv-02-sin6.facebook.com
    atlas-pp-shv-03-sin6.facebook.com
```
### Certificates

Another interesting source of information we can use to extract subdomains is SSL/TLS certificates. The main reason is Certificate Transparency (CT), a project that requires every SSL/TLS certificate issued by a Certificate Authority (CA) to be published in a publicly accessible log.

We will learn how to examine CT logs to discover additional domain names and subdomains for a target organization using two primary resources:

* https://censys.io
* https://crt.sh

We can navigate to https://search.censys.io/certificates or https://crt.sh and introduce the domain name of our target organization to start discovering new subdomains.

Although the website is excellent, we would like to have this information organized and be able to combine it with other sources found throughout the information-gathering process. Let us perform a curl request to the target website asking for a JSON output as this is more manageable for us to process. We can do this via the following commands:
```
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "facebook.com_crt.sh.txt"
```
We also can manually perform this operation against a target using OpenSSL via:
```
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "facebook.com:443" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
```

### Automating Passive Subdomain Enumeration (TheHarvester)

TheHarvester is a simple-to-use yet powerful and effective tool for early-stage penetration testing and red team engagements. We can use it to gather information to help identify a company's attack surface. The tool collects emails, names, subdomains, IP addresses, and URLs from various public data sources for passive information gathering. For now, we will use the following modules:

| Module | Description |
| ------ | ----------- |
| [Baidu](http://www.baidu.com/) | Baidu search engine. |
| Bufferoverun | Uses data from Rapid7's Project Sonar - www.rapid7.com/research/project-sonar/ |
| [Crtsh](https://crt.sh/) | Comodo Certificate search. |
| [Hackertarget](https://hackertarget.com/) | Online vulnerability scanners and network intelligence to help organizations. |
| Otx | AlienVault Open Threat Exchange - https://otx.alienvault.com |
| [Rapiddns](https://rapiddns.io/) | DNS query tool, which makes querying subdomains or sites using the same IP easy. |
| Sublist3r | Fast subdomains enumeration tool for penetration testers - https://api.sublist3r.com/search.php?domain=example.com |
| [Threatcrowd](http://www.threatcrowd.org/) | Open source threat intelligence. |
| [Threatminer](https://www.threatminer.org/) | Data mining for threat intelligence. |
| Trello | Search Trello boards (Uses Google search) |
| [Urlscan](https://urlscan.io/) | A sandbox for the web that is a URL and website scanner. |
| Vhost | Bing virtual hosts search. |
| [Virustotal](https://www.virustotal.com/gui/home/search) | Domain search. |
| [Zoomeye](https://www.zoomeye.org/) | A Chinese version of Shodan. |

To automate this, we will create a file called sources.txt with the following contents. Some of the OSINT services need API to work.
```
cat sources.txt

baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
shodan
fullhunt
securityTrails
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

Once the file is created, we will execute the following commands to gather information from these sources:
```
cat sources.txt | while read source; do theHarvester -d "${domain}" -b ${source} -f ~/${source}_${domain};done
```
Note: since `~/` is not recognized in Python if not expanded, it cannot work inside `" "`, so if you use `~/`, don't use it inside `" "`.

For SOCKS5 proxy, edit the `proxies.yaml` file and add `socks5` protocol like:
```
socks:
    - 127.0.0.1:9150

http:
    - ip:port
```
(I can use http proxy for Burp, 127.0.0.1:8080) otherwise, it can omit some results if I am using TOR network.

(Update: using proxies.yaml does not work... use torsocks without -p argument pls)

Note: -p argument is used for using the proxies specified inside proxies.yaml file.

If you want to check all the sources:
```
theHarvester -d "${domain}" -b all -f ~/theHarvester/${domain}
```
When the process finishes, we can extract all the subdomains found and sort them via the following command:
```
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${domain}_theHarvester.txt"
```
Now we can merge all the passive reconnaissance files via:
```
cat ${domain}_*.txt | sort -u > ${domain}_subdomains_passive.txt
```
and
```
cat ${domain}_subdomains_passive.txt | wc -l

    11947
```
So far, we have managed to find 11947 subdomains merging the passive reconnaissance result files. It is important to note here that there are many more methods to find subdomains passively. There are more possibilities in the OSINT: Corporate Recon module of HTB.

### Sublist3r

Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster and ReverseDNS:
```
python sublist3r.py -d example.com
```
Look https://github.com/aboul3la/Sublist3r#examples for other usage examples.

## Passive Infrastructure Identification

### Netcraft

Netcraft can offer us information about the servers without even interacting with them, and this is something valuable from a passive information gathering point of view. We can use the service by visiting https://sitereport.netcraft.com and entering the target domain.

Some interesting details we can observe from the report are:

| Section | Description |
| ------- | ----------- |
| Background | General information about the domain, including the date it was first seen by Netcraft crawlers. |
| Network | Information about the netblock owner, hosting company, nameservers, etc. |
| Hosting history | Latest IPs used, webserver, and target OS. |

We need to pay special attention to the latest IPs used. Sometimes we can spot the actual IP address from the webserver before it was placed behind a load balancer, web application firewall, or IDS, allowing us to connect directly to it if the configuration allows it. This kind of technology could interfere with or alter our future testing activities.

### Wayback Machine

We can access several versions of websites using the [Wayback Machine](http://web.archive.org/) to find old versions that may have interesting comments in the source code or files that should not be there. This tool can be used to find older versions of a website at a point in time. Let's take a website running WordPress, for example. We may not find anything interesting while assessing it using manual methods and automated tools, so we search for it using Wayback Machine and find a version that utilizes a specific (now vulnerable) plugin. Heading back to the current version of the site, we find that the plugin was not removed properly and can still be accessed via the wp-content directory. We can then utilize it to gain remote code execution on the host and a nice bounty.

For example, we can check one of the first versions of facebook.com captured on December 1, 2005, which is interesting, perhaps gives us a sense of nostalgia but is also extremely useful for us as security researchers.

We can also use the tool [waybackurls](https://github.com/tomnomnom/waybackurls) to inspect URLs saved by Wayback Machine and look for specific keywords. Provided we have Go set up correctly on our host, we can install the tool as follows:
```
go get github.com/tomnomnom/waybackurls
```
To get a list of crawled URLs from a domain with the date it was obtained, we can add the `-dates` switch to our command as follows:
```
waybackurls -dates https://facebook.com > waybackurls.txt
```
Wayback Machine can be a handy tool and should not be overlooked. It can very likely lead to us discovering forgotten assets, pages, etc., which can lead to discovering a flaw.

# Active Information Gathering

## Active Infrastructure Identification

If we discover the webserver behind the target application, it can give us a good idea of what operating system is running on the back-end server. For example, if we find out the IIS version running, we can infer the Windows OS version in use by mapping the IIS version back to the Windows version that it comes installed on by default. Some default installations are:

* IIS 6.0: Windows Server 2003
* IIS 7.0-8.5: Windows Server 2008 / Windows Server 2008R2
* IIS 10.0 (v1607-v1709): Windows Server 2016
* IIS 10.0 (v1809-): Windows Server 2019

We need to discover as much information as possible from the webserver to understand its functionality, which can affect future testing. For example, URL rewriting functionality, load balancing, script engines used on the server, or an Intrusion detection system (IDS) in place may impede some of our testing activities.

The first thing we can do to identify the webserver version is to look at the response headers.

### HTTP Headers
```
curl -I "http://${TARGET}"

    HTTP/1.1 200 OK
    Date: Thu, 23 Sep 2021 15:10:42 GMT
    Server: Apache/2.4.25 (Debian)
    X-Powered-By: PHP/7.3.5
    Link: <http://192.168.10.10/wp-json/>; rel="https://api.w.org/"
    Content-Type: text/html; charset=UTF-8
```
There are also other characteristics to take into account while fingerprinting web servers in the response headers. These are:

* X-Powered-By header: This header can tell us what the web app is using. We can see values like PHP, ASP.NET, JSP, etc.
* Cookies: Cookies are another attractive value to look at as each technology by default has its cookies. Some of the default cookie values are:
   * .NET: ASPSESSIONID`<RANDOM>=<COOKIE_VALUE>`
   * PHP: PHPSESSID=`<COOKIE_VALUE>`
   * JAVA: JSESSION=`<COOKIE_VALUE>`
```
curl -I http://${TARGET}

    HTTP/1.1 200 OK
    Host: randomtarget.com
    Date: Thu, 23 Sep 2021 15:12:21 GMT
    Connection: close
    X-Powered-By: PHP/7.4.21
    Set-Cookie: PHPSESSID=gt02b1pqla35cvmmb2bcli96ml; path=/ 
    Expires: Thu, 19 Nov 1981 08:52:00 GMT
    Cache-Control: no-store, no-cache, must-revalidate
    Pragma: no-cache
    Content-type: text/html; charset=UTF-8
```
Other available tools analyze common web server characteristics by probing them and comparing their responses with a database of signatures to guess information like web server version, installed modules, and enabled services. Some of these tools are:

### Whatweb

Whatweb recognizes web technologies, including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. We recommend reading the whatweb help menu via whatweb `-h` to understand the available options, like the aggression level controls or verbose output. In this case, we will use an aggression level of 3 via the `-a` flag and verbose output via `-v`:
```
whatweb -a <LEVEL> https://www.facebook.com -v
```
We also would want to install Wappalyzer as a browser extension. It has similar functionality to Whatweb, but the results are displayed while navigating the target URL.

### WafW00f

WafW00f is a web application firewall (WAF) fingerprinting tool that sends requests and analyses responses to determine if a security solution is in place.

We can use options like `-a` to check all possible WAFs in place instead of stopping scanning at the first match, read targets from an input file via the `-i` flag, or proxy the requests using the `-p` option:
```
wafw00f -v https://www.tesla.com

                        ~ WAFW00F : v2.1.0 ~
        The Web Application Firewall Fingerprinting Toolkit

    [*] Checking https://www.tesla.com
    [+] The site https://www.tesla.com is behind CacheWall (Varnish) WAF.
    [~] Number of requests: 2
```
### Aquatone

Aquatone is a tool for automatic and visual inspection of websites across many hosts and is convenient for quickly gaining an overview of HTTP-based attack surfaces by scanning a list of configurable ports, visiting the website with a headless Chrome browser, and taking and screenshot. This is helpful, especially when dealing with huge subdomain lists.

Use `cat` in our subdomain list and pipe the command to `aquatone` via:
```
cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000

    aquatone v1.7.0 started at 2021-10-06T10:14:42+01:00

    Targets    : 30
    Threads    : 2
    Ports      : 80, 443, 8000, 8080, 8443
    Output dir : aquatone

    edge-star-shv-01-cdg2.facebook.com: port 80 open
    edge-extern-shv-01-waw1.facebook.com: port 80 open
    whatsapp-chatd-edge-shv-01-ams4.facebook.com: port 80 open
    edge-secure-shv-01-ham3.facebook.com: port 80 open
    sv-se.facebook.com: port 80 open
    ko.facebook.com: port 80 open
    whatsapp-chatd-msgr-mini-edge-shv-01-lis1.facebook.com: port 80 open
    synthetic-e2e-elbprod-sli-shv-01-otp1.facebook.com: port 80 open
    edge-star-shv-01-cdg2.facebook.com: port 443 open
    edge-extern-shv-01-waw1.facebook.com: port 443 open
    whatsapp-chatd-edge-shv-01-ams4.facebook.com: port 443 open
    http://edge-star-shv-01-cdg2.facebook.com/: 200 OK
    http://edge-extern-shv-01-waw1.facebook.com/: 200 OK
    edge-secure-shv-01-ham3.facebook.com: port 443 open
    ondemand-edge-shv-01-cph2.facebook.com: port 443 open
    sv-se.facebook.com: port 443 open
    http://edge-secure-shv-01-ham3.facebook.com/: 200 OK
    ko.facebook.com: port 443 open
    whatsapp-chatd-msgr-mini-edge-shv-01-lis1.facebook.com: port 443 open
    http://sv-se.facebook.com/: 200 OK
    http://ko.facebook.com/: 200 OK
    synthetic-e2e-elbprod-sli-shv-01-otp1.facebook.com: port 443 open
    http://synthetic-e2e-elbprod-sli-shv-01-otp1.facebook.com/: 400 default_vip_400
    https://edge-star-shv-01-cdg2.facebook.com/: 200 OK
    https://edge-extern-shv-01-waw1.facebook.com/: 200 OK
    http://edge-star-shv-01-cdg2.facebook.com/: screenshot timed out
    http://edge-extern-shv-01-waw1.facebook.com/: screenshot timed out
    https://edge-secure-shv-01-ham3.facebook.com/: 200 OK
    https://sv-se.facebook.com/: 200 OK
    https://ko.facebook.com/: 200 OK
    http://edge-secure-shv-01-ham3.facebook.com/: screenshot timed out
    http://sv-se.facebook.com/: screenshot timed out
    http://ko.facebook.com/: screenshot timed out
    https://synthetic-e2e-elbprod-sli-shv-01-otp1.facebook.com/: 400 default_vip_400
    http://synthetic-e2e-elbprod-sli-shv-01-otp1.facebook.com/: screenshot successful
    https://edge-star-shv-01-cdg2.facebook.com/: screenshot timed out
    https://edge-extern-shv-01-waw1.facebook.com/: screenshot timed out
    https://edge-secure-shv-01-ham3.facebook.com/: screenshot timed out
    https://sv-se.facebook.com/: screenshot timed out
    https://ko.facebook.com/: screenshot timed out
    https://synthetic-e2e-elbprod-sli-shv-01-otp1.facebook.com/: screenshot successful
    Calculating page structures... done
    Clustering similar pages... done
    Generating HTML report... done

    Writing session file...Time:
     - Started at  : 2021-10-06T10:14:42+01:00
     - Finished at : 2021-10-06T10:15:01+01:00
     - Duration    : 19s

    Requests:
     - Successful : 12
     - Failed     : 5

     - 2xx : 10
     - 3xx : 0
     - 4xx : 2
     - 5xx : 0

    Screenshots:
     - Successful : 2
     - Failed     : 10

    Wrote HTML report to: aquatone/aquatone_report.html
```
When it finishes, we will have a file called `aquatone_report.html` where we can see screenshots, technologies identified, server response headers, and HTML.

## Active Subdomain Enumeration

We can perform active subdomain enumeration probing the infrastructure managed by the target organization or the 3rd party DNS servers we have previously identified. In this case, the amount of traffic generated can lead to the detection of our reconnaissance activities.

The zone transfer is how a secondary DNS server receives information from the primary DNS server and updates it. The master-slave approach is used to organize DNS servers within a domain, with the slaves receiving updated DNS information from the master DNS. The master DNS server should be configured to enable zone transfers from secondary (slave) DNS servers, although this might be misconfigured.

DNS Zone transfer is the process where a DNS server passes a copy of part of it's database (which is called a "zone") to another DNS server. It's how you can have more than one DNS server able to answer queries about a particular zone; there is a Primary DNS server, and one or more Secondary DNS servers, and the secondaries ask the primary for a copy of the records for that zone. A basic DNS Zone Transfer Attack isn't very fancy: you just pretend to be a secondary (slave) DNS server and ask the primary for a copy of the zone records. And it sends you them; DNS is one of those really old-school Internet protocols that was designed when everyone on the Internet literally knew everyone else's name and address, and so servers trusted each other implicitly.

For example, we will use the https://hackertarget.com/zone-transfer/ service and the `zonetransfer.me` domain to have an idea of the information that can be obtained via this technique.

### nslookup and dig

We can also use a manual approach by executing the following set of commands, where for first we identify the nameservers:
```
nslookup -type=NS zonetransfer.me

    Server:		10.100.0.1
    Address:	10.100.0.1#53

    Non-authoritative answer:
    zonetransfer.me	nameserver = nsztm2.digi.ninja.
    zonetransfer.me	nameserver = nsztm1.digi.ninja.
```
and then we perform a Zone Transfer using `-type=any` and `-query=AXFR` parameters:
```
nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja
```
or use:
```
dig axfr @nsztm1.digi.ninja zonetransfer.me
```
If we manage to perform a successful zone transfer for a domain, there is no need to continue enumerating this particular domain as this will extract all the available information.

From the security point of view, it's worth stopping zone transfer attacks, as a copy of your DNS zone may reveal a lot of topological information about your internal network. In particular, if someone plans to subvert your DNS, by poisoning or spoofing it, for example, they'll find having a copy of the real data very useful. The zone transfer may reveal network elements that are accessible from the Internet, but that a search engine like Google (site:.target.) does not pick up. So best practice is to restrict Zone transfers. At the bare minimum, you tell the primary what the IP addresses of the secondaries are and not to transfer to anyone else. In more sophisticated set-ups, you sign the transfers. So the more sophisticated zone transfer attacks try and get round these controls. An interesting fact about DNS zone transfers is that they usually rely on TCP port 53 instead of UDP port 53. If you see TCP port 53 in use, it could tell you that someone is doing a zone transfer.

Useful information: http://www.digininja.org/projects/zonetransferme.php

### Gobuster DNS

Gobuster is a tool that we can use to perform subdomain enumeration. It is especially interesting for us the patterns options as we have learned some naming conventions from the passive information gathering we can use to discover new subdomains following the same pattern.

We can use a wordlist from Seclists repository along with gobuster if we are looking for words in patterns instead of numbers. Remember that during our passive subdomain enumeration activities, we found a pattern lert-api-shv-{NUMBER}-sin6.facebook.com. We can use this pattern to discover additional subdomains. The first step will be to create a patterns.txt file with the patterns previously discovered, for example:
```
lert-api-shv-{GOBUSTER}-sin6
atlas-pp-shv-{GOBUSTER}-sin6
```
The next step will be to launch gobuster using the dns module:
```
export TARGET="facebook.com"

export NS="d.ns.facebook.com"

export WORDLIST="numbers.txt"

gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"

    Found: lert-api-shv-01-sin6.facebook.com
    Found: atlas-pp-shv-01-sin6.facebook.com
    Found: atlas-pp-shv-02-sin6.facebook.com
    Found: atlas-pp-shv-03-sin6.facebook.com
    Found: lert-api-shv-03-sin6.facebook.com
    Found: lert-api-shv-02-sin6.facebook.com
    Found: lert-api-shv-04-sin6.facebook.com
    Found: atlas-pp-shv-04-sin6.facebook.com
```
We can now see a list of subdomains appearing while Gobuster is performing the enumeration checks.

### Find all zone transfers and all subdomains in the DNS server

In an internal company environment, assuming that we have few information, as only one IP address of the DNS server (i.e., `10.129.194.131`) and the domain name (i.e., `inlanefreight.htb`), and we want to check what are all subdomains and name servers, for first we must edit `/etc/hosts` file by adding:
```
10.129.194.131 inlanefreight.htb
```
Then:
```
dig axfr ns.inlanefreight.htb @10.129.194.131

    ; <<>> DiG 9.16.15-Debian <<>> axfr inlanefreight.htb @10.129.194.131
    ;; global options: +cmd
    inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
    inlanefreight.htb.	604800	IN	NS	ns.inlanefreight.htb.
    admin.inlanefreight.htb. 604800	IN	A	10.10.34.2
    ftp.admin.inlanefreight.htb. 604800 IN	A	10.10.34.2
    careers.inlanefreight.htb. 604800 IN	A	10.10.34.50
    dc1.inlanefreight.htb.	604800	IN	A	10.10.34.16
    dc2.inlanefreight.htb.	604800	IN	A	10.10.34.11
    internal.inlanefreight.htb. 604800 IN	A	127.0.0.1
    admin.internal.inlanefreight.htb. 604800 IN A	10.10.1.11
    wsus.internal.inlanefreight.htb. 604800	IN A	10.10.1.240
    ir.inlanefreight.htb.	604800	IN	A	10.10.45.5
    dev.ir.inlanefreight.htb. 604800 IN	A	10.10.45.6
    ns.inlanefreight.htb.	604800	IN	A	127.0.0.1
    resources.inlanefreight.htb. 604800 IN	A	10.10.34.100
    securemessaging.inlanefreight.htb. 604800 IN A	10.10.34.52
    test1.inlanefreight.htb. 604800	IN	A	10.10.34.101
    us.inlanefreight.htb.	604800	IN	A	10.10.200.5
    cluster14.us.inlanefreight.htb.	604800 IN A	10.10.200.14
    messagecenter.us.inlanefreight.htb. 604800 IN A	10.10.200.10
    ww02.inlanefreight.htb.	604800	IN	A	10.10.34.112
    www1.inlanefreight.htb.	604800	IN	A	10.10.34.111
    inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
    ;; Query time: 4 msec
    ;; SERVER: 10.129.194.131#53(10.129.194.131)
    ;; WHEN: Thu Nov 18 15:01:39 UTC 2021
    ;; XFR size: 22 records (messages 1, bytes 594)
```
Note that also subdomains could have zone transfers, so this list of subdomain is not the only one. For searching where are the other information, we need to analyze the output above. We note that all these IP address above have port 53 TCP and UDP filtered, so I can guess they don't provide DNS service.

But look also the rows where we have`127.0.0.1` that is referred to the localhost NOT of my machine but of `10.129.194.131` (name server) itself. So, in practice, `internal.inlanefreight.htb` and `ns.inlanefreight.htb` are associated to the `10.129.194.131` IP address.

At this point, on `/etc/hosts` file add the following lines:
```
10.129.194.131 internal.inlanefreight.htb
10.129.194.131 ns.inlanefreight.htb
```
and now try to execute:
```
dig axfr internal.inlanefreight.htb @10.129.194.131

    ; <<>> DiG 9.16.15-Debian <<>> axfr internal.inlanefreight.htb @10.129.194.131
    ;; global options: +cmd
    internal.inlanefreight.htb. 604800 IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
    internal.inlanefreight.htb. 604800 IN	TXT	"ZONE_TRANSFER{87o2z3cno7zsoiedznxoi82z3o47xzhoi}"
    internal.inlanefreight.htb. 604800 IN	NS	ns.inlanefreight.htb.
    dev.admin.internal.inlanefreight.htb. 604800 IN	A 10.10.1.2
    panel.admin.internal.inlanefreight.htb.	604800 IN A 10.10.1.2
    printer.admin.internal.inlanefreight.htb. 604800 IN A 10.10.1.3
    dc3.internal.inlanefreight.htb.	604800 IN A	10.10.1.5
    ns.internal.inlanefreight.htb. 604800 IN A	127.0.0.1
    ns2.internal.inlanefreight.htb.	604800 IN A	10.10.34.136
    ws1.internal.inlanefreight.htb.	604800 IN A	10.10.2.11
    ws2.internal.inlanefreight.htb.	604800 IN A	10.10.3.12
    internal.inlanefreight.htb. 604800 IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
    ;; Query time: 0 msec
    ;; SERVER: 10.129.194.131#53(10.129.194.131)
    ;; WHEN: Thu Nov 18 15:07:02 UTC 2021
    ;; XFR size: 12 records (messages 1, bytes 435)
```
So you get additional results.

Doing the same on `ns.inlanefreight.htb` returns a `; Transfer failed` error, maybe because that FQDN is not used anymore, or it is not accessible or other reasons. Anyway, the main point is to add the correct data in `/etc/hosts` file.

Finally, we can conclude there are two DNS zones on the target name server of this example.

## Virtual Hosts

A virtual host (vHost) is a feature that allows several websites to be hosted on a single server. This is an excellent solution if you have many websites and don't want to go through the time-consuming (and expensive) process of setting up a new web server for each one. Imagine having to set up a different webserver for a mobile and desktop version of the same page. There are two ways to configure virtual hosts:

* IP-based virtual hosting: For this type, a host can have multiple network interfaces. Multiple IP addresses, or interface aliases, can be configured on each network interface of a host. The servers or virtual servers running on the host can bind to one or more IP addresses. This means that different servers can be addressed under different IP addresses on this host. From the client's point of view, the servers are independent of each other.
* Name-based virtual hosting: The distinction for which domain the service was requested is made at the application level. For example, several domain names, such as `admin.inlanefreight.htb` and `backup.inlanefreight.htb`, can refer to the same IP. Internally on the server, these are separated and distinguished using different folders. Using this example, on a Linux server, the vHost `admin.inlanefreight.htb` could point to the folder `/var/www/admin`. For `backup.inlanefreight.htb` the folder name would then be adapted and could look something like `/var/www/backup`.

In general, some subdomains having the same IP address can either be virtual hosts or, in some cases, different servers sitting behind a proxy (or a load balancer).

### vHost Fuzzing

We can automate the vHost enumeration by using a dictionary file of possible vhost names (such as `/opt/useful/SecLists/Discovery/DNS/namelist.txt` on the Pwnbox) and examining the Content-Length header to look for any differences.

Let's assume our `namelist.txt` is named `vhosts`:
```
cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done

    ********
    FUZZING: app
    ********
    Content-Length: 612

    ********
    FUZZING: blog
    ********
    Content-Length: 612

    ********
    FUZZING: dev-admin
    ********
    Content-Length: 120

    ********
    FUZZING: forum
    ********
    Content-Length: 612

    ********
    FUZZING: help
    ********
    Content-Length: 612

    ********
    FUZZING: m
    ********
    Content-Length: 612

    <SNIP>
```
We have successfully identified a virtual host called `dev-admin` (look the size of the response), which we can access using a cURL request:
```
curl -s http://192.168.10.10 -H "Host: dev-admin.randomtarget.com"

    <!DOCTYPE html>
    <html>
    <body>

    <h1>Randomtarget.com Admin Website</h1>

    <p>You shouldn't be here!</p>

    </body>
    </html>
```
NOTE: if we are looking for vHost in an internal network company, after we get the list of possible vHosts by using the first command above, remember to add the vHosts inside the `/etc/hosts` file, otherwise the system does not know where to get the resolution of the DNS. After this, we can try to visit the vHost by the browser.

### Automating Virtual Hosts Discovery

We can use this manual approach for a small list of virtual hosts, but it will not be feasible if we have an extensive list. Using `ffuf`, we can speed up the process and filter based on parameters present in the response. Let's replicate the same process we did with ffuf.

We can match or filter responses based on different options. The web server responds with a default and static website every time we issue an invalid virtual host in the HOST header. We can use the filter by size -fs option to discard the default response as it will always have the same size:
```
ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612
```

# Nmap
--
## Scan network range
```
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

    10.129.2.4
    10.129.2.10
    10.129.2.11
    10.129.2.18
    10.129.2.19
    10.129.2.20
    10.129.2.28
```
## Scan single IP with particular arguments
If we disable port scan (`-sn`), Nmap automatically ping scan with ICMP Echo Requests (`-PE`). Once such a request is sent, we usually expect an ICMP reply if the pinging host is alive. The more interesting fact is that our previous scans did not do that because before Nmap could send an ICMP echo request, it would send an ARP ping resulting in an ARP reply. We can confirm this with the `--packet-trace` option. To ensure that ICMP echo requests are sent, we also define the option (`-PE`) for this.
```
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace

    Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:08 CEST
    SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
    RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
    Nmap scan report for 10.129.2.18
    Host is up (0.023s latency).
    MAC Address: DE:AD:00:00:BE:EF
    Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
```
Another way to determine why Nmap has our target marked as "alive" is with the `--reason` option.
```
sudo nmap 10.129.2.18 -sn -oA host -PE --reason

    Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:10 CEST
    SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
    RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
    Nmap scan report for 10.129.2.18
    Host is up, received arp-response (0.028s latency).
    MAC Address: DE:AD:00:00:BE:EF
    Nmap done: 1 IP address (1 host up) scanned in 0.03 seconds
```
## Other interesting commands
```
sudo nmap 10.129.2.28 --top-ports=10

sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
```
We see that we only scanned the top 10 TCP ports of our target, and Nmap displays their state accordingly. If we trace the packets Nmap sends, we will see the RST flag on TCP port 21 that our target sends back to us. To have a clear view of the SYN scan, we disable the ICMP echo requests (`-Pn`), DNS resolution (`-n`), and ARP ping scan (`--disable-arp-ping`).

Another option (`--stats-every=5s`) that we can use is defining how periods of time the status should be shown. Here we can specify the number of seconds (s) or minutes (m), after which we want to get the status:
```
sudo nmap 10.129.2.28 -p- -sV --stats-every=5s
```

## Nmap Scripting Engine

Run default scripts:
```
sudo nmap <target> -sC
```
This command can also provide us information related to the name of services that we cannot get by `-sV` argument.

Run defined scripts:
```
sudo nmap <target> --script <script-name>,<script-name>, ...

sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands
```
Run scripts for category:
```
sudo nmap <target> --script <category>

| Category | Description |
| -------- | ----------- |
| auth | Determination of authentication credentials. |
| broadcast | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| brute | Executes scripts that try to log in to the respective service by brute-forcing with credentials. |
| default | Default scripts executed by using the `-sC` option. |
| discovery | Evaluation of accessible services. |
| dos | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services. |
| exploit | This category of scripts tries to exploit known vulnerabilities for the scanned port. |
| external | Scripts that use external services for further processing. |
| fuzzer | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time. |
| intrusive | Intrusive scripts that could negatively affect the target system. |
| malware | Checks if some malware infects the target system. |
| safe | Defensive scripts that do not perform intrusive and destructive access. |
| version | Extension for service detection. |
| vuln | Identification of specific vulnerabilities. |
```
## Performance

Optimized RTT
```
sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```
Reduced Retries
```
sudo nmap 10.129.2.0/24 -F --max-retries 0 | grep "/tcp" | wc -l
```
Optimized Scan
```
sudo nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300
```
Timing (-T)

| Argument | Description |
| -------- | ----------- |
| -T 0 | -T paranoid |
| -T 1 | -T sneaky |
| -T 2 | -T polite |
| -T 3 | -T normal |
| -T 4 | -T aggressive |
| -T 5 | -T insane |

## Firewall and IDS/IPS Evasion

### Firewall

Determine Firewalls and their rules. We already know that when a port is shown as filtered, it can have several reasons. In most cases, firewalls have certain rules set to handle specific connections. The packets can either be dropped, or rejected. The dropped packets are ignored, and no response is returned from the host.

This is different for rejected packets that are returned with an RST flag. These packets contain different types of ICMP error codes or contain nothing at all.

Such errors can be:
* Net Unreachable
* Net Prohibited
* Host Unreachable
* Host Prohibited
* Port Unreachable
* Proto Unreachable

Nmap's TCP ACK scan (`-sA`) method is much harder to filter for firewalls and IDS/IPS systems than regular SYN (`-sS`) or Connect scans (`-sT`) because they only send a TCP packet with only the ACK flag. When a port is closed or open, the host must respond with an RST flag. Unlike outgoing connections, all connection attempts (with the SYN flag) from external networks are usually blocked by firewalls. However, the packets with the ACK flag are often passed by the firewall because the firewall cannot determine whether the connection was first established from the external network or the internal network.

If we look at these scans, we will see how the results differ:

**SYN-Scan**
```
sudo nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping --packet-trace

    Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 14:56 CEST
    SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:22 S ttl=53 id=22412 iplen=44  seq=4092255222 win=1024 <mss 1460>
    SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:25 S ttl=50 id=62291 iplen=44  seq=4092255222 win=1024 <mss 1460>
    SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:21 S ttl=58 id=38696 iplen=44  seq=4092255222 win=1024 <mss 1460>
    RCVD (0.0329s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3) ] IP [ttl=64 id=40884 iplen=72 ]
    RCVD (0.0341s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0 iplen=44  seq=1153454414 win=64240 <mss 1460>
    RCVD (1.0386s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0 iplen=44  seq=1153454414 win=64240 <mss 1460>
    SENT (1.1366s) TCP 10.10.14.2:57348 > 10.129.2.28:25 S ttl=44 id=6796 iplen=44  seq=4092320759 win=1024 <mss 1460>
    Nmap scan report for 10.129.2.28
    Host is up (0.0053s latency).

    PORT   STATE    SERVICE
    21/tcp filtered ftp
    22/tcp open     ssh
    25/tcp filtered smtp
    MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

    Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
```

**ACK-Scan**
```
sudo nmap 10.129.2.28 -p 21,22 -sA -Pn -n --disable-arp-ping --packet-trace

    Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 14:57 CEST
    SENT (0.0422s) TCP 10.10.14.2:49343 > 10.129.2.28:21 A ttl=49 id=12381 iplen=40  seq=0 win=1024
    SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:22 A ttl=41 id=5146 iplen=40  seq=0 win=1024
    SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:25 A ttl=49 id=5800 iplen=40  seq=0 win=1024
    RCVD (0.1252s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3) ] IP [ttl=64 id=55628 iplen=68 ]
    RCVD (0.1268s) TCP 10.129.2.28:22 > 10.10.14.2:49343 R ttl=64 id=0 iplen=40  seq=1660784500 win=0
    SENT (1.3837s) TCP 10.10.14.2:49344 > 10.129.2.28:25 A ttl=59 id=21915 iplen=40  seq=0 win=1024
    Nmap scan report for 10.129.2.28
    Host is up (0.083s latency).

    PORT   STATE      SERVICE
    21/tcp filtered   ftp
    22/tcp unfiltered ssh
    25/tcp filtered   smtp
    MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

    Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
```
Please pay attention to the RCVD packets and its set flag we receive from our target. With the SYN scan (`-sS`) our target tries to establish the TCP connection by sending a packet back with the SYN-ACK (SA) flags set and with the ACK scan (`-sA`) we get the RST flag because TCP port 22 is open. For the TCP port 25, we do not receive any packets back, which indicates that the packets will be dropped.

### Testing Firewall Rule
```
sudo nmap 10.129.2.28 -n -Pn -p445 -O
    
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 01:23 CEST
    Nmap scan report for 10.129.2.28
    Host is up (0.032s latency).

    PORT    STATE    SERVICE
    445/tcp filtered microsoft-ds
    MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
    Too many fingerprints match this host to give specific OS details
    Network Distance: 1 hop

    OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 3.14 seconds
```
Look `Network Distance: 1 hop`.

### Scan by Using Different Source IP
```
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0

    Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 01:16 CEST
    Nmap scan report for 10.129.2.28
    Host is up (0.010s latency).

    PORT    STATE SERVICE
    445/tcp open  microsoft-ds
    MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Linux 3.1 (95%),   Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Synology DiskStation Manager 5.2-5644 (94%), Linux 2.6.32 - 2.6.   35 (94%), Linux 2.6.32 - 3.5 (94%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 1 hop

    OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 4.11 seconds
```
### IDS/IPS

Unlike firewalls and their rules, the detection of IDS/IPS systems is much more difficult because these are passive traffic monitoring systems. IDS systems examine all connections between hosts. If the IDS finds packets containing the defined contents or specifications, the administrator is notified and takes appropriate action in the worst case.

IPS systems take measures configured by the administrator independently to prevent potential attacks automatically. It is essential to know that IDS and IPS are different applications and that IPS serves as a complement to IDS.

Several virtual private servers (VPS) with different IP addresses are recommended to determine whether such systems are on the target network during a penetration test. If the administrator detects such a potential attack on the target network, the first step is to block the IP address from which the potential attack comes. As a result, we will no longer be able to access the network using that IP address, and our Internet Service Provider (ISP) will be contacted and blocked from all access to the Internet.

* IDS systems alone are usually there to help administrators detect potential attacks on their network. They can then decide how to handle such connections. We can trigger certain security measures from an administrator, for example, by aggressively scanning a single port and its service. Based on whether specific security measures are taken, we can detect if the network has some monitoring applications or not.

* One method to determine whether such IPS system is present in the target network is to scan from a single host (VPS). If at any time this host is blocked and has no access to the target network, we know that the administrator has taken some security measures. Accordingly, we can continue our penetration test with another VPS.

Consequently, we know that we need to be quieter with our scans and, in the best case, disguise all interactions with the target network and its services.

### Decoys

There are cases in which administrators block specific subnets from different regions in principle. This prevents any access to the target network. Another example is when IPS should block us. For this reason, the Decoy scanning method (`-D`) is the right choice. With this method, Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent. With this method, we can generate random (RND) a specific number (for example: 5) of IP addresses separated by a colon (:). Our real IP address is then randomly placed between the generated IP addresses. In the next example, our real IP address is therefore placed in the second position. Another critical point is that the decoys must be alive. Otherwise, the service on the target may be unreachable due to SYN-flooding security mechanisms:
```
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
    
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 16:14 CEST
    SENT (0.0378s) TCP 102.52.161.59:59289 > 10.129.2.28:80 S ttl=42 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
    SENT (0.0378s) TCP 10.10.14.2:59289 > 10.129.2.28:80 S ttl=59 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
    SENT (0.0379s) TCP 210.120.38.29:59289 > 10.129.2.28:80 S ttl=37 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
    SENT (0.0379s) TCP 191.6.64.171:59289 > 10.129.2.28:80 S ttl=38 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
    SENT (0.0379s) TCP 184.178.194.209:59289 > 10.129.2.28:80 S ttl=39 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
    SENT (0.0379s) TCP 43.21.121.33:59289 > 10.129.2.28:80 S ttl=55 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
    RCVD (0.1370s) TCP 10.129.2.28:80 > 10.10.14.2:59289 SA ttl=64 id=0 iplen=44  seq=4056111701 win=64240 <mss 1460>
    Nmap scan report for 10.129.2.28
    Host is up (0.099s latency).

    PORT   STATE SERVICE
    80/tcp open  http
    MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

    Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
```
The spoofed packets are often filtered out by ISPs and routers, even though they come from the same network range. Therefore, we can also specify our VPS servers' IP addresses and use them in combination with "IP ID" manipulation in the IP headers to scan the target.

Another scenario would be that only individual subnets would not have access to the server's specific services. So we can also manually specify the source IP address (`-S`) to test if we get better results with this one. Decoys can be used for SYN, ACK, ICMP scans, and OS detection scans. So let us look at such an example and determine which operating system it is most likely to be.

### DNS Proxying

By default, Nmap performs a reverse DNS resolution unless otherwise specified to find more important information about our target. These DNS queries are also passed in most cases because the given web server is supposed to be found and visited. The DNS queries are made over the UDP port 53. The TCP port 53 was previously only used for the so-called "Zone transfers" between the DNS servers or data transfer larger than 512 bytes. More and more, this is changing due to IPv6 and DNSSEC expansions. These changes cause many DNS requests to be made via TCP port 53.

However, Nmap still gives us a way to specify DNS servers ourselves (`--dns-server <ns>,<ns>`). This method could be fundamental to us if we are in a demilitarized zone (DMZ). The company's DNS servers are usually more trusted than those from the Internet. So, for example, we could use them to interact with the hosts of the internal network. As another example, we can use TCP port 53 as a source port (`--source-port`) for our scans. If the administrator uses the firewall to control this port and does not filter IDS/IPS properly, our TCP packets will be trusted and passed through.

### SYN-Scan of a Filtered Port
```
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace

    Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 22:50 CEST
    SENT (0.0417s) TCP 10.10.14.2:33436 > 10.129.2.28:50000 S ttl=41 id=21939 iplen=44  seq=736533153 win=1024 <mss 1460>
    SENT (1.0481s) TCP 10.10.14.2:33437 > 10.129.2.28:50000 S ttl=46 id=6446 iplen=44  seq=736598688 win=1024 <mss 1460>
    Nmap scan report for 10.129.2.28
    Host is up.

    PORT      STATE    SERVICE
    50000/tcp filtered ibm-db2

    Nmap done: 1 IP address (1 host up) scanned in 2.06 seconds
```
### SYN-Scan From DNS Port
```
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53

    SENT (0.0482s) TCP 10.10.14.2:53 > 10.129.2.28:50000 S ttl=58 id=27470 iplen=44  seq=4003923435 win=1024 <mss 1460>
    RCVD (0.0608s) TCP 10.129.2.28:50000 > 10.10.14.2:53 SA ttl=64 id=0 iplen=44  seq=540635485 win=64240 <mss 1460>
    Nmap scan report for 10.129.2.28
    Host is up (0.013s latency).

    PORT      STATE SERVICE
    50000/tcp open  ibm-db2
    MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

    Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```
### Connect To The Filtered Port
```
ncat -nv --source-port 53 10.129.2.28 50000

    Ncat: Version 7.80 ( https://nmap.org/ncat )
    Ncat: Connected to 10.129.2.28:50000.
    220 ProFTPd
```
## TCPDUMP & NETCAT for Service Enumeration
If we manually connect to the SMTP server on our target using nc, grab the banner, and intercept the network traffic using tcpdump, we can see what Nmap did not show us:
```
sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28

    18:28:07.128564 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [S], seq 1798872233, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 331260178 ecr 0,sackOK,eol], length 0
    18:28:07.255151 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [S.], seq 1130574379, ack 1798872234, win 65160, options [mss 1460,sackOK,TS val 1800383922 ecr 331260178,nop,wscale 7], length 0
    18:28:07.255281 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 1, win 2058, options [nop,nop,TS val 331260304 ecr 1800383922], length 0
    18:28:07.319306 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [P.], seq 1:36, ack 1, win 510, options [nop,nop,TS val 1800383985 ecr 331260304], length 35: SMTP: 220 inlane ESMTP Postfix (Ubuntu)
    18:28:07.319426 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 36, win 2058, options [nop,nop,TS val 331260368 ecr 1800383985], length 0
```
where [S] means SYN, [S.] means SYN-ACK, [.] means ACK, [P.] means PSH-ACK.
```
nc -nv 10.129.2.28 25

    Connection to 10.129.2.28 port 25 [tcp/*] succeeded!
    220 inlane ESMTP Postfix (Ubuntu)
```
# SMB

Anonymous Share Listing:
```
smbclient -L //10.10.227.160/ -N
```
or
```
smbclient -L \\\\10.10.227.160\\ -N
```
Anonymous access to a share folder:
```
smbclient -L //10.10.227.160/<share-folder> -N
```
or
```
smbclient \\\\10.10.227.160\\<share-folder> -N
```
# Brute Forcing

| Password Attack Type |
| -------------------- |
| Dictionary attack |
| Brute force |
| Traffic interception |
| Man In the Middle |
| Key Logging |
| Social engineering |

| Attack | Description |
| ------ | ----------- |
| Online Brute Force Attack | Attacking a live application over the network, like HTTP, HTTPs, SSH, FTP, and others |
| Offline Brute Force Attack | Also known as Offline Password Cracking, where you attempt to crack a hash of an encrypted password. |
| Reverse Brute Force Attack | Also known as username brute-forcing, where you try a single common password with a list of usernames on a certain service. |
| Hybrid Brute Force Attack	| Attacking a user by creating a customized password wordlist, built using known intelligence about the user or the service. |

## Hydra
Combined Credentials Wordlist:
```
hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.211.23.155 -s 31099 http-get /
```
Username/Password Attack:
```
hydra -L /opt/useful/SecLists/Usernames/Names/names.txt -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /
```
Username Brute Force:
```
hydra -L /opt/useful/SecLists/Usernames/Names/usernames.txt -p amormio -u -f 178.35.49.134 -s 32901 http-get /
```

### Brute Forcing Forms
Hydra provides many different types of requests we can use to brute force different services:
```
hydra -h | grep "Supported services" | tr ":" "\n" | tr " " "\n" | column -e

    Supported			        ldap3[-{cram|digest}md5][s]	rsh
    services			        memcached					rtsp
    				            mongodb						s7-300
    adam6500			        mssql						sip
    asterisk			        mysql						smb
    cisco				        nntp						smtp[s]
    cisco-enable		        oracle-listener				smtp-enum
    cvs				            oracle-sid					snmp
    firebird			        pcanywhere					socks5
    ftp[s]				        pcnfs						ssh
    http[s]-{head|get|post}		pop3[s]						sshkey
    http[s]-{get|post}-form		postgres					svn
    http-proxy		        	radmin2						teamspeak
    http-proxy-urlenum		    rdp				  		    telnet[s]
    icq				            redis						vmauthd
    imap[s]		        		rexec						vnc
    irc				            rlogin						xmpp
    ldap2[s]		        	rpcap
```
You can retrieve the correct POST parameter by the browser on login.php page and using "Copy as cURL" (i.e, username=test&password=test) or using BurpSuite and use in a command like the following:
 ```
hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

#### Brute Force SSH credentials
```
hydra -l root -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt 192.168.1.105 ssh
```
### CUPP
```
cupp -i

    ___________
       cupp.py!                 # Common
          \                     # User
           \   ,__,             # Passwords
            \  (oo)____         # Profiler
               (__)    )\
                  ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                                [ Mebus | https://github.com/Mebus/]


    [+] Insert the information about the victim to make a dictionary
    [+] If you don't know all the info, just hit enter when asked! ;)

    > First Name: William
    > Surname: Gates
    > Nickname: Bill
    > Birthdate (DDMMYYYY): 28101955

    > Partners) name: Melinda
    > Partners) nickname: Ann
    > Partners) birthdate (DDMMYYYY): 15081964

    > Child's name: Jennifer
    > Child's nickname: Jenn
    > Child's birthdate (DDMMYYYY): 26041996

    > Pet's name: Nila
    > Company name: Microsoft

    > Do you want to add some key words about the victim? Y/[N]: Phoebe,Rory
    > Do you want to add special chars at the end of words? Y/[N]: y
    > Do you want to add some random numbers at the end of words? Y/[N]:y
    > Leet mode? (i.e. leet = 1337) Y/[N]: y

    [+] Now making a dictionary...
    [+] Sorting list and removing duplicates...
    [+] Saving dictionary to william.txt, counting 43368 words.
    [+] Now load your pistolero with william.txt and shoot! Good luck!
```
We can remove any passwords that do not meet these conditions from our wordlist. Some tools would convert password policies to Hashcat or John rules, but hydra does not support rules for filtering passwords. So, we will simply use the following commands to do that for us:
```
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8`
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars`
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers`
```
### Custom Username Wordlist
```
bash usernameGenerator/usernameGenerator.sh Bill Gates

    Wordlist saved as bill.txt
```
### Service Authentication Brute Forcing

SSH Attack
```
hydra -L bill.txt -P william.txt -u -f ssh://178.35.49.134:22 -t 4
```
FTP Brute Forcing
```
hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1
```

## Crunch
Syntax:
```
crunch <minimum length> <maximum length> <charset> -t <pattern> -o <output file>
```
### Generate Word List
```
crunch 4 8 -o wordlist
```
### Create Word List using Pattern
```
crunch 17 17 -t ILFREIGHT201%@@@@ -o wordlist

    The pattern "ILFREIGHT201%@@@@" will create words with the years 2010-2019 followed by four letters. The length here is 17, which is constant for all words.
```
### Specified Repetition
```
crunch 12 12 -t 10031998@@@@ -d 1 -o wordlist

    If we know a user's birthdate is 10/03/1998 (through social media, etc.), we can include this in their password, followed by a string of letters. Crunch can be used to create a wordlist of such words. The "-d" option is used to specify the amount of repetition.
```
## CUPP
CUPP stands for Common User Password Profiler, and is used to create highly targeted and customized wordlists based on information gained from social engineering and OSINT. People tend to use personal information while creating passwords, such as phone numbers, pet names, birth dates, etc. CUPP takes in this information and creates passwords from them. These wordlists are mostly used to gain access to social media accounts. CUPP is installed by default on Parrot OS, and the repo can be found here. The "-i" option is used to run in interactive mode, prompting CUPP to ask us for information on the target.
```
python3 cupp.py -i
```
## KWPROCESSOR
Kwprocessor is a tool that creates wordlists with keyboard walks. Another common password generation technique is to follow patterns on the keyboard. These passwords are called keyboard walks, as they look like a walk along the keys. For example, the string "qwertyasdfg" is created by using the first five characters from the keyboard's first two rows. This seems complex to the normal eye but can be easily predicted. Kwprocessor uses various algorithms to guess patterns such as these.

The pattern is based on the geographical directions a user could choose on the keyboard. For example, the "--keywalk-west" option is used to specify movement towards the west from the base character. The program takes in base characters as a parameter, which is the character set the pattern will start with. Next, it needs a keymap, which maps the locations of keys on language-specific keyboard layouts. The final option is used to specify the route to be used. A route is a pattern to be followed by passwords. It defines how passwords will be formed, starting from the base characters. For example, the route 222 can denote the path 2 * EAST + 2 * SOUTH + 2 * WEST from the base character. If the base character is considered to be "T" then the password generated by the route would be "TYUJNBV" on a US keymap.
```
kwp -s 1 basechars/full.base keymaps/en-us.keymap  routes/2-to-10-max-3-direction-changes.route
```
## Princeprocessor
PRINCE or PRobability INfinite Chained Elements is an efficient password guessing algorithm to improve password cracking rates. Princeprocessor is a tool that generates passwords using the PRINCE algorithm. The program takes in a wordlist and creates chains of words taken from this wordlist.
```
./pp64.bin -o wordlist.txt < words

    Forming Wordlist

./pp64.bin --pw-min=10 --pw-max=25 -o wordlist.txt < words

    Password Length Limits

./pp64.bin --elem-cnt-min=3 -o wordlist.txt < words

    Specifying Elements

./pp64.bin --keyspace < words

    Find the Number of Combinations
```
## CEWL
CeWL is another tool that can be used to create custom wordlists. It spiders and scrapes a website and creates a list of the words that are present. This kind of wordlist is effective, as people tend to use passwords associated with the content they write or operate on. For example, a blogger who blogs about nature, wildlife, etc. could have a password associated with those topics. This is due to human nature, as such passwords are also easy to remember. Organizations often have passwords associated with their branding and industry-specific vocabulary. For example, users of a networking company may have passwords consisting of words like router, switch, server, and so on. Such words can be found on their websites under blogs, testimonials, and product descriptions.

Syntax:
```
cewl -d <depth to spider> -m <minimum word length> -w <output wordlist> <url of website>
```
Example:
```
cewl -d 5 -m 8 -e http://inlanefreight.com/blog -w wordlist.txt

    The command above scrapes up to a depth of five pages from "http://inlanefreight.com/blog", and includes only words greater than 8 in length.
```
## Hashcat-utils
The Hashcat-utils repo contains many utilities that can be useful for more advanced password cracking. The tool maskprocessor, for example, can be used to create wordlists using a given mask.

For example, maskprocessor can be used to append all special characters to the end of a word:
```
./mp64.bin Welcome?s

    Welcome 
    Welcome!
    Welcome"
    Welcome#
    Welcome$
    Welcome%
    Welcome&
    Welcome'
    Welcome(
    Welcome)
    Welcome*
    Welcome+

    <SNIP>
```
# Command Injections

## Bashfuscator
Linux handy tool we can utilize for obfuscating bash commands.

Examples of usage:
```
D3vil0p3r@htb[/htb]$ ./bashfuscator -c 'cat /etc/passwd'

[+] Mutators used: Token/ForCode -> Command/Reverse
[+] Payload:
 ${*/+27\[X\(} ...SNIP...  ${*~}   
[+] Payload size: 1664 characters
```
We can use some of the flags from the help menu to produce a shorter and simpler obfuscated command, as follows:
```
D3vil0p3r@htb[/htb]$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

[+] Mutators used: Token/ForCode
[+] Payload:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"
[+] Payload size: 104 characters
```
We can now test the outputted command with bash -c '', to see whether it does execute the intended command:
```
D3vil0p3r@htb[/htb]$ bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'

root:x:0:0:root:/root:/bin/bash
...SNIP...
```

## DOSfuscation

Similar tool that we can use for Windows. Unlike Bashfuscator, this is an interactive tool, as we run it once and interact with it to get the desired obfuscated command:
```
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS C:\htb> cd Invoke-DOSfuscation
PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1
PS C:\htb> Invoke-DOSfuscation
Invoke-DOSfuscation> help

HELP MENU :: Available options shown below:
[*]  Tutorial of how to use this tool             TUTORIAL
...SNIP...

Choose one of the below options:
[*] BINARY      Obfuscated binary syntax for cmd.exe & powershell.exe
[*] ENCODING    Environment variable encoding
[*] PAYLOAD     Obfuscated payload via DOSfuscation
```
We can even use `tutorial` to see an example of how the tool works. Once we are set, we can start using the tool, as follows:
```
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1

...SNIP...
Result:
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```
Finally, we can try running the obfuscated command on `CMD`, and we see that it indeed works as expected:
```
C:\htb> typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt

test_flag
```

# Fuzzing
We use mainly `ffuf`. It uses each line of a wordlist file, so it is better we remove comment lines from wordlist files before using them on `ffuf`:
```
sudo sed -i 's/^\#.*$//g' /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt && sudo sed -i '/^$/d' /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
```
## Directory fuzzing
```
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://$RHOST:$RPORT/FUZZ
```
Example:
```
ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
```
This task can be very resource-intensive for the target server. If the website responds slower than usual, we can lower the rate of requests using the `-rate` parameter.

## Extension fuzzing
```
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://$RHOST:$RPORT/blog/indexFUZZ
```
Note that, in case it is asked to first find subdomains or VHosts, and then the possible extensions, remember to keep the subdomain/VHost information in the `Host` header, otherwise you could miss some useful information. For example, if we want to discover all possible extensions in the root of a subdomain, after discovered one of them (for example `faculty`), we can run FFUF in the following manner:
```
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://academy.htb:31581/indexFUZZ -H 'Host: faculty.academy.htb'
```
so we keep the subdomain/VHost information in the `Host` header. Then, if you want to visit that resource, remember to add to `/etc/hosts` the IP address with the subdomain.

## Page fuzzing
```
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://$RHOST:$RPORT/blog/FUZZ.php
```
## Recursive scanning
```
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://$RHOST:$RPORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```
## Subdomain fuzzing
```
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/
```
## Vhosts fuzzing
```
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```
For subdomains and vhosts, to access by browser, maybe could be necessary to add "admin.academy.htb" to "/etc/hosts". "admin" is the subdomain/vhost of our example. Note that, if you want to access to the subdomain/Vhost by browser, add it to `/etc/hosts`.

## Filtering
```
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs 900

    For example, we know the response size of the incorrect results, which, for example, is 900, and we can filter it out with -fs 900.
```
## Parameter fuzzing GET
```
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```
In general, parameter fuzzing is useful also for retrieving hidden web service or API-related files. Remember that the Web Services could be also exposed on other ports, not necessarily to standard HTTP ports.

## Parameter fuzzing POST
```
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
Tip: In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'". Check if also other cases are like it.

If I get a valid parameter, I can use `curl` to see the response by using that parameter:
```
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```
## Value fuzzing
```
ffuf -w custom_wordlist_with_id.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx

    Our command should be fairly similar to the POST command we used to fuzz for parameters, but our FUZZ keyword should be put where the parameter value would be, and we will use the custom_wordlist_with_id.txt wordlist we created on our own.
```
## Real Scenario

It is typical for the webserver and the web application to handle the files it needs to function. However, it is common to find backup or unreferenced files that can have important information or credentials. Backup or unreferenced files can be generated by creating snapshots, different versions of a file, or from at ext editor without the web developer's knowledge. There are some lists of common extensions we can find in the `raft-[ small | medium | large ]-extensions.txt` files from SecLists.

We will combine some of the folders we have found before, a list of common extensions, and some words extracted from the website to see if we can find something that should not be there. The first step will be to create a file with the following folder names and save it as `folders.txt`:
```
wp-admin
wp-content
wp-includes
```
Next, we will extract some keywords from the website using CeWL. We will instruct the tool to extract words with a minimum length of 5 characters `-m5`, convert them to lowercase `--lowercase` and save them into a file called wordlist.txt `-w <FILE>`:
```
cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10
```
The next step will be to combine everything in ffuf to see if we can find some juicy information. For this, we will use the following parameters in `ffuf`:
```
ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS
```
# Password cracking
## Identifying hashes
```
hashid '$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.' -m

hashid hashes.txt
```
## Hashcat
Attack modes (`-a`):
| # | Mode |
| - | ---- |
| 0 | Straight |
| 1 | Combination |
| 3 | Brute-force |
| 6 | Hybrid Wordlist + Mask |
| 7 | Hybrid Mask + Wordlist |

### Benchmark
```
hashcat -b -m 0
```
or
```
hashcat -b
```
for all hash modes.

### Optimization
Two main ways to optimize the speed:
| Option | Description |
| - | - |
| Optimized Kernels | This is the `-O` flag, which according to the documentation, means Enable optimized kernels (limits password length). The magical password length number is generally 32, with most wordlists won't even hit that number. This can take the estimated time from days to hours, so it is always recommended to run with `-O` first and then rerun after without the `-O` if your GPU is idle. |
| Workload | This is the `-w` flag, which, according to the documentation, means Enable a specific workload profile. The default number is 2, but if you want to use your computer while Hashcat is running, set this to 1. If you plan on the computer only running Hashcat, this can be set to 3. |

Note: It is important to note that the use of `--force` should be avoided. While this appears to make Hashcat work on certain hosts, it is actually disabling safety checks, muting warnings, and bypasses problems that the tool's developers have deemed to be blockers. These problems can lead to false positives, false negatives, malfunctions, etc. If the tool is not working properly without forcing it to run with `--force` appended to your command, we should troubleshoot the root cause (i.e., a driver issue). Using `--force` is discouraged by the tool's developers and should only be used by experienced users or developers.

### Straight or Dictionary Attack
```
echo -n '!academy' | sha256sum | cut -f1 -d' ' > sha256_hash_example

hashcat -a 0 -m 1400 sha256_hash_example /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### Combination Attack
```
hashcat -a 1 --stdout wordlist1 wordlist2

    Output a combination starting from two wordlists, for example:
    superhello
    superpassword
    worldhello
    worldpassword
    secrethello
    secretpassword

hashcat -a 1 -m 0 combination_md5 wordlist1 wordlist2

    combination_md5 contains the hash to crack. wordlist1 and wordlist2 will be combined for cracking that hash.
```
### Mask Attack
Mask attacks are used to generate words matching a specific pattern. This type of attack is particularly useful when the password length or format is known. A mask can be created using static characters, ranges of characters (e.g. [a-z] or [A-Z0-9]), or placeholders. The following list shows some important placeholders:

| Placeholder | Meaning |
| ----------- | ------- |
| ?l | lower-case ASCII letters (a-z) |
| ?u | upper-case ASCII letters (A-Z) |
| ?d | digits (0-9) |
| ?h | 0123456789abcdef |
| ?H | 0123456789ABCDEF |
| ?s | special characters (`<<space>>!"#$%&'()*+,-./:;<=>?@[]^_``{` |
| ?a | ?l?u?d?s |
| ?b | 0x00 - 0xff |

The above placeholders can be combined with options `-1` to `-4` which can be used for custom placeholders. See the Custom charsets section [here](https://hashcat.net/wiki/doku.php?id=mask_attack) for a detailed breakdown of each of these four command-line parameters that can be used to configure four custom charsets.

Consider the company Inlane Freight, which this time has passwords with the scheme `ILFREIGHT<userid><year>,` where userid is 5 characters long. The mask `ILFREIGHT?l?l?l?l?l20[0-1]?d` can be used to crack passwords with the specified pattern, where `?l` is a letter and `20[0-1]?d` will include all years from 2000 to 2019.

Creating MD5 hash:
```	
echo -n 'ILFREIGHTabcxy2015' | md5sum | tr -d " -" > md5_mask_example_hash
```
The attack command will be:
```
hashcat -a 3 -m 0 md5_mask_example_hash -1 01 'ILFREIGHT?l?l?l?l?l20?1?d'
```
The `-1` option was used to specify a placeholder with just 0 and 1. Hashcat could crack the hash in 43 seconds on CPU power. The `--increment` flag can be used to increment the mask length automatically, with a length limit that can be supplied using the `--increment-max` flag.

### Hybrid Modes

Creating Hybrid Hash:
```
echo -n 'football1$' | md5sum | tr -d " -" > hybrid_hash
```
Attack command with Hybrid Attack using Wordlists:
```
hashcat -a 6 -m 0 hybrid_hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt '?d?s'
```
Creating Hybrid Hash:
```
echo -n '2015football' | md5sum | tr -d " -" > hybrid_hash_prefix
```
Attack command with Hybrid Attack using Masks:
```
hashcat -a 7 -m 0 hybrid_hash_prefix -1 01 '20?1?d' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### Previously Cracked Password
By default, hashcat stores all cracked passwords in the hashcat.potfile file; the format is hash:password. The main purpose of this file is to remove previously cracked hashes from the work log and display cracked passwords with the --show command. However, it can be used to create new wordlists of previously cracked passwords, and when combined with rule files, it can prove quite effective at cracking themed passwords.
```
cut -d: -f 2- ~/hashcat.potfile
```

### Working with rules
| Function | Description | Input | Output |
| -------- | ----------- | ----- | ------ |
| l | Convert all letters to lowercase | InlaneFreight2020 | inlanefreight2020 |
| u | Convert all letters to uppercase | InlaneFreight2020 | INLANEFREIGHT2020 |
| c / C | capitalize / lowercase first letter and invert the rest | inlaneFreight2020 / Inlanefreight2020 | Inlanefreight2020 / iNLANEFREIGHT2020 |
| t / TN | Toggle case : whole word / at position N | InlaneFreight2020 | iNLANEfREIGHT2020 |
| d / q / zN / ZN | Duplicate word / all characters / first character / last character | InlaneFreight2020 | InlaneFreight2020InlaneFreight2020 / IInnllaanneeFFrreeiigghhtt22002200 / IInlaneFreight2020 / InlaneFreight20200 |
| { / } | Rotate word left / right | InlaneFreight2020 | nlaneFreight2020I / 0InlaneFreight202 |
| ^X / $X | Prepend / Append character X | InlaneFreight2020 (^! / $! ) | !InlaneFreight2020 / InlaneFreight2020! |
| r | Reverse | InlaneFreight2020 | 0202thgierFenalnI |

A complete list of functions can be found [here](https://hashcat.net/wiki/doku.php?id=rule_based_attack#implemented_compatible_functions). A list of rejection rules can be found [here](https://hashcat.net/wiki/doku.php?id=rule_based_attack#rules_used_to_reject_plains).

Creating a rule:
```
echo 'so0 si1 se3 ss5 sa@ c $2 $0 $1 $9' > rule.txt

    The first letter word is capitalized with the c function. Then rule uses the substitute function s to replace o with 0, i with 1, e with 3 and a with @. At the end, the year 2019 is appended to it. Copy the rule to a file so that we can debug it.
```
Store the password in a file:
```
echo 'password_ilfreight' > test.txt
```
Debugging Rules:
```
hashcat -r rule.txt test.txt --stdout

    As expected, the first letter was capitalized, and the letters were replaced with numbers.
```
Another example. Generate a SHA1 hash:
```
echo -n 'St@r5h1p2019' | sha1sum | awk '{print $1}' | tee hash
```
We can then use the custom rule created above and the rockyou.txt dictionary file to crack the hash using Hashcat:
```
hashcat -a 0 -m 100 hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -r rule.txt
```
We were able to crack the hash with our custom rule and rockyou.txt. Hashcat supports the usage of multi-rules with repeated use of the `-r` flag. Hashcat installs with a variety of rules by default. They can be found in the rules folder: `ls -l /usr/share/hashcat/rules/`. It is always better to try using these rules before going ahead and creating custom rules.

Hashcat provides an option to generate random rules on the fly and apply them to the input wordlist. The following command will generate 1000 random rules and apply them to each word from rockyou.txt by specifying the `-g` flag. There is no certainty to the success rate of this attack as the generated rules are not constant:
```
hashcat -a 0 -m 100 -g 1000 hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
There are a variety of publicly available rules as well, such as the [nsa-rules](https://github.com/NSAKEY/nsa-rules), [Hob0Rules](https://github.com/praetorian-code/Hob0Rules), and the [corporate.rule](https://github.com/HackLikeAPornstar/StratJumbo/blob/master/chap3/corporate.rule).

### Cracking Wireless (WPA/WPA2) Handshakes with Hashcat
For cracking WPA handshake, first convert a `.cap` file to a suitable file format:
```
hcxpcapngtool -o test.hc22000 corp_question1-01.cap
```
then, crack the WPA handshake:
```
hashcat -m 22000 test.hc22000 /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt 
```
For cracking PMKID hash, extract the PMKID:
```
hcxpcaptool -z pmkidhash_corp cracking_pmkid.cap
```
then, crack PMKID:
```
hashcat -a 0 -m 16800 pmkidhash_corp /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```    

### Examples of usage
Note: on usage of `<extension>2john` scripts, if you get erros like `base64 has no attribute decodestring`, it is because `decodestring` is deprecated on Python3,1 and later. You need to use:
```
python2.7 /usr/bin/<extension>2john output.hash
```
#### Cracking a database dump of SHA1 hashes
For cracking a database dump of SHA1 hashes:
```
hashcat -m 100 SHA1_hashes /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

#### Cracking Linux Shadow File
For cracking Linux Shadow File (i.e, Root password in Ubuntu Linux like `root:$6$tOA0cyybhb/Hr7DN$htr2vffCWiPGnyFOicJiXJVMbk1muPORR.eRGYfBYUnNPUjWABGPFiphjIjJC5xPfFUASIbVKDAHS3vTW1qU.1:18285:0:99999:7:::`):
```
hashcat -m 1800 nix_hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

#### Common Active Directory Password Hash Type
For cracking common Active Directory Password Hash Type as NTLM hash or NTLMv2 hash:
```
hashcat -a 0 -m 1000 ntlm_example /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

#### Cracking Office document password hash
Extract Office document password hash:
```
python office2john.py hashcat_Word_example.docx
```
and then use hashcat for cracking it:
```
hashcat -m 9600 office_hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

#### Cracking zip file password hash
Extract zip file password hash:
```
zip2john ~/Desktop/HTB/Academy/Cracking\ with\ Hashcat/blueprints.zip
```
and then use hashcat for cracking it:
```
hashcat -a 0 -m 17200 pdf_hash_to_crack /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

#### Cracking KeePass file password hash
Extract KeePass file password hash:
```
python keepass2john.py <filename>.kdbx
```
and then use hashcat for cracking it:
```
hashcat -a 0 -m 13400 keepass_hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

#### Cracking PDF file password hash
Extract pdf file password hash:
```
python pdf2john.py <filename>.pdf | awk -F":" '{ print $2}'
```
and then use hashcat for cracking it:
```
hashcat -a 0 -m 10500 pdf_hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

#### Cracking SSH file password hash
Extract ssh private key hash:
```
python ssh2john.py id_rsa > id_rsa.hash
```
and then use john for cracking it:
```
john id_rsa.hash --format=SSH --wordlist=rockyou.txt
```
Note that `--wordlist` argument needs `=<wordlist file>`. If you don't use `=` character, you will get `Invalid UTF-8 seen reading` warning that won't return any correct cracked password.

# Proxying Tools

An important aspect of using web proxies is enabling the interception of web requests made by command-line tools and thick client applications. This gives us transparency into the web requests made by these applications and allows us to utilize all of the different proxy features we have used with web applications.

To route all web requests made by a specific tool through our web proxy tools, we have to set them up as the tool's proxy (i.e. http://127.0.0.1:8080), similarly to what we did with our browsers. Each tool may have a different method for setting its proxy, so we may have to investigate how to do so for each one.

This section will cover a few examples of how to use web proxies to intercept web requests made by such tools. You may use either Burp or ZAP, as the setup process is the same.

Note: Proxying tools usually slows them down, therefore, only proxy tools when you need to investigate their requests, and not for normal usage.


## Proxychains

One very useful tool in Linux is proxychains, which routes all traffic coming from any command-line tool to any proxy we specify. Proxychains adds a proxy to any command-line tool and is hence the simplest and easiest method to route web traffic of command-line tools through our web proxies.

To use proxychains, we first have to edit `/etc/proxychains.conf`, comment the final line and add the following two lines at the end of it:
```
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
https 127.0.0.1 8080
```
We should also enable Quiet Mode to reduce noise by un-commenting quiet_mode. Once that's done, we can prepend proxychains to any command, and the traffic of that command should be routed through proxychains (i.e., our web proxy). For example, let's try using cURL on one of our previous exercises:
```
proxychains curl http://$RHOST:$RPORT
```
```html
ProxyChains-3.1 (http://proxychains.sf.net)
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Ping IP</title>
    <link rel="stylesheet" href="./style.css">
</head>
...SNIP...
</html>    
```

We see that it worked just as it normally would, with the additional `ProxyChains-3.1` line at the beginning, to note that it is being routed through ProxyChains. If we go back to our web proxy (Burp or ZAP), we will see that the request has indeed gone through it.

## Nmap

We can use the `--proxies` flag. We should also add the `-Pn` flag to skip host discovery (as recommended on the man page). Finally, we'll also use the -sC flag to examine what an nmap script scan does:
```
nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC
```
Once again, if we go to our web proxy tool, we will see all of the requests made by nmap in the proxy history.

Note: Nmap's built-in proxy is still in its experimental phase, as mentioned by its manual (`man nmap`), so not all functions or traffic may be routed through the proxy. In these cases, we can simply resort to proxychains, as we did earlier.

## Metasploit

Finally, let's try to proxy web traffic made by Metasploit modules to better investigate and debug them. We should begin by starting Metasploit with `msfconsole`. Then, to set a proxy for any exploit within Metasploit, we can use the `set PROXIES` flag. Let's try the `robots_txt` scanner as an example and run it against one of our previous exercises:
```
msfconsole

    msf6 > use auxiliary/scanner/http/robots_txt
    msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080

    PROXIES => HTTP:127.0.0.1:8080

    msf6 auxiliary(scanner/http/robots_txt) > set RHOST SERVER_IP

    RHOST => SERVER_IP

    msf6 auxiliary(scanner/http/robots_txt) > set RPORT PORT

    RPORT => PORT

    msf6 auxiliary(scanner/http/robots_txt) > run

    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
```
Once again, we can go back to our web proxy tool of choice and examine the proxy history to view all sent requests.

We see that the request has indeed gone through our web proxy. The same method can be used with other scanners, exploits, and other features in Metasploit.

We can similarly use our web proxies with other tools and applications, including scripts and thick clients. All we have to do is set the proxy of each tool to use our web proxy. This allows us to examine exactly what these tools are sending and receiving and potentially repeat and modify their requests while performing web application penetration testing.

# Web Application

## Vulnerability Tools

### Burpsuite

### ZAP

### Nessus

## XSS 

### XSS Strike

Example of usage:
```
python xsstrike.py -u "http://$RHOST:$RPORT/index.php?task=test"
```
### Brute XSS

### XSSer

# Network Traffic Analysis

## TCPDump

### Usage

Listing Available Interfaces:
```
sudo tcpdump -D
```
Choosing an Interface to Capture From:
```
sudo tcpdump -i eth0
```
Disable Name Resolution:
```
sudo tcpdump -i eth0 -nn
```
Display the Ethernet Header:
```
sudo tcpdump -i eth0 -e

    tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
    listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
    11:05:45.982115 00:0c:29:97:52:65 (oui Unknown) > 8a:66:5a:11:8d:64 (oui Unknown), ethertype IPv4 (0x0800), length 103: 172.16.146.2.57142 > ec2-99-80-22-207.eu-west-1.compute.amazonaws.com.https: Flags [P.], seq 922951468:922951505, ack 1842875143, win 501, options  [nop,nop,TS val 1368272062 ecr 65637925], length 37
    11:05:45.989652 00:0c:29:97:52:65 (oui Unknown) > 8a:66:5a:11:8d:64 (oui Unknown), ethertype IPv4 (0x0800), length 129: 172.16.146.2.55272 > 172.67.1.1.https: Flags [P.], seq 940656124:940656199, ack 4248413119, win 501, length 75
    11:05:46.047731 00:0c:29:97:52:65 (oui Unknown) > 8a:66:5a:11:8d:64 (oui Unknown), ethertype IPv4 (0x0800), length 85: 172.16.146.2.54006 > 172.16.146.1.domain: 31772+ PTR? 207.22.80.99.in-addr.arpa. (43)
    11:05:46.049134 8a:66:5a:11:8d:64 (oui Unknown) > 00:0c:29:97:52:65 (oui Unknown), ethertype IPv4 (0x0800), length 147: 172.16.146.1.domain > 172.16.146.2.54006: 31772 1/0/0 PTR ec2-99-80-22-207.eu-west-1.compute.amazonaws.com. (105)
    
    When utilizing the -e switch, we are tasking tcpdump to include the ethernet headers in the capture's output along with its regular content. We can see this worked by examining the output. Usually, the first and second fields consist of the Timestamp and then the IP header's beginning. Now it consists of Timestamp and the source MAC Address of the host.
```
Include ASCII and Hex Output:
```
sudo tcpdump -i eth0 -X

    tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
    listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
    11:10:34.972248 IP 172.16.146.2.57170 > ec2-99-80-22-207.eu-west-1.compute.amazonaws.com.https: Flags [P.], seq 2612172989:2612173026, ack 3165195759, win 501, options [nop,nop,TS val 1368561052 ecr 65712142], length 37
        0x0000:  4500 0059 4352 4000 4006 3f1b ac10 9202  E..YCR@.@.?.....
        0x0010:  6350 16cf df52 01bb 9bb2 98bd bca9 0def  cP...R..........
        0x0020:  8018 01f5 b87d 0000 0101 080a 5192 959c  .....}......Q...
        0x0030:  03ea b00e 1703 0300 2000 0000 0000 0000  ................
        0x0040:  0adb 84ac 34b4 910a 0fb4 2f49 9865 eb45  ....4...../I.e.E
        0x0050:  883c eafd 8266 3e23 88                   .<...f>#.
    11:10:34.984582 IP 172.16.146.2.38732 > 172.16.146.1.domain: 22938+ A? app.hackthebox.eu. (35)
        0x0000:  4500 003f 2e6b 4000 4011 901e ac10 9202  E..?.k@.@.......
        0x0010:  ac10 9201 974c 0035 002b 7c61 599a 0100  .....L.5.+|aY...
        0x0020:  0001 0000 0000 0000 0361 7070 0a68 6163  .........app.hac
        0x0030:  6b74 6865 626f 7802 6575 0000 0100 01    kthebox.eu.....
    11:10:35.055497 IP 172.16.146.2.43116 > 172.16.146.1.domain: 6524+ PTR? 207.22.80.99.in-addr.arpa. (43)
        0x0000:  4500 0047 2e72 4000 4011 900f ac10 9202  E..G.r@.@.......
        0x0010:  ac10 9201 a86c 0035 0033 7c69 197c 0100  .....l.5.3|i.|..
        0x0020:  0001 0000 0000 0000 0332 3037 0232 3202  .........207.22.
        0x0030:  3830 0239 3907 696e 2d61 6464 7204 6172  80.99.in-addr.ar
        0x0040:  7061 0000 0c00 01                        pa.....

    By issuing the -X switch, we can see the packet a bit clearer now. We get an ASCII output on the right to interpret anything in clear text that corresponds to the hexadecimal output on the left.
```
Tcpdump Switch Combinations:
```
sudo tcpdump -i eth0 -nnvXX

    tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
    11:13:59.149599 IP (tos 0x0, ttl 64, id 24075, offset 0, flags [DF], proto TCP (6), length 89)
    172.16.146.2.42454 > 54.77.251.34.443: Flags [P.], cksum 0x6fce (incorrect -> 0xb042), seq 671020720:671020757, ack 3699222968, win 501, options [nop,nop,TS val 1154433101 ecr 1116647414], length 37
        0x0000:  8a66 5a11 8d64 000c 2997 5265 0800 4500  .fZ..d..).Re..E.
        0x0010:  0059 5e0b 4000 4006 6d11 ac10 9202 364d  .Y^.@.@.m.....6M
        0x0020:  fb22 a5d6 01bb 27fe f6b0 dc7d a9b8 8018  ."....'....}....
        0x0030:  01f5 6fce 0000 0101 080a 44cf 404d 428e  ..o.......D.@MB.
        0x0040:  aff6 1703 0300 2000 0000 0000 0000 09bb  ................
        0x0050:  38d9 d89a 2d70 73d5 a01e 9df7 2c48 5b8a  8...-ps.....,H[.
        0x0060:  d64d 8e42 2ccc 43                        .M.B,.C
    11:13:59.157113 IP (tos 0x0, ttl 64, id 31823, offset 0, flags [DF], proto UDP (17), length 63)
    172.16.146.2.55351 > 172.16.146.1.53: 26460+ A? app.hackthebox.eu. (35)
        0x0000:  8a66 5a11 8d64 000c 2997 5265 0800 4500  .fZ..d..).Re..E.
        0x0010:  003f 7c4f 4000 4011 423a ac10 9202 ac10  .?|O@.@.B:......
        0x0020:  9201 d837 0035 002b 7c61 675c 0100 0001  ...7.5.+|ag\....
        0x0030:  0000 0000 0000 0361 7070 0a68 6163 6b74  .......app.hackt
        0x0040:  6865 626f 7802 6575 0000 0100 01         hebox.eu.....
```
### Output Format
Let's look to this output example:

<span style="color:yellow">17:39:26.500472</span> <span style="color:orange">IP 172.16.146.2.21 > 172.16.146.1.49769:</span> <span style="color:green">Flags [P.]</span>, <span style="color:red">seq 1:77, ack 17</span>, <span style="color:cyan">win 509, options [nop,nop,TS val 428627084 ecr 3427972529], length 76:</span> <span style="color:white">FTP: 220 Welcome to the PowerBroker FTP service. Grab or leave juicy info here.</span>

| Filter | Result |
| ------ | ------ |
| <span style="color:yellow">Timestamp</span> | The timestamp field comes first and is configurable to show the time and date in a format we can ingest easily. |
| <span style="color:orange">Protocol</span> | This section will tell us what the upper-layer header is. In our example, it shows IP. |
| <span style="color:orange">Source & Destination IP.Port</span> | This will show us the source and destination of the packet along with the port number used to connect. Format == `IP.port == 172.16.146.2.21` |
| <span style="color:green">Flags</span> | This portion shows any flags utilized. |
| <span style="color:red">Sequence and Acknowledgement Numbers</span> | This section shows the sequence and acknowledgment numbers used to track the TCP segment. Our example is utilizing low numbers to assume that relative sequence and ack numbers are being displayed. |
| <span style="color:cyan">Protocol Options</span> | Here, we will see any negotiated TCP values established between the client and server, such as window size, selective acknowledgments, window scale factors, and more. |
| <span style="color:white">Notes / Next Header</span> | Misc notes the dissector found will be present here. As the traffic we are looking at is encapsulated, we may see more header information for different protocols. In our example, we can see the TCPDump dissector recognizes FTP traffic within the encapsulation to display it for us. |

There are many other options and information that can be shown. This information varies based on the amount of verbosity that is enabled.

### File INput/Output with TCPDump

Save our PCAP Output to a file:
```
sudo tcpdump -i eth0 -w ~/output.pcap
```
Using `-w` will write our capture to a file. Keep in mind that as we capture traffic off the wire, we can quickly use up open disk space and run into storage issues if we are not careful. The larger our network segment, the quicker we will use up storage. Utilizing the switches demonstrated above can help tune the amount of data stored in our PCAPs.
    
Reading Output From a File:
```
sudo tcpdump -r ~/output.pcap
```
### TCPDump Packet Filtering

| Filter | Result |
| ------ | ------ |
| host | host will filter visible traffic to show anything involving the designated host. Bi-directional |
| src / dest | src and dest are modifiers. We can use them to designate a source or destination host or port. |
| net | net will show us any traffic sourcing from or destined to the network designated. It uses / notation. |
| proto | proto will filter for a specific protocol type. (ether, TCP, UDP, and ICMP as examples) |
| port | port is bi-directional. It will show any traffic with the specified port as the source or destination. |
| portrange | portrange allows us to specify a range of ports. (0-1024) |
| less / greater "< >" | less and greater can be used to look for a packet or protocol option of a specific size. |
| and / && | and && can be used to concatenate two different filters together. for example, src host AND port. |
| or | or allows for a match on either of two conditions. It does not have to meet both. It can be tricky. |
| not | not is a modifier saying anything but x. For example, not UDP. |

Host Filter
```
sudo tcpdump -i eth0 host 172.16.146.2
```
Source/Destination Filter
```
sudo tcpdump -i eth0 src host 172.16.146.2
```
Utilizing Source With Port as a Filter
```
sudo tcpdump -i eth0 tcp src port 80
```
Using Destination in Combination with the Net Filter
```
sudo tcpdump -i eth0 dest net 172.16.146.2.0/24
```
Protocol Filter
```
sudo tcpdump -i eth0 udp
```
Protocol Number Filter
```
sudo tcpdump -i eth0 proto 17
```
Port Filter
```
sudo tcpdump -i eth0 tcp port 443
```
Port Range Filter
```
sudo tcpdump -i eth0 portrange 0-1024
```
Less/Greater Filter
```
sudo tcpdump -i eth0 less 64

sudo tcpdump -i eth0 greater 500
```
Above was an excellent example of using `less`. We can utilize the modifier `greater 500` to only show me packets with 500 or more bytes. It came back with a unique response in the ASCII.

AND Filter
```
sudo tcpdump -i eth0 host 192.168.0.1 and port 23
```
OR Filter
```
sudo tcpdump -r sus.pcap icmp or host 172.16.146.1
```
NOT Filter
```
sudo tcpdump -r sus.pcap not icmp
```
Basic Capture With No Filter
```
sudo tcpdump -i eth0
```
### Pre-Capture Filters VS. Post-Capture Processing

When utilizing filters, we can apply them directly to the capture or apply them when reading a capture file. By applying them to the capture, it will drop any traffic not matching the filter. This will reduce the amount of data in the captures and potentially clear out traffic we may need later, so use them only when looking for something specific, such as troubleshooting a network connectivity issue. When applying the filter to capture, we have read from a file, and the filter will parse the file and remove anything from our terminal output not matching the specified filter. Using a filter in this way can help us investigate while saving potential valuable data in the captures. It will not permanently change the capture file, and to change or clear the filter from our output will require we rerunning our command with a change in the syntax.

Using the `-S` switch will display absolute sequence numbers, which can be extremely long. Typically, tcpdump displays relative sequence numbers, which are easier to track and read. However, if we look for these values in another tool or log, we will only find the packet based on absolute sequence numbers. For example, 13245768092588 to 100.

The `-v`, `-X`, and `-e` switches can help you increase the amount of data captured, while the `-c`, `-n`, `-s`, `-S`, and `-q` switches can help reduce and modify the amount of data written and seen.

Many handy options that can be used but are not always directly valuable for everyone are the `-A` and `-l` switches. `A` will show only the ASCII text after the packet line, instead of bot ASCII and Hex. `L` will tell tcpdump to output packets in a different mode. L will line buffer instead of pooling and pushing in chunks. It allows us to send the output directly to another tool such as grep using a pipe `|`.
```
sudo tcpdump -Ar telnet.pcap

    21:12:43.528695 IP 192.168.0.1.telnet > 192.168.0.2.1550: Flags [P.], seq 157:217, ack 216, win 17376, options [nop,nop,TS val 2467382 ecr 10234022], length 60
    E..p;...@..p..............c.......C........
    .%.6..(.Last login: Sat Nov 27 20:11:43 on ttyp2 from bam.zing.org

    21:12:43.546441 IP 192.168.0.2.1550 > 192.168.0.1.telnet: Flags [.], ack 217, win 32120, options [nop,nop,TS val 10234152 ecr 2467382], length 0
    E..4FP@.@.s...................d...}x.......
    ..)(.%.6
    21:12:43.548353 IP 192.168.0.1.telnet > 192.168.0.2.1550: Flags [P.], seq 217:705, ack 216, win 17376, options [nop,nop,TS val 2467382 ecr 10234152], length 488
    E...;...@.................d.......C........
    .%.6..)(Warning: no Kerberos tickets issued.
    OpenBSD 2.6-beta (OOF) #4: Tue Oct 12 20:42:32 CDT 1999

    Welcome to OpenBSD: The proactively secure Unix-like operating system.

    Please use the sendbug(1) utility to report bugs in the system.
    Before reporting a bug, please try to reproduce it with the latest
    version of the code.  With bug reports, please try to ensure that
    enough information to reproduce the problem is enclosed, and if a
    known fix for it exists, include that as well.


    21:12:43.566442 IP 192.168.0.2.1550 > 192.168.0.1.telnet: Flags [.], ack 705, win 32120, options [nop,nop,TS val 10234154 ecr 2467382], length 0
    E..4FQ@.@.s...................e...}x.0.....
    ..)*.%.6
```
Notice how it has the ASCII values shown below each output line because of our use of -A. This can be helpful when quickly looking for something human-readable in the output.
```
sudo tcpdump -Ar http.cap -l | grep 'mailto:*'

    reading from file http.cap, link-type EN10MB (Ethernet), snapshot length 65535
    <a href="mailto:ethereal-web[AT]ethereal.com">ethereal-web[AT]ethereal.com</a>
    <a href="mailto:free-support[AT]thewrittenword.com">free-support[AT]thewrittenword.com</a>
    <a href="mailto:ethereal-users[AT]ethereal.com">ethereal-users[AT]ethereal.com</a>
    <a href="mailto:ethereal-web[AT]ethereal.com">ethereal-web[AT]ethereal.com</a>
```
It was an example of piping a capture to grep. Using `-l` in this way allowed us to examine the capture quickly and grep for keywords or formatting we suspected could be there. In this case, we used the `-l` to pass the output to `grep` and looking for any instance of the phrase `mailto:*`. This shows us every line with our search in it, and we can see the results above. Using modifiers and redirecting output can be a quick way to scrape websites for email addresses, naming standards, and much more.

We can dig as deep as we wish into the packets we captured. It requires a bit of knowledge of how the protocols are structured, however. For example, if we wanted to see only packets with the TCP SYN flag set, we could use the following command:
```
sudo tcpdump -i eth0 'tcp[13] & 2 != 0'
```
Here we are looking for TCP Protocol Flags. In particular, this is counting to the 13th byte in the structure and looking at the 2nd bit. If it is set to `1` or `ON`, the SYN flag is set. Our results include only packets with the TCP SYN flag set from what we see above.

## TShark

### Basic Usage

With the basic string in the command line above, we utilize TShark to capture on en0, specified with the `-i` flag and the `-w` option to save the capture to a specified output file. Utilizing TShark is very similar to TCPDump in the filters and switches we can use. 
```
tshark -i 1 -w /tmp/test.pcap

sudo tshark -i eth0 -w /tmp/test.pcap

sudo tshark -i eth0 -f "host 172.16.146.2"
```
`-f` allows us to apply filters to the capture. In the example, we utilized host, but you can use almost any filter Wireshark recognizes. 

## Termshark

Termshark is a Text-based User Interface (TUI) application that provides the user with a Wireshark-like interface right in your terminal window.

# MISC

## Callback services
* pingb.in
* Burp Collaborator (paid service)
* interactsh server
* dnslog.cn

## Adding DNS records on hosts file
```
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```
## Getting Semi-Interactive Shell after Reverse Shell
```
script /dev/null -c bash
```
## Search files with SUID bit set
```
find / -perm -u=s -type f 2>/dev/null
```
## Custom wordlist
```
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```
## Hashing
```
echo -n "p@ssw0rd123456" | md5sum
```
### Base64 Encode
```
echo https://www.hackthebox.eu/ | base64
```
### Base64 Decode
```
echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d
```
### Hex Encode
```
echo https://www.hackthebox.eu/ | xxd -p
```
### Hex Decode
```
echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r
```
### Rot13 Encode
```
echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```
### Rot13 Decode
```
echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```
## Payload Lists

https://github.com/payloadbox/xss-payload-list

https://github.com/danielmiessler/SecLists.git

https://github.com/swisskyrepo/PayloadsAllTheThings.git

https://github.com/fuzzdb-project/fuzzdb.git

## Exploit Resources

https://www.exploit-db.com/

https://www.rapid7.com/db/
