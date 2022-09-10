# Crack the hash

All hashes will be stored in hash.txt file.

## Task 1

### 48bb6e862e54f2a795ffc4e541caed4d

```
hashid -m hash.txt

--File 'hash.txt'--
Analyzing '48bb6e862e54f2a795ffc4e541caed4d'
[+] MD2 
[+] MD5 [Hashcat Mode: 0]
[+] MD4 [Hashcat Mode: 900]
[+] Double MD5 [Hashcat Mode: 2600]
[+] LM [Hashcat Mode: 3000]
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 [Hashcat Mode: 8600]
[+] Skype [Hashcat Mode: 23]
[+] Snefru-128 
[+] NTLM [Hashcat Mode: 1000]
[+] Domain Cached Credentials [Hashcat Mode: 1100]
[+] Domain Cached Credentials 2 [Hashcat Mode: 2100]
[+] DNSSEC(NSEC3) [Hashcat Mode: 8300]
[+] RAdmin v2.x [Hashcat Mode: 9900]
--End of file 'hash.txt'--⏎
```
Let's try as MD5:
```
hashcat -a 0 -m 0 hash.txt rockyou.txt -O -w 3

<SNIP>
48bb6e862e54f2a795ffc4e541caed4d:easy
<SNIP>
```

### CBFDAC6008F9CAB4083784CBD1874F76618D2A97 

```
hashid -m hash.txt

--File 'hash.txt'--
Analyzing 'CBFDAC6008F9CAB4083784CBD1874F76618D2A97'
[+] SHA-1 [Hashcat Mode: 100]
[+] Double SHA-1 [Hashcat Mode: 4500]
[+] RIPEMD-160 [Hashcat Mode: 6000]
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn [Hashcat Mode: 190]
[+] Skein-256(160) 
[+] Skein-512(160) 
--End of file 'hash.txt'--⏎
```
Let's try as SHA-1:
```
hashcat -a 0 -m 100 hash.txt rockyou.txt -O -w 3

<SNIP>
cbfdac6008f9cab4083784cbd1874f76618d2a97:password123
<SNIP>
```

### 1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032

```
hashid -m hash.txt

--File 'hash.txt'--
Analyzing '1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032'
[+] Snefru-256 
[+] SHA-256 [Hashcat Mode: 1400]
[+] RIPEMD-256 
[+] Haval-256 
[+] GOST R 34.11-94 [Hashcat Mode: 6900]
[+] GOST CryptoPro S-Box 
[+] SHA3-256 [Hashcat Mode: 5000]
[+] Skein-256 
[+] Skein-512(256) 
--End of file 'hash.txt'--⏎
```
Let's try as SHA-256:
```
hashcat -a 0 -m 1400 hash.txt rockyou.txt -O -w 3

<SNIP>
1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032:letmein
<SNIP>
```

### $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom

```
hashid -m hash.txt

--File 'hash.txt'--
Analyzing '$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom'
[+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
[+] Woltlab Burning Board 4.x 
[+] bcrypt [Hashcat Mode: 3200]
--End of file 'hash.txt'--⏎
```
This is a Bcrypt hash. Cracking bcrypt is very very slow, so it is suggested to use very powerful GPU or cloud services, or a little wordlist. You can also try to search the cracked bcrypt hash on some DB online. From hashes.com, the bcrypt hash was inside an online DB as:
```
$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom:$HEX[b0e0]
```
This result is not complete, but we get a good tip: the first letter of the password is `b` and the third is `e`, and the password has 4 characters. In this way we can reduce the wordlist by searching only for words with those characteristics.

By using Hashcat, we can run:
```
hashcat -a 0 -m 3200 hash.txt rockyou.txt -O -w 3

<SNIP>
$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom:bleh
<SNIP>
```

### 279412f945939ba78ce0758d3fd83daa

```
hashid -m hash.txt

--File 'hash.txt'--
Analyzing '279412f945939ba78ce0758d3fd83daa'
[+] MD2 
[+] MD5 [Hashcat Mode: 0]
[+] MD4 [Hashcat Mode: 900]
[+] Double MD5 [Hashcat Mode: 2600]
[+] LM [Hashcat Mode: 3000]
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 [Hashcat Mode: 8600]
[+] Skype [Hashcat Mode: 23]
[+] Snefru-128 
[+] NTLM [Hashcat Mode: 1000]
[+] Domain Cached Credentials [Hashcat Mode: 1100]
[+] Domain Cached Credentials 2 [Hashcat Mode: 2100]
[+] DNSSEC(NSEC3) [Hashcat Mode: 8300]
[+] RAdmin v2.x [Hashcat Mode: 9900]
--End of file 'hash.txt'--⏎
```
It is a MD4 that we can find on crackstation.net
```
279412f945939ba78ce0758d3fd83daa:Eternity22
```


## Task 2

This task increases the difficulty. All of the answers will be in the classic rockyou password list.

### F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85

```
hashid -m hash.txt

--File 'hash.txt'--
Analyzing 'F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85'
[+] Snefru-256 
[+] SHA-256 [Hashcat Mode: 1400]
[+] RIPEMD-256 
[+] Haval-256 
[+] GOST R 34.11-94 [Hashcat Mode: 6900]
[+] GOST CryptoPro S-Box 
[+] SHA3-256 [Hashcat Mode: 5000]
[+] Skein-256 
[+] Skein-512(256) 
--End of file 'hash.txt'--⏎
```
It is a SHA-256:
```
hashcat -a 0 -m 1400 hash.txt rockyou.txt -O -w 3

<SNIP>
f09edcb1fcefc6dfb23dc3505a882655ff77375ed8aa2d1c13f640fccc2d0c85:paule
<SNIP>
```

### 1DFECA0C002AE40B8619ECF94819CC1B

```
hashid -m hash.txt

--File 'hash.txt'--
Analyzing '1DFECA0C002AE40B8619ECF94819CC1B'
[+] MD2 
[+] MD5 [Hashcat Mode: 0]
[+] MD4 [Hashcat Mode: 900]
[+] Double MD5 [Hashcat Mode: 2600]
[+] LM [Hashcat Mode: 3000]
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 [Hashcat Mode: 8600]
[+] Skype [Hashcat Mode: 23]
[+] Snefru-128 
[+] NTLM [Hashcat Mode: 1000]
[+] Domain Cached Credentials [Hashcat Mode: 1100]
[+] Domain Cached Credentials 2 [Hashcat Mode: 2100]
[+] DNSSEC(NSEC3) [Hashcat Mode: 8300]
[+] RAdmin v2.x [Hashcat Mode: 9900]
--End of file 'hash.txt'--⏎
```

It is NTLM:
```
hashcat -a 0 -m 1000 hash.txt rockyou.txt -O -w 3

<SNIP>
1dfeca0c002ae40b8619ecf94819cc1b:n63umy8lkf4i
<SNIP>
```

### $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.

The text provides also the salt: aReallyHardSalt.

Note that the salt is already inside the hash.
```
hashid -m hash.txt

--File 'hash.txt'--
Analyzing '$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.'
[+] SHA-512 Crypt [Hashcat Mode: 1800]
--End of file 'hash.txt'--⏎
```
It is SHA-512 Crypt:
```
hashcat -a 0 -m 1800 hash.txt rockyou.txt -O -w 3

<SNIP>
$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.:waka99
<SNIP>
```

### e5d8870e5bdd26602cab8dbe07a942c8669e56d6

The text provides also the salt: tryhackme.

Sadly, this time the salt is not inside the provided hash. So, inside `hash.txt` we write:
```
e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme
```
Then:
```
hashid -m hash.txt

--File 'hash.txt'--
Analyzing 'e5d8870e5bdd26602cab8dbe07a942c8669e56d6'
[+] SHA-1 [Hashcat Mode: 100]
[+] Double SHA-1 [Hashcat Mode: 4500]
[+] RIPEMD-160 [Hashcat Mode: 6000]
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn [Hashcat Mode: 190]
[+] Skein-256(160) 
[+] Skein-512(160) 
--End of file 'hash.txt'--⏎ 
```
According to the analysis, is not anyone of these modes. It is `160 | HMAC-SHA1 (key = $salt)`:
```
hashcat -a 0 -m 160 hash.txt rockyou.txt -O -w 3

<SNIP>
e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme:481616481616
<SNIP>
```