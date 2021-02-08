---
layout: single
title:  "Analysis of SSH keys found in the wild"
---

In 2018 I was contracted to help a large organization with a very distributed and remote structure. One of the things that I found was that the organization does not have a strict policy regarding the creation, storage and lifecycle of SSH keys.

I decided to look into this issue in general, so in Feb 2019 wrote a crawler that looked for SSH keys around the web - public repos, s3 bucket with bad permissions, data dumps from companies and so on. 

From this I got 4807 keys. Next I wrote a small python script that tried the SSH keys - just autenticate and close the connection, without opening any channels as to not actually access the target systems which would be illegal.

I managed to authenticate into 221 hosts, 5 were FreeBSD, 1 was MacOS, 3 were Linux on ARM64, and the rest were Linux x64. This means I have 221 working keys found on the web and no way to notify their owners they should change their keys.

General interesting statistics:

- Of the 4807 keys 966 were malformed and 1036 were encrypted (20%). Of the 1036 encrypted I could break 88 passwords using dictionaries and an additional 41 passwords using John-the-ripper on a 3-year old 8-core Xeon workstation after a month of brute-forcing.

- Sizes (all were SHA256):
```
root@DESKTOP-MR4OQPJ:~/keys# for i in id_rsa* ; do ssh-keygen -l -f $i; done | sed 's/:.*//' | sort | uniq -c | sort -n -k 2
      2 1023 SHA256
     37 1024 SHA256
      1 2047 SHA256
   2187 2048 SHA256
      1 3000 SHA256
      1 4048 SHA256
    572 4096 SHA256
      3 8192 SHA256
      1 16384 SHA256
```
    I don''t get the wird sizes: 1023-bit, 2047-bit, 3000-bit, and 4048-bit. Anyone have an idea?
    
- Encryption type:
```
root@DESKTOP-MR4OQPJ:~/enc# grep -h DEK-Info id_rsa* | sed 's/,.*//' | sort | uniq -c
    665 DEK-Info: AES-128-CBC
      2 DEK-Info: AES-256-CBC
     94 DEK-Info: DES-EDE3-CBC
```
    Why still use DES keys?
    
   for keys that I could not break:
```
    531 DEK-Info: AES-128-CBC
      2 DEK-Info: AES-256-CBC
     66 DEK-Info: DES-EDE3-CBC
```
    
- Distributions (in 2019, from uname)
 - 87 were Ubuntu
 - 38 were RHEL/Centos 6
 - 25 were RHEL/Centos 7
 - 7 were Amazon
 - 5 were RHEL/Centos 5
 - 2 were Debian
 - 2 were CoreOS
 - 1 was Gentoo
 - 1 was Fedore32
 - 2 were armv7l
 - 1 was armv5tel 
 - the rest I could not identify from uname -a
 
- Most common kernels (in 2019, from uname)
 - 44 were Linux 2.6.x
 - 39 were Linux 4.4.x
 - 28 were Linux 4.15.x
 - 35 were Linux 3.10.x
 - 15 were Linux 3.13.x
 - 13 were Linux 4.9.x
 
Last week (after two years!) I reran the test against the 221 working keys and 179 still work. To make sure these are not honepots I added to the testing script a checked for the length of the remote .bash_history file, and none seem to be honeypots.

