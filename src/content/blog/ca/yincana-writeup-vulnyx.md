---
author: Lenam  
pubDatetime: 2024-07-18T15:22:00Z  
title: WriteUp Yincana - Vulnyx
slug: yincana-writeup-vulnyx-ca  
featured: false  
draft: false  
ogImage: "assets/yincana/OpenGraph.png"  
tags:  
  - writeup  
  - vulnyx  
  - xxe  
  - xslt  
  - password cracking  
  - binary planting  
  - sudo 
description:  
  Disfruta de la màquina Yincana i no oblidis regalar flors.
lang: ca  
---

Com sempre, demano disculpes pels errors ortogràfics i per no conèixer els noms de les tècniques; sóc un desenvolupador que es submergeix en el món del hacking. Crec que aquesta vegada és una màquina difícil, encara que algú pot trobar maneres més fàcils de comprometre-la.

Per a la creació, he utilitzat algunes de les tecnologies amb les quals he treballat durant la meva vida professional: PHP, XSLT i NodeJs. És un CTF difícil, i es necessita paciència.

Disfruta de la màquina Yincana i **no oblidis regalar flors**. 😉

Habilitats: XXE, XSLT, IDOR?, Crackeig de contrasenyes (SHA2, RSA).

## Taula de continguts

## Enumeració

`$ nmap -sV -sC -A -p 80,22 192.168.1.120 -oN nmap2.txt -vvv  `

<img alt="Imatge" src="/assets/yincana/img_p0_1.png"/>

<img alt="Imatge" src="/assets/yincana/img_p0_2.png" />

<img alt="Imatge" src="/assets/yincana/img_p0_3.png" />

`$ gobuster dir --url http://192.168.1.120/ --wordlist **/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt** -x .php,.htm,.html,.txt,.db,.bak,.pdf -t 20`

<img alt="Imatge" src="/assets/yincana/img_p0_4.png" />

A la pàgina chat.html, trobem aquesta informació. La data es actualitza cada minut, i trobem un nom de domini.

<img alt="Imatge" src="/assets/yincana/img_p1_3.png" />

`# echo "192.168.1.120 yincana.nyx" >> /etc/hosts`

<img alt="Imatge" src="/assets/yincana/img_p1_1.png" />

Continuem buscant arxius aquesta vegada en l'host virtual yincana.nyx.

<img alt="Imatge" src="/assets/yincana/img_p1_2.png" />

`$ gobuster dir --url http://yincana.nyx/ --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.htm,.html,.txt,.db,.bak,.pdf -t 20 `

<img alt="Imatge" src="/assets/yincana/img_p2_1.png" />

Sembla que l'arxiu image.php?id=1 és per mostrar o descarregar imatges de les pàgines:

<img alt="Imatge" src="/assets/yincana/img_p2_2.png" />

Si busquem subdominis, no en trobarem cap.

## Intrusió

Introduïm la nostra IP a la URL i comencem a escoltar amb netcat; sembla que rebem una senyal.

<img alt="Imatge" src="/assets/yincana/img_p3_1.png" />

Creem una pàgina d'exemple que mostri alguna cosa, l'enviem i busquem la imatge a images.php?id=X, la trobem.

<img alt="Imatge" src="/assets/yincana/img_p3_3.png" />

Si observem més de prop, sembla ser un "navegador sense cap" (puppeteer o un sistema similar).

<img alt="Imatge" src="/assets/yincana/img_p3_2.png" />

Fem servir una petita llista de ports comuns per HTTP.

<https://github.com/danielmiessler/SecLists/blob/master/Discovery/Infrastructure/common-http-ports.txt>

i creem un script en JavaScript per analitzar ports locals utilitzant el navegador sense cap.

<img alt="Imatge" src="/assets/yincana/img_p4_1.png" />

i descobrim el port 80 (al qual ja teníem accés des de fora) i el port 7001 (probablement només accessible des de localhost, ja que no el vam trobar amb nmap des de fora).

<img alt="Imatge" src="/assets/yincana/img_p4_2.png" />

Creem un altre script amb un iframe per veure la imatge del que hi ha al port local 7001.

<img alt="Imatge" src="/assets/yincana/img_p4_3.png" />

i obtenim un missatge: "Need url parameter", sembla ser el servei intern que gestiona la generació d'aquestes imatges, afegim el paràmetre URL amb “file:///etc/passwd” i continuem provant, també demana “Need id parameter”, així que passem ambdós:

<img alt="Imatge" src="/assets/yincana/img_p5_1.png" />

Ara a yincana.nyx/image.php?id=41 obtenim

<img alt="Imatge" src="/assets/yincana/img_p5_2.png" />

i a yincana.nyx/image.php?id=200 obtenim

<img alt="Imatge" src="/assets/yincana/img_p5_3.png" />

Ja tenim un LFI.

Buscant i escanejant diversos arxius locals per obtenir informació i intentar RCE (logs, variables d'entorn, arxius de configuració, ...) trobo l'id_rsa de l'usuari jazmin, però el trobo en una imatge i he de convertir-lo a text per utilitzar-lo.

<img alt="Imatge" src="/assets/yincana/img_p6_1.png" /><img alt="Imatge" src="/assets/yincana/img_p6_2.png" />

Instal·lo tesseract OCR.

`$ sudo apt install tesseract-ocr`

Modifico la imatge amb GIMP per donar-li més resolució, contrast i només prendre la part del text. A més de tesseract-ocr, també provem Google Lens App (una bona opció), Gemini, ChatGPT (problemes de la IA amb filtres de seguretat, prompts llargs), i altres OCRs en línia, no puc obtenir una clau completament correcta de la imatge.

Analitzo el text a la cerca de caràcters inacceptables i el comparo visualment amb la imatge per corregir alguns errors.

Al final, després d'un esforç, obtinc una clau id_rsa correcta però xifrada per a jazmin.

<img alt="Imatge" src="/assets/yincana/img_p7_1.png" />

La crackejem amb john i rockyou.txt molt ràpidament ;)

<img alt="Imatge" src="/assets/yincana/img_p7_2.png" />

<img alt="Imatge" src="/assets/yincana/img_p7_3.png" />

Iniciem sessió amb l'usuari jazmin i l'id_rsa al servidor a través de ssh amb la frase de pas “flores”:

<img alt="Imatge" src="/assets/yincana/img_p7_4.png" />

Podem canviar a un altre usuari amb un nom de flor i a un altre usuari amb un nom de flor en un bucle recursiu utilitzant sudo -u usuari /bin/bash.

Hi ha uns 50 usuaris amb noms de flors i podem canviar d'un a un altre utilitzant sudo per a bash. És com un peix que es mossega la cua i cada usuari pot executar bash com el següent.

<img alt="Imatge" src="/assets/yincana/img_p8_1.png" />

Estan els usuaris normals (root, mail, www-data, …), 50 usuaris amb noms de flors i un usuari anomenat “manel”.

¡Tenim accés a tots els usuaris amb noms de flors!

A la carpeta d'inici de jazmin, sembla que hi ha l'aplicació que exposa el servei del port 7001 i s'utilitza per crear les imatges de la pàgina de flors.

<img alt="Imatge" src="/assets/yincana/img_p8_2.png" />

D'altra banda, també trobem els dos llocs web, el predeterminat d'Apache amb els arxius chat.html i index.html, i el lloc web de flors.

A l'arxiu index.php del lloc web de flors, veiem que les credencials de la base de dades es prenen de les variables d'entorn.

<img alt="Imatge" src="/assets/yincana/img_p9_1.png" />

Intentem llegir les variables d'entorn del servidor Apache, però no podem, o intentem iniciar sessió com a www-data inserint una reverse shell, però no tenim permisos a les carpetes públiques del lloc web, ni hem trobat un LFI real on puguem incloure un arxiu per interpretar en PHP. Al final, trobem les credencials de la base de dades configurades en l'host virtual yincana.nyx.conf.

<img alt="Imatge" src="/assets/yincana/img_p9_2.png" />

Entrem a la base de dades per examinar el contingut i trobem una taula d'usuaris amb les seves contrasenyes (aparentment hasheejades).

<img alt="Imatge" src="/assets/yincana/img_p10_1.png" />

Obtenim totes les dades possibles, comentaris de la base de dades, taula d'usuaris i camps. Trobem un comentari al camp de contrasenyes de la taula d'usuaris que indica el tipus de hash (SHA256).

<img alt="Imatge" src="/assets/yincana/img_p10_3.png" />

Intentem crackejar les contrasenyes, però només aconseguim crackejar la contrasenya de l'usuari "margarita".

<img alt="Imatge" src="/assets/yincana/img_p10_2.png" />

Intentem accedir via SSH amb l'usuari margarita i la contrasen

ya flors, però no tenim accés. No obstant això, teníem accés a tots els usuaris amb noms de flors, així que accedim a l'usuari “margarita” des de l'usuari “jazmin”.

<img alt="Imatge" src="/assets/yincana/img_p11_2.png" />

Ara podem executar el binari xsltproc com a manel amb la contrasenya de margarita.

Verifiquem què és aquest binari i per a què serveix; és un processador XSLT, el fem servir per intentar XXE. No està en gtfobins, però encara es pot abusar del seu privilegi sudo.

Informació del binari.

<img alt="Imatge" src="/assets/yincana/img_p11_1.png" />

Podem llegir arxius amb privilegis d'usuari manel (XXE), intentem llegir la clau RSA, però no en té cap. Intentem llegir la bandera user.txt.

<img alt="Imatge" src="/assets/yincana/img_p12_1.png" />

Processarem l'XSL de l'arxiu XML amb el binari xsltproc utilitzant sudo i l'usuari manel:

Hem obtingut la primera bandera user.txt.

<img alt="Imatge" src="/assets/yincana/img_p12_2.png" />

Creem una clau id_rsa per intentar incloure la clau pública als authorized_keys de manel i utilitzar-la per connectar-nos via SSH.

<img alt="Imatge" src="/assets/yincana/img_p12_3.png" />

Podem executar el binari xsltproc amb sudo, la contrasenya de margarita com a manel i el paràmetre “output”. Això ens permet crear arxius amb contingut processat per l'xslt amb privilegis de manel.

Creem un arxiu XML sense dades i un altre amb l'XSLT per processar-lo i obtenir id_rsa.pub com a resultat.

<img alt="Imatge" src="/assets/yincana/img_p13_1.png" />

Executem la següent ordre per intentar incloure la clau pública RSA a l'usuari manel.

`margarita@yincana:/tmp$ sudo -u manel /usr/bin/xsltproc -o /home/manel/.ssh/authorized_keys crea_rsa.xml dades.xml` 

<img alt="Imatge" src="/assets/yincana/img_p13_2.png" />

Intentem accedir a manel via SSH amb la clau RSA generada des del nostre kali.

<img alt="Imatge" src="/assets/yincana/img_p13_3.png" />
  
També podríem realitzar escriptura d'arxius privilegiada utilitzant EXSLT, més informació a:
<https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection#write-files-with-exslt-extension>

¡Genial! Accedim a l'usuari manel, el primer usuari sense nom de flor.

Per curiositat, l'arxiu authorized_keys es veu així, ho arreglem.

<img alt="Imatge" src="/assets/yincana/img_p14_1.png" />

## Obtenir la bandera root.txt

Repassem: Tenim accés a tots els usuaris amb noms de flors i a l'usuari manel. Intentem escalar privilegis a l'usuari root o obtenir la bandera root.

Fem servir pspy64 per monitoritzar els processos que podria estar executant root.

<img alt="Imatge" src="/assets/yincana/img_p14_2.png" />

Trobar un procés de root per a l'arxiu xsltproc que hem utilitzat anteriorment i sembla que crea els missatges per al /chat.html inicial.

<img alt="Imatge" src="/assets/yincana/img_p14_3.png" />

Podem modificar l'arxiu /home/mensaje.xml implicat en aquest procés perquè l'usuari manel pertany al grup backupchat.

<img alt="Imatge" src="/assets/yincana/img_p14_4.png" />

L'arxiu conté les dades (en format XML) dels missatges de xat que es mostren a la pàgina inicial, modifiquem l'arxiu /home/mensajes.xml per intentar obtenir la bandera root.txt a través de XXE.

<img alt="Imatge" src="/assets/yincana/img_p15_1.png" />

Esperem 1 o 2 minuts i la bandera root.txt apareixerà a l'adreça inicial:

http://192.168.1.120/chat.html

<img alt="Imatge" src="/assets/yincana/img_p15_2.png" />

## Escalada

No hem aconseguit l'escalada de privilegis.

Intentem l'escriptura d'arxius amb EXSLT, però per aconseguir-ho necessitem modificar l'arxiu d'estil XSL i només podem modificar l'arxiu de dades XML, o no sabem o no podem fer-ho.

Analitzem el procés utilitzat per a la lectura d'arxius privilegiada per obtenir més informació. Obtenim /etc/shadow però no podem crackejar la contrasenya de root. Intentem llegir dades dels directoris /proc/, /root, etc.

Després d'un temps, molts dels arxius no es poden veure perquè contenen caràcters no permesos en XML o bytes nuls, alguns sí podem veure i al mirar els arxius trobem la tasca CRON programada:

<img alt="Imatge" src="/assets/yincana/img_p16_1.png" />

Trobar dues tasques configurades, la que estem explotant amb XSLT i una altra que executa un "chatbackup" el 1 de gener de cada any. Busquem aquest arxiu i el trobem al nostre directori, podem modificar-lo però hauríem d'esperar fins al 1 de gener per executar-lo. Però això ens dóna una pista.

<img alt="Imatge" src="/assets/yincana/img_p16_2.png" />

La tasca pot executar aquest arxiu perquè està inclòs al PATH (primer quadre vermell a la imatge del crontab) del directori /home/manel/.local/bin.

<img alt="Imatge" src="/assets/yincana/img_p16_3.png" />

L'ordre que s'executa cada minut utilitza "date" sense una ruta absoluta.

<img alt="Imatge" src="/assets/yincana/img_p17_1.png" />
<img alt="Imatge" src="/assets/yincana/img_p17_2.png" />

Busquem on es troba el binari date, i està a /usr/bin/date, atès que la ruta /home/manel/.local/bin té permisos d'escriptura i ve abans de /usr/bin, podem intentar reemplaçar “date” amb el nostre “date” maliciós.

<img alt="Imatge" src="/assets/yincana/img_p17_3.png" />
<img alt="Imatge" src="/assets/yincana/img_p17_4.png" />

Esperem un minut per veure si apareix un bash amb SUID a /tmp.

<img alt="Imatge" src="/assets/yincana/img_p17_5.png" />

¡Felicitats, som root!