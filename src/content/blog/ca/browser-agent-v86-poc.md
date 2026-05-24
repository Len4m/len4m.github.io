---
author: Lenam
pubDatetime: 2026-05-24T00:00:00Z
title: "Browser Agent v86 POC: una VM Linux, un LLM i tools d'agent dins del navegador"
urlSlug: browser-agent-v86-poc
featured: true
draft: false
ogImage: "../../../assets/images/browser-agent-v86-poc/OpenGraph.png"
tags:
  - AI
  - LLM
  - navegador
  - WebGPU
  - WebAssembly
  - v86
  - Linux
description:
  "Amb Browser Agent v86 POC pots provar una VM Linux x86, xatejar amb un LLM local i automatitzar tasques dins de la VM, tot dins del navegador. És privat i gratuït: tot passa al teu equip, sense dependre de servidors externs."
lang: ca
translationId: browser-agent-v86-poc
---
![](../../../assets/images/browser-agent-v86-poc/OpenGraph.png)

## Taula de contingut

## Introducció

I si poguessis executar una **màquina virtual** directament al navegador? Amb [**v86**](https://github.com/copy/v86) això és una realitat: emula maquinari x86 configurable (**RAM**, **VRAM**, discos), de manera que pots instal·lar un sistema operatiu de 32 bits sense sortir del navegador.

I si, a més, poguessis executar un **model d'IA** en local? També és possible gràcies a **Transformers.js**, que permet descarregar i executar models al navegador. Ho explico en aquest [article](/ca/posts/transformersjs-models-ml-navegador/), i també parlo de l'entrenament al navegador amb [**TensorFlow.js**](/ca/posts/tensorflowjs-entrenar-models-navegador/).

Finalment: també pots tenir, al navegador, un **agent d'IA** que utilitzi Transformers.js per executar comandes a la VM de v86; tot això ja és possible amb **Browser Agent v86 POC**, una prova de concepte que permet experimentar executant una **VM Linux x86**, un **xat amb LLM local** i un conjunt de **tools d'agent** directament des del navegador.

![](../../../assets/images/browser-agent-v86-poc/20260524_004649_image.png)

- Repositori:[Len4m/browser-agent-v86-poc](https://github.com/Len4m/browser-agent-v86-poc)
- Demo:[https://browseragent.icu/](https://browseragent.icu/)

El projecte es troba en fase beta, específicament en la versió **0.9.0-beta.1** en el moment d'escriure aquest article. Actualment només està disponible en espanyol, tot i que hi ha la intenció d'afegir suport per a altres idiomes en el futur.

## Què és Browser Agent v86 POC

Browser Agent v86 POC és un laboratori web per barrejar tres peces que normalment viuen separades:

- Una màquina virtual Linux x86 executant-se al navegador amb **v86**;
- Un xat amb models locals utilitzant **Transformers.js** i WebGPU/WASM;
- Un sistema de tools perquè l'agent pugui executar comandes dins de la VM.

La idea no és substituir un entorn real de treball, sinó crear un espai reproduïble, portable i fàcil de llançar per a proves, formació, investigació i automatització controlada. Tot passa des d'una aplicació web estàtica.

### Per què fer-ho al navegador

El navegador modern ja no és només una capa d'interfície. Amb WebAssembly, WebGPU, Web Workers, `SharedArrayBuffer` i memòria cau local, pot executar càrregues força serioses sense dependre sempre d'un backend.

A més, el més important: si tot s'executa al teu navegador, tot és 100% privat i gratuït, sempre que no tinguis instal·lada alguna extensió o utilitzis un navegador que t'espiï.

### Connectivitat de xarxa: proxy opcional amb wsnic

Perquè la VM tingui accés a internet des del mateix navegador, cal recórrer a un petit truc: aixecar un proxy local anomenat **wsnic** que actua com a pont entre la teva màquina real i la virtual. És a dir, tot i que la resta funciona 100% al teu navegador, la connectivitat de xarxa només és possible executant wsnic al teu equip. El més habitual és iniciar-lo fàcilment mitjançant Docker, i la VM s'hi connecta per WebSocket a:

```txt
ws://127.0.0.1:8086/wsnic
```

Això implica que tota la comunicació de xarxa de la VM passa pel teu equip, mai pel servidor web ni per intermediaris externs. Així, la VM utilitzarà **la teva connexió local i estarà integrada a la teva xarxa**, podent fer proves reals de xarxa, participar en CTFs, explorar serveis locals, etc.


![](../../../assets/images/browser-agent-v86-poc/20260524_013011_image.png)

Si no tens wsnic executant-se, la VM funcionarà igual però romandrà **aïllada d'internet i de la teva xarxa**. En altres paraules, la xarxa és totalment opcional per a l'experiència, i només depèn que el proxy estigui arrencat localment.

Quan executes l'aplicació publicada a internet, `127.0.0.1` continua referint-se a l'equip de l'usuari: no hi ha exposició ni reenviament de trànsit fora del teu control. Les comandes necessàries per llançar el proxy wsnic apareixen integrades a la mateixa app, i pots arrencar-lo/aturar-lo en qualsevol moment per experimentar amb la connectivitat segons et convingui.

### Models d'IA

Actualment, l'aplicació permet utilitzar models de Transformers.js o Ollama. Tots dos mètodes fan servir models d'intel·ligència artificial que s'executen a la teva pròpia GPU, per la qual cosa és important disposar d'una bona targeta gràfica i prou memòria.

#### Transformers.js

Per utilitzar els models de Transformers.js cal disposar d'un navegador que suporti WebGPU. Hi ha diversos models preconfigurats, però també pots configurar qualsevol altre model ONNX i es descarregarà automàticament.

- Més informació: https://caniuse.com/webgpu  
- Llistat de models ONNX compatibles amb Transformers.js:  
https://huggingface.co/models?pipeline_tag=text-generation&library=transformers.js&sort=trending

#### Ollama

També hi ha una integració opcional amb **Ollama**. En aquest cas, el navegador fa peticions al servei local de l'usuari a `http://127.0.0.1:11434/api/chat`.

Perquè Ollama funcioni correctament, cal configurar la variable d'entorn `OLLAMA_ORIGINS`; això permetrà que Ollama concedeixi accés.

Exemple:

```bash
OLLAMA_ORIGINS=https://browseragent.icu,https://www.browseragent.icu ollama serve
```

#### Rendiment i integració

Després de diverses proves, els models d'Ollama ofereixen un rendiment molt superior respecte a Transformers.js, tant per les limitacions pròpies del navegador com per la manera en què Ollama s'integra amb les tools de l'agent. Mentre que a Transformers.js cal deduir si el model vol utilitzar una eina analitzant-ne la resposta, a Ollama això s'indica de manera clara i directa.

Confio que l'experiència i la compatibilitat amb Transformers.js aniran millorant amb el temps, i espero poder continuar actualitzant el PoC a mesura que avancin totes dues tecnologies.

### Perfils de VM

He implementat un sistema que permet crear perfils de màquina virtual a partir de fitxers de configuració en format JSON, facilitant així la personalització i el manteniment de les diferents variants d'Alpine disponibles.

A continuació, es detallen els perfils disponibles i els principals paquets que inclouen en el moment d'escriure aquest article:

| Perfil                | Principals paquets instal·lats                                                                                                      |
|-----------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `alpine-base`         | `ca-certificates`, `curl`, `nano`, `tmux`                                                                                            |
| `alpine-pentest-lite` | `ca-certificates`, `curl`, `nano`, `nmap`, `ffuf`, `python3`, `py3-pip`, `bind-tools`, `iproute2`, `tmux` (+ wordlists SecLists Web-Content) |
| `alpine-pentest-web`  | Tots els anteriors, més `nikto`, `httpx`, `perl-net-ssleay`, `perl-io-socket-ssl`, `perl-mozilla-ca`, `openssl`                     |

Aquests perfils permeten adaptar l'entorn segons la necessitat, des d'un sistema bàsic fins a un de preparat per realitzar proves de xarxa o auditories web.

En qualsevol cas, també pots instal·lar paquets addicionals si has configurat la connectivitat de xarxa, utilitzant la comanda apk.

Exemple d'instal·lació de htop:

```bash
apk add htop
```

### Snapshots

Has de tenir en compte que tot s'executa al navegador; per tant, si canvies de pàgina o recarregues el lloc perdràs l'estat de la màquina virtual. Hi ha dues opcions: pots configurar la xarxa per enviar-te les dades necessàries, o bé generar un snapshot.

Tanmateix, vés amb compte en restaurar un snapshot: perquè tot funcioni correctament, has de configurar el mateix perfil de VM amb els mateixos paràmetres. A més, el snapshot desa l'estat de la RAM, la CPU i la VM, però no inclou els canvis realitzats als discos hda.

## Ús

La manera més fàcil d'utilitzar-lo és accedint a la URL: https://browseragent.icu/, on trobaràs tot el necessari.

D'altra banda, si prefereixes executar-lo en local, també ho pots fer, però hauràs de descarregar les dependències, les imatges i compilar el repositori.

```bash
git clone https://github.com/Len4m/browser-agent-v86-poc.git
cd browser-agent-v86-poc
npm install                 # instal·la dependències
npm run prepare:local       # primera vegada: setup VM + build frontend/LLM/assets

# Pots triar una d'aquestes dues opcions per aixecar el servidor local:

npm start                   # Opció recomanada. Inclou capçaleres necessàries i suport complet per als discos hd de la VM.

# O bé, llançar un servidor simple amb Python:
cd public
python3 -m http.server 5173 # Opció alternativa. COMPTE! En aquest mode no tindràs les capçaleres necessàries i els discos hd de la VM i el LLM poden no funcionar correctament.
```

## Limitacions actuals

Això continua sent una prova de concepte. Hi ha diverses limitacions importants:

- La primera arrencada pot requerir descàrregues pesades;
- Els models locals depenen molt del navegador, el maquinari i el suport WebGPU;
- La VM necessita headers concrets per rendir bé, sobretot amb els discos hda;
- La xarxa és lenta, ves amb compte amb la quantitat de peticions.
- La VM només compta amb un nucli, ves amb compte amb la quantitat de processos en execució.
- Les Tools a transformers.js són limitades.

La intenció és mantenir el projecte com un entorn experimental clar, no vendre'l com una plataforma tancada ni com una solució de producció.

## Conclusió

Browser Agent v86 POC integra diverses tecnologies que prèviament havia explorat de manera independent: Linux al navegador, models locals mitjançant Transformers.js, WebGPU, eines d'agent i automatització reproduïble.

El resultat és un laboratori accessible directament des d'una URL, executable en local o fins i tot empaquetable com un entorn estàtic. Tot i que encara es troba en fase beta, ja permet experimentar amb fluxos molt interessants: una màquina virtual amb Linux controlable des de la interfície web, consola i xat, amb una separació clara entre la sessió humana i les accions automatitzades de l'agent.

Desenvolupar aquest PoC ha representat un veritable repte, en particular per la necessitat d'optimitzar el consum de memòria per prioritzar tant la màquina virtual com el model de llenguatge, a més de buscar alternatives a l'aïllament imposat pel navegador. No obstant això, gràcies a la col·laboració de la intel·ligència artificial, la motivació i el temps invertit, ha estat possible materialitzar aquest projecte, que espero continuar millorant.
