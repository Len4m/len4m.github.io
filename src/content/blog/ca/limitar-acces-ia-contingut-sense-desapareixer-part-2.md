---
author: Lenam
pubDatetime: 2026-01-17T00:00:00Z
title: "Com limitar l'accés de la intel·ligència artificial al teu contingut sense desaparèixer de la web (Part 2 - Estratègies tècniques)"
urlSlug: limitar-acces-ia-contingut-sense-desapareixer-part-2
featured: false
draft: false
ogImage: "../../../assets/images/limitar-acceso-ia-contenido-sin-desaparecer/OpenGraph2.png"
tags:
    - ai
    - privacy
    - copyright
    - web
    - opinion
    - legal
    - ia-limitation
    - security
    - nginx
    - apache
    - robots-txt
    - llms-txt
    - seo
description:
  "Solucions tècniques per limitar l'accés de la intel·ligència artificial al teu contingut web."
lang: ca
translationId: limitar-acceso-ia-contenido-sin-desaparecer-parte-2
---

![limitar l'accés](../../../assets/images/limitar-acceso-ia-contenido-sin-desaparecer/OpenGraph2.png)

*Bloqueig total, bloqueig intermedi i contingut alternatiu: com continuar sent visible sense regalar el fons (ni els tokens).*

**Sèrie:**
- [Part 1: Introducció](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-1/)
- **Part 2: Estratègies tècniques**
- [Part 3: Més reducció de tokens](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-3/)

## Taula de continguts

## De la teoria a la pràctica

A la [Part 1](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-1/) defensava una idea senzilla: *si bloqueges a cegues, pots desaparèixer; si ho deixes tot obert, regales el fons i ho paguem tothom sense control*. I aquest cost no és només “tokens”: és també **cost mediambiental** (electricitat, emissions associades al còmput i, en molts casos, aigua per refrigeració), a més de trànsit i emmagatzematge repetits cada vegada que un bot torna a rastrejar.

En aquesta segona part aterro el vessant tècnic: **dues estratègies realistes** (bloqueig total i bloqueig intermedi) i una tercera peça clau, **mostrar contingut alternatiu**. La [Part 3](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-3/) aprofundeix en com **adaptar aquest contingut alternatiu per reduir encara més el consum de tokens**.

* **Bloqueig total:** “no vull que entrenis amb el meu lloc”.
* **Bloqueig intermedi:** “vull que em puguis descobrir (i enllaçar), però no vull que t'enduguis tot el text”.
* **Contingut alternatiu:** “si ets un bot, et dono una versió mínima, pensada per a indexació o context, no per copiar l'article sencer”.

> Important: cap mesura és 100% fiable. L'objectiu és *reduir superfície i cost*, i deixar senyals clars.

## Senyals abans de bloquejar: llms.txt i altres pistes

Abans d'aixecar el mur convé decidir **què vols que “entengui” la IA del teu web**.

**llms.txt (senyal útil, no estàndard)**

`/llms.txt` és una proposta per donar als LLMs una versió “amigable” i controlada del teu lloc (context + enllaços clau). **Avui no hi ha garanties d'adopció**: fes-lo servir com a **pista complementària**, no com a seguretat. Tot i així, és molt útil en una estratègia intermèdia: si limites l'HTML complet, pot ser la “porta” per oferir **exactament** el que vols que entenguin.

* [https://llmstxt.org/](https://llmstxt.org/)

**Altres opcions útils (sense reinventar res)**

* `robots.txt`: l'estàndard clàssic d'exclusió/permissió per a crawlers.
* Meta etiqueta `robots`: pots afegir l'etiqueta `<meta name="robots" content="noindex, nofollow">` (o combinacions com `noai`, si els motors la reconeixen) al `<head>` del teu HTML per controlar el rastreig i la indexació a nivell de pàgina.
* `sitemap.xml`: si vols *SEO clàssic*, mantén el sitemap i decideix quines rutes hi entren.
* **RSS/Atom**: útil si vols que et descobreixin sense exposar el cos complet.

## robots.txt: què és i què NO és

`robots.txt` és un acord de bona fe: **indica** què hauria de rastrejar un bot, però **no ho impedeix** per si mateix.

Dues idees ràpides:

1. Si un bot *respecta* `robots.txt`, el teu fitxer és la manera més simple (i compatible) de controlar el seu comportament.

2. Si un bot *no respecta* `robots.txt`, necessites capes d'enforcement: regles de servidor, WAF, limitació de taxa, etc.

### Nota sobre compliment (reputació i reporting)

A dia d'avui, **OpenAI i Anthropic declaren que els seus bots es controlen mitjançant** `robots.txt` i documenten com permetre/bloquejar els seus agents:

* OpenAI: [https://platform.openai.com/docs/bots](https://platform.openai.com/docs/bots) i FAQ per a publishers: [https://help.openai.com/en/articles/12627856-publishers-and-developers-faq](https://help.openai.com/en/articles/12627856-publishers-and-developers-faq)
* Anthropic: [https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler)

Si detectes que un bot d'aquests proveïdors **no està respectant** les teves regles (i ja has verificat sintaxi, memòries cau i que el User-Agent no és un spoof), **reporta-ho**: és important per corregir possibles bugs i també per a la seva reputació (si prometen respectar-ho, ho han de complir).

**Nota personal (i una dosi de realisme)**

La meva impressió és que **no tots els bots ni scrapers respectaran** `robots.txt`, així que no hauria de ser la teva única defensa.

## Estratègia 1: bloqueig total

Aquesta és la reacció més directa: **bloquejar completament la majoria de bots d'IA**, encara que amb això correm el risc de tornar-nos invisibles per a qui usa la IA com a cercador.

### Fes servir ai-robots-txt (i no reinventis la roda)

El repositori **ai-robots-txt** ja porta *tota la feina feta*: llista viva de user-agents + exemples llestos per copiar. A més del `robots.txt`, inclou **snippets per servidor** (i al mateix repo expliquen com aplicar-ne cadascun segons el teu stack).

* Repositori (guia + context): [https://github.com/ai-robots-txt/ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt)

Guies llestes per copiar: [robots.txt](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/robots.txt), [Apache](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/.htaccess), [Nginx](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/nginx-block-ai-bots.conf), [Caddy](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/Caddyfile), [HAProxy](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/haproxy-block-ai-bots.txt).

**Recomanació pràctica:** copia el fitxer que t'encaixi (o combina'ls: `robots.txt` + bloqueig a servidor) i **mantén-lo actualitzat** amb les releases del projecte.

### Bloqueig per IPs (enforcement real)

Si vols una capa **més dura** que `robots.txt` i el control per user-agent, alguns proveïdors publiquen **rangs d'IP oficials**. Amb ells pots **bloquejar (403)** bots concrets o fer **allowlist** dels bots de cerca i bloquejar la resta.

> Consell: fes servir sempre les **URLs oficials** (les llistes canvien); no copiïs llistats de tercers.

#### On obtenir IPs oficials (JSON)

* **OpenAI**

  * GPTBot (entrenament): [https://openai.com/gptbot.json](https://openai.com/gptbot.json)
  * OAI-SearchBot (cerca): [https://openai.com/searchbot.json](https://openai.com/searchbot.json)
  * ChatGPT-User (peticions iniciades per usuari): [https://openai.com/chatgpt-user.json](https://openai.com/chatgpt-user.json)

* **Perplexity**

  * PerplexityBot (cerca): [https://www.perplexity.ai/perplexitybot.json](https://www.perplexity.ai/perplexitybot.json)
  * Perplexity-User (peticions iniciades per usuari): [https://www.perplexity.ai/perplexity-user.json](https://www.perplexity.ai/perplexity-user.json)

* **Google (crawlers clàssics, útil si t'importa el SEO/visibilitat als cercadors)**

  * Common crawlers (Googlebot): [https://developers.google.com/static/search/apis/ipranges/googlebot.json](https://developers.google.com/static/search/apis/ipranges/googlebot.json)
  * Special crawlers: [https://developers.google.com/static/search/apis/ipranges/special-crawlers.json](https://developers.google.com/static/search/apis/ipranges/special-crawlers.json)
  * User-triggered fetchers: [https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json](https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json)
  * User-triggered fetchers (Google): [https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json](https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json)

* **Microsoft (Bingbot)**

  * Bingbot: [https://www.bing.com/toolbox/bingbot.json](https://www.bing.com/toolbox/bingbot.json)

* **Anthropic (matís important)**

  * Anthropic indica que **no publica rangs IP per als seus bots de crawling** (fan servir IPs públiques de proveïdors). Per tant, el bloqueig per IP no és un mètode fiable per a ClaudeBot/Claude-SearchBot.
  * Tot i així, sí publiquen **IPs de sortida per a la seva API** (no equival a crawling): [https://platform.claude.com/docs/en/api/ip-addresses](https://platform.claude.com/docs/en/api/ip-addresses)

#### Nginx

Per bloquejar bots d'IA per IP a Nginx, pots crear un fitxer amb els rangs a bloquejar i després integrar-lo a la configuració del servidor. D'aquesta manera, qualsevol petició des d'aquestes IPs serà denegada automàticament.

1. Crea el fitxer `/etc/nginx/ai_bot_ips.conf` amb els rangs d'IP que vols bloquejar, per exemple:

```nginx
geo $block_ai_ip {
    default 0;

    # OpenAI GPTBot (exemples)
    132.196.86.0/24 1;
    52.230.152.0/24 1;

    # PerplexityBot (exemples)
    3.224.62.45/32 1;
    107.20.236.150/32 1;
}
```

2. Inclou aquest fitxer al teu bloc `server {}` i aplica el bloqueig:

```nginx
include /etc/nginx/ai_bot_ips.conf;

if ($block_ai_ip) {
    return 403;
}
```

> Recorda: si tens CDN o proxy invers al davant, assegura't que Nginx rebi la IP real del visitant perquè el bloqueig funcioni correctament.

#### Apache 2.4+

A Apache 2.4+ pots bloquejar rangs d'IP fàcilment utilitzant la directiva `Require not ip`. Això permet negar l'accés a certes IPs tant a la configuració del VirtualHost com a nivell de `.htaccess` si el teu hosting ho permet. Només cal especificar els rangs o adreces a bloquejar i qui no estigui en aquestes IPs podrà seguir accedint amb normalitat.

Exemple a VirtualHost:

```apache
<Directory "/var/www/html">
  <RequireAll>
    Require all granted

    # Bloqueig per IP/CIDR (exemples)
    Require not ip 132.196.86.0/24
    Require not ip 52.230.152.0/24
    Require not ip 3.224.62.45/32
  </RequireAll>
</Directory>
```

Exemple a `.htaccess` (necessita que `AllowOverride` estigui actiu):

```apache
<RequireAll>
  Require all granted
  Require not ip 132.196.86.0/24
  Require not ip 52.230.152.0/24
</RequireAll>
```

#### Script auxiliar (bot-ip-ranges.sh)

Per facilitar la feina, he creat **bot-ip-ranges.sh**, un script pensat just per a aquesta sèrie: descarrega i normalitza rangs d'IP de bots des de les fonts oficials, perquè puguis integrar-los a la teva configuració sense fer-ho a mà.

Repositori: [https://github.com/Len4m/bot-ip-ranges.sh](https://github.com/Len4m/bot-ip-ranges.sh)

Ordre ràpida per descarregar, donar permisos i executar (retorna el llistat d'IPs):

```bash
curl -fsSL https://raw.githubusercontent.com/Len4m/bot-ip-ranges.sh/main/bot-ip-ranges.sh -o /tmp/bot-ip-ranges.sh && chmod +x /tmp/bot-ip-ranges.sh && /tmp/bot-ip-ranges.sh
```

### Cost real del bloqueig total

* Pots perdre visibilitat en productes de cerca basats en IA.
* No resol el problema de bots maliciosos o que es fan passar per altres.
* És una postura clara i fàcil de mantenir, però **la més agressiva**.

## Estratègia 2: bloqueig intermedi (continuar sent visible)

La clau és diferenciar entre **bots de cerca** (permetre) i **bots d'entrenament** (bloquejar), aplicant regles diferents a cada tipus per aconseguir visibilitat en resultats d'IA sense facilitar l'entrenament amb el teu contingut.

- Deixa rastrejar l'essencial (títol, resum, metadades), però limita l'accés a l'article complet.
- Permet només als bots de cerca accedir, bloquejant els d'entrenament quan puguis (per User-Agent i/o IP).
- Si necessites visibilitat sense regalar el contingut complet, serveix resums o teasers als bots.

Així, pots continuar apareixent en AI Search sense que tot el teu contingut acabi en datasets d'entrenament.

### 1) Control per bots (cerca vs entrenament)

Cada vegada més proveïdors separen bots:

* Un bot per a **entrenament**.
* Un altre bot per a **cerca**.
* I de vegades un agent per a **peticions iniciades per usuari**.

Un exemple de `robots.txt` amb aquesta filosofia (ajusta'l a la llista viva d'ai-robots-txt):

```txt
# Entrenament (bloqueig)
User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

# Cerca (permetre, si t'interessa visibilitat)
User-agent: OAI-SearchBot
Allow: /

User-agent: Claude-SearchBot
Allow: /

# Peticions iniciades per usuari (opcional)
# (Aquests agents solen gestionar-se millor amb rate limiting i/o allowlist per IP)
User-agent: ChatGPT-User
Allow: /

User-agent: Claude-User
Allow: /
```

### 2) Control per rutes (teaser vs contingut complet)

L'estratègia més neta (si pots adaptar-la) és separar rutes:

* **Ruta completa (humà):** `/blog/mi-articulo` (HTML complet)
* **Ruta IA (bot):** `/ia-content/mi-articulo.md` (contingut mínim per a IA)

Aleshores:

* Permets als bots accedir a `/ia-content/…`
* Bloqueges els bots d'entrenament a `/blog/…`
* I decideixes si el bot de cerca veu l'HTML complet o el contingut per a IA (segons la teva tolerància)

Exemple:

```txt
# Bots d'IA: només contingut per a IA
User-agent: GPTBot
Disallow: /blog/
Allow: /ia-content/

User-agent: ClaudeBot
Disallow: /blog/
Allow: /ia-content/

# Bot de cerca (opció A: permetre-ho tot)
User-agent: OAI-SearchBot
Allow: /

# Bot de cerca (opció B: permetre només contingut per a IA)
# User-agent: OAI-SearchBot
# Disallow: /blog/
# Allow: /ia-content/

User-agent: *
Allow: /
```




### 3) Bloqueig addicional per IP (recomanat)

A més del control per User-Agent, **també pots aplicar bloqueig per IP**. Com vam veure en seccions anteriors, existeixen llistats públics en JSON amb els rangs d'IP dels principals bots d'IA. Això ja ho vam veure a [Bloqueig per IPs (enforcement real)](#bloqueig-per-ips-enforcement-real). Pots filtrar aquests rangs per obtenir únicament les IPs dels bots d'entrenament (excloent els de cerca i usuari) i així bloquejar només a qui realment no vols que hi accedeixi.

Per facilitar aquest filtratge, pots fer servir el script abans mencionat:

[https://github.com/Len4m/bot-ip-ranges.sh](https://github.com/Len4m/bot-ip-ranges.sh)

Per exemple, per obtenir només les IPs de bots d'entrenament, executa:

```bash
./bot-ip-ranges.sh --exclude-search --exclude-user
```

Així aconsegueixes un llistat per bloquejar directament des de Nginx, Apache o el teu WAF, mantenint-te visible per a IA de cerca i usuaris però no per a entrenament.

## Mostrar contingut alternatiu als bots

A la [Part 3](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-3/) entro en detall sobre **com adaptar aquest contingut alternatiu per minimitzar tokens** (què incloure, què ometre i com estructurar-lo sense perdre context). Aquí em limito a dos patrons d'implementació. No són excloents.

### Preparar el contingut alternatiu

Crees una versió alternativa per article (text pla, Markdown o format ultra-minimal). Idealment:

* lleugera
* amb el *mínim context útil*
* amb un enllaç canònic a l'article

Exemple de representació **minimal TOON** (pot ser text pla, json o Markdown) per a aquest mateix article, optimitzat per a LLMs i baix cost:

```yaml
id: limitar-acceso-ia-parte-2
url: https://len4m.github.io/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-2.html
lang: es
title: Limitar acceso IA a tu contenido (Parte 2 - Estrategias técnicas)
summary: Bloqueo total, bloqueo intermedio y contenido alternativo para bots.
points: bloqueo selectivo, contenido alternativo, robots.txt
tags: ai, web, robots, ia-limitation
updated: 2026-01-17
cta: Lee el contenido completo en la URL canónica.
```

Crea un fitxer alternatiu amb format `.toon` (per exemple, `limitar-acceso-ia-contenido-sin-desaparecer-parte-2.toon`), tot i que també podria ser text pla, Markdown o JSON, i enllaça'l tant a `llms.txt` com a l'HTML utilitzant `<link rel="alternate" type="text/plain" href="/ia-content/limitar-acceso-ia-contenido-sin-desaparecer-parte-2.toon">`.

> De tot això (com dissenyar i compactar contingut alternatiu, reduir encara més els tokens exposats, ...) en parlo en profunditat a la [Part 3: Més reducció de tokens](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-3/).

### Mateixa URL, resposta diferent segons User-Agent

Si no vols crear rutes noves, pots servir *una altra cosa* quan detectes un bot.

#### Exemple Nginx (conceptual)

1. Detecta bots per User-Agent (idealment recolzant-te en una llista com ai-robots-txt):

```nginx
map $http_user_agent $is_ai_bot {
    default 0;
    ~*(GPTBot|ClaudeBot|ChatGPT-User|Claude-User|OAI-SearchBot|Claude-SearchBot) 1;
}
```

2. A les rutes d'articles, si és bot, intenta servir un fitxer `.toon` (o `txt`, `json`, `md`):

```nginx
location ^~ /blog/ {
    # Humans (per defecte): contingut complet
    try_files $uri $uri/ /index.html;

    # Bots: servir .toon si existeix
    if ($is_ai_bot) {
        rewrite ^/blog/(.*)$ /ia-content/$1.toon break;
    }
}

location ^~ /ia-content/ {
    default_type text/plain;
    try_files $uri =404;
}
```

#### Exemple Nginx (avançat: User-Agent + IP)

Si vols més fiabilitat, pots combinar User-Agent i rangs d'IP (vegeu [Bloqueig per IPs (enforcement real)](#bloqueig-per-ips-enforcement-real)):

```nginx
# Detecció de bot per UA
map $http_user_agent $is_ai_bot {
    default 0;
    ~*(GPTBot|ClaudeBot|ChatGPT-User|Claude-User|OAI-SearchBot|Claude-SearchBot) 1;
}

# Rangs d'IPs (llista generada amb valors "1;")
geo $is_ai_ip {
    default 0;
    include /etc/nginx/ai_bot_ips.conf;
}

# Requereix UA o IP per servir contingut alternatiu
map "$is_ai_bot:$is_ai_ip" $serve_ai_alt {
    default 0;
    "1:0" 1;
    "0:1" 1;
    "1:1" 1;
}

location ^~ /blog/ {
    try_files $uri $uri/ /index.html;

    if ($serve_ai_alt) {
        rewrite ^/blog/(.*)$ /ia-content/$1.toon break;
    }
}

location ^~ /ia-content/ {
    default_type text/plain;
    try_files $uri =404;
}
```

**Punts importants:**

* No apliquis això a Googlebot (o a la teva estratègia SEO) si no vols problemes de "cloaking".
* Aquesta tècnica és útil quan no vols tocar el CMS, però requereix cura per no trencar caches/CDN.
* L'important és que et quedis amb el **concepte** i aprenguis a configurar el teu servidor segons el que s'explica en aquest article, adaptant-lo al teu stack i a les teves necessitats concretes.
* Una altra opció: en lloc de servir fitxers estàtics, pots tenir tots els continguts alternatius en una **base de dades** i passar la URL com a paràmetre a un endpoint encarregat de retornar el contingut alternatiu (per exemple, `/api/ia-content?url=/blog/mi-articulo`).

## Manteniment i supervisió (imprescindible)

Independentment de l'estratègia que triïs (bloqueig total, bloqueig intermedi o contingut alternatiu), el manteniment i la supervisió són fonamentals perquè les mesures continuïn sent efectives:

* Automatitza la descàrrega de rangs d'IP o JSON (per exemple amb `curl` + `jq`) o utilitzant el script `bot-ip-ranges.sh` i regenera l'include de Nginx/Apache.
* Revisa periòdicament si el proveïdor **actualitza** `creationTime`, canvia prefixos, o publica noves IPs.
* Combina **IP + User-Agent** quan sigui possible: així redueixes spoofing i falsos positius.
* **Mesura**: revisa logs per User-Agent, rutes més accedides i errors 4xx/5xx.
* **Actualitza les llistes de bots**: el fitxer ai-robots-txt i els rangs canvien amb freqüència.
* **Rate limits**: fins i tot bots "ben educats" poden generar pics de trànsit inesperats.
* **No confiïs només en això per protegir URLs sensibles**: si tens recursos crítics, protegeix-los de debò (auth, tokens, WAF…).

I torno a la idea de l'inici: l'objectiu no és "guanyar una guerra". És **decidir què ensenyes, a qui i a quin cost**.

Per facilitar-te el procés, he creat el script [`bot-ip-ranges.sh`](https://github.com/Len4m/bot-ip-ranges.sh), que vaig utilitzar durant la redacció d'aquest article per fer proves. Està comprovat (a data de l'escriptura d'aquest article) i simplifica molt el bloqueig de bots per IP respecte a fer-ho manualment. Consulta el repositori per obtenir instruccions i exemples.

Si vols esprémer encara més la reducció de tokens, continua amb la [Part 3](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-3/).

## Referències i recursos

* Part 1: [Com limitar l'accés de la intel·ligència artificial al teu contingut sense desaparèixer de la web (Part 1 - Introducció)](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-1/)
* Part 3: [Com adaptar el contingut alternatiu per reduir el consum de tokens (Part 3 - Més reducció de tokens)](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-3/)
* ai-robots-txt (repositori): [https://github.com/ai-robots-txt/ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt)
* llms.txt (proposta): [https://llmstxt.org/](https://llmstxt.org/)
* Robots Exclusion Protocol (RFC 9309): [https://www.rfc-editor.org/rfc/rfc9309.html](https://www.rfc-editor.org/rfc/rfc9309.html)
* OpenAI: Visió general dels crawlers d'OpenAI: [https://platform.openai.com/docs/bots](https://platform.openai.com/docs/bots)
* Rangs d'IP d'OpenAI:

  * [https://openai.com/gptbot.json](https://openai.com/gptbot.json)
  * [https://openai.com/searchbot.json](https://openai.com/searchbot.json)
  * [https://openai.com/chatgpt-user.json](https://openai.com/chatgpt-user.json)
* Anthropic: Does Anthropic crawl data from the web, and how can site owners block the crawler?: [https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler)
* Anthropic (IPs de sortida documentades): [https://platform.claude.com/docs/en/api/ip-addresses](https://platform.claude.com/docs/en/api/ip-addresses)
* Google: Especificació de robots.txt: [https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt](https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt)
