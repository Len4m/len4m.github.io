---
author: Lenam
pubDatetime: 2026-01-17T00:00:00Z
title: "Cómo limitar el acceso de la inteligencia artificial a tu contenido sin desaparecer de la web (Parte 2 - Estrategias técnicas)"
urlSlug: limitar-acceso-ia-contenido-sin-desaparecer-parte-2
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
  "Soluciones técnicas para limitar el acceso de la inteligencia artificial a tu contenido web."
lang: es
translationId: limitar-acceso-ia-contenido-sin-desaparecer-parte-2
---

![limitar el acceso](../../../assets/images/limitar-acceso-ia-contenido-sin-desaparecer/OpenGraph2.png)

*Bloqueo total, bloqueo intermedio y contenido alternativo: cómo seguir siendo visible sin regalar el fondo (ni los tokens).*

**Serie:**
- [Parte 1: Introducción](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-1/)
- **Parte 2: Estrategias técnicas**
- [Parte 3: Más reducción de tokens](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-3/)

## Tabla de contenido

## De la teoría a la práctica

En la [Parte 1](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-1/) defendía una idea sencilla: *si bloqueas a ciegas, puedes desaparecer; si lo dejas todo abierto, regalas el fondo y pagamos tod@s el coste sin control*. Y ese coste no es solo “tokens”: es también **coste medioambiental** (electricidad, emisiones asociadas al cómputo y, en muchos casos, agua para refrigeración), además de tráfico y almacenamiento repetidos cada vez que un bot vuelve a rastrear.

En esta segunda parte aterrizo lo técnico: **dos estrategias realistas** (bloqueo total y bloqueo intermedio) y una tercera pieza clave, **mostrar contenido alternativo**. La [Parte 3](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-3/) profundiza en cómo **adaptar ese contenido alternativo para reducir aún más el consumo de tokens**.

* **Bloqueo total:** “no quiero que entrenes con mi sitio”.
* **Bloqueo intermedio:** “quiero que puedas descubrirme (y enlazarme), pero no quiero que te lleves todo el texto”.
* **Contenido alternativo:** “si eres un bot, te doy una versión mínima, pensada para indexación o contexto, no para copiar el artículo entero”.

> Importante: ninguna medida es 100% fiable. El objetivo es *reducir superficie y coste*, y dejar señales claras.

## Señales antes de bloquear: llms.txt y otras pistas

Antes de levantar el muro conviene decidir **qué quieres que “entienda” la IA de tu web**.

**llms.txt (señal útil, no estándar)**

`/llms.txt` es una propuesta para dar a los LLMs una versión “amigable” y controlada de tu sitio (contexto + enlaces clave). **Hoy no hay garantías de adopción**: úsalo como **pista complementaria**, no como seguridad. Aun así, es muy útil en una estrategia intermedia: si limitas el HTML completo, puede ser la “puerta” para ofrecer **exactamente** lo que quieres que entiendan.

* [https://llmstxt.org/](https://llmstxt.org/)

**Otras opciones útiles (sin reinventar nada)**

* `robots.txt`: el estándar clásico de exclusión/permiso para crawlers.
* Meta etiqueta `robots`: puedes añadir la etiqueta `<meta name="robots" content="noindex, nofollow">` (o combinaciones como `noai`, si los motores la reconocen) en el `<head>` de tu HTML para controlar el rastreo e indexación a nivel de página.
* `sitemap.xml`: si quieres *SEO clásico*, mantén el sitemap y decide qué rutas entran.
* **RSS/Atom**: útil si quieres que te descubran sin exponer el cuerpo completo.

## robots.txt: qué es y qué NO es

`robots.txt` es un acuerdo de buena fe: **indica** qué debería rastrear un bot, pero **no lo impide** por sí mismo.

Dos ideas rápidas:

1. Si un bot *respeta* `robots.txt`, tu fichero es la forma más simple (y compatible) de controlar su comportamiento.

2. Si un bot *no respeta* `robots.txt`, necesitas capas de enforcement: reglas de servidor, WAF, rate limiting, etc.

### Nota sobre cumplimiento (reputación y reporting)

A día de hoy, **OpenAI y Anthropic declaran que sus bots se controlan mediante** `robots.txt` y documentan cómo permitir/bloquear sus agentes:

* OpenAI: [https://platform.openai.com/docs/bots](https://platform.openai.com/docs/bots) y FAQ para publishers: [https://help.openai.com/en/articles/12627856-publishers-and-developers-faq](https://help.openai.com/en/articles/12627856-publishers-and-developers-faq)
* Anthropic: [https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler)

Si detectas que un bot de estos proveedores **no está respetando** tus reglas (y ya has verificado sintaxis, cachés y que el User-Agent no es un spoof), **repórtalo**: es importante para corregir posibles bugs y también para su reputación (si prometen respetarlo, tienen que cumplirlo).

**Nota personal (y una dosis de realismo)**

Mi impresión es que **no todos los bots ni scrapers respetarán** `robots.txt`, así que no debería ser tu única defensa.

## Estrategia 1: bloqueo total

Esta es la reacción más directa: **bloquear por completo a la mayoría de bots de IA**, aunque con ello corremos el riesgo de volvernos invisibles para quienes usan la IA como buscador.

### Usa ai-robots-txt (y no reinventes la rueda)

El repositorio **ai-robots-txt** ya trae *todo el trabajo hecho*: lista viva de user-agents + ejemplos listos para copiar. Además del `robots.txt`, incluye **snippets por servidor** (y en el propio repo explican cómo aplicar cada uno según tu stack).

* Repositorio (guía + contexto): [https://github.com/ai-robots-txt/ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt)

Guías listas para copiar: [robots.txt](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/robots.txt), [Apache](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/.htaccess), [Nginx](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/nginx-block-ai-bots.conf), [Caddy](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/Caddyfile), [HAProxy](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/haproxy-block-ai-bots.txt).

**Recomendación práctica:** copia el fichero que te encaje (o combínalos: `robots.txt` + bloqueo en servidor) y **manténlo actualizado** con las releases del proyecto.

### Bloqueo por IPs (enforcement real)

Si quieres una capa **más dura** que `robots.txt` y el control por user-agent, algunos proveedores publican **rangos de IP oficiales**. Con ellos puedes **bloquear (403)** bots concretos o hacer **allowlist** de los bots de búsqueda y bloquear el resto.

> Consejo: usa siempre las **URLs oficiales** (las listas cambian); no copies listados de terceros.

#### Dónde obtener IPs oficiales (JSON)

* **OpenAI**

  * GPTBot (entrenamiento): [https://openai.com/gptbot.json](https://openai.com/gptbot.json)
  * OAI-SearchBot (búsqueda): [https://openai.com/searchbot.json](https://openai.com/searchbot.json)
  * ChatGPT-User (peticiones iniciadas por usuario): [https://openai.com/chatgpt-user.json](https://openai.com/chatgpt-user.json)

* **Perplexity**

  * PerplexityBot (búsqueda): [https://www.perplexity.ai/perplexitybot.json](https://www.perplexity.ai/perplexitybot.json)
  * Perplexity-User (user-initiated): [https://www.perplexity.ai/perplexity-user.json](https://www.perplexity.ai/perplexity-user.json)

* **Google (crawlers clásicos, útil si te importa SEO/visibilidad en buscadores)**

  * Common crawlers (Googlebot): [https://developers.google.com/static/search/apis/ipranges/googlebot.json](https://developers.google.com/static/search/apis/ipranges/googlebot.json)
  * Special crawlers: [https://developers.google.com/static/search/apis/ipranges/special-crawlers.json](https://developers.google.com/static/search/apis/ipranges/special-crawlers.json)
  * User-triggered fetchers: [https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json](https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json)
  * User-triggered fetchers (Google): [https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json](https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json)

* **Microsoft (Bingbot)**

  * Bingbot: [https://www.bing.com/toolbox/bingbot.json](https://www.bing.com/toolbox/bingbot.json)

* **Anthropic (matiz importante)**

  * Anthropic indica que **no publica rangos IP para sus bots de crawling** (usan IPs públicas de proveedores). Por tanto, el bloqueo por IP no es un método fiable para ClaudeBot/Claude-SearchBot.
  * Aun así, sí publican **IPs de salida para su API** (no equivale a crawling): [https://platform.claude.com/docs/en/api/ip-addresses](https://platform.claude.com/docs/en/api/ip-addresses)

#### Nginx

Para bloquear bots de IA por IP en Nginx, puedes crear un archivo con los rangos a bloquear y luego integrarlo en la configuración del servidor. De este modo, cualquier petición desde esas IPs será denegada automáticamente.

1. Crea el archivo `/etc/nginx/ai_bot_ips.conf` con los rangos de IP que quieres bloquear, por ejemplo:

```nginx
geo $block_ai_ip {
    default 0;

    # OpenAI GPTBot (ejemplos)
    132.196.86.0/24 1;
    52.230.152.0/24 1;

    # PerplexityBot (ejemplos)
    3.224.62.45/32 1;
    107.20.236.150/32 1;
}
```

2. Incluye este archivo en tu bloque `server {}` y aplica el bloqueo:

```nginx
include /etc/nginx/ai_bot_ips.conf;

if ($block_ai_ip) {
    return 403;
}
```

> Recuerda: si tienes CDN o proxy inverso delante, asegúrate de que Nginx reciba la IP real del visitante para que el bloqueo funcione correctamente.

#### Apache 2.4+

En Apache 2.4+ puedes bloquear rangos de IP fácilmente usando la directiva `Require not ip`. Esto permite negar el acceso a ciertas IPs tanto en la configuración del VirtualHost como a nivel de `.htaccess` si tu hosting lo permite. Solo necesitas especificar los rangos o direcciones a bloquear y quienes no estén en esas IPs podrán seguir accediendo normalmente.

Ejemplo en VirtualHost:

```apache
<Directory "/var/www/html">
  <RequireAll>
    Require all granted

    # Bloqueo por IP/CIDR (ejemplos)
    Require not ip 132.196.86.0/24
    Require not ip 52.230.152.0/24
    Require not ip 3.224.62.45/32
  </RequireAll>
</Directory>
```

Ejemplo en `.htaccess` (necesita que `AllowOverride` esté activo):

```apache
<RequireAll>
  Require all granted
  Require not ip 132.196.86.0/24
  Require not ip 52.230.152.0/24
</RequireAll>
```

#### Script auxiliar (bot-ip-ranges.sh)

Para facilitar el trabajo, he creado **bot-ip-ranges.sh**, un script pensado justo para esta serie: descarga y normaliza rangos de IP de bots desde las fuentes oficiales, para que puedas integrarlos en tu configuración sin hacerlo a mano.

Repositorio: [https://github.com/Len4m/bot-ip-ranges.sh](https://github.com/Len4m/bot-ip-ranges.sh)

Comando rapido para descargar, dar permisos y ejecutar (devuelve el listado de IPs):

```bash
curl -fsSL https://raw.githubusercontent.com/Len4m/bot-ip-ranges.sh/main/bot-ip-ranges.sh -o /tmp/bot-ip-ranges.sh && chmod +x /tmp/bot-ip-ranges.sh && /tmp/bot-ip-ranges.sh
```

### Coste real del bloqueo total

* Puedes perder visibilidad en productos de búsqueda basados en IA.
* No resuelve el problema de bots maliciosos o que se hacen pasar por otros.
* Es una postura clara y fácil de mantener, pero **la más agresiva**.

## Estrategia 2: bloqueo intermedio (seguir visible)

La clave es diferenciar entre **bots de búsqueda** (permitir) y **bots de entrenamiento** (bloquear), aplicando reglas distintas a cada tipo para lograr visibilidad en resultados de IA sin facilitar el entrenamiento con tu contenido.

- Deja rastrear lo esencial (título, resumen, metadatos), pero limita el acceso al artículo completo.
- Permite solo a bots de búsqueda acceder, bloqueando los de entrenamiento cuando puedas (por User-Agent y/o IP).
- Si necesitas visibilidad sin regalar el contenido completo, sirve resúmenes o teasers a los bots.

Así, puedes seguir apareciendo en AI Search sin que todo tu contenido acabe en datasets de entrenamiento.

### 1) Control por bots (búsqueda vs entrenamiento)

Cada vez más proveedores separan bots:

* Un bot para **entrenamiento**.
* Otro bot para **búsqueda**.
* Y a veces un agente para **peticiones iniciadas por usuario**.

Un ejemplo de `robots.txt` con esta filosofía (ajústalo a la lista viva de ai-robots-txt):

```txt
# Entrenamiento (bloqueo)
User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

# Búsqueda (permitir, si te interesa visibilidad)
User-agent: OAI-SearchBot
Allow: /

User-agent: Claude-SearchBot
Allow: /

# Peticiones iniciadas por usuario (opcional)
# (Estos agentes suelen gestionarse mejor con rate limiting y/o allowlist por IP)
User-agent: ChatGPT-User
Allow: /

User-agent: Claude-User
Allow: /
```

### 2) Control por rutas (teaser vs contenido completo)

La estrategia más limpia (si puedes adaptarla) es separar rutas:

* **Ruta completa (humano):** `/blog/mi-articulo` (HTML completo)
* **Ruta IA (bot):** `/ia-content/mi-articulo.md` (contenido mínimo para IA)

Entonces:

* Permites a bots acceder a `/ia-content/…`
* Bloqueas a bots de entrenamiento en `/blog/…`
* Y decides si el bot de búsqueda ve el HTML completo o el contenido para IA (según tu tolerancia)

Ejemplo:

```txt
# Bots de IA: solo contenido para IA
User-agent: GPTBot
Disallow: /blog/
Allow: /ia-content/

User-agent: ClaudeBot
Disallow: /blog/
Allow: /ia-content/

# Bot de búsqueda (opción A: permitir todo)
User-agent: OAI-SearchBot
Allow: /

# Bot de búsqueda (opción B: permitir solo contenido para IA)
# User-agent: OAI-SearchBot
# Disallow: /blog/
# Allow: /ia-content/

User-agent: *
Allow: /
```




### 3) Bloqueo adicional por IP (recomendado)

Además del control por User-Agent, **también puedes aplicar bloqueo por IP**. Como vimos en secciones anteriores, existen listados públicos en JSON con los rangos de IP de los principales bots de IA. Esto ya lo vimos en [Bloqueo por IPs (enforcement real)](#bloqueo-por-ips-enforcement-real). Puedes filtrar estos rangos para obtener únicamente las IPs de los bots de entrenamiento (excluyendo los de búsqueda y usuario) y así bloquear solo a quienes realmente no quieres que accedan.

Para facilitar este filtrado, puedes usar el script antes mencionado:

[https://github.com/Len4m/bot-ip-ranges.sh](https://github.com/Len4m/bot-ip-ranges.sh)

Por ejemplo, para obtener solo las IPs de bots de entrenamiento, ejecuta:

```bash
./bot-ip-ranges.sh --exclude-search --exclude-user
```

Así consigues un listado para bloquear directamente desde Nginx, Apache o tu WAF, manteniéndote visible para IA de búsqueda y usuarios pero no para entrenamiento.

## Mostrar contenido alternativo a bots

En la [Parte 3](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-3/) entro en detalle sobre **cómo adaptar ese contenido alternativo para minimizar tokens** (qué incluir, qué omitir y cómo estructurarlo sin perder contexto). Aquí me limito a dos patrones de implementación. No son excluyentes.

### Preparar el contenido alternativo

Creas una versión alternativa por artículo (texto plano, Markdown o formato ultra-minimal). Idealmente:

* ligera
* con el *mínimo contexto útil*
* con un enlace canónico al artículo

Ejemplo de representación **minimal TOON** (puede ser texto plano, json o Markdown) para este propio artículo, optimizado para LLMs y bajo coste:

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

Crea un fichero alternativo con formato `.toon` (por ejemplo, `limitar-acceso-ia-contenido-sin-desaparecer-parte-2.toon`), aunque también podría ser texto plano, Markdown o JSON, y enlázalo tanto en `llms.txt` como en el HTML usando `<link rel="alternate" type="text/plain" href="/ia-content/limitar-acceso-ia-contenido-sin-desaparecer-parte-2.toon">`.

> De todo esto (cómo diseñar y compactar contenido alternativo, reducir aún más los tokens expuestos, ...) hablo en profundidad en la [Parte 3: Más reducción de tokens](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-3/).

### Misma URL, respuesta distinta según User-Agent

Si no quieres crear rutas nuevas, puedes servir *otra cosa* cuando detectas un bot.

#### Ejemplo Nginx (conceptual)

1. Detecta bots por User-Agent (idealmente apoyándote en una lista como ai-robots-txt):

```nginx
map $http_user_agent $is_ai_bot {
    default 0;
    ~*(GPTBot|ClaudeBot|ChatGPT-User|Claude-User|OAI-SearchBot|Claude-SearchBot) 1;
}
```

2. En las rutas de artículos, si es bot, intenta servir un fichero `.toon` (o `txt`, `json`, `md`):

```nginx
location ^~ /blog/ {
    # Humanos (por defecto): contenido completo
    try_files $uri $uri/ /index.html;

    # Bots: servir .toon si existe
    if ($is_ai_bot) {
        rewrite ^/blog/(.*)$ /ia-content/$1.toon break;
    }
}

location ^~ /ia-content/ {
    default_type text/plain;
    try_files $uri =404;
}
```

#### Ejemplo Nginx (avanzado: User-Agent + IP)

Si quieres mayor fiabilidad, puedes combinar User-Agent y rangos de IP (ver [Bloqueo por IPs (enforcement real)](#bloqueo-por-ips-enforcement-real)):

```nginx
# UA bot detection
map $http_user_agent $is_ai_bot {
    default 0;
    ~*(GPTBot|ClaudeBot|ChatGPT-User|Claude-User|OAI-SearchBot|Claude-SearchBot) 1;
}

# IP ranges (generated list with "1;" values)
geo $is_ai_ip {
    default 0;
    include /etc/nginx/ai_bot_ips.conf;
}

# Require UA or IP to serve alternate content
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

**Puntos importantes:**

* No apliques esto a Googlebot (o a tu estrategia SEO) si no quieres problemas de "cloaking".
* Esta técnica es útil cuando no quieres tocar el CMS, pero requiere cuidado para no romper cachés/CDN.
* Lo importante es que te quedes con el **concepto** y aprendas a configurar tu servidor según lo explicado en este artículo, adaptándolo a tu stack y necesidades concretas.
* Otra opción: en lugar de servir ficheros estáticos, puedes tener todos los contenidos alternativos en una **base de datos** y pasar la URL como parámetro a un endpoint encargado de devolver el contenido alternativo (por ejemplo, `/api/ia-content?url=/blog/mi-articulo`).

## Mantenimiento y supervisión (imprescindible)

Independientemente de la estrategia que elijas (bloqueo total, bloqueo intermedio o contenido alternativo), el mantenimiento y la supervisión son fundamentales para que las medidas sigan siendo efectivas:

* Automatiza la descarga de rangos de IP o JSON (por ejemplo con `curl` + `jq`) o utilizando el script `bot-ip-ranges.sh` y regenera el include de Nginx/Apache.
* Revisa periódicamente si el proveedor **actualiza** `creationTime`, cambia prefijos, o publica nuevas IPs.
* Combina **IP + User-Agent** cuando sea posible: así reduces spoofing y falsos positivos.
* **Mide**: revisa logs por User-Agent, rutas más accedidas y errores 4xx/5xx.
* **Actualiza las listas de bots**: el archivo ai-robots-txt y los rangos cambian con frecuencia.
* **Rate limits**: incluso bots "bien educados" pueden generar picos de tráfico inesperados.
* **No confíes solo en esto para proteger URLs sensibles**: si tienes recursos críticos, protégelos realmente (auth, tokens, WAF…).

Y vuelvo a la idea del inicio: el objetivo no es "ganar una guerra". Es **decidir qué enseñas, a quién y a qué coste**.

Para facilitarte el proceso, he creado el script [`bot-ip-ranges.sh`](https://github.com/Len4m/bot-ip-ranges.sh), que utilicé durante la redacción de este artículo para realizar pruebas. Está comprobado (a fecha de la escritura de este artículo) y simplifica mucho el bloqueo de bots por IP respecto a hacerlo manualmente. Consulta el repositorio para obtener instrucciones y ejemplos.

Si quieres exprimir aún más la reducción de tokens, continúa con la [Parte 3](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-3/).

## Referencias y recursos

* Parte 1: [Cómo limitar el acceso de la inteligencia artificial a tu contenido sin desaparecer de la web (Parte 1 - Introducción)](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-1/)
* Parte 3: [Cómo adaptar el contenido alternativo para reducir el consumo de tokens (Parte 3 - Más reducción de tokens)](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-3/)
* ai-robots-txt (repositorio): [https://github.com/ai-robots-txt/ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt)
* llms.txt (propuesta): [https://llmstxt.org/](https://llmstxt.org/)
* Robots Exclusion Protocol (RFC 9309): [https://www.rfc-editor.org/rfc/rfc9309.html](https://www.rfc-editor.org/rfc/rfc9309.html)
* OpenAI: Overview of OpenAI Crawlers: [https://platform.openai.com/docs/bots](https://platform.openai.com/docs/bots)
* OpenAI IP ranges:

  * [https://openai.com/gptbot.json](https://openai.com/gptbot.json)
  * [https://openai.com/searchbot.json](https://openai.com/searchbot.json)
  * [https://openai.com/chatgpt-user.json](https://openai.com/chatgpt-user.json)
* Anthropic: Does Anthropic crawl data from the web, and how can site owners block the crawler?: [https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler)
* Anthropic (IPs de salida documentadas): [https://platform.claude.com/docs/en/api/ip-addresses](https://platform.claude.com/docs/en/api/ip-addresses)
* Google: Robots.txt specification: [https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt](https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt)
