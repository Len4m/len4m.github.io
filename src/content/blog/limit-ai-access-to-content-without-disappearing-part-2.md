---
author: Lenam
pubDatetime: 2026-01-17T00:00:00Z
title: "How to limit AI access to your content without disappearing from the web (Part 2 - Technical strategies)"
urlSlug: limit-ai-access-to-content-without-disappearing-part-2
featured: false
draft: false
ogImage: "../../assets/images/limitar-acceso-ia-contenido-sin-desaparecer/OpenGraph2.png"
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
  "Technical solutions to limit AI access to your web content."
lang: en
translationId: limitar-acceso-ia-contenido-sin-desaparecer-parte-2
---

![limit access](../../assets/images/limitar-acceso-ia-contenido-sin-desaparecer/OpenGraph2.png)

*Total block, intermediate block, and alternative content: how to stay visible without giving away the substance (or the tokens).*

**Series:**
- [Part 1: Introduction](/posts/limit-ai-access-to-content-without-disappearing-part-1/)
- **Part 2: Technical strategies**
- [Part 3: More token reduction](/posts/limit-ai-access-to-content-without-disappearing-part-3/)

## Table of Contents

## From theory to practice

In [Part 1](/posts/limit-ai-access-to-content-without-disappearing-part-1/) I defended a simple idea: *if you block blindly, you can disappear; if you leave everything open, you give away the substance and we all pay the cost without control*. And that cost is not just "tokens": it is also **environmental cost** (electricity, emissions associated with computation and, in many cases, water for cooling), plus repeated traffic and storage every time a bot crawls again.

In this second part I get into the technical side: **two realistic strategies** (total block and intermediate block) and a third key piece, **showing alternative content**. [Part 3](/posts/limit-ai-access-to-content-without-disappearing-part-3/) goes deeper into how to **adapt that alternative content to further reduce token consumption**.

* **Total block:** "I do not want you to train on my site".
* **Intermediate block:** "I want you to discover me (and link to me), but I do not want you to take the whole text".
* **Alternative content:** "if you are a bot, I give you a minimal version, meant for indexing or context, not for copying the whole article".

> Important: no measure is 100% reliable. The goal is to *reduce surface and cost*, and leave clear signals.

## Signals before blocking: llms.txt and other clues

Before raising the wall, it is worth deciding **what you want the AI to "understand" about your web**.

**llms.txt (useful signal, not standard)**

`/llms.txt` is a proposal to give LLMs a "friendly" and controlled version of your site (context + key links). **Today there are no guarantees of adoption**: use it as a **complementary hint**, not as security. Even so, it is very useful in an intermediate strategy: if you limit the full HTML, it can be the "door" to offer **exactly** what you want them to understand.

* [https://llmstxt.org/](https://llmstxt.org/)

**Other useful options (without reinventing anything)**

* `robots.txt`: the classic exclusion/permission standard for crawlers.
* Meta `robots` tag: you can add the `<meta name="robots" content="noindex, nofollow">` tag (or combinations like `noai`, if the engines recognize it) in the `<head>` of your HTML to control crawling and indexing at the page level.
* `sitemap.xml`: if you want *classic SEO*, keep the sitemap and decide which routes are included.
* **RSS/Atom**: useful if you want to be discovered without exposing the full body.

## robots.txt: what it is and what it is NOT

`robots.txt` is a good-faith agreement: it **indicates** what a bot should crawl, but it **does not prevent** it by itself.

Two quick ideas:

1. If a bot *respects* `robots.txt`, your file is the simplest (and compatible) way to control its behavior.

2. If a bot *does not respect* `robots.txt`, you need enforcement layers: server rules, WAF, rate limiting, etc.

### Compliance note (reputation and reporting)

As of today, **OpenAI and Anthropic state that their bots are controlled via** `robots.txt` and document how to allow/block their agents:

* OpenAI: [https://platform.openai.com/docs/bots](https://platform.openai.com/docs/bots) and FAQ for publishers: [https://help.openai.com/en/articles/12627856-publishers-and-developers-faq](https://help.openai.com/en/articles/12627856-publishers-and-developers-faq)
* Anthropic: [https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler)

If you detect that a bot from these providers **is not respecting** your rules (and you have already verified syntax, caches, and that the User-Agent is not a spoof), **report it**: it is important to fix possible bugs and also for their reputation (if they promise to respect it, they have to comply).

**Personal note (and a dose of realism)**

My impression is that **not all bots or scrapers will respect** `robots.txt`, so it should not be your only defense.

## Strategy 1: total block

This is the most direct reaction: **completely block most AI bots**, even though it puts us at risk of becoming invisible to those who use AI as a search engine.

### Use ai-robots-txt (and do not reinvent the wheel)

The **ai-robots-txt** repository already has *all the work done*: a living list of user-agents + ready-to-copy examples. In addition to `robots.txt`, it includes **server snippets** (and the repo itself explains how to apply each one depending on your stack).

* Repository (guide + context): [https://github.com/ai-robots-txt/ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt)

Ready-to-copy guides: [robots.txt](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/robots.txt), [Apache](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/.htaccess), [Nginx](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/nginx-block-ai-bots.conf), [Caddy](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/Caddyfile), [HAProxy](https://github.com/ai-robots-txt/ai.robots.txt/blob/main/haproxy-block-ai-bots.txt).

**Practical recommendation:** copy the file that fits you (or combine them: `robots.txt` + server blocking) and **keep it updated** with the project's releases.

### IP blocking (real enforcement)

If you want a **harder** layer than `robots.txt` and user-agent control, some providers publish **official IP ranges**. With them you can **block (403)** specific bots or **allowlist** search bots and block the rest.

> Tip: always use the **official URLs** (lists change); do not copy third-party lists.

#### Where to get official IPs (JSON)

* **OpenAI**

  * GPTBot (training): [https://openai.com/gptbot.json](https://openai.com/gptbot.json)
  * OAI-SearchBot (search): [https://openai.com/searchbot.json](https://openai.com/searchbot.json)
  * ChatGPT-User (user-initiated requests): [https://openai.com/chatgpt-user.json](https://openai.com/chatgpt-user.json)

* **Perplexity**

  * PerplexityBot (search): [https://www.perplexity.ai/perplexitybot.json](https://www.perplexity.ai/perplexitybot.json)
  * Perplexity-User (user-initiated): [https://www.perplexity.ai/perplexity-user.json](https://www.perplexity.ai/perplexity-user.json)

* **Google (classic crawlers, useful if you care about SEO/visibility in search engines)**

  * Common crawlers (Googlebot): [https://developers.google.com/static/search/apis/ipranges/googlebot.json](https://developers.google.com/static/search/apis/ipranges/googlebot.json)
  * Special crawlers: [https://developers.google.com/static/search/apis/ipranges/special-crawlers.json](https://developers.google.com/static/search/apis/ipranges/special-crawlers.json)
  * User-triggered fetchers: [https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json](https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json)
  * User-triggered fetchers (Google): [https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json](https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json)

* **Microsoft (Bingbot)**

  * Bingbot: [https://www.bing.com/toolbox/bingbot.json](https://www.bing.com/toolbox/bingbot.json)

* **Anthropic (important nuance)**

  * Anthropic indicates that **it does not publish IP ranges for its crawling bots** (they use public provider IPs). Therefore, IP blocking is not a reliable method for ClaudeBot/Claude-SearchBot.
  * Even so, they do publish **egress IPs for their API** (this is not equivalent to crawling): [https://platform.claude.com/docs/en/api/ip-addresses](https://platform.claude.com/docs/en/api/ip-addresses)

#### Nginx

To block AI bots by IP in Nginx, you can create a file with the ranges to block and then integrate it into the server configuration. This way, any request from those IPs will be denied automatically.

1. Create the file `/etc/nginx/ai_bot_ips.conf` with the IP ranges you want to block, for example:

```nginx
geo $block_ai_ip {
    default 0;

    # OpenAI GPTBot (examples)
    132.196.86.0/24 1;
    52.230.152.0/24 1;

    # PerplexityBot (examples)
    3.224.62.45/32 1;
    107.20.236.150/32 1;
}
```

2. Include this file in your `server {}` block and apply the block:

```nginx
include /etc/nginx/ai_bot_ips.conf;

if ($block_ai_ip) {
    return 403;
}
```

> Remember: if you have a CDN or reverse proxy in front, make sure Nginx receives the real visitor IP so the block works correctly.

#### Apache 2.4+

In Apache 2.4+ you can block IP ranges easily using the `Require not ip` directive. This lets you deny access to certain IPs both in the VirtualHost configuration and at the `.htaccess` level if your hosting allows it. You only need to specify the ranges or addresses to block, and those not in those IPs will still be able to access normally.

Example in VirtualHost:

```apache
<Directory "/var/www/html">
  <RequireAll>
    Require all granted

    # IP/CIDR block (examples)
    Require not ip 132.196.86.0/24
    Require not ip 52.230.152.0/24
    Require not ip 3.224.62.45/32
  </RequireAll>
</Directory>
```

Example in `.htaccess` (requires `AllowOverride` to be enabled):

```apache
<RequireAll>
  Require all granted
  Require not ip 132.196.86.0/24
  Require not ip 52.230.152.0/24
</RequireAll>
```

#### Helper script (bot-ip-ranges.sh)

To make the work easier, I created **bot-ip-ranges.sh**, a script designed specifically for this series: it downloads and normalizes IP ranges of bots from official sources, so you can integrate them into your configuration without doing it by hand.

Repository: [https://github.com/Len4m/bot-ip-ranges.sh](https://github.com/Len4m/bot-ip-ranges.sh)

Quick command to download, grant permissions, and run (returns the list of IPs):

```bash
curl -fsSL https://raw.githubusercontent.com/Len4m/bot-ip-ranges.sh/main/bot-ip-ranges.sh -o /tmp/bot-ip-ranges.sh && chmod +x /tmp/bot-ip-ranges.sh && /tmp/bot-ip-ranges.sh
```

### Real cost of total blocking

* You can lose visibility in AI-based search products.
* It does not solve the problem of malicious bots or those impersonating others.
* It is a clear and easy stance to maintain, but **the most aggressive**.

## Strategy 2: intermediate block (stay visible)

The key is to differentiate between **search bots** (allow) and **training bots** (block), applying different rules to each type in order to achieve visibility in AI results without facilitating training with your content.

- Let essential elements be crawled (title, summary, metadata), but limit access to the full article.
- Allow only search bots to access, blocking training bots when you can (by User-Agent and/or IP).
- If you need visibility without giving away the full content, serve summaries or teasers to bots.

This way, you can keep appearing in AI Search without all your content ending up in training datasets.

### 1) Bot control (search vs training)

More and more providers separate bots:

* A bot for **training**.
* Another bot for **search**.
* And sometimes an agent for **user-initiated requests**.

An example `robots.txt` with this philosophy (adjust it to the live list of ai-robots-txt):

```txt
# Training (block)
User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

# Search (allow, if you want visibility)
User-agent: OAI-SearchBot
Allow: /

User-agent: Claude-SearchBot
Allow: /

# User-initiated requests (optional)
# (These agents are usually better handled with rate limiting and/or IP allowlist)
User-agent: ChatGPT-User
Allow: /

User-agent: Claude-User
Allow: /
```

### 2) Route control (teaser vs full content)

The cleanest strategy (if you can adapt it) is to separate routes:

* **Full route (human):** `/blog/mi-articulo` (full HTML)
* **AI route (bot):** `/ia-content/mi-articulo.md` (minimal content for AI)

Then:

* You allow bots to access `/ia-content/...`
* You block training bots in `/blog/...`
* And you decide whether the search bot sees the full HTML or the AI content (depending on your tolerance)

Example:

```txt
# AI bots: only AI content
User-agent: GPTBot
Disallow: /blog/
Allow: /ia-content/

User-agent: ClaudeBot
Disallow: /blog/
Allow: /ia-content/

# Search bot (option A: allow everything)
User-agent: OAI-SearchBot
Allow: /

# Search bot (option B: allow only AI content)
# User-agent: OAI-SearchBot
# Disallow: /blog/
# Allow: /ia-content/

User-agent: *
Allow: /
```




### 3) Additional IP blocking (recommended)

In addition to User-Agent control, **you can also apply IP blocking**. As we saw in previous sections, there are public JSON lists with the IP ranges of the main AI bots. We already saw this in [IP blocking (real enforcement)](#ip-blocking-real-enforcement). You can filter those ranges to obtain only the IPs of training bots (excluding search and user bots) and thus block only those you really do not want to access.

To make this filtering easier, you can use the script mentioned earlier:

[https://github.com/Len4m/bot-ip-ranges.sh](https://github.com/Len4m/bot-ip-ranges.sh)

For example, to get only the IPs of training bots, run:

```bash
./bot-ip-ranges.sh --exclude-search --exclude-user
```

That gives you a list to block directly from Nginx, Apache, or your WAF, keeping you visible to search AI and users but not for training.

## Show alternative content to bots

In [Part 3](/posts/limit-ai-access-to-content-without-disappearing-part-3/) I go into detail on **how to adapt that alternative content to minimize tokens** (what to include, what to omit, and how to structure it without losing context). Here I limit myself to two implementation patterns. They are not mutually exclusive.

### Prepare alternative content

You create an alternative version per article (plain text, Markdown, or ultra-minimal format). Ideally:

* lightweight
* with the *minimum useful context*
* with a canonical link to the article

Example of **minimal TOON** representation (it can be plain text, json, or Markdown) for this same article, optimized for LLMs and low cost:

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

Create an alternative file with the `.toon` format (for example, `limitar-acceso-ia-contenido-sin-desaparecer-parte-2.toon`), although it could also be plain text, Markdown, or JSON, and link it both in `llms.txt` and in the HTML using `<link rel="alternate" type="text/plain" href="/ia-content/limitar-acceso-ia-contenido-sin-desaparecer-parte-2.toon">`.

> I talk about all of this (how to design and compact alternative content, further reduce exposed tokens, ...) in depth in [Part 3: More token reduction](/posts/limit-ai-access-to-content-without-disappearing-part-3/).

### Same URL, different response by User-Agent

If you do not want to create new routes, you can serve *something else* when you detect a bot.

#### Nginx example (conceptual)

1. Detect bots by User-Agent (ideally relying on a list like ai-robots-txt):

```nginx
map $http_user_agent $is_ai_bot {
    default 0;
    ~*(GPTBot|ClaudeBot|ChatGPT-User|Claude-User|OAI-SearchBot|Claude-SearchBot) 1;
}
```

2. On article routes, if it is a bot, try to serve a `.toon` file (or `txt`, `json`, `md`):

```nginx
location ^~ /blog/ {
    # Humans (default): full content
    try_files $uri $uri/ /index.html;

    # Bots: serve .toon if it exists
    if ($is_ai_bot) {
        rewrite ^/blog/(.*)$ /ia-content/$1.toon break;
    }
}

location ^~ /ia-content/ {
    default_type text/plain;
    try_files $uri =404;
}
```

#### Nginx example (advanced: User-Agent + IP)

If you want more reliability, you can combine User-Agent and IP ranges (see [IP blocking (real enforcement)](#ip-blocking-real-enforcement)):

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

**Important points:**

* Do not apply this to Googlebot (or to your SEO strategy) if you do not want "cloaking" problems.
* This technique is useful when you do not want to touch the CMS, but it requires care to avoid breaking caches/CDNs.
* The important thing is that you keep the **concept** and learn to configure your server according to what is explained in this article, adapting it to your stack and specific needs.
* Another option: instead of serving static files, you can store all alternative content in a **database** and pass the URL as a parameter to an endpoint in charge of returning the alternative content (for example, `/api/ia-content?url=/blog/mi-articulo`).

## Maintenance and monitoring (must-have)

Regardless of the strategy you choose (total block, intermediate block, or alternative content), maintenance and monitoring are essential for measures to remain effective:

* Automate the download of IP ranges or JSON (for example with `curl` + `jq`) or using the `bot-ip-ranges.sh` script and regenerate the Nginx/Apache include.
* Periodically review if the provider **updates** `creationTime`, changes prefixes, or publishes new IPs.
* Combine **IP + User-Agent** when possible: this reduces spoofing and false positives.
* **Measure**: review logs by User-Agent, most-accessed routes, and 4xx/5xx errors.
* **Update the bot lists**: the ai-robots-txt file and ranges change frequently.
* **Rate limits**: even "well-behaved" bots can generate unexpected traffic spikes.
* **Do not rely on this alone to protect sensitive URLs**: if you have critical resources, protect them properly (auth, tokens, WAF...).

And I return to the idea from the beginning: the goal is not "to win a war". It is **to decide what you show, to whom, and at what cost**.

To make the process easier, I created the script [`bot-ip-ranges.sh`](https://github.com/Len4m/bot-ip-ranges.sh), which I used while writing this article to run tests. It is verified (as of the date of writing this article) and greatly simplifies blocking bots by IP compared to doing it manually. Check the repository for instructions and examples.

If you want to squeeze token reduction even more, continue with [Part 3](/posts/limit-ai-access-to-content-without-disappearing-part-3/).

## References and resources

* Part 1: [How to limit AI access to your content without disappearing from the web (Part 1 - Introduction)](/posts/limit-ai-access-to-content-without-disappearing-part-1/)
* Part 3: [How to adapt alternative content to reduce token consumption (Part 3 - More token reduction)](/posts/limit-ai-access-to-content-without-disappearing-part-3/)
* ai-robots-txt (repository): [https://github.com/ai-robots-txt/ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt)
* llms.txt (proposal): [https://llmstxt.org/](https://llmstxt.org/)
* Robots Exclusion Protocol (RFC 9309): [https://www.rfc-editor.org/rfc/rfc9309.html](https://www.rfc-editor.org/rfc/rfc9309.html)
* OpenAI: Overview of OpenAI Crawlers: [https://platform.openai.com/docs/bots](https://platform.openai.com/docs/bots)
* OpenAI IP ranges:

  * [https://openai.com/gptbot.json](https://openai.com/gptbot.json)
  * [https://openai.com/searchbot.json](https://openai.com/searchbot.json)
  * [https://openai.com/chatgpt-user.json](https://openai.com/chatgpt-user.json)
* Anthropic: Does Anthropic crawl data from the web, and how can site owners block the crawler?: [https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler)
* Anthropic (documented egress IPs): [https://platform.claude.com/docs/en/api/ip-addresses](https://platform.claude.com/docs/en/api/ip-addresses)
* Google: Robots.txt specification: [https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt](https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt)
