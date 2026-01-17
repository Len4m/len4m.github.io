---
author: Lenam
pubDatetime: 2026-01-14T00:00:00Z
title: "How to limit AI access to your content without disappearing from the web (Part 1 - Introduction)"
urlSlug: limit-ai-access-to-content-without-disappearing-part-1
featured: true
draft: false
ogImage: "../../assets/images/limitar-acceso-ia-contenido-sin-desaparecer/OpenGraph.png"
tags:
    - ai
    - privacy
    - copyright
    - web
    - opinion
    - legal
    - ia-limitation
description:
  "An intermediate strategy to stay visible without giving away knowledge or increasing energy costs."
lang: en
translationId: limitar-acceso-ia-contenido-sin-desaparecer-parte-1
---

![COPYRIGHT INFRINGEMENT](../../assets/images/limitar-acceso-ia-contenido-sin-desaparecer/OpenGraph.png)

*An intermediate strategy to stay visible without giving away knowledge or increasing energy costs.*

**Series:**
- **Part 1: Introduction**
- [Part 2: Technical strategies](/posts/limit-ai-access-to-content-without-disappearing-part-2/)
- [Part 3: More token reduction](/posts/limit-ai-access-to-content-without-disappearing-part-3/)

## Table of Contents

## Total block: the initial reaction

Thinking that I do not want artificial intelligence to **learn or be trained** on the content of my blog, the first idea that crossed my mind was to **completely block access for AI bots**. I was aware that, in many cases, this kind of blocking can be bypassed, but even so I considered relying on known lists -- like *ai-robots-txt* or the verified bot lists maintained by services like Cloudflare -- to limit that access as much as possible.

## Legal context and legitimacy of blocking

This initial reaction does not stem solely from individual or economic concern, but also from a much broader context, including the **European legal framework** in which those of us who publish content in the European Union operate. Texts and debates warning that the rapid advance of artificial intelligence, driven mainly by large tech companies, **poses legal, ethical, and environmental risks that are far from minor** are becoming more frequent. In the European sphere, this has translated into specific regulation: EU legislation recognizes exceptions for text and data mining (*Text and Data Mining*), but also allows creators and publishers to **explicitly reserve their rights** and oppose the use of their content for training AI systems.

This legal framework reinforces the idea that limiting the automated use of content is not only a technical or economic matter, but also a legitimate decision from a legal standpoint.

## The risk of disappearing

However, after thinking about it a bit more, a much more unsettling doubt appeared.

More and more people are starting to use artificial intelligence **for absolutely everything**, including searching for information. And although many of those users still end up visiting the linked pages, the reality is that a large majority settles for the answer the LLM provides. In fact, it is not uncommon -- and I do it myself at times -- to ask directly *"make me a summary of this page"* and never visit it.

Then the uncomfortable question arises:
if we completely block AI access to our blog or web service, and most users end up using AI as their main gateway to information, **don't we risk becoming invisible?**

## Intermediate strategy: what to show and what to hold back

The solution, at least from my point of view, **does not involve completely blocking access to content**, but something much more nuanced: **consciously deciding which parts of our content can circulate and which cannot**.

### What AI can see

It makes sense to allow artificial intelligence to access the **non-substantial** elements of an article or service: the title, the summary or introduction, the publication date, a featured image, or a brief description of the service. That information works as a storefront, as context, and as a discovery signal. In addition, by limiting access to the full content, **we substantially reduce the tokens used**, which amounts to a **direct reduction in energy consumption**.

### What should stay out of reach

By contrast, the **full content of the article** -- where knowledge, experience, opinion, and distinctive value are really provided, and from which an LLM could learn -- should remain **out of reach of AI bots**. Not to hide it from the human reader, but to reserve it for those who consciously decide to visit the web.

## Summary and technical preview

The idea is not to disappear from the new AI-driven search ecosystem, but to **stay visible without giving away the substance of the content**. Let AI point the way, but make the real value -- the one that requires time, context, and resources -- exist only in your own space and be consumed consciously and responsibly.

### A technical solution (preview)

Although the technical details will be developed in [Part 2](/posts/limit-ai-access-to-content-without-disappearing-part-2/), it is worth previewing the general idea. This series will have **three parts**: the third will focus on **how to adapt alternative content to further reduce token consumption** and will be published as [Part 3](/posts/limit-ai-access-to-content-without-disappearing-part-3/).

The strategy is to **combine several layers of control**, without yet going into specific implementations:

* indicate to AI bots, through standard signals, which parts of the site they should not crawl;
* limit automatic access to the full content, while keeping titles and summaries visible;
* and, when it makes sense, **show minimal alternative content to bots** (a teaser) that allows linking without exposing the whole text.

These measures do not prevent people from accessing the content, but they reduce the mass use of content by automated systems and the amount of information available for training.

It is worth insisting on a key idea: **none of these solutions is 100% reliable**. They are reasonable approximations in a changing scenario. In [Part 2](/posts/limit-ai-access-to-content-without-disappearing-part-2/) I will go into detail on how to apply them at a technical level, with concrete examples and resources, and [Part 3](/posts/limit-ai-access-to-content-without-disappearing-part-3/) will delve into how to adjust alternative content to reduce tokens without losing visibility.

> **Personal note**: everything laid out in this first part reflects my own opinions, reflections, and conclusions based on my experience and observation of the current context. They are not intended to be absolute truths or definitive solutions, and it is very possible that some of these ideas will evolve or even turn out to be wrong over time. This article does not seek to lecture, but to open an honest reflection on a problem that is still far from being resolved.
