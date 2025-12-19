---
author: Lenam
pubDatetime: 2025-12-12T00:00:00Z
title: "In Defense of $ and # in the Shell Prompt"
urlSlug: why-keep-dollar-hash-shell-prompt
featured: true
draft: false
ogImage: "../../assets/images/opinion/prompt-simbol.png"
tags:
    - linux
    - shell
    - prompt
    - opinion
description:
  "Opinion piece on why keeping $ and # in the shell prompt still matters to quickly see whether you're a normal user or root, even in colorful terminals."
lang: en
translationId: por-que-seguir-usando-dollar-y-hash-en-el-prompt-de-la-shell
---

## Table of Contents

## In Defense of the Humble `$` and the Fearsome `#`

*(totally subjective opinion, but with love)*

This post is **not** a CTF writeup, nor a 0day exploit, nor anything useful for scoring points on a scoreboard.
It's simply a loving rant about something I see more and more: people removing the `$` and `#` from their prompt.

Yes, those old-school symbols that indicate:

* `$` → normal user
* `#` → root (aka: "if you mess up here, you cry")

And I'm here to say:

> **please, let's not kill them just yet.**

## The prompt: that little sign that warns you before you screw up

Call it prompt, path, cursor, "where I type commands", whatever.
That little piece of text before what you type isn't decoration: it's **critical information**.

```text
$ command   <- normal user
# command   <- root
```

With a single character you know:

> Will what I'm about to do break *my* user… or break *the production server*?

No `whoami`, no `id`, no looking at anything. You see it at a glance and you're done.

## Why do some hackers skip the `$` and `#`?

Because in the hacking and sysadmin world we're always trying weird things in the prompt, so it's no surprise that, for whatever reason, many people ditch the `$` and `#`.

I see a lot of prompts like this:

```text
❯
λ
»
```

Or super polished zsh/fish themes, with:

* user, host, path
* git branch
* exit code
* the moon phase if you're not careful

…but no trace of `$` or `#`.

The typical reasons:

* "It looks cleaner / more minimalist"
* "I already distinguish by colors"
* "I *know* what I'm doing, I don't need that"

Fair enough. Until you leave your cave.

## The day colors can't save you

The "I use colors" argument breaks down very quickly:

* In Markdown, README, blogs, writeups…
  The color usually disappears.
  Example:

  ```text
  # iptables -F
  ```

  In your terminal you had it in nuclear red with a radioactive background.
  In the blog: plain text and a face like "well, this must be safe, right?".

* In a crappy TTY, a random container or a remote machine without your zsh config, your favorite theme doesn't exist.

* In a screenshot, in a PDF or on a bad monitor during a talk or conference, colors look iffy, but the `#` is still understood the same way.

Colors are cool, yes. But they **don't travel well**.
The character does.

## Examples where the `#` should give you chills

It's much easier to see the danger like this:

```text
# iptables -F
# userdel -r wrong-user
# mv /etc /etc.bak
# mysql -e 'DROP DATABASE production;'
```

Than like this:

```text
❯ iptables -F
❯ userdel -r wrong-user
❯ mv /etc /etc.bak
❯ mysql -e 'DROP DATABASE production;'
```

In the second case, if you don't have context, it looks like any old script.
In the first one, the `#` is already yelling at you:

> Hey, this isn't a toy, are you sure you want to hit Enter?

It won't always save you, but it's **a free mental brake**.

## Documentation, writeups and CTFs

In CTFs and writeups, `$` and `#` are pure gold:

* `$` → you can copy this as a normal user
* `#` → this is root / sudo stuff

Typical example in a writeup:

```text
$ sudo -l
# cat /root/root.txt
```

Even if you're reading quickly, your brain understands: "ah, okay, here I'm already root".
No colors, no plugins, nothing. In a PDF, in a blog, wherever.

If you remove those symbols, you force the reader to **guess the context**. And we already have enough to deal with—fighting filters, WAFs, triple URL-encoded payloads, race conditions and logs full of 500 errors—without also fighting the prompt.

## The aesthetics argument

Yes, I know: a prompt like:

```text
┌─[ctfer@kali]─[~/ctf/machine]
└──╼ $
```

looks more "pro" than a sad:

```text
$
```

And there's nothing wrong with setting up a nice prompt.
But it costs nothing to end it with:

* `$` if you're a user
* `#` if you're root

You can have:

* colors
* git
* time
* exit code
* environment (prod/stage/dev)

…and still let **one character at the end summarize your privileges**.

## This is not a standard, it's a rant

All of this is simply **my grumpy shell user opinion**:

* Want a prompt with emojis and no `$` or `#`? Go ahead.
* Want a single `❯` symbol for everything? Your terminal, your rules.
* Want to live dangerously without knowing when you're root? That's on you 😂

I'm just arguing that, in a world of:

* screenshots,
* CTF blogs,
* colorless markdown,
* random SSH sessions,

the old `$` and the old `#` are still **the cheapest and most effective way to see privileges at a glance**.

It's not nostalgia. It's pure convenience.

## TL;DR

* `$` → normal user
* `#` → root
* They're ugly, but extremely useful.
* Cool colors and themes are fine, but they don't replace the symbol.
* In writeups, documentation and CTFs they help a lot to understand the context.

And in the end, as always in this world:

> Hack however you want, configure your shell however you want…
> but if you keep the `$` and `#`, you're certainly not hurting yourself.

Thanks for reading this far. I hope I've convinced you a little, and if not, that's fine too: in the end, what matters is that everyone is happy with their prompt. 😊
