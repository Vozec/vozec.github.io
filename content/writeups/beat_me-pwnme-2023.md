---
title: "Beat me! | PWNME CTF 2023"
date: 2023-05-06T12:00:00Z
description: "Voici un writeup complet du troisième challenge web du pwnme ctf"
tags: ["rce","js"]
keywords: ["js", "injection","reverse"]
---
[//]: <> (Wrote By Vozec 06/05/2023)
---

# Introduction du challenge :

```
A pro player challenge you to a new game. He spent a huge amount of time on it, and did an extremely good score.
Your goal is to beat him.. by any way
If the game doesn't start, try an other nagivator
```

# Tree Viewer

Les sources de ce challenge ne sont pas fournies.
A première vue, ce challenge est un jeu ou nous devons battre l'utilisateur **Eteck**.

Interceptons les requêtes interécentes avec burp.
On en retrouve 2:
- ```bash
  GET /scores HTTP/1.1
  Host: 13.37.17.31:51761
  Accept: */*
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
  X-Requested-With: XMLHttpRequest
  Referer: http://13.37.17.31:51761/
  Accept-Encoding: gzip, deflate
  Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
  Connection: close
  ```

- ```bash
  POST /scores HTTP/1.1
  Host: 13.37.17.31:51761
  Content-Length: 53
  Accept: */*
  X-Requested-With: XMLHttpRequest
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
  Content-Type: application/json
  Origin: http://13.37.17.31:51761
  Referer: http://13.37.17.31:51761/
  Accept-Encoding: gzip, deflate
  Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
  Connection: close

  {"score":"0","pseudo":"vozec","signature":-640686249}
  ```

La première nous renvoie juste le scoreboard :  
```bash
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 67
ETag: W/"43-Zll8AEH/EomYGs4Q4wETAixm8pk"
Date: Sat, 06 May 2023 10:54:47 GMT
Connection: close

[{"pseudo":"Eteck","score":1337420},{"pseudo":"vozec","score":"0"}]
```

La seconde est plus intéressante :  
```bash
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 69
ETag: W/"45-FZiNIGLDpIcqrQoobus5oDZkysI"
Date: Sat, 06 May 2023 10:56:04 GMT
Connection: close

{"msg":"Score added to the leaderboard","pseudo":"vozec","score":"0"}
```

Celle-ci permet en effet d'envoyer au serveur notre *score*.
On lui envoie 3 paramètres :
  - score
  - pseudo
  - signature

La première chose à tester est de modifier le score dans la requête d'envoi:
```json
{"score":"99999999","pseudo":"vozec","signature":-640686249}
```
*Résultat*:
```json
{"msg":"Invalid signature"}
```

Nous allons devoir comprendre d'où vient cette signature pour en regénérer une valide pour le score *99999999*.

En inspectant l'élément, on se rend compte que le javascript est obfusqué.
On cherche dans le ``main.....js`` le mot ``signature`` et on tombe sur ce code:

```js
(this, function(_0x2a816a) {
  var _0x534bdd = a0_0x37e9;
  switch (_0x2a816a['label']) {
  case 0x0:
      return _0x401772(_0x534bdd(0xcef))[_0x534bdd(0xdb5)](),
      _0x401772(_0x534bdd(0x456))[_0x534bdd(0x10e8)]('current'),
      _0x401772(_0x534bdd(0x8cc))[_0x534bdd(0x10e8)](_0x534bdd(0x1139)),
      _0x401772(_0x534bdd(0x4e7))[_0x534bdd(0x12df)](_0x534bdd(0x1139)),
      _0x401772(_0x534bdd(0x5c7))[_0x534bdd(0x12df)](_0x534bdd(0x1139)),
      _0x3f306f = function(_0x359a29) {
          var _0x29faf7 = _0x534bdd, _0x54a291, _0x3a1e82 = String(_0x359a29) + _0x29faf7(0xa73), _0x8a3192 = 0x0;
          if (0x0 === _0x3a1e82['length'])
              return _0x8a3192;
          for (_0x54a291 = 0x0; _0x54a291 < _0x3a1e82[_0x29faf7(0x120)]; _0x54a291++)
              _0x8a3192 = (_0x8a3192 << 0x5) - _0x8a3192 + _0x3a1e82[_0x29faf7(0x84)](_0x54a291),
              _0x8a3192 |= 0x0;
          return _0x8a3192;
      }
      ,
      (_0x3f296b = {
          'score': _0x5a84cd[_0x534bdd(0xbe9)](),
          'pseudo': this[_0x534bdd(0xba8)]
      })['signature'] = _0x3f306f(_0x5a84cd),
      [0x4, _0x401772[_0x534bdd(0x10a3)]({
          'type': _0x534bdd(0xa16),
          'url': _0x20fb46,
          'data': JSON[_0x534bdd(0x1fc)](_0x3f296b),
          'contentType': _0x534bdd(0x1309)
      })];
  case 0x1:
      return _0x2a816a[_0x534bdd(0xd34)](),
      this[_0x534bdd(0x79)](),
      [0x2];
  }
  });
```

On comprend que ce code est l'envoi du score au serveur.
On remarque cette fonction :
```js
_0x3f306f = function(_0x359a29) {
    var _0x29faf7 = _0x534bdd, _0x54a291, _0x3a1e82 = String(_0x359a29) + _0x29faf7(0xa73), _0x8a3192 = 0x0;
    if (0x0 === _0x3a1e82['length'])
        return _0x8a3192;
    for (_0x54a291 = 0x0; _0x54a291 < _0x3a1e82[_0x29faf7(0x120)]; _0x54a291++)
        _0x8a3192 = (_0x8a3192 << 0x5) - _0x8a3192 + _0x3a1e82[_0x29faf7(0x84)](_0x54a291),
        _0x8a3192 |= 0x0;
    return _0x8a3192;
}
```
Celle-ci est appelé au moment de la création du postdata de la requête:
```js
(_0x3f296b = {
    'score': _0x5a84cd[_0x534bdd(0xbe9)](),
    'pseudo': this[_0x534bdd(0xba8)]
})['signature'] = _0x3f306f(_0x5a84cd),
```

On place donc un break-point entre la définition de la fonction et l'envoie de la requêtes.  
*(ligne 31188)*   

J'ai ensuite fais exprès de perdre une partie avec 0 point.
On peut ensuite appelé la fonction ``_0x3f306f`` avec en paramètre ``0``:

![Alt text](./img/1.png)

On retrouve bien la même signature : ``-640686249``.
On peut donc en regénérer une pour le score *99999999*

Finalement, on renvoie la requêtes:
```json
{"score":"99999999","pseudo":"vozec","signature":370968487}
```

On reçois en réponse :
```bash
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 113
ETag: W/"71-5rbWWhtuRLQIEbmLl4euBjVB+PY"
Date: Sat, 06 May 2023 11:07:25 GMT
Connection: close

{
  "msg":"Score added to the leaderboard",
  "pseudo":"PWNME{Ch3a7_0n_Cl1en7_G4m3_Is_n0T_H4rD_3d}",
  "score":"99999999"
}
```

```bash
PWNME{Ch3a7_0n_Cl1en7_G4m3_Is_n0T_H4rD_3d}
```
