---
title: "Mod ctfauth | Bsidessf 2022 | Catégorie Reverse | [Vozec/FR]"
date: 2022-06-10T12:00:00Z
description: "Mod ctfauth | Bsidessf 2022"
categories: ["writeup"]
tags: ["reverse","tuto","writeup"]
keywords: ["tuto", "reverse","howto","ctf","mod_ctfauth","ctftime","Bsidessf","crypto","master","factor","vozec"]
---

# Mod ctfauth | Tjctf 2022

## Fichier(s)
- [Challenge files](./files/httpd.conf)
- [Challenge files](./files/ctfauth.so)

## Nécessaires
- Python3 + Ida + Ghidra

## Flag
```
CTF{http_headers_amiright}
```

## Solution détaillée

### Partie 1: Découverte du challenge

Ce challenge mélange un peu de Web et une majorité de reverse.
Deux fichiers sont fournis,

- Une configuration apache2
- Un fichier ``.so``
- Le lien d'un site web (Hébergé en local pour le writeup)

Voici ce que nous avons quand nous nous rendons sur le site :

```html
<html><body><h1>It works!</h1></body></html>
```

Rien de très pertinent , jetons un œil au fichier de configuration ``httpd.conf`` :

```bash
DocumentRoot "/usr/local/apache2/htdocs"
<Directory "/usr/local/apache2/htdocs">
    AllowOverride None
    Header set Cache-Control no-cache
    Require all granted
</Directory>

<Directory "/usr/local/apache2/htdocs/secret">
    AllowOverride None
    Header set Cache-Control no-cache
    Require ctfauth
</Directory>
```

Ça c'est intéressant ! On apprend l'existence de ``/secret``
Malheuresement , l'accés est bloqué !

```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
</body></html>

```

Tous ceci est logique , on remarque que l'accès est limité par un module : ``Require ctfauth``

En remontant dans le fichier :

```bash
LoadModule ctfauth_module modules/ctfauth.so
```

Voilà , maintenant nous savons que le **.so** est un module *apache2* permettant de gérer l'accès ou non à la page en question !

### Partie 2: Mise en place d'un environnement de travail.

Pour continuer ce challenge, j'ai utilisé un serveur en local grâce à *[Docker](https://www.docker.com/)* et celui va me permettre par la suite de tester les manipulations et modification que je vais faire .

Grâce à ce serveur, je pourrais accéder aux logs et donc avoir plus d'informations sur mon avancé .

Voici le DockerFile:

```bash
FROM httpd:2.4
COPY ./httpd.conf /usr/local/apache2/conf/httpd.conf
COPY ./ctfauth3.so /usr/local/apache2/modules/ctfauth.so
RUN \
	mkdir /usr/local/apache2/htdocs/secret; \
	echo '<html><body><h1>flag{randomflag}</h1></body></html>' > /usr/local/apache2/htdocs/secret/secret.html;

EXPOSE 80
```


### Partie 3: Compréhension du plugin.

Ouvrons le fichier ``ctfauth.so`` avec *[Ida](https://hex-rays.com/decompiler/)*

On retrouve une fonction qui gère l'authentification :

Voici le retour de fin :

```c
if ( *v13 == v17 )
{
  ap_log_rerror_("./ctfauth.c", 87LL, 0xFFFFFFFFLL, 4LL, 0LL, a1, "CTF: Looks good!");
  free(v13);
  result = 1LL;
}
else
{
  ap_log_rerror_("./ctfauth.c", 82LL, 0xFFFFFFFFLL, 4LL, 0LL, a1, "CTF: Token doesn't match!");
  free(v13);
  result = 0LL;
}
return result;
```

Reprenons depuis le début de la fonction :

```c
v3 = (const char *)apr_table_get(v2, "X-CTF-User");
if ( !v3 )
{
  ap_log_rerror_("./ctfauth.c", 38LL, 0xFFFFFFFFLL, 4LL, 0LL, a1, "CTF: No username detected");
  return 0LL;
}
v4 = v3;
if ( strcmp(v3, "ctf") )
{
  ap_log_rerror_("./ctfauth.c", 42LL, 0xFFFFFFFFLL, 4LL, 0LL, a1, "CTF: Incorrect username");
  return 0LL;
}
```

Le début est Trivial, on voit tout de suite qu'un **Header** ``X-CTF-User`` égal à ``ctf`` est nécessaire

```c
v5 = apr_table_get(*(_QWORD *)(a1 + 232), "X-CTF-Authorization");
v6 = 0;
v7 = v5 == 0;
if ( !v5 )
{
  ap_log_rerror_("./ctfauth.c", 49LL, 0xFFFFFFFFLL, 4LL, 0LL, a1, "CTF: Missing authorization header");
  return 0LL;
}
v8 = 6LL;
v9 = "Token ";
v10 = (const char *)v5;
do
{
  if ( !v8 )
    break;
  v6 = *v10 < (unsigned int)*v9;
  v7 = *v10++ == *v9++;
  --v8;
}
while ( v7 );
if ( (!v6 && !v7) != v6 )
{
  ap_log_rerror_(
    "./ctfauth.c",
    54LL,
    0xFFFFFFFFLL,
    4LL,
    0LL,
    a1,
    "CTF: Incorrect header format for authorization header");
  return 0LL;
}
```

Un autre **Header** est requis. ``X-CTF-Authorization`` et après avoir passé un petit moment un bien comprendre le pseudo-code , le seul prérequis ici est que la valeur commence par ``Token ``

Par la suite on a :

```c
v11 = v5 + 6;
v12 = apr_base64_decode_len(v5 + 6, v10);
v13 = malloc(v12);
if ( (unsigned int)apr_base64_decode(v13, v11) != 16 )
{
 ap_log_rerror_(
   "./ctfauth.c",
   67LL,
   0xFFFFFFFFLL,
   4LL,
   0LL,
   a1,
   "CTF: Incorrect decoded length for authorization header (expected: %d bytes)");
 return 0LL;
}
 ```

Ici , on a une vérification de la taille de ce qui suit ``Token ``
``apr_base64_decode`` nous indique que le **Header** est de la forme :

```bash
X-CTF-Authorization: Token BASE64
```

 et que la **taille de la base64 décodée est égale à 16**

Enfin , on a :

```c
apr_md5_init(v16);
 apr_md5_update(v16, "GuardingTheGatesFromEvilCTFPlayers", 34LL);
 v14 = strlen(v4);
 apr_md5_update(v16, v4, v14);
 apr_md5_update(v16, "GuardingTheGatesFromEvilCTFPlayers", 34LL);
 apr_md5_final(&v17, v16);
 if ( *v13 == v17 )
 {
   ap_log_rerror_("./ctfauth.c", 87LL, 0xFFFFFFFFLL, 4LL, 0LL, a1, "CTF: Looks good!");
   free(v13);
   result = 1LL;
 }
 else
 {
   ap_log_rerror_("./ctfauth.c", 82LL, 0xFFFFFFFFLL, 4LL, 0LL, a1, "CTF: Token doesn't match!");
   free(v13);
   result = 0LL;
 }
 return result;
```

*lire [cette documentation](https://apr.apache.org/docs/apr/trunk/group___a_p_r___m_d5.html)*

Ici , un hash **MD5** de

```bash
GuardingTheGatesFromEvilCTFPlayers + v4 + GuardingTheGatesFromEvilCTFPlayers
```

avec:
 ``v4 = v3 = (const char *)apr_table_get(v2, "X-CTF-User");`` = ``'ctf' ``

Finalement , la valeur du Token serai:

```bash
base64(md5('GuardingTheGatesFromEvilCTFPlayerscfGuardingTheGatesFromEvilCTFPlayers')[16])
```

Malheureusement , cette technique n'a pas fonctionné et je n'ai toujours pas la réponse à ce soucis .

##### Contournement du Token:

Comme expliqué précédement , le serveur sur le Docker donne accès à des logs :

```
[Fri Jun 10 16:17:07.819589 2022] [:warn] [pid 99:tid 140199342372608] [client 172.17.0.1:33192] CTF: No username detected
[Fri Jun 10 16:17:07.819623 2022] [authz_core:error] [pid 99:tid 140199342372608] [client 172.17.0.1:33192] AH01630: client denied by server configuration: /usr/local/apache2/htdocs/secret
172.17.0.1 - - [10/Jun/2022:16:17:07 +0000] "GET /secret HTTP/1.1" 403 199
172.17.0.1 - - [10/Jun/2022:16:17:57 +0000] "-" 408 -
172.17.0.1 - - [10/Jun/2022:16:18:06 +0000] "-" 408 -
```

Utilisons cette fois *[Ghidra](https://ghidra-sre.org/)*


Le code :

```c
ap_log_rerror_("./ctfauth.c",0x52,0xffffffff,4,0,param_1,"CTF: Token doesn\'t match!",
```


est effectué durant la dernière vérification , ainsi : le bon hash md5 de comparaison est déjà calculé et présent en mémoire . De plus ; celui-ci est constant !



On voit ici  dans l'assembleur que la valeur du md5 est **push** dans le registre ``RDI``

![Alt text](./img/md5.png)

Par chance , le **code d'affichage d'un token invalide** et ce stockage dans **RSI** sont très proche .

On peut vérifier que ce registre **RSI** n'est pas modifié !

On peut donc **patcher** le binaire pour remplacer ``CTF: Token doesn\'t match!`` par ``RSI``

![Alt text](./img/push_key.png)

Enfin , on peut envoyer un token aléatoire dans les **headers** et attendre le retour des logs du serveur !

![Alt text](./img/key.png)

[ctfauth_patched.so](./files/ctfauth_patched.so)

Bingo ! Nous avons maintenant le **MD5**

```python
import base64
a = b'm\xd8Q\b\x14\x1bzXE\x01\xb5\x86\x1b,\x83X)\xb6.p\x8f\x7f'
print(base64.b64encode(a[:16]).decode())
```

Output:
```bash
root@DESKTOP-HNQJECB: /c/mod_ctfauth
➜   python3 find.py
bdhRCBQbelhFAbWGGyyDWA==
```

Il ne nous reste plus qu'à tous envoyer et le tour est joué :

```HTML
<p>Great job! Here's your flag</p>
<pre>CTF{http_headers_amiright}</pre>

```
