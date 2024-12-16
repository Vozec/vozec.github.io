---
title: "Writeup Crackity | TFC CTF 2021 | Catégorie reverse"
date: 2021-12-03T12:00:00Z
description: "Crackity , Java Reverse | TFC CTF 2021 "
categories: ["writeup"]
tags: ["reverse","tuto"]
keywords: ["tuto", "reverse","howto","ctf","TFC","ctftime","Crackity"]
---

# Unknown 2 | GrabCon CTF 2021

## Fichier(s)
- [Crackity.jar](./files/crackity.jar)

## Nécessaires
- [jd-gui](http://java-decompiler.github.io/)
- Python3

## Flag
```
TFCCTF{j4v4_0bfusc4t10n_1s_pr3tty_n0t_pr3tty}
```
## Solution détaillée

La solution n'est pas très longue mais elle permet d'introduire le reverse de fichier .jar avec un exemple assez basique.

Nous avons donc un fichier ``java`` à reverse pour trouver le Flag.
J'ai d'abord essayé d'exécuter le fichier mais il semble cassé, et je ne peux le lancer.

```bash
root@DESKTOP-HNQJECB: /c
➜   java crackity.jar
Error: Could not find or load main class crackity.jar
Caused by: java.lang.ClassNotFoundException: crackity.jar
```

Ouvrons donc avec jd-gui le fichier pour comprendre comment fonctionne le code :

![Alt text](./img/java.png)

Aïe ... C'est laid ; Le code est obfusqué.
J'ai donc cherché ce qu'il y avait de lisible et j'ai d'abord trouver ceci :
```Java
public static final String f4x82c624da = ("Nr" + (Math.log(3.0d) / 4.0d));

public static String IlLLIILIlIILLIllIIILLIlLILlLILLLLLIILIIlLIIIILlIlLlllLIIlLLllLlIlLLIIIIIlIllLlILILLLIILlLILIIllllLIlIlLLllIIILIllIllIllIlIIIIILlLILLLIIIILIILlLlIIIlLILlILllIlllIlLlILllllLlILIlllIlIlLILIlILILIlLLLIIlIlLlLlLlIIIlLILILIILLILLLLILIlLlILILLLIIILILIlLILllLIllILLLLlILlllLlIIlIILlLlILLlIllILlILIIlLlLLlIILllIIILlIIIlLlLlllLlLIIIILlIIILlLIlILLlILLLLLlIILIlLlllIIllLIILIILlLLlLLLllLLlLLLIIlIlllllIlLIILlIlLLLIlIllLLllILlLIILLlILLlLLIIlllIILIIllIlIlILlLILLILILIIIILlLIIlllllLlILIIIIlIlllILlIILLllLlLIIlIIIlILI(String paramString) {
   char[] arrayOfChar = new char[paramString.length()];
   for (byte b = 0; b < paramString.length(); b++)
     arrayOfChar[b] = (char)(paramString.charAt(b) - IlLLI.charAt(b % IlLLI.length()));
   return new String(arrayOfChar);
 }
```

La fonction prend en paramètre une string. Allons donc chercher plus loin dans le code.
Nous reviendrons sur ce code juste après.

Après quelques secondes :

On trouve ce type de string :

```Java
 public static final String IlLLIILIlIILLIllIIILLIlLILlLILLLLLIILIIlLIIIILlIlLlllLIIlLLllLlIlLLIIIIIlIllLlILILLLIILlLILIIllllLIlIlLLllIIILIllIllIllIlIIIIILlLILLLIIIILIILlLlIIIlLILlILllIlllIlLlILllllLlILIlllIlIlLILIlILILIlLLLIIlIlLlLlLlIIIlLILILIILLILLLLILIlLlILILLLIIILILIlLILllLIllILLLLlILlllLlIIlIILlLlILLlIllILlILIIlLlLLlIILllIIILlIIIlLlLlllLlLIIIILlIIILlLIlILLlILLLLLlIILIlLlllIIllLIILIILlLLlLLLllLLlLLLIIlIlllllIlLIILlIlLLLIlIllLLllILlLIILLlILLlLLIIlllIILIIllIlIlILlLILLILILIIIILlLIIlllllLlILIIIIlIlllILlIILLllLlLIIlIIIlILI = «{`zg£}knswiyw¼|¡¢«¨¥¦¨jy×;
 ```

Le padding du nom obfusqué de la fonction faisait qu'on ne les voyait pas tous de suite.

Un nouveau petit souci ce pose. On ne peut pas les récupérer en les copiant collant. Surement qu'il y a une sorte de sanitizing lors de la copie dans *jd-gui* .

Je vais donc utiliser un autre outil pour récupérer les strings et les placer dans un fichier texte :

[Jdax](https://github.com/skylot/jadx)

Il présente les mêmes fonctionnalités que l'autre outils de décompilation.

Maintenant que nous le pouvons, récupérons les strings chiffrés :

```python
allstring = [
'«{`zg£}knswiyw¼|¡¢«¨¥¦¨jy×',
'¤Úai«m©nidldìhªdz¢{a°¥¡¦Éz',
'¿§¤}udmµd`wª~±¨¥~xi¡¥ÀÛ',
'¢¸sq}¯ i©db¬£k¨f~à_¥¤¨h§¤°f«¢©g©Âë­',
'Åª°xie|hv£Ùt¨|¤  sf¢bclÃ`',
'»Ý¬ª~¢t¤¡e®­¯Ö{~e¢lc®e¤¤¨ry}lwÈ¸s',
'¶ug¦j~xè¤¨zgx«¦©yz­¼Èe',
'¹¥¨|¨¨¤m§b|j¬¬j£âd_ig}jy«¦¬dj¯w£Ê¡',
'Üf¬§ighiª¸guzd~­|°¥¡ß',
'´ç¢xn§¨~~w«ª¬«Ùwy¢jmr®~avgµ¥£',
'ârg£eh§¤¯zhyh³Äa¦kd §¤do}¡wÈ',
'¶¨~¤px¢|¢gª±`di¬©»¿|fw}h«¡¬`¤æy',
'¤Úai«m©nidldìhªdz¢{a°¥¡¦Éz',
'»Ë¡~t~i§tz§ª~Üx lhfg}uy±Õ',
'Åe¡¤}{q¦m`cmf®¤¨j¦fa®}¬d²ã¤',
'³Å|«¢¯©|y¤£ubnÕg«£m¥fw©¨°¨¡ªh¹Àb',
'«{e©wf{sr¢c«¯à|i¯hwkpwÀÙ',
'µÈffs¦¡edpxØa¯}m{az¨nu®kxÜ',
'¥³aeo{c}¢¦~kz©»Æha¦¢xuyz§|nß',
'¥Ü~~zxk¤§¦|oªeË¡ ¯¢id{Áç'
]
```

Enfin, nous allons utiliser python pour inverser le chiffrement.

La première chose importante que nous voyons tous de suite est qu’une string n'est pas obfusqué :

```Java
String f4x82c624da = ("Nr" + (Math.log(3.0d) / 4.0d));
```
Je l'ai exécuté en local et j'ai obtenu : ``"Nr0.27465307216702745"``

Nous semblons avoir la clef maintenant .
Analysons brièvement l'algorithme :

- ###### Création d'une string
```Java
char[] cArr = new char[str.length()];
```

- ###### Loop sur la longeur de la string d'entrée
```Java
for (int i = 0; i < str.length(); i++) { }
```

- ###### Ajout d'une lettre dans la string cArr
```Java
 cArr[i] = (char) (str.charAt(i) - f4x82c624da.charAt(i % f4x82c624da.length()));
```
Cette lettre en question est la résultante de la soustraction entre l'index de lettre de la string chiffré avec l'index de la lettre de la clé trouvée plus haut.

Grâce à ceci, on peut écrire [ce petit script python](./files/solve.py) :

```python
bigstr = "Nr0.27465307216702745"

def rev(input_):
  final = ""
  for i in range(len(input_)):
    a = ord(input_[i])
    b = ord(bigstr[i%len(bigstr)])
    final += chr(a - b)
  return final

allstring = [
'«{`zg£}knswiyw¼|¡¢«¨¥¦¨jy×',
'¤Úai«m©nidldìhªdz¢{a°¥¡¦Éz',
'¿§¤}udmµd`wª~±¨¥~xi¡¥ÀÛ',
'¢¸sq}¯ i©db¬£k¨f~à_¥¤¨h§¤°f«¢©g©Âë­',
'Åª°xie|hv£Ùt¨|¤  sf¢bclÃ`',
'»Ý¬ª~¢t¤¡e®­¯Ö{~e¢lc®e¤¤¨ry}lwÈ¸s',
'¶ug¦j~xè¤¨zgx«¦©yz­¼Èe',
'¹¥¨|¨¨¤m§b|j¬¬j£âd_ig}jy«¦¬dj¯w£Ê¡',
'Üf¬§ighiª¸guzd~­|°¥¡ß',
'´ç¢xn§¨~~w«ª¬«Ùwy¢jmr®~avgµ¥£',
'ârg£eh§¤¯zhyh³Äa¦kd §¤do}¡wÈ',
'¶¨~¤px¢|¢gª±`di¬©»¿|fw}h«¡¬`¤æy',
'¤Úai«m©nidldìhªdz¢{a°¥¡¦Éz',
'»Ë¡~t~i§tz§ª~Üx lhfg}uy±Õ',
'Åe¡¤}{q¦m`cmf®¤¨j¦fa®}¬d²ã¤',
'³Å|«¢¯©|y¤£ubnÕg«£m¥fw©¨°¨¡ªh¹Àb',
'«{e©wf{sr¢c«¯à|i¯hwkpwÀÙ',
'µÈffs¦¡edpxØa¯}m{az¨nu®kxÜ',
'¥³aeo{c}¢¦~kz©»Æha¦¢xuyz§|nß',
'¥Ü~~zxk¤§¦|oªeË¡ ¯¢id{Áç'
]

for string in allstring:
  print(rev(string))
```

Celui-ci nous donne le flag une fois exécuté !!!

![Alt text](./img/flag.png)
