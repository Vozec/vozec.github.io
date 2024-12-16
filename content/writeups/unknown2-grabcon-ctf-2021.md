---
title: "Writeup Unknown 2 | GrabCon 2021 | Catégorie reverse"
date: 2021-10-17T12:00:00Z
description: "Unknown 2 | GrabCon CTF 2021"
categories: ["writeup"]
tags: ["reverse","tuto"]
keywords: ["tuto", "reverse","howto","ctf","GrabCon","ctftime","Unknown 2"]
---

# Unknown 2 | GrabCon CTF 2021

## Fichier(s)
- [Unknow_2](./files/med_re_2)

## Nécessaires
Ghidra + Kali

## Flag
```
GrabCON{626C61636B647261676F6E}
```
## Solution détaillée


La première chose que j’ai fait et de faire un `ltrace` mais cela n’a rien donné

J’ai donc fait : `strings med_re_2` et en cherchant un petit peu j’ai trouvé ceci :

![Alt text](./img/strings.png "strings")

Si vous ne connaissez pas,**UPX** est un packer qui ici compresse le binaire . Nativement, le fichier ne peut pas être analysé avec ghidra .

![Alt text](./img/ghidra1.png "ghidra1")

Après quelques recherches, on trouve **[cette commande](https://linux.die.net/man/1/upx)** pour unpack le .exe :

![Alt text](./img/ghidra2.png "ghidra2")

- [Unknow_2_unpacked](./files/med_re_2_unpack)

Retournons sur Ghidra :

![Alt text](./img/ghidra3.png "ghidra3")

Maintenant cherchons dans le `main`
On trouve 2 fonctions intéressantes : main.main et main.one
Regardons d’abord main.main :

![Alt text](./img/ghidra4.png "ghidra4")

Nous voyons de l’ascii art, c’est donc la fonction qui doit être chargée au lancement du binaire.
Exécutons-le :

![Alt text](./img/ghidra5.png "ghidra5")

Si on regarde le code du `main.main` , en bas nous retrouvons :
```C
Prinln()
```

![Alt text](./img/ghidra6.png "ghidra6")

Je suppose donc que le if n’est pas vérifié et que donc `main.one()` n’est pas appelée.
Nous devons donc accéder à cette fonction. Je ne sais pas si c’est la méthode la plus propre pour faire ceci mais j’ai modifié le binaire :
J’ai transformé *== en !=* comme ceci . En assembleur, on sait que *==* géré par l’instruction *JZ ou JNZ*, En cliquant sur la condition on peut patch en remplaçant *JNZ par JZ* (== par !=)

![Alt text](./img/ghidra7.png "ghidra7")

![Alt text](./img/ghidra8.png "ghidra8")

![Alt text](./img/ghidra9.png "ghidra9")

Trouver *JZ* en bas du menu et pressez **Enter**
Il faut maintenant exporter votre nouveau binaire :
`“File” -> “Export program” -> Format : ELF et Output : med_re_2_patch1 -> “Enter”`
Maintenant exécutons notre nouveau binaire :

- [Unknow_2__patch1](./files/med_re_2_patched.txt)

![Alt text](./img/bin.png "bin")

Ça devient intéressant ! On nous demande un mot de passe.
Cherchons donc du côté du main.one
La fonction semble complexe mais nous cherchons uniquement les “PrintLn” et les conditions.
Voici ce qui m’a interpellé :

![Alt text](./img/bin2.png "bin2")

Nous avons une condition et un *PrintLn()* , D’après le résultat du binaire patché , je suppose que c’est là que le flag est caché :

![Alt text](./img/bin3.png "bin3")

Nous voulons que la condition soit vérifiée : `if (local_40 == 0x195)` (ligne 192)
De la même manière que la patch précédent, changeons la condition (JNZ → JZ) puis exportons le nouveau patch

- [Unknow_2__patch2](./files/med_re_2_patched2)

![Alt text](./img/ghidra10.png  "ghidra10")

Exécutons celui-ci :

![Alt text](./img/flag.png  "flag")

Voila ! Afficher une string sous une certaine condition est assez simple à modifier !
