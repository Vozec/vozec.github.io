---
title: "Writeup Herald | Insomnihack 2022 | Catégorie reverse | [Vozec/FR] "
date: 2022-01-30T12:00:00Z
description: "Herald | Insomnihack CTF 2022"
categories: ["writeup"]
tags: ["reverse","tuto"]
keywords: ["tuto", "reverse","howto","ctf","GrabCon","ctftime","Unknown 2"]
---

## Fichier(s)
- [Herald.apk](./files/Original.apk)

## Nécessaires
- Un téléphone Android
- [Apk-signer](https://play.google.com/store/apps/details?id=com.haibison.apksigner)
- [Apktool](https://ibotpeaches.github.io/Apktool/)
- [Jdax](https://github.com/skylot/jadx)

## Flag
```
INS{Y0u_Kn0W_aB0uT_Th3_Her4ld_0F_the_G0ds?}
```

## Description
```
Our lab administrator has just passed out from a strange virus. Please help us find the password to his messaging app so we can identify what he was working on and save his life.
```

## Solution détaillée

La première chose que j'ai faite et de mettre mon fichier apk dans *Jdax* pour voir le code source est commencé à reverse :

![Alt text](./img/jdax.png "jdax")

Je n’en vais pas détailler plus sur cette partie car je n'ai rien trouvé d'intéressant dans le code en lui-même.

J'ai ensuite installé l'application sur mon téléphone et j'ai constaté qu'il y avait un login .
Le challenge consiste donc à retrouver le mot de passe du nom d'utilisateur pour accéder au flag !

J'ai donc dans jdax fais une recherche avec les mots clés : **'password'** **'email'** **'username'** ...

Toujours rien !
Je n'ai absolument rien trouvé donc j'en ai déduis que le code devais être ailleur.

#### Apktool :

Grâce à Apktool , j'ai décompilé le .apk pour en extraire les ressources .

```bash
apktool d original.apk
```

Enfin , à coup de **strings** et **grep** , j'ai finis par trouver ce fichier du nom de : '*index.android.bundle*'

```bash
root@DESKTOP-HNQJECB: /c/Herald
➜   strings index.android.bundle | grep 'login'
```

![Alt text](./img/strings.png "strings")

Je cherche donc et je trouve que les fichiers bundle sont des fichiers packé d'application crées avec ReactJs .

J'ai passé beaucoup de temps à essayer de reverse ce fichier bundle comme un bundle react classique.
Beaucoup de solution proposée de lié le fichier a une page html (script js) puis de le debugger à partir de la console développer du mon navigateur.
Malheuresement , cela n'a pas marché ....

Même si j'y ai pensé tard, j'ai fait un *file* sur le fichier et voici l'output :

```bash
root@DESKTOP-HNQJECB: /c/Herald
➜   file index.android.bundle
index.android.bundle: Hermes JavaScript bytecode, version 84
```

C'est un fichier Hermes JS (en version 84)

Une recherche rapide nous permet de trouver : [HbcTool](https://github.com/bongtrop/hbctool)

Problème, il ne supporte pas la version de notre fichier ByteCode !

![Alt text](./img/support.png "support")

J'ai donc cherché partout, encore et encore pendant plusieurs heures pour enfin trouver ce commit sur GitHub d'une version d'essai qui permet la décompilation des bytes codes en version 84 .

https://github.com/bongtrop/hbctool/issues/12

Qui redirigé vers [cette release](https://github.com/niosega/hbctool/tree/draft/hbc-v84) qui m'a permis de décompilé le fichier bundle !

```bash
root@DESKTOP-HNQJECB: /c/Herald
➜   hbctool disasm index.android.bundle original
[*] Disassemble 'index.android.bundle' to 'original' path
[*] Hermes Bytecode [ Source Hash: fcea8fb1a251839a7811a5cdcfc8f975e0b3d67b, HBC Version: 84 ]
[*] Done
```

#### Le Fun et les Bytes codes :

On a donc 3 nouveaux fichiers :

- instruction.hasm
- metadata.json
- string.json

Dans `string.json` ; on a bien nos strings de l'application ce qui confirme que nous sommes sur la bonne voie :

![Alt text](./img/file_string.png "file_string")

###### Username :

Voici à quoi ressemble les bytes codes dans la fonction login que j'ai retrouvé :

![Alt text](./img/bytecode.png "bytecode")

On voit tout de suite que le nom d’utilisateur est **admin**
Il nous reste le mot de passe !

###### Password :

```C
GetById             	Reg8:3, Reg8:0, UInt8:3, UInt16:4120; Oper[3]: String(4120) 'password'
GetById             	Reg8:4, Reg8:2, UInt8:4, UInt16:3485; Oper[3]: String(3485) 'decodedText'

NewArrayWithBuffer  	Reg8:0, UInt16:28, UInt16:28, UInt16:9398
Call2               	Reg8:0, Reg8:4, Reg8:2, Reg8:0
JStrictEqual        	Addr8:105, Reg8:3, Reg8:0
GetByIdShort        	Reg8:0, Reg8:2, UInt8:1, UInt8:121; Oper[3]: String(121) 'state'
```

Voici le code qui appelle la fonction **decodedText** et voici son contenue :

![Alt text](./img/decode.png "decode")

Les mots : **'ascii_array' , 'fromCharCode' , 'length'** nous indique que le code équivalent en python serait :

```python
def decodedText(array):
  final = ''
  for ch in array:
    final += chr(ch)
  return final
```

Malheureusement , je n'ai pas trouvé d'array qui me permette de trouver le flag . Même avec des grep de ``73, 78, 83, 123`` qui sont les chars de **INS{** , le début du flag connu .

J'ai donc changé de tactique !
Au lieu de trouver le bon mot de passe. Modifions le code pour que le mot de passe que nous entrons soit valide :

Si on reprend le code la fonction on comprend la logique du programme :

```bash
username = input('User')
password = input('Password')

if(username == 'admin'):
  if(password == decodedText(not_founded_array)):
    print('Flag')
  else:
    print('You are not the admin, Liar!')
else:
  print('Wrong Username/Password combination')

```
Nous avons déjà le nom d'utilisateur donc nous devons changer le ``password == decodedText`` en ``password != decodedText``

Pour cela il faut comprendre ou la variable est appelé.

En comparant les autres fonctions donc les actions étaient connues, j'ai compris comment les variables étaient définis. J'ai donc identifié le mot de passe valide comme : **Reg8:0** au niveau de la ligne 210357

```bash
NewArrayWithBuffer  	Reg8:0, UInt16:28, UInt16:28, UInt16:9398
Call2               	Reg8:0, Reg8:4, Reg8:2, Reg8:0
JStrictEqual        	Addr8:105, Reg8:3, Reg8:0
GetByIdShort        	Reg8:0, Reg8:2, UInt8:1, UInt8:121
```

JStrictEqual stock la différence de **Reg8:3** et **Reg8:0** dans un booléen **Addr8:105**.
De plus ; On sait que **Reg8:0** est notre entrée car nous avons au-dessus :

```bash
GetById             	Reg8:3, Reg8:0, UInt8:3, UInt16:4120
; Oper[3]: String(4120) 'password'
```

J'ai donc essayé de faire afficher **Reg8:0** via la code des popup définis plus tard
Mais cela ne fonctionnais pas et quand je changé la variable de la string original par **Reg8:0** , soit dans les premiers tests , l'application crashé instantanément , soit elle affiché une popup vide ...

Code de la popup :
```bash
GetById             	Reg8:0, Reg8:3, UInt8:6, UInt16:5067	; Oper[3]: String(5067) 'alert'

LoadConstString     	Reg8:1, UInt16:1772	; Oper[1]: String(1772) 'Wrong Username/Password combination'

Call2               	Reg8:0, Reg8:0, Reg8:3, Reg8:1
GetById             	Reg8:0, Reg8:2, UInt8:7, UInt16:3904	; Oper[3]: String(3904) 'setPrint'

Call2               	Reg8:0, Reg8:0, Reg8:2, Reg8:1
Jmp                 	Addr8:66
GetEnvironment      	Reg8:0, UInt8:1
LoadFromEnvironment 	Reg8:0, Reg8:0, UInt8:6
GetById             	Reg8:3, Reg8:0, UInt8:5, UInt16:4460	; Oper[3]: String(4460) 'Alert'
```

Finalement, j'ai modifié la fonction **JStrictEqual** en **JStrictNotEqual**

#### Recompilation

Maintenant, nous devons réinstallé notre app modifié sur le téléphone pour tester et espérer avoir le flag .

###### Première étape : Recompilation du bundle

Grâce au même outils que pour décompiler le bundle, j’ai recréé un fichier à partir des BytesCodes :

```bash
root@DESKTOP-HNQJECB: /c/Herald
➜   hbctool asm original index.android.bundle
[*] Assemble 'original' to 'index.android.bundle' path
[*] Hermes Bytecode [ Source Hash: fcea8fb1a251839a7811a5cdcfc8f975e0b3d67b, HBC Version: 84 ]
[*] Done
```
Voici le bundle valide : [index.android.bundle](./files/index.android.bundle)

###### Seconde étape : Modification avec Apktool

Je replace mon bundle au bon endroit dans les fichiers décompilés avec apktool , dans '/assets'
Enfin je rebuild mon apk avec la commande suivante :

```bash
PS D:\APKTOOL> ./apktool b .\original\ -o tampered.apk
I: Using Apktool 2.4.0
I: Checking whether sources has changed...
I: Smaling smali folder into classes.dex...
I: Checking whether resources has changed...
I: Building resources...
I: Copying libs... (/lib)
I: Copying libs... (/kotlin)
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk...
Appuyez sur une touche pour continuer...
```

Je dois donc signer mon apk pout pouvoir l'installer sur mon téléphone.
J'ai déjà expliqué dans [cet](https://vozec.fr/articles/contourner-le-ssl-pinning-sur-android/) article comment faire.

```bash
zipalign -c 4 tampered.apk
```

Ici pour ne pas m’embêter, j'ai utilisé l'application *apk-signer* qui à directement signé le fichier sur mon téléphone .

#### Verdict

Ça a marché !
Un mot de passe incorrect à était validé et nous avons le flag :

![Alt text](./img/final.jpg "final")
