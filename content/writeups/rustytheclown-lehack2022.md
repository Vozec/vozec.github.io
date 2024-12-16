---
title: "RustyTheClown | leHack 2022 | Catégorie reverse"
date: 2022-06-26T12:00:00Z
description: "RustyTheClown , Rust Reverse | leHack 2022"
categories: ["writeup"]
tags: ["reverse","tuto"]
keywords: ["tuto", "reverse","howto","ctf","TFC","ctftime","RustyTheClown"]
---

# RustyTheClown 2 | leHack CTF 2022

## Fichier(s)
- [RustyTheClown](./files/rustyTheClown)

## Nécessaires
- [IDA](https://hex-rays.com/ida-free/)/[Ghidra](https://ghidra-sre.org/)
- Python3

## Flag
```
lh_68eca3c515dbefd71ec8fec3849ba0083af806447d9f9f7cdca2a5cc
```
## Solution détaillée

### Analyse Statique

Le challenge est un crackme . On nous demande un mot de passe et celui est modifié puis comparé avant de nous donner ou non le flag .

Désassemblons le binaire dans IDA :

Dans ``void rustyTheClown::main::hecc4c87ee1b9aeab()`` voici ce qu'on trouve d'important :
```C
std::io::stdio::Stdin::read_line::hd0723957e63cf850();
 if ( &unk_52408 )
   core::ptr::drop_in_place$LT$std..io..error..Error$GT$::h815d6777c4f5f9e1(*((_QWORD *)&dest + 1));
 v4 = 0LL;
 v3 = 1uLL;
 _$LT$core..iter..adapters..map..Map$LT$I$C$F$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$::fold::h77524fc9083f58e3(
   1LL,
   1LL,
   &v3);
 if ( v4 == 17
   && !(*(_QWORD *)v3 ^ 0x6F686F6F686F6F48LL | *(_QWORD *)(v3 + 8) ^ 0x216168616861686FLL | *(unsigned __int8 *)(v3 + 16) ^ 0xALL) )
 {
   dest = v3;
   v10 = v4;
   src[20] = 0u;
   src[21] = 0u;
   src[18] = 0u;
   src[19] = 0u;
   src[16] = 0u;
   src[17] = 0u;
   src[14] = 0u;
   src[15] = 0u;
   src[12] = 0u;
   src[13] = 0u;
   src[10] = 0u;
   src[11] = 0u;
   src[8] = 0u;
   src[9] = 0u;
   src[6] = 0u;
   src[7] = 0u;
   src[4] = 0u;
   src[5] = 0u;
   src[2] = 0u;
   src[3] = 0u;
   src[0] = 0u;
   src[1] = 0u;
   sha3::Keccak224::absorb::h29f13918aa92cc08(src, v3);
   if ( *((_QWORD *)&dest + 1) )
     _rust_dealloc();
   v7[0] = 0LL;
   v7[1] = 0LL;
   v8 = 0;
   v7[2] = 0LL;
   memcpy(&dest, src, 0x160uLL);
   _$LT$sha3..Sha3_224$u20$as$u20$digest..fixed..FixedOutputDirty$GT$::finalize_into_dirty::h6affdc907d7bd5a0(
     &dest,
     v7);
   v10 = 0LL;
   v11 = 0LL;
   v6[0] = (__int64)v7;
   v6[1] = (__int64)generic_array::hex::_$LT$impl$u20$core..fmt..LowerHex$u20$for$u20$generic_array..GenericArray$LT$u8$C$T$GT$$GT$::fmt::h66b0e2e11014508f;
   *(_QWORD *)&dest = &unk_52428;
   *((_QWORD *)&dest + 1) = 2LL;
   v12 = v6;
   v13 = 1LL;
   std::io::stdio::_print::h99789c75449e1f7a();
 }
 else
 {
 }
```

On peut simplifier le code en pseudo-python :

```python
v3 = input('password : ')
v3 = weirdfunction(v3)
if(len(v3)==17 and xor(v3[:8],0x6F686F6F686F6F48) == 0*8 and xor(v3[8:16],0x216168616861686F) == 0*8):
  print('Flag is : %s'%sha3(v3))
```

La première chose à faire est d'expliciter les valeurs :
- ``0x6F686F6F686F6F48``
- ``0x216168616861686F``

Avec [IDA](https://hex-rays.com/ida-free/) ou *binascii.unhexlify*  , on obtient respéctivement :
- ``ohoohooH``
- ``!ahahaho``

Pour conclure l'analyse statique ; on sait que d'après les [``propriétés du Xor``](https://fr.wikipedia.org/wiki/Fonction_OU_exclusif): *A ^ A = 0*

On veut donc que :
- v3[:8] == ohoohooH
- v3[8:16] == !ahahaho


### Analyse Dynamique:

Juste après notre entrée dans ``stdin`` , notre buffer stocké dans ``v3`` et appelé dans une fonction

```c
 _$LT$core..iter..adapters..map..Map$LT$I$C$F$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$::fold::h77524fc9083f58e3(
   1LL,
   1LL,
   &v3);
```

Quand on décompile cette fonction. On voit tout de suite qu'elle sort  des enfers ..

```c
v6 = (unsigned __int8)*v5;
     if ( (*v5 & 0x80000000) != 0 )
     {
       v9 = v5[1] & 0x3F;
       if ( v6 <= 0xDF )
       {
         v5 += 2;
         v7 = v9 & 0xFFFFF83F | ((v6 & 0x1F) << 6);
         v8 = v7 & 0xFFFFFFDF;
         if ( (v7 & 0xFFFFFFDF) - 65 > 0xC )
           goto LABEL_15;
       }
       else
       {
         v10 = v5[2] & 0x3F | ((v5[1] & 0x3F) << 6);
         if ( v6 < 0xF0 )
         {
           v5 += 3;
           v7 = v10 & 0xFFFE0FFF | ((v6 & 0x1F) << 12);
           v8 = v7 & 0xFFFFFFDF;
           if ( (v7 & 0xFFFFFFDF) - 65 > 0xC )
             goto LABEL_15;
         }
         else
         {
           v7 = (v5[3] & 0x3F | ((v10 & 0xFFF) << 6)) & 0xFFE3FFFF | ((v6 & 7) << 18);
           if ( v7 == 1114112 )
             return result;
           v5 += 4;
           v8 = v7 & 0xFFFFFFDF;
           if ( (v7 & 0xFFFFFFDF) - 65 > 0xC )
           {
LABEL_15:
             if ( v8 - 78 <= 0xC )
               v7 = (unsigned __int8)(v7 - 13);
             goto LABEL_17;
           }
         }
       }
     }
     else
     {
       v7 = (unsigned __int8)*v5++;
       v8 = v6 & 0xFFFFFFDF;
       if ( (v6 & 0xFFFFFFDF) - 65 > 0xC )
         goto LABEL_15;
     }

     ....

```

On va donc devoir utiliser un debugger pour comprendre le fonctionnement de cette fonction et ainsi passer le bon mot de passe qui vérifie les 3 conditions précédentes.

##### Mise en place d'un environnement de debug .

```bash
root@DESKTOP-HNQJECB: /c
➜   file rustyTheClown
rustyTheClown: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, BuildID[sha1]=59299c846572d2809876d380f7710f0d1735429e, with debug_info, not stripped
```

Le binaire est un binaire codé en ``Rust`` et compilé en ``ARM aarch64`` . Il n'est donc pas exécutable facilement :

```bash
root@DESKTOP-HNQJECB: /c
➜   ./rustyTheClown
zsh: exec format error: ./rustyTheClown
```

Pour résoudre ce soucis , on peut soit :
- Utiliser une machine avec un processeur adapté (Raspberry)
- Utiliser une machine Qemu.

Nous allons ici utiliser la 2nd option même si elle reste la plus compliquée.

###### Installation :

```bash
sudo apt install qemu-user qemu-user-static gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu binutils-aarch64-linux-gnu-dbg build-essential
```

###### Lancement :

```bash
qemu-aarch64 -L /usr/aarch64-linux-gnu ./rustyTheClown
```


Résultat:
```bash

                                              `.:`
                                            .:ooy.
                          ./+///..      `..-/+osso
                          .-/ssooo:.   `-`````..-:-          `
                             -ssssso:.`:``````````.:    `://+++:.
                              /ssssssso.......---`./ ``:+osssss+/`
                              .sssssss:-` .-` `.-.oo/ooossssy/.
                               ossssso:-/:+:` :`-osssssssssy-
                               `ssss/---/+o+/:::`++ssssssss/
                                .osy+:-.......::-/yssssssy`
                                  `syy/ys/+::+///+yssssy:`
                                    `o-NMMMNNs:/hysys/:.
                                     +:yshhd+/.:``
                                   `/+soo+++s//+`
               .--`           `....+/oossssoy/:+:
               --`-..`...----:/:::/+:///::/+++o++/++:.
           ....-` -.+--------+:::/+::::::::::+/::o/::/:---..`   `-.-
          --.-  `./`+--------+:::+::::::::::/o::++:---------::::.`.:
           -:.`   ../::::::::/+///::::::::::/o+/o/::-------:-:.`  ::``
           :.--- ``:-:.```   .//:::::::::::::/+ooso+/::::--::` ..  `..-.`
           `` :`.-``        ::::::::::::::::::://+o:  `..-/::      .-.`-:
              ..`          :::::::::::::::::::::///+:      `--.  .``--..`
                          ./:::::::::::::::::::::///+-        :. /--`-.
                          /-:::::::::::::::::::::////+        `:`:``..
                          :o+///////////+///+//://///o         `.`
                           `/--------------:::://+++o+
                           -/::-----------------::/+-`
Hey hey, kids!
What's your answer? :
Vozec
Hoohoohoohahaha!
```

On va utiliser ``gdb-mutliarch``:

- Dans un premier shell :
```bash
gdb-multiarch rustyTheClown
set architecture aarch64
```

- Dans un deuxième shell :
```bash
qemu-aarch64 -g 1337 -L /usr/aarch64-linux-gnu ./rustyTheClown
```

- Dans le premier shell :
```bash
target remote :1337
```

Maintenant que notre GDB est lié à notre binaire , nous pouvons placer un breakpoint à la sortie de la fonction mystère .
On va essayer de trouver cette instruction :

```bash
ldr     x8, [sp, #40]
```

![Alt text](./img/call.png)

Elle se situe juste après le call de la fonction ``_ZN13rustyTheClown4main17hecc4c87ee1b9aeabE``

- Dans le deuxième shell :
```bash
disas _ZN13rustyTheClown4main17hecc4c87ee1b9aeabE
# Ici on va chercher l'instruction
b* 0x0000005500006ea8
continue
```

![Alt text](./img/bp.png)

On peut ainsi entrer un mot de passe de 16 charactères aléatoire, ici ``HelloFromVozec!!``
Une fois ceci fait, notre premier shell avec GDB à atteint le breakpoint: **Affichons les registres** !

```bash
X(gdb) x/s $x0
0x5500058b10:   "UryybSebzIbmrp!!\n"
```

![Alt text](./img/resume.png)

Et oui, tout de suite cela devient évident ... C'est un **Rot13** Banal ! Toutes les lettres sont décalés de 13 dans l'alphabet .

On peut donc former le mot de passe :

``Ubbubbubbununun!`` qui sortant de la fonction aura pour valeur : ``Hoohoohoohahaha!`` et validera le challenge :

![Alt text](./img/flag.png)
