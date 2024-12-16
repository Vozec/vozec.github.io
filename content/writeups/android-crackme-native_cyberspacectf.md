---
title: "Android CrackMe Native | CyberSpace CTF 2022 | Catégorie Reverse | [Vozec/FR] "
date: 2022-01-11T12:00:00Z
description: "Android CrackMe Native | CyberSpace CTF 2022"
categories: ["writeup"]
tags: ["reverse","android","writeup"]
keywords: ["android", "reverse","ctf","ctf","reverse","ctftime","java"]
---

## Fichier(s)
- [Android App](./files/CrackMe.apk)

## Nécessaires
- Ghidra
- Python3
- Jdax
- Apktool

## Flag
```
HL{J4v4.nativ3.d0.n0t.c4r3}
```
## Solution détaillée

La première chose est de décompiler l'apk pour en retrouver le code Java .
J'ai utilisé Apktool pour extraire le code smali et avoir tous les fichiers natifs :

```bash
apktool d CrackMe.apk
```

Puis j'ai passé l'apk dans Jadx, un outil très utilisé pour le reverse de code Java  :

![Alt text](./img/jdax.png)


J'ai installé l'apk sur mon appareil après avoir vérifié l'absence de virus et voici la page d'accueil :

![Alt text](./img/intro.png)

Cherchons dans le code la fonction de vérification de mot passe :
On retrouve à 2 endroits une fonction **getCode**

```Java
public int[] getCode(String str) {
    byte[] bytes = str.getBytes();
    int[] iArr = new int[str.length()];
    for (int i = 0; i < str.length(); i++) {
        iArr[i] = bytes[i] ^ x0[i];
    }
    return iArr;
}

```

Ainsi qu'un appel à la fonction :
```Java
int[] checkPw = checkPw(getCode(str));
if (checkPw.length > 0) {
    this.loginResult.setValue(new LoginResult(new LoggedInUser(getStringFromCode(checkPw), "Well done you did it.")));
    return;
}
```

Un autre chose remarquable est ceci :

```Java
public void loginDataChanged(String str) {
        if (!isPasswordValid(str)) {
            this.loginFormState.setValue(new LoginFormState((Integer) null, Integer.valueOf(R.string.invalid_password)));
        } else if (str.indexOf("HL") < 0) {
            this.loginFormState.setValue(new LoginFormState((Integer) null, Integer.valueOf(R.string.must_contain_HL)));
        } else if (checkHooking()) {
            this.loginFormState.setValue(new LoginFormState((Integer) null, Integer.valueOf(R.string.must_not_hook)));
        } else if (str.indexOf(123) < 0) {
            this.loginFormState.setValue(new LoginFormState((Integer) null, Integer.valueOf(R.string.is_of_format)));
        } else if (str.indexOf(125) < 0) {
            this.loginFormState.setValue(new LoginFormState((Integer) null, Integer.valueOf(R.string.is_of_format)));
        } else {
            this.loginFormState.setValue(new LoginFormState(true));
        }
    }
```

Cette fonction prend en entrée supposément le mot de passe et vérifie si il contient :
-   ``HL`` , ``{`` ,  ``}``

On retrouve aussi une fonction qui vérifie si le téléphone est rooté et une autre fonction qui vérifie qu'il n'y a pas de processus de hooking sur l'application . Nous ne nous en servirons pas dans ce challenge .

Regardons de plus prêt la fonction : ``Getode()``

Premièrement , elle prend en entrée une chaine de charactères ; on peut deviner que c'est notre mot de passe entrée .
Puis elle **XoR chaque Bytes de l'input** avec un élément d'une liste prédéfinit en variable globale :

```Java
protected static int[] x0 = {121, 134, 239, 213, 16, 28, 184, 101, 150, 60, 170, 49, 159, 189, 241, 146, 141, 22, 205, 223, 218, 210, 99, 219, 34, 84, 156, 237, 26, 94, 178, 230, 27, 180, 72, 32, 102, 192, 178, 234, 228, 38, 37, 142, 242, 142, 133, 159, 142, 33};
```

Pour être sur de bien comprendre ce que fait **getBytes();** , j'ai écris ce code en java .
Je voulais m'assurer que la fonction : **ord** en python donné le même résultat  
```Java
import java.util.Arrays;
class Decode {

    protected static int[] x0 = {121, 134, 239, 213, 16, 28, 184, 101, 150, 60, 170, 49, 159, 189, 241, 146, 141, 22, 205, 223, 218, 210, 99, 219, 34, 84, 156, 237, 26, 94, 178, 230, 27, 180, 72, 32, 102, 192, 178, 234, 228, 38, 37, 142, 242, 142, 133, 159, 142, 33};

    public static void main(String[] args) {
        String str = "HL{";

        byte[] bytes = str.getBytes();
        int[] iArr = new int[str.length()];
        for (int i = 0; i < str.length(); i++) {
            iArr[i] = bytes[i] ^ x0[i];
        }
        System.out.println(Arrays.toString(iArr));
    }    
}
```


Quelque chose qui m'a perturbé et cette appel : ``int[] checkPw = checkPw(getCode(str));``
On sait que GetCode renvoie une liste de charactères Xorés mais que fais **CheckPw** ???

Je n'ai d'abord pas trouvé de fonction de ce nom puis quelque chose m'a frappé :
```Java
static {
        System.loadLibrary("native-lib");
    }
```

Il y a une importation d'une librairie !
C'est là que apktool nous sert . Dans les fichiers de l'apk , il y avait une librairy en C du nom de : **libnative-lib.so**

Je l'ai donc ouvert avec Ghidra et voici ce que j'y ai trouvé !

![Alt Text](./img/allfunctions.png)

On voit la fonction checkHooking évoqué plus haut et surtout notre fonction **CheckPW** ! Nous sommes sauvés

```C

void Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw
               (int *param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  uint *puVar2;
  uint *puVar3;
  bool bVar4;
  int iVar5;
  FILE *__stream;
  char *pcVar6;
  uint *puVar7;
  int iVar8;
  uint uVar9;
  char acStack4140 [4096];
  int iStack44;

  iStack44 = __stack_chk_guard;
  __android_log_write(4,"Native Check","Checking password ...");
  (**(code **)(*param_1 + 0x2cc))(param_1,0);
  iVar5 = (**(code **)(*param_1 + 0x2ac))(param_1,param_3);
  if (iVar5 == 0x1b) {
    __stream = fopen("/proc/self/maps","r");
    do {
      pcVar6 = fgets(acStack4140,0x1000,__stream);
      if (pcVar6 == (char *)0x0) {
        bVar4 = false;
        goto LAB_00010a32;
      }
      pcVar6 = strstr(acStack4140,"Xposed");
    } while ((pcVar6 == (char *)0x0) &&
            (pcVar6 = strstr(acStack4140,"frida"), pcVar6 == (char *)0x0));
    bVar4 = true;
LAB_00010a32:
    if (__stream != (FILE *)0x0) {
      fclose(__stream);
    }
    if (!bVar4) {
      iVar8 = 0;
      iVar5 = (**(code **)(*param_1 + 0x2ec))(param_1,param_3,0);
      puVar7 = &DAT_00012a60;
      do {
        if (iVar8 == 0x1b) break;
        iVar1 = iVar8 * 4;
        puVar2 = &DAT_000128f8 + iVar8;
        uVar9 = *puVar7;
        puVar3 = &DAT_00012a94 + iVar8;
        iVar8 = iVar8 + 1;
        puVar7 = puVar7 + -1;
      } while ((*(uint *)(iVar5 + iVar1) ^ *puVar2 ^ uVar9) == *puVar3);
    }
  }
  if (__stack_chk_guard - iStack44 == 0) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(__stack_chk_guard - iStack44);
}
```

Voici à quoi ressemble la fonction. On y voit premièrement une partie inutile, la partie supérieur de la fonction est en fait un Hook par Frida , un Framework pour modifier des application Android .

On initialise une liste : ``puVar7 = &DAT_00012a60;``

La Boucle while final est intéressante :

![Alt Text](./img/function.png)

- On identifie directement un conteur :

```C
iVar8 = 0;
. . .
iVar8 = iVar8 + 1;
```

- Nous voyons qu'il y a un ```break;```
  On voit que celui-ci se déclenche quand **iVar8** est égale à **0x1b** soit ``27``
  Parfait, on a déjà la taille de notre mot de passe !

- Finalement, on observe 2 XoR successifs de puVar7 (défini plus haut) avec 2 autres listes : **DAT_000128f8** et **DAT_00012a94**

On peut en déduire que le mot de passe secret est puVar7 et que le XoR avec ces 2 listes et comparé à la liste généré avec le code Java .

On peut donc utiliser les propriétés du XoR pour retrouver le flag original .
Rappel :
```Tex
B ⊕ ( A ⊕ B ) = B ⊕ ( B ⊕ A ) (associative)
B ⊕ ( A ⊕ B ) = (B ⊕ B) ⊕ A   (self-inverse)
B ⊕ ( A ⊕ B ) = 0 ⊕ A         (identity element)
B ⊕ ( A ⊕ B ) = A
```

Voici le code python de ma solution :
On Xor les derniers 27 charactères de DAT_000128f8 avec DAT_00012a94 et DAT_00012a94 puis enfin avec la liste obtenue dans le java :

```python
all_ = [121, 134, 239, 213, 16, 28, 184, 101, 150, 60, 170, 49, 159, 189, 241, 146, 141, 22, 205, 223, 218, 210, 99, 219, 34, 84, 156, 237, 26, 94, 178, 230, 27, 180, 72, 32, 102, 192, 178, 234, 228, 38, 37, 142, 242, 142, 133, 159, 142, 33]

DAT_000128f8 = [0xd0,0x45,0x28,0x76,0x6f,0xf3,0x5a,0xf4,0xc7,0xce,0xfb,0xc3,0x7f,0x48,0xce,0x3c,0x3a,0x0b,0xf1,0x53,0xb1,0x4b,0xb9,0x5e,0xa2,0x65,0x77,0xa5,0x81,0x95,0xca,0x31,0x18,0x88,0xee,0xdd,0x38,0x5d,0xd5,0xa9,0x4a,0x7c,0x9d,0xc9,0xb8,0xe8,0xfb,0x9f,0x64,0x57,0xe0,0xd6,0x42,0x95,0x29,0x8f,0xd4,0x35,0x2d,0x0a,0x54,0xed,0xc4,0x48,0x4c,0x7b,0x73,0x6f,0x72,0x72,0x79,0x2e,0x74,0x68,0x69,0x73,0x2e,0x69,0x73,0x2e,0x4e,0x4f,0x54,0x2e,0x74,0x68,0x65,0x2e,0x66,0x6c,0x61]

DAT_00012a94 = [0x80,0xe3,0xda,0xc7,0x2e,0xf1,0xa2,0x91,0x6b,0xdc,0x6b,0xb5,0xe5,0xaf,0x3f,0xb9,0xee,0x5b,0x26,0x92,0x66,0xc5,0xcb,0xde,0x81,0x79,0xda]

DAT_00012a94_Reversed = DAT_000128f8[::-1][:27+1]


final = []
for i in range(27):
	final.append(chr(DAT_000128f8[i] ^ DAT_00012a94[i] ^ DAT_00012a94_Reversed[i] ^ all_[i]))

print(''.join(final))

```

Output:
```Bash
root@DESKTOP-HNQJECB: /c/AndroidReverse
➜   python3 solve.py
HL{J4v4.nativ3.d0.n0t.c4r3}
```
