---
title: "Writeup All Reverse Challenges CTF 2022 | PwnMe 2022 Edition"
date: 2022-07-04T12:00:00Z
description: "Writeup complet de tous les challenges de Reverse du CTF PwnMe 2022"
categories: ["writeup"]
tags: ["network","tuto"]
keywords: ["network", "pivoting","ssh","ctf","pwnme","ctftime","unbreakable"]
type: "posts"
---

![date](https://img.shields.io/badge/date-29.06.2022-brightgreen.svg)  
![solved in time of CTF](https://img.shields.io/badge/solved-in%20time%20of%20CTF-brightgreen.svg)  

# Description
Le CTF propose **5 Challenges** de reverse :
- 2 de  __Bryton#2690__
- 1 de  __express#7904__
- 1 de __kostadin#0792__


# Prérequis
- IDA
- Connaissances basiques de CTF


## It's easy

- **Nom**  : It's easy
- **Point** : 50
- **Description** : Can you find the secret in this binary ?
- **File** : [ez](./file/ez)

###### Solution :
On peut regarder les **strings** présentes dans le binaire :


```bash
[writeup/file]$ rabin2 -z ez
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002008 0x00002008 37  38   .rodata ascii Type in the password to get the flag
1   0x00002038 0x00002038 36  37   .rodata ascii You got it right but no flag for u !
2   0x00002060 0x00002060 32  33   .rodata ascii UFdOTUV7MXRzX2p1c3RfYV9zdHIxbmd9
```

On reconnait une chaine en Base64  , on la décode :

```
echo UFdOTUV7MXRzX2p1c3RfYV9zdHIxbmd9 | base64 -d
```

et on obtient le flag : ``PWNME{1ts_just_a_str1ng}``

---

## Depycted

- **Nom**  : Depycted
- **Point** : 150
- **Description** : Find the input of this program with this output.
- **File** :
  - [chall.pyc](./file/chall.pyc)
  - [output.txt](./file/output.txt)

###### Solution :


Contenue de **output.txt** :
```
2195160159893668717327286059367551976012130689570892075754234400430874403925069147738764347075321
```

On décompile le .pyc :
```bash
uncompyle6 chall.pyc > cleaned.py
```

On a maintenant le code complet du challenge :

**cleaned.py**
```python
# uncompyle6 version 3.8.0
# Python bytecode 3.8.0 (3413)
# Decompiled from: Python 3.10.4 (main, Mar 24 2022, 13:07:27) [GCC 11.2.0]
# Embedded file name: C:\Users\Express\Documents\Toronto\challrev.py
# Compiled at: 2021-07-06 17:52:29
# Size of source mod 2**32: 555 bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long
from pwn import xor

def a(cipher):
    first = bytes_to_long(cipher[:16].encode()) ^ 13
    second = bytes_to_long(cipher[16:].encode()) ^ 37
    return (first, second)


def b(value1):
    first = str(value1)
    reverse_first = first[::-1]
    return reverse_first


def encrypt(flag):
    global a
    global b
    first, second = a(flag)
    print(b(first) + b(second))


flag = input("[+] Entre ton flag, que je l'encrypt avec mon chiffrement infaillible : ")
encrypt(flag)
```

Une rapide analyse nous indique que la fonction ``b()`` renvoie la chaine rentrée en paramètre à l'envers .

La fonction ``a()`` xor les *16* premiers bytes avec **13** et le reste avec **37**

On peut donc déchiffrer le message en bruteforcant le décalage et les différentes combinaisons de ``first`` et ``second``

solve.py:
```python
from Crypto.Util.number import long_to_bytes

def decoder(data):
    for i in range(1,len(data)):
        first , second = int(data[:i][::-1])^13,int(data[i:][::-1])^17
        part1 , part2 = long_to_bytes(first),long_to_bytes(second)
        if(b'PWNME' in part1):
            print(part1.decode()+part2.decode())        

decoder("2195160159893668717327286059367551976012130689570892075754234400430874403925069147738764347075321")
```

Flag : ``PWNME{84ec5fec3e2ec91291bb74648d35dcbc4I}``

---

## Crackme

- **Nom**  : Crackme
- **Point** : 345
- **Description** : Find the password
- **File** : [main.exe](./file/main.exe)

###### Solution :

On peut regarder le code avec IDA :

![AltText](./img/shema.png)

On retrouve un schéma de crackme simple  :

```python
password = input('Entrez le flag')
if(len(password) != 20):
  return False
else:
  if(isFlag(password,v6)):
    return True
  else:
    return False

```

Récupérons le buffer ``v6``  
On voit qu'il est initialisé à la ligne 9:
``v6 = initFlag()``

```C
__int64 initFlag()
{
  __int64 v1; // [rsp+28h] [rbp-8h]

  v1 = node_init(76i64);
  node_insert(v1, 17i64);
  node_insert(v1, 78i64);
  node_insert(v1, 75i64);
  node_insert(v1, 19i64);
  node_insert(v1, 68i64);
  node_insert(v1, 63i64);
  node_insert(v1, 76i64);
  node_insert(v1, 17i64);
  node_insert(v1, 83i64);
  node_insert(v1, 84i64);
  node_insert(v1, 63i64);
  node_insert(v1, 17i64);
  node_insert(v1, 78i64);
  node_insert(v1, 63i64);
  node_insert(v1, 77i64);
  node_insert(v1, 19i64);
  node_insert(v1, 77i64);
  node_insert(v1, 16i64);
  node_insert(v1, 82i64);
  node_insert(v1, 89i64);
  return v1;
}
```

On peut donc avoir V6 rapidement. ``node_insert`` est une fonction qui a était faite pas Bryton pour le challenge :

```c
__int64 __fastcall node_insert(__int64 a1, char a2)
{
  __int64 result; // rax

  while ( *(_QWORD *)(a1 + 8) )
    a1 = *(_QWORD *)(a1 + 8);
  *(_QWORD *)(a1 + 8) = malloc(0x18ui64);
  *(_QWORD *)(*(_QWORD *)(a1 + 8) + 16i64) = a1;
  **(_BYTE **)(a1 + 8) = a2 - 32;
  result = *(_QWORD *)(a1 + 8);
  *(_QWORD *)(result + 8) = 0i64;
  return result;
}
```

On voit quelque chose d'intéressant :
```C
**(_BYTE **)(a1 + 8) = a2 - 32;
```

On retire ``32`` à tous les chars qu'on ajoute .

On a donc v6 :

```python
v6 = [x-32 for x in [76,17,78,75,19,68,63,76,17,83,84,63,17,78,63,77,19,77,16,82,89]]
```
On a :
```Python
 v6 = [44, -15, 46, 43, -13, 36, 31, 44, -15, 51, 52, 31, -15, 46, 31, 45, -13, 45, -16, 50, 57]
 ```

On peut maintenant regarder la fonction ``isFlag``

```c
__int64 __fastcall isFlag(char *a1, char *a2)
{
  char *v2; // rax

  while ( *a1 && a2 )
  {
    v2 = a1++;
    if ( *a2 != *v2 - 64 )
      return 0i64;
    a2 = (char *)*((_QWORD *)a2 + 1);
  }
  return 1i64;
}
```

On voit rapidement que chaque lettre est comparée une par une avec le nombre de la liste correspondante avec un décalage de 64.

On écrit le programme de résolution suivant :  
*solver.py*
```Python
v6 = [x-32 for x in [76,17,78,75,19,68,63,76,17,83,84,63,17,78,63,77,19,77,16,82,89]]
final = []
for element in v6:
    try:
        final.append(bytes(chr(element+64),'utf-8'))
    except:
        pass

print('PWNME{'+b''.join(final).decode()+'}')
```

Flag : ``PWNME{l1nk3d_l1st_1n_m3m0ry}``

---

## Reverser don't like Rustacer

- **Nom**  : Reverser don't like Rustacer
- **Point** : 487
- **Description** : Simpler than it seems
- **File** : [Reverser.exe](./file/Reverser.exe)

###### Solution :

La première difficulté est que ce programme est codé en ``rust`` et que nous n'avons pas les symbols . Ainsi , IDA a du mal a reconnaitre des fonctions basiques comme ``strlen`` par exemple .

Voici le main :

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  return sub_140002300(sub_140003AE0, argc, argv);
}
```

On peut placer un breakpoint sur les fonctions appelées et de même sur les appels des 2 fonctions précédentes :

```c
// positive sp value has been detected, the output may be wrong!
void sub_140003AE0()
{
  __int64 v0; // [rsp-110h] [rbp-190h] BYREF
  __int64 *v1; // [rsp+78h] [rbp-8h]
  char *v2; // [rsp+80h] [rbp+0h]
  char v3[14]; // [rsp+90h] [rbp+10h] BYREF
  __int64 v4; // [rsp+1A8h] [rbp+128h]

  v4 = -2i64;
  v1 = &v0;
  sub_14000BC60();
  v2 = v3;
  ((void (__fastcall *)(char *, __int64 *))sub_1400019B0)(v3, v1);
  JUMPOUT(0x140003B1Di64);
}
```

On peut lancer un debugger avec IDA et regarder ou le code nous mène :

![AltText](./img/shema2.png)

Super ! On a trouvé le main :)
On le renomme tout de suite pour ne pas le perdre ..

Quand on regarde de plus prêt , on retrouve un schéma de crackme :

![AltText](./img/shema3.png)

Il semblerai que le mot de passe fasse ``12`` caractères .
Puis le mot de passe est vérifié et enfin , on a une fonction commune qui renvoie si le mot de passe est valid ou non .

![AltText](./img/shema4.png)

On remarque quelque chose trés intéréssant dans le fonctionnement du binaire :

![AltText](./img/shema5.png)

D'abord , il appelle la fonction checkflag qui lui renvoie ``0`` ou ``1`` et il stocke le résultat dans ``al`` , puis si ``al==1`` , il va dans la branche de droite qui correspond à un flag valide . Sinon il Jump dans la partie ``Incorrect Flag !!``

On peut le vérifier en cliquant sur : ``lea     rdx, off_7FF63B7B68A8``

![AltText](./img/shema6.png)

Dans la partie ou on gagne , un appel est trés intéressant :

![AltText](./img/shema7.png)

On suppose que c'est une fonction ``printFlag()``
Pour résoudre le challenge, on peut donc patcher le binaire pour call cette fonction !

On va modifier le call de la fonction de check par cette fonction :
![AltText](./img/patched.png)

On peut maintenant tester notre patch avec 12 lettres aléatoires comme mot de passe et nous avons le flag !


```bash
C:\Users\me\Desktop>Reverser.exe aaaaaaaaaaaa
Congratulation valid this flag: rust_1s_c00l
```

Flag : ``PWNME{rust_1s_c00l}``

---

## Attack Equation Solving

- **Nom**  : Reverser don't like Rustacer
- **Point** : 487
- **Description** :
  ```
  I love virGIN tonic
  Vous avez accès au code compilé du site web
  Le flag est sous le format suivant: PWNME{flag}
  ps: afin de valider le code sur le formulaire web il ne faut pas mettre PWNME{}.
  ```
- **Lien** : https://attack-equation-solving.pwnme.fr/
- **File** : [attack_solving.rar](./file/attack_solving.rar)

###### Solution :

Dans le **.rar** on a :
- Le code source du site
- Le binaire qui vérifie les mots de passes

On peut rapidement regarder le site ; on a 2 endpoints:
- **/** qui retourne la page de base
- **/verify** , en POST qui check si le mot de passe est valide .

Le binaire est codé en **GO** et on retrouve ces endpoints dans le programme .

![AltText](./img/functions.png)


Le main est juste le setup du serveur WEB .  
La fonction intéressante est donc : ``main_IsValidCode``

```bash
.text:000000000087AE60                 public main_IsValidCode
.text:000000000087AE60 main_IsValidCode proc near              ; CODE XREF: main_VerifyCode:loc_87B275↓p
.text:000000000087AE60                 lea     r12, [rsp-20h]
.text:000000000087AE65                 cmp     r12, [r14+10h]
.text:000000000087AE69                 jbe     loc_87AFD9
.text:000000000087AE6F                 sub     rsp, 0A0h
.text:000000000087AE76                 mov     [rsp+98h], rbp
.text:000000000087AE7E                 lea     rbp, [rsp+98h]
.text:000000000087AE86                 mov     [rsp+0A8h], rax
.text:000000000087AE8E                 mov     [rsp+0B0h], rbx
.text:000000000087AE96                 call    main_GetAESKey
.text:000000000087AE9B                 mov     [rsp+80h], rax
.text:000000000087AEA3                 mov     [rsp+50h], rbx
.text:000000000087AEA8                 nop
.text:000000000087AEA9                 mov     ecx, 40h ; '@'
.text:000000000087AEAE                 xor     eax, eax
.text:000000000087AEB0                 lea     rbx, aGoPointerStore+0B5E8h ; "59E2267F61917A7832D3608F6DDB2C6146E68AB"...
.text:000000000087AEB7                 call    runtime_stringtoslicebyte
.text:000000000087AEBC                 mov     [rsp+78h], rax
.text:000000000087AEC1                 mov     [rsp+40h], rcx
.text:000000000087AEC6                 mov     rdi, rax
.text:000000000087AEC9                 mov     rsi, rbx
.text:000000000087AECC                 mov     r8, rcx
.text:000000000087AECF                 call    encoding_hex_Decode
.text:000000000087AED4                 mov     rdx, [rsp+40h]
.text:000000000087AED9                 nop     dword ptr [rax+00000000h]
.text:000000000087AEE0                 cmp     rax, rdx
.text:000000000087AEE3                 ja      loc_87AFD0
.text:000000000087AEE9                 mov     [rsp+48h], rax
.text:000000000087AEEE                 lea     rax, [rsp+58h]
.text:000000000087AEF3                 mov     rbx, [rsp+80h]
.text:000000000087AEFB                 mov     rcx, [rsp+50h]
.text:000000000087AF00                 call    runtime_stringtoslicebyte
.text:000000000087AF05                 mov     rdi, rax
.text:000000000087AF08                 mov     rsi, rbx
.text:000000000087AF0B                 mov     r8, rcx
.text:000000000087AF0E                 lea     r9, unk_94E92B
.text:000000000087AF15                 mov     r10d, 5
.text:000000000087AF1B                 mov     rax, [rsp+78h]
.text:000000000087AF20                 mov     rbx, [rsp+48h]
.text:000000000087AF25                 mov     rcx, [rsp+40h]
.text:000000000087AF2A                 call    github_com_forgoer_openssl_AesECBDecrypt
.text:000000000087AF2F                 test    rdi, rdi
.text:000000000087AF32                 jz      short loc_87AF88
.text:000000000087AF34                 movups  xmmword ptr [rsp+88h], xmm15
.text:000000000087AF3D                 jz      short loc_87AF43
.text:000000000087AF3F                 mov     rdi, [rdi+8]
.text:000000000087AF43
.text:000000000087AF43 loc_87AF43:                             ; CODE XREF: main_IsValidCode+DD↑j
.text:000000000087AF43                 mov     [rsp+88h], rdi
.text:000000000087AF4B                 mov     [rsp+90h], rsi
.text:000000000087AF53                 mov     rbx, cs:os_Stdout
.text:000000000087AF5A                 lea     rax, go_itab__os_File_io_Writer
.text:000000000087AF61                 lea     rcx, [rsp+88h]
.text:000000000087AF69                 mov     edi, 1
.text:000000000087AF6E                 mov     rsi, rdi
.text:000000000087AF71                 call    fmt_Fprintln
.text:000000000087AF76                 xor     eax, eax
.text:000000000087AF78                 mov     rbp, [rsp+98h]
.text:000000000087AF80                 add     rsp, 0A0h
.text:000000000087AF87                 retn
```

On voit ici que la fonction récupère une clé de la fonction : ``main_GetAESKey``

Puis , on récupère de la donnée avec :
```c
.text:000000000087AECF                 call    encoding_hex_Decode
```
avec ``59E2267F61917A7832D3608F6DDB2C6146E68AB``

Finalement , la fonction ``github_com_forgoer_openssl_AesECBDecrypt`` est appélé .

Mon idée ici est de placer un **breakpoint** après le déchiffrement pour obtenir la clé de comparaison valid .

On décompile la fonction : ``AesECBDecrypt``

```c
__int64 __fastcall github_com_forgoer_openssl_AesECBDecrypt(__int64 a1, __int64 a2, __int64 a3, int a4, int a5, int a6)
{
  int v6; // eax
  int v7; // ebx
  int v8; // er10
  __int64 v9; // r14
  int v10; // edx
  __int64 v11; // rcx
  __int64 result; // rax
  __int64 v13; // [rsp-38h] [rbp-40h]
  __int64 v14; // [rsp-30h] [rbp-38h]
  __int64 v15; // [rsp-28h] [rbp-30h]
  void *retaddr; // [rsp+8h] [rbp+0h] BYREF
  int v17; // [rsp+10h] [rbp+8h]
  int v20; // [rsp+48h] [rbp+40h]

  if ( (unsigned __int64)&retaddr <= *(_QWORD *)(v9 + 16) )
    runtime_morestack_noctxt_abi0(a1, a2, a3);
  v17 = v6;
  v20 = v8;
  crypto_aes_NewCipher(a1, a2, a3, a5, a5, a6);
  if ( v11 )
    result = 0LL;
  else
    result = github_com_forgoer_openssl_ECBDecrypt(v7, a4, v10, v17, a6, v20, v13, v14, v15);
  return result;
}
```

Avec ``gdb``, on lancer le binaire et on place notre breakpoint juste avant le ``retour de la fonction``

![AltText](./img/bp.png)
On lance le programme avec ``run`` . On se connecte sur le site en ``localhost:8000`` et on rentre un mot de passe au hasard .

Notre programme se stop juste après le déchiffrement et on obtient le flag dans les registres :

![AltText](./img/registres.png)

Flag : ``PWNME{pr0_cr4ck3r_g000}``
