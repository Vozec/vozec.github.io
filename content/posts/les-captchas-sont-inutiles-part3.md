---
title: "Comment utiliser l'OCR pour résoudre des captchas"
date: 2021-10-29T08:00:00Z
description: "Cet articles complète les 2 précédents sur la résolution automatique de captcha."
categories: ["articles"]
tags: ["bypass","tuto"]
keywords: ["bypass", "recaptcha", "google", "ocr","request","harvester","captcha"]
---

## Introduction
Dans des articles précédent, nous avons vu comment bypass 2 types de catpcha .
Nous allons voir comment bypass d'une autre manière ces captchas grâce à l'OCR


# HCaptha

Hcaptcha est un concurrent à google de plus en plus connu :

![Alt text](./img/hcaptcha.png)

Il existe deux manières de le contourner :

- Avec un script JS
- Avec ce lien : https://dashboard.hcaptcha.com/signup?type=accessibility

En effet , on peut recevoir un cookie par mail qui bypass tous les captcha !

La seconde utilise cette extension : https://chrome.google.com/webstore/detail/violentmonkey/jinjaccalgkegednnccohejagnlnfdag/related


Et [ce script](./files/Hcaptcha_Solver.js) :
```js
██╗░░██╗░█████╗░░█████╗░██████╗░████████╗░█████╗░██╗░░██╗░█████╗░  ░██████╗░█████╗░██╗░░░░░██╗░░░██╗███████╗██████╗░
██║░░██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██║░░██║██╔══██╗  ██╔════╝██╔══██╗██║░░░░░██║░░░██║██╔════╝██╔══██╗
███████║██║░░╚═╝███████║██████╔╝░░░██║░░░██║░░╚═╝███████║███████║  ╚█████╗░██║░░██║██║░░░░░╚██╗░██╔╝█████╗░░██████╔╝
██╔══██║██║░░██╗██╔══██║██╔═══╝░░░░██║░░░██║░░██╗██╔══██║██╔══██║  ░╚═══██╗██║░░██║██║░░░░░░╚████╔╝░██╔══╝░░██╔══██╗
██║░░██║╚█████╔╝██║░░██║██║░░░░░░░░██║░░░╚█████╔╝██║░░██║██║░░██║  ██████╔╝╚█████╔╝███████╗░░╚██╔╝░░███████╗██║░░██║
╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚═╝░░░░░░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝  ╚═════╝░░╚════╝░╚══════╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝

// ==/UserScript==
(function() {

    //TODO: Enable debug mode to print console logs
    'use strict';
    var selectedImageCount = 0;
    var tensorFlowModel = undefined;
    var worker = undefined;

    var identifiedObjectsList = [];
    var exampleImageList = [];
    var identifyObjectsFromImagesCompleted = false;
    var currentExampleUrls = [];

    // Option to override the default image matching
    const ENABLE_TENSORFLOW = false;

    // Max Skips that can be done while solving the captcha
    // This is likely not to happen, if it occurs retry for new images
    const MAX_SKIPS = 10;
    var skipCount = 0;    

    String.prototype.equalsOneOf = function(arrayOfStrings) {

        //If this is not an Array, compare it as a String
        if (!Array.isArray(arrayOfStrings)) {
            return this.toLowerCase() == arrayOfStrings.toLowerCase();
        }

        for (var i = 0; i < arrayOfStrings.length; i++) {
            if ((arrayOfStrings[i].substr(0, 1) == "=" && this.toLowerCase() == arrayOfStrings[i].substr(1).toLowerCase()) ||
                (this.toLowerCase() == arrayOfStrings[i].toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    . . . . . .

```
Disponible [ici](./files/Hcaptcha_Solver.js)


# ReCaptha Image
Comme le script précédent, on retrouver [ce script](./files/Recaptcha_Solver.js) qui bypass les images via une reconnaissance sonore moins sécurisé ! Il faut aussi l'utiliser avec l'extension *Violentmonkey*
Disponible [ici](./files/Recaptcha_Solver.js)


# ReCaptha Silent V3
Dans le premier article nous avons vu comment contourner un ReCaptcha d'arrière-plan en Version 2
On ne peut pas utiliser la même méthode pour cette version.
La seul manière de bypass est d'utilisé du `selenium` , avec **pupetteer** sur python ou **ChromeDriver.exe** en C# .

En effet, en selenium le captcha ne vérifie pas l'intégrité du navigateur et agira comme sur un utilisateur lambda.

Prenons l'exemple de Skrill :

![Alt Text](./img/skrill.png)

Il semble difficile de se connecter via un bot . Pourtant c'est possible !
On se connecte en sélénium et on continue notre script avec les cookies de session récupérés du selenium !


```powershell
python3 -m pip install -U selenium
```

```python
from selenium import webdriver
import time
from selenium.webdriver.common.keys import Keys

username = "RecaptchaAreUseless@ez.gmail"
password = "EzPeasy"

driver = webdriver.Chrome()
driver.get('https://account.skrill.com/wallet/account/login?locale=fr') #Navigue a la page de connection
time.sleep(2)

html = driver.page_source
while("Avis sur les cookies" not in html): #Attend le chargement de la page
	html = driver.page_source

driver.find_element_by_xpath('/html/body/div[1]/div[3]/div/div/div[2]/div/div/button').click()  # Allow Cookie

userinput = driver.find_element_by_xpath('/html/body/kl-root/kl-theme/ng-component/kl-login-main-layout/div/div[2]/main/ng-component/form/kl-login/article/form/ps-form-field[1]/div/div[1]/div/input')
userinput.send_keys(username) # Send Username

passinput = driver.find_element_by_xpath('/html/body/kl-root/kl-theme/ng-component/kl-login-main-layout/div/div[2]/main/ng-component/form/kl-login/article/form/ps-form-field[2]/div/div[1]/div[1]/input')
passinput.send_keys(password)  # Send Password
passinput.send_keys(Keys.ENTER)
```

N'oubliez pas d'avoir *chromedriver.exe* dans le même dossier *(La bonne version en fonction de votre version de google-chrome)* [ici](https://chromedriver.chromium.org/downloads) et [la](chrome://settings/help)

# Captcha Image

On peut faciliment contourner ces captchas grâce à de la reconnaissance d'image.
En effet il existe [**Tesseract**](https://github.com/tesseract-ocr/tesseract) , une bibliothèque qui permet de lire les images et donc les catpchas.

![Alt text])(./img/classic.png)

*(Utilisation trés basique)*
```C#
private string OCR(Bitmap bmp)
{
    using (TesseractEngine engine = new TesseractEngine(@"tessdata", "eng", EngineMode.Default))
    {
        engine.SetVariable("tessedit_char_whitelist", "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        engine.SetVariable("tessedit_unrej_any_wd", true);
        using (var page = engine.Process(bmp, PageSegMode.SingleLine))
        {
            return page.GetText();
        }
    }
}
```

# Le Reste
Il reste certain captcha que je n'ai pas encore contourné , comme ceux de ArkosLab :
![Alt text](./img/arkos.png)

Ou encore les captcha puzzle comme chez Macdonald's :
![Alt text](./img/macdo.png)

De plus, il existe des services comme :

- [2Captcha](https://2captcha.com/fr)
- [Anti-Captcha](https://anti-captcha.com/)

Ces services sont payant ett permettent de résoudre ces captchas en maximum 30 secondes grâce à leur api.
