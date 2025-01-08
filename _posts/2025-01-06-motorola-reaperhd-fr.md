---
title: Motorola ReaperHD, ou comment espionner les routes américaines
date: 2025-01-06
categories: ['forensic']
tags: []
author: noderyos
---

> This article is entirely in French, the English version can be found [here](/posts/motorola-reaperhd)
{: .prompt-tip }


> Cet article est à but purement éducatif, exploiter ces données est illégal, malgrès l'absence d'authentification est de chiffrement
{: .prompt-tip }

Suite à cette [cette video](https://www.youtube.com/watch?v=0dUnY1641WM) de Matt Brown dans laquelle il explore les cameras ReadperHD exposées sur internet et relève les port 500x, j'ai décidé dánalyser plus en profondeur le protocole utilisés sur ces ports.

## 1. Capturer quelques paquets

En laissant tourner `nc xxx.xxx.xxx.xxx 5001 | tee capture` quelques minutes, jái pu capturer 23 packets.

## 2. Analyser la structure

Pour cette partie, je vais utiliser [Binwalk](https://github.com/ReFirmLabs/binwalk) pour extraire les images comme Matt Brown l'a fait et obtenir les offsets et tailles des images dans le fichier `capture` ainsi que [ImHex](https://github.com/WerWolv/ImHex) qui est un editeur hexadecimal qui me permettra de creer des pattern/bookmarks pour facciliter la compréhension de la structure.

Commencons par binwalk pour savoir où commencer à chercher:

```sh
-------------------------------------------------------------
DECIMAL      HEXADECIMAL  DESCRIPTION
-------------------------------------------------------------
2548         0x9F4        JPEG image, total size: 46940 bytes
...
```

Voici la première image

![](/assets/articles/motorola-reaperhd/car_image.jpg)

On peut confirmer en allant à la premiere addresse dans ImHex 

```
000009E0  70 9A BF BB D5 07 54 C0  00 00 00 00 02 00 00 00  p.....T.........
000009F0  5C B7 00 00 FF D8 FF E0  00 10 4A 46 49 46 00 01  \.........JFIF..
00000A00  01 00 00 01 00 01 00 00  FF DB 00 43 00 06 04 05  ...........C....
```

Où je retrouve bien `JFIF`, symbole reconnaissable du debut d'une image JPEG.
Juste avant le debut de l'image (`FF D8`), je peut facilement identifier un entier sur 32 bit `5C B7 00 00` qui correspond exactement à la taille du fichier JPEG selon Binwalk. Je peux d'hors et deja commencer a ecrire un pattern.

```
struct Packet {
    u32 image_size;
    u8 image[image_size];
};

Packet packets[1] @ 0x9F0;
```

Juste après l'image (`FF D9`), il y a une suite tres longue de valeurs, toutes tres proche, du moins au debut.

```
0000C140  03 23 34 84 00 29 09 E6  94 7C C7 9A 65 58 FF D9  .#4..)...|..eX..
0000C150  EC 3F 00 00 AE 00 00 00  5E 00 00 00 17 17 14 15  .?......^.......
0000C160  15 16 16 17 17 18 17 17  18 18 17 17 16 16 16 16  ................
0000C170  16 17 17 18 18 18 17 17  17 17 17 17 17 17 19 19  ................
0000C180  19 19 19 19 19 19 1A 1A  1A 19 19 19 19 19 19 19  ................
0000C190  19 19 19 19 19 19 18 18  18 18 18 19 19 19 19 19  ................
0000C1A0  19 19 19 19 19 19 19 19  19 19 19 19 19 19 18 18  ................
0000C1B0  18 18 18 18 18 18 19 19  19 19 19 19 19 19 18 19  ................
```

Cette suite de valeur se termine à l'addresse `0x1013F`, cette "liste" fait donc 16356 octet.
Je cherche désormais un endroit ou cette valeur est ecrite, et juste au dessus on retrouve 3 valeurs sur 32 bits, 16364 (`3C 3F 00 00`), 174 (`AE 00 00 00`) et 94 (`5E 00 00 00`), la première correspond à la taille de la "liste" + la taille des 2 prochains entiers, ces 2 entiers qui multipliées donnent exactement 16356. J'ai donc directement pensé à une image en noir en blanc (`255` ou `FF` pour le blanc, `0` ou `00` pour le noir).

Pour confirmer ca, j'ai fais un petit script python pour enregistrer l'image.

```py
from PIL import Image

data = bytes([
  0x25, 0x25, 0x25, 0x24, 0x24, 0x24, 0x24, 0x24, 0x26, 0x25, 0x25, 0x24, 0x24, 0x25, 0x26, 0x27,
  ...
])

img = Image.frombytes("L", (174, 94), data)
img.save("buf.png")
```

Ce qui nous donne ... Une magnifique image de la plaque d'immatriculation isolée, issue de la caméra Infrarouge, utilisée ensuite pour la lecture de la plaque.

![](/assets/articles/motorola-reaperhd/plate.png)

Je peux donc preciser mon pattern.

```
struct Packet {
    u32 image_size;
    u8 image[image_size];
    u32 plate_section_size;
    u32 plate_width;
    u32 plate_height;
    u8 plate[plate_width*plate_height];
};
```

A la fin de cette image, on retrouve ca 

```
00010140  00 00 00 00 00 00 00 00  00 00 00 00 8E 00 00 00  ................
00010150  7B 0A 22 43 6F 6C 6F 72  4E 61 6D 65 22 3A 20 22  {."ColorName": "
00010160  77 68 69 74 65 22 2C 0A  22 45 6E 67 69 6E 65 54  white",."EngineT
00010170  69 6D 65 44 65 6C 61 79  22 3A 20 22 31 37 39 37  imeDelay": "1797
00010180  22 2C 0A 22 4D 61 6B 65  72 4E 61 6D 65 22 3A 20  ",."MakerName": 
00010190  22 48 4F 4E 44 41 22 2C  0A 22 4D 6F 64 65 6C 4E  "HONDA",."ModelN
000101A0  61 6D 65 22 3A 20 22 41  43 43 4F 52 44 22 2C 0A  ame": "ACCORD",.
000101B0  22 4E 75 6D 53 61 74 65  6C 6C 69 74 65 73 47 50  "NumSatellitesGP
000101C0  53 22 3A 20 22 31 32 22  2C 0A 22 55 73 65 43 61  S": "12",."UseCa
000101D0  63 68 65 47 50 53 22 3A  20 22 30 22 0A 7D 08 04  cheGPS": "0".}..
```

12 fois `00` puis une nouvelle valeur, correspondant à la taille du json qui suit. Que voici

```json
{
"ColorName": "white",
"EngineTimeDelay": "1797",
"MakerName": "HONDA",
"ModelName": "ACCORD",
"NumSatellitesGPS": "12",
"UseCacheGPS": "0"
}
```

Dans lequel on retrouve plusieurs informations, dont la marque, le modèle et la couleur de la voiture.
Je ne suis pas sur exactement comment il obtient ces informations, je doute qu'il analyse l'image, maus je peux me tromper.

Le pattern ressemble desormais a ca 

```
struct Packet {
    u32 image_size;
    u8 image[image_size];
    u32 plate_section_size;
    u32 plate_width;
    u32 plate_height;
    u8 plate[plate_width*plate_height];
    u8 _a[12];
    u32 json_len;
    char json[json_len];
};
```

Juste après ce JSON, on retrouve le `08 04 00 00` en début de fichier, je suppose donc que le JSON est le dernier élément du packet. 

Il reste donc à comprendre le debut du packet que voici.

```
Hex View  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F
 
00000000  08 04 00 00 08 04 00 00  08 04 00 00 BB 0B 00 00  ................
00000010  CA 01 01 00 3D 00 00 00  36 33 45 49 44 44 00 00  ....=...63EIDD..
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000040  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000060  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000070  00 00 00 00 00 00 00 00  36 37 37 42 44 46 33 37  ........677BDF37
00000080  2D 34 43 44 30 2D 30 38  43 31 2D 33 39 36 35 2D  -4CD0-08C1-3965-
00000090  43 38 31 43 45 36 46 44  42 36 34 36 00 00 00 00  C81CE6FDB646....
000000A0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
*
00000170  00 00 00 00 00 00 00 00  01 00 00 00 37 DF 7B 67  ............7.{g
00000180  00 00 00 00 30 30 3A 30  30 3A 30 30 3A 30 30 00  ....00:00:00:00.
```

On retrouve `08 04 00 00` répété 3 fois (dans le 2ème packet il n'est présent qu'une seule fois), probablement un `heartbeat` (un packet qui est là pour maintenir la connection ouverte), suivit de `bob` (`BB 0B`) :). 
S'enchaine une suite de valeurs dont je ne connais pas le sens, puis la plaque d'immatriculation, dans le packet suivant elle fait 1 caractère de plus, mais le nombre de 0 est réduit de 1, pour faciliter l'analyse je suis partit du principe que la chaine de caractère prend toute la place jusqu'au prochain élément.
Prochain élément qui est un UUID, similaire entre les packets mais pas identique.
On retrouve ensuite quelques valeurs puis une valeur qui vaut toujours `00:00:00:00` dans mes packets ... aucune idée de ce dont il s'aggit.
De `0x190` à `0x9F0` on retrouve tout un tas de valeur sans sens evident, puis notre image, etc ...

Mon pattern final ressemble à ça:

```
import std.mem;

struct Packet {
    u32 _a[while(std::mem::read_unsigned($, 1) == 0x08)];
    u16 _bb0b;
    u8 _b[10];
    char plate[0x60];
    char uuid[0x24];
    u8 _c[0xE8];
    char date[11];
    u8 todo[0x861];
    u32 image_size;
    u8 image[image_size];
    u32 plate_section_size;
    u32 plate_width;
    u32 plate_height;
    u8 plate_img[plate_width*plate_height];
    u8 _d[12];
    u32 json_len;
    char json[json_len];
};
```

Qui à l'air complet puisqu'en augmentant la taille du tableau `packet` `Packet packets[20] @ 0x0;` ImHex arrive à formatter le fichier correctement sans aucun décalage.
