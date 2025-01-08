---
title: Motorola ReaperHD, or how to spy on American roads
date: 2025-01-06
categories: ['forensic']
tags: []
author: noderyos
---

> Cet article est entièrement en anglais, la version française se trouve [ici](/posts/motorola-reaperhd-fr)
{: .prompt-tip }

> This article is for educational purposes only. Exploiting this data is illegal, even though it lacks authentication and encryption.  
{: .prompt-tip }

Following [this video](https://www.youtube.com/watch?v=0dUnY1641WM) by Matt Brown, where he explores ReaperHD cameras exposed on the Internet and identifies port 500x, I decided to analyze the protocol used on these ports more deeply.

## 1. Capturing some packets

By running `nc xxx.xxx.xxx.xxx 5001 | tee capture` for a few minutes, I was able to capture 23 packets.

## 2. Analyzing the structure

For this part, we will use [Binwalk](https://github.com/ReFirmLabs/binwalk) to extract images, as Matt Brown did, and to obtain the offsets and sizes of the images in the `capture` file. I will also use [ImHex](https://github.com/WerWolv/ImHex), a hexadecimal editor that allows me to create patterns/bookmarks to make understanding the structure easier.

Let's start with Binwalk to know where to look:

```sh
-------------------------------------------------------------
DECIMAL      HEXADECIMAL  DESCRIPTION
-------------------------------------------------------------
2548         0x9F4        JPEG image, total size: 46940 bytes
...
```

Here is the first image:

![](/assets/articles/motorola-reaperhd/car_image.jpg)

We can confirm this by going to the first address in ImHex:

```
000009E0  70 9A BF BB D5 07 54 C0  00 00 00 00 02 00 00 00  p.....T.........
000009F0  5C B7 00 00 FF D8 FF E0  00 10 4A 46 49 46 00 01  \.........JFIF..
00000A00  01 00 00 01 00 01 00 00  FF DB 00 43 00 06 04 05  ...........C....
```

Here, we find `JFIF`, the recognizable marker for the start of a JPEG image.  
Just before the start of the image (`FF D8`), we can easily identify a 32-bit integer `5C B7 00 00`, which exactly matches the size of the JPEG file according to Binwalk. At this point, I can already start writing a pattern.

```
struct Packet {
    u32 image_size;
    u8 image[image_size];
};

Packet packets[1] @ 0x9F0;
```

Just after the image (`FF D9`), there is a very long sequence of values, all very close to each other, at least initially.

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

This sequence of values ends at address `0x1013F`. This "list" is therefore 16,356 bytes long.  
I now look for a place where this value is written, and just above, I find three 32-bit values: 16,364 (`3C 3F 00 00`), 174 (`AE 00 00 00`), and 94 (`5E 00 00 00`). The first corresponds to the size of the "list" plus the size of the next two integers. These two integers, when multiplied, give exactly 16,356. I immediately thought of a black-and-white image (`255` or `FF` for white, `0` or `00` for black).

To confirm this, I wrote a small Python script to save the image:

```python
from PIL import Image

data = bytes([
  0x25, 0x25, 0x25, 0x24, 0x24, 0x24, 0x24, 0x24, 0x26, 0x25, 0x25, 0x24, 0x24, 0x25, 0x26, 0x27,
  ...
])

img = Image.frombytes("L", (174, 94), data)
img.save("buf.png")
```

This produces... a beautiful image of the isolated license plate, captured by the infrared camera, which is then used for license plate recognition.

![](/assets/articles/motorola-reaperhd/plate.png)

We can now refine our pattern.

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

At the end of this image, we find the following:

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

12 times `00`, followed by a new value corresponding to the size of the JSON that follows. Here it is:

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

This contains several pieces of information, including the car’s make, model, and color.  
I’m not sure exactly how this information is obtained; I doubt it analyzes the image, but I could be wrong.

The pattern now looks like this:

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

Right after this JSON, we find `08 04 00 00` at the start of the file, leading me to assume that the JSON is the last element in the packet.

Now, let’s try to understand the beginning of the packet:

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

We see `08 04 00 00` repeated three times (in the second packet, it appears only once), probably a `heartbeat` (a packet meant to keep the connection alive), followed by `bob` (`BB 0B`) :).  
Next is a sequence of values whose meaning is unclear, then the license plate. In the following packet, the license plate is one character longer, but the number of `0`s is reduced by one. To simplify the analysis, I assumed the string occupies all space until the next element.  
The next element is a UUID, similar across packets but not identical.  
We then find some values and a constant `00:00:00:00` in all packets, its purpose is unclear.  
From `0x190` to `0x9F0`, we find a series of seemingly meaningless values, then the image, and so on.

My final pattern looks like this:

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

This seems complete, as increasing the size of the `packet` array (`Packet packets[20] @ 0x0;`) allows ImHex to format the file correctly with no misalignment.

