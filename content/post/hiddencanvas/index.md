---
title: "Exploiting Caption Extract from Metadata Web Service"
date: "2025-06-07"
categories: [
    "Write-up"
]
tags : [
    "International",
    "As kNowN aS b4r"
]
image: intro.png
---
#####
>Write-up ini adalah bagian dari Write-up TJCTF 2025 dengan nama chall "hidden-canvas"

![Dibuat oleh Gemini AI](intro.png)

#####
Jadi, disalah satu chall `Web Exploitation` di TJCTF 2025, ada sebuah chall yang `unik` yaitu bernama `hidden-canvas`, singkatnya di web service ini, user dapat mengupload sebuah gambar

![](tampilanweb.png)

awalnya, gw mengira bahwa kita perlu menyisipkan `webshell` dengan segala teknik bypass nya, tetapi ada satu error ini yang menandakan bahwa ini kerentanan pada file upload, tapi tidak pakai `webshell`..

![](eror.png)

`Incorrect MIME type`, ini menandakan bahwa server melakukan validasi terhadap gambar yang diinputkan oleh user, jadi meskipun disini gw sudah melakukan semua jenis bypass dari menamakan webshell nya `webshell.jpg.php` sampai mengubah magic byte, tetap tidak tembus karna server memvalidasi semua content yang ada pada gambar yang diinputkan oleh user.

Jadi disini gw coba upload aja foto asal dengan penambahan variabel di metadata

![](exiftool1.png)

lalu gw upload, dan ini response web nya

![](res1.png)

`[Caption Error: Invalid Base64 data ('utf-8' codec can't decode byte 0x93 in position 2: invalid start byte)]` ini nunjukin, bahwa server selain nge-extract extra metadata pada gambar, juga mendecode nya sebagai base64, jadi caranya adalah dengan kita mengencode dulu payload pada metadata nya dengan base64

![](res2.png)

nah berhasil, next step nya, gw udh aga firasat dari fitur fitur kaya gini, biasanya import dari modul python, so disini gw langsung nyoba payload `Server Side Template Injection`

![](res3.png)

dan berhasil, next step nya tinggal bikin payload `SSTI RCE` untuk listing current file directory

![](res4.png)

tinggal dicat deh,

![](flag.png)

Flag: `tjctf{H1dd3n_C@nv@s_D3c0d3d_4nd_R3nd3r3d!}`


