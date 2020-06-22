+++
title = "Crypto"
weight = 2
+++

## ce01

we are provided the following ciphertext:

`IB EVMJGASVCJNM, C TRKTGIGRGIAB EIJNPV IT C OPGNAZ AQ PBEVMJGIBS KM YNIEN RBIGT AQ JWCIBGPHG CVP VPJWCEPZ YIGN EIJNPVGPHG, CEEAVZIBS GA C QIHPZ TMTGPO; GNP "RBIGT" OCM KP TIBSWP WPGGPVT (GNP OATG EAOOAB), JCIVT AQ WPGGPVT, GVIJWPGT AQ WPGGPVT, OIHGRVPT AQ GNP CKAXP, CBZ TA QAVGN. GNP VPEPIXPV ZPEIJNPVT GNP GPHG KM JPVQAVOIBS GNP IBXPVTP TRKTGIGRGIAB. GNP QWCS IT CTIOJWPTRKTGIGRGIAB`

I tried a caesar cipher first and when that didn't pan out I tried a substitution cipher which was correct.  The plaintext is and i used https://quipqiup.com/ to solve it:
```
IN CRYPTOGRAPHY, A SUBSTITUTION CIPHER IS A METHOD OF ENCRYPTING BY WHICH UNITS OF PLAINTEXT ARE REPLACED WITH CIPHERTEXT, ACCORDING TO A FIXED SYSTEM; THE "UNITS" MAY BE SINGLE LETTERS (THE MOST COMMON), PAIRS OF LETTERS, TRIPLETS OF LETTERS, MIXTURES OF THE ABOVE, AND SO FORTH. THE RECEIVER DECIPHERS THE TEXT BY PERFORMING THE INVERSE SUBSTITUTION. THE FLAG IS ASIMPLESUBSTITUTION
```

## ce02

we are provided the following text and told to figure out the flag.  I tried a few and cracked it a caesar cipher of shift 9

```
RW LAHYCXPAJYQH, J LJNBJA LRYQNA, JUBX TWXFW JB LJNBJA'B LRYQNA, CQN BQROC LRYQNA, LJNBJA'B LXMN XA LJNBJA BQROC, RB XWN XO CQN BRVYUNBC JWM VXBC FRMNUH TWXFW NWLAHYCRXW CNLQWRZDNB. RC RB J CHYN XO BDKBCRCDCRXW LRYQNA RW FQRLQ NJLQ UNCCNA RW CQN YUJRWCNGC RB ANYUJLNM KH J UNCCNA BXVN ORGNM WDVKNA XO YXBRCRXWB MXFW CQN JUYQJKNC. OXA NGJVYUN, FRCQ J UNOC BQROC XO 3, M FXDUM KN ANYUJLNM KH J, N FXDUM KNLXVN K, JWM BX XW. CQN VNCQXM RB WJVNM JOCNA SDURDB LJNBJA, FQX DBNM RC RW QRB YAREJCN LXAANBYXWMNWLN. CQN OUJP RB LJNBJAAXCBCQNKAJRW.
```

```
IN CRYPTOGRAPHY, A CAESAR CIPHER, ALSO KNOWN AS CAESAR'S CIPHER, THE SHIFT CIPHER, CAESAR'S CODE OR CAESAR SHIFT, IS ONE OF THE SIMPLEST AND MOST WIDELY KNOWN ENCRYPTION TECHNIQUES. IT IS A TYPE OF SUBSTITUTION CIPHER IN WHICH EACH LETTER IN THE PLAINTEXT IS REPLACED BY A LETTER SOME FIXED NUMBER OF POSITIONS DOWN THE ALPHABET. FOR EXAMPLE, WITH A LEFT SHIFT OF 3, D WOULD BE REPLACED BY A, E WOULD BECOME B, AND SO ON. THE METHOD IS NAMED AFTER JULIUS CAESAR, WHO USED IT IN HIS PRIVATE CORRESPONDENCE. THE FLAG IS CAESARROTSTHEBRAIN.
```

flag: `CAESARROTSTHEBRAIN`

## ce03

the provided files are:

`4870412d81d8af4b494c56462a4d684f24baee6f89627a995dfb6beccb404726e06ea8b99c9cbbe0b906ff5eec76ad602c85903f3e7f40156570cec56a19c244c3c69d9a00cbd4e9606288e1ea2e8b1f8bb1932d1ab67d0e9cb04de01adaac0a5e4558c90df8b519012d8d6a94a5c08e1d1dd81e07b8f2b6f87863290ad1c245530fa9894d9be8c8d2a1d8325a9bf1015180d3247130f170b3f5325c290f75b8eb2cf983443df33eedd6164c308674f21d6e47284983fc7132d056c1b34acc9c3d0bf62f9ea94e7f0cda7ab4d91d92089ccdcb1644f8390ddc27ef27f759870a53910a7407ea8c0896c73fd7841c2f75515512e0a6d4b912cd540b4c444c87a7`

and `iamakeykeykeykey`

the first one is the encrypted flag and the second one is the key to solve it.  We are told it is some form of AES.  

i used https://www.devglan.com/online-tools/aes-encryption-decryption to get `The Advanced Encryption Standard (AES), also known by its original name Rijndael, is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001. The flag is: RijNdaelMe-9912`


## ce04

we are provided with:

`Ulp Giysbssi ntpzsf wt e xptzcr cg iynrqdhwok lwpzopsumn eeph pm vwtyg s gsfjid zf abhssazgef Qostec nihvsft, fldev cb hii wptlsfg pj l veqkcfe. Me pmhzcmt e qzre ct dppjllhvopfxtn smpghjxfeigb.`

and a picture.  this picture is from the vignere cipher wikipedia page so I think we can conclude it is probably a vignere cipher.  

I used https://www.boxentriq.com/code-breaking/vigenere-cipher to solve it.  the plaintext is `the vigenere cipher is a method of encrypting alphabetic text by using a series of interwoven caesar ciphers based on the letters of a keyword it employs a form of polyalphabetic substitution` and the key is `bellasooo`

flag: `bellasooo`