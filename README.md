<p align="center">
  <img src="https://raw.githubusercontent.com/HaxeFoundation/crypto/master/CryptoLogo.png" />
</p>
<p align="center">
<a href="https://github.com/HaxeFoundation/crypto/actions/workflows/main.yml"><img src="https://github.com/HaxeFoundation/crypto/actions/workflows/main.yml/badge.svg" alt="GitHub Build Status"></a>
</p>

Cross platform cryptographic functions for Haxe 4 and 3

This brings cryptographic functions for Haxe 4, with `-lib crypto` after having installed it with `haxelib install crypto`.

It is also usable on Haxe 3, where there is already a `haxe.crypto` package containing Adler32, Base64, BaseCode, Crc32, HMac, Md5, Sha1, Sha224, Sha256. 
Using this library on Haxe 3 with `-lib crypto` will overload the `haxe.crypto` package and allow support for Aes, BCrypt, BlowFish, Des, Pbkdf2, Ripemd160, Sha384, Sha512, TripleDes, TwoFish in addition to the previous 9 classes.

### Supported algorithms

  * [`Aes`](#aes-encryption)
  * [`Blowfish`](#blowfish)
  * [`Twofish`](#twofish)
  * [`TripleDes`](#triple-des--3des)
  * [`Des`](#des)
  * [`BCrypt`](#bcrypt)
  * [`Hmac`](#hmac-with-md5--sha1--sha224--sha256--sha384--sha512)
  * [`Sha1`](#sha1)
  * [`Sha224`](#sha224)
  * [`Sha256`](#sha256)
  * [`Sha384`](#sha384)
  * [`Sha512`](#sha512)
  * [`Ripemd-160`](#ripemd-160)
  * [`PBKDF2`](#pbkdf2)
  * [`Salsa20`](#salsa20)
  * [`XSalsa20`](#xsalsa20)
  * [`ChaCha`](#chacha)
  * [`RC4`](#rc4--arc4-)
  * [`SCrypt`](#scrypt)
  * [`Poly1305`](#poly1305)
  * [`Md5`](#md5)
   
### Other algorithms
  * [`Adler32`](#adler32)
  * [`Crc32`](#crc32)

### Block cipher mode of operation
  * ECB
  * CBC
  * PCBC
  * CFB
  * OFB
  * CTR
  * CMAC
  * CCM
  * GCM
  * SIV
  * GCMSIV
  
### Padding
  * AnsiX923
  * BitPadding / ISO 9797-1 / ISO7816-4 / One and zeros
  * ISO10126 / Random padding
  * NoPadding
  * NullPadding / Zero byte padding
  * PKCS7 ( support PKCS#5 padding)
  * SpacePadding
  * TBC ( Trailing-Bit-Compliment padding )

Security Considerations
-----------------------

This code has not been subjected to a formal, paid, security audit. This library can be use  with a degree of safety equivalent to any other encryption library  written in pure Haxe.

When using this library please keep the following in mind:

- Cryptography is hard. Please review and test this code before depending on it for critical functionality.
- Haxe can compile to different languages , so the execution of this code depends on trusting a very large set of tools and systems.
- Be careful about the source from which you download the library.
- Use "native" functionality where possible. This can be critical when dealing with performance and security.
- Understand possible attacks against cryptographic systems. For instance side channel and timing attacks may be possible due to the difficulty in implementing constant time algorithms in different algorithms and for different targets.
- Certain features within this library may have a lower vulnerability to attacks, this could includes features that deal with data format manipulation or those features that do not play a role in communication.

Questions
-----------------------
#### Should I be using Haxe Crypto for something that actually needs to be secured?
- Yes, you can use it for different tasks. Just because this library doesn't have an formal, paid, security audit check doesn't mean it's insecure. Some algorithms can be	susceptible on side channels and timing attacks when the attacker generates millions of combinations (encryption and decryption) and tries to guess the password, but this does not mean, firstly, that it is an easy task to hack an algorithm, and secondly, not for all algorithms here such attacks can be used. The hacking process is still not that easy task, especially if you use advanced algorithms and long encryption , decryption keys and passwords.
   Just an example, obfuscation is also a process for protection. Is it 100% hack protected? No. Is it widely used for protection? Yes
 
#### Where is it safe to use this library?
- Well, if you are protecting financial and banking transactions, I will recommend you to use audited cryptographic software . In other cases (such as game resources, game communication (not financial) and even login forms, this library should give you enough protection. But for this, you should always use long keys and proven algorithms Don't use old unsecure algorithms like DES or RC4 (it's here for backwards compatibility)
 
#### Are OpenSSL, Nacl 100% bug free and secured?
- Various bugs are found in them over time, as in most, if not all, security libraries.
    So are they 100% secure/bug free? I don't think so. Bugs will likely appear over time. Should I use them then? Of course, you should definitely use it if you need them.
  
#### Is this library not maintained at all ?
- This is not true. There is a regular updates that brings better performance and new algorithms. All  pull request a  timely review and merged. Also all algorithms are properly implemented and include many tests for all platforms (check here https://github.com/HaxeFoundation/crypto/tree/master/tests/src/unit/crypto)
   If you wish, you could add more test by opening pull request
   
### Usage

#### AES Encryption

```haxe
   var aes : Aes = new Aes();
   
   var key = Bytes.ofHex("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4");
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var iv:Bytes = Bytes.ofHex("4F021DB243BC633D7178183A9FA071E8");
   
   aes.init(key,iv);
   
   // Encrypt
   var data = aes.encrypt(Mode.CTR,text,Padding.NoPadding);
   trace("Encrypted text: "+ data.toHex());
   
   // Decrypt
   data = aes.decrypt(Mode.CTR,data,Padding.NoPadding);
   trace("Decrypted text: "+ data);
   
   // CMAC
   var cmacKey = Bytes.ofHex("2b7e151628aed2a6abf7158809cf4f3c");
   var cplaintext = Bytes.ofHex("6bc1bee22e409f96e93d7e117393172a");
   var cresult = Bytes.ofHex("070a16b46b4d4144f79bdd9dd04a287c");
   trace("CMAC: " + CMAC.calculate(cplaintext, cmacKey).toHex());
   trace("Valid: " + CMAC.verify(cplaintext, cresult, cmacKey));
  
   // CCM
   var key = Bytes.ofHex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
   var nonce = Bytes.ofHex("00000003020100a0a1a2a3a4a5");
   var aad = Bytes.ofHex("0001020304050607");
   var plaintext = Bytes.ofHex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
   var aes = new Aes(key, nonce);
   var result = aes.encrypt(Mode.CCM, plaintext, aad, 8);
   trace("CCM Ciphertext: " + result.toHex());
   var decrypted = aes.decrypt(Mode.CCM, result, aad, 8);
   trace("CCM Decrypted: " + decrypted.toHex());

   // GCM
   var key = Bytes.ofHex("feffe9928665731c6d6a8f9467308308");
   var iv = Bytes.ofHex("cafebabefacedbaddecaf888");
   var aad = Bytes.alloc(0);
   var plaintext = Bytes.ofHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
   var expected = "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091473F59854D5C2AF327CD64A62CF35ABD2BA6FAB4";
   var aes = new Aes(key, iv);
   var result = aes.encrypt(Mode.GCM, plaintext, aad, 16);
   var actual = result.toHex().toUpperCase();
   trace("GCM Ciphertext: " + result.toHex()+" --> Match: " + (expected == actual));
   var decryptedText = aes.decrypt(Mode.GCM, result, aad, 16);
   trace("GCM Decrypted: " + decryptedText.toHex()+" --> Match: " + (decryptedText.toHex().toUpperCase() == plaintext.toHex().toUpperCase()));
  
   //SIV
   var plaintext = Bytes.ofHex("112233445566778899aabbccddee");
   var key = Bytes.ofHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
   var nonce = null;
   var associatedData = [Bytes.ofHex("101112131415161718191a1b1c1d1e1f2021222324252627")];
   var aes = new Aes(key,nonce);
   var res  =  aes.encrypt(Mode.SIV, plaintext, associatedData);
   trace("SIV Result: "+res.toHex());
   var dcr = aes.decrypt(Mode.SIV, res, associatedData);
   trace("Decrypted SIV: " + dcr.toHex()+" --> Match: "+(dcr.toHex()==plaintext.toHex()));
  
   // GCM-SIV
   var key = Bytes.ofHex("ee8e1ed9ff2540ae8f2ba9f50bc2f27c");
   var nonce = Bytes.ofHex("752abad3e0afb5f434dc4310");
   var plaintext = Bytes.ofHex("48656c6c6f20776f726c64");
   var aad = Bytes.ofHex("6578616d706c65");
   var aes = new Aes(key, nonce);
   var gcmSivResult = aes.encrypt(Mode.GCMSIV, plaintext, aad);
   trace("GCM-SIV Ciphertext: " + gcmSivResult.toHex());
   var result:Bytes = aes.decrypt(Mode.GCMSIV, gcmSivResult, aad);
   trace("GCM-SIV Decrypted : " + result.toHex());
```

#### Blowfish

```haxe
   var blowFish  : BlowFish = new BlowFish();
   
   var key = Bytes.ofHex("E0FEE0FEF1FEF1FE");
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var iv:Bytes = Bytes.ofHex("7FC38460C9225873");
   
   blowFish.init(key,iv);
   
   // Encrypt
   var data = blowFish.encrypt(Mode.PCBC,text,Padding.PKCS7);
   trace("Encrypted text: "+ data.toHex());
   
   // Decrypt
   data = blowFish.decrypt(Mode.PCBC,data,Padding.PKCS7);
   trace("Decrypted text: "+ data);
```

#### Twofish

```haxe
   var twoFish  : TwoFish = new TwoFish();
   
   var key = Bytes.ofHex("ff08e2dcca459835ac30c39548ae848157ba5fdcc8e4977efc26c0d1cc7a25cb");
   var text = Bytes.ofHex("06051a69c4a72fa8b205ebdca3add79d5e904b5e9e6d08ed60233ad28b9540ba");
   
   twoFish.init(key);
   
   // Encrypt
   var data = twoFish.encrypt(Mode.ECB,text,Padding.NoPadding);
   trace("Encrypted text: "+ data.toHex());
   
   // Decrypt
   data = twoFish.decrypt(Mode.ECB,data,Padding.NoPadding);
   trace("Decrypted text: "+ data.toHex());
```

#### Triple DES / 3Des

```haxe
   var tdes : TripleDes = new TripleDes();
   
   var key = Bytes.ofHex("2BD6459F82C5B300952C49104881FF482BD6459F82C5B300");
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var iv:Bytes = Bytes.ofHex("A015E0CFA1FED3B5");
   
   tdes.init(key,iv);
   
    // Encrypt
   var data = tdes.encrypt(Mode.OFB,text,Padding.NoPadding);
   trace("Encrypted text: "+ data.toHex());
   
   // Decrypt
   data = tdes.decrypt(Mode.OFB,data,Padding.NoPadding);
   trace("Decrypted text: "+ data);
```

####  DES

```haxe
   var des:Des = new Des();
   
   var key = Bytes.ofHex("9816854577667254");
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var iv:Bytes = Bytes.ofHex("69cf9d79757adcab");
   
   des.init(key,iv);
   
    // Encrypt
   var data = des.encrypt(Mode.CTR,text,Padding.NoPadding);
   trace("Encrypted text: "+ data.toHex());
   
   // Decrypt
   data = des.decrypt(Mode.CTR,data,Padding.NoPadding);
   trace("Decrypted text: "+ data);
```

#### BCrypt

```haxe
   var salt = BCrypt.generateSalt(10,BCrypt.Revision2B); // Example: $2b$10$xB5TcOrSHD2quBMES0W8aO
    
   var dataText = BCrypt.encode("Haxe - The Cross-platform Toolkit",salt);
   trace("BCrypt: "+dataText); // Example: $2b$10$xB5TcOrSHD2quBMES0W8aOrxTs3ONJQzqYIe0l.s1BHO6KoYUY5IS
   
   var match = BCrypt.verify("Haxe - The Cross-platform Toolkit",dataText);
   trace("Match: "+match);
```

#### Hmac with MD5 / SHA1 / SHA224 / SHA256 / SHA384 / SHA512

```haxe
   var hmacMd5 = new Hmac(MD5);
   var hmacSha1 = new Hmac(SHA1);
   var hmacSha224 = new Hmac(SHA224);
   var hmacSha256 = new Hmac(SHA256);
   var hmacSha384 = new Hmac(SHA384);
   var hmacSha512 = new Hmac(SHA512);

   var key = ofHex("c8c2c9d386b63964");
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
    
   var data = hmacMd5.make(key,text);
   trace("HMac MD5: "+data.toHex());
   
   data = hmacSha1.make(key,text);
   trace("HMac Sha1: "+data.toHex());

   data = hmacSha224.make(key,text);
   trace("HMac Sha224: "+data.toHex());

   data = hmacSha256.make(key,text);
   trace("HMac Sha256: "+data.toHex());
   
   data = hmacSha384.make(key,text);
   trace("HMac Sha384: "+data.toHex());
   
   data = hmacSha512.make(key,text);
   trace("HMac Sha512: "+data.toHex());
```

#### SHA1

```haxe
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
    
   var dataText = Sha1.encode("Haxe - The Cross-platform Toolkit");
   trace("Sha1: "+dataText);
   
   var dataBytes = Sha1.make(text);
   trace("Sha1: "+dataBytes.toHex());
```

#### SHA224

```haxe
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
    
   var dataText = Sha224.encode("Haxe - The Cross-platform Toolkit");
   trace("Sha224: "+dataText);
   
   var dataBytes = Sha224.make(text);
   trace("Sha224: "+dataBytes.toHex());
```

#### SHA256

```haxe
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
    
   var dataText = Sha256.encode("Haxe - The Cross-platform Toolkit");
   trace("Sha256: "+dataText);
   
   var dataBytes = Sha256.make(text);
   trace("Sha256: "+dataBytes.toHex());
```

#### SHA384

```haxe
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
    
   var dataText = Sha384.encode("Haxe - The Cross-platform Toolkit");
   trace("Sha384: "+dataText);
   
   var dataBytes = Sha384.make(text);
   trace("Sha384: "+dataBytes.toHex());
```

#### SHA512

```haxe
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
    
   var dataText = Sha512.encode("Haxe - The Cross-platform Toolkit");
   trace("Sha512: "+dataText);
   
   var dataBytes = Sha512.make(text);
   trace("Sha512: "+dataBytes.toHex());
```

#### Ripemd-160

```haxe
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   
   var rpmd = Ripemd160.encode("Haxe - The Cross-platform Toolkit");
   trace("Ripemd-160: "+rpmd);
   
   var rpmd = Ripemd160.make(text);
   trace("Ripemd-160: "+rpmd.toHex());
   
   var rpmd = new Ripemd160();
   rpmd.addBytes(text,0,text.length);
   var rdata = rpmd.finish();
   trace("Ripemd-160: "+rdata.toHex());
```

#### PBKDF2

```haxe
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var salt = Bytes.ofString("salt");
   
   // Support: MD5, SHA1,	SHA224, SHA256, SHA384, SHA512, RIPEMD160
   var pbkdf2 : Pbkdf2 = new Pbkdf2(SHA1);
   var data = pbkdf2.encode(text,salt,4096,20);
   trace("PBKDF2: "+data.toHex());
```

#### Salsa20

```haxe
   var key = Sha256.make(Bytes.ofString("secret key"));
   var nonce = Bytes.ofHex("288FF65DC42B92F9");
   var msg = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var salsa = new Salsa20();
   salsa.init(key,nonce);
   var data = salsa.encrypt(msg);
   trace("Salsa20 encrypt: "+data.toHex());

   var salsaDecrypt =  new Salsa20();
   salsaDecrypt.init(key,nonce);
   var plainData = salsaDecrypt.decrypt(data);
   trace("Salsa20 decrypt: "+ plainData.toString());

   salsa.reset();
   plainData = salsa.decrypt(data);
   trace("Salsa20 decrypt ( with reset ) : "+ plainData.toString());

   salsa.seek(0);
   plainData = salsa.decrypt(data);
   trace("Salsa20 decrypt ( with seek position ) : "+ plainData.toString());
``` 

#### XSalsa20

```haxe
   var key = Sha256.make(Bytes.ofString("secret key"));
   var nonce = Bytes.ofHex("9E645A74E9E0A60D8243ACD9177AB51A1BEB8D5A2F5D700C");
   var msg = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var xsalsa = new XSalsa20();
   xsalsa.init(key,nonce);
   var data = xsalsa.encrypt(msg);
   trace("XSalsa20 encrypt: "+data.toHex());

   var xsalsaDecrypt =  new XSalsa20();
   xsalsaDecrypt.init(key,nonce);
   var plainData = xsalsaDecrypt.decrypt(data);
   trace("XSalsa20 decrypt: "+ plainData.toString());
```

#### ChaCha

```haxe
   var key = Sha256.make(Bytes.ofString("secret key"));
   var nonce = Bytes.ofHex("0F1E2D3C4B596877");
   var msg = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var chaCha = new ChaCha();
   chaCha.init(key,nonce);
   var data = chaCha.encrypt(msg);
   trace("ChaCha encrypt: "+data.toHex());

   var chaChaDecrypt =  new ChaCha();
   chaChaDecrypt.init(key,nonce);
   var plainData = chaChaDecrypt.decrypt(data);
   trace("ChaCha decrypt: "+ plainData.toString());
```

#### RC4 ( ARC4 )

```haxe
   var key = Bytes.ofHex("a99c5476d5e5d61d425c01fa29632171");
   var msg = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var rc4 = new RC4();
   rc4.init(key);
   var data = rc4.encrypt(msg);
   trace("RC4 encrypt: "+data.toHex());

   rc4.init(key);
   var plainData = rc4.decrypt(data);
   trace("RC4 decrypt: "+ plainData.toString());
```

#### SCrypt

```haxe
   var salt = Bytes.ofHex("536F6469756D43686C6F72696465");
   var password = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var scrypt:SCrypt = new SCrypt();
   var data = scrypt.hash(password, salt, 1024, 8, 1, 64);
   trace("SCrypt hash: "+data.toHex());
```

#### Poly1305

```haxe
   var key = Sha256.make(Bytes.ofString("secret key")); //32 bytes key
   var msg = Bytes.ofString("Haxe - The Cross-platform Toolkit");
  
   var poly1305 = new Poly1305();
   var data = poly1305.encode(msg,key); 
   trace("Poly1305 encrypt: "+data.toHex());
   
   // Verify
   var verify = poly1305.verify(msg,key,data);
   trace("OK: "+verify);

   // Streaming API
   var poly1305 = new Poly1305();
   poly1305.init(key);
   poly1305.update(msg, 0, msg.length);
   msg = Bytes.ofString("Haxe can build cross-platform applications.");
   poly1305.update(msg, 0, msg.length);
   var data = poly1305.finish();
   trace("Poly1305 encrypt: "+ data.toHex());
```

#### Md5

```haxe
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
    
   var dataText = Md5.encode("Haxe - The Cross-platform Toolkit");
   trace("Md5: "+dataText);
   
   var dataBytes = Md5.make(text);
   trace("Md5: "+dataBytes.toHex());
```

#### Adler32

```haxe
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var data = Adler32.make(text);
   trace("Adler32: "+data);
```

#### Crc32

```haxe
   var text = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var data = Crc32.make(text);
   trace("Crc32: "+data);
```
