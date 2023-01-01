<p align="center">
  <img src="https://raw.githubusercontent.com/HaxeFoundation/crypto/master/CryptoLogo.png" />
</p>
<p align="center">
<a href="https://github.com/HaxeFoundation/crypto/actions"><img src="https://github.com/HaxeFoundation/crypto/workflows/CI/badge.svg" alt="GitHub Build Status"></a>
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
  * Murmur1 (32-bit)
  * Murmur2 (32-bit/64-bit)
  * Murmur3 (32-bit/128-bit(x86)/128-bit(x64) and incremental implementation 32-bit)
   
### Block cipher mode of operation
  * ECB
  * CBC
  * PCBC
  * CFB
  * OFB
  * CTR
  
### Padding
  * AnsiX923
  * BitPadding / ISO 9797-1 / ISO7816-4 / One and zeros
  * ISO10126 / Random padding
  * NoPadding
  * NullPadding / Zero byte padding
  * PKCS7 ( support PKCS#5 padding)
  * SpacePadding
  * TBC ( Trailing-Bit-Compliment padding )

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

#### Murmur hash

```haxe
```