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
  * [`Chacha20Poly1305`](#chacha20poly1305)
  * [`XChacha20Poly1305`](#xchacha20poly1305)
  * [`XSalsa20Poly1305`](#xsalsa20poly1305)
  * [`Blake2b`](#blake2b)
  * [`Blake2s`](#blake2s)
  * [`Blake3`](#blake3)
  * [`Argon2i`](#argon2i)
  * [`Argon2d`](#argon2d)
  * [`Argon2id`](#argon2id)
   
### Other algorithms
  * [`Adler32`](#adler32)
  * [`Crc32`](#crc32)

### Random algorithms
  * [`AesCtrDrbg`](#aesCtrDrbg)
  * [`SecureRandom`](#securerandom)
  
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
  * EAX
  * KW
  * KWP
  * XTS
  * FF1
  
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
   
   // EAX
   var key = Bytes.ofHex("91945D3F4DCBEE0BF45EF52255F095A4");
   var nonce = Bytes.ofHex("BECAF043B0A23D843194BA972C66DEBD");
   var aad = [Bytes.ofHex("FA3BFD4806EB53FA")];
   var plaintext = Bytes.ofHex("F7FB");
   var expected = "19DD5C4C9331049D0BDAB0277408F67967E5";
   var aes = new Aes(key, nonce);
   var result = aes.encrypt(Mode.EAX, plaintext, aad);
   trace("EAX Ciphertext: " + result.toHex());
   var result:Bytes = aes.decrypt(Mode.EAX, result, aad);
   trace("EAX Decrypted : " + result.toHex());
   
   // KW
   var key = Bytes.ofHex("000102030405060708090A0B0C0D0E0F");
   var plaintext = Bytes.ofHex("00112233445566778899AABBCCDDEEFF");
   var expected = "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5";
   var result = KW.encrypt(plaintext, key, nonce);
   trace("KW Ciphertext: " + result.toHex());
   var decrypted = KW.decrypt(result, key, nonce);
   trace("KW Decrypted : " + decrypted.toHex());
   
   // KWP
   var key = Bytes.ofHex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
   var plaintext = Bytes.ofHex("C37B7E6492584340BED12207808941155068F738");
   var expected = "138BDEAA9B8FA7FC61F97742E72248EE5AE6AE5360D1AE6A5F54F373FA543B6A";
   var result = KWP.encrypt(plaintext, key, nonce);
   trace("KWP Ciphertext: " + result.toHex());
   var decrypted = KWP.decrypt(result, key, nonce);
   trace("KWP Decrypted : " + decrypted.toHex());
   
   // XTS
   var key1 = Bytes.ofHex("11111111111111111111111111111111");
   var key2 = Bytes.ofHex("22222222222222222222222222222222");
   var sector:Int64 = Int64.parseString("219902325555");
   var plaintext = Bytes.ofHex("4444444444444444444444444444444444444444444444444444444444444444");
   var expected = "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0";
   var result = XTS.encrypt(plaintext, key1, key2, sector);
   trace("XTS Ciphertext: " + result.toHex());
   var decrypted = XTS.decrypt(result, key1, key2, sector);
   trace("XTS Decrypted : " + decrypted.toHex());
   
   // FF1
   var key = Bytes.ofHex("2B7E151628AED2A6ABF7158809CF4F3C");
   var plaintext = "0123456789";
   var tweak = Bytes.alloc(0);
   var radix = 10;
   var alphabet = "0123456789";
   var expected = "2433477484";
   var result = FF1.encrypt(plaintext, key, tweak, radix, alphabet);
   trace("FF1 Ciphertext: " + result.toHex());
   var decrypted = FF1.decrypt(result, key, tweak, radix, alphabet);
   trace("FF1 Decrypted : " + decrypted.toHex());
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
   
   var sha = new Sha224();
   sha.update(Bytes.ofString("Haxe - "));
   sha.update(Bytes.ofString("The Cross-platform Toolkit"));
   var result = sha.digest();
   trace("Sha224: "+result.toHex());
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
   
   var sha = new Sha512();
   sha.update(Bytes.ofString("Haxe - "));
   sha.update(Bytes.ofString("The Cross-platform Toolkit"));
   var result = sha.digest();
   trace("Sha512: "+result.toHex());
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

#### Chacha20Poly1305

```haxe
   var key = Bytes.ofHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
   var iv = Bytes.ofHex("070000004041424344454647");
   var aad = Bytes.ofHex("50515253c0c1c2c3c4c5c6c7");
   var plaintext = Bytes.ofHex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
   var expected = Bytes.ofHex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
   var cipher = new Chacha20Poly1305();
   var result = cipher.encrypt(key, iv, plaintext, aad);
   trace("Chacha20Poly1305 encrypt: " + result.toHex());
   var decrypted = cipher.decrypt(key, iv, result, aad);
   trace("Chacha20Poly1305 text: " + decryptedText.toHex());
```
   
#### XChacha20Poly1305

```haxe
   var key = Bytes.ofHex("0000000000000000000000000000000000000000000000000000000000000000");
   var iv = Bytes.ofHex("000000000000000000000000000000000000000000000000");
   var aad = Bytes.alloc(0);
   var plaintext = Bytes.ofHex("000000000000000000000000000000");
   var expected = Bytes.ofHex("789e9689e5208d7fd9e1f3c5b5341fb2f7033812ac9ebd3745e2c99c7bbfeb");
   var cipher = new XChaCha20Poly1305();
   var result = cipher.encrypt(key, iv, plaintext, aad);
   trace("XChaCha20Poly1305 encrypt: " + result.toHex());
   var decrypted = cipher.decrypt(key, iv, result, aad);
   trace("XChaCha20Poly1305 text: " + decryptedText.toHex());
```

#### XSalsa20Poly1305

```haxe
   var key = Bytes.ofHex("822bca3c7e05fde0dc204519730b35f81216a9c9f1df9525e2a900ec89718f57");
   var iv = Bytes.ofHex("72b90208d2800e36ad16c730941a038d7c3ad9d87030d329");
   var plaintext = Bytes.alloc(0);
   var expected = Bytes.ofHex("79b34551ed224fa17cb6460ccb90a0d9");
   var cipher = new XSalsa20Poly1305();
   var result = cipher.encrypt(key, iv, plaintext);
   trace("XSalsa20Poly1305 encrypt: " + result.toHex());
   var decrypted = cipher.decrypt(key, iv, result);
   trace("XSalsa20Poly1305 text: " + decryptedText.toHex());
```

#### Blake2b

```haxe
   var input = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var hash = Blake2b.hash(input);
   trace("Blake2b hash: "+hash.toHex());
```

#### Blake2s

```haxe
   var input = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var hash = Blake2s.hash(input);
   trace("Blake2s hash: "+hash.toHex());
```

#### Blake3

```haxe
   var input = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var key = "whats the Elvish word for friend";
   var keyHash = Bytes.ofString(key);
   
   var hash = Blake3.hash(input);
   trace("Blake3 hash: "+hash.toHex());
   
   var hash = Blake3.keyedHash(keyHash,input);
   trace("Blake3 keyd hash: "+hash.toHex());
   
   var hash = Blake3.deriveKey(key,input);
   trace("Blake3 derive key hash: "+hash.toHex());
   
```

#### Argon2i

```haxe
   var password:Bytes = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var salt = Bytes.ofString("somesalt");
   var hash = Argon2i.hash(password, salt, 3, 32, 4, 32);
   trace("Argon2i hash: "+hash.toHex());
```

#### Argon2d

```haxe
   var password:Bytes = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var salt = Bytes.ofString("somesalt");
   var hash = Argon2d.hash(password, salt, 3, 32, 4, 32);
   trace("Argon2i hash: "+hash.toHex());
```

#### Argon2id

```haxe
   var password:Bytes = Bytes.ofString("Haxe - The Cross-platform Toolkit");
   var salt = Bytes.ofString("somesalt");
   var hash = Argon2id.hash(password, salt, 3, 32, 4, 32);
   trace("Argon2id hash: "+hash.toHex());
```

#### AesCtrDrbg

```haxe
   // AES128
   var entropy = Bytes.ofHex("6b098f314b9f95c3a7bb2597182b30483f2194fa4d2142b11d3f46cd94a0fed4");
   var personalization = Bytes.ofHex("5536b0e31db780144ab7f5e6c2255884a84b6df99477039939e26c77bf28470d");
   var drbg = new AesCtrDrbg(AES128, false);
   drbg.init(entropy, personalization);
   var output = drbg.generate(32);
   
   // AES192 with derivation
   var entropy = Bytes.ofHex("c4f088cc369b2c227667e82978f34d2678d1a53de1f056556195e02670bae3bedb2ff0ca0f7a0549");
   var reseedEntropy = Bytes.ofHex("1f37e780fb27d743c52de9bb71d4ddca743900154a8d4622");
   var aad = Bytes.ofHex("5f059ab2c47e54f7735d850d49230696d52238c6ab28f2b11994545389350f78");
   var drbg = new AesCtrDrbg(AES192, true);
   drbg.init(entropy);
   drbg.reseed(reseedEntropy, aad);
   var output = drbg.generate(16);
   
   // AES256
   var entropy = Bytes.ofHex("7bc5d970186b9e1b0052b7564dbabf61c89cb3d64ff42f9a62d625112aca0486cdf0336c3612254b40cbfba83ab65b42");
   var personalization = Bytes.ofHex("a25326fef30f9c94423d99759a1ee575536a9715df9526de9a0b8dbcc3a2234cd835615f5dfe7823927355f569ec6f02");
   var reseedEntropy = Bytes.ofHex("ef8a0137013be212402e42b28c03ed6420881aa38b3a3e6e90a861116516df1ef732a19e8935ffcd9be7a2fc236783b7");
   var aad = Bytes.ofHex("6afcdc760fe62b080f141886b516623971f8014ede86e50d62d307a90cf3512da5fefd37b3932d3d9d86ad0c03447be4");
   var aad1 = Bytes.ofHex("72105702fbf1da4c10ff087b02db764804963fd986de933b757b8fe5a6016e0f2700573925aced85c09e2ad9f9f7b2c2");
   var aad2 = Bytes.ofHex("65f9a3fe4e1953b7d538f6d6ca3c0a73bda2276fe8f80860c07b7ed139d748c3c45db5d96598f77ff863a43977ba390c");
   var drbg = new AesCtrDrbg(AES256, false);
   drbg.init(entropy, personalization);
   drbg.reseed(reseedEntropy, aad);
   var output = drbg.generate(64, aad1);
   var output2 = drbg.generate(48, aad2);
```

#### SecureRandom

```haxe
   var randomInt = SecureRandom.int();
   var randomBytes = SecureRandom.bytes(16);
   var randomFloat = SecureRandom.float();
   var range = SecureRandom.range(0,100);
   var gBool = SecureRandom.bool();
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
