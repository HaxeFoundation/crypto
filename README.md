# Crypto
[![TravisCI Build Status](https://travis-ci.org/HaxeFoundation/crypto.svg?branch=master)](https://travis-ci.org/HaxeFoundation/crypto)
[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/github/HaxeFoundation/crypto?branch=master&svg=true)](https://ci.appveyor.com/project/HaxeFoundation/crypto)

Cross platform cryptographic functions for Haxe



### Supported algorithms
  * Aes
  * Blowfish
  * Twofish
  * TripleDes
  * BCrypt
  * Hmac
  * Sha224
  * Sha256
  * Sha384
  * Sha512
  * Ripemd-160
  * PBKDF2
  * Salsa20
  * XSalsa20
  * ChaCha
  
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