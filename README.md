# crypto
Cross platform cryptographic functions for Haxe

### Supported algorithms
  * Aes
  * Blowfish
  * TripleDes
  * Hmac
  * Sha224
  * Sha256
  
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

 #### AES
 ```haxe
   var aes : Aes = new Aes();
   var key = Bytes.ofHex("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4");
   var text = Bytes.ofString("Haxe is an open source toolkit based on a modern, high level, strictly typed programming language.");
   var iv:Bytes = Bytes.ofHex("4F021DB243BC633D7178183A9FA071E8");
   var data = aes.encrypt(Mode.CTR,text,Padding.NoPadding);
   trace("Encrypted text: "+ data.toHex());
   data = aes.decrypt(Mode.CTR,data,Padding.NoPadding);
   trace("Decrypted text: "+ data);
 ```
 
  #### Blowfish
 ```haxe
   var blowFish  : BlowFish = new BlowFish();
   var key = Bytes.ofHex("E0FEE0FEF1FEF1FE");
   var text = Bytes.ofString("Haxe is an open source toolkit based on a modern, high level, strictly typed programming language.");
   var iv:Bytes = Bytes.ofHex("7FC38460C9225873");
   var data = blowFish.encrypt(Mode.PCBC,text,Padding.PKCS7);
   trace("Encrypted text: "+ data.toHex());
   data = blowFish.decrypt(Mode.PCBC,data,Padding.PKCS7);
   trace("Decrypted text: "+ data);
 ```
 
  #### Triple DES / 3Des
 ```haxe
   var tdes : TripleDes = new TripleDes();
   var key = Bytes.ofHex("2BD6459F82C5B300952C49104881FF482BD6459F82C5B300");
   var text = Bytes.ofString("Haxe is an open source toolkit based on a modern, high level, strictly typed programming language.");
   var iv:Bytes = Bytes.ofHex("A015E0CFA1FED3B5");
   var data = tdes.encrypt(Mode.OFB,text,Padding.NoPadding);
   trace("Encrypted text: "+ data.toHex());
   data = tdes.decrypt(Mode.OFB,data,Padding.NoPadding);
   trace("Decrypted text: "+ data);
 ```

  
