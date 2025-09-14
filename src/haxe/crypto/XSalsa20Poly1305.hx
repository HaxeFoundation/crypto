package haxe.crypto;

import haxe.io.Bytes;

class XSalsa20Poly1305 {

    public function new() {}

    /**
     * Encrypts plaintext using XSalsa20-Poly1305 authenticated encryption.
     * @param key 32-byte encryption key
     * @param nonce 24-byte nonce
     * @param plaintext Data to encrypt
     * @return Tag (16 bytes) concatenated with ciphertext
     */
    public function encrypt(key:Bytes, nonce:Bytes, plaintext:Bytes):Bytes {
        if (key == null || key.length != 32)
            throw "Key must be 32 bytes";
        if (nonce == null || nonce.length != 24)
            throw "Nonce must be 24 bytes";
        var xsalsa = new XSalsa20();
        var poly1305 = new Poly1305();
        xsalsa.init(key, nonce, 0);
        var input = Bytes.alloc(32 + plaintext.length);
        input.fill(0, 32, 0);
        input.blit(32, plaintext, 0, plaintext.length);
        var output = xsalsa.encrypt(input);
        var poly1305Key = Bytes.alloc(32);
        poly1305Key.blit(0, output, 0, 32);
        var ciphertext = Bytes.alloc(plaintext.length);
        ciphertext.blit(0, output, 32, plaintext.length);
        poly1305.init(poly1305Key);
        poly1305.update(ciphertext, 0, ciphertext.length);
        var tag = poly1305.finish();
        var result = Bytes.alloc(16 + ciphertext.length);
        result.blit(0, tag, 0, 16);
        result.blit(16, ciphertext, 0, ciphertext.length);
        return result;
    }

    /**
     * Decrypts ciphertext using XSalsa20-Poly1305 decryption.
     * @param key 32-byte decryption key
     * @param nonce 24-byte nonce
     * @param ciphertextWithTag Tag + ciphertext data to decrypt
     * @return Plaintext
     * @throws String if authentication fails
     */
    public function decrypt(key:Bytes, nonce:Bytes, ciphertextWithTag:Bytes):Bytes {
        if (key == null || key.length != 32)
            throw "Key must be 32 bytes";
        if (nonce == null || nonce.length != 24)
            throw "Nonce must be 24 bytes";
        if (ciphertextWithTag.length < 16)
            throw "Ciphertext with tag must be at least 16 bytes";
        var xsalsa = new XSalsa20();
        var poly1305 = new Poly1305();
        var tag = Bytes.alloc(16);
        var ciphertextLen = ciphertextWithTag.length - 16;
        var ciphertext = Bytes.alloc(ciphertextLen);
        tag.blit(0, ciphertextWithTag, 0, 16);
        ciphertext.blit(0, ciphertextWithTag, 16, ciphertextLen);
        xsalsa.init(key, nonce, 0);
        var keyInput = Bytes.alloc(32);
        keyInput.fill(0, 32, 0);
        var keyOutput = xsalsa.encrypt(keyInput);
        var poly1305Key = Bytes.alloc(32);
        poly1305Key.blit(0, keyOutput, 0, 32);
        poly1305.init(poly1305Key);
        poly1305.update(ciphertext, 0, ciphertext.length);
        var expectedTag = poly1305.finish();
        if (!constantTimeEquals(tag, expectedTag))
            throw "Authentication failed";
        return xsalsa.encrypt(ciphertext);
    }

    private function constantTimeEquals(a:Bytes, b:Bytes):Bool {
        if (a.length != b.length)
            return false;
        var result = 0;
        for (i in 0...a.length) {
            result |= a.get(i) ^ b.get(i);
        }
        return result == 0;
    }
}