/*
 * Copyright (C) 2021 shaswata56
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package SecureThan.Cryptography;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 *
 * @author shaswata56
 */
public class AES {

    private final SecretKeySpec encryptionKey;
    private SecretKeySpec decryptionKey;
    private final SecureRandom prng;
    private final Cipher cipher;
    private final Cipher decipher;
    private final int ivSize = 16;

    public AES (AESKeyGen keyGen) {
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        byte[] encodedKey = Base64.getDecoder().decode(keyGen.getKey());
        encryptionKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        prng = new SecureRandom();
    }

    public void setDecryptionKey (byte[] key) {
        byte[] encodedKey = Base64.getDecoder().decode(key);
        decryptionKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
    }

    public byte[] encrypt (byte[] plainText) {
        byte[] IV = new byte[ivSize];
        prng.nextBytes(IV);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        byte[] encrypted;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivParameterSpec);
            encrypted = cipher.doFinal(plainText);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }

        byte[] encryptedWithIv = new byte[ivSize + encrypted.length];
        System.arraycopy(IV, 0, encryptedWithIv, 0, ivSize);
        System.arraycopy(encrypted, 0, encryptedWithIv, ivSize, encrypted.length);

        return encryptedWithIv;
    }

    public byte[] decrypt (byte[] cipherText) {
        byte[] IV = new byte[ivSize];
        System.arraycopy(cipherText, 0, IV, 0, ivSize);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        int encryptedSize = cipherText.length - ivSize;
        byte[] encrypted = new byte[encryptedSize];
        System.arraycopy(cipherText, ivSize, encrypted, 0, encryptedSize);

        byte[] decrypted;
        try {
            decipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivParameterSpec);
            decrypted = decipher.doFinal(encrypted);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }

        return decrypted;
    }
}
