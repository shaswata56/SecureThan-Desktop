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

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author shaswata56
 */
public class RSA {

    private final PublicKey publicKey;
    private final  PrivateKey privateKey;

    public RSA(RSAKeyGen keyGen) {
            publicKey = keyGen.keyPair.getPublic();
            privateKey = keyGen.keyPair.getPrivate();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String encrypt(String text, PublicKey key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(text.getBytes()));
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException
                | BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } finally {
            return "";
        }
    }

    public String decrypt(String text) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(text)));
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeyException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } finally {
            return "";
        }
    }

    public PublicKey decodePublicKey(byte[] stored)
    {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(stored);
        KeyFactory fact = null;
        try {
            fact = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            assert fact != null;
            return fact.generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } finally {
            return null;
        }
    }
}
