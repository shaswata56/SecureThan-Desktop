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

import SecureThan.Hashing.SHA3;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import static java.lang.System.arraycopy;

/**
 *
 * @author shaswata56
 */
public class ETM {

    private final RSA rsa;
    private final AES aes;
    private final HMAC hmac;
    private final String peerName, userName;
    private final int keyLen, macLen, hashLen;

    public ETM (AES aes, HMAC hmac, RSA rsaUtil, String userName, String peerName) {
        rsa = rsaUtil;
        this.aes = aes;
        this.hmac = hmac;
        this.userName = userName;
        this.peerName = peerName;
        keyLen = this.aes.getEncryptionKey().length;
        hashLen = macLen = 64;
    }

    public byte[] concatByteArray (byte[] array1, byte[] array2) {
        byte[] finalByteArray = new byte[array1.length + array2.length];

        arraycopy(array1, 0, finalByteArray, 0, array1.length);
        arraycopy(array2, 0, finalByteArray, array1.length, array2.length);

        return finalByteArray;
    }

    public byte[] encryptString (String text) {
        byte[] sign = "s:".getBytes();
        byte[] textBytes = text.getBytes();
        return encrypt(concatByteArray(sign, textBytes));
    }

    public byte[] encryptFile (File file) {
        byte[] sign = "f:".getBytes();
        byte[] fileBytes;
        try {
            fileBytes = Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return encrypt(concatByteArray(sign, fileBytes));
    }

    private byte[] encrypt (byte[] plainText) {
        byte[] encrypted = aes.encrypt(plainText);
        byte[] hashed = hmac.getMAC(encrypted);
        return concatByteArray(hashed, encrypted);
    }

    public String decrypt (String cText) {
        int hmacLen = macLen;
        byte[] cipherText = cText.getBytes(StandardCharsets.UTF_8);
        System.out.println(hmacLen + cipherText.length);
        System.out.println(hmacLen);
        System.out.println(cipherText.length);

        byte[] hmacByte = new byte[hmacLen];
        byte[] encrypted = new byte[cipherText.length - hmacLen];
        AtomicReference<String> displayable = new AtomicReference<>("");
        byte[] decrypted;

        arraycopy(cipherText, 0, hmacByte, 0, hmacLen);
        arraycopy(cipherText, hmacLen, encrypted, 0, cipherText.length - hmacLen);

        boolean untouched = true;//hmac.checkMAC(encrypted, hmacByte);

        if (untouched) {
            String fileName;
            decrypted = aes.decrypt(encrypted);
            int signLen = 2;
            byte[] signature = new byte[signLen];
            byte[] byteString = new byte[decrypted.length - signLen];

            arraycopy(decrypted, 0, signature, 0, signLen);

            if (Arrays.equals(signature, "s:".getBytes())) {
                arraycopy(decrypted, signLen, byteString, 0, byteString.length);
                displayable.set(peerName + ": " + new String(byteString) + "\n");
            } else if (Arrays.equals(signature, "f:".getBytes())) {
                int nameLen = 0;

                for (int i = signLen; i < decrypted.length; i++) {
                    if (decrypted[i] == ":".getBytes()[0]) {
                        nameLen = i - signLen;
                        break;
                    }
                }

                byte[] nameBytes = new byte[nameLen];
                arraycopy(decrypted, signLen, nameBytes, 0, nameLen);
                fileName = new String(nameBytes);
                displayable.set(fileName + "saved to Downloads folder!\n");

                byte[] fileBytes = new byte[decrypted.length - signLen - nameLen];
                arraycopy(decrypted, signLen + nameLen, fileBytes, 0, fileBytes.length);

                try (FileOutputStream fileOutputStream = new FileOutputStream(System.getProperty("user.home") + "/Downloads/" + fileName)) {
                    fileOutputStream.write(fileBytes);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        } else {
            displayable.set("THIS IS AN ATTEMPT FOR DATA MODIFICATION. PLEASE USE A DIFFERENT SERVER OR USE USERNAME HARD TO GUESS!\n");
        }

        return displayable.get();
    }

    public String getEncodedCredentials () {
        SHA3 sha3 = new SHA3();
        byte[] aesKey = aes.getEncryptionKey();
        byte[] secretMac = hmac.getSecret();
        byte[] keyId = concatByteArray(sha3.getHashed(userName), aesKey);
        return rsa.encrypt(Base64.getEncoder().encodeToString(concatByteArray(secretMac, keyId)));
    }

    public void setEncodedCredentials (String encodedCredentials) {
        String decrypted = rsa.decrypt(encodedCredentials);
        byte[] keyWithHash = decrypted.getBytes(StandardCharsets.UTF_8);
        byte[] peerMAC = new byte[128];
        byte[] peerHash = new byte[hashLen];
        byte[] key = new byte[keyWithHash.length - 128 - hashLen];

        arraycopy(keyWithHash, 0, peerMAC, 0, 128);
        arraycopy(keyWithHash, 128, peerHash, 0, hashLen);
        arraycopy(keyWithHash, 128 + hashLen, key, 0, key.length);
        hmac.setSecret(peerMAC);

        SHA3 sha3 = new SHA3();
        System.out.println(new String(peerHash));
        System.out.println(new String(sha3.getHashed(peerName)));
        System.out.println(peerName);

        if (sha3.getHashed(peerName) == peerHash) {
            aes.setDecryptionKey(key);
            System.out.println("Oki");
        }
    }

}
