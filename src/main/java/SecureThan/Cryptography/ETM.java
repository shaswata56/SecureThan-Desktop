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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;

/**
 *
 * @author shaswata56
 */
public class ETM {

    private final AES aes;
    private final HMAC hmac;

    public ETM (AES aes, HMAC hmac) {
        this.aes = aes;
        this.hmac = hmac;
    }

    private byte[] concatByteArray (byte[] array1, byte[] array2) {
        byte[] finalByteArray = new byte[array1.length + array2.length];

        System.arraycopy(array1, 0, finalByteArray, 0, array1.length);
        System.arraycopy(array2, 0, finalByteArray, array1.length, array2.length);

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

    public byte[] encrypt (byte[] plainText) {
        byte[] encrypted = aes.encrypt(plainText);
        byte[] hashed = hmac.getMAC(encrypted);
        return concatByteArray(hashed, encrypted);
    }

    public String decrypt (byte[] cipherText) {
        int hmacLen = 64;
        byte[] hmacByte = new byte[hmacLen];
        byte[] encrypted = new byte[cipherText.length - hmacLen];
        String displayable = "";
        byte[] decrypted;

        System.arraycopy(cipherText, 0, hmacByte, 0, hmacLen);
        System.arraycopy(cipherText, hmacLen, encrypted, 0, cipherText.length - hmacLen);

        boolean untouched = hmac.checkMAC(encrypted, hmacByte);

        if (untouched) {
            String fileName;
            decrypted = aes.decrypt(encrypted);
            int signLen = 2;
            byte[] signature = new byte[signLen];
            byte[] byteString = new byte[decrypted.length - signLen];

            System.arraycopy(decrypted, 0, signature, 0, signLen);

            if (Arrays.equals(signature, "s:".getBytes())) {
                System.arraycopy(decrypted, signLen, byteString, 0, byteString.length);
                displayable = new String(byteString) + "\n";
            } else if (Arrays.equals(signature, "f:".getBytes())) {
                int nameLen = 0;
                
                for (int i = signLen; i < decrypted.length; i++) {
                    if (decrypted[i] == ":".getBytes()[0]) {
                        nameLen = i - signLen;
                        break;
                    }
                }

                byte[] nameBytes = new byte[nameLen];
                System.arraycopy(decrypted, signLen, nameBytes, 0, nameLen);
                fileName = new String(nameBytes);
                displayable = fileName + "saved to Downloads folder!\n";

                byte[] fileBytes = new byte[decrypted.length - signLen - nameLen];
                System.arraycopy(decrypted, signLen + nameLen, fileBytes, 0, fileBytes.length);

                try (FileOutputStream fileOutputStream = new FileOutputStream(System.getProperty("user.home") + "/Downloads/" + fileName)) {
                    fileOutputStream.write(fileBytes);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        } else {
            displayable ="THIS IS AN ATTEMPT FOR DATA MODIFICATION. PLEASE USE A DIFFERENT SERVER OR USE USERNAME HARD TO GUESS!\n";
        }

        return displayable;
    }
}
