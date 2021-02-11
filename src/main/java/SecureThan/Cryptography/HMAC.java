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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

/**
 *
 * @author shaswata56
 */
public class HMAC {

    private final Mac macPrivate;
    private Mac macPublic;
    private final byte[] secretPersonal;

    public HMAC () {
        secretPersonal = new byte[128];
        SecureRandom prng = new SecureRandom();
        prng.nextBytes(secretPersonal);

        try {
            String HMAC_SHA512 = "HmacSHA512";
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretPersonal, HMAC_SHA512);
            macPrivate = Mac.getInstance(HMAC_SHA512);
            macPrivate.init(secretKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean checkMAC (byte[] data, byte[] mac) {
        return Arrays.toString(mac).equals(Arrays.toString(macPublic.doFinal(data)));
    }

    public byte[] getMAC (byte[] data) {
        return macPrivate.doFinal(data);
    }

    public void setSecret (byte[] mac) {
        try {
            String HMAC_SHA512 = "HmacSHA512";
            SecretKeySpec secretKeySpec = new SecretKeySpec(mac, HMAC_SHA512);
            macPublic = Mac.getInstance(HMAC_SHA512);
            macPublic.init(secretKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] getSecret () {
        return secretPersonal;
    }
}
