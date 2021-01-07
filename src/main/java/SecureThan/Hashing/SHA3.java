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
package SecureThan.Hashing;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author shaswata56
 */
public class SHA3 {
    
    private final MessageDigest sha3;

    public SHA3() {
        try {
            sha3 = MessageDigest.getInstance("SHA3-512");
        } catch(NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    public String getHashed(String text) {
        byte[] hashByte = sha3.digest(text.getBytes());
        BigInteger bigInt = new BigInteger(1, hashByte);
        StringBuilder hexStr = new StringBuilder(bigInt.toString(16));
        
        while (hexStr.length() < 32)
            hexStr.insert(0, "0");
        
        return hexStr.toString();
    }
}