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
package SecureThan.Client;

import SecureThan.Cryptography.AESKeyGen;
import SecureThan.Cryptography.RSA;
import SecureThan.Cryptography.RSAKeyGen;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Base64;
import javax.swing.JTextArea;

/**
 *
 * @author shaswata56
 */
public class Manager extends Thread {
    
    private Socket client;
    private final int PORT = 5656;
    private DataOutputStream dataOutputStream;
    private DataInputStream dataInputStream;
    private String serverAddress;
    private boolean connected;
    private boolean kill;
    private boolean connection;
    private boolean exchanged;
    private JTextArea jTextArea;
    private PublicKey publicKey;
    private AESKeyGen psk;
    private RSAKeyGen keyGen;
    private RSA rsaUtil;
    
    Manager(String host, JTextArea jTextArea) {
        serverAddress = host;
        connected = false;
        kill = false;
        connection = false;
        exchanged = false;
        this.jTextArea = jTextArea;
    }
    
    @Override
    public void run() {
        try {
            while (!kill) {
                try {
                    keyGen = new RSAKeyGen();
                    psk = new AESKeyGen();
                    client = new Socket(serverAddress, PORT);
                } catch(IOException e) {
                    throw new RuntimeException(e);
                } finally {
                    if (client.isConnected())
                        break;
                }
            }
            
            if (!kill) {
                connected = true;
                rsaUtil = new RSA(keyGen);
                dataOutputStream = new DataOutputStream(client.getOutputStream());
                dataInputStream = new DataInputStream(client.getInputStream());
            }
            
            while (!kill) {
                try {
                    String[] word;
                    
                    if (exchanged) {
                        String out = rsaUtil.decrypt(dataInputStream.readUTF());
                        jTextArea.append(out);
                        word = out.split(":");
                    } else {
                        byte[] out = Base64.getEncoder().encode(rsaUtil.getPublicKey().getEncoded());
                        dataOutputStream.write(out);
                        dataInputStream.readFully(out);
                        publicKey = rsaUtil.decodePublicKey(Base64.getDecoder().decode(out));
                        jTextArea.append(Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n");
                        
                    }
                }
            }
        }
    }
}
