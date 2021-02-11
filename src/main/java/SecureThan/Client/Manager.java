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

import SecureThan.Cryptography.*;
import SecureThan.Hashing.SHA3;

import javax.swing.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 *
 * @author shaswata56
 */
public class Manager extends Thread {
    
    private Socket client;
    private final int PORT = 5656;
    private DataOutputStream dataOutputStream;
    private DataInputStream dataInputStream;
    private final String serverAddress;
    private final String peerName;
    private final String userName;
    private boolean connected;
    private boolean kill;
    private boolean exchanged;
    private boolean authenticated;
    private final JTextArea jTextArea;
    private ETM etm;
    private HMAC mac;
    private AESKeyGen psk;
    private RSAKeyGen keyGen;
    private RSA rsaUtil;
    private AES aes;
    private SHA3 sha3;
    
    Manager(String host, String peerName, String userName, JTextArea jTextArea) {
        serverAddress = host;
        connected = false;
        kill = false;
        exchanged = false;
        this.userName = userName;
        this.peerName = peerName;
        this.jTextArea = jTextArea;
    }
    
    @Override
    public void run() {
        try {
            while (!kill) {
                keyGen = new RSAKeyGen();
                psk = new AESKeyGen();
                mac = new HMAC();
                sha3 = new SHA3();

                try {
                    client = new Socket(serverAddress, PORT);
                } catch(IOException e) {
                    throw new RuntimeException(e);
                }

                if (client.isConnected())
                    break;
            }
            
            if (!kill) {
                connected = true;
                rsaUtil = new RSA(keyGen);
                aes = new AES(psk);
                etm = new ETM(aes, mac, rsaUtil, userName, peerName);
                dataOutputStream = new DataOutputStream(client.getOutputStream());
                dataInputStream = new DataInputStream(client.getInputStream());
            }
            
            while (!kill) {
                try {
                    if (exchanged) {
                        String input = dataInputStream.readUTF();
                        String out = etm.decrypt(input);
                        jTextArea.append(out);
                    } else {
                        if (authenticated) {
                            String out = Base64.getEncoder().encodeToString(rsaUtil.getPublicKey().getEncoded());
                            dataOutputStream.writeUTF(out);
                            String key = dataInputStream.readUTF();
                            rsaUtil.setPeerKey(Base64.getDecoder().decode(key));

                            dataOutputStream.writeUTF(etm.getEncodedCredentials());
                            String peerCredential = dataInputStream.readUTF();
                            etm.setEncodedCredentials(peerCredential);

                            jTextArea.append("\nKey Exchanged!\nAll communication is now end-to-end encrypted!\n");
                            exchanged = true;
                        } else {
                            byte[] hashName = etm.concatByteArray(sha3.getHashed(userName), sha3.getHashed(peerName));
                            byte[] ackBytes = "OK".getBytes();
                            byte[] receivedBytes = new byte[ackBytes.length];
                            dataOutputStream.write(hashName);
                            dataInputStream.readFully(receivedBytes);

                            if (Arrays.equals(ackBytes, receivedBytes)) {
                                jTextArea.append("Connected to the server!\nWaiting for "+ peerName + "!\n");
                            }

                            dataInputStream.readFully(receivedBytes);
                            if (Arrays.equals(receivedBytes, "ON".getBytes())) {
                                jTextArea.append("Connected to "+ peerName + "!");
                                authenticated = true;
                            }
                        }
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    void sendMessage (String text) {
        if (connected) {
            byte[] encryptedMessage = etm.encryptString(text);
            try {
                dataOutputStream.writeUTF(new String(encryptedMessage));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    void sendFile (File f) {
        if (connected) {
            byte[] encryptedMessage = etm.encryptFile(f);
            try {
                dataOutputStream.write(encryptedMessage);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    void setKill() {
        kill = true;
    }
}
