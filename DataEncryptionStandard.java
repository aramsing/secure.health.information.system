/*
Name: Arjun Ramsinghani
Title: Secure Health Information System
Course: CS 4331-001 -- Software Security
 */

package secure.health.information.system;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

/**
 *
 * @author arams
 */
public class DataEncryptionStandard {

    public static void encrypt(String key, InputStream is, OutputStream os) throws Exception {
        secureEncryptDecrypt(key, Cipher.ENCRYPT_MODE, is, os);
    }
    
    public static void decrypt(String key, InputStream is, OutputStream os) throws Exception {
        secureEncryptDecrypt(key, Cipher.DECRYPT_MODE, is, os);
    }
    
    public static void secureEncryptDecrypt(String key, int mode, InputStream is, OutputStream os) throws Exception {
        DESKeySpec dks = new DESKeySpec(key.getBytes());
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey sk = skf.generateSecret(dks);
        Cipher cipher = Cipher.getInstance("DES");
        
        if (mode == Cipher.ENCRYPT_MODE) {
            cipher.init(Cipher.ENCRYPT_MODE, sk);
            CipherInputStream cis = new CipherInputStream(is, cipher);
            makeFile(cis, os);
        }
        
        else if (mode == Cipher.DECRYPT_MODE) {
            cipher.init(Cipher.DECRYPT_MODE, sk);
            CipherOutputStream cos = new CipherOutputStream(os, cipher);
            makeFile(is, cos);
        }
    }
    
    public static void makeFile(InputStream is, OutputStream os) throws IOException {
        byte[] bytes = new byte[64];
        int numBytes;
        
        while ((numBytes = is.read(bytes)) != -1) {
            os.write(bytes, 0, numBytes);
        }
        
        os.flush();
        os.close();
        is.close();
    }
}
