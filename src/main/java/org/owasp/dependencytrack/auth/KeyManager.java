/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.auth;

import org.owasp.dependencytrack.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyManager {

    private static final Logger logger = Logger.getLogger(KeyManager.class);
    private static final KeyManager instance = new KeyManager();
    private KeyPair keyPair;
    private SecretKey secretKey;

    private KeyManager() {
        initialize();
    }

    public static KeyManager getInstance() {
        return instance;
    }

    private void initialize() {
        if (keyPair == null) {
            try {
                loadKeyPair();
            } catch (IOException | NoSuchAlgorithmException |InvalidKeySpecException e) {
                logger.error("An error occurred loading key pair");
                logger.error(e.getMessage());
            }
        }
        if (secretKey == null) {
            try {
                loadSecretKey();
            } catch (IOException | ClassNotFoundException e) {
                logger.error("An error occurred loading secret key");
                logger.error(e.getMessage());
            }
        }
    }

    /**
     * Generates a key pair
     */
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        logger.info("Generating new key pair");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(4096, random);
        return keyGen.generateKeyPair();
    }

    public SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.init(256, random);
        return keyGen.generateKey();
    }

    private File getKeyPath(String keyType) {
        return new File(
                System.getProperty("user.home") + File.separator +
                        ".dependency-track" + File.separator +
                        "keys" + File.separator +
                        keyType + ".key");
    }

    private File getKeyPath(Key key) {
        String keyType = null;
        if (key instanceof PrivateKey) {
            keyType = "private";
        } else if (key instanceof PublicKey) {
            keyType = "public";
        } else if (key instanceof SecretKey) {
            keyType = "secret";
        }
        return getKeyPath(keyType);
    }

    /**
     * Saves a key pair
     */
    public void save(KeyPair keyPair) throws IOException {
        logger.info("Saving key pair");
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key
        File publicKeyFile = getKeyPath(publicKey);
        publicKeyFile.getParentFile().mkdirs(); // make directories if they do not exist
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(publicKeyFile);
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        File privateKeyFile = getKeyPath(privateKey);
        privateKeyFile.getParentFile().mkdirs(); // make directories if they do not exist
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        fos = new FileOutputStream(privateKeyFile);
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

    /**
     * Saves a secret key
     */
    public void save(SecretKey key) throws IOException {
        File keyFile = getKeyPath(key);
        keyFile.getParentFile().mkdirs(); // make directories if they do not exist
        FileOutputStream fos = new FileOutputStream(keyFile);
        ObjectOutputStream oout = new ObjectOutputStream(fos);
        oout.writeObject(key);
        oout.close();
    }

    /**
     * Loads a key pair
     */
    private KeyPair loadKeyPair() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Private Key
        File filePrivateKey = getKeyPath("private");
        FileInputStream pvtfis = new FileInputStream(filePrivateKey);
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        pvtfis.read(encodedPrivateKey);
        pvtfis.close();

        // Read Public Key
        File filePublicKey = getKeyPath("public");
        FileInputStream pubfis = new FileInputStream(filePublicKey);
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        pubfis.read(encodedPublicKey);
        pubfis.close();

        // Generate KeyPair
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return this.keyPair = new KeyPair(publicKey, privateKey);
    }

    private SecretKey loadSecretKey() throws IOException, ClassNotFoundException {
        File file = getKeyPath("secret");
        FileInputStream fis = new FileInputStream(file);
        SecretKey key;
        ObjectInputStream oin = new ObjectInputStream(fis);
        key = (SecretKey) oin.readObject();
        oin.close();
        return this.secretKey = key;
    }

    /**
     * Checks to see if the key pair exists. Both (public and private) need to exist to return true
     */
    public boolean keyPairExists() {
        return (getKeyPath("public").exists() && getKeyPath("private").exists());
    }

    /**
     * Checks to see if the secret key exists.
     */
    public boolean secretKeyExists() {
        return getKeyPath("secret").exists();
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public PublicKey getPublicKey() {
        return (keyPair != null) ? keyPair.getPublic() : null;
    }

    public PrivateKey getPrivateKey() {
        return (keyPair != null) ? keyPair.getPrivate() : null;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

}
