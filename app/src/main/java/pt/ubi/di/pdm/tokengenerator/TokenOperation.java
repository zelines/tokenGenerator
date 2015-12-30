package pt.ubi.di.pdm.tokengenerator;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Created by jo on 12/30/15.
 */
public class TokenOperation {

    //Gerar uma string aleatoria

    public static String genarateSecToken(){
        //  SecretKey secretKey;
        String secret=null;

        // Generate a 256-bit key
        final int outputKeyLength = 256;
        SecureRandom secureRandom = new SecureRandom();

        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        keyGenerator.init(outputKeyLength, secureRandom);
        SecretKey key = keyGenerator.generateKey();
        if (key != null) {secret = Base64.encodeToString(key.getEncoded(), Base64.DEFAULT);}
        return secret;
    }


    //Create rsa keyPair

    public static KeyPair createKeyPair() {
        KeyPair keyPair = null;

        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(1024);
            keyPair = keygen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        return keyPair;
    }


    //Send Keypair to data base

    public static boolean Sendkeytodb(KeyPair key){

        //encode pub and private to string
        String pri = Base64.encodeToString(key.getPrivate().getEncoded(), Base64.DEFAULT);
        String pub = Base64.encodeToString(key.getPublic().getEncoded(), Base64.DEFAULT);

        return true;
    }

    public static String getDigitalSignature(String text, String strPrivateKey)  {

        try {

            // Get private key from String
            PrivateKey pk = loadPrivateKey(strPrivateKey);

            // text to bytes
            byte[] data = text.getBytes("UTF8");

            // signature
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(pk);

            sig.update(data);
            byte[] signatureBytes = sig.sign();

            return Base64.encodeToString(signatureBytes,Base64.DEFAULT);

        }catch(Exception e){
            return null;
        }

    }

    public static boolean verfiySignature(String signature, String original, String publicKey){

        try{

            // Get private key from String
            PublicKey pk = loadPublicKey(publicKey);

            // text to bytes
            byte[] originalBytes = original.getBytes("UTF8");


            byte[] signatureBytes =Base64.decode(signature,Base64.DEFAULT);

            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(pk);
            sig.update(originalBytes);

            return sig.verify(signatureBytes);

        }catch(Exception e){
            e.printStackTrace();
           /* Logger log = Logger.getLogger(RsaCipher.class);
            log.error("error for signature:" + e.getMessage());*/
            return false;
        }

    }

    public static PrivateKey loadPrivateKey(String key64) throws GeneralSecurityException {
        byte[] clear = new byte[0];
        try {
            clear = Base64.decode(key64.getBytes("utf-8"), Base64.DEFAULT);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey priv = fact.generatePrivate(keySpec);
        Arrays.fill(clear, (byte) 0);
        return priv;
    }

    public static PublicKey loadPublicKey(String key64) throws GeneralSecurityException {
        byte[] data = new byte[0];
        try {
            data = Base64.decode(key64.getBytes("utf-8"), Base64.DEFAULT);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }

}
