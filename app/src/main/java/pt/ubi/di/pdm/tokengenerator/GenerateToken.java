package pt.ubi.di.pdm.tokengenerator;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

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

public class GenerateToken extends AppCompatActivity {
    EditText console;
    TextView console2;
    String s=null;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_generate_token);
        console=(EditText)findViewById(R.id.console);
        console2=(TextView)findViewById(R.id.console2Tv);
    }

/////////////////////////////generate token ////////
    public void genToken(View view) {

        //generateSecToken
        s = genarateSecToken();
            console.setText(s);
        //Signtoken


    }

    public static String genarateSecToken(){
      //  SecretKey secretKey;
        String secret=null;
       /* SecureRandom random = new SecureRandom();
        return new BigInteger(256, random).toString(32);
        */
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

      /*  try {
            secretKey = KeyGenerator.getInstance("AES").generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }*/
        if (key != null) {secret = Base64.encodeToString(key.getEncoded(), Base64.DEFAULT);}
        return secret;
    }


//////////////////////////////////////sign token///////////////////////////////////////
    public void signToken(View view) {
        // Get keys pair (RSA)
        KeyPair rsaKyePair = createKeyPair();


        String pri = Base64.encodeToString(rsaKyePair.getPrivate().getEncoded(), Base64.DEFAULT);
        String pub = Base64.encodeToString(rsaKyePair.getPublic().getEncoded(), Base64.DEFAULT);

      // console2.setText(pri);
        String mySignature = getDigitalSignature(s,pri);

       if(verfiySignature(mySignature,s,pub)){
           console2.setText("verifica");
       }

    }


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

    public static String getPrivateKeyBase64Str(KeyPair keyPair){
        if (keyPair == null) return null;
        return getBase64StrFromByte(keyPair.getPrivate().getEncoded());
    }

    public static String getPublicKeyBase64Str(KeyPair keyPair){
        if (keyPair == null) return null;
        return getBase64StrFromByte(keyPair.getPublic().getEncoded());
    }

    public static String getBase64StrFromByte(byte[] key){
        if (key == null || key.length == 0) return null;
        return new String(Base64.encode(key,Base64.DEFAULT));
    }


    public String getDigitalSignature(String text, String strPrivateKey)  {

        try {

            // Get private key from String
            PrivateKey pk = loadPrivateKey(strPrivateKey);
           /* if(pk != null){
             //   console2.setText(pk.getEncoded().toString());
            }*/


            // text to bytes
            byte[] data = text.getBytes("UTF8");

            // signature
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(pk);

            sig.update(data);
            byte[] signatureBytes = sig.sign();
            if (signatureBytes.length!=0){
                console2.setText( "tem");
            }

            return Base64.encodeToString(signatureBytes,Base64.DEFAULT);

        }catch(Exception e){
            return null;
        }

    }



    private PrivateKey loadPrivateKey(String key64) throws GeneralSecurityException {
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


   ////////////////////////////////////////////////////////// verifySign////////////


    public static boolean verfiySignature(String signature, String original, String publicKey){

        try{

            // Get private key from String
           PublicKey pk = loadPublicKey(publicKey);

            // text to bytes
            byte[] originalBytes = original.getBytes("UTF8");

            //signature to bytes
            //byte[] signatureBytes = signature.getBytes("UTF8");
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


    private static PublicKey loadPublicKey(String key64) throws GeneralSecurityException {
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
