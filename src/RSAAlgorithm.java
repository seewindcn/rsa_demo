

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.Base64;



public class RSAAlgorithm {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String loadKey(String fileName) {
        File file = new File(fileName);
        String result = "";
        try {
            BufferedReader  ir = new BufferedReader(new FileReader(file));
            String s = null;
            while ((s = ir.readLine()) != null) {
                result = result + s + "\n";
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    private static byte[] getPemContent(String pemFormatKey) throws Exception {
        PemReader pemReader = new PemReader(new InputStreamReader(
                new ByteArrayInputStream(pemFormatKey.getBytes("UTF-8"))));
        PemObject pemObject = pemReader.readPemObject();
        byte[] content = pemObject.getContent();
        return content;
    }

    public static String byteArrayToHexStr(byte[] byteArray) {
        if (byteArray == null){
            return null;
        }
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int v = byteArray[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        String rs = new String(hexChars);
        return rs.toLowerCase();
    }

    public static byte[] getHash(String plainText) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(plainText.getBytes("UTF-8"));
        return encodedhash;
    }

    public static PrivateKey getPrivateKey(String pemFormatKey) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        byte[] content = getPemContent(pemFormatKey);
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
        return factory.generatePrivate(privKeySpec);
    }

    public static PublicKey getPublicKey(String pemFormatKey) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        byte[] content = getPemContent(pemFormatKey);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
        return factory.generatePublic(pubKeySpec);
    }

    private static Signature getSignature() throws Exception{
        Signature sign = Signature.getInstance("SHA256withRSA/PSS");
//        AlgorithmParameters pss = sign.getParameters();
        PSSParameterSpec spec = new PSSParameterSpec("SHA-256", "MGF1",
                MGF1ParameterSpec.SHA256, 32, 1);
//                new MGF1ParameterSpec("SHA-256"), 11, 1);
        sign.setParameter(spec);
        return sign;
    }

    public static String signPSS(String plainText) throws Exception {
        Signature privateSignature = getSignature();
        String prikey = loadKey("key/id_rsa");
        PrivateKey privateKey = getPrivateKey(prikey);
        privateSignature.initSign(privateKey);
//        privateSignature.update(getHash(plainText));
        privateSignature.update(plainText.getBytes("UTF-8"));

        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verifyPSS(String plainText, String signature) throws Exception {
        Signature publicSignature = getSignature();
        String pubkey = loadKey("key/id_rsa.pub");
        PublicKey publicKey = getPublicKey(pubkey);
        publicSignature.initVerify(publicKey);
//        publicSignature.update(getHash(plainText));
        publicSignature.update(plainText.getBytes("UTF-8"));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static String generateSign(String formatStr) throws Exception {
        String signature = signPSS(formatStr);
        return signature;
    }

    public static boolean verifySign(String formatStr, String sign) throws Exception {
        return verifyPSS(formatStr, sign);
    }
}