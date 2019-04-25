import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Main {
    public static void genKey() throws Exception {
        KeyPair pair = RSAAlgorithm.genKey(1024);
        PrivateKey pk = pair.getPrivate();
        PublicKey puk = pair.getPublic();
        System.out.println("************private**************");
        System.out.println(pk.getFormat());
        System.out.println(pk.getAlgorithm());
        System.out.println("-----BEGIN RSA PRIVATE KEY-----");
        System.out.println(Base64.getEncoder().encodeToString(pk.getEncoded()));
        System.out.println("-----END RSA PRIVATE KEY-----");

        System.out.println("************public**************");
        System.out.println(puk.getFormat());
        System.out.println(puk.getAlgorithm());
        System.out.println("-----BEGIN PUBLIC KEY-----");
        System.out.println(Base64.getEncoder().encodeToString(puk.getEncoded()));
        System.out.println("-----END PUBLIC KEY-----");
    }

    public static void main(String[] args) throws Exception {
        String plainData = "abc";
        String hash = RSAAlgorithm.byteArrayToHexStr(RSAAlgorithm.getHash(plainData));
        System.out.println("hash: " + hash);
        String signData = RSAAlgorithm.generateSign(plainData);
        System.out.println("sign: " + signData);
        boolean ok = RSAAlgorithm.verifySign(plainData, signData);
        System.out.println("verify: " + ok);

        // verify test
        signData = "jFapEh2LH0O7vwuH1pspUxVfWAIx5RxgwVXe/vkaMWIRL05VTsMf/HGC0QE9zE0XtCfW49QLolqeEDNRBAnc/xuoL7XXz7+K+MDMlB7WYFkgEUmALYCNzChn3VEqcOQP8cWH55rOMI/PKRE/45YS/QARwjPcaNrm0sMdN1AJd6IIu9TG0tHX9a67oTFwzMpoNPCR7JuFJ3xdXBojbSBMjsHUwQbqq4eY6XqGOINl1fJahOVi6ns4z7OoyOALJgfCyNAufNKT6kADsGU9GLwpziQ6WLyhVqFcNn00TGp6lPqNXYXyR7WaFJv+EIAohezllshEY7OuUyRa18TKgSavLw==";
        ok = RSAAlgorithm.verifySign(plainData, signData);
        System.out.println("verify test: " + ok);

        //gen
        genKey();
    }
}
