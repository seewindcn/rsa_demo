
public class Main {

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
    }
}
