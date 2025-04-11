# trabalho de calvette

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESCryptoExample {

    public static void main(String[] args) throws Exception {
        String textoOriginal = "Olá, mundo! Isso é um teste de criptografia AES.";

        // Gerar uma chave AES (128, 192 ou 256 bits)
        SecretKey chave = gerarChaveAES(128); // 128 bits

        // Gerar um IV (Initialization Vector) aleatório
        byte[] iv = gerarIV();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Criptografar
        byte[] textoCriptografado = criptografar(textoOriginal, chave, ivSpec);
        System.out.println("Texto criptografado (Base64): " + Base64.getEncoder().encodeToString(textoCriptografado));

        // Descriptografar
        String textoDescriptografado = descriptografar(textoCriptografado, chave, ivSpec);
        System.out.println("Texto descriptografado: " + textoDescriptografado);
    }

    // Gerar uma chave AES
    public static SecretKey gerarChaveAES(int tamanho) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(tamanho); // 128, 192 ou 256 bits
        return keyGen.generateKey();
    }

    // Gerar um IV aleatório (16 bytes para AES)
    public static byte[] gerarIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // Criptografar
    public static byte[] criptografar(String texto, SecretKey chave, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, chave, iv);
        return cipher.doFinal(texto.getBytes());
    }

    // Descriptografar
    public static String descriptografar(byte[] textoCriptografado, SecretKey chave, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, chave, iv);
        byte[] textoDescriptografado = cipher.doFinal(textoCriptografado);
        return new String(textoDescriptografado);
    }
}