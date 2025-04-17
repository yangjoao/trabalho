# trabalho de calvette





# Criptografia Simétrica em Java

A criptografia simétrica usa a mesma chave para cifrar e decifrar dados. Em Java, você pode implementá-la usando as classes do pacote `javax.crypto`.

## Algoritmos comuns de criptografia simétrica

- AES (Advanced Encryption Standard) - recomendado
- DES (Data Encryption Standard) - inseguro, não recomendado
- 3DES (Triple DES) - ainda aceitável, mas sendo substituído por AES

## Implementação básica com AES

```java
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class CriptografiaSimetrica {
    
    // Tamanho da chave (128, 192 ou 256 bits)
    private static final int TAMANHO_CHAVE = 256;
    private static final String ALGORITMO = "AES";
    private static final String TRANSFORMACAO = "AES/CBC/PKCS5Padding";
    
    public static void main(String[] args) throws Exception {
        String textoOriginal = "Este é um texto secreto!";
        
        // Gerar chave
        SecretKey chave = gerarChave();
        
        // Gerar IV (Initialization Vector)
        byte[] iv = gerarIV();
        
        // Cifrar
        byte[] textoCifrado = cifrar(textoOriginal, chave, iv);
        String textoCifradoBase64 = Base64.getEncoder().encodeToString(textoCifrado);
        System.out.println("Texto cifrado: " + textoCifradoBase64);
        
        // Decifrar
        String textoDecifrado = decifrar(textoCifrado, chave, iv);
        System.out.println("Texto decifrado: " + textoDecifrado);
    }
    
    public static SecretKey gerarChave() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITMO);
        keyGen.init(TAMANHO_CHAVE);
        return keyGen.generateKey();
    }
    
    public static byte[] gerarIV() {
        byte[] iv = new byte[16]; // 16 bytes para AES
        new SecureRandom().nextBytes(iv);
        return iv;
    }
    
    public static byte[] cifrar(String texto, SecretKey chave, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMACAO);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, chave, ivSpec);
        return cipher.doFinal(texto.getBytes());
    }
    
    public static String decifrar(byte[] textoCifrado, SecretKey chave, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMACAO);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, chave, ivSpec);
        byte[] textoDecifrado = cipher.doFinal(textoCifrado);
        return new String(textoDecifrado);
    }
}
```

## Armazenando e recuperando chaves

Para armazenar a chave de forma segura:

```java
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import javax.crypto.spec.SecretKeySpec;

public class ArmazenamentoChave {
    public static void salvarChave(SecretKey chave, String arquivo) throws Exception {
        byte[] chaveBytes = chave.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(arquivo)) {
            fos.write(chaveBytes);
        }
    }
    
    public static SecretKey carregarChave(String arquivo, String algoritmo) throws Exception {
        File file = new File(arquivo);
        byte[] chaveBytes = new byte[(int) file.length()];
        
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(chaveBytes);
        }
        
        return new SecretKeySpec(chaveBytes, algoritmo);
    }
}
```

## Usando uma chave a partir de uma senha (PBKDF2)

Para derivar uma chave segura a partir de uma senha:

```java
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;

public class DerivaChave {
    public static SecretKey derivarChave(String senha, byte[] salt) throws Exception {
        // Parâmetros para PBKDF2
        int iteracoes = 65536;
        int tamanhoChave = 256; // bits
        
        // Deriva a chave
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(senha.toCharArray(), salt, iteracoes, tamanhoChave);
        byte[] chaveDerivada = factory.generateSecret(spec).getEncoded();
        
        return new SecretKeySpec(chaveDerivada, "AES");
    }
}
```


# Criptografia Assimétrica em Java

A criptografia assimétrica (ou de chave pública) utiliza um par de chaves: uma pública (para cifrar) e uma privada (para decifrar). Em Java, isso é implementado principalmente com as classes do pacote `java.security`.

## Algoritmos comuns

- **RSA** (mais utilizado)
- **ECDSA** (para assinaturas digitais)
- **ElGamal** (menos comum)

## Implementação básica com RSA

```java
import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class CriptografiaAssimetrica {
    
    public static void main(String[] args) throws Exception {
        // Gerar par de chaves
        KeyPair parChaves = gerarParChavesRSA(2048);
        
        String mensagemOriginal = "Mensagem secreta para criptografia assimétrica";
        System.out.println("Original: " + mensagemOriginal);
        
        // Cifrar com chave pública
        byte[] mensagemCifrada = cifrar(mensagemOriginal, parChaves.getPublic());
        String mensagemCifradaBase64 = Base64.getEncoder().encodeToString(mensagemCifrada);
        System.out.println("Cifrada: " + mensagemCifradaBase64);
        
        // Decifrar com chave privada
        String mensagemDecifrada = decifrar(mensagemCifrada, parChaves.getPrivate());
        System.out.println("Decifrada: " + mensagemDecifrada);
    }
    
    public static KeyPair gerarParChavesRSA(int tamanhoChave) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(tamanhoChave);
        return keyPairGenerator.generateKeyPair();
    }
    
    public static byte[] cifrar(String mensagem, PublicKey chavePublica) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, chavePublica);
        return cipher.doFinal(mensagem.getBytes());
    }
    
    public static String decifrar(byte[] mensagemCifrada, PrivateKey chavePrivada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, chavePrivada);
        byte[] bytesDecifrados = cipher.doFinal(mensagemCifrada);
        return new String(bytesDecifrados);
    }
}
```

## Assinatura Digital

```java
import java.security.*;
import java.util.Base64;

public class AssinaturaDigital {
    
    public static void main(String[] args) throws Exception {
        // Gerar par de chaves
        KeyPair parChaves = gerarParChavesRSA(2048);
        
        String documento = "Documento importante que precisa ser assinado";
        
        // Assinar
        byte[] assinatura = assinar(documento, parChaves.getPrivate());
        String assinaturaBase64 = Base64.getEncoder().encodeToString(assinatura);
        System.out.println("Assinatura: " + assinaturaBase64);
        
        // Verificar
        boolean valido = verificar(documento, assinatura, parChaves.getPublic());
        System.out.println("Assinatura válida? " + valido);
    }
    
    public static byte[] assinar(String dados, PrivateKey chavePrivada) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(chavePrivada);
        signature.update(dados.getBytes());
        return signature.sign();
    }
    
    public static boolean verificar(String dados, byte[] assinatura, PublicKey chavePublica) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(chavePublica);
        signature.update(dados.getBytes());
        return signature.verify(assinatura);
    }
    
    public static KeyPair gerarParChavesRSA(int tamanhoChave) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(tamanhoChave);
        return keyPairGenerator.generateKeyPair();
    }
}
```

## Troca de Chaves (Diffie-Hellman)

```java
import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class TrocaChavesDiffieHellman {
    
    public static void main(String[] args) throws Exception {
        // Alice gera seu par de chaves
        KeyPairGenerator keyGenAlice = KeyPairGenerator.getInstance("DH");
        keyGenAlice.initialize(2048);
        KeyPair parChavesAlice = keyGenAlice.generateKeyPair();
        
        // Bob gera seu par de chaves
        KeyPairGenerator keyGenBob = KeyPairGenerator.getInstance("DH");
        keyGenBob.initialize(2048);
        KeyPair parChavesBob = keyGenBob.generateKeyPair();
        
        // Alice recebe a chave pública de Bob e gera o segredo compartilhado
        byte[] segredoAlice = gerarSegredoCompartilhado(
            parChavesAlice.getPrivate(), 
            parChavesBob.getPublic()
        );
        
        // Bob recebe a chave pública de Alice e gera o segredo compartilhado
        byte[] segredoBob = gerarSegredoCompartilhado(
  