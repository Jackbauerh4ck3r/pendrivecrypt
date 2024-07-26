
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Pendrivecrypt {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Digite o caminho do pendrive:");
        String pendrivePath = scanner.nextLine();

        System.out.println("Digite a senha para criptografar:");
        String senha = scanner.nextLine();

        // Gera a chave de criptografia
        SecretKeySpec chave = geraChave(senha);

        // Verifica se o pendrive existe
        File pendrive = new File(pendrivePath);
        if (!pendrive.exists()) {
            System.out.println("Pendrive não encontrado!");
            return;
        }

        // Criptografa o pendrive
        criptografaPendrive(pendrive, chave);

        // Grava o hash original do pendrive
        byte[] hashOriginal = geraHash(pendrive);

        // Verifica a integridade dos dados criptografados
        verificaIntegridade(pendrive, chave, hashOriginal);
    }

    private static SecretKeySpec geraChave(String senha) {
        try {
            // Gera a chave de criptografia utilizando o algoritmo AES com 256 bits
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(senha.getBytes());
            byte[] chaveBytes = new byte[32];
            System.arraycopy(hash, 0, chaveBytes, 0, 32);
            return new SecretKeySpec(chaveBytes, "AES");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Erro ao gerar chave: " + e.getMessage());
            return null;
        }
    }

    private static byte[] geraHash(File pendrive) {
        try {
            // Gera o hash do pendrive
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            FileInputStream fis = new FileInputStream(pendrive);
            byte[] dados = new byte[(int) pendrive.length()];
            fis.read(dados);
            fis.close();
            return md.digest(dados);
        } catch (Exception e) {
            System.out.println("Erro ao gerar hash: " + e.getMessage());
            return null;
        }
    }

    private static void criptografaPendrive(File pendrive, SecretKeySpec chave) {
        try {
            // Cria um objeto Cipher para criptografar o pendrive
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, chave);

            // Lê o conteúdo do pendrive
            FileInputStream fis = new FileInputStream(pendrive);
            byte[] dados = new byte[(int) pendrive.length()];
            fis.read(dados);
            fis.close();

            // Criptografa o conteúdo do pendrive
            byte[] dadosCriptografados = cipher.doFinal(dados);

            // Grava o conteúdo criptografado no pendrive
            FileOutputStream fos = new FileOutputStream(pendrive);
            fos.write(dadosCriptografados);
            fos.close();
        } catch (Exception e) {
            System.out.println("Erro ao criptografar pendrive: " + e.getMessage());
        }
    }

    private static void verificaIntegridade(File pendrive, SecretKeySpec chave, byte[] hashOriginal) {
        try {
            // Cria um objeto Cipher para descriptografar o pendrive
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, chave);

            // Lê o conteúdo criptografado do pendrive
            FileInputStream fis = new FileInputStream(pendrive);
            byte[] dadosCriptografados = new byte[(int) pendrive.length()];
            fis.read(dadosCriptografados);
            fis.close();

            // Descriptografa o conteúdo do pendrive
            byte[] dadosDescriptografados = cipher.doFinal(dadosCriptografados);

            // Verifica a integridade dos dados descriptografados
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(dadosDescriptografados);

            // Verifica se o hash é igual ao hash original
            if (MessageDigest.isEqual(hash, hashOriginal)) {
                System.out.println("Integridade dos dados verificada com sucesso!");
            } else {
                System.out.println("Integridade dos dados comprometida!");
            }
        } catch (Exception e) {
            System.out.println("Erro ao verificar integridade: " + e.getMessage());
        }
    }
}