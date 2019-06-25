/**
 * 
 * Description:
 * Two-way SSL Client
 * 
 * Version: 
 * 04.2019
 * 
 * Author: 
 * Jose G. Faisca <jose.faisca@gmail.com>
 * 
 */

package client;

import static utils.SSLUtils.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Scanner;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import CryptoUtils.*;
import utils.SSLContextProvider;
import utils.SSLUtils;

public class SSLClient implements SSLContextProvider {
    private static String HASH_FUNCTION = "SHA1";
    private static Scanner input = new Scanner(System.in);
	private static int port = 4433;
    private static String host = null;
    private static KeyPair pair = null;

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println("Usage: SSLClient <host> <keypair_fileName> <storePassword> <keyPassword>\n");
            System.exit(1);
        }

        host = args[0];
        // Get KeyPair from KeyStore
        pair = PKIUtils.getKeyPairFromKeyStore(args[1],args[2],args[3]);

        menuOffine();
    }

    @Override
    public KeyManager[] getKeyManagers() throws GeneralSecurityException, IOException {
        return createKeyManagers("./sslcert/client.jks", "qwerty".toCharArray());
    }

    @Override
    public String getProtocol() {
        return "TLSv1.2";
    }

    @Override
    public TrustManager[] getTrustManagers() throws GeneralSecurityException, IOException {
        return createTrustManagers("./sslcert/cacert.jks", "qwerty".toCharArray());
    }

    public void run(String host, int port) throws Exception {
        try (SSLSocket clientSocket = createSSLSocket(host, port); OutputStream os = clientSocket.getOutputStream(); InputStream is = clientSocket.getInputStream()) {

            System.out.println("|-|--------------------------------------------");
            System.out.printf("|-| Connected to server (%s)", getPeerIdentity(clientSocket));
            System.out.println("|-|--------------------------------------------");

            os.write("hello".getBytes());
            os.flush();

            //System.out.println("|-| hello written, awaiting response...");

            byte[] buf = new byte[5];
            int read = is.read(buf);
            if (read != 5) {
                throw new RuntimeException("|-| Not enough bytes read: " + read + ", expected 5 bytes!");
            }

            String response = new String(buf);
            if (!"HELLO".equals(response)) {
                throw new RuntimeException("|-| Expected 'HELLO', but got '" + response + "'...");
            }

//            System.out.println("|-| HELLO obtained!");
//            System.out.println("|-|--------------------------------------------");
//            System.out.println("|-| Handshake concluida com sucesso!");
//            System.out.println("|-|--------------------------------------------");

        } catch (Exception e) {
            servidorIndisponivel();
        } finally {
            System.out.println("|-|--------------------------------------------");
            //Começar o funcionamento do cliente
            init();
        }
    }

    public void servidorIndisponivel() throws Exception {
        String opcao = null;
        System.out.println("|-|--------------------------------------------");
        System.out.println("|-| Servidor indisponivel....");
        System.out.println("|-|--------------------------------------------");

        do {
            System.out.println("|-|--------------------------------------------");
            System.out.println("|-| Escolha uma opção: ");
            System.out.println("|-|--------------------------------------------");
            System.out.println("|-| [1] - Tentar Novamente.");
            System.out.println("|-| [2] - Sair");
            System.out.println("|-|--------------------------------------------");
            System.out.print("Opção: "); opcao = input.nextLine();
        } while(!(opcao.equals("1") || opcao.equals("2")));

        switch (opcao) {
            case "1" : new SSLClient().run(host, port);
            break;
            case "2":
                System.out.println("|-|--------------------------------------------");
                System.out.println("|-| Aplicação encerrada.");
                System.out.println("|-|--------------------------------------------");
                System.exit(0);
        }
    }

    private SSLSocket createSSLSocket(String host, int port) throws Exception {
        return SSLUtils.createSSLSocket(host, port, this);
    }

    private static void menuOffine() throws Exception {
        String opcao;

        do {
            System.out.println("|-|*******************************************************|");
            System.out.println("|-| Escolha uma opção:                                    |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [1] - Calcular Hash documento digital                 |");
            System.out.println("|-| [2] - Assinar Hash                                    |");
            System.out.println("|-| [3] - Comprimir hash e assinatura                     |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [4] - Ligar Cliente       |");
            System.out.println("|-|---------------------------|");
            System.out.println("|-| [5] - Sair                |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.print("|-| Opção: "); opcao = input.nextLine();

            switch (opcao) {
                case "1":
                    String pathDocumento;
                    System.out.println("|-|-------------------------------------------------------|");
                    System.out.print("|-| Caminho documento: "); pathDocumento = input.nextLine();
                    //verificar se o documento exite antes de calcular o hash do seu nome
                    if(new File(pathDocumento).exists()) {
                        String stringHashNameDocumento = CryptoUtils.getFileHash(pathDocumento, HASH_FUNCTION);
                        System.out.println("|-|-------------------------------------------------------------|");
                        System.out.println("|-| Hash documento: " + stringHashNameDocumento);
                        System.out.println("|-|-------------------------------------------------------------|");
                    } else {
                        System.out.println("|-|-------------------------------------------------------|");
                        System.out.println("|-| File " + pathDocumento + " não existe.");
                    }
                    break;
                case "2":
                    String hashDocumento;
                    System.out.println("|-|-------------------------------------------------------------|");
                    System.out.print("|-| Hash documento: "); hashDocumento = input.nextLine();
                    System.out.println("|-|-------------------------------------------------------------|");
                    String signatureHash = CryptoUtils.signString(hashDocumento, pair.getPrivate());
                    FileUtils.saveStrToFile(signatureHash, "AssinaturasCliente/"+hashDocumento+".signature");
                    System.out.println("|-| Hash assinada com sucesso.");
                    break;
                case "3":

                    break;
                case "4": turnOnline();
                    break;
                case "5":
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Cliente encerrada.");
                    System.out.println("|-|--------------------------------------------");
                    System.exit(0);
                    break;
            }

        } while(!opcao.equals("5"));
    }

    private static void turnOnline() throws Exception {

        new SSLClient().run(host, port);
    }

    public void init() throws Exception {
        String opcao;

        do {
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| Escolha uma opção:                                    |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [1] - Upload ficheiro                                 |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [2] - Terminar sessão     |");
            System.out.println("|-|---------------------------|");
            System.out.println("|-| [3] - Sair                |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.print("|-| Opção: "); opcao = input.nextLine();

            switch (opcao) {
                case "1":
                    break;
                case "2":
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Sessão encerrada.");
                    System.out.println("|-|--------------------------------------------");
                    menuOffine();
                    break;
                case "3":
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Cliente encerrada.");
                    System.out.println("|-|--------------------------------------------");
                    System.exit(0);
                    break;
            }

        } while(!opcao.equals("3"));
    }
}
