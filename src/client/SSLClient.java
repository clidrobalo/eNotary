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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Scanner;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import utils.SSLContextProvider;
import utils.SSLUtils;

public class SSLClient implements SSLContextProvider {
    Scanner input = new Scanner(System.in);
	private static int port = 4433;
    private static String host = null;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: SSLClient <host>\n");
            System.exit(1);
        }

        host = args[0];

        new SSLClient().run(host, port);
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
            System.out.printf("|-| Connected to server (%s). Writing hello...%n", getPeerIdentity(clientSocket));
            System.out.println("|-|--------------------------------------------");

            os.write("hello".getBytes());
            os.flush();

            System.out.println("|-| hello written, awaiting response...");

            byte[] buf = new byte[5];
            int read = is.read(buf);
            if (read != 5) {
                throw new RuntimeException("|-| Not enough bytes read: " + read + ", expected 5 bytes!");
            }

            String response = new String(buf);
            if (!"HELLO".equals(response)) {
                throw new RuntimeException("|-| Expected 'HELLO', but got '" + response + "'...");
            }

            System.out.println("|-| HELLO obtained!");
            System.out.println("|-|--------------------------------------------");
            System.out.println("|-| Handshake concluida com sucesso!");
            System.out.println("|-|--------------------------------------------");

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

    public void init() {
        String opcao = null;

        do {
            System.out.println("|-| Escolha uma opção: ");
            System.out.println("|-|--------------------------------------------");
            System.out.println("|-| [1] - ");
            System.out.println("|-| [2] - ");
            System.out.println("|-| [3] - ");
            System.out.println("|-| [4] - ");
            System.out.println("|-|--------------------------------------------");
            System.out.print("|-| Opção: "); opcao = input.nextLine();
        } while(!(opcao.equals("1") || opcao.equals("2") || opcao.equals("3") || opcao.equals("4")));

    }

    private SSLSocket createSSLSocket(String host, int port) throws Exception {
        return SSLUtils.createSSLSocket(host, port, this);
    }
}
