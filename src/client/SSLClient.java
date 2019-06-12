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

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import utils.SSLContextProvider;
import utils.SSLUtils;

public class SSLClient implements SSLContextProvider {
	
	private static int port = 4433;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: SSLClient <host>\n");
            System.exit(1);
        }

        String host = args[0];

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

            System.out.printf("Connected to server (%s). Writing hello...%n", getPeerIdentity(clientSocket));

            os.write("hello".getBytes());
            os.flush();

            System.out.println("hello written, awaiting response...");

            byte[] buf = new byte[5];
            int read = is.read(buf);
            if (read != 5) {
                throw new RuntimeException("Not enough bytes read: " + read + ", expected 5 bytes!");
            }

            String response = new String(buf);
            if (!"HELLO".equals(response)) {
                throw new RuntimeException("Expected 'HELLO', but got '" + response + "'...");
            }

            System.out.println("HELLO obtained! Ending client...");
        }
    }

    private SSLSocket createSSLSocket(String host, int port) throws Exception {
        return SSLUtils.createSSLSocket(host, port, this);
    }
}
