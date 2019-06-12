/**
 * 
 * Description:
 * Two-way SSL Server
 * 
 * Version: 
 * 04.2019
 * 
 * Author: 
 * Jose G. Faisca <jose.faisca@gmail.com>
 * 
 */

package demo.server;

import static demo.utils.SSLUtils.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;


import demo.utils.SSLContextProvider;

public class SSLServer implements SSLContextProvider {

    private static final KeyManager[][] KeyManager = null;
    private static int port = 4433;

	public static void main(String[] args) throws Exception {
        new SSLServer().run(port);
    }

    @Override
    public KeyManager[] getKeyManagers() throws GeneralSecurityException, IOException {
        return createKeyManagers("./sslcert/server.jks", "qwerty".toCharArray());
    }

    @Override
    public String getProtocol() {
        return "TLSv1.2";
    }

    @Override
    public TrustManager[] getTrustManagers() throws GeneralSecurityException, IOException {
        return createTrustManagers("./sslcert/cacert.jks", "qwerty".toCharArray());
    }

    public void run(int port) throws Exception {
    	
        ServerSocket serverSocket = createSSLSocket(port);

        System.out.println("Server started...");

        while(true) {
            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
            System.out.printf("Client (%s) connected. Awaiting hello...%n", getPeerIdentity(clientSocket));

            Thread t = new Thread(new EchoClientThread(clientSocket));
            t.start();
        }


    }

    public static class EchoClientThread implements Runnable{
        private SSLSocket s;



        public EchoClientThread(SSLSocket socket) {
            this.s = socket;
        }

        public void run() {
            String threadName = Thread.currentThread().getName();//nome da thread
            String stringClient = s.getInetAddress().toString();//IP do cliente
            System.out.println("conectado com " + stringClient);

            try {
                PublicKey publicKeyClient = extractPublicKeyFromSocket(s);
            } catch (Exception e) {
                e.printStackTrace();
            }


            try{//inicio try
                OutputStream os = s.getOutputStream();
                InputStream is = s.getInputStream();

                byte[] buf = new byte[5];
                int read = is.read(buf);
                if (read != 5) {
                    throw new RuntimeException("Not enough bytes read: " + read + ", expected 5 bytes!");
                }

                String command = new String(buf);
                System.out.println("--> " + command);
                if (!"hello".equals(command)) {
                    throw new RuntimeException("Expected 'hello', but got '" + command + "'...");
                }

                System.out.println("hello received. Sending HELLO...");

                os.write("HELLO".getBytes());
                os.flush();


            }//fim try
            catch (Exception e){
                System.err.println("Erro: "+e);
            }
            System.out.println("cliente "+ stringClient+" desconectado!");
        }//fim metodo run
    }//fim classe EchoClientThread

    private ServerSocket createSSLSocket(int port) throws Exception {
        SSLServerSocket socket = createSSLServerSocket(port, this);
        socket.setNeedClientAuth(true);
        return socket;
    }
}
