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

package server;

import static utils.SSLUtils.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Scanner;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import CryptoUtils.*;

import CryptoUtils.PKIUtils;
import utils.SSLContextProvider;
import HashMap.*;

public class SSLServer implements SSLContextProvider {

    private static String HASH_FUNCTION = "SHA1";
    static Scanner input = new Scanner(System.in);
    private static final KeyManager[][] KeyManager = null;
    private static int port = 4433;


    static HashMap<String,String> tableChavePublicaClientes = new HashMap<String,String>();
    static HashMap<String,String> tableDocumentosDigitais= new HashMap<String,String>();
    static HashMap<String,String> tableAssociacaoDocumentoChave = new HashMap<String,String>();
    static HashMap<String,Boolean> tableControloAcesso = new HashMap<String,Boolean>();
    static HashMap<String,Integer> tableMarcaTemporal = new HashMap<String,Integer>();

    static String pathTableChavePublicaClientes = "tables/tableChavePublicaClientes.xml";
    static String pathTableDocumentosDigitais = "tables/tableDocumentosDigitais.xml";
    static String pathTableAssociacaoDocumentoChave = "tables/tableAssociacaoDocumentoChave.xml";
    static String pathTableMarcaTemporal = "tables/tableMarcaTemporal.xml";


	public static void main(String[] args) throws Exception {

	    createXMLFiles();
        menuOffine();
    }

    private static void createXMLFiles() throws IOException {

	    //Intruções que vereficam se um ficheiro exite antes de cria um novo que possa o substituir e apagar os dados gravados

	    boolean res = new File(pathTableChavePublicaClientes).exists() ? false : new File(pathTableChavePublicaClientes).createNewFile();
        res = new File(pathTableDocumentosDigitais).exists() ? false : new File(pathTableDocumentosDigitais).createNewFile();
        res = new File(pathTableAssociacaoDocumentoChave).exists() ? false : new File(pathTableAssociacaoDocumentoChave).createNewFile();
        res = new File(pathTableMarcaTemporal).exists() ? false : new File(pathTableMarcaTemporal).createNewFile();
    }

    private static void menuOffine() throws Exception {
        String opcao;

        do {
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| Escolha uma opção:                                    |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [1] - Chaves Publicas Clientes                        |");
            System.out.println("|-| [2] - Documentos Digitais                             |");
            System.out.println("|-| [3] - Associar Documento Digital á uma Chave publica  |");
            System.out.println("|-| [4] - Controlo de Acesso                              |");
            System.out.println("|-| [5] - Marca Temporal                                  |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [6] - Ligar servidor      |");
            System.out.println("|-|---------------------------|");
            System.out.println("|-| [7] - Sair                |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.print("|-| Opção: "); opcao = input.nextLine();

            switch (opcao) {
                case "1": crudTableChavePublicaClientes();
                    break;
                case "2":
                    break;
                case "3":
                    break;
                case "4": crudTableControloAcesso();
                    break;
                case "5":
                    break;
                case "6": turnOnline();
                    break;
                case "7":
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Server encerrada.");
                    System.out.println("|-|--------------------------------------------");
                    System.exit(0);
                    break;
            }

        } while(!opcao.equals("7"));
    }

    private static void turnOnline() throws Exception {

        new SSLServer().run(port);
    }

    private static void crudTableChavePublicaClientes() throws Exception {
        String opcao;

        System.out.println("   2.  test get(key)");
        System.out.println("   3.  test containsKey(key)");
        System.out.println("   4.  test remove(key)");
        System.out.println("   5.  test table.containsValue(value)");
        System.out.println("   6.  test table.size()");
        System.out.println("   7.  show table ");
        System.out.println("   8.  test table.clear()");
        System.out.println("   9.  order by key");
        System.out.println("   10. order by value");
        System.out.println("   11. create table from XML");
        System.out.println("   12. copy table to XML");

        do {
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| Escolha uma opção:                                    |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [1] - Obter endereço Chave Publica                    |");
            System.out.println("|-| [2] - Apagar Chave Publica                            |");
            System.out.println("|-| [3] - Listar Chaves                                   |");
            System.out.println("|-| [4] - Tamanho da Tabela                               |");
            System.out.println("|-| [5] - Criar Tabela apartir de XML                     |");
            System.out.println("|-| [6] - Copia Tabela para XML                           |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [7] - Voltar              |");
            System.out.println("|-|---------------------------|");
            System.out.println("|-| [8] - Sair                |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.print("|-| Opção: "); opcao = input.nextLine();

            switch (opcao) {
                case "1": obterEnderecoChavePublica();
                    break;
                case "2": apagarChavePublica();
                    break;
                case "3":
                    break;
                case "4":
                    break;
                case "5": criarTabelaApartirDeXML();
                    break;
                case "6":
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Server encerrada.");
                    System.out.println("|-|--------------------------------------------");
                    System.exit(0);
                    break;
            }

        } while(!opcao.equals("6"));
    }

    private static void obterEnderecoChavePublica(){
	    String hash;
        System.out.println("|-|-------------------------------------------------------|");
        System.out.print("|-| Valor do Hash: "); hash = input.nextLine();

        if(tableChavePublicaClientes.containsKey(hash)){
            System.out.println("|-|-------------------------------------------------------------------------------------|");
            System.out.println("|-| Endereço chave publica: " + tableChavePublicaClientes.get(hash));
            System.out.println("|-|-------------------------------------------------------------------------------------|");
        } else {
            System.out.println("|-|-------------------------------------------------------------------------------------|");
            System.out.println("|-| Aviso: Hash Chave Publica não exite!");
            System.out.println("|-|-------------------------------------------------------------------------------------|");
        }

    }

    private static void apagarChavePublica() {

        String hash;
        System.out.println("|-|-------------------------------------------------------|");
        System.out.print("|-| Valor do Hash: "); hash = input.nextLine();

	    tableChavePublicaClientes.remove(hash);

        if(!tableChavePublicaClientes.containsKey(hash)){
            System.out.println("|-|-------------------------------------------------------------------------------------|");
            System.out.println("|-| Chave Publica apagada com sucesso!");
            System.out.println("|-|-------------------------------------------------------------------------------------|");
        } else {
            System.out.println("|-|-------------------------------------------------------------------------------------|");
            System.out.println("|-| Aviso: Chave Publica não apagada!");
            System.out.println("|-|-------------------------------------------------------------------------------------|");
        }

    }

    private static void criarTabelaApartirDeXML() {
	    tableChavePublicaClientes = XMLCode.fileToMap2(pathTableChavePublicaClientes);

	    if(!tableChavePublicaClientes.isEmpty()){
            System.out.println("|-|-------------------------------------------------------------------------------------|");
            System.out.println("|-| Tabela Chaves Publicas carregada com sucesso!");
            System.out.println("|-|-------------------------------------------------------------------------------------|");
        } else {
            System.out.println("|-|-------------------------------------------------------------------------------------|");
            System.out.println("|-| Aviso: Tabela Chaves Publicas não carregada!");
            System.out.println("|-|-------------------------------------------------------------------------------------|");
        }
    }

    private static void crudTableControloAcesso() throws Exception {
        String opcao;

        do {
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| Escolha uma opção:                                    |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [1] - Novo acesso                                     |");
            System.out.println("|-| [2] - Consultar acesso                                |");
            System.out.println("|-| [3] - Atualizar acesso                                |");
            System.out.println("|-| [4] - Apagar acesso                                   |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [5] - Voltar              |");
            System.out.println("|-|---------------------------|");
            System.out.println("|-| [6] - Sair                |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.print("|-| Opção: "); opcao = input.nextLine();

            switch (opcao) {
                case "1":
                    break;
                case "2":
                    break;
                case "3":
                    break;
                case "4":
                    break;
                case "5":
                    break;
                case "6":
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Server encerrada.");
                    System.out.println("|-|--------------------------------------------");
                    System.exit(0);
                    break;
            }

        } while(!opcao.equals("6"));
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

        System.out.println("|-|--------------------------------------------");
        System.out.println("|-| Server started...");
        System.out.println("|-|--------------------------------------------");
        System.out.println("|-| Aguardando cliente(s)....");

        while(true) {
            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
            System.out.println("|-|--------------------------------------------");
            System.out.printf("|-| Client (%s) connected. Awaiting hello...%n", getPeerIdentity(clientSocket));
            System.out.println("|-|--------------------------------------------");

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
            System.out.println("|-| conectado com " + stringClient);
            System.out.println("|-|--------------------------------------------");

            try {
                PublicKey publicKeyClient = extractPublicKeyFromSocket(s);
                // Save public key to (X.509) PEM file
                String nameFile = "certsClients/"+stringClient+"-PK.pem";
                PKIUtils.savePublicKeyToPEMFile(publicKeyClient, nameFile);
                String stringHashChavePublica = CryptoUtils.getFileHash(nameFile, HASH_FUNCTION);
                String newName = "certsClients/"+stringHashChavePublica+"-PK.pem";
                File file=new File(nameFile);
                boolean renameResult = file.renameTo(new File(newName));

                //save Chave publica Cliente
                tableChavePublicaClientes.put(stringHashChavePublica, newName);
                //Save hashMap to file.xml
                XMLCode.mapToFile2(pathTableChavePublicaClientes, tableChavePublicaClientes);
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
                if (!"hello".equals(command)) {
                    throw new RuntimeException("Expected 'hello', but got '" + command + "'...");
                }

                System.out.println("|-| Hello received. Sending HELLO...");
                System.out.println("|-|--------------------------------------------");

                os.write("HELLO".getBytes());
                os.flush();
            }//fim try
            catch (Exception e){
                System.err.println("Erro: "+e);
            }
            System.out.println("|-| cliente "+ stringClient+" desconectado!");
            System.out.println("|-|--------------------------------------------\n*************************************************");
        }//fim metodo run
    }//fim classe EchoClientThread

    private ServerSocket createSSLSocket(int port) throws Exception {
        SSLServerSocket socket = createSSLServerSocket(port, this);
        socket.setNeedClientAuth(true);
        return socket;
    }
}
