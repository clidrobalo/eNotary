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

import java.io.*;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
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
    private static int TAMANHO_BUFFER = 2048;
    static Scanner input = new Scanner(System.in);
    private static final KeyManager[][] KeyManager = null;
    private static int port = 4433;
    private static ServerSocket serverSocket = null;


    static HashMap<String,String> tableChavePublicaClientes = new HashMap<String,String>();
    static HashMap<String,String> tableDocumentosDigitais= new HashMap<String,String>();
    static HashMap<String,String> tableAssociacaoDocumentoChave = new HashMap<String,String>();
    static HashMap<String,Boolean> tableControloAcesso = new HashMap<String,Boolean>();
    static HashMap<String,Integer> tableMarcaTemporal = new HashMap<String,Integer>();

    static String pathTableChavePublicaClientes = "tables/tableChavePublicaClientes.xml";
    static String pathTableDocumentosDigitais = "tables/tableDocumentosDigitais.xml";
    static String pathTableAssociacaoDocumentoChave = "tables/tableAssociacaoDocumentoChave.xml";
    static String pathTableControloAcesso = "tables/TableControloAcesso.xml";
    static String pathTableMarcaTemporal = "tables/tableMarcaTemporal.xml";


	public static void main(String[] args) throws Exception {

	    createXMLFiles();
	    //carregar os HashMaps com os valores dos ficheiros XML
//        for(String tipo : new ArrayList<String>(){{add("chavePublica");add("associacao");add("documentos");add("acesso");add("marca");}}) {
//            criarTabelasApartirDeXML(tipo);
//        }
        menuOffine();
    }

    private static void createXMLFiles() throws IOException {

	    //Intruções que vereficam se um ficheiro exite antes de cria um novo que possa o substituir e apagar os dados gravados

	    boolean res = new File(pathTableChavePublicaClientes).exists() ? false : new File(pathTableChavePublicaClientes).createNewFile();
        res = new File(pathTableDocumentosDigitais).exists() ? false : new File(pathTableDocumentosDigitais).createNewFile();
        res = new File(pathTableAssociacaoDocumentoChave).exists() ? false : new File(pathTableAssociacaoDocumentoChave).createNewFile();
        res = new File(pathTableMarcaTemporal).exists() ? false : new File(pathTableMarcaTemporal).createNewFile();
        res = new File(pathTableControloAcesso).exists() ? false : new File(pathTableControloAcesso).createNewFile();
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

        serverSocket = createSSLSocket(port);

        System.out.println("|-|--------------------------------------------");
        System.out.println("|-| Server started...");
        System.out.println("|-|--------------------------------------------");
        System.out.println("|-| Aguardando conecção...");
        while(true) {
            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
//            System.out.println("|-|--------------------------------------------");
//            System.out.printf("|-| Client (%s) connected. Awaiting hello...%n", getPeerIdentity(clientSocket));
//            System.out.println("|-|--------------------------------------------");

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

            try {
                OutputStream os = s.getOutputStream();
                InputStream is = s.getInputStream();

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
                XMLCode.mapToFileString_String(pathTableChavePublicaClientes, tableChavePublicaClientes);

                //System.out.println("|-| Hash msg "+ stringClient + ": " + stringHashChavePublica);
                //System.out.println("|-|--------------------------------------------------------------------|");

                //Verificar se o Cliente tem acesso as funcionalidades
                boolean clienteTemAcesso = clienteTemAcesso(stringHashChavePublica);

                byte[] buf = new byte[5];

                if(clienteTemAcesso) {
                    int read = is.read(buf);
                    String command = new String(buf);
                    System.out.println("|-| " + command + ", " + read + " - HandShake Sucess");
                    System.out.println("|-|--------------------------------------------------------------------|");
                    os.write("HELLO".getBytes());
                    os.flush();
                    System.out.println("|-|--------------------------------------------------------------------|");
                    System.out.println("|-| conectado com " + stringClient);
                    System.out.println("|-|--------------------------------------------------------------------|");
                    getUpload(s, os, is);
                } else {
                    os.write("false".getBytes());
                    os.flush();
                    System.out.println("|-|--------------------------------------------------------------------|");
                    System.out.println("|-| Cliente " + stringClient + " não tem acesso.");
                    System.out.println("|-|--------------------------------------------------------------------|");
                    //waitConecao(s, is, os);
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }//fim metodo run

        private void getUpload(SSLSocket s, OutputStream os, InputStream is) throws IOException {

            BufferedReader inString = new BufferedReader(
                    new InputStreamReader(s.getInputStream()));
            PrintStream outString = new PrintStream(s.getOutputStream());

            byte[] byteFicheiro = new byte[TAMANHO_BUFFER];

            System.out.println("|-|--------------------------------------------");
            System.out.println("|-| Aguardando upload...");
            System.out.println("|-|--------------------------------------------");

            int read = is.read(byteFicheiro);

            if(read > 0){
                System.out.println("|-|--------------------------------------------");
                System.out.println("|-| Ficheiro recebido: "+ Arrays.toString(byteFicheiro));
                System.out.println("|-|--------------------------------------------");
                os.write("hash".getBytes());
            }

            System.out.println("|-|--------------------------------------------");
            System.out.println("|-| Aguardando hash documento...");
            System.out.println("|-|--------------------------------------------");

            //get hash documento
            byte[] byteHashDocumento = new byte[TAMANHO_BUFFER];
            read = is.read(byteHashDocumento);
            String hashDocumento = new String(byteHashDocumento).replaceAll("\u0000.*", "");
            if(hashDocumento.length() > 0){
                System.out.println("|-| Hash documento recebido: " + hashDocumento);
                System.out.println("|-|--------------------------------------------------------------");
                String zipFile = "repositorioServer/"+hashDocumento+".zip";
                String destination = "repositorioServer/"+hashDocumento;
                writeFile(zipFile, byteFicheiro);
                System.out.println("|-|--------------------------------------------------------------");

                unzip(zipFile, destination);

                //verificar se o ficheiro foi unzip com sucesso
                if(new File("repositorioServer/"+hashDocumento).exists()){
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Unzip realizado com sucesso.");
                    System.out.println("|-|--------------------------------------------");

                } else {
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Unzip não realizado.");
                    System.out.println("|-|--------------------------------------------");
                }
            }
        }

        public void unzip(String zipFile, String outputFolder){
            byte[] buffer = new byte[1024];
            try{
                //create output directory is not exists
                File folder = new File(outputFolder);
                if(!folder.exists()){
                    folder.mkdir();
                }
                //get the zip file content
                ZipInputStream zis =
                        new ZipInputStream(new FileInputStream(zipFile));
                //get the zipped file list entry
                ZipEntry ze = zis.getNextEntry();
                while(ze!=null){
                    String fileName = ze.getName();
                    File newFile = new File(outputFolder + File.separator + fileName);
                    System.out.println("file unzip : "+ newFile.getAbsoluteFile());
                    //create all non exists folders
                    //else you will hit FileNotFoundException for compressed folder
                    new File(newFile.getParent()).mkdirs();
                    FileOutputStream fos = new FileOutputStream(newFile);
                    int len;
                    while ((len = zis.read(buffer)) > 0) {
                        fos.write(buffer, 0, len);
                    }
                    fos.close();
                    ze = zis.getNextEntry();
                }
                zis.closeEntry();
                zis.close();
                System.out.println("Done");
            }catch(IOException ex){
                ex.printStackTrace();
            }
        }

        public void writeFile(String fileOutPut, byte[] result) throws IOException {

            try {

                OutputStream output = new FileOutputStream(fileOutPut);

                output.write(result);
                output.close();
                System.out.println("|-| Ficheiro gravado com sucesso no path \"" + fileOutPut + "\"");

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        private boolean clienteTemAcesso(String stringHashChavePublica) {
            return tableControloAcesso.containsKey(stringHashChavePublica);
        }
    }//fim classe EchoClientThread

    private ServerSocket createSSLSocket(int port) throws Exception {
        SSLServerSocket socket = createSSLServerSocket(port, this);
        socket.setNeedClientAuth(true);
        return socket;
    }

    //--------------CRUDs ----------------------------------------------------------------------------------

    //---Chave Publicas Clientes

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

    //---Controlo Acesso

    private static void novoAcesso() throws Exception {
        String hash = null;
        System.out.println("|-|-------------------------------------------------------|");
        System.out.print("|-| Hash Chave pública: "); hash = input.nextLine();

        if(!hash.isEmpty()){
            tableControloAcesso.put(hash, true);
            System.out.println("|-| Acesso gravado com sucesso!");
            System.out.println("|-|--------------------------------------------");
        } else {
            crudTableControloAcesso();
        }

    }

    //-------------- Menus ----------------------------------------------------------------------------------

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
                    if(tableChavePublicaClientes.size() > 0) {
                        System.out.println("|-|--------------------------------------------");
                        for (String chave : tableChavePublicaClientes.keySet()) {
                            System.out.println("|-| " + chave);
                        }
                        System.out.println("|-|--------------------------------------------");
                    } else {
                        System.out.println("|-|--------------------------------------------");
                        System.out.println("|-| Tabela Chave Publica vazia.");
                        System.out.println("|-|--------------------------------------------");
                    }
                    break;
                case "4":
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Tamanho tabela: " + tableChavePublicaClientes.size());
                    System.out.println("|-|--------------------------------------------");
                    break;
                case "5":
                    criarTabelasApartirDeXML("chavePublica");
                    break;
                case "6": copiarTabelasParaXML("chavePublica");
                    break;
                case "7": menuOffine();
                    break;
                case "8":
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Server encerrada.");
                    System.out.println("|-|--------------------------------------------");
                    System.exit(0);
                    break;
            }

        } while(!opcao.equals("8"));
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
            System.out.println("|-| [5] - Listar acessos                                  |");
            System.out.println("|-| [6] - Tamanho da Tabela                               |");
            System.out.println("|-| [7] - Copia Tabela para XML                           |");
            System.out.println("|-| [8] - Criar Tabela apartir de XML                     |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [9] - Voltar              |");
            System.out.println("|-|---------------------------|");
            System.out.println("|-| [10] - Sair                |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.print("|-| Opção: "); opcao = input.nextLine();

            switch (opcao) {
                case "1": novoAcesso();
                    break;
                case "2": //consultarAcesso();
                    break;
                case "3":
                    break;
                case "4":
                    break;
                case "5":
                    if(tableControloAcesso.size() > 0) {
                        System.out.println("|-|--------------------------------------------");
                        for (String hash : tableControloAcesso.keySet()) {
                            System.out.println("|-| " + hash);
                        }
                        System.out.println("|-|--------------------------------------------");
                    } else {
                        System.out.println("|-|--------------------------------------------");
                        System.out.println("|-| Tabela acesso vazia.");
                        System.out.println("|-|--------------------------------------------");
                    }
                    break;
                case "6":
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Tamanho tabela: " + tableControloAcesso.size());
                    System.out.println("|-|--------------------------------------------");
                    break;
                case "7": copiarTabelasParaXML("acesso");
                    break;
                case "8": criarTabelasApartirDeXML("acesso");
                    break;
                case "9": menuOffine();
                    break;
                case "10":
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Server encerrada.");
                    System.out.println("|-|--------------------------------------------");
                    System.exit(0);
                    break;
            }

        } while(!opcao.equals("10"));
    }

    private static void criarTabelasApartirDeXML(String tipo) {

        switch (tipo) {
            case "chavePublica":
                tableChavePublicaClientes = XMLCode.fileToMapString_String(pathTableChavePublicaClientes);
                System.out.println("|-|-------------------------------------------------------------------------------------|");
                System.out.println("|-| tableChavePublicaClientes carregada com sucesso!");
                System.out.println("|-|-------------------------------------------------------------------------------------|");
                break;
            case "associacao":
                tableAssociacaoDocumentoChave = XMLCode.fileToMapString_String(pathTableAssociacaoDocumentoChave);
                System.out.println("|-|-------------------------------------------------------------------------------------|");
                System.out.println("|-| tableAssociacaoDocumentoChave carregada com sucesso!");
                System.out.println("|-|-------------------------------------------------------------------------------------|");
                break;
            case "documentos":
                tableDocumentosDigitais = XMLCode.fileToMapString_String(pathTableDocumentosDigitais);
                System.out.println("|-|-------------------------------------------------------------------------------------|");
                System.out.println("|-| tableDocumentosDigitais carregada com sucesso!");
                System.out.println("|-|-------------------------------------------------------------------------------------|");
                break;
            case "acesso":
                tableControloAcesso = XMLCode.fileToMapString_Boolean(pathTableControloAcesso);
                System.out.println("|-|-------------------------------------------------------------------------------------|");
                System.out.println("|-| tableControloAcesso carregada com sucesso!");
                System.out.println("|-|-------------------------------------------------------------------------------------|");
                break;
            case "marca":
                tableMarcaTemporal = XMLCode.fileToMapString_Integer(pathTableMarcaTemporal);
                System.out.println("|-|-------------------------------------------------------------------------------------|");
                System.out.println("|-| tableMarcaTemporal carregada com sucesso!");
                System.out.println("|-|-------------------------------------------------------------------------------------|");
                break;
        }
    }

    private static void copiarTabelasParaXML(String tipo) {

        switch (tipo) {
            case "chavePublica":
                if(XMLCode.mapToFileString_String(pathTableChavePublicaClientes,tableChavePublicaClientes)){
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                    System.out.println("|-| tableChavePublicaClientes Salvado com sucesso!");
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                } else {
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                    System.out.println("|-| Aviso: tableChavePublicaClientes não Salvado!");
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                }
                break;
            case "associacao":
                if(XMLCode.mapToFileString_String(pathTableAssociacaoDocumentoChave,tableAssociacaoDocumentoChave)){
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                    System.out.println("|-| tableAssociacaoDocumentoChave Salvado com sucesso!");
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                } else {
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                    System.out.println("|-| Aviso: tableAssociacaoDocumentoChave não Salvado!");
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                }
                break;
            case "documentos":
                if(XMLCode.mapToFileString_String(pathTableDocumentosDigitais,tableDocumentosDigitais)){
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                    System.out.println("|-| tableDocumentosDigitais Salvado com sucesso!");
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                } else {
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                    System.out.println("|-| Aviso: tableDocumentosDigitais não Salvado!");
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                }
                break;
            case "acesso":
                if(XMLCode.mapToFileString_Boolean(pathTableControloAcesso,tableControloAcesso)){
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                    System.out.println("|-| tableControloAcesso Salvado com sucesso!");
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                } else {
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                    System.out.println("|-| Aviso: tableControloAcesso não Salvado!");
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                }
                break;
            case "marca":
                if(XMLCode.mapToFileString_Integer(pathTableMarcaTemporal,tableMarcaTemporal)){
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                    System.out.println("|-| tableMarcaTemporal Salvado com sucesso!");
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                } else {
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                    System.out.println("|-| Aviso: tableMarcaTemporal não Salvado!");
                    System.out.println("|-|-------------------------------------------------------------------------------------|");
                }
                break;
        }
    }
}
