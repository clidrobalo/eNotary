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

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import CryptoUtils.*;
import utils.SSLContextProvider;
import utils.SSLUtils;

public class SSLClient implements SSLContextProvider {
    private static String HASH_FUNCTION = "SHA1";
    private static int TAMANHO_BUFFER = 2048;
    private static Scanner input = new Scanner(System.in);
	private static int port = 4433;
    private static String host = null;
    private static KeyPair pair = null;

    BufferedReader inputString;
    PrintStream outputString;

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

        try(SSLSocket clientSocket = createSSLSocket(host, port); OutputStream os = clientSocket.getOutputStream(); InputStream is = clientSocket.getInputStream())  {
            System.out.println("|-|--------------------------------------------");
            System.out.printf("|-| Connected to server (%s)\n", getPeerIdentity(clientSocket));
            System.out.println("|-|--------------------------------------------");

            os.write("hello".getBytes());
            os.flush();

            byte[] buf = new byte[5];
            int read = is.read(buf);
            String command = new String(buf);

            if(command.equals("HELLO")){
                System.out.println("|-| " + command + ", " + read + " - HandShake Sucess.");
                System.out.println("|-|--------------------------------------------");
                //Começar o funcionamento do cliente
                init(clientSocket, os, is);
            } else if(command.equals("false")){
                System.out.println("|-| Conecção recusada devido o acesso.");
                System.out.println("|-|--------------------------------------------");
                servidorIndisponivel();
            }

        } catch (Exception e) {
            servidorIndisponivel();
        } finally {

        }
    }

    public void servidorIndisponivel() throws Exception {
        String opcao = null;
        System.out.println("|-|--------------------------------------------");
        System.out.println("|-| Servidor indisponivel....");
        System.out.println("|-|--------------------------------------------");

        do {
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| Escolha uma opção:                                    |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [1] - Tentar novamente                                |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| [2] - Voltar              |");
            System.out.println("|-|---------------------------|");
            System.out.println("|-| [3] - Sair                |");
            System.out.println("|-|-------------------------------------------------------|");
            System.out.print("|-| Opção: "); opcao = input.nextLine();

            switch (opcao) {
                case "1": turnOnline();
                    break;
                case "2": menuOffine();
                    break;
                case "3":
                    System.out.println("|-|--------------------------------------------");
                    System.out.println("|-| Server encerrada.");
                    System.out.println("|-|--------------------------------------------");
                    System.exit(0);
                    break;
            }

        } while(!opcao.equals("3"));
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
                case "3": comprimirFicheiros();
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

    public void init(SSLSocket clientSocket, OutputStream os, InputStream is) throws Exception {
        String opcao;

        BufferedReader inString = new BufferedReader(
                new InputStreamReader(clientSocket.getInputStream()));
        PrintStream outString = new PrintStream(clientSocket.getOutputStream());

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
                    String pathFicherio;
                    System.out.println("|-|-------------------------------------------------------------|");
                    System.out.print("|-| Path Ficheiro: "); pathFicherio = input.nextLine();
                    System.out.println("|-|-------------------------------------------------------------|");
                    //verificar se o path existe
                    if(new File(pathFicherio).exists()) {
                        byte[] byteFicherio = readFile(pathFicherio);

                        System.out.println(byteFicherio.length);
                        //Enviar Upload to server
                        os.write(byteFicherio);

                        byte[] nextByte = new byte[4];
                        int read = is.read(nextByte);

                        if(new String(nextByte).equals("hash")){
                            String hashDocumento;
                            System.out.println("|-|-------------------------------------------------------------|");
                            System.out.print("|-| Hash documento: "); hashDocumento = input.nextLine();
                            System.out.println("|-|-------------------------------------------------------------|");
                            //sending hash documento
                            os.write(hashDocumento.getBytes());
                        }
                    }
                    else{
                        System.out.println("|-| Path: " + pathFicherio + " não existe.");
                        System.out.println("|-|--------------------------------------------");
                    }
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

    public byte[] readFile(String fileInput) throws IOException {
        FileInputStream fin = new FileInputStream(fileInput);

        byte[] arrayByte = new byte[fin.available()];

        int nbytes = fin.read(arrayByte);

        //System.out.println(nbytes);
        // close the file
        fin.close();

        System.out.println("|-| Ficheiro lido com sucesso do path \"" + fileInput + "\"");
        return arrayByte;
    }

    public static void comprimirFicheiros() {
        String pathAssinatura;
        String pathDocumento;
        String hashDocumento;

        System.out.println("|-|-------------------------------------------------------------|");
        System.out.print("|-| Path assinatura: "); pathAssinatura = input.nextLine();
        System.out.println("|-|-------------------------------------------------------------|");
        System.out.print("|-| Path documento: "); pathDocumento = input.nextLine();
        System.out.println("|-|-------------------------------------------------------------|");

        //verificar se esses ficheiros exitem
        if(new File(pathDocumento).exists() && new File(pathAssinatura).exists()) {
            List<String> pathArquivos = new ArrayList<>();
            pathArquivos.add(pathDocumento);
            pathArquivos.add(pathAssinatura);
            //comprimir arquivos
            System.out.println("|-|-------------------------------------------------------------|");
            System.out.print("|-| Hash documento: "); hashDocumento = input.nextLine();
            System.out.println("|-|-------------------------------------------------------------|");
            //verificar se esse ficherio com hash exite
            if(new File("AssinaturasCliente/"+hashDocumento+".signature").exists()){
                String pathArquivoComprimido = "arquivosComprimidos/"+hashDocumento+".zip";
                comprimirArquivo(pathArquivoComprimido, pathArquivos);

                //verificar se o arquivo comprimido foi criado
                if(new File(pathArquivoComprimido).exists()){
                    System.out.println("|-| Arquivo comprimido com sucesso.");
                } else {
                    System.out.println("|-| Arquivo não comprimido.");
                }
            }else {
                System.out.println("|-| Hash Invalido.");
            }

        } else {
            System.out.println("|-|-------------------------------------------------------|");
            System.out.println("|-| File " + pathDocumento + " ou ");
            System.out.println("|-| File " + pathAssinatura + " não existe.");
        }
    }
    static private void comprimirArquivo(String pathArquivoComprimido, List<String> pathArquivos) {
        //Constantes
        byte[] buffer = new byte[TAMANHO_BUFFER];

        try {
            // cria o arquivo zip
            ZipOutputStream saidaDeStream = new ZipOutputStream(new FileOutputStream(pathArquivoComprimido));

            // marca o modo de compreensão do arquivo
            saidaDeStream.setLevel(Deflater.BEST_COMPRESSION);

            // laço para pegar todos os arquivos que serao zipados
            for (String arquivo : pathArquivos)
            {
                // carrega o arquivo em um stream
                FileInputStream entradaDeStream = new FileInputStream(arquivo);

                // cria uma entrada no zip para o arquivo
                saidaDeStream.putNextEntry(new ZipEntry(arquivo));

                // transfere os dados do arquivo para o zip
                int tamanhoArquivo;
                while ((tamanhoArquivo = entradaDeStream.read(buffer, 0, TAMANHO_BUFFER)) != -1)
                {
                    saidaDeStream.write(buffer, 0, tamanhoArquivo);
                }

                // fecha a entrada do arquivo no zip
                saidaDeStream.closeEntry();

                // fecha o arquivo
                entradaDeStream.close();
            }

            // fecha o arquivo zip
            saidaDeStream.close();

        } catch (Exception e) {

        }
    }
}
