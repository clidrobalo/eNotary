/**
 * 
 * Description:
 * Class containing methods related to 
 * cryptography and security
 * 
 * Version: 
 * 04.2019
 * 
 * Author: 
 * Jose G. Faisca <jose.faisca@gmail.com>
 * 
 */

package CryptoUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;


public class CryptoUtils {
	
	// AES key size
	private static int KEY_SIZE_AES = 128;
	// cryptographic cipher transformation for encryption and decryption
	// in the  form "algorithm/mode/padding" or "algorithm" 
 	private static String CIPHER_RSA = "RSA/ECB/PKCS1Padding";
 	private static String CIPHER_AES = "AES/CBC/PKCS5Padding";
 	// digital signature algorithm
 	private static String SIGNATUE_ALGORITHM = "SHA256withRSA";
 	
	static SecureRandom srandom = new SecureRandom();

	/**
	 * Process file using cipher
	 * 
	 * @param ci
	 * 		  the cipher		  
	 * @param in
	 *        the input stream   
	 * @param out
	 *        the output stream                                            
	 * @throws Exception
	 */	
	public static void processFile(Cipher ci, InputStream in, OutputStream out)
			throws Exception {
		byte[] ibuf = new byte[1024];
		int len;
		while ((len = in.read(ibuf)) != -1) {
			byte[] obuf = ci.update(ibuf, 0, len);
			if ( obuf != null ) out.write(obuf);
		}
		byte[] obuf = ci.doFinal();
		if ( obuf != null ) out.write(obuf);
	}

	/**
	 * Process file using cipher
	 * 
	 * @param ci
	 * 		  the cipher		  
	 * @param in
	 *        the input file name   
	 * @param out
	 *        the output file name                                            
	 * @throws Exception
	 */	
	static private void processFile(Cipher ci, String inFile, String outFile)
			throws Exception {
		try (FileInputStream in = new FileInputStream(inFile);
             FileOutputStream out = new FileOutputStream(outFile)) {
			processFile(ci, in, out);
		}
	}

	/**
	 * Generate a key using AES algorithm
	 * 
	 * @returns the generated key                                    
	 * @throws Exception
	 */		
	public static SecretKey getKeyAES() throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(KEY_SIZE_AES);
		SecretKey skey = kgen.generateKey();
		return skey;
	}

	/**
	 * Encrypt file content using a private key
	 * 
	 * @param privateKey
	 * 		  the private key		  
	 * @param inputFile
	 *        the input file name                                      
	 * @throws Exception
	 */	
	public static void doEncrypt(PrivateKey privateKey, String inputFile)
			throws Exception {
		Cipher cipher = Cipher.getInstance(CIPHER_RSA);
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		processFile(cipher, inputFile, inputFile + ".enc");
	}

	/**
	 * Decrypt file content using a public key
	 * 
	 * @param privateKey
	 * 		  the private key		  
	 * @param inputFile
	 *        the input file name                                      
	 * @throws Exception
	 */	
	public static void doDecrypt(PublicKey publicKey, String inputFile)
			throws Exception {
		Cipher cipher = Cipher.getInstance(CIPHER_RSA);
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		processFile(cipher, inputFile, inputFile + ".ver");
	}

	/**
	 * Encrypt file content using a combination of 
	 * AES encryption and RSA encryption
	 * 
	 * @param privateKey
	 * 		  the private key		  
	 * @param inputFile
	 *        the input file name                                    
	 * @throws Exception
	 */		
	public static void doEncryptRSAWithAES(PrivateKey privateKey,
                                           String inputFile)	throws Exception {
		SecretKey skey = getKeyAES();
		byte[] iv = new byte[KEY_SIZE_AES/8];
		srandom.nextBytes(iv);
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		try (FileOutputStream out = new FileOutputStream(inputFile + ".enc")) {
			{
				Cipher cipher = Cipher.getInstance(CIPHER_RSA);
				cipher.init(Cipher.ENCRYPT_MODE, privateKey);
				byte[] b = cipher.doFinal(skey.getEncoded());
				out.write(b);
				//System.err.println("AES Key Length: " + b.length);
			}
			out.write(iv);
			//System.err.println("IV Length: " + iv.length);
			Cipher ci = Cipher.getInstance(CIPHER_AES);
			ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
			try (FileInputStream in = new FileInputStream(inputFile)) {
				processFile(ci, in, out);
			}
		}
	}

	/**
	 * Decrypt file content using a combination of 
	 * AES encryption and RSA encryption
	 * 
	 * @param publicKey
	 * 		  the public key		  
	 * @param inputFile
	 *        the input file name                                    
	 * @throws Exception
	 */	
	public static void doDecryptRSAWithAES(PublicKey publicKey, String inputFile)
			throws Exception {
		try (FileInputStream in = new FileInputStream(inputFile)) {
			SecretKeySpec skey = null;
			{
				Cipher cipher = Cipher.getInstance(CIPHER_RSA);
				cipher.init(Cipher.DECRYPT_MODE, publicKey);
				byte[] b = new byte[256];
				in.read(b);
				byte[] keyb = cipher.doFinal(b);
				skey = new SecretKeySpec(keyb, "AES");
			}
			byte[] iv = new byte[KEY_SIZE_AES/8];
			in.read(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher ci = Cipher.getInstance(CIPHER_AES);
			ci.init(Cipher.DECRYPT_MODE, skey, ivspec);
			try (FileOutputStream out = new FileOutputStream(inputFile+".ver")){
				processFile(ci, in, out);
			}
		}
	}
	
	/**
	 * Encrypt a string message 
	 * using the public key
	 * 
	 * @param plainText
	 *        the string message 
	 * @param public Key
	 * 		  the public key	
	 * @return the cipher message
	 * @throws Exception
	 */	
	public static String doEncryptString(String plainText,
                                         PublicKey publicKey) throws Exception {
		Cipher encryptCipher = Cipher.getInstance(CIPHER_RSA);
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] cipherText = encryptCipher.doFinal(plainText.getBytes("UTF8"));
		return Base64.getEncoder().encodeToString(cipherText);
	}

	/**
	 * Decrypt an encrypted message 
	 * using the private key
	 * 
	 * @param cipherText
	 *        the encrypted message
	 * @param private Key
	 * 		  the private key	
	 * @return the decrypted message
	 * @throws Exception
	 */	
	public static String doDecryptString(String cipherText,
                                         PrivateKey privateKey) throws Exception {
		byte[] bytes = Base64.getDecoder().decode(cipherText);
		Cipher decriptCipher = Cipher.getInstance(CIPHER_RSA);
		decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
		return new String(decriptCipher.doFinal(bytes), "UTF8");
	}

	/**
	 * Sign a string message
	 * 
	 * @param plainText
	 *        the string message 
	 * @param privateKey
	 * 		  the private key
	 * @return the signature
	 * @throws Exception
	 */	
	public static String signString(String plainText,
                                    PrivateKey privateKey) throws Exception {
		Signature privateSignature = Signature.getInstance(SIGNATUE_ALGORITHM);
		privateSignature.initSign(privateKey);
		privateSignature.update(plainText.getBytes("UTF8"));
		byte[] signature = privateSignature.sign();	
		String signatureStr = Base64.getEncoder().encodeToString(signature);
		FileUtils.saveStrToFile(signatureStr, "message.signature");
		return signatureStr;
	}	

	/**
	 * Sign a file 
	 * 
	 * @param fileName
	 *        the file name to read 
	 * @param privateKey
	 * 		  the private key	
	 * @return the signature
	 * @throws Exception
	 */	
	public static String signFile(String fileName,
                                  PrivateKey privateKey) throws Exception {
		Signature privateSignature = Signature.getInstance(SIGNATUE_ALGORITHM);
		privateSignature.initSign(privateKey);   
		FileInputStream fis = new FileInputStream(fileName);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while (bufin.available() != 0) {
			len = bufin.read(buffer);
			privateSignature.update(buffer, 0, len);
		};
		bufin.close();
		byte[] signature = privateSignature.sign();
		String signatureStr = Base64.getEncoder().encodeToString(signature);
		FileUtils.saveStrToFile(signatureStr, fileName+".signature");
		return signatureStr;
	}

	/**
	 * Verify a string message using a signature file
	 * 
	 * @param plainText
	 *        the message to read 
	 * @param signatureFile
	 * 		  the signature file name       
	 * @param publicKey
	 * 		  the public key	
	 * @return true or false
	 * @throws Exception
	 */	
	public static boolean verifyString(String plainText,
                                       String signatureFile, PublicKey publicKey) throws Exception {
		String signature = FileUtils.readSimpleFileToString(signatureFile, "UTF8");
		Signature publicSignature = Signature.getInstance(SIGNATUE_ALGORITHM);
		publicSignature.initVerify(publicKey);
		publicSignature.update(plainText.getBytes("UTF8"));
		byte[] signatureBytes = Base64.getDecoder().decode(signature);
		boolean verifies = publicSignature.verify(signatureBytes);
		return verifies;
	}

	/**
	 * Verify a string message using a signature string
	 * 
	 * @param plainText
	 *        the message to read 
	 * @param signatureFile
	 * 		  the signature      
	 * @param publicKey
	 * 		  the public key	
	 * @return true or false
	 * @throws Exception
	 */	
	public static boolean verifyStringUsingSignatureStr(String plainText,
                                                        String signature, PublicKey publicKey) throws Exception {
		Signature publicSignature = Signature.getInstance(SIGNATUE_ALGORITHM);
		publicSignature.initVerify(publicKey);
		publicSignature.update(plainText.getBytes("UTF8"));
		byte[] signatureBytes = Base64.getDecoder().decode(signature);
		boolean verifies = publicSignature.verify(signatureBytes);
		return verifies;
	}

	/**
	 * Verify a file using a signature file
	 * 
	 * @param fileName
	 *        the file name to read 
	 * @param signatureFile
	 * 		  the signature file name       
	 * @param publicKey
	 * 		  the public key	
	 * @return true or false
	 * @throws Exception
	 */		
	public static boolean verifyFile(String fileName,
                                     String signatureFile, PublicKey publicKey) throws Exception {
		String signature = FileUtils.readSimpleFileToString(signatureFile, "UTF8");
		Signature publicSignature = Signature.getInstance(SIGNATUE_ALGORITHM);
		publicSignature.initVerify(publicKey);
		byte[] signatureBytes = Base64.getDecoder().decode(signature);
		FileInputStream fis = new FileInputStream(fileName);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while (bufin.available() != 0) {
			len = bufin.read(buffer);
			publicSignature.update(buffer, 0, len);
		};
		bufin.close();
		boolean verifies = publicSignature.verify(signatureBytes);
		return verifies;
	}

	/**
	 * Verify a file using a signature string
	 * 
	 * @param fileName
	 *        the file name to read 
	 * @param signatureFile
	 * 		  the signature file name       
	 * @param publicKey
	 * 		  the public key	
	 * @return true or false
	 * @throws Exception
	 */		
	public static boolean verifyFileUsingSignatureStr(String fileName,
                                                      String signature, PublicKey publicKey) throws Exception {
		Signature publicSignature = Signature.getInstance(SIGNATUE_ALGORITHM);
		publicSignature.initVerify(publicKey);
		byte[] signatureBytes = Base64.getDecoder().decode(signature);
		FileInputStream fis = new FileInputStream(fileName);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while (bufin.available() != 0) {
			len = bufin.read(buffer);
			publicSignature.update(buffer, 0, len);
		};
		bufin.close();
		boolean verifies = publicSignature.verify(signatureBytes);
		return verifies;
	}
	
	/**
	 * Generate a string hash
	 * 
	 * @param str
	 * 		  the string to read
	 * @param hashFunction
	 *        the cryptographic hash function    
	 * @return the hash hexadecimal representation using lower-case chars 
	 * @throws Exception
	 */
	public static String getStringHash(String str, String hashFunction) throws Exception {
		MessageDigest md = MessageDigest.getInstance(hashFunction);
		md.reset();
		md.update(str.getBytes("UTF8"));
		return String.format("%040x", new BigInteger(1, md.digest()));
	}

	/**
	 * Generate a file hash
	 * 
	 * @param fileName
	 *        the file name to read
	 * @param hashFunction
	 *        the cryptographic hash function 
	 * @return the hash hexadecimal representation using lower-case chars
	 * @throws Exception
	 * 
	 */
	public static String getFileHash(String fileName, String hashFunction) throws Exception {
		File file = new File(fileName);
		MessageDigest md = MessageDigest.getInstance(hashFunction);
		FileInputStream is = new FileInputStream(file);
		byte[] buffer = new byte[8192];
		int len = is.read(buffer);
		while (len != -1) {
			md.update(buffer, 0, len);
			len = is.read(buffer);
		}
		is.close();
		return String.format("%040x", new BigInteger(1, md.digest()));
	}	
}
