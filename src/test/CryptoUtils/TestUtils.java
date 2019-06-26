/**
 * 
 * Description:
 * Class to test Java PKI keys, PEM/Base64 certificates, 
 * cryptographic algorithms, hash functions, digital 
 * signatures and Unix time
 * 
 * Version: 
 * 04.2019
 * 
 * Author: 
 * Jose G. Faisca <jose.faisca@gmail.com>
 * 
 */

package test.CryptoUtils;

import CryptoUtils.CryptoUtils;
import CryptoUtils.PKIUtils;
import CryptoUtils.TimeUtils;

import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyStore;

public class TestUtils {

	private static String HASH_FUNCTION = "SHA1";

	public static void main(String[] args) throws Exception {

		// Generate a public/private key pair
		//KeyPair pair = generateKeyPair("RSA","2048");

		// Check arguments
		if (args.length != 3) {
			System.out.println("Usage: TestUtils <keypair_fileName> <storePassword> <keyPassword>");
			System.exit(1);
		}

		// Get KeyPair from KeyStore 
		KeyPair pair = PKIUtils.getKeyPairFromKeyStore(args[0],args[1],args[2]);
		KeyStore key_store = PKIUtils.KEY_STORE;
		String key_alias = PKIUtils.KEY_ALIAS;

		// Save private key to (X.509) PEM file
		PKIUtils.savePrivateKeyToPEMFile(pair.getPrivate(), key_alias+"privateKey.pem");

		// Save public key to (X.509) PEM file
		PKIUtils.savePublicKeyToPEMFile(pair.getPublic(), key_alias+"publicKey.pem");

				// Save public key to binary file
		PKIUtils.savePublicKeyToDERFile(pair.getPublic(), key_alias+"publicKey.der");		

		// Save certificate to (X.509) PEM file
		PKIUtils.saveCerificateToPEMFile(key_store, key_alias+"cert.pem");
	
		// Save certificate to encoded file
		PKIUtils.saveCertificateToDERFile(key_store, key_alias+"cert.der");

		// data file 1
		String data1Txt = "data1.txt";
		PrintWriter writer = new PrintWriter(data1Txt, "UTF8");
		writer.println("0123456789");
		writer.println("abcdefghij");
		writer.println("-#$%&/*=?+");
		writer.close();

		// data file 2
		String data2Txt = "data2.txt";

		// message
		String message = "9876543210";
		// Print the message
		System.out.println(message);

		// Encrypt a message
		String cipherText = CryptoUtils.doEncryptString(message, pair.getPublic());
		// Now decrypt it
		String decipheredMessage = CryptoUtils.doDecryptString(cipherText, pair.getPrivate());
		// Print deciphered message
		System.out.println(decipheredMessage);

		// Encrypt/decrypt a file using RSA
		CryptoUtils.doEncrypt(pair.getPrivate(), data2Txt);
		CryptoUtils.doDecrypt(pair.getPublic(), data2Txt+".enc");

		// Encrypt/decrypt a file using RSA with AES
		CryptoUtils.doEncryptRSAWithAES(pair.getPrivate(), data2Txt);
		CryptoUtils.doDecryptRSAWithAES(pair.getPublic(), data2Txt+".enc");

		// Sign string message        
		String signatureStr1 = CryptoUtils.signString(message, pair.getPrivate());
		System.out.println("Signature " + message + " : " + signatureStr1);
		// Check the message signature 		
		boolean isCorrect1 = CryptoUtils.verifyString(message, "message.signature", pair.getPublic());        
		System.out.println("Signature correct: " + isCorrect1);

		// Sign file 
		String signatureStr2 = CryptoUtils.signFile(data1Txt, pair.getPrivate());
		System.out.println("Signature " + data1Txt + " : " + signatureStr2);
		// Check the file signature		
		boolean isCorrect2 = CryptoUtils.verifyFile(data1Txt, data1Txt+".signature", pair.getPublic());
		System.out.println("Signature correct: " + isCorrect2);

		// Get public key exponent
		System.out.println("Exponent: " + PKIUtils.geExponent(pair.getPublic()));
		System.out.println("Exponent: " + PKIUtils.geExponent(PKIUtils.getPublicKeyFromPEMFile(key_alias+"publicKey.pem")));
		System.out.println("Exponent: " + PKIUtils.geExponent(PKIUtils.getPublicKeyFromDERFile(key_alias+"publicKey.der")));

		// Get public key modulus
		System.out.println("Modulus: " + PKIUtils.getModulus(pair.getPublic()));
		System.out.println("Modulus: " + PKIUtils.getModulus(PKIUtils.getPublicKeyFromPEMFile(key_alias+"publicKey.pem")));
		System.out.println("Modulus: " + PKIUtils.getModulus(PKIUtils.getPublicKeyFromCertPEMFile(key_alias+"cert.pem")));
		System.out.println("Modulus: " + PKIUtils.getModulus(PKIUtils.getPublicKeyFromDERFile(key_alias+"publicKey.der")));

		// Get certificate fingerprint
		/*
		 * SHA-1 Certificate Fingerprint (openssl)
		 * $ keytool -list -keystore keypair.jks
		 * $ keytool -exportcert -alias 1 -keystore keypair.jks -rfc -file publicKey.pem
		 * $ openssl x509 -noout -fingerprint -sha1 -inform pem -in publicKey.pem
		 */
		System.out.println(HASH_FUNCTION+ " Fingerprint: "+ PKIUtils.getFingerprintFromKeyStore(key_store, HASH_FUNCTION));
		System.out.println(HASH_FUNCTION+ " Fingerprint: "+ PKIUtils.getFingerprintFromCertFile(key_alias+"cert.pem", HASH_FUNCTION));
		System.out.println(HASH_FUNCTION+ " Fingerprint: "+ PKIUtils.getFingerprintFromCertFile(key_alias+"cert.der", HASH_FUNCTION));
		
		// Get Hash
		System.out.println(HASH_FUNCTION+" "+ data1Txt + " :" + CryptoUtils.getFileHash(data1Txt, HASH_FUNCTION));
		System.out.println(HASH_FUNCTION+" "+ message + " :" + CryptoUtils.getStringHash(message, HASH_FUNCTION));
		System.out.println(HASH_FUNCTION+" "+ key_alias+"cert.der" + " :" + CryptoUtils.getFileHash(key_alias+"cert.der", HASH_FUNCTION));

		// Unix time
		long ut = TimeUtils.unixTime();
		System.out.println("Unix time : "+ ut );

		// Convert unix time to date using Greenwich Mean Time (GMT+1) time zone
		System.out.println("Date : "+ TimeUtils.unixTimeToDate(ut,"GMT+1"));
	}	

}