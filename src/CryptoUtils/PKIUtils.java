/**
 * 
 * Description:
 * Class containing methods related to 
 * PKI (Public Key Infrastructure)
 * 
 * Version: 
 * 04.2019
 * 
 * Author: 
 * Jose G. Faisca <jose.faisca@gmail.com>
 * 
 */

package CryptoUtils;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;

public class PKIUtils {	

	public static KeyStore KEY_STORE;
	public static String KEY_ALIAS;

	/**
	 * Generate a public/private key pair
	 * 
	 * @param keyAlg 
	 *        the key cryptographic algorithm name (RSA, DSA, EC,..) 
	 * @param keySize 
	 *        the number of bits in the key (1024 to 4096 bit typical)             
	 * @return the key pair                
	 * @throws Exception
	 */	
	public static KeyPair generateKeyPair(String keyAlg, int keySize) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlg);
		generator.initialize(keySize, new SecureRandom());
		KeyPair pair = generator.generateKeyPair();
		return pair;
	}

	/**
	 * Get keystore alias
	 * 
	 * @param keyStore
	 *        the keystore to read  
	 * @return the keystore alias                
	 * @throws Exception
	 */	
	public static String getKeyStoreAlias(KeyStore keyStore) throws Exception {
		Enumeration<String> aliasenum = null;
		aliasenum = keyStore.aliases();
		String keyAlias = null;
		if (aliasenum.hasMoreElements()) {
			keyAlias = aliasenum.nextElement();
		}
		return keyAlias;
	}	

	/**
	 * Get a public/private key pair from keystore
	 * 
	 * @param fileName
	 *        the keystore file name to read
	 * @param storePassword
	 *        the keystore password    
	 * @param keyPassword
	 *        the key password                
	 * @return the key pair                
	 * @throws Exception
	 */	
	public static KeyPair getKeyPairFromKeyStore(String fileName,
                                                 String storePassword, String keyPassword) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		FileInputStream fis = new FileInputStream(fileName);
		BufferedInputStream bis = new BufferedInputStream(fis);
		keyStore.load(bis, storePassword.toCharArray());
		String keyAlias = getKeyStoreAlias(keyStore);
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias,keyPassword.toCharArray());
		Certificate cert = keyStore.getCertificate(keyAlias);
		PublicKey publicKey = cert.getPublicKey();
		KEY_STORE = keyStore;
		KEY_ALIAS = keyAlias;
		return new KeyPair(publicKey, privateKey);
	}

	/**
	 * Save keystore certificate to a DER (binary) file 
	 *
	 * @param keyStore
	 *        the keystore to read 
	 * @param fileName
	 *        the name of the destination DER file for the certificate                            
	 * @throws Exception
	 */	
	public static void saveCertificateToDERFile(KeyStore keyStore, String fileName) throws Exception {
		Certificate cert = keyStore.getCertificate(KEY_ALIAS);
		byte[] bytes = cert.getEncoded();
		FileOutputStream out = new FileOutputStream(fileName);
		out.write(bytes);
		out.close();
	}		

	/**
	 * Save public key to a DER (binary) file 
	 *
	 * @param publicKey
	 *        the public key to read 
	 * @param fileName
	 *        the name of the destination DER file for the public key                          
	 * @throws Exception
	 */	
	public static void savePublicKeyToDERFile(PublicKey publicKey,
                                              String fileName) throws Exception {
		byte[] bytes = publicKey.getEncoded();
		FileOutputStream out = new FileOutputStream(fileName);
		out.write(bytes);
		out.close();
	}

	/**
	 * Get public key from a DER (binary) file
	 * 
	 * @param fileName
	 *        the public key DER file name to read
	 * @return the public key
	 * @throws Exception
	 */	
	public static PublicKey getPublicKeyFromDERFile(String fileName) throws Exception {
		FileInputStream is = new FileInputStream(fileName);
		byte[] encodedBytes = new byte[is.available()];  
		is.read(encodedBytes);
		is.close();
		X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(spec);
		return publicKey;      
	}  	

	/**
	 * Get public key from PEM (Base64) certificate file
	 * 
	 * @param fileName
	 *        the certificate PEM file name to read
	 * @return the public key
	 * @throws Exception
	 */	
	public static PublicKey getPublicKeyFromCertPEMFile(String fileName) throws Exception {
		String certPEM = FileUtils.readFileToString(fileName,"UTF8");
		certPEM = certPEM
				.replace("-----BEGIN CERTIFICATE-----\n", "")
				.replace("-----END CERTIFICATE-----", "")
				.replaceAll("\\s", "");	
		byte[] decodedBytes = Base64.getDecoder().decode(certPEM);
		ByteArrayInputStream bis  =  new ByteArrayInputStream(decodedBytes);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate)certFactory.generateCertificate(bis);
		bis.close();
		PublicKey publicKey = cert.getPublicKey();
		return publicKey;          
	}	

	/**
	 * Get public key from PEM (Base64) public key file
	 * 
	 * @param fileName
	 *        the public key PEM file name to read
	 * @return the public key
	 * @throws Exception
	 */	
	public static PublicKey getPublicKeyFromPEMFile(String fileName) throws Exception {
		String publicKeyPEM = FileUtils.readFileToString(fileName,"UTF8");
		publicKeyPEM = publicKeyPEM
				.replace("-----BEGIN PUBLIC KEY-----\n", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\\s", "");			
		byte[] decodedBytes = Base64.getDecoder().decode(publicKeyPEM);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(spec);
		return publicKey;         
	}

	/**
	 * Get private key from PEM (Base64) private key file
	 * 
	 * @param fileName
	 *        the name of the PEM private key file to read
	 * @return the private key
	 * @throws Exception
	 */		
	public static PrivateKey getPrivateKeyFromPEMFile(String fileName) throws Exception {
		String privateKeyPEM = FileUtils.readFileToString(fileName,"UTF8");;
		// strip of header, footer, newlines, whitespaces
		privateKeyPEM = privateKeyPEM
				.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "")
				.replaceAll("\\s", "");
		byte[] decodedBytes = Base64.getDecoder().decode(privateKeyPEM);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedBytes);
		PrivateKey privateKey = keyFactory.generatePrivate(spec);
		return privateKey;
	}

	/**
	 * Save certificate from keystore to PEM (Base64) file
	 * 
	 * @param keyStore
	 *        the keystore to read
	 * @param fileName
	 *        the name of the destination PEM file for the certificate                
	 * @throws Exception
	 */	
	public static void saveCerificateToPEMFile(KeyStore keyStore, String fileName) throws Exception {
		X509Certificate cert = (X509Certificate) keyStore.getCertificate(KEY_ALIAS);
		byte[] encodedCert = cert.getEncoded();
		String b64Cert = Base64.getMimeEncoder().encodeToString(encodedCert);
		String beginStr = "-----BEGIN CERTIFICATE-----\n";
		String endStr = "\n-----END CERTIFICATE-----";
		FileUtils.saveStrToFile(beginStr+b64Cert+endStr, fileName);    
	}	

	/**
	 * Save certificate to PEM (Base64) file
	 * 
	 * @param cert
	 *        the X509 certificate
	 * @param fileName
	 *        the name of the destination PEM file for the certificate                
	 * @throws Exception
	 */	
	public static void saveX509CertificateToPEMFile(X509Certificate cert, String fileName) throws Exception {
		byte[] encodedCert = cert.getEncoded();
		String b64Cert = Base64.getMimeEncoder().encodeToString(encodedCert);
		String beginStr = "-----BEGIN CERTIFICATE-----\n";
		String endStr = "\n-----END CERTIFICATE-----";
		FileUtils.saveStrToFile(beginStr+b64Cert+endStr, fileName);    
	}	

	/**
	 * Save certificate to DER (binary) file
	 * 
	 * @param cert
	 *        the X509 certificate
	 * @param fileName
	 *        the name of the destination DER file for the certificate                
	 * @throws Exception
	 */	
	public static void saveX509CertificateToDERFile(X509Certificate cert, String fileName) throws Exception {
		byte[] encodedCert = cert.getEncoded();
		FileOutputStream out = new FileOutputStream(fileName);
		out.write(encodedCert);
		out.close();   
	}	

	/**
	 * Save certificate to PEM (Base64) file
	 * 
	 * @param cert
	 *        the X509 certificate
	 * @param fileName
	 *        the name of the destination PEM file for the certificate                
	 * @throws Exception
	 */	
	public static void saveCerificateToPEMFile(X509Certificate cert, String fileName) throws Exception {
		byte[] encodedCert = cert.getEncoded();
		String b64Cert = Base64.getMimeEncoder().encodeToString(encodedCert);
		String beginStr = "-----BEGIN CERTIFICATE-----\n";
		String endStr = "\n-----END CERTIFICATE-----";
		FileUtils.saveStrToFile(beginStr+b64Cert+endStr, fileName);    
	}	

	/**
	 * Save public key to PEM (Base64) file
	 * 
	 * @param publicKey
	 *        the public key to read 
	 * @param fileName
	 *         the name of the destination PEM file for the public key                      
	 * @throws Exception
	 */	
	public static void savePublicKeyToPEMFile(PublicKey publicKey, String fileName) throws Exception {
		byte[] encodedPublicKey = publicKey.getEncoded();
		String b64PublicKey = Base64.getMimeEncoder().encodeToString(encodedPublicKey);
		String beginStr = "-----BEGIN PUBLIC KEY-----\n";
		String endStr = "\n-----END PUBLIC KEY-----";
		FileUtils.saveStrToFile(beginStr+b64PublicKey+endStr, fileName);  
	}	

	/**
	 * Save private key to PEM (Base64) file
	 * 
	 * @param privateKey
	 *        the private key 
	 * @param fileName
	 *        the name of the destination PEM file for the private key             
	 * @throws Exception
	 */	
	public static void savePrivateKeyToPEMFile(PrivateKey privateKey, String fileName) throws Exception {
		byte[] encodedPrivateKey = privateKey.getEncoded();
		String b64PrivateKey = Base64.getMimeEncoder().encodeToString(encodedPrivateKey);
		String beginStr = "-----BEGIN PRIVATE KEY-----\n";
		String endStr = "\n-----END PRIVATE KEY-----";
		FileUtils.saveStrToFile(beginStr+b64PrivateKey+endStr, fileName);  
	}	

	/**
	 * Save public key from keystore to PEM (Base64) file
	 * 
	 * @param keyStore
	 *        the keystore to read  
	 * @param fileName
	 *        the name of the destination PEM file for the public key                       
	 * @throws Exception
	 */	
	public static void savePublicKeyToPEMFile(KeyStore keyStore, String fileName) throws Exception {
		X509Certificate cert = (X509Certificate) keyStore.getCertificate(KEY_ALIAS);
		PublicKey publicKey = cert.getPublicKey();
		byte[] encodedPublicKey = publicKey.getEncoded();
		String b64PublicKey = Base64.getMimeEncoder().encodeToString(encodedPublicKey);
		String beginStr = "-----BEGIN PUBLIC KEY-----\n";
		String endStr = "\n-----END PUBLIC KEY-----";
		FileUtils.saveStrToFile(beginStr+b64PublicKey+endStr, fileName);  
	}		

	/**
	 * Get certificate fingerprint from PEM (Base64) / DER (binary) file
	 * 
	 * @param fileName
	 *        the certificate PEM/DER file name to read
	 * @param hashFunction
	 *        the cryptographic hash function (SHA1, SHA256,..)             
	 * @return the certificate fingerprint
	 * @throws Exception
	 */	
	public static String getFingerprintFromCertFile(String fileName, String hashFunction) throws Exception {
		FileInputStream is = new FileInputStream(fileName);
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(is);
		is.close();		
		if(cert != null) {	
			MessageDigest md = MessageDigest.getInstance(hashFunction);
			byte[] der = cert.getEncoded();
			md.update(der);
			return String.format("%040x", new BigInteger(1, md.digest()));
		} else {
			return null;
		}
	}	

	/**
	 * Get certificate fingerprint from keystore
	 * 
	 * @param keyStore
	 *        the keystore to read 
	 * @param hashFunction
	 *        the cryptographic hash function (SHA1, SHA256,..)          
	 * @return the certificate fingerprint
	 * @throws Exception
	 */	
	public static String getFingerprintFromKeyStore(KeyStore keyStore, String hashFunction) throws Exception {
		X509Certificate cert = (X509Certificate) keyStore.getCertificate(KEY_ALIAS);
		if(cert != null) {	
			MessageDigest md = MessageDigest.getInstance(hashFunction);
			byte[] der = cert.getEncoded();
			md.update(der);
			return String.format("%040x", new BigInteger(1, md.digest()));
		} else {
			return null;
		}
	}  

	/**
	 * Get public key modulus
	 * 
	 * @param publicKey
	 *        the public key        
	 * @return the public key modulus
	 * @throws Exception
	 */	
	public static String getModulus(PublicKey publicKey) throws Exception {
		String mod = ((RSAPublicKey) publicKey).getModulus().toString(16);
		return mod;
	}  

	/**
	 * Get public key exponent
	 * 
	 * @param publicKey
	 *        the public key        
	 * @return the public key exponent
	 * @throws Exception
	 */	
	public static String geExponent(PublicKey pub) throws Exception {
		String exp = ((RSAPublicKey) pub).getPublicExponent().toString(10);
		return exp;
	}  	

}
