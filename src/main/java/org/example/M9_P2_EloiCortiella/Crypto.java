package org.example.M9_P2_EloiCortiella;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.util.Arrays;

public class Crypto {

	public SecretKey keygenKeyGeneration(int keySize) {
		SecretKey sKey = null;
		if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
			try {
				KeyGenerator kgen = KeyGenerator.getInstance("AES");
				kgen.init(keySize);
				sKey = kgen.generateKey();
			} catch (NoSuchAlgorithmException ex) {
				System.err.println("Generador no disponible.");
			}
		}
		return sKey;
	}
	
	public SecretKey passwordKeyGeneration(String text, int keySize) {
		SecretKey sKey = null;
		if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
			try {
				byte[] data = text.getBytes("UTF-8");
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				byte[] hash = md.digest(data);
				byte[] key = Arrays.copyOf(hash, keySize/8);
				sKey = new SecretKeySpec(key, "AES");
			} catch (Exception ex) {
				System.err.println("Error generant la clau:" + ex);
			}
		}
		return sKey;
	}
	
	public byte[] encryptData(SecretKey sKey, byte[] data) {
		byte[] encryptedData = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, sKey);
			encryptedData = cipher.doFinal(data);
		} catch (Exception ex) {
			System.err.println("Error xifrant les dades: " + ex);
		}
		return encryptedData;
	}
	
	//Definici� d�un IV est�tic. Per l�AES ha der ser de 16 bytes (un bloc)
	public static final byte[] IV_PARAM = {	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
											0x08, 0x09, 0x0A, 0x0B,	0x0C, 0x0D, 0x0E, 0x0F};

	public byte[] encryptDataCBC(SecretKey sKey, byte[] data) {
		byte[] encryptedData = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec iv = new IvParameterSpec(IV_PARAM);
			cipher.init(Cipher.ENCRYPT_MODE, sKey, iv);
			encryptedData = cipher.doFinal(data);
		} catch (Exception ex) {
			System.err.println("Error xifrant les dades: " + ex);
		}
		return encryptedData;
	}
	
	public KeyPair randomGenerate(int len) {
	    KeyPair keys = null;
	    try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(len);
			keys = keyGen.genKeyPair();      
	    } catch (Exception ex) {
	    	System.err.println("Generador no disponible.");
	    }
	    return keys;
	}
	
	public byte[] encryptData(byte[] data, PublicKey pub) {
	    byte[] encryptedData = null;    
	    try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
			cipher.init(Cipher.ENCRYPT_MODE, pub);      
			encryptedData =  cipher.doFinal(data);       
	    } catch (Exception  ex) {  
	    	System.err.println("Error xifrant: " + ex);
	    }
	    return encryptedData;
	}
	
	public byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
	    byte[][] encWrappedData = new byte[2][];
	    try {
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128);      
			SecretKey sKey = kgen.generateKey();
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, sKey);
			byte[] encMsg = cipher.doFinal(data);
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.WRAP_MODE, pub);
			byte[] encKey = cipher.wrap(sKey);
			encWrappedData[0] = encMsg;
			encWrappedData[1] = encKey;      
	    } catch (Exception  ex) {  
	    	System.err.println("Ha succe�t un error xifrant: " + ex);
	    }
	    return encWrappedData;
	}

	// Metode per embolcallar fent servir una clau simetrica generada externament
	public byte[][] encryptWrappedDataExternalKey(byte[] data, SecretKey sKey, PublicKey pub ) {
	    byte[][] encWrappedData = new byte[2][];
	    try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, sKey);
			byte[] encMsg = cipher.doFinal(data);
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.WRAP_MODE, pub);
			byte[] encKey = cipher.wrap(sKey);
			encWrappedData[0] = encMsg;
			encWrappedData[1] = encKey;      
	    } catch (Exception  ex) {  
	    	System.err.println("Ha succe�t un error xifrant: " + ex);
	    }
	    return encWrappedData;
	}

	public byte[] signData(byte[] data, PrivateKey priv) {
		byte[] signature = null;
		try {
			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initSign(priv);
			signer.update(data);
			signature = signer.sign();
		} catch (Exception ex) {
			System.err.println("Error signant les dades: " + ex);
		}
		return signature;
	}
	
	public boolean validateSignature(byte[] data, byte[] signature, PublicKey pub)
	{
		boolean isValid = false;
		try {
			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initVerify(pub);
			signer.update(data);
			isValid = signer.verify(signature);
		} catch (Exception ex) {
			System.err.println("Error validant les dades: " + ex);
		}
		return isValid;
	}
	
	public KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
		KeyStore ks = KeyStore.getInstance("JCEKS");
		File f = new File (ksFile);
		if (f.isFile()) {
			FileInputStream in = new FileInputStream (f);
			ks.load(in, ksPwd.toCharArray());
		}
		return ks;
	}
}

