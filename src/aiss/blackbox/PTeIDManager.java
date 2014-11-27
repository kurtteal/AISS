package aiss.blackbox;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;

import pteidlib.PTEID_Certif;
import pteidlib.PteidException;
import pteidlib.pteid;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class PTeIDManager {
	
	private static String libName;

	public PTeIDManager() {
		try {
			System.loadLibrary("pteidlibj");
			String OS = System.getProperty("os.name").toLowerCase();
			// WINDOWS
			if(OS.indexOf("win") >= 0)
				PTeIDManager.libName = "pteidpkcs11.dll";
			// MAC OS
			if(OS.indexOf("mac") >= 0)
				PTeIDManager.libName = "/usr/local/lib/pteidpkcs11.dylib";
			// LINUX/UNIX
			if(OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0)
				PTeIDManager.libName = "/usr/local/lib/libpteidpkcs11.so";
		} catch (UnsatisfiedLinkError e) {
			System.err.println("Native code library failed to load.\n" + e);
			System.exit(1);
		}
	}

	public byte[] getCitizenAuthCertInBytes() {
		// Certificado 0 no CC e o de autenticacao
		return getCertificateInBytes(0);
	}

	private byte[] getCertificateInBytes(int n) {
		byte[] certificate_bytes = null;
		try {
			PTEID_Certif[] certs = pteid.GetCertificates();
			certificate_bytes = certs[n].certif;
		} catch (PteidException e) {
			e.printStackTrace();
		}
		return certificate_bytes;
	}

	public X509Certificate getCertFromByteArray(byte[] certificateEncoded)
			throws CertificateException {
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(certificateEncoded);
		X509Certificate cert = (X509Certificate) f.generateCertificate(in);
		return cert;
	}

	public byte[] sign(byte[] data) {
		try {
			PKCS11 pkcs11 = PKCS11.getInstance(libName, "C_GetFunctionList",
					new CK_C_INITIALIZE_ARGS(), false);

			// Open the PKCS11 session
			long p11_session = pkcs11.C_OpenSession(0,
					PKCS11Constants.CKF_SERIAL_SESSION, null, null);

			// Token login - 3rd argument is an array with the PIN
			pkcs11.C_Login(p11_session, PKCS11Constants.CKU_USER, null);

			// Get available keys
			CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[] { new CK_ATTRIBUTE(
					PKCS11Constants.CKA_CLASS, new Long(
							PKCS11Constants.CKO_PRIVATE_KEY)) };

			pkcs11.C_FindObjectsInit(p11_session, attributes);
			
			// Gets private keys
			long[] keyHandles = pkcs11.C_FindObjects(p11_session, 5);
			
			// Gets the authorization private key
			long signatureKey = keyHandles[0]; // 0- autenticacao; 1- assinatura
			pkcs11.C_FindObjectsFinal(p11_session);
			
			// Initialize the signature method
			CK_MECHANISM mechanism = new CK_MECHANISM(
					PKCS11Constants.CKM_SHA1_RSA_PKCS, (byte[]) null);
			pkcs11.C_SignInit(p11_session, mechanism, signatureKey);

			// Perform the signature
			byte[] signed_bytes = pkcs11.C_Sign(p11_session, data);
			
			pkcs11.C_Logout(p11_session);
			pkcs11.C_CloseSession(p11_session);
			
			return signed_bytes;
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (PKCS11Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public boolean verifySignature(PublicKey pubkey, String filepath, String signpath) {
		try {
			// Initialize the signature object.
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(pubkey);
			
			// Get the file.
			FileInputStream fisData = new FileInputStream(filepath);
			byte [] dataBytes = new byte[fisData.available()];
			fisData.read(dataBytes);
			signature.update(dataBytes);
			fisData.close();
			
			// Get the signature.
			FileInputStream fisSign = new FileInputStream(signpath);
			byte [] encodedbytes = new byte[fisSign.available()];
			fisSign.read(encodedbytes);
			byte [] sigbytes = Base64.decodeBase64(encodedbytes);
			fisSign.close();
			
			// Verify the signature.
			return signature.verify(sigbytes);
		} catch (InvalidKeyException e) {
			System.err.println("DEBUG: Invalid public key.");
		} catch (NoSuchAlgorithmException e) {
			// Nunca deve chegar aqui.
		} catch (SignatureException e) {
			System.err.println("DEBUG: Signature isn't properly encoded or is the wrong type.");
		} catch (FileNotFoundException fnfe) {
			System.out.println("DEBUG: " + filepath + " (or it's signature) is missing.");
		} catch (IOException ioe) {
			System.out.println("DEBUG: An error occurred while verifying the file's signature.");
		}
		return false;
	}

	public void initPteid() {
		try {
			// OBRIGATORIO Inicia a eID Lib
			pteid.Init("");
			// Don't check the integrity of the ID, address and photo (!)
			pteid.SetSODChecking(false);
		} catch (PteidException e) {
			e.printStackTrace();
		}
	}

	public void closePteid() {
		try {
			// OBRIGATORIO Termina a eID Lib
			pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD);
		} catch (PteidException e) {
			e.printStackTrace();
		}
	}

}
