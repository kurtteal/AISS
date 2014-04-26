package aiss;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
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

import pteidlib.PTEID_ADDR;
import pteidlib.PTEID_Certif;
import pteidlib.PTEID_ID;
import pteidlib.PTEID_PIC;
import pteidlib.PTEID_Pin;
import pteidlib.PTEID_TokenInfo;
import pteidlib.PteidException;
import pteidlib.pteid;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class PteidManager implements IAuthenticator, IRequester {

	// Faz o load da library no construtor
	public PteidManager() {
		try {
			System.loadLibrary("pteidlibj");
		} catch (UnsatisfiedLinkError e) {
			System.err.println("Native code library failed to load.\n" + e);
			System.exit(1);
		}
	}
	
//	public PublicKey getPublicKey() throws CertificateException{
//		return getCertFromByteArray(getCitizenAuthCertInBytes()).getPublicKey();
//	}
	
	//Queremos o certificado de autenticacao (CITIZEN AUTHENTICATION CERTIFICATE)
	public byte[] getCitizenAuthCertInBytes(){
		return getCertificateInBytes(0); //certificado 0 no Cartao do Cidadao eh o de autenticacao
	}
	
	// Returns the n-th certificate, starting from 0
	private byte[] getCertificateInBytes(int n) {
		byte[] certificate_bytes = null;
		try {
			//pteid.Init(""); // OBRIGATORIO Inicia a eID Lib
			//pteid.SetSODChecking(false); // Don't check the integrity of the ID,
											// address and photo (!)
			// Read Certificates
			PTEID_Certif[] certs = pteid.GetCertificates();
			System.out.println("Number of certs found: " + certs.length);
			for (PTEID_Certif cert : certs) {
				System.out.println(cert.certifLabel);
			}

			certificate_bytes = certs[n].certif; //gets the byte[] with the n-th certif

			//pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD); // OBRIGATORIO Termina a eID Lib
		} catch (PteidException e) {
			e.printStackTrace();
		}
		return certificate_bytes;
	}
	
	public X509Certificate getCertFromByteArray(byte[] certificateEncoded) throws CertificateException{
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(certificateEncoded);
		X509Certificate cert = (X509Certificate)f.generateCertificate(in);
		return cert;
	}
	
	public byte[] sign(byte[] data){
		try{
//			pteid.Init(""); // OBRIGATORIO Inicia a eID Lib
//			pteid.SetSODChecking(false); // Don't check the integrity of the ID, address and photo (!)
			
			PKCS11 pkcs11 = null;
			String libName = "/usr/local/lib/libpteidpkcs11.so";
			
			Class pkcs11Class = Class.forName("sun.security.pkcs11.wrapper.PKCS11");
				
			//http://stackoverflow.com/questions/21201697/how-to-obtain-session-handle-in-sunpkcs11
			pkcs11 = PKCS11.getInstance(libName, "C_GetFunctionList", new CK_C_INITIALIZE_ARGS(), false);
			System.out.println(pkcs11.toString());
			
			//Open the PKCS11 session
			long p11_session = pkcs11.C_OpenSession(0, PKCS11Constants.CKF_SERIAL_SESSION, null, null);

			// Token login 
			pkcs11.C_Login(p11_session, PKCS11Constants.CKU_USER, null); //3rd argument is an array with the PIN
			CK_SESSION_INFO info = pkcs11.C_GetSessionInfo(p11_session); //possibly not used

			// Get available keys 
			CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[]{ new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, new Long(PKCS11Constants.CKO_PRIVATE_KEY)) };

			pkcs11.C_FindObjectsInit(p11_session, attributes);
			long[] keyHandles = pkcs11.C_FindObjects(p11_session, 5); //gets private keys

			System.out.println("Num de private keys no cartao: " + keyHandles.length);
			
			// Gets the authorization private key
			long signatureKey = keyHandles[0];		//0- autenticacao; 1- assinatura
			pkcs11.C_FindObjectsFinal(p11_session);			
			System.out.println("Signature key: " + signatureKey);
			

			// Initialize the signature method 
			CK_MECHANISM mechanism = new CK_MECHANISM(PKCS11Constants.CKM_SHA1_RSA_PKCS, (byte[])null);
			pkcs11.C_SignInit(p11_session, mechanism, signatureKey);

			// Perform the signature
			byte[] signed_bytes = pkcs11.C_Sign(p11_session, data);
			
//		    pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD); //OBRIGATORIO Termina a eID Lib
		    
			return signed_bytes;
			    
		}
		catch(ClassNotFoundException e) { e.printStackTrace(); }
		catch(SecurityException e) { e.printStackTrace(); } 
//		catch(PteidException e) { e.printStackTrace(); } 
		catch(IOException e) { e.printStackTrace(); } 
		catch(PKCS11Exception e) { e.printStackTrace(); } 
		return null;
	}
	
	public boolean verifySignedNonce(PublicKey myPublicKey, String nonce, byte[] signed_nonce) {
		boolean verifies = false;	
		try{
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(myPublicKey);
			signature.update(nonce.getBytes());
			verifies = signature.verify(signed_nonce);
		}
		catch(InvalidKeyException e) { e.printStackTrace(); } 
		catch(NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch(SignatureException e) { e.printStackTrace(); } 
		return verifies;
	}
	
	public void initPteid(){
		try{
			//OBRIGATORIO Inicia a eID Lib
			pteid.Init("");
			// Don't check the integrity of the ID, address and photo (!)
		    pteid.SetSODChecking(false); 
		}
		catch (PteidException e){ e.printStackTrace(); }
	}
	
	public void closePteid(){
		try{
			pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD); //OBRIGATORIO Termina a eID Lib
		}
		catch (PteidException e){ e.printStackTrace(); }
	}
	
	public void showStuff() {
	    try {
//	      pteid.Init(""); //OBRIGATORIO Inicia a eID Lib
//	      pteid.SetSODChecking(false); // Don't check the integrity of the ID, address and photo (!)

	      int cardtype = pteid.GetCardType();
	      switch (cardtype)
	      {
	        case pteid.CARD_TYPE_IAS07:
		        System.out.println("IAS 0.7 card\n");
		        break;
	        case pteid.CARD_TYPE_IAS101:
		        System.out.println("IAS 1.0.1 card\n");
		        break;
	        case pteid.CARD_TYPE_ERR:
		        System.out.println("Unable to get the card type\n");
		        break;
	        default:
		        System.out.println("Unknown card type\n");
	      }

	      // Read ID Data
	      PTEID_ID idData = pteid.GetID();
	      if (null != idData)
	        PrintIDData(idData);
	      

		  // Read Picture Data
	      PTEID_PIC picData = pteid.GetPic();
	      if (null != picData){
	           String photo = "photo.jp2";
	           FileOutputStream oFile = new FileOutputStream(photo);
	           oFile.write(picData.picture);
	           oFile.close();
	           System.out.println("Created " + photo);
	      }

	      // Read Pins
	      PTEID_Pin[] pins = pteid.GetPINs();

	      // Read TokenInfo
	      PTEID_TokenInfo token = pteid.GetTokenInfo();

	      // Read personal Data
	      byte[] filein = {0x3F, 0x00, 0x5F, 0x00, (byte)0xEF, 0x07};
	      byte[] file = pteid.ReadFile(filein, (byte)0x81);
	        
//	      pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD); //OBRIGATORIO Termina a eID Lib
	    }
	    catch (PteidException e){
		    e.printStackTrace();
	    }
	    catch (IOException e){
		    e.printStackTrace();
	    }
	}
	
	private void PrintIDData(PTEID_ID idData) {
		System.out.println("DeliveryEntity : " + idData.deliveryEntity);
		System.out.println("PAN : " + idData.cardNumberPAN);
		System.out.println("...");
	}

	private void PrintAddressData(PTEID_ADDR adData) {
		if ("N".equals(adData.addrType)) {
			System.out.println("Type : National");
			System.out.println("Street : " + adData.street);
			System.out.println("Municipality : " + adData.municipality);
			System.out.println("...");
		} else {
			System.out.println("Type : International");
			System.out.println("Address : " + adData.addressF);
			System.out.println("City : " + adData.cityF);
			System.out.println("...");
		}
	}
}	

