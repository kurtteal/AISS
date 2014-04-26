package aiss;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public class Client {
	
	public static int serverPort = 8004;
	public static String serverAddr = "localhost";
	
	public static void main(String args[]){
		
		IRequester mngr = new PteidManager(); 

		try {
			//Create client socket
	        Socket socket = new Socket(serverAddr, serverPort);      
	        System.out.println("Connected to server '"+serverAddr+"' on port '"+serverPort+"'");
	        
	        //init da library
	        mngr.initPteid();
	        
	        //Gets certificate from the card
	        byte[] certificate_bytes = mngr.getCitizenAuthCertInBytes();
	        
	        //Sends the request (which is the certificate itself)
			MySocketUtils.sendEncodedData(socket, certificate_bytes);
	        System.out.println("Request sent");
	        System.out.println("PublicKey: " + mngr.getCertFromByteArray(certificate_bytes).getPublicKey().toString());
	        
	        //Waits for the nonce
	        byte[] nonce = MySocketUtils.receiveEncodedData(socket);
	        
	        //Prints the nonce
	        System.out.println(new String(nonce));
	        
	        //Signs nonce
	        byte[] signed_nonce = mngr.sign(nonce);
	        
	        //Sends the signed nonce to the server
	        MySocketUtils.sendEncodedData(socket, signed_nonce);
	        
	        mngr.closePteid();
	        socket.close();
		}
        catch (IOException e) { e.printStackTrace(); }
        catch (CertificateEncodingException e) { e.printStackTrace(); } 
		catch (CertificateException e) { e.printStackTrace(); } 
	}

}
