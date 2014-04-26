package aiss;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Server {

	private static int port = 8004;
	private static int serialNr = 0;
	
	public static void main(String args[]){

		//PteidManager concentra as funcionalidades para interacao com o CC
		IAuthenticator mngr = new PteidManager();
		
		//Create server socket
        ServerSocket serverSocket;
		try {
			serverSocket = new ServerSocket(port);
	        System.out.printf("Server accepting connections on port %d %n", port);
	
	        //Wait for and then accept client connection
	        //a socket is created to handle the created connection
	        Socket clientSocket = serverSocket.accept();
	        System.out.printf("Connected to client %s on port %d %n",
	            clientSocket.getInetAddress().getHostAddress(), clientSocket.getPort());
	
	        //Init da library
	        mngr.initPteid();
	        
			//Waits for clients auth requests
			//the request contains the auth certificate for that client
			//TODO verificacao da cadeia de certificados so no projecto final
	        byte[] request = MySocketUtils.receiveEncodedData(clientSocket);
			
	        //Prints publickey to compare against client
	        X509Certificate certificate = mngr.getCertFromByteArray(request);
	        PublicKey pubKey = certificate.getPublicKey();
	        System.out.println("Public key: " + pubKey.toString());
	        
			//Sends nonce (sequential num + date + time)
			String nonce = getNonce();
	        System.out.println(nonce);
	        MySocketUtils.sendEncodedData(clientSocket, nonce.getBytes());
	        
			//Waits for the signed nonce from the client
	        byte[] signed_nonce = MySocketUtils.receiveEncodedData(clientSocket);
			
			//Verifies the nonce using the publicKey obtained from the certificate
	        boolean nonceVerified = mngr.verifySignedNonce(pubKey, nonce, signed_nonce);
			if(nonceVerified)
				System.out.println("Client authenticated!");
			else
				System.out.println("Client not authenticated.");
	        
			mngr.showStuff();
			
			mngr.closePteid();
			clientSocket.close();
			serverSocket.close();
		} 
		catch (IOException e) { e.printStackTrace(); }
		catch (CertificateException e) { e.printStackTrace(); } 
	}
	
	//Nonce is a counter number + current date and time coded into a string
	//Ex: the first nonce ever on 13th of April 2014 at 15:40:06 would output: 1140413154006
	private static String getNonce(){
		serialNr++;
		return serialNr + currentTimeToString();
	}
	
	private static String currentTimeToString(){
		SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss");
        Date resultdate = new Date(System.currentTimeMillis());
        return sdf.format(resultdate);
	}
}
