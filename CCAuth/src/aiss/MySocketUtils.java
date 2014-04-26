package aiss;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
import java.net.*;

import org.apache.commons.codec.binary.Base64;

public class MySocketUtils {
	public static void sendData(Socket target, byte[] data) throws IOException{
		DataOutputStream dos = new DataOutputStream(target.getOutputStream());      
      
        int len = data.length;
        dos.writeInt(len);
        if (len > 0) 
            dos.write(data);
        
        //dos.close(); //deve fechar-se mas fecha tambem o socket associado, cuidado!
	}
	
	public static void sendEncodedData(Socket target, byte[] data) throws IOException{
		DataOutputStream dos = new DataOutputStream(target.getOutputStream());      
      
		byte[] encodedBytes = Base64.encodeBase64(data);
		
        int len = encodedBytes.length;
        dos.writeInt(len);
        if (len > 0) 
            dos.write(encodedBytes);
        
        //dos.close(); //deve fechar-se mas fecha tambem o socket associado, cuidado!
	}
	
	public static byte[] receiveData(Socket sender) throws IOException{
        // Create stream to receive data from client
        DataInputStream in = new DataInputStream(sender.getInputStream());
        
        // Receive response
        int size = in.readInt();
        byte[] result = new byte[size];
        in.readFully(result);
        //in.close(); //deve fechar-se mas fecha tambem o socket associado, cuidado!
        
        return result;
	}
	
	public static byte[] receiveEncodedData(Socket sender) throws IOException{
        // Create stream to receive data from client
        DataInputStream in = new DataInputStream(sender.getInputStream()); 
        
        // Receive response
        int size = in.readInt();
        byte[] encodedBytes = new byte[size];
        in.readFully(encodedBytes);
        byte[] result = Base64.decodeBase64(encodedBytes);
        //in.close(); //deve fechar-se mas fecha tambem o socket associado, cuidado!
        
        return result;
	}
	
    public static byte[] fileToByteArray(String pathName)
    {
    	FileInputStream fileInputStream=null;
 
        File file = new File(pathName);
 
        byte[] bFile = new byte[(int) file.length()];
 
        try {
            //convert file into array of bytes
	    fileInputStream = new FileInputStream(file);
	    fileInputStream.read(bFile);
	    fileInputStream.close();

        }catch(Exception e){
        	e.printStackTrace();
        }
        return bFile;
    }
    
    public static void printByteToString(byte[] dados) {
		try {
			for (int i = 0; i < dados.length; i++) {
				System.out.print((char) dados[i]);
			}
		} catch (Exception e) {
		System.out.println("Erro - printByteToString: " + e);;
		}
	}
    
    public static void saveFiles(byte[] dados, String path) throws IOException {
		FileOutputStream fileOut = new FileOutputStream(path);
		try {
			fileOut.write(dados);
		} finally {
			fileOut.close();

		}
    }
}
