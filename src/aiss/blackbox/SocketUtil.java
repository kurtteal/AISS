package aiss.blackbox;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

import org.apache.commons.codec.binary.Base64;

public class SocketUtil {

	public static void sendData(Socket socket, byte[] data) throws IOException {
		DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
		dos.writeInt(data.length);
		if (data.length > 0)
			dos.write(data);
	}
	
	public static void sendEncodedData(Socket socket, byte[] data)
			throws IOException {
		byte[] encodedBytes = Base64.encodeBase64(data);
		sendData(socket, encodedBytes);
	}

	public static byte[] receiveData(Socket socket) throws IOException {
		DataInputStream in = new DataInputStream(socket.getInputStream());
		int size = in.readInt();
		byte[] result = new byte[size];
		in.readFully(result);
		return result;
	}

	public static byte[] receiveEncodedData(Socket socket) throws IOException {
		byte[] encodedBytes = receiveData(socket);
		byte[] result = Base64.decodeBase64(encodedBytes);
		return result;
	}

}
