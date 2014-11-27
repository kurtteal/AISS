package aiss.blackbox;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Scanner;

import org.apache.commons.codec.binary.Base64;


import pteidlib.PteidException;
import pteidlib.pteid;

public class SecureRepo {
	
	private static PTeIDManager manager = new PTeIDManager();
	private static HashMap<String, X509Certificate> certificates;
	
	private static final String HOME = System.getProperty("user.home");
	private static final String certPath = HOME + "/Desktop/certificates/";
	private static final String repoPath = HOME + "/Desktop/SecureRepo/";
	private static final String localPath = HOME + "/Desktop/LocalRepo/";
	private static final String authPath = repoPath + "authentication/";

	private static final String instructions = "\nINSTRUCTIONS:\n"
			+ "\tTo retrieve a file: get <filename>\n"
			+ "\tTo store a file: put <filename>\n"
			+ "\tTo exit program: exit\n";

	/*
	 * Main method.
	 */
	
	public static void main(String args[]) {
		// Initialize the PTeID library.
		manager = new PTeIDManager();
		manager.initPteid();
		
		System.out.println("========== Secure Repository ==========");
		System.out.println("Loading certificates ...");

		// Build/load the certificates "DB" (HashMap).
		certificates = new HashMap<String, X509Certificate>();
		File folder = new File(certPath.substring(0, certPath.length() - 1));
		File[] listOfFiles = folder.listFiles();
		for (int i = 0; i < listOfFiles.length; i++) {
			if (listOfFiles[i].isFile() && !listOfFiles[i].getName().startsWith(".")) {
				try {
					String certfilename = listOfFiles[i].getName();
					FileInputStream fis = new FileInputStream(certPath + certfilename);
					FileChannel fic = fis.getChannel();
					ByteBuffer buffer = ByteBuffer.allocate(16384); // 16KB buffer
					fic.read(buffer);
					X509Certificate certificate = manager
							.getCertFromByteArray(buffer.array());
					String id = certfilename.substring(0,
							certfilename.length() - 4);
					certificates.put(id, certificate);
					System.out.println("\t... " + certfilename);
					fis.close();
				} catch (FileNotFoundException fnfe) {
					System.out.println("ERROR: couldn't find certificate.");
				} catch (IOException ioe) {
					System.out
							.println("ERROR: error while reading certificate file.");
				} catch (CertificateException certe) {
					System.out
							.println("ERROR: corrupt certificate.");
				}
			}
		}
		
		System.out.println("Finished loading certificates.");

		Scanner scanner = new Scanner(System.in);
		String command = null;
		int option;
		String filename = null;

		while (!"exit".equals(command)) {
			System.out.println(instructions);
			try {
				String[] input = scanner.nextLine().split(" ");
				if (input.length > 0) {
					command = input[0];
					if (input.length > 1)
						filename = input[1];
					if(command.equals("get")){
						if (filename != null)
							get(filename);
						else
							System.out.println("Usage:\n\tget <filename>");
					}else if(command.equals("put")){
						if (filename != null)
							put(filename);
						else
							System.out.println("Usage:\n\tput <filename>");
					}else if(command.equals("exit")){
						scanner.close();
						manager.closePteid();
					}else{
						System.out.println("Unknown command.\n" + instructions);
					}
				}
			} catch (NullPointerException npe) {
				npe.printStackTrace();
			}
		}
	}

	/*
	 * Get method to retrieve a file from the secure repository to the local repository.
	 */
	
	private static void get(String filename) {
		String inputpath = repoPath + filename;
		String outputpath = localPath + filename;
		String signpath = authPath + filename + "-signature.txt";
		String authorpath = authPath + filename + "-authors.txt";

		// Check if file exists before trying to decipher it.
		File f = new File(inputpath);
		if (!f.exists()) {
			System.out.println("ERROR: File does not exist in the repository.");
			return;
		}
		
		// Decipher the file and store it "locally".
		BlackBoxUtil.cypher("-d", inputpath, outputpath);

		// Get the last author id and the correct certificate to extract the public key.
		String id_name = "";
		try {
			BufferedReader br = new BufferedReader(new FileReader(authorpath));
			while (br.ready())
				id_name = br.readLine();
			if (id_name == null) {
				System.out.println("ERROR: file metadata is corrupt.");
				System.out.println("AUTHENTICATION FAILED. The file's authenticity is compromised");
				br.close();
				return;
			}
			br.close();
		} catch (FileNotFoundException fnfe) {
			System.out.println("ERROR: couldn't find the file.");
			System.out.println("AUTHENTICATION FAILED. The file's authenticity is compromised");
			return;
		} catch (IOException ioe) {
			System.out.println("ERROR: an error occurred. Try again.");
			System.out.println("AUTHENTICATION FAILED. The file's authenticity is compromised");
			return;
		}
		
		X509Certificate certificate = certificates.get(id_name);
		PublicKey pubKey = null;
		if(certificate != null)
			pubKey = certificate.getPublicKey();
		else {
			System.out.println("ERROR: missing certificate.");
			System.out.println("AUTHENTICATION FAILED. The file's authenticity is compromised");
			return;
		}
			
		
		// Check the file's digital signature to authenticate it with the last
		// person that actually modified and stored the file in the repository.
		boolean verifies = manager.verifySignature(pubKey, outputpath, signpath);
		if (verifies)
			System.out
					.println("AUTHENTICATION SUCCESS. Last modification done by " + id_name);
		else {
			System.out.println("AUTHENTICATION FAILED. The file's authenticity is compromised");
			return;
		}
		
	}

	/*
	 * Put method to store a file in secure repository.
	 */
	
	private static void put(String filename) {
		String inputpath = localPath + filename;
		String outputpath = repoPath + filename;
		String signpath = authPath + filename + "-signature.txt";
		String authorpath = authPath + filename + "-authors.txt";

		// Check if file exists in local repository.
		if (!new File(inputpath).exists()) {
			System.out.println("ERROR: file does not exist.");
			return;
		}

        //Check file size (shorter than 50Mb) limited due to the signature process which will put the whole
        //file in memory
		if (new File(inputpath).length() > 50*1024*1024) {
			System.out.println("ERROR: file is too big! Try another file");
			return;
		}

		// Get id and certificate(if needed) from the card.
		String id_name = "";
		try {
			id_name = "(" + pteid.GetID().numBI + ") " + pteid.GetID().name;
			// Check if certificate is already stored and loaded.
			if (!certificates.containsKey(id_name)) {
				System.out.println("INFO: adding new certificate, id: " + id_name);
				byte[] certificate_bytes = manager.getCitizenAuthCertInBytes();
				X509Certificate certificate = manager
						.getCertFromByteArray(certificate_bytes);
				FileOutputStream fos = new FileOutputStream(certPath + id_name + ".cer");
				fos.write(certificate.getEncoded());
				fos.close();
				certificates.put(id_name, certificate);
			}
		} catch (PteidException pte) {
			System.out.println("ERROR: couldn't get your ID. Insert your card.");
		} catch (CertificateException cfe) {
			System.out.println("ERROR: failed to get the certificate.");
		} catch (FileNotFoundException e) {
			// Should never get here.
			e.printStackTrace();
		} catch (IOException e) {
			// Should never get here.
			e.printStackTrace();
		}

		// Generate digital signature and store it. Add author's id to modification history.
		try {
			// Create digital signature.
			FileInputStream fis = new FileInputStream(inputpath);
			byte[] databytes = new byte[fis.available()];
			fis.read(databytes);
			byte[] signaturebytes = manager.sign(databytes);
			fis.close();

			// Write the signature file.
			FileOutputStream fos = new FileOutputStream(signpath);
			byte[] encodedBytes = Base64.encodeBase64(signaturebytes);
			fos.write(encodedBytes);
			fos.close();
			
			// Write the authors file.
			BufferedWriter bw = new BufferedWriter(new FileWriter(new File(
					authorpath), true));
			bw.write(id_name);
			bw.newLine();
			bw.close();
		} catch (FileNotFoundException e) {
			System.out.println("ERROR: FileNotFoundException @ signing on put");
		} catch (IOException ioe) {
			System.out.println("ERROR: IOException @ signing on put");
		}

		// Cipher the file.
		BlackBoxUtil.cypher("-c", inputpath, outputpath);
	}

}
