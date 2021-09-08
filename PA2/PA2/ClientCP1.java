import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Arrays;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;

public class ClientCP1 {

	public static void main(String[] args) {

    	String filename = "100.txt";
    	if (args.length > 0) filename = args[0];

		// Send multiple files
		int filenames = args.length;
		int count = 0;
		filename = args[count];

    	String serverAddress = "localhost";
    	//if (args.length > 1) filename = args[1];

    	int port = 4321;
    	//if (args.length > 2) port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();
		

		try {

			System.out.println("Establishing connection to server...");

			byte[] encryptedMsg = new byte[128];
			int nonce = 0;

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			// Get server Public Key 
			PublicKey publicKey = getPublicKey("public_key.der");

			// Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as decrypt and encrypt mode, use PUBLIC key.
			Cipher rsaCipher_decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
			rsaCipher_decrypt.init(Cipher.DECRYPT_MODE, publicKey);
			Cipher rsaCipher_encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
			rsaCipher_encrypt.init(Cipher.ENCRYPT_MODE, publicKey);

			System.out.println("Authenticating...");

			// if packetType == 0, send filename to server
			// if packetType == 1, send content to server
			// if packetType == 2, request proof of server identity  

			String message = "Hello SecStore, please prove your identity";
			toServer.writeInt(2); 
			toServer.writeInt(message.getBytes().length);
			toServer.write(message.getBytes());

			FileOutputStream fileOutputStream = new FileOutputStream("recv_cacsertificate.crt");
			BufferedOutputStream bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

			// if packetType == 3, receive encryptedMsg to be decrypted 
			// if packetType == 4, request CAcert 
			// if packetType == 5, receive encrypted nonce 
			// if packetType == 6, receive CAcert 

			while (!clientSocket.isClosed()) { //waiting 

				int packetType = fromServer.readInt();

				if (packetType == 3) {
					int encryptedNumBytes = fromServer.readInt();
					encryptedMsg = new byte[encryptedNumBytes];
					fromServer.readFully(encryptedMsg, 0, encryptedNumBytes);
	

					String request = "Give me your certificate signed by CA";
					toServer.writeInt(4);
					toServer.writeInt(request.getBytes().length);
					toServer.write(request.getBytes());
					System.out.println("Client sent message: " + request);


				} else if (packetType == 5) {

					int auth = fromServer.readInt();
					byte[] encryptedNonceBytes = new byte[auth];
					fromServer.readFully(encryptedNonceBytes, 0, auth);
					byte[] nonceBytes = rsaCipher_decrypt.doFinal(encryptedNonceBytes);
					ByteBuffer byteBuffer = ByteBuffer.wrap(nonceBytes);
					nonce = byteBuffer.getInt();
					System.out.println("Nonce received: " + nonce);


				} else if (packetType == 6) {

					int cert = fromServer.readInt();
					byte[] certBytes = new byte[cert];
					fromServer.readFully(certBytes, 0, cert);

					if (cert > 0) {
						bufferedFileOutputStream.write(certBytes, 0, cert);
					}

					if (cert < 117) {
						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();

						System.out.println("CAcert received");

						InputStream fis = new FileInputStream("cacsertificate.crt");
						CertificateFactory cf = CertificateFactory.getInstance("X.509");
						X509Certificate serverCert =(X509Certificate)cf.generateCertificate(fis);

						PublicKey p_key = serverCert.getPublicKey();
						PublicKey server_p_key = getPublicKey("public_key.der");

						serverCert.checkValidity();
						serverCert.verify(p_key);

						System.out.println("Certificate verified!");

						// Decrypt message with server_p_key
						byte[] messageBytes = rsaCipher_decrypt.doFinal(encryptedMsg);
						message = new String(messageBytes, StandardCharsets.UTF_8);
						System.out.println("Decrypted message: " + message);


						// Checking if the message is from server if not close socket connection 
						boolean success = message.equals("Hello, this is SecStore");

						if (!success) {
							fromServer.close();
							toServer.close();
							clientSocket.close();
							
						} else { // if packetType == 7, send back nonce to server 
							toServer.writeInt(7);
							toServer.writeInt(nonce);


							// if packetType == 0, send filename to server - as mentioned earlier
							while (count <= filenames - 1) {
								System.out.println("Sending file..." + filename); 
								toServer.writeInt(0); 
								toServer.writeInt(filename.getBytes().length);
								toServer.write(filename.getBytes());

								// Open the file
								FileInputStream filesInputStream = new FileInputStream(filename);
								BufferedInputStream bufferedFilesInputStream = new BufferedInputStream(filesInputStream);

								byte [] fromFileBuffer = new byte[117];

								// if packetType == 1, send content to server - as mentioned earlier
								for (boolean fileEnded = false; !fileEnded;) {
									numBytes = bufferedFilesInputStream.read(fromFileBuffer);
									fileEnded = numBytes < 117;
									if (fileEnded == true) {
										fromFileBuffer = Arrays.copyOfRange(fromFileBuffer, 0, numBytes);
									}

									byte[] encryptedFromFileBuffer = rsaCipher_encrypt.doFinal(fromFileBuffer);

									toServer.writeInt(1); 
									toServer.writeInt(encryptedFromFileBuffer.length);
									toServer.writeInt(numBytes);
									toServer.write(encryptedFromFileBuffer);
									toServer.flush();
								}

								// Send the last file before closing socket connection 
								toServer.writeInt(1);
								toServer.writeInt(0);
								toServer.writeInt(0);
								System.out.println("Total number of files left: " + (filenames - 1 - count));
								toServer.writeInt(filenames - 1 - count); 


								// Final check if all files are sent 
								byte[] checking = "closing".getBytes();
								fromServer.readFully(checking, 0, checking.length);
								String check = new String(checking, StandardCharsets.UTF_8);
								boolean completed = (count == filenames - 1);

								if (check.equals("closing") && completed == true) {
									System.out.println("Closing socket connection...");
									count ++;

									if (bufferedFilesInputStream != null) {
										bufferedFilesInputStream.close();
										filesInputStream.close();
									}
							
									fromServer.close();
									toServer.close();
									clientSocket.close();

								} else {
									count ++;
									filename = args[count];
								}
							}
						}
					}
				} 
			}

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}


	public static PublicKey getPublicKey(String filename) throws Exception {
 
		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
}
