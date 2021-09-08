import java.io.BufferedInputStream;
import java.io.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class ClientCP2 {
	public static PublicKey getPublicKey(String filename)
	throws Exception {
 
		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	
		X509EncodedKeySpec spec =
		new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
	public static void main(String[] args) {

    	String filename = "100000.txt";
    	if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
    	// if (args.length > 1) filename = args[1];

    	int port = 4321;
    	// if (args.length > 2) port = Integer.parseInt(args[2]);

		// To account for multiple files
		int fileCount = args.length;
		int fileN = 0;
		filename = args[fileN];

		// Initiate variables
		int numBytes = 0;
		Socket clientSocket = null;
        DataOutputStream toServer = null;
        DataInputStream fromServer = null;
    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());
			byte[] encryptedMessageBytes = new byte[128];
			int nonce = 0;

			// Server Public Key + Cipher (Decrypt and Encrypt)
			PublicKey publicKey = getPublicKey("public_key.der");
			Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
			Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
			Cipher symEncryptCipher;
			decryptCipher.init(Cipher.DECRYPT_MODE, publicKey);
			encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

			// Authentication Protocol
			System.out.println("Authenticating..");

			// 3: Request Server Identity
			String message = "Requesting SecStore verification.";
			toServer.writeInt(3); 
			toServer.writeInt(message.getBytes().length);
			toServer.write(message.getBytes());

			// incoming cert
			FileOutputStream fileOutputStream = new FileOutputStream("server_cacsertificate.crt");
			BufferedOutputStream bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

			// Wait for server
			while (!clientSocket.isClosed()) {
				int packetType = fromServer.readInt();
				
				if (packetType == 4) {
					// Receive encrypted verification message from server
					int encryptedMessageNumBytes = fromServer.readInt();
					encryptedMessageBytes = new byte[encryptedMessageNumBytes];
					fromServer.readFully(encryptedMessageBytes, 0, encryptedMessageNumBytes);
	
					// 5: Request for CA certificate
					String requestMessage = "Requesting CA Signed Cert";
					toServer.writeInt(5);
					toServer.writeInt(requestMessage.getBytes().length);
					toServer.write(requestMessage.getBytes());
					System.out.println("From Client: " + requestMessage);
				} else if (packetType == 6) {
					// Receive encrypted nonce 
					int authBytes = fromServer.readInt();
					byte[] encryptedNonceBytes = new byte[authBytes];
					fromServer.readFully(encryptedNonceBytes, 0, authBytes);
					byte[] nonceBytes = decryptCipher.doFinal(encryptedNonceBytes);
					ByteBuffer byteBuffer = ByteBuffer.wrap(nonceBytes);
					nonce = byteBuffer.getInt();
					System.out.println("Nonce to Client: " + nonce);
				} else if (packetType == 7) {
					// Receive CA cert 
					int certNumBytes = fromServer.readInt();
					byte[] certBytes = new byte[certNumBytes];
					fromServer.readFully(certBytes, 0, certNumBytes);

					if (certNumBytes > 0) {
						bufferedFileOutputStream.write(certBytes, 0, certNumBytes);
					}

					if (certNumBytes < 117) {
						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();

						// Verify certificate
						System.out.println("Client: CACert received.");

						InputStream fis = new FileInputStream("cacsertificate.crt");
						CertificateFactory cf = CertificateFactory.getInstance("X.509");
						X509Certificate serverCert =(X509Certificate)cf.generateCertificate(fis);

						PublicKey CAPublicKey = serverCert.getPublicKey();
						PublicKey serverPublicKey = getPublicKey("public_key.der");

						serverCert.checkValidity();
						serverCert.verify(CAPublicKey);

						System.out.println("Client: CACert verified.");

						//Decrypt Server message.
						byte[] messageBytes = decryptCipher.doFinal(encryptedMessageBytes);
						message = new String(messageBytes, StandardCharsets.UTF_8);
						System.out.println("Client Verification: " + message);

						//Check server message.
						boolean success = message.equals("SecStore verificaton.");

						if (!success) {
							System.out.println("Message unverfied, closing connection to server.");
							fromServer.close();
							toServer.close();
							clientSocket.close();
						} else {
							// Create Symmetric Key
							KeyGenerator keyGen = KeyGenerator.getInstance("AES");
							SecretKey symKey = keyGen.generateKey();
							symEncryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
							symEncryptCipher.init(Cipher.ENCRYPT_MODE, symKey);

							// Encrypt symmetric key with server's public key
							byte[] encryptedSymKey = encryptCipher.doFinal(symKey.getEncoded());
							// 10: Send encrypted sym key
							toServer.writeInt(10);
							toServer.writeInt(encryptedSymKey.length);
							toServer.write(encryptedSymKey);
							// 8: Send back nonce to server
							toServer.writeInt(8);
							toServer.writeInt(nonce);
							// 0: Send filename to server
							// 1: Send file content to server
							while (fileN <= fileCount-1) {
								System.out.println("Sending file: " + filename);
								toServer.writeInt(0);
								toServer.writeInt(filename.getBytes().length);
								toServer.write(filename.getBytes());

								// Open file
								FileInputStream filesInputStream = new FileInputStream(filename);
								BufferedInputStream bufferedFilesInputStream = new BufferedInputStream(filesInputStream);

								byte [] fromFileBuffer = new byte[117];

								// Send file
								for (boolean fileEnded = false; !fileEnded;) {
									numBytes = bufferedFilesInputStream.read(fromFileBuffer);
									fileEnded = numBytes < 117;
									if (fileEnded == true) {
										fromFileBuffer = Arrays.copyOfRange(fromFileBuffer, 0, numBytes);
									}

									byte[] encryptedFromFileBuffer = symEncryptCipher.doFinal(fromFileBuffer);

									toServer.writeInt(1);
									toServer.writeInt(encryptedFromFileBuffer.length);
									toServer.writeInt(numBytes);
									toServer.write(encryptedFromFileBuffer);
									toServer.flush();
								}

								toServer.writeInt(1);
								toServer.writeInt(0);
								toServer.writeInt(0);
								int filesRemaining = fileCount-fileN-1;
								System.out.println("Total file left: " + (filesRemaining));
								toServer.writeInt(filesRemaining);

								// check if there are any files remaining
								byte[] checkBytes = "closing".getBytes();
								fromServer.readFully(checkBytes, 0, checkBytes.length);
								String check = new String(checkBytes, StandardCharsets.UTF_8);
								boolean fileFinished = (fileN == fileCount - 1);
								if (check.equals("closing") && fileFinished == true) {
									System.out.println("Closing connection...");
									fileN = fileN + 1;

									if (bufferedFilesInputStream != null) {
										bufferedFilesInputStream.close();
										filesInputStream.close();
									}
							
									fromServer.close();
									toServer.close();
									clientSocket.close();
								} else {
									fileN = fileN + 1;
									filename = args[fileN];
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
}

