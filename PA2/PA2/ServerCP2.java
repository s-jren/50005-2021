import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ServerCP2 {
	public static PrivateKey getPrivateKey(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
  }

	public static void main(String[] args) {

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;
		byte[] filename = new byte[117];

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());
			int nonce=-1;

			PrivateKey privateKey = getPrivateKey("private_key.der");
			Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			var decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
			SecretKey symKey;
			Cipher symDecryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");;
			encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);
			decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("server_"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {
					int encryptedNumBytes = fromClient.readInt();
					int numBytes = fromClient.readInt();

					if (encryptedNumBytes > 0){
						byte[] block = new byte[numBytes];
						byte[] encBlock = new byte[encryptedNumBytes];
						fromClient.readFully(encBlock, 0, encryptedNumBytes);
						block = symDecryptCipher.doFinal(encBlock);
						bufferedFileOutputStream.write(block, 0, block.length);
					}

					if (encryptedNumBytes == 0) {
						// Let client know that file is received
						int filesLeft = fromClient.readInt();
						String closing = "closing";
						byte[] closingByte = closing.getBytes();
						toClient.write(closingByte);

						// Close output stream
						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						if (filesLeft == 0) {
							System.out.println("Closing connection...");

							fromClient.close();
							toClient.close();
							connectionSocket.close();
						}
					}
				}
				else if (packetType == 3) {
					// Receive request message from Client
					int messageNumBytes = fromClient.readInt();
					byte[] messageBytes = new byte[messageNumBytes];
					fromClient.readFully(messageBytes, 0, messageNumBytes);
  					String message = new String(messageBytes, StandardCharsets.UTF_8);
					System.out.println("To Server: " + message);

					// (PACKET = 4) Send message back to Client
					String responseMessage = "SecStore verificaton.";
					byte[] encryptedResponseMessageByte = encryptCipher.doFinal(responseMessage.getBytes());
					toClient.writeInt(4);
					toClient.writeInt(encryptedResponseMessageByte.length);
					toClient.write(encryptedResponseMessageByte);
					System.out.println("From Server: " + responseMessage);
				} else if (packetType == 5) {
					// Receive request for CA certificate
					int messageNumBytes = fromClient.readInt();
					byte[] messageBytes = new byte[messageNumBytes];
					fromClient.readFully(messageBytes, 0, messageNumBytes);
  					String message = new String(messageBytes, StandardCharsets.UTF_8);
					System.out.println("To Server: " + message);

					// Send certificate and nonce back to Client

					// (PACKET = 6) Send Nonce (encrypted)
					Random random = new Random();
					nonce = random.nextInt();
					BigInteger bigNonce = BigInteger.valueOf(nonce);
					byte[] encryptedBigNonce = encryptCipher.doFinal(bigNonce.toByteArray());
					toClient.writeInt(6);
					toClient.writeInt(encryptedBigNonce.length);
					toClient.write(encryptedBigNonce);
					System.out.println("Nonce out: " + bigNonce);

					// Open the CA cert file
					FileInputStream caCert = new FileInputStream("cacsertificate.crt");
					BufferedInputStream bufferedCaCert = new BufferedInputStream(caCert);
					byte[] caCertBuffer = new byte[117];

					// (PACKET = 7) Send the CA cert file
					for (boolean fileEnded = false; !fileEnded;) {
						int numCertBytes = caCert.read(caCertBuffer);
						fileEnded = numCertBytes < 117;
						if (fileEnded == true) {
							caCertBuffer = Arrays.copyOfRange(caCertBuffer, 0, numCertBytes);
						}
		
						toClient.writeInt(7);
						toClient.writeInt(numCertBytes);
						toClient.write(caCertBuffer);
						toClient.flush();
					}
		
					bufferedCaCert.close();
					caCert.close();
					System.out.println("CACert sent.");
				} else if (packetType == 8) {
					// Receive back the nonce from client
					int receivedNonce = fromClient.readInt();
					boolean rightNonce = (receivedNonce == nonce);
					if (rightNonce) {
						System.out.println("Received Nonce: " + receivedNonce);
						System.out.println("Sent Nonce: " + nonce);
						System.out.println("Nonce valid.");
					} else {
						System.out.println("Nonce invalid.");
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				} else if (packetType == 10) {
					// Receive encrypted sym key
					int numEncryptedSymKeyBytes = fromClient.readInt();
					byte[] encryptedSymKeyBytes = new byte[numEncryptedSymKeyBytes];
					fromClient.readFully(encryptedSymKeyBytes, 0, numEncryptedSymKeyBytes);
					byte[] decryptedSymKeyBytes = decryptCipher.doFinal(encryptedSymKeyBytes);
					symKey = new SecretKeySpec(decryptedSymKeyBytes, 0, decryptedSymKeyBytes.length, "AES");
					symDecryptCipher.init(Cipher.DECRYPT_MODE, symKey);

				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

}
