import java.io.BufferedOutputStream;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Arrays;
import java.util.Random;

public class ServerCP1 {


	public static void main(String[] args) {

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		byte[] filename = new byte[117];

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());
			
			int nonce = 0;

			// Get server Private Key
			PrivateKey privateKey = getPrivateKey("private_key.der");

			// Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as decrypt and encrypt mode, use PRIVATE key.
			Cipher rsaCipher_encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
			rsaCipher_encrypt.init(Cipher.ENCRYPT_MODE, privateKey);
			Cipher rsaCipher_decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
			rsaCipher_decrypt.init(Cipher.DECRYPT_MODE, privateKey);

			while (!connectionSocket.isClosed()) { // waiting
				int packetType = fromClient.readInt();

				// if packetType == 0, send filename to server - receive filename
				if (packetType == 0) {
					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);


				// if packetType == 1, send content to server - receiving content
				} else if (packetType == 1) {

					int encryptedNumBytes = fromClient.readInt();
					int numBytes = fromClient.readInt();

					if (encryptedNumBytes == 128) {
						byte [] block = new byte[numBytes];
						byte[] encryptedBlock = new byte[encryptedNumBytes];
						fromClient.readFully(encryptedBlock, 0, encryptedNumBytes); // read 
						block = rsaCipher_decrypt.doFinal(encryptedBlock); // decrypt 

						bufferedFileOutputStream.write(block, 0, block.length);
					}

					if (encryptedNumBytes == 0) { // no more content then the whole file is well received 
						int count = fromClient.readInt();
						String closing = "closing";
						byte[] closingByte = closing.getBytes();
						toClient.write(closingByte);

						// Close output stream
						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();

						if (count == 0) { 
							System.out.println("Closing connection...");

							fromClient.close();
							toClient.close();
							connectionSocket.close();

						}
					}

				// if packetType == 2, request proof of server identity - receive request
				} else if (packetType == 2) {
					int msgNumBytes = fromClient.readInt();
					byte[] messageBytes = new byte[msgNumBytes];
					fromClient.readFully(messageBytes, 0, msgNumBytes);
  					String message = new String(messageBytes, StandardCharsets.UTF_8);
					System.out.println("Received message: " + message);
			

					// if packetType == 3, receive encryptedMsg to be decrypted - send to client
					String responseMessage = "Hello, this is SecStore";
					byte[] encryptedResponseMessageByte = rsaCipher_encrypt.doFinal(responseMessage.getBytes());
					toClient.writeInt(3);
					toClient.writeInt(encryptedResponseMessageByte.length);
					toClient.write(encryptedResponseMessageByte);
					System.out.println("Sent message: " + responseMessage);

				// if packetType == 4, request CAcert from server - request received
				} else if (packetType == 4) {
				
					int msgNumBytes = fromClient.readInt();
					byte[] messageBytes = new byte[msgNumBytes];
					fromClient.readFully(messageBytes, 0, msgNumBytes);
  					String message = new String(messageBytes, StandardCharsets.UTF_8);
					System.out.println("Received message: " + message);

					// Send certificate and nonce back to Client

					// if packetType == 5, receive encrypted nonce from server - send to client
					Random random = new Random();
					nonce = random.nextInt();
					BigInteger bigIntegerNonce = BigInteger.valueOf(nonce);
					byte[] encryptedBigNonce = rsaCipher_encrypt.doFinal(bigIntegerNonce.toByteArray());

					
					toClient.writeInt(5);
					toClient.writeInt(encryptedBigNonce.length);
					toClient.write(encryptedBigNonce);
					System.out.println("Nonce sent: " + bigIntegerNonce);

					FileInputStream caCert = new FileInputStream("cacsertificate.crt");
					BufferedInputStream bufferedCaCert = new BufferedInputStream(caCert);
					byte[] buffer_CAcert = new byte[117];

					// if packetType == 6, receive CAcert from server - send to client 
					for (boolean fileEnded = false; !fileEnded;) {
						int numCertBytes = caCert.read(buffer_CAcert);
						fileEnded = numCertBytes < 117;
						if (fileEnded == true) {
							buffer_CAcert = Arrays.copyOfRange(buffer_CAcert, 0, numCertBytes);
						}
		
						toClient.writeInt(6);
						toClient.writeInt(numCertBytes);
						toClient.write(buffer_CAcert);
						toClient.flush();
					}
		
					bufferedCaCert.close();
					caCert.close();
					System.out.println("Server sent CA certificate");

				// if packetType == 7, send back nonce to server  - receive nonce from client
				} else if (packetType == 7) {
					int receivedNonce = fromClient.readInt();
					boolean rightNonce = (receivedNonce == nonce);
					if (rightNonce) {
						System.out.println("Received Nonce: " + receivedNonce);
						System.out.println("Sent Nonce: " + nonce);
						System.out.println("Correct Nonce");
					} else {
						System.out.println("Incorrect Nonce");

						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				}
			}
		} catch (Exception e) {e.printStackTrace();}

	}



	public static PrivateKey getPrivateKey(String filename) throws Exception {
 
		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}
}
