package PA2;
import java.io.*;
import java.nio.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
 
public class PrivateKeyReader {
 
  private static PrivateKey privateKey;

public static PrivateKey get(String filename)
  throws Exception {
 
	byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
 
	PKCS8EncodedKeySpec spec =
  	new PKCS8EncodedKeySpec(keyBytes);
	KeyFactory kf = KeyFactory.getInstance("RSA");
	return kf.generatePrivate(spec);
  }

//   public static void main(String[] args) {
// 	  String filename="private_key.der";
// 	  try {
// 	  	privateKey = get(filename);
// 		System.out.println(privateKey);
// 	  } catch (Exception e) {
// 		  System.out.println(e);
// 	  }
//   }
}
