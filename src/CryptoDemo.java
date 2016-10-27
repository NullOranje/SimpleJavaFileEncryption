import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class CryptoDemo {
    public static void main(String[] args) {
	    String alg = "DES/CBC/PKCS5Padding";

	    File inFile = new File("/Users/nicholas/Desktop/pg10.txt");
	    File outFile = new File("/Users/nicholas/Desktop/cg10.txt");
	    File decryptFile = new File("/Users/nicholas/Desktop/dg10.txt");

	    /* Picking up a key, IV.  NOT RANDOM.  This is only to ensure the same ciphertext for debugging purposes */
	    byte[] keyMat = {0x50, 0x41, 0x53, 0x53, 0x57, 0x52, 0x52, 0x44}; // "PASSWORD"
	    byte[] IV = {0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0D, 0x15};  // Fibonacci Sequence

	    try {
			FileCipher fc = new FileCipher(alg, keyMat, IV);
			fc.EncryptFile(inFile, outFile);
			fc.DecryptFile(outFile, decryptFile);


	    } catch (NoSuchPaddingException e) {
		    System.err.println(e.getMessage());
		    System.exit(100);
	    } catch (NoSuchAlgorithmException e) {
		    System.err.println(e.getMessage());
		    System.exit(101);
	    } catch (InvalidKeyException e) {
		    System.err.println(e.getMessage());
		    System.exit(102);
	    } catch (FileNotFoundException e) {
		    System.err.println(e.getMessage());
		    System.exit(99);
	    } catch (InvalidKeySpecException e) {
		    System.err.println(e.getMessage());
		    System.exit(103);
	    } catch (IOException e) {
		    System.err.println(e.getMessage());
		    System.exit(255);
	    } catch (InvalidAlgorithmParameterException e) {
		    System.err.println(e.getMessage());
		    System.exit(104);
	    }
    }
}
