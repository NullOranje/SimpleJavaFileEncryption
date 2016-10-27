import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.StringTokenizer;

public class CryptoDemo {
    public static void main(String[] args) {
	    String[] schemes = {
			    "AES/CBC/PKCS5Padding",
			    "AES/CTR/PKCS5Padding",
			    "DES/CBC/PKCS5Padding",
			    "DES/CTR/PKCS5Padding",
			    "DESede/CBC/PKCS5Padding",
			    "DESede/CTR/PKCS5Padding"
	    };

	    String path = "/Users/nicholas/Desktop/Cipher/";
	    File inFile = new File(path + "pg10.txt");

	    /* Begin the client testing */
	    try {
		    for (String alg : schemes) {
			    StringTokenizer st = new StringTokenizer(alg, "/");
			    String method = st.nextToken();

			    // Generate a random key
			    KeyGenerator keygen = KeyGenerator.getInstance(method);
				SecretKey keymat = keygen.generateKey();

			    FileCipher fc = new FileCipher(alg, keymat);  // This will produce a random IV when initializing the cipher

			    // Take our test scheme and make a pretty filename for it.
			    st = new StringTokenizer(alg, "/");
			    String niceString = st.nextToken() + "-" + st.nextToken();

			    // Important: save our key!
			    File keyFile = new File(path + niceString + "-keyfile.txt");
			    FileOutputStream keyOut = new FileOutputStream(keyFile);
			    keyOut.write(keymat.getEncoded());
			    keyOut.close();

			    // Create new files for the output
			    File outFile = new File(path + niceString + "-cipher.txt");


			    File decryptFile = new File(path + niceString + "-decrypted.txt");


			    // Encrypt our source
			    System.out.println("Encrypting using: " + alg);
			    long start = System.currentTimeMillis();
			    fc.EncryptFile(inFile, outFile); // The actual encryption
			    long stop = System.currentTimeMillis();
			    System.out.println("Encryption time: " + (stop - start) + '\n');

			    // Decrypt our source
			    System.out.println("Decrypting using: " + alg);
			    start = System.currentTimeMillis();
			    fc.DecryptFile(outFile, decryptFile);  // The actual decryption
			    stop = System.currentTimeMillis();
			    System.out.println("Decryption time: " + (stop - start));
				System.out.println("---------------------------------------------------");
		    }
		/* End Client Testing */
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
