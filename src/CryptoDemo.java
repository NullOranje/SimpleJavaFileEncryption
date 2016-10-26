import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
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
		    SecretKeyFactory keyGen = SecretKeyFactory.getInstance("DES");
		    DESKeySpec desKeySpec = new DESKeySpec(keyMat);

		    SecretKey k = keyGen.generateSecret(desKeySpec);

		    /* Declare and initialize our cipher */
		    Cipher c = Cipher.getInstance(alg);
		    c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(IV));

		    /* Build an input stream that processes our plaintext through the block cipher */
		    CipherInputStream cin = new CipherInputStream(new FileInputStream(inFile), c);

		    /* Build an output stream for out encrypted data */
		    FileOutputStream out = new FileOutputStream(outFile);

		    /* Output the IV as the first block to our file */
		    out.write(c.getIV());

		    byte[] b = new byte[c.getBlockSize()];

		    /* Encrypt the entire file */
		    while (cin.read(b) != -1)
			    out.write(b);

		    out.close();
		    cin.close();

		    /* Now, let's go in reverse! */
		    FileInputStream in = new FileInputStream(outFile);

		    /* Read our IV from the ciphertext file */
		    int status = in.read(b);

		    /* Initialize the Cipher object in DECRYPT_MODE, with the same key and the IV from our ciphertext file */
		    c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(b));

		    /* Initialize a new CipherOutputStream to process our decrypted text. */
		    CipherOutputStream cout = new CipherOutputStream(new FileOutputStream(decryptFile), c);
		    while (in.read(b) != -1) {
			    cout.write(b);
		    }

		    cout.close();
		    in.close();

	    } catch (NoSuchPaddingException e) {
		    System.err.println(e);
		    System.exit(100);
	    } catch (NoSuchAlgorithmException e) {
		    System.err.println(e);
		    System.exit(101);
	    } catch (InvalidKeyException e) {
		    System.err.println(e);
		    System.exit(102);
	    } catch (FileNotFoundException e) {
		    System.err.println(e);
		    System.exit(99);
	    } catch (InvalidKeySpecException e) {
		    System.err.println(e);
		    System.exit(103);
	    } catch (IOException e) {
		    System.err.println(e);
		    System.exit(255);
	    } catch (InvalidAlgorithmParameterException e) {
		    System.err.println(e);
		    System.exit(104);
	    }

    }
}
