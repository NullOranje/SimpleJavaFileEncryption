/*
 * Created by Nick McKinney on 10/26/16.
 *
 * Assignment: TCSS 581 (Cryptology) HW#2
 *
 * This is a generalized file encryption/decryption class based on the SunJCE provider
 * It will encrypt/decrypt any file using any scheme in the SunJCE provider
 *
 * This is the test client for the FileCipher class I created.  This program just feeds information to/from the class
 * and logs performance results.
 */

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
		// Define the encryption algorithms and modes I intend to use here.  For padding, I will use PKCS#5 padding
		String[] schemes = {
				"AES/CBC/PKCS5Padding",
				"AES/CTR/PKCS5Padding",
				"DES/CBC/PKCS5Padding",
				"DES/CTR/PKCS5Padding",
				"DESede/CBC/PKCS5Padding",
				"DESede/CTR/PKCS5Padding"
		};

		// Define the number of test runs I will execute
		final int TEST_COUNT = 32;

		// Statically-linked file.  Probably bad practice, but it's a simple client
		String path = "/Users/nicholas/Desktop/Cipher/";
		File inFile = new File(path + "pg10.txt");

		// Where I will log my results for external analysis (mean & standard deviation)
		File logFile = new File(path + "results.csv");

	    /* Begin the client testing */
		try {

			String output;
			for (int i = 0; i < TEST_COUNT; i++) {

				for (String alg : schemes) {
					// Separate the algorithm (AES, DES, or DESede [3DES]) from the rest of the scheme.
					StringTokenizer st = new StringTokenizer(alg, "/");
					String method = st.nextToken();

					// Generate a random key
					KeyGenerator keygen = KeyGenerator.getInstance(method);
					SecretKey keymat = keygen.generateKey();

					// Initialize my file encryption/decryption utility
					// This will produce a random IV when initializing the cipher
					FileCipher fc = new FileCipher(alg, keymat);

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
					System.out.println("Encryption time:  " + (stop - start) + "ms\n");

					// Log runtime statistics
					output = "encryption," + alg + "," + (stop - start) + '\n';
					logResults(output, logFile);

					// Decrypt our source
					System.out.println("Decrypting using: " + alg);
					start = System.currentTimeMillis();
					fc.DecryptFile(outFile, decryptFile);  // The actual decryption
					stop = System.currentTimeMillis();
					System.out.println("Decryption time:  " + (stop - start) + "ms");
					System.out.println("---------------------------------------------------");

					// Log runtime statistics
					output = "decryption," + alg + "," + (stop - start) + '\n';
					logResults(output, logFile);
				}
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

	// Write given string to logfile.
	private static void logResults(String logData, File logFile) throws IOException {
		FileOutputStream logResults = new FileOutputStream(logFile, true);
		logResults.write(logData.getBytes());
		logResults.close();
	}
}
