/*
 * Created by Nick McKinney on 10/26/16.
 *
 * Assignment: TCSS 581 (Cryptology) HW#2
 *
 * This is a generalized file encryption/decryption class based on the SunJCE provider
 * It will encrypt/decrypt any file using any scheme in the SunJCE provider
 *
 * This is the encrytion/decryption engine.  It uses Java's javax.crypto.Cipher object to do the heavy lifting
 *
 */

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.StringTokenizer;

class FileCipher {

    // javax.crypto.cipher is the main cryptographic engine for Java
    private Cipher cipher;

    // This is my secret key.  It remains valid until changed
    private SecretKey key;

    // This is where our IV will go
    private byte[] IV;

    // Construct object for our algorithm
    // This does not initialize the Cipher, only builds the parameters into the class for later use
    FileCipher(String scheme, SecretKey k)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {

        // Parse the plain algorithm from the entire encryption scheme, if applicable
        StringTokenizer st = new StringTokenizer(scheme, "/");

	    // Constructor for javax.crypto.Cipher
	    cipher = Cipher.getInstance(scheme);

	    // Store our key
	    key = k;

    }

    /* File I/O is the same across all implementations */
    void EncryptFile(File plainText, File cipherText) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException {
	    // Probably not the right way to do this, but we will generate a new IV here
        newIV();

        // Fully initialize Java's javax.crypto.Cipher object
	    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));

		// Build an input stream that processes our plaintext through the block cipher
        // CipherInputStream is a wrapper for a FileInputStream that takes the fileinput and processes it through the Cipher object
        CipherInputStream cin = new CipherInputStream(new FileInputStream(plainText), cipher);

		/* Build an output stream for out encrypted data */
        FileOutputStream out = new FileOutputStream(cipherText);

        /* Output the IV as the first block to our file */
        out.write(cipher.getIV());

        // Initialize the array b to the exact size of our block.
        byte[] b = new byte[cipher.getBlockSize()];

		/* Encrypt the entire file */
        while (cin.read(b) != -1)
            out.write(b);

        // Cleanup
        out.close();
        cin.close();
    }

    void DecryptFile(File cipherText, File plainText) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException {
        /* Now, let's go in reverse! */
	    FileInputStream in = new FileInputStream(cipherText);

        // Read our IV from the ciphertext file.  First, we have to initialize the array b to be the blocksize of our algorithm
		byte[] b = new byte[cipher.getBlockSize()];
		in.read(b);
		newIV(b);

		/* Initialize the Cipher object in DECRYPT_MODE, with the same key and the IV from our ciphertext file */
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));

        // Initialize a new CipherOutputStream to process our decrypted text.
        // CipherOutputStream is a wrapper for a FileOutStream that takes some byte[] and processes it through the Cipher object before writing it to a file
        CipherOutputStream cout = new CipherOutputStream(new FileOutputStream(plainText), cipher);
	    while (in.read(b) != -1) {
			cout.write(b);
	    }

	    // Cleanup
		cout.close();
	    in.close();
    }

    // Create a new random IV using Java's FIPS 140-2 RNG
    private void newIV() {
        SecureRandom rng = new SecureRandom();
        // Create a
        IV = new byte[cipher.getBlockSize()];
	    rng.nextBytes(IV);
    }

    // Sets a new IV to a specific value.  Used mainly for file decryption
    private void newIV(byte[] iv) {
        IvParameterSpec ivps = new IvParameterSpec(iv);
        IV = ivps.getIV();
    }
}
