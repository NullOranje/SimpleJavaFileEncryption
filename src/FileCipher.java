/*
 * Created by Nick McKinney on 10/26/16.
 *
 * Assignment: TCSS 581 (Cryptology) HW#2
 *
 * This is a generalized file encryptor based on the SunJCE provider
 * It will encrypt/decrypt any file using any scheme in the SunJCE provider
 *
 */

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
    FileCipher(String scheme, byte[] k, byte[] iv)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {

        // Parse the plain algorithm from the entire encryption scheme, if applicable
        StringTokenizer st = new StringTokenizer(scheme, "/");
        String alg = st.nextToken();

        // Build out our key.
        SecretKeySpec keySpec = new SecretKeySpec(k, alg);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(alg);

        key = secretKeyFactory.generateSecret(keySpec);
        cipher = Cipher.getInstance(scheme);

        if (iv == null)
            newIV();
        else
            newIV(iv);
    }

    /* File I/O is the same across all implementations */
    void EncryptFile(File plainText, File cipherText) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException {
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));

		/* Build an input stream that processes our plaintext through the block cipher */
        CipherInputStream cin = new CipherInputStream(new FileInputStream(plainText), cipher);

		/* Build an output stream for out encrypted data */
        FileOutputStream out = new FileOutputStream(cipherText);

        /* Output the IV as the first block to our file */
        out.write(cipher.getIV());

        byte[] b = new byte[cipher.getBlockSize()];

		/* Encrypt the entire file */
        while (cin.read(b) != -1)
            out.write(b);

        out.close();
        cin.close();
    }

    void DecryptFile(File cipherText, File plainText) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException {
        /* Now, let's go in reverse! */
	    FileInputStream in = new FileInputStream(cipherText);

		/* Read our IV from the ciphertext file */
		byte[] b = new byte[cipher.getBlockSize()];
		int status = in.read(b);
		newIV(b);

		/* Initialize the Cipher object in DECRYPT_MODE, with the same key and the IV from our ciphertext file */
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));

		/* Initialize a new CipherOutputStream to process our decrypted text. */
		CipherOutputStream cout = new CipherOutputStream(new FileOutputStream(plainText), cipher);
	    while (in.read(b) != -1) {
			cout.write(b);
	    }

		cout.close();
	    in.close();
    }

    public byte[] getIV() {
        return IV;
    }

    public void newIV() {
        SecureRandom rng = new SecureRandom();
        IV = new byte[cipher.getBlockSize()];
    }

    public void newIV(byte[] iv) {
        IvParameterSpec ivps = new IvParameterSpec(iv);
        IV = ivps.getIV();
    }
}
