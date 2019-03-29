package hr.fer.zemris.java.tecaj.hw07.crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This program can be run by entering one of the three commands through the
 * command line:
 * <ul>
 * <li><tt>checksha</tt> command - syntax: checksha &lt;filename&gt;; used for
 * checking if the expected sha-256 digest matches the generated sha-256 digest.
 * <li><tt>encrypt</tt> command - syntax: encrypt &lt;sourcefile&gt;
 * &lt;destfile&gt;; used for encrypting the specified files with AES algorithm.
 * <li><tt>decrypt</tt> command - syntax: decrypt &lt;sourcefile&gt;
 * &lt;destfile&gt;; used for decrypting the specified files with AES algorithm.
 * </ul>
 *
 * @author Mario Bobic
 */
public class Crypto {

    /** The checksha keyword. */
    private static final String CHECK_SHA = "checksha";
    /** The encrypt keyword. */
    private static final String ENCRYPT = "encrypt";
    /** The decrypt keyword. */
    private static final String DECRYPT = "decrypt";

    /** Standard size for the loading byte buffer array */
    public static final int STD_LOADER_SIZE = 4096;

    /**
     * Program entry point
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("Command line argument should be one of the following: "
                             + "checksha, encrypt, decrypt");
            System.exit(1);
        }

        String command = args[0];
        String[] otherArgs = Arrays.copyOfRange(args, 1, args.length);

        if (command.equalsIgnoreCase(CHECK_SHA)) {
            checkSHA(otherArgs);
        } else if (command.equalsIgnoreCase(ENCRYPT)) {
            encrypt(otherArgs);
        } else if (command.equalsIgnoreCase(DECRYPT)) {
            decrypt(otherArgs);
        } else {
            System.err.println("Unknown command: " + command);
        }
    }

    /**
     * Checks if the digest specified by the first argument of the <tt>args</tt>
     * array matches the calculated digest. This method uses the SHA-256
     * {@linkplain MessageDigest} for calculating the digest. This method also
     * writes out an error message if something goes wrong and terminates the
     * program.
     *
     * @param args the filename argument
     */
    static void checkSHA(String[] args) {
        if (args.length != 1) {
            System.err.println(CHECK_SHA + " command must have exactly 1 argument: filename");
            System.exit(2);
        }

        String filename = args[0];
        String actualDigest = getActualDigest(filename);

        System.out.println("Please provide expected sha-256 digest for " + filename + ":");
        prompt();

        Scanner sc = new Scanner(System.in);
        String expectedDigest = sc.nextLine();
        sc.close();

        System.out.print("Digesting completed. ");
        if (actualDigest.equals(expectedDigest)) {
            System.out.println("Digest of " + filename + " matches the expected digest.");
        } else {
            System.out.println("Digest of " + filename + " does not match the expected digest.");
            System.out.println("Digest was: " + actualDigest);
        }
    }

    /**
     * Calculates and returns the digest from a file with the specified
     * <tt>filename</tt>. This method writes out an error message and terminates
     * the program in case the file is not found, or if an I/O exception occurs.
     *
     * @param filename the file path and name
     * @return the digest from a file with the specified filename
     */
    private static String getActualDigest(String filename) {
        String actualDigest = null;

        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(filename))) {

            MessageDigest sha = getSHA();

            int len;
            byte[] bytes = new byte[STD_LOADER_SIZE];
            while ((len = in.read(bytes)) != -1) {
                sha.update(bytes, 0, len);
            }

            byte[] hash = sha.digest();
            actualDigest = byteToHexString(hash);

        } catch (FileNotFoundException e) {
            System.err.println("File not found: " + e.getMessage());
            System.exit(3);
        } catch (IOException e) {
            System.err.println("IO Exception: " + e.getMessage());
            System.exit(4);
        }

        return actualDigest;
    }

    /**
     * <b>Encrypts</b> the file specified by the first argument in the
     * <tt>args</tt> array by generating a file specified by the second argument
     * in the same array. The encryption is done by using the AES cryptographic
     * algorithm. This method also writes out an error message if something goes
     * wrong and terminates the program.
     *
     * @param args an array of strings containing sourcefile and destfile
     */
    static void encrypt(String[] args) {
        crypt(args, true);
    }

    /**
     * <b>Decrypts</b> the file specified by the first argument in the
     * <tt>args</tt> array by generating a file specified by the second argument
     * in the same array. The decryption is done by using the AES cryptographic
     * algorithm. This method also writes out an error message if something goes
     * wrong and terminates the program.
     *
     * @param args an array of strings containing sourcefile and destfile
     */
    static void decrypt(String[] args) {
        crypt(args, false);
    }

    /**
     * <b>Encrypts</b> or <b>decrypts</b> the file specified by the first
     * argument in the <tt>args</tt> array by generating a file specified by
     * the second argument in the same array. The encryption or decryption is
     * specified by the second parameter in this method, an <tt>encrypt</tt>
     * boolean. This method uses the AES cryptographic algorithm. This method
     * also writes out an error message if something goes wrong and terminates
     * the program.
     *
     * @param args an array of strings containing sourcefile and destfile
     * @param encrypt true if the file must be encrypted, false if decrypted
     */
    private static void crypt(String[] args, boolean encrypt) {
        if (args.length != 2) {
            System.err.println(encrypt ? ENCRYPT : DECRYPT
                    + " command must have exactly 2 arguments: sourcefile destfile");
            System.exit(5);
        }

        String sourcefile = args[0];
        String destfile = args[1];

        try (
                BufferedInputStream in = new BufferedInputStream(new FileInputStream(sourcefile));
                BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(destfile));
        ) {

            /* Read user's input and create specs. */
            Scanner sc = new Scanner(System.in);

            System.out.println("Please provide password as hex-encoded text (16 bytes, i.e. 32 hex-digits):");
            prompt();
            String keyText = sc.nextLine();
            SecretKeySpec keySpec = new SecretKeySpec(hextobyte(keyText), "AES");

            System.out.println("Please provide initialization vector as hex-encoded text (32 hex-digits):");
            prompt();
            String ivText = sc.nextLine();
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(hextobyte(ivText));

            sc.close();


            /* Create a cipher and start encrypting/decrypting. */
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, keySpec, paramSpec);

            int len;
            byte[] bytes = new byte[STD_LOADER_SIZE];
            while ((len = in.read(bytes)) != -1) {
                // Update until the very end
                byte[] processedBytes = cipher.update(bytes, 0, len);
                out.write(processedBytes);
            }
            // Do the final touch
            byte[] processedBytes = cipher.doFinal();
            out.write(processedBytes);

        } catch (FileNotFoundException e) {
            System.err.println("File not found: " + e.getMessage());
            System.exit(6);
        } catch (IOException e) {
            System.err.println("IO Exception: " + e.getMessage());
            System.exit(7);
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid hex: " + e.getMessage());
            System.exit(8);
        } catch (GeneralSecurityException e) {
            System.err.println("Security exception: " + e.getMessage());
            System.exit(9);
        }

        System.out.printf((encrypt ? "Encryption" : "Decryption")
                + " completed. Generated file %s based on file %s.",
                destfile, sourcefile);
    }

    /**
     * Returns an array of bytes from the specified hex string <tt>hex</tt>.
     * This method throws an {@linkplain IllegalArgumentException} if the
     * <tt>hex</tt> is not even-length or contains an illegal character.
     *
     * @param hex the hex string to be converted into a byte array
     * @return an array of bytes from the specified hex string
     * @throws IllegalArgumentException
     *             if <tt>hex</tt> does not have an even number of
     *             characters, or if it contains illegal characters
     */
    public static byte[] hextobyte(String hex) {
//        return DatatypeConverter.parseHexBinary(hex); // existent implementation
        final int len = hex.length();

        if (len % 2 != 0) {
            throw new IllegalArgumentException("Hex binary needs to be even-length: " + hex);
        }

        byte[] bytes = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            int h = hexToBin(hex.charAt(i));
            int l = hexToBin(hex.charAt(i + 1));

            bytes[i / 2] = (byte) (h * 16 + l);
        }

        return bytes;
    }

    /**
     * Returns a binary representation of the specified hexadecimal character,
     * or <tt>-1</tt> if the specified character is an invalid hexadecimal.
     * <p>
     * This method throws an {@linkplain IllegalArgumentException} if the
     * specified character <tt>ch</tt> is not a hexadecimal character.
     *
     * @param ch character whose binary representation is to be returned
     * @return a binary representation of the specified hexadecimal character
     * @throws IllegalArgumentException if the character is not a hexadecimal
     */
    private static int hexToBin(char ch) {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'A' && ch <= 'F') {
            return ch - 'A' + 10;
        }
        if (ch >= 'a' && ch <= 'f') {
            return ch - 'a' + 10;
        }
        throw new IllegalArgumentException("Illegal character for hex binary: " + ch);
    }

    /**
     * Returns a string representation of the specified <tt>bytes</tt> byte
     * array.
     *
     * @param bytes byte array to be represented as string
     * @return a string representation of the hash
     */
    public static String byteToHexString(byte[] bytes) {
//        return DatatypeConverter.printHexBinary(bytes); // existent implementation
        StringBuilder sb = new StringBuilder(bytes.length * 2);

        for (byte b : bytes) {
            String hex = String.format("%02x", 0xFF & b);
            sb.append(hex);
        }

        return sb.toString();
    }

    /**
     * Returns a SHA-256 instance of {@linkplain MessageDigest}.
     *
     * @return a SHA-256 instance of {@linkplain MessageDigest}
     */
    private static MessageDigest getSHA() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
            System.exit(10);
            return null;
        }
    }

    /**
     * Prints out the prompt symbol for user interaction.
     */
    private static void prompt() {
        System.out.print("> ");
    }

}
