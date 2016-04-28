package hr.fer.zemris.java.tecaj.hw07.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

@SuppressWarnings("javadoc")
public class CryptoTests {
	
	/** Password as hex-encoded text (16 bytes, i.e. 32 hex-digits). */
	private static final String PASSWORD = "a52217e3ee213ef1ffdee3a192e2ac7e";
	/** Initialization vector as hex-encoded text (32 hex-digits). */
	private static final String VECTOR = "000102030405060708090a0b0c0d0e0f";
	
	/** A ByteArrayOutputStream used for capturing System.out printing. */
	private static ByteArrayOutputStream baos;
	
	/**
	 * A dummy print stream that does nothing to prevent console printing when
	 * running the main program.
	 */
	private static final PrintStream EMPTY_OUT = new PrintStream(new OutputStream() {
		@Override
		public void write(int b) throws IOException {}
	});
	
	static {
		System.setOut(EMPTY_OUT);
	}

	/* ------------------------------ Tests ------------------------------ */
	
	@Test
	public void testHextobyte1() {
		byte[] bytes = DatatypeConverter.parseHexBinary("ABAB");
		if (!Arrays.equals(bytes, Crypto.hextobyte("ABAB"))) {
			fail();
		}
	}
	
	@Test
	public void testHextobyte2() {
		byte[] bytes = DatatypeConverter.parseHexBinary(PASSWORD);
		if (!Arrays.equals(bytes, Crypto.hextobyte(PASSWORD))) {
			fail();
		}
	}
	
	@Test
	public void testHextobyteEmptyString() {
		byte[] bytes = {};
		// must return empty array
		if (!Arrays.equals(bytes, Crypto.hextobyte(""))) {
			fail();
		}
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testHextobyteIllegalCharacter1() {
		// must throw
		Crypto.hextobyte("ABAB.B");
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testHextobyteIllegalCharacter2() {
		// must throw
		Crypto.hextobyte("ABCDEFGH");
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testHextobyteUnevenLength() {
		// must throw
		Crypto.hextobyte("ABA");
	}
	
	@Test
	public void testHextobyteAndReverse1() {
		byte[] arr = Crypto.hextobyte("abac");
		String original = Crypto.byteToHexString(arr);
		
		assertEquals("abac", original);
	}
	
	@Test
	public void testHextobyteAndReverse2() {
		byte[] arr = Crypto.hextobyte(PASSWORD);
		String original = Crypto.byteToHexString(arr);
		
		assertEquals(PASSWORD, original);
	}
	
	@Test
	public void testEncryptThenDecryptThenCheckSHA() {
		setIn(PASSWORD + "\n" + VECTOR);
		// encrypt hw07test.bin (again...)
		Crypto.main(new String[]{"encrypt", "hw07test.bin", "hw07test.cryptedAgain.bin"});
		
		setIn(PASSWORD + "\n" + VECTOR);
		// decrypt hw07test.cryptedAgain.bin as hw07test.original.bin
		Crypto.main(new String[]{"decrypt", "hw07test.cryptedAgain.bin", "hw07test.original.bin"});
		
		setIn("-");
		startCaptureOut();
		Crypto.main(new String[]{"checksha", "hw07test.bin"});
		String check1 = endCaptureOut();
		
		setIn("-");
		startCaptureOut();
		Crypto.main(new String[]{"checksha", "hw07test.original.bin"});
		String check2 = endCaptureOut();
		
		assertEquals(true, check1.contains("0d3d4424461e22a458c6c716395f07dd9cea2180a996e78349985eda78e8b800"));
		assertEquals(true, check2.contains("0d3d4424461e22a458c6c716395f07dd9cea2180a996e78349985eda78e8b800"));
		
		File file = new File("hw07test.cryptedAgain.bin");
		file.delete();
		file = new File("hw07test.original.bin");
		file.delete();
	}
	
	/**
	 * Sets the standard input to the byte array input stream of the specified
	 * <tt>input</tt> string.
	 * 
	 * @param input the input string
	 */
	private static void setIn(String input) {
		InputStream in = new ByteArrayInputStream(input.getBytes());
		System.setIn(in);
	}
	
	/**
	 * Starts the capturing of standard output by redirecting it to a byte array
	 * output stream. It is later ended and fetched by calling the
	 * {@linkplain #endCaptureOut()} method.
	 */
	private static void startCaptureOut() {
		baos = new ByteArrayOutputStream();
	    PrintStream ps = new PrintStream(baos);
	    System.setOut(ps);
	}
	
	/**
	 * End the capturing of standard output by converting the contents of the
	 * byte array output stream to a string. The standard output capturing first
	 * must be started by calling the {@linkplain #startCaptureOut()} method.
	 */
	private static String endCaptureOut() {
		System.out.flush();
	    System.setOut(EMPTY_OUT);
	    return baos.toString();
	}
	
}
