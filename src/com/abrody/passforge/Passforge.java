package com.abrody.passforge;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.Callable;

class PassforgeException extends GeneralSecurityException {
	private static final long serialVersionUID = 1L;

	public PassforgeException(String message) {
		super(message);
	}
}

/**
 * Passforge needs a way to provide timing information.
 * 
 * This can be provided by android.os.SystemClock.uptimeMillis() or this
 * call to System.currentTimeMillis();
 * 
 * If only Java had functions as first-class objects...
 */
class StandardSystemClock implements Callable<Long> {
	public Long call() {
		return System.currentTimeMillis();
	}
}

/*
// Example Android-based clock
class AndroidSystemClock implements Callable<Long> {
	public Long call() {
		return android.os.SystemClock.uptimeMillis();
	}
}
*/

public class Passforge {
	private long startTime;
	private long endTime;
	private PBKDF2KeyGenerator generator;
	private String password;
	private byte[] salt;
	private String generatedPassword;
	public int iterations;
	Callable<Long> getMillisFunc;
	
	public class PassforgeException extends Exception {
		private static final long serialVersionUID = 1L;
		PassforgeException(String message) {
			super(message);
		}
	}
	
	public Passforge(String password, byte[] salt, int iterations) throws GeneralSecurityException {
		this(password, salt, iterations, 20, new StandardSystemClock());
	}
	
	public Passforge(String password, byte[] salt, int iterations, int length,
			Callable<Long> getMillis) throws GeneralSecurityException {
		
		// Argument validation
		if (password.length() == 0) {
			throw new IllegalArgumentException("Password is empty");
		}
		if (salt.length == 0) {
			throw new IllegalArgumentException("Salt is empty");
		}
		if (iterations <= 0) {
			iterations = 1;
		}
		
		this.generator = new PBKDF2KeyGenerator(20, iterations, "HMACSHA1");
		this.password = password;
		this.salt = salt;
		this.iterations = iterations;
		this.getMillisFunc = getMillis;
		
		startTime = 0;
		endTime = 0;

	}
	
	public String generatePassword() throws GeneralSecurityException {
		byte[] derivedKey = deriveKey();
		generatedPassword = byteArrayToString(derivedKey);
		return generatedPassword;
	}

	public byte[] deriveKey() throws GeneralSecurityException {
		byte[] derivedKey;
		
		startTime = getMillis();
		
		derivedKey = generator.generateKey(password, salt);
		
		endTime = getMillis();

		return derivedKey;
	}
	
	public long getMillis() {
		try {
			return getMillisFunc.call();
		} catch (Exception e) {
			// Exception is discarded
			return -1;
		}
	}
	
	public float getElapsedSeconds() {
		if (startTime == 0 || endTime == 0) {
			return Float.NaN;
		}
		return (float) (endTime - startTime) / 1000;
	}
	
	public float getCurrentElapsedSeconds() {
		if (startTime == 0) {
			return Float.NaN;
		}
		return (getMillis() - startTime) / 1000;
	}
	
	public String getGeneratedPassword() {
		return generatedPassword;
	}

	public static void main(String[] args) throws GeneralSecurityException {
		byte[] salt = "salt".getBytes();
		
		if (args.length < 1) {
			System.out.println("must supply password");
			System.exit(1);
		}
		String pass = args[0];
		
		System.out.println("password: " + pass);
		System.out.println("salt: " + new String(salt));
		printByteArray("salt bytes: ", salt);

		Passforge p = new Passforge(pass, salt, 1);
		byte[] key = p.deriveKey();
		
		int[] test0i = {0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6};
		byte[] test0 = intArrayToByteArray(test0i);
		
		
		if (Arrays.equals(test0, key)) {
			System.out.println("OK");
		} else {
			System.out.println("FAIL");
		}
		
		printByteArray("derived key: ", key);
	}

	public static void printByteArray(String prefix, byte[] arr) {
		System.out.print(prefix);
		printByteArray(arr);
	}
	
	public static void printByteArray(byte[] arr) {
		System.out.println(byteArrayToString(arr));
	}
	
	public static String byteArrayToString(byte[] arr) {
		StringBuffer sb = new StringBuffer();
		sb.append("0x { ");
		for (byte b : arr) {
			sb.append(String.format("%02x ", b));
		}
		sb.append("}");
		return sb.toString();
	}
	
	/* WTF JAVA!? THIS SHOULD NOT BE SO COMPLICATED. Hopefully I just don't know the real way to do it. */
	public static byte[] intArrayToByteArray(int[] arr) {
		byte[] arrB = new byte[arr.length];
		for (int i = 0; i < arr.length; i++) {
			arrB[i] = (byte) arr[i];
		}
		
		return arrB;
	}
}

