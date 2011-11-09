package com.abrody.passforge;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import android.os.SystemClock;

class PassforgeException extends GeneralSecurityException {
	public PassforgeException(String message) {
		super(message);
	}
}

public class Passforge {
	private long startTime;
	private long endTime;
	private PBKDF2KeyGenerator generator;
	private String password;
	private byte[] salt;
	private String generatedPassword;
	public int iterations;
	
	public class PassforgeException extends Exception {
		private static final long serialVersionUID = 1L;
		PassforgeException(String message) {
			super(message);
		}
	}
	
	public Passforge(String password, byte[] salt, int iterations) throws GeneralSecurityException {
		
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
		
		startTime = 0;
		endTime = 0;

	}
	
	public String deriveKey() throws GeneralSecurityException {
		byte[] derivedKey;
		
		startTime = SystemClock.uptimeMillis();
		
		derivedKey = generator.generateKey(password, salt);
		
		endTime = SystemClock.uptimeMillis();
		
		generatedPassword = byteArrayToString(derivedKey);
		return generatedPassword;
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
		return (SystemClock.uptimeMillis() - startTime) / 1000;
	}
	
	public String getGeneratedPassword() {
		return generatedPassword;
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		args = new String[1];
		args[0] = "password";
		byte[] salt = "salt".getBytes();
		
		if (args.length < 1) {
			System.out.println("must supply password");
			System.exit(1);
		}
		String pass = args[0];
		
		System.out.println("password: " + pass);
		System.out.println("salt: " + new String(salt));
		printByteArray("salt bytes: ", salt);
		
		//byte[] key = deriveKey(pass.toCharArray(), salt, 1, 8 * 20);
		
		byte[] key = null;
		
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

