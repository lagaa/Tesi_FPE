import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Cycle_walking_FPE {

	public static final boolean DEBUG = true;
	public static final int AES_KEY_SIZE = 128; // bits
	public static final int AES_BLOCK_SIZE = 16; // bytes. 16*8 = 128
	
	public static void main(String[] args) throws Exception {
		
		if(args.length != 1) {
			System.err.println("Expect args: <PLAINTEXT string>");
			System.exit(1);
		}
		
		System.out.println("Plaintext = " + args[0]);
		
		int len = args[0].length();		// lenght in byte
		byte[] plaintextBytes = str2ByteArr(args[0]);	// I transform the input string in an array of bytes
		
		BigInteger maxVal = BigInteger.ZERO;
		maxVal = maxVal.setBit(len*8).subtract(BigInteger.ONE);	// the range is [0, 2^(len*8)-1]
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(AES_KEY_SIZE);
		SecretKey key = keyGenerator.generateKey();
		
		// cycle-walking encryption
		plaintextBytes = expand(plaintextBytes, AES_BLOCK_SIZE);
		byte[] ciphertext = cycle_permute(key, plaintextBytes, Cipher.ENCRYPT_MODE, maxVal);
		System.out.print("Ciphertext = ");
		System.out.println(DatatypeConverter.printHexBinary(ciphertext)); // "printhexBinary" converts from binary to hexadecimal
		System.out.println("Ciphertext len = " + ciphertext.length);
		
		// cycle-walking decryption
		ciphertext = expand(ciphertext, AES_BLOCK_SIZE);
		byte[] decrypted = cycle_permute(key, ciphertext, Cipher.DECRYPT_MODE, maxVal);
		System.out.println(new String(decrypted));
		
	}
	
	public static byte[] cycle_permute(SecretKey key, byte[] block, int mode, BigInteger maxVal) throws Exception {
		byte[] permuted;
		byte[] block_copy = Arrays.copyOf(block, block.length); // It copies the specified array, truncating or padding with false (if necessary) so the copy has the specified length
		int steps = 0;
		
		while(true) {
			steps++;
			if(mode == Cipher.ENCRYPT_MODE) {
				permuted = permute(key, block_copy, Cipher.ENCRYPT_MODE);
			}
			else {
				permuted = permute(key, block_copy, Cipher.DECRYPT_MODE);
			}
			BigInteger permutedInt = new BigInteger(1, permuted);		// permutedInt is  the BigInteger where I arrived. maxVal is the maximum possible value where 
			if(permutedInt.compareTo(maxVal) != 1) {				// I end the cycle only if I entered inside the maxVal range (only if permutedInt is less than maxVal)
				break;
			}
			block_copy = permuted;
		}
		
		if(DEBUG) {
			System.out.println("Num steps = " + steps);
		}
		return trimZeroPrefix(permuted);
	}
	
	
	public static byte[] permute(SecretKey key, byte[] block, int mode) throws Exception {
		assert block.length == AES_BLOCK_SIZE;
		assert mode == Cipher.ENCRYPT_MODE || mode == Cipher.DECRYPT_MODE;
		
		// Cipher instance. ECB is ok (despite the fact that is a poor choice in general)-only one block msg
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		
		// Create SecretKeySpec
		SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
		
		// Initialize Cipher MODE
		if (mode == Cipher.ENCRYPT_MODE) {
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		} else {
			cipher.init(Cipher.DECRYPT_MODE, keySpec);
		}
		
		return cipher.doFinal(block);
	}
	
	// Delete leading 0s
	protected static byte[] trimZeroPrefix(byte[] byeArray) {
		// count how many leading zeros
        int count = 0;
        while ((count < byeArray.length - 1) && (byeArray[count] == 0)) {
            count++;
        }
        if (count == 0) {
            // no leading zeros initially
            return byeArray;
        }
        byte[] trimmedByteArray = new byte[byeArray.length - count];
        System.arraycopy(byeArray, count, trimmedByteArray, 0, trimmedByteArray.length);
        return trimmedByteArray;
	}
	
	// Expand with padding
	protected static byte[] expand(byte[] byeArray, int size) {
		byte[] newByteArray = new byte[size];
		
		int i;
		for(i = 0; i < size - byeArray.length; i++) {
			newByteArray[i] = 0;
		}
		System.arraycopy(byeArray, 0, newByteArray, i, byeArray.length);
		return newByteArray;
	}
	
	// Returns a byte array containing hexadecimal values parsed from the string
	protected static byte[] str2ByteArr(String s) {
        return s.getBytes();
    }

}
