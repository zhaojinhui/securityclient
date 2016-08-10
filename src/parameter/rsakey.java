package parameter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class rsakey {
	//get server's public key
	public Key getserverpub(){
		try {
			FileInputStream rsaStream = new FileInputStream("d:/RSApublic.txt");
			ObjectInputStream rsaobjStream=new ObjectInputStream(rsaStream);
			Key rsaKey=(Key)rsaobjStream.readObject();
			return rsaKey;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	//encrypt with rsa 
	public static String enrsa(Key rsaKey, String msg) {
			try {
				byte[] bytes=msg.getBytes("ISO-8859-1");
				Cipher cipher=Cipher.getInstance("RSA");
				cipher.init(Cipher.ENCRYPT_MODE, rsaKey);
				byte[] ciphertext=cipher.doFinal(bytes);
				String result=new String(ciphertext,"ISO-8859-1");
				return result;
			} catch (IOException e) {
				e.printStackTrace();
			}  catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
			return null;
		}
}
