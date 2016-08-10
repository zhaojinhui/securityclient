package parameter;

import static parameter.mainclient.clientkey;
import static parameter.mainclient.judgeString;
import static parameter.mainclient.usernames;
import static parameter.mainclient.rsakeys;
import static parameter.mainclient.clientusername;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

// respond to other client message requests
public class clientthread implements Runnable {

	Socket socket;
	String timestamp;
	AESkeys aes;
	rsakey rsa;
	SecretKeySpec DHAESkey;
	String request;
	String recmsg;
	String dhpubkey;
	DHkeys dHkeys;
	public clientthread(Socket s, String m) {
		socket=s;
		recmsg=m;
	}

	@Override
	public void run() {
		try {
			rsa=new rsakey();
			aes=new AESkeys();
			dHkeys=new DHkeys();
			
			InputStream in = socket.getInputStream();
			DataInputStream inStream=new DataInputStream(in);
			OutputStream out=socket.getOutputStream();
			DataOutputStream outStream=new DataOutputStream(out);
			String sendmsg=null;
			String judge;
			recmsg=recmsg.substring(6);
			recmsg=dersa(rsakeys.getPrivate(), recmsg);
			judge=clientusername;
			// if the other client is legal
			if(recmsg.startsWith(judge))
			{
				// generate other client session key
				recmsg=recmsg.substring(judge.length());
				dhpubkey=recmsg;
				DHAESkey=dHkeys.generateAESKey(dhpubkey);
				dhpubkey=dHkeys.getpub();
				sendmsg=usernames+dHkeys.getpub();
				byte[] msg=clientkey.getBytes("ISO-8859-1");
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				EncodedKeySpec pubKeySpec=new X509EncodedKeySpec(msg);
				PublicKey pKey=keyFactory.generatePublic(pubKeySpec);
				sendmsg=rsa.enrsa(pKey, sendmsg);
				outStream.writeUTF(sendmsg);
				// use the session key to send message
				recmsg=inStream.readUTF();
				recmsg=aes.AESdecrypt(DHAESkey, recmsg);
				if(recmsg.startsWith(judge))
				{
					recmsg.substring(judge.length());
					System.out.println(judge+":"+recmsg.substring(judge.length()));
				}
			}
			else {
				System.out.println("the server is not trusted");
			}
			
		} catch (IOException e) {
			System.out.println("there is something wrong with client");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} 
	}

	//decrypt with rsa keys
	private String dersa(PrivateKey pkey, String m) {
		try {
			byte[] msg=m.getBytes("ISO-8859-1");
			
			Cipher cipher=Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, pkey);
			byte[] ciphertext=cipher.doFinal(msg);
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
