package parameter;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static parameter.mainclient.rsakeys;

// the client will run as server to receive other clients communication request
// one is from old client communication message
// one is from server send other client communication request
public class serverthread implements Runnable {
	public static boolean loopnot;
	int port;
	public serverthread(int p) {
		port=p;
	}

	@Override
	public void run() {
		String recmsg=null;
		try {
			ExecutorService executorService=Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors()*100);
			ServerSocket server = new ServerSocket(port);
			loopnot=true;
			while(loopnot)
			{
				Socket socket=server.accept();
				if(loopnot)
				{
					InputStream in = socket.getInputStream();
					DataInputStream inStream=new DataInputStream(in);
					recmsg=inStream.readUTF();
					// server other client communication request
					if(recmsg.startsWith("visit"))
					{
						executorService.execute((new visitthread(socket,recmsg)));
					}
					else 
					// other's client message
					if(recmsg.startsWith("client"))
					{
						executorService.execute((new clientthread(socket,recmsg)));
					}
				}
			}
		} catch (IOException e) {
			System.out.println("there is some thing wrong, server thread closed");
		}
	}
	
	//rsa decryption
	public String dersa(Key rsaKey, String msg) {
		try {
			byte[] bytes=msg.getBytes("ISO-8859-1");
			Cipher cipher=Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, rsaKey);
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
