package parameter;
import java.io.BufferedReader;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyPair;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static parameter.mainclient.usernames;
import static parameter.mainclient.rsakeys;
import static parameter.mainclient.clientkey;
import static parameter.mainclient.judgeString;
import static parameter.requestthread.ip;
import static parameter.requestthread.port;

// build up the session key with target client
public class tellclient implements Runnable {
	Socket socket;
	rsakey rsa;
	AESkeys aes;
	SecretKeySpec DHAESkey;
	String serverclient;
	KeyPair DHKeyPair;
	public tellclient(String request) {
		serverclient=request;
	}

	@Override
	public void run() {
		try {
			Socket socket=new Socket(ip,port);
			rsa=new rsakey();
			aes=new AESkeys();
			InputStream in = socket.getInputStream();
			DataInputStream inStream=new DataInputStream(in);
			OutputStream out=socket.getOutputStream();
			DataOutputStream outStream=new DataOutputStream(out);
			String sendmsg = null;
			String recmsg; 
			String judge;
			sendmsg=usernames+DHpub();
			// use the target information and send diffie hellman key to the target client
			byte[] msg=clientkey.getBytes("ISO-8859-1");
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			EncodedKeySpec pubKeySpec=new X509EncodedKeySpec(msg);
			PublicKey pKey=keyFactory.generatePublic(pubKeySpec);
			sendmsg=rsa.enrsa(pKey, sendmsg);
			sendmsg="client"+sendmsg;
			outStream.writeUTF(sendmsg);
			
			recmsg=inStream.readUTF();
			recmsg=dersa(rsakeys.getPrivate(), recmsg);
			judge=serverclient;
			// if target client is trusted
			if(recmsg.startsWith(judge))
			{
				// get the target client diffie hellman key and generate the session key
				recmsg=recmsg.substring(judge.length());
				DHAESkey=generateAESkey(recmsg);
				System.out.println("message");
				BufferedReader bReader = new BufferedReader(new InputStreamReader(System.in));
				// use the diffie hellman key to send some message to target client
				sendmsg=usernames+bReader.readLine();
				sendmsg=aes.AESencrypt(DHAESkey, sendmsg);
				outStream.writeUTF(sendmsg);
				judgeString="finish";
			}
			else {
				System.out.println("server is not trusted");
			}
		} catch (UnknownHostException e) {
			System.out.println("there is something wrong with client");
			judgeString="finish";
		} catch (IOException e) {
			System.out.println("there is something wrong with client");
			judgeString="finish";
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	
	//generate DH key pair
	private void generateDHKeyPair() {
		try {
			KeyPairGenerator keGenerator=KeyPairGenerator.getInstance("DH");
			keGenerator.initialize(512);
			DHKeyPair=keGenerator.genKeyPair();
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 
	}
	
	//get DH public key
	private String DHpub() {
		try {
			generateDHKeyPair();
			byte[] temp=DHKeyPair.getPublic().getEncoded();
			String pubkey;
			pubkey = new String(temp, "ISO-8859-1");
			return pubkey;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
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
	
	//generate session key
	private SecretKeySpec generateAESkey(String m) {
		try {
			byte[] msg=m.getBytes("ISO-8859-1");
			KeyFactory keyFactory = KeyFactory.getInstance("DH");
			EncodedKeySpec pubKeySpec=new X509EncodedKeySpec(msg);
			PublicKey pKey=keyFactory.generatePublic(pubKeySpec);
			
			KeyAgreement bKeyAgreement=KeyAgreement.getInstance("DH");
		    bKeyAgreement.init(DHKeyPair.getPrivate());
		    bKeyAgreement.doPhase(pKey, true);
		    
		    MessageDigest bdigest=MessageDigest.getInstance("MD5");
		    byte[] bt=bdigest.digest(bKeyAgreement.generateSecret());
		    DHAESkey=new SecretKeySpec(bt, "AES");
			return DHAESkey;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} 
		return null;
	}
}
