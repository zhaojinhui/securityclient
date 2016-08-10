package parameter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// handle the diffie hellman operation
public class DHkeys {
    KeyPair DHKeyPair;
	SecretKeySpec DHAESkey;
	// generate the diffie hellman key pair
	public KeyPair generateDHkeypair(){
		try {
			KeyPairGenerator keGenerator=KeyPairGenerator.getInstance("DH");
			keGenerator.initialize(512);
			DHKeyPair=keGenerator.genKeyPair();
			return DHKeyPair;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// generate the session key
	public SecretKeySpec generateAESKey(String  m) {
		try {
			byte[] msg=m.getBytes("ISO-8859-1");
			KeyFactory keyFactory=KeyFactory.getInstance("DH");
			EncodedKeySpec pubKeySpec=new X509EncodedKeySpec(msg);
			PublicKey pKey=keyFactory.generatePublic(pubKeySpec);
			
			DHParameterSpec dhParameterSpec=((DHPublicKey)pKey).getParams();
			KeyPairGenerator bGenerator=KeyPairGenerator.getInstance("DH");
			bGenerator.initialize(dhParameterSpec);
			DHKeyPair=bGenerator.generateKeyPair();
			
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
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// get the client's side diffie hellman key
	public String getpub() {
		try {
			byte[] temp=DHKeyPair.getPublic().getEncoded();
			String result=new String(temp,"ISO-8859-1");
			return result;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}
}
