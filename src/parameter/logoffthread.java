package parameter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Key;

import static parameter.mainclient.syncookies;
import static parameter.mainclient.DHAESkeys;
import static parameter.mainclient.timestamps;
import static parameter.mainclient.usernames;
import static parameter.mainclient.judgeString;
import static parameter.serverthread.loopnot;
import static parameter.loginthread.port;

// send log off request to the server
public class logoffthread implements Runnable {
	Socket socket;
	AESkeys aes;
	rsakey rsa;
	public logoffthread(Socket s) {
		socket=s;
	}

	@Override
	public void run() {
		try {
			aes=new AESkeys();
			rsa=new rsakey();
			InputStream in = socket.getInputStream();
			DataInputStream inStream=new DataInputStream(in);
			OutputStream out=socket.getOutputStream();
			DataOutputStream outStream=new DataOutputStream(out);
			String sendmsg = null;
			String recmsg; 
			String judge=syncookies+timestamps;
			// use the session key to encrypt the logoff request and send the log off request
			sendmsg=aes.AESencrypt(DHAESkeys, judge);
			sendmsg="logoff"+usernames+"|"+sendmsg;
			Key serverpub=rsa.getserverpub();
			sendmsg=rsa.enrsa(serverpub, sendmsg);
			outStream.writeUTF(sendmsg);
			recmsg=inStream.readUTF();
			recmsg=aes.AESdecrypt(DHAESkeys, recmsg);
			judge=syncookies+"logoff success"+timestamps;
			// log off
			if(recmsg.startsWith(judge))
			{
				System.out.println("log off");
				judgeString="logoff";
				loopnot=false;
				String ip=InetAddress.getLocalHost().getHostAddress();
				Socket socket=new Socket(ip,port);
			}
		} catch (IOException e) {
			System.out.println("there is something wrong with server");
			judgeString="logoff";
			loopnot=false;
		}

	}

}
