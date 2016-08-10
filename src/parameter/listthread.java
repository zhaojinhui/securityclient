package parameter;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.Key;

import static parameter.mainclient.syncookies;
import static parameter.mainclient.DHAESkeys;
import static parameter.mainclient.timestamps;
import static parameter.mainclient.usernames;
import static parameter.mainclient.judgeString;

// send the list request and get the current login client from server list
public class listthread implements Runnable {
	public static int port;
	public static String ip;
	public static String list;
	Socket socket;
	BufferedReader bReader;
	AESkeys aes;
	rsakey rsa;
	public listthread(Socket s) {
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
			
			// use the session key to encrypt a request for the login username list 
			String judge=syncookies+timestamps;
			sendmsg=aes.AESencrypt(DHAESkeys, judge);
			sendmsg="list"+usernames+"|"+sendmsg;
			Key serverpubKey=rsa.getserverpub();
			sendmsg=rsakey.enrsa(serverpubKey, sendmsg);
			outStream.writeUTF(sendmsg);
			
			recmsg=inStream.readUTF();
			recmsg=aes.AESdecrypt(DHAESkeys, recmsg);
			// if send by server
			if(recmsg.startsWith(judge))
			{
				// get the current login username list
				recmsg=recmsg.substring(judge.length());
				System.out.println(recmsg);
				list=recmsg;
				judgeString="close";
			}
			else {
				System.out.println("server is not trusted");
			}
		} catch (IOException e) {
			System.out.println("server is something wrong");
			judgeString="close";
		}
	}
}
