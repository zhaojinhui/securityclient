package parameter;

import static parameter.mainclient.clientkey;
import static parameter.mainclient.syncookies;
import static parameter.mainclient.timestamps;
import static parameter.mainclient.DHAESkeys;
import static parameter.mainclient.clientusername;
import static parameter.mainclient.rsakeys;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;


// target client respond to the server's message which indicate that there is a client want to talk you
public class visitthread implements Runnable {

	Socket socket;
	AESkeys aes;
	String recmsg;
	String username;  
	public visitthread(Socket s, String m) {
		socket=s;
		recmsg=m;
	}
	@Override
	public void run() {
		try {
			aes=new AESkeys();
			OutputStream out=socket.getOutputStream();
			DataOutputStream outStream=new DataOutputStream(out);
			String sendmsg=null;
			recmsg=recmsg.substring(5);
			recmsg=aes.AESdecrypt(DHAESkeys, recmsg);
			String judge=syncookies+timestamps;
			// if server is trusted
			if(recmsg.startsWith(judge))
			{
				// send client one time public key to server
				recmsg=recmsg.substring(judge.length());
				username = getusername();
				clientusername=username;
				clientkey=recmsg.substring(username.length()+1);
				sendmsg=syncookies+timestamps+new String(rsakeys.getPublic().getEncoded(),"ISO-8859-1");
				sendmsg=aes.AESencrypt(DHAESkeys, sendmsg);
				outStream.writeUTF(sendmsg);
			}
			else {
				System.out.println("server is not trusted");
			}
		} catch (IOException e) {
			System.out.println("there is snomething wrong with server");
		}
		

	}
	
	private String getusername() {
		byte[]receiveinfo = null;
		int num=0;
		int start=0;
		try {
			byte[] msg=recmsg.getBytes("ISO-8859-1");
			for(int i=0;i<msg.length;i++)
			{
				if(msg[i]!='|')
				{
					num++;
				}
				else{
					receiveinfo=new byte[num];
					System.arraycopy(msg, start, receiveinfo, 0, num);
					break;
				}
			}
			String result=new String(receiveinfo,"ISO-8859-1");
			return result;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

}
