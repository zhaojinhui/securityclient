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

import static parameter.mainclient.syncookies;
import static parameter.mainclient.DHAESkeys;
import static parameter.mainclient.timestamps;
import static parameter.mainclient.usernames;
import static parameter.mainclient.rsakeys;
import static parameter.mainclient.clientkey;
import static parameter.mainclient.userpubkeys;
import static parameter.mainclient.judgeString;
import static parameter.serverthread.loopnot;
import static parameter.mainclient.loopornot;


// request client send server the request to communicate with other client
public class requestthread implements Runnable {
	public static int port;
	public static String ip;
	Socket socket;
	BufferedReader bReader;
	AESkeys aes;
	rsakey rsa;
	public requestthread(Socket s) {
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
			
			System.out.println("the client you want to talk:");
			// send the request client one time public key and the target client name it want to talk with
			bReader = new BufferedReader(new InputStreamReader(System.in));
			String request = bReader.readLine();
			String judge=syncookies+timestamps+request;
			sendmsg=aes.AESencrypt(DHAESkeys, judge);
			sendmsg="send"+usernames+'|'+sendmsg;
			Key serverpub=rsa.getserverpub();
			sendmsg=rsakey.enrsa(serverpub, sendmsg);
			outStream.writeUTF(sendmsg);
			
			recmsg=inStream.readUTF();
			recmsg=aes.AESdecrypt(DHAESkeys, recmsg);
			int count=0;
			// if the request is not legal, try less than 5 times
			while(recmsg.equals("wrong request"))
			{
				count++;
				System.out.println("the client you want to talk:");
				bReader = new BufferedReader(new InputStreamReader(System.in));
				request = bReader.readLine();
				judge=syncookies+timestamps+request;
				sendmsg=aes.AESencrypt(DHAESkeys, judge);
				outStream.writeUTF(sendmsg);
				if(count<5)
				{
					recmsg=inStream.readUTF();
					recmsg=aes.AESdecrypt(DHAESkeys, recmsg);
				}
				if(count==5)
					break;
			}
			// if trying times less than 5 times
			if(count<5)
			{
				sendmsg=judge+"|"+new String(rsakeys.getPublic().getEncoded(),"ISO-8859-1");
				sendmsg=aes.AESencrypt(DHAESkeys, sendmsg);
				outStream.writeUTF(sendmsg);
				
				recmsg=inStream.readUTF();
				recmsg=aes.AESdecrypt(DHAESkeys, recmsg);
				// if the clients not respond to server 
				if(recmsg.endsWith("clients wrong"))
				{
					System.out.println("the request client is something wrong");
					judgeString="finish";
				}
				// if the client respond to server
				else{
					judge=syncookies+timestamps;
					if(recmsg.startsWith(judge))
					{
						// get target client information
						recmsg=recmsg.substring(judge.length());
						clientkey=recmsg;
						userpubkeys.put(request, clientkey);
					}
					else {
						System.out.println("server is not trusted");
					}
					
					recmsg=inStream.readUTF();
					recmsg=aes.AESdecrypt(DHAESkeys, recmsg);
					
					if(recmsg.startsWith(judge))
					{
						// get target client ip
						recmsg=recmsg.substring(judge.length());
						ip=recmsg;
					}
					else {
						judgeString="finish";
						System.out.println("server is not trusted");
					}
					
					recmsg=inStream.readUTF();
					recmsg=aes.AESdecrypt(DHAESkeys, recmsg);
					if(recmsg.startsWith(judge))
					{
						// get the target client port
						recmsg=recmsg.substring(judge.length());
						port=Integer.parseInt(recmsg);
						// start the talk thread
						new Thread(new tellclient(request)).start();
					}
					else {
						System.out.println("server is not trusted");
					}
				}
				
			}
			else {
				System.out.println("too many times");
				judgeString="finish";
			}
		} catch (IOException e) {
			System.out.println("there is something wrong with server");
			loopornot=false;
			loopnot=false;
			try {
				Socket newsocket=new Socket("127.0.0.1",loginthread.port);
				newsocket.close();
			} catch (UnknownHostException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			judgeString="finish";
		}
	}
}