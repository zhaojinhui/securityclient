package parameter;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.SecretKeySpec;
import static parameter.mainclient.syncookies;
import static parameter.mainclient.DHAESkeys;
import static parameter.mainclient.timestamps;
import static parameter.mainclient.usernames;
import static parameter.mainclient.judgeString;
import static parameter.mainclient.rsakeys;
import static parameter.mainclient.initiallogin;
import static parameter.serverthread.loopnot;
import static parameter.mainclient.loopornot;

// send the login request to server
public class loginthread implements Runnable {
	public static int port;
	public static Key serverpubKey;
	Socket socket;
	mainclient object;
	String username;
	String hashpwd;
	BufferedReader bReader;
	String timestamp;
	int handshaketimes;
	KeyPair dhKeyPair;
	DHkeys dHkeys;
	rsakey rsa;
	AESkeys aes;
	SecretKeySpec DHAESkey;
	public static String receiveinfo[];  
	public loginthread(Socket s) {
		socket=s;
		receiveinfo=new String [10];
	}

	@Override
	public void run() {
		{
		handshaketimes=0;
		int count=0;
		boolean looponot=true;
		try {
			InputStream in=socket.getInputStream();
			DataInputStream inStream=new DataInputStream(in);
			OutputStream out=socket.getOutputStream();
			DataOutputStream outStream=new DataOutputStream(out);
			String sendmsg;
			String recmsg; 
			String judge;
			while(looponot)
			{
				// use server public key encrypt username and send to server
				if(handshaketimes==0)
				{
					initmsg();
					sendmsg="login"+username;
					sendmsg=rsa.enrsa(serverpubKey, sendmsg);
					outStream.writeUTF(sendmsg);
					handshaketimes++;
				}
				else 
				if(handshaketimes==1)
				{
					recmsg=inStream.readUTF();
					// if this is a repeat login 
					if(recmsg.endsWith("repeat login"))
					{
						System.out.println("repeat login, try other name");
						handshaketimes--;
						count++;
						if(count==5)
						{
							System.out.println("try too many times");
							looponot=false;
							judgeString="too many times";
						}
					}
					else
					// if use wrong login username
					if(recmsg.endsWith("wrong user"))
					{
						System.out.println("wrong user, try other name");
						handshaketimes--;
						count++;
						if(count==5)
						{
							System.out.println("try too many times");
							looponot=false;
							judgeString="too many times";
						}
					}
					else
					{
						count=0;
						// get the correct syncookies and timestamps
						explainmsg exobject = new explainmsg();
						exobject.explainmsg(recmsg);
						syncookies=receiveinfo[0];
						timestamps=receiveinfo[1];
						timestamp=timestamps;
						// make sure the timestamp is the most recent one
						System.out.println(timestamp+"if timestamp wrong please don't input password");
						System.out.println("input password:");
						// get the user input password and generate the hashed password
						bReader=new BufferedReader(new InputStreamReader(System.in));
						String password = bReader.readLine();
						MessageDigest tempdigest=MessageDigest.getInstance("SHA-1");
						byte[] bt=tempdigest.digest(password.getBytes("ISO-8859-1"));
						hashpwd=new String(bt,"ISO-8859-1");
						sendmsg=syncookies+username+hashpwd+addtimestamp();
						sendmsg=rsa.enrsa(serverpubKey, sendmsg);
						// after server public key encrypt, send to the server
						outStream.writeUTF(sendmsg);
						handshaketimes++;
					}
				}
				else 
				if(handshaketimes==2)
				{
					recmsg=inStream.readUTF();
					// if password is not right
					if(recmsg.equals("wrong password"))
					{
						System.out.println("wrong password");
						looponot=false;
						judgeString="too many times";
					}
					// if password is right
					else
					{
						recmsg=aes.dehashpwd(hashpwd, recmsg);
						judge=syncookies+addtimestamp();
						// if the message is from the server
						if(recmsg.startsWith(judge))
						{
							// use the server's diffie hellman key and client's diffie hellman key 
							// to generate the session key between client and server
							String dhpub=recmsg.substring(judge.length());
							DHAESkey=dHkeys.generateAESKey(dhpub);
							DHAESkeys=DHAESkey;
							// send the client diffie hellman key to the server
							sendmsg=syncookies+addtimestamp()+dHkeys.getpub();
							sendmsg=aes.enhashpwd(hashpwd, sendmsg);
							outStream.writeUTF(sendmsg);
							handshaketimes++;
							recmsg=inStream.readUTF();
							recmsg=aes.AESdecrypt(DHAESkey, recmsg);
							// if the key is generated successfully
							if(recmsg.startsWith(syncookies))
							{
								boolean judgeport=false;
								// client will select a port and running on that port to receive 
								// other clients messages
								while(!judgeport)
								{
									System.out.println("please input the listening port");
									bReader=new BufferedReader(new InputStreamReader(System.in));
									port = Integer.parseInt(bReader.readLine());
									try {
										ServerSocket server = new ServerSocket(port);
										judgeport=true;
										server.close();
									} catch (Exception e) {
										System.out.println("the port is occupied");
									}
								}
								// start the client server
								new Thread(new serverthread(port)).start();
								sendmsg=syncookies+addtimestamp()+port;
								sendmsg=aes.enhashpwd(hashpwd, sendmsg);
								// tell the server on which port the client is lestening on
								outStream.writeUTF(sendmsg);
								looponot=false;
								System.out.println(recmsg.substring(syncookies.length()));
								judgeString="successful";
							}
						}
						else {
							System.out.println("the server is not trusted");
							looponot=false;
							initiallogin=true;
						} 
					}
				}	
			}	
		}catch (IOException e) {
			System.out.println("server is something wrong");
			loopnot=false;
			loopornot=false;
			try {
				Socket newsocket=new Socket("127.0.0.1",port);
				newsocket.close();
			} catch (UnknownHostException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			judgeString="successful";
		} catch (NoSuchAlgorithmException e) {
			System.out.println("server is something wrong");
			judgeString="successful";
			
		}
	}
}

	//initiate AES key, RSA key, Diff Hellman Key
	private void initmsg() {
		object=new mainclient();
		dHkeys=new DHkeys();
		rsa=new rsakey();
		aes=new AESkeys();
		serverpubKey=rsa.getserverpub();
		initrsakeypair();
		try {
		System.out.println("input username:");
		bReader=new BufferedReader(new InputStreamReader(System.in));
		username=bReader.readLine();
		usernames=username;
	} catch (IOException e) {
		e.printStackTrace();
	}
	}
	
	//add time stamp
	private String addtimestamp() {
		String times=String.valueOf(handshaketimes);
		String temp=timestamp+times;
		return temp;
	}
	
	// generate an one time RSA key pair
	private void initrsakeypair() {
		try {
			KeyPairGenerator RSAGenerator = KeyPairGenerator.getInstance("RSA");
			RSAGenerator.initialize(2048);
			rsakeys=RSAGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
}
