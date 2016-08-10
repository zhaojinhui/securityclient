package parameter;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.util.HashMap;
import javax.crypto.spec.SecretKeySpec;
import static parameter.serverthread.loopnot;

// client main proces
public class mainclient {
	
	public static String syncookies;
	public static String timestamps;
	public static String usernames;
	public static String clientusername;
	public static SecretKeySpec DHAESkeys;
	public static KeyPair rsakeys;
	public static KeyPair rsaskeys;
	public static String clientkey;
	public static String judgeString;
	public static HashMap<String, String> userpubkeys;
	public static HashMap<String, KeyPair> rsaserverkeys;
	public static HashMap<String, KeyPair> rsaclientkeys;
	public static HashMap<SocketAddress, String> ipanduser;
	public static boolean initiallogin;
	public static boolean loopornot;
	private static int port;
	private static String ip;
	
	public static void main(String[] args) {
		syncookies=new String();
		timestamps=new String();
		usernames=new String();
		judgeString=new String();
		userpubkeys=new HashMap<String, String>();
		rsaserverkeys=new HashMap<String, KeyPair>();
		rsaclientkeys=new HashMap<String, KeyPair>();
		ipanduser=new HashMap<SocketAddress, String>();
	
		loopornot=true;
		initiallogin=false;
		while(loopornot)
		{
			judgeString="wait";
			try {
			//	System.out.println("what is the request:");
				BufferedReader bReader = new BufferedReader(new InputStreamReader(System.in));
				String request = bReader.readLine();
				// send the login request
				if(request.equals("login")&&!initiallogin)
				{
					try {
						getportandip();
						Socket socket=new Socket(ip,port);
						// use login thread to do the requst 
						new Thread(new loginthread(socket)).start();
						while(!judgeString.equals("successful")&&!judgeString.equals("too many times"))
						{
							initiallogin=true;
						}
						if(judgeString.equals("too many times"))
						{
							Thread.sleep(3);
							initiallogin=false;
						}
					} catch (UnknownHostException e) {
						e.printStackTrace();
					} catch (IOException e) {
						System.out.println("there is something wrong with server");
						loopornot=false;
						loopnot=false;
						try {
							Socket newsocket=new Socket("127.0.0.1",loginthread.port);
							newsocket.close();
						} catch (UnknownHostException e1) {
							System.out.println("there is something wrong with server");
						} catch (IOException e1) {
							System.out.println("there is something wrong with server");
						}
					}
				}
				else 
				// send the list request
				if(request.equals("list")&&initiallogin)
				{
					try {
						Socket socket=new Socket(ip,port);
						// use list thread to do the request
						new Thread(new listthread(socket)).start();
						while(!judgeString.equals("close"))
						{
							
						}
					} catch (UnknownHostException e) {
						e.printStackTrace();
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
					}
				}
				else
				// request to talk with other client
				if(request.equals("send")&&initiallogin)
				{
					try {
						Socket socket=new Socket(ip,port);
						// start the request thread to do it
						new Thread(new requestthread(socket)).start();
						while(!judgeString.equals("finish"))
						{
							
						}
					} catch (UnknownHostException e) {
						e.printStackTrace();
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
					}
				}
				else
				// send log off request
				if(request.equals("logoff")&&initiallogin)
				{
					try {
						Socket socket=new Socket(ip,port);
						// use the logoff to do the reuqest
						new Thread(new logoffthread(socket)).start();
						while(!judgeString.equals("logoff"))
						{
							
						}
						initiallogin=false;
					} catch (UnknownHostException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
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
					}
				}
				else {
					System.out.println("wrong input, please try again");
					Thread.sleep(1000);
				}
			} catch (Exception e) {
				// TODO: handle exception
			}
		}
	}
	// get server port and ip
	private static void getportandip() {
		try {
			FileReader reader=new FileReader("d:/serverportandip.txt");
			BufferedReader bf=new BufferedReader(reader);
			ip=bf.readLine();
			String temp;
			temp=bf.readLine();
			port=Integer.parseInt(temp);
			
			bf.close();
			reader.close();
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}