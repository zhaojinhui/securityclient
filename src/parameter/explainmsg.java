package parameter;
import java.io.UnsupportedEncodingException;


public class explainmsg {
	// explain the receiving message
	public void explainmsg(String m){
		loginthread object = new loginthread(null);
		byte[][] receiveinfo=new byte [6][];
		int count=0;
		int num=0;
		int start=0;
		int len=0;
		byte[] msg;
		try {
			msg = m.getBytes("ISO-8859-1");
			for(int i=0;i<msg.length;i++)
			{
				if(msg[i]!='|')
				{
					num++;
				}
				else{
					receiveinfo[count]=new byte[num];
					System.arraycopy(msg, start, receiveinfo[count], 0, num);
					count++;
					start=i+1;
					num=0;
					String tempString=new String(receiveinfo[count-1]);
					if(tempString.equals("keys"))
					{
						len=msg.length-start;
						receiveinfo[count]=new byte[len];
						System.arraycopy(msg, start, receiveinfo[count], 0, len);
						break;
					}
				}
				for(int j=0;j<count;j++)
				{
					object.receiveinfo[j]=new String(receiveinfo[j],"ISO-8859-1");
				}
			}
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
