package sample;

public class Mult implements Runnable{
	String str1;
	String str2;
	Thread t;
	public Mult(String st1,String st2) {
		str1=st1; 	str2=st2; 	t=new Thread(this);	t.start();}
	public void run() {
		System.out.print(str1);
		try{
			Thread.sleep(500);}catch(InterruptedException e){};
		System.out.print(str2);}
}

