package sample;

import java.awt.*;

public class Fr extends Frame {
	public Fr(String s) {
		Frame f = new Frame(s);
		setSize(300, 300);
		Checkbox winXP = new Checkbox("Windows XP");
		Checkbox win2000 = new Checkbox("Windows 2000");
		Checkbox sol = new Checkbox("Solaris");
		add(winXP);
		add(win2000);
		//add(sol);
	}
	public static void rise(double d) {
		d=2*d;}

	public static void main(String[] args) {

			double x=Math.PI;
			rise(x);
			System.out.println(x);
		}


	}
