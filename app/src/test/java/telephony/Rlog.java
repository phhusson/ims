package android.telephony;

public final class Rlog {
	private static int log(String tag, String msg) {

		System.out.print(tag);
		System.out.print(": ");
		System.out.println(msg);
		return 0;
	}
	public static int d(String tag, String msg) {
		return log(tag, msg);
	}
	public static int d(String tag, String msg, Throwable tr) {
		return log(tag, msg);
	}
	public static int w(String tag, String msg) {
		return log(tag, msg);
	}
	public static int w(String tag, String msg, Throwable tr) {
		return log(tag, msg);
	}
}
