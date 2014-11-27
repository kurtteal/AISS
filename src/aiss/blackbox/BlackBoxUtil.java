package aiss.blackbox;

public class BlackBoxUtil {
	// on Windows this code would look for blackboxutil.dll, 
	// on Linux and Solaris blackboxutil.so,
	// on MacOS blackboxutil.dylib
    static { System.loadLibrary("blackboxutil"); }
    public static native byte[] cypher(String mode, String inPAth, String outPath);
}
