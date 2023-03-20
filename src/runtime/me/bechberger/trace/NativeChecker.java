package me.bechberger.trace;

import java.io.*;
import java.nio.file.Path;

public class NativeChecker {

    private static final String NATIVE_LIB = "jnilibrary";
    private static Path nativeLibPath;

    /**
     * extract the native library and return its temporary path
     */
    public static synchronized Path getNativeLibPath(ClassLoader loader) {
        if (nativeLibPath == null) {
            try {
                // based on https://github.com/gkubisa/jni-maven/blob/master/src/main/java/ie/agisoft/LibraryLoader.java
                String filename = System.mapLibraryName(NATIVE_LIB);
                InputStream in = loader.getResourceAsStream(filename);
                assert in != null;
                int pos = filename.lastIndexOf('.');
                File file = File.createTempFile(filename.substring(0, pos), filename.substring(pos));

                file.deleteOnExit();
                try {
                    byte[] buf = new byte[4096];
                    try (OutputStream out = new FileOutputStream(file)) {
                        while (in.available() > 0) {
                            int len = in.read(buf);
                            if (len >= 0) {
                                out.write(buf, 0, len);
                            }
                        }
                    }
                } finally {
                    in.close();
                }
                nativeLibPath = file.toPath().toAbsolutePath();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return nativeLibPath;
    }

    public static void staticInit(ClassLoader loader) {
        System.load(getNativeLibPath(loader).toString());
    }


    /**
     * Set the config
     */
    public static native void init(boolean printAllStacks, int maxDepth, int printEveryNthBrokenTrace, int printEveryNthValidTrace, int printStatsEveryNthTrace, int printStatsEveryNthBrokenTrace, int checkEveryNthStackFully, int sampleInterval, boolean runTraceStackSampler, boolean ignoreInstrumentationForTraceStack, boolean asgctGSTSamplingCheck, int asgctGSTSamplingIgnoreTopNFrames);

    /**
     * check a trace and print according to config
     */
    public static native void checkTrace();

    /**
     * push to the thread local call stack
     */
    public static native void push(String className, String method);

    /**
     * pop from the thread local call stack
     */
    public static native void pop();

    /**
     * push to the thread local trace stack,
     * used to compare safe point safe ASGCT calls (by this method) with ASGCT
     * called in a signal handler
     */
    public static native void pushTraceStack();

    /**
     * pop from the thread local trace stack
     */
    public static native void popTraceStack();

    public static native void setInInstrumentation(boolean inInstrumentation);
}
