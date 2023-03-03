package trace;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;

public class NativeChecker {

    private static final String NATIVE_LIB = "jnilibrary";
    private static Path nativeLibPath;

    public static synchronized Path getNativeLibPath() {
        if (nativeLibPath == null) {
            try {
                // based on https://github.com/gkubisa/jni-maven/blob/master/src/main/java/ie/agisoft/LibraryLoader.java
                String filename = System.mapLibraryName(NATIVE_LIB);
                InputStream in = NativeChecker.class.getClassLoader().getResourceAsStream(filename);
                assert in != null;
                int pos = filename.lastIndexOf('.');
                File file = null;

                file = File.createTempFile(filename.substring(0, pos), filename.substring(pos));

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

    static {
        System.load(getNativeLibPath().toString());
        String nameOfRunningVM = ManagementFactory.getRuntimeMXBean().getName();
        String pid = nameOfRunningVM.substring(0, nameOfRunningVM.indexOf('@'));
        try {
            VirtualMachine vm = VirtualMachine.attach(pid);
            vm.loadAgentPath(NativeChecker.getNativeLibPath().toString(), null);
        } catch (AttachNotSupportedException | IOException | AgentLoadException | AgentInitializationException e) {
            throw new RuntimeException(e);
        }
        init();
    }


    private static native void init();

    public static native void checkTrace(boolean printAllStacks, int maxDepth);
}
