package me.bechberger.trace;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;

import java.io.*;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.lang.management.ManagementFactory;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarFile;
import java.util.logging.Logger;

public class Main {

    private static final Logger LOGGER = Logger.getLogger("Main");

    private static Path extractedJARPath;

    public static void premain(
            String agentArgs, Instrumentation inst) {
        agentmain(agentArgs, inst);
    }

    public static void agentmain(
            String agentArgs, Instrumentation inst) {
        Thread t = new Thread(() -> {
            while (true) {
                Thread.getAllStackTraces().keySet().forEach(t1 -> {
                    t1.getStackTrace();
                });
                Thread.getAllStackTraces();
            }
        });
        t.setPriority(Thread.MAX_PRIORITY);
        t.setDaemon(true);
        t.start();
    }

    private static Path getExtractedJARPath() {
        if (extractedJARPath != null) {
            return extractedJARPath;
        }
        try {
            // based on https://github.com/gkubisa/jni-maven/blob/master/src/main/java/ie/agisoft/LibraryLoader.java
            InputStream in = Main.class.getClassLoader().getResourceAsStream("trace-validation-runtime.jar");
            assert in != null;

            File file = File.createTempFile("runtime", ".jar");

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
            extractedJARPath = file.toPath().toAbsolutePath();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return extractedJARPath;
    }

    static class Config {

        /** Probability of adding a call to the native check method */
        public float callNativeMethodProbability = 1f;

        public boolean printAllTraces = false;

        public int maxDepth = 1024;

        public int printEveryNthBrokenTrace = 1;

        public int printEveryNthValidTrace = -1;

        public int printStatsEveryNthTrace = -1;

        public int checkEveryNthStackFully = 1;

        public boolean collectStack() {
            return checkEveryNthStackFully > 0;
        }

        public static void printConfigHelp() {
            System.out.println("Agent arguments:");
            System.out.println("  cnmProb=<float> (default: 1.0)");
            System.out.println("       probability of adding a call to the native check method at every method");
            System.out.println("  printAllTraces=<true|false> (default: false)");
            System.out.println("       print all traces, not just the ones that are invalid");
            System.out.println("  maxDepth=<int> (default and max: 1024)");
            System.out.println("       maximum depth of the stack trace");
            System.out.println("  printEveryNthBrokenTrace=<int> (default: 1)");
            System.out.println("       print every nth broken trace");
            System.out.println("  printEveryNthValidTrace=<int> (default: -1)");
            System.out.println("       print every nth valid trace (-1 == none)");
            System.out.println("  printStatsEveryNthTrace=<int> (default: -1)");
            System.out.println("       print stats every nth trace (-1 == none)");
            System.out.println("  checkEveryNthStackFully=<int> (default: 1)");
            System.out.println("       check every nth stack against the stack collected via instrumentation (1 == all)");
            System.out.println("       if GST and ASGCT match");
        }

        public static Config parseAgentArgument(String agentArgs) {
            Config config = new Config();
            if (agentArgs != null) {
                String[] args = agentArgs.split(",");
                for (String arg : args) {
                    String[] parts = arg.split("=");
                    if (parts.length != 2) {
                        throw new IllegalArgumentException("Invalid argument: " + arg);
                    }
                    String key = parts[0];
                    String value = parts[1];
                    switch (key) {
                        case "cnmProb":
                            config.callNativeMethodProbability = Float.parseFloat(value);
                            break;
                        case "printAllTraces":
                            config.printAllTraces = Boolean.parseBoolean(value);
                            break;
                        case "maxDepth":
                            config.maxDepth = Integer.parseInt(value);
                            break;
                        case "printEveryNthBrokenTrace":
                            config.printEveryNthBrokenTrace = Integer.parseInt(value);
                            break;
                        case "printEveryNthValidTrace":
                            config.printEveryNthValidTrace = Integer.parseInt(value);
                            break;
                        case "printStatsEveryNthTrace":
                            config.printStatsEveryNthTrace = Integer.parseInt(value);
                            break;
                        case "checkEveryNthStackFully":
                            config.checkEveryNthStackFully = Integer.parseInt(value);
                            break;
                        default:
                            printConfigHelp();
                            throw new IllegalArgumentException("Unknown argument: " + key);
                    }
                }
            }
            return config;
        }
    }

    private static void transformClass(Instrumentation inst, Config config) {
        inst.addTransformer(new ClassTransformer(config, extractedJARPath), true);
        List<Class<?>> transformable = new ArrayList<>();
        for (Class<?> klass : inst.getAllLoadedClasses()) {
            if (inst.isModifiableClass(klass)) {
                transformable.add(klass);
            }
        }
        try {
            inst.retransformClasses(transformable.toArray(new Class[0]));
        } catch (UnmodifiableClassException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        System.out.println("Hello World");
    }

    // fibonacci
    public static int fib(int n) {
        if (n <= 1) {
            return n;
        }
        return fib(n - 1) + fib(n - 2);
    }
}