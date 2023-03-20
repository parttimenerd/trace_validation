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
        Config config = Config.parseAgentArgument(agentArgs);
        try {
            inst.appendToBootstrapClassLoaderSearch(new JarFile(getExtractedJARPath().toFile()));
            Class<?> nc = Class.forName("me.bechberger.trace.NativeChecker");
            nc.getMethod("staticInit", ClassLoader.class).invoke(null, Main.class.getClassLoader());
            String nameOfRunningVM = ManagementFactory.getRuntimeMXBean().getName();
            String pid = nameOfRunningVM.substring(0, nameOfRunningVM.indexOf('@'));
            try {
                VirtualMachine vm = VirtualMachine.attach(pid);
                vm.loadAgentPath(nc.getMethod("getNativeLibPath", ClassLoader.class).invoke(null, Main.class.getClassLoader()).toString(), null);
                nc.getMethod("init", boolean.class, int.class, int.class, int.class, int.class, int.class, int.class, int.class, boolean.class, boolean.class, boolean.class, int.class).invoke(null, config.printAllTraces, config.maxDepth, config.printEveryNthBrokenTrace, config.printEveryNthValidTrace, config.printStatsEveryNthTrace, config.printStatsEveryNthBrokenTrace, config.checkEveryNthStackFully, config.sampling() ? config.sampleInterval : -1, config.traceCollectionProbability > 0, config.ignoreInstrumentationForTraceStack, config.asgctGSTSamplingCheck, config.asgctGSTSamplingIgnoreTopNFrames);
            } catch (AttachNotSupportedException | IOException | AgentLoadException | AgentInitializationException e) {
                throw new RuntimeException(e);
            }
        } catch (IOException | IllegalAccessException | InvocationTargetException | ClassNotFoundException |
                 NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
        try {
            transformClass(inst, config);
        } catch (RuntimeException ignored) {
        }
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

        /**
         * Probability of adding a call to the native check method
         */
        public float callNativeMethodProbability = 1f;

        public boolean printAllTraces = false;

        public int maxDepth = 1024;

        public int printEveryNthBrokenTrace = 1;

        public int printEveryNthValidTrace = -1;

        public int printStatsEveryNthTrace = -1;
        public int printStatsEveryNthBrokenTrace = -1;

        public int checkEveryNthStackFully = 1;

        /**
         * probability of add trace stack collection method calls to a method
         */
        public float traceCollectionProbability = 1f;

        /**
         * interval of the trace collection async checker, in us, -1 means no checks
         */
        public int sampleInterval = -1;

        public boolean ignoreInstrumentationForTraceStack = false;

        /** compare ASGCT with GCT in the sampler */
        public boolean asgctGSTSamplingCheck = false;

        /** ignore the top N frames in the ASGCT/GCT comparison */
        public int asgctGSTSamplingIgnoreTopNFrames = 5;

        public boolean collectStack() {
            return checkEveryNthStackFully > 0;
        }

        public boolean instrumenting() {
            return traceCollectionProbability > 0 || callNativeMethodProbability > 0 || collectStack();
        }

        public boolean sampling() {
            return sampleInterval > -1 && (traceCollectionProbability > 0 || asgctGSTSamplingCheck);
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
            System.out.println("  printStatsEveryNthBrokenTrace=<int> (default: -1)");
            System.out.println("       print stats every nth broken trace (-1 == none)");
            System.out.println("  checkEveryNthStackFully=<int> (default: 1)");
            System.out.println("       check every nth stack against the stack collected via instrumentation (1 == all)");
            System.out.println("       if GST and ASGCT match");
            System.out.println("  traceCollectionProbability=<float> (default: 0)");
            System.out.println("       probability of adding a call to the trace collection method at every method (0 == no checks)");
            System.out.println("  sampleInterval=<int> (default: -1)");
            System.out.println("       interval of the trace collection async checker and other sampler in us");
            System.out.println("  traceIgnoreInstrumentation=<true|false> (default: false)");
            System.out.println("       ignore instrumentation for trace stack collection");
            System.out.println("  asgctGSTSamplingCheck=<true|false> (default: false)");
            System.out.println("       compare ASGCT with GCT in the signal handler in the sampler");
            System.out.println("  asgctGSTSamplingIgnoreTopNFrames=<int> (default: 5)");
            System.out.println("       ignore the top N frames in the ASGCT/GCT comparison");
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
                        case "printStatsEveryNthBrokenTrace":
                            config.printStatsEveryNthBrokenTrace = Integer.parseInt(value);
                            break;
                        case "checkEveryNthStackFully":
                            config.checkEveryNthStackFully = Integer.parseInt(value);
                            break;
                        case "traceCollectionProbability":
                            config.traceCollectionProbability = Float.parseFloat(value);
                            break;
                        case "sampleInterval":
                            config.sampleInterval = Integer.parseInt(value);
                            break;
                        case "traceIgnoreInstrumentation":
                            config.ignoreInstrumentationForTraceStack = Boolean.parseBoolean(value);
                            break;
                        case "asgctGSTSamplingCheck":
                            config.asgctGSTSamplingCheck = Boolean.parseBoolean(value);
                            break;
                        case "asgctGSTSamplingIgnoreTopNFrames":
                            config.asgctGSTSamplingIgnoreTopNFrames = Integer.parseInt(value);
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
        if (!config.instrumenting()) {
            return;
        }
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