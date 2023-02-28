package me.bechberger.trace;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class Main {

    private static final Logger LOGGER = Logger.getLogger("Main");

    public static void premain(
            String agentArgs, Instrumentation inst) {
        agentmain(agentArgs, inst);
    }

    public static void agentmain(
            String agentArgs, Instrumentation inst) {
        String nameOfRunningVM = ManagementFactory.getRuntimeMXBean().getName();
        String pid = nameOfRunningVM.substring(0, nameOfRunningVM.indexOf('@'));
        try {
            VirtualMachine vm = VirtualMachine.attach(pid);
            vm.loadAgentPath(NativeChecker.getNativeLibPath().toString(), null);
        } catch (AttachNotSupportedException | IOException | AgentLoadException | AgentInitializationException e) {
            throw new RuntimeException(e);
        }
        try {
            transformClass(inst, Config.parseAgentArgument(agentArgs));
        } catch (RuntimeException ignored) {
        }
    }

    static class Config {
        public boolean collectStack = false;

        /** Probability of adding a call to the native check method */
        public float callNativeMethodProbability = 1f;

        public boolean printAllTraces = false;

        public static void printConfigHelp() {
            System.out.println("Agent arguments:");
            System.out.println("  collectStack=<true|false> (default: false)");
            System.out.println("  cnmProb=<float> (default: 1.0)");
            System.out.println("  printAllTraces=<true|false> (default: false)");
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
                        case "collectStack":
                            config.collectStack = Boolean.parseBoolean(value);
                            break;
                        case "cnmProb":
                            config.callNativeMethodProbability = Float.parseFloat(value);
                            break;
                        case "printAllTraces":
                            config.printAllTraces = Boolean.parseBoolean(value);
                            break;
                        default:
                            throw new IllegalArgumentException("Unknown argument: " + key);
                    }
                }
            }
            return config;
        }
    }

    private static void transformClass(Instrumentation inst, Config config) {
        inst.addTransformer(new ClassTransformer(config), true);
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