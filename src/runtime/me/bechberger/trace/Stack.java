package trace;

/**
 * Misses methods from all classes which are not loaded by an "app" class loader
 */
public class Stack {

    public final static int MAX_STACK_DEPTH = 1024;

    public String[] classes = new String[MAX_STACK_DEPTH];
    public String[] methods = new String[MAX_STACK_DEPTH];
    public String[] signatures = new String[MAX_STACK_DEPTH];
    public int length = 0;

    public String[] methodsInCaller = new String[MAX_STACK_DEPTH];
    public int methodsInCallerLength = 0;

    public static ThreadLocal<Stack> threadStack = ThreadLocal.withInitial(Stack::new);

    public static void push(String className, String method, String signature) {
        Stack ts = threadStack.get();
        if (ts.length < MAX_STACK_DEPTH) {
            ts.classes[ts.length] = className;
            ts.methods[ts.length] = method;
            ts.signatures[ts.length] = signature;
        }
        ts.length++;
    }

    public static void pop() {
        threadStack.get().length--;
    }

    public static boolean isFull() {
        return threadStack.get().length > MAX_STACK_DEPTH;
    }

    public static void pushMethodInCaller(String methodName) {
        Stack ts = threadStack.get();
        if (ts.methodsInCallerLength < MAX_STACK_DEPTH) {
            ts.methodsInCaller[ts.methodsInCallerLength] = methodName;
        }
        ts.methodsInCallerLength++;
    }

    public static void popMethodInCaller() {
        threadStack.get().methodsInCallerLength--;
    }

    public static boolean isMethodInCallerMoreThanFull() {
        return threadStack.get().methodsInCallerLength > MAX_STACK_DEPTH;
    }

    public static Stack get() {
        return threadStack.get();
    }
}
