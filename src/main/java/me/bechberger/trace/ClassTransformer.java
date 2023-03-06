package me.bechberger.trace;

import javassist.*;
import javassist.expr.ExprEditor;
import javassist.expr.MethodCall;
import javassist.expr.NewExpr;
import javassist.scopedpool.ScopedClassPoolFactoryImpl;
import javassist.scopedpool.ScopedClassPoolRepositoryImpl;
import me.bechberger.trace.Main.Config;

import java.io.*;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.util.concurrent.atomic.AtomicInteger;

class ClassTransformer implements ClassFileTransformer {

    private final Config config;
    private final Path runtimeJar;
    private final ScopedClassPoolFactoryImpl scopedClassPoolFactory = new ScopedClassPoolFactoryImpl();

    public ClassTransformer(Config config, Path runtimeJar) {
        this.config = config;
        this.runtimeJar = runtimeJar;
    }

    @Override
    public byte[] transform(Module module, ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        //System.out.println("try transforming " + className);
        // see https://technology.amis.nl/software-development/java/java-agent-rewrite-java-code-at-runtime-using-javassist/
        try {
            if (className.startsWith("me/bechberger/trace/Stack") || className.startsWith("jdk.internal.event")) {
                return classfileBuffer;
            }
            try {
                ClassPool cp = scopedClassPoolFactory.create(loader, ClassPool.getDefault(),
                        ScopedClassPoolRepositoryImpl.getInstance());
                cp.appendClassPath(runtimeJar.toString()); // you get errors else because of not found classes
                CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));
                if (cc.isFrozen()) {
                    return classfileBuffer;
                }
                transform(className, cc);
                return cc.toBytecode();
            } catch (CannotCompileException | IOException | NotFoundException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            } catch (RuntimeException e) {
                e.printStackTrace();
                return classfileBuffer;
            }
        } catch (RuntimeException e) {
            return classfileBuffer;
        }
    }

    public void transform(String className, CtClass cc) {
        for (CtMethod method : cc.getDeclaredMethods()) {
            try {
                transform(className, method);
            } catch (CannotCompileException e) {
                if (!e.getMessage().equals("no method body")) {
                    System.err.println("error for method " + method.getLongName());
                    e.printStackTrace();
                }
            }
        }
    }

    private void transform(String className, CtMethod method) throws CannotCompileException {
        if (config.collectStack()) {
            method.insertBefore(String.format("me.bechberger.trace.NativeChecker.push(\"%s\", \"%s\");", className, method.getName() + method.getSignature()));
          /*  method.instrument(new ExprEditor() {
                @Override
                public void edit(MethodCall m) throws CannotCompileException {
                    if (m.getClassName().equals("me/bechberger/trace/Stack")) {
                        return;
                    }
                    m.replace("me.bechberger.trace.Stack.pushMethodInCaller(\"" + m.getMethodName() + "\"); $_ = $proceed($$); me.bechberger.trace.Stack.popMethodInCaller();");
                }
            });*/
            method.insertAfter("me.bechberger.trace.NativeChecker.pop();", true);
        }
        if (config.callNativeMethodProbability >= Math.random()) {
            method.insertBefore("me.bechberger.trace.NativeChecker.checkTrace();");
        }
    }
}
