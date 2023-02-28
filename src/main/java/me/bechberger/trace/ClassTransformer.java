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
import java.security.ProtectionDomain;
import java.util.concurrent.atomic.AtomicInteger;

class ClassTransformer implements ClassFileTransformer {

    private final Config config;
    private final ScopedClassPoolFactoryImpl scopedClassPoolFactory = new ScopedClassPoolFactoryImpl();

    private final AtomicInteger count = new AtomicInteger(0);

    public ClassTransformer(Config config) {
        this.config = config;
    }

    @Override
    public byte[] transform(Module module, ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        // see https://technology.amis.nl/software-development/java/java-agent-rewrite-java-code-at-runtime-using-javassist/
        if (className.startsWith("me/bechberger/trace/Stack") || !loader.getName().equals("app")) {
            return classfileBuffer;
        }
        try {
            ClassPool cp = scopedClassPoolFactory.create(loader, ClassPool.getDefault(),
                    ScopedClassPoolRepositoryImpl.getInstance());
            CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));
            if (cc.isFrozen()) {
                return classfileBuffer;
            }
            transform(module, loader, className, classBeingRedefined, cp, cc);
            return cc.toBytecode();
        } catch (CannotCompileException | IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (RuntimeException e) {
            e.printStackTrace();
            return classfileBuffer;
        }
    }

    public void transform(Module module, ClassLoader loader, String className, Class<?> classBeingRedefined,
                          ClassPool cp, CtClass cc) throws CannotCompileException {
        for (CtMethod method : cc.getDeclaredMethods()) {
            try {
                transform(cp, className, cc, method);
            } catch (CannotCompileException e) {
                //e.printStackTrace();
                //System.err.println("error for method " + method.getLongName());
                //throw e;
            }
        }
    }

    private void transform(ClassPool cp, String className, CtClass cc, CtMethod method) throws CannotCompileException {
        if (config.collectStack) {
            method.insertBefore(String.format("me.bechberger.trace.Stack.push(\"%s\", \"%s\", \"%s\");", className, method.getName() + count.getAndIncrement(), method.getSignature()));
            method.instrument(new ExprEditor() {
                @Override
                public void edit(MethodCall m) throws CannotCompileException {
                    if (m.getClassName().equals("me/bechberger/trace/Stack")) {
                        return;
                    }
                    m.replace("me.bechberger.trace.Stack.pushMethodInCaller(\"" + m.getMethodName() + "\"); $_ = $proceed($$); me.bechberger.trace.Stack.popMethodInCaller();");
                }
            });
            method.insertAfter("me.bechberger.trace.Stack.pop();", true);
        }
        if (config.callNativeMethodProbability >= Math.random()) {
            method.insertBefore("me.bechberger.trace.NativeChecker.checkTrace(" + config.printAllTraces + ");");
        }
    }
}
