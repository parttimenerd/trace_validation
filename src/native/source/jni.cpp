#include "me_bechberger_trace_NativeChecker.h"

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>
#include "jvmti.h"

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif
#include <ucontext.h>
#include <atomic>
#include <array>

/** maximum size of stack trace arrays */
const int MAX_DEPTH = 1024;

static jvmtiEnv* jvmti;

template <class T>
class JvmtiDeallocator {
 public:
  JvmtiDeallocator() {
    elem_ = NULL;
  }

  ~JvmtiDeallocator() {
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(elem_));
  }

  T* get_addr() {
    return &elem_;
  }

  T get() {
    return elem_;
  }

 private:
  T elem_;
};

std::string jstring2string(JNIEnv *env, jstring str) {
  // https://stackoverflow.com/a/57666349/19040822 helped
  if (str == NULL) {
      return std::string();
  }
  const char* raw = env->GetStringUTFChars(str, NULL);
  if (raw == NULL) {
    return std::string();
  }
  std::string result(raw);

  env->ReleaseStringUTFChars(str, raw);
  return result;
}

static void GetJMethodIDs(jclass klass) {
  jint method_count = 0;
  JvmtiDeallocator<jmethodID*> methods;
  jvmtiError err = jvmti->GetClassMethods(klass, &method_count, methods.get_addr());

  // If ever the GetClassMethods fails, just ignore it, it was worth a try.
  if (err != JVMTI_ERROR_NONE) {
    //fprintf(stderr, "GetJMethodIDs: Error in GetClassMethods: %d\n", err);
  }
}


// AsyncGetCallTrace needs class loading events to be turned on!
static void JNICALL OnClassLoad(jvmtiEnv *jvmti, JNIEnv *jni_env,
                                jthread thread, jclass klass) {
}

static void JNICALL OnClassPrepare(jvmtiEnv *jvmti, JNIEnv *jni_env,
                                   jthread thread, jclass klass) {
  // We need to do this to "prime the pump" and get jmethodIDs primed.
  GetJMethodIDs(klass);
}

static void JNICALL OnVMInit(jvmtiEnv *jvmti, JNIEnv *jni_env, jthread thread) {
  jint class_count = 0;

  // Get any previously loaded classes that won't have gone through the
  // OnClassPrepare callback to prime the jmethods for AsyncGetCallTrace.
  JvmtiDeallocator<jclass*> classes;
  jvmtiError err = jvmti->GetLoadedClasses(&class_count, classes.get_addr());
  if (err != JVMTI_ERROR_NONE) {
    //fprintf(stderr, "OnVMInit: Error in GetLoadedClasses: %d\n", err);
    return;
  }

  // Prime any class already loaded and try to get the jmethodIDs set up.
  jclass *classList = classes.get();
  for (int i = 0; i < class_count; ++i) {
    GetJMethodIDs(classList[i]);
  }
}

// A copy of the ASGCT data structures.
typedef struct {
    jint lineno;                      // line number in the source file
    jmethodID method_id;              // method executed in this frame
} ASGCT_CallFrame;

typedef struct {
    JNIEnv *env_id;                   // Env where trace was recorded
    jint num_frames;                  // number of frames in this trace
    ASGCT_CallFrame *frames;          // frames
} ASGCT_CallTrace;

typedef void (*ASGCTType)(ASGCT_CallTrace *, jint, void *);

ASGCTType asgct;

static int maxDepth = MAX_DEPTH;
static int printAllStacks = 0;
static int printEveryNthBrokenTrace = 1;
static int printEveryNthValidTrace = -1;
static int printStatsEveryNthTrace = -1;
static int checkEveryNthStackFully = 0;

JNIEXPORT void JNICALL Java_me_bechberger_trace_NativeChecker_init
  (JNIEnv *env, jclass, jboolean _printAllStacks, jint _maxDepth, jint _printEveryNthBrokenTrace,
  jint _printEveryNthValidTrace, jint _printStatsEveryNthTrace, jint _checkEveryNthStackFully) {
  maxDepth = _maxDepth;
  printAllStacks = _printAllStacks;
  printEveryNthBrokenTrace = _printEveryNthBrokenTrace;
  printEveryNthValidTrace = _printEveryNthValidTrace;
  printStatsEveryNthTrace = _printStatsEveryNthTrace;
  checkEveryNthStackFully = _checkEveryNthStackFully;
}

extern "C" {

void JNICALL
OnVMDeath(jvmtiEnv *jvmti_env,
            JNIEnv* jni_env);

static
jint Agent_Initialize(JavaVM *jvm, char *options, void *reserved) {
  jint res = jvm->GetEnv((void **) &jvmti, JVMTI_VERSION);
  if (res != JNI_OK || jvmti == NULL) {
    fprintf(stderr, "Error: wrong result of a valid call to GetEnv!\n");
    return JNI_ERR;
  }

  jvmtiError err;
  jvmtiCapabilities caps;
  memset(&caps, 0, sizeof(caps));
  caps.can_get_line_numbers = 1;
  caps.can_get_source_file_name = 1;

  err = jvmti->AddCapabilities(&caps);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stderr, "AgentInitialize: Error in AddCapabilities: %d\n", err);
    return JNI_ERR;
  }

  jvmtiEventCallbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ClassLoad = &OnClassLoad;
  callbacks.VMInit = &OnVMInit;
  callbacks.ClassPrepare = &OnClassPrepare;
  callbacks.VMDeath = &OnVMDeath;
  err = jvmti->SetEventCallbacks(&callbacks, sizeof(jvmtiEventCallbacks));
  jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_DEATH, (jthread)NULL);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stderr, "AgentInitialize: Error in SetEventCallbacks: %d\n", err);
    return JNI_ERR;
  }

  err = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_LOAD, NULL);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stderr, "AgentInitialize: Error in SetEventNotificationMode for CLASS_LOAD: %d\n", err);
    return JNI_ERR;
  }

  err = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_PREPARE, NULL);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stderr,
            "AgentInitialize: Error in SetEventNotificationMode for CLASS_PREPARE: %d\n",
            err);
    return JNI_ERR;
  }

  err = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, NULL);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(
        stderr, "AgentInitialize: Error in SetEventNotificationMode for VM_INIT: %d\n",
        err);
    return JNI_ERR;
  }

   asgct = reinterpret_cast<ASGCTType>(dlsym(RTLD_DEFAULT, "AsyncGetCallTrace"));
   if (asgct == NULL) {
     fprintf(stderr, "AsyncGetCallTrace not found.\n");
     return JNI_ERR;
   }

  return JNI_OK;
}

JNIEXPORT
jint JNICALL Agent_OnLoad(JavaVM *jvm, char *options, void *reserved) {
  return Agent_Initialize(jvm, options, reserved);
}

JNIEXPORT
jint JNICALL Agent_OnAttach(JavaVM *jvm, char *options, void *reserved) {
  return Agent_Initialize(jvm, options, reserved);
}

JNIEXPORT
jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {
  return JNI_VERSION_1_8;
}

void printMethod(FILE* stream, jmethodID method) {
  JvmtiDeallocator<char*> name;
  JvmtiDeallocator<char*> signature;
  jvmtiError err = jvmti->GetMethodName(method, name.get_addr(), signature.get_addr(), NULL);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stream, "Error in GetMethodName: %d", err);
    return;
  }
  jclass klass;
  JvmtiDeallocator<char*> className;
  jvmti->GetMethodDeclaringClass(method, &klass);
  jvmti->GetClassSignature(klass, className.get_addr(), NULL);
  fprintf(stream, "%s.%s%s", className.get(), name.get(), signature.get());
}

void printGSTFrame(FILE* stream, jvmtiFrameInfo frame) {
  if (frame.location == -1) {
    fprintf(stream, "Native frame");
    printMethod(stream, frame.method);
  } else {
    fprintf(stream, "Java frame   ");
    printMethod(stream, frame.method);
    fprintf(stream, ": %d", (int)frame.location);
  }
}


void printGSTTrace(FILE* stream, jvmtiFrameInfo* frames, int length) {
  fprintf(stream, "GST Trace length: %d\n", length);
  for (int i = 0; i < length; i++) {
    fprintf(stream, "Frame %d: ", i);
    printGSTFrame(stream, frames[i]);
    fprintf(stream, "\n");
  }
  fprintf(stream, "GST Trace end\n");
}

bool isASGCTNativeFrame(ASGCT_CallFrame frame) {
  return frame.lineno == -3;
}

void printASGCTFrame(FILE* stream, ASGCT_CallFrame frame) {
  JvmtiDeallocator<char*> name;
  jvmtiError err = jvmti->GetMethodName(frame.method_id, name.get_addr(), NULL, NULL);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stream, "=== asgst sampler failed: Error in GetMethodName: %d", err);
    return;
  }
  if (isASGCTNativeFrame(frame)) {
    fprintf(stream, "Native frame ");
    printMethod(stream, frame.method_id);
  } else {
    fprintf(stream, "Java frame   ");
    printMethod(stream, frame.method_id);
    fprintf(stream, ": %d", frame.lineno);
  }
}

void printASGCTFrames(FILE* stream, ASGCT_CallFrame *frames, int length) {
  for (int i = 0; i < length; i++) {
    fprintf(stream, "Frame %d: ", i);
    printASGCTFrame(stream, frames[i]);
    fprintf(stream, "\n");
  }
}

void printASGCTTrace(FILE* stream, ASGCT_CallTrace trace) {
  fprintf(stream, "ASGCT Trace length: %d\n", trace.num_frames);
  if (trace.num_frames > 0) {
    printASGCTFrames(stream, trace.frames, trace.num_frames);
  }
  fprintf(stream, "ASGCT Trace end\n");
}

std::atomic<long> traceCount(0);
std::atomic<long> brokenTraces(0);
std::atomic<long> errorWhenNoErrorExpected(0);
std::atomic<long> tooFewTraces(0);
std::atomic<long> tooManyTraces(0);
std::atomic<long> wrongLocation(0);
std::atomic<long> wrongMethod(0);
std::atomic<long> directMethodHandleRelated(0);
std::atomic<long> instrumentationRelated(0);
std::atomic<long> gstError(0);
std::atomic<long> instrumentationChecked(0);
std::atomic<long> instrumentationMismatch(0);
std::atomic<long> instrumentationMismatchCount(0);

void printValue(const char* name, std::atomic<long> &value, std::atomic<long> &total = traceCount) {
  fprintf(stdout, "%-25s: %10ld %10.3f%%\n", name, value.load(), value.load() * 100.0 / total.load());
}

void printInfo() {
  printValue("traces", traceCount);
  printValue("broken traces", brokenTraces);
  printValue("  error", errorWhenNoErrorExpected);
  printValue("  too few traces", tooFewTraces);
  printValue("  too few traces", tooFewTraces);
  printValue("  too many traces", tooManyTraces);
  printValue("  wrong location", wrongLocation);
  printValue("  wrong method", wrongMethod);
  printValue(" of all: method handle", directMethodHandleRelated);
  printValue(" of all: instrumentation", instrumentationRelated);
  printValue(" add: GST error", gstError);
  if (checkEveryNthStackFully > 0) {
    printValue("instrumentation checked", instrumentationChecked, instrumentationChecked);
    printValue("  err", instrumentationMismatch, instrumentationChecked);
    printValue("  err count", instrumentationMismatchCount, instrumentationChecked);
  }
}

JNIEXPORT
void JNICALL Agent_OnUnload(JavaVM *jvm) {
printInfo();
}

void JNICALL
OnVMDeath(jvmtiEnv *jvmti_env,
            JNIEnv* jni_env) {
                         }

bool doesTraceHaveBottomClass(ASGCT_CallTrace &trace, const char* className) {
  if (trace.num_frames > 0) {
    ASGCT_CallFrame frame = trace.frames[trace.num_frames - 1];
    if (isASGCTNativeFrame(frame)) {
      return false;
    }
    JvmtiDeallocator<char*> name;
    jvmtiError err = jvmti->GetMethodName(frame.method_id, name.get_addr(), NULL, NULL);
    if (err != JVMTI_ERROR_NONE) {
      fprintf(stderr, "=== asgst sampler failed: Error in GetMethodName: %d", err);
      return false;
    }
    jclass klass;
    JvmtiDeallocator<char*> klassName;
    jvmti->GetMethodDeclaringClass(frame.method_id, &klass);
    jvmti->GetClassSignature(klass, klassName.get_addr(), NULL);
    if (strncmp(klassName.get(), className, strlen(className)) == 0) {
      return true;
    }
  }
  return false;
}

bool doesTraceHaveClassSomewhere(ASGCT_CallTrace &trace, const char* className) {
  for (int i = 0; i < trace.num_frames; i++) {
    ASGCT_CallFrame frame = trace.frames[i];
    if (isASGCTNativeFrame(frame)) {
      continue;
    }
    JvmtiDeallocator<char*> name;
    jvmtiError err = jvmti->GetMethodName(frame.method_id, name.get_addr(), NULL, NULL);
    if (err != JVMTI_ERROR_NONE) {
      fprintf(stderr, "=== asgst sampler failed: Error in GetMethodName: %d", err);
      return false;
    }
    jclass klass;
    JvmtiDeallocator<char*> klassName;
    jvmti->GetMethodDeclaringClass(frame.method_id, &klass);
    jvmti->GetClassSignature(klass, klassName.get_addr(), NULL);
    if (strcmp(klassName.get(), className) == 0) {
      return true;
    }
  }
  return false;
}

bool shouldPrintStackTrace(bool valid) {
  if (printAllStacks) {
    return true;
  }
  if (valid && printEveryNthValidTrace > 0) {
    return traceCount % printEveryNthValidTrace == 0;
  }
  if (!valid && printEveryNthBrokenTrace > 0) {
    return traceCount % printEveryNthBrokenTrace == 0;
  }
  return false;
}

bool shouldPrintStats() {
  return printStatsEveryNthTrace > 0 && traceCount % printStatsEveryNthTrace == 0;
}

struct StackFrame {
  std::string klass;
  std::string method;
};

class InstrumentationStack {
  std::array<StackFrame, MAX_DEPTH> instrumentationStack;
  std::atomic<size_t> _size; // movs are not guaranteed to be atomic otherwise (albeit it is on x86_64)

public:

  InstrumentationStack() : _size(0) {}

  void push(JNIEnv *env, const jstring klass, const jstring method) {
    jboolean isCopy;
    if (_size.load() < MAX_DEPTH) {
      instrumentationStack.at(_size.load()) = {
        .klass = "L" + jstring2string(env, klass) + ";",
        .method = jstring2string(env, method)
      };
    }
    _size++;
  }

  void pop() {
    _size--;
  }

  const StackFrame& frame(size_t index) const {
    return instrumentationStack.at(index);
  }

  /** returns the frame index from top */
  const StackFrame& cframe(size_t index) const {
    return instrumentationStack.at(size() - index - 1);
  }

  size_t size() const {
    return std::min((int)_size.load(), MAX_DEPTH);
  }

  void print() {
    if (size() == 0) {
      fprintf(stderr, "no frames\n");
      return;
    }
    for (int i = size() - 1; i >= 0; i--) {
      fprintf(stderr, "ins frame %ld: %s.%s\n", size() - i - 1, frame(i).klass.c_str(), frame(i).method.c_str());
    }
  }
};

thread_local InstrumentationStack instrumentationStack;


/*
 * Class:     me_bechberger_trace_NativeChecker
 * Method:    push
 * Signature: (Ljava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_me_bechberger_trace_NativeChecker_push
  (JNIEnv *env, jclass, jstring klass, jstring method) {
  instrumentationStack.push(env, klass, method);
}

/*
 * Class:     me_bechberger_trace_NativeChecker
 * Method:    pop
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_me_bechberger_trace_NativeChecker_pop
  (JNIEnv *, jclass) {
  instrumentationStack.pop();
}

void compareASGCTWithInstrumentation(JNIEnv *env, ASGCT_CallFrame *frames, int num_frames) {
  assert(num_frames < maxDepth); // it doesn't make sense to check if the trace is possibly cut off
  if (num_frames < 0) {
    return; // some error occurred
  }
  instrumentationChecked++;
  auto handleError = [&]()  {
    fprintf(stderr, "instrumentation stack:\n");
    instrumentationStack.print();
    fprintf(stderr, "asgct stack:\n");
    printASGCTFrames(stderr, frames, num_frames);
    instrumentationMismatch++;
  };

  // first check the size
  if (num_frames < instrumentationStack.size()) {
    // this should never be the case, the reverse might be true
    fprintf(stderr, "instrumentation stack is larger than asgct stack: %ld vs %d\n", instrumentationStack.size(), num_frames);
    handleError();
    return;
  }

  // now go from bottom to top most frame
  int cindex = 0; // instrumentation stack index
  for (int i = 0; i < num_frames && cindex < instrumentationStack.size(); i++) {
    ASGCT_CallFrame frame = frames[i];
    StackFrame cframe = instrumentationStack.cframe(cindex);
    JvmtiDeallocator<char*> name;
    JvmtiDeallocator<char*> signature;
    jvmtiError err = jvmti->GetMethodName(frame.method_id, name.get_addr(), signature.get_addr(), NULL);
    if (err != JVMTI_ERROR_NONE) {
      fprintf(stderr, "Error in GetMethodName: %d", err);
      return;
    }
    jclass klass;
    JvmtiDeallocator<char*> className;
    jvmti->GetMethodDeclaringClass(frame.method_id, &klass);
    jvmti->GetClassSignature(klass, className.get_addr(), NULL);

    std::string classNameString = className.get();
    std::string methodNameString = std::string(name.get()) + std::string(signature.get());

    if (classNameString == cframe.klass && methodNameString == cframe.method) {
      cindex++;
    }
  }
  if (cindex != instrumentationStack.size()) {
    fprintf(stderr, "Did not find bottom %ld instrumentation frames in ASGCT\n", instrumentationStack.size() - cindex);
    handleError();
  }
  return;
}

JNIEXPORT void JNICALL Java_me_bechberger_trace_NativeChecker_checkTrace
  (JNIEnv *env, jclass klass) {
  if (maxDepth > MAX_DEPTH) {
    fprintf(stderr, "maxDepth too large: %d > %d", maxDepth, MAX_DEPTH);
    return;
  }


  jthread thread;
  jvmti->GetCurrentThread(&thread);
  jvmtiFrameInfo gstFrames[MAX_DEPTH];
  jint gstCount = 0;
  jvmtiError err = jvmti->GetStackTrace(thread, 0, maxDepth, gstFrames, &gstCount);
  if (err != JVMTI_ERROR_NONE && err) {
    gstError++;
    if (err == JVMTI_ERROR_WRONG_PHASE) {
      return; // omit
    }
    fprintf(stderr, "=== asgst sampler failed: Error in GetStackTrace: ");
    switch (err) {
      case JVMTI_ERROR_ILLEGAL_ARGUMENT:
        fprintf(stderr, "start_depth is positive and greater than or equal to stackDepth. Or start_depth is negative and less than -stackDepth.\n");
        break;
      case JVMTI_ERROR_INVALID_THREAD:
        fprintf(stderr, "thread is not a thread object. \n");
        break;
      case JVMTI_ERROR_THREAD_NOT_ALIVE:
        fprintf(stderr, "thread is not alive (has not been started or has terminated).\n");
        break;
      case JVMTI_ERROR_NULL_POINTER:
        fprintf(stderr, "stack_info_ptr is NULL.\n");
        break;
      case JVMTI_ERROR_WRONG_PHASE:
        fprintf(stderr, "JVMTI is not in live phase.\n");
        break;
      default:
        fprintf(stderr, "unknown error %d.\n", err);
        break;
    }
    return; // we're not getting anything with the oracle
  }

  traceCount++;

  ASGCT_CallTrace trace;
  ASGCT_CallFrame frames[MAX_DEPTH];
  trace.frames = frames;
  trace.env_id = env;
  trace.num_frames = 0;
  asgct(&trace, maxDepth, NULL);

  if (checkEveryNthStackFully > 0 && traceCount % checkEveryNthStackFully == 0 && trace.num_frames < maxDepth) {
    compareASGCTWithInstrumentation(env, frames, trace.num_frames);
  }

  auto printTraces = [&] () {
    if (shouldPrintStackTrace(false)) {
      fprintf(stderr, "GST Trace:\n");
      printGSTTrace(stderr, gstFrames, gstCount);
      fprintf(stderr, "ASGCT Trace:\n");
      printASGCTTrace(stderr, trace);
      setenv("ASGCT_LOG", "1", 1);
      asgct(&trace, MAX_DEPTH, NULL);
      setenv("ASGCT_LOG", "0", 1);
    }
    if (doesTraceHaveBottomClass(trace, "Ljava/lang/invoke/DirectMethodHandle$Holder;") || doesTraceHaveBottomClass(trace, "Ljava/lang/invoke/LambdaForm")) {
      directMethodHandleRelated++;
    }
    if (doesTraceHaveClassSomewhere(trace, "Lsun/instrument/InstrumentationImpl;")) {
      instrumentationRelated++;
    }
    if (shouldPrintStats()) {
      printInfo();
    }
  };

  // For now, just check that the first frame is (-3, checkAsyncGetCallTraceCall).
  if (trace.num_frames <= 0) {
    // we are at a well defined point in the execution, so we should be able to obtain a trace
    fprintf(stderr, "The num_frames must be positive: %d\n", trace.num_frames);
    printTraces();
    brokenTraces++;
    errorWhenNoErrorExpected++;
    return;
  }

  if (gstCount != trace.num_frames) {
    fprintf(stderr, "GetStackTrace and AsyncGetCallTrace return different number of frames: GST=%d vs ASGCT=%d)\n", gstCount, trace.num_frames);
    printTraces();
    brokenTraces++;
    if (gstCount > trace.num_frames) {
      tooFewTraces++;
    } else {
      tooManyTraces++;
    }
    return;
  }

  for (int i = 0; i < trace.num_frames; ++i) {
    if (trace.frames[i].lineno == -3) {
      if (gstFrames[i].location != -1) {
        fprintf(stderr, "%d: ASGCT found native frame but GST did not\n", i);
        printTraces();
        brokenTraces++;
        wrongLocation++;
        return;
      }
    } else {
      if (gstFrames[i].method != trace.frames[i].method_id) {
        fprintf(stderr, "%d: method_id mismatch: %p vs %p\n", i, gstFrames[i].method, trace.frames[i].method_id);
        printTraces();
        brokenTraces++;
        wrongMethod++;
        return;
      }
    }
  }

  if (shouldPrintStackTrace(true)) {
    printASGCTTrace(stderr, trace);
  }
  if (shouldPrintStats()) {
    printInfo();
  }
  return;
}

}
