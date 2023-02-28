#include "me_bechberger_trace_NativeChecker.h"

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jvmti.h"

#define _XOPEN_SOURCE 600
#include <ucontext.h>
#include <atomic>


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

JNIEXPORT void JNICALL Java_me_bechberger_trace_NativeChecker_init
  (JNIEnv *env, jclass) {

}


extern "C" {

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
  err = jvmti->SetEventCallbacks(&callbacks, sizeof(jvmtiEventCallbacks));
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

void printValue(const char* name, std::atomic<long> &value) {
  fprintf(stderr, "%20s: %10ld %10.4f%%\n", name, value.load(), value.load() * 100.0 / traceCount.load());
}

JNIEXPORT
void JNICALL Agent_OnUnload(JavaVM *jvm) {
  printValue("traces", traceCount);
  printValue("broken traces", brokenTraces);
  printValue("  error", errorWhenNoErrorExpected);
  printValue("  too few traces", tooFewTraces);
  printValue("  too many traces", tooManyTraces);
  printValue("  wrong location", wrongLocation);
  printValue("  wrong method", wrongMethod);
}

JNIEXPORT void JNICALL Java_me_bechberger_trace_NativeChecker_checkTrace
  (JNIEnv *env, jclass klass, jboolean printAllTraces) {
  const int MAX_DEPTH = 1024;

  jthread thread;
  jvmti->GetCurrentThread(&thread);
  jvmtiFrameInfo gstFrames[MAX_DEPTH];
  jint gstCount = 0;
  jvmtiError err = jvmti->GetStackTrace(thread, 0, MAX_DEPTH, gstFrames, &gstCount);
  if (err != JVMTI_ERROR_NONE) {
    return; // we're not getting anything with the oracle
  }

  traceCount++;

  if (printAllTraces) {
    printGSTTrace(stderr, gstFrames, gstCount);
  }

  ASGCT_CallTrace trace;
  ASGCT_CallFrame frames[MAX_DEPTH];
  trace.frames = frames;
  trace.env_id = env;
  trace.num_frames = 0;
  asgct(&trace, MAX_DEPTH, NULL);
  if (printAllTraces) {
    printASGCTTrace(stderr, trace);
  }
  auto printTraces = [&] () {
    fprintf(stderr, "GST Trace:\n");
    printGSTTrace(stderr, gstFrames, gstCount);
    fprintf(stderr, "ASGCT Trace:\n");
    printASGCTTrace(stderr, trace);
  };

  // For now, just check that the first frame is (-3, checkAsyncGetCallTraceCall).
  if (trace.num_frames <= 0) {
    // we are at a well defined point in the execution, so we should be able to obtain a trace
    fprintf(stderr, "The num_frames must be positive: %d\n", trace.num_frames);
    brokenTraces++;
    errorWhenNoErrorExpected++;
    return;
  }

  if (gstCount != trace.num_frames) {
    fprintf(stderr, "GetStackTrace and AsyncGetCallTrace return different number of frames: GST=%d vs ASGCT=%d)\n", gstCount, trace.num_frames);
    printTraces();
    brokenTraces++;
    if (gstCount < trace.num_frames) {
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
  return;
}

}
