#include "me_bechberger_trace_NativeChecker.h"

#include <algorithm>
#include <assert.h>
#include <iterator>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>
#include <mutex>
#include "jvmti.h"
#include <unordered_set>
#include <thread>
#include <signal.h>
#include <random>
#include <cassert>
#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif
#include <ucontext.h>
#include <atomic>
#include <array>

#if defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
#endif

/** maximum size of stack trace arrays */
const int MAX_DEPTH = 1024;

static jvmtiEnv* jvmti;
static JavaVM* jvm;
static JNIEnv* env;

std::mutex threadsMutex;
std::unordered_set<pthread_t> threads;

typedef void (*SigAction)(int, siginfo_t*, void*);
typedef void (*SigHandler)(int);
typedef void (*TimerCallback)(void*);

static SigAction installSignalHandler(int signo, SigAction action, SigHandler handler = NULL) {
    struct sigaction sa;
    struct sigaction oldsa;
    sigemptyset(&sa.sa_mask);

    if (handler != NULL) {
        sa.sa_handler = handler;
        sa.sa_flags = 0;
    } else {
        sa.sa_sigaction = action;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
    }

    sigaction(signo, &sa, &oldsa);
    return oldsa.sa_sigaction;
}

void ensureSuccess(jvmtiError err, const char *msg) {
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stderr, "Error in %s: %d", msg, err);
    exit(1);
  }
}

template <class T>
class JvmtiDeallocator {
 public:
  JvmtiDeallocator() {
    elem_ = NULL;
  }

  ~JvmtiDeallocator() {
    if (elem_ != NULL) {
      jvmti->Deallocate(reinterpret_cast<unsigned char*>(elem_));
    }
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

pid_t get_thread_id() {
  #if defined(__APPLE__) && defined(__MACH__)
  uint64_t tid;
  pthread_threadid_np(NULL, &tid);
  return (pid_t) tid;
  #else
  return syscall(SYS_gettid);
  #endif
}

void OnThreadStart(jvmtiEnv *jvmti_env, JNIEnv* jni_env, jthread thread) {
  const std::lock_guard<std::mutex> lock(threadsMutex);
  threads.insert(get_thread_id());
}

void OnThreadEnd(jvmtiEnv *jvmti_env, JNIEnv* jni_env, jthread thread) {
  const std::lock_guard<std::mutex> lock(threadsMutex);
  threads.erase(get_thread_id());
}

static void GetJMethodIDs(jclass klass) {
  jint method_count = 0;
  JvmtiDeallocator<jmethodID*> methods;
  jvmtiError err = jvmti->GetClassMethods(klass, &method_count, methods.get_addr());
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

/** obtain all os threads */
std::vector<pthread_t> obtainThreads() {
  std::vector<pthread_t> result;
  #if defined(__APPLE__) && defined(__MACH__)
  // TODO: check if this is correct
  int count = 0;
  thread_act_array_t thread_list;
  kern_return_t kr = task_threads(mach_task_self(), &thread_list, &count);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "Error in obtaining threads\n");
    exit(1);
  }

  for (int i = 0; i < count; i++) {
    result.push_back(thread_list[i]);
  }

  vm_deallocate(mach_task_self(), (vm_address_t)thread_list, count * sizeof(thread_act_t));
  #else
  // source https://stackoverflow.com/a/29546902/19040822
    DIR *proc_dir;
    {
        char dirname[100];
        snprintf(dirname, sizeof dirname, "/proc/%d/task", getpid());
        proc_dir = opendir(dirname);
    }

    if (proc_dir)
    {
        /* /proc available, iterate through tasks... */
        struct dirent *entry;
        while ((entry = readdir(proc_dir)) != NULL)
        {
            if(entry->d_name[0] == '.')
                continue;

            result.push_back((pthread_t)atoi(entry->d_name));

        }

        closedir(proc_dir);
    }
    else
    {
      fprintf(stderr, "Error in obtaining threads\n");
      exit(1);
    }
  #endif
  return result;
}

static void updateThreads() {
  auto ts = obtainThreads();
  std::lock_guard<std::mutex> lock(threadsMutex);
  threads = {ts.begin(), ts.end()};
}

static void JNICALL OnVMInit(jvmtiEnv *jvmti, JNIEnv *jni_env, jthread thread) {
  env = jni_env;
  jint class_count = 0;

  // Get any previously loaded classes that won't have gone through the
  // OnClassPrepare callback to prime the jmethods for AsyncGetCallTrace.
  // else the jmethods are all NULL. This might still happen if ASGCT is called at the very beginning,
  // while this code is executed.
  // But this is not a problem in the typical use case.
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
  updateThreads();
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

std::atomic<bool> shouldStop;

static void sampleLoop();

std::thread samplerThread;


static void signalHandler(int signum, siginfo_t* info, void* ucontext);

static void startSamplerThread() {
  updateThreads();
  samplerThread = std::thread(sampleLoop);
  installSignalHandler(SIGPROF, signalHandler);
}

static int maxDepth = MAX_DEPTH;
static int printAllStacks = 0;
static int printEveryNthBrokenTrace = 1;
static int printEveryNthValidTrace = -1;
static int printStatsEveryNthTrace = -1;
static int printStatsEveryNthBrokenTrace = -1;
static int checkEveryNthStackFully = 0;
static int sampleIntervalInUs = -1;
static bool runTraceStackSampler = false;
static bool ignoreInstrumentationForTraceStack = false;

thread_local bool inInstrumentation = false;

JNIEXPORT void JNICALL Java_me_bechberger_trace_NativeChecker_init
  (JNIEnv *env, jclass, jboolean _printAllStacks, jint _maxDepth, jint _printEveryNthBrokenTrace,
  jint _printEveryNthValidTrace, jint _printStatsEveryNthTrace, int _printStatsEveryNthBrokenTrace, jint _checkEveryNthStackFully,
  jint _sampleIntervalInUs, jboolean _runTraceStackSampler, jboolean _ignoreInstrumentationForTraceStack) {
  maxDepth = _maxDepth;
  printAllStacks = _printAllStacks;
  printEveryNthBrokenTrace = _printEveryNthBrokenTrace;
  printEveryNthValidTrace = _printEveryNthValidTrace;
  printStatsEveryNthTrace = _printStatsEveryNthTrace;
  printStatsEveryNthBrokenTrace = _printStatsEveryNthBrokenTrace;
  checkEveryNthStackFully = _checkEveryNthStackFully;
  sampleIntervalInUs = _sampleIntervalInUs;
  runTraceStackSampler = _runTraceStackSampler;
  ignoreInstrumentationForTraceStack = _ignoreInstrumentationForTraceStack;
  if (sampleIntervalInUs > -1) {
    startSamplerThread();
  }
}

void JNICALL Java_me_bechberger_trace_NativeChecker_setInInstrumentation
  (JNIEnv *, jclass, jboolean _inInstrumentation) {
  inInstrumentation = _inInstrumentation == JNI_TRUE;
}

extern "C" {

void JNICALL
OnVMDeath(jvmtiEnv *jvmti_env,
            JNIEnv* jni_env);

static
jint Agent_Initialize(JavaVM *_jvm, char *options, void *reserved) {
  jvm = _jvm;
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

  ensureSuccess(jvmti->AddCapabilities(&caps), "AddCapabilities");

  jvmtiEventCallbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ClassLoad = &OnClassLoad;
  callbacks.VMInit = &OnVMInit;
  callbacks.ClassPrepare = &OnClassPrepare;
  callbacks.VMDeath = &OnVMDeath;
  callbacks.ThreadStart = &OnThreadStart;
  callbacks.ThreadEnd = &OnThreadEnd;
  ensureSuccess(jvmti->SetEventCallbacks(&callbacks, sizeof(jvmtiEventCallbacks)), "SetEventCallbacks");
  ensureSuccess(jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_LOAD, NULL), "class load");
  ensureSuccess(jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_PREPARE, NULL), "class prepare");
  ensureSuccess(jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, NULL), "vm init");
  ensureSuccess(jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_DEATH, NULL), "vm death");
  ensureSuccess(jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_THREAD_START, NULL), "thread start");
  ensureSuccess(jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_THREAD_END, NULL), "thread end");


   asgct = reinterpret_cast<ASGCTType>(dlsym(RTLD_DEFAULT, "AsyncGetCallTrace"));
   if (asgct == NULL) {
     fprintf(stderr, "AsyncGetCallTrace not found.\n");
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
  if (method == nullptr) {
    fprintf(stream, "<null>");
    return;
  }
  jvmtiError err = jvmti->GetMethodName(method, name.get_addr(), signature.get_addr(), NULL);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stream, "<err>");
    return;
  }
  jclass klass;
  JvmtiDeallocator<char*> className;
  jvmti->GetMethodDeclaringClass(method, &klass);
  if (klass == NULL) {
    fprintf(stream, "<err>");
    return;
  }
  jvmti->GetClassSignature(klass, className.get_addr(), NULL);
  if (className.get() == NULL) {
    fprintf(stream, "<err>");
    return;
  }
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
  if (frame.method_id == NULL) {
    fprintf(stream, "<null>");
    return;
  }
  jvmtiError err = jvmti->GetMethodName(frame.method_id, name.get_addr(), NULL, NULL);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stream, "<err %p>", frame.method_id);
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

std::atomic<size_t> traceCount(0);
std::atomic<size_t> brokenTraces(0);
std::atomic<size_t> errorWhenNoErrorExpected(0);
std::atomic<size_t> tooFewTraces(0);
std::atomic<size_t> tooManyTraces(0);
std::atomic<size_t> wrongLocation(0);
std::atomic<size_t> wrongMethod(0);
std::atomic<size_t> directMethodHandleRelated(0);
std::atomic<size_t> instrumentationRelated(0);
std::atomic<size_t> gstError(0);
std::atomic<size_t> instrumentationChecked(0);
std::atomic<size_t> instrumentationMismatch(0);
std::atomic<size_t> instrumentationMismatchCount(0);

void printValue(const char* name, std::atomic<size_t> &value, std::atomic<size_t> &total = traceCount) {
  fprintf(stderr, "%-26s: %10ld %10.3f%%\n", name, value.load(), value.load() * 100.0 / total.load());
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

void printTraceStackInfo();

JNIEXPORT
void JNICALL Agent_OnUnload(JavaVM *jvm) {
  shouldStop = true;
  printInfo();
  printTraceStackInfo();
}

void JNICALL
OnVMDeath(jvmtiEnv *jvmti_env,
            JNIEnv* jni_env) {
  shouldStop = true;
                         }

bool doesFrameHaveClass(ASGCT_CallFrame frame, const char* className) {
  JvmtiDeallocator<char*> name;
  if (frame.method_id == NULL) {
    return false;
  }
  jvmtiError err = jvmti->GetMethodName(frame.method_id, name.get_addr(), NULL, NULL);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stderr, "=== asgst sampler failed: Error in GetMethodName: %d", err);
    return false;
  }
  jclass klass;
  JvmtiDeallocator<char*> klassName;
  jvmti->GetMethodDeclaringClass(frame.method_id, &klass);
  if (klass == NULL) {
    return false;
  }
  jvmti->GetClassSignature(klass, klassName.get_addr(), NULL);
  if (klassName.get() == NULL) {
    return false;
  }
  if (strncmp(klassName.get(), className, strlen(className)) == 0) {
    return true;
  }
  return false;
}

bool doesTraceHaveBottomClass(ASGCT_CallTrace &trace, const char* className) {
  if (trace.num_frames > 0) {
    ASGCT_CallFrame frame = trace.frames[trace.num_frames - 1];
    return doesFrameHaveClass(frame, className);
  }
  return false;
}

bool doesTraceHaveClassSomewhere(ASGCT_CallTrace &trace, const char* className) {
  for (int i = 0; i < trace.num_frames; i++) {
    ASGCT_CallFrame frame = trace.frames[i];
    return doesFrameHaveClass(frame, className);
  }
  return false;
}

bool doesTraceHaveTopClass(ASGCT_CallTrace &trace, const char* className) {
  if (trace.num_frames > 0) {
    ASGCT_CallFrame frame = trace.frames[0];
    return doesFrameHaveClass(frame, className);
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

bool shouldPrintStats(bool broken) {
  return (printStatsEveryNthTrace > 0 && traceCount % printStatsEveryNthTrace == 0) || (printStatsEveryNthBrokenTrace > 0 && broken && brokenTraces % printStatsEveryNthBrokenTrace == 0);
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
    if (frame.method_id == NULL) {
      handleError();
    }
    jvmtiError err = jvmti->GetMethodName(frame.method_id, name.get_addr(), signature.get_addr(), NULL);
    if (err != JVMTI_ERROR_NONE) {
      fprintf(stderr, "Error in GetMethodName: %d", err);
      return;
    }
    jclass klass;
    JvmtiDeallocator<char*> className;
    jvmti->GetMethodDeclaringClass(frame.method_id, &klass);
    if (klass == NULL) {
      fprintf(stderr, "klass is null\n");
      return;
    }
    jvmti->GetClassSignature(klass, className.get_addr(), NULL);
    if (className.get() == NULL) {
      fprintf(stderr, "className is null\n");
      return;
    }

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
      asgct(&trace, maxDepth, NULL);
      setenv("ASGCT_LOG", "0", 1);
    }
    if (doesTraceHaveBottomClass(trace, "Ljava/lang/invoke/DirectMethodHandle$Holder;") || doesTraceHaveBottomClass(trace, "Ljava/lang/invoke/LambdaForm")) {
      directMethodHandleRelated++;
    }
    if (doesTraceHaveClassSomewhere(trace, "Lsun/instrument/InstrumentationImpl;")) {
      instrumentationRelated++;
    }
    if (shouldPrintStats(true)) {
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
  if (shouldPrintStats(false)) {
    printInfo();
  }
  return;
}

std::atomic<size_t> traceStackCount(0);
std::atomic<size_t> traceStackTooLong(0); // signal handler trace has >= maxDepth frames, not considered broken
std::atomic<size_t> traceStackASGCTError(0); // error in ASGCT in signal handler
std::atomic<size_t> checkedTraceStackCount(0);
std::atomic<size_t> brokenTraceStacks(0);
std::atomic<size_t> traceStackTooShort(0); // signal handler trace is shorter than expected
std::atomic<size_t> traceStackOneFrameTooShort(0);
std::atomic<size_t> traceStackWrongFrameMethodId(0);
std::atomic<size_t> traceStackWrongFrameMethodIdForTopMostFrame(0);
std::atomic<size_t> traceStackWrongFrameLocation(0); // not checked for the top most stored frame
std::atomic<size_t> traceStackWrongNativeness(0); // frames differ in their nativeness
std::atomic<size_t> traceStackBrokenMethodHandleRelated(0); // of all broken
std::atomic<size_t> traceStackBrokenInstrumentationRelated(0); // of all broken
std::atomic<size_t> trackStackLambdaMetaFactoryRelated(0); // of all broken
std::atomic<size_t> traceStackBrokenPushStack(0); // NativeChecker::pushStack on top

void printTraceStackInfo() {
  printValue("trace stack count", traceStackCount, traceStackCount);
  printValue("trace stack too long", traceStackTooLong, traceStackCount);
  printValue("trace stack ASGCT error", traceStackASGCTError, traceStackCount);
  printValue("checked trace stack count", checkedTraceStackCount, traceStackCount);
  printValue("  broken trace stacks", brokenTraceStacks, checkedTraceStackCount);
  printValue("    too short", traceStackTooShort, checkedTraceStackCount);
  printValue("      one frame", traceStackOneFrameTooShort, traceStackTooShort);
  printValue("    wrong frame method id", traceStackWrongFrameMethodId, checkedTraceStackCount);
  printValue("      top most frame", traceStackWrongFrameMethodIdForTopMostFrame, traceStackWrongFrameMethodId);
  printValue("    wrong frame location", traceStackWrongFrameLocation, checkedTraceStackCount);
  printValue("    wrong nativeness", traceStackWrongNativeness, checkedTraceStackCount);
  printValue("    of all: method handle", traceStackBrokenMethodHandleRelated, brokenTraceStacks);
  printValue("    of all: instrument", traceStackBrokenInstrumentationRelated, brokenTraceStacks);
  printValue("    of all: lambda factory", trackStackLambdaMetaFactoryRelated, brokenTraceStacks);
  printValue("    of all: pNC.pushStack", traceStackBrokenPushStack, brokenTraceStacks);
}

// run over all frames and return false if any of the method ids are null
bool checkTraceForMissingMethodIds(ASGCT_CallTrace trace) {
  assert(trace.num_frames > 0);
  for (int i = 0; i < trace.num_frames; ++i) {
    if (trace.frames[i].method_id == NULL) {
      return false;
    }
  }
  return true;
}

const int NO_LINENO = -7;

std::mutex javaThreadMutex;
std::unordered_set<pthread_t> javaThreads;

/**
 * @brief Stores the stack
 *
 */
class TraceStack {

  std::array<ASGCT_CallFrame, MAX_DEPTH> frames; // stack frames, from bottom to top
  std::array<int, MAX_DEPTH> prevStack; // previous stack index
  std::array<int, MAX_DEPTH> failedPushs; // number of times a push failed on this level
  volatile int top = -1; // current stack index (length - 1)
  bool checked = false; // already inserted itself into the javaThreads set

  ASGCT_CallTrace lastTrace;
  ASGCT_CallFrame lastFrames[MAX_DEPTH];

  void discardFirstFrame(ASGCT_CallTrace& trace) {
    assert(trace.num_frames > 0);
    trace.num_frames--;
    trace.frames = trace.frames + 1;
  }

  /**
   * @brief Pushes a new stack frame to the stack
   *
   * Deals with failed traces and traces that are too long
   *
   * We throw away the top most frame, as it should be the native method that called the push method.
   *
   * @return true if the trace was pushed, false otherwise (trace too long, failed or missing method ids)
   */
  bool push(ASGCT_CallTrace trace) {
    if (!checked) {
      std::lock_guard<std::mutex> lock(javaThreadMutex);
      int tid = get_thread_id();
      javaThreads.insert(tid);
      std::lock_guard<std::mutex> lock2(threadsMutex);
      if (threads.find(tid) == threads.end()) {
        threads.insert(tid);
      }
      checked = true;
    }
    if (trace.num_frames >= maxDepth || trace.num_frames <= 1 || !checkTraceForMissingMethodIds(trace)) {
      pushFailed();
      return false;
    }
    discardFirstFrame(trace);
    int lastTop = top;
    // keep in mind that the bottom most stack is at trace.num_frames - 1
    int diff = trace.num_frames - 1 - top;
    int framesOffset = 0;
    int locationDiff = diff; // diff used to loop over the frames array, that is offset by 1 if the top most frame is defined
                             // to override the lineno of the top most frame too
    if (diff < trace.num_frames) {
      locationDiff++; // so we override the lineno of the top most frame currently stored, which is now defined
      framesOffset = 1; // offset the access into the frames array
    }
    for (int i = 0; i < locationDiff; ++i) {
      assert(i < MAX_DEPTH);
      auto sframe = trace.frames[i];
      int framesIndex = top + locationDiff - i - framesOffset;
      frames.at(framesIndex) = sframe;
      if (i < diff) {
        prevStack.at(framesIndex) = -8; // should never be accessed
      }
    }
    top = trace.num_frames - 1;
    prevStack.at(top) = lastTop;
    frames.at(top).lineno = NO_LINENO;
    return true;
  }

  void pushFailed() {
    failedPushs[top]++;
  }

public:

  TraceStack() {
    lastTrace.frames = lastFrames;
    lastTrace.num_frames = 0;
  }

  void debugPrint(FILE* file) {
    fprintf(file, "ts top: %d\n", top);
    for (int i = 0; i <= top; ++i) {
      fprintf(file, "  %2d: ps=%2d fp=%2d ", i, prevStack[i], failedPushs[i]);
      printASGCTFrame(file, frames[i]);
      fprintf(file, "\n");
    }
    fprintf(file, "ts end\n");
  }


  void printTraceStack(FILE* file) {
    if (top < 0) {
      return;
    }
    for (int i = 0; i < top + 1; ++i) {
      auto frame = frames[top - i];
      fprintf(file, "Frame %d: ", i);
      printASGCTFrame(file, frame);
      fprintf(file,  "\n");
    }
  }

  void push(JNIEnv* env) {
    lastTrace.env_id = env;
    asgct(&lastTrace, maxDepth, NULL);
   // printASGCTTrace(stdout, lastTrace);
    if (push(lastTrace)) {
     // fprintf(stderr, "              pushed %d\n", get_thread_id());
      //debugPrint(stderr);
    } else {
      //fprintf(stderr, "-");
    }
  }

  /**
   * @brief Pops the last stack frame from the stack
   */
  void pop() {
    if (top < 0) {
      return;
    }
    if (failedPushs.at(top) > 0) {
      failedPushs.at(top)--;
    } else {
      top = prevStack.at(top);
    }
    if (top >= 0) {
      frames.at(top).lineno = NO_LINENO; // we don't know the line number of the top most frame anymore
    }
  }

  bool hasStack() {
    return top >= 0;
  }

  void check(ASGCT_CallTrace trace, bool dropTop = false) {
    if (dropTop && trace.num_frames > 0) {
      discardFirstFrame(trace);
    }
    traceStackCount++;
    if (top < 0) {
      return;
    }
    if (trace.num_frames >= maxDepth) {
      traceStackTooLong++;
      fprintf(stderr, "trace too long: %d\n", trace.num_frames);
      return;
    }
    if (trace.num_frames <= 0) {
      traceStackASGCTError++;
      //fprintf(stderr, "trace empty or error %d\n", trace.num_frames);
      return;
    }
    if (ignoreInstrumentationForTraceStack && doesTraceHaveClassSomewhere(trace, "Ljavaassist/bytecode")) {
      return;
    }
    bool onNativeChecker = false;
    if (doesTraceHaveTopClass(trace, "Lme/bechberger/trace/NativeChecker;")) {
      discardFirstFrame(trace);
      onNativeChecker = true;
    }
    auto printTraces = [&](bool correct, const char* msg = nullptr, int frameIndex = -1) {
      if (!correct) {
        brokenTraceStacks++;
        if (frameIndex >= 0) {
          fprintf(stderr, "incorrect trace stack at frame %d: %s\n", frameIndex, msg);
        } else {
          fprintf(stderr, "incorrect trace stack: %s\n", msg);
        }
        if (doesTraceHaveBottomClass(trace, "Ljava/lang/invoke/DirectMethodHandle$Holder;") || doesTraceHaveBottomClass(trace, "Ljava/lang/invoke/LambdaForm") || doesTraceHaveClassSomewhere(trace, "Ljava/lang/invoke/MethodHandles$Lookup")) {
          traceStackBrokenMethodHandleRelated++;
        }
        if (doesTraceHaveClassSomewhere(trace, "Ljava/lang/invoke/InnerClassLambdaMetafactory") || doesTraceHaveClassSomewhere(trace, "Ljava/lang/invoke/LambdaMetafactory")) {
          trackStackLambdaMetaFactoryRelated++;
        }
        if (doesTraceHaveClassSomewhere(trace, "Lsun/instrument/InstrumentationImpl;") || doesTraceHaveClassSomewhere(trace, "Ljavaassist/bytecode")) {
          traceStackBrokenInstrumentationRelated++;
        }
        if (!onNativeChecker) {
          traceStackBrokenPushStack++;
        }
      }
      if ((correct && printEveryNthValidTrace > 0 && checkedTraceStackCount % printEveryNthValidTrace == 0) ||
          (!correct && printEveryNthBrokenTrace > 0 && brokenTraceStacks % printEveryNthBrokenTrace == 0)) {
         if (msg != nullptr) {
          fprintf(stderr, "%s\n", msg);
        }
        fprintf(stderr, "stored stack:\n");
        printTraceStack(stderr);
        fprintf(stderr, "ASGCT stack:\n");
        printASGCTTrace(stderr, trace);
      }
      if ((printStatsEveryNthTrace > 0 && checkedTraceStackCount % printStatsEveryNthTrace == 0) || (!correct && printStatsEveryNthBrokenTrace > 0 && brokenTraceStacks % printStatsEveryNthBrokenTrace == 0)) {
        printTraceStackInfo();
      }
    };

    checkedTraceStackCount++;
    // check that the length is correct
    // top + 1 is the length of the current stack
    if (trace.num_frames < top + 1) {
      traceStackTooShort++;
      printTraces(false, "trace too short");
      if (trace.num_frames == top) {
        traceStackOneFrameTooShort++;
      }
      return;
    }
    // check that the frames are correct
    // keep in mind that the bottom most stack is at trace.num_frames - 1
    int diff = trace.num_frames - 1 - top;
    for (int i = diff; i < trace.num_frames; ++i) {
      // from the top most frame to the bottom most frame
      auto sframe = trace.frames[i];
      auto cframe = frames[top - i + diff];
      if (sframe.method_id != cframe.method_id) {
        traceStackWrongFrameMethodId++;
        printTraces(false, "wrong method id", i);
        if (i == diff) {
          traceStackWrongFrameMethodIdForTopMostFrame++;
        }
        return;
      }
      if (isASGCTNativeFrame(sframe) != isASGCTNativeFrame(cframe)) {
        traceStackWrongNativeness++;
        printTraces(false, "wrong nativeness", i);
        return;
      }
      if (cframe.lineno != NO_LINENO && sframe.lineno != cframe.lineno) {
        traceStackWrongFrameLocation++;
        printTraces(false);
        return;
      }
    }
    printTraces(true);
  }
};

thread_local TraceStack traceStack;

JNIEXPORT void JNICALL Java_me_bechberger_trace_NativeChecker_pushTraceStack(JNIEnv *env, jclass) {
  traceStack.push(env);
}


JNIEXPORT void JNICALL Java_me_bechberger_trace_NativeChecker_popTraceStack(JNIEnv *, jclass) {
  traceStack.pop();
}

}

const int TRACE_STACK_HANDLER = 1;

/*
 * Idea: send signal to thread, store trace in tsTrace, set tsWritten to 1 (tsWritten = 2 if no trace stack available)-
 * Then check if the trace is correct in the sample thread. Do as little work as possible in the signal handler.
 */

std::atomic_int tsWritten; // 0 = not yet, 1 = written, 2 = error
ASGCT_CallTrace tsTrace;
ASGCT_CallFrame tsFrames[MAX_DEPTH];
TraceStack tsStack;

/** returns true if successful */
bool sendSignal(pthread_t thread, int handlerType) {
  union sigval sigval;
  sigval.sival_int = handlerType;
  return sigqueue(thread, SIGPROF, sigval) == 0;
}

void checkAsync(pthread_t thread) {
  tsWritten = 0;
  sendSignal(thread, TRACE_STACK_HANDLER);
  auto start = std::chrono::system_clock::now();
  while (tsWritten == 0 && std::chrono::system_clock::now() - start < std::chrono::milliseconds(10)) {
  }
  if (tsWritten == 1) {
    tsStack.check(tsTrace);
  }
}

void traceStackHandler(ucontext_t *ucontext) {
  if (traceStack.hasStack() && (!inInstrumentation || !ignoreInstrumentationForTraceStack)) {
    tsTrace.frames = tsFrames;
    tsTrace.env_id = env;
    asgct(&tsTrace, maxDepth, ucontext);
    tsStack = traceStack; // intentional copy, otherwise the stack might be modified while we are checking it
    tsWritten = 1;
  } else {
    tsWritten = 2;
  }
}

void signalHandler(int signum, siginfo_t* info, void* ucontext) {
  switch (info->si_code) {
    case SI_QUEUE:
      switch (info->si_value.sival_int) {
        case TRACE_STACK_HANDLER:
          traceStackHandler((ucontext_t *) ucontext);
          break;
      }
      break;
  }
}

std::vector<pthread_t> availableJavaThreads() {
  std::lock_guard<std::mutex> lock(threadsMutex);
  std::lock_guard<std::mutex> lock2(javaThreadMutex);
  std::vector<pthread_t> intersection;
  for (auto thread : threads) {
    if (javaThreads.find(thread) != javaThreads.end()) {
      intersection.push_back(thread);
    }
  }
  return intersection;
}

void sampleLoop() {
  std::random_device rd;
  std::mt19937 g(rd());
  JNIEnv* newEnv;
  jvm->AttachCurrentThreadAsDaemon((void **) &newEnv, NULL); // important, so that the thread doesn't keep the JVM alive
  std::chrono::microseconds interval{sampleIntervalInUs};
  while (!shouldStop) {
    auto start = std::chrono::system_clock::now();
    // randomly select a thread
    std::vector<pthread_t> avThreads = availableJavaThreads();
    if (avThreads.empty()) {
      std::this_thread::sleep_for(interval);
      continue;
    }
    pthread_t thread;
    std::sample(avThreads.begin(), avThreads.end(), &thread, 1, g);
    if (runTraceStackSampler) {
      checkAsync(thread);
    }
    auto duration = std::chrono::system_clock::now() - start;
    auto sleep = interval - duration;
    if (std::chrono::seconds::zero() < sleep) {
      std::this_thread::sleep_for(sleep);
    }
  }
}