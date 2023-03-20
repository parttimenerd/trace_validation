trace-validation
================

Agent which instruments byte-code to validate that AsyncGetCallTrace returns correct stack traces when called at
a safe-point (directly in a native method).

Correct in this case means that the stack trace returned is the same the one return by GetStackTrace

Currently only tested on Linux.

To learn more on this topic, read my accompanying blog post: [Validating Java Profiling APIs](https://mostlynerdless.de/blog/2023/03/14/validating-java-profiling-apis/)

Goal
----
Try to check that ASGCT returns "correct" stack traces.

Argent Arguments
----------------
- `cnmProb=<float> (default: 1.0)`
  - probability of inserting a call to the check method at the beginning of a given method
  - lower values reduce the overhead by not instrumenting all methods
- `printAllTraces=<true|false> (default: false)`
  - print all traces, not just the ones that are invalid
- `maxDepth=<int> (default: 1024)`
  - maximum depth of the stack trace to check
  - this is useful to reduce the overhead of the agent
- `printEveryNthBrokenTrace=<int> (default: 1)`
- `printEveryNthValidTrace=<int> (default: -1)`
- `printStatsEveryNthTrace=<int> (default: -1)`
- `printStatsEveryNthBrokenTrace=<int> (default: -1)`
- `checkEveryNthStackFully=<int> (default: 1)`
  - check every nth stack (1 == all) against the stack collected via instrumentation
    if GST and ASGCT match
- `traceCollectionProbability=<float> (default: 0)`
  - probability of adding a call to the trace collection method at every method (0 == no checks)
- `sampleInterval=<int> (default: -1)`
  - interval of the trace collection async checker in us
- `traceIgnoreInstrumentation=<true|false> (default: false)`
    - ignore the instrumentation related code in the trace collection async checker
- `asgctGSTSamplingCheck=<true|false> (default: false)`
    - check ASGCT and GST in the signal handler in the sampler
- `asgctGSTSamplingIgnoreTopNFrames=<int> (default: 5)`
    - ignore the top n frames in the ASGCT and GST check in the signal handler in the sampler

Usage
-----
```sh
mvn package
java -Djdk.attach.allowAttachSelf=true -javaagent:target/trace-validation.jar ... <your application>
```

On segfault, you might want to use the `printAllTraces=<true|false> (default: false)` option to print all stack traces.
Use the `maxDepth` option to limit the depth of the stack traces.

The code calls ASGCT a second time on error and sets the `ASGCT_LOG` environment variable to `1` to enable you to
check for this in a modified JDK and log information.

Examples
--------

To reproduce a bug related to a `_cb->is_runtime_stub()` check in `frame::safe_for_sender` on linux x86_64
([source](https://github.com/openjdk/jdk/blob/db483a38a815f85bd9668749674b5f0f6e4b27b4/src/hotspot/cpu/x86/frame_x86.cpp#L98),
[JBS](https://bugs.openjdk.org/browse/JDK-8303444)),
use the following command with a `db483a38a815f85bd9668` build of OpenJDK (errors with other revisions might differ):

```sh

```sh
# download the renaissance benchmark suite
test -e renaissance.jar || wget https://github.com/renaissance-benchmarks/renaissance/releases/download/v0.14.2/renaissance-gpl-0.14.2.jar -O renaissance.jar
# run the dotty benchmark with the agent, but only consider the top 100 frames
java -Djdk.attach.allowAttachSelf=true -javaagent:target/trace-validation.jar=maxDepth=5 -jar renaissance.jar dotty
```

Another example is to check how many stack traces are broken approximately: You can use the `printStatsEveryNthTrace`
option in combination with `cnmProb=0.01` to only look into every 100th method:

```sh
test -e renaissance.jar || wget https://github.com/renaissance-benchmarks/renaissance/releases/download/v0.14.2/renaissance-gpl-0.14.2.jar -O renaissance.jar

java -Djdk.attach.allowAttachSelf=true -javaagent:target/trace-validation.jar=maxDepth=1024,printEveryNthBrokenTrace=1,printStatsEveryNthTrace=1000000,cnmProb=0.01 -jar renaissance.jar dotty
```

To compare the stacks to the information from the instrumentation, you can use the `checkEveryNthStackFully` option:

```sh
java -Djdk.attach.allowAttachSelf=true -javaagent:target/trace-validation.jar=maxDepth=1024,printEveryNthBrokenTrace=0,checkEveryNthStackFully=1 -jar renaissance.jar
```

To check the stack at non safepoints, use `sampleInterval` and `traceCollectionProbability`:

```sh
java -Djdk.attach.allowAttachSelf=true -javaagent:target/trace-validation.jar=maxDepth=1024,cnmProb=0,sampleInterval=1,traceCollectionProbability=1,printStatsEveryNthTrace=10000,printEveryNthBrokenTrace=1,printStatsEveryNthBrokenTrace=1 -jar renaissance.jar dotty
```

You might need to kill it via `kill -9` because it might freeze.

To check the stack non safepoints without instrumentation use (many of the options turn off the other features):

```sh
java -Djdk.attach.allowAttachSelf=true -javaagent:ap-loader.jar=start,event=cpu,file=profile.html -javaagent:target/trace-validation.jar=maxDepth=1024,cnmProb=0,sampleInterval=1,traceCollectionProbability=0,printStatsEveryNthTrace=10000,printEveryNthBrokenTrace=1,printStatsEveryNthBrokenTrace=1,checkEveryNthStackFully=0,asgctGSTSamplingCheck=true -jar renaissance.jar dotty
```

Developer notes
---------------

### Structure

It consists of two agents and a runtime library:

- transformer
  - the agent which instruments the byte-code
  - attaches the checker agent
  - puts the trace validation runtime onto the boot classpath
- checker agent
  - we need this native agent because using ASGCT is only really possible with such an agent
  - ... consider all the initialization code
- runtime
  - this has to be on the boot classpath
  - and therefore has to be a separate jar
  - it contains the Java part of the native checker and the native agent

### Checks

The following checks are performed (depending on the settings):
- Comparing ASGCT with GCT in a (safepoint safe) native method
- Comparing ASGCT with the stacks collected by the instrumentation
- Comparing ASGCT in the signal handler with the ASGCT collected on entries of instrumented methods
- Comparing ASGCT in the signal handler with GST called between two ASGCT calls
  - safer than the previous, with less precision but also less overhead and without instrumentation

### VSCode

To get proper editor support for the C++ code, use VSCode with the clangd extension and
run `bear -- mvn package` to generate a `compile_commands.json` file.

License
-------
MIT, Copyright 2023 SAP SE or an SAP affiliate company, Johannes Bechberger
and trace-validation contributors


*This project is a tool of the [SapMachine](https://sapmachine.io) team
at [SAP SE](https://sap.com)*