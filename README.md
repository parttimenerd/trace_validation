trace-validation
================

Agent which instruments byte-code to validate that AsyncGetCallTrace returns correct stack traces when called at
a safe-point (directly in a native method).

Correct in this case means that the stack trace returned is the same the one return by GetStackTrace

This code uses javaassist to instrument all possible methods.

Goal
----
Try to check that ASGCT returns "correct" stack traces.

Argent Arguments
----------------
- `collectStack=<true|false> (default: false)`
  - partially collect the current stack trace by byte-code instrumentation
  - the checker currently does not use the collected stack trace
- `cnmProb=<float> (default: 1.0)`
  - probability of inserting a call to the check method at the beginning of a given method
  - lower values reduce the overhead by not instrumenting all methods

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
([source](https://github.com/openjdk/jdk/blob/db483a38a815f85bd9668749674b5f0f6e4b27b4/src/hotspot/cpu/x86/frame_x86.cpp#L98)),
use the following command with a `db483a38a815f85bd9668` build of OpenJDK (errors with other revisions might differ):

```sh

```sh
# download the renaissance benchmark suite
test -e renaissance.jar || wget https://github.com/renaissance-benchmarks/renaissance/releases/download/v0.14.2/renaissance-gpl-0.14.2.jar -O renaissance.jar
# run the dotty benchmark with the agent, but only consider the top 4 frames
java -Djdk.attach.allowAttachSelf=true -javaagent:target/trace-validation.jar=maxDepth=4 -jar renaissance.jar dotty
```


License
-------
MIT, Copyright 2023 SAP SE or an SAP affiliate company, Johannes Bechberger
and trace-validation contributors


*This project is a prototype of the [SapMachine](https://sapmachine.io) team
at [SAP SE](https://sap.com)*