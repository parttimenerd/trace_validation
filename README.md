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

License
-------
## License
MIT, Copyright 2023 SAP SE or an SAP affiliate company, Johannes Bechberger
and trace-validation contributors


*This project is a prototype of the [SapMachine](https://sapmachine.io) team
at [SAP SE](https://sap.com)*