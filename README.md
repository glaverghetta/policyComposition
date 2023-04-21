# Gray Policy Specification
This project is a fork of the PoCo policy specification language. You can find the original PoCo project here: https://github.com/caoyan66/PoCo-PolicyComposition

This project adds support for gray policies (https://cse.usf.edu/~ligatti/papers/gray.pdf) to PoCo. The README file for the original PoCo project explains in detail how to compile and run PoCo. This README file lists the changes made to PoCo and gives some additional compilation instructions. Additional information about this project may be found in "Gray Policy Specification.pdf".

PoCo has been run successfully using Java version 1.8. Use Eclipse 2018 64 bit version.

You will need to use a custom run configuration in Eclipse to run PoCo. In the folder pic/runConfig there are several screenshots showing the configuration to use.

The following is a list of changes made to PoCo for this project.

-  Added class GrayPolicy to package edu.cseusf.poco.policy
-  Added class SpamPolicy to package edu.cseusf.poco.poco_demo.polymerPolicies
-  In class PolicyVisitor, in package edu.cseusf.poco.policy.staticAnalysis, changed line 47 to: `if (subClassName.equals("Policy") || subClassName.equals("GrayPolicy")) {`
-  In class PolicyVisitor, in package edu.cseusf.poco.policy.staticAnalysis.visitClasses, changed line 33 to: if(superName.equals("edu/cseusf/poco/policy/Policy") || superName.equals("edu/cseusf/poco/policy/GrayPolicy")) {
-  In class PolicyScanner, in package, edu.cseusf.poco.policy.staticAnalysis.scanPolicies, changed line 76 to: if ((subClassName.equals("Policy") || subClassName.equals("GrayPolicy")) && _declaredPolicies.contains(_className)) {
