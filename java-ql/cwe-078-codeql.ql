/**
 * @name Uncontrolled command line (including parameters)
 * @description Treats method/function parameters as taint sources in addition to the standard threat model sources.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id java/command-line-injection-params
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.CommandLineQuery

module ParamAsSourceCmdConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // keep the standard sources (remote/local user input etc.)
    InputToArgumentToExecFlowConfig::isSource(source)
    or
    // additionally treat any formal parameter as a source
    exists(Parameter p | source = DataFlow::parameterNode(p))
  }

  predicate isSink(DataFlow::Node sink) { InputToArgumentToExecFlowConfig::isSink(sink) }

  predicate isBarrier(DataFlow::Node node) { InputToArgumentToExecFlowConfig::isBarrier(node) }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    InputToArgumentToExecFlowConfig::isAdditionalFlowStep(n1, n2)
  }
}

module ParamAsSourceCmdFlow = TaintTracking::Global<ParamAsSourceCmdConfig>;

import ParamAsSourceCmdFlow::PathGraph

from ParamAsSourceCmdFlow::PathNode source, ParamAsSourceCmdFlow::PathNode sink
where ParamAsSourceCmdFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This command line depends on a $@.", source.getNode(),
  "user-provided value (incl. parameters)"
