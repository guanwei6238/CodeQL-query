/**
 * @name Uncontrolled data used in path expression (including parameters)
 * @description Treats method/function parameters as taint sources in addition to the standard threat model sources.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id java/path-injection-params
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.TaintedPathQuery

module ParamAsSourceConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // keep the standard sources (remote user input etc.)
    TaintedPathConfig::isSource(source)
    or
    // additionally treat any formal parameter as a source
    exists(Parameter p |
      source = DataFlow::parameterNode(p)
    )
  }

  predicate isSink(DataFlow::Node sink) { TaintedPathConfig::isSink(sink) }

  predicate isBarrier(DataFlow::Node node) { TaintedPathConfig::isBarrier(node) }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    TaintedPathConfig::isAdditionalFlowStep(n1, n2)
  }
}

module ParamAsSourceFlow = TaintTracking::Global<ParamAsSourceConfig>;
import ParamAsSourceFlow::PathGraph

from ParamAsSourceFlow::PathNode source, ParamAsSourceFlow::PathNode sink
where ParamAsSourceFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This path depends on a $@.", source.getNode(),
  "user-provided value (incl. parameters)"
