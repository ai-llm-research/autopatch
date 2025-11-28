import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking


/**
 * Recursively reconstructs a full access string for complex expressions, including:
 * - Dot field access (obj.field)
 * - Pointer field access (ptr->field)
 * - Array access (arr[i])
 * - Simple variable access
 */
string getFullAccessString_r(Expr e) {
  // Simple variable or other expressions
  not e instanceof FieldAccess and
  not e instanceof ArrayExpr and
  not e instanceof AddressOfExpr and
  not e instanceof FunctionCall and
  not e instanceof PointerDereferenceExpr and
  result = e.toString()

  or

  e instanceof FunctionCall and
  exists(FunctionCall fc | fc = e |
    result = fc.getTarget().getQualifiedName()
  )

  or

  // DotFieldAccess: obj.field
  e instanceof DotFieldAccess and
  exists(DotFieldAccess dfa | dfa = e |
    result = getFullAccessString_r(dfa.getQualifier()) + "." + dfa.getTarget().getName()
  )

  or

  // PointerFieldAccess: ptr->field
  e instanceof PointerFieldAccess and
  exists(PointerFieldAccess pfa | pfa = e |
    result = getFullAccessString_r(pfa.getQualifier()) + "->" + pfa.getTarget().getName()
  )

  or

  // ArrayExpr: arr[i]
  e instanceof ArrayExpr and
  exists(ArrayExpr ae | ae = e |
    result = getFullAccessString_r(ae.getArrayBase()) + "[" + ae.getArrayOffset().toString() + "]"
  )
  
  or
    // ArrayExpr: arr[i]
  e instanceof AddressOfExpr and
  exists(AddressOfExpr ae | ae = e |
    result = "&" + getFullAccessString_r(ae.getOperand())
  )

  or
    // ArrayExpr: arr[i]
  e instanceof PointerDereferenceExpr and
  exists(PointerDereferenceExpr pde | pde = e |
    result = "*" + getFullAccessString_r(pde.getOperand())
  )
}

string getFullAccessString(Expr e) {
  // Handle anonymous struct
  result = getFullAccessString_r(e).replaceAll("->(unknown field).", "->")
                                  .replaceAll("->(unknown field)->", "->")
                                  .replaceAll(".(unknown field).", ".")
                                  .replaceAll(".(unknown field)->", ".")
                                  .replaceAll("->(unknown field)", "")
                                  .replaceAll(".(unknown field)", "")
                                  .regexpReplaceAll("^[*&0-9]+", "")
}


string getFullAccessStringNode(DataFlow::Node nd) {

  exists( Expr e | e = nd.asExpr() | result = getFullAccessString(nd.asExpr()))

  or
  
  if nd.toString().matches("%") then
    exists( Expr e | e.toString() = nd.toString() | result = getFullAccessString(e))
  else
    result = nd.toString()
}


string getCleanFullAccessString(Expr e) {
  // Handle anonymous struct
  result = getFullAccessString(e).regexpReplaceAll("^(?:[*&.0-9]|->)+", "")
}


string getCleanFullAccessStringNode(DataFlow::Node nd) {

  exists( Expr e | e = nd.asExpr() | result = getCleanFullAccessString(nd.asExpr()))

  or
  
  if nd.toString().matches("%") then
    exists( Expr e | e.toString() = nd.toString() | result = getCleanFullAccessString(e))
  else
    result = nd.toString()
}

module MyFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    any() // asExpr changes all the time! check later
  }

  predicate isSink(DataFlow::Node sink) {
    any()
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(FunctionCall call, int i |
      nodeFrom.asExpr() = call.getArgument(i) and 
      nodeTo.toString() = call.toString()
    )
  }

}

module MyFlow = TaintTracking::Global<MyFlowConfiguration>;
import MyFlow::PathGraph

from MyFlow::PathNode source, MyFlow::PathNode sink , string sourceString, string sinkString
where 
source.getNode().getFunction().getQualifiedName() = "<TARGET_FUNCTION_NAME>" and
sink.getNode().getFunction().getQualifiedName() = "<TARGET_FUNCTION_NAME>" and
getCleanFullAccessStringNode(source.getNode()) = sourceString and
getCleanFullAccessStringNode(sink.getNode()) = sinkString and
sourceString != sinkString and
sourceString in <VARIABLES_AND_FUNCTIONS_LIST> and
sinkString in <VARIABLES_AND_FUNCTIONS_LIST> and
MyFlow::flowPath(source, sink)
select sourceString, sinkString


//https://github.blog/security/vulnerability-research/codeql-zero-to-hero-part-3-security-research-with-codeql/
//https://medium.com/csg-govtech/hunting-bugs-in-accel-ppp-with-codeql-8370e297e18f
//https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-cpp/
// https://github.blog/changelog/2023-08-14-new-dataflow-api-for-writing-custom-codeql-queries/
// https://geun-yeong.tistory.com/42
// https://github.blog/security/vulnerability-research/codeql-zero-to-hero-part-3-security-research-with-codeql/