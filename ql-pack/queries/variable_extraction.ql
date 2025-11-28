import cpp

predicate isTargetFunction(Function f) {
  f.getQualifiedName() = "<TARGET_FUNCTION_NAME>"
}

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

string getCleanFullAccessString(Expr e) {
  // Handle anonymous struct
  result = getFullAccessString(e).regexpReplaceAll("^(?:[*&.0-9]|->)+", "")
}


from Expr access, Function f
where
  isTargetFunction(f) and
  access.getEnclosingFunction() = f and
  (
    access instanceof FieldAccess or
    access instanceof VariableAccess
  )
select getCleanFullAccessString(access)
