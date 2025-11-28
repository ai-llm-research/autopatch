import cpp


from Function func, FunctionCall call, string funcName, string funcFullName, string callFuncFullName
where funcName = func.getName() and
      funcFullName = func.getQualifiedName() and
      (
            (funcName = "<TARGET_FUNCTION_NAME>" or funcFullName = "<TARGET_FUNCTION_NAME>") and
            call.getEnclosingFunction() = func and
            callFuncFullName = call.getTarget().getQualifiedName() and
            not callFuncFullName.matches("%operator[]%") and // Remove all not-very interesting functions
            not callFuncFullName.matches("%operator->%") and
            not callFuncFullName.matches("%operator*%") and
            not callFuncFullName.matches("%operator!=%") and
            not callFuncFullName.matches("%operator=%") and
            not callFuncFullName.matches("%operator==%") and
            not callFuncFullName.matches("%operator++%") and
            not callFuncFullName.matches("%operator+%") and
            not callFuncFullName.matches("%operator-%") and
            not callFuncFullName.matches("%operator>>%") and
            not callFuncFullName.matches("%operator<<%") and
            not callFuncFullName.matches("%operator()%") and
            not callFuncFullName.matches("%operator %") and
            not callFuncFullName.matches("%operator delete%") and
            not callFuncFullName.matches("%operator new%") and
            not callFuncFullName.matches("__gnu_cxx::%") //and
            // not callFuncFullName.matches("%::begin%") and
            // not callFuncFullName.matches("%::end%") and
            // not callFuncFullName.matches("std::%")
      )
select callFuncFullName