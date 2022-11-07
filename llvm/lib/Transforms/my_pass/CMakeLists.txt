add_llvm_library(LLVMTestPass MODULE
        pass.cpp

        PLUGIN_TOOL
        opt
        )

