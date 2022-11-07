#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <string>

using namespace std;
using namespace llvm;

namespace {
struct MyPass : FunctionPass {
  static char ID;
  MyPass() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override {
    auto &Context = F.getContext();
    auto Module = F.getParent();
    FunctionType *PrintfType = FunctionType::get(
        Type::getInt32Ty(Context), {Type::getInt8PtrTy(Context)}, true);
    FunctionCallee PrintF = Module->getOrInsertFunction("printf", PrintfType);

    string FunctionName = F.getName().str();
    string functionCountName = FunctionName + "__count";
    GlobalVariable *functionCallCount =
        Module->getGlobalVariable(functionCountName);
    if (!functionCallCount) {
      functionCallCount = new GlobalVariable(
          *Module, Type::getInt32Ty(Context), false, GlobalValue::CommonLinkage,
          ConstantInt::get(Type::getInt32Ty(Context), 0), functionCountName);
    }
    Instruction *firstInstruction = &F.front().front();

    IRBuilder<> builder(firstInstruction);
    Value *loadedCallCount =
        builder.CreateLoad(Type::getInt32Ty(Context), functionCallCount);
    Value *addedCallCount =
        builder.CreateAdd(loadedCallCount, builder.getInt32(1));
    builder.CreateStore(addedCallCount, functionCallCount);

    string printLog = FunctionName + " %d\n";
    Value *functionPtr = builder.CreateGlobalString(printLog);
    builder.CreateCall(PrintF, {functionPtr, addedCallCount});
    return true;
  }
};

} // namespace

char MyPass::ID = 0;
static RegisterPass<MyPass> X("mypass", "my test function passf", false, false);

static llvm::RegisterStandardPasses
    Y(llvm::PassManagerBuilder::EP_EarlyAsPossible,
      [](const llvm::PassManagerBuilder &Builder,
         llvm::legacy::PassManagerBase &PM) { PM.add(new MyPass()); });
