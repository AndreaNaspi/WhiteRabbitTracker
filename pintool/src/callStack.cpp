#include "CallStack.h"

// callStackPush version where alignement is performed. Before pushing the new frame, esp address is checked to see if stale frames are present in the shadow stack.
void callStackPush(callStackThreadP shadowStackThread, ADDRINT calladdr, ADDRINT retaddr, ADDRINT currentSP) {
	// This step is performed to avoid tail calls
	// If esp == top.esp
	if (currentSP == (*(shadowStackThread->callStack))[shadowStackThread->callStackTop - 1].spaddr) { return; }
	// At first, alignment is performed to clean stack from stale frames
	// While there is at least one frame in callStack
	while (shadowStackThread->callStackTop > 0 && //AND
		// SP of actual calling/returning function >= SP on top of the stack ==> align stack
		currentSP >= (*(shadowStackThread->callStack))[shadowStackThread->callStackTop - 1].spaddr) {
		shadowStackThread->callStack->pop_back(); 
		shadowStackThread->callStackTop--; // Decrease top position in stack
	}

	callStackFrameP temp = new callStackFrame;
	temp->calladdr = calladdr;
	temp->retaddr = retaddr;
	temp->spaddr = currentSP;
	// To avoid if/else case when stack empty
	if (shadowStackThread->callStackTop > 0) {
		temp->hashID = temp->retaddr ^ (*(shadowStackThread->callStack))[shadowStackThread->callStackTop - 1].hashID;
		shadowStackThread->callStack->push_back(*temp);
		shadowStackThread->callStackTop++;
		return;
	}
	temp->hashID = temp->retaddr;
	shadowStackThread->callStack->push_back(*temp);
	shadowStackThread->callStackTop++;
}

void callStackPop(callStackThreadP shadowStackThread, ADDRINT retaddr, ADDRINT currentSP) {
	callStackThreadP shadowStackThreadTmp = shadowStackThread;
	// Shadow stack is empty
	if (!shadowStackThreadTmp->callStackTop) { return; }

	int idx = shadowStackThreadTmp->callStackTop - 1;
	callStackFrame csf = (*(shadowStackThreadTmp->callStack))[idx];
	while (true) {
		// Entry found
		if (csf.retaddr == retaddr) 
			break;
		// Stack finished
		if (--idx < 0) 
			break;
		callStackFrame csf = (*(shadowStackThreadTmp->callStack))[idx];
	}
	if (idx == -1)  
		return; 
	// Flushing (shadowStackThreadTmp->callStackTop - idx) entries
	if (currentSP == csf.spaddr) {
		shadowStackThreadTmp->callStack->resize(idx);
		shadowStackThreadTmp->callStackTop = idx;
	}
}

// Popping nodes from stack till retaddr is hit: pop till SP is aligned with callStack frames -	implementation which pops from the end of the vector
void callStackPop(callStackThreadP shadowStackThread, ADDRINT retaddr) {
	int pop_counter = 0;
	callStackThreadP shadowStackThreadTmp = shadowStackThread;
	// Same as shadowStackThreadTmp->size() > 0
	while (shadowStackThreadTmp->callStackTop > 0) {
		// If top frame in the stack is not the returning function, delete it
		if ((*(shadowStackThreadTmp)->callStack)[shadowStackThreadTmp->callStackTop - 1].retaddr != retaddr) {
			shadowStackThreadTmp->callStack->pop_back(); //Pop
			shadowStackThreadTmp->callStackTop--; //Decrease position callStack top frame
		}
		// Else top frame in the stack is the returning function, delete it and stop popping
		else {
			shadowStackThreadTmp->callStack->pop_back();
			shadowStackThreadTmp->callStackTop--;	
			return;
		}
	}
}

// Used when callStack is not aligned - implementation with pop_back() 
void alignCallStack(callStackThreadP shadowStackThread, ADDRINT currentSP, std::string fromWhere) {

	// While there is at least one frame in callStack
	while (shadowStackThread->callStackTop > 0 && //AND
		// SP of actual calling/returning function >= SP on top of the stack ==> align stack
		currentSP >= (*(shadowStackThread->callStack))[shadowStackThread->callStackTop - 1].spaddr) {
		shadowStackThread->callStack->pop_back(); 
		shadowStackThread->callStackTop--; // Decrease top position in stack
	}
}