# Find path to sink functions from name of shared variables. Different output format for the function calling certain check functions. NOT heuristic.
# @author tkmk
# @category Analysis

import time
import sys
from ghidra.util.classfinder import ClassSearcher
from ghidra.app.plugin.core.analysis import ConstantPropagationAnalyzer
from ghidra.program.util import SymbolicPropogator
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import CancelledException
from ghidra.program.model.symbol.FlowType import UNCONDITIONAL_CALL
# Added by LHY
from ghidra.util import UndefinedFunction 
from collections import Counter, defaultdict
import json

DEBUG = False

heuristicMin = 4
sinks = ['system', '___system', 'bstar_system', 'popen', 'doSystemCmd', 'doShell', 'twsystem']
digest = ['strcpy', 'sprintf', 'memcpy', 'strcat']

# zero means the first param.
shareFunctionKeyPos = {
    'nvram_safe_get': 0,
    'nvram_bufget': 1,
    'getenv': 0,
    'nvram_get': 1,
    'acosNvramConfig_get': 0,
    'bcm_nvram_get': 0,
    'envram_get_value': 0,
}
needCheckConstantStr = {
    'system': 0,
    'fwrite': 0,
    '___system': 0,
    'bstar_system': 0,
    'popen': 0,
    'execve': 0,
    'strcpy': 1,
    'memcpy': 1,
    'twsystem': 0
}
needCheckFormat = {
    'sprintf': 1,
    'doSystemCmd': 0,
    'doShell': 0,
    'do_system': 0
}

syms = {}
analyzer = None


# Added by LHY
nameToFunc = {}
def initNameToFunc():
    for funcName in shareFunctionKeyPos.keys():
        if funcName not in nameToFunc:
            func = getFunction(funcName)
            if func is None:
                for f in currentProgram.functionManager.getFunctions(True):
                    if f.name == funcName:
                        func = f
                        break
            nameToFunc[funcName] = func

def parseShareJson(paramFile):
    config_setter_sum_data = dict()
    with open(paramFile) as f:
        config_setter_sum_data = json.load(f)
    shareResult = defaultdict(set)    
    for shared_keyword in config_setter_sum_data.keys():
        config_getters = []
        for item in config_setter_sum_data[shared_keyword]:
            config_setter = item.split()[1]
            funcName = config_setter.replace('set', 'get')
            # In fact, the nvram func names doesn't have to be completely related.
            if "nvram" in funcName:
                for name, func in nameToFunc.items():
                    if "nvram" in name:
                        config_getters.append(func)
            else:
                func = nameToFunc[funcName]
                config_getters.append(func)
        for func in config_getters:
            if func is not None:
                shareResult[func].add(shared_keyword)
    return shareResult



def a2h(address):
    return '0x' + str(address)


def getAnalyzer():
    global analyzer
    for a in ClassSearcher.getInstances(ConstantPropagationAnalyzer):
        if a.canAnalyze(currentProgram):
            analyzer = a
            break
    else:
        assert 0


def getCallingArgs(addr, pos):
    if not 0 <= pos <= 3:
        return
    arch = str(currentProgram.language.processor)
    if arch == 'ARM':
        reg = currentProgram.getRegister('r%d' % pos)
    elif arch == 'MIPS':
        nextInst = getInstructionAt(addr).next
        if len(nextInst.pcode):  # not NOP
            addr = addr.add(8)
        reg = currentProgram.getRegister('a%d' % pos)
    else:
        return
    return getRegister(addr, reg)


def getRegister(addr, reg):
    if analyzer is None:
        getAnalyzer()

    func = getFunctionContaining(addr)
    if func is None:
        return

    if func in syms:
        symEval = syms[func]
    else:
        symEval = SymbolicPropogator(currentProgram)
        symEval.setParamRefCheck(True)
        symEval.setReturnRefCheck(True)
        symEval.setStoredRefCheck(True)
        analyzer.flowConstants(currentProgram, func.entryPoint, func.body, symEval, monitor)
        syms[func] = symEval

    return symEval.getRegisterValue(addr, reg)


def getStr(addr):
    ad = addr
    ret = ''
    try:
        while not ret.endswith('\0'):
            ret += chr(getByte(ad) % 256)
            ad = ad.add(1)
    except MemoryAccessException:
        return
    return ret[:-1]


def getStrArg(addr, argpos=0):
    rv = getCallingArgs(addr, argpos)
    if rv is None:
        return
    return getStr(toAddr(rv.value))


def checkConstantStr(addr, argpos=0):
    # empty string is not considered as constant, for it may be uninitialized global variable
    return bool(getStrArg(addr, argpos))


def checkSafeFormat(addr, offset=0):
    data = getStrArg(addr, offset)
    if data is None:
        return False

    fmtIndex = offset
    for i in range(len(data) - 1):
        if data[i] == '%' and data[i + 1] != '%':
            fmtIndex += 1
            if data[i + 1] == 's':
                if fmtIndex > 3:
                    return False
                if not checkConstantStr(addr, fmtIndex):
                    return False
    return True


def getCallee(inst):
    callee = None
    if len(inst.pcode):
        if inst.pcode[-1].mnemonic == 'CALL':
            callee = getFunctionAt(inst.getOpObjects(0)[0])
        elif inst.pcode[-1].mnemonic == 'CALLIND':
            regValue = getRegister(inst.address, inst.getOpObjects(0)[0])
            if regValue is not None:
                callee = getFunctionAt(toAddr(regValue.value))
    return callee


callMap = {}
safeFuncs = set()
referenced = set()

pathNumCounter = defaultdict(lambda: 0)
def findSinkPath(refaddr, stringval, stringaddr, shareFunc):
    pending = []

    def search(func, start=None):
        if func in callMap:
            return
        callMap[func] = {}

        start = start or func.entryPoint
        end = func.body.maxAddress

        inst = getInstructionAt(start)
        while inst is not None and inst.address < end:
            callee = getCallee(inst)
            if callee is not None:
                callMap[func][inst.address] = callee
                if callee not in callMap:
                    pending.append(callee)
            inst = inst.next

    def printpath(path):
        # Added by LHY
        if pathNumCounter[a2h(refaddr)] > 500:
            print "Too many paths from this paramRefAddr!"
            return
        else:
            pathNumCounter[a2h(refaddr)] += 1
        print >>f, '[Key "%s"(%s), %s at %s : %s]' % (stringval, a2h(stringaddr), shareFunc, startFunc, a2h(refaddr)),
        for i in range(len(path)):
            addr, callee = path[i][:2]
            if i == len(path) - 1:
                print >>f, '>>', a2h(addr), '->', callee,
            else:
                calleeCallDigestFunc = path[i + 1][-1]
                if calleeCallDigestFunc:
                    print >>f, '>>', a2h(addr), '>>', callee,
                else:
                    print >>f, '>>', a2h(addr), '->', callee,

        print >>f

    def dfs(func, path, start=None):
        '''path: list of (addr of call, callee, callDigestFunc)'''
        if func.name in sinks and len(path):
            if func.name in needCheckConstantStr and checkConstantStr(path[-1][0], needCheckConstantStr[func.name]):
                return False
            if func.name in needCheckFormat and checkSafeFormat(path[-1][0], needCheckFormat[func.name]):
                return False
            printpath(path)
            return True
        callDigestFunc = False
        vulnerable = False
        for addr, callee in sorted(callMap[func].items()):
            if start is not None and addr < start:
                continue
            if not callDigestFunc and callee.name in digest:
                if callee.name in needCheckConstantStr and checkConstantStr(addr, needCheckConstantStr[callee.name]):
                    pass
                elif callee.name in needCheckFormat and checkSafeFormat(addr, needCheckFormat[callee.name]):
                    pass
                else:
                    callDigestFunc = True
            if callee in [x[1] for x in path] + [startFunc] or callee in safeFuncs:
                continue
            vulnerable = dfs(callee, path + [(addr, callee, callDigestFunc)]) or vulnerable
        if not vulnerable and func != startFunc:
            safeFuncs.add(func)
        return vulnerable

    startFunc = getFunctionContaining(refaddr)
    assert startFunc is not None

    pending.append(startFunc)
    while len(pending):
        search(pending.pop())

    vulnerable = dfs(startFunc, [], refaddr)
    return vulnerable


def getFunctionContainingPlus(addr):
    func = getFunctionContaining(addr)
    if func is not None:
        return func
    undefinedFunc = UndefinedFunction.findFunction(currentProgram, addr, ConsoleTaskMonitor())
    if undefinedFunc is not None:
        # eg. UndefinedFunction_0008dd10 -> FUN_0008dd10
        entryPoint = undefinedFunc.getEntryPoint()
        oldName = undefinedFunc.getName()
        newName = oldName.replace("UndefinedFunction", "FUN")
        func = createFunction(entryPoint, newName)
        return func
    return None

referencedKeywordNotToSink = []
def searchShareFunc(parsedResult):
    # parsedResult: config_getter function -> set of keywords
    for func, keywordSet in parsedResult.items():
        for ref in getReferencesTo(func.entryPoint):
            if ref.referenceType != UNCONDITIONAL_CALL:
                continue
            if not getFunctionContainingPlus(ref.fromAddress): 
                continue
            paramPos = shareFunctionKeyPos[func.name]
            regValue = getCallingArgs(ref.fromAddress, paramPos)
            if not regValue:
                continue
            strAddr = toAddr(regValue.value)
            keyword = getStrArg(ref.fromAddress, paramPos)
            if keyword and keyword in keywordSet:
                print("Search Func:{0} and Keyword:{1}.".format(func.name, keyword))
                vulnerable = findSinkPath(ref.fromAddress, keyword, strAddr, func)
                if not vulnerable:
                    referencedKeywordNotToSink.append(keyword + ' @ ' + a2h(ref.fromAddress))


if __name__ == '__main__':
    t = time.time()
    args = getScriptArgs()
    f = None
    if len(args) > 1:
        f = open(args[1], 'w')
    else:
        print "No output file!";exit(0)

    initNameToFunc()

    shareResult = parseShareJson(args[0])
    # shareResult: config_getter function -> set of keywords
    
    print >>f, 'binary base:', a2h(currentProgram.imageBase)
    searchShareFunc(shareResult)

    t = time.time() - t
    print 'Time Elapsed:', t
        
    # print >>f, "Referenced Keywords But Not To Sink:"
    # referencedKeywordNotToSink.sort()
    # for s in referencedKeywordNotToSink:
    #     print >>f, "\t" + s
    # print >>f, 'Time Elapsed:', t
    # f.close()
