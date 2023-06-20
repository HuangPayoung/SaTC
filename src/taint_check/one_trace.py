from bug_finder.taint import main, setSinkTarget
from bug_finder.sinks import getfindflag, setfindflag
from taint_analysis.coretaint import setfollowTarget
import sys
import angr
import random, string
import pickle
import os
from bug_finder.config import checkcommandinjection, checkbufferoverflow

def taint_stain_analysis(binary, ghidra_analysis_result, i):
    with open(ghidra_analysis_result, 'r') as f:
        cont = f.read().split('\n')
    proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=True)
    cfg = proj.analyses.CFG()
    try:
        if cont[i * 3 + 1] != '':
            func_addr = [int(j, 0) for j in cont[i * 3 + 1].split(' ')]
        else:
            func_addr = []
        taint_addr = int(cont[i * 3].split(' ')[0], 0)
        sinkTargets = [int(j, 0) for j in cont[i * 3 + 2].split(' ')]
        # put it to the head of cfg node
        if proj.arch.name != "MIPS32":
            if not proj.loader.main_object.pic:
                start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).addr
                callerbb = None
            else:
                func_addr = [j - 0x10000 + 0x400000 for j in func_addr]
                taint_addr = taint_addr - 0x10000 + 0x400000
                sinkTargets = [j - 0x10000 + 0x400000 for j in sinkTargets]
                start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                anyaddr=True).addr
                callerbb = None
        else:
            if not proj.loader.main_object.pic or "system.so" in proj.filename:
                # print hex(int(cont[i * 3].split(' ')[1], 0))
                # print cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True)
                start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).function_address
                callerbb = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).addr
                with open(binary, 'rb') as f:
                    conttmp = f.read()
                    sec = proj.loader.main_object.sections_map['.got']
                    proj.loader.memory.write_bytes(sec.min_addr, conttmp[sec.offset: sec.offset + sec.memsize])
            else:
                func_addr = [j - 0x10000 + 0x400000 for j in func_addr]
                taint_addr = taint_addr - 0x10000 + 0x400000
                sinkTargets = [j - 0x10000 + 0x400000 for j in sinkTargets]
                start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                anyaddr=True).function_address
                callerbb = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                            anyaddr=True).addr
                with open(binary, 'rb') as f:
                    conttmp = f.read()
                    sec = proj.loader.main_object.sections_map['.got']
                    proj.loader.memory.write_bytes(sec.min_addr, conttmp[sec.offset: sec.offset + sec.memsize])

        sinkTargets = [cfg.get_any_node(j, anyaddr=True).addr for j in sinkTargets]
        # for j in func_addr:
        #     print j
        #     print cfg.get_any_node(j, anyaddr=True).addr
        followtar = [cfg.get_any_node(j, anyaddr=True).addr for j in func_addr]

        setfindflag(False)
        setSinkTarget(sinkTargets)
        setfollowTarget(followtar)

        print "Analyzing %s from 0x%X, taint 0x%X, sinkTarget%s, functrace %s" % (
            binary, start_addr, taint_addr, str([hex(j) for j in sinkTargets]), str([hex(j) for j in followtar]))
        if not callerbb:
            main(start_addr, taint_addr, binary, proj, cfg)
        else:
            main(start_addr, taint_addr, binary, proj, cfg, callerbb)

        if getfindflag()[0]:
            res = "0x%x 0x%x " % (taint_addr, start_addr) + "  found : %s" % " ".join(
                [hex(i) for i in set(getfindflag()[1])])
        else:
            res = "0x%x 0x%x " % (taint_addr, start_addr) + "  not found"
        print res + '\n'
    except Exception as e:
        print e


if __name__ == '__main__':
    global checkcommandinjection, checkbufferoverflow
    binary = ''
    ghidra_output_path = ''
    idx = 0
    checkcommandinjection = True
    # checkcommandinjection = False
    # checkbufferoverflow = True
    checkbufferoverflow = False
    taint_stain_analysis(binary, ghidra_output_path, idx)


