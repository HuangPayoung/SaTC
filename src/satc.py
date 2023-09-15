#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/8/21 上午11:29
# @Author  : TT
# @File    : satc.py

from front_analysise.untils.logger.logger import get_logger
from front_analysise.modules.analysise import FrontAnalysise, BackAnalysise
from front_analysise.untils.config import ANALYSIZER, B_FILTERS, F_FILTERS, API_SPLIT_MARCH, FROM_BIN_ADD, \
    UPNP_ANALYSISE
from front_analysise.untils.output import Output
from front_analysise.untils.tools import runtimer
from front_analysise.tools.upnpanalysise import UpnpAnalysise
from config import GHIDRA_SCRIPT, HEADLESS_GHIDRA

import datetime
import subprocess
import shutil
import argparse
import uuid
import os
import json
import sys

sys.setrecursionlimit(5000)

front_result_output = ""
ghidra_result_output = ""

# Init log
log = get_logger()

scripts = {
    "ref2share": os.path.join(GHIDRA_SCRIPT, "ref2share.py"),
    "ref2sink_bof": os.path.join(GHIDRA_SCRIPT, "ref2sink_bof.py"),
    "ref2sink_cmdi": os.path.join(GHIDRA_SCRIPT, "ref2sink_cmdi.py"),
    "share2sink": os.path.join(GHIDRA_SCRIPT, "share2sink.py"),
    "call2sink": os.path.join(GHIDRA_SCRIPT, "call2sink.py")
}


def argsparse():
    # Parse command line parameters
    parser = argparse.ArgumentParser(description="SATC tool",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-d", "--directory", required=True, metavar="/root/path/_ac18.extracted",
                        help="Directory of the file system after firmware decompression")

    # 添加默认输出路径，后续设置docker映射后设置
    parser.add_argument("-o", "--output", required=True, metavar="/root/output",
                        help="Folder for output results ")
    # execute ghidra ： command
    parser.add_argument("--ghidra_script", required=False,
                        choices=["ref2sink_cmdi", "ref2sink_bof", "share2sink", "ref2share", "call2sink", "all"],
                        action="append",
                        help="ghidra script to run"
                        )
    parser.add_argument("--ref2share_result", required=False, metavar="/root/path/ref2share_result",
                        help="This input is this parameter is the result of ref2share")

    parser.add_argument("--save_ghidra_project", required=False, action="store_true",
                        help="whether to save the ghidra project")
    
    parser.add_argument("--skip_keyword_extract", required=False, action="store_true",
                        help="If this is enabled, SaTC will try to search previous keyword results.")

    # 是否启用污点分析，默认不启用
    parser.add_argument("--taint_check", required=False, action="store_true", default=False,
                        help="Enable taint analysis")

    # 添加指定前几个为边界程序，与 --bin互斥

    # Other command
    # 添加指定边界程序的方法
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-b", "--bin", required=False, action="append", metavar="/var/ac18/bin/httpd",
                       help="Input border bin")
    group.add_argument("-l", "--len", required=False, default=3, type=int, metavar="3", help="Take the first few")

    args = parser.parse_args()

    # Init output dir
    global ghidra_result_output, front_result_output
    front_result_output = os.path.join(args.output, "keyword_extract_result")
    ghidra_result_output = os.path.join(args.output, "ghidra_extract_result")

    # check firmware directory is exist
    if not os.path.isdir(args.directory):
        log.error("Firmware path entered : {} not found".format(args.directory))
        sys.exit()

    # check output exist
    if not os.path.isdir(front_result_output):
        log.info("Init output keyword_extract_result directory : {} ".format(front_result_output))
        os.makedirs(front_result_output)

    if args.ghidra_script:
        # If you want execute ghidra, perform output directory detection
        if not os.path.isdir(ghidra_result_output):
            log.info("Init output ghidra_extract_result directory : {} ".format(ghidra_result_output))
            os.makedirs(ghidra_result_output)

    return args

def find_file_path(folder_path, filename):
    for root, dirs, files in os.walk(folder_path):
        if filename in files:
            return os.path.join(root, filename)
    return None


def front_analysise(args):
    # Run front-end keyword extraction, return border bin list
    remove_keyword_collection = []
    remove_function_collection = []

    runtimer.set_step1()
    f_analysise = FrontAnalysise(args.directory)
    f_analysise.analysise(ANALYSIZER)

    runtimer.set_step2()
    f_res = f_analysise.get_analysise_result()
    f_remove_file = f_analysise.get_remove_file()

    # 处理UPNP协议
    upapanalysise = set()
    if UPNP_ANALYSISE:
        upnpanaly = UpnpAnalysise(args.directory)
        upapanalysise = upnpanaly.get_result()

    runtimer.set_step3()
    for _F in F_FILTERS:
        f = _F()
        f()

        remove_keyword = f.get_remove_keyword()
        remove_func = f.get_remove_functions()

        remove_keyword_collection = list(set(remove_keyword + remove_keyword_collection))
        remove_function_collection = list(set(remove_func + remove_function_collection))

    runtimer.set_step4()
    if args.bin:
        b_analysise = BackAnalysise(args.directory, args.bin)
    else:
        b_analysise = BackAnalysise(args.directory)
    b_analysise.analysise()
    names = b_analysise.getbinname_and_path()

    # 开始从结果中过滤
    for _F in B_FILTERS:
        f = _F()
        f()
        remove_keyword = f.get_remove_keyword()
        remove_func = f.get_remove_functions()

        remove_keyword_collection = list(set(remove_keyword + remove_keyword_collection))
        remove_function_collection = list(set(remove_func + remove_function_collection))

        # 从b_analysise.elf_result里面删除上述结果
        b_analysise.delete_function(remove_func)
        b_analysise.delete_keyword(remove_keyword)

    # 处理部分匹配
    api_match_results = set()
    if API_SPLIT_MARCH:
        api_match_results = b_analysise.api_march()

    runtimer.set_end_time()
    # 获取结果
    res = b_analysise.get_result()

    # 整理bin
    border_bin = []
    if not args.bin:
        for bin in res[:args.len]:
            pth = bin["name"]
            name = pth.split("/")[-1]
            border_bin.append((name, pth))
    else:
        for f_name, f_path in names:
            border_bin.append((f_name, f_path))

    # TODO 写结果  args.output可以加上随机路径
    o = Output(res, front_result_output)
    o.custom_write()

    # 可选项
    o.write_file_info(f_res)
    o.write_remove_info(remove_function_collection, remove_keyword_collection)

    o.write_info()

    o.write_remove_jsfile(f_remove_file)
    o.write_api_split(api_match_results)

    if FROM_BIN_ADD:
        o.write_from_bin_add()
        o.write_from_bin_add_v2()

    if UPNP_ANALYSISE:
        res = b_analysise.get_upnp_result()
        o.write_upnp_keywords(res)
        o.write_upnp_analysise(upapanalysise)

    # 存储第一阶段得到的border_bin结果
    border_bin_json = os.path.join(front_result_output, "border_bin.json")
    with open(border_bin_json, 'w') as f:
        json.dump(border_bin, f, indent=2)

    return border_bin


def ghidra_analysise(args, border_bin):


    ghidra_scripts = args.ghidra_script

    if "all" in ghidra_scripts:
        ghidra_scripts = ["ref2share", "ref2sink_bof", "ref2sink_cmdi"]

    # keyword_file = os.path.join(front_result_output, "detail", "Clustering_result_v2.result")

    ghidra_project = os.path.join(ghidra_result_output, "ghidra_project")

    # 判断ghidra_project目录是否存在，如果不存在则创建
    if not os.path.isdir(ghidra_project):
        os.makedirs(ghidra_project)

    # dispose config_setter of all border binaries first to support cross binary analysis
    config_setter_sum = os.path.join(ghidra_result_output, "config_setter_sum.json")
    isExist = os.path.exists(config_setter_sum)
    # 如果指定了相关参数，就先对所有边界二进制做一遍ref2share脚本的预检测
    # if ("share2sink" in ghidra_scripts or "ref2share" in ghidra_scripts):
    if ("share2sink" in ghidra_scripts or "ref2share" in ghidra_scripts) and not isExist:
        # run ref2share
        s = "ref2share"
        random = uuid.uuid4().hex
        exec_script = scripts.get("ref2share", "")
        # loop border binaries
        for binname, binpath in border_bin:
            keyword_file = os.path.join(front_result_output, "simple", ".data", binname + ".result")
            ghidra_rep = os.path.join(ghidra_project, binname + "_" + s) + ".rep"
            bin_ghidra_project = os.path.join(ghidra_result_output, binname)
            if not os.path.isdir(bin_ghidra_project):
                os.makedirs(bin_ghidra_project)

            # 复制分析到binpath到bin_ghidra_project目录
            print("copy {} to {}".format(binname, bin_ghidra_project))
            shutil.copy2(binpath, bin_ghidra_project)

            output_name = os.path.join(bin_ghidra_project, "{}_{}.result".format(binname, s))
            # config_setter_sum = os.path.join(ghidra_result_output, "config_setter_sum.json")

            project_name = binname + "_" + s + random

            ghidra_args = [
                HEADLESS_GHIDRA, ghidra_project, project_name,
                '-postscript', exec_script, keyword_file, output_name, config_setter_sum, binname,
                '-scriptPath', os.path.dirname(exec_script),
            ]
            if os.path.exists(ghidra_rep):
                ghidra_args.append('-noanalysis')
                ghidra_args += ['-process', os.path.basename(binpath)]
            else:
                ghidra_args += ['-import', "'" + binpath + "'"]

            print(ghidra_args)
            p = subprocess.Popen(ghidra_args)
            p.wait()
        

    # 遍历其他脚本（ref2sink_bof, ref2sink_cmdi, call2sink, share2sink）
    # loop ghidra_scripts
    for s in ghidra_scripts:
        if s == "ref2share":
            continue
        keyword_file = ""
        exec_script = scripts.get(s, "")
        if exec_script == "":
            log.error("没有找到%s脚本", args.ghidra_script)

        random = uuid.uuid4().hex

        # loop border binaries
        for binname, binpath in border_bin:
            # 从工作逻辑上讲，share2sink应该只支持单个二进制，因为要手动指定args.ref2share_result的话一次就只能指定一个result文件
            # 修改后，不再需要单独指定ref2share_result
            if s == "share2sink":
                # keyword_file = args.ref2share_result
                keyword_file = os.path.join(ghidra_result_output, "config_setter_sum.json")
            else:
                keyword_file = os.path.join(front_result_output, "simple", ".data", binname + ".result")
            ghidra_rep = os.path.join(ghidra_project, binname + "_" + s) + ".rep"

            bin_ghidra_project = os.path.join(ghidra_result_output, binname)

            if not os.path.isdir(bin_ghidra_project):
                os.makedirs(bin_ghidra_project)

            # 复制分析到binpath到bin_ghidra_project目录
            print("copy {} to {}".format(binname, bin_ghidra_project))
            shutil.copy2(binpath, bin_ghidra_project)

            output_name = os.path.join(bin_ghidra_project, "{}_{}.result".format(binname, s))

            project_name = binname + "_" + s #+ random

            ghidra_args = [
                HEADLESS_GHIDRA, ghidra_project, project_name,
                '-postscript', exec_script, keyword_file, output_name,
                '-scriptPath', os.path.dirname(exec_script),
            ]
            if os.path.exists(ghidra_rep):
                ghidra_args.append('-noanalysis')
                ghidra_args += ['-process', os.path.basename(binpath)]
            else:
                ghidra_args += ['-import', "'" + binpath + "'"]

            print(ghidra_args)
            p = subprocess.Popen(ghidra_args)
            p.wait()

    # 移除Ghidra Project目录和rep目录
    if not args.save_ghidra_project:
        shutil.rmtree(ghidra_project)


def main():
    start_time = datetime.datetime.now()
    log.info("Start analysis time : {}".format(str(start_time)))
    args = argsparse()

    if not args.skip_keyword_extract:
        bin_list = front_analysise(args)
    else:
        border_bin_json = os.path.join(front_result_output, "border_bin.json")
        if not os.path.isfile(border_bin_json):
            print("Fail to find border_bin.json!")
            sys.exit(-1)
        with open(border_bin_json) as f:
            bin_list = json.load(f)
    
    # Support specify multi-bin manually.
    if args.bin:
        bin_list = []
        for bin in args.bin:
            bin_path = find_file_path(args.directory, bin)
            if bin_path is None:
                print("Fail to locate bin file: {}!".format(bin))
                sys.exit(-1)
            else:
                bin_list.append([bin, bin_path])

    if args.ghidra_script:
        ghidra_analysise(args, bin_list)
        # if ("share2sink" in args.ghidra_script and args.ref2share_result) or ("share2sink" not in args.ghidra_script):
        #     ghidra_analysise(args, bin_list)
        # elif "share2sink" in args.ghidra_script and not args.ref2share_result:
        #     print("Please use --ref2share_result args input ref2share script result")
        #     sys.exit(-1)


    if args.ghidra_script and args.taint_check:
        # 启用污点分析
        from taint_check.main import taint_stain_analysis
        from taint_check.bug_finder.config import checkcommandinjection, checkbufferoverflow

        global checkcommandinjection, checkbufferoverflow

        log.info("Start taint check ... ")

        for bin_name, bin_path in bin_list:
            for gs in args.ghidra_script:
                if gs in ["ref2sink_bof", "ref2sink_cmdi"]:
                    ghidra_result = os.path.join(ghidra_result_output, bin_name, "{}_{}.result".format(bin_name, gs))
                    if gs == "ref2sink_bof":
                        checkbufferoverflow = True
                        checkcommandinjection = False
                    if gs == "ref2sink_cmdi":
                        checkbufferoverflow = False
                        checkcommandinjection = True

                    # TODO 更改结果文件的保存位置
                    taint_stain_analysis(bin_path, ghidra_result, args.output)

        log.info("End taint check ...")
    end_time = datetime.datetime.now()

    log.info("Total time : {}s".format((end_time-start_time).seconds))


if __name__ == "__main__":
    main()
