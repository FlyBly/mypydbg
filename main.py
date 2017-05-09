# coding:utf-8
# 主模块

import debugger

debug = debugger.debugger()

exepath = raw_input("Enter Exe path:")

#执行exe文件
debug.load(exepath)



