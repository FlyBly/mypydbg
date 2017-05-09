# coding:utf-8
# 调试核心

from ctypes import *
from defines import*
import Asm
kernel32 = windll.kernel32


class debugger():

    # 初始化数据
    def __init__(self):
        self.h_process = None
        self.h_thread = None
        self.pid = None
        self.thread_id = None
        self.debugger_active = False
        self.context = CONTEXT()
        self.context.ContextFlags = CONTEXT_DEBUG_REGISTERS|CONTEXT_FULL

        self.exception_addr = None
        self.lpOep  =None

        self.first_breakpoint = True
        self.hardware_breakpoints = {}

        #硬件断点触发的单步
        self.Ishard_breake_single = False

        #软件触发的单步
        self.Isbreak_point_single  = False

        #内存断点触发的单步
        self.Ismem_breadk_point_single  = False
        self.Ismem_breadk_point_single_data=()

        #软件断点列表
        self.breakpoints = {}
        self.temp=()

        # 系统中默认内存页大小
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

        # 保护属性
        self.guarded_pages = []
        self.memory_breadkpoints = {}

    #加载exe
    def load(self,exe_path):
        #创建标志
        create_flags = DEBUG_ONLY_THIS_PROCESS
        #启动信息
        startupinfo = STARTUPINFO()
        #进程信息
        process_information = PROCESS_INFORMATION()

        #创建进程
        if kernel32.CreateProcessA(exe_path, None, None,
                                   None, None, create_flags,
                                   None, None,
                                   byref(startupinfo),
                                   byref(process_information)):
            print("run success")
            self.pid  = process_information.dwProcessId
            self.h_process  = process_information.hProcess
            self.run()
        else:
            print("Error:%08X" % kernel32.GetLastError())

    #运行框架
    def run(self):
        debug_event = DEBUG_EVENT()
        contine_status = DBG_CONTINUE

        while kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            #记录当前线程
            self.h_thread = self.open_thread(debug_event.dwThreadId)

            #调试事件触发异常
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                #异常代码
                exception =\
                    debug_event.u.Exception.ExceptionRecord.ExceptionCode
                #异常地址
                self.exception_addr=\
                    debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                # 内存访问异常
                if exception == EXCEPTION_ACCESS_VIOLATION:
                    contine_status = self.exception_handler_access_violation()

                # 软件断点
                elif exception == EXCEPTION_BREAKPOINT:
                    contine_status = self.exception_handler_breakpoint()
                #页保护异常
                elif exception == EXCEPTION_GUARD_PAGE:
                    print("Guard Page Access Detected")
                #单步异常
                elif exception == EXCEPTION_SINGLE_STEP:
                    contine_status =self.exception_handler_single_step()

            # 进程创建触发
            elif debug_event.dwDebugEventCode  ==CREATE_PROCESS_DEBUG_EVENT:
                self.lpOep = debug_event.u.CreateProcessInfo.lpStartAddress
                print("pragme start address 0x%08x"% int(self.lpOep))


            kernel32.ContinueDebugEvent(
                debug_event.dwProcessId, debug_event.dwThreadId, contine_status)

    #打开线程
    def open_thread(self,thread_id):
        self.thread_id = kernel32.OpenThread(
            THREAD_ALL_ACCESS, None, thread_id)

        if self.thread_id is not None:
            return self.thread_id
        else:
            print(" could not obtain a valid thrad handle")
            return False

    #软件断点处理
    def exception_handler_breakpoint(self):

        #处理第一次系统断点
        if self.first_breakpoint == True:
            print("System breadkepoint address :0x%08x" % self.exception_addr)
            self.bp_set_int3(self.lpOep)

            self.first_breakpoint=False
            return DBG_CONTINUE
        #其他触发断点
        else:
            #断点在列表中
            if self.exception_addr in self.breakpoints:

                kernel32.GetThreadContext(self.h_thread,byref(self.context))
                self.context.Eip -=1
                kernel32.SetThreadContext(self.h_thread,byref(self.context))
                self.bp_reply_int3(self.exception_addr)

            #步过触发的断点
            elif self.temp[0]==self.exception_addr:
                kernel32.GetThreadContext(self.h_thread,byref(self.context))
                self.context.Eip -=1
                kernel32.SetThreadContext(self.h_thread,byref(self.context))
                self.bp_reply_Temp_int3(self.exception_addr)
            else:
                return  DBG_EXCEPTION_HANDLED

            self.CommandLine()
            return  DBG_CONTINUE

    #设置软件断点
    def bp_set_int3(self,address):
        if not self.breakpoints.has_key(address):
            try:
                #读取一个字节
                original_byte = self.read_process_memory(address,1)
                #写入0xcc 断点
                self.write_process_memory(address, "\xcc")
                # 在断点列表中记录
                self.breakpoints[address] = (address, original_byte,True)
            except:
                return False

        return True

    #设置步过断点
    def bp_set_temp_int3(self,address):
        try:
            # 读取一个字节
            original_byte = self.read_process_memory(address, 1)
            # 写入0xcc 断点
            self.write_process_memory(address, "\xcc")
            # 在断点列表中记录
            self.temp = (address, original_byte)
        except:
            return False
        return  True

    #回复软件断点
    def bp_reply_int3(self,address):
        try:
            stemp=self.breakpoints[address][1]
            self.write_process_memory(address,stemp)
        except:
            return  False

        return True

    #回复步过断点
    def bp_reply_Temp_int3(self,address):
        try:
            self.write_process_memory(address,self.temp[1])
        except:
            return  False
        return True

    # 读取地址数据
    def read_process_memory(self, address, lenth):
        data = ""
        read_buff = create_string_buffer(lenth)

        count = c_ulong(0)

        kernel32.ReadProcessMemory(self.h_process,address,read_buff,5, byref(count))


        data = read_buff.raw
        return data

    # 写入地址数据
    def write_process_memory(self, address, data):

        count = c_ulong(0)
        lenth = len(data)
        c_date = c_char_p(data[count.value:])

        if not kernel32.WriteProcessMemory(self.h_process,
                                           address, c_date,
                                           lenth, byref(count)):
            return False
        else:
            return True


    # 单步断点处理
    def exception_handler_single_step(self):

        #恢复软件的断点
        if self.Isbreak_point_single == True:
            pass

        #恢复硬件断点
        elif self.Ishard_breake_single == True:
            pass

        #内存断点
        elif self.Ismem_breadk_point_single == True:
            tem_protection = c_ulong(0)
            kernel32.VirtualProtectEx(self.h_process, self.exception_addr,
                                      self.Ismem_breadk_point_single_data[1],
                                      self.Ismem_breadk_point_single_data[4],
                                      byref(tem_protection))
            self.Ismem_breadk_point_single = False




        #普通单步
        else:
            if self.Ishardware_touch()!=-1:
                self.bp_del_hw(self.Ishardware_touch())

            self.CommandLine()


        return  DBG_CONTINUE

    #检测是否是硬件触发的断点
    def Ishardware_touch(self):
        kernel32.GetThreadContext(self.h_thread, byref(self.context))
        if self.context.Dr6 & 1:
            return 0
        elif self.context.Dr6 & (1 << 1):
            return 1
        elif self.context.Dr6 & (1 << 2):
            return 2
        elif self.context.Dr6 & (1 << 3):
            return 3
        return -1




    #设置硬件断点
    def bp_set_hw(self, address, length, condition):
        if length not in (1, 2, 3):
            return False
        else:
            length -= 1

        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False
        if not self.hardware_breakpoints.has_key(0):
            available = 0
        elif not self.hardware_breakpoints.has_key(1):
            available = 1
        elif not self.hardware_breakpoints.has_key(2):
            available = 2
        elif not self.hardware_breakpoints.has_key(3):
            available = 3
        else:
            return False

        kernel32.GetThreadContext(self.h_thread,byref(self.context))

        # 设置DR7 相应的标志位  L0 L1 L2 L3
        self.context.Dr7 |= 1 << (available * 2)

        if available == 0:
            self.context.Dr0 = address
        elif available == 1:
            self.context.Dr1 = address
        elif available == 2:
            self.context.Dr2 = address
        elif available == 3:
            self.context.Dr3 = address

        # 设置相应的出发条件 读写执行
        self.context.Dr7 | condition << ((available * 4) + 16)

        # 设置硬件断点长度
        self.context.Dr7 | length << ((available * 4) + 18)

        kernel32.SetThreadContext(self.h_thread, byref(self.context))

        self.hardware_breakpoints[available] = (address, length, condition)

        return True

    #删除硬件断点
    def bp_del_hw(self,slot):
        kernel32.GetThreadContext(self.h_thread,byref(self.context))

        # 将L0 L1 L2 L3 出发的位置 填充 0
        self.context.Dr7 &= ~(1 << (slot * 2))

        if slot == 0:
            self.context.Dr0 = 0x0000000
        elif slot == 1:
            self.context.Dr1 = 0x0000000
        elif slot == 2:
            self.context.Dr2 = 0x0000000
        elif slot == 3:
            self.context.Dr3 = 0x0000000

        # 清空断点触发标志
        self.context.Dr7 &= ~(3 << ((slot * 4) + 16))

        # 清空断点长度标志
        self.context.Dr7 &= ~(3 << ((slot * 4) + 18))

        # 提交断点
        kernel32.SetThreadContext(self.h_thread, byref(self.context))
        del self.hardware_breakpoints[slot]

        return True

    # 获取当前线程环境
    def get_thread_context(self, thread_id=None, h_thread=None):

        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        if thread_id is not None:
            h_thread = self.open_thread(thread_id)

        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            return False



    #设置内存断点
    def bp_set_mem (self, address, size):

        mbi = MEMORY_BASIC_INFORMATION()

        if kernel32.VirtualQueryEx(self.h_process, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
            return False

        current_page = mbi.BaseAddress

        # 将对于整个内存断点区域覆盖的所有内存页 设置访问属性
        while current_page <= address + size:

            # 保存这个页到列表中，用于保护
            self.guarded_pages.append(current_page)
            # 原来的属性
            old_protection = c_ulong(0)
            new_protection = c_ulong(0)


            if not kernel32.VirtualProtectEx(self.h_process, current_page, size, PAGE_NOACCESS,
                                             byref(old_protection)):
                return False

            current_page += self.page_size

        self.memory_breadkpoints[address] = (address, size, mbi.BaseAddress,old_protection,PAGE_NOACCESS)
        return True

    #内存访问处理
    def exception_handler_access_violation(self):

        for i in self.memory_breadkpoints:

            if (self.memory_breadkpoints[i][2]+self.page_size >self.exception_addr) and (self.memory_breadkpoints[i][2]<= self.exception_addr):
                tem_protection = c_ulong(0)
                kernel32.VirtualProtectEx(self.h_process,
                                          self.exception_addr,
                                          self.memory_breadkpoints[i][1],
                                          self.memory_breadkpoints[i][3],
                                          byref(tem_protection))

                if self.memory_breadkpoints[i][0]==self.exception_addr:
                    self.CommandLine()
                else:
                    self.Ismem_breadk_point_single =True
                    self.Ismem_breadk_point_single_data =self.memory_breadkpoints[i]
                    kernel32.GetThreadContext(self.h_thread, byref(self.context))
                    self.context.EFlags |= (1 << 8)
                    kernel32.SetThreadContext(self.h_thread, byref(self.context))

                    break

        return DBG_CONTINUE

        # 解析函数名对应的地址

    def func_resolve(self, dll, function):
        address =None

        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)
        kernel32.CloseHandle(handle)
        if address is None:
            return False
        else:
            return address

    #执行命令
    def CommandLine(self):

        #反汇编
        myasm = Asm.MyAsm(self.h_process)
        opcode,asm,lenth =myasm.AnitAsm(self.exception_addr)
        self.print_Asm(self.exception_addr,myasm)

        #循环接收命令
        while True:
            #接收命令
            scommand = raw_input("Enter the a command line: ")
            comline =scommand.split(' ')

            #设置单步
            if "t"== comline[0]:
                kernel32.GetThreadContext(self.h_thread, byref(self.context))
                self.context.EFlags |= (1<<8)
                kernel32.SetThreadContext(self.h_thread,byref(self.context))
                return

            #设置步过
            if "p" == comline[0]:
                kernel32.GetThreadContext(self.h_thread, byref(self.context))
                self.bp_set_temp_int3(self.context.Eip+lenth)
                return

            #显示反汇编
            elif "u" == comline[0]:
                #u后面是否带地址
                if len(comline)==2 and comline[1].isalnum():
                    self.print_Asm(int(comline[1],16),myasm)
                else:
                    self.print_Asm(self.exception_addr,myasm)

            #设置软件断点
            elif "bp" == comline[0]:
                # bp 后面是地址
                if len(comline)==2 and comline[1].isalnum():
                    if self.bp_set_int3(int(comline[1],16)):
                        print("[*] set int3 succeed ")
                    else:
                        print("[*] set int3 error again try")
                 # bp后面是函数名
                elif len(comline)==3:
                    fun_address = self.func_resolve(comline[1],comline[2])
                    if fun_address is not False:
                        self.bp_set_int3(self.func_resolve(comline[1],comline[2]))
                        print ("set funtion success")
                    else:
                        print("set funtion error")

            #设置内存断点
            elif "bm" == comline[0]:
                if len(comline)==3 and comline[1].isalnum() and comline[2].isalnum():
                    self.bp_set_mem(int(comline[1],16),int(comline[2]))
                    print("set memory break potion success")
                else:
                    print("input error memory break potion")

            #设置硬件断点
            elif "bh" == comline[0]:
                if len(comline)==4 and comline[1].isalnum() and comline[2].isalnum()and comline[3].isalnum():
                    if self.bp_set_hw(int(comline[1],16),int(comline[2]),int(comline[3])):
                        print ("set hardwarn break potion success")
                    else:
                        print("set hardwarn field")
                else:
                    print("set hardwarn field")

            #查看寄存器
            elif "r" == comline[0]:
                kernel32.GetThreadContext(self.h_thread,byref(self.context))
                print(" EIP: 0x%08x" % self.context.Eip)
                print(" ESP: 0x%08x" % self.context.Esp)
                print(" EBP: 0x%08x" % self.context.Ebp)
                print(" EAX: 0x%08x" % self.context.Eax)
                print(" EBX: 0x%08x" % self.context.Ebx)
                print(" ECX: 0x%08x" % self.context.Ecx)
                print(" EDX: 0x%08x" % self.context.Edx)

            #查看命令
            elif "help"==comline[0]:
                print("t                             -- single setp")
                print("p                             -- step over")
                print("r                             -- look register")
                print("g                             -- run program")
                print("q                             -- exit program")
                print("u  -address or None           -- disassembling")
                print("bp -address or -dll -funtion  -- set int3 break point")
                print("bm -address -lenth            -- set memory break point")
                print("bh -address -lenth -option    -- set hardwar break point")

            #结束进程
            elif "q"==comline[0]:
                print "Exit..............."
                exit(0)
            # 运行
            elif "g" == comline[0]:
                return
            #输入错误
            else:
                print("command  error agagin enter ")

    #打印数据
    def print_Asm(self,addr,myasm):

        count=0
        for i in range(5):
            opcode, asm, lenth = myasm.AnitAsm(addr+count)
            print("0x%08x : %-30s  %-30s" %(addr+count,opcode,asm))
            count += lenth








