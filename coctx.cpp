/*
* Tencent is pleased to support the open source community by making Libco
available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "coctx.h"
#include <stdio.h>
#include <string.h>

#define ESP 0
#define EIP 1
#define EAX 2
#define ECX 3
// -----------
#define RSP 0
#define RIP 1
#define RBX 2
#define RDI 3
#define RSI 4

#define RBP 5
#define R12 6
#define R13 7
#define R14 8
#define R15 9
#define RDX 10
#define RCX 11
#define R8 12
#define R9 13

//----- --------
// 32 bit
// | regs[0]: ret |
// | regs[1]: ebx |
// | regs[2]: ecx |
// | regs[3]: edx |
// | regs[4]: edi |
// | regs[5]: esi |
// | regs[6]: ebp |
// | regs[7]: eax |  = esp 
enum {
  kEIP = 0,
  kEBP = 6,
  kESP = 7,
};

//-------------
// 64 bit
// low | regs[0]: r15 |
//    | regs[1]: r14 |
//    | regs[2]: r13 |
//    | regs[3]: r12 |
//    | regs[4]: r9  |
//    | regs[5]: r8  |
//    | regs[6]: rbp |
//    | regs[7]: rdi |
//    | regs[8]: rsi |
//    | regs[9]: ret |  //ret func addr
//    | regs[10]: rdx |
//    | regs[11]: rcx |
//    | regs[12]: rbx |
// hig | regs[13]: rsp |
enum {
  kRDI = 7,
  kRSI = 8,
  kRETAddr = 9,
  kRSP = 13,
};

// 64 bit
extern "C" {
extern void coctx_swap(coctx_t*, coctx_t*) asm("coctx_swap");
};
#if defined(__i386__)
int coctx_init(coctx_t* ctx) {
  memset(ctx, 0, sizeof(*ctx));
  return 0;
}
int coctx_make(coctx_t* ctx, coctx_pfn_t pfn, const void* s, const void* s1) {
  // make room for coctx_param
  char* sp = ctx->ss_sp + ctx->ss_size - sizeof(coctx_param_t);
  sp = (char*)((unsigned long)sp & -16L);

  coctx_param_t* param = (coctx_param_t*)sp;
  // 注意这里32位中只有8个寄存器，因此参数是通过栈进行传递的，因此对于函数需要多留两个参数地址
  void** ret_addr = (void**)(sp - sizeof(void*) * 2);
  *ret_addr = (void*)pfn;
  param->s1 = s;
  param->s2 = s1;

  memset(ctx->regs, 0, sizeof(ctx->regs));

  ctx->regs[kESP] = (char*)(sp) - sizeof(void*) * 2;
  return 0;
}
#elif defined(__x86_64__)

int coctx_init(coctx_t* ctx) {
  memset(ctx, 0, sizeof(*ctx));
  return 0;
}

int coctx_make(coctx_t* ctx, coctx_pfn_t pfn, const void* s, const void* s1) {
  // 定义共享栈顶指针位置
  char* sp = ctx->ss_sp + ctx->ss_size - sizeof(void*);
  //-16LL的16进制表示是0xfffffffffffffff0
  //& -16LL 相当于后四位清0，也就是最后16bit清零，完成16字节对齐
  sp = (char*)((unsigned long)sp & -16LL);

  memset(ctx->regs, 0, sizeof(ctx->regs));
  // 设置返回值地址指针
  void** ret_addr = (void**)(sp);
  // 指向返回函数地址
  *ret_addr = (void*)pfn;
  // 设置栈顶指针
  ctx->regs[kRSP] = sp;
  // 设置返回函数地址
  ctx->regs[kRETAddr] = (char*)pfn;
  // 函数入参地址可以通过rdi与rsi进行传入，因此不必再设置栈
  // rdi地址
  ctx->regs[kRDI] = (char*)s;
  // rsi地址
  ctx->regs[kRSI] = (char*)s1;
  return 0;
}


#endif
