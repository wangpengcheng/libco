/*
* Tencent is pleased to support the open source community by making Libco available.

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
/*
https://zhuanlan.zhihu.com/p/42874353
*/
.globl coctx_swap
#if !defined( __APPLE__ )
.type  coctx_swap, @function
#endif
coctx_swap:
# 定义交换函数
#if defined(__i386__)
    movl 4(%esp), %eax # 将其上移四个位置
    movl %esp,  28(%eax) # 
    movl %ebp, 24(%eax)
    movl %esi, 20(%eax)
    movl %edi, 16(%eax)
    movl %edx, 12(%eax)
    movl %ecx, 8(%eax)
    movl %ebx, 4(%eax)


    movl 8(%esp), %eax
    movl 4(%eax), %ebx
    movl 8(%eax), %ecx
    movl 12(%eax), %edx
    movl 16(%eax), %edi
    movl 20(%eax), %esi
    movl 24(%eax), %ebp
    movl 28(%eax), %esp

	ret
/* x86寄存器编码*/
# coctx_swap的2个参数并没有入栈，而是存放在rdi(第一个参数),rsi(第二个参数)寄存器中！注意这里传入的数据结构是coctx_t指针地址
# rsp是当前栈顶，8(%rsp)是跳过rip,指向调用coctxswap函数之前的栈顶；将rax指向栈顶指针
#elif defined(__x86_64__)
	leaq (%rsp),%rax # 将栈顶地址加载到rax寄存器中
    movq %rax, 104(%rdi) #  保存当前栈顶指针到regs[13];注意这里是120-16所以是104 中间包含队了大小和具体的指针
    movq %rbx, 96(%rdi) # 将rbx寄存器的值进行保存
    movq %rcx, 88(%rdi) # 
    movq %rdx, 80(%rdi)
	  movq 0(%rax), %rax # 计算返回值地址；其中rax中暂存的是rsp的值，这里将rsp指向的地址值，传输给rax;进行一次间接寻址；主要是为了获取返回值地址
	  movq %rax, 72(%rdi)  # 将返回值地址重新保存到regs[9]
    movq %rsi, 64(%rdi) 
	  movq %rdi, 56(%rdi)
    movq %rbp, 48(%rdi)
    movq %r8, 40(%rdi)
    movq %r9, 32(%rdi)
    movq %r12, 24(%rdi)
    movq %r13, 16(%rdi)
    movq %r14, 8(%rdi)
    movq %r15, (%rdi)
	  xorq %rax, %rax  # 进行亦或操作，相当于重新置为0
    # 接下来就是参数的逆序操作；主要是将rsi中的参数都加载到寄存器中
    movq 48(%rsi), %rbp 
    movq 104(%rsi), %rsp
    movq (%rsi), %r15 
    movq 8(%rsi), %r14
    movq 16(%rsi), %r13
    movq 24(%rsi), %r12
    movq 32(%rsi), %r9
    movq 40(%rsi), %r8
    movq 56(%rsi), %rdi
    movq 80(%rsi), %rdx
    movq 88(%rsi), %rcx
    movq 96(%rsi), %rbx
		leaq 8(%rsp), %rsp # 注意这里将rsp的 的上一个地址栈加载到rsp中
		pushq 72(%rsi)  # 将regs[9] 放入到栈中，相当于将返回值ret压入栈中

    movq 64(%rsi), %rsi # 加载rsi的值
	ret 
#endif
