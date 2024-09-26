# About 

This is a Linux Kernel Module designed for LKM rootkit detection. 

Written entierly in Rust using the Linux Rust API. See the corresponding linux fork repository, which have the expended Rust API needed to compile and run this module.

This module was designed to be used mostly on `x86_64` architecture, but some check are non architectural dependent.

# Available checks

## 1- Module name presence in list

Many rootkit hide themselves from the module list (/proc/modules, lsmod ...) by removing themselves from the module list used by the kernel. 

The module hook (using fprobe) many commonly used by LKM rootkit linux API function.
The callback function get the caller ip and using `kallsyms_module` check if the caller is a module or not, and if so check if it's name is in the kernel's module list. An absent name is highly suspicious.

## 2- Function integrity

Many rootkit act on the system by hooking multiple function such as `ip_rcv` to hide communication and open backdoor (listen for magic packet for example). 

Other commonly hooked function is `sys_kill`, often used as a way of communication with the module assigning to some signal number specials actions such as giving root to the user or unhiding himself.

Some rootkit have their own framework to hook thoses function (for example `khook` for Reptile) and work by modifying the code of the hooked function to modify their flow of execution.

This check work by reading the text of multiple commonly hooked function (see the list given after) as loading and regulary checking the integrity of the function.

This check don't work if the rootkit is already present at the loading of the module.

Checked functions (choosen by reading code of rootkit using the method described):
- `ip_rcv` (used by Reptile)
- `tcp4_seq_show` 
- `sys_getdents` (used by Reptile, BDS Ftrace)
- `sys_getdents64` (used by Reptile, BDS Ftrace)
- `sys_kill` (used by Reptile)



## 3- Syscall table entries address position

One of the privilieged way for LKM rootkit to alter it's environment is to hijack syscalls. The classical hooking method are possible (see above for details), but a more simple way to hook syscall is to modify the sycall table `sys_call_table`. 

This check works by getting the `sys_call_table` address and iterating over all it's entry checking for the position of each address, if the address is situated in a module the syscall has been hijacked.

## 4 - Symbol address lookup blacklist

Created a list of symbol which are often used by rootkit (for the moment using only the 3 tested rootkit). 

By hooking `kallsyms_lookup_name` we can get it's argument `name` and see if it is in the list of suspicious symbol.

## 5 - Control register pinned bits

Some rootkit unset some of the bits in the controls registers CR0 and CR4 to give themselves more freedom. 
A check that can be done is to look to the commonly attacked bits that should be set. 
However most of the time the rootkit set them back when they don't need them unset anymore.

The checked bits are:
- CR0:WP : Write Protect prevent the CPU to write read only page in ring 0. This bits is unset often to write to the `.rodata` section of the kernel (for example to the `sys_call_table`). This is used by the Diamorphine rootkit.
- CR4:UMIP : Block the usage of some instruction in user mode. Might be used by some rootkit to allow userspace program to have more freedom.
- CR4:SMEP / CR4:SMAP : Generate a fault in case of execution of code and data access to page in userspace.

## 6 - MSR LSTAR

A way to hijack the execution flow of the kernel is to modify the LSTAR register which controll the address to jump to when a syscall is triggered.

In the `syscall_init` the LSTAR register (used in x86_64's long mode) is set to the symbol `entry_SYSCALL_64` : 

```C
wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);
```

So we check that the address stored in the register still coreespond to the same symbol.

# Rootkit tested and detected

### Reptile : 

Source : https://github.com/f0rb1dd3n/Reptile

### Diamorphine : 

Source : https://github.com/m0nad/Diamorphine

### reveng_rtkit 

Source : https://github.com/reveng007/reveng_rtkit

Detected by 1- and 3- 

### Reptile improved :

Source : https://gitlab.hades.lan/t026/reptile

Detected by 3- and 4-