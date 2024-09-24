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

Checked functions :
- `ip_rcv`

## 3- Syscall table entries address position

One of the privilieged way for LKM rootkit to alter it's environment is to hijack syscalls. The classical hooking method are possible (see above for details), but a more simple way to hook syscall is to modify the sycall table `sys_call_table`. 

This check works by getting the `sys_call_table` address and iterating over all it's entry checking for the position of each address, if the address is situated in a module the syscall has been hijacked.

## 4 - Symbol address lookup blacklist

Created a list of symbol which are often used by rootkit (for the moment using only the 3 tested rootkit). 

By hooking `kallsyms_lookup_name` we can get it's argument `name` and see if it is in the list of suspicious symbol.

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
