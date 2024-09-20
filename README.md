# About 

This is a Linux Kernel Module designed for LKM rootkit detection. 

Written entierly in Rust using the Linux Rust API. See the corresponding linux fork repository, which have the expended Rust API needed to compile and run this module.

This module was designed to be used mostly on `x86_64` architecture, but some check are non architectural dependent.

# Available checks

## Module name presence in list

Many rootkit hide themselves from the module list (/proc/modules, lsmod ...) by removing themselves from the module list used by the kernel. 

The module hook (using fprobe) many commonly used by LKM rootkit linux API function.
The callback function get the caller ip and using `kallsyms_module` check if the caller is a module or not, and if so check if it's name is in the kernel's module list. An absent name is highly suspicious.

## Function integrity

Many rootkit act on the system by hooking multiple function such as `ip_rcv` to hide communication and open backdoor (listen for magic packet for example). 

Other commonly hooked function is `sys_kill`, often used as a way of communication with the module assigning to some signal number specials actions such as giving root to the user or unhiding himself.

Some rootkit have their own framework to hook thoses function (for example `khook` for Reptile) and work by modifying the code of the hooked function to modify their flow of execution.

This check work by reading the text of multiple commonly hooked function (see the list given after) as loading and regulary checking the integrity of the function.

This check don't work if the rootkit is already present at the loading of the module.

Checked functions :
- `ip_rcv`

# Rootkit tested and detected

Reptile : https://github.com/f0rb1dd3n/Reptile
Diamorphine : https://github.com/m0nad/Diamorphine
