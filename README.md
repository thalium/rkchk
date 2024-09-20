# About 

This is a Linux Kernel Module designed for LKM rootkit detection. 

Written entierly in Rust using the Linux Rust API. See the corresponding linux fork repository, which have the expended Rust API needed to compile and run this module.

This module was designed to be used mostly on `x86_64` architecture, but some check are non architectural dependent.

# Available checks

## Module name presence in list

Many rootkit hide themselves from the module list (/proc/modules, lsmod ...) by removing themselves from the module list used by the kernel. 

The module hook (using fprobe) many commonly used by LKM rootkit linux API function.
The callback function get the caller ip and using `kallsyms_module` check if the caller is a module or not, and if so check if it's name is in the kernel's module list. An absent name is highly suspicious.


# Rootkit checked

Reptile : https://github.com/f0rb1dd3n/Reptile
Diamorphine : https://github.com/m0nad/Diamorphine
