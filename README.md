# About 

This is a Linux Kernel Module designed for LKM rootkit detection. 

Written entierly in Rust using the Linux Rust API. See the corresponding linux fork repository, which have the expended Rust API needed to compile and run this module.

This module was designed to be used mostly on `x86_64` architecture, but some check are non architectural dependent.

# Installation guide

## Installing the Linux kernel 

To run this detection tool you need to first install a custom linux kernel. This kernel is provided in a separated git repo.

### Installing Rust toolchain

The linux kernel will need to be compiled with Rust support, for that I advice to check out [this page](https://docs.kernel.org/rust/quick-start.html).

To be sure that rust can be activated you can run in the kernel source tree : 

```
make rustavailable
```

### Configuring the kernel

Then to activate Rust you first need to make a default config, for example with : 
```
make defconfig
```

Then you can activate various configuration option with :

```
make menuconfig
```

Precisly you need to activate : 
```
RUST
FUNCTION_TRACER
FPROBE
```

(those are activated in most major distribution's kernel by default)

### Compiling the kernel

You can now compile the kernel with Rust (so LLVM) activated.

```
make LLVM=1 vmlinux
```

For a easy to use result you can make the build process produce a package. To see the different package format supported you can do :

```
make help
```

For example for debian you can do :

```
make LLVM=1 bindeb-pkg
```

And then install the .deb generated.

## Installing our tool 




# Available checks

## 1- Module name presence in list

Many rootkit hide themselves from the module list (/proc/modules, lsmod ...) by removing themselves from the module list used by the kernel. 

The module hook (using fprobe) many commonly used by LKM rootkit linux API function.
The callback function get the caller ip and using `kallsyms_module` check if the caller is a module or not, and if so check if it's name is in the kernel's module list. An absent name is highly suspicious.

## 1.1 - Calling address in kernel space

If the precedent code don't find a module name associated with the address of the caller, we check that this address is in kernel text, if not the calling address is suspicious because neither in kernel text nor module text.

## 2- Function integrity

Many rootkit act on the system by hooking multiple function such as `ip_rcv` to hide communication and open backdoor (listen for magic packet for example). 

Other commonly hooked function is `sys_kill`, often used as a way of communication with the module assigning to some signal number specials actions such as giving root to the user or unhiding himself.

Some rootkit have their own framework to hook thoses function (for example `khook` for Reptile) and work by modifying the code of the hooked function to modify their flow of execution.

This check work by calculating the hash of the text of multiple commonly hooked function (see the list given after) at loading and regulary checking the integrity of the function.

This check don't work if the rootkit is already present at the loading of the module.

Checked functions (choosen by reading code of rootkit using the method described):
- `ip_rcv` (used by Reptile)
- `tcp4_seq_show` (used by Reptile)
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


## 7 - Custom hooking

Some rootkit, in order to alter the control flow of the kernel, hook on interzesting function using custom hooking framework. Those framework often involve placing a breakpoint (opcode `0xCC`) or a jump (opcode `0xE9`) at the begining of the hooked function. 

This check disassemble the first instruction of choosen functions (using the in kernel disassembler) to see if it's not a jump or a breakpoint. Therefor we can analyze if a function has been hooked even if the checker is loaded after the rootkit.

Function checked : 
- `ip_rcv` (used by Reptile)
- `tcp4_seq_show` (used by Reptile)

## 8 - File hiding

Most of the rootkit offer a way to hide files. The most common way to hide file is to hook the `getdents64` syscall (used to get the list of the files present in a directory) and modify the buffer it return. 

The buffer returned by `getdents64` is an array of `struct linux_dirent64`. Containing the following entry : 

```C
struct linux_dirent64 {
    ino64_t        d_ino;    /* 64-bit inode number */
    off64_t        d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};
```
The `d_reclen` give the size of the current `linux_dirent64` entry and is used to jump to the following entry. 
So we can hide an entry by modifying the field `d_reclen` of the precedent entry to be the size of the hidden entry and the precedent entry. 

We can detect the tampering of the returned buffer by checking that each structure has the size of it's `d_reclen`. If not the buffer has been tampered with and we can retreive the name of the hidden file (if it wasn't overwrote). 

## 9 - Process Hiding

A very simple way of hiding process is by hiding `/proc/<pid>` directory for each `pid` we want to hide using the technique described in (8).

We can detect hidden process by the technique in (8). 
But a more robust way is by iterating through the linked list of `task_struct` in the kernel. 
Because a process want to be scheduled it need to be in this list so it's quite difficult for a rootkit to remove a process from this list and make so that the process still run.

## 10 - Write capable eBPF helper usage

Inspired by the (Aqua tracee's check)[https://aquasecurity.github.io/tracee/latest/docs/events/builtin/extra/bpf_attach/].

eBPF programms are very limited in terms of write capacity. 
They can't write directly to pointer they receive (from kernel or userspace). 
The only way they have to modify user or kernel data is through a limited number of helpers : 
- `bpf_probe_write_user` : allow to write data to an user pointer
- `bpf_override_return` : allow to override the return value of a hooked function

We can detect the usage of thoses function during the verifying step of the eBPF program loading process. 
We hook into `check_helper_call` which is called for each function the verifier encounter. 
This allow us to check if a programm contains helper capable of modifying it's environment.

## 11 - Bruteforcing the LKM address space

Inspired by the [Phrack article](https://phrack.org/issues/71/12#article). 

To hide themselves, LKM rootkit must remove themselves from 3 structures the kernel use to keep track of the modules. Most of them remove themselves from only one or two, which allow us to find them by integrity checks, however if the rootkit remove themselves from all of the structures.
The idea is to find all the kernel module in the kernel module address space by iterating over it, finding all the allocated spaces and in it trying to match with a `struct module` using the knowledge that somes of the fields of these structure have specific value for exemple : 
- name : A null terminated string of at most 56 characters
- state : An enum
- entry : A pointer in the module address space
...

This allow us to retrieve all the LKM in the kernel.


## 12 - Integrity check on all kernel text page 

A copy of one of the kernel text pages (~ 2 MB) is realized at rkchk's loading and is regularly compared with the actual kernel's page. This allow us to find inlines hooks, the placed opcode and the hooked function. More useful for post mortem analysis than a integrity check using the hash of the whole page.


## 13 - List the activated probes

Inspired by a [TODO list in KoviD's repo](https://github.com/carloslack/KoviD/blob/master/TODO.txt).

When using the kernel's API to place probes in the kernel thoses probes are listed in `/sys/kernel/debug/tracing/enabled_functions`. Therefor we can see the probes that are not placed by rkchk and report them.

## 14 - Write on sensible files 

The main way (and to my knowledge the only one) for an userspace rootkit to hook itself to system's library is to add their library to `ld.so.preload` so their library is loaded before all the others. Another more discret way is to modify directly `ld.so` such that it uses another configuration file (that's what [Bedevil](https://github.com/Error996/bdvl) do). 

Therefor to detect userspace rootkit installation we can check the open syscall with write flag set on thoses files.

## 15 - Getting stacktrace

Using the stack unwinder of the kernel we dump the stacktrace each time a suspicious kernel API call is made (for the moment `kallsym_lookup_name` calls on suspicious symbols to detect kprobe's tricks usage). 


# Available response

We can respond to the threat we detect.

## LKM 

The suspicious LKM are identified by their name.
The available response is the equivalent of a `rmmod --force <name_module>`.

## eBPF

Most eBPF programs are linked to an userspace program so the most efficient way to unload an eBPF rootkit is to end it's asociated process.
The available response is the equivalent of a `kill -9 <pid>`.

(this response is also useful against suspect process, for example hidden one by a rootkit).

# Rootkit tested and detected

## LKM Rootkits

### Reptile

Source : https://github.com/f0rb1dd3n/Reptile

### Diamorphine

Source : https://github.com/m0nad/Diamorphine

(only worked on 6.3 kernel)

#### Detection
    1 / 3 / 4

### reveng_rtkit 

Source : https://github.com/reveng007/reveng_rtkit

(only worked on 6.3 kernel)

#### Detection
    1 / 3 / 4

### Reptile improved

#### Detection
If loaded after rkchk :

    1-1 / 2 / 7 / 11 / 12

If loaded before rkchk :

    1-1 / 7 / 11

### KoviD

Source : https://github.com/carloslack/KoviD

#### Detection 

    11 / 12 / 13

## Userspace rootkits 

### Bedevil 

Source : https://github.com/Error996/bdvl

#### Detection

If loaded before rkchk : 

    14

## eBPF rootkits

### TripleCross

Source : https://github.com/h3xduck/TripleCross

#### Result

The rootkit don't load because of a failed check during the verifying process : 
```
361: (07) r2 += 64                    ; R2_w=pkt(off=64,r=54,imm=0)
362: (67) r2 <<= 32
R2 pointer arithmetic with <<= operator prohibited
```
I suppose that it's because the verifier became stricter since the version of the kernel the module has been made for. (5.11)

### ebpfkit

Source : https://github.com/Gui774ume/ebpfkit

#### Result

The rootkit don't load because of a failed check during the verifying process : 
```
5401: (6b) *(u16 *)(r3 +0) = r1
R3 offset is outside of the packet
```
Same as before.


