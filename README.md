# rkchk

This is a Linux Kernel Module designed for LKM rootkit detection. 

Written entirely in Rust using the Linux Rust API. See the corresponding Linux fork repository, which has the expanded Rust API needed to compile and run this module.

This module was designed to be used mostly on `x86_64` architecture, but some checks are not architecture-dependent.

# Installation guide

## Installing the Linux kernel 

To run this detection tool you first need to install a custom linux kernel, provided in a [separate repository](https://github.com/thalium/rkchk-linux-next).

### Installing Rust toolchain

The Linux kernel must be compiled with Rust support: for that, it is recommended to check out [this page](https://docs.kernel.org/rust/quick-start.html).

To make sure that Rust can be enabled, you can run the following command in the kernel source tree: 

```
make rustavailable
```

### Configuring the kernel

To enable Rust, you first need to make a default config, for example with:

```
make defconfig
```

Then, you can enable various configuration options with:

```
make menuconfig
```

In particular, you need to enable the following options:

```
RUST
FUNCTION_TRACER
FPROBE
BPF_SYSCALL
```

(those are enabled by default in the kernel of most major distributions)

### Compiling the kernel

You can now compile the kernel with Rust (so LLVM) enabled:

```
make LLVM=1 vmlinux
```

You can also have the build process produce a package. To see the different package formats supported:

```
make help
```

For example, for Debian, you can run:

```
make LLVM=1 bindeb-pkg
```

And then install the generated `.deb` file.

## Installing & running rkchk

A small script is provided to automatically build the kernel module, install it and launch the user space program.

You can launch the script with the following command (run it without root privilege):

```
sh run.sh
```

## Configuring

The tool can generate a lot of noise and some feedbacks may be very verbose. You can select which events to display by changing the `user/src/main.rs` file.

The effects for all the events are documented in `user/src/event.rs`.

# Available checks

## 1. Module name presence in list

Many rootkits hide themselves from the modules list (`/proc/modules`, `lsmod`...), by removing themselves from the list used in the kernel. 

The module hook (using fprobe) many commonly used by LKM rootkit linux API function.
The callback function gets the caller ip, uses `kallsyms_module` to check whether the caller is a module, and if so, checks if its name is in the kernel's module list. An absent name is highly suspicious.

## 1.1 - Calling address in kernel space

If the previous code doesn't find a module name associated with the address of the caller, we check that this address is in kernel text. If not, the calling address is suspicious because it is neither in kernel text nor module text.

## 2 - Function integrity

Many rootkits act on the system by hooking multiple functions such as `ip_rcv` to hide communications and open backdoors (listening and waiting to receive a magic packet for example). 

Another commonly hooked function is `sys_kill`, often used as a way to communicate with the module by assigning special actions to signal numbers, such as giving root access to the user or unhiding itself.

Some rootkits have their own framework to hook these functions (for example, `khook` for Reptile) and work by modifying the code of the hooked function to change their execution flow.

This check works by calculating the hash of the text of multiple commonly hooked function (see the list given after) at loading and regulary checking the integrity of the function.

This check doesn't work if the rootkit is already present when the module is loaded.

Checked functions (chosen by reading the code of rootkits using this method):

- `ip_rcv` (used by Reptile)
- `tcp4_seq_show` (used by Reptile)
- `sys_getdents` (used by Reptile, BDS Ftrace)
- `sys_getdents64` (used by Reptile, BDS Ftrace)
- `sys_kill` (used by Reptile)

## 3 - Syscall table entries address position

One of the privilieged ways for LKM rootkits to alter its environment is to hijack syscalls. The classic hooking method is possible (see above), but a simpler way to hook syscalls is to modify the syscall table `sys_call_table`.

This check works by getting the `sys_call_table` address, iterating over each entry, and checking for the location in the kernel of each address. If the address is located in a module, the syscall has been hijacked.

## 4 - Symbol address lookup blacklist

Created a list of symbols which are often used by rootkits (for now using only the 3 tested rootkits). 

By hooking `kallsyms_lookup_name`, we can get its argument `name` and see if it is in the list of suspicious symbols.

## 5 - Control register pinned bits

Rootkits sometimes clear bits in control registers (CR0, CR4) to grant themselves more freedom. 
A check that can be performed is to look at the bits that are commonly tampered with.
However, most of the time, these bits are often quickly set back to their original value.

The checked bits are:
- `CR0:WP` (*Write Protect*): prevents the CPU from writing to read only pages in ring 0. This bit is often cleared to write in the `.rodata` section of the kernel (for example, to edit `sys_call_table`). This is used by the Diamorphine rootkit.
- `CR4:UMIP`: blocks the usage of some instructions in user mode. Might be used by some rootkits to allow userspace programs to have more freedom.
- `CR4:SMEP` and `CR4:SMAP`: generate a fault in case of execution of code and data access to pages in userspace.

## 6 - MSR LSTAR

A way to hijack the execution flow of the kernel is to modify the LSTAR register which controls the address to jump to when a syscall is triggered.

In `syscall_init`, the LSTAR register (used in `x86_64`'s long mode) is set to the symbol `entry_SYSCALL_64`: 

```C
wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);
```

We check that the address stored in this register still corresponds to the same symbol.

## 7 - Custom hooking

Some rootkits, in order to alter the control flow of the kernel, hook on interesting functions using a custom hooking framework. These frameworks often involve setting a breakpoint (opcode `0xCC`) or a jump (opcode `0xE9`) at the beginning of the hooked function. 

This check disassembles the first instruction of chosen functions (using the in-kernel disassembler) to see if it's not a jump or a breakpoint. Therefore, we can analyze if a function has been hooked even if the checker is loaded after the rootkit.

Functions checked: 
- `ip_rcv` (used by Reptile)
- `tcp4_seq_show` (used by Reptile)

## 8 - File hiding

Most rootkits offer a way to hide files. The most common way to hide files is to hook the `getdents64` syscall (used to list a directory) and modify the returned buffer, which is an array of `struct linux_dirent64`: 

```C
struct linux_dirent64 {
    ino64_t        d_ino;    /* 64-bit inode number */
    off64_t        d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};
```

The `d_reclen` field gives the size of the current `linux_dirent64` entry and is used to jump to the following entry. 
One can hide an entry by modifying the previous entry's `d_reclen` to be the size of the hidden entry and the previous entry. 

We can detect the tampering of the returned buffer by checking that each structure has the size of its `d_reclen`. If not, the buffer has been tampered with and we can retrieve the name of the hidden file (if it wasn't overwritten). 

## 9 - Process Hiding

A very simple way of hiding processes is by hiding the `/proc/<pid>` directory for each `pid` to hide, using the technique described in (8).
Therefore, we can detect such hidden processes by the technique in (8). 

A more robust way is to iterate through the `task_struct` linked list in the kernel. 
Because a process wants to be scheduled, it must be in this list, so it is quite difficult for a rootkit to remove a process from this list and make sure it still runs.

## 10 - Write capable eBPF helper usage

Inspired by the (Aqua tracee's check)[https://aquasecurity.github.io/tracee/latest/docs/events/builtin/extra/bpf_attach/].

eBPF programms are very limited in terms of write capacity. 
They can't write directly to pointers they receive (from kernel or userspace). 
The only way they can modify user or kernel data is through a limited number of helpers: 
- `bpf_probe_write_user`: allows to write data to a user pointer
- `bpf_override_return`: allow to override the return value of a hooked function

We can detect the usage of these functions during the verifying step of the eBPF program loading process. 
We hook into `check_helper_call`, which is called for each function the verifier encounters. 
This allows us to check if a program contains helpers that are capable of modifying its environment.

## 11 - Bruteforcing the LKM address space

Inspired by this [Phrack article](https://phrack.org/issues/71/12#article). 

To hide themselves, LKM rootkits must remove themselves from 3 structures the kernel uses to keep track of modules. Some rootkits remove themselves from only one or two of these structures, and can thus be detected by performing integrity checks.

The idea is to find all kernel modules by iterating over the kernel module address space, find all the allocated spaces and try to match a `struct module` using simple heuristics about its fields. For example: 
- `name` is a null-terminated string of at most 56 characters
- `state` is a known enum
- `entry` is a pointer in the module address space
- ...

This allows us to retrieve all the LKMs in the kernel.


## 12 - Integrity check on kernel text pages 

A copy of one of the kernel text pages (~ 2 MB) is performed at rkchk's loading and is regularly compared with the current kernel's page. This allows us to find inlines hooks, the placed opcode and the hooked function. More useful for post-mortem analysis than an integrity check using the hash of the whole page.

## 13 - List the enabled probes

Inspired by a [TODO list in KoviD's repo](https://github.com/carloslack/KoviD/blob/master/TODO.txt).

When using the kernel's API to place probes in the kernel, these probes are listed in `/sys/kernel/debug/tracing/enabled_functions`. Therefore, we can see the probes that are not placed by rkchk and report them.

## 14 - Check modified sensitive files 

The main way for a userspace rootkit to hook to system libraries is to add their library to `ld.so.preload` so it is loaded before all the others. Another more discreet way is to directly modify `ld.so` such that it uses another configuration file (that's what [Bedevil](https://github.com/Error996/bdvl) does).

Therefore, to detect userspace rootkit installations, we can check the open syscall with write flag set on those files.

## 15 - Dumping stack traces

Using the kernel's stack unwinder, we dump the stack trace each time a suspicious kernel API call is made (for now, `kallsym_lookup_name` calls on suspicious symbols to detect the use of the kprobe trick). 


# Available responses

We can respond to the threats we detect.

## LKM 

The suspicious LKMs are identified by their name.
The response is equivalent to `rmmod --force <name_module>`.

## eBPF

Most eBPF programs are linked to a userspace program, so the most efficient way to unload an eBPF rootkit is to end its associated process.
The response is equivalent to `kill -9 <pid>`.

This response is also useful against suspicious processes, for example processes that were hidden by a rootkit.

# Tested and detected rootkits

## LKM Rootkits

### Diamorphine

Source: https://github.com/m0nad/Diamorphine (only worked on kernel version 6.3)

Detected: 1 / 3 / 4

### reveng_rtkit 

Source: https://github.com/reveng007/reveng_rtkit (only worked on kernel version 6.3)

Detected: 1 / 3 / 4

### Reptile (updated)

Source: https://github.com/f0rb1dd3n/Reptile

Detected: 1.1 / 2 / 7 / 11 / 12 (if loaded after rkchk)

Detected: 1.1 / 7 / 11 (if loaded before rkchk)

### KoviD

Source: https://github.com/carloslack/KoviD

Detection: 11 / 12 / 13

## Userspace rootkits 

### Bedevil 

Source: https://github.com/Error996/bdvl

Detected: 14 (if loaded before rkchk)

## eBPF rootkits

### TripleCross

Source: https://github.com/h3xduck/TripleCross

The rootkit won't load because of a failed check during the verifying process:

```
361: (07) r2 += 64                    ; R2_w=pkt(off=64,r=54,imm=0)
362: (67) r2 <<= 32
R2 pointer arithmetic with <<= operator prohibited
```

We suppose that is because the verifier became more strict since the version of the kernel the module has been made for (5.11).

### ebpfkit

Source: https://github.com/Gui774ume/ebpfkit

The rootkit won't load because of a failed check during the verifying process:

```
5401: (6b) *(u16 *)(r3 +0) = r1
R3 offset is outside of the packet
```

Same as previous.
