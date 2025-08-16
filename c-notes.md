# C Programming & Binary Analysis Notes

**Purpose:** Learning C programming fundamentals for cybersecurity research, binary analysis, and understanding memory vulnerabilities.

**Key Focus Areas:**
- Memory management and security concepts
- Binary analysis tools and techniques
- Debugging with sanitizers and debuggers
- Understanding memory vulnerabilities and exploitation

**Examples to Practice:**
- `strcpy`, `strncpy`, `malloc`, `free`
- Buffer overflows (safely in controlled environment)
- Binary analysis with `objdump`, `otool`, `nm`, `readelf`

**Learning Resources:**
- [learn-c.org](https://www.learn-c.org/en/Welcome) - Interactive C tutorials
- [Harvard CS50: C](https://cs50.harvard.edu/x/weeks/0/) - Comprehensive C programming introduction with lectures, problem sets, and hands-on practice

---

## Table of Contents

- [Binary Analysis Skills](#binary-analysis-skills)
- [Headers](#headers)
- [Format Specifiers](#format-specifiers)
- [Stack and Heap](#stack-and-heap)
- [Memory Errors](#memory-errors)
- [Out-of-Bounds Accesses](#out-of-bounds-accesses)
- [Binary File Formats](#binary-file-formats)
- [Debuggers](#debuggers)
- [Sanitizers](#sanitizers)
- [First Test Program](#how-to-write-your-first-test-program-print-hello-world)
- [Understanding Compiled Binaries](#understanding-compiled-binary-file)
- [Print Variables](#print-variables)
- [For Loop](#for-loop)
- [Arrays](#arrays)
- [Functions](#functions)
- [Data Structures](#data-structures)
- [Static Variables](#static)
- [Pointers](#pointers)
- [Structures](#structures)
- [Operators](#operators-incrementdecrement--compound-assignment)
- [Function Arguments by Reference](#function-arguments-by-reference)
- [Dynamic Memory Allocation](#dynamic-memory-allocation)
- [Recursion](#recursion)
- [Linked Lists](#linked-lists)
- [Binary Trees](#binary-trees)
- [Testing strncpy](#testing-strncpy)
- [Memory Error Examples](#error-use-after-free)

---

[learn-c.org](https://www.learn-c.org/en/Welcome)

## Binary Analysis Skills

Skill	| Why It's Important
Understanding binary sections	| .text, .data, .bss, .rodata, .got, etc.
Using objdump / otool	| To disassemble and inspect machine instructions
Using readelf / nm	| To view symbols and headers
Running gdb or lldb	| To debug and step through compiled code
Identifying vulnerabilities	| E.g., buffer overflows, [use-after-free](#error-use-after-free), etc.
Writing exploits / shellcode	| In advanced scenarios (CTFs, pentesting)

- .text Executable program code — your functions and logic
- .data Global/static variables that are initialized with non-zero values (like `int i = 5;`)
- .bss Global/static variables uninitialized or zero-initialized (like `int i;` or `static int x = 0;`)
- .rodata Read-only data, like constants or literal strings (like `"Hello world"` or `const int MAX = 100;`)
- .got Global Offset Table — addresses of external (shared library) functions

---

## Headers

```c
#include <stdio.h>    // I/O: printf, scanf, fopen
#include <stdlib.h>   // Memory: malloc, free; calloc, realloc, exit
#include <string.h>   // Strings: strcpy, strlen, strcmp, memset, memcmp
#include <ctype.h>    // Character tests: isdigit, isalpha, toupper, tolower
#include <limits.h>   // Numeric limits: INT_MAX, CHAR_BIT
#include <math.h>     // Math: sqrt, pow, sin, cos
#include <stdarg.h>   // Variadic functions handling: va_list, va_start, used for printf-style parsing
#include <time.h>     // Time: time(), clock()
#include <unistd.h>   // POSIX: fork, getpid, sleep
#include <errno.h>    // Error handling: errno
#include <assert.h>   // Debug asserts
```

---

## Format Specifiers

Specifier | Meaning	| Example
%d	| Integer	| 42
%c	| Character	| 'A'
%p	| Pointer (address)	| &vowels[i]
%s	| String	| "Hello"
%f	| Floating-point	| 3.141593
%.2f	| Float, 2 decimals	| 3.14

---

## Stack and heap:
- Stack grows downward (high memory address → low memory). Allocated by compiler and automatically freed after function ends
- Heap grows upward (low memory address → high memory). Allocated by programmer and need to be manually freed (malloc, free)
- They can **grow toward each other** in the same memory space
- It keeps them from overlapping too early
- Heap is slow (more flexible), can be accessed from anywhere and stack is fast (CPU-managed), usually accessed from top only

Visual Stack (in your head)	| Memory Stack (in hardware)
Grows upward (you add to the top)	| Grows downward in memory addresses
Plate on top = newest data	| Lowest address = newest data
Plates below = older data	| Higher address = older data
Bottom plate = oldest	 | Top of memory = base of the stack

Memory addresses count upward, and the CPU stack moves downward when pushing

Read [Sanitizers](#sanitizers) for how to detect memory errors.

---

## Memory errors

Memory errors can cause crashes (segmentation faults), data corruption, security vulnerabilities (like code injection). Types include:
- Out-of-bounds accesses to heap, stack and globals 
  - Buffer Overflow: Writing 10 bytes to a `char[8]`
  - Buffer Underflow: Accessing `arr[-1]`
- Use-After-Scope
- Use-After-Free: Using a pointer after `free()`
- Dangling Pointer: Can arise from use-after-free or use-after-scope.
- Double Free: `free(ptr); free(ptr);`
- Memory Leak: `malloc()` with no `free()`
- Invalid Free: free a pointer not from `malloc()`, such as stack variable or already freed pointer
- Null Pointer Dereference: Accessing memory via a NULL pointer (`int *p = NULL; *p = 5;`). OS does not map address `0x0` in user space. OS generally maps it as an invalid address - causes segmentation fault.

A segmentation fault (`segfault`) is a type of error that occurs at runtime when a computer program attempts to access an illegal (not allowed to access) memory region. Causes include: Null Pointer Dereference, accessing an invalid memory address, buffer overflows, trying to write to read-only memory

---

## Out-of-Bounds Accesses

Out-of-bounds accesses an overwrite other variables, return address (→ leads to code execution), function pointers, stack or heap metadata. 

Types based on Location of Memory:
- Stack Overflow: Writing past a buffer on the stack
- Heap Overflow: Writing past a buffer on the heap (allocated with `malloc`)
- Global/Data Segment Overflow: Overflowing global/static arrays

Types based on Direction of corruption:
- Overflow (Overrun): Writing beyond the end of the buffer
- Underflow (Underrun): Writing before the start of the buffer

Types based on Target of the Overwrite:
- Return Address (Stack): Gain control of execution (classic exploit)
- Function Pointer / VTable: Hijack object-oriented calls
- Heap Metadata (e.g., malloc chunks): Heap exploitation
- Global Vars / Flags: Change logic or bypass auth

Security Impact:
- Denial of Service (crash the app)
- Privilege Escalation
- Remote Code Execution
- Data Leakage/ Information Disclosure (passwords, keys, etc)

---

## Binary file formats (for executables, libraries, kernel modules)

1. Mach-O (Mach Object)  — common on macOS systems.
2. ELF (Executable and Linkable Format) is standard binary format used on Linux & Unix-like systems (like FreeBSD, Solaris)

Task/ Concept	| Linux (ELF)	| macOS (Mach-O) | Notes
Disassembly	| `objdump -d` | `otool -tvVq` | Look at `__text` section (code), use `-s __TEXT __stubs` to see stubs
Headers	| `readelf -h`, `readelf -l`	| `otool -h`, `otool -l` | filetype, flags, PIE/ASLR, `LC_MAIN`, segments
Entry Point | `readelf -h`, `objdump`	| `otool -l` | Look at `LC_MAIN → entryoff`
Symbol table	| `nm`	| `nm`, `otool -Iv` | `_main`, `_printf`, etc. — T = text, U = undefined
Dynamic Linking	| readelf -d, ldd	| otool -l	| LC_LOAD_DYLIB, __stubs, __got
Linked Libraries	| ldd	| otool -L, otool -l	| Check which `.dylib` files are used
Binary Info	| file	| file, lipo	| ELF or Mach-O, 32/64-bit, architecture. lipo (for universal/fat binaries)
Strings in Binary	| strings	| strings, otool -s __TEXT __cstring	| Look for literals like `"Hello World!"`
Raw Hex View	| hexdump -C	| hexdump -C	| Inspect byte layout
Debugger	| gdb	| lldb	| For runtime inspection and breakpoints
Advanced RE	| radare2, ghidra, IDA	| radare2, ghidra, IDA	| Full binary reverse engineering

Linker	| ld	| ld (Apple’s version)

However:
* Apple's `ld` is not the same as GNU `ld`. It’s quite different and tuned for Mach-O.
* `readelf` has no direct exact equivalent, but `otool -h` and `otool -l` are the closest.
* `objdump` on macOS works, but it's limited for Mach-O binaries and more raw. Use `otool` instead for Mach-O.
* `otool` can read segments, symbols, disassemble, show headers

More on `strings`, `file`, `obbjdump`/ `otool`, `nm` [here](#understanding-compiled-binary-file)

---

## Debuggers

Debuggers like `lldb`, `gdb` are manual inspection tools. They do not detect memory errors automatically. Check [sanitizers](#sanitizers) for more on automated compiler instrumented inspection.

LLDB Command	| Purpose
disassemble	| Show assembly (Shows how C code becomes CPU instructions)
register read	| Show CPU registers like %rdi, %rbp, %rax
memory read --format x --size 4 --count 4 $rsp	| Read memory at stack
frame variable	| Show variables in current frame (only if they exist)
stepi or si	| Step 1 instruction
next or n	| Step over (skip into calls)
breakpoint list	| Show active breakpoints

Check `lldb` usage [here](#print-variables)

---

## Sanitizers

Sanitizers are automated runtime instrumentation tools provided by compilers like `clang` or `gcc`. They insert additional instrumentation code into the binary during compilation to **detect and report bugs** at runtime — such as memory errors (e.g., buffer overflows, use-after-free), undefined behavior, memory leaks, thread race conditions, and more.

With sanitizers, the compiler instruments your program with additional runtime checks, such as validating memory accesses and object lifetimes. Without sanitizers, debuggers like `lldb` or `gdb` only see CPU instructions and do not automatically detect memory errors like writing to an out-of-bounds index (`p[-1] = 'Z'`). `lldb` and `gdb` are manual debugging tools not memory error detectors. 

Clang supports several sanitizers, including:
- AddressSanitizer (ASan): `-fsanitize=address` — detects memory errors like buffer overflows and use-after-free.
- UndefinedBehaviorSanitizer (UBSan): `-fsanitize=undefined` — catches undefined behavior (e.g., signed integer overflow, bad casts).
- ThreadSanitizer (TSan): `-fsanitize=thread` — detects data races in multithreaded programs.
- LeakSanitizer: detects memory leaks; enabled by default with ASan, or standalone via `-fsanitize=leak`.
- MemorySanitizer (MSan): detects uninitialized memory reads (Linux-only).
- DataFlowSanitizer (DFSan): experimental taint tracking.
- TypeSanitizer / RealtimeSanitizer: less commonly used; for detecting type confusion or real-time issues.

Note: 
- Combine sanitizers for better coverage: `clang -fsanitize=address,undefined -g prog.c -o prog`
- On Linux, `valgrind ./prog` can detect memory leaks, invalid frees, and some buffer overruns. However, `valgrind` is much slower than sanitizers and does not detect uninitialized memory reads as precisely as MSan (Linux-only).

Check usage [here](#error-use-after-free). 
Check types of memory errors [here](#memory-errors).
Read more on specific sanitizer [here](https://clang.llvm.org/docs/index.html)

---

## How to Write Your First Test Program: Print "Hello, world!"

1. Create a file with vim:
```bash
vim prog.c
```

```c
#include <stdio.h> // for print()

int main() {
    printf("Hello, world!\n");
    return 0;
}
```
Save and exit (in vim `:wq`)

2. Compile It with `gcc` or `clang`

```bash
gcc prog.c -o prog
```

This tells GCC:
* Compile `prog.c`
* Output a binary named `prog`

MacOS comes with `clang` by default. When you run above command, you're actually using `clang`, not the original GNU GCC. Apple just keeps the command name gcc for compatibility, but under the hood, it's Clang.

`gcc --version`
Output:
Apple clang version 17.0.0 (clang-1700.0.13.5)

OR

```bash
gcc -g prog.c -o prog
```

* `-g` includes debug symbols
* So tools like `gdb`, `lldb`, and `Valgrind` can understand variable names, line numbers, etc.
* Required for stepping through code and seeing C-level info during debugging
🔍 If you don’t add `-g`, debuggers only see raw memory addresses — no variable names or line numbers.

OR

```bash
gcc -Wall -Wextra -g prog.c -o prog
```

* -Wall -Wextra → shows helpful warnings
* -g → includes debug symbols (for gdb or valgrind)

3. Run It using `./prog`

Output:
Hello, world!

---

## Understanding compiled binary file

### Exploring Binaries: `strings`, `file`, `hexdump`, `nm`

```bash
strings prog          # Find "Hello, world!"
# Output:
Hello World!

file prog             # ELF or Mach-O? 32 or 64 bit?
# Output:
prog: Mach-O 64-bit executable x86_64

hexdump -C prog       # See the binary structure, Canonical hex+ASCII display
# Output: binary data

nm prog               # Function names (like main, printf)
# Output:
0000000100000000 T __mh_execute_header
0000000100000470 T _main  # Program defines a main() function
                 U _printf # Symbol is undefined in the binary; it will be resolved at runtime by the dynamic linker (e.g., from /usr/lib/libSystem.B.dylib)

# T stands for text(code) section; U for undefined.
```

### Disassembling: `otool -tvVq`, `objdump -d`, `__text`, `__stubs`

`otool -tvVq` only disassembles the `__TEXT,__text` section by default. This includes the actual code like `_main`, but not the stub table (`__stubs`). To explicitly disassemble the __stubs section using otool: `otool -tvV -s __TEXT __stubs prog`

`-t` = Disassemble `__TEXT,__text` section; 
`-v` = Verbose (with symbol names if available)
`-V` = Show addresses in the disassembly
`-q` or `-Q` = Choose LLVM (default) or classic disassembler (optional)
`-s __TEXT __stubs`: Selects the exact section to disassemble (`__stubs` inside `__TEXT` segment)

`objdump -d` disassembles all executable sections by default.

```bash
otool -tvVq prog     # object file displaying tool (Disassemble and inspect machine instructions)

# Output: 
prog:
(__TEXT,__text) section
_main:
0000000100000470	pushq	%rbp
0000000100000471	movq	%rsp, %rbp
0000000100000474	subq	$0x10, %rsp
0000000100000478	movl	$0x0, -0x4(%rbp)
000000010000047f	leaq	0x16(%rip), %rdi    ## literal pool for: "Hello World!\n"
0000000100000486	movb	$0x0, %al
0000000100000488	callq	0x100000496         ## symbol stub for: _printf
000000010000048d	xorl	%eax, %eax
000000010000048f	addq	$0x10, %rsp
0000000100000493	popq	%rbp
0000000100000494	retq
```

> Note: ## comment above is from the output. # this is my comment.

<details>

### Registers & Instruction Set Reference

Register	| Bits | Role
%rsp (Stack Pointer)	| 64-bit | Points to the top of the stack | 
%rbp (Base Pointer / Frame Pointer)	| 64-bit | Points to the bottom of the current function's frame | 
%rip (Instruction Pointer) | 64-bit |Points to current instruction (i.e., where you are in the code)
%rdi (Register destination index)	| 64-bit | Holds the 1st argument for functions like printf (i.e., first "inbox/ register" for arguments when assigned a task)
%rax (General purpose) |  64-bit | The full Accumulator Register- Holds data like return values
%eax (Extended %ax register) | 32-bit | Lower 32 bits of %rax
%ax (old/ original Accumulator register) | 16-bit | Lower 16 bits of %rax
%al (low byte of %ax) | 8-bit |Lowest byte (bits 0–7) of %rax

%rax, %rsp, %rbp, %rdi, %rsi, %rdx, etc. are all 64-bit registers on a 64-bit system (like macOS using x86_64 architecture)— all hold 64-bit values (i.e., 8 bytes). These registers don’t store blocks of memory — they store a 64-bit address that points to memory.

%rdi is the first function argument. %rsi is the second argument. 3rd is %rdx. 4th is %rcx. 5th is %r8. 6th is %r9. If there are more than 6 arguments, the rest go on the stack (via %rsp).

> Note: %rdi holds the first argument to functions (on x86_64). Its name historically comes from “Destination Index” used in string operations, but that’s unrelated to function calls now.

Suffix	| Stands for	| Meaning
q	| quadword	| 64-bit (4x2 = 8 bytes)	
l	| longword	| 32-bit (4 bytes)	
w	| word	| 16-bit (2 bytes)	
b	| byte	| 8-bit (1 byte)	

So:
movq = move a 64-bit value
movl = move a 32-bit value
movb = move an 8-bit value

**Disassembly of main function**

This is the machine instructions your computer runs, turned back into readable assembly language.
These lines are what your C program main() becomes:

Step	| Assembly	| Meaning
1. Save old frame	| pushq %rbp	| Save the previous base pointer
2. New stack frame	| movq %rsp, %rbp	| Start the current function’s frame (copy the stack pointer into the base pointer)
3. Reserve memory	| subq $0x10, %rsp	| Allocate 16 bytes for local vars
4. Initialize var	| movl $0x0, -0x4(%rbp)	| Store 0 in a local variable
5. Load string	| leaq 0x16(%rip), %rdi	| Load string address into 1st arg
6. Prep function call	| movb $0x0, %al	| Sets "no floats" args for printf
7. Call function	| callq _printf	| Call printf using stub
8. Set return value	| xorl %eax, %eax	| Return 0 (success)
9. Clean up	| addq $0x10, %rsp	| Free local stack space (add 16 bytes to %rsp- undo subq)
10. Restore frame	| popq %rbp	| Restore old frame pointer
11. Exit	| retq	| Return to OS / caller

Note:
- subq → subtract 16 from the stack pointer → moving the stack "down" to allocate space for local variables. The stack grows downward in memory (from high to low), so subtracting increases its size.
- movl → Store the value 0 in a local variable at the location `rbp - 4` - `int x = 0;` in C
- leaq → Load Effective Address of the string `"Hello World!\n"` into %rdi (Register Destination Index - Historical name). 

`leaq 0x16(%rip), %rdi` means: Compute the address of %rip + 22 bytes, and store that address into %rdi

LEA doesn't load a value, it loads the memory address and points to a string in `__cstring`
`%rdi` holds first argument for a function like `printf` (on x86_64).
CPU says: “Let me grab the string’s address using `leaq`, put it in `%rdi`, and call `printf()` with that argument.”

- movb $0x0, %al → Sets the %al register to 0. This is used by `printf` to tell if there are floating point arguments. $0x0 = false (no float args)

- callq _printf → `callq` jumps into a stub function (`__stubs`) at address `0x100000496`, which will resolve and call `printf()` at runtime.
The stub is just a trampoline — it jumps to the **real `printf()`**, which lives in a system library (like `/usr/lib/libSystem.B.dylib`). This is how dynamic libraries work.

- xorl %eax, %eax → XOR %eax with itself = sets %eax to 0. %eax is used to return 0 from main() (success)
</details> <br>

```bash
objdump -d prog   # object file displaying tool (Disassemble and inspect machine instructions)
# Output:
prof:	file format mach-o 64-bit x86-64
Disassembly of section __TEXT,__text:
...

Disassembly of section __TEXT,__stubs:

0000000100000496 <__stubs>:
100000496: ff 25 64 0b 00 00           	jmpq	*0xb64(%rip)            ## 0x100001000 <_printf+0x100001000>
```

> Note: ## comment above is from the output. # this is my comment.

Explanation: Stub Section

"stub" `jmpq *0xb64(%rip)` a placeholder for the real `printf` function, jumps to `GOT` entry for `_printf`. Since the function `printf()` lives outside the binary file, in a shared library, the actual function is found at runtime, through dynamic linking from system library (like `/usr/lib/libSystem.B.dylib`).

Security: These are where you can hook or trace function calls. Because the call goes through this stub, you can log it, redirect it to your own function, modify arguments. You might replace them during binary patching or instrumentation (modify to jump elsewhere)

### Mach-O Header: `otool -h`, filetype, flags

```bash
otool -h prog
# Output:
prog:
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
 0xfeedfacf 16777223          3  0x00           2    16       1040 0x00200085
```

### Load Commands/ Segment layout: `LC_SEGMENT_64`, `LC_MAIN`, `LC_LOAD_DYLIB`, etc.

```bash
otool -l prog
# Output:
prog:
Load command 0
      cmd LC_SEGMENT_64 # LC_SEGMENT_64 describes a 64-bit segment, including its sections
  cmdsize 72
  segname __PAGEZERO... # Reserved memory at 0x0 (very beginning of virtual memory) - prevents NULL bugs
Load command 1
      cmd LC_SEGMENT_64...
  segname __TEXT... # Program’s instructions (actual code, stubs, constant strings, etc.)
   nsects 4... # contains __text, __stubs, __cstring, __unwind_info
Section
  sectname __text # Machine instructions (main() function)
   segname __TEXT...
Section
  sectname __stubs # Tiny jump instructions used for indirect calls to dylibs (external functions like printf)
   segname __TEXT... 
 reserved1 0 (index into indirect symbol table)
 reserved2 6 (size of stubs)
Section
  sectname __cstring # Literal strings like "Hello World!\n"
   segname __TEXT...
Section
  sectname __unwind_info # Info used for error handling (like stack unwinding for exceptions)
   segname __TEXT...
Load command 2
      cmd LC_SEGMENT_64...
  segname __DATA_CONST... # Read-only data used for linking, like the GOT
   nsects 1... # contains __got
Section
  sectname __got # Global Offset Table — actual runtime addresses of linked functions (like printf)
   segname __DATA_CONST...
 reserved1 1 (index into indirect symbol table)
 reserved2 0
Load command 3
      cmd LC_SEGMENT_64... # Contains metadata for dynamic linking
  segname __LINKEDIT... # holds metadata, not actual code (for the linker and debugger)

# Load Commands 4–15: support commands
Load command 4
      cmd LC_DYLD_CHAINED_FIXUPS... # Used for address patching at load time (optimized way for dyld to fix pointers)
Load command 5
      cmd LC_DYLD_EXPORTS_TRIE... # Lists which symbols (functions) the binary exports
Load command 6
     cmd LC_SYMTAB # Symbol table: names of functions, variables, etc.
 cmdsize 24
  symoff 8344
   nsyms 12
  stroff 8544
 strsize 152
Load command 7
            cmd LC_DYSYMTAB # Dynamic symbol table: extra info for linker/debugger
        cmdsize 80
      ilocalsym 0
      nlocalsym 9
     iextdefsym 9
     nextdefsym 2
      iundefsym 11
      nundefsym 1
         tocoff 0
           ntoc 0
      modtaboff 0
        nmodtab 0
   extrefsymoff 0
    nextrefsyms 0
 indirectsymoff 8536
  nindirectsyms 2
      extreloff 0
        nextrel 0
      locreloff 0
        nlocrel 0
Load command 8
          cmd LC_LOAD_DYLINKER... # Tells the OS which dynamic linker to use to load the program
         name /usr/lib/dyld (offset 12) # dynamic linker to use
Load command 9
     cmd LC_UUID... # Unique identifier for the binary (like a fingerprint)
    uuid 00X0X0X0-0XX0-0XX0-0XX0-0X0XXX0000X0 # 128-bit uuid (for debugging symbols or crash reporting)
Load command 10
      cmd LC_BUILD_VERSION... # OS version + SDK (Software Development Kit) used to compile the binary
      sdk 11.1...
  version 1111.1
Load command 11
      cmd LC_SOURCE_VERSION...
Load command 12
       cmd LC_MAIN... # Entry point offset
  entryoff 1111... # byte offset in __TEXT segment where execution starts (typically _main or _start)
Load command 13
          cmd LC_LOAD_DYLIB... # Dynamically load /usr/lib/libSystem.B.dylib (which includes printf, etc.). stub links to functions found in these shared libraries.
         name /usr/lib/libSystem.B.dylib (offset 24)...
Load command 14
      cmd LC_FUNCTION_STARTS... # Info for profiling, debugging, and stack unwinding
Load command 15
      cmd LC_DATA_IN_CODE... # Marks embedded data in code (e.g., jump tables)
```      

Note:

LC_MAIN's `entryoff` is critical for:
- Understanding execution flow
- Hooking or modifying entry points in malware analysis or exploits

---

## Print variables

```c
#include <stdio.h> // for print()

int main() {
    int x = 123;
    int y = 456;
    printf("x = %d, y = %d\n", x, y);
    return 0;
}
```

Compile & run:

```bash
gcc -g prog.c -o prog
lldb ./prog     # Low level debugger: Step through execution

(lldb) target create "./prog"
Current executable set to '.../prog' (x86_64).

(lldb) break set --name main
Breakpoint 1: where = prog`main...

(lldb) run
...
   3   	int main() {
-> 4   	    int x = 42;
   5   	    int y = 123;
   6   	
   7   	    printf("x = %d, y = %d\n", x, y);...

(lldb) frame variable
(int) x = 1580630760
(int) y = 32760
```
Here the code hit a breakpoint at line 4. Line 4 and 5 is not yet executed and hence displays garbage value

```bash 
(lldb) step
...
   4   	    int x = 42;
-> 5   	    int y = 123;
   6   	
   7   	    printf("x = %d, y = %d\n", x, y);...

(lldb) step
...  	
-> 7   	    printf("x = %d, y = %d\n", x, y);...

(lldb) frame variable
(int) x = 42
(int) y = 123
```

This displays correct value.

<details>
`break set --name main`
- `break` A command in `lldb` to manage breakpoints
- `set` subcommand to actually create (set a breakpoint)
- `—name main` tells `lldb` to find a function called main an pause when it starts
</details>

Note: Use breakpoints to jump to a specific line: `(lldb) breakpoint set --file file.c --line 7`

---

## For loop

for (initialization; condition; increment) 
- Initialization: runs once at the beginning → i = 0
- Condition: checked before every iteration → i < 2
- Loop Body: if condition is true, body runs
- Increment: runs after the body → i++ or ++i

Check difference between Post-increment vs Compound-assignment operators [here](#operators-post-increment-vs-compound-assignment)

---

## Arrays

```c
#include <stdio.h>

int main() {
  int grades[3];  // array to store 3 grades

  grades[0] = 80;
  grades[1] = 85;
  grades[2] = 90;

  int average = (grades[0] + grades[1] + grades[2]) / 3;
  printf("The average of the 3 grades is: %d", average);

  return 0;
}
```

Output:
The average of the 3 grades is: 85

---

## Multidimensional Arrays

```c
#include <stdio.h>

int main() {
  int grades[2][5]; // 2 dimensional array of grades
	float average;
	int i;
	int j;

	grades[0][0] = 80;
	grades[0][1] = 70;
	grades[0][2] = 65;
	grades[0][3] = 89;
	grades[0][4] = 90;

	grades[1][0] = 85;
	grades[1][1] = 80;
	grades[1][2] = 80;
	grades[1][3] = 82;
	grades[1][4] = 87;

	Calculate average
  for (i = 0; i < 2; i++) {
	  average = 0;
		for (j = 0; j < 5; j++) {
			average += grades[i][j];
		}
    average = average/5;
		printf("The average marks obtained in subject %d is: %.2f\n", i, average);
	}
		return 0;
	}
```

Output:
The average marks obtained in subject 0 is: 78.80
The average marks obtained in subject 1 is: 82.80

Note: Multidimentional array can also be  wriiten as
```c
int grades[2][5] = {
  {80, 70, 65, 89, 90},
  {85, 80, 80, 82, 87}
};
```
Or simply `int grades[2][5] = {80, 70, 65, 89, 90, 85, 80, 80, 82, 87};`

---

## Functions

Named, reusable blocks of code.

In C, all function arguments are passed by value — including pointers.
- If you pass a variable, a **copy of its value** is passed. You can't change the original variable from the caller.
- If you pass a pointer, a **copy of the pointer** is passed. The function can modify the data it points to, but not reassign the original pointer in the caller.
- If you pass a **pointer to pointer**, a copy of original pointer's address is passed. This allows the function to modify the pointer in the caller - change what the pointer points to.

### Define a Function called `print_big` to print `x is big` when `x > 10`

```c
#include <stdio.h>

// Define Function print_big
void print_big(int number) {
    if (number > 10) {
        printf("%d is big\n", number);
    }
}   

int main() {
  int array[] = { 1, 11, 2, 22, 3, 33 };
  for (int i = 0; i < 6; i++) {
    print_big(array[i]);
  }
  return 0;
}
```

Output:
11 is big
22 is big
33 is big

---

## Data Structures

A data structure is a general concept in computer science. It's a way of organizing and storing data in memory so it can be accessed, organised and modified efficiently.

Common data structures:
- Array
- Linked List
- Stack
- Queue
- Tree
- Hash Table
- Graph

---

## static

`static` is a keyword in the C programming language. It can be used with variables and functions.

Declaring a variable as `static` means:
- It is initialized only once — when the function is first called.
- Its value is preserved between function calls.
- It has function scope but lives in static memory, not the stack.

By default, variables are local to the scope in which they are defined. Variables can be declared as `static` to increase their scope up to file containing them. As a result, these variables can be accessed anywhere inside a file.

```c
#include <stdio.h> // for print()

// Function to find sum of n numbers
int sum (int num) {
   static int sum = 0; //initialized only once when function is called
   sum += num;
   return sum;
}

int main() {
   printf("%d ",sum(55));
   printf("%d ",sum(45));
   printf("%d ",sum(50));
   return 0;
}
```

Output:
55 100 150

> Note: Without static, `int sum = 0;` would return the output: 55 45 50

---

Above code in Python:
```py
def sum(num):
  if not hasattr(sum,"total"):
    sum.total=0 #initialize once
  sum.total+=num
  return sum.total

print(sum(55))
print(sum(45))
print(sum(50))
```

`hasattr()` checks if the function already has an attribute `total`

---

## Pointers

Pointers are variables that stores a memory address. They are used for several reasons, such as:

- Strings
- Dynamic memory allocation
- Sending function arguments by reference
- Building complicated data structures
- Pointing to functions
- Building special data structures (i.e. Tree, Tries, etc...)

```c
#include <stdio.h> // for printf

int main() {
  int n = 10;
// adding pointer to n
int *pointer_to_n = &n; // pointer_to_n stores address of n (&n)
int **p_to_p = &pointer_to_n; // pointer to pointer_to_n

  printf("n = %d, address of n (&n) = %p\n",n, &n);
  printf("pointer_to_n = %p, *pointer_to_n = %d\n", pointer_to_n, *pointer_to_n);
  printf("address of pointer_to_n = %p\n", &pointer_to_n);

  *pointer_to_n += 1; // dereference pointer (n) and add 1

  printf("n = %d, address of n (&n) = %p\n",n, &n);
  printf("pointer_to_n = %p, *pointer_to_n = %d\n", pointer_to_n, *pointer_to_n);
  printf("p_to_p (address of pointer_to_n) = %p\n", p_to_p);
  printf("*p_to_p (value of pointer_to_n) = %p\n", *p_to_p);
  printf("**p_to_p (value of n) = %d\n", **p_to_p);
  return 0;
}
```

Output:
n = 10, address of n (&n) = 0x7ff7b557a3b8
pointer_to_n = 0x7ff7b557a3b8, *pointer_to_n = 10
address of pointer_to_n = 0x7ff7b557a3b0
n = 11, address of n (&n) = 0x7ff7b557a3b8
pointer_to_n = 0x7ff7b557a3b8, *pointer_to_n = 11
p_to_p (address of pointer_to_n) = 0x7ff7b28983b0
*p_to_p (value of pointer_to_n) = 0x7ff7b28983b8
**p_to_p (value of n) = 11

Note:
- `n`: integer variable, type `int`
- `&n`: memory address of n, type `int *`
- `pointer_to_n`: pointer variable that stores `address of n` (so `pointer_to_n` = `&n`). Type `int *`
- `*pointer_to_n`: dereferencing the pointer — this gives you the value stored at the memory address it points to (n).
- `p_to_p`: pointer to pointer variable that stores `address of pointer_to_n` (so `p_to_p` = `&pointer_to_n`). Type `int **`
- `*p_to_p`: dereferencing the pointer  — this gives you the value stored at the memory address it points to (pointer_to_n -> which inturn points to address of n).

---

## Structures

A structure (struct) in C is a user-defined data type that groups different variables under one name. Structures are the basic foundation for objects and classes in C. Structures are used for:

- Serialization of data
- Passing multiple arguments in and out of functions through a single argument
- Data structures such as linked lists, binary trees, and more

### Defining struct without typedef:

```c
#include <stdio.h> // for printf

struct person { //assign struct a name, 'person'
  char *name;   // string (pointer to char)
  int age;
};

int main() {
  struct person john;   // Declare a variable 'john' of type 'struct person'
  john.name = "John";   // assign name
  john.age = 27;        // assign age
  printf("%s is %d years old.\n", john.name, john.age);
}
```

### Define struct using typedef syntax:

```c
#include <stdio.h> // for printf

// define a struct 'person' using the typedef syntax
typedef struct {
  char *name;  // string (pointer to char)
  int age;
} person;       // 'person' is now an alias for the anonymous struct (data type)

int main() {
  // create a struct variable 'john'
  person john; // declares a variable 'john' of type 'person' (alias for struct)
  john.name = "John";
  john.age = 27;
  printf("%s is %d years old.\n", john.name, john.age);
}
```

Output: John is 27 years old.

Note: 
- `typedef` signals to the compiler that you are defining a new type alias. 
- typedef syntax: `typedef existing_type new_name;`
- struct definition should end with `;` after closing brace.
- `char *name;` is a pointer to a character, used to store a string.

---

## Operators: increment/decrement & compound assignment

**Increment and Decrement**
Syntax | Meaning | Notes
------|-----------------|-------
`x++`	| Post-increment | Returns original value, then increments x
`++x`	| Pre-increment	| Increments x, returns new value
`x--`	| Post-decrement | Returns original value, then decrements x
`--x`	| Pre-decrement	| Decrements x, returns new value

These are often used in loops and pointer arithmetic: 
```c
*ptr++   // use ptr, then move to next element
++*ptr   // increment the value *ptr points to
```
**Compound Assignment Operators**
Syntax | Equivalent to | Meaning
---------|-------------|---------
`x += y` | `x = x + y` | Addition assignment
`x &= y` | `x = x & y` | Bitwise AND assignment
`x ^= y` | `x = x ^ y` | Bitwise XOR assignment
`x <<= y`	| `x = x << y` | Left shift assignment
`x >>= y`	| `x = x >> y` | Right shift assignment

- These operators are evaluated left to right, and return the updated value, so:
```c
int a = 5;
int b = (a += 2); // a becomes 7, b gets 7
```

- `+=`, `-=`, `*=`, `/=`, `%=` work similarly
- `&=` is a bitwise AND assignment operator.`|=` is a bitwise OR assignment operator. `^=` is bitwise XOR assignment operator. `~x` is bitwise NOT operator. 
```c
int x = 5;    // binary: 0101
int y = 3;    // binary: 0011

int a = x & y;   // 0001 = 1 (bitwise AND)
int b = x | y;   // 0111 = 7 (bitwise OR)
int c = x ^ y;   // 0110 = 6 (bitwise XOR)
int d = ~x;      // 0b11111010 in 8-bit = -6 in 2's complement (bitwise NOT)
```
- Binary (`0b`) and Hexadecimal (`0x`) Literals: In C, you can express integers using their binary or hexadecimal(digits 0-F) representations by prefixing them with `0b` or `0x`
- A full 32-bit signed integer stores the value of `x = 5` as: `00000000 00000000 00000000 00000101` decimal number 5. The `~`operator flips every bit (1's complement): `11111111 11111111 11111111 11111010`. This is not interpreted as a large positive number — it's interpreted as a negative number in two's complement representation. To get the decimal value (2's complement) invert it back and add 1: `00000000 00000000 00000000 00000110` which is 6. So the original value `11111111 11111111 11111111 11111010` is -6.
- **Two’s complement** is how negative numbers are stored in binary on modern systems. In two’s complement, to get the negative of a number: invert all bits (1's complement) and add 1
```
    5   = 00000101
  - 3   = 11111101  ← this is two’s complement of 3

Add them:
  00000101
+ 11111101
-----------
  00000010   ← result is 2
```
- Positive and negative integers are differentiated using the most significant bit (**MSB**) — also known as the `sign bit`. If the MSB is 0, the number is positive. If the MSB is 1, the number is negative.

- Left shift assignment operator, `x <<= y` shifts the bits of x left by y positions. `x >>= y` shifts bits of x right by y positions

### Logical Operators (&&, ||, !)
Work with true/false (non-zero is true, 0 is false)

Check examples [here](#example-for-operator-difference)

---

## Function arguments by reference

Function arguments are passed by value, which means they are copied in and out of functions. But what if we pass pointers to values instead of the values themselves? This will allow us to give functions control over the variables and structures of the parent functions and not just a copy of them, thus directly reading and writing the original object.

### Function called birthday, which adds one to the age of a person.

```c
#include <stdio.h> // for printf

// Define a new data type 'person' using an anonymous struct
typedef struct {
  char *name;
  int age;
} person;

// function declaration: birthday takes a pointer to a person and no return (void)
void birthday(person * p);

// function definition: increases the age of the person by 1
void birthday(person * p) {
  (*p).age++; // increment age using the pointer (equivalent to p->age++)
}

int main() {

  person john;  // create a struct variable named 'john'

  john.name = "John";
  john.age = 27;

  printf("%s is %d years old.\n", john.name, john.age);
  birthday(&john);    // call function with address of john
  printf("Happy birthday! %s is now %d years old.\n", john.name, john.age);

  return 0;
}
```

Output: John is 27 years old.
Happy birthday! John is now 28 years old.

Note: person *p = &john; --> p points to john
```c
(*p).age++;
john.age++;
p->age++; //shortcut for (*p).age++;
(*p).age += 1;
john.age += 1;
```
All the above mean increment john's age by 1

---

### Example for operator difference

int a = (*p).age++;     // a gets the old value, age increases after
int b = (*p).age += 1;  // b gets the new value after addition
The above applies to (*p).age++ and (*p).age+=1 as well

### `john.age++` vs `john.age+=1`

```c
int main() {
  person john;

  john.name = "John";
  john.age = 27;

  int a = john.age++;
  printf("a is %d\n",a);
  printf("%s is now %d years old.\n", john.name, john.age);

  int b = john.age+=1;
  printf("b is %d\n",b);
  printf("%s is now %d years old.\n", john.name, john.age);
  return 0;
}
```

Output:
a is 27
John is now 28 years old.
b is 29
John is now 29 years old.

---

## Dynamic Memory Allocation

### Use malloc to dynamically allocate a point structure.

```c
#include <stdio.h> // for printf
#include <stdlib.h> // for malloc, free

typedef struct {
  int x;
  int y;
} point; // 'point' is now an alias for the anonymous struct (data type)

int main() {

  // Dynamically allocate 'point' struct which 'mypoint' points to
point *mypoint = malloc (sizeof(point));  // Allocate memory for 1 point

  mypoint->x = 10;  // add value 10 to x at pointer 'mypoint' (equivalent to (*mypoint).x = 10)
  mypoint->y = 5;   // add value 10 to y at pointer 'mypoint' (equivalent to (*mypoint).y = 5)
  printf("mypoint coordinates: %d, %d\n", mypoint->x, mypoint->y);

  free(mypoint);  // free dynamically allocated memory
  return 0;
}
```

Note:
- `malloc()` allocates dynamic memory on the heap. You must `free()` the memory to avoid [memory leaks](#memory-leak).
- `malloc ()` returns `void *` (void pointer). `void *` is a generic pointer that can point to any type. 
- In C, a `void *` can be implicitly converted to any other object pointer type without the need for an explicit cast (such as `(pointer *) malloc (sizeof(point))` to match the type of `mypoint`). In C++, the rules are different, and an explicit cast is required when using malloc().

### malloc vs calloc

`malloc(n * size)`: Allocates a block of memory of `n * size` bytes. The contents of the memory are uninitialized (i.e., may contain garbage). This is slightly faster as it skips the zeroing.

`calloc(n, size)`: Also allocates `n * size` bytes. Zero-initializes all the **memory** (sets all bytes to 0). This prevents bugs from garbage values.

```c
int *a = malloc(5 * sizeof(int));   // allocate memory for 5 integers
int *a = calloc(5, sizeof(int));    // same size, but zero-initialized
```

Note:
- malloc expects total size.
- calloc separates the logic: "how many?" and "how big?"

Check notes [here](#linked-lists) for more info

---

In C:
You can use pointers to directly modify memory — even integers or characters.

```c
int a = 10;
int *p = &a;
*p = 42;  // a is now 42
```

In Python:
- You cannot use pointers like in C.
- You cannot directly modify immutable types (like integers, strings, tuples). It protects memory from low-level access.
- Python doesn’t expose memory addresses or allow pointer manipulation (unless using special modules like ctypes or id() in inspection).

Concept	| Summary
C is pass-by-value	| Use pointers to modify originals
Python passes references	| But immutables act like pass-by-value

---

## Dynamic Memory Allocation for Arrays

### 1D array

Use case: Single string or flat character buffer ([ 'A' ][ 'E' ][ 'I' ][ 'O' ][ 'U' ])

Memory layout: one block of memory

```c
#include <stdio.h>
#include <stdlib.h>

// Allocate memory to store five characters
int main () {
  int n = 5;
  char *pvowels = malloc(n * sizeof(char));
  int i;

  pvowels[0] = 'A';
  pvowels[1] = 'E';
  *(pvowels + 2) = 'I';
  pvowels[3] = 'O';
  *(pvowels + 4) = 'U';

  for (i = 0; i < n; i++) {
      printf("%c ", pvowels[i]);
  }

  printf("\n");

  free(pvowels);
}
```

Output: A E I O U

### 2D array

Use case: Multiple strings

Memory layout: Array of pointers, each pointing to a string or characters

- char *ptr → `ptr` is pointer to `char`
- char **ptr → `ptr` is pointer to `char *` (pointer to a pointer)

**Example 1**

Memory dynamically assigned using malloc. 3 mallocs: 1 for rows + 2 for data.

```c
int main () {
  int nrows = 2;
  int ncols = 5;
  int i, j;

  // For each row, allocate memory for nrows elements
  char **pvowels = malloc(nrows * sizeof(char *));

  // For each columns, allocate memory for ncols elements
  pvowels[0] = malloc(ncols * sizeof(char));
  pvowels[1] = malloc(ncols * sizeof(char));

  pvowels[0][0] = 'A';
  pvowels[0][1] = 'E';
  pvowels[0][2] = 'I';
  pvowels[0][3] = 'O';
  pvowels[0][4] = 'U';

  pvowels[1][0] = 'a';
  pvowels[1][1] = 'e';
  pvowels[1][2] = 'i';
  pvowels[1][3] = 'o';
  pvowels[1][4] = 'u';

  for (i = 0; i < nrows; i++) {
    for (j=0; j < ncols; j++) {
    printf("%c ", pvowels[i][j]);
    }
    printf("\n");
  }

  // Free individual rows
  free(pvowels[0]);
  free(pvowels[1]);

  // Free the top-level pointer
  free(pvowels);
}
```

Output: 

A E I O U 
a e i o u 

**Example 2**

Memory assigned to string literals. 1 malloc only for pointer array.

```c
int main () {
  int nrows = 2;

  // For each row, allocate memory for nrows elements
  char **pvowels = malloc(nrows * sizeof(char *));

  pvowels[0] = "AEIOU";
  pvowels[1] = "aeiou";

  printf("%s\n%s\n", pvowels[0], pvowels[1]);

  free(pvowels);
}
```

Output: 

AEIOU
aeiou

Example 1 vs 2:
- Characters cannot be modified in Example 2 as they are string literals, but can be in Example 1. String literals are stored in .rodata segment (read-only data).
- The second one is simpler, but the first one gives full control & safety.

### Code that stores the first 3 rows of `Pascal's triangle`.

1
1 1
1 2 1
1 3 3 1
1 4 6 4 1

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
  int i, j;
  // For each row, allocate memory for 3 elements
  int **pnumbers = (int **) malloc(3 * sizeof(int *));

  // For each column, allocate memory for required elements
  pnumbers[0] = (int *) malloc(1 * sizeof(int));
  pnumbers[1] = (int *) malloc(2 * sizeof(int));
  pnumbers[2] = (int *) malloc(3 * sizeof(int));

  pnumbers[0][0] = 1;
  pnumbers[1][0] = 1;
  pnumbers[1][1] = 1;
  pnumbers[2][0] = 1;
  pnumbers[2][1] = 2;
  pnumbers[2][2] = 1;

  for (i = 0; i < 3; i++) {
    for (j = 0; j <= i; j++) {
      printf("%d", pnumbers[i][j]);
    }
    printf("\n");
  }

  for (i = 0; i < 3; i++) {
    // Free individual rows
    free(pnumbers[0]);
    free(pnumbers[1]);
    free(pnumbers[2]);
  }

  // Free the top-level pointer
  free(pnumbers);
  return 0;
}
```

---

## Recursion

`unsigned int` is a data type in C that holds only non-negative whole numbers. `unsigned` means no sign bit, so value can't be negative.

### Calculating factorial

```c
#include <stdio.h>

unsigned int factorial(unsigned int x) {
  if (x > 1) {
    return x * factorial(x-1);
  }
  return 1; // Base case: factorial of 0 or 1 is 1
}

int main() {

    printf("0! = %i\n", factorial(0));
    printf("1! = %i\n", factorial(1));
    printf("3! = %i\n", factorial(3));
    printf("5! = %i\n", factorial(5));
    return 0;
}
```

Output:

0! = 1
1! = 1
3! = 6
5! = 120


Note: In C, `OR` will not work as it does in Python. `||` is used as logical OR. Similarly, `&&` for AND, and `!` for NOT.

For example, in the base case of a recursive factorial function:
```c
if (x == 1 || x == 0) {
  return 1;
}
```

Recursion uses the `call stack`, which is limited in size. Using excessive recursion can cause **stack overflow**. For larger numbers, a non-recursive (like loop-based) version would be better.

A `stack overflow` is a specific type of `buffer overflow` that occurs exclusively on the program's call stack. Stack overflow is typically caused due to `excessive recursion` or `allocation of large local variables`.

`Buffer overflow` is a broader category of `memory error`.

### Calculating factorial using non-recursive loop based version:

```c
unsigned int factorial(unsigned int x) {
  unsigned int result = 1;
  for (unsigned int i = 2; i <= x; i++) {
    result *= i;
  }
  return result;
}
```

---

## Linked Lists

A linked list is a linear data structure where each element (called a **node**) contains: 
- Data (the value) 
- A pointer to the next node

Unlike arrays, linked lists don't store data in contiguous memory blocks.

### Pseudocode
1. Define a node structure

```c
#include <stdio.h>
#include <stdlib.h>

// Define the structure
struct node {
  int data;
  struct node *next;
};
```

2. Print the list

```c
// Function to print the list
void print_list(struct node *head) {
  struct node *current = head;  // Start traversal from head
  while (current != NULL) { // loop if current is not NULL
    printf("%d -> ",current->data); //access value of current node
    current = current->next; // move pointer to next node
  }
  printf("NULL\n"); // if current is NULL
}
```

3. Add Node to the Beginning (push_head)

**[In C, all function arguments are passed by value — including pointers.](#functions)** 
- If you pass a variable, a copy of its **value** is passed. You can't change the original variable from the caller.
- If you pass a pointer, a copy of the **pointer** is passed. The function can modify the data it points to, but not reassign the original pointer in the caller.
- When `head` is a `struct node*`, and you pass it to a function, a copy of `head` pointer is passed. The function can access the same nodes, but cannot change the original pointer variable (`head`) in the calling function. 
- When `head` is a `struct node**`, and you pass `&head`(its address) to a function that takes a `struct node**`, a pointer to the original `head` pointer is passed. This allows the function to modify the original `head` pointer in the caller.

-Function `void push_head(struct node *head, int data)` means `head` is passed by value, not by reference - a copy of the `head` pointer is passed into the function. To modify the actual `head` pointer in the caller, use a **double pointer**: `struct node** head`.
- When using double pointer: `head` is of type: `struct node**`, `*head` is of type: `struct node*` (the actual head node), `new_node` is of type: `struct node*`
- `new_node->next = head;` → assigns a `struct node**` to a `struct node*` → type mismatch!
- `new_node->next = *head;` → assigns a `struct node*` to a `struct node*` → correct. So, `*head` is used to refer to the current head node, and `*head = new_node;` to update it.

```c
// Function to add a new node to the beginning of the list
void push_head(struct node **head, int data) { // double pointer- be able to modify actual head pointer

  struct node *new_node = malloc(sizeof(struct node)); // create a new node
  new_node->data = data;  // set start value
  new_node->next = *head; // set pointer to next node to current head
  *head = new_node;   // update head to point to new_node
}
```
4. Add Node to the End (push_tail)

Handle both empty and non-empty list cases.

```c
// Function to add a new node to the end of the list (works even if list is empty)
void push_tail(struct node **head, int data) { // double pointer- able to modify the actual head pointer

  struct node *new_node = malloc(sizeof(struct node)); // create a new node
  new_node->data = data;  // set end value
  new_node->next = NULL; // set pointer to next node to NULL

  // Empty list
  if (*head == NULL) {  // If empty list
    *head = new_node;   // new_node becomes head
    return;
  }

  // Non-empty list — Traverse to the last node
  struct node *current = *head;  // Start traversal from head
  while (current->next != NULL) { // Traverse to the last node
    current = current->next; // move pointer to the next node
  }
  current->next = new_node; // if at last node, update last node to point to new_node
}
```
5. Remove Node from Beginning (pop_head)

```c
// Function to remove first item
int pop_head(struct node **head) {  // double pointer- able to modify the actual head pointer
  if (*head == NULL) return -1; // return error if empty list

  int retval = (*head)->data;  // Save data of first node
  struct node *next_node = (*head)->next;  // Save pointer to second node
  free(*head);                // free/remove first node
  *head = next_node;          // set head to next
  return retval;              // return data removed
}
```

6. Remove Node from End (pop_tail)

```c
// Function to remove last item
int pop_tail(struct node** head) { // double pointer- able to modify the actual head pointer
  if (*head == NULL) return -1; // return error if empty list
  
  struct node* current = *head; // Start traversal from head

  // Only one node/item on the list
  if (current->next == NULL) {  // If only one node (next node is NULL)
    int retval = current->data;  // Save data of node
    free(current);   // free node
    *head = NULL; // set head to NULL (empty list)
    return retval;  // return data removed
  }

  // More than one node
  while (current->next->next != NULL) { // until second-last node is reached
    current = current->next;  // move pointer to the next node
  }
  int retval = current->next->data; // Save data of last node
  free(current->next);         // free/remove last node
  current->next = NULL;         // set current as new last node (next points to NULL)
  return retval;  // return data removed
}
```
7. Remove Node by index (pop_index)

```c
// Function to remove item at a specific index
int pop_index(struct node** head, int n) { // double pointer- able to modify the actual head pointer
  if (*head == NULL) return -1; // return error if empty list

  // Special case: remove head
  if (n==0) {
    return pop_head(head);  // remove first node- head is struct node**
  }

  struct node *current = *head; // Start traversal from head

  // Traverse to (n-1)th node — the node before the one to be removed
  // After traversal, ensure node to be deleted (current->next) exists
  for (int i=0; i < n-1; i++) {
    if (current == NULL || current->next == NULL) { // invalid index: end of the list, or past the end
      return -1;   // index out of bounds (nothing to delete)
    }
    current = current->next;  // move pointer to the next node
  }

  // For n = 1, (current = *head) loop skips. 
  if (current->next == NULL) {  // node to be removed is NULL
    return -1; // index out of bounds (nothing to delete)
  }
  int retval = current->next->data;  // Save node data (at n)
  struct node *temp_node = current->next;   // Save node pointer (at n-1)
  current->next = temp_node->next; // bypass deleted node (pointer at n-1 points to n+1)
  free(temp_node);   // free node
  return retval;  // return data removed
}
```

8. Define Main and Free All Nodes in Main

```c
int main() {

  // Create head node in the heap
  struct node *head = malloc(sizeof(struct node));
  head->data = 1;
  head->next = NULL;

  // Print initial list
  printf("Initial list:\n");
  print_list(head);

  // Add items to the head and tail
  push_head(&head, 0); // pass pointer to head (memory address of head)
  printf("After push(0):\n");
  print_list(head);

  push_head(&head, -1); // pass pointer to head (memory address of head)
  printf("After push(-1):\n");
  print_list(head);
  
  push_tail(&head, 2);
  printf("After push(2):\n");
  print_list(head);

  push_tail(&head, 3);
  printf("After push(3):\n");
  print_list(head);

  // Remove from head and tail
  pop_head(&head);
  printf("After pop(-1):\n");
  print_list(head);

  pop_tail(&head);
  printf("After pop(3):\n");
  print_list(head);

  // Remove by index
  pop_index(&head, 1);
  printf("After pop(1):\n");
  print_list(head);

  // Free all nodes
  struct node *current = head;  // Start traversal from head
  struct node *next;    //  create new pointer
  while (current != NULL) {
    next = current->next;  // Save the node pointer
    free(current);         // free the current node
    current = next;        // move to the next node
  }
  return 0;
}
```
Output:
Initial list:
1 -> NULL
After push(0):
0 -> 1 -> NULL
After push(-1):
-1 -> 0 -> 1 -> NULL
After push(2):
-1 -> 0 -> 1 -> 2 -> NULL
After push(3):
-1 -> 0 -> 1 -> 2 -> 3 -> NULL
After pop(-1):
0 -> 1 -> 2 -> 3 -> NULL
After pop(3):
0 -> 1 -> 2 -> NULL
After pop(1):
0 -> 2 -> NULL

Note:
- `struct node* head = NULL;` is not strictly necessary if memory is assigned immediately afterward using `malloc()` or `calloc()`. However it helps prevent undefined behavior if you accidentally use `head` before allocating memory. Also, check return value (allocation success) when using `malloc()` or `calloc()`.
```c
struct node* head = NULL;
head = malloc(sizeof(struct node));
// Check if allocation succeeded
if (head == NULL) {
  printf("Memory allocation failed.\n");
  return 1; // exit with error
}
```
- In `main()` function, you typically return `1` for general errors. In `pop_*` functions, you return `-1` to signaling invalid operations (like "nothing to pop").
-  To create 3 nodes in the heap:
```c
struct node *head = malloc(sizeof(struct node));
struct node *second = malloc(sizeof(struct node));
struct node *third = malloc(sizeof(struct node));
```
OR
```c
struct node *head = malloc(sizeof(struct node)),
            *second = malloc(sizeof(struct node)),
            *third = malloc(sizeof(struct node));

head->data = 1;
head->next = second;

second->data = 2;
second->next = third;

third->data = 3;
third->next = NULL;
```
-`struct node* head, *second, *third = NULL;` Wrong! - only `third` is initialized to `NULL`; `head` and `second` remain uninitialized.
- For simplified version: `struct node *head = NULL, *second = NULL, *third = NULL;` all 3 pointers are initialized to NULL. Notice the 3 are separated by `,`.

- `calloc()` initializes the memory it allocates (sets the contents of the allocated block to 0 - `data = 0 `and `next = NULL`). However, it does not initialize the pointer variable (`head`) itself, — you still need to assign the result of `calloc()` to it

- To reduce duplication, you could create a helper and then use it in push_head() and push_tail()
```c
struct node* create_node(int data) {
  struct node* n = malloc(sizeof(struct node));
  n->data = data;
  n->next = NULL;
  return n;
}
```

---

## Binary trees

A Binary Tree is a type of data structure in which each node has at most two children (left child and right child). A binary tree is a special case of a K-ary tree, where k is 2. A linked list can be seen as a degenerate tree where each node has at most one child, similar to a unary tree.

The logarithm is the inverse of exponentiation. If `a^x = n` then, `logₐ(n) = x`

log₂(1) = 0 → because 2⁰ = 1
log₂(2) = 1 → because 2¹ = 2
...
log₂(16) = 4 → because 2⁴ = 16
...

As n increases, log₂(n) also increases — but much more slowly than n itself.

n	| log₂(n) ≈
---|-----
10	| 3.32
100	| 6.64
1,000	| 9.97
1,000,000	| 19.93
1,000,000,000	| 29.9
As you can see, even if n is in the billions, log₂(n) is still under 30.

If an algorithm runs in O(log₂(n)) time, then for 1 billion items, it would only take about 30 steps. In contrast, an O(n) algorithm takes 1 billion steps. That’s why binary search (O(log₂(n))) is so powerful.

Big O Notation is a mathematical way of describing the upper bound of an algorithm’s running time or space usage as the input size grows. The "O" stands for "Order of" — as in “the order of growth”.

### Common Big O Examples (from fastest to slowest)
Big O Notation	| Name	| Example Use Case
------|---------------|-------------------------------------
O(1)	| Constant time	| Accessing an array element by index
O(log n)	| Logarithmic time	| Binary search
O(n)	| Linear time	| Looping through an array
O(n log n)	| Linearithmic time (or log-linear)	| Efficient sorting (Merge Sort, Quick Sort)
O(n²)	| Quadratic time	| Nested loops (e.g., bubble sort)
O(2ⁿ)	| Exponential time	| Recursive brute-force algorithms
O(n!)	| Factorial time	| Solving permutations (e.g., traveling salesman)

### Searching a Tree: Two Main Ways
When we work with trees (like family trees or file folders), we often need to visit or search through the nodes. There are two main ways to search a tree: `Depth First Search` and `Breadth-First Search`. Both are algorithms for traversing or searching tree or graph data structures. 

Depth-first search (DFS) starts at the root and explores as far as possible along each branch before backtracking. There are three types of depth first search traversal:

- Pre-order: `Visit → Left → Right`. Visit the node (parent) first, before its children. Use when you want to copy or save the structure of a tree, or when the root must be handled before its children.
- In-order: `Left → Visit → Right`. Commonly used in binary search trees (BSTs) to retrieve values in sorted order.
- Post-order: `Left → Right → Visit`. Children are processed first, then the parent. Useful for deleting nodes or freeing memory from the bottom up.

Here, "visit" means to process the node — like printing it, storing its value, or doing some operation on it.

Breadth-first search (BFS) explores the tree in level-order, visiting every node on a level before moving to a lower level. It's useful when you're looking for the shortest path in an unweighted graph, or when you need to process nodes based on their distance from the root. In AI (like puzzle-solving), it's used to explore all possibilities evenly.

---

## Testing strncpy

```c
#include <stdio.h>
#include <string.h>

int main() {
    char dest[6];
    strncpy(dest, "hello world", 5);
    dest[5] = '\0';

    printf("Result: %s\n", dest);
    return 0;
}
```

---

## Error: use after free

```bash
vim use-after-free.c
```

```c
#include <stdlib.h> // for malloc(), free ()
#include <stdio.h> // for printf()

int main() {
    int *x = malloc(10);
    *x = 42;
    free (x); //x is freed
    printf("%d\n", *x); // Use-after-free
    return 0;
}
```

Compile and run:
```bash
clang -fsanitize=address -g use-after-free.c -o use-after-free
./use-after-free
```
Output:
ERROR: AddressSanitizer: heap-use-after-free on address 0x...

Running `echo $?` after this will give a non-zero return value such as `134`.

Note:
- `malloc()` returns a pointer to a block of memory. You need a pointer (`int *x`) to store and access that memory.
- The safer way to allocate memory is `int *x = malloc(sizeof(*x))` or `int *x = malloc(sizeof(int));`

---

## Error: use after scope

```bash
vim use-after-scope.c
```

```c
#include <stdio.h> // for printf()

int *p;

int main(void) {
    {
        int x = 42;
        p = &x;
    } // x is out of scope
    printf("%d\n", *p);  // Use-after-scope
    return 0;
}
```

Compile and run:
```bash
clang -fsanitize=address -g prog.c -o prog
./prog
```

Output:
ERROR: AddressSanitizer: stack-use-after-scope on address 0x7...

Note: 
- `int *p;` should be defined in global/file-scope to be accessed outside `main()`

---

## Memory leak

```bash
vim leaks.c
```

```c
#include <stdlib.h> // for malloc()

int main() {
    int *x = malloc(10); // allocated but not freed → leak
    return 0;
}
```

Compile & run:
```bash
clang -g leaks.c -o leaks
./leaks
leaks --atExit -- ./leaks
```
Output:
leaks Report Version: ...
Process 2819: ...
Process 2819: 1 leak for 32 total leaked bytes.

Note:
- `leaks` is a tool provided by Apple. Use `-fanitize=address` or `-fsanitize=leak` for portable, compiler-integrated detection (Linux & macOS with `clang`).
- `malloc()` returns a pointer to a block of memory. You need a pointer (`int *x`) to store and access that memory.
- The safer way to allocate memory is `int *x = malloc(sizeof(*x))` or `int *x = malloc(sizeof(int));`
- Memory Leaks do not crash the program but lead to increased memory usage over time.

---

## Null pointer Dereference

```c
void demo_null_dereference() {
  int *p = NULL;
  printf("\n[Null Pointer Test]\n");
  printf("Pointer p = %p\n", (void *)p);
    
  *p = 5;   // This will crash
  printf("Value at *p: %d\n", *p);
}

int main() {
  demo_null_dereference();
  return 0;
}
```

Output when compiled using `clang` without `-fsanitize=address` option:
[Null Pointer Test]
Pointer p = 0x0
zsh: segmentation fault  ./prog

This prints a [segmentation fault](#memory-errors) after the output.

Using debugger `lldb`
```bash
lldb ./prog
(lldb) break set --name main
(lldb) run
(lldb) step # until line 10
```

`lldb` output:

stop reason = EXC_BAD_ACCESS (code=1, address=0x0)
...
-> 10  	    *p = 5; ...

`lldb` stops at line `*p = 5;` with stop reason "EXC_BAD_ACCESS" and does not proceed evn with `step`.

Using `clang -fsanitize=address -g prog.c -o prog` instead of `clang -g prog -o prog` and running the program using `./prog` will show the error.

Output when compiled using `clang` and `-fsanitize=address` option:
...ERROR: AddressSanitizer: SEGV on unknown address 0x0...


### Valid pointer example

```c
void valid_pointer() {
    int x = 0;
    int *p = &x;
    *p = 10;
    printf("Value of x: %d\n", x);
}
int main() {
  valid_pointer();
  return 0;
}
```

Output:
Value of x: 10

---

## Buffer Underflow

```c
void demo_buffer_underflow() {
    char buffer[8] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    char *p = buffer;

    printf("\n[Buffer Underflow Test]\n");
    printf("buffer[0] = %c\n", buffer[0]);

    // Underflow: writing before buffer[0]
    p[-1] = 'Z';  // Corrupts adjacent memory
    printf("Wrote 'Z' to buffer[-1] (underflow)\n");
}

int main() {
  demo_buffer_underflow();
  return 0;
}
```

Output:
[Buffer Underflow Test]
buffer[0] = A
Wrote 'Z' to buffer[-1] (underflow)

Without sanitizers, `lldb` won't catch this invalid memory write immediately — the program continues, but memory corruption happened.

Using `clang -fsanitize=address -g prog.c -o prog` instead of `clang -g prog -o prog` and running the program using `./prog` will show the error.

Output when compiled using `clang` and `-fsanitize=address` option:
...ERROR: AddressSanitizer: stack-buffer-underflow on address 0x7...

Note: writing to `p[-1]` is undefined behavior and might not crash but can corrupt data or cause weird bugs

---