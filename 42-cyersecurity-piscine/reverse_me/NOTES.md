

Level 1: The expected comparison string was __stack_check. Break at strcmp and check the 1st and 2nd arg that were compared.
Level 2: the program checks for the required initial characters (00: It compares 2nd character first and then the first character), converts groups of three decimal digits with atoi, and compares the constructed string with delabere.

level1
```
(gdb) disassemble /r main # disassemble main's instructions (includes call to strcmp)

(gdb) break strcmp # break at strcmp

(gdb) run
Please enter key: whatever

# x/s display memory as null terminated string, $esp+4 first arg, $esp+8 second arg

(gdb) x/s *(char **)($esp+4)
0xffffcfac:	"0"

(gdb) x/s *(char **)($esp+8)
0xffffcf9e:	"__stack_check"

(gdb) finish # runs until the current function (strcmp) returns to the caller

(gdb) p $eax # prints 0 if they match
$1 = 0

(gdb) continue
Continuing.
Good job.
```

level2

At the atoi@plt call, the input string was "101".
After stepping over the call with ni, $eax was 101 decimal (0x65 hexadecimal).
The following mov %al,%cl instruction copies the low byte of $eax into $cl; step it with stepi, then inspect with p/x $cl.
Later, the stack words at $esp began 0xffffcffb, 0, 9, and 11. The first word was a pointer to "de"; the second was a null value, not a valid string pointer.

```
(gdb) info break
Num     Type                   Disp Enb Address    What
1       STT_GNU_IFUNC resolver keep y   0xf7c9af80 <strcmp>
2       STT_GNU_IFUNC resolver keep y   0xf7c9af80 <strcmp>

(gdb) ni
0x565562fe in main ()
1: x/i $pc
=> 0x565562fe <main+46>:	lea    -0x35(%ebp),%eax
# lea: Load Effective Address - calculate the address (ebp-0x35) and store that in $eax

(gdb) ni
1: x/i $pc
=> 0x56556313 <main+67>:	mov    %eax,-0xc(%ebp)

..

(gdb) x/s $ebp-0x35
0xffffcfe3:	"h"
```

// lea set to start of the buffer which is $ebp-35
   0x565562fe <main+46>:	lea    -0x35(%ebp),%eax
   0x56556301 <main+49>:	lea    -0x42d2(%ebx),%ecx
   0x56556307 <main+55>:	mov    %ecx,(%esp)
   0x5655630a <main+58>:	mov    %eax,0x4(%esp)
   0x5655630e <main+62>:	call   0x565560c0 <__isoc99_scanf@plt>
   0x56556313 <main+67>:	mov    %eax,-0xc(%ebp)
   0x56556316 <main+70>:	mov    $0x1,%eax
   0x5655631b <main+75>:	cmp    -0xc(%ebp),%eax
   0x5655631e <main+78>:	je     0x5655632c <main+92>
   0x56556324 <main+84>:	mov    -0x40(%ebp),%ebx
   0x56556327 <main+87>:	call   0x56556220 <no>
// ebp-34 is the second character
   0x5655632c <main+92>:	movsbl -0x34(%ebp),%ecx
   0x56556330 <main+96>:	mov    $0x30,%eax
// so second cahracter is compared (p/x $ecx and p/x $eax to see comparison values)
   0x56556335 <main+101>:	cmp    %ecx,%eax
   0x56556337 <main+103>:	je     0x56556345 <main+117>
...
(gdb) x/10i $pc
=> 0x56556337 <main+103>:	je     0x56556345 <main+117>
   0x5655633d <main+109>:	mov    -0x40(%ebp),%ebx
   0x56556340 <main+112>:	call   0x56556220 <no>
// ebp-35 is the first character
   0x56556345 <main+117>:	movsbl -0x35(%ebp),%ecx
   0x56556349 <main+121>:	mov    $0x30,%eax
// so first character is now compared (p/x $ecx and p/x $eax)
   0x5655634e <main+126>:	cmp    %ecx,%eax
...
// 3 chars are given as input to atoi
   0x565563fe <main+302>:	mov    -0x40(%ebp),%ebx
   0x56556401 <main+305>:	mov    -0x14(%ebp),%eax
   0x56556404 <main+308>:	mov    -0x35(%ebp,%eax,1),%al
   0x56556408 <main+312>:	mov    %al,-0x39(%ebp)
   0x5655640b <main+315>:	mov    -0x14(%ebp),%eax
   0x5655640e <main+318>:	mov    -0x34(%ebp,%eax,1),%al
   0x56556412 <main+322>:	mov    %al,-0x38(%ebp)
   0x56556415 <main+325>:	mov    -0x14(%ebp),%eax
   0x56556418 <main+328>:	mov    -0x33(%ebp,%eax,1),%al
   0x5655641c <main+332>:	mov    %al,-0x37(%ebp)
   0x5655641f <main+335>:	lea    -0x39(%ebp),%eax
   0x56556422 <main+338>:	mov    %eax,(%esp)
   0x56556425 <main+341>:	call   0x565560d0 <atoi@plt>
...

// so tryng input 00hjdk
   0x565563b7 <main+231>:	call   0x565560a0 <strlen@plt>
// strlen of 'd'
(gdb) x/s *(char **)$esp
0xffffcffb:	"d"
// trying with 00shdfjsjfklshsdg as atoi is called several times with breakpoint in strcmp
(gdb) break strcmp
(gdb) p/s *(char **)($esp+4)
$7 = 0xffffcffb "d"
(gdb) p/s *(char **)($esp+8)
$6 = 0x56557d33 "delabere"
// d is compared to delabere. Earlier there was a strlen call that gave the number 8. As atoi is taken for every 3 chars to get the comparison to delabere. The input after 00 should be 101 108 97 98 101 114 101. As 98 and 97 as 2 characters, the first character for them can be 0 or the last can be any number or digit.

Other useful commands

```
info files # show entry point address

info functions # symbols

info registers # list of registers

starti # stop at ELF entry point

x/10i $pc
# x/10i disassemble 10 instructions; $pc around current intruction

set $ret = *(void **)$esp
# GDB variable named $ret; copy it to $esp into $ret

x/10i $ret-8
# x/10i disassemble 10 instructions; $ret-8 starting 8 bytes before ret

si # or ni: step one intruction /next intruction
stepi # execute one machine instruction, entering a function if that instruction is a call

x/i $pc — show the instruction at the current program counter.
ni — execute the next instruction, stepping over function calls.
stepi — execute one machine instruction, stepping into calls.
p/d $eax — print the value in $eax as decimal.
p/x $eax — print the value in $eax as hexadecimal.
x/s ADDRESS — interpret memory at ADDRESS as a string.
x/16xb $esp — show 16 bytes starting at the stack pointer.
x/8wx $esp — show 8 words (4 bytes each) starting at the stack pointer.
```

Registers and stack
   On 32-bit x86, a function’s integer return value is in $eax.
   $al is the low 8 bits of $eax; $cl is the low 8 bits of $ecx.
   At a call site, the stack may hold function arguments, but elsewhere $esp can point to local data or other stack values.
   For a typical 32-bit x86 call, the first argument is at [$esp] just before the call, and at [$esp+4] on entry to the called function. Check where execution is stopped before interpreting stack contents.
   x/s *(char **)$esp treats the word at $esp as a pointer, then displays the string it points to. Use x/s $esp to inspect the bytes at $esp directly as a string.