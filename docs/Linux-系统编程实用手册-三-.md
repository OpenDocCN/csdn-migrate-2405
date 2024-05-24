# Linux 系统编程实用手册（三）

> 原文：[`zh.annas-archive.org/md5/9713B9F84CB12A4F8624F3E68B0D4320`](https://zh.annas-archive.org/md5/9713B9F84CB12A4F8624F3E68B0D4320)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Linux 内存问题

一个简单的真理：内存问题存在。我们使用 C（和 C++）等语言编程的事实本身就隐含着无限类型的问题！在某个时候，人们意识到（或许有点悲观地认识到），在一个受管理的内存安全语言中小心编程最终是避免内存问题的（唯一？）现实方式。

然而，在这里，我们正在使用我们选择的强大工具：卓越而古老的 C 编程语言！因此，我们可以做些什么来减轻，如果不能消除，常见的内存问题，这就是本章的主题。最终，目标是真正的内存安全；好吧，说起来容易做起来难！

尽管如此，我们将尝试通过阐明开发人员可能会遇到的常见内存问题，成功地完成这项任务。在接下来的章节中，我们将探讨一些强大的内存调试工具如何在这方面提供巨大帮助。

在本章中，开发人员将了解到，尽管动态内存管理 API（在第四章，*动态内存分配*中涵盖）很少，但当使用不慎时，它们可能会引起看似无穷无尽的麻烦和错误！

具体来说，本章将阐明导致现场软件中难以检测的错误的常见内存问题：

+   不正确的内存访问问题（其中有几种类型）

+   内存泄漏

+   未定义行为

# 常见内存问题

如果要对细粒度的内存错误进行分类（通常是由 C 或 C++编程引起的），将会很困难——存在数百种类型！相反，让我们把讨论控制在可管理的范围内，看看什么被认为是我们这些可怜的 C 程序员经常遭遇的典型或常见内存错误：

+   不正确的内存访问

+   使用未初始化的变量

+   越界内存访问（读/写下溢/溢出错误）

+   释放后使用/返回后使用（超出范围）错误

+   双重释放

+   泄漏

+   未定义行为（UB）

+   数据竞争

+   碎片化（内部实现）问题

+   内部

+   外部

所有这些常见的内存问题（除了碎片化）都被归类为 UB；尽管如此，我们将 UB 作为一个单独的条目，因为我们将更深入地探讨它。此外，虽然人们口头上使用*bug*这个词，但一个人应该真正（并更正确地）将其视为*defect*。

我们在本章不涵盖数据竞争（请等到第十五章，*使用 Pthreads 的多线程 Part II - 同步*）。

为了帮助测试这些内存问题，`membugs`程序是每个问题的一系列小测试用例。

**侧边栏 :: Clang 编译器**

LLVM/Clang 是一个用于 C 的开源编译器。我们确实使用 Clang 编译器，特别是在本章和下一章中，特别是在下一章中涵盖的 sanitizer 编译器工具集。它在整本书中都很有用（事实上，在我们的许多 Makefile 中都使用它），因此在 Linux 开发系统上安装 Clang 是一个好主意！再次强调，这并非完全必要，人们也可以继续使用熟悉的 GCC——只要愿意在必要时编辑 Makefile(s)以切换回 GCC！

在 Ubuntu 18.04 LTS 桌面上安装 Clang 很容易：`sudo apt install clang`

Clang 文档可以在[`clang.llvm.org/docs/index.html`](https://clang.llvm.org/docs/index.html)找到。

当编译`membugs`程序（使用 GCC 进行正常情况以及使用 Clang 编译器进行 sanitizer 变体）时，你会看到大量的编译器警告被发出！这是预期的；毕竟，它的代码充满了错误。放松心情，继续阅读。

此外，我们提醒您，本章的目的是了解（和分类）典型的 Linux 内存问题；使用强大的工具来识别和修复它们是下一章的主题。两者都是必需的，所以请继续阅读。

构建的一些示例输出如下所示（为了可读性，输出被剪切了）。现在，我们不会尝试分析它；这将在我们通过本章时发生（*记住，您也需要安装 Clang！*）：

```
$ make
gcc -Wall -c ../common.c -o common.o
gcc -Wall -c membugs.c -o membugs.o
membugs.c: In function ‘uar’:
membugs.c:143:9: warning: function returns address of local variable [-Wreturn-local-addr]
 return name;
 ^~~~
 [...]

gcc -Wall -o membugs membugs.o common.o

[...]
clang -g -ggdb -gdwarf-4 -O0 -Wall -Wextra -fsanitize=address -c membugs.c -o membugs_dbg_asan.o
membugs.c:143:9: warning: address of stack memory associated with local variable 'name' returned [-Wreturn-stack-address]
 return name;
 ^~~~

gcc -g -ggdb -gdwarf-4 -O0 -Wall -Wextra -o membugs_dbg membugs_dbg.o common_dbg.o
[...]
$ 
```

我们还强调，在我们将运行的所有测试案例中，我们使用由 GCC 生成的*membugs*二进制可执行文件（而不是 Clang；我们将在后面使用 sanitizer 工具时使用 Clang）。

在构建过程中，可以将所有输出捕获到文件中，如下所示：

`make >build.txt 2>&1`

使用`--help`开关运行`membugs`程序以查看所有可用的测试案例：

```
$ ./membugs --help

Usage: ./membugs test_case [ -h | --help]
 test case  1 : uninitialized var test case
 test case  2 : out-of-bounds : write overflow [on compile-time memory]
 test case  3 : out-of-bounds : write overflow [on dynamic memory]
 test case  4 : out-of-bounds : write underflow
 test case  5 : out-of-bounds : read overflow [on compile-time memory]
 test case  6 : out-of-bounds : read overflow [on dynamic memory]
 test case  7 : out-of-bounds : read underflow
 test case  8 : UAF (use-after-free) test case
 test case  9 : UAR (use-after-return) test case
 test case 10 : double-free test case
 test case 11 : memory leak test case 1: simple leak
 test case 12 : memory leak test case 2: leak more (in a loop)
 test case 13 : memory leak test case 3: "lib" API leak
-h | --help : show this help screen
$ 
```

您将注意到写入和读取上溢各有两个测试案例：一个是在编译时内存上，一个是在动态分配的内存上。区分这些情况很重要，因为工具在检测哪些类型的缺陷时有所不同。

# 不正确的内存访问

通常，这个类别中的错误和问题是如此常见，以至于被轻率地忽视！请注意，它们仍然非常危险；请注意找到、理解和修复它们。

所有内存缓冲区上溢和下溢错误的类别都经过仔细记录和跟踪，通过**通用漏洞和暴露（CVE）**和**通用弱点枚举（CWE）**网站。与我们讨论的相关的是，CWE-119 是*内存缓冲区边界内操作的不当限制*（[`cwe.mitre.org/data/definitions/119.html`](https://cwe.mitre.org/data/definitions/119.html)）。

# 访问和/或使用未初始化的变量

为了让读者对这些内存问题的严重性有所了解，我们编写了一个测试程序`membugs.c`。这个测试程序允许用户测试各种常见的内存错误，这将帮助他们更好地理解潜在的问题。

每个内存错误测试案例都被赋予一个测试案例编号。这样读者可以很容易地跟随源代码和解释材料，我们也会指定测试案例如下。

# 测试案例 1：未初始化内存访问

这些也被称为**未初始化内存读取**（**UMR**）错误。一个经典案例：本地（或自动）变量根据定义是未初始化的（不像全局变量，它们总是预设为零*）*：

```
/* test case 1 : uninitialized var test case */
static void uninit_var()
{
   int x; /* static mem */

    if (x)
        printf("true case: x=%d\n", x);
    else
        printf("false case\n");
}
```

在前面的代码中，由于`x`未初始化并且将具有随机内容，因此在运行时会发生未定义的情况。现在，我们按以下方式运行这个测试案例：

```
$ ./membugs 1
true case: x=32604
$ ./membugs 1
true case: x=32611
$ ./membugs 1
true case: x=32627
$ ./membugs 1
true case: x=32709
$ 
```

值得庆幸的是，现代版本的编译器（`gcc`和`clang`）会对这个问题发出警告：

```
$ make 
[...]
gcc -Wall -c membugs.c -o membugs.o
[...]
membugs.c: In function ‘uninit_var’:
membugs.c:272:5: warning: ‘x’ is used uninitialized in this function [-Wuninitialized]
 if (x) 
 ^ 

[...]
clang -g -ggdb -gdwarf-4 -O0 -Wall -Wextra -fsanitize=address -c membugs.c -o membugs_dbg_asan.o
[...]
membugs.c:272:6: warning: variable 'x' is uninitialized when used here [-Wuninitialized]
 if (x)
 ^
membugs.c:270:7: note: initialize the variable 'x' to silence this warning
 int x; /* static mem */
 ^
 = 0
[...]
```

# 越界内存访问

这个类别再次属于更常见但致命的内存访问错误。它们可以被分类为不同类型的错误：

+   **写入上溢**：尝试向内存缓冲区的最后一个合法可访问位置之后写入的错误

+   **写入下溢**：在第一个合法可访问位置之前尝试向内存缓冲区写入

+   **读取下溢**：在第一个合法可访问位置之前尝试读取内存缓冲区的错误

+   **读取上溢**：在第一个合法可访问位置之后尝试读取内存缓冲区的错误

让我们通过我们的`membugs.c`程序的源代码来检查这些。

# 测试案例 2

编写或缓冲区溢出在编译时分配的内存。请参见以下代码片段：

```
/* test case 2 : out-of-bounds : write overflow [on compile-time memory] */
static void write_overflow_compilemem(void)
{
    int i, arr[5], tmp[8];
    for (i=0; i<=5; i++) {
       arr[i] = 100;  /* Bug: 'arr' overflows on i==5,
                         overwriting part of the 'tmp' variable
                         - a stack overflow! */
    }
}
```

这导致了堆栈溢出（也称为堆栈破坏或**缓冲区溢出**（**BOF**））错误；这是一类严重的漏洞，攻击者已经成功地多次利用，从 1988 年的 Morris Worm 病毒开始！在 GitHub 存储库的*进一步阅读*部分中，了解更多关于这个漏洞的信息。

有趣的是，在我们的*Fedora 28*工作站 Linux 系统上编译和运行代码的这一部分（通过传递适当的参数），显示默认情况下既没有编译时也没有运行时检测到这种（和其他类似的）危险错误（稍后详细介绍！）：

```
$ ./membugs 2
$ ./membugs_dbg 2
$ 
```

这些错误有时也被称为一次性错误。

当然还有更多（像往常一样）；让我们进行一个快速实验。在`membugs.c:write_overflow_compilemem()`函数中，将我们循环的次数从 5 更改为 50：

```
 for (i = 0; i <= 50; i++) {
    arr[i] = 100;
}
```

重新构建并重试；现在在*Ubuntu 18.04 LTS*桌面 Linux 系统上查看输出（在 Fedora 上也是如此，但使用原始内核）：

```
$ ./membugs 2
*** stack smashing detected ***: <unknown> terminated
Aborted
$ 
```

事实上，现代编译器使用堆栈保护功能来检测堆栈溢出错误，更重要的是，攻击。当值足够大时，溢出被检测到；但是使用默认值时，错误却未被检测到！我们强调在下一章中使用工具（包括编译器）来检测这些隐藏的错误的重要性。

# 测试案例 3

在动态分配的内存上写入或 BOF。请参阅以下代码片段：

```
/* test case 3 : out-of-bounds : write overflow [on dynamic memory] */
static void write_overflow_dynmem(void)
{
    char *dest, src[] = "abcd56789";

    dest = malloc(8);
    if (!dest) 

    FATAL("malloc failed\n");

    strcpy(dest, src); /* Bug: write overflow */
    free(dest);
}
```

同样，没有发生错误的编译或运行时检测：

```
$ ./membugs 3
$ ./membugs 3           *<< try once more >>*
$ 
```

不幸的是，与 BOF 相关的错误和漏洞在行业中往往相当常见。根本原因并不为人所知，因此导致编写不良代码；这就是我们作为开发人员必须提高自己水平的地方！

有关安全漏洞的真实世界示例，请参阅 2017 年 Linux 上 52 个文档化的安全漏洞（由各种 BOF 错误引起）的表格：[`www.cvedetails.com/vulnerability-list/vendor_id-33/year-2017/opov-1/Linux.html`](https://www.cvedetails.com/vulnerability-list/vendor_id-33/year-2017/opov-1/Linux.html)。

# 测试案例 4

写入下溢。我们使用`malloc(3)`动态分配一个缓冲区，将指针减小，然后写入该内存位置——写入或缓冲区下溢错误：

```
/* test case 4 : out-of-bounds : write underflow */
static void write_underflow(void)
{
    char *p = malloc(8);
    if (!p)
        FATAL("malloc failed\n");
    p--;
    strncpy(p, "abcd5678", 8); /* Bug: write underflow */
    free(++p);
}
```

在这个测试案例中，我们不希望`free(3)`失败，所以我们确保传递给它的指针是正确的。编译器在这里没有检测到任何错误；尽管在运行时，现代的 glibc 确实会崩溃，检测到错误（在这种情况下是内存损坏）：

```
$ ./membugs 4
double free or corruption (out)
Aborted
$
```

# 测试案例 5

读取溢出，编译时分配的内存。我们尝试在编译时分配的内存缓冲区的最后一个合法可访问位置之后进行读取：

```
/* test case 5 : out-of-bounds : read overflow [on compile-time memory] */
static void read_overflow_compilemem(void)
{
    char arr[5], tmp[8];

    memset(arr, 'a', 5);
    memset(tmp, 't', 8);
    tmp[7] = '\0';

    printf("arr = %s\n", arr); /* Bug: read buffer overflow */
}
```

这个测试案例的设计方式是，我们在内存中顺序排列了两个缓冲区。错误在于：我们故意没有对第一个缓冲区进行空终止（但对第二个缓冲区进行了空终止），因此，`printf(3)`将会继续读取`arr`中的内容，直到`tmp`缓冲区。如果`tmp`缓冲区包含秘密呢？

当然，问题是编译器无法捕捉到这个看似明显的错误。还要意识到，这里我们编写的是小型、简单、易于阅读的测试案例；在一个有几百万行代码的真实项目中，这样的缺陷很容易被忽视。

以下是示例输出：

```
$ ./membugs 2>&1 | grep -w 5
 option =  5 : out-of-bounds : read overflow [on compile-time memory]
$ ./membugs 5
arr = aaaaattttttt
$ 
```

嘿，我们读取了`tmp`的秘密内存。

实际上，诸如 ASan（地址消毒剂，在下一章中介绍）之类的工具将此错误分类为堆栈缓冲区溢出。

顺便说一句，在我们的*Fedora 28*工作站上，我们在这个测试案例中从第二个缓冲区中只得到了垃圾：

```
$ ./membugs 5
arr = aaaaa0<5=�
$ ./membugs 5
arr = aaaaa�:��
$ 
```

这向我们表明，这些错误可能会因编译器版本、glibc 版本和机器硬件的不同而表现出不同的特征。

一个始终有用的测试技术是尽可能在多种硬件/软件变体上运行测试案例。隐藏的错误可能会暴露出来！考虑到诸如字节序问题、编译器优化（填充、打包）和特定平台的对齐等情况。

# 测试案例 6

读取溢出，动态分配的内存。再次尝试读取；这次是在动态分配的内存缓冲区的最后一个合法可访问位置之后：

```
/* test case 6 : out-of-bounds : read overflow [on dynamic memory] */
static void read_overflow_dynmem(void)
{
    char *arr;

    arr = malloc(5);
    if (!arr)
        FATAL("malloc failed\n",);
    memset(arr, 'a', 5);

    /* Bug 1: Steal secrets via a buffer overread.
     * Ensure the next few bytes are _not_ NULL.
     * Ideally, this should be caught as a bug by the compiler,
     * but isn't! (Tools do; seen later).
     */
    arr[5] = 'S'; arr[6] = 'e'; arr[7] = 'c';
    arr[8] = 'r'; arr[9] = 'e'; arr[10] = 'T';
    printf("arr = %s\n", arr);

    /* Bug 2, 3: more read buffer overflows */
    printf("*(arr+100)=%d\n", *(arr+100));
    printf("*(arr+10000)=%d\n", *(arr+10000));

    free(arr);
}
```

测试案例与前一个测试案例（编译时内存的读取溢出*）*基本相同，只是我们动态分配了内存缓冲区，并且为了好玩插入了一些其他错误：

```
$ ./membugs 2>&1 |grep -w 6
 option =  6 : out-of-bounds : read overflow [on dynamic memory]
$ ./membugs 6
arr = aaaaaSecreT
*(arr+100)=0
*(arr+10000)=0
$  
```

嘿，妈妈，看！我们得到了秘密！

它甚至不会导致崩溃。乍一看，这样的错误可能看起来相当无害——但事实上，这是一个非常危险的错误！

著名的 OpenSSL Heartbleed 安全漏洞（CVE-2014-0160）是利用读取溢出的一个很好的例子，或者通常被称为缓冲区过读取漏洞。

简而言之，这个错误允许一个恶意客户端进程向 OpenSSL 服务器进程发出一个看似正确的请求；实际上，它可以请求并接收比应该允许的更多的内存，因为存在缓冲区过读取漏洞。实际上，这个错误使得攻击者可以轻松地绕过安全性并窃取秘密[[`heartbleed.com`](http://heartbleed.com/)]。

如果感兴趣，在 GitHub 存储库的*进一步阅读*部分中找到更多信息。

# 测试案例 7

读取下溢。我们尝试在动态分配的内存缓冲区上进行读取，而在其第一个合法可访问的位置之前：

```
/* test case 7 : out-of-bounds : read underflow */
static void read_underflow(int cond)
{
    char *dest, src[] = "abcd56789", *orig;

    printf("%s(): cond %d\n", __FUNCTION__, cond);
    dest = malloc(25);
    if (!dest)
        FATAL("malloc failed\n",);
    orig = dest;

    strncpy(dest, src, strlen(src));
    if (cond) {
 *(orig-1) = 'x';
 dest --;
 }
    printf(" dest: %s\n", dest);

    free(orig);
}
```

测试案例设计了一个运行时条件；我们两种方式测试它：

```
 case 7:
     read_underflow(0);
     read_underflow(1);
     break;
```

如果条件为真，则缓冲区指针会减少，从而导致后续`printf`的读取缓冲区下溢：

```
$ ./membugs 7
read_underflow(): cond 0
 dest: abcd56789
read_underflow(): cond 1
 dest: xabcd56789
double free or corruption (out)
Aborted (core dumped)
$ 
```

同样，glibc 通过显示双重释放或损坏来帮助我们——在这种情况下，它是内存损坏。

# 释放后使用/返回后使用错误

**使用-** **释放后使用**（UAF）和**返回后使用**（UAR）是危险的、难以发现的错误。查看以下每个测试案例。

# 测试案例 8

**释放后使用（UAF）**。在释放内存指针后对其进行操作显然是一个错误，会导致 UB。这个指针有时被称为悬空指针。这里是一个快速测试案例：

```
/* test case 8 : UAF (use-after-free) test case */
static void uaf(void)
{
    char *arr, *next;
    char name[]="Hands-on Linux Sys Prg";
    int n=512;

    arr = malloc(n);
    if (!arr)
        FATAL("malloc failed\n");
    memset(arr, 'a', n);
    arr[n-1]='\0';
    printf("%s():%d: arr = %p:%.*s\n", __FUNCTION__, __LINE__, arr,
                32, arr);

    next = malloc(n);
    if (!next) {
        free(arr);
        FATAL("malloc failed\n");
    }
    free(arr);
    strncpy(arr, name, strlen(name));  /* Bug: UAF */ 
    printf("%s():%d: arr = %p:%.*s\n", __FUNCTION__, __LINE__, arr,
                32, arr);
    free(next);
}
```

同样，无论在编译时还是在运行时都无法检测到 UAF 错误，也不会导致崩溃：

```
$ ./membugs 2>&1 |grep -w 8
 option =  8 : UAF (use-after-free) test case
$ ./membugs 8
uaf():158: arr = 0x558012280260:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
uaf():166: arr = 0x558012280260:Hands-on Linux Sys Prgaaaaaaaaaa
$  
```

你注意到了巧妙的`printf(3)`格式说明符`%.*s`吗？这种格式用于打印特定长度的字符串（不需要终止空字符！）。首先，指定要打印的字节数，然后是字符串的指针。

# 测试案例 9

**返回后使用**（**UAR**）。另一个经典的错误，这个错误涉及将存储项（或指向它的指针）返回给调用函数。问题在于存储是局部的或自动的，因此一旦返回受影响，存储对象现在就超出了范围。

这里显示了一个经典的例子：我们为一个局部变量分配了`32`字节，初始化它，并将其返回给调用者：

```
/* test case 9 : UAR (use-after-return) test case */
static void * uar(void)
{
    char name[32];

    memset(name, 0, 32);
    strncpy(name, "Hands-on Linux Sys Prg", 22);

    return name;
}
```

这是调用者调用前面的错误函数的方式：

```
[...]
    case 9:
            res = uar();
            printf("res: %s\n", (char *)res);
            break;
[...]
```

当然，一旦`uar()`函数中的`return`语句生效，`name`变量就会自动超出范围！因此，指向它的指针是无效的，运行时会失败：

```
$ ./membugs 2>&1 |grep -w 9
 option = 9 : UAR (use-after-return) test case
$ ./membugs 9
res: (null)
$ 
```

幸运的是，现代 GCC（我们使用的是 GCC ver 7.3.0）会警告我们这个常见的错误：

```
$ make membugs
gcc -Wall -c membugs.c -o membugs.o
membugs.c: In function ‘uar’:
membugs.c:143:9: warning: function returns address of local variable [-Wreturn-local-addr]
 return name;
 ^~~~
[...]
```

如前所述（但值得重申），请注意并修复所有警告！

实际上，有时这个错误会被忽视——看起来它工作正常，没有错误。这是因为没有实际的保证在函数返回时立即销毁堆栈内存帧——内存和编译器优化可能会保留帧（通常是为了重用）。然而，这是一个危险的错误，必须修复！

在下一章中，我们将介绍一些内存调试工具。事实上，Valgrind 和 Sanitizer 工具都无法捕捉到这个可能致命的错误。但是，适当使用 ASan 工具集确实可以捕捉到 UAR！继续阅读。

# 测试案例 10

双重释放。一旦释放了`malloc`系列缓冲区，就不允许再使用该指针。尝试再次释放相同的指针（而不是通过`malloc`系列 API 之一再次分配内存）是一个错误：双重释放。它会导致堆损坏；攻击者经常利用这样的错误来造成**拒绝服务**（**DoS**）攻击或更糟糕的情况（权限提升）。

这是一个简单的测试案例：

```
/* test case 10 : double-free test case */
static void doublefree(int cond)
{
    char *ptr;
    char name[]="Hands-on Linux Sys Prg";
    int n=512;

    printf("%s(): cond %d\n", __FUNCTION__, cond);
    ptr = malloc(n);
    if (!ptr)
        FATAL("malloc failed\n");
    strncpy(ptr, name, strlen(name));
    free(ptr);

    if (cond) {
        bogus = malloc(-1UL); /* will fail! */
        if (!bogus) {
            fprintf(stderr, "%s:%s:%d: malloc failed\n",
                       __FILE__, __FUNCTION__, __LINE__);
            free(ptr); /* Bug: double-free */
            exit(EXIT_FAILURE);
        }
    }
}
```

在前面的测试案例中，我们模拟了一个有趣且相当现实的场景：一个运行时条件（通过`cond`参数模拟）导致程序执行一个调用，让我们说，失败了——`malloc(-1UL)`几乎可以保证这种情况发生。

为什么？因为在 64 位操作系统上，`-1UL = 0xffffffffffffffff = 18446744073709551615 字节 = 16 EB`。这是 64 位虚拟地址空间的全部范围。

回到重点：在我们的 malloc 错误处理代码中，发生了一个错误的双重释放——之前释放的`ptr`指针——导致了双重释放错误。

真正的问题是，作为开发人员，我们经常不为错误处理代码路径编写（负面的）测试案例；然后一个缺陷就会逃脱检测进入现场：

```
$ ./membugs 10
doublefree(): cond 0
doublefree(): cond 1
membugs.c:doublefree:56: malloc failed
$ 
```

有趣的是，编译器确实警告我们关于错误（有缺陷）的第二次 malloc（但没有关于双重释放的警告！）；请参见以下内容：

```
$ make
[...]
membugs.c: In function ‘doublefree’:
membugs.c:125:9: warning: argument 1 value ‘18446744073709551615’ exceeds maximum object size 9223372036854775807 [-Walloc-size-larger-than=]
 bogus = malloc(-1UL); /* will fail! */
 ~~~~~~^~~~~~~~~~~~~~
In file included from membugs.c:18:0:
/usr/include/stdlib.h:539:14: note: in a call to allocation function ‘malloc’ declared here
 extern void *malloc (size_t __size) __THROW __attribute_malloc__ __wur;
 ^~~~~~
[...]
```

为了强调检测和修复此类错误的重要性——记住，这只是一个例子——我们展示了*国家漏洞数据库*（NVD）在过去 3 年内（在此写作时）关于双重释放错误的一些信息：[`nvd.nist.gov/vuln/search/results?adv_search=false&form_type=basic&results_type=overview&search_type=last3years&query=double+free`](https://nvd.nist.gov/vuln/search/results?adv_search=false&form_type=basic&results_type=overview&search_type=last3years&query=double+free)

在*国家漏洞数据库*（NVD）上执行的双重释放错误的搜索结果的部分截图（在此写作时）如下：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/50802625-fc81-4ea1-b8b2-09e417c38592.png)

完整的截图没有在这里显示。

# 泄漏

动态内存的黄金法则是释放你分配的内存。

内存泄漏是用来描述未能释放内存的情况。程序员认为内存区域确实已经被释放了。但实际上没有——这就是错误。因此，这使得认为已释放的内存区域对进程和系统不可用；实际上，它是不可用的，尽管它本应该是可用的。

据说内存已经泄漏了。那么为什么程序员不能在代码的其他地方通过调用 free 来处理这个内存指针呢？这实际上是问题的关键：在典型情况下，由于代码的实现方式，基本上不可能重新访问泄漏的内存指针。

一个快速的测试案例将证明这一点。

`amleaky`函数被故意编写成每次调用时泄漏`mem`字节的内存——它的参数。

# 测试案例 11

内存泄漏 - 情况 1：（简单的）内存泄漏测试案例。请参见以下代码片段：

```
static const size_t BLK_1MB = 1024*1024;
[...]
static void amleaky(size_t mem)
{
    char *ptr;

    ptr = malloc(mem);
    if (!ptr)
        FATAL("malloc(%zu) failed\n", mem);

    /* Do something with the memory region; else, the compiler
     * might just optimize the whole thing away!
     * ... and we won't 'see' the leak.
     */
    memset(ptr, 0, mem);

    /* Bug: no free, leakage */
}

[...]
/* test case 11 : memory leak test case 1: simple leak */
static void leakage_case1(size_t size)
{
 printf("%s(): will now leak %zu bytes (%ld MB)\n",
     __FUNCTION__, size, size/(1024*1024));
 amleaky(size);
}

[...]

 case 11:
     leakage_case1(32);
     leakage_case1(BLK_1MB);
     break;
[...]
```

正如大家可以清楚地看到的，在`amleaky`函数中，`ptr`内存指针是一个局部变量，因此一旦我们从有缺陷的函数返回，它就会丢失；这使得以后无法释放它。还要注意——注释解释了它——我们需要`memset`来强制编译器生成代码并使用内存区域。

对前面测试案例的快速构建和执行将显示，再次没有明显的编译时或运行时检测到泄漏的发生：

```
$ ./membugs 2>&1 | grep "memory leak"
 option = 11 : memory leak test case 1: simple leak
 option = 12 : memory leak test case 2: leak more (in a loop)
 option = 13 : memory leak test case 3: lib API leak
$ ./membugs 11
leakage_case1(): will now leak 32 bytes (0 MB)
leakage_case1(): will now leak 1048576 bytes (1 MB)
$ 
```

# 测试案例 12

内存泄漏情况 2 - 泄漏更多（在循环中）。很多时候，有缺陷的泄漏代码可能只会泄漏少量内存，几个字节。问题是，如果这个有泄漏的函数在进程执行期间被调用了数百次，甚至数千次，现在泄漏就变得显著了，但不幸的是，不会立即显现出来。

为了精确模拟这一点以及更多内容，我们执行两个测试案例（选项 12）：

+   我们分配并泄漏了少量内存（32 字节），但在循环中重复了 10 万次（因此，是的，我们最终泄漏了超过 3 MB）。

+   我们在循环中分配并泄漏了大量内存（1 MB），循环了 12 次（因此，我们最终泄漏了 12 MB）。

以下是相关代码：

```
[...]

/* test case 12 : memory leak test case 2: leak in a loop */
static void leakage_case2(size_t size, unsigned int reps)
{
    unsigned int i, threshold = 3*BLK_1MB;
    double mem_leaked;

    if (reps == 0)
        reps = 1;
    mem_leaked = size * reps;
    printf("%s(): will now leak a total of %.0f bytes (%.2f MB)"
            " [%zu bytes * %u loops]\n",
            __FUNCTION__, mem_leaked, mem_leaked/(1024*1024),
            size, reps);

    if (mem_leaked >= threshold)
        system("free|grep \"^Mem:\"");

    for (i=0; i<reps; i++) {
        if (i%10000 == 0)
            printf("%s():%6d:malloc(%zu)\n", __FUNCTION__, i, size);
        amleaky(size);
    }

    if (mem_leaked >= threshold)
       system("free|grep \"^Mem:\""); printf("\n");
}

[...]

  case 12:
 leakage_case2(32, 100000);
 leakage_case2(BLK_1MB, 12);
 break;
[...]
```

这个逻辑确保在每 10,000 次循环迭代时才显示泄漏循环中的`printf(3)`。

另外，我们想要看看内存是否确实泄漏了。为了以一种近似的方式来做到这一点，我们使用`free`实用程序：

```
$ free
 total     used       free    shared   buff/cache  available
Mem:  16305508   5906672   348744   1171944   10050092   10248116
Swap:  8000508         0  8000508
$ 
```

`free(1)`实用程序以千字节为单位显示系统整体上当前（近似）使用的内存量、空闲内存量和可用内存量。它进一步将已使用的内存分为共享、缓冲/页面缓存；它还显示`Swap`分区统计信息。我们还应该注意，使用`free(1)`来检测内存泄漏的方法并不被认为是非常准确的；这最多是一种粗略的方法。操作系统报告的已使用内存、空闲内存、缓存等等可能会有所不同。对于我们的目的来说，这是可以接受的。

我们感兴趣的是`Mem`行和`free`列的交集；因此，我们可以看到在总共可用的 16 GB 内存（RAM）中，当前空闲的内存量约为 348744 KB ~= 340 MB。

我们可以快速尝试一个一行脚本，只显示感兴趣的区域——`Mem`行：

```
$ free | grep "^Mem:"
Mem:  16305508   5922772   336436   1165960   10046300   10237452
$ 
```

在`Mem`之后的第三列是`free`内存（有趣的是，它已经从上一次的输出中减少了；这并不重要）。

回到程序；我们使用`system(3)`库 API 在 C 程序中运行前面的管道化的 shell 命令（我们将在第十章中构建我们自己的`system(3)`API 的小型模拟，*进程创建*）：

```
if (mem_leaked >= threshold) system("free|grep \"^Mem:\");
```

`if`语句确保只有在泄漏量大于等于 3 MB 时才会出现这个输出。

在执行后，这是输出：

```
$ ./membugs 12
leakage_case2(): will now leak a total of 3200000 bytes (3.05 MB) 
 [32 bytes * 100000 loops]
Mem:   16305508     5982408   297708   1149648   10025392   10194628
leakage_case2():     0:malloc(32)
leakage_case2(): 10000:malloc(32)
leakage_case2(): 20000:malloc(32)
leakage_case2(): 30000:malloc(32)
leakage_case2(): 40000:malloc(32)
leakage_case2(): 50000:malloc(32)
leakage_case2(): 60000:malloc(32)
leakage_case2(): 70000:malloc(32)
leakage_case2(): 80000:malloc(32)
leakage_case2(): 90000:malloc(32)
Mem:   16305508     5986996   293120   1149648   10025392   10190040

leakage_case2(): will now leak a total of 12582912 bytes (12.00 MB) 
 [1048576 bytes * 12 loops]
Mem:   16305508     5987500   292616   1149648   10025392   10189536
leakage_case2():     0:malloc(1048576)
Mem:   16305508     5999124   280992   1149648   10025392   10177912
$ 
```

我们看到两种情况正在执行；查看`free`列的值。我们将它们相减以查看泄漏的内存量：

+   我们在循环中分配并泄漏了一小部分内存（32 字节），但是循环了 100,000 次：`泄漏内存 = 297708 - 293120 = 4588 KB ~= 4.5 MB`

+   我们在循环中分配并泄漏了大量内存（1 MB），共 12 次：`泄漏内存 = 292616 - 280992 = 11624 KB ~= 11.4 MB`

当然，要意识到一旦进程死掉，它的所有内存都会被释放回系统。这就是为什么我们在进程还活着的时候执行了这个一行脚本。

# 测试案例 13

复杂情况——包装器 API。有时，人们会原谅地认为所有程序员都被教导：在调用 malloc（或 calloc、realloc）之后，调用 free。malloc 和 free 是一对！这有多难？如果是这样，为什么会有这么多隐蔽的泄漏错误呢？

泄漏缺陷发生并且难以准确定位的一个关键原因是因为一些 API——通常是第三方库 API——可能在内部执行动态内存分配，并期望调用者释放内存。API（希望）会记录这一重要事实；但是谁（半开玩笑地）会去读文档呢？

这实际上是现实世界软件中的问题的关键所在；它很复杂，我们在大型复杂项目上工作。很容易忽略的一个事实是，底层 API 分配内存，调用者负责释放它。这种情况确实经常发生。

在复杂的代码库（尤其是那些有意大利面代码的代码库）中，深度嵌套的层次结构使代码纠缠在一起，要执行所需的清理工作，包括释放内存，在每种可能的错误情况下都变得特别困难。

Linux 内核社区提供了一种干净但颇具争议的方式来保持清理代码路径的干净和良好运行，即使用本地跳转来执行集中的错误处理！这确实有帮助。想要了解更多吗？查看[`www.kernel.org/doc/Documentation/process/coding-style.rst`](https://www.kernel.org/doc/Documentation/process/coding-style.rst)中的第七部分，*函数的集中退出*。

# 测试案例 13.1

这是一个简单的例子。让我们用以下测试案例代码来模拟这个：

```
/* 
 * A demo: this function allocates memory internally; the caller
 * is responsible for freeing it!
 */
static void silly_getpath(char **ptr)
{
#include <linux/limits.h>
    *ptr = malloc(PATH_MAX);
    if (!ptr)
        FATAL("malloc failed\n");

    strcpy(*ptr, getenv("PATH"));
    if (!*ptr)
        FATAL("getenv failed\n");
}

/* test case 13 : memory leak test case 3: "lib" API leak */
static void leakage_case3(int cond)
{
    char *mypath=NULL;

    printf("\n## Leakage test: case 3: \"lib\" API"
        ": runtime cond = %d\n", cond);

    /* Use C's illusory 'pass-by-reference' model */
    silly_getpath(&mypath);
    printf("mypath = %s\n", mypath);

    if (cond) /* Bug: if cond==0 then we have a leak! */
        free(mypath);
}
```

我们这样调用它：

```
[...]
case 13:
     leakage_case3(0);
     leakage_case3(1);
     break;
```

和往常一样，没有编译器或运行时警告。这是输出（注意第一次调用是有 bug 的情况，因为`cond`的值为`0`，因此不会调用`free(3)`）：

```
$ ./membugs 13

## Leakage test: case 3: "lib" API: runtime cond = 0
mypath = /usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/sbin:/usr/sbin:/usr/local/sbin:/home/kai/MentorGraphics/Sourcery_CodeBench_Lite_for_ARM_GNU_Linux/bin/:/mnt/big/scratchpad/buildroot-2017.08.1/output/host/bin/:/sbin:/usr/sbin:/usr/local/sbin

## Leakage test: case 3: "lib" API: runtime cond = 1
mypath = /usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/sbin:/usr/sbin:/usr/local/sbin:/home/kai/MentorGraphics/Sourcery_CodeBench_Lite_for_ARM_GNU_Linux/bin/:/mnt/big/scratchpad/buildroot-2017.08.1/output/host/bin/:/sbin:/usr/sbin:/usr/local/sbin
$ 
```

通过查看输出看不出有 bug，这也是这些 bug 如此危险的部分原因！

这种情况对开发人员和测试人员来说非常关键；它值得检查一些真实世界的例子。

# 测试案例 13.2

例子——*Motif*库**。***Motif*是 X Window 系统的一部分的传统库；它被用于（也许仍在用）为 Unix（和类 Unix）系统开发 GUI。

为了举例说明，我们将专注于其中一个 API：`XmStringCreateLocalized(3)`。GUI 开发人员使用这个函数来创建 Motif 称之为“复合字符串”的东西——本质上，就是一个以特定区域设置（用于国际化 I18N）的文本为内容的字符串。这是它的签名：

```
#include <Xm/Xm.h>
XmString XmStringCreateLocalized(char *text);
```

所以，让我们想象一下，开发人员使用它来生成复合字符串（用于各种目的；很多时候是用于标签或按钮小部件的标签）。

那么问题出在哪里呢？

内存泄漏！怎么回事？从`XmStringCreateLocalized(3)`的 man 页面（[`linux.die.net/man/3/xmstringcreatelocalized`](https://linux.die.net/man/3/xmstringcreatelocalized)）上阅读文档：

```
[...]

The function will allocate space to hold the returned compound string. The application is responsible for managing the allocated space. The application can recover the allocated space by calling XmStringFree. 
[...]
```

显然，开发人员不仅必须调用`XmStringCreateLocalized(3)`，还必须记得通过调用`XmStringFree(3)`释放由它内部分配的复合字符串的内存！

如果不这样做，就会导致内存泄漏。我有这种情况的亲身经历——一个有 bug 的应用程序调用了`XmStringCreateLocalized(3)`，但没有调用它的对应函数`XmStringFree(3)`。更糟糕的是，这段代码经常运行，因为它是外部循环的一部分！所以，内存泄漏不断增加。

# 测试案例 13.3

例子——Nortel 移植项目。有一个关于 Nortel（加拿大一家大型电信和网络设备跨国公司）的开发人员在调试一个内存泄漏问题时遇到了很大困难的故事。问题的关键在于：在将 Unix 应用程序移植到 VxWorks 时，在测试过程中，他们注意到发生了一个小的 18 字节的内存泄漏，最终导致应用程序崩溃。找到内存泄漏的源头是一场噩梦——无休止地审查代码没有提供任何线索。最终，改变游戏规则的是使用了一个内存泄漏检测工具（我们将在接下来的第六章中介绍，*内存问题调试工具*）。几分钟内，他们发现了内存泄漏的根本原因：一个看似无害的 API，`inet_ntoa(3)`（参见信息框），在 Unix 上和 VxWorks 上都是正常工作的。问题在于，在 VxWorks 的实现中，它在幕后分配了内存——调用者有责任释放！这个事实是有文档记录的，但这是一个移植项目！一旦意识到这一点，问题很快就解决了。

文章：嵌入式调试的十个秘密，Schneider 和 Fraleigh：[`www.embedded.com/design/prototyping-and-development/4025015/The-ten-secrets-of-embedded-debugging`](https://www.embedded.com/design/prototyping-and-development/4025015/The-ten-secrets-of-embedded-debugging)

`inet_ntoa(3)`的 man 页面条目指出：`inet_ntoa()`函数将以网络字节顺序给出的 Internet 主机地址转换为 IPv4 点分十进制表示的字符串。字符串以静态分配的缓冲区返回，后续调用将覆盖它。

关于有内存泄漏 bug 的程序的一些观察：

+   程序在很长一段时间内表现正常；突然之间，比如说，运行一个月后，它突然崩溃了。

+   根源的内存泄漏可能非常小——每次只有几个字节；但可能经常被调用。

+   通过仔细匹配你的`malloc(3)`和`free(3)`的实例来寻找泄漏错误是行不通的；库 API 包装器通常在后台分配内存，并期望调用者释放它。

+   泄漏通常会被忽视，因为它们在大型代码库中很难被发现，一旦进程死掉，泄漏的内存就会被释放回系统。

底线：

+   不要假设任何事情

+   仔细阅读 API 文档

+   使用工具（在即将到来的第六章中涵盖的*内存问题调试工具*）

不能过分强调使用工具检测内存错误的重要性！

# 未定义行为

我们已经涵盖了相当多的内容，并看到了一些常见的内存错误，包括：

+   不正确的内存访问

+   使用未初始化的变量

+   越界内存访问（读/写下溢/溢出错误）

+   释放后使用/返回后使用（超出范围）错误

+   双重释放

+   泄漏

+   数据竞争（详细信息将在后面的章节中介绍）

如前所述，所有这些都属于一个通用的分类——UB。正如短语所暗示的，一旦发生这些错误中的任何一个，进程（或线程）的行为就会变得*未定义*。更糟糕的是，其中许多错误并不显示任何直接可见的副作用；但进程是不稳定的，并且最终会崩溃。特别是泄漏错误在其中是主要的破坏者：泄漏可能在崩溃实际发生之前存在很长时间。不仅如此，留下的痕迹（开发人员将气喘吁吁地追踪）往往可能是一个误导——与错误根本原因无关紧要的事情，没有真正影响错误根本原因的事情。当然，所有这些都使得调试 UB 成为大多数人都愿意避免的经历！

好消息是，只要开发人员了解 UB 的根本原因（我们在前面的章节中已经涵盖了），并且有能力使用强大的工具来发现并修复这些错误，UB 是可以避免的，这也是我们下一个话题领域。

要深入了解许多可能的 UB 错误，请查看：*附录 J.2：未定义行为*：C 中未定义行为的非规范、非穷尽列表：[`www.open-std.org/jtc1/sc22/wg14/www/docs/n1548.pdf#page=571`](http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1548.pdf#page=571)。

来自深入的 C 编程语言标准——ISO/IEC 9899:201x 委员会草案，日期为 2010 年 12 月 2 日。

同样，还请参阅*CWE VIEW：C 编写的软件中的弱点*：[`cwe.mitre.org/data/definitions/658.html`](https://cwe.mitre.org/data/definitions/658.html)。

# 碎片

碎片问题通常指的是主要由内存分配引擎的内部实现面临的问题，而不是典型的应用程序开发人员所面临的问题。碎片问题通常有两种类型：内部和外部。

外部碎片通常指的是这样一种情况：在系统运行了几天后，即使系统上的空闲内存为 100MB，物理上连续的空闲内存可能少于 1MB。因此，随着进程获取和释放各种大小的内存块，内存变得碎片化。

内部碎片通常指的是由于使用低效的分配策略而导致的内存浪费；然而，这通常是无法避免的，因为浪费往往是许多基于堆的分配器的副作用。现代的 glibc 引擎使用内存池，大大减少了内部碎片。

我们不打算在本书中深入探讨碎片问题。

可以说，如果在一个大型项目中你怀疑存在碎片问题，你应该尝试使用一个显示进程运行时内存映射的工具（在 Linux 上，可以查看`/proc/<PID>/maps`作为起点）。通过解释它，你可能可以重新设计你的应用程序以避免这种碎片。

# 杂项

同时，要意识到，除非已经分配了内存，否则尝试仅使用指针来访问内存是一个错误。记住指针本身没有内存；它们必须分配内存（无论是在编译时静态分配还是在运行时动态分配）。

例如，有人编写了一个使用参数作为返回值的 C 函数——这是一种常见的 C 编程技巧（这些通常被称为值-结果或输入-输出参数）：

```
unsigned long *uptr; 
[...] 
    my_awesome_func(uptr); // bug! value to be returned in 'uptr'
[...]
```

这是一个错误；`uptr`变量只是一个指针——它没有内存。修复这个问题的一种方法如下：

```
unsigned long *uptr; 
[...]
    uptr = malloc(sizeof(unsigned long));
    if (!uptr) {
        [...handle the error...]
    }
    my_awesome_func(uptr); // value returned in 'uptr'
    [...]
    free(uptr);
```

或者，更简单地说，为什么不在这种情况下使用编译时内存：

```
unsigned long uptr; // compile-time allocated memory
[...] 
    my_awesome_func(&uptr); // value returned in 'uptr'
[...]
```

# 总结

在本章中，我们深入研究了一个关键领域：看似简单的动态内存管理 API 在实际应用系统中可能引发深层次且难以检测的错误。

我们讨论了内存错误的常见类别，比如未初始化的内存使用（UMR），越界访问（读取|写入下溢|溢出错误）和双重释放。内存泄漏是一种常见且危险的内存错误——我们看了三种不同的情况。

提供的`membugs`程序帮助读者通过小型测试案例实际看到并尝试各种内存错误。在下一章中，我们将深入使用工具来帮助识别这些危险的缺陷。


# 第六章：内存问题调试工具

我们人类（我们假设是人类在阅读这本书，而不是某种形式的人工智能，尽管，谁知道现在）擅长许多复杂的任务；但是，我们也擅长许多平凡的任务。这就是为什么我们发明了计算机——配备了驱动它们的软件！

嗯。我们并不擅长发现深藏在 C（或汇编）代码中的细节——内存错误是我们人类可以使用帮助的典型案例。所以，猜猜看：我们发明了软件工具来帮助我们——它们做乏味的工作，检查我们数以百万计甚至数十亿行代码和二进制代码，并且在捕捉我们的错误方面非常有效。当然，说到底，最好的工具仍然是你的大脑，但是人们可能会问：谁和什么来调试我们用于调试的工具？答案当然是更多的工具，以及你，作为人类程序员。

在本章中，读者将学习如何使用两种最佳的内存调试工具：

+   Valgrind 的 Memcheck

+   Sanitizer 工具（ASan）

提供了有用的表格，总结和比较它们的特性。还可以看到通过`mallopt(3)`调整 glibc 的 malloc。

这一章没有自己的源代码；相反，我们使用了上一章的源代码，即第五章，*Linux 内存问题*。我们的`membugs`程序测试案例将在 Valgrind 和 ASan 下进行测试，以查看它们是否能捕捉到我们的*memugs*程序的测试案例努力提供的内存错误。因此，我们强烈建议您复习前一章和`membugs.c`源代码，以重新熟悉我们将要运行的测试案例。

# 工具类型

总的来说，在这些领域范围内，有两种工具：

+   动态分析工具

+   静态分析工具

动态分析工具基本上通过对运行时进程进行仪器化来工作。因此，为了充分利用它们，必须要花费大量精力来确保工具实际上覆盖了所有可能的代码路径；通过仔细而费力地编写测试案例来确保完整的代码覆盖。这是一个关键点，将在后面提到（重要的是，第十九章，*故障排除和最佳实践*，涵盖了这些要点）。虽然非常强大，但动态分析工具通常会导致显著的运行时性能损失和更多的内存使用。

另一方面，静态分析工具是针对源代码进行工作的；在这个意义上，它们类似于编译器。它们通常远远超出了典型的编译器，帮助开发人员发现各种潜在的错误。也许最初的 Unix *lint*程序可以被认为是今天强大的静态分析器的前身。如今，存在着非常强大的商业静态分析器（带有花哨的图形用户界面），并且值得花费在它们上的金钱和时间。缺点是这些工具可能会引发许多错误的警报；更好的工具可以让程序员执行有用的过滤。我们不会在本文中涵盖静态分析器（请参阅 GitHub 存储库上的*进一步阅读*部分，了解 C/C++的静态分析器列表）。

现在，让我们来看看一些现代内存调试工具；它们都属于动态分析工具类。确实要学会如何有效地使用它们——它们是对各种**未定义行为**（**UB**）的必要武器。

# Valgrind

Valgrind（发音为*val-grinned*）是一套强大工具的仪器化框架。它是**开源软件**（OSS），根据 GNU GPL ver. 2 的条款发布；它最初由 Julian Seward 开发。Valgrind 是一套用于内存调试和性能分析的获奖工具。它已经发展成为创建动态分析工具的框架。事实上，它实际上是一个虚拟机；Valgrind 使用一种称为**动态二进制仪器化**（DBI）的技术来对代码进行检测。在其主页上阅读更多信息：[`valgrind.org/`](http://valgrind.org/)。

Valgrind 的巨大优势在于其工具套件，主要是**Memory Checker**工具（**Memcheck**）。还有其他几个检查器和性能分析工具，按字母顺序列在下表中：

| **Valgrind 工具名称** | **目的** |
| --- | --- |
| cachegrind | CPU 缓存性能分析器。 |
| callgrind | cachegrind 的扩展；提供更多的调用图信息。KCachegrind 是 cachegrind/callgrind 的良好 GUI 可视化工具。 |
| drd | Pthreads 错误检测器。 |
| helgrind | 多线程应用程序（主要是 Pthreads）的数据竞争检测器。 |
| massif | 堆分析器（堆使用情况图表，最大分配跟踪）。 |
| Memcheck | 内存错误检测器；包括**越界**（**OOB**）访问（读取 | 写入 | 溢出），未初始化数据访问，UAF，UAR，内存泄漏，双重释放和重叠内存区域错误。这是默认工具。 |

请注意，一些较少使用的工具（如 lackey、nulgrind、none）和一些实验性工具（exp-bbv、exp-dhat、exp-sgcheck）没有在表中显示。

通过`--tool=`选项选择 Valgrind 要运行的工具（将前述任何一个作为参数）。在本书中，我们只关注 Valgrind 的 Memcheck 工具。

# 使用 Valgrind 的 Memcheck 工具

Memcheck 是 Valgrind 的默认工具；你不需要显式传递它，但可以使用`valgrind --tool=memcheck <要执行的程序及参数>`语法来执行。

作为一个简单的例子，让我们在 Ubuntu 上运行 Valgrind 对`df(1)`实用程序进行检测：

```
$ lsb_release -a
No LSB modules are available.
Distributor ID:    Ubuntu
Description:    Ubuntu 17.10
Release:    17.10
Codename:    artful
$ df --version |head -n1
df (GNU coreutils) 8.26
$ valgrind df
==1577== Memcheck, a memory error detector
==1577== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==1577== Using Valgrind-3.13.0 and LibVEX; rerun with -h for copyright info
==1577== Command: df
==1577== 
Filesystem     1K-blocks    Used Available Use% Mounted on
udev              479724       0    479724   0% /dev
tmpfs             100940   10776     90164  11% /run
/dev/sda1       31863632 8535972  21686036  29% /
tmpfs             504692       0    504692   0% /dev/shm
tmpfs               5120       0      5120   0% /run/lock
tmpfs             504692       0    504692   0% /sys/fs/cgroup
tmpfs             100936       0    100936   0% /run/user/1000
==1577== 
==1577== HEAP SUMMARY:
==1577==     in use at exit: 3,577 bytes in 213 blocks
==1577==   total heap usage: 447 allocs, 234 frees, 25,483 bytes allocated
==1577== 
==1577== LEAK SUMMARY:
==1577==    definitely lost: 0 bytes in 0 blocks
==1577==    indirectly lost: 0 bytes in 0 blocks
==1577==      possibly lost: 0 bytes in 0 blocks
==1577==    still reachable: 3,577 bytes in 213 blocks
==1577==         suppressed: 0 bytes in 0 blocks
==1577== Rerun with --leak-check=full to see details of leaked memory
==1577== 
==1577== For counts of detected and suppressed errors, rerun with: -v
==1577== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
$ 
```

Valgrind 实际上接管并在其中运行`df`进程，对所有动态内存访问进行检测。然后打印出其报告。在前面的代码中，这些行都以`==1577==`为前缀；那只是`df`进程的 PID 而已。

没有发现运行时内存错误，因此没有输出（当我们在 Valgrind 的控制下运行我们的`membugs`程序时，很快你就会看到差异）。就内存泄漏而言，报告指出：

```
definitely lost: 0 bytes in 0 blocks
```

所有这些都是零值，所以没问题。如果`definitely lost`下的值为正数，那么这确实会表明存在必须进一步调查和修复的内存泄漏错误。其他标签——`indirectly`/`possibly lost`，`still reachable`——通常是由于代码库中复杂或间接的内存处理而产生的（实际上，它们通常是可以忽略的假阳性）。

`still reachable`通常表示在进程退出时，一些内存块未被应用程序显式释放（但在进程死亡时被隐式释放）。以下语句显示了这一点：

+   **退出时使用**：213 个块中的 3,577 字节

+   **总堆使用情况**：447 次分配，234 次释放，25,483 字节

在总共的 447 次分配中，只有 234 次释放，剩下了 447 - 234 = 213 个未释放的块。

好了，现在来看有趣的部分：让我们运行我们的`membugs`程序测试用例（来自前面的第五章，*Linux 内存问题*）在 Valgrind 下运行，并看看它是否能捕捉到测试用例努力提供的内存错误。

我们强烈建议您回顾前一章和`membugs.c`源代码，以便重新熟悉我们将要运行的测试用例。

membugs 程序共有 13 个测试用例；我们不打算在书中展示所有测试用例的输出；我们把这留给读者作为一个练习，尝试在 Valgrind 下运行程序并解密其输出报告。

大多数读者可能会对本节末尾的摘要表感兴趣，该表显示了在每个测试用例上运行 Valgrind 的结果。

**测试用例＃1：未初始化内存访问**

```
$ ./membugs 1
true: x=32568
$ 
```

为了便于阅读，我们删除了以下显示的部分并截断了程序路径名。

现在处于 Valgrind 的控制之下：

```
$ valgrind ./membugs 1
==19549== Memcheck, a memory error detector
==19549== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==19549== Using Valgrind-3.13.0 and LibVEX; rerun with -h for copyright info
==19549== Command: ./membugs 1
==19549== 
==19549== Conditional jump or move depends on uninitialised value(s)
==19549==    at 0x40132C: uninit_var (in <...>/ch3/membugs)
==19549==    by 0x401451: process_args (in <...>/ch3/membugs)
==19549==    by 0x401574: main (in <...>/ch3/membugs)
==19549==  

[...] 

==19549== Conditional jump or move depends on uninitialised value(s)
==19549==    at 0x4E9101C: vfprintf (in /usr/lib64/libc-2.26.so)
==19549==    by 0x4E99255: printf (in /usr/lib64/libc-2.26.so)
==19549==    by 0x401357: uninit_var (in <...>/ch3/membugs)
==19549==    by 0x401451: process_args (in <...>/ch3/membugs)
==19549==    by 0x401574: main (in <...>/ch3/membugs)
==19549== 
false: x=0
==19549== 
==19549== HEAP SUMMARY:
==19549==     in use at exit: 0 bytes in 0 blocks
==19549==   total heap usage: 1 allocs, 1 frees, 1,024 bytes allocated
==19549== 
==19549== All heap blocks were freed -- no leaks are possible
==19549== 
==19549== For counts of detected and suppressed errors, rerun with: -v
==19549== Use --track-origins=yes to see where uninitialised values come from
==19549== ERROR SUMMARY: 6 errors from 6 contexts (suppressed: 0 from 0)
$ 
```

显然，Valgrind 捕捉到了未初始化的内存访问错误！粗体突出显示的文本清楚地揭示了这种情况。

但是，请注意，尽管 Valgrind 可以向我们显示调用堆栈（包括进程路径名），但似乎无法向我们显示源代码中存在错误的行号。不过，我们可以通过使用程序的启用调试版本来精确地实现这一点：

```
$ make membugs_dbg
gcc -g -ggdb -gdwarf-4 -O0 -Wall -Wextra -c membugs.c -o membugs_dbg.o

[...]

membugs.c: In function ‘uninit_var’:
membugs.c:283:5: warning: ‘x’ is used uninitialized in this function [-Wuninitialized]
  if (x > MAXVAL)
     ^

[...] 

gcc -g -ggdb -gdwarf-4 -O0 -Wall -Wextra -c ../common.c -o common_dbg.o
gcc -o membugs_dbg membugs_dbg.o common_dbg.o

[...]
```

用于调试的常见 GCC 标志

有关详细信息，请参阅`gcc(1)`的 man 页面。简而言之：`-g`：生成足够的调试信息，使得诸如**GNU 调试器**（GDB）之类的工具必须使用符号信息来进行调试（现代 Linux 通常会使用 DWARF 格式）。

`-ggdb`：使用操作系统可能的最表达格式。

`-gdwarf-4`：调试信息以 DWARF-<version>格式（版本 4 适用）。

`-O0`：优化级别`0`；用于调试。

在以下代码中，我们重试了使用启用调试版本的二进制可执行文件`membugs_dbg`运行 Valgrind：

```
$ valgrind --tool=memcheck ./membugs_dbg 1
==20079== Memcheck, a memory error detector
==20079== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==20079== Using Valgrind-3.13.0 and LibVEX; rerun with -h for copyright info
==20079== Command: ./membugs_dbg 1
==20079== 
==20079== Conditional jump or move depends on uninitialised value(s)
==20079== at 0x40132C: uninit_var (membugs.c:283)
==20079== by 0x401451: process_args (membugs.c:326)
==20079== by 0x401574: main (membugs.c:379)
==20079== 
==20079== Conditional jump or move depends on uninitialised value(s)
==20079== at 0x4E90DAA: vfprintf (in /usr/lib64/libc-2.26.so)
==20079== by 0x4E99255: printf (in /usr/lib64/libc-2.26.so)
==20079== by 0x401357: uninit_var (membugs.c:286)
==20079== by 0x401451: process_args (membugs.c:326)
==20079== by 0x401574: main (membugs.c:379)
==20079== 
==20079== Use of uninitialised value of size 8
==20079== at 0x4E8CD7B: _itoa_word (in /usr/lib64/libc-2.26.so)
==20079== by 0x4E9043D: vfprintf (in /usr/lib64/libc-2.26.so)
==20079== by 0x4E99255: printf (in /usr/lib64/libc-2.26.so)
==20079== by 0x401357: uninit_var (membugs.c:286)
==20079== by 0x401451: process_args (membugs.c:326)
==20079== by 0x401574: main (membugs.c:379) 

[...]

==20079== 
false: x=0
==20079== 
==20079== HEAP SUMMARY:
==20079== in use at exit: 0 bytes in 0 blocks
==20079== total heap usage: 1 allocs, 1 frees, 1,024 bytes allocated
==20079== 
==20079== All heap blocks were freed -- no leaks are possible
==20079== 
==20079== For counts of detected and suppressed errors, rerun with: -v
==20079== Use --track-origins=yes to see where uninitialised values come from
==20079== ERROR SUMMARY: 6 errors from 6 contexts (suppressed: 0 from 0)
$
```

像往常一样，以自下而上的方式阅读调用堆栈，它就会有意义！

重要提示：请注意，不幸的是，输出中显示的精确行号可能与书中 GitHub 存储库中最新版本的源文件中的行号不完全匹配。

以下是源代码（此处使用`nl`实用程序显示所有行编号的代码）：

```
$  nl --body-numbering=a membugs.c [...]  

   278    /* option =  1 : uninitialized var test case */
   279    static void uninit_var()
   280    {
   281        int x;
   282    
 283        if (x)   284            printf("true case: x=%d\n", x);
   285        else
   286           printf("false case\n");
   287    } 

[...]

   325            case 1:
   326                uninit_var();
   327                 break; 

[...]

   377    int main(int argc, char **argv)
   378    {
   379        process_args(argc, argv);
   380         exit(EXIT_SUCCESS);
   381    }
```

我们现在可以看到 Valgrind 确实完美地捕捉到了错误的情况。

**测试用例＃5：** 编译时内存读取溢出：

```
$ valgrind ./membugs_dbg 5
==23024== Memcheck, a memory error detector
==23024== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==23024== Using Valgrind-3.13.0 and LibVEX; rerun with -h for copyright info
==23024== Command: ./membugs_dbg 5
==23024== 
arr = aaaaa����
==23024== 
==23024== HEAP SUMMARY:
==23024==     in use at exit: 0 bytes in 0 blocks
==23024==   total heap usage: 1 allocs, 1 frees, 1,024 bytes allocated
==23024== 
==23024== All heap blocks were freed -- no leaks are possible
==23024== 
==23024== For counts of detected and suppressed errors, rerun with: -v
==23024== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
$ 
```

看看！Valgrind 未能捕捉到读取溢出内存错误。为什么？这是一个限制：Valgrind 只能对动态分配的内存进行插装和捕捉 UB（错误）。前面的测试用例使用了静态编译时分配的内存。

因此，让我们尝试相同的测试，但这次使用动态分配的内存；这正是测试用例＃6 的设计目的。

**测试用例＃6：** 动态内存上的读取溢出（为了便于阅读，我们截断了部分输出）：

```
$ ./membugs_dbg 2>&1 |grep 6
 option =  6 : out-of-bounds : read overflow [on dynamic memory]
$ valgrind ./membugs_dbg 6
[...]
==23274== Command: ./membugs_dbg 6
==23274== 
==23274== Invalid write of size 1
==23274==    at 0x401127: read_overflow_dynmem (membugs.c:215)
==23274==    by 0x401483: process_args (membugs.c:341)
==23274==    by 0x401574: main (membugs.c:379)
==23274==  Address 0x521f045 is 0 bytes after a block of size 5 alloc'd
==23274==    at 0x4C2FB6B: malloc (vg_replace_malloc.c:299)
==23274==    by 0x4010D9: read_overflow_dynmem (membugs.c:205)
==23274==    by 0x401483: process_args (membugs.c:341)
==23274==    by 0x401574: main (membugs.c:379)
[...]
==23274== Invalid write of size 1
==23274==    at 0x40115E: read_overflow_dynmem (membugs.c:216)
==23274==    by 0x401483: process_args (membugs.c:341)
==23274==    by 0x401574: main (membugs.c:379)
==23274==  Address 0x521f04a is 5 bytes after a block of size 5 alloc'd
==23274==    at 0x4C2FB6B: malloc (vg_replace_malloc.c:299)
==23274==    by 0x4010D9: read_overflow_dynmem (membugs.c:205)
==23274==    by 0x401483: process_args (membugs.c:341)
==23274==    by 0x401574: main (membugs.c:379)
==23274== 
==23274== Invalid read of size 1
==23274==    at 0x4C32B94: strlen (vg_replace_strmem.c:458)
==23274==    by 0x4E91955: vfprintf (in /usr/lib64/libc-2.26.so)
==23274==    by 0x4E99255: printf (in /usr/lib64/libc-2.26.so)
==23274==    by 0x401176: read_overflow_dynmem (membugs.c:217)
==23274==    by 0x401483: process_args (membugs.c:341)
==23274==    by 0x401574: main (membugs.c:379)
==23274==  Address 0x521f045 is 0 bytes after a block of size 5 alloc'd
==23274==    at 0x4C2FB6B: malloc (vg_replace_malloc.c:299)
==23274==    by 0x4010D9: read_overflow_dynmem (membugs.c:205)
==23274==    by 0x401483: process_args (membugs.c:341)
==23274==    by 0x401574: main (membugs.c:379)
[...]
arr = aaaaaSecreT
==23274== Conditional jump or move depends on uninitialised value(s)
==23274==    at 0x4E90DAA: vfprintf (in /usr/lib64/libc-2.26.so)
==23274==    by 0x4E99255: printf (in /usr/lib64/libc-2.26.so)
==23274==    by 0x401195: read_overflow_dynmem (membugs.c:220)
==23274==    by 0x401483: process_args (membugs.c:341)
==23274==    by 0x401574: main (membugs.c:379)
==23274== 
==23274== Use of uninitialised value of size 8
==23274==    at 0x4E8CD7B: _itoa_word (in /usr/lib64/libc-2.26.so)
==23274==    by 0x4E9043D: vfprintf (in /usr/lib64/libc-2.26.so)
==23274==    by 0x4E99255: printf (in /usr/lib64/libc-2.26.so)
==23274==    by 0x401195: read_overflow_dynmem (membugs.c:220)
==23274==    by 0x401483: process_args (membugs.c:341)
==23274==    by 0x401574: main (membugs.c:379)
[...]
==23274== ERROR SUMMARY: 31 errors from 17 contexts (suppressed: 0 from 0)
$ 
```

这一次，大量的错误被捕捉到，显示了源代码中的确切位置（因为我们使用了`-g`进行编译）。

**测试用例＃8：** **UAF**（释放后使用）：

```
$ ./membugs_dbg 2>&1 |grep 8
 option =  8 : UAF (use-after-free) test case
$ 
```

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/8edb68da-2b47-4a7d-884a-5184c6a8bbe9.png)

当 Valgrind 捕捉到 UAF 错误时的（部分）屏幕截图

Valgrind 确实捕捉到了 UAF！

**测试用例＃8：** **UAR**（返回后使用）：

```
$ ./membugs_dbg 9
res: (null)
$ valgrind ./membugs_dbg 9
==7594== Memcheck, a memory error detector
==7594== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==7594== Using Valgrind-3.13.0 and LibVEX; rerun with -h for copyright info
==7594== Command: ./membugs_dbg 9
==7594== 
res: (null)
==7594== 
==7594== HEAP SUMMARY:
==7594==     in use at exit: 0 bytes in 0 blocks
==7594==   total heap usage: 1 allocs, 1 frees, 1,024 bytes allocated
==7594== 
==7594== All heap blocks were freed -- no leaks are possible
==7594== 
==7594== For counts of detected and suppressed errors, rerun with: -v
==7594== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
$ 
```

哎呀！Valgrind 没有捕捉到 UAR 错误！

**测试用例＃13：** 内存泄漏案例＃3—lib API 泄漏。我们通过选择 13 作为*membugs*的参数来运行内存泄漏测试用例＃3。值得注意的是，只有在使用`--leak-check=full`选项运行时，Valgrind 才会显示泄漏的来源（通过显示的调用堆栈）：

```
$ valgrind --leak-resolution=high --num-callers=50 --leak-check=full ./membugs_dbg 13
==22849== Memcheck, a memory error detector
==22849== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==22849== Using Valgrind-3.13.0 and LibVEX; rerun with -h for copyright info
==22849== Command: ./membugs_dbg 13
==22849== 

## Leakage test: case 3: "lib" API: runtime cond = 0
mypath = /usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/sbin:/usr/sbin:/usr/local/sbin:/home/kai/MentorGraphics/Sourcery_CodeBench_Lite_for_ARM_GNU_Linux/bin/:/mnt/big/scratchpad/buildroot-2017.08.1/output/host/bin/:/sbin:/usr/sbin:/usr/local/sbin

## Leakage test: case 3: "lib" API: runtime cond = 1
mypath = /usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/sbin:/usr/sbin:/usr/local/sbin:/home/kai/MentorGraphics/Sourcery_CodeBench_Lite_for_ARM_GNU_Linux/bin/:/mnt/big/scratchpad/buildroot-2017.08.1/output/host/bin/:/sbin:/usr/sbin:/usr/local/sbin
==22849== 
==22849== HEAP SUMMARY:
==22849==     in use at exit: 4,096 bytes in 1 blocks
==22849==   total heap usage: 3 allocs, 2 frees, 9,216 bytes allocated
==22849== 
==22849== 4,096 bytes in 1 blocks are definitely lost in loss record 1 of 1
==22849==    at 0x4C2FB6B: malloc (vg_replace_malloc.c:299)
==22849==    by 0x400A0C: silly_getpath (membugs.c:38)
==22849==    by 0x400AC6: leakage_case3 (membugs.c:59)
==22849==    by 0x40152B: process_args (membugs.c:367)
==22849==    by 0x401574: main (membugs.c:379)
==22849== 
==22849== LEAK SUMMARY:
==22849==    definitely lost: 4,096 bytes in 1 blocks
==22849==    indirectly lost: 0 bytes in 0 blocks
==22849==      possibly lost: 0 bytes in 0 blocks
==22849==    still reachable: 0 bytes in 0 blocks
==22849==         suppressed: 0 bytes in 0 blocks
==22849== 
==22849== For counts of detected and suppressed errors, rerun with: -v
==22849== ERROR SUMMARY: 1 errors from 1 contexts (suppressed: 0 from 0)
$ 
```

Valgrind 的 man 页面建议设置`--leak-resolution=high`和`--num-callers=`为 40 或更高。

`valgrind(1)`的 man 页面涵盖了它提供的许多选项（如日志和工具（Memcheck）选项）；请查看以更深入地了解此工具的用法。

# Valgrind 摘要表

关于我们的测试用例（并入我们的`membugs`程序），以下是 Valgrind 的报告卡和内存错误如下：

| **测试用例＃** | **测试用例** | **Valgrind 检测到了吗？** |
| --- | --- | --- |
| 1 | **未初始化内存读取**（UMR） | 是 |
| 2 | **越界**（**OOB**）：写入溢出[在编译时内存上] | 否 |
| 3 | OOB：写入溢出[在动态内存上] | 是 |
| 4 | OOB：写入下溢[在动态内存上] | 是 |
| 5 | OOB：读取溢出[在编译时内存上] | 否 |
| 6 | OOB：读取溢出[在动态内存上] | 是 |
| 7 | OOB：读取下溢[在动态内存上] | 是 |
| 8 | UAF，也称为悬空指针 | 是 |
| 9 | UAR，也称为**use-after-scope**(**UAS**) | 否 |
| 10 | 重复释放 | 是 |
| 11 | 内存泄漏测试案例 1：简单泄漏 | 是 |
| 12 | 内存泄漏测试案例 1：泄漏更多（循环中） | 是 |
| 13 | 内存泄漏测试案例 1：库 API 泄漏 | 是 |

# Valgrind 优点和缺点：快速总结

Valgrind 优点*：*

+   捕获动态分配内存区域上的常见内存错误（UB）

+   使用未初始化的变量

+   越界内存访问（读取/写入下溢/溢出错误）

+   释放后使用/返回后使用（超出范围）错误

+   重复释放

+   泄漏

+   无需修改源代码

+   无需重新编译

+   无需特殊的编译器标志

Valgrind 缺点：

+   性能：在 Valgrind 下运行目标软件可能会慢 10 到 30 倍。

+   内存占用：目标程序中的每个分配都需要 Valgrind 进行内存分配（在高资源约束的嵌入式 Linux 系统上运行 Valgrind 变得困难）。

+   无法捕获静态（编译时）分配的内存区域上的错误。

+   为了查看带有行号信息的调用堆栈，需要使用`-g`标志重新编译/构建。

事实上，Valgrind 仍然是对抗错误的有力武器。有许多真实世界的项目使用 Valgrind；在[`valgrind.org/gallery/users.html`](http://valgrind.org/gallery/users.html)上查看长列表*.*

总是有更多可以学习和探索的：Valgrind 提供了 GDB 监视器模式，允许您通过**GNU 调试器**（**GDB**）对程序进行高级调试。这对于在从不终止的程序上使用 Valgrind 特别有用（守护进程是典型案例）。

Valgrind 手册的第三章在这方面非常有帮助：[`valgrind.org/docs/manual/manual-core-adv.html`](http://valgrind.org/docs/manual/manual-core-adv.html)

# Sanitizer 工具

Sanitizer 是来自 Google 的一套开源工具；与其他内存调试工具一样，它们解决了通常的常见内存错误和 UB 问题，包括 OOB（越界访问：读取/写入下溢/溢出）、UAF、UAR、重复释放和内存泄漏。其中一个工具还处理 C/C++代码中的数据竞争。

一个关键区别是，Sanitizer 工具通过编译器向代码引入了插装。它们使用一种称为**编译时插装**（CTI）的技术以及影子内存技术。截至目前，ASan 是 GCC ver 4.8 和 LLVM（Clang）ver. 3.1 及以上的一部分并支持它。

# Sanitizer 工具集

要使用给定的工具，需要使用 Usage 列中显示的标志编译程序：

| **Sanitizer 工具（简称）** | **目的** | **使用（编译器标志）** | **Linux 平台[+注释]** |
| --- | --- | --- | --- |
| **AddressSanitizer** (**ASan**) | 检测通用内存错误[堆栈全局缓冲区溢出、UAF、UAR、初始化顺序错误] | `-fsanitize=address` | x86、x86_64、ARM、Aarch64、MIPS、MIPS64、PPC64\. [不能与 TSan 组合] |
| **Kernel AddressSanitizer** (**KASAN**) | 用于 Linux 内核空间的 ASan | `-fsanitize=kernel-address` | x86_64 [内核版本>=4.0]，Aarch64 [内核版本>= 4.4] |
| **MemorySanitizer** (**MSan**) | UMR 检测器 | `-fsanitize=memory -fPIE -pie [-fno-omit-frame-pointer]`  | 仅适用于 Linux x86_64 |
| **ThreadSanitizer** (**TSan**) | 数据竞争检测器 | `-fsanitize=thread` | 仅适用于 Linux x86_64。[不能与 ASan 或 LSan 标志组合] |
| **LeakSanitizer** (**LSan**)（ASan 的子集） | 内存泄漏检测器 | `-fsanitize=leak` | Linux x86_64 和 OS X [不能与 TSan 组合] |
| **UndefinedBehaviorSanitizer** (**UBSan**) | UB 检测器 | `-fsanitize=undefined` | x86, x86_64, ARM, Aarch64, PPC64, MIPS, MIPS64 |

额外的文档 Google 维护着一个 GitHub 页面，其中包含有关 sanitizer 工具的文档：

+   [`github.com/google/sanitizers`](https://github.com/google/sanitizers)

+   [`github.com/google/sanitizers/wiki`](https://github.com/google/sanitizers/wiki)

+   [`github.com/google/sanitizers/wiki/SanitizerCommonFlags`](https://github.com/google/sanitizers/wiki/SanitizerCommonFlags)

每个工具的个别 wiki（文档）页面都有链接。建议您在使用工具时仔细阅读它们（例如，每个工具可能具有用户可以利用的特定标志和/或环境变量）。

`gcc(1)`的 man 页面是关于`-fsanitize=`sanitizer 工具 gcc 选项的复杂信息的丰富来源。有趣的是，大多数 sanitizer 工具也支持 Android（>=4.1）平台。

Clang 文档还记录了使用 sanitizer 工具的方法：[`clang.llvm.org/docs/index.html`](https://clang.llvm.org/docs/index.html)。

在本章中，我们专注于使用 ASan 工具。

# 为 ASan 构建程序

正如前表所示，我们需要使用适当的编译器标志来编译我们的目标应用程序 membugs。此外，建议使用`clang`而不是`gcc`作为编译器。

`clang`被认为是几种编程语言的编译器前端，包括 C 和 C++；后端是 LLVM 编译器基础设施项目。关于 Clang 的更多信息可以在其维基百科页面上找到。

您需要确保在您的 Linux 系统上安装了 Clang 软件包；使用您的发行版的软件包管理器（`apt-get`，`dnf`，`rpm`）是最简单的方法。

我们的 Makefile 片段显示了我们如何使用`clang`来编译 membugs sanitizer 目标：

```
CC=${CROSS_COMPILE}gcc
CL=${CROSS_COMPILE}clang

CFLAGS=-Wall -UDEBUG
CFLAGS_DBG=-g -ggdb -gdwarf-4 -O0 -Wall -Wextra -DDEBUG
CFLAGS_DBG_ASAN=${CFLAGS_DBG} -fsanitize=address
CFLAGS_DBG_MSAN=${CFLAGS_DBG} -fsanitize=memory
CFLAGS_DBG_UB=${CFLAGS_DBG} -fsanitize=undefined

[...]

#--- Sanitizers (use clang): <foo>_dbg_[asan|ub|msan]
membugs_dbg_asan.o: membugs.c
    ${CL} ${CFLAGS_DBG_ASAN} -c membugs.c -o membugs_dbg_asan.o
membugs_dbg_asan: membugs_dbg_asan.o common_dbg_asan.o
    ${CL} ${CFLAGS_DBG_ASAN} -o membugs_dbg_asan membugs_dbg_asan.o common_dbg_asan.o

membugs_dbg_ub.o: membugs.c
    ${CL} ${CFLAGS_DBG_UB} -c membugs.c -o membugs_dbg_ub.o
membugs_dbg_ub: membugs_dbg_ub.o common_dbg_ub.o
    ${CL} ${CFLAGS_DBG_UB} -o membugs_dbg_ub membugs_dbg_ub.o common_dbg_ub.o

membugs_dbg_msan.o: membugs.c
    ${CL} ${CFLAGS_DBG_MSAN} -c membugs.c -o membugs_dbg_msan.o
membugs_dbg_msan: membugs_dbg_msan.o common_dbg_msan.o
    ${CL} ${CFLAGS_DBG_MSAN} -o membugs_dbg_msan membugs_dbg_msan.o common_dbg_msan.o
[...]
```

# 使用 ASan 运行测试用例

为了提醒我们，这是我们的 membugs 程序的帮助屏幕：

```
$ ./membugs_dbg_asan 
Usage: ./membugs_dbg_asan option [ -h | --help]
 option =  1 : uninitialized var test case
 option =  2 : out-of-bounds : write overflow [on compile-time memory]
 option =  3 : out-of-bounds : write overflow [on dynamic memory]
 option =  4 : out-of-bounds : write underflow
 option =  5 : out-of-bounds : read overflow [on compile-time memory]
 option =  6 : out-of-bounds : read overflow [on dynamic memory]
 option =  7 : out-of-bounds : read underflow
 option =  8 : UAF (use-after-free) test case
 option =  9 : UAR (use-after-return) test case
 option = 10 : double-free test case
 option = 11 : memory leak test case 1: simple leak
 option = 12 : memory leak test case 2: leak more (in a loop)
 option = 13 : memory leak test case 3: "lib" API leak
-h | --help : show this help screen
$ 
```

membugs 程序共有 13 个测试用例；我们不打算在本书中显示所有这些测试用例的输出；我们把它留给读者来尝试使用 ASan 构建和运行所有测试用例的程序，并解密其输出报告。读者有兴趣看到本节末尾的摘要表，显示在每个测试用例上运行 ASan 的结果。

**测试用例＃1：** UMR

让我们尝试第一个——未初始化变量读取测试用例：

```
$ ./membugs_dbg_asan 1
false case
$ 
```

它没有捕获到错误！是的，我们已经发现了 ASan 的限制：AddressSanitizer 无法捕获静态（编译时）分配的内存上的 UMR。Valgrind 可以。

MSan 工具已经处理了这个问题；它的具体工作是捕获 UMR 错误。文档说明 MSan 只能捕获动态分配的内存上的 UMR。我们发现它甚至捕获了一个在静态分配的内存上的 UMR 错误，而我们的简单测试用例使用了：

```
$ ./membugs_dbg_msan 1
==3095==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x496eb8 (<...>/ch5/membugs_dbg_msan+0x496eb8)
    #1 0x494425 (<...>/ch5/membugs_dbg_msan+0x494425)
    #2 0x493f2b (<...>/ch5/membugs_dbg_msan+0x493f2b)
    #3 0x7fc32f17ab96 (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
    #4 0x41a8c9 (<...>/ch5/membugs_dbg_msan+0x41a8c9)
 SUMMARY: MemorySanitizer: use-of-uninitialized-value (<...>/ch5/membugs_dbg_msan+0x496eb8) Exiting $ 
```

它已经捕获了错误；然而，这一次，尽管我们使用了带有`-g -ggdb`标志构建的调试二进制可执行文件，但在堆栈跟踪中缺少通常的`filename:line_number`信息。实际上，下一个测试用例中演示了一种获得这种信息的方法。

现在，不管怎样：这给了我们一个学习另一种有用的调试技术的机会：`objdump(1)`是可以极大帮助的工具链实用程序之一（我们可以使用诸如`readelf(1)`或`gdb(1)`之类的工具获得类似的结果）。我们将使用`objdump(1)`（`-d`开关，并通过`-S`开关提供源代码），并在其输出中查找 UMR 发生的地址：

```
SUMMARY: MemorySanitizer: use-of-uninitialized-value (<...>/ch5/membugs_dbg_msan+0x496eb8)
```

由于`objdump`的输出非常庞大，我们截断它，只显示相关部分：

```
$ objdump -d -S ./membugs_dbg_msan > tmp 

<< Now examine the tmp file >>

$ cat tmp

./membugs_dbg_msan: file format elf64-x86-64

Disassembly of section .init:

000000000041a5b0 <_init>:
  41a5b0: 48 83 ec 08 sub $0x8,%rsp
  41a5b4: 48 8b 05 ad a9 2a 00 mov 0x2aa9ad(%rip),%rax # 6c4f68 <__gmon_start__>
  41a5bb: 48 85 c0 test %rax,%rax
  41a5be: 74 02 je 41a5c2 <_init+0x12>

[...]

0000000000496e60 <uninit_var>:
{
  496e60: 55 push %rbp
  496e61: 48 89 e5 mov %rsp,%rbp
  int x; /* static mem */
  496e64: 48 83 ec 10 sub $0x10,%rsp
 [...]
  if (x)
  496e7f: 8b 55 fc mov -0x4(%rbp),%edx
  496e82: 8b 31 mov (%rcx),%esi
  496e84: 89 f7 mov %esi,%edi
  [...]
  496eaf: e9 00 00 00 00 jmpq 496eb4 <uninit_var+0x54>
  496eb4: e8 a7 56 f8 ff callq 41c560 <__msan_warning_noreturn>
  496eb9: 8a 45 fb mov -0x5(%rbp),%al
  496ebc: a8 01 test $0x1,%al
[...]
```

在`objdump`输出中与 MSan 提供的`0x496eb8`错误点最接近的是`0x496eb4`。没问题：只需查看代码的第一行之前的内容；它是以下一行：

```
   if (x)
```

完美。这正是 UMR 发生的地方！

**测试案例＃2：**写溢出[在编译时内存上]

我们运行`membugs`程序，同时在 Valgrind 和 ASan 下运行，只调用`write_overflow_compilemem()`函数来测试编译时分配的内存的越界写溢出错误。

**案例 1：**使用 Valgrind

请注意，Valgrind 没有捕获越界内存错误：

```
$ valgrind ./membugs_dbg 2 ==8959== Memcheck, a memory error detector
==8959== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==8959== Using Valgrind-3.13.0 and LibVEX; rerun with -h for copyright info
==8959== Command: ./membugs_dbg 2
==8959== 
==8959== 
==8959== HEAP SUMMARY:
==8959==     in use at exit: 0 bytes in 0 blocks
==8959==   total heap usage: 0 allocs, 0 frees, 0 bytes allocated
==8959== 
==8959== All heap blocks were freed -- no leaks are possible
==8959== 
==8959== For counts of detected and suppressed errors, rerun with: -v
==8959== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
$ 
```

这是因为 Valgrind 仅限于处理动态分配的内存；它无法插装和处理编译时分配的内存。

**案例 2：**地址消毒剂

ASan 确实捕获了 bug：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/073b0391-40f5-447a-b292-fab3db12592d.png)

AddressSanitizer（ASan）捕获了 OOB 写溢出 bug

以下是一个类似的文本版本：

```
$ ./membugs_dbg_asan 2
=================================================================
==25662==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff17e789f4 at pc 0x00000051271d bp 0x7fff17e789b0 sp 0x7fff17e789a8
WRITE of size 4 at 0x7fff17e789f4 thread T0
    #0 0x51271c (<...>/membugs_dbg_asan+0x51271c)
    #1 0x51244e (<...>/membugs_dbg_asan+0x51244e)
    #2 0x512291 (<...>/membugs_dbg_asan+0x512291)
    #3 0x7f7e19b2db96 (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
    #4 0x419ea9 (<...>/membugs_dbg_asan+0x419ea9)

Address 0x7fff17e789f4 is located in stack of thread T0 at offset 52 in frame
    #0 0x5125ef (/home/seawolf/0tmp/membugs_dbg_asan+0x5125ef)
[...]
SUMMARY: AddressSanitizer: stack-buffer-overflow (/home/seawolf/0tmp/membugs_dbg_asan+0x51271c) 
[...]
==25662==ABORTING
$ 
```

然而，请注意，在堆栈回溯中，没有`filename:line#信息`。这令人失望。我们能获取它吗？

确实—诀窍在于确保几件事情：

+   使用`-g`开关编译应用程序（包括调试符号信息；我们对所有*_dbg 版本都这样做）。

+   除了 Clang 编译器，还必须安装一个名为`llvm-symbolizer`的工具。安装后，您必须找出它在磁盘上的确切位置，并将该目录添加到路径中。

+   在运行时，必须将`ASAN_OPTIONS`环境变量设置为`symbolize=1`值。

在这里，我们使用`llvm-symbolizer`重新运行有 bug 的案例：

```
$ export PATH=$PATH:/usr/lib/llvm-6.0/bin/
$ ASAN_OPTIONS=symbolize=1 ./membugs_dbg_asan 2
=================================================================
==25807==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd63e80cf4 at pc 0x00000051271d bp 0x7ffd63e80cb0 sp 0x7ffd63e80ca8
WRITE of size 4 at 0x7ffd63e80cf4 thread T0
 #0 0x51271c in write_overflow_compilemem <...>/ch5/membugs.c:268:10
    #1 0x51244e in process_args <...>/ch5/membugs.c:325:4
    #2 0x512291 in main <...>/ch5/membugs.c:375:2
    #3 0x7f9823642b96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310
    #4 0x419ea9 in _start (<...>/membugs_dbg_asan+0x419ea9)
[...]
$ 
```

现在`filename:line#信息`显示出来了！

显然，ASan 可以并且确实插装编译时分配的内存以及动态分配的内存区域，从而捕获内存类型的错误。

另外，正如我们所看到的，它显示了一个调用堆栈（当然是从底部到顶部）。我们可以看到调用链是：

```
_start --> __libc_start_main --> main --> process_args --> 
             write_overflow_compilemem
```

AddressSanitizer 还显示了“在有 bug 的地址周围的影子字节”；在这里，我们不试图解释用于捕获此类错误的内存阴影技术；如果感兴趣，请参阅 GitHub 存储库上的*进一步阅读*部分。

**测试案例＃3：**写溢出（在动态内存上）

正如预期的那样，ASan 捕获了 bug：

```
$ ./membugs_dbg_asan 3
=================================================================
==25848==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018 at pc 0x0000004aaedc bp 0x7ffe64dd2cd0 sp 0x7ffe64dd2480
WRITE of size 10 at 0x602000000018 thread T0
    #0 0x4aaedb in __interceptor_strcpy.part.245 (<...>/membugs_dbg_asan+0x4aaedb)
    #1 0x5128fd in write_overflow_dynmem <...>/ch5/membugs.c:258:2
    #2 0x512458 in process_args <...>/ch5/membugs.c:328:4
    #3 0x512291 in main <...>/ch5/membugs.c:375:2
    #4 0x7f93abb88b96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310
    #5 0x419ea9 in _start (<...>/membugs_dbg_asan+0x419ea9)

0x602000000018 is located 0 bytes to the right of 8-byte region [0x602000000010,0x602000000018) allocated by thread T0 here:
    #0 0x4d9d60 in malloc (<...>/membugs_dbg_asan+0x4d9d60)
    #1 0x512896 in write_overflow_dynmem <...>/ch5/membugs.c:254:9
    #2 0x512458 in process_args <...>/ch5/membugs.c:328:4
    #3 0x512291 in main <...>/ch5/membugs.c:375:2
    #4 0x7f93abb88b96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310
[...]
```

有了`llvm-symbolizer`在路径中，`filename:line#信息`再次显示出来。

尝试为消毒剂插装编译（通过`-fsanitize=`GCC 开关）并尝试在 Valgrind 上运行二进制可执行文件是不受支持的；当我们尝试这样做时，Valgrind 报告如下：

```
$ valgrind ./membugs_dbg 3
==8917== Memcheck, a memory error detector
==8917== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==8917== Using Valgrind-3.13.0 and LibVEX; rerun with -h for copyright info
==8917== Command: ./membugs_dbg 3
==8917== 
==8917==ASan runtime does not come first in initial library list; you should either link runtime to your application or manually preload it with LD_PRELOAD.
[...]
```

**测试案例＃8：**UAF（释放后使用）。看看以下代码：

```
$ ./membugs_dbg_asan 8 uaf():162: arr = 0x615000000080:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
=================================================================
==25883==ERROR: AddressSanitizer: heap-use-after-free on address 0x615000000080 at pc 0x000000444b14 bp 0x7ffde4315390 sp 0x7ffde4314b40
WRITE of size 22 at 0x615000000080 thread T0
    #0 0x444b13 in strncpy (<...>/membugs_dbg_asan+0x444b13)
    #1 0x513529 in uaf <...>/ch5/membugs.c:172:2
    #2 0x512496 in process_args <...>/ch5/membugs.c:344:4
    #3 0x512291 in main <...>/ch5/membugs.c:375:2
    #4 0x7f4ceea9fb96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310
    #5 0x419ea9 in _start (<...>/membugs_dbg_asan+0x419ea9)

0x615000000080 is located 0 bytes inside of 512-byte region [0x615000000080,0x615000000280)
freed by thread T0 here:
    #0 0x4d9b90 in __interceptor_free.localalias.0 (<...>/membugs_dbg_asan+0x4d9b90)
    #1 0x513502 in uaf <...>/ch5/membugs.c:171:2
    #2 0x512496 in process_args <...>/ch5/membugs.c:344:4
    #3 0x512291 in main <...>/ch5/membugs.c:375:2
    #4 0x7f4ceea9fb96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310

previously allocated by thread T0 here:
    #0 0x4d9d60 in malloc (<...>/membugs_dbg_asan+0x4d9d60)
    #1 0x513336 in uaf <...>/ch5/membugs.c:157:8
    #2 0x512496 in process_args <...>/ch5/membugs.c:344:4
    #3 0x512291 in main <...>/ch5/membugs.c:375:2
    #4 0x7f4ceea9fb96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310

SUMMARY: AddressSanitizer: heap-use-after-free (<...>/membugs_dbg_asan+0x444b13) in strncpy
[...]
```

太棒了。ASan 不仅报告了 UAF bug，甚至还报告了缓冲区的确切分配和释放位置！强大的东西。

**测试案例＃9：**UAR

为了举例，假设我们以通常的方式使用`gcc`编译`membugs`程序。运行测试案例：

```
$ ./membugs_dbg 2>&1 | grep -w 9
 option =  9 : UAR (use-after-return) test case
$ ./membugs_dbg_asan 9
res: (null)
$ 
```

ASan 本身并没有捕获这个危险的 UAR bug！正如我们之前看到的，Valgrind 也没有。但是，编译器确实发出了警告！

不过，消毒剂文档提到，如果：

+   `clang`（版本从 r191186 开始）用于编译代码（而不是 gcc）

+   设置了一个特殊标志`detect_stack_use_after_return`为`1`

因此，我们通过 Clang 重新编译可执行文件（再次，我们假设已安装 Clang 软件包）。实际上，我们的 Makefile 确实对所有`membugs_dbg_*`构建使用了`clang`。因此，请确保我们使用 Clang 重新构建编译器并重试：

```
$ ASAN_OPTIONS=detect_stack_use_after_return=1 ./membugs_dbg_asan 9
=================================================================
==25925==ERROR: AddressSanitizer: stack-use-after-return on address 0x7f7721a00020 at pc 0x000000445b17 bp 0x7ffdb7c3ba10 sp 0x7ffdb7c3b1c0
READ of size 23 at 0x7f7721a00020 thread T0
    #0 0x445b16 in printf_common(void*, char const*, __va_list_tag*) (<...>/membugs_dbg_asan+0x445b16)
    #1 0x4465db in vprintf (<...>/membugs_dbg_asan+0x4465db)
    #2 0x4466ae in __interceptor_printf (<...>/membugs_dbg_asan+0x4466ae)
    #3 0x5124b9 in process_args <...>/ch5/membugs.c:348:4
    #4 0x512291 in main <...>/ch5/membugs.c:375:2
    #5 0x7f7724e80b96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310
    #6 0x419ea9 in _start (/home/seawolf/0tmp/membugs_dbg_asan+0x419ea9)

Address 0x7f7721a00020 is located in stack of thread T0 at offset 32 in frame
    #0 0x5135ef in uar <...>/ch5/membugs.c:141

  This frame has 1 object(s):
    [32, 64) 'name' (line 142) <== Memory access at offset 32 is inside this variable
[...]
```

它确实有效。正如我们在*测试案例＃1：UMR*中所展示的，可以进一步利用`objdump(1)`来找出 bug 发生的确切位置。我们把这留给读者作为一个练习。

有关 ASan 如何检测堆栈 UAR 的更多信息，请访问[`github.com/google/sanitizers/wiki/AddressSanitizerUseAfterReturn`](https://github.com/google/sanitizers/wiki/AddressSanitizerUseAfterReturn)。

**测试案例＃10：**双重释放

这个错误的测试用例有点有趣（参考`membugs.c`源代码）；我们执行`malloc`，释放指针，然后用一个如此大的值（`-1UL`，它变成了无符号，因此太大）执行另一个`malloc`，这是保证会失败的。在错误处理代码中，我们（故意）释放了之前已经释放过的指针，从而生成了双重释放的测试用例。在更简单的伪代码中：

```
ptr = malloc(n);
strncpy(...);
free(ptr);

bogus = malloc(-1UL); /* will fail */
if (!bogus) {
     free(ptr);  /* the Bug! */
     exit(1);
}
```

重要的是，这种编码揭示了另一个非常关键的教训：开发人员通常不够重视错误处理代码路径；他们可能或可能不编写负面测试用例来彻底测试它们。这可能导致严重的错误！

通过 ASan 的插装运行，一开始并没有产生预期的效果：你会看到由于明显巨大的`malloc`失败，ASan 实际上中止了进程执行；因此，它没有检测到我们真正想要的双重释放的真正错误：

```
$ ./membugs_dbg_asan 10 doublefree(): cond 0
doublefree(): cond 1
==25959==WARNING: AddressSanitizer failed to allocate 0xffffffffffffffff bytes
==25959==AddressSanitizer's allocator is terminating the process instead of returning 0
==25959==If you don't like this behavior set allocator_may_return_null=1
==25959==AddressSanitizer CHECK failed: /build/llvm-toolchain-6.0-QjOn7h/llvm-toolchain-6.0-6.0/projects/compiler-rt/lib/sanitizer_common/sanitizer_allocator.cc:225 "((0)) != (0)" (0x0, 0x0)
    #0 0x4e2eb5 in __asan::AsanCheckFailed(char const*, int, char const*, unsigned long long, unsigned long long) (<...>/membugs_dbg_asan+0x4e2eb5)
    #1 0x500765 in __sanitizer::CheckFailed(char const*, int, char const*, unsigned long long, unsigned long long) (<...>/membugs_dbg_asan+0x500765)
    #2 0x4e92a6 in __sanitizer::ReportAllocatorCannotReturnNull() (<...>/membugs_dbg_asan+0x4e92a6)
    #3 0x4e92e6 in __sanitizer::ReturnNullOrDieOnFailure::OnBadRequest() (<...>/membugs_dbg_asan+0x4e92e6)
    #4 0x424e66 in __asan::asan_malloc(unsigned long, __sanitizer::BufferedStackTrace*) (<...>/membugs_dbg_asan+0x424e66)
    #5 0x4d9d3b in malloc (<...>/membugs_dbg_asan+0x4d9d3b)
    #6 0x513938 in doublefree <...>/ch5/membugs.c:129:11
    #7 0x5124d2 in process_args <...>/ch5/membugs.c:352:4
    #8 0x512291 in main <...>/ch5/membugs.c:375:2
    #9 0x7f8a7deccb96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310
    #10 0x419ea9 in _start (/home/seawolf/0tmp/membugs_dbg_asan+0x419ea9)

$  
```

是的，但是，请注意前一行输出，它说：

```
[...] If you don't like this behavior set allocator_may_return_null=1 [...]
```

我们如何告诉 ASan 呢？一个环境变量`ASAN_OPTIONS`使得可以传递运行时选项；查找它们（回想一下我们已经提供了卫生器工具集的文档链接），我们像这样使用它（可以同时传递多个选项，用`:`分隔选项；为了好玩，我们还打开了冗长选项，但修剪了输出）：

```
$ ASAN_OPTIONS=verbosity=1:allocator_may_return_null=1 ./membugs_dbg_asan 10
==26026==AddressSanitizer: libc interceptors initialized
[...]
SHADOW_OFFSET: 0x7fff8000
==26026==Installed the sigaction for signal 11
==26026==Installed the sigaction for signal 7
==26026==Installed the sigaction for signal 8
==26026==T0: stack 0x7fffdf206000,0x7fffdfa06000) size 0x800000; local=0x7fffdfa039a8
==26026==AddressSanitizer Init done
doublefree(): cond 0
doublefree(): cond 1
==26026==WARNING: AddressSanitizer failed to allocate 0xffffffffffffffff bytes
membugs.c:doublefree:132: malloc failed
=================================================================
==26026==ERROR: AddressSanitizer: attempting double-free on 0x615000000300 in thread T0:
    #0 0x4d9b90 in __interceptor_free.localalias.0 (<...>/membugs_dbg_asan+0x4d9b90)
    #1 0x5139b0 in doublefree <...>/membugs.c:133:4
    #2 0x5124d2 in process_args <...>/ch5/membugs.c:352:4
    #3 0x512291 in main <...>/ch5/membugs.c:375:2
    #4 0x7fd41e565b96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310
    #5 0x419ea9 in _start (/home/seawolf/0tmp/membugs_dbg_asan+0x419ea9)

0x615000000300 is located 0 bytes inside of 512-byte region [0x615000000300,0x615000000500) freed by thread T0 here:
    #0 0x4d9b90 in __interceptor_free.localalias.0 (<...>/membugs_dbg_asan+0x4d9b90)
    #1 0x51391f in doublefree <...>/ch5/membugs.c:126:2
    #2 0x5124d2 in process_args <...>/ch5/membugs.c:352:4
    #3 0x512291 in main <...>/ch5/membugs.c:375:2
    #4 0x7fd41e565b96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310

previously allocated by thread T0 here:
    #0 0x4d9d60 in malloc (<...>/membugs_dbg_asan+0x4d9d60)
    #1 0x51389d in doublefree <...>/ch5/membugs.c:122:8
    #2 0x5124d2 in process_args <...>/ch5/membugs.c:352:4
    #3 0x512291 in main <...>/ch5/membugs.c:375:2
    #4 0x7fd41e565b96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310

SUMMARY: AddressSanitizer: double-free (<...>/membugs_dbg_asan+0x4d9b90) in __interceptor_free.localalias.0
==26026==ABORTING
$ 
```

这次，即使遇到分配失败，ASan 也会继续运行，因此找到了真正的错误-双重释放。

**测试用例＃11：**内存泄漏测试用例 1-简单泄漏。参考以下代码：

```
$ ./membugs_dbg_asan 11
leakage_case1(): will now leak 32 bytes (0 MB)
leakage_case1(): will now leak 1048576 bytes (1 MB)

=================================================================
==26054==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 1048576 byte(s) in 1 object(s) allocated from:
    #0 0x4d9d60 in malloc (<...>/membugs_dbg_asan+0x4d9d60)
    #1 0x513e34 in amleaky <...>/ch5/membugs.c:66:8
    #2 0x513a79 in leakage_case1 <...>/ch5/membugs.c:111:2
    #3 0x5124ef in process_args <...>/ch5/membugs.c:356:4
    #4 0x512291 in main <...>/ch5/membugs.c:375:2
    #5 0x7f2dd5884b96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0x4d9d60 in malloc (<...>/membugs_dbg_asan+0x4d9d60)
    #1 0x513e34 in amleaky <...>/ch5/membugs.c:66:8
    #2 0x513a79 in leakage_case1 <...>/ch5/membugs.c:111:2
    #3 0x5124e3 in process_args <...>/ch5/membugs.c:355:4
    #4 0x512291 in main <...>/ch5/membugs.c:375:2
    #5 0x7f2dd5884b96 in __libc_start_main /build/glibc-OTsEL5/glibc-2.27/csu/../csu/libc-start.c:310

SUMMARY: AddressSanitizer: 1048608 byte(s) leaked in 2 allocation(s).
$ 
```

它确实找到了泄漏，并指出了它。还要注意，LeakSanitizer（LSan）实际上是 ASan 的一个子集。

**测试用例＃13****：**内存泄漏测试用例 3- libAPI 泄漏

这是一个截图，展示了 ASan（在幕后，LSan）捕获泄漏时的操作：

![

很好地抓住了！

# AddressSanitizer（ASan）摘要表

关于我们的测试用例（并入我们的`membugs`程序），这是 ASan 的报告卡：

| **测试用例＃** | **测试用例** | **由 Address Sanitizer 检测到？** |
| --- | --- | --- |
| 1 | UMR | 否[1] |
| 2 | OOB（越界）：写入溢出[在编译时内存] | 是 |
| 3 | OOB（越界）：写入溢出[在动态内存上] | 是 |
| 4 | OOB（越界）：写入下溢[在动态内存上] | 是 |
| 5 | OOB（越界）：读取溢出[在编译时内存] | 是 |
| 6 | OOB（越界）：读取溢出[在动态内存上] | 是 |
| 7 | OOB（越界）：读取下溢[在动态内存上] | 是 |
| 8 | UAF（释放后使用）也称为悬空指针 | 是 |
| 9 | UAR 也称为 UAS（返回后使用） | 是[2] |
| 10 | 双重释放 | 是 |
| 11 | 内存泄漏测试用例 1：简单泄漏 | 是 |
| 12 | 内存泄漏测试用例 1：泄漏更多（循环中） | 是 |
| 13 | 内存泄漏测试用例 1：lib API 泄漏 | 是 |

表 4：AddressSanitizer 和内存错误

[1] **MemorySanitizer**（**MSan**）正好实现了这个目的-它确实检测到 UMR。但是，有两件事需要注意：

+   UMR 只能由 MSan 在动态分配的内存上检测到

+   成功使用 MSan 需要使用 Clang 编译器（它不能与 GCC 一起工作）

[2]这适用的前提是代码使用 Clang 编译，并通过`ASAN_OPTIONS`传递`detect_stack_use_after_return=1`标志。

# AddressSanitizer 的优缺点-快速总结

ASan 的优点：

+   捕获常见的内存错误（UB）在静态（编译时）和动态分配的内存区域上

+   越界（OOB）内存访问（读/写下溢/溢出错误）

+   释放后使用（UAF）错误

+   返回后使用（UAR）错误

+   双重释放

+   泄漏

+   性能远远优于其他工具（如 Valgrind）；最坏情况下性能下降似乎是 2 倍

+   不需要修改源代码

+   完全支持多线程应用程序

ASan 的缺点：

+   ASan 无法检测到某些类型的错误：

+   UMR（如前所述，带有一些警告，MSan 可以）

+   无法检测所有 UAF 错误

+   IOF（整数下溢/上溢）错误

+   一次只能使用一个特定的工具；不能总是组合多个消毒剂工具（参见前表）；这意味着通常必须为 ASan、TSan、LSan 编写单独的测试用例

+   编译器：

+   通常，需要使用 LLVM 前端 Clang 和适当的编译器标志重新编译程序。

+   为了查看带有行号信息的调用堆栈，需要使用`-g`标志重新编译/构建。

在这里，我们已经合并了前面的两个表。请参考以下表格，内存错误 - Valgrind 和地址消毒剂之间的快速比较：

| **测试用例＃** | **测试用例** | **Valgrind 检测到？** | **地址消毒剂检测到？** |
| --- | --- | --- | --- |
| 1 | UMR | 是 | 否[1] |
| 2 | OOB（越界）：写入溢出[在编译时内存上] | 否 | 是 |
| 3 | OOB（越界）：写入溢出[在动态内存上] | 是 | 是 |
| 4 | OOB（越界）：写入下溢[在动态内存上] | 是 | 是 |
| 5 | OOB（越界）：读取溢出[在编译时内存上] | 否 | 是 |
| 6 | OOB（越界）：读取溢出[在动态内存上] | 是 | 是 |
| 7 | OOB（越界）：读取下溢[在动态内存上] | 是 | 是 |
| 8 | UAF（释放后使用）也称为悬空指针 | 是 | 是 |
| 9 | UAR（返回后使用）也称为 UAS（作用域后使用） | 否 | 是[2] |
| 10 | 重复释放 | 是 | 是 |
| 11 | 内存泄漏测试用例 1：简单泄漏 | 是 | 是 |
| 12 | 内存泄漏测试用例 1：泄漏更多（循环中） | 是 | 是 |
| 13 | 内存泄漏测试用例 1：lib API 泄漏 | 是 | 是 |

[1]MSan 正好实现了这个目的-它确实检测 UMR（也请参见警告）。

它与警告一起使用，即代码使用 Clang 编译，并通过`ASAN_OPTIONS`传递了`detect_stack_use_after_return=1`标志。

# Glibc mallopt

对程序员有时很有用，glibc 提供了一种通过传递一些特定参数来更改 malloc 引擎默认值的方法。API 是`mallopt(3)`：

```
#include <malloc.h>
int mallopt(int param, int value);
```

请参阅`mallopt(3)`的 man 页面，了解所有可怕的细节（可在[`man7.org/linux/man-pages/man3/mallopt.3.html`](http://man7.org/linux/man-pages/man3/mallopt.3.html)上找到）。

作为一个有趣的例子，可以调整的参数之一是**`M_MMAP_THRESHOLD`**；回想一下，在之前的第五章中，*Linux 内存问题*，我们已经讨论过在现代 glibc 上，malloc 并不总是从堆段获取内存块。如果分配请求的大小大于或等于`MMAP_THRESHOLD`，则在底层通过强大的`mmap(2)`系统调用（设置请求大小的任意虚拟地址空间区域）来服务请求。`MMAP_THRESHOLD`的默认值为 128 KB；可以通过使用`mallopt(3)`的`M_MMAP_THRESHOLD`参数进行更改！

再次强调，这并不意味着您应该更改它；只是您可以。默认值经过精心设计，可能最适合大多数应用程序工作负载。

另一个有用的参数是`M_CHECK_ACTION`；此参数确定在检测到内存错误时 glibc 的反应（例如，写入溢出或重复释放）。还要注意，该实现*不*检测所有类型的内存错误（例如，泄漏不会被注意到）。

在运行时，glibc 解释参数值的最低三位（LSB）以确定如何做出反应：

+   **位 0**：如果设置，将在`stderr`上打印一行错误消息，提供有关原因的详细信息；错误行格式为：

```
*** glibc detected *** <program-name>: <function where error was detected> : <error description> : <address>
```

+   **位 1**：如果设置了，在打印错误消息后，将调用`abort(3)`导致进程终止。根据库的版本，还可能打印堆栈跟踪和进程内存映射的相关部分（通过 proc）。

+   **位 2**：如果设置，并且设置了位 0，则简化错误消息格式。

从 glibc ver。2.3.4 开始，`M_CHECK_ACTION`的默认值为 3（意味着二进制 011；之前是 1）。

将`M_CHECK_ACTION`设置为非零值非常有用，因为它将导致出现错误的进程在命中错误时崩溃，并显示有用的诊断信息。如果值为零，进程可能会进入未定义状态（UB），并在将来的某个任意点崩溃，这将使调试变得更加困难。

作为一个快速的参考者，这里有一些有用的`M_CHECK_ACTION`值及其含义：

+   1 (001b)：打印详细的错误消息，但继续执行（进程现在处于 UB 状态！）。

+   3 (011b)：打印详细的错误消息、调用堆栈、内存映射，并中止执行[默认]。

+   5 (101b)：打印简单的错误消息并继续执行（进程现在处于 UB 状态！）。

+   7 (111b)：打印简单的错误消息、调用堆栈、内存映射，并中止执行。

`mallopt(3)`的 man 页面提供了一个使用`M_CHECK_ACTION`的 C 程序示例。

# 通过环境设置 Malloc 选项

一个有用的功能：系统允许我们通过环境变量方便地调整一些分配参数，而不是通过编程方式使用`mallopt(3)` API。也许最有用的是，从调试和测试的角度来看，`MALLOC_CHECK_`变量是与先前描述的`M_CHECK_ACTION`参数对应的环境变量；因此，我们只需设置值，运行我们的应用程序，然后亲自查看结果！

以下是一些示例，使用我们通常的 membugs 应用程序来检查一些测试用例：

**测试用例＃10：**在设置`MALLOC_CHECK_`的情况下，使用`double free`：

```
$ MALLOC_CHECK_=1 ./membugs_dbg 10
doublefree(): cond 0
doublefree(): cond 1
membugs.c:doublefree:134: malloc failed
*** Error in `./membugs_dbg': free(): invalid pointer: 0x00005565f9f6b420 ***
$ MALLOC_CHECK_=3 ./membugs_dbg 10
doublefree(): cond 0
doublefree(): cond 1
membugs.c:doublefree:134: malloc failed
*** Error in `./membugs_dbg': free(): invalid pointer: 0x0000562f5da95420 ***
Aborted
$ MALLOC_CHECK_=5 ./membugs_dbg 10
doublefree(): cond 0
doublefree(): cond 1
membugs.c:doublefree:134: malloc failed
$ MALLOC_CHECK_=7 ./membugs_dbg 10
doublefree(): cond 0
doublefree(): cond 1
membugs.c:doublefree:134: malloc failed
$ 
```

请注意，当`MALLOC_CHECK_`的值为 1 时，错误消息被打印，但进程没有中止；这就是当环境变量的值设置为`3`时发生的情况。

**测试用例＃7：**在设置`MALLOC_CHECK_`的情况下，进行越界（读取下溢）：

```
$ MALLOC_CHECK_=3 ./membugs_dbg 7
read_underflow(): cond 0
 dest: abcd56789
read_underflow(): cond 1
 dest: xabcd56789
*** Error in `./membugs_dbg': free(): invalid pointer: 0x0000562ce36d9420 ***
Aborted
$ 
```

**测试用例＃11：**内存泄漏测试用例 1——在设置`MALLOC_CHECK_`的情况下，进行简单泄漏：

```
$ MALLOC_CHECK_=3 ./membugs_dbg 11
leakage_case1(): will now leak 32 bytes (0 MB)
leakage_case1(): will now leak 1048576 bytes (1 MB)
$ 
```

注意泄漏错误测试用例未被检测到。

前面的示例是在 Ubuntu 17.10 x86_64 上执行的；由于某种原因，在 Fedora 27 上对`MALLOC_CHECK_`的解释似乎并不像广告中描述的那样有效。

# 一些关键点

我们已经介绍了一些强大的内存调试工具和技术，但归根结底，这些工具本身是不够的。今天的开发人员必须保持警惕——还有一些关键点需要简要提及，这将为本章画上一个圆满的句号。

# 测试时的代码覆盖率

要记住使用动态分析工具（我们介绍了使用 Valgrind 的 Memcheck 工具和 ASan/MSan）的一个关键点是，只有在运行工具时实现了完整的代码覆盖率，它才真正有助于我们的工作！

这一点无法强调得足够。如果代码的错误部分实际上没有运行，那么运行一个奇妙的工具或编译器插装（例如 Sanitizers）有什么用呢！错误仍然潜伏，未被捕获。作为开发人员和测试人员，我们必须自律地编写严格的测试用例，确保实际上执行了完整的代码覆盖，以便通过这些强大的工具测试所有代码，包括库中的项目代码。

这并不容易：记住，任何值得做的事情都值得做好。

# 现代 C/C++开发人员该怎么办？

面对 C/C++复杂软件项目中潜在的 UB 问题，关注的开发人员可能会问，我们该怎么办？

来源：[`blog.regehr.org/archives/1520`](https://blog.regehr.org/archives/1520)。这是一篇来自优秀博客文章《2017 年的未定义行为》的摘录，作者是 Cuoq 和 Regehr。

**现代 C 或 C++开发人员该怎么办？**

+   熟悉一些易于使用的 UB 工具——通常可以通过调整 makefile 来启用的工具，例如编译器警告和 ASan 和 UBSan。尽早并经常使用这些工具，并（至关重要）根据它们的发现采取行动。

+   熟悉一些难以使用的 UB 工具——例如 TIS Interpreter 通常需要更多的努力来运行——并在适当的时候使用它们。

+   在进行广泛的测试（跟踪代码覆盖率，使用模糊器）以便充分利用动态 UB 检测工具。

+   进行 UB 意识的代码审查：建立一个文化，我们共同诊断潜在危险的补丁并在其落地之前修复它们。

+   要了解 C 和 C++标准中实际包含的内容，因为这是编译器编写者所遵循的。避免重复的陈词滥调，比如 C 是一种可移植的汇编语言，相信程序员。

# 提到了 malloc API 辅助程序

有很多`malloc`API 辅助程序。在调试困难的情况下，这些可能会很有用；了解有哪些可用的是个好主意。

在 Ubuntu Linux 系统中，我们通过 man 检查与关键字`malloc`匹配的内容：

```
$ man -k malloc
__after_morecore_hook (3) - malloc debugging variables
__free_hook (3)      - malloc debugging variables
__malloc_hook (3)    - malloc debugging variables
__malloc_initialize_hook (3) - malloc debugging variables
__memalign_hook (3)  - malloc debugging variables
__realloc_hook (3)   - malloc debugging variables
malloc (3)           - allocate and free dynamic memory
malloc_get_state (3) - record and restore state of malloc implementation
malloc_hook (3)      - malloc debugging variables
malloc_info (3)      - export malloc state to a stream
malloc_set_state (3) - record and restore state of malloc implementation
malloc_stats (3)     - print memory allocation statistics
malloc_trim (3)      - release free memory from the top of the heap
malloc_usable_size (3) - obtain size of block of memory allocated from heap
mtrace (1)           - interpret the malloc trace log
mtrace (3)           - malloc tracing
muntrace (3)         - malloc tracing
$
```

这些`malloc`API 中有相当多的（提醒：括号内的数字三（3）表示这是一个库例程）与 malloc 挂钩的概念有关。基本思想是：可以用自己的`hook`函数替换库的`malloc(3)`、`realloc(3)`、`memalign(3)`和`free(3)`API，当应用程序调用 API 时将调用该函数。

然而，我们不会进一步深入这个领域；为什么呢？glibc 的最新版本记录了这样一个事实，即这些挂钩函数是：

+   不是 MT-Safe（在第十六章中有介绍，*使用 Pthreads 进行多线程编程第三部分*）

+   从 glibc ver. 2.24 开始弃用

最后，这可能是显而易见的，但我们更愿意明确指出：必须意识到，使用这些工具只在测试环境中有意义；它们不应该在生产中使用！一些研究已经揭示了在生产中运行 ASan 时可能会被利用的安全漏洞；请参阅 GitHub 存储库上的*进一步阅读*部分。

# 总结

在本章中，我们试图向读者展示几个关键点、工具和技术；其中包括：

+   人会犯错误；这在内存未受管理的语言（C、C++）中尤其如此。

+   在非平凡的代码库中，确实需要强大的内存调试工具。

+   我们详细介绍了这两种最佳动态分析工具中的两种：

+   Valgrind 的 Memcheck

+   消毒剂（主要是 ASan）

+   通过`mallopt(3)`API 和环境变量，glibc 允许对`malloc`进行一些调整。

+   在构建测试用例时确保完整的代码覆盖率对项目的成功至关重要。

下一章与文件 I/O 的基本方面有关，这对于组件读者来说是必不可少的。它向您介绍了如何在 Linux 平台上执行高效的文件 I/O。我们请求读者阅读这一章，可在此处找到：[`www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf`](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)。我们强烈建议读者阅读系统调用层的 Open，文件描述符和 I/O - 读/写系统调用，这有助于更容易理解下一章，即第七章，*进程凭证*。
