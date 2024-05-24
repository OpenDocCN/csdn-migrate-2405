# PHP8 编程提示（五）

> 原文：[`zh.annas-archive.org/md5/7838a031e7678d26b84966d54ffa29dd`](https://zh.annas-archive.org/md5/7838a031e7678d26b84966d54ffa29dd)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：提高性能

PHP 8.x 引入了许多新功能，对性能产生了积极影响。此外，许多 PHP 8 最佳实践涵盖的内容可以提高效率并降低内存使用。在本章中，您将了解如何优化您的 PHP 8 代码以实现最佳性能。

PHP 8 包括一种称为弱引用的技术。通过掌握本章最后一节讨论的这项技术，您的应用程序将使用更少的内存。通过仔细审查本章涵盖的材料并研究代码示例，您将能够编写更快，更高效的代码。这种掌握将极大地提高您作为 PHP 开发人员的地位，并带来满意的客户，同时提高您的职业潜力。

本章涵盖的主题包括以下内容：

+   使用即时（JIT）编译器

+   加速数组处理

+   实现稳定排序

+   使用弱引用来提高效率

# 技术要求

为了检查和运行本章提供的代码示例，最低推荐的硬件如下：

+   基于 x86_64 的台式 PC 或笔记本电脑

+   1 GB 的可用磁盘空间

+   4 GB 的 RAM

+   每秒 500 千比特（Kbps）或更快的互联网连接

此外，您还需要安装以下软件：

+   Docker

+   Docker Compose

有关 Docker 和 Docker Compose 安装的更多信息，请参阅*第一章*的*技术要求*部分，以及如何构建用于演示本书中解释的代码的 Docker 容器。在本书中，我们将存储本书示例代码的目录称为`/repo`。

本章的源代码位于此处：https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices。现在我们可以开始讨论了，看看备受期待的 JIT 编译器。

# 使用 JIT 编译器

PHP 8 引入了备受期待的 JIT 编译器。这是一个重要的步骤，对 PHP 语言的长期可行性有重要影响。尽管 PHP 已经有能力生成和缓存字节码，但在引入 JIT 编译器之前，PHP 没有直接缓存机器码的能力。

实际上，自 2011 年以来就有几次尝试为 PHP 添加 JIT 编译器功能。PHP 7 中看到的性能提升是这些早期努力的直接结果。由于它们并没有显著提高性能，因此以前的 JIT 编译器努力都没有被提议为 RFC（请求评论）。核心团队现在认为，只有使用 JIT 才能实现进一步的性能提升。作为一个附带的好处，这打开了 PHP 作为非 Web 环境语言的可能性。另一个好处是 JIT 编译器打开了使用其他语言（而不是 C）开发 PHP 扩展的可能性。

在本章中非常重要的是要仔细阅读给出的细节，因为正确使用新的 JIT 编译器有可能极大地提高 PHP 应用程序的性能。在我们深入实现细节之前，首先需要解释 PHP 在没有 JIT 编译器的情况下如何执行字节码。然后我们将向您展示 JIT 编译器的工作原理。之后，您将更好地理解各种设置以及如何对其进行微调，以产生最佳的应用程序代码性能。

让我们现在关注 PHP 在没有 JIT 编译器的情况下是如何工作的。

## 了解 PHP 在没有 JIT 的情况下如何工作

当在服务器上安装 PHP（或在 Docker 容器中），除了核心扩展之外，实际安装的主要组件是一个通常被称为**Zend 引擎**的**虚拟机**（**VM**）。这个虚拟机的运行方式与*VMware*或*Docker*等虚拟化技术大不相同。Zend 引擎更接近于**Java 虚拟机**（**JVM**），它接受*字节码*并产生*机器码*。

这引出了一个问题：*什么是字节码*和*什么是机器码*？让我们现在来看一下这个问题。

### 理解字节码和机器码

机器码，或**机器语言**，是 CPU 直接理解的一组硬件指令。每条机器码都是一条指令，会导致 CPU 执行特定的操作。这些低级操作包括在寄存器之间移动信息，在内存中移动指定字节数，加法，减法等等。

机器码通常通过使用**汇编语言**来使其在一定程度上可读。以下是一个以汇编语言呈现的机器码示例：

```php
JIT$Mandelbrot::iterate: ;
        sub $0x10, %esp
        cmp $0x1, 0x1c(%esi)
        jb .L14
        jmp .L1
.ENTRY1:
        sub $0x10, %esp
.L1:
        cmp $0x2, 0x1c(%esi)
        jb .)L15
        mov $0xec3800f0, %edi
        jmp .L2
.ENTRY2:
        sub $0x10, %esp
.L2:
        cmp $0x5, 0x48(%esi)
        jnz .L16
        vmovsd 0x40(%esi), %xmm1
        vsubsd 0xec380068, %xmm1, %xmm1
```

尽管大部分命令不容易理解，但您可以从汇编语言表示中看到指令包括比较（`cmp`），在寄存器和/或内存之间移动信息（`mov`），以及跳转到指令集中的另一个点（`jmp`）。

字节码，也称为**操作码**，是原始程序代码的大大简化的符号表示。字节码是由一个解析过程（通常称为**解释器**）产生的，该过程将可读的程序代码分解为称为**标记**的符号，以及值。值可以是程序代码中使用的任何字符串，整数，浮点数和布尔数据。

以下是基于后面显示的示例代码创建 Mandelbrot 所产生的字节码片段的一个示例：

![图 10.1 - PHP 解析过程产生的字节码片段](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/B16992_Figure_10.1.jpg)

图 10.1 - PHP 解析过程产生的字节码片段

现在让我们来看一下 PHP 程序的传统执行流程。

### 理解传统的 PHP 程序执行

在传统的 PHP 程序运行周期中，PHP 程序代码通过一个称为**解析**的操作进行评估并分解为字节码。然后将字节码传递给 Zend 引擎，Zend 引擎将字节码转换为机器码。

当 PHP 首次安装在服务器上时，安装过程会启动必要的逻辑，将 Zend 引擎定制为特定服务器的 CPU 和硬件（或虚拟 CPU 和硬件）。因此，当您编写 PHP 代码时，您并不知道最终运行代码的实际 CPU 的具体情况。正是 Zend 引擎提供了硬件特定的意识。

接下来显示的*图 10.2*说明了传统的 PHP 执行方式：

![图 10.2 - 传统的 PHP 程序执行流程](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/B16992_Figure_10.2.jpg)

图 10.2 - 传统的 PHP 程序执行流程

尽管 PHP，特别是 PHP 7，非常快，但获得额外的速度仍然很有意义。出于这个目的，大多数安装也启用了 PHP **OPcache**扩展。在继续讨论 JIT 编译器之前，让我们快速了解一下 OPcache。

### 理解 PHP OPcache 的操作

顾名思义，PHP OPcache 扩展在首次运行 PHP 程序时*缓存*了操作码（字节码）。在后续的程序运行中，字节码将从缓存中获取，消除了解析阶段。这节省了大量时间，是一个在生产环境中启用的非常理想的功能。PHP OPcache 扩展是核心扩展集的一部分；但是，默认情况下它并未启用。

在启用此扩展之前，您必须首先确认您的 PHP 版本是否使用了`--enable-opcache`配置选项进行编译。您可以通过在运行在 Web 服务器上的 PHP 代码中执行`phpinfo()`命令来检查这一点。从命令行中，输入`php -i`命令。以下是在本书使用的 Docker 容器中运行`php -i`的示例：

```php
root@php8_tips_php8 [ /repo/ch10 ]# php -i
phpinfo()
PHP Version => 8.1.0-dev
System => Linux php8_tips_php8 5.8.0-53-generic #60~20.04.1-Ubuntu SMP Thu May 6 09:52:46 UTC 2021 x86_64
Build Date => Dec 24 2020 00:11:29
Build System => Linux 9244ac997bc1 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt11-1 (2015-05-24) x86_64 GNU/Linux
Configure Command =>  './configure'  '--prefix=/usr' '--sysconfdir=/etc' '--localstatedir=/var' '--datadir=/usr/share/php' '--mandir=/usr/share/man' '--enable-fpm' '--with-fpm-user=apache' '--with-fpm-group=apache'
// not all options shown
'--with-jpeg' '--with-png' '--with-sodium=/usr' '--enable-opcache-jit' '--with-pcre-jit' '--enable-opcache'
```

从输出中可以看出，OPcache 已包含在此 PHP 安装的配置中。要启用 OPcache，请添加或取消注释以下`php.ini`文件设置：

+   `zend_extension=opcache`

+   `opcache.enable=1`

+   `opcache.enable_cli=1`

最后一个设置是可选的。它确定是否还要处理从命令行执行的 PHP 命令。一旦启用，还有许多其他`php.ini`文件设置会影响性能，但这超出了本讨论的范围。

提示

有关影响 OPcache 的 PHP `php.ini`文件设置的更多信息，请查看这里：https://www.php.net/manual/en/opcache.configuration.php。

现在让我们来看看 JIT 编译器的运行方式，以及它与 OPcache 的区别。

### 使用 JIT 编译器发现 PHP 程序执行

当前方法的问题在于，无论字节码是否被缓存，Zend 引擎仍然需要每次程序请求时将字节码转换为机器代码。JIT 编译器提供的是将字节码编译成机器代码并且*缓存机器代码*的能力。这个过程是通过一个跟踪机制来实现的，它创建请求的跟踪。跟踪允许 JIT 编译器确定哪些块的机器代码需要被优化和缓存。使用 JIT 编译器的执行流程总结在*图 10.3*中：

![图 10.3 - 带有 JIT 编译器的 PHP 执行流](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/B16992_Figure_10.3.jpg)

图 10.3 - 带有 JIT 编译器的 PHP 执行流

从图表中可以看出，包含 OPcache 的正常执行流仍然存在。主要区别在于请求可能会调用一个 trace，导致程序流立即转移到 JIT 编译器，有效地绕过了解析过程和 Zend 引擎。JIT 编译器和 Zend 引擎都可以生成准备直接执行的机器代码。

JIT 编译器并非凭空产生。PHP 核心团队选择移植了高性能和经过充分测试的**DynASM**预处理汇编器。虽然 DynASM 主要是为**Lua**编程语言使用的 JIT 编译器开发的，但其设计非常适合作为任何基于 C 的语言（如 PHP！）的 JIT 编译器的基础。

PHP JIT 实现的另一个有利方面是它不会产生任何**中间表示**（**IR**）代码。相比之下，用于使用 JIT 编译器技术运行 Python 代码的**PyPy VM**必须首先产生**图结构**中的 IR 代码，用于流分析和优化，然后才能产生实际的机器代码。PHP JIT 中的 DynASM 核心不需要这一额外步骤，因此比其他解释性编程语言可能实现的性能更高。

提示

有关 DynASM 的更多信息，请查看此网站：https://luajit.org/dynasm.html。这是关于 PHP 8 JIT 操作的出色概述：https://www.zend.com/blog/exploring-new-php-jit-compiler。您还可以在这里阅读官方的 JIT RFC：https://wiki.php.net/rfc/jit。

现在您已经了解了 JIT 编译器如何适应 PHP 程序执行周期的一般流程，是时候学习如何启用它了。

## 启用 JIT 编译器

因为 JIT 编译器的主要功能是缓存机器代码，它作为 OPcache 扩展的独立部分运行。OPcache 既可以作为启用 JIT 功能的网关，也可以从自己的分配中为 JIT 编译器分配内存。因此，为了启用 JIT 编译器，您必须首先启用 OPcache（请参阅前一节，*理解 PHP OPcache 的操作*）。

为了启用 JIT 编译器，您必须首先确认 PHP 已经使用`--enable-opcache-jit`配置选项进行编译。然后，您可以通过简单地将非零值分配给`php.ini`文件的`opcache.jit_buffer_size`指令来启用或禁用 JIT 编译器。

值可以指定为整数——在这种情况下，该值表示字节数；值为零（默认值）会禁用 JIT 编译器；或者您可以分配一个数字，后面跟着以下任何一个字母：

+   `K`：千字节

+   `M`：兆字节

+   `G`：千兆字节

您为 JIT 编译器缓冲区大小指定的值必须小于您为 OPcache 分配的内存分配，因为 JIT 缓冲区是从 OPcache 缓冲区中取出的。

以下是一个示例，将 OPcache 内存消耗设置为 256 M，JIT 缓冲区设置为 64 M。这些值可以放在`php.ini`文件的任何位置：

```php
opcache.memory_consumption=256
opcache.jit_buffer_size=64M
```

现在您已经了解了 JIT 编译器的工作原理，以及如何启用它，了解如何正确设置跟踪模式非常重要。

## 配置跟踪模式

`php.ini`设置`opcache.jit`控制 JIT 跟踪器的操作。为了方便起见，可以使用以下四个预设字符串之一：

+   `opcache.jit=disable`

完全禁用 JIT 编译器（不考虑其他设置）。

+   `opcache.jit=off`

禁用 JIT 编译器，但（在大多数情况下）您可以使用`ini_set()`在运行时启用它。

+   `opcache.jit=function`

将 JIT 编译器跟踪器设置为功能模式。此模式对应于**CPU 寄存器触发优化（CRTO）**数字 1205（下面解释）。

+   `opcache.jit=tracing`

将 JIT 编译器跟踪器设置为跟踪模式。此模式对应于 CRTO 数字 1254（下面解释）。在大多数情况下，此设置可以获得最佳性能。

+   `opcache.jit=on`

这是跟踪模式的别名。

提示

依赖运行时 JIT 激活是有风险的，并且可能产生不一致的应用程序行为。最佳实践是使用`tracing`或`function`设置。

这四个便利字符串实际上解析为一个四位数。每个数字对应 JIT 编译器跟踪器的不同方面。这四个数字不像其他`php.ini`文件设置那样是位掩码，并且按照这个顺序指定：`CRTO`。以下是每个四位数的摘要。

### C（CPU 优化标志）

第一个数字代表 CPU 优化设置。如果将此数字设置为 0，则不会进行 CPU 优化。值为 1 会启用**高级矢量扩展**（**AVX**）**指令**的生成。AVX 是针对英特尔和 AMD 微处理器的 x86 指令集架构的扩展。自 2011 年以来，AVX 已在英特尔和 AMD 处理器上得到支持。大多数服务器型处理器（如英特尔至强）都支持 AVX2。

### R（寄存器分配）

第二位数字控制 JIT 编译器如何处理**寄存器**。寄存器类似于 RAM，只是它们直接驻留在 CPU 内部。CPU 不断地在寄存器中移动信息，以执行操作（例如，加法、减法、执行逻辑 AND、OR 和 NOT 操作等）。与此设置相关的选项允许您禁用寄存器分配优化，或者在本地或全局级别允许它。

### T（JIT 触发器）

第三位数字决定 JIT 编译器何时触发。选项包括在加载脚本时首次操作 JIT 编译器或在首次执行时操作。或者，您可以指示 JIT 何时编译**热函数**。热函数是最常被调用的函数。还有一个设置，告诉 JIT 只编译带有`@jit docblock`注释的函数。

### O（优化级别）

第四位数字对应优化级别。选项包括禁用优化、最小化和选择性。您还可以指示 JIT 编译器根据单个函数、调用树或内部过程分析的结果进行优化。

提示

要完全了解四个 JIT 编译器跟踪器设置，请查看此文档参考页面：https://www.php.net/manual/en/opcache.configuration.php#ini.opcache.jit。

现在让我们来看看 JIT 编译器的运行情况。

## 使用 JIT 编译器

在这个例子中，我们使用一个经典的基准测试程序来生成**Mandelbrot**。这是一个非常消耗计算资源的优秀测试。我们在这里使用的实现是来自 PHP 核心开发团队成员**Dmitry Stogov**的实现代码。您可以在这里查看原始实现：[`gist.github.com/dstogov/12323ad13d3240aee8f1`](https://gist.github.com/dstogov/12323ad13d3240aee8f1)：

1.  我们首先定义 Mandelbrot 参数。特别重要的是迭代次数（`MAX_LOOPS`）。较大的数字会产生更多的计算并减慢整体生产速度。我们还捕获开始时间：

```php
// /repo/ch10/php8_jit_mandelbrot.php
define('BAILOUT',   16);
define('MAX_LOOPS', 10000);
define('EDGE',      40.0);
$d1  = microtime(1);
```

1.  为了方便多次运行程序，我们添加了一个捕获命令行参数`-n`的选项。如果存在此参数，则 Mandelbrot 输出将被抑制：

```php
$time_only = (bool) ($argv[1] ?? $_GET['time'] ?? FALSE);
```

1.  然后，我们定义一个名为`iterate()`的函数，直接从 Dmitry Stogov 的 Mandelbrot 实现中提取。实际代码在此未显示，可以在前面提到的 URL 中查看。

1.  接下来，我们通过`EDGE`确定的 X/Y 坐标运行，生成 ASCII 图像：

```php
$out = '';
$f   = EDGE - 1;
for ($y = -$f; $y < $f; $y++) {
    for ($x = -$f; $x < $f; $x++) {
        $out .= (iterate($x/EDGE,$y/EDGE) == 0)
              ? '*' : ' ';
    }
    $out .= "\n";
}
```

1.  最后，我们生成输出。如果通过 Web 请求运行，则输出将包含在`<pre>`标签中。如果存在`-n`标志，则只显示经过的时间：

```php
if (!empty($_SERVER['REQUEST_URI'])) {
    $out = '<pre>' . $out . '</pre>';
}
if (!$time_only) echo $out;
$d2 = microtime(1);
$diff = $d2 - $d1;
printf("\nPHP Elapsed %0.3f\n", $diff);
```

1.  我们首先在 PHP 7 Docker 容器中使用`-n`标志运行程序三次。以下是结果。请注意，在与本书配合使用的演示 Docker 容器中，经过的时间很容易超过 10 秒：

```php
root@php8_tips_php7 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 10.320
root@php8_tips_php7 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 10.134
root@php8_tips_php7 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 11.806
```

1.  现在我们转向 PHP 8 Docker 容器。首先，我们调整`php.ini`文件以禁用 JIT 编译器。以下是设置：

```php
opcache.jit=off
opcache.jit_buffer_size=0
```

1.  以下是在使用`-n`标志的 PHP 8 中运行程序三次的结果：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 1.183
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 1.192
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 1.210
```

1.  立即可以看到切换到 PHP 8 的一个很好的理由！即使没有 JIT 编译器，PHP 8 也能在 1 秒多一点的时间内执行相同的程序：1/10 的时间量！

1.  接下来，我们修改`php.ini`文件设置，以使用 JIT 编译器`function`跟踪器模式。以下是使用的设置：

```php
opcache.jit=function
opcache.jit_buffer_size=64M
```

1.  然后我们再次使用`-n`标志运行相同的程序。以下是在使用 JIT 编译器`function`跟踪器模式的 PHP 8 中运行的结果：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 0.323
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 0.322
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 0.324
```

1.  哇！我们成功将处理速度提高了 3 倍。速度现在不到 1/3 秒！但是如果我们尝试推荐的 JIT 编译器`tracing`模式会发生什么呢？以下是调用该模式的设置：

```php
opcache.jit=tracing
opcache.jit_buffer_size=64M
```

1.  以下是我们上一组程序运行的结果：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 0.132
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 0.132
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
PHP Elapsed 0.131
```

正如输出所示，最后的结果真是令人震惊。我们不仅可以比没有 JIT 编译器的 PHP 8 运行相同的程序快 10 倍，而且比 PHP 7 运行*快 100 倍*！

重要提示

重要的是要注意，时间会根据您用于运行与本书相关的 Docker 容器的主机计算机而变化。您将看不到与此处显示的完全相同的时间。

现在让我们来看看 JIT 编译器调试。

## 使用 JIT 编译器进行调试

当使用 JIT 编译器时，使用**XDebug**或其他工具进行常规调试效果不佳。因此，PHP 核心团队添加了一个额外的`php.ini`文件选项`opcache.jit_debug`，它会生成额外的调试信息。在这种情况下，可用的设置采用位标志的形式，这意味着您可以使用按位运算符（如`AND`，`OR`，`XOR`等）将它们组合起来。

*表 10.1*总结了可以分配为`opcache.jit_debug`设置的值。请注意，标有**内部常量**的列不显示 PHP 预定义常量。这些值是内部 C 代码引用：

![表 10.1 - opcache.jit_debug 设置](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_10.1_B16992.jpg)

表 10.1 - opcache.jit_debug 设置

例如，如果您希望为`ZEND_JIT_DEBUG_ASM`，`ZEND_JIT_DEBUG_PERF`和`ZEND_JIT_DEBUG_EXIT`启用调试，可以在`php.ini`文件中进行如下分配：

1.  首先，您需要将要设置的值相加。在这个例子中，我们将添加：

`1 + 16 + 32768`

1.  然后将总和应用于`php.ini`设置：

`opcache.jit_debug=32725`

1.  或者，使用按位`OR`表示这些值：

`opcache.jit_debug=1|16|32768`

根据调试设置，您现在可以使用诸如 Linux `perf`命令或 Intel `VTune`之类的工具来调试 JIT 编译器。

以下是在运行前一节讨论的 Mandelbrot 测试程序时的部分调试输出示例。为了说明，我们使用了`php.ini`文件设置`opcache.jit_debug=32725`：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_jit_mandelbrot.php -n
---- TRACE 1 start (loop) iterate() /repo/ch10/php8_jit_mandelbrot.php:34
---- TRACE 1 stop (loop)
---- TRACE 1 Live Ranges
#15.CV6($i): 0-0 last_use
#19.CV6($i): 0-20 hint=#15.CV6($i)
... not all output is shown
---- TRACE 1 compiled
---- TRACE 2 start (side trace 1/7) iterate()
/repo/ch10/php8_jit_mandelbrot.php:41
---- TRACE 2 stop (return)
TRACE-2$iterate$41: ; (unknown)
    mov $0x2, EG(jit_trace_num)
    mov 0x10(%r14), %rcx
    test %rcx, %rcx
    jz .L1
    mov 0xb0(%r14), %rdx
    mov %rdx, (%rcx)
    mov $0x4, 0x8(%rcx)
...  not all output is shown
```

输出显示的是用汇编语言呈现的机器代码。如果在使用 JIT 编译器时遇到程序代码问题，汇编语言转储可能会帮助您找到错误的源头。

但是，请注意，汇编语言不具有可移植性，完全面向使用的 CPU。因此，您可能需要获取该 CPU 的硬件参考手册，并查找正在使用的汇编语言代码。

现在让我们来看看影响 JIT 编译器操作的其他`php.ini`文件设置。

## 发现额外的 JIT 编译器设置

*表 10.2*提供了`php.ini`文件中尚未涵盖的所有其他`opcache.jit*`设置的摘要：

![表 10.2 - 附加的 opcache.jit* php.ini 文件设置](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_10.2_B16992.jpg)

表 10.2 - 附加的 opcache.jit* php.ini 文件设置

从表中可以看出，您对 JIT 编译器的操作有很高的控制度。总体而言，这些设置代表了控制 JIT 编译器做出决策的阈值。如果正确配置这些设置，JIT 编译器可以忽略不经常使用的循环和函数调用。现在我们将离开 JIT 编译器的激动人心的世界，看看如何提高数组性能。

# 加速数组处理

数组是任何 PHP 程序的重要组成部分。实际上，处理数组是不可避免的，因为您的程序每天处理的大部分现实世界数据都以数组的形式到达。一个例子是来自 HTML 表单提交的数据。数据最终以数组的形式出现在`$_GET`或`$_POST`中。

在本节中，我们将向您介绍 SPL 中包含的一个鲜为人知的类：`SplFixedArray`类。将数据从标准数组迁移到`SplFixedArray`实例不仅可以提高性能，而且还需要更少的内存。学习如何利用本章涵盖的技术可以对当前使用大量数据的数组的任何程序代码的速度和效率产生重大影响。

## 在 PHP 8 中使用 SplFixedArray

`SplFixedArray`类是在 PHP 5.3 中引入的，它实际上是一个像数组一样操作的对象。然而，与`ArrayObject`不同，这个类要求您对数组大小设置一个硬限制，并且只允许整数索引。您可能想要使用`SplFixedArray`而不是`ArrayObject`的原因是，`SplFixedArray`占用的内存明显更少，并且性能非常好。事实上，`SplFixedArray`实际上比具有相同数据的标准数组占用*更少的内存*！

### 将 SplFixedArray 与数组和 ArrayObject 进行比较

一个简单的基准程序说明了标准数组、`ArrayObject`和`SplFixedArray`之间的差异：

1.  首先，我们定义了代码中稍后使用的一对常量：

```php
// /repo/ch10/php7_spl_fixed_arr_size.php
define('MAX_SIZE', 1000000);
define('PATTERN', "%14s : %8.8f : %12s\n");
```

1.  接下来，我们定义一个函数，该函数添加了 100 万个由 64 个字节长的字符串组成的元素：

```php
function testArr($list, $label) {
    $alpha = new InfiniteIterator(
        new ArrayIterator(range('A','Z')));
    $start_mem = memory_get_usage();
    $start_time = microtime(TRUE);
    for ($x = 0; $x < MAX_SIZE; $x++) {
        $letter = $alpha->current();
        $alpha->next();
        $list[$x] = str_repeat($letter, 64);
    }
    $mem_diff = memory_get_usage() - $start_mem;
    return [$label, (microtime(TRUE) - $start_time),
        number_format($mem_diff)];
}
```

1.  然后，我们调用该函数三次，分别提供`array`、`ArrayObject`和`SplFixedArray`作为参数：

```php
printf("%14s : %10s : %12s\n", '', 'Time', 'Memory');
$result = testArr([], 'Array');
vprintf(PATTERN, $result);
$result = testArr(new ArrayObject(), 'ArrayObject');
vprintf(PATTERN, $result);
$result = testArr(
    new SplFixedArray(MAX_SIZE), 'SplFixedArray');
vprintf(PATTERN, $result);
```

1.  以下是我们的 PHP 7.1 Docker 容器的结果：

```php
root@php8_tips_php7 [ /repo/ch10 ]# 
php php7_spl_fixed_arr_size.php 
               :       Time :       Memory
         Array : 1.19430900 :  129,558,888
   ArrayObject : 1.20231009 :  129,558,832
 SplFixedArray : 1.19744802 :   96,000,280
```

1.  在 PHP 8 中，所花费的时间显著减少，如下所示：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php7_spl_fixed_arr_size.php 
               :       Time :       Memory
         Array : 0.13694692 :  129,558,888
   ArrayObject : 0.11058593 :  129,558,832
 SplFixedArray : 0.09748793 :   96,000,280
```

从结果中可以看出，PHP 8 处理数组的速度比 PHP 7.1 快 10 倍。两个版本使用的内存量是相同的。无论使用哪个版本的 PHP，`SplFixedArray`使用的内存量都明显少于标准数组或`ArrayObject`。现在让我们来看看在 PHP 8 中`SplFixedArray`的使用方式发生了哪些变化。

### 在 PHP 8 中使用 SplFixedArray 的变化

您可能还记得在*第七章*中对`Traversable`接口的简要讨论，*在使用 PHP 8 扩展时避免陷阱*，*Traversable to IteratorAggregate migration*部分。在该部分提出的相同考虑也适用于`SplFixedArray`。虽然`SplFixedArray`没有实现`Traversable`，但它实现了`Iterator`，而`Iterator`又扩展了`Traversable`。

在 PHP 8 中，`SplFixedArray`不再实现`Iterator`。相反，它实现了`IteratorAggregate`。这种变化的好处是，PHP 8 中的`SplFixedArray`更快，更高效，并且在嵌套循环中使用也更安全。不利之处，也是潜在的代码中断，是如果您正在与以下任何方法一起使用`SplFixedArray`：`current()`、`key()`、`next()`、`rewind()`或`valid()`。

如果您需要访问数组导航方法，现在必须使用`SplFixedArray::getIterator()`方法来访问内部迭代器，从中可以使用所有导航方法。下面的简单代码示例说明了潜在的代码中断：

1.  我们首先从数组构建一个`SplFixedArray`实例：

```php
// /repo/ch10/php7_spl_fixed_arr_iter.php
$arr   = ['Person', 'Woman', 'Man', 'Camera', 'TV'];$fixed = SplFixedArray::fromArray($arr);
```

1.  然后，我们使用数组导航方法来遍历数组：

```php
while ($fixed->valid()) {
    echo $fixed->current() . '. ';
    $fixed->next();
}
```

在 PHP 7 中，输出是数组中的五个单词：

```php
root@php8_tips_php7 [ /repo/ch10 ]# 
php php7_spl_fixed_arr_iter.php 
Person. Woman. Man. Camera. TV.
```

在 PHP 8 中，结果却大不相同，如下所示：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php7_spl_fixed_arr_iter.php 
PHP Fatal error:  Uncaught Error: Call to undefined method SplFixedArray::valid() in /repo/ch10/php7_spl_fixed_arr_iter.php:5
```

为了使示例在 PHP 8 中工作，您只需要使用`SplFixedArray::getIterator()`方法来访问内部迭代器。代码的其余部分不需要重写。以下是为 PHP 8 重新编写的修订后的代码示例：

```php
// /repo/ch10/php8_spl_fixed_arr_iter.php
$arr   = ['Person', 'Woman', 'Man', 'Camera', 'TV'];
$obj   = SplFixedArray::fromArray($arr);
$fixed = $obj->getIterator();
while ($fixed->valid()) {
    echo $fixed->current() . '. ';
    $fixed->next();
}
```

现在输出的是五个单词，没有任何错误：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_spl_fixed_arr_iter.php
Person. Woman. Man. Camera. TV. 
```

现在您已经了解了如何提高数组处理性能，我们将把注意力转向数组性能的另一个方面：排序。

# 实现稳定排序

在设计数组排序逻辑时，最初的 PHP 开发人员为了速度而牺牲了稳定性。当时，这被认为是一个合理的牺牲。然而，如果在排序过程中涉及复杂对象，则需要**稳定排序**。

在本节中，我们将讨论稳定排序是什么，以及为什么它很重要。如果您可以确保数据被稳定排序，您的应用代码将产生更准确的输出，从而提高客户满意度。在我们深入了解 PHP 8 如何实现稳定排序之前，我们首先需要定义什么是稳定排序。

## 理解稳定排序

当用于排序目的的属性的值相等时，在*稳定排序*中保证了元素的原始顺序。这样的结果更接近用户的期望。让我们看一个简单的数据集，并确定什么构成了稳定排序。为了说明，让我们假设我们的数据集包括访问时间和用户名的条目：

```php
2021-06-01 11:11:11    Betty
2021-06-03 03:33:33    Betty
2021-06-01 11:11:11    Barney
2021-06-02 02:22:22    Wilma
2021-06-01 11:11:11    Wilma
2021-06-03 03:33:33    Barney
2021-06-01 11:11:11    Fred
```

如果我们希望按时间排序，您会立即注意到`2021-06-01 11:11:11`存在重复。如果我们对这个数据集执行稳定排序，预期的结果将如下所示：

```php
2021-06-01 11:11:11    Betty
2021-06-01 11:11:11    Barney
2021-06-01 11:11:11    Wilma
2021-06-01 11:11:11    Fred
2021-06-02 02:22:22    Wilma
2021-06-03 03:33:33    Betty
2021-06-03 03:33:33    Barney
```

您会注意到从排序后的数据集中，重复时间`2021-06-01 11:11:11`的条目按照它们最初的输入顺序出现。因此，我们可以说这个结果代表了一个稳定的排序。

在理想的情况下，相同的原则也应该适用于保留键/值关联的排序。稳定排序的一个额外标准是，它在性能上不应该与无序排序有任何差异。

提示

有关 PHP 8 稳定排序的更多信息，请查看官方 RFC：https://wiki.php.net/rfc/stable_sorting。

在 PHP 8 中，核心的`*sort*()`函数和`ArrayObject::*sort*()`方法已经被重写以实现稳定排序。让我们看一个代码示例，说明在 PHP 的早期版本中可能出现的问题。

## 对比稳定和非稳定排序

在这个例子中，我们希望按时间对`Access`实例的数组进行排序。每个`Access`实例有两个属性，`$name`和`$time`。样本数据集包含重复的访问时间，但用户名不同：

1.  首先，我们定义`Access`类：

```php
// /repo/src/Php8/Sort/Access.php
namespace Php8\Sort;
class Access {
    public $name, $time;
    public function __construct($name, $time) {
        $this->name = $name;
        $this->time = $time;
    }
}
```

1.  接下来，我们定义一个样本数据集，其中包含一个 CSV 文件，`/repo/sample_data/access.csv`，共有 21 行。每一行代表不同的姓名和访问时间的组合：

```php
"Fred",  "2021-06-01 11:11:11"
"Fred",  "2021-06-01 02:22:22"
"Betty", "2021-06-03 03:33:33"
"Fred",  "2021-06-11 11:11:11"
"Barney","2021-06-03 03:33:33"
"Betty", "2021-06-01 11:11:11"
"Betty", "2021-06-11 11:11:11"
"Barney","2021-06-01 11:11:11"
"Fred",  "2021-06-11 02:22:22"
"Wilma", "2021-06-01 11:11:11"
"Betty", "2021-06-13 03:33:33"
"Fred",  "2021-06-21 11:11:11"
"Betty", "2021-06-21 11:11:11"
"Barney","2021-06-13 03:33:33"
"Betty", "2021-06-23 03:33:33"
"Barney","2021-06-11 11:11:11"
"Barney","2021-06-21 11:11:11"
"Fred",  "2021-06-21 02:22:22"
"Barney","2021-06-23 03:33:33"
"Wilma", "2021-06-21 11:11:11"
"Wilma", "2021-06-11 11:11:11"
```

您会注意到，扫描样本数据时，所有具有`11:11:11`作为入口时间的日期都是重复的，但是您还会注意到，任何给定日期的原始顺序始终是用户`Fred`，`Betty`，`Barney`和`Wilma`。另外，请注意，对于时间为`03:33:33`的日期，`Betty`的条目总是在`Barney`之前。

1.  然后我们定义一个调用程序。在这个程序中，首先要做的是配置自动加载和`use` `Access`类：

```php
// /repo/ch010/php8_sort_stable_simple.php
require __DIR__ . 
'/../src/Server/Autoload/Loader.php';
$loader = new \Server\Autoload\Loader();
use Php8\Sort\Access;
```

1.  接下来，我们将样本数据加载到`$access`数组中：

```php
$access = [];
$data = new SplFileObject(__DIR__ 
    . '/../sample_data/access.csv');
while ($row = $data->fgetcsv())
    if (!empty($row) && count($row) === 2)
        $access[] = new Access($row[0], $row[1]);
```

1.  然后我们执行`usort()`。请注意，用户定义的回调函数执行每个实例的`time`属性的比较：

```php
usort($access, 
    function($a, $b) { return $a->time <=> $b->time; });
```

1.  最后，我们循环遍历新排序的数组并显示结果：

```php
foreach ($access as $entry)
    echo $entry->time . "\t" . $entry->name . "\n";
```

在 PHP 7 中，请注意虽然时间是有序的，但是姓名并不反映预期的顺序`Fred`，`Betty`，`Barney`和`Wilma`。以下是 PHP 7 的输出：

```php
root@php8_tips_php7 [ /repo/ch10 ]# 
php php8_sort_stable_simple.php 
2021-06-01 02:22:22    Fred
2021-06-01 11:11:11    Fred
2021-06-01 11:11:11    Wilma
2021-06-01 11:11:11    Betty
2021-06-01 11:11:11    Barney
2021-06-03 03:33:33    Betty
2021-06-03 03:33:33    Barney
2021-06-11 02:22:22    Fred
2021-06-11 11:11:11    Barney
2021-06-11 11:11:11    Wilma
2021-06-11 11:11:11    Betty
2021-06-11 11:11:11    Fred
2021-06-13 03:33:33    Barney
2021-06-13 03:33:33    Betty
2021-06-21 02:22:22    Fred
2021-06-21 11:11:11    Fred
2021-06-21 11:11:11    Betty
2021-06-21 11:11:11    Barney
2021-06-21 11:11:11    Wilma
2021-06-23 03:33:33    Betty
2021-06-23 03:33:33    Barney
```

从输出中可以看出，在第一组`11:11:11`日期中，最终顺序是`Fred`，`Wilma`，`Betty`和`Barney`，而原始的入口顺序是`Fred`，`Betty`，`Barney`和`Wilma`。您还会注意到，对于日期和时间`2021-06-13 03:33:33`，`Barney`在`Betty`之前，而原始的入口顺序是相反的。根据我们的定义，PHP 7 没有实现稳定排序！

现在让我们看一下在 PHP 8 中运行相同代码示例的输出。以下是 PHP 8 的输出：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_sort_stable_simple.php
2021-06-01 02:22:22    Fred
2021-06-01 11:11:11    Fred
2021-06-01 11:11:11    Betty
2021-06-01 11:11:11    Barney
2021-06-01 11:11:11    Wilma
2021-06-03 03:33:33    Betty
2021-06-03 03:33:33    Barney
2021-06-11 02:22:22    Fred
2021-06-11 11:11:11    Fred
2021-06-11 11:11:11    Betty
2021-06-11 11:11:11    Barney
2021-06-11 11:11:11    Wilma
2021-06-13 03:33:33    Betty
2021-06-13 03:33:33    Barney
2021-06-21 02:22:22    Fred
2021-06-21 11:11:11    Fred
2021-06-21 11:11:11    Betty
2021-06-21 11:11:11    Barney
2021-06-21 11:11:11    Wilma
2021-06-23 03:33:33    Betty
2021-06-23 03:33:33    Barney
```

从 PHP 8 的输出中可以看出，对于所有的`11:11:11`条目，原始的输入顺序`Fred`，`Betty`，`Barney`和`Wilma`都得到了尊重。您还会注意到，对于日期和时间`2021-06-13 03:33:33`，`Betty`始终在`Barney`之前。因此，我们可以得出结论，PHP 8 执行了稳定排序。

现在您已经看到了 PHP 7 中的问题，并且现在知道了 PHP 8 如何解决这个问题，让我们来看看稳定排序对键的影响。

## 检查稳定排序对键的影响

稳定排序的概念也影响使用`asort()`、`uasort()`或等效的`ArrayIterator`方法时的键/值对。在接下来展示的示例中，`ArrayIterator`被填充了 20 个元素，每隔一个元素是重复的。键是一个按顺序递增的十六进制数：

1.  首先，我们定义一个函数来生成随机的 3 个字母组合：

```php
// /repo/ch010/php8_sort_stable_keys.php
$randVal = function () {
    $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    return $alpha[rand(0,25)] . $alpha[rand(0,25)] 
           . $alpha[rand(0,25)];};
```

1.  接下来，我们使用示例数据加载了一个`ArrayIterator`实例。每隔一个元素是重复的。我们还记录了开始时间：

```php
$start = microtime(TRUE);
$max   = 20;
$iter  = new ArrayIterator;
for ($x = 256; $x < $max + 256; $x += 2) {
    $key = sprintf('%04X', $x);
    $iter->offsetSet($key, $randVal());
    $key = sprintf('%04X', $x + 1);
    $iter->offsetSet($key, 'AAA'); // <-- duplicate
}
```

1.  然后我们执行`ArrayIterator::asort()`并显示结果的顺序以及经过的时间：

```php
// not all code is shown
$iter->asort();
foreach ($iter as $key => $value) echo "$key\t$value\n";
echo "\nElapsed Time: " . (microtime(TRUE) - $start);
```

以下是在 PHP 7 中运行此代码示例的结果：

```php
root@php8_tips_php7 [ /repo/ch10 ]# 
php php8_sort_stable_keys.php 
0113    AAA
010D    AAA
0103    AAA
0105    AAA
0111    AAA
0107    AAA
010F    AAA
0109    AAA
0101    AAA
010B    AAA
0104    CBC
... some output omitted ...
010C    ZJW
Elapsed Time: 0.00017094612121582
```

从输出中可以看出，尽管值是有序的，但在重复值的情况下，键是以混乱的顺序出现的。相比之下，看一下在 PHP 8 中运行相同程序代码的输出：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_sort_stable_keys.php 
0101    AAA
0103    AAA
0105    AAA
0107    AAA
0109    AAA
010B    AAA
010D    AAA
010F    AAA
0111    AAA
0113    AAA
0100    BAU
... some output omitted ...
0104    QEE
Elapsed Time: 0.00010395050048828
```

输出显示，任何重复条目的键都按照它们原始的顺序出现在输出中。输出表明，PHP 8 不仅对值实现了稳定排序，而且对键也实现了稳定排序。此外，从经过的时间结果来看，PHP 8 已经成功地保持了与以前相同（或更好）的性能。现在让我们将注意力转向 PHP 8 中直接影响数组排序的另一个不同之处：处理非法排序函数。

## 处理非法排序函数

PHP 7 及更早版本允许开发人员在使用`usort()`或`uasort()`（或等效的`ArrayIterator`方法）时使用**非法函数**。您非常重要的是要意识到这种不良实践。否则，当您将代码迁移到 PHP 8 时，可能存在潜在的向后兼容性问题。

在接下来展示的示例中，创建了与“对比稳定和非稳定排序”部分中描述的示例相同的数组。*非法*排序函数返回一个布尔值，而`u*sort()`回调需要返回两个元素之间的*相对位置*。从字面上讲，用户定义的函数或回调需要在第一个操作数小于第二个操作数时返回`-1`，相等时返回`0`，第一个操作数大于第二个操作数时返回`1`。如果我们重写定义`usort()`回调的代码行，一个非法函数可能如下所示：

```php
usort($access, function($a, $b) { 
    return $a->time < $b->time; });
```

在这段代码片段中，我们没有使用太空船操作符（`<=>`），而是使用了小于符号（`<`）。在 PHP 7 及更低版本中，返回布尔返回值的回调是可以接受的，并且会产生期望的结果。但实际发生的是，PHP 解释器需要添加额外的操作来弥补缺失的操作。因此，如果回调只执行这个比较：

`op1 > op2`

PHP 解释器添加了一个额外的操作：

`op1 <= op2`

在 PHP 8 中，非法排序函数会产生一个弃用通知。以下是在 PHP 8 中运行的重写代码：

```php
root@php8_tips_php8 [ /repo/ch10 ]#
php php8_sort_illegal_func.php 
PHP Deprecated:  usort(): Returning bool from comparison function is deprecated, return an integer less than, equal to, or greater than zero in /repo/ch10/php8_sort_illegal_func.php on line 30
2021-06-01 02:22:22    Fred
2021-06-01 11:11:11    Fred
2021-06-01 11:11:11    Betty
2021-06-01 11:11:11    Barney
... not all output is shown
```

从输出中可以看出，PHP 8 允许操作继续进行，并且在使用正确的回调时结果是一致的。但是，您还可以看到发出了一个`Deprecation`通知。

提示

您也可以在 PHP 8 中使用箭头函数。之前展示的回调可以重写如下：

`usort($array, fn($a, $b) => $a <=> $b)`。

现在您对稳定排序是什么以及为什么它很重要有了更深入的了解。您还能够发现由于 PHP 8 和早期版本之间处理差异而可能出现的潜在问题。现在我们将看一下 PHP 8 中引入的其他性能改进。

# 使用弱引用来提高效率

随着 PHP 的不断发展和成熟，越来越多的开发人员开始使用 PHP 框架来促进快速应用程序开发。然而，这种做法的一个必然副产品是占用内存的对象变得越来越大和复杂。包含许多属性、其他对象或大型数组的大对象通常被称为**昂贵的对象**。

这种趋势引起的潜在内存问题的加剧是，所有 PHP 对象赋值都是自动通过引用进行的。没有引用，第三方框架的使用将变得非常麻烦。然而，当您通过引用分配一个对象时，对象必须保持在内存中，直到所有引用被销毁。只有在取消设置或覆盖对象之后，对象才会完全被销毁。

在 PHP 7.4 中，弱引用支持以解决这个问题的潜在解决方案首次引入。PHP 8 通过添加弱映射类扩展了这种新能力。在本节中，您将学习这项新技术的工作原理，以及它如何对开发有利。让我们先看看弱引用。

## 利用弱引用

**弱引用** 首次在 PHP 7.4 中引入，并在 PHP 8 中得到改进。这个类作为对象创建的包装器，允许开发人员以一种方式使用对象的引用，使得超出范围（例如 `unset()`）的对象不受垃圾回收的保护。

目前有许多 PHP 扩展驻留在 [pecl.php.net](http://pecl.php.net)，提供对弱引用的支持。大多数实现都是通过入侵 PHP 语言核心的 C 语言结构，要么重载对象处理程序，要么操纵堆栈和各种 C 指针。在大多数情况下，结果是丧失可移植性和大量的分段错误。PHP 8 的实现避免了这些问题。

如果您正在处理涉及大型对象并且程序代码可能运行很长时间的程序代码，那么掌握 PHP 8 弱引用的使用是非常重要的。在深入使用细节之前，让我们先看一下类的定义。

## 审查 `WeakReference` 类的定义

`WeakReference` 类的正式定义如下：

```php
WeakReference {
    public __construct() : void
    public static create (object $object) : WeakReference
    public get() : object|null
}
```

正如您所看到的，类的定义非常简单。该类可用于提供任何对象的包装器。这个包装器使得完全销毁一个对象变得更容易，而不必担心可能会有残留的引用导致对象仍然驻留在内存中。

提示

有关弱引用的背景和性质的更多信息，请查看这里：https://wiki.php.net/rfc/weakrefs。文档参考在这里：[`www.php.net/manual/en/class.weakreference.php`](https://www.php.net/manual/en/class.weakreference.php)。

现在让我们看一个简单的例子来帮助您理解。

## 使用弱引用

这个例子演示了如何使用弱引用。您将在这个例子中看到，当通过引用进行普通对象赋值时，即使原始对象被取消设置，它仍然保留在内存中。另一方面，如果您使用 `WeakReference` 分配对象引用，一旦原始对象被取消设置，它就会完全从内存中删除。

1.  首先，我们定义了四个对象。请注意，`$obj2` 是对 `$obj1` 的普通引用，而 `$obj4` 是对 `$obj3` 的弱引用：

```php
// /repo/ch010/php8_weak_reference.php
$obj1 = new class () { public $name = 'Fred'; };
$obj2 = $obj1;  // normal reference
$obj3 = new class () { public $name = 'Fred'; };
$obj4 = WeakReference::create($obj3); // weak ref
```

1.  然后我们显示 `$obj1` 在取消设置之前和之后的 `$obj2` 的内容。由于 `$obj1` 和 `$obj2` 之间的连接是一个普通的 PHP 引用，所以由于创建了强引用，`$obj1` 仍然保留在内存中：

```php
var_dump($obj2);
unset($obj1);
var_dump($obj2);  // $obj1 still loaded in memory
```

1.  然后我们对 `$obj3` 和 `$obj4` 做同样的操作。请注意，我们需要使用 `WeakReference::get()` 来获取关联的对象。一旦取消设置了 `$obj3`，与 `$obj3` 和 `$obj4` 相关的所有信息都将从内存中删除：

```php
var_dump($obj4->get());
unset($obj3);
var_dump($obj4->get()); // both $obj3 and $obj4 are gone
```

以下是在 PHP 8 中运行此代码示例的输出：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_weak_reference.php 
object(class@anonymous)#1 (1) {
  ["name"]=>  string(4) "Fred"
}
object(class@anonymous)#1 (1) {
  ["name"]=>  string(4) "Fred"
}
object(class@anonymous)#2 (1) {
  ["name"]=>  string(4) "Fred"
}
NULL
```

输出告诉我们一个有趣的故事！第二个 `var_dump()` 操作向我们展示了，即使 `$obj1` 已经取消设置，由于与 `$obj2` 创建的强引用，它仍然像僵尸一样存在。如果您正在处理昂贵的对象和复杂的应用程序代码，为了释放内存，您需要首先找到并销毁所有引用，然后才能释放内存！

另一方面，如果你真的需要内存，而不是直接进行对象赋值，在 PHP 中是自动引用的，可以使用`WeakReference::create()`方法创建引用。弱引用具有普通引用的所有功能。唯一的区别是，如果它引用的对象被销毁或超出范围，弱引用也会被自动销毁。

从输出中可以看出，最后一个`var_dump()`操作的结果是`NULL`。这告诉我们对象确实已经被销毁。当主对象取消引用时，它的所有弱引用也会自动消失。现在你已经了解了如何使用弱引用以及它们解决的潜在问题，是时候来看看一个新类`WeakMap`了。

## 使用 WeakMap

在 PHP 8 中，添加了一个新类`WeakMap`，它利用了弱引用支持。这个新类在功能上类似于`SplObjectStorage`。以下是官方的类定义：

```php
final WeakMap implements Countable,
    ArrayAccess, IteratorAggregate {
    public __construct ( )
    public count ( ) : int
    abstract public getIterator ( ) : Traversable
    public offsetExists ( object $object ) : bool
    public offsetGet ( object $object ) : mixed
    public offsetSet ( object $object , mixed $value ) :     void
    public offsetUnset ( object $object ) : void
}
```

就像`SplObjectStorage`一样，这个新类看起来像一个对象数组。因为它实现了`IteratorAggregate`，你可以使用`getIterator()`方法来访问内部迭代器。因此，这个新类不仅提供了传统的数组访问，还提供了面向对象的迭代器访问，两全其美！在深入了解如何使用`WeakMap`之前，你需要了解`SplObjectStorage`的典型用法。

## 使用 SplObjectStorage 实现容器类

`SplObjectStorage`类的一个潜在用途是将其用作**依赖注入**（**DI**）容器的基础（也称为**服务定位器**或**控制反转**容器）。DI 容器类旨在创建和保存对象实例，以便轻松检索。

在这个例子中，我们使用一个包含从`Laminas\Filter\*`类中提取的昂贵对象数组的容器类。然后我们使用容器来清理样本数据，之后我们取消过滤器数组：

1.  首先，我们基于`SplObjectStorage`定义一个容器类。（稍后，在下一节中，我们将开发另一个执行相同功能并基于`WeakMap`的容器类。）这是`UsesSplObjectStorage`类。在`__construct()`方法中，我们将配置的过滤器附加到`SplObjectStorage`实例：

```php
// /repo/src/Php7/Container/UsesSplObjectStorage.php
namespace Php7\Container;
use SplObjectStorage;
class UsesSplObjectStorage {
    public $container;
    public $default;
    public function __construct(array $config = []) {
        $this->container = new SplObjectStorage();
        if ($config) foreach ($config as $obj)
            $this->container->attach(
                $obj, get_class($obj));
        $this->default = new class () {
            public function filter($value) { 
                return $value; }};
    }
```

1.  然后，我们定义一个`get()`方法，遍历`SplObjectStorage`容器并返回找到的过滤器。如果找不到，则返回一个简单地将数据直接传递的默认类：

```php
    public function get(string $key) {
        foreach ($this->container as $idx => $obj)
            if ($obj instanceof $key) return $obj;
        return $this->default;    
    }
}
```

请注意，当使用`foreach()`循环来迭代`SplObjectStorage`实例时，我们返回*值*（`$obj`），而不是键。另一方面，如果我们使用`WeakMap`实例，我们需要返回*键*而不是值！

然后，我们定义一个调用程序，使用我们新创建的`UsesSplObjectStorage`类来包含过滤器集：

1.  首先，我们定义自动加载并使用适当的类：

```php
// /repo/ch010/php7_weak_map_problem.php
require __DIR__ . '/../src/Server/Autoload/Loader.php';
loader = new \Server\Autoload\Loader();
use Laminas\Filter\ {StringTrim, StripNewlines,
    StripTags, ToInt, Whitelist, UriNormalize};
use Php7\Container\UsesSplObjectStorage;
```

1.  接下来，我们定义一个样本数据数组：

```php
$data = [
    'name'    => '<script>bad JavaScript</script>name',
    'status'  => 'should only contain digits 9999',
    'gender'  => 'FMZ only allowed M, F or X',
    'space'   => "  leading/trailing whitespace or\n",
    'url'     => 'unlikelysource.com/about',
];
```

1.  然后，我们分配了对所有字段（`$required`）和对某些字段特定的过滤器（`$added`）：

```php
$required = [StringTrim::class, 
             StripNewlines::class, StripTags::class];
$added = ['status'  => ToInt::class,
          'gender'  => Whitelist::class,
          'url'     => UriNormalize::class ];
```

1.  之后，我们创建一个过滤器实例数组，用于填充我们的服务容器`UseSplObjectStorage`。请记住，每个过滤器类都带有很大的开销，可以被认为是一个*昂贵*的对象：

```php
$filters = [
    new StringTrim(),
    new StripNewlines(),
    new StripTags(),
    new ToInt(),
    new Whitelist(['list' => ['M','F','X']]),
    new UriNormalize(['enforcedScheme' => 'https']),
];
$container = new UsesSplObjectStorage($filters);
```

1.  现在我们使用我们的容器类循环遍历数据文件，以检索过滤器实例。`filter()`方法会产生特定于该过滤器的经过清理的值：

```php
foreach ($data as $key => &$value) {
    foreach ($required as $class) {
        $value = $container->get($class)->filter($value);
    }
    if (isset($added[$key])) {
        $value = $container->get($added[$key])
                            ->filter($value);
    }
}
var_dump($data);
```

1.  最后，我们获取内存统计信息，以便比较`SplObjectStorage`和`WeakMap`的使用情况。我们还取消了`$filters`，理论上应该释放大量内存。我们运行`gc_collect_cycles()`来强制 PHP 垃圾回收过程，将释放的内存重新放入池中。

```php
$mem = memory_get_usage();
unset($filters);
gc_collect_cycles();
$end = memory_get_usage();
echo "\nMemory Before Unset: $mem\n";
echo "Memory After  Unset: $end\n";
echo 'Difference         : ' . ($end - $mem) . "\n";
echo 'Peak Memory Usage : ' . memory_get_peak_usage();
```

这是在 PHP 8 中运行的调用程序的结果：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php7_weak_map_problem.php 
array(5) {
  ["name"]=>  string(18) "bad JavaScriptname"
  ["status"]=>  int(0)
  ["gender"]=>  NULL
  ["space"]=>  string(30) "leading/trailing whitespace or"
  ["url"]=>  &string(32) "https://unlikelysource.com/about"
}
Memory Before Unset: 518936
Memory After  Unset: 518672
Difference          :    264
Peak Memory Usage  : 780168
```

从输出中可以看出，我们的容器类完美地工作，让我们可以访问存储的任何过滤器类。另一个有趣的地方是，在执行`unset($filters)`命令后释放的内存是`264`字节：并不多！

现在你已经了解了`SplObjectStorage`类的典型用法。现在让我们来看看`SplObjectStorage`类可能存在的问题，以及`WeakMap`是如何解决的。

## 了解 WeakMap 相对于 SplObjectStorage 的优势

`SplObjectStorage`的主要问题是，当分配的对象被取消分配或者超出范围时，它仍然保留在内存中。原因是当对象附加到`SplObjectStorage`实例时，是通过引用进行的。

如果你只处理少量对象，可能不会遇到严重的问题。如果你使用`SplObjectStorage`并为存储分配大量昂贵的对象，这可能最终会导致长时间运行的程序内存泄漏。另一方面，如果你使用`WeakMap`实例进行存储，垃圾回收可以移除对象，从而释放内存。当你开始将`WeakMap`实例整合到你的常规编程实践中时，你会得到更高效的代码，占用更少的内存。

提示

有关`WeakMap`的更多信息，请查看原始 RFC：https://wiki.php.net/rfc/weak_maps。还请查看文档：https://www.php.net/weakMap。

现在让我们重新编写前一节的示例(`/repo/ch010/php7_weak_map_problem.php`)，但这次使用`WeakMap`：

1.  如前面的代码示例所述，我们定义了一个名为`UsesWeakMap`的容器类，其中包含我们昂贵的过滤器类。这个类和前一节中显示的类的主要区别在于`UsesWeakMap`使用`WeakMap`而不是`SplObjectStorage`进行存储。以下是类设置和`__construct()`方法：

```php
// /repo/src/Php7/Container/UsesWeakMap.php
namespace Php8\Container;
use WeakMap;
class UsesWeakMap {
    public $container;
    public $default;
    public function __construct(array $config = []) {
        $this->container = new WeakMap();
        if ($config)
            foreach ($config as $obj)
                $this->container->offsetSet(
                    $obj, get_class($obj));
        $this->default = new class () {
            public function filter($value) { 
                return $value; }};
    }
```

1.  两个类之间的另一个区别是`WeakMap`实现了`IteratorAggregate`。然而，这仍然允许我们在`get()`方法中使用简单的`foreach()`循环：

```php
    public function get(string $key) {
        foreach ($this->container as $idx => $obj)
            if ($idx instanceof $key) return $idx;
        return $this->default;
    }
}
```

请注意，当使用`foreach()`循环来迭代`WeakMap`实例时，我们返回的是*键*(`$idx`)，而不是值！

1.  然后，我们定义一个调用程序，调用自动加载程序并使用适当的过滤器类。这个调用程序和上一节的程序最大的区别在于我们使用基于`WeakMap`的新容器类：

```php
// /repo/ch010/php8_weak_map_problem.php
require __DIR__ . '/../src/Server/Autoload/Loader.php';
$loader = new \Server\Autoload\Loader();
use Laminas\Filter\ {StringTrim, StripNewlines,
    StripTags, ToInt, Whitelist, UriNormalize};
use Php8\Container\UsesWeakMap;
```

1.  与前一个示例一样，我们定义了一个样本数据数组并分配过滤器。这段代码没有显示，因为它与前一个示例的*步骤 2*和*3*相同。

1.  然后，我们在一个数组中创建过滤器实例，该数组作为参数传递给我们的新容器类。我们使用过滤器数组作为参数来创建容器类实例：

```php
$filters = [
    new StringTrim(),
    new StripNewlines(),
    new StripTags(),
    new ToInt(),
    new Whitelist(['list' => ['M','F','X']]),
    new UriNormalize(['enforcedScheme' => 'https']),
];
$container = new UsesWeakMap($filters);
```

1.  最后，就像前一个示例中的*步骤 6*一样，我们循环遍历数据并应用容器类中的过滤器。我们还收集并显示内存统计信息。

这是在 PHP 8 中运行的输出，使用`WeakMap`进行修订的程序：

```php
root@php8_tips_php8 [ /repo/ch10 ]# 
php php8_weak_map_problem.php 
array(5) {
  ["name"]=>  string(18) "bad JavaScriptname"
  ["status"]=>  int(0)
  ["gender"]=>  NULL
  ["space"]=>  string(30) "leading/trailing whitespace or"
  ["url"]=>  &string(32) "https://unlikelysource.com/about"
}
Memory Before Unset: 518712
Memory After  Unset: 517912
Difference          :    800
Peak Memory Usage  : 779944
```

正如你所期望的，总体内存使用略低。然而，最大的区别在于取消分配`$filters`后的内存差异。在前一个示例中，差异是`264`字节。而在这个示例中，使用`WeakMap`产生了`800`字节的差异。这意味着使用`WeakMap`有可能释放的内存量是使用`SplObjectStorage`的三倍以上！

这结束了我们对弱引用和弱映射的讨论。现在你可以编写更高效、占用更少内存的代码了。存储的对象越大，节省的内存就越多。

# 总结

在本章中，您不仅了解了新的 JIT 编译器的工作原理，还了解了传统的 PHP 解释-编译-执行循环。使用 PHP 8 并启用 JIT 编译器有可能将您的 PHP 应用程序加速三倍以上。

在下一节中，您将了解什么是稳定排序，以及 PHP 8 如何实现这一重要技术。通过掌握稳定排序，您的代码将以一种理性的方式产生数据，从而带来更大的客户满意度。

接下来的部分介绍了一种可以通过利用`SplFixedArray`类大大提高性能并减少内存消耗的技术。之后，您还了解了 PHP 8 对弱引用的支持以及新的`WeakMap`类。使用本章涵盖的技术将使您的应用程序执行速度更快，运行更高效，并且使用更少的内存。

在下一章中，您将学习如何成功迁移到 PHP 8。


# 第十一章：将现有 PHP 应用迁移到 PHP 8

在整本书中，您已经被警告可能出现代码断裂的情况。不幸的是，目前没有真正好的工具可以扫描您现有的代码并检查潜在的代码断裂。在本章中，我们将带您了解一组类的开发过程，这些类构成了 PHP 8 **向后兼容**（**BC**）断裂扫描器的基础。此外，您还将学习将现有客户 PHP 应用迁移到 PHP 8 的推荐流程。

阅读本章并仔细研究示例后，您将更好地掌握 PHP 8 迁移。了解整体迁移过程后，您将更加自信，并能够以最少的问题执行 PHP 8 迁移。

本章涵盖的主题包括以下内容：

+   了解开发、暂存和生产环境

+   学习如何在迁移之前发现 BC（向后兼容）断裂

+   执行迁移

+   测试和故障排除迁移

# 技术要求

为了检查和运行本章提供的代码示例，最低推荐的硬件配置如下：

+   基于 x86_64 的台式 PC 或笔记本电脑

+   1 **千兆字节**（**GB**）的可用磁盘空间

+   4GB 的 RAM

+   500 **千比特每秒**（**Kbps**）或更快的互联网连接

此外，您还需要安装以下软件：

+   Docker

+   Docker Compose

有关 Docker 和 Docker Compose 安装的更多信息，以及如何构建用于演示本书中解释的代码的 Docker 容器，请参阅*第一章*的*技术要求*部分，介绍新的 PHP 8 面向对象编程特性。在本书中，我们将您为本书恢复示例代码的目录称为`/repo`。

本章的源代码位于[`github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices`](https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices)。我们现在可以开始讨论使用作为整体迁移过程的一部分的环境。

# 了解开发、暂存和生产环境

网站更新的最终目标是以尽可能无缝的方式将更新的应用程序代码从开发环境移动到生产环境。这种应用程序代码的移动被称为**部署**。在这种情况下，移动涉及将应用程序代码和配置文件从一个**环境**复制到另一个环境。

在我们深入讨论将应用程序迁移到 PHP 8 之前，让我们先看看这些环境是什么。了解不同环境可能采用的形式对于您作为开发人员的角色至关重要。有了这种理解，您就能更好地将代码部署到生产环境，减少错误的发生。

## 定义环境

我们使用*环境*一词来描述包括操作系统、Web 服务器、数据库服务器和 PHP 安装在内的软件堆栈的组合。过去，环境等同于*服务器*。然而，在现代，*服务器*这个术语是具有误导性的，因为它暗示着一个金属箱子中的物理计算机，放置在某个看不见的服务器房间的机架上。如今，鉴于云服务提供商和高性能的虚拟化技术（例如 Docker）的丰富，这更有可能不是真实情况。因此，当我们使用*环境*这个术语时，请理解它指的是物理或虚拟服务器。

环境通常分为三个不同的类别：**开发**、**暂存**和**生产**。一些组织还提供单独的**测试**环境。让我们先看看所有环境中的共同点。

### 常见组件

重要的是要注意，所有环境中的内容都受生产环境的驱动。生产环境是应用程序代码的最终目的地。因此，所有其他环境应尽可能与操作系统、数据库、Web 服务器和 PHP 安装匹配。因此，例如，如果生产环境启用了 PHP OPCache 扩展，所有其他环境也必须启用此扩展。

所有环境，包括生产环境，至少需要安装操作系统和 PHP。根据应用程序的需求，安装 Web 服务器和数据库服务器也是非常常见的。Web 和数据库服务器的类型和版本应尽可能与生产环境匹配。

一般来说，开发环境与生产环境越接近，部署后出现错误的几率就越小。

现在我们来看看开发环境需要什么。

### 开发环境

开发环境是您最初开发和测试代码的地方。它具有应用程序维护和开发所需的工具。这包括存储源代码的存储库（例如 Git），以及启动、停止和重置环境所需的各种脚本。

通常，开发环境会有触发自动部署过程的脚本。这些脚本可以取代**提交钩子**，设计用于在提交到源代码存储库时激活。其中一个例子是**Git Hooks**，即可放置在`.git/hooks`目录中的脚本文件。

提示

有关 Git Hooks 的更多信息，请查看此处的文档：[`git-scm.com/book/en/v2/Customizing-Git-Git-Hooks`](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)。

传统的开发环境包括个人计算机、数据库服务器、Web 服务器和 PHP。这种传统范式未能考虑到目标生产环境可能存在的变化。例如，如果您经常与 12 个客户合作，那么这 12 个客户几乎不可能拥有完全相同的操作系统、数据库服务器、Web 服务器和 PHP 版本！*最佳实践*是尽可能模拟生产环境，可以采用虚拟机或 Docker 容器的形式。

因此，代码编辑器或**IDE**（集成开发环境）并不位于开发环境内。相反，您在开发环境之外进行代码创建和编辑。然后，您可以通过直接将文件复制到虚拟开发环境的共享目录，或者通过提交更改到源代码存储库，然后从开发环境虚拟机内拉取更改来本地推送更改。

在开发环境进行单元测试也是合适的。开发单元测试不仅可以更好地保证您的代码在生产环境中运行，而且还是发现应用程序开发早期阶段的错误的好方法。当然，您需要在本地环境中尽可能多地进行调试！在开发中捕获和修复错误通常只需要在生产中发现错误所需的十分之一的时间！

现在让我们来看看暂存环境。

### 暂存环境

大型应用程序开发项目通常会有多个开发人员共同在同一代码库上工作。在这种情况下，使用版本控制存储库至关重要。*暂存*环境是所有开发人员在开发环境测试和调试阶段完成后上传其代码的地方。

暂存环境必须是生产环境的*精确副本*。你可以把暂存环境想象成汽车工厂装配线上的最后一步。这是所有来自一个或多个开发环境的各种部件安装到位的地方。暂存环境是生产应该出现的原型。

重要的是要注意，暂存服务器通常可以直接访问互联网；然而，它通常位于一个需要密码才能访问的安全区域。

最后，让我们来看看生产环境。

### 生产环境

生产环境通常由客户直接维护和托管。这个环境也被称为**现场环境**。打个比方，如果开发环境是练习，暂存环境是彩排，那么生产环境就是现场演出（也许没有歌唱和舞蹈！）。

生产环境可以直接访问互联网，但受到防火墙的保护，通常还受到入侵检测和防御系统的保护（例如，[`snort.org/`](https://snort.org/)）。此外，生产环境可能被隐藏在运行在面向互联网的 Web 服务器上的反向代理配置后面。否则，至少在理论上，生产环境应该是暂存环境的*精确克隆*。

现在你已经对应用程序代码从开发到生产的环境有了一个概念，让我们来看看 PHP 8 迁移的一个关键第一步：发现潜在的 BC 代码中断。

# 学习如何在迁移前发现 BC 中断

理想情况下，你应该带着一个行动计划进入 PHP 8 迁移。这个行动计划的关键部分包括了解当前代码库中存在多少潜在的 BC 中断。在本节中，我们将向您展示如何开发一个自动化查找潜在 BC 中断的 BC 中断嗅探器。

首先，让我们回顾一下到目前为止关于 PHP 8 中可能出现的 BC 问题学到的东西。

## 获取 BC 中断概述

您已经知道，通过阅读本书的前几章，潜在的代码中断源自几个方面。让我们简要总结一下可能导致迁移后代码失败的一般趋势。请注意，我们在本章中不涵盖这些主题，因为这些主题在本书的早期章节中都已经涵盖过了：

+   资源到对象的迁移

+   支持 OS 库的最低版本

+   `Iterator`到`IteratorAggregate`的迁移

+   已删除的函数

+   使用变化

+   魔术方法签名强制执行

许多变化可以通过添加基于`preg_match()`或`strpos()`的简单回调来检测。使用变化更难以检测，因为乍一看，自动断点扫描器无法在不广泛使用`eval()`的情况下检测使用结果。

现在让我们来看看一个中断扫描配置文件可能是什么样子。

## 创建一个 BC 中断扫描配置文件

配置文件允许我们独立于 BC 中断扫描器类开发一组搜索模式。使用这种方法，BC 中断扫描器类定义了用于进行搜索的实际逻辑，而配置文件提供了一系列特定条件以及警告和建议的补救措施。

通过简单查找已在 PHP 8 中删除的函数的存在来检测到许多潜在的代码中断。为此，简单的`strpos()`搜索就足够了。另一方面，更复杂的搜索可能需要我们开发一系列回调。让我们首先看看如何基于简单的`strpos()`搜索开发配置。

### 定义一个简单的 strpos()搜索配置

在简单的`strpos()`搜索的情况下，我们只需要提供一个键/值对数组，其中键是被移除的函数的名称，值是它的建议替代品。BC 破坏扫描器类中的搜索逻辑可以这样做：

```php
$contents = file_get_contents(FILE_TO_SEARCH);
foreach ($config['removed'] as $key => $value)
    if (str_pos($contents, $key) !== FALSE)  echo $value;
```

我们将在下一节中介绍完整的 BC 破坏扫描器类实现。现在，我们只关注配置文件。以下是前几个`strpos()`搜索条目可能出现的方式：

```php
// /repo/ch11/bc_break_scanner.config.php
use Migration\BreakScan;
return [
    // not all keys are shown
    BreakScan::KEY_REMOVED => [
        '__autoload' => 'spl_autoload_register(callable)',
        'each' => 'Use "foreach()" or ArrayIterator',
        'fgetss' => 'strip_tags(fgets($fh))',
        'png2wbmp' => 'imagebmp',
        // not all entries are shown
    ],
];
```

不幸的是，一些 PHP 8 向后不兼容性可能超出了简单的`strpos()`搜索的能力。我们现在将注意力转向检测由 PHP 8 资源到对象迁移引起的潜在破坏。

### 检测与`is_resource()`相关的 BC 破坏

在*第七章*，*在使用 PHP 8 扩展时避免陷阱*，在*PHP 8 扩展资源到对象迁移*部分，您了解到 PHP 中存在一种从资源到对象的普遍趋势。您可能还记得，这种趋势本身并不构成任何 BC 破坏的威胁。然而，如果您的代码在确认连接已建立时使用了`is_resource()`，就有可能发生 BC 破坏。

为了考虑这种 BC 破坏的潜在性，我们的 BC 破坏扫描配置文件需要列出以前产生资源但现在产生对象的任何函数。然后我们需要在 BC 破坏扫描类中添加一个使用此列表的方法（下面讨论）。

这是受影响函数潜在配置键可能出现的方式：

```php
// /repo/ch11/bc_break_scanner.config.php
return [    // not all keys are shown
    BreakScan::KEY_RESOURCE => [
        'curl_init',
        'xml_parser_create',
        // not all entries are shown
    ],
];
```

在破坏扫描类中，我们只需要首先确认是否调用了`is_resource()`，然后检查`BreakScan::KEY_RESOURCE`数组下列出的任何函数是否存在。

我们现在将注意力转向**魔术方法签名**违规。

### 检测魔术方法签名违规

PHP 8 严格执行魔术方法签名。如果您的类使用宽松的定义，即不对方法签名进行数据类型定义，并且对于魔术方法不定义返回值数据类型，那么您就不会受到潜在代码破坏的威胁。另一方面，如果您的魔术方法签名包含数据类型，并且这些数据类型与 PHP 8 中强制执行的严格定义集不匹配，那么您就有可能出现代码破坏！

因此，我们需要创建一组正则表达式，以便检测魔术方法签名违规。此外，我们的配置应包括正确的签名。通过这种方式，如果检测到违规，我们可以在生成的消息中呈现正确的签名，加快更新过程。

这是一个魔术方法签名配置可能出现的方式：

```php
// /repo/ch11/bc_break_scanner.config.php
use Php8\Migration\BreakScan;
return [    
    BreakScan::KEY_MAGIC => [
    '__call' => [ 'signature' => 
        '__call(string $name, array $arguments): mixed',
        'regex' => '/__call\s*\((string\s)?'
            . '\$.+?(array\s)?\$.+?\)(\s*:\s*mixed)?/',
        'types' => ['string', 'array', 'mixed']],
    // other configuration keys not shown
    '__wakeup' => ['signature' => '__wakeup(): void',
        'regex' => '/__wakeup\s*\(\)(\s*:\s*void)?/',
        'types' => ['void']],
    ]
    // other configuration keys not shown
];
```

您可能注意到我们包含了一个额外的选项`types`。这是为了自动生成一个正则表达式。负责此操作的代码没有显示。如果您感兴趣，可以查看`/path/to/repo/ch11/php7_build_magic_signature_regex.php`。

让我们看看在简单的`strpos()`搜索不足以满足的情况下，您可能如何处理复杂的破坏检测。

### 解决复杂的 BC 破坏检测

在简单的`strpos()`搜索不足以证明的情况下，我们可以开发另一组键/值对，其中值是一个回调函数。举个例子，考虑一个可能的 BC 破坏，一个类定义了一个`__destruct()`方法，但也在`__construct()`方法中使用了`die()`或`exit()`。在 PHP 8 中，可能在这些情况下`__destruct()`方法不会被调用。

在这种情况下，简单的`strpos()`搜索是不够的。相反，我们必须开发逻辑来执行以下操作：

+   检查是否定义了`__destruct()`方法。如果是，则无需继续，因为在 PHP 8 中不会出现破坏的危险。

+   检查是否在`__construct()`方法中使用了`die()`或`exit()`。如果是，则发出潜在 BC 破坏的警告。

在我们的 BC 断点扫描配置数组中，回调采用匿名函数的形式。它接受文件内容作为参数。然后我们将回调分配给数组配置键，并包括如果回调返回`TRUE`时要传递的警告消息：

```php
// /repo/ch11/bc_break_scanner.config.php
return [
    // not all keys are shown
   BreakScan::KEY_CALLBACK => [
    'ERR_CONST_EXIT' => [
      'callback' => function ($contents) {
        $ptn = '/__construct.*?\{.*?(die|exit).*?}/im';
        return (preg_match($ptn, $contents)
                && strpos('__destruct', $contents)); },
      'msg' => 'WARNING: __destruct() might not get '
               . 'called if "die()" or "exit()" used '
               . 'in __construct()'],
    ], // etc.
    // not all entries are shown
];
```

在我们的 BC 断点扫描器类（下面讨论）中，调用回调所需的逻辑可能如下所示：

```php
$contents = file_get_contents(FILE_TO_SEARCH);
$className = 'SOME_CLASS';
foreach ($config['callbacks'] as $key => $value)
    if ($value'callback') echo $value['msg'];
```

如果检测到额外的潜在 BC 断点的要求超出了回调的能力，那么我们将在 BC 断点扫描类中定义一个单独的方法。

正如你所看到的，我们可以开发一个支持不仅简单的`strpos()`搜索，还支持使用回调数组进行更复杂搜索的配置数组。

现在你已经对配置数组中会包含什么有了一个概念，是时候定义执行断点扫描的主要类了。

## 开发 BC 断点扫描类

`BreakScan`类是针对单个文件的。在这个类中，我们定义了利用刚刚覆盖的各种断点扫描配置的方法。如果我们需要扫描多个文件，调用程序会生成一个文件列表，并将它们逐个传递给`BreakScan`。

`BreakScan`类可以分为两个主要部分：定义基础设施的方法和定义如何进行给定扫描的方法。后者主要由配置文件的结构来决定。对于每个配置文件部分，我们将需要一个`BreakScan`类方法。

让我们先看看基础方法。

### 定义 BreakScan 类基础方法

在这一部分，我们看一下`BreakScan`类的初始部分。我们还涵盖了执行基础相关活动的方法：

1.  首先，我们设置类基础设施，将其放在`/repo/src/Php8/Migration`目录中：

```php
// /repo/src/Php8/Migration/BreakScan.php
declare(strict_types=1);
namespace Php8\Migration;
use InvalidArgumentException;
use UnexpectedValueException;
class BreakScan {
```

1.  接下来，我们定义一组类常量，用于表示任何给定的后扫描失败的性质的消息：

```php
    const ERR_MAGIC_SIGNATURE = 'WARNING: magic method '
        . 'signature for %s does not appear to match '
        . 'required signature';
    const ERR_NAMESPACE = 'WARNING: namespaces can no '
        . 'longer contain spaces in PHP 8.';
    const ERR_REMOVED = 'WARNING: the following function'
        . 'has been removed: %s.  Use this instead: %s';
    // not all constants are shown
```

1.  我们还定义了一组表示配置数组键的常量。我们这样做是为了在配置文件和调用程序中保持键定义的一致性（稍后讨论）：

```php
    const KEY_REMOVED         = 'removed';
    const KEY_CALLBACK        = 'callbacks';
    const KEY_MAGIC           = 'magic';
    const KEY_RESOURCE        = 'resource';
```

1.  然后我们初始化关键属性，表示配置，要扫描的文件的内容和任何消息：

```php
    public $config = [];
    public $contents = '';
    public $messages = [];
```

1.  `__construct()`方法接受我们的断点扫描配置文件作为参数，并循环遍历所有键以确保它们存在：

```php
    public function __construct(array $config) {
        $this->config = $config;
        $required = [self::KEY_CALLBACK,
            self::KEY_REMOVED,
            self::KEY_MAGIC, 
            self::KEY_RESOURCE];
        foreach ($required as $key) {
            if (!isset($this->config[$key])) {
                $message = sprintf(
                    self::ERR_MISSING_KEY, $key);
                throw new Exception($message);
            }
        }
    }
```

1.  然后我们定义一个方法，读取要扫描的文件的内容。请注意，我们删除回车（`"\r"`)和换行符（`"\n"`)，以便通过正则表达式更容易处理扫描：

```php
    public function getFileContents(string $fn) {
        if (!file_exists($fn)) {
            self::$className = '';
            $this->contents  = '';
            throw new  Exception(
                sprintf(self::ERR_FILE_NOT_FOUND, $fn));
        }
        $this->contents = file_get_contents($fn);
        $this->contents = str_replace(["\r","\n"],
            ['', ' '], $this->contents);
        return $this->contents;
    }
```

1.  一些回调需要一种方法来提取类名或命名空间。为此，我们定义了静态的`getKeyValue()`方法：

```php
    public static function getKeyValue(
        string $contents, string $key, string $end) {
        $pos = strpos($contents, $key);
        $end = strpos($contents, $end, 
            $pos + strlen($key) + 1);
        return trim(substr($contents, 
            $pos + strlen($key), 
            $end - $pos - strlen($key)));
    }
```

这个方法寻找关键字（例如，`class`）。然后找到关键字后面的内容，直到分隔符（例如，`';'）。所以，如果你想要获取类名，你可以执行以下操作：`$name = BreakScan::geyKeyValue($contents,'class',';')`。

1.  我们还需要一种方法来检索和重置`$this->messages`。以下是这两种方法：

```php
    public function clearMessages() : void {
        $this->messages = [];
    }
    public function getMessages(bool $clear = FALSE) {
        $messages = $this->messages;
        if ($clear) $this->clearMessages();
        return $messages;
    }
```

1.  然后我们定义一个运行所有扫描的方法（在下一节中涵盖）。这个方法还会收集检测到的潜在 BC 断点的数量并报告总数：

```php
    public function runAllScans() : int {
        $found = 0;
        $found += $this->scanRemovedFunctions();
        $found += $this->scanIsResource();
        $found += $this->scanMagicSignatures();
        $found += $this->scanFromCallbacks();
        return $found;
    }
```

现在你已经对基本的`BreakScan`类基础设施可能是什么有了一个概念，让我们来看看单独的扫描方法。

### 检查单独的扫描方法

四个单独的扫描方法直接对应于断点扫描配置文件中的顶级键。每个方法都应该累积关于潜在 BC 断点的消息在`$this->messages`中。此外，每个方法都应该返回一个表示检测到的潜在 BC 断点总数的整数。

现在让我们按顺序检查这些方法：

1.  我们首先检查的方法是`scanRemovedFunctions()`。在这个方法中，我们搜索函数名称，后面直接跟着开括号`'('`，或者是空格和开括号`' ('`。如果找到函数，我们递增`$found`，并将适当的警告和建议的替换添加到`$this-> messages`中。如果没有发现潜在的破坏，我们添加一个成功消息并返回`0`：

```php
public function scanRemovedFunctions() : int {
    $found = 0;
    $config = $this->config[self::KEY_REMOVED];
    foreach ($config as $func => $replace) {
        $search1 = ' ' . $func . '(';
        $search2 = ' ' . $func . ' (';
        if (
            strpos($this->contents, $search1) !== FALSE
            || 
            strpos($this->contents, $search2) !== FALSE)
        {
            $this->messages[] = sprintf(
                self::ERR_REMOVED, $func, $replace);
            $found++;
        }
    }
    if ($found === 0)
        $this->messages[] = sprintf(
            self::OK_PASSED, __FUNCTION__);
    return $found;
}
```

这种方法的主要问题是，如果函数没有在空格之前，则不会检测到其使用。但是，如果我们在搜索中不包括前导空格，我们可能会得到错误的结果。例如，没有前导空格，每个`foreach()`的实例在寻找`each()`时都会触发破坏扫描器的警告！

1.  接下来，我们看一下扫描`is_resource()`使用的方法。如果找到引用，此方法将遍历不再生成资源的函数列表。如果同时找到`is_resource()`和其中一个这些方法，将标记潜在的 BC 破坏：

```php
public function scanIsResource() : int {
    $found = 0;
    $search = 'is_resource';
    if (strpos($this->contents, $search) === FALSE)
        return 0;
    $config = $this->config[self::KEY_RESOURCE];
    foreach ($config as $func) {
        if ((strpos($this->contents, $func) !== FALSE)){
            $this->messages[] =
                sprintf(self::ERR_IS_RESOURCE, $func);
            $found++;
        }
    }
    if ($found === 0)
        $this->messages[] = 
            sprintf(self::OK_PASSED, __FUNCTION__);
    return $found;
}
```

1.  然后我们看一下需要通过我们的回调列表的内容。您还记得，我们需要在简单的`strpos()`无法满足的情况下使用回调。因此，我们首先收集所有回调子键并依次循环遍历每个子键。如果没有底层键*callback*，我们会抛出一个`Exception`。否则，我们运行回调，提供`$this->contents`作为参数。如果发现任何潜在的 BC 破坏，我们添加适当的错误消息，并递增`$found`：

```php
public function scanFromCallbacks() {
    $found = 0;
    $list = array_keys($this-config[self::KEY_CALLBACK]);
    foreach ($list as $key) {
        $config = $this->config[self::KEY_CALLBACK][$key] 
            ?? NULL;
        if (empty($config['callback']) 
            || !is_callable($config['callback'])) {
            $message = sprintf(self::ERR_INVALID_KEY,
                self::KEY_CALLBACK . ' => ' 
                . $key . ' => callback');
            throw new Exception($message);
        }
        if ($config'callback') {
            $this->messages[] = $config['msg'];
            $found++;
        }
    }
    return $found;
}
```

1.  最后，我们转向迄今为止最复杂的方法，该方法扫描无效的魔术方法签名。主要问题是方法签名差异很大，因此我们需要构建单独的正则表达式来正确测试有效性。正则表达式存储在 BC 破坏配置文件中。如果检测到魔术方法，我们检索其正确的签名并将其添加到`$this->messages`中。

1.  首先，我们检查是否有任何魔术方法，通过查找与`function __`匹配的内容：

```php
public function scanMagicSignatures() : int {
    $found   = 0;
    $matches = [];
    $result  = preg_match_all(
        '/function __(.+?)\b/', 
        $this->contents, $matches);
```

1.  如果匹配数组不为空，我们循环遍历匹配集并将魔术方法名称分配给`$key`：

```php
   if (!empty($matches[1])) {
        $config = $this->config[self::KEY_MAGIC] ?? NULL;
        foreach ($matches[1] as $name) {
            $key = '__' . $name;
```

1.  如果未设置与假定魔术方法匹配的配置键，我们假设它既不是魔术方法，也不在配置文件中，因此无需担心。否则，如果存在键，我们提取表示分配给`$sub`的方法调用的子字符串：

```php
            if (empty($config[$key])) continue;
            if ($pos = strpos($this->contents, $key)) {
                $end = strpos($this->contents, 
                    '{', $pos);
            $sub = (empty($sub) || !is_string($sub))
                 ? '' : trim($sub);
```

1.  然后，我们从配置中提取正则表达式并将其与子字符串匹配。该模式表示该特定魔术方法的正确签名。如果`preg_match()`返回`FALSE`，我们知道实际签名不正确，并将其标记为潜在的 BC 破坏。我们检索并存储警告消息并递增`$found`：

```php
            $ptn = $config[$key]['regex'] ?? '/.*/';
            if (!preg_match($ptn, $sub)) {
                $this->messages[] = sprintf(
                  self::ERR_MAGIC_SIGNATURE, $key);
                $this->messages[] = 
                  $config[$key]['signature'] 
                  ?? 'Check signature'
                $found++;
    }}}}
    if ($found === 0)
        $this->messages[] = sprintf(
            self::OK_PASSED, __FUNCTION__);
     return $found;
}
```

这结束了我们对`BreakScan`类的审查。现在我们将注意力转向定义调用程序，该程序需要运行`BreakScan`类中编程的扫描。

### 构建一个调用程序的 BreakScan 类

调用`BreakScan`类的程序的主要工作是接受一个路径参数，并递归构建该路径中的 PHP 文件列表。然后，我们循环遍历列表，依次提取每个文件的内容，并运行 BC 破坏扫描。最后，我们提供一个报告，可以是简洁的或详细的，取决于所选的详细级别。

请记住，`BreakScan`类和我们即将讨论的调用程序都是设计用于在 PHP 7 下运行。我们不使用 PHP 8 的原因是因为我们假设开发人员希望在进行 PHP 8 更新之前运行 BC 破坏扫描器：

1.  我们首先通过配置自动加载程序并从命令行（`$argv`）或 URL（`$_GET`）获取路径和详细级别。此外，我们提供了一个选项，将结果写入 CSV 文件，并接受此类文件的名称作为参数。您可能注意到我们还进行了一定程度的输入消毒，尽管理论上 BC 破坏扫描器只会在开发服务器上直接由开发人员使用：

```php
// /repo/ch11/php7_bc_break_scanner.php
define('DEMO_PATH', __DIR__);
require __DIR__ . '/../src/Server/Autoload/Loader.php';
$loader = new \Server\Autoload\Loader();
use Php8\Migration\BreakScan;
// some code not shown
$path = $_GET['path'] ?? $argv[1] ?? NULL;
$show = $_GET['show'] ?? $argv[2] ?? 0;
$show = (int) $show;
$csv  = $_GET['csv']  ?? $argv[3] ?? '';
$csv  = basename($csv);
```

1.  接下来我们确认路径。如果找不到，我们将退出并显示使用信息（`$usage`未显示）：

```php
if (empty($path)) {
    if (!empty($_SERVER['REQUEST_URI']))
        echo '<pre>' . $usage . '</pre>';
    else
        echo $usage;
    exit;
}
```

1.  然后我们抓取 BC 破坏配置文件并创建`BreakScan`实例：

```php
$config  = include __DIR__ 
. '/php8_bc_break_scanner_config.php';
$scanner = new BreakScan($config);
```

1.  为了构建文件列表，我们使用`RecursiveDirectoryIterator`，包装在`RecursiveIteratorIterator`中，从给定路径开始。然后，这个列表通过`FilterIterator`进行过滤，限制扫描仅限于 PHP 文件：

```php
$iter = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($path));
$filter = new class ($iter) extends FilterIterator {
    public function accept() {
        $obj = $this->current();
        return ($obj->getExtension() === 'php');
    }
};
```

1.  如果开发人员选择 CSV 选项，将创建一个`SplFileObject`实例。与此同时，我们还输出了一个标题数组。此外，我们定义了一个写入 CSV 文件的匿名函数：

```php
if ($csv) {
    $csv_file = new SplFileObject($csv, 'w');
    $csv_file->fputcsv(
        ['Directory','File','OK','Messages']);
}
$write = function ($dir, $fn, $found, $messages) 
    use ($csv_file) {
    $ok = ($found === 0) ? 1 : 0;
    $csv_file->fputcsv([$dir, $fn, $ok, $messages]);
    return TRUE;
};
```

1.  我们通过循环遍历`FilterIterator`实例呈现的文件列表来启动扫描。由于我们是逐个文件扫描，所以在每次通过时`$found`都被清零。但是，我们确实保持`$total`，以便在最后给出潜在 BC 破坏的总数。您可能还注意到我们区分文件和目录。如果目录发生变化，其名称将显示为标题：

```php
$dir   = '';
$total = 0;
foreach ($filter as $name => $obj) {
    $found = 0;
    $scanner->clearMessages();
    if (dirname($name) !== $dir) {
        $dir = dirname($name);
        echo "Processing Directory: $name\n";
    }
```

1.  我们使用`SplFileObject::isDir()`来确定文件列表中的项目是否是目录。如果是，我们将继续处理列表中的下一个项目。然后我们将文件内容推送到`$scanner`并运行所有扫描。然后以字符串形式检索消息：

```php
    if ($obj->isDir()) continue;
    $fn = basename($name);
    $scanner->getFileContents($name);
    $found    = $scanner->runAllScans();
    $messages = implode("\n", $scanner->getMessages());
```

1.  我们使用`switch()`块根据`$show`表示的显示级别采取行动。级别`0`仅显示发现潜在 BC 破坏的文件。级别`1`显示此外还有消息。级别`2`显示所有可能的输出，包括成功消息：

```php
    switch ($show) {
        case 2 :
            echo "Processing: $fn\n";
            echo "$messages\n";
            if ($csv) 
                $write($dir, $fn, $found, $messages);
            break;
        case 1 :
            if (!$found) break;
            echo "Processing: $fn\n";
            echo BreakScan::WARN_BC_BREAKS . "\n";
            printf(BreakScan::TOTAL_BREAKS, $found);
            echo "$messages\n";
            if ($csv) 
                $write($dir, $fn, $found, $messages);
            break;
        case 0 :
        default :
            if (!$found) break;
            echo "Processing: $fn\n";
            echo BreakScan::WARN_BC_BREAKS . "\n";
            if ($csv) 
                $write($dir, $fn, $found, $messages);
    }
```

1.  最后，我们累积总数并显示最终结果：

```php
    $total += $found;
}
echo "\n" . str_repeat('-', 40) . "\n";
echo "\nTotal number of possible BC breaks: $total\n";
```

现在您已经了解了调用可能的外观，让我们来看一下测试扫描的结果。

### 扫描应用程序文件

为了演示目的，在与本书相关的源代码中，我们包含了一个较旧版本的**phpLdapAdmin**。您可以在`/path/to/repo/sample_data/phpldapadmin-1.2.3`找到源代码。对于此演示，我们打开了 PHP 7 容器的 shell，并运行了以下命令：

```php
root@php8_tips_php7 [ /repo ]# 
php ch11/php7_bc_break_scanner.php \
    sample_data/phpldapadmin-1.2.3/ 1 |less
```

这是运行此命令的部分结果：

```php
Processing: functions.php
WARNING: the code in this file might not be 
compatible with PHP 8
Total potential BC breaks: 4
WARNING: the following function has been removed: function __autoload.  
Use this instead: spl_autoload_register(callable)
WARNING: the following function has been removed: create_function.  Use this instead: Use either "function () {}" or "fn () => <expression>"
WARNING: the following function has been removed: each.  Use this instead: Use "foreach()" or ArrayIterator
PASSED this scan: scanIsResource
PASSED this scan: scanMagicSignatures
WARNING: using the "@" operator to suppress warnings 
no longer works in PHP 8.
```

从输出中可以看出，尽管`functions.php`通过了`scanMagicSignatures`和`scanIsResource`扫描，但这个代码文件使用了在 PHP 8 中已删除的三个函数：`__autoload()`，`create_function()`和`each()`。您还会注意到这个文件使用`@`符号来抑制错误，在 PHP 8 中不再有效。

如果您指定了 CSV 文件选项，您可以在任何电子表格程序中打开它。以下是在 Libre Office Calc 中的显示方式：

![图 11.1-在 Libre Office Calc 中打开的 CSV 文件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_11.1_B16562.jpg)

图 11.1-在 Libre Office Calc 中打开的 CSV 文件

现在您已经了解了如何创建自动化程序来检测潜在的 BC 破坏。请记住，代码远非完美，并不能涵盖每一个可能的代码破坏。为此，您必须在仔细审阅本书材料后依靠自己的判断。

现在是时候将我们的注意力转向实际迁移本身了。

# 执行迁移

执行从当前版本到 PHP 8 版本的实际迁移，就像部署新功能集到现有应用程序的过程一样。如果可能的话，您可以考虑并行运行两个网站，直到您确信新版本按预期工作为止。许多组织为此目的并行运行暂存环境和生产环境。

在本节中，我们提供了一个**十二步指南**来执行成功的迁移。虽然我们专注于迁移到 PHP 8，但这十二个步骤可以适用于您可能希望执行的任何 PHP 更新。仔细理解并遵循这些步骤对于您的生产网站的成功至关重要。在这十二个步骤中，有很多地方可以在遇到问题时恢复到早期版本。

在我们从旧版本的 PHP 迁移到 PHP 8 的十二步迁移过程中，这是一个概述：

1.  仔细阅读 PHP 文档附录中的适当迁移指南。在我们的情况下，我们选择*Migrating from PHP 7.4x to PHP 8.0x*。([`www.php.net/manual/en/appendices.php`](https://www.php.net/manual/en/appendices.php))。

1.  确保您当前的代码在当前版本的 PHP 上运行正常。

1.  备份数据库（如果有），所有源代码和任何相关的文件和资产（例如，CSS，JavaScript 或图形图像）。

1.  在您的版本控制软件中为即将更新的应用程序代码创建一个新分支。

1.  扫描 BC 中断（可能使用前一节中讨论的`BreakScan`类）。

1.  更新任何不兼容的代码。

1.  根据需要重复*步骤 5*和*6*。

1.  将您的源代码上传到存储库。

1.  在尽可能模拟生产服务器的虚拟环境中测试源代码。

1.  如果虚拟化模拟不成功，请返回到*步骤 5*。

1.  将暂存服务器（或等效的虚拟环境）更新到 PHP 8，确保可以切换回旧版本。

1.  运行您能想象到的每一个测试。如果不成功，请切换回主分支并返回到*步骤 5*。如果成功，克隆暂存环境到生产环境。

现在让我们依次看看每一步。

## 第 1 步 - 查看迁移指南

随着每个 PHP 的主要发布，PHP 核心团队都会发布一个**迁移指南**。我们在本书中主要关注的指南是*Migrating from PHP 7.4.x to PHP 8.0.x*，位于[`www.php.net/manual/en/migration80.php`](https://www.php.net/manual/en/migration80.php)。这个迁移指南分为四个部分：

+   新功能

+   向后不兼容的更改

+   弃用功能

+   其他更改

如果您正在从 PHP 7.4 以外的版本迁移到 PHP 8.0，您还应该查看您当前 PHP 版本的所有过去迁移指南，直到 PHP 8。我们现在将看看迁移过程中的其他推荐步骤。

## 第 2 步 - 确保当前代码正常工作

在开始对当前代码进行更改以确保其在 PHP 8 中正常工作之前，确保它绝对正常工作是非常关键的。如果现在代码不起作用，那么一旦迁移到 PHP 8，它肯定也不会起作用！运行任何单元测试以及任何**黑盒测试**，以确保代码在当前版本的 PHP 中正常运行。

如果在迁移之前对当前代码进行了任何更改，请确保这些更改反映在您版本控制软件的主分支（通常称为**主分支**）中。

## 第 3 步 - 备份所有内容

下一步是备份所有内容。这包括数据库、源代码、JavaScript、CSS、图像等。还请不要忘记备份重要的配置文件，如`php.ini`文件、web 服务器配置和与 PHP 和 web 通信相关的任何其他配置文件。

## 第 4 步 - 创建版本控制分支

在这一步中，您应该在您的版本控制系统中创建一个新的分支并检出该分支。在主分支中，您应该只有当前有效的代码。

这是使用 Git 进行此类命令的方式：

```php
$ git branch php8_migration
$ git checkout php8_migration
Switched to branch 'php8_migration'
```

所示的第一条命令创建了一个名为`php8_migration`的分支。第二条命令使`git`切换到新分支。在这个过程中，所有现有的代码都被移植到了新分支。主分支现在是安全的，并且在新分支中进行任何更改都得到了保留。

有关使用 Git 进行版本控制的更多信息，请查看这里：[`git-scm.com/`](https://git-scm.com/)。

## 第 5 步 - 扫描 BC 破坏

现在是时候充分利用`BreakScan`类了。运行调用程序，并作为参数提供项目的起始目录路径以及详细级别（`0`，`1`或`2`）。您还可以指定一个 CSV 文件作为第三个选项，就像*图 11.1*中早些时候所示的那样。

## 第 6 步 - 修复不兼容性

在这一步中，知道破坏的位置，您可以继续修复不兼容性。您应该能够以这样的方式进行修复，使得代码在当前版本的 PHP 中继续运行，同时也可以在 PHP 8 中运行。正如我们在整本书中一直指出的那样，BC 破坏在很大程度上源自糟糕的编码实践。通过修复不兼容性，您同时改进了您的代码。

## 第 7 步 - 根据需要重复步骤 5 和 6

有一句名言在许多好莱坞电影中反复出现，医生对焦虑的病人说，“服用两片阿司匹林，明天早上给我打电话”。同样的建议也适用于解决 BC 破坏的过程。您必须要有耐心，继续修复和扫描，修复和扫描。一直这样做，直到扫描不再显示潜在的 BC 破坏为止。

## 第 8 步 - 将更改提交到存储库

一旦您相对确信没有进一步的 BC 破坏，就是时候将更改提交到您在版本控制软件中创建的新 PHP 8 迁移分支。现在可以推送更改。然后，您可以在生产服务器上解决 PHP 更新后，从该分支检索更新的代码。

请记住这一重要点：您当前的工作代码安全地存储在主分支中。您只是在这个阶段保存到 PHP 8 迁移分支，所以您随时可以切换回去。

## 第 9 步 - 在模拟虚拟环境中进行测试

将这一步看作是真正事情的彩排。在这一步中，您创建一个虚拟环境（例如，使用 Docker 容器），最接近模拟生产服务器。在这个虚拟环境中，然后安装 PHP 8。一旦创建了虚拟环境，您可以打开一个命令行进入其中，并从 PHP 8 迁移分支下载您的源代码。

然后，您可以运行单元测试和任何其他您认为必要的测试，以测试更新后的代码。希望在这一步中能够捕获任何额外的错误。

## 第 10 步 - 如果测试不成功，则返回第 5 步

如果在虚拟环境中进行的单元测试、黑盒测试或其他测试显示您的应用程序代码失败，您必须返回到*第 5 步*。在面对明显的失败时继续前往实际生产站点将是极不明智的！

## 第 11 步 - 在暂存环境中安装 PHP 8

下一步是在暂存环境中安装 PHP 8。您可能还记得我们在本章第一部分讨论中提到的，传统流程是从开发环境到暂存环境，然后再到生产环境。一旦在暂存环境上完成了所有测试，您就可以将暂存克隆到生产环境。

PHP 的安装在主[php.net](http://php.net)网站上有详细的文档，因此这里不需要进一步的细节。相反，在本节中，我们为您提供了 PHP 安装的简要概述，重点是能够在 PHP 8 和当前 PHP 版本之间切换的能力。

提示

有关在各种环境中安装 PHP 的信息，请参阅此文档页面：[`www.php.net/manual/en/install.php`](https://www.php.net/manual/en/install.php)。

为了举例说明，我们选择讨论两个主要 Linux 分支上的 PHP 8 安装：Debian/Ubuntu 和 Red Hat/CentOS/Fedora。让我们从 Debian/Ubuntu Linux 开始。

### 在 Debian/Ubuntu Linux 上安装 PHP 8

安装 PHP 8 的最佳方法是使用现有的一组预编译的二进制文件。较新的 PHP 版本往往比发布日期晚得多，并且 PHP 8 也不例外。在这种情况下，建议您使用（**Personal Package Archive(PPA**）。托管在[`launchpad.net/~ondrej`](https://launchpad.net/~ondrej)的 PPA 是最全面和广泛使用的。

如果您想在自己的计算机上模拟以下步骤，请使用以下命令运行一个预先安装了 PHP 7.4 的 Ubuntu Docker 镜像：

```php
docker run -it \
  unlikelysource/ubuntu_focal_with_php_7_4:latest /bin/bash
```

为了在 Debian 或 Ubuntu Linux 上安装 PHP 8，打开一个命令行到生产服务器（或演示容器）上，并以*root*用户的身份进行如下操作。或者，如果没有*root*用户访问权限，可以在每个显示的命令前加上`sudo`。

从命令行安装 PHP 8，请按照以下步骤进行：

1.  使用**apt**实用程序更新和升级当前的软件包集。可以使用任何软件包管理器；但是，我们展示了使用`apt`来保持这里涵盖的安装步骤之间的一致性：

```php
apt update
apt upgrade
```

1.  将`Ondrej PPA`存储库添加到您的`apt`源中：

```php
add-apt-repository ppa:ondrej/php
```

1.  安装 PHP 8。这只安装了 PHP 8 核心和基本扩展：

```php
apt install php8.0
```

1.  使用以下命令扫描存储库以获取额外的扩展，并使用`apt`根据需要安装它们：

```php
apt search php8.0-*
```

1.  进行 PHP 版本检查，以确保您现在正在运行 PHP 8：

```php
php --version
```

以下是版本检查输出：

```php
root@ec873e16ee93:/# php --version
PHP 8.0.7 (cli) (built: Jun  4 2021 21:26:10) ( NTS )
Copyright (c) The PHP Group
Zend Engine v4.0.7, Copyright (c) Zend Technologies
with Zend OPcache v8.0.7, Copyright (c), by Zend Technologies
```

现在您已经对 PHP 8 安装可能进行的基本步骤有了基本的了解，让我们看看如何在当前版本和 PHP 8 之间切换。为了举例说明，我们假设在安装 PHP 8 之前，PHP 7.4 是当前的 PHP 版本。

### 在 Debian 和 Ubuntu Linux 之间切换 PHP 版本

如果您检查 PHP 的位置，您会注意到在 PHP 8 安装后，较早的版本 PHP 7.4 仍然存在。您可以使用`whereis php`来实现这一目的。我们模拟的 Ubuntu Docker 容器上的输出如下：

```php
root@ec873e16ee93:/# whereis php
php: /usr/bin/php /usr/bin/php8.0 /usr/bin/php7.4 /usr/lib/php /etc/php /usr/share/php7.4-opcache /usr/share/php8.0-opcache /usr/share/php8.0-readline /usr/share/php7.4-readline /usr/share/php7.4-json /usr/share/php8.0-common /usr/share/php7.4-common
```

如您所见，我们现在安装了 7.4 和 8.0 版本的 PHP。要在两者之间切换，请使用此命令：

```php
update-alternatives --config php
```

然后会出现一个选项屏幕，让您选择哪个 PHP 版本应该处于活动状态。以下是 Ubuntu Docker 镜像上输出屏幕的样子：

```php
root@ec873e16ee93:/# update-alternatives --config php 
There are 2 choices for the alternative php 
(providing /usr/bin/php).
  Selection    Path             Priority   Status
------------------------------------------------------------
* 0            /usr/bin/php8.0   80        auto mode
  1            /usr/bin/php7.4   74        manual mode
  2            /usr/bin/php8.0   80        manual mode
Press <enter> to keep the current choice[*], or type selection number:
```

切换后，您可以再次执行`php --version`来确认另一个 PHP 版本是否处于活动状态。

现在让我们把注意力转向 Red Hat Linux 及其衍生产品上的 PHP 8 安装。

### 在 Red Hat、CentOS 或 Fedora Linux 上安装 PHP 8

Red Hat、CentOS 或 Fedora Linux 上的 PHP 安装遵循一系列与 Debian/Ubuntu 安装过程相似的命令。主要区别在于，您很可能会使用`dnf`和`yum`的组合来安装预编译的 PHP 二进制文件。

如果您想跟随本节中我们概述的安装步骤，可以使用一个已经安装了 PHP 7.4 的 Fedora Docker 容器进行模拟。以下是运行模拟的命令：

```php
docker run -it unlikelysource/fedora_34_with_php_7_4 /bin/bash
```

与前一节描述的 PPA 环境非常相似，在 Red Hat 世界中，**Remi's RPM Repository**项目（[`rpms.remirepo.net/`](http://rpms.remirepo.net/)）以**Red Hat Package Management**（**RPM**）格式提供预编译的二进制文件。

要在 Red Hat、CentOS 或 Fedora 上安装 PHP 8，请打开一个命令行到生产服务器（或演示环境）上，并以*root*用户的身份进行如下操作：

1.  首先，确认您正在使用的操作系统版本和发行版是一个好主意。为此，使用`uname`命令，以及一个简单的`cat`命令来查看发行版（存储在`/etc`目录中的文本文件）：

```php
[root@9d4e8c93d7b6 /]# uname -a
Linux 9d4e8c93d7b6 5.8.0-55-generic #62~20.04.1-Ubuntu
SMP Wed Jun 2 08:55:04 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
[root@9d4e8c93d7b6 /]# cat /etc/fedora-release 
Fedora release 34 (Thirty Four)
```

1.  在开始之前，请确保更新`dnf`并安装配置管理器：

```php
dnf upgrade  
dnf install 'dnf-command(config-manager)'
```

1.  然后，您可以将 Remi 的存储库添加到您的软件包源中，使用您喜欢的版本号替换`NN`：

```php
dnf install \
  https://rpms.remirepo.net/fedora/remi-release-NN.rpm
```

1.  此时，您可以使用`dnf module list`确认已安装的 PHP 版本。我们还使用`grep`来限制显示的模块列表仅为 PHP。`[e]`表示*已启用*：

```php
[root@56b9fbf499d6 /]# dnf module list |grep php
php                    remi-7.4 [e]     common [d] [i],
devel, minimal    PHP scripting language                        php                    remi-8.0         common [d], devel, minimal        PHP scripting language
```

1.  然后我们检查当前的 PHP 版本：

```php
[root@d044cbe477c8 /]# php --version
PHP 7.4.20 (cli) (built: Jun  1 2021 15:41:56) (NTS)
Copyright (c) The PHP Group
Zend Engine v3.4.0, Copyright (c) Zend Technologies
```

1.  接下来，我们重置 PHP 模块，并安装 PHP 8：

```php
dnf -y module reset php
dnf -y module install php:remi-8.0
```

1.  另一个快速的 PHP 版本检查显示我们现在使用的是 PHP 8 而不是 PHP 7：

```php
[root@56b9fbf499d6 /]# php -v
PHP 8.0.7 (cli) (built: Jun  1 2021 18:43:05) 
( NTS gcc x86_64 ) Copyright (c) The PHP Group
Zend Engine v4.0.7, Copyright (c) Zend Technologies
```

1.  要切换回较早版本的 PHP，请按照以下步骤进行，其中`X.Y`是您打算使用的版本：

```php
dnf -y module reset php
dnf -y module install php:remi-X.Y
```

这完成了 Red Hat、CentOS 或 Fedora 的 PHP 安装说明。在本演示中，我们只向您展示了 PHP 命令行安装。如果您计划与 Web 服务器一起使用 PHP，还需要安装适当的 PHP Web 服务器包和/或安装 PHP-FPM（FastCGI 处理模块）包。

现在让我们来看看最后一步。

## 第 12 步 – 测试并将暂存环境克隆到生产环境

在最后一步中，您将从 PHP 8 迁移分支下载源代码到暂存环境，并运行各种测试以确保一切正常。一旦您确保成功，然后将暂存环境克隆到生产环境。

如果您使用虚拟化，克隆过程可能只涉及创建一个相同的 Docker 容器或虚拟磁盘文件。否则，如果涉及实际硬件，您可能最终会克隆硬盘，或者根据您的设置选择适当的方法。

这完成了我们关于如何执行迁移的讨论。现在让我们来看看测试和故障排除。

# 测试和故障排除迁移

在理想的情况下，迁移故障排除将在上线服务器或模拟的虚拟环境上进行，远在实际上线之前。然而，正如经验丰富的开发人员所知，我们需要抱最好的希望，但做最坏的准备！在本节中，我们将涵盖一些可能被轻易忽视的测试和故障排除的其他方面。

在本节中，如果您正在遵循 Debian/Ubuntu 或 Red Hat/CentOS/Fedora 安装过程，可以退出临时 shell。返回用于本课程的 Docker 容器，并打开 PHP 8 容器的命令 shell。如果您不确定如何操作，请参阅*第一章*的*技术要求*部分，了解更多信息。

## 测试和故障排除工具

这里有太多优秀的测试和故障排除工具可用，无法在此处一一列举，因此我们将重点放在一些开源工具上，以帮助测试和故障排除。

### 使用 Xdebug

Xdebug 是一个工具，提供诊断、分析、跟踪和逐步调试等功能。它是一个 PHP 扩展，因此能够在您遇到无法轻松解决的问题时提供详细信息。主要网站是[`xdebug.org/`](https://xdebug.org/)。

要启用 Xdebug 扩展，您可以像安装任何其他 PHP 扩展一样安装它：使用`pecl`命令，或者从[`pecl.php.net/package/xdebug`](https://pecl.php.net/package/xdebug)下载并编译源代码。

此外，至少应设置以下`/etc/php.ini`设置：

```php
zend_extension=xdebug.so
xdebug.log=/repo/xdebug.log
xdebug.log_level=7
xdebug.mode=develop,profile
```

*图 11.2*显示了从`/repo/ch11/php8_xdebug.php`调用的`xdebug_info()`命令的输出：

![图 11.2 – xdebug_info()输出](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_11.2_B16562.jpg)

图 11.2 – xdebug_info()输出

现在让我们来看看另一个从外部视角检查您的应用程序的工具。

### 使用 Apache JMeter

用于测试 Web 应用程序的一个非常有用的开源工具是**Apache JMeter**([`jmeter.apache.org/`](https://jmeter.apache.org/))。它允许您开发一系列测试计划，模拟来自浏览器的请求。您可以模拟数百个用户请求，每个请求都有自己的 cookie 和会话。尽管主要设计用于 HTTP 或 HTTPS，但它还能够处理其他十几种协议。除了出色的图形用户界面外，它还有一个命令行模式，可以将 JMeter 纳入自动部署过程中。

安装非常简单，只需从[`jmeter.apache.org/download_jmeter.cgi`](https://jmeter.apache.org/download_jmeter.cgi)下载一个文件。在运行 JMeter 之前，您必须安装**Java 虚拟机**（**JVM**）。测试计划的执行超出了本书的范围，但文档非常详尽。另外，请记住，JMeter 设计为在客户端上运行，而不是在服务器上运行。因此，如果您希望在本书的 Docker 容器中测试网站，您需要在本地计算机上安装 Apache JMeter，然后构建一个指向 Docker 容器的测试计划。通常，PHP 8 容器的 IP 地址是`172.16.0.88`。

*图 11.3*显示了在本地计算机上运行的 Apache JMeter 的开屏幕：

![图 11.3 – Apache JMeter](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_11.3_B16562.jpg)

图 11.3 – Apache JMeter

从这个屏幕上，您可以开发一个或多个测试计划，指示要访问的 URL，模拟`GET`和`POST`请求，设置用户数量等。

提示

如果您在尝试运行`jmeter`时遇到此错误：“无法加载库：/usr/lib/jvm/java-11-openjdk-amd64/lib/ libawt_xawt.so”，请尝试安装*OpenJDK 8*。然后，您可以使用前面部分提到的技术来在不同版本的 Java 之间切换。

现在让我们看看在 PHP 8 升级后可能出现的 Composer 问题。

## 处理 Composer 的问题

在迁移到 PHP 8 后，开发人员可能面临的一个常见问题是与第三方软件有关。在本节中，我们讨论了使用流行的*Composer*包管理器为 PHP 可能遇到的潜在问题。

您可能会遇到的第一个问题与 Composer 本身的版本有关。在 2020 年，Composer 2 版本发布了。然而，并非所有驻留在主要打包网站([`packagist.org/`](https://packagist.org/))上的 30 万多个软件包都已更新到版本 2。因此，为了安装特定软件包，您可能需要在 Composer 2 和 Composer 1 之间切换。每个版本的最新发布都在这里：

+   版本 1：[`getcomposer.org/download/latest-1.x/composer.phar`](https://getcomposer.org/download/latest-1.x/composer.phar)

+   版本 2：[`getcomposer.org/download/latest-2.x/composer.phar`](https://getcomposer.org/download/latest-2.x/composer.phar)

另一个更严重的问题与您可能使用的各种 Composer 软件包的平台要求有关。每个软件包都有自己的`composer.json`文件，具有自己的要求。在许多情况下，软件包提供者可能会添加 PHP 版本要求。

问题在于，虽然大多数 Composer 软件包现在在 PHP 7 上运行，但要求是以一种排除 PHP 8 的方式指定的。在 PHP 8 更新后，当您使用 Composer 更新第三方软件包时，会出现错误并且更新失败。具有讽刺意味的是，大多数 PHP 7 软件包也可以在 PHP 8 上运行！

例如，我们安装了一个名为`laminas-api-tools`的 Composer 项目。在撰写本文时，尽管软件包本身已准备好用于 PHP 8，但其许多依赖软件包尚未准备好。在运行安装 API 工具的命令时，会遇到以下错误：

```php
root@php8_tips_php8 [ /srv ]# 
composer create-project laminas-api-tools/api-tools-skeleton
Creating a "laminas-api-tools/api-tools-skeleton" project at "./api-tools-skeleton"
Installing laminas-api-tools/api-tools-skeleton (1.3.1p1)
  - Downloading laminas-api-tools/api-tools-skeleton (1.3.1p1)
  - Installing laminas-api-tools/api-tools-skeleton (1.3.1p1):
Extracting archiveCreated project in /srv/api-tools-skeleton
Loading composer repositories with package information
Updating dependencies
Your requirements could not be resolved to an installable set of packages.
  Problem 1
    - Root composer.json requires laminas/laminas-developer-tools dev-master, found laminas/laminas-developer-tools[dev-release-1.3, 0.0.1, 0.0.2, 1.0.0alpha1, ..., 1.3.x-dev, 2.0.0, ..., 2.2.x-dev] but it does not match the constraint.
  Problem 2
    - zendframework/zendframework 2.5.3 requires php ⁵.5     || ⁷.0 -> your php version (8.1.0-dev) does not satisfy     that requirement.
```

刚刚显示的输出的最后部分突出显示的核心问题是，其中一个依赖包需要 PHP `⁷.0`。在 `composer.json` 文件中，这表示从 PHP 7.0 到 PHP 8.0 的一系列版本。在这个特定的例子中，使用的 Docker 容器运行的是 PHP 8.1，所以我们有问题。

幸运的是，在这种情况下，我们有信心，如果这个包在 PHP 8.0 中运行，它也应该在 PHP 8.1 中运行。因此，我们只需要添加 `--ignore-platform-reqs` 标志。当我们重新尝试安装时，如下输出所示，安装成功了：

```php
root@php8_tips_php8 [ /srv ]# 
composer create-project --ignore-platform-reqs \
    laminas-api-tools/api-tools-skeleton
Creating a "laminas-api-tools/api-tools-skeleton" project at "./api-tools-skeleton"
Installing laminas-api-tools/api-tools-skeleton (1.6.0)
  - Downloading laminas-api-tools/api-tools-skeleton (1.6.0)
  - Installing laminas-api-tools/api-tools-skeleton (1.6.0):
Extracting archive
Created project in /srv/api-tools-skeleton
Installing dependencies from lock file (including require-dev)
Verifying lock file contents can be installed on current
platform.
Package operations: 109 installs, 0 updates, 0 removals
- Downloading laminas/laminas-zendframework-bridge (1.3.0)
- Downloading laminas-api-tools/api-tools-asset-manager
(1.4.0)
- Downloading squizlabs/php_codesniffer (3.6.0)
- Downloading dealerdirect/phpcodesniffer-composer-installer
(v0.7.1)
- Downloading laminas/laminas-component-installer (2.5.0)
... not all output is shown
```

刚刚显示的输出中，没有出现平台要求错误，我们可以继续使用应用程序。

现在让我们把注意力转向单元测试。

## 使用单元测试

使用 PHPUnit 进行单元测试是确保应用程序在添加新功能或进行 PHP 更新后能够运行的关键因素。大多数开发人员至少创建一组单元测试，以至少执行最低要求，以证明应用程序的预期性能。测试是一个类中的方法，该类扩展了 `PHPUnit\Framework\TestCase`。测试的核心是所谓的“断言”。

提示

本书不涵盖如何创建和运行测试的说明。但是，您可以在主要 PHPUnit 网站的出色文档中找到大量示例：[`phpunit.de/`](https://phpunit.de/)。

在进行 PHP 迁移后，您可能会遇到的问题是 PHPUnit（[`phpunit.de/`](https://phpunit.de/)）本身可能会失败！原因是因为 PHPUnit 每年都会发布一个新版本，对应于当年的 PHP 版本。较旧的 PHPUnit 版本是基于官方支持的 PHP 版本。因此，您的应用程序当前安装的 PHPUnit 版本可能是不支持 PHP 8 的较旧版本。最简单的解决方案是使用 Composer 进行更新。

为了说明可能的问题，让我们假设应用程序的测试目录当前包括 PHP unit 5。如果我们在运行 PHP 7.1 的 Docker 容器中运行测试，一切都按预期工作。以下是输出：

```php
root@php8_tips_php7 [ /repo/test/phpunit5 ]# php --version
PHP 7.1.33 (cli) (built: May 16 2020 12:47:37) (NTS)
Copyright (c) 1997-2018 The PHP Group
Zend Engine v3.1.0, Copyright (c) 1998-2018 Zend Technologies
    with Xdebug v2.9.1, Copyright (c) 2002-2020, by Derick
Rethans
root@php8_tips_php7 [ /repo/test/phpunit5 ]#
vendor/bin/phpunit 
PHPUnit 5.7.27 by Sebastian Bergmann and contributors.
........                                                          8 / 8 (100%)
Time: 27 ms, Memory: 4.00MB
OK (8 tests, 8 assertions)
```

然而，如果我们在运行 PHP 8 的 Docker 容器中运行相同的版本，结果会大不相同：

```php
root@php8_tips_php8 [ /repo/test/phpunit5 ]# php --version
PHP 8.1.0-dev (cli) (built: Dec 24 2020 00:13:50) (NTS)
Copyright (c) The PHP Group
Zend Engine v4.1.0-dev, Copyright (c) Zend Technologies
    with Zend OPcache v8.1.0-dev, Copyright (c), 
    by Zend Technologies
root@php8_tips_php8 [ /repo/test/phpunit5 ]#
vendor/bin/phpunit 
PHP Warning:  Private methods cannot be final as they are never overridden by other classes in /repo/test/phpunit5/vendor/ phpunit/phpunit/src/Util/Configuration.php on line 162
PHPUnit 5.7.27 by Sebastian Bergmann and contributors.
........                                                            8 / 8 (100%)
Time: 33 ms, Memory: 2.00MB
OK (8 tests, 8 assertions)
```

从输出中可以看出，PHPUnit 本身报告了一个错误。当然，简单的解决方案是，在 PHP 8 升级后，您还需要重新运行 Composer，并更新您的应用程序及其使用的所有第三方包。

这就结束了我们对测试和故障排除的讨论。您现在知道可以使用哪些额外工具来帮助您进行测试和故障排除。请注意，这绝不是所有测试和故障排除工具的全面列表。还有许多其他工具，有些是免费开源的，有些提供免费试用期，还有一些只能通过购买获得。

# 总结

在本章中，您了解到术语“环境”是指“服务器”，因为如今许多网站使用虚拟化服务。然后，您了解到在部署阶段使用了三种不同的环境：开发、暂存和生产。

介绍了一种自动化工具，能够扫描您的应用程序代码，以寻找潜在的代码错误。正如您在该部分学到的那样，一个扫描应用程序可能包括一个配置文件，用于处理已删除的功能、方法签名的更改、不再生成资源的函数，以及用于复杂用法检测的一组回调，一个扫描类，以及一个收集文件名的调用程序。

接下来，您将看到一个典型的十二步 PHP 8 迁移过程，确保在最终准备升级生产环境时成功的机会更大。每个步骤都旨在发现潜在的代码错误，并在出现问题时有备用程序。您还学会了如何在两个常见平台上安装 PHP 8，以及如何轻松地恢复到旧版本。最后，您了解了一些可以帮助测试和故障排除的免费开源工具。

总的来说，仔细阅读本章并学习示例后，您现在不仅可以使用现有的测试和故障排除工具，还可以想到如何开发自己的扫描工具，大大降低 PHP 8 迁移后潜在代码错误的风险。您现在也对 PHP 8 迁移涉及的内容有了很好的了解，并且可以进行更顺畅的过渡，而不必担心失败。您新的预期和解决迁移问题的能力将减轻您可能会遇到的任何焦虑。您还可以期待拥有快乐和满意的客户。

下一章将介绍 PHP 编程中的新潮流和令人兴奋的趋势，可以进一步提高性能。
