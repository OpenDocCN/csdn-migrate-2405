# Linux 系统编程实用手册（八）

> 原文：[`zh.annas-archive.org/md5/9713B9F84CB12A4F8624F3E68B0D4320`](https://zh.annas-archive.org/md5/9713B9F84CB12A4F8624F3E68B0D4320)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：Pthreads 多线程第三部分

在第十四章和第十五章中已经涵盖了编写强大的多线程（MT）应用程序的许多原因和方法，本章重点介绍了教授读者多线程编程的几个关键安全方面。

它为开发安全和健壮的 MT 应用程序的许多关键安全方面提供了一些启示；在这里，读者将了解线程安全性，为什么需要它以及如何使函数线程安全。在运行时，可能会有一个线程杀死另一个线程；这是通过线程取消机制实现的——与取消一起，如何确保在线程终止之前，首先确保它释放任何仍在持有的资源（如锁和动态内存）？线程清理处理程序用于展示这一点。

最后，本章深入探讨了如何安全地混合多线程和信号，多进程与多线程的一些优缺点，以及一些技巧和常见问题解答。

# 线程安全

在开发多线程应用程序时一个关键，但不幸的是经常不明显的问题是线程安全。一个*线程安全*，或者如 man 页面所指定的那样，MT-Safe 的函数或 API 是可以安全地由多个线程并行执行而没有不利影响的函数。

要理解这个线程安全问题实际上是什么，让我们回到我们在[附录 A](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)中看到的程序之一，*文件 I/O 基础知识*；您可以在书的 GitHub 存储库中找到源代码：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux/blob/master/A_fileio/iobuf.c`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux/blob/master/A_fileio/iobuf.c)。在这个程序中，我们使用`fopen(3)`以附加模式打开文件，然后对其进行一些 I/O（读/写）；我们在这里复制了该章节的一小段：

+   我们通过`fopen(3)`在附加模式（`a`）中打开一个流到我们的目标，只是在`/tmp`目录中的一个常规文件（如果不存在，将创建它）

+   然后，在一个循环中，对用户提供的迭代次数，我们将执行以下操作：

+   通过`fread(3)`stdio 库 API 从源流中读取几个（512）字节（它们将是随机值）

+   通过`fwrite(3)`stdio 库 API 将这些值写入我们的目标流（检查 EOF 和/或错误条件）

这是代码片段，主要是`testit`函数执行实际的 I/O；参考：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux/blob/master/A_fileio/iobuf.c`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux/blob/master/A_fileio/iobuf.c)：

```
static char *gbuf = NULL;

static void testit(FILE * wrstrm, FILE * rdstrm, int numio)
{
  int i, syscalls = NREAD*numio/getpagesize();
  size_t fnr=0;

  if (syscalls <= 0)
      syscalls = 1;
  VPRINT("numio=%d total rdwr=%u expected # rw syscalls=%d\n",
                 numio, NREAD*numio, NREAD*numio/getpagesize());

  for (i = 0; i < numio; i++) {
     fnr = fread(gbuf, 1, NREAD, rdstrm);
     if (!fnr)
         FATAL("fread on /dev/urandom failed\n");

     if (!fwrite(gbuf, 1, fnr, wrstrm)) {
         free(gbuf);
         if (feof(wrstrm))
             return;
         if (ferror(wrstrm))
             FATAL("fwrite on our file failed\n");
     }
  }
}
```

注意代码的第一行，它对我们的讨论非常重要；用于保存源和目标数据的内存缓冲区是一个全局（静态）变量，`gbuf`。

这是在应用程序的`main()`函数中分配的位置：

```
...
  gbuf = malloc(NREAD);
  if (!gbuf)
      FATAL("malloc %zu failed!\n", NREAD);
...
```

那又怎样？在《附录 A》*文件 I/O 基础*中，我们以隐含的假设为前提，即进程是单线程的；只要这个假设保持不变，程序就能正常工作。但仔细想想；一旦我们想要将这个程序移植成多线程能力，这段代码就不够好了。为什么？很明显：如果多个线程同时执行`testit`函数的代码（这正是预期的），全局共享的可写内存变量`gbuf`的存在告诉我们，在代码路径中会有临界区。正如我们在《第十五章》*使用 Pthreads 进行多线程 - 同步*中详细学到的，每个临界区必须要么被消除，要么被保护起来以防止数据竞争。

在前面的代码片段中，我们高兴地在这个全局缓冲区上调用了`fread(3)`和`fwrite(3)`，而没有任何保护。*想象一下多个线程同时运行这段代码路径；结果将是一片混乱。

所以，现在我们可以看到并得出结论，`testit`函数是不是线程安全的（至少，程序员必须记录这一事实，防止其他人在多线程应用中使用这段代码！）。

更糟糕的是，我们开发的前面的线程不安全函数被合并到一个共享库（在 Unix/Linux 上通常称为共享对象文件）中；任何链接到这个库的（多线程）应用程序都将可以访问这个函数。如果这样的应用程序的多个线程曾经调用它，我们就有了潜在的竞争 - 一个错误，一个缺陷！不仅如此，这样的缺陷是真正难以发现和理解的，会引起各种问题，也许还会有各种临时的应急措施（这只会让情况变得更糟，让客户对软件的信心更少）。灾难确实是以看似无辜的方式引起的。

我们的结论是，要么使函数线程安全，要么明确将其标记为线程不安全（如果有的话，只在单线程环境中使用）。

# 使代码线程安全

显然，我们希望使`testit`函数线程安全。现在问题变成了，我们究竟该如何做到呢？嗯，再次，这很简单：有两种方法（实际上不止两种，但我们稍后再讨论）。

如果我们能消除代码路径中的任何全局共享可写数据，我们将不会有临界区问题；换句话说，它将变得线程安全。因此，实现这一点的一种方法是确保函数只使用本地（自动）变量。该函数现在是可重入安全的。在进一步进行之前，了解一些关于可重入和线程安全的关键要点是很重要的。

# 可重入安全与线程安全

可重入安全究竟与线程安全有何不同？混淆确实存在。这里有一个简洁的解释：可重入安全是在多任务和多线程操作系统出现之前的一个问题，其含义是只有一个相关的线程在执行。为了使函数具有可重入安全性，它应该能够在上一个上下文尚未完成执行的情况下，从另一个上下文中被正确地重新调用（想象一个信号处理程序在已经执行的情况下重新调用给定的函数）。关键要求是：它应该只使用局部变量，或者具有保存和恢复它使用的全局变量的能力，以便它是安全的。（这些想法在《第十一章》*信号 - 第一部分*的*可重入安全和信号*部分中有详细讨论。正如我们在那一章中提到的，信号处理程序应该只调用那些保证是可重入安全的函数；在信号处理上下文中，这些函数被称为是异步信号安全的。）

另一方面，线程安全是一个更近期的问题-我们指的是支持多线程的现代操作系统。一个线程安全的函数可以在多个线程（可能在多个 CPU 核心上）同时并行调用，而不会破坏它。共享的可写数据是重要的，因为代码本身只能读取和执行，因此完全可以并行执行。

通过使用互斥锁使函数线程安全（这些讨论将详细介绍并举例说明）是可能的，但会引入性能问题。有更好的方法使函数线程安全：重构它，或者使用 TLS 或 TSD-我们将在“通过 TLS 实现线程安全”和“通过 TSD 实现线程安全”部分介绍这些方法。

简而言之，可重入安全关注的是一个线程在活动调用仍然存在时重新调用函数；线程安全关注的是多个线程-并发代码-同时执行相同的函数。 （一个优秀的 Stack Overflow 帖子更详细地描述了这一点，请参考 GitHub 存储库上的*进一步阅读*部分。）

现在，回到我们之前的讨论。理论上，只使用局部变量听起来不错（对于小型实用函数，我们应该设计成这样），但现实是，有些复杂的项目会以这样的方式发展，以至于在函数内部使用全局共享可写数据对象是无法避免的。在这种情况下，根据我们在之前的第十五章中学到的关于同步的知识，我们知道答案：识别和保护关键部分，使用互斥锁。

是的，那样可以，但会显著影响性能。请记住，锁会破坏并行性并使代码流程串行化，从而创建瓶颈。在不使用互斥锁的情况下实现线程安全才是真正构成可重入安全函数的关键。这样的代码确实是有用的，并且可以实现；有两种强大的技术可以实现这一点，称为 TLS 和 TSD。请稍作耐心，我们将在“通过 TLS 实现线程安全”和“通过 TSD 实现线程安全”部分介绍如何使用这些技术。

需要强调的一点是：设计师和程序员必须保证所有可以在任何时间点由多个线程执行的代码都被设计、实现、测试和记录为线程安全。这是设计和实现多线程应用程序时需要满足的关键挑战之一。

另一方面，如果可以保证一个函数始终只会被单个线程执行（例如在创建线程之前从 main()调用的早期初始化例程），那显然就不需要保证它是线程安全的。

# 总结表-使函数线程安全的方法

让我们总结前面的观点，以表格的形式告诉我们如何实现所有函数的重要目标-线程安全：

| **使函数线程安全的方法** | **评论** |
| --- | --- |
| 只使用局部变量 | 天真；在实践中难以实现。 |
| 使用全局和/或静态变量，并使用互斥锁保护关键部分 | 可行但可能会显著影响性能[1] |
| 重构函数，使其可重入安全-通过使用更多参数来消除函数中静态变量的使用 | 有用的方法-将几个旧的`foo` glibc 函数重构为`foo_r`。 |
| **线程本地存储**（**TLS**） | 通过每个线程拥有一个变量副本来确保线程安全；工具链和操作系统版本相关。非常强大且易于使用。 |
| **线程特定数据**（**TSD**） | 同样的目标：使数据线程安全-旧的实现，使用起来更麻烦。 |

表 1：使函数线程安全的方法

[1]虽然我们说使用互斥锁可能会显著影响性能，但在正常情况下，互斥锁的性能确实非常高（主要是因为在 Linux 上通过 futex-快速用户互斥锁进行内部实现）。

让我们更详细地查看这些方法。

第一种方法，只使用局部变量，是一个相当天真的方法，可能只适用于小型程序；我们就此打住。

# 通过互斥锁实现线程安全

考虑到函数确实使用全局和/或静态变量，并且决定继续使用它们（我们在*表 1*中提到的第二种方法），显然在代码中使用它们的地方构成了关键部分。正如第十五章“使用 Pthreads 进行多线程编程第二部分-同步”中详细展示的那样，我们必须保护这些关键部分；在这里，我们使用 pthread 的互斥锁来实现。

为了可读性，这里只显示了源代码的关键部分；要查看完整的源代码，构建并运行它，整个树都可以从 GitHub 克隆：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

我们将这种方法应用于我们示例函数的 pthread 互斥锁的添加（我们适当地重命名它；在下面的片段中找到完整的源代码：`ch16/mt_iobuf_mtx.c`）：

```
static void testit_mt_mtx(FILE * wrstrm, FILE * rdstrm, int numio,
                             int thrdnum)
{
 ...
  for (i = 0; i < numio; i++) {
 LOCK_MTX(&mylock);
      fnr = fread(gbuf, 1, NREAD, rdstrm);
      UNLOCK_MTX(&mylock);
      if (!fnr)
          FATAL("fread on /dev/urandom failed\n");

 LOCK_MTX(&mylock);
      if (!fwrite(gbuf, 1, fnr, wrstrm)) {
          free(gbuf);
 UNLOCK_MTX(&mylock);
          if (feof(wrstrm))
              return;
          if (ferror(wrstrm))
              FATAL("fwrite on our file failed\n");
      }
 UNLOCK_MTX(&mylock);
   }
}
```

在这里，我们使用相同的宏来执行互斥锁和解锁，就像我们在（为了避免重复，我们不显示初始化互斥锁的代码，请参考第十五章“使用 Pthreads 进行多线程编程第二部分-同步”中的细节。我们还添加了一个额外的`thrdnum`参数到函数中，以便能够打印出当前正在运行的线程编号。）

关键点：在关键部分——我们访问（读取或写入）共享可写全局变量`gbuf`的代码部分——我们获取互斥锁，执行访问（在我们的情况下是`fread(3)`和`fwrite(3)`），然后释放互斥锁。

现在，即使多个线程运行前面的函数，也不会出现数据完整性问题。是的，它会工作，但会付出显著的性能代价；正如前面所述，每个关键部分（在`lock`和相应的`unlock`之间的代码）都将被序列化。因此，在代码路径中，锁定可能形成瓶颈，特别是如果，就像我们的示例一样，`numio`参数是一个大数，那么`for`循环将执行一段时间。类似地，如果函数是一个繁忙的函数并且经常被调用，那么也会产生瓶颈。（使用`perf(1)`进行快速检查，单线程版本执行 100,000 次 I/O 需要 379 毫秒，而带锁的多线程版本执行相同次数的 I/O 需要 790 毫秒。）

我们已经涵盖了这一点，但让我们快速测试一下自己：为什么我们没有保护使用变量`fnr`和`syscalls`的代码部分？答案是因为它是一个局部变量；更重要的是，当执行前面的函数时，每个线程都会获得自己的局部变量副本，因为每个线程都有自己的私有堆栈，局部变量是在堆栈上实例化的。

为了使程序工作，我们必须重构前面的函数如何实际设置为线程工作程序；我们发现需要使用自定义数据结构向每个线程传递各种参数，然后有一个小的`wrapper`函数—`wrapper_testit_mt_mtx()`—调用实际的 I/O 函数；我们留给读者详细查看源代码。

让我们运行它：

```
$ ./mt_iobuf_mtx 10000
./mt_iobuf_mtx: using default stdio IO RW buffers of size 4096 bytes; # IOs=10000
mt_iobuf_mtx.c:testit_mt_mtx:62: [Thread #0]: numio=10000   total rdwr=5120000   expected # rw syscalls=1250
mt_iobuf_mtx.c:testit_mt_mtx:66: gbuf = 0x23e2670
mt_iobuf_mtx.c:testit_mt_mtx:62: [Thread #1]: numio=10000   total rdwr=5120000   expected # rw syscalls=1250
mt_iobuf_mtx.c:testit_mt_mtx:66: gbuf = 0x23e2670
 Thread #0 successfully joined; it terminated with status=0
 Thread #1 successfully joined; it terminated with status=0
$ 
```

这揭示了全部情况；显然，正在使用的 I/O 缓冲区`gbuf`对于两个线程是相同的（看打印出的地址），因此需要对其进行锁定。

顺便说一下，在标准文件流 API 中存在（非标准）*_unlocked APIs，例如`fread_unlocked(3)`和`fwrite_unlocked(3)`。它们与常规 API 相同，只是在文档中明确标记为 MT-unsafe。不建议使用它们。

顺便说一下，打开的文件是进程的线程之间共享的资源；开发人员也必须考虑到这一点。在同一底层文件对象上同时使用多个线程进行 IO 可能会导致损坏，除非使用文件锁定技术。在这种特定情况下，我们明确使用互斥锁来保护临界区-这些临界区恰好是我们进行文件 I/O 的地方，因此显式文件锁定变得不必要。

# 通过函数重构实现线程安全

正如我们在前面的示例中看到的，我们需要互斥锁，因为`gbuf`全局缓冲区被所有应用程序线程用作它们的 I/O 缓冲区。因此，请考虑一下：如果我们可以为每个线程分配一个本地 I/O 缓冲区呢？那确实会解决问题！具体如何做将在下面的代码中展示。

但首先，现在您已经熟悉了之前的示例（我们在其中使用了互斥锁），请研究重构后程序的输出：

```
$ ./mt_iobuf_rfct 10000
./mt_iobuf_rfct: using default stdio IO RW buffers of size 4096 bytes; # IOs=10000
mt_iobuf_rfct.c:testit_mt_refactored:51: [Thread #0]: numio=10000   total rdwr=5120000   expected # rw syscalls=1250
 iobuf = 0x7f283c000b20
mt_iobuf_rfct.c:testit_mt_refactored:51: [Thread #1]: numio=10000   total rdwr=5120000   expected # rw syscalls=1250
 iobuf = 0x7f2834000b20
 Thread #0 successfully joined; it terminated with status=0
 Thread #1 successfully joined; it terminated with status=0
$ 
```

关键认识：这里使用的 I/O 缓冲区`iobuf`对于每个线程都是唯一的（只需查看打印出的地址）！因此，这消除了 I/O 函数中的临界区和使用互斥锁的需要。实际上，该函数仅使用本地变量，因此既可重入又线程安全。

为了可读性，这里只显示了源代码的关键部分。要查看完整的源代码，请构建并运行它；整个树可在 GitHub 上克隆：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

以下代码片段清楚地显示了如何设置（完整源代码：`ch16/mt_iobuf_rfct.c`）：

```
struct stToThread {
    FILE *wrstrm, *rdstrm;
    int thrdnum, numio;
 char *iobuf;
};
static struct stToThread *ToThread[NTHREADS];
static void * wrapper_testit_mt_refactored(void *msg)
{
  struct stToThread *pstToThread = (struct stToThread *)msg;
  assert (pstToThread);

  /* Allocate the per-thread IO buffer here, thus avoiding the global
 * heap buffer completely! */
 pstToThread->iobuf = malloc(NREAD);
  ...
  testit_mt_refactored(pstToThread->wrstrm, pstToThread->rdstrm,
           pstToThread->numio, pstToThread->thrdnum,
           pstToThread->iobuf);

  free(pstToThread->iobuf);
  pthread_exit((void *)0);
}
```

可以看到，我们通过向自定义`stToThread`结构添加额外的缓冲区指针成员来进行重构。重要的部分是：在线程包装函数中，我们分配了内存并将指针传递给我们的线程例程。我们为此目的向我们的线程 I/O 例程添加了额外的参数：

```
static void testit_mt_refactored(FILE * wrstrm, FILE * rdstrm, int numio, int thrdnum, char *iobuf)
{
...
  for (i = 0; i < numio; i++) {
      fnr = fread(iobuf, 1, NREAD, rdstrm);
      if (!fnr)
          FATAL("fread on /dev/urandom failed\n");
      if (!fwrite(iobuf, 1, fnr, wrstrm)) {
      ...
  }
```

现在，在前面的 I/O 循环中，我们操作每个线程的`iobuf`缓冲区，因此没有临界区，也不需要锁定。

# 标准 C 库和线程安全

标准 C 库（glibc）中有相当多的代码不是线程安全的。什么？有人会问。但是，嘿，很多这些代码是在 20 世纪 70 年代和 80 年代编写的，当时多线程并不存在（至少对于 Unix 来说）；因此，我们几乎不能责怪他们没有设计成线程安全！

# 不需要线程安全的 API 列表

标准 C 库 glibc 有许多较旧的函数，按照 Open Group 手册的说法，这些函数不需要线程安全（或者不需要线程安全）。POSIX.1-2017 的这一卷中定义的所有函数都应该是线程安全的，除了以下函数不需要线程安全。这实际上意味着什么？简单：这些 API 不是线程安全的。因此，请小心-不要在 MT 应用程序中使用它们。完整列表可以在以下网址找到：[`pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_09_01`](http://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_09_01)。

当然，前面的列表只适用于 POSIX.1-2017，并且可能会过时。读者必须意识到这个反复出现的问题，以及不断更新这样的信息的需要。

它们大多是库层（glibc）的 API。在所有前面的 API 中，只有一个-`readdir(2)`-是一个系统调用；这也被认为是不推荐使用的（我们应该使用它的 glibc 包装器`readdir(3)`）。作为一个经验法则，所有系统调用都是编写为线程安全的。

一个有趣的事实：PHP，一种流行的 Web 脚本语言，被认为不是线程安全的；因此，提供 PHP 页面的 Web 服务器使用传统的多进程模型，而不是更快的多线程框架（例如，Apache 使用其内部的`mpm_prefork`模块-这是单线程的-来处理 PHP 页面）。

因此，看到我们刚刚讨论的内容，有人会得出结论说`glibc`不再适用于开发线程安全的 MT 应用程序吗？不，工作已经进行，将前面的许多 API 转换为线程安全。继续阅读。

# 从`foo`重构`glibc`API 为`foo_r`

当然，今天，随着 MT 应用程序成为事实上的现实，我们该怎么办呢？`glibc`的维护人员了解这些问题，并且已经使用了精确的重构技术-传递额外的参数以避免使用全局和/或静态变量（就像我们之前在`ch16/mt_iobuf_rfct.c`代码中所做的那样），包括使用参数作为返回值-来重构标准的`glibc`函数以使其成为线程安全。`glibc`的命名约定是，如果旧函数被命名为`foo`，则重构后的，通常是可重入和线程安全的版本被命名为`foo_r`。

为了帮助澄清这个讨论，让我们以一个`glibc`API 的例子来说明，它既有旧的`foo`功能，也有新的`foo_r`功能。`ctime(3)`API 经常被应用程序开发人员使用；给定一个 Unix 时间戳，它将其转换为可读的日期时间戳（ASCII 文本）。 （回想一下我们在第十三章中使用了`ctime`API，*定时器*。）让我们回忆一下，直接来自第十三章，*定时器，*Unix 系统将时间存储为自 1970 年 1 月 1 日午夜（00:00）以来经过的秒数-可以将其视为 Unix 的诞生！这个时间值被称为自纪元以来的时间或 Unix 时间。好的，但是今天会是一个相当大的秒数，对吧？那么如何以人类可读的格式表示它呢？很高兴你问到了；这正是`ctime(3)`和`ctime_r(3)`API 的工作。

`ctime(3)`API 的签名如下：

```
include <time.h>
char *ctime(const time_t *timep);
```

你是否发现了多线程应用程序的问题？返回值是以纯 ASCII 文本表示的时间；它由`ctime(3)`存储在静态（因此是共享的）数据变量中。如果多个线程同时执行`ctime(3)`（这在现代多核系统上确实会发生），就会存在脏读或写共享数据的风险。这是因为它没有受到保护；仅仅因为当`ctime(3)`首次设计和实现时，只有一个线程会在给定时间点运行它。当然，这在今天不是这样的情况。换句话说，`ctime(3)`在手册页中被标记为 MT-Unsafe，也就是说，它不是线程安全的。因此，从 MT 应用程序中调用`ctime(3)`是错误的-你会面临在某个时候出现竞争、错误或缺陷的风险。

`glibc`的开发人员确实重新实现（重构）了`ctime(3)`，使其成为可重入和线程安全；新的 API 被命名为`ctime_r(3)`。以下是它的手册页中的一句引用：可重入版本`ctime_r()`做同样的事情，但将字符串存储在用户提供的缓冲区中，该缓冲区至少应该有 26 个字节的空间。

```
char *ctime_r(const time_t *timep, char *buf);
```

太棒了！你注意到这里的关键点是`ctime(3)` API 已经被重构（并重命名为`ctime_r(3)`)，通过让用户提供结果返回的缓冲区，使其成为可重入和线程安全的？用户将如何做到这一点？简单；下面是一些代码，展示了实现这一点的一种方式（我们只需要理解概念，没有显示错误检查）：

```
// Thread Routine here
struct timespec tm;
char * mybuf = malloc(32);
...
clock_gettime(CLOCK_REALTIME, &tm); /* get the current 'UNIX' timestamp*/
ctime_r(&tm.tv_sec, mybuf); /* put the human-readable ver into 'mybuf'*/
...
free(mybuf);
```

想想看：执行前面代码的每个线程都会分配一个独立的唯一缓冲区，并将该缓冲区指针传递给`ctime_r(3)`例程。这样，我们确保不会互相干扰；API 现在是可重入和线程安全的。

请注意在前面的代码中，我们如何在 C 中实现了这种重构技巧：通过将要写入的唯一缓冲区作为值-结果式参数传递！这确实是一种常见的技术，通常由 glibc `foo_r`例程使用：我们通过传递一个或多个值给它（甚至返回给调用者，作为一种返回值）而不使用静态或全局变量（而是使用值-结果（或输入-输出）式参数）来保持例程的线程安全！

`ctime(3)`的 man 页面，以及大多数其他 API 的 man 页面，都记录了它描述的 API 是否是线程安全的：这一点非常重要！我们无法过分强调：多线程应用程序的程序员必须检查并确保在一个应该是线程安全的函数中调用的所有函数本身（记录为）是线程安全的。

这是`ctime(3)`man 页面的一部分截图，显示在**ATTRIBUTES**部分下的这些信息：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/624d94f5-2e34-4d0a-bfea-a95243a043eb.png)

图 1：`ctime(3)` man 页面的 ATTRIBUTES 部分的截图

显然，MT-Safe 意味着例程是线程安全的；MT-Unsafe 意味着它不是。attributes(7)上的 man 页面深入探讨了这些细节；它清楚地指出，线程安全并不保证 API 也是原子的；请仔细阅读。

我们还注意到 man 页面指出，POSIX.1-2008 将`ctime_r` API 本身标记为过时，并建议使用`strftime(3)`来替代。请这样做。在这里，我们仅仅使用`ctime(3)`和`ctime_r(3)` API 来举例说明 glibc 例程的线程不安全和安全版本。

# 一些 glibc `foo`和`foo_r` API

`ctime(3)`，这是不安全的线程，现在被它的线程安全的对应物`ctime_r(3)`所取代；这只是现代 glibc 中一种通用趋势的一个例子：

+   旧的、线程（MT-unsafe）不安全的函数被称为`foo`

+   有一个新的、线程（MT-Safe）安全的`foo_r` API

为了让读者了解这一点，我们列举了一些（不是全部！）glibc `foo_r`风格的 API：

| `asctime_r(3)` `crypt_r(3)`

`ctime_r(3)`

`drand48_r(3)` | `getpwnam_r(3)` `getpwuid_r(3)`

`getrpcbyname_r(3)`

`getrpcbynumber_r(3)`

`getrpcent_r(3)`

`getservbyname_r(3)` | `seed48_r(3)` `setkey_r(3)`

`srand48_r(3)`

`srandom_r(3)`

`strerror_r(3)`

`strtok_r(3)` |

| `getdate_r(3)` `getgrent_r(3)`

`getgrgid_r(3)`

`getgrnam_r(3)`

`gethostbyaddr_r(3)`

`gethostbyname2_r(3)`

`gethostbyname_r(3)`

`gethostent_r(3)`

`getlogin_r(3)` | `nrand48_r(3)` `ptsname_r(3)`

`qecvt_r(3)`

`qfcvt_r(3)`

`qsort_r(3)`

`radtofix_r(3)`

`rand_r(3)`

`random_r(3)`

`readdir_r(3)` | `ustrtok_r(3)` `val_gethostbyaddr_r(3)`

`val_gethostbyname2_r(3)`

`val_gethostbyname_r(3)` |

表 3：一些 glibc `foo_r` API

这个列表并不是详尽无遗的；请注意`ctime_r(3)` API 在这个列表中。冒着重复的风险，请确保在 MT 应用程序中只使用`foo_r` API，因为它们是`foo` API 的线程安全版本。

# 通过 TLS 实现线程安全

前面的讨论是关于已经存在的标准 C 库 glibc 及其 API 集。那么新设计和开发的 MT 应用程序呢？显然，我们为它们编写的代码必须是线程安全的。

不要忘记我们如何通过重构将我们的`testit_mt_refactored`函数变得线程安全——添加一个`iobuf`参数，传递要用于 I/O 的缓冲区的地址——确保每个线程的缓冲区都是唯一的，因此是线程安全的（无需任何锁定）。

我们能自动获得这样的功能吗？嗯，是的：编译器（GCC 和 clang）确实提供了一个几乎神奇的功能来做类似的事情：TLS。使用 TLS，用`__thread`特殊存储类关键字标记的变量将在每个活动的线程中实例化一次。实际上，如果我们只使用本地和 TLS 变量，我们的函数将根据定义是线程安全的，而无需任何（昂贵的）锁定。

确实存在一些基本规则和注意事项；让我们来看看：

+   `__thread`关键字可以单独使用，也可以与（实际上，只能与）`static`或`extern`关键字一起使用；如果与它们一起使用，必须出现在它们之后。

```
__thread long l;
extern __thread struct MyStruct s1;
static __thread int safe;
```

+   更广泛地说，`__thread`关键字可以针对任何全局和文件或函数作用域的`static`或`extern`变量进行指定。它不能应用于任何局部变量。

+   TLS 只能在（相当）新版本的工具链和内核上使用。

重要的是要理解：尽管它可能看起来类似于有锁的变量，但实际上并非如此！考虑这一点：给定一个名为`mytls`的 TLS 变量，不同的线程并行使用它是可以的。但是，如果一个线程对 TLS 变量使用地址运算符`&mytls`，它将具有该变量的实例的地址。任何其他线程，如果访问此地址，都可以使用此地址来访问该变量；因此，从实质上讲，它并没有真正被锁定。当然，如果程序员使用正常的约定（不让其他线程访问不同线程的 TLS 变量），那么一切都会很顺利。

重要的是要意识到 TLS 支持仅在 Linux 2.6 内核及更高版本、gcc ver 3.3 或更高版本和 NPTL 中可用。实际上，这意味着几乎任何相当新的 Linux 发行版都将支持 TLS。

因此，像往常一样，让我们通过 TLS 将我们的线程不安全的函数移植为线程安全。这真的很简单；我们所要做的就是将以前的全局缓冲区`gbuf`变成线程安全的 TLS 缓冲区（`iobuf`）：

```
static __thread char iobuf[NREAD];     // our TLS variable

static void testit_mt_tls(FILE * wrstrm, FILE * rdstrm, int numio, int thrdnum)
{
  int i, syscalls = NREAD*numio/getpagesize();
  size_t fnr=0;

  if (syscalls <= 0)
    syscalls = 1;
  VPRINT("[Thread #%d]: numio=%d total rdwr=%u expected # rw 
          syscalls=%d\n"
         " iobuf = %p\n", thrdnum, numio, NREAD*numio, syscalls, iobuf);
...
```

唯一重要的变化是现在将`iobuf`变量声明为 TLS 变量；其他几乎都保持不变。快速测试确认每个线程都会收到 TLS 变量的单独副本：

```
$ ./mt_iobuf_tls 12500
./mt_iobuf_tls: using default stdio IO RW buffers of size 4096 bytes; # IOs=12500
mt_iobuf_tls.c:testit_mt_tls:48: [Thread #0]: numio=12500 total rdwr=6400000 expected # rw syscalls=1562
 iobuf = 0x7f23df1af500
mt_iobuf_tls.c:testit_mt_tls:48: [Thread #1]: numio=12500 total rdwr=6400000 expected # rw syscalls=1562
 iobuf = 0x7f23de9ae500
 Thread #0 successfully joined; it terminated with status=0
 Thread #1 successfully joined; it terminated with status=0
$ 
```

每个`iobuf`都是一个每个线程的 TLS 实例；每个都有一个唯一的地址。没有锁定，没有麻烦，工作完成。TLS 的实际使用很高；未初始化的全局`errno`是一个完美的例子。

TLS 似乎是一种强大且易于使用的技术，可以使函数线程安全；有什么缺点吗？嗯，想想看：

+   对于每个标记为 TLS 存储类的变量，将必须为每个活动的线程分配内存；如果我们有大型 TLS 缓冲区，这可能导致分配大量内存。

+   平台支持：如果您的 Linux 平台太旧，将不支持它（通常不应该是这种情况）。

# 通过 TSD 实现线程安全

在我们刚刚看到的 TLS 技术之前（也就是在 Linux 2.6 和 gcc 3.3 之前），如何保证编写的新 API 是线程安全的？还存在一种更古老的技术，称为 TSD。

总之，从应用程序开发人员的角度来看，TSD 是一个更复杂的解决方案——需要做更多的工作才能实现 TLS 轻松给我们的相同结果；使函数线程安全。

使用 TSD，线程安全的例程必须调用一个初始化函数（通常使用 `pthread_once(3)` 完成），该函数创建一个唯一的线程特定数据键（使用 `pthread_key_create(3)` API）。这个初始化例程使用 `pthread_getspecific(3)` 和 `pthread_setspecific(3)` API 将一个线程特定的数据变量（例如我们例子中的 `iobuf` 缓冲指针）与该键关联起来。最终的结果是数据项现在是线程特定的，因此是线程安全的。在这里，我们不深入讨论使用 TSD，因为它是一个旧的解决方案，在现代 Linux 平台上 TLS 轻松而优雅地取代了它。然而，对于感兴趣的读者，请参考 GitHub 仓库上的 *进一步阅读* 部分——我们提供了一个使用 TSD 的链接。

# 线程取消和清理

pthread 的设计提供了一个复杂的框架，用于实现多线程应用程序的另外两个关键活动：使应用程序中的一个线程取消（实际上是终止）另一个线程，以及使一个线程能够正常终止（通过 `pthread_exit(3)`）或异常终止（通过取消）并能够执行所需的资源清理。

以下部分涉及这些主题。

# 取消线程

想象一个运行的 GUI 应用程序；它弹出一个对话框，通知用户它现在正在执行一些工作（也许还显示一个进度条）。我们想象这项工作是由整个应用程序进程的一个线程执行的。为了用户的方便，还提供了一个取消按钮；点击它应该导致正在进行的工作被取消。

我们如何实现这个？换句话说，如何终止一个线程？首先要注意的是，pthreads 提供了一个框架，用于正是这种类型的操作：线程取消。取消线程不是发送信号；它是一种让一个线程请求另一个线程死掉的方式。要实现这一点，我们需要理解并遵循提供的框架。

# 线程取消框架

为了带来清晰，让我们举个例子：假设一个应用程序的主线程创建了两个工作线程 A 和 B。现在，主线程想要取消线程 A。

请求取消目标线程（这里是 A）的 API 如下：

`int pthread_cancel(pthread_t thread);`

`thread` 参数是目标线程——我们（礼貌地）请求它请去死，非常感谢。

但是，你猜对了，事情并不像那么简单：目标线程有两个属性（它可以设置），决定它是否以及何时被取消：

+   取消能力状态

+   取消能力类型

# 取消能力状态

目标线程需要处于适当的取消能力状态。该状态是布尔型取消能力（在目标线程 A 上）要么是 *启用* 要么是 *禁用*；以下是设置这一点的 API：

`int pthread_setcancelstate(int state, int *oldstate);`

线程的两种可能的取消能力状态，作为第一个参数提供的值，如下所示：

+   `PTHREAD_CANCEL_ENABLE`（默认创建时）

+   `PTHREAD_CANCEL_DISABLE`

显然，前一个取消能力状态将在第二个参数 `oldstate` 中返回。只有当目标线程的取消能力状态为启用时，才能取消线程。线程的取消能力状态在创建时默认为启用。

这是框架的一个强大特性：如果目标线程 A 正在执行关键活动，并且不希望被考虑取消，它只需将其取消能力状态设置为禁用，并在完成所述的关键活动后将其重置为启用。

# 取消能力类型

假设目标线程已启用取消状态是第一步；线程的可取消类型决定接下来会发生什么。有两种类型：延迟（默认）和异步。当线程的可取消类型是异步时，它可以在任何时候被取消（实际上，它应该立即发生，但并不总是保证）；如果可取消类型是延迟（默认），它只能在下一个取消点时被取消（终止）。

取消点是一个（通常是阻塞的）函数列表（稍后会详细介绍）。当目标线程——记住，它是启用取消状态和延迟类型的——在其代码路径中遇到下一个取消点时，它将终止。

这是设置可取消类型的 API：

`int pthread_setcanceltype(int type, int *oldtype);`

作为第一个参数类型提供的两种可能的可取消类型值是：

+   `PTHREAD_CANCEL_DEFERRED`（默认创建时）

+   `PTHREAD_CANCEL_ASYNCHRONOUS`

显然，以前的可取消类型将在第二个参数`oldtype`中返回。

呼！让我们尝试将这个取消框架表示为一个流程图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/39252ce8-4494-4e42-a3b2-73a52e05d354.png)

图 2：Pthreads 取消

`pthread_cancel(3)`是一个非阻塞的 API。我们的意思是，即使目标线程已禁用其可取消状态，或者其可取消状态已启用但可取消类型是延迟的，并且尚未达到取消点，尽管目标线程可能需要一些时间才能真正死去，主线程的`pthread_cancel(3)`调用将成功返回（返回值为`0`），这意味着取消请求已成功排队。

在进行关键活动时短暂禁用取消状态是可以的，但是长时间禁用可能会导致应用程序看起来无响应。

通常不应该使用异步值作为可取消类型。为什么？嗯，这变成了一个竞赛，究竟是在线程分配一些资源（例如通过`malloc(3)`分配内存）之前取消，还是之后取消？在这种情况下，即使清理处理程序也不是真正有用。此外，只有被记录为“异步取消安全”的 API 才能安全地以异步方式取消；实际上只有很少的 API——只有取消 API 本身。因此，最好避免异步取消。另一方面，如果一个线程主要是高度 CPU 绑定的（执行一些数学计算，比如素数生成），那么使用异步取消可以帮助确保线程立即在请求时死亡。

另一个关键点：（在我们的例子中）主线程如何知道目标线程是否已经终止？请记住，主线程预期会加入所有线程；因此，目标线程在终止时将被加入，并且这里的关键是`pthread_join(3)`的返回值（状态）将是`PTHREAD_CANCELED`。`pthread_join(3)`是检查取消是否实际发生的唯一方法。

我们已经了解到，默认的取消类型为延迟时，实际的线程取消将不会发生，直到目标线程遇到取消点函数。取消点只是一个 API，在该 API 中，线程取消实际上被检测并由底层实现生效。取消点不仅限于 pthread API；许多 glibc 函数都充当取消点。读者可以通过在 GitHub 存储库的*进一步阅读*部分提供的链接（Open Group POSIX.1c 线程）找到取消点 API 的列表。作为一个经验法则，取消点通常是阻塞库 API。

但是，如果一个线程正在执行的代码中根本没有取消点（比如说，是一个 CPU 密集型的计算循环）怎么办？在这种情况下，可以使用异步取消类型，或者更好的是，通过调用`void pthread_test_cancel(void);`API 在循环中显式引入一个保证的取消点。

如果将要取消的目标线程调用此函数，并且有一个取消请求挂起，它将终止。

# 取消线程-一个代码示例

以下是一个简单的代码示例，演示了线程取消；我们让`main`线程创建两个工作线程（将它们视为线程 A 和线程 B），然后让`main`线程取消线程 A。同时，我们故意让线程 A 禁用取消（通过将取消状态设置为禁用），做一些虚假的工作（我们调用我们信任的`DELAY_LOOP`宏来模拟工作），然后重新启用取消。取消请求在下一个取消点生效（因为`type`默认为延迟），这里，就是`sleep(3)`API。

演示线程取消的代码（`ch16/cancelit.c`）如下。

为了可读性，这里只显示了源代码的关键部分。要查看完整的源代码，请构建并运行它。整个树可在 GitHub 上克隆：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

我们在线程创建循环完成后在`main`中接着执行代码：

```
int main(void)
{
...  
  // Lets send a cancel request to thread A (the first worker thread)
  ret = pthread_cancel(tid[0]);
  if (ret)
      FATAL("pthread_cancel(thread 0) failed! [%d]\n", ret);

  // Thread join loop
  for (i = 0; i < NTHREADS; i++) {
      printf("main: joining (waiting) upon thread #%ld ...\n", i);
      ret = pthread_join(tid[i], (void **)&stat);
      ...
          printf("Thread #%ld successfully joined; it terminated with"
                 "status=%ld\n", i, stat);
          if ((void *)stat == PTHREAD_CANCELED)
              printf(" *** Was CANCELLED ***\n");
      }
  }
```

这是线程`worker`例程：

```
void * worker(void *data)
{
  long datum = (long)data;
  int slptm=8, ret=0;

  if (datum == 0) { /* "Thread A"; lets keep it in a 'critical' state,
           non-cancellable, for a short while, then enable
           cancellation upon it. */
      printf(" worker #%ld: disabling Cancellation:"
      " will 'work' now...\n", datum);
      if ((ret = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)))
          FATAL("pthread_setcancelstate failed 0 [%d]\n", ret);
      DELAY_LOOP(datum+48, 100);   // the 'work'
      printf("\n worker #%ld: enabling Cancellation\n", datum);
      if ((ret = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)))
          FATAL("pthread_setcancelstate failed 1 [%d]\n", ret);
  }

  printf(" worker #%ld: will sleep for %ds now ...\n", datum, slptm);
 sleep(slptm); // sleep() is a 'cancellation point'
  printf(" worker #%ld: work (eyeroll) done, exiting now\n", datum);

  /* Terminate with success: status value 0.
   * The join will pick this up. */
  pthread_exit((void *)0);
}
```

快速测试运行显示它确实有效；可以看到线程 A 已被取消。我们建议您运行程序的调试版本，因为这样可以看到`DELAY_LOOP`宏的效果（否则它几乎会被编译器优化掉，几乎瞬间完成其工作）：

```
$ ./cancelit_dbg 
main: creating thread #0 ...
main: creating thread #1 ...
 worker #0: disabling Cancellation: will 'work' now...
0 worker #1: will sleep for 8s now ...
main: joining (waiting) upon thread #0 ...
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
 worker #0: enabling Cancellation
 worker #0: will sleep for 8s now ...
Thread #0 successfully joined; it terminated with status=-1
 *** Was CANCELLED ***
main: joining (waiting) upon thread #1 ...
 worker #1: work (eyeroll) done, exiting now
Thread #1 successfully joined; it terminated with status=0

main: now dying... <Dramatic!> Farewell!
$ 
```

# 在线程退出时进行清理

考虑这种假设情况：一个线程获取互斥锁并分配了一些堆内存。显然，一旦它所在的临界区完成，我们期望它释放堆内存并解锁互斥锁。未进行这种清理将导致严重的，甚至是致命的应用程序错误（缺陷），如内存泄漏或死锁。

但是，有人会想，如果可怜的线程在释放和解锁之前被取消了怎么办？这可能发生，对吧？不！只要开发人员理解并使用 pthreads 框架提供的线程清理处理程序机制就不会发生。

当线程终止时会发生什么？以下步骤是 pthreads 清理框架的一部分：

1.  所有清理处理程序都被弹出（清理处理程序推送的相反顺序）

1.  如果存在 TSD 析构函数，则会被调用

1.  线程死亡

这让我们看到了一个有趣的事实：pthreads 框架提供了一种保证线程在终止之前清理自己的方法-释放内存资源，关闭打开的文件等。

程序员可以通过设置线程清理处理程序来处理所有这些情况-实际上是一种析构函数。清理处理程序是一个在线程被取消或使用`pthread_exit(3)`终止时自动执行的函数；通过调用`pthread_cleanup_push(3)`API 来设置它：

```
void pthread_cleanup_push(void (*routine)(void *), void *arg);
```

显然，前面例程的第一个参数是清理处理程序函数指针，换句话说，是清理处理程序函数的名称。第二个参数是任何一个想要传递给处理程序的参数（通常是指向动态分配的缓冲区或数据结构的指针）。

通过相应的清理弹出例程可以实现相反的语义；当调用时，它会弹出清理处理程序堆栈，并以相反的顺序执行先前推送到清理处理程序堆栈上的清理处理程序：

`void pthread_cleanup_pop(int execute);`

还可以通过调用`thread_cleanup_pop(3)`API 并传递一个非零参数来显式调用清理堆栈上面的清理处理程序。

POSIX 标准规定，前面一对 API——推送和弹出清理处理程序——可以实现为扩展为函数的宏；事实上，在 Linux 平台上似乎是这样实现的。作为这一副作用，程序员必须在同一个函数内调用这两个例程（一对）。不遵守这一规定会导致奇怪的编译器失败。

正如所指出的，如果存在 TSD 析构处理程序，它们也会被调用；在这里，我们忽略了这一方面。

你可能会想，好吧，如果我们使用这些清理处理程序技术，我们可以安全地恢复状态，因为线程取消和终止都将保证调用任何注册的清理处理程序（析构函数）。但是，如果另一个进程（也许是一个 root 进程）向我的 MT 应用程序发送了一个致命信号（比如`kill -9 <mypid>`）呢？那么就没什么可做的了。请意识到，对于致命信号，进程中的所有线程，甚至整个进程本身，都将死亡（在这个例子中）。这是一个学术问题——一个无关紧要的问题。另一方面，一个线程不能随意被杀死；必须对其进行显式的`pthread_exit(3)`或取消操作。因此，懒惰的程序员没有借口——设置清理处理程序来执行适当的清理，一切都会好起来。

# 线程清理-代码示例

作为一个简单的代码示例，让我们修改我们之前重构的程序——`ch16/mt_iobif_rfct.c`，通过安装一个线程清理处理程序例程。为了测试它，如果用户将`1`作为第二个参数传递给我们的演示程序`ch16/cleanup_hdlr.c`，我们将取消第一个工作线程。

为了便于阅读，这里只显示了源代码的关键部分。要查看完整的源代码，请构建并运行它。整个树可在 GitHub 上克隆：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

这是清理处理程序函数和重新编写的包装程序——现在带有清理处理程序推送和弹出 API：

```
static void cleanup_handler(void *arg)
{
    printf("+++ In %s +++\n" " free-ing buffer %p\n", __func__, arg);
 free(arg);
}
...
static void *wrapper_testit_mt_refactored(void *msg)
{
  struct stToThread *pstToThread = (struct stToThread *)msg;
  ...
  /* Allocate the per-thread IO buffer here, thus avoiding the global
   * heap buffer completely! */
 pstToThread->iobuf = malloc(NREAD);
  ...
 /* Install a 'cleanup handler' routine */
 pthread_cleanup_push(cleanup_handler, pstToThread->iobuf);

  testit_mt_refactored(pstToThread->wrstrm, pstToThread->rdstrm,
           pstToThread->numio, pstToThread->thrdnum,
           pstToThread->iobuf);

/* *Must* invoke the 'push's counterpart: the cleanup 'pop' routine;
 * passing 0 as parameter just registers it, it does not actually pop
 * off and execute the handler. Why not? Because that's precisely what
 * the next API, the pthread_exit(3) will implicitly do!
 */
 pthread_cleanup_pop(0);
  free(pstToThread->iobuf);

 // Required for pop-ping the cleanup handler!
 pthread_exit((void *)0);
}
```

在这里，`main()`设置了所需的线程取消：

```
...
  if (atoi(argv[2]) == 1) {
    /* Lets send a cancel request to thread A */
    ret = pthread_cancel(tid[0]);
  ...
```

快速测试确认，在取消时，清理处理程序确实被调用并执行了清理：

```
$ ./cleanup_hdlr 23114 1
./cleanup_hdlr: using default stdio IO RW buffers of size 4096 bytes; # IOs=23114
main: sending CANCEL REQUEST to worker thread 0 ...
cleanup_hdlr.c:testit_mt_refactored:52: [Thread #0]: numio=23114 total rdwr=11834368 expected # rw syscalls=2889
 iobuf = 0x7f2364000b20
cleanup_hdlr.c:testit_mt_refactored:52: [Thread #1]: numio=23114 total rdwr=11834368 expected # rw syscalls=2889
 iobuf = 0x7f235c000b20
+++ In cleanup_handler +++
 free-ing buffer 0x7f2364000b20
 Thread #0 successfully joined; it terminated with status=-1
 : was CANCELED
 Thread #1 successfully joined; it terminated with status=0
$ 
```

# 线程和信号

在第十一章中，*信号-第 I 部分*，和第十二章中，*信号-第 II 部分*，我们详细介绍了信号。我们仍然在同一个 Unix/Linux 平台上；信号及其在应用程序设计/开发中的使用并没有因为我们现在正在处理 MT 应用程序而消失！我们仍然必须处理信号（请记住，你可以在 shell 上用简单的`kill -l`列出你平台上可用的信号）。

# 问题

那么问题是什么？在 MT 应用程序中，我们处理信号的方式有很大的不同。为什么？事实是，传统的信号处理方式与 pthread 框架并不真正兼容。如果你可以避免在 MT 应用程序中使用信号，请尽量这样做。如果不行（在现实世界的 MT 应用程序中通常是这样），那么请继续阅读——我们将详细介绍在 MT 应用程序中处理信号的方法。

但是为什么现在发出信号成了一个问题？很简单：信号是为进程模型设计和用于的。想想看：一个进程如何向另一个进程发送信号？很明显——使用`kill(2)`系统调用：

`int kill(pid_t pid, int sig);`

显然，第一个参数 pid 是要将信号`sig`（数字）传递给的进程的 PID。但是，这里我们看到，一个进程可以是多线程的——哪个特定线程会接收，哪个特定线程会处理这个信号？POSIX 标准懦弱地声明“任何准备好的线程都可以处理给定的信号”。如果所有线程都准备好了怎么办？那么谁来处理？所有的线程？至少可以说是模棱两可的。

# POSIX 处理 MT 上的信号的解决方案

好消息是，POSIX 委员会为 MT 应用程序的开发人员提出了信号处理的建议。这个解决方案基于一个有趣的设计事实；虽然进程有一个由内核和`sigaction(2)`系统调用设置的信号处理表，但进程内的每个线程都有自己独立的信号掩码（使用它可以选择性地阻塞信号）和信号挂起掩码（内核记住了要传递给线程的挂起信号）。

知道这一点，POSIX 标准建议开发人员在 pthreads 应用程序中处理信号如下：

+   在主线程中屏蔽（阻塞）所有信号。

+   现在，主线程创建的任何线程都会继承其信号掩码，这意味着所有随后创建的线程中的信号都将被阻塞——这正是我们想要的。

+   创建一个专门的线程，专门用于执行整个应用程序的信号处理。它的工作是捕获（陷阱）所有必需的信号并处理它们（以同步方式）。

请注意，虽然可以通过`sigaction(2)`系统调用捕获信号，但在多线程应用程序中，信号处理的语义通常导致使用信号 API 的阻塞变体——`sigwait(3)`、`sigwaitinfo(3)`和`sigtimedwait(3)`库 API。通常最好在专用的信号处理程序线程中使用这些阻塞 API 来阻塞所有所需的信号。

因此，每当信号到达时，信号处理程序线程将被解除阻塞，并接收到信号；此外（假设我们使用`sigwait(3)` API），信号编号将更新到`sigwait(3)`的第二个参数中。现在它可以代表应用程序执行所需的信号处理。

# 代码示例-在 MT 应用程序中处理信号

遵循 POSIX 推荐的处理 MT 应用程序中信号的技术的快速演示如下（`ch16/tsig.c`）：

为了便于阅读，这里只显示了源代码的关键部分。要查看完整的源代码，请构建并运行它。整个树都可以从 GitHub 克隆：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

```
// ... in main:
/* Block *all* signals here in the main thread.
 * Now all subsequently created threads also block all signals. */
  sigfillset(&sigset);
  if (pthread_sigmask(SIG_BLOCK, &sigset, NULL))
      FATAL("main: pthread_sigmask failed");
...
  /*--- Create the dedicated signal handling thread ---*/
  ret = pthread_create(&pthrd[t], &attr, signal_handler, NULL);
  if (ret)
      FATAL("pthread_create %ld failed [%d]\n", t, ret);
...
```

工作线程并没有做太多事情——它们只是调用我们的`DELAY_LOOP`宏来模拟一些工作。在这里，看看信号处理程序线程例程：

```
static void *signal_handler(void *arg)
{
  sigset_t sigset;
  int sig;

  printf("Dedicated signal_handler() thread alive..\n");
  while (1) {
      /* Wait for any/all signals */
      if (sigfillset(&sigset) == -1)
          FATAL("sigfillset failed");
      if (sigwait(&sigset, &sig) < 0)
          FATAL("sigwait failed");

  /* Note on sigwait():
   * sigwait suspends the calling thread until one of (any of) the  
   * signals in set is delivered to the calling thread. It then stores 
   * the number of the signal received in the location pointed to by 
   * "sig" and returns. The signals in set must be blocked and not 
   * ignored on entrance to sigwait. If the delivered signal has a 
   * signal handler function attached, that function is *not* called.
   */
 switch (sig) {
    case SIGINT:
        // Perform signal handling for SIGINT here
        printf("+++ signal_handler(): caught signal #%d +++\n", sig);
        break;
    case SIGQUIT:
        // Perform signal handling for SIGQUIT here
        printf("+++ signal_handler(): caught signal #%d +++\n", sig);
        break;
    case SIGIO:
        // Perform signal handling for SIGIO here
        printf("+++ signal_handler(): caught signal #%d +++\n", sig);
        break;
    default:
        // Signal <whichever> caught
        printf("*** signal_handler(): caught signal #%2d [unhandled] ***\n", sig);
        break;
    }
  }
  return (void *)0;
}
```

我们将其留给读者快速尝试，并注意输出。顺便问一下，你最终会如何杀死它？只需打开另一个终端窗口，然后从那里发出`kill -9 <PID>`。

为了方便读者，我们重复了第十二章中最重要的提示，*信号-第二部分*。

一个重要的要点是：`sigwait(3)`、`sigwaitinfo(2)`和`sigtimedwait(2)` API 都不能等待来自内核的同步生成的信号——通常是指示某种失败的信号，比如`SIGFPE`和`SIGSEGV`。这些只能以正常的异步方式捕获——通过`signal(2)`或`sigaction(2)`。对于这种情况，正如我们反复展示的那样，`sigaction(2)`系统调用将是更好的选择。

此外，在 MT 应用程序中屏蔽信号时，不要使用`sigprocmask(2)` API——它不是线程安全的。而是使用`pthread_sigmask(3)`库例程。

请注意，以下 API 可用于向进程内的线程发送信号：

+   `pthread_kill(3)`：向同一进程内的特定线程发送信号的 API

+   `tgkill(2)`：向给定线程组内的特定线程发送信号的 API。

+   `tkill(2)`：`tgkill`的已弃用前身。

查阅它们各自的手册页面上的详细信息。话虽如此，最好通过 pthread 取消框架来终止线程，而不是通过发送信号。 

# 线程与进程-再次查看

从这个三部曲的开始（第十四章，*使用 Pthreads 进行多线程编程第一部分-基础*，第十五章，*使用 Pthreads 进行多线程编程第二部分-同步*，和第十六章，*使用 Pthreads 进行多线程编程第三部分*），关于多线程编程，关于多进程（单线程）与多线程的争论，我们一再说过，并不是完全优势或劣势——总是有一些优点和缺点，是一种权衡。

*表 4*和*表 5*描述了多进程（多个单线程进程）与多线程（单个进程内的多个线程）方法的一些优缺点。

# 多进程与多线程模型- MT 模型的优点

MT 模型相对于单线程进程的一些优点如下：

| **上下文** | **多进程（单线程）模型** | **多线程（MT）模型** |
| --- | --- | --- |
| 为并行化工作负载设计 |

+   繁琐

+   不直观

+   重复使用 fork/wait 语义（创建大量进程）也不简单或直观

|

+   适用于构建并行化软件；在循环中调用`pthread_create(3)`也很容易和直观

+   实现任务的逻辑分离变得容易

+   操作系统将隐式地使线程利用多核系统；对于 Linux 操作系统，调度的粒度是线程，而不是进程（关于这一点，下一章会详细介绍）*

+   重叠 CPU 与 IO 变得容易

|

| 创建/销毁性能 | 比较慢 | 比进程快得多；资源共享保证了这一点 |
| --- | --- | --- |
| 上下文切换 | 慢 | 在进程的线程之间快得多 |
| 数据共享 | 通过 IPC（进程间通信）机制完成；需要学习曲线，可能相当复杂；需要同步（通过信号量） | 内在；给定进程的所有全局和静态数据项在线程之间隐式共享；需要同步（通过互斥锁） |

表 4：多进程与多线程模型- MT 模型的优点

# 多进程与多线程模型- MT 模型的缺点

MT 模型相对于单线程进程的一些缺点

| **上下文** | **多进程（单线程）模型** | **多线程（MT）模型** |
| --- | --- | --- |
| 线程安全 | 没有这样的要求；进程始终具有地址空间分离。 | 最严重的缺点：MT 应用程序中可以由线程并行运行的每个函数都必须编写、验证和记录为线程安全。这包括应用程序代码和项目库，以及其链接到的任何第三方库。 |
| 应用程序完整性 | 在大型 MT 应用程序中，如果任何一个线程遇到致命错误（如段错误），整个应用程序现在都有 bug 并且必须关闭。 | 在多进程应用程序中，只有遇到致命错误的进程必须关闭；项目的其余部分继续运行[1]。 |
| 地址空间限制 | 在 32 位 CPU 上，用户模式应用程序可用的虚拟地址空间（VAS）相当小（2GB 或 3GB），但对于典型的单线程应用程序来说仍然足够大；在 64 位 CPU 上，VAS 是巨大的（2⁶⁴ = 16 EB）。 | 在 32 位系统上（许多嵌入式 Linux 产品仍然常见），用户模式的可用 VAS 将很小（2/3GB）。考虑到具有许多线程的复杂 MT 应用程序，这并不多！事实上，这是嵌入式供应商积极将产品迁移到 64 位系统的原因之一。 |

| Unix 的一切都是文件语义 | 语义成立：文件（描述符）、设备、套接字、终端等都可以被视为文件；此外，每个进程都有自己的资源副本。| 资源共享，被视为优势，也可以被视为劣势：

+   共享可能会破坏传统的 Unix 模型优势

+   共享打开文件、内存区域、IPC 对象、分页表、资源限制等会导致访问时的同步开销

|

| 信号处理 | 针对进程模型设计。 | 不适用于 MT 模型；可以做到，但处理信号有点笨拙。 |
| --- | --- | --- |
| 设计、维护和调试 | 与 MT 模型相比相当直接。 | 增加了复杂性，因为程序员必须同时跟踪（在脑海中）多个线程的状态，包括众所周知的复杂锁定场景。调试死锁（和其他）情况可能会非常困难（诸如 GDB 和 helgrind 之类的工具有所帮助，但人仍然需要跟踪事物）。 |

表 5：多进程与多线程模型的比较 - MT 模型的缺点

[1] Google Chrome 开源项目的架构基于多进程模型；请参阅他们关于此的漫画改编：[`www.google.com/googlebooks/chrome/med_00.html`](http://www.google.com/googlebooks/chrome/med_00.html)。从软件设计的角度来看，该网站非常有趣。

# Pthreads - 一些随机提示和常见问题

为了结束本章，我们提供了关于多线程的常见问题的答案，以及如何使用 GDB 调试 MT 应用程序的简要说明。请继续阅读。

您的 MT 应用程序中可以由线程并行运行的每个函数都必须编写、验证和记录为线程安全。这包括您的 MT 应用程序代码、项目库以及您链接到的任何第三方库。

# Pthreads - 一些常见问题

+   问：在多线程进程中，当一个线程调用`exec*()`例程之一时会发生什么？

答：调用应用程序（前任）完全被后续进程替换，后续进程将只是调用 exec 的线程。请注意，不会调用 TSD 析构函数或线程清理处理程序。

+   问：在多线程进程中，当一个线程调用`fork(2)`时会发生什么？

答：这取决于操作系统。在现代 Linux 上，只有调用`fork(2)`的线程会在新的子进程中复制。所有在 fork 之前存在的其他线程都消失了。不会调用 TSD 析构函数或线程清理处理程序。在多线程应用程序中调用 fork 可能会导致困难；不建议这样做。在 GitHub 存储库的*进一步阅读*部分中找到有关这个问题的链接。

这样想：在 MT 应用程序中调用`fork`进行多进程处理被认为是错误的方法；仅为执行另一个程序而调用 fork 是可以的（通过我们学到的典型的 fork-exec-wait 语义）。换句话说，新生的子进程应该只调用被记录为异步信号安全和/或 exec*例程的函数来调用另一个应用程序。

此外，您可以设置处理程序，以在通过`pthread_atfork(3)`API 调用 fork 时运行。

+   问：多线程应用程序中资源限制（参见 ulimit/prlimit）的影响是什么？

答：所有资源限制 - 当然不包括堆栈大小限制 - 都由进程中的所有线程共享。在旧版 Linux 内核上，情况并非如此。

# 使用 GDB 调试多线程（pthread）应用程序

GDB 支持调试 MT 应用程序；几乎所有常用命令都可以正常工作，只有少数命令倾向于特定于线程。以下是需要注意的关键命令：

+   查看所有可见线程：

```
(gdb) info threads
 Id     Target  Id              Frame
<thr#>  Thread  <addr> (LWP ...) in <function> [at <srcfile>]
```

+   通过使用`thread <thread#>`命令切换上下文到特定线程*。*

+   将给定命令应用于进程的所有线程：`(gdb) thread apply all <cmd>`

+   显示所有线程的堆栈（GDB 的回溯或`bt`命令）（以下示例输出来自我们之前的 MT 应用程序`mt_iobuf_rfct_dbg`；首先，我们通过`thread find .`命令显示线程）：

```
(gdb) thread find . Thread 1 has target name 'tsig_dbg'
Thread 1 has target id 'Thread 0x7ffff7fc9740 (LWP 24943)'
Thread 2 has target name 'tsig_dbg'
Thread 2 has target id 'Thread 0x7ffff77f7700 (LWP 25010)'
Thread 3 has target name 'tsig_dbg'
Thread 3 has target id 'Thread 0x7ffff6ff6700 (LWP 25194)' (gdb) thread apply all bt

Thread 3 (Thread 0x7fffeffff700 (LWP 21236)):
#0 testit_mt_refactored (wrstrm=0x603670, rdstrm=0x6038a0, numio=10, thrdnum=1, iobuf=0x7fffe8000b20 "")
    at mt_iobuf_rfct.c:44
#1 0x00000000004010e9 in wrapper_testit_mt_refactored (msg=0x603c20) at mt_iobuf_rfct.c:88
#2 0x00007ffff7bbe594 in start_thread () from /lib64/libpthread.so.0
#3 0x00007ffff78f1e6f in clone () from /lib64/libc.so.6

Thread 2 (Thread 0x7ffff77f7700 (LWP 21235)):
#0 testit_mt_refactored (wrstrm=0x603670, rdstrm=0x6038a0, numio=10, thrdnum=0, iobuf=0x7ffff0000b20 "")
    at mt_iobuf_rfct.c:44
#1 0x00000000004010e9 in wrapper_testit_mt_refactored (msg=0x603ad0) at mt_iobuf_rfct.c:88
#2 0x00007ffff7bbe594 in start_thread () from /lib64/libpthread.so.0
#3 0x00007ffff78f1e6f in clone () from /lib64/libc.so.6

Thread 1 (Thread 0x7ffff7fc9740 (LWP 21203)):
#0 0x00007ffff7bbfa2d in __pthread_timedjoin_ex () from /lib64/libpthread.so.0
#1 0x00000000004013ec in main (argc=2, argv=0x7fffffffcd88) at mt_iobuf_rfct.c:150
(gdb) 
```

关于使用 pthread 进行 MT 编程的一些其他提示和技巧（包括我们已经遇到的几个），在 GitHub 存储库的*进一步阅读*部分中提到的博客文章中（Pthreads Dev - 避免的常见编程错误）；请务必查看。

# 总结

在本章中，我们涵盖了使用强大的 pthreads 框架处理线程时的几个安全方面。我们看了线程安全的 API，它们是什么，为什么需要，以及如何使线程例程线程安全。我们还学习了如何让一个线程取消（有效地终止）给定的线程，以及如何让受害线程处理任何必要的清理工作。

本章的其余部分侧重于如何安全地混合线程与信号接口；我们还比较和对比了典型的多进程单线程与多线程（一个进程）方法的利弊（确实是一些值得思考的东西）。提示和常见问题解答结束了这一系列章节（第十四章，*使用 Pthreads 进行多线程编程第一部分-基础知识* 和本章）。

在下一章中，读者将通过详细了解 Linux 平台上的 CPU 调度，以及非常有趣的是，应用程序开发人员如何利用 CPU 调度（使用多线程应用程序演示）。


# 第十七章：Linux 上的 CPU 调度

人们经常问关于 Linux 的一个问题是，调度是如何工作的？我们将在本章中详细解答这个问题，以便用户空间应用程序开发人员清楚地掌握有关 Linux 上 CPU 调度的重要概念，以及如何在应用程序中强大地使用这些概念，我们还将涵盖必要的背景信息（进程状态机，实时等）。本章将以简要说明 Linux 操作系统如何甚至可以用作硬实时操作系统而结束。

在本章中，读者将了解以下主题：

+   Linux 进程（或线程）状态机，以及 Linux 在幕后实现的 POSIX 调度策略

+   相关概念，如实时和 CPU 亲和力

+   如何利用这一事实，即在每个线程基础上，您可以使用给定的调度策略和实时优先级来编程线程（将显示一个示例应用程序）

+   关于 Linux 也可以用作 RTOS 的简要说明

# Linux 操作系统和 POSIX 调度模型

为了理解应用程序开发人员的调度（以及如何在实际代码中利用这些知识），我们首先必须涵盖一些必需的背景信息。

开发人员必须理解的第一个非常重要的概念是，操作系统维护一种称为**内核可调度实体**（**KSE**）的构造。*KSE 是操作系统调度代码操作的粒度。实际上，操作系统调度的是什么对象？是应用程序、进程还是线程？嗯，简短的答案是 Linux 操作系统上的 KSE 是一个线程。换句话说，所有可运行的线程都竞争 CPU 资源；内核调度程序最终是决定哪个线程在哪个 CPU 核心上运行以及何时运行的仲裁者。

接下来，我们将概述进程或线程的状态机。

# Linux 进程状态机

在 Linux 操作系统上，每个进程或线程都会经历各种明确定义的状态，并通过对这些状态进行编码，我们可以形成 Linux 操作系统上进程（或线程）的状态机（在阅读本文时，请参考下一节中的*图 1*）。

既然我们现在了解了 Linux 操作系统上的 KSE 是一个线程而不是一个进程，我们将忽略使用单词*进程*的传统，而在描述通过各种状态的实体时使用单词*线程*。（如果更舒适的话，您可以在脑海中用*线程*替换*进程*。）

Linux 线程可以循环经历的状态如下（`ps(1)`实用程序通过此处显示的字母对*状态*进行编码）：

+   **R**：准备运行或正在运行

+   睡眠：

+   **S**：可中断睡眠

+   **D**：不可中断睡眠

+   **T**：停止（或暂停/冻结）

+   **Z**：僵尸（或无效）

+   **X**：死亡

当线程新创建（通过`fork(2)`，`pthread_create(3)`或`clone(2)`API）时，一旦操作系统确定线程完全创建，它通过将线程放入可运行状态来通知调度程序其存在。**R**状态的线程实际上正在 CPU 核心上运行，或者处于准备运行状态。我们需要理解的是，在这两种情况下，线程都被排队在操作系统内的一个称为**运行队列**（**RQ**）的数据结构上。运行队列中的线程是可以运行的有效候选者；除非线程被排队在操作系统运行队列上，否则不可能运行任何线程。 （供您参考，从 2.6 版开始，Linux 通过为每个 CPU 核心设置一个 RQ 来充分利用所有可能的 CPU 核心，从而获得完美的 SMP 可伸缩性。）Linux 不明确区分准备运行和运行状态；它只是将处于**R**状态的线程标记为准备运行或运行状态。

# 睡眠状态

一旦线程正在运行其代码，显然会一直这样做，直到通常发生以下几种情况：

+   它在 I/O 上阻塞，因此进入睡眠状态**S**或**D**，具体取决于（见下一段）。

+   它被抢占；没有状态改变，它仍然处于就绪运行状态**R**，在运行队列上。

+   它收到一个导致其停止的信号，因此进入状态**T**。

+   它收到一个信号（通常是 SIGSTOP 或 SIGTSTP），导致其终止，因此首先进入状态**Z**（僵尸状态是通向死亡的瞬态状态），然后实际死亡（状态 X）。

通常，线程在其代码路径中会遇到一个阻塞 API，这会导致它进入睡眠状态，等待事件。在被阻塞时，它会从原来的运行队列中移除（或出队），然后添加到所谓的**等待队列**（**WQ**）上。当它等待的事件发生时，操作系统会发出唤醒信号，导致它变为可运行状态（从等待队列中出队并加入运行队列）。请注意，线程不会立即运行；它将变为可运行状态（*图 1*中的**Rr**），成为调度程序的候选；很快，它将有机会在 CPU 上实际运行（**Rcpu**）。

一个常见的误解是认为操作系统维护一个运行队列和一个等待队列。不，Linux 内核为每个 CPU 维护一个运行队列。等待队列通常由设备驱动程序（以及内核）创建和使用；因此，可以有任意数量的等待队列。

睡眠的深度确定了线程被放入的确切状态。如果一个线程发出了一个阻塞调用，底层内核代码（或设备驱动程序代码）将其放入可中断睡眠状态，状态标记为**S**。可中断的睡眠状态意味着当发送给它的任何信号被传递时，线程将被唤醒；然后，它将运行信号处理程序代码，如果没有终止（或停止），将恢复睡眠（回想一下`sigaction(2)`中的`SA_RESTART`标志，来自第十一章*，信号-第一部分*）。这种可中断的睡眠状态**S**确实非常常见。

另一方面，操作系统（或驱动程序）可能会将阻塞线程放入更深的不可中断睡眠状态，此时状态标记为**D**。不可中断的睡眠状态意味着线程不会响应信号（没有；甚至没有来自 root 的 SIGKILL！）。当内核确定睡眠是关键的，并且线程必须等待挂起的事件时，会这样做（一个常见的例子是从文件中读取`read(2)`—当实际读取数据时，线程被放入不可中断的睡眠状态；另一个是挂载和卸载文件系统）。

性能问题通常是由非常高的 I/O 瓶颈引起的；高 CPU 使用率并不总是一个主要问题，但持续高的 I/O 会使系统感觉非常慢。确定哪个应用程序（实际上是进程和线程）导致了大量 I/O 的一个快速方法是过滤`ps(1)`输出，查找处于**D**状态的进程（或线程），即不可中断的睡眠状态。例如，参考以下内容：

**`$ ps -LA -o state,pid,cmd | grep`** `"^D"`

`**D** 10243 /usr/bin/gnome-shell`

`**D** 13337 [kworker/0:2+eve]`

`**D** 22545 /home/<user>/.dropbox-dist/dropbox-lnx.x86_64-58.4.92/dropbox`

`$`

请注意我们使用了`ps -LA`；`-L`开关显示所有活动的线程。 （FYI，前面方括号中显示的线程，`[kworker/...]`，是一个内核线程。）

以下图表示了任何进程或线程的 Linux 状态机：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/b25cef64-61ac-4c07-99f0-8cf2773c27cb.png)

图 1：Linux 状态机

前面的图表显示了状态之间的转换，通过红色箭头。请注意，为了清晰起见，一些转换（例如，线程在睡眠或停止时可能被终止）在前面的图表中没有明确显示。

# 什么是实时？

关于“实时”（在应用程序编程和操作系统上下文中）的含义存在许多误解。实时基本上意味着实时线程（或线程）不仅要正确执行其工作，而且它们必须在给定的最坏情况截止日期内执行。实际上，实时系统的关键因素称为确定性。确定性系统对真实世界（或人工生成的）事件有保证的最坏情况响应时间；它们将在有限的时间约束内处理这些事件。确定性导致可预测的响应，在任何条件下都是如此，甚至在极端负载下也是如此。计算机科学家对算法进行分类的一种方式是通过它们的时间复杂度：大 O 符号。O(1)算法是确定性的；它们保证无论输入负载如何，都将在一定的最坏情况时间内完成。真实的实时系统需要 O(1)算法来实现其性能敏感的代码路径。

有趣的是，实时并不一定意味着真正快速。 VDC 调查（有关更多详细信息，请参阅 GitHub 存储库上的“进一步阅读”部分）显示，大多数实时系统的截止日期（实时响应时间）要求为 1 至 9 毫秒。只要系统能够始终且无故障地在给定的截止日期内处理事件（可能相当长），它就是实时的。

# 实时类型

实时通常被分类为三种类型，如下：

+   **硬实时系统**被定义为必须始终满足所有截止日期的系统。甚至一次未能满足截止日期都会导致系统的灾难性失败，包括可能造成人员伤亡、财务损失等。硬实时系统需要一个**实时操作系统**（RTOS）来驱动它。（此外，应用程序编写成硬实时也非常重要！）。可能的硬实时领域包括各种人员运输工具（飞机、船舶、宇宙飞船、火车和电梯）以及某些类型的军用或国防设备、核反应堆、医疗电子设备和股票交易所。（是的，股票交易所确实是一个硬实时系统；请阅读书籍《自动化：算法如何统治我们的世界》—请参阅 GitHub 存储库上的“进一步阅读”部分获取更多信息。）

+   **软实时系统**都是尽最大努力；截止日期确实存在，但绝对不能保证会被满足。系统将尽最大努力满足它们；未能做到这一点被认为是可以接受的（通常只是对最终用户而言更多是一种烦恼而不是危险）。消费类电子产品（如我们的智能手机、MP3 播放器、相机、平板电脑和智能音箱）是典型的例子。在使用它们时，经常会发生听音乐时出现故障，或者流媒体视频出现卡顿、缓冲和抖动。虽然令人讨厌，但用户不太可能因此而丧生。

+   **中实时系统**介于硬实时和软实时系统之间——截止日期很重要，尽可能会被满足，但同样，无法做出铁 clad 保证。由于错过太多截止日期而导致性能下降是一个问题。

# 调度策略

**操作系统**（OS）的一个关键工作是调度可运行的任务。POSIX 标准规定 POSIX 兼容的操作系统必须提供（至少）三种调度策略。调度策略实际上是操作系统用于调度任务的调度算法。在本书中，我们不会深入探讨这些细节，但我们确实需要应用程序开发人员了解可用的调度策略。这些如下：

+   `SCHED_FIFO`

+   `SCHED_RR`

+   `SCHED_OTHER`（也称为`SCHED_NORMAL`）

我们的讨论自然而然地将仅涉及 Linux 操作系统。

首先要理解的第一件重要事情是，普通的 Linux 操作系统不是实时操作系统；它不支持硬实时，并且被分类为**通用目的操作系统**（**GPOS**），就像其他操作系统一样——Unix，Windows 和 macOS。

不过，请继续阅读；我们将看到，虽然普通的 Linux 不支持硬实时，但确实可以运行一个经过适当打补丁的 Linux 作为 RTOS。

尽管 Linux 是一个 GPOS，但它很容易表现为一个软实时系统。事实上，它的高性能特征使其接近成为一个坚实的实时系统。因此，Linux 操作系统在消费电子产品（和企业）产品中的主要使用并不奇怪。

接下来，我们提到的前两个调度策略——`SCHED_FIFO`和`SCHED_RR`——是 Linux 的软实时调度策略。`SCHED_OTHER`（也称为`SCHED_NORMAL`）策略是非实时调度策略，并且始终是默认的。`SCHED_OTHER`策略在现代 Linux 内核上实现为**完全公平调度器**（**CFS**）；其主要设计目标是提供整体高系统吞吐量和对每个可运行任务（线程）的公平性，确保线程不会饿死。这与实时策略算法的主要动机——线程的优先级相反。

对于`SCHED_FIFO`和`SCHED_RR`软实时策略，Linux 操作系统指定了一个优先级范围。这个范围是从 1 到 99，其中 1 是最低的实时优先级，99 是最高的。Linux 上的软实时调度策略设计遵循所谓的*固定优先级抢占调度*，这一点很重要。固定优先级意味着应用程序决定并固定线程优先级（并且可以更改它）；操作系统不会。抢占是操作系统从运行线程手中夺走 CPU 的行为，将其降回运行队列，并切换到另一个线程。关于调度策略的精确抢占语义将在接下来进行介绍。

现在，我们将简要描述在这些不同的调度策略下运行意味着什么。

运行中的`SCHED_FIFO`线程只能在以下三种情况下被抢占：

+   它（不）自愿地放弃处理器（从技术上讲，它从**R**状态移出）。当任务发出阻塞调用或调用`sched_yield(2)`等系统调用时会发生这种情况。

+   它停止或终止。

+   更高优先级的实时任务变为可运行状态。

这是需要理解的关键点：`SCHED_FIFO`任务是具有侵略性的；它以无限时间片运行，除非它被阻塞（或停止或终止），否则将继续在处理器上运行。然而，一旦更高优先级的线程变为可运行状态（状态**R**，进入运行队列），它将被优先于这个线程。

`SCHED_RR`的行为几乎与`SCHED_FIFO`相同，唯一的区别是：

+   它有一个有限的时间片，因此在时间片到期时可以被抢占的额外情况。

+   被抢占时，任务被移动到其优先级级别的运行队列尾部，确保所有相同优先级级别的`SCHED_RR`任务依次执行（因此它的名称为轮询）。

请注意，在 RTOS 上，调度算法是简单的，因为它实际上只需要实现这个语义：最高优先级的可运行线程必须是正在运行的线程。

所有线程默认情况下都在`SCHED_OTHER`（或`SCHED_NORMAL`）调度策略下运行。这是一个明显的非实时策略，重点是公平性和整体吞吐量。从 Linux 内核版本 2.6.0 到 2.6.22（包括）的实现是通过所谓的 O(1)调度程序；从 2.6.23 开始，进一步改进的算法称为**完全公平调度器**（**CFS**）实现了这种调度策略（实际上是一种调度类）。有关更多信息，请参考以下表格：

| **调度策略** | **类型** | **优先级范围** |
| --- | --- | --- |
| `SCHED_FIFO` | 软实时：激进，不公平 | 1 到 99 |
| `SCHED_RR` | 软实时：较不激进 | 1 到 99 |
| `SCHED_OTHER` | 非实时：公平，时间共享；默认值 | 优先级范围（-20 到+19） |

尽管不太常用，但我们指出 Linux 也支持使用 SCHED_BATCH 策略的批处理模式进程执行策略。此外，SCHED_IDLE 策略用于非常低优先级的后台任务。（实际上，CPU 空闲线程 - 名为`swapper`，PID 为`0`，每个 CPU 都存在，并且只有在绝对没有其他任务想要处理器时才运行）。

# 查看调度策略和优先级

Linux 提供了`chrt(1)`实用程序来查看和更改线程（或进程）的实时调度策略和优先级。可以在以下代码中看到使用它来显示给定进程（按 PID）的调度策略和优先级的快速演示：

```
$ chrt -p $$
pid 1618's current scheduling policy: SCHED_OTHER
pid 1618's current scheduling priority: 0
$ 
```

在前面的内容中，我们已经查询了`chrt(1)`进程本身的调度策略和优先级（使用 shell 的`$$`变量）。尝试对其他线程执行此操作；您会注意到策略（几乎）总是`SCHED_OTHER`，而实时优先级为零。实时优先级为零意味着该进程不是实时的。

您可以通过将线程 PID（通过`ps -LA`的输出或类似方式）传递给`chrt(1)`来查询线程的调度策略和（实时）优先级。

# `nice value`

那么，现在您可能会想知道，如果所有非实时线程（`SCHED_OTHER`）的优先级都为零，那么我如何在它们之间支持优先级？好吧，这正是`SCHED_OTHER`线程的`nice value`的用途：这是（较旧的）Unix 风格的优先级模型，现在在 Linux 上指定了非实时线程之间的相对优先级。

`nice value`是在现代 Linux 上介于`-20`到`+19`之间的优先级范围，基本优先级为零。在 Linux 上，这是一个每个线程的属性；当创建线程时，它会继承其创建者线程的`nice value` - 零是默认值。请参考以下图表：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/7552b647-8192-4284-ab25-ef4e8ba443a2.png)

图 2：Linux 线程优先级范围

从 2.6.23（使用 CFS 内核调度程序），线程的`nice value`对调度有很大影响（每个`nice value`度的因素为 1.25）；因此，`-20`的`nice value`线程获得更多的 CPU 带宽（这对于像多媒体这样对 CPU 敏感的应用程序很有好处），而`+19`的`nice value`线程获得的 CPU 很少。

应用程序员可以通过`nice(1)`命令行实用程序以及`nice(2)`，`setpriority(2)`和`sched_setattr(2)`系统调用（最后一个是最近和正确的使用方法）来查询和设置`nice value`。我们建议您参考这些 API 的相应手册页。

请记住，实时（`SCHED_FIFO`或`SCHED_RR`）线程在优先级方面始终优于`SCHED_OTHER`线程（因此几乎可以保证它将有机会更早运行）。

# CPU 亲和力

让我们想象一个具有四个 CPU 核心的 Linux 系统，为简单起见，有一个准备运行的线程。这个线程将在哪个 CPU 核心上运行？内核将决定这一点；要意识到的关键事情是它可以在四个可用的 CPU 中的任何一个上运行！

程序员可以指定它可能运行的 CPU 吗？是的，确实；这个特性本身就叫做 CPU 亲和力。在 Linux 上，这是一个每个线程的属性（在操作系统内）。CPU 亲和力可以通过改变线程的 CPU 亲和力掩码来在每个线程上进行更改；当然，这是通过系统调用实现的。让我们看一下下面的代码：

```
#define _GNU_SOURCE /* See feature_test_macros(7) */
#include <sched.h>
int sched_setaffinity(pid_t pid, size_t cpusetsize,
                        const cpu_set_t *mask);
int sched_getaffinity(pid_t pid, size_t cpusetsize,
                        cpu_set_t *mask);
```

内核调度程序将遵守程序员设置的 CPU 掩码，即线程被允许执行的 CPU 集合。我们期望将 CPU 亲和力掩码指定为`cpu_set_t`对象。（我们建议读者参考`sched_setaffinity(2)`的手册页，它提供了一个示例程序）。

请注意，pthread 框架提供了包装 API `pthread_setaffinity_np(3)`和`pthread_getaffinity_np(3)`，以在给定线程上执行相同的操作（它们在内部调用`sched_setaffinity(2)`系统调用）。

CPU 预留的一个有趣设计是 CPU 亲和力掩码模型，可以在多核系统上有效地为性能关键的线程（或线程）设置一个 CPU 核心。这意味着必须为该线程设置特定的 CPU 掩码，并且将所有其他线程的 CPU 掩码设置为排除核心 3。

尽管听起来很简单，但这并不是一个微不足道的练习；其中一些原因如下：

+   您必须意识到，预留的 CPU 并不是真正专门为指定的线程（们）保留的；对于真正的 CPU 预留，除了在该 CPU 上运行的给定线程（们）之外，整个系统上的所有其他线程都必须以某种方式被排除在该 CPU 之外。

+   作为一般准则，操作系统调度程序最了解如何在可用的 CPU 核心之间分配 CPU 带宽（它具有负载平衡器组件并了解 CPU 层次结构）；因此，最好将 CPU 分配留给操作系统。

现代 Linux 内核支持一个非常强大的功能：**控制组**（**cgroups**）。关于 CPU 预留，可以通过 cgroup 模型实现。请参考 Stack Overflow 上的以下问答以获取更多详细信息：*如何使用 cgroups 限制除白名单之外的所有进程到单个 CPU*：[`unix.stackexchange.com/questions/247209/how-to-use-cgroups-to-limit-all-processes-except-whitelist-to-a-single-cpu`](https://unix.stackexchange.com/questions/247209/how-to-use-cgroups-to-limit-all-processes-except-whitelist-to-a-single-cpu)。

为了方便起见，Linux 提供了`taskset(1)`实用程序，作为查询和指定任何给定进程（或线程）的 CPU 亲和力掩码的简单方法。在这里，我们将查询两个进程的 CPU 亲和力掩码。（我们假设我们运行的系统有四个 CPU 核心；我们可以使用`lscpu(1)`来查询这一点）：

```
$ taskset -p 1
pid 1's current affinity mask: f
$ taskset -p 12446
pid 12446's current affinity mask: 7
$ 
```

PID 1（systemd）的 CPU 亲和力掩码是`0xf`，当然，这是二进制`1111`。如果设置了一个位`1`，则表示线程可以在由该位表示的 CPU 上运行。如果清除了该位`0`，则表示线程不能在由该位表示的 CPU 上运行。正如预期的那样，在一个四 CPU 的盒子上，CPU 亲和力位掩码默认为 0xf（1111），这意味着进程（或线程）可以在任何可用的 CPU 上运行。有趣的是，在前面的输出中，bash 进程似乎具有 CPU 亲和力掩码为`7`，这对应于二进制`0111`，这意味着它永远不会被调度到 CPU 3 上运行。

在下面的代码中，一个简单的 shell 脚本在循环中调用`chrt(1)`和`taskset(1)`实用程序，显示系统上每个进程的调度策略（实时）优先级和 CPU 亲和力掩码。

```
# ch17/query_sched_allprcs.sh
for p in $(ps -A -To pid)
do
    chrt -p $p 2>/dev/null
    taskset -p $p 2>/dev/null
done
```

我们鼓励读者在自己的系统上尝试这个。在下面的代码中，我们使用`grep(1)`来查找任何`SCHED_FIFO`任务：

```
$ ./query_sched_allprcs.sh | grep -A2 -w SCHED_FIFO
pid 12's current scheduling policy: SCHED_FIFO
pid 12's current scheduling priority: 99
pid 12's current affinity mask: 1
pid 13's current scheduling policy: SCHED_FIFO
pid 13's current scheduling priority: 99
pid 13's current affinity mask: 1
--
pid 16's current scheduling policy: SCHED_FIFO
pid 16's current scheduling priority: 99
pid 16's current affinity mask: 2
pid 17's current scheduling policy: SCHED_FIFO
pid 17's current scheduling priority: 99
pid 17's current affinity mask: 2
--
[...]
```

是的！我们找到了一些线程。哇，它们都是`SCHED_FIFO`实时优先级 99！让我们来看看这些线程是谁（还有一个很酷的一行脚本）：

```
$ ps aux | awk '$2==12 || $2==13 || $2==16 || $2==17 {print $0}'
USER PID %CPU %MEM  VSZ  RSS TTY STAT   START  TIME   COMMAND
root 12  0.0  0.0     0    0   ?    S   13:42  0:00   [migration/0]
root 13  0.0  0.0     0    0   ?    S   13:42  0:00   [watchdog/0]
root 16  0.0  0.0     0    0   ?    S   13:42  0:00   [watchdog/1]
root 17  0.0  0.0     0    0   ?    S   13:42  0:00   [migration/1]
$ 
```

为了清晰起见，前面的代码中显示了通常不会显示的`ps aux`标题。此外，我们使用`ps aux`样式，因为内核线程会显示在括号中。

事实证明（至少在这个特定的例子中），它们都是内核线程（请参阅下面的信息框）。要理解的重要一点是，它们故意设置为`SCHED_FIFO`（实时）优先级 99，这样，当它们想要在 CPU 上运行时，它们几乎立即就会运行。实际上，让我们来看一下它们的 CPU 亲和性掩码：它们被故意分配（具有值如 1,2,4,8），以便它们与特定的 CPU 核心相关联。重要的是要理解，这些内核线程并不会占用 CPU；实际上，它们大部分时间都处于睡眠状态（状态**S**），只有在需要时才会立即行动。

内核线程与它们的用户空间对应物并没有太大的不同；它们也会竞争 CPU 资源。关键的区别在于，内核线程无法看到用户空间，它们只在内核虚拟地址空间中执行（而用户空间线程当然可以看到用户模式下的用户空间，并且在发出系统调用时会切换到内核空间）。

# 利用 Linux 的软实时能力

回想一下，在本章的前面，我们曾经说过：Linux 上的软实时调度策略设计遵循所谓的固定优先级抢占式调度；固定优先级意味着应用程序决定并固定线程优先级（并且可以更改它）；操作系统不会。

应用程序不仅可以在线程优先级之间切换，甚至可以由应用程序开发人员更改调度策略（实际上是操作系统在后台使用的调度算法）；这可以在每个线程的基础上进行。这确实非常强大；这意味着一个应用程序拥有，比如说，五个线程，可以决定为每个线程分配什么调度策略和优先级！

# 调度策略和优先级 API

显然，为了实现这一点，操作系统必须暴露一些 API；事实上，有一些系统调用处理这一点——改变给定进程或线程的调度策略和优先级。

这里列出了一些更重要的这些 API 中的一部分，实际上只是一小部分：

+   `sched_setscheduler(2)`: 设置指定线程的调度策略和参数。

+   `sched_getscheduler(2)`: 返回指定线程的调度策略。

+   `sched_setparam(2)`: 设置指定线程的调度参数。

+   `sched_getparam(2)`: 获取指定线程的调度参数。

+   `sched_get_priority_max(2)`: 返回指定调度策略中可用的最大优先级。

+   `sched_get_priority_min(2)`: 返回指定调度策略中可用的最小优先级。

+   `sched_rr_get_interval(2)`: 获取在轮转调度策略下调度的线程使用的时间片。

+   `sched_setattr(2)`: 设置指定线程的调度策略和参数。这个（特定于 Linux 的）系统调用提供了`sched_setscheduler(2)`和`sched_setparam(2)`功能的超集。

+   `sched_getattr(2)`: 获取指定线程的调度策略和参数。这个（特定于 Linux 的）系统调用提供了`sched_getscheduler(2)`和`sched_getparam(2)`功能的超集。

`sched_setattr(2)`和`sched_getattr(2)`目前被认为是这些 API 中最新和最强大的。此外，在 Ubuntu 上，可以使用方便的`man -k sched`命令来查看与调度相关的所有实用程序和 API（-k：关键字）。

敏锐的读者很快会注意到我们之前提到的所有 API 都是系统调用（手册的第二部分），但 pthread API 呢？的确，它们也存在，并且，正如你可能已经猜到的那样，它们大多只是调用底层系统调用的包装器；在下面的代码中，我们展示了其中的两个：

```
#include <pthread.h>
int pthread_setschedparam(pthread_t thread, int policy,
                           const struct sched_param *param);
int pthread_getschedparam(pthread_t thread, int *policy,
                           struct sched_param *param);
```

重要的是要注意，为了设置线程（或进程）的调度策略和优先级，您需要以 root 访问权限运行。请记住，赋予线程特权的现代方式是通过 Linux Capabilities 模型（我们在第八章中详细介绍了*进程特权*）。具有`CAP_SYS_NICE`能力的线程可以任意将其调度策略和优先级设置为任何它想要的值。想一想：如果不是这样的话，那么几乎所有的应用程序都可以坚持以`SCHED_FIFO`优先级 99 运行，从而有效地使整个概念变得毫无意义！

`pthread_setschedparam(3)`在内部调用了`sched_setscheduler(2)`系统调用，`pthread_getschedparam(3)`在底层调用了`sched_getscheduler(2)`系统调用。它们的 API 签名是：

```
#include <sched.h>
int sched_setscheduler(pid_t pid, int policy,
                        const struct sched_param *param);
int sched_getscheduler(pid_t pid);
```

还存在其他 pthread API。请注意，这里显示的 API 有助于设置线程属性结构：`pthread_attr_setinheritsched(3)`、`pthread_attr_setschedparam(3)`、`pthread_attr_setschedpolicy(3)`和`pthread_setschedprio(3)`等。

`sched(7)`的 man 页面（在终端窗口中键入`man 7 sched`查找）详细介绍了用于控制线程调度策略、优先级和行为的可用 API。它提供了有关当前 Linux 调度策略、更改它们所需的权限、相关资源限制值和调度的内核可调参数，以及其他杂项细节。

# 代码示例-设置线程调度策略和优先级

为了巩固本章前几节学到的概念，我们将设计并实现一个小型演示程序，演示现代 Linux pthreads 应用程序如何设置单个线程的调度策略和优先级，以使线程（软）实时。

我们的演示应用程序将有三个线程。第一个当然是`main()`。以下要点显示了应用程序的设计目的：

+   线程 0（实际上是`main()`）：

这以`SCHED_OTHER`调度策略和实时优先级 0 运行，这是默认值。它执行以下操作：

+   查询`SCHED_FIFO`的优先级范围，并打印出值

+   创建两个工作线程（可连接状态设置为分离状态）；它们将自动继承主线程的调度策略和优先级

+   在循环中向终端打印字符`m`（使用我们的`DELAY_LOOP`宏；比平常长一点）

+   终止

+   工作线程 1：

+   将其调度策略更改为`SCHED_RR`，将其实时优先级设置为命令行传递的值

+   休眠 2 秒（因此在 I/O 上阻塞，允许主线程完成一些工作）

+   唤醒后，它在循环中向终端打印字符`1`（通过`DELAY_LOOP`宏）

+   终止

+   工作线程 2：

+   将其调度策略更改为`SCHED_FIFO`，将其实时优先级设置为命令行传递的值加上 10

+   休眠 4 秒（因此在 I/O 上阻塞，允许线程 1 完成一些工作）

+   唤醒后，它在循环中向终端打印字符`2`

+   终止

让我们快速看一下代码（`ch17/sched_rt_eg.c`）：

为了便于阅读，这里只显示了源代码的关键部分；要查看完整的源代码，并构建和运行它，整个树可在 GitHub 上克隆：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

以下代码是`main()`的代码。（我们省略了显示错误检查代码）：

```
#define NUMWORK   200
...
  min = sched_get_priority_min(SCHED_FIFO);
  max = sched_get_priority_max(SCHED_FIFO);
  printf("SCHED_FIFO: priority range is %d to %d\n", min, max);
  rt_prio = atoi(argv[1]);
...
  ret = pthread_create(&tid[0], &attr, worker1, (void *)rt_prio);
  ret = pthread_create(&tid[1], &attr, worker2, (void *)rt_prio);
  pthread_attr_destroy(&attr);
  DELAY_LOOP('m', NUMWORK+100);
  printf("\nmain: all done, app exiting ...\n");
  pthread_exit((void *)0);
}
```

以下代码是工作线程 1 的代码。我们省略了显示错误检查代码：

```
void *worker1(void *msg)
{
  struct sched_param p;
  printf(" RT Thread p1 (%s():%d:PID %d):\n"
   " Setting sched policy to SCHED_RR and RT priority to %ld"
   " and sleeping for 2s ...\n", __func__, __LINE__, getpid(), (long)msg);

   p.sched_priority = (long)msg;
   pthread_setschedparam(pthread_self(), SCHED_RR, &p);
   sleep(2);
   puts(" p1 working");
   DELAY_LOOP('1', NUMWORK);
   puts(" p1: exiting..");
   pthread_exit((void *)0);
}
```

工作线程 2 的代码几乎与前面的工作线程相同；然而，不同之处在于我们将策略设置为`SCHED_FIFO`，并且将实时优先级提高了 10 分，从而使其更具侵略性。我们只在这里显示这个片段：

```
  p.sched_priority = prio + 10;
  pthread_setschedparam(pthread_self(), SCHED_FIFO, &p);
  sleep(4);
  puts(" p2 working");
  DELAY_LOOP('2', NUMWORK);
```

让我们构建它（我们强烈建议构建调试版本，因为这样`DELAY_LOOP`宏的效果就可以清楚地看到），然后试一试：

```
$ make sched_rt_eg_dbg
gcc -g -ggdb -gdwarf-4 -O0 -Wall -Wextra -DDEBUG -pthread -c sched_rt_eg.c -o sched_rt_eg_dbg.o
gcc -o sched_rt_eg_dbg sched_rt_eg_dbg.o common_dbg.o -pthread -lrt
$ 
```

我们必须以 root 身份运行我们的应用程序；我们使用`sudo(8)`来做到这一点：

```
$ sudo ./sched_rt_eg_dbg 14
SCHED_FIFO: priority range is 1 to 99
main: creating RT worker thread #1 ...
main: creating RT worker thread #2 ...
  RT Thread p1 (worker1():68:PID 18632):
 Setting sched policy to SCHED_RR and RT priority to 14 and sleeping for 2s ...
m RT Thread p2 (worker2():101:PID 18632):
 Setting sched policy to SCHED_FIFO and RT priority to 24 and sleeping for 4s ...
mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm p1 working
1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m11m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m11m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m1m11m1m1m p2 working
2m12m12m1m2m12m12m1m2m12m12m1m2m12m12m12m12m12m112m12m12m12m112m12m12m112m12m12m112m12m12m12m112m12m12m121m211m21m21m21m211m21m21m21m211m21m21m21m211m21m21m21m211m21m21m21m211m21m21m21
main: all done, app exiting ...
$ 
```

在前面的输出中，我们可以看到以下字符：

+   `m`：这意味着`main`线程目前正在 CPU 上运行

+   `1`：这意味着（软）实时工作线程 1 目前正在 CPU 上运行

+   `2`：这意味着（软）实时工作线程 2 目前正在 CPU 上运行

但是，哎呀，前面的输出并不是我们期望的：`m`，`1`和`2`字符混在一起，让我们得出它们已经被分时切片的结论。

但事实并非如此。仔细想想——输出与前面的代码中所显示的一样，是因为我们在多核系统上运行了应用程序（在前面的代码中，在一个具有四个 CPU 核心的笔记本电脑上）；因此，内核调度程序巧妙地利用了硬件，在不同的 CPU 核心上并行运行了所有三个线程！因此，为了使我们的演示应用程序按我们的期望运行，我们需要确保它只在一个 CPU 核心上运行，而不是更多。如何做到？回想一下 CPU 亲和力：我们可以使用`sched_setaffinity(2)`系统调用来做到这一点。还有一种更简单的方法：我们可以使用`taskset(1)`来保证进程（因此其中的所有线程）只在一个 CPU 核心上运行（例如，CPU 0），方法是将 CPU 掩码值指定为`01`。因此，让我们执行以下命令：

```
$ sudo taskset 01 ./sched_rt_eg_dbg 14
[sudo] password for <username>: xxx 
SCHED_FIFO: priority range is 1 to 99
main: creating RT worker thread #1 ...
main: creating RT worker thread #2 ...
m RT Thread p2 (worker2():101:PID 19073):
 Setting sched policy to SCHED_FIFO and RT priority to 24 and sleeping for 4s ...
 RT Thread p1 (worker1():68:PID 19073):
 Setting sched policy to SCHED_RR and RT priority to 14 and sleeping for 2s ...
mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm p1 working
11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 p2 working
22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222 p2 exiting ...
111111111111111111111111111111111111111111111111111111111111111111111111 p1: exiting..
mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm
main: all done, app exiting ...
$ 
```

是的，使用`taskset(1)`来确保整个应用程序——所有三个线程——在第一个 CPU 核心上运行产生了期望的效果。现在，仔细研究前面的输出；我们可以看到`main()`线程——非实时——首先运行了大约 2 秒；一旦经过了 2 秒，工作线程 1 就会醒来，变得可运行。由于它的策略和优先级远远超过了`main()`，它抢占了`main()`并运行，向终端打印 1s。请记住，工作线程 2 也在并行运行，但是它当然会睡眠 4 秒。所以，2 秒后——一共经过了 4 秒——工作线程 2 醒来，变得可运行。由于它的策略是`SCHED_FIFO`，更重要的是，它的优先级比线程 1 高 10 分，它抢占了线程 1 并运行，向终端打印`2s`。在它终止之前，其他线程无法运行；一旦它终止，工作线程 1 运行。同样，在它终止之前，`main()`无法运行；一旦它终止，`main()`最终获得 CPU 并完成，应用程序终止。有趣；你自己试试吧。

供您参考，关于`pthread_setschedparam(3)`的 man 页面有一个相当详细的示例程序：[`man7.org/linux/man-pages/man3/pthread_setschedparam.3.html`](http://man7.org/linux/man-pages/man3/pthread_setschedparam.3.html)。

# 软实时——额外考虑

还有一些额外的要点需要考虑：我们有权将线程与（软）实时策略和优先级相关联（前提是我们拥有 root 访问权限；或者 CAP_SYS_NICE 能力）。对于大多数人机交互应用领域来说，这不仅是不必要的，而且会给典型的桌面或服务器系统最终用户带来令人不安的反馈和副作用。一般来说，您应该避免在交互式应用程序上使用这些实时策略。只有在必须高度优先考虑一个线程时——通常是为了实时应用程序（可能在嵌入式 Linux 盒子上运行），或某些类型的基准测试或分析软件（`perf(1)`是一个很好的例子；可以指定`--realtime=n`参数给`perf`，使其以`SCHED_FIFO`优先级`n`运行）——您才应该考虑使用这些强大的技术。

此外，要使用的精确实时优先级留给应用架构师；对于`SCHED_FIFO`和`SCHED_RR`线程使用相同的优先级值（请记住，这两种策略是同级的，`SCHED_FIFO`更为激进）可能会导致不可预测的调度。仔细考虑设计，并相应地设置每个实时线程的策略和优先级。

最后，尽管本书没有深入介绍，但 Linux 的 cgroups 模型允许您强大地控制资源（CPU、网络和块 I/O）的带宽分配给特定进程或一组进程。如果需要这样做，请考虑使用 cgroups 框架来实现您的目标。

# RTL - Linux 作为 RTOS

事实上，令人难以置信的是，Linux 操作系统可以用作 RTOS；也就是说，可以用作硬实时 RTOS。该项目最初是 Linutronix 的 Thomas Gleixner 的构想。

再次强调，这真的是开源模型和 Linux 的美丽之处；作为开源项目，有兴趣和动力的人将 Linux（或其他项目）作为起点，并在此基础上构建，通常会产生显著新颖和有用的产品。

关于该项目的一些要点如下：

+   修改 Linux 内核以成为 RTOS 是一个必然具有侵入性的过程；事实上，Linux 的领导者 Linus Torvalds 不希望这些代码出现在上游（原始）Linux 内核中。因此，实时 Linux 内核项目作为一个补丁系列存在（在 kernel.org 本身上；请参阅 GitHub 存储库上的*进一步阅读*部分中的链接以获取更多信息），可以应用于主线内核。

+   这一努力从 Linux 2.6.18 内核开始就已经成功进行（大约从 2006 年或 2007 年开始）。

+   多年来，该项目被称为 Preempt-RT（补丁本身被称为 PREEMPT_RT）。

+   后来（从 2015 年 10 月起），该项目的管理权被**Linux 基金会**（**LF**）接管——这是一个积极的举措。名称从 Preempt RT 更改为**real-time Linux**（**RTL**）。

+   事实上，RTL 路线图非常有推动相关的 PREEMPT_RT 工作上游（进入主线 Linux 内核；请参阅 GitHub 存储库上的*进一步阅读*部分以获取相关链接）的目标。

实际上，您可以应用适当的 RTL 补丁，然后将 Linux 用作硬实时 RTOS。行业已经开始在工业控制应用程序、无人机和电视摄像机中使用该项目；我们只能想象这将会大大增长。还要注意的是，拥有硬实时操作系统并不足以满足真正实时使用的要求；甚至应用程序也必须按照实时预期进行编写。请查看 RTL 项目维基站点上提供的*HOWTO*文档（请参阅 GitHub 存储库上的*进一步阅读*部分）。

# 总结

在本章中，我们涵盖了与 Linux 和实时 CPU 调度相关的重要概念。读者已经逐步了解了 Linux 线程状态机、实时性、CPU 亲和力以及可用的 POSIX 调度策略等主题。此外，我们展示了在 pthread 和系统调用层面利用这些强大机制的 API。演示应用程序强化了我们学到的概念。最后，我们简要介绍了 Linux 也可以用作硬实时（RTOS）的事实。

在下一章中，读者将学习如何利用现代技术实现最佳的 I/O 性能。


# 第十八章：高级文件 I/O

在[附录 A](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)，*文件 I/O 基础*中，我们介绍了应用程序开发人员如何利用可用的 glibc 库 API 以及执行文件 I/O（打开、读取、写入和关闭）的典型系统调用。虽然它们可以工作，但实际上性能并没有得到真正优化。在本章中，我们将重点介绍更高级的文件 I/O 技术，以及开发人员如何利用更新和更好的 API 来提高性能。

通常，人们会对 CPU 及其性能感到紧张。虽然重要，但在许多（如果不是大多数）真实的应用工作负载中，真正拖慢性能的不是 CPU，而是 I/O 代码路径。这是可以理解的；回想一下，从第二章 *虚拟内存*中我们展示了磁盘速度与 RAM 相比要慢几个数量级。网络 I/O 也是类似的情况；因此，可以推断真正的性能瓶颈是由于大量持续的磁盘和网络 I/O 造成的。

在本章中，读者将学习几种改进 I/O 性能的方法；广义上讲，这些方法将包括以下内容：

+   充分利用内核页面缓存

+   向内核提供关于文件使用模式的提示和建议

+   使用分散-聚集（向量）I/O

+   利用内存映射进行文件 I/O

+   学习和使用复杂的 DIO 和 AIO 技术

+   学习 I/O 调度程序

+   用于监视、分析和带宽控制 I/O 的实用程序/工具/API/cgroups

# I/O 性能建议

进行 I/O 时的关键是意识到底层存储（磁盘）硬件比 RAM 慢得多。因此，制定策略以最小化对磁盘的访问并更多地从内存中工作总是有帮助的。事实上，库层（我们已经详细讨论了 studio 缓冲区），以及操作系统（通过页面缓存和块 I/O 层中的其他功能，事实上，甚至在现代硬件中）将执行大量工作来确保这一点。对于（系统）应用程序开发人员，下面提出了一些建议。

如果可行，执行文件 I/O 操作时使用大缓冲区（用于保存读取或要写入的数据）——但有多大？一个经验法则是使用与文件系统的 I/O 块大小相同的本地缓冲区大小（实际上，这个字段在文件系统 I/O 中内部记录为块大小）。查询很简单：在要执行 I/O 的文件上发出`stat(1)`命令。例如，假设在 Ubuntu 18.04 系统上，我们想要读取当前运行的内核配置文件的内容：

```
$ uname -r
4.15.0-23-generic
$ ls -l /boot/config-4.15.0-23-generic 
-rw-r--r-- 1 root root 216807 May 23 22:24 /boot/config-4.15.0-23-generic
$ stat /boot/config-4.15.0-23-generic 
 File: /boot/config-4.15.0-23-generic
 Size: 216807 Blocks: 424 IO Block: 4096 regular file
Device: 801h/2049d Inode: 398628 Links: 1
Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
Access: 2018-07-30 12:42:09.789005000 +0530
Modify: 2018-05-23 22:24:55.000000000 +0530
Change: 2018-06-17 12:36:34.259614987 +0530
 Birth: -
$ 
```

从代码中可以看出，`stat(1)`从文件的 inode 数据结构中显示了几个文件特性（或属性），其中包括 I/O 块大小。

在内部，`stat(1)`实用程序发出`stat(2)`系统调用，解析底层文件的 inode 并向用户空间提供所有细节。因此，当需要以编程方式时，利用`[f]stat(2)`API。

此外，如果内存不是一个限制，为什么不分配一个中等到非常大的缓冲区并通过它执行 I/O；这将有所帮助。确定需要多大需要在目标平台上进行一些调查；为了给你一个概念，在早期，管道 I/O 通常使用一个页面大小的内核缓冲区；在现代 Linux 内核上，默认情况下管道 I/O 缓冲区大小增加到了一兆字节。

# 内核页面缓存

从[附录 A](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)中我们了解到，当一个进程（或线程）通过使用`fread(3)`或`fwrite(3)`库层 API 执行文件 I/O 时，最终会通过`read(2)`和`write(2)`系统调用发出到底层操作系统。这些系统调用让内核执行 I/O；尽管这似乎是直观的，但实际情况是读写系统调用并不是同步的；也就是说，它们可能在实际 I/O 完成之前返回。（显然，对文件的写入会是这种情况；同步读取必须将读取的数据返回到用户空间内存缓冲区；在此之前，读取会被阻塞。然而，即使是读取也可以通过**异步 I/O**（**AIO**）变成异步。）

事实上，在内核中，每个单个文件 I/O 操作都被缓存在一个称为*页缓存*的全局内核缓存中。因此，当一个进程向文件写入数据时，数据缓冲区并不会立即刷新到底层块设备（磁盘或闪存存储），而是被缓存在页缓存中。同样，当一个进程从底层块设备读取数据时，数据缓冲区也不会立即复制到用户空间进程内存缓冲区；不，你猜对了，它首先存储在页缓存中（进程实际上会从那里接收到它）。再次参考[附录 A](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)，*文件 I/O 基础*，*图 3：更多细节—应用到 stdio I/O 缓冲区到内核页缓存*，来看看这一点。

为什么内核页缓存中的缓存有用呢？简单：通过利用缓存的关键属性，即缓存内存区域（RAM）和正在缓存的区域（块设备）之间的速度差异，我们获得了巨大的性能提升。页缓存位于 RAM 中，因此保持所有文件 I/O 的内容被缓存（尽可能）几乎可以保证应用程序在文件数据上执行读取时命中缓存；从 RAM 读取比从存储设备读取要快得多。同样，内核将写入数据缓冲区缓存到页缓存中，而不是将应用程序数据缓冲区慢慢同步地直接写入块设备。显然，刷新已写入的数据到底层块设备以及管理页缓存内存本身的工作都在 Linux 内核的工作范围之内（我们在这里不讨论这些内部细节）。

程序员总是可以显式地将文件数据刷新到底层存储设备；我们在[附录 A](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)中已经介绍了相关的 API 及其用法，*文件 I/O 基础*。

# 给内核提供文件 I/O 模式的提示

我们现在明白了内核会缓存所有文件 I/O 在其页缓存中；这对性能有好处。想象一个例子会很有用：一个应用程序设置并对一个非常大的视频文件进行流式读取（在某个应用窗口中向用户显示；我们假设特定的视频文件是第一次被访问）。一般来说，从磁盘读取文件时进行缓存是有帮助的，但在这种特殊情况下，它并不会帮助太多，因为第一次，我们仍然必须首先去磁盘读取。因此，我们耸耸肩，继续以通常的方式编写代码，顺序读取视频数据块（通过其底层编解码器）并将其传递给渲染代码。

# 通过 posix_fadvise(2) API

我们能做得更好吗？是的，Linux 提供了`posix_fadvise(2)`系统调用，允许应用程序进程通过一个名为`advice`的参数向内核提供关于其对文件数据访问模式的提示。与我们的示例相关，我们可以将建议作为值`POSIX_FADV_SEQUENTIAL`，`POSIX_FADV_WILLNEED`传递，以通知内核我们期望按顺序读取文件数据，并且我们期望我们将来会需要访问文件的数据。这个建议会导致内核按顺序（从较低到较高的文件偏移）积极地预读文件数据到内核页缓存中。这将极大地帮助提高性能。

`posix_fadvise(2)`系统调用的签名如下：

```
#include <fcntl.h>
int posix_fadvise(int fd, off_t offset, off_t len, int advice);
```

显然，第一个参数`fd`代表文件描述符（我们参考读者到[附录 A](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)，*文件 I/O 基础*），第二个和第三个参数`offset`和`len`指定了文件的一个区域，我们通过第四个参数`advice`传递了提示或建议。（长度实际上是按页粒度四舍五入的。）

不仅如此，应用程序在处理完视频数据块后，甚至可以通过调用`posix_fadvise(2)`并将建议设置为值`POSIX_FADV_DONTNEED`来告知操作系统，它将不再需要那个特定的内存块；这将是一个提示给内核，它可以释放持有该数据的页（页）的页缓存，从而为重要数据（以及可能仍然有用的已缓存数据）腾出空间。

需要注意一些注意事项。首先，开发人员要意识到这个建议实际上只是对操作系统的一个提示，一个建议；它可能会被采纳，也可能不会。其次，即使目标文件的页被读入页缓存，它们也可能因为各种原因被驱逐，内存压力是一个典型的原因。尽管如此，尝试也没有坏处；内核通常会考虑这个建议，并且它确实可以提高性能。（关于这个 API 的更多建议值可以像往常一样在 man 页面中查找。）

有趣的是，现在可以理解，`cat(1)`使用`posix_fadvise(2)`系统调用通知内核，它打算执行顺序读取直到文件结束。在`cat(1)`上使用强大的`strace(1)`工具可以发现以下内容：`...fadvise64(3, 0, 0, POSIX_FADV_SEQUENTIAL) = 0`

不要被 fadvise64 搞得紧张，它只是 Linux 上`posix_fadvise(2)`系统调用的底层实现。显然，`cat(1)`已经在文件（描述符 3），偏移量 0 和长度 0 上调用了这个系统调用，意味着直到文件结束，并且将`advice`参数设置为`POSIX_FADV_SEQUENTIAL`。

# 通过 readahead(2) API

Linux（GNU）特定的`readahead(2)`系统调用实现了与我们刚刚看到的`posix_fadvise(2)`类似的结果，以便进行积极的文件预读。它的签名如下：

```
include <fcntl.h>
ssize_t readahead(int fd, off64_t offset, size_t count);
```

预读是从指定为`fd`的目标文件开始的，从文件`offset`开始，最多`count`字节（按页粒度四舍五入）。

虽然通常不需要，但如果您想要明确地清空（清理）Linux 内核页缓存的内容怎么办？如果需要，以 root 用户身份执行以下操作：

`# sync && echo 1 > /proc/sys/vm/drop_caches`

不要忘记先使用`sync(1)`，否则会有丢失数据的风险。再次强调，正常情况下不应该刷新内核页缓存，因为这实际上可能会损害 I/O 性能。在 GitHub 上有一个有用的**命令行接口**（**CLI**）包装工具集合，称为 linux-ftools，可以在这里找到：[`github.com/david415/linux-ftools`](https://github.com/david415/linux-ftools)。它提供了`fincore(1)`（读作 f-in-core）、`fadvise(1)`和`fallocate(1)`工具；查看它们的 GitHub README，阅读它们的 man 页面，并尝试使用它们，这是非常有教育意义的。

# 使用 pread、pwrite API 的 MT 应用程序文件 I/O

回想一下我们在[附录 A](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)中看到的`read(2)`和`write(2)`系统调用，它们构成了对文件进行 I/O 的基础。你还会记得，使用这些 API 时，操作系统会隐式更新底层文件的偏移量。例如，如果一个进程通过`open(2)`打开一个文件，然后执行 512 字节的`read(2)`，文件的偏移量（或所谓的寻位位置）现在将是 512。如果现在写入，比如说 200 字节，写入将从位置 512 到 712 进行，从而将新的寻位位置或偏移量设置为这个数字。

那又怎样？我们的观点很简单，文件的偏移量被隐式设置会在多线程应用程序中引起问题，当多个线程同时对同一底层文件进行 I/O 操作时。但是，等等，我们之前提到过：文件需要被锁定然后进行操作。但是，锁定会导致主要的性能瓶颈。如果你设计一个 MT 应用程序，其线程并行地处理同一文件的不同部分，听起来很棒，除了文件的偏移量会不断变化，从而破坏我们的并行性和性能（你还会记得我们在[附录 A](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)中的讨论，*文件 I/O 基础*，简单地使用`lseek(2)`来显式设置文件的寻位位置可能导致危险的竞争）。

那么，你该怎么办？Linux 提供了`pread(2)`和`pwrite(2)`系统调用（p 代表定位 I/O）来解决这个问题；使用这些 API，可以指定要执行 I/O 的文件偏移量（或定位），操作系统不会改变实际的底层文件偏移量。它们的签名如下：

```
#include <unistd.h>
ssize_t pread(int fd, void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);
```

`pread(2)`/`pwrite(2)`与通常的`read(2)`/`write(2)`系统调用的区别在于，前者的 API 需要额外的第四个参数——文件偏移量，用于执行读取或写入 I/O 操作，而不会修改它。这使我们能够实现我们想要的：通过多个线程同时并行读取和写入文件的不同部分，从而使 MT 应用程序执行高性能 I/O。（我们将尝试这个任务留给读者作为一个有趣的练习。）

需要注意的一些注意事项：首先，就像`read(2)`和`write(2)`一样，`pread(2)`和`pwrite(2)`也可能在没有传输所有请求的字节的情况下返回；程序员有责任检查并调用 API，直到没有剩余的字节需要传输（参见[附录 A](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)，*文件 I/O 基础知识*）。正确使用读/写 API，解决这类问题）。其次，当文件以指定了`O_APPEND`标志打开时，Linux 的`pwrite(2)`系统调用总是将数据追加到 EOF，而不管当前偏移值如何；这违反了 POSIX 标准，该标准规定`O_APPEND`标志不应对写入发生的起始位置产生影响。第三，显而易见的是（但我们必须声明），正在操作的文件必须能够进行寻址（即支持`fseek(3)`或`lseek(2)`的 API）。常规文件总是支持寻址操作，但管道和某些类型的设备不支持）。

# 分散-聚集 I/O

为了帮助解释这个主题，让我们假设我们被委托向文件写入数据，使得三个不连续的数据区域 A、B 和 C 被写入（分别填充为 A、B 和 C）；以下图表显示了这一点：

```
+------+-----------+---------+-----------+------+-----------+
|      | ... A ... |         | ... B ... |      | ... C ... |
+------+-----------+---------+-----------+------+-----------+
|A_HOLE|   A_LEN   | B_HOLE  |   B_LEN   |C_HOLE|  C_LEN    |
+------+-----------+---------+-----------+------+-----------+
       ^                     ^                  ^
       A_START_OFF           B_START_OFF        C_START_OFF
```

不连续的数据文件

注意文件中有空洞——不包含任何数据内容的区域；这在常规文件中是可能实现的（大部分是空洞的文件称为稀疏文件）。如何创建空洞呢？简单：只需执行`lseek(2)`，然后`write(2)`数据；向前寻找的长度确定了文件中空洞的大小。

那么，我们如何实现所示的数据文件布局呢？我们将展示两种方法——一种是传统的方法，另一种是更为优化性能的方法。让我们从传统方法开始。

# 不连续的数据文件-传统方法

这似乎很简单：首先寻找所需的起始偏移量，然后为所需的长度写入数据内容；这可以通过一对`lseek(2)`和`write(2)`系统调用来完成。当然，我们将不得不调用这一对系统调用三次。因此，我们编写一些代码来实际执行这个任务；在这里查看代码的（相关片段）(`ch18/sgio_simple.c`)：

为了可读性，只显示了源代码的关键部分；要查看完整的源代码，构建并运行它，整个树都可以从 GitHub 克隆到这里：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

```
#define A_HOLE_LEN  10
#define A_START_OFF A_HOLE_LEN
#define A_LEN       20

#define B_HOLE_LEN  100
#define B_START_OFF (A_HOLE_LEN+A_LEN+B_HOLE_LEN)
#define B_LEN        30

#define C_HOLE_LEN  20
#define C_START_OFF (A_HOLE_LEN+A_LEN+B_HOLE_LEN+B_LEN+C_HOLE_LEN)
#define C_LEN       42
...
static int wr_discontig_the_normal_way(int fd)
{ ...
    /* A: {seek_to A_START_OFF, write gbufA for A_LEN bytes} */
    if (lseek(fd, A_START_OFF, SEEK_SET) < 0)
        FATAL("lseek A failed\n");
    if (write(fd, gbufA, A_LEN) < 0)
        FATAL("write A failed\n");

    /* B: {seek_to B_START_OFF, write gbufB for B_LEN bytes} */
    if (lseek(fd, B_START_OFF, SEEK_SET) < 0)
        FATAL("lseek B failed\n");
    if (write(fd, gbufB, B_LEN) < 0)
        FATAL("write B failed\n");

    /* C: {seek_to C_START_OFF, write gbufC for C_LEN bytes} */
    if (lseek(fd, C_START_OFF, SEEK_SET) < 0)
        FATAL("lseek C failed\n");
    if (write(fd, gbufC, C_LEN) < 0)
        FATAL("write C failed\n");
    return 0;
}
```

注意我们已经编写了代码，连续三次使用`{lseek, write}`系统调用；让我们试一试：

```
$ ./sgio_simple 
Usage: ./sgio_simple use-method-option
 0 = traditional lseek/write method
 1 = better SG IO method
$ ./sgio_simple 0
In setup_buffers_goto()
In wr_discontig_the_normal_way()
$ ls -l tmptest 
-rw-rw-r--. 1 kai kai 222 Oct 16 08:45 tmptest
$ hexdump -x tmptest 
0000000 0000 0000 0000 0000 0000 4141 4141 4141
0000010 4141 4141 4141 4141 4141 4141 4141 0000
0000020 0000 0000 0000 0000 0000 0000 0000 0000
*
0000080 0000 4242 4242 4242 4242 4242 4242 4242
0000090 4242 4242 4242 4242 4242 4242 4242 4242
00000a0 0000 0000 0000 0000 0000 0000 0000 0000
00000b0 0000 0000 4343 4343 4343 4343 4343 4343
00000c0 4343 4343 4343 4343 4343 4343 4343 4343
00000d0 4343 4343 4343 4343 4343 4343 4343 
00000de
$ 
```

它起作用了；我们创建的文件`tmptest`（我们没有展示创建文件、分配和初始化缓冲区等代码，请通过书的 GitHub 存储库查找），长度为 222 字节，尽管实际的数据内容（A、B 和 C）的长度为 20+30+42=92 字节。剩下的（222-92）130 字节是文件中的三个空洞（长度分别为 10+100+20 字节；请查看代码中定义这些的宏）。`hexdump(1)`实用程序方便地转储了文件的内容；0x41 代表 A，0x42 代表 B，0x43 代表 C。空洞清楚地显示为我们想要的长度的空值填充区域。

# 不连续的数据文件- SG-I/O 方法

当然，使用连续三次`{lseek, write}`系统调用的传统方法是有效的，但性能上存在相当大的惩罚；事实上，发出系统调用被认为是非常昂贵的。从性能上讲，一种更优越的方法是称为*分散-聚集 I/O*（SG-I/O，或向量 I/O）。相关的系统调用是`readv(2)`和`writev(2)`；这是它们的签名：

```
#include <sys/uio.h>
ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
```

这些系统调用允许您一次性指定一堆要读取或写入的段；每个段通过称为`iovec`的结构描述一个单独的 I/O 操作：

```
struct iovec {
    void *iov_base; /* Starting address */
    size_t iov_len; /* Number of bytes to transfer */
};
```

程序员可以传递一个描述要执行的 I/O 操作的段数组；这正是第二个参数——指向 struct iovecs 数组的指针；第三个参数是要处理的段数。第一个参数很明显——表示要执行聚集读或分散写的文件描述符。

因此，请考虑一下：您可以通过 I/O 向量指针将给定文件的不连续读取聚集到您指定的缓冲区（及其大小）中，也可以通过 I/O 向量指针将给定文件的不连续写入分散到您指定的缓冲区（及其大小）中；这些类型的多个不连续 I/O 操作因此称为 scatter-gather I/O！这里是真正酷的部分：系统调用保证按数组顺序和原子方式执行这些 I/O 操作；也就是说，它们只有在所有操作完成时才会返回。不过，要注意：`readv(2)`或`writev(2)`的返回值是实际读取或写入的字节数，失败时为-1。始终有可能 I/O 操作执行的字节数少于请求的数量；这不是一个失败，开发人员需要检查。

现在，对于我们之前的数据文件示例，让我们看一下通过`writev(2)`设置和执行不连续的分散有序和原子写入的代码：

```
static int wr_discontig_the_better_SGIO_way(int fd)
{
  struct iovec iov[6];
  int i=0;

  /* We don't want to call lseek of course; so we emulate the seek
   * by introducing segments that are just "holes" in the file. */

  /* A: {seek_to A_START_OFF, write gbufA for A_LEN bytes} */
  iov[i].iov_base = gbuf_hole;
  iov[i].iov_len = A_HOLE_LEN;
  i ++;
  iov[i].iov_base = gbufA;
  iov[i].iov_len = A_LEN;

  /* B: {seek_to B_START_OFF, write gbufB for B_LEN bytes} */
  i ++;
  iov[i].iov_base = gbuf_hole;
  iov[i].iov_len = B_HOLE_LEN;
  i ++;
  iov[i].iov_base = gbufB;
  iov[i].iov_len = B_LEN;

  /* C: {seek_to C_START_OFF, write gbufC for C_LEN bytes} */
  i ++;
  iov[i].iov_base = gbuf_hole;
  iov[i].iov_len = C_HOLE_LEN;
  i ++;
  iov[i].iov_base = gbufC;
  iov[i].iov_len = C_LEN;
  i ++;

  /* Perform all six discontiguous writes in order and atomically! */
  if (writev(fd, iov, i) < 0)
    return -1;
/* Do note! As mentioned in Ch 19:
   * "the return value from readv(2) or writev(2) is the actual number
   * of bytes read or written, and -1 on failure. It's always possible
   * that an I/O operation performs less than the amount requested; this
   * is not a failure, and it's up to the developer to check."
   * Above, we have _not_ checked; we leave it as an exercise to the
   * interested reader to modify this code to check for and read/write
   * any remaining bytes (similar to this example: ch7/simpcp2.c).
   */
  return 0;
}
```

最终结果与传统方法相同；我们将其留给读者去尝试并查看。这是关键：传统方法要求我们发出至少六个系统调用（3 x `{lseek, write}`对）来执行对文件的不连续数据写入，而 SG-I/O 代码只需一个系统调用就可以执行相同的不连续数据写入。这将带来显著的性能提升，特别是对于 I/O 工作负载较重的应用程序。

对于前面示例程序（`ch18/sgio_simple.c`）的完整源代码感兴趣的读者可能会注意到一些奇怪的事情（甚至是错误的）：明目张胆地使用了备受争议的`goto`语句！事实上，`goto`在错误处理中非常有用——在由于失败而退出函数内部的深层嵌套路径时执行所需的代码清理。请查看 GitHub 存储库中*进一步阅读*部分提供的链接以获取更多信息。Linux 内核社区已经很长时间以来一直很高兴地使用`goto`；我们敦促开发人员研究其适当的用法。

# SG - I/O 变体

回想一下*MT app 文件 I/O 与 pread、pwrite APIs*部分，我们可以使用`pread(2)`和`pwrite(2)`系统调用通过多个线程有效地并行执行文件 I/O（在多线程应用程序中）。类似地，Linux 提供了`preadv(2)`和`pwritev(2)`系统调用；正如你猜到的那样，它们提供了`readv(2)`和`writev(2)`的功能，并增加了第四个参数 offset；就像`readv(2)`和`writev(2)`一样，可以指定要执行 SG-IO 的文件偏移量，并且不会更改（再次，对于 MT 应用程序可能有用）。`preadv(2)`和`pwritev(2)`的签名如下所示：

```
#include <sys/uio.h>
ssize_t preadv(int fd, const struct iovec *iov, int iovcnt,
                      off_t offset);
ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt,
                       off_t offset);
```

最近的 Linux 内核（某些版本从 4.6 开始）还提供了 API 的另一个变体：`preadv2(2)`和`pwritev2(2)`系统调用。与以前的 API 不同之处在于，它们接受一个额外的第五个参数 flag，允许开发人员更多地控制 SG-I/O 操作的行为，可以指定它们是同步的（通过 RWF_DSYNC 和 RWF_SYNC 标志）、高优先级的（通过 RWF_HIPRI 标志）还是非阻塞的（通过 RWF_NOWAIT 标志）。我们建议读者查看`preadv2(2)`/`pwritev2(2)`的手册页面以获取详细信息。

# 文件 I/O 通过内存映射

在[附录 A](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)中，*文件 I/O 基础*，以及本章中，我们已经多次提到 Linux 内核的*页面缓存*通过在其中缓存文件内容大大提高了性能（减轻了每次都需要访问真正缓慢的存储设备的需求，而是在 RAM 中只读取或写入数据块）。然而，尽管我们通过页面缓存获得了性能，但使用传统的`read(2)`、`write(2)`API 或者更快的 SG-I/O（`[p][read|write][v]2`）API 仍然存在一个隐藏的问题。

# Linux I/O 代码路径简介

为了理解问题所在，我们必须首先更深入地了解 I/O 代码路径的工作原理；以下图表概括了相关的要点：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/ed260a42-11ae-4f52-bc88-a2347b755b7a.png)

图 1：页面缓存填充

磁盘数据

读者应该意识到，尽管这个图表看起来相当详细，但我们实际上只是看到了整个 Linux I/O 代码路径（或 I/O 堆栈）的一个相当简化的视图，只有与本讨论相关的内容。有关更详细的概述（和图表），请参见 GitHub 存储库中*进一步阅读*部分提供的链接。

假设**进程 P1**打算从它打开的目标文件（通过`open(2)`系统调用）中读取大约 12KB 的数据；我们设想它是通过通常的方式来做到这一点：

+   通过`malloc(3)`API 分配一个 12KB 的堆缓冲区（3 页= 12,288 字节）。

+   发出`read(2)`系统调用，将数据从文件读入堆缓冲区。

+   `read(2)`系统调用在操作系统中执行工作；当读取完成时，它返回（希望值为`12,288`；请记住，检查这一点是程序员的工作，不要假设任何东西）。

这听起来很简单，但在幕后发生了更多的事情，我们有兴趣深入挖掘一下。以下是更详细的视图（在前面的图表中，数字点**1**、**2**和**3**以圆圈的形式显示；请跟随）：

1.  **进程 P1**通过`malloc(3)`API 分配了一个 12KB 的堆缓冲区（长度= 12KB = 12,288 字节）。

1.  接下来，它发出一个`read(2)`系统调用，从文件（由 fd 指定）中读取数据到刚刚分配的堆缓冲区 buf 中，长度为 12KB。

1.  由于`read(2)`是一个系统调用，进程（或线程）现在切换到内核模式（记得我们在第一章中讨论过的单 olithic 设计吗？），它进入 Linux 内核的通用文件系统层（称为**虚拟文件系统开关**（**VFS**）），然后将自动转移到适当的底层文件系统驱动程序（也许是 ext4 fs），之后 Linux 内核首先检查：所需文件数据的这些页面是否已经缓存在我们的页面缓存中？如果是，工作就完成了（我们直接跳到*步骤 7*），只需将页面复制回用户空间缓冲区。假设我们遇到了缓存未命中-所需的文件数据页面不在页面缓存中。

1.  因此，内核首先为页面缓存分配足够的 RAM（页面框架）（在我们的示例中，三个框架，显示为页面缓存内存区域中的粉色方块）。然后，它向底层层发出适当的 I/O 请求，请求文件数据。

1.  请求最终到达块（存储）驱动程序；我们假设它知道自己的工作，并从底层存储设备控制器（磁盘或闪存控制器芯片，也许）读取所需的数据块。然后（有趣的是）给出一个目标地址来写入文件数据；这是页面缓存内分配的页面框架的地址；因此，块驱动程序总是将文件数据写入内核的页面缓存，而不是直接写回用户模式进程缓冲区。

1.  块驱动程序已成功地将数据块从存储设备（或其他设备）复制到内核页缓存中先前分配的帧中。（实际上，这些数据传输是通过一种称为**直接内存访问**（**DMA**）的高级内存传输技术进行高度优化的，在这种技术中，驱动程序利用硬件直接在设备和系统内存之间传输数据，而无需 CPU 的干预。显然，这些话题远远超出了本书的范围。）

1.  刚刚填充的内核页缓存帧现在由内核复制到用户空间堆缓冲区。

1.  （阻塞的）`read(2)`系统调用现在终止，返回值为 12,288，表示文件数据的三个页面确实已经被传输（再次强调，您作为应用程序开发人员应该检查此返回值，而不是假设任何内容）。

看起来一切都很好，是吗？实际上并不是；仔细考虑一下：尽管`read(2)`（或`pread[v]2`）API 确实成功了，但这种成功是以相当大的代价为代价的：内核必须分配 RAM（页面帧）以在其页缓存中保存文件数据（步骤 4），一旦数据传输完成（步骤 6），然后将该内容复制到用户空间堆内存（步骤 7）。因此，我们使用了应该使用的两倍 RAM 来保留数据的额外副本。这是非常浪费的，显然，数据缓冲区在块驱动程序和内核页缓存之间以及内核页缓存和用户空间堆缓冲区之间的多次复制也会降低性能（更不用说 CPU 缓存不必要地被这些内容占用）。通过以前的代码模式，解决了不等待慢存储设备的问题（通过页缓存的效率），但其他方面都非常糟糕——我们实际上将所需的内存使用量加倍了，而且在复制过程中 CPU 缓存被（不必要的）文件数据覆盖。

# 为 I/O 映射文件

以下是解决这些问题的方法：通过`mmap(2)`系统调用进行内存映射。Linux 提供了非常强大的`mmap(2)`系统调用；它使开发人员能够将任何内容直接映射到进程的虚拟地址空间（VAS）。这些内容包括文件数据、硬件设备（适配器）内存区域或通用内存区域。在本章中，我们将只关注使用`mmap(2)`将常规文件的内容映射到进程的 VAS。在深入讨论`mmap(2)`如何成为我们刚刚讨论的内存浪费问题的解决方案之前，我们首先需要更多地了解如何使用`mmap(2)`系统调用本身。

`mmap(2)`系统调用的签名如下所示：

```
#include <sys/mman.h>
void *mmap(void *addr, size_t length, int prot, int flags,
           int fd, off_t offset);
```

我们希望将文件的给定区域，从给定的`offset`开始，映射到我们的进程 VAS 中的`length`字节；我们希望实现的简单视图如下图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/61b1e79e-6de8-4622-a1f7-3ee3b24b376e.png)

图 2：将文件区域映射到进程虚拟地址空间

为了将文件映射到进程 VAS，我们使用`mmap(2)`系统调用。从其签名可以看出，我们首先需要做的是：通过`open(2)`打开要映射的文件（以适当的模式：只读或读写，取决于您想要做什么），从而获得文件描述符；将此描述符作为第五个参数传递给`mmap(2)`。要映射到进程 VAS 的文件区域可以分别通过第六个和第二个参数指定——映射应该从哪个文件`offset`开始以及`length`（以字节为单位）。

第一个参数`addr`是对内核的提示，指示在进程 VAS 中应该创建映射的位置；建议在这里传递`0`（NULL），允许操作系统决定新映射的位置。这是使用`mmap(2)`的正确可移植方式；然而，一些应用程序（是的，一些恶意的安全黑客也是如此！）使用此参数来尝试预测映射将发生的位置。无论如何，映射在进程 VAS 中创建的实际（虚拟）地址是`mmap(2)`的返回值；NULL 返回表示失败，必须进行检查。

这是一个有趣的技术，用于修复映射的位置：首先执行所需映射大小的`malloc(3)`，并将此`malloc(3)`的返回值传递给`mmap(2)`的第一个参数（还要设置 flags 参数以包括 MAP_FIXED 位）！如果长度超过 MMAP_THRESHOLD（默认为 128 KB）并且大小是系统页面大小的倍数，则这可能有效。再次注意，这种技术不具有可移植性，可能有效也可能无效。

另一个要注意的是，大多数映射（始终是文件映射）都是以页面大小的倍数进行的；因此，返回地址通常是页面对齐的。

`mmap(2)`的第三个参数是一个整数位掩码`prot`——给定区域的内存保护（回想一下我们已经在第四章的*Dynamic Memory Allocation*中的*Memory protection*部分遇到的内存保护）。`prot`参数是一个位掩码，可以是只有`PROT_NONE`位（意味着没有权限）或其余位的按位或；这个表列举了位及其含义：

| **保护位** | **含义** |
| --- | --- |
| `PROT_NONE` | 页面上不允许访问 |
| `PROT_READ` 读取页面允许 |
| `PROT_WRITE` | 页面上允许写入 |
| `PROT_EXEC` | 页面上允许执行访问 |

mmap(2)保护位

页面的保护必须与文件的`open(2)`相匹配。还要注意，在旧的 x86 系统上，可写内存意味着可读内存（即`PROT_WRITE => PROT_READ`）。这不再适用；必须明确指定映射的页面是否可读（可执行页面也是如此：必须指定，文本段是典型示例）。为什么要使用`PROT_NONE`？一个现实的例子是*guard page*（回想一下第十四章的*Stack guards*部分，*使用 Pthreads 的多线程 Part I - Essentials*）。

# 文件和匿名映射

下一个要理解的要点是，有广泛两种类型的映射；文件映射区域或匿名区域。文件映射区域很明显地映射了文件的（全部或部分）内容（如前面的图所示）。我们认为该区域由文件支持；也就是说，如果操作系统内存不足并决定回收一些文件映射的页面，它不需要将它们写入交换分区——它们已经在映射的文件中可用。另一方面，匿名映射是内容动态的映射；初始化数据段、BSS、堆的数据段，库映射的数据部分以及进程（或线程）的堆栈都是匿名映射的绝佳例子。将它们视为没有文件支持；因此，如果内存不足，它们的页面可能确实被操作系统写入交换分区。还要记得我们在第四章中学到的关于`malloc(3)`的内容；事实上，glibc 的`malloc(3)`引擎仅在分配小额时（默认为 128 KB 以下）才使用堆段来提供分配。超过这个值的任何`malloc(3)`都将导致内部调用`mmap(2)`来设置所需大小的匿名内存区域——映射！这些映射（或段）将存在于堆的顶部和主栈之间的可用虚拟地址空间中。

回到`mmap(2)`：第四个参数是一个称为`flags`的位掩码；有几个标志，它们影响映射的许多属性。其中，两个标志确定了映射的私密性，并且彼此互斥（一次只能使用其中任何一个）：

+   MAP_SHARED：映射是共享的；其他进程可能同时在同一映射上工作（实际上，这是实现常见 IPC 机制——共享内存的通用方式）。在文件映射的情况下，如果对内存区域进行写入，底层文件将被更新！（您可以使用`msync(2)`来控制将内存中的写入刷新到底层文件。）

+   MAP_PRIVATE：这设置了一个私有映射；如果可写，它意味着 COW 语义（导致最佳内存使用，如第十章中所解释的，*进程创建*）。私有的文件映射区域不会将写入传递到底层文件。实际上，在 Linux 上私有文件映射是非常常见的：这正是在开始执行进程时，加载器（见信息框）如何将二进制可执行文件的文本和数据以及进程使用的所有共享库的文本和数据带入的方式。

事实上，当一个进程运行时，控制首先转到嵌入到您的`a.out`二进制可执行文件中的程序——加载器（`ld.so`或`ld-linux[-*].so`）。它执行设置 C 运行时环境的关键工作：它通过`mmap(2)`将二进制可执行文件中的文本（代码）和初始化数据段映射到进程中，从而在 VAS 中创建我们自从第二章以来一直在谈论的段。此外，它设置了初始化数据段、BSS、堆和`main()`的栈，然后寻找并将所有共享库内存映射到进程 VAS 中。

尝试对程序执行`strace(1)`；您将看到（在执行早期）所有`mmap(2)`系统调用设置进程 VAS！`mmap(2)`对 Linux 至关重要：实际上，进程 VAS 的整个设置，包括进程启动时和以后的段或映射，都是通过`mmap(2)`系统调用完成的。

为了帮助读者清楚这些重要事实，我们展示了运行`strace(1)`对`ls(1)`的（截断的）输出；（例如）看看`open(2)`是如何在 glibc 上执行的，返回文件描述符 3，然后`mmap(2)`使用它创建 glibc 代码的私有文件映射只读映射（我们可以通过看到第一个`mmap`中的偏移量为`0`来判断）。`strace(1)`（截断的）输出如下：

```
$ strace -e trace=openat,mmap ls > /dev/null
...
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3 
mmap(NULL, 4131552, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f963d8a5000
mmap(0x7f963dc8c000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e7000) = 0x7f963dc8c000
...
```

内核为每个进程的每个这样的映射维护一个称为**虚拟内存区域**（**VMA**）的数据结构；proc 文件系统通过`/proc/PID/maps`向我们展示所有映射。请看一下；您将在进程用户空间中实际看到虚拟内存映射。（尝试`sudo cat /proc/self/maps`查看 cat 进程本身的映射。）`proc(5)`手册详细解释了如何解释这个映射；请查看。

# mmap 优势

现在我们了解了如何使用`mmap(2)`系统调用，我们重新讨论了之前的讨论：回想一下，使用`read(2)`/`write(2)`甚至 SG-I/O 类型的 API（`[p]readv|writev2`）会导致双重拷贝；内存浪费（还有 CPU 缓存也会被清空）。

理解`mmap(2)`如此有效地解决这个严重问题的关键在于：`mmap(2)`通过内部映射包含文件数据（从存储设备中读取的数据）的内核页缓存页面，直接映射到进程虚拟地址空间。这个图表（*图 3*）将这一点放入了透视图中（并使其不言自明）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/17d428b0-e611-49dc-9c50-908fa2bc0d98.png)

图 3：页面缓存填充

磁盘数据

映射不是复制；因此，基于`mmap(2)`的文件 I/O 被称为零拷贝技术：一种在内核的页面缓存中维护的 I/O 缓冲区上执行工作的方式；不需要更多的拷贝。

事实上，设备驱动程序作者寻求使用零拷贝技术优化其数据路径，其中`mmap(2)`当然是一个候选者。在 GitHub 存储库的*进一步阅读*部分提供了有关这个有趣的高级主题的更多信息。

`mmap(2)`在设置映射时确实会产生显著的开销（第一次），但一旦完成，I/O 速度非常快，因为它基本上是在内存中执行的。想想看：要在文件中寻找位置并在那里执行 I/O，只需使用常规的'C'代码从`mmap(2)`的返回值（它只是一个指针偏移量）移动到给定位置，并在内存中进行 I/O 工作（通过`memcpy(3)`、`s[n]printf(3)`或您喜欢的其他方法）；完全没有`lseek(2)`、`read(2)`/`write(2)`或 SG-I/O 系统调用开销。对于非常小的 I/O 工作量，使用`mmap(2)`可能不是最佳选择；建议在指示大量和连续的 I/O 工作负载时使用它。

# 代码示例

为了帮助读者使用`mmap(2)`进行文件 I/O，我们提供了一个简单应用程序的代码；它通过`mmap(2)`内存映射给定文件（文件路径名、起始偏移量和长度作为参数提供），并将指定的内存区域的十六进制转储（使用略微增强的开源`hexdump`函数）到`stdout`。我们敦促读者查看代码，构建并尝试运行它。

本书的完整源代码可以从 GitHub 克隆到这里：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。前述程序在源代码树中的位置是：`ch18/mmap_file_simple.c`。

# 内存映射-额外要点

以下是一些额外要点的快速总结，以结束内存映射的讨论：

+   `mmap(2)`的第四个参数`flags`可以采用其他几个（非常有趣的）值；我们建议读者查阅`mmap(2)`的 man 页面以浏览这些值：[`man7.org/linux/man-pages/man2/mmap.2.html`](http://man7.org/linux/man-pages/man2/mmap.2.html)。

+   与我们可以通过`posix_fadvise(2)`API 向内核提供关于内核页缓存页面的提示或建议类似，您可以通过`posix_madvise(3)`库 API 向内核提供关于给定内存范围的内存使用模式的类似提示或建议（提供起始地址、长度）。建议值包括能够说我们期望对数据进行随机访问（从而通过`POSIX_MADV_RANDOM`位减少预读取），或者我们期望很快访问指定范围内的数据（通过`POSIX_MADV_WILLNEED`位，导致更多的预读取和映射）。此例程在 Linux 上调用底层系统调用`madvise(2)`。

+   假设我们已经将文件的某个区域映射到我们的进程地址空间中；我们如何知道映射的哪些页面当前驻留在内核页（或缓冲）缓存中？可以通过`mincore(2)`系统调用（读作“m-in-core”）精确确定这一点。

+   程序员可以通过`msync(2)`系统调用显式（和精细调整的）控制同步（刷新）文件映射区域（返回到文件）。

+   完成后，应通过`munmap(2)`系统调用取消内存映射；参数是映射的基地址（从`mmap(2)`返回的值）和长度。如果进程终止，映射将被隐式取消。

+   在`fork(2)`中，内存映射被子进程继承。

+   如果映射了一个巨大的文件，并且在运行时分配页面帧以在进程 VAS 中保存映射时，系统耗尽了内存（这是极端的，但可能发生）；在这种情况下，进程将收到`SIGSEGV`信号（因此，这取决于应用程序的信号处理能力是否能够优雅地终止）。

# DIO 和 AIO

使用阻塞的`[p]readv` / `[p]writev` API 以及`mmap(2)`（实际上更多地是使用`mmap`）的一个重要缺点是：它们依赖于内核页缓存始终填充有文件的页面（它正在处理或映射）。如果不是这种情况——当数据存储远大于 RAM 大小时（也就是说，文件可能非常庞大）——它将导致内核**内存管理**（**mm**）代码进行大量的元工作，从磁盘中带入页面到页缓存，分配帧，为它们编制页表条目等等。因此，当 RAM 与存储的比率尽可能接近 1:1 时，`mmap`技术效果最好。当存储大小远大于 RAM 时（通常是数据库、云虚拟化等大规模软件的情况），它可能会因为所有元工作而导致延迟，再加上大量的内存将用于分页元数据。

两种 I/O 技术——DIO 和 AIO——缓解了这些问题（以复杂性为代价）；我们接下来简要介绍它们。（由于空间限制，我们将重点放在这些主题的概念方面；学习使用相关 API 实际上是一个相对容易的任务。请参考 GitHub 存储库上的*进一步阅读*部分。）

# 直接 I/O（DIO）

一个有趣的 I/O 技术是**直接 I/O**（**DIO**）；要使用它，在通过`open(2)`系统调用打开文件时指定`O_DIRECT`标志。

使用 DIO，内核页缓存完全被绕过，因此立即获得了使用`mmap`技术可能面临的所有问题的好处。另一方面，这意味着整个缓存管理完全由用户空间应用程序处理（像数据库这样的大型项目肯定需要缓存！）。对于没有特殊 I/O 要求的常规小型应用程序，使用 DIO 可能会降低性能；要小心，对工作负载进行压力测试，并确定是否使用 DIO 或跳过它。

传统上，内核处理哪些 I/O 请求在何时服务——换句话说，I/O 调度（虽然与此不直接相关，但也请参阅*I/O 调度器*部分）。使用 DIO（以及接下来要介绍的 AIO），应用程序开发人员可以基本上接管 I/O 调度，决定何时执行 I/O。这既是一种福音，也是一种诅咒：它为（复杂的）应用程序开发人员提供了灵活性，可以设计和实现 I/O 调度，但这并不是一件容易做好的事情；像往常一样，这是一种权衡。

此外，你应该意识到，尽管我们称 I/O 路径是直接的，但这并不保证写入会立即刷新到底层存储介质；这是一个单独的特性，可以通过在`open(2)`中指定`O_SYNC`标志或显式刷新（通过`[f]sync(2)`系统调用）来请求。

# 异步 I/O（AIO）

异步 I/O（AIO）是 Linux 实现的一种现代高性能的异步非阻塞 I/O 技术。想象一下：非阻塞和异步意味着应用程序线程可以发出读取（文件或网络数据）的请求；用户模式 API 立即返回；I/O 在内核中排队；应用程序线程可以继续在 CPU 密集型任务上工作；一旦 I/O 请求完成，内核通知线程读取已准备就绪；然后线程实际执行读取操作。这是高性能的——应用程序不会在 I/O 上保持阻塞，而是可以在 I/O 请求处理时执行有用的工作；不仅如此，当 I/O 工作完成时，它还会异步通知应用程序。

使用 AIO，一个线程可以同时启动多个 I/O 传输；每个传输都需要一个上下文——称为*[a]iocb*——即异步 I/O 控制块数据结构（Linux 将该结构称为 iocb，POSIX AIO 框架（一个包装库）将其称为 aiocb）。[a]iocb 结构包含文件描述符、数据缓冲区、异步事件通知结构`sigevent`等。细心的读者会记得，我们已经在第十三章的*定时器*部分中使用了这个强大的`sigevent`结构，在*创建和使用 POSIX（间隔）定时器*部分。实际上，正是通过这个`sigevent`结构实现了异步通知机制（我们在第十三章的*定时器*中使用它，以异步通知我们的定时器已过期；这是通过将`sigevent.sigev_notify`设置为值`SIGEV_SIGNAL`来实现的，从而在定时器到期时接收信号）。Linux 为应用程序开发人员暴露了五个系统调用来利用 AIO；它们分别是：`io_setup(2)`、`io_submit(2)`、`io_cancel(2)`、`io_getevents(2)`和`io_destroy(2)`。

AIO 包装器 API 由两个库提供-libaio 和 librt（与 glibc 一起发布）；您可以使用它们的包装器，最终会调用系统调用。还有 POSIX AIO 包装器；请参阅`aio(7)`的手册页，了解如何使用它以及示例代码。（还可以在 GitHub 存储库的*进一步阅读*部分中查看更多详细信息和示例代码的文章。）

# I/O 技术-快速比较

以下表格提供了我们所见过的四到五种 Linux I/O 技术之间一些更显著的比较要点的快速比较，即：阻塞`read(2)`/`write(2)`（以及 SG-I/O/定位`[p]readv`/`[p]writev`），内存映射，非阻塞（大部分同步）DIO 和非阻塞异步 AIO：

| **I/O 类型** | **API** | **优点** | **缺点** |
| --- | --- | --- | --- |
| 阻塞（常规和 SG-IO / 定位） | `[p]readv`/`[p]writev` | 易于使用 | 慢；数据缓冲区的双重拷贝 |
| 内存映射 | `mmap(2)` | （相对）易于使用；快速（内存 I/O）；数据的单次拷贝（零拷贝技术）；当 RAM:Storage :: ~ 1:1 时效果最佳 | 当 RAM: Storage 比例为 1:N（N>>1）时，需要大量 MMU（高页表开销，元工作） |
| DIO（非阻塞，大部分同步） | 带有`O_DIRECT`标志的`open(2)` | 零拷贝技术；对页面缓存没有影响；对缓存有控制；对 I/O 调度有一定控制 | 设置和使用相对复杂：应用程序必须执行自己的缓存 |
| AIO（非阻塞，异步） | <各种：参见 aio(7)-POSIX AIO，Linux `io_*(2)`等> | 真正的异步和非阻塞-适用于高性能应用程序；零拷贝技术；对页面缓存没有影响；完全控制缓存、I/O 和线程调度 | 设置和使用复杂 |

Linux I/O 技术-快速比较

在 GitHub 存储库的*进一步阅读*部分，我们提供了两篇博客文章的链接（来自两个真实世界的产品：Scylla，一个现代高性能的分布式 No SQL 数据存储，以及 NGINX，一个现代高性能的 Web 服务器），深入讨论了这些替代强大的 I/O 技术（AIO，线程池）在（各自的）真实世界产品中的使用方式；一定要看一看。

# 多路复用或异步阻塞 I/O-简要说明

您经常听说强大的多路复用 I/O API-`select(2)`，`poll(2)`，以及最近的 Linux 强大的`epoll(7)`框架。这些 API，`select(2)`，`poll(2)`，和/或`epoll(7)`，提供了所谓的异步阻塞 I/O。它们在保持 I/O 阻塞的描述符上工作良好；例如套接字，Unix 和 Internet 域，以及管道-无名管道和命名管道（FIFO）。

这些 I/O 技术是异步的（您可以发出系统调用并立即返回），但实际上它们仍然是阻塞的，因为线程必须检查 I/O 完成，例如通过使用`poll(2)`与`read(2)`系统调用配合使用，这仍然是一个阻塞操作。

这些 API 对于网络 I/O 操作非常有用，典型的例子是繁忙的（Web）服务器监视数百（甚至数千）个连接。首先，每个连接由套接字描述符表示，使用`select(2)`或`poll(2)`系统调用非常吸引人。然而，事实是`select(2)`已经过时且受限（最多 1,024 个描述符；不够）；其次，`select(2)`和`poll(2)`的内部实现具有 O(n)的算法时间复杂度，这使它们不可扩展。`epoll(7)`的实现没有（理论上的）描述符限制，并使用 O(1)算法以及所谓的边缘触发通知。这张表总结了这些要点。

| **API** | **算法时间复杂度** | **最大客户端数** |
| --- | --- | --- |
| `select(2)` | O(n) | FD_SETSIZE（1024） |
| `poll(2)` | O(n) | （理论上）无限 |
| `epoll(7)` API | O(1) | （理论上）无限 |

Linux 异步阻塞 API

这些特性使得`epoll(7)`一组 API（`epoll_create(2)`、`epoll_ctl(2)`、`epoll_wait(2)`和`epoll_pwait(2)`）成为实现网络应用程序上非阻塞 I/O 的首选，这些应用程序需要非常高的可扩展性。（在 GitHub 存储库的*进一步阅读*部分中，有一篇博客文章提供了有关在 Linux 上使用多路复用 I/O，包括 epoll 的更多详细信息的链接。）

# I/O – 其他

以下是本章的一些其他杂项主题。

# Linux 的 inotify 框架

尽管对于网络 I/O 非常出色，这些多路复用 API 在理论上可以用于监视常规文件描述符，但它们将简单地报告这些描述符始终准备就绪（用于读取、写入或发生错误条件），从而降低了它们的实用性（当用于常规文件时）。

也许 Linux 的 inotify 框架，一种监视文件系统事件（包括单个文件上的事件）的方法，可能是你正在寻找的。inotify 框架提供以下系统调用来帮助开发人员监视文件：`inotify_init(2)`、`inotify_add_watch(2)`（随后可以`read(2)`），然后`inotify_rm_watch(2)`。查看`inotify(7)`的手册页面以获取更多详细信息：[`man7.org/linux/man-pages/man7/inotify.7.html`](http://man7.org/linux/man-pages/man7/inotify.7.html)。

# I/O 调度程序

Linux I/O 堆栈中的一个重要特性是内核块层的一部分，称为 I/O 调度程序。这里要解决的问题基本上是：内核不断地发出 I/O 请求（因为应用程序希望执行各种文件数据/代码读取和写入）；这导致块驱动程序最终接收和处理连续的 I/O 请求流。内核人员知道 I/O 影响性能的主要原因之一是典型 SCSI 磁盘的物理搜索速度非常慢（与硅速度相比；是的，当然，SSD（固态设备）现在使这变得更加可接受）。

因此，如果我们可以使用一些智能来对块 I/O 请求进行排序，以使其在底层物理介质方面最有意义，这将有助于性能。想象一下建筑物中的电梯：它使用一种排序算法，以最佳方式在穿越各个楼层时搭载和卸载人员。这基本上是操作系统 I/O 调度程序试图做的事情；事实上，第一个实现被称为 Linus 的电梯。

存在各种 I/O 调度程序算法（截止时间、完全公平队列（cfq）、noop、预期调度程序：这些现在被认为是传统的；截至撰写本文时，最新的似乎是 mq-deadline 和预算公平队列（bfq）I/O 调度程序，bfq 对于重型或轻型 I/O 工作负载看起来非常有前途（bfq 是最近的添加，内核版本为 4.16）。您的 Linux 操作系统中存在的 I/O 调度程序是一个内核特性；您可以检查它们是哪些以及正在使用哪个；在我的 Ubuntu 18.04 x86_64 系统上进行了演示：

```
$ cat /sys/block/sda/queue/scheduler 
noop deadline [cfq] 
$ 
```

在我的 Fedora 28 系统上正在使用的 I/O 调度程序是`bfq`（使用了更近期的内核）：

```
$ cat /sys/block/sda/queue/scheduler 
mq-deadline [bfq] none
$ 
```

这里的默认 I/O 调度程序是`bfq`。有趣的是：用户实际上可以在 I/O 调度程序之间进行选择，运行他们的 I/O 压力工作负载和/或基准测试，并查看哪个产生了最大的好处！如何？要在引导时选择 I/O 调度程序，请通过内核参数传递（通常是 GRUB 在基于 x86 的笔记本电脑、台式机或服务器系统上，嵌入式 Linux 上是 U-Boot）；所涉及的参数作为`elevator=<iosched-name>`传递；例如，要将 I/O 调度程序设置为 noop（对于可能使用 SSD 的系统有用），将参数传递给内核为`elevator=noop`。

有一个更简单的方法可以立即在运行时更改 I/O 调度程序；只需将所需的调度程序写入伪文件中；例如，要将 I/O 调度程序更改为`mq-deadline`，请执行以下操作：

```
# echo mq-deadline > /sys/block/sda/queue/scheduler 
# cat /sys/block/sda/queue/scheduler 
[mq-deadline] bfq none
# 
```

现在，您可以对不同的 I/O 调度程序进行（压力）测试，从而决定哪种对您的工作负载产生最佳性能。

# 确保有足够的磁盘空间

Linux 提供了`posix_fallocate(3)` API；它的作用是保证给定文件的特定范围内有足够的磁盘空间。这实际上意味着每当应用程序在该范围内写入该文件时，由于磁盘空间不足而导致写入失败是被保证不会发生的（如果失败，`errno`将被设置为 ENOSPC；这不会发生）。它的签名如下：

```
#include <fcntl.h>
int posix_fallocate(int fd, off_t offset, off_t len);
```

以下是关于此 API 的一些要点：

+   文件是由描述符`fd`引用的文件。

+   范围是从`offset`开始，长度为`len`字节；实际上，这是将为文件保留的磁盘空间。

+   如果当前文件大小小于范围请求（即`offset`+`len`），则文件将增长到这个大小；否则，文件的大小保持不变。

+   `posix_fallocate(3)`是对底层系统调用`fallocate(2)`的可移植包装。

+   为了使此 API 成功，底层文件系统必须支持`fallocate`；如果不支持，则会进行模拟（但有很多警告和问题；请参阅手册页以了解更多）。

+   此外，还存在一个名为`fallocate(1)`的 CLI 实用程序，可以从 shell 脚本中执行相同的任务。

这些 API 和工具可能对诸如备份、云提供、数字化等软件非常有用，确保在长时间 I/O 操作开始之前有足够的磁盘空间可用。

# 用于 I/O 监控、分析和带宽控制的实用程序

这张表总结了各种实用程序、API、工具，甚至包括 cgroup blkio 控制器；这些工具/功能在监视、分析（以确定 I/O 瓶颈）和分配 I/O 带宽（通过`ioprio_set(2)`和强大的 cgroups blkio 控制器）方面将非常有用。

| **实用程序名称** | **功能** |
| --- | --- |
| `iostat(1)` | 监控 I/O 并显示有关设备和存储设备分区的 I/O 统计信息。从`iostat(1)`的手册页上：`iostat`命令用于通过观察设备活动时间与其平均传输速率的关系来监视系统输入/输出设备的负载。`iostat`命令生成的报告可用于更好地平衡物理磁盘之间的输入/输出负载，从而改变系统配置。 |
| `iotop(1)` | 类似于`top(1)`（用于 CPU），iotop 不断显示按其 I/O 使用情况排序的线程。必须以 root 身份运行。 |
| `ioprio_get&#124;set` | 用于查询和设置给定线程的 I/O 调度类和优先级的系统调用；有关详细信息，请参阅手册页面：[`man7.org/linux/man-pages/man2/ioprio_set.2.html`](http://man7.org/linux/man-pages/man2/ioprio_set.2.html)；也可以查看其包装实用程序`ionice(1)`。 |
| perf-tools | 在这些工具（来自 B Gregg）中有`iosnoop-perf(1)`和`iolatecy-perf(1)`，分别用于窥探 I/O 事务和观察 I/O 延迟。从这里的 GitHub 存储库安装这些工具：[`github.com/brendangregg/perf-tools`](https://github.com/brendangregg/perf-tools)。 |
| cgroup blkio 控制器 | 使用强大的 Linux cgroup 的 blkio 控制器以任何所需的方式限制进程或一组进程的 I/O 带宽（在云环境中广泛使用，包括 Docker）；请在 GitHub 存储库的*进一步阅读*部分中查看相关链接。 |

用于 I/O 监控、分析和带宽控制的工具/实用程序/API/cgroups

注意：前面提到的实用程序可能不会默认安装在 Linux 系统上；（显然）安装它们以尝试它们。

还要查看 Brendan Gregg 的出色的 Linux 性能博客页面和工具（其中包括 perf-tools、iosnoop 和 iosnoop 延迟热图）；请在 GitHub 存储库的*进一步阅读*部分中找到相关链接。

# 总结

在本章中，我们学习了处理文件时确保 I/O 性能尽可能高的强大方法，因为在许多真实世界的工作负载中，I/O 确实是性能瓶颈。这些技术包括向操作系统传递文件访问模式建议、SG-I/O 技术和 API、文件 I/O 的内存映射、DIO、AIO 等等。

书中的下一章简要介绍了守护进程；它们是什么以及如何设置。请查看这一章节：[`www.packtpub.com/sites/default/files/downloads/Daemon_Processes.pdf`](https://www.packtpub.com/sites/default/files/downloads/Daemon_Processes.pdf)。
