# Spring5 高性能实用指南（四）

> 原文：[`zh.annas-archive.org/md5/40194AF6586468BFD8652280B650BA1F`](https://zh.annas-archive.org/md5/40194AF6586468BFD8652280B650BA1F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：JVM 内部

上一章让我们了解了如何通过理解性能问题的症状来调整应用程序的性能。我们走过了性能调整生命周期，学习了在应用程序性能的哪些阶段可以进行调整以及如何进行调整。我们还学会了如何将 JMX 连接到 Spring 应用程序，观察应用程序的瓶颈并进行调整。

在本章中，我们将深入了解**Java 虚拟机**（**JVM**）的内部和调整 JVM 以实现高性能。JVM 执行两项主要工作——执行代码和管理内存。JVM 从操作系统分配内存，管理堆压缩，并对未引用的对象执行**垃圾回收**（**GC**）。GC 很重要，因为适当的 GC 可以改善应用程序的内存管理和性能。

本章我们将学习以下主题：

+   理解 JVM 内部

+   理解内存泄漏

+   常见陷阱

+   GC

+   GC 方法和策略

+   分析 GC 日志的工具

# 理解 JVM 内部

作为 Java 开发人员，我们知道 Java 字节码在**Java 运行环境**（**JRE**）中运行，而 JRE 最重要的部分是 JVM，它分析并执行 Java 字节码。当我们创建一个 Java 程序并编译它时，结果是一个扩展名为`.class`的文件。它包含 Java 字节码。JVM 将 Java 字节码转换为在我们运行应用程序的硬件平台上执行的机器指令。当 JVM 运行程序时，它需要内存来存储来自加载的类文件、实例化对象、方法参数、返回值、局部变量和计算的中间结果的字节码和其他信息。JVM 将它需要的内存组织成几个运行时数据区域。

JVM 由三部分组成：

+   类加载器子系统

+   内存区域

+   执行引擎

以下图表说明了高级 JVM 架构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/cfada67e-a629-4d24-a687-572f75805824.jpg)

JVM 架构

让我们简要了解一下图表中我们看到的 JVM 的三个不同部分。

# 类加载器子系统

类加载器子系统的责任不仅仅是定位和导入类的二进制数据。它还验证导入的类是否正确，为类变量分配和初始化内存，并协助解析符号引用。这些活动按严格顺序执行：

1.  **加载**：类加载器读取`.class`文件并查找和导入类型的二进制数据。

1.  **链接**：它执行验证、准备和（可选）解析：

+   **验证**：确保导入类型的正确性

+   **准备**：为类变量分配内存并将内存初始化为默认值

+   **解析**：将类型的符号引用转换为直接引用

1.  **初始化**：为代码中定义的所有静态变量分配值并执行静态块（如果有）。执行顺序是从类的顶部到底部，从类层次结构的父类到子类。

一般来说，有三个类加载器：

+   **引导类加载器**：这加载位于`JAVA_HOME/jre/lib`目录中的核心可信 Java API 类。这些 Java API 是用本地语言（如 C 或 C++）实现的。

+   **扩展类加载器**：这继承自引导类加载器。它从`JAVA_HOME/jre/lib/ext`目录或`java.ext.dirs`系统属性指定的任何其他目录加载类。它是由`sun.misc.Launcher$ExtClassLoader`类以 Java 实现的。

+   **系统类加载器**：这继承自扩展类加载器。它从我们应用程序的类路径加载类。它使用`java.class.path`环境变量。

为了加载类，JVM 遵循委托层次原则。系统类加载器将请求委托给扩展类加载器，扩展类加载器将请求委托给引导类加载器。如果在引导路径中找到类，则加载该类，否则将请求转移到扩展类加载器，然后再转移到系统类加载器。最后，如果系统类加载器无法加载类，则会生成`java.lang.ClassNotFoundException`异常。

以下图表说明了委托层次原则：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/a69d9611-b82a-41b5-a33b-4395f6b52766.jpg)

委托层次原则

# 内存区域

Java 运行时内存分为五个不同的区域，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/0e01a252-cd4f-468e-af57-7d81a78d933a.jpg)

内存区域

让我们简要描述每个组件：

+   **方法区**：这包含所有类级别的信息，如类名、父类、方法、实例和静态变量。每个 JVM 只有一个方法区，它是一个共享资源。

+   **堆区**：这包含所有对象的信息。每个 JVM 有一个**堆区**。它也是一个共享资源。由于**方法区**和**堆区**是多个线程之间的共享内存，所以存储的数据不是线程安全的。

+   **栈内存**：JVM 为每个正在执行的线程创建一个运行时栈，并将其存储在栈区。这个栈的每个块被称为一个**激活记录**，用于存储方法调用。该方法的所有局部变量都存储在相应的帧中。栈区是线程安全的，因为它不是共享资源。运行时栈将在线程终止时由 JVM 销毁。因此，在方法调用的无限循环中，我们可能会看到`StackOverFlowError`，这是由于栈中没有足够的内存来存储方法调用。

+   **PC 寄存器**：这些保存正在执行的当前指令的地址。一旦指令执行完毕，**PC 寄存器**将被更新为下一条指令。每个线程有一个单独的**PC 寄存器**。

+   **本地方法栈**：为每个线程创建一个单独的本地栈。它存储本地方法信息。本地信息就是本地方法调用。

# 执行引擎

执行引擎在运行时数据区域执行字节码。它逐行执行字节码，并使用运行时数据区域中可用的信息。执行引擎可以分为三部分：

+   **解释器**：这逐行读取、解释和执行字节码。它快速解释和执行字节码；然而，在执行解释结果时可能非常缓慢。

+   **即时（JIT）**：为了克服解释器在执行解释结果时的缓慢，即时编译器在解释器第一次解释代码后将字节码转换为本机代码。使用本机代码执行速度快；它逐条执行指令。

+   垃圾收集器：这会销毁任何没有被引用的东西。这非常重要，因此任何不需要的东西都将被销毁，以便为新的执行腾出空间。

# 理解内存泄漏

Java 的最大好处是 JVM，它提供了开箱即用的内存管理。我们可以创建对象，Java 的垃圾收集器会帮我们释放内存。然而，在 Java 应用程序中会发生内存泄漏。在接下来的部分中，我们将看到一些内存泄漏的常见原因，并介绍一些检测/避免它们的解决方案。

# Java 中的内存泄漏

当垃圾收集器无法收集应用程序不再使用/引用的对象时，就会发生内存泄漏。如果对象没有被垃圾收集，应用程序将使用更多内存，一旦整个堆区满了，对象就无法分配，导致`OutOfMemoryError`。

堆内存有两种对象——被引用的对象和未被引用的对象。垃圾回收器会移除所有未被引用的对象。然而，垃圾回收器无法移除被引用的对象，即使它们没有被应用程序使用。

# 内存泄漏的常见原因

以下是内存泄漏的最常见原因：

+   打开流：在处理流和读取器时，我们经常忘记关闭流，最终导致内存泄漏。未关闭流导致两种类型的泄漏——低级资源泄漏和内存泄漏。低级资源泄漏包括操作系统级资源，如文件描述符和打开连接。由于 JVM 消耗内存来跟踪这些资源，这导致内存泄漏。为了避免泄漏，使用`finally`块关闭流，或者使用 Java 8 的自动关闭功能。

+   打开的连接：我们经常忘记关闭已打开的 HTTP、数据库或 FTP 连接，这会导致内存泄漏。与关闭流类似，要关闭连接。

+   静态变量引用实例对象：任何引用重对象的静态变量都可能导致内存泄漏，因为即使变量没有被使用，它也不会被垃圾回收。为了防止这种情况发生，尽量不要使用重的静态变量，而是使用局部变量。

+   集合中对象缺少方法：向`HashSet`中添加没有实现`equals`和`hashcode`方法的对象会增加`HashSet`中重复对象的数量，一旦添加就无法移除这些对象。为了避免这种情况，在添加到`HashSet`中的对象中实现`equals`和`hashcode`方法。

诊断内存泄漏是一个需要大量实际经验、调试技能和对应用程序的详细了解的漫长过程。以下是诊断内存泄漏的方法：

+   启用 GC 日志并调整 GC 参数

+   性能分析

+   代码审查

在接下来的部分中，我们将看到 GC 的常见陷阱、GC 方法和分析 GC 日志的工具。

# 常见陷阱

性能调优至关重要，只需一个小的 JVM 标志，事情就可能变得复杂。JVM 会出现 GC 暂停，频率和持续时间各不相同。在暂停期间，一切都会停止，各种意外行为开始出现。在暂停和不稳定行为的情况下，JVM 被卡住，性能受到影响。我们可以看到响应时间变慢、CPU 和内存利用率高，或者系统大部分时间表现正常，但偶尔出现异常行为，比如执行极慢的事务和断开连接。

大部分时间我们测量平均事务时间，忽略导致不稳定行为的异常值。大部分时间系统表现正常，但在某些时刻，系统响应性下降。这种低性能的原因大部分是由于对 GC 开销的低意识和只关注平均响应时间。

在定义性能要求时，我们需要回答一个重要问题：与 GC 暂停频率和持续时间相关的应用程序的可接受标准是什么？要求因应用程序而异，因此根据我们的应用程序和用户体验，我们需要首先定义这些标准。

我们通常存在一些常见的误解。

# 垃圾回收器的数量

大多数时候，人们并不知道不只有一个，而是四个垃圾收集器。这四个垃圾收集器是——**串行**，**并行**，**并发**和**垃圾优先**（**G1**）。我们将在下一节中看到它们。还有一些第三方垃圾收集器，比如**Shenandoah**。JVM HotSpot 的默认垃圾收集器在 Java 8 之前是并行的，而从 Java 9 开始，默认收集器是**垃圾优先垃圾收集器**（**G1 GC**）。并行垃圾收集器并不总是最好的；然而，这取决于我们的应用程序需求。例如，**并发标记清除**（**CMS**）和 G1 收集器导致 GC 暂停的频率较低。但是当它们导致暂停时，暂停持续时间很可能比并行收集器导致的暂停时间长。另一方面，对于相同的堆大小，并行收集器通常能实现更高的吞吐量。

# 错误的垃圾收集器

GC 问题的一个常见原因是选择了错误的垃圾收集器。每个收集器都有其自己的重要性和好处。我们需要找出我们应用程序的行为和优先级，然后根据这些来选择正确的垃圾收集器。HotSpot 的默认垃圾收集器是并行/吞吐量，大多数情况下并不是一个好选择。CMS 和 G1 收集器是并发的，导致暂停的频率较低，但当暂停发生时，其持续时间比并行收集器长。因此，选择收集器是我们经常犯的一个常见错误。

# 并行/并发关键字

GC 可能会导致**全局停顿**（**STW**）的情况，或者对象可以在不停止应用程序的情况下并发收集。GC 算法可以在单线程或多线程中执行。因此，并发 GC 并不意味着它是并行执行的，而串行 GC 并不意味着它由于串行执行而导致更多的暂停。并发和并行是不同的，其中并发表示 GC 周期，而并行表示 GC 算法。

# G1 是一个问题解决者

随着 Java 7 引入新的垃圾收集器，许多人认为它是解决以前所有垃圾收集器问题的问题解决者。G1 GC 解决的一个重要问题是碎片问题，这是 CMS 收集器常见的问题。然而，在许多情况下，其他收集器可能会胜过 G1 GC。因此，一切取决于我们应用程序的行为和需求。

# 平均事务时间

大多数情况下，在测试性能时，我们倾向于测量平均事务时间，但仅这样做会忽略异常值。当 GC 导致长时间暂停时，应用程序的响应时间会急剧增加，影响用户访问应用程序。这可能会被忽视，因为我们只关注平均事务时间。当 GC 暂停频率增加时，响应时间成为一个严重的问题，我们可能会忽略只测量平均响应时间而忽略的问题。

# 减少新对象分配率可以改善 GC 行为

与其专注于减少新对象分配率，我们应该专注于对象的生命周期。有三种不同类型的对象生命周期：长期对象，我们对它们无能为力；中期对象，这些会导致最大的问题；和短期对象，通常会被快速释放和分配，因此它们会在下一个 GC 周期中被收集。因此，与其专注于长期和短期对象，专注于中期对象的分配率可能会带来积极的结果。问题不仅仅在于对象分配率，而是在于所涉及的对象类型。

# GC 日志会导致开销

GC 日志并不会导致开销，尤其是在默认日志设置中。这些数据非常有价值，Java 7 引入了控制日志文件大小的钩子。如果我们不收集带有时间戳的 GC 日志，那么我们就错过了分析和解决暂停问题的关键数据来源。GC 日志是系统中 GC 状态的最丰富的数据来源。我们可以获得关于应用程序中所有 GC 事件的数据；比如，它是并发完成的还是导致了 STW 暂停：花了多长时间，消耗了多少 CPU，释放了多少内存。通过这些数据，我们将能够了解暂停的频率和持续时间，它们的开销，并采取行动来减少它们。

通过添加以下参数启用 GC：

```java
-XX:+PrintGCDetails -XX:+PrintGCDateStamps -Xloggc:`date +%F_%H-%M-%S`-gc.log -XX:+UseGCLogFileRotation -XX:NumberOfGCLogFiles=10 -XX:GCLogFileSize=10M
```

# GC

Java 最大的成就之一就是 GC。GC 进程自动管理内存和堆分配，跟踪死对象，删除它们，并将内存重新分配给新对象。理论上，由于垃圾收集器自动管理内存，开发人员可以创建新对象而不必考虑内存的分配和释放，以消除内存泄漏和其他与内存相关的问题。

# GC 的工作原理

通常我们认为 GC 收集并删除未引用的对象。相反，Java 中的 GC 跟踪活动对象，并将所有未引用的对象标记为垃圾。

内存的堆区是动态分配对象的地方。在运行应用程序之前，我们应该为 JVM 分配堆内存。提前为 JVM 分配堆会产生一些后果：

+   提高对象创建速率，因为 JVM 不需要与操作系统通信为每个新对象获取内存。一旦 JVM 为对象分配了内存，JVM 就会将指针移向下一个可用内存。

+   当没有对象引用时，垃圾收集器收集对象并重用其内存以分配新对象。由于垃圾收集器不删除对象，因此不会将内存返回给操作系统。

直到对象被引用，JVM 认为它们是活动对象。当一个对象不再被引用并且不可被应用程序代码访问时，垃圾收集器将其删除并回收其内存。我们会想到一个问题，对象树中的第一个引用是谁？让我们看看对象树及其根。

# GC 根

对象的每个树都有一个或多个对象作为根。如果垃圾收集器可以到达根，那么该树是可达的。任何未被 GC 根引用或引用的对象都被视为死对象，垃圾收集器将其删除。

以下是 Java 中不同类型的 GC 根：

+   **局部变量：**Java 方法的变量或参数。

+   **活动线程：**正在运行的线程是一个活动对象。

+   **静态变量：**引用静态变量的类。当垃圾收集器收集类时，它会删除对静态变量的引用。

+   **JNI 引用：**在 JNI 调用期间创建的对象引用。它们保持活动状态，因为 JVM 不知道本地代码对它的引用。

请看下面的图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/659a24ab-1fe8-43dd-a409-8b29f771150d.jpg)

GC 根

# GC 方法和策略

正如我们在前面的部分中学到的，不只有一个，而是四种不同的垃圾收集器。每种都有其自己的优点和缺点。这些收集器共同的一点是它们将托管堆分成不同的段，假设对象的寿命很短，应该很快被移除。让我们看看 GC 的四种不同算法。

# 串行收集器

串行收集器是最简单的 GC 实现，主要设计用于单线程环境和小堆。这种 GC 实现在工作时会冻结所有应用程序线程。因此，在多线程应用程序中使用它并不是一个好主意，比如服务器环境。

要启用串行垃圾收集器，请将`-XX:+UseSerialGC`设置为 VM 参数

# 并行/吞吐量收集器

并行收集器是 JVM 的默认收集器，也被称为吞吐量收集器。顾名思义，这个收集器与串行收集器不同，它使用多线程来管理堆内存。并行垃圾收集器在执行部分或完整的 GC 时仍会冻结所有应用程序线程。如果我们想使用并行垃圾收集器，我们应该指定调优参数，如线程、暂停时间、吞吐量和占用空间。

以下是指定调优参数的参数：

+   线程：`-XX:ParallelGCThreads=<N>`

+   暂停时间：`-XX:MaxGCPauseMillis=<N>`

+   吞吐量：`-XX:GCTimeRatio=<N>`

+   占用空间（最大堆大小）：`-Xmx<N>`

要在我们的应用程序中启用并行垃圾收集器，请设置`-XX:+UseParallelGC`选项。

# CMS 垃圾收集器

CMS 实现使用多个垃圾收集器线程来扫描（标记）可以被移除的未使用对象（清除）。这种垃圾收集器适用于需要短暂 GC 暂停的应用程序，并且在应用程序运行时可以与垃圾收集器共享处理器资源。

CMS 算法只在两种情况下进入 STW 模式：当 Old Generations 中的对象仍然被线程入口点或静态变量引用时，以及当应用程序在 CMS 运行时改变了堆的状态，使算法返回并重新迭代对象树以验证它已标记正确的对象。

使用这个收集器，晋升失败是最大的担忧。晋升失败发生在 Young 和 Old Generations 的对象收集之间发生竞争条件时。如果收集器需要将对象从 Young Generation 晋升到 Old Generation，而没有足够的空间，它必须首先 STW 来创建空间。为了确保在 CMS 收集器的情况下不会发生这种情况，增加 Old Generation 的大小或为收集器分配更多的后台线程来与分配速率竞争。

为了提供高吞吐量，CMS 使用更多的 CPU 来扫描和收集对象。这对于长时间运行的服务器应用程序是有利的，这些应用程序不希望应用程序冻结。因此，如果我们可以分配更多的 CPU 来避免应用程序暂停，我们可以选择 CMS 收集器作为应用程序中的 GC。要启用 CMS 收集器，请设置`-XX:+UseConcMarkSweepGC`选项。

# G1 收集器

这是在 JDK 7 更新 4 中引入的新收集器。G1 收集器设计用于愿意分配超过 4GB 堆内存的应用程序。G1 将堆分成多个区域，跨越从 1MB 到 32MB 的范围，取决于我们配置的堆，并使用多个后台线程来扫描堆区域。将堆分成多个区域的好处是，G1 将首先扫描有大量垃圾的区域，以满足给定的暂停时间。

G1 减少了后台线程完成未使用对象扫描之前低堆可用性的机会。这减少了 STW 的机会。G1 在进行堆压缩时是动态的，而 CMS 是在 STW 期间进行的。

为了在我们的应用程序中启用 G1 垃圾收集器，我们需要在 JVM 参数中设置`-XX:+UseG1GC`选项。

Java 8 更新 20 引入了一个新的 JVM 参数，`-XX:+UseStringDeduplication`，用于 G1 收集器。通过这个参数，G1 识别重复的字符串，并创建指向相同的`char[]`数组的指针，以避免多个相同字符串的副本。

从 Java 8 开始，PermGen 的一部分堆被移除。这部分堆是为类元数据、静态变量和 interned 字符串分配的。这种参数调优导致了许多`OutOfMemory`异常，在 Java 8 之后，JVM 会处理这些异常。

# 堆内存

堆内存主要分为两代：年轻代和老年代。在 Java 7 之前，堆内存中有一个**PERM GENERATION**，而从 Java 8 开始，**PERM GENERATION**被**METASPACE**取代。**METASPACE**不是堆内存的一部分，而是**本地内存**的一部分。使用`-XX:MaxMetaspaceSize`选项设置**METASPACE**的大小。在投入生产时，考虑此设置至关重要，因为如果**METASPACE**占用过多内存，会影响应用程序的性能：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/3c93fe61-8690-43ce-9362-ff57c083d627.png)

Java 8 内存管理

**年轻代**是对象创建和分配的地方；它是为年轻对象而设的。**年轻代**进一步分为**幸存者空间**。以下是**Hotspot 堆结构**：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/f239e0c8-d541-4a54-9646-068d5a38f0ec.jpg)

**伊甸园**区域默认比**幸存者空间**大。所有对象首先都是在**伊甸园**区域中创建的。当**伊甸园**满时，将触发小型 GC，它将快速扫描对象的引用，并标记未引用的对象为死亡并进行收集。**幸存者空间**中的任何一个区域始终为空。在小型 GC 期间在**伊甸园**中幸存的对象将被移至空的**幸存者空间**。我们可能会想为什么有两个**幸存者空间**而不是一个。原因是为了避免内存碎片化。当**年轻代**运行并从**幸存者空间**中删除死对象时，会在内存中留下空洞并需要压缩。为了避免压缩，JVM 将幸存对象从一个**幸存者空间**移至另一个。这种从**伊甸园**和一个**幸存者空间**到另一个的活对象的乒乓运动会持续，直到出现以下条件：

+   对象达到最大 tenuring 阈值。这意味着对象不再年轻。

+   **幸存者空间**已满，无法容纳任何新对象。

当出现上述条件时，对象将被移至**老年代**。

# JVM 标志

以下是应用程序中常用的用于调整 JVM 以获得更好性能的 JVM 参数/标志。调整值取决于我们应用程序的行为以及生成速率。因此，没有明确定义的指南来使用特定值的 JVM 标志以实现更好的性能。

# -Xms 和-Xmx

`-Xms`和`-Xmx`被称为最小和最大堆大小。将`-Xms`设置为等于`-Xmx`可以防止堆扩展时的 GC 暂停，并提高性能。

# -XX:NewSize 和-XX:MaxNewSize

我们可以使用`-XX:MaxNewSize`设置年轻代的大小。如果我们将年轻代的大小设置得很大，那么老年代的大小将会较小。出于稳定性的原因，年轻代的大小不应该大于老年代。因此，`-Xmx/2`是我们可以为`-XX:MaxNewSize`设置的最大大小。

为了获得更好的性能，通过设置`-XX:NewSize`标志来设置年轻代的初始大小。这样可以节省一些成本，因为年轻代随着时间的推移会增长到该大小。

# -XX:NewRatio

我们可以使用`-XX:NewRatio`选项将年轻代的大小设置为老年代的比例。使用此选项的好处可能是，当 JVM 在执行过程中调整总堆大小时，年轻代可以增长和收缩。`-XX:NewRatio`表示老年代的比例大于年轻代。`-XX:NewRatio=2`表示老年代的大小是年轻代的两倍，这进一步意味着年轻代是总堆的 1/3。

如果我们指定了 Young Generation 的比例和固定大小，那么固定大小将优先。关于指定 Young Generation 大小的方法没有一定的规则。这里的经验法则是，如果我们知道应用程序生成的对象的大小，那么指定固定大小，否则指定比例。

# -XX:SurvivorRatio

`-XX:SurvivorRatio`值是 Eden 相对于 Survivor Spaces 的比例。将有两个 Survivor Spaces，每个都相等。如果`-XX:SurvivorRatio=8`，那么 Eden 占 3/4，每个 Survivor Spaces 占老年代总大小的 1/4。

如果我们设置了 Survivor Spaces 很小的比例，那么 Eden 将为新对象腾出更多空间。在 Minor GC 期间，未引用的对象将被收集，Eden 将为空出来给新对象，但是如果对象仍然有引用，垃圾收集器会将它们移动到 Survivor Space。如果 Survivor Space 很小，无法容纳新对象，那么对象将被移动到老年代。老年代中的对象只能在 Full GC 期间被收集，这会导致应用程序长时间暂停。如果 Survivor Space 足够大，那么更多的对象可以存活在 Survivor Space 中，但会死得很快。如果 Survivor Spaces 很大，Eden 将会很小，而小的 Eden 会导致频繁的 Young GC。

# -XX:InitialTenuringThreshold、-XX:MaxTenuringThreshold 和-XX:TargetSurvivorRatio

Tenuring 阈值决定了对象何时可以从 Young Generation 晋升/移动到 Old Generation。我们可以使用`-XX:InitialTenuringThreshold`和`-XX:MaxTenuringThreshold` JVM 标志来设置 tenuring 阈值的初始值和最大值。我们还可以使用`-XX:TargetSurvivorRatio`来指定 Young Generation GC 结束时 Survivor Space 的目标利用率（以百分比表示）。

# -XX:CMSInitiatingOccupancyFraction

当使用 CMS 收集器（-XX:+UseConcMarkSweepGC）时，使用`-XX:CMSInitiatingOccupancyFraction=85`选项。如果设置了该标志，并且老年代占用了 85%，CMS 收集器将开始收集未引用的对象。并不是必须老年代占用了 85% CMS 才开始收集。如果我们希望 CMS 只在 85%时开始收集，那么需要设置`-XX:+UseCMSInitiatingOccupancyOnly`。`-XX:CMSInitiatingOccupancyFraction`标志的默认值为 65%。

# -XX:+PrintGCDetails、-XX:+PrintGCDateStamps 和-XX:+PrintTenuringDistribution

设置标志以生成 GC 日志。为了微调 JVM 参数以实现更好的性能，了解 GC 日志和应用程序的行为非常重要。`-XX:+PrintTenuringDistribution`报告对象的统计信息（它们的年龄）以及它们晋升时的期望阈值。这对于了解我们的应用程序如何持有对象非常重要。

# 分析 GC 日志的工具

Java GC 日志是我们在性能问题发生时可以开始调试应用程序的地方之一。GC 日志提供重要信息，例如：

+   GC 上次运行的时间

+   GC 循环运行的次数

+   GC 运行的间隔

+   GC 运行后释放的内存量

+   GC 运行的时间

+   垃圾收集器运行时 JVM 暂停的时间

+   分配给每个代的内存量

以下是样本 GC 日志：

```java
2018-05-09T14:02:17.676+0530: 0.315: Total time for which application threads were stopped: 0.0001783 seconds, Stopping threads took: 0.0000239 seconds
2018-05-09T14:02:17.964+0530: 0.603: Application time: 0.2881052 seconds
.....
2018-05-09T14:02:18.940+0530: 1.579: Total time for which application threads were stopped: 0.0003113 seconds, Stopping threads took: 0.0000517 seconds
2018-05-09T14:02:19.028+0530: 1.667: Application time: 0.0877361 seconds
2018-05-09T14:02:19.028+0530: 1.667: [GC (Allocation Failure) [PSYoungGen: 65536K->10723K(76288K)] 65536K->13509K(251392K), 0.0176650 secs] [Times: user=0.05 sys=0.00, real=0.02 secs] 
2018-05-09T14:02:19.045+0530: 1.685: Total time for which application threads were stopped: 0.0179326 seconds, Stopping threads took: 0.0000525 seconds
2018-05-09T14:02:20.045+0530: 2.684: Application time: 0.9992739 seconds
.....
2018-05-09T14:03:54.109+0530: 96.748: Total time for which application threads were stopped: 0.0000498 seconds, Stopping threads took: 0.0000171 seconds
Heap
 PSYoungGen total 76288K, used 39291K [0x000000076b200000, 0x0000000774700000, 0x00000007c0000000)
  eden space 65536K, 43% used [0x000000076b200000,0x000000076cde5e30,0x000000076f200000)
  from space 10752K, 99% used [0x000000076f200000,0x000000076fc78e28,0x000000076fc80000)
  to space 10752K, 0% used [0x0000000773c80000,0x0000000773c80000,0x0000000774700000)
 ParOldGen total 175104K, used 2785K [0x00000006c1600000, 0x00000006cc100000, 0x000000076b200000)
  object space 175104K, 1% used [0x00000006c1600000,0x00000006c18b86c8,0x00000006cc100000)
 Metaspace used 18365K, capacity 19154K, committed 19456K, reserved 1067008K
  class space used 2516K, capacity 2690K, committed 2816K, reserved 1048576K
2018-05-09T14:03:54.123+0530: 96.761: Application time: 0.0131957 seconds
```

这些日志很难快速解释。如果有一个工具可以将这些日志呈现在可视化界面中，那么就可以轻松快速地理解 GC 的情况。我们将在下一节中看一下这样的工具来解释 GC 日志。

# GCeasy

GCeasy 是最受欢迎的垃圾收集日志分析工具之一。GCeasy 被开发出来自动从 GC 日志中识别问题。它足够智能，可以提供解决问题的替代方法。

以下是 GCeasy 提供的重要基本功能：

+   使用机器学习算法分析日志

+   快速检测内存泄漏、过早对象晋升、长时间的 JVM 暂停以及许多其他性能问题

+   功能强大且信息丰富的可视化分析工具

+   提供用于主动日志分析的 REST API

+   免费的基于云的日志分析工具

+   提供有关 JVM 堆大小的建议

+   能够分析所有格式的 GC 日志

GCeasy.io ([`www.gceasy.io/`](http://www.gceasy.io/))是在线垃圾收集日志分析工具。它需要将日志文件上传到 GCeasy 公共云。

使用在线工具收集详细的日志分析的步骤如下：

1.  通过在服务器的 JVM 参数中添加`XX:+PrintGCDetails -XX:+PrintGCDateStamps -Xloggc:<GC-log-file-path>`来在应用程序中启用 GC 日志。

1.  一旦在指定位置生成了 GC 日志文件，通过导航到[`gceasy.io/`](http://gceasy.io/)将文件上传到 GCeasy 云。如果有多个日志文件需要分析，也可以上传压缩的 ZIP 文件。

1.  处理日志文件后，将生成详细的分析报告。

报告组织得当且详细到足以突出每一个可能导致性能下降的问题。以下部分解释了 GCeasy 生成的报告中的重要部分。

# JVM 调优提示

报告中的顶部部分根据垃圾收集日志分析提供建议。这些建议是通过机器学习算法动态生成的，经过对日志文件的彻底分析。建议中的细节还包括问题的可能原因。以下是 GCeasy 在 GC 日志分析后提供的一个示例建议：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/a9d60f2f-d1d0-4b46-9d97-627b209fc693.jpg)

# JVM 堆大小

报告中的这一部分提供了每个内存代的堆分配和峰值内存使用情况的信息。可能分配的堆大小可能与 JVM 参数中定义的大小不匹配。这是因为 GCeasy 工具从日志中获取了分配的内存信息。可能我们分配了 2GB 的堆内存，但在运行时，JVM 只分配了 1GB 的堆内存。在这种情况下，报告将显示分配的内存为 1GB。报告以表格和图形格式显示堆分配。以下是报告中堆大小部分的示例：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/760de75d-71b3-44b7-84b9-9583efa5af91.png)

# 关键绩效指标

**关键绩效指标**（**KPIs**）有助于做出改善应用程序性能的深刻决策。吞吐量、延迟和占用空间是一些重要的 KPIs。报告中的 KPIs 包括吞吐量和延迟。占用空间基本上描述了 CPU 占用的时间。它可以从性能监控工具（如 JVisualVM）中获取。

吞吐量选项表示在指定时间段内应用程序完成的有效工作量。延迟选项表示 GC 运行所花费的平均时间。

以下是报告中 KPIs 的示例：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/6d375ac5-b067-44c4-8efe-98a2a8498c14.jpg)

# GC 统计

GC 统计部分提供了一段时间内垃圾收集器的行为信息。这段时间是分析日志的时间段。GC 统计是基于实时分析提供的。统计数据包括垃圾收集器运行后回收的字节数、累积 GC 时间（以秒为单位）和平均 GC 时间（以秒为单位）。该部分还以表格格式提供了有关总 GC 统计、小型 GC 统计和完整 GC 统计以及 GC 暂停统计的信息。

# GC 原因

GC Causes 部分提供了有关垃圾收集器运行原因的信息。该信息以表格和图形格式提供。除了原因，它还提供了垃圾收集器执行所需的时间信息。以下是报告中的一个示例：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/1f5ee498-4526-4f89-a07b-3d56e0863889.png)

基于上述细节，GCeasy 是一个帮助开发人员以可视化方式解释 GC 日志的重要工具。

# 摘要

在本章中，我们学习了 JVM 及其参数。我们了解了内存泄漏以及与 GC 相关的常见误解。我们了解了不同的 GC 方法及其重要性。我们了解了重要的 JVM 标志，这些标志被调整以实现更好的性能。

在下一章中，我们将学习关于 Spring Boot 微服务及其性能调优。微服务是一种应用架构，它由松散耦合的服务实现业务功能。Spring Boot 使我们能够构建生产就绪的应用程序。


# 第十二章：Spring Boot 微服务性能调优

在上一章中，我们了解了**Java 虚拟机**（**JVM**）。从 JVM 的内部和 Java 的类加载机制开始，我们了解了 Java 中的内存管理是如何进行的。本章的最后一节关注了垃圾回收和 JVM 调优。本章充满了对应用程序性能优化非常重要的细节。

在本章中，我们将着手解决性能问题。方法是开发微服务。微服务目前在软件开发行业中非常流行。微服务和相关关键词引起了很多关注。这种方法基本上是在应用架构层面调整应用程序的性能。它描述了我们如何通过以不同的方式设置架构来改善应用程序的性能。本章将涵盖以下主题：

+   Spring Boot 配置

+   Spring Boot 执行器的指标

+   健康检查

+   使用 Spring Boot 的微服务

+   使用 Spring Cloud 的微服务

+   Spring 微服务配置示例

+   使用 Spring Boot admin 监控微服务

+   Spring Boot 性能调优

# Spring Boot 配置

在本节中，我们将专注于让 Spring Boot 为我们工作。在跳转到 Spring Boot 配置之前，我们将了解 Spring Boot 是什么，为什么我们应该使用它，以及 Spring Boot 带来了什么。我们将迅速转向如何做这一部分。

# 什么是 Spring Boot？

软件开发过程需要更快、更准确、更健壮。要求软件团队快速开发原型，展示应用程序的功能给潜在客户。对生产级应用程序也是如此。以下是软件架构师关注的一些领域，以提高开发团队的效率：

+   使用正确的一套工具，包括框架、IDE 和构建工具

+   减少代码混乱

+   减少编写重复代码的时间

+   大部分时间用于实现业务功能

让我们思考一下。为什么我们要讨论这个？原因是这是 Spring Boot 的基础。这些想法是任何帮助团队提高生产力的框架或工具的基石。Spring Boot 也是出于同样的原因而存在——提高生产力！

使用 Spring Boot，轻松创建由 Spring 框架驱动的生产级应用程序。它还可以轻松创建具有最小挑战的生产就绪服务。Spring Boot 通过对 Spring 框架持有一种看法，帮助新用户和现有用户快速进行生产任务。Spring Boot 是一个工具，可以帮助创建一个独立的 Java 应用程序，可以使用`java -jar`命令运行，或者一个可以部署到 Web 服务器的 Web 应用程序。Spring Boot 设置捆绑了命令行工具来运行 Spring 程序。

Spring Boot 的主要目标是：

+   以极快的速度开始使用 Spring 项目

+   广泛的可访问性

+   主要支持开箱即用的配置

+   根据需要灵活地偏离 Spring 默认设置

+   不生成任何代码

+   不需要 XML 配置

除了前面列出的主要特性，Spring Boot 还提供了以下非功能特性的支持：

+   支持广为人知和使用的框架的版本和配置

+   应用安全支持

+   监控应用程序健康检查参数的支持

+   性能指标监控支持

+   外部化配置支持

尽管 Spring Boot 为主要和非功能特性提供了默认值，但它足够灵活，允许开发人员使用他们选择的框架、服务器和工具。

# Spring Initializr

Spring Boot 应用程序可以以多种方式启动。其中一种方式是使用基于 Eclipse 的 Spring 工具套件 IDE ([`spring.io/tools/sts`](https://spring.io/tools/sts))。另一种方式是使用[`start.spring.io`](https://start.spring.io)，也称为 Spring Initializr。首先，Spring Initializr 不是 Spring Boot 或等效物。Spring Initializr 是一个具有简单 Web UI 支持的工具，用于配置 Spring Boot 应用程序。它可以被认为是一个用于快速启动生成 Spring 项目的工具。它提供了可以扩展的 API，以便生成项目的定制化。

Spring Initializr 工具提供了一个配置结构，用于定义依赖项列表、支持的 Java 和 Spring Boot 版本以及支持的依赖项版本。

基本上，Spring Initializr 根据提供的配置创建一个初始的 Spring 项目，并允许开发人员下载 ZIP 文件中的项目。以下是要遵循的步骤：

1.  导航到[`start.spring.io/`](https://start.spring.io/)。

1.  从 Maven 或 Gradle 中选择依赖项管理工具。

1.  从 Java、Kotlin 和 Groovy 中选择基于 JVM 的编程语言。

1.  选择要使用的 Spring Boot 版本。

1.  通过输入组名`com.packt.springhighperformance`来提供组件名称。

1.  输入 Artifact，这是 Maven 项目的 Artifact ID。这将成为要部署或执行的项目 WAR 或 JAR 文件的名称。

1.  从 Jar 和 War 中选择一种打包类型。

1.  单击“切换到完整版本”链接。这将打开一个可供选择的起始项目列表。起始项目将在下一节中详细解释。

1.  一旦我们选择了起始器或依赖项，点击“生成项目”按钮。这将下载包含初始项目配置的 ZIP 文件。

以下是带有一些配置的 Spring Initializr 屏幕：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/a6a45a4d-e090-4376-ba21-fc3485818310.jpeg)

完成后，将生成类似于以下截图所示的文件夹结构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/7ea85fbb-0031-4bc6-9bcd-3f572426642f.jpg)

Spring Initializr 还支持命令行界面来创建 Spring 项目配置。可以使用以下命令来生成项目配置：

```java
> curl https://start.spring.io/starter.zip -d dependencies=web,jpa -d bootVersion=2.0.0 -o ch-09-spring-boot-example-1.zip
```

正如前面提到的，Spring Initializr 支持与 IDE 的集成。它与 Eclipse/STS、IntelliJ ultimate 版和带有 NB SpringBoot 插件的 NetBeans 集成良好。

# 使用 Maven 的起始器

在前面的部分中，我们看了 Spring Initializr 工具。现在是时候快速查看 Spring Boot 支持的起始器或依赖项了。

随着项目复杂性的增加，依赖项管理变得具有挑战性。建议不要为复杂项目手动管理依赖项。Spring Boot 起始器解决了类似的问题。Spring Boot 起始器是一组依赖描述符，可以在使用 starter POMs 的 Spring 应用程序中包含。它消除了寻找示例代码和复制/粘贴大量 Spring 和相关库的依赖描述符的需要。例如，如果我们想要使用 Spring 和 JPA 开发应用程序，我们可以在项目中包含`spring-boot-data-jpa-starter`依赖项。`spring-boot-data-jpa-starter`是其中的一个起始器。这些起始器遵循统一的命名模式，例如`spring-boot-starter-*`，其中`*`表示应用程序的类型。

以下是一些 Spring Boot 应用程序起始器的列表：

| **名称** | **描述** |
| --- | --- |
| `spring-boot-starter` | 核心起始器提供自动配置和日志记录支持。 |
| `spring-boot-starter-activemq` | 使用 Apache ActiveMQ 的 JMS 消息起始器。 |
| `spring-boot-starter-amqp` | Spring AMQP 和 Rabbit MQ 起始器。 |
| `spring-boot-starter-aop` | Spring AOP 和 AspectJ 起始器。 |
| `spring-boot-starter-artemis` | 使用 Apache Artemis 的 JMS 消息起始器。 |
| `spring-boot-starter-batch` | Spring Batch 起始器。 |
| `spring-boot-starter-cache` | Spring Framework 的缓存支持。 |
| `spring-boot-starter-cloud-connectors` | 提供支持，使用 Spring Cloud Connectors 在云平台（如 Cloud Foundry 和 Heroku）中简化与云服务的连接。 |
| `spring-boot-starter-data-elasticsearch` | 具有对 elasticsearch 和分析引擎以及 Spring Data Elasticsearch 的支持的启动器。 |
| `spring-boot-starter-data-jpa` | 使用 Hibernate 的 Spring Data JPA。 |
| `spring-boot-starter-data-ldap` | Spring Data LDAP。 |
| `spring-boot-starter-data-mongodb` | MongoDB 文档导向数据库和 Spring Data MongoDB。 |
| `spring-boot-starter-data-redis` | 使用 Spring Data Redis 和 Lettuce 客户端的 Redis 键值数据存储。 |
| `spring-boot-starter-data-rest` | 提供支持，使用 Spring Data REST 在 REST 上公开 Spring Data 存储库的启动器。 |
| `spring-boot-starter-data-solr` | 使用 Spring Data Solr 的 Apache Solr 搜索平台。 |
| `spring-boot-starter-freemarker` | 支持使用 FreeMarker 视图构建 MVC Web 应用程序的启动器。 |
| `spring-boot-starter-groovy-templates` | 支持使用 Groovy 模板视图构建 MVC Web 应用程序的启动器。 |
| `spring-boot-starter-integration` | Spring Integration。 |
| `spring-boot-starter-jdbc` | 使用 Tomcat JDBC 连接池的 JDBC。 |
| `spring-boot-starter-jersey` | 支持使用 JAX-RS 和 Jersey 构建 RESTful Web 应用程序。这是`spring-boot-starter-web starter`的替代品。 |
| `spring-boot-starter-json` | 支持 JSON 操作的启动器。 |
| `spring-boot-starter-mail` | 支持使用 Java Mail 和 Spring Framework 的邮件发送支持的启动器。 |
| `spring-boot-starter-quartz` | 用于使用 Spring Boot Quartz 的启动器。 |
| `spring-boot-starter-security` | Spring Security 启动器。 |
| `spring-boot-starter-test` | 支持使用包括 JUnit、Hamcrest 和 Mockito 在内的库的 Spring Boot 应用程序。 |
| `spring-boot-starter-thymeleaf` | 支持使用 Thymeleaf 视图构建 MVC Web 应用程序。 |
| `spring-boot-starter-validation` | 使用 Hibernate Validator 支持 Java Bean 验证的启动器。 |
| `spring-boot-starter-web` | 支持使用 Spring MVC 构建 Web 应用程序，包括 RESTful 应用程序。它使用 Tomcat 作为默认的嵌入式容器。 |
| `spring-boot-starter-web-services` | 支持使用 Spring Web Services。 |
| `spring-boot-starter-websocket` | 支持使用 Spring Framework 的 WebSocket 支持构建 WebSocket 应用程序。 |

`spring-boot-starter-actuator` 是 Spring Boot Actuator 工具的生产启动器，提供了生产就绪功能的支持，如应用程序监控、健康检查、日志记录和 bean。

以下列表包括 Spring Boot 的一些技术启动器：

| **名称** | **描述** |
| --- | --- |
| `spring-boot-starter-jetty `                        | 作为嵌入式 Servlet 容器的 Jetty 支持。这是`spring-boot-starter-tomcat`的替代品。 |
| `spring-boot-starter-log4j2`                          | 支持 Log4j 2 进行日志记录。这是`spring-boot-starter-logging`的替代品。 |
| `spring-boot-starter-logging` | 这是使用 logback 的默认日志启动器。 |
| `spring-boot-starter-tomcat` | 这是用于`spring-boot-starter-web`的默认 Servlet 容器启动器。它使用 Tomcat 作为嵌入式服务器。 |
| `spring-boot-starter-undertow` | 这是`spring-boot-starter-tomcat starter`的替代品。它使用 Undertow 作为嵌入式服务器。 |
| `spring-boot-starter-cache` | Spring Framework 的缓存支持。 |

# 创建您的第一个 Spring Boot 应用程序

在本节中，我们将查看开发 Spring Boot 应用程序的先决条件。我们将开发一个小型的 Spring Boot 应用程序，以了解 Spring Boot 应用程序所需的配置和每个配置的重要性。

以下是使用 Spring Boot 的先决条件列表：

+   Java 8 或 9

+   Spring 5.0.4 或更高版本

Spring Boot 支持：

+   Maven 3.2+和 Gradle 4 用于依赖管理和显式构建

+   Tomcat 8.5，Jetty 9.4 和 Undertow 1.4

Spring Boot 应用程序可以部署到任何 servlet 3.0+兼容的 servlet 容器。

开发 Spring Boot 应用程序的第一步是安装 Spring Boot。设置非常简单。它可以像其他标准 Java 库一样设置。要安装 Spring Boot，我们需要在类路径中包含适当的`spring-boot-*.jar`库文件。Spring Boot 不需要任何专门的工具，可以使用任何 IDE 或文本编辑器。

虽然我们可以将所需的 Spring Boot JAR 文件复制到应用程序类路径中，但建议使用构建工具，如 Maven 或 Gradle，进行依赖管理。

Spring Boot 依赖项使用的 Maven `groupId`是`org.springframework.boot`。对于 Spring Boot 应用程序，Maven POM 文件继承了`spring-boot-starter-parent`项目。Spring Boot 定义了启动器项目，并在 Spring Boot 应用程序的依赖项中定义为依赖项。

让我们开始创建我们的第一个 Spring Boot 应用程序，按照以下步骤进行：

1.  使用 Spring Initializr 创建一个 kickstarter 应用程序。

1.  选择 Maven 作为构建和依赖管理工具。

1.  选择适当的 Spring Boot 版本。

1.  选择打包类型为 War。

1.  为了简单起见，我们将不在应用程序中包含 JPA 启动器。我们只会包含一个 web 模块，以演示一个请求-响应流程。

1.  下载并导入项目到 STS 或 Eclipse。

1.  在 STS 中，您可以将应用程序作为 Spring Boot 应用程序运行，而在 Eclipse 中，您可以选择将应用程序作为 Java 应用程序运行。

现在让我们浏览一下代码片段。以下是示例 Maven POM 文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project  

    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0         
    http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.packt.springhighperformance.ch09</groupId>
  <artifactId>ch-09-boot-example</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>

  <name>boot-example</name>
  <description>Demo project for Spring boot</description>

  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.0.0.RELEASE</version>
    <relativePath/> <!-- lookup parent from repository -->
  </parent>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-
    8</project.reporting.outputEncoding>
    <java.version>1.8</java.version>
    <spring-cloud.version>Finchley.M9</spring-cloud.version>
  </properties>

  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>
```

在前面的配置文件中，一个值得注意的配置是父依赖项。如前所述，所有 Spring Boot 应用程序在`pom.xml`文件中使用`spring-boot-starter-parent`作为父依赖项。

父 POM 帮助管理子项目和模块的以下内容：

+   Java 版本

+   包含依赖项的版本管理

+   插件的默认配置

Spring Boot 父启动器将 Spring Boot 依赖项定义为父 POM。因此，它从 Spring Boot 依赖项继承了依赖项管理功能。它将默认的 Java 版本定义为 1.6，但在项目级别上，我们可以将其更改为`1.8`，如前面的代码示例所示。

除了默认的 POM 文件外，Spring Boot 还创建了一个作为应用程序启动器的 Java 类。以下是示例 Java 代码：

```java
package com.packt.springhighperformance.ch09;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class BootExampleApplication {

  public static void main(String[] args) {
    SpringApplication.run(BootExampleApplication.class, args);
  }
}
```

`SpringApplication`是一个负责引导 Spring Boot 应用程序的类。

Spring Boot 应用程序开发人员习惯于使用`@Configuration`、`@EnableAutoConfiguration`和`@ComponentScan`注解来注释主应用程序类。以下是每个注解的简要描述：

+   `@Configuration`：这是一个 Spring 注解，不特定于 Spring Boot 应用程序。它表示该类是 bean 定义的来源。

+   `@EnableAutoConfiguration`：这是一个 Spring Boot 特定的注解。该注解使应用程序能够从类路径定义中添加 bean。

+   `@ComponentScan`：此注解告诉 Spring 应用程序在提供的搜索路径中搜索组件、配置和服务。

以下是`@SpringBootApplication`注解的定义：

```java
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@Configuration
@EnableAutoConfiguration
@ComponentScan
public @interface SpringBootApplication {
......
```

从前面的代码可以看出，`@SpringBootApplication`作为一个方便的注解来定义 Spring Boot 应用程序，而不是声明三个注解。

以下代码块显示了当 Spring Boot 应用程序启动时的日志输出：

```java

  . ____ _ __ _ _
 /\\ / ___'_ __ _ _(_)_ __ __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/ ___)| |_)| | | | | || (_| | ) ) ) )
  ' |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot :: (v2.0.0.RELEASE)

2018-05-23 16:29:21.382 INFO 32268 --- [ main] c.p.s.ch09.BootExampleApplication : Starting BootExampleApplication on DESKTOP-4DS55MC with PID 32268 (E:\projects\spring-high-performance\ch-09\boot-example\target\classes started by baps in E:\projects\spring-high-performance\ch-09\boot-example)
2018-05-23 16:29:21.386 INFO 32268 --- [ main] c.p.s.ch09.BootExampleApplication : No active profile set, falling back to default profiles: default
2018-05-23 16:29:21.441 INFO 32268 --- [ main] ConfigServletWebServerApplicationContext : Refreshing org.springframework.boot.web.servlet.context.AnnotationConfigServletWebServerApplicationContext@58ce9668: startup date [Wed May 23 16:29:21 IST 2018]; root of context hierarchy
2018-05-23 16:29:23.854 INFO 32268 --- [ main] o.s.b.w.embedded.tomcat.TomcatWebServer : Tomcat initialized with port(s): 8080 (http)
2018-05-23 16:29:23.881 INFO 32268 --- [ main] o.apache.catalina.core.StandardService : Starting service [Tomcat]
2018-05-23 16:29:23.881 INFO 32268 --- [ main] org.apache.catalina.core.StandardEngine : Starting Servlet Engine: Apache Tomcat/8.5.28
2018-05-23 16:29:23.888 INFO 32268 --- [ost-startStop-1] o.a.catalina.core.AprLifecycleListener : The APR based Apache Tomcat Native library which allows optimal performance in production environments was not found on the java.library.path: ...
2018-05-23 16:29:24.015 INFO 32268 --- [ost-startStop-1] o.a.c.c.C.[Tomcat].[localhost].[/] : Initializing Spring embedded WebApplicationContext
2018-05-23 16:29:24.016 INFO 32268 --- [ost-startStop-1] o.s.web.context.ContextLoader : Root WebApplicationContext: initialization completed in 2581 ms
2018-05-23 16:29:25.011 INFO 32268 --- [ost-startStop-1] o.s.b.w.servlet.ServletRegistrationBean : Servlet dispatcherServlet mapped to [/]
2018-05-23 16:29:25.015 INFO 32268 --- [ost-startStop-1] o.s.b.w.servlet.FilterRegistrationBean : Mapping filter: 'characterEncodingFilter' to: [/*]
2018-05-23 16:29:25.016 INFO 32268 --- [ost-startStop-1] o.s.b.w.servlet.FilterRegistrationBean : Mapping filter: 'hiddenHttpMethodFilter' to: [/*]
2018-05-23 16:29:25.016 INFO 32268 --- [ost-startStop-1] o.s.b.w.servlet.FilterRegistrationBean : Mapping filter: 'httpPutFormContentFilter' to: [/*]
2018-05-23 16:29:25.016 INFO 32268 --- [ost-startStop-1] o.s.b.w.servlet.FilterRegistrationBean : Mapping filter: 'requestContextFilter' to: [/*]
2018-05-23 16:29:25.016 INFO 32268 --- [ost-startStop-1] o.s.b.w.servlet.FilterRegistrationBean : Mapping filter: 'httpTraceFilter' to: [/*]
2018-05-23 16:29:25.016 INFO 32268 --- [ost-startStop-1] o.s.b.w.servlet.FilterRegistrationBean : Mapping filter: 'webMvcMetricsFilter' to: [/*]
2018-05-23 16:29:26.283 INFO 32268 --- [ main] s.w.s.m.m.a.RequestMappingHandlerMapping : Mapped "{[/welcome]}" onto public java.lang.String com.packt.springhighperformance.ch09.controllers.MainController.helloMessage(java.lang.String)
2018-05-23 16:29:26.284 INFO 32268 --- [ main] s.w.s.m.m.a.RequestMappingHandlerMapping : Mapped "{[/]}" onto public java.lang.String com.packt.springhighperformance.ch09.controllers.MainController.helloWorld()
2018-05-23 16:29:26.291 INFO 32268 --- [ main] s.w.s.m.m.a.RequestMappingHandlerMapping : Mapped "{[/error]}" onto public org.springframework.http.ResponseEntity<java.util.Map<java.lang.String, java.lang.Object>> org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController.error(javax.servlet.http.HttpServletRequest)
2018-05-23 16:29:26.292 INFO 32268 --- [ main] s.w.s.m.m.a.RequestMappingHandlerMapping : Mapped "{[/error],produces=[text/html]}" onto public org.springframework.web.servlet.ModelAndView org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController.errorHtml(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)
2018-05-23 16:29:26.358 INFO 32268 --- [ main] o.s.w.s.handler.SimpleUrlHandlerMapping : Mapped URL path [/webjars/**] onto handler of type [class org.springframework.web.servlet.resource.ResourceHttpRequestHandler]
2018-05-23 16:29:26.359 INFO 32268 --- [ main] o.s.w.s.handler.SimpleUrlHandlerMapping : Mapped URL path [/**] onto handler of type [class org.springframework.web.servlet.resource.ResourceHttpRequestHandler]
2018-05-23 16:29:26.410 INFO 32268 --- [ main] o.s.w.s.handler.SimpleUrlHandlerMapping : Mapped URL path [/**/favicon.ico] onto handler of type [class org.springframework.web.servlet.resource.ResourceHttpRequestHandler]
2018-05-23 16:29:27.033 INFO 32268 --- [ main] o.s.j.e.a.AnnotationMBeanExporter : Registering beans for JMX exposure on startup
2018-05-23 16:29:27.082 INFO 32268 --- [ main] o.s.b.w.embedded.tomcat.TomcatWebServer : Tomcat started on port(s): 8080 (http) with context path ''
2018-05-23 16:29:27.085 INFO 32268 --- [ main] c.p.s.ch09.BootExampleApplication : Started BootExampleApplication in 6.068 seconds (JVM running for 7.496)
```

到目前为止，我们已经准备好了 Spring Boot 应用程序，但我们没有任何要呈现的 URL。因此，当您访问`http://localhost:8080`时，将显示类似于以下屏幕截图的页面：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/3443f7f2-8712-47e8-9cb8-98bcd0b86b72.jpeg)

让我们定义 Spring 控制器和默认路由，并向其添加文本内容。以下是控制器类的代码片段：

```java
package com.packt.springhighperformance.ch09.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MainController {

  @RequestMapping(value="/")
  @ResponseBody
  public String helloWorld() {
    return "<h1>Hello World<h1>";
  }

  @RequestMapping(value="/welcome")
  @ResponseBody
  public String showMessage(@RequestParam(name="name") String name) {
    return "<h1>Hello " + name + "<h1>";
  }

}
```

在上面的示例代码中，我们使用`@RequestMapping`注解定义了两个路由。以下是上述代码块中使用的注解列表及简要描述：

+   `@Controller`注解表示该类是一个控制器类，可能包含请求映射。

+   `@RequestMapping`注解定义了用户可以在浏览器中导航到的应用程序 URL。

+   `@ResponseBody`注解表示方法返回值应该作为 HTML 内容呈现在页面上。value 参数可以采用要导航的 URL 路径。

当我们在浏览器中输入`http://localhost:8080`时，以下屏幕截图显示了显示或呈现的页面：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/bc305322-30ca-4029-b5c7-2b02130fdb37.jpeg)

我们还定义了带有值`/welcome`的参数化请求映射。当我们在浏览器中导航到 URL 时，请求参数的值将反映在页面上的消息中。以下屏幕截图显示了内容的呈现方式：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/3785fbe1-ea04-493b-aae8-f3f9f3383565.jpeg)

当应用程序使用这些请求映射引导时，我们可以找到以下日志条目：

```java
2018-03-24 10:26:26.154 INFO 11148 --- [ main] s.w.s.m.m.a.RequestMappingHandlerAdapter : Looking for @ControllerAdvice: org.springframework.boot.web.servlet.context.AnnotationConfigServletWebServerApplicationContext@3c153a1: startup date [Sat Mar 24 10:26:24 IST 2018]; root of context hierarchy
2018-03-24 10:26:26.214 INFO 11148 --- [ main] s.w.s.m.m.a.RequestMappingHandlerMapping : Mapped "{[/]}" onto public java.lang.String com.packt.springhighperformance.ch09.controllers.MainController.helloWorld()
2018-03-24 10:26:26.218 INFO 11148 --- [ main] s.w.s.m.m.a.RequestMappingHandlerMapping : Mapped "{[/welcome]}" onto public java.lang.String com.packt.springhighperformance.ch09.controllers.MainController.helloMessage(java.lang.String)
```

到目前为止，我们的第一个 Spring Boot 应用程序已经有了示例请求映射。本节作为 Spring Boot 应用程序开发的逐步指南。在下一节中，我们将看到更多 Spring Boot 功能。

# 使用 Spring Boot 执行器的指标

在我们继续之前，了解 Spring Boot 执行器的重要性是很重要的。我们将在接下来的章节中介绍 Spring Boot 执行器。我们还将查看 Spring Boot 执行器提供的开箱即用的功能。我们还将通过示例来了解配置和其他必要的细节。

# 什么是 Spring 执行器？

实质上，Spring Boot 执行器可以被认为是 Spring Boot 的一个子项目。它可以在我们使用 Spring Boot 开发的应用程序中提供生产级功能。在利用其提供的功能之前，需要配置 Spring Boot 执行器。Spring Boot 执行器自 2014 年 4 月首次发布以来一直可用。Spring Boot 执行器实现了不同的 HTTP 端点，因此开发团队可以执行以下任务：

+   应用程序监控

+   分析应用指标

+   与应用程序交互

+   版本信息

+   记录器详情

+   Bean 详情

# 启用 Spring Boot 执行器

除了帮助引导应用程序开发外，Spring Boot 还可以在应用程序中使用许多功能。这些附加功能包括但不限于监视和管理应用程序。应用程序的管理和监视可以通过 HTTP 端点或使用 JMX 来完成。审计、健康检查和指标也可以通过 Spring Boot 应用程序中的配置来应用。这些都是由`spring-boot-actuator`模块提供的生产就绪功能。

以下是来自 Spring Boot 参考文档的执行器定义（[`docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#production-ready`](https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#production-ready)）：

执行器是一个制造业术语，指的是用于移动或控制某物的机械装置。执行器可以从微小的变化中产生大量运动。

为了利用 Spring Boot Actuator 的功能，第一步是启用它。它不是默认启用的，我们必须添加依赖项才能启用它。在 Spring Boot 应用程序中启用 Spring Boot Actuator 非常容易。如果我们在应用程序中使用 Maven 进行依赖管理，我们需要在 `pom.xml` 文件中添加 `spring-boot-starter-actuator` 依赖项。以下是 Maven 依赖项的片段，用于 Spring Boot Actuator：

```java
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

如前所述，Spring Boot Actuator 通过暴露或启用端点来实现应用程序监控。该模块具有许多开箱即用的端点。它还允许开发人员创建自定义端点。我们可以启用或禁用每个单独的端点。这确保了端点在应用程序中创建，并且应用程序上下文中存在相应的 bean。

端点可以通过在 JMX 或 HTTP 上暴露来远程访问。通常，应用程序会通过 HTTP 暴露端点。端点的 URL 是通过将端点 ID 与 `/actuator` 前缀进行映射而派生的。

以下是一些与技术无关的端点列表：

| **ID** | **描述** | **默认启用** |
| --- | --- | --- |
| `auditevents` | 此端点公开了音频事件的信息。 | 是 |
| `beans` | 此端点显示应用程序中可用的所有 Spring `beans` 的完整列表。 | 是 |
| `conditions` | 此端点显示在配置和自动配置类上评估的 `conditions`。 | 是 |
| `configprops` | 此端点显示标有 `@ConfigurationProperties` 的属性列表。 | 是 |
| `env` | 此端点显示来自 Spring 的 `ConfigurableEnvironment` 的属性。 | 是 |
| `flyway` | 此端点显示可能已应用的任何 `flyway` 数据库迁移。 | 是 |
| `health` | 此端点显示应用程序的 `health` 信息。 | 是 |
| `httptrace` | 此端点显示 HTTP 跟踪信息。默认情况下，它显示最后 100 个 HTTP 请求-响应交换。 | 是 |
| `info` | 此端点公开应用程序信息。 | 是 |
| `loggers` | 此端点显示应用程序 `logger` 配置。 | 是 |
| `liquibase` | 此端点显示可能已应用的任何 `liquibase` 数据库迁移。 | 是 |
| `metrics` | 此端点显示应用程序的 `metrics` 信息。 | 是 |
| `mappings` | 此端点显示所有 `@RequestMapping` 路径的列表。 | 是 |
| `scheduledtasks` | 此端点显示应用程序的定时任务。 | 是 |
| `sessions` | 此端点允许从 Spring Session 支持的会话存储中检索和删除用户 `sessions`。在使用 Spring Session 对响应式 Web 应用程序的支持时不可用。 | 是 |
| `shutdown` | 此端点允许应用程序优雅地关闭。 | 否 |
| `threaddump` | 此端点执行 `threaddump`。 | 是 |

以下是一些在应用程序是 Web 应用程序时暴露的附加端点：

| **ID** | **描述** | **默认启用** |
| --- | --- | --- |
| `heapdump` | 此端点返回一个压缩的 `hprof` 堆转储文件。 | 是 |
| `jolokia` | 此端点通过 HTTP 公开 JMX bean。 | 是 |
| `logfile` | 如果在属性中设置了 `logging.file` 或 `logging.path`，此端点将显示 `logfile` 的内容。它使用 HTTP 范围标头来部分检索日志文件的内容。 | 是 |
| `prometheus` | 此端点显示以 Prometheus 服务器可以抓取的格式的指标。 | 是 |

# 启用端点

使用 Spring Boot Actuator，默认情况下所有端点都是启用的，除了 `shutdown` 端点。为了启用或禁用特定端点，应在 `application.properties` 文件中添加相关属性。以下是启用端点的格式：

```java
management.endpoint.<id>.enabled=true
```

例如，可以添加以下属性以启用`shutdown`端点：

```java
management.endpoint.shutdown.enabled=true
```

当我们启动一个默认启用 Actuator 端点的应用程序时，可以看到以下日志条目：

```java
2018-03-24 17:51:36.687 INFO 8516 --- [ main] s.b.a.e.w.s.WebMvcEndpointHandlerMapping : Mapped "{[/actuator/health],methods=[GET],produces=[application/vnd.spring-boot.actuator.v2+json || application/json]}" onto public java.lang.Object org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping$OperationHandler.handle(javax.servlet.http.HttpServletRequest,java.util.Map<java.lang.String, java.lang.String>)
2018-03-24 17:51:36.696 INFO 8516 --- [ main] s.b.a.e.w.s.WebMvcEndpointHandlerMapping : Mapped "{[/actuator/info],methods=[GET],produces=[application/vnd.spring-boot.actuator.v2+json || application/json]}" onto public java.lang.Object org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping$OperationHandler.handle(javax.servlet.http.HttpServletRequest,java.util.Map<java.lang.String, java.lang.String>)
2018-03-24 17:51:36.697 INFO 8516 --- [ main] s.b.a.e.w.s.WebMvcEndpointHandlerMapping : Mapped "{[/actuator],methods=[GET],produces=[application/vnd.spring-boot.actuator.v2+json || application/json]}" onto protected java.util.Map<java.lang.String, java.util.Map<java.lang.String, org.springframework.boot.actuate.endpoint.web.Link>> org.springframework.boot.actuate.endpoint.web.servlet.WebMvcEndpointHandlerMapping.links(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)
```

仔细查看日志条目，我们发现以下端点或 URL 被暴露：

+   `/actuator`

+   `/actuator/health`

+   `/actuator/info`

应用程序为什么有三个端点暴露出来，而之前列出的端点如此之多？为了回答这个问题，Spring Boot Actuator 只在 HTTP 上暴露了三个端点。之前列出的其余端点是通过 JMX 连接暴露的。以下是端点列表以及它们是否在 HTTP 或 JMX 上暴露的信息：

| **ID** | **在 JMX 上暴露** | **在 HTTP 上暴露** |
| --- | --- | --- |
| `auditevents` | 是 | 否 |
| `beans` | 是 | 否 |
| `conditions` | 是 | 否 |
| `configprops` | 是 | 否 |
| `env` | 是 | 否 |
| `flyway` | 是 | 否 |
| `health` | 是 | 是 |
| `heapdump` | N/A | 否 |
| `httptrace` | 是 | 否 |
| `info` | 是 | 是 |
| `jolokia` | N/A | 否 |
| `logfile` | N/A | 否 |
| `loggers` | 是 | 否 |
| `liquibase` | 是 | 否 |
| `metrics` | 是 | 否 |
| `mappings` | 是 | 否 |
| `prometheus` | N/A | 否 |
| `scheduledtasks` | 是 | 否 |
| `sessions` | 是 | 否 |
| `shutdown` | 是 | 否 |
| `threaddump` | 是 | 否 |

Spring Boot 为什么不默认在 HTTP 上暴露所有端点？原因是端点可能暴露敏感信息。因此，在暴露它们时应该仔细考虑。

以下属性可用于更改或覆盖端点的默认暴露行为：

+   `management.endpoints.jmx.exposure.exclude`: 以逗号分隔的端点 ID 从默认的 JMX 连接暴露中排除。默认情况下，没有一个默认端点被排除。

+   `management.endpoints.jmx.exposure.include`: 以逗号分隔的端点 ID 与默认的 JMX 连接暴露一起包括。该属性可用于暴露那些未包含在默认端点列表中的端点。该属性的默认值是`*`，表示所有端点都被暴露。

+   `management.endpoints.web.exposure.exclude`: 以逗号分隔的端点 ID 从 HTTP 暴露中排除。虽然没有默认值，但只有`info`和`health`端点被暴露。其余端点对于 HTTP 隐式排除。

+   `management.endpoints.web.exposure.include`: 以逗号分隔的端点 ID 包括在默认的 HTTP 暴露中。该属性可用于暴露那些未包含在默认端点列表中的端点。该属性的默认值是`info`，`health`。

# 健康检查

确保应用程序高性能的一个极其关键的方面是监控应用程序的健康状况。生产级应用程序始终受到专门监控和警报软件的监视。为每个参数配置了阈值，无论是平均响应时间、磁盘利用率还是 CPU 利用率。一旦参数值超过指定的阈值，监控软件通过电子邮件或通知发出警报。开发和运维团队采取必要的措施，确保应用程序恢复到正常状态。

对于 Spring Boot 应用程序，我们可以通过导航到`/actuator/health` URL 来收集健康信息。`health`端点默认启用。对于部署在生产环境中的应用程序，使用`health`端点收集的健康信息可以发送到监控软件进行警报目的。

`health`端点呈现的信息取决于`management.endpoint.health.show-details`属性。以下是该属性支持的值列表：

+   `always`：表示所有信息都应显示给所有用户。

+   `never`：表示永远不显示详细信息。

+   `when-authorized`：表示只有授权角色的用户才能查看详细信息。授权角色可以使用`management.endpoint.health.roles`属性进行配置。

`show-details`属性的默认值为`never`。此外，当用户具有一个或多个端点的授权角色时，用户可以被视为已授权。默认情况下，没有角色被配置为已授权。因此，所有经过身份验证的用户都被视为已授权用户。

`HealthIndicator`是一个重要的接口，它提供了关于应用程序健康状况的指示，例如磁盘空间、数据源或 JMS。`health`端点从应用程序上下文中定义的所有`HealthIndicator`实现 bean 收集健康信息。Spring Boot 带有一组自动配置的健康指标。该框架足够灵活，可以支持自定义健康指标的实现。应用程序的最终健康状态由`HealthAggregator`派生。健康聚合器根据已定义的状态顺序对所有健康指标的状态进行排序。

以下是 Spring Boot 自动配置的`HealthIndicators`列表：

+   `CassandraHealthIndicator`：检查 Cassandra 数据库是否正常运行

+   `DiskSpaceHealthIndicator`：检查是否有足够的磁盘空间可用

+   `DataSourceHealthIndicator`：检查是否可以与数据源建立连接

+   `ElasticSearchHealthIndicator`：检查 elasticsearch 集群是否正常

+   `InfluxDbHealthIndicator`：检查 Influx 服务器是否正常运行

+   `JmsHealthIndicator`：检查 JMS 代理是否正常运行

+   `MailHealthIndicator`：检查邮件服务器是否正常运行

+   `MongoHealthIndicator`：检查 Mongo 数据库是否正常运行

+   `Neo4jHealthIndicator`：检查 Neo4j 服务器是否正常运行

+   `RabbitHealthIndicator`：检查 Rabbit 服务器是否正常运行

+   `RedisHealthIndicator`：检查 Redis 服务器是否正常运行

+   `SolrHealthIndicator`：检查 Solr 服务器是否正常运行

这些健康指标是基于适当的 Spring Boot starter 配置进行自动配置的。

当我们导航到`http://localhost:8080/actuator/health` URL 时，以下是示例磁盘空间健康检查的输出：

```java
{
  "status": "UP",
  "details": {
    "diskSpace": {
      "status": "UP",
      "details": {
        "total": 407250137088,
        "free": 392089661440,
        "threshold": 10485760
      }
    }
  }
}
```

我们可以添加额外的自定义健康指标来包含我们想要查看的信息。自定义健康指标将显示在`health`端点的结果中。创建和注册自定义健康指标非常容易。

以下是自定义健康指标的示例：

```java
package com.packt.springhighperformance.ch09.healthindicators;

import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;
import org.springframework.stereotype.Component;

@Component
public class ExampleHealthCheck extends AbstractHealthIndicator {
    @Override
      protected void doHealthCheck(Health.Builder builder) 
      throws Exception   
   {
        // TODO implement some check
        boolean running = true;
        if (running) {
          builder.up();
        } else {
          builder.down();
        }
    }
}
```

我们必须创建一个 Java 类，该类继承自`AbstractHealthIndicator`。在自定义健康指标类中，我们必须实现`doHealthCheck()`方法。该方法期望传递一个`Health.Builder`对象。如果我们发现健康参数正常，则应调用`builder.up()`方法，否则应调用`builder.down()`方法。

当访问`/actuator/health` URL 时，以下是页面上呈现的输出：

```java
{
  "status": "UP",
  "details": {
    "exampleHealthCheck": {
 "status": "UP"
 },
    "diskSpace": {
      "status": "UP",
      "details": {
        "total": 407250137088,
        "free": 392071581696,
        "threshold": 10485760
      }
    },
    "db": {
      "status": "UP",
      "details": {
        "database": "MySQL",
        "hello": 1
      }
    }
  }
}
```

不需要注册自定义健康指标。`@Component`注解会被扫描，并且该 bean 会被注册到`ApplicationContext`中。

到目前为止，我们已经详细学习了 Spring Boot 并举例说明。接下来的部分将专注于使用 Spring Boot 与微服务。

# 使用 Spring Boot 的微服务

我们现在已经从前面的部分中获得了大量关于 Spring Boot 的信息。有了我们到目前为止所拥有的信息，我们现在有能力使用 Spring Boot 构建微服务。在着手实现我们的第一个 Spring Boot 微服务之前，假设您已经了解了关于微服务的基本信息，包括单体应用程序的问题、微服务的定义以及微服务带来的特性。

# 使用 Spring Boot 的第一个微服务

以下是我们将要开发的微服务的详细信息：

+   我们将实现一个作为微服务的会计服务。

+   这个微服务将是基于 REST 的。这是一种用于开发 Web 服务的架构模式。它专注于使用唯一的 URL 标识应用程序中的每个资源。

+   我们将确定我们需要的 Spring Boot 启动器项目，并相应地生成 Maven 的`pom.xml`文件。

+   我们将实现一个带有一些基本属性的`Account`类。

+   我们将使用 find-by-name 示例方法实现`AccountRepository`。

+   我们将实现控制器类，其中有一个自动装配的存储库。控制器公开了端点。

+   我们还将实现一种将测试数据输入到数据库的方法。

让我们开始吧！

我们将通过使用 Spring Initializr 生成 Spring Boot 应用程序来开始实现。我们必须决定要使用的 Spring Boot 启动项目。我们想要开发一个基于 JPA 的 Web 应用程序。为了在数据库中存储`Account`数据，我们可以使用 MySQL 或 H2。通常，H2 是一个更方便的选择，因为我们不需要设置任何东西。在本章的示例中，我们将使用 MySQL。

以下是要选择的启动项目：

+   Web

+   JPA

+   MySQL 或 H2

+   REST 存储库

我们还可以添加 Spring Boot Actuator 进行应用程序监控，但这对于示例来说并不是必需的。

以下是 Spring Initializr 生成的`pom.xml`文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project  
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
  http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.packt.springhighperformance.ch09</groupId>
  <artifactId>ch-09-accounting-service</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>

  <name>accounting-service</name>
  <description>Example accounting service</description>

  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.0.0.RELEASE</version>
    <relativePath /> <!-- lookup parent from repository -->
  </parent>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-    
    8</project.reporting.outputEncoding>
    <java.version>1.8</java.version>
  </properties>

  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-data-rest</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-hateoas</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.data</groupId>
      <artifactId>spring-data-rest-hal-browser</artifactId>
    </dependency>
    <dependency>
      <groupId>mysql</groupId>
      <artifactId>mysql-connector-java</artifactId>
      <scope>runtime</scope>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>
```

Spring Initializr 生成的另一段代码是 Spring Boot 应用程序：

```java
package com.packt.springhighperformance.ch09.accountingservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AccountingServiceApplication {

  public static void main(String[] args) {
    SpringApplication.run(AccountingServiceApplication.class, args);
  }
}
```

到目前为止，我们应该已经将我们的项目导入到我们首选的 IDE 中。

人们，准备好进行实际开发了。我们将从创建`Account` JPA 实体类开始。我们将使用`@Entity`和`@Table`注解来注释`Account`类。`@Table`注解允许我们提供所需的表名。我们还有一个列，即`accountName`。它存储并表示`Account`的名称。基本上，`Account`实体代表了现实世界中的账户类型。我们添加的另一个重要属性是`id`。`id`代表一个唯一的、自动生成的数字标识符。我们可以使用这个标识符唯一地标识每个账户。`@GeneratedValue`注解允许我们提供在数据库中生成`id`值的方式。将其保持为`AUTO`定义了它取决于数据库自动生成`id`值。`@Column`注解允许我们将`accountName`属性与`ACCT_NAME`数据库字段匹配。

以下是`Account`实体的代码：

```java
package com.packt.springhighperformance.ch09.accountingservice.models;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "accounts")
public class Account {

  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  @Column(name = "ACCT_ID")
  private Long id;

  @Column(name = "ACCT_NAME")
      private String accountName;

  public Account() {
  }

  public Account(String accountName) {
    this.accountName = accountName;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getAccountName() {
    return accountName;
  }

  public void setAccountName(String accountName) {
    this.accountName = accountName;
  }

  @Override
  public String toString() {
    return "Account{"
        + "id=" + id + 
        ", accountName='" + accountName + '\'' +
        '}';
  }

}
```

Spring Data 提供了一个方便的接口来执行常见的数据库操作。这个接口叫做`CrudRepository`。它支持特定类型的基本`Create`、`Read`、`Update`和`Delete`操作。这个接口是由`JpaRepository`接口继承的，它是`CrudRepository`接口的 JPA 特定定义。`JpaRepository`还从`PagingAndSortingRepository`接口继承了排序和分页功能。

有了这个背景，我们接下来的任务是构建一个与`accounts`数据库表交互的接口。以下是`AccountsRepository`类的代码：

```java
package com.packt.springhighperformance.ch09.
accountingservice.repositories;

import java.util.Collection;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import com.packt.springhighperformance.ch09.accountingservice.models.Account;

@RepositoryRestResource
public interface AccountsRepository extends JpaRepository<Account, Long> {

  Collection<Account> findByAccountName(@Param("an") String an);
}
```

在`AccountsRepository`接口中，我们定义了一个方法，用于根据`accountName`从数据库中查找`Account`条目。`CrudRepository`接口非常强大。它将为`findByAccountName`方法生成实现。它可以为所有遵循约定的查询方法生成实现，例如`findBy{model-attribute-name}`。它还返回`Account`类型的对象。

另外，你可能已经注意到，`@RepositoryRestResource`的使用是由 Spring Data REST 模块提供的。它简要地将存储库方法暴露为 REST 端点，无需进一步配置或开发。

现在，我们已经有了实体和存储库。接下来是 Web 应用程序的控制器部分。我们需要创建一个控制器类。以下是`AccountsController`类的代码：

```java
package com.packt.springhighperformance.ch09
.accountingservice.controllers;

import java.util.Collections;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountsController {
  @GetMapping(value = "/account/{name}")
  Map<String, Object> getAccount(@PathVariable String name) {
    return Collections.singletonMap("Account : ", name);
  }
}
```

`AccountsController`代码中的三个值得注意的注解是：

+   @RestController：这个注解是`@Controller`和`@ResponseBody`注解的组合。如果我们使用`@RestController`注解，就不需要定义这两个其他的注解。`@RestController`注解表示该类应该被视为一个控制器，每个端点方法都会作为响应体返回内容。

+   `@GetMapping`：这个注解用于定义 REST `GET`端点映射。

+   `@PathVariable`：这个注解用于获取 URL 路径中提供的值。

还有两件事情。一是数据库和其他重要属性，另一个是在`accounts`表中填充初始数据的方式。

以下是管理应用程序配置部分的`application.properties`文件：

```java
spring.jpa.hibernate.ddl-auto=create-drop
spring.datasource.url=jdbc:mysql://localhost:3306/db_example?useSSL=false
spring.datasource.username=root
spring.datasource.password=root
```

从属性列表中，`spring.jpa.hibernate.ddl-auto`属性确定了基于提供的数据库配置的数据库的初始生成。它确定了 Spring Boot 应用程序是否应该在应用程序启动时创建数据库模式。`none`、`validate`、`update`、`create`和`create-drop`是该属性的可用选项。

在启动应用程序时，我们可能还会收到以下错误：

```java
Establishing SSL connection without server's identity verification is not recommended.
```

我们可以在数据库连接 URL 中使用`useSSL=true`来解决这个警告，就像你在前面的代码示例中看到的那样。

# 向数据库加载示例数据

此时，有必要在数据库的`accounts`表中有一些初始数据。这将帮助我们测试我们开发的账户微服务。Spring 模块提供了多种方法来实现这一点。

# JPA 的初始数据加载方式

Spring Data JPA 提供了一种在应用程序启动时执行数据库操作命令的方式。由于数据库模式将根据 JPA 实体配置和`ddl-auto`属性值在数据库中生成，我们必须注意只在`accounts`表中插入账户记录。以下是实现这一点的步骤：

1.  在`application.properties`文件中添加以下属性：

```java
spring.datasource.initialization-mode=always
```

1.  在项目的`src/main/resources`文件夹中创建一个`data.sql`文件，其中包含`INSERT`查询：

```java
INSERT INTO accounts (ACCT_NAME) VALUES
  ('Savings'),
  ('Current'),
  ('Fixed Deposit'),
  ('Recurring Deposit'),
  ('Loan');
```

就是这样！当我们启动应用程序时，Spring 会自动将数据插入到数据库的`accounts`表中。

# ApplicationRunner 的初始数据加载方式

我们也可以使用`ApplicationRunner`接口来实现这一点。这个接口负责在应用启动时执行`run`方法中定义的代码。

以下是`ApplicationRunner`接口实现的代码：

```java
package com.packt.springhighperformance.ch09.accountingservice;

import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import com.packt.springhighperformance.ch09.accountingservice.models.Account;
import com.packt.springhighperformance.ch09.accountingservice.repositories.AccountsRepository;

@Component
public class AccountsDataRunner implements ApplicationRunner {

  @Autowired
  private AccountsRepository acctRepository;

  @Override
  public void run(ApplicationArguments args) throws Exception {
    Stream.of("Savings", "Current", "Recurring", "Fixed Deposit")
    .forEach(name -> acctRepository.save(new Account(name)));
    acctRepository.findAll().forEach(System.out::println);
  }

}
```

我们已经自动装配了存储库，这样我们就可以访问`AccountsRepository`方法，将`accounts`记录插入到数据库中。

# 微服务客户端

现在我们已经有了微服务，我们必须看看如何消费它。计划是使用 Spring Initializr 创建另一个 Web 应用程序，并使用适当的工具来消费会计微服务。

以下是客户端应用程序的 POM 文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project  
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
  http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.packt.springhighperformance.ch09</groupId>
  <artifactId>ch-09-accounting-service-client</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>

  <name>accounting-service-client</name>
  <description>Example accounting service client</description>

  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.0.0.RELEASE</version>
    <relativePath /> <!-- lookup parent from repository -->
  </parent>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-
    8</project.reporting.outputEncoding>
    <java.version>1.8</java.version>
    <spring-cloud.version>Finchley.M9</spring-cloud.version>
  </properties>

  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-starter-openfeign</artifactId>
 </dependency>

    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <dependencyManagement>
 <dependencies>
 <dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-dependencies</artifactId>
 <version>${spring-cloud.version}</version>
 <type>pom</type>
 <scope>import</scope>
 </dependency>
 </dependencies>
 </dependencyManagement>

  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>

  <repositories>
    <repository>
      <id>spring-milestones</id>
      <name>Spring Milestones</name>
      <url>https://repo.spring.io/milestone</url>
      <snapshots>
        <enabled>false</enabled>
      </snapshots>
    </repository>
  </repositories>

</project>
```

在上述的`pom.xml`文件中，我们使用 Maven 的 dependency-management 元素导入了 Spring Cloud 依赖项。我们还添加了`openfeign` starter 项目。Feign 是一个用于消费 Web 服务并提供 REST 客户端模板设施的客户端工具。

以下是我们 Spring Boot 客户端应用程序中`main`类的代码：

```java
package com.packt.springhighperformance.ch09.accountingclient;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.json.BasicJsonParser;
import org.springframework.boot.json.JsonParser;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class AccountingServiceClientApplication {

  public static void main(String[] args) {
    SpringApplication.run(AccountingServiceClientApplication.class, 
    args);
  }
}

@RestController
class MainController {

  @Value("${accounting.service.url}")
  private String accountingServiceUrl;

  @GetMapping("/account")
  public String getAccountName(@RequestParam("id") Long id) {
    ResponseEntity<String> responseEntity = new 
    RestTemplate().getForEntity(accountingServiceUrl + "/" + id,
    String.class);
    JsonParser parser = new BasicJsonParser();
    Map<String, Object> responseMap = 
    parser.parseMap(responseEntity.getBody());
    return (String) responseMap.get("accountName");
  }
}
```

我们在同一个 Java 文件中定义了 REST 控制器。

以下是定义微服务 URL 并定义运行客户端应用程序的`server.port`的`application.properties`文件：

```java
accounting.service.url=http://localhost:8080/accounts/
server.port=8181
```

# 使用 Spring Cloud 的微服务

Spring Cloud 提供了一种声明式的方法来构建云原生 Web 应用程序。云原生是一种应用程序开发范式，鼓励采用价值驱动的开发最佳实践。Spring Cloud 是建立在 Spring Boot 之上的。Spring Cloud 为分布式系统中的所有组件提供了易于访问所有功能的方式。

Spring Cloud 提供：

+   由 Git 管理的集中式配置数据的版本控制

+   与 Netflix Eureka 和 Ribbon 配对，以便应用程序服务动态发现彼此

+   将负载均衡决策从专用代理负载均衡器推送到客户端服务

外部化配置是 Spring Cloud 的主要优势之一。在下一节中，我们将开发一个示例来展示 Spring Boot 应用程序的外部化配置。

# Spring 微服务配置示例

为了使外部化配置生效，我们需要设置一个集中式配置服务器。配置服务器将存储并提供注册的 Spring Boot 应用程序的配置数据。在本节中，我们将开发一个配置服务器，之前开发的会计服务将作为配置客户端。

以下是 Spring Boot 配置服务器的 POM 文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project      

    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0     
    http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.spring.server.config</groupId>
  <artifactId>spring-config-server</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>

  <name>config-server</name>
  <description>Example spring boot config server</description>

  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.0.0.RELEASE</version>
    <relativePath /> <!-- lookup parent from repository -->
  </parent>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-
    8</project.reporting.outputEncoding>
    <java.version>1.8</java.version>
    <spring-cloud.version>Finchley.M9</spring-cloud.version>
  </properties>

  <dependencies>
    <dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-config-server</artifactId>
 </dependency>

    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <dependencyManagement>
 <dependencies>
 <dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-dependencies</artifactId>
 <version>${spring-cloud.version}</version>
 <type>pom</type>
 <scope>import</scope>
 </dependency>
 </dependencies>
 </dependencyManagement>

  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>

  <repositories>
    <repository>
      <id>spring-milestones</id>
      <name>Spring Milestones</name>
      <url>https://repo.spring.io/milestone</url>
      <snapshots>
        <enabled>false</enabled>
      </snapshots>
    </repository>
  </repositories>
</project>
```

应该注意前面的依赖项中的两个配置：

+   `spring-cloud-dependencies`**：**它提供了 Spring Cloud 项目所需的一组依赖项

+   `spring-cloud-config-server`**：**这是 Spring Boot 的 Spring Cloud starter 项目

以下是`application.properties`文件：

```java
spring.application.name=configserver
spring.cloud.config.server.git.uri:${user.home}\\Desktop\\config-repo
server.port=9000
spring.profiles.active=development,production
```

`spring.cloud.config.server.git.uri`属性指向存储配置的基于 Git 的目录。版本控制由 Git 本身维护。

`spring.profiles.active`表示应用程序要使用的配置文件。对于开发团队来说，拥有多个环境是一个常见的用例。为了为每个环境设置单独的配置，我们可以使用这个属性。

`@EnableConfigServer`注解由 Spring Cloud starter 项目提供。它标记类为配置服务器。以下是 Spring Boot 应用程序`main`类的代码：

```java
package com.spring.server.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.config.server.EnableConfigServer;

@SpringBootApplication
@EnableConfigServer
public class ConfigServerApplication {

  public static void main(String[] args) {
    SpringApplication.run(ConfigServerApplication.class, args);
  }
}
```

完成后，配置服务器准备就绪。在 Git 存储库中，我们已经创建了一个名为`accountingservice.properties`的文件，内容如下：

```java
server.port=8101
```

应用程序启动后，我们可以导航到`http://localhost:9000/accountingservice/default`。由于配置服务器中没有`accountingservice`应用程序的特定配置文件，它会选择默认配置。页面的内容如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/7edd193e-7ab4-4cc6-b503-8829d4ce7a94.png)

正如我们所看到的，`server.port`属性值在页面上呈现。

下一步是构建一个客户端，利用配置服务器中定义的集中式配置。我们必须创建一个带有 web 依赖的 Spring Boot starter 应用程序。

以下是配置服务器客户端的 POM 文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project  

    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0     
    http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.packt.springhighperformance.ch09</groupId>
  <artifactId>ch-09-accounting-service</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>

  <name>accounting-service</name>
  <description>Example accounting service</description>

  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.0.0.RELEASE</version>
    <relativePath /> <!-- lookup parent from repository -->
  </parent>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-
    8</project.reporting.outputEncoding>
    <java.version>1.8</java.version>
  </properties>

  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
    </dependency>
    <dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-starter-config</artifactId>
 <version>2.0.0.M9</version>
 </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>
```

正如我们在前面的 Maven 文件中所看到的，我们需要将`spring-cloud-config-starter`项目添加为依赖项。该项目为应用程序注册为配置服务器客户端提供了必要的配置。

以下是`application.properties`文件：

```java
management.endpoints.web.exposure.include=*
server.port=8888
```

为了将应用程序注册为配置服务器的客户端，我们必须启用管理 Web 端点。服务器将在端口`8888`上运行，根据`application.properties`文件中的配置。

Spring Cloud 在另一个上下文中运行，称为**bootstrap**上下文。引导上下文是主`ApplicationContext`的父级。引导上下文的责任是将外部配置属性从外部源加载到本地外部配置中。建议为引导上下文单独创建一个属性文件。

以下是`bootstrap.properties`文件中的属性：

```java
spring.application.name=accountingservice
spring.cloud.config.uri=http://localhost:9000
```

我们已经定义了与配置属性文件在配置服务器的 Git 目录中存储的名称匹配的应用程序名称。`bootstrap.properties`文件还定义了 Spring Cloud 配置服务器的 URL。

这就是客户端注册到 Spring Cloud 配置服务器的全部内容。在服务器启动时可以看到以下日志条目：

```java
2018-04-01 16:11:11.196 INFO 13556 --- [ main] c.c.c.ConfigServicePropertySourceLocator : Fetching config from server at: http://localhost:9000
....

2018-04-01 16:11:13.303  INFO 13556 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat initialized with port(s): 8101 (http)
....

2018-04-01 16:11:17.825  INFO 13556 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat started on port(s): 8101 (http) with context path ''
```

正如您所看到的，尽管我们已经为客户端应用程序定义了服务器端口为`8888`，但它从配置服务器获取`server.port`属性，并在端口`8101`上启动 Tomcat。当我们渲染`/accounts` URL 时，页面看起来像这样：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/c969f12b-ed37-4680-9537-6167a2e1bb93.png)

本节逐步介绍了创建简单配置服务器和使用配置服务器的客户端的方法。在接下来的部分中，我们将看到一种监视 Spring 微服务的方法。

# 使用 Spring Boot admin 监视微服务

Spring Boot admin 是一个便于监视和管理 Spring Boot 应用程序的应用程序。Spring Boot admin 应用程序的最新版本尚不兼容 Spring 2.0.0。在本节展示的示例中，我们使用了 Spring Boot 1.5.11 快照。Spring Boot admin 版本为 1.5.4。

Spring Boot 客户端应用程序通过 HTTP 向 Spring Boot 管理应用程序注册自己。管理应用程序还可以使用 Spring Cloud Eureka 发现服务发现客户端应用程序。Spring Boot 管理用户界面是在 AngularJS 上构建的，覆盖了执行器端点。

这应该足够作为介绍部分，示例将提供更多见解。让我们首先构建 Spring Boot 管理服务器。

`spring-boot-admin-server`是构建管理服务器应用程序的依赖项。Spring Boot 管理应用程序可以注册多个 Spring Boot 应用程序，因此，Spring Boot 管理应用程序必须是安全的。这就是我们添加 Spring Security starter 项目依赖项的原因。我们将为此应用程序添加基本身份验证，但这并不是限制。我们可以添加高级安全机制，如 OAuth，以保护应用程序。以下是 Spring Boot 管理服务器的 POM 文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project  

    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
    http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.spring.admin</groupId>
  <artifactId>admin-server</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>

  <name>admin-server</name>
  <description>Demo project for Spring Boot</description>

  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>1.5.11.BUILD-SNAPSHOT</version>
    <relativePath /> <!-- lookup parent from repository -->
  </parent>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
    <java.version>1.8</java.version>
  </properties>

  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
 <groupId>de.codecentric</groupId>
 <artifactId>spring-boot-admin-server</artifactId>
 <version>1.5.4</version>
 </dependency>
 <dependency>
 <groupId>de.codecentric</groupId>
 <artifactId>spring-boot-admin-server-ui</artifactId>
 <version>1.5.4</version>
 </dependency>
 <dependency>
 <groupId>org.springframework.boot</groupId>
 <artifactId>spring-boot-starter-security</artifactId>
 </dependency>
 <dependency>
 <groupId>de.codecentric</groupId>
 <artifactId>spring-boot-admin-server-ui-login</artifactId>
 <version>1.5.4</version>
 </dependency>

    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>

  <repositories>
    <repository>
      <id>spring-snapshots</id>
      <name>Spring Snapshots</name>
      <url>https://repo.spring.io/snapshot</url>
      <snapshots>
        <enabled>true</enabled>
      </snapshots>
    </repository>
    <repository>
      <id>spring-milestones</id>
      <name>Spring Milestones</name>
      <url>https://repo.spring.io/milestone</url>
      <snapshots>
        <enabled>false</enabled>
      </snapshots>
    </repository>
  </repositories>

  <pluginRepositories>
    <pluginRepository>
      <id>spring-snapshots</id>
      <name>Spring Snapshots</name>
      <url>https://repo.spring.io/snapshot</url>
      <snapshots>
        <enabled>true</enabled>
      </snapshots>
    </pluginRepository>
    <pluginRepository>
      <id>spring-milestones</id>
      <name>Spring Milestones</name>
      <url>https://repo.spring.io/milestone</url>
      <snapshots>
        <enabled>false</enabled>
      </snapshots>
    </pluginRepository>
  </pluginRepositories>
</project>
```

`application.properties`文件是我们定义访问管理应用程序的安全凭据的地方。以下是`application.properties`文件的内容：

```java
security.user.name=admin
security.user.password=admin
```

`@EnableAdminServer`由 Spring Boot admin 服务器依赖项提供。它表示应用程序作为 Spring Boot admin 应用程序运行。以下是 Spring Boot 应用程序`main`类的代码：

```java
package com.spring.admin.adminserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import de.codecentric.boot.admin.config.EnableAdminServer;

@SpringBootApplication
@EnableAdminServer
public class AdminServerApplication {

  public static void main(String[] args) {
    SpringApplication.run(AdminServerApplication.class, args);
  }
}
```

下一步是构建一个样本应用程序，该应用程序将注册到 Spring Boot 管理应用程序。以下是 POM 文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project  

    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
    http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <parent>
 <groupId>org.springframework.boot</groupId>
 <artifactId>spring-boot-starter-parent</artifactId>
 <version>1.5.11.BUILD-SNAPSHOT</version>
 <relativePath /> <!-- lookup parent from repository -->
 </parent>

  <properties>
    <spring-boot-admin.version>1.5.7</spring-boot-admin.version>
  </properties>

  <dependencies>
    <dependency>
 <groupId>de.codecentric</groupId>
 <artifactId>spring-boot-admin-starter-client</artifactId>
 </dependency>
    <dependency>
 <groupId>org.springframework.boot</groupId>
 <artifactId>spring-boot-starter-actuator</artifactId>
 </dependency>
    <dependency>
 <groupId>org.springframework.boot</groupId>
 <artifactId>spring-boot-starter-security</artifactId>
 </dependency>
</project>
```

我们必须定义以下属性：

+   `spring.boot.admin.url`：该 URL 指向 Spring Boot 管理应用程序。

+   `spring.boot.admin.username`：管理客户端需要使用安全凭据访问管理应用程序。此属性指定了管理应用程序的用户名。

+   `spring.boot.admin.password`：此属性指定了管理应用程序的密码。

+   `management.security.enabled`：此属性表示客户端应用程序是否启用了安全性。

+   `security.user.name`：此属性定义了访问客户端应用程序的用户名。

+   `security.user.password`：此属性指定了访问客户端应用程序的密码。

以下是`application.properties`文件：

```java
spring.boot.admin.url=http://localhost:8080
server.port=8181
spring.boot.admin.username=admin
spring.boot.admin.password=admin
management.endpoints.web.exposure.include=*
security.user.name=user
security.user.password=password
management.security.enabled=false
```

以下是简单 Spring Boot 应用程序类的代码：

```java
package com.spring.admin.client.bootadminclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class BootAdminClientApplication {

  public static void main(String[] args) {
    SpringApplication.run(BootAdminClientApplication.class, args);
  }
}
```

还可以对 Spring Security 提供的默认 Web 安全配置进行自定义。以下是一个示例，演示了允许所有请求进行授权的情况：

```java
package com.spring.admin.client.bootadminclient;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityPermitAllConfig extends WebSecurityConfigurerAdapter {
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests().anyRequest().permitAll().
    and().csrf().disable();
  }
}
```

此时，我们准备启动 Spring Boot 管理和客户端应用程序。当我们导航到 Spring Boot 管理应用程序的 URL 时，将显示以下屏幕，其中列出了所有注册的应用程序：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/ce6c6bfe-dda9-4ed2-bab8-e4df15e96c25.png)

单击应用程序名称右侧的“详细信息”按钮将显示类似于此处所示的界面。详细信息选项卡显示应用程序的健康状况、内存和 JVM 统计信息以及垃圾收集器详细信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/77063b97-a470-4573-9cf0-f7d38b61946d.png)

应用程序详细信息的日志选项卡显示了所有配置的记录器列表。可以更改日志级别。以下是日志的界面：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/d5126e2b-7604-4b50-beae-0e0ef839d2e9.png)

这就是 Spring Boot 管理应用程序的全部内容。它提供了用于监视 Spring Boot 应用程序的生产级界面和详细信息。下一节将提供 Spring Boot 应用程序的性能调优。

# Spring Boot 性能调优

Spring Boot 是一个很好的工具，可以快速启动和开发基于 Spring Framework 的应用程序。毫无疑问，Spring Boot 应用程序的原始版本提供了高性能。但随着应用程序的增长，其性能开始成为瓶颈。这对所有 Web 应用程序来说都是正常情况。当添加不同的功能并且每天增加的请求时，就会观察到性能下降。在本节中，我们将学习 Spring Boot 应用程序的性能优化技术。

# Undertow 作为嵌入式服务器

Spring Boot 提供了可以在 JAR 文件中运行 Web 应用程序的嵌入式服务器。可用于使用的一些嵌入式服务器包括 Tomcat、Undertow、Webflux 和 Jetty。建议使用 Undertow 作为嵌入式服务器。与 Tomcat 和 Jetty 相比，Undertow 提供了更高的吞吐量并且消耗的内存更少。以下比较可能会提供一些见解：

+   吞吐量比较：

| 服务器 样本 错误% 吞吐量 |
| --- |
| Tomcat 3000 0 293.86 |
| Jetty 3000 0 291.52 |
| Undertow 3000 0 295.68 |

+   堆内存比较：

| 服务器 堆大小 已使用 最大 |
| --- |
| Tomcat 665.5 MB 118.50 MB 2 GB |
| Jetty 599.5 MB 297 MB 2 GB |
| Undertow 602 MB 109 MB 2 GB |

+   线程比较：

| 服务器 活动 已启动 |
| --- |
| Tomcat 17 22 |
| Jetty 19 22 |
| Undertow 17 20 |

从前面的比较中，Undertow 看起来是 Spring Boot 应用程序中嵌入式服务器的明显选择。

# 使用@SpringBootApplication 注解的开销

`@SpringBootApplication`注解是为那些习惯于使用`@ComponentScan`、`@EnableAutoConfiguration`和`@Configuration`注解 Spring 类的开发人员提供的。因此，`@SpringBootApplication`注解相当于使用三个带有默认配置的注解。隐式的`@ComponentScan`注解扫描在基本包（Spring Boot 应用程序主类的包）和所有子包中定义的 Java 类。当应用程序在规模上显著增长时，这会减慢应用程序的启动速度。

为了克服这一点，我们可以用单独的注解替换`@SpringBootApplication`注解，其中我们提供要与`@ComponentScan`一起扫描的包路径。我们还可以考虑使用`@Import`注解来仅导入所需的组件、bean 或配置。

# 摘要

本章以对 Spring Boot、Spring Cloud、微服务以及它们的综合详细信息开始。我们涵盖了 Spring Initializr 的细节，Spring Boot starter 项目，并学习了如何创建我们的第一个 Spring Boot 应用程序。然后，我们了解了 Spring Boot 执行器和执行器提供的生产级功能。应用程序健康检查和端点的细节对于生产就绪的应用程序非常重要。

在本章的后面，我们迁移到了微服务的世界。我们学习了 Spring Boot 如何利用功能来构建微服务。我们使用 Spring Boot 和 Spring Cloud 开发了一个支持外部化配置的微服务。我们还研究了 Spring Boot 管理器集成，用于监控 Spring Boot 应用程序。最后但同样重要的是，我们学习了一些提高 Spring Boot 应用程序性能的技术。相当庞大的内容，不是吗？

到目前为止，您对 Spring 和基本上任何基于 Java 的 Web 应用程序的性能评估和性能调优有很好的理解。这就是本书的范围。在向前迈进一步时，您可以学习 JVM 类加载机制、Spring Batch 框架、微服务设计模式、微服务部署和基础设施即服务（IaaS）。我们希望您会发现这些内容有帮助。
