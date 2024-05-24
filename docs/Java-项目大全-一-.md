# Java 项目大全（一）

> 原文：[JAVA PROJECTS](https://libgen.rs/book/index.php?md5=C751311C3F308045737DA4CD071BA359)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 零、前言

随着 Java8 的引入，Java 发生了巨大的变化，这个变化随着新版本 Java8 以及 Java8 和 11 被提升到了一个全新的水平。Java 有着悠久的历史，已经有 20 多年的历史了，但同时，它是新的、函数式的、反应式的和性感的。这是一种开发人员喜爱的语言，同时也是许多企业项目开发人员语言的首选。

从 Java11 开始，现在学习 Java 可能比以前更有利可图。我们鼓励您通过学习 Java 开始您的专业开发生涯，在本书中我们已经尽了最大的努力来帮助您沿着这条道路前进。我们把这本书的主题组合起来，这样就很容易开始，而且你可以感觉到事情进展得很快。同时，我们也尝试着走得更远，为专业开发人员指明了前进的道路。

时间的沙子不停地移动，我发现了函数式编程。

我很清楚为什么写副作用免费代码有效！我被迷住了，开始和 Skara、克鲁和埃尔朗一起玩。不可变性是这里的标准，但是，我想知道传统算法是如何在函数环境中看到的，并开始学习它。

数据结构永远不会原地突变。相反，将创建数据结构的新版本。最大化共享的复制和写作策略是一个有趣的策略！所有这些小心的同步根本不需要！这些语言配备了垃圾收集。因此，如果不再需要某个版本，运行时将负责回收内存。不过，一切都来得正是时候！阅读这本书将帮助你看到，我们不需要牺牲算法性能，同时避免原地变异！

# 这本书是给谁的

这本书是给任何想学习 Java 编程语言的人准备的。无需编程经验。如果你有先例，它将帮助你更容易地读完这本书。

# 这本书的内容

第 1 章“Java11 入门”，为您提供 Java 入门，帮助您在计算机上安装 Java，并使用新的 JShell 运行第一个交互式程序。

第 2 章、“第一个真正的 Java 程序-排序名称”，教您如何创建开发项目。我们将创建程序文件并编译代码。

第 3 章、“优化专业排序代码”，进一步开发代码，使代码可重用，不仅是玩具。

第 4 章、“策划者——创造一个游戏*”，就是乐趣开始的时候。我们开发了一个有趣的游戏应用，并不像最初看起来那么简单，但我们会做到的。

第 5 章、“扩展游戏——跑得并行，跑得更快”，展示如何利用现代架构的多处理器功能。这是一个非常重要的章节，详细介绍了只有少数开发人员真正了解的技术。

第 6 章、“让我们的游戏专业化——做一个 Web 应用*”，将用户界面从命令行转变为基于 Web 浏览器，提供更好的用户体验。

第 7 章“使用 REST 构建一个商业 Web 应用”，带领您完成一个具有许多商业应用特性的应用的开发。我们将使用标准的 REST 协议，它已经在企业计算领域取得了进展。

第 8 章“扩展我们的电子商务应用”，利用脚本和 Lambda 表达式等现代语言特性，帮助您进一步开发应用。

第 9 章“使用反应式编程构建会计应用”，教您如何使用反应式编程解决一些问题。

第 10 章“将 Java 知识提升到专业水平”，对 Java 开发人员生活中起重要作用的开发人员话题进行了鸟瞰，这将指导您进一步成为专业开发人员。

# 充分利用这本书

为了让自己沉浸在这本书的内容中并吸收技能和知识，我们假设您已经有了一些编程经验。我们不做太多假设，但希望您已经知道什么是变量，计算机有内存、磁盘、网络接口，以及它们通常是什么。
除了这些基本技能外，还有一些技术要求你需要尝试一下书中的代码和例子。你需要一台今天可以使用的电脑，可以运行 Windows、Linux 或 OSX。你需要一个操作系统，也许，这就是你需要支付的全部费用。您需要的所有其他工具和服务都是开源的，并且是免费的。其中一些还可以作为带有扩展特性集的商业产品提供，但是在本书的范围内，开始学习 Java9 编程时，这些特性是不需要的。Java、开发环境、构建工具以及我们使用的所有其他软件组件都是开源的。

# 下载示例代码文件

您可以从您的帐户[下载本书的示例代码文件 www.packtpub.com](http://www.packtpub.com)。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，将文件直接通过电子邮件发送给您。

您可以通过以下步骤下载代码文件：

1.  在[登录或注册 www.packtpub.com](http://www.packtpub.com/)[。](http://www.packt.com)
2.  选择“支持”选项卡。
3.  点击代码下载和勘误表。
4.  在搜索框中输入图书名称，然后按照屏幕上的说明进行操作。

下载文件后，请确保使用最新版本的解压缩或解压缩文件夹：

*   用于 Windows 的 WinRAR/7-Zip
*   Mac 的 Zipeg/iZip/UnRarX
*   用于 Linux 的 7-Zip/PeaZip

这本书的代码包也托管[在 GitHub 上](https://github.com/PacktPublishing/Java-Projects)。如果代码有更新，它将在现有 GitHub 存储库中更新。

我们的丰富书籍和视频目录中还有其他代码包，可在[这个页面](https://github.com/PacktPublishing/)上找到。看看他们！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。[您可以在这里下载](https://www.packtpub.com/sites/default/files/downloads/JavaProjects_ColorImages.pdf)。

# 使用的约定

这本书中使用了许多文本约定。

`CodeInText`：表示文本中的码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、伪 URL、用户输入和 Twitter 句柄。下面是一个例子：“最简单的方法是启动`new Thread()`，然后在线程上调用`start()`方法。”

代码块设置如下：

```java
 private boolean isNotUnique(Color[] guess) {
        final var alreadyPresent = new HashSet<Color>();
        for (final var color : guess) {
            if (alreadyPresent.contains(color)) {
                return true;
            }
            alreadyPresent.add(color);
        }
        return false;
    }
```

当我们希望提请您注意代码块的特定部分时，相关行或项以粗体显示：

```java
@Override 
 public boolean equals(Object o) { 
     if (this == o) return true; 
     if (o == null || getClass() != o.getClass()) return false; 
     MyObjectJava7 that = (MyObjectJava7) o; 
     return Objects.equals(field1, that.field1) && 
             Objects.equals(field2, that.field2) && 
             Objects.equals(field3, that.field3); 
 }
```

任何命令行输入或输出的编写方式如下：

```java
Benchmark     (nrThreads)  (queueSize)  Score   Error 
playParallel            1           -1 15,636  ± 1,905 
playParallel            1            1 15,316  ± 1,237 
playParallel            1           10 15,425  ± 1,673 
playParallel            1          100 16,580  ± 1,133 
playParallel            1      1000000 15,035  ± 1,148 
playParallel            4           -1 25,945  ± 0,939 
```

**粗体**：表示一个新术语、一个重要单词或屏幕上显示的单词。例如，菜单或对话框中的单词会像这样出现在文本中。下面是一个例子：“如果您启动了 **VisualVM**，您可以选择任何 JVM 进程的 Threads 选项卡，并查看 JVM 中的实际线程

警告或重要提示如下所示。

提示和窍门是这样出现的。

# 一、Java11 入门

你想学习 Java，你有充分的理由。Java 是一种成熟的现代应用编程语言，广泛应用于电信、金融等行业。Java 开发人员的职位是最多的，而且可能是薪水最高的。除其他外，这使得年轻的专业人士学习这门语言有利可图。

另一方面，这并非毫无道理。Java 语言、工具以及它周围的整个基础设施都是复杂和复杂的。成为 Java 专业人员不会在一天或一周内发生；这是一项多年的工作。要成为一名 Java 专家，您不仅需要了解编程语言，还需要了解面向对象编程原则、开源库、应用服务器、网络、数据库等许多方面。然而，学习语言是绝对的最低限度。所有其他实践都是基于此。在本书中，您将学习 Java 版本 18.9，也称为 Java11，以及其他内容。您不仅要学习语言，还将学习最重要的工具，如 Maven、gradle、spring、Guice、SoapUI；HTTP/2、SOAP、REST 等协议；如何在敏捷专业团队中工作；以及团队应该使用哪些工具进行合作。在最后一章中，您甚至将学习如何规划您打算作为 Java 开发人员开始的职业生涯。

在本章中，您将介绍 Java 环境，并将逐步给出如何安装、编辑示例代码、编译和运行 Java 的说明。您将了解在开发中帮助的基本工具，无论是 Java 的一部分还是其他供应商提供的。本章将介绍以下主题：

*   Java 简介
*   在 Windows、Linux 和 MacOS 上安装
*   执行`jshell`
*   使用其他 Java 工具
*   使用集成开发环境

# Java 入门

就像穿过森林里的小路。你可以把注意力集中在道路的碎石上，但这是毫无意义的。相反，你可以欣赏你周围的景色、树木、鸟儿和环境，这更令人愉快。这本书很相似，因为我不会只关注语言。我会不时地介绍一些接近道路的话题，并将给你一些概述和指导，你可以在你完成这本书之后去哪里。我不仅要教你语言，而且还将介绍一些算法、面向对象的编程原则、围绕 Java 开发的工具以及专业人员如何工作。这将与我们将要遵循的编码示例混合。最后，最后一章将全面讨论这个主题，接下来要学习什么，以及如何进一步成为一个专业的 Java 开发人员。

到这本书出版的时候，[Java 已经完成了 22 年](http://www.oracle.com/technetwork/java/javase/overview/javahistory-index-198355.html)。在这段时间里，语言发生了很大的变化，变得更好了。真正要问的问题不是它在这里呆了多久，而是它会呆多久？这门语言还值得学吗？自从 Java 诞生以来，[有许多新的语言被开发出来](http://blog.takipi.com/java-vs-net-vs-python-vs-ruby-vs-node-js-who-reigns-the-job-market/)。这些语言更加现代，并且具有函数式编程特性，顺便说一句，Java 从版本 8 开始就有了这些特性。很多人说 Java 是过去的，未来是 Scala、Swift、Go、Kotlin、JavaScript 等等。您可以将许多其他语言添加到此列表中，对于每一种语言，您都可以找到一篇庆祝 Java 诞生的博客文章。对于这一问题，有两种答案：一种是务实的商业方法，另一种更注重工程：

*   考虑到 COBOL 仍在金融业中得到积极应用，而且 COBOL 开发人员的薪酬可能比 Java 开发人员高，所以说作为一名 Java 开发人员，您将在未来 40 年内找到合适的职位并不太冒险。就我个人而言，我会赌 100 多年，但考虑到我的年龄，预测未来 20 到 40 年是不公平的。
*   Java 不仅是一种语言，也是一种技术，您将从本书中了解到一些。该技术包括 **Java 虚拟机**（**JVM**），通常被称为 JVM，为多种语言提供了运行环境；例如 Kotlin 和 Scala，没有 JVM 就无法运行。即使 Java 将被预示，JVM 仍将是企业场景中的头号玩家。

理解和学习 JVM 的基本操作几乎和语言本身一样重要。Java 是一种编译和解释语言。它是一种特殊的野兽，能锻造两个世界的精华。在 Java 之前，有解释语言和编译语言。

解释器从源代码中读取解释语言，然后解释器执行代码。在每种语言中，都有一些初步的词法和语法分析步骤；然而，在这之后，解释器作为程序本身由处理器执行，解释器不断地解释程序代码，以知道该做什么。编译语言是不同的。在这种情况下，源代码被编译成二进制文件（Windows 平台上的`.exe`文件），由操作系统加载，处理器直接执行。编译后的程序通常运行得更快，但通常有一个较慢的编译阶段，这可能会使开发速度变慢，而且执行环境也不是那么灵活。Java 结合了这两种方法。

要执行 Java 程序，必须将 Java 源代码编译成 JVM 字节码（`.class`文件），JVM 加载该字节码并对其进行解释或编译。嗯…是解释的还是编译的？Java 附带的东西是**即时**（JIT）编译器。这使得编译阶段的计算密集型和编译语言的编译相对缓慢。JVM 首先开始解释 Java 字节码，同时跟踪执行统计信息。当它收集到足够的代码执行统计信息时，它会编译成本机代码（例如，Intel/AMD 平台上的 x86 代码），以便直接执行频繁执行的代码部分，并不断解释很少使用的代码片段。毕竟，为什么要浪费昂贵的 CPU 时间来编译一些很少使用的代码呢？（例如，在启动期间读取配置的代码，除非应用服务器重新启动，否则不会再次执行。）字节码的编译速度很快，并且代码生成只针对有回报的段。

JIT 使用代码执行的统计信息来优化代码，这也很有趣。例如，如果它可以看到某个条件分支在 99% 的情况下执行，而另一个分支仅在 1% 的情况下执行，那么它将生成运行速度很快的本机代码，从而支持频繁的分支。如果该部分程序的行为随时间而变化，并且统计数据显示比率发生了变化，那么 JIT 会不时地自动重新编译字节码。这一切都是自动的和幕后的。

除了自动编译之外，JVM 还有一个非常重要的特性，它管理 Java 程序的内存。现代语言的执行环境是这样做的，Java 是第一个拥有自动垃圾收集（GC）的主流语言。在 Java 之前，我用 C 编程了 20 年，跟踪所有内存分配情况，并且在程序不再需要时忘记释放内存是一个巨大的痛苦。忘记代码中的单个点的内存分配，而长时间运行的程序会慢慢地耗尽所有内存。这种问题在 Java 中实际上已经不存在了。我们必须为 GC 支付一个代价，它需要处理器容量和一些额外的内存，但这在大多数企业应用中我们并不缺少。一些特殊的程序，比如控制重型卡车刹车的实时嵌入式系统，可能没有那么豪华。

这些程序仍然是用汇编或 C 语言编写的。对于我们其他人来说，我们有 Java，尽管这对许多专业人士来说似乎很奇怪，但即使是几乎实时的程序，如高频交易应用，也是用 Java 编写的。

这些应用通过网络连接到证券交易所，它们根据市场变化在毫秒内进行股票买卖。Java 能够做到这一点。执行编译的 Java 代码所需的 Java 运行时环境（也包括 JVM 本身）包含允许 Java 程序访问网络、磁盘上的文件和其他资源的代码。为此，运行时包含代码可以实例化、执行的高级类，以及执行低级作业的高级类。你也要这样做。这意味着实际的 Java 代码不需要处理 IP 包、TCP 连接，甚至当它想要在某些微服务架构中使用或提供 REST 服务时，也不需要处理 HTTP。它已经在运行库中实现，程序员所要做的就是在代码中包含类，并在与程序匹配的抽象级别上使用它们提供的 API。当你用 Java 编程时，你可以专注于你想要解决的实际问题，那就是*业务*代码，而不是底层的系统代码。如果它不在标准库中，您将在某个外部库中的某个产品中找到它，并且您很可能会找到解决该问题的开源解决方案。

这也是 Java 的一个优点。有大量的开源库可用于各种不同的用途。如果您找不到适合您的问题的库，并且开始编写一些低级代码，那么您可能是做错了什么。本书中的一些主题很重要，比如类加载器或反射，不是因为你必须每天使用它们，而是因为它们被框架使用，了解它们有助于你理解这些框架是如何工作的。如果不使用反射或直接编写自己的类加载器或程序多线程就无法解决问题，那么您可能选择了错误的框架。几乎可以肯定有一个很好的例子：ApacheCommons 、Google 和软件行业的许多其他重要参与者将其 Java 库发布为开源。

多线程编程也是如此。Java 从一开始就是一个多线程编程环境。JVM 和运行时支持执行代码的程序。执行在多个线程上并行运行。有一些运行时语言结构支持程序的并行执行。这些构造中的一些是非常低级的，而另一些则处于高度抽象级别。多线程代码利用多核处理器，这是更有效的。这些处理器越来越普遍。20 年前，只有高端服务器有多个处理器，只有数字 Alpha 处理器有 64 位架构，CPU 时钟高于 100MHz。10 年前，多处理器结构在服务器端很常见，大约 5 年前，多核处理器出现在一些台式机和笔记本电脑上；今天，甚至手机也有。当 Java 在 1995 年诞生时，创造它的天才们已经看到了这个未来。

他们设想 Java 是一种只写一次，可以在任何地方运行的语言。当时，该语言的第一个目标是浏览器中运行的 Applet。今天，许多人认为（我也同意这种观点）Applet 是一个错误的目标，或者至少事情没有以正确的方式进行。到目前为止，您在互联网上遇到小程序的频率将低于 Flash 应用或恐龙。更重要的是，applet 接口在 Java9 中已经被弃用了，这使得人们认为 Applet 并不好。

然而，与此同时，Java 解释器也在不使用任何浏览器的情况下执行服务器和客户端应用。此外，随着语言和执行环境的发展，这些应用领域变得越来越重要。如今，Java 主要用于企业计算和移动应用，主要用于 Android 平台。未来，随着**物联网**（**IoT**）越来越多地进入人们的视野，环境在嵌入式系统中的应用也越来越广泛。

# 版本号

Java 版本控制是不断变化的。这不仅仅意味着版本号在从一个版本到另一个版本的变化。这是很明显的；毕竟，这就是版本号的意义所在。然而，在 Java 中，版本号的结构也在改变。Java 从版本 1.0 开始（惊喜！）紧接着是 1.1 版。下一个版本是 1.2，它与以前的版本有很大的不同，人们开始称它为 Java2。然后，我们使用 Java1.3 直到 Java1.8。就我们考虑版本号的结构而言，这是一个稳定的时期。然而，下一个 Java 版本在 2017 年被命名为 Java9，而不是去年的 1.9。这是有道理的，因为经过 22 年的开发和 9 次发布，版本号的`1.`部分并没有真正意义。没有人期待一个“真正的”Java2.0，它与任何其他版本有如此大的不同，以至于它应该有`2.`版本前缀。实际上，Java 版本实际上是 1、2、3 等等；它们只是被命名为 1.1、1.2、1.3 等等。

您可以预期，在版本号格式发生巨大变化之后，Java 的下一个版本将是 Java10。一点也不。甲骨文决定使用基于日期的版本号。点之前的版本号的第一部分将是两位数的年份，如 2018 年发布的版本的`18`。点后面的部分是月份的数字，通常是 3 月的`3`，9 月的`9`。因此，当您看到 Java 版本号 18.3 时，您马上就会知道这个版本是在 2018 年 3 月发布的，按照旧的命名法，实际上是 Java10。

# 安装 Java

要开发、编译和执行 Java 程序，需要 Java 执行环境。由于我们通常用于软件开发的操作系统不包含预先安装的语言，因此您必须下载它。尽管该语言有多种实现，但我建议您从 Oracle 下载该软件的正式版本。Java 的官方网站是[这个页面](http://java.com)，这是该语言最新版本的下载站点。在撰写本书时，Java 的第 11 个版本尚未发布。早期预发布版本可通过[这个页面](http://jdk.java.net/11/)下载。稍后，还将从以下位置提供发布版本：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/cdba56ff-6616-41ce-afe4-f39d1f4b45f9.png)

您可以从这里下载的是所谓的早期访问版本的代码，它只能用于实验，任何专业人士都不应将其用于商业目的。

在页面上，您必须单击单选按钮才能接受，但必须单击许可证。之后，您可以单击直接启动安装工具包下载的链接。许可证是一个特殊的早期访问许可版本，您作为专业人士，只有在您同意条款的情况下才应仔细阅读、理解和接受该版本。

对于 Windows 32 和 64 位系统、MacOS、Linux 32 和 64 位版本、Linux for ARM 处理器、Solaris for SPARC 处理器系统和 Solaris x86 版本，有一个单独的安装工具包。由于不太可能使用 Solaris，因此我将仅详细介绍 Windows、Linux 和 MacOS 的安装过程。在后面的章节中，示例将始终是 MacOS，但是由于 Java 是一种*编写一次、在任何地方运行*的语言，因此在安装之后没有区别。目录分隔符的倾斜方式可能不同，类路径分隔符字符在 Windows 上是分号而不是冒号，终端或命令应用的外观也不同。然而，在重要的地方，我将尽量不忘记提到它。

让您感到困惑的是，这些操作系统版本的 Java 下载都列出了一个 JRE 链接和一个 JDK 链接。**JRE** 代表 **Java 运行时环境**，它包含运行 Java 程序所需的所有工具和可执行文件。**JDK** 是 **Java 开发工具包**，包含开发 Java 程序所需的所有工具和可执行文件，包括 Java 程序的执行。换句话说，JDK 包含自己的 JRE。现在，您需要做的就是下载 JDK。

安装的一个要点是在三个操作系统中的每一个上都是相同的，您必须在安装之前做好准备要安装 Java，您应该具有管理权限。

# 在 Windows 上安装

Windows 上的安装过程从双击下载的文件开始。它将启动安装程序并向您显示欢迎屏幕。Windows 10 可能会要求您具有安装 Java 的管理员权限：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/99bcd7e5-8dbd-4e20-a81b-2b5a7e22ac88.png)

按下“下一步”按钮可获得一个窗口，您可以在其中选择要安装的部件，并且，我们还可以更改 Java 将安装的位置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/f2eb6810-ed8a-4b2e-8be6-4a123638588c.png)

让我们在这里保留默认设置，这意味着我们将安装 Java 的所有下载部分，然后按“下一步”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/6123e3d1-bc48-42fe-9642-011a1ced73f3.png)

当 Java 正在安装时，我们会看到一个进度屏幕。这是一个相当快的过程，不超过 10 秒。安装 Java 后，我们会看到一个确认屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/b42be226-5cfd-43c6-959a-9175e1ad799d.png)

我们可以按关闭键。可以按下“下一步”按钮，打开浏览器，进入一个页面，描述我们可以使用 Java 执行的下一步操作。使用预发布版本会导致 HTTP404 错误。当你读这本书的时候，这个问题有望得到解决。

最后一步是设置环境变量`JAVA_HOME`。为此，在 Windows 中，我们必须打开控制中心并选择“编辑帐户的环境变量”菜单：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/25e9b910-88e7-45dd-9c7e-caac0194c6f9.png)

这将打开一个新窗口，我们应该使用该窗口为当前用户创建新的环境变量：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/c6c955f2-91bd-450a-b82f-f4f2699fd6fa.png)

新变量的名称必须是`JAVA_HOME`，值应该指向 JDK 的安装目录：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/6c14fe8d-1bb2-4954-92b2-0398ca203ae3.png)

大多数系统上的这个值是`C:\Program Files\Java\jdk-11`。许多 Java 程序和工具都使用它来定位 Java 运行时。

# 在 MacOS 上安装

在本节中，我们将逐步了解如何在 MacOS 平台上安装 Java。我将描述在编写本书时发布的版本的安装过程。到目前为止，Java18.9EarlyAccess 版本的安装有点棘手。Java18.9 的发行版很可能有与 Java9 相似或相同的安装步骤。

Java 的 MacOS 版本以`.dmg`文件的形式出现。这是 MacOS 的打包格式。要打开它，只需双击浏览器保存的`Download`文件夹中的文件，操作系统就会将该文件挂载为只读磁盘映像：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/868d1814-0b79-410b-ad40-ce26bdb41e6a.png)

这个磁盘上只有一个文件安装映像。双击 Finder 应用中的文件名或图标，安装过程将开始：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/6e29bd79-5e55-437c-8ab9-cec87ee7662d.png)

第一个屏幕是欢迎屏幕。单击“继续”，您将看到概览页面，其中显示将要安装的内容。

您将看到一个标准的 Java 安装，这并不奇怪。这次，这个按钮被称为“安装”。单击它，您将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/e3f30445-70d8-4eb2-b2fb-b6ac4983da2e.png)

此时您必须为管理用户提供登录参数（用户名和密码）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/8b157760-5b5a-4928-a3e7-312b11e2313d.png)

提供后，安装开始，几秒钟后，您将看到摘要页面：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/09d16861-59d4-47ea-aa86-93f062e6bc78.png)

点击关闭，你就准备好了。你的 Mac 上安装了 Java。或者，您可以卸载安装盘，稍后还可以删除`.dmg`文件。您将不需要它，如果需要，您可以随时从 Oracle 下载它。

最后一件事是检查安装是否正常。吃布丁就是证据。启动一个终端窗口，在提示符处键入`java -version`；Java 将告诉您已安装的版本。

在下面的屏幕截图中，您可以看到 my workstation 上的输出以及便于在不同版本的 Java 之间切换的 MacOS 命令：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/1ea3c678-d986-4a00-aeee-ad01d2756313.png)

在前面的屏幕截图中，您可以看到我已经安装了 Java11 版本，同时，我还安装了 Java18.9 早期版本，我将用它来测试本书中 Java 的新特性。

# 在 Linux 上安装

在 Linux 上安装 Java 有几种方法，这取决于它的风格。在这里，我将描述一种安装方法，它在所有风格上的工作方式或多或少都是相同的。我用的是 Debian。

第一步与在任何其他操作系统中下载安装工具包的步骤相同。在 Linux 中，您应该选择一个以`tar.gz`结尾的包。这是一种压缩的存档格式。您还应该仔细选择与计算机中的处理器和 32/64 位操作系统版本相匹配的包。包下载完成后，需要切换到 root 模式，发出`su`命令。这是您在以下屏幕截图中看到的第一个命令，显示了安装命令：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/06eb92d5-f573-49b0-9268-148cba25dc04.png)

`tar`命令将存档解压缩到一个子文件夹中。在 Debian 中，此子文件夹必须移动到`/opt/jdk`，而`mv`命令用于此目的。这两个`update-alternatives`命令是 Debian 特有的。这些命令告诉操作系统使用这个新安装的 Java，以防已经安装了旧的 Java。我用来在虚拟机上测试和演示安装过程的 Debian 附带了一个有 7 年历史的 Java 版本。

安装的最后一步与检查安装是否成功发出了`java -version`命令的任何其他操作系统相同。对于 Linux，这一点更为重要。安装过程不会检查下载的版本是否与操作系统和处理器架构匹配。

# 设置 JAVA 主目录

`JAVA_HOME`环境变量在 Java 中起着特殊的作用。即使 JVM 可执行文件`java.exe`或`java`位于`PATH`（因此，您可以通过键入名称`java`来执行它，而无需在命令提示符中指定目录）（终端），建议您使用正确的 Java 安装来设置此环境变量。变量的值应该指向已安装的 JDK。有许多与 Java 相关的程序，例如 Tomcat 或 Maven，使用这个变量来定位已安装和当前使用的 Java 版本。在 MacOS 中，设置这个变量是不可避免的。

在 MacOS 中，当您键入`java`时开始执行的程序是一个包装器，它首先查看`JAVA_HOME`来决定启动哪个 Java 版本。如果未设置此变量，MacOS 将自行决定，从可用的已安装 JDK 版本中进行选择。要查看可用版本，可以发出以下命令：

```java
~$ /usr/libexec/java_home -V
Matching Java Virtual Machines (13):
    11, x86_64: "Java SE 11-ea" /Library/Java/JavaVirtualMachines/jdk-11.jdk/Contents/Home
    10, x86_64: "Java SE 10"    /Library/Java/JavaVirtualMachines/jdk-10.jdk/Contents/Home
    9.0.1, x86_64:      "Java SE 9.0.1" /Library/Java/JavaVirtualMachines/jdk-9.0.1.jdk/Contents/Home
    9, x86_64:  "Java SE 9-ea"  /Library/Java/JavaVirtualMachines/jdk-9.jdk/Contents/Home
    1.8.0_92, x86_64:   "Java SE 8"     /Library/Java/JavaVirtualMachines/JDK1.8.0_92.jdk/Contents/Home
    1.8.0_20, x86_64:   "Java SE 8"     /Library/Java/JavaVirtualMachines/JDK1.8.0_20.jdk/Contents/Home
    1.8.0_05, x86_64:   "Java SE 8"     /Library/Java/JavaVirtualMachines/JDK1.8.0_05.jdk/Contents/Home
    1.8.0, x86_64:      "Java SE 8"     /Library/Java/JavaVirtualMachines/JDK1.8.0.jdk/Contents/Home
    1.7.0_60, x86_64:   "Java SE 7"     /Library/Java/JavaVirtualMachines/JDK1.7.0_60.jdk/Contents/Home
    1.7.0_40, x86_64:   "Java SE 7"     /Library/Java/JavaVirtualMachines/JDK1.7.0_40.jdk/Contents/Home
    1.7.0_21, x86_64:   "Java SE 7"     /Library/Java/JavaVirtualMachines/JDK1.7.0_21.jdk/Contents/Home
    1.7.0_07, x86_64:   "Java SE 7"     /Library/Java/JavaVirtualMachines/JDK1.7.0_07.jdk/Contents/Home
    1.7.0_04, x86_64:   "Java SE 7"     /Library/Java/JavaVirtualMachines/1.7.0.jdk/Contents/Home

/Library/Java/JavaVirtualMachines/jdk-11.jdk/Contents/Home
```

然后您将得到已安装 JDK 的列表。注意，命令是小写的，但是选项是大写的。如果您不向程序提供任何选项和参数，它只会返回它认为最新、最适合该用途的 JDK。当我从终端窗口复制命令的输出时，您可以看到我的机器上安装了相当多的 Java 版本。

程序响应的最后一行是 JDK 的主目录，这是默认的。您可以使用它来使用一些 bash 编程来设置您的`JAVA_HOME`变量：

```java
export JAVA_HOME=$(/usr/libexec/java_home)
```

您可以将此文件放入`.bashrc`文件中，每次启动终端应用时都会执行该文件，因此`JAVA_HOME`始终设置。如果您想使用不同版本，可以使用`-v`，这次使用小写选项，到同一个工具，如下所示：

```java
export JAVA_HOME=$(/usr/libexec/java_home -v 1.8)
```

参数是要使用的 Java 版本。请注意，此版本控制将变为以下内容：

```java
export JAVA_HOME=$(/usr/libexec/java_home -v 11)
```

如果您想使用 JavaJDKEarlyAccess 版本，而不是 1.11，那么对于同样的情况没有一个解释。

注意，还有一个环境变量对 Java 很重要-`CLASSPATH`。我们稍后再谈。

# 执行 JShell

现在我们已经花了很多时间安装 Java，是时候让你的手指烧伤了。当我们使用 Java18.9 时，有一个新的工具可以帮助开发人员使用该语言。这是一个**读取-求值-打印-循环**（**REPL**）工具，许多语言工具集都包含这个工具，也有来自 Java 的实现，但是版本 9 是第一个包含这个特性的现成工具。

REPL 是一个具有交互式提示和语言命令的工具，可以直接输入这些命令，而无需编辑一些独立的文件。直接执行输入的命令，然后循环再次启动，等待用户键入下一个命令。

这是一个非常有效的工具，可以在不延迟编辑、编译和加载的情况下尝试一些语言构造。这些步骤由 REPL 工具自动透明地完成。

Java18.9 中的 REPL 工具称为 JShell。要启动它，只需键入它的名称。如果它不在`PATH`上，则键入 Java18.9 附带的 JShell 的完整路径，如下例所示：

```java
$ jshell | Welcome to JShell -- Version 11-ea | For an introduction type: /help intro jshell>
```

JShell 以交互方式启动，它显示的提示是`jshell>`，以帮助您识别 JShell 正在运行。输入的内容由程序读取，而不是由操作系统外壳读取。由于这是您第一次启动 JShell，它告诉您键入`/help intro`。我们开始吧。它将打印出一个关于 JShell 是什么的简短文本，如下代码所示：

```java
jshell> /help intro
|  
|                                   intro
|                                   =====
|  
|  The jshell tool allows you to execute Java code, getting immediate results.
|  You can enter a Java definition (variable, method, class, etc), like:  int x = 8
|  or a Java expression, like:  x + x
|  or a Java statement or import.
|  These little chunks of Java code are called 'snippets'.
|  
|  There are also the jshell tool commands that allow you to understand and
|  control what you are doing, like:  /list
|  
|  For a list of commands: /help
```

好的，我们可以输入 Java 代码段和`/list`，但这只是可用命令的一个示例。我们可以通过键入`/help`来获得更多信息，如下代码所示：

```java
jshell> /help
|  Type a Java language expression, statement, or declaration.
|  Or type one of the following commands:
|  /list [<name or id>|-all|-start]
|       list the source you have typed
|  /edit <name or id>
|       edit a source entry
|  /drop <name or id>
|       delete a source entry
|  /save [-all|-history|-start] <file>
|       Save snippet source to a file
...
```

你得到的是一长串命令。这里介绍的大部分内容并不是为了节省纸张和您的注意力。在接下来的几页中，我们将使用其中的许多命令。让我们从一个小的 Java 片段开始，即永恒的 Hello World 示例：

```java
jshell> System.out.println("Hello, World!")
Hello World!
```

这是 Java 中有史以来最短的 Hello World 程序。在 Java9 之前，如果您只想打印出`Hello World!`，就必须创建一个程序文件。它必须包含一个类的源代码，包括`public static main`方法，其中包含一行我们必须用 Java9JShell 输入的代码。仅仅对于一个简单的示例代码打印输出来说，这是很麻烦的。现在就容易多了，JShell 也很宽容。它原谅了我们在行尾缺少分号的问题。

接下来我们应该尝试声明一个变量，如下所示：

```java
jshell> var a = 13
a ==> 13
```

我们声明了一个名为`a`的变量，并将值赋给它-`13`。变量的类型是`int`，是 Java 中整数类型的缩写。现在，我们的代码段中已经有了这个变量，所以如果需要，我们可以打印出来，如下所示：

```java
jshell> System.out.println(a)
13
```

现在是时候将比一个行更复杂的东西写入 JShell 了：

```java
jshell> void main(String[] args){
   ...> System.out.println("Hello, World")
   ...> }
|  Error:
|  ';' expected
|  System.out.println("Hello, World")
|                                   ^
```

JShell 认识到这不是一行，当我们在第一行末尾按`Enter`时，它无法处理我们迄今为止键入的内容，并且它表示它希望我们输入更多字符，因此它显示`...>`作为继续提示。我们输入组成整个 helloworld`main`方法的命令。

但是，这次 JShell 不允许我们忽略分号；这只允许在单行代码段的情况下使用。由于 JShell 是交互式的，因此很容易纠正错误按几次向上箭头键返回前几行，这次在第二行末尾添加分号：

```java
jshell> void main(String[] args){
   ...> System.out.println("Hello, World");
   ...> }
|  created method main(String[])
```

此方法是作为代码段为我们创建的，现在我们可以调用它：

```java
jshell> main(null)
Hello, World
```

它起作用了。您可以列出创建的所有代码段，如下所示：

```java
jshell> /list 
   1 : System.out.println("Hello World!")
   2 : var a = 13;
   3 : System.out.println(a)
   4 : void main(String[] args){
       System.out.println("Hello, World");
       }
   5 : main(null)
```

另外，当我们想继续编写一个完整的 Java 版本的 *hello world* 时，我们可以将我们的工作从 JShell 保存到一个文件中，如下所示：

```java
jshell> /save HelloWorld.java
```

最后，我们通过键入`/exit`退出 JShell。返回系统提示时，键入`cat HelloWorld.java`（或在 Windows 上键入`type HelloWorld.java`以查看文件的内容。具体如下：

```java
$ cat HelloWorld.java 
System.out.println("Hello, World!")
var a = 13;
System.out.println(a)
void main(String[] args){
System.out.println("Hello, World");
}
main(null)
```

这个文件包含我们输入的所有片段，一个接一个。如果你认为你已经用很多你不再需要的变量和代码片段弄乱了 Shell，你可以发出`/reset`命令：

```java
jshell> /reset
|  Resetting state.
```

执行此命令后，JShell 与之前启动时一样干净：

```java
jshell> /list

jshell>
```

清单并没有产生任何结果，因为我们将其全部删除。幸运的是，我们将 JShell 的状态保存到了一个文件中，我们还可以通过发出`/open`命令来加载该文件的内容：

```java
jshell> /open HelloWorld.java
Hello, World!
13
Hello, World
```

它从文件中加载行并执行它，就像在命令提示符中键入字符一样。

您可能还记得，`/list`命令在每个片段前面都打印了一个数字。我们可以使用它来单独编辑代码段。为此，发出`/edit`命令，后跟代码段的编号：

```java
jshell> /edit 1
```

您可能还记得，我们输入的第一个命令是将参数打印到控制台的`System.out.println`系统调用。当您在`/edit 1`命令后按`Enter`时，不会得到返回的提示。相反，JShell 会打开一个单独的图形编辑器，其中包含要编辑的代码段，如图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/eae68a4d-d55a-45b3-88e4-0dc0435ff4b1.png)

编辑框中的文本，使其如下所示：

```java
void printf(String format, Object... args) { System.out.printf(format, args); }
printf("Hello World!")
```

单击“接受”，然后单击“退出”。单击“接受”时，终端将执行代码段并显示以下结果：

```java
| created method printf(String,Object...) Hello World!
```

我们使用的方法`printf`表示格式化打印。这可能是许多其他语言所熟知的。它最初是由 C 语言引入的，虽然它很神秘，但它的名字仍然存在。这也是标准 Java 类`PrintStream`的一部分，就像`println`。如果是`println`，我们必须在方法名称前面写`System.out`。为了避免这种情况，我们在编辑器中定义了被截取的，并为我们定义了`printf`方法。

JShell 还定义了一些在 JShell 启动或重置时自动加载的代码段。如果您使用`-start`选项发出`/list`命令，您可以看到这些，如下所示：

```java
jshell> /list -start

  s1 : import java.io.*;
  s2 : import java.math.*;
  s3 : import java.net.*;
  s4 : import java.nio.file.*;
  s5 : import java.util.*;
  s6 : import java.util.concurrent.*;
  s7 : import java.util.function.*;
  s8 : import java.util.prefs.*;
  s9 : import java.util.regex.*;
 s10 : import java.util.stream.*;
```

这些预定义的代码片段有助于 JShell 的使用。大多数用户将导入这些类。

如果您想列出您输入的所有代码段以及预定义的代码段，以及那些包含一些错误并因此未执行的代码段，您可以使用`/list`命令上的`-all`选项，如下所示：

```java
jshell> /list -all
  s1 : import java.io.*;
  s2 : import java.math.*;
  s3 : import java.net.*;
  s4 : import java.nio.file.*;
  s5 : import java.util.*;
  s6 : import java.util.concurrent.*;
  s7 : import java.util.function.*;
  s8 : import java.util.prefs.*;
  s9 : import java.util.regex.*;
 s10 : import java.util.stream.*;
   1 : System.out.println("Hello, World!")
   2 : var a = 13;
   3 : System.out.println(a)
   4 : void main(String[] args){
       System.out.println("Hello, World");
       }
   5 : main(null)
   6 : void printf(String format, Object... args) { System.out.printf(format, args); }
   7 : System.out.println("Hello, World!");
```

预加载的行用`s`前缀编号。包含错误的代码段有一个前缀为`e`的数字。（此打印输出中没有。）

如果要再次执行某些代码段，只需键入`/n`，其中`n`是代码段的编号，如下所示：

```java
jshell> /1 System.out.println("Hello, World!") Hello, World!
```

不能重新执行预加载的代码段或包含错误的代码段。无论如何，这些都没有必要。预加载的代码段声明了一些导入；错误的代码段不会执行，因为它们是错误的。

当您想重新执行一个代码段时，不需要依赖 JShell 的数量。当 JShell 会话中已经有很多代码段时，将它们全部列出会太麻烦；有一个快捷方式可以重新执行最后`n`个代码段。你必须写`/-n`。这里，`n`是从最后一个开始计算的片段数。因此，如果要执行最后一个代码段，就必须编写`/-1`。如果要执行上一个之前的一个，必须写入`/-2`。请注意，如果您已经键入了`/-1`，那么最后一个是最后一个代码段的重新执行，代码段编号`-2`将成为编号`-3`。

列出所有代码片段也可以通过其他方式避免。当您只对某些类型的代码段感兴趣时，可以使用特殊的命令。

如果我们只想看到我们在代码段中定义的变量，我们可以发出`/vars`命令，如下所示：

```java
jshell> /vars
|    int a = 13
```

如果我们只想看到类，`/types`命令将执行以下操作：

```java
jshell> class s {}
|  created class s

jshell> /types
|    class s
```

在这里，我们只是创建了一个空类，然后列出它。

要列出代码段中定义的方法，可以发出`/methods`命令：

```java
jshell> /methods
|    void main(String[])
|    void printf(String,Object...)
```

您可以在输出中看到，只有两种方法，如下所示：

*   `main`：该程序的主要类
*   `printf`：这个，我们在使用编辑器的时候定义的

如果您想查看您键入的所有内容，则必须对您键入的所有代码段和命令发出`/history`命令。（我不会在这里复制输出；我不想让自己羞愧地展示我所有的打字错误和失败。你应该试试自己，看看自己的历史！）

回想一下，我们可以通过发出`/reset`命令来删除所有代码段。也可以单独删除代码段。为此，您应该发出`/drop n`命令，其中`n`是截取的编号：

```java
jshell> /drop 1

jshell> /list

   2 : var a = 13;
   3 : System.out.println(a)
   4 : void main(String[] args){
       System.out.println("Hello, World");
       }
   5 : main(null)
   6 : void printf(String format, Object... args) { System.out.printf(format, args); }
   7 : System.out.println("Hello, World!");
   8 : System.out.println("Hello, World!")
```

我们可以看到，我们删除了第一个片段：

```java
jshell> /drop 2
|  dropped variable a

jshell> /drop 4
|  dropped method main(String[])
```

JShell 错误消息要求我们查看`/types`、`/methods`、`/vars`或`/list`命令的输出。问题是，`/types`、`/methods`和`/vars`不显示代码段的编号。这很可能是 JShell 预发布版本中的一个小错误，可能在 JDK 发布时修复。

当我们编辑代码片段时，JShell 打开了一个单独的图形编辑器。您可能正在远程服务器上使用 SSH 运行 JShell，并且无法打开单独的窗口。您可以使用`/set`命令设置编辑器。这个命令可以设置 JShell 的许多配置选项。要将编辑器设置为使用无处不在的 vi，请发出以下命令：

```java
jshell> /set editor "vi"
|  Editor set to: vi
```

在此之后，JShell 将在您发出`/edit`命令的同一终端窗口中打开在`vi`中截取的。

您不仅可以设置编辑器。您可以设置启动文件，还可以设置 JShell 在执行命令后将反馈打印到控制台的方式。

如果您设置了启动文件，则将执行启动文件中列出的命令，而不是在`/reset`命令之后执行 JShell 的内置命令。这也意味着您将无法使用默认情况下直接导入的类，并且您将没有`printf`方法片段，除非您自己的启动文件包含导入和片段的定义。

创建具有以下内容的`sample.startup`文件：

```java
void println(String message) { System.out.println(message); }
```

启动一个新的 JShell，执行如下操作：

```java
jshell> /set start sample.startup

jshell> /reset
|  Resetting state.

jshell> println("wuff")
wuff

jshell> printf("This won't work...")
|  Error:
|  cannot find symbol
|    symbol:   method printf(java.lang.String)
|  printf("This won't work...")
|  ^----^
```

定义了`println`方法，但是我们前面定义的`printf`方法没有定义。

反馈定义了 JShell 打印并等待输入的提示、连续行的提示以及每个命令之后的消息详细信息。有预定义的模式，如下所示：

*   `normal`
*   `silent`
*   `concise`
*   `verbose`

默认情况下选择`normal`。如果您发出`/set feedback silent`，提示变为`->`，JShell 将不打印有关命令的详细信息。`/set feedback concise`代码打印更多信息，`/set feedback verbose`打印执行命令的详细信息：

```java
jshell> /set feedback verbose
|  Feedback mode: verbose

jshell> int z = 13
z ==> 13
|  created variable z : int

jshell> int z = 13
z ==> 13
|  modified variable z : int
|    update overwrote variable z : int
```

您还可以定义自己的模式，使用`/set mode xyz`命令为新模式命名，其中`xyz`是新模式的名称。之后，可以为模式设置提示、截断和格式。定义格式后，可以使用与内置模式相同的方式使用它。

最后，JShell 最重要的命令是`/exit`。这将终止程序，您将返回操作系统 Shell 提示符。

现在，让我们编辑`HelloWorld.java`文件来创建我们的第一个 Java 程序。要做到这一点，您可以使用 vi、记事本、Emacs 或您的机器上提供的任何适合您的工具。稍后，我们将使用一些集成开发环境（IDE）、NetBeans、Eclipse 或 IntelliJ；不过，就目前而言，一个简单的文本编辑器就足够了。

编辑文件，使内容如下：

```java
public class HelloWorld { 
  public static void main(String[] args){ 
        System.out.println("Hello World"); 
       } 
  }
```

为了将源代码编译成字节码，而字节码是 JVM 可执行的，我们必须使用名为`javac`的 Java 编译器：

```java
javac HelloWorld.java
```

这将在当前目录中生成`java.class`文件。这是一个编译代码，可以按如下方式执行：

```java
$ java HelloWorld
Hello World
```

通过这个，您已经创建并执行了第一个完整的 Java 程序。你可能仍然想知道我们在做什么，一切都会很清楚的。此时此刻，我想让你感受到它的作用。

我们编辑的文件只包含代码片段，我们删除了大部分行，除了`main`方法的声明，并在其周围插入了类的声明。

在 Java 中，不能像在许多其他语言中那样拥有独立的方法或函数。每个方法都属于某个类，每个类都应该在一个单独的文件中声明（好吧，差不多，但现在，让我们跳过异常）。文件名必须与类名相同。编译器对`public`类要求这样。即使是非公共类，我们也通常遵循这个惯例。如果您将文件从`HelloWorld.java`重命名为`Hello.java`，则当您尝试用新名称编译文件时，编译器将显示一个错误：

```java
$ mv HelloWorld.java Hello.java
~/Dropbox/java_9-by_Example$ javac Hello.java
Hello.java:2: error: class HelloWorld is public, should be declared in a file named HelloWorld.java
public class HelloWorld {
       ^
1 error
```

那么，让我们把它移回原来的名字，也就是，`mv Hello.java HelloWorld.java`。

类的声明以`class`关键字开始，然后是类的名称，一个大括号开始，直到匹配的大括号结束。中间的一切都属于类。

现在，让我们跳过为什么我在类前写了`public`，重点讨论其中的`main`方法。该方法不返回任何值，因此返回值为`void`。参数，名为`args`，是一个字符串数组。当 JVM 启动`main`方法时，它将命令行参数传递给这个数组中的程序。然而，这次我们没有用。`main`方法包含打印出`Hello World`的行。现在，让我们再检查一下这条线。

在其他语言中，将内容打印到控制台只需要一个`print`语句，或者一个非常类似的命令。我记得有些初级解释器甚至允许我们输入`?`而不是`print`，因为在屏幕上打印是很常见的。这在过去的 40 年里已经发生了很大的变化。我们使用图形屏幕、互联网和许多其他输入和输出通道。现在，在控制台上写东西已经不是很常见了。

通常，在专业的大型企业应用中，甚至没有一行可以做到这一点。相反，我们将文本定向到日志文件，将消息发送到消息队列，并通过 TCP/IP 协议发送请求和响应。由于这是如此不经常使用，没有理由创造一个快捷方式的目的，在语言。在最初的几个程序之后，当您熟悉了调试器和日志记录的可能性之后，您将不会自己将任何内容直接打印到控制台。

尽管如此，Java 仍然有一些特性，可以让您直接将文本发送到进程的标准输出，就像它最初是为 UNIX 发明的那样。这是以 Java 方式实现的，其中所有内容都必须是对象或类。为了访问系统输出，有一个名为`System`的类，它有以下三个变量：

*   `in`：这是标准输入流
*   `out`：这是标准输出流
*   `err`：这是标准错误流

要引用输出流变量，因为它不在我们的类中，而是在`System`中，我们必须指定类名，所以在我们的程序中将它引用为`System.out`。这个变量的类型是`PrintStream`，也是一个类。类和类型在 Java 中是同义词。每个属于`PrintStream`类型的对象都有一个名为`println`的方法，该方法接受一个`String`。如果实际的打印流是标准输出，并且我们正在从命令行执行 Java 代码，那么字符串将被发送到控制台。

方法名为`main`，这是 Java 程序中的一个特殊名称。当我们从命令行启动 Java 程序时，JVM 从我们在命令行上指定的类中调用名为`main`的方法。它可以做到这一点，因为我们声明了这个方法`public`，以便任何人都可以看到和调用它。如果它是`private`，则只能从同一个类或在同一源文件中定义的类中看到和调用它。

方法也被声明为`static`，这意味着可以在没有包含方法的类的实际实例的情况下调用它。如今，使用静态方法通常不被视为一种好的做法，除非它们实现的函数实际上与实例不相关，或者具有不同的实现，例如`java.lang.Math`类中的函数。然而，在某些地方，代码执行必须开始，Java 运行时通常不会自动为我们创建类的实例。

要启动代码，命令行应如下所示：

```java
java -cp . HelloWorld
```

`-cp`选项代表类路径。对于 Java 来说，类路径是一个相当复杂的概念，但是现在，让我们简单地说，它是包含类的目录和 JAR 文件的列表。类路径的列表分隔符在类 UNIX 系统中是`:`（冒号），在 Windows 系统中是`;`（分号）。在我们的例子中，类路径是实际的目录，因为那是 Java 编译器创建`HelloWorld.class`的地方。如果不在命令行中指定类路径，Java 将使用当前目录作为默认目录。这就是为什么我们的程序在没有`-cp`选项的情况下运行的原因。

`java`和`javac`都处理许多选项。要获取选项列表，请键入`javac -help`或`java -help`。我们使用 IDE 来编辑代码，并在开发过程中多次编译、构建和运行它。在这种情况下，环境会设置合理的参数。对于生产，我们使用同样支持环境配置的构建工具。因此，我们很少遇到这些命令行选项。然而，专业人士必须至少理解它们的含义，并且知道在哪里学习它们的实际用法，以防需要。

# 查看字节码

类文件是二进制文件。这种格式的主要作用是由 JVM 执行，并在代码使用库中的某些类时为 Java 编译器提供符号信息。当我们编译包含`System.out.println`的程序时，编译器会查看编译的`.class`文件，而不是源代码。它必须找到`System`类、`out`字段和`println`方法

当我们调试一段代码或试图找出程序找不到类或方法的原因时，我们需要一种方法来查看`.class`文件的二进制文件。这不是一项日常工作，它需要一些先进的知识。

为此，有一个*反编译器*，它可以以或多或少可读的格式显示`.class`文件的内容。此命令称为`javap`。要执行它，可以发出以下命令：

```java
$ javap HelloWorld.class
Compiled from "HelloWorld.java"
public class HelloWorld {
  public HelloWorld();
  public static void main(java.lang.String[]);
}
```

程序的输出显示类文件包含一个 Java 类，它有一个名为`HelloWorld()`的东西；它似乎是一个与类同名的方法，它还包含我们编写的方法。

与类同名的*方法*是类的构造器。由于 Java 中的每个类都可以实例化，因此需要一个构造器。如果我们不给出一个，Java 编译器将为我们创建一个。这是默认构造器。默认构造器不执行任何特殊操作，但返回类的新实例。如果我们自己提供一个构造器，Java 编译器就不会费心去创建一个。

除非我们提供`-c`选项，否则`javap`反编译器不会显示方法内部的内容或它包含的 Java 代码：

```java
$ javap -c HelloWorld.class
Compiled from "HelloWorld.java"
public class HelloWorld {
  public HelloWorld();
    Code:
       0: aload_0
       1: invokespecial #1                  // Method java/lang/Object."<init>":()V
       4: return
  public static void main(java.lang.String[]);
    Code:
       0: getstatic     #2                  // Field java/lang/System.out:Ljava/io/PrintStream;
       3: ldc           #3                  // String hali
       5: invokevirtual #4                  // Method java/io/PrintStream.println:(Ljava/lang/String;)V
       8: return
}
```

它非常神秘，不适合普通人。只有少数处理 Java 代码生成的专家能够流利地阅读这些内容。然而，看一下它可以帮助您了解字节码的含义。这有点像一个古老的集会。虽然这是二进制代码，但里面没有什么秘密：Java 是开源的，类文件格式有很好的文档记录，专家可以调试。

# 将类打包到 JAR 文件中

在交付 Java 应用时，通常将代码打包为 JAR、WAR、EAR 或其他打包格式。我们又学到了一些乍一看似乎晦涩难懂的东西，但实际上，这并没有那么复杂。它们都是 ZIP 文件。您可以使用 WinZip 或其他您有许可证的 ZIP 管理器打开这些文件中的任何一个。额外的要求是，例如，在 JAR 文件的情况下，归档文件应该包含一个名为`META-INF`的目录和一个名为`MANIFEST.MF`的文件。此文件为文本文件，包含格式如下的元信息：

```java
Manifest-Version: 1.0 
Created-By: 11-ea (Oracle Corporation)
```

文件中可能有很多其他信息，但这是 Java 提供的工具`jar`在将类文件打包到一个 JAR 中时，发出以下命令的最低限度：

```java
jar -cf hello.jar HelloWorld.class
```

`-c`选项告诉 JAR 归档程序创建一个新的 JAR 文件，`f`选项用于指定新归档文件的名称。我们在这里指定的是`hello.jar`，添加到其中的文件是类文件。

打包的 JAR 文件也可以用来启动 Java 应用。Java 可以直接从 JAR 档案中读取并从那里加载类。唯一的要求是它们在类路径上。

不能将单个类放在类路径上，只能放在目录上。由于 JAR 文件是带有内部目录结构的归档文件，它们的行为就像一个目录。

检查 JAR 文件是使用`ls hello.jar`创建的，删除`rm HelloWorld.class`类文件只是为了确保在发出命令行时，代码是从 JAR 文件执行的，而不是从类执行的：

```java
$ java -cp hello.jar HelloWorld
Hello World
```

但是，要查看 JAR 文件的内容，建议您使用 JAR 工具，而不是 WinZip，尽管这可能更为方便。真正的专业人士使用 Java 工具来处理 Java 文件：

```java
$ jar -tf hello.jar META-INF/ META-INF/MANIFEST.MF HelloWorld.class
```

# 管理正在运行的 Java 应用

JDK 附带的 Java 工具集也支持运行 Java 应用的执行和管理。为了让一些程序在执行时能够管理，我们需要一个不仅能运行几毫秒的代码，而且在它运行时，还能将一些东西打印到控制台。我们创建一个名为`HelloWorldLoop.java`的新程序，内容如下：

```java
public class HelloWorldLoop { 
  public static void main(String[] args){ 
       for( ;; ){ 
         System.out.println("Hello World"); 
         } 
       } 
  }
```

包含一个`for`循环。循环允许重复执行代码块，我们将在第 2 章“第一个真正的 Java 程序——排序名称”讨论。我们在这里创建的循环是一个特殊的循环，它从不终止，而是重复打印方法调用，打印`Hello World`，直到在 Linux 或 MacOSX 上按`Ctrl + C`或发出`kill`命令终止程序，或者在 Windows 下的任务管理器中终止程序。

在一个窗口中编译并启动它，然后打开另一个终端窗口来管理应用。

我们首先要熟悉的命令是`jps`。为了更熟悉`jps`，[您可以在这里阅读一些内容](http://docs.oracle.com/javase/7/docs/technotes/tools/share/jps.html)，列出了机器上运行的 Java 进程，如下所示：

```java
$ jps 
21873 sun.tools.jps.Jps 
21871 HelloWorldLoop
```

您可以看到有两个进程：一个是我们执行的程序，另一个是`jps`程序本身。毫不奇怪，`jps`工具也是用 Java 编写的。您还可以将选项传递给`jps`，这些选项记录在 Web 上。

还有许多其他工具，我们将研究其中一个，它是一个非常强大且易于使用的工具 Java VisualVM：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/2b116d3c-a0c1-4740-9b92-1cbe4f468c90.png)

VisualVM 是一个命令行图形工具，它连接到正在运行的 Java 进程并显示不同的性能参数。要启动 VisualVM 工具，您将发出不带任何参数的`jvisualvm`命令。很快，就会出现一个窗口，左侧是一棵探索树，右侧是一个欢迎窗格。左侧显示了名为 Local 的分支下所有正在运行的 Java 进程。如果您双击`HelloWorldLoop`，它将在右侧窗格中打开流程的详细信息。在 header 选项卡上，可以选择 Overview、Monitor、Threads、Sampler 和 Profiler。前三个选项卡是最重要的，它可以让您很好地了解 JVM 中的线程数、CPU 使用率、内存消耗等情况。

# 使用 IDE

集成开发环境是优秀的工具，它通过将机械任务从开发人员的肩上卸下来来帮助开发。当我们键入代码时，它们可以识别许多编程错误，帮助我们找到所需的库方法，显示库的文档，并为样式检查、调试等提供额外的工具。

在本节中，我们将介绍一些 IDE 以及如何利用它们提供的功能。

要获得 IDE，您必须下载并安装它。它不随 Java 开发工具一起提供，因为它们不是语言环境的一部分。不过，别担心，它们可以免费下载，安装也很简单。它们可能比记事本编辑器更复杂，但即使工作了几个小时，它们也会回报你花在学习上的时间。毕竟，并不是没有理由没有开发人员用记事本或 vi 编写 Java 代码。

最上面的三个 IDE 是* NetBeans*、*Eclipse* 和 *IntelliJ*。所有这些都可以在社区版本，这意味着你不需要支付他们。IntelliJ 有一个*完整的*版本，您也可以购买。社区版将用于学习语言。如果您不喜欢 IntelliJ，可以使用 Eclipse 或 NetBeans。这些都是免费的。就我个人而言，我的大多数项目都使用 IntelliJ 社区版，本书中显示 IDE 的屏幕示例将以该 IDE 为特色。然而，这并不一定意味着你必须坚持这个 IDE。

在开发人员社区中，有些话题可以引起激烈的争论。这些话题是关于意见的。如果他们讨论的是事实，辩论很快就会结束。其中一个主题是“哪一个是最好的 IDE？”。这是品味的问题。没有确切的答案。如果你学会如何使用一个，你会喜欢的，你会不愿意学习另一个，除非你看到另一个更好。这就是为什么开发人员喜欢他们使用的 IDE（或者只是讨厌，这取决于他们的个性），但是他们一直使用同一个 IDE，通常是很长一段时间。没有最好的 IDE。

要下载您选择的 IDE，您可以访问以下任一网站：

*   [NetBeans](https://netbeans.org/)
*   [Eclipse](http://www.eclipse.org/)
*   [IntelliJ](https://www.jetbrains.com/idea/)

# NetBeans

NetBeans 是由 Oracle 支持的，并且是不断开发的。它包含一些组件，如 NetBeans profiler，这些组件已成为 OracleJava 发行版的一部分。您可能会注意到，当您启动 visualvm 并启动评测时，Java 启动进程的名称中有`netbeans`。

一般来说，NetBeans 是一个开发富客户端应用的框架，IDE 只是构建在该框架之上的众多应用中的一个。它支持多种语言，不仅仅是 Java。您可以使用 NetBeans 开发 PHP、C 或 JavaScript 代码，并为 Java 提供类似的服务。为了支持不同的语言，您可以下载插件或 NetBeans 的特殊版本。这些特殊版本可以从 IDE 的下载页面获得，它们只不过是带有一些预配置插件的基本 IDE。在 C 包中，开发人员配置开发 C 所需的插件；在 PHP 版本中，开发人员配置 PHP。

# Eclipse

IBM 支持 Eclipse。与 NetBeans 类似，它也是一个富客户端应用平台，它是围绕 *OSGi* 容器架构构建的，而这个架构本身就是一个可以填满这样一本书的主题。大多数开发人员都使用 Eclipse，而且几乎完全是这样，当开发人员为 *ibmwebsphere* 应用服务器创建代码时，可以选择 Eclipse。Eclipse 特殊版本包含 WebSphere 的开发人员版本。

Eclipse 还具有支持不同编程语言的插件，并且具有类似于 NetBeans 的不同变体。这些变体是用基本 IDE 预先打包的插件。

# IntelliJ

前面枚举中的最后一个是 IntelliJ。这个 IDE 是唯一一个不想成为框架的 IDE。IntelliJ 是一个 IDE。它也有插件，但是您需要下载以在 NetBeans 或 Eclipse 中使用的大多数插件都是预先配置的。当你想使用一些更高级的插件时，它可能是你必须付费的，这在你从事专业的有偿工作时应该不是问题，对吗？这些东西没那么贵。要学习本书中的主题，您不需要任何社区版以外的插件。在本书中，我将使用 IntelliJ 开发示例，我建议您在学习过程中遵循我的建议。

我想强调的是，本书中的示例独立于要使用的实际 IDE。您可以使用 NetBeans、Eclipse 甚至 Emacs、notepad 或 vi 来阅读本书。

# IDE 服务

集成开发环境为我们提供服务。最基本的服务是您可以用它们编辑文件，但它们也可以帮助构建代码、查找 bug、运行代码、以开发模式部署到应用服务器、调试等等。在下面的部分中，我们将研究这些特性。关于如何使用一个或另一个 IDE，我将不作确切的介绍。像这样的书对这样的教程来说不是一个好的媒介。

IDE 在菜单位置、键盘快捷键上有所不同，甚至可能随着新版本的发布而改变。最好看一下实际的 IDE 教程视频或在线帮助。另一方面，它们的特征非常相似。IntelliJ 在[这个页面](https://www.jetbrains.com/idea/documentation/)有视频文档。

# IDE 屏幕结构

不同的 IDE 看起来很相似，它们的屏幕结构也差不多。在下面的屏幕截图中，您可以看到 IntelliJ IDE：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/7396ca5f-9996-4c0d-a37e-d50296740c77.png)

在左边，您可以看到 Java 项目的文件结构。Java 项目通常包含不同目录中的许多文件，我们将在下一章中讨论。简单的 *HelloWorld* 应用包含一个`pom.xml`项目描述文件。Maven 构建工具需要这个文件，这也是下一章的主题。现在，您应该只知道它是一个描述 Maven 项目结构的文件。IDE 还为自己跟踪一些管理数据。存储在`HelloWorld.iml`中。主程序文件存储在`src/main/java`目录中，命名为`HelloWorld.java`。

在右边，你可以看到文件。在前面的截图中，我们只打开了一个文件。如果打开了多个文件，则会有选项卡，每个文件有一个选项卡。现在，活动文件为`HelloWorld.java`，可以在源代码编辑器中编辑。

# 编辑文件

编辑时，您可以键入字符或删除字符、单词和行，但这是所有编辑器都可以做的事情。IDE 提供了额外的功能，它们分析源代码并对其进行格式化，从而自动缩进行。它还会在您编辑代码时在后台不断编译代码，如果有语法错误，它会用红色的放弃线来强调这一点。修复错误时，红色下划线将消失：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/3f42bf65-b11b-4fb9-ad3c-ac4e8850b864.png)

编辑器还会自动为您键入的其他字符提供建议。您可以忽略弹出的窗口并继续键入。但很多时候，在按`Enter`键之前，更容易在一个字符后停下来，用上下箭头选择需要完成的单词；该单词会自动插入到源代码中。

在前面的截图中，你可以看到我写了`System.o`，编辑马上建议我写`out`。其他替代方法是`System`类中包含字母`o`的其他静态字段和方法。

IDE 编辑器不仅可以为您输入提示，而且可以为您输入提示。在下面的屏幕截图中，IDE 告诉您键入一些表达式作为`println()`方法的参数，即`boolean`、`char`、`int`等等。IDE 完全不知道在那里输入什么。你必须构造表达式。不过，它可以告诉你它需要某种类型：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/feae1580-7fd5-429f-9794-24b2cfc8c54f.png)

编辑不仅知道内置类型。与 JDK 集成的编辑器不断地扫描源文件，并知道源代码中有哪些类、方法和字段，以及哪些类、方法和字段在编辑时可用。

当您想重命名方法或变量时，也会大量使用此知识。旧方法是重命名源文件中的字段或方法，然后对变量的所有引用进行彻底搜索。使用 IDE，机械工作由它完成。它知道字段或方法的所有用途，并自动用新标识符替换旧标识符。它还可以识别本地变量是否恰好与我们重命名的变量同名，IDE 仅重命名那些真正指的事件，我们正在重命名。

你通常可以做的不仅仅是重命名。程序员称之为**重构**的机械任务或多或少都有。IDE 使用一些键盘快捷键和编辑器中的上下文相关菜单右键单击鼠标并单击菜单来支持这些功能：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/93823b5a-b4d9-4f0c-8ca0-0053c4b4a580.png)

IDE 还帮助您阅读库的文档和源代码，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/ceedbc0b-8596-4b05-a00a-74c1dbac2ee0.png)

库为`public`方法提供 *Javadoc* 文档，您还应该为自己的方法编写 Javadoc。Javadoc 文档是从源代码中的特殊注释中提取出来的，我们将在第 4 章、“策划人——创建游戏”中学习如何创建这些文档。它们位于实际方法头前面的注释中。由于创建编译文档是编译流的一部分，IDE 也知道文档，当您将光标定位到元素上时，它会显示为方法名、类名或任何要在源文件中使用的元素上方的悬停框。

# 管理项目

在 IDE 窗口的左侧，您可以看到项目的目录结构。IDE 了解不同类型的文件，并以编程的角度显示它们的方式。例如，它不显示`Main.java`作为文件名。相反，它显示`Main`和一个图标，表示`Main`是一个类。它也可以是一个仍然在名为`Main.java`的文件中的接口，但是在这种情况下，图标将显示这是一个接口。IDE 继续扫描和编译代码，这一点再次实现。

当我们开发 Java 代码时，这些文件被构造成子目录。这些子目录遵循代码的打包结构。很多时候，在 Java 中，我们使用复合的和长的包名，而将其显示为一个深度嵌套的目录结构将不那么容易处理。

包用于对源文件进行分组。以某种方式相关的类的源文件应该放在一个包中。我们将在下一章讨论包的概念以及如何使用它们。

IDE 能够显示包结构，而不是包含源文件的项目目录的嵌套目录：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/305d1838-cca0-4bd5-8063-74b3cb9218c9.png)

当您将类或接口从一个包移动到另一个包时，它的发生方式与重命名或任何其他重构操作的发生方式类似。源文件中对类或接口的所有引用都将重命名为新包。如果文件包含引用该类的`import`语句，则该语句中的类名称将被更正。要移动一个类，可以打开包并使用旧的拖放技术。

包层次结构不是 IDE 中显示的唯一层次结构。类在包中，但同时存在继承层次结构。类可以实现接口，也可以扩展其他类。JavaIDE 通过显示类型层次结构来帮助我们，您可以在其中沿着继承关系在图形界面上导航。

IDE 可以显示另一个层次结构，以帮助我们使用开发方法调用层次结构。在分析代码之后，IDE 可以向我们展示一个图形，显示方法之间的关系：哪个方法调用哪个其他方法。有时，这个调用图在显示方法之间的依赖关系时也很重要。

# 构建代码并运行它

IDE 通常编译代码进行分析，以帮助我们及时发现语法错误或未定义的类和方法。这种编译通常是局部的，涵盖了代码的一部分，而且由于它一直在运行，源代码会发生变化，而且永远不会真正完成。要创建可部署文件，即项目的最终可交付代码，必须启动一个单独的构建过程。大多数 IDE 都有一些内置的工具，但是除了最小的项目外，不建议使用这些工具，专业开发项目使用 Ant、Maven 或 Gradle。

下面是 Maven 的一个例子：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/a9a0eeb3-64ef-4463-84b3-fc709595c7eb.png)

IDE 准备使用这样一个外部工具，它们可以帮助我们启动它们。这样，构建过程可以在开发人员机器上运行，而不需要启动新的 Shell 窗口。IDE 还可以从这些外部构建工具的配置文件导入设置，以识别项目结构、源文件所在位置以及在编辑时支持错误检查的编译内容。

构建过程通常包含对代码执行某些检查。一堆 Java 源文件可以编译得很好，很流畅。尽管如此，代码可能包含很多 bug，并且可能以糟糕的风格编写。从长远来看，这些东西使这个项目无法维持。为了避免这些问题，我们将使用单元测试和静态代码分析工具。这些并不能保证无错误的代码，但可能性要小得多。

IDE 有运行静态代码分析工具和单元测试的插件。集成到 IDE 中有一个巨大的优势。当分析工具或某些单元测试发现任何问题时，IDE 会提供一条错误消息，其功能类似于网页上的链接。如果单击消息（通常是蓝色和下划线的），就像在网页上一样，编辑器会打开有问题的文件并将光标放在问题所在的位置。

# 调试 Java

开发代码需要调试。Java 在开发过程中有很好的工具来调试代码。JVM 通过 Java 平台调试器架构支持调试器。这允许您在调试模式下执行代码，JVM 将接受外部调试器工具通过网络连接到它，或者根据命令行选项尝试连接到调试器。JDK 包含一个客户端，`jdb`工具，它包含一个调试器；然而，与 IDE 中内置的图形客户端相比，它的使用非常麻烦，我从来没有听说有人在实际工作中使用它。

要在调试模式下启动 Java 程序，以便 JVM 接受调试器客户端将选项附加到该程序，请执行以下命令：

```java
-Xagentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=7896
```

`Xagentlib`选项指示 Java 运行时加载`jdwp`代理。`-Xagentlib:jdwp=`后面的选项部分由调试器代理解释。这些选项如下：

*   `transport`：应该指定要使用的传输。它可以是共享内存（`dt_shmem`）套接字或 TCP/IP 套接字传输，但实际上，您将始终使用后者。这在前面的`dt_socket`样本中有规定。
*   `server`：指定被调试的 JVM 是以服务器模式还是以客户端模式启动。当您在服务器模式下启动 JVM 时，它开始监听套接字并接受调试器连接到它。如果它是在客户端模式下启动的，它会尝试连接一个调试器，该调试器应该在服务器模式下启动，监听一个端口。该选项的值为`y`，表示服务器模式；或`n`，表示非服务器，表示客户端模式。
*   `suspend`：也可以是`y`或`n`。如果 JVM 是在挂起模式下启动的，它将不会启动 Java 代码，直到一个调试器连接到它。如果它是以`suspend=n`启动的，JVM 将启动，当调试器连接时，它将在到达断点时立即停止。如果您启动一个独立的 Java 应用，您通常会使用默认值`suspend=y`启动调试。如果要在应用服务器或 Servlet 容器环境中调试应用，最好从`suspend=n`开始；否则，直到调试器连接到服务器，服务器才会启动。在`suspend=y`模式下启动 Java 进程，以防 Servlet 应用只在您想要调试 Servlet 静态初始化器代码时才有用，该代码是在服务器启动时执行的。如果没有挂起模式，则需要快速附加调试器。在这种情况下，JVM 最好只是等待您。
*   `address`：应该指定 JVM 与之通信的地址。如果 JVM 以客户端模式启动，它将开始连接到此地址。如果 JVM 在服务器模式下运行，它将接受来自该地址上调试器的连接。地址只能指定端口。在这种情况下，IP 地址是本地机器的 IP 地址。

调试器代理可能处理的其他选项用于特殊情况。对于本书涵盖的主题，前面的选项就足够了。

下面的截图显示了一个典型的调试会话，在 IntelliJ IDE 中调试最简单的程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/b249e654-0dc4-4248-9f04-00169bca1124.png)

在调试模式下从 IDE 启动程序时，所有这些选项都会自动为您设置。只需在编辑器中单击源代码，就可以设置断点。您可以使用单独的窗体来添加、删除和编辑断点。断点可以附加到特定的行或特定的事件，比如抛出异常时。附加到特定行的断点也可以有条件告诉调试器停止代码的执行，但只有在条件为`true`时才停止；例如，如果变量具有某个预定义的值。

# 总结

在本章中，我们互相介绍了 Java。我们不太了解对方，但我们是认识的。我们安装了 Java 环境：Java、JDK 和集成开发环境。我们编写了一个小程序，简要介绍了使用开发工具可以做些什么。这远非精通，但即使是最长的旅程也要从第一步开始，这一步有时是最难迈出的。我们已经在 Java 之旅中做到了这一点。我们开始滚动，对于我们这样的狂热者来说，没有什么能阻止我们一路前行。

# 二、第一个真正的 Java 程序-排序名称

在上一章中，我们熟悉了 Java，特别是使用 REPL 工具和交互式地执行一些简单代码。这是一个好的开始，但我们需要更多。在本章中，我们将开发一个简单的程序。以这段代码为例，我们将研究 Java 项目中常用的不同构建工具，并学习 Java 语言的基本特性。

本章将涵盖以下主题：

*   排序问题
*   项目结构和构建工具
*   Make、Ant、Maven 和 Gradle 构建工具
*   Java 语言相关功能的代码示例

# 排序入门

排序问题是工程师处理的最古老的编程任务之一。我们有一套记录，我们知道我们想尽快找到一个具体的。为了找到它，我们按照特定的顺序对记录进行排序，以帮助我们快速找到所需的记录。

例如，我们有学生的名字，他们的标记在一些卡片上。当学生们来到院长的小屋要求成绩时，我们一张接一张地查看所有卡片，找到询问学生的姓名。然而，如果我们按学生的名字按字母顺序排列卡片，那就更好了。当学生进行查询时，我们可以更快地搜索附加在名字上的标记。

我们可以看看中间的卡片；如果它显示了学生的名字，那么我们很高兴找到了名字和标记。如果卡片按字母顺序在学生姓名之前，那么我们将在下半部分继续搜索；否则，我们将检查上半部分。

按照这个方法，我们可以通过几个步骤找到学生的名字。步数不能超过牌包减半的次数。如果我们有两张牌，那么最多是两步。如果是四步，那么我们最多需要三步。如果有八张牌，那么我们可能需要四个步骤，但不能更多。如果有 1000 张卡片，那么我们可能最多需要 11 个步骤，而原始的，未排序的一组将需要 1000 个步骤，作为最坏的情况。也就是说，它大约将搜索速度提高了 100 倍，因此这是值得对卡片进行排序的，除非排序本身花费太多时间。在我们刚才描述的已经排序的集合中查找元素的算法称为[**二分搜索**](https://en.wikipedia.org/wiki/Binary_search_algorithm)。

在许多情况下，对数据集进行排序是值得的，有许多排序算法可以做到这一点。有更简单和更复杂的算法，在许多情况下，更复杂的算法运行得更快。

由于我们关注的是 Java 编程部分，而不是算法锻造，因此在本章中，我们将开发一个 Java 代码来实现一个简单而不是那么快的算法。

# 冒泡排序

我们将在本章中实现的算法是众所周知的**冒泡排序**。方法非常简单。从卡片的开头开始，比较第一张和第二张卡片。如果第一张卡片的字典顺序比第二张晚，那么交换这两张卡片。然后，对第二位的牌重复这个步骤，然后是第三位，依此类推。威尔逊说，有一张卡片是最新的。当我们得到这张卡片并开始与下一张卡片比较时，我们总是交换它们；这样，威尔逊的卡片就会移动到最后一个地方，在排序之后。我们所要做的就是从一开始就重复这个过程，偶尔再交换一次牌，但这次只换到最后一个元素。这一次，第二个最新的元素将得到它的位置说，威尔金森将在威尔逊之前。如果我们有`n`张牌，我们重复这个`n-1`次，所有的牌都会到达它们的位置。

在接下来的小节中，我们将创建一个实现该算法的 Java 项目。

# 项目结构和构建工具入门

当一个项目比一个类更复杂时，通常是这样，那么定义一个项目结构是明智的。我们必须决定源文件存储在哪里，资源文件（那些包含程序的一些资源但不是 Java 源代码的文件）在哪里，`.class`文件应该由编译器写在哪里，等等。通常，结构主要是目录设置和执行构建的工具的配置。

使用发出`javac`命令的命令行不可能编译复杂的程序。如果我们有 100 个 Java 源文件，编译将需要发出许多`javac`命令。它可以使用通配符来缩短，比如`javac *.java`，或者我们可以编写一个简单的 bash 脚本或一个 BAT 命令文件来实现这一点。首先，它将只有 100 行，每行编译一个源 Java 文件到类文件。然后，我们会意识到这是编译自上次编译以来没有更改的文件所消耗的 CPU 和电源的唯一时间，因此我们可以添加一些 bash 编程来检查源代码和生成的文件的时间戳。最后，我们将得到一个基本上是构建工具的工具。构建工具是现成的；不值得重新设计轮子。

我们将使用一个准备好的构建工具，而不是创建一个。在[这个页面](https://en.wikipedia.org/wiki/List_of_build_automation_software)可以找到一些软件。在本章中，我们将使用一个名为 Maven 的工具；但是，在深入讨论这个工具的细节之前，我们将研究一些其他工具，您可能会在企业项目中作为 Java 专业人员遇到这些工具。

在接下来的部分中，我们将讨论以下四种构建工具：

*   Make
*   Ant
*   Maven
*   Gradle

我们将简要地提到 Make，因为它现在不在 Java 环境中使用。然而，Make 是第一个构建工具，现代 Java 构建工具所基于的许多思想都来自于*古老的*`make`。作为一名专业的 Java 开发人员，您还应该熟悉 Make，这样当您碰巧看到 Make 在某个项目中用于某种目的时，您就不会惊慌失措，并且可以知道它是什么以及在哪里可以找到它的详细文档。

Ant 是许多年前第一个广泛用于 Java 的构建工具，现在它仍在许多项目中使用。

Maven 比 Ant 更新，它使用了不同的方法。我们将详细地看一下。Maven 也是 Apache 软件基金会的 Java 项目的官方构建工具。我们也将在本章中使用 Maven 作为构建工具。

Gradle 甚至比 Maven 更新，最近它已经开始赶上 Maven 了。我们将在本书后面的章节中更详细地使用这个工具。

# Make

`make`程序最初创建于 1976 年 4 月，因此这不是一个新工具。它包含在 Unix 系统中，因此此工具在 Linux、MacOSX 或任何其他基于 Unix 的系统上都不需要额外安装。另外，这个工具在 Windows 上有许多端口，VisualStudio 编译器工具集中包含了一些版本。

Make 与 Java 无关。它是在主要编程语言是 C 时创建的，但它与 C 或任何其他语言无关。`make`是一种语法非常简单的依赖描述语言。与任何其他构建工具一样，`make`由项目描述文件控制。对于 Make，此文件包含一个规则集。描述文件通常命名为`Makefile`，但如果描述文件的名称不同，则可以将其指定为`make`命令的命令行选项。

`Makefile`中的规则相互遵循，由一行或多行组成。第一行从第一个位置开始（行首没有制表符或空格），下面的行从制表符字符开始。因此，`Makefile`可能类似于以下代码：

```java
run : hello.jar
    java -cp hello.jar HelloWorld

hello.jar : HelloWorld.class
    jar -cf hello.jar HelloWorld.class

HelloWorld.class : HelloWorld.java
    javac HelloWorld.java
```

这个文件定义了三个所谓的目标：`run`、`hello.jar`和`HelloWorld.class`。要创建`HelloWorld.class`，请在命令提示符处键入以下行：

```java
make HelloWorld.class
```

Make 将查看规则并确定它依赖于`HelloWorld.java`。如果`HelloWorld.class`文件不存在，或者`HelloWorld.java`比 Java 类文件更新，`make`执行下一行写的命令，编译 Java 源文件。如果类文件是在上次修改`HelloWorld.java`之后创建的，则`make`知道不需要运行该命令。

在创建`HelloWorld.class`的情况下，`make`程序的任务很简单。源文件已经存在。如果您发出`make hello.jar`命令，程序会更复杂。`make`命令看到为了创建`hello.jar`，它需要`HelloWorld.class`，它本身也是另一个规则的目标。因此，我们可能不得不创造它。

首先，它以与以前一样的方式开始问题。如果`HelloWorld.class`存在且年龄大于`hello.jar`，则无需做任何事情。如果不存在或更新于`hello.jar`，则需要执行`jar -cf hello.jar HelloWorld.class`命令，尽管在意识到必须执行时不一定执行。`make`程序记得，当创建`HelloWorld.class`所需的所有命令都已成功执行时，必须在将来某个时间执行此命令。因此，它继续以与前面描述的完全相同的方式创建类文件。

一般来说，规则可以具有以下格式：

```java
target : dependencies
    command
```

`make`命令可以使用`make target`命令创建任何目标，首先计算要执行的命令，然后逐个执行。这些命令是在不同进程中执行的 Shell 命令，在 Windows 下可能会出现问题，这可能会导致`Makefile`文件的操作系统相互依赖。

注意，`run`目标不是`make`创建的实际文件。目标可以是文件名，也可以只是目标的名称。在后一种情况下，`make`永远不会认为目标是现成的。

由于我们不将`make`用于 Java 项目，因此没有理由深入了解更多细节。此外，我还通过使规则的描述比它应该的更简单来作弊。`make`工具有许多强大的特性，超出了本书的范围。还有几个实现彼此略有不同。你很可能会遇到一个由自由软件基金会 GNU 制造的。当然，就任何 Unix 命令行工具而言，`man`是您的朋友。`man make`命令将在屏幕上显示工具的文档。

以下是关于`make`你应该记住的要点：

*   它以声明的方式定义各个工件（目标）的依赖关系
*   它以命令式的方式定义了创建缺少的工件的操作

这种结构是几十年前发明的，并且一直存在到现在，对于大多数构建工具，您将在接下来的几章中看到。

# Ant

`ant`构建工具是专门为 2000 年左右的 Java 项目构建的。Java 的目标是成为一种只需一次编写就可以在任何地方运行的语言，这就需要一种也可以在不同环境中使用的工具。尽管`make`在 Unix 机器和 Windows 上都可用，但`Makefiles`并不总是兼容的。在使用制表符时出现了一个小问题，一些编辑器用空格代替了制表符，导致`Makefile`无法使用，但这不是主要原因。`make`引发 Ant 发展的主要问题是命令是 Shell 命令。即使`make`程序的实现是兼容的，运行在不同的操作系统上，所使用的命令也常常是不兼容的，这是 Make 本身无法改变的。因为`make`发出外部命令来构建目标，开发人员可以自由地使用开发机器上为他们提供的任何外部工具。使用相同操作系统的另一台机器可能没有`make`调用的相同工具集。这破坏了`make`已建项目的可移植性。

同时，Ant 遵循了`make`的主要原则。有些目标可能相互依赖，有些命令需要按适当的顺序执行，以便按照依赖顺序一个接一个地创建目标。依赖关系和命令的描述是 XML（解决了制表符问题），命令是用 Java 实现的（解决了系统依赖关系，以及。。。或多或少）。

由于 Ant 既不是操作系统的一部分，也不是 JDK 的一部分，因此如果您想使用它，就必须单独下载并安装它。

# 安装 Ant

Ant 可从其[官方网站](http://ant.apache.org)下载。您可以下载源或预编译版本。最简单的方法是以`tar.gz`格式下载二进制文件。

无论何时从互联网下载软件，强烈建议您检查下载文件的完整性。HTTP 协议不包含错误检查，并且可能发生网络错误仍然隐藏或恶意内部代理修改下载的文件的情况。下载站点通常为可下载的文件提供校验和。它们通常是 MD5、SHA1、SHA512 或其他一些校验和。

当我以`tar.gz`格式下载 ApacheAnt1.9.7 版本时，我还打开了导致 MD5 校验和的页面。校验和值为`bc1d9e5fe73eee5c50b26ed411fb0119`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/5547972d-0d49-4922-a323-964ebb767050.png)

可以使用以下命令行检查下载的文件：`$ md5 apache-ant-1.9.7-bin.tar.gz MD5 (apache-ant-1.9.7-bin.tar.gz) = bc1d9e5fe73eee5c50b26ed411fb0119`计算出的 MD5 校验和与网站上的相同，说明文件完整性没有受到损害。在 Windows 操作系统上，没有计算 MD5 摘要的工具。微软提供了一个工具，叫做**文件完整性校验和验证工具**，可以在[这个页面](https://support.microsoft.com/en-us/help/841290/availability-and-description-of-the-file-checksum-integrity-verifier-utility)上找到。如果您使用 Linux，可能会发生未安装`md5`或`md5sum`工具的情况。在这种情况下，您可以使用`apt-get`命令或 Linux 发行版支持的任何安装工具来安装它。

下载文件后，可以使用以下命令将其分解为子目录：

```java
tar xfz apache-ant-1.9.7-bin.tar.gz
```

创建的子目录是 Ant 的可用二进制分布。通常我会把它移到`~/bin`下，只让我在 OSX 上的用户可以使用，然后把环境变量设为`ANT_HOME`指向这个目录，同时把安装的`bin`目录添加到`PATH`。为此，您应该编辑`~/.bashrc`文件并添加以下行：

```java
export ANT_HOME=~/bin/apache-ant-1.9.7/
export PATH=${ANT_HOME}bin:$PATH
```

然后，重新启动终端应用，或者只需键入`. ~/.bashrc`并通过键入以下命令来测试 Ant 的安装：

```java
$ ant
Buildfile: build.xml does not exist!
Build failed
```

如果安装正确，您应该看到前面的错误消息。

# 使用 Ant

当您看到一个由 Ant 构建的项目时，您将看到一个`build.xml`文件。这是项目构建文件，当您检查安装是否正确时，Ant 丢失了这个文件。它可以有任何其他名称，并且您可以将文件名指定为 Ant 的命令行选项，但这是默认文件名，因为`Makefile`是针对`make`的。`build.xml`样本如下：

```java
<project name="HelloWorld" default="jar" basedir=".">
<description>
    This is a sample HelloWorld project build file.
</description>
    <property name="buildDir" value="build"/>
    <property name="srcDir" value="src"/>
    <property name="classesDir" value="${buildDir}/classes"/>
    <property name="jarDir" value="${buildDir}/jar"/>

    <target name="dirs">
        <mkdir dir="${classesDir}"/>
        <mkdir dir="${jarDir}"/>
    </target>

    <target name="compile" depends="dirs">
        <javac srcdir="${srcDir}" destdir="${classesDir}"/>
    </target>

    <target name="jar" depends="dirs,compile">
        <jar destfile="${jarDir}/HelloWorld.jar" basedir="${classesDir}"/>
    </target>
</project>
```

顶层 XML 标记为`project`。每个构建文件都描述一个项目，因此名称。标记有三个可能的属性，如下所示：

*   `name`：定义了项目的名称，一些 IDE 使用它在左侧面板中显示项目名称
*   `default`：当命令行上没有定义目标时，命名要使用的目标
*   `basedir`：定义生成文件中其他目录名计算的初始目录

生成文件可以包含项目的描述以及属性标记中的属性。这些属性可以作为`${`和`}`字符之间任务属性的变量，并在构建过程中发挥重要作用。

目标在目标 XML 标记中定义。每个标记都应该有一个唯一标识生成文件中目标的名称，并且可以有一个指定该目标所依赖的一个或多个其他目标的`depends`标记。如果有多个目标，则这些目标在属性中用逗号分隔。属于目标的任务按照目标依赖链要求的相同顺序执行，方式与我们在`make`中看到的非常相似。

您还可以向 Ant 在使用`-projecthelp`命令行选项时打印的目标添加一个`description`属性。这有助于构建文件的用户知道存在哪些目标，哪些目标做什么。构建文件往往会随着许多目标而变大，当您有 10 个或更多目标时，很难记住每个目标。

`HelloWorld.java`样本项目现安排在以下目录中：

*   `build.xml`：存在于项目的`root`文件夹中
*   `HelloWorld.java`：存在于项目的`src`文件夹中
*   `build/`：此文件夹不存在，将在生成过程中创建
*   `build/classes`和`build/jar`：这些还不存在，将在构建过程中创建

当您第一次启动`HelloWorld`项目的构建时，您将看到以下输出：

```java
$ ant
Buildfile: ~/java_11-fundamentalssources/ch02/build.xml

dirs:
    [mkdir] Created dir:
~/java_11-fundamentalssources/ch02/build/classes
    [mkdir] Created dir:
~/java_11-fundamentalssources/ch02/build/jar

compile:
...
    [javac] Compiling 1 source file to
~/java_11-fundamentalssources/ch02/build/classes

jar:
      [jar] Building jar:
~/java_11-fundamentalssources/ch02/build/jar/HelloWorld.jar

BUILD SUCCESSFUL
Total time: 0 seconds
```

从实际输出中删除一些不重要的行。

Ant 意识到，首先，它必须创建目录，然后它必须编译源代码，最后，它可以将`.class`文件打包成`.jar`文件。现在，您需要记住执行`HelloWorld`应用的命令。它已经在第一章列出了。注意，这次 JAR 文件名为`HelloWorld.jar`，它不在当前目录中。您还可以尝试阅读 Ant 的在线文档，并创建一个执行编译和打包器的目标`run`。

Ant 有一个名为`java`的内置任务，它执行 Java 类的方式与您在终端中键入`java`命令的方式几乎相同。

# Maven

由于 Ant 是为了克服`make`的不足而被创造的，Maven 也是为了克服 Ant 的不足而被创造的。您可能还记得，`make`不能保证构建的可移植性，因为`make`执行的命令是任意 Shell 命令，可能是系统特定的。如果所有任务都在类路径上可用，那么只要 Java 在不同的平台上以相同的方式运行，Ant 构建就是可移植的。

Ant 的问题有点不同。当您下载一个项目的源代码并想要构建时，命令是什么？您应该让 Ant 列出所有目标，并选择一个似乎最合适的目标。任务的名称取决于创建`build.xml`文件的工程师。有一些惯例，但它们不是严格的规则。

在哪里可以找到 Java 源文件？它们是否在`src`目录中？如果项目是 polyglot，还会有一些 Groovy 或其他编程语言文件吗？那要看情况了。同样，有些团体或公司文化可能会提出一些惯例，但没有一般的最佳行业实践。

使用 Ant 启动新项目时，必须创建编译、测试执行和打包的目标。这是你已经为其他项目做过的事情。在完成第二个或第三个项目后，您只需将以前的`build.xml`复制并粘贴到新项目中。有问题吗？是的，是的。它是复制/粘贴编程，即使只是一些构建文件。

开发人员意识到，使用 Ant 的项目的很大一部分精力都集中在项目构建工具配置上，包括重复性任务。当一个新手加入团队时，他们首先要学习如何配置构建。如果启动了新项目，则必须创建生成配置。如果这是一个重复的任务，那么最好让电脑来做。这通常就是编程的意义所在，不是吗？

Maven 处理构建问题的方式有点不同。我们想要构建 Java 项目。有时候，一些 Groovy *或* Jython 之类的东西，但它们也是 JVM 语言；因此，说我们要构建 Java 项目并不是一个很大的限制。Java 项目包含 Java 文件，有时是一些其他编程语言的源文件、资源文件，通常就是这样。Ant 可以做任何事情，但是我们不想仅仅用构建工具做任何事情。我们想建立项目。

好吧，在我们限制自己并且接受了我们不需要一个可以用于任何事情的构建工具之后，我们可以继续。我们可以要求源文件在`src`目录下。有些文件是操作代码所需要的，有些文件包含一些测试代码和数据。因此，我们将有两个目录，`src/test`和`src/main`。Java 文件在`src/main/java`和`src/test/java`中。资源文件在`src/main/resources`和`src/test/resources`下。

如果你想把你的源文件放在别的地方，那就不要。我是认真的。这是可能的，但我甚至不告诉你怎么做。没人会这么做。我甚至不知道为什么 Maven 能做到这一点。每当您看到一个使用 Maven 作为构建工具的项目时，源代码都是这样组织的。不需要理解项目的构建工程师所设想的目录结构。总是一样的。

目标和任务如何？对于所有基于 Maven 的项目，它们也是相同的。除了编译、测试、打包或部署 Java 项目之外，您还想对它做些什么？Maven 为我们定义了这些项目生命周期。当您想使用 Maven 作为构建工具来编译项目时，您必须键入`$ mvn compile`来编译项目。你甚至可以在了解项目的实际情况之前就这么做。

由于我们有相同的目录结构和相同的目标，导致目标的实际任务也都是相同的。当我们创建一个 Maven 项目时，我们不必描述构建过程必须做什么以及它必须如何做。我们将不得不描述该项目，只有部分是具体项目。

Maven 项目的构建配置在 XML 文件中给出。这个文件的名字通常是`pom.xml`，应该在项目的`root`目录下，这个目录应该是启动 Maven 时的当前工作目录。**POM** 代表**项目对象模型**，对项目进行分层描述。源目录、打包和其他内容都在所谓的超级 POM 中定义。这个 POM 是 Maven 程序的一部分。POM 定义的任何内容都会覆盖超级 POM 中定义的默认值。当一个项目有多个模块时，POM 被安排成一个层次结构，并且它们从父级到模块都继承了配置值。由于我们将使用 Maven 来开发排序代码，我们将在后面看到更多细节。

# 安装 Maven

Maven 既不是操作系统的一部分，也不是 JDK 的一部分。它必须以与 Ant 非常相似的方式下载和安装。您可以从 [Maven 的官方网站](https://maven.apache.org/)下载部分。目前，最新的稳定版本是 3.5.4。当您下载它时，实际版本可能会有所不同；相反，请使用最新的稳定版本。您可以下载源代码或预编译版本。最简单的方法是下载`tar.gz`格式的二进制文件。

我不能不提请您注意使用校验和检查下载完整性的重要性。我在“安装 Ant”一节中详细介绍了该方法。

下载文件后，可以使用以下命令将其分解为子目录：

```java
tar xfz apache-maven-3.5.4-bin.tar.gz
```

创建的子目录是 Maven 的可用二进制分布。通常我会在`~/bin`下移动，只对 OSX 上的用户使用，之后，您应该将安装的`bin`目录添加到`PATH`。为此，您应该编辑`~/.bashrc`文件并将以下行添加到其中：

```java
export M2_HOME=~/bin/apache-maven-3.5.4/
export PATH=${M2_HOME}bin:$PATH
```

然后，重新启动终端应用，或者只需键入`. ~/.bashrc`并测试 Maven 的安装，如下所示：

```java
$ mvn -v
Apache Maven 3.5.4 (1edded0938998edf8bf061f1ceb3cfdeccf443fe; 2018-06-17T20:33:14+02:00)
Maven home: /Users/verhasp/bin/apache-maven-3.5.4
Java version: 11-ea, vendor: Oracle Corporation, runtime: /Library/Java/JavaVirtualMachines/jdk-11.jdk/Contents/Home
Default locale: en_HU, platform encoding: UTF-8
OS name: "mac os x", version: "10.13.6", arch: "x86_64", family: "mac" 
```

您应该会在屏幕上看到类似的消息，其中显示已安装的 Maven 版本和其他信息。

# 使用 Maven

与 Ant 不同，Maven 帮助您创建新项目的框架。为此，必须键入以下命令：

```java
$ mvn archetype:generate
```

Maven 将首先从网络上下载实际可用的项目类型，并提示您选择要使用的项目类型。这种方法似乎是一个好主意，而 Maven 是新的。当我第一次启动 Maven 时，列出的项目数量大约在 10 到 20 个之间。今天，我在写这本书的时候，列出了 1635 种不同的原型。这个数字似乎更像是一个历史日期（法国科学院的章程），而不是不同原型的可用大小列表。但是，不要惊慌失措。Maven 在请求您选择时提供一个默认值。默认值对`HelloWorld`有利，我们选择。

```java
Choose a number: 817: 
```

安装时实际数量可能不同。不管是什么，接受建议，按`Enter`键。之后，Maven 会向您询问项目的版本：

```java
Choose version:
1: 1.0-alpha-1
2: 1.0-alpha-2
3: 1.0-alpha-3
4: 1.0-alpha-4
5: 1.0
6: 1.1
Choose a number: 6: 5
```

选择列为编号`5`的`1.0`版本。Maven 接下来要求的是项目的组 ID 和工件 ID。我们将在后面讨论的依赖关系管理使用这些。我根据书和出版商选择了一个组 ID。这个项目的工件是`SortTutorial`，因为我们将在这个项目中开始我们的章节示例。

```java
Define value for property 'groupId': : packt.java11.example
Define value for property 'artifactId': : SortTutorial
```

下一个问题是项目的当前版本。我们已经选择了`1.0`，Maven 提供`1.0-SNAPSHOT`。在这里，我选择了`1.0.0-SNAPSHOT`，因为我更喜欢语义版本。

```java
Define value for property 'version':  1.0-SNAPSHOT: : 1.0.0-SNAPSHOT
```

语义版本控制，定义于[这个页面](http://semver.org/)是一种版本控制方案，建议*主要*、*次要*和*补丁*版本号使用三位版本号`M.M.p`。这对库非常有用。如果自上一版本以来只有一个 bug 修复，那么您将增加最后一个版本号。当新版本还包含新功能，但库与以前的版本兼容时，您将增加次要数字；换句话说，任何使用旧版本的程序仍然可以使用新版本。当新版本与前一版本有显著差异时，主要版本号会增加。在应用的情况下，没有使用应用 API 的代码；因此，次要版本号没有那么重要。不过，这并没有什么坏处，而且事实证明，在应用中发出较小变化的信号通常是有用的。我们将在最后一章讨论如何对软件进行版本化。

Maven 将带有`-SNAPSHOT`后缀的版本处理为非发布版本。在开发代码时，我们将有许多版本的代码，所有版本都具有相同的快照版本号。另一方面，非快照版本号只能用于单个版本：

```java
Define value for property 'package':  packt.java11.example: :
```

程序框架生成的最后一个问题是 Java 包的名称。默认值是我们为`groupId`提供的值，我们将使用它。使用其他东西是一个罕见的例外。

当我们指定了所有需要的参数后，最后的请求是确认设置：

```java
Confirm properties configuration:
groupId: packt.java11.example
artifactId: SortTutorial
version: 1.0.0-SNAPSHOT
package: packt.java11.example
 Y: : Y
```

进入`Y`后，Maven 会生成项目所需的文件，并显示此报告：

```java
[INFO] -----------------------------------------------------------
[INFO] Using following parameters for creating project from Old (1.x)
Archetype: maven-archetype-quickstart:1.0
[INFO] -----------------------------------------------------------
[INFO] Parameter: basedir, Value: .../mavenHelloWorld
[INFO] Parameter: package, Value: packt.java11.example
[INFO] Parameter: groupId, Value: packt.java11.example
[INFO] Parameter: artifactId, Value: SortTutorial
[INFO] Parameter: packageName, Value: packt.java11.example
[INFO] Parameter: version, Value: 1.0.0-SNAPSHOT
[INFO] *** End of debug info from resources from generated POM ***
[INFO] project created from Old (1.x) Archetype in dir:
.../mavenHelloWorld/SortTutorial
[INFO] -----------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] -----------------------------------------------------------
[INFO] Total time: 01:27 min
[INFO] Finished at: 2016-07-24T14:22:36+02:00
[INFO] Final Memory: 11M/153M
[INFO] -----------------------------------------------------------
```

您可以查看以下生成的目录结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/113c68df-9aa6-49f2-8941-60c5b7a8cfa9.png)

您还可以看到，它生成了以下三个文件：

*   `SortTutorial/pom.xml`：包含**项目对象模型**
*   `SortTutorial/src/main/java/packt/java11/example/App.java`：这包含一个`HelloWorld`示例应用
*   `SortTutorial/src/test/java/packt/java11/example/AppTest.java`：它包含一个利用`junit4`库的单元测试框架

我们将在下一章讨论单元测试。现在，我们将重点讨论排序应用。由于 Maven 非常友好，并为应用生成了一个示例类，因此我们可以编译并运行它，而无需实际编码，只是为了看看如何使用 Maven 构建项目。通过发出`cd SortTutorial`将默认目录更改为`SortTutorial`，并发出以下命令：

```java
$ mvn package
```

我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/667bb862-202c-4272-8765-841d8d1a714b.png)

Maven 自动启动、编译和打包项目。如果没有，请阅读下一个信息框。

当您第一次启动 Maven 时，它会从中央存储库下载很多依赖项。这些下载需要时间，时间值会在屏幕上报告，并且这些值对于不同的运行可能不同。实际输出可能与您在前面代码中看到的不同。Maven 使用 Java 版本 1.5 的默认设置编译代码。这意味着生成的类文件与 Java1.5 版本兼容，而且编译器只接受 Java1.5 中已有的语言结构。后来的 Maven 编译器插件版本将此行为更改为使用 1.6 作为默认版本。如果我们想使用较新的语言特性，并且在本书中，我们使用了很多这些特性，`pom.xml`文件应该被编辑为包含以下行：

```java
<build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.8.0</version>
        <configuration>
            <source>1.11</source>
            <target>1.11</target>
            <release>11</release>
        </configuration>
      </plugin>
    </plugins>
  </build>
```

当使用 Java11 对 Maven 的默认设置时，它变得更加复杂，因为 Java9 和更高版本不生成类格式，也不限制早于 Java1.6 的源代码兼容性。这就是编译器插件更改其默认行为的原因。

现在，可以使用以下命令启动代码：

```java
$ java -cp target/SortTutorial-1.0.0-SNAPSHOT.jar packt.java11.example.App
```

您可以在以下屏幕截图中看到示例运行的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/79cf1967-fbf9-4427-ba2b-be4ef9d20cc5.png)

# Gradle

Ant 和 Maven 是两个世界，使用一个或另一个可能导致在互联网论坛上激烈的辩论。Ant 给开发人员自由创建符合他们口味的构建过程。Maven 限制团队使用更标准的构建过程。一些特殊的过程与任何标准构建不匹配，但有时在某些环境中需要，很难使用 Maven 实现。在 Ant 中，您可以使用内置任务编写几乎任何脚本，几乎与编程 bash 的方式相同。使用 Maven 并不是那么简单，而且它通常需要编写一个插件。即使编写插件不是火箭科学，开发人员通常也喜欢以更简单的方式编写脚本。我们有两种方法，两种思维方式和风格，而不是一个工具来满足所有的需求。毫不奇怪，当 Java 技术开发时，一个新的构建工具正在出现。

Gradle 试图利用两个世界中最好的，利用 Maven 和 Ant 最初开发时所没有的技术。

Gradle 有内置目标和生命周期，但同时，您也可以编写自己的目标。您可以像使用 Maven 一样配置项目，而不需要编写任务脚本来完成，但是同时，您也可以像 Ant 那样编写自己的目标脚本。更重要的是，Gradle 集成 Ant，因此为 Ant 实现的任何任务都可以用于 Gradle。

Maven 和 Ant 使用 XML 文件来描述构建。今天，XML 已经成为过去的技术。我们仍然使用它，开发人员应该能够熟练地处理、读取和编写 XML 文件，但现代工具不使用 XML 进行配置。新的、新奇的格式，比如 JSON，更受欢迎。Gradle 也不例外。Gradle 的配置文件使用基于 Groovy 的**领域专用语言**（**DSL**）。这种语言对于程序员来说更具可读性，并且给了编程构建过程更多的自由。这也是 Gradle 的危险所在。

将强大的 JVM 语言 Groovy 交给开发人员来创建构建工具，这给了开发人员创建复杂构建过程的自由和诱惑，这在一开始似乎是个好主意，但后来可能会被证明过于复杂和困难，因此维护成本高昂。这正是 Maven 最初实现的原因。

在进入另一个激烈而毫无意义的辩论的领域之前，我必须停下来。Gradle 是一个非常强大的构建工具。你应该小心使用它，就像你会用武器一样不要射你的腿。

# 安装 Gradle

要安装 Gradle，您必须从[网站](https://gradle.org/gradle-download/)载编译的二进制文件。

再次强调使用校验和检查下载完整性的重要性。我已经在 Ant 安装一节中给出了一个详细的方法。不幸的是，Gradle 网站没有提供可下载文件的校验和值。

Gradle 以 ZIP 格式下载。要解压缩文件，必须使用 unzip 命令：

```java
$ unzip gradle-4.9-bin.zip
```

创建的子目录是 Gradle 的可用二进制分布。通常，我会把它移到`~/bin`下，使它只对我在 OSX 上的用户可用。之后，您应该将安装的`bin`目录添加到`PATH`中。

为此，您应该编辑`~/.bashrc`文件并添加以下行：

```java
export GRADLE_HOME=~/bin/gradle-4.9/
export PATH=${GRADLE_HOME}bin:$PATH
```

然后，重新启动终端应用，或者只需键入`. ~/.bashrc`并通过键入以下内容来测试 Gradle 的安装：

```java
$ gradle -version
```

我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/c845eff4-c1bc-4604-95a9-39945edcc020.png)

# 使用 Maven 建立项目

为了启动项目，我们将使用目录结构和`pom.xml`，它是由 Maven 自己创建的，当我们使用以下命令行启动时：

```java
$ mvn archetype:generate
```

它创建了目录、`pom.xml`文件和`App.java`文件。现在，我们将通过创建新文件来扩展这个项目。我们将首先在`packt.java11.example.stringsort`包中对排序算法进行编码：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/555d22db-702c-4229-b824-6f89b9cc9c1a.png)

当我们在 IDE 中创建新包时，编辑器会自动在已经存在的`src/main/java/packt/java11/example`目录下创建`stringsort`子目录：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/bfe2ed29-1d64-4fdc-83a5-a868a4113c1e.png)

使用 IDE 创建新的`Sort`类也会自动在这个目录中创建一个名为`Sort.java`的新文件，它会填充类的骨架：

```java
package packt.java11.example.stringsort;

public class Sort {
}
```

我们现在将有包含以下代码的`App.java`：

```java
package packt.java11.example;

public class App {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

Maven 将其创建为初始版本。我们将编辑此文件以提供排序算法可以排序的示例列表。我建议您使用 IDE 来编辑文件，并编译和运行代码。IDE 提供了一个快捷菜单来启动代码，这比在终端中键入命令要简单一些。通常，建议您熟悉 IDE 特性，以节省时间并避免重复性任务，例如键入终端命令。专业开发人员几乎完全使用命令行来测试命令行功能，并尽可能使用 IDE：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/74e29fa7-672e-4f34-891d-2594b077859d.png)

# 编写排序

Maven 和 IDE 为排序程序创建了文件。它们构成了我们代码的骨架，现在是时候在它们身上长些肌肉让它移动了。我们花了相当长的时间通过访问不同的构建工具来设置项目，只是为了学习如何编译代码。

我希望这不会让你分心太多，但无论如何，我们应该看到一些真正的代码。

首先，我们将为排序代码创建代码，然后是调用排序的代码。调用排序的代码是一种测试代码。为了简单起见，我们现在将简单地使用一个`public static void main()`方法来启动代码。我们将在后面的章节中使用测试框架。

目前，排序代码如下所示：

```java
var n = names.length;
while (n > 1) {
    for (var j = 0; j < n - 1; j++) {
        if (names[j].compareTo(names[j + 1]) > 0) {
            final var tmp = names[j + 1];
            names[j + 1] = names[j];
            names[j] = tmp;
        }
    }
    n--;
}
```

这是进行排序的类。这个类中只有一个方法进行排序。该方法的参数是一个包含字符串的数组，该方法对该数组进行排序。方法没有返回值。这在使用伪类型`void`的声明中表示。方法使用其参数执行某些任务，并且可能返回一个值。方法的参数是按值传递的，这意味着方法不能修改作为参数传递的变量。但是，它可以修改参数包含的对象。在本例中，将修改数组并对其进行排序。另一方面，`actualNames`变量将指向同一数组，`sort()`方法无法使该变量指向不同的数组。

这个类中没有`main()`方法，这意味着它不能单独从命令行启动。这个类只能从其他类中使用，因为每个 Java 程序都应该有一个类，该类具有我们单独创建的`public static void main()`方法。

我也可以在类中放入一个`main()`方法，使其可执行，但这不是一个好的做法。真正的程序是由许多类组成的，一个类不应该做很多事情。恰恰相反。*单一责任原则*说一个类应该负责一件事；因此，`class sort`进行排序。执行应用是一个不同的任务，因此它必须在不同的类中实现。

通常，我们不实现包含`main()`方法的类；框架提供了它。例如，编写在 Servlet 容器中运行的 Servlet 需要包含实现`javax.servlet.Servlet`接口的类。在这种情况下，程序似乎没有`main()`方法。Servlet 容器的实际实现并不需要。Java 命令行启动容器，容器在需要时加载 Servlet。

在下面的示例代码中，我们实现了包含`main()`方法的`App`类：

```java
package packt.java11.example.stringsort;

public class App {
    public static void main(String[] args) {
        var actualNames = new String[]{
                "Johnson", "Wilson",
                "Wilkinson", "Abraham", "Dagobert"};
        Sort.sort(actualNames);
        for (final String name : actualNames) {
            System.out.println(name);
        }
    }
}
```

该代码包含一个初始化为包含常量值的字符串数组，创建一个新的`Sort`类实例，调用`sort()`方法，然后将代码打印到标准输出。

在实际的程序中，我们几乎从来没有在程序代码中有这样的常量；我们将它们放入资源文件中，并有一些代码来读取实际值。这将代码与数据分离，简化维护，消除了仅更改数据时意外修改代码结构的风险。同样，我们几乎永远不会使用`System.out`将任何内容写入标准输出。通常，我们将使用不同来源的日志记录可能性。有不同的库提供日志功能，日志也可以从 JDK 本身获得。

目前，我们将重点关注简单的解决方案，以避免由于大量不同的库和工具而分散您对 Java 的关注。在接下来的部分中，我们将介绍我们在编码算法时使用的 Java 语言构造。首先，我们将一般地看它们，然后，在更详细的地方。这些语言特性彼此不独立，因此，解释首先是一般性的，我们将在下面的小节中详细介绍。

# 理解算法和语言结构

在本章的开头对算法进行了说明。实现在`sort()`方法内`Sort`类中，仅由几行组成：

```java
var n = names.length;
while (n > 1) {
    for (var j = 0; j < n - 1; j++) {
        if (names[j].compareTo(names[j + 1]) > 0) {
            final var tmp = names[j + 1];
            names[j + 1] = names[j];
            names[j] = tmp;
        }
    }
    n--;
}
```

`n`变量在排序开始时保持数组的长度。Java 中的数组总是有一个给定长度的属性，它被称为`length`。当我们开始排序时，我们将从数组的开始到它的末尾，正如您可能记得的，最后一个元素`Wilson`将在第一次迭代中到达最后一个位置。后续迭代将更短，因此，变量`n`将减少。

# 代码块

Java 中的代码是在代码块中创建的。任何介于`{`和`}`字符之间的字符都是块。在前面的示例中，方法的代码是一个块。它包含命令，其中一些命令，比如`while`循环，也包含一个块。在该块中，有两个命令。其中一个是一个`for`循环，同样是一个块。虽然我们可以使用单个表达式来形成循环体，但我们通常使用块。我们将在几页中详细讨论循环。

正如我们在前面的示例中所看到的，循环可以嵌套，因此，`{`和`}`字符形成成对。一个块可以在另一个块内，但两个块不能重叠。当代码包含一个`}`字符时，它将关闭最后打开的块。

# 变量

在 Java 中，就像在几乎所有编程语言中一样，我们使用变量。Java 中的变量是类型化的。这意味着变量可以保存单一类型的值。变量不可能在程序中的某个点上保存`int`类型，然后保存`String`类型。声明变量时，变量的类型写在变量名前面。当局部变量在声明它的行上获得初始值时，可以使用名为`var`的特殊保留类型。它表示与赋值运算符右侧表达式的类型完全相同的类型。

代码的外观如下：

```java
var n = names.length;
```

也可以这样写：

```java
int n = names.length;
```

这是因为表达式`names.length`具有`int`类型。此功能称为局部变量类型推断，因为类型是从右侧推断的。如果变量不是某个方法的局部变量，则不能使用此选项。

当我们声明一个字段（一个在类的方法体之外的类级别上的变量，而不是在初始化器块或构造器中）时，我们必须指定我们想要的变量的确切类型。

变量也具有可见性范围。方法中的局部变量只能在定义它们的块内使用。变量可以在方法内部使用，也可以属于类或对象。为了区分两者，我们通常称之为变量字段。

# 类型

每个变量都有一种类型。在 Java 中，主要有两组类型：原始类型和引用类型。原始类型是预定义的，不能定义或创建新的原始类型。原始类型有八种：`byte`、`short`、`int`、`long`、`float`、`double`、`boolean`、`char`。

前四种类型`byte`、`short`、`int`和`long`是有符号数字整数类型，能够存储 8 位、16 位、32 位和 64 位的正数和负数。

`float`和`double`类型以 IEEE754 浮点格式存储 32 位和 64 位的浮点数。

`boolean`类型是一个原始类型，只能是`true`或`false`。

`char`类型是存储单个 16 位 Unicode 字符的字符数据类型。

对于每个原始类型，都有一个对应的类。类的实例可以存储相同类型的值。当一个原始类型必须转换为匹配的类类型时，它是自动补全的。它被称为自动装箱。这些类型是`Byte`、`Short`、`Integer`、`Long`、`Float`、`Double`、`Boolean`和`Character`。以以下变量声明为例：

```java
Integer a = 113;
```

这将值`113`（即`int`数字）转换为`Integer`对象。

这些类型是运行时的一部分，也是语言的一部分。

有一个特殊的类，叫`String`。此类型的对象包含字符。`String`没有原始对应物，但我们使用它很多次，就像是原始类型，它不是。它在 Java 程序中无处不在，并且有一些语言构造，例如直接与这种类型一起工作的字符串连接。

原始类型和对象之间的主要区别在于原始类型不能用来调用它们的方法。它们只是值。当我们创建并发程序时，它们不能用作锁。另一方面，它们消耗更少的内存。内存消耗与其对速度的影响之间的差异非常重要，尤其是当我们有一个值数组时。

# 数组

根据它们的声明，变量可以是原始类型，也可以包含对对象的引用。一种特殊的对象类型是数组。当一个变量持有一个数组的引用时，它可以用`[`和`]`字符以及一个由 0 组成的整数值或一个小于数组长度的正数来索引，以访问数组的某个元素。当数组中的元素也是数组时，Java 也支持多维数组。在 Java 中数组是从零开始索引的。在运行时检查索引不足或索引过度，结果是异常。

异常是一种特殊情况，它会中断正常的执行流并停止代码的执行或跳到最近的封闭的`catch`语句。我们将在下一章讨论异常以及如何处理它们。

当一个代码有一个原始类型的数组时，该数组包含内存槽，每个槽都保存该类型的值。当数组有一个引用类型时，换句话说，当它是一个对象数组时，那么数组元素就是对对象的引用，每个元素都引用该类型的一个实例。例如，在`int`的情况下，数组的每个元素是 32 位的，即 4 字节。如果数组是一种类型`Integer`，那么元素就是对对象、指针的引用，也就是说，使用 64 位 JVM 通常是 64 位的，32 位 JVM 通常是 32 位的。除此之外，内存中某处还有一个包含 4 字节值的`Integer`对象，还有一个可能高达 24 字节的对象头。

标准中没有定义管理每个对象所需的额外信息的实际大小。在 JVM 的不同实现上可能会有所不同。实际的编码，甚至环境中代码的优化，不应该依赖于实际的大小。但是，开发人员应该意识到这种开销是存在的，每个对象的开销大约在 20 字节左右。对象在内存消耗方面是昂贵的。

内存消耗是一个问题，但还有其他问题。当程序处理大量数据并且工作需要数组中的连续元素时，CPU 会将一块内存加载到处理器缓存中。这意味着 CPU 可以连续访问数组中速度更快的元素。如果数组是原始类型，那么它是快速的。如果数组是某个类类型，那么 CPU 可能需要访问内存，通过数组中的引用获取数组元素的实际值。这可能要慢 50 倍。

# 表达式

Java 中的表达式与其他编程语言非常相似。可以使用类似于 C 语言或 C++ 语言的操作符。具体如下：

*   一元前缀和后缀递增运算符（`--`和`++`在变量前后）
*   一元符号（`+`和`-`运算符）
*   逻辑（`!`）和位（`~`）取反
*   乘法（`*`）、除法（`/`）和模（`%`）
*   加减法（再次是`+`和`-`，但这次是二进制运算符）
*   移位运算符按位移动值，有左移位（`<<`）、右移位（`>>`）和无符号右移位（`>>>`）
*   比较运算符为产生`boolean`值的`<`、`>`、`<=`、`>=`、`==`、`!=`和`instanceof`
*   有位或（`|`）和（`&`）、异或（`^`）运算符，以及类似的逻辑或（`||`）和（`&&`）运算符

对逻辑运算符求值时，将对其进行快捷方式求值。这意味着，只有在无法从左操作数的结果中识别结果时，才对右操作数求值。

三元运算符也类似于 C 上的运算符，根据某种条件从表达式中选择-`condition ? expression 1 : expression 2`。通常，三元运算符没有问题，但有时必须小心，因为有一个复杂的规则控制类型转换，以防两个表达式的类型不同。最好有两个相同类型的表达式。

最后，还有一个赋值运算符（`=`），它将表达式的值赋给变量。对于每个二元运算符，都有一个赋值版本，它将`=`与一个二元运算符结合起来，执行一个涉及右操作数的操作，并将结果赋给左操作数，左操作数必须是一个变量。它们是`+=`、`-=`、`*=`、`/=`、`%=`、`&=`、`^=`、`|=`、`<<=`、`>>=`和`>>>=`。

运算符具有优先权，可以像往常一样用括号覆盖。

表达式的一个重要部分是调用方法。静态方法可以通过类的名称和方法的名称点分隔来调用。例如，要计算 1.22 的正弦值，我们可以编写以下代码行：

```java
double z = Math.sin(1.22);
```

这里，`Math`是包`java.lang`中的类。调用`sin`方法时不使用`Math`的实例。这个方法是`static`，除了类`Math`中提供的方法之外，我们不太可能需要任何其他的实现。

可以使用实例和方法名调用非静态方法，方法名之间用点分隔。例如，考虑以下代码：

```java
System.out.println("Hello World");
```

该代码使用通过`System`类中的静态字段随时可用的`PrintStream`类实例。这个变量叫做`out`，当我们编写代码时，我们必须引用它为`System.out`。`println`方法是在`PrintStream`类中定义的，我们在`out`变量引用的对象上调用它。这个例子还显示静态字段也可以通过类的名称和用点分隔的字段来引用。类似地，当我们需要引用非静态字段时，我们可以通过类的实例来实现。

在同一个类中定义的静态方法，可以从调用它或者继承的地方，在没有类名的情况下调用。调用在同一类中定义的或被继承的非静态方法可以在没有显式实例表示法的情况下调用。在本例中，实例是执行所在的当前对象。这个对象也可以通过`this`关键字获得。类似地，当我们使用代码所在的同一类的字段时，我们只使用名称。对于静态字段，我们所在的类是默认的。对于非静态字段，实例是由`this`关键字引用的对象。

您还可以使用`import static`语言特性将静态方法导入到代码中，在这种情况下，您可以调用不带类名的方法。

方法调用的参数用逗号分隔。方法和方法参数传递是我们稍后将讨论的一个重要主题。

# 循环

让我们再次看看字符串排序的代码。`while`循环中的`for`循环将遍历从第一个元素（在 Java 中用零索引）到最后一个元素（用`n-1`索引）的所有元素。一般来说，这个`for`循环与 C 中的语法相同：

```java
for( initial expression ; condition ; increment expression )
  block
```

首先，计算初始表达式。它可能包含变量声明，如我们的示例所示。前例中的`j`变量仅在循环块内可见。之后，将求值条件，在执行块之后，执行增量表达式。只要条件为真，循环就会重复。如果在执行初始表达式之后条件为`false`，则循环根本不会执行。该块是一个用分号分隔的命令列表，并在`{`和`}`字符之间封闭。

封闭块 Java 代替了`{`和`}`，它允许您在`for`循环头之后使用单个命令。在`while`循环的情况下也是如此，对于`if...else`构造也是如此。实践表明，这不是专业人士应该使用的。专业代码总是使用大括号，即使只有一个命令块在适当的位置。这就避免了悬空`else`问题，通常使代码更具可读性。这类似于许多 C 语言。它们中的大多数都允许在这些地方使用单个命令，而专业程序员为了可读性的目的避免在这些语言中使用单个命令。讽刺的是，在这些地方，唯一严格要求使用`{`和`}`大括号的语言是 Perl—一种因代码不可读而臭名昭著的语言。

`for (var j = 0; j < n - 1; j++) {`样品回路从零开始，进入`n-2`。在这种情况下，写入`j < n-1`与`j <= n-2`相同。我们将限制`j`在数组结束之前停止在循环中，因为我们通过比较和有条件地交换`j`和`j+1`索引的元素，达到了索引`j`之外的范围。如果我们进一步讨论一个元素，我们将尝试访问数组中不存在的元素，并且它会导致运行时异常。尝试将回路条件修改为`j < n`或`j <= n-1`，系统会得到以下错误信息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/37826676-a01e-48e5-8343-6eff833dfc07.png)

Java 的一个重要特性是运行时检查内存访问，并在数组索引错误的情况下抛出异常。在过去的好日子里，当我们用 C 语言编写代码时，我们经常会遇到无法解释的错误，这些错误使我们的代码在很久以后停止运行，并且与真正的错误所在的代码位置完全不同。C 中的数组索引悄悄地损坏了内存。一旦你犯了错误，Java 就会阻止你。它遵循同样应该在代码中使用的快速失败方法。如果出了问题，程序就会失败。任何代码都不应该试图忍受或克服来自编码错误的错误。在编码错误造成更大的损害之前，应该先修复它们。

Java 中还有另外两个循环构造，`while`循环和`do`循环。下面的示例包含一个`while`循环。只要数组中至少有两个元素可能需要交换，就可以运行外部循环：

```java
while (n > 1) {
```

`while`循环的一般语法和语义非常简单，如下代码所示：

```java
while ( condition ) block
```

只要条件是`true`，就重复执行该块。如果条件在循环的最开始不是真的，那么根本不执行块。`do`循环也是类似的，但是它在每次执行块之后检查条件：

```java
do block while( condition );
```

出于某种原因，程序员很少使用`do`循环。

# 条件执行

排序的核心是循环内的条件和值交换。

```java
if (names[j].compareTo(names[j + 1]) > 0) {
                    final String tmp = names[j + 1];
                    names[j + 1] = names[j];
                    names[j] = tmp;
                }
```

Java 中只有一个条件命令，`if`命令。其格式如下：

```java
if( condition ) block else block
```

代码结构的含义非常简单。如果条件为`true`，则执行第一块，否则执行第二块。`else`关键字和第二个块是可选的。创建`else`并在其后面创建一个块是可选的。如果条件为`false`时没有要执行的内容，那么我们就不创建`else`部分。如果用`j`索引的数组元素在排序顺序上晚于元素`j+1`，那么我们交换它们；但是，如果它们已经在排序中，则与它们无关。

为了交换这两个数组元素，我们使用了一个名为`tmp`的临时变量。该变量的类型为`String`，声明为`final`。`final`关键字有不同的含义，这取决于它在 Java 中的使用位置。这可能会让初学者感到困惑，除非你像现在一样被警告过。`final`类或方法与`final`字段完全不同，后者又不同于`final`局部变量。

注意，这次我们使用显式类型`String`来声明变量。我们可以用`var`和`final var`来代替，这样就可以推断出相同的类型。这里使用显式类型的唯一原因是为了演示。

# 最终变量

在我们的例子中，`tmp`是一个`final`局部变量。这个变量的作用域被限制在`if`语句后面的块中，在这个块中，这个变量只得到一个值。该块在代码执行期间执行多次，每次变量进入作用域时，它都会得到一个值。但是，此值不能在块内更改，并且在块外不存在。这可能有点混乱。您可以将其视为每次执行块时都有一个新的`tmp`。变量被声明；首先它是未定义的，然后它得到一个值。

最终的局部变量不需要获得声明它们的值。您可以稍后为一个`final`变量赋值。重要的是，不应该有一个代码执行为之前已经赋值的`final`变量赋值。如果存在重新分配`final`变量的可能性，编译器会检查它，并且不会编译代码。编译器还检查在未定义变量时不应使用局部变量（不仅仅是`final`变量）的值。

将变量声明为`final`通常是为了简化代码的可读性。当您在代码中看到一个声明为`final`的变量时，您可以假设该变量的值不会改变，并且该变量的含义在方法中使用的任何地方都是相同的。当你试图修改一些变量时，它也会帮助你避免一些错误，IDE 会立即对此提出抱怨。在这种情况下，很可能是一个很早就发现的编程错误。

原则上，可以编写一个所有变量都是`final`的程序。通常，将所有可声明为`final`的`final`变量声明为`final`是一种好的做法，如果某些变量可能未声明为`final`，则尝试找到某种方法对该方法进行稍微不同的编码。

如果您需要引入一个新变量来实现这一点，可能意味着您使用了一个变量来存储两个不同的东西。这些东西属于同一类型，在不同的时间存储在同一个变量中，但从逻辑上讲，它们仍然是不同的东西。不要试图优化变量的使用。永远不要使用变量，因为您的代码中已经有一个可用的相同类型的变量。如果它在逻辑上是一个不同的东西，那么声明一个新变量。在编码时，总是喜欢源代码的清晰性和可读性。特别是在 Java 中，即时编译器将为您优化所有这些。

尽管我们不明确地倾向于在方法的参数列表中使用`final`关键字，但是如果参数声明为`final`，那么确保方法编译并工作是一种很好的做法。包括我在内的一些专家认为，默认情况下，该语言应该将方法参数设置为`final`。只要 Java 遵循向后兼容的理念，这在任何版本的 Java 中都不会发生。

# 类

现在我们已经查看了实际的代码行，并且已经了解了算法的工作原理，接下来让我们看看更全局的代码结构，它将类和封装方法的包结合在一起。

Java 程序中的每个文件都定义一个类。Java 程序中的任何代码都在一个类中。没有什么比 C、Python、Go 或其他语言中的全局变量或全局函数更好的了。Java 是完全面向对象的。

一个文件中可以有多个类，但通常一个文件就是一个类。稍后，当一个类在另一个类中时，我们将看到有内部类，但是，现在，我们将把一个类放入一个文件中。

Java 语言中有一些我们不使用的特性。当语言被创建时，这些特性似乎是个好主意。CPU、内存和其他资源，包括平庸的开发人员，也比今天更加有限。由于这些环境限制，其中一些特性可能更有意义。有时候，我会提到这些。对于类，您可以将多个类放入一个文件中，只要只有一个是`public`。那是不好的做法，我们永远不会那样做。Java 从不抛弃这些特性。直到最近，Java 的一个理念是保持与以前所有版本的兼容性，这种理念变化缓慢。这对于已经编写的大量遗留代码来说是很好的。使用旧版本编写和测试的 Java 代码将在更新的环境中工作。同时，这些特性将初学者引入错误的风格。出于这个原因，有时，我甚至不会提及这些特性。例如，在这里，我可以说-*文件中有一个类*。这不是绝对正确的。同时，详细解释一个我建议不要使用的特性或多或少是没有意义的。稍后，我可能会跳过它们。这些功能并不多。

类是使用`class`关键字定义的，每个类都必须有一个名称。名称在包中应该是唯一的（请参阅下一节），并且必须与文件名相同。一个类可以实现一个接口或扩展另一个类，我们将在后面看到一个示例。类也可以是`abstract`、`final`、`public`。这些是用适当的关键字定义的，您将在下面的示例中看到。

我们的项目有两个类。它们都是`public`。`public`类可以从任何地方访问。不是`public`的类只在包内可见。内部类和嵌套类也可以`private`仅在文件级定义的顶级类中可见。

包含要由 Java 环境调用的`main()`方法的类应该是`public`。这是因为它们是由 JVM 调用的。

类从文件的开头开始，在包声明之后，所有字符之间的`{`和`}`字符都属于该类。方法、字段、内部或嵌套类等是类的一部分。通常，大括号表示 Java 中的某些块。这是用 C 语言发明的，许多语言都遵循这个符号。类声明是块，方法是使用块、循环和条件命令定义的，所有这些命令都使用块。

当我们使用类时，我们必须创建类的实例。这些实例是对象。换句话说，对象是通过实例化类来创建的。为此，在 Java 中使用了`new`关键字。在`App`类中执行`final Sort sorter = new Sort();`行时，它会创建一个实例化`Sort`类的新对象。我们还将说我们创建了一个新的`Sort`对象，或者该对象的类型是`Sort`。创建新对象时，将调用该对象的构造器。有点草率，我可以说，构造器是类中的一个特殊方法，它与类本身具有相同的名称，并且没有返回值。这是因为它返回创建的对象。准确地说，构造器不是方法。它们是初始化器，不返回新对象。他们正在处理尚未准备好的对象。当执行对象的构造器未完全初始化时，某些最终字段可能未初始化，并且如果构造器引发异常，则整体初始化仍可能失败。在我们的示例中，代码中没有任何构造器。在这种情况下，Java 会创建一个默认构造器，它不接受任何参数，也不会修改已经分配但尚未初始化的对象。如果 Java 代码定义了一个初始化器，那么 Java 编译器不会创建一个默认的初始化器。

一个类可以有许多构造器，每个构造器都有不同的参数列表。

除了构造器之外，Java 类还可以包含初始化器块。它们是类级别上的块，与构造器和方法处于同一级别。这些块中的代码被编译到构造器中，并在构造器执行时执行。

也可以初始化静态初始化器块中的静态字段。这些是类中顶层的块，前面有`static`关键字。它们只执行一次，也就是说，当类被加载时。

我们将示例中的类命名为`App`和`Sort`。这是 Java 示例`App`和`Sort`中的约定。这是 Java 中的一个约定，在这个约定中，您必须命名驼峰大小写中的几乎所有内容。

驼峰大小写是单词之间没有空格的情况。第一个单词可以以小写或大写开头，为了表示第二个和随后的单词的开头，它们以大写开头。`ForExampleThisIsALongCamelCase`姓名。

类名以大写字母开头。这不是语言形式上的要求，但这是每个程序员都应该遵循的惯例。这些编码约定可以帮助您创建其他程序员更容易理解的代码，并使维护更容易。静态代码分析器工具，如 [Checkstyle](http://checkstyle.sourceforge.net/)，还要检查程序员是否遵循约定。

# 内部、嵌套、本地和匿名类

在上一节中我已经提到了内部类和嵌套类。现在，我们将更详细地了解它们。

此时，内部类和嵌套类的细节可能很难理解。如果你不完全理解这一节，不要感到羞愧。如果太难，请跳到下一节，阅读有关包的内容，稍后返回此处。嵌套类、内部类和本地类很少使用，尽管它们在 Java 中有自己的角色和用途。匿名类在 GUI 编程中非常流行，Swing 用户界面允许开发人员创建 JavaGUI 应用。有了 Java8 和 Lambda 特性，匿名类现在已经不那么重要了，而随着 JavaScript 和浏览器技术的出现，JavaGUI 变得不那么流行了。

当一个类单独在一个文件中定义时，它被称为顶级类。显然，在另一个类中的类不是顶级类。如果它们是在与字段（不是某个方法或另一个块的局部变量）相同级别的类中定义的，则它们是内部类或嵌套类。它们之间有两个区别。一种是嵌套类在其定义中将`static`关键字放在`class`关键字之前，而内部类则没有。

另一个区别是嵌套类的实例可以在没有周围类实例的情况下存在。内部类实例总是引用周围类的实例。

由于没有周围类的实例，内部类实例不可能存在，因此只能通过提供外部类的实例来创建它们的实例。如果周围的类实例是实际的`this`变量，我们将看不到区别，但是如果我们想从周围类外部创建一个内部类的实例，那么我们必须在`new`关键字之前提供一个实例变量，用点分隔，就像`new`是方法一样。例如，我们可以有一个名为`TopLevel`的类，它有一个名为`InnerClass`的类，如下面的代码段所示：

```java
public class TopLevel {

    class InnerClass { }
}
```

然后，我们可以从外部创建一个只包含一个`TopLevel`对象的`InnerClass`实例，如下代码段所示：

```java
TopLevel tl = new TopLevel();
InnerClass ic = tl.new InnerClass();
```

由于非静态内部类具有对封闭类实例的隐式引用，因此内部类中的代码可以访问封闭类的字段和方法。

嵌套类没有对封闭类实例的隐式引用，它们可以用`new`关键字实例化，而不引用任何其他类的实例。因此，它们不能访问封闭类的字段，除非它们是静态字段。

局部类是在方法、构造器或初始化器块中定义的类。我们将很快讨论初始化器块和构造器。本地类可以在定义它们的块中使用。

匿名类是在一个命令中定义和实例化的。它们是嵌套、内部或本地类的一种短形式，以及类的实例化。匿名类总是实现接口或扩展命名类。新关键字后面是接口的名称或类，在括号之间的构造器中包含参数列表。定义匿名类主体的块在构造器调用之后立即站在后面。在扩展接口的情况下，构造器可以是唯一没有参数的构造器。没有名称的匿名类不能有自己的构造器。在现代 Java 中，我们通常使用 Lambda 而不是匿名类。

最后但同样重要的是，实际上，至少我应该提到嵌套类和内部类也可以嵌套在更深的结构中。内部类不能包含嵌套类，但嵌套类可以包含内部类。为什么？我从来没有遇到过谁能可靠地告诉我真正的原因。没有架构上的原因。可能是这样的。Java 不允许这样。然而，这并不是很有趣。如果您碰巧编写了具有多个类嵌套级别的代码，那么请停止这样做。很可能你做错了什么。

# 包

类被组织成包，文件中的第一行代码应该指定类所在的包：

```java
package packt.java11.example.stringsort;
```

如果不指定包，则类将位于默认包中。除非在最简单的情况下您想尝试一些代码，否则不应使用此选项。在 Java11 中，您可以使用`jshell`来实现这个目的。因此，与以前版本的 Java 不同，现在的建议变得非常简单：不要将任何类放在默认包中。

包的名称是分层的。名字的各个部分用点隔开。使用包名有助于避免名称冲突。类的名称通常保持简短，将它们放入包中有助于程序的组织。类的全名包括类所在的包的名称。通常，我们会将这些类放入一个以某种方式相关的包中，并向程序的类似方面添加一些内容。例如，MVC 模式程序中的控制器保存在单个包中。包还可以帮助您避免类的名称冲突。但是，这只会将问题从类名冲突推到包名冲突。我们必须确保包的名称是唯一的，并且当我们的代码与任何其他库一起使用时不会引起任何问题。当开发一个应用时，我们只是不知道在以后的版本中将使用哪些库。为了防患于未然，惯例是根据一些互联网域名来命名包。当开发公司拥有域名`acmecompany.com`时，他们的软件通常在`com.acmecompany...`包下。这不是一个严格的语言要求。从右到左写域名，并将其用作包名，这只是一种惯例，但这在实践中证明是相当好的。有时，就像我在这本书中所做的，一个人可以偏离这一做法，所以你可以看到这条规则不是刻在石头上的。

当机器启动时，代码被编译成字节码，包就成为类的名称。因此，`Sort`类的全名是`packt.java11.example.stringsort.Sort`。使用另一个包中的类时，可以使用此全名或将该类导入到类中。同样，这是在语言层面。当 Java 变成字节码时，使用完全限定名或导入没有区别。

# 方法

我们已经讨论了方法，但没有详细讨论，在继续之前，还有一些方面需要讨论。

示例类中有两个方法。一个类中可以有许多方法。方法名也是按约定大小写的，名称以小写字母开头，而不是类。

方法可能返回一个值。如果一个方法返回一个值，那么这个方法必须声明它返回的值的类型，在这种情况下，任何代码的执行都必须用一个`return`语句来完成。`return`语句在关键字后面有一个表达式，在方法执行时对其求值，然后由方法返回。一个方法只有一个返回是一个很好的实践，但是在一些简单的情况下，打破这种编码惯例是可以原谅的。编译器检查可能的方法执行路径，如果某些路径不返回值，则为编译时错误。

当一个方法不返回任何值时，它必须声明为`void`。这是一个特殊类型，表示没有值。`void`方法，例如`public static void main()`方法，可能只是错过了`return`语句而只是结束。如果有一个`return`语句，则在`return`关键字后面没有定义返回值的表达式。同样，这是一种编码约定，在方法不返回任何值的情况下不使用`return`语句，但在某些编码模式中，可能不遵循这种约定。

方法可以是`private`、`protected`、`public`、`static`，我们稍后再讨论它们的含义。

我们已经看到，程序启动时调用的`main()`方法是`static`方法。这样的方法属于类，可以在没有类实例的情况下调用。静态方法是用`static`修饰符声明的，它们不能访问任何非静态的字段或方法。

在我们的例子中，`sort()`方法不是静态的，但是因为它不访问任何字段，也不调用任何非静态方法（事实上，它根本不调用任何方法）；它也可以是`static`。如果我们将方法的声明改为`public static void sort(String[] names) {`（注意`static`一词），程序仍然可以运行，但是编辑时 IDE 会给出警告，如下例所示：

```java
Static member 'packt.java11.example.stringsort.Sort.sort(java.lang.String[])' accessed via instance reference
```

这是因为您可以通过`Sort.sort(actualNames);`类的名称直接访问方法，而无需使用`sorter`变量。在 Java 中，通过实例变量调用静态方法是可能的（同样，在 Java 的起源中似乎是一个好主意，但可能不是），但它可能会误导代码的读者，使他们认为该方法是一个实例方法。

制作`sort()`方法`static`，`main()`方法如下：

```java
public static void main(String[] args) {
    String[] actualNames = new String[]{
            "Johnson", "Wilson",
            "Wilkinson", "Abraham", "Dagobert"
    };
    Sort.sort(actualNames);
    for (final String name : actualNames) {
        System.out.println(name);
    }
}
```

它看起来简单得多（它是），并且，如果方法没有使用任何字段，您可能认为没有理由使方法非静态。在 Java 的前 10 年中，静态方法得到了大量使用。甚至还有一个术语，工具类，它意味着一个类只有静态方法，不应该实例化。随着**控制反转**容器的出现，我们往往采用较少的静态方法。当使用静态方法时，使用**依赖注入**难度较大，创建测试也比较困难。我们将在接下来的几章中讨论这些高级主题。目前，您将了解静态方法是什么，哪些方法可以使用；但是，通常，除非对它们有非常特殊的需求，否则我们将避免使用它们。

稍后，我们将研究如何在层次结构中实现类，以及类如何实现接口和扩展其他类。当我们查看这些特性时，我们将看到，有所谓的抽象类可能包含抽象方法。这些方法有`abstract`修饰符，它们不仅定义名称、参数类型（和名称）以及返回类型。扩展抽象类的具体（非抽象）类应该定义它们。

抽象方法的对立面是用`final`修饰符声明的最终方法。`final`方法不能在子类中覆盖。

# 接口

方法也在接口中声明。接口中声明的方法不定义方法的实际行为；它们不包含代码。它们只有方法的头；换句话说，它们是隐式抽象的。虽然没有人这样做，但在定义方法时，甚至可以在接口中使用`abstract`关键字。

接口看起来与类非常相似，但是我们没有使用`class`关键字，而是使用`interface`关键字。由于接口主要用于定义方法，如果不使用修饰符，则方法为`public`。

接口也可以定义字段，但由于接口不能有实例（只有实现类才能有实例），所以这些字段都是`static`，也必须是`final`。这是接口中字段的默认值，因此如果在接口中定义字段，则不需要编写这些字段。

通常的做法是只在一些接口中定义常量，然后在类中使用这些常量。为此，最简单的方法是实现接口。因为这些接口没有定义任何方法，所以实现只不过是将`implements`关键字和接口的名称写入类声明的头中。这种做法不好，因为这样接口就成为类的公共声明的一部分，尽管类中需要这些常量。如果您需要定义不是某个类的本地常量，而是在许多类中使用的常量，那么可以在一个类中定义这些常量，并使用`import static`导入字段，或者只使用类和字段的名称。

接口也可以有嵌套类，但不能有内部类。这样做的明显原因是内部类实例引用了封闭类的实例。在接口的情况下，没有实例，因此内部类不能有对封闭接口实例的引用，因为封闭接口实例不存在。令人高兴的是，在嵌套类的情况下，我们不需要使用`static`关键字，因为这是默认值，就像在字段的情况下一样。

随着 Java8 的出现，您还可以在接口中拥有`default`方法，这些方法为实现接口的类提供该方法的默认实现。从 Java9 开始，接口中也可以有`static`和`private`方法。

方法由它们的名称和参数列表标识。您可以重用方法的名称，并具有不同的参数类型；Java 将根据实际参数的类型确定要使用哪种方法。这称为**方法重载**。通常，很容易判断您调用的方法，但是当有类型相互扩展时，情况会变得更加复杂。标准为编译器所遵循的方法的实际选择定义了非常精确的规则，因此不存在歧义。然而，阅读代码的同行程序员可能会误解重载方法，或者至少很难确定实际调用哪种方法。方法重载可能会妨碍在扩展类时向后兼容。一般建议是在创建重载方法之前仔细考虑。它们是有利可图的，但有时可能会很昂贵。

# 参数传递

在 Java 中，参数是按值传递的。当方法修改参数变量时，只修改原始值的副本。在方法调用期间复制任何原始值。当对象作为参数传递时，则传递对该对象的引用的副本。

这样，就可以为方法修改对象。对于具有其原始对应项的类，以及对于`String`和其他一些类类型，对象只是不提供方法或字段来修改状态。这对于语言的完整性很重要，并且在对象和原始类型值自动转换时不会遇到麻烦。

在其他情况下，当对象是可修改的时，该方法可以有效地处理传递给它的对象。这也是我们示例中的`sort()`方法在数组上的工作方式。同一个数组本身也是一个对象，会被修改。

这种参数的传递比其他语言要简单得多。其他语言允许开发人员混合传递引用和**传递值**参数。在 Java 中，当您单独使用一个变量作为表达式将一个参数传递给一个方法时，您可以确保变量本身不会被修改。但是，如果对象是可变的，则可以修改它。

一个对象是可变的，如果它可以被修改，直接或通过一些方法调用改变它的一些字段的值。当一个类被设计成在对象创建之后没有正常的方式来修改对象的状态时，对象是不可变的。类`Byte`、`Short`、`Integer`、`Long`、`Float`、`Double`、`Boolean`、`Character`以及`String`在 JDK 中被设计成对象是不可变的。使用反射可以克服某些类的不变性实现的限制，但这样做是黑客行为，而不是专业的编码。这样做的目的只有一个，即更好地了解和理解一些 Java 类的内部工作原理，而不是别的。

# 字段

字段是类级别的变量。它们代表一个物体的状态。它们是定义了类型和可能的初始值的变量。字段可以是`static`、`final`、`transient`、`volatile`，可以使用`public`、`protected`、`private`关键字修改访问权限。

静态字段属于该类。这意味着类的所有实例都共享其中一个。正常的、非静态的字段属于对象。如果您有一个名为`f`的字段，那么类的每个实例都有自己的`f`。如果将`f`声明为`static`，则实例将共享同一`f`字段。

`final`字段初始化后不能修改。初始化可以在声明它们的行、初始化器块或构造器代码中完成。严格的要求是初始化必须在构造器返回之前发生。这样，`final`关键字的含义就与类或方法的含义大不相同了。在扩展类中，`final`类不能被扩展，`final`方法不能被覆盖，我们将在下一章中看到。`final`字段要么未初始化，要么在实例创建期间获取值。编译器还检查代码是否在创建对象实例期间或类加载期间初始化了所有的`final`字段（如果`final`字段是`static`），以及代码是否没有访问/读取任何尚未初始化的`final`字段。

一个常见的误解是，`final`字段必须在声明时初始化。它可以在初始化器代码或构造器中完成。限制条件是，如果有更多的构造器，无论调用哪个构造器，`final`字段都必须初始化一次。

`transient`字段不是对象序列化状态的一部分。序列化是将对象的实际值转换为物理字节的行为。当从字节创建对象时，反序列化则相反。它在某些框架中用于保存状态。执行序列化的代码`java.lang.io.ObjectOutputStream`只与实现`Serializable`接口的类一起工作，并且只使用那些不属于`transient`的对象中的字段。很明显，`transient`字段也不会从表示对象序列化形式的字节还原，因为它们的值不在那里。

序列化通常用于分布式程序。一个很好的例子是 Servlet 的会话对象。当 Servlet 容器在集群节点上运行时，存储在会话对象中的一些对象字段可能会在 HTTP 点击之间神奇地消失。这是因为序列化保存并重新加载会话以在节点之间移动会话。在这种情况下，如果开发人员不知道会话中存储的大型对象的副作用，序列化也可能是一个性能问题。

`volatile`关键字告诉编译器该字段可能被不同的线程使用。当任何代码访问`volatile`字段时，JIT 编译器生成代码，以确保所访问字段的值是最新的。

如果一个字段不是易失性的，编译器生成的代码可能会将该字段的值存储在处理器缓存或注册表中，以便在看到某个后续代码片段很快就需要该值时更快地访问。在`volatile`字段的情况下，无法进行此优化。另外，请注意，将值保存到内存并从中一直加载可能比从注册表或缓存访问值慢 50 倍或更多倍。

# 修饰符

方法、构造器、字段、接口和类可以有访问修饰符。一般规则是，如果没有修饰符，那么方法、构造器等的作用域就是包。同一个包中的任何代码都可以访问它。

当使用`private`修饰符时，范围仅限于所谓的编译单元。这意味着一个文件中的类。一个文件中的内容可以看到并使用任何声明为`private`的内容。这样，内部类和嵌套类就可以访问彼此的`private`变量，这可能不是一种好的编程风格，但 Java 允许这样做。

`private`成员可以从同一顶级类中的代码访问。如果顶级类中有内部类，那么编译器将从这些文件中生成单独的类文件。JVM 不知道什么是内部类。对于 JVM，类只是一个类。`private`成员仍然必须可以从顶级类访问，或者在`private`成员（方法或字段）所在的顶级类中访问。同时，其他类应该不能访问`private`字段。为了解决这种模糊性，Java 生成了所谓的合成代理方法，这些方法从外部可见，因此可以访问。当您想从同一顶级类调用不同内部类中的`private`方法时，编译器会生成一个代理类。这就是 IDE 多次警告`private`方法从性能角度来看可能不是最优方法的原因。

Java11 引入了嵌套的概念，这就改变了。顶级类是一个嵌套宿主，每个类都能分辨出哪些在它们的嵌套中，哪些是它们的嵌套宿主。通过这种方式，JVM 知道是否允许访问`private`成员（读取或写入字段或调用方法）。同时，Java11 不再生成合成代理方法。

`private`的反面是`public`。它将可见性扩展到整个 Java 程序，或者至少在整个模块中（如果项目是 Java 模块）扩展。

中间有一条路：`protected`。具有此修饰符的任何内容都可以在包内访问，也可以在扩展受保护方法、字段等所在的类（无论包是什么）的类中访问。

# 对象初始化器和构造器

当实例化一个对象时，会调用相应的构造器。构造器声明看起来像具有以下偏差的方法构造器没有返回值。这是因为构造器在调用`new`命令操作符时处理未完全就绪的实例，并且不返回任何内容。构造器与类同名，不能相互区分。如果需要多个构造器，则必须重载它们。因此，构造器可以互相调用，就像它们是具有不同参数的方法一样。但是，当一个构造器调用另一个构造器时有一个限制，它必须是构造器中的第一条指令。使用`this()`语法和适当的参数列表（可能为空）从另一个构造器调用构造器。

对象实例的初始化也执行初始化器块。这些块在方法和构造器之外的`{`和`}`字符中包含可执行代码。它们按照在代码中出现的顺序在构造器之前执行，如果它们的声明包含值初始化，则还会初始化字段。

如果在初始化器块前面看到`static`关键字，则该块属于类，并且在加载类时与静态字段初始化器一起执行。

# 编译和运行程序

最后，我们将从命令行编译并执行我们的程序。本章没有什么新内容；我们将仅使用以下两个命令应用本章所学内容：

```java
$ mvn package
```

这将编译程序，将结果打包到 JAR 文件中，最后执行以下命令：

```java
$ java -cp target/SortTutorial-1.0.0-SNAPSHOT.jar packt.java11.example.App
```

这将在命令行上打印以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/d3fff99a-f5dd-415d-bafa-ea71d509071b.png)

# 总结

在本章中，我们开发了一个非常基本的排序算法。它被有意地简化了，以便我们可以重申基本的和最重要的 Java 语言元素、类、包、变量、方法等等。我们还研究了构建工具，因此在接下来的章节中，当项目将包含两个以上的文件时，我们不会空手而归。在接下来的章节中，我们将使用 Maven 和 Gradle。

在下一章中，我们将使排序程序更复杂，实现更高效的算法，并使代码更灵活，使我们有机会学习更高级的 Java 语言特性。