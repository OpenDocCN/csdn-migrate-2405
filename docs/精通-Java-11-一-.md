# 精通 Java 11（一）

> 原文：[Mastering Java 11](https://libgen.rs/book/index.php?md5=550A7DE63D6FA28E9423A226A5BBE759)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 零、前言

Java11 及其新特性增加了语言的丰富性，这是构建健壮软件应用最常用的编程语言之一。Java11 扩展了 Java 平台的功能。本书是您掌握自 Java9 以来对 Java 平台所做更改的一站式指南。

本书概述并解释了 Java11 中引入的新特性及其重要性。我们将为您提供实用的指导，帮助您将新学到的 Java11 知识以及有关 Java 平台未来发展的信息应用到 Java 平台上。这本书的目的是提高您的生产率，使您的应用更快。通过学习 Java 中的最佳实践，您将成为组织中 Java 的准用户。

在本书的结尾，您不仅将学习 Java11 的重要概念，而且还将对使用这种伟大语言编程的重要方面有一个细微的了解

# 这本书是给谁的

本书面向企业开发人员和现有 Java 开发人员。掌握 Java 的基本知识是必要的。

# 这本书的内容

[第一章](01.html)“Java11 场景”探讨了 Java 平台上新实现的基于时间的版本控制系统。我们调查了当前的 Java 环境，特别关注 Java9、10（18.3）和 11（18.9）带来的变化。我们的探索包括对 Java9 的模块化、Javashell、外部进程控制、垃圾收集、JHM 等的概述。对于 Java10，我们将重点介绍关键更改，包括局部变量类型推断、JDK 整合、垃圾收集、应用类数据共享和根证书等。最后，我们将探讨 Java11 中引入的更改，包括动态类文件常量、垃圾收集和 Lambda 的局部变量类型推断。

第 2 章“探索 Java11”，关注 Java 平台中引入的几个内部变化，包括 Java9、10 和 11 的变化。Java9 代表 Java 平台的主要版本；Java10 和 11 是定时版本。总的来说，这些版本包含了大量的内部更改，为 Java 开发人员提供了一系列新的可能性，有些源于开发人员的请求，有些源于 Oracle 的增强

第 3 章“Java11 基础”，介绍了影响变量处理器的 Java 平台变更、导入语句、Project Coin 改进、局部变量类型推断、根证书、动态类文件常量等。这些表示对 Java 语言本身的更改。

第 4 章“使用 Java11 构建模块化应用”，分析了 Jigsaw 项目指定的 Java 模块的结构，深入探讨了 Jigsaw 项目作为 Java 平台的一部分是如何实现的。我们还回顾了 Java 平台与模块化系统相关的关键内部更改。

第 5 章“将应用迁移到 Java11”，探讨如何将现有的应用迁移到当前的 Java 平台。我们将研究手动和半自动迁移过程。本章旨在为您提供一些见解和过程，使您的非模块化 Java 代码能够在当前的 Java 平台上工作。

第 6 章“Java Shell 实验”，介绍了新的命令行，Java 中的**读取求值打印循环**（也称为 **REPL** 工具），以及 **Java Shell**（**JShell**）。我们从介绍该工具、REPL 概念开始，然后进入 JShell 使用的命令和命令行选项。我们采用实践者的方法来回顾 JShell，并包含一些您可以自己尝试的示例。

第 7 章“利用默认的 G1 垃圾收集器”，深入研究了垃圾收集及其在 Java 中的处理方式。我们从垃圾收集的概述开始，然后看看 Java9 之前的领域中的细节。有了这些基本信息，我们就来看看 Java9 平台中具体的垃圾收集更改。最后，我们来看一些即使在 Java11 之后仍然存在的垃圾收集问题。

第 8 章“使用 JMH 的微基准应用”，介绍如何使用 **Java 微基准线束**（**JMH**）编写性能测试，这是一个用于为 **Java 虚拟机**（**JVM**）编写基准测试的 Java 线束库。我们使用 Maven 和 JMH 来帮助说明使用新 Java 平台进行微标记的威力。

第 9 章“利用进程 API”，重点介绍了`Process`类和`java.lang.ProcessHandle`API 的更新。在 Java 的早期版本中，在 Java9 之前，用 Java 管理进程是很困难的。API 不够，有些功能不够，有些任务需要以特定于系统的方式来解决。例如，在 Java8 中，让进程访问自己的**进程标识符**（**PID**）是一项不必要的困难任务。

第 10 章“细粒度栈跟踪”，重点介绍 Java 的`StackWalker`API。API 支持普通程序很少需要的特殊功能。API 在一些非常特殊的情况下非常有用，比如框架提供的功能。因此，如果您想要一种有效的栈遍历方法，使您能够对栈跟踪信息进行可过滤的访问，那么您将喜欢使用`StackWalker`API。该 API 提供对调用栈的快速优化访问，实现对单个帧的延迟访问。

第 11 章“新工具和工具增强”，涵盖了十几种与现代 Java 平台相关的工具和工具增强。这些特色的变化将涵盖广泛的工具和 API 的更新，这些工具和 API 旨在简化 Java 开发，增强创建优化 Java 应用的能力。

第 12 章“并发增强”介绍了 Java 平台的并发增强。我们主要关注的是对反应式编程的支持，这是一种由`Flow`类 API 提供的并发增强。反应式编程最初是在 Java9 中发布的，它仍然是 Java10 和 Java11 的一个重要特性。

第 13 章“安全增强”介绍了最近对 JDK 进行的几个涉及安全性的更改，这些更改的大小并没有反映出它们的重要性。现代 Java 平台的安全性增强为开发人员提供了编写和维护比以前更安全的应用的能力。

第 14 章“命令行标志”，探讨了现代 Java 平台的一些变化，这些变化的共同主题是命令行标志。这些包括以下概念：统一 JVM 日志、编译器控制、诊断命令、堆分析代理、删除 JHAT、命令行标志参数验证、针对旧平台版本的编译，以及实验性的基于 Java 的 JIT 编译器。

第 15 章“Java 平台的附加增强”，重点介绍 Java 平台提供的附加工具的最佳实践。具体来说，本章介绍对 UTF-8、Unicode 支持、Linux/AArch64 端口、多分辨率图像和公共区域设置数据存储库的支持。

第 16 章“未来方向”概述了 Java 平台在 Java11 之外的未来发展。我们看一下 Java19.3 和 19.9 的计划内容，以及将来可能会看到哪些进一步的变化。我们首先简要介绍一下 **JDK 增强程序**（**JEP**）。

第 17 章“对 Java 平台的贡献”，讨论了 Java 社区和开发人员对 Java 平台的贡献方式。具体来说，本章涵盖了以下与 Java 社区相关的主题，如 Java 社区、参与 Java 用户组、Java 社区流程、**Oracle 技术网络**（**OTN**）以及撰写技术文章

# 充分利用这本书

我们鼓励您下载 Java11JDK，以便遵循本书中提供的示例。

# 下载示例代码文件

您可以从您的帐户[下载本书的示例代码文件 www.packt.com](http://www.packt.com)。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，将文件直接通过电子邮件发送给您。

您可以通过以下步骤下载代码文件：

1.  在[登录或注册 www.packt.com](http://www.packt.com)。
2.  选择“支持”选项卡。
3.  点击代码下载和勘误表。
4.  在搜索框中输入图书名称，然后按照屏幕上的说明进行操作。

下载文件后，请确保使用最新版本的解压缩或解压缩文件夹：

*   用于 Windows 的 WinRAR/7-Zip
*   Mac 的 Zipeg/iZip/UnRarX
*   用于 Linux 的 7-Zip/PeaZip

这本书的代码包也托管[在 GitHub 上](https://github.com/PacktPublishing/Mastering-Java-11-Second-Edition)。如果代码有更新，它将在现有 GitHub 存储库中更新。

我们的丰富书籍和视频目录中还有其他代码包，可在[这个页面](https://github.com/PacktPublishing/)上找到。看看他们！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。[您可以在这里下载](https://www.packtpub.com/sites/default/files/downloads/9781789137613_ColorImages.pdf)。

# 使用的约定

这本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。下面是一个示例：“将下载的`WebStorm-10*.dmg`磁盘映像文件作为系统中的另一个磁盘装入。”

代码块设置如下：

```java
try ( Scanner xmlScanner = new Scanner(new File(xmlFile)); {
  while (xmlScanner.hasNext()) {
    // read the xml document and perform needed operations
```

当我们希望提请您注意代码块的特定部分时，相关行或项以粗体显示：

```java
public default void fastWalk() {
    Scanner scanner = new Scanner(System.in);
    System.out.println("Enter desired pacing: ");
```

任何命令行输入或输出的编写方式如下：

```java
$ java --version
```

**粗体**：表示一个新术语、一个重要单词或屏幕上显示的单词。例如，菜单或对话框中的单词会像这样出现在文本中。下面是一个示例：“从管理面板中选择系统信息。”

警告或重要提示如下所示。

提示和窍门是这样出现的。

# 一、Java11 环境

在本章中，我们将探讨新实现的、基于时间的 Java 平台版本控制系统。我们将调查当前的 Java 环境，特别关注 Java9、Java10（18.3）和 Java11（18.9）引入的变化。我们的探索将包括对 Java9 的模块化、Javashell、外部进程控制、垃圾收集、**Java 微基准线束**（**JMH**）等的概述。对于 Java10，我们将重点介绍关键的更改，包括局部变量类型推断、**Java 开发工具包**（**JDK**）整合、垃圾收集、应用**类数据共享**（**CDS**）、根证书等等。最后，我们将探讨 Java11 中引入的更改，包括动态类文件常量、垃圾收集、Lambdas 的局部变量类型推断等等。

本章结束时，我们将学到的内容包括：

*   了解 Java 平台的新版本控制模型
*   了解 Java9 的重要性
*   Java10 引入的变化带来的好处
*   Java11 引入的变化带来的好处

# 技术要求

本章及后续章节主要介绍 Java11，Java 平台的**标准版**（**SE**）可从 [Oracle 官方下载网站](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

一个**集成开发环境**（**IDE**）包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

# 了解 Java 平台的新版本控制模型

Java 的第一个版本在 1996 年作为 Java1 发布。从那时起，出现了几个增量版本，每个版本都遵循一个特性驱动的版本模型。从 Java10 开始，Oracle 实现了一个新的、基于时间的发布模型。在本节中，我们将查看原始模型，以提供一个基础来说明 Java 平台是如何演变的，并查看新版本模型及其原因。

# 特性驱动的发布

在 1996 年 Java1 发布之后，随后的版本的命名为 1.1、1.2、1.3 和 1.4。随着 1.5 的发布，Java 平台被称为 Java5。在 Java6 发布之前，Java5 经常更新，随后是 Java7、Java8 和 Java9

下表提供了 Java9 之前的 Java 发行历史的压缩视图：

| **版本名称** | **版本** | **发布年份** | **代号** |
| --- | --- | --- | --- |
| Java1 | 1 | 1996 | Oak |
| Java1.1 | 1.1 | 1997 | （Abigail, Brutus, Chelsea） |
| Java2 | 1.2 | 1998 | Playground |
| Java3 | 1.3 | 2000 | Kestrel |
| Java4 | 1.4 | 2002 | Merlin |
| Java5 | 1.5 | 2004 | Tiger |
| Java6 | 1.6 | 2006 | Mustang |
| Java7 | 1.7 | 2011 | Dolphin |
| Java8 | 1.8 | 2014 | Spider |
| Java9 | 9 | 2017 | \*不再使用代号 |

Java9 的发布是对 Java 平台和每个版本的编号方式的重大改变。在后 Java9 版本中，Oracle 决定放弃基于特性的模型，转而选择时间发布的模型

# 基于时间的发布

Java9 于 2017 年发布，2018 年计划发布两个版本。这些版本是 Java10 和 Java11。这些后 Java9 版本的版本号遵循`YY.M`格式。因此，随着 Java10 在 2018 年 3 月发布，版本号是 18.3。Java11 于 2018 年 9 月发布，版本号为 18.9。

新的基于时间的发布模型背后的一般前提是，发布的计划是可预测且频繁的。详情如下：

*   **专题发布**：每半年（每年 3 月、9 月）发布一次
*   **更新发布**：每季度发布一次
*   **长期支持发布**：每三年发布一次

从开发人员的角度来看，使用此模型可以获得巨大的收益。开发人员不再需要等待 Java 平台的发布。更重要的是，没有一个版本将代表对 Java9 平台的重大改变。

# 了解 Java9 的重要性

毫无疑问，作为 Jigsaw 项目的一部分开发的 Java 平台的模块化是 Java9 引入 Java 平台的最大变化。最初计划用于 Java8，但推迟了，Jigsaw 项目是 Java9 最终版本推迟的主要原因之一。Jigsaw 还为 Java 平台引入了一些显著的变化，这也是 Java9 被认为是主要版本的原因之一。我们将在后面的章节中详细探讨这些特性。

除了 Jigsaw 相关的 Java 增强建议之外，还有一长串在 Java9 中实现的其他增强。本节将探讨 Java9 中引入的最重要的特性，特别是：

*   拆解整体
*   使用 Java Shell
*   控制外部过程
*   使用 G1 提高性能
*   用 **Java 微基准线束**（**JMH**）测量性能
*   为 HTTP 2.0 做准备
*   包含反应式编程

# 拆解整体

多年来，Java 平台的工具不断发展和增加，使其成为一个巨大的整体。为了使平台更适合于嵌入式和移动设备，有必要发布精简版，如 Java **连接设备配置**（**CDC**）和 Java **微型版**（**ME**）。然而，对于 JDK 所提供的功能有不同需求的现代应用来说，这些方法并没有足够的灵活性。在这方面，对模块化系统的需求是一个至关重要的需求，不仅是为了解决 Java 工具的模块化（总的来说，HotSpot 运行时有 5000 多个 Java 类和 1500 多个 C++ 源文件，其中包含 250000 多行代码），而且还为开发人员提供了一种创建和管理的机制使用与 JDK 中使用的模块系统相同的模块化应用。Java8 提供了一种中间机制，使应用能够只使用整个 JDK 提供的 API 的一个子集，这种机制被命名为**紧凑概要文件**。事实上，紧凑的概要文件还为进一步的工作提供了基础，这些工作是为了打破 JDK 不同组件之间的依赖关系。为了在 Java 中实现模块系统，需要打破依赖关系。

模块系统本身以 Jigsaw 项目的名义开发，在此基础上形成了多个 Java 增强方案和一个目标 **Java 规范请求**（**JSR376**）。对 JDK 代码库进行了完整的重组，同时对 JDK 可分发映像进行了完整的重组。

对于是否应该采用一个现有的成熟的 Java 模块系统（比如 OSGi）作为 JDK 的一部分，而不是提供一个全新的模块系统，社区中存在着相当大的争议。但是，OSGi 以运行时行为为目标，比如模块依赖关系的解析、模块的安装、卸载、启动和停止（在 OSGi 中也称为 bundle）、自定义模块类加载器等等

OSGi 是指 **OSGi 联盟**，正式名称为**开放服务网关倡议**。OSGi 是 Java 平台模块化系统的开放标准。

然而，Jigsaw 项目的目标是编译时模块系统，在该系统中，依赖项的解析在编译应用时发生。此外，作为 JDK 的一部分安装和卸载一个模块，就不需要在编译过程中将它显式地包含为依赖项。此外，通过类加载器的现有层次结构（引导、扩展和系统类加载器）可以加载模块类。

Java 模块系统的其他好处包括增强的安全性和性能。通过将 JDK 和应用模块化为 Jigsaw 模块，开发人员能够在组件及其相应的域之间创建定义良好的边界。这种关注点的分离与平台的安全架构保持一致，并且是更好地利用资源的一个使能器

# 使用 Java Shell

很长一段时间以来，Java 编程语言中一直没有标准的 Shell 来试验新的语言特性或库，或者进行快速原型设计。如果您想这样做，您可以用一个`main()`方法编写一个测试应用，用`javac`编译它，然后运行它。这既可以在命令行中完成，也可以使用 JavaIDE 完成；但是，在这两种情况下，这并不像使用交互式 Shell 那样方便。

在 JDK9 中启动交互式 Shell 非常简单，只需运行以下命令（假设 JDK9 安装的`bin`目录位于当前路径中）：

```java
jshell
```

您可能会发现，在 Java 平台的早期还没有引入交互式 Shell，这有点令人费解，因为许多编程语言（如 Python、Ruby 和其他一些语言）在其最早的版本中已经附带了交互式 Shell。然而，直到 Java9，它才出现在优先特性列表中。javaShell 使用 JShellapi，它提供了启用表达式和代码段的自动补全或求值等功能。第 6 章“Java Shell 实验”，致力于讨论 Java Shell 的细节，让开发者充分利用。

# 控制外部进程

在 JDK9 之前，如果要创建 Java 进程并处理进程输入/输出，必须使用以下方法之一：

*   `Runtime.getRuntime.exec()`方法，它允许我们在单独的操作系统进程中执行命令。使用这种方法需要您获得一个`java.lang.Process`实例，在该实例上提供某些操作，以便管理外部流程。
*   新的`java.lang.ProcessBuilder`类，在与外部进程交互方面有更多的增强。您还需要创建一个`java.lang.Process`实例来表示外部进程。

这两种方法都是不灵活的，也不可移植的，因为外部进程执行的命令集高度依赖于操作系统。为了使特定的进程操作能够跨多个操作系统进行移植，还必须付出额外的努力。第 9 章“利用进程 API”开发了新的流程 API，为开发人员提供了创建和管理外部流程的知识。

# 使用 G1 提高性能

G1 垃圾收集器已经在 JDK7 中引入，现在在 JDK9 中默认启用。它针对具有多个处理核心和大量可用内存的系统。与以前的垃圾收集器相比，G1 有什么好处？它是如何实现这些改进的？是否需要手动调整，在什么情况下？关于 G1 的这些和其他几个问题将在第 7 章“利用默认的 G1 垃圾收集器”中讨论。

# 用 JMH 测量性能

在许多情况下，Java 应用可能会出现性能下降的问题，更严重的是缺乏性能测试，这些测试至少可以提供一组最低限度的性能保证来满足性能要求，而且，某些特性的性能不会随着时间的推移而下降。衡量 Java 应用的性能并非易事，特别是由于存在许多编译器和运行时优化，这些优化可能会影响性能统计。因此，为了提供更准确的性能度量，必须使用额外的度量，例如预热阶段和其他技巧。JMH 是一个框架，它包含了许多技术，以及一个方便的 API，可用于此目的。它不是一个新工具，但是包含在 Java9 的发行版中。如果您还没有将 JMH 添加到工具箱中，请阅读第 8 章、“使用 JMH 的微标记应用”，了解 JMH 在 Java 应用开发中的使用。

# 为 HTTP 2.0 做准备

HTTP2.0 是 HTTP1.1 协议的继承者，这个新版本的协议解决了前一个协议的一些限制和缺点。HTTP 2.0 以多种方式提高性能，并提供诸如在单个 TCP 连接中请求/响应多路复用、在服务器推送中发送响应、流控制和请求优先级等功能。Java 提供了可用于建立不安全 HTTP 1.1 连接的`java.net.HttpURLConnection`工具。然而，API 被认为难以维护，这一问题由于需要支持 HTTP 2.0 而变得更加复杂，因此引入了全新的客户端 API，以便通过 HTTP 2.0 或 Web 套接字协议建立连接。HTTP 2.0 客户端及其提供的功能，将在第 11 章、“新工具和工具增强”中介绍。

# 包含反应式编程

反应式编程是一种用于描述系统中变化传播的特定模式的范例。反应式不是 Java 本身构建的，但是可以使用第三方库（如 RxJava 或 projectreactor（Spring 框架的一部分））来建立反应式数据流。JDK9 还解决了对 API 的需求，该 API 通过为此提供`java.util.concurrent.Flow`类来帮助开发基于反应流思想构建的高响应性应用。`Flow`类以及 JDK9 中引入的其他相关更改将在第 12 章、“并发增强”中介绍。

# 受益于 Java10 带来的变化

Java10 于 2018 年 3 月发布，除了之前介绍的基于时间的版本控制之外，还有以下 11 个特性：

*   局部变量类型推断
*   将 JDK 森林整合到单个存储库中
*   垃圾收集接口
*   G1 的并行完全垃圾收集器
*   应用类数据共享
*   线程本地握手
*   删除本机头生成工具（`javah`）
*   其他 Unicode 语言标记扩展
*   备用内存设备上的堆分配
*   基于 Java 的 JIT 编译器实验
*   根证书

本章将简要概述这些功能，随后的章节将更详细地介绍这些功能。

# 局部变量类型推断

从 Java10 开始，声明局部变量已经简化。开发人员不再需要包含本地变量类型的清单声明。这是使用新的`var`标识符完成的，如本示例所示：

```java
var myList = new ArrayList<String>();
```

使用前面的代码，`ArrayList<String>`是推断出来的，所以我们不再需要使用`ArrayList<String> myList = new ArrayList<String>();`

局部变量类型推断在第 3 章、“Java11 基础”中介绍

# 将 JDK 森林整合到单个存储库中

在 Java10 之前，JDK 有八个存储库（CORBA、HotSpot、JDK、JAXP、JAX-WS、langtools、Nashorn 和 ROOT）。使用 Java10，这些存储库被整合到一个代码库中。值得注意的是，javafx 并不是这次整合的一部分。本课题将在第 2 章、第 11 章中进一步说明。

# 垃圾收集接口

Java10 带来了对垃圾收集过程的增强。新的垃圾收集器接口带来了改进，将在第 7 章“利用默认的 G1 垃圾收集器”中详细介绍。

# G1 的并行完全垃圾收集器

在 Java10 中，G1 完全垃圾收集器是并行的。从 Java9 开始，G1 被设置为默认的垃圾收集器，因此这个更改具有特殊的意义。此更改将在第 7 章“利用默认的 G1 垃圾收集器”中详细说明。

# 应用类数据共享

**类数据共享**（**CDS**）已经扩展，以支持更快的应用启动和更小的占用空间。使用 cd，开发人员可以预先解析特定的类文件并将其存储在可共享的归档文件中。我们将在第 2 章“探索 Java11”中探讨 Java 平台的这种变化。

# 线程本地握手

使用 Java10 及更高版本，可以停止单个线程，而不必执行全局虚拟机安全点。我们将在第 3 章“Java11 基础”中充分探讨这一变化

# 删除本机头生成工具（`javah`）

为了将 Javah 工具从 JDK 中删除，进行了协调一致的工作。由于`javac`中提供的功能，因此此更改是有保证的。我们将在第 11 章、“新工具和工具增强”中详细说明这一变化。

# 附加 Unicode 语言标记扩展

Java 平台从 Java7 开始就支持语言标记。在 Java10 中，对`java.util.Local`和相关 API 进行了更改，以合并额外的 Unicode 语言标记。详见第 2 章、第 11 章。

# 备用内存设备上的堆分配

从 Java10 开始，热点虚拟机支持非 DRAM 内存设备。这将在第 3 章、“Java11 基础”中解释

# 基于 Java 的实验性 JIT 编译器

Java9 向我们介绍了一个基于 Java 的**即时**（**JIT**）编译器。此 JIT 编译器已为 Linux/x64 平台启用。这个实验编译器将在第 14 章、“命令行标志”中进一步探讨。

# 根证书

从 Java10 发布开始，JDK 中就有一组默认的**证书颁发机构**（**CA**）证书。这一变化及其好处将在第 3 章、“Java11 基础”中介绍

# 受益于 Java11 引入的变化

Java11 于 2018 年 9 月发布，具有以下四个特性：

*   动态类文件常量
*   Epsilon 一个任意低开销的垃圾收集器
*   删除 JavaEE 和 CORBA 模块
*   Lambda 参数的局部变量语法

本章将简要概述这些功能，随后的章节将更详细地介绍这些功能。

# 动态类文件常量

在 Java11 中，Java 类文件的文件格式被扩展为支持`CONSTANT_Dynamic`，它将创建委托给自举方法。这一变化将在第 3 章、“Java11 基础”中详细探讨

# Epsilon–一个任意低开销的垃圾收集器

垃圾收集增强似乎是每个 Java 平台版本的一部分。Java11 包括一个不回收内存的被动垃圾收集器。我们将在第 7 章“利用默认的 G1 垃圾收集器”中探讨这一点。

# 删除 JavaEE 和 CORBA 模块

**Java 企业版**（**JavaEE**）和**公共对象请求代理架构**（**CORBA**）模块在 Java9 中被废弃，并从 Java11 开始从 Java 平台中移除。详见第 3 章、“Java11 基础”

# Lambda 参数的局部变量语法

正如本章前面所讨论的，`var`标识符是在 Java10 中引入的。在最新版本 Java11 中，`var`可以用在隐式类型的 Lambda 表达式中。第 3 章“Java11 基础”介绍了`var`标识符的使用

# 总结

在本章中，我们探讨了新实现的、基于时间的 Java 平台版本控制系统。我们还从较高的层次了解了 Java9、10 和 11 中引入的更改（分别称为 9、18.3 和 18.9 版本）。Java9 最重要的变化是基于 Jigsaw 项目的模块化，包括关注 Javashell、控制外部进程、垃圾收集、JHM 等的其他变化。讨论了 Java10 的关键特性，包括局部变量类型推断、JDK 整合、垃圾收集、应用 CD、根证书等等。Java11 中引入的更改包括动态类文件常量、垃圾收集、Lambdas 的局部变量类型推断等等。

在下一章中，我们将研究 Java 平台中引入的几个内部更改，包括来自 Java9、10 和 11 的更改。

# 问题

1.  2019 年第一个 Java 版本会是什么？
2.  新的 Java 基于时间的发布模型的主要优点是什么？ 
3.  JDK9 对 Java 平台最重要的改变是什么？
4.  Java11 删除了什么：CORBA、Lambda 还是 G1？
5.  CD 支持更快的启动还是更高效的垃圾收集？
6.  什么是 Epsilon？
7.  `var`是数据类型、标识符、保留字还是关键字？
8.  哪个 Java 版本向 Java 平台引入了根证书？
9.  哪个版本包括对垃圾收集的增强？
10.  Java 中默认的垃圾收集器是什么？

# 进一步阅读

本调查章节对 Java 平台的最新变化进行了粗略的介绍。如果您不熟悉其中任何一个概念，请考虑使用以下一个或多个资源来复习 Java 知识：

*   [《Java：面向对象编程概念》综合课程](https://www.packtpub.com/application-development/java-object-oriented-programming-concepts-integrated-course)。

*   [《Java9 高性能》](https://www.packtpub.com/application-development/java-9-high-performance)。

# 二、探索 Java11

在上一章中，我们探讨了新实现的 Java 平台基于时间的版本控制系统。我们还从高层次了解了 Java9、10 和 11 中引入的更改，这些更改分别称为 9、18.3 和 18.9 版本。Java9 最重要的变化是引入了基于 Jigsaw 项目的模块化，包括关注 Javashell、控制外部进程、垃圾收集、JHM 等的其他变化。介绍了 Java10 的主要特性，包括局部变量类型推断、JDK 合并、垃圾收集、应用**类数据共享**（**CDS**）、根证书等。Java11 中引入的更改包括动态类文件常量、垃圾收集、Lambda 的局部变量类型推断等等。

在本章中，我们将介绍几个引入 Java 平台的内部更改，包括来自 Java9、10 和 11 的更改。Java9 是 Java 平台的主要版本；Java10 和 11 是定时版本。总的来说，这些版本包含了大量的内部更改，为 Java 开发人员提供了一系列新的可能性，有些源于开发人员的请求，有些源于 Oracle 的增强

在本章中，我们将回顾 29 个最重要的变化。每个变更都与一个 **JDK 增强方案**（**JEP**）相关。JEP 索引并存放在[这个页面](http://openjdk.java.net/jeps/0)。您可以访问此链接以获取有关每个 JEP 的更多信息。

JEP 计划是 Oracle 支持开源、开放创新和开放标准的一部分。虽然可以找到其他开源 Java 项目，但 OpenJDK 是 Oracle 唯一支持的项目。

在本章中，我们将介绍以下内容：

*   改进的争用锁
*   分段代码缓存
*   智能 Java 编译，第二阶段【JEP199】
*   解决 Lint 和 Doclint 警告【JEP212】
*   Javac 的分层属性【JEP215】
*   注解管道 2.0【JEP217】
*   新版本字符串方案
*   自动生成运行时编译器测试【JEP233】
*   测试 Javac【JEP235】生成的类文件属性
*   在 CD 档案中存储内部字符串【JEP250】
*   为模块化准备 JavaFXUI 控件和 CSS API【JEP253】
*   紧凑字符串
*   将选定的 Xerces 2.11.0 更新合并到 JAXP【JEP255】
*   将 JavaFX/Media 更新为 GStreamer 的更新版本【JEP257】
*   HarfBuzz 字体布局引擎
*   Windows 和 Linux 上的 HiDPI 图形【JEP263】
*   Marlin 图形渲染器
*   Unicode 8.0.0[JEP267 和 JEP314]
*   临界段的预留栈区【JEP270】
*   语言定义对象模型的动态链接
*   G1 中大型对象的附加试验【JEP278】
*   改进测试失败的故障排除
*   优化字符串连接
*   Hotspot C++ 单元测试框架【JEP281】
*   在 Linux 上启用 GTK3【JEP283】
*   新 Hotspot 构建系统
*   将 JDF 森林整合到单个存储库中【JEP296】

# 技术要求

本章及后续章节以 Java11 为特色，Java 平台的**标准版**（**SE**）可从 [Oracle 官方下载网站的链接](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

一个**集成开发环境**（**IDE**）包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

本章的源代码可以在 [GitHub 的 URL](https://github.com/PacktPublishing/Mastering-Java-11-Second-Edition)上找到。

# 改进的争用锁

JVM 将堆空间用于类和对象。每当我们创建一个对象时，JVM 就会在堆上分配内存。这有助于促进 Java 的垃圾收集，垃圾收集释放以前用来保存不再有内存引用的对象的内存。Java 栈内存有点不同，通常比堆内存小得多

JVM 在管理由多个线程共享的数据区域方面做得很好。它将监视器与每个对象和类相关联；这些监视器具有在任何时候由单个线程控制的锁。这些由 JVM 控制的锁本质上是给控制线程对象的监视器？当一个线程在一个队列中等待一个当前被锁定的对象时，它就被认为是在争夺这个锁。下图显示了此争用的高级视图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/052c1197-4bb1-4760-ba9a-ad858eec2af6.png)

正如您在前面的图中所看到的，任何正在等待的线程在被释放之前都不能使用锁定的对象。

# 改进目标

JEP143 的总体目标是提高 JVM 如何在锁定的 Java 对象监视器上管理争用的总体性能。对争用锁的改进都是 JVM 内部的，不需要任何开发人员操作就可以从中获益。总体改进目标与更快的操作相关。其中包括：

*   更快的监视器输入
*   更快的监视器退出
*   更快的通知

通知是当对象的锁定状态改变时调用的`notify()`和`notifyAll()`操作。测试这种改进并不是一件容易完成的事情。任何级别的更高的效率都是值得欢迎的，因此这一改进是值得我们感谢的。

# 分段代码缓存

Java 的分段代码缓存升级已经完成，结果是执行速度更快、效率更高。这一变化的核心是将代码缓存分割为三个不同的段：非方法段、概要代码段和非概要代码段。

代码缓存是 JVM 存储生成的本机代码的内存区域。

前面提到的每个代码缓存段都将保存特定类型的编译代码。如下图所示，代码堆区域按编译代码的类型进行分段：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/6488fee8-2fe5-4389-8cb2-513751c09e3d.png)

# 内存分配

包含非方法代码的代码堆用于 JVM 内部代码，由 3MB 固定内存块组成。其余的代码缓存内存平均分配给已分析代码和未分析代码段。您可以通过命令行命令对此进行控制。

以下命令可用于定义非方法编译代码的代码堆大小：

```java
-XX:NonMethodCodeHeapSize
```

以下命令可用于定义已分析编译方法的代码堆大小：

```java
-XX:ProfiledCodeHeapSize
```

以下命令可用于定义非概要编译方法的代码堆大小：

```java
-XX:NonProfiledCodeHeapSize
```

这个特性当然可以提高 Java 应用的效率。它还会影响使用代码缓存的其他进程。

# 智能 Java 编译

所有 Java 开发人员都将熟悉将源代码编译成字节码的工具，JVM 使用它来运行 Java 程序。智能 Java 编译，也称为智能 Javac 和`sjavac`，在`javac`进程周围添加了一个智能包装器。`sjavac`增加的核心改进可能是只重新编译必要的代码。在此上下文中，必要的代码是自上一个编译周期以来更改的代码。

如果开发人员只在小项目上工作，这种增强可能不会让他们感到兴奋。但是，考虑一下，当您不断地为中大型项目重新编译代码时，在效率方面的巨大收益。开发人员节省的时间足以让他们接受 JEP199。

这将如何改变编译代码的方式？它可能不会，至少现在不会，Javac 仍然是默认的编译器。尽管`sjavac`提供了增量构建的效率，但 Oracle 认为它没有足够的稳定性来成为标准编译工作流程的一部分。

# 解决 Lint 和 Doclint 警告

Lint 和 Doclint 是向`javac`报告警告的来源。我们来看看每一个：

*   Lint 分析`javac`的字节码和源代码。Lint 的目标是识别所分析代码中的安全漏洞。Lint 还可以深入了解可伸缩性和线程锁定问题。Lint 还有更多的功能，其总体目的是节省开发人员的时间。

[您可以在这里阅读更多关于 Lint 的信息](http://openjdk.java.net/jeps/212)。

*   Doclint 与 Lint 类似，是针对`javadoc`的。Lint 和 Doclint 都报告编译过程中的错误和警告。这些警告的解决是 JEP212 的重点。使用核心库时，不应出现任何警告。这种思维方式导致了 JEP212，它已经在 Java9 中得到了解决和实现。

Lint 和 Doclint 警告的综合列表可以在 **JDK 错误系统**（**JBS**）中查看，可在[这个页面](https://bugs.openjdk.java.net)中获得。

# Javac 的分层属性

Javac 的类型检查已经简化了，让我们首先回顾一下 Java8 中的类型检查是如何工作的，然后我们将探讨现代 Java 平台中的变化。

在 Java8 中，poly 表达式的类型检查由推测属性工具处理

推测属性是一种类型检查方法，作为`javac`编译过程的一部分。它有很大的处理开销。

使用推测属性方法进行类型检查是准确的，但缺乏效率。这些检查包括参数位置，在递归、多态、嵌套循环和 Lambda 表达式中进行测试时，速度会以指数级的速度减慢。因此，更新的目的是更改类型检查模式以创建更快的结果。结果本身并不是不准确的推测归因，他们只是没有迅速产生。

Java9-11 中提供的新方法使用了分层属性工具。此工具实现了一种分层方法，用于对所有方法调用的参数表达式进行类型检查。还为方法重写设置了权限。为了使此新架构正常工作，将为以下列出的每种类型的方法参数创建新的结构类型：

*   Lambda 表达式
*   多边形表达式
*   常规方法调用
*   方法引用
*   菱形实例创建表达式

对`javac`的修改比本节强调的更为复杂。对开发人员来说，除了效率更高和节省时间之外，没有什么直接的影响。

# 注解管道 2.0

Java 注解是指驻留在 Java 源代码文件中的一种特殊元数据。它们不会被`javac`剥离，因此它们可以在运行时对 JVM 保持可用。

注解看起来类似于 JavaDocs 引用，因为它们以`@`符号开头。注解有三种类型。让我们按如下方式检查每一项：

*   注解的最基本形式是标记注解。这些是独立的注解，唯一的组件是动画的名称。举个例子：

```java
@thisIsAMarkerAnnotation
public double computeSometing(double x, double y) {
     // do something and return a double
}
```

*   第二种类型的注解是包含一个值或一段数据的注解。正如您在下面的代码中所看到的，以`@`符号开头的注解后面是包含数据的圆括号：

```java
@thisIsAMarkerAnnotation (data="compute x and y coordinates")
public double computeSometing(double x, double y) {
     // do something and return a double
}
```

编码单值注解类型的另一种方法是省略`data=`组件，如以下代码所示：

```java
@thisIsAMarkerAnnotation ("compute x and y coordinates")
public double computeSometing(double x, double y) {
     // do something and return a double
}
```

*   第三种类型的注解是当有多个数据组件时。对于这种类型的注解，`data=`组件不能省略。举个例子：

```java
@thisIsAMarkerAnnotation (data="compute x and y coordinates", purpose="determine intersecting point")
public double computeSometing(double x, double y) {
     // do something and return a double
}
```

那么，Java9、10 和 11 中发生了什么变化？要回答这个问题，我们需要回顾一下 Java8 引入的几个影响 Java 注解的更改：

*   Lambda 表达式
*   重复注解
*   Java 类型注解

这些与 Java8 相关的更改影响了 Java 注解，但并没有改变`javac`处理它们的方式。有一些硬编码的解决方案允许`javac`处理新的注解，但它们效率不高。此外，这种类型的编码（硬编码解决方法）很难维护。

因此，JEP217 专注于重构`javac`注解管道。这种重构都是`javac`内部的，所以对开发人员来说应该不明显。

# 新版本字符串方案

在 Java9 之前，版本号没有遵循行业标准的版本控制语义版本控制。例如，最后四个 JDK8 版本如下：

*   Java SE 8 更新 144
*   Java SE 8 更新 151
*   Java SE 8 更新 152
*   Java SE 8 更新 161
*   Java SE 8 更新 162

**语义版本控制**使用主要、次要、补丁（`0.0.0`）模式，如下所示：

*   **主要**等同于不向后兼容的新 API 更改
*   **次要**是添加向后兼容的功能的情况
*   **补丁**是指错误修复或向后兼容的小改动

Oracle 从 Java9 开始就支持语义版本控制。对于 Java，Java 版本号的前三个元素将使用主次安全模式：

*   **主要**：由一组重要的新特性组成的主要版本
*   **次要**：向后兼容的修订和错误修复
*   **安全**：被认为是提高安全性的关键修复

Java9 有三个版本：初始版本和两个更新。下面列出的版本演示了主要的次要安全模式：

*   Java SE 9
*   Java SE 9.0.1
*   Java SE 9.0.4

如第 1 章、“Java11 场景”所述，在 Java9 之后的版本将遵循*的时间发布模式年月日*。使用该模式，Java9 之后的四个版本如下：

*   Java SE 18.3（2018 年 3 月）
*   Java SE 18.9（2018 年 9 月）
*   Java SE 19.3（2019 年 3 月）
*   Java SE 19.9（2019 年 9 月）

# 自动生成运行时编译器测试

Java 可以说是最常用的编程语言，并且驻留在越来越多样化的平台上。这加剧了以有效方式运行目标编译器测试的问题。新的 Java 平台包括一个自动化运行时编译器测试的工具。

这个新工具首先生成一组随机的 Java 源代码和/或字节码。生成的代码将具有三个关键特征：

*   它在语法上是正确的
*   它在语义上是正确的
*   它将使用一个随机种子，允许重用相同的随机生成的代码

随机生成的源代码将保存在以下目录中：

```java
hotspot/test/testlibrary/jit-tester
```

这些测试用例将被存储起来以供以后重用。它们可以从`j-treg`目录或工具的 makefile 运行。重新运行保存的测试的好处之一是测试系统的稳定性。

# 测试 Javac 生成的类文件属性

缺乏或不足以为类文件属性创建测试的能力是确保`javac`完全正确地创建类文件属性的动力。这表明，即使某些属性没有被类文件使用，所有类文件都应该生成一组完整的属性。还需要有一种方法来测试类文件是否根据文件的属性正确创建

在 Java9 之前，没有测试类文件属性的方法。运行类并测试代码以获得预期的或预期的结果是测试`javac`生成的类文件最常用的方法。这种技术无法通过测试来验证文件的属性。

JVM 使用的类文件属性有三类：可选属性和 JVM 不使用的属性。

JVM 使用的属性包括：

*   `BootstrapMethods`
*   `Code`
*   `ConstantValue`
*   `Exceptions`
*   `StackMapTable`

可选属性包括：

*   `Deprecated`
*   `LineNumberTable`
*   `LocalVariableTable`
*   `LocalVariableTypeTable`
*   `SourceDebugExtension`
*   `SourceFile`

JVM 未使用的属性包括：

*   `AnnotationDefault`
*   `EnclosingMethod`
*   ``InnerClasses``
*   `MethodParameters`
*   `RuntimeInvisibleAnnotations`
*   `RuntimeInvisibleParameterAnnotations`
*   `RuntimeInvisibleTypeAnnotations`
*   `RuntimeVisibleAnnotations`
*   `RuntimeVisibleParameterAnnotations`
*   `RuntimeVisibleTypeAnnotations`
*   `Signature`
*   `Synthetic`

# 在类数据共享档案中存储内部字符串

在 Java5 到 Java5 中，存储字符串并从 CDS 存档中访问字符串的方法效率低下，非常耗时，而且浪费了内存。下图说明了 Java 在 Java9 之前将内部字符串存储在 CD 存档中的方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/938faf92-cb4f-4fc8-98d2-265e234673ad.png)

低效率源于存储模式。当 CDS 工具将类转储到共享存档文件中时，这一点尤为明显。包含`CONSTANT_String`项的常量池具有 UTF-8 字符串表示。

UTF-8 是一种 8 位可变长度字符编码标准。

# 问题

在 Java9 之前使用 UTF-8 时，字符串必须转换为字符串对象，即`java.lang.String`类的实例。这种转换是按需进行的，这通常会导致系统速度变慢和不必要的内存使用。处理时间非常短，但内存使用过多。一个内部字符串中的每个字符都需要至少 3 个字节的内存，甚至更多。

一个相关的问题是，并非所有 JVM 进程都可以访问存储的字符串。

# Java9 解决方案

CDS 存档从 Java9 开始，在堆上为字符串分配特定的空间。该过程如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/d47d308f-f085-43e8-831d-b5ca4f955d93.png)

使用共享字符串表、哈希表和重复数据消除映射字符串空间。

**数据去重**是一种数据压缩技术，可消除档案中的重复信息。

# Java10 的改进

Java9 引入了更高效的 cd，Java9 进一步改进了这个特性，特别是支持将应用类添加到共享存档中。JEP310 应用 cd 的目的不是为了使归档文件膨胀、启动时间变慢或消耗超过需要的内存。尽管如此，如果不对 CDS 采取有目的的方法，这些结果是可能的

我们对 CDS 存档使用三个步骤：确定要包含的类、创建存档和使用存档：

1.  类的确定
2.  AppCD 存档创建
3.  使用 AppCD 存档

让我们检查一下每一步的细节。

# 类的确定

使用 cd 的最佳实践是只归档所使用的类。这将有助于防止档案不必要地膨胀。我们可以使用以下命令行和标志来确定加载了哪些类：

```java
java -Xshare:off -XX:+UseAppCDS -XX:DumpLoadedClassList=ch2.lst - cp cp2.jar Chapter2
```

# AppCD 存档创建

一旦我们知道加载了哪些类，我们就可以创建 AppCDS 存档。以下是要使用的命令行和标志选项：

```java
java  -Xshare:dump -XX:+UseApsCDS \
 -XX:SharedClassListFile=ch2.lst \
 -XX:SharedArchiveFile=ch2.jsa -cp ch2.jar
```

# 使用 AppCD 存档

为了使用 AppCDS 存档，我们发出`-Xshare:on`命令行选项，如下所示：

```java
java -Xshare:on -XX:+UseAppCDS -XX:SharedArchiveFile=ch2.jsa -cp ch2.jar Chapter2
```

# 为模块化准备 JavaFXUI 控件和级联样式表 API

JavaFX 是一组允许设计和开发富媒体图形用户界面的包。JavaFX 应用为开发人员提供了一个很好的 API，用于为应用创建一致的接口。**级联样式表**（**CSS**）可用于定制接口。JavaFX 的一个优点是编程和接口设计的任务可以很容易地分开。

# JavaFX 概述

JavaFX 包含一个很棒的可视化脚本工具场景构建器，它允许您使用拖放和属性设置来创建图形用户界面。场景生成器生成 IDE 使用的必要 FXML 文件，例如 NetBeans。

以下是使用场景生成器创建的示例 UI：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/07a369be-63f8-4cd1-a34b-18e1c9e676b2.png)

下面是场景生成器创建的 FXML 文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<?import java.lang.*?>
<?import java.util.*?>
<?import javafx.scene.control.*?>
<?import javafx.scene.layout.*?>
<?import javafx.scene.paint.*?>
<?import javafx.scene.text.*?>

<AnchorPane id="AnchorPane" maxHeight="-Infinity"
  maxWidth="-Infinity" minHeight="-Infinity"
  minWidth="-Infinity" prefHeight="400.0" prefWidth="600.0"
  xmlns:fx="http://javafx.com/fxml/1"
  >
  <children>
    <TitledPane animated="false" collapsible="false"
      layoutX="108.0" layoutY="49.0" text="Sample">
    <content>
      <AnchorPane id="Content" minHeight="0.0" minWidth="0.0"
        prefHeight="180.0" prefWidth="200.0">
      <children>
        <CheckBox layoutX="26.0" layoutY="33.0"
          mnemonicParsing="false" prefWidth="94.0"
          text="CheckBox" />
        <ColorPicker layoutX="26.0" layoutY="65.0" />
        <Hyperlink layoutX="26.0" layoutY="103.0"
          text="Hyperlink" />
        <Label alignment="CENTER" layoutX="14.0" layoutY="5.0"
          prefWidth="172.0" text="This is a Label"
          textAlignment="CENTER">
          <font>
            <Font size="14.0" />
          </font>
        </Label>
        <Button layoutX="81.0" layoutY="146.0"
          mnemonicParsing="false" text="Button" />
      </children>
      </AnchorPane>
    </content>
    </TitledPane>
  </children>
</AnchorPane>
```

# 对 Java9、10 和 11 的影响

在 Java9 之前，JavaFX 控件和 CSS 功能只能通过与内部 API 接口提供给开发人员。Java9 的模块化使得内部 API 无法访问。因此，创建 JEP253 是为了定义公共 API，而不是内部 API

这是一项比看上去更大的任务。以下是作为 JEP 一部分采取的一些行动：

*   将 JavaFX 控件皮肤从内部移动到公共 API（`javafx.scene.skin`）
*   确保 API 一致性
*   产生一个彻底的`javadoc`

以下类已从内部包移到公共`javafx.scene.control.skin`包：

| | | | |
| --- | --- | --- | --- |
| `AccordionSkin` | `ButtonBarSkin` | `ButtonSkin` | `CellSkinBase` |
| `CheckBoxSkin` | `ChoiceBoxSkin` | `ColorPickerSkin` | `ComboBoxBaseSkin` |
| `ComboBoxListViewSkin` | `ComboBoxPopupControl` | `ContextMenuSkin` | `DateCellSkin` |
| `DatePickerSkin` | `HpyerLinkSkin` | `LabelSkin` | `LabeledSkinBase` |
| `ListCellSkin` | `ListViewSkin` | `MenuBarSkin` | `MenuButtonSkin` |
| `MenuButtonSkinBase` | `NestedTableColumnHeader` | `PaginationSkin` | `ProgressBarSkin` |
| `ProgressIndicatorSkin` | `RadioButtonSkin` | `ScrollBarSkin` | `ScrollPanelSkin` |
| `SeparatorSkin` | `SliderSkin` | `SpinnerSkin` | `SplitMenuButtonSkin` |
| `SplitPaneSkin` | `TabPaneSkin` | `TableCellSkin` | `TableCellSkinBase` |
| `TableColumnHeader` | `TableHeaderRow` | `TableHeaderSkin` | `TabelRowSkinBase` |
| `TableViewSkin` | `TableViewSkinBase` | `TextAreaSkin` | `TextFieldSkin` |
| `TextInputControlSkin` | `TitledPaneSkin` | `ToggleButtonSkin` | `ToolBarSkin` |
| `TooltipSkin` | `TreeCellSkin` | `TreeTableCellSkin` | `TreeTableRowSkin` |
| `TreeTableViewSkin` | `TreeViewSkin` | `VirtualContainerBase` | `VirtualFlow` |

公共`javafx.css`包现在有以下附加类：

*   `CascadingStyle.java:public class CascadingStyle implements Comparable<CascadingStyle>`
*   `CompoundSelector.java:final public class CompoundSelector extends Selector`
*   `CssError.java:public class CssError`
*   `Declaration.java:final public class Declaration`
*   `Rule.java:final public class Rule`
*   `Selector.java:abstract public class Selector`
*   `SimpleSelector.java:final public class SimpleSelector extends Selector`
*   `Size.java:final public class Size`
*   `Style.java:final public class Style`
*   `Stylesheet.java:public class Stylesheet`
*   `CssParser.java:final public class CssParser`

# 紧凑字符串

字符串数据类型几乎是每个 Java 应用的重要组成部分，在 Java9 之前，字符串数据存储为一个数组`chars`。这要求每个`char`有 16 位。确定大多数字符串对象只能用 8 位或 1 字节的存储空间来存储。这是因为大多数字符串都由拉丁 1 字符组成。

**拉丁 1 字符**是指国际标准化组织建立的拉丁 1 字符集。字符集由字符编码的单字节集组成。

从 Java9 开始，字符串现在在内部用一个`byte`数组表示，还有一个用于编码引用的标志字段。

# 将选定的 Xerces 2.11.0 更新合并到 JAXP 中

Xerces 是一个用于在 Java 中解析 XML 的库。它在 2010 年末被更新为 2.11.0，JAXP 也被更新为包含 Xerces2.11.0 中的更改。

JAXP 是 Java 用于 XML 处理的 API。

在 Java9 之前，JDK 关于 XML 处理的最新更新是基于 Xerces2.7.1 的，JDK7 在 Xerces2.10.0 的基础上有一些额外的变化。Java 现在对基于 Xerces2.11.0 的 JAXP 进行了进一步的改进。

Xerces 2.11.0 支持以下标准：

*   XML 1.0，第四版
*   XML 1.0 中的名称空间，第二版
*   XML 1.1，第二版
*   XML 1.1 中的名称空间，第二版
*   XML 1.0，第二版
*   **文档对象模型**（**DOM**）：
*   3 级：
    *   核心
    *   加载和保存
*   2 级：
    *   核心
    *   事件

*   遍历和范围
*   元素遍历，第一版
*   XML 2.0.2 的简单 API
*   Java API for XML Processing（JAXP）1.4
*   XML 1.0 流 API
*   XML 模式 1.0
*   XML 模式 1.1
*   XML 模式定义语言

JDK 已更新为包括以下 Xerces 2.11.0 类别：

*   目录分解器
*   数据类型
*   文档对象模型级别 3
*   XML 架构验证
*   XPointer

JAXP 的公共 API 在 Java9、10 或 11 中没有改变。

# 将 JavaFX/Media 更新为 GStreamer 的更新版本

JavaFX 用于创建桌面和 Web 应用。JavaFX 的创建是为了取代 Swing 成为 Java 的标准 GUI 库。`Media`类`javafx.scene.media.Media`用于实例化表示媒体资源的对象。JavaFX/`Media`表示如下类：

```java
public final class Media extends java.lang.Object
```

此类向媒体资源提供引用数据。`javafx.scene.media`包为开发人员提供了将媒体合并到 JavaFX 应用中的能力。JavaFX/`Media`使用 GStreamer 管道。

GStreamer 是一个多媒体处理框架，可用于构建系统，该系统接收多种不同格式的媒体，并在处理后以选定的格式导出它们。

对现代 Java 平台的更新确保了 JavaFX/Media 被更新为包括 GStreamer 的最新版本，以保证稳定性、性能和安全性。

# HarfBuzz 字体布局引擎

在 Java9 之前，布局引擎用于处理字体的复杂性，特别是那些具有超出常用拉丁字体的呈现行为的字体。Java 使用统一客户端接口（也称为 ICU）作为事实上的文本呈现工具。ICU 布局引擎已经贬值，在 Java9 中，已经被 HarfBuzz 字体布局引擎所取代。

HarfBuzz 是一个 OpenType 文本呈现引擎。这种类型的布局引擎的特点是提供脚本感知代码，以帮助确保文本按所需布局。

OpenType 是一个 HTML 格式的字体格式规范。

从 ICU 布局引擎向 HarfBuzz 字体布局引擎转变的动力是 IBM 决定停止支持 ICU 布局引擎。因此，JDK 被更新为包含 HarfBuzz 字体布局引擎。

# Windows 和 Linux 下的 HiDPI 图形

为了确保屏幕组件相对于显示器像素密度的清晰度，我们做出了一致的努力。以下术语与此工作相关，并随附所列描述性信息一起提供：

*   **DPI 感知应用**：一种能够根据显示器的特定像素密度检测和缩放图像的应用。
*   **DPI 非感知应用**：不尝试检测和缩放显示器特定像素密度的图像的应用。
*   **HiDPI 图形**：每英寸高点图形。
*   **视网膜显示器**：这个术语是由苹果公司创建的，指像素密度至少为每英寸 300 像素的显示器。向用户显示图形（包括图像和图形用户界面组件）通常是最重要的性能。以高质量显示此图像可能有些问题。计算机显示器 DPIs 的变化很大。开发显示器有三种基本方法：
*   开发应用时不考虑潜在的不同显示尺寸。换句话说，创建一个 DPI 应用。
*   开发一个支持 DPI 的应用，有选择地使用给定显示的预渲染图像大小。
*   开发一个支持 DPI 的应用，该应用可以根据运行应用的特定显示适当地上下缩放图像。

显然，前两种方法有问题，原因不同。对于第一种方法，不考虑用户体验。当然，如果应用是为一个没有预期像素密度变化的非常特定的显示而开发的，那么这种方法是可行的。

第二种方法需要在设计和开发端进行大量工作，以确保以编程方式创建和实现每个预期显示密度的图像。除了大量的工作之外，应用大小将不必要地增加，并且新的和不同的像素密度将不被考虑。

第三种方法是创建具有 DPI 意识的应用，该应用具有高效和有效的扩展功能。这种方法工作得很好，已经在 Mac 视网膜显示器上得到了验证

在 Java9 之前，MacOSX 已经在 Java 中实现了自动伸缩和调整大小。这个功能是在 Windows 和 Linux 操作系统的 Java9 中添加的。

# Marlin 图形渲染器

在 Java2dAPI 中，双鱼座图形光栅化器已经被 Marlin 图形渲染器所取代。此 API 用于绘制 2D 图形和动画。

我们的目标是用一个光栅化器/渲染器来代替双鱼座，这个光栅化器/渲染器效率更高，而且没有任何质量损失。这个目标是在 Java9 中实现的。一个预期的附带好处是包括一个开发人员可访问的 API。以前，与 AWT 和 Java2d 的接口是内部的。

# Unicode 8.0.0 标准

Unicode 8.0.0 于 2015 年 6 月 17 日发布。Java 的相关 API 已更新为支持 Unicode 8.0.0。

# Unicode 8.0.0 中的新功能

Unicode 8.0.0 增加了近 8000 个字符。以下是此次发布的亮点：

*   泰阿洪语的阿洪语脚本（印度）
*   阿尔维语，泰米尔语（阿拉伯语）
*   切罗基符号
*   中日韩统一象形文字
*   表情符号以及肉色符号修饰符
*   格鲁吉亚拉里货币符号
*   lk 语言（乌干达）
*   库兰戈语（科特迪瓦）

# Java9 中的类更新

为了完全符合新的 Unicode 标准，更新了几个 Java 类。为使 Java9 符合新的 Unicode 标准，更新了以下列出的类：

*   `java.awt.font.NumericShaper`
*   `java.lang.Character`
*   `java.lang.String`
*   `java.text.Bidi`
*   `java.text.BreakIterator`
*   `java.text.Normalizer`

# 临界段的预留栈区

在执行关键部分期间，由栈溢出引起的问题得到了缓解。这种缓解措施的形式是保留额外的线程栈空间。

# Java9 之前的情况

当 JVM 被要求在栈空间不足且没有分配额外空间权限的线程中执行数据计算时，JVM 抛出`StackOverflowError`。这是一个异步异常。JVM 还可以在调用方法时同步抛出`StackOverflowError`异常。

调用方法时，将使用内部进程报告栈溢出。虽然当前模式足以报告错误，但调用应用没有空间轻松地从错误中恢复。这不仅会给开发者和用户带来麻烦。如果`StackOverflowError`是在关键的计算操作期间抛出的，则数据可能已损坏，从而导致其他问题。

虽然不是这些问题的唯一原因，`ReentrantLock`类的锁的有效状态是导致不良结果的常见原因。这个问题在 Java7 中很明显，因为`ConcurrentHashMap`代码实现了`ReentrantLock`类。为 Java8 修改了`ConcurrentHashMap`代码，但是`ReentrantLock`类的任何实现仍然存在问题。类似的问题不仅仅存在于`ReentrantLock`类的使用上。

下图概括介绍了`StackOverflowError`问题：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/590b44f9-3e49-4274-9035-e239bbcad1fd.png)

在下一节中，我们将看看 Java9 是如何解决这个问题的。

# Java9 中的新功能

随着现代 Java 平台的变化，一个关键的部分会自动地被赋予额外的空间，这样它就可以完成它的执行而不受`StackOverflowError`的影响，这是基于额外的空间分配需求很小。对 JVM 进行了必要的更改以允许此功能。

当关键部分正在执行时，JVM 实际上会延迟`StackOverflowError`，或者至少尝试延迟。为了利用这个新模式，必须用以下内容对方法进行注解：

```java
jdk.internal.vm.annotation.ReservedStackAccess
```

当一个方法有这个注解并且存在一个`StackOverflowError`条件时，就授予对保留内存空间的临时访问权。新流程在高抽象层次上呈现如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/6214c971-ddd5-45f8-adb1-61dddd75511f.png)

# 语言定义对象模型的动态链接

Java 互操作性得到了增强。对 JDK 进行了必要的更改，以允许来自多种语言的运行时链接器在单个 JVM 实例中共存。正如您所期望的那样，此更改适用于高级操作。相关高级操作的一个示例是使用诸如访问器和变异器之类的元素读取或写入属性。

高级操作适用于未知类型的对象。它们可以通过`INVOKEDYNAMIC`指令调用。下面是一个在编译时对象类型未知时调用对象属性的示例：

```java
INVOKEDYNAMIC "dyn:getProp:age"
```

# 概念证明

Nashorn 是一个轻量级、高性能的 JavaScript 运行时，它允许在 Java 应用中嵌入 JavaScript。它是为 Java8 创建的，并取代了以前基于 MozillaRhino 的 JavaScript 脚本引擎。Nashorn 已经有了这个功能。它提供对任何未知类型的对象（如`obj.something`）的高级操作之间的链接，其中它产生以下结果：

```java
INVOKEDYNAMIC "dyn.getProp.something"
```

动态链接器启动并在可能的情况下提供适当的实现。

# G1 中大型对象的附加试验

Java 平台长期以来最受欢迎的特性之一是幕后垃圾收集。改进的目标是为庞大的对象创建额外的白盒测试，作为 G1 垃圾收集器的一个特性。

**白盒测试**是用于查询 JVM 内部的 API。 白盒测试 API 是在 Java7 中引入的，并在 Java8 和 Java9 中进行了升级。

G1 垃圾收集器工作得非常好，但仍有提高效率的空间。G1 垃圾收集器的工作方式是首先将堆划分为大小相等的区域，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/a6592a5c-c346-4ed6-83e2-616af8af0856.png)

G1 垃圾收集器的问题是如何处理庞大的对象。

在垃圾收集上下文中，庞大的对象是占用堆上多个区域的任何对象。

庞大对象的问题是，如果它们占用了堆上某个区域的任何部分，那么剩余的空间就无法分配给其他对象。在 Java9 中，白盒 API 扩展了四种新方法：

*   方法，其目的是阻止完全垃圾收集并启动并发标记。
*   可以访问单个 G1 垃圾收集堆区域的方法。对这些区域的访问包括属性读取，例如区域的当前状态。
*   直接访问 G1 垃圾收集内部变量的方法。
*   方法，这些方法可以确定堆上是否存在大量对象，如果存在，则位于哪些区域。

# 改进测试失败的故障排除

Java 中添加了额外的功能来自动收集信息，以支持测试失败和超时的故障排除。在测试期间收集现成的诊断信息，为开发人员和工程师的日志和其他输出提供更高的保真度。

测试中有两种基本类型的信息：

*   环境
*   进程

每种类型的信息将在下一节中描述。

# 环境信息

在运行测试时，测试环境信息对于故障排除工作非常重要。这些信息包括：

*   CPU 负载
*   磁盘空间
*   I/O 负载
*   内存空间
*   打开的文件
*   打开的套接字
*   正在运行的进程
*   系统事件
*   系统消息

# Java 进程信息

在测试过程中也有与 Java 进程直接相关的信息。其中包括：

*   C 堆
*   堆转储
*   小型转储
*   堆统计信息
*   Java 栈

关于这个概念的更多信息，请阅读 JDK 的回归测试工具（`jtreg`）。

# 优化字符串连接

在 Java9 之前，字符串连接由`javac`翻译成`StringBuilder : : append`链。这是一种次优的翻译方法，通常需要预先确定。

增强更改了由`javac`生成的字符串连接字节码序列，因此它使用`INVOKEDYNAMIC`调用。增强的目的是增加优化并支持将来的优化，而不需要重新格式化`javac`的字节码。

有关`INVOKEDYNAMIC`的更多信息，请参见 JEP276。

使用`INVOKEDYAMIC`调用`java.lang.invoke.StringConcatFactory`允许我们使用类似于 Lambda 表达式的方法，而不是使用`StringBuilder`的逐步过程。这样可以更有效地处理字符串连接。

# HotSpot C++ 单元测试框架

HotSpot 是 JVM 的名称。此 Java 增强旨在支持 JVM 的 C++ 单元测试的开发。以下是此增强功能的部分非优先目标列表：

*   命令行测试
*   创建适当的文档
*   调试编译目标
*   框架弹性
*   IDE 支持
*   单个和独立单元测试
*   个性化测试结果
*   与现有基础设施集成
*   内部测试支持
*   正例和负例检测
*   短执行时间测试
*   支持所有 JDK9 构建平台
*   测试编译目标
*   测试排除
*   测试分组
*   需要初始化 JVM 的测试
*   测试与源代码共存
*   平台相关代码的测试
*   编写和执行单元测试（针对类和方法）

这种增强是扩展性不断增强的证据。

# 在 Linux 上启用 GTK3

GTK+，正式称为 GIMP 工具箱，是一种用于创建图形用户界面的跨平台工具。该工具由可通过其 API 访问的小部件组成，Java 的增强功能确保在 Linux 上开发带有图形组件的 Java 应用时支持 GTK2 和 GTK3。该实现支持使用 JavaFX、AWT 和 Swing 的 Java 应用。

我们可以使用 JavaFX、AWT 和 Swing 创建 Java 图形应用。下面的表格总结了这三种方法与 GTK（Java9 之前）的关系：

| **方法** | **备注** |
| --- | --- |
| JavaFX |  使用动态 GTK 函数查找 |
| | 通过 JFXPanel 与 AWT 和 Swing 交互 |
| | 使用 AWT 打印功能 |
| AWT | 使用动态 GTK 函数查找 |
| Swing | 使用动态 GTK 函数查找 |

那么，实现这一增强需要进行哪些更改？对于 JavaFX，更改了三个具体内容：

*   GTK 2 和 GTK 3 都增加了自动测试
*   添加了动态加载 GTK2 的功能
*   为 GTK 3 添加了支持

对于 AWT 和 Swing，实现了以下更改：

*   GTK 2 和 GTK 3 都增加了自动测试
*   `AwtRobot`迁移到 GTK3
*   为 GTK 3 更新了`FileChooserDilaog`
*   添加了动态加载 GTK3 的功能
*   Swing GTK LnF 经过修改以支持 GTK 3

Swing GTK LnF 是 Swing GTK look and feel 的缩写。

# 新 HotSpot 构建系统

在 Java9-11 之前使用的 Java 平台是一个充满重复代码、冗余和其他低效的构建系统。构建系统已经为基于 buildinfra 框架的现代 Java 平台重新设计。在这种情况下，infra 是 infrastructure 的缩写。这个增强的首要目标是将构建系统升级到一个简化的系统。

具体目标包括：

*   利用现有构建系统
*   创建可维护代码
*   最小化重复代码
*   简化
*   支持未来的增强功能

您可以通过[以下链接](http://www.oracle.com/technetwork/oem/frmwrk-infra-496656.html)了解更多关于 Oracle 基础架构框架的信息。

# 将 JDF 森林整合到单个存储库中

Java9 平台由八个不同的存储库组成，如下图所示。在 Java10 中，所有这些存储库都合并到一个存储库中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/7e2e6ff6-78ac-40ca-826e-ca874d7ad31a.png)

存储库整合有助于简化开发。此外，它还增加了维护和更新 Java 平台的容易性。

# 总结

在本章中，我们介绍了 Java9、10 和 11 引入的 Java 平台的一些令人印象深刻的新特性。我们关注于`javac`、JDK 库和各种测试套件。内存管理的改进，包括堆空间效率、内存分配和改进的垃圾收集，代表了一组强大的 Java 平台增强功能。关于提高效率的汇编过程的变化是我们这一章的一部分。我们还介绍了一些重要的改进，如编译过程、类型测试、注解和自动运行时编译器测试。

在下一章中，我们将介绍 Java9、10 和 11 中引入的几个小的语言增强。

# 问题

1.  什么是乐观锁？
2.  什么是代码缓存？
3.  用于定义已分析编译方法的代码堆大小的命令行代码是什么？
4.  警告上下文中的 Lint 和 Doclint 是什么？
5.  自动生成运行时编译器测试时使用的目录是什么？
6.  在确定 CDS 类时，`-Xshare`命令行选项使用了什么标志？
7.  场景生成器生成的文件扩展名是什么？
8.  在 Java9 之前，字符串数据是如何存储的？
9.  从 Java9 开始，字符串数据是如何存储的？
10.  什么是 OpenType？

# 进一步阅读

这里列出的书籍也可以作为电子书提供，它们将帮助您深入了解 Java9 和 JavaFX：

*   [《Java9 高性能》](https://www.packtpub.com/application-development/java-9-high-performance)。
*   [《JavaFX 基础》](https://www.packtpub.com/web-development/javafx-essentials)。

# 三、Java11 基础

在最后一章中，我们介绍了 Java9、10 和 11 引入的 Java 平台的一些令人印象深刻的新特性。我们关注 Javac、JDK 库和各种测试套件。内存管理的改进，包括堆空间效率、内存分配和改进的垃圾收集，代表了一组强大的 Java 平台增强功能。关于提高效率的汇编过程的变化是我们这一章的一部分。我们还介绍了一些重要的改进，例如有关编译过程、类型测试、注解和自动运行时编译器测试的改进。

本章介绍对 Java 平台的一些更改，这些更改会影响变量处理器、导入语句、对 Coin 项目的改进、局部变量类型推断、根证书、动态类文件常量等等。这些表示对 Java 语言本身的更改。

我们将在本章介绍的具体主题如下：

*   变量处理器
*   `import`语句废弃警告
*   Coin 项目
*   `import`语句处理
*   推断局部变量
*   线程本地握手
*   备用内存设备上的堆分配
*   根证书
*   动态类文件常量
*   删除 JavaEE 和 CORBA 模块

# 技术要求

本章及后续章节主要介绍 Java11，Java 平台的**标准版**（**SE**）可从 [Oracle 官方网站](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

IDE 包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

本章的源代码可以在 [GitHub](https://github.com/PacktPublishing/Mastering-Java-11-Second-Edition) 上找到。

# 使用变量处理器

变量处理器是对变量的类型化引用，由`java.lang.invoke.VarHandle`抽象类控制。`VarHandle`方法的签名是多态的。这使得方法签名和返回类型都具有很大的可变性。下面是一个代码示例，演示如何使用`VarHandle`：

```java
. . .
class Example {
  int myInt;
  . . .
}
. . .
class Sample {
  static final VarHandle VH_MYINT;

  static { 
    try {
      VH_MYINT =
        MethodHandles.lookup().in(Example.class)
        .findVarHandle(Example.class, "myInt", int.class);
    }
    catch (Exception e) {
      throw new Error(e);
    }
  }
}
. . .
```

正如您在前面的代码片段中所看到的，`VarHandle.lookup()`执行的操作与由`MethodHandle.lookup()`方法执行的操作相同。

对 Java 平台的这一更改旨在标准化调用以下类的方法的方式：

*   `java.util.concurrent.atomic`
*   `sun.misc.Unsafe`

具体地说，是执行以下操作的方法：

*   访问/修改对象字段
*   数组的已访问/已修改元素

此外，这种变化导致了内存排序和对象可达性的两种栅栏操作。本着尽职尽责的精神，特别注意确保 JVM 的安全。确保这些更改不会导致内存错误非常重要。数据完整性、可用性，当然还有性能是上述尽职调查的关键组成部分，解释如下：

*   **安全**：不能出现损坏的内存状态。
*   **数据完整性**：必须确保对对象字段的访问使用相同的规则：
*   `getfield`字节码
*   `putfield`字节码

*   **可用性**：可用性的基准是`sun.misc.Unsafe`API。目标是使新的 API 比基准更易于使用。
*   **性能**：与`sun.misc.Unsafe`API 相比，性能无下降。目标是超越 API。

在 Java 中，栅栏操作是 Javac 以屏障指令的形式强制内存约束的操作。这些操作发生在屏障指令之前和之后，本质上是将它们封闭起来。

# 使用原子工具包

`java.util.concurrent.atomic`包是 12 个子类的集合，它们支持对线程安全和无锁的单个变量的操作。在此上下文中，线程安全是指访问或修改共享单个变量而不妨碍其他线程同时对该变量执行的代码。这个超类是在 Java7 中引入的。

下面是原子工具箱中 12 个子类的列表。如您所料，类名是自描述性的：

*   `java.util.concurrent.atomic.AtomicBoolean`
*   `java.util.concurrent.atomic.AtomicInteger`
*   `java.util.concurrent.atomic.AtomicIntegerArray`
*   `java.util.concurrent.atomic.AtomicIntegerFieldUpdater<T>`
*   `java.util.concurrent.atomic.AtomicLong`
*   `java.util.concurrent.atomic.AtomicLongArray`
*   `java.util.concurrent.atomic.AtomicLongFieldUpdater<T>`
*   `java.util.concurrent.atomic.AtomicMarkableReference<V>`
*   `java.util.concurrent.atomic.AtomicReference<V>`
*   `java.util.concurrent.atomic.AtomicReferenceArray<E>`
*   `java.util.concurrent.atomic.AtomicReferenceFieldUpdater<T,V>`
*   `java.util.concurrent.atomic.AtomicStampedReference<V>`

使用 AtoMIC 工具箱的关键是理解可变变量。可变变量、字段和数组元素可以由并发线程异步修改。

在 Java 中，`volatile`关键字用于通知 Javac 工具从主存中读取值、字段或数组元素，而不是缓存它们。

下面是一段代码片段，演示了对实例变量使用`volatile`关键字：

```java
public class Sample {
  private static volatile Sample myVolatileVariable; // a volatile   
  //
instance     
  //variable

  // getter method
  public static Sample getVariable() { 
    if (myVolatileVariable != null) {
      return myVolatileVariable;
    }

    // this section executes if myVolatileVariable == null
    synchronized(Sample.class) {
      if (myVolatileVariable == null) {
        myVolatileVariable = new Sample();
      }
    }
    return null;
  }
}
```

# 使用`sun.misc.Unsafe`类

`sun.misc.Unsafe`类和其他`sun`类一样，没有正式的文档记录或支持。它被用来规避 Java 的一些内置内存管理安全特性。虽然这可以看作是我们代码中实现更大控制和灵活性的窗口，但这是一种糟糕的编程实践。

该类只有一个私有构造器，因此无法轻松实例化该类的实例。所以，如果我们尝试用`myUnsafe = new Unsafe()`实例化一个实例，在大多数情况下都会抛出`SecurityException`。这个有些不可访问的类有 100 多个方法，允许对数组、类和对象进行操作。以下是这些方法的简单示例：

| **数组** | **类** | **对象** |
| --- | --- | --- |
| `arrayBaseOffset` | `defineAnonymousClass` | `allocateInstance` |
| `arrayIndexScale` | `defineClass` | `objectFieldOffset` |
|  | `ensureClassInitialized` |  |
|  | `staticFieldOffset` |  |

以下是用于信息、内存和同步的`sun.misc.Unsafe`类方法的第二个分组：

| **信息** | **存储器** | **同步** |
| --- | --- | --- |
| `addressSize` | `allocateMemory` | `compareAndSwapInt` |
| `pageSize` | `copyMemory` | `monitorEnter` |
|  | `freeMemory` | `monitorExit` |
|  | `getAddress` | `putOrderedEdit` |
|  | `getInt` | `tryMonitorEnter` |
|  | `putInt` |  |

在 Java9 中，`sun.misc.Unsafe`类被指定要删除。实际上，编程行业对这一决定有一些反对意见。为了平息他们的担忧，这个阶级已经被贬低了，但不会被完全消除。

# `import`语句废弃警告

通常，当我们编译程序时，会收到许多警告和错误。编译器错误必须被修复，因为它们在本质上是典型的语法错误。另一方面，应该对警告进行审查并适当处理。开发人员忽略了一些警告消息。

Java9 略微减少了我们收到的警告数量。特别是，不再生成由导入报表引起的废弃警告。在 Java9 之前，我们可以使用以下注解抑制不推荐使用的警告消息：

```java
@SupressWarnings
```

现在，如果以下一种或多种情况为真，编译器将抑制废弃警告：

*   如果使用`@Deprecated`注解
*   如果使用`@SuppressWarnings`注解
*   如果警告生成代码和声明在祖先类中使用
*   如果警告生成代码在`import`语句中使用

# Coin 项目

Coin 项目是 Java7 中引入的一组小改动的特性集。这些变化如下：

*   `switch`语句中的字符串
*   二进制整数字面值
*   在数字文本中使用下划线
*   实现多重捕获
*   允许更精确地重新触发异常
*   泛型实例创建的改进
*   带资源的`try`语句的添加
*   调用`varargs`方法的改进

[详细信息见以下 Oracle 演示](http://www.oracle.com/us/technologies/java/project-coin-428201.pdf)。

对于 Java9 版本，Coin 项目有五个改进。这些增强功能将在下面的部分中详细介绍。

# 使用`@SafeVarargs`注解

从 Java9 开始，我们可以将`@SafeVarargs`注解与私有实例方法结合使用。当我们使用这个注解时，我们断言这个方法不包含对作为参数传递给这个方法的`varargs`的任何有害操作。

使用的语法如下：

```java
@SafeVarargs // this is the annotation
static void methodName(...) {

/*
  The contents of the method or constructor must not
  perform any unsafe or potentially unsafe operations
  on the varargs parameter or parameters.
*/
}
```

`@SafeVarargs`注解的使用仅限于以下内容：

*   静态方法
*   最终方法
*   私有实例方法

# 带资源的`try`语句

带资源的`try`语句以前要求在使用`final`变量时为语句中的每个资源声明一个新变量。以下是 Java9 之前的带资源的`try`语句的语法（在 Java7 或 Java8 中）：

```java
try ( // open resources ) {
  // use resources
} catch (// error) { 
  // handle exceptions
}
// automatically close resources
```

以下是使用上述语法的代码段：

```java
try ( Scanner xmlScanner = new Scanner(new File(xmlFile)); {
  while (xmlScanner.hasNext()) {
    // read the xml document and perform needed operations
    }
  xmlScanner.close();
  } catch (FileNotFoundException fnfe) {
  System.out.println("Your XML file was not found.");
}
```

自 Java9 以来，带资源的`try`语句可以管理`final`变量，而不需要新的变量声明。因此，我们现在可以重写 Java9、10 或 11 中的早期代码，如图所示：

```java
Scanner xmlScanner = new Scanner(newFile(xmlFile));
try ( while (xmlScanner.hasNext()) {
  {
    // read the xml document and perform needed operations
  }
  xmlScanner.close();
} catch (FileNotFoundException fnfe) {
    System.out.println("Your XML file was not found.");
  }
```

如您所见，`xmlScanner`对象引用包含在带资源的`try`语句块中，它提供了自动资源管理。一旦退出带资源的`try`语句块，资源将自动关闭。

您也可以使用`finally`块作为带资源的`try`语句的一部分。

# 使用菱形运算符

Java9 中引入了菱形操作符，如果推断的数据类型是可表示的，那么菱形操作符可以用于匿名类。当推断出数据类型时，它表明 Java 编译器可以确定方法调用中的数据类型。这包括声明和其中包含的任何参数。

菱形运算符是小于和大于符号对（`<>`），它对 Java9 并不陌生，相反，匿名类的具体用法是。

菱形操作符是在 Java7 中引入的，它简化了泛型类的实例化。以下是 Java7 之前的一个示例：

```java
ArrayList<Student> roster = new ArrayList<Student>();
```

然后，在 Java7 中，我们可以重写它：

```java
ArrayList<Student> roster = new ArrayList<>();
```

问题是这个方法不能用于匿名类。下面是 Java8 中一个运行良好的示例：

```java
public interface Example<T> {
  void aMethod() {
    // interface code goes here
  }
}

Example example = new Example<Integer>()
{
```

```java
  @Override
  public void aMethod() {
    // code
  }
};
```

虽然前面的代码可以正常工作，但当我们将其更改为使用菱形运算符时（如图所示），将出现编译器错误：

```java
public interface Example<T> {
  void aMethod() {
    // interface code goes here
  }
}

Example example = new Example<>() 
{
  @Override
  public void aMethod() { 
    // code
  }
};
```

该错误是由于对匿名内部类使用菱形运算符而导致的。Java9 救命！虽然前面的代码在 Java8 中会导致编译时错误，但在 Java9、10 和 11 中工作正常。

# 停止使用下划线

下划线字符（`_`）不能再用作合法的标识符名称。先前删除标识符名称中下划线的尝试是不完整的。使用下划线将产生错误和警告的组合。自 Java9 以来，警告现在是错误。考虑以下示例代码：

```java
public class UnderscoreTest {
  public static void main(String[] args) {
    int _ = 319;
    if ( _ > 300 ) {
      System.out.println("Your value us greater than 300.");
    }
    else {
      System.out.println("Your value is not greater than 300.");
    }
  }
}
```

在 Java8 中，前面的代码将导致针对`int _ = 319;`和`if ( _ > 300`语句的编译器警告。警告是：`As of Java9, '_' is a keyword, and may not be used as an identifier`。因此，在 Java9、10 或 11 中，不能单独使用下划线作为合法标识符。

使用非自描述性的标识符名称被认为是不好的编程实践。因此，将下划线字符本身用作标识符名称不应该是一个有问题的更改。

# 使用私有接口方法

Lambda 表达式是 Java8 版本的重要组成部分。作为这一改进的后续，接口中的私有方法现在是可行的。以前，我们不能在接口的非抽象方法之间共享数据。使用 Java9、10 和 11，这种数据共享是可能的。接口方法现在可以是私有的。让我们看一些示例代码

第一个代码片段是如何在 Java8 中编写接口的：

```java
. . . 
public interface characterTravel { 
  public default void walk() { 
    Scanner scanner = new Scanner(System.in);
    System.out.println("Enter desired pacing: ");
    int p = scanner.nextInt();
    p = p +1;
  }
  public default void run() {
    Scanner scanner = new Scanner(System.in);
    System.out.println("Enter desired pacing: ");
    int p = scanner.nextInt();
    p = p +4;
  }
  public default void fastWalk() {
    Scanner scanner = new Scanner(System.in);
    System.out.println("Enter desired pacing: ");
    int p = scanner.nextInt();
    p = p +2;
  }
  public default void retreat() {
    Scanner scanner = new Scanner(System.in);
    System.out.println("Enter desired pacing: ");
    int p = scanner.nextInt();
    p = p - 1;
  }
  public default void fastRetreat() {
    Scanner scanner = new Scanner(System.in);
    System.out.println("Enter desired pacing: ");
    int p = scanner.nextInt();
    p = p - 4;
  }
}
```

从 Java9 开始，我们可以重写这段代码。正如您在下面的代码片段中所看到的，冗余代码已经被移动到一个名为`characterTravel`的私有方法中：

```java
. . .
public interface characterTravel {
  public default void walk() {
    characterTravel("walk");
  }
  public default void run() {
    characterTravel("run");
  }
  public default void fastWalk() {
    characterTravel("fastWalk");
  }
  public default void retreat() {
    characterTravel("retreat");
  }
  public default void fastRetreat() {
    characterTravel("fastRetreat");
  }
  private default void characterTravel(String pace) {
    Scanner scanner = new Scanner(System.in);
    System.out.println("Enter desired pacing: ");
    int p = scanner.nextInt();
    if (pace.equals("walk")) {
      p = p +1;
    }
    else if (pace.equals("run")) {
      p = p + 4;
    }
    else if (pace.equals("fastWalk")) {
      p = p + 2;
    }
    else if (pace.equals("retreat")) {
      p = p - 1;
    }
    else if (pace.equals("fastRetreat"))
    {
      p = p - 4;
    }
    else
    {
      //
    }
  }
}
```

# `import`语句处理

**JDK 增强建议**（**JEP**）216 是针对 Javac 如何处理导入语句而发布的。在 Java9 之前，如果源代码是否被接受，导入语句的顺序会产生影响

当我们用 Java 开发应用时，我们通常会根据需要添加`import`语句，从而导致`import`语句的无序列表。IDE 在对未使用的导入语句进行颜色编码方面做得很好，还可以通知我们需要的导入语句，但这还没有包括在内。导入语句的顺序应该无关紧要；没有适用的层次结构

`javac`编译类有两个主要步骤。具体到导入语句的处理，步骤如下：

*   **类型解析**：类型解析包括对抽象语法树的检查，以识别类和接口的声明
*   **成员解析**：成员解析包括确定类的层次结构、单个类变量和成员

从 Java9 开始，我们在类和文件中列出`import`语句的顺序将不再影响编译过程。让我们看一个例子：

```java
package samplePackage;

import static SamplePackage.OuterPackage.Nested.*;
import SamplePackage.Thing.*;

public class OuterPackage {
  public static class Nested implements Inner {
    // code
  }
}

package SamplePackage.Thing;

public interface Inner {
  // code
}
```

在前面的示例中，发生类型解析并导致以下实现：

*   `SamplePackage.OuterPackage`存在
*   `SamplePackage.OuterPackage.Nested`存在
*   `SamplePackage.Thing.Innner`存在

下一步是成员解析，这就是 Java9 之前存在的问题所在。下面是 Javac 将用于为我们的示例代码执行成员解析的连续步骤的概述：

1.  `SamplePackage.OuterPackage`的解析开始。
2.  处理`SamplePackage.OuterPackage.Nested`导入。
3.  `SamplePackage.Outer.Nested`类的决议开始。
4.  内部接口是经过类型检查的，但由于此时它不在范围内，因此无法解析内部接口。
5.  `SamplePackage.Thing`的解析开始。此步骤包括将`SamplePackage.Thing`的所有成员类型导入范围。

因此，在我们的示例中，出现错误是因为在尝试解析时，`Inner`超出了范围。如果把第 4 步和第 5 步互换，就不会有问题了。

这个问题的解决方案是在 Java9 中实现的，它将成员解析步骤分解为额外的子步骤。以下是这些步骤：

1.  分析导入语句
2.  创建层次结构（类和接口）
3.  分析类头部和类型参数

# 推断局部变量

从 Java10 开始，局部变量的声明已经简化。开发人员不再需要包含局部变量类型的清单声明；相反，可以通过使用新的`var`标识符来推断声明

# 使用`var`标识符推断声明

我们可以使用新的`var`标识符来推断数据类型，如下例所示。因此，我们不必显式声明数据类型，而是可以推断它们：

```java
var myList = new ArrayList<String>();
```

前面的代码推断出了`ArrayList<String>`，因此我们不再需要使用详细的`ArrayList<String> myList = new ArrayList<String>();`语法。

引入`var`标识符不应被解释为向 Java 语言中添加`new`关键字。`var`标识符在技术上是一个保留的类型名

使用`new`标识符有一些限制。例如，当存在以下任何一种情况时，不能使用它们：

*   未使用初始化器
*   声明多个变量
*   使用数组维度括号
*   使用对初始化变量的引用

如预期的那样，如果`var`使用不正确，`javac`将发出特定的错误消息。

# Lambda 参数的局部变量语法

正如本章前面所讨论的，`var`标识符是在 Java10 中引入的。在最新版本 Java11 中，`var`可以用在隐式类型的 Lambda 表达式中。以下是两个等效 Java 语句的示例：

*   `(object1, object2) -> object1.myMyethod(object2)`
*   `(var object1, var object2) -> object1.myMethod(object2)`

在第一个语句中，不使用`var`标识符。在第二个语句中，使用了`var`。需要注意的是，如果在隐式类型的 Lambda 表达式中使用了`var`，则必须将其用于所有形式参数。

# 线程本地握手

版本 10 中添加到 Java 平台的一个特性是能够单独停止线程，而不必执行全局虚拟机安全点。拥有此功能的好处包括有偏差的锁撤销改进、虚拟机延迟减少、更安全的栈跟踪以及省略内存障碍。

这种变化在 x64 和 SPARC 系统中非常明显。如果我们想选择正常的安全点，我们将使用以下选项：

```java
XX: ThreadLocalHandshakes
```

# 备用内存设备上的堆分配

从 Java10 开始，热点虚拟机支持非 DRAM 内存设备。我们可以使用以下选项在备用内存设备中分配 Java 对象堆：

```java
XX:AllocateHeapAt=<file system path>
```

在使用备用设备文件系统分配内存时，解决位置冲突和安全问题非常重要。具体来说，请确保使用了正确的权限，并且在应用终止时清除堆。

# 根证书

从 Java10 的发布开始，JDK 中有一组默认的**证书颁发机构**（**CA**）证书。Java10 之前的 JDK 的`cacerts`和`keystore`不包含一组证书。在此 Java 版本之前，开发人员需要为`cacerts`和`keystore`创建和配置一组根证书

现在，Java 平台在`cacerts`和`keystore`中包含了一组由 Oracle 颁发的根证书。特定 CA 是 JavaSE 根 CA 程序的一部分。

从 Java10 开始，根证书中包括以下经 Oracle 验证的 CA：

*   Actalis S.p.A.
*   Buypass AS
*   Camerfirma
*   Certum
*   Chunghwa Telecom Co., Ltd.
*   Comodo CA Ltd.
*   Digicert Inc
*   DocuSign
*   D-TRUST GmbH
*   IdenTrust
*   Let's Encrypt
*   LuxTrust
*   QuoVadis Ltd
*   Secom Trust Systems
*   SwissSign AG
*   Tella
*   Trustwave

很可能在 Java 平台的每个后续版本中都会添加额外的 ca

# 动态类文件常量

在 Java11 中，Java 类文件的文件格式被扩展为支持`CONSTANT_Dynamic`，它将创建委托给自举方法。Java 平台中增加了一个新的常量形式`CONSTANT_Dynamic`，它包含两个组件：

*   `CONSTANT_InvokeDynamic`
*   `CONSTANT_NameAndType`

有关此功能增强的更多细节，请按照本章“进一步阅读”部分的链接找到。

# 删除 JavaEE 和 CORBA 模块

**Java 企业版**（**JavaEE**）和**公共对象请求代理架构**（**CORBA**）模块在 Java9 中被废弃，并从 Java11 开始从 Java 平台中移除。

以下 Java SE 模块包含 Java EE 和 CORBA 模块，已被删除：

*   聚合器模块（`java.se.ee`）
*   常用注解（`java.xml.ws.annotation`
*   CORBA（`java.corba`）
*   JAF（`java.activation`）
*   JAX-WS（`java.xml.ws`）
*   JAX-WS 工具（`jdk.xml.ws`）
*   JAXB（`java.xml.bind`）
*   JAXB 工具（`jdk.xml.bind)`
*   JTA（`java.transaction`）

# 总结

在本章中，我们介绍了 Java 平台的一些变化，这些变化会影响变量处理器、导入语句、对 Coin 项目的改进、局部变量类型推断、根证书、动态类文件常量等等。我们还介绍了废弃警告，以及在特定情况下为什么现在禁止这些警告。最后，我们探讨了导入语句处理的改进。

在下一章中，我们将研究 Jigsaw 项目指定的 Java 模块的结构。我们将深入探讨 Jigsaw 项目是如何作为 Java 平台的一部分实现的。本章使用代码片段演示 Java 的模块化系统，还将讨论 Java 平台在模块化系统方面的内部变化。

# 问题

1.  什么是栅栏操作？
2.  什么是 Coin 计划？
3.  `@SafeVarargs`可以与什么类型的方法一起使用？
4.  `import`语句处理的变化有什么意义？
5.  Java 在哪里存储根证书？
6.  `var`不是关键字。这是怎么一回事？
7.  `var`是用来做什么的？
8.  Java 平台的下划线字符（`_`有什么变化？
9.  原子包中有多少子类？
10.  哪个类管理变量处理器？

# 进一步阅读

下面列出的链接将帮助您深入了解本章介绍的概念：

*   [《学习 Java Lambdas》](https://www.packtpub.com/application-development/learning-java-lambdas)

# 四、用 Java11 构建模块化应用

在最后一章中，我们讨论了 Java 平台在变量处理器方面的最新变化，以及它们与原子工具包的关系。我们还讨论了贬值警告，以及在特定情况下抑制贬值警告的原因。研究了与项目 Coin 相关的变化，以及导入语句处理、推断局部变量和线程局部握手。我们通过查看堆分配、根证书、动态类文件常量以及 JavaEE 和 CORBA 模块的删除，进一步探讨了 Java 语言的变化。

在本章中，我们将研究由 projectjigsaw 指定的 Java 模块的结构，深入探讨如何将 Jigsaw 项目作为 Java 平台的一部分来实现。我们还将回顾 Java 平台与模块化系统相关的关键内部更改。

我们将研究以下主题：

*   模块化入门
*   模块化 JDK
*   模块化运行时映像
*   模块系统
*   模块化 Java 应用打包
*   Java 链接器
*   封装大多数内部 API

# 技术要求

本章及后续章节主要介绍 Java11，Java 平台的**标准版**（**SE**）可从 [Oracle 官方下载网站](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

IDE 包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

# 模块化入门

我们可以将术语**模块化**定义为计算机软件的一种设计或构造。这种类型的软件设计涉及一组模块，这些模块共同构成了整个系统。例如，房子可以作为一个单一的结构或以模块化的方式建造，其中每个房间都是独立建造的，并连接起来形成一个家。通过这个类比，您可以有选择地添加模块或不添加模块来创建您的家庭。

模块的集合，在我们的类比中，成为你家的设计。您的设计不需要使用每个模块，只需要使用您想要的模块。因此，例如，如果有地下室和奖励房间模块，而您的设计不包括这些模块化房间，则这些模块不用于构建您的家。另一种选择是，每个家庭都包括每个房间，而不仅仅是使用的房间。这当然是浪费。让我们看看这和软件有什么关系。

这个概念可以应用于计算机架构和软件系统。我们的系统可以由几个组件组成，而不是一个庞然大物系统。正如您可能想象的那样，这为我们提供了一些特定的好处：

*   我们应该能够扩展 Java 应用以在小型设备上运行
*   我们的 Java 应用将更小
*   我们的模块化代码可以更有针对性
*   更多地使用面向对象编程模型
*   还有其他封装的机会
*   我们的代码将更高效
*   Java 应用将提高性能
*   降低了整个系统的复杂性
*   测试和调试更容易
*   代码维护更容易

Java 向模块化系统的转变是必要的，原因有几个。以下是 Java9 之前的 Java 平台导致在当前 Java 平台中创建模块化系统的主要条件：

*   **Java 开发工具包**（**JDK**）实在太大了。这使得很难支持小型设备。即使在下一节讨论的紧凑配置文件中，支持一些小型设备充其量也是困难的，在某些情况下是不可能的
*   由于 JDK 过大，我们的 Java 应用很难支持真正优化的性能。在这种情况下，越小越好
*   **Java 运行时环境**（**JRE**）太大，无法有效地测试和维护我们的 Java 应用。这将导致耗时、低效的测试和维护操作
*   **Java 存档**（**JAR**）文件也太大。这使得支持小型设备成了问题
*   由于 JDK 和 JRE 都是包罗万象的，所以安全性非常令人担忧，例如，Java 应用未使用的内部 API，由于公共访问修饰符的性质，仍然可用
*   最后，我们的 Java 应用太大了。

模块化系统具有以下要求：

*   必须有一个公共接口，以允许所有连接模块之间的互操作性
*   必须支持隔离和连接测试
*   编译时操作必须能够识别正在使用的模块
*   必须有对模块的运行时支持

模块概念最初是在 Java9 中引入的；它是一个命名的数据和代码集合。具体而言，Java 模块是以下内容的集合：

*   包
*   类
*   接口
*   代码
*   数据
*   资源

成功实现的关键在于，模块在其模块化声明中是自我描述的。模块名必须是唯一的，并且通常使用反向域名架构。下面是一个示例声明：

```java
module com.three19.irisScan { }
```

模块声明包含在`module-info.java`文件中，该文件应位于模块的`root`文件夹中。正如人们所料，这个文件被编译成一个`module-info.class`文件，并将被放在适当的输出目录中。这些输出目录是在模块源代码中建立的

在下一节中，我们将研究 Java 平台在模块化方面的具体变化。

# 模块化 JDK

JEP-200 的核心目标是使用 **Java 平台模块系统**（**JPMS**）对 JDK 进行模块化。在 Java9 之前，我们对 JDK 的熟悉包括对其主要组件的了解：

*   JRE
*   解释器（Java）
*   编译器（Javac）
*   归档器（Jar）
*   文档生成器（Javadoc）

模块化 JDK 的任务是将其分解为可在编译时或运行时组合的组件。模块化结构基于以下在 Java8 中作为紧凑概要文件建立的模块概要文件。下表详细介绍了这三种配置文件：

**紧凑配置文件 1**：

| | | |
| --- | --- | --- |
| `java.io` | `java.lang.annotation` | `java.lang.invoke` |
| `java.lang.ref` | `java.lang.reflect` | `java.math` |
| `java.net` | `java.nio` | `java.nio.channels` |
| `java.nio.channels.spi` | `java.nio.charset` | `java.nio.charset.spi` |
| `java.nio.file` | `java.nio.file.attribute` | `java.nio.file.spi` |
| `java.security` | `java.security.cert` | `java.security.interfaces` |
| `java.security.spec` | `java.text` | `java.text.spi` |
| `java.time` | `java.time.chrono` | `java.time.format` |
| `java.time.temporal` | `java.time.zone` | `java.util` |
| `java.util.concurrent` | `java.util.concurrent.atomic` | `java.util.concurrent.locks` |
| `java.util.function` | `java.util.jar` | `java.util.logging` |
| `java.util.regex` | `java.tuil.spi` | `java.util.stream` |
| `java.util.zip` | `javax.crypto` | `javax.crypto.interfaces` |
| `javax.crypto.spec` | `javax.net` | `javax.net.ssl` |
| `javax.script` | `javax.security.auth` | `javax.security.auth.callback` |
| `javax.security.auth.login` | `javax.security.auth.spi` | `javax.security.auth.spi` |
| `javax.security.auth.x500` | `javax.security.cert` |  |

**紧凑配置文件 2**：

| | | |
| --- | --- | --- |
| `java.rmi` | `java.rmi.activation` | `java.rmi.drc` |
| `java.rmi.registry` | `java.rmi.server` | `java.sql` |
| `javax.rmi.ssl` | `javax.sql` | `javax.transaction` |
| `javax.transaction.xa` | `javax.xml` | `javax.xml.database` |
| `javax.xml.namespace` | `javax.xml.parsers` | `javax.xml.stream` |
| `javax.xml.stream.events` | `javax.xml.stream.util` | `javax.xml.transform` |
| `javax.xml.transform.dom` | `javax.xml.transform.sax` | `javax.xml.transform.stax` |
| `java.xml.transform.stream` | `javax.xml.validation` | `javax.xml.xpath` |
| `org.w3c.dom` | `org.w3c.dom.bootstrap` | `org.w3c.dom.events` |
| `org.w3c.dom.ls` | `org.xml.sax` | `org.xml.sax.ext` |
| `org.xml.sax.helpers` |  |  |

**紧凑配置文件 3**：

| | | |
| --- | --- | --- |
| `java.lang.instrument` | `java.lang.management` | `java.security.acl` |
| `java.util.prefs` | `javax.annotation.processing` | `javax.lang.model` |
| `javax.lang.model.element` | `javax.lang.model.type` | `javax.lang.model.util` |
| `javax.management` | `javax.management.loading` | `javax.management.modelmbean` |
| `javax.management.monitor` | `javax.management.openmbean` | `javax.management.relation` |
| `javax.management.remote` | `javax.management.remote.rmi` | `javax.management.timer` |
| `javax.naming` | `javax.naming.directory` | `javax.naming.event` |
| `javax.naing.ldap` | `javax.naming.spi` | `javax.security.auth.kerberos` |
| `javax.security.sasl` | `javax.sql.rowset` | `javax.sql.rowset.serial` |
| `javax.sql.rowset.spi` | `javax.tools` | `javax.xml.crypto` |
| `javax.xml.crypto.dom` | `javax.xml.crypto.dsig` | `javax.xml.crypto.dsig.dom` |
| `javax.xml.crypto.dsig.keyinfo` | `javax.xml.crypto.dsig.spec` | `org.ieft.jgss` |

这三个紧凑的模块概要文件代表了当前 Java 平台中标准化模块化系统的基础。标准化的有效性取决于以下六个原则：

*   所有 JCP 管理的模块都必须以字符串`java`开头。因此，如果正在开发一个关于空间工具的模块，它的名称应该是`java.spatial.util`。

**JCP** 是指 **Java 社区流程**。 JCP 允许开发人员为 Java 创建技术规范。 您可以在 [JCP 官方网站](https://www.jcp.org/en/home/index)上了解有关 JCP 的更多信息并成为会员 

*   非 JCP 模块被认为是 JDK 的一部分，它们的名称必须以字符串`jdk`开头。
*   确保方法调用链接正常工作。下面的流程图最好地说明了这一点：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/763a18bd-417d-4aca-bb5f-9a0e07479187.png)

正如您在前面的流程图中所看到的，它只适用于导出包的模块。

*   第四个原则处理标准模块中使用的标准和非标准 API 包。以下流程图说明了本原则契约的实现情况：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/9921bd3b-db59-488a-b6df-329c42c9f544.jpg)

*   第五个设计原则是标准模块可以依赖于多个非标准模块。虽然允许这种依赖关系，但不允许对非标准模块进行隐含的可读性访问
*   最终的设计原则确保非标准模块不会导出标准 API 包。

# 模块化源代码

如前所述，Jigsaw 项目的目标是模块化。设想的标准模块化系统将应用于 JavaSE 平台和 JDK。除了提高效率外，模块化转换还将带来更好的安全性和易维护性。JEP-201 中详细介绍的增强集中在 JDK 源代码重组上。让我们仔细看看。

重新组织 JDK 的源代码是一项重要的任务，并通过以下目标子集完成：

*   向 JDK 开发人员提供洞察和熟悉新的 Java9 模块化系统的信息。所以，这个目标是针对 JDK 的开发人员，而不是主流开发人员
*   确保在整个 JDK 构建过程中建立和维护模块化边界
*   第三个目标是确保未来的增强，特别是 Jigsaw 项目，能够轻松地集成到新的模块化系统中。

这种源代码重组的重要性怎么强调都不为过。Java9 之前的源代码组织已经有 20 年的历史了。这种过期的 JDK 源代码重组将使代码更易于维护。让我们看一下 JDK 源代码之前的组织结构，然后检查更改。

# 模块化前的 JDK 源代码组织

JDK 是代码文件、工具、库等的汇编。下图概述了 JDK 组件：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/df7ae80d-09d4-43c8-a863-bf895df69e2f.jpg)

前面的图中 JDK 组件的预模块化组织将在下面的七个小节中详细介绍。

# 开发工具

开发工具位于`\bin`目录中。这些工具包括七个大的分类，每一个都将在后面的章节中详细介绍。

# 部署

这是一组用于帮助部署 Java 应用的工具：

*   `appletviewer`：该工具使您能够运行和调试 Java 小程序，而无需使用 Web 浏览器。
*   `extcheck`：该工具允许您在 JAR 文件中查找冲突。
*   `jar`：该工具用于创建和操作 JAR 文件。JAR 文件是 Java 存档文件。
*   `java`：这是 Java 应用启动器。
*   `javac`：这是 Java 编译器。
*   `javadoc`：该工具生成 API 文档。
*   `javah`：这个工具允许您编写本机方法；它生成 C 头文件。
*   `javap`：该工具反汇编类文件。
*   `javapackager`：用于 Java 应用的签名和打包，包括 JavaFX。
*   `jdb`：这是 Java 调试器。
*   `jdeps`：这是一个 Java 类依赖的分析器。
*   `pack200`：将 JAR 文件压缩成`pack200`文件的工具。使用这个工具的压缩比令人印象深刻。
*   `unpack200`：此工具解压`pack200`文件，生成 JAR 文件。

# 国际化

如果您对创建可本地化的应用感兴趣，以下工具可能会派上用场：

*   `native2ascii`：该工具从普通文本创建 Unicode 拉丁 1

# 监控

用于提供 JVM 性能数据的监视工具包括：

*   `jps`：这是 JVM 进程状态工具（`jps`）。它提供了特定系统上 HotSpot JVM 的列表。
*   `jstat`：JVM 统计监控工具。它从具有 HotSpot JVM 的机器收集日志数据和性能信息。
*   `jstatd`：这是`jstat`守护程序工具。它运行一个 RMI 服务器应用来监视 HotSpot JVM 操作。

# RMI 

**RMI** 工具是**远程方法调用**工具。它们帮助开发人员创建通过网络运行的应用，包括互联网：

*   `rmic`：该工具可以为网络上的对象生成存根和骨架
*   `rmiregistry`：这是一个远程对象的注册服务
*   `rmid`：此工具是 RMI 的激活系统守护程序
*   `serialver`：此工具返回类`serialVersionUID`值

# 安全

这组安全工具使开发人员能够创建可在开发人员的计算机系统以及远程系统上实现的安全策略：

*   `keytool`：管理安全证书和密钥库
*   `jarsigner`：该工具生成并验证用于创建/打开 JAR 文件的 JAR 签名
*   `policytool`：这个工具有一个图形用户界面，帮助开发人员管理他们的安全策略文件

# 故障排除

这些实验性的故障排除工具对于非常具体的故障排除非常有用。它们是实验性的，因此没有得到官方的支持：

*   `jinfo`：此工具提供特定进程、文件或服务器的配置信息
*   `jhat`：这是一个堆转储工具。它实例化了一个 Web 服务器，以便可以用浏览器查看堆
*   `jmap`：显示进程、文件或服务器的堆和共享对象内存映射
*   `jsadebugd`：这是 Java 的可服务性代理调试守护进程。它充当进程或文件的调试服务器
*   `jstack`：这是一个 Java 栈跟踪工具，为进程、文件或服务器提供线程栈跟踪

# Web 服务

这组工具提供了一个实用工具，可与 **Java Web Start** 和其他 Web 服务一起使用：

*   `javaws`：这是一个启动 JavaWebStart 的命令行工具。
*   `schemagen`：该工具为 Java 架构生成模式。这些模式用于 XML 绑定。
*   `wsgen`：该工具用于生成可移植的 JAX-WS 工件。
*   `wsimport`：这个工具用于导入可移植的 JAX-WS 工件。
*   `xjc`：这是用于 XML 绑定的绑定编译器。

# JavaFX 工具

JavaFX 工具位于几个不同的地方，包括`\bin`、`\man`和`\lib`目录。

# Java 运行时环境

JRE 位于`\jre`目录中。主要内容包括 JVM 和类库。

# 源代码

JDK 的源代码是 Java9 之前的版本，具有以下基本组织架构：

```java
source code / [shared, OS-specific] / [classes / native] / Java API package name / [.file extension]
```

我们再仔细看看。在源代码之后，我们有两个选择。如果代码是跨平台的，那么它是一个共享目录；否则，它是特定于操作系统的。例如：

```java
src/share/...
src/windows/...
```

接下来，我们有`classes`目录或本地语言目录。例如：

```java
src/share/classes/...
src/share/classes/java/...
```

接下来，我们有 JavaAPI 包的名称，后跟文件扩展名。文件扩展名依赖于`.java`、`.c`等内容。

# 库

`\lib`目录包含`\bin`目录中一个或多个开发工具所需的类库。以下是典型 Java8`\lib`目录中的文件列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/21c27de9-b47f-436c-8c76-e3002770ff89.png)

查看目录列表并不能提供很好的细粒度洞察力。我们可以使用以下命令列出任何一个`.jar`文件中包含的类：`jar tvf fileName.jar`。例如，下面是在命令行执行`jar tvf javafx-mx.jar`生成的类列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/4354da68-104c-483d-9382-5013031bc7ab.png)

# C 头文件

`/include`目录包含 C 头文件。这些文件主要支持以下内容：

*   **Java 本机接口（JNI）**：用于本机代码编程支持，JNI 用于将 Java 本机方法和 JVM 嵌入到本机应用中。
*   **JVM 工具接口（JVM TI）**：用于对运行 JVM 的应用进行状态检查和执行控制的工具。

# 数据库

ApacheDerby 关系数据库存储在`/db`目录中。您可以在以下站点了解有关 Java DB 的更多信息：

*   <http://docs.oracle.com/javadb/support/overview.html>
*   <http://db.apache.org/derby/manuals/#docs_10.11>

# JDK 源代码重组

在上一节中，您了解到 Java9 之前的源代码组织模式如下：

```java
source code / [shared, OS-specific] / [classes / native] / Java API package name / [.file extension]
```

在当前的 Java 平台中，我们有一个模块化的模式。该模式如下：

```java
source code / module / [shared, OS-specific] / [classes / native / configuration] / [ package / include / library ] / [.file extension]
```

新模式中有一些不同之处，最明显的是模块名。在共享或 OS 特定目录之后，有类目录、用于 C 或 C++ 源文件的本机目录或配置目录。这种看似基本的组织模式更改会导致更易于维护的代码库。

# 模块化运行时映像

Java9 中引入的 Java 模块化系统需要更改运行时映像以实现兼容性。这些更改的好处包括以下方面的增强：

*   维修性
*   性能
*   安全

这些更改的核心是用于资源命名的新 URI 模式。这些资源包括模块和类。

**统一资源标识符**（**URI**）与**统一资源定位器**（**URL**）相似，它标识某物的名称和位置。对于 URL，某物是网页；对于 URI，它是资源。

 **JEP-220 有五个主要目标，这些目标将在下面的章节中详细介绍。

# 采用运行时格式

为 Java9 创建了一个运行时格式，以供存储类和其他资源文件采用。此格式适用于以下情况下存储的类和资源：

*   当新的运行时格式比 Java9Jar 之前的格式具有更高的效率（时间和空间）时。

**JAR** 文件是 **Java 归档**文件。这是一种基于传统 ZIP 格式的压缩文件格式。

*   当存储的类和其他资源可以单独隔离和加载时。
*   当 JDK 和库类和资源可以存储时。这也包括应用模块。
*   当它们被设计成促进未来增强的方式时。这要求它们具有可扩展性、文档化和灵活性。

# 运行时映像重构

Java 中有两种类型的运行时映像：JDK 和 JRE。从 Java9 开始，这两种图像类型都被重新构造，以区分用户可以使用和修改的文件和开发人员及其应用可以使用但不能修改的内部文件。

在 Java9 之前的 JDK 构建系统同时生成了 JRE 和 JDK。JRE 是 Java 平台的完整实现。JDK 包括 JRE 以及其他工具和库。Java9 中一个显著的变化是 JRE 子目录不再是 JDK 映像的一部分。进行此更改的部分原因是为了确保两种图像类型（JDK 和 JRE）具有相同的图像结构。有了共同和重组的结构，未来的变革将更有效地结合起来。

如果您在 Java9 之前创建了针对特定结构的自定义插件，那么您的应用可能无法在 Java9 中工作。如果您显式地寻址`tools.jar`，这也是正确的。

下图提供了 Java9 发布前每个图像内容的高级视图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/e1b55a00-4ec3-43d3-be69-d9ed4a7b07d9.jpg)

Java9 运行时映像如下图所示。如图所示，完整的 JDK 映像包含与模块化运行时映像相同的目录以及`demo`、`sample`、`man`，并且包括目录：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/b6355c6c-6223-4abc-88f4-183cc41ba2cd.jpg)

JRE 和 JDK 映像之间不再有区别。在当前的 Java 平台上，JDK 映像是一个 JRE 映像，它包含一整套开发工具。

# 支持常见操作

开发人员有时必须编写代码来执行需要访问运行时映像的操作。Java9 包括对这些常见操作的支持。由于 JDK 和 JRE 运行时映像结构的重新构造和标准化，这是可能的。

# 剥夺 JDK 类的权限

当前的 Java 平台允许对单个 JDK 类进行特权撤销。此更改增强了系统安全性，因为它确保 JDK 类只接收系统操作所需的权限。

# 保留现有行为

JEP-220 的最终目标是确保现有的类不会受到负面影响。这是指不依赖于内部 JDK 或 JRE 运行时映像的应用。

# 模块系统

您会记得，创建模块化系统是为了为 Java 程序提供可靠的配置和强大的封装。这个实现的关键是链接时间的概念。如这里所示，链接时间是编译时和运行时之间的一个可选阶段。此阶段允许将适当的模块组装到优化的运行时映像中。

这在一定程度上是由于 JLink 链接工具的缘故，您将在本章后面详细了解该工具：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/c2b08b46-a4ce-4691-afd4-c724091421ad.jpg)

# 模块路径

重要的是要组织模块，以便它们可以很容易地定位。模块路径（模块组件或目录的序列）提供了搜索所使用的组织结构。依次搜索这些路径组件，返回包含模块的第一个路径组件。

模块及其路径不应被视为与包或类路径相同。他们确实是不同的，有更高水平的忠诚。关键的区别在于，对于类路径，将搜索单个组件。模块路径搜索返回完整的模块。这种类型的搜索可以通过按显示顺序搜索以下路径，直到返回模块：

*   编译模块路径
*   升级模块路径
*   系统模块路径
*   应用模块路径

让我们简要回顾一下这些路径。编译模块路径仅在编译时适用，并且包含模块定义。升级模块路径具有已编译的模块定义。系统模块是内置的，包括 JavaSE 和 JDK 模块。最后一个路径，即应用模块路径，包含来自应用模块和库模块的已编译模块定义。

# 访问控制边界冲突

作为一个专业的开发人员，您总是希望您的代码是安全的、可移植的和无 bug 的，这需要严格遵守 Java 构造，比如封装。在某些情况下，比如白盒测试，您需要打破 JVM 要求的封装。此授权允许跨模块访问。

为了允许破坏封装，您可以在模块声明中添加一个`add-exports`选项。以下是您将使用的语法：

```java
module com.three19.irisScan
{
  - - add-exports <source-module>/<package> = <target-module>
  (, <target-module> )*
}
```

让我们仔细看看前面的语法。`<source-module>`和`<targetmodule>`是模块名，`<package>`是包名。使用`add-exports`选项允许我们违反访问控制边界。

关于使用`add-exports`选项有两条规则：

*   它可以在一个模块中多次使用
*   每次使用必须是`<source-module>`和`<targetmodule>`的唯一配对

除非绝对必要，否则不建议使用`add-exports`选项。它的使用允许对库模块的内部 API 进行危险的访问。这种类型的使用使您的代码依赖于内部 API 而不会改变，这是您无法控制的。

# 运行时

热点虚拟机为`jmod`和`jlink`命令行工具实现`<options>`。

以下是`jmod`命令行工具的`<options>`列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/5c00499f-23ec-43bf-9796-355d5b1bfd31.png)

以下是`jlink`命令行工具的`<options>`列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/0a7436c3-a573-4a97-aa3d-7726517810d3.png)

# 模块化 Java 应用打包

Java9 以及 Java10 和 Java11 的最大改进之一是由 **Java 打包器**生成的运行时二进制文件的大小。这在一定程度上是由于 **Java 链接器**的缘故，这将在下一节中介绍。在当前的 Java11 中，JavaPackager 的工作流程基本上与 Java8 中的相同。您将在本节后面看到，工作流中添加了新工具。

Java 打包器只创建 JDK 应用。对 Java 打包器的这一更改旨在简化并提高生成运行时映像的过程的效率。因此，Java 打包器将只为与其关联的 SDK 版本创建运行时映像。

# Java 链接器的高级研究

在 Java9 中引入 Java 链接器工具`jlink`之前，运行时映像创建包括复制整个 JRE。然后，移除未使用的组件。简单地说，`jlink`促进了只使用所需模块创建运行时映像。`jlink`被 Java 打包器用来生成嵌入式运行时映像。

# Java 打包器选项

Java 打包器的语法如下：

```java
javapackager -command [-options]
```

可以使用五种不同的命令（`-command`。具体描述如下：

| **命令** | **说明** |
| --- | --- |
| `-createbss` | 此命令用于将文件从 CSS 转换为二进制文件。 |
| `-createjar` | 这个命令与其他参数一起使用，创建一个 JAR 归档文件。 |
| `-deploy` | 此命令用于生成 Java 网络启动协议（JNLP）和 HTML 文件。 |
| `-makeall` | 此命令结合了`-createjar`、`-deploy`和编译步骤。 |
| `-signJar` | 这个命令创建并签署一个 JAR 文件。 |

`-createbss`命令的`[-options]`包括：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/526297f0-7c46-4c42-8520-7c41aa9d1918.png)

`-createjar`命令的`[-options]`包括：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/4641841d-7f71-4fb3-8201-bce93588b955.png)

`-deploy`命令的第一组`[-options]`包括：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/2a3a8cf8-94fa-4c68-94f4-d2b9c77da037.png)

`-deploy`命令的剩余`[-options]`集合包括以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/a20fbfb3-e0be-4721-aa19-69a4a264c72d.png)

`-makeall`命令的`[-options]`包括：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/b49730c7-33bc-4480-bdcf-4ca8be1584bb.png)

`-signJar`命令的`[-options]`包括：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/0fececea-eea1-414e-916d-e0abbfa200c0.png)

Java 打包器分为两个模块：

*   `jdk.packager`
*   `jdk.packager.services`

# Java 链接器

Java 链接器，通常称为 JLink，是一个创建自定义运行时映像的工具。该工具收集相应的模块及其依赖项，然后对它们进行优化以创建映像。这代表了 Java 的一个重大变化，它将在 Java9 的发行版中实现。在 Java 链接器工具 JLink 可用之前，运行时映像创建包括最初复制整个 JRE。在随后的步骤中，将删除未使用的组件。在当前的 Java 平台中，`jlink`只创建需要的模块的运行时映像。`jlink`由 Java 打包器生成嵌入式运行时映像。

如前一节所示，最近对 Java 平台的更改导致链接时成为编译时和运行时之间的可选阶段。正是在这个阶段，适当的模块被组装成一个优化的运行时映像。

JLink 是一个命令行链接工具，它允许创建包含较小 JDK 模块子集的运行时映像。这将导致更小的运行时映像。以下语法由四个组件组成`jlink`命令、选项、模块路径和输出路径：

```java
$ jlink <options> ---module-path <modulepath> --output <path>
```

以下是可与`jlink`工具一起使用的选项列表，以及每个选项的简要说明：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/f16c6d54-7178-4dc9-a001-8b40449d55cb.png)

模块路径告诉链接器在哪里可以找到模块。链接器不会使用分解的模块或 JAR/JMOD 文件。

输出路径只是通知链接器保存自定义运行时映像的位置。

# 封装大多数内部 API

JEP-260 的实现使 Java 平台更加安全。JEP 的核心目标是封装大多数内部 API。具体来说，JDK 的大多数内部 API 在默认情况下不再可访问。目前，被认为是关键和广泛使用的内部 API 仍然可以访问。在将来，我们很可能会看到替代它们的功能，届时，默认情况下，这些内部 API 将无法访问。

那么，为什么这种改变是必要的呢？有一些广泛使用的 API 是不稳定的，在某些情况下是不标准的。不受支持的 API 不应访问 JDK 的内部详细信息。因此，JEP-260 提高了 Java 平台的安全性，一般来说，您不应该在开发项目中使用不受支持的 API。

上述关键 API（JDK 内部）如下所示：

*   `sun.misc`
*   `sun.misc.Unsafe`
*   `sun.reflect.Reflection`
*   `sun.reflect.ReflectionFactory.newConstrutorForSerialization`

上述关键的内部 API 在当前 Java 平台中仍然可以访问。它们可以通过`jdk.unsupported`JDK 模块访问。完整的 JRE 和 JDK 映像将包含`jdk.unsupported`模块。

您可以使用 Java 依赖性分析工具`jdeps`来帮助确定 Java 程序是否依赖于 JDK 内部 API。

这是一个有趣的变化。在未来的 Java 版本中，默认情况下，当前可访问的内部 API 可能无法访问。

# 总结

在本章中，我们检查了 Jigsaw 项目指定的 Java 模块的结构，并深入了解了如何实现 Jigsaw 项目以改进 Java 平台。我们还回顾了 Java 平台与模块化系统相关的关键内部更改。我们的回顾从模块化入门开始，从好处和需求的角度了解了 Java 的模块化系统。

我们探讨了构成 JDK 的七个主要工具类别。正如我们所了解的，Java 中的模块化还扩展到运行时映像，从而提高了可维护性、性能和安全性。链接时间的概念是作为编译时和运行时之间的可选阶段引入的。在本章的结尾，我们介绍了 Java 链接器以及 Java 如何封装内部 API。

在下一章中，我们将探讨如何将现有的应用迁移到当前的 Java 平台。我们将研究手动和半自动迁移过程。

# 问题

1.  导致 Java 平台模块化的主要因素是什么？
2.  模块化系统的四个强制性要求是什么？
3.  Java 模块是哪六个组件的集合？
4.  所有 JCP 管理的模块都以什么前缀开头？
5.  JDK 的七个主要组件是什么？
6.  模块化运行时映像有什么好处？
7.  模块化运行时映像中有哪些目录？
8.  完整 JDK 映像中有哪些目录？
9.  编译时和运行时之间的可选阶段是什么？
10.  Java 打包器创建的二进制文件比以前的 Java 版本小是什么原因？

# 进一步阅读

此处列出的参考资料将帮助您深入了解本章中介绍的概念：

*   [《学习 Java9——模块化编程》](https://www.packtpub.com/application-development/learning-java-9-%E2%80%93-modular-programming-video)。
*   [《使用 Java9 逐步学习 JShell》](https://www.packtpub.com/application-development/learn-jshell-java-9-step-step-video)。