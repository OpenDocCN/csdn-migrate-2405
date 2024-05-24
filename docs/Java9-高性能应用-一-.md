# Java9 高性能应用（一）

> 原文：[`zh.annas-archive.org/md5/051c92f3ddab22ee9b33739e7a959dd3`](https://zh.annas-archive.org/md5/051c92f3ddab22ee9b33739e7a959dd3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本书是关于 Java 9 的，它是最受欢迎的应用程序开发语言之一。最新发布的 Java 9 版本带来了许多新功能和新 API，具有大量可用的组件，可用于构建高效和可扩展的应用程序。流式处理、并行和异步处理、多线程、JSON 支持、响应式编程和微服务构成了现代编程的特点，并已完全集成到 JDK 中。

因此，如果您想将您的 Java 知识提升到另一个水平，并且想要改进您的应用程序性能，您选择了正确的路径。

# 对我有什么好处？

地图对您的旅程至关重要，特别是当您在另一个大陆度假时。在学习方面，路线图可以帮助您确定前进目标的明确路径。因此，在开始旅程之前，我们为您提供了一张路线图。

这本书经过精心设计和开发，旨在为您提供有关 Java 的所有正确和相关信息。我们为您创建了这个学习路径，其中包括五课：

第 1 课，*学习 Java 9 底层性能改进*，涵盖了 Java 9 的令人兴奋的功能，这些功能将改善应用程序的性能。它侧重于模块化开发及其对应用程序性能的影响。

第 2 课，*提高生产力和加快应用程序*，描述了 Java 9 中新增的两个工具--JShell 和 Ahead-of-Time（AOT）编译器--它们可以提高您的生产力，同时改善应用程序的整体性能。

第 3 课，*多线程和响应式编程*，展示了如何使用命令行工具以编程方式监视 Java 应用程序。您还将探索如何通过多线程来提高应用程序性能，并在了解监视后如何调整 JVM 本身。

第 4 课，*微服务*，描述了许多行业领袖在应对负载下的灵活扩展时采用的解决方案。它讨论了通过将应用程序拆分为多个微服务并独立部署每个微服务，并使用多线程和响应式编程来实现更好的性能、响应、可扩展性和容错性。

第 5 课，*利用新 API 改进您的代码*，描述了编程工具的改进，包括流过滤器、堆栈遍历 API、用于创建不可变集合的新便捷静态工厂方法、支持异步处理的强大的 CompletableFuture 类以及 JDK 9 流 API 的改进。

# 我将从这本书中得到什么？

+   熟悉模块化开发及其对性能的影响

+   学习各种与字符串相关的性能改进，包括紧凑字符串和字符串连接

+   探索各种底层编译器改进，如分层归因和 Ahead-of-Time（AOT）编译

+   学习安全管理器的改进

+   了解图形光栅化器的增强功能

+   使用命令行工具加快应用程序开发

+   学习如何实现多线程和响应式编程

+   在 Java 9 中构建微服务

+   实现 API 以改进应用程序代码

# 先决条件

这本书是为想要构建可靠和高性能应用程序的 Java 开发人员而设计的。在开始阅读本书之前，需要具备一些先决条件：

+   假定具有先前的 Java 编程知识


# 第一章：学习 Java 9 的底层性能改进

就在你以为你已经掌握了 Java 8 的 lambda 和所有与性能相关的功能时，Java 9 就出现了。接下来是 Java 9 中的一些功能，可以帮助改进应用程序的性能。这些功能超越了像字符串存储或垃圾收集变化这样的字节级变化，这些变化你几乎无法控制。还有，忽略实现变化，比如用于更快的对象锁定的变化，因为你不需要做任何不同的事情，你会自动获得这些改进。相反，有新的库功能和全新的命令行工具，可以帮助你快速创建应用程序。

在本课程中，我们将涵盖以下主题：

+   模块化开发及其对性能的影响

+   各种与字符串相关的性能改进，包括紧凑字符串和字符串连接的改进

+   并发的进步

+   各种底层编译器改进，如分层归因和**提前编译**（**AOT**）编译

+   安全管理器的改进

+   图形光栅化器的增强

# 介绍 Java 9 的新功能

在本课程中，我们将探讨许多在新环境中运行应用程序时自动获得的性能改进。在内部，字符串的改变也大大减少了在不需要完整的 Unicode 支持的字符字符串时的内存占用。如果你的大部分字符串可以被编码为 ISO-8859-1 或 Latin-1（每个字符 1 个字节），它们将在 Java 9 中存储得更有效。因此，让我们深入研究核心库，并学习底层性能改进。

# 模块化开发及其影响

在软件工程中，模块化是一个重要的概念。从性能和可维护性的角度来看，创建称为**模块**的自主单元非常重要。这些模块可以被绑定在一起以构建完整的系统。模块提供了封装，其中实现对其他模块隐藏。每个模块可以暴露出不同的 API，可以作为连接器，使其他模块可以与之通信。这种设计有助于促进松散耦合，有助于专注于单一功能以使其具有内聚性，并使其能够在隔离环境中进行测试。它还减少了系统复杂性并优化了应用程序开发过程。改进每个模块的性能有助于提高整体应用程序性能。因此，模块化开发是一个非常重要的概念。

我知道你可能会想，等一下，Java 不是已经是模块化的了吗？Java 的面向对象性质不是已经提供了模块化操作吗？嗯，面向对象确实强调了独特性和数据封装。它只建议松散耦合，但并不严格执行。此外，它未能在对象级别提供标识，并且也没有接口的版本控制。现在你可能会问，JAR 文件呢？它们不是模块化的吗？嗯，尽管 JAR 文件在一定程度上提供了模块化，但它们缺乏模块化所需的独特性。它们确实有规定版本号的规定，但很少被使用，而且也隐藏在 JAR 的清单文件中。

因此，我们需要与我们已有的不同的设计。简单来说，我们需要一个模块化系统，其中每个模块可以包含多个包，并且相对于标准的 JAR 文件，提供了强大的封装。

这就是 Java 9 的模块化系统所提供的。除此之外，它还通过明确声明依赖关系来取代了不可靠的类路径机制。这些增强功能提高了整体应用程序的性能，因为开发人员现在可以优化单个自包含单元，而不会影响整体系统。

这也使得应用程序更具可扩展性并提供高度的完整性。

让我们来看一下模块系统的一些基础知识以及它们是如何联系在一起的。首先，您可以运行以下命令来查看模块系统的结构：

```java
$java --list-modules

```

![模块化开发及其影响](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/01_01.jpg)

如果您对特定模块感兴趣，您可以简单地在命令的末尾添加模块名称，如下命令所示：

```java
$java --list-modules java.base

```

![模块化开发及其影响](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/01_02.jpg)

之前的命令将显示基本模块中包的所有导出。Java base 是系统的核心。

这将显示所有图形用户界面包。这也将显示`requires`，即依赖项：

```java
$java --list-modules java.desktop

```

![模块化开发及其影响](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/01_03.jpg)

到目前为止，一切都还好，对吧？现在您可能会想，我已经开发了我的模块，但如何将它们集成在一起呢？让我们来看看。Java 9 的模块化系统配备了一个名为**JLink**的工具。我知道你可以猜到我现在要说什么。你是对的，它链接一组模块并创建一个运行时映像。现在想象一下它可以提供的可能性。您可以使用自己的自定义模块创建自己的可执行系统。我希望对您来说生活将会更有趣！哦，另一方面，您将能够控制执行并删除不必要的依赖项。

让我们看看如何将模块链接在一起。嗯，很简单。只需运行以下命令：

```java
$jlink --module-path $JAVA_HOME/jmods:mlib --add-modules java.desktop --output myawesomeimage

```

这个链接器命令将为您链接所有模块并创建一个运行时映像。您需要提供一个模块路径，然后添加您想要生成图形并给出名称的模块。很简单，不是吗？

现在，让我们检查之前的命令是否正常工作。让我们从图中验证模块：

```java
$myawesomeimage/bin/java --list-modules

```

输出如下所示：

![模块化开发及其影响](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/01_04.jpg)

有了这个，现在您将能够在应用程序中分发一个快速运行时。这太棒了，不是吗？现在您可以看到我们是如何从有点庞大的设计转变为一个自包含的连贯设计的。每个模块都包含自己的导出和依赖项，而 JLink 允许您创建自己的运行时。有了这个，我们得到了我们的模块化平台。

请注意，本节的目的只是为了向您介绍模块化系统。还有很多内容可以探索，但这超出了本书的范围。在本书中，我们将专注于性能增强领域。

## 模块的快速介绍

我相信在阅读了模块化平台的介绍之后，您一定会对深入了解模块架构并了解如何开发模块感到兴奋。请稍等兴奋，我很快会带您进入模块的激动人心的世界。

正如您可能已经猜到的那样，每个模块都有一个`name`属性，并且由包组织。每个模块都作为一个自包含的单元，并且可能具有本地代码、配置、命令、资源等。模块的详细信息存储在一个名为`module-info.java`的文件中，该文件位于模块源代码的根目录中。在该文件中，可以定义一个模块，如下所示：

```java
module <name>{
}
```

为了更好地理解它，让我们通过一个例子来看一下。假设我们的模块名是`PerformanceMonitor`。这个模块的目的是监控应用程序的性能。输入连接器将接受方法名称和该方法所需的参数。该方法将从我们的模块中调用，以监视模块的性能。输出连接器将为给定模块提供性能反馈。让我们在性能应用程序的根目录中创建一个`module-info.java`文件，并插入以下部分：

```java
module com.java9highperformance.PerformanceMonitor{
}
```

太棒了！你得到了你的第一个模块声明。但等一下，它还没有做任何事情。别担心，我们只是创建了一个框架。让我们给这个框架加点肉。假设我们的模块需要与我们已经创建并命名为`PerformanceBase`、`StringMonitor`、`PrimitiveMonitor`、`GenericsMonitor`等的其他（了不起的）模块进行通信。换句话说，我们的模块有外部依赖。你可能想知道，我们如何在模块声明中定义这种关系？好吧，耐心点，这就是我们现在要看到的：

```java
module com.java9highperformance.PerformanceMonitor{
    exports com.java9highperformance.StringMonitor;
    exports com.java9highperformance.PrimitiveMonitor;
    exports com.java9highperformance.GenericsMonitor;
    requires com.java9highperformance.PerformanceBase;
    requires com.java9highperformance.PerformanceStat;
    requires com.java9highperformance.PerformanceIO;
}
```

是的，我知道你已经发现了两个子句，即`exports`和`requires`。我相信你很好奇它们的含义以及为什么我们要在这里使用它们。我们首先来谈谈这些子句以及它们在模块声明中的含义：

+   `exports`：当你的模块依赖于另一个模块时，使用这个子句。它表示这个模块只向其他模块公开公共类型，内部包都是不可见的。在我们的例子中，模块`com.java9highperformance.PerformanceMonitor`依赖于`com.java9highperformance.StringMonitor`、`com.java9highperformance.PrimitiveMonitor`和`com.java9highperformance.GenericsMonitor`。这些模块分别导出它们的 API 包`com.java9highperformance.StringMonitor`、`com.java9highperformance.PrimitiveMonitor`和`com.java9highperformance.GenericsMonitor`。

+   `requires`：这个子句表示模块在编译和运行时依赖于声明的模块。在我们的例子中，`com.java9highperformance.PerformanceBase`、`com.java9highperformance.PerformanceStat`和`com.java9highperformance.PerformanceIO`模块都被`com.java9highperformance.PerformanceMonitor`模块所需。然后模块系统会定位所有可观察的模块，递归解析所有依赖关系。这种传递闭包给我们一个模块图，显示了两个依赖模块之间的有向边。

### 注意

**注意**：每个模块都依赖于`java.base`，即使没有明确声明。正如你所知，Java 中的一切都是对象。

现在你知道了模块及其依赖关系。所以，让我们画一个模块表示来更好地理解它。下图显示了各种包依赖于`com.java9highperformance.PerformanceMonitor`。

![模块快速介绍](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/01_05.jpg)

底部的模块是`exports`模块，右侧的模块是`requires`模块。

现在让我们探讨一个叫做**可读性关系**的概念。可读性关系是两个模块之间的关系，其中一个模块依赖于另一个模块。这种可读性关系是可靠配置的基础。因此在我们的例子中，我们可以说`com.java9highperformance.PerformanceMonitor`读取`com.java9highperformance.PerformanceStat`。

让我们来看看`com.java9highperformance.PerformanceStat`模块的描述文件`module-info.java`：

```java
module com.java9highperformance.PerformanceStat{
    requires transitive java.lang;
}
```

这个模块依赖于`java.lang`模块。让我们详细看看`PerformanceStat`模块：

```java
package com.java9highperformance.PerformanceStat;
import java.lang.*;

public Class StringProcessor{
    public String processString(){...}
}
```

在这种情况下，`com.java9highperformance.PerformanceMonitor`只依赖于`com.java9highperformance.PerformanceStat`，但`com.java9highperformance.PerformanceStat`依赖于`java.lang`。`com.java9highperformance.PerformanceMonitor`模块不知道`com.java9highperformance.PerformanceStat`模块对`java.lang`的依赖。模块系统已经解决了这种问题，它添加了一个叫做**transitive**的新修饰符。如果你看`com.java9highperformance.PerformanceStat`，你会发现它需要 transitive`java.lang`。这意味着任何依赖于`com.java9highperformance.PerformanceStat`的模块都会读取`java.lang`。

请看下面的图表，显示了可读性图：

![模块快速介绍](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/01_06.jpg)

现在，为了编译`com.java9highperformance.PerformanceMonitor`模块，系统必须能够解析所有依赖关系。这些依赖关系可以从模块路径中找到。这是显而易见的，不是吗？然而，不要将类路径误解为模块路径。它是一个完全不同的品种。它没有包的问题。

# 字符串操作性能

如果你不是编程新手，字符串一定是你迄今为止最好的朋友。在许多情况下，你可能会更喜欢它而不是你的配偶或伴侣。我们都知道，没有字符串你无法生存，事实上，甚至没有一个字符串的使用你都无法完成你的应用程序。好了，关于字符串已经表达得足够多了，我已经感到头晕，就像早期版本的 JVM 一样。开玩笑的，让我们谈谈 Java 9 中发生了什么改变，将帮助你的应用程序表现更好。虽然这是一个内部变化，但作为应用程序开发人员，了解这个概念很重要，这样你就知道在哪里集中精力进行性能改进。

Java 9 已经迈出了改善字符串性能的一步。如果你曾经遇到过 JDK 6 的失败尝试`UseCompressedStrings`，那么你一定在寻找改善字符串性能的方法。由于`UseCompressedStrings`是一个实验性功能，容易出错且设计不太好，它在 JDK 7 中被移除了。不要为此感到难过，我知道这很糟糕，但金色时代终将到来。JEP 团队经历了巨大的痛苦，添加了一项紧凑字符串功能，将减少字符串及其相关类的占用空间。

紧凑字符串将改善字符串的占用空间，并帮助高效使用内存空间。它还保留了所有相关的 Java 和本地接口的兼容性。第二个重要的特性是**Indify String Concatenation**，它将在运行时优化字符串。

在这一部分，我们将仔细研究这两个特性及其对整体应用程序性能的影响。

## 紧凑字符串

在我们谈论这个特性之前，了解为什么我们要关心这个问题是很重要的。让我们深入了解 JVM 的地下世界（或者正如任何星球大战迷所说的，原力的黑暗面）。让我们首先了解 JVM 如何对待我们心爱的字符串，这将帮助我们理解这个新的闪亮的紧凑字符串改进。让我们进入堆的神奇世界。事实上，没有讨论这个神秘世界的性能书籍是不完整的。

### 堆的世界

每次 JVM 启动时，它从底层操作系统获取一些内存。它被分成两个不同的区域，称为**堆空间**和**Permgen**。这些是你的应用程序资源的家园。就像生活中的所有美好事物一样，这个家园的大小是有限的。这个大小在 JVM 初始化时设置；然而，你可以通过指定 JVM 参数`-Xmx`和`-XX:MaxPermSize`来增加或减少这个大小。

堆大小分为两个区域，幼年空间和老年空间。顾名思义，幼年空间是新对象的家园。这听起来很棒，但每个房子都需要清理。因此，JVM 有一个非常高效的清理工具，称为**垃圾收集器**（最有效？嗯...我们暂时不讨论这个）。就像任何高效的清洁工一样，垃圾收集器高效地收集所有未使用的对象并回收内存。当这个幼年空间被新对象填满时，垃圾收集器会负责将那些在幼年空间中生活了足够长时间的对象移动到老年空间。这样，幼年空间总是有更多对象的空间。

同样，如果老年空间被填满，垃圾收集器会回收使用的内存。

## 为什么要压缩字符串？

现在你对堆有了一点了解，让我们来看看`String`类和字符串在堆上是如何表示的。如果你解剖你的应用程序的堆，你会注意到有两个对象，一个是 Java 语言`String`对象，它引用第二个对象`char[]`，实际上处理数据。`char`数据类型是 UTF-16，因此占用 2 个字节。让我们看看以下两种不同语言字符串的例子：

```java
2 byte per char[]
Latin1 String : 1 byte per char[]
```

因此，你可以看到`Latin1 String`只占用 1 个字节，因此我们在这里损失了大约 50%的空间。有机会以更密集的形式表示它并改进占用空间，这最终也将有助于加快垃圾回收的速度。

现在，在对此进行任何更改之前，了解其对现实应用的影响是很重要的。了解应用程序是使用 1 个字节还是 2 个字节的`char[]`字符串是至关重要的。

为了得到这个答案，JPM 团队分析了大量真实数据的堆转储。结果表明，大多数堆转储中有大约 18%到 30%的整个堆被`chars[]`占用，这些来自字符串。此外，大多数字符串由`char[]`的单个字节表示。因此，很明显，如果我们尝试改进单字节字符串的占用空间，将会显著提高许多现实应用的性能。

### 他们做了什么？

经过了许多不同的解决方案，JPM 团队最终决定制定一项在构建过程中压缩字符串的策略。首先，乐观地尝试以 1 个字节压缩，如果不成功，再复制为 2 个字节。还有一些可能的捷径，例如使用像 ISO-8851-1 这样的特殊情况编码器，它总是输出 1 个字节。

这个实现比 JDK 6 的`UseCompressedStrings`实现要好得多，因为它只对少数应用有帮助，因为它在每个实例上都对字符串进行重新打包和解包。因此，性能的提升来自于它现在可以同时处理两种形式。

### 逃逸路线是什么？

尽管这一切听起来很棒，但如果你的应用程序只使用 2 个字节的`char[]`字符串，它可能会影响应用程序的性能。在这种情况下，不使用前面提到的检查，直接将字符串存储为 2 个字节的`char[]`是有意义的。因此，JPM 团队提供了一个关闭开关`--XX: -CompactStrings`，你可以使用它来禁用这个功能。

### 性能提升是什么？

前面的优化影响了堆，因为我们之前看到字符串是在堆中表示的。因此，它影响了应用程序的内存占用。为了评估性能，我们真的需要关注垃圾收集器。我们将稍后探讨垃圾收集的主题，但现在让我们专注于运行时性能。

## Indify 字符串连接

我相信你一定对我们刚刚学到的紧凑字符串功能感到兴奋。现在让我们来看看字符串最常见的用法，即连接。你是否曾经想过当我们尝试连接两个字符串时到底发生了什么？让我们来探索一下。看下面的例子：

```java
public static String getMyAwesomeString(){
    int javaVersion = 9;
    String myAwesomeString = "I love " + "Java " + javaVersion + " high       performance book by Mayur Ramgir";
    return myAwesomeString;
}
```

在前面的例子中，我们试图连接几个带有`int`值的字符串。编译器将获取你的精彩字符串，初始化一个新的`StringBuilder`实例，然后追加所有这些单独的字符串。让我们看看`javac`生成的以下字节码。我使用了**Eclipse**的**ByteCode Outline**插件来可视化这个方法的反汇编字节码。你可以从[`andrei.gmxhome.de/bytecode/index.html`](http://andrei.gmxhome.de/bytecode/index.html)下载它。

```java
// access flags 0x9
public static getMyAwesomeString()Ljava/lang/String;
  L0
  LINENUMBER 10 L0
  BIPUSH 9
  ISTORE 0
  L1
  LINENUMBER 11 L1
  NEW java/lang/StringBuilder
  DUP
  LDC "I love Java "
  INVOKESPECIAL java/lang/StringBuilder.<init> (Ljava/lang/String;)V
  ILOAD 0
  INVOKEVIRTUAL java/lang/StringBuilder.append (I)Ljava/lang/StringBuilder;
  LDC " high performance book by Mayur Ramgir"
  INVOKEVIRTUAL java/lang/StringBuilder.append (Ljava/lang/String;)Ljava/lang/StringBuilder;
  INVOKEVIRTUAL java/lang/StringBuilder.toString ()Ljava/lang/String;
  ASTORE 1
  L2
  LINENUMBER 12 L2
  ALOAD 1
  ARETURN
  L3
  LOCALVARIABLE javaVersion I L1 L3 0
  LOCALVARIABLE myAwesomeString Ljava/lang/String; L2 L3 1
  MAXSTACK = 3
  MAXLOCALS = 2
```

快速说明：我们如何解释这个？

+   `INVOKESTATIC`：这对于调用静态方法很有用

+   `INVOKEVIRTUAL`：这使用动态分派来调用公共和受保护的非静态方法

+   `INVOKEINTERFACE`：这与`INVOKEVIRTUAL`非常相似，只是方法分派是基于接口类型的。

+   `INVOKESPECIAL`：这对于调用构造函数、超类方法和私有方法非常有用

然而，在运行时，由于将`-XX:+-OptimizeStringConcat`包含到 JIT 编译器中，它现在可以识别`StringBuilder`的附加和`toString`链。如果识别到匹配，就会产生低级代码进行最佳处理。计算所有参数的长度，确定最终容量，分配存储空间，复制字符串，并对原始数据进行就地转换。之后，将此数组交给`String`实例而不进行复制。这是一个有利可图的优化。

但是，这在连接方面也有一些缺点。一个例子是，如果连接长字符串或双精度字符串，它将无法正确优化。这是因为编译器首先必须执行`.getChar`，这会增加开销。

此外，如果您将`int`附加到`String`，那么它的工作效果很好；但是，如果您有像`i++`这样的增量运算符，那么它就会出错。其原因是您需要回到表达式的开头并重新执行，因此您实际上是在做两次`++`。现在是 Java 9 中最重要的变化：紧凑字符串的长度拼写为`value.length >> coder`；`C2`无法优化它，因为它不知道 IR。

因此，为了解决编译器优化和运行时支持的问题，我们需要控制字节码，而不能指望`javac`来处理。

我们需要推迟在运行时决定哪些连接可以完成。那么我们是否可以只有`String.concat`方法来完成这一点。好吧，不要急着这样做，因为你如何设计`concat`方法呢。让我们来看看。解决这个问题的一种方法是接受`String`实例的数组：

```java
public String concat(String... n){
    //do the concatenation
}
```

然而，这种方法在处理原始数据时不起作用，因为现在您需要将每个原始数据转换为`String`实例，而且正如我们之前看到的，长字符串和双精度字符串连接将不允许我们进行优化。我知道，我能感觉到你脸上闪现出一丝光芒，就像你想到了解决这个痛苦问题的绝妙主意。你在考虑使用`Object`实例而不是`String`实例，对吗？正如你所知道的，`Object`实例是一个通用实例。让我们来看看你的绝妙主意：

```java
public String concat(Object... n){
    //do the concatenation
}
```

首先，如果您正在使用`Object`实例，那么编译器需要进行自动装箱。此外，您正在传递`varargs`数组，因此它不会表现出最佳性能。那么，我们被困在这里了吗？这意味着我们不能在字符串连接中使用卓越的紧凑字符串特性吗？让我们再想一想；也许我们可以让`javac`处理连接而不是使用`runtime`方法，并为我们提供优化的字节码。这听起来是个好主意。等一下，我知道你也在想同样的事情。如果 JDK 10 进一步优化这一点怎么办？这是否意味着当我升级到新的 JDK 时，我必须重新编译我的代码并再次部署？在某些情况下，这不是问题，但在其他情况下，这是一个大问题。所以，我们又回到了原点。

我们需要一些可以在运行时处理的东西。好吧，这意味着我们需要一些可以动态调用方法的东西。嗯，这让人想起了什么。如果我们回到时光机，回到 JDK 7 时代的黎明，它给了我们`invokedynamic`。我知道你能看到解决方案，我能感觉到你眼中的闪光。是的，你是对的，`invokedynamic`可以帮助我们。如果您不了解`invokedynamic`，让我们花点时间来了解一下。对于那些已经掌握了这个主题的人，你可以跳过它，但我建议你再次阅读一遍。

### 调用动态

`invokedynamic`功能是 Java 历史上最显著的功能。现在，我们不再受限于 JVM 字节码，可以自定义操作的方式。那么`invokedynamic`是什么？简单来说，它是用户可定义的字节码。这种字节码（而不是 JVM）决定了执行和优化策略。它提供了各种方法指针和适配器，这些适配器以方法处理 API 的形式存在。JVM 然后根据字节码中给定的指针进行工作，并使用类似反射的方法指针来优化它。这样，作为开发人员，您可以完全控制代码的执行和优化。

它本质上是用户定义的字节码（称为**字节码+引导**）和方法句柄的混合。我知道你也在想方法句柄--它们是什么，如何使用它们？好的，我听到你了，让我们谈谈方法句柄。

方法句柄提供各种指针，包括字段、数组和方法，用于传递数据并获取结果。借助这一点，您可以进行参数操作和流控制。从 JVM 的角度来看，这些是本机指令，它可以将其优化为字节码。但是，您可以选择以编程方式生成此字节码。

让我们来看看方法句柄，看看它们是如何联系在一起的。主要包的名称是`java.lang.invoke`，其中包括`MethodHandle`、`MethodType`和`MethodHandles`。`MethodHandle`是将用于调用函数的指针。`MethodType`是来自方法的一组参数和返回值的表示。实用类`MethodHandles`将充当指向一个方法的指针，该方法将获得`MethodHandle`的实例并映射参数。

我们不会深入探讨这一部分，因为目的只是让您了解`invokedynamic`功能是什么以及它是如何工作的，这样您就能理解字符串连接的解决方案。所以，我们回到了我们对字符串连接的讨论。我知道，你正在享受`invokedynamic`的讨论，但我想我已经给了你足够的见解，让你理解 Indify 字符串连接的核心思想。

让我们回到我们正在寻找解决方案来连接我们的精简字符串的部分。为了连接这些精简字符串，我们需要注意方法的类型和数量以及这就是`invokedynamic`给我们的。

所以让我们为`concat`使用`invokedynamic`。好吧，朋友，不要那么快。这种方法存在一个根本问题。我们不能只是使用`invokedynamic`来解决这个问题。为什么？因为存在循环引用。`concat`函数需要`java.lang.invoke`，而`java.lang.invoke`使用`concat`。这种情况会继续下去，最终会导致`StackOverflowError`。

看一下以下代码：

```java
String concat(int i, long l, String s){
    return s + i + l
}
```

所以如果我们在这里使用`invokedynamic`，`invokedynamic`调用会是这样的：

```java
InvokeDynamic #0: makeConcat(String, int, long)
```

有必要打破循环引用。然而，在当前的 JDK 实现中，您无法控制`java.invoke`从完整的 JDK 库中调用什么。此外，从`java.invoke`中删除完整的 JDK 库引用会产生严重的副作用。我们只需要`java.base`模块来进行 Indify 字符串连接，如果我们能找到一种方法只调用`java.base`模块，那么它将显著提高性能并避免不愉快的异常。我知道你在想什么。我们刚刚学习了 Java 9 的最酷的新功能，**Project Jigsaw**。它提供了模块化的源代码，现在我们只能接受`java.base`模块。这解决了我们在连接两个字符串、原语等方面所面临的最大问题。

经过几种不同的策略，Java 性能管理团队已经确定了以下策略：

1.  对所有引用参数调用`toString()`方法。

1.  调用`tolength()`方法或者由于所有底层方法都是公开的，只需在每个参数上调用`T.stringSize(T t)`。

1.  找出编码器并为所有引用参数调用`coder()`。

1.  分配`byte[]`存储，然后复制所有参数。然后，在原地转换原始数据。

1.  通过将数组传递给`String`的私有构造函数来调用。

有了这个，我们能够在同一代码中获得优化的字符串连接，而不是在`C2 IR`中。这种策略使我们的性能提高了 2.9 倍，垃圾减少了 6.4 倍。

# 将 Interned Strings 存储在 CDS 存档中

这个功能的主要目标是减少每个 JVM 进程中创建新字符串实例所造成的内存占用。在任何 JVM 进程中加载的所有类都可以通过**类数据共享**（**CDS**）存档与其他 JVM 进程共享。

哦，我没告诉你 CDS 的事。我认为花点时间了解 CDS 是很重要的，这样你就能理解底层的性能改进。

许多时候，特别是小型应用在启动操作上花费相对较长的时间。为了减少这种启动时间，引入了一个叫做 CDS 的概念。CDS 使得可以在 JRE 安装期间将从系统 JAR 文件加载的一组类共享到私有内部表示中。这对于任何进一步的 JVM 调用都很有帮助，因为它们可以利用这些加载类的共享存档中的表示，而不是再次加载这些类。与多个 JVM 进程共享与这些类相关的元数据。

CDS 在常量池中以 UTF-8 形式存储字符串。当这些加载的类中的一个类开始初始化过程时，这些 UTF-8 字符串会按需转换为`String`对象。在这种结构中，每个受限字符串中的每个字符在`String`对象中占据 2 个字节，在 UTF-8 中占据 1 个字节到 3 个字节，这实际上浪费了内存。由于这些字符串是动态创建的，不同的 JVM 进程无法共享这些字符串。

共享字符串需要一个名为**固定区域**的功能来利用垃圾收集器。由于唯一支持固定的 HotSpot 垃圾收集器是 G1；它只能与 G1 垃圾收集器一起使用。

# 并发性能

多线程是一个非常流行的概念。它允许程序同时运行多个任务。这些多线程程序可能有多个单位可以同时运行。每个单位可以处理不同的任务，保持可用资源的最佳利用。这可以通过多个线程并行运行来管理。

Java 9 改进了争用锁定。也许你想知道什么是争用锁定。让我们来探讨一下。每个对象都有一个监视器，一次只能被一个线程拥有。监视器是并发的基本构建块。为了让一个线程执行在对象上标记为同步的代码块或对象声明的同步方法，它必须拥有这个对象的监视器。由于有多个线程试图访问所述监视器，JVM 需要协调这个过程，并且一次只允许一个线程。这意味着其余的线程进入等待状态。然后这个监视器被称为争用。由于这个规定，程序在等待状态中浪费了时间。

此外，**Java 虚拟机**（**JVM**）还要做一些工作来协调锁争用。此外，它还必须管理线程，因此一旦现有线程完成执行，它就可以允许新线程进入。这肯定会增加开销，并对性能产生不利影响。Java 9 已经采取了一些措施来改进这一领域。该规定完善了 JVM 的协调，最终将导致高度竞争代码的性能改进。

以下基准测试可以用来检查争用 Java 对象监视器的性能改进：

+   `CallTimerGrid`（这更像是一个压力测试而不是基准测试）

+   `Dacapo-bach`（之前的 dacapo2009）

+   _ avrora

+   _ batik

+   _ fop

+   _ h2

+   _ luindex

+   _ lusearch

+   _ pmd

+   _ sunflow

+   _ tomcat

+   _ tradebeans

+   _ tradesoap

+   _ xalan

+   DerbyContentionModelCounted

+   HighContentionSimulator

+   LockLoops-JSR166-Doug-Sept2009（早期的 LockLoops）

+   PointBase

+   SPECjbb2013-critical（早期的 specjbb2005）

+   SPECjbb2013-max

+   specjvm2008

+   volano29（早期的 volano2509）

# 编译器改进

已经做出了一些努力来改进编译器的性能。在本节中，我们将重点关注编译器方面的改进。

## Tiered Attribution

提供编译器改进的首要变化与**Tiered Attribution**（**TA**）有关。这个改变更多地涉及到 lambda 表达式。目前，多态表达式的类型检查是通过多次对同一树针对不同目标进行类型检查来完成的。这个过程被称为**Speculative Attribution**（**SA**），它使得可以使用不同的重载解析目标来检查 lambda 表达式。

尽管这种类型检查方式是一种强大的技术，但它对性能有显著的不利影响。例如，采用这种方法，*n*个重载候选者将在每个重载阶段对相同的参数表达式进行检查，严格、宽松和可变参数分别进行一次，总共*n*3 次。除此之外，还有一个最终的检查阶段。当 lambda 返回一个多态方法调用结果时，会导致属性调用的组合爆炸，这会造成巨大的性能问题。因此，我们确实需要一种不同的多态表达式类型检查方法。

核心思想是确保方法调用为每个多态参数表达式创建自下而上的结构类型，其中包含每个细节，这将在执行重载解析适用性检查之前执行重载解析时需要。

因此，总的来说，性能改进能够通过减少尝试的总次数来实现对给定表达式的属性。

## 提前编译

用于编译器改进的第二个显著变化是提前编译。如果你对这个术语不熟悉，让我们看看 AOT 是什么。你可能知道，任何语言中的程序都需要一个运行时环境来执行。Java 也有自己的运行时环境，被称为**Java 虚拟机**（**JVM**）。我们大多数人使用的典型运行时是一个字节码解释器，也是 JIT 编译器。这个运行时被称为**HotSpot JVM**。

这个 HotSpot JVM 以通过 JIT 编译和自适应优化来提高性能而闻名。到目前为止一切都很好。然而，这并不适用于每个单独的应用程序。如果你有一个非常轻量的程序，比如一个单独的方法调用，那该怎么办呢？在这种情况下，JIT 编译将帮助不大。你需要一些能够更快加载的东西。这就是 AOT 将会帮助你的地方。与 JIT 相反，AOT 不是编译成字节码，而是编译成本地机器代码。运行时然后使用这个本地机器代码来管理对新对象的调用，将其分配到 malloc 中，以及对文件访问的系统调用。这可以提高性能。

# 安全管理器改进

好的，让我们谈谈安全性。如果你不是那些更关心在发布中推出更多功能而不是应用程序安全的人，那么你的表情可能会像**嗯！那是什么？**如果你是其中之一，那么让我们首先了解安全性的重要性，并找到一种方法来考虑在应用程序开发任务中。在今天由 SaaS 主导的世界中，一切都暴露在外部世界。一个决心的个人（委婉地说，一个**恶意黑客**）可以访问你的应用程序，并利用你可能由于疏忽而引入的安全漏洞。我很乐意深入讨论应用程序安全，因为这是我非常感兴趣的另一个领域。然而，应用程序安全超出了本书的范围。我们在这里谈论它的原因是 JPM 团队已经采取了改进现有安全管理器的举措。因此，在谈论安全管理器之前，首先了解安全性的重要性是很重要的。

希望这一行描述可能已经引起了您对安全编程的兴趣。然而，我理解有时候您可能没有足够的时间来实现完整的安全编程模型，因为时间安排很紧。因此，让我们找到一种可以适应您紧张时间表的方法。让我们思考一分钟；有没有办法自动化安全？我们是否可以有一种方法来创建一个蓝图，并要求我们的程序保持在边界内？好吧，你很幸运，Java 确实有一个名为**安全管理器**的功能。它只是一个为应用程序定义安全策略的策略管理器。听起来很令人兴奋，不是吗？但这个策略是什么样的？它包含什么？这两个问题都是合理的提问。这个安全策略基本上规定了具有危险或敏感性质的行为。如果您的应用程序不符合这个策略，那么安全管理器会抛出`SecurityException`。另一方面，您可以让您的应用程序调用这个安全管理器来了解允许的操作。现在，让我们详细了解安全管理器。

在 Web 小程序的情况下，浏览器提供了安全管理器，或者 Java Web Start 插件运行此策略。在许多情况下，除了 Web 小程序之外的应用程序都没有安全管理器，除非这些应用程序实现了一个。毫无疑问地说，如果没有安全管理器和没有附加安全策略，应用程序将无限制地运行。

现在我们对安全管理器有了一些了解，让我们来看看这一领域的性能改进。根据 Java 团队的说法，安装了安全管理器的应用程序可能会导致性能下降 10%至 15%。然而，虽然不可能消除所有性能瓶颈，但缩小这一差距可以有助于改善安全性和性能。

Java 9 团队研究了一些优化措施，包括执行安全策略和评估权限，这将有助于改善使用安全管理器的整体性能。在性能测试阶段，突出显示了即使权限类是线程安全的，它们也会显示为 HotSpot。已经进行了许多改进，以减少线程争用并提高吞吐量。

改进了`java.security.CodeSource`的`hashcode`方法，以使用代码源 URL 的字符串形式，以避免潜在昂贵的 DNS 查找。此外，`java.lang.SecurityManager`的`checkPackageAccess`方法，其中包含包检查算法，已经得到改进。

安全管理器改进中的一些其他显着变化如下：

+   第一个显著的变化是，使用`ConcurrentHashMap`代替`Collections.synchronizedMap`有助于提高`Policy.implie`方法的吞吐量。看看下面的图表，摘自 OpenJDK 网站，突出显示了使用`ConcurrentHashMap`时吞吐量的显著增加：![Security Manager Improvements](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/01_07.jpg)

+   除此之外，在`java.security.SecureClassLoader`中用于维护`CodeSource`内部集合的`HashMap`已被`ConcurrentHashMap`替换。

+   还有一些其他小的改进，比如通过从`getPermissions`方法（`CodeSource`）中删除兼容性代码来提高吞吐量，该方法在身份上进行同步。

+   使用`ConcurrentHashMap`代替在权限检查代码中被同步块包围的`HashMap`可以显著提高线程性能，从而实现了性能的显著增加。

# 图形光栅化器

如果您对 Java 2D 和使用 OpenJDK 感兴趣，您将会欣赏 Java 9 团队所做的努力。Java 9 主要与图形光栅化器有关，这是当前 JDK 的一部分。OpenJDK 使用 Pisces，而 Oracle JDK 使用 Ductus。Oracle 的闭源 Ductus 光栅化器的性能优于 OpenJDK 的 Pisces。

这些图形光栅化器对于抗锯齿渲染非常有用，除了字体。因此，对于图形密集型应用程序，这种光栅化器的性能非常重要。然而，Pisces 在许多方面都表现不佳，其性能问题非常明显。因此，团队决定将其替换为一个名为 Marlin Graphics Renderer 的不同光栅化器。

Marlin 是用 Java 开发的，最重要的是，它是 Pisces 光栅化器的分支。对其进行了各种测试，结果非常令人期待。它的性能始终优于 Pisces。它展示了多线程可伸缩性，甚至在单线程应用程序中也优于闭源的 Ductus 光栅化器。

# 总结

在这节课中，我们已经看到了一些令人兴奋的功能，可以在不费吹灰之力的情况下提高您的应用程序性能。

在下一课中，我们将学习 JShell 和**提前**（**AOT**）编译器。我们还将学习**读取-求值-打印循环**（**REPL**）工具。

# 评估

1.  JLink 是 Java 9 模块系统的 ___________。

1.  两个模块之间的关系是什么，其中一个模块依赖于另一个模块？

1.  可读性关系

1.  可操作性关系

1.  模块化关系

1.  实体关系

1.  判断真假：每次 JVM 启动时，它都会从底层操作系统获取一些内存。

1.  以下哪项执行一些工作来编排锁争用？

1.  固定区域

1.  可读性关系

1.  Java 虚拟机

1.  类数据共享

1.  以下哪项使得可以使用不同的过载解析目标来检查 lambda 表达式？

1.  分层归因

1.  HotSpot JVM

1.  推测性归因

1.  Permgen


# 第二章：提高生产力和加快应用程序的工具

```java
/list), and /-<n> allow re-running of the snippets that have been run previously.
JShell was able to provide the suggestion because the JAR file with the compiled Pair class was on the classpath (set there by default as part of JDK libraries). You can also add to the classpath any other JAR file with the compiled classes you need for your coding. You can do it by setting it at JShell startup by the option --class-path (can be also used with one dash -class-path):
```

![创建 JShell 会话和设置上下文](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/02_07.jpg)

```java
Shift + *Tab* and then *I* as described earlier.
`<name or id>`: This is the name or ID of a specific snippet or method or type or variable (we will see examples later)`-start`: This shows snippets or methods or types or variables loaded at the JShell start (we will see later how to do it)`-all`: This shows snippets or methods or types or variables loaded at the JShell start and entered later during the session
```

默认情况下，在启动时导入了几个常见的包。您可以通过键入`/l -start`或`/l -all`命令来查看它们：

![JShell 命令](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/02_12.jpg)

```java
/l s5command, for example, it will retrieve the snippet with ID s5:
```

![JShell 命令](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/02_13.jpg)

```java
pair), saved the session entries in the file mysession.jsh (in the home directory), and closed the session. Let's look in the file mysession.jsh now:
```

![JShell 命令](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/02_15.jpg)

```java
7:
```

![JShell 命令](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/02_29.jpg)

```java
/o <file> that opens the file as the source input.
```

命令`/en`、`/res`和`/rel`具有重叠的功能：

+   `/en [options]`：这允许查看或更改评估上下文

+   `/res [options]`：这将丢弃所有输入的片段并重新启动会话

+   `/rel[options]`：这将重新加载会话，与命令`/en`的方式相同

有关更多详细信息和可能的选项，请参阅官方 Oracle 文档（[`docs.oracle.com/javase/9/tools/jshell.htm`](http://docs.oracle.com/javase/9/tools/jshell.htm)）。

命令`[/se [setting]`设置配置信息，包括外部编辑器、启动设置和反馈模式。此命令还用于创建具有自定义提示、格式和截断值的自定义反馈模式。如果未输入任何设置，则显示编辑器、启动设置和反馈模式的当前设置。前面提到的文档详细描述了所有可能的设置。

JShell 在 IDE 内部集成后将变得更加有用，这样程序员就可以实时评估表达式，甚至更好的是，它们可以像编译器今天评估语法一样自动评估。

# 提前（AOT）

Java 的一个重要宣称是一次编写，到处运行。这是通过为几乎所有平台创建**Java Runtime Environment**（**JRE**）的实现来实现的，因此通过 Java 编译器（`javac`工具）从源代码生成的字节码可以在安装了 JRE 的任何地方执行，前提是编译器`javac`的版本与 JRE 的版本兼容。

JRE 的最初版本主要是字节码的解释器，性能比一些其他语言和它们的编译器（如 C 和 C++）要慢。然而，随着时间的推移，JRE 得到了大幅改进，现在产生的结果相当不错，与许多其他流行的系统一样。在很大程度上，这要归功于 JIT 动态编译器，它将最常用的方法的字节码转换为本机代码。一旦生成，编译后的方法（特定于平台的机器代码）将根据需要执行，而无需任何解释，从而减少执行时间。

为了利用这种方法，JRE 需要一些时间来找出应用程序中最常用的方法。在这个编程领域工作的人称之为热方法。这种发现期直到达到最佳性能通常被称为 JVM 的预热时间。对于更大更复杂的 Java 应用程序，这个时间更长，对于较小的应用程序可能只有几秒钟。然而，即使在达到最佳性能之后，由于特定输入的原因，应用程序可能会开始利用以前从未使用过的执行路径，并调用尚未编译的方法，从而突然降低性能。当代码尚未编译的部分属于在某些罕见的关键情况下调用的复杂过程时，这可能尤为重要，这正是需要最佳性能的时候。

自然的解决方案是允许程序员决定应用程序的哪些组件必须预编译成本机机器代码--那些经常使用的（从而减少应用程序的预热时间），以及那些不经常使用但必须尽快执行的（以支持关键情况和整体稳定性能）。这就是**Java Enhancement ProposalJEP 295: Ahead-of-Time Compilation**的动机：

JIT 编译器速度快，但 Java 程序可能变得非常庞大，以至于 JIT 完全预热需要很长时间。很少使用的 Java 方法可能根本不会被编译，可能因为重复的解释调用而导致性能下降。

值得注意的是，即使在 JIT 编译器中，也可以通过设置编译阈值来减少预热时间--一个方法被调用多少次后才将其编译成本机代码。默认情况下，这个数字是 1500。因此，如果我们将其设置为小于这个值，预热时间将会更短。可以使用`java`工具的`-XX:CompileThreshold`选项来实现。例如，我们可以将阈值设置为 500，如下所示（其中`Test`是具有`main()`方法的编译过的 Java 类）：

```java
java -XX:CompileThreshold=500 -XX:-TieredCompilation Test
```

添加`-XX:-TieredCompilation`选项以禁用分层编译，因为它默认启用并且不遵守编译阈值。可能的缺点是 500 的阈值可能太低，太多的方法将被编译，从而降低性能并增加预热时间。这个选项的最佳值将因应用程序而异，并且甚至可能取决于相同应用程序的特定数据输入。

## 静态与动态编译

许多高级编程语言，如 C 或 C++，从一开始就使用 AOT 编译。它们也被称为**静态编译**语言。由于 AOT（或静态）编译器不受性能要求的限制（至少不像运行时的解释器，也称为**动态编译器**），它们可以花费时间产生复杂的代码优化。另一方面，静态编译器没有运行时（分析）数据，这在动态类型语言的情况下尤其受限，Java 就是其中之一。由于 Java 中的动态类型能力--向子类型进行下转换，查询对象的类型以及其他类型操作--是面向对象编程的支柱之一（多态原则），Java 的 AOT 编译变得更加受限。Lambda 表达式对静态编译提出了另一个挑战，目前还不支持。

动态编译器的另一个优点是它可以做出假设并相应地优化代码。如果假设被证明是错误的，编译器可以尝试另一个假设，直到达到性能目标。这样的过程可能会减慢应用程序的速度和/或增加预热时间，但从长远来看，可能会导致更好的性能。基于配置文件的优化也可以帮助静态编译器沿着这条道路前进，但与动态编译器相比，它在优化的机会上始终受到限制。

尽管如此，我们不应该感到惊讶，JDK 9 中当前的 AOT 实现是实验性的且受限的，目前仅适用于 64 位 Linux 系统，支持并行或 G1 垃圾回收，并且唯一支持的模块是`java.base`。此外，AOT 编译应该在执行生成的机器代码的相同系统或具有相同配置的系统上执行。然而，尽管如此，JEP 295 指出：

性能测试显示，一些应用程序受益于 AOT 编译的代码，而其他一些明显显示出退化。

值得注意的是，AOT 编译在**Java Micro Edition**（**ME**）中长期得到支持，但在**Java Standard Edition**（**SE**）中 AOT 的更多用例尚待确定，这是实验性 AOT 实现随 JDK 9 发布的原因之一--以便促进社区尝试并反馈实际需求。

## AOT 命令和程序

JDK 9 中的底层 AOT 编译基于 Oracle 项目`Graal`，这是一个在 JDK 8 中引入的开源编译器，旨在改进 Java 动态编译器的性能。 AOT 组不得不对其进行修改，主要是围绕常量处理和优化。他们还添加了概率性分析和特殊的内联策略，从而使 Grall 更适合静态编译。

除了现有的编译工具`javac`之外，JDK 9 安装中还包括一个新的`jaotc`工具。使用`libelf`库生成 AOT 共享库`.so`，这是将来版本中将要删除的依赖项。

要开始 AOT 编译，用户必须启动`jaotc`并指定要编译的类、JAR 文件或模块。还可以将输出库的名称（保存生成的机器代码）作为`jaotc`参数传递。如果未指定，默认输出的名称将为`unnamed.so`。例如，让我们看看 AOT 编译器如何与类`HelloWorld`一起工作：

```java
public class HelloWorld {
   public static void main(String... args) {
       System.out.println("Hello, World!");
   }
}
```

首先，我们将使用`javac`生成字节码并生成`HelloWorld.class`：

```java
javac HelloWorld.java
```

然后，我们将使用文件`HelloWorld.class`中的字节码生成库`libHelloWorld.so`中的机器代码：

```java
jaotc --output libHelloWorld.so HelloWorld.class
```

现在，我们可以使用`java`工具执行生成的库（在与执行`jaotc`的平台规格相同的平台上），并使用`-XX:AOTLibrary`选项：

```java
java -XX:AOTLibrary=./libHelloWorld.so HelloWorld
```

选项`-XX:AOTLibrary`允许我们列出用逗号分隔的多个 AOT 库。

请注意，`java`工具除了一些组件的本机代码外，还需要所有应用程序的字节码。这一事实减少了一些 AOT 爱好者声称的静态编译的所谓优势，即它更好地保护代码免受反编译。如果相同的类或方法已经在 AOT 库中，未来当字节码在运行时不再需要时，这可能是真的。但是，就目前而言，情况并非如此。

要查看是否使用了 AOT 编译的方法，可以添加一个`-XX:+PrintAOT`选项：

```java
java -XX:AOTLibrary=./libHelloWorld.so -XX:+PrintAOT HelloWorld
```

它将允许您在输出中看到加载的行`./libHelloWorld.so` AOT 库。

如果类的源代码已更改但未通过`jaotc`工具推送到 AOT 库中，JVM 将在运行时注意到，因为每个编译类的指纹都与其在 AOT 库中的本机代码一起存储。 JIT 然后将忽略 AOT 库中的代码，而使用字节码。

JDK 9 中的`java`工具支持与 AOT 相关的其他几个标志和选项：

+   `-XX:+/-UseAOT`告诉 JVM 使用或忽略 AOT 编译的文件（默认情况下，设置为使用 AOT）

+   `-XX:+/-UseAOTStrictLoading`打开/关闭 AOT 严格加载；如果打开，它指示 JVM 在任何 AOT 库是在与当前运行时配置不同的平台上生成的时退出

JEP 295 描述了`jaotc`工具的命令格式如下：

```java
jaotc <options> <name or list>
```

`name`是类名或 JAR 文件。`list`是一个以冒号`:`分隔的类名、模块、JAR 文件或包含类文件的目录列表。`options`是以下列表中的一个或多个标志：

+   `--output <file>`：这是输出文件名（默认情况下为`unnamed.so`）

+   `--class-name <class names>`：这是要编译的 Java 类列表

+   --jar <jar files>：这是要编译的 JAR 文件列表

+   `--module <modules>`：这是要编译的 Java 模块列表

+   `--directory <dirs>`：这是您可以搜索要编译的文件的目录列表

+   `--search-path <dirs>`：这是要搜索指定文件的目录列表

+   `--compile-commands <file>`：这是带有编译命令的文件名；这是一个例子：

```java
exclude sun.util.resources..*.TimeZoneNames_.*.getContents\(\)\[\[Ljava/lang/Object;
exclude sun.security.ssl.*
compileOnly java.lang.String.*

```

AOT 目前识别两个编译命令：

+   `exclude`：这将排除指定方法的编译

+   `compileOnly`：这只编译指定的方法

正则表达式用于指定这里提到的类和方法：

+   --compile-for-tiered：这为分层编译生成了分析代码（默认情况下，不会生成分析代码）

+   --compile-with-assertions：这生成带有 Java 断言的代码（默认情况下，不会生成断言代码）

+   --compile-threads <number>：这是要使用的编译线程数（默认情况下，使用较小值 16 和可用 CPU 的数量）

+   --ignore-errors：这忽略在类加载期间抛出的所有异常（默认情况下，如果类加载抛出异常，则在编译时退出）

+   --exit-on-error：这在编译错误时退出（默认情况下，跳过编译失败，而其他方法的编译继续）

+   --info：这打印有关编译阶段的信息

+   --verbose：这打印有关编译阶段的更多细节

+   --debug：这打印更多细节

+   --help：这打印帮助信息

+   --version：这打印版本信息

+   -J<flag>：这将一个标志直接传递给 JVM 运行时系统

正如我们已经提到的，一些应用程序可以通过 AOT 来提高性能，而其他一些可能会变慢。只有测试才能对每个应用程序的 AOT 的有用性问题提供明确的答案。无论如何，改善性能的一种方法是编译和使用`java.base`模块的 AOT 库：

```java
jaotc --output libjava.base.so --module java.base
```

在运行时，AOT 初始化代码在`$JAVA_HOME/lib`目录中查找共享库，或者在`-XX:AOTLibrary`选项列出的库中查找。如果找到共享库，则会被选中并使用。如果找不到共享库，则 AOT 将被关闭。

# 总结

在本课程中，我们描述了两个新工具，可以帮助开发人员更加高效（JShell 工具）并帮助改善 Java 应用程序的性能（`jaotc`工具）。使用它们的示例和步骤将帮助您了解其使用的好处，并在您决定尝试它们的情况下帮助您入门。

在下一课中，我们将讨论如何使用命令行工具以编程方式监视 Java 应用程序。我们还将探讨如何通过多线程来改善应用程序性能，以及在通过监视了解瓶颈后如何调整 JVM 本身。

# 评估

1.  ______ 编译器接受 Java 字节码并生成本机机器代码，以便生成的二进制文件可以在本机上执行。

1.  以下哪个命令丢弃了一个由名称或 ID 引用的片段？

1.  /d <name or id>

1.  /drop <name or id>

1.  /dr <name or id>

1.  /dp <name or id>

1.  判断真假：Shell 是一种著名的 Ahead-of-Time 工具，适用于那些使用 Scala、Ruby 编程的人。它接受用户输入，对其进行评估，并在一段时间后返回结果。

1.  以下哪个命令用于列出您在 JShell 中键入的源代码？

1.  /l [<name or id>|-all|-start]

1.  /m [<name or id>|-all|-start]L

1.  /t [<name or id>|-all|-start]

1.  /v [<name or id>|-all|-start]

1.  以下哪个正则表达式忽略在类加载期间抛出的所有异常？

1.  --exit-on-error

1.  –ignores-errors

1.  --ignore-errors

1.  --exits-on-error


# 第三章：多线程和响应式编程

在本课中，我们将探讨一种通过在多个工作线程之间编程地分割任务来支持应用程序高性能的方法。这就是 4,500 年前建造金字塔的方法，自那时以来，这种方法从未失败。但是，可以参与同一项目的劳动者数量是有限制的。共享资源为工作人员的增加提供了上限，无论资源是以平方英尺和加仑（如金字塔时代的居住区和水）计算，还是以千兆字节和千兆赫（如计算机的内存和处理能力）计算。

生活空间和计算机内存的分配、使用和限制非常相似。但是，我们对人力和 CPU 的处理能力的感知却大不相同。历史学家告诉我们，数千年前的古埃及人同时工作于切割和移动大型石块。即使我们知道这些工人一直在轮换，有些人暂时休息或处理其他事务，然后回来取代完成年度任务的人，其他人死亡或受伤并被新兵取代，我们也不会有任何问题理解他们的意思。

但是，在计算机数据处理的情况下，当我们听到工作线程同时执行时，我们自动假设它们确实并行执行其编程的任务。只有在我们深入了解这样的系统之后，我们才意识到，只有在每个线程由不同的 CPU 执行时，才可能进行这样的并行处理。否则，它们共享相同的处理能力，并且我们认为它们同时工作，只是因为它们使用的时间段非常短——是我们在日常生活中使用的时间单位的一小部分。当线程共享相同的资源时，在计算机科学中，我们说它们是并发执行的。

在本课中，我们将讨论通过使用同时处理数据的工作线程（线程）来增加 Java 应用程序性能的方法。我们将展示如何通过对线程进行池化来有效地使用线程，如何同步同时访问的数据，如何在运行时监视和调整工作线程，以及如何利用响应式编程概念。

但在这之前，让我们重新学习在同一个 Java 进程中创建和运行多个线程的基础知识。

# 先决条件

主要有两种方法可以创建工作线程——通过扩展`java.lang.Thread`类和通过实现`java.lang.Runnable`接口。在扩展`java.lang.Thread`类时，我们不需要实现任何内容：

```java
class MyThread extends Thread {
}
```

我们的`MyThread`类继承了自动生成值的`name`属性和`start（）`方法。我们可以运行此方法并检查`name`：

```java
System.out.print("demo_thread_01(): ");
MyThread t1 = new MyThread();
t1.start();
System.out.println("Thread name=" + t1.getName());
```

如果我们运行此代码，结果将如下所示：

![先决条件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_01.jpg)

如您所见，生成的`name`是`Thread-0`。如果我们在同一个 Java 进程中创建另一个线程，`name`将是`Thread-1`等等。`start（）`方法什么也不做。源代码显示，如果实现了`run（）`方法，它会调用`run（）`方法。

我们可以将任何其他方法添加到`MyThread`类中，如下所示：

```java
class MyThread extends Thread {
    private double result;
    public MyThread(String name){ super(name); }
    public void calculateAverageSqrt(){
        result =  IntStream.rangeClosed(1, 99999)
                           .asDoubleStream()
                           .map(Math::sqrt)
                           .average()
                           .getAsDouble();
    }
    public double getResult(){ return this.result; }
}
```

`calculateAverageSqrt（）`方法计算前 99,999 个整数的平均平方根，并将结果分配给可以随时访问的属性。以下代码演示了我们如何使用它：

```java
System.out.print("demo_thread_02(): ");
MyThread t1 = new MyThread("Thread01");
t1.calculateAverageSqrt();
System.out.println(t1.getName() + ": result=" + t1.getResult());
```

运行此方法将产生以下结果：

![先决条件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_02.jpg)

正如您所期望的，`calculateAverageSqrt（）`方法会阻塞，直到计算完成。它是在主线程中执行的，没有利用多线程。为了做到这一点，我们将功能移动到`run（）`方法中：

```java
class MyThread01 extends Thread {
    private double result;
    public MyThread01(String name){ super(name); }
    public void run(){
        result =  IntStream.rangeClosed(1, 99999)
                           .asDoubleStream()
                           .map(Math::sqrt)
                           .average()
                           .getAsDouble();
    }
    public double getResult(){ return this.result; }
}
```

现在我们再次调用`start（）`方法，就像第一个示例中一样，并期望计算结果：

```java
System.out.print("demo_thread_03(): ");
MyThread01 t1 = new MyThread01("Thread01");
t1.start();
System.out.println(t1.getName() + ": result=" + t1.getResult());
```

然而，这段代码的输出可能会让您感到惊讶：

![先决条件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_03.jpg)

这意味着主线程在新的`t1`线程完成计算之前访问（并打印）了`t1.getResult()`函数。我们可以尝试改变`run()`方法的实现，看看`t1.getResult()`函数是否可以获得部分结果：

```java
public void run() {
    for (int i = 1; i < 100000; i++) {
        double s = Math.sqrt(1\. * i);
        result = result + s;
    }
    result = result / 99999;
}
```

但是，如果我们再次运行`demo_thread_03()`方法，结果仍然是相同的：

![先决条件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_04.jpg)

创建新线程并使其运行需要时间。与此同时，`main`线程立即调用`t1.getResult()`函数，因此还没有得到结果。

为了给新的（子）线程完成计算的时间，我们添加了以下代码：

```java
try {
     t1.join();
 } catch (InterruptedException e) { 
     e.printStackTrace();
 }
```

您已经注意到我们通过 100 毫秒暂停了主线程，并添加了打印当前线程名称，以说明我们所说的`main`线程，这个名称是自动分配给执行`main()`方法的线程。前面代码的输出如下：

![先决条件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_05.jpg)

100 毫秒的延迟足以让`t1`线程完成计算。这是创建多线程计算的两种方式中的第一种。第二种方式是实现`Runnable`接口。如果进行计算的类已经扩展了其他类，并且由于某些原因您不能或不想使用组合，那么可能是唯一的可能方式。`Runnable`接口是一个函数接口（只有一个抽象方法），必须实现`run()`方法：

```java
@FunctionalInterface
public interface Runnable {
    /**
     * When an object implementing interface <code>Runnable</code> is used
     * to create a thread, starting the thread causes the object's
     * <code>run</code> method to be called in that separately executing
     * thread.
     */
    public abstract void run();
```

我们在`MyRunnable`类中实现了这个接口：

```java
class MyRunnable01 implements Runnable {
    private String id;
    private double result;
    public MyRunnable01(int id) {
        this.id = String.valueOf(id);
    }
    public String getId() { return this.id; }
    public double getResult() { return this.result; }
    public void run() {
        result = IntStream.rangeClosed(1, 99999)
                          .asDoubleStream()
                          .map(Math::sqrt)
                          .average()
                          .getAsDouble();
    }
}
```

它具有与之前的`Thread01`类相同的功能，另外我们添加了 id，以便在必要时识别线程，因为`Runnable`接口没有像`Thread`类那样内置的`getName()`方法。

同样，如果我们执行这个类而不暂停`main`线程，就像这样：

```java
System.out.print("demo_runnable_01(): ");
MyRunnable01 myRunnable = new MyRunnable01(1);
Thread t1 = new Thread(myRunnable);
t1.start();
System.out.println("Worker " + myRunnable.getId() 
           + ": result=" + myRunnable.getResult());
```

输出将如下所示：

![先决条件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_06.jpg)

现在我们将添加暂停如下：

```java
System.out.print("demo_runnable_02(): ");
MyRunnable01 myRunnable = new MyRunnable01(1);
Thread t1 = new Thread(myRunnable);
t1.start();
try {
    t1.join();
} catch (InterruptedException e) { 
    e.printStackTrace();
}
System.out.println("Worker " + myRunnable.getId() 
           + ": result=" + myRunnable.getResult());
```

结果与`Thread01`类产生的结果完全相同：

![先决条件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/3_07.jpg)

所有先前的示例都将生成的结果存储在类属性中。但情况并非总是如此。通常，工作线程要么将其值传递给另一个线程，要么将其存储在数据库或其他外部位置。在这种情况下，可以利用`Runnable`接口作为函数接口，并将必要的处理函数作为 lambda 表达式传递到新线程中：

```java
System.out.print("demo_lambda_01(): ");
String id = "1";
Thread t1 = 
    new Thread(() -> IntStream.rangeClosed(1, 99999)
         .asDoubleStream().map(Math::sqrt).average()
         .ifPresent(d -> System.out.println("Worker " 
                            + id + ": result=" + d)));
t1.start();
try {
    t1.join();
} catch (InterruptedException e) { 
    e.printStackTrace();
}
```

结果将会完全相同，如下所示：

![先决条件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_08.jpg)

根据首选的样式，您可以重新排列代码，并将 lambda 表达式隔离在一个变量中，如下所示：

```java
Runnable r = () -> IntStream.rangeClosed(1, 99999)
       .asDoubleStream().map(Math::sqrt).average()
      .ifPresent(d -> System.out.println("Worker " 
                           + id + ": result=" + d));
Thread t1 = new Thread(r);
```

或者，您可以将 lambda 表达式放在一个单独的方法中：

```java
void calculateAverage(String id) {
    IntStream.rangeClosed(1, 99999)
        .asDoubleStream().map(Math::sqrt).average()
        .ifPresent(d -> System.out.println("Worker " 
                            + id + ": result=" + d));
}
void demo_lambda_03() {
    System.out.print("demo_lambda_03(): ");
    Thread t1 = new Thread(() -> calculateAverage("1"));
    ...
}
```

结果将是相同的，如下所示：

![先决条件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_09.jpg)

有了对线程创建的基本理解，我们现在可以回到讨论如何使用多线程来构建高性能应用程序。换句话说，在我们了解了每个工作线程所需的能力和资源之后，我们现在可以讨论如何为像吉萨金字塔这样的大型项目引入许多工作线程的后勤问题。

编写管理工作线程的生命周期和它们对共享资源的访问的代码是可能的，但在一个应用程序到另一个应用程序中几乎是相同的。这就是为什么在 Java 的几个版本发布之后，线程管理的管道成为标准 JDK 库的一部分，作为`java.util.concurrent`包。这个包有丰富的接口和类，支持多线程和并发。我们将在后续章节中讨论如何使用大部分这些功能，同时讨论线程池、线程监视、线程同步和相关主题。

# 线程池

在本节中，我们将研究`java.util.concurrent`包中提供的`Executor`接口及其实现。它们封装了线程管理，并最大程度地减少了应用程序开发人员在编写与线程生命周期相关的代码上所花费的时间。

`Executor`接口在`java.util.concurrent`包中定义了三个。第一个是基本的`Executor`接口，其中只有一个`void execute(Runnable r)`方法。它基本上替代了以下内容：

```java
Runnable r = ...;
(new Thread(r)).start()
```

但是，我们也可以通过从池中获取线程来避免创建新线程。

第二个是`ExecutorService`接口，它扩展了`Executor`并添加了以下管理工作线程和执行器本身生命周期的方法组：

+   `submit()`: 将对象的执行放入接口`Runnable`或接口`Callable`的队列中（允许工作线程返回值）；返回`Future`接口的对象，可用于访问`Callable`返回的值并管理工作线程的状态

+   `invokeAll()`: 将一组接口`Callable`对象的执行放入队列中，当所有工作线程都完成时返回`Future`对象的列表（还有一个带有超时的重载`invokeAll()`方法）

+   `invokeAny()`: 将一组接口`Callable`对象的执行放入队列中；返回任何已完成的工作线程的一个`Future`对象（还有一个带有超时的重载`invokeAny()`方法）

管理工作线程状态和服务本身的方法：

+   `shutdown()`: 防止新的工作线程被提交到服务

+   `isShutdown()`: 检查执行器是否已启动关闭

+   `awaitTermination(long timeout, TimeUnit timeUnit)`: 在关闭请求后等待，直到所有工作线程完成执行，或超时发生，或当前线程被中断，以先发生的为准

+   `isTerminated()`: 在关闭被启动后检查所有工作线程是否已完成；除非首先调用了`shutdown()`或`shutdownNow()`，否则它永远不会返回`true`

+   `shutdownNow()`: 中断每个未完成的工作线程；工作线程应该定期检查自己的状态（例如使用`Thread.currentThread().isInterrupted()`），并在自己上优雅地关闭；否则，即使调用了`shutdownNow()`，它也会继续运行

第三个接口是`ScheduledExecutorService`，它扩展了`ExecutorService`并添加了允许调度工作线程执行（一次性和周期性）的方法。

可以使用`java.util.concurrent.ThreadPoolExecutor`或`java.util.concurrent.ScheduledThreadPoolExecutor`类创建基于池的`ExecutorService`实现。还有一个`java.util.concurrent.Executors`工厂类，涵盖了大部分实际情况。因此，在编写自定义代码创建工作线程池之前，我们强烈建议查看`java.util.concurrent.Executors`类的以下工厂方法：

+   `newSingleThreadExecutor()`: 创建一个按顺序执行工作线程的`ExecutorService`（池）实例

+   `newFixedThreadPool()`: 创建一个重用固定数量的工作线程的线程池；如果在所有工作线程仍在执行时提交了新任务，它将被放入队列，直到有工作线程可用

+   `newCachedThreadPool()`: 创建一个线程池，根据需要添加新线程，除非之前已创建了空闲线程；空闲了六十秒的线程将从缓存中移除

+   `newScheduledThreadPool()`: 创建一个固定大小的线程池，可以安排命令在给定延迟后运行，或定期执行

+   `newSingleThreadScheduledExecutor()`: 这将创建一个可以在给定延迟后调度命令运行或定期执行的单线程执行程序。

+   `newWorkStealingThreadPool()`: 这将创建一个使用与`ForkJoinPool`相同的工作窃取机制的线程池，对于工作线程生成其他线程的情况特别有用，比如递归算法。

每个方法都有一个重载版本，允许传入一个`ThreadFactory`，在需要时用于创建新线程。让我们看看在代码示例中如何运行。

首先，我们创建一个实现`Runnable`接口的`MyRunnable02`类——我们未来的工作线程：

```java
class MyRunnable02 implements Runnable {
    private String id;
    public MyRunnable02(int id) {
        this.id = String.valueOf(id);
    }
    public String getId(){ return this.id; }
    public void run() {
        double result = IntStream.rangeClosed(1, 100)
           .flatMap(i -> IntStream.rangeClosed(1, 99999))
           .takeWhile(i -> 
                 !Thread.currentThread().isInterrupted())
           .asDoubleStream()
           .map(Math::sqrt)
           .average()
           .getAsDouble();
        if(Thread.currentThread().isInterrupted()){
            System.out.println(" Worker " + getId() 
                       + ": result=ignored: " + result);
        } else {
            System.out.println(" Worker " + getId() 
                                + ": result=" + result);
        }
}
```

请注意，这种实现与之前的示例有一个重要的区别——`takeWhile(i -> !Thread.currentThread().isInterrupted())`操作允许流继续流动，只要线程工作状态未被设置为中断，这在调用`shutdownNow()`方法时会发生。一旦`takeWhile()`的谓词返回`false`（工作线程被中断），线程就会停止产生结果（只是忽略当前的`result`值）。在实际系统中，这相当于跳过将`result`值存储在数据库中，例如。

值得注意的是，在前面的代码中使用`interrupted()`状态方法来检查线程状态可能会导致不一致的结果。由于`interrupted()`方法返回正确的状态值，然后清除线程状态，因此对该方法的第二次调用（或在调用`interrupted()`方法后调用`isInterrupted()`方法）总是返回`false`。

尽管在这段代码中不是这种情况，但我们想在这里提到一些开发人员在实现工作线程的`try/catch`块时常犯的错误。例如，如果工作线程需要暂停并等待中断信号，代码通常如下所示：

```java
try {
    Thread.currentThread().wait();
} catch (InterruptedException e) {}
// Do what has to be done
```

```java
The better implementation is as follows:
```

```java
try {
    Thread.currentThread().wait();
} catch (InterruptedException e) {
    Thread.currentThread().interrupt();
}
// Do what has to be done
```

```java
join() method, we did not need to do that because that was the main code (the highest level code) that had to be paused.
```

现在我们可以展示如何使用`ExecutiveService`池的缓存池实现来执行之前的`MyRunnable02`类（其他类型的线程池使用方式类似）。首先，我们创建池，提交三个`MyRunnable02`类的实例进行执行，然后关闭池：

```java
ExecutorService pool = Executors.newCachedThreadPool();
IntStream.rangeClosed(1, 3).
       forEach(i -> pool.execute(new MyRunnable02(i)));
System.out.println("Before shutdown: isShutdown()=" 
          + pool.isShutdown() + ", isTerminated()=" 
                                + pool.isTerminated());
pool.shutdown(); // New threads cannot be submitted
System.out.println("After  shutdown: isShutdown()=" 
          + pool.isShutdown() + ", isTerminated()=" 
                                + pool.isTerminated());
```

如果运行这些代码，将会看到以下输出：

![线程池](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_10.jpg)

这里没有什么意外！在调用`shutdown()`方法之前，`isShutdown()`方法返回`false`值，之后返回`true`值。`isTerminated()`方法返回`false`值，因为没有任何工作线程已经完成。

通过在`shutdown()`方法后添加以下代码来测试`shutdown()`方法：

```java
try {
    pool.execute(new MyRunnable02(100));
} catch(RejectedExecutionException ex){
    System.err.println("Cannot add another worker-thread to the service queue:\n" + ex.getMessage());
}
```

现在输出将包含以下消息（如果截图对于此页面来说太大或者在适应时不可读）。

```java
Cannot add another worker-thread to the service queue:
Task com.packt.java9hp.ch09_threads.MyRunnable02@6f7fd0e6 
    rejected from java.util.concurrent.ThreadPoolExecutor
    [Shutting down, pool size = 3, active threads = 3, 
    queued tasks = 0, completed tasks = 0]
```

预期的是，在调用`shutdown()`方法后，将无法再向线程池中添加更多的工作线程。

现在让我们看看在启动关闭之后我们能做些什么：

```java
long timeout = 100;
TimeUnit timeUnit = TimeUnit.MILLISECONDS;
System.out.println("Waiting for all threads completion " 
                     + timeout + " " + timeUnit + "...");
// Blocks until timeout or all threads complete execution
boolean isTerminated = 
                pool.awaitTermination(timeout, timeUnit);
System.out.println("isTerminated()=" + isTerminated);
if (!isTerminated) {
    System.out.println("Calling shutdownNow()...");
    List<Runnable> list = pool.shutdownNow(); 
    printRunningThreadIds(list);
    System.out.println("Waiting for threads completion " 
                     + timeout + " " + timeUnit + "...");
    isTerminated = 
                pool.awaitTermination(timeout, timeUnit);
    if (!isTerminated){
        System.out.println("Some threads are running...");
    }
    System.out.println("Exiting.");
}
```

`printRunningThreadIds()`方法如下所示：

```java
void printRunningThreadIds(List<Runnable> l){
    String list = l.stream()
            .map(r -> (MyRunnable02)r)
            .map(mr -> mr.getId())
            .collect(Collectors.joining(","));
    System.out.println(l.size() + " thread"
       + (l.size() == 1 ? " is" : "s are") + " running"
            + (l.size() > 0 ? ": " + list : "") + ".");
}
```

前面代码的输出将如下所示：

![线程池](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_11.jpg)

这意味着每个工作线程完成计算所需的时间为 100 毫秒。（请注意，如果您尝试在您的计算机上重现这些数据，由于性能差异，结果可能会略有不同，因此您需要调整超时时间。）

当我们将等待时间减少到 75 毫秒时，输出如下：

![线程池](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_12.jpg)

在我们的计算机上，75 毫秒不足以让所有线程完成，因此它们被`shutdownNow()`中断，并且它们的部分结果被忽略。

现在让我们移除`MyRunnable01`类中对中断状态的检查：

```java
class MyRunnable02 implements Runnable {
    private String id;
    public MyRunnable02(int id) {
        this.id = String.valueOf(id);
    }
    public String getId(){ return this.id; }
    public void run() {
        double result = IntStream.rangeClosed(1, 100)
           .flatMap(i -> IntStream.rangeClosed(1, 99999))
           .asDoubleStream()
           .map(Math::sqrt)
           .average()
           .getAsDouble();
        System.out.println(" Worker " + getId() 
                                + ": result=" + result);
}
```

没有这个检查，即使我们将超时时间减少到 1 毫秒，结果也将如下所示：

![线程池](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_13.jpg)

这是因为工作线程从未注意到有人试图中断它们并完成了它们分配的计算。这最后的测试演示了在工作线程中观察中断状态的重要性，以避免许多可能的问题，即数据损坏和内存泄漏。

演示的缓存池在工作线程执行短任务且其数量不会过多增长时运行良好，不会出现问题。如果您需要更多地控制任何时候运行的工作线程的最大数量，请使用固定大小的线程池。我们将在本课程的以下部分讨论如何选择池的大小。

单线程池非常适合按特定顺序执行任务的情况，或者当每个任务需要的资源太多，无法与其他任务并行执行时。使用单线程执行的另一个情况是对修改相同数据的工作线程，但数据无法以其他方式受到并行访问的保护。线程同步也将在本课程的以下部分中更详细地讨论。

在我们的示例代码中，到目前为止，我们只包括了`Executor`接口的`execute()`方法。在接下来的部分中，我们将演示`ExecutorService`池的其他方法，同时讨论线程监控。

在本节的最后一条备注。工作线程不需要是同一个类的对象。它们可以代表完全不同的功能，仍然可以由一个池管理。

# 监控线程

有两种监控线程的方法，即通过编程和使用外部工具。我们已经看到了如何检查工作计算的结果。让我们重新访问一下那段代码。我们还将稍微修改我们的工作实现：

```java
class MyRunnable03 implements Runnable {
  private String name;
  private double result;
  public String getName(){ return this.name; }
  public double getResult() { return this.result; }
  public void run() {
    this.name = Thread.currentThread().getName();
    double result = IntStream.rangeClosed(1, 100)
      .flatMap(i -> IntStream.rangeClosed(1, 99999))
      .takeWhile(i -> !Thread.currentThread().isInterrupted())
      .asDoubleStream().map(Math::sqrt).average().getAsDouble();
    if(!Thread.currentThread().isInterrupted()){
      this.result = result;
    }
  }
}
```

对于工作线程的标识，我们现在使用在执行时自动分配的线程名称，而不是自定义 ID（这就是为什么我们在`run()`方法中分配`name`属性，在线程获取其名称时调用该方法）。新的`MyRunnable03`类可以像这样使用：

```java
void demo_CheckResults() {
    ExecutorService pool = Executors.newCachedThreadPool();
    MyRunnable03 r1 = new MyRunnable03();
    MyRunnable03 r2 = new MyRunnable03();
    pool.execute(r1);
    pool.execute(r2);
    try {
        t1.join();
    } catch (InterruptedException e) { 
        e.printStackTrace();
    }
    System.out.println("Worker " + r1.getName() + ": result=" + r1.getResult());
    System.out.println("Worker " + r2.getName() + ": result=" + r2.getResult());
    shutdown(pool);
}
```

`shutdown()`方法包含以下代码：

```java
void shutdown(ExecutorService pool) {
    pool.shutdown();
    try {
        if(!pool.awaitTermination(1, TimeUnit.SECONDS)){
            pool.shutdownNow();
        }
    } catch (InterruptedException ie) {}
}
```

如果我们运行上述代码，输出将如下所示：

![监控线程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_14.jpg)

如果您的计算机上的结果不同，请尝试增加`sleepMs()`方法的输入值。

获取有关应用程序工作线程的信息的另一种方法是使用`Future`接口。我们可以使用`ExecutorService`池的`submit()`方法访问此接口，而不是`execute()`、`invokeAll()`或`invokeAny()`方法。以下代码显示了如何使用`submit()`方法：

```java
ExecutorService pool = Executors.newCachedThreadPool();
Future f1 = pool.submit(new MyRunnable03());
Future f2 = pool.submit(new MyRunnable03());
printFuture(f1, 1);
printFuture(f2, 2);
shutdown(pool);
```

`printFuture()`方法的实现如下：

```java
void printFuture(Future future, int id) {
    System.out.println("printFuture():");
    while (!future.isCancelled() && !future.isDone()){
        System.out.println("    Waiting for worker " 
                                + id + " to complete...");
        sleepMs(10);
    }
    System.out.println("    Done...");
}
```

`sleepMs()`方法包含以下代码：

```java
void sleepMs(int sleepMs) {
    try {
        TimeUnit.MILLISECONDS.sleep(sleepMs);
    } catch (InterruptedException e) {}
}
```

我们更喜欢这种实现而不是传统的`Thread.sleep()`，因为它明确指定了使用的时间单位。

如果我们执行前面的代码，结果将类似于以下内容：

![监控线程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_15.jpg)

`printFuture()`方法已经阻塞了主线程的执行，直到第一个线程完成。与此同时，第二个线程也已经完成。如果我们在`shutdown()`方法之后调用`printFuture()`方法，那么两个线程在那时已经完成了，因为我们设置了 1 秒的等待时间（参见`pool.awaitTermination()`方法），这足够让它们完成工作。

![监控线程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_16.jpg)

如果您认为这不是从线程监视的角度来看的太多信息，`java.util.concurrent`包通过`Callable`接口提供了更多功能。这是一个允许通过`Future`对象返回任何对象（包含工作线程计算结果的结果）的功能接口，使用`ExecutiveService`方法--`submit()`、`invokeAll()`和`invokeAny()`。例如，我们可以创建一个包含工作线程结果的类：

```java
class Result {
    private double result;
    private String workerName;
    public Result(String workerName, double result) {
        this.result = result;
        this.workerName = workerName;
    }
    public String getWorkerName() { return workerName; }
    public double getResult() { return result;}
}
```

我们还包括了工作线程的名称，以便监视生成的结果。实现`Callable`接口的类可能如下所示：

```java
class MyCallable01<T> implements Callable {
  public Result call() {
    double result = IntStream.rangeClosed(1, 100)
       .flatMap(i -> IntStream.rangeClosed(1, 99999))
       .takeWhile(i -> !Thread.currentThread().isInterrupted())
       .asDoubleStream().map(Math::sqrt).average().getAsDouble();

    String workerName = Thread.currentThread().getName();
    if(Thread.currentThread().isInterrupted()){
        return new Result(workerName, 0);
    } else {
        return new Result(workerName, result);
    }
  }
}
```

以下是使用`MyCallable01`类的代码：

```java
ExecutorService pool = Executors.newCachedThreadPool();
Future f1 = pool.submit(new MyCallable01<Result>());
Future f2 = pool.submit(new MyCallable01<Result>());
printResult(f1, 1);
printResult(f2, 2);
shutdown(pool);
```

`printResult()` 方法包含以下代码：

```java
void printResult(Future<Result> future, int id) {
    System.out.println("printResult():");
    while (!future.isCancelled() && !future.isDone()){
        System.out.println("    Waiting for worker " 
                              + id + " to complete...");
        sleepMs(10);
    }
    try {
        Result result = future.get(1, TimeUnit.SECONDS);
        System.out.println("    Worker " 
                + result.getWorkerName() + ": result = " 
                                   + result.getResult());
    } catch (Exception ex) {
        ex.printStackTrace();
    }
}
```

此代码的输出可能如下所示：

![监视线程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_17.jpg)

先前的输出显示，与之前的示例一样，`printResult()`方法会等待工作线程中的第一个完成，因此第二个线程成功在同一时间完成其工作。正如您所看到的，使用`Callable`的优点是，我们可以从`Future`对象中检索实际结果，如果需要的话。

`invokeAll()`和`invokeAny()`方法的使用看起来很相似：

```java
ExecutorService pool = Executors.newCachedThreadPool();
try {
    List<Callable<Result>> callables = 
              List.of(new MyCallable01<Result>(), 
                           new MyCallable01<Result>());
    List<Future<Result>> futures = 
                             pool.invokeAll(callables);
    printResults(futures);
} catch (InterruptedException e) {
    e.printStackTrace();
}
shutdown(pool);
```

`printResults()`方法使用了您已经了解的`printResult()`方法：

```java
void printResults(List<Future<Result>> futures) {
    System.out.println("printResults():");
    int i = 1;
    for (Future<Result> future : futures) {
        printResult(future, i++);
    }
}
```

如果我们运行上述代码，输出将如下所示：

![监视线程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_18.jpg)

如您所见，不再等待工作线程完成工作。这是因为`invokeAll()`方法在所有作业完成后返回`Future`对象的集合。

`invokeAny()`方法的行为类似。如果我们运行以下代码：

```java
System.out.println("demo_InvokeAny():");
ExecutorService pool = Executors.newCachedThreadPool();
try {
    List<Callable<Result>> callables = 
                   List.of(new MyCallable01<Result>(), 
                            new MyCallable01<Result>());
    Result result = pool.invokeAny(callables);
    System.out.println("    Worker " 
                        + result.getWorkerName()
                  + ": result = " + result.getResult());
} catch (InterruptedException | ExecutionException e) {
    e.printStackTrace();
}
shutdown(pool);
```

以下将是输出：

![监视线程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_19.jpg)

这些是以编程方式监视线程的基本技术，但可以轻松地扩展我们的示例，以涵盖更复杂的情况，以满足特定应用程序的需求。在第 5 课中，*利用新的 API 改进您的代码*，我们还将讨论另一种以编程方式监视工作线程的方法，即 JDK 8 中引入并在 JDK 9 中扩展的`java.util.concurrent.CompletableFuture`类。

如果需要，可以使用`java.lang.Thread`类获取有关 JVM 进程中的应用程序工作线程以及所有其他线程的信息：

```java
void printAllThreads() {
    System.out.println("printAllThreads():");
    Map<Thread, StackTraceElement[]> map = Thread.getAllStackTraces();
    for(Thread t: map.keySet()){
        System.out.println("    " + t);
    }
```

现在，让我们按如下方式调用此方法：

```java
void demo_CheckResults() {
    ExecutorService pool = Executors.newCachedThreadPool();
    MyRunnable03 r1 = new MyRunnable03();
    MyRunnable03 r2 = new MyRunnable03();
    pool.execute(r1);
    pool.execute(r2);
    sleepMs(1000);
    printAllThreads();
    shutdown(pool);
}
```

结果如下所示：

![监视线程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_20.jpg)

我们利用了`Thread`类的`toString()`方法，该方法仅打印线程名称、优先级和线程所属的线程组。我们可以在名称为`pool-1-thread-1`和`pool-1-thread-2`的列表中明确看到我们创建的两个应用程序线程（除了`main`线程）。但是，如果我们在调用`shutdown()`方法后调用`printAllThreads()`方法，输出将如下所示：

![监视线程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_21.jpg)

我们不再在列表中看到`pool-1-thread-1`和`pool-1-thread-2`线程，因为`ExecutorService`池已关闭。

我们可以轻松地添加从相同映射中提取的堆栈跟踪信息：

```java
void printAllThreads() {
    System.out.println("printAllThreads():");
    Map<Thread, StackTraceElement[]> map 
                               = Thread.getAllStackTraces();
    for(Thread t: map.keySet()){
        System.out.println("   " + t);
        for(StackTraceElement ste: map.get(t)){
            System.out.println("        " + ste);
        }
    }
}
```

然而，这将占用书页太多空间。在第 5 课中，*利用新的 API 改进您的代码*，我们将介绍随 JDK 9 一起提供的新的 Java 功能，并讨论通过`java.lang.StackWalker`类更好地访问堆栈跟踪的方法。

`Thread`类对象还有其他几个方法，提供有关线程的信息，如下所示：

+   `dumpStack()`: 这将堆栈跟踪打印到标准错误流

+   `enumerate(Thread[] arr)`: 这将当前线程的线程组中的活动线程及其子组复制到指定的数组`arr`中

+   `getId()`: 这提供了线程的 ID

+   `getState()`：这读取线程的状态；`enum Thread.State`的可能值可以是以下之一：

+   `NEW`：这是尚未启动的线程

+   `RUNNABLE`：这是当前正在执行的线程

+   `BLOCKED`：这是正在等待监视器锁释放的线程

+   `WAITING`：这是正在等待中断信号的线程

+   `TIMED_WAITING`：这是等待中断信号直到指定等待时间的线程

+   `TERMINATED`：这是已退出的线程

+   `holdsLock(Object obj)`：这表示线程是否持有指定对象的监视器锁

+   `interrupted()`或`isInterrupted()`：这表示线程是否已被中断（收到中断信号，意味着中断标志被设置为`true`）

+   `isAlive()`：这表示线程是否存活

+   `isDaemon()`：这表示线程是否为守护线程。

`java.lang.management`包为监视线程提供了类似的功能。例如，让我们运行这段代码片段：

```java
void printThreadsInfo() {
    System.out.println("printThreadsInfo():");
    ThreadMXBean threadBean = 
                      ManagementFactory.getThreadMXBean();
    long ids[] = threadBean.getAllThreadIds();
    Arrays.sort(ids);
    ThreadInfo[] tis = threadBean.getThreadInfo(ids, 0);
    for (ThreadInfo ti : tis) {
        if (ti == null) continue;
        System.out.println("    Id=" + ti.getThreadId() 
                       + ", state=" + ti.getThreadState() 
                          + ", name=" + ti.getThreadName());
    }
}
```

为了更好地呈现，我们利用了列出的线程 ID，并且如您之前所见，已按 ID 对输出进行了排序。如果我们在`shutdown()`方法之前调用`printThreadsInfo()`方法，输出将如下所示：

![监控线程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_22.jpg)

但是，如果我们在`shutdown()`方法之后调用`printThreadsInfo()`方法，输出将不再包括我们的工作线程，就像使用`Thread`类 API 的情况一样：

![监控线程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_23.jpg)

`java.lang.management.ThreadMXBean`接口提供了关于线程的许多其他有用数据。您可以参考 Oracle 网站上关于此接口的官方 API，了解更多信息，请查看此链接：[`docs.oracle.com/javase/8/docs/api/index.html?java/lang/management/ThreadMXBean.html`](https://docs.oracle.com/javase/8/docs/api/index.html?java/lang/management/ThreadMXBean.html)。

在前面提到的线程列表中，您可能已经注意到`Monitor Ctrl-Break`线程。此线程提供了另一种监视 JVM 进程中线程的方法。在 Windows 上按下*Ctrl*和*Break*键会导致 JVM 将线程转储打印到应用程序的标准输出。在 Oracle Solaris 或 Linux 操作系统上，*Ctrl*键和反斜杠*\*的组合具有相同的效果。这将我们带到了用于线程监视的外部工具。

如果您无法访问源代码或更喜欢使用外部工具进行线程监视，则 JDK 安装中提供了几种诊断实用程序。在以下列表中，我们仅提到允许线程监视的工具，并仅描述所列工具的此功能（尽管它们还具有其他广泛的功能）：

+   `jcmd`实用程序使用 JVM 进程 ID 或主类的名称向同一台机器上的 JVM 发送诊断命令请求：`jcmd <process id/main class> <command> [options]`，其中`Thread.print`选项打印进程中所有线程的堆栈跟踪。

+   JConsole 监控工具使用 JVM 中的内置 JMX 工具来提供有关运行应用程序的性能和资源消耗的信息。它有一个线程选项卡窗格，显示随时间变化的线程使用情况，当前活动线程数，自 JVM 启动以来的最高活动线程数。可以选择线程及其名称、状态和堆栈跟踪，以及对于阻塞线程，线程正在等待获取的同步器以及拥有锁的线程。使用**死锁检测**按钮来识别死锁。运行该工具的命令是`jconsole <process id>`或（对于远程应用程序）`jconsole <hostname>:<port>`，其中`port`是使用启用 JMX 代理的 JVM 启动命令指定的端口号。

+   `jdb`实用程序是一个示例命令行调试器。它可以附加到 JVM 进程并允许您检查线程。

+   `jstack`命令行实用程序可以附加到 JVM 进程并打印所有线程的堆栈跟踪，包括 JVM 内部线程，还可以选择打印本地堆栈帧。它还允许您检测死锁。

+   **Java Flight Recorder**（**JFR**）提供有关 Java 进程的信息，包括等待锁的线程，垃圾收集等。它还允许获取线程转储，这类似于使用`Thread.print`诊断命令或使用 jstack 工具生成的线程转储。如果满足条件，可以设置**Java Mission Control**（**JMC**）来转储飞行记录。JMC UI 包含有关线程、锁争用和其他延迟的信息。尽管 JFR 是商业功能，但对于开发人员的台式机/笔记本电脑以及测试、开发和生产环境中的评估目的，它是免费的。

### 注意

您可以在官方 Oracle 文档[`docs.oracle.com/javase/9/troubleshoot/diagnostic-tools.htm`](https://docs.oracle.com/javase/9/troubleshoot/diagnostic-tools.htm)中找到有关这些和其他诊断工具的更多详细信息。

# 线程池执行器的大小

在我们的示例中，我们使用了一个缓存线程池，根据需要创建新线程，或者如果可用，重用已经使用过的线程，但是完成了工作并返回到池中以便新的分配。我们不担心创建太多线程，因为我们的演示应用程序最多只有两个工作线程，并且它们的生命周期非常短。

但是，在应用程序没有固定的工作线程限制或者没有好的方法来预测线程可能占用多少内存或执行多长时间的情况下，设置工作线程计数的上限可以防止应用程序性能意外下降，内存耗尽或工作线程使用的其他任何资源枯竭。如果线程行为非常不可预测，单个线程池可能是唯一的解决方案，并且可以选择使用自定义线程池执行器（稍后将对此最后一个选项进行解释）。但在大多数情况下，固定大小的线程池执行器是应用程序需求和代码复杂性之间的一个很好的实际折衷。根据具体要求，这样的执行器可能是以下三种类型之一：

+   一个直接的、固定大小的`ExecutorService.newFixedThreadPool(int nThreads)`池，不会超出指定的大小，也不会采用其他方式

+   `ExecutorService.newScheduledThreadPool(int nThreads)` 提供了几个允许调度不同线程组的线程池，具有不同的延迟或执行周期

+   `ExecutorService.newWorkStealingPool(int parallelism)`，它适应于指定数量的 CPU，您可以将其设置为高于或低于计算机上实际 CPU 数量

在任何上述池中设置固定大小过低可能会剥夺应用程序有效利用可用资源的机会。因此，在选择池大小之前，建议花一些时间对其进行监视和调整 JVM（请参阅本课程的某个部分中如何执行此操作），以便识别应用程序行为的特殊性。实际上，部署-监视-调整-调整的周期必须在整个应用程序生命周期中重复进行，以适应并利用代码或执行环境中发生的变化。

您考虑的第一个参数是系统中的 CPU 数量，因此线程池大小至少可以与 CPU 数量一样大。然后，您可以监视应用程序，查看每个线程使用 CPU 的时间以及使用其他资源（如 I/O 操作）的时间。如果未使用 CPU 的时间与线程的总执行时间相当，那么可以通过**未使用 CPU 的时间/总执行时间**来增加池大小。但前提是另一个资源（磁盘或数据库）不是线程之间争用的主题。如果是后者的情况，那么可以使用该资源而不是 CPU 作为界定因素。

假设您的应用程序的工作线程不是太大或执行时间不太长，并且属于典型工作线程的主流人口，可以通过增加期望响应时间和线程使用 CPU 或其他最具争议资源的时间的比率（四舍五入）来增加池大小。这意味着，对于相同的期望响应时间，线程使用 CPU 或其他同时访问的资源越少，池大小就应该越大。如果具有改善并发访问能力的争议资源（如数据库中的连接池），请首先考虑利用该功能。

如果在不同情况下运行的同时所需的线程数量在运行时发生变化，可以使池大小动态化，并创建一个新大小的池（在所有线程完成后关闭旧池）。在添加或删除可用资源后，可能还需要重新计算新池的大小。例如，您可以使用`Runtime.getRuntime().availableProcessors()`根据当前可用 CPU 的数量来以编程方式调整池大小。

如果 JDK 提供的现成线程池执行器实现都不适合特定应用程序的需求，在从头开始编写线程管理代码之前，可以尝试首先使用`java.util.concurrent.ThreadPoolExecutor`类。它有几个重载的构造函数。

为了让您了解其功能，这是具有最多选项的构造函数：

```java
ThreadPoolExecutor (int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue, ThreadFactory threadFactory, RejectedExecutionHandler handler)
```

前面提到的参数是（引用自 JavaDoc）：

+   `corePoolSize`: 这是保留在池中的线程数，即使它们处于空闲状态，除非设置了`allowCoreThreadTimeOut`

+   `maximumPoolSize`: 这是允许在池中的最大线程数

+   `keepAliveTime`: 当线程数大于核心数时，这是多余的空闲线程在终止之前等待新任务的最长时间

+   `unit`: 这是`keepAliveTime`参数的时间单位

+   `workQueue`: 这是在执行任务之前用于保存任务的队列，该队列将仅保存由`execute`方法提交的`Runnable`任务

+   `threadFactory`: 这是执行器创建新线程时要使用的工厂

+   `handler`: 这是在执行受阻时要使用的处理程序，因为已达到线程边界和队列容量

除了`workQueue`参数之外，以前的构造函数参数也可以在创建`ThreadPoolExecutor`对象后通过相应的 setter 进行设置，从而在动态调整现有池特性时提供更大的灵活性。

# 线程同步

我们已经收集了足够的人员和资源，如食物、水和工具，用于金字塔的建造。我们将人员分成团队，并为每个团队分配了一个任务。一个（池）人住在附近的村庄，处于待命状态，随时准备取代在任务中生病或受伤的人。我们调整了劳动力数量，以便只有少数人会在村庄中闲置。我们通过工作-休息周期轮换团队，以保持项目以最大速度进行。我们监控了整个过程，并调整了团队数量和他们所需的供应流量，以确保没有明显的延迟，并且整个项目中有稳定的可测量的进展。然而，整体上有许多活动部分和各种大小的意外事件和问题经常发生。

为了确保工人和团队不会互相干扰，并且有某种交通规则，以便下一个技术步骤在前一个完成之前不会开始，主建筑师派遣他的代表到建筑工地的所有关键点。这些代表确保任务以预期的质量和规定的顺序执行。他们有权力阻止下一个团队开始工作，直到前一个团队尚未完成。他们就像交通警察或可以关闭工作场所的锁，或者在必要时允许它。

这些代表正在做的工作可以用现代语言定义为执行单元的协调或同步。没有它，成千上万的工人的努力结果将是不可预测的。从一万英尺高的大局观看起来平稳和和谐，就像飞机窗户外的农田一样。但是，如果不仔细检查和关注关键细节，这个看起来完美的画面可能会带来一次糟糕的收成，甚至没有收成。

同样，在多线程执行环境的安静电子空间中，如果它们共享对同一工作场所的访问权，工作线程必须进行同步。例如，让我们为一个线程创建以下类-工作者：

```java
class MyRunnable04 implements Runnable {
  private int id;
  public MyRunnable04(int id) { this.id = id; }
  public void run() {
    IntStream.rangeClosed(1, 5)
      .peek(i -> System.out.println("Thread "+id+": "+ i))
      .forEach(i -> Demo04Synchronization.result += i);
    }
}
```

正如你所看到的，它依次将 1、2、3、4、5（因此，预期的总和应该是 15）添加到`Demo04Synchronization`类的静态属性中：

```java
public class Demo04Synchronization {
    public static int result;
    public static void main(String... args) {
        System.out.println();
        demo_ThreadInterference();
    }
    private static void demo_ThreadInterference(){
        System.out.println("demo_ThreadInterference: ");
        MyRunnable04 r1 = new MyRunnable04(1);
        Thread t1 = new Thread(r1);
        MyRunnable04 r2 = new MyRunnable04(2);
        Thread t2 = new Thread(r2);
        t1.start();
        sleepMs(100);
        t2.start();
        sleepMs(100);
        System.out.println("Result=" + result);
    }
    private static void sleepMs(int sleepMs) {
        try {
            TimeUnit.MILLISECONDS.sleep(sleepMs);
        } catch (InterruptedException e) {}
    }
}
```

在早期的代码中，当主线程第一次暂停 100 毫秒时，线程`t1`将变量 result 的值带到 15，然后线程`t2`再添加 15，得到总和 30。以下是输出：

![线程同步](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_24.jpg)

如果我们去掉 100 毫秒的第一个暂停，线程将同时工作：

![线程同步](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_25.jpg)

最终结果仍然是 30。我们对这段代码感到满意，并将其部署到生产环境中作为经过充分测试的代码。然而，如果我们将添加的次数从 5 增加到 250，例如，结果将变得不稳定，并且每次运行都会发生变化。以下是第一次运行（我们注释掉了每个线程的打印输出，以节省空间）：

![线程同步](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_26.jpg)

以下是另一次运行的输出：

![线程同步](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_27.jpg)

它证明了`Demo04Synchronization.result += i`操作不是原子的。这意味着它包括几个步骤，从`result`属性中读取值，向其添加值，将得到的总和分配回`result`属性。这允许以下情景，例如：

+   两个线程都读取了`result`的当前值（因此每个线程都有相同原始`result`值的副本）

+   每个线程都向相同的原始整数添加另一个整数

+   第一个线程将总和分配给`result`属性

+   第二个线程将其总和分配给`result`属性

正如你所看到的，第二个线程不知道第一个线程所做的加法，并且覆盖了第一个线程分配给`result`属性的值。但是这种线程交错并不是每次都会发生。这只是一个机会游戏。这就是为什么我们只看到五个数字时没有看到这样的效果。但是随着并发操作数量的增加，这种情况发生的概率会增加。

在建造金字塔的过程中也可能发生类似的情况。第二个团队可能在第一个团队完成任务之前开始做一些事情。我们绝对需要一个**同步器**，它使用`synchronized`关键字。通过使用它，我们可以在`Demo04Synchronization`类中创建一个方法（建筑师代表），控制对`result`属性的访问，并向其添加这个关键字。

```java
private static int result;
public static synchronized void incrementResult(int i){
    result += i;
}
```

现在我们也需要修改工作线程中的`run()`方法：

```java
public void run() {
    IntStream.rangeClosed(1, 250)
       .forEach(Demo04Synchronization::incrementResult);
}
```

现在输出显示每次运行都有相同的最终数字：

![线程同步](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_28.jpg)

`synchronized`关键字告诉 JVM 一次只允许一个线程进入这个方法。所有其他线程将等待，直到当前访问者退出该方法。

通过向代码块添加`synchronized`关键字也可以实现相同的效果：

```java
public static void incrementResult(int i){
    synchronized (Demo04Synchronization.class){
        result += i;
    }
}
```

不同之处在于，代码块同步需要一个对象--在静态属性同步的情况下是一个类对象（就像我们的情况一样），或者在实例属性同步的情况下是任何其他对象。每个对象都有一个固有锁或监视器锁，通常简称为监视器。一旦一个线程在对象上获取了锁，直到第一个线程从锁定的代码中正常退出或代码抛出异常后释放锁，其他线程就无法在同一个对象上获取锁。

事实上，在同步方法的情况下，一个对象（方法所属的对象）也被用于锁定。它只是在幕后自动发生，不需要程序员明确地使用对象的锁。

如果您没有访问`main`类代码（就像之前的例子一样），您可以将`result`属性保持为公共，并在工作线程中添加一个同步方法（而不是像我们所做的那样添加到类中）：

```java
class MyRunnable05 implements Runnable {
    public synchronized void incrementResult(int i){
        Demo04Synchronization.result += i;
    }
    public void run() {
        IntStream.rangeClosed(1, 250)
                .forEach(this::incrementResult);
    }
}
```

在这种情况下，`MyRunnable05`工作类的对象默认提供其固有锁。这意味着，您需要为所有线程使用`MyRunnable05`类的相同对象：

```java
void demo_Synchronized(){
    System.out.println("demo_Synchronized: ");
    MyRunnable05 r1 = new MyRunnable05();
    Thread t1 = new Thread(r1);
    Thread t2 = new Thread(r1);
    t1.start();
    t2.start();
    sleepMs(100);
    System.out.println("Result=" + result);
}
```

前面代码的输出与之前相同：

![线程同步](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_29.jpg)

有人可能会认为这种最后的实现更可取，因为它将同步的责任分配给了线程（以及其代码的作者），而不是共享资源。这样，随着线程实现的演变，同步的需求也会发生变化，只要客户端代码（使用相同或不同的对象进行线程）也可以根据需要进行更改。

还有另一个可能发生在某些操作系统中的并发问题。根据线程缓存的实现方式，一个线程可能会保留`result`属性的本地副本，并且在另一个线程更改其值后不会更新它。通过向共享（在线程之间）属性添加`volatile`关键字，可以保证其当前值始终从主内存中读取，因此每个线程都将看到其他线程所做的更新。在我们之前的例子中，我们只是将`Demo04Synchronization`类的属性设置为`private static volatile int result`，在同一类或线程中添加一个同步的`incrementResult()`方法，不再担心线程相互干扰。

所描述的线程同步通常对主流应用程序来说已经足够了。但是，更高性能和高并发处理通常需要更仔细地查看线程转储，这通常显示方法同步比块同步更有效。当然，这也取决于方法和块的大小。由于所有其他尝试访问同步方法或块的线程都将停止执行，直到当前访问者退出该方法或块，因此尽管有开销，但小的同步块可能比大的同步方法性能更好。

对于某些应用程序，默认的内部锁的行为可能不太合适，因为它只会在锁被释放之前阻塞。如果是这种情况，请考虑使用`java.util.concurrent.locks`包中的锁。与使用默认的内部锁相比，该包中的锁所基于的访问控制有几个不同之处。这些差异可能对您的应用程序有利，也可能提供不必要的复杂性，但重要的是要了解它们，以便您可以做出明智的决定：

+   代码的同步片段不需要属于一个方法；它可以跨越几个方法，由实现`Lock`接口的对象上调用`lock()`和`unlock()`方法来界定

+   在创建名为`ReentrantLock`的`Lock`接口对象时，可以在构造函数中传递一个`fair`标志，使锁能够首先授予等待时间最长的线程访问，这有助于避免饥饿（低优先级线程永远无法访问锁）

+   允许线程在承诺被阻塞之前测试锁是否可访问

+   允许中断等待锁的线程，以便它不会无限期地保持阻塞

+   您可以根据应用程序需要自己实现`Lock`接口

`Lock`接口的典型使用模式如下：

```java
Lock lock = ...;
...
    lock.lock();
    try {
        // the fragment that is synchronized
    } finally {
        lock.unlock();
    }
...
}
```

注意`finally`块。这是确保最终释放`lock`的方法。否则，在`try-catch`块内的代码可能会抛出异常，而锁却永远不会被释放。

除了`lock()`和`unlock()`方法之外，`Lock`接口还有以下方法：

+   `lockInterruptibly()`: 除非当前线程被中断，否则获取锁。与`lock()`方法类似，此方法在等待锁被获取时阻塞，与`lock()`方法不同的是，如果另一个线程中断等待线程，此方法会抛出`InterruptedException`异常

+   `tryLock()`: 如果在调用时空闲，立即获取锁

+   `tryLock(long time, TimeUnit unit)`: 如果在给定的等待时间内空闲，并且当前线程未被中断，则获取锁

+   `newCondition()`: 返回一个绑定到此`Lock`实例的新`Condition`实例，获取锁后，线程可以释放它（在`Condition`对象上调用`await()`方法），直到其他线程在相同的`Condition`对象上调用`signal()`或`signalAll()`，还可以指定超时期限（使用重载的`await()`方法），因此如果没有收到信号，线程将在超时后恢复，有关更多详细信息，请参阅`Condition` API

本书的范围不允许我们展示`java.util.concurrent.locks`包中提供的所有线程同步可能性。描述所有这些可能需要几节课。但即使从这个简短的描述中，您也可以看到很难找到一个不能使用`java.util.concurrent.locks`包解决的同步问题。

当需要隔离几行代码作为原子（全有或全无）操作时，方法或代码块的同步才有意义。但是在简单的变量赋值或数字的增加/减少的情况下（就像我们之前的例子中一样），有一种更好的方式可以通过使用`java.util.concurrent.atomic`包中支持无锁线程安全编程的类来同步这个操作。各种类涵盖了所有的数字，甚至是数组和引用类型，比如`AtomicBoolean`、`AtomicInteger`、`AtomicIntegerArray`、`AtomicReference`和`AtomicReferenceArray`。

总共有 16 个类。根据值类型的不同，每个类都允许进行全方位的操作，即`set()`、`get()`、`addAndGet()`、`compareAndSet()`、`incrementAndGet()`、`decrementAndGet()`等等。每个操作的实现要比使用`synchronized`关键字实现的同样操作要高效得多。而且不需要`volatile`关键字，因为它在底层使用了它。

如果同时访问的资源是一个集合，`java.util.concurrent`包提供了各种线程安全的实现，其性能优于同步的`HashMap`、`Hashtable`、`HashSet`、`Vector`和`ArrayList`（如果我们比较相应的`ConcurrentHashMap`、`CopyOnWriteArrayList`和`CopyOnWriteHashSet`）。传统的同步集合会锁定整个集合，而并发集合使用诸如锁分离之类的先进技术来实现线程安全。并发集合在更多读取和较少更新时特别出色，并且比同步集合更具可伸缩性。但是，如果您的共享集合的大小较小且写入占主导地位，那么并发集合的优势就不那么明显了。

# 调整 JVM

每座金字塔建筑，就像任何大型项目一样，都经历着设计、规划、执行和交付的相同生命周期。在每个阶段，都在进行持续的调整，一个复杂的项目之所以被称为如此，是有原因的。软件系统在这方面并没有什么不同。我们设计、规划和构建它，然后不断地进行更改和调整。如果我们幸运的话，新的更改不会太大地回到最初的阶段，也不需要改变设计。为了防范这种激烈的步骤，我们使用原型（如果采用瀑布模型）或迭代交付（如果采用敏捷过程）来尽早发现可能的问题。就像年轻的父母一样，我们总是警惕地监视着我们孩子的进展，日夜不停。

正如我们在之前的某个部分中已经提到的，每个 JDK 9 安装都附带了几个诊断工具，或者可以额外使用这些工具来监视您的 Java 应用程序。这些工具的完整列表（以及如何创建自定义工具的建议，如果需要的话）可以在 Oracle 网站的官方 Java SE 文档中找到：[`docs.oracle.com/javase/9/troubleshoot/diagnostic-tools.htm`](https://docs.oracle.com/javase/9/troubleshoot/diagnostic-tools.htm)。

使用这些工具，可以识别应用程序的瓶颈，并通过编程或调整 JVM 本身或两者兼而行之来解决。最大的收益通常来自良好的设计决策以及使用某些编程技术和框架，其中一些我们在其他部分中已经描述过。在本节中，我们将看看在应用所有可能的代码更改后或者当更改代码不是一个选项时可用的选项，因此我们所能做的就是调整 JVM 本身。

努力的目标取决于应用程序的分析结果和非功能性需求：

+   延迟，或者说应用程序对输入的响应速度

+   吞吐量，或者说应用程序在给定时间单位内所做的工作量

+   内存占用，或者说应用程序需要多少内存

其中一个的改进通常只能以牺牲另一个或两者的方式实现。内存消耗的减少可能会降低吞吐量和延迟，而延迟的减少通常只能通过增加内存占用来实现，除非你可以引入更快的 CPU，从而改善这三个特性。

应用程序分析可能会显示，一个特定的操作在循环中不断分配大量内存。如果你可以访问代码，可以尝试优化代码的这一部分，从而减轻 JVM 的压力。另外，它可能会显示涉及 I/O 或其他与低性能设备的交互，并且在代码中无法做任何改进。

定义应用程序和 JVM 调优的目标需要建立指标。例如，已经众所周知，将延迟作为平均响应时间的传统度量隐藏了更多关于性能的信息。更好的延迟指标将是最大响应时间与 99%最佳响应时间的结合。对于吞吐量，一个好的指标将是单位时间内的交易数量。通常，这些指标的倒数（每个交易的时间）会反映延迟。对于内存占用，最大分配的内存（在负载下）允许进行硬件规划，并设置防范可怕的`OutOfMemoryError`异常。避免完整（停止一切）的垃圾收集循环将是理想的。然而，在实践中，如果**Full GC**不经常发生，不明显影响性能，并且在几个周期后最终堆大小大致相同，那就足够了。

不幸的是，这种简单的需求在实践中确实会发生。现实生活中不断出现更多的问题，如下：

+   目标延迟（响应时间）是否会被超过？

+   如果是，频率是多少，幅度是多少？

+   响应时间不佳的时间段可以持续多久？

+   谁/什么在生产中测量延迟？

+   目标性能是峰值性能吗？

+   预期的峰值负载是多少？

+   预期的峰值负载将持续多久？

只有在回答了所有这些类似的问题并建立了反映非功能性需求的指标之后，我们才能开始调整代码，运行它并一遍又一遍地进行分析，然后调整代码并重复这个循环。这项活动必须占用大部分的努力，因为与通过代码更改获得的性能改进相比，调整 JVM 本身只能带来一小部分性能改进。

然而，JVM 调优的几次尝试必须在早期进行，以避免浪费努力并试图将代码强行放入配置不良的环境中。JVM 配置必须尽可能慷慨，以便代码能够充分利用所有可用资源。

首先，从 JVM 9 支持的四种垃圾收集器中选择一个，它们分别是：

+   **串行收集器**：这使用单个线程执行所有垃圾收集工作。

+   **并行收集器**：这使用多个线程加速垃圾收集。

+   **并发标记清除（CMS）收集器**：这使用更短的垃圾收集暂停来换取更多的处理器时间。

+   **垃圾优先（G1）收集器**：这是为多处理器机器和大内存设计的，但在高概率下达到垃圾收集暂停时间目标，同时实现高吞吐量。

官方的 Oracle 文档（[`docs.oracle.com/javase/9/gctuning/available-collectors.htm`](https://docs.oracle.com/javase/9/gctuning/available-collectors.htm)）提供了垃圾收集选择的初始指南：

+   如果应用程序的数据集很小（大约 100MB 以下），则选择带有`-XX:+UseSerialGC`选项的串行收集器。

+   如果应用程序将在单个处理器上运行，并且没有暂停时间要求，则选择带有`-XX:+UseSerialGC`选项的串行收集器。

+   如果（a）峰值应用程序性能是第一优先级，（b）没有暂停时间要求或者接受一秒或更长时间的暂停，那么让虚拟机选择收集器或者选择并行收集器与`-XX:+UseParallelGC`

+   如果响应时间比整体吞吐量更重要，并且垃圾收集暂停必须保持在大约一秒以下，则选择带有`-XX:+UseG1GC`或`-XX:+UseConcMarkSweepGC`的并发收集器。

但是，如果您还没有特定的偏好，让 JVM 选择垃圾收集器，直到您更多地了解您的应用程序的需求。在 JDK 9 中，G1 在某些平台上是默认选择的，如果您使用的硬件资源足够，这是一个很好的开始。

Oracle 还建议使用 G1 的默认设置，然后使用`-XX:MaxGCPauseMillis`选项和`-Xmx`选项来尝试不同的暂停时间目标和最大 Java 堆大小。增加暂停时间目标或堆大小通常会导致更高的吞吐量。延迟也受暂停时间目标的改变影响。

在调整 GC 时，保持`-Xlog:gc*=debug`日志选项是有益的。它提供了许多有关垃圾收集活动的有用细节。JVM 调优的第一个目标是减少完整堆 GC 周期（Full GC）的数量，因为它们非常消耗资源，因此可能会减慢应用程序的速度。这是由老年代区域的占用率过高引起的。在日志中，它被识别为`Pause Full (Allocation Failure)`。以下是减少 Full GC 机会的可能步骤：

+   使用`-Xmx`增加堆的大小。但要确保它不超过物理内存的大小。最好留一些 RAM 空间给其他应用程序。

+   显式增加并发标记线程的数量，使用`-XX:ConcGCThreads`。

+   如果庞大的对象占用了太多堆空间（观察显示在**gc+heap=info**日志中的巨大区域旁边的数字），尝试使用`-XX:G1HeapRegionSize`来增加区域大小。

+   观察 GC 日志，并修改代码，以便您的应用程序创建的几乎所有对象都不会超出年轻代（早夭）。

+   一次添加或更改一个选项，这样您就可以清楚地了解 JVM 行为变化的原因。

这些步骤将帮助您创建一个试错循环，让您更好地了解您正在使用的平台，应用程序的需求，以及 JVM 和所选 GC 对不同选项的敏感性。掌握了这些知识，您将能够通过更改代码、调整 JVM 或重新配置硬件来满足非功能性能要求。

# 响应式编程

经过几次失败的尝试和一些灾难性的中断，然后是英勇的恢复，金字塔建造的过程形成了，古代建筑师们能够完成一些项目。最终的形状有时并不完全如预期（第一座金字塔最终弯曲了），但是，金字塔至今仍然装饰着沙漠。经验代代相传，设计和工艺经过调整，能够在 4000 多年后产生一些宏伟而令人愉悦的东西。

软件实践也随着时间而改变，尽管图灵先生编写了第一个现代程序只有大约 70 年。起初，当世界上只有少数程序员时，计算机程序通常是一连串的指令。函数式编程（像第一类公民一样推动函数）也很早就被引入，但并没有成为主流。相反，**GOTO**指令允许您将代码卷入意大利面条般的混乱中。接着是结构化编程，然后是面向对象编程，函数式编程也在某些领域蓬勃发展。许多程序员已经习惯了异步处理按键生成的事件。JavaScript 试图使用所有最佳实践，并获得了很大的力量，尽管在调试（有趣）阶段程序员会感到沮丧。最后，随着线程池和 lambda 表达式成为 JDK SE 的一部分，将响应式流 API 添加到 JDK 9 中，使 Java 成为允许使用异步数据流进行响应式编程的家庭的一部分。

公平地说，即使没有这个新的 API，我们也能够异步处理数据--通过旋转工作线程和使用线程池和可调用对象（正如我们在前面的部分中所描述的）或通过传递回调（即使偶尔在谁调用谁的迷宫中迷失）。但是，在几次编写这样的代码之后，人们会注意到大多数这样的代码只是一个可以包装在框架中的管道，可以显著简化异步处理。这就是响应式流倡议（[`www.reactive-streams.org`](http://www.reactive-streams.org)）的创建背景和努力的范围定义如下：

响应式流的范围是找到一组最小的接口、方法和协议，描述必要的操作和实体以实现异步数据流和非阻塞背压。

术语**非阻塞背压**是重要的，因为它确定了现有异步处理的问题之一--协调传入数据的速率与系统处理这些数据的能力，而无需停止（阻塞）数据输入。解决方案仍然会包括一些背压，通过通知源消费者在跟不上输入时存在困难，但新框架应该以更灵活的方式对传入数据的速率变化做出反应，而不仅仅是阻止流动，因此称为**响应式**。

响应式流 API 由包含在类中的五个接口组成，它们是`java.util.concurrent.Flow`、`Publisher`、`Subscriber`、`Subscription`和`Processor`：

```java
@FunctionalInterface
public static interface Flow.Publisher<T> {
  public void subscribe(Flow.Subscriber<? super T> subscriber);
}

public static interface Flow.Subscriber<T> {
  public void onSubscribe(Flow.Subscription subscription);
  public void onNext(T item);
  public void onError(Throwable throwable);
  public void onComplete();
}

public static interface Flow.Subscription {
  public void request(long numberOfItems);
  public void cancel();
}

public static interface Flow.Processor<T,R> 
               extends Flow.Subscriber<T>, Flow.Publisher<R> {
}
```

在`Flow.Publisher`对象的`subscribe()`方法中将`Flow.Subscriber`对象作为参数传递后，`Flow.Subscriber`对象成为`Flow.Publisher`对象产生的数据的订阅者。发布者（`Flow.Publisher`对象）调用订阅者的`onSubscribe()`方法，并将`Flow.Subscription`对象作为参数传递。现在，订阅者可以通过调用订阅的`request()`方法从发布者那里请求`numberOffItems`个数据。这是实现拉模型的方式，订阅者决定何时请求另一个项目进行处理。订阅者可以通过调用`cancel()`订阅方法取消订阅发布者的服务。

作为回报（或者如果实现者决定这样做，那将是一种推送模型），发布者可以通过调用订阅者的`onNext()`方法向订阅者传递一个新项目。发布者还可以告诉订阅者，项目生产遇到了问题（通过调用订阅者的`onError()`方法）或者不会再有数据传入（通过调用订阅者的`onComplete()`方法）。

`Flow.Processor`接口描述了一个既可以充当订阅者又可以充当发布者的实体。它允许创建这些处理器的链（管道），因此订阅者可以从发布者那里接收一个项目，对其进行调整，然后将结果传递给下一个订阅者。

这是 Reactive Streams 倡议定义的最小接口集（现在是 JDK 9 的一部分），支持非阻塞背压的异步数据流。正如您所看到的，它允许订阅者和发布者相互交流和协调，如果需要的话，协调传入数据的速率，从而使我们在开始讨论时所讨论的背压问题有可能有各种解决方案。

有许多实现这些接口的方法。目前，在 JDK 9 中，只有一个接口实现的例子——`SubmissionPublisher`类实现了`Flow.Publisher`。但已经存在几个其他库实现了 Reactive Streams API：RxJava、Reactor、Akka Streams 和 Vert.x 是其中最知名的。我们将在我们的示例中使用 RxJava 2.1.3。您可以在[`reactivex.io`](http://reactivex.io)上找到 RxJava 2.x API，名称为 ReactiveX，代表 Reactive Extension。

在这样做的同时，我们也想解释一下`java.util.stream`包和响应式流（例如 RxJava 中实现的）之间的区别。可以使用任何一种流编写非常相似的代码。让我们看一个例子。这是一个程序，它遍历五个整数，只选择偶数（2 和 4），对每个偶数进行转换（对每个选定的数字取平方根），然后计算两个平方根的平均值。它基于传统的`for`循环。

让我们从相似性开始。可以使用任何一种流来实现相同的功能。例如，这是一个方法，它遍历五个整数，只选择偶数（在这种情况下是 2 和 4），对每个偶数进行转换（对每个偶数取平方根），然后计算两个平方根的平均值。它基于传统的`for`循环：

```java
void demo_ForLoop(){
    List<Double> r = new ArrayList<>();
    for(int i = 1; i < 6; i++){
        System.out.println(i);
        if(i%2 == 0){
            System.out.println(i);
            r.add(doSomething(i));
        }
    }
    double sum = 0d;
    for(double d: r){ sum += d; }
    System.out.println(sum / r.size());
}
static double doSomething(int i){
    return Math.sqrt(1.*i);
}
```

如果我们运行这个程序，结果将如下所示：

![响应式编程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_30.jpg)

相同的功能（具有相同的输出）也可以使用`java.util.stream`包来实现，如下所示：

```java
void demo_Stream(){
    double a = IntStream.rangeClosed(1, 5)
        .peek(System.out::println)
        .filter(i -> i%2 == 0)
        .peek(System.out::println)
        .mapToDouble(i -> doSomething(i))
        .average().getAsDouble();
    System.out.println(a);
}
```

相同的功能也可以使用 RxJava 实现：

```java
void demo_Observable1(){
    Observable.just(1,2,3,4,5)
        .doOnNext(System.out::println)
        .filter(i -> i%2 == 0)
        .doOnNext(System.out::println)
        .map(i -> doSomething(i))
        .reduce((r, d) -> r + d)
        .map(r -> r / 2)
        .subscribe(System.out::println);
}
```

RxJava 基于`Observable`对象（扮演`Publisher`的角色）和订阅`Observable`并等待数据被发射的`Observer`。从`Observable`到`Observer`的每个发射数据项都可以通过以流畅的方式链接的操作进行处理（参见之前的代码）。每个操作都采用 lambda 表达式。操作功能从其名称中很明显。

尽管能够表现得与流类似，但`Observable`具有显着不同的功能。例如，流一旦关闭，就无法重新打开，而`Observable`可以被重复使用。这是一个例子：

```java
void demo_Observable2(){
    Observable<Double> observable = Observable
            .just(1,2,3,4,5)
            .doOnNext(System.out::println)
            .filter(i -> i%2 == 0)
            .doOnNext(System.out::println)
            .map(Demo05Reactive::doSomething);

    observable
            .reduce((r, d) -> r + d)
            .map(r -> r / 2)
            .subscribe(System.out::println);

    observable
            .reduce((r, d) -> r + d)
            .subscribe(System.out::println);
}
```

在之前的代码中，我们两次使用了`Observable`——一次用于计算平均值，一次用于对偶数的平方根求和。输出如下截图所示：

![响应式编程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_31.jpg)

如果我们不希望`Observable`运行两次，可以通过添加`.cache()`操作来缓存其数据：

```java
void demo_Observable2(){
    Observable<Double> observable = Observable
            .just(1,2,3,4,5)
            .doOnNext(System.out::println)
            .filter(i -> i%2 == 0)
            .doOnNext(System.out::println)
            .map(Demo05Reactive::doSomething)
            .cache();

    observable
            .reduce((r, d) -> r + d)
            .map(r -> r / 2)
            .subscribe(System.out::println);

    observable
            .reduce((r, d) -> r + d)
            .subscribe(System.out::println);
}
```

之前代码的结果如下：

![响应式编程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hiperf-java9/img/03_32.jpg)

您可以看到同一个`Observable`的第二次使用利用了缓存的数据，从而实现了更好的性能。

另一个`Observable`的优势是异常可以被`Observer`捕获：

```java
subscribe(v -> System.out.println("Result=" + v),
        e -> {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        },
        () -> System.out.println("All the data processed"));
```

`subscribe()`方法是重载的，允许传入一个、两个或三个函数：

+   第一个用于成功的情况

+   第二个用于异常情况

+   第三个在所有数据处理完毕后调用

`Observable`模型还允许更多控制多线程处理。在流中使用`.parallel()`不允许您指定要使用的线程池。但是，在 RxJava 中，您可以使用`Observable`中的`subscribeOn()`方法设置您喜欢的池类型：

```java
observable.subscribeOn(Schedulers.io())
        .subscribe(System.out::println);
```

`subscribeOn()`方法告诉`Observable`在哪个线程上放置数据。`Schedulers`类有生成线程池的方法，主要处理 I/O 操作（如我们的示例中），或者处理计算密集型操作（`computation()`方法），或者为每个工作单元创建一个新线程（`newThread()`方法），以及其他几种方法，包括传入自定义线程池（`from(Executor executor)`方法）。

这本书的格式不允许我们描述 RxJava API 和其他响应式流实现的所有丰富性。它们的主要目的反映在响应式宣言（[`www.reactivemanifesto.org/`](http://www.reactivemanifesto.org/)）中，该宣言将响应式系统描述为新一代高性能软件解决方案。建立在异步消息驱动进程和响应式流上，这些系统能够展示响应式宣言中声明的特性：

+   **弹性**：具有根据负载需要扩展和收缩的能力

+   **更好的响应性**：在这里，处理可以使用异步调用进行并行化

+   **弹性**：在这里，系统被分解为多个（通过消息松耦合）组件，从而促进灵活的复制、封装和隔离

使用响应式流来编写响应式系统的代码，以实现先前提到的特性，构成了响应式编程。这种系统今天的典型应用是微服务，下一课将对此进行描述。

# 摘要

在本课中，我们讨论了通过使用多线程来改善 Java 应用程序性能的方法。我们描述了如何通过使用线程池和适用于不同处理需求的各种类型的线程池来减少创建线程的开销。我们还提出了用于选择池大小的考虑因素，以及如何同步线程，使它们不会相互干扰，并产生最佳性能结果。我们指出，对性能改进的每个决定都必须通过直接监视应用程序进行制定和测试，并讨论了通过编程和使用各种外部工具进行此类监视的可能选项。最后一步，JVM 调优，可以通过我们在相应部分列出并评论的 Java 工具标志来完成。采用响应式编程的概念可能会使 Java 应用程序的性能获得更多收益，我们将其作为朝着高度可伸缩和高性能 Java 应用程序的最有效举措之一。

在下一课中，我们将讨论通过将应用程序拆分为多个微服务来添加更多的工作线程，每个微服务都独立部署，并且每个微服务都使用多个线程和响应式编程以获得更好的性能、响应、可伸缩性和容错性。

# 评估

1.  命名一个方法，计算前 99,999 个整数的平均平方根，并将结果分配给可以随时访问的属性。

1.  以下哪种方法创建了一个固定大小的线程池，可以在给定延迟后安排命令运行，或定期执行：

1.  新的调度线程池()

1.  新的工作窃取线程池()

1.  新的单线程调度执行器()

1.  新的固定线程池()

1.  陈述是否正确：可以利用`Runnable`接口是一个函数式接口，并将必要的处理函数作为 lambda 表达式传递到新线程中。

1.  在调用`__________`方法之后，不能再向池中添加更多的工作线程。

1.  shutdownNow()

1.  shutdown()

1.  isShutdown()

1.  isShutdownComplete()

1.  ________ 基于`Observable`对象，它扮演着发布者的角色。
