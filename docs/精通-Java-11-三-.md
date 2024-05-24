# 精通 Java 11（三）

> 原文：[Mastering Java 11](https://libgen.rs/book/index.php?md5=550A7DE63D6FA28E9423A226A5BBE759)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 八、JMH 的微基准应用

在上一章中，我们深入回顾了垃圾收集，包括对象生命周期、垃圾收集算法、垃圾收集选项以及与垃圾收集相关的方法。我们简要介绍了 Java8 中垃圾收集的升级，重点介绍了新 Java 平台的变化。我们对 Java11 中的垃圾收集的探索包括：默认垃圾收集、废弃的垃圾收集组合、统一的垃圾收集日志记录以及持久存在的垃圾收集问题。

在本章中，我们将研究如何使用 **Java 微基准线束**（**JMH**）编写性能测试，这是一个用于编写 JVM 基准测试的 Java 线束库。我们将使用 Maven 和 JMH 来帮助说明使用新 Java 平台进行微标记的威力。

具体来说，我们将讨论以下主题：

*   微基准概述
*   Maven 微基准
*   基准选择
*   避免微基准陷阱的技术

# 技术要求

本章以 Java11 为特色，Java 平台的**标准版**（**SE**）可从 [Oracle 官方下载网站](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

IDE 包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

本章的源代码可以在 [GitHub 的 URL](https://github.com/PacktPublishing/Mastering-Java-11-Second-Edition) 上找到。

# 微基准概述

微基准是用来测试系统性能的。这与宏观基准测试不同，后者在不同的平台上运行测试，以进行效率比较和后续分析。使用微标记，我们通常针对一个系统上的特定代码片段，例如方法或循环。微基准的主要目的是在我们的代码中识别优化机会。

基准测试有多种方法；我们将重点介绍如何使用 JMH 工具？开发人员并不总是关心性能问题，除非性能是一个明确的要求。这可能会导致部署后的意外情况，如果将微基准作为开发过程的一部分进行，则可以避免这些意外情况。

微基准发生在一个过程的几个阶段。如下图所示，流程包括设计、实现、执行、分析和增强：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/533b89ec-0fe6-45fa-a0e8-ac92c9018a3e.png)

微基准过程阶段

在**设计**阶段，我们确定了我们的目标并设计了相应的微基准；在**实现**阶段，我们编写了微基准，然后在**执行**阶段，我们实际运行了测试。在**分析**阶段，我们利用手中的微标记结果对结果进行了解释和分析。这导致了**增强**阶段的代码改进。一旦我们的代码被更新，我们就重新设计微基准测试，调整实现，或者直接进入**执行**阶段。这是一个循环的过程，一直持续到我们实现目标中确定的性能优化为止。

# 使用 JMH 的方法

Oracle 的文档表明，最理想的 JMH 用例是使用依赖于应用 JAR 文件的 Maven 项目。他们进一步建议微标记通过命令行进行，而不是从 IDE 中进行，因为这可能会影响结果。

Maven，也称为 ApacheMaven，是一个项目管理和理解工具，我们可以使用它来管理我们的应用项目构建、报告和文档。

为了使用 JMH，我们将使用字节码处理器（注解）来生成基准代码。

为了测试 JMH，您必须有一个支持 Maven 的 IDE 和您正在使用的 Java 版本。如果您还没有 Java11 或支持 Java11 的 IDE，可以按照下一节中的步骤操作。

# 安装 Java 和 Eclipse

您可以从 [JDK11 早期访问构建页面](http://jdk.java.net/11/)下载并安装。

一旦安装了 Java11，请下载最新版本的 Eclipse。在写这本书的时候，那是氧气。[这是相关链接](https://www.eclipse.org/downloads/)。

# 动手实验

现在我们已经安装了 EclipseOxygen，您可以运行一个快速测试来确定 JMH 是否在您的开发计算机上工作。首先创建一个新的 Maven 项目，如以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/4889a0b4-6ec1-4e9a-b8e8-d7b61065eaf9.png)

新 Maven 项目

接下来，我们需要添加一个依赖项。我们可以用以下代码直接编辑`pom.xml`文件：

```java
<dependency>
  <groupId>org.openjdk.jmh</groupId>
```

```java
  <artifactId>jmh-core</artifactId>
  <version>0.1</version>
</dependency>
```

或者，我们可以单击添加。。。按钮，以在对话框窗口中输入数据，如下面的屏幕截图所示。使用此表单用前面的代码更新`pom.xml`文件：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/d397f418-4a7c-4997-8e3a-5a197d3cc797.png)

依赖项选择

接下来，我们需要编写一个包含 JMH 方法的类。这只是确认我们最近更新的开发环境的初始测试。以下是可用于测试的示例代码：

```java
package com.packt.benchmark.test.com.packt.benchmark.test;
import org.openjdk.jmh.Main;

public class Test {
  public static void main(String[] args) {
    Main.main(args);
  }
}
```

我们现在可以编译和运行我们非常简单的测试程序。结果在控制台选项卡中提供，如果使用命令行，则在实际控制台中提供。以下是您将看到的内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/df97d398-6b52-4e0f-bdd5-571012b6bc5a.png)

JMH 测试结果

# Maven 微基准

开始使用 JMH 的一种方法是使用 JMHMaven 原型。第一步是创建一个新的 JMH 项目。在我们系统的命令提示符下，我们将输入`mvn`命令，然后输入一组长参数，以创建一个新的 Java 项目和必要的 Maven`pom.xml`文件：

```java
mvn archetype:generate -DinteractiveMode=false -DarchetypeGroupId=org.openjdk.jmh -DarchetypeArtifactId=jmh-java-benchmark-archetype -DgroupId=com.packt -DartifactId=chapter8-benchmark -Dversion=1.0
```

一旦您输入`mvn`命令和前面的详细参数，您将看到通过终端向您报告的结果。根据您的使用级别，您可能会看到大量来自[这个页面](https://repo.maven.apache.org/maven2/org/apache/maven/plugins/)的下载和其他类似的存储库站点。

您还将看到一个信息部分，通知您项目构建过程，如以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/71aaeb34-9690-4f26-b549-1dc6c03ba21d.png)

Maven 构建过程

可能会有额外的插件和从[这个页面](https://repo.maven.apache.org)下载的其他资源仓库。然后，您将看到一个信息反馈组件，它让您知道项目是以批处理模式生成的，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/e52f236b-699b-4b52-96b1-8dc3ee5f32ac.png)

Maven 项目生成

最后，您将看到一组参数，并注意到您的项目构建是成功的。正如您在下面的示例中所看到的，该过程用了不到 21 秒的时间完成：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/70befb56-7cd7-4f75-a915-de242d21d3dc.png)

新 Maven 项目

我们将根据`-DartifactId`选项中包含的参数创建一个文件夹，在我们的示例中，我们使用了`-DartifactId=chapter8-benchmark`，Maven 创建了一个`chapter8-benchmark`项目文件夹，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/6fa5c2e2-0a15-4b74-b28d-cf902ca6a9d5.png)

基准项目文件夹

您将看到 Maven 创建了`pom.xml`文件以及一个源（`src`文件夹。在该文件夹中，`C:\chapter8-benchmark\src\main\java\com\packt`的子目录结构下是`MyBenchmark.java`文件。Maven 为我们创建了一个基准类，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/cf163b03-6320-4908-8990-69ddf95f3598.png)

`MyBenchmark.java`文件位置

以下是 JMH Maven 项目创建过程创建的`MyBenchmark.java`类的内容：

```java
/*
 * Copyright (c) 2014, Oracle America, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions 
   are met:
 *
 * 
 * Redistributions of source code must retain the above copyright 
   notice,
 * this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of Oracle nor the names of its contributors may 
   be used
 * to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
   "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED 
   TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
   PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
   CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
   BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
   IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
   OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
   OF 
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.packt;
import org.openjdk.jmh.annotations.Benchmark;

public class MyBenchmark {
  @Benchmark
  public void testMethod() {
    // This is a demo/sample template for building your JMH benchmarks.
    // Edit as needed.
    // Put your benchmark code here.
  }
}
```

我们的下一步是修改`testMethod()`，这样就有东西要测试了。下面是我们将用于基准测试的修改方法：

```java
@Benchmark
public void testMethod() {
  int total = 0;
  for (int i=0; i<100000; i++) {
    total = total + (i * 2 );
  }
System.out.println("Total: " + total);
}
```

编辑代码后，我们将导航回本例中的项目文件夹`C:\chapter8-benchmark`，并在命令提示符下执行`mvn clean install`。

您将看到多个存储库下载、源代码编译、插件安装，最后还有`Build Success`指示符，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/005eba3e-dc06-48c2-9443-1f89eeaec7ae.png)

生成结果

现在您将在项目目录中看到`.classpath`和`.project`文件以及新的`.settings`和`target`子文件夹，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/7743445a-5eec-49f6-8865-f9f2f1b0da41.png)

项目目录

如果您导航到`\target`子文件夹，您将看到我们的`benchmarks.jar`文件已创建。这个 JAR 包含我们运行基准测试所需的内容。

`benchmarks.jar`中的外部依赖在`pom.xml`文件中配置。

我们可以在 IDE 中更新我们的`MyBenchmark.java`文件，比如 Eclipse。然后，我们可以再次执行`mvn clean install`来覆盖我们的文件。在初始执行之后，我们的构建速度会更快，因为不需要下载任何东西。

以下是初始执行后构建过程的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/e86a8c3a-e29d-4752-9ef2-b645daedf701.png)

清洁安装过程

最后一步是从`C:\chapter8-benchmark\target`文件夹运行基准工具。我们可以通过以下命令`-java -jar benchmarks.jar`来完成。即使对于简单代码上的小型基准测试（如我们的示例所示），运行基准测试也可能需要一些时间。可能会有几个迭代，包括热身，以提供更简洁有效的基准测试结果集

这里提供了我们的基准测试结果。如您所见，测试运行了`00:08:08`个小时：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/308f08b2-4c0a-4cf6-9544-1f1c7d8407cf.png)

`MyBenchmark.java`文件位置

# 基准选择

在上一节中，您学习了如何运行基准测试。在本节中，我们将查看以下用于运行基准测试的可配置选项：

*   模式
*   时间单位

# 模式

在上一节中，我们的基准测试结果的输出包括一个`Mode`列，该列的值为`thrpt`，是吞吐量的缩写。这是默认模式，另外还有四种模式。所有 JMH 基准模式如下所示：

| **模式** | **说明** |
| --- | --- |
| 全部 | 依次测量所有其他模式。 |
| 平均时间 | 此模式测量单个基准运行的平均时间。 |
| 采样时间 | 此模式测量基准执行时间，包括最小和最大时间。 |
| 单发时间 | 在这种模式下，没有 JVM 预热，测试是确定单个基准测试方法运行所需的时间。 |
| 吞吐量 | 这是默认模式，测量每秒的操作数。 |

要指定使用哪种基准模式，您需要将`@Benchmark`代码行修改为以下代码之一：

*   `@Benchmark @BenchmarkMode(Mode.All)`
*   `@Benchmark @BenchmarkMode(Mode.AverageTime)`
*   `@Benchmark @BenchmarkMode(Mode.SampleTime)`
*   `@Benchmark @BenchmarkMode(Mode.SingleShotTime)`
*   `@Benchmark @BenchmarkMode(Mode.Throughput)`

# 时间单位

为了在基准输出中获得更高的保真度，我们可以指定一个特定的时间单位，从最短到最长列出：

*   `NANOSECONDS`
*   `MICROSECONDS`
*   `MILLISECONDS`
*   `SECONDS`
*   `MINUTES`
*   `HOURS`
*   `DAYS`

为了进行此指定，我们只需在`@Benchmark`行中添加以下代码：

```java
@Benchmark @BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
```

在前面的示例中，我们指定了平均模式和纳秒作为时间单位。

# 避免微基准陷阱的技术

微基准并不是每个开发者都要担心的事情，但是对于那些这样做的人来说，有几个陷阱你应该注意。在本节中，我们将回顾最常见的陷阱，并提出避免它们的策略。

# 电源管理

有许多子系统可以用来帮助您管理电源和性能之间的平衡（即，`cpufreq`。这些系统可以在基准测试期间改变时间状态。

对于这个陷阱，有两种建议策略：

*   在运行测试之前禁用任何电源管理系统
*   长时间运行基准测试

# 操作系统调度器

操作系统调度器（如 Solaris 调度器）有助于确定哪些软件进程可以访问系统资源。使用这些调度器可能会产生不可靠的基准测试结果。

对于这个陷阱，有两种建议策略：

*   优化系统调度策略
*   长时间运行基准测试

# 分时

分时系统用于帮助平衡系统资源。使用这些系统通常会导致线程的开始和停止时间之间出现不规则的间隔。而且，CPU 负载将不统一，我们的基准数据也不会对我们有多大用处。

有两种建议策略可以避免这种陷阱：

*   在运行基准测试之前测试所有代码，以确保一切正常工作
*   只有在所有线程都已启动或停止之后，才使用 JMH 进行测量

# 消除死代码和常量折叠

死代码和常量折叠通常被称为冗余代码，我们的现代编译器非常擅长消除它们。死代码的一个例子是永远达不到的代码。考虑以下示例：

```java
. . .
int value = 10;
if (value != null) {
  System.out.println("The value is " + value + ".");
} else {
    System.out.println("The value is null."); // This is a line of Dead-Code
}
. . .
```

在我们前面的示例中，由于变量值永远不会等于`null`，因此永远不会到达标识为死代码的行。在条件语句`if`计算变量之前，它被设置为`10`。

问题是，为了消除死代码，有时可以删除基准测试代码。

常量折叠是编译时约束被实际结果替换时发生的编译器操作。编译器执行常量折叠以删除任何冗余的运行时计算。在下面的例子中，我们根据涉及第一个`int`的数学计算得到了最后一个`int`，后面是第二个`int`：

```java
. . .
static final int value = 10;
int newValue = 319 * value;
. . .
```

常量折叠操作将前面代码的两行转换为：

```java
int newValue = 3190;
```

对于这个陷阱，有一个建议的策略：

*   使用 JMH API 支持来确保您的基准测试代码不会被消除

# 运行间差异

有太多的问题会严重影响基准测试中的运行差异。

对于这个陷阱，有两种建议策略：

*   在每个子系统中多次运行 JVM
*   使用多个 JMH 分叉

# 缓存容量

**动态随机存取存储器**（**DRAM**）非常慢。在基准测试期间，这可能会导致非常不同的性能结果。

有两种策略可以解决这个陷阱：

*   使用不同的问题集运行多个基准测试。在测试期间跟踪内存占用。
*   使用`@State`注解来指示 JMH 状态。此注解用于定义实例的范围。有三种状态：
*   `Scope.Benchmark`：实例在运行同一测试的所有线程之间共享
*   `Scope.Group`：每个线程组分配一个实例
*   `Scope.Thread`：每个线程都有自己的实例。这是默认状态

# 总结

在本章中，我们了解到 JMH 是一个 Java 工具库，用于为 JVM 编写基准测试。我们尝试使用 Maven 和 JMH 编写性能测试，以帮助说明使用新 Java 平台进行微基准标记的过程。我们从微基准概述开始，然后与 Maven 深入到微基准，回顾了基准选项，最后介绍了一些避免微基准陷阱的技术。

在下一章中，我们将学习编写一个管理其他进程并利用 Java 平台的现代进程管理 API 的应用。

# 问题

1.  什么是微基准？
2.  微基准的主要阶段是什么？
3.  什么是 Maven？
4.  什么文件用于定义依赖关系？
5.  关于基准测试，模式和时间单位有什么共同点？
6.  什么是 JMH 基准模式？
7.  基准测试中使用的时间单位是什么，按从最小到最大的顺序排列？
8.  有什么建议策略可以避免电源管理陷阱？
9.  为避免操作系统调度器陷阱，有哪些建议策略？
10.  避免分时陷阱的建议策略是什么？

# 进一步阅读

下面列出的参考资料将帮助您深入了解本章介绍的概念：

*   《Java EE Eclipse 开发》，可在[这个页面](https://www.packtpub.com/application-development/java-ee-development-eclipse)上获得。
*   《Java EE Eclipse 开发——第二版》，可在[这个页面](https://www.packtpub.com/application-development/java-ee-development-eclipse-second-edition)上获得。

# 九、利用进程 API

在上一章中，我们了解到，**Java 微基准线束**（**JMH**）是一个 Java 线束库，用于为 JVM 编写基准测试。我们尝试使用 Maven 和 JMH 编写性能测试，以帮助说明使用新 Java 平台进行微基准标记的过程。我们从微基准概述开始，然后与 Maven 深入到微基准，回顾了基准选项，最后介绍了一些避免微基准陷阱的技术。

在本章中，我们将重点介绍对`Process`类和`java.lang.ProcessHandle`API 的更新。在 Java 的早期版本中，在 Java9 之前，用 Java 管理进程是很困难的。API 不够，有些功能不够，有些任务需要以特定于系统的方式来解决。例如，在 Java8 中，让进程访问自己的**进程标识符**（**PID**）是一项不必要的困难任务。

在本章中，我们将探讨编写一个利用 Java 的进程管理 API 管理其他进程的应用所需的必要知识。具体来说，我们将介绍以下内容：

*   进程简介
*   使用`ProcessHandle`接口
*   查看示例进程控制器应用

# 技术要求

本章以 Java11 为特色，Java 平台的**标准版**（**SE**）可从 [Oracle 官方下载网站](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

IDE 包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

本章的源代码可以在 [GitHub 的 URL](https://github.com/PacktPublishing/Mastering-Java-11-Second-Edition) 上找到。

# 进程简介

在 Java 应用编程的上下文中，进程是操作系统中的执行单元。当你启动一个程序，你就启动了一个过程。当机器引导代码时，它做的第一件事就是执行引导过程。然后，此进程启动其他进程，这些进程将成为引导进程的子进程。这些子进程可能会启动其他进程。这样，当机器运行时，就会有进程树在运行。

当机器做某事时，它是在某个进程内执行的某个代码中完成的。操作系统还作为同时执行的多个进程运行。应用作为一个或多个进程执行。大多数应用都是作为一个进程运行的，但作为一个例子，Chrome 浏览器启动几个进程来执行所有渲染和网络通信操作，这些操作共同起到浏览器的作用

要更好地了解进程是什么，请启动 Windows 上的任务管理器或 OSX 上的活动监视器，然后单击“进程”选项卡。您将看到机器上当前存在的不同进程。使用这些工具，您可以查看进程的参数，并且可以逐个终止进程

单个进程为其工作分配了内存，不允许它们自由访问彼此的内存

操作系统调度的执行单元是线程。进程由一个或多个线程组成。这些线程由操作系统调度器调度，并在时隙中执行

对于每个操作系统，进程都有一个 PID，它是一个标识进程的数字。不能同时有两个进程共享同一 PID。当我们想要在操作系统中识别一个活动进程时，我们使用 PID。在 Linux 和其他类似 Unix 的操作系统上，`kill`命令终止进程。要传递给此程序的参数是要终止的进程的 PID。终止可以是优雅的。这有点像要求进程退出。如果进程决定不运行，它可以继续运行。

程序可以准备在收到此类请求时停止。例如，Java 应用可以添加一个调用`Runtime.getRuntime().addShutdownHook(Thread t)`方法的`Thread`对象。传递的线程应该在进程被要求停止时启动，这样线程就可以执行程序退出前必须执行的所有任务。不幸的是，不能保证线程会真正启动，这取决于实际的实现。

# 使用`ProcessHandle`接口

Java9 中引入了两个支持处理操作系统进程的新接口-`ProcessHandle`和`ProcessHandle.Info`。

`ProcessHandle`对象标识操作系统进程并提供管理该进程的方法。在以前的 Java 版本中，这只能通过特定于操作系统的方法使用 PID 来标识进程。这种方法的主要问题是，PID 只有在进程处于活动状态时才是唯一的。当一个进程完成时，操作系统可以自由地为一个新进程重用 PID。当我们使用 PID 检查一个进程是否仍在运行时，我们实际上是在用该 PID 检查一个活动进程。当我们检查进程时，它可能是活动的，但是下次程序查询进程状态时，它可能是另一个进程

桌面和服务器操作系统尽量不重用 PID 值。在某些嵌入式系统上，操作系统可能只使用 16 位值来存储 PID。当仅使用 16 位值时，PIDs 被重用的可能性更大。我们现在可以使用`ProcessHandle`API 来避免这个问题。我们可以接收`ProcessHandle`，也可以调用`handle.is.Alive()`方法。此方法将在进程完成时返回`false`。即使重用了 PID，这种方法也可以工作。

# 获取当前进程的 PID

我们可以通过`handle`访问进程的 PID。`handle.getPid()`方法返回`Long`表示 PID 的数值，由于通过句柄访问进程更安全，因此该方法的重要性受到限制。当我们的代码想要将自己的信息提供给其他管理工具时，它可能会派上用场。

程序通常会创建一个以数字 PID 作为文件名的文件。某个程序不能在多个进程中运行可能是一个要求。在这种情况下，代码将自己的 PID 文件写入特定目录。如果具有该名称的 PID 文件已存在，则处理将停止。如果前一个进程崩溃或终止而没有删除 PID 文件，那么系统管理器可以轻松地删除该文件并启动新进程。如果程序挂起，那么如果 PID 已知，系统管理器可以很容易地终止死进程。

为了得到当前进程的 PID，可以使用调用链`ProcessHandle.current().getPid()`。

# 获取有关进程的信息

要获取有关进程的信息，我们需要访问进程的`Info`对象。可通过`ProcessHandle`获取。我们使用对`handle.info()`方法的调用来返回它。

`Info`接口定义了传递进程信息的查询方法。这些是：

*   `command()`返回`Optional<String>`，其中包含用于启动进程的命令
*   `arguments()`返回`Optional<String[]>`，其中包含启动进程的命令后在命令行上使用的参数
*   `commandLine()`返回包含整个命令行的`Optional<String>`
*   `startInstant()`返回`Optional<Instant>`，它本质上表示进程开始的时间
*   `totalCpuDuration()`返回`Optional<Duration>`，表示进程自启动以来占用的 CPU 时间
*   `user()`返回`Optional<String>`，其中包含进程所属的用户的名称

这些方法返回的值都是`Optional`，因为不能保证操作系统或 Java 实现能够返回信息，但是在大多数操作系统上，它应该工作，并且返回的值应该存在。

以下示例代码显示给定进程的信息：

```java
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

public class ProcessHandleDemonstration {
  public static void main(String[] args) throws InterruptedException, 
  IOException {
    provideProcessInformation(ProcessHandle.current());
    Process theProcess = new 
     ProcessBuilder("SnippingTool.exe").start();
    provideProcessInformation(theProcess.toHandle());
    theProcess.waitFor();
    provideProcessInformation(theProcess.toHandle());
  }
  static void provideProcessInformation(ProcessHandle theHandle) {
    // get id
    long pid = ProcessHandle.current().pid();

    // Get handle information (if available)
    ProcessHandle.Info handleInformation = theHandle.info();

    // Print header
    System.out.println("|=============================|");
    System.out.println("| INFORMATION ON YOUR PROCESS |");
    System.out.println("|=============================|\n");

    // Print the PID
    System.out.println("Process id (PID): " + pid);
    System.out.println("Process Owner: " + 
    handleInformation.user().orElse(""));

    // Print additional information if available
    System.out.println("Command:" + 
    handleInformation.command().orElse(""));
    String[] args = handleInformation.arguments().orElse (new String[]{});
    System.out.println("Argument(s): ");
    for (String arg: args) System.out.printf("\t" + arg);
      System.out.println("Command line: " + 
      handleInformation.commandLine().orElse(""));
      System.out.println("Start time: " + 
      handleInformation.startInstant().orElse(Instant.now()).
      toString());
      System.out.printf("Run time duration: %sms%n",    
      handleInformation.totalCpuDuration().
      orElse(Duration.ofMillis(0)).toMillis());
  }
}
```

以下是前面代码的控制台输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/4336ca9f-0b8d-4a26-9553-8d774e57d74d.png)

# 列出进程

在 Java9 之前，我们没有获得活动进程列表的方法。使用 Java9、10 和 11，可以在`Stream`中获取进程。有三种方法返回`Stream<ProcessHandle>`，用于：

*   列出子进程
*   列出所有子项
*   列出所有进程

下一节将对每一项进行回顾。

# 列出子项

为了得到控制子进程的进程句柄的`Stream`，应该使用静态方法`processHandle.children()`。这将创建`processHandle`表示的进程的子进程的快照，并创建`Stream`，由于进程是动态的，因此不能保证在代码执行过程中，当我们的程序处理句柄时，所有子进程仍然是活动的。它们中的一些可能会终止，而我们的进程可能会产生新的子进程，可能来自不同的线程。因此，代码不应该假设`Stream`的`ProcessHandle`元素代表一个活动的、正在运行的进程

以下程序在 Windows 中启动 10 个命令提示，然后计算子进程的数量并将其打印到标准输出：

```java
import java.io.IOException;

public class ChildLister {
  public static void main(String[] args) throws IOException {
    for (int i = 0; i < 10; i++) {
      new ProcessBuilder().command("cmd.exe").start();
    }
    System.out.println("Number of children :" +
      ProcessHandle.current().children().count());
  }
}
```

执行该程序将导致以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/2199a7d7-f51d-4157-b783-69a2464387f2.png)

# 列出后继

列出子进程与列出子进程非常相似，但是如果我们调用`processHandle.descendants()`方法，那么`Stream`将包含所有子进程以及这些进程的子进程，依此类推。

以下程序以命令行参数启动命令提示，以便它们也生成另一个终止的`cmd.exe`：

```java
import java.io.IOException;
import java.util.stream.Collectors;

public class DescendantLister {
  public static void main(String[] args) throws IOException {
    for (int i = 0; i < 10; i++) {
      new ProcessBuilder().command("cmd.exe","/K","cmd").start();
    }
    System.out.println("Number of descendants: " +
      ProcessHandle.current().descendants().count();
  }
}
```

多次运行该命令将导致以下不确定的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/d7f07f7d-8572-4606-812d-991479d5f98e.png)

输出清楚地表明，当子进程的`Stream`被创建时，并不是所有进程都是活动的。示例代码启动 10 个进程，每个进程启动另一个进程。`Stream`没有 20 个元素，因为其中一些子进程在处理过程中被终止。

# 列出所有进程

列出所有进程与列出子进程和子进程略有不同。方法`allProcess()`是静态的，返回执行时操作系统中所有活动进程的句柄`Stream`。

以下示例代码将进程命令打印到控制台，这些命令看起来像是 Java 进程：

```java
import java.lang.ProcessHandle.Info;

public class ProcessLister {
  private static void out(String format, Object... params) {
    System.out.println(String.format(format, params));
  }

  private static boolean looksLikeJavaProcess(Info info) {
    return info.command().isPresent() && info.command().get().
      toLowerCase().indexOf("java") != -1;
  }

  public static void main(String[] args) {
    ProcessHandle.allProcesses().map(ProcessHandle::info).
      filter(info -> looksLikeJavaProcess(info)).
      forEach((info) -> System.out.println(info.command().
      orElse("---")));
  }
}
```

程序的输出列出了所有内有字符串`java`的过程命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/caaf1528-0a11-4701-8fc9-9dc6e2dadda4.png)

当然，您的实际输出可能不同。

# 等待进程

当一个进程启动另一个进程时，它可能会多次等待该进程，因为它需要另一个程序的结果。如果任务的结构可以这样组织，即父程序可以在等待子进程完成时执行其他操作，则父进程可以调用进程句柄上的`isAlive()`方法。通常，在派生的进程完成之前，父进程无事可做。遗留应用实现了调用`Thread.sleep()`方法的循环，这样 CPU 就不会过度浪费，进程会定期检查，看它是否还活着

当前的 Java 平台提供了一种更好的方法来处理等待过程，`ProcessHandle`接口有一个名为`onExit()`的方法返回`CompletableFuture`。这个类可以在不循环的情况下等待任务完成。如果我们有一个进程的句柄，我们可以简单地调用`handle.onExit().join()`方法等待进程完成。返回的`CompletableFuture`的`get()`方法返回最初用于创建它的`ProcessHandle`实例

我们可以多次调用句柄上的`onExit()`方法，每次它都会返回不同的`CompletableFuture`对象，每个对象都与同一进程相关。我们可以在对象上调用`cancel()`方法，但它只会取消`CompletableFuture`对象，而不会取消进程，并且不会对从同一`ProcessHandle`实例创建的其他`CompletableFuture`对象产生任何影响。

# 终止进程

要终止一个进程，我们可以在`ProcessHandle`实例上调用`destroy()`方法或`destroyForcibly()`方法。这两种方法都将终止进程，`destroy()`方法将终止进程，优雅地执行进程关闭序列。在这种情况下，如果实际实现支持进程的正常终止，那么将执行添加到运行时的关闭挂钩。

`destroyForcibly()`方法将强制进程终止，在这种情况下，将不执行关闭序列。如果句柄管理的进程不活动，则代码调用这些方法时不会发生任何事情。如果在句柄上创建了调用`onExit()`方法的`CompletableFuture`对象，则当进程终止时，在调用`destroy()`或`destroyForcefully()`方法后，这些对象将完成。

这意味着`CompletableFuture`对象将在进程结束一段时间后从`join()`或类似方法返回，而不是在`destroy()`或`destroyForcefully()`返回之后立即返回

同样重要的是要注意，进程终止可能取决于许多事情。如果等待终止另一个进程的实际进程无权终止另一个进程，则请求将失败。在这种情况下，方法的返回值是`false`。返回值`true`并不意味着进程实际上已经终止。这只意味着操作系统接受了终止请求，并且操作系统将在将来的某个时候终止进程。这实际上很快就会发生，但不是瞬间发生的，因此如果方法`isAlive()`在`destroy()`或`destroyForcefully()`方法返回值`true`之后的一段时间内返回`true`，也就不足为奇了。

`destroy()`和`destroyForcefully()`之间的区别是具体实现的。Java 标准没有规定`destroy()`终止让关闭序列执行的进程。它只请求终止进程。此`ProcessHandle`对象表示的进程是否正常终止取决于实现。

这是因为某些操作系统没有实现优雅的进程终止特性。在这种情况下，`destroy()`的实现与调用`destroyForcefully()`相同。接口`ProcessHandle`的系统特定实现必须实现方法`supportsNormalTermination()`，只有当实现支持正常（非强制）进程终止时，才应该是`true`。对于实际实现中的所有调用，该方法应返回相同的值，并且在执行 JVM 实例期间不应更改返回值。不需要多次调用该方法。

下面的示例演示了进程启动、进程终止和等待进程终止。在我们的示例中，我们使用两个类。第一个类演示了`.sleep()`方法：

```java
public class WaitForChildToBeTerminated { 
  public static void main(String[] args) throws InterruptedException {
    Thread.sleep(10_000);
  }
}
```

我们示例中的第二个类称为`WaitForChildToBeTerminated`类：

```java
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

public class TerminateAProcessAfterWaiting {
  private static final int N = 10;
  public static void main(String[] args) throws IOException, 
  InterruptedException {
    ProcessHandle ph[] = new ProcessHandle[N];
      for (int i = 0; i < N; i++) {
        final ProcessBuilder pb = ew ProcessBuilder().
          command("java", "-cp", "build/classes/main",
          "packt.mastering.java11.process.WaitForChildToBeTerminated");
        Process p = pb.start();
        ph[i] = p.toHandle();
      }

      long start = System.currentTimeMillis();
      Arrays.stream(ph).forEach(ProcessHandle::destroyForcibly);
      CompletableFuture.allOf(Arrays.stream(ph).
        map(ProcessHandle::onExit).collect(Collectors.toList()).
        toArray(new CompletableFuture[ph.length])).join();
      long duration = System.currentTimeMillis() - start;
      System.out.println("Duration " + duration + "ms");
  }
}
```

前面的代码启动 10 个进程，每个进程执行休眠 10 秒的程序。它强制销毁进程，或者更具体地说，要求操作系统销毁进程。我们的示例连接了由`CompletableFuture`对象数组组成的`CompletableFuture`，这些对象是使用各个进程的句柄创建的

当所有进程完成后，它以毫秒为单位打印出测量的时间。时间间隔从进程创建和进程创建循环完成时开始。当 JVM 从`join()`方法返回时，当进程被识别时，测量的时间间隔结束

示例代码将睡眠时间设置为 10 秒。这是一个更明显的时间段。运行两次代码并删除破坏进程的行会导致打印速度慢得多。实际上，测量和打印的运行时间也会显示终止进程会产生影响。

# 查看示例进程控制器应用

最后一节提供了一个示例过程控制应用来演示本章的内容。应用的功能非常简单。它从一系列配置文件参数中读取如何启动某些进程，然后，如果其中任何进程停止，它将尝试重新启动进程。

这个示例应用可以作为实际应用的起点。可以使用环境变量规范扩展进程的参数集。您还可以为进程、输入和输出重定向添加一个默认目录，甚至还可以添加一个进程的 CPU 消耗量，而无需控制应用终止并重新启动它

应用由四个类组成：

*   `Main`：此类包含`public static void main`方法，用于启动守护进程。
*   `Parameters`：此类包含进程的配置参数。在这个简单的例子中，它只包含一个字段，即命令行。如果应用得到扩展，这个类将包含默认目录、重定向和 CPU 使用限制数据。
*   `ParamsAndHandle`：这个类只不过是一个数据元组，其中包含对`Parameters`对象的引用，同时也是一个进程句柄。当一个进程死亡并重新启动时，进程句柄将被新的句柄替换，但是对`Parameters`对象的引用不会改变它的配置
*   `ControlDaemon`：这个类实现了`Runnable`接口，作为一个单独的线程启动。

# `Main`类

`main()`方法从命令行参数中获取目录名。它将此视为相对于当前工作目录。它使用同一类中的单独方法从目录中的文件读取配置集，然后启动控制守护进程。以下代码是程序的`main()`方法：

```java
public static void main(String[] args) throws IOException, 
  InterruptedException {

  // DemoOutput.out() simulated - implementation not shown
  DemoOutput.out(new File(".").getAbsolutePath().toString());
  if (args.length == 0) {
    System.err.println("Usage: daemon directory");
    System.exit(-1);
  }

  Set<Parameters> params = parametersSetFrom(args[0]);
  Thread t = new Thread(new ControlDaemon(params));
  t.start();
}
```

虽然这是一个守护进程，但我们将它作为普通线程而不是守护线程启动。当一个线程被设置为守护线程时，它不会使 JVM 保持活动状态。当所有其他非守护线程停止时，JVM 将退出，守护线程将停止。在我们的例子中，我们执行的守护线程是保持代码运行的唯一线程。在启动之后，主线程就没有什么事情可做了，但是 JVM 应该保持活动状态，直到运算符发出 Unix`kill`命令或在命令行上按`Ctrl + C`将其杀死。

使用 JDK 中新的`Files`和`Paths`类，获取指定目录中的文件列表并从文件中获取参数非常简单：

```java
private static Set<Parameters>
  GetListOfFilesInDirectory(String directory) throws IOException {
    return Files.walk(Paths.get(directory)).map(Path::toFile)
      .filter(File::isFile).map(file -> Parameters.fromFile(file))
      .collect(Collectors.toSet());
}
```

我们得到一个以`Path`对象形式出现的文件流，将其映射到`File`对象，然后过滤出`configuration`目录中的目录，并使用静态方法将剩余的普通文件从`Parameters`类的`File`映射到`Parameters`对象。最后，我们返回对象的`Set`。

# `Parameters`类

我们的`Parameters`类有一个字段和一个构造器，如下所示：

```java
final String[] commandLine;
public Parameters(String[] commandLine) {
  this.commandLine = commandLine;
}
```

`Parameters`类有两个方法。第一个方法`getCommandLineStrings()`从属性中检索命令行字符串。此数组包含命令和命令行参数。如果文件中没有定义，则返回一个空数组，如下所示：

```java
private static String[] getCommandLineStrings(Properties props) {
  return Optional.ofNullable(props.getProperty("commandLine"))
    .orElse("").split("\\s+");
}
```

第二种方法是静态的`fromFile()`，它从`properties`文件中读取属性，如下所示：

```java
public static Parameters fromFile(final File file) {
  final Properties props = new Properties();
  try (final InputStream is = new FileInputStream(file)) {
    props.load(is);
  } catch (IOException e) {
      throw new RuntimeException(e);
    }
  return new Parameters(getCommandLineStrings(props));
}
```

如果程序处理的参数集被扩展，那么这个类也应该被修改。

# `ParamsAndHandle`

`ParamsAndHandle`是一个非常简单的类，它包含两个字段，一个是参数字段，另一个是进程句柄的句柄，用于访问使用参数启动的进程，如下所示：

```java
public class ParamsAndHandle {
  final Parameters params;
  ProcessHandle handle;
  public ParamsAndHandle(Parameters params,ProcessHandle handle) {
    this.params = params;
    this.handle = handle;
  }

  public ProcessHandle toHandle() {
    return handle;
  }
}
```

由于该类与使用它的`ControlDaemon`类紧密相连，因此没有与该字段相关联的更改器或访问器。我们把这两个类看作是在同一个封装边界内的东西。`toHandle () `方法就在那里，所以我们可以将它用作方法句柄，我们将在第 10 章、“细粒度栈跟踪”中看到。

# `ControlDaemon`

`ControlDaemon`类实现`Runnable`接口，并作为单独的线程启动。构造器获取从属性文件读取的参数集，并将其转换为一组`ParamsAndHandle`对象，如下所示：

```java
private final Set<ParamsAndHandle> handlers;

public ControlDaemon(Set<Parameters> params) {
  handlers = params.stream()
    .map( s -> new ParamsAndHandle(s,null))
    .collect(Collectors.toSet());
}
```

因为此时没有启动进程，所以句柄都是`null`。使用`run()`方法启动进程，如下所示：

```java
@Override
public void run() {
  try {
    for (ParamsAndHandle pah : handlers) {
      log.log(DEBUG, "Starting {0}", pah.params);
      ProcessHandle handle = start(pah.params);
      pah.handle = handle;
    }
    keepProcessesAlive();
    while (handlers.size() > 0) {
      allMyProcesses().join();
    }
  } catch (IOException e) {
      log.log(ERROR, e);
    }
}
```

处理遍历参数集并使用方法（稍后在此类中实现）启动进程。每个进程的句柄到达`ParamsAndHandle`对象。之后，调用`keepProcessesAlive()`方法并等待进程完成。当进程停止时，它就会重新启动。如果不能重新启动，它将从集合中删除

`allMyProcesses()`方法（也在这个类中实现）返回一个`CompletableFuture`，当所有启动的进程都停止时，该方法就会完成。当`join()`方法返回时，一些进程可能已经重新启动。只要至少有一个进程在运行，线程就应该运行。

使用`CompletableFuture`等待进程和`while`循环，只要至少有一个进程可以运行，我们就使用最少的 CPU 来保持线程的活动性，可能甚至在重新启动几次之后。我们必须让这个线程保持活动状态，即使它大部分时间不使用 CPU，也不执行代码，以便让`keepProcessesAlive()`方法使用`CompletableFutures`完成工作。该方法显示在以下代码段中：

```java
private void keepProcessesAlive() {
  anyOfMyProcesses().thenAccept(ignore -> {
    restartProcesses();
    keepProcessesAlive();
  });
}
```

`keepProcessesAlive()`方法调用返回`CompletableFuture`的`anyOfMyProcesses()`方法，该方法在任何托管进程退出时完成。方法计划在完成`CompletableFuture`时执行作为参数传递给`thenAccept()`方法的 Lambda。Lambda 做了两件事：

*   重新启动已停止的进程（可能只有一个）
*   调用`keepProcessesAlive()`方法

重要的是要理解这个调用不是从`keepProcessesAlive()`方法本身执行的。这不是递归调用。这被安排为一个`CompletableFuture`动作。我们不是在递归调用中实现循环，因为我们会耗尽栈空间。我们要求 JVM 执行者在进程重新启动时再次执行这个方法。

JVM 使用默认的`ForkJoinPool`来调度这些任务，这个池包含守护线程。这就是我们必须等待并保持方法运行的原因，因为这是唯一阻止 JVM 退出的非守护线程。

下一种方法是`restartProcesses()`，如下所示：

```java
private void restartProcesses() {
  Set<ParamsAndHandle> failing = new HashSet<>();
  handlers.stream()
    .filter(pah -> !pah.toHandle().isAlive())
    .forEach(pah -> {
  try {
    pah.handle = start(pah.params);
  } catch (IOException e) {
      failing.add(pah);
    }
  });
handlers.removeAll(failing);
}
```

此方法启动我们的托管进程集中且不存在的进程。如果任何重新启动失败，它将从集合中删除失败的进程。（注意不要在回路中取出，以免`ConcurrentModificationException`。`anyOfMyProcesses()`和`allMyProcesses()`方法采用辅助`completableFuturesOfTheProcessesand()`方法，简单明了，如下：

```java
private CompletableFuture anyOfMyProcesses() {
  return CompletableFuture.anyOf(
    completableFuturesOfTheProcesses());
}

private CompletableFuture allMyProcesses() {
  return CompletableFuture.allOf(
    completableFuturesOfTheProcesses());
}
```

`completableFuturesOfTheProcesses()`方法返回从当前运行的托管进程调用其`onExit()`方法创建的`CompletableFutures`数组。这是以简洁易读的函数式编程风格完成的，如下所示：

```java
private CompletableFuture[] completableFuturesOfTheProcesses() {
  return handlers.stream()
    .map(ParamsAndHandle::toHandle)
    .map(ProcessHandle::onExit)
    .collect(Collectors.toList())
    .toArray(new CompletableFuture[handlers.size()]);
}
```

集合被转换成一个`Stream`，映射到`ProcessHandle`对象的`Stream`（这就是为什么我们需要`ParamsAndHandle`类中的`toHandle()`方法）。然后使用`onExit()`方法将句柄映射到`CompletableFuture`流，最后将其收集到列表并转换为数组。

我们完成示例应用的最后一种方法如下：

```java
private ProcessHandle start(Parameters params) 
  throws IOException {
    return new ProcessBuilder(params.commandLine)
      .start().toHandle();
}
```

此方法使用`ProcessBuilder`启动进程并返回`ProcessHandle`，以便替换集合中的旧进程并管理新进程。

# 总结

在本章中，我们讨论了当前的 Java 平台如何使我们能够管理进程。这与早期版本的 Java 相比有了很大的改进，后者需要特定于操作系统的实现，而且在 CPU 使用和编码实践方面还不够理想。现代的 API，加上像`ProcessHandle`这样的新类，使得处理进程的几乎所有方面成为可能。我们还构建了一个完整的应用，管理将学到的 API 付诸实践的进程。

在下一章中，我们将详细介绍 Java 栈遍历 API。我们将使用代码示例来说明如何使用 API。

# 问题

1.  什么是进程？
2.  哪两个接口支持处理操作系统进程？
3.  当一个进程结束时，什么方法返回`false`？
4.  如何访问进程的 PID？
5.  如何检索当前进程的 PID？
6.  列出`Info`接口用于传递进程信息的六种查询方法。

7.  用什么方法得到控制子进程的进程句柄的`Stream`？
8.  使用什么方法来获取子体的进程句柄的`Stream`？
9.  什么方法可以用来检索所有子代和子代的列表？
10.  `onExit()`方法返回什么？

# 进一步阅读

有关详细信息，请访问以下链接：

*  《Java9 高性能》在[这个页面](https://www.packtpub.com/application-development/java-9-high-performance)提供。

# 十、细粒度栈跟踪

在最后一章中，我们探讨了`Process`类和`java.lang.ProcessHandle`API。在 Java 早期版本中，Java 中的流程管理需要特定于 OS 的实现，在 CPU 使用和编码实践方面，它的实现不如最优。现代 API，带有诸如`ProcessHandle`等新类，使得几乎可以处理过程管理的所有方面。具体来说，我们介绍了过程，使用`ProcessHandle`接口，并回顾了一个示例过程控制器应用。

在本章中，我们将重点介绍 Java 的`StackWalker`API。API 支持普通程序很少需要的特殊功能。API 在一些非常特殊的情况下非常有用，比如框架提供的功能。因此，如果您想要一种有效的栈遍历方法，使您能够对栈跟踪信息进行可过滤的访问，那么您将喜欢使用`StackWalker`API。API 提供了对调用栈的快速优化访问，实现了对单个帧的延迟访问。

具体来说，我们将讨论以下主题：

*   Java 栈概述
*   栈信息的重要性
*   使用`StackWalker`
*   `StackFrame`
*   性能

# 技术要求

本章以及随后的章节以 Java18.9（也称为 Java11）为特色。Java 平台的标准版（SE）可以从 [Oracle 的官方下载站点](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

集成开发环境（IDE）包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。[IntelliJ IDEA 的社区版可从以下网站下载](https://www.jetbrains.com/idea/features/)。

# Java 栈概述

在深入研究`StackWalker`之前，让我们先介绍一下 Java 栈。我们将查看基本栈信息，而不是针对`StackWalker`。

Java 运行时有一个名为`Stack`的类，可以使用**后进先出**（**LIFO**）策略来存储对象。算术表达式是使用栈计算的。如果我们在代码中加上`A`和`B`，首先将`A`推送到**操作数栈**上，然后将`B`推送到操作数栈上，最后执行加法运算，取操作数栈最上面的两个元素并推送结果，`A`+`B`那里。

JVM 是用 C 编写的，并执行调用 C 函数并从那里返回。此调用返回序列使用**本机方法栈**与其他 C 程序一样进行维护。

最后，当 JVM 创建一个新线程时，它还会分配一个调用栈，其中包含一个帧，该帧依次包含本地变量、对上一个帧的引用以及对包含执行方法的类的引用。当调用一个方法时，会创建一个新的框架。当一个方法完成它的执行时，框架就被破坏了；换句话说，它返回或抛出一个异常。这个栈，**Java 虚拟机栈**，是`StackWalker`API 管理的栈。

# 栈信息的重要性

一般来说，我们在开发依赖调用方的代码时需要栈信息。拥有关于调用者的信息可以让我们的代码根据这些信息做出决策。在一般实践中，让功能依赖于调用者不是一个好主意。影响方法行为的信息应该可以通过参数获得。依赖调用方的代码开发应该相当有限。

JDK 使用 Java 应用不可用的本机方法访问栈信息。`SecurityManager`类是定义应用安全策略的类。此类检查是否允许反射 API 的调用方访问另一个类的非公共成员。要做到这一点，它必须能够访问调用者类，并通过受保护的本机方法实现这一点。

这是一个实现一些安全措施而不必遍历栈的示例。我们为外部开发人员打开代码，将其用作库。我们还调用库用户提供的类的方法，它们可能会回调到我们的代码。我们希望允许库用户调用某些代码，但前提是这些代码不是从我们的代码中调用的。如果我们不想让库使用代码直接访问某些代码，我们可以使用 Java 的模块化结构，而不导出包含不被调用的类的包。这就是我们设置额外条件的原因，即代码对来自外部的调用者可用，除非它们是由我们的代码调用的：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/31c242c4-8d21-4b3d-8785-2228ed9bee35.png)

隔离受保护代码

另一个例子是当我们想要访问一个记录器时。Java 应用使用许多不同的记录器，并且日志记录系统通常非常灵活，因此可以根据实际需要打开和关闭不同记录器的输出，以便对代码进行内省。最常见的做法是为每个类使用不同的记录器，记录器的名称通常是类的名称。这种做法非常普遍，日志框架甚至提供了记录器访问方法，这些方法接受对类本身的引用而不是名称。它本质上意味着获取记录器句柄的调用如下所示：

```java
private static final Logger LOG = Logger.getLogger(MyClass.class);
```

如果在获取新记录器的调用中忘记更改类名的名称，则在从现有类创建新类时可能会出现问题。这不是一个严重的问题，但它是常见的。在这种情况下，我们的代码将使用另一个类的记录器，它实际上可以工作，但在分析日志文件时可能会造成混乱。如果我们有一个方法返回名为调用方类的记录器，那就更好了。

让我们在接下来的两节中用示例代码片段继续探索栈信息。

# 示例-限制调用者

在本节中，我们将用两种方法开发一个示例库。`hello()`方法将`hello`打印到标准输出。`callMe()`方法接受`Runnable`作为参数并运行它。然而，第一种方法受到限制。它只在调用方完全在库之外时执行。如果调用方以调用库的方式获得控件，则抛出`IllegalCallerException`，可能是通过调用传递的`Runnable`的第二个方法。API 的实现很简单：

```java
package packt.java9.deep.stackwalker.myrestrictivelibrary;
public class RestrictedAPI {
  public void hello() {
    CheckEligibility.itIsNotCallBack();
    System.out.println("hello");
  }
  public void callMe(Runnable cb) {
    cb.run();
  }
}
```

执行资格检查的代码是在一个单独的类中实现的，以保持简单；我们将在本节稍后检查该代码。首先，让我们回顾一下用于开始演示的主要代码：

```java
package packt.java9.deep.stackwalker.externalcode;
import packt.java9.deep.stackwalker.myrestrictivelibrary.RestrictedAPI;

public class DirectCall {
  public static void main(String[] args) {
    RestrictedAPI api = new RestrictedAPI();
    api.hello();
    api.callMe(() -> { api.hello(); 
    });
  }
}
```

这段代码创建了我们的 API 类的一个实例，然后直接调用`hello()`方法。它应该可以工作，并且应该在屏幕上打印字符`hello`。下一行代码要求`callMe()`方法回调以 Lambda 表达式形式提供的`Runnable`。在这种情况下，调用将失败，因为调用方在库外部，但是从库内部调用的。

现在让我们看看资格检查是如何实现的：

```java
package packt.java9.deep.stackwalker.myrestrictivelibrary;
import static java.lang.StackWalker.Option.RETAIN_CLASS_REFERENCE;

public class CheckEligibility {
  private static final String packageName
    = CheckEligibility.class.getPackageName();
  private static boolean notInLibrary(StackWalker.StackFrame f) {
    return !inLibrary(f);
  }

  private static boolean inLibrary(StackWalker.StackFrame f) {
    return f.getDeclaringClass().getPackageName()
      .equals(packageName);
  }

  public static void itIsNotCallBack() {
    boolean eligible = StackWalker
      .getInstance(RETAIN_CLASS_REFERENCE)
      .walk(s -> s.dropWhile(CheckEligibility::inLibrary)
      .dropWhile(CheckEligibility::notInLibrary)
      .count() == 0
    );
    if (!eligible) {
      throw new IllegalCallerException();
    }
  }
}
```

`itIsNotCallBack()`方法是从`hello()`方法调用的方法。此方法创建`StackWalker`并调用`walk()`方法。`walk()`方法的参数是一个函数，它将`StackFrame`对象的`Stream`转换为`walk()`方法将返回的其他值。

一开始，这个参数设置似乎很复杂，很难理解。更合乎逻辑的做法是返回提供`StackFrame`对象的`Stream`，而不是强制调用者定义一个将其作为参数的函数。

示例代码使用 Lambda 表达式将函数定义为`walk()`方法的参数。Lambda 表达式的参数是流。因为这个流的第一个元素是实际的调用，所以我们放弃它。因为如果调用方不符合条件，也应该拒绝这些调用，即使对`hello()`方法的调用是通过库中已经存在的其他类和方法进行的，所以我们从框架中删除属于`CheckEligibility`类包中类的所有元素。这个包是`packt.java9.deep.stackwalker.myrestrictivelibrary`，在代码中，这个字符串存储在`packageName`字段中。结果流只包含来自库外部的`StackFrame`对象。我们把这些也扔下去，直到流耗尽，或者直到我们发现`StackFrame`又属于库。如果所有的元素都消失了，我们就好了。在这种情况下，`count()`的结果为零。如果我们在`StackFrame`中找到一个属于库的类，这意味着外部代码是从库中调用的，在这种情况下，我们必须拒绝工作。在这种情况下，变量`eligible`将是`false`，我们抛出一个异常，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/8da943bd-0406-4257-8bcb-2707259cb2a4.png)

`StackFrame`在库中找到的类

# 示例–为调用者获取记录器

在 Java 中，我们使用 API 来获取`Logger`。使用 API，模块可以为服务`LoggerFinder`提供实现，服务`LoggerFinder`可以返回实现`getLogger()`方法的`Logger`。这消除了库对特定记录器或记录器外观的依赖，这是一个巨大的优势。还有一个更小但仍然很烦人的问题需要我们在`getLogger()`方法的参数中再次写入类名。

为了避免这个繁琐的任务，我们创建了一个辅助类来查找调用者类并检索适合调用者类和模块的记录器。因为在这种情况下不需要栈跟踪中引用的所有类，所以我们将调用`StackWalker`类的`getCallerClass()`方法。我们在`packt.java9.deep.stackwalker.logretrieve`包中创建一个名为`Labrador`的类：

```java
package packt.java9.deep.stackwalker.logretriever;
import java.lang.System.Logger;
import java.lang.System.LoggerFinder;
import static java.lang.StackWalker.Option.RETAIN_CLASS_REFERENCE;

public class Labrador {
  public static Logger retrieve() {
    final Class clazz = StackWalker
      .getInstance(RETAIN_CLASS_REFERENCE)
      .getCallerClass();
    return LoggerFinder.getLoggerFinder().getLogger(
      clazz.getCanonicalName(), clazz.getModule());
  }
}
```

在 Java9 之前，这个问题的解决方案是从`Thread`类中获取`StackTrace`数组，并从中查找调用者类的名称。另一种方法是扩展`SecurityManager`，它有一个受保护的方法`getClassContext()`，该方法返回栈上所有类的数组。这两种解决方案都遍历栈并组成一个数组，尽管我们只需要数组中的一个元素。在`Logger`检索的情况下，这可能不是显著的性能损失，因为记录器通常存储在`private static final`字段中，因此在类初始化期间每个类初始化一次。在其他用例中，性能损失可能很大。

接下来，我们来看看`StackWalker`的细节。

# 与`StackWalker`合作

在本节中，您将熟悉如何使用`StackWalker`。本节将探讨以下主题：

*   获取`StackWalker`实例
*   枚举选项
*   访问类
*   `StackWalker`方法

# 获取`StackWalker`的实例

要遍历栈元素，我们需要一个`StackWalker`的实例。为此，我们调用`getInstance()`方法。如图所示，此方法有四个重载版本：

*   `static StackWalker getInstance()`
*   ``static StackWalker getInstance(StackWalker.Option option)``
*   `static StackWalker getInstance(Set<StackWalker.Option> options)`
*   `static StackWalker getInstance(Set<StackWalker.Option> options, int estimateDepth)`

第一个版本不接受任何参数，并返回一个`StackWalker`实例，让我们遍历正常的栈帧。这通常是我们感兴趣的。该方法的其他版本接受一个或多个`StackWalker`类中的`StackWalker.Option`枚举，有三个值：

*   `RETAIN_CLASS_REFERENCE`
*   `SHOW_REFLECT_FRAMES`
*   `SHOW_HIDDEN_FRAMES`

# 枚举选项

`RETAIN_CLASS_REFERENCE`、`SHOW_REFLECT_FRAMES`和`SHOW_HIDDEN_FRAMES`枚举选项具有自描述性名称，下面将对其进行说明。

# `RETAIN_CLASS_REFERENCE`

如果我们指定第一个选项的枚举常量，`RETAIN_CLASS_REFERENCE`作为`getInstance()`方法的参数，那么返回的实例将授予我们访问各个栈在遍历期间引用的类的权限。

# `SHOW_REFLECT_FRAMES`

`SHOW_REFLECT_FRAMES`枚举常量将生成一个遍历器，其中包含来自某个反射调用的帧。

# `SHOW_HIDDEN_FRAMES`

最后，枚举常量选项`SHOW_HIDDEN_FRAMES`将包括所有隐藏帧，其中包含反射调用以及为 Lambda 函数调用生成的调用帧。

下面是反射和隐藏框架的简单演示：

```java
package packt;
import static java.lang.StackWalker.Option.SHOW_HIDDEN_FRAMES;
import static java.lang.StackWalker.Option.SHOW_REFLECT_FRAMES;
public class Main {
```

允许我们执行此代码的`main`方法直接调用`simpleCall()`方法：

```java
public static void main(String[] args) {
  simpleCall();
}
```

`simpleCall()`方法只是调用，顾名思义：

```java
static void simpleCall() {
  reflectCall();
}
```

链中的下一个方法要复杂一些。虽然这也只调用下一个，但它使用反射：

```java
static void reflectCall() {
  try {
    Main.class.getDeclaredMethod("lambdaCall",
      new Class[0]).invoke(null, new Object[0]);
  } catch (Exception e) {
      throw new RuntimeException();
  }
}
```

在下一个示例中，我们有一个使用 Lambda 调用的方法：

```java
static void lambdaCall() {
  Runnable r = () -> {
    walk();
  };
  r.run();
}
```

实际行走前的最后一种方法称为`walk()`：

```java
static void walk() {
  noOptions();
  System.out.println();
  reflect();
  System.out.println();
  hidden();
}
```

前面的`walk()`方法依次调用三个方法。这些方法非常相似，如下所示：

```java
static void noOptions() {
  StackWalker
    .getInstance()
    .forEach(System.out::println);
}

static void reflect() {
  StackWalker
    .getInstance(SHOW_REFLECT_FRAMES)
    .forEach(System.out::println);
}

static void hidden() {
  StackWalker
    .getInstance(SHOW_HIDDEN_FRAMES)
    .forEach(System.out::println);
}
```

前面三种方法将帧打印到标准输出。他们使用`StackWalker`的`forEach()`方法。下面是栈遍历程序的输出：

```java
stackwalker/packt.Main.noOptions(Main.java:45)
stackwalker/packt.Main.walk(Main.java:34)
stackwalker/packt.Main.lambda$lambdaCall$0(Main.java:28)
stackwalker/packt.Main.lambdaCall(Main.java:30)
stackwalker/packt.Main.reflectCall(Main.java:19)
stackwalker/packt.Main.simpleCall(Main.java:12)
stackwalker/packt.Main.main(Main.java:8)
```

此输出仅包含属于代码中的调用的帧。`main()`方法调用`simpleCall()`，后者调用`reflectCall()`，后者依次调用`lambdaCall()`，后者调用 Lambda 表达式，后者调用`walk()`，依此类推。我们没有指定任何选项的事实并没有从栈中删除 Lambda 调用。我们执行了那个调用，所以它一定在那里。它删除的是 JVM 实现 Lambda 所需的额外栈帧。我们可以在下一个输出中看到，当选项为`SHOW_REFLECT_FRAMES`时，反射帧已经存在：

```java
stackwalker/packt.Main.reflect(Main.java:58)
stackwalker/packt.Main.walk(Main.java:36)
stackwalker/packt.Main.lambda$lambdaCall$0(Main.java:28)
stackwalker/packt.Main.lambdaCall(Main.java:30)
java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(NativeMethod)
java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
java.base/java.lang.reflect.Method.invoke(Method.java:547)
stackwalker/packt.Main.reflectCall(Main.java:19)
stackwalker/packt.Main.simpleCall(Main.java:12)
stackwalker/packt.Main.main(Main.java:8)
```

在这种情况下，区别在于我们可以看到，从`reflectCall()`方法到`lambdaCall()`方法的调用不是直接的。`reflectCall()`方法调用调用调用另一个名称相同的方法的`invoke()`方法，该方法在不同的类中定义，该方法反过来调用`invoke()`方法，该方法是 JVM 提供的本机方法。然后，我们终于找到了`lambdaCall()`方法。

在输出中，我们还可以看到这些反射调用属于`java.base`模块，而不是我们的`StackWalker`模块。

如果我们除了反射帧之外还包括隐藏帧，并指定选项`SHOW_HIDDEN_FRAMES`，那么我们将看到以下输出：

```java
stackwalker/packt.Main.hidden(Main.java:52)
 stackwalker/packt.Main.walk(Main.java:38)
stackwalker/packt.Main.lambda$lambdaCall$0(Main.java:28)
stackwalker/packt.Main$$Lambda$46/269468037.run(Unknown Source)
stackwalker/packt.Main.lambdaCall(Main.java:30)
java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(NativeMethod)
java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
java.base/java.lang.reflect.Method.invoke(Method.java:547)
stackwalker/packt.Main.reflectCall(Main.java:19)
stackwalker/packt.Main.simpleCall(Main.java:12)
stackwalker/packt.Main.main(Main.java:8)
```

这包括 JVM 用来执行 Lambda 调用的额外隐藏帧。此外，还包括反射框。

# 关于枚举常量的最后思考

我们还可以指定多个选项来提供一组选项。最简单的方法是使用`java.util.Set`接口的静态`of()`方法。这样，`RETAIN_CLASS_REFERENCE`选项可以与`SHOW_REFLECT_FRAMES`选项或`SHOW_HIDDEN_FRAMES`选项组合。

尽管从技术上讲可以将`SHOW_REFLECT_FRAMES`和`SHOW_HIDDEN_FRAMES`组合为一个选项集，但这样做并没有什么好处。后者包括前者，因此两者的结合与后者完全相同。

# 访问类

当我们想在栈遍历期间访问类对象时，我们必须指定`RETAIN_CLASS_REFERENCE`选项。虽然`StackFrame`接口定义了`getClassName()`方法，但可以使用`Class.forName()`方法访问名称为的类，这样做并不能保证`StackFrame`对象引用的类是由调用`Class.forName()`的代码所在的类装入器装入的。在某些特殊情况下，我们可能会得到由两个不同的类装入器装入的两个同名的不同类。

如果在创建`StackWalker`实例的过程中没有使用该选项，则返回类对象的方法将抛出`UnsupportedOperationException`异常。这样，`getDeclaringClass()`就不能用在`StackFrame`上，`getCallerClass()`不能用在`StackWalker`上。

# `walk()`方法

`StackWalker`类定义了`forEach()`方法，该方法期望`Consumer`（最好是以 Lambda 表达式的形式），该方法为向上遍历栈的栈跟踪的每个元素调用。`Consumer`方法的参数是`StackFrame`对象。

尽管名为`forEach`的方法也是由`Stream`接口定义的，并且`walk()`方法将`Stream`对象作为参数传递给它得到的函数，但我们不应混淆这两者。`StackWalker`中的`forEach()`方法是一种更简单的方法，大多数情况下是一种不太有效的方法，可以穿透栈跟踪的所有元素。

在大多数情况下，它的效率较低，因为它强制`StackWalker`实例获取栈跟踪的所有元素，这样`forEach()`方法就可以遍历每个元素到最后。如果我们知道我们不会遍历栈跟踪到最后，我们应该使用`walk()`方法，即以惰性的方式访问栈，从而为性能优化留下更多的空间。

`StackWalker`类有`walk()`方法，这是使其成为遍历器的定义方法。该方法接受由`StackWalker`调用的函数。`walk()`方法的返回值将是函数返回的对象。函数的参数是传递栈帧的`Stream<StackFrame>`。第一帧是包含`walk()`方法调用的帧，下一帧是调用包含`walk()`方法调用的帧，依此类推。

该函数可用于根据来自流的`StackFrame`对象计算一些值，并决定调用方是否有资格调用我们的代码。

在回顾了`walk()`方法之后，您可能会想，这个方法需要一个函数，而函数又得到一个`Stream<StackFrame>`作为参数，为什么它如此复杂。理想情况下，我们可以直接从`StackWalter`实例获取`Stream<StackFrame>`。最简单的方法是将流从函数传回。考虑以下示例：

```java
// EXAMPLE OF WHAT NOT TO DO!!!!
public static void itIsNotCallBack() {
  Stream<StackWalker.StackFrame> stream = StackWalker
    .getInstance(RETAIN_CLASS_REFERENCE)
    .walk(s -> s);
  // The following results in an EXCEPTION 
  boolean eligible = stream
    .dropWhile(CheckEligibility::inLibrary)
    .dropWhile(CheckEligibility::notInLibrary)
    .count() == 0;
  if (!eligible) {
    throw new IllegalCallerException();
  }
}
```

我们所做的只是直接从遍历器调用返回流，然后遍历流，然后执行相同的计算。我们的结果是`IllegalStateException`异常，而不是资格检查。

原因是`StackWalker`的实现高度优化。它不会复制整个栈来为流提供源信息。它是从实际的，活生生的栈中工作的。为此，必须确保在使用流时不修改栈。这与迭代集合时更改集合可能得到的`ConcurrentModificationException`异常非常相似。如果我们在调用栈中向上传递流，然后想要从中获取`StackFrame`，那么流将尝试从早已消失的栈帧中获取信息，因为我们从它所属的方法返回。这样，`StackWalker`就不会生成整个栈的快照，而是从实际栈开始工作，并且必须确保所需的栈部分不会更改。我们可以从函数中调用方法，这样我们可以在调用链中更深入地挖掘，但是在流被使用时，我们不能得到更高的值。

`StackWalker`类是`final`类，不能扩展。

# `StackFrame`

在前面的部分中，我们遍历了`StackFrame`元素并提供了示例代码片段。接下来，我们将更仔细地研究它。`StackFrame`是`StackWalker`类内部定义的接口。它定义了访问器，是一个转换器，可用于将信息转换为`StackTraceElement`。

接口定义的访问器如下：

*   `getClassName()`返回`StackFrame`表示的方法类的二进制名称。
*   `getMethodName()`返回`StackFrame`表示的方法名称。
*   `getDeclaringClass()`返回`StackFrame`表示的方法的类。如果在创建`StackWalker`实例时没有使用`Option.RETAIN_CLASS_REFERENCE`，则该方法将抛出`UnsupportedOperationException`。
*   `getByteCodeIndex()`获取包含`StackFrame`表示的方法的执行点的代码数组的索引。当查看命令行工具`javap`可以提供给我们的反汇编 Java 代码时，这个值的使用在 bug 搜索期间会很有帮助。这个值的编程使用只能对直接访问代码的字节码的应用、Java 代理或在运行时生成字节码的库有价值。如果方法是本机的，则该方法将返回一个负数。
*   `getFileName()`返回定义了`StackFrame`表示的方法的源文件名。
*   `getLineNumber()`返回源代码的行号。
*   如果`StackFrame`表示的方法是本机方法，`isNativeMethod()`返回`true`，否则返回`false`。

`StackFrame`不提供任何方法来访问该方法所属的对象。您无法访问由`StackFrame`表示的方法的参数和局部变量，并且没有其他方法可以实现这一点。这很重要。这样的访问太具侵入性，是不可能的。

# 性能

如果不考虑性能因素，我们对`StackWalker`的报道是不完整的。

`StackWalker`高度优化，不会产生大量未使用的内存结构。这就是为什么我们必须使用传递给`walker()`方法的函数作为参数的原因。这也是创建时，`StackTrace`不会自动转换为`StackTraceElement`的原因。只有当我们查询方法名，即特定的`StackTraceElement`的行号时，才会发生这种情况。理解这种转换需要花费大量的时间是很重要的，如果它在代码中用于某种调试目的，则不应将其留在那里。

为了使`StackWalker`更快，我们可以提供我们将在流中工作的`StackFrame`元素的估计数。如果我们不提供这样的估计，JDK 中的当前实现将使用八个预分配的`StackFrame`对象，当这些对象用完时，JDK 将分配更多的对象。JDK 将根据我们的估计分配元素的数量，除非我们估计的值大于 256。在这种情况下，JDK 将使用 256。

# 总结

在本章中，我们学习了如何使用`StackWalker`API，并检查了示例代码片段以加强我们的理解。我们对 API 的详细审查包括不同的使用场景、选项和信息。我们探讨了 API 的复杂性，并分享了如何使用和如何不使用该类。最后我们讨论了一些开发人员应该注意的相关性能问题。

在下一章中，我们将介绍与现代 Java 平台相关的十几种工具和工具增强。这些特色的变化将涵盖各种各样的工具和 API 的更新，这些工具和 API 旨在使使用 Java 进行开发变得更容易，并且能够创建优化的 Java 应用。我们将介绍新的 HTTP 客户端、对 Javadoc 和 Doclet API 的更改、新的 JavaScript 解析器、JAR 和 JRE 更改、新的 Java 级 JVM 编译器接口、对 TIFF 图像的支持、平台日志记录、XML 目录支持、集合、新的特定于平台的桌面功能、对方法处理的增强以及废弃注解。

# 问题

1.  Java 如何使用栈存储对象？
2.  Java 对调用返回序列使用什么栈？
3.  `StackWalker`API 管理什么栈？
4.  如何检索记录器？
5.  `getCallerClass()`方法属于哪一类？
6.  `StackWalker.Option`枚举的可能值是什么？
7.  `RETAIN_CLASS_REFERNCE`枚举用于什么？
8.  `SHOW_REFLECT_FRAMES`枚举用于什么？
9.  `SHOW_HIDDEN_FRAMES`枚举用于什么？
10.  `StackWalker`类怎么扩展？

# 十一、新工具和工具增强功能

在上一章中，我们学习了如何使用`StackWalker`API，并检查了示例代码片段以加强我们的理解。我们对 API 的详细审查包括不同的使用场景、选项和信息。我们探讨了 API 的复杂性和类用法的共享细节。在本章的结尾，我们介绍了与`StackWalker`API 相关的性能问题。

在本章中，我们将介绍十几种与现代 Java 平台相关的工具和工具增强。这些特色的变化将涵盖广泛的工具和 API 的更新，这些工具和 API 旨在简化 Java 开发，增强创建优化 Java 应用的能力。

更具体地说，我们将审查以下主题：

*   HTTP 客户端
*   Javadoc 和 Doclet API
*   mJRE 变更
*   JavaScript 解析器
*   多版本 JAR 文件
*   Java 级 JVM 编译器接口
*   TIFF 支持
*   平台日志记录
*   XML 目录
*   集合
*   特定于平台的桌面功能
*   增强的方法句柄
*   废弃的改进
*   本机头生成工具（`javah`）

# 技术要求

本章介绍 Java11，Java 平台的**标准版**（**SE**）可从 [Oracle 官方下载网站](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

IDE 包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

本章的源代码可以在 [GitHub 的 URL](https://github.com/PacktPublishing/Mastering-Java-11-Second-Edition) 上找到。

# 使用 HTTP 客户端

在本节中，我们将回顾 Java 的**超文本传输协议**（**HTTP**）客户端，从旧的 Java9 之前的客户端开始，然后深入到作为当前 Java 平台一部分的新 HTTP 客户端。最后，我们将看看当前 HTTP 客户端的局限性。需要这种方法来支持对变化的理解。

# Java9 之前的 HTTP 客户端

JDK1.1 版引入了支持 HTTP 特定特性的`HttpURLConnection`API。这是一个健壮的类，包含以下字段：

*   `chunkLength`
*   `fixedContentLength`

*   `HTTP_ACCEPTED`
*   `HTTP_BAD_GATEWAY`
*   `HTTP_BAD_METHOD`
*   `HTTP_BAD_REQUEST`
*   `HTTP_CLIENT_TIMEOUT`
*   `HTTP_CONFLICT`
*   `HTTP_CREATED`
*   `HTTP_ENTITY_TOO_LARGE`
*   `HTTP_FORBIDDEN`
*   `HTTP_GONE`
*   `HTTP_INTERNAL_ERROR`

*   `HTTP_LENGTH_REQUIRED`
*   `HTTP_MOVED_PERM`

*   `HTTP_MULT_CHOICE`
*   `HTTP_NO_CONTENT`
*   `HTTP_NOT_ACCEPTABLE`
*   `HTTP_NOT_AUTHORITATIVE`
*   `HTTP_NOT_FOUND`
*   `HTTP_NOT_IMPLEMENTED`
*   `HTTP_NOT_MODIFIED`
*   `HTTP_OK`
*   `HTTP_PARTIAL`
*   `HTTP_PAYMENT_REQUIRED`
*   `HTTP_PRECON_FAILED`

*   `HTTP_PROXY_AUTH`
*   `HTTP_REQ_TOO_LONG`

*   `HTTP_SEE_OTHER`
*   `HTTP_SERVER_ERROR`
*   `HTTP_UNAUTHORIZED`
*   `HTTP_UNAVAIABLE`
*   `HTTP_UNSUPPORTED_TYPE`
*   `HTTP_USE_PROXY`
*   `HTTP_VERSION`
*   `instanceFollowRedirects`
*   `method`
*   `responseCode`
*   `responseMessage`

从前面的字段列表中可以看到，已经有了对 HTTP 的强大支持。除了构造器之外，还有大量可用的方法，包括以下方法：

*   `disconnect()`
*   `getErrorStream()`
*   `getFollowRedirects()`
*   `getHeaderField(int n)`
*   `getHeaderFieldDate(String name, long Default)`
*   `getHeaderFieldKey(int n)`
*   `getInstanceFollowRedirects()`
*   `getPermission()`
*   `getRequestMethod()`
*   `getResponseCode()`
*   `getResponseMessage()`
*   `setChunkedStreamingMode(int chunklen)`
*   `setFixedLengthStreamingMode(int contentLength)`
*   `setFixedlengthStreamingMode(long contentLength)`
*   `setFollowRedirects(boolean set)`
*   `setInstanceFollowRedircts(boolean followRedirects)`
*   `setRequestMethod(String method)`
*   `usingProxy()`

前面列出的类方法是继承自`java.net.URLConnection`类和`java.lang.Object`类的方法的补充。

原来的 HTTP 客户端存在一些问题，这些问题使得它适合用新的 Java 平台进行更新。这些问题如下：

*   基本的`URLConnection`API 已经失效了一些协议，比如 Gopher 和 FTP，这些年来成为了一个日益严重的问题
*   `HttpURLConnection`API 早于 HTTP1.1，过于抽象，使其不易使用
*   HTTP 客户端的文档记录严重不足，使得 API 令人沮丧，难以使用
*   客户端一次只能在一个线程上运行
*   由于 API 早于 HTTP1.1，并且缺乏足够的文档，因此维护起来非常困难

现在我们知道以前的 HTTP 客户端有什么问题了，让我们看看当前的 HTTP 客户端。

# Java11 HTTP 客户端

为现代 Java 平台创建新的 HTTP 客户端有几个相关的目标，java9、10 和 11 提供了这些目标。下表列出了主要目标。这些目标分为易用性、核心功能、附加功能和性能等大类：

| 易用性 | API 旨在提供高达 90% 的 HTTP 相关应用要求。 |
| --- | --- |
| | 对于最常见的用例，新 API 是可用的，没有不必要的复杂性。 |
| | 包括一个简单的阻塞模式。 |
| | API 支持现代 Java 语言功能。 Lambda 表达式是一个与 Java 8 一起发布的主要新介绍，就是一个例子。 |
| 核心能力 |  支持 HTTPS/TLS |
| | 支持 HTTP/2 |
| | 提供与 HTTP 协议请求和响应相关的所有详细信息的可见性 |
| | 支持标准/通用认证机制 |
| | 提供头部接收事件通知 |
| | 提供响应体接收事件通知 |
| | 提供错误事件通知 |
| 附加功能 | 新的 API 可用于 WebSocket 握手 |
| | 它与当前的网络 API 一起执行安全检查 |
| 性能 | HTTP/1.1： |
| | 新 API 的性能必须至少与旧 API 一样有效。 |
| | 用作客户端 API 时，内存消耗不得超过 Apache HttpClient、Netty 和 Jetty 的内存消耗。 |
| | HTTP/2： |
| | 性能必须超过 HTTP/1.1。 |
| | 当用作客户端 API 时，新的性能必须达到或超过 Netty 和 Jetty 的性能。 性能下降不应该是新客户端的结果。 |
| | 用作客户端 API 时，内存消耗不得超过 Apache HttpClient、Netty 和 Jetty 的内存消耗。 |
| | 避免运行计时器线程。 |

# HTTP 客户端 API 的限制

HTTP 客户端 API 有一些故意的缺点。虽然这听起来可能有悖常理，但新的 API 并不打算完全取代当前的`HttpURLConnection`API。相反，新的 API 最终将取代当前的 API。

下面的代码片段提供了如何实现`HttpURLConnect`类以在 Java 应用中打开和读取 URL 的示例：

```java
/*
import statements
*/

public class HttpUrlConnectionExample {
  public static void main(String[] args) {
    new HttpUrlConnectionExample();
  }

  public HttpUrlConnectionExample() {
    URL theUrl = null;
    BufferedReader theReader = null;
    StringBuilder theStringBuilder;

    // put the URL into a String
    String theUrl = "https://www.packtpub.com/";

    // here we are creating the connection
    theUrl = new URL(theUrl);
    HttpURLConnection theConnection = (HttpURLConnection)
      theUrl.openConnection();

    theConnection.setRequestedMethod("GET");

    // add a delay
    theConnection.setReadTimeout(30000); // 30 seconds
    theConnection.connect();

    // next, we can read the output
    theReader = new BufferedReader(
      new InputStreamReader(theConnection.getInputStream()));
    theStringBuilder = new StringBuilder();

    // read the output one line at a time
    String theLine = null;
    while ((theLine = theReader.readLine() != null) {
      theStringBUilder.append(line + "\n");
    }

    // echo the output to the screen console
    System.out.println(theStringBuilder.toString());

    // close the reader
    theReader.close();
  }
}
. . .
```

为了简洁起见，前面的代码不包括异常处理。

以下是新 API 的一些特定限制：

*   并非所有与 HTTP 相关的功能都受支持。据估计，大约 10% 的 HTTP 协议没有被 API 公开。
*   标准/通用认证机制仅限于基本认证。
*   新 API 的首要目标是使用的简单性，这意味着性能改进可能无法实现。当然，不会出现性能下降，但也不太可能出现压倒性的改进。
*   不支持对请求进行过滤。
*   不支持对响应进行过滤。
*   新的 API 不包括可插入的连接缓存。
*   缺乏通用的升级机制。

# 了解 Javadoc 和 Doclet API

Javadoc 和 Doclet API 密切相关。Javadoc 是一个文档工具，DocletAPI 提供了一些功能，以便我们可以检查嵌入在库和程序源代码级别的 Javadoc 注释。在本节中，我们将回顾 DocletAPI（Java9 之前）的早期状态，然后探讨在当前 Java 平台中引入 DocletAPI 的更改。最后，我们将回顾 Javadoc。

# Java9 之前的 Doclet API

Java9 DocletAPI 之前的版本，或者`com.sun.javadoc`包，使我们能够查看源代码中的 Javadoc 注释。调用 Doclet 是通过使用`start`方法完成的。此方法的签名为`public static boolean start(RootDoc root)`。我们将使用`RootDoc`实例作为程序结构信息的容器。

为了调用 Javadoc，我们需要传递以下信息：

*   包名称
*   源文件名（用于类和接口）
*   访问控制选项可以是以下选项之一：
*   `package`
*   `private`
*   `protected`
*   `public`

当前面列出的项目用于调用`javadoc`时，提供一个文档集作为过滤列表。如果我们的目标是获得一个全面的、未经过滤的列表，我们可以使用`allClasses(false)`。

让我们回顾一个示例 Doclet：

```java
// Mandatory import statement
import com.sun.javadoc.*;

// We will be looking for all the @throws documentation tags
public class AllThrowsTags extends Doclet {

  // This is used to invoke the Doclet.
  public static boolean start(Rootdoc myRoot) {
    // "ClassDoc[]" here refers to classes and interfaces.
    ClassDoc[] classesAndInterfaces = myRoot.classesAndInterfaces();
    for (int i = 0; i < classesAndInterfaces.length; ++i) {
      ClassDoc tempCD = classesAndInterfaces[i];
      printThrows(tempCD.contructors());
      printThrows(tempCD.methods());
    }
    return true;
  }

  static void printThrows(ExecutableMemberDoc[] theThrows) {
    for (int i = 0; i < theThrows.length; ++i) {
      ThrowsTag[] throws = theThrows[i].throwsTags();
      // Print the "qualified name" which will be 
      // the class or interface name
      System.out.println(theThrows[i].qualifiedName());
      // A loop to print all comments with the 
      // Throws Tag that belongs to the previously
      // printed class or interface name
      for (int j = 0; j < throws.length; ++j) {
        // A println statement that calls three 
        // methods from the ThrowsTag Interface: 
        // exceptionType(), exceptionName(),
        // and exceptionComment().
        System.out.println("--> TYPE: " + 
          throws[j].exceptionType() +
          " | NAME: " + throws[j].exceptionName() +
          " | COMMENT: " + throws[j].exceptionComment());
      }
    }
  }
}
```

正如您通过完整注释的代码所看到的，访问`javadoc`内容相对容易。在前面的示例中，我们将通过在命令行中使用以下代码来调用`AllThrows`类：

```java
javadoc -doclet AllThrowsTags -sourcepath <source-location> java.util
```

我们的结果输出将由以下结构组成：

```java
<class or interface name>
TYPE: <exception type> | NAME: <exception name> | COMMENT: <exception comment>
TYPE: <exception type> | NAME: <exception name> | COMMENT: <exception comment>
TYPE: <exception type> | NAME: <exception name> | COMMENT: <exception comment>
<class or interface name>
TYPE: <exception type> | NAME: <exception name> | COMMENT: <exception comment>
TYPE: <exception type> | NAME: <exception name> | COMMENT: <exception comment>
```

# API 枚举

API 由一个枚举`LanguageVersion`组成，它提供 Java 编程语言版本。此枚举的常量是`Java_1_1`和`Java_1_5`。

# API 类

`Doclet`类提供了一个如何创建类来启动 Doclet 的示例。它包含一个空的`Doclet()`构造器和以下方法：

*   `languageVersion()`
*   `optionLength(String option)`
*   `start(RootDoc root)`
*   `validOptions(String[][] options, DocErrorReporter reporter)`

# API 接口

Doclet API 包含以下列出的接口。接口名称是不言自明的。有关其他详细信息，请参阅文档：


*   `AnnotatedType`
*   `AnnotationDesc`
*   `AnnotationDesc.ElementValuePair`
*   `AnnotationTypeDoc`
*   `AnnotationTypeElementDoc`
*   `AnnotationValue`

*   `ConstructorDoc`

*   `DoCErrorReporter`
*   `ExecutableMemberDoc`
*   `FieldDoc`
*   `MemberDoc`
*   `MethodDoc`
*   `PackageDoc`

*   `ParameterizedType`


*   `ProgramElementDoc`
*   `RootDoc`
*   `SeeTag`
*   `SerialFieldTag`
*   `SourcePosition`
*   `Tag`

*   `Type`

*   `WildcardType`


# 现有 Doclet API 的问题

先前存在的 Doclet API 存在几个问题，这些问题增加了对新 Doclet API 的需求：

*   它不适合于测试或并发使用。这源于它对静态方法的实现。
*   API 中使用的语言模型有几个限制，并且随着每次 Java 升级而变得更麻烦。
*   API 效率低下，主要是因为它大量使用子字符串匹配。
*   没有提及任何注释的具体位置。这使得诊断和故障排除变得困难。

# Java9 的 Doclet API

既然您已经很好地掌握了 Java9 之前存在的 Doclet API，那么让我们看看 Java9 平台已经做了哪些更改并交付了哪些更改。新的 Doclet API 在`jdk.javadoc.doclet`包中。

在较高级别上，Doclet API 的更改如下：

*   更新`com.sun.javadoc`Doclet API 以利用几个 JavaSE 和 JDKapi
*   更新`com.sun.tools.doclets.standard.Standard`Doclet 以使用新的 API
*   支持用于创建自定义`javadoc`标记的更新的 Taglet API

除上述更改外，新 API 还使用以下两个 API：

*   编译器树 API
*   语言模型 API

让我们在下面的部分中探讨每一个问题。

# 编译器树 API

编译树 API 在`com.sun.source.doctree`包中。它提供了几个接口来记录源代码级别的注释。这些 API 表示为**抽象语法树**（**AST**）。

有两个枚举，如下所示：

*   `AttributeTree.ValueKind`，具有以下常数：
*   `DOUBLE`
*   `EMPTY`
*   `SINGLE`
*   `UNQUOTED`

*   `DocTree.Kind`，具有以下常数：
*   `ATTRIBUTE`
*   `AUTHOR`
*   `CODE`
*   `COMMENT`
*   `DEPRECATED`
*   `DOC_COMMENT`
*   `DOC_ROOT`
*   `END_ELEMENT`
*   `ENTITY`
*   `ERRONEOUS`
*   `EXCEPTION`
*   `IDENTIFIER`
*   `INHERIT_DOC`
*   `LINK`
*   `LINK_PLAIN`
*   `LITERAL`
*   `OTHER`
*   `PARAM`
*   `REFERENCE`
*   `RETURN`
*   `SEE`
*   `SERIAL`
*   `SERIAL_DATA`
*   ``SERIAL_FIELD``
*   `SINCE`
*   `START_ELEMENT`
*   `TEXT`
*   `THROWS`
*   `UNKNOWN_BLOCK_TAG`
*   `UNKNOWN_INLINE_TAG`
*   `VALUE`
*   `VERSION`

`com.sun.source.doctree`包包含几个接口。具体见下表：

| **接口名称** | **扩展** | **所用于的树节点** | **非继承方法** |
| --- | --- | --- | --- |
| `AttributeTree` | `DocTree` | HTML 元素 | `getName(), getValue(), getValueKind()` |
| `AuthorTree` | `BlockTagTree, DocTree` | `@author`块标签 | `getName()` |
| `BlockTagTree` | `DocTree` | 不同类型的块标记的基类 | `getTagName()` |
| `CommentTree` | `DocTree` | 带有以下 HTML 标记的嵌入式 HTML 注释-`<!--text-->` | `getBody()` |
| `DeprecatedTree` | `BlockTagTree` | `@deprecated`块标签 | `getBody()` |
| `DocCommentTree` | `DocTree` | 正文块标记 | `getBlockTags(), getBody(), getFirstSentence()` |
| `DocRootTree` | `InlineTagTree` | `@docroot`内联标签 | 不适用 |
| `DocTree` | 不适用 | 所有用户的通用接口 | `accept(DocTreeVisitor<R,D>visitor,Ddata), getKind()` |
| `DocTreeVisitor<R,P>` | 药方： | `R`=访问者方法的返回类型；`P`=附加参数的类型 | `visitAttribute(AttributeTree node, P p)`、`visitAuthor(AuthorTree node, P p)`、`visitComment(CommentTree node, P p)`、`visitDeprecated(DeprecatedTree node, P p)`、`visitDocComment(DocCommentTree node, P p)`、`visitDocRoot(DocRootTree node, P p)`、`visitEndElement(EndElementTree node, P p)`、`visitEntity(EntityTree node, P p)`、`visitErroneous(ErroneousTree node, P p)`、`visitIdentifier(IdentifierTree node, P p)`、`visitInheritDoc(InheritDocTree node, P p)`、`visitLink(LinkTree node, P p)`、`visitLiteral(LiteralTree node, P p)`、`visitOther(DocTree node, P p)`、`visitParam(ParamTree node, P p)`、`visitReference(ReferenceTree node, P p)`、`visitReturn(ReturnTree node, P p)`、`visitSee(SeeTree node, P p)`、`visitSerial(SerialTree node, P p)`、`visitSerialData(SerialDataTree node, P p)`、`visitSerialField(SerialFieldTree node, P p)`、`visitSince(SinceTree node, P p)`、`visitStartElement(StartElementTree node, P p)`、`visitText(TextTree node, P p)`、`visitThrows(ThrowsTree node, P p)`、`visitUnknownBlockTag(UnknownBlockTagTree node, P p)`，`visitUnknownInlineTag(UnknownInlineTagTree node, P p), visitValue(ValueTree node, P p), visitVersion(VersionTree node, P p) ` |
| `EndElementTree` | `DocTree` | HTML 元素`</name>`的结尾 | `getName()` |
| `EntityTree` | `DocTree` | HTML 实体 | `getName()` |
| `ErroneousTree` | `TextTree` | 这是用于格式错误的文本 | `getDiagnostic()` |
| `IdentifierTree` | `DocTree` | 注释中的标识符 | `getName()` |
| `InheritDocTree` | `InlineTagTree` | `@inheritDoc`内联标签 | 不适用 |
| `InlineTagTree` | `DocTree` | 内联标记的公共接口 | `getTagName()` |
| `LinkTree` | `InlineTagTree` | `@link`或`@linkplan`内联标签 | `getLabel(), getReference()` |
| `LiteralTree` | `InlineTagTree` | `@literal`或`@code`内联标签 | `getBody()` |
| `ParamTree` | `BlockTagTree` | `@param`块标签 | `getDescription(), getName(), isTypeParameter()` |
| `ReferenceTree` | `DocTree` | 用于引用 Java 语言元素 | `getSignature()` |
| `ReturnTree` | `BlockTagTree` | `@return`块标签 | `getDescription()` |
| `SeeTree` | `BlockTagTree` | `@see`块标签 | `getReference()` |
| `SerialDataTree` | `BlockTagTree` | `@serialData`块标签 | `getDescription()` |
| `SerialFieldTree` | `BlockTagTree` | `@serialData`块标签和`@serialField`字段名称和说明 | `getDescription(), getName(), getType()` |
| `SerialTree` | `BlockTagTree` | `@serial`块标签 | `getDescription()` |
| `SinceTree` | `BlockTagTree` | `@since`块标签 | `getBody()` |
| `StartElementTree` | `DocTree` | HTML 元素`< name [attributes] [/] >`的开头 | `getAttributes(), getName(), isSelfClosing()` |
| `TextTree` | `DocTree` | 纯文本 | `getBody()` |
| `ThrowsTree` | `BlockTagTree` | `@exception`或`@throws`块标签 | `getDescription(), getExceptionname()` |
| `UnknownBlockTagTree` | `BlockTagTree` | 无法识别的内联标记 | `getContent()` |
| `UnknownInlineTagTree` | `InlineTagTree` | 无法识别的内联标记 | `getContent()` |
| `ValueTree` | `InlineTagTree` | `@value`内联标签 | `getReference()` |
| `VersionTree` | `BlockTagTree` | `@version`块标签 | `getBody()` |

# 语言模型 API

语言模型 API 在`java.lang.model`包中。它包括用于语言处理和语言建模的包和类。它由以下组件组成：

*   `AnnotatedConstruct`接口
*   `SourceVersion`枚举
*   `UnknownEntityException`异常

下面三节将进一步探讨这些语言模型 API 组件中的每一个。

# `AnnotatedConstruction`接口

`AnnotatedConstruction`接口为语言模型 API 提供了一个可注解的构造，该 API 自版本 1.8 以来一直是 Java 平台的一部分。适用于元素（接口`Element`）或类型（接口`TypeMirror`）的构造，每个构造的注解不同，如下表所示：

| **构造类型** | **接口** | **注释** |
| --- | --- | --- |
| `element` | `Element` | 宣言 |
| `type` | `TypeMirror` | 基于类型名的使用 |

`AnnotatedConstruction`接口有三种方式：

*   `getAnnotation(Class<A> annotationType)`：返回构造的注解类型
*   `getAnnotationMirrors()`：此方法返回构造上的注解列表
*   `getAnnotationsByType(Class<A> annotationType)`：此方法返回构造的相关注解

# `SourceVersion`枚举

`SourceVersion`枚举由以下常量组成：

*   `RELEASE_0`
*   `RELEASE_1`
*   `RELEASE_2`
*   `RELEASE_3`
*   `RELEASE_4`
*   `RELEASE_5`
*   `RELEASE_6`
*   `RELEASE_7`
*   `RELEASE_8`
*   `RELEASE_9`

预计随着 Java 平台的正式发布，`SourceVersion`枚举将更新为包含`RELEASE_10`和`RELEASE_11`。

此枚举还包含以下几种方法：

**方法名称**：`isIdentifier`：

```java
public static boolean isIdentifier(CharSequence name)
```

如果参数字符串是 Java 标识符或关键字，则返回`true`。

**方法名称**：`isKeyword`：

```java
public static boolean isKeyword(CharSequence s)
```

如果给定的`CharSequence`是文本或关键字，则此方法返回`true`。

**方法名称**：`isName`：

```java
public static boolean isName(CharSequence name)
```

如果`CharSequence`是有效名称，则返回`true`。

**方法名称**：`latest`：

```java
public static SourceVersion latest()
```

此方法返回用于建模的最新源版本。

**方法名称**：`latestSupported`：

```java
public static SourceVersion latestSupported()
```

此方法返回可完全支持建模的最新源代码版本。

**方法名称**：`valueOf`：

```java
public static SourceVersion valueOf(String name)
```

此方法基于提供的参数字符串返回枚举常量。

您应该知道，`value(String name)`方法抛出两个异常：`IllegalArgumentException`和`NullPointerException`。

**方法名称**：`values`：

```java
public static SourceVersion[] values()
```

此方法返回枚举常量的数组。

# `UnknownEntityException`

`UnknownEntityException`类扩展了`RuntimeException`，是未知异常的超类。类构造器如下所示：

```java
protected UnknownEntityException(String message)
```

构造器使用作为字符串参数提供的消息创建一个新的`UnknownEntityException`实例。该方法不接受其他参数。

这个类没有自己的方法，但是从`java.lang.Throwable`和`class.java.lang.Object`类继承方法，如下所示：

`java.lang.Throwable`类方法如下：

*   `addSuppressed()`
*   `fillInStackTrace()`
*   `getCause()`
*   `getLocalizedMessage()`
*   `getMessage()`
*   `getStackTrace()`
*   `getSuppressed()`
*   `initCause()`
*   `printStackTrace()`
*   `setStackTrace()`
*   `toString()`

`java.lang.Object`类方法如下：

*   `clone()`
*   `equals()`
*   `finalize()`
*   `getClass()`
*   `hashCode()`
*   `notify()`
*   `notifyAll()`
*   `wait()`

# 使用 HTML5 JavaDoc

Javadoc 工具已针对现代 Java 平台（定义为 Java9 及更高版本）进行了更新。除了 HTML4 之外，它还可以生成 HTML5 标记输出。Javadoc 工具提供了对 HTML4 和 HTML5 的支持。从 Java10 开始，HTML5 是默认的输出标记格式。

下面的简短 Java 应用只是生成一个由`319`高的`319`宽的帧。这里显示的是没有任何 Javadoc 标记的，我们将在本节后面讨论：

```java
import javax.swing.JFrame;
import javax.swing.WindowConstants;

public class JavadocExample {

  public static void main(String[] args) {
    drawJFrame();
  }

  public static void drawJFrame() {
    JFrame myFrame = new JFrame("Javadoc Example");
    myFrame.setSize(319,319);
    myFrame.setDefaultCloseOperation(
      WindowConstants.EXIT_ON_CLOSE);
    myFrame.setVisible(true);
  }
}
```

完成包或类后，可以使用 Javadoc 工具生成 Javadoc，可以从命令行或 IDE 中运行位于 JDK`/bin`目录中的 Javadoc 工具。每个 IDE 处理 Javadoc 生成的方式都不同。例如，在 Eclipse 中，您可以从下拉菜单中选择“项目”，然后选择“生成 JavaDoc”。在 IntelliJ IDEA IDEA 中，选择“工具”下拉菜单，然后选择“生成 JavaDoc”。

下面的截图显示了生成 Javadoc 功能的 IntelliJ IDEA 接口。如您所见，`-html5`命令行参数已包含：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/ee0c059a-46ae-45ba-8171-347dbb1e8a78.png)

生成 Javadoc

单击“确定”按钮时，您将看到一系列状态消息，如以下示例所示：

```java
"C:\Program Files\Java\jdk-9\bin\javadoc.exe" -public -splitindex -use -author -version -nodeprecated -html5 @C:\Users\elavi\AppData\Local\Temp\javadoc1304args.txt -d C:\Chapter11\JDOutput
Loading source file C:\Chapter11\src\JavadocExample.java...
Constructing Javadoc information...
Standard Doclet version 9
Building tree for all the packages and classes...
Generating C:\Chapter11\JD-Output\JavadocExample.html...
Generating C:\Chapter11\JD-Output\package-frame.html...
Generating C:\Chapter11\JD-Output\package-summary.html...
Generating C:\Chapter11\JD-Output\package-tree.html...
Generating C:\Chapter11\JD-Output\constant-values.html...
Generating C:\Chapter11\JD-Output\class-use\JavadocExample.html...
Generating C:\Chapter11\JD-Output\package-use.html...
Building index for all the packages and classes...
Generating C:\Chapter11\JD-Output\overview-tree.html...
Generating C:\Chapter11\JD-Output\index-files\index-1.html...
Generating C:\Chapter11\JD-Output\index-files\index-2.html...
Generating C:\Chapter11\JD-Output\index-files\index-3.html...
Building index for all classes...
Generating C:\Chapter11\JD-Output\allclasses-frame.html...
Generating C:\Chapter11\JD-Output\allclasses-frame.html...
Generating C:\Chapter11\JD-Output\allclasses-noframe.html...
Generating C:\Chapter11\JD-Output\allclasses-noframe.html...
Generating C:\Chapter11\JD-Output\index.html...
Generating C:\Chapter11\JD-Output\help-doc.html...
javadoc exited with exit code 0
```

一旦 Javadoc 工具退出，就可以查看 Javadoc 了。以下是基于先前提供的代码生成的内容的屏幕截图。如您所见，它的格式与 Oracle 的正式 Java 文档的格式相同：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/483343ad-839b-43bd-ba78-3da44cde0dea.png)

Javadoc 示例

当我们生成 Javadoc 时，创建了多个文档，如以下屏幕截图中提供的目录树所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/240fe7f5-0c0a-4a01-b1db-44e042d1b766.png)

Javadoc 目录树

您还可以添加 Javadoc 工具识别的可选标记。此处提供了这些标签：

*   `@author`
*   `@code`
*   `@deprecated`
*   `@docRoot`
*   `@exception`
*   ``@inheritDoc``
*   `@link`
*   ``@linkplain``
*   `@param`
*   `@return`
*   `@see`
*   `@serial`
*   `@serialData`
*   `@serialField`
*   `@since`
*   `@throws`
*   `@value`
*   `@version`

有关如何为 Javadoc 工具编写文档注释的更多信息，[请访问 Oracle 的官方说明](http://www.oracle.com/technetwork/articles/java/index-137868.html)。

# Javadoc 搜索

在 Java9 之前，标准 Doclet 生成的 API 文档页面很难导航。除非您非常熟悉这些文档页面的布局，否则您可能会使用基于浏览器的查找功能来搜索文本，这被认为是笨拙和次优的。

当前平台包括一个搜索框作为 API 文档的一部分。此搜索框由标准 Doclet 授予，可用于搜索文档中的文本。这为开发人员提供了极大的便利，可能会改变我们对 Doclet 生成的文档的使用。

通过新的 Javadoc 搜索功能，我们可以搜索以下索引组件：

*   模块名称
*   包名称
*   类型
*   成员
*   使用新的`@index`内联标签索引的术语/短语

# 大小写搜索

Javadoc 搜索功能通过使用驼峰大小写搜索提供了一个很好的快捷方式。例如，我们可以搜索`openED`来找到`openExternalDatabase()`方法。

# 对多重 JRE 功能的更改

**mJRE**（简称**多重 JRE**）特性以前用于指定启动应用的特定 JRE 版本或版本范围。我们可以通过命令行选项`-version`或者通过 JAR 文件清单中的一个条目来实现这一点。以下流程图说明了根据我们的选择所发生的情况：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/e96e35e9-c105-4eaf-b741-0e69b856ac91.png)

多 JRE 流

这个功能是在 JDK5 中引入的，在该版本或 JDK9 之前的任何后续版本中都没有完整的文档记录。

现代平台引入了以下具体变化：

*   已删除 mJRE 功能。
*   现在，只要使用`-version`命令行选项，启动器就会产生错误。这是一个终端错误，处理将无法继续。
*   在 Java9 中，如果 JAR 的清单中有一个`-version`条目，就会产生一个警告。警告不会停止执行。
*   在 Java10 和 Java11 中，清单文件中存在一个`-version`条目将导致终端错误。

# JavaScript 解析器

Java 平台最近的一个变化是为 Nashorn 的 ECMAScript AST 创建了一个 API。在本节中，我们将分别介绍 Nashorn、ECMAScript，然后介绍解析器 API。

# Nashorn

Oracle Nashorn 是 Oracle 用 Java 开发的 JVM 的 JavaScript 引擎。它是与 Java8 一起发布的，旨在为开发人员提供一个高效、轻量级的 JavaScript 运行时引擎。使用这个引擎，开发人员能够在 Java 应用中嵌入 JavaScript 代码。在 Java8 之前，开发人员可以访问 Netscape 创建的 JavaScript 引擎。该引擎于 1997 年推出，由 Mozilla 维护。

Nashorn 既可以用作命令行工具，也可以用作 Java 应用中的嵌入式解释器。让我们看看这两个例子

Nashorn 是德语中犀牛的意思。这个名字来源于 Mozilla 基金会的 Rhino JavaScript 引擎。据说犀牛起源于一本书封面上的动物图片。把这个放在有趣的事实下面。

# 使用 Nashorn 作为命令行工具

Nashorn 可执行文件`jjs.exe`位于`\bin`文件夹中。要访问它，您可以导航到该文件夹，或者，如果您的系统路径设置正确，您可以通过在系统的终端/命令提示符窗口中输入`jjs`命令来启动 Shell：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/86f9e555-1bc7-4bbc-bbb5-43b719abda1f.png)

Nashorn 可执行文件的位置

在这里，您可以看到一个打开的终端窗口，它首先检查 Java 的版本，然后使用`jjs -version`命令启动 Nashorn shell。在本例中，Java 和 Nashorn 的版本都是 1.8.0.121。或者，我们可以简单地用`jjs`命令启动 Nashorn，Shell 将在没有版本标识的情况下打开：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/c363b799-e305-4757-ac57-55a76dadfaad.png)

用`jjs`命令启动 Nashorn

接下来，让我们创建一个简短的 JavaScript 并使用 Nashorn 运行它。考虑以下具有三行简单输出的简单 JavaScript 代码：

```java
var addtest = function() {
  print("Simple Test");
  print("This JavaScript program adds the 
    numbers 300 and 19.");
  print("Addition results = " + (300 + 19));
}
addtest();
```

为了让 Java 运行这个 JavaScript 应用，我们将使用`jjs addtest.js`命令。下面是输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/1763415e-3938-41c6-9775-803bd89973d4.png)

用 Java 运行 JavaScript

你可以对 Nashorn 做很多事。在终端/命令提示符窗口中，我们可以使用`-help`选项执行`jjs`，以查看命令行命令的完整列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/c4349d9a-0284-4fcd-a5b5-5ca4a3eec19e.png)

`-help`组件

如您所见，使用`-scripting`选项使我们能够通过使用 Nashorn 作为文本编辑器来创建脚本。使用 Nashorn 时，有几个内置函数非常有用：

*   `echo()`：类似于`System.out.print()`Java 方法
*   `exit()`：这是 Nashorn 的出口
*   `load()`：从给定路径或 URL 加载脚本
*   `print()`：类似于`System.out.print()`Java 方法
*   `readFull()`：读取文件的内容
*   `readLine()`：读取`stdin`中的一行
*   `quit()`：这是 Nashorn 的出口

# 使用 Nashorn 作为嵌入式解释器

与将 Nashorn 用作命令行工具相比，Nashorn 更常用的用法是将其用作嵌入式解释器。`javax.script`API 是公共的，可以通过`nashorn`标识符访问。下面的代码演示了如何在 Java 应用中访问 Nashorn、定义 JavaScript 函数和获取结果：

```java
// required imports
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class EmbeddedAddTest {

  public static void main(String[] args) 
    throws Throwable {
    // instantiate a new ScriptEngineManager
    ScriptEngineManager myEngineManager =
      new ScriptEngineManager();

    // instantiate a new Nashorn ScriptEngine
    ScriptEngine myEngine = myEngineManager.
      getEngineByName("nashorn");

    // create the JavaScript function
    myEngine.eval("function addTest(x, y) 
      { return x + y; }");

    // generate output including a call to the 
    // addTest function via the engine
    System.out.println("The addition results are:
      " + myEngine.eval("addTest(300, 19);"));
  }
}
```

以下是控制台窗口中提供的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/3a0403b1-19ba-4b4a-bb52-1d4dca98f686.png)

控制台输出

这是一个简单的例子，让您了解嵌入使用 Nashorn 的可能性。甲骨文的官方文档中有大量的例子。

# ECMAScript 

**ECMA**（简称**欧洲计算机制造商协会**）成立于 1961 年，是一个信息系统和通信系统的标准组织。今天，ECMA 继续制定标准并发布技术报告，以帮助标准化消费电子、信息系统和通信技术的使用方式。ECMA 有 400 多项标准，其中大部分已被采用。

你会注意到 ECMA 并不是用所有的大写字母拼写的，因为它不再被认为是首字母缩写。1994 年**欧洲计算机制造商协会**正式更名为 **ECMA**。

ECMAScript（也称为 ES）创建于 1997 年，是一种脚本语言规范。JavaScript 实现了此规范，包括以下内容：

*   补充技术
*   库
*   脚本语言语法
*   语义

# 分析器 API

Java 平台最近的一个变化是为 Nashorn 的 ECMAScript 抽象语法树提供了特定的支持。新 API 的目标是提供以下内容：

*   表示 Nashorn 语法树节点的接口
*   创建可以用命令行选项配置的解析器实例的能力
*   用于与 AST 节点接口的访问者模式 API
*   使用 API 的测试程序

新的 API`jdk.nashorn.api.tree`是为了允许将来对 Nashorn 类进行更改而创建的。在新的解析器 API 之前，IDEs 使用 Nashorn 的内部 AST 表示进行代码分析。根据 Oracle 的说法，`jdk.nashorn.internal.ir`包的使用阻止了 Nashorn 内部类的现代化。

下面是新的`jdk.nashorn.api.tree`包的类层次结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/9f08b304-b258-4cc9-b27d-9927d409d174.png)

`jdk.nashorn.api.tree`类层次结构

下图说明了新 API 的复杂性，具有完整的接口层次结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/7c9b2874-c046-472e-b5dc-897727491d35.png)

Nashorn 接口层次结构

`jdk.nashorn.api.tree`包的最后一个组件是枚举层次结构，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/b0a47229-1548-4f50-9827-6235a731389d.png)

枚举层次结构

# 多版本 JAR 文件

JAR 文件格式已经在 Java 平台中进行了扩展，现在允许在一个 JAR 文件中存在多个版本的类文件。类版本可以特定于 Java 发布版本。这种增强允许开发人员使用一个 JAR 文件来存放多个版本的软件

JAR 文件增强包括以下内容：

*   支持`JarFile`API
*   支持标准类装入器

对 JAR 文件格式的更改导致了对核心 Java 工具的必要更改，以便它们能够解释新的多版本 JAR 文件。这些核心工具包括：

*   `javac`
*   `javap`
*   `jdeps`

最后，新的 JAR 文件格式支持模块化，这是现代 Java 平台的关键特性。对 JAR 文件格式的更改并没有导致相关工具或进程的性能降低。

# 识别多版本 JAR 文件

多版本 JAR 文件将有一个新属性，`Multi-Release: true`。该属性将位于 JAR`MANIFEST.MF`主节中

标准 JAR 文件和多版本 JAR 文件的目录结构不同。下面是一个典型的 JAR 文件结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/f2774198-f409-4d54-96d0-365155d95084.png)

Javadoc 目录树

下图显示了新的多版本 JAR 文件结构，其中包含 Java8 和 Java9 的特定于 Java 版本的类文件：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/8739ea3b-444b-443c-a81e-5eae4587f12f.png)

JAR 文件结构

# 相关 JDK 更改

为了支持新的多版本 JAR 文件格式，必须对 JDK 进行一些更改。这些变化包括：

*   `URLClassLoader`是基于 JAR 的，经过修改，可以从指定的版本中读取类文件。
*   新的基于模块的类加载器是 Java9 的新成员，它可以从指定的版本读取类文件。
*   修改了`java.util.jar.JarFile`类，以便从多版本 JAR 文件中选择适当的类版本。
*   jarURL 方案的协议处理器被修改，以便它从多版本 JAR 文件中选择适当的类版本。
*   Java 编译器`javac`是用来读取类文件的已识别版本的，这些版本识别是通过使用`JavacFileManager`API 和`ZipFileSystem`API 的`-target`和`-release`命令行选项来完成的。
*   为了利用`JavacFileManager`API 和`ZipFileSystem`API 的变化，对以下工具进行了修改：
*   `javah`：生成 C 头文件和源文件
*   `schemagen`：这是 Java 类中名称空间的模式生成器
*   `wsgen`：这是 Web 服务部署的解析器

*   更新了`javap`工具以支持新的版本控制模式。
*   修改了`jdeps`工具以支持新的版本控制模式。
*   JAR 打包工具集也相应地更新了。该工具集由`pack200`和`unpack200`组成。
*   当然，JAR 工具得到了增强，因此可以创建多版本 JAR 文件。

所有相关文档都已更新，以支持建立和支持新的多版本 JAR 文件格式所涉及的所有更改。

# Java 级 JVM 编译器接口

基于 Java 的 **JVM 编译器接口**（**JVMCI**）允许 Java 编译器（必须是用 Java 编写的）被 JVM 用作动态编译器。

JVMCI 需求背后的原因是，它将是一个高度优化的编译器，不需要低级语言特性。一些 JVM 子系统需要低级功能，比如垃圾收集和字节码解释。所以，JVMCI 是用 Java 编写的，而不是用 C 或 C++ 编写的。这提供了 Java 一些最强大功能的附带好处，例如：

*   异常处理
*   既免费又健壮的 IDE
*   内存管理
*   运行时扩展性
*   同步
*   单元测试支持

由于 JVMCI 是用 Java 编写的，因此可以说维护起来更容易。

JVMCI API 有三个主要组件：

*   虚拟机数据结构访问
*   安装已编译代码及其元数据
*   使用 JVM 的编译系统

JVMCI 实际上在某种程度上存在于 Java8 中。JVMCIAPI 只能通过在引导类路径上处理代码的类加载器进行访问。在 Java9 中，这种情况发生了变化。它在当前的 Java 平台上仍然是实验性的，但是更容易访问。为了启用 JVMCI，必须使用以下一系列命令行选项：

```java
-XX:+UnlockExperimentalVMOptions -XX:+EnableJVMCI -XX:+UseJVMCICompiler -Djvmci.Compiler=<name of compiler>
```

Oracle 将 JVMCI 保持在 Java9 中的实验性，以允许进一步的测试，并为开发人员提供最高级别的保护。

# `BeanInfo`注解

`@beaninfo`Javadoc 标签已经被更合适的注解所取代。此外，这些新注解现在在运行时被处理，这样就可以动态生成`BeanInfo`类。Java 的模块化导致了这种变化。自定义`BeanInfo`类的创建已经简化，客户端库已经模块化。

为了充分把握这一变化，我们将在进一步讨论本 JEP 之前回顾`JavaBean`、`BeanProperty`和`SwingContainer`。

# `JavaBean`

`JavaBean`是一个 Java 类。与其他 Java 类一样，`JavaBean`是可重用代码。它们在设计上是独特的，因为它们将多个对象封装成一个对象。`JavaBean`类必须遵循三个约定：

*   构造器不应接受任何参数
*   它必须是可序列化的
*   它的属性必须包含更改器和访问器方法

下面是一个例子`JavaBean`类：

```java
public class MyBean implements java.io.Serializable {

  // instance variables
  private int studentId;
  private String studentName;

  // no-argument constructor
  public MyBean() {
  }

  // mutator/setter
  public void setStudentId(int theID) {
    this.studentId = theID;
  }

  // accessor/getter
  public int getStudentId() {
    return studentId;
  }

  // mutator/setter
  public void setStudentName(String theName) {
    this.studentName = theName;
  }

  // accessor/getter
  public String getStudentName(){
    return studentName;
  }
}
```

访问`JavaBean`类就像使用更改器和访问器方法一样简单。这对您来说可能并不新鲜，但很可能您不知道您创建的那些经过仔细编码的类被称为`JavaBean`类。

# `BeanProperty`

`BeanProperty`是注解类型。我们使用这个注解来指定一个属性，这样我们就可以自动生成`BeanInfo`类。这是一个相对较新的 Java 注解，从 Java9 开始

`BeanProperty`注解具有以下可选元素：

*   `boolean bound`
*   `String description`
*   `String[] enumerationValues`
*   `boolean expert`
*   `boolean hidden`
*   `boolean preferred`
*   `boolean required`
*   `boolean visualUpdate`

# `SwingContainer`

`SwingContainer`是注解类型。我们使用这个注解来指定与 Swing 相关的属性，这样我们就可以自动生成`BeanInfo`类。

`SwingContainer`注解具有以下可选元素：

*   `String delegate`
*   `boolean value`

现在我们已经复习了`JavaBean`、`BeanProperty`和`SwingContainer`，让我们来看看`BeanInfo`类。

# `BeanInfo`类

在大多数情况下，`BeanInfo`类是在运行时自动生成的。例外是`Swing`类。这些类基于`@beaninfo`Javadoc 标记生成`BeanInfo`类。这是在编译时完成的，而不是在运行时。从 Java9 开始，`@beaninfo`标记被`@interface JavaBean`、`@interface BeanProperty`和`@interface SwingContainer`注解所取代。

这些新注解用于根据前面部分中提到的可选元素设置相应的属性。例如，下面的代码片段设置了`SwingContainer`的属性：

```java
package javax.swing;

public @interface SwingContainer {
  boolean value() default false;
  String delegate() default "";
}
```

这为我们提供了三个好处：

*   在`Bean`类中指定属性要容易得多，而不必创建单独的`BeanInfo`类
*   我们将能够删除自动生成的类
*   使用这种方法，客户端库更容易模块化

# TIFF 支持

图像输入/输出插件已经为现代 Java 平台进行了扩展，包括对 TIFF 图像格式的支持。`ImageIO`类扩展了`Object`类，是 JavaSE 的一部分。这个类包含几种编码和解码图像的方法。以下是静态方法列表：

| **方法** | **返回值** |
| --- | --- |
| `createImageInputStream(Object input)` | `ImageInputStream` |
| `createImageOutputStream(Object output)` | `ImageOutputStream` |
| `getCacheDirectory()` | `CacheDirectory`的当前值 |
| `getImageReader(ImageWriter writer)` | `ImageReader` |
| `getImageReaders(Object input)` | 当前`ImageReaders`的迭代器 |
| `getImageReadersByFormatName(String formatName)` | 具有指定格式名的当前`ImageReaders`的迭代器 |
| `getImageReadersByMIMEType(String MIMEType)` | 指定 MIME 类型的当前`ImageReaders`的迭代器 |
| `getImageReadersBySuffix(String fileSuffix)` | 具有指定后缀的当前`ImageReaders`的迭代器 |
| `getImageTranscoders(ImageReader reader)` | 当前`ImageTranscoders`的迭代器 |
| `getImageWriter(ImageReader reader)` | `ImageWriter` |
| `getImageWriters(ImageTypeSpecifier type, String formatName)` | 当前`ImageWriters`的迭代器，可以编码到指定类型 |
| `getImageWritersByFormatName(String formatName)` | 具有指定格式名的当前`ImageWriters`的迭代器 |
| `getImageWritersByMIMEType(String MIMEType)` | 指定 MIME 类型的当前`ImageWriters`的迭代器 |
| `getImageWritersBySuffix(String fileSuffix)` | 具有指定后缀的当前`ImageWriters`的迭代器 |
| `getReaderFileSuffixes()` | 具有当前读取器可以理解的文件后缀的字符串数组 |
| `getReaderFormatNames()` | 具有当前读取器可以理解的格式名称的字符串数组 |
| `getReaderMIMETypes()` | 具有当前读取器可以理解的 MIME 类型的字符串数组 |
| `getUseCache()` | `UseCache`值 |
| `getWriterFileSuffixes()` | 当前写入程序可以理解的文件后缀的字符串数组 |
| `getWriterFormatNames()` | 具有当前编写器可以理解的格式名称的字符串数组 |
| `getWriterMIMETypes()` | 具有当前编写器可以理解的 MIME 类型的字符串数组 |
| `read(File input)` | `BufferedImage`与`ImageReader` |
| `read(ImageInputStream stream)` | 带`ImageInputStream`和`ImageReader`的`BufferedImage` |
| `read(InputStream input)` | 带`InputStream`和`ImageReader`的`BufferedImage` |
| `read(URL input)` | `BufferedImage`与`ImageReader` |

还有一些静态方法不返回值或布尔值：

| **方法** | **说明** |
| --- | --- |
| `scanForPlugins()` | 执行以下操作： |
| | 扫描应用类路径以查找插件 |
| | 加载插件服务供应器类 |
| | 在 IORegistry 中注册服务供应器实例 |
| `setCacheDirectory(File cacheDirectory)` | 这是缓存文件的存储位置。 |
| `setUseCache(boolean useCache)` | 此方法切换缓存是否基于磁盘。这适用于`ImageInputStream`和`ImageOutputStream`实例。 |
| `write(RenderedImage im, String formatName, File output)` | 将图像写入指定的文件。 |
| `write(RenderedImage im, String formatName, ImageOutputStream output)` | 将图像写入`ImageOutputStream`。 |
| `write(RenderedImage im, String formatName, OutputStream output)` | 将图像写入`OutputStream`。 |

从提供的方法中可以看出，图像输入/输出框架为我们提供了使用图像编解码器的方便方法。从 Java7 开始，`javax.imageio`实现了以下图像格式插件：

*   BMP
*   GIF
*   JPEG
*   PNG
*   WBMP

如您所见，TIFF 不在图像文件格式列表中。TIFF 是一种常见的文件格式，2001 年，MacOS 随着 MacOSX 的发布，广泛使用了这种格式

当前的 Java 平台包括用于 TIFF 的`ImageReader`和`ImageWriter`插件。这些插件是用 Java 编写的，并被捆绑在新的`javax.imageio.plugins.tiff`包中。

# 平台日志记录

现代 Java 平台包括一个日志 API，它使平台类能够记录消息，并提供相应的服务来操作日志。在我们深入了解日志 API 和服务的新特性之前，让我们回顾一下 Java7 中引入的`java.util.logging.api`。

# `java.util.logging`包

`java.util.logging`包包括类和接口，这些类和接口共同构成了 Java 的核心日志功能。创建此功能的目的如下：

*   最终用户和系统管理员的问题诊断
*   现场服务工程师的问题诊断
*   开发组织的问题诊断

如您所见，主要目的是支持远程软件的维护。

`java.util.logging`包有两个接口：

*   `public interface Filter`：
*   目的：提供对记录数据的细粒度控制
*   方法：`isLoggable(LogRecord record)`

*   `public interface LoggingMXBean`：
*   用途：这是日志设备的管理接口
*   方法：
    *   `getLoggerLevel(String loggerName)`
    *   `getLoggerNames()`
    *   `getparentLoggerName(String loggerName)`
    *   `setLoggerLevel(String loggerName, String levelName)`

下表提供了`java.util.logging`包类，并简要说明了每个类在日志功能和管理方面提供的内容：

| **类** | **定义** | **说明** |
| --- | --- | --- |
| `ConsoleHandler` | `public class ConsoleHandler extends StreamHandler` | 将日志记录发布到`System.err` |
| `ErrorManager` | `public class ErrorManager extends Object` | 用于在日志记录期间处理错误 |
| `FileHandler` | `public class FileHandler extends StreamHandler` | 文件记录 |
| `Formatter` | `public abstract class Formatter extends Object` | 用于格式化`LogRecords` |
| `Handler` | `public abstract class Handler extends Object` | 导出`Logger`消息 |
| `Level` | `public class Level extends Object implements Serializable` | 控制日志记录级别。级别从高到低依次为严重级别、警告级别、信息级别、配置级别、精细级别、精细级别和精细级别 |
| `Logger` | `public class Logger extends Object` | 记录消息 |
| `LoggingPermission` | `public final class LoggingPermission extends BasicPermission` | `SecurityManager`支票 |
| `LogManager` | `public class LogManager` | 用于维护记录器和日志服务之间的共享状态 |
| `LogRecord` | `public class LogRecord extends Object implements Serializable` | 在处理器之间传递 |
| `MemoryHandler` | `public class MemoryHandler extends Handler` | 内存中的缓冲请求 |
| `SimpleFormatter` | `public class SimpleFormatter extends Formatter` | 提供人类可读的`LogRecord`元数据 |
| `SocketHandler` | `public class SocketHandler extends StreamHandler` | 网络日志处理器 |
| `StreamHandler` | `public class StreamHandler extends Handler` | 基于流的日志处理器 |
| `XMLFormatter` | `public class XMLFormatter extends Formatter` | 将日志格式化为 XML |

接下来，让我们回顾一下现代 Java 平台中发生了哪些变化。

# 现代 Java 平台的日志

在 Java9 之前，有多种日志模式可用，包括`java.util.logging`、`SLF4J`和`Log4J`。后两种是第三方框架，它们有单独的外观和实现组件。这些模式已经在当前的 Java 平台中得到了复制。

`java.base`模块已更新以处理日志记录功能，不依赖`java.util.logging`API。它有一个独立的外观和实现组件。这意味着，当使用第三方框架时，JDK 只需要提供实现组件并返回与请求日志框架一起工作的平台日志记录器。

如下图所示，我们使用`java.util.ServiceLoader`API 加载`LoggerFinder`实现。如果在使用系统类加载器时找不到具体实现，JDK 将使用默认实现：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/46ceb6ca-1454-4b78-83a4-fb32470de09b.png)

`ServiceLoader` API 的`LoggerFinder`实现

# XML 目录

现代 Java 平台包括一个标准的 XMLCatalogAPI，以支持 OasisXMLCatalogs 标准 v1.1。新的 API 定义了目录和目录解析抽象，以便 JAXP 处理器可以使用它们。在本节中，我们将了解以下内容：

*   OasisXML 目录标准
*   JAXP 处理器
*   早期的 XML 目录
*   当前 XML 目录

# OasisXML 目录标准

**XML**（**可扩展标记语言**）目录是由目录项组成的 XML 文档。每个条目将一个标识符与另一个位置配对。OASIS 是一个非盈利的财团，其使命是推进开放标准。他们在 2005 年发布了 XML 目录标准 1.1 版。本标准有两个基本用例：

*   将外部标识符映射到 URI 引用
*   将 URI 引用映射到另一个 URI 引用

下面是一个示例 XML 目录条目：

```java
<public publicId="-//Packt Publishing Limited//Mastering Java9//EN" uri="https://www.packtpub.com/application-development/mastering-java-9"/>
```

[完整的 oasisXML 目录标准可以在官方网站上找到](https://www.oasis-open.org/committees/download.php/14809/xml-catalogs.html)。

# JAXP 处理器

用于 XML 处理的 JavaAPI 称为 JAXP。顾名思义，这个 API 用于解析 XML 文档。有四个相关接口：

*   **DOM**：文档对象模型解析
*   **SAX**：用于 XML 解析的简单 API
*   **StAX**：用于 XML 解析的流式 API
*   **XSLT**：转换 XML 文档的接口

# 早期的 XML 目录

自从 JDK6 以来，Java 平台就有了一个内部目录解析器。由于没有公共 API，因此使用外部工具和库来访问其功能。进入现代 Java 平台，即版本 9、10 和 11，我们的目标是使内部目录解析器成为一个标准 API，以便通用和易于支持。

# 当前 XML 目录

Java9 提供的新的 XML 目录 API 遵循 OASISXML 目录标准 v1.1。以下是特性和功能亮点：

*   执行`EntityResolver`。
*   执行`URIResolver`。
*   可以通过`CatalogManager`创建 XML 目录。
*   `CatalogManager`将用于创建`CatalogResolvers`。
*   将遵循 OASIS 打开目录文件语义：
*   将外部标识符映射到 URI 引用
*   将 URI 引用映射到另一个 URI 引用

*   `CatalogResolvers`将实现 JAXP`EntityResolver`接口。
*   `CatalogResolvers`将实现 JAXP`URIResolver`接口。
*   SAX`XMLFilter`将由解析器支持。

因为新的 XML 目录 API 是公共的，所以 Java9 之前的内部目录解析器已经被删除，因为它不再是必需的。

# 集合

Java 编程语言不支持集合文本。将此功能添加到 Java 平台是在 2013 年提出的，并在 2016 年重新进行了讨论，但它只是作为一个研究建议而被公开，并不是为了将来的实现。

Oracle 对集合字面值的定义是[**一种语法表达式形式，其计算结果是聚合类型，例如数组、列表或映射**](http://openjdk.java.net/jeps/186)。

当然，直到 Java9 发布。据报道，在 Java 编程语言中实现集合字面值具有以下好处：

*   性能改进
*   提高安全性
*   样板代码缩减

即使没有加入研究小组，我们对 Java 编程语言的了解也会给我们带来更多好处：

*   编写较短代码的能力
*   编写节省空间 d 的代码的能力
*   使集合字面值不可变的能力

让我们看两个案例，一个是使用现代 Java 平台之前的集合，另一个是使用新 Java 平台中对集合文本的新支持。

# 使用现代 Java 平台之前的集合

下面是一个示例，说明如何在现代 Java 平台之前创建自己的集合。第一个类定义了`PlanetCollection`的结构。它包含以下组件：

*   单个实例变量
*   单参数构造器
*   一种更改/设置方法
*   访问器/获取器方法
*   打印对象的方法

下面是实现前面列出的构造器和方法的代码：

```java
public class PlanetCollection {

  // Instance Variable
  private String planetName;

  // constructor
  public PlanetCollection(String name) {
    setPlanetName(name);
  }

  // mutator
  public void setPlanetName(String name) {
    this.planetName = name;
  }

  // accessor
  public String getPlanetName() {
    return this.planetName;
  }

  public void print() {
    System.out.println(getPlanetName());
  }
}
```

现在，让我们看看填充集合的驱动程序类：

```java
import java.util.ArrayList;

public class OldSchool {

  private static ArrayList<PlanetCollection> 
    myPlanets = new ArrayList<>();

  public static void main(String[] args) {
    add("Earth");
    add("Jupiter");
    add("Mars");
    add("Venus");
    add("Saturn");
    add("Mercury");
    add("Neptune");
    add("Uranus");
    add("Dagobah");
    add("Kobol");

    for (PlanetCollection orb : myPlanets) {
      orb.print();
    }
  }

  public static void add(String name) {
    PlanetCollection newPlanet = 
      new PlanetCollection(name);
    myPlanets.add(newPlanet);
  }
}
```

以下是此应用的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/8d2afd93-4226-4018-a9b1-d009b4bd9362.png)

`OldSchool`类的输出

不幸的是，这段代码非常冗长。我们在静态初始化器块中填充集合，而不是使用字段初始化器。还有其他方法填充我们的列表，但它们都比应该的更冗长。这些其他方法还有其他问题，比如需要创建额外的类、使用晦涩的代码和隐藏的引用。

现在，让我们看看这个问题的解决方案，它是由现代 Java 平台提供的，我们将在下一节中介绍它的新特性。

# 使用新集合字面值

为了纠正创建集合时当前所需代码的冗长性，我们需要用于创建集合实例的库 API。请看上一节前面的代码片段，然后考虑以下可能的重构：

```java
PlanetCollection<String> myPlanets = Set.of(
  "Earth",
  "Jupiter",
  "Mars",
  "Venus",
  "Saturn",
  "Mercury",
  "Neptune",
  "Uranus",
  "Dagobah",
  "Kobol");
```

这段代码是高度可读的，而不是冗长的。

新的实现将包括以下接口上的静态工厂方法：

*   `List`
*   `Map`
*   `Set`

因此，我们现在可以创建不可修改的`List`集合、`Map`集合和`Set`集合实例。它们可以用以下语法实例化：

*   `List.of(a, b, c, d, e);`
*   `Set.of(a, b, c, d, e);`
*   `Map.of();`

`Map`集合将有一组固定参数。

# 特定于平台的桌面功能

现代 Java 平台包括一个公共 API，它使我们能够编写能够访问特定于平台的桌面功能的应用。这些功能包括与任务栏/工作台交互以及监听应用和系统事件。

MacOSX`com.apple.eawt`包是一个内部 API，从 Java9 开始，就不能再访问了。为了支持 Java 的嵌入式平台特定的桌面特性，`apple.applescript`类被删除而不进行替换。它们在 Java9、10 或 11 中不可用。

新 API 已添加到`java.awt.Desktop`类中，并提供以下内容：

*   它创建了一个公共 API 来替换`com.apple.{east,eio}`中的功能。
*   它确保了 OSX 开发人员不会丢失功能。为此，当前的 Java 平台替换了以下包：
*   `com.apple.eawt`
*   `com.apple.eio`

*   除了 OS X 之外，它还为开发人员提供了一套近乎通用的平台（即 Windows 和 Linux）功能。这些通用功能包括：
*   带有事件监听器的登录/注销处理器
*   带有事件监听器的屏幕锁处理器
*   任务栏/停靠操作包括以下内容：
*   请求用户注意
*   指示任务进度
*   动作快捷方式

# 增强的方法句柄

现代 Java 平台包括增强的方法句柄，作为改进以下列出的类的一种方法，以便通过改进的优化简化常见用法：

*   `MethodHandle`类
*   `MethodHandles`类
*   `MethodHandles.Lookup`类

前面的类都是`java.lang.invoke`包的一部分，该包已针对现代 Java 平台进行了更新。这些改进是通过使用`MethodHandle`组合、`for`循环和`try...finally`块的查找细化实现的。

在本节中，我们将了解以下内容：

*   增强的原因
*   查找函数
*   参数处理
*   额外组合

# 增强的原因

这种增强源于开发人员的反馈，以及使`MethodHandle`、`MethodHandles`和`MethodHandles.Lookup`类更易于使用的愿望，还有添加额外用例的呼吁。

这些变化带来了以下好处：

*   在使用`MethodHandle`API 时启用的精度
*   实例化缩减
*   增加的 JVM 编译器优化

# 查找函数

有关查找函数的更改包括：

*   `MethodHandles`现在可以绑定到接口中的非抽象方法
*   LookupAPI 允许从不同的上下文进行类查找

`MethodHandles.Lookup.findSpecial(Class<?> refs, String name, MethodType type, Class<?> specialCaller)`类已被修改，以允许在接口上定位超级可调用方法。

另外，在`MethodHandles.Lookup`类中增加了以下方法：

*   `Class<?> findClass(String targetName)`
*   `Class<?> accessClass(Class<?> targetClass)`

# 参数处理

最近进行了三次更新以改进`MethodHandle`参数处理。这些变化如下：

*   使用`foldArguments(MethodHandle target, MethodHandle combinator)`的参数折叠以前没有位置参数：
    *   使用`MethodHandle.asCollector(Class<?> arrayType, int arrayLength)`方法的参数集合以前不支持将参数集合到数组中，但尾部元素除外。这一点已经改变，现在有一个额外的`asCollector`方法来支持该功能。

*   在参数集合的反向方法中，使用`MethodHandle.asSpreader(Class<?> arrayType, int arrayLength)`方法的参数扩展将尾部数组的内容扩展到多个参数。已修改参数扩展，以支持在方法签名的任何位置扩展数组。

下一节将提供更新的`asCollector`和`asSpreader`方法的新方法定义。

# 额外组合

添加了以下额外组合以支持`java.lang.invoke`包的`MethodHandle`、`MethodHandles`和`MethodHandles.Lookup`类的易用性和优化：

*   通用循环抽象：
*   `MethodHandle loop(MethodHandle[] . . . clauses)`
*   `While`循环：
*   `MethodHandle whileLoop(MethodHandle init, MethodHandle pred, MethodHandle body)`
*   `Do...while`循环：
*   `MethodHandle doWhileLoop(MethodHandle init, MethodHandle body, MethodHandle pred)`
*   计数循环：
*   `MethodHandle countedLoop(MethodHandle iterations, MethodHandle init, MethodHandle body)`
*   数据结构迭代：
*   `MethodHandle iteratedLoop(MethodHandle iterator, MethodHandle init, MethodHandle body)`
*   `Try...finally`块：
*   `MethodHandle tryFinally(MethodHandle target, MethodHandle cleanup)`

*   参数处理：
*   参数传播：
    *   `MethodHandle asSpreader(int pos, Class<?> arrayType, int arrayLength)`
*   参数收集：
    *   `MethodHandle asCollector(int pos, Class<?> arrayType, int arrayLength)`
*   参数折叠：
    *   `MethodHandle foldArguments(MethodHandle target, int pos, MethodHandle combiner)`

# 废弃的改进

有两种表达反对意见的工具：

*   `@Deprecated`注解
*   `@deprecated`Javadoc 标签

这些工具分别在 JavaSE5 和 JDK1.1 中引入。`@Deprecated`注解的目的是注解那些不应该使用的程序组件，因为它们被认为是危险的和/或有更好的选择。这就是预期用途，实际用途各不相同，而且由于警告只在编译时提供，因此几乎没有理由忽略带注解的代码。

增强的弃用工作是为了向开发人员提供关于规范文档中 API 的预期配置的更清晰的信息。这方面的工作还产生了一个分析程序使用不推荐的 API 的工具。

为了支持信息的保真度，以下组件被添加到`java.lang.Deprecated`注解类型中：

*   `forRemoval()`：
*   返回布尔值`true`，如果 API 元素已被安排在将来删除
*   如果 API 元素未被指定为将来删除，但已弃用，则返回布尔值`false`
*   默认为`false`

*   `since()`：
*   返回包含版本号或版本号的字符串，此时指定的 API 被标记为已弃用

# `@Deprecated`注解的真正含义

当一个 API 或 API 中的方法已标记有`@Deprecated`注解时，通常存在以下一个或多个条件：

*   API 中存在错误，没有计划修复这些错误
*   使用 API 可能会导致错误
*   API 已被另一个 API 替换
*   API 是实验性的

# 本机头生成工具（`javah`）

Java 头工具（`javah`是用 Java8 引入 Java 平台的。它为开发人员提供了编写本机头的能力。从 Java10 开始，`javah`工具被 Java 编译器（`javac`中包含的功能所取代

开发人员不使用`javah`，而只使用`javac -h`。

# 总结

在本章中，我们介绍了有关现代平台的几个升级。这些更新涵盖了广泛的工具和 API 更新，使使用 Java 进行开发变得更容易，并为我们生成的程序提供了更大的优化可能性。我们回顾了新的 HTTP 客户端、对 Javadoc 和 Doclet API 的更改、新的 JavaScript 解析器、JAR 和 JRE 更改、新的 Java 级 JVM 编译器接口、对 TIFF 图像的新支持、平台日志记录、XML 目录支持、集合以及新的平台特定桌面功能。我们还研究了方法处理和弃用注解的增强功能。

在下一章中，我们将讨论并发增强，我们的主要关注点是对`Flow`类 API 提供的反应式编程的支持。我们还将探讨额外的并发增强。

# 问题

1.  升级 HTTP 客户端的主要原因是什么？
2.  列出新的 HTTP 客户端 API 的限制。
3.  使用`javadoc`必须传递哪三个组件？
4.  命名一个或多个属于 Doclet 类的方法（构造器除外）。
5.  编译器树 API 中的枚举是什么？
6.  Javadoc 工具的默认输出是什么？
7.  Nashorn 是什么？
8.  什么是 ECMAScript？
9.  说出两个主要的 JAR 文件增强。
10.  `JavaBean`的三个约定是什么？

# 进一步阅读

以下是您可以参考的信息列表：

*   《Docker 基础》【综合课程】在[这个页面](https://www.packtpub.com/virtualization-and-cloud/docker-fundamentals-integrated-course)提供。
*   《Java9：构建健壮的模块化应用》，可在[这个页面](https://www.packtpub.com/application-development/java-9-building-robust-modular-applications)获得。