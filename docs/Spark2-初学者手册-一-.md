# Spark2 初学者手册（一）

> 原文：[`zh.annas-archive.org/md5/4803F9F0B1A27EADC7FE0DFBB64A3594`](https://zh.annas-archive.org/md5/4803F9F0B1A27EADC7FE0DFBB64A3594)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

数据处理框架 Spark 最初是为了证明，通过在多次迭代中重用数据集，它在 Hadoop MapReduce 作业表现不佳的地方提供了价值。研究论文《Mesos：数据中心细粒度资源共享平台》讨论了 Spark 设计背后的哲学。加州大学伯克利分校的研究人员为测试 Mesos 而构建的一个非常简单的参考实现，已经远远超越了最初的用途，发展成为一个完整的数据处理框架，后来成为最活跃的 Apache 项目之一。它从一开始就被设计用于在 Hadoop、Mesos 等集群上进行分布式数据处理，以及在独立模式下运行。Spark 是一个基于 JVM 的数据处理框架，因此它可以在支持基于 JVM 的应用程序的大多数操作系统上运行。Spark 广泛安装在 UNIX 和 Mac OS X 平台上，而 Windows 上的采用也在增加。

Spark 通过编程语言 Scala、Java、Python 和 R 提供了一个统一的编程模型。换句话说，无论使用哪种语言编写 Spark 应用程序，API 在所有语言中几乎都是相同的。这样，组织可以采用 Spark 并在他们选择的编程语言中开发应用程序。这也使得在需要时可以快速将 Spark 应用程序从一个语言移植到另一个语言，而无需太多努力。Spark 大部分是用 Scala 开发的，因此 Spark 编程模型本质上支持函数式编程原则。最基本的 Spark 数据抽象是弹性分布式数据集（RDD），基于此构建了所有其他库。基于 RDD 的 Spark 编程模型是开发者可以构建数据处理应用程序的最低级别。

Spark 迅速发展，以满足更多数据处理用例的需求。当采取这种前瞻性的产品路线图步骤时，出现了对商业用户进行更高级别编程的需求。基于 Spark 核心的 Spark SQL 库，以其 DataFrame 抽象，被构建来满足大量非常熟悉无处不在的 SQL 的开发者的需求。

数据科学家使用 R 语言进行计算需求。R 语言最大的限制是所有需要处理的数据都应该*适合*运行 R 程序的计算机的主内存。Spark 为 R 语言引入的 API 让数据科学家们熟悉了在熟悉的数据帧抽象中的分布式数据处理世界。换句话说，使用 R 语言的 Spark API，数据处理可以在 Hadoop 或 Mesos 上并行进行，远远超出了主机内存的限制。

在当前大规模应用收集数据的时代，摄入数据的速率非常高。许多应用场景要求对流式数据进行实时处理。建立在 Spark Core 之上的 Spark Streaming 库正是为此而设计。

静态数据或流式数据被输入机器学习算法以训练数据模型，并使用这些模型来回答业务问题。在 Spark 之前创建的所有机器学习框架在处理计算机的内存、无法进行并行处理、重复的读写周期等方面存在许多限制。Spark 没有这些限制，因此建立在 Spark Core 和 Spark DataFrames 之上的 Spark MLlib 机器学习库成为了最佳的机器学习库，它将数据处理管道和机器学习活动紧密结合。

图是一种非常有用的数据结构，在某些特殊用例中被大量使用。用于处理图数据结构的算法计算密集。在 Spark 之前，出现了许多图处理框架，其中一些处理速度非常快，但生成图数据结构所需的数据预处理在大多数图处理应用中成为了一个巨大的瓶颈。建立在 Spark 之上的 Spark GraphX 库填补了这一空白，使得数据处理和图处理成为链式活动。

过去，存在许多数据处理框架，其中许多是专有的，迫使组织陷入供应商锁定的陷阱。Spark 为各种数据处理需求提供了一个非常可行的替代方案，且无需许可费用；同时，它得到了许多领先公司的支持，提供专业的生产支持。

# 本书涵盖的内容

第一章，*Spark 基础*，探讨了 Spark 作为一个框架的基本原理，包括其 API 和随附的库，以及 Spark 与之交互的整个数据处理生态系统。

第二章，*Spark 编程模型*，讨论了基于函数式编程方法论的统一编程模型，该模型在 Spark 中使用，并涵盖了弹性分布式数据集（RDD）的基础、Spark 转换和 Spark 操作。

第三章，*Spark SQL*，讨论了 Spark SQL，这是最强大的 Spark 库之一，用于使用无处不在的 SQL 结构以及 Spark DataFrame API 来操作数据，并探讨了它如何与 Spark 程序协同工作。本章还讨论了如何使用 Spark SQL 从各种数据源访问数据，实现对多样数据源的数据处理统一。

第四章，*使用 R 进行 Spark 编程*，讨论了 SparkR 或 R on Spark，这是 Spark 的 R API；这使得 R 用户能够利用 Spark 的数据处理能力，使用他们熟悉的数据帧抽象。它为 R 用户提供了一个很好的基础，以便熟悉 Spark 数据处理生态系统。

第五章，*使用 Python 进行 Spark 数据分析*，讨论了使用 Spark 进行数据处理和使用 Python 进行数据分析，利用了 Python 提供的各种图表和绘图库。本章讨论了将这两项相关活动结合在一起，作为使用 Python 作为首选编程语言的 Spark 应用程序。

第六章，*Spark 流处理*，讨论了 Spark Streaming，这是用于捕获和处理以流形式输入的数据的最强大的 Spark 库之一。还讨论了作为分布式消息代理的 Kafka 和作为消费者的 Spark Streaming 应用程序。

第七章，*Spark 机器学习*，探讨了 Spark MLlib，这是用于开发入门级机器学习应用程序的最强大的 Spark 库之一。

第八章，*Spark 图处理*，讨论了 Spark GraphX，这是处理图数据结构的最强大的 Spark 库之一，并附带了许多用于图数据处理的算法。本章涵盖了 GraphX 的基础知识以及使用 GraphX 提供的算法实现的一些用例。

第九章，*设计 Spark 应用程序*，讨论了 Spark 数据处理应用程序的设计和开发，涵盖了本书前几章中介绍的 Spark 的各种特性。

# 本书所需条件

Spark 2.0.0 或更高版本需要安装在至少一台独立机器上，以运行代码示例并进行进一步的活动，以更深入地了解该主题。对于第六章，*Spark 流处理*，需要安装并配置 Kafka 作为消息代理，其命令行生产者产生消息，而使用 Spark 开发的应用程序作为这些消息的消费者。

# 本书面向的读者

如果你是应用程序开发者、数据科学家或大数据解决方案架构师，并对将 Spark 的数据处理能力与 R 结合，以及将数据处理、流处理、机器学习、图处理整合到一个统一且高度互操作的框架中，使用统一的 API（Scala 或 Python）感兴趣，那么这本书适合你。

# 约定

在本书中，您会发现多种文本样式用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄如下所示："将此属性`spark.driver.memory`设置为更高值是个好主意。"

代码块设置如下：

```scala
Python 3.5.0 (v3.5.0:374f501f4567, Sep 12 2015, 11:00:19)
[GCC 4.2.1 (Apple Inc. build 5666) (dot 3)] on darwin
```

任何命令行输入或输出书写如下：

```scala
$ python 
Python 3.5.0 (v3.5.0:374f501f4567, Sep 12 2015, 11:00:19)  
[GCC 4.2.1 (Apple Inc. build 5666) (dot 3)] on darwin 
Type "help", "copyright", "credits" or "license" for more information. 
>>> 

```

**新术语**和**重要词汇**以粗体显示。屏幕上出现的词汇，例如在菜单或对话框中，在文本中这样呈现："本书中的快捷键基于`Mac OS X 10.5+`方案。"

### 注意

警告或重要提示以这样的方框形式出现。

### 提示

提示和技巧这样呈现。


# 第一章：Spark 基础

数据是任何组织最重要的资产之一。组织中收集和使用的数据规模正以超出想象的速度增长。数据摄取的速度、使用的数据类型多样性以及处理和存储的数据量每时每刻都在打破历史记录。如今，即使在小型组织中，数据从千兆字节增长到太字节再到拍字节也变得非常普遍。因此，处理需求也在增长，要求能够处理静态数据以及移动中的数据。

以任何组织为例，其成功取决于领导者所做的决策，而为了做出明智的决策，你需要依赖于处理数据产生的良好数据和信息。这给如何及时且成本效益高地处理数据提出了巨大挑战，以便做出正确决策。自计算机早期以来，数据处理技术已经发展。无数的数据处理产品和框架进入市场，又随着时间的推移而消失。这些数据处理产品和框架大多数并非通用性质。大多数组织依赖于定制的应用程序来满足其数据处理需求，以孤岛方式或与特定产品结合使用。

大规模互联网应用，俗称**物联网**（**IoT**）应用，预示着对开放框架的共同需求，以高速处理各种类型的大量数据。大型网站、媒体流应用以及组织的大规模批处理需求使得这一需求更加迫切。开源社区也随着互联网的发展而显著壮大，提供由知名软件公司支持的生产级软件。众多公司开始采用开源软件，并将其部署到生产环境中。

从技术角度看，数据处理需求正面临巨大挑战。数据量从单机溢出到大量机器集群。单个 CPU 的处理能力达到瓶颈，现代计算机开始将它们组合起来以获取更多处理能力，即所谓的多核计算机。应用程序并未设计成充分利用多核计算机中的所有处理器，导致现代计算机中大量处理能力被浪费。

### 注意

本书中，*节点*、*主机*和*机器*这些术语指的是在独立模式或集群中运行的计算机。

在此背景下，理想的数据处理框架应具备哪些特质？

+   它应能处理分布在计算机集群中的数据块

+   它应该能够以并行方式处理数据，以便将大型数据处理任务分解为多个并行处理的子任务，从而显著减少处理时间

+   它应该能够利用计算机中所有核心或处理器的处理能力

+   它应该能够利用集群中所有可用的计算机

+   它应该能够在商品硬件上运行

有两个开源数据处理框架值得提及，它们满足所有这些要求。第一个是 Apache Hadoop，第二个是 Apache Spark。

本章我们将涵盖以下主题：

+   Apache Hadoop

+   Apache Spark

+   安装 Spark 2.0

# Apache Hadoop 概览

Apache Hadoop 是一个开源软件框架，从零开始设计用于在计算机集群上进行分布式数据存储，并对分布在集群计算机上的数据进行分布式数据处理。该框架配备了一个分布式文件系统用于数据存储，即**Hadoop 分布式文件系统**（**HDFS**），以及一个数据处理框架，即 MapReduce。HDFS 的创建灵感来自 Google 的研究论文《The Google File System》，而 MapReduce 则基于 Google 的研究论文《MapReduce: Simplified Data Processing on Large Clusters》。

Hadoop 被组织大规模采用，通过实施庞大的 Hadoop 集群进行数据处理。从 Hadoop MapReduce 版本 1（MRv1）到 Hadoop MapReduce 版本 2（MRv2），它经历了巨大的增长。从纯粹的数据处理角度来看，MRv1 由 HDFS 和 MapReduce 作为核心组件组成。许多应用程序，通常称为 SQL-on-Hadoop 应用程序，如 Hive 和 Pig，都建立在 MapReduce 框架之上。尽管这些类型的应用程序是独立的 Apache 项目，但作为一套，许多此类项目提供了巨大的价值，这种情况非常常见。

**Yet Another Resource Negotiator**（**YARN**）项目随着非 MapReduce 类型的计算框架在 Hadoop 生态系统中运行而崭露头角。随着 YARN 的引入，位于 HDFS 之上，从组件架构分层的角度看，位于 MapReduce 之下，用户可以编写自己的应用程序，这些应用程序可以在 YARN 和 HDFS 上运行，以利用 Hadoop 生态系统的分布式数据存储和数据处理能力。换句话说，经过全面改造的 MapReduce 版本 2（MRv2）成为了位于 HDFS 和 YARN 之上的应用程序框架之一。

*图 1*简要介绍了这些组件以及它们如何堆叠在一起：

![Apache Hadoop 概览](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_01_002.jpg)

图 1

MapReduce 是一种通用数据处理模型。数据处理经过两个步骤，即*映射*步骤和*归约*步骤。在第一步中，输入数据被分割成许多较小的部分，以便每个部分可以独立处理。一旦*映射*步骤完成，其输出被整合，最终结果在*归约*步骤中生成。在典型的词频统计示例中，以每个单词为键，值为 1 创建键值对是*映射*步骤。基于键对这些对进行排序，对具有相同键的对的值进行求和属于中间*合并*步骤。生成包含唯一单词及其出现次数的对是*归约*步骤。

从应用程序编程的角度来看，一个过度简化的 MapReduce 应用程序的基本要素如下：

+   输入位置

+   输出位置

+   MapReduce 库中适当的接口和类实现了数据处理所需的`Map`函数。

+   MapReduce 库中适当的接口和类实现了数据处理所需的`Reduce`函数。

将 MapReduce 作业提交给 Hadoop 运行，一旦作业完成，可以从指定的输出位置获取输出。

将`MapReduce`数据处理作业分为*映射*和*归约*任务的两个步骤过程非常有效，并且证明是许多批量数据处理用例的完美匹配。在整个过程中，有许多与磁盘的输入/输出（I/O）操作在幕后发生。即使在 MapReduce 作业的中间步骤中，如果内部数据结构充满数据或当任务完成超过一定百分比时，写入磁盘也会发生。因此，MapReduce 作业的后续步骤必须从磁盘读取。

然后，当有多个 MapReduce 作业需要以链式方式完成时，另一个最大的挑战出现了。换句话说，如果一项大数据处理工作是通过两个 MapReduce 作业完成的，使得第一个 MapReduce 作业的输出成为第二个 MapReduce 作业的输入。在这种情况下，无论第一个 MapReduce 作业的输出大小如何，它都必须写入磁盘，然后第二个 MapReduce 作业才能将其用作输入。因此，在这种情况下，存在一个明确且*不必要的*写操作。

在许多批量数据处理的用例中，这些 I/O 操作并不是大问题。如果结果高度可靠，对于许多批量数据处理用例来说，延迟是可以容忍的。但最大的挑战出现在进行实时数据处理时。MapReduce 作业中涉及的大量 I/O 操作使其不适合以最低可能延迟进行实时数据处理。

# 理解 Apache Spark

Spark 是一个基于**Java 虚拟机**（**JVM**）的分布式数据处理引擎，具有可扩展性，且速度远超许多其他数据处理框架。Spark 起源于*加州大学伯克利分校*，后来成为 Apache 的顶级项目之一。研究论文《Mesos：数据中心细粒度资源共享平台》阐述了 Spark 设计背后的理念。论文指出：

> *"为了验证简单专用框架的价值，我们识别出实验室机器学习研究人员发现运行不佳的一类作业：迭代作业，其中数据集在多次迭代中被重复使用。我们构建了一个专为这些工作负载优化的框架，名为 Spark。"*

Spark 关于速度的最大宣称是，它能在内存中*“运行程序比 Hadoop MapReduce 快 100 倍，或在磁盘上快 10 倍”*。Spark 之所以能做出这一宣称，是因为它在工作者节点的主内存中进行处理，避免了*不必要*的磁盘 I/O 操作。Spark 的另一优势是，即使在应用程序编程级别，也能链式执行任务，完全不写入磁盘或最小化磁盘写入次数。

Spark 相较于 MapReduce，为何在数据处理上如此高效？这得益于其先进的**有向无环图**（**DAG**）数据处理引擎。这意味着每个 Spark 作业都会创建一个任务 DAG 供引擎执行。在数学术语中，DAG 由一组顶点和连接它们的定向边组成。任务按照 DAG 布局执行。而在 MapReduce 中，DAG 仅包含两个顶点，一个用于*映射*任务，另一个用于*归约*任务，边从*映射*顶点指向*归约*顶点。内存数据处理与基于 DAG 的数据处理引擎相结合，使得 Spark 极为高效。在 Spark 中，任务的 DAG 可以非常复杂。幸运的是，Spark 提供了实用工具，能够出色地可视化任何运行中的 Spark 作业的 DAG。以词频统计为例，Spark 的 Scala 代码将类似于以下代码片段。这些编程细节将在后续章节中详细介绍：

```scala
val textFile = sc.textFile("README.md") 
val wordCounts = textFile.flatMap(line => line.split(" ")).map(word => 
 (word, 1)).reduceByKey((a, b) => a + b) 
wordCounts.collect()

```

随 Spark 提供的 Web 应用程序能够监控工作者和应用程序。前述 Spark 作业实时生成的 DAG 将呈现为*图 2*，如图所示：

![理解 Apache Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_01_003.jpg)

图 2

Spark 编程范式非常强大，提供了一个统一的编程模型，支持使用多种编程语言进行应用程序开发。尽管在所有支持的编程语言之间没有功能对等性，但 Spark 支持 Scala、Java、Python 和 R 的编程。除了使用这些编程语言编写 Spark 应用程序外，Spark 还为 Scala、Python 和 R 提供了具有**读取、评估、打印和循环**（**REPL**）功能的交互式 Shell。目前，Spark 中没有为 Java 提供 REPL 支持。Spark REPL 是一个非常多功能的工具，可用于以交互方式尝试和测试 Spark 应用程序代码。Spark REPL 便于原型设计、调试等。

-   除了核心数据处理引擎外，Spark 还配备了一个强大的特定领域库栈，这些库使用核心 Spark 库并提供各种功能，以满足各种大数据处理需求。下表列出了支持的库：

| **库** | **用途** | **支持的语言** |
| --- | --- | --- |
| Spark SQL | 使在 Spark 应用程序中使用 SQL 语句或 DataFrame API 成为可能 | Scala, Java, Python, 和 R |
| Spark Streaming | 使处理实时数据流成为可能 | Scala, Java, 和 Python |
| Spark MLlib | 使机器学习应用程序的开发成为可能 | Scala, Java, Python, 和 R |
| Spark GraphX | 启用图形处理并支持不断增长的图形算法库 | Scala |

Spark 可以在各种平台上部署。Spark 运行在**操作系统**（**OS**）Windows 和 UNIX（如 Linux 和 Mac OS）上。Spark 可以在具有支持 OS 的单个节点上以独立模式部署。Spark 也可以在 Hadoop YARN 和 Apache Mesos 的集群节点上部署。Spark 还可以在 Amazon EC2 云上部署。Spark 可以从各种数据存储中访问数据，其中一些最受欢迎的包括 HDFS、Apache Cassandra、Hbase、Hive 等。除了前面列出的数据存储外，如果有驱动程序或连接器程序可用，Spark 几乎可以从任何数据源访问数据。

### Tip

-   本书中使用的所有示例均在 Mac OS X Version 10.9.5 计算机上开发、测试和运行。除 Windows 外，相同的指令适用于所有其他平台。在 Windows 上，对应于所有 UNIX 命令，都有一个带有`.cmd`扩展名的文件，必须使用该文件。例如，对于 UNIX 中的`spark-shell`，Windows 中有`spark-shell.cmd`。程序行为和结果应在所有支持的操作系统上保持一致。

在任何分布式应用中，通常都有一个控制执行的主程序和多个工作节点。主程序将任务分配给相应的工作节点。即使在 Spark 独立模式下也是如此。对于 Spark 应用，其**SparkContext**对象即为主程序，它与相应的集群管理器通信以运行任务。Spark 核心库中的 Spark 主节点、Mesos 主节点和 Hadoop YARN 资源管理器都是 Spark 支持的一些集群管理器。在 Hadoop YARN 部署的 Spark 情况下，Spark 驱动程序在 Hadoop YARN 应用主进程内运行，或者作为 Hadoop YARN 的客户端运行。*图 3*描述了 Spark 的独立部署：

![理解 Apache Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_01_006.jpg)

图 3

在 Spark 的 Mesos 部署模式下，集群管理器将是**Mesos 主节点**。*图 4*描述了 Spark 的 Mesos 部署：

![理解 Apache Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_01_008.jpg)

图 4

在 Spark 的 Hadoop YARN 部署模式下，集群管理器将是 Hadoop 资源管理器，其地址将从 Hadoop 配置中获取。换句话说，在提交 Spark 作业时，无需给出明确的 master URL，它将从 Hadoop 配置中获取集群管理器的详细信息。*图 5*描述了 Spark 的 Hadoop YARN 部署：

![理解 Apache Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_01_010.jpg)

图 5

Spark 也运行在云端。在 Spark 部署在 Amazon EC2 的情况下，除了从常规支持的数据源访问数据外，Spark 还可以从 Amazon S3 访问数据，这是亚马逊提供的在线数据存储服务。

# 在您的机器上安装 Spark

Spark 支持使用 Scala、Java、Python 和 R 进行应用开发。本书中使用了 Scala、Python 和 R。以下是本书示例选择这些语言的原因。Spark 交互式 shell，或 REPL，允许用户像在终端提示符下输入操作系统命令一样即时执行程序，并且仅适用于 Scala、Python 和 R 语言。REPL 是在将代码组合到文件中并作为应用程序运行之前尝试 Spark 代码的最佳方式。REPL 甚至可以帮助经验丰富的程序员尝试和测试代码，从而促进快速原型设计。因此，特别是对于初学者，使用 REPL 是开始使用 Spark 的最佳方式。

作为安装 Spark 和使用 Python 和 R 进行 Spark 编程的前提条件，必须在安装 Spark 之前安装 Python 和 R。

## 安装 Python

访问[`www.python.org`](https://www.python.org/)以下载并安装适用于您计算机的 Python。安装完成后，确保所需的二进制文件位于操作系统搜索路径中，且 Python 交互式 shell 能正常启动。shell 应显示类似以下内容：

```scala
$ python 
Python 3.5.0 (v3.5.0:374f501f4567, Sep 12 2015, 11:00:19)  
[GCC 4.2.1 (Apple Inc. build 5666) (dot 3)] on darwin 
Type "help", "copyright", "credits" or "license" for more information. 
>>> 

```

图表和绘图使用的是`matplotlib`库。

### 注意

Python 版本 3.5.0 被选为 Python 的版本。尽管 Spark 支持 Python 2.7 版本进行编程，但为了面向未来，我们采用了最新且最稳定的 Python 版本。此外，大多数重要库也正在迁移至 Python 3.x 版本。

访问[`matplotlib.org`](http://matplotlib.org/)以下载并安装该库。为确保库已正确安装且图表和图形能正常显示，请访问[`matplotlib.org/examples/index.html`](http://matplotlib.org/examples/index.html)页面，获取一些示例代码，并确认您的计算机具备图表和绘图所需的所有资源和组件。在尝试运行这些图表和绘图示例时，如果 Python 代码中引入了库，可能会出现缺少 locale 的错误。此时，请在相应的用户配置文件中设置以下环境变量以消除错误信息：

```scala
export LC_ALL=en_US.UTF-8 
export LANG=en_US.UTF-8

```

## R 安装

访问[`www.r-project.org`](https://www.r-project.org/)以下载并安装适用于您计算机的 R。安装完成后，确保所需的二进制文件位于操作系统搜索路径中，且 R 交互式 shell 能正常启动。shell 应显示类似以下内容：

```scala
$ r 
R version 3.2.2 (2015-08-14) -- "Fire Safety" 
Copyright (C) 2015 The R Foundation for Statistical Computing 
Platform: x86_64-apple-darwin13.4.0 (64-bit) 
R is free software and comes with ABSOLUTELY NO WARRANTY. 
You are welcome to redistribute it under certain conditions. 
Type 'license()' or 'licence()' for distribution details. 
  Natural language support but running in an English locale 
R is a collaborative project with many contributors. 
Type 'contributors()' for more information and 
'citation()' on how to cite R or R packages in publications. 
Type 'demo()' for some demos, 'help()' for on-line help, or 
'help.start()' for an HTML browser interface to help. 
Type 'q()' to quit R. 
[Previously saved workspace restored] 
>

```

### 注意

R 版本 3.2.2 是 R 的选择。

## Spark 安装

Spark 安装有多种方式。Spark 安装最重要的前提是系统中已安装 Java 1.8 JDK，并且`JAVA_HOME`环境变量指向 Java 1.8 JDK 的安装目录。访问[`spark.apache.org/downloads.html`](http://spark.apache.org/downloads.html)以了解、选择并下载适合您计算机的安装类型。Spark 版本 2.0.0 是本书示例所选用的版本。对于有兴趣从源代码构建和使用 Spark 的用户，应访问：[`spark.apache.org/docs/latest/building-spark.html`](http://spark.apache.org/docs/latest/building-spark.html)以获取指导。默认情况下，从源代码构建 Spark 时不会构建 Spark 的 R 库。为此，需要构建 SparkR 库，并在从源代码构建 Spark 时包含适当的配置文件。以下命令展示了如何包含构建 SparkR 库所需的配置文件：

```scala
$ mvn -DskipTests -Psparkr clean package

```

一旦 Spark 安装完成，在适当的用户配置文件中定义以下环境变量：

```scala
export SPARK_HOME=<the Spark installation directory> 
export PATH=$SPARK_HOME/bin:$PATH

```

如果系统中有多个版本的 Python 可执行文件，那么最好在以下环境变量设置中明确指定 Spark 要使用的 Python 可执行文件：

```scala
export PYSPARK_PYTHON=/usr/bin/python

```

在`$SPARK_HOME/bin/pyspark`脚本中，有一段代码用于确定 Spark 要使用的 Python 可执行文件：

```scala
# Determine the Python executable to use if PYSPARK_PYTHON or PYSPARK_DRIVER_PYTHON isn't set: 
if hash python2.7 2>/dev/null; then 
  # Attempt to use Python 2.7, if installed: 
  DEFAULT_PYTHON="python2.7" 
else 
  DEFAULT_PYTHON="python" 
fi

```

因此，即使系统中只有一个版本的 Python，也最好明确设置 Spark 的 Python 可执行文件。这是为了防止将来安装其他版本的 Python 时出现意外行为的安全措施。

一旦完成所有前面的步骤并成功，确保所有语言（Scala、Python 和 R）的 Spark shell 都能正常工作。在操作系统终端提示符下运行以下命令，并确保没有错误，且显示内容与以下类似。以下命令集用于启动 Spark 的 Scala REPL：

```scala
$ cd $SPARK_HOME 
$ ./bin/spark-shellUsing Spark's default log4j profile: org/apache/spark/log4j-defaults.properties 
Setting default log level to "WARN". 
To adjust logging level use sc.setLogLevel(newLevel). 
16/06/28 20:53:48 WARN NativeCodeLoader: Unable to load native-hadoop library for your platform... using builtin-java classes where applicable 
16/06/28 20:53:49 WARN SparkContext: Use an existing SparkContext, some configuration may not take effect. 
Spark context Web UI available at http://192.168.1.6:4040 
Spark context available as 'sc' (master = local[*], app id = local-1467143629623). 
Spark session available as 'spark'. 
Welcome to 
      ____              __ 
     / __/__  ___ _____/ /__ 
    _\ \/ _ \/ _ `/ __/  '_/ 
   /___/ .__/\_,_/_/ /_/\_\   version 2.0.1 
      /_/ 

Using Scala version 2.11.8 (Java HotSpot(TM) 64-Bit Server VM, Java 1.8.0_66) 
Type in expressions to have them evaluated. 
Type :help for more information. 
scala> 
scala>exit 

```

在前述显示中，验证 JDK 版本、Scala 版本和 Spark 版本是否与安装 Spark 的计算机中的设置相符。最重要的是验证没有错误消息显示。

以下命令集用于启动 Spark 的 Python REPL：

```scala
$ cd $SPARK_HOME 
$ ./bin/pyspark 
Python 3.5.0 (v3.5.0:374f501f4567, Sep 12 2015, 11:00:19)  
[GCC 4.2.1 (Apple Inc. build 5666) (dot 3)] on darwin 
Type "help", "copyright", "credits" or "license" for more information. 
Using Spark's default log4j profile: org/apache/spark/log4j-defaults.properties 
Setting default log level to "WARN". 
To adjust logging level use sc.setLogLevel(newLevel). 
16/06/28 20:58:04 WARN NativeCodeLoader: Unable to load native-hadoop library for your platform... using builtin-java classes where applicable 
Welcome to 
      ____              __ 
     / __/__  ___ _____/ /__ 
    _\ \/ _ \/ _ `/ __/  '_/ 
   /__ / .__/\_,_/_/ /_/\_\   version 2.0.1 
      /_/ 

Using Python version 3.5.0 (v3.5.0:374f501f4567, Sep 12 2015 11:00:19) 
SparkSession available as 'spark'. 
>>>exit() 

```

在前述显示中，验证 Python 版本和 Spark 版本是否与安装 Spark 的计算机中的设置相符。最重要的是验证没有错误消息显示。

以下命令集用于启动 Spark 的 R REPL：

```scala
$ cd $SPARK_HOME 
$ ./bin/sparkR 
R version 3.2.2 (2015-08-14) -- "Fire Safety" 
Copyright (C) 2015 The R Foundation for Statistical Computing 
Platform: x86_64-apple-darwin13.4.0 (64-bit) 

R is free software and comes with ABSOLUTELY NO WARRANTY. 
You are welcome to redistribute it under certain conditions. 
Type 'license()' or 'licence()' for distribution details. 

  Natural language support but running in an English locale 

R is a collaborative project with many contributors. 
Type 'contributors()' for more information and 
'citation()' on how to cite R or R packages in publications. 

Type 'demo()' for some demos, 'help()' for on-line help, or 
'help.start()' for an HTML browser interface to help. 
Type 'q()' to quit R. 

[Previously saved workspace restored] 

Launching java with spark-submit command /Users/RajT/source-code/spark-source/spark-2.0/bin/spark-submit   "sparkr-shell" /var/folders/nf/trtmyt9534z03kq8p8zgbnxh0000gn/T//RtmphPJkkF/backend_port59418b49bb6  
Using Spark's default log4j profile: org/apache/spark/log4j-defaults.properties 
Setting default log level to "WARN". 
To adjust logging level use sc.setLogLevel(newLevel). 
16/06/28 21:00:35 WARN NativeCodeLoader: Unable to load native-hadoop library for your platform... using builtin-java classes where applicable 

 Welcome to 
    ____              __  
   / __/__  ___ _____/ /__  
  _\ \/ _ \/ _ `/ __/  '_/  
 /___/ .__/\_,_/_/ /_/\_\   version  2.0.1 
    /_/  

 Spark context is available as sc, SQL context is available as sqlContext 
During startup - Warning messages: 
1: 'SparkR::sparkR.init' is deprecated. 
Use 'sparkR.session' instead. 
See help("Deprecated")  
2: 'SparkR::sparkRSQL.init' is deprecated. 
Use 'sparkR.session' instead. 
See help("Deprecated")  
>q() 

```

在前述显示中，验证 R 版本和 Spark 版本是否与安装 Spark 的计算机中的设置相符。最重要的是验证没有错误消息显示。

如果 Scala、Python 和 R 的所有 REPL 都运行良好，那么几乎可以肯定 Spark 安装是良好的。作为最终测试，运行一些随 Spark 附带的示例程序，并确保它们给出的结果与命令下方所示结果相近，且不在控制台抛出任何错误消息。当运行这些示例程序时，除了命令下方显示的输出外，控制台还会显示许多其他消息。为了专注于结果，这些消息被省略了：

```scala
$ cd $SPARK_HOME 
$ ./bin/run-example SparkPi 
Pi is roughly 3.1484 
$ ./bin/spark-submit examples/src/main/python/pi.py 
Pi is roughly 3.138680 
$ ./bin/spark-submit examples/src/main/r/dataframe.R 
root 
 |-- name: string (nullable = true) 
 |-- age: double (nullable = true) 
root 
 |-- age: long (nullable = true) 
 |-- name: string (nullable = true) 
    name 
1 Justin 

```

## 开发工具安装

本书中将要讨论的大部分代码都可以在相应的 REPL 中尝试和测试。但没有一些基本的构建工具，就无法进行适当的 Spark 应用程序开发。作为最低要求，对于使用 Scala 开发和构建 Spark 应用程序，**Scala 构建工具**（**sbt**）是必需的。访问[`www.scala-sbt.org`](http://www.scala-sbt.org/)以下载和安装 sbt。

Maven 是构建 Java 应用程序的首选构建工具。本书虽不涉及 Java 中的 Spark 应用程序开发，但系统中安装 Maven 也是有益的。如果需要从源代码构建 Spark，Maven 将派上用场。访问[`maven.apache.org`](https://maven.apache.org/)以下载并安装 Maven。

有许多**集成开发环境**（**IDEs**）适用于 Scala 和 Java。这是个人选择，开发者可以根据自己开发 Spark 应用程序所用的语言选择工具。

## 可选软件安装

Spark REPL for Scala 是开始进行代码片段原型设计和测试的好方法。但当需要开发、构建和打包 Scala 中的 Spark 应用程序时，拥有基于 sbt 的 Scala 项目并在支持的 IDE（包括但不限于 Eclipse 或 IntelliJ IDEA）中开发它们是明智的。访问相应的网站以下载并安装首选的 Scala IDE。

笔记本式应用程序开发工具在数据分析师和研究人员中非常普遍。这类似于实验室笔记本。在典型的实验室笔记本中，会有指导、详细描述和步骤，以进行实验。然后进行实验。一旦实验完成，结果将被记录在笔记本中。如果将所有这些构造结合起来，并将其置于软件程序的上下文中，以实验室笔记本格式建模，将会有文档、代码、输入和运行代码产生的输出。这将产生非常好的效果，特别是如果程序生成大量图表和绘图。

### 提示

对于不熟悉笔记本式应用程序开发 IDE 的人，有一篇很好的文章名为*交互式笔记本：共享代码*，可从[`www.nature.com/news/interactive-notebooks-sharing-the-code-1.16261`](http://www.nature.com/news/interactive-notebooks-sharing-the-code-1.16261)阅读。作为 Python 的可选软件开发 IDE，IPython 笔记本将在下一节中描述。安装后，请先熟悉该工具，再进行严肃的开发。

### IPython

在 Python 中开发 Spark 应用程序时，IPython 提供了一个出色的笔记本式开发工具，它是 Jupyter 的 Python 语言内核。Spark 可以与 IPython 集成，以便当调用 Python 的 Spark REPL 时，它将启动 IPython 笔记本。然后，创建一个笔记本并在其中编写代码，就像在 Python 的 Spark REPL 中给出命令一样。访问[`ipython.org`](http://ipython.org/)下载并安装 IPython 笔记本。安装完成后，调用 IPython 笔记本界面，并确保一些示例 Python 代码运行正常。从存储笔记本的目录或将要存储笔记本的目录调用命令。这里，IPython 笔记本是从临时目录启动的。当调用以下命令时，它将打开 Web 界面，从中通过点击“新建”下拉框并选择适当的 Python 版本来创建新笔记本。

下图展示了如何在 IPython 笔记本中将 Markdown 风格的文档、Python 程序以及生成的输出结合起来：

```scala
$ cd /Users/RajT/temp 
$ ipython notebook 

```

![IPython](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_01_011.jpg)

*图 6*

*图 6*展示了如何使用 IPython 笔记本编写简单的 Python 程序。IPython 笔记本可以配置为 Spark 的首选 Shell，当调用 Python 的 Spark REPL 时，它将启动 IPython 笔记本，从而可以使用 IPython 笔记本进行 Spark 应用程序开发。为此，需要在适当的用户配置文件中定义以下环境变量：

```scala
export PYSPARK_DRIVER_PYTHON=ipython 
export PYSPARK_DRIVER_PYTHON_OPTS='notebook' 

```

现在，不是从命令提示符调用 IPython 笔记本，而是调用 Python 的 Spark REPL。就像之前所做的那样，创建一个新的 IPython 笔记本并在其中编写 Spark 代码：

```scala
$ cd /Users/RajT/temp 
$ pyspark 

```

请看下面的截图：

![IPython](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_01_012.jpg)

*图 7*

### 提示

在任何语言的标准 Spark REPL 中，都可以通过相对路径引用本地文件系统中的文件。当使用 IPython 笔记本时，需要通过完整路径引用本地文件。

### RStudio

在 R 用户社区中，首选的 IDE 是 RStudio。RStudio 也可用于开发 R 中的 Spark 应用程序。访问[`www.rstudio.com`](https://www.rstudio.com/)下载并安装 RStudio。安装完成后，在运行任何 Spark R 代码之前，必须包含`SparkR`库并设置一些变量，以确保从 RStudio 顺利运行 Spark R 程序。以下代码片段实现了这一点：

```scala
SPARK_HOME_DIR <- "/Users/RajT/source-code/spark-source/spark-2.0" 
Sys.setenv(SPARK_HOME=SPARK_HOME_DIR) 
.libPaths(c(file.path(Sys.getenv("SPARK_HOME"), "R", "lib"), .libPaths())) 
library(SparkR) 
spark <- sparkR.session(master="local[*]")

```

在前述 R 代码中，将`SPARK_HOME_DIR`变量定义更改为指向 Spark 安装目录。*图 8*展示了从 RStudio 运行 Spark R 代码的示例：

![RStudio](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_01_013.jpg)

*图 8*

一旦所有必需的软件安装、配置并按先前所述正常运行，便可以开始在 Scala、Python 和 R 中进行 Spark 应用程序开发。

### 提示

Jupyter 笔记本通过为各种语言定制内核实现策略支持多种语言。Jupyter 有一个原生的 R 内核，即 IRkernel，可以作为 R 包安装。

### Apache Zeppelin

Apache Zeppelin 是另一个目前正处于孵化阶段的有前景的项目。它是一个基于 Web 的笔记本，类似于 Jupyter，但通过其解释器策略支持多种语言、Shell 和技术，从而内在地支持 Spark 应用程序开发。目前它还处于初期阶段，但有很大的潜力成为最佳的基于笔记本的应用程序开发平台之一。Zeppelin 利用笔记本中编写的程序生成的数据，具备非常强大的内置图表和绘图功能。

Zeppelin 具有高度的可扩展性，能够通过其解释器框架插入多种类型的解释器。终端用户，就像使用任何其他基于笔记本的系统一样，在笔记本界面中输入各种命令。这些命令需要由某个解释器处理以生成输出。与许多其他笔记本风格的系统不同，Zeppelin 开箱即支持大量解释器或后端，如 Spark、Spark SQL、Shell、Markdown 等。在前端方面，它同样采用可插拔架构，即**Helium 框架**。后端生成的数据由前端组件（如 Angular JS）显示。有多种选项可以显示数据，包括表格格式、解释器生成的原始格式、图表和绘图。由于后端、前端以及能够插入各种组件的架构分离关注点，它是一种选择异构组件以适应不同任务的绝佳方式。同时，它能够很好地集成，提供一个和谐的用户友好型数据处理生态系统。尽管 Zeppelin 为各种组件提供了可插拔架构能力，但其可视化选项有限。换句话说，Zeppelin 开箱即用提供的图表和绘图选项并不多。一旦笔记本正常工作并产生预期结果，通常会将笔记本共享给其他人，为此，笔记本需要被持久化。Zeppelin 在这方面再次与众不同，它拥有一个高度灵活的笔记本存储系统。笔记本可以持久化到文件系统、Amazon S3 或 Git，并且如有需要，还可以添加其他存储目标。

**平台即服务**（**PaaS**）自云计算作为应用开发和部署平台以来，在过去几年中经历了巨大的创新和发展。对于软件开发者而言，通过云提供的众多 PaaS 平台消除了他们拥有自己的应用开发栈的需求。Databricks 推出了一款基于云的大数据平台，用户可以访问基于笔记本的 Spark 应用开发界面，并与微集群基础设施相结合，以便提交 Spark 应用。此外，还有一个社区版，服务于更广泛的开发社区。该 PaaS 平台最大的优势在于它是一个基于浏览器的界面，用户可以在多个版本的 Spark 和不同类型的集群上运行代码。

# 参考文献

更多信息请参考以下链接：

+   [`static.googleusercontent.com/media/research.google.com/en//archive/gfs-sosp2003.pdf`](http://static.googleusercontent.com/media/research.google.com/en//archive/gfs-sosp2003.pdf)

+   [`static.googleusercontent.com/media/research.google.com/en//archive/mapreduce-osdi04.pdf`](http://static.googleusercontent.com/media/research.google.com/en//archive/mapreduce-osdi04.pdf)

+   [`www.cs.berkeley.edu/~alig/papers/mesos.pdf`](https://www.cs.berkeley.edu/~alig/papers/mesos.pdf)

+   [`spark.apache.org/`](http://spark.apache.org/)

+   [`jupyter.org/`](https://jupyter.org/)

+   [`github.com/IRkernel/IRkernel`](https://github.com/IRkernel/IRkernel)

+   [`zeppelin.incubator.apache.org/`](https://zeppelin.incubator.apache.org/)

+   [`community.cloud.databricks.com/`](https://community.cloud.databricks.com/)

# 摘要

Spark 是一个功能强大的数据处理平台，支持统一的编程模型。它支持 Scala、Java、Python 和 R 中的应用程序开发，提供了一系列高度互操作的库，用于满足各种数据处理需求，以及大量利用 Spark 生态系统的第三方库，涵盖了其他各种数据处理用例。本章简要介绍了 Spark，并为本书后续章节将要介绍的 Spark 应用程序开发设置了开发环境。

下一章将讨论 Spark 编程模型、基本抽象和术语、Spark 转换和 Spark 操作，结合实际用例进行阐述。


# 第二章：Spark 编程模型

**提取**、**转换**和**加载**（**ETL**）工具随着组织中数据的增长，大量涌现。将数据从一个源移动到一个或多个目的地，并在到达目的地之前对其进行实时处理，这些都是当时的需求。大多数情况下，这些 ETL 工具仅支持少数类型的数据，少数类型的数据源和目的地，并且对扩展以支持新数据类型和新源和目的地持封闭态度。由于这些工具的严格限制，有时甚至一个步骤的转换过程也必须分多个步骤完成。这些复杂的方法要求在人力以及其他计算资源方面产生不必要的浪费。商业 ETL 供应商的主要论点始终如一，那就是“一刀切”并不适用。因此，请使用*我们*的工具套件，而不是市场上可用的单一产品。许多组织因处理数据的迫切需求而陷入供应商锁定。几乎所有在 2005 年之前推出的工具，如果它们支持在商品硬件上运行，都没有充分利用计算机多核架构的真正力量。因此，简单但大量的数据处理任务使用这些工具需要数小时甚至数天才能完成。

Spark 因其处理大量数据类型以及不断增长的数据源和数据目的地的能力而在市场上迅速走红。Spark 提供的最重要的基本数据抽象是**弹性分布式数据集**（**RDD**）。如前一章所述，Spark 支持在节点集群上进行分布式处理。一旦有了节点集群，在数据处理过程中，某些节点可能会死亡。当此类故障发生时，框架应能够从中恢复。Spark 的设计就是为了做到这一点，这就是 RDD 中*弹性*部分的含义。如果有大量数据要处理，并且集群中有可用节点，框架应具备将大数据集分割成小块并在集群中多个节点上并行处理的能力。Spark 能够做到这一点，这就是 RDD 中*分布式*部分的含义。换句话说，Spark 从一开始就设计其基本数据集抽象能够确定性地分割成小块，并在集群中多个节点上并行处理，同时优雅地处理节点故障。

本章我们将涵盖以下主题：

+   使用 Spark 进行函数式编程

+   Spark RDD

+   数据转换与操作

+   Spark 监控

+   Spark 编程基础

+   从文件创建 RDD

+   Spark 库

# 使用 Spark 进行函数式编程

运行时对象的变异，以及由于程序逻辑产生的副作用而无法从程序或函数中获得一致的结果，使得许多应用程序变得非常复杂。如果编程语言中的函数开始表现得完全像数学函数一样，即函数的输出仅依赖于输入，那么这为应用程序提供了大量的可预测性。计算机编程范式强调构建这种函数和其他元素的过程，并使用这些函数就像使用任何其他数据类型一样，这种范式被称为函数式编程范式。在基于 JVM 的编程语言中，Scala 是最重要的语言之一，它具有非常强大的函数式编程能力，同时不失面向对象的特性。Spark 主要使用 Scala 编写。正因为如此，Spark 从 Scala 中借鉴了许多优秀的概念。

# 理解 Spark RDD

Spark 从 Scala 中借鉴的最重要特性是能够将函数作为参数传递给 Spark 转换和 Spark 操作。通常情况下，Spark 中的 RDD 表现得就像 Scala 中的集合对象一样。因此，Scala 集合中的一些数据转换方法名称在 Spark RDD 中被用来执行相同的操作。这是一种非常简洁的方法，熟悉 Scala 的开发者会发现使用 RDD 编程非常容易。我们将在后续章节中看到一些重要的特性。

## Spark RDD 是不可变的

创建 RDD 有一些严格的规则。一旦 RDD 被创建，无论是故意还是无意，它都不能被更改。这为我们理解 RDD 的构造提供了另一个视角。正因为如此，当处理 RDD 某部分的节点崩溃时，驱动程序可以重新创建这些部分，并将处理任务分配给另一个节点，最终成功完成数据处理工作。

由于 RDD 是不可变的，因此可以将大型 RDD 分割成小块，分发到各个工作节点进行处理，并最终编译结果以生成最终结果，而无需担心底层数据被更改。

## Spark RDD 是可分布的

如果 Spark 在集群模式下运行，其中有多台工作节点可以接收任务，所有这些节点将具有不同的执行上下文。各个任务被分发并在不同的 JVM 上运行。所有这些活动，如大型 RDD 被分割成小块，被分发到工作节点进行处理，最后将结果重新组装，对用户是完全隐藏的。

Spark 拥有自己的机制来从系统故障和其他数据处理过程中发生的错误中恢复，因此这种数据抽象具有极高的弹性。

## Spark RDD 存储在内存中

Spark 尽可能将所有 RDD 保留在内存中。仅在极少数情况下，如 Spark 内存不足或数据量增长超出容量时，数据才会被写入磁盘。RDD 的大部分处理都在内存中进行，这也是 Spark 能够以极快速度处理数据的原因。

## Spark RDD 是强类型的

Spark RDD 可以使用任何受支持的数据类型创建。这些数据类型可以是 Scala/Java 支持的固有数据类型，也可以是自定义创建的数据类型，如您自己的类。这一设计决策带来的最大优势是避免了运行时错误。如果因数据类型问题导致程序崩溃，它将在编译时崩溃。

下表描述了包含零售银行账户数据元组的 RDD 结构。其类型为 RDD[(string, string, string, double)]：

| **账户号** | **名字** | **姓氏** | **账户余额** |
| --- | --- | --- | --- |
| SB001 | John | Mathew | 250.00 |
| SB002 | Tracy | Mason | 450.00 |
| SB003 | Paul | Thomson | 560.00 |
| SB004 | Samantha | Grisham | 650.00 |
| SB005 | John | Grove | 1000.00 |

假设此 RDD 正在一个包含三个节点 N1、N2 和 N3 的集群中进行处理，以计算所有这些账户的总金额；它可以被分割并分配，例如用于并行数据处理。下表包含了分配给节点 N1 进行处理的 RDD[(string, string, string, double)]的元素：

| **账户号** | **名字** | **姓氏** | **账户余额** |
| --- | --- | --- | --- |
| SB001 | John | Mathew | 250.00 |
| SB002 | Tracy | Mason | 450.00 |

下表包含了分配给节点 N2 进行处理的 RDD[(string, string, string, double)]的元素：

| **账户号** | **名字** | **姓氏** | **账户余额** |
| --- | --- | --- | --- |
| SB003 | Paul | Thomson | 560.00 |
| SB004 | Samantha | Grisham | 650.00 |
| SB005 | John | Grove | 1000.00 |

在节点 N1 上，求和过程发生并将结果返回给 Spark 驱动程序。同样，在节点 N2 上，求和过程发生，结果返回给 Spark 驱动程序，并计算最终结果。

Spark 在将大型 RDD 分割成小块并分配给各个节点方面有非常确定的规则，因此，即使某个节点如 N1 出现问题，Spark 也知道如何精确地重新创建丢失的块，并通过将相同的负载发送到节点 N3 来继续数据处理操作。

图 1 捕捉了该过程的本质：

![Spark RDD 是强类型的](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_02_002.jpg)

图 1

### 提示

Spark 在其驱动内存和集群节点的执行器内存中进行大量处理。Spark 有多种可配置和微调的参数，以确保在处理开始前所需的资源已就绪。

# 使用 RDD 进行数据转换和操作

Spark 使用 RDD 进行数据处理。从相关的数据源（如文本文件和 NoSQL 数据存储）读取数据以形成 RDD。对这样的 RDD 执行各种数据转换，并最终收集结果。确切地说，Spark 提供了作用于 RDD 的 Spark 转换和 Spark 动作。让我们以捕获零售银行业务交易列表的以下 RDD 为例，其类型为 RDD[(string, string, double)]：

| **账户号** | **交易号** | **交易金额** |
| --- | --- | --- |
| SB001 | TR001 | 250.00 |
| SB002 | TR004 | 450.00 |
| SB003 | TR010 | 120.00 |
| SB001 | TR012 | -120.00 |
| SB001 | TR015 | -10.00 |
| SB003 | TR020 | 100.00 |

从形式为`(AccountNo,TranNo,TranAmount)`的 RDD 计算账户级交易摘要：

1.  首先需要将其转换为键值对形式`(AccountNo,TranAmount)`，其中`AccountNo`是键，但会有多个具有相同键的元素。

1.  在此键上对`TranAmount`执行求和操作，生成另一个 RDD，形式为(AccountNo,TotalAmount)，其中每个 AccountNo 只有一个元素，TotalAmount 是给定 AccountNo 的所有 TranAmount 的总和。

1.  现在按`AccountNo`对键值对进行排序并存储输出。

在整个描述的过程中，除了存储输出结果外，其余均为 Spark 转换操作。存储输出结果是一项**Spark 动作**。Spark 根据需要执行这些操作。当应用 Spark 转换时，Spark 不会立即执行。真正的执行发生在链中的第一个 Spark 动作被调用时。然后它会按顺序勤奋地应用所有先前的 Spark 转换，并执行遇到的第一个 Spark 动作。这是基于**惰性求值**的概念。

### 注意

在编程语言中声明和使用变量的上下文中，*惰性求值*意味着变量只在程序中首次使用时才进行求值。

除了将输出存储到磁盘的动作外，还有许多其他可能的 Spark 动作，包括但不限于以下列表中的一些：

+   将结果 RDD 中的所有内容收集到驱动程序中的数组

+   计算 RDD 中元素的数量

+   计算 RDD 元素中每个键的元素数量

+   获取 RDD 中的第一个元素

+   从常用的 RDD 中取出指定数量的元素用于生成 Top N 报告

+   从 RDD 中抽取元素样本

+   遍历 RDD 中的所有元素

在此示例中，对各种 RDD 进行了多次转换，这些 RDD 是在流程完成过程中动态创建的。换句话说，每当对 RDD 进行转换时，都会创建一个新的 RDD。这是因为 RDD 本质上是不可变的。在每个转换结束时创建的这些 RDD 可以保存以供将来参考，或者它们最终会超出作用域。

总结来说，创建一个或多个 RDD 并对它们应用转换和操作的过程是 Spark 应用程序中非常普遍的使用模式。

### 注意

前面数据转换示例中提到的表包含一个类型为 RDD[(string, string, double)]的 RDD 中的值。在这个 RDD 中，有多个元素，每个元素都是一个类型为(string, string, double)的元组。为了便于参考和传达思想，程序员和用户社区通常使用术语`记录`来指代 RDD 中的一个元素。在 Spark RDD 中，没有记录、行和列的概念。换句话说，术语`记录`被错误地用作 RDD 中元素的同义词，这可能是一个复杂的数据类型，如元组或非标量数据类型。在本书中，我们尽量避免使用这种做法，而是使用正确的术语。

Spark 提供了大量的 Spark 转换。这些转换非常强大，因为大多数转换都以函数作为输入参数来进行转换。换句话说，这些转换根据用户定义和提供的函数作用于 RDD。Spark 的统一编程模型使得这一点更加强大。无论选择的编程语言是 Scala、Java、Python 还是 R，使用 Spark 转换和 Spark 操作的方式都是相似的。这使得组织可以选择他们偏好的编程语言。

Spark 中虽然 Spark 操作的数量有限，但它们非常强大，如果需要，用户可以编写自己的 Spark 操作。市场上有许多 Spark 连接器程序，主要用于从各种数据存储中读取和写写数据。这些连接器程序由用户社区或数据存储供应商设计和开发，以实现与 Spark 的连接。除了现有的 Spark 操作外，它们可能还会定义自己的操作来补充现有的 Spark 操作集合。例如，Spark Cassandra 连接器用于从 Spark 连接到 Cassandra，它有一个操作`saveToCassandra`。

# Spark 监控

前一章节详细介绍了使用 Spark 开发和运行数据处理应用程序所需的安装和开发工具设置。在大多数现实世界的应用中，Spark 应用程序可能会变得非常复杂，涉及一个庞大的**有向无环图**(**DAG**)，其中包含 Spark 转换和 Spark 操作。Spark 自带了非常强大的监控工具，用于监控特定 Spark 生态系统中运行的作业。但监控不会自动启动。

### 提示

请注意，这是运行 Spark 应用程序的一个完全可选步骤。如果启用，它将提供关于 Spark 应用程序运行方式的深刻见解。在生产环境中启用此功能需谨慎，因为它可能会影响应用程序的响应时间。

首先，需要进行一些配置更改。事件日志机制应开启。为此，请执行以下步骤：

```scala
$ cd $SPARK_HOME 
$ cd conf 
$ cp spark-defaults.conf.template spark-defaults.conf

```

完成前述步骤后，编辑新创建的`spark-defaults.conf`文件，使其包含以下属性：

```scala
spark.eventLog.enabled           true 
spark.eventLog.dir               <give a log directory location> 

```

### 提示

完成前述步骤后，确保之前使用的日志目录存在于文件系统中。

除了上述配置文件的更改外，该配置文件中还有许多属性可以更改以微调 Spark 运行时。其中最常用且最重要的是 Spark 驱动程序内存。如果应用程序处理大量数据，将此属性`spark.driver.memory`设置为较高值是个好主意。然后运行以下命令以启动 Spark 主节点：

```scala
$ cd $SPARK_HOME 
$ ./sbin/start-master.sh

```

完成前述步骤后，确保通过访问`http://localhost:8080/`启动 Spark Web **用户界面** (**UI**)。这里假设`8080`端口上没有其他应用程序运行。如果出于某种原因，需要在不同的端口上运行此应用程序，可以在启动 Web 用户界面的脚本中使用命令行选项`--webui-port <PORT>`。

Web UI 应该类似于图 2 所示：

![使用 Spark 进行监控](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_02_003.jpg)

图 2

前述图中最重要的信息是完整的 Spark 主 URL（不是 REST URL）。它将在本书中讨论的许多实践练习中反复使用。该 URL 可能因系统而异，并受 DNS 设置影响。还要注意，本书中所有实践练习均使用 Spark 独立部署，这是在单台计算机上开始部署最简单的方式。

### 提示

现在给出这些 Spark 应用程序监控步骤，是为了让读者熟悉 Spark 提供的工具集。熟悉这些工具或对应用程序行为非常自信的人可能不需要这些工具的帮助。但为了理解概念、调试以及一些过程的可视化，这些工具无疑提供了巨大的帮助。

从图 2 所示的 Spark Web UI 中可以看出，没有可用于执行任何任务的工作节点，也没有正在运行的应用程序。以下步骤记录了启动工作节点的指令。注意在启动工作节点时如何使用 Spark 主 URL：

```scala
$ cd $SPARK_HOME 
$ ./sbin/start-slave.sh spark://Rajanarayanans-MacBook-Pro.local:7077

```

一旦 worker 节点启动，在 Spark Web UI 中，新启动的 worker 节点将被显示。`$SPARK_HOME/conf/slaves.template`模板捕获了默认的 worker 节点，这些节点将在执行上述命令时启动。

### 注意

如果需要额外的 worker 节点，将`slaves.template`文件复制并重命名为 slaves，并在其中捕获条目。当启动 spark-shell、pyspark 或 sparkR 时，可以给出指令让其使用特定的 Spark master。这在需要远程 Spark 集群或针对特定 Spark master 运行 Spark 应用程序或语句时非常有用。如果没有给出任何内容，Spark 应用程序将在本地模式下运行。

```scala
$ cd $SPARK_HOME 
$ ./bin/spark-shell --master spark://Rajanarayanans-MacBook-Pro.local:7077 

```

Spark Web UI 在成功启动 worker 节点后将类似于图 3 所示。之后，如果使用上述 Spark master URL 运行应用程序，该应用程序的详细信息也会显示在 Spark Web UI 中。本章后续将详细介绍应用程序。使用以下脚本停止 worker 和 master 进程：

```scala
$ cd $SPARK_HOME 
$ ./sbin/stop-all.sh

```

![使用 Spark 进行监控](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_02_004.jpg)

图 3

# Spark 编程基础

Spark 编程围绕 RDD 展开。在任何 Spark 应用程序中，待处理的数据被用来创建适当的 RDD。首先，从创建 RDD 的最基本方式开始，即从一个列表开始。用于这种`hello world`类型应用程序的输入数据是一小部分零售银行交易。为了解释核心概念，只选取了一些非常基础的数据项。交易记录包含账户号和交易金额。

### 提示

在本书的所有用例中，如果使用术语“记录”，那将是在业务或用例的上下文中。

以下是用于阐释 Spark 转换和 Spark 动作的用例：

1.  交易记录以逗号分隔的值形式传入。

1.  从列表中筛选出仅包含良好交易记录的部分。账户号应以`SB`开头，且交易金额应大于零。

1.  查找所有交易金额大于 1000 的高价值交易记录。

1.  查找所有账户号有问题的交易记录。

1.  查找所有交易金额小于或等于零的交易记录。

1.  查找所有不良交易记录的合并列表。

1.  计算所有交易金额的总和。

1.  找出所有交易金额的最大值。

1.  找出所有交易金额的最小值。

1.  查找所有良好账户号。

本书中将遵循的方法是，对于任何将要开发的应用程序，都从适用于相应语言的 Spark REPL 开始。启动 Scala REPL 以使用 Spark，并确保它无错误启动且可以看到提示符。对于此应用程序，我们将启用监控以学习如何操作，并在开发过程中使用它。除了显式启动 Spark 主节点和从节点外，Spark 还提供了一个脚本，该脚本将使用单个脚本同时启动这两个节点。然后，使用 Spark 主 URL 启动 Scala REPL：

```scala
$ cd $SPARK_HOME 
$ ./sbin/start-all.sh 
$ ./bin/spark-shell --master spark://Rajanarayanans-MacBook-Pro.local:7077 

```

在 Scala REPL 提示符下，尝试以下语句。语句的输出以粗体显示。请注意，`scala>`是 Scala REPL 提示符：

```scala
scala> val acTransList = Array("SB10001,1000", "SB10002,1200", "SB10003,8000", "SB10004,400", "SB10005,300", "SB10006,10000", "SB10007,500", "SB10008,56", "SB10009,30","SB10010,7000", "CR10001,7000", "SB10002,-10") 
acTransList: Array[String] = Array(SB10001,1000, SB10002,1200, SB10003,8000, SB10004,400, SB10005,300, SB10006,10000, SB10007,500, SB10008,56, SB10009,30, SB10010,7000, CR10001,7000, SB10002,-10) 
scala> val acTransRDD = sc.parallelize(acTransList) 
acTransRDD: org.apache.spark.rdd.RDD[String] = ParallelCollectionRDD[0] at parallelize at <console>:23 
scala> val goodTransRecords = acTransRDD.filter(_.split(",")(1).toDouble > 0).filter(_.split(",")(0).startsWith("SB")) 
goodTransRecords: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[2] at filter at <console>:25 
scala> val highValueTransRecords = goodTransRecords.filter(_.split(",")(1).toDouble > 1000) 
highValueTransRecords: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[3] at filter at <console>:27 
scala> val badAmountLambda = (trans: String) => trans.split(",")(1).toDouble <= 0 
badAmountLambda: String => Boolean = <function1> 
scala> val badAcNoLambda = (trans: String) => trans.split(",")(0).startsWith("SB") == false 
badAcNoLambda: String => Boolean = <function1> 
scala> val badAmountRecords = acTransRDD.filter(badAmountLambda) 
badAmountRecords: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[4] at filter at <console>:27 
scala> val badAccountRecords = acTransRDD.filter(badAcNoLambda) 
badAccountRecords: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[5] at filter at <console>:27 
scala> val badTransRecords  = badAmountRecords.union(badAccountRecords) 
badTransRecords: org.apache.spark.rdd.RDD[String] = UnionRDD[6] at union at <console>:33

```

除第一个 RDD 创建和两个函数值定义外，所有先前的语句都属于一类，即 Spark 转换。以下是迄今为止所做操作的逐步详细说明：

+   值`acTransList`是包含逗号分隔交易记录的数组。

+   值`acTransRDD`是从数组创建的 RDD，其中`sc`是 Spark 上下文或 Spark 驱动程序，RDD 以并行化方式创建，使得 RDD 元素能够形成分布式数据集。换句话说，向 Spark 驱动程序发出指令，以从给定值集合形成并行集合或 RDD。

+   值`goodTransRecords`是从`acTransRDD`创建的 RDD，经过过滤条件筛选，交易金额大于 0 且账户号码以`SB`开头。

+   值`highValueTransRecords`是从`goodTransRecords`创建的 RDD，经过过滤条件筛选，交易金额大于 1000。

+   接下来的两条语句将函数定义存储在 Scala 值中，以便稍后轻松引用。

+   值`badAmountRecords`和`badAccountRecords`是从`acTransRDD`创建的 RDD，分别用于过滤包含错误交易金额和无效账户号码的不良记录。

+   值`badTransRecords`包含`badAmountRecords`和`badAccountRecords`两个 RDD 元素的并集。

到目前为止，此应用程序的 Spark Web UI 将不会显示任何内容，因为仅执行了 Spark 转换。真正的活动将在执行第一个 Spark 动作后开始。

以下语句是已执行语句的延续：

```scala
scala> acTransRDD.collect() 
res0: Array[String] = Array(SB10001,1000, SB10002,1200, SB10003,8000, SB10004,400, SB10005,300, SB10006,10000, SB10007,500, SB10008,56, SB10009,30, SB10010,7000, CR10001,7000, SB10002,-10) 
scala> goodTransRecords.collect() 
res1: Array[String] = Array(SB10001,1000, SB10002,1200, SB10003,8000, SB10004,400, SB10005,300, SB10006,10000, SB10007,500, SB10008,56, SB10009,30, SB10010,7000) 
scala> highValueTransRecords.collect() 
res2: Array[String] = Array(SB10002,1200, SB10003,8000, SB10006,10000, SB10010,7000) 
scala> badAccountRecords.collect() 
res3: Array[String] = Array(CR10001,7000) 
scala> badAmountRecords.collect() 
res4: Array[String] = Array(SB10002,-10) 
scala> badTransRecords.collect() 
res5: Array[String] = Array(SB10002,-10, CR10001,7000) 

```

所有先前的语句执行了一项操作，即对之前*定义*的 RDD 执行 Spark 动作。只有在 RDD 上触发 Spark 动作时，才会对 RDD 进行评估。以下语句正在对 RDD 进行一些计算：

```scala
scala> val sumAmount = goodTransRecords.map(trans => trans.split(",")(1).toDouble).reduce(_ + _) 
sumAmount: Double = 28486.0 
scala> val maxAmount = goodTransRecords.map(trans => trans.split(",")(1).toDouble).reduce((a, b) => if (a > b) a else b) 
maxAmount: Double = 10000.0 
scala> val minAmount = goodTransRecords.map(trans => trans.split(",")(1).toDouble).reduce((a, b) => if (a < b) a else b) 
minAmount: Double = 30.0

```

前述数字计算了来自良好记录的所有交易金额的总和、最大值和最小值。在前述所有转换中，交易记录一次处理一条。从这些记录中，提取账户号和交易金额并进行处理。这样做是因为用例需求如此。现在，每个交易记录中的逗号分隔值将被分割，而不考虑它是账户号还是交易金额。结果 RDD 将包含一个集合，其中所有这些混合在一起。从中提取以`SB`开头的元素，将得到良好的账户号码。以下语句将执行此操作：

```scala
scala> val combineAllElements = acTransRDD.flatMap(trans => trans.split(",")) 
combineAllElements: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[10] at flatMap at <console>:25 
scala> val allGoodAccountNos = combineAllElements.filter(_.startsWith("SB")) 
allGoodAccountNos: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[11] at filter at <console>:27 
scala> combineAllElements.collect() 
res10: Array[String] = Array(SB10001, 1000, SB10002, 1200, SB10003, 8000, SB10004, 400, SB10005, 300, SB10006, 10000, SB10007, 500, SB10008, 56, SB10009, 30, SB10010, 7000, CR10001, 7000, SB10002, -10) 
scala> allGoodAccountNos.distinct().collect() 
res14: Array[String] = Array(SB10006, SB10010, SB10007, SB10008, SB10009, SB10001, SB10002, SB10003, SB10004, SB10005)

```

此时，如果打开 Spark Web UI，与图 3 不同，可以注意到一个差异。由于已经执行了一些 Spark 操作，将显示一个应用程序条目。由于 Spark 的 Scala REPL 仍在运行，它显示在仍在运行的应用程序列表中。图 4 捕捉了这一点：

![Spark 编程基础](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_02_005.jpg)

图 4

点击应用程序 ID 进行导航，以查看与运行中的应用程序相关的所有指标，包括 DAG 可视化图表等更多内容。

这些语句涵盖了讨论过的所有用例，值得回顾迄今为止介绍的 Spark 转换。以下是一些基本但非常重要的转换，它们将在大多数应用程序中反复使用：

| **Spark 转换** | **功能描述** |
| --- | --- |
| `filter(fn)` | **遍历 RDD 中的所有元素，应用传入的函数，并选取函数评估为真的元素。** |
| `map(fn)` | 遍历 RDD 中的所有元素，应用传入的函数，并选取函数返回的输出。 |
| `flatMap(fn)` | 遍历 RDD 中的所有元素，应用传入的函数，并选取函数返回的输出。与 Spark 转换`map(fn)`的主要区别在于，该函数作用于单个元素并返回一个扁平的元素集合。例如，它将一条银行交易记录拆分为多个字段，从单个元素生成一个集合。 |
| `union(other)` | 获取此 RDD 和另一个 RDD 的所有元素的并集。 |

同样值得回顾迄今为止介绍的 Spark 动作。这些是一些基本动作，但后续将介绍更多动作。

| **Spark 动作** | **功能描述** |
| --- | --- |
| `collect()` | **将 RDD 中的所有元素收集到 Spark 驱动程序中的数组中。** |
| `reduce(fn)` | 对 RDD 的所有元素应用函数 fn，并根据函数定义计算最终结果。该函数应接受两个参数并返回一个结果，且具有交换性和结合性。 |
| `foreach(fn)` | 对 RDD 的所有元素应用函数 fn。这主要用于产生副作用。Spark 转换`map(fn)`将函数应用于 RDD 的所有元素并返回另一个 RDD。但`foreach(fn)` Spark 转换不返回 RDD。例如，`foreach(println)`将从 RDD 中取出每个元素并将其打印到控制台。尽管这里未涉及的用例中未使用它，但值得一提。 |

学习 Spark 的下一步是尝试在 Python REPL 中执行语句，覆盖完全相同的用例。变量定义在两种语言中尽可能保持相似，以便轻松吸收概念。与 Scala 方式相比，这里使用的方式可能会有细微差别；从概念上讲，它与所选语言无关。

启动 Spark 的 Python REPL，并确保它无错误启动且能看到提示符。在尝试 Scala 代码时，监控已启用。现在使用 Spark 主 URL 启动 Python REPL：

```scala
$ cd $SPARK_HOME 
$ ./bin/pyspark --master spark://Rajanarayanans-MacBook-Pro.local:7077 

```

在 Python REPL 提示符下，尝试以下语句。语句的输出以粗体显示。请注意，`>>>`是 Python REPL 提示符：

```scala
>>> from decimal import Decimal 
>>> acTransList = ["SB10001,1000", "SB10002,1200", "SB10003,8000", "SB10004,400", "SB10005,300", "SB10006,10000", "SB10007,500", "SB10008,56", "SB10009,30","SB10010,7000", "CR10001,7000", "SB10002,-10"] 
>>> acTransRDD = sc.parallelize(acTransList) 
>>> goodTransRecords = acTransRDD.filter(lambda trans: Decimal(trans.split(",")[1]) > 0).filter(lambda trans: (trans.split(",")[0]).startswith('SB') == True) 
>>> highValueTransRecords = goodTransRecords.filter(lambda trans: Decimal(trans.split(",")[1]) > 1000) 
>>> badAmountLambda = lambda trans: Decimal(trans.split(",")[1]) <= 0 
>>> badAcNoLambda = lambda trans: (trans.split(",")[0]).startswith('SB') == False 
>>> badAmountRecords = acTransRDD.filter(badAmountLambda) 
>>> badAccountRecords = acTransRDD.filter(badAcNoLambda) 
>>> badTransRecords  = badAmountRecords.union(badAccountRecords) 
>>> acTransRDD.collect() 
['SB10001,1000', 'SB10002,1200', 'SB10003,8000', 'SB10004,400', 'SB10005,300', 'SB10006,10000', 'SB10007,500', 'SB10008,56', 'SB10009,30', 'SB10010,7000', 'CR10001,7000', 'SB10002,-10'] 
>>> goodTransRecords.collect() 
['SB10001,1000', 'SB10002,1200', 'SB10003,8000', 'SB10004,400', 'SB10005,300', 'SB10006,10000', 'SB10007,500', 'SB10008,56', 'SB10009,30', 'SB10010,7000'] 
>>> highValueTransRecords.collect() 
['SB10002,1200', 'SB10003,8000', 'SB10006,10000', 'SB10010,7000'] 
>>> badAccountRecords.collect() 
['CR10001,7000'] 
>>> badAmountRecords.collect() 
['SB10002,-10'] 
>>> badTransRecords.collect() 
['SB10002,-10', 'CR10001,7000'] 
>>> sumAmounts = goodTransRecords.map(lambda trans: Decimal(trans.split(",")[1])).reduce(lambda a,b : a+b) 
>>> sumAmounts 
Decimal('28486') 
>>> maxAmount = goodTransRecords.map(lambda trans: Decimal(trans.split(",")[1])).reduce(lambda a,b : a if a > b else b) 
>>> maxAmount 
Decimal('10000') 
>>> minAmount = goodTransRecords.map(lambda trans: Decimal(trans.split(",")[1])).reduce(lambda a,b : a if a < b else b) 
>>> minAmount 
Decimal('30') 
>>> combineAllElements = acTransRDD.flatMap(lambda trans: trans.split(",")) 
>>> combineAllElements.collect() 
['SB10001', '1000', 'SB10002', '1200', 'SB10003', '8000', 'SB10004', '400', 'SB10005', '300', 'SB10006', '10000', 'SB10007', '500', 'SB10008', '56', 'SB10009', '30', 'SB10010', '7000', 'CR10001', '7000', 'SB10002', '-10'] 
>>> allGoodAccountNos = combineAllElements.filter(lambda trans: trans.startswith('SB') == True) 
>>> allGoodAccountNos.distinct().collect() 
['SB10005', 'SB10006', 'SB10008', 'SB10002', 'SB10003', 'SB10009', 'SB10010', 'SB10004', 'SB10001', 'SB10007']

```

如果比较 Scala 和 Python 代码集，Spark 统一编程模型的真正力量就非常明显。Spark 转换和 Spark 操作在两种语言实现中都是相同的。由于编程语言语法的差异，函数传递给这些操作的方式不同。

在运行 Spark 的 Python REPL 之前，有意关闭了 Scala REPL。然后，Spark Web UI 应类似于图 5 所示。由于 Scala REPL 已关闭，它被列在已完成应用程序列表中。由于 Python REPL 仍在运行，它被列在运行中的应用程序列表中。请注意 Spark Web UI 中 Scala REPL 和 Python REPL 的应用程序名称。这些都是标准名称。当从文件运行自定义应用程序时，可以在定义 Spark 上下文对象时指定自定义名称，以便于监控应用程序和日志记录。这些细节将在本章后面介绍。

花时间熟悉 Spark Web UI 是个好主意，了解所有捕获的指标以及如何在 UI 中呈现 DAG 可视化。这将大大有助于调试复杂的 Spark 应用程序。

![Spark 编程基础](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_02_006.jpg)

图 5

## MapReduce

自 Spark 诞生之日起，它就被定位为 Hadoop MapReduce 程序的替代品。通常，如果一个数据处理任务可以分解为多个子任务，并且这些子任务能够并行执行，且最终结果可以在收集所有这些分布式片段的结果后计算得出，那么该任务就会采用 MapReduce 风格。与 Hadoop MapReduce 不同，即使活动的有向无环图（DAG）超过两个阶段（如 Map 和 Reduce），Spark 也能完成这一过程。Spark 正是为此而设计，这也是 Spark 强调的最大价值主张之一。

本节将继续探讨同一零售银行应用程序，并选取一些适合 MapReduce 类型数据处理的理想用例。

此处为阐明 MapReduce 类型数据处理所选用的用例如下：

1.  零售银行交易记录带有以逗号分隔的账户号码和交易金额字符串。

1.  将交易配对成键/值对，例如(`AccNo`, `TranAmount`)。

1.  查找所有交易的账户级别汇总，以获取账户余额。

在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> val acTransList = Array("SB10001,1000", "SB10002,1200", "SB10001,8000", "SB10002,400", "SB10003,300", "SB10001,10000", "SB10004,500", "SB10005,56", "SB10003,30","SB10002,7000", "SB10001,-100", "SB10002,-10") 
acTransList: Array[String] = Array(SB10001,1000, SB10002,1200, SB10001,8000, SB10002,400, SB10003,300, SB10001,10000, SB10004,500, SB10005,56, SB10003,30, SB10002,7000, SB10001,-100, SB10002,-10) 
scala> val acTransRDD = sc.parallelize(acTransList) 
acTransRDD: org.apache.spark.rdd.RDD[String] = ParallelCollectionRDD[0] at parallelize at <console>:23 
scala> val acKeyVal = acTransRDD.map(trans => (trans.split(",")(0), trans.split(",")(1).toDouble)) 
acKeyVal: org.apache.spark.rdd.RDD[(String, Double)] = MapPartitionsRDD[1] at map at <console>:25 
scala> val accSummary = acKeyVal.reduceByKey(_ + _).sortByKey() 
accSummary: org.apache.spark.rdd.RDD[(String, Double)] = ShuffledRDD[5] at sortByKey at <console>:27 
scala> accSummary.collect() 
res0: Array[(String, Double)] = Array((SB10001,18900.0), (SB10002,8590.0), (SB10003,330.0), (SB10004,500.0), (SB10005,56.0)) 

```

以下是迄今为止所做工作的详细步骤记录：

1.  值`acTransList`是包含逗号分隔交易记录的数组。

1.  值`acTransRDD`是由数组创建的 RDD，其中 sc 是 Spark 上下文或 Spark 驱动程序，RDD 以并行化方式创建，以便 RDD 元素可以形成分布式数据集。

1.  将`acTransRDD`转换为`acKeyVal`，以拥有形式为(K,V)的键值对，其中选择账户号码作为键。在此 RDD 的元素集合中，将存在多个具有相同键的元素。

1.  下一步，将键值对按键分组，并传递一个缩减函数，该函数会将交易金额累加，形成包含特定键的一个元素以及同一键下所有金额总和的键值对。然后在生成最终结果前，根据键对元素进行排序。

1.  在驱动程序级别收集元素到数组中。

假设 RDD `acKeyVal`被分为两部分并分布到集群进行处理，图 6 捕捉了处理的核心：

![MapReduce](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_02_008.jpg)

图 6

下表概述了本用例中引入的 Spark 操作：

| **Spark 操作** | **其作用是什么？** |
| --- | --- |
| `reduceByKey(fn,[noOfTasks])` | **对形式为(K,V)的 RDD 应用函数 fn，并通过减少重复键并应用作为参数传递的函数来在键级别对值进行操作，从而实现缩减。** |
| `sortByKey([ascending], [numTasks])` | 如果 RDD 为形式(K,V)，则根据其键 K 对 RDD 元素进行排序 |

`reduceByKey`操作值得特别提及。在图 6 中，按键对元素进行分组是一个众所周知的操作。但在下一步中，对于相同的键，作为参数传递的函数接受两个参数并返回一个。要正确理解这一点并不直观，你可能会疑惑在遍历每个键的(K,V)对值时，这两个输入从何而来。这种行为借鉴了 Scala 集合方法`reduceLeft`的概念。下图 7 展示了键**SB10001**执行`reduceByKey(_ + _)`操作的情况，旨在解释这一概念。这只是为了阐明此示例的目的，实际的 Spark 实现可能有所不同：

![MapReduce](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_02_010.jpg)

图 7

在图 7 的右侧，展示了 Scala 集合方法中的`reduceLeft`操作。这是为了提供一些关于`reduceLeft`函数两个参数来源的见解。事实上，Spark RDD 上使用的许多转换都是从 Scala 集合方法改编而来的。

在 Python REPL 提示符下，尝试以下语句：

```scala
>>> from decimal import Decimal 
>>> acTransList = ["SB10001,1000", "SB10002,1200", "SB10001,8000", "SB10002,400", "SB10003,300", "SB10001,10000", "SB10004,500", "SB10005,56", "SB10003,30","SB10002,7000", "SB10001,-100", "SB10002,-10"] 
>>> acTransRDD = sc.parallelize(acTransList) 
>>> acKeyVal = acTransRDD.map(lambda trans: (trans.split(",")[0],Decimal(trans.split(",")[1]))) 
>>> accSummary = acKeyVal.reduceByKey(lambda a,b : a+b).sortByKey() 
>>> accSummary.collect() 
[('SB10001', Decimal('18900')), ('SB10002', Decimal('8590')), ('SB10003', Decimal('330')), ('SB10004', Decimal('500')), ('SB10005', Decimal('56'))] 

```

`reduceByKey`接受一个输入参数，即一个函数。与此类似，还有一种转换以略有不同的方式执行基于键的操作，即`groupByKey()`。它将给定键的所有值聚集起来，形成来自所有单独元素的值列表。

如果需要对每个键的相同值元素集合进行多级处理，这种转换是合适的。换句话说，如果有许多(K,V)对，此转换将为每个键返回(K, Iterable<V>)。

### 提示

开发者唯一需要注意的是，确保此类(K,V)对的数量不会过于庞大，以免操作引发性能问题。并没有严格的规则来确定这一点，它更多取决于具体用例。

在前述所有代码片段中，为了从逗号分隔的交易记录中提取账号或其他字段，`map()`转换过程中多次使用了`split(`,`)`。这是为了展示在`map()`或其他转换或方法中使用数组元素的用法。更佳的做法是将交易记录字段转换为包含所需字段的元组，然后从元组中提取字段，用于后续代码片段。这样，就无需为每个字段提取重复调用`split(`,`)`。

## 连接

在**关系型数据库管理系统**（**RDBMS**）领域，基于键连接多个表的行是一种非常常见的做法。而在 NoSQL 数据存储中，多表连接成为一个真正的问题，因为许多 NoSQL 数据存储不支持表连接。在 NoSQL 世界中，允许冗余。无论技术是否支持表连接，业务用例始终要求基于键连接数据集。因此，在许多用例中，批量执行连接是至关重要的。

Spark 提供了基于键连接多个 RDD 的转换。这支持了许多用例。如今，许多 NoSQL 数据存储都有与 Spark 通信的连接器。当与这些数据存储一起工作时，从多个表构建 RDD、通过 Spark 执行连接并将结果以批量模式甚至近实时模式存储回数据存储变得非常简单。Spark 转换支持左外连接、右外连接以及全外连接。

以下是用于阐明使用键连接多个数据集的用例。

第一个数据集包含零售银行主记录摘要，包括账户号、名字和姓氏。第二个数据集包含零售银行账户余额，包括账户号和余额金额。两个数据集的关键字都是账户号。将这两个数据集连接起来，创建一个包含账户号、全名和余额金额的数据集。

在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> val acMasterList = Array("SB10001,Roger,Federer", "SB10002,Pete,Sampras", "SB10003,Rafael,Nadal", "SB10004,Boris,Becker", "SB10005,Ivan,Lendl") 
acMasterList: Array[String] = Array(SB10001,Roger,Federer, SB10002,Pete,Sampras, SB10003,Rafel,Nadal, SB10004,Boris,Becker, SB10005,Ivan,Lendl) 
scala> val acBalList = Array("SB10001,50000", "SB10002,12000", "SB10003,3000", "SB10004,8500", "SB10005,5000") 
acBalList: Array[String] = Array(SB10001,50000, SB10002,12000, SB10003,3000, SB10004,8500, SB10005,5000) 
scala> val acMasterRDD = sc.parallelize(acMasterList) 
acMasterRDD: org.apache.spark.rdd.RDD[String] = ParallelCollectionRDD[0] at parallelize at <console>:23 
scala> val acBalRDD = sc.parallelize(acBalList) 
acBalRDD: org.apache.spark.rdd.RDD[String] = ParallelCollectionRDD[1] at parallelize at <console>:23 
scala> val acMasterTuples = acMasterRDD.map(master => master.split(",")).map(masterList => (masterList(0), masterList(1) + " " + masterList(2))) 
acMasterTuples: org.apache.spark.rdd.RDD[(String, String)] = MapPartitionsRDD[3] at map at <console>:25 
scala> val acBalTuples = acBalRDD.map(trans => trans.split(",")).map(transList => (transList(0), transList(1))) 
acBalTuples: org.apache.spark.rdd.RDD[(String, String)] = MapPartitionsRDD[5] at map at <console>:25 
scala> val acJoinTuples = acMasterTuples.join(acBalTuples).sortByKey().map{case (accno, (name, amount)) => (accno, name,amount)} 
acJoinTuples: org.apache.spark.rdd.RDD[(String, String, String)] = MapPartitionsRDD[12] at map at <console>:33 
scala> acJoinTuples.collect() 
res0: Array[(String, String, String)] = Array((SB10001,Roger Federer,50000), (SB10002,Pete Sampras,12000), (SB10003,Rafael Nadal,3000), (SB10004,Boris Becker,8500), (SB10005,Ivan Lendl,5000)) 

```

除了 Spark 转换连接之外，之前给出的所有语句现在应该都很熟悉了。类似地，`leftOuterJoin`、`rightOuterJoin`和`fullOuterJoin`也以相同的用法模式提供：

| **Spark 转换** | **功能** |
| --- | --- |
| `join(other, [numTasks])` | **将此 RDD 与另一个 RDD 连接，元素基于键进行连接。假设原始 RDD 的形式为(K,V1)，第二个 RDD 的形式为(K,V2)，则连接操作将生成形式为(K, (V1,V2))的元组，包含每个键的所有配对。** |

在 Python REPL 提示符下，尝试以下语句：

```scala
>>> acMasterList = ["SB10001,Roger,Federer", "SB10002,Pete,Sampras", "SB10003,Rafael,Nadal", "SB10004,Boris,Becker", "SB10005,Ivan,Lendl"] 
>>> acBalList = ["SB10001,50000", "SB10002,12000", "SB10003,3000", "SB10004,8500", "SB10005,5000"] 
>>> acMasterRDD = sc.parallelize(acMasterList) 
>>> acBalRDD = sc.parallelize(acBalList) 
>>> acMasterTuples = acMasterRDD.map(lambda master: master.split(",")).map(lambda masterList: (masterList[0], masterList[1] + " " + masterList[2])) 
>>> acBalTuples = acBalRDD.map(lambda trans: trans.split(",")).map(lambda transList: (transList[0], transList[1])) 
>>> acJoinTuples = acMasterTuples.join(acBalTuples).sortByKey().map(lambda tran: (tran[0], tran[1][0],tran[1][1])) 
>>> acJoinTuples.collect() 
[('SB10001', 'Roger Federer', '50000'), ('SB10002', 'Pete Sampras', '12000'), ('SB10003', 'Rafael Nadal', '3000'), ('SB10004', 'Boris Becker', '8500'), ('SB10005', 'Ivan Lendl', '5000')] 

```

## 更多动作

到目前为止，重点主要放在 Spark 转换上。Spark 动作同样重要。为了深入了解一些更重要的 Spark 动作，请继续从上一节用例停止的地方开始，考虑以下用例：

+   从包含账户号、姓名和账户余额的列表中，获取余额最高的账户

+   从包含账户号、姓名和账户余额的列表中，获取余额最高的前三个账户

+   统计账户级别上的余额交易记录数量

+   统计余额交易记录的总数

+   打印所有账户的姓名和账户余额

+   计算账户余额总额

### 提示

遍历集合中的元素，对每个元素进行一些数学计算，并在最后使用结果，这是一个非常常见的需求。RDD 被分区并分布在 worker 节点上。如果在遍历 RDD 元素时使用普通变量存储累积结果，可能无法得到正确的结果。在这种情况下，不要使用常规变量，而是使用 Spark 提供的累加器。

在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> val acNameAndBalance = acJoinTuples.map{case (accno, name,amount) => (name,amount)} 
acNameAndBalance: org.apache.spark.rdd.RDD[(String, String)] = MapPartitionsRDD[46] at map at <console>:35 
scala> val acTuplesByAmount = acBalTuples.map{case (accno, amount) => (amount.toDouble, accno)}.sortByKey(false) 
acTuplesByAmount: org.apache.spark.rdd.RDD[(Double, String)] = ShuffledRDD[50] at sortByKey at <console>:27 
scala> acTuplesByAmount.first() 
res19: (Double, String) = (50000.0,SB10001) 
scala> acTuplesByAmount.take(3) 
res20: Array[(Double, String)] = Array((50000.0,SB10001), (12000.0,SB10002), (8500.0,SB10004)) 
scala> acBalTuples.countByKey() 
res21: scala.collection.Map[String,Long] = Map(SB10001 -> 1, SB10005 -> 1, SB10004 -> 1, SB10002 -> 1, SB10003 -> 1) 
scala> acBalTuples.count() 
res22: Long = 5 
scala> acNameAndBalance.foreach(println) 
(Boris Becker,8500) 
(Rafel Nadal,3000) 
(Roger Federer,50000) 
(Pete Sampras,12000) 
(Ivan Lendl,5000) 
scala> val balanceTotal = sc.accumulator(0.0, "Account Balance Total") 
balanceTotal: org.apache.spark.Accumulator[Double] = 0.0 
scala> acBalTuples.map{case (accno, amount) => amount.toDouble}.foreach(bal => balanceTotal += bal) 
scala> balanceTotal.value 
res8: Double = 78500.0) 

```

下表概述了本用例中引入的 Spark 行动：

| **触发行动** | **其作用** |
| --- | --- |
| `first()` | **返回 RDD 的第一个元素。** |
| `take(n)` | 返回 RDD 的前`n`个元素的数组。 |
| `countByKey()` | 按键返回元素计数。如果 RDD 包含(K,V)对，这将返回一个字典`(K, numOfValues)`。 |
| `count()` | 返回 RDD 中的元素数量。 |
| `foreach(fn)` | 将函数 fn 应用于 RDD 中的每个元素。在前述用例中，使用`foreach(fn)`与 Spark Accumulator。 |

在 Python REPL 提示符下，尝试以下语句：

```scala
>>> acNameAndBalance = acJoinTuples.map(lambda tran: (tran[1],tran[2])) 
>>> acTuplesByAmount = acBalTuples.map(lambda tran: (Decimal(tran[1]), tran[0])).sortByKey(False) 
>>> acTuplesByAmount.first() 
(Decimal('50000'), 'SB10001') 
>>> acTuplesByAmount.take(3) 
[(Decimal('50000'), 'SB10001'), (Decimal('12000'), 'SB10002'), (Decimal('8500'), 'SB10004')] 
>>> acBalTuples.countByKey() 
defaultdict(<class 'int'>, {'SB10005': 1, 'SB10002': 1, 'SB10003': 1, 'SB10004': 1, 'SB10001': 1}) 
>>> acBalTuples.count() 
5 
>>> acNameAndBalance.foreach(print) 
('Pete Sampras', '12000') 
('Roger Federer', '50000') 
('Rafael Nadal', '3000') 
('Boris Becker', '8500') 
('Ivan Lendl', '5000') 
>>> balanceTotal = sc.accumulator(0.0) 
>>> balanceTotal.value0.0>>> acBalTuples.foreach(lambda bals: balanceTotal.add(float(bals[1]))) 
>>> balanceTotal.value 
78500.0

```

# 从文件创建 RDD

到目前为止，讨论的重点是 RDD 功能和使用 RDD 编程。在前述所有用例中，RDD 的创建都是从集合对象开始的。但在现实世界的用例中，数据将来自存储在本地文件系统、HDFS 中的文件。数据通常来自 Cassandra 等 NoSQL 数据存储。可以通过从这些数据源读取内容来创建 RDD。一旦创建了 RDD，所有操作都是统一的，如前述用例所示。来自文件系统的数据文件可能是固定宽度、逗号分隔或其他格式。但读取此类数据文件的常用模式是逐行读取数据，并将行分割以获得必要的数据项分离。对于来自其他来源的数据，应使用适当的 Spark 连接器程序和读取数据的适当 API。

有许多第三方库可用于从各种类型的文本文件读取内容。例如，GitHub 上提供的 Spark CSV 库对于从 CSV 文件创建 RDD 非常有用。

下表概述了从各种来源（如本地文件系统、HDFS 等）读取文本文件的方式。如前所述，文本文件的处理取决于用例需求：

| **文件位置** | **RDD 创建** | **其作用** |
| --- | --- | --- |
| 本地文件系统 | `val textFile = sc.textFile("README.md")` | **通过读取目录中名为`README.md`的文件内容创建 RDD，该目录是 Spark shell 被调用的位置。这里，RDD 的类型为 RDD[string]，元素将是文件中的行。** |
| HDFS | `val textFile = sc.textFile("hdfs://<location in HDFS>")` | 通过读取 HDFS URL 中指定的文件内容创建 RDD |

从本地文件系统读取文件时，最重要的是该文件应位于所有 Spark 工作节点上。除了上表中给出的这两个文件位置外，还可以使用任何支持的文件系统 URI。

就像从各种文件系统中读取文件内容一样，也可以使用`saveAsTextFile`(path) Spark 操作将 RDD 写入文件。

### 提示

本文讨论的所有 Spark 应用案例均在 Spark 相应语言的 REPL 上运行。编写应用程序时，它们将被编写到适当的源代码文件中。对于 Scala 和 Java，应用程序代码文件需要编译、打包，并在适当的库依赖项下运行，通常使用 maven 或 sbt 构建。本书最后一章设计数据处理应用程序时，将详细介绍这一点。

# 理解 Spark 库栈

Spark 自带一个核心数据处理引擎以及一系列在核心引擎之上的库。理解在核心框架之上堆叠库的概念非常重要。

所有这些利用核心框架提供的服务的库都支持核心框架提供的数据抽象，以及更多。在 Spark 进入市场之前，有很多独立的开放源代码产品在做这里讨论的库栈现在所做的事情。这些点产品最大的缺点是它们的互操作性。它们不能很好地堆叠在一起。它们是用不同的编程语言实现的。这些产品支持的编程语言选择，以及这些产品暴露的 API 缺乏统一性，对于使用两个或更多此类产品完成一个应用程序来说确实具有挑战性。这就是在 Spark 之上工作的库栈的相关性。它们都使用相同的编程模型协同工作。这有助于组织在没有供应商锁定的情况下标准化数据处理工具集。

Spark 附带了以下一系列特定领域的库，图 8 为开发者提供了一个全面的生态系统概览：

+   **Spark SQL**

+   **Spark Streaming**

+   **Spark MLlib**

+   **Spark GraphX**

![理解 Spark 库栈](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_02_012.jpg)

图 8

在任何组织中，结构化数据仍然被广泛使用。最普遍的结构化数据访问机制是 SQL。Spark SQL 提供了在称为 DataFrame API 的结构化数据抽象之上编写类似 SQL 查询的能力。DataFrame 和 SQL 非常契合，支持来自各种来源的数据，如 Hive、Avro、Parquet、JSON 等。一旦数据加载到 Spark 上下文中，它们就可以被操作，就像它们都来自同一来源一样。换句话说，如果需要，可以使用类似 SQL 的查询来连接来自不同来源的数据，例如 Hive 和 JSON。Spark SQL 和 DataFrame API 带给开发者的另一个巨大优势是易于使用，无需了解函数式编程方法，而这是使用 RDD 编程的要求。

### 提示

使用 Spark SQL 和 DataFrame API，可以从各种数据源读取数据并处理，就像它们都来自统一来源一样。Spark 转换和 Spark 操作支持统一的编程接口。因此，数据源的统一、API 的统一以及能够使用多种编程语言编写数据处理应用程序，帮助组织标准化一个数据处理框架。

组织数据池中的数据摄取量每天都在增加。同时，数据被摄取的速度也在加快。Spark Streaming 提供了处理来自各种来源的高速摄取数据的库。

过去，数据科学家面临的挑战是在他们选择的编程语言中构建自己的机器学习算法和实用程序实现。通常，这些编程语言与组织的数据处理工具集不兼容。Spark MLlib 提供了统一过程，它自带了许多在 Spark 数据处理引擎之上工作的机器学习算法和实用程序。

物联网应用，特别是社交媒体应用，要求具备将数据处理成类似图结构的能力。例如，LinkedIn 中的连接、Facebook 中朋友之间的关系、工作流应用以及许多此类用例，都广泛使用了图抽象。使用图进行各种计算需要非常高的数据处理能力和复杂的算法。Spark GraphX 库提供了一个图 API，并利用了 Spark 的并行计算范式。

### 提示

有许多由社区为各种目的开发的 Spark 库。许多这样的第三方库包都在网站[`spark-packages.org/`](http://spark-packages.org/)上有所介绍。随着 Spark 用户社区的增长，这些包的数量也在日益增长。在开发 Spark 数据处理应用程序时，如果需要一个特定领域的库，首先检查这个网站看看是否已经有人开发了它，这将是一个好主意。

# 参考

更多信息请访问：[`github.com/databricks/spark-csv`](https://github.com/databricks/spark-csv)

# 总结

本章讨论了 Spark 的基本编程模型及其主要数据集抽象 RDDs。从各种数据源创建 RDDs，以及使用 Spark 转换和 Spark 操作处理 RDDs 中的数据，这些内容都通过 Scala 和 Python API 进行了介绍。所有 Spark 编程模型的重要特性都通过真实世界的用例进行了讲解。本章还讨论了随 Spark 一起提供的库栈以及每个库的功能。总之，Spark 提供了一个非常用户友好的编程模型，并因此提供了一个非常强大的数据处理工具集。

下一章将讨论数据集 API 和数据帧 API。数据集 API 将成为使用 Spark 编程的新方式，而数据帧 API 则处理更结构化的数据。Spark SQL 也被引入，用于操作结构化数据，并展示如何将其与任何 Spark 数据处理应用程序混合使用。


# 第三章：Spark SQL

大多数企业始终处理着大量的结构化数据。尽管处理非结构化数据的方法众多，但许多应用场景仍需依赖结构化数据。处理结构化数据与非结构化数据的主要区别是什么？如果数据源是结构化的，且数据处理引擎事先知晓数据结构，那么该引擎在处理数据时可以进行大量优化，甚至提前进行。当数据处理量巨大且周转时间极为关键时，这一点尤为重要。

企业数据的激增要求赋予终端用户通过简单易用的应用程序用户界面查询和处理数据的能力。关系型数据库管理系统供应商联合起来，**结构化查询语言**（**SQL**）应运而生，成为解决这一问题的方案。在过去几十年里，所有与数据打交道的人，即使不是高级用户，也熟悉了 SQL。

社交网络和微博等大规模互联网应用产生的数据超出了许多传统数据处理工具的消耗能力。面对如此海量的数据，从中挑选并选择正确的数据变得更为重要。Spark 是一个广泛使用的数据处理平台，其基于 RDD 的编程模型相比 Hadoop MapReduce 数据处理框架减少了数据处理的工作量。然而，Spark 早期基于 RDD 的编程模型对于终端用户（如数据科学家、数据分析师和业务分析师）来说使用起来并不直观。主要原因是它需要一定程度的功能编程知识。解决这一问题的方案是 Spark SQL。Spark SQL 是建立在 Spark 之上的一个库，它提供了 SQL 接口和 DataFrame API。DataFrame API 支持 Scala、Java、Python 和 R 等编程语言。

如果事先知道数据的结构，如果数据符合行和列的模型，那么数据来自哪里并不重要，Spark SQL 可以将所有数据整合在一起处理，仿佛所有数据都来自单一来源。此外，查询语言是普遍使用的 SQL。

本章我们将涵盖以下主题：

+   数据结构

+   Spark SQL

+   聚合

+   多数据源连接

+   数据集

+   数据目录

# 理解数据结构

此处讨论的数据结构需要进一步阐明。我们所说的数据结构是什么意思？存储在 RDBMS 中的数据以行/列或记录/字段的方式存储。每个字段都有数据类型，每个记录是相同或不同数据类型的字段集合。在 RDBMS 早期，字段的数据类型是标量的，而在近期版本中，它扩展到包括集合数据类型或复合数据类型。因此，无论记录包含标量数据类型还是复合数据类型，重要的是要注意底层数据具有结构。许多数据处理范式已采用在内存中镜像 RDBMS 或其他存储中持久化的底层数据结构的概念，以简化数据处理。

换言之，如果 RDBMS 表中的数据正被数据处理应用程序处理，且内存中存在与该表类似的数据结构供程序、最终用户和程序员使用，那么建模应用程序和查询数据就变得容易了。例如，假设有一组逗号分隔的数据项，每行具有固定数量的值，且每个特定位置的值都有特定的数据类型。这是一个结构化数据文件，类似于 RDBMS 表。

在 R 等编程语言中，使用数据框抽象在内存中存储数据表。Python 数据分析库 Pandas 也有类似的数据框概念。一旦该数据结构在内存中可用，程序就可以根据需要提取数据并进行切片和切块。同样的数据表概念被扩展到 Spark，称为 DataFrame，建立在 RDD 之上，并且有一个非常全面的 API，即 Spark SQL 中的 DataFrame API，用于处理 DataFrame 中的数据。还开发了一种类似 SQL 的查询语言，以满足最终用户查询和处理底层结构化数据的需求。总之，DataFrame 是一个分布式数据表，按行和列组织，并为每个列命名。

Spark SQL 库建立在 Spark 之上，是基于题为*“Spark SQL：Spark 中的关系数据处理”*的研究论文开发的。它提出了 Spark SQL 的四个目标，并如下所述：

+   支持在 Spark 程序内部（基于原生 RDD）以及使用程序员友好 API 的外部数据源上进行关系处理

+   利用成熟的 DBMS 技术提供高性能

+   轻松支持新的数据源，包括半结构化数据和易于查询联合的外部数据库

+   支持扩展高级分析算法，如图形处理和机器学习

DataFrame 存储结构化数据，并且是分布式的。它允许进行数据的选择、过滤和聚合。听起来与 RDD 非常相似吗？RDD 和 DataFrame 的关键区别在于，DataFrame 存储了关于数据结构的更多信息，如数据类型和列名，这使得 DataFrame 在处理优化上比基于 RDD 的 Spark 转换和操作更为有效。另一个需要提及的重要方面是，Spark 支持的所有编程语言都可以用来开发使用 Spark SQL 的 DataFrame API 的应用程序。实际上，Spark SQL 是一个分布式的 SQL 引擎。

### 提示

那些在 Spark 1.3 之前工作过的人一定对 SchemaRDD 很熟悉，而 DataFrame 的概念正是建立在 SchemaRDD 之上，并保持了 API 级别的兼容性。

# 为何选择 Spark SQL？

毫无疑问，SQL 是进行数据分析的通用语言，而 Spark SQL 则是 Spark 工具集家族对此的回应。那么，它提供了什么？它提供了在 Spark 之上运行 SQL 的能力。无论数据来自 CSV、Avro、Parquet、Hive、NoSQL 数据存储如 Cassandra，甚至是 RDBMS，Spark SQL 都能用于分析数据，并与 Spark 程序混合使用。这里提到的许多数据源都由 Spark SQL 内在支持，而其他许多则由外部包支持。这里最值得强调的是 Spark SQL 处理来自极其多样数据源的数据的能力。一旦数据作为 DataFrame 在 Spark 中可用，Spark SQL 就能以完全分布式的方式处理数据，将来自不同数据源的 DataFrames 组合起来进行处理和查询，仿佛整个数据集都来自单一源。

在前一章中，详细讨论了 RDD 并将其引入为 Spark 编程模型。Spark SQL 中的 DataFrames API 和 SQL 方言的使用是否正在取代基于 RDD 的编程模型？绝对不是！基于 RDD 的编程模型是 Spark 中通用且基本的数据处理模型。基于 RDD 的编程需要使用实际的编程技术。Spark 转换和 Spark 操作使用了许多函数式编程结构。尽管与 Hadoop MapReduce 或其他范式相比，基于 RDD 的编程模型所需的代码量较少，但仍需要编写一定量的函数式代码。这对于许多数据科学家、数据分析师和业务分析师来说是一个障碍，他们可能主要进行探索性的数据分析或对数据进行一些原型设计。Spark SQL 完全消除了这些限制。简单易用的**领域特定语言**（**DSL**）方法，用于从数据源读取和写入数据，类似 SQL 的语言用于选择、过滤和聚合，以及从各种数据源读取数据的能力，使得任何了解数据结构的人都可以轻松使用它。

### 注意

何时使用 RDD，何时使用 Spark SQL 的最佳用例是什么？答案很简单。如果数据是结构化的，可以排列在表格中，并且可以为每一列命名，那么使用 Spark SQL。这并不意味着 RDD 和 DataFrame 是两个截然不同的实体。它们互操作得非常好。从 RDD 到 DataFrame 以及反之的转换都是完全可能的。许多通常应用于 RDD 的 Spark 转换和 Spark 操作也可以应用于 DataFrames。

通常，在应用程序设计阶段，业务分析师通常使用 SQL 对应用程序数据进行大量分析，这些分析结果被用于应用程序需求和测试工件。在设计大数据应用程序时，同样需要这样做，在这种情况下，除了业务分析师之外，数据科学家也将成为团队的一部分。在基于 Hadoop 的生态系统中，Hive 广泛用于使用大数据进行数据分析。现在，Spark SQL 将这种能力带到了任何支持大量数据源的平台。如果商品硬件上有一个独立的 Spark 安装，可以进行大量此类活动来分析数据。在商品硬件上以独立模式部署的基本 Spark 安装足以处理大量数据。

SQL-on-Hadoop 策略引入了许多应用程序，例如 Hive 和 Impala 等，为存储在 **Hadoop 分布式文件系统** (**HDFS**) 中的底层大数据提供类似 SQL 的接口。Spark SQL 在这个领域中处于什么位置？在深入探讨之前，了解一下 Hive 和 Impala 是个好主意。Hive 是一种基于 MapReduce 的数据仓库技术，由于使用 MapReduce 处理查询，Hive 查询在完成之前需要进行大量的 I/O 操作。Impala 通过进行内存处理并利用描述数据的 Hive 元存储提出了一个出色的解决方案。Spark SQL 使用 SQLContext 执行所有数据操作。但它也可以使用 HiveContext，后者比 SQLContext 功能更丰富、更高级。HiveContext 可以执行 SQLContext 所能做的一切，并且在此基础上，它可以读取 Hive 元存储和表，还可以访问 Hive 用户定义的函数。使用 HiveContext 的唯一要求显然是应该有一个现成的 Hive 设置。这样，Spark SQL 就可以轻松地与 Hive 共存。

### 注意

从 Spark 2.0 开始，SparkSession 是基于 Spark SQL 的应用程序的新起点，它是 SQLContext 和 HiveContext 的组合，同时支持与 SQLContext 和 HiveContext 的向后兼容性。

Spark SQL 处理来自 Hive 表的数据比使用 Hive 查询语言的 Hive 更快。Spark SQL 的另一个非常有趣的功能是它能够从不同版本的 Hive 读取数据，这是一个很好的功能，可以实现数据处理的数据源整合。

### 注意

提供 Spark SQL 和 DataFrame API 的库提供了可以通过 JDBC/ODBC 访问的接口。这为数据分析开辟了一个全新的世界。例如，使用 JDBC/ODBC 连接到数据源的 **商业智能** (**BI**) 工具可以使用 Spark SQL 支持的大量数据源。此外，BI 工具可以将处理器密集型的连接聚合操作推送到 Spark 基础设施中的大量工作节点上。

# Spark SQL 剖析

与 Spark SQL 库的交互主要通过两种方法进行。一种是通过类似 SQL 的查询，另一种是通过 DataFrame API。在深入了解基于 DataFrame 的程序如何工作之前，了解一下基于 RDD 的程序如何工作是个好主意。

Spark 转换和 Spark 操作被转换为 Java 函数，并在 RDD 之上执行，RDD 本质上就是作用于数据的 Java 对象。由于 RDD 是纯粹的 Java 对象，因此在编译时或运行时都无法预知将要处理的数据。执行引擎事先没有可用的元数据来优化 Spark 转换或 Spark 操作。没有提前准备的多条执行路径或查询计划来处理这些数据，因此无法评估各种执行路径的有效性。

这里没有执行优化的查询计划，因为没有与数据关联的架构。在 DataFrame 的情况下，结构是事先已知的。因此，可以对查询进行优化并在事先构建数据缓存。

以下*图 1*展示了相关内容：

![Spark SQL 结构解析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_03_002.jpg)

图 1

针对 DataFrame 的类似 SQL 的查询和 DataFrame API 调用被转换为与语言无关的表达式。与 SQL 查询或 DataFrame API 对应的与语言无关的表达式称为未解析的逻辑计划。

未解析的逻辑计划通过验证 DataFrame 元数据中的列名来转换为逻辑计划。逻辑计划通过应用标准规则（如表达式简化、表达式求值和其他优化规则）进一步优化，形成优化的逻辑计划。优化的逻辑计划被转换为多个物理计划。物理计划是通过在逻辑计划中使用 Spark 特定的操作符创建的。选择最佳物理计划，并将生成的查询推送到 RDD 以作用于数据。由于 SQL 查询和 DataFrame API 调用被转换为与语言无关的查询表达式，因此这些查询在所有支持的语言中的性能是一致的。这也是 DataFrame API 被所有 Spark 支持的语言（如 Scala、Java、Python 和 R）支持的原因。未来，由于这个原因，很可能会有更多语言支持 DataFrame API 和 Spark SQL。

Spark SQL 的查询规划和优化也值得一提。通过 SQL 查询或 DataFrame API 对 DataFrame 执行的任何查询操作在物理应用于底层基本 RDD 之前都经过了高度优化。在 RDD 上实际操作发生之前，存在许多中间过程。

*图 2* 提供了关于整个查询优化过程的一些见解：

![Spark SQL 结构解析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_03_004.jpg)

图 2

针对 DataFrame，可以调用两种类型的查询：SQL 查询或 DataFrame API 调用。它们经过适当的分析，生成逻辑查询执行计划。随后，对逻辑查询计划进行优化，以得到优化的逻辑查询计划。从最终的优化逻辑查询计划出发，制定一个或多个物理查询计划。对于每个物理查询计划，都会计算成本模型，并根据最优成本选择合适的物理查询计划，生成高度优化的代码，并针对 RDDs 运行。这就是 DataFrame 上任何类型查询性能一致的原因。这也是为什么从 Scala、Java、Python 和 R 等不同语言调用 DataFrame API 都能获得一致性能的原因。

让我们再次回顾*图 3*所示的大局，以设定背景，了解当前讨论的内容，然后再深入探讨并处理这些用例：

![Spark SQL 结构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_03_006.jpg)

图 3

接下来要讨论的使用案例将展示如何将 SQL 查询与 Spark 程序结合。我们将选择多个数据源，使用 DataFrame 从这些源读取数据，并展示统一的数据访问。演示使用的编程语言仍然是 Scala 和 Python。本书议程中还包括使用 R 操作 DataFrame，并为此专门设立了一章。

# DataFrame 编程

以下是用于阐释使用 DataFrame 进行 Spark SQL 编程方式的用例：

+   交易记录以逗号分隔的值形式呈现。

+   从列表中筛选出仅包含良好交易记录的部分。账户号码应以`SB`开头，且交易金额应大于零。

+   查找所有交易金额大于 1000 的高价值交易记录。

+   查找所有账户号码异常的交易记录。

+   查找所有交易金额小于或等于零的交易记录。

+   查找所有不良交易记录的合并列表。

+   计算所有交易金额的总和。

+   查找所有交易金额的最大值。

+   查找所有交易金额的最小值。

+   查找所有良好账户号码。

这正是上一章中使用的同一组用例，但这里的编程模型完全不同。通过这组用例，我们展示了两种编程模型：一种是使用 SQL 查询，另一种是使用 DataFrame API。

## 使用 SQL 编程

在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> // Define the case classes for using in conjunction with DataFrames 
scala> case class Trans(accNo: String, tranAmount: Double) 
defined class Trans 
scala> // Functions to convert the sequence of strings to objects defined by the case classes 
scala> def toTrans =  (trans: Seq[String]) => Trans(trans(0), trans(1).trim.toDouble) 
toTrans: Seq[String] => Trans 
scala> // Creation of the list from where the RDD is going to be created 
scala> val acTransList = Array("SB10001,1000", "SB10002,1200", "SB10003,8000", "SB10004,400", "SB10005,300", "SB10006,10000", "SB10007,500", "SB10008,56", "SB10009,30","SB10010,7000", "CR10001,7000", "SB10002,-10") 
acTransList: Array[String] = Array(SB10001,1000, SB10002,1200, SB10003,8000, SB10004,400, SB10005,300, SB10006,10000, SB10007,500, SB10008,56, SB10009,30, SB10010,7000, CR10001,7000, SB10002,-10) 
scala> // Create the RDD 
scala> val acTransRDD = sc.parallelize(acTransList).map(_.split(",")).map(toTrans(_)) 
acTransRDD: org.apache.spark.rdd.RDD[Trans] = MapPartitionsRDD[2] at map at <console>:30 
scala> // Convert RDD to DataFrame 
scala> val acTransDF = spark.createDataFrame(acTransRDD) 
acTransDF: org.apache.spark.sql.DataFrame = [accNo: string, tranAmount: double] 
scala> // Register temporary view in the DataFrame for using it in SQL 
scala> acTransDF.createOrReplaceTempView("trans") 
scala> // Print the structure of the DataFrame 
scala> acTransDF.printSchema 
root 
 |-- accNo: string (nullable = true) 
 |-- tranAmount: double (nullable = false) 
scala> // Show the first few records of the DataFrame 
scala> acTransDF.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+ 
scala> // Use SQL to create another DataFrame containing the good transaction records 
scala> val goodTransRecords = spark.sql("SELECT accNo, tranAmount FROM trans WHERE accNo like 'SB%' AND tranAmount > 0") 
goodTransRecords: org.apache.spark.sql.DataFrame = [accNo: string, tranAmount: double] 
scala> // Register temporary view in the DataFrame for using it in SQL 
scala> goodTransRecords.createOrReplaceTempView("goodtrans") 
scala> // Show the first few records of the DataFrame 
scala> goodTransRecords.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
+-------+----------+ 
scala> // Use SQL to create another DataFrame containing the high value transaction records 
scala> val highValueTransRecords = spark.sql("SELECT accNo, tranAmount FROM goodtrans WHERE tranAmount > 1000") 
highValueTransRecords: org.apache.spark.sql.DataFrame = [accNo: string, tranAmount: double] 
scala> // Show the first few records of the DataFrame 
scala> highValueTransRecords.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10006|   10000.0| 
|SB10010|    7000.0| 
+-------+----------+ 
scala> // Use SQL to create another DataFrame containing the bad account records 
scala> val badAccountRecords = spark.sql("SELECT accNo, tranAmount FROM trans WHERE accNo NOT like 'SB%'") 
badAccountRecords: org.apache.spark.sql.DataFrame = [accNo: string, tranAmount: double] 
scala> // Show the first few records of the DataFrame 
scala> badAccountRecords.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|CR10001|    7000.0| 
+-------+----------+ 
scala> // Use SQL to create another DataFrame containing the bad amount records 
scala> val badAmountRecords = spark.sql("SELECT accNo, tranAmount FROM trans WHERE tranAmount < 0") 
badAmountRecords: org.apache.spark.sql.DataFrame = [accNo: string, tranAmount: double] 
scala> // Show the first few records of the DataFrame 
scala> badAmountRecords.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|     -10.0| 
+-------+----------+ 
scala> // Do the union of two DataFrames and create another DataFrame 
scala> val badTransRecords = badAccountRecords.union(badAmountRecords) 
badTransRecords: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [accNo: string, tranAmount: double] 
scala> // Show the first few records of the DataFrame 
scala> badTransRecords.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+ 
scala> // Calculate the sum 
scala> val sumAmount = spark.sql("SELECT sum(tranAmount) as sum FROM goodtrans") 
sumAmount: org.apache.spark.sql.DataFrame = [sum: double] 
scala> // Show the first few records of the DataFrame 
scala> sumAmount.show 
+-------+ 
|    sum| 
+-------+ 
|28486.0| 
+-------+ 
scala> // Calculate the maximum 
scala> val maxAmount = spark.sql("SELECT max(tranAmount) as max FROM goodtrans") 
maxAmount: org.apache.spark.sql.DataFrame = [max: double] 
scala> // Show the first few records of the DataFrame 
scala> maxAmount.show 
+-------+ 
|    max| 
+-------+ 
|10000.0| 
+-------+ 
scala> // Calculate the minimum 
scala> val minAmount = spark.sql("SELECT min(tranAmount) as min FROM goodtrans") 
minAmount: org.apache.spark.sql.DataFrame = [min: double] 
scala> // Show the first few records of the DataFrame 
scala> minAmount.show 
+----+ 
| min| 
+----+ 
|30.0| 
+----+ 
scala> // Use SQL to create another DataFrame containing the good account numbers 
scala> val goodAccNos = spark.sql("SELECT DISTINCT accNo FROM trans WHERE accNo like 'SB%' ORDER BY accNo") 
goodAccNos: org.apache.spark.sql.DataFrame = [accNo: string] 
scala> // Show the first few records of the DataFrame 
scala> goodAccNos.show 
+-------+ 
|  accNo| 
+-------+ 
|SB10001| 
|SB10002| 
|SB10003| 
|SB10004| 
|SB10005| 
|SB10006| 
|SB10007| 
|SB10008| 
|SB10009| 
|SB10010| 
+-------+ 
scala> // Calculate the aggregates using mixing of DataFrame and RDD like operations 
scala> val sumAmountByMixing = goodTransRecords.map(trans => trans.getAsDouble).reduce(_ + _) 
sumAmountByMixing: Double = 28486.0 
scala> val maxAmountByMixing = goodTransRecords.map(trans => trans.getAsDouble).reduce((a, b) => if (a > b) a else b) 
maxAmountByMixing: Double = 10000.0 
scala> val minAmountByMixing = goodTransRecords.map(trans => trans.getAsDouble).reduce((a, b) => if (a < b) a else b) 
minAmountByMixing: Double = 30.0 

```

零售银行业务的交易记录包含账户号码和交易金额，通过 SparkSQL 处理以获得用例所需的结果。以下是上述脚本执行的概要：

+   Scala case 类被定义以描述将要输入 DataFrame 的交易记录的结构。

+   定义了一个包含必要交易记录的数组。

+   RDD 由数组生成，分割逗号分隔的值，映射以使用 Scala 脚本中定义的第一个步骤中的 case 类创建对象，并将 RDD 转换为 DataFrame。这是 RDD 与 DataFrame 之间互操作性的一个用例。

+   使用一个名称将表注册到 DataFrame。该注册表的名称可以在 SQL 语句中使用。

+   然后，所有其他活动只是使用 `spark.sql` 方法发出 SQL 语句。这里的 spark 对象是 SparkSession 类型。

+   所有这些 SQL 语句的结果存储为 DataFrames，并且就像 RDD 的 `collect` 操作一样，使用 DataFrame 的 show 方法将值提取到 Spark 驱动程序中。

+   聚合值的计算以两种不同的方式进行。一种是使用 SQL 语句的方式，这是最简单的方式。另一种是使用常规的 RDD 风格的 Spark 转换和 Spark 操作。这是为了展示即使 DataFrame 也可以像 RDD 一样操作，并且可以在 DataFrame 上应用 Spark 转换和 Spark 操作。

+   有时，通过使用函数的功能样式操作进行一些数据操作活动很容易。因此，这里有一个灵活性，可以混合使用 SQL、RDD 和 DataFrame，以拥有一个非常方便的数据处理编程模型。

+   DataFrame 内容以表格格式使用 DataFrame 的 `show` 方法显示。

+   使用 `printSchema` 方法展示 DataFrame 结构的详细视图。这类似于数据库表的 `describe` 命令。

在 Python REPL 提示符下，尝试以下语句：

```scala
>>> from pyspark.sql import Row 
>>> # Creation of the list from where the RDD is going to be created 
>>> acTransList = ["SB10001,1000", "SB10002,1200", "SB10003,8000", "SB10004,400", "SB10005,300", "SB10006,10000", "SB10007,500", "SB10008,56", "SB10009,30","SB10010,7000", "CR10001,7000", "SB10002,-10"] 
>>> # Create the DataFrame 
>>> acTransDF = sc.parallelize(acTransList).map(lambda trans: trans.split(",")).map(lambda p: Row(accNo=p[0], tranAmount=float(p[1]))).toDF() 
>>> # Register temporary view in the DataFrame for using it in SQL 
>>> acTransDF.createOrReplaceTempView("trans") 
>>> # Print the structure of the DataFrame 
>>> acTransDF.printSchema() 
root 
 |-- accNo: string (nullable = true) 
 |-- tranAmount: double (nullable = true) 
>>> # Show the first few records of the DataFrame 
>>> acTransDF.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+ 
>>> # Use SQL to create another DataFrame containing the good transaction records 
>>> goodTransRecords = spark.sql("SELECT accNo, tranAmount FROM trans WHERE accNo like 'SB%' AND tranAmount > 0") 
>>> # Register temporary table in the DataFrame for using it in SQL 
>>> goodTransRecords.createOrReplaceTempView("goodtrans") 
>>> # Show the first few records of the DataFrame 
>>> goodTransRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
+-------+----------+ 
>>> # Use SQL to create another DataFrame containing the high value transaction records 
>>> highValueTransRecords = spark.sql("SELECT accNo, tranAmount FROM goodtrans WHERE tranAmount > 1000") 
>>> # Show the first few records of the DataFrame 
>>> highValueTransRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10006|   10000.0| 
|SB10010|    7000.0| 
+-------+----------+ 
>>> # Use SQL to create another DataFrame containing the bad account records 
>>> badAccountRecords = spark.sql("SELECT accNo, tranAmount FROM trans WHERE accNo NOT like 'SB%'") 
>>> # Show the first few records of the DataFrame 
>>> badAccountRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|CR10001|    7000.0| 
+-------+----------+ 
>>> # Use SQL to create another DataFrame containing the bad amount records 
>>> badAmountRecords = spark.sql("SELECT accNo, tranAmount FROM trans WHERE tranAmount < 0") 
>>> # Show the first few records of the DataFrame 
>>> badAmountRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|     -10.0| 
+-------+----------+ 
>>> # Do the union of two DataFrames and create another DataFrame 
>>> badTransRecords = badAccountRecords.union(badAmountRecords) 
>>> # Show the first few records of the DataFrame 
>>> badTransRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+ 
>>> # Calculate the sum 
>>> sumAmount = spark.sql("SELECT sum(tranAmount)as sum FROM goodtrans") 
>>> # Show the first few records of the DataFrame 
>>> sumAmount.show() 
+-------+ 
|    sum| 
+-------+ 
|28486.0| 
+-------+ 
>>> # Calculate the maximum 
>>> maxAmount = spark.sql("SELECT max(tranAmount) as max FROM goodtrans") 
>>> # Show the first few records of the DataFrame 
>>> maxAmount.show() 
+-------+ 
|    max| 
+-------+ 
|10000.0| 
+-------+ 
>>> # Calculate the minimum 
>>> minAmount = spark.sql("SELECT min(tranAmount)as min FROM goodtrans") 
>>> # Show the first few records of the DataFrame 
>>> minAmount.show() 
+----+ 
| min| 
+----+ 
|30.0| 
+----+ 
>>> # Use SQL to create another DataFrame containing the good account numbers 
>>> goodAccNos = spark.sql("SELECT DISTINCT accNo FROM trans WHERE accNo like 'SB%' ORDER BY accNo") 
>>> # Show the first few records of the DataFrame 
>>> goodAccNos.show() 
+-------+ 
|  accNo| 
+-------+ 
|SB10001| 
|SB10002| 
|SB10003| 
|SB10004| 
|SB10005| 
|SB10006| 
|SB10007| 
|SB10008| 
|SB10009| 
|SB10010| 
+-------+ 
>>> # Calculate the sum using mixing of DataFrame and RDD like operations 
>>> sumAmountByMixing = goodTransRecords.rdd.map(lambda trans: trans.tranAmount).reduce(lambda a,b : a+b) 
>>> sumAmountByMixing 
28486.0 
>>> # Calculate the maximum using mixing of DataFrame and RDD like operations 
>>> maxAmountByMixing = goodTransRecords.rdd.map(lambda trans: trans.tranAmount).reduce(lambda a,b : a if a > b else b) 
>>> maxAmountByMixing 
10000.0 
>>> # Calculate the minimum using mixing of DataFrame and RDD like operations 
>>> minAmountByMixing = goodTransRecords.rdd.map(lambda trans: trans.tranAmount).reduce(lambda a,b : a if a < b else b) 
>>> minAmountByMixing 
30.0 

```

在前面的 Python 代码片段中，除了一些特定于语言的构造（如导入库和定义 lambda 函数）之外，编程风格几乎与 Scala 代码相同。这是 Spark 统一编程模型的优势。如前所述，当业务分析师或数据分析师提供数据访问的 SQL 时，很容易将其与 Spark 中的数据处理代码集成。这种统一的编程风格对于组织使用他们选择的语言在 Spark 中开发数据处理应用程序非常有用。

### 提示

在 DataFrame 上，如果应用了适用的 Spark 转换，则会返回一个 Dataset 而不是 DataFrame。Dataset 的概念在本章末尾引入。DataFrame 和 Dataset 之间有着非常紧密的联系，这在涵盖 Datasets 的部分中有所解释。在开发应用程序时，必须在这种情况下谨慎行事。例如，在前面的代码片段中，如果在 Scala REPL 中尝试以下转换，它将返回一个数据集：`val amount = goodTransRecords.map(trans => trans.getAsDouble)amount: org.apache.spark.sql.Dataset[Double] = [value: double]`

## 使用 DataFrame API 编程

在本节中，代码片段将在适当的语言 REPL 中运行，作为前一节的延续，以便数据设置和其他初始化不会重复。与前面的代码片段一样，最初给出了一些 DataFrame 特定的基本命令。这些命令通常用于查看内容并对 DataFrame 及其内容进行一些合理性测试。这些是在数据分析的探索阶段经常使用的命令，通常用于更深入地了解底层数据的结构和内容。

在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> acTransDF.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+ 
scala> // Create the DataFrame using API for the good transaction records 
scala> val goodTransRecords = acTransDF.filter("accNo like 'SB%'").filter("tranAmount > 0") 
goodTransRecords: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [accNo: string, tranAmount: double] 
scala> // Show the first few records of the DataFrame 
scala> goodTransRecords.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
+-------+----------+ 
scala> // Create the DataFrame using API for the high value transaction records 
scala> val highValueTransRecords = goodTransRecords.filter("tranAmount > 1000") 
highValueTransRecords: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [accNo: string, tranAmount: double] 
scala> // Show the first few records of the DataFrame 
scala> highValueTransRecords.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10006|   10000.0| 
|SB10010|    7000.0| 
+-------+----------+ 
scala> // Create the DataFrame using API for the bad account records 
scala> val badAccountRecords = acTransDF.filter("accNo NOT like 'SB%'") 
badAccountRecords: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [accNo: string, tranAmount: double] 
scala> // Show the first few records of the DataFrame 
scala> badAccountRecords.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|CR10001|    7000.0| 
+-------+----------+ 
scala> // Create the DataFrame using API for the bad amount records 
scala> val badAmountRecords = acTransDF.filter("tranAmount < 0") 
badAmountRecords: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [accNo: string, tranAmount: double] 
scala> // Show the first few records of the DataFrame 
scala> badAmountRecords.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|     -10.0| 
+-------+----------+ 
scala> // Do the union of two DataFrames 
scala> val badTransRecords = badAccountRecords.union(badAmountRecords) 
badTransRecords: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [accNo: string, tranAmount: double] 
scala> // Show the first few records of the DataFrame 
scala> badTransRecords.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+ 
scala> // Calculate the aggregates in one shot 
scala> val aggregates = goodTransRecords.agg(sum("tranAmount"), max("tranAmount"), min("tranAmount")) 
aggregates: org.apache.spark.sql.DataFrame = [sum(tranAmount): double, max(tranAmount): double ... 1 more field] 
scala> // Show the first few records of the DataFrame 
scala> aggregates.show 
+---------------+---------------+---------------+ 
|sum(tranAmount)|max(tranAmount)|min(tranAmount)| 
+---------------+---------------+---------------+ 
|        28486.0|        10000.0|           30.0| 
+---------------+---------------+---------------+ 
scala> // Use DataFrame using API for creating the good account numbers 
scala> val goodAccNos = acTransDF.filter("accNo like 'SB%'").select("accNo").distinct().orderBy("accNo") 
goodAccNos: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [accNo: string] 
scala> // Show the first few records of the DataFrame 
scala> goodAccNos.show 
+-------+ 
|  accNo| 
+-------+ 
|SB10001| 
|SB10002| 
|SB10003| 
|SB10004| 
|SB10005| 
|SB10006| 
|SB10007| 
|SB10008| 
|SB10009| 
|SB10010| 
+-------+ 
scala> // Persist the data of the DataFrame into a Parquet file 
scala> acTransDF.write.parquet("scala.trans.parquet") 
scala> // Read the data into a DataFrame from the Parquet file 
scala> val acTransDFfromParquet = spark.read.parquet("scala.trans.parquet") 
acTransDFfromParquet: org.apache.spark.sql.DataFrame = [accNo: string, tranAmount: double] 
scala> // Show the first few records of the DataFrame 
scala> acTransDFfromParquet.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
|SB10001|    1000.0| 
|SB10004|     400.0| 
|SB10007|     500.0| 
|SB10010|    7000.0| 
+-------+----------+

```

从 DataFrame API 的角度来看，这里是前面脚本的总结：

+   包含前一部分所用数据超集的 DataFrame 在此处被使用。

+   接下来演示记录的过滤。这里，最重要的是要注意过滤谓词必须像 SQL 语句中的谓词一样给出。过滤器可以链式使用。

+   聚合方法作为结果 DataFrame 中的三列一次性计算。

+   本组中的最终语句在一个单一的链式语句中完成了选择、过滤、选择不同的记录以及排序。

+   最后，交易记录以 Parquet 格式持久化，从 Parquet 存储中读取并创建一个 DataFrame。关于持久化格式的更多细节将在接下来的部分中介绍。

+   在此代码片段中，Parquet 格式的数据存储在当前目录中，从该目录调用相应的 REPL。当作为 Spark 程序运行时，目录再次将是调用 Spark 提交的当前目录。

在 Python REPL 提示符下，尝试以下语句：

```scala
>>> acTransDF.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+ 
>>> # Print the structure of the DataFrame 
>>> acTransDF.printSchema() 
root 
 |-- accNo: string (nullable = true) 
 |-- tranAmount: double (nullable = true) 
>>> # Create the DataFrame using API for the good transaction records 
>>> goodTransRecords = acTransDF.filter("accNo like 'SB%'").filter("tranAmount > 0") 
>>> # Show the first few records of the DataFrame 
>>> goodTransRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
+-------+----------+ 
>>> # Create the DataFrame using API for the high value transaction records 
>>> highValueTransRecords = goodTransRecords.filter("tranAmount > 1000") 
>>> # Show the first few records of the DataFrame 
>>> highValueTransRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10006|   10000.0| 
|SB10010|    7000.0| 
+-------+----------+ 
>>> # Create the DataFrame using API for the bad account records 
>>> badAccountRecords = acTransDF.filter("accNo NOT like 'SB%'") 
>>> # Show the first few records of the DataFrame 
>>> badAccountRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|CR10001|    7000.0| 
+-------+----------+ 
>>> # Create the DataFrame using API for the bad amount records 
>>> badAmountRecords = acTransDF.filter("tranAmount < 0") 
>>> # Show the first few records of the DataFrame 
>>> badAmountRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|     -10.0| 
+-------+----------+ 
>>> # Do the union of two DataFrames and create another DataFrame 
>>> badTransRecords = badAccountRecords.union(badAmountRecords) 
>>> # Show the first few records of the DataFrame 
>>> badTransRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+ 
>>> # Calculate the sum 
>>> sumAmount = goodTransRecords.agg({"tranAmount": "sum"}) 
>>> # Show the first few records of the DataFrame 
>>> sumAmount.show() 
+---------------+ 
|sum(tranAmount)| 
+---------------+ 
|        28486.0| 
+---------------+ 
>>> # Calculate the maximum 
>>> maxAmount = goodTransRecords.agg({"tranAmount": "max"}) 
>>> # Show the first few records of the DataFrame 
>>> maxAmount.show() 
+---------------+ 
|max(tranAmount)| 
+---------------+ 
|        10000.0| 
+---------------+ 
>>> # Calculate the minimum 
>>> minAmount = goodTransRecords.agg({"tranAmount": "min"}) 
>>> # Show the first few records of the DataFrame 
>>> minAmount.show() 
+---------------+ 
|min(tranAmount)| 
+---------------+ 
|           30.0| 
+---------------+ 
>>> # Create the DataFrame using API for the good account numbers 
>>> goodAccNos = acTransDF.filter("accNo like 'SB%'").select("accNo").distinct().orderBy("accNo") 
>>> # Show the first few records of the DataFrame 
>>> goodAccNos.show() 
+-------+ 
|  accNo| 
+-------+ 
|SB10001| 
|SB10002| 
|SB10003| 
|SB10004| 
|SB10005| 
|SB10006| 
|SB10007| 
|SB10008| 
|SB10009| 
|SB10010| 
+-------+ 
>>> # Persist the data of the DataFrame into a Parquet file 
>>> acTransDF.write.parquet("python.trans.parquet") 
>>> # Read the data into a DataFrame from the Parquet file 
>>> acTransDFfromParquet = spark.read.parquet("python.trans.parquet") 
>>> # Show the first few records of the DataFrame 
>>> acTransDFfromParquet.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
|SB10001|    1000.0| 
|SB10004|     400.0| 
|SB10007|     500.0| 
|SB10010|    7000.0| 
+-------+----------+ 

```

在前面的 Python 代码片段中，除了聚合计算的极少数变化外，编程结构几乎与其 Scala 对应部分相似。

前述 Scala 和 Python 部分最后几条语句涉及将 DataFrame 内容持久化到媒体中。在任何数据处理操作中，写入和读取操作都非常必要，但大多数工具并没有统一的写入和读取方式。Spark SQL 则不同。DataFrame API 配备了一套丰富的持久化机制。将 DataFrame 内容写入多种支持的持久化存储非常简便。所有这些写入和读取操作都具有非常简单的 DSL 风格接口。以下是 DataFrame 可以写入和读取的一些内置格式。

除此之外，还有许多其他外部数据源通过第三方包得到支持：

+   JSON

+   Parquet

+   Hive

+   MySQL

+   PostgreSQL

+   HDFS

+   纯文本

+   亚马逊 S3

+   ORC

+   JDBC

在前述代码片段中已演示了将 DataFrame 写入和读取自 Parquet。所有这些内置支持的数据存储都具有非常简单的 DSL 风格语法用于持久化和读取，这使得编程风格再次统一。DataFrame API 参考资料是了解处理这些数据存储细节的绝佳资源。

本章中的示例代码将数据持久化在 Parquet 和 JSON 格式中。所选数据存储位置名称如`python.trans.parquet`、`scala.trans.parquet`等。这仅是为了表明使用哪种编程语言以及数据格式是什么。这不是正式约定，而是一种便利。当程序运行一次后，这些目录将被创建。下次运行同一程序时，它将尝试创建相同的目录，这将导致错误。解决方法是手动删除这些目录，在后续运行之前进行，然后继续。适当的错误处理机制和其他精细编程的细微差别会分散注意力，因此故意未在此书中涉及。

# 理解 Spark SQL 中的聚合

SQL 中的数据聚合非常灵活。Spark SQL 亦是如此。Spark SQL 并非在单机上的单一数据源上运行 SQL 语句，而是可以在分布式数据源上执行相同操作。在前一章中，讨论了一个 MapReduce 用例以进行数据聚合，此处同样使用该用例来展示 Spark SQL 的聚合能力。本节中，用例既采用 SQL 查询方式，也采用 DataFrame API 方式进行处理。

此处为阐明 MapReduce 类型数据处理而选取的用例如下：

+   零售银行业务交易记录包含以逗号分隔的账户号和交易金额

+   查找所有交易的账户级别汇总以获取账户余额

在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> // Define the case classes for using in conjunction with DataFrames 
scala> case class Trans(accNo: String, tranAmount: Double) 
defined class Trans 
scala> // Functions to convert the sequence of strings to objects defined by the case classes 
scala> def toTrans =  (trans: Seq[String]) => Trans(trans(0), trans(1).trim.toDouble) 
toTrans: Seq[String] => Trans 
scala> // Creation of the list from where the RDD is going to be created 
scala> val acTransList = Array("SB10001,1000", "SB10002,1200","SB10001,8000", "SB10002,400", "SB10003,300", "SB10001,10000","SB10004,500","SB10005,56", "SB10003,30","SB10002,7000","SB10001,-100", "SB10002,-10") 
acTransList: Array[String] = Array(SB10001,1000, SB10002,1200, SB10001,8000, SB10002,400, SB10003,300, SB10001,10000, SB10004,500, SB10005,56, SB10003,30, SB10002,7000, SB10001,-100, SB10002,-10) 
scala> // Create the DataFrame 
scala> val acTransDF = sc.parallelize(acTransList).map(_.split(",")).map(toTrans(_)).toDF() 
acTransDF: org.apache.spark.sql.DataFrame = [accNo: string, tranAmount: double] 
scala> // Show the first few records of the DataFrame 
scala> acTransDF.show 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10001|    8000.0| 
|SB10002|     400.0| 
|SB10003|     300.0| 
|SB10001|   10000.0| 
|SB10004|     500.0| 
|SB10005|      56.0| 
|SB10003|      30.0| 
|SB10002|    7000.0| 
|SB10001|    -100.0| 
|SB10002|     -10.0| 
+-------+----------+ 
scala> // Register temporary view in the DataFrame for using it in SQL 
scala> acTransDF.createOrReplaceTempView("trans") 
scala> // Use SQL to create another DataFrame containing the account summary records 
scala> val acSummary = spark.sql("SELECT accNo, sum(tranAmount) as TransTotal FROM trans GROUP BY accNo") 
acSummary: org.apache.spark.sql.DataFrame = [accNo: string, TransTotal: double] 
scala> // Show the first few records of the DataFrame 
scala> acSummary.show 
+-------+----------+ 
|  accNo|TransTotal| 
+-------+----------+ 
|SB10005|      56.0| 
|SB10004|     500.0| 
|SB10003|     330.0| 
|SB10002|    8590.0| 
|SB10001|   18900.0| 
+-------+----------+ 
scala> // Create the DataFrame using API for the account summary records 
scala> val acSummaryViaDFAPI = acTransDF.groupBy("accNo").agg(sum("tranAmount") as "TransTotal") 
acSummaryViaDFAPI: org.apache.spark.sql.DataFrame = [accNo: string, TransTotal: double] 
scala> // Show the first few records of the DataFrame 
scala> acSummaryViaDFAPI.show 
+-------+----------+ 
|  accNo|TransTotal| 
+-------+----------+ 
|SB10005|      56.0| 
|SB10004|     500.0| 
|SB10003|     330.0| 
|SB10002|    8590.0| 
|SB10001|   18900.0| 
+-------+----------+

```

在本代码片段中，与前述章节的代码非常相似。唯一的区别是，这里在 SQL 查询和 DataFrame API 中都使用了聚合。

在 Python REPL 提示符下，尝试以下语句：

```scala
>>> from pyspark.sql import Row 
>>> # Creation of the list from where the RDD is going to be created 
>>> acTransList = ["SB10001,1000", "SB10002,1200", "SB10001,8000","SB10002,400", "SB10003,300", "SB10001,10000","SB10004,500","SB10005,56","SB10003,30","SB10002,7000", "SB10001,-100","SB10002,-10"] 
>>> # Create the DataFrame 
>>> acTransDF = sc.parallelize(acTransList).map(lambda trans: trans.split(",")).map(lambda p: Row(accNo=p[0], tranAmount=float(p[1]))).toDF() 
>>> # Register temporary view in the DataFrame for using it in SQL 
>>> acTransDF.createOrReplaceTempView("trans") 
>>> # Use SQL to create another DataFrame containing the account summary records 
>>> acSummary = spark.sql("SELECT accNo, sum(tranAmount) as transTotal FROM trans GROUP BY accNo") 
>>> # Show the first few records of the DataFrame 
>>> acSummary.show()     
+-------+----------+ 
|  accNo|transTotal| 
+-------+----------+ 
|SB10005|      56.0| 
|SB10004|     500.0| 
|SB10003|     330.0| 
|SB10002|    8590.0| 
|SB10001|   18900.0| 
+-------+----------+ 
>>> # Create the DataFrame using API for the account summary records 
>>> acSummaryViaDFAPI = acTransDF.groupBy("accNo").agg({"tranAmount": "sum"}).selectExpr("accNo", "`sum(tranAmount)` as transTotal") 
>>> # Show the first few records of the DataFrame 
>>> acSummaryViaDFAPI.show() 
+-------+----------+ 
|  accNo|transTotal| 
+-------+----------+ 
|SB10005|      56.0| 
|SB10004|     500.0| 
|SB10003|     330.0| 
|SB10002|    8590.0| 
|SB10001|   18900.0| 
+-------+----------+

```

在 Python 的 DataFrame API 中，与 Scala 版本相比，存在一些细微的语法差异。

# 理解 SparkSQL 中的多数据源合并

在上一章节中，讨论了基于键合并多个 RDD 的情况。本节中，将使用 Spark SQL 实现相同的用例。以下是用于阐明基于键合并多个数据集的用例。

第一个数据集包含零售银行业务主记录摘要，包括账号、名字和姓氏。第二个数据集包含零售银行账户余额，包括账号和余额金额。两个数据集的关键字段都是账号。将这两个数据集合并，创建一个包含账号、名字、姓氏和余额金额的数据集。从这份报告中，挑选出余额金额排名前三的账户。

本节还演示了从多个数据源合并数据的概念。首先，从两个数组创建 DataFrame，并以 Parquet 和 JSON 格式持久化。然后从磁盘读取它们以形成 DataFrame，并将它们合并在一起。

在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> // Define the case classes for using in conjunction with DataFrames 
scala> case class AcMaster(accNo: String, firstName: String, lastName: String) 
defined class AcMaster 
scala> case class AcBal(accNo: String, balanceAmount: Double) 
defined class AcBal 
scala> // Functions to convert the sequence of strings to objects defined by the case classes 
scala> def toAcMaster =  (master: Seq[String]) => AcMaster(master(0), master(1), master(2)) 
toAcMaster: Seq[String] => AcMaster 
scala> def toAcBal =  (bal: Seq[String]) => AcBal(bal(0), bal(1).trim.toDouble) 
toAcBal: Seq[String] => AcBal 
scala> // Creation of the list from where the RDD is going to be created 
scala> val acMasterList = Array("SB10001,Roger,Federer","SB10002,Pete,Sampras", "SB10003,Rafael,Nadal","SB10004,Boris,Becker", "SB10005,Ivan,Lendl") 
acMasterList: Array[String] = Array(SB10001,Roger,Federer, SB10002,Pete,Sampras, SB10003,Rafael,Nadal, SB10004,Boris,Becker, SB10005,Ivan,Lendl) 
scala> // Creation of the list from where the RDD is going to be created 
scala> val acBalList = Array("SB10001,50000", "SB10002,12000","SB10003,3000", "SB10004,8500", "SB10005,5000") 
acBalList: Array[String] = Array(SB10001,50000, SB10002,12000, SB10003,3000, SB10004,8500, SB10005,5000) 
scala> // Create the DataFrame 
scala> val acMasterDF = sc.parallelize(acMasterList).map(_.split(",")).map(toAcMaster(_)).toDF() 
acMasterDF: org.apache.spark.sql.DataFrame = [accNo: string, firstName: string ... 1 more field] 
scala> // Create the DataFrame 
scala> val acBalDF = sc.parallelize(acBalList).map(_.split(",")).map(toAcBal(_)).toDF() 
acBalDF: org.apache.spark.sql.DataFrame = [accNo: string, balanceAmount: double] 
scala> // Persist the data of the DataFrame into a Parquet file 
scala> acMasterDF.write.parquet("scala.master.parquet") 
scala> // Persist the data of the DataFrame into a JSON file 
scala> acBalDF.write.json("scalaMaster.json") 
scala> // Read the data into a DataFrame from the Parquet file 
scala> val acMasterDFFromFile = spark.read.parquet("scala.master.parquet") 
acMasterDFFromFile: org.apache.spark.sql.DataFrame = [accNo: string, firstName: string ... 1 more field] 
scala> // Register temporary view in the DataFrame for using it in SQL 
scala> acMasterDFFromFile.createOrReplaceTempView("master") 
scala> // Read the data into a DataFrame from the JSON file 
scala> val acBalDFFromFile = spark.read.json("scalaMaster.json") 
acBalDFFromFile: org.apache.spark.sql.DataFrame = [accNo: string, balanceAmount: double] 
scala> // Register temporary view in the DataFrame for using it in SQL 
scala> acBalDFFromFile.createOrReplaceTempView("balance") 
scala> // Show the first few records of the DataFrame 
scala> acMasterDFFromFile.show 
+-------+---------+--------+ 
|  accNo|firstName|lastName| 
+-------+---------+--------+ 
|SB10001|    Roger| Federer| 
|SB10002|     Pete| Sampras| 
|SB10003|   Rafael|   Nadal| 
|SB10004|    Boris|  Becker| 
|SB10005|     Ivan|   Lendl| 
+-------+---------+--------+ 
scala> acBalDFFromFile.show 
+-------+-------------+ 
|  accNo|balanceAmount| 
+-------+-------------+ 
|SB10001|      50000.0| 
|SB10002|      12000.0| 
|SB10003|       3000.0| 
|SB10004|       8500.0| 
|SB10005|       5000.0| 
+-------+-------------+ 
scala> // Use SQL to create another DataFrame containing the account detail records 
scala> val acDetail = spark.sql("SELECT master.accNo, firstName, lastName, balanceAmount FROM master, balance WHERE master.accNo = balance.accNo ORDER BY balanceAmount DESC") 
acDetail: org.apache.spark.sql.DataFrame = [accNo: string, firstName: string ... 2 more fields] 
scala> // Show the first few records of the DataFrame 
scala> acDetail.show 
+-------+---------+--------+-------------+ 
|  accNo|firstName|lastName|balanceAmount| 
+-------+---------+--------+-------------+ 
|SB10001|    Roger| Federer|      50000.0| 
|SB10002|     Pete| Sampras|      12000.0| 
|SB10004|    Boris|  Becker|       8500.0| 
|SB10005|     Ivan|   Lendl|       5000.0| 
|SB10003|   Rafael|   Nadal|       3000.0| 
+-------+---------+--------+-------------+

```

在同一 Scala REPL 会话中继续，以下代码行通过 DataFrame API 获得相同结果：

```scala
scala> // Create the DataFrame using API for the account detail records 
scala> val acDetailFromAPI = acMasterDFFromFile.join(acBalDFFromFile, acMasterDFFromFile("accNo") === acBalDFFromFile("accNo"), "inner").sort($"balanceAmount".desc).select(acMasterDFFromFile("accNo"), acMasterDFFromFile("firstName"), acMasterDFFromFile("lastName"), acBalDFFromFile("balanceAmount")) 
acDetailFromAPI: org.apache.spark.sql.DataFrame = [accNo: string, firstName: string ... 2 more fields] 
scala> // Show the first few records of the DataFrame 
scala> acDetailFromAPI.show 
+-------+---------+--------+-------------+ 
|  accNo|firstName|lastName|balanceAmount| 
+-------+---------+--------+-------------+ 
|SB10001|    Roger| Federer|      50000.0| 
|SB10002|     Pete| Sampras|      12000.0| 
|SB10004|    Boris|  Becker|       8500.0| 
|SB10005|     Ivan|   Lendl|       5000.0| 
|SB10003|   Rafael|   Nadal|       3000.0| 
+-------+---------+--------+-------------+ 
scala> // Use SQL to create another DataFrame containing the top 3 account detail records 
scala> val acDetailTop3 = spark.sql("SELECT master.accNo, firstName, lastName, balanceAmount FROM master, balance WHERE master.accNo = balance.accNo ORDER BY balanceAmount DESC").limit(3) 
acDetailTop3: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [accNo: string, firstName: string ... 2 more fields] 
scala> // Show the first few records of the DataFrame 
scala> acDetailTop3.show 
+-------+---------+--------+-------------+ 
|  accNo|firstName|lastName|balanceAmount| 
+-------+---------+--------+-------------+ 
|SB10001|    Roger| Federer|      50000.0| 
|SB10002|     Pete| Sampras|      12000.0| 
|SB10004|    Boris|  Becker|       8500.0| 
+-------+---------+--------+-------------+

```

在前述代码段中选择的连接类型是内连接。实际上，可以通过 SQL 查询方式或 DataFrame API 方式使用其他任何类型的连接。在这个特定用例中，可以发现 DataFrame API 显得有些笨拙，而 SQL 查询则非常直接。关键在于，根据情况，在应用程序代码中，可以将 SQL 查询方式与 DataFrame API 方式混合使用，以产生期望的结果。以下脚本中给出的 DataFrame `acDetailTop3`就是一个例子。

在 Python REPL 提示符下，尝试以下语句：

```scala
>>> from pyspark.sql import Row 
>>> # Creation of the list from where the RDD is going to be created 
>>> AcMaster = Row('accNo', 'firstName', 'lastName') 
>>> AcBal = Row('accNo', 'balanceAmount') 
>>> acMasterList = ["SB10001,Roger,Federer","SB10002,Pete,Sampras", "SB10003,Rafael,Nadal","SB10004,Boris,Becker", "SB10005,Ivan,Lendl"] 
>>> acBalList = ["SB10001,50000", "SB10002,12000","SB10003,3000", "SB10004,8500", "SB10005,5000"] 
>>> # Create the DataFrame 
>>> acMasterDF = sc.parallelize(acMasterList).map(lambda trans: trans.split(",")).map(lambda r: AcMaster(*r)).toDF() 
>>> acBalDF = sc.parallelize(acBalList).map(lambda trans: trans.split(",")).map(lambda r: AcBal(r[0], float(r[1]))).toDF() 
>>> # Persist the data of the DataFrame into a Parquet file 
>>> acMasterDF.write.parquet("python.master.parquet") 
>>> # Persist the data of the DataFrame into a JSON file 
>>> acBalDF.write.json("pythonMaster.json") 
>>> # Read the data into a DataFrame from the Parquet file 
>>> acMasterDFFromFile = spark.read.parquet("python.master.parquet") 
>>> # Register temporary table in the DataFrame for using it in SQL 
>>> acMasterDFFromFile.createOrReplaceTempView("master") 
>>> # Register temporary table in the DataFrame for using it in SQL 
>>> acBalDFFromFile = spark.read.json("pythonMaster.json") 
>>> # Register temporary table in the DataFrame for using it in SQL 
>>> acBalDFFromFile.createOrReplaceTempView("balance") 
>>> # Show the first few records of the DataFrame 
>>> acMasterDFFromFile.show() 
+-------+---------+--------+ 
|  accNo|firstName|lastName| 
+-------+---------+--------+ 
|SB10001|    Roger| Federer| 
|SB10002|     Pete| Sampras| 
|SB10003|   Rafael|   Nadal| 
|SB10004|    Boris|  Becker| 
|SB10005|     Ivan|   Lendl| 
+-------+---------+--------+ 
>>> # Show the first few records of the DataFrame 
>>> acBalDFFromFile.show() 
+-------+-------------+ 
|  accNo|balanceAmount| 
+-------+-------------+ 
|SB10001|      50000.0| 
|SB10002|      12000.0| 
|SB10003|       3000.0| 
|SB10004|       8500.0| 
|SB10005|       5000.0| 
+-------+-------------+ 
>>> # Use SQL to create another DataFrame containing the account detail records 
>>> acDetail = spark.sql("SELECT master.accNo, firstName, lastName, balanceAmount FROM master, balance WHERE master.accNo = balance.accNo ORDER BY balanceAmount DESC") 
>>> # Show the first few records of the DataFrame 
>>> acDetail.show() 
+-------+---------+--------+-------------+ 
|  accNo|firstName|lastName|balanceAmount| 
+-------+---------+--------+-------------+ 
|SB10001|    Roger| Federer|      50000.0| 
|SB10002|     Pete| Sampras|      12000.0| 
|SB10004|    Boris|  Becker|       8500.0| 
|SB10005|     Ivan|   Lendl|       5000.0| 
|SB10003|   Rafael|   Nadal|       3000.0| 
+-------+---------+--------+-------------+ 
>>> # Create the DataFrame using API for the account detail records 
>>> acDetailFromAPI = acMasterDFFromFile.join(acBalDFFromFile, acMasterDFFromFile.accNo == acBalDFFromFile.accNo).sort(acBalDFFromFile.balanceAmount, ascending=False).select(acMasterDFFromFile.accNo, acMasterDFFromFile.firstName, acMasterDFFromFile.lastName, acBalDFFromFile.balanceAmount) 
>>> # Show the first few records of the DataFrame 
>>> acDetailFromAPI.show() 
+-------+---------+--------+-------------+ 
|  accNo|firstName|lastName|balanceAmount| 
+-------+---------+--------+-------------+ 
|SB10001|    Roger| Federer|      50000.0| 
|SB10002|     Pete| Sampras|      12000.0| 
|SB10004|    Boris|  Becker|       8500.0| 
|SB10005|     Ivan|   Lendl|       5000.0| 
|SB10003|   Rafael|   Nadal|       3000.0| 
+-------+---------+--------+-------------+ 
>>> # Use SQL to create another DataFrame containing the top 3 account detail records 
>>> acDetailTop3 = spark.sql("SELECT master.accNo, firstName, lastName, balanceAmount FROM master, balance WHERE master.accNo = balance.accNo ORDER BY balanceAmount DESC").limit(3) 
>>> # Show the first few records of the DataFrame 
>>> acDetailTop3.show() 
+-------+---------+--------+-------------+ 
|  accNo|firstName|lastName|balanceAmount| 
+-------+---------+--------+-------------+ 
|SB10001|    Roger| Federer|      50000.0| 
|SB10002|     Pete| Sampras|      12000.0| 
|SB10004|    Boris|  Becker|       8500.0| 
+-------+---------+--------+-------------+ 

```

在前述章节中，已展示了在 DataFrame 上应用 RDD 操作的情况。这表明了 Spark SQL 与 RDD 之间互操作的能力。同样地，SQL 查询和 DataFrame API 可以混合使用，以便在解决应用程序中的实际用例时，能够灵活地采用最简便的计算方法。

# 引入数据集

Spark 编程范式在开发数据处理应用时提供了多种抽象选择。Spark 编程的基础始于 RDD，它能轻松处理非结构化、半结构化和结构化数据。Spark SQL 库在处理结构化数据时展现出高度优化的性能，使得基本 RDD 在性能上显得逊色。为了弥补这一差距，自 Spark 1.6 起，引入了一种名为 Dataset 的新抽象，它补充了基于 RDD 的 Spark 编程模型。在 Spark 转换和 Spark 操作方面，Dataset 的工作方式与 RDD 大致相同，同时它也像 Spark SQL 一样高度优化。Dataset API 在编写程序时提供了强大的编译时类型安全，因此，Dataset API 仅在 Scala 和 Java 中可用。

本章讨论的 Spark 编程模型中的交易银行业务用例在此再次被提及，以阐明基于 Dataset 的编程模型，因为这种编程模型与基于 RDD 的编程非常相似。该用例主要处理一组银行交易记录以及对这些记录进行的各种处理，以从中提取各种信息。用例描述在此不再重复，通过查看注释和代码不难理解。

以下代码片段展示了创建 Dataset 的方法及其使用、RDD 到 DataFrame 的转换以及 DataFrame 到 Dataset 的转换。RDD 到 DataFrame 的转换已经讨论过，但在此再次捕捉，以保持概念的上下文。这主要是为了证明 Spark 中的各种编程模型和数据抽象具有高度的互操作性。

在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> // Define the case classes for using in conjunction with DataFrames and Dataset 
scala> case class Trans(accNo: String, tranAmount: Double)  
defined class Trans 
scala> // Creation of the list from where the Dataset is going to be created using a case class. 
scala> val acTransList = Seq(Trans("SB10001", 1000), Trans("SB10002",1200), Trans("SB10003", 8000), Trans("SB10004",400), Trans("SB10005",300), Trans("SB10006",10000), Trans("SB10007",500), Trans("SB10008",56), Trans("SB10009",30),Trans("SB10010",7000), Trans("CR10001",7000), Trans("SB10002",-10)) 
acTransList: Seq[Trans] = List(Trans(SB10001,1000.0), Trans(SB10002,1200.0), Trans(SB10003,8000.0), Trans(SB10004,400.0), Trans(SB10005,300.0), Trans(SB10006,10000.0), Trans(SB10007,500.0), Trans(SB10008,56.0), Trans(SB10009,30.0), Trans(SB10010,7000.0), Trans(CR10001,7000.0), Trans(SB10002,-10.0)) 
scala> // Create the Dataset 
scala> val acTransDS = acTransList.toDS() 
acTransDS: org.apache.spark.sql.Dataset[Trans] = [accNo: string, tranAmount: double] 
scala> acTransDS.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+ 
scala> // Apply filter and create another Dataset of good transaction records 
scala> val goodTransRecords = acTransDS.filter(_.tranAmount > 0).filter(_.accNo.startsWith("SB")) 
goodTransRecords: org.apache.spark.sql.Dataset[Trans] = [accNo: string, tranAmount: double] 
scala> goodTransRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
+-------+----------+ 
scala> // Apply filter and create another Dataset of high value transaction records 
scala> val highValueTransRecords = goodTransRecords.filter(_.tranAmount > 1000) 
highValueTransRecords: org.apache.spark.sql.Dataset[Trans] = [accNo: string, tranAmount: double] 
scala> highValueTransRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10006|   10000.0| 
|SB10010|    7000.0| 
+-------+----------+ 
scala> // The function that identifies the bad amounts 
scala> val badAmountLambda = (trans: Trans) => trans.tranAmount <= 0 
badAmountLambda: Trans => Boolean = <function1> 
scala> // The function that identifies bad accounts 
scala> val badAcNoLambda = (trans: Trans) => trans.accNo.startsWith("SB") == false 
badAcNoLambda: Trans => Boolean = <function1> 
scala> // Apply filter and create another Dataset of bad amount records 
scala> val badAmountRecords = acTransDS.filter(badAmountLambda) 
badAmountRecords: org.apache.spark.sql.Dataset[Trans] = [accNo: string, tranAmount: double] 
scala> badAmountRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|     -10.0| 
+-------+----------+ 
scala> // Apply filter and create another Dataset of bad account records 
scala> val badAccountRecords = acTransDS.filter(badAcNoLambda) 
badAccountRecords: org.apache.spark.sql.Dataset[Trans] = [accNo: string, tranAmount: double] 
scala> badAccountRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|CR10001|    7000.0| 
+-------+----------+ 
scala> // Do the union of two Dataset and create another Dataset 
scala> val badTransRecords  = badAmountRecords.union(badAccountRecords) 
badTransRecords: org.apache.spark.sql.Dataset[Trans] = [accNo: string, tranAmount: double] 
scala> badTransRecords.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10002|     -10.0| 
|CR10001|    7000.0| 
+-------+----------+ 
scala> // Calculate the sum 
scala> val sumAmount = goodTransRecords.map(trans => trans.tranAmount).reduce(_ + _) 
sumAmount: Double = 28486.0 
scala> // Calculate the maximum 
scala> val maxAmount = goodTransRecords.map(trans => trans.tranAmount).reduce((a, b) => if (a > b) a else b) 
maxAmount: Double = 10000.0 
scala> // Calculate the minimum 
scala> val minAmount = goodTransRecords.map(trans => trans.tranAmount).reduce((a, b) => if (a < b) a else b) 
minAmount: Double = 30.0 
scala> // Convert the Dataset to DataFrame 
scala> val acTransDF = acTransDS.toDF() 
acTransDF: org.apache.spark.sql.DataFrame = [accNo: string, tranAmount: double] 
scala> acTransDF.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+ 
scala> // Use Spark SQL to find out invalid transaction records 
scala> acTransDF.createOrReplaceTempView("trans") 
scala> val invalidTransactions = spark.sql("SELECT accNo, tranAmount FROM trans WHERE (accNo NOT LIKE 'SB%') OR tranAmount <= 0") 
invalidTransactions: org.apache.spark.sql.DataFrame = [accNo: string, tranAmount: double] 
scala> invalidTransactions.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+ 
scala> // Interoperability of RDD, DataFrame and Dataset 
scala> // Create RDD 
scala> val acTransRDD = sc.parallelize(acTransList) 
acTransRDD: org.apache.spark.rdd.RDD[Trans] = ParallelCollectionRDD[206] at parallelize at <console>:28 
scala> // Convert RDD to DataFrame 
scala> val acTransRDDtoDF = acTransRDD.toDF() 
acTransRDDtoDF: org.apache.spark.sql.DataFrame = [accNo: string, tranAmount: double] 
scala> // Convert the DataFrame to Dataset with the type checking 
scala> val acTransDFtoDS = acTransRDDtoDF.as[Trans] 
acTransDFtoDS: org.apache.spark.sql.Dataset[Trans] = [accNo: string, tranAmount: double] 
scala> acTransDFtoDS.show() 
+-------+----------+ 
|  accNo|tranAmount| 
+-------+----------+ 
|SB10001|    1000.0| 
|SB10002|    1200.0| 
|SB10003|    8000.0| 
|SB10004|     400.0| 
|SB10005|     300.0| 
|SB10006|   10000.0| 
|SB10007|     500.0| 
|SB10008|      56.0| 
|SB10009|      30.0| 
|SB10010|    7000.0| 
|CR10001|    7000.0| 
|SB10002|     -10.0| 
+-------+----------+

```

很明显，基于 Dataset 的编程在许多数据处理用例中具有良好的适用性；同时，它与 Spark 内部的其他数据处理抽象具有高度的互操作性。

### 提示

在前述代码片段中，DataFrame 通过类型指定`acTransRDDToDF.as[Trans]`转换为 Dataset。当从外部数据源（如 JSON、Avro 或 Parquet 文件）读取数据时，这种转换是真正需要的，此时需要强类型检查。通常，结构化数据被读入 DataFrame，然后可以像这样一次性转换为具有强类型安全检查的 DataSet：`spark.read.json("/transaction.json").as[Trans]`

如果本章中的 Scala 代码片段被仔细检查，当某些方法被调用在一个 DataFrame 上时，返回的不是一个 DataFrame 对象，而是一个类型为`org.apache.spark.sql.Dataset[org.apache.spark.sql.Row]`的对象。这是 DataFrame 与 dataset 之间的重要关系。换句话说，DataFrame 是一个类型为`org.apache.spark.sql.Row`的 dataset。如果需要，这个类型为`org.apache.spark.sql.Dataset[org.apache.spark.sql.Row]`的对象可以显式地使用`toDF()`方法转换为 DataFrame。

过多的选择让所有人困惑。在 Spark 编程模型中，同样的问题也存在。但这并不像许多其他编程范式那样令人困惑。每当需要处理任何类型的数据，并且对数据处理要求具有极高的灵活性，以及拥有最低级别的 API 控制，如库开发时，基于 RDD 的编程模型是理想选择。每当需要处理结构化数据，并且需要跨所有支持的编程语言灵活访问和处理数据，同时优化性能时，基于 DataFrame 的 Spark SQL 编程模型是理想选择。

每当需要处理非结构化数据，同时要求优化性能和编译时类型安全，但不需要非常复杂的 Spark 转换和 Spark 操作使用要求时，基于 dataset 的编程模型是理想选择。在数据处理应用开发层面，如果所选编程语言允许，使用 dataset 和 DataFrame 会获得更好的性能。

# 理解数据目录

本章前几节介绍了使用 DataFrames 和 datasets 的编程模型。这两种编程模型都能处理结构化数据。结构化数据自带元数据，即描述数据结构的数据。Spark SQL 提供了一个极简的 API，称为 Catalog API，供数据处理应用查询和使用应用中的元数据。Catalog API 展示了一个包含多个数据库的目录抽象。对于常规的 SparkSession，它只有一个数据库，即默认数据库。但如果 Spark 与 Hive 一起使用，那么整个 Hive 元数据存储将通过 Catalog API 可用。以下代码片段展示了在 Scala 和 Python 中使用 Catalog API 的示例。

继续在同一个 Scala REPL 提示符下，尝试以下语句：

```scala
scala> // Get the catalog object from the SparkSession object
scala> val catalog = spark.catalog
catalog: org.apache.spark.sql.catalog.Catalog = org.apache.spark.sql.internal.CatalogImpl@14b8a751
scala> // Get the list of databases
scala> val dbList = catalog.listDatabases()
dbList: org.apache.spark.sql.Dataset[org.apache.spark.sql.catalog.Database] = [name: string, description: string ... 1 more field]
scala> // Display the details of the databases
scala> dbList.select("name", "description", "locationUri").show()**+-------+----------------+--------------------+**
**| name| description| locationUri|**
**+-------+----------------+--------------------+**
**|default|default database|file:/Users/RajT/...|**
**+-------+----------------+--------------------+**
scala> // Display the details of the tables in the database
scala> val tableList = catalog.listTables()
tableList: org.apache.spark.sql.Dataset[org.apache.spark.sql.catalog.Table] = [name: string, database: string ... 3 more fields]
scala> tableList.show()**+-----+--------+-----------+---------+-----------+**
 **| name|database|description|tableType|isTemporary|**
**+-----+--------+-----------+---------+-----------+**
**|trans| null| null|TEMPORARY| true|**
**+-----+--------+-----------+---------+-----------+**
scala> // The above list contains the temporary view that was created in the Dataset use case discussed in the previous section
// The views created in the applications can be removed from the database using the Catalog APIscala> catalog.dropTempView("trans")
// List the available tables after dropping the temporary viewscala> val latestTableList = catalog.listTables()
latestTableList: org.apache.spark.sql.Dataset[org.apache.spark.sql.catalog.Table] = [name: string, database: string ... 3 more fields]
scala> latestTableList.show()**+----+--------+-----------+---------+-----------+**
**|name|database|description|tableType|isTemporary|**
**+----+--------+-----------+---------+-----------+**
**+----+--------+-----------+---------+-----------+** 

```

同样，Catalog API 也可以从 Python 代码中使用。由于 dataset 示例在 Python 中不适用，表列表将为空。在 Python REPL 提示符下，尝试以下语句：

```scala
>>> #Get the catalog object from the SparkSession object
>>> catalog = spark.catalog
>>> #Get the list of databases and their details.
>>> catalog.listDatabases()   [Database(name='default', description='default database', locationUri='file:/Users/RajT/source-code/spark-source/spark-2.0/spark-warehouse')]
// Display the details of the tables in the database
>>> catalog.listTables()
>>> []

```

Catalog API 在编写能够根据元数据存储内容动态处理数据的数据处理应用时非常方便，尤其是在与 Hive 结合使用时。

# 参考资料

更多信息，请参考：

+   [Spark SQL 在 SIGMOD 2015 上的论文](https://amplab.cs.berkeley.edu/wp-content/uploads/2015/03/SparkSQLSigmod2015.pdf)

+   [Pandas 数据分析库](http://pandas.pydata.org/)

# 总结

Spark SQL 是建立在 Spark 核心基础设施之上的一个极其有用的库。该库使得 Spark 编程对更广泛的熟悉命令式编程风格的程序员更加包容，尽管他们在函数式编程方面可能不那么熟练。此外，Spark SQL 是 Spark 数据处理库家族中处理结构化数据的最佳库。基于 Spark SQL 的数据处理应用程序可以使用类似 SQL 的查询或 DataFrame API 的 DSL 风格命令式程序编写。本章还展示了混合 RDD 和 DataFrames、混合类似 SQL 的查询和 DataFrame API 的各种策略。这为应用程序开发人员提供了极大的灵活性，使他们能够以最舒适的方式或更适合用例的方式编写数据处理程序，同时不牺牲性能。

Dataset API 作为基于 Spark 中数据集的下一代编程模型，提供了优化的性能和编译时的类型安全。

目录 API 作为一个非常便捷的工具，可根据元数据存储的内容动态处理数据。

R 是数据科学家的语言。在 Spark SQL 支持 R 作为编程语言之前，对他们来说，进行大规模分布式数据处理并不容易。现在，使用 R 作为首选语言，他们可以无缝地编写分布式数据处理应用程序，就像使用个人机器上的 R 数据框一样。下一章将讨论在 Spark SQL 中使用 R 进行数据处理。
