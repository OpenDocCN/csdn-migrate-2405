# Spark2 数据处理和实时分析（一）

> 原文：[`zh.annas-archive.org/md5/16D84784AD68D8BF20A18AC23C62DD82`](https://zh.annas-archive.org/md5/16D84784AD68D8BF20A18AC23C62DD82)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Apache Spark 是一个基于内存的集群数据处理系统，提供广泛的功能，如大数据处理、分析、机器学习等。通过这个学习路径，您可以将 Apache Spark 的知识提升到一个新的水平，学习如何扩展 Spark 的功能，并在此平台上构建自己的数据流和机器学习程序。您将使用 Apache Spark 的不同模块，如使用 Spark SQL 进行交互式查询、使用 DataFrames 和数据集、使用 Spark Streaming 实现流分析，以及使用 MLlib 和各种外部工具在 Spark 上应用机器学习和深度学习技术。通过这个精心设计的学习...

# 本书面向的读者

如果您是一名中级 Spark 开发者，希望掌握 Apache Spark 2.x 的高级功能和用例，这个学习路径非常适合您。希望学习如何集成和使用 Apache Spark 功能并构建强大大数据管道的大数据专业人士也会发现这个学习路径很有用。要理解本学习路径中解释的概念，您必须了解 Apache Spark 和 Scala 的基础知识。

# 本书内容

*第一章*，*Apache Spark V2 初体验及新特性*，概述了 Apache Spark，介绍了其模块内的功能，以及如何进行扩展。它涵盖了 Apache Spark 标准模块之外的生态系统中可用的处理和存储工具。还提供了性能调优的技巧。

*第二章*，*Apache Spark 流处理*，讲述了使用 Apache Spark Streaming 的连续应用程序。您将学习如何增量处理数据并创建可行的见解。

*第三章*，*结构化流处理*，讲述了使用 DataFrame 和 Dataset API 定义连续应用程序的新方式——结构化流处理。

*第四章*，*Apache Spark MLlib*，介绍了...

# 充分利用本书

**操作系统：** 首选 Linux 发行版（包括 Debian、Ubuntu、Fedora、RHEL 和 CentOS），具体来说，推荐使用完整的 Ubuntu 14.04（LTS）64 位（或更高版本）安装，VMware player 12 或 VirtualBox。您也可以在 Windows（XP/7/8/10）或 Mac OS X（10.4.7+）上运行 Spark 作业。

**硬件配置：** 处理器建议使用 Core i3、Core i5（推荐）或 Core i7（以获得最佳效果）。然而，多核处理将提供更快的数据处理和可扩展性。对于独立模式，您至少需要 8-16 GB RAM（推荐），对于单个虚拟机至少需要 32 GB RAM——集群模式则需要更多。您还需要足够的存储空间来运行繁重的作业（取决于您将处理的数据集大小），并且最好至少有 50 GB 的可用磁盘存储空间（对于独立模式和 SQL 仓库）。

此外，您还需要以下内容：

+   VirtualBox 5.1.22 或更高版本

+   Hortonworks HDP Sandbox V2.6 或更高版本

+   Eclipse Neon 或更高版本

+   Eclipse Scala 插件

+   Eclipse Git 插件

+   Spark 2.0.0（或更高版本）

+   Hadoop 2.7（或更高版本）

+   Java（JDK 和 JRE）1.7+/1.8+

+   Scala 2.11.x（或更高版本）

+   Python 2.7+/3.4+

+   R 3.1+ 和 RStudio 1.0.143（或更高版本）

+   Maven Eclipse 插件（2.9 或更高版本）

+   Maven 编译器插件 for Eclipse（2.3.2 或更高版本）

+   Maven 装配插件 for Eclipse（2.4.1 或更高版本）

+   Oracle JDK SE 1.8.x

+   JetBrain IntelliJ 社区版 2016.2.X 或更高版本

+   IntelliJ 的 Scala 插件 2016.2.x

+   Jfreechart 1.0.19

+   breeze-core 0.12

+   Cloud9 1.5.0 JAR

+   Bliki-core 3.0.19

+   hadoop-streaming 2.2.0

+   Jcommon 1.0.23

+   Lucene-analyzers-common 6.0.0

+   Lucene-core-6.0.0

+   Spark-streaming-flume-assembly 2.0.0

+   Spark-streaming-kafka-assembly 2.0.0

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的账户下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册于[www.packt.com](http://www.packt.com)。

1.  选择支持选项卡。

1.  点击代码下载与勘误。

1.  在搜索框中输入书名，并按照屏幕上的指示操作。

下载文件后，请确保使用最新版本的以下软件解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

[本书代码包](https://github.com/PacktPublishing/Apache-Spark-2-Data-Processing-and-Real-Time-Analytics)也托管在 GitHub 上。

# 使用的约定

本书中，您会发现多种文本样式用于区分不同类型的信息。以下是这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“接下来的代码行读取链接并将其分配给`BeautifulSoup`函数。”

代码块设置如下：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf
```

任何命令行输入或输出如下所示：

```scala
$./bin/spark-submit --class com.chapter11.RandomForestDemo \
--master spark://ip-172-31-21-153.us-west-2.compute:7077 \
--executor-memory 2G \
--total-executor-cores 2 \
file:///home/KMeans-0.0.1-SNAPSHOT.jar \
file:///home/mnist.bz2
```

**粗体**：新术语和重要词汇以粗体显示。屏幕上看到的词汇，例如在菜单或对话框中，在文本中这样显示：“配置全局库。选择 Scala SDK 作为您的全局库。”

警告或重要提示以这种方式出现。

提示和技巧以这种方式出现。


# 第一章：初探 Apache Spark V2 的新特性

**Apache Spark**是一个分布式且高度可扩展的内存数据分析系统，为你提供了使用 Java、Scala、Python 以及 R 等语言开发应用程序的能力。它是当前 Apache 顶级项目中贡献/参与度最高的项目之一。Apache 系统，如 Mahout，现在将其作为处理引擎，而非 MapReduce。还可以使用 Hive 上下文让 Spark 应用程序直接处理 Apache Hive 中的数据。

最初，Apache Spark 提供了四个主要子模块——SQL、MLlib、GraphX 和 Streaming。它们将在各自的章节中进行解释，但在此之前，一个简单的概述将是有益的。...

# Spark 机器学习

机器学习是 Apache Spark 的真正原因，因为归根结底，你不仅仅希望将数据从 A 地运送到 B 地（这一过程称为**ETL**（**提取、转换、加载**））。你希望在你的数据上运行高级数据分析算法，并且希望这些算法能够扩展。这正是 Apache Spark 发挥作用的地方。

Apache Spark 的核心提供了大规模并行数据处理的运行时环境，不同的并行机器学习库在其上运行。这是因为流行的编程语言如 R 和 Python 有大量机器学习算法，但它们不具备可扩展性。一旦你向系统可用主内存加载更多数据，它们就会崩溃。

相比之下，Apache Spark 可以利用多个计算机节点形成集群，并且即使在单个节点上，也能透明地将数据溢出到磁盘，从而避免主内存瓶颈。Apache Spark 自带了两个有趣的机器学习库，但本工作还将涵盖第三方机器学习库。

Spark MLlib 模块，即经典 MLlib，提供了一个不断增长但尚不完整的机器学习算法列表。自从基于**DataFrame**的机器学习 API——**SparkML**推出以来，MLlib 的命运已定。它仅因向后兼容的原因而被保留。

在 SparkML 中，我们已有一个机器学习库，该库开箱即用，可利用这些改进作为底层架构。

SparkML 最终将取代 MLlib。Apache SystemML 推出了首个运行在 Apache Spark 之上的库，该库并非随 Apache Spark 发行版一同提供。SystemML 为你提供了一个具有内置成本优化器的 R 风格语法执行环境。大规模并行机器学习是一个不断变化的高频领域。很难预测这一旅程将走向何方，但这是首次，使用开源和云计算的每个人都能获得大规模的高级机器学习。

Apache Spark 上的深度学习使用**H2O**、**Deeplearning4j**和**Apache SystemML**，这些都是非常有趣的第三方机器学习库的例子，它们并未随 Apache Spark 分发。

尽管 H2O 在某种程度上与 MLlib 互补，但 Deeplearning4j 仅专注于深度学习算法。两者都使用 Apache Spark 作为数据处理并行化的手段。您可能会好奇为什么我们要研究不同的机器学习库。

实际上，每个库在实现不同算法时都有其优缺点。因此，通常取决于您的数据和数据集大小，您会选择哪种实现以获得最佳性能。

然而，令人高兴的是，使用 Apache Spark 时有如此多的选择，您不会被锁定在一个单一的库中。开源意味着开放性，这只是我们如何从与单一供应商、单一产品锁定相反的方法中受益的一个例子。尽管最近 Apache Spark 将另一个库 GraphX 集成到其分发中，但我们不期望这种情况会很快发生。因此，最有可能的是，Apache Spark 作为一个中央数据处理平台和额外的第三方库将共存，就像 Apache Spark 是大数据操作系统，而第三方库是您在其上安装和运行的软件一样。

# Spark Streaming

**流处理**是 Apache Spark 的另一个重大且流行的话题。它涉及在 Spark 中以流的形式处理数据，并涵盖了输入和输出操作、转换、持久性和检查点等主题。

Apache Spark Streaming 将涵盖处理领域，我们还将看到不同类型流处理的实际示例。这讨论了批处理和窗口流配置，并提供了一个检查点设置的实际示例。它还涵盖了包括 Kafka 和 Flume 在内的不同流处理示例。

流数据有许多用途。其他 Spark 模块功能（例如，SQL、MLlib 和 GraphX）可用于处理流。您...

# Spark SQL

从 Spark 版本 1.3 开始，Apache Spark 引入了数据帧，使得 Spark 数据可以以表格形式处理，并可以使用表格函数（如`select`、`filter`和`groupBy`）来处理数据。Spark SQL 模块与 Parquet 和 JSON 格式集成，允许数据以更好地表示数据的格式存储。这也提供了更多与外部系统集成的选项。

将 Apache Spark 集成到 Hadoop Hive 大数据数据库的想法也可以引入。基于 Hive 上下文的 Spark 应用程序可用于操作基于 Hive 的表数据。这使得 Hive 能够利用 Spark 的快速内存分布式处理能力，有效地让 Hive 使用 Spark 作为处理引擎。

此外，还有大量额外的连接器，可以直接从 Apache Spark 访问 Hadoop 生态系统之外的 NoSQL 数据库。

# Spark 图处理

图处理是数据分析中另一个非常重要的主题。事实上，大多数问题都可以表示为图。

**图**基本上是一个项目及其相互关系的网络。项目称为**节点**，关系称为**边**。关系可以是定向的或非定向的。关系以及项目可以具有属性。因此，例如，地图也可以表示为图。每个城市是一个节点，城市之间的街道是边。城市之间的距离可以作为边上的属性分配。

**Apache Spark GraphX**模块使 Apache Spark 能够提供快速的大数据内存图处理。这使您能够运行图算法...

# 扩展生态系统

在审视大数据处理系统时，我们认为不仅要关注系统本身，还要关注它如何扩展以及如何与外部系统集成，以便提供更高级别的功能。在这本书的篇幅中，我们无法涵盖每一种选择，但通过引入一个主题，我们希望能够激发读者的兴趣，使他们能够进一步研究。

# 在 Apache Spark V2 中有哪些新变化？

自 Apache Spark V2 以来，许多事情都发生了变化。这并不意味着 API 已被破坏。相反，大多数 V1.6 的 Apache Spark 应用程序将在 Apache Spark V2 上运行，无论是否需要很少的更改，但在幕后，已经发生了很多变化。

尽管**Java 虚拟机**（**JVM**）本身是一件杰作，但它是一个通用的字节码执行引擎。因此，存在大量的 JVM 对象管理和**垃圾回收**（**GC**）开销。例如，存储一个 4 字节的字符串，在 JVM 上需要 48 字节。GC 基于对象生命周期估计进行优化，但 Apache Spark 通常比 JVM 更了解这一点。因此，Tungsten 对私有子集禁用了 JVM GC...

# 集群设计

正如我们已经提到的，Apache Spark 是一个分布式、内存内并行处理系统，需要一个关联的存储系统。因此，当您构建大数据集群时，您可能会使用分布式存储系统，如 Hadoop，以及用于移动数据的工具，如 Sqoop、Flume 和 Kafka。

我们希望在大数据集群中引入边缘节点的概念。这些集群中的节点将面向客户端，上面驻留着如 Hadoop NameNode 或可能是 Spark master 等客户端面向组件。大多数大数据集群可能位于防火墙后面。边缘节点将减少由防火墙引起的复杂性，因为它们将是外部可访问的唯一接触点。下图展示了一个简化的大数据集群：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/c67b8c64-37f1-45fb-99f3-ee2d80a03065.png)

它展示了五个简化的集群节点，每个 CPU 核心有一个执行器 JVM，以及位于集群外部的 Spark 驱动程序 JVM。此外，您可以看到直接连接到节点的磁盘。这被称为**JBOD**（**只是一堆磁盘**）方法。非常大的文件在磁盘上分区，虚拟文件系统（如 HDFS）将这些块作为一个大虚拟文件提供。当然，这是风格化和简化的，但您可以理解这个概念。

下面的简化组件模型展示了驱动程序 JVM 位于集群外部。它与集群管理器通信，以获得在 worker 节点上调度任务的许可，因为集群管理器负责跟踪集群上运行的所有进程的资源分配。

正如我们稍后将看到的，存在多种不同的集群管理器，其中一些还能够管理其他 Hadoop 工作负载，甚至与 Spark 执行器并行运行的非 Hadoop 应用程序。请注意，执行器和驱动程序之间始终保持双向通信，因此从网络角度来看，它们也应该彼此靠近：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/6e9505fc-7541-41a5-94b3-1b823fe6c1b4.png)

图源：https://spark.apache.org/docs/2.0.2/cluster-overview.html

通常，虽然防火墙为集群增加了安全性，但也增加了复杂性。系统组件之间的端口需要打开，以便它们可以相互通信。例如，Zookeeper 被许多组件用于配置。Apache Kafka，发布/订阅消息系统，使用 Zookeeper 来配置其主题、组、消费者和生产者。因此，需要打开到 Zookeeper 的客户端端口，可能跨越防火墙。

最后，需要考虑将系统分配给集群节点的方案。例如，如果 Apache Spark 使用 Flume 或 Kafka，则会使用内存通道。这些通道的大小以及数据流导致的内存使用量需要考虑。Apache Spark 不应与其他 Apache 组件竞争内存使用。根据您的数据流和内存使用情况，可能需要在不同的集群节点上部署 Spark、Hadoop、Zookeeper、Flume 和其他工具。或者，可以使用 YARN、Mesos 或 Docker 等资源管理器来解决此问题。在标准的 Hadoop 环境中，YARN 最有可能被采用。

通常，作为集群 NameNode 服务器或 Spark 主服务器的边缘节点将需要比防火墙内的集群处理节点更多的资源。当许多 Hadoop 生态系统组件部署在集群上时，它们都需要在主服务器上额外内存。您应该监控边缘节点的资源使用情况，并根据需要调整资源和/或应用程序位置。例如，YARN 正在处理这个问题。

本节简要介绍了大数据集群中的 Apache Spark、Hadoop 及其他工具。但是，大数据集群内部，Apache Spark 集群本身可能如何配置呢？例如，可以有多种类型的 Spark 集群管理器。下一节将探讨这一点，并描述每种 Apache Spark 集群管理器的类型。

# 集群管理

Spark 上下文，正如你在本书的许多示例中看到的，可以通过 Spark 配置对象和 Spark URL 来定义。Spark 上下文连接到 Spark 集群管理器，后者随后在集群的工作节点之间分配资源给应用程序。集群管理器在集群的工作节点上分配执行器。它将应用程序 JAR 文件复制到工作节点，并最终分配任务。

以下小节描述了目前可用的 Apache Spark 集群管理器的各种选项。

# 本地

通过指定一个本地 Spark 配置 URL，可以使应用程序在本地运行。通过指定 `local[n]`，可以使 Spark 使用 *n* 个线程在本地运行应用程序。这是一个有用的开发和测试选项，因为你还可以测试某种并行化场景，但将所有日志文件保留在单个机器上。

# Standalone

Standalone 模式使用 Apache Spark 自带的基本集群管理器。Spark 主节点的 URL 将如下所示：

`Spark://<hostname>:7077`

在此，`<hostname>` 表示运行 Spark 主节点的宿主机的名称。我们已将端口指定为 `7077`，这是默认值，但可配置。当前这种简单的集群管理器仅支持 **FIFO**（**先进先出**）调度策略。你可以通过为每个应用程序设置资源配置选项来设法实现并发应用调度；例如，使用 `spark.core.max` 在应用程序之间共享核心。

# Apache YARN

在更大规模上，当与 Hadoop YARN 集成时，Apache Spark 集群管理器可以是 YARN，应用程序可以运行在两种模式之一。如果将 Spark 主节点值设置为 `yarn-cluster`，则可以将应用程序提交到集群并随后终止。集群将负责分配资源和运行任务。然而，如果应用程序主节点以 `yarn-client` 方式提交，则应用程序在处理周期内保持活动状态，并向 YARN 请求资源。

# Apache Mesos

**Apache Mesos** 是一个开源系统，用于集群间的资源共享。它允许多个框架通过管理和调度资源来共享集群。作为一个集群管理器，它利用 Linux 容器提供隔离，并允许 Hadoop、Spark、Kafka、Storm 等多种系统安全地共享集群。它高度可扩展至数千个节点。它是一个基于主/从的系统，并具有故障容忍性，使用 Zookeeper 进行配置管理。

对于单个主节点的 Mesos 集群，Spark 主 URL 将采用以下形式：

`mesos://<hostname>:5050`.

在此，`<hostname>`是 Mesos 主服务器的 hostname；端口定义为`5050`，这是默认的 Mesos 主端口（...）

# 基于云的部署

云系统有三种不同的抽象层次——**基础设施即服务**（**IaaS**）、**平台即服务**（**PaaS**）和**软件即服务**（**SaaS**）。我们将探讨如何在所有这些层面上使用和安装 Apache Spark。

新的 IaaS 方式是 Docker 和 Kubernetes，与虚拟机相对，基本上提供了一种在几分钟内自动设置 Apache Spark 集群的方法。Kubernetes 的优势在于，由于它是开放标准且基于开源，因此可以在多个不同的云提供商之间使用。

你甚至可以使用 Kubernetes，在本地数据中心内透明且动态地移动工作负载，跨越本地、专用和公共云数据中心。相比之下，PaaS 为你减轻了安装和操作 Apache Spark 集群的负担，因为这作为一项服务提供。

关于 Docker 是 IaaS 还是 PaaS 的讨论仍在进行中，但在我们看来，它只是一种轻量级预装虚拟机形式。这一点特别有趣，因为其完全基于开源技术，使得你能够在任何其他数据中心复制该系统。

我们将介绍的开源组件之一是 Jupyter 笔记本；一种在基于云的协作环境中进行数据科学的现代方式。

# 性能

在进入涵盖 Apache Spark 功能区域和扩展的其余章节之前，我们将审视性能领域。需要考虑哪些问题和领域？从集群级别到实际 Scala 代码，哪些因素可能影响 Spark 应用程序性能？我们不想仅仅重复 Spark 网站上的内容，因此请查看此 URL：`http://spark.apache.org/docs/<version>/tuning.html`。

在此，`<version>`对应于你正在使用的 Spark 版本；即，最新版本或类似`1.6.1`的特定版本。因此，浏览此页面后，我们将简要提及一些主题领域。本节中，我们将列出一些一般性要点，但不暗示...

# 集群结构

大数据集群的规模和结构将影响性能。如果你拥有一个基于云的集群，相比非共享硬件集群，你的 IO 和延迟将会受到影响。你将与多个客户共享底层硬件，且集群硬件可能位于远程。当然，也有例外。例如，IBM 云提供按小时租赁的专用裸金属高性能集群节点，配备 InfiniBand 网络连接。

此外，集群组件在服务器上的位置可能导致资源争用。例如，在大规模集群中仔细考虑 Hadoop NameNodes、Spark 服务器、Zookeeper、Flume 和 Kafka 服务器的布局。在高负载情况下，您可能需要将服务器隔离到单独的系统中。您还可以考虑使用 Apache Mesos 等系统，它为各个进程提供更好的资源分配和分配。

同时考虑潜在的并行性。对于大型数据集，您的 Spark 集群中的工作者数量越多，实现并行处理的机会就越大。一个经验法则是每个超线程或虚拟核心分别对应一个工作者。

# Hadoop 分布式文件系统

根据您的集群需求，您可能考虑使用 HDFS 的替代方案。例如，IBM 提供了**GPFS**（**通用目的文件系统**）以提高性能。

GPFS 可能是更好选择的原因在于，它源自高性能计算背景，这种文件系统具有完整的读写能力，而 HDFS 设计为一次写入、多次读取的文件系统。它在性能上优于 HDFS，因为它在核心级别运行，而 HDFS 在**Java 虚拟机**（**JVM**）中运行，后者又作为操作系统进程运行。它还与 Hadoop 和 Spark 集群工具集成。IBM 使用 GPFS 配置了数百 PB 的系统。...

# 数据局部性

良好数据处理性能的关键是避免网络传输。这在几年前是非常正确的，但对于 CPU 需求高、I/O 需求低的任务来说，这不太相关，但对于 CPU 需求低、I/O 需求高的数据处理算法，这仍然适用。

由此我们可以得出结论，HDFS 是实现数据局部性的最佳方式之一，因为文件块分布在集群节点上，在大多数情况下，使用直接连接到服务器系统的硬盘。这意味着可以在包含个别数据块的机器上使用 CPU 并行处理这些块，以避免网络传输。

另一种实现数据局部性的方法是使用`ApacheSparkSQL`。根据连接器实现的不同，SparkSQL 可以利用源引擎的数据处理能力。例如，当结合使用 MongoDB 和 SparkSQL 时，SQL 语句的部分内容在数据发送到 Apache Spark 之前由 MongoDB 预处理。

# 内存

为了避免 Apache Spark 集群上的任务出现**内存不足**（**OOM**）消息，请考虑以下调优问题：

+   考虑您的 Spark 工作节点上可用的物理内存级别。是否可以增加？在高负载期间检查操作系统进程的内存消耗，以了解可用内存的情况。确保工作者有足够的内存。

+   考虑数据分区。你能增加分区数量吗？一般而言，分区的数量应至少与集群中可用的 CPU 核心数相等。可使用 RDD API 中的`repartition`函数。

+   你能调整用于存储和缓存 RDD 的 JVM 内存比例吗？...

# 编码

尝试优化你的代码，以提升 Spark 应用程序的性能。例如，在你的 ETL 周期早期基于应用程序数据进行过滤。一个例子是，当使用原始 HTML 文件时，在早期阶段去除标签并裁剪掉不需要的部分。调整并行度，尝试找出代码中资源消耗大的部分，并寻找替代方案。

**ETL**是分析项目中首先要做的事情之一。因此，你正在从第三方系统抓取数据，要么直接访问关系型或 NoSQL 数据库，要么通过读取各种文件格式的导出，如 CSV、TSV、JSON，甚至是来自本地或远程文件系统或 HDFS 中暂存区的更奇特的格式：在对文件进行一些检查和合理性检查后，Apache Spark 中的 ETL 过程基本上读取这些文件并从中创建 RDD 或 DataFrames/Datasets。

它们被转换以适应下游的分析应用程序，这些应用程序运行在 Apache Spark 或其他应用程序之上，然后存储回文件系统，格式可以是 JSON、CSV 或 PARQUET 文件，甚至返回到关系型或 NoSQL 数据库。

最后，对于任何与 Apache Spark 性能相关的问题，我推荐以下资源：[`spark.apache.org/docs/latest/tuning.html`](https://spark.apache.org/docs/latest/tuning.html)。

# 云

尽管本书的部分内容将专注于 Apache Spark 在物理服务器集群上安装的示例，但我们想强调，市面上存在多种基于云的选项，它们带来了许多好处。有些云系统将 Apache Spark 作为集成组件，而有些则提供 Spark 作为服务。

# 错误与恢复

通常，对于你的应用程序，需要问的问题是：是否必须接收并处理所有数据？如果不是，那么在失败时，你可能只需重启应用程序并丢弃缺失或丢失的数据。如果情况并非如此，那么你需要使用将在下一节中描述的检查点机制。

同样值得注意的是，你的应用程序的错误管理应该是健壮且自给自足的。我们的意思是，如果异常不是关键性的，那么管理该异常，可能记录它，并继续处理。例如，当任务达到最大失败次数（由`spark.task.maxFailures`指定）时，它将终止处理。

这一属性及其他属性，可以在创建`SparkContext`对象时设置，或者在调用`spark-shell`或`spark-submit`时作为额外的命令行参数。

# 总结

在结束本章之际，我们邀请你逐步学习后续章节中基于 Scala 代码的示例。Apache Spark 的发展速度令人印象深刻，值得注意的是其发布的频繁程度。因此，尽管在撰写本文时 Spark 已达到 2.2 版本，但我们确信你将使用更新的版本。

如果你遇到问题，请在[www.stackoverflow.com](http://www.stackoverflow.com)上报并相应地标记它们；你将在几分钟内收到反馈——用户社区非常活跃。获取信息和帮助的另一种方式是订阅 Apache Spark 邮件列表：`user@apachespark.org`。

本章结束时，你应该对本书中等待你的内容有了一个清晰的认识。我们专门...


# 第二章：Apache Spark 流处理

Apache 流处理模块是 Apache Spark 中的一个基于流处理的模块。它使用 Spark 集群，提供高度扩展的能力。基于 Spark，它也具有高度容错性，能够通过检查点正在处理的数据流来重新运行失败的任务。在本章的介绍部分之后，将涵盖以下主题，该部分将提供 Apache Spark 如何处理基于流的数据的实际概述：

+   错误恢复与检查点

+   TCP 基础的流处理

+   文件流

+   Kafka 流源

对于每个主题，我们将提供一个在 Scala 中实现的工作示例，并展示如何设置和测试基于流的架构。

# 概览

以下图表展示了 Apache 流处理的潜在数据源，如 Kafka、Flume 和 HDFS：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/4c32c387-9352-43a0-9566-9d7d8bcd34f8.png)

这些输入被送入 Spark 流处理模块，并作为离散流进行处理。该图还显示了其他 Spark 模块功能，如机器学习，也可以用于处理基于流的数。

完全处理后的数据可以作为输出到 HDFS、数据库或仪表板。此图基于 Spark 流处理网站上的图，但我们希望扩展它以表达 Spark 模块功能：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/1691aceb-6ff7-4e59-a23e-498ba8631f74.png)

# 检查点

在批处理中，我们习惯于具备容错性。这意味着，如果某个节点崩溃，作业不会丢失其状态，丢失的任务会在其他工作节点上重新调度。中间结果被写入持久存储（当然，这种存储也必须具备容错性，如 HDFS、GPFS 或云对象存储）。现在我们希望在流处理中也实现同样的保证，因为确保我们正在处理的数据流不丢失可能至关重要。

可以设置一个基于 HDFS 的检查点目录来存储基于 Apache Spark 的流处理信息。在这个 Scala 示例中，数据将存储在 HDFS 下的`/data/spark/checkpoint`。以下 HDFS 文件系统`ls`命令显示，在开始之前，该目录不存在：

```scala
[hadoop@hc2nn stream]$ hdfs dfs -ls /data/spark/checkpoint
 ls: `/data/spark/checkpoint': No such file or directory
```

为了复制以下示例，我们使用 Twitter API 凭证来连接到 Twitter API 并获取推文流。以下链接解释了如何在 Twitter UI 中创建此类凭证：[`dev.twitter.com/oauth/overview/application-owner-access-tokens`](https://dev.twitter.com/oauth/overview/application-owner-access-tokens)。

以下 Scala 代码示例首先导入 Spark 流处理上下文和基于 Twitter 的功能。然后定义了一个名为`stream1`的应用程序对象：

```scala
import org.apache.spark._
import org.apache.spark.SparkContext._
import org.apache.spark.streaming._
import org.apache.spark.streaming.twitter._
import org.apache.spark.streaming.StreamingContext._

object stream1 {
```

接下来，定义了一个名为 `createContext` 的方法，该方法将用于创建 Spark 和 Streaming 上下文。它还将使用流上下文检查点方法将流检查点到基于 HDFS 的目录，该方法接受目录路径作为参数。目录路径是传递给 `createContext` 方法的值 `(cpDir)`：

```scala
def createContext( cpDir : String ) : StreamingContext = {
  val appName = "Stream example 1"
  val conf    = new SparkConf()
  conf.setAppName(appName)
  val sc = new SparkContext(conf)
  val ssc    = new StreamingContext(sc, Seconds(5) )
  ssc.checkpoint( cpDir )
  ssc
}
```

现在，定义了主方法以及 HDFS 目录、Twitter 访问权限和参数。Spark Streaming 上下文 `ssc` 通过 `StreamingContext` 方法的 `checkpoint` 使用 HDFS 检查点目录检索或创建。如果目录不存在，则调用之前的方法 `createContext`，该方法将创建上下文和 `checkpoint`。显然，出于安全原因，我们在这个例子中截断了自己的 Twitter `auth.keys`：

```scala
def main(args: Array[String]) {
  val hdfsDir = "/data/spark/checkpoint"
  val consumerKey       = "QQpxx"
  val consumerSecret    = "0HFzxx"
  val accessToken       = "323xx"
  val accessTokenSecret = "IlQxx"

  System.setProperty("twitter4j.oauth.consumerKey", consumerKey)
  System.setProperty("twitter4j.oauth.consumerSecret", consumerSecret)
  System.setProperty("twitter4j.oauth.accessToken", accessToken)
  System.setProperty("twitter4j.oauth.accessTokenSecret", accessTokenSecret)
  val ssc = StreamingContext.getOrCreate(hdfsDir,
        () => { createContext( hdfsDir ) })
  val stream = TwitterUtils.createStream(ssc,None).window(  Seconds(60) )
  // do some processing
  ssc.start()
  ssc.awaitTermination()
} // end main
```

运行此代码后，由于没有实际处理，可以再次检查 HDFS `checkpoint` 目录。这次，很明显 `checkpoint` 目录已被创建，数据已被存储：

```scala
 [hadoop@hc2nn stream]$ hdfs dfs -ls /data/spark/checkpoint
 Found 1 items
 drwxr-xr-x   - hadoop supergroup          0 2015-07-02 13:41  /data/spark/checkpoint/0fc3d94e-6f53-40fb-910d-1eef044b12e9
```

本例取自 Apache Spark 官网，展示了如何设置和使用检查点存储。检查点执行的频率是多少？元数据在每个流批次期间存储。实际数据存储在一个周期内，该周期是批次间隔或十秒的最大值。这可能不适合您，因此您可以使用以下方法重置该值：

```scala
 DStream.checkpoint( newRequiredInterval )
```

这里，`newRequiredInterval` 是您需要的新检查点间隔值；通常，您应该瞄准一个值，该值是您的批次间隔的五到十倍。检查点保存了流批次和元数据（关于数据的数据）。

如果应用程序失败，那么当它重新启动时，在处理开始时使用检查点数据。在失败时正在处理的数据批次与自失败以来的批处理数据一起重新处理。请记住监控用于检查点的 HDFS 磁盘空间。

在下一节中，我们将检查流源并提供每种类型的示例。

# 流源

在本节中，我们无法涵盖所有流类型的实际示例，但当本章太小而无法包含代码时，我们将至少提供描述。在本章中，我们将介绍 TCP 和文件流以及 Flume、Kafka 和 Twitter 流。Apache Spark 通常只支持这个有限的集合开箱即用，但这不是问题，因为第三方开发者也提供了连接到其他源的连接器。我们将从一个基于 TCP 的实际示例开始。本章检查流处理架构。

例如，在流数据交付速率超过潜在数据处理速率的情况下会发生什么？像 Kafka 这样的系统提供了可能解决这个问题的可能性...

# TCP 流

有可能使用 Spark Streaming Context 的`socketTextStream`方法通过 TCP/IP 流式传输数据，只需指定主机名和端口号。本节中的基于 Scala 的代码示例将在端口`10777`接收数据，这些数据是通过`netcat`Linux 命令提供的。

`netcat`命令是一个 Linux/Unix 命令，它允许你使用 TCP 或 UDP 向本地或远程 IP 目的地发送和接收数据。这样，每个 shell 脚本都可以充当完整的网络客户端或服务器。以下是一个关于如何使用`netcat`的良好教程：[`www.binarytides.com/netcat-tutorial-for-beginners/`](http://www.binarytides.com/netcat-tutorial-for-beginners/)。

代码示例首先导入了 Spark、上下文以及流处理类。定义了一个名为`stream2`的对象类，它是带有参数的主方法。

```scala
import org.apache.spark._
import org.apache.spark.SparkContext._
import org.apache.spark.streaming._
import org.apache.spark.streaming.StreamingContext._

object stream2 {
  def main(args: Array[String]) {
```

检查传递给类的参数数量，以确保它是主机名和端口号。创建了一个带有定义的应用程序名称的 Spark 配置对象。然后创建了 Spark 和流处理上下文。接着，设置了`10`秒的流处理批次时间：

```scala
if ( args.length < 2 ) {
 System.err.println("Usage: stream2 <host> <port>")
 System.exit(1)
}

val hostname = args(0).trim
val portnum  = args(1).toInt
val appName  = "Stream example 2"
val conf     = new SparkConf()
conf.setAppName(appName)
val sc  = new SparkContext(conf)
val ssc = new StreamingContext(sc, Seconds(10) )
```

通过使用`hostname`和端口名参数调用流处理上下文的`socketTextStream`方法，创建了一个名为`rawDstream`的 DStream：

```scala
val rawDstream = ssc.socketTextStream( hostname, portnum )
```

通过用空格分割单词，从原始流数据中创建了一个前十单词计数。然后，创建了一个(key, value)对，即(word,1)，它按键值，即单词进行缩减。现在，有一个单词列表及其关联的计数。键和值被交换，使得列表变为(计数和单词)。然后，对键（现在是计数）进行排序。最后，从 DStream 中的 RDD 中取出前 10 项并打印出来：

```scala
val wordCount = rawDstream
  .flatMap(line => line.split(" "))
  .map(word => (word,1))
  .reduceByKey(_+_)
  .map(item => item.swap)
  .transform(rdd => rdd.sortByKey(false))
  .foreachRDD( rdd =>
    { rdd.take(10).foreach(x=>println("List : " + x)) }
  )
```

代码以调用 Spark Streaming 的`start`和`awaitTermination`方法结束，以启动流处理并等待进程终止：

```scala
    ssc.start()
      ssc.awaitTermination()
  } // end main
} // end stream2
```

正如我们之前所述，此应用程序的数据由 Linux Netcat (`nc`)命令提供。Linux `cat`命令转储日志文件的内容，该内容被管道传输到`nc`。`lk`选项强制 Netcat 监听连接，并在连接丢失时保持监听。此示例显示正在使用的端口是`10777`：

```scala
 [root@hc2nn log]# pwd
 /var/log
 [root@hc2nn log]# cat ./anaconda.storage.log | nc -lk 10777
```

这里展示了基于 TCP 的流处理的输出。实际输出不如所展示的方法重要。然而，数据显示，正如预期的那样，是一份按降序计数的 10 个日志文件单词列表。请注意，顶部单词为空，因为流未被过滤以排除空单词：

```scala
 List : (17104,)
 List : (2333,=)
 List : (1656,:)
 List : (1603,;)
 List : (1557,DEBUG)
 List : (564,True)
 List : (495,False)
 List : (411,None)
 List : (356,at)
 List : (335,object)
```

如果你想基于 TCP/IP 从主机和端口使用 Apache Spark Streaming 进行数据流处理，这会很有趣。但是，更奇特的方法呢？如果你想从消息系统或通过基于内存的通道流式传输数据怎么办？如果你想使用当今可用的一些大数据工具，如 Flume 和 Kafka，该怎么办？接下来的部分将探讨这些选项，但首先，我们将展示如何基于文件构建流。

# 文件流

我们已修改上一节中的基于 Scala 的代码示例，通过调用 Spark Streaming 上下文的`textFileStream`方法来监控基于 HDFS 的目录。鉴于这一小改动，我们将不展示所有代码。应用程序类现在称为`stream3`，它接受一个参数——HDFS 目录。目录路径也可以位于另一个存储系统上（所有代码示例都将随本书提供）：

```scala
val rawDstream = ssc.textFileStream( directory )
```

流处理与之前相同。流被分割成单词，并打印出前十个单词列表。这次唯一的区别是，数据必须在应用程序运行时放入 HDFS 目录。这是通过...实现的

# Flume

**Flume** 是一个 Apache 开源项目及产品，旨在以大数据规模移动大量数据。它具有高度可扩展性、分布式和可靠性，基于数据源、数据接收器和数据通道运作，如下图所示，取自[`flume.apache.org/`](http://flume.apache.org/)：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/3dc8cd75-e72b-41ac-9c65-67f383d60539.png)

Flume 使用代理处理数据流。如前图所示，一个代理具有数据源、数据处理通道和数据接收器。更清晰地描述此流程的方法是通过我们刚才看到的图。通道充当源数据的队列，接收器将数据传递到链中的下一个环节。

Flume 代理可以构成 Flume 架构；一个代理的接收器输出可以作为第二个代理的输入。Apache Spark 支持两种使用 Apache Flume 的方法。第一种是基于 Avro 的内存推送方法，而第二种方法，同样基于 Avro，是使用自定义 Spark 接收器库的拉取系统。本例中我们使用 Flume 版本 1.5：

```scala
[root@hc2nn ~]# flume-ng version
Flume 1.5.0-cdh5.3.3
Source code repository: https://git-wip-us.apache.org/repos/asf/flume.git
Revision: b88ce1fd016bc873d817343779dfff6aeea07706
Compiled by jenkins on Wed Apr  8 14:57:43 PDT 2015
From source with checksum 389d91c718e03341a2367bf4ef12428e
```

我们在此初步实现的基于 Flume 的 Spark 示例是基于 Flume 的推送方法，其中 Spark 充当接收器，Flume 将数据推送到 Spark。下图表示我们将在单个节点上实现的结构：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/1a77c7f0-9d03-4ca9-9a72-db41aa75affb.png)

消息数据将被发送到名为`hc2r1m1`的主机的`10777`端口，使用 Linux 的`netcat`（`nc`）命令。这将作为 Flume 代理（`agent1`）的一个源（`source1`），该代理将有一个名为`channel1`的内存通道。`agent1`使用的接收器将是基于 Apache Avro 的，同样在名为`hc2r1m1`的主机上，但这次端口号将是`11777`。Apache Spark Flume 应用程序`stream4`（我们稍后将描述）将监听此端口上的 Flume 流数据。

我们通过向`10777`端口执行`nc`命令来启动流处理。现在，当我们在该窗口中输入文本时，它将作为 Flume 源，数据将被发送到 Spark 应用程序：

```scala
[hadoop@hc2nn ~]$ nc  hc2r1m1.semtech-solutions.co.nz  10777
```

为了运行 Flume 代理`agent1`，我们创建了一个名为`agent1.flume.cfg`的 Flume 配置文件，该文件描述了代理的源、通道和接收器。文件内容如下。第一部分定义了`agent1`的源、通道和接收器名称。

```scala
agent1.sources  = source1
agent1.channels = channel1
agent1.sinks    = sink1
```

下一部分定义`source1`为基于 netcat，运行在名为`hc2r1m1`的主机上和`10777`端口：

```scala
agent1.sources.source1.channels=channel1
agent1.sources.source1.type=netcat
agent1.sources.source1.bind=hc2r1m1.semtech-solutions.co.nz
agent1.sources.source1.port=10777
```

`agent1`通道`channel1`被定义为具有最大事件容量`1000`事件的内存通道：

```scala
agent1.channels.channel1.type=memory
agent1.channels.channel1.capacity=1000
```

最后，`agent1`接收器`sink1`被定义为在名为`hc2r1m1`的主机上和`11777`端口的 Apache Avro 接收器：

```scala
agent1.sinks.sink1.type=avro
agent1.sinks.sink1.hostname=hc2r1m1.semtech-solutions.co.nz
agent1.sinks.sink1.port=11777 agent1.sinks.sink1.channel=channel1
```

我们创建了一个名为`flume.bash`的 Bash 脚本来运行 Flume 代理`agent1`。它如下所示：

```scala
[hadoop@hc2r1m1 stream]$ more flume.bash #!/bin/bash # run the bash agent flume-ng agent \
 --conf /etc/flume-ng/conf \
 --conf-file ./agent1.flume.cfg \
 -Dflume.root.logger=DEBUG,INFO,console  \
 -name agent1
```

该脚本调用 Flume 可执行文件`flume-ng`，传递`agent1`配置文件。调用指定了名为`agent1`的代理。它还指定了 Flume 配置目录为`/etc/flume-ng/conf/`，这是默认值。最初，我们将使用一个基于 Scala 的示例，该示例使用`netcat` Flume 源来展示如何将数据发送到 Apache Spark 应用程序。然后，我们将展示如何以类似方式处理基于 RSS 的数据源。因此，最初接收`netcat`数据的 Scala 代码看起来是这样的。应用程序类名被定义。导入 Spark 和 Flume 所需的类。最后，定义了主方法：

```scala
import org.apache.spark._
import org.apache.spark.SparkContext._
import org.apache.spark.streaming._
import org.apache.spark.streaming.StreamingContext._
import org.apache.spark.streaming.flume._

object stream4 {
  def main(args: Array[String]) {
  //The host and port name arguments for the data stream are checked and extracted:
      if ( args.length < 2 ) {
        System.err.println("Usage: stream4 <host> <port>")
        System.exit(1)
      }
      val hostname = args(0).trim
      val portnum  = args(1).toInt
      println("hostname : " + hostname)
      println("portnum  : " + portnum)
```

Spark 和 Streaming 上下文被创建。然后，使用流上下文主机和端口号创建基于 Flume 的数据流。为此，使用了基于 Flume 的类`FlumeUtils`，通过调用其`createStream`方法来实现：

```scala
val appName = "Stream example 4"
val conf    = new SparkConf()
conf.setAppName(appName)
val sc  = new SparkContext(conf)
val ssc = new StreamingContext(sc, Seconds(10) )
val rawDstream = FlumeUtils.createStream(ssc,hostname,portnum)
```

最终，会打印出流事件计数，并且在测试流时（出于调试目的）会转储流内容。之后，流上下文被启动并配置为运行，直到通过应用程序终止：

```scala
    rawDstream.count()
           .map(cnt => ">>>> Received events : " + cnt )
           .print()
    rawDstream.map(e => new String(e.event.getBody.array() ))
           .print
    ssc.start()
    ssc.awaitTermination()
  } // end main
} // end stream4
```

编译完成后，我们将使用`spark-submit`运行此应用程序。在本书的其他一些章节中，我们将使用一个名为`run_stream.bash`的基于 Bash 的脚本来执行任务。该脚本如下所示：

```scala
[hadoop@hc2r1m1 stream]$ more run_stream.bash #!/bin/bash SPARK_HOME=/usr/local/spark
SPARK_BIN=$SPARK_HOME/bin
SPARK_SBIN=$SPARK_HOME/sbin JAR_PATH=/home/hadoop/spark/stream/target/scala-2.10/streaming_2.10-1.0.jar
CLASS_VAL=$1
CLASS_PARAMS="${*:2}" STREAM_JAR=/usr/local/spark/lib/spark-examples-1.3.1-hadoop2.3.0.jar cd $SPARK_BIN ./spark-submit \
 --class $CLASS_VAL \
 --master spark://hc2nn.semtech-solutions.co.nz:7077  \
 --executor-memory 100M \
 --total-executor-cores 50 \
 --jars $STREAM_JAR \
 $JAR_PATH \
 $CLASS_PARAMS
```

因此，此脚本设置了一些基于 Spark 的变量和一个 JAR 库路径用于此作业。它将 Spark 类作为第一个参数运行。它将所有其他变量作为参数传递给 Spark 应用程序类作业。因此，应用程序的执行如下所示：

```scala
[hadoop@hc2r1m1 stream]$ ./run_stream.bash stream4 hc2r1m1 11777
```

这意味着 Spark 应用程序已准备好，并在端口`11777`上作为 Flume 接收器运行。Flume 输入已准备好，作为端口`10777`上的`netcat`任务运行。现在，Flume 代理`agent1`可以使用名为`flume.bash`的 Flume 脚本启动，以将基于`netcat`源的数据发送到 Apache Spark 基于 Flume 的接收器：

```scala
 [hadoop@hc2r1m1 stream]$ ./flume.bash
```

现在，当文本传递给`netcat`会话时，它应该通过 Flume 流动，并由 Spark 作为流处理。让我们试试：

```scala
[hadoop@hc2nn ~]$ nc  hc2r1m1.semtech-solutions.co.nz 10777
 I hope that Apache Spark will print this
 OK
 I hope that Apache Spark will print this
 OK
 I hope that Apache Spark will print this
 OK
```

已向`netcat`会话添加了三个简单的文本片段，并使用`OK`进行了确认，以便它们可以传递给 Flume。Flume 会话中的调试输出显示已收到并处理了事件（每行一个）：

```scala
2015-07-06 18:13:18,699 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:318)] Chars read = 41
 2015-07-06 18:13:18,700 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:322)] Events processed = 1
 2015-07-06 18:13:18,990 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:318)] Chars read = 41
 2015-07-06 18:13:18,991 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:322)] Events processed = 1
 2015-07-06 18:13:19,270 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:318)] Chars read = 41
 2015-07-06 18:13:19,271 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:322)] Events processed = 1
```

最后，在 Spark `stream4`应用程序会话中，已收到并处理了三个事件；在这种情况下，它们已被转储到会话中，以证明数据已到达。当然，这不是您通常会做的，但我们想证明数据通过此配置传输：

```scala
-------------------------------------------
 Time: 1436163210000 ms
 -------------------------------------------
 >>> Received events : 3
 -------------------------------------------
 Time: 1436163210000 ms
 -------------------------------------------
 I hope that Apache Spark will print this
 I hope that Apache Spark will print this
 I hope that Apache Spark will print this
```

这很有趣，但它并不是真正值得生产的 Spark Flume 数据处理示例。因此，为了演示一种可能的实际数据处理方法，我们将更改 Flume 配置文件源详细信息，使其使用一个 Perl 脚本，该脚本可执行如下：

```scala
agent1.sources.source1.type=exec
agent1.sources.source.command=./rss.perl
```

先前引用的 Perl 脚本`rss.perl`仅作为路透社科学新闻的来源。它接收 XML 格式的消息并将其转换为 JSON 格式。它还清理了数据中的不必要噪音。首先，它导入 LWP 和`XML::XPath`等包以启用 XML 处理。然后，它指定基于科学的 Reuters 新闻数据源，并创建一个新的 LWP 代理来处理数据，如下所示：

```scala
#!/usr/bin/perl
use strict;
use LWP::UserAgent;
use XML::XPath;
my $urlsource="http://feeds.reuters.com/reuters/scienceNews" ;
my  $agent = LWP::UserAgent->new;
#Then an infinite while loop is opened, and an HTTP GET request is carried out against  the URL. The request is configured, and the agent makes the request via  a call to the request method:
while()
{
  my  $req = HTTP::Request->new(GET => ($urlsource));
  $req->header('content-type' => 'application/json');
  $req->header('Accept'       => 'application/json');
  my $resp = $agent->request($req);
```

如果请求成功，则返回的 XML 数据定义为请求的解码内容。通过使用路径`/rss/channel/item/title`的 XPath 调用从 XML 中提取标题信息：

```scala
    if ( $resp->is_success )
    {
      my $xmlpage = $resp -> decoded_content;
      my $xp = XML::XPath->new( xml => $xmlpage );
      my $nodeset = $xp->find( '/rss/channel/item/title' );
      my @titles = () ;
      my $index = 0 ;
```

对于提取的标题数据`XML`字符串中的每个节点，都会提取数据。它清除了不需要的`XML`标签，并添加到名为 titles 的基于 Perl 的数组中：

```scala
     foreach my $node ($nodeset->get_nodelist) {
        my $xmlstring = XML::XPath::XMLParser::as_string($node) ;
        $xmlstring =~ s/<title>//g;
        $xmlstring =~ s/<\/title>//g;
        $xmlstring =~ s/"//g;
        $xmlstring =~ s/,//g;
        $titles[$index] = $xmlstring ;
        $index = $index + 1 ;
      } # foreach find node
```

对于请求响应 XML 中的基于描述的数据，执行相同的处理。这次使用的 XPath 值是`/rss/channel/item/description/`。描述数据中有许多更多的标签需要清理，因此有许多更多的 Perl 搜索和行替换作用于该数据（`s///g`）：

```scala
    my $nodeset = $xp->find( '/rss/channel/item/description' );
    my @desc = () ;
    $index = 0 ;
    foreach my $node ($nodeset->get_nodelist) {
       my $xmlstring = XML::XPath::XMLParser::as_string($node) ;
       $xmlstring =~ s/<img.+\/img>//g;
       $xmlstring =~ s/href=".+"//g;
       $xmlstring =~ s/src="img/.+"//g;
       $xmlstring =~ s/src='.+'//g;
       $xmlstring =~ s/<br.+\/>//g;
       $xmlstring =~ s/<\/div>//g;
       $xmlstring =~ s/<\/a>//g;
       $xmlstring =~ s/<a >\n//g;
       $xmlstring =~ s/<img >//g;
       $xmlstring =~ s/<img \/>//g;
       $xmlstring =~ s/<div.+>//g;
       $xmlstring =~ s/<title>//g;
       $xmlstring =~ s/<\/title>//g;
       $xmlstring =~ s/<description>//g;
       $xmlstring =~ s/<\/description>//g;
       $xmlstring =~ s/&lt;.+>//g;
       $xmlstring =~ s/"//g;
       $xmlstring =~ s/,//g;
       $xmlstring =~ s/\r|\n//g;
       $desc[$index] = $xmlstring ;
       $index = $index + 1 ;
    } # foreach find node
```

最后，基于 XML 的标题和描述数据使用`print`命令以 RSS JSON 格式输出。然后脚本休眠 30 秒，并请求更多 RSS 新闻信息进行处理：

```scala
   my $newsitems = $index ;
   $index = 0 ;
   for ($index=0; $index < $newsitems; $index++) {
      print "{"category": "science","
              . " "title": "" .  $titles[$index] . "","
              . " "summary": "" .  $desc[$index] . """
               . "}\n";
      } # for rss items
    } # success ?
    sleep(30) ;
 } # while
```

我们创建了第二个基于 Scala 的流处理代码示例，名为 `stream5`。它类似于 `stream4` 示例，但现在它处理来自流中的 `rss` 项数据。接下来，定义 `case class` 以处理来自 XML RSS 信息的类别、标题和摘要。定义了一个 HTML 位置来存储从 Flume 通道传来的结果数据。

```scala
case class RSSItem(category : String, title : String, summary : String) {
  val now: Long = System.currentTimeMillis
  val hdfsdir = "hdfs://hc2nn:8020/data/spark/flume/rss/"
```

来自基于 Flume 事件的 RSS 流数据被转换为字符串，然后使用名为 `RSSItem` 的 case 类进行格式化。如果有事件数据，则使用之前的 `hdfsdir` 路径将其写入 HDFS 目录。

```scala
         rawDstream.map(record => {
         implicit val formats = DefaultFormats
         readRSSItem.array()))
      }).foreachRDD(rdd => {
              if (rdd.count() > 0) {
                rdd.map(item => {
                  implicit val formats = DefaultFormats
                  write(item)
                 }).saveAsTextFile(hdfsdir+"file_"+now.toString())
               }
      })
```

运行此代码示例，可以观察到 Perl RSS 脚本正在生成数据，因为 Flume 脚本的输出表明已接受并接收了 80 个事件。

```scala
2015-07-07 14:14:24,017 (agent-shutdown-hook) [DEBUG - org.apache.flume.source.ExecSource.stop(ExecSource.java:219)] Exec source with command:./news_rss_collector.py stopped. Metrics:SOURCE:source1{src.events.accepted=80, src.events.received=80, src.append.accepted=0, src.append-batch.accepted=0, src.open-connection.count=0, src.append-batch.received=0, src.append.received=0}
The Scala Spark application stream5 has processed 80 events in two batches:
>>>> Received events : 73
>>>> Received events : 7
```

事件已存储在 HDFS 下的预期目录中，正如 Hadoop 文件系统 `ls` 命令所示：

```scala
[hadoop@hc2r1m1 stream]$ hdfs dfs -ls /data/spark/flume/rss/
 Found 2 items
 drwxr-xr-x   - hadoop supergroup          0 2015-07-07 14:09 /data/spark/flume/rss/file_1436234439794
 drwxr-xr-x   - hadoop supergroup          0 2015-07-07 14:14 /data/spark/flume/rss/file_1436235208370
```

此外，使用 Hadoop 文件系统 `cat` 命令，可以证明 HDFS 上的文件包含基于 `rss` 订阅源的新闻数据，如下所示：

```scala
[hadoop@hc2r1m1 stream]$  hdfs dfs -cat /data/spark/flume/rss/file_1436235208370/part-00000 | head -1 {"category":"healthcare","title":"BRIEF-Aetna CEO says has not had specific conversations with DOJ on Humana - CNBC","summary":"* Aetna CEO Says Has Not Had Specific Conversations With Doj About Humana Acquisition - CNBC"}
```

此基于 Spark 流的示例使用了 Apache Flume 将数据从 `rss` 源传输，经过 Flume，通过 Spark 消费者到达 HDFS。这是一个很好的示例，但如果你想向一组消费者发布数据呢？在下一节中，我们将探讨 Apache Kafka——一个发布/订阅消息系统——并确定如何将其与 Spark 结合使用。

# Kafka

Apache Kafka ([`kafka.apache.org/`](http://kafka.apache.org/)) 是 Apache 基金会下的一个顶级开源项目。它是一个快速且高度可扩展的大数据发布/订阅消息系统，利用消息代理进行数据管理，并通过 ZooKeeper 进行配置，以便数据可以组织成消费者组和主题。

Kafka 中的数据被分割成多个分区。在本例中，我们将展示一个基于 Spark 的无接收器 Kafka 消费者，这样我们就不需要在比较 Kafka 数据时担心配置 Spark 数据分区。为了演示基于 Kafka 的消息生产和消费，我们将使用上一节中的 Perl RSS 脚本作为数据源。传递到 Kafka 并到 Spark 的数据将是路透社 RSS 新闻...

# 总结

我们本可以为其他系统提供流式示例，但本章没有空间。Twitter 流式传输已在 *检查点* 部分通过示例进行了探讨。本章提供了通过 Spark Streaming 中的检查点进行数据恢复的实用示例。它还触及了检查点的性能限制，并表明检查点间隔应设置为 Spark 流批处理间隔的五到十倍。

检查点提供了一种基于流的恢复机制，用于在 Spark 应用程序失败时进行恢复。本章提供了一些基于 TCP、文件、Flume 和 Kafka 的 Spark 流编码的流式工作示例。这里所有的示例都是基于 Scala 并用`sbt`编译的。如果你更熟悉**Maven**，以下教程将解释如何设置基于 Maven 的 Scala 项目：[`www.scala-lang.org/old/node/345`](http://www.scala-lang.org/old/node/345)。


# 第三章：结构化流处理

正如你可能已经从前几章理解的那样，Apache Spark 目前正从基于 RDD 的数据处理过渡到更结构化的处理，背后有 DataFrames 和 Datasets 支持，以便让 Catalyst 和 Tungsten 发挥作用，进行性能优化。这意味着社区目前采用双轨制。虽然非结构化 API 仍然得到支持——它们甚至还没有被标记为已弃用，而且它们是否会这样做也值得怀疑——但在 Apache Spark V 2.0 中为各种组件引入了一套新的结构化 API，这也适用于 Spark Streaming。Structured Steaming 在 Apache Spark V 2.2 中被标记为稳定。请注意，截至 Apache Spark V 2.1 时...

# 连续应用的概念

流应用程序往往变得复杂。流计算不是孤立运行的；它们与存储系统、批处理应用程序和机器学习库交互。因此，与批处理相对的连续应用的概念应运而生，基本上意味着批处理和实时流处理的组合，其中流处理部分是应用程序的主要驱动力，并且仅访问由批处理过程创建或处理的数据以进行进一步增强。连续应用程序永不停止，并且随着新数据的到达而持续产生数据。

# 真正的统一 - 相同的代码，相同的引擎

因此，一个连续的应用程序也可以基于 RDD 和 DStreams 实现，但需要使用两种不同的 API。在 Apache Spark Structured Streaming 中，API 得到了统一。这种统一是通过将结构化流视为一张无边界的关系表来实现的，其中新数据不断追加到表的底部。在批处理中使用关系 API 或 SQL 处理 DataFrames 时，会创建中间 DataFrames。由于流和批处理在 Apache SparkSQL 引擎上得到了统一，当处理结构化流时，会创建无边界的中间关系表。

重要的是要注意，可以混合（连接）静态和增量...

# 窗口化

开源和商业流处理引擎，如 IBM Streams、Apache Storm 或 Apache Flink，都在使用窗口的概念。

Windows 指定了粒度或后续记录的数量，这些记录在执行流上的聚合函数时会被考虑。

# 流处理引擎如何使用窗口化

存在五个不同的属性，分为两个维度，这就是窗口如何被定义的方式，其中每个窗口定义都需要使用每个维度的一个属性。

第一个属性是连续流中元组的后续窗口可以创建的模式：滑动和翻滚。

第二个是必须指定落入窗口的元组数量：基于计数、基于时间或基于会话。

让我们来看看它们的含义：

+   **滑动窗口**：每当有新元组符合条件被纳入时，滑动窗口就会移除一个元组。

+   **翻滚窗口**：每当有足够多的元组到达以创建新窗口时，翻滚窗口就会移除所有元组。

+   **基于计数的...**

# Apache Spark 如何优化窗口操作

Apache Spark 结构化流在窗口处理模型中展现出显著的灵活性。由于流被视为持续追加的表，且表中每行都带有时间戳，窗口操作可以在查询中直接指定，每个查询可以定义不同的窗口。此外，如果静态数据中存在时间戳，窗口操作也可以定义，从而形成一个非常灵活的流处理模型。

换言之，Apache Spark 的窗口操作本质上是对时间戳列的一种特殊分组。这使得处理迟到数据变得非常简单，因为 Apache Spark 可以将迟到数据纳入适当的窗口，并在特定数据项迟到时重新计算该窗口。此功能高度可配置。

**事件时间与处理时间对比**：在时间序列分析中，尤其是在流计算中，每个记录都会被分配一个特定的时戳。一种创建这种时戳的方法是记录到达流处理引擎的时间。然而，这往往并非所需。通常，我们希望为每个记录分配一个事件时间，即该记录创建时的特定时间点，例如，当物联网设备进行测量时。这有助于处理事件创建与处理之间的延迟，例如，当物联网传感器离线一段时间，或网络拥堵导致数据交付延迟时。

在使用事件时间而非处理时间为每个元组分配唯一时戳时，迟到数据的概念颇具趣味。事件时间是指特定测量发生的时间戳。Apache Spark 结构化流能够自动透明地处理在稍后时间点到达的数据子集。

**迟到数据**：无论记录何时到达任何流引擎，都会立即处理。在此方面，Apache Spark 流处理与其他引擎并无二致。然而，Apache Spark 具备在任何时间确定特定元组所属窗口的能力。如果由于任何原因元组迟到，所有受影响的窗口将被更新，基于这些更新窗口的所有受影响聚合操作将重新运行。这意味着，如果迟到数据到达，结果允许随时间变化，而无需程序员为此担忧。最后，自 Apache Spark V2.1 起，可以使用`withWatermark`方法指定系统接受迟到数据的时间量。

水印基本上是阈值，用于定义延迟到达的数据点允许有多旧，以便仍能被包含在相应的窗口中。再次考虑 HTTP 服务器日志文件在超过一分钟长度的窗口上工作。如果，由于任何原因，一个数据元组到达，它超过 4 小时旧，如果这个应用程序用于创建基于小时的时间序列预测模型来为集群提供或取消提供额外的 HTTP 服务器，那么它可能没有意义将其包含在窗口中。一个四小时前的数据点就没有意义处理，即使它可能改变决策，因为决策已经做出。

# 与老朋友一起提升性能

正如在 Apache SparkSQL 中用于批处理，以及作为 Apache Spark 结构化流的一部分，Catalyst Planner 也为微批创建增量执行计划。这意味着整个流模型基于批处理。这也是为什么能够实现流处理和批处理的统一 API 的原因。我们付出的代价是，Apache Spark 流处理在面对极低延迟要求（亚秒级，在几十毫秒范围内）时有时会有缺点。正如结构化流和使用 DataFrame 及 Dataset 所暗示的，我们也因 Tungsten 项目带来的性能提升而受益，该项目在之前的...

# 如何实现透明的容错和精确一次投递保证

Apache Spark 结构化流支持完全崩溃容错和精确一次投递保证，而无需用户处理任何特定的错误处理例程。这不是很神奇吗？那么这是如何实现的呢？

完全崩溃容错和精确一次投递保证是系统理论中的术语。完全崩溃容错意味着你可以在任何时间点拔掉整个数据中心的电源，而不会丢失任何数据或留下不一致的状态。精确一次投递保证意味着，即使拔掉同一个电源插头，也能确保每个元组——从数据源到数据汇——仅且仅一次被投递。既不是零次，也不会超过一次。当然，这些概念也必须在一个节点失败或行为异常（例如开始限流）的情况下成立。

首先，各个批次和偏移量范围（源流中的位置）之间的状态保持在内存中，但由**预写日志**（**WAL**）在如 HDFS 这样的容错文件系统中支持。WAL 基本上是一个日志文件，以主动的方式反映整个流处理状态。这意味着在数据通过操作符转换之前，它首先以一种可以在崩溃后恢复的方式持久存储在 WAL 中。因此，换句话说，在处理单个迷你批次期间，工作者内存的区域以及流源的偏移位置都被持久化到磁盘。如果系统失败并需要恢复，它可以重新请求源中的数据块。当然，这只在源支持这种语义的情况下才可能。

# 可重放源可以从给定的偏移量重放流

端到端的一次性交付保证要求流源支持在请求位置进行某种流重放。这对于文件源和 Apache Kafka 等是正确的，例如，以及本章中示例将基于的 IBM Watson 物联网平台。

# 幂等接收器防止数据重复

端到端一次性交付保证的另一个关键是幂等接收器。这基本上意味着接收器知道过去哪些特定的写操作已经成功。这意味着这样的智能接收器可以在失败时重新请求数据，并在相同数据被发送多次时丢弃数据。

# 状态版本化确保重跑后结果一致

那么状态呢？设想一个机器学习算法在所有工作者上维护一个计数变量。如果你将完全相同的数据重放两次，你最终会多次计数这些数据。因此，查询计划器也在工作者内部维护一个版本化的键值映射，这些工作者依次将其状态持久化到 HDFS——这是设计上的容错机制。

因此，在发生故障时，如果数据需要被替换，计划器确保工作者使用正确的键值映射版本。

# 示例 - 连接到 MQTT 消息代理

那么，让我们从一个示例用例开始。让我们连接到一个**物联网**（**IoT**）传感器数据流。由于我们到目前为止还没有涉及机器学习，我们不分析数据，我们只是展示概念。

我们使用 IBM Watson 物联网平台作为流数据源。在其核心，Watson 物联网平台由**MQTT**（**消息队列遥测传输**）消息代理支持。MQTT 是 IBM 于 1999 年发明的一种轻量级遥测协议，并于 2013 年成为**OASIS**（**结构化信息标准促进组织**，一个全球非营利性联盟，致力于安全、物联网、能源、内容技术、应急管理等领域的标准开发、融合和采纳）的标准——物联网数据集成的实际标准。

应用程序间的消息传递可以由消息队列支持，这是一种支持各种交付模式的异步点对点通道的中间件系统，如**先进先出**（**FIFO**）、**后进先出**（**LIFO**）或**优先级队列**（其中每条消息可以根据特定标准重新排序）。

这已经是一个非常棒的功能，但仍然以某种方式耦合了应用程序，因为一旦消息被读取，它就对其他应用程序不可用了。

这种 N 对 N 通信实现起来较为困难（但并非不可能）。在发布/订阅模型中，应用程序完全解耦。不再存在任何队列，而是引入了主题的概念。数据提供者在特定主题上发布消息，而数据消费者则订阅这些主题。这样一来，N 对 N 通信的实现就变得非常直接，因为它反映了底层的消息传递模型。这种中间件被称为消息代理，与消息队列相对。

由于云服务不断变化，且本书稍后才会介绍云，以下教程解释了如何在云中设置测试数据生成器并连接到远程 MQTT 消息代理。在本例中，我们将使用 IBM Watson IoT 平台，这是一个在云中可用的 MQTT 消息代理。或者，也可以安装开源消息代理如 MOSQUITTO，它还提供了一个公开可用的测试安装，网址如下：[`test.mosquitto.org/`](http://test.mosquitto.org/)。

为了复现示例，以下步骤（1）和（2）是必要的，如以下教程所述：[`www.ibm.com/developerworks/library/iot-cognitive-iot-app-machine-learning/index.html`](https://www.ibm.com/developerworks/library/iot-cognitive-iot-app-machine-learning/index.html)。请确保在执行教程时记下`http_host`、`org`、`apiKey`和`apiToken`。这些信息稍后用于通过 Apache Spark 结构化流订阅数据。

由于 IBM Watson 物联网平台采用开放的 MQTT 标准，因此无需特殊的 IBM 组件即可连接到该平台。相反，我们使用 MQTT 和 Apache Bahir 作为 MQTT 与 Apache Spark 结构化流之间的连接器。

Apache Bahir 项目的目标是为包括 Apache Spark 和 Apache Flink 在内的各种数据处理引擎提供一组源和汇连接器，因为它们缺乏这些连接器。在这种情况下，我们将使用 Apache Bahir MQTT 数据源进行 MQTT 通信。

为了使用 Apache Bahir，我们需要向本地 maven 仓库添加两个依赖项。本章下载部分提供了一个完整的`pom.xml`文件。让我们看一下`pom.xml`的依赖部分：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/3408ec51-5ead-4efd-902c-37efc6735a9f.png)

我们基本上是在获取 Apache Bahir 的 MQTT Apache 结构化流适配器以及一个用于低级 MQTT 处理的依赖包。在`pom.xml`文件所在的目录中执行简单的`mvn dependency:resolve`命令，会将所需的依赖项拉取到我们的本地 maven 仓库，在那里它们可以被 Apache Spark 驱动程序访问并自动传输到 Apache Spark 工作节点。

另一种解决依赖关系的方法是在启动 spark-shell（spark-submit 同样适用）时使用以下命令；必要的依赖项会自动分发给工作节点：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/929fb112-1ce2-45d8-a721-ebd6b7db7a15.png)

现在我们需要之前获取的 MQTT 凭证。让我们在这里设置值：

```scala
val mqtt_host = "pcoyha.messaging.internetofthings.ibmcloud.com"
val org = "pcoyha"
val apiKey = "a-pcoyha-oaigc1k8ub"
val apiToken = "&wuypVX2yNgVLAcLr8"
var randomSessionId = scala.util.Random.nextInt(10000)
```

现在我们可以开始创建一个连接到 MQTT 消息代理的流。我们告诉 Apache Spark 使用 Apache Bahir MQTT 流源：

```scala
val df = spark.readStream.format("org.apache.bahir.sql.streaming.mqtt.MQTTStreamSourceProvider")
```

为了从 MQTT 消息代理拉取数据，我们需要指定凭证，如`username`、`password`和`clientId`；前面提到的教程链接解释了如何获取这些凭证：

```scala
    .option("username",apiKey)
    .option("password",apiToken)
    .option("clientId","a:"+org+":"+apiKey)
```

由于我们使用的是发布/订阅消息模型，我们必须提供我们正在订阅的主题——这个主题由您之前部署到云端的测试数据生成器使用：

```scala
.option("topic", "iot-2/type/WashingMachine/id/Washer01/evt/voltage/fmt/json")
```

一旦配置方面一切就绪，我们就必须提供端点主机和端口以创建流：

```scala
   .load("tcp://"+mqtt_host+":1883")
```

有趣的是，正如以下截图所示，这导致了 DataFrame 的创建：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/7303999c-963f-42ee-935a-149985204527.png)

请注意，模式固定为`[String, Timestamp]`，并且在流创建过程中无法更改——这是 Apache Bahir 库的一个限制。然而，使用丰富的 DataFrame API，您可以解析值（例如，JSON 字符串）并创建新列。

如前所述，这是 Apache Spark 结构化流的一个强大功能，因为相同的 DataFrame（和 Dataset）API 现在可以用于处理历史和实时数据。因此，让我们通过将其写入控制台来查看此流的

```scala
val query = df.writeStream.
outputMode("append").
format("console").
start()
```

作为输出模式，我们选择`append`以强制增量显示，并避免历史流的内容被反复写入控制台。作为`格式`，我们指定`console`，因为我们只想调试流上发生的情况：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/7a3c0353-00f4-43e3-92fa-1d3b9e656b7e.png)

最后，`start` 方法启动查询处理，如这里所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/af7770d2-b680-4aaf-b6c3-e7c683163054.png)

# 控制连续应用程序

一旦连续应用程序（即使是简单的，不考虑历史数据）启动并运行，它就必须以某种方式进行控制，因为调用 `start` 方法立即开始处理，但也不会阻塞返回。如果您希望程序在此阶段阻塞，直到应用程序完成，可以使用 `awaitTermination` 方法，如下所示：

```scala
query.awaitTermination()
```

这在预编译代码并使用 `spark-submit` 命令时尤为重要。当使用 `spark-shell` 时，应用程序无论如何都不会终止。

# 更多关于流生命周期管理

流式传输通常用于创建连续应用程序。这意味着该过程在后台运行，与批处理不同，它没有明确的停止时间；因此，由流式源支持的 DataFrames 和 Datasets 支持各种流生命周期管理方法，如下所述：

+   `start`：这启动了连续应用程序。此方法不会阻塞。如果这不是您想要的，请使用 `awaitTermination`。

+   `stop`：这终止了连续应用程序。

+   `awaitTermination`：如前所述，使用 `start` 方法启动流立即返回，这意味着调用不会阻塞。有时您希望等待直到流被终止，无论是由其他人调用 `stop` 还是由于错误。

+   `exception`：如果流因错误而停止，可以使用此方法读取原因。

+   `sourceStatus`：这是为了获取流式源的实时元信息。

+   `sinkStatus`：这是为了获取流式接收器的实时元信息。

Apache Spark 流式传输中的接收器很智能，因为它们支持故障恢复和端到端的一次性交付保证，如前所述。此外，Apache Spark 需要它们支持不同的输出方法。目前，以下三种输出方法 `append`、`update` 和 `complete` 显著改变了底层语义。以下段落包含有关不同输出方法的更多详细信息。

不同的输出模式在接收器上：接收器可以指定以不同方式处理输出。这称为 `outputMode`。最简单的选择是使用增量方法，因为我们无论如何都在处理增量数据流。此模式称为 `append`。然而，存在一些需求，其中已经由接收器处理的数据必须更改。一个例子是特定时间窗口中缺失数据的延迟到达问题，一旦为该特定时间窗口重新计算，就可能导致结果改变。此模式称为 `complete`。

自 Apache Spark 2.1 版本起，引入了`update`模式，其行为类似于`complete`模式，但仅更改已修改的行，从而节省处理资源并提高速度。某些模式不支持所有查询类型。由于这不断变化，最好参考[`spark.apache.org/docs/latest/streaming-programming-guide.html`](http://spark.apache.org/docs/latest/streaming-programming-guide.html)上的最新文档。

# 总结

那么为什么在同一个数据处理框架内会有两种不同的流处理引擎呢？我们希望在阅读本章后，您会认同经典 DStream 引擎的主要痛点已得到解决。以前，基于事件时间的处理是不可能的，只考虑了数据的到达时间。随后，延迟数据仅以错误的时戳进行处理，因为只能使用处理时间。此外，批处理和流处理需要使用两种不同的 API：RDD 和 DStreams。尽管 API 相似，但并不完全相同；因此，在两种范式之间来回切换时重写代码是必要的。最后，端到端的交付保证难以实现...


# 第四章：Apache Spark MLlib

MLlib 是 Apache Spark 附带的原始机器学习库，Apache Spark 是一个基于内存的集群式开源数据处理系统。该库仍然基于 RDD API。在本章中，我们将从回归、分类和神经网络处理等领域来探讨 MLlib 库提供的功能。在提供解决实际问题的示例之前，我们将先探讨每种算法的理论基础。网络上的示例代码和文档可能稀少且令人困惑。

我们将采取逐步的方式来描述以下算法的使用方法及其功能：

+   架构

+   使用朴素贝叶斯进行分类

+   K-Means 聚类

+   使用**人工神经网络**进行图像分类

# 架构

请记住，尽管 Spark 因其内存中的分布式处理速度而被使用，但它并不提供存储。您可以使用主机（本地）文件系统来读写数据，但如果您的数据量足够大，可以称之为大数据，那么使用基于云的分布式存储系统（如 OpenStack Swift 对象存储）是有意义的，该系统可以在许多云环境中找到，也可以安装在私有数据中心中。

如果需要极高的 I/O 性能，HDFS 也是一个选项。更多关于 HDFS 的信息可以在这里找到：[`hadoop.apache.org/docs/current/hadoop-project-dist/hadoop-hdfs/HdfsDesign.html`](http://hadoop.apache.org/docs/current/hadoop-project-dist/hadoop-hdfs/HdfsDesign.html)。

# 开发环境

本书中的代码示例将使用 Scala 语言编写。这是因为作为一种脚本语言，它产生的代码比 Java 少。它也可以在 Spark shell 中使用，以及与 Apache Spark 应用程序一起编译。我们将使用**sbt 工具**来编译 Scala 代码，我们已经按照以下方式将其安装到 Hortonworks HDP 2.6 Sandbox 中：

```scala
[hadoop@hc2nn ~]# sudo su -
[root@hc2nn ~]# cd /tmp
[root@hc2nn ~]#wget http://repo.scala-sbt.org/scalasbt/sbt-native-packages/org/scala-sbt/sbt/0.13.1/sbt.rpm
[root@hc2nn ~]# rpm -ivh sbt.rpm
```

以下 URL 提供了在包括 Windows、Linux 和 macOS 在内的其他操作系统上安装 sbt 的说明：[`www.scala-sbt.org/0.13/docs/Setup.html`](http://www.scala-sbt.org/0.13/docs/Setup.html)。

我们使用了一个名为**Hadoop**的通用 Linux 账户。如前述命令所示，我们需要以 root 账户安装`sbt`，我们通过`sudo su -l`（切换用户）访问了该账户。然后，我们使用`wget`从名为`repo.scala-sbt.org`的基于网络的服务器下载了`sbt.rpm`文件到`/tmp`目录。最后，我们使用带有`i`（安装）、`v`（验证）和`h`（打印哈希标记）选项的`rpm`命令安装了`rpm`文件。

本章中，我们在 Linux 服务器上使用 Linux Hadoop 账户开发了 Apache Spark 的所有 Scala 代码。我们将每组代码放置在`/home/hadoop/spark`下的一个子目录中。例如，以下`sbt`结构图显示 MLlib 朴素贝叶斯代码存储在 Spark 目录下的名为`nbayes`的子目录中。该图还显示，Scala 代码是在`nbayes`目录下的`src/main/scala`子目录结构中开发的。名为`bayes1.scala`和`convert.scala`的文件包含将在下一节中使用的朴素贝叶斯代码：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/4e6ee246-91df-45b4-b62d-91322e97ea0f.png)

`bayes.sbt`文件是`sbt`工具使用的配置文件，描述了如何编译 Scala 目录内的 Scala 文件。（注意，如果你使用 Java 开发，你将使用`nbayes/src/main/java`这样的路径。）接下来展示`bayes.sbt`文件的内容。`pwd`和`cat`Linux 命令提醒你文件位置，并提示你查看文件内容。

`name`、`version`和`scalaVersion`选项设置项目详细信息及使用的 Scala 版本。`libraryDependencies`选项定义 Hadoop 和 Spark 库的位置。

```scala
[hadoop@hc2nn nbayes]$ pwd
/home/hadoop/spark/nbayes
[hadoop@hc2nn nbayes]$ cat bayes.sbt 
name := "Naive Bayes"
version := "1.0"
scalaVersion := "2.11.2"
libraryDependencies += "org.apache.hadoop" % "hadoop-client" % "2.8.1"
libraryDependencies += "org.apache.spark" %% "spark-core" % "2.6.0"
libraryDependencies += "org.apache.spark" %% "spark-mllib" % "2.1.1"
```

可以使用以下命令从`nbayes`子目录编译 Scala `nbayes`项目代码：

```scala
[hadoop@hc2nn nbayes]$ sbt compile
```

`sbt compile`命令用于将代码编译成类。这些类随后被放置在`nbayes/target/scala-2.10/classes`目录下。使用此命令可将编译后的类打包成 JAR 文件：

```scala
[hadoop@hc2nn nbayes]$ sbt package
```

`sbt package`命令将在`nbayes/target/scala-2.10`目录下创建一个 JAR 文件。如**sbt 结构图**所示例中，编译打包成功后，名为`naive-bayes_2.10-1.0.jar`的 JAR 文件已被创建。此 JAR 文件及其包含的类可通过`spark-submit`命令使用。随着对 Apache Spark MLlib 模块功能的探索，这将在后面描述。

# 使用朴素贝叶斯进行分类

本节将提供一个 Apache Spark MLlib 朴素贝叶斯算法的实际示例。它将阐述该算法的理论基础，并提供一个逐步的 Scala 示例，展示如何使用该算法。

# 分类理论

要使用朴素贝叶斯算法对数据集进行分类，数据必须是线性可分的；即数据中的类别必须能通过类别边界线性分割。下图通过三条数据集和两条虚线表示的类别边界直观解释了这一点：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/5d57d6e1-50f8-4545-adac-23de9f528038.png)

朴素贝叶斯假设数据集内的特征（或维度）彼此独立；即它们互不影响。以下示例考虑将电子邮件分类为垃圾邮件。如果你有 100 封电子邮件，则执行以下操作：

```scala
60% of emails are spam
80% of spam emails contain the word buy
20% of spam emails don't contain the word buy
40% of emails are not spam
10% of non spam emails contain the word buy
90% of non spam emails don't contain the word buy
```

让我们将此示例转换为条件概率，以便朴素贝叶斯分类器可以识别：

```scala
P(Spam) = the probability that an email is spam = 0.6
P(Not Spam) = the probability that an email is not spam = 0.4
P(Buy|Spam) = the probability that an email that is spam has the word buy = 0.8
P(Buy|Not Spam) = the probability that an email that is not spam has the word buy = 0.1
```

包含单词“buy”的电子邮件是垃圾邮件的概率是多少？这可以写为*P(Spam|Buy)*。朴素贝叶斯表示，它由以下等式描述：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/3adfb0ba-fb3c-4349-9460-d2957e12edc5.png)

因此，使用之前的百分比数据，我们得到以下结果：

*P(Spam|Buy) = ( 0.8 * 0.6 ) / (( 0.8 * 0.6 ) + ( 0.1 * 0.4 ) ) = ( .48 ) / ( .48 + .04 )*

*= .48 / .52 = .923*

这意味着包含单词“buy”的电子邮件是垃圾邮件的可能性*92%*更高。以上是理论部分；现在是时候尝试一个使用 Apache Spark MLlib 朴素贝叶斯算法的真实示例了。

# 朴素贝叶斯实践

第一步是选择一些用于分类的数据。我们选择了英国政府数据网站上的一些数据，网址为[`data.gov.uk/dataset/road-accidents-safety-data`](http://data.gov.uk/dataset/road-accidents-safety-data)。

数据集名为**道路安全 - 数字呼吸测试数据 2013**，下载一个名为`DigitalBreathTestData2013.txt`的压缩文本文件。该文件包含大约五十万行。数据如下所示：

```scala
Reason,Month,Year,WeekType,TimeBand,BreathAlcohol,AgeBand,GenderSuspicion of Alcohol,Jan,2013,Weekday,12am-4am,75,30-39,MaleMoving Traffic Violation,Jan,2013,Weekday,12am-4am,0,20-24,MaleRoad Traffic Collision,Jan,2013,Weekend,12pm-4pm,0,20-24,Female
```

为了对数据进行分类，我们对列进行了修改...

# 使用 K-Means 进行聚类

本例将使用与前例相同的测试数据，但我们尝试使用 MLlib 的 K-Means 算法在数据中寻找簇。

# 聚类理论

K-Means 算法通过迭代尝试，通过最小化簇中心向量的均值与新候选簇成员向量之间的距离，来确定测试数据中的簇。以下等式假设数据集成员范围从*X1*到*Xn*；同时也假设*K*个簇集合，范围从*S1*到*Sk*，其中*K <= n*。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/55533695-d1e3-486e-a661-261ea6f75809.png)

# K-Means 实践

MLlib 的 K-Means 功能使用`LabeledPoint`结构处理数据，因此需要数值输入数据。由于正在重复使用上一节的数据，我们将不再解释数据转换。本节中数据方面的唯一变化是，处理将在 HDFS 下的`/data/spark/kmeans/`目录进行。此外，K-Means 示例的转换 Scala 脚本生成的记录全部以逗号分隔。

为了将工作与其他开发分开，K-Means 示例的开发和处理已在`/home/hadoop/spark/kmeans`目录下进行。`sbt`配置文件现在称为`kmeans.sbt`，与上一个示例相同，只是项目名称不同：

```scala
name := "K-Means"
```

本节代码可在软件包的`chapter7\K-Means`目录下找到。因此，查看存储在`kmeans/src/main/scala`下的`kmeans1.scala`代码，会发现一些类似的操作。导入语句引用了 Spark 上下文和配置。然而，这一次，K-Means 功能是从 MLlib 导入的。此外，为了这个例子，应用程序类名已更改为`kmeans1`：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.clustering.{KMeans,KMeansModel}

object kmeans1 extends App {
```

与上例相同，正在采取行动定义数据文件——定义 Spark 配置并创建 Spark 上下文：

```scala
 val hdfsServer = "hdfs://localhost:8020"
 val hdfsPath   = "/data/spark/kmeans/" 
 val dataFile   = hdfsServer + hdfsPath + "DigitalBreathTestData2013-MALE2a.csv"
 val sparkMaster = "spark://localhost:7077"
 val appName = "K-Means 1"
 val conf = new SparkConf()
 conf.setMaster(sparkMaster)
 conf.setAppName(appName)
 val sparkCxt = new SparkContext(conf)
```

接下来，从数据文件加载 CSV 数据，并通过逗号字符分割到`VectorData`变量中：

```scala
 val csvData = sparkCxt.textFile(dataFile)
 val VectorData = csvData.map {
   csvLine =>
     Vectors.dense( csvLine.split(',').map(_.toDouble))
 }
```

`KMeans`对象被初始化，并设置参数以定义簇的数量和确定它们的最大迭代次数：

```scala
 val kMeans = new KMeans
 val numClusters         = 3
 val maxIterations       = 50
```

为初始化模式、运行次数和 Epsilon 定义了一些默认值，这些值是我们进行 K-Means 调用所需的，但在处理过程中并未改变。最后，这些参数被设置到`KMeans`对象上：

```scala
 val initializationMode = KMeans.K_MEANS_PARALLEL
 val numRuns            = 1
 val numEpsilon         = 1e-4 
 kMeans.setK( numClusters )
 kMeans.setMaxIterations( maxIterations )
 kMeans.setInitializationMode( initializationMode )
 kMeans.setRuns( numRuns )
 kMeans.setEpsilon( numEpsilon )
```

我们缓存了训练向量数据以提高性能，并使用向量数据训练了`KMeans`对象，创建了一个经过训练的 K-Means 模型：

```scala
 VectorData.cache
 val kMeansModel = kMeans.run( VectorData )
```

我们计算了 K-Means 成本和输入数据行数，并通过`println`语句输出了结果。成本值表示簇的紧密程度以及簇之间的分离程度：

```scala
 val kMeansCost = kMeansModel.computeCost( VectorData ) 
 println( "Input data rows : " + VectorData.count() )
 println( "K-Means Cost   : " + kMeansCost )
```

接下来，我们使用 K-Means 模型打印出计算出的三个簇中每个簇的中心作为向量：

```scala
 kMeansModel.clusterCenters.foreach{ println }
```

最后，我们使用 K-Means 模型的预测函数来创建一个簇成员资格预测列表。然后，我们按值计数这些预测，以给出每个簇中数据点的计数。这显示了哪些簇更大，以及是否真的存在三个簇：

```scala
 val clusterRddInt = kMeansModel.predict( VectorData ) 
 val clusterCount = clusterRddInt.countByValue
  clusterCount.toList.foreach{ println }
} // end object kmeans1
```

因此，为了运行此应用程序，必须从`kmeans`子目录进行编译和打包，正如 Linux 的`pwd`命令所示：

```scala
[hadoop@hc2nn kmeans]$ pwd
/home/hadoop/spark/kmeans
[hadoop@hc2nn kmeans]$ sbt package
Loading /usr/share/sbt/bin/sbt-launch-lib.bash
[info] Set current project to K-Means (in build file:/home/hadoop/spark/kmeans/)
[info] Compiling 2 Scala sources to /home/hadoop/spark/kmeans/target/scala-2.10/classes...
[info] Packaging /home/hadoop/spark/kmeans/target/scala-2.10/k-means_2.10-1.0.jar ...
[info] Done packaging.
[success] Total time: 20 s, completed Feb 19, 2015 5:02:07 PM
```

一旦打包成功，我们检查 HDFS 以确保测试数据已就绪。如前例所示，我们使用软件包中提供的`convert.scala`文件将数据转换为数值形式。我们将处理 HDFS 目录`/data/spark/kmeans`中的`DigitalBreathTestData2013-MALE2a.csv`数据文件，如下所示：

```scala
[hadoop@hc2nn nbayes]$ hdfs dfs -ls /data/spark/kmeans
Found 3 items
-rw-r--r--   3 hadoop supergroup   24645166 2015-02-05 21:11 /data/spark/kmeans/DigitalBreathTestData2013-MALE2.csv
-rw-r--r--   3 hadoop supergroup   5694226 2015-02-05 21:48 /data/spark/kmeans/DigitalBreathTestData2013-MALE2a.csv
drwxr-xr-x   - hadoop supergroup         0 2015-02-05 21:46 /data/spark/kmeans/result
```

使用`spark-submit`工具运行 K-Means 应用程序。此命令中唯一的更改是类名现在是`kmeans1`：

```scala
spark-submit \
 --class kmeans1 \
 --master spark://localhost:7077 \
 --executor-memory 700M \
 --total-executor-cores 100 \
 /home/hadoop/spark/kmeans/target/scala-2.10/k-means_2.10-1.0.jar
```

来自 Spark 集群运行的输出显示如下：

```scala
Input data rows : 467054
K-Means Cost   : 5.40312223450789E7
```

先前的输出显示了输入数据量，看起来是正确的；它还显示了`K-Means 成本`值。该成本基于**内部总和平方误差（WSSSE）**，基本上给出了找到的簇质心与数据点分布匹配程度的度量。匹配得越好，成本越低。以下链接[`datasciencelab.wordpress.com/2013/12/27/finding-the-k-in-k-means-clustering/`](https://datasciencelab.wordpress.com/2013/12/27/finding-the-k-in-k-means-clustering/)更详细地解释了 WSSSE 以及如何找到一个好的**k**值。

接下来是三个向量，它们描述了具有正确维数的数据簇中心。请记住，这些簇质心向量将具有与原始向量数据相同的列数：

```scala
[0.24698249738061878,1.3015883142472253,0.005830116872250263,2.9173747788555207,1.156645130895448,3.4400290524342454] 
[0.3321793984152627,1.784137241326256,0.007615970459266097,2.5831987075928917,119.58366028156011,3.8379106085083468] 
[0.25247226760684494,1.702510963969387,0.006384899819416975,2.231404248000688,52.202897927594805,3.551509158139135]
```

最后，给出了 1 至 3 簇的簇成员资格，其中簇 1（索引 0）拥有最大的成员资格，有`407539`个成员向量：

```scala
(0,407539)
(1,12999)
(2,46516)
```

因此，这两个示例展示了如何使用朴素贝叶斯和 K-Means 对数据进行分类和聚类。如果我想对图像或更复杂的模式进行分类，并使用黑盒方法进行分类呢？下一节将探讨基于 Spark 的分类，使用**ANNs**，即**人工神经网络**。

# 人工神经网络

下图左侧展示了一个简单的生物神经元。该神经元具有接收其他神经元信号的树突。细胞体控制激活，轴突将电脉冲传递到其他神经元的树突。右侧的人工神经元有一系列加权输入：一个汇总函数，将输入分组，以及一个**触发机制**（**F(Net)**），该机制决定输入是否达到阈值，如果是，则神经元将触发：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/663b4884-b77e-4a07-8718-7f41d2f5fdf1.png)

神经网络对噪声图像和失真具有容忍度，因此在需要潜在的...黑盒分类方法时非常有用。

# ANN 实践

为了开始 ANN 训练，需要测试数据。鉴于这种分类方法应该擅长分类扭曲或噪声图像，我们决定在这里尝试对图像进行分类：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/19b4278b-afec-4d67-826c-20e4b767737f.png)

它们是手工制作的文本文件，包含由 1 和 0 组成的形状块。当存储在 HDFS 上时，回车符会被移除，使得图像呈现为单行向量。因此，ANN 将对一系列形状图像进行分类，然后与添加了噪声的相同图像进行测试，以确定分类是否仍然有效。有六张训练图像，每张图像将被赋予一个从 0.1 到 0.6 的任意训练标签。因此，如果 ANN 呈现一个闭合的正方形，它应该返回标签 0.1。下图展示了一个带有噪声的测试图像示例。

通过在图像内添加额外的零（0）字符创建的噪声已被突出显示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/9a151e3d-12c8-4d62-9c5b-2b7c4c9674f9.png)

与之前一样，ANN 代码是在 Linux Hadoop 账户下的`spark/ann`子目录中开发的。`ann.sbt`文件位于`ann`目录中：

```scala
[hadoop@hc2nn ann]$ pwd
/home/hadoop/spark/ann

[hadoop@hc2nn ann]$ ls
ann.sbt   project src target
```

`ann.sbt`文件的内容已更改，以使用 Spark 依赖项 JAR 库文件的完整路径：

```scala
name := "A N N"
version := "1.0"
scalaVersion := "2.11.2"
libraryDependencies += "org.apache.hadoop" % "hadoop-client" % "2.8.1"
libraryDependencies += "org.apache.spark" % "spark-core" % "2.6.0"
libraryDependencies += "org.apache.spark" % "spark-mllib" % "2.1.1"
libraryDependencies += "org.apache.spark" % "akka" % "2.5.3"
```

如前例所示，实际要编译的 Scala 代码存放在名为`src/main/scala`的子目录中。我们创建了两个 Scala 程序。第一个程序使用输入数据进行训练，然后用同一输入数据测试 ANN 模型。第二个程序则用噪声数据测试已训练模型的扭曲数据分类能力：

```scala
[hadoop@hc2nn scala]$ pwd
/home/hadoop/spark/ann/src/main/scala 
[hadoop@hc2nn scala]$ ls
test_ann1.scala test_ann2.scala
```

我们将检查第一个 Scala 文件，然后仅展示第二个文件的额外特性，因为两个示例在训练 ANN 之前非常相似。此处展示的代码示例可在本书提供的软件包中的路径`chapter2\ANN`下找到。因此，要检查第一个 Scala 示例，导入语句与前例类似。正在导入 Spark 上下文、配置、向量和`LabeledPoint`。这次还导入了用于 RDD 处理的`RDD`类以及新的 ANN 类`ANNClassifier`。请注意，MLlib/分类例程广泛使用`LabeledPoint`结构作为输入数据，该结构将包含要训练的特征和标签：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf 
import org.apache.spark.mllib.classification.ANNClassifier
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.linalg._
import org.apache.spark.rdd.RDD 

object testann1 extends App {
```

本例中的应用程序类名为`testann1`。要处理的 HDFS 文件已根据 HDFS 的`server`、`path`和文件名定义：

```scala
 val server = "hdfs://localhost:8020"
 val path   = "/data/spark/ann/"

 val data1 = server + path + "close_square.img"
 val data2 = server + path + "close_triangle.img"
 val data3 = server + path + "lines.img"
 val data4 = server + path + "open_square.img"
 val data5 = server + path + "open_triangle.img"
 val data6 = server + path + "plus.img"
```

Spark 上下文已使用 Spark 实例的 URL 创建，现在端口号不同——`8077`。应用程序名称为`ANN 1`。当应用程序运行时，这将在 Spark Web UI 上显示：

```scala
 val sparkMaster = "spark://localhost:8077"
 val appName = "ANN 1"
 val conf = new SparkConf()

 conf.setMaster(sparkMaster)
 conf.setAppName(appName)

 val sparkCxt = new SparkContext(conf)
```

基于 HDFS 的输入训练和测试数据文件被加载。每行上的值通过空格字符分割，数值已转换为双精度数。包含此数据的变量随后存储在一个名为**inputs**的数组中。同时，创建了一个名为 outputs 的数组，包含从`0.1`到`0.6`的标签。这些值将用于对输入模式进行分类：

```scala
 val rData1 = sparkCxt.textFile(data1).map(_.split(" ").map(_.toDouble)).collect
 val rData2 = sparkCxt.textFile(data2).map(_.split(" ").map(_.toDouble)).collect
 val rData3 = sparkCxt.textFile(data3).map(_.split(" ").map(_.toDouble)).collect
 val rData4 = sparkCxt.textFile(data4).map(_.split(" ").map(_.toDouble)).collect
 val rData5 = sparkCxt.textFile(data5).map(_.split(" ").map(_.toDouble)).collect
 val rData6 = sparkCxt.textFile(data6).map(_.split(" ").map(_.toDouble)).collect 
 val inputs = Array[Array[Double]] (
     rData1(0), rData2(0), rData3(0), rData4(0), rData5(0), rData6(0) ) 
 val outputs = ArrayDouble
```

代表输入数据特征和标签的输入和输出数据随后被合并并转换为`LabeledPoint`结构。最后，数据被并行化，以便为最佳并行处理进行分区：

```scala
 val ioData = inputs.zip( outputs )
 val lpData = ioData.map{ case(features,label) =>

   LabeledPoint( label, Vectors.dense(features) )
 }
 val rddData = sparkCxt.parallelize( lpData )
```

变量用于定义人工神经网络（ANN）的隐藏层拓扑结构。在此例中，我们选择了两个隐藏层，每层各有 100 个神经元。同时定义了最大迭代次数、批次大小（六个模式）以及收敛容差。容差指的是训练误差达到多大时，我们可以认为训练已经成功。接着，根据这些配置参数和输入数据创建了一个 ANN 模型：

```scala
 val hiddenTopology : Array[Int] = Array( 100, 100 )
 val maxNumIterations = 1000
 val convTolerance   = 1e-4
 val batchSize       = 6
 val annModel = ANNClassifier.train(rddData,
                                    batchSize,
                                    hiddenTopology,
                                    maxNumIterations,
                                    convTolerance)
```

为了测试已训练的 ANN 模型，使用相同的输入训练数据作为测试数据以获取预测标签。首先，创建一个名为`rPredictData`的输入数据变量。然后，数据被分区，并最终使用已训练的 ANN 模型获取预测结果。为了使该模型工作，它必须输出标签，即`0.1`到`0.6`：

```scala
 val rPredictData = inputs.map{ case(features) => 
   ( Vectors.dense(features) )
 }
 val rddPredictData = sparkCxt.parallelize( rPredictData )
 val predictions = annModel.predict( rddPredictData )
```

打印标签预测结果，脚本以闭合括号结束：

```scala
 predictions.toArray().foreach( value => println( "prediction > " + value ) )
} // end ann1
```

因此，要运行此代码示例，首先必须对其进行编译和打包。至此，您应该已经熟悉了从`ann`子目录执行的`sbt`命令：

```scala
[hadoop@hc2nn ann]$ pwd
/home/hadoop/spark/ann
[hadoop@hc2nn ann]$ sbt package
```

然后，在新`spark/spark`路径内使用新的基于 Spark 的 URL（端口`8077`）运行应用程序`testann1`，使用`spark-submit`命令：

```scala
/home/hadoop/spark/spark/bin/spark-submit \
 --class testann1 \
 --master spark://localhost:8077 \
 --executor-memory 700M \
 --total-executor-cores 100 \
 /home/hadoop/spark/ann/target/scala-2.10/a-n-n_2.10-1.0.jar
```

通过访问 Apache Spark 网页 URL `http://localhost:19080/`，现在可以看到应用程序正在运行。下图显示了`ANN 1`应用程序的运行情况以及先前完成的执行：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/e5e83e52-c0db-4506-8eeb-3ea0c81a5c5e.png)

通过选择其中一个集群主机工作实例，可以看到实际执行集群处理的工作实例的执行程序列表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/689d4c67-406b-4b41-8e9a-e437d9354d48.png)

最后，通过选择其中一个执行程序，可以看到其历史和配置，以及到日志文件和错误信息的链接。在这一级别，借助提供的日志信息，可以进行调试。可以检查这些日志文件以处理错误消息：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/467af2aa-e9ae-4b6b-927b-8b44c9d32c6d.png)

`ANN 1`应用程序提供了以下输出，以显示它已正确地对相同输入数据进行了重新分类。重新分类成功，因为每个输入模式都被赋予了与其训练时相同的标签：

```scala
prediction > 0.1
prediction > 0.2
prediction > 0.3
prediction > 0.4
prediction > 0.5
prediction > 0.6
```

这表明 ANN 训练和测试预测将适用于相同的数据。现在，我们将使用相同的数据进行训练，但测试时使用扭曲或含噪声的数据，我们已展示了一个示例。该示例可在软件包中的`test_ann2.scala`文件中找到。它与第一个示例非常相似，因此我们将仅展示更改的代码。该应用程序现在称为`testann2`：

```scala
object testann2 extends App
```

在 ANN 模型使用训练数据创建后，会生成一组额外的测试数据。此测试数据包含噪声：

```scala
 val tData1 = server + path + "close_square_test.img"
 val tData2 = server + path + "close_triangle_test.img"
 val tData3 = server + path + "lines_test.img"
 val tData4 = server + path + "open_square_test.img"
 val tData5 = server + path + "open_triangle_test.img"
 val tData6 = server + path + "plus_test.img"
```

此数据被处理成输入数组并分区以供集群处理：

```scala
 val rtData1 = sparkCxt.textFile(tData1).map(_.split(" ").map(_.toDouble)).collect
 val rtData2 = sparkCxt.textFile(tData2).map(_.split(" ").map(_.toDouble)).collect
 val rtData3 = sparkCxt.textFile(tData3).map(_.split(" ").map(_.toDouble)).collect
 val rtData4 = sparkCxt.textFile(tData4).map(_.split(" ").map(_.toDouble)).collect
 val rtData5 = sparkCxt.textFile(tData5).map(_.split(" ").map(_.toDouble)).collect
 val rtData6 = sparkCxt.textFile(tData6).map(_.split(" ").map(_.toDouble)).collect 
 val tInputs = Array[Array[Double]] (
     rtData1(0), rtData2(0), rtData3(0), rtData4(0), rtData5(0), rtData6(0) )

 val rTestPredictData = tInputs.map{ case(features) => ( Vectors.dense(features) ) }
 val rddTestPredictData = sparkCxt.parallelize( rTestPredictData )
```

它随后以与第一个示例相同的方式生成标签预测。如果模型正确分类数据，则应从`0.1`到`0.6`打印相同的标签值：

```scala
 val testPredictions = annModel.predict( rddTestPredictData )
 testPredictions.toArray().foreach( value => println( "test prediction > " + value ) )
```

代码已经编译完成，因此可以使用`spark-submit`命令运行：

```scala
/home/hadoop/spark/spark/bin/spark-submit \
 --class testann2 \
 --master spark://localhost:8077 \
 --executor-memory 700M \
 --total-executor-cores 100 \
 /home/hadoop/spark/ann/target/scala-2.10/a-n-n_2.10-1.0.jar
```

本脚本的集群输出显示了使用训练好的 ANN 模型对一些噪声测试数据进行成功分类的情况。噪声数据已被正确分类。例如，如果训练模型出现混淆，它可能会对位置一的噪声`close_square_test.img`测试图像给出 0.15 的值，而不是像实际那样返回`0.1`：

```scala
test prediction > 0.1
test prediction > 0.2
test prediction > 0.3
test prediction > 0.4
test prediction > 0.5
test prediction > 0.6
```

# 总结

本章试图为你概述 Apache Spark MLlib 模块中可用的一些功能。它还展示了即将在 ANNs 或人工神经网络方面可用的功能。你可能会对 ANNs 的工作效果印象深刻。由于时间和篇幅限制，本章无法涵盖 MLlib 的所有领域。此外，我们现在希望在下一章中更多地关注 SparkML 库，该库通过支持 DataFrames 以及底层 Catalyst 和 Tungsten 优化来加速机器学习。

我们学习了如何开发基于 Scala 的示例，用于朴素贝叶斯分类、K-Means 聚类和 ANNs。你了解了如何准备测试...


# 第五章：Apache SparkML

既然你已经学了很多关于 MLlib 的知识，为什么还需要另一个 ML API 呢？首先，在数据科学中，与多个框架和 ML 库合作是一项常见任务，因为它们各有优劣；大多数情况下，这是性能和功能之间的权衡。例如，R 在功能方面是王者——存在超过 6000 个 R 附加包。然而，R 也是数据科学执行环境中最慢的之一。另一方面，SparkML 目前功能相对有限，但却是速度最快的库之一。为什么会这样呢？这引出了 SparkML 存在的第二个原因。

RDD 与 DataFrames 和 Datasets 之间的二元性就像本书中的一条红线，并且不断影响着机器学习章节。由于 MLlib 设计为在 RDD 之上工作，SparkML 在 DataFrames 和 Datasets 之上工作，因此利用了 Catalyst 和 Tungsten 带来的所有新性能优势。

本章我们将涵盖以下主题：

+   SparkML API 简介

+   管道概念

+   转换器和估计器

+   一个工作示例

# 新 API 是什么样的？

在 Apache Spark 上进行机器学习时，我们习惯于在将数据实际输入算法之前将其转换为适当的格式和数据类型。全球的机器学习实践者发现，机器学习项目中的预处理任务通常遵循相同的模式：

+   数据准备

+   训练

+   评估

+   超参数调整

因此，新的 ApacheSparkML API 原生支持这一过程。它被称为 **管道**，灵感来源于 scikit-learn [`scikit-learn.org`](http://scikit-learn.org)，一个非常流行的 Python 编程语言机器学习库。中央数据结构是 DataFrame，所有操作都在其上运行。

# 管道概念

ApacheSparkML 管道包含以下组件：

+   **DataFrame**：这是中央数据存储，所有原始数据和中间结果都存储于此。

+   **转换器**：顾名思义，转换器通过在大多数情况下添加额外的（特征）列将一个 DataFrame 转换为另一个。转换器是无状态的，这意味着它们没有任何内部内存，每次使用时行为完全相同；这个概念在使用 RDD 的 map 函数时你可能已经熟悉。

+   **估计器**：在大多数情况下，估计器是一种机器学习模型。与转换器不同，估计器包含内部状态表示，并且高度依赖于它已经见过的数据历史。

+   **管道**：这是将前面提到的组件——DataFrame、Transformer 和 Estimator——粘合在一起的胶水。

+   **参数**：机器学习算法有许多可调整的旋钮。这些被称为**超参数**，而机器学习算法为了拟合数据所学习的值被称为参数。通过标准化超参数的表达方式，ApacheSparkML 为任务自动化打开了大门，正如我们稍后将看到的。

# 变压器

让我们从简单的事情开始。机器学习数据准备中最常见的任务之一是对分类值进行字符串索引和独热编码。让我们看看这是如何完成的。

# 字符串索引器

假设我们有一个名为`df`的 DataFrame，其中包含一个名为 color 的分类标签列——红色、绿色和蓝色。我们希望将它们编码为整数或浮点值。这时`org.apache.spark.ml.feature.StringIndexer`就派上用场了。它会自动确定类别集的基数，并为每个类别分配一个唯一值。所以在我们的例子中，一个类别列表，如红色、红色、绿色、红色、蓝色、绿色，应该被转换为 1、1、2、1、3、2：

```scala
import org.apache.spark.ml.feature.StringIndexer
var indexer = new StringIndexer()
  .setInputCol("colors")
  .setOutputCol("colorsIndexed")

var indexed = indexer.fit(df).transform(df)
```

此转换的结果是一个名为 indexed 的 DataFrame，除了字符串类型的颜色列外，现在还包含一个名为`colorsIndexed`的 double 类型列。

# 独热编码器

我们仅进行了一半。尽管机器学习算法能够利用`colorsIndexed`列，但如果我们对其进行独热编码，它们的表现会更好。这意味着，与其拥有一个包含 1 到 3 之间标签索引的`colorsIndexed`列，不如我们拥有三个列——每种颜色一个——并规定每行只允许将其中一个列设置为 1，其余为 0。让我们这样做：

```scala
var encoder = new OneHotEncoder()  .setInputCol("colorIndexed")  .setOutputCol("colorVec")var encoded = encoder.transform(indexed)
```

直观上，我们期望在编码后的 DataFrame 中得到三个额外的列，例如，`colorIndexedRed`、`colorIndexedGreen`和`colorIndexedBlue`...

# 向量汇编器

在我们开始实际的机器学习算法之前，我们需要应用最后一个转换。我们必须创建一个额外的`特征`列，其中包含我们希望机器学习算法考虑的所有列的信息。这是通过`org.apache.spark.ml.feature.VectorAssembler`如下完成的：

```scala
import org.apache.spark.ml.feature.VectorAssembler
vectorAssembler = new VectorAssembler()
        .setInputCols(Array("colorVec", "field2", "field3","field4"))
        .setOutputCol("features")
```

这个转换器只为结果 DataFrame 添加了一个名为**features**的列，该列的类型为`org.apache.spark.ml.linalg.Vector`。换句话说，这个由`VectorAssembler`创建的新列 features 包含了我们定义的所有列（在这种情况下，`colorVec`、`field2`、`field3`和`field4`），每行编码在一个向量对象中。这是 Apache SparkML 算法所喜欢的格式。

# 管道

在我们深入了解估计器之前——我们已经在`StringIndexer`中使用过一个——让我们首先理解管道的概念。你可能已经注意到，转换器只向 DataFrame 添加一个单一列，并且基本上省略了所有未明确指定为输入列的其他列；它们只能与`org.apache.spark.ml.Pipeline`一起使用，后者将单个转换器（和估计器）粘合在一起，形成一个完整的数据分析过程。因此，让我们为我们的两个`Pipeline`阶段执行此操作：

```scala
var transformers = indexer :: encoder :: vectorAssembler :: Nilvar pipeline = new Pipeline().setStages(transformers).fit(df)var transformed = pipeline.transform(df)
```

现在得到的 DataFrame 称为**transformed**，包含所有...

# 估计器

我们在`StringIndexer`中已经使用过估计器。我们已经说过，估计器在查看数据时会改变其状态，而转换器则不会。那么为什么`StringIndexer`是估计器呢？这是因为它需要记住所有先前见过的字符串，并维护字符串和标签索引之间的映射表。

在机器学习中，通常至少使用可用的训练数据的一个训练和测试子集。在管道中的估计器（如`StringIndexer`）在查看训练数据集时可能没有看到所有的字符串标签。因此，当你使用测试数据集评估模型时，`StringIndexer`现在遇到了它以前未见过的标签，你会得到一个异常。实际上，这是一个非常罕见的情况，基本上可能意味着你用来分离训练和测试数据集的样本函数不起作用；然而，有一个名为`setHandleInvalid("skip")`的选项，你的问题就解决了。

区分估计器和转换器的另一种简单方法是查看估计器上是否有额外的`fit`方法。实际上，fit 方法会根据给定数据集填充估计器的内部数据管理结构，在`StringIndexer`的情况下，这是标签字符串和标签索引之间的映射表。现在让我们来看另一个估计器，一个实际的机器学习算法。

# RandomForestClassifier

假设我们处于二分类问题设置中，并希望使用`RandomForestClassifier`。所有 SparkML 算法都有一个兼容的 API，因此它们可以互换使用。所以使用哪个并不重要，但`RandomForestClassifier`比更简单的模型如逻辑回归有更多的（超）参数。在稍后的阶段，我们将使用（超）参数调整，这也是 Apache SparkML 内置的。因此，使用一个可以调整更多参数的算法是有意义的。将这种二分类器添加到我们的`Pipeline`中非常简单：

```scala
import org.apache.spark.ml.classification.RandomForestClassifiervar rf = new RandomForestClassifier()   .setLabelCol("label") .setFeaturesCol("features") ...
```

# 模型评估

如前所述，模型评估是 ApacheSparkML 内置的，你会在`org.apache.spark.ml.evaluation`包中找到所需的一切。让我们继续进行二分类。这意味着我们将不得不使用`org.apache.spark.ml.evaluation.BinaryClassificationEvaluator`：

```scala
import org.apache.spark.ml.evaluation.BinaryClassificationEvaluator
val evaluator = new BinaryClassificationEvaluator()

import org.apache.spark.ml.param.ParamMap
var evaluatorParamMap = ParamMap(evaluator.metricName -> "areaUnderROC")
var aucTraining = evaluator.evaluate(result, evaluatorParamMap)
```

为了编码，之前初始化了一个`二元分类评估器`函数，并告诉它计算`ROC 曲线下面积`，这是评估机器学习算法预测性能的众多可能指标之一。

由于我们在名为`结果`的数据框中同时拥有实际标签和预测，因此计算此分数很简单，使用以下代码行完成：

```scala
var aucTraining = evaluator.evaluate(result, evaluatorParamMap)
```

# 交叉验证和超参数调整

我们将分别看一个`交叉验证`和超参数调整的例子。让我们来看看`交叉验证`。

# 交叉验证

如前所述，我们使用了机器学习算法的默认参数，我们不知道它们是否是好的选择。此外，与其简单地将数据分为训练集和测试集，或训练集、测试集和验证集，`交叉验证`可能是一个更好的选择，因为它确保最终所有数据都被机器学习算法看到。

`交叉验证`基本上将你全部可用的训练数据分成若干个**k**折。这个参数**k**可以指定。然后，整个`流水线`对每一折运行一次，并为每一折训练一个机器学习模型。最后，通过分类器的投票方案或回归的平均方法将得到的各种机器学习模型合并。

下图说明了十折`交叉验证`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/650d0e60-930f-48eb-b434-af3077044821.png)

# 超参数调整

`交叉验证`通常与所谓的（超）参数调整结合使用。什么是超参数？这些是你可以在你的机器学习算法上调整的各种旋钮。例如，以下是随机森林分类器的一些参数：

+   树的数量

+   特征子集策略

+   不纯度

+   最大箱数

+   最大树深度

设置这些参数可能会对训练出的分类器的性能产生重大影响。通常，没有明确的方案来选择它们——当然，经验有帮助——但超参数调整被视为黑魔法。我们不能只选择许多不同的参数并测试预测性能吗？当然可以。这个功能...

# 使用 Apache SparkML 赢得 Kaggle 竞赛

赢得 Kaggle 竞赛本身就是一门艺术，但我们只是想展示如何有效地使用 Apache SparkML 工具来做到这一点。

我们将使用博世公司提供的一个存档竞赛来进行这个操作，博世是一家德国跨国工程和电子公司，关于生产线性能数据。竞赛数据的详细信息可以在[`www.kaggle.com/c/bosch-production-line-performance/data`](https://www.kaggle.com/c/bosch-production-line-performance/data)找到。

# 数据准备

挑战数据以三个 ZIP 包的形式提供，但我们只使用其中两个。一个包含分类数据，一个包含连续数据，最后一个包含测量时间戳，我们暂时忽略它。

如果你提取数据，你会得到三个大型 CSV 文件。因此，我们首先要做的是将它们重新编码为 parquet，以便更节省空间：

```scala
def convert(filePrefix : String) = {   val basePath = "yourBasePath"   var df = spark              .read              .option("header",true)              .option("inferSchema", "true")              .csv("basePath+filePrefix+".csv")    df = df.repartition(1)    df.write.parquet(basePath+filePrefix+".parquet")}convert("train_numeric")convert("train_date")convert("train_categorical")
```

首先，我们定义一个函数...

# 特征工程

现在，是时候运行第一个转换器（实际上是估计器）了。它是`StringIndexer`，需要跟踪字符串和索引之间的内部映射表。因此，它不是转换器，而是估计器：

```scala
import org.apache.spark.ml.feature.{OneHotEncoder, StringIndexer}

var indexer = new StringIndexer()
  .setHandleInvalid("skip")
  .setInputCol("L0_S22_F545")
  .setOutputCol("L0_S22_F545Index")

var indexed = indexer.fit(df_notnull).transform(df_notnull)
indexed.printSchema
```

如图所示，已创建一个名为`L0_S22_F545Index`的附加列：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/4052e492-9d0b-4dd8-8dbd-8ad0aaca53bf.png)

最后，让我们检查新创建列的一些内容，并与源列进行比较。

我们可以清楚地看到类别字符串是如何转换为浮点索引的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/08902e98-db50-473b-9f20-c83646239384.png)

现在，我们想要应用`OneHotEncoder`，这是一个转换器，以便为我们的机器学习模型生成更好的特征：

```scala
var encoder = new OneHotEncoder()
  .setInputCol("L0_S22_F545Index")
  .setOutputCol("L0_S22_F545Vec")

var encoded = encoder.transform(indexed)
```

如图所示，新创建的列`L0_S22_F545Vec`包含`org.apache.spark.ml.linalg.SparseVector`对象，这是一种稀疏向量的压缩表示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/7566dc66-93d4-4433-97de-b09abb41cc1f.png)**稀疏向量表示**：`OneHotEncoder`与其他许多算法一样，返回一个`org.apache.spark.ml.linalg.SparseVector`类型的稀疏向量，根据定义，向量中只有一个元素可以为 1，其余必须保持为 0。这为压缩提供了大量机会，因为只需知道非零元素的位置即可。Apache Spark 使用以下格式的稀疏向量表示：*(l,[p],[v])*，其中*l*代表向量长度，*p*代表位置（这也可以是位置数组），*v*代表实际值（这可以是值数组）。因此，如果我们得到(13,[10],[1.0])，如我们之前的例子所示，实际的稀疏向量看起来是这样的：(0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,1.0,0.0,0.0,0.0)。

现在，我们的特征工程已完成，我们想要创建一个包含机器学习器所需所有必要列的总体稀疏向量。这是通过使用`VectorAssembler`完成的：

```scala
import org.apache.spark.ml.feature.VectorAssembler
import org.apache.spark.ml.linalg.Vectors

var vectorAssembler = new VectorAssembler()
        .setInputCols(Array("L0_S22_F545Vec", "L0_S0_F0", "L0_S0_F2","L0_S0_F4"))
        .setOutputCol("features")

var assembled = vectorAssembler.transform(encoded)
```

我们基本上只需定义列名列表和目标列，其余工作将自动完成：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/77298190-a703-4228-b9df-e8b960a720c6.png)

由于`features`列的视图有些压缩，让我们更详细地检查特征字段的一个实例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/1c6cb5ae-1cae-4f6d-aacd-3514e383fe0a.png)

我们可以清楚地看到，我们处理的是一个长度为 16 的稀疏向量，其中位置 0、13、14 和 15 是非零的，并包含以下值：`1.0`、`0.03`、`-0.034`和`-0.197`。完成！让我们用这些组件创建一个`Pipeline`。

# 测试特征工程管道

让我们用我们的转换器和估计器创建一个`Pipeline`：

```scala
import org.apache.spark.ml.Pipelineimport org.apache.spark.ml.PipelineModel//Create an array out of individual pipeline stagesvar transformers = Array(indexer,encoder,assembled)var pipeline = new Pipeline().setStages(transformers).fit(df_notnull)var transformed = pipeline.transform(df_notnull)
```

请注意，`Pipeline`的`setStages`方法仅期望一个由`transformers`和`estimators`组成的数组，这些我们之前已经创建。由于`Pipeline`的部分包含估计器，我们必须先对我们的`DataFrame`运行`fit`。得到的`Pipeline`对象在`transform`方法中接受一个`DataFrame`，并返回转换的结果：

正如预期的，...

# 训练机器学习模型

现在是时候向`Pipeline`添加另一个组件了：实际的机器学习算法——随机森林：

```scala
import org.apache.spark.ml.classification.RandomForestClassifier
var rf = new RandomForestClassifier() 
  .setLabelCol("label")
  .setFeaturesCol("features")

var model = new Pipeline().setStages(transformers :+ rf).fit(df_notnull)

var result = model.transform(df_notnull)
```

这段代码非常直接。首先，我们必须实例化我们的算法，并将其作为引用获取到`rf`中。我们可以为模型设置额外的参数，但我们将稍后在`CrossValidation`步骤中以自动化方式进行。然后，我们只需将阶段添加到我们的`Pipeline`，拟合它，并最终转换。`fit`方法，除了运行所有上游阶段外，还调用`RandomForestClassifier`上的拟合以训练它。训练好的模型现在包含在`Pipeline`中，`transform`方法实际上创建了我们的预测列：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/8b66350b-866d-4207-9ea6-db5097902fbf.png)

正如我们所见，我们现在获得了一个名为 prediction 的额外列，其中包含`RandomForestClassifier`模型的输出。当然，我们仅使用了可用特征/列的一个非常有限的子集，并且尚未调整模型，因此我们不期望表现很好；但是，让我们看看如何使用 Apache SparkML 轻松评估我们的模型。

# 模型评估

没有评估，模型一文不值，因为我们不知道它的准确性如何。因此，我们现在将使用内置的`BinaryClassificationEvaluator`来评估预测性能，并使用一个广泛使用的度量标准，称为`areaUnderROC`（深入探讨这一点超出了本书的范围）：

```scala
import org.apache.spark.ml.evaluation.BinaryClassificationEvaluatorval evaluator = new BinaryClassificationEvaluator()import org.apache.spark.ml.param.ParamMapvar evaluatorParamMap = ParamMap(evaluator.metricName -> "areaUnderROC")var aucTraining = evaluator.evaluate(result, evaluatorParamMap)
```

正如我们所见，有一个内置类名为`org.apache.spark.ml.evaluation.BinaryClassificationEvaluator`，还有其他一些...

# 交叉验证与超参数调整

如前所述，机器学习中的一个常见步骤是使用测试数据对训练数据进行交叉验证，并调整机器学习算法的旋钮。让我们使用 Apache SparkML 来自动完成这一过程！

首先，我们必须配置参数映射和`CrossValidator`：

```scala
import org.apache.spark.ml.tuning.{CrossValidator, ParamGridBuilder}
var paramGrid = new ParamGridBuilder()
    .addGrid(rf.numTrees, 3 :: 5 :: 10 :: 30 :: 50 :: 70 :: 100 :: 150 :: Nil)
    .addGrid(rf.featureSubsetStrategy, "auto" :: "all" :: "sqrt" :: "log2" :: "onethird" :: Nil)
    .addGrid(rf.impurity, "gini" :: "entropy" :: Nil)    
    .addGrid(rf.maxBins, 2 :: 5 :: 10 :: 15 :: 20 :: 25 :: 30 :: Nil)
    .addGrid(rf.maxDepth, 3 :: 5 :: 10 :: 15 :: 20 :: 25 :: 30 :: Nil)
    .build()

var crossValidator = new CrossValidator()
      .setEstimator(new Pipeline().setStages(transformers :+ rf))
      .setEstimatorParamMaps(paramGrid)
      .setNumFolds(5)
.setEvaluator(evaluator)
var crossValidatorModel = crossValidator.fit(df_notnull)
var newPredictions = crossValidatorModel.transform(df_notnull)
```

`org.apache.spark.ml.tuning.ParamGridBuilder`用于定义`CrossValidator`需要在其中搜索的超参数空间，而`org.apache.spark.ml.tuning.CrossValidator`则接收我们的`Pipeline`、随机森林分类器的超参数空间以及`CrossValidation`的折数作为参数。现在，按照惯例，我们只需对`CrossValidator`调用 fit 和 transform 方法，它就会基本运行我们的`Pipeline`多次，并返回一个表现最佳的模型。你知道训练了多少个不同的模型吗？我们有 5 折的`CrossValidation`和 5 维超参数空间基数在 2 到 8 之间，所以让我们计算一下：5 * 8 * 5 * 2 * 7 * 7 = 19600 次！

# 使用评估器来评估经过交叉验证和调优的模型的质量

既然我们已经以全自动方式优化了`Pipeline`，接下来让我们看看如何获得最佳模型：

```scala
var bestPipelineModel = crossValidatorModel.bestModel.asInstanceOf[PipelineModel]    var stages = bestPipelineModel.stagesimport org.apache.spark.ml.classification.RandomForestClassificationModel    val rfStage = stages(stages.length-1).asInstanceOf[RandomForestClassificationModel]rfStage.getNumTreesrfStage.getFeatureSubsetStrategyrfStage.getImpurityrfStage.getMaxBinsrfStage.getMaxDepth
```

`crossValidatorModel.bestModel`代码基本上返回了最佳`Pipeline`。现在我们使用`bestPipelineModel.stages`来获取各个阶段，并获得经过调优的`RandomForestClassificationModel ...`

# 总结

你已经了解到，正如在许多其他领域一样，引入`DataFrames`促进了互补框架的发展，这些框架不再直接使用 RDDs。机器学习领域亦是如此，但还有更多内容。`Pipeline`实际上将 Apache Spark 中的机器学习提升到了一个新的水平，极大地提高了数据科学家的生产力。

所有中间对象之间的兼容性以及精心设计的概念简直令人惊叹。太棒了！最后，我们将讨论的概念应用于来自 Kaggle 竞赛的真实数据集，这对于你自己的 Apache SparkML 机器学习项目来说是一个非常好的起点。下一章将介绍 Apache SystemML，这是一个第三方机器学习库，用于 Apache Spark。让我们看看它为何有用以及与 SparkML 的区别。


# 第六章：Apache SystemML

到目前为止，我们只涵盖了 Apache Spark 标准发行版附带的组件（当然，除了 HDFS、Kafka 和 Flume）。然而，Apache Spark 也可以作为第三方组件的运行时，使其成为某种大数据应用的操作系统。在本章中，我们将介绍最初由*IBM Almaden Research Lab*在加利福尼亚开发的 Apache SystemML，这是一项令人惊叹的技术。Apache SystemML 经历了许多转变阶段，现在已成为 Apache 顶级项目。

在本章中，我们将探讨以下主题，以深入了解该主题：

+   在 Apache Spark 之上使用 SystemML 开发您自己的机器学习应用

+   学习...

# 为什么我们需要另一个库？

为了回答这个问题，我们需要了解 SystemML 的历史，该历史始于 2007 年，作为*IBM Almaden Research Lab*在加利福尼亚的一个研究项目。该项目旨在改善数据科学家的工作流程，特别是那些希望改进和增强现有机器学习算法功能的人。

因此，**SystemML**是一种声明性标记语言，能够透明地在 Apache Spark 上分发工作。它支持通过多线程和 CPU 上的 SIMD 指令以及 GPU 进行 Scale-up，以及通过集群进行 Scale-out，当然，两者可以同时进行。

最后，有一个基于成本的优化器，它生成考虑数据集大小统计信息的低级执行计划。换句话说，**Apache SystemML**之于机器学习，正如 Catalyst 和 Tungsten 之于 DataFrames。

# 为何基于 Apache Spark？

Apache Spark 解决了数据处理和机器学习中的许多常见问题，因此 Apache SystemML 可以利用这些功能。例如，Apache Spark 支持在通用 RDD 结构之上统一 SQL、图形、流和机器学习数据处理。

换言之，它是一个支持惰性求值和分布式内存缓存的通用**DAG**（**有向无环图**）执行引擎。

# Apache SystemML 的历史

Apache SystemML 已有十年历史。当然，它经历了多次重构，现已成为世界上最先进、最快的机器学习库之一。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/99d7fcbd-805c-4eb7-8ce4-824feb427843.png)

如前图所示，针对 Apache SystemML 进行了大量研究。它比 Apache Spark 早两年，并在 2017 年成为 Apache 顶级项目，脱离**孵化器**状态。甚至在 SystemML 启动之初，*IBM Research Almaden*的研究人员就意识到，通常情况下，开箱即用的机器学习算法在大数据集上表现非常糟糕。

因此，数据分析管道在经过小规模原型调整后必须进行优化。下图说明了这一点：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/f320753c-315a-4185-884d-d5cf1092b0c4.png)

这意味着数据科学家将在他选择的编程语言中设计他的应用程序，最可能是 Matlab、R 或 Python，最终，系统程序员将接手这个工作，并将其重新实现为 JVM 语言，如 Java 或 Scala，这通常会提供更好的性能，并且也能在数据并行框架如 Apache Spark 上进行线性扩展。

原型的缩放版本将在整个数据集上返回结果，数据科学家再次负责修改原型，整个循环再次开始。不仅 IBM Almaden 研究中心的员工经历过这种情况，我们的团队也见证了这一点。因此，让我们使系统程序员变得多余（或者至少只需要他来处理我们的 Apache Spark 作业），使用 Apache SystemML。

# 机器学习算法的成本优化器

让我们从一个例子开始，来说明 Apache SystemML 内部是如何工作的。考虑一个推荐系统。

# 一个例子 - 交替最小二乘法

推荐系统试图根据其他用户的历史记录预测用户可能感兴趣的潜在商品。

因此，让我们考虑一个所谓的商品-用户或产品-客户矩阵，如图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/fec9348c-089f-4c7a-a554-afe5dc4c2ed1.png)

这是一个所谓的**稀疏**矩阵，因为只有少数单元格填充了非零值，表示客户*i*和产品*j*之间的匹配。要么在单元格中放置一个**一**，要么放置任何其他数值，例如，表示购买的产品数量或客户*i*对特定产品*j*的评分。我们称这个矩阵为*r[ui]*，其中*u*代表用户，*i*代表商品。

熟悉线性代数的你可能知道，任何矩阵都可以通过两个较小的矩阵进行因式分解。这意味着你需要找到两个矩阵*p[u]*和*q[i]*，当它们相乘时，能够重构原始矩阵*r[ui]*；我们称这个重构为*r[ui]'*。目标是找到*p[u]*和*q[i]*以重构*r[ui]'*，使其与*r[ui]*的差异不过大。这通过求和平方误差目标函数来实现。

下图说明了这一点以及矩阵的稀疏性特性：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/313de954-d123-4de2-9a17-946ba029838a.png)

一旦我们找到了良好的因子*p[u]*和*q[i]*，我们就能构建*r[ui]'*，最终，新的非零单元格将出现，这些将成为新的预测产品推荐。如果你还没有完全理解所有细节，不用担心，因为理解本章其余部分并不需要太多这个例子。

寻找*p[u]*和*q[i]*的常用算法称为**交替最小二乘法**（**ALS**）——交替是因为在每次迭代中，优化目标从*p[u]*切换到*q[i]*，反之亦然。对此不必过于纠结，但实际运作即是如此，而在 Apache Spark MLlib 中，这仅是一行 Scala 代码：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/09984e95-cf71-420f-a20e-a54a99248aad.png)

那么问题何在？在我们解释之前，先来看看 ALS 如何在统计编程语言如 R 中实现：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/11ca287a-c585-495a-b154-b356f6576364.png)

同样，若你未能理解每一行代码也不必担心，此图旨在展示在 R 中，该算法仅需 27 行代码即可表达。若我们再查看 MLlib 中的 ALS 实现，会发现它有超过 800 行代码。你可在[`github.com/apache/spark/tree/master/mllib/src/main/scala/org/apache/spark/mllib/recommendation`](https://github.com/apache/spark/tree/master/mllib/src/main/scala/org/apache/spark/mllib/recommendation)找到此实现。

那么为何在 Spark 上需要超过 800 行的 Scala 代码，而在 R 中仅需 27 行呢？这是因为性能优化。MLlib 中的 ALS 实现包含了超过 50%的性能优化代码。如果我们能做到以下这些呢？

+   去除我们算法实现中的所有性能优化

+   将我们的 R 代码 1:1 移植到某个并行框架

+   如有变动，只需修改我们的 R 实现

这正是 Apache SystemML 发挥作用的地方，它支持这一切。Apache SystemML 的**DSL**（**特定领域语言**）是 R 语法的一个子集，因此你可以直接将之前的示例原封不动地运行在 Apache SystemML 之上，无需任何修改。此外，基于成本的性能优化器会在 Apache Spark 之上生成物理执行计划，以根据数据规模属性最小化执行时间。那么，让我们探究其工作原理。

# Apache SystemML 架构

在 Apache SystemML 中，关键在于优化器。该组件将算法的高级描述在特定领域语言中转化为 Apache Spark 上高度优化的物理执行，如图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/0747c796-c870-468f-bf36-ba63cf7b6945.png)

# 语言解析

让我们稍稍揭开 Apache SystemML 优化器的神秘面纱，以便理解其中究竟发生了什么。引擎首先进行的是 DSL 的编译步骤。首先是语法检查，然后进行活跃变量分析以确定哪些中间结果仍需保留，最后进行语义检查。

# 生成高级操作符

一旦通过前述步骤，便生成使用所谓**高级操作符**（**HOPs**）的执行计划。这些操作符构建自 DSL 的**抽象语法树**（**AST**）。在此阶段，以下重要优化步骤正在进行：

+   **静态重写**：DSL 提供了一套丰富的语法和语义特性，使得实现易于理解，但可能导致非最优执行。Apache SystemML 检测到这些 AST 分支，并静态地将其重写为更好的版本，保持语义等价。

+   **动态重写**：动态重写与静态重写非常相似，但它们是由基于成本的统计数据驱动的，考虑了数据集的大小...

# 低级操作符如何被优化

让我们看看，低级操作符是如何被选择和优化的。我们将坚持使用加权除法矩阵乘法的例子——一个在 HOP 优化过程之前被选中的 HOP，而不是一系列普通的矩阵乘法。现在问题来了，例如，是否应该使用在 Apache Spark 工作节点上并行运行的 LOP 的并行版本，或者是否应该优先考虑本地执行。在这个例子中，Apache SystemML 确定所有中间结果都适合驱动节点的主内存，并选择本地操作符**WDivMM**，而不是并行操作符**MapWDivMM**。下图说明了这一过程：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/41cf44d5-92c7-4841-b372-0bd9d429d63f.png)

# 性能测量

所有这些努力值得吗？让我们来看一些本地 R 脚本、MLlib 和 Apache SystemML 之间的性能比较：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/730107a4-fa1e-4a18-9661-09639c998ed2.png)

在不同大小的数据集（1.2GB、12GB 和 120GB）上运行 ALS 算法，使用 R、MLlib 和 ApacheSystemML。我们可以清楚地看到，即使在最小的数据集上，R 也不是一个可行的解决方案，因为它花费了超过 24 小时，我们不确定它是否能完成。在 12GB 的数据集上，我们注意到 ApacheSystemML 比 MLlib 运行得快得多，最后，在 120GB 的数据集上，MLlib 的 ALS 实现一天内没有完成，我们...

# Apache SystemML 的实际应用

让我们来看一个非常简单的例子。让我们在 Apache SystemML DSL 中创建一个脚本——一种类似 R 的语法——以便乘以两个矩阵：

```scala
import org.apache.sysml.api.MLOutput
import org.apache.spark.sql.SQLContext
import org.apache.spark.mllib.util.LinearDataGenerator
import org.apache.sysml.api.MLContext
import org.apache.sysml.runtime.instructions.spark.utils.{RDDConverterUtilsExt => RDDConverterUtils}
import org.apache.sysml.runtime.matrix.MatrixCharacteristics;

val sqlContext = new SQLContext(sc)

val simpleScript =
"""
fileX = "";
fileY = "";
fileZ = "";

X = read (fileX);
Y = read (fileY);

Z = X %*% Y

write (Z,fileZ);
"""
```

然后，我们生成一些测试数据：

```scala
// Generate data
val rawDataX = sqlContext.createDataFrame(LinearDataGenerator.generateLinearRDD(sc, 100, 10, 1))
val rawDataY = sqlContext.createDataFrame(LinearDataGenerator.generateLinearRDD(sc, 10, 100, 1))

// Repartition into a more parallelism-friendly number of partitions
val dataX = rawDataX.repartition(64).cache()
val dataY = rawDataY.repartition(64).cache()
```

为了使用 Apache SystemML，我们必须创建一个`MLContext`对象：

```scala
// Create SystemML context
val ml = new MLContext(sc)
```

现在我们需要将数据转换成 Apache SystemML 能理解的格式：

```scala
// Convert data to proper format
val mcX = new MatrixCharacteristics()
val mcY = new MatrixCharacteristics()
val X = RDDConverterUtils.vectorDataFrameToBinaryBlock(sc, dataX, mcX, false, "features")
val Y = RDDConverterUtils.vectorDataFrameToBinaryBlock(sc, dataY, mcY, false, "features")
```

现在，我们将数据`X`和`Y`传递给 Apache SystemML 运行时，并预先注册一个名为`Z`的变量，以便从运行时获取结果：

```scala
// Register inputs & outputs
ml.reset()  
ml.registerInput("X", X, mcX)
ml.registerInput("Y", Y, mcY)
ml.registerOutput("Z")
```

最后，我们实际执行了存储在`simpleScript`中的脚本，并使用`executeScript`方法从运行时获取结果：

```scala
val outputs = ml.executeScript(simpleScript)

// Get outputs
val Z = outputs.getDF(sqlContext, "Z")
```

现在`Z`包含了一个带有矩阵乘法结果的`DataFrame`。完成！

# 概要

你已了解到，在 Apache Spark 之上还有额外的机器学习框架和库的空间，并且，一个类似于我们在 Catalyst 中已使用的基于成本的优化器可以极大地加速处理。此外，将性能优化代码与算法代码分离，有助于在不考虑性能的情况下进一步改进算法方面。

另外，这些执行计划高度适应数据量的大小，并根据主内存大小和可能的加速器（如 GPU）等可用硬件配置进行调整。Apache SystemML 显著提升了机器学习应用的生命周期，尤其是在机器学习方面...
