# Flink 学习手册（一）

> 原文：[`zh.annas-archive.org/md5/0715B65CE6CD5C69C124166C204B4830`](https://zh.annas-archive.org/md5/0715B65CE6CD5C69C124166C204B4830)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

随着大型计算系统的出现，不同领域的组织以实时方式生成大量数据。作为大数据处理的最新参与者，Apache Flink 旨在以极快的速度处理连续的数据流。

这本书将成为您使用 Apache Flink 进行批处理和流数据处理的权威指南。该书首先介绍了 Apache Flink 生态系统，设置它并使用 DataSet 和 DataStream API 处理批处理和流式数据集。随后，本书将探讨如何将 SQL 的强大功能引入 Flink，并探索用于查询和操作数据的 Table API。在书的后半部分，读者将学习 Apache Flink 的其余生态系统，以实现事件处理、机器学习和图处理等复杂任务。该书的最后部分将包括诸如扩展 Flink 解决方案、性能优化和将 Flink 与 Hadoop、ElasticSearch、Cassandra 和 Kafka 等其他工具集成的主题。

无论您是想深入了解 Apache Flink，还是想探索如何更好地利用这一强大技术，您都会在本书中找到一切。本书涵盖了许多真实世界的用例，这将帮助您串联起各个方面。

# 本书涵盖的内容

第一章，“介绍 Apache Flink”，向您介绍了 Apache Flink 的历史、架构、特性和在单节点和多节点集群上的安装。

第二章，“使用 DataStream API 进行数据处理”，为您提供了有关 Flink 流优先概念的详细信息。您将了解有关 DataStream API 提供的数据源、转换和数据接收器的详细信息。

第三章，“使用批处理 API 进行数据处理”，为您介绍了批处理 API，即 DataSet API。您将了解有关数据源、转换和接收器的信息。您还将了解 API 提供的连接器。

第四章，“使用 Table API 进行数据处理”，帮助您了解如何将 SQL 概念与 Flink 数据处理框架相结合。您还将学习如何将这些概念应用于实际用例。

第五章，“复杂事件处理”，为您提供了如何使用 Flink CEP 库解决复杂事件处理问题的见解。您将了解有关模式定义、检测和警报生成的详细信息。

第六章，“使用 FlinkML 进行机器学习”，详细介绍了机器学习概念以及如何将各种算法应用于实际用例。

第七章，“Flink 图形 API - Gelly”，向您介绍了图形概念以及 Flink Gelly 为我们解决实际用例提供的功能。它向您介绍了 Flink 提供的迭代图处理能力。

第八章，“使用 Flink 和 Hadoop 进行分布式数据处理”，详细介绍了如何使用现有的 Hadoop-YARN 集群提交 Flink 作业。它详细介绍了 Flink 在 YARN 上的工作原理。

第九章，“在云上部署 Flink”，提供了有关如何在云上部署 Flink 的详细信息。它详细介绍了如何在 Google Cloud 和 AWS 上使用 Flink。

第十章，“最佳实践”，涵盖了开发人员应遵循的各种最佳实践，以便以高效的方式使用 Flink。它还讨论了日志记录、监控最佳实践以控制 Flink 环境。

# 您需要为本书准备什么

您需要一台带有 Windows、Mac 或 UNIX 等任何操作系统的笔记本电脑或台式电脑。最好有一个诸如 Eclipse 或 IntelliJ 的 IDE，当然，您需要很多热情。

# 这本书是为谁准备的

这本书适用于希望在分布式系统上处理批处理和实时数据的大数据开发人员，以及寻求工业化分析解决方案的数据科学家。

# 惯例

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下: "这将在`/flinkuser/.ssh`文件夹中生成公钥和私钥。"

代码块设置如下:

```java
CassandraSink.addSink(input)
  .setQuery("INSERT INTO cep.events (id, message) values (?, ?);")
  .setClusterBuilder(new ClusterBuilder() {
    @Override
    public Cluster buildCluster(Cluster.Builder builder) {
      return builder.addContactPoint("127.0.0.1").build();
    }
  })
  .build();
```

任何命令行输入或输出都以以下方式编写:

```java
$sudo tar -xzf flink-1.1.4-bin-hadoop27-scala_2.11.tgz 
$cd flink-1.1.4 
$bin/start-local.sh

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中显示为: "一旦我们的所有工作都完成了，关闭集群就变得很重要。为此，我们需要再次转到 AWS 控制台，然后单击**终止**按钮"。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会显示如此。


# 第一章：介绍 Apache Flink

随着分布式技术不断发展，工程师们试图将这些技术推向极限。以前，人们正在寻找更快、更便宜的处理数据的方法。当 Hadoop 被引入时，这种需求得到了满足。每个人都开始使用 Hadoop，开始用 Hadoop 生态系统工具替换他们的 ETL。现在，这种需求已经得到满足，Hadoop 在许多公司的生产中被使用，另一个需求出现了，即以流式方式处理数据，这催生了 Apache Spark 和 Flink 等技术。快速处理引擎、能够在短时间内扩展以及对机器学习和图技术的支持等功能，正在开发者社区中推广这些技术。

你们中的一些人可能已经在日常生活中使用 Apache Spark，并且可能一直在想，如果我有 Spark，为什么还需要使用 Flink？这个问题是可以预料的，比较是自然的。让我试着简要回答一下。我们需要在这里理解的第一件事是，Flink 基于**流式优先原则**，这意味着它是真正的流处理引擎，而不是将流作为小批量收集的快速处理引擎。Flink 将批处理视为流处理的特例，而在 Spark 的情况下则相反。同样，我们将在本书中发现更多这样的区别。

这本书是关于最有前途的技术之一--Apache Flink。在本章中，我们将讨论以下主题：

+   历史

+   架构

+   分布式执行

+   特性

+   快速启动设置

+   集群设置

+   运行一个示例应用程序

# 历史

Flink 作为一个名为*Stratosphere*的研究项目开始，旨在在柏林地区的大学建立下一代大数据分析平台。它于 2014 年 4 月 16 日被接受为 Apache 孵化器项目。Stratosphere 的最初版本基于 Nephele 的研究论文[`stratosphere.eu/assets/papers/Nephele_09.pdf`](http://stratosphere.eu/assets/papers/Nephele_09.pdf)。

以下图表显示了 Stratosphere 随时间的演变：

![历史](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_001.jpg)

Stratosphere 的第一个版本主要关注运行时、优化器和 Java API。随着平台的成熟，它开始支持在各种本地环境以及**YARN**上的执行。从 0.6 版本开始，Stratosphere 更名为 Flink。Flink 的最新版本专注于支持各种功能，如批处理、流处理、图处理、机器学习等。

Flink 0.7 引入了 Flink 最重要的功能，即 Flink 的流式 API。最初的版本只有 Java API。后来的版本开始支持 Scala API。现在让我们在下一节中看一下 Flink 的当前架构。

# 架构

Flink 1.X 的架构包括各种组件，如部署、核心处理和 API。我们可以轻松地将最新的架构与 Stratosphere 的架构进行比较，并看到它的演变。以下图表显示了组件、API 和库：

![架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_002.jpg)

Flink 具有分层架构，其中每个组件都是特定层的一部分。每个层都建立在其他层之上，以清晰的抽象。Flink 被设计为在本地机器、YARN 集群或云上运行。运行时是 Flink 的核心数据处理引擎，通过 API 以 JobGraph 的形式接收程序。**JobGraph**是一个简单的并行数据流，其中包含一组产生和消费数据流的任务。

DataStream 和 DataSet API 是程序员用于定义作业的接口。当程序编译时，这些 API 生成 JobGraphs。一旦编译完成，DataSet API 允许优化器生成最佳执行计划，而 DataStream API 使用流构建进行高效的执行计划。

然后根据部署模型将优化后的 JobGraph 提交给执行器。您可以选择本地、远程或 YARN 部署模式。如果已经运行了 Hadoop 集群，最好使用 YARN 部署模式。

# 分布式执行

Flink 的分布式执行由两个重要的进程组成，即主节点和工作节点。当执行 Flink 程序时，各种进程参与执行，即作业管理器、任务管理器和作业客户端。

以下图表显示了 Flink 程序的执行：

![分布式执行](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_003.jpg)

Flink 程序需要提交给作业客户端。然后作业客户端将作业提交给作业管理器。作业管理器负责编排资源分配和作业执行。它的第一件事是分配所需的资源。资源分配完成后，任务被提交给相应的任务管理器。收到任务后，任务管理器启动线程开始执行。在执行过程中，任务管理器不断向作业管理器报告状态的变化。可能有各种状态，如执行开始、进行中或已完成。作业执行完成后，结果被发送回客户端。

## 作业管理器

主进程，也称为作业管理器，协调和管理程序的执行。它们的主要职责包括调度任务、管理检查点、故障恢复等。

可以并行运行多个主节点并共享这些责任。这有助于实现高可用性。其中一个主节点需要成为领导者。如果领导节点宕机，备用主节点将被选举为领导者。

作业管理器包括以下重要组件：

+   actor 系统

+   调度器

+   检查点

Flink 在内部使用 Akka actor 系统在作业管理器和任务管理器之间进行通信。

### actor 系统

actor 系统是具有各种角色的 actor 的容器。它提供诸如调度、配置、日志记录等服务。它还包含一个线程池，所有 actor 都是从中初始化的。所有 actor 都驻留在一个层次结构中。每个新创建的 actor 都会分配给一个父级。actor 之间使用消息系统进行通信。每个 actor 都有自己的邮箱，从中读取所有消息。如果 actor 是本地的，消息通过共享内存共享，但如果 actor 是远程的，消息则通过 RPC 调用传递。

每个父级负责监督其子级。如果子级出现任何错误，父级会收到通知。如果 actor 能够解决自己的问题，它可以重新启动其子级。如果无法解决问题，则可以将问题升级给自己的父级：

![actor 系统](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_004.jpg)

在 Flink 中，actor 是一个具有状态和行为的容器。actor 的线程会顺序地处理它在邮箱中接收到的消息。状态和行为由它接收到的消息确定。

### 调度器

在 Flink 中，执行器被定义为任务槽。每个任务管理器需要管理一个或多个任务槽。在内部，Flink 决定哪些任务需要共享槽，哪些任务必须放入特定的槽中。它通过 SlotSharingGroup 和 CoLocationGroup 来定义。

### 检查点

检查点是 Flink 提供一致性容错的支柱。它不断为分布式数据流和执行器状态进行一致的快照。它受 Chandy-Lamport 算法的启发，但已经修改以满足 Flink 的定制要求。有关 Chandy-Lamport 算法的详细信息可以在以下网址找到：[`research.microsoft.com/en-us/um/people/lamport/pubs/chandy.pdf`](http://research.microsoft.com/en-us/um/people/lamport/pubs/chandy.pdf)。

有关快照实现细节的详细信息可以在以下研究论文中找到：*Lightweight Asynchronous Snapshots for Distributed Dataflows (*[`arxiv.org/abs/1506.08603`](http://arxiv.org/abs/1506.08603))。

容错机制不断为数据流创建轻量级快照。因此，它们在没有显着负担的情况下继续功能。通常，数据流的状态保存在配置的位置，如 HDFS。

在发生故障时，Flink 会停止执行器并重置它们，然后从最新可用的检查点开始执行。

流障是 Flink 快照的核心元素。它们被吸收到数据流中而不影响流程。障碍永远不会超越记录。它们将一组记录分组成一个快照。每个障碍都携带一个唯一的 ID。以下图表显示了障碍如何被注入到数据流中进行快照：

![检查点](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_005.jpg)

每个快照状态都报告给 Flink 的**作业管理器**的检查点协调器。在绘制快照时，Flink 处理记录的对齐，以避免由于任何故障而重新处理相同的记录。这种对齐通常需要一些毫秒。但对于一些强烈的应用程序，即使毫秒级的延迟也是不可接受的，我们可以选择低延迟而不是精确的单个记录处理。默认情况下，Flink 会精确处理每个记录一次。如果任何应用程序需要低延迟，并且可以接受至少一次交付，我们可以关闭该触发器。这将跳过对齐并提高延迟。

## 任务管理器

任务管理器是在 JVM 中以一个或多个线程执行任务的工作节点。任务管理器上的任务执行的并行性由每个任务管理器上可用的任务槽确定。每个任务代表分配给任务槽的一组资源。例如，如果一个任务管理器有四个槽，那么它将为每个槽分配 25%的内存。一个任务槽中可能运行一个或多个线程。同一槽中的线程共享相同的 JVM。同一 JVM 中的任务共享 TCP 连接和心跳消息：

![任务管理器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_006.jpg)

## 作业客户端

作业客户端不是 Flink 程序执行的内部部分，而是执行的起点。作业客户端负责接受用户的程序，然后创建数据流，然后将数据流提交给作业管理器进行进一步执行。执行完成后，作业客户端将结果提供给用户。

数据流是执行计划。考虑一个非常简单的单词计数程序：

![作业客户端](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_007.jpg)

当客户端接受用户的程序时，然后将其转换为数据流。上述程序的数据流可能如下所示：

![作业客户端](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_008.jpg)

前面的图表显示了程序如何转换为数据流。Flink 数据流默认是并行和分布式的。对于并行数据处理，Flink 对操作符和流进行分区。操作符分区称为子任务。流可以以一对一或重新分布的方式分发数据。

数据直接从源流向映射操作符，因此无需洗牌数据。但对于 GroupBy 操作，Flink 可能需要按键重新分发数据以获得正确的结果。

![作业客户端](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_009.jpg)

# 特点

在之前的章节中，我们试图了解 Flink 的架构和其执行模型。由于其健壮的架构，Flink 充满了各种功能。

## 高性能

Flink 旨在实现高性能和低延迟。与 Spark 等其他流处理框架不同，您不需要进行许多手动配置以获得最佳性能。Flink 的流水线数据处理与其竞争对手相比具有更好的性能。

## 精确一次性有状态计算

正如我们在前一节中讨论的，Flink 的分布式检查点处理有助于确保每个记录的处理仅一次。在高吞吐量应用程序的情况下，Flink 为我们提供了一个开关，允许至少一次处理。

## 灵活的流式窗口

Flink 支持数据驱动的窗口。这意味着我们可以基于时间、计数或会话设计窗口。窗口也可以定制，这使我们能够在事件流中检测特定模式。

## 容错

Flink 的分布式、轻量级快照机制有助于实现很高程度的容错。它允许 Flink 提供高吞吐量性能和可靠的传递。

## 内存管理

Flink 配备了自己的内存管理，位于 JVM 内部，这使其独立于 Java 的默认垃圾收集器。它通过使用哈希、索引、缓存和排序有效地进行内存管理。

## 优化器

为了避免消耗大量内存的操作（如洗牌、排序等），Flink 的批处理数据处理 API 进行了优化。它还确保使用缓存以避免大量的磁盘 IO 操作。

## 流和批处理在一个平台上

Flink 提供了用于批处理和流处理数据的 API。因此，一旦设置了 Flink 环境，它就可以轻松托管流和批处理应用程序。事实上，Flink 首先考虑流处理，并将批处理视为流处理的特例。

## 库

Flink 拥有丰富的库，可用于机器学习、图处理、关系数据处理等。由于其架构，执行复杂事件处理和警报非常容易。我们将在后续章节中更多地了解这些库。

## 事件时间语义

Flink 支持事件时间语义。这有助于处理事件到达顺序混乱的流。有时事件可能会延迟到达。Flink 的架构允许我们基于时间、计数和会话定义窗口，这有助于处理这种情况。

# 快速开始设置

现在我们了解了 Flink 的架构和其过程模型的细节，是时候开始快速设置并自己尝试一些东西了。Flink 可以在 Windows 和 Linux 机器上运行。

我们需要做的第一件事是下载 Flink 的二进制文件。Flink 可以从 Flink 下载页面下载：[`flink.apache.org/downloads.html`](http://flink.apache.org/downloads.html)。

在下载页面上，您将看到多个选项，如下面的截图所示：

![快速开始设置](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_010.jpg)

为了安装 Flink，您不需要安装 Hadoop。但是，如果您需要使用 Flink 连接到 Hadoop，那么您需要下载与您拥有的 Hadoop 版本兼容的确切二进制文件。

由于我已经安装了最新版本的**Hadoop 2.7.0**，我将下载与 Hadoop 2.7.0 兼容并基于 Scala 2.11 构建的 Flink 二进制文件。

这是直接下载链接：

[`www-us.apache.org/dist/flink/flink-1.1.4/flink-1.1.4-bin-hadoop27-scala_2.11.tgz`](http://www-us.apache.org/dist/flink/flink-1.1.4/flink-1.1.4-bin-hadoop27-scala_2.11.tgz)

## 先决条件

Flink 需要首先安装 Java。因此，在开始之前，请确保已安装 Java。我在我的机器上安装了 JDK 1.8：

![先决条件](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_011.jpg)

## 在 Windows 上安装

Flink 安装非常容易。只需提取压缩文件并将其存储在所需位置。

提取后，转到文件夹并执行`start-local.bat`：

```java
>cd flink-1.1.4
>bin\start-local.bat

```

然后您会看到 Flink 的本地实例已经启动。

您还可以在`http://localhost:8081/`上检查 Web UI：

![在 Windows 上安装](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_012.jpg)

您可以通过按下*Cltr* + *C*来停止 Flink 进程。

## 在 Linux 上安装

与 Windows 类似，在 Linux 机器上安装 Flink 非常容易。我们需要下载二进制文件，将其放在特定文件夹中，然后进行提取和完成：

```java
$sudo tar -xzf flink-1.1.4-bin-hadoop27-scala_2.11.tgz
$cd flink-1.1.4
$bin/start-local.sh 

```

与 Windows 一样，请确保 Java 已安装在机器上。

现在我们已经准备好提交一个 Flink 作业。要停止 Linux 上的本地 Flink 实例，请执行以下命令：

```java
$bin/stop-local.sh

```

# 集群设置

设置 Flink 集群也非常简单。那些有安装 Hadoop 集群背景的人将能够非常容易地理解这些步骤。为了设置集群，让我们假设我们有四台 Linux 机器，每台机器都有适度的配置。至少两个核心和 4 GB RAM 的机器将是一个很好的选择来开始。

我们需要做的第一件事是选择集群设计。由于我们有四台机器，我们将使用一台机器作为**作业管理器**，另外三台机器作为**任务管理器**：

![集群设置](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_013.jpg)

## SSH 配置

为了设置集群，我们首先需要在作业管理器机器上进行无密码连接到任务管理器。需要在创建 SSH 密钥并将其复制到`authorized_keys`上执行以下步骤：

```java
$ssh-keygen

```

这将在`/home/flinkuser/.ssh`文件夹中生成公钥和私钥。现在将公钥复制到任务管理器机器，并在任务管理器上执行以下步骤，以允许从作业管理器进行无密码连接：

```java
sudo mkdir -p /home/flinkuser/.ssh 
sudo touch /home/flinkuser/authorized_keys 
sudo cp /home/flinkuser/.ssh 
 sudo sh -c "cat id_rsa.pub >> /home/flinkuser/.ssh/authorized_keys"

```

确保密钥通过执行以下命令具有受限访问权限：

```java
sudo chmod 700 /home/flinkuser/.ssh
sudo chmod 600 /home/flinkuser/.ssh/authorized_keys 

```

现在您可以从作业管理器机器测试无密码 SSH 连接：

```java
sudo ssh <task-manager-1>
sudo ssh <task-manager-2>
sudo ssh <task-manager-3>

```

### 提示

如果您正在使用任何云服务实例进行安装，请确保从 SSH 启用了 ROOT 登录。为了做到这一点，您需要登录到每台机器：`打开文件/etc/ssh/sshd_config`。然后将值更改为`PermitRootLogin yes`。保存文件后，通过执行命令重新启动 SSH 服务：`sudo service sshd restart`

## Java 安装

接下来，我们需要在每台机器上安装 Java。以下命令将帮助您在基于 Redhat/CentOS 的 UNIX 机器上安装 Java。

```java
wget --no-check-certificate --no-cookies --header "Cookie: 
    oraclelicense=accept-securebackup-cookie" 
    http://download.oracle.com/otn-pub/java/jdk/8u92-b14/jdk-8u92-
    linux-x64.rpm
sudo rpm -ivh jdk-8u92-linux-x64.rpm

```

接下来，我们需要设置`JAVA_HOME`环境变量，以便 Java 可以从任何地方访问。

创建一个`java.sh`文件：

```java
sudo vi /etc/profile.d/java.sh

```

并添加以下内容并保存：

```java
#!/bin/bash
JAVA_HOME=/usr/java/jdk1.8.0_92
PATH=$JAVA_HOME/bin:$PATH
export PATH JAVA_HOME
export CLASSPATH=.

```

使文件可执行并对其进行源操作：

```java
sudo chmod +x /etc/profile.d/java.sh
source /etc/profile.d/java.sh

```

您现在可以检查 Java 是否已正确安装：

```java
$ java -version
java version "1.8.0_92"
Java(TM) SE Runtime Environment (build 1.8.0_92-b14)
Java HotSpot(TM) 64-Bit Server VM (build 25.92-b14, mixed mode)

```

在作业管理器和任务管理器机器上重复这些安装步骤。

## Flink 安装

一旦 SSH 和 Java 安装完成，我们需要下载 Flink 二进制文件并将其提取到特定文件夹中。请注意，所有节点上的安装目录应该相同。

所以让我们开始吧：

```java
cd /usr/local
sudo wget  http://www-eu.apache.org/dist/flink/flink-1.1.4/flink-
    1.1.4-bin-hadoop27-scala_2.11.tgz
sudo tar -xzf flink-1.1.4-bin-hadoop27-scala_2.11.tgz

```

现在二进制文件已经准备好，我们需要进行一些配置。

## 配置

Flink 的配置很简单。我们需要调整一些参数，然后就可以了。大多数配置对作业管理器节点和任务管理器节点都是相同的。所有配置都在`conf/flink-conf.yaml`文件中完成。

以下是作业管理器节点的配置文件：

```java
jobmanager.rpc.address: localhost
jobmanager.rpc.port: 6123
jobmanager.heap.mb: 256
taskmanager.heap.mb: 512
taskmanager.numberOfTaskSlots: 1

```

您可能希望根据节点配置更改作业管理器和任务管理器的内存配置。对于任务管理器，`jobmanager.rpc.address`应填入正确的作业管理器主机名或 IP 地址。

因此，对于所有任务管理器，配置文件应如下所示：

```java
jobmanager.rpc.address: <jobmanager-ip-or-host>
jobmanager.rpc.port: 6123
jobmanager.heap.mb: 256
taskmanager.heap.mb: 512
taskmanager.numberOfTaskSlots: 1

```

我们需要在此文件中添加`JAVA_HOME`详细信息，以便 Flink 确切知道从何处查找 Java 二进制文件：

```java
export JAVA_HOME=/usr/java/jdk1.8.0_92

```

我们还需要在`conf/slaves`文件中添加从节点的详细信息，每个节点占据一个新的单独行。

示例`conf/slaves`文件应如下所示：

```java
<task-manager-1>
<task-manager-2>
<task-manager-3>

```

## 启动守护程序

现在唯一剩下的就是启动 Flink 进程。 我们可以在各个节点上分别启动每个进程，也可以执行`start-cluster.sh`命令在每个节点上启动所需的进程：

```java
bin/start-cluster.sh

```

如果所有配置都正确，那么您会看到集群正在运行。 您可以在`http://<job-manager-ip>:8081/`上检查 Web UI。

以下是 Flink Web UI 的一些快照：

![启动守护程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_014.jpg)

您可以单击**作业管理器**链接以获取以下视图：

![启动守护程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_015.jpg)

同样，您可以按以下方式查看**任务管理器**视图：

![启动守护程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_016.jpg)

## 添加额外的作业/任务管理器

Flink 为您提供了向正在运行的集群添加额外的作业和任务管理器实例的功能。

在启动守护程序之前，请确保您已按照先前给出的步骤进行操作。

要向现有集群添加额外的作业管理器，请执行以下命令：

```java
sudo bin/jobmanager.sh start cluster

```

同样，我们需要执行以下命令以添加额外的任务管理器：

```java
sudo bin/taskmanager.sh start cluster

```

## 停止守护程序和集群

作业执行完成后，您希望关闭集群。 以下命令用于此目的。

要一次停止整个集群：

```java
sudo bin/stop-cluster.sh

```

要停止单个作业管理器：

```java
sudo bin/jobmanager.sh stop cluster

```

要停止单个任务管理器：

```java
sudo bin/taskmanager.sh stop cluster

```

# 运行示例应用程序

Flink 二进制文件附带了一个示例应用程序，可以直接使用。 让我们从一个非常简单的应用程序开始，单词计数。 在这里，我们将尝试一个从特定端口上的 netcat 服务器读取数据的流式应用程序。

让我们开始吧。 首先通过执行以下命令在端口`9000`上启动 netcat 服务器：

```java
nc -l 9000

```

现在 netcat 服务器将开始监听端口 9000，所以无论您在命令提示符上输入什么都将被发送到 Flink 处理中。

接下来，我们需要启动 Flink 示例程序以侦听 netcat 服务器。 以下是命令：

```java
bin/flink run examples/streaming/SocketTextStreamWordCount.jar --
hostname localhost --port 9000
08/06/2016 10:32:40     Job execution switched to status RUNNING.
08/06/2016 10:32:40     Source: Socket Stream -> Flat Map(1/1)   
switched to SCHEDULED
08/06/2016 10:32:40     Source: Socket Stream -> Flat Map(1/1) 
switched to DEPLOYING
08/06/2016 10:32:40     Keyed Aggregation -> Sink: Unnamed(1/1) 
switched to SCHEDULED
08/06/2016 10:32:40     Keyed Aggregation -> Sink: Unnamed(1/1) 
switched to DEPLOYING
08/06/2016 10:32:40     Source: Socket Stream -> Flat Map(1/1) 
switched to RUNNING
08/06/2016 10:32:40     Keyed Aggregation -> Sink: Unnamed(1/1) 
switched to RUNNING

```

这将启动 Flink 作业执行。 现在您可以在 netcat 控制台上输入一些内容，Flink 将对其进行处理。

例如，在 netcat 服务器上键入以下内容：

```java
$nc -l 9000
hi Hello
Hello World
This distribution includes cryptographic software.  The country in
which you currently reside may have restrictions on the import,
possession, use, and/or re-export to another country, of
encryption software.  BEFORE using any encryption software, please
check your country's laws, regulations and policies concerning the
import, possession, or use, and re-export of encryption software,   
to
see if this is permitted.  See <http://www.wassenaar.org/> for    
more
information.

```

您可以在日志中验证输出：

```java
$ tail -f flink-*-taskmanager-*-flink-instance-*.out
==> flink-root-taskmanager-0-flink-instance-1.out <== 
(see,2) 
(http,1) 
(www,1) 
(wassenaar,1) 
(org,1) 
(for,1) 
(more,1) 
(information,1) 
(hellow,1) 
(world,1) 

==> flink-root-taskmanager-1-flink-instance-1.out <== 
(is,1) 
(permitted,1) 
(see,2) 
(http,1)
(www,1) 
(wassenaar,1) 
(org,1) 
(for,1) 
(more,1) 
(information,1) 

==> flink-root-taskmanager-2-flink-instance-1.out <== 
(hello,1) 
(worlds,1) 
(hi,1) 
(how,1) 
(are,1) 
(you,1) 
(how,2) 
(is,1) 
(it,1) 
(going,1)

```

您还可以查看 Flink Web UI，以查看作业的执行情况。 以下屏幕截图显示了执行的数据流计划：

![运行示例应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_017.jpg)

在作业执行中，Flink 有两个运算符。 第一个是源运算符，它从 Socket 流中读取数据。 第二个运算符是转换运算符，它聚合单词的计数。

我们还可以查看作业执行的时间轴：

![运行示例应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_01_018.jpg)

# 摘要

在本章中，我们讨论了 Flink 如何作为大学项目开始，然后成为一款成熟的企业级数据处理平台。 我们查看了 Flink 架构的细节以及其处理模型的工作原理。 我们还学会了如何在本地和集群模式下运行 Flink。

在下一章中，我们将学习 Flink 的流式 API，并查看其细节以及如何使用该 API 来解决我们的数据流处理问题。


# 第二章：使用 DataStream API 进行数据处理

实时分析目前是一个重要问题。许多不同的领域需要实时处理数据。到目前为止，已经有多种技术试图提供这种能力。像 Storm 和 Spark 这样的技术已经在市场上存在很长时间了。源自**物联网**（**IoT**）的应用程序需要实时或几乎实时地存储、处理和分析数据。为了满足这些需求，Flink 提供了一个名为 DataStream API 的流数据处理 API。

在本章中，我们将详细了解 DataStream API 的相关细节，涵盖以下主题：

+   执行环境

+   数据源

+   转换

+   数据汇

+   连接器

+   用例 - 传感器数据分析

任何 Flink 程序都遵循以下定义的解剖结构：

![使用 DataStream API 进行数据处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_02_001.jpg)

我们将逐步了解每个步骤以及如何使用此解剖结构的 DataStream API。

# 执行环境

为了开始编写 Flink 程序，我们首先需要获取现有的执行环境或创建一个。根据您要做什么，Flink 支持：

+   获取已存在的 Flink 环境

+   创建本地环境

+   创建远程环境

通常情况下，您只需要使用`getExecutionEnvironment()`。这将根据您的上下文执行正确的操作。如果您在 IDE 中执行本地环境，则会启动本地执行环境。否则，如果您执行 JAR 文件，则 Flink 集群管理器将以分布式方式执行程序。

如果您想自己创建本地或远程环境，那么您也可以选择使用`createLocalEnvironment()`和`createRemoteEnvironment`（`String host`，`int port`，`String`和`.jar`文件）等方法来执行。

# 数据源

数据源是 Flink 程序期望从中获取数据的位置。这是 Flink 程序解剖的第二步。Flink 支持多个预先实现的数据源函数。它还支持编写自定义数据源函数，因此可以轻松编程任何不受支持的内容。首先让我们尝试了解内置的源函数。

## 基于套接字

DataStream API 支持从套接字读取数据。您只需要指定要从中读取数据的主机和端口，它就会完成工作：

```java
socketTextStream(hostName, port); 

```

您还可以选择指定分隔符：

```java
socketTextStream(hostName,port,delimiter) 

```

您还可以指定 API 应尝试获取数据的最大次数：

```java
socketTextStream(hostName,port,delimiter, maxRetry) 

```

## 基于文件

您还可以选择使用 Flink 中基于文件的源函数从文件源中流式传输数据。您可以使用`readTextFile(String path)`从指定路径的文件中流式传输数据。默认情况下，它将读取`TextInputFormat`并逐行读取字符串。

如果文件格式不是文本，您可以使用这些函数指定相同的内容：

```java
readFile(FileInputFormat<Out> inputFormat, String path) 

```

Flink 还支持读取文件流，因为它们使用`readFileStream()`函数生成：

```java
readFileStream(String filePath, long intervalMillis, FileMonitoringFunction.WatchType watchType) 

```

您只需要指定文件路径、轮询间隔（应轮询文件路径的时间间隔）和观察类型。观察类型包括三种类型：

+   当系统应该仅处理新文件时，使用`FileMonitoringFunction.WatchType.ONLY_NEW_FILES`

+   当系统应该仅处理文件的附加内容时，使用`FileMonitoringFunction.WatchType.PROCESS_ONLY_APPENDED`

+   当系统应该重新处理文件的附加内容以及文件中的先前内容时，使用`FileMonitoringFunction.WatchType.REPROCESS_WITH_APPENDED`

如果文件不是文本文件，那么我们可以使用以下函数，它让我们定义文件输入格式：

```java
readFile(fileInputFormat, path, watchType, interval, pathFilter, typeInfo) 

```

在内部，它将读取文件任务分为两个子任务。一个子任务仅基于给定的`WatchType`监视文件路径。第二个子任务并行进行实际的文件读取。监视文件路径的子任务是一个非并行子任务。它的工作是根据轮询间隔不断扫描文件路径，并报告要处理的文件，拆分文件，并将拆分分配给相应的下游线程：

![基于文件的](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_02_002.jpg)

# 转换

数据转换将数据流从一种形式转换为另一种形式。输入可以是一个或多个数据流，输出也可以是零个、一个或多个数据流。现在让我们逐个尝试理解每个转换。

## 映射

这是最简单的转换之一，其中输入是一个数据流，输出也是一个数据流。

在 Java 中：

```java
inputStream.map(new MapFunction<Integer, Integer>() { 
  @Override 
  public Integer map(Integer value) throws Exception { 
        return 5 * value; 
      } 
    }); 

```

在 Scala 中：

```java
inputStream.map { x => x * 5 } 

```

## FlatMap

FlatMap 接受一个记录并输出零个、一个或多个记录。

在 Java 中：

```java
inputStream.flatMap(new FlatMapFunction<String, String>() { 
    @Override 
    public void flatMap(String value, Collector<String> out) 
        throws Exception { 
        for(String word: value.split(" ")){ 
            out.collect(word); 
        } 
    } 
}); 

```

在 Scala 中：

```java
inputStream.flatMap { str => str.split(" ") } 

```

## 过滤

过滤函数评估条件，然后，如果结果为真，则仅发出记录。过滤函数可以输出零条记录。

在 Java 中：

```java
inputStream.filter(new FilterFunction<Integer>() { 
    @Override 
    public boolean filter(Integer value) throws Exception { 
        return value != 1; 
    } 
}); 

```

在 Scala 中：

```java
inputStream.filter { _ != 1 } 

```

## KeyBy

KeyBy 根据键逻辑地将流分区。在内部，它使用哈希函数来分区流。它返回`KeyedDataStream`。

在 Java 中：

```java
inputStream.keyBy("someKey"); 

```

在 Scala 中：

```java
inputStream.keyBy("someKey") 

```

## 减少

Reduce 通过将上次减少的值与当前值进行减少来展开`KeyedDataStream`。以下代码执行了`KeyedDataStream`的求和减少。

在 Java 中：

```java
keyedInputStream. reduce(new ReduceFunction<Integer>() { 
    @Override 
    public Integer reduce(Integer value1, Integer value2) 
    throws Exception { 
        return value1 + value2; 
    } 
}); 

```

在 Scala 中：

```java
keyedInputStream. reduce { _ + _ } 

```

## 折叠

Fold 通过将上次的文件夹流与当前记录组合起来来展开`KeyedDataStream`。它发出一个数据流。

在 Java 中：

```java
keyedInputStream keyedStream.fold("Start", new FoldFunction<Integer, String>() { 
    @Override 
    public String fold(String current, Integer value) { 
        return current + "=" + value; 
    } 
  }); 

```

在 Scala 中：

```java
keyedInputStream.fold("Start")((str, i) => { str + "=" + i }) 

```

应用于流(1,2,3,4,5)的前面给定的函数将发出这样的流：`Start=1=2=3=4=5`

## 聚合

DataStream API 支持各种聚合，如`min`、`max`、`sum`等。这些函数可以应用于`KeyedDataStream`，以便进行滚动聚合。

在 Java 中：

```java
keyedInputStream.sum(0) 
keyedInputStream.sum("key") 
keyedInputStream.min(0) 
keyedInputStream.min("key") 
keyedInputStream.max(0) 
keyedInputStream.max("key") 
keyedInputStream.minBy(0) 
keyedInputStream.minBy("key") 
keyedInputStream.maxBy(0) 
keyedInputStream.maxBy("key") 

```

在 Scala 中：

```java
keyedInputStream.sum(0) 
keyedInputStream.sum("key") 
keyedInputStream.min(0) 
keyedInputStream.min("key") 
keyedInputStream.max(0) 
keyedInputStream.max("key") 
keyedInputStream.minBy(0) 
keyedInputStream.minBy("key") 
keyedInputStream.maxBy(0) 
keyedInputStream.maxBy("key") 

```

`max`和`maxBy`之间的区别在于 max 返回流中的最大值，但`maxBy`返回具有最大值的键。对`min`和`minBy`也适用相同的规则。

## 窗口

`window`函数允许按时间或其他条件对现有的`KeyedDataStreams`进行分组。以下转换通过 10 秒的时间窗口发出记录组。

在 Java 中：

```java
inputStream.keyBy(0).window(TumblingEventTimeWindows.of(Time.seconds(10))); 

```

在 Scala 中：

```java
inputStream.keyBy(0).window(TumblingEventTimeWindows.of(Time.seconds(10))) 

```

Flink 定义了数据的切片，以处理（可能是）无限的数据流。这些切片称为窗口。这种切片有助于通过应用转换来以块的方式处理数据。要对流进行窗口处理，我们需要分配一个键，以便进行分发，并且需要一个描述在窗口流上执行什么转换的函数。

要将流切片成窗口，我们可以使用预先实现的 Flink 窗口分配器。我们有选项，如滚动窗口、滑动窗口、全局和会话窗口。Flink 还允许您通过扩展`WindowAssginer`类来编写自定义窗口分配器。让我们尝试理解这些各种分配器是如何工作的。

### 全局窗口

全局窗口是永不结束的窗口，除非由触发器指定。通常在这种情况下，每个元素都分配给一个单一的按键全局窗口。如果我们不指定任何触发器，将永远不会触发任何计算。

### 滚动窗口

根据特定时间创建滚动窗口。它们是固定长度的窗口，不重叠。当您需要在特定时间内对元素进行计算时，滚动窗口应该是有用的。例如，10 分钟的滚动窗口可用于计算在 10 分钟内发生的一组事件。

### 滑动窗口

滑动窗口类似于滚动窗口，但它们是重叠的。它们是固定长度的窗口，通过用户给定的窗口滑动参数与前一个窗口重叠。当您想要计算在特定时间范围内发生的一组事件时，这种窗口处理非常有用。

### 会话窗口

会话窗口在需要根据输入数据决定窗口边界时非常有用。会话窗口允许窗口开始时间和窗口大小的灵活性。我们还可以提供会话间隙配置参数，指示在考虑会话关闭之前等待多长时间。

## WindowAll

`windowAll`函数允许对常规数据流进行分组。通常这是一个非并行的数据转换，因为它在非分区数据流上运行。

在 Java 中：

```java
inputStream.windowAll(TumblingEventTimeWindows.of(Time.seconds(10))); 

```

在 Scala 中：

```java
inputStream.windowAll(TumblingEventTimeWindows.of(Time.seconds(10))) 

```

与常规数据流函数类似，我们也有窗口数据流函数。唯一的区别是它们适用于窗口化的数据流。因此，窗口缩减类似于`Reduce`函数，窗口折叠类似于`Fold`函数，还有聚合函数。

## 联合

`Union`函数执行两个或多个数据流的并集。这会并行地组合数据流。如果我们将一个流与自身组合，则每个记录都会输出两次。

在 Java 中：

```java
inputStream. union(inputStream1, inputStream2, ...); 

```

在 Scala 中：

```java
inputStream. union(inputStream1, inputStream2, ...) 

```

## 窗口连接

我们还可以通过一些键在一个公共窗口中连接两个数据流。下面的示例显示了在`5`秒的窗口中连接两个流的情况，其中第一个流的第一个属性的连接条件等于另一个流的第二个属性。

在 Java 中：

```java
inputStream. join(inputStream1) 
   .where(0).equalTo(1) 
    .window(TumblingEventTimeWindows.of(Time.seconds(5))) 
    .apply (new JoinFunction () {...}); 

```

在 Scala 中：

```java
inputStream. join(inputStream1) 
    .where(0).equalTo(1) 
    .window(TumblingEventTimeWindows.of(Time.seconds(5))) 
    .apply { ... }
```

## 分割

此函数根据条件将流拆分为两个或多个流。当您获得混合流并且可能希望分别处理每个数据时，可以使用此函数。

在 Java 中：

```java
SplitStream<Integer> split = inputStream.split(new OutputSelector<Integer>() { 
    @Override 
    public Iterable<String> select(Integer value) { 
        List<String> output = new ArrayList<String>(); 
        if (value % 2 == 0) { 
            output.add("even"); 
        } 
        else { 
            output.add("odd"); 
        } 
        return output; 
    } 
}); 

```

在 Scala 中：

```java
val split = inputStream.split( 
  (num: Int) => 
    (num % 2) match { 
      case 0 => List("even") 
      case 1 => List("odd") 
    } 
) 

```

## 选择

此函数允许您从拆分流中选择特定流。

在 Java 中：

```java
SplitStream<Integer> split; 
DataStream<Integer> even = split.select("even"); 
DataStream<Integer> odd = split.select("odd"); 
DataStream<Integer> all = split.select("even","odd"); 

```

在 Scala 中：

```java
val even = split select "even" 
val odd = split select "odd" 
val all = split.select("even","odd") 

```

## 项目

`Project`函数允许您从事件流中选择一部分属性，并仅将选定的元素发送到下一个处理流。

在 Java 中：

```java
DataStream<Tuple4<Integer, Double, String, String>> in = // [...] 
DataStream<Tuple2<String, String>> out = in.project(3,2); 

```

在 Scala 中：

```java
val in : DataStream[(Int,Double,String)] = // [...] 
val out = in.project(3,2) 

```

前面的函数从给定记录中选择属性编号`2`和`3`。以下是示例输入和输出记录：

```java
(1,10.0, A, B )=> (B,A) 
(2,20.0, C, D )=> (D,C) 

```

# 物理分区

Flink 允许我们对流数据进行物理分区。您可以选择提供自定义分区。让我们看看不同类型的分区。

## 自定义分区

如前所述，您可以提供分区器的自定义实现。

在 Java 中：

```java
inputStream.partitionCustom(partitioner, "someKey"); 
inputStream.partitionCustom(partitioner, 0); 

```

在 Scala 中：

```java
inputStream.partitionCustom(partitioner, "someKey") 
inputStream.partitionCustom(partitioner, 0) 

```

在编写自定义分随机器时，您需要确保实现有效的哈希函数。

## 随机分区

随机分区以均匀的方式随机分区数据流。

在 Java 中：

```java
inputStream.shuffle(); 

```

在 Scala 中：

```java
inputStream.shuffle() 

```

## 重新平衡分区

这种类型的分区有助于均匀分布数据。它使用轮询方法进行分发。当数据发生偏斜时，这种类型的分区是很好的。

在 Java 中：

```java
inputStream.rebalance(); 

```

在 Scala 中：

```java
inputStream.rebalance() 

```

## 重新缩放

重新缩放用于在操作之间分发数据，对数据子集执行转换并将它们组合在一起。这种重新平衡仅在单个节点上进行，因此不需要在网络上进行任何数据传输。

以下图表显示了分布情况：

![重新缩放](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_02_003.jpg)

在 Java 中：

```java
inputStream.rescale(); 

```

在 Scala 中：

```java
inputStream.rescale() 

```

## 广播

广播将所有记录分发到每个分区。这会将每个元素扩展到所有分区。

在 Java 中：

```java
inputStream.broadcast(); 

```

在 Scala 中：

```java
inputStream.broadcast() 

```

# 数据接收器

数据转换完成后，我们需要将结果保存到某个地方。以下是 Flink 提供的一些保存结果的选项：

+   `writeAsText()`: 逐行将记录写为字符串。

+   `writeAsCsV()`: 将元组写为逗号分隔值文件。还可以配置行和字段分隔符。

+   `print()/printErr()`: 将记录写入标准输出。您也可以选择写入标准错误。

+   `writeUsingOutputFormat()`: 您还可以选择提供自定义输出格式。在定义自定义格式时，您需要扩展负责序列化和反序列化的`OutputFormat`。

+   `writeToSocket()`: Flink 还支持将数据写入特定的套接字。需要定义`SerializationSchema`以进行适当的序列化和格式化。

# 事件时间和水印

Flink Streaming API 受到 Google Data Flow 模型的启发。它支持其流式 API 的不同时间概念。一般来说，在流式环境中有三个地方可以捕获时间。它们如下

## 事件时间

事件发生的时间是指其产生设备上的时间。例如，在物联网项目中，传感器捕获读数的时间。通常这些事件时间需要在记录进入 Flink 之前嵌入。在处理时，这些时间戳被提取并考虑用于窗口处理。事件时间处理可以用于无序事件。

## 处理时间

处理时间是机器执行数据处理流的时间。处理时间窗口只考虑事件被处理的时间戳。处理时间是流处理的最简单方式，因为它不需要处理机器和生产机器之间的任何同步。在分布式异步环境中，处理时间不提供确定性，因为它取决于记录在系统中流动的速度。

## 摄取时间

这是特定事件进入 Flink 的时间。所有基于时间的操作都参考这个时间戳。摄取时间比处理时间更昂贵，但它提供可预测的结果。摄取时间程序无法处理任何无序事件，因为它只在事件进入 Flink 系统后分配时间戳。

以下是一个示例，显示了如何设置事件时间和水印。在摄取时间和处理时间的情况下，我们只需要时间特征，水印生成会自动处理。以下是相同的代码片段。

在 Java 中：

```java
final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment(); 
env.setStreamTimeCharacteristic(TimeCharacteristic.ProcessingTime); 
//or 
env.setStreamTimeCharacteristic(TimeCharacteristic.IngestionTime); 

```

在 Scala 中：

```java
val env = StreamExecutionEnvironment.getExecutionEnvironment 
env.setStreamTimeCharacteristic(TimeCharacteristic.ProcessingTime) 
//or  
env.setStreamTimeCharacteristic(TimeCharacteristic.IngestionTime) 

```

在事件时间流程序中，我们需要指定分配水印和时间戳的方式。有两种分配水印和时间戳的方式：

+   直接从数据源属性

+   使用时间戳分配器

要使用事件时间流，我们需要按照以下方式分配时间特征

在 Java 中：

```java
final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment(); 
env.setStreamTimeCharacteristic(TimeCharacteristic.EventTime; 

```

在 Scala 中：

```java
val env = StreamExecutionEnvironment.getExecutionEnvironment 
env.setStreamTimeCharacteristic(TimeCharacteristic.EventTime) 

```

在存储记录时，最好同时存储事件时间。Flink 还支持一些预定义的时间戳提取器和水印生成器。参考[`ci.apache.org/projects/flink/flink-docs-release-1.2/dev/event_timestamp_extractors.html`](https://ci.apache.org/projects/flink/flink-docs-release-1.2/dev/event_timestamp_extractors.html)。

# 连接器

Apache Flink 支持允许在各种技术之间读取/写入数据的各种连接器。让我们更多地了解这一点。

## Kafka 连接器

Kafka 是一个发布-订阅的分布式消息队列系统，允许用户向特定主题发布消息；然后将其分发给主题的订阅者。Flink 提供了在 Flink Streaming 中将 Kafka 消费者定义为数据源的选项。为了使用 Flink Kafka 连接器，我们需要使用特定的 JAR 文件。

以下图表显示了 Flink Kafka 连接器的工作原理：

![Kafka 连接器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_02_004.jpg)

我们需要使用以下 Maven 依赖项来使用连接器。我一直在使用 Kafka 版本 0.9，所以我将在`pom.xml`中添加以下依赖项：

```java
<dependency> 
  <groupId>org.apache.flink</groupId> 
  <artifactId>flink-connector-kafka-0.9_2.11/artifactId> 
  <version>1.1.4</version> 
</dependency> 

```

现在让我们试着理解如何将 Kafka 消费者作为 Kafka 源来使用：

在 Java 中：

```java
Properties properties = new Properties(); 
  properties.setProperty("bootstrap.servers", "localhost:9092"); 
  properties.setProperty("group.id", "test"); 
DataStream<String> input  = env.addSource(new FlinkKafkaConsumer09<String>("mytopic", new SimpleStringSchema(), properties)); 

```

在 Scala 中：

```java
val properties = new Properties(); 
properties.setProperty("bootstrap.servers", "localhost:9092"); 
// only required for Kafka 0.8 
properties.setProperty("zookeeper.connect", "localhost:2181"); 
properties.setProperty("group.id", "test"); 
stream = env 
    .addSource(new FlinkKafkaConsumer09String, properties)) 
    .print 

```

在上述代码中，我们首先设置了 Kafka 主机和 zookeeper 主机和端口的属性。接下来，我们需要指定主题名称，在本例中为`mytopic`。因此，如果任何消息发布到`mytopic`主题，它们将被 Flink 流处理。

如果您以不同的格式获取数据，那么您也可以为反序列化指定自定义模式。默认情况下，Flink 支持字符串和 JSON 反序列化器。

为了实现容错，我们需要在 Flink 中启用检查点。Flink 会定期对状态进行快照。在发生故障时，它将恢复到最后一个检查点，然后重新启动处理。

我们还可以将 Kafka 生产者定义为接收器。这将把数据写入 Kafka 主题。以下是将数据写入 Kafka 主题的方法：

在 Scala 中：

```java
stream.addSink(new FlinkKafkaProducer09<String>("localhost:9092", "mytopic", new SimpleStringSchema())); 

```

在 Java 中：

```java
stream.addSink(new FlinkKafkaProducer09String)) 

```

## Twitter 连接器

如今，从 Twitter 获取数据并处理数据非常重要。许多公司使用 Twitter 数据来进行各种产品、服务、电影、评论等的情感分析。Flink 提供 Twitter 连接器作为一种数据源。要使用连接器，您需要拥有 Twitter 账户。一旦您拥有了 Twitter 账户，您需要创建一个 Twitter 应用程序并生成用于连接器的身份验证密钥。以下是一个链接，可以帮助您生成令牌：[`dev.twitter.com/oauth/overview/application-owner-access-tokens`](https://dev.twitter.com/oauth/overview/application-owner-access-tokens)。

Twitter 连接器可以通过 Java 或 Scala API 使用：

![Twitter 连接器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_02_005.jpg)

生成令牌后，我们可以开始编写程序从 Twitter 获取数据。首先我们需要添加一个 Maven 依赖项：

```java
<dependency> 
  <groupId>org.apache.flink</groupId> 
  <artifactId>flink-connector-twitter_2.11/artifactId> 
  <version>1.1.4</version> 
</dependency> 

```

接下来我们将 Twitter 作为数据源。以下是示例代码：

在 Java 中：

```java
Properties props = new Properties(); 
props.setProperty(TwitterSource.CONSUMER_KEY, ""); 
props.setProperty(TwitterSource.CONSUMER_SECRET, ""); 
props.setProperty(TwitterSource.TOKEN, ""); 
props.setProperty(TwitterSource.TOKEN_SECRET, ""); 
DataStream<String> streamSource = env.addSource(new TwitterSource(props)); 

```

在 Scala 中：

```java
val props = new Properties(); 
props.setProperty(TwitterSource.CONSUMER_KEY, ""); 
props.setProperty(TwitterSource.CONSUMER_SECRET, ""); 
props.setProperty(TwitterSource.TOKEN, ""); 
props.setProperty(TwitterSource.TOKEN_SECRET, ""); 
DataStream<String> streamSource = env.addSource(new TwitterSource(props)); 

```

在上述代码中，我们首先为我们得到的令牌设置属性。然后我们添加`TwitterSource`。如果给定的信息是正确的，那么您将开始从 Twitter 获取数据。`TwitterSource`以 JSON 字符串格式发出数据。示例 Twitter JSON 如下所示：

```java
{ 
... 
"text": ""Loyalty 3.0: How to Revolutionize Customer &amp; Employee Engagement with Big Data &amp; #Gamification" can be ordered here: http://t.co/1XhqyaNjuR", 
  "geo": null, 
  "retweeted": false, 
  "in_reply_to_screen_name": null, 
  "possibly_sensitive": false, 
  "truncated": false, 
  "lang": "en", 
    "hashtags": [{ 
      "text": "Gamification", 
      "indices": [90, 
      103] 
    }], 
  }, 
  "in_reply_to_status_id_str": null, 
  "id": 330094515484508160 
... 
} 

```

`TwitterSource`提供各种端点。默认情况下，它使用`StatusesSampleEndpoint`，返回一组随机推文。如果您需要添加一些过滤器，并且不想使用默认端点，可以实现`TwitterSource.EndpointInitializer`接口。

现在我们知道如何从 Twitter 获取数据，然后可以根据我们的用例决定如何处理这些数据。我们可以处理、存储或分析数据。

## RabbitMQ 连接器

RabbitMQ 是一个广泛使用的分布式、高性能的消息队列系统。它用作高吞吐量操作的消息传递系统。它允许您创建分布式消息队列，并在队列中包括发布者和订阅者。可以在以下链接进行更多关于 RabbitMQ 的阅读[`www.rabbitmq.com/`](https://www.rabbitmq.com/)

Flink 支持从 RabbitMQ 获取和发布数据。它提供了一个连接器，可以作为数据流的数据源。

为了使 RabbitMQ 连接器工作，我们需要提供以下信息：

+   RabbitMQ 配置，如主机、端口、用户凭据等。

+   队列，您希望订阅的 RabbitMQ 队列的名称。

+   关联 ID 是 RabbitMQ 的一个特性，用于在分布式世界中通过唯一 ID 相关请求和响应。Flink RabbitMQ 连接器提供了一个接口，可以根据您是否使用它来设置为 true 或 false。

+   反序列化模式--RabbitMQ 以序列化方式存储和传输数据，以避免网络流量。因此，当接收到消息时，订阅者应该知道如何反序列化消息。Flink 连接器为我们提供了一些默认的反序列化器，如字符串反序列化器。

RabbitMQ 源为我们提供了以下关于流传递的选项：

+   确切一次：使用 RabbitMQ 关联 ID 和 Flink 检查点机制与 RabbitMQ 事务

+   至少一次：当启用 Flink 检查点但未设置 RabbitMQ 关联 ID 时

+   RabbitMQ 自动提交模式没有强有力的交付保证

以下是一个图表，可以帮助您更好地理解 RabbitMQ 连接器：

![RabbitMQ 连接器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_02_006.jpg)

现在让我们看看如何编写代码来使这个连接器工作。与其他连接器一样，我们需要向代码添加一个 Maven 依赖项：

```java
<dependency> 
  <groupId>org.apache.flink</groupId> 
  <artifactId>flink-connector-rabbitmq_2.11/artifactId> 
  <version>1.1.4</version> 
</dependency> 

```

以下代码段显示了如何在 Java 中使用 RabbitMQ 连接器：

```java
//Configurations 
RMQConnectionConfig connectionConfig = new RMQConnectionConfig.Builder() 
.setHost(<host>).setPort(<port>).setUserName(..) 
.setPassword(..).setVirtualHost("/").build(); 

//Get Data Stream without correlation ids 
DataStream<String> streamWO = env.addSource(new RMQSource<String>(connectionConfig, "my-queue", new SimpleStringSchema())) 
  .print 
//Get Data Stream with correlation ids 
DataStream<String> streamW = env.addSource(new RMQSource<String>(connectionConfig, "my-queue", true, new SimpleStringSchema())) 
  .print 

```

同样，在 Scala 中，代码可以写成如下形式：

```java
val connectionConfig = new RMQConnectionConfig.Builder() 
.setHost(<host>).setPort(<port>).setUserName(..) 
.setPassword(..).setVirtualHost("/").build() 
streamsWOIds = env 
    .addSource(new RMQSourceString) 
    .print 

streamsWIds = env 
    .addSource(new RMQSourceString) 
    .print 

```

我们还可以使用 RabbitMQ 连接器作为 Flink sink。如果要将处理过的数据发送回不同的 RabbitMQ 队列，可以按以下方式操作。我们需要提供三个重要的配置：

+   RabbitMQ 配置

+   队列名称--要将处理过的数据发送回哪里

+   序列化模式--RabbitMQ 的模式，将数据转换为字节

以下是 Java 中的示例代码，展示了如何将此连接器用作 Flink sink：

```java
RMQConnectionConfig connectionConfig = new RMQConnectionConfig.Builder() 
.setHost(<host>).setPort(<port>).setUserName(..) 
.setPassword(..).setVirtualHost("/").build(); 
stream.addSink(new RMQSink<String>(connectionConfig, "target-queue", new StringToByteSerializer())); 

```

在 Scala 中也可以这样做：

```java
val connectionConfig = new RMQConnectionConfig.Builder() 
.setHost(<host>).setPort(<port>).setUserName(..) 
.setPassword(..).setVirtualHost("/").build() 
stream.addSink(new RMQSinkString。

在许多用例中，您可能希望使用 Flink 处理数据，然后将其存储在 ElasticSearch 中。为此，Flink 支持 ElasticSearch 连接器。到目前为止，ElasticSearch 已经发布了两个主要版本。Flink 支持它们两个。

对于 ElasticSearch 1.X，需要添加以下 Maven 依赖项：

```java
<dependency> 
  <groupId>org.apache.flink</groupId> 
  <artifactId>flink-connector-elasticsearch_2.11</artifactId> 
  <version>1.1.4</version> 
</dependency> 

```

Flink 连接器提供了一个 sink，用于将数据写入 ElasticSearch。它使用两种方法连接到 ElasticSearch：

+   嵌入式节点

+   传输客户端

以下图表说明了这一点：

![ElasticSearch 连接器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_02_007.jpg)

### 嵌入式节点模式

在嵌入式节点模式中，sink 使用 BulkProcessor 将文档发送到 ElasticSearch。我们可以配置在将文档发送到 ElasticSearch 之前缓冲多少个请求。

以下是代码片段：

```java
DataStream<String> input = ...; 

Map<String, String> config = Maps.newHashMap(); 
config.put("bulk.flush.max.actions", "1"); 
config.put("cluster.name", "cluster-name"); 

input.addSink(new ElasticsearchSink<>(config, new IndexRequestBuilder<String>() { 
    @Override 
    public IndexRequest createIndexRequest(String element, RuntimeContext ctx) { 
        Map<String, Object> json = new HashMap<>(); 
        json.put("data", element); 

        return Requests.indexRequest() 
                .index("my-index") 
                .type("my-type") 
                .source(json); 
    } 
})); 

```

在上述代码片段中，我们创建了一个哈希映射，其中包含集群名称以及在发送请求之前要缓冲多少个文档的配置。然后我们将 sink 添加到流中，指定要存储的索引、类型和文档。在 Scala 中也有类似的代码：

```java
val input: DataStream[String] = ... 

val config = new util.HashMap[String, String] 
config.put("bulk.flush.max.actions", "1") 
config.put("cluster.name", "cluster-name") 

text.addSink(new ElasticsearchSink(config, new IndexRequestBuilder[String] { 
  override def createIndexRequest(element: String, ctx: RuntimeContext): IndexRequest = { 
    val json = new util.HashMap[String, AnyRef] 
    json.put("data", element) 
    Requests.indexRequest.index("my-index").`type`("my-type").source(json) 
  } 
})) 

```

### 传输客户端模式

ElasticSearch 允许通过端口 9300 的传输客户端进行连接。Flink 支持通过其连接器使用这些连接。这里唯一需要提到的是配置中存在的所有 ElasticSearch 节点。

以下是 Java 中的片段：

```java
DataStream<String> input = ...; 

Map<String, String> config = Maps.newHashMap(); 
config.put("bulk.flush.max.actions", "1"); 
config.put("cluster.name", "cluster-name"); 

List<TransportAddress> transports = new ArrayList<String>(); 
transports.add(new InetSocketTransportAddress("es-node-1", 9300)); 
transports.add(new InetSocketTransportAddress("es-node-2", 9300)); 
transports.add(new InetSocketTransportAddress("es-node-3", 9300)); 

input.addSink(new ElasticsearchSink<>(config, transports, new IndexRequestBuilder<String>() { 
    @Override 
    public IndexRequest createIndexRequest(String element, RuntimeContext ctx) { 
        Map<String, Object> json = new HashMap<>(); 
        json.put("data", element); 

        return Requests.indexRequest() 
                .index("my-index") 
                .type("my-type") 
                .source(json); 
    } 
})); 

```

在这里，我们还提供了有关集群名称、节点、端口、发送的最大请求数等的详细信息。在 Scala 中，类似的代码可以编写如下：

```java
val input: DataStream[String] = ... 

val config = new util.HashMap[String, String] 
config.put("bulk.flush.max.actions", "1") 
config.put("cluster.name", "cluster-name") 

val transports = new ArrayList[String] 
transports.add(new InetSocketTransportAddress("es-node-1", 9300)) 
transports.add(new InetSocketTransportAddress("es-node-2", 9300)) 
transports.add(new InetSocketTransportAddress("es-node-3", 9300)) 

text.addSink(new ElasticsearchSink(config, transports, new IndexRequestBuilder[String] { 
  override def createIndexRequest(element: String, ctx: RuntimeContext): IndexRequest = { 
    val json = new util.HashMap[String, AnyRef] 
    json.put("data", element) 
    Requests.indexRequest.index("my-index").`type`("my-type").source(json) 
  } 
})) 

```

## Cassandra 连接器

Cassandra 是一个分布式、低延迟的 NoSQL 数据库。它是一个基于键值的数据库。许多高吞吐量应用程序将 Cassandra 用作其主要数据库。Cassandra 使用分布式集群模式，其中没有主从架构。任何节点都可以进行读取和写入。有关 Cassandra 的更多信息可以在此处找到：[`cassandra.apache.org/`](http://cassandra.apache.org/)。

Apache Flink 提供了一个连接器，可以将数据写入 Cassandra。在许多应用程序中，人们可能希望将来自 Flink 的流数据存储到 Cassandra 中。以下图表显示了 Cassandra sink 的简单设计：

![Cassandra 连接器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_02_008.jpg)

与其他连接器一样，要获得此连接器，我们需要将其添加为 Maven 依赖项：

```java
<dependency> 
  <groupId>org.apache.flink</groupId> 
  <artifactId>flink-connector-cassandra_2.11</artifactId> 
  <version>1.1.4</version> 
</dependency>
```

一旦添加了依赖项，我们只需要添加 Cassandra sink 及其配置，如下所示：

在 Java 中：

```java
CassandraSink.addSink(input) 
  .setQuery("INSERT INTO cep.events (id, message) values (?, ?);") 
  .setClusterBuilder(new ClusterBuilder() { 
    @Override 
    public Cluster buildCluster(Cluster.Builder builder) { 
      return builder.addContactPoint("127.0.0.1").build(); 
    } 
  }) 
  .build() 

```

上述代码将数据流写入名为**events**的表中。该表期望事件 ID 和消息。在 Scala 中也是如此：

```java
CassandraSink.addSink(input) 
  .setQuery("INSERT INTO cep.events (id, message) values (?, ?);") 
  .setClusterBuilder(new ClusterBuilder() { 
    @Override 
    public Cluster buildCluster(Cluster.Builder builder) { 
      return builder.addContactPoint("127.0.0.1").build(); 
    } 
  }) 
  .build(); 

```

# 用例 - 传感器数据分析

既然我们已经看过了 DataStream API 的各个方面，让我们尝试使用这些概念来解决一个真实的用例。考虑一个安装了传感器的机器，我们希望从这些传感器收集数据，并计算每五分钟每个传感器的平均温度。

以下是架构：

![用例 - 传感器数据分析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_02_009.jpg)

在这种情况下，我们假设传感器正在向名为**temp**的 Kafka 主题发送信息，信息格式为（时间戳，温度，传感器 ID）。现在我们需要编写代码从 Kafka 主题中读取数据，并使用 Flink 转换进行处理。

在这里需要考虑的重要事情是，由于我们已经从传感器那里得到了时间戳数值，我们可以使用事件时间计算来处理时间因素。这意味着即使事件到达时是无序的，我们也能够处理这些事件。

我们从简单的流执行环境开始，它将从 Kafka 中读取数据。由于事件中有时间戳，我们将编写自定义的时间戳和水印提取器来读取时间戳数值，并根据此进行窗口处理。以下是相同的代码片段。

```java
// set up the streaming execution environment 
final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment(); 
// env.enableCheckpointing(5000); 
nv.setStreamTimeCharacteristic(TimeCharacteristic.EventTime); 
Properties properties = new Properties(); 
properties.setProperty("bootstrap.servers", "localhost:9092"); 

properties.setProperty("zookeeper.connect", "localhost:2181"); 
properties.setProperty("group.id", "test"); 

FlinkKafkaConsumer09<String> myConsumer = new FlinkKafkaConsumer09<>("temp", new SimpleStringSchema(), 
                      properties); 
myConsumer.assignTimestampsAndWatermarks(new CustomWatermarkEmitter()); 

```

在这里，我们假设我们从 Kafka 主题中以字符串格式接收事件，并且格式为：

```java
Timestamp,Temperature,Sensor-Id
```

以下是从记录中提取时间戳的示例代码：

```java
public class CustomWatermarkEmitter implements AssignerWithPunctuatedWatermarks<String> {
    private static final long serialVersionUID = 1L;

    @Override
    public long extractTimestamp(String arg0, long arg1) {
        if (null != arg0 && arg0.contains(",")) {
           String parts[] = arg0.split(",");
           return Long.parseLong(parts[0]);
           }

          return 0;
    }
    @Override
    public Watermark checkAndGetNextWatermark(String arg0, long arg1) {
        if (null != arg0 && arg0.contains(",")) {
            String parts[] = arg0.split(",");
            return new Watermark(Long.parseLong(parts[0]));
        }
        return null;
    }
}
```

现在我们简单地创建了分区数据流，并对温度数值进行了平均计算，如下面的代码片段所示：

```java
DataStream<Tuple2<String, Double>> keyedStream = env.addSource(myConsumer).flatMap(new Splitter()).keyBy(0)
.timeWindow(Time.seconds(300))
.apply(new WindowFunction<Tuple2<String, Double>, Tuple2<String, Double>, Tuple, TimeWindow>() {
    @Override
    public void apply(Tuple key, TimeWindow window, 
    Iterable<Tuple2<String, Double>> input,
    Collector<Tuple2<String, Double>> out) throws Exception {
        double sum = 0L;
            int count = 0;
            for (Tuple2<String, Double> record : input) {
                sum += record.f1;
                count++;
            }
     Tuple2<String, Double> result = input.iterator().next();
     result.f1 = (sum/count);
     out.collect(result);
   }
});
```

当执行上述给定的代码时，如果在 Kafka 主题上发布了适当的传感器事件，那么我们将每五分钟得到每个传感器的平均温度。

完整的代码可以在 GitHub 上找到：[`github.com/deshpandetanmay/mastering-flink/tree/master/chapter02/flink-streaming`](https://github.com/deshpandetanmay/mastering-flink/tree/master/chapter02/flink-streaming)。

# 总结

在本章中，我们从 Flink 最强大的 API 开始：DataStream API。我们看了数据源、转换和接收器是如何一起工作的。然后我们看了各种技术连接器，比如 ElasticSearch、Cassandra、Kafka、RabbitMQ 等等。

最后，我们还尝试将我们的学习应用于解决真实世界的传感器数据分析用例。

在下一章中，我们将学习 Flink 生态系统中另一个非常重要的 API，即 DataSet API。


# 第三章：使用批处理 API 进行数据处理

尽管许多人欣赏流数据处理在大多数行业中的潜在价值，但也有许多用例，人们认为不需要以流式方式处理数据。在所有这些情况下，批处理是前进的方式。到目前为止，Hadoop 一直是数据处理的默认选择。但是，Flink 也通过 DataSet API 支持批处理数据处理。

对于 Flink，批处理是流处理的一种特殊情况。在[`data-artisans.com/batch-is-a-special-case-of-streaming/`](http://data-artisans.com/batch-is-a-special-case-of-streaming/)上有一篇非常有趣的文章详细解释了这个想法。

在本章中，我们将详细了解 DataSet API 的详细信息。这包括以下主题：

+   数据源

+   转换

+   数据接收器

+   连接器

正如我们在上一章中学到的，任何 Flink 程序都遵循以下定义的解剖结构：

![使用批处理 API 进行数据处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_03_001.jpg)

DataSet API 也不例外。我们将详细了解每个步骤。我们已经在上一章中讨论了如何获取执行环境。因此，我们将直接转向 DataSet API 支持的数据源的详细信息。

# 数据源

源是 DataSet API 期望从中获取数据的地方。它可以是文件形式，也可以是来自 Java 集合。这是 Flink 程序解剖的第二步。DataSet API 支持许多预先实现的数据源函数。它还支持编写自定义数据源函数，因此可以轻松地编程任何不受支持的内容。首先让我们尝试理解内置的源函数。

## 基于文件的

Flink 支持从文件中读取数据。它逐行读取数据并将其作为字符串返回。以下是您可以使用的内置函数来读取数据：

+   `readTextFile(Stringpath)`: 从指定路径读取文件中的数据。默认情况下，它将读取`TextInputFormat`并逐行读取字符串。

+   `readTextFileWithValue(Stringpath)`: 从指定路径读取文件中的数据。它返回`StringValues`。`StringValues`是可变字符串。

+   `readCsvFile(Stringpath)`: 从逗号分隔的文件中读取数据。它返回 Java POJOs 或元组。

+   `readFileofPremitives(path, delimiter, class)`: 将新行解析为原始数据类型，如字符串或整数。

+   `readHadoopFile(FileInputFormat, Key, Value, path)`: 从指定路径使用给定的`FileInputFormat`、`Key`类和`Value`类读取文件。它将解析后的值返回为元组`Tuple2<Key,Value>`。

+   `readSequenceFile(Key, Value, path)`: 从指定路径使用给定的`SequenceFileInputFormat`、`Key`类和`Value`类读取文件。它将解析后的值返回为元组`Tuple2<Key,Value>`。

### 注意

对于基于文件的输入，Flink 支持递归遍历指定路径中的文件夹。为了使用这个功能，我们需要设置一个环境变量，并在读取数据时将其作为参数传递。要设置的变量是`recursive.file.enumeration`。我们需要将此变量设置为`true`以启用递归遍历。

## 基于集合的

使用 Flink DataSet API，我们还可以从基于 Java 的集合中读取数据。以下是一些我们可以使用的函数来读取数据：

+   `fromCollection(Collection)`: 从基于 Java 的集合创建数据集。

+   `fromCollection(Iterator, Class)`: 从迭代器创建数据集。迭代器的元素由类参数给定的类型。

+   `fromElements(T)`: 创建一个包含一系列对象的数据集。对象类型在函数本身中指定。

+   `fromParallelCollection(SplittableIterator, Class)`: 这将并行从迭代器创建数据集。Class 代表对象类型。

+   `generateSequence(from, to)`: 生成给定范围内的数字序列。

## 通用源

DataSet API 支持一些通用函数来读取数据：

+   `readFile(inputFormat, path)`: 这将从给定路径创建一个`FileInputFormat`类型的数据集

+   `createInput(inputFormat)`: 这将创建一个通用输入格式的数据集

## 压缩文件

Flink 支持在读取文件时解压缩文件，如果它们标有适当的扩展名。我们不需要对读取压缩文件进行任何不同的配置。如果检测到具有适当扩展名的文件，则 Flink 会自动解压缩并发送到进一步处理。

这里需要注意的一点是，文件的解压缩不能并行进行，因此在实际数据处理开始之前可能需要一些时间。

在这个阶段，建议避免使用压缩文件，因为在 Flink 中解压缩不是可扩展的活动。

支持以下算法：

| **压缩算法** | **扩展名** | **是否并行？** |
| --- | --- | --- |
| Gzip | `.gz`, `.gzip` | 否 |
| Deflate | `.deflate` | 否 |

# 转换

数据转换将数据集从一种形式转换为另一种形式。输入可以是一个或多个数据集，输出也可以是零个、一个或多个数据流。现在让我们逐个了解每个转换。

## 映射

这是最简单的转换之一，输入是一个数据集，输出也是一个数据集。

在 Java 中：

```java
inputSet.map(new MapFunction<Integer, Integer>() { 
  @Override 
  public Integer map(Integer value) throws Exception { 
        return 5 * value; 
      } 
    }); 

```

在 Scala 中：

```java
inputSet.map { x => x * 5 } 

```

在 Python 中：

```java
inputSet.map { lambda x : x * 5 } 

```

## Flat map

flat map 接受一个记录并输出零个、一个或多个记录。

在 Java 中：

```java
inputSet.flatMap(new FlatMapFunction<String, String>() { 
    @Override 
    public void flatMap(String value, Collector<String> out) 
        throws Exception { 
        for(String word: value.split(" ")){ 
            out.collect(word); 
        } 
    } 
}); 

```

在 Scala 中：

```java
inputSet.flatMap { str => str.split(" ") } 

```

在 Python 中：

```java
inputSet.flat_map {lambda str, c:[str.split() for line in str } 

```

## 过滤

过滤函数评估条件，然后如果返回`true`则只发出记录。过滤函数可以输出零个记录。

在 Java 中：

```java
inputSet.filter(new FilterFunction<Integer>() { 
    @Override 
    public boolean filter(Integer value) throws Exception { 
        return value != 1; 
    } 
}); 
In Scala: 
inputSet.filter { _ != 1 } 

```

在 Python 中：

```java
inputSet.filter {lambda x: x != 1 } 

```

## 项目

项目转换删除或移动元组的元素到另一个元组。这可以用来对特定元素进行选择性处理。

在 Java 中：

```java
DataSet<Tuple3<Integer, String, Double>> in = // [...] 
DataSet<Tuple2<String, Integer>> out = in.project(1,0); 

```

在 Scala 中，不支持这种转换。

在 Python 中：

```java
inputSet.project(1,0) 

```

## 对分组数据集进行减少

减少转换根据用户定义的减少函数将每个组减少为单个元素。

在 Java 中：

```java
public class WC { 
  public String word; 
  public int count; 
} 

//Reduce function 
public class WordCounter implements ReduceFunction<WC> { 
  @Override 
  public WC reduce(WC in1, WC in2) { 
    return new WC(in1.word, in1.count + in2.count); 
  } 
} 

// [...] 
DataSet<WC> words = // [...] 
DataSet<WC> wordCounts = words 
                         // grouping on field "word" 
                         .groupBy("word") 
                         // apply ReduceFunction on grouped DataSet 
                         .reduce(new WordCounter()); 

```

在 Scala 中：

```java
class WC(val word: String, val count: Int) { 
  def this() { 
    this(null, -1) 
  } 
} 

val words: DataSet[WC] = // [...] 
val wordCounts = words.groupBy("word").reduce { 
  (w1, w2) => new WC(w1.word, w1.count + w2.count) 
} 

```

在 Python 中，代码不受支持。

## 按字段位置键对分组数据集进行减少

对于元组数据集，我们也可以按字段位置进行分组。以下是一个例子。

在 Java 中：

```java
DataSet<Tuple3<String, Integer, Double>> reducedTuples = tuples 
                           // group by on second and third field  
                            .groupBy(1, 2) 
                            // apply ReduceFunction 
                            .reduce(new MyTupleReducer()); 

```

在 Scala 中：

```java
val reducedTuples = tuples.groupBy(1, 2).reduce { ... } 

```

在 Python 中：

```java
reducedTuples = tuples.group_by(1, 2).reduce( ... ) 

```

## 组合组

在一些应用中，在进行一些更多的转换之前进行中间操作非常重要。在这种情况下，组合操作非常方便。中间转换可以减小大小等。

这是使用贪婪策略在内存中执行的，需要进行多个步骤。

在 Java 中：

```java
DataSet<String> input = [..]  

  DataSet<Tuple2<String, Integer>> combinedWords = input 
  .groupBy(0); // group similar words 
  .combineGroup(new GroupCombineFunction<String, Tuple2<String,  
   Integer>() { 

    public void combine(Iterable<String> words,   
    Collector<Tuple2<String, Integer>>) { // combine 
        String key = null; 
        int count = 0; 

        for (String word : words) { 
            key = word; 
            count++; 
        } 
        // emit tuple with word and count 
        out.collect(new Tuple2(key, count)); 
    } 
}); 

```

在 Scala 中：

```java
val input: DataSet[String] = [..]  

val combinedWords: DataSet[(String, Int)] = input 
  .groupBy(0) 
  .combineGroup { 
    (words, out: Collector[(String, Int)]) => 
        var key: String = null 
        var count = 0 

        for (word <- words) { 
            key = word 
            count += 1 
        } 
        out.collect((key, count)) 
} 

```

在 Python 中，不支持这段代码。

## 对分组元组数据集进行聚合

聚合转换非常常见。我们可以很容易地对元组数据集执行常见的聚合，如`sum`、`min`和`max`。以下是我们执行的方式。

在 Java 中：

```java
DataSet<Tuple3<Integer, String, Double>> input = // [...] 
DataSet<Tuple3<Integer, String, Double>> output = input 
             .groupBy(1)        // group DataSet on second field 
             .aggregate(SUM, 0) // compute sum of the first field 
             .and(MIN, 2);      // compute minimum of the third field 

```

在 Scala 中：

```java
val input: DataSet[(Int, String, Double)] = // [...] 
val output = input.groupBy(1).aggregate(SUM, 0).and(MIN, 2) 

```

在 Python 中：

```java
input = # [...] 
output = input.group_by(1).aggregate(Sum, 0).and_agg(Min, 2) 

```

请注意，在 DataSet API 中，如果我们需要应用多个聚合，我们需要使用`and`关键字。

## 对分组元组数据集进行 MinBy

`minBy`函数从元组数据集的每个组中选择一个元组，其值为最小值。用于比较的字段必须是可比较的。

在 Java 中：

```java
DataSet<Tuple3<Integer, String, Double>> input = // [...] 
DataSet<Tuple3<Integer, String, Double>> output = input 
                  .groupBy(1)   // group by on second field 
                  .minBy(0, 2); // select tuple with minimum values for first and third field. 

```

在 Scala 中：

```java
val input: DataSet[(Int, String, Double)] = // [...] 
val output: DataSet[(Int, String, Double)] = input 
           .groupBy(1)                                     
           .minBy(0, 2)
```

在 Python 中，不支持这段代码。

## 对分组元组数据集进行 MaxBy

`MaxBy`函数从元组数据集的每个组中选择一个元组，其值为最大值。用于比较的字段必须是可比较的。

在 Java 中：

```java
DataSet<Tuple3<Integer, String, Double>> input = // [...] 
DataSet<Tuple3<Integer, String, Double>> output = input 
                  .groupBy(1)   // group by on second field 
                  .maxBy(0, 2); // select tuple with maximum values for         
                                /*first and third field. */

```

在 Scala 中：

```java
val input: DataSet[(Int, String, Double)] = // [...] 
val output: DataSet[(Int, String, Double)] = input 
.groupBy(1)                                    
.maxBy(0, 2)  

```

在 Python 中，不支持这段代码。

## 对完整数据集进行减少

减少转换允许在整个数据集上应用用户定义的函数。以下是一个例子。

在 Java 中：

```java
public class IntSumReducer implements ReduceFunction<Integer> { 
  @Override 
  public Integer reduce(Integer num1, Integer num2) { 
    return num1 + num2; 
  } 
} 

DataSet<Integer> intNumbers = // [...] 
DataSet<Integer> sum = intNumbers.reduce(new IntSumReducer()); 

```

在 Scala 中：

```java
val sum = intNumbers.reduce (_ + _) 

```

在 Python 中：

```java
sum = intNumbers.reduce(lambda x,y: x + y) 

```

## 对完整数据集进行组减少

组减少转换允许在整个数据集上应用用户定义的函数。以下是一个例子。

在 Java 中：

```java
DataSet<Integer> input = // [...] 
DataSet<Integer> output = input.reduceGroup(new MyGroupReducer()); 

```

在 Scala 中：

```java
val input: DataSet[Int] = // [...] 
val output = input.reduceGroup(new MyGroupReducer())  

```

在 Python 中：

```java
output = data.reduce_group(MyGroupReducer()) 

```

## 对完整元组数据集进行聚合

我们可以对完整数据集运行常见的聚合函数。到目前为止，Flink 支持`MAX`、`MIN`和`SUM`。

在 Java 中：

```java
DataSet<Tuple2<Integer, Double>> output = input 
.aggregate(SUM, 0) // SUM of first field                   
.and(MIN, 1); // Minimum of second  

```

在 Scala 中：

```java
val input: DataSet[(Int, String, Double)] = // [...] 
val output = input.aggregate(SUM, 0).and(MIN, 2)  

```

在 Python 中：

```java
output = input.aggregate(Sum, 0).and_agg(Min, 2) 

```

## 在完整元组数据集上的 MinBy

`MinBy`函数从完整数据集中选择一个数值最小的元组。用于比较的字段必须是可比较的。

在 Java 中：

```java
DataSet<Tuple3<Integer, String, Double>> input = // [...] 
DataSet<Tuple3<Integer, String, Double>> output = input 
                  .minBy(0, 2); // select tuple with minimum values for 
                                first and third field. 

```

在 Scala 中：

```java
val input: DataSet[(Int, String, Double)] = // [...] 
val output: DataSet[(Int, String, Double)] = input 
.minBy(0, 2)  

```

在 Python 中，此代码不受支持。

## 在完整元组数据集上的 MaxBy

`MaxBy`选择数值最大的单个元组完整数据集。用于比较的字段必须是可比较的。

在 Java 中：

```java
DataSet<Tuple3<Integer, String, Double>> input = // [...] 
DataSet<Tuple3<Integer, String, Double>> output = input 
                 .maxBy(0, 2); // select tuple with maximum values for first and third field. 

```

在 Scala 中：

```java
val input: DataSet[(Int, String, Double)] = // [...] 
val output: DataSet[(Int, String, Double)] = input 
                                  .maxBy(0, 2)  

```

在 Python 中，此代码不受支持。

## 不同

distinct 转换从源数据集中发出不同的值。这用于从源中删除重复的值。

在 Java 中：

```java
DataSet<Tuple2<Integer, Double>> output = input.distinct(); 

```

在 Scala 中：

```java
val output = input.distinct() 

```

在 Python 中，此代码不受支持。

## 连接

join 转换将两个数据集连接成一个数据集。连接条件可以定义为每个数据集的一个键。

在 Java 中：

```java
public static class Student { public String name; public int deptId; } 
public static class Dept { public String name; public int id; } 
DataSet<Student> input1 = // [...] 
DataSet<Dept> input2 = // [...] 
DataSet<Tuple2<Student, Dept>> 
            result = input1.join(input2) 
.where("deptId")                                  
.equalTo("id"); 

```

在 Scala 中：

```java
val input1: DataSet[(String, Int)] = // [...] 
val input2: DataSet[(String, Int)] = // [...] 
val result = input1.join(input2).where(1).equalTo(1) 

```

在 Python 中

```java
result = input1.join(input2).where(1).equal_to(1)  

```

### 注意

有各种其他方式可以连接两个数据集。在这里有一个链接，您可以阅读更多关于所有这些连接选项的信息：[`ci.apache.org/projects/flink/flink-docs-master/dev/batch/dataset_transformations.html#join`](https://ci.apache.org/projects/flink/flink-docs-master/dev/batch/dataset_transformations.html#join)。

## 交叉

交叉转换通过应用用户定义的函数对两个数据集进行交叉乘积。

在 Java 中：

```java
DataSet<Class> input1 = // [...] 
DataSet<class> input2 = // [...] 
DataSet<Tuple3<Integer, Integer, Double>> 
            result = 
            input1.cross(input2) 
                   // applying CrossFunction 
                   .with(new MyCrossFunction()); 

```

在 Scala 中：

```java
val result = input1.cross(input2) { 
//custom function 
} 

```

在 Python 中：

```java
result = input1.cross(input2).using(MyCrossFunction()) 

```

## 联合

union 转换结合了两个相似的数据集。我们也可以一次联合多个数据集。

在 Java 中：

```java
DataSet<Tuple2<String, Integer>> input1 = // [...] 
DataSet<Tuple2<String, Integer>> input2 = // [...] 
DataSet<Tuple2<String, Integer>> input3 = // [...] 
DataSet<Tuple2<String, Integer>> unioned = input1.union(input2).union(input3); 

```

在 Scala 中：

```java
val input1: DataSet[(String, Int)] = // [...] 
val input2: DataSet[(String, Int)] = // [...] 
val input3: DataSet[(String, Int)] = // [...] 
val unioned = input1.union(input2).union(input3)  

```

在 Python 中：

```java
unioned = input1.union(input2).union(input3) 

```

## 重新平衡

这个转换均匀地重新平衡并行分区。这有助于提高性能，因为它有助于消除数据倾斜。

在 Java 中：

```java
DataSet<String> in = // [...] 
DataSet<Tuple2<String, String>> out = in.rebalance(); 

```

在 Scala 中：

```java
val in: DataSet[String] = // [...] 
val out = in.rebalance() 

```

在 Python 中，此代码不受支持。

## 哈希分区

这个转换在给定的键上对数据集进行分区。

在 Java 中：

```java
DataSet<Tuple2<String, Integer>> in = // [...] 
DataSet<Tuple2<String, String>> out = in.partitionByHash(1); 

```

在 Scala 中：

```java
val in: DataSet[(String, Int)] = // [...] 
val out = in.partitionByHash(1) 

```

在 Python 中，此代码不受支持。

## 范围分区

这个转换在给定的键上对数据集进行范围分区。

在 Java 中：

```java
DataSet<Tuple2<String, Integer>> in = // [...] 
DataSet<Tuple2<String, String>> out = in.partitionByRange(1); 

```

在 Scala 中：

```java
val in: DataSet[(String, Int)] = // [...] 
val out = in.partitionByRange(1) 

```

在 Python 中，此代码不受支持。

## 排序分区

这个转换在给定的键和给定的顺序上本地对分区数据集进行排序。

在 Java 中：

```java
DataSet<Tuple2<String, Integer>> in = // [...] 
DataSet<Tuple2<String, String>> out = in.sortPartition(1,Order.ASCENDING); 

```

在 Scala 中：

```java
val in: DataSet[(String, Int)] = // [...] 
val out = in.sortPartition(1, Order.ASCENDING) 

```

在 Python 中，此代码不受支持。

## 首 n

这个转换任意返回数据集的前 n 个元素。

在 Java 中：

```java
DataSet<Tuple2<String, Integer>> in = // [...] 
// Returns first 10 elements of the data set.  
DataSet<Tuple2<String, String>> out = in.first(10); 

```

在 Scala 中：

```java
val in: DataSet[(String, Int)] = // [...] 
val out = in.first(10) 

```

在 Python 中，此代码不受支持。

# 广播变量

广播变量允许用户将某些数据集作为集合访问到所有操作符。通常，当您希望在某个操作中频繁引用少量数据时，可以使用广播变量。熟悉 Spark 广播变量的人也可以在 Flink 中使用相同的功能。

我们只需要广播一个具有特定名称的数据集，它将在每个执行器上都可用。广播变量保存在内存中，因此在使用它们时必须谨慎。以下代码片段显示了如何广播数据集并根据需要使用它。

```java
// Get a data set to be broadcasted 
DataSet<Integer> toBroadcast = env.fromElements(1, 2, 3); 
DataSet<String> data = env.fromElements("India", "USA", "UK").map(new RichMapFunction<String, String>() { 
    private List<Integer> toBroadcast; 
    // We have to use open method to get broadcast set from the context 
    @Override 
    public void open(Configuration parameters) throws Exception { 
    // Get the broadcast set, available as collection 
    this.toBroadcast = 
    getRuntimeContext().getBroadcastVariable("country"); 
    } 

    @Override 
    public String map(String input) throws Exception { 
          int sum = 0; 
          for (int a : toBroadcast) { 
                sum = a + sum; 
          } 
          return input.toUpperCase() + sum; 
    } 
}).withBroadcastSet(toBroadcast, "country"); // Broadcast the set with name 
data.print(); 

```

当我们有查找条件要用于转换时，广播变量非常有用，查找数据集相对较小。

# 数据接收器

数据转换完成后，我们需要将结果保存在某个地方。以下是 Flink DataSet API 提供的一些选项，用于保存结果：

+   `writeAsText()`: 这将记录一行一行地写入字符串。

+   `writeAsCsV()`: 这将元组写为逗号分隔值文件。还可以配置行和字段分隔符。

+   `print()`/`printErr()`: 这将记录写入标准输出。您也可以选择写入标准错误。

+   `write()`: 这支持在自定义`FileOutputFormat`中写入数据。

+   `output()`: 这用于不基于文件的数据集。这可以用于我们想要将数据写入某个数据库的地方。

# 连接器

Apache Flink 的 DataSet API 支持各种连接器，允许在各种系统之间读取/写入数据。让我们尝试更多地探索这一点。

## 文件系统

Flink 允许默认连接到各种分布式文件系统，如 HDFS、S3、Google Cloud Storage、Alluxio 等。在本节中，我们将看到如何连接到这些文件系统。

为了连接到这些系统，我们需要在`pom.xml`中添加以下依赖项：

```java
<dependency> 
  <groupId>org.apache.flink</groupId> 
  <artifactId>flink-hadoop-compatibility_2.11</artifactId> 
  <version>1.1.4</version> 
</dependency> 

```

这使我们能够使用 Hadoop 数据类型、输入格式和输出格式。Flink 支持开箱即用的可写和可比较可写，因此我们不需要兼容性依赖项。

### HDFS

要从 HDFS 文件中读取数据，我们使用`readHadoopFile()`或`createHadoopInput()`方法创建数据源。为了使用此连接器，我们首先需要配置`flink-conf.yaml`并将`fs.hdfs.hadoopconf`设置为正确的 Hadoop 配置目录。

生成的数据集将是与 HDFS 数据类型匹配的元组类型。以下代码片段显示了如何做到这一点。

在 Java 中：

```java
ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 
DataSet<Tuple2<LongWritable, Text>> input = 
    env.readHadoopFile(new TextInputFormat(), LongWritable.class, Text.class, textPath);  

```

在 Scala 中：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 
val input: DataSet[(LongWritable, Text)] = 
  env.readHadoopFile(new TextInputFormat, classOf[LongWritable], classOf[Text], textPath) 

```

我们还可以使用此连接器将处理后的数据写回 HDFS。`OutputFormat`包装器期望数据集以`Tuple2`格式。以下代码片段显示了如何将处理后的数据写回 HDFS。

在 Java 中：

```java
// Get the processed data set 
DataSet<Tuple2<Text, IntWritable>> results = [...] 

// Set up the Hadoop Output Format. 
HadoopOutputFormat<Text, IntWritable> hadoopOF = 
  // create the Flink wrapper. 
  new HadoopOutputFormat<Text, IntWritable>( 
    // set the Hadoop OutputFormat and specify the job. 
    new TextOutputFormat<Text, IntWritable>(), job 
  ); 
hadoopOF.getConfiguration().set("mapreduce.output.textoutputformat.separator", " "); 
TextOutputFormat.setOutputPath(job, new Path(outputPath)); 

// Emit data  
result.output(hadoopOF); 

```

在 Scala 中：

```java
// Get the processed data set 
val result: DataSet[(Text, IntWritable)] = [...] 

val hadoopOF = new HadoopOutputFormatText,IntWritable 

hadoopOF.getJobConf.set("mapred.textoutputformat.separator", " ") 
FileOutputFormat.setOutputPath(hadoopOF.getJobConf, new Path(resultPath)) 

result.output(hadoopOF) 

```

### Amazon S3

如前所述，Flink 默认支持从 Amazon S3 读取数据。但是，我们需要在 Hadoop 的`core-site.xml`中进行一些配置。我们需要设置以下属性：

```java
<!-- configure the file system implementation --> 
<property> 
  <name>fs.s3.impl</name> 
  <value>org.apache.hadoop.fs.s3native.NativeS3FileSystem</value> 
</property> 
<!-- set your AWS ID --> 
<property> 
  <name>fs.s3.awsAccessKeyId</name> 
  <value>putKeyHere</value> 
</property> 
<!-- set your AWS access key --> 
<property> 
  <name>fs.s3.awsSecretAccessKey</name> 
  <value>putSecretHere</value> 
</property> 

```

完成后，我们可以像这样访问 S3 文件系统：

```java
// Read from S3 bucket 
env.readTextFile("s3://<bucket>/<endpoint>"); 
// Write to S3 bucket 
stream.writeAsText("s3://<bucket>/<endpoint>"); 

```

### Alluxio

Alluxio 是一个开源的、内存速度的虚拟分布式存储。许多公司都在使用 Alluxio 进行高速数据存储和处理。您可以在[`www.alluxio.org/`](http://www.alluxio.org/)上了解更多关于 Alluxio 的信息。

Flink 默认支持从 Alluxio 读取数据。但是，我们需要在 Hadoop 的`core-site.xml`中进行一些配置。我们需要设置以下属性：

```java
<property> 
  <name>fs.alluxio.impl</name> 
  <value>alluxio.hadoop.FileSystem</value> 
</property> 

```

完成后，我们可以像这样访问 Alluxio 文件系统：

```java
// Read from Alluxio path 
env.readTextFile("alluxio://<path>"); 

// Write to Alluxio path 
stream.writeAsText("alluxio://<path>"); 

```

### Avro

Flink 内置支持 Avro 文件。它允许轻松读写 Avro 文件。为了读取 Avro 文件，我们需要使用`AvroInputFormat`。以下代码片段显示了如何读取 Avro 文件：

```java
AvroInputFormat<User> users = new AvroInputFormat<User>(in, User.class); 
DataSet<User> userSet = env.createInput(users); 

```

数据集准备好后，我们可以轻松执行各种转换，例如：

```java
userSet.groupBy("city") 

```

### Microsoft Azure 存储

Microsoft Azure Storage 是一种基于云的存储，允许以持久且可扩展的方式存储数据。Flink 支持管理存储在 Microsoft Azure 表存储上的数据。以下解释了我们如何做到这一点。

首先，我们需要从`git`下载`azure-tables-hadoop`项目，然后编译它：

```java
git clone https://github.com/mooso/azure-tables-hadoop.git 
cd azure-tables-hadoop 
mvn clean install 

```

接下来，在`pom.xml`中添加以下依赖项：

```java
<dependency> 
    <groupId>org.apache.flink</groupId> 
    <artifactId>flink-hadoop-compatibility_2.11</artifactId> 
    <version>1.1.4</version> 
</dependency> 
<dependency> 
  <groupId>com.microsoft.hadoop</groupId> 
  <artifactId>microsoft-hadoop-azure</artifactId> 
  <version>0.0.4</version> 
</dependency> 

```

接下来，我们编写以下代码来访问 Azure 存储：

```java
final ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 

    // create a  AzureTableInputFormat, using a Hadoop input format wrapper 
    HadoopInputFormat<Text, WritableEntity> hdIf = new HadoopInputFormat<Text, WritableEntity>(new AzureTableInputFormat(), Text.class, WritableEntity.class, new Job()); 

// set account URI     
hdIf.getConfiguration().set(AzureTableConfiguration.Keys.ACCOUNT_URI.getKey(), "XXXX"); 
    // set the secret storage key 
    hdIf.getConfiguration().set(AzureTableConfiguration.Keys.STORAGE_KEY.getKey(), "XXXX"); 
    // set the table name  
    hdIf.getConfiguration().set(AzureTableConfiguration.Keys.TABLE_NAME.getKey(), "XXXX"); 

 DataSet<Tuple2<Text, WritableEntity>> input = env.createInput(hdIf); 

```

现在我们已经准备好处理数据集了。

## MongoDB

通过开源贡献，开发人员已经能够将 Flink 连接到 MongoDB。在本节中，我们将讨论这样一个项目。

该项目是开源的，可以从 GitHub 下载：

```java
git clone https://github.com/okkam-it/flink-mongodb-test.git 
cd flink-mongodb-test 
mvn clean install 

```

接下来，我们在 Java 程序中使用前面的连接器连接到 MongoDB：

```java
// set up the execution environment 
    final ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 

// create a MongodbInputFormat, using a Hadoop input format wrapper 
HadoopInputFormat<BSONWritable, BSONWritable> hdIf =  
        new HadoopInputFormat<BSONWritable, BSONWritable>(new MongoInputFormat(), 
       BSONWritable.class, BSONWritable.class, new JobConf()); 

// specify connection parameters 
hdIf.getJobConf().set("mongo.input.uri",  
                "mongodb://localhost:27017/dbname.collectioname"); 

DataSet<Tuple2<BSONWritable, BSONWritable>> input = env.createInput(hdIf); 

```

一旦数据作为数据集可用，我们可以轻松进行所需的转换。我们还可以像这样将数据写回 MongoDB 集合：

```java
MongoConfigUtil.setOutputURI( hdIf.getJobConf(),  
                "mongodb://localhost:27017/dbname.collectionname "); 
 // emit result (this works only locally) 
 result.output(new HadoopOutputFormat<Text,BSONWritable>( 
                new MongoOutputFormat<Text,BSONWritable>(), hdIf.getJobConf())); 

```

# 迭代

Flink 支持的一个独特功能是迭代。如今，许多开发人员希望使用大数据技术运行迭代的机器学习和图处理算法。为了满足这些需求，Flink 支持通过定义步骤函数来运行迭代数据处理。

## 迭代器操作符

迭代器操作符由以下组件组成：

![迭代器操作符](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_03_002.jpg)

+   **迭代输入**：这是接收到的初始数据集或上一次迭代的输出

+   **步骤函数**：这是需要应用于输入数据集的函数

+   **下一个部分解**：这是需要反馈到下一次迭代的步骤函数的输出

+   **迭代结果**：在完成所有迭代后，我们得到迭代的结果

迭代次数可以通过各种方式进行控制。一种方式可以是设置要执行的迭代次数，或者我们也可以进行条件终止。

## 增量迭代器

增量运算符对一组元素进行增量迭代操作。增量迭代器和常规迭代器之间的主要区别在于，增量迭代器在更新解决方案集而不是在每次迭代中完全重新计算解决方案集上工作。

这导致了更高效的操作，因为它使我们能够在更短的时间内专注于解决方案的重要部分。下图显示了 Flink 中增量迭代器的流程。

![增量迭代器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_03_003.jpg)

+   **迭代输入**：我们必须从某些文件中读取增量迭代器的工作集和解决方案集

+   **步骤函数**：步骤函数是需要应用于输入数据集的函数

+   **下一个工作集/更新解决方案**：在每次迭代解决方案集之后，它会根据最新结果进行更新，并将下一个工作集提供给下一个迭代

+   **迭代结果**：在完成所有迭代后，我们以解决方案集的形式获得迭代的结果

由于增量迭代器在热数据集本身上运行，因此性能和效率非常好。以下是一篇详细的文章，讨论了使用 Flink 迭代器进行 PageRank 算法。[`data-artisans.com/data-analysis-with-flink-a-case-study-and-tutorial/`](http://data-artisans.com/data-analysis-with-flink-a-case-study-and-tutorial/)。

# 用例 - 使用 Flink 批处理 API 进行运动员数据洞察

现在我们已经了解了 DataSet API 的细节，让我们尝试将这些知识应用到一个真实的用例中。假设我们手头有一个数据集，其中包含有关奥运会运动员及其在各种比赛中表现的信息。示例数据如下表所示：

| **球员** | **国家** | **年份** | **比赛** | **金牌** | **银牌** | **铜牌** | **总计** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 杨伊琳 | 中国 | 2008 | 体操 | 1 | 0 | 2 | 3 |
| 利塞尔·琼斯 | 澳大利亚 | 2000 | 游泳 | 0 | 2 | 0 | 2 |
| 高基贤 | 韩国 | 2002 | 短道速滑 | 1 | 1 | 0 | 2 |
| 陈若琳 | 中国 | 2008 | 跳水 | 2 | 0 | 0 | 2 |
| 凯蒂·莱德基 | 美国 | 2012 | 游泳 | 1 | 0 | 0 | 1 |
| 鲁塔·梅卢蒂特 | 立陶宛 | 2012 | 游泳 | 1 | 0 | 0 | 1 |
| 达尼尔·吉尔塔 | 匈牙利 | 2004 | 游泳 | 0 | 1 | 0 | 1 |
| 阿里安娜·方塔纳 | 意大利 | 2006 | 短道速滑 | 0 | 0 | 1 | 1 |
| 奥尔加·格拉茨基赫 | 俄罗斯 | 2004 | 韵律体操 | 1 | 0 | 0 | 1 |
| 卡里克莱亚·潘塔齐 | 希腊 | 2000 | 韵律体操 | 0 | 0 | 1 | 1 |
| 金·马丁 | 瑞典 | 2002 | 冰球 | 0 | 0 | 1 | 1 |
| 凯拉·罗斯 | 美国 | 2012 | 体操 | 1 | 0 | 0 | 1 |
| 加布里埃拉·德拉戈伊 | 罗马尼亚 | 2008 | 体操 | 0 | 0 | 1 | 1 |
| 塔莎·施维克特-沃伦 | 美国 | 2000 | 体操 | 0 | 0 | 1 | 1 |

现在我们想要得到答案，比如，每个国家有多少运动员参加了比赛？或者每个比赛有多少运动员参加了？由于数据处于静止状态，我们将使用 Flink 批处理 API 进行分析。

可用的数据以 CSV 格式存在。因此，我们将使用 Flink API 提供的 CSV 读取器，如下面的代码片段所示。

```java
final ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 
DataSet<Record> csvInput = env.readCsvFile("olympic-athletes.csv") 
                     .pojoType(Record.class, "playerName", "country", "year", "game", "gold", "silver", "bronze", "total"); 

```

一旦数据被正确解析，就很容易继续使用它。以下代码片段显示了如何获取每个国家的球员数量的信息：

```java
DataSet<Tuple2<String, Integer>> groupedByCountry = csvInput
.flatMap(new FlatMapFunction<Record, Tuple2<String, Integer>>() {
private static final long serialVersionUID = 1L;
@Override
public void flatMap(Record record, Collector<Tuple2<String, Integer>> out) throws Exception {
out.collect(new Tuple2<String, Integer>(record.getCountry(), 1));
}
}).groupBy(0).sum(1);
groupedByCountry.print();
```

在前面的代码片段中，我们首先创建了以球员国家为键，值为`1`的数据集，然后对其进行分组并求和以获得总数。一旦我们执行了代码，输出如下所示：

```java
(Australia,11)
(Belarus,7)
(China,25)
(France,3)
(Germany,2)
(Italy,4)
(Turkey,1)
(United States,22)
(Cameroon,2)
(Hungary,1)
(Kenya,1)
(Lithuania,1)
(Russia,23)
(Spain,2)
(Ukraine,1)
(Chinese Taipei,2)
(Great Britain,1)
(Romania,14)
(Switzerland,1)
(Bulgaria,3)
(Finland,1)
(Greece,7)
(Japan,1)
(Mexico,1)
(Netherlands,2)
(Poland,1)
(South Korea,6)
(Sweden,6)
(Thailand,1)
```

同样，我们可以应用相同的逻辑来查找每场比赛的球员数量，如下面的代码片段所示：

```java
DataSet<Tuple2<String, Integer>> groupedByGame = csvInput
.flatMap(new FlatMapFunction<Record, Tuple2<String, Integer>>() { private static final long serialVersionUID = 1L;
@Override
public void flatMap(Record record, Collector<Tuple2<String, Integer>> out) throws Exception {
out.collect(new Tuple2<String, Integer>(record.getGame(), 1));
}
}).groupBy(0).sum(1);
groupedByGame.print();
```

前面代码片段的输出如下：

```java
(Basketball,1)
(Gymnastics,42)
(Ice Hockey,7)
(Judo,1)
(Swimming,33)
(Athletics,2)
(Fencing,2)
(Nordic Combined,1)
(Rhythmic Gymnastics,27)
(Short-Track Speed Skating,5)
(Table Tennis,1)
(Weightlifting,4)
(Boxing,3)
(Taekwondo,3)
(Archery,3)
(Diving,14)
(Figure Skating,1)
(Football,2)
(Shooting,1)
```

这样，您可以运行各种其他转换以获得所需的输出。此用例的完整代码可在[`github.com/deshpandetanmay/mastering-flink/tree/master/chapter03/flink-batch`](https://github.com/deshpandetanmay/mastering-flink/tree/master/chapter03/flink-batch)上找到。

# 摘要

在本章中，我们学习了 DataSet API。它使我们能够进行批处理。我们学习了各种转换以进行数据处理。后来，我们还探索了各种基于文件的连接器，以从 HDFS、Amazon S3、MS Azure、Alluxio 等读取/写入数据。

在最后一节中，我们看了一个用例，在这个用例中，我们应用了在前几节中学到的知识。

在下一章中，我们将学习另一个非常重要的 API，即 Table API，从 Flink 的生态系统角度来看。
