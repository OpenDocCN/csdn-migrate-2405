# Scala 和 Spark 大数据分析（八）

> 原文：[`zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A`](https://zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十七章：前往集群之地的时候——在集群上部署 Spark

"我看见月亮像一块剪下的银子。星星像镀金的蜜蜂一样围绕着她"

- 奥斯卡·王尔德

在前几章中，我们已经看到如何使用不同的 Spark API 开发实际应用程序。然而，在本章中，我们将看到 Spark 在集群模式下的工作方式及其底层架构。最后，我们将看到如何在集群上部署完整的 Spark 应用程序。简而言之，本章将涵盖以下主题：

+   集群中的 Spark 架构

+   Spark 生态系统和集群管理

+   在集群上部署 Spark

+   在独立集群上部署 Spark

+   在 Mesos 集群上部署 Spark

+   在 YARN 集群上部署 Spark

+   基于云的部署

+   在 AWS 上部署 Spark

# 集群中的 Spark 架构

基于 Hadoop 的 MapReduce 框架在过去几年被广泛使用；然而，它在 I/O、算法复杂性、低延迟流式作业和完全基于磁盘的操作方面存在一些问题。Hadoop 提供了 Hadoop 分布式文件系统（HDFS）来进行高效的计算和廉价存储大数据，但你只能使用基于 Hadoop 的 MapReduce 框架进行高延迟批处理模型或静态数据的计算。Spark 为我们带来的主要大数据范式是引入了内存计算和缓存抽象。这使得 Spark 非常适合大规模数据处理，并使计算节点能够通过访问相同的输入数据执行多个操作。

Spark 的弹性分布式数据集（RDD）模型可以做到 MapReduce 范式所能做的一切，甚至更多。然而，Spark 可以在规模上对数据集进行迭代计算。这个选项有助于以更快的速度执行机器学习、通用数据处理、图分析和结构化查询语言（SQL）算法，无论是否依赖于 Hadoop。因此，此时重振 Spark 生态系统是一个需求。

足够了解 Spark 的美丽和特性。此时，重振 Spark 生态系统是您了解 Spark 如何工作的需求。

# Spark 生态系统简介

为了为您提供更先进和额外的大数据处理能力，您的 Spark 作业可以在基于 Hadoop（又名 YARN）或基于 Mesos 的集群上运行。另一方面，Spark 中的核心 API 是用 Scala 编写的，使您能够使用多种编程语言（如 Java、Scala、Python 和 R）开发您的 Spark 应用程序。Spark 提供了几个库，这些库是 Spark 生态系统的一部分，用于通用数据处理和分析、图处理、大规模结构化 SQL 和机器学习（ML）领域的额外功能。Spark 生态系统包括以下组件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00161.jpeg)**图 1：** Spark 生态系统（截至 Spark 2.1.0）

Spark 的核心引擎是用 Scala 编写的，但支持不同的语言来开发您的 Spark 应用程序，如 R、Java、Python 和 Scala。Spark 核心引擎中的主要组件/ API 如下：

1.  SparkSQL：这有助于无缝地将 SQL 查询与 Spark 程序混合在一起，以便在 Spark 程序内查询结构化数据。

1.  Spark Streaming：这是用于大规模流应用程序开发的，提供了与其他流数据源（如 Kafka、Flink 和 Twitter）无缝集成的 Spark。

1.  SparkMLlib 和 SparKML：这些是用于基于 RDD 和数据集/ DataFrame 的机器学习和管道创建。

1.  GraphX：这是用于大规模图计算和处理，使您的图数据对象完全连接。

1.  SparkR：R on Spark 有助于基本的统计计算和机器学习。

正如我们已经提到的，可以无缝地结合这些 API 来开发大规模的机器学习和数据分析应用程序。此外，Spark 作业可以通过 Hadoop YARN、Mesos 和独立的集群管理器提交和执行，也可以通过访问数据存储和源（如 HDFS、Cassandra、HBase、Amazon S3 甚至 RDBMS）在云中执行。然而，要充分利用 Spark 的功能，我们需要在计算集群上部署我们的 Spark 应用程序。

# 集群设计

Apache Spark 是一个分布式和并行处理系统，它还提供了内存计算能力。这种类型的计算范式需要一个关联的存储系统，以便您可以在大数据集群上部署您的应用程序。为了实现这一点，您将需要使用 HDFS、S3、HBase 和 Hive 等分布式存储系统。为了移动数据，您将需要其他技术，如 Sqoop、Kinesis、Twitter、Flume 和 Kafka。

在实践中，您可以很容易地配置一个小型的 Hadoop 集群。您只需要一个主节点和多个工作节点。在您的 Hadoop 集群中，通常一个主节点包括 NameNodes、DataNodes、JobTracker 和 TaskTracker。另一方面，工作节点可以配置为既作为 DataNode 又作为 TaskTracker。

出于安全原因，大多数大数据集群可能会设置在网络防火墙后，以便计算节点可以克服或至少减少防火墙造成的复杂性。否则，计算节点无法从网络外部访问，即外部网络。以下图片显示了一个常用的 Spark 简化大数据集群：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00379.jpeg)**图 2：**带有 JVM 的大数据处理的一般架构

上图显示了一个由五个计算节点组成的集群。每个节点都有一个专用的执行器 JVM，每个 CPU 核心一个，以及位于集群外部的 Spark Driver JVM。磁盘直接连接到节点上，使用 JBOD（Just a bunch of disks）方法。非常大的文件被分区存储在磁盘上，而像 HDFS 这样的虚拟文件系统将这些块作为一个大的虚拟文件提供。以下简化的组件模型显示了位于集群外部的驱动程序 JVM。它与集群管理器（见图 4）通信，以获取在工作节点上调度任务的权限，因为集群管理器跟踪集群上运行的所有进程的资源分配情况。

如果您使用 Scala 或 Java 开发了您的 Spark 应用程序，这意味着您的作业是基于 JVM 的进程。对于基于 JVM 的进程，您可以通过指定以下两个参数来简单配置 Java 堆空间：

+   -Xmx：这个参数指定了 Java 堆空间的上限

+   -Xms：这个参数是 Java 堆空间的下限

一旦您提交了一个 Spark 作业，就需要为您的 Spark 作业分配堆内存。以下图片提供了一些关于如何分配堆内存的见解：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00113.jpeg)**图 3：**JVM 内存管理

如前图所示，Spark 以 512MB 的 JVM 堆空间启动 Spark 作业。然而，为了保证 Spark 作业的不间断处理并避免内存不足（OOM）错误，Spark 允许计算节点仅利用堆的 90%（即约 461MB），这最终通过控制 Spark 环境中的`spark.storage.safetyFraction`参数来增加或减少。更加现实的情况是，JVM 可以被看作是存储（Java 堆的 60%）、执行（即 Shuffle 的堆的 20%）和其他存储的 20%的连接。

此外，Spark 是一种集群计算工具，试图同时利用内存和基于磁盘的计算，并允许用户将一些数据存储在内存中。实际上，Spark 仅利用主内存作为其 LRU 缓存。为了实现不间断的缓存机制，需要保留一小部分内存用于应用程序特定的数据处理。非正式地说，这大约占据了由`spark.memory.fraction`控制的 Java 堆空间的 60%。

因此，如果您想要查看或计算在您的 Spark 应用程序中可以缓存多少应用程序特定数据，您只需将所有执行程序使用的堆大小总和，并将其乘以`safetyFraction`和`spark.memory.fraction`。实际上，您可以允许 Spark 计算节点使用总堆大小的 54%（276.48 MB）。现在，洗牌内存的计算如下：

```scala
Shuffle memory= Heap Size * spark.shuffle.safetyFraction * spark.shuffle.memoryFraction

```

`spark.shuffle.safetyFraction`和`spark.shuffle.memoryFraction`的默认值分别为 80%和 20%。因此，在实际中，您可以使用*0.8*0.2 = 16%*的 JVM 堆用于洗牌。最后，展开内存是计算节点中可以被展开进程利用的主内存量。计算如下：

```scala
Unroll memory = spark.storage.unrollFraction * spark.storage.memoryFraction * spark.storage.safetyFraction

```

上述计算约占堆的 11%（0.2*0.6*0.9 = 10.8~11%），即 Java 堆空间的 56.32 MB。

更详细的讨论可以在[`spark.apache.org/docs/latest/configuration.html`](http://spark.apache.org/docs/latest/configuration.html)找到。

正如我们将在后面看到的，存在各种不同的集群管理器，其中一些还能够同时管理其他 Hadoop 工作负载或非 Hadoop 应用程序。请注意，执行程序和驱动程序始终具有双向通信，因此在网络方面它们也应该坐得很近。

**图 4：** Spark 集群中的驱动程序、主节点和工作节点架构

Spark 使用驱动程序（又称驱动程序）、主节点和工作节点架构（又称主机、从节点或计算节点）。驱动程序（或机器）与称为主节点的协调器进行通信。主节点实际上管理所有工作节点（又称从节点或计算节点），其中多个执行程序在集群中并行运行。需要注意的是，主节点也是一个具有大内存、存储、操作系统和底层计算资源的计算节点。从概念上讲，这种架构可以在**图 4**中显示。更多细节将在本节后面讨论。

在实际的集群模式中，集群管理器（又称资源管理器）管理集群中所有计算节点的所有资源。通常，防火墙在为集群增加安全性的同时也增加了复杂性。系统组件之间的端口需要打开，以便它们可以相互通信。例如，Zookeeper 被许多组件用于配置。Apache Kafka 是一个订阅消息系统，使用 Zookeeper 来配置其主题、组、消费者和生产者。因此，需要打开到 Zookeeper 的客户端端口，可能要穿过防火墙。

最后，需要考虑将系统分配给集群节点。例如，如果 Apache Spark 使用 Flume 或 Kafka，那么将使用内存通道。Apache Spark 不应该与其他 Apache 组件竞争内存使用。根据数据流和内存使用情况，可能需要在不同的集群节点上安装 Spark、Hadoop、Zookeeper、Flume 和其他工具。或者，也可以使用资源管理器，如 YARN、Mesos 或 Docker 等来解决这个问题。在标准的 Hadoop 环境中，很可能已经有 YARN 了。

作为工作节点或 Spark 主节点的计算节点将需要比防火墙内的集群处理节点更多的资源。当集群上部署了许多 Hadoop 生态系统组件时，所有这些组件都将需要主服务器上额外的内存。您应该监视工作节点的资源使用情况，并根据需要调整资源和/或应用程序位置。例如，YARN 正在处理这个问题。

本节简要介绍了 Apache Spark、Hadoop 和其他工具在大数据集群中的情况。然而，Apache Spark 集群本身在大数据集群中如何配置？例如，可能有许多类型的 Spark 集群管理器。下一节将对此进行探讨，并描述每种类型的 Apache Spark 集群管理器。

# 集群管理

Spark 上下文可以通过 Spark 配置对象（即`SparkConf`）和 Spark URL 来定义。首先，Spark 上下文的目的是连接 Spark 集群管理器，您的 Spark 作业将在其中运行。然后，集群或资源管理器会为您的应用程序在计算节点之间分配所需的资源。集群管理器的第二个任务是在集群工作节点之间分配执行程序，以便执行您的 Spark 作业。第三，资源管理器还会将驱动程序（也称为应用程序 JAR 文件、R 代码或 Python 脚本）复制到计算节点。最后，资源管理器将计算任务分配给计算节点。

以下小节描述了当前 Spark 版本（即本书撰写时的 Spark 2.1.0）提供的可能的 Apache Spark 集群管理器选项。要了解资源管理器（也称为集群管理器）的资源管理情况，以下内容显示了 YARN 如何管理其所有底层计算资源。但是，无论您使用的是哪种集群管理器（例如 Mesos 或 YARN），情况都是一样的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00380.jpeg)**图 5：** 使用 YARN 进行资源管理

详细讨论可在[`spark.apache.org/docs/latest/cluster-overview.html#cluster-manager-types`](http://spark.apache.org/docs/latest/cluster-overview.html#cluster-manager-types)找到。

# 伪集群模式（也称为 Spark 本地）

正如您已经知道的，Spark 作业可以在本地模式下运行。有时这被称为伪集群执行模式。这也是一种非分布式和基于单个 JVM 的部署模式，其中 Spark 将所有执行组件（例如驱动程序、执行程序、LocalSchedulerBackend 和主节点）放入单个 JVM 中。这是唯一一种驱动程序本身被用作执行程序的模式。下图显示了提交 Spark 作业的本地模式的高级架构：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00214.jpeg)**图 6：** Spark 作业本地模式的高级架构（来源：[`jaceklaskowski.gitbooks.io/mastering-apache-spark/content/spark-local.html`](https://jaceklaskowski.gitbooks.io/mastering-apache-spark/content/spark-local.html))

这太令人惊讶了吗？不，我想不是，因为您也可以实现某种并行性，其中默认并行性是在主 URL 中指定的线程数（也称为使用的核心），即 local [4]表示 4 个核心/线程，`local [*]`表示所有可用的线程。我们将在本章后面讨论这个话题。

# 独立

通过指定 Spark 配置本地 URL，可以使应用程序在本地运行。通过指定*local[n]*，可以让 Spark 使用*n*个线程在本地运行应用程序。这是一个有用的开发和测试选项，因为您还可以测试某种并行化场景，但将所有日志文件保留在单台机器上。独立模式使用了 Apache Spark 提供的基本集群管理器。Spark 主 URL 将如下所示：

```scala
spark://<hostname>:7077

```

在这里，`<hostname>`是运行 Spark 主的主机名。我指定了 7077 作为端口，这是默认值，但它是可配置的。这个简单的集群管理器目前只支持**FIFO**（先进先出）调度。您可以通过为每个应用程序设置资源配置选项来构想允许并发应用程序调度。例如，`spark.core.max`用于在应用程序之间共享处理器核心。本章后面将进行更详细的讨论。

# Apache YARN

如果将 Spark 主值设置为 YARN-cluster，则可以将应用程序提交到集群，然后终止。集群将负责分配资源和运行任务。然而，如果应用程序主作为 YARN-client 提交，则应用程序在处理的生命周期中保持活动，并从 YARN 请求资源。这在与 Hadoop YARN 集成时适用于更大规模。本章后面将提供逐步指南，以配置单节点 YARN 集群，以启动需要最少资源的 Spark 作业。

# Apache Mesos

Apache Mesos 是一个用于跨集群资源共享的开源系统。它允许多个框架通过管理和调度资源来共享集群。它是一个集群管理器，使用 Linux 容器提供隔离，允许多个系统（如 Hadoop、Spark、Kafka、Storm 等）安全地共享集群。这是一个基于主从的系统，使用 Zookeeper 进行配置管理。这样，您可以将 Spark 作业扩展到数千个节点。对于单个主节点 Mesos 集群，Spark 主 URL 将采用以下形式：

```scala
mesos://<hostname>:5050

```

通过专门使用 Mesos 提交 Spark 作业的后果可以在以下图中以可视化方式显示：

！[](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00075.jpeg)**图 7：**Mesos 在操作中（图片来源：[`jaceklaskowski.gitbooks.io/mastering-apache-spark/content/spark-architecture.html`](https://jaceklaskowski.gitbooks.io/mastering-apache-spark/content/spark-architecture.html))

在前面的图中，`<hostname>`是 Mesos 主服务器的主机名，端口定义为 5050，这是默认的 Mesos 主端口（可配置）。如果在大规模高可用性 Mesos 集群中有多个 Mesos 主服务器，则 Spark 主 URL 将如下所示：

```scala
mesos://zk://<hostname>:2181

```

因此，Mesos 主服务器的选举将由 Zookeeper 控制。`<hostname>`将是 Zookeeper 群的主机名。此外，端口号 2181 是 Zookeeper 的默认主端口。

# 基于云的部署

云计算范式中有三种不同的抽象级别：

+   基础设施即服务（简称 IaaS）

+   平台即服务（简称 PaaS）

+   软件即服务（简称 SaaS）

IaaS 通过空虚拟机提供计算基础设施，用于运行作为 SaaS 的软件。这对于在 OpenStack 上的 Apache Spark 也是如此。

OpenStack 的优势在于它可以在多个不同的云提供商之间使用，因为它是一个开放标准，也是基于开源的。您甚至可以在本地数据中心使用 OpenStack，并在本地、专用和公共云数据中心之间透明动态地移动工作负载。

相比之下，PaaS 从您身上解除了安装和操作 Apache Spark 集群的负担，因为这是作为服务提供的。换句话说，您可以将其视为类似于操作系统的一层。

有时，甚至可以将 Spark 应用程序 Docker 化并以云平台独立方式部署。然而，关于 Docker 是 IaaS 还是 PaaS 正在进行讨论，但在我们看来，这只是一种轻量级预安装虚拟机的形式，更多的是 IaaS。

最后，SaaS 是云计算范式提供和管理的应用层。坦率地说，您不会看到或必须担心前两层（IaaS 和 PaaS）。

Google Cloud，Amazon AWS，Digital Ocean 和 Microsoft Azure 是提供这三个层作为服务的云计算服务的良好示例。我们将在本章后面展示如何在云顶部使用 Amazon AWS 部署您的 Spark 集群的示例。

# 在集群上部署 Spark 应用程序

在本节中，我们将讨论如何在计算集群上部署 Spark 作业。我们将看到如何在三种部署模式（独立，YARN 和 Mesos）中部署集群。以下图总结了本章中需要引用集群概念的术语：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00258.jpeg)**图 8：**需要引用集群概念的术语（来源：http://spark.apache.org/docs/latest/cluster-overview.html#glossary）

但是，在深入研究之前，我们需要了解如何一般提交 Spark 作业。

# 提交 Spark 作业

一旦将 Spark 应用程序打包为 jar 文件（用 Scala 或 Java 编写）或 Python 文件，就可以使用 Spark 分发（即`$SPARK_HOME/bin`下的 bin 目录中的 Spark-submit 脚本）提交。根据 Spark 网站提供的 API 文档（[`spark.apache.org/docs/latest/submitting-applications.html`](http://spark.apache.org/docs/latest/submitting-applications.html)），该脚本负责以下内容：

+   设置`JAVA_HOME`，`SCALA_HOME`与 Spark 的类路径

+   设置执行作业所需的所有依赖项

+   管理不同的集群管理器

+   最后，部署 Spark 支持的模型

简而言之，Spark 作业提交语法如下：

```scala
$ spark-submit [options] <app-jar | python-file> [app arguments]

```

在这里，`[options]`可以是：`--conf <configuration_parameters> --class <main-class> --master <master-url> --deploy-mode <deploy-mode> ... # other options`

+   `<main-class>`是主类名。这实际上是我们 Spark 应用程序的入口点。

+   `--conf`表示所有使用的 Spark 参数和配置属性。配置属性的格式是键=值格式。

+   `<master-url>`指定集群的主 URL（例如，`spark://HOST_NAME:PORT`*）*用于连接到 Spark 独立集群的主机，`local`用于在本地运行 Spark 作业。默认情况下，它只允许您使用一个工作线程，没有并行性。`local [k]`可用于在本地运行具有*K*工作线程的 Spark 作业。需要注意的是，K 是您计算机上的核心数。最后，如果您指定主机为`local[*]`以在本地运行 Spark 作业，您将允许`spark-submit`脚本利用计算机上所有工作线程（逻辑核心）。最后，您可以指定主机为`mesos://IP_ADDRESS:PORT`以连接到可用的 Mesos 集群。或者，您可以指定使用`yarn`在基于 YARN 的集群上运行 Spark 作业。

有关 Master URL 的其他选项，请参考以下图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00183.jpeg)**图 9：**Spark 支持的主 URL 的详细信息

+   `<deploy-mode>`如果要在 worker 节点（集群）上部署驱动程序，或者在外部客户端（客户端）上本地部署，必须指定。支持四种（4）模式：local，standalone，YARN 和 Mesos。

+   `<app-jar>`是您使用依赖项构建的 JAR 文件。在提交作业时，只需传递 JAR 文件。

+   `<python-file>`是使用 Python 编写的应用程序主要源代码。在提交作业时，只需传递`.py`文件。

+   `[app-arguments]`可以是应用程序开发人员指定的输入或输出参数。

在使用 spark-submit 脚本提交 Spark 作业时，可以使用`--jars`选项指定 Spark 应用程序的主要 jar（以及包括的其他相关 JAR 包）。然后所有的 JAR 包将被传输到集群。在`--jars`之后提供的 URL 必须用逗号分隔。

然而，如果您使用 URL 指定 jar 包，最好在`--jars`之后使用逗号分隔 JAR 包。Spark 使用以下 URL 方案来允许不同的 JAR 包传播策略：

+   **file:** 指定绝对路径和`file:/`

+   **hdfs****:**、**http****:**、**https:**、**ftp****:** JAR 包或任何其他文件将从您指定的 URL/URI 中按预期进行下载

+   **local:** 以`local:/`开头的 URI 可用于指向每个计算节点上的本地 jar 文件

需要注意的是，依赖的 JAR 包、R 代码、Python 脚本或任何其他相关的数据文件需要复制或复制到每个计算节点上的工作目录中。这有时会产生很大的开销，并且需要大量的磁盘空间。磁盘使用量会随时间增加。因此，在一定时间内，需要清理未使用的数据对象或相关的代码文件。然而，使用 YARN 可以很容易地实现这一点。YARN 会定期处理清理工作，并可以自动处理。例如，在 Spark 独立模式下，可以通过`spark.worker.cleanup.appDataTtl`属性配置自动清理提交 Spark 作业时。

在计算上，Spark 被设计为在作业提交时（使用`spark-submit`脚本），可以从属性文件加载默认的 Spark 配置值，并将其传播到 Spark 应用程序。主节点将从名为`spark-default.conf`的配置文件中读取指定的选项。确切的路径是您的 Spark 分发目录中的`SPARK_HOME/conf/spark-defaults.conf`。然而，如果您在命令行中指定了所有参数，这将获得更高的优先级，并且将相应地使用。

# 在本地和独立运行 Spark 作业

示例显示在第十三章，*我的名字是贝叶斯，朴素贝叶斯*，并且可以扩展到更大的数据集以解决不同的目的。您可以将这三个聚类算法与所有必需的依赖项打包，并将它们作为 Spark 作业提交到集群中。如果您不知道如何制作一个包并从 Scala 类创建 jar 文件，您可以使用 SBT 或 Maven 将应用程序与所有依赖项捆绑在一起。

根据 Spark 文档[`spark.apache.org/docs/latest/submitting-applications.html#advanced-dependency-management`](http://spark.apache.org/docs/latest/submitting-applications.html#advanced-dependency-management)，SBT 和 Maven 都有汇编插件，用于将您的 Spark 应用程序打包为一个 fat jar。如果您的应用程序已经捆绑了所有的依赖项，可以使用以下代码行提交您的 k-means 聚类 Spark 作业，例如（对其他类使用类似的语法），用于 Saratoga NY Homes 数据集。要在本地提交和运行 Spark 作业，请在 8 个核心上运行以下命令：

```scala
$ SPARK_HOME/bin/spark-submit 
 --class com.chapter15.Clustering.KMeansDemo 
 --master local[8] 
 KMeans-0.0.1-SNAPSHOT-jar-with-dependencies.jar 
 Saratoga_NY_Homes.txt

```

在上述代码中，`com.chapter15.KMeansDemo`是用 Scala 编写的主类文件。Local [8]是使用您机器的八个核心的主 URL。`KMeansDemo-0.1-SNAPSHOT-jar-with-dependencies.jar`是我们刚刚通过 Maven 项目生成的应用程序 JAR 文件；`Saratoga_NY_Homes.txt`是 Saratoga NY Homes 数据集的输入文本文件。如果应用程序成功执行，您将在下图中找到包括输出的消息（摘要）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00015.gif)**图 10:** 终端上的 Spark 作业输出[本地模式]

现在，让我们深入研究独立模式下的集群设置。要安装 Spark 独立模式，您应该在集群的每个节点上放置每个版本的预构建版本的 Spark。或者，您可以自己构建它，并根据[`spark.apache.org/docs/latest/building-spark.html`](http://spark.apache.org/docs/latest/building-spark.html)上的说明使用它。

要将环境配置为 Spark 独立模式，您将需要为集群的每个节点提供所需版本的预构建版本的 Spark。或者，您可以自己构建它，并根据[`spark.apache.org/docs/latest/building-spark.html`](http://spark.apache.org/docs/latest/building-spark.html)上的说明使用它。现在我们将看到如何手动启动独立集群。您可以通过执行以下命令启动独立主节点：

```scala
$ SPARK_HOME/sbin/start-master.sh

```

一旦启动，您应该在终端上观察以下日志：

```scala
Starting org.apache.spark.deploy.master.Master, logging to <SPARK_HOME>/logs/spark-asif-org.apache.spark.deploy.master.Master-1-ubuntu.out

```

您应该能够默认访问`http://localhost:8080`的 Spark Web UI。观察以下 UI，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00321.jpeg)**图 11：**Spark 主节点作为独立节点

您可以通过编辑以下参数更改端口号：

```scala
SPARK_MASTER_WEBUI_PORT=8080

```

在`SPARK_HOME/sbin/start-master.sh`中，只需更改端口号，然后应用以下命令：

```scala
$ sudo chmod +x SPARK_HOME/sbin/start-master.sh.

```

或者，您可以重新启动 Spark 主节点以实现前面的更改。但是，您将不得不在`SPARK_HOME/sbin/start-slave.sh`中进行类似的更改。

正如您在这里所看到的，没有与主节点关联的活动工作节点。现在，要创建一个从节点（也称为工作节点或计算节点），请创建工作节点并使用以下命令将其连接到主节点：

```scala
$ SPARK_HOME/sbin/start-slave.sh <master-spark-URL>

```

成功完成上述命令后，您应该在终端上观察以下日志：

```scala
Starting org.apache.spark.deploy.worker.Worker, logging to <SPARK_HOME>//logs/spark-asif-org.apache.spark.deploy.worker.Worker-1-ubuntu.out 

```

一旦您的一个工作节点启动，您可以在 Spark Web UI 的`http://localhost:8081`上查看其状态。但是，如果您启动另一个工作节点，您可以在连续的端口（即 8082、8083 等）上访问其状态。您还应该在那里看到新节点的列表，以及其 CPU 和内存的数量，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00055.jpeg)**图 12：**Spark 工作节点作为独立节点

现在，如果您刷新`http://localhost:8080`，您应该看到与您的主节点关联的一个工作节点已添加，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00104.jpeg)**图 13：**Spark 主节点现在有一个独立的工作节点

最后，如下图所示，这些都是可以传递给主节点和工作节点的配置选项：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00195.jpeg)**图 14：**可以传递给主节点和工作节点的配置选项（来源：[`spark.apache.org/docs/latest/spark-standalone.html#starting-a-cluster-manually`](http://spark.apache.org/docs/latest/spark-standalone.html#starting-a-cluster-manually))

现在您的一个主节点和一个工作节点正在读取和活动。最后，您可以提交与本地模式不同的独立模式下的相同 Spark 作业，使用以下命令：

```scala
$ SPARK_HOME/bin/spark-submit  
--class "com.chapter15.Clustering.KMeansDemo"  
--master spark://ubuntu:7077   
KMeans-0.0.1-SNAPSHOT-jar-with-dependencies.jar  
Saratoga_NY_Homes.txt

```

作业启动后，访问`http://localhost:80810`的 Spark Web UI 以查看主节点和`http://localhost:8081`的工作节点，您可以看到作业的进度，如第十四章中所讨论的那样，*Time to Put Some Order - Cluster Your Data with Spark MLlib*。

总结这一部分，我们想引导您查看下图（即**图 15**），显示了以下 shell 脚本用于启动或停止集群的用法：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00295.jpeg)**图 15：**用于启动或停止集群的 shell 脚本的用法

# Hadoop YARN

如前所述，Apache Hadoop YARN 有两个主要组件：调度程序和应用程序管理器，如下图所示：

**图 16：**Apache Hadoop YARN 架构（蓝色：系统组件；黄色和粉色：两个正在运行的应用程序）

现在使用调度程序和应用程序管理器，可以配置以下两种部署模式来在基于 YARN 的集群上启动 Spark 作业：

+   **集群模式**：在集群模式下，Spark 驱动程序在 YARN 的应用程序管理器管理的应用程序的主进程内工作。即使客户端在应用程序启动后被终止或断开连接，应用程序也可以继续运行。

+   **客户端模式**：在此模式下，Spark 驱动程序在客户端进程内运行。之后，Spark 主节点仅用于从 YARN（YARN 资源管理器）请求计算节点的计算资源。

在 Spark 独立模式和 Mesos 模式中，需要在`--master`参数中指定主节点（即地址）。然而，在 YARN 模式中，资源管理器的地址是从 Hadoop 配置文件中读取的。因此，`--master`参数是`yarn`。在提交 Spark 作业之前，您需要设置好 YARN 集群。下一小节将逐步展示如何操作。

# 配置单节点 YARN 集群

在本小节中，我们将看到如何在在 YARN 集群上运行 Spark 作业之前设置 YARN 集群。有几个步骤，所以请耐心按照以下步骤操作：

# 步骤 1：下载 Apache Hadoop

从 Hadoop 网站（[`hadoop.apache.org/`](http://hadoop.apache.org/)）下载最新的发行版。我在 Ubuntu 14.04 上使用了最新的稳定版本 2.7.3，如下所示：

```scala
$  cd /home
$  wget http://mirrors.ibiblio.org/apache/hadoop/common/hadoop-2.7.3/hadoop-2.7.3.tar.gz

```

接下来，按以下方式创建并提取包在`/opt/yarn`中：

```scala
$  mkdir –p /opt/yarn
$  cd /opt/yarn
$  tar xvzf /root/hadoop-2.7.3.tar.gz

```

# 步骤 2：设置 JAVA_HOME

有关详细信息，请参阅第一章中的 Java 设置部分，*Scala 简介*，并应用相同的更改。

# 步骤 3：创建用户和组

可以按以下方式创建`hadoop`组的`yarn`、`hdfs`和`mapred`用户帐户：

```scala
$  groupadd hadoop
$  useradd -g hadoop yarn
$  useradd -g hadoop hdfs
$  useradd -g hadoop mapred

```

# 步骤 4：创建数据和日志目录

要使用 Hadoop 运行 Spark 作业，需要具有具有各种权限的数据和日志目录。您可以使用以下命令：

```scala
$  mkdir -p /var/data/hadoop/hdfs/nn
$  mkdir -p /var/data/hadoop/hdfs/snn
$  mkdir -p /var/data/hadoop/hdfs/dn
$  chown hdfs:hadoop /var/data/hadoop/hdfs –R
$  mkdir -p /var/log/hadoop/yarn
$  chown yarn:hadoop /var/log/hadoop/yarn -R

```

现在您需要创建 YARN 安装的日志目录，然后按以下方式设置所有者和组：

```scala
$  cd /opt/yarn/hadoop-2.7.3
$  mkdir logs
$  chmod g+w logs
$  chown yarn:hadoop . -R

```

# 步骤 5：配置 core-site.xml

两个属性（即`fs.default.name`和`hadoop.http.staticuser.user`）需要设置到`etc/hadoop/core-site.xml`文件中。只需复制以下代码行：

```scala
<configuration>
       <property>
               <name>fs.default.name</name>
               <value>hdfs://localhost:9000</value>
       </property>
       <property>
               <name>hadoop.http.staticuser.user</name>
               <value>hdfs</value>
       </property>
</configuration>

```

# 步骤 6：配置 hdfs-site.xml

五个属性（即`dfs.replication`，`dfs.namenode.name.dir`，`fs.checkpoint.dir`，`fs.checkpoint.edits.dir`和`dfs.datanode.data.dir`）需要设置到`etc/hadoop/hdfs-site.xml`文件中。只需复制以下代码行：

```scala
<configuration>
 <property>
   <name>dfs.replication</name>
   <value>1</value>
 </property>
 <property>
   <name>dfs.namenode.name.dir</name>
   <value>file:/var/data/hadoop/hdfs/nn</value>
 </property>
 <property>
   <name>fs.checkpoint.dir</name>
   <value>file:/var/data/hadoop/hdfs/snn</value>
 </property>
 <property>
   <name>fs.checkpoint.edits.dir</name>
   <value>file:/var/data/hadoop/hdfs/snn</value>
 </property>
 <property>
   <name>dfs.datanode.data.dir</name>
   <value>file:/var/data/hadoop/hdfs/dn</value>
 </property>
</configuration>

```

# 步骤 7：配置 mapred-site.xml

有一个属性（即`mapreduce.framework.name`）需要设置到`etc/hadoop/mapred-site.xml`文件中。首先，将原始模板文件复制并替换为以下内容到`mapred-site.xml`中：

```scala
$  cp mapred-site.xml.template mapred-site.xml

```

现在，只需复制以下代码行：

```scala
<configuration>
<property>
   <name>mapreduce.framework.name</name>
   <value>yarn</value>
 </property>
</configuration>

```

# 步骤 8：配置 yarn-site.xml

两个属性（即`yarn.nodemanager.aux-services`和`yarn.nodemanager.aux-services.mapreduce.shuffle.class`）需要设置到`etc/hadoop/yarn-site.xml`文件中。只需复制以下代码行：

```scala
<configuration>
<property>
   <name>yarn.nodemanager.aux-services</name>
   <value>mapreduce_shuffle</value>
 </property>
 <property>
   <name>yarn.nodemanager.aux-services.mapreduce.shuffle.class</name>
   <value>org.apache.hadoop.mapred.ShuffleHandler</value>
 </property>
</configuration>

```

# 步骤 9：设置 Java 堆空间

要在基于 Hadoop 的 YARN 集群上运行 Spark 作业，需要为 JVM 指定足够的堆空间。您需要编辑`etc/hadoop/hadoop-env.sh`文件。启用以下属性：

```scala
HADOOP_HEAPSIZE="500"
HADOOP_NAMENODE_INIT_HEAPSIZE="500"

```

现在您还需要编辑`mapred-env.sh`文件，添加以下行：

```scala
HADOOP_JOB_HISTORYSERVER_HEAPSIZE=250

```

最后，请确保已编辑`yarn-env.sh`以使更改对 Hadoop YARN 永久生效：

```scala
JAVA_HEAP_MAX=-Xmx500m
YARN_HEAPSIZE=500

```

# 步骤 10：格式化 HDFS

如果要启动 HDFS NameNode，Hadoop 需要初始化一个目录，用于存储或持久化其用于跟踪文件系统所有元数据的数据。格式化将销毁所有内容并设置一个新的文件系统。然后它使用`etc/hadoop/hdfs-site.xml`中`dfs.namenode.name.dir`参数设置的值。要进行格式化，首先转到`bin`目录并执行以下命令：

```scala
$  su - hdfs
$ cd /opt/yarn/hadoop-2.7.3/bin
$ ./hdfs namenode -format

```

如果前面的命令执行成功，您应该在 Ubuntu 终端上看到以下内容：

```scala
INFO common.Storage: Storage directory /var/data/hadoop/hdfs/nn has been successfully formatted

```

# 第 11 步：启动 HDFS

在第 10 步的`bin`目录中，执行以下命令：

```scala
$ cd ../sbin
$ ./hadoop-daemon.sh start namenode

```

在执行前面的命令成功后，您应该在终端上看到以下内容：

```scala
starting namenode, logging to /opt/yarn/hadoop-2.7.3/logs/hadoop-hdfs-namenode-limulus.out

```

要启动`secondarynamenode`和`datanode`，您应该使用以下命令：

```scala
$ ./hadoop-daemon.sh start secondarynamenode

```

如果前面的命令成功，您应该在终端上收到以下消息：

```scala
Starting secondarynamenode, logging to /opt/yarn/hadoop-2.7.3/logs/hadoop-hdfs-secondarynamenode-limulus.out

```

然后使用以下命令启动数据节点：

```scala
$ ./hadoop-daemon.sh start datanode

```

如果前面的命令成功，您应该在终端上收到以下消息：

```scala
starting datanode, logging to /opt/yarn/hadoop-2.7.3/logs/hadoop-hdfs-datanode-limulus.out

```

现在确保检查所有与这些节点相关的服务是否正在运行，请使用以下命令：

```scala
$ jps

```

您应该观察到类似以下的内容：

```scala
35180 SecondaryNameNode
45915 NameNode
656335 Jps
75814 DataNode

```

# 第 12 步：启动 YARN

要使用 YARN，必须以用户 yarn 启动一个`resourcemanager`和一个节点管理器：

```scala
$  su - yarn
$ cd /opt/yarn/hadoop-2.7.3/sbin
$ ./yarn-daemon.sh start resourcemanager

```

如果前面的命令成功，您应该在终端上收到以下消息：

```scala
starting resourcemanager, logging to /opt/yarn/hadoop-2.7.3/logs/yarn-yarn-resourcemanager-limulus.out

```

然后执行以下命令启动节点管理器：

```scala
$ ./yarn-daemon.sh start nodemanager

```

如果前面的命令成功，您应该在终端上收到以下消息：

```scala
starting nodemanager, logging to /opt/yarn/hadoop-2.7.3/logs/yarn-yarn-nodemanager-limulus.out

```

如果要确保这些节点中的所有服务都在运行，应该使用`$jsp`命令。此外，如果要停止资源管理器或`nodemanager`，请使用以下`g`命令：

```scala
$ ./yarn-daemon.sh stop nodemanager
$ ./yarn-daemon.sh stop resourcemanager

```

# 第 13 步：在 Web UI 上进行验证

访问`http://localhost:50070`查看 NameNode 的状态，并在浏览器上访问`http://localhost:8088`查看资源管理器。

前面的步骤展示了如何配置基于 Hadoop 的 YARN 集群，只有几个节点。但是，如果您想要配置从几个节点到拥有数千个节点的极大集群的基于 Hadoop 的 YARN 集群，请参考[`hadoop.apache.org/docs/current/hadoop-project-dist/hadoop-common/ClusterSetup.html`](https://hadoop.apache.org/docs/current/hadoop-project-dist/hadoop-common/ClusterSetup.html)。

# 在 YARN 集群上提交 Spark 作业

现在，我们的 YARN 集群已经满足最低要求（用于执行一个小的 Spark 作业），要在 YARN 的集群模式下启动 Spark 应用程序，可以使用以下提交命令：

```scala
$ SPARK_HOME/bin/spark-submit --classpath.to.your.Class --master yarn --deploy-mode cluster [options] <app jar> [app options]

```

要运行我们的`KMeansDemo`，应该这样做：

```scala
$ SPARK_HOME/bin/spark-submit  
    --class "com.chapter15.Clustering.KMeansDemo"  
    --master yarn  
    --deploy-mode cluster  
    --driver-memory 16g  
    --executor-memory 4g  
    --executor-cores 4  
    --queue the_queue  
    KMeans-0.0.1-SNAPSHOT-jar-with-dependencies.jar  
    Saratoga_NY_Homes.txt

```

前面的`submit`命令以默认应用程序主节点启动 YARN 集群模式。然后`KMeansDemo`将作为应用程序主节点的子线程运行。为了获取状态更新并在控制台中显示它们，客户端将定期轮询应用程序主节点。当您的应用程序（即我们的情况下的`KMeansDemo`）执行完毕时，客户端将退出。

提交作业后，您可能希望使用 Spark web UI 或 Spark 历史服务器查看进度。此外，您应该参考第十八章，*测试和调试 Spark*）以了解如何分析驱动程序和执行程序日志。

要以客户端模式启动 Spark 应用程序，应该使用之前的命令，只是您将不得不将集群替换为客户端。对于想要使用 Spark shell 的人，请在客户端模式下使用以下命令：

```scala
$ SPARK_HOME/bin/spark-shell --master yarn --deploy-mode client

```

# 在 YARN 集群中进行高级作业提交

如果您选择更高级的方式将 Spark 作业提交到您的 YARN 集群中进行计算，您可以指定其他参数。例如，如果要启用动态资源分配，请将`spark.dynamicAllocation.enabled`参数设置为 true。但是，为了这样做，您还需要指定`minExecutors`，`maxExecutors`和`initialExecutors`，如下所述。另一方面，如果要启用洗牌服务，请将`spark.shuffle.service.enabled`设置为`true`。最后，您还可以尝试使用`spark.executor.instances`参数指定将运行多少执行程序实例。

现在，为了使前面的讨论更具体，您可以参考以下提交命令：

```scala
$ SPARK_HOME/bin/spark-submit   
    --class "com.chapter13.Clustering.KMeansDemo"  
    --master yarn  
    --deploy-mode cluster  
    --driver-memory 16g  
    --executor-memory 4g  
    --executor-cores 4  
    --queue the_queue  
    --conf spark.dynamicAllocation.enabled=true  
    --conf spark.shuffle.service.enabled=true  
    --conf spark.dynamicAllocation.minExecutors=1  
    --conf spark.dynamicAllocation.maxExecutors=4  
    --conf spark.dynamicAllocation.initialExecutors=4  
    --conf spark.executor.instances=4  
    KMeans-0.0.1-SNAPSHOT-jar-with-dependencies.jar  
    Saratoga_NY_Homes.txt

```

然而，前面的作业提交脚本的后果是复杂的，有时是不确定的。根据我的以往经验，如果您从代码中增加分区和执行程序的数量，那么应用程序将更快完成，这是可以接受的。但是，如果您只增加执行程序核心，完成时间是相同的。然而，您可能期望时间比初始时间更短。其次，如果您两次启动前面的代码，您可能期望两个作业都在 60 秒内完成，但这也可能不会发生。通常情况下，两个作业可能在 120 秒后才完成。这有点奇怪，不是吗？然而，下面是一个解释，可以帮助您理解这种情况。

假设您的机器上有 16 个核心和 8GB 内存。现在，如果您使用四个每个核心的执行程序，会发生什么？当您使用执行程序时，Spark 会从 YARN 中保留它，并且 YARN 会分配所需的核心数（例如，在我们的情况下为 1）和所需的内存。实际上，为了更快地处理，所需的内存要比您实际请求的更多。如果您请求 1GB，实际上它将分配几乎 1.5GB，其中包括 500MB 的开销。此外，它可能会为驱动程序分配一个执行程序，可能使用 1024MB 内存（即 1GB）。

有时，不管您的 Spark 作业需要多少内存，而是需要预留多少内存。在前面的例子中，它不会占用 50MB 的内存，而是大约 1.5GB（包括开销）每个执行程序。我们将在本章后面讨论如何在 AWS 上配置 Spark 集群。

# Apache Mesos

当使用 Mesos 时，Mesos 主节点通常会取代 Spark 主节点作为集群管理器（也称为资源管理器）。现在，当驱动程序创建一个 Spark 作业并开始分配相关任务进行调度时，Mesos 确定哪些计算节点处理哪些任务。我们假设您已经在您的机器上配置和安装了 Mesos。

要开始，以下链接可能有助于在您的机器上安装 Mesos。[`blog.madhukaraphatak.com/mesos-single-node-setup-ubuntu/,`](http://blog.madhukaraphatak.com/mesos-single-node-setup-ubuntu/) [`mesos.apache.org/gettingstarted/.`](https://mesos.apache.org/gettingstarted/)

根据硬件配置的不同，需要一段时间。在我的机器上（Ubuntu 14.04 64 位，带有 Core i7 和 32GB RAM），完成构建需要 1 小时。

要通过利用 Mesos 集群模式提交和计算您的 Spark 作业，请确保检查 Spark 二进制包是否可在 Mesos 可访问的位置。此外，请确保您的 Spark 驱动程序可以配置成自动连接到 Mesos。第二个选项是在与 Mesos 从属节点相同的位置安装 Spark。然后，您将需要配置`spark.mesos.executor.home`参数来指向 Spark 分发的位置。需要注意的是，可能指向的默认位置是`SPARK_HOME`。

当 Mesos 在 Mesos 工作节点（也称为计算节点）上首次执行 Spark 作业时，Spark 二进制包必须在该工作节点上可用。这将确保 Spark Mesos 执行程序在后台运行。

Spark 二进制包可以托管到 Hadoop 上，以便让它们可以被访问：

1. 通过`http://`使用 URI/URL（包括 HTTP），

2. 通过`s3n://`使用 Amazon S3，

3. 通过`hdfs://`使用 HDFS。

如果设置了`HADOOP_CONF_DIR`环境变量，参数通常设置为`hdfs://...`；否则为`file://`。

您可以按以下方式指定 Mesos 的主 URL：

1.  对于单主 Mesos 集群，使用`mesos://host:5050`，对于由 ZooKeeper 控制的多主 Mesos 集群，使用`mesos://zk://host1:2181,host2:2181,host3:2181/mesos`。

有关更详细的讨论，请参阅[`spark.apache.org/docs/latest/running-on-mesos.html`](http://spark.apache.org/docs/latest/running-on-mesos.html)。

# 客户端模式

在此模式下，Mesos 框架以这样的方式工作，即 Spark 作业直接在客户端机器上启动。然后等待计算结果，也称为驱动程序输出。然而，为了与 Mesos 正确交互，驱动程序期望在`SPARK_HOME/conf/spark-env.sh`中指定一些特定于应用程序的配置。为了实现这一点，在`$SPARK_HOME /conf`下修改`spark-env.sh.template`文件，并在使用此客户端模式之前，在您的`spark-env.sh`中设置以下环境变量：

```scala
$ export MESOS_NATIVE_JAVA_LIBRARY=<path to libmesos.so>

```

在 Ubuntu 上，此路径通常为`/usr/local /lib/libmesos.so`。另一方面，在 macOS X 上，相同的库称为`libmesos.dylib`，而不是`libmesos.so`：

```scala
$ export SPARK_EXECUTOR_URI=<URL of spark-2.1.0.tar.gz uploaded above>

```

现在，当提交和启动要在集群上执行的 Spark 应用程序时，您将需要将 Mesos `:// HOST:PORT`作为主 URL 传递。这通常是在 Spark 应用程序开发中创建`SparkContext`时完成的，如下所示：

```scala
val conf = new SparkConf()              
                   .setMaster("mesos://HOST:5050")  
                   .setAppName("My app")             
                  .set("spark.executor.uri", "<path to spark-2.1.0.tar.gz uploaded above>")
val sc = new SparkContext(conf)

```

另一种方法是使用`spark-submit`脚本，并在`SPARK_HOME/conf/spark-defaults.conf`文件中配置`spark.executor.uri`。在运行 shell 时，`spark.executor.uri`参数从`SPARK_EXECUTOR_URI`继承，因此不需要作为系统属性冗余传递。只需使用以下命令从您的 Spark shell 访问客户端模式：

```scala
$ SPARK_HOME/bin/spark-shell --master mesos://host:5050

```

# 集群模式

Mesos 上的 Spark 还支持集群模式。如果驱动程序已经启动了 Spark 作业（在集群上），并且计算也已经完成，客户端可以从 Mesos Web UI 访问（驱动程序的）结果。如果您通过`SPARK_HOME/sbin/start-mesos-dispatcher.sh`脚本在集群中启动了`MesosClusterDispatcher`，则可以使用集群模式。

同样，条件是在创建 Spark 应用程序的`SparkContext`时，您必须传递 Mesos 主 URL（例如，`mesos://host:5050`）。在集群模式下启动 Mesos 还会启动作为守护程序在主机上运行的`MesosClusterDispatcher`。

为了获得更灵活和高级的执行 Spark 作业，您还可以使用**Marathon**。使用 Marathon 的优点是可以使用 Marathon 运行`MesosClusterDispatcher`。如果这样做，请确保`MesosClusterDispatcher`在前台运行。

**Marathon**是 Mesos 的一个框架，旨在启动长时间运行的应用程序，在 Mesosphere 中，它作为传统 init 系统的替代品。它具有许多功能，简化了在集群环境中运行应用程序，如高可用性、节点约束、应用程序健康检查、用于脚本编写和服务发现的 API，以及易于使用的 Web 用户界面。它将其扩展和自我修复功能添加到 Mesosphere 功能集中。Marathon 可用于启动其他 Mesos 框架，还可以启动可以在常规 shell 中启动的任何进程。由于它设计用于长时间运行的应用程序，它将确保其启动的应用程序将继续运行，即使它们正在运行的从节点失败。有关在 Mesosphere 中使用 Marathon 的更多信息，请参考 GitHub 页面[`github.com/mesosphere/marathon`](https://github.com/mesosphere/marathon)。

更具体地说，从客户端，您可以使用`spark-submit`脚本提交 Spark 作业到您的 Mesos 集群，并指定主 URL 为`MesosClusterDispatcher`的 URL（例如，`mesos://dispatcher:7077`）。操作如下：

```scala
$ SPARK_HOME /bin/spark-class org.apache.spark.deploy.mesos.MesosClusterDispatcher

```

您可以在 Spark 集群 web UI 上查看驱动程序状态。例如，使用以下作业提交命令来执行：

```scala
$ SPARK_HOME/bin/spark-submit   
--class com.chapter13.Clustering.KMeansDemo   
--master mesos://207.184.161.138:7077    
--deploy-mode cluster   
--supervise   
--executor-memory 20G   
--total-executor-cores 100   
KMeans-0.0.1-SNAPSHOT-jar-with-dependencies.jar   
Saratoga_NY_Homes.txt

```

请注意，传递给 Spark-submit 的 JARS 或 Python 文件应该是 Mesos 从节点可以访问的 URI，因为 Spark 驱动程序不会自动上传本地 jar 文件。最后，Spark 可以在 Mesos 上以两种模式运行：*粗粒度*（默认）和*细粒度*（已弃用）。有关更多详细信息，请参考[`spark.apache.org/docs/latest/running-on-mesos.html`](http://spark.apache.org/docs/latest/running-on-mesos.html)。

在集群模式下，Spark 驱动程序在不同的机器上运行，也就是说，驱动程序、主节点和计算节点是不同的机器。因此，如果尝试使用`SparkContext.addJar`添加 JARS，这将不起作用。为了避免这个问题，请确保客户端上的 jar 文件也可以通过`SparkContext.addJar`使用启动命令中的`--jars`选项。

```scala
$ SPARK_HOME/bin/spark-submit --class my.main.Class    
     --master yarn    
     --deploy-mode cluster    
     --jars my-other-jar.jar, my-other-other-jar.jar    
     my-main-jar.jar    
     app_arg1 app_arg2

```

# 在 AWS 上部署

在前一节中，我们说明了如何在本地、独立或部署模式（YARN 和 Mesos）中提交 spark 作业。在这里，我们将展示如何在 AWS EC2 上的真实集群模式中运行 spark 应用程序。为了使我们的应用程序在 spark 集群模式下运行并实现更好的可扩展性，我们将考虑**Amazon 弹性计算云**（**EC2**）服务作为 IaaS 或**平台即服务**（**PaaS**）。有关定价和相关信息，请参考[`aws.amazon.com/ec2/pricing/`](https://aws.amazon.com/ec2/pricing/)。

# 步骤 1：密钥对和访问密钥配置

我们假设您已经创建了 EC2 账户。首先要求是创建 EC2 密钥对和 AWS 访问密钥。EC2 密钥对是您在通过 SSH 进行安全连接到 EC2 服务器或实例时需要的私钥。要创建密钥，您必须通过 AWS 控制台进行操作，网址为[`docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair`](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)。请参考以下图示，显示了 EC2 账户的密钥对创建页面：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00237.jpeg)**图 17:** AWS 密钥对生成窗口

下载后将其命名为`aws_key_pair.pem`并保存在本地计算机上。然后通过执行以下命令确保权限（出于安全目的，您应该将此文件存储在安全位置，例如`/usr/local/key`）：

```scala
$ sudo chmod 400 /usr/local/key/aws_key_pair.pem

```

现在您需要的是 AWS 访问密钥和您的帐户凭据。如果您希望使用`spark-ec2`脚本从本地机器提交 Spark 作业到计算节点，则需要这些内容。要生成并下载密钥，请登录到您的 AWS IAM 服务，网址为[`docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_CreateAccessKey`](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_CreateAccessKey)。

下载完成后（即`/usr/local/key`），您需要在本地机器上设置两个环境变量。只需执行以下命令：

```scala
$ echo "export AWS_ACCESS_KEY_ID=<access_key_id>" >> ~/.bashrc 
$ echo " export AWS_SECRET_ACCESS_KEY=<secret_access_key_id>" >> ~/.bashrc 
$ source ~/.bashrc

```

# 第 2 步：在 EC2 上配置 Spark 集群

在 Spark 1.6.3 版本发布之前，Spark 分发（即`/SPARK_HOME/ec2`）提供了一个名为**spark-ec2**的 shell 脚本，用于从本地机器启动 EC2 实例中的 Spark 集群。这最终有助于在 AWS 上启动、管理和关闭您将在其中使用的 Spark 集群。然而，自 Spark 2.x 以来，相同的脚本已经移至 AMPLab，以便更容易修复错误并单独维护脚本本身。

该脚本可以从 GitHub 仓库[`github.com/amplab/spark-ec2`](https://github.com/amplab/spark-ec2)中访问和使用。

在 AWS 上启动和使用集群将会产生费用。因此，当计算完成时，停止或销毁集群始终是一个好习惯。否则，这将给您带来额外的费用。有关 AWS 定价的更多信息，请参阅[`aws.amazon.com/ec2/pricing/`](https://aws.amazon.com/ec2/pricing/)。

您还需要为您的 Amazon EC2 实例（控制台）创建 IAM 实例配置文件。有关详细信息，请参阅[`docs.aws.amazon.com/codedeploy/latest/userguide/getting-started-create-iam-instance-profile.html`](https://github.com/amplab/spark-ec2)。为简单起见，让我们下载脚本并将其放置在 Spark 主目录（`$SPARK_HOME/ec2`）下的一个名为`ec2`的目录中。一旦您执行以下命令启动一个新实例，它会自动在集群上设置 Spark、HDFS 和其他依赖项：

```scala
$ SPARK_HOME/spark-ec2 
--key-pair=<name_of_the_key_pair> 
--identity-file=<path_of_the key_pair>  
--instance-type=<AWS_instance_type > 
--region=<region> zone=<zone> 
--slaves=<number_of_slaves> 
--hadoop-major-version=<Hadoop_version> 
--spark-version=<spark_version> 
--instance-profile-name=<profile_name>
launch <cluster-name>

```

我们相信这些参数是不言自明的。或者，如需更多详细信息，请参阅[`github.com/amplab/spark-ec2#readme`](https://github.com/amplab/spark-ec2#readme)。

**如果您已经有一个 Hadoop 集群并希望在其上部署 spark：**如果您正在使用 Hadoop-YARN（甚至是 Apache Mesos），运行 spark 作业相对较容易。即使您不使用其中任何一个，Spark 也可以以独立模式运行。Spark 运行一个驱动程序，然后调用 spark 执行程序。这意味着您需要告诉 Spark 您希望您的 spark 守护程序在哪些节点上运行（以主/从的形式）。在您的`spark/conf`目录中，您可以看到一个名为`slaves`的文件。更新它以提及您想要使用的所有机器。您可以从源代码设置 spark，也可以从网站使用二进制文件。您应该始终为所有节点使用**完全限定域名**（**FQDN**），并确保这些机器中的每一台都可以从您的主节点无密码访问。

假设您已经创建并配置了一个实例配置文件。现在您已经准备好启动 EC2 集群。对于我们的情况，它可能类似于以下内容：

```scala
$ SPARK_HOME/spark-ec2 
 --key-pair=aws_key_pair 
 --identity-file=/usr/local/aws_key_pair.pem 
 --instance-type=m3.2xlarge 
--region=eu-west-1 --zone=eu-west-1a --slaves=2 
--hadoop-major-version=yarn 
--spark-version=2.1.0 
--instance-profile-name=rezacsedu_aws
launch ec2-spark-cluster-1

```

以下图显示了您在 AWS 上的 Spark 主目录：

图 18：AWS 上的集群主页

成功完成后，spark 集群将在您的 EC2 帐户上实例化两个工作节点（从节点）。然而，这个任务有时可能需要大约半个小时，具体取决于您的互联网速度和硬件配置。因此，您可能想要休息一下。在集群设置成功完成后，您将在终端上获得 Spark 集群的 URL。为了确保集群真的在运行，可以在浏览器上检查`https://<master-hostname>:8080`，其中`master-hostname`是您在终端上收到的 URL。如果一切正常，您将发现您的集群正在运行；请参见**图 18**中的集群主页。

# 第 3 步：在 AWS 集群上运行 Spark 作业

现在您的主节点和工作节点都是活动的并正在运行。这意味着您可以将 Spark 作业提交给它们进行计算。但在此之前，您需要使用 SSH 登录远程节点。为此，请执行以下命令以 SSH 远程 Spark 集群：

```scala
$ SPARK_HOME/spark-ec2 
--key-pair=<name_of_the_key_pair> 
--identity-file=<path_of_the _key_pair> 
--region=<region> 
--zone=<zone>
login <cluster-name> 

```

对于我们的情况，应该是以下内容：

```scala
$ SPARK_HOME/spark-ec2 
--key-pair=my-key-pair 
--identity-file=/usr/local/key/aws-key-pair.pem 
--region=eu-west-1 
--zone=eu-west-1
login ec2-spark-cluster-1

```

现在将您的应用程序，即 JAR 文件（或 python/R 脚本），复制到远程实例（在我们的情况下是`ec2-52-48-119-121.eu-west-1.compute.amazonaws.com`）中，通过执行以下命令（在新的终端中）：

```scala
$ scp -i /usr/local/key/aws-key-pair.pem /usr/local/code/KMeans-0.0.1-SNAPSHOT-jar-with-dependencies.jar ec2-user@ec2-52-18-252-59.eu-west-1.compute.amazonaws.com:/home/ec2-user/

```

然后，通过执行以下命令将您的数据（在我们的情况下是`/usr/local/data/Saratoga_NY_Homes.txt`）复制到同一远程实例：

```scala
$ scp -i /usr/local/key/aws-key-pair.pem /usr/local/data/Saratoga_NY_Homes.txt ec2-user@ec2-52-18-252-59.eu-west-1.compute.amazonaws.com:/home/ec2-user/

```

请注意，如果您已经在远程机器上配置了 HDFS 并放置了您的代码/数据文件，您就不需要将 JAR 和数据文件复制到从节点；主节点会自动执行这些操作。

干得好！您几乎完成了！现在，最后，您需要提交您的 Spark 作业以由从节点进行计算。要这样做，只需执行以下命令：

```scala
$SPARK_HOME/bin/spark-submit 
 --class com.chapter13.Clustering.KMeansDemo 
--master spark://ec2-52-48-119-121.eu-west-1.compute.amazonaws.com:7077 
file:///home/ec2-user/KMeans-0.0.1-SNAPSHOT-jar-with-dependencies.jar 
file:///home/ec2-user/Saratoga_NY_Homes.txt

```

如果您的机器上没有设置 HDFS，请将输入文件放在`file:///input.txt`下。

如果您已经将数据放在 HDFS 上，您应该发出类似以下命令的提交命令：

```scala
$SPARK_HOME/bin/spark-submit 
 --class com.chapter13.Clustering.KMeansDemo 
--master spark://ec2-52-48-119-121.eu-west-1.compute.amazonaws.com:7077 
hdfs://localhost:9000/KMeans-0.0.1-SNAPSHOT-jar-with-dependencies.jar 
hdfs://localhost:9000//Saratoga_NY_Homes.txt

```

在作业计算成功完成后，您应该在端口 8080 上看到作业的状态和相关统计信息。

# 第 4 步：暂停、重新启动和终止 Spark 集群

当您的计算完成后，最好停止您的集群以避免额外的成本。要停止您的集群，请从本地机器执行以下命令：

```scala
$ SPARK_HOME/ec2/spark-ec2 --region=<ec2-region> stop <cluster-name>

```

对于我们的情况，应该是以下内容：

```scala
$ SPARK_HOME/ec2/spark-ec2 --region=eu-west-1 stop ec2-spark-cluster-1

```

要在以后重新启动集群，请执行以下命令：

```scala
$ SPARK_HOME/ec2/spark-ec2 -i <key-file> --region=<ec2-region> start <cluster-name>

```

对于我们的情况，应该是以下内容：

```scala
$ SPARK_HOME/ec2/spark-ec2 --identity-file=/usr/local/key/-key-pair.pem --region=eu-west-1 start ec2-spark-cluster-1

```

最后，要在 AWS 上终止您的 Spark 集群，我们使用以下代码：

```scala
$ SPARK_HOME/ec2/spark-ec2 destroy <cluster-name>

```

在我们的情况下，应该是以下内容：

```scala
$ SPARK_HOME /spark-ec2 --region=eu-west-1 destroy ec2-spark-cluster-1

```

Spot 实例非常适合降低 AWS 成本，有时可以将实例成本降低一个数量级。使用这种设施的逐步指南可以在[`blog.insightdatalabs.com/spark-cluster-step-by-step/`](http://blog.insightdatalabs.com/spark-cluster-step-by-step/)上找到。

有时，移动大型数据集，比如 1TB 的原始数据文件，是困难的。在这种情况下，如果您希望您的应用程序能够扩展到更大规模的数据集，最快的方法是将它们从 Amazon S3 或 EBS 设备加载到节点上的 HDFS，并使用`hdfs://`指定数据文件路径。

数据文件或任何其他文件（数据、jar 包、脚本等）都可以托管在 HDFS 上，以使它们具有高度的可访问性：

1. 通过`http://`获取 URI/URL（包括 HTTP）

2. 通过`s3n://`使用 Amazon S3

3. 通过`hdfs://`使用 HDFS

如果设置了`HADOOP_CONF_DIR`环境变量，参数通常设置为`hdfs://...`；否则为`file://`。

# 摘要

在本章中，我们讨论了 Spark 在集群模式下的工作原理及其基础架构。您还看到了如何在集群上部署完整的 Spark 应用程序。您看到了如何在不同的集群模式（如本地、独立、YARN 和 Mesos）中部署集群以运行 Spark 应用程序。最后，您看到了如何使用 EC2 脚本在 AWS 上配置 Spark 集群。我们相信本章将帮助您对 Spark 有一些良好的理解。然而，由于页面限制，我们无法涵盖许多 API 及其底层功能。

如果您遇到任何问题，请不要忘记向 Spark 用户邮件列表`user@spark.apache.org`报告。在这样做之前，请确保您已经订阅了它。在下一章中，您将看到如何测试和调试 Spark 应用程序。


# 第十八章：测试和调试 Spark

“每个人都知道调试比一开始编写程序要难两倍。所以，如果你在编写程序时尽可能聪明，那么你将如何调试它？”

- Brian W. Kernighan

在理想的世界中，我们编写完美的 Spark 代码，一切都完美运行，对吧？开个玩笑；实际上，我们知道处理大规模数据集几乎从来都不那么容易，必然会有一些数据点会暴露出代码的任何边缘情况。

因此，考虑到上述挑战，在本章中，我们将看到如果应用程序是分布式的，测试可能有多么困难；然后，我们将看到一些解决方法。简而言之，本章将涵盖以下主题：

+   在分布式环境中进行测试

+   测试 Spark 应用程序

+   调试 Spark 应用程序

# 在分布式环境中进行测试

莱斯利·兰波特（Leslie Lamport）对分布式系统的定义如下：

“分布式系统是指我无法完成任何工作，因为我从未听说过的某台机器已经崩溃了。”

通过**万维网**（又称**WWW**）进行资源共享，连接的计算机网络（又称集群），是分布式系统的一个很好的例子。这些分布式环境通常非常复杂，经常发生许多异构性。在这些异构环境中进行测试也是具有挑战性的。在本节中，首先我们将观察一些在使用这种系统时经常出现的常见问题。

# 分布式环境

有许多关于分布式系统的定义。让我们看一些定义，然后我们将尝试在之后将上述类别相关联。Coulouris 将分布式系统定义为*一个系统，其中位于网络计算机上的硬件或软件组件仅通过消息传递进行通信和协调*。另一方面，Tanenbaum 以多种方式定义这个术语：

+   *一组独立的计算机，对系统的用户来说，它们看起来像是一个单一的计算机。*

+   *由两个或两个以上独立计算机组成的系统，它们通过同步或异步消息传递来协调它们的处理。*

+   *分布式系统是由网络连接的自主计算机组成的集合，其软件旨在产生一个集成的计算设施。*

现在，根据前面的定义，分布式系统可以分为以下几类：

+   只有硬件和软件是分布式的：本地分布式系统通过局域网连接。

+   用户是分布式的，但是运行后端的计算和硬件资源，例如 WWW。

+   用户和硬件/软件都是分布式的：通过 WAN 连接的分布式计算集群。例如，您可以在使用 Amazon AWS、Microsoft Azure、Google Cloud 或 Digital Ocean 的 droplets 时获得这些类型的计算设施。

# 分布式系统中的问题

在这里，我们将讨论一些在软件和硬件测试过程中需要注意的主要问题，以便 Spark 作业在集群计算中顺利运行，这本质上是一个分布式计算环境。

请注意，所有这些问题都是不可避免的，但我们至少可以调整它们以获得更好的效果。您应该遵循上一章中给出的指示和建议。根据*Kamal Sheel Mishra*和*Anil Kumar Tripathi*在*国际计算机科学和信息技术杂志*第 5 卷（4），2014 年，4922-4925 页中的*分布式软件系统的一些问题、挑战和问题*，URL：[`pdfs.semanticscholar.org/4c6d/c4d739bad13bcd0398e5180c1513f18275d8.pdf`](https://pdfs.semanticscholar.org/4c6d/c4d739bad13bcd0398e5180c1513f18275d8.pdf)，在分布式环境中工作时需要解决几个问题：

+   可扩展性

+   异构语言、平台和架构

+   资源管理

+   安全和隐私

+   透明度

+   开放性

+   互操作性

+   服务质量

+   失败管理

+   同步

+   通信

+   软件架构

+   性能分析

+   生成测试数据

+   测试组件选择

+   测试顺序

+   测试系统的可伸缩性和性能

+   源代码的可用性

+   事件的可重现性

+   死锁和竞争条件

+   测试容错性

+   分布式系统的调度问题

+   分布式任务分配

+   测试分布式软件

+   从硬件抽象级别的监控和控制机制

的确，我们无法完全解决所有这些问题，但是，使用 Spark，我们至少可以控制一些与分布式系统相关的问题。例如，可伸缩性、资源管理、服务质量、故障管理、同步、通信、分布式系统的调度问题、分布式任务分配以及测试分布式软件中的监控和控制机制。其中大部分在前两章中已经讨论过。另一方面，我们可以解决一些与测试和软件相关的问题：如软件架构、性能分析、生成测试数据、测试组件选择、测试顺序、测试系统的可伸缩性和性能，以及源代码的可用性。这些问题至少在本章中将被明确或隐含地涵盖。

# 在分布式环境中软件测试的挑战

在敏捷软件开发中有一些常见的挑战，而在最终部署之前在分布式环境中测试软件时，这些挑战变得更加复杂。通常团队成员需要在错误不断增加后并行合并软件组件。然而，基于紧急性，合并通常发生在测试阶段之前。有时，许多利益相关者分布在不同的团队中。因此，存在误解的巨大潜力，团队经常在其中失去。

例如，Cloud Foundry（[`www.cloudfoundry.org/`](https://www.cloudfoundry.org/)）是一个开源的、高度分布式的 PaaS 软件系统，用于管理云中应用程序的部署和可伸缩性。它承诺不同的功能，如可伸缩性、可靠性和弹性，这些功能在 Cloud Foundry 上的部署中是内在的，需要底层分布式系统实施措施来确保健壮性、弹性和故障转移。

众所周知，软件测试的过程包括*单元测试*、*集成测试*、*烟雾测试*、*验收测试*、*可伸缩性测试*、*性能测试*和*服务质量测试*。在 Cloud Foundry 中，测试分布式系统的过程如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00106.jpeg)**图 1：**像 Cloud 这样的分布式环境中软件测试的一个例子

如前图（第一列）所示，在像 Cloud 这样的分布式环境中进行测试的过程始于针对系统中最小的接口点运行单元测试。在所有单元测试成功执行后，运行集成测试来验证作为单一连贯软件系统的相互作用组件的行为（第二列），这些组件运行在单个盒子上（例如，一个虚拟机（VM）或裸机）。然而，虽然这些测试验证了系统作为单体的整体行为，但并不保证在分布式部署中系统的有效性。一旦集成测试通过，下一步（第三列）是验证系统的分布式部署并运行烟雾测试。

正如您所知，软件的成功配置和单元测试的执行使我们能够验证系统行为的可接受性。通过运行验收测试（第四列）来进行验证。现在，为了克服分布式环境中前面提到的问题和挑战，还有其他隐藏的挑战需要研究人员和大数据工程师来解决，但这些实际上超出了本书的范围。

现在我们知道了分布式环境中软件测试的真正挑战是什么，现在让我们开始对我们的 Spark 代码进行一些测试。下一节将专门讨论测试 Spark 应用程序。

# 测试 Spark 应用程序

有许多方法可以尝试测试您的 Spark 代码，具体取决于它是 Java（您可以进行基本的 JUnit 测试来测试非 Spark 部分）还是 ScalaTest 用于您的 Scala 代码。您还可以通过在本地或小型测试集群上运行 Spark 来进行完整的集成测试。Holden Karau 提供的另一个很棒的选择是使用 Spark-testing base。您可能知道目前还没有用于 Spark 的本机单元测试库。尽管如此，我们可以有以下两种替代方法来使用两个库：

+   ScalaTest

+   Spark 测试基础

但是，在开始测试用 Scala 编写的 Spark 应用程序之前，对单元测试和测试 Scala 方法的背景知识是必需的。

# 测试 Scala 方法

在这里，我们将看到一些测试 Scala 方法的简单技术。对于 Scala 用户来说，这是最熟悉的单元测试框架（您也可以用它来测试 Java 代码，很快也可以用于 JavaScript）。ScalaTest 支持多种不同的测试样式，每种样式都设计用于支持特定类型的测试需求。有关详细信息，请参阅 ScalaTest 用户指南[`www.scalatest.org/user_guide/selecting_a_style`](http://www.scalatest.org/user_guide/selecting_a_style)。尽管 ScalaTest 支持许多样式，但快速入门的一种方法是使用以下 ScalaTest 特质，并以**TDD**（测试驱动开发）风格编写测试：

1.  `FunSuite`

1.  `Assertions`

1.  `BeforeAndAfter`

随时浏览前述 URL 以了解有关这些特质的更多信息；这将使本教程的其余部分顺利进行。

需要注意的是 TDD 是一种开发软件的编程技术，它规定您应该从测试开始开发。因此，它不影响测试的编写方式，而是测试的编写时间。在`ScalaTest.FunSuite`中没有特质或测试样式来强制或鼓励 TDD，`Assertions`和`BeforeAndAfter`只是更类似于 xUnit 测试框架。

在任何样式特质中，ScalaTest 中有三种断言可用：

+   `assert`：这用于在您的 Scala 程序中进行一般断言。

+   `assertResult`：这有助于区分预期值和实际值。

+   `assertThrows`：这用于确保一小段代码抛出预期的异常。

ScalaTest 的断言是在特质`Assertions`中定义的，该特质进一步由`Suite`扩展。简而言之，`Suite`特质是所有样式特质的超级特质。根据 ScalaTest 文档[`www.scalatest.org/user_guide/using_assertions`](http://www.scalatest.org/user_guide/using_assertions)，`Assertions`特质还提供以下功能：

+   `assume`：有条件地取消测试

+   `fail`：无条件地使测试失败

+   `cancel`：无条件地取消测试

+   `succeed`：无条件使测试成功

+   `intercept`：确保一小段代码抛出预期的异常，然后对异常进行断言

+   `assertDoesNotCompile`：确保一小段代码不会编译

+   `assertCompiles`：确保一小段代码确实编译

+   `assertTypeError`：确保一小段代码由于类型（而不是解析）错误而无法编译

+   `withClue`：添加有关失败的更多信息

从前面的列表中，我们将展示其中的一些。在您的 Scala 程序中，您可以通过调用`assert`并传递`Boolean`表达式来编写断言。您可以简单地使用`Assertions`开始编写简单的单元测试用例。`Predef`是一个对象，其中定义了 assert 的行为。请注意，`Predef`的所有成员都会被导入到您的每个 Scala 源文件中。以下源代码将为以下情况打印`Assertion success`：

```scala
package com.chapter16.SparkTesting
object SimpleScalaTest {
  def main(args: Array[String]):Unit= {
    val a = 5
    val b = 5
    assert(a == b)
      println("Assertion success")       
  }
}

```

然而，如果您使`a = 2`和`b = 1`，例如，断言将失败，您将看到以下输出：

图 2：断言失败的一个示例

如果传递一个真表达式，assert 将正常返回。但是，如果提供的表达式为假，assert 将突然终止并出现断言错误。与`AssertionError`和`TestFailedException`形式不同，ScalaTest 的 assert 提供了更多信息，可以告诉您测试用例失败的确切行或表达式。因此，ScalaTest 的 assert 提供了比 Scala 的 assert 更好的错误消息。

例如，对于以下源代码，您应该会遇到`TestFailedException`，告诉您 5 不等于 4：

```scala
package com.chapter16.SparkTesting
import org.scalatest.Assertions._
object SimpleScalaTest {
  def main(args: Array[String]):Unit= {
    val a = 5
    val b = 4
    assert(a == b)
      println("Assertion success")       
  }
}

```

以下图显示了前面的 Scala 测试的输出：

图 3：TestFailedException 的一个示例

以下源代码解释了使用`assertResult`单元测试来测试方法的结果：

```scala
package com.chapter16.SparkTesting
import org.scalatest.Assertions._
object AssertResult {
  def main(args: Array[String]):Unit= {
    val x = 10
    val y = 6
    assertResult(3) {
      x - y
    }
  }
}

```

前面的断言将失败，Scala 将抛出异常`TestFailedException`并打印`Expected 3 but got 4`（*图 4*）：

图 4：TestFailedException 的另一个示例

现在，让我们看一个单元测试来显示预期的异常：

```scala
package com.chapter16.SparkTesting
import org.scalatest.Assertions._
object ExpectedException {
  def main(args: Array[String]):Unit= {
    val s = "Hello world!"
    try {
      s.charAt(0)
      fail()
    } catch {
      case _: IndexOutOfBoundsException => // Expected, so continue
    }
  }
}

```

如果尝试访问超出索引的数组元素，前面的代码将告诉您是否允许访问前面字符串`Hello world!`的第一个字符。如果您的 Scala 程序可以访问索引中的值，断言将失败。这也意味着测试用例失败了。因此，前面的测试用例自然会失败，因为第一个索引包含字符`H`，您应该看到以下错误消息（*图 5*）：

图 5：TestFailedException 的第三个示例

然而，现在让我们尝试访问位置为`-1`的索引，如下所示：

```scala
package com.chapter16.SparkTesting
import org.scalatest.Assertions._
object ExpectedException {
  def main(args: Array[String]):Unit= {
    val s = "Hello world!"
    try {
      s.charAt(-1)
      fail()
    } catch {
      case _: IndexOutOfBoundsException => // Expected, so continue
    }
  }
}

```

现在断言应该为真，因此测试用例将通过。最后，代码将正常终止。现在，让我们检查我们的代码片段是否会编译。很多时候，您可能希望确保代表出现的“用户错误”的代码的某种排序根本不会编译。目标是检查库对错误的强度，以阻止不需要的结果和行为。ScalaTest 的`Assertions` trait 包括以下语法：

```scala
assertDoesNotCompile("val a: String = 1")

```

如果您想确保一段代码由于类型错误（而不是语法错误）而无法编译，请使用以下方法：

```scala
assertTypeError("val a: String = 1")

```

语法错误仍会导致抛出`TestFailedException`。最后，如果您想要声明一段代码确实编译，可以使用以下方法更明显地表达：

```scala
assertCompiles("val a: Int = 1")

```

完整的示例如下所示：

```scala
package com.chapter16.SparkTesting
import org.scalatest.Assertions._ 
object CompileOrNot {
  def main(args: Array[String]):Unit= {
    assertDoesNotCompile("val a: String = 1")
    println("assertDoesNotCompile True")

    assertTypeError("val a: String = 1")
    println("assertTypeError True")

    assertCompiles("val a: Int = 1")
    println("assertCompiles True")

    assertDoesNotCompile("val a: Int = 1")
    println("assertDoesNotCompile True")
  }
}

```

前面代码的输出如下图所示：

图 6：多个测试一起

由于页面限制，我们现在想要结束基于 Scala 的单元测试。但是，对于其他单元测试用例，您可以参考 Scala 测试指南[`www.scalatest.org/user_guide`](http://www.scalatest.org/user_guide)。

# 单元测试

在软件工程中，通常会对源代码的单个单元进行测试，以确定它们是否适合使用。这种软件测试方法也称为单元测试。这种测试确保软件工程师或开发人员开发的源代码符合设计规范并按预期工作。

另一方面，单元测试的目标是以模块化的方式分离程序的每个部分。然后尝试观察所有单独部分是否正常工作。在任何软件系统中，单元测试有几个好处：

+   **早期发现问题：**它可以在开发周期的早期发现错误或规范的缺失部分。

+   **促进变更：**它有助于重构和升级，而不必担心破坏功能。

+   **简化集成：**它使集成测试更容易编写。

+   **文档：**它提供了系统的实时文档。

+   **设计：**它可以作为项目的正式设计。

# 测试 Spark 应用程序

我们已经看到如何使用 Scala 的内置`ScalaTest`包测试您的 Scala 代码。但是，在本小节中，我们将看到如何测试我们用 Scala 编写的 Spark 应用程序。将讨论以下三种方法：

+   **方法 1：**使用 JUnit 测试 Spark 应用程序

+   **方法 2：**使用`ScalaTest`包测试 Spark 应用程序

+   **方法 3：**使用 Spark 测试基础测试 Spark 应用程序

这里将讨论方法 1 和方法 2，并提供一些实际代码。但是，对方法 3 的详细讨论将在下一小节中提供。为了使理解简单易懂，我们将使用著名的单词计数应用程序来演示方法 1 和方法 2。

# 方法 1：使用 Scala JUnit 测试

假设您已经在 Scala 中编写了一个应用程序，可以告诉您文档或文本文件中有多少个单词，如下所示：

```scala
package com.chapter16.SparkTesting
import org.apache.spark._
import org.apache.spark.sql.SparkSession
class wordCounterTestDemo {
  val spark = SparkSession
    .builder
    .master("local[*]")
    .config("spark.sql.warehouse.dir", "E:/Exp/")
    .appName(s"OneVsRestExample")
    .getOrCreate()
  def myWordCounter(fileName: String): Long = {
    val input = spark.sparkContext.textFile(fileName)
    val counts = input.flatMap(_.split(" ")).distinct()
    val counter = counts.count()
    counter
  }
}

```

上述代码简单地解析文本文件，并通过简单地拆分单词执行`flatMap`操作。然后，它执行另一个操作，只考虑不同的单词。最后，`myWordCounter`方法计算有多少个单词，并返回计数器的值。

现在，在进行正式测试之前，让我们检查上述方法是否有效。只需添加主方法并创建一个对象，如下所示：

```scala
package com.chapter16.SparkTesting
import org.apache.spark._
import org.apache.spark.sql.SparkSession
object wordCounter {
  val spark = SparkSession
    .builder
    .master("local[*]")
    .config("spark.sql.warehouse.dir", "E:/Exp/")
    .appName("Testing")
    .getOrCreate()    
  val fileName = "data/words.txt";
  def myWordCounter(fileName: String): Long = {
    val input = spark.sparkContext.textFile(fileName)
    val counts = input.flatMap(_.split(" ")).distinct()
    val counter = counts.count()
    counter
  }
  def main(args: Array[String]): Unit = {
    val counter = myWordCounter(fileName)
    println("Number of words: " + counter)
  }
}

```

如果您执行上述代码，您应该观察到以下输出：`单词数量：214`。太棒了！它真的作为一个本地应用程序运行。现在，使用 Scala JUnit 测试用例测试上述测试用例。

```scala
package com.chapter16.SparkTesting
import org.scalatest.Assertions._
import org.junit.Test
import org.apache.spark.sql.SparkSession
class wordCountTest {
  val spark = SparkSession
    .builder
    .master("local[*]")
    .config("spark.sql.warehouse.dir", "E:/Exp/")
    .appName(s"OneVsRestExample")
    .getOrCreate()   
    @Test def test() {
      val fileName = "data/words.txt"
      val obj = new wordCounterTestDemo()
      assert(obj.myWordCounter(fileName) == 214)
           }
    spark.stop()
}

```

如果您仔细查看先前的代码，您会发现在`test()`方法之前我使用了`Test`注解。在`test()`方法内部，我调用了`assert()`方法，其中实际的测试发生。在这里，我们尝试检查`myWordCounter()`方法的返回值是否等于 214。现在将先前的代码作为 Scala 单元测试运行，如下所示（*图 7*）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00151.jpeg)**图 7：**将 Scala 代码作为 Scala JUnit 测试运行

现在，如果测试用例通过，您应该在 Eclipse IDE 上观察以下输出（*图 8*）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00173.jpeg)**图 8：**单词计数测试用例通过

例如，尝试以以下方式断言：

```scala
assert(obj.myWordCounter(fileName) == 210)

```

如果上述测试用例失败，您应该观察到以下输出（*图 9*）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00299.jpeg)**图 9：**测试用例失败

现在让我们看一下方法 2 以及它如何帮助我们改进。

# 方法 2：使用 FunSuite 测试 Scala 代码

现在，让我们通过仅返回文档中文本的 RDD 来重新设计上述测试用例，如下所示：

```scala
package com.chapter16.SparkTesting
import org.apache.spark._
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.SparkSession
class wordCountRDD {
  def prepareWordCountRDD(file: String, spark: SparkSession): RDD[(String, Int)] = {
    val lines = spark.sparkContext.textFile(file)
    lines.flatMap(_.split(" ")).map((_, 1)).reduceByKey(_ + _)
  }
}

```

因此，上述类中的`prepareWordCountRDD()`方法返回一个字符串和整数值的 RDD。现在，如果我们想要测试`prepareWordCountRDD()`方法的功能，我们可以通过将测试类扩展为`ScalaTest`包的`FunSuite`和`BeforeAndAfterAll`来更明确地进行测试。测试以以下方式进行：

+   将测试类扩展为`ScalaTest`包的`FunSuite`和`BeforeAndAfterAll`

+   覆盖`beforeAll()`创建 Spark 上下文

+   使用`test()`方法执行测试，并在`test()`方法内部使用`assert()`方法

+   覆盖`afterAll()`方法停止 Spark 上下文

根据前面的步骤，让我们看一个用于测试前面的`prepareWordCountRDD()`方法的类：

```scala
package com.chapter16.SparkTesting
import org.scalatest.{ BeforeAndAfterAll, FunSuite }
import org.scalatest.Assertions._
import org.apache.spark.sql.SparkSession
import org.apache.spark.rdd.RDD
class wordCountTest2 extends FunSuite with BeforeAndAfterAll {
  var spark: SparkSession = null
  def tokenize(line: RDD[String]) = {
    line.map(x => x.split(' ')).collect()
  }
  override def beforeAll() {
    spark = SparkSession
      .builder
      .master("local[*]")
      .config("spark.sql.warehouse.dir", "E:/Exp/")
      .appName(s"OneVsRestExample")
      .getOrCreate()
  }  
  test("Test if two RDDs are equal") {
    val input = List("To be,", "or not to be:", "that is the question-", "William Shakespeare")
    val expected = Array(Array("To", "be,"), Array("or", "not", "to", "be:"), Array("that", "is", "the", "question-"), Array("William", "Shakespeare"))
    val transformed = tokenize(spark.sparkContext.parallelize(input))
    assert(transformed === expected)
  }  
  test("Test for word count RDD") {
    val fileName = "C:/Users/rezkar/Downloads/words.txt"
    val obj = new wordCountRDD
    val result = obj.prepareWordCountRDD(fileName, spark)    
    assert(result.count() === 214)
  }
  override def afterAll() {
    spark.stop()
  }
}

```

第一个测试说，如果两个 RDD 以两种不同的方式实现，内容应该是相同的。因此，第一个测试应该通过。我们将在下面的示例中看到这一点。现在，对于第二个测试，正如我们之前看到的，RDD 的单词计数为 214，但让我们假设它暂时未知。如果它恰好是 214，测试用例应该通过，这是预期的行为。

因此，我们期望两个测试都通过。现在，在 Eclipse 上，运行测试套件作为`ScalaTest-File`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00342.jpeg) **图 10：**作为 ScalaTest-File 运行测试套件

现在您应该观察以下输出（*图 11*）。输出显示我们执行了多少个测试用例，其中有多少通过、失败、取消、忽略或挂起。它还显示了执行整体测试所需的时间。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00268.jpeg)**图 11：**运行两个测试套件作为 ScalaTest 文件的测试结果

太棒了！测试用例通过了。现在，让我们尝试使用`test()`方法在两个单独的测试中更改断言中的比较值，如下所示：

```scala
test("Test for word count RDD") { 
  val fileName = "data/words.txt"
  val obj = new wordCountRDD
  val result = obj.prepareWordCountRDD(fileName, spark)    
  assert(result.count() === 210)
}
test("Test if two RDDs are equal") {
  val input = List("To be", "or not to be:", "that is the question-", "William Shakespeare")
  val expected = Array(Array("To", "be,"), Array("or", "not", "to", "be:"), Array("that", "is", "the", "question-"), Array("William", "Shakespeare"))
  val transformed = tokenize(spark.sparkContext.parallelize(input))
  assert(transformed === expected)
}

```

现在，您应该期望测试用例将失败。现在运行之前的类作为`ScalaTest-File`（*图 12*）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00029.jpeg)**图 12：**运行前面的两个测试套件作为 ScalaTest-File 的测试结果

干得好！我们已经学会了如何使用 Scala 的 FunSuite 进行单元测试。然而，如果你仔细评估前面的方法，你会同意存在一些缺点。例如，您需要确保显式管理`SparkContext`的创建和销毁。作为开发人员或程序员，您必须编写更多的代码行来测试一个样本方法。有时，代码重复出现，因为*Before*和*After*步骤必须在所有测试套件中重复。然而，这是值得讨论的，因为通用代码可以放在一个共同的特性中。

现在的问题是我们如何改善我们的体验？我的建议是使用 Spark 测试基础使生活更轻松和更直接。我们将讨论如何使用 Spark 测试基础进行单元测试。

# 方法 3：使用 Spark 测试基础使生活更轻松

Spark 测试基础帮助您轻松测试大部分 Spark 代码。那么，这种方法的优点是什么呢？实际上有很多。例如，使用这种方法，代码不啰嗦，但我们可以得到非常简洁的代码。API 本身比 ScalaTest 或 JUnit 更丰富。多语言支持，例如 Scala、Java 和 Python。它支持内置的 RDD 比较器。您还可以用它来测试流应用程序。最后但最重要的是，它支持本地和集群模式的测试。这对于在分布式环境中进行测试非常重要。

GitHub 仓库位于[`github.com/holdenk/spark-testing-base`](https://github.com/holdenk/spark-testing-base)。

在使用 Spark 测试基础进行单元测试之前，您应该在 Maven 友好的`pom.xml`文件中包含以下依赖项，以便在 Spark 2.x 项目树中使用：

```scala
<dependency>
  <groupId>com.holdenkarau</groupId>
  <artifactId>spark-testing-base_2.10</artifactId>
  <version>2.0.0_0.6.0</version>
</dependency>

```

对于 SBT，您可以添加以下依赖项：

```scala
"com.holdenkarau" %% "spark-testing-base" % "2.0.0_0.6.0"

```

请注意，建议在 Maven 和 SBT 的情况下通过指定`<scope>test</scope>`将前面的依赖项添加到`test`范围中。除此之外，还有其他考虑因素，如内存需求和 OOM 以及禁用并行执行。SBT 测试中的默认 Java 选项太小，无法支持运行多个测试。有时，如果作业以本地模式提交，测试 Spark 代码会更加困难！现在您可以自然地理解在真正的集群模式下（即 YARN 或 Mesos）会有多么困难。

为了摆脱这个问题，您可以在项目树中的`build.sbt`文件中增加内存量。只需添加以下参数：

```scala
javaOptions ++= Seq("-Xms512M", "-Xmx2048M", "-XX:MaxPermSize=2048M", "-XX:+CMSClassUnloadingEnabled")

```

但是，如果您使用 Surefire，可以添加以下内容：

```scala
<argLine>-Xmx2048m -XX:MaxPermSize=2048m</argLine>

```

在基于 Maven 的构建中，您可以通过设置环境变量的值来实现。有关此问题的更多信息，请参阅[`maven.apache.org/configure.html`](https://maven.apache.org/configure.html)。

这只是一个运行 spark 测试基础自己测试的例子。因此，您可能需要设置更大的值。最后，请确保您已经通过添加以下代码行来禁用 SBT 中的并行执行：

```scala
parallelExecution in Test := false

```

另一方面，如果您使用 surefire，请确保`forkCount`和`reuseForks`分别设置为 1 和 true。让我们看一个使用 Spark 测试基础的例子。以下源代码有三个测试用例。第一个测试用例是一个比较，看看 1 是否等于 1，显然会通过。第二个测试用例计算句子中单词的数量，比如`Hello world! My name is Reza`，并比较是否有六个单词。最后一个测试用例尝试比较两个 RDD：

```scala
package com.chapter16.SparkTesting
import org.scalatest.Assertions._
import org.apache.spark.rdd.RDD
import com.holdenkarau.spark.testing.SharedSparkContext
import org.scalatest.FunSuite
class TransformationTestWithSparkTestingBase extends FunSuite with SharedSparkContext {
  def tokenize(line: RDD[String]) = {
    line.map(x => x.split(' ')).collect()
  }
  test("works, obviously!") {
    assert(1 == 1)
  }
  test("Words counting") {
    assert(sc.parallelize("Hello world My name is Reza".split("\\W")).map(_ + 1).count == 6)
  }
  test("Testing RDD transformations using a shared Spark Context") {
    val input = List("Testing", "RDD transformations", "using a shared", "Spark Context")
    val expected = Array(Array("Testing"), Array("RDD", "transformations"), Array("using", "a", "shared"), Array("Spark", "Context"))
    val transformed = tokenize(sc.parallelize(input))
    assert(transformed === expected)
  }
}

```

从前面的源代码中，我们可以看到我们可以使用 Spark 测试基础执行多个测试用例。成功执行后，您应该观察到以下输出（*图 13*）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00280.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00093.jpeg)**图 13：**使用 Spark 测试基础进行成功执行和通过测试的示例

# 在 Windows 上配置 Hadoop 运行时

我们已经看到如何在 Eclipse 或 IntelliJ 上测试用 Scala 编写的 Spark 应用程序，但还有一个潜在的问题不容忽视。尽管 Spark 可以在 Windows 上运行，但 Spark 是设计为在类 UNIX 操作系统上运行的。因此，如果您在 Windows 环境中工作，则需要额外小心。

在使用 Eclipse 或 IntelliJ 在 Windows 上开发用于解决数据分析、机器学习、数据科学或深度学习应用程序的 Spark 应用程序时，您可能会遇到 I/O 异常错误，您的应用程序可能无法成功编译或可能被中断。实际上，问题在于 Spark 期望在 Windows 上也有一个 Hadoop 的运行时环境。例如，如果您在 Eclipse 上首次运行 Spark 应用程序，比如`KMeansDemo.scala`，您将遇到一个 I/O 异常，内容如下：

```scala
17/02/26 13:22:00 ERROR Shell: Failed to locate the winutils binary in the hadoop binary path java.io.IOException: Could not locate executable null\bin\winutils.exe in the Hadoop binaries.

```

原因是默认情况下，Hadoop 是为 Linux 环境开发的，如果您在 Windows 平台上开发 Spark 应用程序，则需要一个桥梁，为 Spark 的 Hadoop 运行时提供一个正确执行的环境。I/O 异常的详细信息可以在下图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00088.gif)**图 14：**由于未能在 Hadoop 二进制路径中找到 winutils 二进制而发生的 I/O 异常

那么，如何解决这个问题呢？解决方案很简单。正如错误消息所说，我们需要一个可执行文件，即`winutils.exe`。现在从[`github.com/steveloughran/winutils/tree/master/hadoop-2.7.1/bin`](https://github.com/steveloughran/winutils/tree/master/hadoop-2.7.1/bin)下载`winutils.exe`文件，将其粘贴到 Spark 分发目录中，并配置 Eclipse。更具体地说，假设您的包含 Hadoop 的 Spark 分发位于`C:/Users/spark-2.1.0-bin-hadoop2.7`。在 Spark 分发中，有一个名为 bin 的目录。现在，将可执行文件粘贴到那里（即`路径=C:/Users/spark-2.1.0-binhadoop2.7/bin/`）。

解决方案的第二阶段是转到 Eclipse，然后选择主类（即本例中的`KMeansDemo.scala`），然后转到运行菜单。从运行菜单中，转到运行配置选项，然后从中选择环境选项卡，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00049.jpeg)**图 15：**由于 Hadoop 二进制路径中缺少 winutils 二进制而发生的 I/O 异常的解决方案

如果您选择该选项卡，您将有选项为 Eclipse 使用 JVM 创建新的环境变量。现在创建一个名为`HADOOP_HOME`的新环境变量，并将值设置为`C:/Users/spark-2.1.0-bin-hadoop2.7/`。现在点击“应用”按钮并重新运行您的应用程序，您的问题应该得到解决。

需要注意的是，在 Windows 上使用 PySpark 时，也需要`winutils.exe`文件。有关 PySpark 的参考，请参阅第十九章，*PySpark 和 SparkR*。

请注意，前面的解决方案也适用于调试您的应用程序。有时，即使出现前面的错误，您的 Spark 应用程序也会正常运行。但是，如果数据集的大小很大，前面的错误很可能会发生。

# 调试 Spark 应用程序

在本节中，我们将看到如何调试在 Eclipse 或 IntelliJ 上本地运行（独立或集群模式在 YARN 或 Mesos 中）的 Spark 应用程序。然而，在深入讨论之前，有必要了解 Spark 应用程序中的日志记录。

# 使用 log4j 记录 Spark 回顾

我们已经在第十四章，*使用 Spark MLlib 对数据进行集群化*中讨论过这个话题。然而，让我们重复相同的内容，以使您的思维与当前讨论*调试 Spark 应用程序*保持一致。如前所述，Spark 使用 log4j 进行自身的日志记录。如果您正确配置了 Spark，Spark 会将所有操作记录到 shell 控制台。以下是文件的样本快照：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00259.jpeg)**图 16：** log4j.properties 文件的快照

将默认的 spark-shell 日志级别设置为 WARN。运行 spark-shell 时，此类的日志级别用于覆盖根记录器的日志级别，以便用户可以为 shell 和常规 Spark 应用程序设置不同的默认值。当启动由执行器执行并由驱动程序管理的作业时，我们还需要附加 JVM 参数。为此，您应该编辑`conf/spark-defaults.conf`。简而言之，可以添加以下选项：

```scala
spark.executor.extraJavaOptions=-Dlog4j.configuration=file:/usr/local/spark-2.1.1/conf/log4j.properties spark.driver.extraJavaOptions=-Dlog4j.configuration=file:/usr/local/spark-2.1.1/conf/log4j.properties

```

为了使讨论更清晰，我们需要隐藏 Spark 生成的所有日志。然后我们可以将它们重定向到文件系统中进行记录。另一方面，我们希望我们自己的日志被记录在 shell 和单独的文件中，这样它们就不会与 Spark 的日志混在一起。从这里开始，我们将指向 Spark 的文件，其中我们自己的日志所在，特别是`/var/log/sparkU.log`。这个`log4j.properties`文件在应用程序启动时被 Spark 接管，因此我们除了将其放在指定的位置之外，不需要做任何事情：

```scala
package com.chapter14.Serilazition
import org.apache.log4j.LogManager
import org.apache.log4j.Level
import org.apache.spark.sql.SparkSession
object myCustomLog {
  def main(args: Array[String]): Unit = {   
    val log = LogManager.getRootLogger    
    //Everything is printed as INFO once the log level is set to INFO untill you set the level to new level for example WARN. 
    log.setLevel(Level.INFO)
    log.info("Let's get started!")    
    // Setting logger level as WARN: after that nothing prints other than WARN
    log.setLevel(Level.WARN)    
    // Creating Spark Session
    val spark = SparkSession
      .builder
      .master("local[*]")
      .config("spark.sql.warehouse.dir", "E:/Exp/")
      .appName("Logging")
      .getOrCreate()
    // These will note be printed!
    log.info("Get prepared!")
    log.trace("Show if there is any ERROR!")
    //Started the computation and printing the logging information
    log.warn("Started")
    spark.sparkContext.parallelize(1 to 20).foreach(println)
    log.warn("Finished")
  }
}

```

在上述代码中，一旦将日志级别设置为`INFO`，则所有内容都将以 INFO 打印，直到将级别设置为新级别，例如`WARN`。然而，在那之后，不会打印任何信息或跟踪等，不会被打印。除此之外，log4j 与 Spark 支持几个有效的日志记录级别。前面的代码成功执行应该生成以下输出：

```scala
17/05/13 16:39:14 INFO root: Let's get started!
17/05/13 16:39:15 WARN root: Started
4 
1 
2 
5 
3 
17/05/13 16:39:16 WARN root: Finished

```

您还可以在`conf/log4j.properties`中设置 Spark shell 的默认日志记录。Spark 提供了 log4j 的模板作为属性文件，我们可以扩展和修改该文件以记录 Spark 的日志。转到`SPARK_HOME/conf`目录，您应该看到`log4j.properties.template`文件。将其重命名为`log4j.properties`后，您应该使用以下`conf/log4j.properties.template`。在开发 Spark 应用程序时，您可以将`log4j.properties`文件放在项目目录下，例如在 Eclipse 等基于 IDE 的环境中工作。但是，要完全禁用日志记录，只需将`log4j.logger.org`标志设置为`OFF`，如下所示：

```scala
log4j.logger.org=OFF

```

到目前为止，一切都很容易。然而，在前面的代码段中，我们还没有注意到一个问题。`org.apache.log4j.Logger`类的一个缺点是它不可序列化，这意味着我们不能在对 Spark API 的某些部分进行操作时在闭包内使用它。例如，假设我们在我们的 Spark 代码中执行以下操作：

```scala
object myCustomLogger {
  def main(args: Array[String]):Unit= {
    // Setting logger level as WARN
    val log = LogManager.getRootLogger
    log.setLevel(Level.WARN)
    // Creating Spark Context
    val conf = new SparkConf().setAppName("My App").setMaster("local[*]")
    val sc = new SparkContext(conf)
    //Started the computation and printing the logging information
    //log.warn("Started")
    val i = 0
    val data = sc.parallelize(i to 100000)
    data.map{number =>
      log.info(“My number”+ i)
      number.toString
    }
    //log.warn("Finished")
  }
}

```

您应该会遇到一个异常，显示“任务”不可序列化，如下所示：

```scala
org.apache.spark.SparkException: Job aborted due to stage failure: Task not serializable: java.io.NotSerializableException: ...
Exception in thread "main" org.apache.spark.SparkException: Task not serializable 
Caused by: java.io.NotSerializableException: org.apache.log4j.spi.RootLogger
Serialization stack: object not serializable

```

首先，我们可以尝试以一种天真的方式解决这个问题。您可以做的是使执行实际操作的 Scala 类（使用`extends Serializable`）可序列化。例如，代码如下所示：

```scala
class MyMapper(n: Int) extends Serializable {
  @transient lazy val log = org.apache.log4j.LogManager.getLogger("myLogger")
  def logMapper(rdd: RDD[Int]): RDD[String] =
    rdd.map { i =>
      log.warn("mapping: " + i)
      (i + n).toString
    }
  }

```

本节旨在讨论日志记录。然而，我们借此机会使其更具通用性，适用于 Spark 编程和问题。为了更有效地克服“任务不可序列化”错误，编译器将尝试通过使其可序列化并强制 SPark 接受整个对象（而不仅仅是 lambda）来发送整个对象。然而，这会显著增加洗牌，特别是对于大对象！其他方法包括使整个类`Serializable`或仅在 map 操作中传递的 lambda 函数内声明实例。有时，跨节点保留不可序列化的对象也可以起作用。最后，使用`forEachPartition()`或`mapPartitions()`而不仅仅是`map()`并创建不可序列化的对象。总之，这些是解决该问题的方法：

+   使类可序列化

+   仅在 map 中传递的 lambda 函数内声明实例

+   将 NotSerializable 对象设置为静态，并在每台机器上创建一次

+   调用`forEachPartition()`或`mapPartitions()`而不是`map()`并创建 NotSerializable 对象

在前面的代码中，我们使用了`@transient lazy`注解，将`Logger`类标记为非持久化。另一方面，包含`apply`方法（即`MyMapperObject`）的对象，它实例化了`MyMapper`类的对象如下：

```scala
//Companion object 
object MyMapper {
  def apply(n: Int): MyMapper = new MyMapper(n)
}

```

最后，包含`main()`方法的对象如下：

```scala
//Main object
object myCustomLogwithClosureSerializable {
  def main(args: Array[String]) {
    val log = LogManager.getRootLogger
    log.setLevel(Level.WARN)
    val spark = SparkSession
      .builder
      .master("local[*]")
      .config("spark.sql.warehouse.dir", "E:/Exp/")
      .appName("Testing")
      .getOrCreate()
    log.warn("Started")
    val data = spark.sparkContext.parallelize(1 to 100000)
    val mapper = MyMapper(1)
    val other = mapper.logMapper(data)
    other.collect()
    log.warn("Finished")
  }

```

现在，让我们看另一个例子，它提供了更好的洞察力，以继续解决我们正在讨论的问题。假设我们有一个计算两个整数乘法的类如下：

```scala
class MultiplicaitonOfTwoNumber {
  def multiply(a: Int, b: Int): Int = {
    val product = a * b
    product
  }
}

```

现在，如果您尝试在 lambda 闭包中使用此类来计算乘法，您将得到我们之前描述的“任务不可序列化”错误。现在我们可以简单地使用`foreachPartition()`和 lambda，如下所示：

```scala
val myRDD = spark.sparkContext.parallelize(0 to 1000)
    myRDD.foreachPartition(s => {
      val notSerializable = new MultiplicaitonOfTwoNumber
      println(notSerializable.multiply(s.next(), s.next()))
    })

```

现在，如果您编译它，应该返回所需的结果。为了方便起见，包含`main()`方法的完整代码如下：

```scala
package com.chapter16.SparkTesting
import org.apache.spark.sql.SparkSession
class MultiplicaitonOfTwoNumber {
  def multiply(a: Int, b: Int): Int = {
    val product = a * b
    product
  }
}
object MakingTaskSerilazible {
  def main(args: Array[String]): Unit = {
    val spark = SparkSession
      .builder
      .master("local[*]")
      .config("spark.sql.warehouse.dir", "E:/Exp/")
      .appName("MakingTaskSerilazible")
      .getOrCreate()
 val myRDD = spark.sparkContext.parallelize(0 to 1000)
    myRDD.foreachPartition(s => {
      val notSerializable = new MultiplicaitonOfTwoNumber
      println(notSerializable.multiply(s.next(), s.next()))
    })
  }
}

```

输出如下：

```scala
0
5700
1406
156
4032
7832
2550
650

```

# 调试 Spark 应用程序

在本节中，我们将讨论如何在 Eclipse 或 IntelliJ 上本地运行或以 YARN 或 Mesos 的独立或集群模式运行的 Spark 应用程序进行调试。在开始之前，您还可以阅读[﻿https://hortonworks.com/hadoop-tutorial/setting-spark-development-environment-scala/](https://hortonworks.com/hadoop-tutorial/setting-spark-development-environment-scala/)上的调试文档。

# 在 Eclipse 上调试 Spark 应用程序作为 Scala 调试

为了实现这一点，只需将您的 Eclipse 配置为调试您的 Spark 应用程序，就像调试常规的 Scala 代码一样。要配置，请选择 Run | Debug Configuration | Scala Application，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00022.jpeg)**图 17：**配置 Eclipse 以调试 Spark 应用程序，作为常规的 Scala 代码调试

假设我们想要调试我们的`KMeansDemo.scala`并要求 Eclipse（您也可以在 InteliJ IDE 上有类似的选项）从第 56 行开始执行，并在第 95 行设置断点。要这样做，运行您的 Scala 代码进行调试，您应该在 Eclipse 上观察到以下情景：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00327.jpeg)**图 18：**在 Eclipse 上调试 Spark 应用程序

然后，Eclipse 将在你要求它在第 95 行停止执行时暂停，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00221.jpeg)**图 19：**在 Eclipse 上调试 Spark 应用程序（断点）

总之，为了简化上面的例子，如果在第 56 行和第 95 行之间有任何错误，Eclipse 将显示错误实际发生的位置。否则，如果没有中断，它将按照正常的工作流程进行。

# 在本地和独立模式下运行 Spark 作业的调试

在本地或独立模式下调试你的 Spark 应用程序时，你应该知道调试驱动程序程序和调试执行程序之间是不同的，因为使用这两种类型的节点需要传递不同的提交参数给`spark-submit`。在本节中，我将使用端口 4000 作为地址。例如，如果你想调试驱动程序程序，你可以将以下内容添加到你的`spark-submit`命令中：

```scala
--driver-java-options -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=4000

```

之后，你应该设置你的远程调试器连接到你提交驱动程序的节点。对于前面的情况，指定了端口号 4000。然而，如果某些东西（即其他 Spark 作业、其他应用程序或服务等）已经在该端口上运行，你可能还需要自定义该端口，即更改端口号。

另一方面，连接到执行程序与前面的选项类似，除了地址选项。更具体地说，你需要用你本地机器的地址（IP 地址或带有端口号的主机名）替换地址。然而，测试你是否可以从实际计算发生的 Spark 集群访问你的本地机器是一种良好的实践和建议。例如，你可以使用以下选项使调试环境对你的`spark-submit`命令启用：

```scala
--num-executors 1\
--executor-cores 1 \
--conf "spark.executor.extraJavaOptions=-agentlib:jdwp=transport=dt_socket,server=n,address=localhost:4000,suspend=n"

```

总之，使用以下命令提交你的 Spark 作业（在这种情况下是`KMeansDemo`应用程序）：

```scala
$ SPARK_HOME/bin/spark-submit \
--class "com.chapter13.Clustering.KMeansDemo" \
--master spark://ubuntu:7077 \
--num-executors 1\
--executor-cores 1 \
--conf "spark.executor.extraJavaOptions=-agentlib:jdwp=transport=dt_socket,server=n,address= host_name_to_your_computer.org:5005,suspend=n" \
--driver-java-options -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=4000 \
 KMeans-0.0.1-SNAPSHOT-jar-with-dependencies.jar \
Saratoga_NY_Homes.txt

```

现在，启动你的本地调试器处于监听模式，并启动你的 Spark 程序。最后，等待执行程序连接到你的调试器。你将在你的终端上看到以下消息：

```scala
Listening for transport dt_socket at address: 4000 

```

重要的是要知道，你只需要将执行程序的数量设置为 1。设置多个执行程序将尝试连接到你的调试器，并最终创建一些奇怪的问题。需要注意的是，有时设置`SPARK_JAVA_OPTS`有助于调试在本地或独立模式下运行的 Spark 应用程序。命令如下：

```scala
$ export SPARK_JAVA_OPTS=-agentlib:jdwp=transport=dt_socket,server=y,address=4000,suspend=y,onuncaught=n

```

然而，自 Spark 1.0.0 发布以来，`SPARK_JAVA_OPTS`已被弃用，并由`spark-defaults.conf`和传递给 Spark-submit 或 Spark-shell 的命令行参数取代。需要注意的是，在`spark-defaults.conf`中设置`spark.driver.extraJavaOptions`和`spark.executor.extraJavaOptions`并不是`SPARK_JAVA_OPTS`的替代。但坦率地说，`SPARK_JAVA_OPTS`仍然运行得很好，你也可以尝试一下。

# 在 YARN 或 Mesos 集群上调试 Spark 应用程序

在 YARN 上运行 Spark 应用程序时，有一个选项可以通过修改`yarn-env.sh`来启用：

```scala
YARN_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=4000 $YARN_OPTS"

```

现在，远程调试将通过 Eclipse 或 IntelliJ IDE 上的端口 4000 可用。第二个选项是通过设置`SPARK_SUBMIT_OPTS`。你可以使用 Eclipse 或 IntelliJ 开发你的 Spark 应用程序，然后将其提交以在远程多节点 YARN 集群上执行。我在 Eclipse 或 IntelliJ 上创建一个 Maven 项目，并将我的 Java 或 Scala 应用程序打包为一个 jar 文件，然后将其提交为一个 Spark 作业。然而，为了将你的 IDE（如 Eclipse 或 IntelliJ）调试器连接到你的 Spark 应用程序，你可以使用`SPARK_SUBMIT_OPTS`环境变量定义所有的提交参数，如下所示：

```scala
$ export SPARK_SUBMIT_OPTS=-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=4000

```

然后按照以下方式提交你的 Spark 作业（请根据你的需求和设置相应地更改值）：

```scala
$ SPARK_HOME/bin/spark-submit \
--class "com.chapter13.Clustering.KMeansDemo" \
--master yarn \
--deploy-mode cluster \
--driver-memory 16g \
--executor-memory 4g \
--executor-cores 4 \
--queue the_queue \
--num-executors 1\
--executor-cores 1 \
--conf "spark.executor.extraJavaOptions=-agentlib:jdwp=transport=dt_socket,server=n,address= host_name_to_your_computer.org:4000,suspend=n" \
--driver-java-options -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=4000 \
 KMeans-0.0.1-SNAPSHOT-jar-with-dependencies.jar \
Saratoga_NY_Homes.txt

```

运行上述命令后，它将等待您连接调试器，如下所示：`Listening for transport dt_socket at address: 4000`。现在，您可以在 IntelliJ 调试器上配置您的 Java 远程应用程序（Scala 应用程序也可以），如下截图所示：

图 20：在 IntelliJ 上配置远程调试器

对于上述情况，10.200.1.101 是远程计算节点的 IP 地址，您的 Spark 作业基本上是在该节点上运行的。最后，您将需要通过在 IntelliJ 的运行菜单下单击“调试”来启动调试器。然后，如果调试器连接到您的远程 Spark 应用程序，您将在 IntelliJ 的应用程序控制台中看到日志信息。现在，如果您可以设置断点，其他操作都是正常的调试。下图显示了在 IntelliJ 上暂停具有断点的 Spark 作业时的示例：

图 21：在 IntelliJ 上暂停 Spark 作业并设置断点时的示例

尽管它运行良好，但有时我发现在 Eclipse 甚至 IntelliJ 上使用`SPARK_JAVA_OPTS`并不会对调试过程有太大帮助。相反，当在真实集群（YARN、Mesos 或 AWS）上运行 Spark 作业时，请使用和导出`SPARK_WORKER_OPTS`和`SPARK_MASTER_OPTS`，如下所示：

```scala
$ export SPARK_WORKER_OPTS="-Xdebug -Xrunjdwp:server=y,transport=dt_socket,address=4000,suspend=n"
$ export SPARK_MASTER_OPTS="-Xdebug -Xrunjdwp:server=y,transport=dt_socket,address=4000,suspend=n"

```

然后按以下方式启动您的 Master 节点：

```scala
$ SPARKH_HOME/sbin/start-master.sh

```

现在打开一个 SSH 连接到实际运行 Spark 作业的远程机器，并将您的本地主机映射到`host_name_to_your_computer.org:5000`的 4000 端口（即`localhost:4000`），假设集群位于`host_name_to_your_computer.org:5000`并在端口 5000 上监听。现在，您的 Eclipse 将认为您只是在调试本地 Spark 应用程序或进程。但是，要实现这一点，您将需要在 Eclipse 上配置远程调试器，如下图所示：

图 22：在 Eclipse 上连接远程主机以调试 Spark 应用程序

就是这样！现在您可以像在桌面上一样在您的实时集群上进行调试。上述示例是在将 Spark Master 设置为 YARN-client 模式下运行时的。但是，当在 Mesos 集群上运行时，它也应该起作用。如果您使用 YARN-cluster 模式运行，您可能需要将驱动程序设置为连接到调试器，而不是将调试器附加到驱动程序，因为您不一定会预先知道驱动程序将在哪种模式下执行。

# 使用 SBT 调试 Spark 应用程序

上述设置在大多数情况下适用于使用 Maven 项目的 Eclipse 或 IntelliJ。假设您已经完成了应用程序，并且正在使用您喜欢的 IDE（如 IntelliJ 或 Eclipse）进行工作，如下所示：

```scala
object DebugTestSBT {
  def main(args: Array[String]): Unit = {
    val spark = SparkSession
      .builder
      .master("local[*]")
      .config("spark.sql.warehouse.dir", "C:/Exp/")
      .appName("Logging")
      .getOrCreate()      
    spark.sparkContext.setCheckpointDir("C:/Exp/")
    println("-------------Attach debugger now!--------------")
    Thread.sleep(8000)
    // code goes here, with breakpoints set on the lines you want to pause
  }
}

```

现在，如果您想将此作业提交到本地集群（独立运行），第一步是将应用程序及其所有依赖项打包成一个 fat JAR。为此，请使用以下命令：

```scala
$ sbt assembly

```

这将生成 fat JAR。现在的任务是将 Spark 作业提交到本地集群。您需要在系统的某个地方有 spark-submit 脚本：

```scala
$ export SPARK_JAVA_OPTS=-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005

```

上述命令导出一个 Java 参数，该参数将用于启动带有调试器的 Spark：

```scala
$ SPARK_HOME/bin/spark-submit --class Test --master local[*] --driver-memory 4G --executor-memory 4G /path/project-assembly-0.0.1.jar

```

在上述命令中，`--class`需要指向作业的完全限定类路径。成功执行此命令后，您的 Spark 作业将在不中断断点的情况下执行。现在，要在您的 IDE（比如 IntelliJ）上获得调试功能，您需要配置连接到集群。有关官方 IDEA 文档的更多详细信息，请参考[`stackoverflow.com/questions/21114066/attach-intellij-idea-debugger-to-a-running-java-process`](http://stackoverflow.com/questions/21114066/attach-intellij-idea-debugger-to-a-running-java-process)。

需要注意的是，如果您只创建一个默认的远程运行/调试配置并保留默认端口 5005，它应该可以正常工作。现在，当您提交下一次作业并看到附加调试器的消息时，您有八秒钟切换到 IntelliJ IDEA 并触发此运行配置。程序将继续执行并在您定义的任何断点处暂停。然后，您可以像任何普通的 Scala/Java 程序一样逐步执行它。您甚至可以进入 Spark 函数以查看它在幕后做了什么。

# 总结

在本章中，您看到了测试和调试 Spark 应用程序有多么困难。在分布式环境中，这甚至可能更加关键。我们还讨论了一些解决这些问题的高级方法。总之，您学会了在分布式环境中进行测试的方法。然后，您学会了更好地测试您的 Spark 应用程序。最后，我们讨论了一些调试 Spark 应用程序的高级方法。

我们相信这本书将帮助您对 Spark 有一些很好的理解。然而，由于页面限制，我们无法涵盖许多 API 及其基本功能。如果您遇到任何问题，请不要忘记向 Spark 用户邮件列表`user@spark.apache.org`报告。在这样做之前，请确保您已经订阅了它。

这更多或多少是我们在 Spark 高级主题上的小旅程的结束。现在，我们对您作为读者的一般建议是，如果您对数据科学、数据分析、机器学习、Scala 或 Spark 相对较新，您应该首先尝试了解您想要执行的分析类型。更具体地说，例如，如果您的问题是一个机器学习问题，尝试猜测哪种类型的学习算法应该是最合适的，即分类、聚类、回归、推荐或频繁模式挖掘。然后定义和规划问题，之后，您应该基于我们之前讨论过的 Spark 的特征工程概念生成或下载适当的数据。另一方面，如果您认为您可以使用深度学习算法或 API 解决问题，您应该使用其他第三方算法并与 Spark 集成并立即工作。

我们最后的建议是，读者定期浏览 Spark 网站（[`spark.apache.org/`](http://spark.apache.org/)）以获取更新，并尝试将常规提供的 Spark API 与其他第三方应用程序或工具结合起来，以获得合作的最佳结果。
