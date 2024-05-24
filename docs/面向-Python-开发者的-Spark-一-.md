# 面向 Python 开发者的 Spark（一）

> 原文：[`zh.annas-archive.org/md5/1F2AF128A0828F73EE5EA24057C01070`](https://zh.annas-archive.org/md5/1F2AF128A0828F73EE5EA24057C01070)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

*Python 开发人员的 Spark*旨在将 Python 的优雅和灵活性与 Apache Spark 的强大和多功能性相结合。Spark 是用 Scala 编写的，并在 Java 虚拟机上运行。然而，它是多语言的，并为 Java、Scala、Python 和 R 提供了绑定和 API。Python 是一种设计良好的语言，具有广泛的专业库。本书探讨了 PySpark 在 PyData 生态系统中的应用。一些著名的 PyData 库包括 Pandas、Blaze、Scikit-Learn、Matplotlib、Seaborn 和 Bokeh。这些库是开源的。它们由数据科学家和 Python 开发人员社区开发、使用和维护。PySpark 与 PyData 生态系统很好地集成在一起，得到了 Anaconda Python 发行版的认可。本书提出了一个构建数据密集型应用程序的旅程，以及涵盖以下步骤的架构蓝图：首先，使用 Spark 建立基础设施。其次，获取、收集、处理和存储数据。第三，从收集的数据中获得见解。第四，实时传输数据并实时处理。最后，可视化信息。

本书的目标是通过构建分析社交网络上 Spark 社区互动的应用程序来学习 PySpark 和 PyData 库。重点是 Twitter 数据。

# 本书内容

第一章，“设置 Spark 虚拟环境”，介绍了如何创建一个分隔的虚拟机作为我们的沙盒或开发环境，以实验 Spark 和 PyData 库。它涵盖了如何安装 Spark 和 Python Anaconda 发行版，其中包括 PyData 库。在此过程中，我们解释了关键的 Spark 概念、Python Anaconda 生态系统，并构建了一个 Spark 词频统计应用程序。

第二章，“使用 Spark 构建批处理和流处理应用程序”，奠定了*数据密集型应用程序架构*的基础。它描述了应用程序架构蓝图的五个层次：基础设施、持久性、集成、分析和参与。我们与三个社交网络建立了 API 连接：Twitter、GitHub 和 Meetup。本章提供了连接到这三个非平凡 API 的工具，以便您在以后阶段创建自己的数据混搭。

第三章，“使用 Spark 处理数据”，介绍了如何从 Twitter 收集数据，并使用 Pandas、Blaze 和 SparkSQL 以及它们各自的数据框架数据结构进行处理。我们继续使用 Spark SQL 进行进一步的调查和技术，利用 Spark 数据框架数据结构。

第四章，“使用 Spark 从数据中学习”，概述了 Spark MLlib 算法库的不断扩展。它涵盖了监督学习和无监督学习、推荐系统、优化和特征提取算法。我们通过 Python Scikit-Learn 和 Spark MLlib K-means 聚类将 Twitter 收集的数据集进行了处理，以区分与*Apache Spark*相关的推文。

第五章，“使用 Spark 流式传输实时数据”，奠定了流式架构应用程序的基础，并描述了它们的挑战、约束和好处。我们用 TCP 套接字来说明流式传输的概念，然后直接从 Twitter firehose 进行实时推文摄取和处理。我们还描述了 Flume，这是一个可靠、灵活和可扩展的数据摄取和传输管道系统。Flume、Kafka 和 Spark 的结合在不断变化的环境中提供了无与伦比的稳健性、速度和灵活性。我们在本章结束时对两种流式架构范式——Lambda 和 Kappa 架构进行了一些评论和观察。

第六章，*可视化洞察和趋势*，侧重于一些关键的可视化技术。它涵盖了如何构建词云并展示它们直观的力量，以揭示成千上万条推文中携带的关键词、情绪和表情。然后，我们专注于使用 Bokeh 进行交互式地图可视化。我们从零开始构建世界地图，并创建关键推文的散点图。我们最终的可视化是将伦敦的实际谷歌地图叠加在一起，突出即将举行的聚会及其各自的主题。

# 本书所需内容

您需要好奇心、毅力和对数据、软件工程、应用架构和可扩展性以及简洁美观的可视化的热情。范围广泛。

您需要对 Python 或具有面向对象和函数式编程能力的类似语言有很好的理解。有使用 Python、R 或任何类似工具进行数据整理的初步经验会有所帮助。

您需要欣赏如何构想、构建和扩展数据应用程序。

# 本书的受众

目标受众包括以下内容：

+   数据科学家是主要的利益相关方。本书将帮助您释放 Spark 的力量，并利用您的 Python、R 和机器学习背景。

+   专注于 Python 的软件开发人员将很容易扩展他们的技能，使用 Spark 作为处理引擎和 Python 可视化库和 Web 框架创建数据密集型应用程序。

+   数据架构师可以创建快速数据管道，并构建包含批处理和流处理的著名 Lambda 架构，以实时渲染数据洞察，使用 Spark 和 Python 丰富的生态系统，也将受益于本书。

# 约定

在本书中，您会发现一些区分不同类型信息的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“在存储 Jupyter 或 IPython 笔记本的目录`examples/AN_Spark`中使用`IPYNB`启动 PySpark”。

代码块设置如下：

```py
# Word count on 1st Chapter of the Book using PySpark

# import regex module
import re
# import add from operator module
from operator import add

# read input file
file_in = sc.textFile('/home/an/Documents/A00_Documents/Spark4Py 20150315')
```

任何命令行输入或输出都以以下方式编写：

```py
# install anaconda 2.x.x
bash Anaconda-2.x.x-Linux-x86[_64].sh

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，会在文本中以这种方式出现：“安装 VirtualBox 后，让我们打开 Oracle VM VirtualBox Manager 并单击**New**按钮。”

### 注意

警告或重要说明会以这种方式出现在一个框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：设置 Spark 虚拟环境

在本章中，我们将为开发目的构建一个隔离的虚拟环境。该环境将由 Spark 和 Python Anaconda 发行版提供的 PyData 库驱动。这些库包括 Pandas、Scikit-Learn、Blaze、Matplotlib、Seaborn 和 Bokeh。我们将执行以下活动：

+   使用 Anaconda Python 发行版设置开发环境。这将包括启用由 PySpark 驱动的 IPython Notebook 环境，用于我们的数据探索任务。

+   安装和启用 Spark，以及 Pandas、Scikit-Learn、Blaze、Matplotlib 和 Bokeh 等 PyData 库。

+   构建一个“单词计数”示例应用程序，以确保一切正常运行。

过去十年见证了像亚马逊、谷歌、Twitter、LinkedIn 和 Facebook 这样的数据驱动巨头的崛起和主导地位。这些公司通过播种、分享或披露他们的基础设施概念、软件实践和数据处理框架，培育了一个充满活力的开源软件社区。这已经改变了企业技术、系统和软件架构。

这包括利用虚拟化、云技术和软件定义网络的新基础设施和 DevOps（开发和运维）概念。

为了处理千兆字节的数据，Hadoop 被开发并开源，它从**Google 文件系统**（**GFS**）和相邻的分布式计算框架 MapReduce 中汲取了灵感。克服了扩展的复杂性，同时控制成本也导致了新数据存储的大量出现。最近的数据库技术示例包括列数据库 Cassandra、文档数据库 MongoDB 和图数据库 Neo4J。

由于其处理大型数据集的能力，Hadoop 已经培育出一个庞大的生态系统，可以使用 Pig、Hive、Impala 和 Tez 更迭地和交互地查询数据。Hadoop 在使用 MapReduce 时只能以批处理模式运行，因此它很繁琐。Spark 通过针对磁盘输入输出和带宽密集型 MapReduce 作业的缺点，正在为分析和数据处理领域带来革命。

Spark 是用 Scala 编写的，因此与由**Java 虚拟机**（**JVM**）驱动的生态系统本地集成。Spark 早期提供了 Python API 和绑定，通过启用 PySpark。Spark 架构和生态系统本质上是多语言的，显然有着 Java 主导系统的强大存在。

本书将专注于 PySpark 和 PyData 生态系统。Python 是学术和科学界进行数据密集处理的首选语言之一。Python 在数据处理方面发展了丰富的库和工具生态系统，包括 Pandas 和 Blaze 的数据操作、Scikit-Learn 的机器学习以及 Matplotlib、Seaborn 和 Bokeh 的数据可视化。因此，本书的目标是构建一个由 Spark 和 Python 驱动的数据密集型应用程序的端到端架构。为了将这些概念付诸实践，我们将分析 Twitter、GitHub 和 Meetup 等社交网络。我们将关注 Spark 和开源软件社区的活动和社交互动，通过 GitHub、Twitter 和 Meetup 进行调查。

构建数据密集型应用程序需要高度可扩展的基础架构、多语言存储、无缝数据集成、多范式分析处理和高效的可视化。下一段描述了我们将在整本书中采用的数据密集型应用程序架构蓝图。这是本书的骨干。我们将在更广泛的 PyData 生态系统的背景下发现 Spark。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

# 理解数据密集型应用程序的架构

为了理解数据密集型应用程序的架构，使用以下概念框架。架构设计在以下五个层次上：

+   基础设施层

+   持久层

+   集成层

+   分析层

+   参与层

以下屏幕截图描述了**数据密集型应用程序框架**的五个层次：

![理解数据密集型应用程序的架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_01.jpg)

从下到上，让我们逐层介绍它们的主要目的。

## 基础设施层

基础设施层主要涉及虚拟化，可扩展性和持续集成。在实际操作和虚拟化方面，我们将通过在 VirtualBox 中构建我们自己的开发环境，并使用 Spark 和 Python 的 Anaconda 发行版来驱动虚拟机。如果我们希望从那里扩展，我们可以在云中创建类似的环境。创建一个分隔的开发环境并移动到测试和生产部署的实践可以自动化，并且可以成为由 DevOps 工具（如**Vagrant**，**Chef**，**Puppet**和**Docker**）驱动的持续集成周期的一部分。 Docker 是一个非常受欢迎的开源项目，它简化了新环境的安装和部署。本书将仅限于使用 VirtualBox 构建虚拟机。从数据密集型应用程序架构的角度来看，我们通过提及可扩展性和持续集成来描述基础设施层的基本步骤。

## 持久层

持久层根据数据需求和形状管理各种存储库。它确保设置和管理多语言数据存储。它包括关系数据库管理系统，如**MySQL**和**PostgreSQL**；键值数据存储，如**Hadoop**，**Riak**和**Redis**；列数据库，如**HBase**和**Cassandra**；文档数据库，如**MongoDB**和**Couchbase**；以及图数据库，如**Neo4j**。持久层管理 Hadoop 的 HDFS 等各种文件系统。它与从本地硬盘到 Amazon S3 的各种存储系统进行交互。它管理各种文件存储格式，如`csv`，`json`和`parquet`，这是一种面向列的格式。

## 集成层

集成层专注于数据获取、转换、质量、持久性、消费和治理。它基本上由以下五个 C 驱动：*连接*，*收集*，*校正*，*组合*和*消费*。

这五个步骤描述了数据的生命周期。它们关注如何获取感兴趣的数据集，探索它，迭代地完善和丰富收集的信息，并准备好供使用。因此，这些步骤执行以下操作：

+   **连接**：针对从各种数据源获取数据的最佳方式，这些数据源提供的 API，输入格式，如果存在的话，输入模式，数据收集速率和提供者的限制

+   **校正**：专注于转换数据以进行进一步处理，并确保所接收的数据的质量和一致性得到维护

+   **收集**：查看存储哪些数据以及以何种格式，以便在后期阶段轻松进行数据组合和使用

+   **组合**：集中关注如何混合收集的各种数据集，并丰富信息以构建引人注目的数据驱动产品

+   消费：负责数据供应和呈现，以及确保正确的数据在正确的时间到达正确的个人

+   控制：随着数据、组织和参与者的增长，迟早会需要这第六个额外步骤，它关乎确保数据治理

以下图表描述了数据获取和精炼的迭代过程，以供使用：

![集成层](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_02.jpg)

## 分析层

分析层是 Spark 处理数据的地方，使用各种模型、算法和机器学习管道来获取洞察力。在本书中，分析层由 Spark 提供支持。我们将在随后的章节中更深入地探讨 Spark 的优点。简而言之，它之所以如此强大，是因为它允许在单一统一平台上进行多种分析处理范式。它允许批处理、流处理和交互式分析。在具有较长延迟周期的大型数据集上进行批处理允许我们提取模式和洞察力，这些可以用于流处理模式中的实时事件。交互式和迭代式分析更适合数据探索。Spark 提供了 Python 和 R 的绑定和 API。通过其 SparkSQL 模块和 Spark Dataframe，它提供了一个非常熟悉的分析接口。

## 参与层

参与层与最终用户进行交互，并提供仪表板、交互式可视化和警报。我们将重点关注 PyData 生态系统提供的工具，如 Matplotlib、Seaborn 和 Bokeh。

# 理解 Spark

Hadoop 随着数据增长而水平扩展。Hadoop 在廉价硬件上运行，因此具有成本效益。可扩展的分布式处理框架使得机构能够在大型廉价集群上分析 PB 级数据。Hadoop 是 map-reduce 的第一个开源实现。Hadoop 依赖于称为 HDFS（Hadoop 分布式文件系统）的分布式存储框架。Hadoop 在批处理作业中运行 map-reduce 任务。Hadoop 需要在每个 map、shuffle 和 reduce 过程步骤中将数据持久化到磁盘上。这种批处理作业的开销和延迟对性能产生不利影响。

Spark 是一个快速的、分布式的大规模数据处理通用分析计算引擎。与 Hadoop 的主要突破之处在于，Spark 允许数据在处理步骤之间通过内存处理进行共享。

Spark 独特之处在于它允许四种不同的数据分析和处理样式。Spark 可用于：

+   批处理：此模式用于操作大型数据集，通常执行大型 map-reduce 作业

+   流处理：此模式用于近实时处理传入信息

+   迭代式：这种模式适用于机器学习算法，例如梯度下降，其中数据被重复访问以达到收敛

+   交互式：此模式用于数据探索，因为大量数据在内存中，并且由于 Spark 的非常快的响应时间

以下图表突出了前面四种处理样式：

![理解 Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_03.jpg)

Spark 有三种模式：单一模式，在单台机器上独立运行；两种分布式模式，在机器集群上运行——在 Hadoop 分布式资源管理器 Yarn 上，或者在与 Spark 同时开发的开源集群管理器 Mesos 上：

![理解 Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_04.jpg)

Spark 提供了 Scala、Java、Python 和 R 的多语言接口。

## Spark 库

Spark 自带一些强大的库：

+   SparkSQL：提供类似 SQL 的能力来查询结构化数据并交互式地探索大型数据集

+   SparkMLLIB：为机器学习提供主要算法和管道框架

+   **Spark Streaming**：用于对数据进行近实时分析，使用微批处理和滑动窗口处理传入的数据流

+   **Spark GraphX**：用于图处理和复杂连接实体和关系的计算

### PySpark 的实际应用

Spark 是用 Scala 编写的。整个 Spark 生态系统自然地利用了 JVM 环境，并充分利用了 HDFS。 Hadoop HDFS 是 Spark 支持的许多数据存储之一。Spark 是不可知的，并且从一开始就与多个数据源、类型和格式进行交互。

PySpark 不是 Spark 在支持 Java 的 Python 方言（如 Jython）上的抄写版本。PySpark 提供了围绕 Spark 的集成 API 绑定，并允许在集群的所有节点中完全使用 Python 生态系统，使用 pickle Python 序列化，并更重要的是，提供对 Python 的丰富生态系统的访问，如 Scikit-Learn 等机器学习库或数据处理库，如 Pandas。

当我们初始化一个 Spark 程序时，Spark 程序必须做的第一件事是创建一个`SparkContext`对象。它告诉 Spark 如何访问集群。Python 程序创建一个`PySparkContext`。Py4J 是将 Python 程序绑定到 Spark JVM `SparkContext`的网关。JVM `SparkContext`序列化应用程序代码和闭包，并将它们发送到集群进行执行。集群管理器分配资源并安排，并将闭包发送到集群中的 Spark 工作程序，根据需要激活 Python 虚拟机。在每台机器上，Spark Worker 由控制计算、存储和缓存的执行者管理。

以下是 Spark 驱动程序如何管理 PySpark 上下文和 Spark 上下文以及其与集群管理器通过本地文件系统和与 Spark 工作程序的交互的示例：

![PySpark in action](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_05.jpg)

### 弹性分布式数据集

Spark 应用程序由驱动程序组成，驱动程序运行用户的主要函数，在集群上创建分布式数据集，并对这些数据集执行各种并行操作（转换和操作）。

Spark 应用程序作为一组独立的进程运行，由驱动程序中的`SparkContext`协调。

`SparkContext`将从**集群管理器**分配系统资源（机器、内存、CPU）。

`SparkContext`管理执行者，执行者管理集群中的工作节点。驱动程序具有需要运行的 Spark 作业。作业被拆分为任务，提交给执行者完成。执行者负责在每台机器上进行计算、存储和缓存。

Spark 中的关键构建块是**RDD**（**弹性分布式数据集**）。数据集是元素的集合。分布式意味着数据集可以在集群中的任何节点上。弹性意味着数据集可能会丢失或部分丢失，而不会对正在进行的计算造成重大伤害，因为 Spark 将从内存中的数据血统重新计算，也称为操作的**DAG**（**有向无环图**）。基本上，Spark 将在缓存中快照 RDD 的状态。如果在操作过程中其中一台计算机崩溃，Spark 将从缓存的 RDD 和操作的 DAG 重新构建 RDD。RDD 可以从节点故障中恢复。

RDD 上有两种操作类型：

+   **转换**：转换获取现有的 RDD，并导致新转换的 RDD 的指针。RDD 是不可变的。一旦创建，就无法更改。每个转换都会创建一个新的 RDD。转换是惰性评估的。转换只有在发生操作时才会执行。在失败的情况下，转换的数据血统会重建 RDD。

+   **操作**：对 RDD 的操作会触发一个 Spark 作业并产生一个值。操作操作会导致 Spark 执行（懒惰的）转换操作，这些操作是计算由操作返回的 RDD 所需的。操作会导致一系列操作的 DAG。DAG 被编译成阶段，每个阶段都作为一系列任务执行。任务是工作的基本单位。

以下是关于 RDD 的一些有用信息：

+   RDD 是从数据源（如 HDFS 文件或数据库查询）创建的。有三种方法可以创建 RDD：

+   从数据存储中读取

+   转换现有的 RDD

+   使用内存集合

+   RDD 可以通过`map`或`filter`等函数进行转换，产生新的 RDD。

+   对 RDD 进行的操作，比如 first、take、collect 或 count，会将结果传递到 Spark 驱动程序。Spark 驱动程序是用户与 Spark 集群交互的客户端。

以下图示了 RDD 的转换和操作：

![弹性分布式数据集](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_06.jpg)

# 了解 Anaconda

Anaconda 是一个广泛使用的免费 Python 发行版，由**Continuum**维护（[`www.continuum.io/`](https://www.continuum.io/)）。我们将使用 Anaconda 提供的主流软件堆栈来生成我们的应用程序。在本书中，我们将使用 PySpark 和 PyData 生态系统。PyData 生态系统由**Continuum**推广、支持和维护，并由**Anaconda** Python 发行版提供支持。Anaconda Python 发行版在安装 Python 环境方面节省了时间和烦恼；我们将与 Spark 一起使用它。Anaconda 有自己的软件包管理，补充了传统的`pip` `install`和`easy-install`。Anaconda 自带了一些最重要的软件包，比如 Pandas、Scikit-Learn、Blaze、Matplotlib 和 Bokeh。对已安装库的升级只需在控制台上输入一个简单的命令：

```py
$ conda update

```

可以使用以下命令获取我们环境中安装的库的列表：

```py
$ conda list

```

堆栈的关键组件如下：

+   **Anaconda**：这是一个免费的 Python 发行版，几乎包含了 200 个用于科学、数学、工程和数据分析的 Python 软件包。

+   **Conda**：这是一个软件包管理器，负责安装复杂软件堆栈的所有依赖项。它不仅限于 Python，还管理 R 和其他语言的安装过程。

+   **Numba**：它提供了在 Python 中加速代码的能力，具有高性能函数和即时编译。

+   **Blaze**：它通过提供统一和可适应的接口来访问各种数据提供程序（包括流式 Python、Pandas、SQLAlchemy 和 Spark），实现了大规模数据分析。

+   **Bokeh**：它为大型和流式数据集提供交互式数据可视化。

+   **Wakari**：这允许我们在托管环境中共享和部署 IPython Notebooks 和其他应用程序。

下图显示了 Anaconda 堆栈的组件：

![了解 Anaconda](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_07.jpg)

# 建立由 Spark 驱动的环境

在本节中，我们将学习如何设置 Spark：

+   在运行 Ubuntu 14.04 的虚拟机中创建一个独立的开发环境，以便不会干扰任何现有系统。

+   安装 Spark 1.3.0 及其依赖项，即。

+   安装 Anaconda Python 2.7 环境以及所有必需的库，比如 Pandas、Scikit-Learn、Blaze 和 Bokeh，并启用 PySpark，以便可以通过 IPython Notebooks 访问。

+   设置我们环境的后端或数据存储。我们将使用 MySQL 作为关系数据库，MongoDB 作为文档存储，Cassandra 作为列式数据库。

每个存储后端根据要处理的数据的性质提供特定的用途。MySQL RDBMs 用于可以使用 SQL 轻松查询的标准表格处理信息。由于我们将从各种 API 处理大量 JSON 类型数据，因此将它们存储在文档中是最简单的方式。对于实时和时间序列相关信息，Cassandra 最适合作为列式数据库。

以下图表显示了我们将在整本书中构建和使用的环境：

![设置 Spark 动力环境](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_08.jpg)

## 在 Ubuntu 上设置 Oracle VirtualBox

在 Ubuntu 14.04 上设置一个干净的新 VirtualBox 环境是创建一个开发环境的最安全方式，它不会与现有的库发生冲突，并且可以在云中使用类似的命令列表进行复制。

为了建立一个带有 Anaconda 和 Spark 的环境，我们将创建一个运行 Ubuntu 14.04 的 VirtualBox 虚拟机。

让我们来看看在 Ubuntu 上使用 VirtualBox 的步骤：

1.  Oracle VirtualBox VM 是免费的，可以从[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)下载。安装非常简单。

1.  安装 VirtualBox 后，让我们打开 Oracle VM VirtualBox Manager 并单击**新建**按钮。

1.  我们将为新的虚拟机命名，并选择类型**Linux**和版本**Ubuntu（64 位）**。

1.  您需要从 Ubuntu 网站下载 ISO 并分配足够的 RAM（建议 4GB）和磁盘空间（建议 20GB）。我们将使用 Ubuntu 14.04.1 LTS 版本，可以在这里找到：[`www.ubuntu.com/download/desktop`](http://www.ubuntu.com/download/desktop)。

1.  安装完成后，建议通过转到（从新的虚拟机运行的 VirtualBox 菜单）**设备** | **插入增强功能光盘映像**来安装 VirtualBox 增强功能。在 Windows 主机中未提供增强功能会导致用户界面非常有限，窗口大小减小。

1.  安装完成后，重新启动虚拟机，它将准备好使用。通过选择虚拟机并单击**设置**，然后转到**常规** | **高级** | **共享剪贴板**并单击**双向**，可以启用共享剪贴板。

## 安装带有 Python 2.7 的 Anaconda

PySpark 目前仅在 Python 2.7 上运行。（社区要求升级到 Python 3.3。）要安装 Anaconda，请按照以下步骤进行：

1.  从[`continuum.io/downloads#all`](http://continuum.io/downloads#all)下载 Linux 64 位 Python 2.7 的 Anaconda 安装程序。

1.  下载 Anaconda 安装程序后，打开终端并导航到安装程序保存的目录或文件夹。然后运行以下命令，将命令中的`2.x.x`替换为下载安装程序文件的版本号：

```py
# install anaconda 2.x.x
bash Anaconda-2.x.x-Linux-x86[_64].sh

```

1.  接受许可条款后，您将被要求指定安装位置（默认为~/anaconda）。

1.  自解压完成后，您应该将 anaconda 二进制目录添加到您的 PATH 环境变量中：

```py
# add anaconda to PATH
bash Anaconda-2.x.x-Linux-x86[_64].sh

```

## 安装 Java 8

Spark 在 JVM 上运行，并且需要 Java **SDK**（软件开发工具包）而不是**JRE**（Java 运行环境），因为我们将使用 Spark 构建应用程序。推荐的版本是 Java 版本 7 或更高版本。Java 8 是最合适的，因为它包括许多 Scala 和 Python 可用的函数式编程技术。

要安装 Java 8，请按照以下步骤进行：

1.  使用以下命令安装 Oracle Java 8：

```py
# install oracle java 8
$ sudo apt-get install software-properties-common
$ sudo add-apt-repository ppa:webupd8team/java
$ sudo apt-get update
$ sudo apt-get install oracle-java8-installer

```

1.  设置`JAVA_HOME`环境变量，并确保 Java 程序在您的 PATH 上。

1.  检查`JAVA_HOME`是否正确安装：

```py
# 
$ echo JAVA_HOME

```

## 安装 Spark

转到 Spark 下载页面[`spark.apache.org/downloads.html`](http://spark.apache.org/downloads.html)。

Spark 下载页面提供了下载早期版本的 Spark 和不同的软件包和下载类型的可能性。我们将选择最新版本，为 Hadoop 2.6 及更高版本预构建。安装 Spark 的最简单方法是使用为 Hadoop 2.6 及更高版本预构建的 Spark 软件包，而不是从源代码构建。将文件移动到根目录下的`~/spark`目录中。

下载最新版本的 Spark—2015 年 11 月 9 日发布的 Spark 1.5.2：

1.  选择 Spark 版本**1.5.2（2015 年 11 月 9 日发布）**，

1.  选择软件包类型**为 Hadoop 2.6 及更高版本预构建**，

1.  选择下载类型**直接下载**，

1.  下载 Spark：**spark-1.5.2-bin-hadoop2.6.tgz**，

1.  使用 1.3.0 签名和校验和验证此版本，

这也可以通过运行以下命令来完成：

```py
# download spark
$ wget http://d3kbcqa49mib13.cloudfront.net/spark-1.5.2-bin-hadoop2.6.tgz

```

接下来，我们将提取文件并清理：

```py
# extract, clean up, move the unzipped files under the spark directory
$ tar -xf spark-1.5.2-bin-hadoop2.6.tgz
$ rm spark-1.5.2-bin-hadoop2.6.tgz
$ sudo mv spark-* spark

```

现在，我们可以运行 Spark Python 解释器：

```py
# run spark
$ cd ~/spark
./bin/pyspark

```

您应该看到类似于这样的东西：

```py
Welcome to
 ____              __
 / __/__  ___ _____/ /__
 _\ \/ _ \/ _ `/ __/  '_/
 /__ / .__/\_,_/_/ /_/\_\   version 1.5.2
 /_/
Using Python version 2.7.6 (default, Mar 22 2014 22:59:56)
SparkContext available as sc.
>>> 

```

解释器将已经为我们提供了一个 Spark 上下文对象`sc`，我们可以通过运行来查看：

```py
>>> print(sc)
<pyspark.context.SparkContext object at 0x7f34b61c4e50>

```

## 启用 IPython 笔记本

我们将使用 IPython Notebook 以获得比控制台更友好的用户体验。

您可以使用以下命令启动 IPython Notebook：

```py
$ IPYTHON_OPTS="notebook --pylab inline"  ./bin/pyspark

```

在存储 Jupyter 或 IPython 笔记本的`examples/AN_Spark`目录中使用`IPYNB`启动 PySpark：

```py
# cd to  /home/an/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark
# launch command using python 2.7 and the spark-csv package:
$ IPYTHON_OPTS='notebook' /home/an/spark/spark-1.5.0-bin-hadoop2.6/bin/pyspark --packages com.databricks:spark-csv_2.11:1.2.0

# launch command using python 3.4 and the spark-csv package:
$ IPYTHON_OPTS='notebook' PYSPARK_PYTHON=python3
 /home/an/spark/spark-1.5.0-bin-hadoop2.6/bin/pyspark --packages com.databricks:spark-csv_2.11:1.2.0

```

# 使用 PySpark 构建我们的第一个应用程序

我们现在准备检查一切是否正常工作。在处理本书第一章的单词计数时，将对其进行测试。

我们将要运行的代码在这里列出：

```py
# Word count on 1st Chapter of the Book using PySpark

# import regex module
import re
# import add from operator module
from operator import add

# read input file
file_in = sc.textFile('/home/an/Documents/A00_Documents/Spark4Py 20150315')

# count lines
print('number of lines in file: %s' % file_in.count())

# add up lengths of each line
chars = file_in.map(lambda s: len(s)).reduce(add)
print('number of characters in file: %s' % chars)

# Get words from the input file
words =file_in.flatMap(lambda line: re.split('\W+', line.lower().strip()))
# words of more than 3 characters
words = words.filter(lambda x: len(x) > 3)
# set count 1 per word
words = words.map(lambda w: (w,1))
# reduce phase - sum count all the words
words = words.reduceByKey(add)
```

在此程序中，我们首先从目录`/home/an/Documents/A00_Documents/Spark4Py 20150315`中读取文件到`file_in`中。

然后通过计算每行的行数和每行的字符数来审查文件。

我们将输入文件拆分为单词并将它们转换为小写。为了避免较短和更频繁的单词（如*the*、*and*、*for*）对计数产生偏向，我们选择长度超过三个字符的单词进行单词计数。通常，它们被认为是停用词，并且应该在任何语言处理任务中被过滤掉。

在这个阶段，我们准备进行 MapReduce 步骤。对于每个单词，我们将映射一个值`1`并通过对所有唯一单词求和来减少它。

以下是 IPython Notebook 中代码的示例。前 10 个单元格是对数据集上的单词计数进行预处理，该数据集是从本地文件目录中检索的。

![使用 PySpark 构建我们的第一个应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_09.jpg)

交换元组中的单词计数格式`(count, word)`，以便按`count`排序，这现在是元组的主键：

```py
# create tuple (count, word) and sort in descending
words = words.map(lambda x: (x[1], x[0])).sortByKey(False)

# take top 20 words by frequency
words.take(20)
```

为了显示我们的结果，我们创建元组`(count, word)`并按降序显示前 20 个最常用的单词：

![使用 PySpark 构建我们的第一个应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_10.jpg)

让我们创建一个直方图函数：

```py
# create function for histogram of most frequent words

% matplotlib inline
import matplotlib.pyplot as plt
#

def histogram(words):
    count = map(lambda x: x[1], words)
    word = map(lambda x: x[0], words)
    plt.barh(range(len(count)), count,color = 'grey')
    plt.yticks(range(len(count)), word)

# Change order of tuple (word, count) from (count, word) 
words = words.map(lambda x:(x[1], x[0]))
words.take(25)

# display histogram
histogram(words.take(25))
```

在这里，我们通过在条形图中绘制它们来可视化最常用的单词。我们首先将元组从原始的`(count, word)`交换为`(word, count)`：

![使用 PySpark 构建我们的第一个应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_11.jpg)

因此，您现在拥有的是：第一章中最常用的单词是**Spark**，其次是**Data**和**Anaconda**。

# 使用 Vagrant 虚拟化环境

为了创建一个可以轻松共享和克隆的便携式 Python 和 Spark 环境，可以使用`vagrantfile`构建开发环境。

我们将指向由*伯克利大学和 Databricks*提供的**大规模在线开放课程**（**MOOCs**）：

+   *Anthony D. Joseph 教授的 Apache Spark 大数据介绍*可在[`www.edx.org/course/introduction-big-data-apache-spark-uc-berkeleyx-cs100-1x`](https://www.edx.org/course/introduction-big-data-apache-spark-uc-berkeleyx-cs100-1x)找到

+   *可扩展机器学习，教授* *Ameet Talwalkar* 可以在[`www.edx.org/course/scalable-machine-learning-uc-berkeleyx-cs190-1x`](https://www.edx.org/course/scalable-machine-learning-uc-berkeleyx-cs190-1x)找到

课程实验室是在由 PySpark 提供动力的 IPython 笔记本上执行的。它们可以在以下 GitHub 存储库中找到：[`github.com/spark-mooc/mooc-setup/`](https://github.com/spark-mooc/mooc-setup/)。

一旦在您的机器上设置了 Vagrant，请按照以下说明开始：[`docs.vagrantup.com/v2/getting-started/index.html`](https://docs.vagrantup.com/v2/getting-started/index.html)。

在您的工作目录中克隆`spark-mooc/mooc-setup/ github`存储库，并在克隆的目录中启动命令`$ vagrant up`：

请注意，由于`vagrantfile`可能不是最新的，Spark 的版本可能已过时。

您将看到类似于这样的输出：

```py
C:\Programs\spark\edx1001\mooc-setup-master>vagrant up
Bringing machine 'sparkvm' up with 'virtualbox' provider...
==> sparkvm: Checking if box 'sparkmooc/base' is up to date...
==> sparkvm: Clearing any previously set forwarded ports...
==> sparkvm: Clearing any previously set network interfaces...
==> sparkvm: Preparing network interfaces based on configuration...
 sparkvm: Adapter 1: nat
==> sparkvm: Forwarding ports...
 sparkvm: 8001 => 8001 (adapter 1)
 sparkvm: 4040 => 4040 (adapter 1)
 sparkvm: 22 => 2222 (adapter 1)
==> sparkvm: Booting VM...
==> sparkvm: Waiting for machine to boot. This may take a few minutes...
 sparkvm: SSH address: 127.0.0.1:2222
 sparkvm: SSH username: vagrant
 sparkvm: SSH auth method: private key
 sparkvm: Warning: Connection timeout. Retrying...
 sparkvm: Warning: Remote connection disconnect. Retrying...
==> sparkvm: Machine booted and ready!
==> sparkvm: Checking for guest additions in VM...
==> sparkvm: Setting hostname...
==> sparkvm: Mounting shared folders...
 sparkvm: /vagrant => C:/Programs/spark/edx1001/mooc-setup-master
==> sparkvm: Machine already provisioned. Run `vagrant provision` or use the `--provision`
==> sparkvm: to force provisioning. Provisioners marked to run always will still run.

C:\Programs\spark\edx1001\mooc-setup-master>

```

这将在`localhost:8001`上启动由 PySpark 提供动力的 IPython 笔记本：

![使用 Vagrant 虚拟化环境](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_12.jpg)

# 转移到云端

由于我们正在处理分布式系统，运行在单个笔记本电脑上的虚拟机上的环境对于探索和学习是有限的。我们可以转移到云端，以体验 Spark 分布式框架的强大和可扩展性。

## 在 Amazon Web Services 中部署应用程序

一旦我们准备好扩展我们的应用程序，我们可以将开发环境迁移到**Amazon** **Web Services** (**AWS**)。

如何在 EC2 上运行 Spark 在以下页面中清楚地描述：[`spark.apache.org/docs/latest/ec2-scripts.html`](https://spark.apache.org/docs/latest/ec2-scripts.html)。

我们强调在设置 AWS Spark 环境时的五个关键步骤：

1.  通过 AWS 控制台创建 AWS EC2 密钥对[`aws.amazon.com/console/`](http://aws.amazon.com/console/)。

1.  将您的密钥对导出到您的环境中：

```py
export AWS_ACCESS_KEY_ID=accesskeyid
export AWS_SECRET_ACCESS_KEY=secretaccesskey

```

1.  启动您的集群：

```py
~$ cd $SPARK_HOME/ec2
ec2$ ./spark-ec2 -k <keypair> -i <key-file> -s <num-slaves> launch <cluster-name>

```

1.  SSH 进入集群运行 Spark 作业：

```py
ec2$ ./spark-ec2 -k <keypair> -i <key-file> login <cluster-name>

```

1.  在使用后销毁您的集群：

```py
ec2$ ./spark-ec2 destroy <cluster-name>

```

## 使用 Docker 虚拟化环境

为了创建一个可以轻松共享和克隆的便携式 Python 和 Spark 环境，开发环境可以在 Docker 容器中构建。

我们希望利用 Docker 的两个主要功能：

+   创建可以轻松部署在不同操作系统或云中的隔离容器。

+   使用 DockerHub 允许轻松共享开发环境镜像及其所有依赖项。DockerHub 类似于 GitHub。它允许轻松克隆和版本控制。配置环境的快照图像可以作为进一步增强的基线。

以下图表说明了一个具有 Spark、Anaconda 和数据库服务器及其各自数据卷的 Docker 启用环境。

![使用 Docker 虚拟化环境](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_01_13.jpg)

Docker 提供了从 Dockerfile 克隆和部署环境的能力。

您可以在以下地址找到一个带有 PySpark 和 Anaconda 设置的示例 Dockerfile：[`hub.docker.com/r/thisgokeboysef/pyspark-docker/~/dockerfile/`](https://hub.docker.com/r/thisgokeboysef/pyspark-docker/~/dockerfile/)。

按照以下链接提供的说明安装 Docker：

+   [`docs.docker.com/mac/started/`](http://docs.docker.com/mac/started/) 如果您使用的是 Mac OS X

+   [`docs.docker.com/linux/started/`](http://docs.docker.com/linux/started/) 如果你在 Linux 上

+   [`docs.docker.com/windows/started/`](http://docs.docker.com/windows/started/) 如果您使用的是 Windows

使用以下命令安装提供的 Dockerfile 的 docker 容器：

```py
$ docker pull thisgokeboysef/pyspark-docker

```

关于如何*dockerize*您的环境的其他重要信息源可以在 Lab41 中找到。GitHub 存储库包含必要的代码：

[`github.com/Lab41/ipython-spark-docker`](https://github.com/Lab41/ipython-spark-docker)

支持的博客文章中包含了构建 docker 环境所涉及的思维过程丰富的信息：[`lab41.github.io/blog/2015/04/13/ipython-on-spark-on-docker/`](http://lab41.github.io/blog/2015/04/13/ipython-on-spark-on-docker/)。

# 摘要

我们通过描述围绕基础设施、持久性、集成、分析和参与层的整体架构来设定构建数据密集型应用的背景。我们还讨论了 Spark 和 Anaconda 以及它们各自的构建模块。我们在 VirtualBox 中使用 Anaconda 和 Spark 设置了一个环境，并演示了使用第一章的文本内容作为输入的词频统计应用程序。

在下一章中，我们将更深入地探讨数据密集型应用的架构蓝图，并利用 Twitter、GitHub 和 Meetup 的 API 来感受我们将使用 Spark 进行挖掘的数据。


# 第二章：使用 Spark 构建批处理和流处理应用

本书的目标是通过构建一个应用程序来分析社交网络上 Spark 社区的互动，教会你关于 PySpark 和 PyData 库。我们将从 GitHub 收集有关 Apache Spark 的信息，在 Twitter 上检查相关的推文，并通过 Meetup 感受 Spark 在更广泛的开源软件社区中的热度。

在本章中，我们将概述各种数据和信息来源。我们将了解它们的结构。我们将概述从收集到批处理和流处理的数据处理流程。

在这一部分，我们将涵盖以下要点：

+   从收集到批处理和流处理的数据处理流程，有效地描述我们计划构建的应用程序的架构。

+   查看各种数据来源（GitHub、Twitter 和 Meetup）、它们的数据结构（JSON、结构化信息、非结构化文本、地理位置、时间序列数据等）以及它们的复杂性。我们还讨论了连接三种不同 API 的工具，这样你就可以构建自己的数据混搭。本书将在接下来的章节中重点关注 Twitter。

# 架构数据密集型应用

我们在上一章中定义了数据密集型应用框架架构蓝图。让我们重新将我们原始框架中将在整本书中使用的各种软件组件放回到上下文中。以下是数据密集型架构框架中映射的各种软件组件的示意图：

![架构数据密集型应用](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_02_01.jpg)

Spark 是一个非常高效的分布式计算框架。为了充分利用其功能，我们需要相应地设计我们的解决方案。出于性能原因，整体解决方案还需要考虑其在 CPU、存储和网络方面的使用情况。

这些要求驱动我们解决方案的架构：

+   **延迟**：这种架构结合了慢速和快速处理。慢速处理是在批处理模式下对历史数据进行处理。这也被称为静态数据。这个阶段构建了将由快速处理部分在实时连续数据输入系统后使用的预先计算的模型和数据模式。数据的快速处理或实时分析是指处理运动中的数据。静态数据实际上是以批处理模式处理数据，具有较长的延迟。运动中的数据是指实时摄取的数据的流式计算。

+   **可扩展性**：Spark 通过其分布式内存计算框架本身具有线性可扩展性。与 Spark 交互的数据库和数据存储也需要能够随着数据量的增长而线性扩展。

+   **容错性**：当由于硬件、软件或网络原因发生故障时，架构应具有足够的弹性，并始终提供可用性。

+   **灵活性**：在这种架构中建立的数据流程可以根据用例迅速进行调整和改装。

Spark 独特之处在于它允许在同一统一平台上进行批处理和流式分析。

我们将考虑两种数据处理流程：

+   第一个处理静态数据，并专注于构建批量分析数据的流程。

+   第二个流程是处理运动中的数据，目标是实时数据摄取和基于预先计算的模型和数据模式提供洞察力

## 处理静态数据

让我们了解一下静态数据或批处理流程。这个流程的目标是从 Twitter、GitHub 和 Meetup 中摄取各种数据集；为 Spark MLlib 准备数据，这是机器学习引擎；并推导出将在批处理模式或实时模式下应用的基本模型。

以下图表说明了数据流程，以便处理静态数据：

![处理静态数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_02_02.jpg)

## 处理运动中的数据

处理运动数据引入了新的复杂性，因为我们引入了新的失败可能性。如果我们想要扩展，我们需要考虑引入分布式消息队列系统，如 Kafka。我们将专门讨论理解流式分析的后续章节。

以下图表描述了用于处理运动数据的数据管道：

![处理运动数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_02_03.jpg)

## 交互式地探索数据

构建数据密集型应用程序并不像将数据库暴露给 Web 界面那样简单。在静态数据和运动数据处理的设置过程中，我们将利用 Spark 分析数据的能力，以交互方式分析和细化所需的机器学习和流处理活动所需的数据丰富性和质量。在这里，我们将进行数据收集、细化和调查的迭代循环，以获取我们应用程序感兴趣的数据集。

# 连接到社交网络

让我们深入探讨数据密集型应用程序架构集成层的第一步。我们将专注于收集数据，确保其完整性，并为 Spark 在下一阶段的批处理和流处理数据做准备。这个阶段描述了五个处理步骤：*连接*，*校正*，*收集*，*组合*和*消费*。这些是数据探索的迭代步骤，将使我们熟悉数据，并帮助我们为进一步处理调整数据结构。

以下图表描述了用于消费的数据采集和细化的迭代过程：

![连接到社交网络](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_02_04.jpg)

我们连接到感兴趣的社交网络：Twitter、GitHub 和 Meetup。我们将讨论如何访问**APIs**（应用程序编程接口）的方式，以及如何与这些服务创建 RESTful 连接，同时尊重社交网络施加的速率限制。**REST**（表示状态转移）是互联网上最广泛采用的架构风格，以实现可扩展的 Web 服务。它依赖于主要以**JSON**（JavaScript 对象表示）交换消息。RESTful APIs 和 Web 服务实现了四种最常见的动词`GET`，`PUT`，`POST`和`DELETE`。`GET`用于从给定的`URI`检索元素或集合。`PUT`使用新的集合更新一个集合。`POST`允许创建新条目，而`DELETE`则删除一个集合。

## 获取 Twitter 数据

Twitter 允许注册用户访问其搜索和流式推文服务，使用名为 OAuth 的授权协议，允许 API 应用程序安全地代表用户进行操作。为了创建连接，第一步是在 Twitter 上创建一个应用程序，网址为[`apps.twitter.com/app/new`](https://apps.twitter.com/app/new)。

![获取 Twitter 数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_02_05.jpg)

应用程序创建后，Twitter 将发出四个代码，允许其接入 Twitter 的数据流：

```py
CONSUMER_KEY = 'GetYourKey@Twitter'
CONSUMER_SECRET = ' GetYourKey@Twitter'
OAUTH_TOKEN = ' GetYourToken@Twitter'
OAUTH_TOKEN_SECRET = ' GetYourToken@Twitter'
```

如果您想了解提供的各种 RESTful 查询，可以在开发控制台上探索 Twitter API，网址为[`dev.twitter.com/rest/tools/console`](https://dev.twitter.com/rest/tools/console)：

![获取 Twitter 数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_02_06.jpg)

我们将使用以下代码在 Twitter 上进行程序化连接，这将激活我们的 OAuth 访问，并允许我们在速率限制下接入 Twitter API。在流模式下，限制是针对 GET 请求的。

## 获取 GitHub 数据

GitHub 使用类似的身份验证流程来 Twitter。前往开发者网站，在[`developer.github.com/v3/`](https://developer.github.com/v3/)上注册 GitHub 后，检索您的凭据：

![获取 GitHub 数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_02_07.jpg)

## 获取 Meetup 数据

可以使用在 Meetup.com 成员的开发资源中发行的令牌来访问 Meetup。可以在他们的开发者网站上获取 Meetup API 访问所需的令牌或 OAuth 凭据：[`secure.meetup.com/meetup_api`](https://secure.meetup.com/meetup_api)。

![获取 Meetup 数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_02_08.jpg)

# 分析数据

让我们首先感受一下从每个社交网络中提取的数据，并了解来自这些来源的数据结构。

## 发现推文的结构

在本节中，我们将建立与 Twitter API 的连接。Twitter 提供两种连接模式：REST API，允许我们搜索给定搜索词或标签的历史推文，以及流 API，它在限制速率下提供实时推文。

为了更好地了解如何操作 Twitter API，我们将按照以下步骤进行：

1.  安装 Twitter Python 库。

1.  通过 OAuth 以编程方式建立连接，这是 Twitter 所需的身份验证。

1.  搜索查询*Apache Spark*的最新推文并探索所获得的结果。

1.  决定感兴趣的关键属性，并从 JSON 输出中检索信息。

让我们一步一步地进行这个过程：

1.  安装 Python Twitter 库。为了安装它，您需要从命令行中编写`pip install twitter`：

```py
$ pip install twitter

```

1.  创建 Python Twitter API 类及其用于身份验证、搜索和解析结果的基本方法。`self.auth`从 Twitter 获取凭据。然后创建一个注册的 API 作为`self.api`。我们实现了两种方法：第一种是使用给定的查询搜索 Twitter，第二种是解析输出以检索相关信息，如推文 ID、推文文本和推文作者。代码如下：

```py
import twitter
import urlparse
from pprint import pprint as pp

class TwitterAPI(object):
    """
    TwitterAPI class allows the Connection to Twitter via OAuth
    once you have registered with Twitter and receive the 
    necessary credentiials 
    """

# initialize and get the twitter credentials
     def __init__(self): 
        consumer_key = 'Provide your credentials'
        consumer_secret = 'Provide your credentials'
        access_token = 'Provide your credentials'
        access_secret = 'Provide your credentials'

        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.access_token = access_token
        self.access_secret = access_secret

#
# authenticate credentials with Twitter using OAuth
        self.auth = twitter.oauth.OAuth(access_token, access_secret, consumer_key, consumer_secret)
    # creates registered Twitter API
        self.api = twitter.Twitter(auth=self.auth)
#
# search Twitter with query q (i.e. "ApacheSpark") and max. result
    def searchTwitter(self, q, max_res=10,**kwargs):
        search_results = self.api.search.tweets(q=q, count=10, **kwargs)
        statuses = search_results['statuses']
        max_results = min(1000, max_res)

        for _ in range(10): 
            try:
                next_results = search_results['search_metadata']['next_results']
            except KeyError as e: 
                break

            next_results = urlparse.parse_qsl(next_results[1:])
            kwargs = dict(next_results)
            search_results = self.api.search.tweets(**kwargs)
            statuses += search_results['statuses']

            if len(statuses) > max_results: 
                break
        return statuses
#
# parse tweets as it is collected to extract id, creation 
# date, user id, tweet text
    def parseTweets(self, statuses):
        return [ (status['id'], 
                  status['created_at'], 
                  status['user']['id'],
                  status['user']['name'], 
                  status['text'], url['expanded_url']) 
                        for status in statuses 
                            for url in status['entities']['urls'] ]
```

1.  用所需的身份验证实例化类：

```py
t= TwitterAPI()
```

1.  在查询词*Apache Spark*上运行搜索：

```py
q="ApacheSpark"
tsearch = t.searchTwitter(q)
```

1.  分析 JSON 输出：

```py
pp(tsearch[1])

{u'contributors': None,
 u'coordinates': None,
 u'created_at': u'Sat Apr 25 14:50:57 +0000 2015',
 u'entities': {u'hashtags': [{u'indices': [74, 86], u'text': u'sparksummit'}],
               u'media': [{u'display_url': u'pic.twitter.com/WKUMRXxIWZ',
                           u'expanded_url': u'http://twitter.com/bigdata/status/591976255831969792/photo/1',
                           u'id': 591976255156715520,
                           u'id_str': u'591976255156715520',
                           u'indices': [143, 144],
                           u'media_url': 
...(snip)... 
 u'text': u'RT @bigdata: Enjoyed catching up with @ApacheSpark users &amp; leaders at #sparksummit NYC: video clips are out http://t.co/qrqpP6cG9s http://t\u2026',
 u'truncated': False,
 u'user': {u'contributors_enabled': False,
           u'created_at': u'Sat Apr 04 14:44:31 +0000 2015',
           u'default_profile': True,
           u'default_profile_image': True,
           u'description': u'',
           u'entities': {u'description': {u'urls': []}},
           u'favourites_count': 0,
           u'follow_request_sent': False,
           u'followers_count': 586,
           u'following': False,
           u'friends_count': 2,
           u'geo_enabled': False,
           u'id': 3139047660,
           u'id_str': u'3139047660',
           u'is_translation_enabled': False,
           u'is_translator': False,
           u'lang': u'zh-cn',
           u'listed_count': 749,
           u'location': u'',
           u'name': u'Mega Data Mama',
           u'notifications': False,
           u'profile_background_color': u'C0DEED',
           u'profile_background_image_url': u'http://abs.twimg.com/images/themes/theme1/bg.png',
           u'profile_background_image_url_https': u'https://abs.twimg.com/images/themes/theme1/bg.png',
           ...(snip)... 
           u'screen_name': u'MegaDataMama',
           u'statuses_count': 26673,
           u'time_zone': None,
           u'url': None,
           u'utc_offset': None,
           u'verified': False}}
```

1.  解析 Twitter 输出以检索感兴趣的关键信息：

```py
tparsed = t.parseTweets(tsearch)
pp(tparsed)

[(591980327784046592,
  u'Sat Apr 25 15:01:23 +0000 2015',
  63407360,
  u'Jos\xe9 Carlos Baquero',
  u'Big Data systems are making a difference in the fight against cancer. #BigData #ApacheSpark http://t.co/pnOLmsKdL9',
  u'http://tmblr.co/ZqTggs1jHytN0'),
 (591977704464875520,
  u'Sat Apr 25 14:50:57 +0000 2015',
  3139047660,
  u'Mega Data Mama',
  u'RT @bigdata: Enjoyed catching up with @ApacheSpark users &amp; leaders at #sparksummit NYC: video clips are out http://t.co/qrqpP6cG9s http://t\u2026',
  u'http://goo.gl/eF5xwK'),
 (591977172589539328,
  u'Sat Apr 25 14:48:51 +0000 2015',
  2997608763,
  u'Emma Clark',
  u'RT @bigdata: Enjoyed catching up with @ApacheSpark users &amp; leaders at #sparksummit NYC: video clips are out http://t.co/qrqpP6cG9s http://t\u2026',
  u'http://goo.gl/eF5xwK'),
 ... (snip)...  
 (591879098349268992,
  u'Sat Apr 25 08:19:08 +0000 2015',
  331263208,
  u'Mario Molina',
  u'#ApacheSpark speeds up big data decision-making http://t.co/8hdEXreNfN',
  u'http://www.computerweekly.com/feature/Apache-Spark-speeds-up-big-data-decision-making')]
```

# 探索 GitHub 世界

为了更好地了解如何操作 GitHub API，我们将按照以下步骤进行：

1.  安装 GitHub Python 库。

1.  通过使用在开发者网站上注册时提供的令牌来访问 API。

1.  检索有关托管 spark 存储库的 Apache 基金会的一些关键事实。

让我们一步一步地进行这个过程：

1.  安装 Python PyGithub 库。为了安装它，您需要从命令行中`pip install PyGithub`：

```py
pip install PyGithub
```

1.  通过编程方式创建客户端来实例化 GitHub API：

```py
from github import Github

# Get your own access token

ACCESS_TOKEN = 'Get_Your_Own_Access_Token'

# We are focusing our attention to User = apache and Repo = spark

USER = 'apache'
REPO = 'spark'

g = Github(ACCESS_TOKEN, per_page=100)
user = g.get_user(USER)
repo = user.get_repo(REPO)
```

1.  从 Apache 用户检索关键事实。GitHub 中有 640 个活跃的 Apache 存储库：

```py
repos_apache = [repo.name for repo in g.get_user('apache').get_repos()]
len(repos_apache)
640
```

1.  从 Spark 存储库检索关键事实，Spark 存储库中使用的编程语言在此处给出：

```py
pp(repo.get_languages())

{u'C': 1493,
 u'CSS': 4472,
 u'Groff': 5379,
 u'Java': 1054894,
 u'JavaScript': 21569,
 u'Makefile': 7771,
 u'Python': 1091048,
 u'R': 339201,
 u'Scala': 10249122,
 u'Shell': 172244}
```

1.  检索广泛的 Spark GitHub 存储库网络中的一些关键参与者。在撰写本文时，Apache Spark 存储库中有 3,738 名关注者。这个网络是巨大的。第一个关注者是*Matei Zaharia*，他在伯克利读博士期间是 Spark 项目的联合创始人。

```py
stargazers = [ s for s in repo.get_stargazers() ]
print "Number of stargazers", len(stargazers)
Number of stargazers 3738

[stargazers[i].login for i in range (0,20)]
[u'mateiz',
 u'beyang',
 u'abo',
 u'CodingCat',
 u'andy327',
 u'CrazyJvm',
 u'jyotiska',
 u'BaiGang',
 u'sundstei',
 u'dianacarroll',
 u'ybotco',
 u'xelax',
 u'prabeesh',
 u'invkrh',
 u'bedla',
 u'nadesai',
 u'pcpratts',
 u'narkisr',
 u'Honghe',
 u'Jacke']
```

## 通过 Meetup 了解社区

为了更好地了解如何操作 Meetup API，我们将按照以下步骤进行：

1.  创建一个 Python 程序，使用身份验证令牌调用 Meetup API。

1.  检索 Meetup 小组的过去事件信息，例如*London Data Science*。

1.  检索 Meetup 成员的个人资料，以分析他们参与类似 Meetup 小组的情况。

让我们一步一步地进行这个过程：

1.  由于没有可靠的 Meetup API Python 库，我们将通过编程方式创建一个客户端来实例化 Meetup API：

```py
import json
import mimeparse
import requests
import urllib
from pprint import pprint as pp

MEETUP_API_HOST = 'https://api.meetup.com'
EVENTS_URL = MEETUP_API_HOST + '/2/events.json'
MEMBERS_URL = MEETUP_API_HOST + '/2/members.json'
GROUPS_URL = MEETUP_API_HOST + '/2/groups.json'
RSVPS_URL = MEETUP_API_HOST + '/2/rsvps.json'
PHOTOS_URL = MEETUP_API_HOST + '/2/photos.json'
GROUP_URLNAME = 'London-Machine-Learning-Meetup'
# GROUP_URLNAME = 'London-Machine-Learning-Meetup' # 'Data-Science-London'

class Mee
tupAPI(object):
    """
    Retrieves information about meetup.com
    """
    def __init__(self, api_key, num_past_events=10, http_timeout=1,
                 http_retries=2):
        """
        Create a new instance of MeetupAPI
        """
        self._api_key = api_key
        self._http_timeout = http_timeout
        self._http_retries = http_retries
        self._num_past_events = num_past_events

    def get_past_events(self):
        """
        Get past meetup events for a given meetup group
        """
        params = {'key': self._api_key,
                  'group_urlname': GROUP_URLNAME,
                  'status': 'past',
                  'desc': 'true'}
        if self._num_past_events:
            params['page'] = str(self._num_past_events)

        query = urllib.urlencode(params)
        url = '{0}?{1}'.format(EVENTS_URL, query)
        response = requests.get(url, timeout=self._http_timeout)
        data = response.json()['results']
        return data

    def get_members(self):
        """
        Get meetup members for a given meetup group
        """
        params = {'key': self._api_key,
                  'group_urlname': GROUP_URLNAME,
                  'offset': '0',
                  'format': 'json',
                  'page': '100',
                  'order': 'name'}
        query = urllib.urlencode(params)
        url = '{0}?{1}'.format(MEMBERS_URL, query)
        response = requests.get(url, timeout=self._http_timeout)
        data = response.json()['results']
        return data

    def get_groups_by_member(self, member_id='38680722'):
        """
        Get meetup groups for a given meetup member
        """
        params = {'key': self._api_key,
                  'member_id': member_id,
                  'offset': '0',
                  'format': 'json',
                  'page': '100',
                  'order': 'id'}
        query = urllib.urlencode(params)
        url = '{0}?{1}'.format(GROUPS_URL, query)
        response = requests.get(url, timeout=self._http_timeout)
        data = response.json()['results']
        return data
```

1.  然后，我们将从给定的 Meetup 小组中检索过去的事件：

```py
m = MeetupAPI(api_key='Get_Your_Own_Key')
last_meetups = m.get_past_events()
pp(last_meetups[5])

{u'created': 1401809093000,
 u'description': u"<p>We are hosting a joint meetup between Spark London and Machine Learning London. Given the excitement in the machine learning community around Spark at the moment a joint meetup is in order!</p> <p>Michael Armbrust from the Apache Spark core team will be flying over from the States to give us a talk in person.\xa0Thanks to our sponsors, Cloudera, MapR and Databricks for helping make this happen.</p> <p>The first part of the talk will be about MLlib, the machine learning library for Spark,\xa0and the second part, on\xa0Spark SQL.</p> <p>Don't sign up if you have already signed up on the Spark London page though!</p> <p>\n\n\nAbstract for part one:</p> <p>In this talk, we\u2019ll introduce Spark and show how to use it to build fast, end-to-end machine learning workflows. Using Spark\u2019s high-level API, we can process raw data with familiar libraries in Java, Scala or Python (e.g. NumPy) to extract the features for machine learning. Then, using MLlib, its built-in machine learning library, we can run scalable versions of popular algorithms. We\u2019ll also cover upcoming development work including new built-in algorithms and R bindings.</p> <p>\n\n\n\nAbstract for part two:\xa0</p> <p>In this talk, we'll examine Spark SQL, a new Alpha component that is part of the Apache Spark 1.0 release. Spark SQL lets developers natively query data stored in both existing RDDs and external sources such as Apache Hive. A key feature of Spark SQL is the ability to blur the lines between relational tables and RDDs, making it easy for developers to intermix SQL commands that query external data with complex analytics. In addition to Spark SQL, we'll explore the Catalyst optimizer framework, which allows Spark SQL to automatically rewrite query plans to execute more efficiently.</p>",
 u'event_url': u'http://www.meetup.com/London-Machine-Learning-Meetup/events/186883262/',
 u'group': {u'created': 1322826414000,
            u'group_lat': 51.52000045776367,
            u'group_lon': -0.18000000715255737,
            u'id': 2894492,
            u'join_mode': u'open',
            u'name': u'London Machine Learning Meetup',
            u'urlname': u'London-Machine-Learning-Meetup',
            u'who': u'Machine Learning Enthusiasts'},
 u'headcount': 0,
 u'id': u'186883262',
 u'maybe_rsvp_count': 0,
 u'name': u'Joint Spark London and Machine Learning Meetup',
 u'rating': {u'average': 4.800000190734863, u'count': 5},
 u'rsvp_limit': 70,
 u'status': u'past',
 u'time': 1403200800000,
 u'updated': 1403450844000,
 u'utc_offset': 3600000,
 u'venue': {u'address_1': u'12 Errol St, London',
            u'city': u'EC1Y 8LX',
            u'country': u'gb',
            u'id': 19504802,
            u'lat': 51.522533,
            u'lon': -0.090934,
            u'name': u'Royal Statistical Society',
            u'repinned': False},
 u'visibility': u'public',
 u'waitlist_count': 84,
 u'yes_rsvp_count': 70}
```

1.  获取有关 Meetup 成员的信息：

```py
members = m.get_members()

{u'city': u'London',
  u'country': u'gb',
  u'hometown': u'London',
  u'id': 11337881,
  u'joined': 1421418896000,
  u'lat': 51.53,
  u'link': u'http://www.meetup.com/members/11337881',
  u'lon': -0.09,
  u'name': u'Abhishek Shivkumar',
  u'other_services': {u'twitter': {u'identifier': u'@abhisemweb'}},
  u'photo': {u'highres_link': u'http://photos3.meetupstatic.com/photos/member/9/6/f/3/highres_10898643.jpeg',
             u'photo_id': 10898643,
             u'photo_link': u'http://photos3.meetupstatic.com/photos/member/9/6/f/3/member_10898643.jpeg',
             u'thumb_link': u'http://photos3.meetupstatic.com/photos/member/9/6/f/3/thumb_10898643.jpeg'},
  u'self': {u'common': {}},
  u'state': u'17',
  u'status': u'active',
  u'topics': [{u'id': 1372, u'name': u'Semantic Web', u'urlkey': u'semweb'},
              {u'id': 1512, u'name': u'XML', u'urlkey': u'xml'},
              {u'id': 49585,
               u'name': u'Semantic Social Networks',
               u'urlkey': u'semantic-social-networks'},
              {u'id': 24553,
               u'name': u'Natural Language Processing',
...(snip)...
               u'name': u'Android Development',
               u'urlkey': u'android-developers'}],
  u'visited': 1429281599000}
```

# 预览我们的应用程序

我们的挑战是理解从这些社交网络中检索到的数据，找到关键关系并得出见解。一些感兴趣的元素如下：

+   可视化顶级影响者：发现社区中的顶级影响者：

+   *Apache Spark*上的重度 Twitter 用户

+   GitHub 的提交者

+   领先的 Meetup 演示

+   了解网络：GitHub 提交者、观察者和星标用户的网络图

+   确定热门位置：定位 Spark 最活跃的位置

以下截图提供了我们应用程序的预览：

![预览我们的应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_02_09.jpg)

# 总结

在本章中，我们阐述了我们应用程序的总体架构。我们解释了处理数据的两种主要范例：批处理，也称为静态数据，和流式分析，也称为动态数据。我们继续建立与三个感兴趣的社交网络的连接：Twitter、GitHub 和 Meetup。我们对数据进行了抽样，并提供了我们的构建目标的预览。本书的其余部分将专注于 Twitter 数据集。我们在这里提供了访问三个社交网络的工具和 API，这样你就可以在以后创建自己的数据混搭。我们现在准备调查收集的数据，这将是下一章的主题。

在下一章中，我们将深入研究数据分析，提取我们感兴趣的关键属性，并管理批处理和流处理的信息存储。


# 第三章：使用 Spark 玩弄数据

根据上一章中概述的批处理和流处理架构，我们需要数据来支持我们的应用程序。我们将从 Twitter 上收集关于 Apache Spark 的数据。本章的目标是准备数据以供机器学习和流处理应用程序进一步使用。本章重点介绍如何在分布式网络中交换代码和数据。我们将深入了解序列化、持久化、编组和缓存。我们将深入了解 Spark SQL，这是交互式地探索结构化和半结构化数据的关键 Spark 模块。支持 Spark SQL 的基本数据结构是 Spark dataframe。Spark dataframe 受到 Python Pandas dataframe 和 R dataframe 的启发。它是一种强大的数据结构，被具有 R 或 Python 背景的数据科学家充分理解和赞赏。

在本章中，我们将涵盖以下内容：

+   连接到 Twitter，收集相关数据，然后以 JSON 和 CSV 等各种格式以及数据存储（如 MongoDB）进行持久化

+   使用 Blaze 和 Odo 来分析数据，Odo 是 Blaze 的一个衍生库，用于连接和传输来自各种来源和目的地的数据

+   介绍 Spark dataframe 作为各种 Spark 模块之间数据交换的基础，并使用 Spark SQL 交互式地探索数据

# 重新审视数据密集型应用架构

让我们首先将本章的重点与数据密集型应用架构放在一起。我们将集中精力放在集成层上，并基本上通过迭代循环来运行数据的获取、精炼和持久化。这个循环被称为五个 C。五个 C 代表连接、收集、校正、组合和消费。这些是我们在集成层中运行的基本流程，以便从 Twitter 中获取正确质量和数量的数据。我们还将深入研究持久化层，并设置一个数据存储，如 MongoDB，以便稍后收集我们的数据进行处理。

我们将使用 Blaze 和 Spark SQL 来探索数据，Blaze 是用于数据操作的 Python 库，而 Spark SQL 是由 Spark dataframe 支持的用于数据发现的交互模块。Dataframe 范式由 Python Pandas、Python Blaze 和 Spark SQL 共享。我们将了解这三种 dataframe 的细微差别。

以下图表设置了本章重点的背景，突出了集成层和持久化层：

重新审视数据密集型应用架构

# 序列化和反序列化数据

从网络 API 中收集数据时受到速率限制的约束，我们需要将它们存储起来。由于数据在分布式集群上进行处理，我们需要一致的方法来保存状态并在以后使用时检索它。

现在让我们定义序列化、持久化、编组和缓存或记忆化。

将 Python 对象序列化为一系列字节。当程序关闭时，需要检索 Python 对象以超出其存在范围，序列化的 Python 对象可以通过网络传输或存储在持久存储中。反序列化是相反的过程，将一系列字节转换为原始的 Python 对象，以便程序可以从保存的状态继续进行。Python 中最流行的序列化库是 Pickle。事实上，PySpark 命令通过 pickled 数据通过网络传输到工作节点。

持久化将程序的状态数据保存到磁盘或内存中，以便在重新启动时可以继续之前的工作。它将 Python 对象从内存保存到文件或数据库中，并在以后以相同的状态加载它。

编组将 Python 代码或数据通过网络 TCP 连接发送到多核或分布式系统中。

缓存将 Python 对象转换为内存中的字符串，以便以后可以用作字典键。Spark 支持将数据集缓存在整个集群的内存中。当数据被重复访问时，比如查询一个小的参考数据集或运行迭代算法（如 Google PageRank）时，这是非常有用的。

缓存对于 Spark 来说是一个关键概念，因为它允许我们将 RDD 保存在内存中或溢出到磁盘。缓存策略可以根据数据的血统或 RDD 应用的转换的 DAG（有向无环图的缩写）来选择，以最小化洗牌或跨网络的重数据交换。为了在 Spark 中实现良好的性能，要注意数据洗牌。良好的分区策略和 RDD 缓存的使用，再加上避免不必要的操作操作，可以提高 Spark 的性能。

# 收集和存储数据

在深入研究数据库持久存储（如 MongoDB）之前，我们将看一些广泛使用的有用文件存储：CSV（逗号分隔值的缩写）和 JSON（JavaScript 对象表示法的缩写）文件存储。这两种文件格式的持久受欢迎之处在于几个关键原因：它们易于阅读，简单，相对轻量级，易于使用。

## 在 CSV 中持久化数据

CSV 格式是轻量级的，易于阅读和使用。它具有带有固有表格模式的分隔文本列。

Python 提供了一个强大的`csv`库，可以将`csv`文件序列化为 Python 字典。为了实现我们的程序目的，我们编写了一个`python`类，用于管理以 CSV 格式持久化数据并从给定的 CSV 文件中读取。

让我们运行`IO_csv`类对象的代码。该类的`__init__`部分基本上实例化了文件路径、文件名和文件后缀（在本例中为`.csv`）：

```py
class IO_csv(object):

    def __init__(self, filepath, filename, filesuffix='csv'):
        self.filepath = filepath       # /path/to/file without the /' at the end
        self.filename = filename       # FILE_NAME
        self.filesuffix = filesuffix
```

该类的`save`方法使用 Python 命名元组和`csv`文件的标题字段，以便在持久化 CSV 的同时传递模式。如果`csv`文件已经存在，它将被追加而不是覆盖；否则将被创建：

```py
    def save(self, data, NTname, fields):
        # NTname = Name of the NamedTuple
        # fields = header of CSV - list of the fields name
        NTuple = namedtuple(NTname, fields)

        if os.path.isfile('{0}/{1}.{2}'.format(self.filepath, self.filename, self.filesuffix)):
            # Append existing file
            with open('{0}/{1}.{2}'.format(self.filepath, self.filename, self.filesuffix), 'ab') as f:
                writer = csv.writer(f)
                # writer.writerow(fields) # fields = header of CSV
                writer.writerows([row for row in map(NTuple._make, data)])
                # list comprehension using map on the NamedTuple._make() iterable and the data file to be saved
                # Notice writer.writerows and not writer.writerow (i.e. list of multiple rows sent to csv file
        else:
            # Create new file
            with open('{0}/{1}.{2}'.format(self.filepath, self.filename, self.filesuffix), 'wb') as f:
                writer = csv.writer(f)
                writer.writerow(fields) # fields = header of CSV - list of the fields name
                writer.writerows([row for row in map(NTuple._make, data)])
                #  list comprehension using map on the NamedTuple._make() iterable and the data file to be saved
                # Notice writer.writerows and not writer.writerow (i.e. list of multiple rows sent to csv file
```

该类的`load`方法还使用 Python 命名元组和`csv`文件的标题字段，以便使用一致的模式检索数据。`load`方法是一个内存高效的生成器，以避免在内存中加载大文件：因此我们使用`yield`代替`return`：

```py
    def load(self, NTname, fields):
        # NTname = Name of the NamedTuple
        # fields = header of CSV - list of the fields name
        NTuple = namedtuple(NTname, fields)
        with open('{0}/{1}.{2}'.format(self.filepath, self.filename, self.filesuffix),'rU') as f:
            reader = csv.reader(f)
            for row in map(NTuple._make, reader):
                # Using map on the NamedTuple._make() iterable and the reader file to be loaded
                yield row 
```

这是命名元组。我们使用它来解析推文，以便将它们保存或从`csv`文件中检索出来：

```py
fields01 = ['id', 'created_at', 'user_id', 'user_name', 'tweet_text', 'url']
Tweet01 = namedtuple('Tweet01',fields01)

def parse_tweet(data):
    """
    Parse a ``tweet`` from the given response data.
    """
    return Tweet01(
        id=data.get('id', None),
        created_at=data.get('created_at', None),
        user_id=data.get('user_id', None),
        user_name=data.get('user_name', None),
        tweet_text=data.get('tweet_text', None),
        url=data.get('url')
    )
```

## 在 JSON 中持久化数据

JSON 是互联网应用程序中最流行的数据格式之一。我们正在处理的所有 API，Twitter、GitHub 和 Meetup，都以 JSON 格式传递它们的数据。与 XML 相比，JSON 格式相对轻量级且易于阅读，其模式嵌入在 JSON 中。与 CSV 格式相反，其中所有记录都遵循完全相同的表格结构，JSON 记录的结构可以有所不同。JSON 是半结构化的。JSON 记录可以映射到 Python 字典的字典中。

让我们运行`IO_json`类对象的代码。该类的`__init__`部分基本上实例化了文件路径、文件名和文件后缀（在本例中为`.json`）：

```py
class IO_json(object):
    def __init__(self, filepath, filename, filesuffix='json'):
        self.filepath = filepath        # /path/to/file without the /' at the end
        self.filename = filename        # FILE_NAME
        self.filesuffix = filesuffix
        # self.file_io = os.path.join(dir_name, .'.join((base_filename, filename_suffix)))
```

该类的`save`方法使用`utf-8`编码，以确保数据的读取和写入兼容性。如果 JSON 文件已经存在，它将被追加而不是覆盖；否则将被创建：

```py
    def save(self, data):
        if os.path.isfile('{0}/{1}.{2}'.format(self.filepath, self.filename, self.filesuffix)):
            # Append existing file
            with io.open('{0}/{1}.{2}'.format(self.filepath, self.filename, self.filesuffix), 'a', encoding='utf-8') as f:
                f.write(unicode(json.dumps(data, ensure_ascii= False))) # In python 3, there is no "unicode" function 
                # f.write(json.dumps(data, ensure_ascii= False)) # create a \" escape char for " in the saved file        
        else:
            # Create new file
            with io.open('{0}/{1}.{2}'.format(self.filepath, self.filename, self.filesuffix), 'w', encoding='utf-8') as f:
                f.write(unicode(json.dumps(data, ensure_ascii= False)))
                # f.write(json.dumps(data, ensure_ascii= False))
```

该类的`load`方法只返回已读取的文件。需要进一步应用`json.loads`函数以从读取的文件中检索出`json`：

```py
    def load(self):
        with io.open('{0}/{1}.{2}'.format(self.filepath, self.filename, self.filesuffix), encoding='utf-8') as f:
            return f.read()
```

## 设置 MongoDB

存储收集到的信息至关重要。因此，我们将 MongoDB 设置为我们的主要文档数据存储。由于收集的所有信息都是以 JSON 格式，而 MongoDB 以 BSON（Binary JSON 的缩写）存储信息，因此它是一个自然的选择。

现在我们将按以下步骤进行：

+   安装 MongoDB 服务器和客户端

+   运行 MongoDB 服务器

+   运行 Mongo 客户端

+   安装 PyMongo 驱动程序

+   创建 Python Mongo 客户端

### 安装 MongoDB 服务器和客户端

为了安装 MongoDB 软件包，请按以下步骤执行：

1.  导入软件包管理系统（在我们的情况下是 Ubuntu 的`apt`）使用的公钥。要导入 MongoDB 公钥，我们发出以下命令：

```py
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10

```

1.  为 MongoDB 创建一个列表文件。要创建列表文件，我们使用以下命令：

```py
echo "deb http://repo.mongodb.org/apt/ubuntu "$("lsb_release -sc)"/ mongodb-org/3.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.0.list

```

1.  将本地软件包数据库更新为`sudo`：

```py
sudo apt-get update

```

1.  安装 MongoDB 软件包。我们使用以下命令安装 MongoDB 的最新稳定版本：

```py
sudo apt-get install -y mongodb-org

```

### 运行 MongoDB 服务器

让我们启动 MongoDB 服务器：

1.  要启动 MongoDB 服务器，我们发出以下命令来启动`mongod`：

```py
sudo service mongodb start

```

1.  要检查`mongod`是否已正确启动，我们发出以下命令：

```py
an@an-VB:/usr/bin$ ps -ef | grep mongo
mongodb    967     1  4 07:03 ?        00:02:02 /usr/bin/mongod --config /etc/mongod.conf
an        3143  3085  0 07:45 pts/3    00:00:00 grep --color=auto mongo

```

在这种情况下，我们看到`mongodb`正在进程`967`中运行。

1.  `mongod`服务器发送一条消息，表示它正在等待`端口 27017`上的连接。这是 MongoDB 的默认端口。可以在配置文件中更改。

1.  我们可以在`/var/log/mongod/mongod.log`中检查日志文件的内容：

```py
an@an-VB:/var/lib/mongodb$ ls -lru
total 81936
drwxr-xr-x 2 mongodb nogroup     4096 Apr 25 11:19 _tmp
-rw-r--r-- 1 mongodb nogroup       69 Apr 25 11:19 storage.bson
-rwxr-xr-x 1 mongodb nogroup        5 Apr 25 11:19 mongod.lock
-rw------- 1 mongodb nogroup 16777216 Apr 25 11:19 local.ns
-rw------- 1 mongodb nogroup 67108864 Apr 25 11:19 local.0
drwxr-xr-x 2 mongodb nogroup     4096 Apr 25 11:19 journal

```

1.  要停止`mongodb`服务器，只需发出以下命令：

```py
sudo service mongodb stop

```

### 运行 Mongo 客户端

在控制台中运行 Mongo 客户端就像调用`mongo`一样简单，如以下命令所示：

```py
an@an-VB:/usr/bin$ mongo
MongoDB shell version: 3.0.2
connecting to: test
Server has startup warnings: 
2015-05-30T07:03:49.387+0200 I CONTROL  [initandlisten] 
2015-05-30T07:03:49.388+0200 I CONTROL  [initandlisten] 

```

在 mongo 客户端控制台提示符下，我们可以使用以下命令查看数据库：

```py
> show dbs
local  0.078GB
test   0.078GB
```

我们使用`use test`选择测试数据库：

```py
> use test
switched to db test
```

我们显示测试数据库中的集合：

```py
> show collections
restaurants
system.indexes
```

我们检查先前列出的餐厅集合中的一个示例记录：

```py
> db.restaurants.find()
{ "_id" : ObjectId("553b70055e82e7b824ae0e6f"), "address : { "building : "1007", "coord" : [ -73.856077, 40.848447 ], "street : "Morris Park Ave", "zipcode : "10462 }, "borough : "Bronx", "cuisine : "Bakery", "grades : [ { "grade : "A", "score" : 2, "date" : ISODate("2014-03-03T00:00:00Z") }, { "date" : ISODate("2013-09-11T00:00:00Z"), "grade : "A", "score" : 6 }, { "score" : 10, "date" : ISODate("2013-01-24T00:00:00Z"), "grade : "A }, { "date" : ISODate("2011-11-23T00:00:00Z"), "grade : "A", "score" : 9 }, { "date" : ISODate("2011-03-10T00:00:00Z"), "grade : "B", "score" : 14 } ], "name : "Morris Park Bake Shop", "restaurant_id : "30075445" }
```

### 安装 PyMongo 驱动程序

使用 anaconda 安装 Python 驱动程序很容易。只需在终端运行以下命令：

```py
conda install pymongo
```

### 创建 Python 客户端以用于 MongoDB

我们正在创建一个`IO_mongo`类，该类将用于我们的收集和处理程序中，以存储收集和检索到的信息。为了创建`mongo`客户端，我们将从`pymongo`导入`MongoClient`模块。我们在本地主机的端口 27017 上连接到`mongodb`服务器。命令如下：

```py
from pymongo import MongoClient as MCli

class IO_mongo(object):
    conn={'host':'localhost', 'ip':'27017'}
```

我们通过客户端连接、数据库（在本例中为`twtr_db`）和要访问的集合（在本例中为`twtr_coll`）来初始化我们的类：

```py
    def __init__(self, db='twtr_db', coll='twtr_coll', **conn ):
        # Connects to the MongoDB server 
        self.client = MCli(**conn)
        self.db = self.client[db]
        self.coll = self.db[coll]
```

`save`方法在预初始化的集合和数据库中插入新记录：

```py
    def save(self, data):
        # Insert to collection in db  
        return self.coll.insert(data)
```

`load`方法允许根据条件和投影检索特定记录。在数据量大的情况下，它返回一个游标：

```py
    def load(self, return_cursor=False, criteria=None, projection=None):

            if criteria is None:
                criteria = {}

            if projection is None:
                cursor = self.coll.find(criteria)
            else:
                cursor = self.coll.find(criteria, projection)

            # Return a cursor for large amounts of data
            if return_cursor:
                return cursor
            else:
                return [ item for item in cursor ]
```

## 从 Twitter 收集数据

每个社交网络都存在其局限性和挑战。收集数据的主要障碍之一是强加的速率限制。在运行重复或长时间连接的速率限制暂停时，我们必须小心避免收集重复数据。

我们已经重新设计了在前一章中概述的连接程序，以处理速率限制。

在这个`TwitterAPI`类中，根据我们指定的搜索查询连接和收集推文，我们添加了以下内容：

+   使用 Python 日志库的记录功能，以便在程序失败时收集任何错误或警告。

+   使用 MongoDB 的持久性功能，以及之前公开的`IO_mongo`类和使用`IO_json`类的 JSON 文件

+   API 速率限制和错误管理功能，因此我们可以确保更具弹性地调用 Twitter，而不会因为接入 firehose 而被禁止

让我们按以下步骤进行：

1.  我们通过实例化 Twitter API 来初始化：

```py
class TwitterAPI(object):
    """
    TwitterAPI class allows the Connection to Twitter via OAuth
    once you have registered with Twitter and receive the 
    necessary credentials 
    """

    def __init__(self): 
        consumer_key = 'get_your_credentials'
        consumer_secret = get your_credentials'
        access_token = 'get_your_credentials'
        access_secret = 'get your_credentials'
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.access_token = access_token
        self.access_secret = access_secret
        self.retries = 3
        self.auth = twitter.oauth.OAuth(access_token, access_secret, consumer_key, consumer_secret)
        self.api = twitter.Twitter(auth=self.auth)
```

1.  我们通过提供日志级别来初始化记录器：

+   `logger.debug`（调试消息）

+   `logger.info`（信息消息）

+   `logger.warn`（警告消息）

+   `logger.error`（错误消息）

+   `logger.critical`（临界消息）

1.  我们设置日志路径和消息格式：

```py
        # logger initialisation
        appName = 'twt150530'
        self.logger = logging.getLogger(appName)
        #self.logger.setLevel(logging.DEBUG)
        # create console handler and set level to debug
        logPath = '/home/an/spark/spark-1.3.0-bin-hadoop2.4/examples/AN_Spark/data'
        fileName = appName
        fileHandler = logging.FileHandler("{0}/{1}.log".format(logPath, fileName))
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fileHandler.setFormatter(formatter)
        self.logger.addHandler(fileHandler) 
        self.logger.setLevel(logging.DEBUG)
```

1.  我们初始化 JSON 文件持久性指令：

```py
        # Save to JSON file initialisation
        jsonFpath = '/home/an/spark/spark-1.3.0-bin-hadoop2.4/examples/AN_Spark/data'
        jsonFname = 'twtr15053001'
        self.jsonSaver = IO_json(jsonFpath, jsonFname)
```

1.  我们初始化 MongoDB 数据库和集合以进行持久化：

```py
        # Save to MongoDB Intitialisation
        self.mongoSaver = IO_mongo(db='twtr01_db', coll='twtr01_coll')
```

1.  `searchTwitter`方法根据指定的查询启动搜索：

```py
    def searchTwitter(self, q, max_res=10,**kwargs):
        search_results = self.api.search.tweets(q=q, count=10, **kwargs)
        statuses = search_results['statuses']
        max_results = min(1000, max_res)

        for _ in range(10):
            try:
                next_results = search_results['search_metadata']['next_results']
                # self.logger.info('info' in searchTwitter - next_results:%s'% next_results[1:])
            except KeyError as e:
                self.logger.error('error' in searchTwitter: %s', %(e))
                break

            # next_results = urlparse.parse_qsl(next_results[1:]) # python 2.7
            next_results = urllib.parse.parse_qsl(next_results[1:])
            # self.logger.info('info' in searchTwitter - next_results[max_id]:', next_results[0:])
            kwargs = dict(next_results)
            # self.logger.info('info' in searchTwitter - next_results[max_id]:%s'% kwargs['max_id'])
            search_results = self.api.search.tweets(**kwargs)
            statuses += search_results['statuses']
            self.saveTweets(search_results['statuses'])

            if len(statuses) > max_results:
                self.logger.info('info' in searchTwitter - got %i tweets - max: %i' %(len(statuses), max_results))
                break
        return statuses
```

1.  `saveTweets`方法实际上将收集到的推文保存为 JSON 和 MongoDB：

```py
    def saveTweets(self, statuses):
        # Saving to JSON File
        self.jsonSaver.save(statuses)

        # Saving to MongoDB
        for s in statuses:
            self.mongoSaver.save(s)
```

1.  `parseTweets`方法允许我们从 Twitter API 提供的大量信息中提取关键的推文信息：

```py
    def parseTweets(self, statuses):
        return [ (status['id'], 
                  status['created_at'], 
                  status['user']['id'],
                  status['user']['name'] 
                  status['text''text'], 
                  url['expanded_url']) 
                        for status in statuses 
                            for url in status['entities']['urls'] ]
```

1.  `getTweets`方法调用了先前描述的`searchTwitter`方法。`getTweets`方法确保可靠地进行 API 调用，同时尊重强加的速率限制。代码如下：

```py
    def getTweets(self, q,  max_res=10):
        """
        Make a Twitter API call whilst managing rate limit and errors.
        """
        def handleError(e, wait_period=2, sleep_when_rate_limited=True):
            if wait_period > 3600: # Seconds
                self.logger.error('Too many retries in getTweets: %s', %(e))
                raise e
            if e.e.code == 401:
                self.logger.error('error 401 * Not Authorised * in getTweets: %s', %(e))
                return None
            elif e.e.code == 404:
                self.logger.error('error 404 * Not Found * in getTweets: %s', %(e))
                return None
            elif e.e.code == 429: 
                self.logger.error('error 429 * API Rate Limit Exceeded * in getTweets: %s', %(e))
                if sleep_when_rate_limited:
                    self.logger.error('error 429 * Retrying in 15 minutes * in getTweets: %s', %(e))
                    sys.stderr.flush()
                    time.sleep(60*15 + 5)
                    self.logger.info('error 429 * Retrying now * in getTweets: %s', %(e))
                    return 2
                else:
                    raise e # Caller must handle the rate limiting issue
            elif e.e.code in (500, 502, 503, 504):
                self.logger.info('Encountered %i Error. Retrying in %i seconds' % (e.e.code, wait_period))
                time.sleep(wait_period)
                wait_period *= 1.5
                return wait_period
            else:
                self.logger.error('Exit - aborting - %s', %(e))
                raise e
```

1.  在这里，我们根据指定的参数调用`searchTwitter`API 进行相关查询。如果我们遇到来自提供者的速率限制等错误，将由`handleError`方法处理：

```py
        while True:
            try:
                self.searchTwitter( q, max_res=10)
            except twitter.api.TwitterHTTPError as e:
                error_count = 0 
                wait_period = handleError(e, wait_period)
                if wait_period is None:
                    return
```

# 使用 Blaze 探索数据

Blaze 是一个开源的 Python 库，主要由 Continuum.io 开发，利用 Python Numpy 数组和 Pandas 数据框架。Blaze 扩展到了核外计算，而 Pandas 和 Numpy 是单核的。

Blaze 在各种后端之间提供了一个适应性强、统一和一致的用户界面。Blaze 编排以下内容：

+   **数据**：在不同存储之间无缝交换数据，如 CSV、JSON、HDF5、HDFS 和 Bcolz 文件。

+   **计算**：使用相同的查询处理对计算后端进行计算，如 Spark、MongoDB、Pandas 或 SQL Alchemy。

+   **符号表达式**：抽象表达式，如连接、分组、过滤、选择和投影，其语法类似于 Pandas，但范围有限。实现了 R 语言开创的分割-应用-合并方法。

Blaze 表达式是惰性评估的，在这方面与 Spark RDD 转换共享类似的处理范式。

让我们首先导入必要的库来深入了解 Blaze：`numpy`、`pandas`、`blaze`和`odo`。Odo 是 Blaze 的一个衍生项目，确保从各种后端迁移数据。命令如下：

```py
import numpy as np
import pandas as pd
from blaze import Data, by, join, merge
from odo import odo
BokehJS successfully loaded.
```

我们通过读取保存在 CSV 文件`twts_csv`中的解析推文来创建一个 Pandas `Dataframe`：

```py
twts_pd_df = pd.DataFrame(twts_csv_read, columns=Tweet01._fields)
twts_pd_df.head()

Out[65]:
id    created_at    user_id    user_name    tweet_text    url
1   598831111406510082   2015-05-14 12:43:57   14755521 raulsaeztapia    RT @pacoid: Great recap of @StrataConf EU in L...   http://www.mango-solutions.com/wp/2015/05/the-...
2   598831111406510082   2015-05-14 12:43:57   14755521 raulsaeztapia    RT @pacoid: Great recap of @StrataConf EU in L...   http://www.mango-solutions.com/wp/2015/05/the-...
3   98808944719593472   2015-05-14 11:15:52   14755521 raulsaeztapia   RT @alvaroagea: Simply @ApacheSpark http://t.c...    http://www.webex.com/ciscospark/
4   598808944719593472   2015-05-14 11:15:52   14755521 raulsaeztapia   RT @alvaroagea: Simply @ApacheSpark http://t.c...   http://sparkjava.com/
```

我们运行 Tweets Panda `Dataframe`到`describe()`函数，以获取数据集的一些整体信息：

```py
twts_pd_df.describe()
Out[66]:
id    created_at    user_id    user_name    tweet_text    url
count  19  19  19  19  19  19
unique    7  7   6   6     6   7
top    598808944719593472    2015-05-14 11:15:52    14755521 raulsaeztapia    RT @alvaroagea: Simply @ApacheSpark http://t.c...    http://bit.ly/1Hfd0Xm
freq    6    6    9    9    6    6
```

我们通过简单地通过`Data()`函数传递 Pandas `dataframe`将其转换为 Blaze `dataframe`：

```py
#
# Blaze dataframe
#
twts_bz_df = Data(twts_pd_df)
```

我们可以通过传递`schema`函数来检索 Blaze `dataframe`的模式表示：

```py
twts_bz_df.schema
Out[73]:
dshape("""{
  id: ?string,
  created_at: ?string,
  user_id: ?string,
  user_name: ?string,
  tweet_text: ?string,
  url: ?string
  }""")
```

`.dshape`函数给出记录计数和模式：

```py
twts_bz_df.dshape
Out[74]: 
dshape("""19 * {
  id: ?string,
  created_at: ?string,
  user_id: ?string,
  user_name: ?string,
  tweet_text: ?string,
  url: ?string
  }""")
```

我们可以打印 Blaze `dataframe`的内容：

```py
twts_bz_df.data
Out[75]:
id    created_at    user_id    user_name    tweet_text    url
1    598831111406510082    2015-05-14 12:43:57   14755521 raulsaeztapia    RT @pacoid: Great recap of @StrataConf EU in L...    http://www.mango-solutions.com/wp/2015/05/the-...
2    598831111406510082    2015-05-14 12:43:57    14755521 raulsaeztapia    RT @pacoid: Great recap of @StrataConf EU in L...    http://www.mango-solutions.com/wp/2015/05/the-...
... 
18   598782970082807808    2015-05-14 09:32:39    1377652806 embeddedcomputer.nl    RT @BigDataTechCon: Moving Rating Prediction w...    http://buff.ly/1QBpk8J
19   598777933730160640     2015-05-14 09:12:38   294862170    Ellen Friedman   I'm still on Euro time. If you are too check o...http://bit.ly/1Hfd0Xm
```

我们提取列`tweet_text`并获取唯一值：

```py
twts_bz_df.tweet_text.distinct()
Out[76]:
    tweet_text
0   RT @pacoid: Great recap of @StrataConf EU in L...
1   RT @alvaroagea: Simply @ApacheSpark http://t.c...
2   RT @PrabhaGana: What exactly is @ApacheSpark a...
3   RT @Ellen_Friedman: I'm still on Euro time. If...
4   RT @BigDataTechCon: Moving Rating Prediction w...
5   I'm still on Euro time. If you are too check o...
```

我们从`dataframe`中提取多列`['id', 'user_name','tweet_text']`并获取唯一记录：

```py
twts_bz_df[['id', 'user_name','tweet_text']].distinct()
Out[78]:
  id   user_name   tweet_text
0   598831111406510082   raulsaeztapia   RT @pacoid: Great recap of @StrataConf EU in L...
1   598808944719593472   raulsaeztapia   RT @alvaroagea: Simply @ApacheSpark http://t.c...
2   598796205091500032   John Humphreys   RT @PrabhaGana: What exactly is @ApacheSpark a...
3   598788561127735296   Leonardo D'Ambrosi   RT @Ellen_Friedman: I'm still on Euro time. If...
4   598785545557438464   Alexey Kosenkov   RT @Ellen_Friedman: I'm still on Euro time. If...
5   598782970082807808   embeddedcomputer.nl   RT @BigDataTechCon: Moving Rating Prediction w...
6   598777933730160640   Ellen Friedman   I'm still on Euro time. If you are too check o...
```

## 使用 Odo 传输数据

Odo 是 Blaze 的一个衍生项目。Odo 允许数据的交换。Odo 确保数据在不同格式（CSV、JSON、HDFS 等）和不同数据库（SQL 数据库、MongoDB 等）之间的迁移非常简单：

```py
Odo(source, target)
```

要传输到数据库，需要使用 URL 指定地址。例如，对于 MongoDB 数据库，它看起来像这样：

```py
mongodb://username:password@hostname:port/database_name::collection_name
```

让我们运行一些使用 Odo 的示例。在这里，我们通过读取一个 CSV 文件并创建一个 Blaze `dataframe`来说明`odo`：

```py
filepath   = csvFpath
filename   = csvFname
filesuffix = csvSuffix
twts_odo_df = Data('{0}/{1}.{2}'.format(filepath, filename, filesuffix))
```

计算`dataframe`中的记录数：

```py
twts_odo_df.count()
Out[81]:
19
```

显示`dataframe`的前五条记录：

```py
twts_odo_df.head(5)
Out[82]:
  id   created_at   user_id   user_name   tweet_text   url
0   598831111406510082   2015-05-14 12:43:57   14755521   raulsaeztapia   RT @pacoid: Great recap of @StrataConf EU in L...   http://www.mango-solutions.com/wp/2015/05/the-...
1   598831111406510082   2015-05-14 12:43:57   14755521   raulsaeztapia   RT @pacoid: Great recap of @StrataConf EU in L...   http://www.mango-solutions.com/wp/2015/05/the-...
2   598808944719593472   2015-05-14 11:15:52   14755521   raulsaeztapia   RT @alvaroagea: Simply @ApacheSpark http://t.c...   http://www.webex.com/ciscospark/
3   598808944719593472   2015-05-14 11:15:52   14755521   raulsaeztapia   RT @alvaroagea: Simply @ApacheSpark http://t.c...   http://sparkjava.com/
4   598808944719593472   2015-05-14 11:15:52   14755521   raulsaeztapia   RT @alvaroagea: Simply @ApacheSpark http://t.c...   https://www.sparkfun.com/
```

从`dataframe`获取`dshape`信息，这给出了记录数和模式：

```py
twts_odo_df.dshape
Out[83]:
dshape("var * {
  id: int64,
  created_at: ?datetime,
  user_id: int64,
  user_name: ?string,
  tweet_text: ?string,
  url: ?string
  }""")
```

将处理后的 Blaze `dataframe`保存为 JSON：

```py
odo(twts_odo_distinct_df, '{0}/{1}.{2}'.format(jsonFpath, jsonFname, jsonSuffix))
Out[92]:
<odo.backends.json.JSONLines at 0x7f77f0abfc50>
```

将 JSON 文件转换为 CSV 文件：

```py
odo('{0}/{1}.{2}'.format(jsonFpath, jsonFname, jsonSuffix), '{0}/{1}.{2}'.format(csvFpath, csvFname, csvSuffix))
Out[94]:
<odo.backends.csv.CSV at 0x7f77f0abfe10>
```

# 使用 Spark SQL 探索数据

Spark SQL 是建立在 Spark Core 之上的关系查询引擎。Spark SQL 使用名为**Catalyst**的查询优化器。

可以使用 SQL 或 HiveQL 表示关系查询，并针对 JSON、CSV 和各种数据库执行。Spark SQL 使我们能够在功能编程的 RDD 之上使用 Spark 数据框架的声明式编程的全部表达能力。

## 了解 Spark 数据框架

这是一条来自`@bigdata`的推文，宣布了 Spark 1.3.0 的到来，以及 Spark SQL 和数据框的出现。它还突出了图表下部的各种数据源。在图表的上部，我们可以注意到 R 作为新语言，将逐渐支持 Scala、Java 和 Python。最终，数据框的理念在 R、Python 和 Spark 之间普遍存在。

![理解 Spark 数据框](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_03_02.jpg)

Spark 数据框源自 SchemaRDDs。它将 RDD 与可以由 Spark 推断的模式结合在一起，如果请求的话，可以在注册数据框时推断出模式。它允许我们使用普通 SQL 查询复杂嵌套的 JSON 数据。惰性评估、血统、分区和持久性适用于数据框。

让我们通过首先导入`SparkContext`和`SQLContext`来使用 Spark SQL 查询数据：

```py
from pyspark import SparkConf, SparkContext
from pyspark.sql import SQLContext, Row
In [95]:
sc
Out[95]:
<pyspark.context.SparkContext at 0x7f7829581890>
In [96]:
sc.master
Out[96]:
u'local[*]'
''In [98]:
# Instantiate Spark  SQL context
sqlc =  SQLContext(sc)
```

我们读取了用 Odo 保存的 JSON 文件：

```py
twts_sql_df_01 = sqlc.jsonFile ("/home/an/spark/spark-1.3.0-bin-hadoop2.4/examples/AN_Spark/data/twtr15051401_distinct.json")
In [101]:
twts_sql_df_01.show()
created_at           id                 tweet_text           user_id    user_name          
2015-05-14T12:43:57Z 598831111406510082 RT @pacoid: Great... 14755521   raulsaeztapia      
2015-05-14T11:15:52Z 598808944719593472 RT @alvaroagea: S... 14755521   raulsaeztapia      
2015-05-14T10:25:15Z 598796205091500032 RT @PrabhaGana: W... 48695135   John Humphreys     
2015-05-14T09:54:52Z 598788561127735296 RT @Ellen_Friedma... 2385931712 Leonardo D'Ambrosi
2015-05-14T09:42:53Z 598785545557438464 RT @Ellen_Friedma... 461020977  Alexey Kosenkov    
2015-05-14T09:32:39Z 598782970082807808 RT @BigDataTechCo... 1377652806 embeddedcomputer.nl
2015-05-14T09:12:38Z 598777933730160640 I'm still on Euro... 294862170  Ellen Friedman     
```

我们打印 Spark dataframe 的模式：

```py
twts_sql_df_01.printSchema()
root
 |-- created_at: string (nullable = true)
 |-- id: long (nullable = true)
 |-- tweet_text: string (nullable = true)
 |-- user_id: long (nullable = true)
 |-- user_name: string (nullable = true)
```

我们从数据框中选择`user_name`列：

```py
twts_sql_df_01.select('user_name').show()
user_name          
raulsaeztapia      
raulsaeztapia      
John Humphreys     
Leonardo D'Ambrosi
Alexey Kosenkov    
embeddedcomputer.nl
Ellen Friedman     
```

我们将数据框注册为表，这样我们就可以对其执行 SQL 查询：

```py
twts_sql_df_01.registerAsTable('tweets_01')
```

我们对数据框执行了一条 SQL 语句：

```py
twts_sql_df_01_selection = sqlc.sql("SELECT * FROM tweets_01 WHERE user_name = 'raulsaeztapia'")
In [109]:
twts_sql_df_01_selection.show()
created_at           id                 tweet_text           user_id  user_name    
2015-05-14T12:43:57Z 598831111406510082 RT @pacoid: Great... 14755521 raulsaeztapia
2015-05-14T11:15:52Z 598808944719593472 RT @alvaroagea: S... 14755521 raulsaeztapia
```

让我们处理一些更复杂的 JSON；我们读取原始的 Twitter JSON 文件：

```py
tweets_sqlc_inf = sqlc.jsonFile(infile)
```

Spark SQL 能够推断复杂嵌套的 JSON 文件的模式：

```py
tweets_sqlc_inf.printSchema()
root
 |-- contributors: string (nullable = true)
 |-- coordinates: string (nullable = true)
 |-- created_at: string (nullable = true)
 |-- entities: struct (nullable = true)
 |    |-- hashtags: array (nullable = true)
 |    |    |-- element: struct (containsNull = true)
 |    |    |    |-- indices: array (nullable = true)
 |    |    |    |    |-- element: long (containsNull = true)
 |    |    |    |-- text: string (nullable = true)
 |    |-- media: array (nullable = true)
 |    |    |-- element: struct (containsNull = true)
 |    |    |    |-- display_url: string (nullable = true)
 |    |    |    |-- expanded_url: string (nullable = true)
 |    |    |    |-- id: long (nullable = true)
 |    |    |    |-- id_str: string (nullable = true)
 |    |    |    |-- indices: array (nullable = true)
... (snip) ...
|    |-- statuses_count: long (nullable = true)
 |    |-- time_zone: string (nullable = true)
 |    |-- url: string (nullable = true)
 |    |-- utc_offset: long (nullable = true)
 |    |-- verified: boolean (nullable = true)
```

我们通过选择数据框中特定列（在本例中为`['created_at', 'id', 'text', 'user.id', 'user.name', 'entities.urls.expanded_url']`）提取感兴趣的关键信息：

```py
tweets_extract_sqlc = tweets_sqlc_inf[['created_at', 'id', 'text', 'user.id', 'user.name', 'entities.urls.expanded_url']].distinct()
In [145]:
tweets_extract_sqlc.show()
created_at           id                 text                 id         name                expanded_url        
Thu May 14 09:32:... 598782970082807808 RT @BigDataTechCo... 1377652806 embeddedcomputer.nl ArrayBuffer(http:...
Thu May 14 12:43:... 598831111406510082 RT @pacoid: Great... 14755521   raulsaeztapia       ArrayBuffer(http:...
Thu May 14 12:18:... 598824733086523393 @rabbitonweb spea... 

...   
Thu May 14 12:28:... 598827171168264192 RT @baandrzejczak... 20909005   Paweł Szulc         ArrayBuffer()       
```

## 理解 Spark SQL 查询优化器

我们对数据框执行了一条 SQL 语句：

```py
tweets_extract_sqlc_sel = sqlc.sql("SELECT * from Tweets_xtr_001 WHERE name='raulsaeztapia'")
```

我们可以详细查看 Spark SQL 执行的查询计划：

+   解析逻辑计划

+   分析逻辑计划

+   优化逻辑计划

+   物理计划

查询计划使用了 Spark SQL 的 Catalyst 优化器。为了从查询部分生成编译后的字节码，Catalyst 优化器通过逻辑计划解析和优化，然后根据成本进行物理计划评估和优化。

这在以下推文中有所体现：

![理解 Spark SQL 查询优化器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_03_03.jpg)

回顾我们的代码，我们在刚刚执行的 Spark SQL 查询上调用了`.explain`函数，它提供了 Catalyst 优化器评估逻辑计划和物理计划并得出结果 RDD 所采取的步骤的全部细节：

```py
tweets_extract_sqlc_sel.explain(extended = True)
== Parsed Logical Plan ==
'Project [*]
 'Filter ('name = raulsaeztapia)'name'  'UnresolvedRelation' [Tweets_xtr_001], None
== Analyzed Logical Plan ==
Project [created_at#7,id#12L,text#27,id#80L,name#81,expanded_url#82]
 Filter (name#81 = raulsaeztapia)
  Distinct 
   Project [created_at#7,id#12L,text#27,user#29.id AS id#80L,user#29.name AS name#81,entities#8.urls.expanded_url AS expanded_url#82]
    Relation[contributors#5,coordinates#6,created_at#7,entities#8,favorite_count#9L,favorited#10,geo#11,id#12L,id_str#13,in_reply_to_screen_name#14,in_reply_to_status_id#15,in_reply_to_status_id_str#16,in_reply_to_user_id#17L,in_reply_to_user_id_str#18,lang#19,metadata#20,place#21,possibly_sensitive#22,retweet_count#23L,retweeted#24,retweeted_status#25,source#26,text#27,truncated#28,user#29] JSONRelation(/home/an/spark/spark-1.3.0-bin-hadoop2.4/examples/AN_Spark/data/twtr15051401.json,1.0,None)
== Optimized Logical Plan ==
Filter (name#81 = raulsaeztapia)
 Distinct 
  Project [created_at#7,id#12L,text#27,user#29.id AS id#80L,user#29.name AS name#81,entities#8.urls.expanded_url AS expanded_url#82]
   Relation[contributors#5,coordinates#6,created_at#7,entities#8,favorite_count#9L,favorited#10,geo#11,id#12L,id_str#13,in_reply_to_screen_name#14,in_reply_to_status_id#15,in_reply_to_status_id_str#16,in_reply_to_user_id#17L,in_reply_to_user_id_str#18,lang#19,metadata#20,place#21,possibly_sensitive#22,retweet_count#23L,retweeted#24,retweeted_status#25,source#26,text#27,truncated#28,user#29] JSONRelation(/home/an/spark/spark-1.3.0-bin-hadoop2.4/examples/AN_Spark/data/twtr15051401.json,1.0,None)
== Physical Plan ==
Filter (name#81 = raulsaeztapia)
 Distinct false
  Exchange (HashPartitioning [created_at#7,id#12L,text#27,id#80L,name#81,expanded_url#82], 200)
   Distinct true
    Project [created_at#7,id#12L,text#27,user#29.id AS id#80L,user#29.name AS name#81,entities#8.urls.expanded_url AS expanded_url#82]
     PhysicalRDD [contributors#5,coordinates#6,created_at#7,entities#8,favorite_count#9L,favorited#10,geo#11,id#12L,id_str#13,in_reply_to_screen_name#14,in_reply_to_status_id#15,in_reply_to_status_id_str#16,in_reply_to_user_id#17L,in_reply_to_user_id_str#18,lang#19,metadata#20,place#21,possibly_sensitive#22,retweet_count#23L,retweeted#24,retweeted_status#25,source#26,text#27,truncated#28,user#29], MapPartitionsRDD[165] at map at JsonRDD.scala:41
Code Generation: false
== RDD ==
```

最后，这是查询的结果：

```py
tweets_extract_sqlc_sel.show()
created_at           id                 text                 id       name          expanded_url        
Thu May 14 12:43:... 598831111406510082 RT @pacoid: Great... 14755521 raulsaeztapia ArrayBuffer(http:...
Thu May 14 11:15:... 598808944719593472 RT @alvaroagea: S... 14755521 raulsaeztapia ArrayBuffer(http:...
In [148]:
```

## 使用 Spark SQL 加载和处理 CSV 文件

我们将使用 Spark 包`spark-csv_2.11:1.2.0`。启动 PySpark 与 IPython Notebook 和`spark-csv`包应明确说明`–packages`参数的命令：

```py
$ IPYTHON_OPTS='notebook' /home/an/spark/spark-1.5.0-bin-hadoop2.6/bin/pyspark --packages com.databricks:spark-csv_2.11:1.2.0

```

这将触发以下输出；我们可以看到`spark-csv`包已安装及其所有依赖项：

```py
an@an-VB:~/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark$ IPYTHON_OPTS='notebook' /home/an/spark/spark-1.5.0-bin-hadoop2.6/bin/pyspark --packages com.databricks:spark-csv_2.11:1.2.0

```

```py
... (snip) ...
Ivy Default Cache set to: /home/an/.ivy2/cache
The jars for the packages stored in: /home/an/.ivy2/jars
:: loading settings :: url = jar:file:/home/an/spark/spark-1.5.0-bin-hadoop2.6/lib/spark-assembly-1.5.0-hadoop2.6.0.jar!/org/apache/ivy/core/settings/ivysettings.xml
com.databricks#spark-csv_2.11 added as a dependency
:: resolving dependencies :: org.apache.spark#spark-submit-parent;1.0
  confs: [default]
  found com.databricks#spark-csv_2.11;1.2.0 in central
  found org.apache.commons#commons-csv;1.1 in central
  found com.univocity#univocity-parsers;1.5.1 in central
:: resolution report :: resolve 835ms :: artifacts dl 48ms
  :: modules in use:
  com.databricks#spark-csv_2.11;1.2.0 from central in [default]
  com.univocity#univocity-parsers;1.5.1 from central in [default]
  org.apache.commons#commons-csv;1.1 from central in [default]
  ----------------------------------------------------------------
  |               |          modules            ||   artifacts   |
  |    conf     | number| search|dwnlded|evicted|| number|dwnlded|
  ----------------------------------------------------------------
  |    default     |   3   |   0   |   0   |   0   ||   3   |   0   
  ----------------------------------------------------------------
:: retrieving :: org.apache.spark#spark-submit-parent
  confs: [default]
  0 artifacts copied, 3 already retrieved (0kB/45ms)
```

现在我们准备加载我们的`csv`文件并处理它。让我们首先导入`SQLContext`：

```py
#
# Read csv in a Spark DF
#
sqlContext = SQLContext(sc)
spdf_in = sqlContext.read.format('com.databricks.spark.csv')\
                                    .options(delimiter=";").options(header="true")\
                                    .options(header='true').load(csv_in)
```

我们访问从加载的`csv`创建的数据框的模式：

```py
In [10]:
spdf_in.printSchema()
root
 |-- : string (nullable = true)
 |-- id: string (nullable = true)
 |-- created_at: string (nullable = true)
 |-- user_id: string (nullable = true)
 |-- user_name: string (nullable = true)
 |-- tweet_text: string (nullable = true)
```

我们检查数据框的列：

```py
In [12]:
spdf_in.columns
Out[12]:
['', 'id', 'created_at', 'user_id', 'user_name', 'tweet_text']
```

我们审查数据框的内容：

```py
In [13]:
spdf_in.show()
+---+------------------+--------------------+----------+------------------+--------------------+
|   |                id|          created_at|   user_id|         user_name|          tweet_text|
+---+------------------+--------------------+----------+------------------+--------------------+
|  0|638830426971181057|Tue Sep 01 21:46:...|3276255125|     True Equality|ernestsgantt: Bey...|
|  1|638830426727911424|Tue Sep 01 21:46:...|3276255125|     True Equality|ernestsgantt: Bey...|
|  2|638830425402556417|Tue Sep 01 21:46:...|3276255125|     True Equality|ernestsgantt: Bey...|
... (snip) ...
| 41|638830280988426250|Tue Sep 01 21:46:...| 951081582|      Jack Baldwin|RT @cloudaus: We ...|
| 42|638830276626399232|Tue Sep 01 21:46:...|   6525302|Masayoshi Nakamura|PynamoDB 使いやすいです  |
+---+------------------+--------------------+----------+------------------+--------------------+
only showing top 20 rows
```

## 从 Spark SQL 查询 MongoDB

从 Spark 到 MongoDB 有两种主要的交互方式：第一种是通过 Hadoop MongoDB 连接器，第二种是直接从 Spark 到 MongoDB。

从 Spark 与 MongoDB 交互的第一种方法是设置一个 Hadoop 环境，并通过 Hadoop MongoDB 连接器进行查询。连接器的详细信息托管在 GitHub 上：[`github.com/mongodb/mongo-hadoop/wiki/Spark-Usage`](https://github.com/mongodb/mongo-hadoop/wiki/Spark-Usage)。MongoDB 的一系列博客文章中描述了一个实际用例：

+   *使用 MongoDB 与 Hadoop 和 Spark：第一部分-介绍和设置* ([`www.mongodb.com/blog/post/using-mongodb-hadoop-spark-part-1-introduction-setup`](https://www.mongodb.com/blog/post/using-mongodb-hadoop-spark-part-1-introduction-setup))

+   使用 MongoDB 与 Hadoop 和 Spark：第二部分 - Hive 示例 ([`www.mongodb.com/blog/post/using-mongodb-hadoop-spark-part-2-hive-example`](https://www.mongodb.com/blog/post/using-mongodb-hadoop-spark-part-2-hive-example))

+   使用 MongoDB 与 Hadoop 和 Spark：第三部分 - Spark 示例和关键要点

设置完整的 Hadoop 环境有点复杂。我们将倾向于第二种方法。我们将使用由 Stratio 开发和维护的`spark-mongodb`连接器。我们使用托管在`spark.packages.org`上的`Stratio spark-mongodb`包。包的信息和版本可以在`spark.packages.org`中找到：

### 注意

**发布**

版本：0.10.1（8263c8 | zip | jar）/日期：2015-11-18 /许可证：Apache-2.0 / Scala 版本：2.10

（[`spark-packages.org/package/Stratio/spark-mongodb`](http://spark-packages.org/package/Stratio/spark-mongodb)）

启动 PySpark 与 IPython 笔记本和`spark-mongodb`包的命令应明确说明 packages 参数：

```py
$ IPYTHON_OPTS='notebook' /home/an/spark/spark-1.5.0-bin-hadoop2.6/bin/pyspark --packages com.stratio.datasource:spark-mongodb_2.10:0.10.1

```

这将触发以下输出；我们可以看到`spark-mongodb`包与其所有依赖项一起安装：

```py
an@an-VB:~/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark$ IPYTHON_OPTS='notebook' /home/an/spark/spark-1.5.0-bin-hadoop2.6/bin/pyspark --packages com.stratio.datasource:spark-mongodb_2.10:0.10.1
... (snip) ... 
Ivy Default Cache set to: /home/an/.ivy2/cache
The jars for the packages stored in: /home/an/.ivy2/jars
:: loading settings :: url = jar:file:/home/an/spark/spark-1.5.0-bin-hadoop2.6/lib/spark-assembly-1.5.0-hadoop2.6.0.jar!/org/apache/ivy/core/settings/ivysettings.xml
com.stratio.datasource#spark-mongodb_2.10 added as a dependency
:: resolving dependencies :: org.apache.spark#spark-submit-parent;1.0
  confs: [default]
  found com.stratio.datasource#spark-mongodb_2.10;0.10.1 in central
[W 22:10:50.910 NotebookApp] Timeout waiting for kernel_info reply from 764081d3-baf9-4978-ad89-7735e6323cb6
  found org.mongodb#casbah-commons_2.10;2.8.0 in central
  found com.github.nscala-time#nscala-time_2.10;1.0.0 in central
  found joda-time#joda-time;2.3 in central
  found org.joda#joda-convert;1.2 in central
  found org.slf4j#slf4j-api;1.6.0 in central
  found org.mongodb#mongo-java-driver;2.13.0 in central
  found org.mongodb#casbah-query_2.10;2.8.0 in central
  found org.mongodb#casbah-core_2.10;2.8.0 in central
downloading https://repo1.maven.org/maven2/com/stratio/datasource/spark-mongodb_2.10/0.10.1/spark-mongodb_2.10-0.10.1.jar ...
  [SUCCESSFUL ] com.stratio.datasource#spark-mongodb_2.10;0.10.1!spark-mongodb_2.10.jar (3130ms)
downloading https://repo1.maven.org/maven2/org/mongodb/casbah-commons_2.10/2.8.0/casbah-commons_2.10-2.8.0.jar ...
  [SUCCESSFUL ] org.mongodb#casbah-commons_2.10;2.8.0!casbah-commons_2.10.jar (2812ms)
downloading https://repo1.maven.org/maven2/org/mongodb/casbah-query_2.10/2.8.0/casbah-query_2.10-2.8.0.jar ...
  [SUCCESSFUL ] org.mongodb#casbah-query_2.10;2.8.0!casbah-query_2.10.jar (1432ms)
downloading https://repo1.maven.org/maven2/org/mongodb/casbah-core_2.10/2.8.0/casbah-core_2.10-2.8.0.jar ...
  [SUCCESSFUL ] org.mongodb#casbah-core_2.10;2.8.0!casbah-core_2.10.jar (2785ms)
downloading https://repo1.maven.org/maven2/com/github/nscala-time/nscala-time_2.10/1.0.0/nscala-time_2.10-1.0.0.jar ...
  [SUCCESSFUL ] com.github.nscala-time#nscala-time_2.10;1.0.0!nscala-time_2.10.jar (2725ms)
downloading https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.6.0/slf4j-api-1.6.0.jar ...
  [SUCCESSFUL ] org.slf4j#slf4j-api;1.6.0!slf4j-api.jar (371ms)
downloading https://repo1.maven.org/maven2/org/mongodb/mongo-java-driver/2.13.0/mongo-java-driver-2.13.0.jar ...
  [SUCCESSFUL ] org.mongodb#mongo-java-driver;2.13.0!mongo-java-driver.jar (5259ms)
downloading https://repo1.maven.org/maven2/joda-time/joda-time/2.3/joda-time-2.3.jar ...
  [SUCCESSFUL ] joda-time#joda-time;2.3!joda-time.jar (6949ms)
downloading https://repo1.maven.org/maven2/org/joda/joda-convert/1.2/joda-convert-1.2.jar ...
  [SUCCESSFUL ] org.joda#joda-convert;1.2!joda-convert.jar (548ms)
:: resolution report :: resolve 11850ms :: artifacts dl 26075ms
  :: modules in use:
  com.github.nscala-time#nscala-time_2.10;1.0.0 from central in [default]
  com.stratio.datasource#spark-mongodb_2.10;0.10.1 from central in [default]
  joda-time#joda-time;2.3 from central in [default]
  org.joda#joda-convert;1.2 from central in [default]
  org.mongodb#casbah-commons_2.10;2.8.0 from central in [default]
  org.mongodb#casbah-core_2.10;2.8.0 from central in [default]
  org.mongodb#casbah-query_2.10;2.8.0 from central in [default]
  org.mongodb#mongo-java-driver;2.13.0 from central in [default]
  org.slf4j#slf4j-api;1.6.0 from central in [default]
  ---------------------------------------------------------------------
  |                  |            modules            ||   artifacts   |
  |       conf       | number| search|dwnlded|evicted|| number|dwnlded|
  ---------------------------------------------------------------------
  |      default     |   9   |   9   |   9   |   0   ||   9   |   9   |
  ---------------------------------------------------------------------
:: retrieving :: org.apache.spark#spark-submit-parent
  confs: [default]
  9 artifacts copied, 0 already retrieved (2335kB/51ms)
... (snip) ... 
```

我们现在准备从数据库`twtr01_db`的集合`twtr01_coll`上的`localhost:27017`查询 MongoDB。

我们首先导入`SQLContext`：

```py
In [5]:
from pyspark.sql import SQLContext
sqlContext.sql("CREATE TEMPORARY TABLE tweet_table USING com.stratio.datasource.mongodb OPTIONS (host 'localhost:27017', database 'twtr01_db', collection 'twtr01_coll')")
sqlContext.sql("SELECT * FROM tweet_table where id=598830778269769728 ").collect()
```

这是我们查询的输出：

```py
Out[5]:
[Row(text=u'@spark_io is now @particle - awesome news - now I can enjoy my Particle Cores/Photons + @sparkfun sensors + @ApacheSpark analytics :-)', _id=u'55aa640fd770871cba74cb88', contributors=None, retweeted=False, user=Row(contributors_enabled=False, created_at=u'Mon Aug 25 14:01:26 +0000 2008', default_profile=True, default_profile_image=False, description=u'Building open source tools for and teaching enterprise software developers', entities=Row(description=Row(urls=[]), url=Row(urls=[Row(url=u'http://t.co/TSHp13EWeu', indices=[0, 22], 

... (snip) ...

 9], name=u'Spark is Particle', screen_name=u'spark_io'), Row(id=487010011, id_str=u'487010011', indices=[17, 26], name=u'Particle', screen_name=u'particle'), Row(id=17877351, id_str=u'17877351', indices=[88, 97], name=u'SparkFun Electronics', screen_name=u'sparkfun'), Row(id=1551361069, id_str=u'1551361069', indices=[108, 120], name=u'Apache Spark', screen_name=u'ApacheSpark')]), is_quote_status=None, lang=u'en', quoted_status_id_str=None, quoted_status_id=None, created_at=u'Thu May 14 12:42:37 +0000 2015', retweeted_status=None, truncated=False, place=None, id=598830778269769728, in_reply_to_user_id=3187046084, retweet_count=0, in_reply_to_status_id=None, in_reply_to_screen_name=u'spark_io', in_reply_to_user_id_str=u'3187046084', source=u'<a href="http://twitter.com" rel="nofollow">Twitter Web Client</a>', id_str=u'598830778269769728', coordinates=None, metadata=Row(iso_language_code=u'en', result_type=u'recent'), quoted_status=None)]
#
```

# 摘要

在本章中，我们从 Twitter 上收集了数据。一旦获取了数据，我们就使用`Continuum.io`的 Blaze 和 Odo 库来探索信息。Spark SQL 是交互式数据探索、分析和转换的重要模块，利用了 Spark dataframe 数据结构。 dataframe 的概念起源于 R，然后被 Python Pandas 成功采用。 dataframe 是数据科学家的得力助手。 Spark SQL 和 dataframe 的结合为数据处理创建了强大的引擎。

我们现在准备利用 Spark MLlib 从数据集中提取洞察。
