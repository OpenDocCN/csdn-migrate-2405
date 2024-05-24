# Spark 数据科学（一）

> 原文：[`zh.annas-archive.org/md5/D6F94257998256DE126905D8038FBE11`](https://zh.annas-archive.org/md5/D6F94257998256DE126905D8038FBE11)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在这个智能时代，数据分析是维持和促进业务增长的关键。每家企业都在尝试尽可能利用他们的数据，借助各种数据科学工具和技术沿着分析成熟度曲线前进。数据科学需求的突然增加是数据科学家短缺的明显原因。很难满足市场需求，因为独角兽数据科学家是统计学、机器学习、数学建模以及编程方面的专家。

独角兽数据科学家的可用性只会随着市场需求的增加而减少，并将继续如此。因此，需要一个解决方案，不仅能够赋予独角兽数据科学家更多的权力，而且还能创造 Gartner 所称的“公民数据科学家”。公民数据科学家不是其他人，而是开发人员、分析师、BI 专业人员或其他主要工作职能不在统计或分析之外，但足够热衷于学习数据科学。他们正在成为组织和整个行业中民主化数据分析的关键推动者。

有越来越多的工具和技术旨在促进大规模的大数据分析。这本书试图创建能够利用 Apache Spark 分布式计算平台进行数据分析的公民数据科学家。

这本书是一个实用指南，教授统计分析和机器学习，以构建可扩展的数据产品。它有助于掌握数据科学的核心概念，以及 Apache Spark，帮助您在任何实际的数据分析项目上快速启动。整本书的每一章都有足够的例子支持，可以在家用电脑上执行，以便读者可以轻松地跟踪和吸收概念。每一章都试图是独立的，以便读者可以从任何章节开始，并指向相关章节以获取详细信息。虽然章节从基础知识开始，供初学者学习和理解，但同时也足够全面，供高级架构师使用。

# 本书内容

第一章, *大数据和数据科学-简介*，本章简要讨论了大数据分析中的各种挑战，以及 Apache Spark 如何在单一平台上解决这些问题。本章还解释了数据分析是如何演变成现在的样子，也对 Spark 堆栈有了基本的了解。

第二章, *Spark 编程模型*，本章讨论了 Apache Spark 的设计考虑和支持的编程语言。它还解释了 Spark 的核心组件，并详细介绍了 RDD API，这是 Spark 的基本构建模块。

第三章, *数据框简介*，本章介绍了数据框，这是数据科学家最方便和有用的组件，可以轻松工作。它解释了 Spark SQL 和 Catalyst 优化器如何赋予数据框权力。还演示了各种数据框操作的代码示例。

第四章, *统一数据访问*，本章讨论了我们从不同来源获取数据的各种方式，以统一的方式 consolide 和工作。它涵盖了实时数据收集和操作的流方面。它还讨论了这些 API 的底层基础知识。

第五章，Spark 上的数据分析，本章讨论了完整的数据分析生命周期。通过大量的代码示例，它解释了如何从不同来源获取数据，使用数据清洗和转换技术准备数据，并进行描述性和推断性统计，以从数据中生成隐藏的见解。

第六章，机器学习，本章解释了各种机器学习算法，它们是如何在 MLlib 库中实现的，以及如何使用流水线 API 进行流畅的执行。本章涵盖了所有算法的基础知识，因此可以作为一个一站式参考。

第七章，使用 SparkR 扩展 Spark，本章主要面向想要利用 Spark 进行数据分析的 R 程序员。它解释了如何使用 SparkR 进行编程以及如何使用 R 库的机器学习算法。

第八章，分析非结构化数据，本章仅讨论非结构化数据分析。它解释了如何获取非结构化数据，处理它并对其进行机器学习。它还涵盖了一些在“机器学习”章节中未涵盖的降维技术。

第九章，可视化大数据，本章介绍了在 Spark 上支持的各种可视化技术。它解释了数据工程师、数据科学家和业务用户的不同可视化需求，并建议了正确的工具和技术。它还讨论了利用 IPython/Jupyter 笔记本和 Zeppelin，这是一个用于数据可视化的 Apache 项目。

第十章，将所有内容放在一起，到目前为止，本书已经分别讨论了不同章节中的大多数数据分析组件。本章是为了将典型的数据科学项目的各个步骤串联起来，并演示一个完整的分析项目执行的逐步方法。

第十一章，构建数据科学应用，到目前为止，本书主要讨论了数据科学组件以及一个完整的执行示例。本章提供了如何构建可以部署到生产环境中的数据产品的概述。它还介绍了 Apache Spark 项目的当前开发状态以及未来的发展方向。

# 您需要什么

在执行本书中提到的代码之前，您的系统必须具有以下软件。但是，并非所有章节都需要所有软件组件：

+   Ubuntu 14.4 或 Windows 7 或更高版本

+   Apache Spark 2.0.0

+   Scala：2.10.4

+   Python 2.7.6

+   R 3.3.0

+   Java 1.7.0

+   Zeppelin 0.6.1

+   Jupyter 4.2.0

+   IPython 内核 5.1

# 这本书适合谁

这本书适用于任何希望利用 Apache Spark 进行数据科学和机器学习的人。如果您是一名技术人员，希望扩展自己的知识以在 Spark 中执行数据科学操作，或者是一名数据科学家，希望了解算法在 Spark 中是如何实现的，或者是一名具有最少开发经验的新手，希望了解大数据分析，那么这本书适合您！

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“当程序在 Spark shell 上运行时，它被称为带有用户`main`方法的驱动程序。”

代码块设置如下：

```scala
Scala> sc.parallelize(List(2, 3, 4)).count()
res0: Long = 3
Scala> sc.parallelize(List(2, 3, 4)).collect()
res1: Array[Int] = Array(2, 3, 4)
Scala> sc.parallelize(List(2, 3, 4)).first()
res2: Int = 2
Scala> sc.parallelize(List(2, 3, 4)).take(2)
res3: Array[Int] = Array(2, 3)
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“它还允许用户使用**数据源 API**从不受支持的数据源（例如 CSV，Avro HBase，Cassandra 等）中获取数据。”

### 注意

警告或重要提示会以这样的方式显示在框中。

### 提示

提示和技巧会显示为这样。


# 第一章：大数据和数据科学-介绍

*大数据绝对是一件大事！*它承诺通过从庞大的数据堆中获取隐藏的见解，并开辟新的业务发展途径，为组织创造和保持竞争优势提供了丰富的机会。通过先进的分析技术利用大数据已经成为组织的必然选择。

本章解释了大数据的全部内容，大数据分析的各种挑战，以及 Apache Spark 如何成为解决计算挑战的事实标准，并且还作为数据科学平台。

本章涵盖的主题如下：

+   大数据概述-为什么如此重要？

+   大数据分析的挑战-为什么如此困难？

+   大数据分析的演变-数据分析趋势

+   数据分析的 Spark-解决大数据挑战的解决方案

+   Spark 堆栈-构成完整大数据解决方案的一切

# 大数据概述

关于大数据已经有很多言论和文章，但没有明确的标准来清晰地定义它。在某种程度上，这实际上是一个相对的术语。无论数据是小还是大，只有当你能够正确地分析它时，你才能利用它。为了从数据中得出一些意义，需要正确的分析技术，并且在数据分析中选择正确的工具和技术至关重要。然而，当数据本身成为问题的一部分，并且在执行数据分析之前需要解决计算挑战时，它就成为了一个大数据问题。

在万维网上发生了一场革命，也被称为 Web 2.0，改变了人们使用互联网的方式。静态网页变成了互动网站，并开始收集越来越多的数据。云计算、社交媒体和移动计算的技术进步创造了数据爆炸。每个数字设备开始发出数据，许多其他来源开始驱动数据洪流。来自各个角落的数据流产生了各种大量的数据，速度之快！以这种方式形成大数据是一种自然现象，因为这就是万维网的演变方式，没有明确的特定努力。这是关于过去的事情！如果考虑到正在发生的变化，以及未来将会发生的变化，数据生成的数量和速度超出了人们的预期。我之所以要做出这样的表态，是因为如今每个设备都变得更加智能，这要感谢物联网（IoT）。

IT 趋势是技术进步也促进了数据爆炸。随着更便宜的在线存储集群和廉价的通用硬件的出现，数据存储经历了一次范式转变。将来自不同来源的数据以其原生形式存储在单一数据湖中，迅速取代了精心设计的数据集市和数据仓库。使用模式也从严格的基于模式的 RDBMS 方法转变为无模式、持续可用的 NoSQL 数据存储驱动的解决方案。因此，无论是结构化、半结构化还是非结构化的数据创建速度都加速了前所未有的速度。

组织非常确信，利用大数据不仅可以回答特定的业务问题，还可以带来机会，以覆盖业务中未发现的可能性，并解决与此相关的不确定性。因此，除了自然的数据涌入外，组织开始制定策略，产生越来越多的数据，以保持其竞争优势并做好未来准备。举个例子来更好地理解这一点。想象一下，在制造工厂的机器上安装了传感器，这些传感器不断地发出数据，因此可以得知机器零部件的状态，公司能够预测机器何时会发生故障。这让公司能够预防故障或损坏，避免计划外停机，从而节省大量资金。

# 大数据分析的挑战

在大数据分析中，主要存在两种类型的严峻挑战。第一个挑战是需要一个庞大的计算平台，一旦建立起来，第二个挑战就是在规模上分析和理解大量数据。

## 计算挑战

随着数据量的增加，大数据的存储需求也越来越大。数据管理变成了一项繁琐的任务。尽管处理器的处理速度和 RAM 的频率达到了标准，但由于寻道时间导致的访问磁盘存储的延迟成为了主要瓶颈。

从各种业务应用程序和数据孤岛中提取结构化和非结构化数据，对其进行整合并加工以找到有用的业务见解是具有挑战性的。只有少数应用程序能够解决任何一个领域，或者只能解决少数多样化的业务需求。然而，将这些应用程序集成在一起以统一方式解决大部分业务需求只会增加复杂性。

为了解决这些挑战，人们转向了具有分布式文件系统的分布式计算框架，例如 Hadoop 和**Hadoop 分布式文件系统**（**HDFS**）。这可以消除由于磁盘 I/O 而产生的延迟，因为数据可以在机器集群上并行读取。

分布式计算技术在之前已存在几十年，但直到行业意识到大数据的重要性后才变得更加突出。因此，诸如 Hadoop 和 HDFS 或 Amazon S3 之类的技术平台成为了行业标准。除了 Hadoop 之外，还开发了许多其他解决方案，如 Pig、Hive、Sqoop 等，以满足不同类型的行业需求，如存储、**提取、转换和加载**（**ETL**）以及数据集成，从而使 Hadoop 成为一个统一的平台。

## 分析挑战

分析数据以发现一些隐藏的见解一直是具有挑战性的，因为处理大型数据集涉及到额外的复杂性。传统的 BI 和 OLAP 解决方案无法解决由大数据带来的大部分挑战。举个例子，如果数据集有多个维度，比如 100 个，那么很难将这些变量相互比较以得出结论，因为会有大约 100C2 种组合。这种情况需要使用统计技术，如*相关性*等，来发现隐藏的模式。

尽管许多问题都有统计解决方案，但对于数据科学家或分析专业人员来说，除非他们将整个数据集加载到内存中的**DataFrame**中，否则很难对数据进行切片和切块以找到智能洞见。主要障碍在于，大多数用于统计分析和机器学习的通用算法都是单线程的，并且是在数据集通常不那么庞大且可以适应单台计算机的 RAM 中编写的时代编写的。这些用 R 或 Python 编写的算法在原始形式上在分布式计算环境中部署时不再非常有用，因为存在内存计算的限制。

为了解决这一挑战，统计学家和计算机科学家不得不共同努力，重写大部分算法，使其在分布式计算环境中能够良好运行。因此，在 Hadoop 上开发了一个名为**Mahout**的库，用于机器学习算法的并行处理。它包含了行业中经常使用的大多数常见算法。其他分布式计算框架也采取了类似的举措。

# 大数据分析的演变

前一节概述了如何解决大数据需求的计算和数据分析挑战。这是可能的，因为多个相关趋势的融合，如低成本的通用硬件、大数据的可访问性和改进的数据分析技术。Hadoop 成为许多大型分布式数据处理基础设施的基石。

然而，人们很快意识到 Hadoop 的局限性。Hadoop 解决方案最适合特定类型的大数据需求，如 ETL；它只在这些需求中才变得流行。

有时数据工程师或分析师需要对数据集执行即席查询进行交互式数据分析。每次在 Hadoop 上运行查询时，数据都会从磁盘（HDFS 读取）读取并加载到内存中，这是一项昂贵的工作。实际上，作业的运行速度取决于网络和磁盘集群上的 I/O 传输速度，而不是 CPU 和 RAM 的速度。

以下是情景的图示表示：

![大数据分析的演变](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_01_001.jpg)

Hadoop 的 MapReduce 模型无法很好地适应迭代性质的机器学习算法。Hadoop MapReduce 在迭代计算中性能不佳，延迟巨大。由于 Map 和 Reduce 工作者之间禁止通信的受限编程模型，中间结果需要存储在稳定的存储器中。因此，这些结果被推送到 HDFS，然后写入磁盘，而不是保存在 RAM 中，然后在后续迭代中重新加载到内存中，其他迭代也是如此。磁盘 I/O 的数量取决于算法中涉及的迭代次数，这还伴随着在保存和加载数据时的序列化和反序列化开销。总的来说，这是计算昂贵的，与预期相比，并没有达到预期的受欢迎程度。

以下是这种情景的图示表示：

![大数据分析的演变](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_01_002.jpg)

为了解决这个问题，开发了定制解决方案，例如谷歌的 Pregel，这是一种迭代图处理算法，针对进程间通信和中间结果的内存存储进行了优化，以使其运行更快。类似地，还开发或重新设计了许多其他解决方案，以最好地满足一些特定的算法使用的特定需求。

不需要重新设计所有算法，而是需要一个通用引擎，大多数算法可以利用它在分布式计算平台上进行内存计算。人们也期望这样的设计会导致迭代计算和临时数据分析的更快执行。这就是 Spark 项目在加州大学伯克利分校的 AMPLab 中开辟道路的方式。

# 用于数据分析的 Spark

在 AMPLab 中，Spark 项目成功之后，它于 2010 年开源，并于 2013 年转移到 Apache 软件基金会。目前由 Databricks 领导。

Spark 相对于其他分布式计算平台具有许多明显的优势，例如：

+   用于迭代机器学习和交互式数据分析的更快执行平台

+   用于批处理、SQL 查询、实时流处理、图处理和复杂数据分析的单一堆栈

+   通过隐藏分布式编程的复杂性，提供高级 API 来开发各种分布式应用程序

+   对各种数据源的无缝支持，如 RDBMS、HBase、Cassandra、Parquet、MongoDB、HDFS、Amazon S3 等

![用于数据分析的 Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_01_003.jpg)

以下是迭代算法的内存数据共享的图示表示：

![用于数据分析的 Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_01_004.jpg)

Spark 隐藏了编写核心 MapReduce 作业的复杂性，并通过简单的函数调用提供了大部分功能。由于其简单性，它能够满足更广泛和更大的受众群体，如数据科学家、数据工程师、统计学家和 R/Python/Scala/Java 开发人员。

Spark 架构主要包括数据存储层、管理框架和 API。它旨在在 HDFS 文件系统之上工作，并因此利用现有的生态系统。部署可以作为独立服务器或在诸如 Apache Mesos 或 YARN 之类的分布式计算框架上进行。提供了 Scala 的 API，这是 Spark 编写的语言，以及 Java、R 和 Python。

# Spark 堆栈

Spark 是一个通用的集群计算系统，它赋予其他更高级别的组件利用其核心引擎的能力。它与 Apache Hadoop 是可互操作的，可以从 HDFS 读取和写入数据，并且还可以与 Hadoop API 支持的其他存储系统集成。

虽然它允许在其上构建其他更高级的应用程序，但它已经在其核心之上构建了一些组件，这些组件与其核心引擎紧密集成，以利用核心的未来增强。这些应用程序与 Spark 捆绑在一起，以满足行业中更广泛的需求。大多数现实世界的应用程序需要在项目之间进行集成，以解决通常具有一组要求的特定业务问题。Apache Spark 可以简化这一点，因为它允许其更高级别的组件无缝集成，例如在开发项目中的库。

此外，由于 Spark 内置支持 Scala、Java、R 和 Python，更广泛的开发人员和数据工程师能够利用整个 Spark 堆栈：

![Spark 堆栈](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_01_005.jpg)

## Spark 核心

Spark 核心在某种程度上类似于操作系统的内核。它是通用执行引擎，既快速又容错。整个 Spark 生态系统都是建立在这个核心引擎之上的。它主要设计用于作业调度、任务分发和跨工作节点的作业监控。它还负责内存管理，与各种异构存储系统的交互以及各种其他操作。

Spark 核心的主要构建模块是**弹性分布式数据集**（**RDD**），它是一个不可变的、容错的元素集合。Spark 可以从各种数据源（如 HDFS、本地文件系统、Amazon S3、其他 RDD、Cassandra 等 NoSQL 数据存储）创建 RDD。它们在失败时会自动重建，因此具有容错性。RDD 是通过惰性并行转换构建的。它们可以被缓存和分区，也可以或者不可以被实现。

整个 Spark 核心引擎可以被视为对分布式数据集进行简单操作的集合。Spark 中所有作业的调度和执行都是基于与每个 RDD 相关联的方法完成的。此外，与每个 RDD 相关联的方法定义了它们自己的分布式内存计算方式。

## Spark SQL

这个 Spark 模块旨在查询、分析和对结构化数据执行操作。这是整个 Spark 堆栈中非常重要的一个组件，因为大多数组织数据都是结构化的，尽管非结构化数据正在迅速增长。作为一个分布式查询引擎，它使 Hadoop Hive 查询在不进行任何修改的情况下可以运行得更快，最多可以提高 100 倍。除了 Hive，它还支持 Apache Parquet（一种高效的列存储）、JSON 和其他结构化数据格式。Spark SQL 使得可以在 Python、Scala 和 Java 中运行 SQL 查询以及复杂程序。

Spark SQL 提供了一个名为**数据框**的分布式编程抽象，之前称为 SchemaRDD，它的相关函数较少。数据框是命名列的分布式集合，类似于 SQL 表或 Python 的 Pandas 数据框。它们可以使用具有模式的各种数据源构建，例如 Hive、Parquet、JSON、其他 RDBMS 源，以及 Spark RDD。

Spark SQL 可用于跨不同格式的 ETL 处理，然后进行临时分析。Spark SQL 配备了一个名为 Catalyst 的优化器框架，可以将 SQL 查询转换为更高效的形式。

## Spark 流处理

企业数据的处理窗口正在变得比以往任何时候都要短。为了满足行业的实时处理需求，设计了 Spark 的这个组件，它既具有容错性又可扩展。Spark 通过支持对实时数据流进行数据分析、机器学习和图处理，实现了对实时数据流的实时数据分析。

它提供了一个名为**离散流**（**DStream**）的 API，用于操作实时数据流。实时数据流被切分成小批次，比如说，*x*秒。Spark 将每个批次视为 RDD 并对它们进行基本的 RDD 操作。DStreams 可以从 HDFS、Kafka、Flume 或任何其他能够通过 TCP 套接字流式传输数据的源创建出来。通过在 DStreams 上应用一些高级操作，可以产生其他 DStreams。

Spark 流处理的最终结果可以被写回到 Spark 支持的各种数据存储中，也可以被推送到任何仪表板进行可视化。

## MLlib

MLlib 是 Spark 堆栈中内置的机器学习库。它是在 Spark 0.8 中引入的。其目标是使机器学习变得可扩展和简单。开发人员可以无缝地在他们选择的编程语言（Java、Python 或 Scala）中使用 Spark SQL、Spark 流处理和 GraphX。MLlib 提供了执行各种统计分析（如相关性、抽样、假设检验等）所需的函数。此组件还涵盖了分类、回归、协同过滤、聚类和分解等领域的广泛应用和算法。

机器学习工作流程涉及收集和预处理数据，构建和部署模型，评估结果和改进模型。在现实世界中，预处理步骤需要大量的工作。这些通常是涉及昂贵的中间读/写操作的多阶段工作流程。通常情况下，这些处理步骤可能会在一段时间内多次执行。引入了一个新概念**ML Pipelines**来简化这些预处理步骤。管道是一个转换序列，其中一个阶段的输出是另一个阶段的输入，形成一个链。ML Pipeline 利用了 Spark 和 MLlib，使开发人员能够定义可重用的转换序列。

## GraphX

GraphX 是 Spark 上的一个薄层统一图分析框架。它旨在成为一个通用的分布式数据流框架，取代专门的图处理框架。它具有容错性，并且利用了内存计算。

GraphX 是一个嵌入式图处理 API，用于操作图（例如社交网络）和进行图并行计算（例如 Google 的 Pregel）。它结合了 Spark 堆栈上图并行和数据并行系统的优势，统一了探索性数据分析、迭代图计算和 ETL 处理。它扩展了 RDD 抽象，引入了**Resilient Distributed Graph**（**RDG**），这是一个带有每个顶点和边属性的有向图。

GraphX 包括大量的图算法，如 PageRank、K-Core、Triangle Count、LDA 等。

## SparkR

SparkR 项目旨在将 R 的统计分析和机器学习能力与 Spark 的可伸缩性相结合。它解决了 R 的局限性，即其能够处理的数据量受限于单台机器的内存。现在，R 程序可以通过 SparkR 在分布式环境中扩展。

SparkR 实际上是一个 R 包，提供了一个 R shell 来利用 Spark 的分布式计算引擎。借助 R 丰富的内置数据分析包，数据科学家可以交互式地分析大型数据集。

# 总结

在本章中，我们简要介绍了大数据的概念。然后，我们讨论了大数据分析中涉及的计算和分析挑战。后来，我们看了一下大数据背景下分析领域是如何随着时间的推移而发展的，趋势是什么。我们还介绍了 Spark 如何解决了大部分大数据分析挑战，并成为了数据科学和并行计算的通用统一分析平台。在本章的结尾，我们简要介绍了 Spark 堆栈及其组件。

在下一章中，我们将学习 Spark 编程模型。我们将深入了解 Spark 的基本构建块，即 RDD。此外，我们将学习如何在 Scala 和 Python 上使用 RDD API 进行编程。

# 参考资料

Apache Spark 概述：

+   [`spark.apache.org/docs/latest/`](http://spark.apache.org/docs/latest/)

+   [`databricks.com/spark/about`](https://databricks.com/spark/about)

Apache Spark 架构：

+   [`lintool.github.io/SparkTutorial/slides/day1_context.pdf`](http://lintool.github.io/SparkTutorial/slides/day1_context.pdf)


# 第二章：Spark 编程模型

大规模数据处理使用数千个具有内置容错能力的节点已经变得普遍，这是由于开源框架的可用性，Hadoop 是一个受欢迎的选择。这些框架在执行特定任务（如**提取、转换和加载**（**ETL**）以及处理网络规模数据的存储应用程序）方面非常成功。然而，开发人员在使用这些框架时需要使用大量的工具，以及成熟的 Hadoop 生态系统。需要一个单一的、通用的开发平台，满足批处理、流式处理、交互式和迭代式需求。这就是 Spark 背后的动机。

上一章概述了大数据分析的挑战，以及 Spark 在很高的层次上解决了大部分问题。在本章中，我们将深入研究 Spark 的设计目标和选择，以更清楚地了解其作为大数据科学平台的适用性。我们还将深入介绍核心抽象**弹性分布式数据集**（**RDD**）并提供示例。

在本章之前，需要基本了解 Python 或 Scala 以及对 Spark 的初步了解。本章涵盖的主题如下：

+   编程范式 - 语言支持和设计优势

+   支持的编程语言

+   选择正确的语言

+   Spark 引擎 - Spark 核心组件及其影响

+   驱动程序

+   Spark shell

+   SparkContext

+   工作节点

+   执行器

+   共享变量

+   执行流程

+   RDD API - 理解 RDD 基础

+   RDD 基础

+   持久性

+   RDD 操作 - 让我们动手做

+   开始使用 shell

+   创建 RDD

+   对普通 RDD 的转换

+   对成对 RDD 的转换

+   操作

# 编程范式

为了解决大数据挑战并作为数据科学和其他可扩展应用程序的平台，Spark 在设计时考虑周全，并提供了语言支持。

Spark 提供了专为各种应用程序开发人员设计的 API，使用标准 API 接口创建基于 Spark 的应用程序。Spark 提供了 Scala、Java、R 和 Python 编程语言的 API，如下节所述。

## 支持的编程语言

Spark 内置对多种语言的支持，可以通过一个称为**读取-求值-打印-循环**（**REPL**）的 shell 进行交互式使用，这对任何语言的开发人员来说都会感到熟悉。开发人员可以使用他们选择的语言，利用现有的库，并与 Spark 及其生态系统无缝交互。让我们看看 Spark 支持的语言以及它们如何适应 Spark 生态系统。

### Scala

Spark 本身是用 Scala 编写的，Scala 是一种基于**Java 虚拟机**（**JVM**）的函数式编程语言。Scala 编译器生成的字节码在 JVM 上执行。因此，它可以与任何其他基于 JVM 的系统（如 HDFS、Cassandra、HBase 等）无缝集成。Scala 是首选语言，因为它具有简洁的编程接口、交互式 shell 以及捕获函数并有效地在集群中的节点之间传输的能力。Scala 是一种可扩展（可伸缩，因此得名）、静态类型的、高效的多范式语言，支持函数式和面向对象的语言特性。

除了完整的应用程序外，Scala 还支持 shell（Spark shell），用于在 Spark 上进行交互式数据分析。

### Java

由于 Spark 是基于 JVM 的，它自然地支持 Java。这有助于现有的 Java 开发人员开发数据科学应用程序以及其他可扩展的应用程序。几乎所有内置库函数都可以从 Java 中访问。在 Spark 中使用 Java 进行数据科学任务的编码相对困难，但对 Java 非常熟悉的人可能会觉得很容易。

这个 Java API 只缺少一个基于 shell 的接口，用于在 Spark 上进行交互式数据分析。

### Python

Python 通过 PySpark 在 Spark 上得到支持，它是建立在 Spark 的 Java API（使用 Py4J）之上的。从现在开始，我们将使用术语**PySpark**来指代 Spark 上的 Python 环境。Python 在数据整理、数据处理和其他数据科学相关任务方面已经非常受开发人员欢迎。随着 Spark 能够解决可伸缩计算的挑战，对 Python 在 Spark 上的支持变得更加流行。

通过 Python 在 Spark 上的交互式 shell（PySpark），可以进行大规模的交互式数据分析。

### R

R 通过 SparkR 支持 Spark，这是一个 R 包，通过它可以通过 R 访问 Spark 的可伸缩性。SparkR 使 R 能够解决单线程运行时的限制，因此计算仅限于单个节点。

由于 R 最初只设计用于统计分析和机器学习，它已经丰富了大部分的包。数据科学家现在可以在大规模数据上工作，学习曲线很小。R 仍然是许多数据科学家的首选。

## 选择合适的语言

除了开发人员的语言偏好之外，有时还有其他约束条件可能会引起注意。在选择一种语言而不是另一种语言时，以下方面可能会补充您的开发经验：

+   在开发复杂逻辑时，交互式 shell 非常方便。除了 Java 之外，Spark 支持的所有语言都有交互式 shell。

+   R 是数据科学家的通用语言。由于其更丰富的库集，它绝对更适合纯数据分析。R 支持是在 Spark 1.4.0 中添加的，以便 Spark 能够接触到使用 R 的数据科学家。

+   Java 拥有更广泛的开发人员基础。Java 8 已经包含了 lambda 表达式，因此具有函数式编程方面。尽管如此，Java 往往冗长。

+   Python 在数据科学领域逐渐变得更受欢迎。Pandas 和其他数据处理库的可用性，以及其简单和表达性的特性，使 Python 成为一个强有力的选择。Python 在数据聚合、数据清洗、自然语言处理等方面比 R 更灵活。

+   Scala 可能是实时分析的最佳选择，因为它与 Spark 最接近。对于来自其他语言的开发人员来说，初始学习曲线不应成为严重生产系统的障碍。Spark 的最新增加通常首先在 Scala 中可用。其静态类型和复杂的类型推断提高了效率以及编译时检查。Scala 可以利用 Java 的库，因为 Scala 自己的库基础仍处于早期阶段，但正在迎头赶上。

# Spark 引擎

要使用 Spark 进行编程，需要对 Spark 组件有基本的了解。在本节中，将解释一些重要的 Spark 组件以及它们的执行机制，以便开发人员和数据科学家可以编写程序和构建应用程序。

在深入细节之前，我们建议您查看以下图表，以便在阅读更多内容时更容易理解 Spark 齿轮的描述：

![The Spark engine](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_02_001.jpg)

## 驱动程序

Spark shell 是驱动程序的一个示例。驱动程序是在 JVM 中执行并在其上运行用户的*main*函数的进程。它具有一个 SparkContext 对象，它是与底层集群管理器的连接。驱动程序启动时启动 Spark 应用程序，并在驱动程序停止时完成。通过 SparkContext 的实例，驱动程序协调 Spark 应用程序中的所有进程。

主要是在驱动程序端使用数据源（可能是 RDD）和转换构建 RDD 谱系有向无环图（DAG）。当遇到*action*方法时，此 DAG 被提交给 DAG 调度程序。然后 DAG 调度程序将 DAG 拆分为逻辑工作单元（例如 map 或 reduce）称为阶段。每个阶段又是一组任务，每个任务由任务调度程序分配给执行者（工作节点）。作业可以按 FIFO 顺序或循环顺序执行，具体取决于配置。

### 提示

在单个 Spark 应用程序中，如果从不同的线程提交，多个并行作业可以同时运行。

## Spark shell

Spark shell 实际上就是由 Scala 和 Python 提供的接口。它看起来非常类似于任何其他交互式 shell。它有一个 SparkContext 对象（默认为您创建），让您利用分布式集群。交互式 shell 非常适用于探索性或临时分析。您可以通过 shell 逐步开发复杂的脚本，而无需经历编译-构建-执行的周期。

## SparkContext

SparkContext 是 Spark 核心引擎的入口点。此对象用于在集群上创建和操作 RDD，并创建共享变量。SparkContext 对象连接到负责资源分配的集群管理器。Spark 自带其自己的独立集群管理器。由于集群管理器在 Spark 中是可插拔的组件，因此可以通过外部集群管理器（如 Apache Mesos 或 YARN）进行管理。

当启动 Spark shell 时，默认会为您创建一个 SparkContext 对象。您也可以通过传递一个用于设置各种 Spark 配置参数的 SparkConf 对象来创建它。请注意，在一个 JVM 中只能有一个 SparkContext 对象。

## 工作节点

工作节点是在集群中运行应用程序代码的节点，遵循驱动程序。实际工作实际上是由工作节点执行的。集群中的每台机器可能有一个或多个工作实例（默认一个）。工作节点执行属于一个或多个 Spark 应用程序的一个或多个执行者。它包括一个*块管理器*组件，负责管理数据块。这些块可以是缓存的 RDD 数据、中间洗牌数据或广播数据。当可用的 RAM 不足时，它会自动将一些数据块移动到磁盘上。块管理器的另一个责任是在节点之间复制数据。

## 执行者

每个应用程序都有一组执行者进程。执行者驻留在工作节点上，并一旦由集群管理器建立连接，就直接与驱动程序通信。所有执行者都由 SparkContext 管理。执行者是一个单独的 JVM 实例，为单个 Spark 应用程序提供服务。执行者负责通过任务、存储和缓存在每个工作节点上管理计算。它可以同时运行多个任务。

## 共享变量

通常，代码会与变量的单独副本一起传输到分区。这些变量不能用于将结果（例如中间工作计数）传播回驱动程序。共享变量用于此目的。共享变量有两种，即**广播变量**和**累加器**。

广播变量使程序员能够保留只读副本，而不是将其与任务一起传输到每个节点。如果大型只读数据在多个操作中使用，可以将其指定为广播变量，并且只传输一次到所有工作节点。以这种方式广播的数据以序列化形式缓存，并在运行每个任务之前进行反序列化。后续操作可以访问这些变量以及与代码一起移动的本地变量。在所有情况下都不需要创建广播变量，除非跨多个阶段的任务需要相同的只读数据副本。

累加器是始终递增的变量，例如计数器或累积和。Spark 本身支持数值类型的累加器，但允许程序员为新类型添加支持。请注意，工作节点无法读取累加器的值；它们只能修改它们的值。

## 执行流程

一个 Spark 应用程序由一个*驱动*程序和多个*工作*(*执行器*)程序组成。驱动程序包含应用程序的*main*函数和一个代表与 Spark 集群的连接的 SparkContext 对象。驱动程序和其他进程之间的协调通过 SparkContext 对象进行。

典型的 Spark 客户端程序执行以下步骤：

1.  当程序在 Spark shell 上运行时，它被称为驱动程序，其中包含用户的`main`方法。它在运行驱动程序的系统的 JVM 中执行。

1.  第一步是使用所需的配置参数创建一个 SparkContext 对象。当您运行 PySpark 或 Spark shell 时，默认情况下会实例化它，但对于其他应用程序，您必须显式创建它。SparkContext 实际上是通往 Spark 的入口。

1.  下一步是定义一个或多个 RDD，可以通过加载文件或通过以并行集合引用项目数组来以编程方式定义

1.  然后，更多的 RDD 可以通过一系列的转换来定义，这些转换由一个**血统图**跟踪和管理。这些 RDD 转换可以被视为管道 UNIX 命令，其中一个命令的输出成为下一个命令的输入，依此类推。每个*转换*步骤的结果 RDD 都有一个指向其父 RDD 的指针，并且还有一个用于计算其数据的函数。只有在遇到*操作*语句后，RDD 才会被执行。因此，*转换*是用于定义新 RDD 的惰性操作，而*操作*会启动计算以将值返回给程序或将数据写入外部存储。我们将在接下来的部分中更详细地讨论这一方面。

1.  在这个阶段，Spark 创建一个执行图，其中节点表示 RDD，边表示转换步骤。Spark 将作业分解为多个任务在单独的机器上运行。这就是 Spark 如何在集群中的节点之间发送**计算**，而不是将所有数据聚集在一起进行计算。

# RDD API

RDD 是一个只读的、分区的、容错的记录集合。从设计的角度来看，需要一个单一的数据结构抽象，隐藏处理各种各样的数据源的复杂性，无论是 HDFS、文件系统、RDBMS、NOSQL 数据结构还是任何其他数据源。用户应该能够从这些源中定义 RDD。目标是支持各种操作，并让用户以任何顺序组合它们。

## RDD 基础

每个数据集在 Spark 的编程接口中表示为一个名为 RDD 的对象。Spark 提供了两种创建 RDD 的方式。一种方式是并行化现有集合。另一种方式是引用外部存储系统中的数据集，例如文件系统。

一个 RDD 由一个或多个数据源组成，可能经过一系列的转换，包括几个操作符。每个 RDD 或 RDD 分区都知道如何在发生故障时重新创建自己。它具有转换的日志，或者是从稳定存储或另一个 RDD 重新创建自己所需的*血统*。因此，使用 Spark 的任何程序都可以确保具有内置的容错性，而不管底层数据源和 RDD 的类型如何。

RDD 上有两种方法可用：转换和操作。转换是用于创建 RDD 的方法。操作是利用 RDD 的方法。RDD 通常是分区的。用户可以选择持久化 RDD，以便在程序中重复使用。

RDD 是不可变（只读）的数据结构，因此任何转换都会创建一个新的 RDD。转换是懒惰地应用的，只有当对它们应用任何操作时，而不是在定义 RDD 时。除非用户明确将 RDD 持久化在内存中，否则每次在操作中使用 RDD 时都会重新计算 RDD。保存在内存中可以节省大量时间。如果内存不足以容纳整个 RDD，剩余部分将自动存储（溢出）到硬盘上。懒惰转换的一个优点是可以优化转换步骤。例如，如果操作是返回第一行，Spark 只计算一个分区并跳过其余部分。

RDD 可以被视为一组分区（拆分），具有对父 RDD 的依赖关系列表和一个计算分区的函数。有时，父 RDD 的每个分区被单个子 RDD 使用。这被称为*窄依赖*。窄依赖是可取的，因为当父 RDD 分区丢失时，只需要重新计算一个子分区。另一方面，计算涉及*group-by-keys*等操作的单个子 RDD 分区依赖于多个父 RDD 分区。每个父 RDD 分区的数据依次用于创建多个子 RDD 分区的数据。这样的依赖被称为*宽依赖*。在窄依赖的情况下，可以将父 RDD 分区和子 RDD 分区都保留在单个节点上（共同分区）。但在宽依赖的情况下是不可能的，因为父数据分散在多个分区中。在这种情况下，数据应该在分区之间*洗牌*。数据洗牌是一个资源密集型的操作，应尽量避免。宽依赖的另一个问题是，即使丢失一个父 RDD 分区，所有子 RDD 分区也需要重新计算。

## 持久性

RDD 在每次通过操作方法进行操作时都是即时计算的。开发人员有能力覆盖这种默认行为，并指示在分区之间*持久化*或*缓存*数据集。如果这个数据集需要参与多个操作，那么持久化可以节省大量的时间、CPU 周期、磁盘 I/O 和网络带宽。容错机制也适用于缓存分区。当任何分区由于节点故障而丢失时，它将使用一个血统图进行重新计算。如果可用内存不足，Spark 会优雅地将持久化的分区溢出到磁盘上。开发人员可以使用*unpersist*来删除不需要的 RDD。然而，Spark 会自动监视缓存，并使用**最近最少使用**（**LRU**）算法删除旧的分区。

### 提示

`Cache()`与`persist()`或`persist(MEMORY_ONLY)`相同。虽然`persist()`方法可以有许多其他参数用于不同级别的持久性，比如仅内存、内存和磁盘、仅磁盘等，但`cache()`方法仅设计用于在内存中持久化。

# RDD 操作

Spark 编程通常从选择一个合适的接口开始，这取决于您的熟练程度。如果您打算进行交互式数据分析，那么 shell 提示符将是显而易见的选择。然而，选择 Python shell（PySpark）或 Scala shell（Spark-Shell）在某种程度上取决于您对这些语言的熟练程度。如果您正在构建一个完整的可扩展应用程序，那么熟练程度就非常重要，因此您应该选择 Scala、Java 和 Python 中的一种语言来开发应用程序，并将其提交给 Spark。我们将在本书的后面更详细地讨论这个方面。

## 创建 RDDs

在本节中，我们将使用 Python shell（PySpark）和 Scala shell（Spark-Shell）来创建一个 RDD。这两个 shell 都有一个预定义的、解释器感知的 SparkContext，分配给一个名为`sc`的变量。

让我们从一些简单的代码示例开始。请注意，代码假定当前工作目录是 Spark 的主目录。以下代码片段启动了 Spark 交互式 shell，从本地文件系统读取文件，并打印该文件的第一行：

**Python**:

```scala
> bin/pyspark  // Start pyspark shell  
>>> _         // For simplicity sake, no Log messages are shown here 

>>> type(sc)    //Check the type of Predefined SparkContext object 
<class 'pyspark.context.SparkContext'> 

//Pass the file path to create an RDD from the local file system 
>>> fileRDD = sc.textFile('RELEASE') 

>>> type(fileRDD)  //Check the type of fileRDD object  
<class 'pyspark.rdd.RDD'> 

>>>fileRDD.first()   //action method. Evaluates RDD DAG and also returns the first item in the RDD along with the time taken 
took 0.279229 s 
u'Spark Change Log' 

```

**Scala**:

```scala
> bin/Spark-Shell  // Start Spark-shell  
Scala> _      // For simplicity sake, no Log messages are shown here 

Scala> sc   //Check the type of Predefined SparkContext object 
res1: org.apache.spark.SparkContext = org.apache.spark.SparkContext@70884875 

//Pass the file path to create an RDD from the local file system 

Scala> val fileRDD = sc.textFile("RELEASE") 

Scala> fileRDD  //Check the type of fileRDD object  
res2: org.apache.spark.rdd.RDD[String] = ../ RELEASE
MapPartitionsRDD[1] at textFile at <console>:21 

Scala>fileRDD.first()   //action method. Evaluates RDD DAG and also returns the first item in the RDD along with the time taken 
0.040965 s 
res6: String = Spark Change Log 

```

在前面的两个例子中，第一行已经调用了交互式 shell。SparkContext 变量`sc`已经按预期定义。我们已经创建了一个名为`fileRDD`的 RDD，指向一个名为`RELEASE`的文件。这个语句只是一个转换，直到遇到一个动作才会被执行。你可以尝试给一个不存在的文件名，但直到执行下一个语句（也就是一个*动作*语句）时才会得到任何错误。

我们已经完成了启动 Spark 应用程序（shell）、创建 RDD 和消耗它的整个循环。由于 RDD 在执行动作时每次都会重新计算，`fileRDD`没有被持久化在内存或硬盘上。这使得 Spark 能够优化步骤序列并智能地执行。实际上，在前面的例子中，优化器可能只读取了输入文件的一个分区，因为`first()`不需要完整的文件扫描。

请记住，创建 RDD 有两种方式：一种是创建一个指向数据源的指针，另一种是并行化一个现有的集合。前面的例子涵盖了一种方式，即从存储系统加载文件。现在我们将看到第二种方式，即并行化现有集合。通过传递内存中的集合来创建 RDD 是简单的，但对于大型集合可能效果不佳，因为输入集合应该完全适合驱动节点的内存。

以下示例通过使用`parallelize`函数传递 Python/Scala 列表来创建一个 RDD：

**Python**:

```scala
// Pass a Python collection to create an RDD 
>>> numRDD = sc.parallelize([1,2,3,4],2) 
>>> type(numRDD) 
<class 'pyspark.rdd.RDD'> 
>>> numRDD 
ParallelCollectionRDD[1] at parallelize at PythonRDD.scala:396 
>>> numRDD.first() 
1 
>>> numRDD.map(lambda(x) : x*x).collect() 
[1,4,9,16] 
>>> numRDD.map(lambda(x) : x * x).reduce(lambda a,b: a+b) 
30 

```

### 提示

Lambda 函数是一个无名函数，通常用作其他函数的函数参数。Python lambda 函数只能是一个单一表达式。如果你的逻辑需要多个步骤，创建一个单独的函数并在 lambda 表达式中使用它。

**Scala**:

```scala
// Pass a Scala collection to create an RDD 
Scala> val numRDD = sc.parallelize(List(1,2,3,4),2) 
numRDD: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[8] at parallelize at <console>:21 

Scala> numRDD 
res15: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[8] at parallelize at <console>:21 

Scala> numRDD.first() 
res16: Int = 1 

Scala> numRDD.map(x => x*x).collect() 
res2: Array[Int] = Array(1, 4, 9, 16) 

Scala> numRDD.map(x => x * x).reduce(_+_) 
res20: Int = 30 

```

正如我们在前面的例子中看到的，我们能够传递一个 Scala/Python 集合来创建一个 RDD，并且我们也有自由来指定将这些集合切分成的分区数。Spark 对集群的每个分区运行一个任务，因此必须仔细决定以优化计算工作。虽然 Spark 根据集群自动设置分区数，但我们可以通过将其作为`parallelize`函数的第二个参数手动设置（例如，`sc.parallelize(data, 3)`）。以下是一个 RDD 的图形表示，它是使用一个包含 14 条记录（或元组）的数据集创建的，并且被分区为 3 个，分布在 3 个节点上：

![创建 RDDs](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/1-1.jpg)

编写 Spark 程序通常包括转换和动作。转换是延迟操作，定义了如何构建 RDD。大多数转换接受一个函数参数。所有这些方法都将一个数据源转换为另一个数据源。每次对任何 RDD 执行转换时，都会生成一个新的 RDD，即使是一个小的改变，如下图所示：

![创建 RDDs](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_02_003.jpg)

这是因为 RDD 是不可变（只读）的抽象设计。从动作中产生的输出可以被写回到存储系统，也可以返回给驱动程序进行本地计算，以便产生最终输出。

到目前为止，我们已经看到了一些简单的转换来定义 RDD，并进行了一些处理和生成一些输出的动作。让我们快速浏览一些方便的转换和转换对配对 RDD 的转换。

## 对普通 RDD 的转换

Spark API 包括丰富的转换操作符，开发人员可以以任意方式组合它们。尝试在交互式 shell 上尝试以下示例，以更好地理解这些操作。

### filter 操作

`filter`操作返回一个只包含满足`filter`条件的元素的 RDD，类似于 SQL 中的`WHERE`条件。

**Python**：

```scala
a = sc.parallelize([1,2,3,4,5,6], 3) 
b = a.filter(lambda x: x % 3 == 0) 
b.collect() 
[3,6] 

```

**Scala**：

```scala
val a = sc.parallelize(1 to 10, 3) 
val b = a.filter(_ % 3 == 0) 
b.collect 

res0: Array[Int] = Array(3, 6, 9) 

```

### distinct 操作

distinct(`[numTasks]`)操作在消除重复后返回一个新数据集的 RDD。

**Python**：

```scala
c = sc.parallelize(["John", "Jack", "Mike", "Jack"], 2) 
c.distinct().collect() 

['Mike', 'John', 'Jack'] 

```

**Scala**：

```scala
val c = sc.parallelize(List("John", "Jack", "Mike", "Jack"), 2) 
c.distinct.collect 
res6: Array[String] = Array(Mike, John, Jack) 

val a = sc.parallelize(List(11,12,13,14,15,16,17,18,19,20)) 
a.distinct(2).partitions.length      //create 2 tasks on two partitions of the same RDD for parallel execution 

res16: Int = 2 

```

### 交集操作

intersection 操作接受另一个数据集作为输入。它返回一个包含共同元素的数据集。

**Python**：

```scala
x = sc.parallelize([1,2,3,4,5,6,7,8,9,10]) 
y = sc.parallelize([5,6,7,8,9,10,11,12,13,14,15]) 
z = x.intersection(y) 
z.collect() 

[8, 9, 10, 5, 6, 7] 

```

**Scala**：

```scala
val x = sc.parallelize(1 to 10) 
val y = sc.parallelize(5 to 15) 
val z = x.intersection(y) 
z.collect 

res74: Array[Int] = Array(8, 9, 5, 6, 10, 7) 

```

### union 操作

union 操作接受另一个数据集作为输入。它返回一个包含自身元素和提供给它的输入数据集的元素的数据集。如果两个集合中有共同的值，则它们将在联合后的结果集中出现为重复值。

**Python**：

```scala
a = sc.parallelize([3,4,5,6,7], 1) 
b = sc.parallelize([7,8,9], 1) 
c = a.union(b) 
c.collect() 

[3, 4, 5, 6, 7, 7, 8, 9] 

```

**Scala**：

```scala
val a = sc.parallelize(3 to 7, 1) 
val b = sc.parallelize(7 to 9, 1) 
val c = a.union(b)     // An alternative way is (a ++ b).collect 

res0: Array[Int] = Array(3, 4, 5, 6, 7, 7, 8, 9) 

```

### map 操作

map 操作通过在输入数据集的每个元素上执行输入函数来返回一个分布式数据集。

**Python**：

```scala
a = sc.parallelize(["animal", "human", "bird", "rat"], 3) 
b = a.map(lambda x: len(x)) 
c = a.zip(b) 
c.collect() 

[('animal', 6), ('human', 5), ('bird', 4), ('rat', 3)] 

```

**Scala**：

```scala
val a = sc.parallelize(List("animal", "human", "bird", "rat"), 3) 
val b = a.map(_.length) 
val c = a.zip(b) 
c.collect 

res0: Array[(String, Int)] = Array((animal,6), (human,5), (bird,4), (rat,3)) 

```

### flatMap 操作

flatMap 操作类似于`map`操作。而`map`为每个输入元素返回一个元素，`flatMap`为每个输入元素返回零个或多个元素的列表。

**Python**：

```scala
a = sc.parallelize([1,2,3,4,5], 4) 
a.flatMap(lambda x: range(1,x+1)).collect() 
   // Range(1,3) returns 1,2 (excludes the higher boundary element) 
[1, 1, 2, 1, 2, 3, 1, 2, 3, 4, 1, 2, 3, 4, 5] 

sc.parallelize([5, 10, 20], 2).flatMap(lambda x:[x, x, x]).collect() 
[5, 5, 5, 10, 10, 10, 20, 20, 20] 

```

**Scala**：

```scala
val a = sc.parallelize(1 to 5, 4) 
a.flatMap(1 to _).collect 
res47: Array[Int] = Array(1, 1, 2, 1, 2, 3, 1, 2, 3, 4, 1, 2, 3, 4, 5) 

//One more example 
sc.parallelize(List(5, 10, 20), 2).flatMap(x => List(x, x, x)).collect 
res85: Array[Int] = Array(5, 5, 5, 10, 10, 10, 20, 20, 20) 

```

### keys 操作

keys 操作返回每个元组的键的 RDD。

**Python**：

```scala
a = sc.parallelize(["black", "blue", "white", "green", "grey"], 2) 
b = a.map(lambda x:(len(x), x)) 
c = b.keys() 
c.collect() 

[5, 4, 5, 5, 4] 

```

**Scala**：

```scala
val a = sc.parallelize(List("black", "blue", "white", "green", "grey"), 2) 
val b = a.map(x => (x.length, x)) 
b.keys.collect 

res2: Array[Int] = Array(5, 4, 5, 5, 4) 

```

### cartesian 操作

`cartesian`操作接受另一个数据集作为参数，并返回两个数据集的笛卡尔积。这可能是一个昂贵的操作，返回一个大小为`m` x `n`的数据集，其中`m`和`n`是输入数据集的大小。

**Python**：

```scala
x = sc.parallelize([1,2,3]) 
y = sc.parallelize([10,11,12]) 
x.cartesian(y).collect() 

[(1, 10), (1, 11), (1, 12), (2, 10), (2, 11), (2, 12), (3, 10), (3, 11), (3, 12)] 

```

**Scala**：

```scala
val x = sc.parallelize(List(1,2,3)) 
val y = sc.parallelize(List(10,11,12)) 
x.cartesian(y).collect 

res0: Array[(Int, Int)] = Array((1,10), (1,11), (1,12), (2,10), (2,11), (2,12), (3,10), (3,11), (3,12))  

```

## 对成对 RDD 的转换

一些 Spark 操作仅适用于键值对的 RDD。请注意，除了计数操作之外，这些操作通常涉及洗牌，因为与键相关的数据可能并不总是驻留在单个分区上。

### groupByKey 操作

类似于 SQL 的`groupBy`操作，这根据键对输入数据进行分组，您可以使用`aggregateKey`或`reduceByKey`执行聚合操作。

**Python**：

```scala
a = sc.parallelize(["black", "blue", "white", "green", "grey"], 2) 
b = a.groupBy(lambda x: len(x)).collect() 
sorted([(x,sorted(y)) for (x,y) in b]) 

[(4, ['blue', 'grey']), (5, ['black', 'white', 'green'])] 

```

**Scala**：

```scala
val a = sc.parallelize(List("black", "blue", "white", "green", "grey"), 2) 
val b = a.keyBy(_.length) 
b.groupByKey.collect 

res11: Array[(Int, Iterable[String])] = Array((4,CompactBuffer(blue, grey)), (5,CompactBuffer(black, white, green))) 

```

### join 操作

join 操作接受另一个数据集作为输入。两个数据集都应该是键值对类型。结果数据集是另一个具有来自两个数据集的键和值的键值数据集。

**Python**：

```scala
a = sc.parallelize(["blue", "green", "orange"], 3) 
b = a.keyBy(lambda x: len(x)) 
c = sc.parallelize(["black", "white", "grey"], 3) 
d = c.keyBy(lambda x: len(x)) 
b.join(d).collect() 
[(4, ('blue', 'grey')), (5, ('green', 'black')), (5, ('green', 'white'))] 

//leftOuterJoin 
b.leftOuterJoin(d).collect() 
[(6, ('orange', None)), (4, ('blue', 'grey')), (5, ('green', 'black')), (5, ('green', 'white'))] 

//rightOuterJoin 
b.rightOuterJoin(d).collect() 
[(4, ('blue', 'grey')), (5, ('green', 'black')), (5, ('green', 'white'))] 

//fullOuterJoin 
b.fullOuterJoin(d).collect() 
[(6, ('orange', None)), (4, ('blue', 'grey')), (5, ('green', 'black')), (5, ('green', 'white'))] 

```

**Scala**：

```scala
val a = sc.parallelize(List("blue", "green", "orange"), 3) 
val b = a.keyBy(_.length) 
val c = sc.parallelize(List("black", "white", "grey"), 3) 
val d = c.keyBy(_.length) 
b.join(d).collect 
res38: Array[(Int, (String, String))] = Array((4,(blue,grey)), (5,(green,black)), (5,(green,white))) 

//leftOuterJoin 
b.leftOuterJoin(d).collect 
res1: Array[(Int, (String, Option[String]))] = Array((6,(orange,None)), (4,(blue,Some(grey))), (5,(green,Some(black))), (5,(green,Some(white)))) 

//rightOuterJoin 
b.rightOuterJoin(d).collect 
res1: Array[(Int, (Option[String], String))] = Array((4,(Some(blue),grey)), (5,(Some(green),black)), (5,(Some(green),white))) 

//fullOuterJoin 
b.fullOuterJoin(d).collect 
res1: Array[(Int, (Option[String], Option[String]))] = Array((6,(Some(orange),None)), (4,(Some(blue),Some(grey))), (5,(Some(green),Some(black))), (5,(Some(green),Some(white))))  

```

### reduceByKey 操作

reduceByKey 操作使用关联的 reduce 函数合并每个键的值。这也会在将结果发送到 reducer 并生成哈希分区输出之前在每个 mapper 上本地执行合并。

**Python**：

```scala
a = sc.parallelize(["black", "blue", "white", "green", "grey"], 2) 
b = a.map(lambda x: (len(x), x)) 
b.reduceByKey(lambda x,y: x + y).collect() 
[(4, 'bluegrey'), (5, 'blackwhitegreen')] 

a = sc.parallelize(["black", "blue", "white", "orange"], 2) 
b = a.map(lambda x: (len(x), x)) 
b.reduceByKey(lambda x,y: x + y).collect() 
[(4, 'blue'), (6, 'orange'), (5, 'blackwhite')] 

```

**Scala**：

```scala
val a = sc.parallelize(List("black", "blue", "white", "green", "grey"), 2) 
val b = a.map(x => (x.length, x)) 
b.reduceByKey(_ + _).collect 
res86: Array[(Int, String)] = Array((4,bluegrey), (5,blackwhitegreen)) 

val a = sc.parallelize(List("black", "blue", "white", "orange"), 2) 
val b = a.map(x => (x.length, x)) 
b.reduceByKey(_ + _).collect 
res87: Array[(Int, String)] = Array((4,blue), (6,orange), (5,blackwhite))  

```

### aggregate 操作

aggregrate 操作返回每个元组的键的 RDD。

**Python**：

```scala
z = sc.parallelize([1,2,7,4,30,6], 2) 
z.aggregate(0,(lambda x, y: max(x, y)),(lambda x, y: x + y)) 
37 
z = sc.parallelize(["a","b","c","d"],2) 
z.aggregate("",(lambda x, y: x + y),(lambda x, y: x + y)) 
'abcd' 
z.aggregate("s",(lambda x, y: x + y),(lambda x, y: x + y)) 
'ssabsscds' 
z = sc.parallelize(["12","234","345","56789"],2) 
z.aggregate("",(lambda x, y: str(max(len(str(x)), len(str(y))))),(lambda x, y: str(y) + str(x))) 
'53' 
z.aggregate("",(lambda x, y: str(min(len(str(x)), len(str(y))))),(lambda x, y: str(y) + str(x))) 
'11' 
z = sc.parallelize(["12","234","345",""],2) 
z.aggregate("",(lambda x, y: str(min(len(str(x)), len(str(y))))),(lambda x, y: str(y) + str(x))) 
'01' 

```

**Scala**：

```scala
val z = sc.parallelize(List(1,2,7,4,30,6), 2) 
z.aggregate(0)(math.max(_, _), _ + _) 
res40: Int = 37 

val z = sc.parallelize(List("a","b","c","d"),2) 
z.aggregate("")(_ + _, _+_) 
res115: String = abcd 

z.aggregate("x")(_ + _, _+_) 
res116: String = xxabxcd 

val z = sc.parallelize(List("12","234","345","56789"),2) 
z.aggregate("")((x,y) => math.max(x.length, y.length).toString, (x,y) => x + y) 
res141: String = 53 

z.aggregate("")((x,y) => math.min(x.length, y.length).toString, (x,y) => x + y) 
res142: String = 11 

val z = sc.parallelize(List("12","234","345",""),2) 
z.aggregate("")((x,y) => math.min(x.length, y.length).toString, (x,y) => x + y) 
res143: String = 01 

```

### 注意

请注意，在前面的聚合示例中，您得到的结果字符串（例如`abcd`，`xxabxcd`，`53`，`01`）不一定要与此处显示的输出完全匹配。这取决于各个任务返回其输出的顺序。

## 动作

一旦创建了 RDD，各种转换只有在对其执行*动作*时才会执行。动作的结果可以是写回存储系统的数据，也可以返回给启动此操作的驱动程序，以便在本地进行进一步计算以生成最终结果。

我们已经在之前的转换示例中涵盖了一些动作函数。以下是一些更多的示例，但还有很多需要您去探索。

### collect()函数

`collect()`函数将 RDD 操作的所有结果作为数组返回给驱动程序。这通常对于生成数据集足够小的操作非常有用。理想情况下，结果应该很容易适应托管驱动程序的系统的内存。

### count()函数

这返回数据集中的元素数量或 RDD 操作的结果输出。

### take(n)函数

`take(n)`函数返回数据集的前(`n`)个元素或 RDD 操作的结果输出。

### first()函数

`first()`函数返回数据集的第一个元素或 RDD 操作的结果输出。它的工作方式类似于`take(1)`函数。

### takeSample()函数

`takeSample(withReplacement, num, [seed])`函数返回数据集中元素的随机样本数组。它有三个参数如下：

+   `withReplacement`/`withoutReplacement`：这表示采样是否有放回（在取多个样本时，它表示是否将旧样本放回集合然后取新样本或者不放回取样）。对于`withReplacement`，参数应为`True`，否则为`False`。

+   `num`：这表示样本中的元素数量。

+   `Seed`：这是一个随机数生成器的种子（可选）。

### countByKey()函数

`countByKey()`函数仅适用于键值类型的 RDD。它返回一个(`K`, `Int`)对的表，其中包含每个键的计数。

以下是一些关于 Python 和 Scala 的示例代码片段：

**Python**：

```scala
>>> sc.parallelize([2, 3, 4]).count() 
3 

>>> sc.parallelize([2, 3, 4]).collect() 
[2, 3, 4] 

>>> sc.parallelize([2, 3, 4]).first() 
2 

>>> sc.parallelize([2, 3, 4]).take(2) 
[2, 3] 

```

**Scala**：

```scala
Scala> sc.parallelize(List(2, 3, 4)).count() 
res0: Long = 3 

Scala> sc.parallelize(List(2, 3, 4)).collect() 
res1: Array[Int] = Array(2, 3, 4) 

Scala> sc.parallelize(List(2, 3, 4)).first() 
res2: Int = 2 

Scala> sc.parallelize(List(2, 3, 4)).take(2) 
res3: Array[Int] = Array(2, 3)  

```

# 总结

在本章中，我们涉及了支持的编程语言，它们的优势以及何时选择一种语言而不是另一种语言。我们讨论了 Spark 引擎的设计以及其核心组件及其执行机制。我们看到了 Spark 如何将要计算的数据发送到许多集群节点上。然后我们讨论了一些 RDD 概念。我们学习了如何通过 Scala 和 Python 在 RDD 上创建 RDD 并对其执行转换和操作。我们还讨论了一些 RDD 的高级操作。

在下一章中，我们将详细了解 DataFrame 以及它们如何证明适用于各种数据科学需求。

# 参考资料

Scala 语言：

+   [`www.scala-lang.org`](http://www.scala-lang.org)

Apache Spark 架构：

+   [`lintool.github.io/SparkTutorial/slides/day1_context.pdf`](http://lintool.github.io/SparkTutorial/slides/day1_context.pdf)

Spark 编程指南是概念的主要资源；参考特定语言的 API 文档以获取可用操作的完整列表。

+   [`spark.apache.org/docs/latest/programming-guide.html`](http://spark.apache.org/docs/latest/programming-guide.html)

弹性分布式数据集：Matei Zaharia 等人的《内存集群计算的容错抽象》是 RDD 基础知识的原始来源：

+   [`people.csail.mit.edu/matei/papers/2012/nsdi_spark.pdf`](https://people.csail.mit.edu/matei/papers/2012/nsdi_spark.pdf)

+   [`www.eecs.berkeley.edu/Pubs/TechRpts/2014/EECS-2014-12.pdf`](http://www.eecs.berkeley.edu/Pubs/TechRpts/2014/EECS-2014-12.pdf)

Spark Summit 是 Apache Spark 的官方活动系列，提供了大量最新信息。查看过去活动的演示文稿和视频：

+   [`spark-summit.org/2016/`](https://spark-summit.org/2016/)


# 第三章：DataFrames 简介

要解决任何真实的大数据分析问题，绝对需要访问一个高效且可扩展的计算系统。然而，如果计算能力对目标用户不易于访问，那么这几乎没有任何意义。交互式数据分析通过可以表示为命名列的数据集变得更加容易，而这在普通的 RDDs 中是不可能的。因此，需要一种基于模式的方法来以标准化的方式表示数据，这就是 DataFrames 背后的灵感来源。

上一章概述了 Spark 的一些设计方面。我们了解到 Spark 如何通过内存计算在分布式数据集（RDDs）上进行分布式数据处理。它涵盖了大部分内容，揭示了 Spark 作为一个快速、高效和可扩展的计算平台。在本章中，我们将看到 Spark 如何引入 DataFrame API，使数据科学家能够轻松进行他们通常的数据分析活动。

这个主题将作为许多即将到来的章节的基础，并且我们强烈建议您非常了解这里涵盖的概念。作为本章的先决条件，需要对 SQL 和 Spark 有基本的了解。本章涵盖的主题如下：

+   为什么要使用 DataFrames？

+   Spark SQL

+   Catalyst 优化器

+   DataFrame API

+   DataFrame 基础知识

+   RDD 与 DataFrame

+   创建 DataFrames

+   从 RDDs

+   从 JSON

+   从 JDBC 数据源

+   从其他数据源

+   操作 DataFrames

# 为什么要使用 DataFrames？

除了大规模、可扩展的计算能力外，大数据应用还需要一些其他特性的混合，例如支持交互式数据分析的关系系统（简单的 SQL 风格）、异构数据源以及不同的存储格式以及不同的处理技术。

尽管 Spark 提供了一个用于操作分布式数据集的函数式编程 API，但最终却以元组（_1、_2 等）结束。对元组进行操作的编码有时会有些复杂和混乱，有时还会很慢。因此，需要一个标准化的层，具有以下特点：

+   具有模式的命名列（比元组更高级的抽象），使得操作和跟踪它们变得容易

+   从各种数据源（如 Hive、Parquet、SQL Server、PostgreSQL、JSON 以及 Spark 的本地 RDDs）整合数据的功能，并将它们统一到一个通用格式中

+   利用特殊文件格式（如 Avro、CSV、JSON 等）中的内置模式的能力

+   支持简单的关系操作以及复杂的逻辑操作

+   消除了基于特定领域任务定义列对象的需求，以便 ML 算法能够正常工作，并为 MLlib 中的所有算法提供一个通用的数据层

+   一个可以在不同语言的函数之间传递的与语言无关的实体

为了满足上述要求，DataFrame API 被构建为在 Spark SQL 之上的另一层抽象。

# Spark SQL

执行基本业务需求的 SQL 查询非常常见，几乎每个企业都会使用某种数据库进行操作。因此，Spark SQL 也支持使用基本 SQL 语法或 HiveQL 编写的 SQL 查询。Spark SQL 还可以用于从现有的 Hive 安装中读取数据。除了这些普通的 SQL 操作，Spark SQL 还解决了一些棘手的问题。通过关系查询设计复杂的逻辑有时很麻烦，几乎不可能。因此，Spark SQL 被设计为整合关系处理和函数式编程的能力，以便在分布式计算环境中实现、优化和扩展复杂的逻辑。与 Spark SQL 交互的基本上有三种方式，包括 SQL、DataFrame API 和 Dataset API。Dataset API 是在撰写本书时添加到 Spark 1.6 中的一个实验性层，因此我们将限制我们的讨论只涉及 DataFrames。

Spark SQL 将 DataFrames 公开为更高级别的 API，并处理所有涉及的复杂性，并执行所有后台任务。通过声明性语法，用户可以专注于程序应该完成的任务，而不必担心由 Spark SQL 内置的 Catalyst 优化器处理的控制流。

## Catalyst 优化器

Catalyst 优化器是 Spark SQL 和 DataFrame 的支点。它是使用 Scala 的函数式编程构造构建的，并具有以下功能：

+   来自各种数据格式的模式推断：

+   Spark 内置支持 JSON 模式推断。用户只需将任何 JSON 文件注册为表，并使用 SQL 语法简单查询即可创建表格。

+   RDDs 是 Scala 对象；类型信息从 Scala 的类型系统中提取，即**case classes**，如果它们包含 case classes。

+   RDDs 是 Python 对象；类型信息是使用不同的方法提取的。由于 Python 不是静态类型的，并遵循动态类型系统，RDD 可以包含多种类型。因此，Spark SQL 对数据集进行抽样，并使用类似于 JSON 模式推断的算法推断模式。

+   未来，将提供对 CSV、XML 和其他格式的内置支持。

+   内置支持广泛的数据源和查询联合以实现高效的数据导入：

+   Spark 具有内置机制，可以通过查询联合从一些外部数据源（例如 JSON、JDBC、Parquet、MySQL、Hive、PostgreSQL、HDFS、S3 等）中获取数据。它可以使用开箱即用的 SQL 数据类型和其他复杂数据类型（如 Struct、Union、Array 等）准确地对数据进行建模。

+   它还允许用户使用**Data Source API**从不受支持的数据源（例如 CSV、Avro HBase、Cassandra 等）中获取数据。

+   Spark 使用谓词下推（将过滤或聚合推入外部存储系统）来优化从外部系统获取数据并将它们组合成数据管道。

+   控制和优化代码生成：

+   优化实际上发生在整个执行管道的非常晚期。

+   Catalyst 旨在优化查询执行的所有阶段：分析、逻辑优化、物理规划和代码生成，以将查询的部分编译为 Java 字节码。

# DataFrame API

类似 Excel 电子表格的数据表示，或者来自数据库投影的输出（select 语句的输出），最接近人类的数据表示始终是一组具有多行统一列的数据。这种通常具有标记行和列的二维数据结构在某些领域被称为 DataFrame，例如 R DataFrames 和 Python 的 Pandas DataFrames。在 DataFrame 中，通常单个列具有相同类型的数据，并且行描述了关于该列的数据点，这些数据点一起表示某种含义，无论是关于一个人、一次购买还是一场棒球比赛的结果。您可以将其视为矩阵、电子表格或 RDBMS 表。

R 和 Pandas 中的 DataFrames 非常方便地对数据进行切片、重塑和分析-这是任何数据整理和数据分析工作流程中必不可少的操作。这启发了在 Spark 上开发类似概念的 DataFrames。

## DataFrame 基础知识

DataFrame API 首次在 2015 年 3 月发布的 Spark 1.3.0 中引入。它是 Spark SQL 的编程抽象，用于结构化和半结构化数据处理。它使开发人员能够通过 Python，Java，Scala 和 R 利用 DataFrame 数据结构的强大功能。与 RDD 类似，Spark DataFrame 是一个分布式记录集合，组织成命名列，类似于 RDBMS 表或 R 或 Pandas 的 DataFrame。但是，与 RDD 不同的是，它们跟踪模式并促进关系操作以及`map`等过程操作。在内部，DataFrame 以列格式存储数据，但在需要时通过过程函数构造行对象。

DataFrame API 带来了两个特性：

+   内置支持各种数据格式，如 Parquet，Hive 和 JSON。尽管如此，通过 Spark SQL 的外部数据源 API，DataFrame 可以访问各种第三方数据源，如数据库和 NoSQL 存储。

+   具有为常见任务设计的函数的更健壮和功能丰富的 DSL，例如：

+   元数据

+   抽样

+   关系数据处理 - 项目，过滤，聚合，连接

+   UDFs

DataFrame API 建立在 Spark SQL 查询优化器之上，可以在机器集群上自动高效地执行代码。

## RDD 与 DataFrame

RDD 和 DataFrame 是 Spark 提供的两种不同类型的容错和分布式数据抽象。它们在某种程度上相似，但在实现时有很大的不同。开发人员需要清楚地了解它们的差异，以便能够将其需求与正确的抽象匹配。

### 相似之处

以下是 RDD 和 DataFrame 之间的相似之处：

+   两者都是 Spark 中的容错，分区数据抽象

+   两者都可以处理不同的数据源

+   两者都是惰性评估的（在它们上执行输出操作时发生执行），因此具有最优化的执行计划的能力

+   这两个 API 在 Scala，Python，Java 和 R 中都可用

### 差异

以下是 RDD 和 DataFrame 之间的区别：

+   数据框架比 RDDs 更高级的抽象。

+   RDD 的定义意味着定义一个**有向无环图**（**DAG**），而定义 DataFrame 会导致创建一个**抽象语法树**（**AST**）。 AST 将由 Spark SQL catalyst 引擎利用和优化。

+   RDD 是一种通用的数据结构抽象，而 DataFrame 是一种专门处理二维表格数据的数据结构。

DataFrame API 实际上是 SchemaRDD 重命名。重命名是为了表示它不再继承自 RDD，并且以熟悉的名称和概念安慰数据科学家。

# 创建数据框架

Spark DataFrame 的创建类似于 RDD 的创建。要访问 DataFrame API，您需要 SQLContext 或 HiveContext 作为入口点。在本节中，我们将演示如何从各种数据源创建数据框架，从基本的代码示例开始，使用内存集合：

![创建数据框架](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_03_001.jpg)

## 从 RDD 创建数据框架

以下代码从颜色列表创建了一个 RDD，然后是一个包含颜色名称及其长度的元组集合。它使用`toDF`方法将 RDD 转换为 DataFrame。`toDF`方法将列标签列表作为可选参数：

**Python**：

```scala
   //Create a list of colours 
>>> colors = ['white','green','yellow','red','brown','pink'] 
//Distribute a local collection to form an RDD 
//Apply map function on that RDD to get another RDD containing colour, length tuples 
>>> color_df = sc.parallelize(colors) 
        .map(lambda x:(x,len(x))).toDF(["color","length"]) 

>>> color_df 
DataFrame[color: string, length: bigint] 

>>> color_df.dtypes        //Note the implicit type inference 
[('color', 'string'), ('length', 'bigint')] 

>>> color_df.show()  //Final output as expected. Order need not be the same as shown 
+------+------+ 
| color|length| 
+------+------+ 
| white|     5| 
| green|     5| 
|yellow|     6| 
|   red|     3| 
| brown|     5| 
|  pink|     4| 
+------+------+ 

```

**Scala**：

```scala
//Create a list of colours 
Scala> val colors = List("white","green","yellow","red","brown","pink") 
//Distribute a local collection to form an RDD 
//Apply map function on that RDD to get another RDD containing colour, length tuples 
Scala> val color_df = sc.parallelize(colors) 
         .map(x => (x,x.length)).toDF("color","length") 

Scala> color_df 
res0: org.apache.spark.sql.DataFrame = [color: string, length: int] 

Scala> color_df.dtypes  //Note the implicit type inference   
res1: Array[(String, String)] = Array((color,StringType), (length,IntegerType)) 

Scala> color_df.show()//Final output as expected. Order need not be the same as shown 
+------+------+ 
| color|length| 
+------+------+ 
| white|     5| 
| green|     5| 
|yellow|     6| 
|   red|     3| 
| brown|     5| 
|  pink|     4| 
+------+------+ 

```

从上面的示例中可以看出，从开发人员的角度来看，创建 DataFrame 与从 RDD 创建类似。我们在这里创建了一个 RDD，然后将其转换为元组，然后将其发送到`toDF`方法。请注意，`toDF`接受元组列表而不是标量元素。即使要创建单列 DataFrame，您也需要传递元组。每个元组类似于一行。您可以选择标记列；否则，Spark 会创建类似`_1`、`_2`的模糊名称。列的类型推断隐式发生。

如果您已经将数据作为 RDDs，Spark SQL 支持将现有 RDDs 转换为 DataFrame 的两种不同方法：

+   第一种方法使用反射来推断包含特定类型对象的 RDD 的模式，这意味着您了解模式。

+   第二种方法是通过编程接口，允许您构建模式，然后将其应用于现有的 RDD。虽然这种方法更冗长，但它允许您在运行时构建 DataFrame，当列类型直到运行时才知道时。

## 从 JSON 创建 DataFrame

JavaScript 对象表示法（JSON）是一种与语言无关、自描述、轻量级的数据交换格式。JSON 已经成为一种流行的数据交换格式，并且变得无处不在。除了 JavaScript 和 RESTful 接口之外，诸如 MySQL 之类的数据库已经接受 JSON 作为一种数据类型，而 MongoDB 以二进制形式将所有数据存储为 JSON 文档。数据与 JSON 之间的转换对于任何现代数据分析工作流程都是必不可少的。Spark DataFrame API 允许开发人员将 JSON 对象转换为 DataFrame，反之亦然。让我们仔细看一下以下示例，以便更好地理解：

Python：

```scala
//Pass the source json data file path 
>>> df = sqlContext.read.json("./authors.json") 
>>> df.show() //json parsed; Column names and data    types inferred implicitly 
+----------+---------+ 
|first_name|last_name| 
+----------+---------+ 
|      Mark|    Twain| 
|   Charles|  Dickens| 
|    Thomas|    Hardy| 
+----------+---------+ 

```

Scala：

```scala
//Pass the source json data file path 
Scala> val df = sqlContext.read.json("./authors.json") 
Scala> df.show()  //json parsed; Column names and    data types inferred implicitly 
+----------+---------+ 
|first_name|last_name| 
+----------+---------+ 
|      Mark|    Twain| 
|   Charles|  Dickens| 
|    Thomas|    Hardy| 
+----------+---------+ 

```

Spark 会自动从键中推断模式并相应地创建 DataFrame。

## 使用 JDBC 从数据库创建 DataFrame

Spark 允许开发人员使用 JDBC 从其他数据库创建 DataFrame，只要确保所需数据库的 JDBC 驱动程序可访问。JDBC 驱动程序是一种软件组件，允许 Java 应用程序与数据库交互。不同的数据库需要不同的驱动程序。通常，诸如 MySQL 之类的数据库提供商会提供这些驱动程序组件以访问他们的数据库。您必须确保您拥有要使用的数据库的正确驱动程序。

以下示例假设您已经在给定的 URL 上运行了 MySQL 数据库，在名为`test`的数据库中有一个名为`people`的表，并且有有效的凭据登录。还有一个额外的步骤是使用适当的 JAR 文件重新启动 REPL shell：

### 注意

如果您的系统中尚未有 JAR 文件，请从 MySQL 网站下载：[`dev.mysql.com/downloads/connector/j/`](https://dev.mysql.com/downloads/connector/j/)。

Python：

```scala
//Launch shell with driver-class-path as a command line argument 
pyspark --driver-class-path /usr/share/   java/mysql-connector-java.jar 
   //Pass the connection parameters 
>>> peopleDF = sqlContext.read.format('jdbc').options( 
                        url = 'jdbc:mysql://localhost', 
                        dbtable = 'test.people', 
                        user = 'root', 
                        password = 'mysql').load() 
   //Retrieve table data as a DataFrame 
>>> peopleDF.show() 
+----------+---------+------+----------+----------+---------+ 
|first_name|last_name|gender|       dob|occupation|person_id| 
+----------+---------+------+----------+----------+---------+ 
|    Thomas|    Hardy|     M|1840-06-02|    Writer|      101| 
|     Emily|   Bronte|     F|1818-07-30|    Writer|      102| 
| Charlotte|   Bronte|     F|1816-04-21|    Writer|      103| 
|   Charles|  Dickens|     M|1812-02-07|    Writer|      104| 
+----------+---------+------+----------+----------+---------+ 

```

Scala：

```scala
//Launch shell with driver-class-path as a command line argument 
spark-shell --driver-class-path /usr/share/   java/mysql-connector-java.jar 
   //Pass the connection parameters 
scala> val peopleDF = sqlContext.read.format("jdbc").options( 
           Map("url" -> "jdbc:mysql://localhost", 
               "dbtable" -> "test.people", 
               "user" -> "root", 
               "password" -> "mysql")).load() 
peopleDF: org.apache.spark.sql.DataFrame = [first_name: string, last_name: string, gender: string, dob: date, occupation: string, person_id: int] 
//Retrieve table data as a DataFrame 
scala> peopleDF.show() 
+----------+---------+------+----------+----------+---------+ 
|first_name|last_name|gender|       dob|occupation|person_id| 
+----------+---------+------+----------+----------+---------+ 
|    Thomas|    Hardy|     M|1840-06-02|    Writer|      101| 
|     Emily|   Bronte|     F|1818-07-30|    Writer|      102| 
| Charlotte|   Bronte|     F|1816-04-21|    Writer|      103| 
|   Charles|  Dickens|     M|1812-02-07|    Writer|      104| 
+----------+---------+------+----------+----------+---------+ 

```

## 从 Apache Parquet 创建 DataFrame

Apache Parquet 是 Hadoop 生态系统中任何项目都可以使用的高效的、压缩的列式数据表示。列式数据表示按列存储数据，而不是传统的按行存储数据的方法。需要频繁查询多个列中的两到三列的用例因此受益于这样的安排，因为列在磁盘上是连续存储的，您不必读取不需要的列在面向行的存储中。另一个优势在于压缩。单个列中的数据属于单一类型。这些值往往是相似的，有时是相同的。这些特性极大地增强了压缩和编码的效率。Parquet 允许在每列级别指定压缩方案，并允许在发明和实现更多编码时添加更多编码。

Apache Spark 提供了对 Parquet 文件的读取和写入支持，可以自动保留原始数据的模式。以下示例将在上一个示例中加载到 DataFrame 中的 people 数据写入 Parquet 格式，然后重新读取到 RDD 中：

**Python**：

```scala
//Write DataFrame contents into Parquet format 
>>> peopleDF.write.parquet('writers.parquet') 
//Read Parquet data into another DataFrame 
>>> writersDF = sqlContext.read.parquet('writers.parquet')  
writersDF: org.apache.spark.sql.DataFrame = [first_name:    string, last_name: string, gender: string, dob:    date, occupation: string, person_id: int]
```

**Scala**：

```scala
//Write DataFrame contents into Parquet format 
scala> peopleDF.write.parquet("writers.parquet") 
//Read Parquet data into another DataFrame 
scala> val writersDF = sqlContext.read.parquet("writers.parquet")  
writersDF: org.apache.spark.sql.DataFrame = [first_name:    string, last_name: string, gender: string, dob:    date, occupation: string, person_id: int]
```

## 从其他数据源创建数据框架

Spark 提供了对多种数据源的内置支持，例如 JSON、JDBC、HDFS、Parquet、MYSQL、Amazon S3 等。此外，它还提供了一个数据源 API，通过 Spark SQL 提供了一种可插拔的机制来访问结构化数据。基于这个可插拔组件构建了几个库，例如 CSV、Avro、Cassandra 和 MongoDB 等。这些库不是 Spark 代码库的一部分，它们是为个别数据源构建的，并托管在一个名为 Spark packages 的社区网站上。

# DataFrame 操作

在本章的前一部分，我们学习了创建数据框架的许多不同方法。在本节中，我们将重点关注可以在数据框架上执行的各种操作。开发人员可以链接多个操作来过滤、转换、聚合和排序数据框架中的数据。底层的 Catalyst 优化器确保这些操作的高效执行。这里的函数与通常在表上进行的 SQL 操作中常见的函数相似：

**Python**：

```scala
//Create a local collection of colors first 
>>> colors = ['white','green','yellow','red','brown','pink'] 
//Distribute the local collection to form an RDD 
//Apply map function on that RDD to get another RDD containing colour, length tuples and convert that RDD to a DataFrame 
>>> color_df = sc.parallelize(colors) 
        .map(lambda x:(x,len(x))).toDF(['color','length']) 
//Check the object type 
>>> color_df 
DataFrame[color: string, length: bigint] 
//Check the schema 
>>> color_df.dtypes 
[('color', 'string'), ('length', 'bigint')] 

//Check row count 
>>> color_df.count() 
6 
//Look at the table contents. You can limit displayed rows by passing parameter to show 
color_df.show() 
+------+------+ 
| color|length| 
+------+------+ 
| white|     5| 
| green|     5| 
|yellow|     6| 
|   red|     3| 
| brown|     5| 
|  pink|     4| 
+------+------+ 

//List out column names 
>>> color_df.columns 
[u'color', u'length'] 

//Drop a column. The source DataFrame color_df remains the same. //Spark returns a new DataFrame which is being passed to show 
>>> color_df.drop('length').show() 
+------+ 
| color| 
+------+ 
| white| 
| green| 
|yellow| 
|   red| 
| brown| 
|  pink| 
+------+ 
//Convert to JSON format 
>>> color_df.toJSON().first() 
u'{"color":"white","length":5}' 
//filter operation is similar to WHERE clause in SQL 
//You specify conditions to select only desired columns and rows 
//Output of filter operation is another DataFrame object that is usually passed on to some more operations 
//The following example selects the colors having a length of four or five only and label the column as "mid_length" 
filter 
------ 
>>> color_df.filter(color_df.length.between(4,5)) 
      .select(color_df.color.alias("mid_length")).show() 
+----------+ 
|mid_length| 
+----------+ 
|     white| 
|     green| 
|     brown| 
|      pink| 
+----------+ 

//This example uses multiple filter criteria 
>>> color_df.filter(color_df.length > 4) 
     .filter(color_df[0]!="white").show() 
+------+------+ 
| color|length| 
+------+------+ 
| green|     5| 
|yellow|     6| 
| brown|     5| 
+------+------+ 

//Sort the data on one or more columns 
sort 
---- 
//A simple single column sorting in default (ascending) order 
>>> color_df.sort("color").show() 
+------+------+ 
| color|length| 
+------+------+ 
| brown|     5| 
| green|     5| 
|  pink|     4| 
|   red|     3| 
| white|     5| 
|yellow|     6| 
+------+------+ 
//First filter colors of length more than 4 and then sort on multiple columns 
//The Filtered rows are sorted first on the column length in default ascending order. Rows with same length are sorted on color in descending order   
>>> color_df.filter(color_df['length']>=4).sort("length", 'color',ascending=False).show()
+------+------+ 
| color|length| 
+------+------+ 
|yellow|     6| 
| white|     5| 
| green|     5| 
| brown|     5| 
|  pink|     4| 
+------+------+ 

//You can use orderBy instead, which is an alias to sort 
>>> color_df.orderBy('length','color').take(4)
[Row(color=u'red', length=3), Row(color=u'pink', length=4), Row(color=u'brown', length=5), Row(color=u'green', length=5)]

//Alternative syntax, for single or multiple columns.  
>>> color_df.sort(color_df.length.desc(),   color_df.color.asc()).show() 
+------+------+ 
| color|length| 
+------+------+ 
|yellow|     6| 
| brown|     5| 
| green|     5| 
| white|     5| 
|  pink|     4| 
|   red|     3| 
+------+------+ 
//All the examples until now have been acting on one row at a time, filtering or transforming or reordering.  
//The following example deals with regrouping the data 
//These operations require "wide dependency" and often involve shuffling.  
groupBy 
------- 
>>> color_df.groupBy('length').count().show() 
+------+-----+ 
|length|count| 
+------+-----+ 
|     3|    1| 
|     4|    1| 
|     5|    3| 
|     6|    1| 
+------+-----+ 
//Data often contains missing information or null values. We may want to drop such rows or replace with some filler information. dropna is provided for dropping such rows 
//The following json file has names of famous authors. Firstname data is missing in one row. 
dropna 
------ 
>>> df1 = sqlContext.read.json('./authors_missing.json')
>>> df1.show() 
+----------+---------+ 
|first_name|last_name| 
+----------+---------+ 
|      Mark|    Twain| 
|   Charles|  Dickens| 
|      null|    Hardy| 
+----------+---------+ 

//Let us drop the row with incomplete information 
>>> df2 = df1.dropna() 
>>> df2.show()  //Unwanted row is dropped 
+----------+---------+ 
|first_name|last_name| 
+----------+---------+ 
|      Mark|    Twain| 
|   Charles|  Dickens| 
+----------+---------+ 

```

**Scala**：

```scala
//Create a local collection of colors first 
Scala> val colors = List("white","green","yellow","red","brown","pink") 
//Distribute a local collection to form an RDD 
//Apply map function on that RDD to get another RDD containing color, length tuples and convert that RDD to a DataFrame 
Scala> val color_df = sc.parallelize(colors) 
        .map(x => (x,x.length)).toDF("color","length") 
//Check the object type 
Scala> color_df 
res0: org.apache.spark.sql.DataFrame = [color: string, length: int] 
//Check the schema 
Scala> color_df.dtypes 
res1: Array[(String, String)] = Array((color,StringType), (length,IntegerType)) 
//Check row count 
Scala> color_df.count() 
res4: Long = 6 
//Look at the table contents. You can limit displayed rows by passing parameter to show 
color_df.show() 
+------+------+ 
| color|length| 
+------+------+ 
| white|     5| 
| green|     5| 
|yellow|     6| 
|   red|     3| 
| brown|     5| 
|  pink|     4| 
+------+------+ 
//List out column names 
Scala> color_df.columns 
res5: Array[String] = Array(color, length) 
//Drop a column. The source DataFrame color_df remains the same. 
//Spark returns a new DataFrame which is being passed to show 
Scala> color_df.drop("length").show() 
+------+ 
| color| 
+------+ 
| white| 
| green| 
|yellow| 
|   red| 
| brown| 
|  pink| 
+------+ 
//Convert to JSON format 
color_df.toJSON.first() 
res9: String = {"color":"white","length":5} 

//filter operation is similar to WHERE clause in SQL 
//You specify conditions to select only desired columns and rows 
//Output of filter operation is another DataFrame object that is usually passed on to some more operations 
//The following example selects the colors having a length of four or five only and label the column as "mid_length" 
filter 
------ 
Scala> color_df.filter(color_df("length").between(4,5)) 
       .select(color_df("color").alias("mid_length")).show() 
+----------+ 
|mid_length| 
+----------+ 
|     white| 
|     green| 
|     brown| 
|      pink| 
+----------+ 

//This example uses multiple filter criteria. Notice the not equal to operator having double equal to symbols  
Scala> color_df.filter(color_df("length") > 4).filter(color_df( "color")!=="white").show() 
+------+------+ 
| color|length| 
+------+------+ 
| green|     5| 
|yellow|     6| 
| brown|     5| 
+------+------+ 
//Sort the data on one or more columns 
sort 
---- 
//A simple single column sorting in default (ascending) order 
Scala> color_df..sort("color").show() 
+------+------+                                                                  
| color|length| 
+------+------+ 
| brown|     5| 
| green|     5| 
|  pink|     4| 
|   red|     3| 
| white|     5| 
|yellow|     6| 
+------+------+ 
//First filter colors of length more than 4 and then sort on multiple columns 
//The filtered rows are sorted first on the column length in default ascending order. Rows with same length are sorted on color in descending order  
Scala> color_df.filter(color_df("length")>=4).sort($"length", $"color".desc).show() 
+------+------+ 
| color|length| 
+------+------+ 
|  pink|     4| 
| white|     5| 
| green|     5| 
| brown|     5| 
|yellow|     6| 
+------+------+ 
//You can use orderBy instead, which is an alias to sort. 
scala> color_df.orderBy("length","color").take(4) 
res19: Array[org.apache.spark.sql.Row] = Array([red,3], [pink,4], [brown,5], [green,5]) 
//Alternative syntax, for single or multiple columns 
scala> color_df.sort(color_df("length").desc, color_df("color").asc).show() 
+------+------+ 
| color|length| 
+------+------+ 
|yellow|     6| 
| brown|     5| 
| green|     5| 
| white|     5| 
|  pink|     4| 
|   red|     3| 
+------+------+ 
//All the examples until now have been acting on one row at a time, filtering or transforming or reordering. 
//The following example deals with regrouping the data.  
//These operations require "wide dependency" and often involve shuffling. 
groupBy 
------- 
Scala> color_df.groupBy("length").count().show() 
+------+-----+ 
|length|count| 
+------+-----+ 
|     3|    1| 
|     4|    1| 
|     5|    3| 
|     6|    1| 
+------+-----+ 
//Data often contains missing information or null values.  
//The following json file has names of famous authors. Firstname data is missing in one row. 
dropna 
------ 
Scala> val df1 = sqlContext.read.json("./authors_missing.json") 
Scala> df1.show() 
+----------+---------+ 
|first_name|last_name| 
+----------+---------+ 
|      Mark|    Twain| 
|   Charles|  Dickens| 
|      null|    Hardy| 
+----------+---------+ 
//Let us drop the row with incomplete information 
Scala> val df2 = df1.na.drop() 
Scala> df2.show()  //Unwanted row is dropped 
+----------+---------+ 
|first_name|last_name| 
+----------+---------+ 
|      Mark|    Twain| 
|   Charles|  Dickens| 
+----------+---------+ 

```

## 底层

你现在已经知道 DataFrame API 是由 Spark SQL 支持的，并且 Spark SQL 的 Catalyst 优化器在优化性能方面起着关键作用。

尽管查询是惰性执行的，但它使用 Catalyst 的*catalog*组件来识别程序中使用的列名或表达式是否存在于正在使用的表中，数据类型是否正确，以及采取许多其他预防性措施。这种方法的优势在于，用户一输入无效表达式，就会立即弹出错误，而不是等到程序执行。

# 摘要

在本章中，我们解释了开发 Spark 数据框架 API 背后的动机，以及 Spark 开发如何变得比以往更容易。我们简要介绍了数据框架 API 的设计方面，以及它是如何构建在 Spark SQL 之上的。我们讨论了从不同数据源（如 RDD、JSON、Parquet 和 JDBC）创建数据框架的各种方法。在本章末尾，我们简要介绍了如何对数据框架执行操作。在接下来的章节中，我们将更详细地讨论数据科学和机器学习中的 DataFrame 操作。

在下一章中，我们将学习 Spark 如何支持统一数据访问，并详细讨论数据集和结构化流组件。

# 参考资料

Apache Spark 官方资源的 SQL 编程指南上的 DataFrame 参考：

+   [`spark.apache.org/docs/latest/sql-programming-guide.html#creating-dataframes`](https://spark.apache.org/docs/latest/sql-programming-guide.html#creating-dataframes)

Databricks：介绍 Apache Spark 用于大规模数据科学的数据框架：

+   [`databricks.com/blog/2015/02/17/introducing-dataframes-in-spark-for-large-scale-data-science.html`](https://databricks.com/blog/2015/02/17/introducing-dataframes-in-spark-for-large-scale-data-science.html)

Databricks：从 Pandas 到 Apache Spark 的 DataFrame：

+   [`databricks.com/blog/2015/08/12/from-pandas-to-apache-sparks-dataframe.html`](https://databricks.com/blog/2015/08/12/from-pandas-to-apache-sparks-dataframe.html)

Scala 中 Spark 数据框架的 API 参考指南：

+   [`spark.apache.org/docs/1.5.1/api/java/org/apache/spark/sql/DataFrame.html`](https://spark.apache.org/docs/1.5.1/api/java/org/apache/spark/sql/DataFrame.html)

Cloudera 博客关于 Parquet - 一种高效的通用列式文件格式，用于 Apache Hadoop：

+   [`blog.cloudera.com/blog/2013/03/introducing-parquet-columnar-storage-for-apache-hadoop/`](http://blog.cloudera.com/blog/2013/03/introducing-parquet-columnar-storage-for-apache-hadoop/)


# 第四章：统一数据访问

来自不同数据源的数据集成一直是一项艰巨的任务。大数据的三个 V 和不断缩短的处理时间框架使这项任务变得更加具有挑战性。在几乎实时地提供清晰的精心策划的数据对于业务来说非常重要。然而，实时策划的数据以及在统一方式中执行 ETL、临时查询和机器学习等不同操作的能力正在成为关键的业务差异化因素。

Apache Spark 的创建是为了提供一个可以处理各种数据源数据并支持各种不同操作的单一通用引擎。Spark 使开发人员能够在单个工作流中结合 SQL、流式处理、图形和机器学习算法！

在前几章中，我们讨论了**弹性分布式数据集**（**RDDs**）以及数据框架。在第三章中，*数据框架简介*，我们介绍了 Spark SQL 和 Catalyst 优化器。本章将在此基础上深入探讨这些主题，帮助您认识到统一数据访问的真正本质。我们将介绍新的构造，如数据集和结构化流。具体来说，我们将讨论以下内容：

+   Apache Spark 中的数据抽象

+   数据集

+   使用数据集

+   数据集 API 的限制

+   Spark SQL

+   SQL 操作

+   底层

+   结构化流

+   Spark 流式编程模型

+   底层

+   与其他流处理引擎的比较

+   连续应用

+   总结

# Apache Spark 中的数据抽象

在过去的十年中，MapReduce 框架及其流行的开源实现 Hadoop 得到了广泛的应用。然而，迭代算法和交互式临时查询得到的支持并不好。作业或算法内部阶段之间的任何数据共享都是通过磁盘读写进行的，而不是通过内存数据共享。因此，逻辑上的下一步将是有一种机制，可以在多个作业之间重复使用中间结果。RDD 是一个通用的数据抽象，旨在解决这一需求。

RDD 是 Apache Spark 中的核心抽象。它是一个不可变的、容错的分布式集合，通常存储在内存中，其中包含静态类型的对象。RDD API 提供了简单的操作，如 map、reduce 和 filter，可以以任意方式组合。

数据框架抽象建立在 RDD 之上，并添加了“命名”列。因此，Spark 数据框架具有类似关系数据库表和 R 和 Python（pandas）中的数据框架的命名列行。这种熟悉的高级抽象使开发工作变得更加容易，因为它让您可以像处理 SQL 表或 Excel 文件一样处理数据。此外，底层的 Catalyst 优化器编译操作并生成 JVM 字节码以进行高效执行。然而，命名列方法也带来了一个新问题。编译器不再具有静态类型信息，因此我们失去了编译时类型安全的优势。

数据集 API 被引入，以结合 RDD 和数据框架的最佳特性，以及一些自己的特性。数据集提供了类似数据框架的行和列数据抽象，但在其之上定义了一种结构。这种结构可以由 Scala 中的 case 类或 Java 中的类定义。它们提供了类型安全和类似 RDD 的 lambda 函数。因此，它们支持诸如`map`和`groupByKey`之类的类型化方法，也支持诸如`select`和`groupBy`之类的无类型方法。除了 Catalyst 优化器外，数据集还利用了 Tungsten 执行引擎提供的内存编码，进一步提高了性能。

到目前为止引入的数据抽象形成了核心抽象。还有一些更专门的数据抽象是在这些抽象之上工作的。引入了流式 API 来处理来自各种来源（如 Flume 和 Kafka）的实时流数据。这些 API 共同工作，为数据工程师提供了一个统一的、连续的 DataFrame 抽象，可用于交互式和批量查询。另一个专门的数据抽象的例子是 GraphFrame。这使开发人员能够分析社交网络和任何其他图形，以及类似 Excel 的二维数据。

现在，考虑到现有数据抽象的基础知识，让我们了解一下我们所说的统一数据访问平台到底是什么：

![Apache Spark 中的数据抽象](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_04_001.jpg)

统一平台背后的意图是它不仅可以让您将静态和流式数据结合在一起，还可以以统一的方式对数据进行各种不同类型的操作！从开发人员的角度来看，数据集是与之一起工作的核心抽象，而 Spark SQL 是与 Spark 功能交互的主要接口。与 SQL 声明式编程接口相结合的二维数据结构一直是处理数据的一种熟悉方式，从而缩短了数据工程师的学习曲线。因此，理解统一平台意味着理解数据集和 Spark SQL。

# 数据集

Apache Spark 的**数据集**是 DataFrame API 的扩展，提供了一种类型安全的面向对象的编程接口。这个 API 首次在 1.6 版本中引入。Spark 2.0 版本带来了 DataFrame 和 Dataset API 的统一。DataFrame 变成了一个通用的、无类型的数据集；或者说数据集是一个带有附加结构的 DataFrame。在这个上下文中，“结构”指的是底层数据的模式或组织，更像是 RDBMS 术语中的表模式。结构对可以在底层数据中表达或包含的内容施加了限制。这反过来使得内存组织和物理执行的优化更好。编译时类型检查导致在运行时之前捕获错误。例如，在 SQL 比较中的类型不匹配直到运行时才被捕获，而如果它被表达为对数据集的一系列操作，它将在编译时被捕获。然而，Python 和 R 的固有动态特性意味着没有编译时类型安全，因此数据集的概念不适用于这些语言。数据集和 DataFrame 的统一仅适用于 Scala 和 Java API。

数据集抽象的核心是**编码器**。这些编码器在 JVM 对象和 Spark 内部 Tungsten 二进制格式之间进行转换。这种内部表示绕过了 JVM 的内存管理和垃圾回收。Spark 有自己的 C 风格内存访问，专门用于解决它支持的工作流类型。由此产生的内部表示占用更少的内存，并具有高效的内存管理。紧凑的内存表示导致在洗牌操作期间减少网络负载。编码器生成紧凑的字节码，直接在序列化对象上操作，而无需反序列化，从而提高性能。早期了解模式会导致在缓存数据集时内存布局更加优化。

## 使用数据集

在这一部分，我们将创建数据集并执行转换和操作，就像 DataFrame 和 RDD 一样。

示例 1-从简单集合创建数据集：

**Scala:**

```scala
//Create a Dataset from a simple collection 
scala> val ds1 = List.range(1,5).toDS() 
ds1: org.apache.spark.sql.Dataset[Int] = [value: int] 
//Perform an action 
scala> ds1.collect() 
res3: Array[Int] = Array(1, 2, 3, 4) 

//Create from an RDD 
scala> val colors = List("red","orange","blue","green","yellow") 
scala> val color_ds = sc.parallelize(colors).map(x => 
     (x,x.length)).toDS() 
//Add a case class 
case class Color(var color: String, var len: Int) 
val color_ds = sc.parallelize(colors).map(x => 
     Color(x,x.length)).toDS() 

```

正如在前面的代码中的最后一个示例中所示，`case class`添加了结构信息。Spark 使用这个结构来创建最佳的数据布局和编码。以下代码向我们展示了结构和执行计划：

**Scala:**

```scala
//Examine the structure 
scala> color_ds.dtypes 
res26: Array[(String, String)] = Array((color,StringType), (len,IntegerType)) 
scala> color_ds.schema 
res25: org.apache.spark.sql.types.StructType = StructType(StructField(color,StringType,true), 
StructField(len,IntegerType,false)) 
//Examine the execution plan 
scala> color_ds.explain() 
== Physical Plan == 
Scan ExistingRDD[color#57,len#58] 

```

前面的例子显示了预期的结构和实现物理计划。如果您想获得更详细的执行计划，您必须传递 explain（true），这将打印扩展信息，包括逻辑计划。

我们已经从简单集合和 RDD 中创建了数据集。我们已经讨论过 DataFrame 只是无类型数据集。以下示例显示了数据集和 DataFrame 之间的转换。

示例 2-将数据集转换为 DataFrame

**Scala:**

```scala
//Convert the dataset to a DataFrame 
scala> val color_df = color_ds.toDF() 
color_df: org.apache.spark.sql.DataFrame = [color: string, len: int] 

scala> color_df.show() 
+------+---+ 
| color|len| 
+------+---+ 
|   red|  3| 
|orange|  6| 
|  blue|  4| 
| green|  5| 
|yellow|  6| 
+------+---+ 

```

这个例子看起来非常像我们在第三章中看到的例子，*DataFrame 简介*。这些转换在现实世界中非常方便。考虑向不完整的数据添加结构（也称为案例类）。您可以首先将数据读入 DataFrame，进行清洗，然后将其转换为数据集。另一个用例可能是，您希望基于某些运行时信息（例如`user_id`）仅公开数据的子集（行和列）。您可以将数据读入 DataFrame，将其注册为临时表，应用条件，并将子集公开为数据集。以下示例首先创建一个`DataFrame`，然后将其转换为`Dataset`。请注意，DataFrame 列名必须与案例类匹配。

示例 3-将 DataFrame 转换为数据集

```scala
//Construct a DataFrame first 
scala> val color_df = sc.parallelize(colors).map(x => 
           (x,x.length)).toDF("color","len") 
color_df: org.apache.spark.sql.DataFrame = [color: string, len: int] 
//Convert the DataFrame to a Dataset with a given structure 
scala> val ds_from_df = color_df.as[Color] 
ds_from_df: org.apache.spark.sql.Dataset[Color] = [color: string, len: int] 
//Check the execution plan 
scala> ds_from_df.explain 
== Physical Plan == 
WholeStageCodegen 
:  +- Project [_1#102 AS color#105,_2#103 AS len#106] 
:     +- INPUT 
+- Scan ExistingRDD[_1#102,_2#103] 

```

解释命令的响应显示`WholeStageCodegen`，它将多个操作融合为单个 Java 函数调用。这通过减少多个虚拟函数调用来增强性能。自 1.1 以来，代码生成一直存在于 Spark 引擎中，但当时它仅限于表达式评估和一小部分操作，如过滤。相比之下，Tungsten 的整个阶段代码生成为整个查询计划生成代码。

### 从 JSON 创建数据集

数据集可以像 DataFrame 一样从 JSON 文件中创建。请注意，JSON 文件可能包含多个记录，但每个记录必须在一行上。如果您的源 JSON 有换行符，您必须以编程方式将其删除。JSON 记录可能包含数组并且可能是嵌套的。它们不需要具有统一的模式。以下示例文件包含具有附加标记和数据数组的 JSON 记录。

示例 4-从 JSON 创建数据集

**Scala:**

```scala
//Set filepath 
scala> val file_path = <Your path> 
file_path: String = ./authors.json 
//Create case class to match schema 
scala> case class Auth(first_name: String, last_name: String,books: Array[String]) 
defined class Auth 

//Create dataset from json using case class 
//Note that the json document should have one record per line 
scala> val auth = spark.read.json(file_path).as[Auth] 
auth: org.apache.spark.sql.Dataset[Auth] = [books: array<string>, firstName: string ... 1 more field] 

//Look at the data 
scala> auth.show() 
+--------------------+----------+---------+ 
|               books|first_name|last_name| 
+--------------------+----------+---------+ 
|                null|      Mark|    Twain| 
|                null|   Charles|  Dickens| 
|[Jude the Obscure...|    Thomas|    Hardy| 
+--------------------+----------+---------+ 

//Try explode to see array contents on separate lines 

scala> auth.select(explode($"books") as "book", 
            $"first_name",$"last_name").show(2,false) 
+------------------------+----------+---------+ 
|book                    |first_name|last_name| 
+------------------------+----------+---------+ 
|Jude the Obscure        |Thomas    |Hardy    | 
|The Return of the Native|Thomas    |Hardy    | 
+------------------------+----------+---------+ 

```

## 数据集 API 的限制

尽管数据集 API 是使用 RDD 和 DataFrame 的最佳部分创建的，但在当前开发阶段仍存在一些限制：

+   在查询数据集时，所选字段应该具有与案例类相同的特定数据类型，否则输出将变为 DataFrame。例如`auth.select(col("first_name").as[String])`。

+   Python 和 R 在本质上是动态的，因此类型化的数据集不适合。

# Spark SQL

**Spark SQL**是 Spark 1.0 引入的用于结构化数据处理的 Spark 模块。该模块是一个与核心 Spark API 紧密集成的关系引擎。它使数据工程师能够编写应用程序，从不同来源加载结构化数据，并将它们作为统一的、可能连续的类似 Excel 的数据框进行连接；然后他们可以实现复杂的 ETL 工作流和高级分析。

Spark 2.0 版本带来了 API 的显著统一和扩展的 SQL 功能，包括对子查询的支持。数据集 API 和 DataFrame API 现在是统一的，DataFrame 是数据集的一种“类型”。统一的 API 为 Spark 的未来奠定了基础，跨越所有库。开发人员可以将“结构”强加到其数据上，并可以使用高级声明性 API，从而提高性能和生产率。性能增益是由底层优化层带来的。数据框，数据集和 SQL 共享相同的优化和执行管道。

## SQL 操作

SQL 操作是用于数据操作的最广泛使用的构造。一些最常用的操作是，选择所有或一些列，基于一个或多个条件进行过滤，排序和分组操作，以及计算`average`等汇总函数。多个数据源上的`JOIN`操作和`set`操作，如`union`，`intersect`和`minus`，是广泛执行的其他操作。此外，数据框被注册为临时表，并传递传统的 SQL 语句来执行上述操作。**用户定义的函数**（**UDF**）被定义并用于注册和不注册。我们将专注于窗口操作，这是在 Spark 2.0 中刚刚引入的。它们处理滑动窗口操作。例如，如果您想要报告过去七天内每天的平均最高温度，那么您正在操作一个直到今天的七天滑动窗口。这是一个示例，计算过去三个月每月的平均销售额。数据文件包含 24 个观测值，显示了两种产品 P1 和 P2 的月销售额。

示例 5-使用移动平均计算的窗口示例

**Scala:**

```scala
scala> import org.apache.spark.sql.expressions.Window 
import org.apache.spark.sql.expressions.Window 
//Create a DataFrame containing monthly sales data for two products 
scala> val monthlySales = spark.read.options(Map({"header"->"true"},{"inferSchema" -> "true"})). 
                            csv("<Your Path>/MonthlySales.csv") 
monthlySales: org.apache.spark.sql.DataFrame = [Product: string, Month: int ... 1 more field] 

//Prepare WindowSpec to create a 3 month sliding window for a product 
//Negative subscript denotes rows above current row 
scala> val w = Window.partitionBy(monthlySales("Product")).orderBy(monthlySales("Month")).rangeBetween(-2,0) 
w: org.apache.spark.sql.expressions.WindowSpec = org.apache.spark.sql.expressions.WindowSpec@3cc2f15 

//Define compute on the sliding window, a moving average in this case 
scala> val f = avg(monthlySales("Sales")).over(w) 
f: org.apache.spark.sql.Column = avg(Sales) OVER (PARTITION BY Product ORDER BY Month ASC RANGE BETWEEN 2 PRECEDING AND CURRENT ROW) 
//Apply the sliding window and compute. Examine the results 
scala> monthlySales.select($"Product",$"Sales",$"Month", bround(f,2).alias("MovingAvg")). 
                    orderBy($"Product",$"Month").show(6) 
+-------+-----+-----+---------+                                                  
|Product|Sales|Month|MovingAvg| 
+-------+-----+-----+---------+ 
|     P1|   66|    1|     66.0| 
|     P1|   24|    2|     45.0| 
|     P1|   54|    3|     48.0| 
|     P1|    0|    4|     26.0| 
|     P1|   56|    5|    36.67| 
|     P1|   34|    6|     30.0| 
+-------+-----+-----+---------+ 

```

**Python:**

```scala
    >>> from pyspark.sql import Window
    >>> import pyspark.sql.functions as func
    //Create a DataFrame containing monthly sales data for two products
    >> file_path = <Your path>/MonthlySales.csv"
    >>> monthlySales = spark.read.csv(file_path,header=True, inferSchema=True)

    //Prepare WindowSpec to create a 3 month sliding window for a product
    //Negative subscript denotes rows above current row
    >>> w = Window.partitionBy(monthlySales["Product"]).orderBy(monthlySales["Month"]).rangeBetween(-2,0)
    >>> w
    <pyspark.sql.window.WindowSpec object at 0x7fdc33774a50>
    >>>
    //Define compute on the sliding window, a moving average in this case
    >>> f = func.avg(monthlySales["Sales"]).over(w)
    >>> f
    Column<avg(Sales) OVER (PARTITION BY Product ORDER BY Month ASC RANGE BETWEEN 2 PRECEDING AND CURRENT ROW)>
    >>>
    //Apply the sliding window and compute. Examine the results
    >>> monthlySales.select(monthlySales.Product,monthlySales.Sales,monthlySales.Month,
                          func.bround(f,2).alias("MovingAvg")).orderBy(
                          monthlySales.Product,monthlySales.Month).show(6)
    +-------+-----+-----+---------+                                                 
    |Product|Sales|Month|MovingAvg|
    +-------+-----+-----+---------+
    |     P1|   66|    1|     66.0|
    |     P1|   24|    2|     45.0|
    |     P1|   54|    3|     48.0|
    |     P1|    0|    4|     26.0|
    |     P1|   56|    5|    36.67|
    |     P1|   34|    6|     30.0|
    +-------+-----+-----+---------+

```

## 在幕后

当开发人员使用 RDD API 编写程序时，高效执行手头的工作负载是他/她的责任。数据类型和计算对于 Spark 来说是不可用的。相比之下，当开发人员使用 DataFrames 和 Spark SQL 时，底层引擎具有关于模式和操作的信息。在这种情况下，开发人员可以编写更少的代码，而优化器会做所有的艰苦工作。

Catalyst 优化器包含用于表示树和应用规则以转换树的库。这些树转换被应用于创建最优化的逻辑和物理执行计划。在最后阶段，它使用 Scala 语言的一个特殊功能**quasiquotes**生成 Java 字节码。优化器还使外部开发人员能够通过添加数据源特定规则来扩展优化器，这些规则导致将操作推送到外部系统，或支持新的数据类型。

Catalyst 优化器得出了最优化的计划来执行手头的操作。实际的执行和相关的改进由 Tungsten 引擎提供。Tungsten 的目标是提高 Spark 后端执行的内存和 CPU 效率。以下是该引擎的一些显着特点：

+   通过绕过（堆外）Java 内存管理来减少内存占用和消除垃圾收集开销。

+   代码生成在多个操作符之间融合，避免了过多的虚拟函数调用。生成的代码看起来像手动优化的代码。

+   内存布局是以列为基础的，内存中的 parquet 格式，因为这样可以实现矢量化处理，并且更接近通常的数据访问操作。

+   使用编码器进行内存编码。编码器使用运行时代码生成来构建自定义字节码，以实现更快和更紧凑的序列化和反序列化。许多操作可以在原地执行，而无需反序列化，因为它们已经处于 Tungsten 二进制格式中。

# 结构化流处理

流处理似乎是一个广泛的话题！如果您仔细观察现实世界的问题，企业不仅希望流处理引擎实时做出决策。一直以来，都需要集成批处理栈和流处理栈，并与外部存储系统和应用程序集成。此外，解决方案应该能够适应业务逻辑的动态变化，以满足新的和不断变化的业务需求。

Apache Spark 2.0 具有称为**结构化流**引擎的高级流处理 API 的第一个版本。这个可扩展和容错的引擎依赖于 Spark SQL API 来简化实时连续的大数据应用程序的开发。这可能是统一批处理和流处理计算的第一次成功尝试。

在技术层面上，结构化流依赖于 Spark SQL API，它扩展了数据框/数据集，我们在前面的部分已经讨论过。Spark 2.0 让您以统一的方式执行根本不同的活动，例如：

+   构建 ML 模型并将其应用于流数据

+   将流数据与其他静态数据结合

+   执行临时、交互和批量查询

+   在运行时更改查询

+   聚合数据流并使用 Spark SQL JDBC 提供服务

与其他流式引擎不同，Spark 允许您将实时**流数据**与**静态数据**结合，并执行前述操作。

![结构化流](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_04_002.jpg)

从根本上讲，结构化流由 Spark SQL 的 Catalyst 优化器赋予了能力。因此，它使开发人员不必担心处理静态或实时数据流时使查询更有效的底层管道。

截至目前，Spark 2.0 的结构化流主要集中在 ETL 上，以后的版本将具有更多的操作符和库。

让我们看一个简单的例子。以下示例监听 Linux 上本地机器上的**系统活动报告**（**sar**）并计算平均空闲内存。系统活动报告提供系统活动统计信息，当前示例收集内存使用情况，以 2 秒的间隔报告 20 次。Spark 流读取这个流式输出并计算平均内存。我们使用一个方便的网络实用工具**netcat**（**nc**）将`sar`输出重定向到给定端口。选项`l`和`k`指定`nc`应该监听传入连接，并且在当前连接完成后，它必须继续监听另一个连接。

**Scala:**

示例 6-流式示例

```scala
//Run the following command from one terminal window 
sar -r 2 20 | nc -lk 9999 

//In spark-shell window, do the following 
//Read stream 
scala> val myStream = spark.readStream.format("socket"). 
                       option("host","localhost"). 
                       option("port",9999).load() 
myStream: org.apache.spark.sql.DataFrame = [value: string] 

//Filter out unwanted lines and then extract free memory part as a float 
//Drop missing values, if any 
scala> val myDF = myStream.filter($"value".contains("IST")). 
               select(substring($"value",15,9).cast("float").as("memFree")). 
               na.drop().select($"memFree") 
myDF: org.apache.spark.sql.DataFrame = [memFree: float] 

//Define an aggregate function 
scala> val avgMemFree = myDF.select(avg("memFree")) 
avgMemFree: org.apache.spark.sql.DataFrame = [avg(memFree): double] 

//Create StreamingQuery handle that writes on to the console 
scala> val query = avgMemFree.writeStream. 
          outputMode("complete"). 
          format("console"). 
          start() 
query: org.apache.spark.sql.streaming.StreamingQuery = Streaming Query - query-0 [state = ACTIVE] 

Batch: 0 
------------------------------------------- 
+-----------------+ 
|     avg(memFree)| 
+-----------------+ 
|4116531.380952381| 
+-----------------+ 
.... 

```

**Python:**

```scala
    //Run the following command from one terminal window
     sar -r 2 20 | nc -lk 9999

    //In another window, open pyspark shell and do the following
    >>> import pyspark.sql.functions as func
    //Read stream
    >>> myStream = spark.readStream.format("socket"). \
                           option("host","localhost"). \
                           option("port",9999).load()
    myStream: org.apache.spark.sql.DataFrame = [value: string]

    //Filter out unwanted lines and then extract free memory part as a float
    //Drop missing values, if any
    >>> myDF = myStream.filter("value rlike 'IST'"). \
               select(func.substring("value",15,9).cast("float"). \
               alias("memFree")).na.drop().select("memFree")

    //Define an aggregate function
    >>> avgMemFree = myDF.select(func.avg("memFree"))

    //Create StreamingQuery handle that writes on to the console
    >>> query = avgMemFree.writeStream. \
              outputMode("complete"). \
              format("console"). \
              start()
    Batch: 0
    -------------------------------------------
    +------------+
    |avg(memFree)|
    +------------+
    |   4042749.2|
    +------------+
    .....

```

前面的示例定义了一个连续的数据框（也称为流）来监听特定端口，执行一些转换和聚合，并显示连续的输出。

## Spark 流式编程模型

正如本章前面所示，只需使用单个 API 来处理静态和流数据。其想法是将实时数据流视为不断追加的表，如下图所示：

![Spark 流式编程模型](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_04_003.jpg)

因此，无论是静态数据还是流数据，您只需像在静态数据表上那样启动类似批处理的查询，Spark 会将其作为无界输入表上的增量查询运行，如下图所示：

![Spark 流式编程模型](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_04_004.jpg)

因此，开发人员以相同的方式在输入表上定义查询，无论是静态有界表还是动态无界表。让我们了解整个过程的各种技术术语，以了解它是如何工作的：

+   **输入：**来自源的追加表的数据

+   **触发器：**何时检查输入以获取新数据

+   **查询：**对数据执行的操作，例如过滤、分组等

+   **结果：**每个触发间隔的结果表

+   **输出：**选择在每个触发后写入数据接收器的结果的哪一部分

现在让我们看看 Spark SQL 规划器如何处理整个过程：

![Spark 流式编程模型](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_04_005.jpg)

提供：Databricks

前面的屏幕截图在官方 Apache Spark 网站的结构化编程指南中有非常简单的解释，如*参考*部分所示。

![Spark 流式编程模型](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_04_006.jpg)

在这一点上，我们需要了解支持的输出模式。每次更新结果表时，更改都需要写入外部系统，如 HDFS、S3 或任何其他数据库。我们通常倾向于增量写入输出。为此，结构化流提供了三种输出模式：

+   **Append:**在外部存储中，自上次触发以来追加到结果表的新行将被写入。这仅适用于查询，其中结果表中的现有行不会更改（例如，对输入流的映射）。

+   **Complete:**在外部存储中，整个更新的结果表将按原样写入。

+   **更新：**在外部存储中，自上次触发以来在结果表中更新的行将被更改。此模式适用于可以就地更新的输出接收器，例如 MySQL 表。

在我们的示例中，我们使用了完整模式，直接写入控制台。您可能希望将数据写入一些外部文件，如 Parquet，以便更好地理解。

## 底层原理

如果您查看在**DataFrames/Datasets**上执行的操作的“幕后”执行机制，它将如下图所示：

![底层原理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_04_007.jpg)

请注意，**Planner**事先知道如何将流式**Logical Plan**转换为一系列**Incremental Execution Plans**。这可以用以下图表示：

![底层原理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_04_008.jpg)

**Planner**可以轮询数据源以便以优化的方式规划执行。

## 与其他流式引擎的比较

我们已经讨论了结构化流的许多独特特性。现在让我们与其他可用的流式引擎进行比较：

![与其他流式引擎的比较](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_04_009.jpg)

提供：Databricks

# 连续应用程序

我们讨论了 Spark 如何赋予统一数据访问的能力。它让您以多种方式处理数据，通过启用各种分析工作负载来构建端到端的连续应用程序，例如 ETL 处理、adhoc 查询、在线机器学习建模，或生成必要的报告...所有这些都可以通过让您使用高级的、类似 SQL 的 API 来处理静态和流式数据的方式来统一进行，从而大大简化了实时连续应用程序的开发和维护。

![连续应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_04_010.jpg)

提供：Databricks

# 摘要

在本章中，我们讨论了统一数据访问的真正含义以及 Spark 如何实现这一目的。我们仔细研究了 Datasets API 以及实时流如何通过它得到增强。我们了解了 Datasets 的优势以及它们的局限性。我们还研究了连续应用程序背后的基本原理。

在下一章中，我们将探讨利用 Spark 平台进行规模化数据分析操作的各种方法。

# 参考文献

+   [`people.csail.mit.edu/matei/papers/2015/sigmod_spark_sql.pdf`](http://people.csail.mit.edu/matei/papers/2015/sigmod_spark_sql.pdf)：Spark SQL：Spark 中的关系数据处理

+   [`databricks.com/blog/2016/07/14/a-tale-of-three-apache-spark-apis-rdds-dataframes-and-datasets.html`](https://databricks.com/blog/2016/07/14/a-tale-of-three-apache-spark-apis-rdds-dataframes-and-datasets.html)：三种 Apache Spark API 的故事：RDDs、DataFrames 和 Datasets-何时使用它们以及为什么

+   [`databricks.com/blog/2016/01/04/introducing-apache-spark-datasets.html`](https://databricks.com/blog/2016/01/04/introducing-apache-spark-datasets.html)：介绍 Apache Spark Datasets

+   [`databricks.com/blog/2015/04/13/deep-dive-into-spark-sqls-catalyst-optimizer.html`](https://databricks.com/blog/2015/04/13/deep-dive-into-spark-sqls-catalyst-optimizer.html)：深入了解 Spark SQL 的 Catalyst 优化器

+   [`databricks.com/blog/2016/05/23/apache-spark-as-a-compiler-joining-a-billion-rows-per-second-on-a-laptop.html`](https://databricks.com/blog/2016/05/23/apache-spark-as-a-compiler-joining-a-billion-rows-per-second-on-a-laptop.html) : Apache Spark 作为编译器：在笔记本电脑上每秒连接十亿行

+   [`databricks.com/blog/2015/04/28/project-tungsten-bringing-spark-closer-to-bare-metal.html`](https://databricks.com/blog/2015/04/28/project-tungsten-bringing-spark-closer-to-bare-metal.html) : 将 Spark 靠近裸金属

+   [`databricks.com/blog/2016/07/28/structured-streaming-in-apache-spark.html`](https://databricks.com/blog/2016/07/28/structured-streaming-in-apache-spark.html) : Apache Spark 中的结构化流 API 详细信息

+   [`spark.apache.org/docs/latest/structured-streaming-programming-guide.html`](https://spark.apache.org/docs/latest/structured-streaming-programming-guide.html) : Spark 结构化流编程指南

+   [`spark-summit.org/east-2016/events/structuring-spark-dataframes-datasets-and-streaming/`](https://spark-summit.org/east-2016/events/structuring-spark-dataframes-datasets-and-streaming/): Michael Armbrust 介绍 Apache Spark SQL，DataFrames，Datasets 和 Streaming

+   [`databricks.com/blog/2016/06/22/apache-spark-key-terms-explained.html`](https://databricks.com/blog/2016/06/22/apache-spark-key-terms-explained.html): Apache Spark 关键术语解释
