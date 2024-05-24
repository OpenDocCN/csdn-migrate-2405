# 精通 Spark（一）

> 原文：[`zh.annas-archive.org/md5/5211DAC7494A736A2B4617944224CFC3`](https://zh.annas-archive.org/md5/5211DAC7494A736A2B4617944224CFC3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

已经写了一本关于 Hadoop 生态系统的介绍性书籍，我很高兴 Packt 邀请我写一本关于 Apache Spark 的书。作为一个有支持和维护背景的实用主义者，我对系统构建和集成很感兴趣。因此，我总是问自己“系统如何被使用？”，“它们如何相互配合？”，“它们与什么集成？”在本书中，我将描述 Spark 的每个模块，并通过实际例子解释它们如何被使用。我还将展示如何通过额外的库（如来自[`h2o.ai/`](http://h2o.ai/)的 H2O）扩展 Spark 的功能。

我将展示 Apache Spark 的图处理模块如何与 Aurelius（现在是 DataStax）的 Titan 图数据库一起使用。这将通过将 Spark GraphX 和 Titan 组合在一起，提供基于图的处理和存储的耦合。流处理章节将展示如何使用 Apache Flume 和 Kafka 等工具将数据传递给 Spark 流。

考虑到过去几年已经有大规模迁移到基于云的服务，我将检查[`databricks.com/`](https://databricks.com/)提供的 Spark 云服务。我将从实际的角度来做，本书不试图回答“服务器还是云”的问题，因为我认为这是另一本书的主题；它只是检查了可用的服务。

# 本书涵盖的内容

第一章 *Apache Spark*，将全面介绍 Spark，其模块的功能以及用于处理和存储的工具。本章将简要介绍 SQL、流处理、GraphX、MLlib、Databricks 和 Hive on Spark 的细节。

第二章 *Apache Spark MLlib*，涵盖了 MLlib 模块，其中 MLlib 代表机器学习库。它描述了本书中将使用的 Apache Hadoop 和 Spark 集群，以及涉及的操作系统——CentOS。它还描述了正在使用的开发环境：Scala 和 SBT。它提供了安装和构建 Apache Spark 的示例。解释了使用朴素贝叶斯算法进行分类的示例，以及使用 KMeans 进行聚类的示例。最后，使用 Bert Greevenbosch（[www.bertgreevenbosch.nl](http://www.bertgreevenbosch.nl)）的工作扩展 Spark 以包括一些人工神经网络（ANN）工作的示例。我一直对神经网络很感兴趣，能够在本章中使用 Bert 的工作（在得到他的许可后）是一件令人愉快的事情。因此，本章的最后一个主题是使用简单的 ANN 对一些小图像进行分类，包括扭曲的图像。结果和得分都相当不错！

第三章 *Apache Spark Streaming*，涵盖了 Apache Spark 与 Storm 的比较，特别是 Spark Streaming，但我认为 Spark 提供了更多的功能。例如，一个 Spark 模块中使用的数据可以传递到另一个模块中并被使用。此外，正如本章所示，Spark 流处理可以轻松集成大数据移动技术，如 Flume 和 Kafka。

因此，流处理章节首先概述了检查点，并解释了何时可能需要使用它。它给出了 Scala 代码示例，说明了如何使用它，并展示了数据如何存储在 HDFS 上。然后，它继续给出了 Scala 的实际示例，以及 TCP、文件、Flume 和 Kafka 流处理的执行示例。最后两个选项通过处理 RSS 数据流并最终将其存储在 HDFS 上来展示。

第四章 *Apache Spark SQL*，用 Scala 代码术语解释了 Spark SQL 上下文。它解释了文本、Parquet 和 JSON 格式的文件 I/O。使用 Apache Spark 1.3，它通过示例解释了数据框架的使用，并展示了它们提供的数据分析方法。它还通过基于 Scala 的示例介绍了 Spark SQL，展示了如何创建临时表，以及如何对其进行 SQL 操作。

接下来，介绍了 Hive 上下文。首先创建了一个本地上下文，然后执行了 Hive QL 操作。然后，介绍了一种方法，将现有的分布式 CDH 5.3 Hive 安装集成到 Spark Hive 上下文中。然后展示了针对此上下文的操作，以更新集群上的 Hive 数据库。通过这种方式，可以创建和调度 Spark 应用程序，以便 Hive 操作由实时 Spark 引擎驱动。

最后，介绍了创建用户定义函数（UDFs），然后使用创建的 UDFs 对临时表进行 SQL 调用。

第五章 *Apache Spark GraphX*，介绍了 Apache Spark GraphX 模块和图形处理模块。它通过一系列基于示例的图形函数工作，从基于计数到三角形处理。然后介绍了 Kenny Bastani 的 Mazerunner 工作，该工作将 Neo4j NoSQL 数据库与 Apache Spark 集成。这项工作已经得到 Kenny 的许可；请访问[www.kennybastani.com](http://www.kennybastani.com)。

本章通过 Docker 的介绍，然后是 Neo4j，然后介绍了 Neo4j 接口。最后，通过提供的 REST 接口介绍了一些 Mazerunner 提供的功能。

第六章 *基于图形的存储*，检查了基于图形的存储，因为本书介绍了 Apache Spark 图形处理。我寻找一个能够与 Hadoop 集成、开源、能够高度扩展，并且能够与 Apache Spark 集成的产品。

尽管在社区支持和开发方面仍然相对年轻，但我认为 Aurelius（现在是 DataStax）的 Titan 符合要求。截至我写作时，可用的 0.9.x 版本使用 Apache TinkerPop 进行图形处理。

本章提供了使用 Gremlin shell 和 Titan 创建和存储图形的示例。它展示了如何将 HBase 和 Cassandra 用于后端 Titan 存储。

第七章 *使用 H2O 扩展 Spark*，讨论了在[`h2o.ai/`](http://h2o.ai/)开发的 H2O 库集，这是一个可以用来扩展 Apache Spark 功能的机器学习库系统。在本章中，我研究了 H2O 的获取和安装，以及用于数据分析的 Flow 接口。还研究了 Sparkling Water 的架构、数据质量和性能调优。

最后，创建并执行了一个深度学习的示例。第二章 *Spark MLlib*，使用简单的人工神经网络进行神经分类。本章使用了一个高度可配置和可调整的 H2O 深度学习神经网络进行分类。结果是一个快速而准确的训练好的神经模型，你会看到的。

第八章 *Spark Databricks*，介绍了[`databricks.com/`](https://databricks.com/) AWS 基于云的 Apache Spark 集群系统。它提供了逐步设置 AWS 账户和 Databricks 账户的过程。然后，它逐步介绍了[`databricks.com/`](https://databricks.com/)账户功能，包括笔记本、文件夹、作业、库、开发环境等。

它检查了 Databricks 中基于表的存储和处理，并介绍了 Databricks 实用程序功能的 DBUtils 包。这一切都是通过示例完成的，以便让您对这个基于云的系统的使用有一个很好的理解。

第九章，*Databricks 可视化*，通过专注于数据可视化和仪表板来扩展 Databricks 的覆盖范围。然后，它检查了 Databricks 的 REST 接口，展示了如何使用各种示例 REST API 调用远程管理集群。最后，它从表的文件夹和库的角度看数据移动。

本章的集群管理部分显示，可以使用 Spark 发布的脚本在 AWS EC2 上启动 Apache Spark。[`databricks.com/`](https://databricks.com/)服务通过提供一种轻松创建和调整多个基于 EC2 的 Spark 集群的方法，进一步提供了这种功能。它为集群管理和使用提供了额外的功能，以及用户访问和安全性，正如这两章所示。考虑到为我们带来 Apache Spark 的人们创建了这项服务，它一定值得考虑和审查。

# 本书所需内容

本书中的实际示例使用 Scala 和 SBT 进行基于 Apache Spark 的代码开发和编译。还使用了基于 CentOS 6.5 Linux 服务器的 Cloudera CDH 5.3 Hadoop 集群。Linux Bash shell 和 Perl 脚本都用于帮助 Spark 应用程序并提供数据源。在 Spark 应用程序测试期间，使用 Hadoop 管理命令来移动和检查数据。

考虑到之前的技能概述，读者对 Linux、Apache Hadoop 和 Spark 有基本的了解会很有帮助。话虽如此，鉴于今天互联网上有大量信息可供查阅，我不想阻止一个勇敢的读者去尝试。我相信从错误中学到的东西可能比成功更有价值。

# 这本书是为谁准备的

这本书适用于任何对 Apache Hadoop 和 Spark 感兴趣的人，他们想了解更多关于 Spark 的知识。它适用于希望了解如何使用 Spark 扩展 H2O 等系统的用户。对于对图处理感兴趣但想了解更多关于图存储的用户。如果读者想了解云中的 Apache Spark，那么他/她可以了解由为他们带来 Spark 的人开发的[`databricks.com/`](https://databricks.com/)。如果您是具有一定 Spark 经验的开发人员，并希望加强对 Spark 世界的了解，那么这本书非常适合您。要理解本书，需要具备 Linux、Hadoop 和 Spark 的基本知识；同时也需要合理的 Scala 知识。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“第一步是确保`/etc/yum.repos.d`目录下存在 Cloudera 存储库文件，在服务器 hc2nn 和所有其他 Hadoop 集群服务器上。”

代码块设置如下：

```scala
export AWS_ACCESS_KEY_ID="QQpl8Exxx"
export AWS_SECRET_ACCESS_KEY="0HFzqt4xxx"

./spark-ec2  \
    --key-pair=pairname \
    --identity-file=awskey.pem \
    --region=us-west-1 \
    --zone=us-west-1a  \
    launch cluster1
```

任何命令行输入或输出都是这样写的：

```scala
[hadoop@hc2nn ec2]$ pwd

/usr/local/spark/ec2

[hadoop@hc2nn ec2]$ ls
deploy.generic  README  spark-ec2  spark_ec2.py

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“选择**用户操作**选项，然后选择**管理访问密钥**。”

### 注意

警告或重要说明会以这样的方式出现在框中。

### 提示

提示和技巧会以这样的方式出现。


# 第一章：Apache Spark

Apache Spark 是一个分布式和高度可扩展的内存数据分析系统，提供了在 Java、Scala、Python 以及 R 等语言中开发应用程序的能力。它在目前的 Apache 顶级项目中具有最高的贡献/参与率。现在，像 Mahout 这样的 Apache 系统使用它作为处理引擎，而不是 MapReduce。此外，正如在第四章中所示，*Apache Spark SQL*，可以使用 Hive 上下文，使 Spark 应用程序直接处理 Apache Hive 中的数据。

Apache Spark 提供了四个主要的子模块，分别是 SQL、MLlib、GraphX 和 Streaming。它们将在各自的章节中进行解释，但在这里简单的概述会很有用。这些模块是可互操作的，因此数据可以在它们之间传递。例如，流式数据可以传递到 SQL，然后创建一个临时表。

以下图解释了本书将如何处理 Apache Spark 及其模块。前两行显示了 Apache Spark 及其前面描述的四个子模块。然而，尽可能地，我总是试图通过示例来展示如何使用额外的工具来扩展功能：

![Apache Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_01_01.jpg)

例如，第三章中解释的数据流模块，*Apache Spark Streaming*，将有工作示例，展示如何使用 Apache **Kafka**和**Flume**执行数据移动。机器学习模块**MLlib**将通过可用的数据处理功能进行功能检查，但也将使用 H2O 系统和深度学习进行扩展。

前面的图当然是简化的。它代表了本书中呈现的系统关系。例如，Apache Spark 模块与 HDFS 之间的路线比前面的图中显示的要多得多。

Spark SQL 章节还将展示 Spark 如何使用 Hive 上下文。因此，可以开发一个 Spark 应用程序来创建基于 Hive 的对象，并对存储在 HDFS 中的 Hive 表运行 Hive QL。

第五章 *Apache Spark GraphX* 和 第六章 *基于图的存储* 将展示 Spark GraphX 模块如何用于处理大数据规模的图，以及如何使用 Titan 图数据库进行存储。将展示 Titan 允许存储和查询大数据规模的图。通过一个例子，将展示 Titan 可以同时使用**HBase**和**Cassandra**作为存储机制。当使用 HBase 时，将会显示 Titan 隐式地使用 HDFS 作为一种廉价可靠的分布式存储机制。

因此，我认为本节已经解释了 Spark 是一个内存处理系统。在大规模使用时，它不能独立存在——数据必须存放在某个地方。它可能会与 Hadoop 工具集以及相关的生态系统一起使用。幸运的是，Hadoop 堆栈提供商，如 Cloudera，提供了与 Apache Spark、Hadoop 和大多数当前稳定工具集集成的 CDH Hadoop 堆栈和集群管理器。在本书中，我将使用安装在 CentOS 6.5 64 位服务器上的小型 CDH 5.3 集群。您可以使用其他配置，但我发现 CDH 提供了我需要的大多数工具，并自动化了配置，为我留下更多的时间进行开发。

提到了 Spark 模块和本书中将介绍的软件后，下一节将描述大数据集群的可能设计。

# 概述

在本节中，我希望提供一个关于本书中将介绍的 Apache Spark 功能以及将用于扩展它的系统的概述。我还将尝试审视 Apache Spark 与云存储集成的未来。

当您查看 Apache Spark 网站（[`spark.apache.org/`](http://spark.apache.org/)）上的文档时，您会发现有涵盖 SparkR 和 Bagel 的主题。虽然我会在本书中涵盖四个主要的 Spark 模块，但我不会涵盖这两个主题。我在本书中时间和范围有限，所以我会把这些主题留给读者自行探究或将来研究。

## Spark 机器学习

Spark MLlib 模块提供了在多个领域进行机器学习功能。Spark 网站上提供的文档介绍了使用的数据类型（例如，向量和 LabeledPoint 结构）。该模块提供的功能包括：

+   统计

+   分类

+   回归

+   协同过滤

+   聚类

+   维度约简

+   特征提取

+   频繁模式挖掘

+   优化

基于 Scala 的 KMeans、朴素贝叶斯和人工神经网络的实际示例已在本书的第二章 *Apache Spark MLlib*中介绍和讨论。

## Spark Streaming

流处理是 Apache Spark 的另一个重要和受欢迎的主题。它涉及在 Spark 中作为流处理数据，并涵盖输入和输出操作、转换、持久性和检查点等主题。

第三章 *Apache Spark Streaming*，涵盖了这一领域的处理，并提供了不同类型的流处理的实际示例。它讨论了批处理和窗口流配置，并提供了一个实际的检查点示例。它还涵盖了不同类型的流处理示例，包括 Kafka 和 Flume。

流数据还有许多其他用途。其他 Spark 模块功能（例如 SQL、MLlib 和 GraphX）可以用于处理流。您可以将 Spark 流处理与 Kinesis 或 ZeroMQ 等系统一起使用。您甚至可以为自己定义的数据源创建自定义接收器。

## Spark SQL

从 Spark 版本 1.3 开始，数据框架已经引入到 Apache Spark 中，以便以表格形式处理 Spark 数据，并且可以使用表格函数（如 select、filter、groupBy）来处理数据。Spark SQL 模块与 Parquet 和 JSON 格式集成，允许数据以更好地表示数据的格式存储。这也提供了更多与外部系统集成的选项。

将 Apache Spark 集成到 Hadoop Hive 大数据数据库中的想法也可以介绍。基于 Hive 上下文的 Spark 应用程序可用于操作基于 Hive 的表数据。这使得 Spark 的快速内存分布式处理能力可以应用到 Hive 的大数据存储能力上。它有效地让 Hive 使用 Spark 作为处理引擎。

## Spark 图处理

Apache Spark GraphX 模块使 Spark 能够提供快速的大数据内存图处理。图由顶点和边的列表（连接顶点的线）表示。GraphX 能够使用属性、结构、连接、聚合、缓存和取消缓存操作来创建和操作图。

它引入了两种新的数据类型来支持 Spark 中的图处理：VertexRDD 和 EdgeRDD 来表示图的顶点和边。它还介绍了图处理的示例函数，例如 PageRank 和三角形处理。这些函数中的许多将在第五章 *Apache Spark GraphX*中进行研究。

## 扩展生态系统

在审查大数据处理系统时，我认为重要的是不仅要看系统本身，还要看它如何扩展，以及它如何与外部系统集成，以便提供更高级别的功能。在这样大小的书中，我无法涵盖每个选项，但希望通过介绍一个主题，我可以激发读者的兴趣，以便他们可以进一步调查。

我已经使用了 H2O 机器学习库系统来扩展 Apache Spark 的机器学习模块。通过使用基于 Scala 的 H2O 深度学习示例，我展示了如何将神经处理引入 Apache Spark。然而，我知道我只是触及了 H2O 功能的表面。我只使用了一个小型神经集群和一种分类功能。此外，H2O 还有很多其他功能。

随着图形处理在未来几年变得更加被接受和使用，基于图形的存储也将如此。我已经调查了使用 NoSQL 数据库 Neo4J 的 Spark，使用了 Mazerunner 原型应用程序。我还调查了 Aurelius（Datastax）Titan 数据库用于基于图形的存储。同样，Titan 是一个新生的数据库，需要社区支持和进一步发展。但我想研究 Apache Spark 集成的未来选项。

## Spark 的未来

下一节将展示 Apache Spark 发布包含的脚本，允许在 AWS EC2 存储上创建一个 Spark 集群。有一系列选项可供选择，允许集群创建者定义属性，如集群大小和存储类型。但这种类型的集群很难调整大小，这使得管理变化的需求变得困难。如果数据量随时间变化或增长，可能需要更大的集群和更多的内存。

幸运的是，开发 Apache Spark 的人创建了一个名为 Databricks 的新创企业[`databricks.com/`](https://databricks.com/)，它提供基于 Web 控制台的 Spark 集群管理，以及许多其他功能。它提供了笔记本组织的工作思路，用户访问控制、安全性和大量其他功能。这些内容在本书的最后进行了描述。

它目前只在亚马逊 AWS 上提供基于云的存储服务，但将来可能会扩展到谷歌和微软 Azure。其他基于云的提供商，即谷歌和微软 Azure，也在扩展他们的服务，以便他们可以在云中提供 Apache Spark 处理。

# 集群设计

正如我之前提到的，Apache Spark 是一个分布式、内存中、并行处理系统，需要一个关联的存储机制。因此，当你构建一个大数据集群时，你可能会使用分布式存储系统，比如 Hadoop，以及用于数据移动的工具，如 Sqoop、Flume 和 Kafka。

我想介绍大数据集群中边缘节点的概念。集群中的这些节点将面向客户端，上面有像 Hadoop NameNode 或者 Spark 主节点这样的客户端组件。大多数大数据集群可能在防火墙后面。边缘节点将减少防火墙带来的复杂性，因为它们是唯一可访问的节点。下图显示了一个简化的大数据集群：

![集群设计](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_01_02.jpg)

它显示了四个简化的集群机架，带有交换机和边缘节点计算机，面向防火墙的客户端。当然，这是风格化和简化的，但你明白了。一般处理节点隐藏在防火墙后面（虚线），可用于一般处理，比如 Hadoop、Apache Spark、Zookeeper、Flume 和/或 Kafka。下图代表了一些大数据集群边缘节点，并试图展示可能驻留在它们上面的应用程序。

边缘节点应用程序将是类似于 Hadoop NameNode 或 Apache Spark 主服务器的主应用程序。它将是将数据带入和带出集群的组件，比如 Flume、Sqoop 和 Kafka。它可以是任何使用户界面对客户用户可用的组件，类似于 Hive：

![集群设计](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_01_03.jpg)

通常，防火墙在增加集群安全性的同时也增加了复杂性。系统组件之间的端口需要打开，以便它们可以相互通信。例如，Zookeeper 被许多组件用于配置。Apache Kafka，发布订阅消息系统，使用 Zookeeper 来配置其主题、组、消费者和生产者。因此，潜在地需要打开防火墙的客户端端口到 Zookeeper。

最后，需要考虑将系统分配给集群节点。例如，如果 Apache Spark 使用 Flume 或 Kafka，则将使用内存通道。需要考虑这些通道的大小和由数据流引起的内存使用。Apache Spark 不应该与其他 Apache 组件竞争内存使用。根据您的数据流和内存使用情况，可能需要在不同的集群节点上拥有 Spark、Hadoop、Zookeeper、Flume 和其他工具。

通常，作为集群 NameNode 服务器或 Spark 主服务器的边缘节点将需要比防火墙内的集群处理节点更多的资源。例如，CDH 集群节点管理器服务器将需要额外的内存，同样 Spark 主服务器也是如此。您应该监视边缘节点的资源使用情况，并根据需要调整资源和/或应用程序位置。

本节简要介绍了 Apache Spark、Hadoop 和其他工具在大数据集群中的情景。然而，在大数据集群中，Apache Spark 集群本身如何配置呢？例如，可以有多种类型的 Spark 集群管理器。下一节将对此进行探讨，并描述每种类型的 Apache Spark 集群管理器。

# 集群管理

下图从 spark.apache.org 网站借来，展示了 Apache Spark 集群管理器在主节点、从节点（工作节点）、执行器和 Spark 客户端应用程序方面的作用：

![集群管理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_01_04.jpg)

正如您将从本书的许多示例中看到的那样，Spark 上下文可以通过 Spark 配置对象和 Spark URL 来定义。Spark 上下文连接到 Spark 集群管理器，然后为应用程序在工作节点之间分配资源。集群管理器在集群工作节点之间分配执行器。它将应用程序 jar 文件复制到工作节点，最后分配任务。

以下小节描述了目前可用的可能的 Apache Spark 集群管理器选项。

## 本地

通过指定一个 Spark 配置本地 URL，可以让应用程序在本地运行。通过指定 local[n]，可以让 Spark 使用`<n>`个线程在本地运行应用程序。这是一个有用的开发和测试选项。

## 独立模式

独立模式使用了 Apache Spark 提供的基本集群管理器。Spark 主 URL 将如下所示：

```scala
Spark://<hostname>:7077

```

在这里，`<hostname>`是运行 Spark 主节点的主机名。我已经指定了端口`7077`，这是默认值，但它是可配置的。目前，这个简单的集群管理器只支持 FIFO（先进先出）调度。您可以通过为每个应用程序设置资源配置选项来构建允许并发应用程序调度。例如，使用`spark.core.max`来在应用程序之间共享核心。

## Apache YARN

在与 Hadoop YARN 集成的较大规模下，Apache Spark 集群管理器可以是 YARN，并且应用程序可以在两种模式下运行。如果将 Spark 主值设置为 yarn-cluster，那么应用程序可以提交到集群，然后终止。集群将负责分配资源和运行任务。然而，如果应用程序主作为 yarn-client 提交，那么应用程序在处理的生命周期内保持活动，并从 YARN 请求资源。

## Apache Mesos

Apache Mesos 是一个用于跨集群共享资源的开源系统。它允许多个框架通过管理和调度资源来共享集群。它是一个集群管理器，使用 Linux 容器提供隔离，允许多个系统（如 Hadoop、Spark、Kafka、Storm 等）安全地共享集群。它可以高度扩展到数千个节点。它是一个基于主从的系统，并且具有容错性，使用 Zookeeper 进行配置管理。

对于单个主节点 Mesos 集群，Spark 主 URL 将采用以下形式：

```scala
Mesos://<hostname>:5050

```

其中`<hostname>`是 Mesos 主服务器的主机名，端口被定义为`5050`，这是 Mesos 主端口的默认值（可配置）。如果在大规模高可用性 Mesos 集群中有多个 Mesos 主服务器，则 Spark 主 URL 将如下所示：

```scala
Mesos://zk://<hostname>:2181

```

因此，Mesos 主服务器的选举将由 Zookeeper 控制。`<hostname>`将是 Zookeeper quorum 中的主机名。此外，端口号`2181`是 Zookeeper 的默认主端口。

## Amazon EC2

Apache Spark 发行版包含用于在亚马逊 AWS EC2 基础服务器上运行 Spark 的脚本。以下示例显示了在 Linux CentOS 服务器上安装的 Spark 1.3.1，位于名为`/usr/local/spark/`的目录下。Spark 发行版 EC2 子目录中提供了 EC2 资源：

```scala
[hadoop@hc2nn ec2]$ pwd

/usr/local/spark/ec2

[hadoop@hc2nn ec2]$ ls
deploy.generic  README  spark-ec2  spark_ec2.py

```

要在 EC2 上使用 Apache Spark，您需要设置一个 Amazon AWS 帐户。您可以在此处设置一个初始免费帐户来尝试：[`aws.amazon.com/free/`](http://aws.amazon.com/free/)。

如果您查看第八章*Spark Databricks*，您会看到已经设置了这样一个帐户，并且用于访问[`databricks.com/`](https://databricks.com/)。接下来，您需要访问 AWS IAM 控制台，并选择**用户**选项。您可以创建或选择一个用户。选择**用户操作**选项，然后选择**管理访问密钥**。然后，选择**创建访问密钥**，然后**下载凭据**。确保您下载的密钥文件是安全的，假设您在 Linux 上，使用`chmod`命令将文件权限设置为`600`，以便仅用户访问。

现在您已经拥有了**访问密钥 ID**、**秘密访问密钥**、密钥文件和密钥对名称。您现在可以使用`spark-ec2`脚本创建一个 Spark EC2 集群，如下所示：

```scala
export AWS_ACCESS_KEY_ID="QQpl8Exxx"
export AWS_SECRET_ACCESS_KEY="0HFzqt4xxx"

./spark-ec2  \
 --key-pair=pairname \
 --identity-file=awskey.pem \
 --region=us-west-1 \
 --zone=us-west-1a  \
 launch cluster1

```

在这里，`<pairname>`是在创建访问详细信息时给出的密钥对名称；`<awskey.pem>`是您下载的文件。您要创建的集群的名称称为`<cluster1>`。此处选择的区域位于美国西部，`us-west-1`。如果您像我一样住在太平洋地区，可能更明智的选择一个更近的区域，如`ap-southeast-2`。但是，如果遇到访问问题，则需要尝试另一个区域。还要记住，像这样使用基于云的 Spark 集群将具有更高的延迟和较差的 I/O 性能。您与多个用户共享集群主机，您的集群可能位于远程地区。

您可以使用一系列选项来配置您创建的基于云的 Spark 集群。`-s`选项可以使用：

```scala
-s <slaves>

```

这允许您定义在您的 Spark EC2 集群中创建多少个工作节点，即`-s 5`表示六个节点集群，一个主节点和五个从节点。您可以定义您的集群运行的 Spark 版本，而不是默认的最新版本。以下选项启动了一个带有 Spark 版本 1.3.1 的集群：

```scala
--spark-version=1.3.1

```

用于创建集群的实例类型将定义使用多少内存和可用多少核心。例如，以下选项将将实例类型设置为`m3.large`：

```scala
--instance-type=m3.large

```

Amazon AWS 的当前实例类型可以在[`aws.amazon.com/ec2/instance-types/`](http://aws.amazon.com/ec2/instance-types/)找到。

下图显示了当前（截至 2015 年 7 月）AWS M3 实例类型、型号细节、核心、内存和存储。目前有许多实例类型可用；例如 T2、M4、M3、C4、C3、R3 等。检查当前可用性并选择适当的：

![Amazon EC2](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_01_05.jpg)

定价也非常重要。当前 AWS 存储类型的价格可以在此找到：[`aws.amazon.com/ec2/pricing/`](http://aws.amazon.com/ec2/pricing/)。

价格按地区显示，并有一个下拉菜单和按小时计价。请记住，每种存储类型都由核心、内存和物理存储定义。价格也由操作系统类型定义，即 Linux、RHEL 和 Windows。只需通过顶级菜单选择操作系统。

下图显示了写作时（2015 年 7 月）的定价示例；它只是提供一个想法。价格会随时间而变化，而且会因服务提供商而异。它们会根据你需要的存储大小和你愿意承诺的时间长度而有所不同。

还要注意将数据从任何存储平台移出的成本。尽量考虑长期。检查你是否需要在未来五年将所有或部分基于云的数据移动到下一个系统。检查移动数据的过程，并将该成本纳入你的规划中。

![Amazon EC2](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_01_06.jpg)

如前所述，上图显示了 AWS 存储类型的成本，按操作系统、地区、存储类型和小时计价。成本是按单位小时计算的，因此像[`databricks.com/`](https://databricks.com/)这样的系统在完整的小时过去之前不会终止 EC2 实例。这些成本会随时间变化，需要通过（对于 AWS）AWS 计费控制台进行监控。

当你想要调整你的 Spark EC2 集群大小时，你需要确保在开始之前确定主从配置。确定你需要多少工作节点和需要多少内存。如果你觉得你的需求会随着时间改变，那么你可能会考虑使用[`databricks.com/`](https://databricks.com/)，如果你确实希望在云中使用 Spark。前往第八章 *Spark Databricks*，看看你如何设置和使用[`databricks.com/`](https://databricks.com/)。

在接下来的部分，我将研究 Apache Spark 集群性能以及可能影响它的问题。

# 性能

在继续涵盖 Apache Spark 的其他章节之前，我想要研究性能领域。需要考虑哪些问题和领域？什么可能会影响从集群级别开始到实际 Scala 代码结束的 Spark 应用程序性能？我不想只是重复 Spark 网站上的内容，所以请查看以下网址：`http://spark.apache.org/docs/<version>/tuning.html`。

在这里，`<version>`指的是你正在使用的 Spark 版本，即最新版本或特定版本的 1.3.1。因此，在查看了该页面之后，我将简要提及一些主题领域。在本节中，我将列出一些一般要点，而不意味着重要性的顺序。

## 集群结构

你的大数据集群的大小和结构将影响性能。如果你有一个基于云的集群，你的 IO 和延迟会与未共享硬件的集群相比受到影响。你将与多个客户共享基础硬件，并且集群硬件可能是远程的。

此外，集群组件在服务器上的定位可能会导致资源争用。例如，如果可能的话，仔细考虑在大集群中定位 Hadoop NameNodes、Spark 服务器、Zookeeper、Flume 和 Kafka 服务器。在高工作负载下，你可能需要考虑将服务器分隔到单独的系统中。你可能还需要考虑使用 Apache 系统，如 Mesos，以共享资源。

另外，考虑潜在的并行性。对于大数据集，Spark 集群中的工作节点数量越多，就越有并行处理的机会。

## Hadoop 文件系统

根据您的集群需求，您可能考虑使用 HDFS 的替代方案。例如，MapR 具有基于 MapR-FS NFS 的读写文件系统，可提高性能。该文件系统具有完整的读写功能，而 HDFS 设计为一次写入，多次读取的文件系统。它比 HDFS 性能更好。它还与 Hadoop 和 Spark 集群工具集成。MapR 的架构师 Bruce Penn 撰写了一篇有趣的文章，描述了其特性：[`www.mapr.com/blog/author/bruce-penn`](https://www.mapr.com/blog/author/bruce-penn)。

只需查找名为“比较 MapR-FS 和 HDFS NFS 和快照”的博客文章。文章中的链接描述了 MapR 架构和可能的性能提升。

## 数据本地性

数据本地性或正在处理的数据的位置将影响延迟和 Spark 处理。数据是来自 AWS S3、HDFS、本地文件系统/网络还是远程来源？

如前面的调整链接所述，如果数据是远程的，那么功能和数据必须被整合在一起进行处理。Spark 将尝试使用最佳的数据本地性级别来进行任务处理。

## 内存

为了避免在 Apache Spark 集群上出现**OOM**（**内存不足**）消息，您可以考虑以下几个方面：

+   考虑 Spark 工作节点上可用的物理内存级别。能增加吗？

+   考虑数据分区。您能增加 Spark 应用程序代码中使用的数据分区数量吗？

+   您能增加存储分数，即 JVM 用于存储和缓存 RDD 的内存使用吗？

+   考虑调整用于减少内存的数据结构。

+   考虑将 RDD 存储序列化以减少内存使用。

## 编码

尝试调整代码以提高 Spark 应用程序的性能。例如，在 ETL 周期的早期筛选应用程序数据。调整并行度，尝试找到代码中资源密集型的部分，并寻找替代方案。

# 云

尽管本书大部分内容将集中在安装在基于物理服务器的集群上的 Apache Spark 的示例上（除了[`databricks.com/`](https://databricks.com/)），我想指出有多种基于云的选项。有一些基于云的系统将 Apache Spark 作为集成组件，还有一些基于云的系统提供 Spark 作为服务。尽管本书无法对所有这些进行深入介绍，但我认为提到其中一些可能会有用：

+   本书的两章涵盖了 Databricks。它提供了一个基于 Spark 的云服务，目前使用 AWS EC2。计划将该服务扩展到其他云供应商（[`databricks.com/`](https://databricks.com/)）。

+   在撰写本书时（2015 年 7 月），微软 Azure 已扩展到提供 Spark 支持。

+   Apache Spark 和 Hadoop 可以安装在 Google Cloud 上。

+   Oryx 系统是基于 Spark 和 Kafka 构建的实时大规模机器学习系统（[`oryx.io/`](http://oryx.io/)）。

+   用于提供机器学习预测的 velox 系统基于 Spark 和 KeystoneML（[`github.com/amplab/velox-modelserver`](https://github.com/amplab/velox-modelserver)）。

+   PredictionIO 是建立在 Spark、HBase 和 Spray 上的开源机器学习服务（[`prediction.io/`](https://prediction.io/)）。

+   SeldonIO 是一个基于 Spark、Kafka 和 Hadoop 的开源预测分析平台（[`www.seldon.io/`](http://www.seldon.io/)）。

# 总结

在结束本章时，我想邀请你逐个阅读以下章节中基于 Scala 代码的示例。我对 Apache Spark 的发展速度印象深刻，也对其发布频率印象深刻。因此，即使在撰写本文时，Spark 已经达到 1.4 版本，我相信你将使用更新的版本。如果遇到问题，请以逻辑方式解决。尝试向 Spark 用户组寻求帮助（`<user@spark.apache.org>`），或者查看 Spark 网站：[`spark.apache.org/`](http://spark.apache.org/)。

我一直对与人交流感兴趣，也愿意在 LinkedIn 等网站上与人联系。我渴望了解人们参与的项目和新机遇。我对 Apache Spark、你使用它的方式以及你构建的系统在规模上的应用很感兴趣。你可以通过 LinkedIn 联系我：[linkedin.com/profile/view?id=73219349](http://linkedin.com/profile/view?id=73219349)。

或者，你可以通过我的网站联系我：[`semtech-solutions.co.nz/`](http://semtech-solutions.co.nz)，最后，也可以通过电子邮件联系我：`<info@semtech-solutions.co.nz>`。


# 第二章：Apache Spark MLlib

MLlib 是 Apache Spark 提供的机器学习库，它是基于内存的开源数据处理系统。在本章中，我将研究 MLlib 库提供的回归、分类和神经处理等领域的功能。我将在提供解决实际问题的工作示例之前，先研究每个算法背后的理论。网络上的示例代码和文档可能稀少且令人困惑。我将采用逐步的方法来描述以下算法的用法和能力。

+   朴素贝叶斯分类

+   K-Means 聚类

+   ANN 神经处理

在决定学习 Apache Spark 之前，我假设你对 Hadoop 很熟悉。在继续之前，我将简要介绍一下我的环境。我的 Hadoop 集群安装在一组 Centos 6.5 Linux 64 位服务器上。接下来的部分将详细描述架构。

# 环境配置

在深入研究 Apache Spark 模块之前，我想解释一下我在本书中将使用的 Hadoop 和 Spark 集群的结构和版本。我将在本章中使用 Cloudera CDH 5.1.3 版本的 Hadoop 进行存储，并且我将使用两个版本的 Spark：1.0 和 1.3。

早期版本与 Cloudera 软件兼容，并经过了他们的测试和打包。它是作为一组 Linux 服务从 Cloudera 仓库使用 yum 命令安装的。因为我想要研究尚未发布的神经网络技术，我还将从 GitHub 下载并运行 Spark 1.3 的开发版本。这将在本章后面进行解释。

## 架构

以下图表解释了我将在本章中使用的小型 Hadoop 集群的结构：

![架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_01.jpg)

前面的图表显示了一个包含 NameNode（称为 hc2nn）和 DataNodes（hc2r1m1 到 hc2r1m4）的五节点 Hadoop 集群。它还显示了一个包含一个主节点和四个从节点的 Apache Spark 集群。Hadoop 集群提供了物理 Centos 6 Linux 机器，而 Spark 集群运行在同一台主机上。例如，Spark 主服务器运行在 Hadoop NameNode 机器 hc2nn 上，而 Spark 从节点 1 运行在主机 hc2r1m1 上。

Linux 服务器命名标准应该解释得更清楚。例如，Hadoop NameNode 服务器被称为 hc2nn。这个服务器名字中的 h 代表 Hadoop，c 代表集群，nn 代表 NameNode。因此，hc2nn 代表 Hadoop 集群 2 的 NameNode。同样，对于服务器 hc2r1m1，h 代表 Hadoop，c 代表集群，r 代表机架，m 代表机器。因此，这个名字代表 Hadoop 集群 2 的机架 1 的机器 1。在一个大型的 Hadoop 集群中，机器会被组织成机架，因此这种命名标准意味着服务器很容易被定位。

你可以根据自己的需要安排 Spark 和 Hadoop 集群，它们不需要在同一台主机上。为了撰写本书，我只有有限的机器可用，因此将 Hadoop 和 Spark 集群放在同一台主机上是有意义的。你可以为每个集群使用完全独立的机器，只要 Spark 能够访问 Hadoop（如果你想用它来进行分布式存储）。

请记住，尽管 Spark 用于其内存分布式处理的速度，但它并不提供存储。你可以使用主机文件系统来读写数据，但如果你的数据量足够大，可以被描述为大数据，那么使用像 Hadoop 这样的分布式存储系统是有意义的。

还要记住，Apache Spark 可能只是**ETL**（**提取**，**转换**，**加载**）链中的处理步骤。它并不提供 Hadoop 生态系统所包含的丰富工具集。您可能仍然需要 Nutch/Gora/Solr 进行数据采集；Sqoop 和 Flume 用于数据传输；Oozie 用于调度；HBase 或 Hive 用于存储。我要说明的是，尽管 Apache Spark 是一个非常强大的处理系统，但它应被视为更广泛的 Hadoop 生态系统的一部分。

在描述了本章将使用的环境之后，我将继续描述 Apache Spark **MLlib**（**机器学习库**）的功能。

## 开发环境

本书中的编码示例将使用 Scala 语言。这是因为作为一种脚本语言，它产生的代码比 Java 少。它也可以用于 Spark shell，并与 Apache Spark 应用程序一起编译。我将使用 sbt 工具来编译 Scala 代码，安装方法如下：

```scala
[hadoop@hc2nn ~]# su -
[root@hc2nn ~]# cd /tmp
[root@hc2nn ~]#wget http://repo.scala-sbt.org/scalasbt/sbt-native-packages/org/scala-sbt/sbt/0.13.1/sbt.rpm
[root@hc2nn ~]# rpm -ivh sbt.rpm

```

为了方便撰写本书，我在 Hadoop NameNode 服务器`hc2nn`上使用了名为**hadoop**的通用 Linux 帐户。由于前面的命令表明我需要以 root 帐户安装`sbt`，因此我通过`su`（切换用户）访问了它。然后，我使用`wget`从名为`repo.scala-sbt.org`的基于 Web 的服务器下载了`sbt.rpm`文件到`/tmp`目录。最后，我使用`rpm`命令安装了`rpm`文件，选项为`i`表示安装，`v`表示验证，`h`表示在安装包时打印哈希标记。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

我在 Linux 服务器`hc2nn`上使用 Linux hadoop 帐户为 Apache Spark 开发了所有 Scala 代码。我将每组代码放在`/home/hadoop/spark`目录下的子目录中。例如，以下 sbt 结构图显示了 MLlib 朴素贝叶斯代码存储在`spark`目录下名为`nbayes`的子目录中。图表还显示了 Scala 代码是在名为`src/main/scala`的子目录结构下开发的。文件`bayes1.scala`和`convert.scala`包含了下一节将使用的朴素贝叶斯代码：

![开发环境](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_02.jpg)

`bayes.sbt`文件是 sbt 工具使用的配置文件，描述了如何编译`Scala`目录中的 Scala 文件（还要注意，如果您在 Java 中开发，您将使用形式为`nbayes/src/main/java`的路径）。下面显示了`bayes.sbt`文件的内容。`pwd`和`cat` Linux 命令提醒您文件位置，并提醒您转储文件内容。

名称、版本和`scalaVersion`选项设置了项目的详细信息，以及要使用的 Scala 版本。`libraryDependencies`选项定义了 Hadoop 和 Spark 库的位置。在这种情况下，使用 Cloudera parcels 安装了 CDH5，并且包库可以在标准位置找到，即 Hadoop 的`/usr/lib/hadoop`和 Spark 的`/usr/lib/spark`。解析器选项指定了 Cloudera 存储库的位置以获取其他依赖项：

```scala
[hadoop@hc2nn nbayes]$ pwd
/home/hadoop/spark/nbayes
[hadoop@hc2nn nbayes]$ cat bayes.sbt

name := "Naive Bayes"

version := "1.0"

scalaVersion := "2.10.4"

libraryDependencies += "org.apache.hadoop" % "hadoop-client" % "2.3.0"

libraryDependencies += "org.apache.spark" %% "spark-core"  % "1.0.0"

libraryDependencies += "org.apache.spark" %% "spark-mllib" % "1.0.0"

// If using CDH, also add Cloudera repo
resolvers += "Cloudera Repository" at https://repository.cloudera.com/artifactory/cloudera-repos/

```

Scala nbayes 项目代码可以使用以下命令从`nbayes`子目录编译：

```scala
[hadoop@hc2nn nbayes]$ sbt compile

```

使用` sbt compile`命令将代码编译成类。然后将类放置在`nbayes/target/scala-2.10/classes`目录中。可以使用以下命令将编译后的类打包成 JAR 文件：

```scala
[hadoop@hc2nn nbayes]$ sbt package

```

`Sbt package`命令将在目录`nbayes/target/scala-2.10`下创建一个 JAR 文件。正如*sbt 结构图*中的示例所示，成功编译和打包后，创建了名为`naive-bayes_2.10-1.0.jar`的 JAR 文件。然后，可以在`spark-submit`命令中使用此 JAR 文件及其包含的类。随后将在探索 Apache Spark MLlib 模块中描述此功能。

## 安装 Spark

最后，当描述用于本书的环境时，我想谈谈安装和运行 Apache Spark 的方法。我不会详细说明 Hadoop CDH5 的安装，只是说我使用 Cloudera parcels 进行了安装。但是，我手动从 Cloudera 存储库安装了 Apache Spark 的 1.0 版本，使用了 Linux 的`yum`命令。我安装了基于服务的软件包，因为我希望能够灵活安装 Cloudera 的多个版本的 Spark 作为服务，根据需要进行安装。

在准备 CDH Hadoop 版本时，Cloudera 使用 Apache Spark 团队开发的代码和 Apache Bigtop 项目发布的代码。他们进行集成测试，以确保作为代码堆栈工作。他们还将代码和二进制文件重新组织为服务和包。这意味着库、日志和二进制文件可以位于 Linux 下的定义位置，即`/var/log/spark`、`/usr/lib/spark`。这也意味着，在服务的情况下，可以使用 Linux 的`yum`命令安装组件，并通过 Linux 的`service`命令进行管理。

尽管在本章后面描述的神经网络代码的情况下，使用了不同的方法。这是如何安装 Apache Spark 1.0 以与 Hadoop CDH5 一起使用的：

```scala
[root@hc2nn ~]# cd /etc/yum.repos.d
[root@hc2nn yum.repos.d]# cat  cloudera-cdh5.repo

[cloudera-cdh5]
# Packages for Cloudera's Distribution for Hadoop, Version 5, on RedHat or CentOS 6 x86_64
name=Cloudera's Distribution for Hadoop, Version 5
baseurl=http://archive.cloudera.com/cdh5/redhat/6/x86_64/cdh/5/
gpgkey = http://archive.cloudera.com/cdh5/redhat/6/x86_64/cdh/RPM-GPG-KEY-cloudera
gpgcheck = 1

```

第一步是确保在服务器`hc2nn`和所有其他 Hadoop 集群服务器的`/etc/yum.repos.d`目录下存在 Cloudera 存储库文件。该文件名为`cloudera-cdh5.repo`，并指定 yum 命令可以定位 Hadoop CDH5 集群软件的位置。在所有 Hadoop 集群节点上，我使用 Linux 的 yum 命令，以 root 身份，安装 Apache Spark 组件核心、主、工作、历史服务器和 Python：

```scala
[root@hc2nn ~]# yum install spark-core spark-master spark-worker spark-history-server spark-python

```

这使我能够在将来以任何我想要的方式配置 Spark。请注意，我已经在所有节点上安装了主组件，尽管我目前只打算从 Name Node 上使用它。现在，需要在所有节点上配置 Spark 安装。配置文件存储在`/etc/spark/conf`下。首先要做的事情是设置一个`slaves`文件，指定 Spark 将在哪些主机上运行其工作组件：

```scala
[root@hc2nn ~]# cd /etc/spark/conf

[root@hc2nn conf]# cat slaves
# A Spark Worker will be started on each of the machines listed below.
hc2r1m1
hc2r1m2
hc2r1m3
hc2r1m4

```

从上面的`slaves`文件的内容可以看出，Spark 将在 Hadoop CDH5 集群的四个工作节点 Data Nodes 上运行，从`hc2r1m1`到`hc2r1m4`。接下来，将更改`spark-env.sh`文件的内容以指定 Spark 环境选项。`SPARK_MASTER_IP`的值被定义为完整的服务器名称：

```scala
export STANDALONE_SPARK_MASTER_HOST=hc2nn.semtech-solutions.co.nz
export SPARK_MASTER_IP=$STANDALONE_SPARK_MASTER_HOST

export SPARK_MASTER_WEBUI_PORT=18080
export SPARK_MASTER_PORT=7077
export SPARK_WORKER_PORT=7078
export SPARK_WORKER_WEBUI_PORT=18081

```

主和工作进程的 Web 用户界面端口号已经指定，以及操作端口号。然后，Spark 服务可以从 Name Node 服务器以 root 身份启动。我使用以下脚本：

```scala
echo "hc2r1m1 - start worker"
ssh   hc2r1m1 'service spark-worker start'

echo "hc2r1m2 - start worker"
ssh   hc2r1m2 'service spark-worker start'

echo "hc2r1m3 - start worker"
ssh   hc2r1m3 'service spark-worker start'

echo "hc2r1m4 - start worker"
ssh   hc2r1m4 'service spark-worker start'

echo "hc2nn - start master server"
service spark-master         start
service spark-history-server start

```

这将在所有从节点上启动 Spark 工作服务，并在 Name Node `hc2nn`上启动主和历史服务器。因此，现在可以使用`http://hc2nn:18080` URL 访问 Spark 用户界面。

以下图显示了 Spark 1.0 主节点 Web 用户界面的示例。它显示了有关 Spark 安装、工作节点和正在运行或已完成的应用程序的详细信息。给出了主节点和工作节点的状态。在这种情况下，所有节点都是活动的。显示了总内存使用情况和可用情况，以及按工作节点的情况。尽管目前没有应用程序在运行，但可以选择每个工作节点链接以查看在每个工作节点上运行的执行器进程，因为每个应用程序运行的工作量都分布在 Spark 集群中。

还要注意 Spark URL，`spark://hc2nn.semtech-solutions.co.nz:7077`，在运行 Spark 应用程序（如`spark-shell`和`spark-submit`）时将被使用。使用此 URL，可以确保对该 Spark 集群运行 shell 或应用程序。

![安装 Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_03.jpg)

这快速概述了使用服务的 Apache Spark 安装、其配置、如何启动以及如何监视。现在，是时候着手处理 MLlib 功能领域中的第一个部分，即使用朴素贝叶斯算法进行分类。随着 Scala 脚本的开发和生成的应用程序的监视，Spark 的使用将变得更加清晰。

# 朴素贝叶斯分类

本节将提供 Apache Spark MLlib 朴素贝叶斯算法的工作示例。它将描述算法背后的理论，并提供一个 Scala 的逐步示例，以展示如何使用该算法。

## 理论

为了使用朴素贝叶斯算法对数据集进行分类，数据必须是线性可分的，也就是说，数据中的类必须能够通过类边界进行线性划分。以下图形通过三个数据集和两个虚线所示的类边界来直观解释这一点：

![理论](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_04.jpg)

朴素贝叶斯假设数据集中的特征（或维度）彼此独立，即它们互不影响。Hernan Amiune 在[`hernan.amiune.com/`](http://hernan.amiune.com/)提供了朴素贝叶斯的一个例子。以下例子考虑将电子邮件分类为垃圾邮件。如果你有 100 封电子邮件，那么执行以下操作：

```scala
60% of emails are spam
 80% of spam emails contain the word buy
 20% of spam emails don't contain the word buy
40% of emails are not spam
 10% of non spam emails contain the word buy
 90% of non spam emails don't contain the word buy

```

因此，将这个例子转换为概率，以便创建一个朴素贝叶斯方程。

```scala
P(Spam) = the probability that an email is spam = 0.6
P(Not Spam) = the probability that an email is not spam = 0.4
P(Buy|Spam) = the probability that an email that is spam has the word buy = 0.8
P(Buy|Not Spam) = the probability that an email that is not spam has the word buy = 0.1

```

那么，包含单词“buy”的电子邮件是垃圾邮件的概率是多少？这将被写成**P(垃圾邮件|Buy)**。朴素贝叶斯表示它由以下图中的方程描述：

![理论](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_05.jpg)

因此，使用先前的百分比数据，我们得到以下结果：

```scala
P(Spam|Buy) = ( 0.8 * 0.6 ) / (( 0.8 * 0.6 )  + ( 0.1 * 0.4 )  )  = ( .48 ) / ( .48 + .04 )
= .48 / .52 = .923

```

这意味着包含单词“buy”的电子邮件更有可能是垃圾邮件，概率高达 92%。这是对理论的一瞥；现在，是时候尝试使用 Apache Spark MLlib 朴素贝叶斯算法进行一个真实世界的例子了。

## 实践中的朴素贝叶斯

第一步是选择一些用于分类的数据。我选择了来自英国政府数据网站的一些数据，可在[`data.gov.uk/dataset/road-accidents-safety-data`](http://data.gov.uk/dataset/road-accidents-safety-data)上找到。

数据集名为“道路安全-2013 年数字酒精测试数据”，下载一个名为`DigitalBreathTestData2013.txt`的压缩文本文件。该文件包含大约 50 万行数据。数据如下所示：

```scala
Reason,Month,Year,WeekType,TimeBand,BreathAlcohol,AgeBand,Gender
Suspicion of Alcohol,Jan,2013,Weekday,12am-4am,75,30-39,Male
Moving Traffic Violation,Jan,2013,Weekday,12am-4am,0,20-24,Male
Road Traffic Collision,Jan,2013,Weekend,12pm-4pm,0,20-24,Female

```

为了对数据进行分类，我修改了列布局和列数。我只是使用 Excel 来给出数据量。但是，如果我的数据量达到了大数据范围，我可能需要使用 Scala，或者像 Apache Pig 这样的工具。如下命令所示，数据现在存储在 HDFS 上，目录名为`/data/spark/nbayes`。文件名为`DigitalBreathTestData2013- MALE2.csv`。此外，来自 Linux `wc`命令的行数显示有 467,000 行。最后，以下数据样本显示我已经选择了列：Gender, Reason, WeekType, TimeBand, BreathAlcohol 和 AgeBand 进行分类。我将尝试使用其他列作为特征对 Gender 列进行分类：

```scala
[hadoop@hc2nn ~]$ hdfs dfs -cat /data/spark/nbayes/DigitalBreathTestData2013-MALE2.csv | wc -l
467054

[hadoop@hc2nn ~]$ hdfs dfs -cat /data/spark/nbayes/DigitalBreathTestData2013-MALE2.csv | head -5
Male,Suspicion of Alcohol,Weekday,12am-4am,75,30-39
Male,Moving Traffic Violation,Weekday,12am-4am,0,20-24
Male,Suspicion of Alcohol,Weekend,4am-8am,12,40-49
Male,Suspicion of Alcohol,Weekday,12am-4am,0,50-59
Female,Road Traffic Collision,Weekend,12pm-4pm,0,20-24

```

Apache Spark MLlib 分类函数使用一个名为`LabeledPoint`的数据结构，这是一个通用的数据表示，定义在：[`spark.apache.org/docs/1.0.0/api/scala/index.html#org.apache.spark.mllib.regression.LabeledPoint`](http://spark.apache.org/docs/1.0.0/api/scala/index.html#org.apache.spark.mllib.regression.LabeledPoint)。

这个结构只接受 Double 值，这意味着前面数据中的文本值需要被分类为数字。幸运的是，数据中的所有列都将转换为数字类别，我已经在本书的软件包中提供了两个程序，在`chapter2\naive bayes`目录下。第一个叫做`convTestData.pl`，是一个 Perl 脚本，用于将以前的文本文件转换为 Linux。第二个文件，将在这里进行检查，名为`convert.scala`。它将`DigitalBreathTestData2013- MALE2.csv`文件的内容转换为 Double 向量。

关于基于 sbt Scala 的开发环境的目录结构和文件已经在前面进行了描述。我正在使用 Linux 账户 hadoop 在 Linux 服务器`hc2nn`上开发我的 Scala 代码。接下来，Linux 的`pwd`和`ls`命令显示了我的顶级`nbayes`开发目录，其中包含`bayes.sbt`配置文件，其内容已经被检查过：

```scala
[hadoop@hc2nn nbayes]$ pwd
/home/hadoop/spark/nbayes
[hadoop@hc2nn nbayes]$ ls
bayes.sbt     target   project   src

```

接下来显示了运行朴素贝叶斯示例的 Scala 代码，在`src/main/scala`子目录下的`nbayes`目录中：

```scala
[hadoop@hc2nn scala]$ pwd
/home/hadoop/spark/nbayes/src/main/scala
[hadoop@hc2nn scala]$ ls
bayes1.scala  convert.scala

```

我们稍后将检查`bayes1.scala`文件，但首先，HDFS 上的基于文本的数据必须转换为数值 Double 值。这就是`convert.scala`文件的用途。代码如下：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf

```

这些行导入了 Spark 上下文的类，连接到 Apache Spark 集群的类，以及 Spark 配置。正在创建的对象名为`convert1`。它是一个应用程序，因为它扩展了类`App`：

```scala
object convert1 extends App
{

```

下一行创建了一个名为`enumerateCsvRecord`的函数。它有一个名为`colData`的参数，它是一个字符串数组，并返回一个字符串：

```scala
def enumerateCsvRecord( colData:Array[String]): String =
{

```

然后，该函数枚举每一列中的文本值，例如，`Male` 变成 `0`。这些数值存储在像 `colVal1` 这样的值中：

```scala
 val colVal1 =
 colData(0) match
 {
 case "Male"                          => 0
 case "Female"                        => 1
 case "Unknown"                       => 2
 case _                               => 99
 }

 val colVal2 =
 colData(1) match
 {
 case "Moving Traffic Violation"      => 0
 case "Other"                         => 1
 case "Road Traffic Collision"        => 2
 case "Suspicion of Alcohol"          => 3
 case _                               => 99
 }

 val colVal3 =
 colData(2) match
 {
 case "Weekday"                       => 0
 case "Weekend"                       => 0
 case _                               => 99
 }

 val colVal4 =
 colData(3) match
 {
 case "12am-4am"                      => 0
 case "4am-8am"                       => 1
 case "8am-12pm"                      => 2
 case "12pm-4pm"                      => 3
 case "4pm-8pm"                       => 4
 case "8pm-12pm"                      => 5
 case _                               => 99
 }

 val colVal5 = colData(4)

 val colVal6 =
 colData(5) match
 {
 case "16-19"                         => 0
 case "20-24"                         => 1
 case "25-29"                         => 2
 case "30-39"                         => 3
 case "40-49"                         => 4
 case "50-59"                         => 5
 case "60-69"                         => 6
 case "70-98"                         => 7
 case "Other"                         => 8
 case _                               => 99
 }

```

从数值列值创建一个逗号分隔的字符串`lineString`，然后返回它。函数以最终的大括号字符`}`结束。请注意，下一个创建的数据行从第一列的标签值开始，然后是一个代表数据的向量。向量是以空格分隔的，而标签与向量之间用逗号分隔。使用这两种分隔符类型可以让我稍后以两个简单的步骤处理标签和向量：

```scala
 val lineString = colVal1+","+colVal2+" "+colVal3+" "+colVal4+" "+colVal5+" "+colVal6

 return lineString
}

```

主脚本定义了 HDFS 服务器名称和路径。它定义了输入文件和输出路径，使用这些值。它使用 Spark URL 和应用程序名称创建一个新的配置。然后使用这些详细信息创建一个新的 Spark 上下文或连接：

```scala
val hdfsServer = "hdfs://hc2nn.semtech-solutions.co.nz:8020"
val hdfsPath   = "/data/spark/nbayes/"
val inDataFile  = hdfsServer + hdfsPath + "DigitalBreathTestData2013-MALE2.csv"
val outDataFile = hdfsServer + hdfsPath + "result"

val sparkMaster = "spark://hc2nn.semtech-solutions.co.nz:7077"
val appName = "Convert 1"
val sparkConf = new SparkConf()

sparkConf.setMaster(sparkMaster)
sparkConf.setAppName(appName)

val sparkCxt = new SparkContext(sparkConf)

```

使用 Spark 上下文的`textFile`方法从 HDFS 加载基于 CSV 的原始数据文件。然后打印数据行数：

```scala
val csvData = sparkCxt.textFile(inDataFile)
println("Records in  : "+ csvData.count() )

```

CSV 原始数据逐行传递给`enumerateCsvRecord`函数。返回的基于字符串的数字数据存储在`enumRddData`变量中：

```scala
 val enumRddData = csvData.map
 {
 csvLine =>
 val colData = csvLine.split(',')

 enumerateCsvRecord(colData)

 }

```

最后，打印`enumRddData`变量中的记录数，并将枚举数据保存到 HDFS 中：

```scala
 println("Records out : "+ enumRddData.count() )

 enumRddData.saveAsTextFile(outDataFile)

} // end object

```

为了将此脚本作为 Spark 应用程序运行，必须对其进行编译。这是通过`package`命令来完成的，该命令还会编译代码。以下命令是从`nbayes`目录运行的：

```scala
[hadoop@hc2nn nbayes]$ sbt package
Loading /usr/share/sbt/bin/sbt-launch-lib.bash
....
[info] Done packaging.
[success] Total time: 37 s, completed Feb 19, 2015 1:23:55 PM

```

这将导致创建的编译类被打包成一个 JAR 库，如下所示：

```scala
[hadoop@hc2nn nbayes]$ pwd
/home/hadoop/spark/nbayes
[hadoop@hc2nn nbayes]$ ls -l target/scala-2.10
total 24
drwxrwxr-x 2 hadoop hadoop  4096 Feb 19 13:23 classes
-rw-rw-r-- 1 hadoop hadoop 17609 Feb 19 13:23 naive-bayes_2.10-1.0.jar

```

现在可以使用应用程序名称、Spark URL 和创建的 JAR 文件的完整路径来运行应用程序`convert1`。一些额外的参数指定了应该使用的内存和最大核心：

```scala
spark-submit \
 --class convert1 \
 --master spark://hc2nn.semtech-solutions.co.nz:7077  \
 --executor-memory 700M \
 --total-executor-cores 100 \
 /home/hadoop/spark/nbayes/target/scala-2.10/naive-bayes_2.10-1.0.jar

```

这在 HDFS 上创建了一个名为`/data/spark/nbayes/`的数据目录，随后是包含处理过的数据的部分文件：

```scala
[hadoop@hc2nn nbayes]$  hdfs dfs -ls /data/spark/nbayes
Found 2 items
-rw-r--r--   3 hadoop supergroup   24645166 2015-01-29 21:27 /data/spark/nbayes/DigitalBreathTestData2013-MALE2.csv
drwxr-xr-x   - hadoop supergroup          0 2015-02-19 13:36 /data/spark/nbayes/result

[hadoop@hc2nn nbayes]$ hdfs dfs -ls /data/spark/nbayes/result
Found 3 items
-rw-r--r--   3 hadoop supergroup          0 2015-02-19 13:36 /data/spark/nbayes/result/_SUCCESS
-rw-r--r--   3 hadoop supergroup    2828727 2015-02-19 13:36 /data/spark/nbayes/result/part-00000
-rw-r--r--   3 hadoop supergroup    2865499 2015-02-19 13:36 /data/spark/nbayes/result/part-00001

```

在以下 HDFS `cat`命令中，我已经将部分文件数据连接成一个名为`DigitalBreathTestData2013-MALE2a.csv`的文件。然后，我使用`head`命令检查了文件的前五行，以显示它是数字的。最后，我使用`put`命令将其加载到 HDFS 中：

```scala
[hadoop@hc2nn nbayes]$ hdfs dfs -cat /data/spark/nbayes/result/part* > ./DigitalBreathTestData2013-MALE2a.csv

[hadoop@hc2nn nbayes]$ head -5 DigitalBreathTestData2013-MALE2a.csv
0,3 0 0 75 3
0,0 0 0 0 1
0,3 0 1 12 4
0,3 0 0 0 5
1,2 0 3 0 1

[hadoop@hc2nn nbayes]$ hdfs dfs -put ./DigitalBreathTestData2013-MALE2a.csv /data/spark/nbayes

```

以下 HDFS `ls`命令现在显示了存储在 HDFS 上的数字数据文件，位于`nbayes`目录中：

```scala
[hadoop@hc2nn nbayes]$ hdfs dfs -ls /data/spark/nbayes
Found 3 items
-rw-r--r--   3 hadoop supergroup   24645166 2015-01-29 21:27 /data/spark/nbayes/DigitalBreathTestData2013-MALE2.csv
-rw-r--r--   3 hadoop supergroup    5694226 2015-02-19 13:39 /data/spark/nbayes/DigitalBreathTestData2013-MALE2a.csv
drwxr-xr-x   - hadoop supergroup          0 2015-02-19 13:36 /data/spark/nbayes/result

```

现在数据已转换为数字形式，可以使用 MLlib 朴素贝叶斯算法进行处理；这就是 Scala 文件`bayes1.scala`的作用。该文件导入了与之前相同的配置和上下文类。它还导入了朴素贝叶斯、向量和 LabeledPoint 结构的 MLlib 类。这次创建的应用程序类名为`bayes1`：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf
import org.apache.spark.mllib.classification.NaiveBayes
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.regression.LabeledPoint

object bayes1 extends App
{

```

再次定义 HDFS 数据文件，并像以前一样创建一个 Spark 上下文：

```scala
 val hdfsServer = "hdfs://hc2nn.semtech-solutions.co.nz:8020"
 val hdfsPath   = "/data/spark/nbayes/"

 val dataFile = hdfsServer+hdfsPath+"DigitalBreathTestData2013-MALE2a.csv"

 val sparkMaster = "spark://hc2nn.semtech-solutions.co.nz:7077"
 val appName = "Naive Bayes 1"
 val conf = new SparkConf()
 conf.setMaster(sparkMaster)
 conf.setAppName(appName)

 val sparkCxt = new SparkContext(conf)

```

原始 CSV 数据被加载并按分隔符字符拆分。第一列成为数据将被分类的标签（`男/女`）。最后由空格分隔的列成为分类特征：

```scala
 val csvData = sparkCxt.textFile(dataFile)

 val ArrayData = csvData.map
 {
 csvLine =>
 val colData = csvLine.split(',')
 LabeledPoint(colData(0).toDouble, Vectors.dense(colData(1).split(' ').map(_.toDouble)))
 }

```

然后，数据被随机分成训练（70%）和测试（30%）数据集：

```scala
 val divData = ArrayData.randomSplit(Array(0.7, 0.3), seed = 13L)

 val trainDataSet = divData(0)
 val testDataSet  = divData(1)

```

现在可以使用先前的训练集来训练朴素贝叶斯 MLlib 函数。训练后的朴素贝叶斯模型存储在变量`nbTrained`中，然后可以用于预测测试数据的`男/女`结果标签：

```scala
 val nbTrained = NaiveBayes.train(trainDataSet)
 val nbPredict = nbTrained.predict(testDataSet.map(_.features))

```

鉴于所有数据已经包含标签，可以比较测试数据的原始和预测标签。然后可以计算准确度，以确定预测与原始标签的匹配程度：

```scala
 val predictionAndLabel = nbPredict.zip(testDataSet.map(_.label))
 val accuracy = 100.0 * predictionAndLabel.filter(x => x._1 == x._2).count() / testDataSet.count()
 println( "Accuracy : " + accuracy );
}

```

这解释了 Scala 朴素贝叶斯代码示例。现在是时候使用`spark-submit`运行编译后的`bayes1`应用程序，并确定分类准确度。参数是相同的。只是类名已经改变：

```scala
spark-submit \
 --class bayes1 \
 --master spark://hc2nn.semtech-solutions.co.nz:7077  \
 --executor-memory 700M \
 --total-executor-cores 100 \
 /home/hadoop/spark/nbayes/target/scala-2.10/naive-bayes_2.10-1.0.jar

```

Spark 集群给出的准确度只有`43`％，这似乎意味着这些数据不适合朴素贝叶斯：

```scala
Accuracy: 43.30

```

在下一个示例中，我将使用 K-Means 来尝试确定数据中存在的聚类。请记住，朴素贝叶斯需要数据类沿着类边界线性可分。使用 K-Means，将能够确定数据中的成员资格和聚类的中心位置。

# 使用 K-Means 进行聚类

这个示例将使用前一个示例中的相同测试数据，但将尝试使用 MLlib K-Means 算法在数据中找到聚类。

## 理论

K-Means 算法通过迭代尝试确定测试数据中的聚类，方法是最小化聚类中心向量的平均值与新候选聚类成员向量之间的距离。以下方程假设数据集成员的范围从**X1**到**Xn**；它还假设了从**S1**到**Sk**的**K**个聚类集，其中**K <= n**。

![Theory](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_06.jpg)

## 实际中的 K-Means

再次，K-Means MLlib 功能使用 LabeledPoint 结构来处理其数据，因此需要数值输入数据。由于本节重复使用了上一节的相同数据，我不会重新解释数据转换。在本节中在数据方面唯一的变化是，HDFS 下的处理现在将在`/data/spark/kmeans/`目录下进行。此外，K-Means 示例的 Scala 脚本转换产生的记录是逗号分隔的。

K-Means 示例的开发和处理已经在`/home/hadoop/spark/kmeans`目录下进行，以便将工作与其他开发分开。sbt 配置文件现在称为`kmeans.sbt`，与上一个示例相同，只是项目名称不同：

```scala
name := "K-Means"

```

这一部分的代码可以在软件包的`chapter2\K-Means`目录下找到。因此，查看存储在`kmeans/src/main/scala`下的`kmeans1.scala`的代码，会发生一些类似的操作。导入语句涉及到 Spark 上下文和配置。然而，这次 K-Means 功能也被从 MLlib 中导入。此外，本示例的应用程序类名已更改为`kmeans1`：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf

import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.clustering.{KMeans,KMeansModel}

object kmeans1 extends App
{

```

与上一个示例一样，正在采取相同的操作来定义数据文件——定义 Spark 配置并创建 Spark 上下文：

```scala
 val hdfsServer = "hdfs://hc2nn.semtech-solutions.co.nz:8020"
 val hdfsPath   = "/data/spark/kmeans/"

 val dataFile   = hdfsServer + hdfsPath + "DigitalBreathTestData2013-MALE2a.csv"

 val sparkMaster = "spark://hc2nn.semtech-solutions.co.nz:7077"
 val appName = "K-Means 1"
 val conf = new SparkConf()

 conf.setMaster(sparkMaster)
 conf.setAppName(appName)

 val sparkCxt = new SparkContext(conf)

```

接下来，从数据文件加载了 CSV 数据，并按逗号字符分割为变量`VectorData`：

```scala
 val csvData = sparkCxt.textFile(dataFile)
 val VectorData = csvData.map
 {
 csvLine =>
 Vectors.dense( csvLine.split(',').map(_.toDouble))
 }

```

初始化了一个 K-Means 对象，并设置了参数来定义簇的数量和确定它们的最大迭代次数：

```scala
 val kMeans = new KMeans
 val numClusters         = 3
 val maxIterations       = 50

```

为初始化模式、运行次数和 Epsilon 定义了一些默认值，这些值我需要用于 K-Means 调用，但在处理中没有变化。最后，这些参数被设置到 K-Means 对象中：

```scala
 val initializationMode  = KMeans.K_MEANS_PARALLEL
 val numRuns             = 1
 val numEpsilon          = 1e-4

 kMeans.setK( numClusters )
 kMeans.setMaxIterations( maxIterations )
 kMeans.setInitializationMode( initializationMode )
 kMeans.setRuns( numRuns )
 kMeans.setEpsilon( numEpsilon )

```

我缓存了训练向量数据以提高性能，并使用向量数据训练了 K-Means 对象以创建训练过的 K-Means 模型：

```scala
 VectorData.cache
 val kMeansModel = kMeans.run( VectorData )

```

我计算了 K-Means 成本、输入数据行数，并通过打印行语句输出了结果。成本值表示簇有多紧密地打包在一起，以及簇之间有多分离：

```scala
 val kMeansCost = kMeansModel.computeCost( VectorData )

 println( "Input data rows : " + VectorData.count() )
 println( "K-Means Cost    : " + kMeansCost )

```

接下来，我使用了 K-Means 模型来打印计算出的三个簇的簇中心作为向量：

```scala
 kMeansModel.clusterCenters.foreach{ println }

```

最后，我使用了 K-Means 模型的`predict`函数来创建簇成员预测列表。然后，我通过值来计算这些预测，以给出每个簇中数据点的计数。这显示了哪些簇更大，以及是否真的有三个簇：

```scala
 val clusterRddInt = kMeansModel.predict( VectorData )

 val clusterCount = clusterRddInt.countByValue

 clusterCount.toList.foreach{ println }

} // end object kmeans1

```

因此，为了运行这个应用程序，必须从`kmeans`子目录编译和打包，如 Linux 的`pwd`命令所示：

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

一旦这个打包成功，我检查 HDFS 以确保测试数据已准备就绪。与上一个示例一样，我使用软件包中提供的`convert.scala`文件将我的数据转换为数值形式。我将在 HDFS 目录`/data/spark/kmeans`中处理数据文件`DigitalBreathTestData2013-MALE2a.csv`：

```scala
[hadoop@hc2nn nbayes]$ hdfs dfs -ls /data/spark/kmeans
Found 3 items
-rw-r--r--   3 hadoop supergroup   24645166 2015-02-05 21:11 /data/spark/kmeans/DigitalBreathTestData2013-MALE2.csv
-rw-r--r--   3 hadoop supergroup    5694226 2015-02-05 21:48 /data/spark/kmeans/DigitalBreathTestData2013-MALE2a.csv
drwxr-xr-x   - hadoop supergroup          0 2015-02-05 21:46 /data/spark/kmeans/result

```

`spark-submit`工具用于运行 K-Means 应用程序。在这个命令中唯一的变化是，类现在是`kmeans1`：

```scala
spark-submit \
 --class kmeans1 \
 --master spark://hc2nn.semtech-solutions.co.nz:7077  \
 --executor-memory 700M \
 --total-executor-cores 100 \
 /home/hadoop/spark/kmeans/target/scala-2.10/k-means_2.10-1.0.jar

```

Spark 集群运行的输出如下所示：

```scala
Input data rows : 467054
K-Means Cost    : 5.40312223450789E7

```

先前的输出显示了输入数据量，看起来是正确的，还显示了 K-Means 成本值。接下来是三个向量，描述了具有正确维数的数据簇中心。请记住，这些簇中心向量将具有与原始向量数据相同的列数：

```scala
[0.24698249738061878,1.3015883142472253,0.005830116872250263,2.9173747788555207,1.156645130895448,3.4400290524342454]

[0.3321793984152627,1.784137241326256,0.007615970459266097,2.5831987075928917,119.58366028156011,3.8379106085083468]

[0.25247226760684494,1.702510963969387,0.006384899819416975,2.231404248000688,52.202897927594805,3.551509158139135]

```

最后，对 1 到 3 号簇的簇成员资格进行了给出，其中 1 号簇（索引 0）的成员数量最多，为`407,539`个成员向量。

```scala
(0,407539)
(1,12999)
(2,46516)

```

因此，这两个例子展示了如何使用朴素贝叶斯和 K 均值对数据进行分类和聚类。但是，如果我想对图像或更复杂的模式进行分类，并使用黑盒方法进行分类呢？下一节将介绍使用 ANN（人工神经网络）进行基于 Spark 的分类。为了做到这一点，我需要下载最新的 Spark 代码，并为 Spark 1.3 构建服务器，因为它在撰写本文时尚未正式发布。

# ANN - 人工神经网络

为了研究 Apache Spark 中的**ANN**（人工神经网络）功能，我需要从 GitHub 网站获取最新的源代码。**ANN**功能由 Bert Greevenbosch ([`www.bertgreevenbosch.nl/`](http://www.bertgreevenbosch.nl/)) 开发，并计划在 Apache Spark 1.3 中发布。撰写本文时，当前的 Spark 版本是 1.2.1，CDH 5.x 附带的 Spark 版本是 1.0。因此，为了研究这个未发布的**ANN**功能，需要获取源代码并构建成 Spark 服务器。这是我在解释一些**ANN**背后的理论之后将要做的事情。

## 理论

下图显示了左侧的一个简单的生物神经元。神经元有树突接收其他神经元的信号。细胞体控制激活，轴突将电脉冲传递给其他神经元的树突。右侧的人工神经元具有一系列加权输入：将输入分组的求和函数，以及一个触发机制（**F(Net)**），它决定输入是否达到阈值，如果是，神经元将发射：

![理论](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_07.jpg)

神经网络对嘈杂的图像和失真具有容忍性，因此在需要对潜在受损图像进行黑盒分类时非常有用。接下来要考虑的是神经元输入的总和函数。下图显示了神经元 i 的总和函数**Net**。具有加权值的神经元之间的连接包含网络的存储知识。通常，网络会有一个输入层，一个输出层和若干隐藏层。如果神经元的输入总和超过阈值，神经元将发射。

![理论](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_08.jpg)

在前述方程中，图表和关键显示了来自模式**P**的输入值被传递到网络的输入层神经元。这些值成为输入层神经元的激活值；它们是一个特例。神经元**i**的输入是神经元连接**i-j**的加权值的总和，乘以神经元**j**的激活。神经元**j**的激活（如果它不是输入层神经元）由**F(Net)**，即压缩函数给出，接下来将对其进行描述。

一个模拟神经元需要一个触发机制，决定神经元的输入是否达到了阈值。然后，它会发射以创建该神经元的激活值。这种发射或压缩功能可以用下图所示的广义 S 形函数来描述：

![理论](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_09.jpg)

该函数有两个常数：**A**和**B**；**B**影响激活曲线的形状，如前图所示。数值越大，函数越类似于开/关步骤。**A**的值设置了返回激活的最小值。在前图中为零。

因此，这提供了模拟神经元、创建权重矩阵作为神经元连接以及管理神经元激活的机制。但是网络是如何组织的呢？下图显示了一个建议的神经元架构 - 神经网络具有一个输入层的神经元，一个输出层和一个或多个隐藏层。每层中的所有神经元都与相邻层中的每个神经元相连。

![理论](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_10.jpg)

在训练期间，激活从输入层通过网络传递到输出层。然后，期望的或实际输出之间的错误或差异导致错误增量通过网络传递回来，改变权重矩阵的值。一旦达到期望的输出层向量，知识就存储在权重矩阵中，网络可以进一步训练或用于分类。

因此，神经网络背后的理论已经以反向传播的方式描述。现在是时候获取 Apache Spark 代码的开发版本，并构建 Spark 服务器，以便运行 ANN Scala 代码。

## 构建 Spark 服务器

我通常不建议在 Spark 发布之前下载和使用 Apache Spark 代码，或者在 Cloudera（用于 CDH）打包，但是对 ANN 功能进行检查的愿望，以及本书允许的时间范围，意味着我需要这样做。我从这个路径提取了完整的 Spark 代码树：

```scala
https://github.com/apache/spark/pull/1290.

```

我将这段代码存储在 Linux 服务器`hc2nn`的目录`/home/hadoop/spark/spark`下。然后我从 Bert Greevenbosch 的 GitHub 开发区域获取了 ANN 代码：

```scala
https://github.com/bgreeven/spark/blob/master/mllib/src/main/scala/org/apache/spark/mllib/ann/ArtificialNeuralNetwork.scala
https://github.com/bgreeven/spark/blob/master/mllib/src/main/scala/org/apache/spark/mllib/classification/ANNClassifier.scala

```

`ANNClassifier.scala`文件包含将被调用的公共函数。`ArtificialNeuralNetwork.scala`文件包含`ANNClassifier.scala`调用的私有 MLlib ANN 函数。我已经在服务器上安装了 Java open JDK，所以下一步是在`/home/hadoop/spark/spark/conf`路径下设置`spark-env.sh`环境配置文件。我的文件如下：

```scala
export STANDALONE_SPARK_MASTER_HOST=hc2nn.semtech-solutions.co.nz
export SPARK_MASTER_IP=$STANDALONE_SPARK_MASTER_HOST
export SPARK_HOME=/home/hadoop/spark/spark
export SPARK_LAUNCH_WITH_SCALA=0
export SPARK_MASTER_WEBUI_PORT=19080
export SPARK_MASTER_PORT=8077
export SPARK_WORKER_PORT=8078
export SPARK_WORKER_WEBUI_PORT=19081
export SPARK_WORKER_DIR=/var/run/spark/work
export SPARK_LOG_DIR=/var/log/spark
export SPARK_HISTORY_SERVER_LOG_DIR=/var/log/spark
export SPARK_PID_DIR=/var/run/spark/
export HADOOP_CONF_DIR=/etc/hadoop/conf
export SPARK_JAR_PATH=${SPARK_HOME}/assembly/target/scala-2.10/
export SPARK_JAR=${SPARK_JAR_PATH}/spark-assembly-1.3.0-SNAPSHOT-hadoop2.3.0-cdh5.1.2.jar
export JAVA_HOME=/usr/lib/jvm/java-1.7.0
export SPARK_LOCAL_IP=192.168.1.103

```

`SPARK_MASTER_IP`变量告诉集群哪个服务器是主服务器。端口变量定义了主服务器、工作服务器 web 和操作端口值。还定义了一些日志和 JAR 文件路径，以及`JAVA_HOME`和本地服务器 IP 地址。有关使用 Apache Maven 构建 Spark 的详细信息，请参阅：

```scala
http://spark.apache.org/docs/latest/building-spark.html

```

在相同目录中的 slaves 文件将像以前一样设置为四个工作服务器的名称，从`hc2r1m1`到`hc2r1m4`。

为了使用 Apache Maven 构建，我必须在我的 Linux 服务器`hc2nn`上安装`mvn`，我将在那里运行 Spark 构建。我以 root 用户的身份进行了这个操作，首先使用`wget`获取了一个 Maven 存储库文件：

```scala
wget http://repos.fedorapeople.org/repos/dchen/apache-maven/epel-apache-maven.repo -O /etc/yum.repos.d/epel-apache-maven.repo

```

然后使用`ls`长列表检查新的存储库文件是否就位。

```scala
[root@hc2nn ~]# ls -l /etc/yum.repos.d/epel-apache-maven.repo
-rw-r--r-- 1 root root 445 Mar  4  2014 /etc/yum.repos.d/epel-apache-maven.repo

```

然后可以使用 Linux 的`yum`命令安装 Maven，下面的示例展示了安装命令以及通过`ls`检查`mvn`命令是否存在。

```scala
[root@hc2nn ~]# yum install apache-maven
[root@hc2nn ~]# ls -l /usr/share/apache-maven/bin/mvn
-rwxr-xr-x 1 root root 6185 Dec 15 06:30 /usr/share/apache-maven/bin/mvn

```

我用来构建 Spark 源代码树的命令以及成功的输出如下所示。首先设置环境，然后使用`mvn`命令启动构建。添加选项以构建 Hadoop 2.3/yarn，并跳过测试。构建使用`clean`和`package`选项每次删除旧的构建文件，然后创建 JAR 文件。最后，构建输出通过`tee`命令复制到一个名为`build.log`的文件中：

```scala
cd /home/hadoop/spark/spark/conf ; . ./spark-env.sh ; cd ..

mvn  -Pyarn -Phadoop-2.3  -Dhadoop.version=2.3.0-cdh5.1.2 -DskipTests clean package | tee build.log 2>&1

[INFO] ----------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ----------------------------------------------------------
[INFO] Total time: 44:20 min
[INFO] Finished at: 2015-02-16T12:20:28+13:00
[INFO] Final Memory: 76M/925M
[INFO] ----------------------------------------------------------

```

您使用的实际构建命令将取决于您是否安装了 Hadoop 以及其版本。有关详细信息，请查看之前的*构建 Spark*，在我的服务器上构建大约需要 40 分钟。

考虑到这个构建将被打包并复制到 Spark 集群中的其他服务器，很重要的一点是所有服务器使用相同版本的 Java，否则会出现诸如以下错误：

```scala
15/02/15 12:41:41 ERROR executor.Executor: Exception in task 0.1 in stage 0.0 (TID 2)
java.lang.VerifyError: class org.apache.hadoop.hdfs.protocol.proto.ClientNamenodeProtocolProtos$GetBlockLocationsRequestProto overrides final method getUnknownFields.()Lcom/google/protobuf/UnknownFieldSet;
 at java.lang.ClassLoader.defineClass1(Native Method)

```

鉴于源代码树已经构建完成，现在需要将其捆绑并发布到 Spark 集群中的每台服务器上。考虑到这些服务器也是 CDH 集群的成员，并且已经设置了无密码 SSH 访问，我可以使用`scp`命令来发布构建好的软件。以下命令展示了将`/home/hadoop/spark`路径下的 spark 目录打包成名为`spark_bld.tar`的 tar 文件。然后使用 Linux 的`scp`命令将 tar 文件复制到每个从服务器；以下示例展示了`hc2r1m1`：

```scala
[hadoop@hc2nn spark]$ cd /home/hadoop/spark
[hadoop@hc2nn spark]$ tar cvf spark_bld.tar spark
[hadoop@hc2nn spark]$ scp ./spark_bld.tar hadoop@hc2r1m1:/home/hadoop/spark/spark_bld.tar

```

现在，打包的 Spark 构建已经在从节点上，需要进行解压。以下命令显示了服务器`hc2r1m1`的过程。tar 文件解压到与构建服务器`hc2nn`相同的目录，即`/home/hadoop/spark`：

```scala
[hadoop@hc2r1m1 ~]$ mkdir spark ; mv spark_bld.tar spark
[hadoop@hc2r1m1 ~]$ cd spark ; ls
spark_bld.tar
[hadoop@hc2r1m1 spark]$ tar xvf spark_bld.tar

```

一旦构建成功运行，并且构建的代码已经发布到从服务器，Spark 的构建版本可以从主服务器**hc2nn**启动。请注意，我已经选择了与这些服务器上安装的 Spark 版本 1.0 不同的端口号。还要注意，我将以 root 身份启动 Spark，因为 Spark 1.0 安装是在 root 帐户下管理的 Linux 服务。由于两个安装将共享日志记录和`.pid`文件位置等设施，root 用户将确保访问。这是我用来启动 Apache Spark 1.3 的脚本：

```scala
cd /home/hadoop/spark/spark/conf ;  . ./spark-env.sh ; cd ../sbin
echo "hc2nn - start master server"
./start-master.sh
echo "sleep 5000 ms"
sleep 5
echo "hc2nn - start history server"
./start-history-server.sh
echo "Start Spark slaves workers"
./start-slaves.sh

```

它执行`spark-env.sh`文件来设置环境，然后使用 Spark `sbin`目录中的脚本来启动服务。首先在`hc2nn`上启动主服务器和历史服务器，然后启动从服务器。在启动从服务器之前，我添加了延迟，因为我发现它们在主服务器准备好之前就尝试连接到主服务器。现在可以通过此 URL 访问 Spark 1.3 Web 用户界面：

```scala
http://hc2nn.semtech-solutions.co.nz:19080/

```

Spark URL 允许应用程序连接到 Spark 是这样的：

```scala
Spark Master at spark://hc2nn.semtech-solutions.co.nz:8077

```

根据 spark 环境配置文件中的端口号，Spark 现在可以与 ANN 功能一起使用。下一节将展示 ANN Scala 脚本和数据，以展示如何使用基于 Spark 的功能。

## ANN 实践

为了开始 ANN 训练，需要测试数据。鉴于这种分类方法应该擅长分类扭曲或嘈杂的图像，我决定尝试在这里对图像进行分类：

![ANN in practice](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_11.jpg)

它们是手工制作的文本文件，包含由字符 1 和 0 创建的形状块。当它们存储在 HDFS 上时，回车字符被移除，因此图像呈现为单行向量。因此，ANN 将对一系列形状图像进行分类，然后将针对添加噪声的相同图像进行测试，以确定分类是否仍然有效。有六个训练图像，它们将分别被赋予从 0.1 到 0.6 的任意训练标签。因此，如果 ANN 被呈现为封闭的正方形，它应该返回一个标签 0.1。以下图像显示了添加噪声的测试图像的示例。通过在图像中添加额外的零（0）字符创建的噪声已经被突出显示：

![ANN in practice](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_12.jpg)

由于 Apache Spark 服务器已经从之前的示例中更改，并且 Spark 库的位置也已更改，用于编译示例 ANN Scala 代码的`sbt`配置文件也必须更改。与以前一样，ANN 代码是在 Linux hadoop 帐户中的一个名为`spark/ann`的子目录中开发的。`ann.sbt`文件存在于`ann`目录中：

```scala
 [hadoop@hc2nn ann]$ pwd
/home/hadoop/spark/ann

 [hadoop@hc2nn ann]$ ls
ann.sbt    project  src  target

```

`ann.sbt`文件的内容已更改为使用 Spark 依赖项的 JAR 库文件的完整路径。这是因为新的 Apache Spark 构建 1.3 现在位于`/home/hadoop/spark/spark`下。此外，项目名称已更改为`A N N`：

```scala
name := "A N N"
version := "1.0"
scalaVersion := "2.10.4"
libraryDependencies += "org.apache.hadoop" % "hadoop-client" % "2.3.0"
libraryDependencies += "org.apache.spark" % "spark-core"  % "1.3.0" from "file:///home/hadoop/spark/spark/core/target/spark-core_2.10-1.3.0-SNAPSHOT.jar"
libraryDependencies += "org.apache.spark" % "spark-mllib" % "1.3.0" from "file:///home/hadoop/spark/spark/mllib/target/spark-mllib_2.10-1.3.0-SNAPSHOT.jar"
libraryDependencies += "org.apache.spark" % "akka" % "1.3.0" from "file:///home/hadoop/spark/spark/assembly/target/scala-2.10/spark-assembly-1.3.0-SNAPSHOT-hadoop2.3.0-cdh5.1.2.jar"

```

与以前的示例一样，要编译的实际 Scala 代码存在于名为`src/main/scala`的子目录中，如下所示。我创建了两个 Scala 程序。第一个使用输入数据进行训练，然后用相同的输入数据测试 ANN 模型。第二个使用嘈杂的数据测试训练模型，以测试扭曲数据的分类：

```scala
[hadoop@hc2nn scala]$ pwd
/home/hadoop/spark/ann/src/main/scala

[hadoop@hc2nn scala]$ ls
test_ann1.scala  test_ann2.scala

```

我将完全检查第一个 Scala 文件，然后只展示第二个文件的额外特性，因为这两个示例在训练 ANN 的时候非常相似。这里展示的代码示例可以在本书提供的软件包中找到，路径为`chapter2\ANN`。因此，要检查第一个 Scala 示例，导入语句与之前的示例类似。导入了 Spark 上下文、配置、向量和`LabeledPoint`。这次还导入了 RDD 类用于 RDD 处理，以及新的 ANN 类`ANNClassifier`。请注意，`MLlib/classification`例程广泛使用`LabeledPoint`结构作为输入数据，其中包含了应该被训练的特征和标签：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf

import org.apache.spark.mllib.classification.ANNClassifier
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.linalg._
import org.apache.spark.rdd.RDD

object testann1 extends App
{

```

在这个例子中，应用程序类被称为`testann1`。要处理的 HDFS 文件已经根据 HDFS 服务器、路径和文件名进行了定义：

```scala
 val server = "hdfs://hc2nn.semtech-solutions.co.nz:8020"
 val path   = "/data/spark/ann/"

 val data1 = server + path + "close_square.img"
 val data2 = server + path + "close_triangle.img"
 val data3 = server + path + "lines.img"
 val data4 = server + path + "open_square.img"
 val data5 = server + path + "open_triangle.img"
 val data6 = server + path + "plus.img"

```

Spark 上下文已经创建，使用了 Spark 实例的 URL，现在端口号不同了——`8077`。应用程序名称是`ANN 1`。当应用程序运行时，这将出现在 Spark Web UI 上：

```scala
 val sparkMaster = "spark://hc2nn.semtech-solutions.co.nz:8077"
 val appName = "ANN 1"
 val conf = new SparkConf()

 conf.setMaster(sparkMaster)
 conf.setAppName(appName)

 val sparkCxt = new SparkContext(conf)

```

加载基于 HDFS 的输入训练和测试数据文件。每行的值都被空格字符分割，并且数值已经转换为双精度。包含这些数据的变量然后存储在一个名为 inputs 的数组中。同时，创建了一个名为 outputs 的数组，其中包含了从 0.1 到 0.6 的标签。这些值将用于对输入模式进行分类：

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

输入和输出数据，表示输入数据特征和标签，然后被合并并转换成`LabeledPoint`结构。最后，数据被并行化以便对其进行最佳并行处理：

```scala
 val ioData = inputs.zip( outputs )
 val lpData = ioData.map{ case(features,label) =>

 LabeledPoint( label, Vectors.dense(features) )
 }
 val rddData = sparkCxt.parallelize( lpData )

```

创建变量来定义 ANN 的隐藏层拓扑。在这种情况下，我选择了有两个隐藏层，每个隐藏层有 100 个神经元。定义了最大迭代次数，以及批处理大小（六个模式）和收敛容限。容限是指在我们可以考虑训练已经完成之前，训练误差可以达到多大。然后，使用这些配置参数和输入数据创建了一个 ANN 模型：

```scala
 val hiddenTopology : Array[Int] = Array( 100, 100 )
 val maxNumIterations = 1000
 val convTolerance    = 1e-4
 val batchSize        = 6

 val annModel = ANNClassifier.train(rddData,
 batchSize,
 hiddenTopology,
 maxNumIterations,
 convTolerance)

```

为了测试训练好的 ANN 模型，相同的输入训练数据被用作测试数据来获取预测标签。首先创建一个名为`rPredictData`的输入数据变量。然后，对数据进行分区，最后使用训练好的 ANN 模型获取预测。对于这个模型工作，必须输出标签 0.1 到 0.6：

```scala
 val rPredictData = inputs.map{ case(features) =>

 ( Vectors.dense(features) )
 }
 val rddPredictData = sparkCxt.parallelize( rPredictData )
 val predictions = annModel.predict( rddPredictData )

```

打印标签预测，并以一个闭合括号结束脚本：

```scala
 predictions.toArray().foreach( value => println( "prediction > " + value ) )
} // end ann1

```

因此，为了运行这个代码示例，必须首先编译和打包。到目前为止，您一定熟悉`ann`子目录中执行的`sbt`命令：

```scala
[hadoop@hc2nn ann]$ pwd
/home/hadoop/spark/ann
[hadoop@hc2nn ann]$ sbt package

```

然后，使用`spark-submit`命令从新的`spark/spark`路径使用新的基于 Spark 的 URL 在端口 8077 上运行应用程序`testann1`：

```scala
/home/hadoop/spark/spark/bin/spark-submit \
 --class testann1 \
 --master spark://hc2nn.semtech-solutions.co.nz:8077  \
 --executor-memory 700M \
 --total-executor-cores 100 \
 /home/hadoop/spark/ann/target/scala-2.10/a-n-n_2.10-1.0.jar

```

通过检查`http://hc2nn.semtech-solutions.co.nz:19080/`上的 Apache Spark Web URL，现在可以看到应用程序正在运行。下图显示了应用程序**ANN 1**正在运行，以及之前完成的执行：

![实践中的 ANN](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_13.jpg)

通过选择集群主机工作实例中的一个，可以看到实际执行该工作的执行程序列表：

![实践中的 ANN](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_14.jpg)

最后，通过选择一个执行程序，可以查看其历史和配置，以及日志文件和错误信息的链接。在这个级别上，通过提供的日志信息，可以进行调试。可以检查这些日志文件以获取处理错误消息。

![实践中的 ANN](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_02_15.jpg)

**ANN 1**应用程序提供以下输出，以显示它已经正确地重新分类了相同的输入数据。重新分类是成功的，因为每个输入模式都被赋予了与训练时相同的标签。

```scala
prediction > 0.1
prediction > 0.2
prediction > 0.3
prediction > 0.4
prediction > 0.5
prediction > 0.6

```

因此，这表明 ANN 训练和测试预测将使用相同的数据。现在，我将使用相同的数据进行训练，但使用扭曲或嘈杂的数据进行测试，这是我已经演示过的一个例子。您可以在软件包中的名为`test_ann2.scala`的文件中找到这个例子。它与第一个例子非常相似，所以我只会演示修改后的代码。该应用程序现在称为`testann2`。

```scala
object testann2 extends App

```

在使用训练数据创建 ANN 模型后，会创建额外的一组测试数据。这些测试数据包含噪音。

```scala
 val tData1 = server + path + "close_square_test.img"
 val tData2 = server + path + "close_triangle_test.img"
 val tData3 = server + path + "lines_test.img"
 val tData4 = server + path + "open_square_test.img"
 val tData5 = server + path + "open_triangle_test.img"
 val tData6 = server + path + "plus_test.img"

```

这些数据被处理成输入数组，并被分区进行集群处理。

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

然后，它被用来以与第一个示例相同的方式生成标签预测。如果模型正确分类数据，则应该从 0.1 到 0.6 打印相同的标签值。

```scala
 val testPredictions = annModel.predict( rddTestPredictData )
 testPredictions.toArray().foreach( value => println( "test prediction > " + value ) )

```

代码已经被编译，因此可以使用`spark-submit`命令运行。

```scala
/home/hadoop/spark/spark/bin/spark-submit \
 --class testann2 \
 --master spark://hc2nn.semtech-solutions.co.nz:8077  \
 --executor-memory 700M \
 --total-executor-cores 100 \
 /home/hadoop/spark/ann/target/scala-2.10/a-n-n_2.10-1.0.jar

```

这是脚本的集群输出，显示了使用训练过的 ANN 模型进行成功分类以及一些嘈杂的测试数据。嘈杂的数据已经被正确分类。例如，如果训练模型混淆了，它可能会在位置一的嘈杂的`close_square_test.img`测试图像中给出`0.15`的值，而不是返回`0.1`。

```scala
test prediction > 0.1
test prediction > 0.2
test prediction > 0.3
test prediction > 0.4
test prediction > 0.5
test prediction > 0.6

```

# 摘要

本章试图为您提供 Apache Spark MLlib 模块中一些功能的概述。它还展示了即将在 Spark 1.3 版本中推出的 ANN（人工神经网络）的功能。由于本章的时间和空间限制，无法涵盖 MLlib 的所有领域。

您已经学会了如何为朴素贝叶斯分类、K 均值聚类和 ANN 或人工神经网络开发基于 Scala 的示例。您已经学会了如何为这些 Spark MLlib 例程准备测试数据。您还了解到它们都接受包含特征和标签的 LabeledPoint 结构。此外，每种方法都采用了训练和预测的方法，使用不同的数据集来训练和测试模型。使用本章展示的方法，您现在可以研究 MLlib 库中剩余的功能。您应该参考[`spark.apache.org/`](http://spark.apache.org/)网站，并确保在查看文档时参考正确的版本，即[`spark.apache.org/docs/1.0.0/`](http://spark.apache.org/docs/1.0.0/)，用于 1.0.0 版本。

在本章中，我们已经研究了 Apache Spark MLlib 机器学习库，现在是时候考虑 Apache Spark 的流处理能力了。下一章将使用基于 Spark 和 Scala 的示例代码来研究流处理。


# 第三章：Apache Spark Streaming

Apache Streaming 模块是 Apache Spark 中基于流处理的模块。它利用 Spark 集群提供高度扩展的能力。基于 Spark，它也具有高度的容错性，能够通过检查点数据流重新运行失败的任务。在本章的初始部分之后，将涵盖以下领域，这部分将提供 Apache Spark 处理基于流的数据的实际概述：

+   错误恢复和检查点

+   基于 TCP 的流处理

+   文件流

+   Flume 流源

+   Kafka 流源

对于每个主题，我将在 Scala 中提供一个示例，并展示如何设置和测试基于流的架构。

# 概览

在介绍 Apache Spark 流模块时，我建议您查看[`spark.apache.org/`](http://spark.apache.org/)网站以获取最新信息，以及 Spark 用户组，如`<user@spark.apache.org>`。我之所以这样说是因为这些是 Spark 信息可获得的主要地方。而且，极快（并且不断增加）的变化速度意味着到您阅读此内容时，新的 Spark 功能和版本将会可用。因此，在这种情况下，当进行概述时，我会尽量概括。

![概览](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_03_01.jpg)

前面的图显示了 Apache Streaming 的潜在数据来源，例如**Kafka**，**Flume**和**HDFS**。这些数据源输入到 Spark Streaming 模块中，并作为离散流进行处理。该图还显示了其他 Spark 模块功能，例如机器学习，可以用来处理基于流的数据。经过完全处理的数据可以作为**HDFS**，**数据库**或**仪表板**的输出。这个图是基于 Spark streaming 网站上的图，但我想扩展它，既表达了 Spark 模块的功能，也表达了仪表板的选项。前面的图显示了从 Spark 到 Graphite 的 MetricSystems 数据源。此外，还可以将基于 Solr 的数据源提供给 Lucidworks banana（kabana 的一个端口）。值得在这里提到的是 Databricks（见第八章，*Spark Databricks*和第九章，*Databricks Visualization*）也可以将 Spark 流数据呈现为仪表板。

![概览](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_03_02.jpg)

在讨论 Spark 离散流时，前面的图，再次取自 Spark 网站[`spark.apache.org/`](http://spark.apache.org/)，是我喜欢使用的图。前面的图中的绿色框显示了连续的数据流发送到 Spark，被分解为**离散流**（**DStream**）。然后，流中每个元素的大小基于批处理时间，可能是两秒。还可以创建一个窗口，表示为前面的红色框，覆盖 DStream。例如，在实时进行趋势分析时，可能需要确定在十分钟窗口内的前十个基于 Twitter 的 Hashtags。

因此，鉴于 Spark 可以用于流处理，如何创建流呢？以下基于 Scala 的代码显示了如何创建 Twitter 流。这个例子是简化的，因为没有包括 Twitter 授权，但您可以理解（完整的示例代码在*检查点*部分）。使用 Spark 上下文`sc`创建了名为`ssc`的 Spark 流上下文。在创建时指定了批处理时间；在这种情况下是五秒。然后从`Streamingcontext`创建了基于 Twitter 的 DStream，称为`stream`，并使用了 60 秒的窗口：

```scala
 val ssc    = new StreamingContext(sc, Seconds(5) )
 val stream = TwitterUtils.createStream(ssc,None).window( Seconds(60) )

```

流处理可以使用流上下文开始方法（下面显示），`awaitTermination`方法表示应该一直处理直到停止。因此，如果此代码嵌入在基于库的应用程序中，它将一直运行直到会话终止，也许使用*Crtl* + *C*：

```scala
 ssc.start()
 ssc.awaitTermination()

```

这解释了 Spark 流是什么以及它的作用，但没有解释错误处理，或者如果基于流的应用程序失败该怎么办。下一节将讨论 Spark 流错误管理和恢复。

# 错误和恢复

通常，对于您的应用程序需要问的问题是：是否关键接收和处理所有数据？如果不是，那么在失败时，您可能只需重新启动应用程序并丢弃丢失的数据。如果不是这种情况，那么您将需要使用检查点，这将在下一节中描述。

值得注意的是，您的应用程序的错误管理应该是健壮和自给自足的。我的意思是，如果异常是非关键的，那么管理异常，也许记录它，并继续处理。例如，当任务达到最大失败次数（由`spark.task.maxFailures`指定）时，它将终止处理。

## 检查点

可以设置一个基于 HDFS 的检查点目录来存储 Apache Spark 基于流的信息。在这个 Scala 示例中，数据将存储在 HDFS 的`/data/spark/checkpoint`目录下。下面的 HDFS 文件系统`ls`命令显示，在开始之前，该目录不存在：

```scala
[hadoop@hc2nn stream]$ hdfs dfs -ls /data/spark/checkpoint
ls: `/data/spark/checkpoint': No such file or directory

```

接下来给出的基于 Twitter 的 Scala 代码示例，首先定义了应用程序的包名称，并导入了 Spark、流、上下文和基于 Twitter 的功能。然后定义了一个名为`stream1`的应用程序对象：

```scala
package nz.co.semtechsolutions

import org.apache.spark._
import org.apache.spark.SparkContext._
import org.apache.spark.streaming._
import org.apache.spark.streaming.twitter._
import org.apache.spark.streaming.StreamingContext._

object stream1 {

```

接下来定义了一个名为`createContext`的方法，该方法将用于创建 spark 和流上下文，并将流检查点到基于 HDFS 的目录，使用流上下文检查点方法，该方法以目录路径作为参数。目录路径是传递给`createContext`方法的值（`cpDir`）：

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

现在，主要方法已经定义，`HDFS`目录也已经定义，还有 Twitter 访问权限和参数。Spark 流上下文`ssc`要么通过`StreamingContext`方法-`getOrCreate`从 HDFS `checkpoint`目录中检索或创建。如果目录不存在，则调用之前的`createContext`方法，该方法将创建上下文和检查点。显然，出于安全原因，我在此示例中截断了自己的 Twitter 授权密钥。

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

 val stream = TwitterUtils.createStream(ssc,None).window( Seconds(60) )

 // do some processing

 ssc.start()
 ssc.awaitTermination()

 } // end main

```

运行了这段代码，没有实际处理，可以再次检查 HDFS `checkpoint`目录。这次明显可以看到`checkpoint`目录已经创建，并且数据已经存储：

```scala
[hadoop@hc2nn stream]$ hdfs dfs -ls /data/spark/checkpoint
Found 1 items
drwxr-xr-x   - hadoop supergroup          0 2015-07-02 13:41 /data/spark/checkpoint/0fc3d94e-6f53-40fb-910d-1eef044b12e9

```

这个例子来自 Apache Spark 网站，展示了如何设置和使用检查点存储。但是检查点操作有多频繁？元数据在每个流批次期间存储。实际数据存储的周期是批处理间隔或十秒的最大值。这可能不是您理想的设置，因此您可以使用该方法重置该值：

```scala
DStream.checkpoint( newRequiredInterval )

```

其中`newRequiredInterval`是您需要的新检查点间隔值，通常应该瞄准是批处理间隔的五到十倍。

检查点保存了流批次和元数据（关于数据的数据）。如果应用程序失败，那么在重新启动时，将使用检查点数据进行处理。在失败时正在处理的批处理数据将被重新处理，以及失败后的批处理数据。

记得监控用于检查点的 HDFS 磁盘空间。在下一节中，我将开始检查流源，并提供每种类型的一些示例。

# 流源

在本节中，我将无法涵盖所有流类型的实际示例，但在本章太小以至于无法包含代码的情况下，我至少会提供一个描述。在本章中，我将涵盖 TCP 和文件流，以及 Flume、Kafka 和 Twitter 流。我将从一个实际的基于 TCP 的示例开始。

本章探讨了流处理架构。例如，在流数据传递速率超过潜在数据处理速率的情况下会发生什么？像 Kafka 这样的系统提供了通过使用多个数据主题和消费者来解决这个问题的可能性。

## TCP 流

有可能使用 Spark 流上下文方法`socketTextStream`通过指定主机名和端口号来通过 TCP/IP 流式传输数据。本节中的基于 Scala 的代码示例将在端口`10777`上接收使用`netcat` Linux 命令提供的数据。代码示例从定义包名开始，并导入 Spark、上下文和流类。定义了一个名为`stream2`的对象类，因为它是带有参数的主方法：

```scala
package nz.co.semtechsolutions

import org.apache.spark._
import org.apache.spark.SparkContext._
import org.apache.spark.streaming._
import org.apache.spark.streaming.StreamingContext._

object stream2 {

 def main(args: Array[String]) {

```

检查传递给类的参数数量，以确保它是主机名和端口号。创建了一个具有应用程序名称的 Spark 配置对象。然后创建了 Spark 和流上下文。然后，设置了 10 秒的流批处理时间：

```scala
 if ( args.length < 2 )
 {
 System.err.println("Usage: stream2 <host> <port>")
 System.exit(1)
 }

 val hostname = args(0).trim
 val portnum  = args(1).toInt

 val appName = "Stream example 2"
 val conf    = new SparkConf()

 conf.setAppName(appName)

 val sc  = new SparkContext(conf)
 val ssc = new StreamingContext(sc, Seconds(10) )

```

通过使用主机和端口名称参数调用流上下文的`socketTextStream`方法创建了一个名为`rawDstream`的 DStream。

```scala
 val rawDstream = ssc.socketTextStream( hostname, portnum )

```

通过按空格拆分单词，从原始流数据创建了一个前十个单词计数。然后创建了一个（键，值）对，即`(word,1)`，通过键值进行了减少，这就是单词。现在，有一个单词及其相关计数的列表。现在，键和值被交换，所以列表变成了（`count`和`word`）。然后，对现在是计数的键进行排序。最后，从 DStream 中的`rdd`中取出前 10 个项目并打印出来：

```scala
 val wordCount = rawDstream
 .flatMap(line => line.split(" "))
 .map(word => (word,1))
 .reduceByKey(_+_)
 .map(item => item.swap)
 .transform(rdd => rdd.sortByKey(false))
 .foreachRDD( rdd =>
 { rdd.take(10).foreach(x=>println("List : " + x)) })

```

代码以 Spark Streaming 的启动和调用`awaitTermination`方法结束，以启动流处理并等待处理终止：

```scala
 ssc.start()
 ssc.awaitTermination()

 } // end main

} // end stream2

```

该应用程序的数据是由 Linux 的`netcat` (`nc`)命令提供的，正如我之前所说的。Linux 的`cat`命令会将日志文件的内容转储到`nc`。`lk`选项强制`netcat`监听连接，并在连接丢失时继续监听。该示例显示使用的端口是`10777`：

```scala
[root@hc2nn log]# pwd
/var/log
[root@hc2nn log]# cat ./anaconda.storage.log | nc -lk 10777

```

基于 TCP 的流处理的输出如下所示。实际输出并不像所示方法那样重要。然而，数据显示了预期的结果，即按降序列出了 10 个日志文件单词。请注意，顶部的单词为空，因为流没有过滤空单词：

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

如果您想要使用 Apache Spark 流处理基于 TCP/IP 的主机和端口的流数据，这是很有趣的。但是更奇特的方法呢？如果您希望从消息系统或通过基于内存的通道流式传输数据呢？如果您想要使用今天可用的一些大数据工具，比如 Flume 和 Kafka 呢？接下来的章节将探讨这些选项，但首先我将演示如何基于文件创建流。

## 文件流

我已经修改了上一节中基于 Scala 的代码示例，通过调用 Spark 流上下文方法`textFileStream`来监视基于 HDFS 的目录。鉴于这个小改变，我不会显示所有的代码。应用程序类现在称为`stream3`，它接受一个参数——`HDFS`目录。目录路径可以是 NFS 或 AWS S3（所有代码示例都将随本书提供）：

```scala
 val rawDstream = ssc.textFileStream( directory )

```

流处理与以前相同。流被分割成单词，并打印出前十个单词列表。这次唯一的区别是，在应用程序运行时，数据必须放入`HDFS`目录中。这是通过 HDFS 文件系统的`put`命令实现的：

```scala
[root@hc2nn log]# hdfs dfs -put ./anaconda.storage.log /data/spark/stream

```

如您所见，使用的`HDFS`目录是`/data/spark/stream/`，文本源日志文件是`anaconda.storage.log`（位于`/var/log/`下）。如预期的那样，打印出相同的单词列表和计数：

```scala
List : (17104,)
List : (2333,=)
……..
List : (564,True)
List : (495,False)
List : (411,None)
List : (356,at)
List : (335,object)

```

这些都是基于 TCP 和文件系统数据的简单流式处理方法。但是，如果我想要在 Spark 流处理中使用一些内置的流处理功能呢？接下来将对此进行检查。将使用 Spark 流处理 Flume 库作为示例。

## Flume

Flume 是一个 Apache 开源项目和产品，旨在以大数据规模移动大量数据。它具有高度可扩展性、分布式和可靠性，基于数据源、数据汇和数据通道工作，如此图所示，取自[`flume.apache.org/`](http://flume.apache.org/)网站：

![Flume](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_03_03.jpg)

Flume 使用代理来处理数据流。如前图所示，代理具有数据源、数据处理通道和数据汇。更清晰地描述这一点的方法是通过以下图。通道充当源数据的队列，而汇将数据传递给链中的下一个链接。

![Flume](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_03_04.jpg)

Flume 代理可以形成 Flume 架构；一个代理的 sink 的输出可以是第二个代理的输入。Apache Spark 允许使用两种方法来使用 Apache Flume。第一种是基于 Avro 的推送式内存方法，而第二种仍然基于 Avro，是一个基于拉取的系统，使用自定义的 Spark sink 库。

我通过 Cloudera CDH 5.3 集群管理器安装了 Flume，它安装了一个单一代理。检查 Linux 命令行，我可以看到 Flume 版本 1.5 现在可用：

```scala
[root@hc2nn ~]# flume-ng version
Flume 1.5.0-cdh5.3.3
Source code repository: https://git-wip-us.apache.org/repos/asf/flume.git
Revision: b88ce1fd016bc873d817343779dfff6aeea07706
Compiled by jenkins on Wed Apr  8 14:57:43 PDT 2015
From source with checksum 389d91c718e03341a2367bf4ef12428e

```

我将在这里最初实现的基于 Flume 的 Spark 示例是基于 Flume 的推送方法，其中 Spark 充当接收器，Flume 将数据推送到 Spark。以下图表示我将在单个节点上实现的结构：

![Flume](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_03_05.jpg)

消息数据将使用 Linux `netcat` (`nc`)命令发送到名为`hc2r1m1`的主机的端口`10777`。这将作为 Flume 代理(`agent1`)的源(`source1`)，它将有一个名为`channel1`的内存通道。`agent1`使用的 sink 将再次基于 Apache Avro，但这次是在名为`hc2r1m1`的主机上，端口号将为`11777`。Apache Spark Flume 应用程序`stream4`（我将很快描述）将在此端口上监听 Flume 流数据。

我通过执行`netcat` (`nc`)命令来启动流处理过程，针对`10777`端口。现在，当我在此窗口中输入文本时，它将被用作 Flume 源，并且数据将被发送到 Spark 应用程序：

```scala
[hadoop@hc2nn ~]$ nc  hc2r1m1.semtech-solutions.co.nz  10777

```

为了运行我的 Flume 代理`agent1`，我创建了一个名为`agent1.flume.cfg`的 Flume 配置文件，描述了代理的源、通道和 sink。文件的内容如下。第一部分定义了`agent1`的源、通道和 sink 名称。

```scala
agent1.sources  = source1
agent1.channels = channel1
agent1.sinks    = sink1

```

下一节定义`source1`为基于 netcat 的，运行在名为`hc2r1m1`的主机上，端口为`10777`：

```scala
agent1.sources.source1.channels=channel1
agent1.sources.source1.type=netcat
agent1.sources.source1.bind=hc2r1m1.semtech-solutions.co.nz
agent1.sources.source1.port=10777

```

`agent1`的通道`channel1`被定义为一个基于内存的通道，最大事件容量为 1000 个事件：

```scala
agent1.channels.channel1.type=memory
agent1.channels.channel1.capacity=1000

```

最后，`agent1`的 sink `sink1` 被定义为在名为`hc2r1m1`的主机上的 Apache Avro sink，并且端口为`11777`：

```scala
agent1.sinks.sink1.type=avro
agent1.sinks.sink1.hostname=hc2r1m1.semtech-solutions.co.nz
agent1.sinks.sink1.port=11777
agent1.sinks.sink1.channel=channel1

```

我创建了一个名为`flume.bash`的 Bash 脚本来运行 Flume 代理`agent1`。它看起来像这样：

```scala
[hadoop@hc2r1m1 stream]$ more flume.bash

#!/bin/bash

# run the bash agent

flume-ng agent \
 --conf /etc/flume-ng/conf \
 --conf-file ./agent1.flume.cfg \
 -Dflume.root.logger=DEBUG,INFO,console  \
 -name agent1

```

脚本调用 Flume 可执行文件`flume-ng`，传递`agent1`配置文件。调用指定了名为`agent1`的代理。它还指定了 Flume 配置目录为`/etc/flume-ng/conf/`，默认值。最初，我将使用基于 Scala 的`netcat` Flume 源示例来展示数据如何被发送到 Apache Spark 应用程序。然后，我将展示如何以类似的方式处理基于 RSS 的数据源。因此，最初接收`netcat`数据的 Scala 代码如下。定义了类包名称和应用程序类名称。导入了 Spark 和 Flume 所需的类。最后，定义了主方法：

```scala
package nz.co.semtechsolutions

import org.apache.spark._
import org.apache.spark.SparkContext._
import org.apache.spark.streaming._
import org.apache.spark.streaming.StreamingContext._
import org.apache.spark.streaming.flume._

object stream4 {

 def main(args: Array[String]) {

```

检查并提取了数据流的主机和端口名称参数：

```scala
 if ( args.length < 2 )
 {
 System.err.println("Usage: stream4 <host> <port>")
 System.exit(1)
 }
 val hostname = args(0).trim
 val portnum  = args(1).toInt

 println("hostname : " + hostname)
 println("portnum  : " + portnum)

```

创建了 Spark 和流上下文。然后，使用流上下文主机和端口号创建了基于 Flume 的数据流。通过调用 Flume 基类`FlumeUtils`的`createStream`方法来实现这一点：

```scala
 val appName = "Stream example 4"
 val conf    = new SparkConf()

 conf.setAppName(appName)

 val sc  = new SparkContext(conf)
 val ssc = new StreamingContext(sc, Seconds(10) )

 val rawDstream = FlumeUtils.createStream(ssc,hostname,portnum)

```

最后，打印了一个流事件计数，并（在我们测试流时用于调试目的）转储了流内容。之后，流上下文被启动并配置为在应用程序终止之前运行：

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

编译完成后，我将使用`spark-submit`运行此应用程序。在本书的其他章节中，我将使用一个名为`run_stream.bash`的基于 Bash 的脚本来执行该作业。脚本如下所示：

```scala
[hadoop@hc2r1m1 stream]$ more run_stream.bash

#!/bin/bash

SPARK_HOME=/usr/local/spark
SPARK_BIN=$SPARK_HOME/bin
SPARK_SBIN=$SPARK_HOME/sbin

JAR_PATH=/home/hadoop/spark/stream/target/scala-2.10/streaming_2.10-1.0.jar
CLASS_VAL=$1
CLASS_PARAMS="${*:2}"

STREAM_JAR=/usr/local/spark/lib/spark-examples-1.3.1-hadoop2.3.0.jar

cd $SPARK_BIN

./spark-submit \
 --class $CLASS_VAL \
 --master spark://hc2nn.semtech-solutions.co.nz:7077  \
 --executor-memory 100M \
 --total-executor-cores 50 \
 --jars $STREAM_JAR \
 $JAR_PATH \
 $CLASS_PARAMS

```

因此，此脚本设置了一些基于 Spark 的变量，并为此作业设置了 JAR 库路径。它将要运行的 Spark 类作为其第一个参数。它将所有其他变量作为参数传递给 Spark 应用程序类作业。因此，应用程序的执行如下所示：

```scala
[hadoop@hc2r1m1 stream]$ ./run_stream.bash  \
 nz.co.semtechsolutions.stream4 \
 hc2r1m1.semtech-solutions.co.nz  \
 11777

```

这意味着 Spark 应用程序已准备就绪，并作为 Flume 接收器在端口`11777`上运行。Flume 输入已准备就绪，作为端口`10777`上的 netcat 任务运行。现在，可以使用名为`flume.bash`的 Flume 脚本启动 Flume 代理`agent1`，以将 netcat 源数据发送到基于 Apache Spark Flume 的接收器：

```scala
[hadoop@hc2r1m1 stream]$ ./flume.bash

```

现在，当文本传递到 netcat 会话时，它应该通过 Flume 流动，并由 Spark 作为流进行处理。让我们试一试：

```scala
[hadoop@hc2nn ~]$ nc  hc2r1m1.semtech-solutions.co.nz 10777
I hope that Apache Spark will print this
OK
I hope that Apache Spark will print this
OK
I hope that Apache Spark will print this
OK

```

已经向 netcat 会话添加了三个简单的文本片段，并收到了`OK`的确认，以便它们可以传递给 Flume。Flume 会话中的调试输出显示已接收和处理了事件（每行一个）：

```scala
2015-07-06 18:13:18,699 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:318)] Chars read = 41
2015-07-06 18:13:18,700 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:322)] Events processed = 1
2015-07-06 18:13:18,990 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:318)] Chars read = 41
2015-07-06 18:13:18,991 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:322)] Events processed = 1
2015-07-06 18:13:19,270 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:318)] Chars read = 41
2015-07-06 18:13:19,271 (netcat-handler-0) [DEBUG - org.apache.flume.source.NetcatSource$NetcatSocketHandler.run(NetcatSource.java:322)] Events processed = 1

```

最后，在 Spark`stream4`应用程序会话中，已接收和处理了三个事件。在这种情况下，将其转储到会话以证明数据已到达。当然，这不是您通常会做的事情，但我想证明数据通过此配置传输：

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

这很有趣，但实际上并不是一个生产值得的 Spark Flume 数据处理示例。因此，为了演示潜在的真实数据处理方法，我将更改 Flume 配置文件的源细节，以便使用一个 Perl 脚本，如下所示：

```scala
agent1.sources.source1.type=exec
agent1.sources.source.command=./rss.perl

```

之前提到的 Perl 脚本`rss.perl`只是作为路透社科学新闻的数据源。它将新闻作为 XML 接收，并将其转换为 JSON 格式。它还清理了不需要的噪音数据。首先，导入了像 LWP 和`XML::XPath`这样的包以启用 XML 处理。然后，它指定了基于科学的路透社新闻数据源，并创建了一个新的 LWP 代理来处理数据，类似于这样：

```scala
#!/usr/bin/perl

use strict;
use LWP::UserAgent;
use XML::XPath;

my $urlsource="http://feeds.reuters.com/reuters/scienceNews" ;

my  $agent = LWP::UserAgent->new;

```

然后打开一个无限循环，对 URL 执行 HTTP 的`GET`请求。请求被配置，代理通过调用请求方法发出请求：

```scala
while()
{
 my  $req = HTTP::Request->new(GET => ($urlsource));

 $req->header('content-type' => 'application/json');
 $req->header('Accept'       => 'application/json');

 my $resp = $agent->request($req);

```

如果请求成功，那么返回的 XML 数据被定义为请求的解码内容。通过使用路径`/rss/channel/item/title`调用 XPath 来从 XML 中提取标题信息：

```scala
 if ( $resp->is_success )
 {
 my $xmlpage = $resp -> decoded_content;

 my $xp = XML::XPath->new( xml => $xmlpage );
 my $nodeset = $xp->find( '/rss/channel/item/title' );

 my @titles = () ;
 my $index = 0 ;

```

对于从提取的标题数据标题 XML 字符串中的每个节点，都会提取数据。清除不需要的 XML 标签，并添加到名为`titles`的基于 Perl 的数组中：

```scala
 foreach my $node ($nodeset->get_nodelist)
 {
 my $xmlstring = XML::XPath::XMLParser::as_string($node) ;

 $xmlstring =~ s/<title>//g;
 $xmlstring =~ s/<\/title>//g;
 $xmlstring =~ s/"//g;
 $xmlstring =~ s/,//g;

 $titles[$index] = $xmlstring ;
 $index = $index + 1 ;

 } # foreach find node

```

对于请求响应 XML 中的基于描述的数据，进行相同的处理过程。这次使用的 XPath 值是`/rss/channel/item/description/`。需要清理的描述数据标签更多，因此有更多的 Perl 搜索和行替换操作（`s///g`）：

```scala
 my $nodeset = $xp->find( '/rss/channel/item/description' );

 my @desc = () ;
 $index = 0 ;

 foreach my $node ($nodeset->get_nodelist)
 {
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

最后，基于 XML 的标题和描述数据以 RSS JSON 格式输出，使用`print`命令。然后脚本休眠 30 秒，并请求更多的 RSS 新闻信息进行处理：

```scala
 my $newsitems = $index ;
 $index = 0 ;

 for ($index=0; $index < $newsitems; $index++) {

 print "{\"category\": \"science\","
 . " \"title\": \"" .  $titles[$index] . "\","
 . " \"summary\": \"" .  $desc[$index] . "\""
 . "}\n";

 } # for rss items

 } # success ?

 sleep(30) ;

} # while

```

我已经创建了第二个基于 Scala 的流处理代码示例，名为`stream5`。它类似于`stream4`示例，但现在它处理来自流的`rss`项数据。接下来定义了一个案例类来处理 XML `rss`信息中的类别、标题和摘要。定义了一个 HTML 位置来存储来自 Flume 通道的结果数据：

```scala
 case class RSSItem(category : String, title : String, summary : String)

 val now: Long = System.currentTimeMillis

 val hdfsdir = "hdfs://hc2nn:8020/data/spark/flume/rss/"

```

从基于 Flume 的事件的`rss`流数据转换为字符串。然后使用名为`RSSItem`的案例类进行格式化。如果有事件数据，那么将使用先前的`hdfsdir`路径将其写入 HDFS 目录：

```scala
 rawDstream.map(record => {
 implicit val formats = DefaultFormats
 readRSSItem.array()))
 })
 .foreachRDD(rdd => {
 if (rdd.count() > 0) {
 rdd.map(item => {
 implicit val formats = DefaultFormats
 write(item)
 }).saveAsTextFile(hdfsdir+"file_"+now.toString())
 }
 })

```

运行此代码示例，可以看到 Perl `rss`脚本正在生成数据，因为 Flume 脚本输出表明已接受和接收了 80 个事件：

```scala
2015-07-07 14:14:24,017 (agent-shutdown-hook) [DEBUG - org.apache.flume.source.ExecSource.stop(ExecSource.java:219)] Exec source with command:./news_rss_collector.py stopped. Metrics:SOURCE:source1{src.events.accepted=80, src.events.received=80, src.append.accepted=0, src.append-batch.accepted=0, src.open-connection.count=0, src.append-batch.received=0, src.append.received=0}

```

Scala Spark 应用程序`stream5`已经处理了 80 个事件，分为两批：

```scala
>>>> Received events : 73
>>>> Received events : 7

```

事件已存储在 HDFS 中，位于预期目录下，如 Hadoop 文件系统`ls`命令所示：

```scala
[hadoop@hc2r1m1 stream]$ hdfs dfs -ls /data/spark/flume/rss/
Found 2 items
drwxr-xr-x   - hadoop supergroup          0 2015-07-07 14:09 /data/spark/flume/rss/file_1436234439794
drwxr-xr-x   - hadoop supergroup          0 2015-07-07 14:14 /data/spark/flume/rss/file_1436235208370

```

此外，使用 Hadoop 文件系统`cat`命令，可以证明 HDFS 上的文件包含 rss feed 新闻数据，如下所示：

```scala
[hadoop@hc2r1m1 stream]$  hdfs dfs -cat /data/spark/flume/rss/file_1436235208370/part-00000 | head -1

{"category":"healthcare","title":"BRIEF-Aetna CEO says has not had specific conversations with DOJ on Humana - CNBC","summary":"* Aetna CEO Says Has Not Had Specific Conversations With Doj About Humana Acquisition - CNBC"}

```

这个基于 Spark 流的示例使用 Apache Flume 从 rss 源传输数据，通过 Flume，通过 Spark 消费者传输到 HDFS。这是一个很好的例子，但如果您想要向一组消费者发布数据怎么办？在下一节中，我将研究 Apache Kafka——一个发布订阅消息系统，并确定它如何与 Spark 一起使用。

## Kafka

Apache Kafka ([`kafka.apache.org/`](http://kafka.apache.org/)) 是 Apache 中的一个顶级开源项目。它是一个快速且高度可扩展的大数据发布/订阅消息系统。它使用消息代理进行数据管理，并使用 ZooKeeper 进行配置，以便数据可以组织成消费者组和主题。Kafka 中的数据被分成分区。在这个示例中，我将演示一个无接收器的基于 Spark 的 Kafka 消费者，因此与我的 Kafka 数据相比，我不需要担心配置 Spark 数据分区。

为了演示基于 Kafka 的消息生产和消费，我将使用上一节中的 Perl RSS 脚本作为数据源。传递到 Kafka 并传递到 Spark 的数据将是 JSON 格式的 Reuters RSS 新闻数据。

当消息生产者创建主题消息时，它们会按消息顺序顺序放置在分区中。分区中的消息将保留一段可配置的时间。Kafka 然后为每个消费者存储偏移值，该值是该消费者在该分区中的位置（以消息消费为准）。

我目前正在使用 Cloudera 的 CDH 5.3 Hadoop 集群。为了安装 Kafka，我需要从[`archive.cloudera.com/csds/kafka/`](http://archive.cloudera.com/csds/kafka/)下载 Kafka JAR 库文件。

下载文件后，鉴于我正在使用 CDH 集群管理器，我需要将文件复制到我的 NameNode CentOS 服务器上的`/opt/cloudera/csd/`目录，以便安装时可见：

```scala
[root@hc2nn csd]# pwd
/opt/cloudera/csd

[root@hc2nn csd]# ls -l KAFKA-1.2.0.jar
-rw-r--r-- 1 hadoop hadoop 5670 Jul 11 14:56 KAFKA-1.2.0.jar

```

然后，我需要重新启动我的 NameNode 或主服务器上的 Cloudera 集群管理器服务器，以便识别更改。这是以 root 用户使用 service 命令完成的，命令如下：

```scala
[root@hc2nn hadoop]# service cloudera-scm-server restart
Stopping cloudera-scm-server:                              [  OK  ]
Starting cloudera-scm-server:                              [  OK  ]

```

现在，Kafka 包应该在 CDH 管理器的**主机** | **包裹**下可见，如下图所示。您可以按照 CDH 包安装的常规下载、分发和激活周期进行操作：

![Kafka](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_03_06.jpg)

我在集群中的每个数据节点或 Spark 从节点机器上安装了 Kafka 消息代理。然后为每个 Kafka 代理服务器设置了 Kafka 代理 ID 值，分别为 1 到 4。由于 Kafka 使用 ZooKeeper 进行集群数据配置，我希望将所有 Kafka 数据保留在 ZooKeeper 中名为`kafka`的顶级节点中。为了做到这一点，我将 Kafka ZooKeeper 根值设置为`zookeeper.chroot`，称为`/kafka`。在进行这些更改后，我重新启动了 CDH Kafka 服务器，以使更改生效。

安装了 Kafka 后，我可以检查可用于测试的脚本。以下清单显示了基于 Kafka 的消息生产者和消费者脚本，以及用于管理主题和检查消费者偏移的脚本。这些脚本将在本节中使用，以演示 Kafka 的功能：

```scala
[hadoop@hc2nn ~]$ ls /usr/bin/kafka*

/usr/bin/kafka-console-consumer         /usr/bin/kafka-run-class
/usr/bin/kafka-console-producer         /usr/bin/kafka-topics
/usr/bin/kafka-consumer-offset-checker

```

为了运行已安装的 Kafka 服务器，我需要设置经纪人服务器 ID（`broker.id`）值，否则将出现错误。安装并运行 Kafka 后，我需要准备一个消息生产者脚本。下面给出的简单 Bash 脚本名为`kafka.bash`，它定义了一个以逗号分隔的主机和端口的经纪人列表。它还定义了一个名为`rss`的主题。然后，它调用 Perl 脚本`rss.perl`生成基于 RSS 的数据。然后将这些数据传送到名为`kafka-console-producer`的 Kafka 生产者脚本以发送到 Kafka。

```scala
[hadoop@hc2r1m1 stream]$ more kafka.bash

#!/bin/bash

BROKER_LIST="hc2r1m1:9092,hc2r1m2:9092,hc2r1m3:9092,hc2r1m4:9092"
TOPIC="rss"

./rss.perl | /usr/bin/kafka-console-producer --broker-list $BROKER_LIST --topic $TOPIC

```

注意，我还没有在这一点上提到 Kafka 主题。在 Kafka 中创建主题时，可以指定分区的数量。在下面的示例中，使用`create`选项调用了`kafka-topics`脚本。分区的数量设置为`5`，数据复制因子设置为`3`。ZooKeeper 服务器字符串已定义为`hc2r1m2-4`，端口号为`2181`。还要注意，顶级 ZooKeeper Kafka 节点在 ZooKeeper 字符串中被定义为`/kafka`：

```scala
/usr/bin/kafka-topics \
 --create  \
 --zookeeper hc2r1m2:2181,hc2r1m3:2181,hc2r1m4:2181/kafka \
 --replication-factor 3  \
 --partitions 5  \
 --topic rss

```

我还创建了一个名为`kafka_list.bash`的 Bash 脚本，用于测试时检查已创建的所有 Kafka 主题以及 Kafka 消费者偏移。它使用`kafka-topics`命令调用`list`选项和`ZooKeeper`字符串来获取已创建主题的列表。然后，它使用 Kafka 脚本`kafka-consumer-offset-checker`调用`ZooKeeper`字符串、主题名称和组名称来获取消费者偏移值的列表。使用此脚本，我可以检查我的主题是否已创建，并且主题数据是否被正确消耗：

```scala
[hadoop@hc2r1m1 stream]$ cat kafka_list.bash

#!/bin/bash

ZOOKEEPER="hc2r1m2:2181,hc2r1m3:2181,hc2r1m4:2181/kafka"
TOPIC="rss"
GROUP="group1"

echo ""
echo "================================"
echo " Kafka Topics "
echo "================================"

/usr/bin/kafka-topics --list --zookeeper $ZOOKEEPER

echo ""
echo "================================"
echo " Kafka Offsets "
echo "================================"

```

```scala
/usr/bin/kafka-consumer-offset-checker \
 --group $GROUP \
 --topic $TOPIC \
 --zookeeper $ZOOKEEPER

```

接下来，我需要创建基于 Apache Spark Scala 的 Kafka 消费者代码。正如我所说的，我将创建一个无接收器的示例，以便 Kafka 数据分区在 Kafka 和 Spark 中匹配。示例被称为`stream6`。首先，定义了包，并导入了 Kafka、spark、context 和 streaming 的类。然后，定义了名为`stream6`的对象类和主方法。代码如下：

```scala
package nz.co.semtechsolutions

import kafka.serializer.StringDecoder

import org.apache.spark._
import org.apache.spark.SparkContext._
import org.apache.spark.streaming._
import org.apache.spark.streaming.StreamingContext._
import org.apache.spark.streaming.kafka._

object stream6 {

 def main(args: Array[String]) {

```

接下来，检查和处理了类参数（经纪人字符串、组 ID 和主题）。如果类参数不正确，则打印错误并停止执行，否则定义参数变量：

```scala
 if ( args.length < 3 )
 {
 System.err.println("Usage: stream6 <brokers> <groupid> <topics>\n")
 System.err.println("<brokers> = host1:port1,host2:port2\n")
 System.err.println("<groupid> = group1\n")
 System.err.println("<topics>  = topic1,topic2\n")
 System.exit(1)
 }

 val brokers = args(0).trim
 val groupid = args(1).trim
 val topics  = args(2).trim

 println("brokers : " + brokers)
 println("groupid : " + groupid)
 println("topics  : " + topics)

```

Spark 上下文根据应用程序名称进行了定义。同样，Spark URL 保持默认值。使用 Spark 上下文创建了流上下文。我将流批处理间隔保持为 10 秒，与上一个示例相同。但是，您可以使用自己选择的参数进行设置：

```scala
 val appName = "Stream example 6"
 val conf    = new SparkConf()

 conf.setAppName(appName)

 val sc  = new SparkContext(conf)
 val ssc = new StreamingContext(sc, Seconds(10) )

```

接下来，设置了经纪人列表和组 ID 作为参数。然后使用这些值创建了一个名为`rawDStream`的基于 Kafka 的 Spark 流：

```scala
 val topicsSet = topics.split(",").toSet
 val kafkaParams : Map[String, String] =
 Map("metadata.broker.list" -> brokers,
 "group.id" -> groupid )

 val rawDstream = KafkaUtils.createDirectStreamString, String, StringDecoder, StringDecoder

```

出于调试目的，我再次打印了流事件计数，以便我知道应用程序何时接收和处理数据。

```scala
 rawDstream.count().map(cnt => ">>>>>>>>>>>>>>> Received events : " + cnt ).print()

```

Kafka 数据的 HDSF 位置已定义为`/data/spark/kafka/rss/`。它已从 DStream 映射到变量`lines`。使用`foreachRDD`方法，在`lines`变量上进行数据计数检查，然后使用`saveAsTextFile`方法将数据保存到 HDFS 中。

```scala
 val now: Long = System.currentTimeMillis

 val hdfsdir = "hdfs://hc2nn:8020/data/spark/kafka/rss/"

 val lines = rawDstream.map(record => record._2)

 lines.foreachRDD(rdd => {
 if (rdd.count() > 0) {
 rdd.saveAsTextFile(hdfsdir+"file_"+now.toString())
 }
 })

```

最后，Scala 脚本通过启动流处理并将应用程序类设置为使用`awaitTermination`直到终止来关闭：

```scala
 ssc.start()
 ssc.awaitTermination()

 } // end main

} // end stream6

```

在解释了所有脚本并运行了 Kafka CDH 代理之后，现在是时候检查 Kafka 配置了，您可能还记得这是由 Apache ZooKeeper 维护的（迄今为止描述的所有代码示例都将随本书一起发布）。我将使用`zookeeper-client`工具，并连接到名为`hc2r1m2`的主机上的`2181`端口上的`zookeeper`服务器。如您在此处所见，我已从`client`会话收到了连接消息。

```scala
[hadoop@hc2r1m1 stream]$ /usr/bin/zookeeper-client -server hc2r1m2:2181

[zk: hc2r1m2:2181(CONNECTED) 0]

```

如果您记得，我指定了 Kafka 的顶级 ZooKeeper 目录为`/kafka`。如果我现在通过客户端会话检查这一点，我可以看到 Kafka ZooKeeper 结构。我将对`brokers`（CDH Kafka 代理服务器）和`consumers`（先前的 Spark Scala 代码）感兴趣。ZooKeeper `ls`命令显示，四个 Kafka 服务器已在 ZooKeeper 中注册，并按其`broker.id`配置值从一到四列出。

```scala
[zk: hc2r1m2:2181(CONNECTED) 2] ls /kafka
[consumers, config, controller, admin, brokers, controller_epoch]

[zk: hc2r1m2:2181(CONNECTED) 3] ls /kafka/brokers
[topics, ids]

[zk: hc2r1m2:2181(CONNECTED) 4] ls /kafka/brokers/ids
[3, 2, 1, 4]

```

我将使用 Kafka 脚本`kafka-topics`和`create`标志创建我想要用于此测试的主题。我这样做是因为我可以在手动操作时演示数据分区的定义。请注意，我已经在 Kafka `topic rss`中设置了五个分区，如下面的代码所示。还要注意，命令的 ZooKeeper 连接字符串是由逗号分隔的 ZooKeeper 服务器列表组成的，以`/kafka`结尾，这意味着命令将新主题放在适当的位置。

```scala
[hadoop@hc2nn ~]$ /usr/bin/kafka-topics \
>   --create  \
>   --zookeeper hc2r1m2:2181,hc2r1m3:2181,hc2r1m4:2181/kafka \
>   --replication-factor 3  \
>   --partitions 5  \
>   --topic rss

Created topic "rss".

```

现在，当我使用 ZooKeeper 客户端检查 Kafka 主题配置时，我可以看到正确的主题名称和预期的分区数。

```scala
[zk: hc2r1m2:2181(CONNECTED) 5] ls /kafka/brokers/topics
[rss]

[zk: hc2r1m2:2181(CONNECTED) 6] ls /kafka/brokers/topics/rss
[partitions]

[zk: hc2r1m2:2181(CONNECTED) 7] ls /kafka/brokers/topics/rss/partitions
[3, 2, 1, 0, 4]

```

这描述了 ZooKeeper 中 Kafka 代理服务器的配置，但数据消费者的情况如何呢？好吧，以下清单显示了数据将被保存的位置。但请记住，此时没有运行消费者，因此在 ZooKeeper 中没有表示。

```scala
[zk: hc2r1m2:2181(CONNECTED) 9]  ls /kafka/consumers
[]
[zk: hc2r1m2:2181(CONNECTED) 10] quit

```

为了开始这个测试，我将运行我的 Kafka 数据生产者和消费者脚本。我还需要检查 Spark 应用程序类的输出，并需要检查 Kafka 分区偏移和 HDFS，以确保数据已到达。这非常复杂，所以我将在下图中添加一个图表来解释测试架构。

名为`rss.perl`的 Perl 脚本将用于为 Kafka 数据生产者提供数据源，该数据生产者将数据提供给 CDH Kafka 代理服务器。数据将存储在 ZooKeeper 中，结构刚刚在顶级节点`/kafka`下进行了检查。然后，基于 Apache Spark Scala 的应用程序将充当 Kafka 消费者，并读取将存储在 HDFS 中的数据。

![Kafka](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_03_07.jpg)

为了尝试解释这里的复杂性，我还将检查运行 Apache Spark 类的方法。它将通过`spark-submit`命令启动。请再次记住，所有这些脚本都将随本书一起发布，这样您就可以在自己的时间内对它们进行检查。我总是使用脚本进行服务器测试管理，以便封装复杂性，并且命令执行可以快速重复。脚本`run_stream.bash`类似于本章和本书中已经使用过的许多示例脚本。它接受一个类名和类参数，并通过 spark-submit 运行该类。

```scala
[hadoop@hc2r1m1 stream]$ more run_stream.bash

#!/bin/bash

SPARK_HOME=/usr/local/spark
SPARK_BIN=$SPARK_HOME/bin
SPARK_SBIN=$SPARK_HOME/sbin

JAR_PATH=/home/hadoop/spark/stream/target/scala-2.10/streaming_2.10-1.0.jar
CLASS_VAL=$1
CLASS_PARAMS="${*:2}"

STREAM_JAR=/usr/local/spark/lib/spark-examples-1.3.1-hadoop2.3.0.jar
cd $SPARK_BIN

./spark-submit \
 --class $CLASS_VAL \
 --master spark://hc2nn.semtech-solutions.co.nz:7077  \
 --executor-memory 100M \
 --total-executor-cores 50 \
 --jars $STREAM_JAR \
 $JAR_PATH \
 $CLASS_PARAMS

```

然后我使用了第二个脚本，调用`run_kafka_example.bash`脚本来执行先前`stream6`应用程序类中的 Kafka 消费者代码。请注意，此脚本设置了完整的应用程序类名-代理服务器列表。它还设置了一个名为`rss`的主题名称，用于数据消耗。最后，它定义了一个名为`group1`的消费者组。请记住，Kafka 是一个发布/订阅消息代理系统。可以通过主题、组和分区组织许多生产者和消费者：

```scala
[hadoop@hc2r1m1 stream]$ more run_kafka_example.bash

#!/bin/bash

RUN_CLASS=nz.co.semtechsolutions.stream6
BROKERS="hc2r1m1:9092,hc2r1m2:9092,hc2r1m3:9092,hc2r1m4:9092"
GROUPID=group1
TOPICS=rss

# run the Apache Spark Kafka example

./run_stream.bash $RUN_CLASS \
 $BROKERS \
 $GROUPID \
 $TOPICS

```

因此，我将通过运行`run_kafka_example.bash`脚本来启动 Kafka 消费者，然后将运行先前的`stream6` Scala 代码使用 spark-submit。在使用名为`kafka_list.bash`的脚本监视 Kafka 数据消耗时，我能够让`kafka-consumer-offset-checker`脚本列出基于 Kafka 的主题，但由于某种原因，它在检查偏移时不会检查正确的路径（在 ZooKeeper 中的`/kafka`下）如下所示：

```scala
[hadoop@hc2r1m1 stream]$ ./kafka_list.bash

================================
 Kafka Topics
================================
__consumer_offsets
rss

================================
 Kafka Offsets
================================
Exiting due to: org.apache.zookeeper.KeeperException$NoNodeException: KeeperErrorCode = NoNode for /consumers/group1/offsets/rss/4.

```

通过使用`kafka.bash`脚本启动 Kafka 生产者 rss feed，我现在可以开始通过 Kafka 将基于 rss 的数据馈送到 Spark，然后进入 HDFS。定期检查`spark-submit`会话输出，可以看到事件通过基于 Spark 的 Kafka DStream 传递。下面的输出来自 Scala 代码中的流计数，并显示在那一点上，处理了 28 个事件：

```scala
-------------------------------------------
Time: 1436834440000 ms
-------------------------------------------
>>>>>>>>>>>>>>> Received events : 28

```

通过在`/data/spark/kafka/rss/`目录下检查 HDFS，通过 Hadoop 文件系统`ls`命令，可以看到现在在 HDFS 上存储了数据：

```scala
[hadoop@hc2r1m1 stream]$ hdfs dfs -ls /data/spark/kafka/rss
Found 1 items
drwxr-xr-x   - hadoop supergroup          0 2015-07-14 12:40 /data/spark/kafka/rss/file_1436833769907

```

通过检查这个目录的内容，可以看到存在一个 HDFS 部分数据文件，应该包含来自路透社的基于 RSS 的数据：

```scala
[hadoop@hc2r1m1 stream]$ hdfs dfs -ls /data/spark/kafka/rss/file_1436833769907
Found 2 items
-rw-r--r--   3 hadoop supergroup          0 2015-07-14 12:40 /data/spark/kafka/rss/file_1436833769907/_SUCCESS
-rw-r--r--   3 hadoop supergroup       8205 2015-07-14 12:40 /data/spark/kafka/rss/file_1436833769907/part-00001

```

使用下面的 Hadoop 文件系统`cat`命令，我可以转储这个基于 HDFS 的文件的内容以检查其内容。我已经使用了 Linux 的`head`命令来限制数据以节省空间。显然，这是 Perl 脚本`rss.perl`从 XML 转换为 RSS JSON 格式的 RSS 路透社科学信息。

```scala
[hadoop@hc2r1m1 stream]$ hdfs dfs -cat /data/spark/kafka/rss/file_1436833769907/part-00001 | head -2

{"category": "science", "title": "Bear necessities: low metabolism lets pandas survive on bamboo", "summary": "WASHINGTON (Reuters) - Giant pandas eat vegetables even though their bodies are better equipped to eat meat. So how do these black-and-white bears from the remote misty mountains of central China survive on a diet almost exclusively of a low-nutrient food like bamboo?"}

{"category": "science", "title": "PlanetiQ tests sensor for commercial weather satellites", "summary": "CAPE CANAVERAL (Reuters) - PlanetiQ a privately owned company is beginning a key test intended to pave the way for the first commercial weather satellites."}

```

这结束了这个 Kafka 示例。可以看到 Kafka 代理已经安装和配置。它显示了一个基于 RSS 数据的 Kafka 生产者已经将数据馈送到代理中。使用 ZooKeeper 客户端已经证明了 Kafka 架构，匹配代理、主题和分区已经在 ZooKeeper 中设置。最后，使用基于 Apache Spark 的 Scala 代码，在`stream6`应用程序中已经显示了 Kafka 数据已被消耗并保存到 HDFS 中。

# 总结

我本可以提供像 Kinesis 这样的系统的流式示例，以及排队系统，但在本章中没有足够的空间。Twitter 流已经在检查点部分的示例中进行了检查。

本章提供了通过 Spark 流检查点进行数据恢复的实际示例。它还触及了检查点的性能限制，并表明检查点间隔应设置为 Spark 流批处理间隔的五到十倍。检查点提供了一种基于流的恢复机制，以防 Spark 应用程序失败。

本章提供了一些基于流的 TCP、文件、Flume 和 Kafka 的 Spark 流编码示例。这里的所有示例都是基于 Scala 的，并且使用`sbt`进行编译。所有的代码都将随本书一起发布。当示例架构变得过于复杂时，我提供了一个架构图（我在这里考虑的是 Kafka 示例）。

对我来说，Apache Spark 流模块包含了丰富的功能，应该能满足大部分需求，并且随着未来版本的 Spark 发布而不断增长。记得查看 Apache Spark 网站（[`spark.apache.org/`](http://spark.apache.org/)），并通过`<user@spark.apache.org>`加入 Spark 用户列表。不要害怕提问，或犯错误，因为在我看来，错误教会的比成功多。

下一章将审查 Spark SQL 模块，并提供 SQL、数据框架和访问 Hive 等主题的实例。
