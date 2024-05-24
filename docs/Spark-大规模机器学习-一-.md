# Spark 大规模机器学习（一）

> 原文：[`zh.annas-archive.org/md5/7A35D303E4132E910DFC5ADB5679B82A`](https://zh.annas-archive.org/md5/7A35D303E4132E910DFC5ADB5679B82A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

机器学习的核心是关注将原始数据转化为可操作智能的算法。这一事实使得机器学习非常适合于大数据的预测分析。因此，如果没有机器学习，要跟上这些大规模信息流几乎是不可能的。相对较新且新兴的技术 Spark 为大数据工程师和数据科学家提供了一个强大的响应和统一的引擎，既更快速又易于使用。

这使得来自多个领域的学习者能够以更大规模地交互解决他们的机器学习问题。本书旨在使数据科学家、工程师和研究人员能够开发和部署规模化的机器学习应用程序，以便他们学会如何在数据密集型环境中处理大数据集群，构建强大的机器学习模型。

本书的内容是从 Spark 和 ML 基础开始以自下而上的方式编写的，探索了特征工程中的数据，构建可扩展的 ML 管道，通过调整和适应新的数据和问题类型，最终进行模型构建和部署。为了更清晰，我们以这样一种方式提供了章节大纲，以便具有最基本的机器学习和 Spark 编程知识的新读者能够跟随示例，并朝着一些真实的机器学习问题及其解决方案迈进。

# 本书内容包括以下内容

第一章，*使用 Spark 进行数据分析简介*，本章介绍了 Spark 的概述、计算范式、安装，并帮助我们开始使用 Spark。它将简要描述 Spark 的主要组件，并专注于其具有弹性分布式数据集（RDD）和数据集的新计算进展。然后，它将专注于 Spark 的机器学习库生态系统。在扩展到 Amazon EC2 之前，将演示使用 Spark 和 Maven 安装、配置和打包简单的机器学习应用程序。

第二章，*机器学习最佳实践*，提供了对统计机器学习（ML）技术的概念介绍，旨在带领新手从对机器学习的最基本知识到成为熟练的从业者。本章的第二部分侧重于为根据应用类型和要求选择合适的机器学习算法提供一些建议。然后，它将介绍应用大规模机器学习管道时的一些最佳实践。

第三章，*通过了解数据来理解问题*，详细介绍了用于处理结构化数据的数据集和弹性分布式数据集（RDD）API，旨在提供对可用数据进行基本理解的机器学习问题。最后，您将能够轻松处理基本和复杂的数据操作。将提供使用 RDD 和基于数据集的数据操作的基本抽象的一些比较，以展示在编程和性能方面的收益。此外，我们将指导您走上正确的道路，以便您能够使用 Spark 将 RDD 或数据对象持久化在内存中，从而在后期的并行操作中有效地重复使用。

《第四章》《通过特征工程提取知识》解释了了解应该用于创建预测模型的特征不仅至关重要，而且可能是一个需要深入了解问题领域的难题。可以自动选择数据中对某人正在处理的问题最有用或最相关的特征。考虑到这些问题，本章详细介绍了特征工程，解释了应用它的原因以及特征工程中的一些最佳实践。

除此之外，还将讨论应用于大规模机器学习技术的特征提取、转换和选择的理论描述和示例，使用 Spark MLlib 和 Spark ML API。

《第五章》《通过示例进行监督和无监督学习》将提供围绕如何快速而有力地将监督和无监督技术应用于可用数据解决新问题的实际知识，这些知识是基于前几章的一些广泛使用的示例。这些示例将从 Spark 的角度进行演示。

《第六章》《构建可扩展的机器学习管道》解释了机器学习的最终目标是使机器能够在不需要繁琐和耗时的人工参与和交互的情况下自动从数据中构建模型。因此，本章将指导读者通过使用 Spark MLlib 和 Spark ML 创建一些实用和广泛使用的机器学习管道和应用。将详细描述这两个 API，并且还将涵盖基线用例。然后，我们将专注于扩展 ML 应用程序，使其能够应对不断增加的数据负载。

《第七章》《调整机器学习模型》表明，调整算法或机器学习应用可以简单地被视为一个过程，通过这个过程优化影响模型的参数，以使算法表现最佳。本章旨在指导读者进行模型调整。它将涵盖用于优化 ML 算法性能的主要技术。技术将从 MLlib 和 Spark ML 的角度进行解释。我们还将展示如何通过调整多个参数（如超参数、MLlib 和 Spark ML 的网格搜索参数、假设检验、随机搜索参数调整和交叉验证）来改善 ML 模型的性能。

《第八章》《调整您的机器学习模型》涵盖了使算法适应新数据和问题类型的高级机器学习技术。它将主要关注批处理/流处理架构和使用 Spark 流处理的在线学习算法。最终目标是为静态机器学习模型带来动态性。读者还将看到机器学习算法如何逐渐从数据中学习，即每次算法看到新的训练实例时，模型都会更新。

第九章《使用流式和图形数据进行高级机器学习》解释了如何利用 Spark MLlib 和 Spark ML 等工具在流式和图形数据上应用机器学习技术，例如在主题建模中。读者将能够利用现有的 API 从流数据源（如 Twitter）构建实时和预测性应用程序。通过 Twitter 数据分析，我们将展示如何进行大规模社交情感分析。我们还将展示如何使用 Spark MLlib 开发大规模电影推荐系统，这是社交网络分析的一个隐含部分。

第十章《配置和使用外部库》指导读者如何使用外部库来扩展他们的数据分析。将给出使用第三方包或库在 Spark 核心和 ML/MLlib 上进行机器学习应用的示例。我们还将讨论如何编译和使用外部库与 Spark 的核心库进行时间序列分析。如约定的，我们还将讨论如何配置 SparkR 以改进探索性数据操作。

# 本书所需内容

**软件要求：**

第 1-8 章和第十章需要以下软件：Spark 2.0.0（或更高版本）、Hadoop 2.7（或更高版本）、Java（JDK 和 JRE）1.7+/1.8+、Scala 2.11.x（或更高版本）、Python 2.6+/3.4+、R 3.1+和已安装的 RStudio 0.99.879（或更高版本）。可以使用 Eclipse Mars 或 Luna（最新版本）。此外，还需要 Maven Eclipse 插件（2.9 或更高版本）、用于 Eclipse 的 Maven 编译器插件（2.3.2 或更高版本）和用于 Eclipse 的 Maven 汇编插件（2.4.1 或更高版本）。最重要的是，重复使用 Packt 提供的`pom.xml`文件，并相应地更改先前提到的版本和 API，一切都会得到解决。

对于第九章《使用流式和图形数据进行高级机器学习》，几乎所有先前提到的所需软件都是必需的，除了 Twitter 数据收集示例，该示例将在 Spark 1.6.1 中展示。因此，需要 Spark 1.6.1 或 1.6.2，以及友好的 Maven `pom.xml`文件。

**操作系统要求：**

Spark 可以在多个操作系统上运行，包括 Windows、Mac OS 和 LINUX。然而，Linux 发行版更可取（包括 Debian、Ubuntu、Fedora、RHEL、CentOS 等）。更具体地说，例如对于 Ubuntu，建议使用 14.04/15.04（LTS）64 位完整安装或 VMWare player 12 或 Virtual Box。对于 Windows，建议使用 Windows（XP/7/8/10），对于 Mac OS X（10.4.7+）也是如此。

**硬件要求：**

为了顺利使用 Spark，建议使用至少核心 i3 或核心 i5 处理器的计算机。然而，为了获得最佳结果，核心 i7 将实现更快的数据处理和可伸缩性，至少需要 8GB RAM（建议）用于独立模式，至少需要 32GB RAM 用于单个 VM，或者用于集群的更高内存。此外，需要足够的存储空间来运行繁重的任务（取决于您将处理的数据大小），最好至少有 50GB 的免费磁盘存储空间（用于独立和 SQL 仓库）。

# 本书适合对象

由于 Python 和 R 是数据科学家常用的两种流行语言，因为有大量的模块或软件包可用来帮助他们解决数据分析问题。然而，这些工具的传统用法通常有限，因为它们在单台机器上处理数据，或者使用基于主存储器的方法处理数据，数据的移动变得耗时，分析需要抽样，并且从开发到生产环境的转换需要大量的重新设计。为了解决这些问题，Spark 提供了一个强大且统一的引擎，既快速又易于使用，这使您能够以交互方式解决机器学习问题，并且规模更大。

因此，如果您是学术界人士、研究人员、数据科学工程师，甚至是处理大型和复杂数据集的大数据工程师。此外，如果您想要加速数据处理管道和机器学习应用的扩展，这本书将是您旅程中的合适伴侣。此外，Spark 提供了许多语言选择，包括 Scala、Java 和 Python。这将帮助您将机器学习应用程序置于 Spark 之上，并使用这些编程语言之一进行重塑。

您应该至少熟悉机器学习概念的基础知识。了解开源工具和框架，如 Apache Spark 和基于 Hadoop 的 MapReduce，会很有帮助，但并非必需。我们期望您具备扎实的统计学和计算数学背景。此外，了解 Scala、Python 和 Java 是明智的。然而，如果您熟悉中级编程语言，这将有助于您理解本书中的讨论和示例。

# 约定

在这本书中，您会发现许多不同风格的文本，用以区分不同类型的信息。以下是一些这些风格的例子，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下: "我们可以通过使用 `include` 指令来包含其他上下文。"

在 Windows 环境中创建 Spark 会话的代码块设置如下:

```scala
[default]
SparkSession spark = SparkSession
                  .builder()
                  .appName("JavaFPGrowthExample")
                  .master("local[*]")
                  .config("spark.sql.warehouse.dir", "E:/Exp/")                  .getOrCreate();
```

或者从输入数据集创建简单的 RDD 设置如下:

```scala
[default]
            String filename = “input/dataset.txt”;
            RDD<String> data = spark.sparkContext().textFile(fileName, 1);
```

任何命令行输入或输出都以如下方式编写:

```scala
$ scp -i /usr/local/key/my-key-pair.pem  /usr/local/code/FPGrowth-0.0.1-SNAPSHOT-jar-with-dependencies.jar ec2-user@ec2-52-18-252-59.eu-west-1.compute.amazonaws.com:/home/ec2-user/

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词、菜单或对话框中的单词等都会以这样的方式出现在文本中: "点击 **下一步** 按钮将您移动到下一个屏幕"。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会出现在这样。


# 第一章：Spark 数据分析简介

本章概述了 Apache Spark、其计算范式和安装开始。它将简要描述 Spark 的主要组件，并专注于其新的计算进展。将讨论**弹性分布式数据集**（**RDD**）和数据集作为本书其余部分的基础知识。然后将专注于 Spark 机器学习库。然后演示如何安装和打包一个简单的机器学习应用程序与 Spark 和 Maven。简而言之，本章将涵盖以下主题：

+   Spark 概述

+   具有 Spark 的新计算范式

+   Spark 生态系统

+   Spark 机器学习库

+   安装和开始使用 Spark

+   打包您的应用程序与依赖项

+   运行一个简单的机器学习应用程序

# Spark 概述

本节介绍了 Spark（[`spark.apache.org/`](https://spark.apache.org/)）的基础知识，然后介绍了传统并行和分布式计算的问题，接着介绍了 Spark 的演变，以及它为大数据处理和分析带来了新的计算范式。此外，我们还介绍了一些令人兴奋的 Spark 功能，这些功能很容易吸引大数据工程师、数据科学家和研究人员，包括：

+   数据处理和计算的简单性

+   计算速度

+   在大规模数据集上的可伸缩性和吞吐量

+   对各种数据类型的复杂性

+   使用不同的集群管理器轻松进行集群计算和部署

+   与各种大数据存储和来源的工作能力和支持

+   广泛使用和新兴编程语言编写的多样化 API

## Spark 基础知识

在赞美 Spark 及其许多优点之前，有必要进行简要概述。Apache Spark 是一个快速、内存中的大数据处理和通用集群计算框架，具有一系列复杂的高级 API，用于高级数据分析。与基于 Hadoop 的 MapReduce 只适用于批处理作业的速度和易用性不同，Spark 可以被认为是一个适用于对静态（批处理）和实时数据应用高级分析的通用执行引擎：

+   Spark 最初是在加州大学伯克利分校的 AMPLab 基于**弹性分布式数据集**（**RDDs**）开发的，它为内存集群计算设施提供了容错抽象。然而，后来 Spark 的代码库被捐赠给了 Apache 软件基金会，使其成为开源，自那时起，开源社区一直在照顾它。Spark 提供了一个接口，通过其高级 API（Java、Scala、Python 和 R 编写）在整个集群上以规模执行数据分析，具有隐式数据并行性和容错性。

在 Spark 2.0.0 中，实现了提升的库（最广泛使用的数据分析算法），包括：

+   用于查询和处理大规模结构化数据的 Spark SQL

+   SparkR 用于统计计算，使用 R 语言进行分布式计算规模化

+   MLlib 用于机器学习（ML）应用程序，内部分为两部分；MLlib 用于基于 RDD 的机器学习应用程序开发和 Spark ML 用于开发完整的计算数据科学和机器学习工作流的高级抽象

+   用于大规模图形数据处理的 GraphX

+   Spark Streaming 用于处理大规模实时流数据，为静态机器学习提供动态工作环境

自其首个稳定版本发布以来，Spark 已经经历了戏剧性和迅速的发展，并得到了全球范围内各种 IT 解决方案提供商、开源社区和研究人员的积极倡导。最近，它已成为大数据处理和集群计算领域最活跃、最大的开源项目之一，不仅因为其广泛的采用，还因为全球范围内 IT 人员、数据科学家和大数据工程师对其部署和调查。正如 Spark 的创始人、Databricks 的 CTO Matei Zaharia 在*Big Data analytics*新闻网站上所说：

> *这是一件有趣的事情。在商业上并没有引起太多噪音，但实际的开发者社区通过实际行动投票，人们实际上正在完成工作并与项目合作。*

尽管许多科技巨头如雅虎、百度、Conviva、ClearStory、Hortonworks、Gartner 和腾讯已经在生产中使用 Spark，另一方面，IBM、DataStax、Cloudera 和 BlueData 为企业提供了商业化的 Spark 分发。这些公司已经热情地在规模庞大的集群上部署了 Spark 应用程序，共同处理了数百 PB 的数据，这是已知的最大的 Spark 集群。

## Spark 的优点

您计划开发机器学习（ML）应用程序吗？如果是这样，您可能已经有一些数据在训练模型之前进行预处理，最终，您将使用训练好的模型对新数据进行预测以查看适应性。这就是您需要的全部吗？我们猜想不是，因为您还必须考虑其他参数。显然，您希望您的 ML 模型在准确性、执行时间、内存使用、吞吐量、调整和适应性方面都能完美运行。等等！还没有结束；如果您希望您的应用程序能够处理大规模的训练和新数据集呢？或者作为数据科学家，如果您可以构建您的 ML 模型，以克服这些问题，从数据整合到训练和错误再到生产的多步旅程，通过在大集群和个人计算机上运行相同的机器学习代码而不会进一步崩溃？您可以简单地依靠 Spark 并闭上眼睛。

Spark 相对于其他大数据技术（如 MapReduce 和 Storm）具有几个优势。首先，Spark 提供了一个全面统一的引擎，以满足各种数据集（文本、表格、图形数据）和数据源（批处理和实时流数据）的大数据处理需求。作为用户（数据科学工程师、学者或开发人员），您可能会从 Spark 的快速应用程序开发中受益，因为它具有简单易懂的 API，可用于批处理、交互和实时流应用程序。

使用 Spark 进行工作和编程是简单易行的。让我们来展示一个例子。雅虎是 Spark 的贡献者和早期采用者之一，他们用 120 行 Scala 代码实现了一个 ML 算法。仅仅 30 分钟的大型数据集训练，包含 1 亿条记录，Scala ML 算法就准备好投入使用了。令人惊讶的是，之前使用 C++编写相同算法需要 15000 行代码（请参考以下网址获取更多信息：[`www.datanami.com/2014/03/06/apache_spark_3_real-world_use_cases/`](https://www.datanami.com/2014/03/06/apache_spark_3_real-world_use_cases/)）。您可以使用 Java、Scala、R 或 Python 开发您的应用程序，并使用 100 多个高级操作符（大多数在 Spark 1.6.1 发布后支持）来转换数据集，并熟悉数据框 API，以操作半结构化、结构化和流数据。除了 Map 和 Reduce 操作，它还支持 SQL 查询、流数据、机器学习和图数据处理。此外，Spark 还提供了用 Scala 和 Python 编写的交互式 shell，用于顺序执行代码（如 SQL 或 R 风格）。

Spark 之所以迅速被采用的主要原因是因为两个主要因素：速度和复杂性。Spark 为许多应用程序提供了数量级的性能，使用粗粒度、不可变和复杂的数据，称为弹性分布式数据集，这些数据集分布在集群中，并且可以存储在内存或磁盘中。RDD 提供了容错性，即一旦创建就无法更改。此外，Spark 的 RDD 具有从其血统中重新创建的属性，如果在计算过程中丢失，它可以重新创建。此外，RDD 可以通过分区自动分布到集群中，并且可以保存您的数据。您还可以通过 Spark 的缓存机制将数据保存在内存中，并且这种机制使得基于 Hadoop 的 MapReduce 集群中的大数据应用程序在内存中执行时速度提高了 100 倍，甚至在基于磁盘的操作中提高了 10 倍。

让我们来看一下关于 Spark 及其计算能力的一个令人惊讶的统计数据。最近，Spark 通过完成 2014 年 Gray Sort Benchmark 中的 100 TB 类别，取代了基于 Hadoop 的 MapReduce，这是一个关于系统能够多快地对 100 TB 数据（1 万亿条记录）进行排序的行业基准（请参考[`spark.apache.org/news/spark-wins-daytona-gray-sort-100tb-benchmark.html`](http://spark.apache.org/news/spark-wins-daytona-gray-sort-100tb-benchmark.html)和[`sortbenchmark.org/`](http://sortbenchmark.org/)）。最终，它成为了用于对 PB 级数据进行排序的开源引擎（请参考以下网址获取更多信息[`databricks.com/blog/2014/11/05/spark-officially-sets-a-new-record-in-large-scale-sorting.html`](https://databricks.com/blog/2014/11/05/spark-officially-sets-a-new-record-in-large-scale-sorting.html)）。相比之下，之前由 Hadoop MapReduce 创下的世界纪录需要使用 2100 台机器，执行时间为 72 分钟，这意味着 Spark 使用了 10 倍少的机器，以三倍的速度对相同的数据进行了排序。此外，您可以无缝地结合多个库来开发大规模机器学习和数据分析管道，以在各种集群管理器（如 Hadoop YARN、Mesos 或通过访问数据存储和源（如 HDFS、Cassandra、HBase、Amazon S3 甚至 RDBMs）在云中执行作业。此外，作业可以作为独立模式在本地 PC 或集群上执行，甚至在 AWS EC2 上执行。因此，将 Spark 应用程序部署到集群上非常容易（我们将在本章后面展示如何在集群上部署 Spark 应用程序）。

Spark 的其他优点是：它是开源的，平台无关的。这两点也是它的最大优势，即可以免费使用、分发和修改，并在任何平台上开发应用程序。开源项目也更安全，因为代码对每个人都是可访问的，任何人都可以在发现错误时修复错误。因此，Spark 发展得如此迅速，以至于它已成为涉及大数据解决方案的最大开源项目，拥有来自 200 多个组织的 750 多名贡献者。

# 具有 Spark 的新计算范式

在本节中，我们将展示 Spark 的发展历程，以及它如何成为大数据处理和集群计算的革命。除此之外，我们还将简要描述 Spark 生态系统，以更详细地了解 Spark 的特点和功能。

## 传统分布式计算

传统的数据处理范式通常被称为客户端-服务器模型，人们过去常常将数据移动到代码中。数据库服务器（或简称服务器）主要负责执行数据操作，然后将结果返回给客户端-服务器（或简称客户端）程序。然而，当需要计算的任务数量增加时，各种操作和客户端设备也开始呈指数级增长。因此，服务器中的计算端点也开始逐渐复杂起来。因此，为了保持这种计算模型，我们需要增加应用程序（客户端）服务器和数据库服务器的平衡，以存储和处理增加的操作数量。因此，节点之间的数据传播和网络中来回传输的数据也急剧增加。因此，网络本身成为性能瓶颈。因此，在这种计算范式中，性能（无论是可伸缩性还是吞吐量）也无疑会下降。如下图所示：

![传统分布式计算](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00124.jpeg)

图 1：传统分布式处理的实际应用。

在生命科学中成功完成人类基因组计划后，实时物联网数据、传感器数据、移动设备数据和网络数据正在创造数据洪流，并为大数据做出贡献，这在很大程度上推动了数据密集型计算的发展。如今，数据密集型计算正在以一种新兴的方式不断发展，这需要一个集成的基础设施或计算范式，以便将计算资源和数据带入一个共同的平台，并在其上进行分析。原因是多样的，因为大数据在复杂性（**容量**、**多样性**和**速度**）方面确实非常庞大，从操作角度来看，还有四个 ms（即**移动**、**管理**、**合并**和**整理**）。

此外，由于本书将讨论大规模机器学习应用程序，我们还需要考虑一些额外的关键评估参数，如有效性、真实性、价值和可见性，以促进业务增长。可见性很重要，因为假设你有一个大小为 1PB 的大数据集；但是如果没有可见性，一切都是一个黑洞。我们将在接下来的章节中更详细地解释大数据价值。

在单个系统中存储和处理这些大规模和复杂的大型数据集可能是不可行的；因此，它们需要被分区并存储在多台物理机器上。大型数据集被分区或分布，但为了处理和分析这些严格复杂的数据集，数据库服务器和应用程序服务器可能需要增加，以加强大规模的处理能力。同样，多维度中出现的性能瓶颈问题最糟糕，需要一种新的、更数据密集的大数据处理和相关计算范式。

## 将代码移动到数据

为了克服先前提到的问题，迫切需要一种新的计算范式，这样我们就可以将代码或应用程序移动到数据中，执行数据操作、处理和相关计算（也就是说，数据存储的地方）。由于您已经了解了动机和目标，现在可以将反转的编程模型称为**将代码移动到数据并在分布式系统上进行并行处理**，可以在以下图表中可视化：

![将代码移动到数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00111.jpeg)

图 2：新的计算（将代码移动到数据并在分布式系统上进行并行处理）。

为了理解*图 2*中所示的工作流程，我们可以设想一个新的编程模型，描述如下：

+   使用您在个人计算机上启动的应用程序执行大数据处理（让我们称之为**驱动程序**），它在集群、网格或更开放地说是云中远程协调执行。

+   现在你需要做的是将开发的应用程序/算法/代码段（可以使用命令行或 shell 脚本调用或撤销）转移到具有大容量存储、主存储器和处理能力的计算/工作节点。我们可以简单地想象要计算或操作的数据已经存储在这些计算节点中，作为分区或块。

+   可以理解的是，由于网络或计算瓶颈，大容量数据不再需要传输（上传/下载）到驱动程序，而是仅在其变量中保存数据引用，基本上是一个地址（主机名/IP 地址和端口），用于在集群中定位存储在计算节点中的物理数据（当然，也可以使用其他解决方案进行大容量上传，例如可扩展的配置，将在后面的章节中讨论）。

+   那么远程计算节点有什么？它们既有数据，也有执行数据计算和必要处理以实现输出或修改数据的代码，而不离开它们的家（更准确地说是计算节点）。

+   最后，根据您的请求，只有结果可以通过网络传输到您的驱动程序进行验证或其他分析，因为原始数据集有许多子集。

值得注意的是，通过将代码移动到数据，计算结构已经发生了巨大变化。最有趣的是，网络传输的数据量显著减少。这里的理由是，您只会将一小部分软件代码传输到计算节点，并收到原始数据的一个小子集作为返回的结果。这是 Spark 为我们带来的大数据处理最重要的范式转变，它引入了 RDD、数据集、DataFrame 和其他有利特性，这意味着在大数据工程和集群计算历史上有着巨大的革命。然而，为了简洁起见，下一节我们将只讨论 RDD 的概念，其他计算特性将在接下来的章节中讨论。

## RDD - 一种新的计算范式

为了理解新的计算范式，我们需要了解**弹性分布式数据集**（**RDDs**）的概念及 Spark 如何实现数据引用的概念。因此，它已经能够轻松地将数据处理扩展。RDD 的基本特点是它帮助您几乎像处理任何其他数据对象一样处理输入数据集。换句话说，它带来了输入数据类型的多样性，这是您在基于 Hadoop 的 MapReduce 框架中极度缺失的。

RDD 以一种弹性的方式提供了容错能力，一旦创建就无法更改，Spark 引擎将尝试在操作失败时迭代操作。它是分布式的，因为一旦执行了分区操作，RDD 会自动通过分区在集群中分布。RDD 允许您更多地处理输入数据集，因为 RDD 也可以快速而稳健地转换为其他形式。同时，RDD 也可以通过操作转储并在逻辑上相关或计算上同质的应用程序之间共享。这是因为它是 Spark 通用执行引擎的一部分，可以获得大规模的并行性，因此几乎可以应用于任何类型的数据集。

然而，为了在输入数据上进行 RDD 和相关操作，Spark 引擎要求您在数据指针（即引用）和输入数据本身之间建立明显的界限。基本上，您的驱动程序不会保存数据，而只会保存数据的引用，数据实际上位于集群中的远程计算节点上。

为了使数据处理更快、更容易，Spark 支持可以在 RDD 上执行的两种操作：转换和操作（请参考*图 3*）。转换操作基本上是从现有数据集创建一个新数据集。另一方面，操作在成功计算远程服务器上的输入数据集后，将一个值实现为驱动程序（更确切地说是计算节点）。

由驱动程序启动的数据执行方式构建了一个**有向无环图**（**DAG**）样式的图表；其中节点表示 RDD，转换操作由边表示。然而，执行本身直到执行操作之前不会在 Spark 集群中的计算节点中开始。然而，在开始操作之前，驱动程序将执行图（表示数据计算流水线或工作流的操作方式）和代码块（作为特定领域的脚本或文件）发送到集群，每个工作节点/计算节点从集群管理节点接收一个副本：

![RDD-一种新的计算范式](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00113.jpeg)

图 3：RDD 的操作（转换和操作操作）。

在继续下一节之前，我们建议您更详细地了解操作和转换操作。虽然我们将在第三章中详细讨论这两种操作，但目前 Spark 支持两种类型的转换操作。第一种是窄转换，其中数据混合是不必要的。典型的 Spark 窄转换操作使用`filter()`、`sample()`、`map()`、`flatMap()`、`mapPartitions()`等方法进行。宽转换对于对输入数据集进行更广泛的更改是必不可少的，以便将数据从多个数据分区中的共同节点中带出。宽转换操作包括`groupByKey()`、`reduceByKey()`、`union()`、`intersection()`、`join()`等。

动作操作通过触发执行作为**有向无环图**（**DAG**）样式返回 RDD 计算的最终结果到驱动程序。但实际上，材料化的结果实际上是写在存储中的，包括数据对象的中间转换结果，并返回最终结果。常见的动作包括：`first()`、`take()`、`reduce()`、`collect()`、`count()`、`saveAsTextFile()`、`saveAsSequenceFile()`等。在这一点上，我们相信您已经掌握了 RDD 的基本操作，因此我们现在可以以自然的方式定义 RDD 和相关程序。Spark 提供的典型 RDD 编程模型可以描述如下：

+   从环境变量中，Spark 上下文（Spark shell 或 Python Pyspark 为您提供了一个 Spark 上下文，或者您可以自己创建，这将在本章后面描述）创建一个初始数据引用 RDD 对象。

+   通过转换初始 RDD 以创建更多的 RDD 对象，遵循函数式编程风格（稍后将讨论）。

+   将代码/算法/应用程序从驱动程序发送到集群管理器节点。然后集群管理器为每个计算节点提供一个副本。

+   计算节点在其分区中保存 RDD 的引用（同样，驱动程序也保存数据引用）。然而，计算节点也可以由集群管理器提供输入数据集。

+   在转换之后（通过窄转换或宽转换），生成的结果将是全新的 RDD，因为原始的 RDD 不会被改变。最后，通过动作将 RDD 对象或更多（具体数据引用）实现为将 RDD 转储到存储中。

+   驱动程序可以请求计算节点为程序的分析或可视化结果请求一部分结果。

等等！到目前为止，我们一切顺利。我们假设您将把应用程序代码发送到集群中的计算节点。但是您仍然需要上传或发送输入数据集到集群中以分发给计算节点。即使在大量上传期间，您也需要通过网络传输数据。我们还认为应用程序代码和结果的大小是可以忽略不计的。另一个障碍是，如果您/我们希望 Spark 进行规模计算的数据处理，可能需要首先从多个分区合并数据对象。这意味着我们需要在工作节点/计算节点之间进行数据洗牌，通常通过`partition()`、`intersection()`和`join()`转换操作来完成。

坦率地说，数据传输并没有完全消除。正如我们和你理解的那样，特别是对于这些操作的大量上传/下载所贡献的开销，它们对应的结果如下：

![RDD - 一种新的计算范式](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00062.jpeg)

图 4：RDD 的操作（缓存机制）。

好吧，我们已经受到了这些负担的影响是事实。然而，使用 Spark 的缓存机制可以显著减少或解决这些情况。想象一下，您将在相同的 RDD 对象上多次执行操作，这些对象具有很长的血统；这将导致执行时间的增加以及计算节点内部的数据移动。您可以使用 Spark 的缓存机制（*图 4*）来消除（或至少减少）这种冗余，该机制将 RDD 的计算结果存储在内存中。这样就可以消除每次的重复计算。因为当您在 RDD 上进行缓存时，其分区将加载到主内存中，而不是节点的磁盘（但是，如果内存空间不足，将使用磁盘）。这种技术使得 Spark 集群上的大数据应用程序在每一轮并行处理中明显优于 MapReduce。我们将在第三章中详细讨论 Spark 数据操作和其他技术，*通过了解数据来理解问题*。

# Spark 生态系统

为了提供更多增强和额外的大数据处理能力，Spark 可以配置并在现有基于 Hadoop 的集群上运行。正如已经提到的，尽管 Hadoop 提供了**Hadoop 分布式文件系统**（**HDFS**）以便廉价高效地存储大规模数据；然而，MapReduce 提供的计算完全基于磁盘。MapReduce 的另一个限制是；只能使用高延迟批处理模型执行简单计算，或者更具体地说是静态数据。另一方面，Spark 的核心 API 是用 Java、Scala、Python 和 R 编写的。与 MapReduce 相比，Spark 具有更通用和强大的编程模型，还提供了几个库，这些库是 Spark 生态系统的一部分，用于大数据分析、处理和机器学习领域的冗余功能。如*图 5*所示，Spark 生态系统包括以下组件：

![Spark 生态系统](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00103.jpeg)

图 5：Spark 生态系统（截至 Spark 1.6.1）。

正如我们已经提到的，可以无缝地结合这些 API 来开发大规模的机器学习和数据分析应用程序。此外，可以通过访问 HDFS、Cassandra、HBase、Amazon S3 甚至 RDBMs 等数据存储和源，在各种集群管理器上执行作业，如 Hadoop YARN、Mesos、独立或云端。

然而，Spark 还具有其他功能和 API。例如，最近思科宣布向 Spark 生态系统投资 1.5 亿美元，用于思科 Spark 混合服务（[`www.cisco.com/c/en/us/solutions/collaboration/cloud-collaboration/index.html`](http://www.cisco.com/c/en/us/solutions/collaboration/cloud-collaboration/index.html)）。因此，思科 Spark 开放 API 可以提高其在开发人员中的受欢迎程度（高度安全的协作和将智能手机系统连接到云端）。除此之外，Spark 最近集成了 Tachyon（[`ampcamp.berkeley.edu/5/exercises/tachyon.html`](http://ampcamp.berkeley.edu/5/exercises/tachyon.html)），这是一个分布式内存存储系统，可以经济地适应内存，进一步提高 Spark 的性能。

## Spark 核心引擎

Spark 本身是用 Scala 编写的，它是一种功能性的面向对象编程语言，运行在 JVM 之上。此外，如图 5 所示，Spark 的生态系统是建立在通用和核心执行引擎之上的，该引擎在不同语言中实现了一些可扩展的 API。较低级别的层或较高级别的层也使用 Spark 核心引擎作为通用执行作业执行引擎，并在其上提供所有其他功能。Spark Core 已经提到是用 Scala 编写的，并且在 Java 虚拟机上运行，高级 API（即 Spark MLlib、SparkR、Spark SQL、Dataset、DataFrame、Spark Streaming 和 GraphX）在执行时使用核心。

Spark 已经使内存计算模式得到了很大的可见度。这个概念（内存计算）使得 Spark 核心引擎能够通过通用执行模型来提高速度，从而开发多样化的应用程序。

用 Java、Scala、R 和 Python 编写的通用数据计算和机器学习算法的低级实现对大数据应用程序开发非常容易。Spark 框架是基于 Scala 构建的，因此在 Scala 中开发 ML 应用程序可以访问最新的功能，这些功能最初可能在其他 Spark 语言中不可用。然而，这并不是一个大问题，开源社区也关注全球开发者的需求。因此，如果您需要开发特定的机器学习算法，并希望将其添加到 Spark 库中，您可以向 Spark 社区做出贡献。Spark 的源代码在 GitHub 上是公开可用的。您可以提交拉取请求，开源社区将在将其添加到主分支之前审查您的更改或算法。有关更多信息，请查看 Spark Jira confluence 网站。

Python 以前是数据科学家的强大工具，Python 在 Spark 中的贡献也不例外。这意味着 Python 也有一些优秀的用于数据分析和处理的库；然而，它相对较慢。另一方面，R 具有丰富的环境，用于数据处理、数据预处理、图形分析、机器学习和统计分析，这可以帮助提高开发者的生产力。对于来自 Java 和 Hadoop 背景的开发者来说，Java 绝对是一个不错的选择。然而，Java 也有与 Python 类似的问题，因为 Java 也比 Scala 慢。

最近在 Databricks 网站上发布的一项调查显示，Spark 用户中有 58%使用 Python，71%使用 Scala，31%使用 Java，18%使用 R 来开发他们的 Spark 应用程序。然而，在本书中，我们将尽量以 Java 为主要示例，必要时会使用少量 Scala 来简化。这是因为许多读者非常熟悉基于 Java 的 MapReduce。然而，我们将在附录中提供一些在 Python 或 R 中使用相同示例的提示。

## Spark SQL

Spark SQL 是用于查询和结构化数据处理的 Spark 组件。需求是显而易见的，因为许多数据科学工程师和商业智能分析师也依赖于交互式 SQL 查询来探索来自 RDBMS 的数据。以前，企业经常使用 MS SQL 服务器、Oracle 和 DB2。然而，这些工具不具备可扩展性或交互性。因此，为了使其更容易，Spark SQL 提供了一个称为 DataFrames 和数据集的编程抽象，它们作为分布式 SQL 查询引擎，支持在现有部署和数据上执行未修改的 Hadoop Hive 查询，速度提高了 100 倍。Spark SQL 与 Spark 生态系统的其他部分强大地集成在一起。

最近，Spark 提供了一个新的实验性接口，通常称为数据集（将在下一节中详细讨论），它提供了与 RDD 相同的好处，可以强大地使用`lambda`函数。Lambda 源自 Lambda 演算（[`en.wikipedia.org/wiki/Lambda_calculus`](http://en.wikipedia.org/wiki/Lambda_calculus)），指的是计算机编程中的匿名函数。这是现代编程语言中的一个灵活概念，允许您快速编写任何函数而不给它们命名。此外，它还提供了一种写闭包的好方法。例如，在 Python 中：

```scala
def adder(x): 
    return lambda y: x + y 
add6 = adder(6) 
add4(4) 

```

它返回结果为`10`。另一方面，在 Java 中，如果一个整数是奇数还是偶数，可以类似地编写：

```scala
Subject<Integer> sub = x -> x % 2 = 0; // Tests if the parameter is even. 
boolean result = sub.test(8); 

true since 8 is divisible by 2.
```

请注意，在 Spark 2.0.0 中，Spark SQL 在 SQL 2003 支持的基础上大幅改进了 SQL 功能。因此，现在 Spark SQL 可以执行所有 99 个 TPC-DS 查询。更重要的是，现在原生 SQL 解析器支持 ANSI_SQL 和 Hive QL。原生 DDL 是一个可以执行的命令，它现在也支持 SQL 的子查询和规范化支持的视图。

## DataFrames 和数据集的统一

在最新的 Spark 2.0.0 版本中，在 Scala 和 Java 中，DataFrame 和数据集已经统一。换句话说，DataFrame 只是行数据集的类型别名。然而，在 Python 和 R 中，由于缺乏类型安全性，DataFrame 是主要的编程接口。对于 Java，不再支持 DataFrame，而只支持基于数据集和 RDD 的计算，DataFrame 已经过时（请注意，它已经过时 - 而不是被折旧）。虽然为了向后兼容性保留了 SQLContext 和 HiveContext；然而，在 Spark 2.0.0 版本中，替代 DataFrame 和数据集 API 的新入口点是 SparkSession。

## Spark Streaming

您可能希望您的应用程序能够处理和分析不仅是静态数据集，还有实时流数据。为了使您的愿望更容易实现，Spark Streaming 提供了将应用程序与流行的批处理和流数据源集成的功能。最常用的数据源包括 HDFS、Flume、Kafka 和 Twitter，它们可以通过它们的公共 API 使用。这种集成允许用户在流和历史数据上开发强大的交互式和分析应用程序。除此之外，容错特性是通过 Spark Streaming 实现的。

## 图计算 - GraphX

**GraphX**是建立在 Spark 之上的弹性分布式图计算引擎。GraphX 为希望以大规模交互方式构建、转换和推理图结构化数据的用户带来了革命。作为开发人员，您将享受到简单性，以便使用少量 Scala、Java 或 Python 代码表示大规模图（社交网络图、普通网络图或天体物理学）。GraphX 使开发人员能够充分利用数据并行和图并行系统，通过简单快速地表达图计算。GraphX 柜中增加的另一个美丽之处是，它可以用于构建实时流数据上的端到端图分析管道，其中图空间分区用于处理具有与每个顶点和边相关的属性的大规模有向多图。为了实现这一点，使用了一些基本的图操作符，如子图、joinVertices 和 aggregateMessages，以及 Pregel API 的优化变体。

## 机器学习和 Spark ML 管道

传统的机器学习应用程序是使用 R 或 Matlab 构建的，存在可扩展性问题。Spark 引入了两个新兴的 API，Spark MLlib 和 Spark ML。这些 API 使得机器学习成为了工程大数据的可行见解，以消除可扩展性约束。建立在 Spark 之上，MLlib 是一个可扩展的机器学习库，拥有众多高质量的算法，具有高精度性能，主要适用于 RDD。Spark 为开发人员提供了许多语言选项，包括 Java、Scala、R 和 Python，以开发完整的工作流程。另一方面，Spark ML 是一个 ALPHA 组件，它增强了一组新的机器学习算法，让数据科学家可以快速组装和配置基于 DataFrames 的实用机器学习管道。

## 统计计算 - SparkR

SparkR 是一个专为熟悉 R 语言并希望分析大型数据集并从 R shell 交互式运行作业的数据科学家设计的 R 包，支持所有主要的 Spark DataFrame 操作，如聚合、过滤、分组、摘要统计等。同样，用户还可以从本地 R 数据框或任何 Spark 支持的数据源（如 Hive、HDFS、Parquet 或 JSON）创建 SparkR 数据框。从技术上讲，Spark DataFrame 的概念类似于 R 的本机 DataFrame（[`cran.r-project.org/web/packages/dplyr/vignettes/data_frames.html`](https://cran.r-project.org/web/packages/dplyr/vignettes/data_frames.html)），另一方面，在语法上类似于`dplyr`（一个 R 包，参见[`cran.rstudio.com/web/packages/dplyr/vignettes/introduction.html`](https://cran.rstudio.com/web/packages/dplyr/vignettes/introduction.html)），但存储在集群设置中。

# Spark 机器学习库

在本节中，我们将描述两个主要的机器学习库（Spark MLib 和 Spark ML）以及最广泛使用的实现算法。最终目标是让您对 Spark 的机器学习宝藏有所了解，因为许多人仍然认为 Spark 只是一个通用的内存大数据处理或集群计算框架。然而，情况并非如此，相反，这些信息将帮助您了解使用 Spark 机器学习 API 可以做些什么。此外，这些信息将帮助您探索并增加使用 Spark MLlib 和 Spark ML 部署实际机器学习管道的可用性。

## 使用 Spark 进行机器学习

在 Spark 时代之前，大数据建模者通常使用统计语言（如 R 和 SAS）构建他们的机器学习模型。然后数据工程师通常会重新在 Java 中实现相同的模型以部署在 Hadoop 上。然而，这种工作流程缺乏效率、可伸缩性、吞吐量和准确性，执行时间也较长。使用 Spark，可以构建、采用和部署相同的机器学习模型，使整个工作流程更加高效、稳健和快速，从而提供实时洞察力以提高性能。Spark 机器学习库的主要目标是使实际的机器学习应用可扩展、更快速和更容易。它包括常见和广泛使用的机器学习算法及其实用工具，包括分类、回归、聚类、协同过滤和降维。它分为两个包：Spark MLlib（`spark.mllib`）和 Spark ML（`spark.ml`）。

## Spark MLlib

MLlib 是 Spark 的机器学习库。它是一个分布式的低级库，使用 Scala、Java 和 Python 针对 Spark 核心运行时编写。MLlib 主要关注学习算法及其适当的实用工具，不仅提供机器学习分析能力。主要的学习工具包括分类、回归、聚类、推荐系统和降维。此外，它还有助于优化用于开发大规模机器学习流水线的通用原语。正如前面所述，MLlib 带有一些令人兴奋的 API，使用 Java、Scala、R 和 Python 编写。Spark MLlib 的主要组件将在以下部分中描述。

### 数据类型

Spark 提供了支持存储在单台机器上的本地向量和矩阵数据类型，以及由一个或多个 RDD 支持的分布式矩阵。本地向量和矩阵是简单的数据模型，用作公共接口。向量和矩阵操作严重依赖于线性代数运算，建议在使用这些数据类型之前先获取一些背景知识。

### 基本统计

Spark 不仅提供了对 RDD 进行列摘要和基本统计的功能，还支持计算两个或多个数据系列之间的相关性，或者更复杂的相关性操作，例如在许多数据系列之间的成对相关性，这是统计学中的常见操作。然而，目前仅支持 Pearson 和 Spearman 的相关性，未来 Spark 版本将添加更多相关性。与其他统计函数不同，Spark 还支持分层抽样，并且可以在 RDD 的键值对上执行；但是，一些功能尚未添加到 Python 开发人员。

Spark 仅提供 Pearson 卡方检验用于假设检验的拟合优度和声明假设的独立性，这是统计学中的一种强大技术，用于确定结果是否在统计上显著以满足声明。Spark 还提供了一些在线实现的测试，以支持诸如 A/B 测试之类的用例，通常在实时流数据上执行显著性测试。Spark 的另一个令人兴奋的功能是生成随机双重 RDD 或向量 RDD 的工厂方法，这对于随机算法、原型、性能和假设检验非常有用。当前 Spark MLib 中的其他功能提供了从样本 RDD 计算核密度估计的计算功能，这是一种用于可视化经验概率分布的有用技术。

### 分类和回归

分类是一个典型的过程，它帮助新的数据对象和组件根据训练数据进行组织、区分和理解，或者以某种方式属于某种方式。在统计计算中，存在两种类型的分类，二元分类（也常常被称为二项分类）和多类分类。二元分类是将给定观察的数据对象分类为两组的任务。**支持向量机**（**SVMs**）、逻辑回归、决策树、随机森林、梯度提升树和朴素贝叶斯已经实现到 Spark 的最新版本。

多类分类，另一方面，是将给定观察的数据对象分类到两组以上的任务。逻辑回归、决策树、随机森林和朴素贝叶斯被实现为多类分类。然而，更复杂的分类算法，如多级分类和多类感知器尚未被实现。回归分析也是一种估计变量或观察之间关系的统计过程。除了分类过程，回归分析还涉及多种建模和分析数据对象的技术。目前，Spark MLlib 库支持以下算法：

+   线性最小二乘

+   套索

+   岭回归

+   决策树

+   随机森林

+   梯度提升树

+   等渗回归

### 推荐系统开发

智能和可扩展的推荐系统是一种新兴的应用，目前许多企业正在开发，以扩大他们的业务和成本，以实现对客户的推荐自动化。协同过滤方法是推荐系统中最广泛使用的算法，旨在填补用户-项目关联矩阵的缺失条目。例如，Netflix 就是一个例子，他们成功地减少了数百万美元的电影推荐。然而，目前 Spark MLlib 的实现只提供了基于模型的协同过滤技术。

基于模型的协同过滤算法的优点是用户和产品可以通过一小组潜在因素来描述，使用**交替最小二乘**（**ALS**）算法来预测缺失的条目。缺点是用户评分或反馈不能被考虑在内以预测兴趣。有趣的是，开源开发人员也在努力开发一种基于内存的协同过滤技术，以纳入 Spark MLib 中，其中用户评分数据可以用于计算用户或项目之间的相似性，使得机器学习模型更加多功能。

### 聚类

聚类是一种无监督的机器学习问题/技术。其目的是根据某种相似性概念将实体的子集彼此分组，通常用于探索性分析和开发分层监督学习管道。Spark MLib 提供了对各种聚类模型的支持，如 K 均值、高斯矩阵、**幂迭代聚类**（**PIC**）、**潜在狄利克雷分配**（**LDA**）、二分 K 均值和来自实时流数据的流式 K 均值。我们将在接下来的章节中更多地讨论监督/无监督和强化学习。

### 降维

处理高维数据既酷又需要满足与大数据相关的复杂性。然而，高维数据的一个问题是不需要的特征或变量。由于所有测量的变量可能对建立模型并不重要，为了回答感兴趣的问题，您可能需要减少搜索空间。因此，基于某些考虑或要求，我们需要在创建任何模型之前减少原始数据的维度，而不损害原始结构。

MLib API 的当前实现支持两种降维技术：**奇异值分解**（**SVD**）和**主成分分析**（**PCA**），用于存储在面向行的格式中的高瘦矩阵和任何向量。SVD 技术存在一些性能问题；然而，PCA 是降维中最广泛使用的技术。这两种技术在大规模 ML 应用中非常有用，但它们需要对线性代数有很强的背景知识。

### 特征提取和转换

Spark 提供了不同的技术，通过**词频-逆文档频率**（**TF-IDF**）、**Word2Vec**、**标准缩放器**、**ChiSqSelector**等，使特征工程易于使用。如果您正在从事或计划从事文本挖掘领域的工作，TF-IDF 将是 Spark MLlib 中一个有趣的选项。TF-IDF 提供了一种特征向量化方法，以反映术语对语料库中文档的重要性，这对开发文本分析管道非常有帮助。

此外，您可能对在文本分析的 ML 应用中使用 Word2Vec 计算机分布式词向量表示感兴趣。Word2Vec 的这一特性最终将使您在新颖模式领域的泛化和模型估计更加健壮。您还可以使用 StandardScaler 来通过基于列摘要统计的单位方差缩放或去除均值来规范提取的特征。在构建可扩展的 ML 应用程序的预处理步骤中通常在训练数据集中执行。假设您已通过这种方法提取了特征，现在您需要选择要纳入 ML 模型的特征。因此，您可能还对 Spark MLlib 的 ChiSqSelector 算法进行特征选择感兴趣。ChiSqSelector 在 ML 模型构建过程中尝试识别相关特征。显然，其目的是减少特征空间的大小以及树状方法中的搜索空间，并改善强化学习算法中的速度和统计学习行为。

### 频繁模式挖掘

在开始构建 ML 模型之前，分析大规模数据集通常是挖掘频繁项、最大频繁模式/项集、连续频繁模式或子序列等的第一步。Spark MLib 的当前实现提供了 FP-growth 的并行实现，用于挖掘频繁模式和关联规则。它还提供了另一个流行算法 PrefixSpan 的实现，用于挖掘序列模式。但是，您将需要根据需要定制算法来挖掘最大频繁模式。我们将在即将到来的章节中提供一个可扩展的 ML 应用程序，用于挖掘隐私并保留最大频繁模式。

## Spark ML

Spark ML 是一个 ALPHA 组件，它为用户提供了一组新的机器学习 API，让用户可以快速组装和配置实用的机器学习管道，基于 DataFrames。在赞扬 Spark ML 的特性和优势之前，我们应该了解可以应用和开发到各种数据类型的 DataFrames 机器学习技术，例如向量、非结构化（即原始文本）、图像和结构化数据。为了支持各种数据类型，使应用程序开发更容易，最近，Spark ML 采用了来自 Spark SQL 的 DataFrame 和 Dataset。

数据框架或数据集可以从支持基本和结构化类型的对象的 RDD 隐式或显式创建。Spark ML 的目标是提供一组统一的高级 API，构建在数据框架和数据集之上，而不是 RDD。它帮助用户创建和调整实际的机器学习管道。Spark ML 还提供了用于开发可扩展 ML 管道的特征估计器和转换器。Spark ML 系统化了许多 ML 算法和 API，使得更容易将多个算法组合成单个管道或数据工作流，使用数据框架和数据集的概念。

特征工程中的三个基本步骤是特征提取、特征转换和选择。Spark ML 提供了几种算法的实现，使这些步骤更容易。提取提供了从原始数据中提取特征的功能，而转换提供了从提取步骤中找到的特征进行缩放、转换或修改的功能，选择则帮助从第二步的较大特征集中选择子集。Spark ML 还提供了几种分类（逻辑回归、决策树分类器、随机森林分类器等）、回归（线性回归、决策树回归、随机森林回归、生存回归和梯度提升树回归）、决策树和树集成（随机森林和梯度提升树）以及聚类（K 均值和 LDA）算法的实现，用于在数据框架之上开发 ML 管道。我们将在第三章中更多地讨论 RDD 和数据框架及其基础操作，*通过了解数据来理解问题*。

# 安装和开始使用 Spark

Spark 是 Apache Hadoop 的继任者。因此，最好将 Spark 安装和工作到基于 Linux 的系统中，即使您也可以尝试在 Windows 和 Mac OS 上。还可以配置 Eclipse 环境以将 Spark 作为 Maven 项目在任何操作系统上运行，并将应用程序作为具有所有依赖项的 jar 文件捆绑。其次，您可以尝试从 Spark shell（更具体地说是 Scala shell）运行应用程序，遵循与 SQL 或 R 编程相同的方式：

第三种方法是从命令行（Windows）/终端（Linux/Mac OS）开始。首先，您需要使用 Scala 或 Java 编写您的 ML 应用程序，并准备具有所需依赖项的 jar 文件。然后，可以将 jar 文件提交到集群以计算 Spark 作业。

我们将展示如何以三种方式开发和部署 Spark ML 应用程序。但是，第一个前提是准备好您的 Spark 应用程序开发环境。您可以在许多操作系统上安装和配置 Spark，包括：

+   Windows（XP/7/8/10）

+   Mac OS X（10.4.7+）

+   Linux 发行版（包括 Debian、Ubuntu、Fedora、RHEL、CentOS 等）

### 注意

请查看 Spark 网站[`spark.apache.org/documentation.html`](https://spark.apache.org/documentation.html)获取与 Spark 版本和操作系统相关的文档。以下步骤向您展示如何在 Ubuntu 14.04（64 位）上安装和配置 Spark。请注意，Spark 2.0.0 运行在 Java 7+、Python 2.6+/3.4+和 R 3.1+上。对于 Scala API，Spark 2.0.0 使用 Scala 2.11。因此，您需要使用兼容的 Scala 版本（2.11.x）。

**步骤 1：Java 安装**

在安装 Spark 时，应将 Java 安装视为安装的强制要求之一，因为基于 Java 和 Scala 的 API 需要在系统上安装 Java 虚拟机。尝试以下命令验证 Java 版本：

```scala
$ java -version 

```

如果 Java 已经安装在您的系统上，您应该看到以下消息：

```scala
java version "1.7.0_80"
Java(TM) SE Runtime Environment (build 1.7.0_80-b15)
Java HotSpot(TM) 64-Bit Server VM (build 24.80-b11, mixed mode)

```

如果您的系统上没有安装 Java，请确保在进行下一步之前安装 Java。请注意，为了使用 lambda 表达式支持，建议在系统上安装 Java 8，最好同时安装 JDK 和 JRE。尽管对于 Spark 1.6.2 和之前的版本，Java 7 应该足够：

```scala
$ sudo apt-add-repository ppa:webupd8team/java
$ sudo apt-get update
$ sudo apt-get install oracle-java8-installer

```

安装后，请不要忘记设置`JAVA_HOME`。只需应用以下命令（我们假设 Java 安装在`/usr/lib/jvm/java-8-oracle`）：

```scala
$ echo "export JAVA_HOME=/usr/lib/jvm/java-8-oracle" >> ~/.bashrc 
$ echo "export PATH=$PATH:$JAVA_HOME/bin" >> ~/.bashrc

```

您可以在主目录中的`.bashrc`文件中手动添加这些环境变量。如果找不到文件，可能是隐藏的，因此需要进行探索。只需转到**视图**选项卡并启用**显示隐藏文件**。

**步骤 2：安装 Scala**

Spark 本身是用 Scala 编写的，因此您的系统上应该安装了 Scala。通过使用以下命令检查这一点非常简单：

```scala
$ scala -version

```

如果 Scala 已经安装在您的系统上，您应该在终端上收到以下消息：

```scala
Scala code runner version 2.11.8 -- Copyright 2002-2016, LAMP/EPFL

```

请注意，在编写此安装过程时，我们使用的是最新版本的 Scala，即 2.11.8。如果您的系统上没有安装 Scala，请确保安装 Scala，因此在进行下一步之前，您可以从 Scala 网站[`www.scala-lang.org/download/`](http://www.scala-lang.org/download/)下载最新版本的 Scala。下载完成后，您应该在下载文件夹中找到 Scala `tar`文件：

1.  通过从其位置提取 Scala `tar`文件来提取，或者在终端中键入以下命令来提取 Scala tar 文件：

```scala
 $ tar -xvzf scala-2.11.8.tgz 

```

1.  现在将 Scala 分发移动到用户的透视图（例如，`/usr/local/scala`）通过以下命令或手动执行：

```scala
 $ cd /home/Downloads/ 
 $ mv scala-2.11.8 /usr/local/scala 

```

1.  设置 Scala 主目录：

```scala
$ echo "export SCALA_HOME=/usr/local/scala/scala-2.11.8" >> 
        ~/.bashrc 
$ echo "export PATH=$PATH:$SCALA_HOME/bin" >> ~/.bashrc

```

1.  安装完成后，您应该使用以下命令进行验证：

```scala
 $ scala -version

```

1.  如果 Scala 已成功配置到您的系统上，您应该在终端上收到以下消息：

```scala
Scala code runner version 2.11.8 -- Copyright 2002-2016, LAMP/EPFL

```

**步骤 3：安装 Spark**

从 Apace Spark 网站[`spark.apache.org/downloads.html`](https://spark.apache.org/downloads.html)下载最新版本的 Spark。对于此安装步骤，我们使用了最新的 Spark 稳定版本 2.0.0 版本，预先构建为 Hadoop 2.7 及更高版本。下载完成后，您将在下载文件夹中找到 Spark `tar`文件：

1.  从其位置提取 Scala `tar`文件，或者在终端中键入以下命令来提取 Scala `tar`文件：

```scala
 $ tar -xvzf spark-2.0.0-bin-hadoop2.7.tgz 

```

1.  现在将 Scala 分发移动到用户的透视图（例如，`/usr/local/spark`）通过以下命令或手动执行：

```scala
 $ cd /home/Downloads/ 
 $ mv spark-2.0.0-bin-hadoop2.7 /usr/local/spark 

```

1.  安装完 Spark 后，只需应用以下命令：

```scala
$ echo "export SPARK_HOME=/usr/local/spark/spark-2.0.0-bin-hadoop2.7" >>
      ~/.bashrc 
$ echo "export PATH=$PATH:$SPARK_HOME/bin" >> ~/.bashrc

```

**步骤 4：使所有更改永久生效**

使用以下命令对`~/.bashrc`文件进行源操作，以使更改永久生效：

```scala
$ source ~/.bashrc

```

如果执行`$ vi ~/. bashrc`命令，您将在`bashrc`文件中看到以下条目如下：

```scala
export JAVA_HOME=/usr/lib/jvm/java-8-oracle
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/lib/jvm/java-8-oracle/bin:/usr/lib/jvm/java-8-oracle/db/bin:/usr/lib/jvm/java-8-oracle/jre/bin: /usr/lib/jvm/java-8-oracle/bin
export SCALA_HOME=/usr/local/scala/scala-2.11.8
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/lib/jvm/java-8-oracle/bin:/usr/lib/jvm/java-8-oracle/db/bin:/usr/lib/jvm/java-8-oracle/jre/bin: /bin
export SPARK_HOME=/usr/local/spark/spark-2.0.0-bin-hadoop2.7
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/lib/jvm/java-8-oracle/bin:/usr/lib/jvm/java-8-oracle/db/bin:/usr/lib/jvm/java-8-oracle/jre/bin: /bin

```

**步骤 5：验证 Spark 安装**

Spark 安装的验证显示在以下截图中：

![安装并开始使用 Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00149.jpeg)

图 6：Spark shell 确认了成功安装 Spark。

写以下命令以打开 Spark shell，以验证 Spark 是否已成功配置：

```scala
$ spark-shell

```

如果 Spark 安装成功，您应该看到以下消息（*图 6*）。

Spark 服务器将在本地主机的端口`4040`上启动，更确切地说是在`http://localhost:4040/`（*图 7*）。只需转到那里，以确保它是否真的在运行：

![安装并开始使用 Spark](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00075.jpeg)

图 7：Spark 作为本地 Web 服务器运行。

干得好！现在您已经准备好在 Spark shell 上开始编写 Scala 代码。

# 使用依赖项打包您的应用程序

现在我们将向您展示如何在 Eclipse 上将应用程序打包为带有所有必需依赖项的 Java 存档（`JAR`）文件，这是一个**集成开发环境**（**IDE**）和一个用于 Java 开发的开源工具，是 Apache Maven 项目（[`maven.apache.org/`](https://maven.apache.org/)）。Maven 是一个软件项目管理和理解工具，就像 Eclipse 一样。基于**项目对象模型**（**POM**）的概念，Maven 可以管理项目的构建、报告和文档编制，从一个中央信息中。

请注意，可以使用命令提示符将用 Java 或 Scala 编写的 ML 应用程序导出为存档/可执行的 jar 文件。但是，为了简化和加快应用程序开发，我们将使用与 Eclipse 相同的 Maven 项目，以便读者可以享受相同的便利性将应用程序提交到主节点进行计算。现在让我们转到讨论如何将频繁模式挖掘应用程序导出为带有所有依赖项的 jar 文件。

**步骤 1：在 Eclipse 中创建一个 Maven 项目**

成功创建示例 Maven 项目后，您将在 Eclipse 中看到以下项目结构，如*图 8*所示：

![使用依赖项打包应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00121.jpeg)

图 8：Eclipse 中的 Maven 项目结构。

**步骤 2：应用程序开发**

创建一个 Java 类，并将以下源代码复制到`src/main/java`目录下，用于挖掘频繁模式。在这里，输入文件名已经通过命令行参数或手动指定源代码来指定文件名字符串。目前，我们只提供了行注释，但是您将从第三章中了解详细信息，*通过了解数据来了解问题*以及之后的内容：

```scala
import java.util.Arrays; 
import java.util.List; 
import org.apache.spark.api.java.JavaRDD; 
import org.apache.spark.api.java.function.Function; 
import org.apache.spark.mllib.fpm.FPGrowth; 
import org.apache.spark.mllib.fpm.FPGrowthModel; 
import org.apache.spark.rdd.RDD; 
import org.apache.spark.sql.SparkSession; 

public class JavaFPGrowthExample { 
  public static void main(String[] args) { 
   //Specify the input transactional as command line argument  
   String fileName = "input/input.txt";  
   //Configure a SparkSession as spark by specifying the application name, master URL, Spark config, and Spark warehouse directory 
  SparkSession spark = SparkSession 
                  .builder() 
                  .appName("JavaFPGrowthExample") 
                  .master("local[*]") 
                  .config("spark.sql.warehouse.dir", "E:/Exp/") 
                  .getOrCreate(); 

   //Create an initial RDD by reading the input database  
   RDD<String> data = spark.sparkContext().textFile(fileName, 1); 

   //Read the transactions by tab delimiter & mapping RDD(data) 
   JavaRDD<List<String>> transactions = data.toJavaRDD().map( 
                   new Function<String, List<String>>(){ 
                   public List<String> call(String line) { 
                          String[] parts = line.split(" "); 
                          return Arrays.asList(parts); 
                                 } 
                             }); 

  //Create FPGrowth object by min. support & no. of partition     
  FPGrowth fpg = new  FPGrowth() 
                       .setMinSupport(0.2) 
                       .setNumPartitions(10); 

  //Train and run your FPGrowth model using the transactions 
  FPGrowthModel<String> model = fpg.run(transactions); 

  //Convert and then collect frequent patterns as Java RDD. After that print the frequent patterns along with their support 
    for (FPGrowth.FreqItemset<String> itemset :      
          model.freqItemsets().toJavaRDD().collect()) {   
       System.out.println(itemset.javaItems()  
                             + "==> " + itemset.freq()); 
      } 
    }   
  }  

```

**步骤 3：Maven 配置**

现在您需要配置 Maven，指定相关依赖项和配置。首先，编辑您现有的`pom.xml`文件，将每个 XML 源代码片段复制到`<dependencies>`标记内。请注意，根据 Spark 版本，您的依赖项可能会有所不同，因此请相应更改版本：

1.  Spark 核心依赖项用于 Spark 上下文和配置：

```scala
      <dependency> 
      <groupId>org.apache.spark</groupId> 
      <artifactId>spark-core_2.11</artifactId> 
      <version>2.0.0</version> 
     </dependency> 

```

1.  Spark MLib 依赖项用于 FPGrowth：

```scala
    <dependency> 
      <groupId>org.apache.spark</groupId> 
      <artifactId>spark-mllib_2.11</artifactId> 
      <version>2.0.0</version> 
     </dependency> 

```

现在您需要添加构建要求。将以下代码片段立即复制到`</dependencies>`标记之后。在这里，我们将`<groupId>`指定为 maven 插件，`<artifactId>`指定为 maven shade 插件，并使用`<finalName>`标记指定 jar 文件命名约定。确保您已经指定了源代码下载插件，设置了编译器级别，并为 Maven 设置了装配插件，如下所述：

1.  使用 Maven 指定源代码下载插件：

```scala
       <plugin> 
        <groupId>org.apache.maven.plugins</groupId> 
        <artifactId>maven-eclipse-plugin</artifactId> 
        <version>2.9</version> 
        <configuration> 
          <downloadSources>true</downloadSources> 
          <downloadJavadocs>false</downloadJavadocs> 
        </configuration> 
      </plugin>  

```

1.  为 Maven 设置编译器级别：

```scala
      <plugin> 
        <groupId>org.apache.maven.plugins</groupId> 
        <artifactId>maven-compiler-plugin</artifactId> 
        <version>2.3.2</version>         
      </plugin> 
      <plugin> 
        <groupId>org.apache.maven.plugins</groupId> 
        <artifactId>maven-shade-plugin</artifactId> 
        <configuration> 
          <shadeTestJar>true</shadeTestJar> 
        </configuration> 
      </plugin> 

```

1.  设置 Maven 装配插件：

```scala
      <plugin> 
        <groupId>org.apache.maven.plugins</groupId> 
        <artifactId>maven-assembly-plugin</artifactId> 
        <version>2.4.1</version> 
        <configuration> 
          <!-- get all project dependencies --> 
          <descriptorRefs> 
            <descriptorRef>jar-with-dependencies</descriptorRef> 
          </descriptorRefs> 
          <!-- MainClass in mainfest make a executable jar --> 
          <archive> 
            <manifest>              <mainClass>com.example.SparkFPGrowth.JavaFPGrowthExample</mainClass>            </manifest> 
          </archive> 
          <property> 
            <name>oozie.launcher.mapreduce.job.user.classpath.first</name> 
            <value>true</value> 
          </property> 
          <finalName>FPGrowth-${project.version}</finalName> 
        </configuration> 
        <executions> 
          <execution> 
            <id>make-assembly</id> 
            <!-- bind to the packaging phase --> 
            <phase>package</phase> 
            <goals> 
              <goal>single</goal> 
            </goals> 
          </execution> 
        </executions> 
      </plugin> 

```

完整的`pom.xml`文件，输入数据和 Java 源文件可以从我们的 GitHub 存储库[`github.com/rezacsedu/PacktMLwithSpark`](https://github.com/rezacsedu/PacktMLwithSpark)下载。请注意，我们使用了 Eclipse Mars Eclipse IDE for Java Developers，并且版本是 Mars Release (4.5.0)。您可以选择这个版本或其他发行版，比如 Eclipse Luna。

**步骤 4：Maven 构建**

在本节中，我们将描述如何在 Eclipse 上创建一个 Maven 友好的项目。在您按照所有步骤后，您将能够成功运行 Maven 项目。步骤应按照以下时间顺序进行：

1.  将您的项目作为 Maven 安装运行。

1.  如果您的代码和 Maven 配置文件没有问题，那么 Maven 构建将成功。

1.  构建 Maven 项目。

1.  右键单击您的项目，运行 Maven 项目为**Maven 构建...**，并在**Goals**选项中写入`clean package`。

1.  检查 Maven 依赖项。

1.  展开 Maven 依赖树，并检查是否已安装所需的 jar 文件。

1.  检查 jar 文件是否生成了依赖项。

1.  如我们所指定的，您应该在`/target`目录树下找到两个 jar 文件（参考*图 9*）。打包文件应该与`<finalName>`标签中指定的名称完全相同。现在将您的代码（jar 文件）移动到与我们的实验对齐的目录（即`/user/local/code`）和您的数据（即`/usr/local/data/`）。我们将在后期使用这个 jar 文件在 AWS EC2 集群上执行 Spark 作业。我们将在下一步讨论输入数据集。![使用依赖项打包您的应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00097.jpeg)

图 9：在 Eclipse 上生成了所有必需依赖项的 Maven 项目的 jar。

# 运行一个样本机器学习应用程序

在本节中，我们将描述如何从 Spark shell 在本地机器上以独立模式运行一个样本机器学习应用程序，最后我们将向您展示如何使用 Amazon EC2（[`aws.amazon.com/ec2/`](https://aws.amazon.com/ec2/)）部署和运行应用程序。

## 从 Spark shell 运行 Spark 应用程序

请注意，这只是一个检查安装和运行样本代码的练习。有关机器学习应用程序开发的详细信息将从第三章开始，*通过了解数据来理解问题*，到*第九章*，*使用流和图数据进行高级机器学习*。

现在我们将进一步进行一种流行的机器学习问题，也称为频繁模式挖掘，使用频繁模式增长或 FP-growth。假设我们有一个如下表所示的交易数据库。每行表示特定客户完成的交易。我们的目标是从数据库中找到频繁模式，这是计算关联规则（[`en.wikipedia.org/wiki/Association_rule_learning`](https://en.wikipedia.org/wiki/Association_rule_learning)）的先决条件，从客户购买规则中。将此数据库保存为`input.txt`，不包括交易 ID，在`/usr/local/data`目录中：

| **交易 ID** | **交易** |
| --- | --- |
| 12345678910 | A B C D FA B C EB C D E FA C D EC D FD E FD EC D FC FA C D E |

表 1：交易数据库。

现在让我们通过指定主机和要使用的计算核心数量来移动到 Spark shell，作为独立模式（这里有四个核心，例如）：

```scala
$ spark-shell --master "local[4]" 

```

第 1 步：加载软件包

加载所需的 FPGrowth 软件包和其他依赖软件包：

```scala
scala>import org.apache.spark.mllib.fpm.FPGrowth
scala>import org.apache.spark.{SparkConf, SparkContext}

```

第 2 步：创建 Spark 上下文

要创建一个 Spark 上下文，首先需要通过提及应用程序名称和主 URL 来配置 Spark 会话。然后，您可以使用 Spark 配置实例变量来创建一个 Spark 上下文，如下所示：

```scala
val conf = new SparkConf().setAppName(s"FPGrowthExample with $params")
val sc = new SparkContext(conf)

```

第 3 步：读取交易

让我们在创建的 Spark 上下文（`sc`）上将交易作为 RDDs 读取（参见*图 6*）：

```scala
scala> val transactions = sc.textFile(params.input).map(_.split(" ")).cache()

```

第 4 步：检查交易数量

这是用于检查交易数量的代码：

```scala
Scala>println(s"Number of transactions: ${transactions.count()}")
Number of transactions: 22
Scala>

```

第 5 步：创建 FPGrowth 模型

通过指定最小支持阈值（也请参阅[`en.wikipedia.org/wiki/Association_rule_learning`](https://en.wikipedia.org/wiki/Association_rule_learning)）和分区数来创建模型：

```scala
scala>val model = new FPGrowth()
 .setMinSupport(0.2)
 .setNumPartitions(2)
 .run(transactions)

```

第 6 步：检查频繁模式的数量

以下代码解释了如何检查频繁模式的数量：

```scala
scala> println(s"Number of frequent itemsets:
    ${model.freqItemsets.count()}")
Number of frequent itemsets: 18
Scala>

```

第 7 步：打印模式和支持

打印频繁模式及其相应的支持/频率计数（参见*图 10*）。Spark 作业将在本地主机上运行（参见*图 11*）：

```scala
scala> model.freqItemsets.collect().foreach { itemset => println(itemset.items.mkString("[", ",", "]") + ", " + itemset.freq)}

```

![从 Spark shell 运行 Spark 应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00106.jpeg)

图 10：频繁模式。

## 在本地集群上运行 Spark 应用程序

一旦用户应用程序被打包为 jar 文件（用 Scala 或 Java 编写）或 Python 文件，它可以使用 Spark 分发中 bin 目录下的`spark-submit`脚本启动。

根据 Spark 网站提供的 API 文档[`spark.apache.org/docs/2.0.0-preview/submitting-applications.html`](http://spark.apache.org/docs/2.0.0-preview/submitting-applications.html)，此脚本负责设置带有 Spark 及其依赖项的类路径，并且可以支持 Spark 支持的不同集群管理器和部署模型。简而言之，Spark 作业提交语法如下：

```scala
$spark-submit [options] <app-jar | python-file> [app arguments]

```

在这里，`[options]`可以是：`--class <main-class>``--master <master-url>``--deploy-mode <deploy-mode>`，以及许多其他选项。

更具体地说，`<main-class>`是主类名称，是我们应用程序的入口点。`<master-url>`指定了集群的主 URL（例如，`spark://HOST:PORT`用于连接给定的 Spark 独立集群主节点，local 用于在本地运行具有没有并行性的一个工作线程的 Spark，`local [k]`用于在具有 K 个工作线程的本地运行 Spark 作业，这是您计算机上的核心数，`local[*]`用于在具有与计算机上逻辑核心一样多的工作线程的本地运行 Spark 作业，`mesos://IP:PORT`用于连接到可用的 Mesos 集群，甚至您可以将作业提交到 Yarn 集群-有关更多信息，请参见[`spark.apache.org/docs/latest/submitting-applications.html#master-urls`](http://spark.apache.org/docs/latest/submitting-applications.html#master-urls)）。

`<deploy-mode>`用于在工作节点（集群）上部署我们的驱动程序，或者作为外部客户端（client）在本地部署。`<app-jar>`是我们刚刚构建的 jar 文件，包括所有依赖项。`<python-file>`是使用 Python 编写的应用程序主要源代码。`[app-arguments]`可以是应用程序开发人员指定的输入或输出参数：

![在本地集群上运行 Spark 应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00083.jpeg)

图 11：在本地主机上运行的 Spark 作业

因此，对于我们的情况，作业提交语法将如下所示：

```scala
$./bin/spark-submit --class com.example.SparkFPGrowth.JavaFPGrowthExample --master local[4] FPGrowth-0.0.1-SNAPSHOT-jar-with-dependencies.jar input.txt

```

在这里，`JavaFPGrowthExample`是用 Java 编写的主类文件；local 是主 URL；`FPGrowth-0.0.1-SNAPSHOT-jar-with-dependencies.jar`是我们刚刚通过 maven 项目生成的应用程序`jar`文件；`input.txt`是作为文本文件的事务数据库，output 是要生成输出的目录（在我们的情况下，输出将显示在控制台上）。现在让我们提交此作业以在本地执行。

如果成功执行，您将找到以下消息，包括*图 12*中的输出（摘要）：

![在本地集群上运行 Spark 应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00132.jpeg)

图 12：终端上的 Spark 作业输出。

## 在 EC2 集群上运行 Spark 应用程序

在前一节中，我们说明了如何在本地或独立模式下提交 spark 作业。在这里，我们将描述如何在集群模式下运行 spark 应用程序。为了使我们的应用程序在 spark 集群模式下运行，我们考虑**亚马逊弹性计算云**（**EC2**）服务，作为**基础设施即服务**（**IaaS**）或**平台即服务**（**PaaS**）。有关定价和相关信息，请参阅此网址[`aws.amazon.com/ec2/pricing/`](https://aws.amazon.com/ec2/pricing/)。

**步骤 1：密钥对和访问密钥配置**

我们假设您已经创建了 EC2 帐户。第一个要求是创建 EC2 密钥对和 AWS 访问密钥。EC2 密钥对是您在通过 SSH 进行安全连接到 EC2 服务器或实例时需要的私钥。要创建密钥，您必须通过 AWS 控制台 [`docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair`](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)。请参考*图 13*，显示了 EC2 帐户的密钥对创建页面：

![在 EC2 集群上运行 Spark 应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00139.jpeg)

图 13：AWS 密钥对生成窗口。

一旦下载并保存在本地机器上，请将其命名为`my-key-pair.pem`。然后通过执行以下命令确保权限（出于安全目的，您应该将此文件存储在安全位置，比如`/usr/local/key`）：

```scala
$ sudo chmod  400  /usr/local/key/my-key-pair.pem

```

现在您需要的是 AWS 访问密钥，您的帐户凭据，如果您想要使用 spark-ec2 脚本从本地机器提交您的 Spark 作业到计算节点。要生成和下载密钥，请登录到您的 AWS IAM 服务 [`docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_CreateAccessKey`](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_CreateAccessKey)。下载完成后（即`/usr/local/key`），您需要在本地机器上设置两个环境变量。只需执行以下命令：

```scala
$ echo "export AWS_ACCESS_KEY_ID=<access_key_id>" >> ~/.bashrc 
$ echo " export AWS_SECRET_ACCESS_KEY=<secret_access_key_id>" >> ~/.bashrc 

```

**步骤 2：在 EC2 上配置 Spark 集群**

Spark 分发（即`/usr/local/spark``/ec2`）提供了一个名为`spark-ec2`的脚本，用于从本地机器（驱动程序）在 EC2 实例上启动 Spark 集群，帮助启动、管理和关闭 Spark 集群。

### 注意

请注意，在 AWS 上启动集群将花费金钱。因此，当计算完成时，停止或销毁集群始终是一个好习惯。否则，将产生额外的费用。有关 AWS 定价的更多信息，请参阅此 URL [`aws.amazon.com/ec2/pricing/`](https://aws.amazon.com/ec2/pricing/)。

一旦您执行以下命令启动新实例，它将自动在集群上设置 Spark、HDFS 和其他依赖项：

```scala
$./spark-ec2 --key-pair=<name_of_the_key_pair> --identity-file=<path_of_the key_pair>  --instance-type=<AWS_instance_type > --region=<region> zone=<zone> --slaves=<number_of_slaves> --hadoop-major-version=<Hadoop_version> --spark-version=<spark_version> launch <cluster-name>

```

我们相信这些参数是不言自明的，或者，也可以在[`spark.apache.org/docs/latest/ec2-scripts.html`](http://spark.apache.org/docs/latest/ec2-scripts.html)上查看详细信息。对于我们的情况，应该是这样的：

```scala
$./spark-ec2 --key-pair=my-key-pair --identity-file=/usr/local/key/my-key-pair.pem  --instance-type=m3.2xlarge --region=eu-west-1 --zone=eu-west-1a --slaves=2 --hadoop-major-version=yarn --spark-version=1.6.0 launch ec2-spark-cluster-1

```

如下截图所示：

![在 EC2 集群上运行 Spark 应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00022.jpeg)

图 14：集群主页。

成功完成后，spark 集群将在您的 EC2 帐户上实例化两个工作（从属）节点。这个任务可能需要大约半个小时，具体取决于您的互联网速度和硬件配置。因此，您可能需要喝杯咖啡休息一下。在集群设置成功完成后，您将在终端上获得 Spark 集群的 URL。

要检查集群是否真的在运行，请在浏览器上检查此 URL `https://<master-hostname>:8080`，其中主机名是您在终端上收到的 URL。如果一切正常，您将发现您的集群正在运行，参见*图 14*中的集群主页。

**步骤 3：在 Spark 集群上运行和部署 Spark 作业**

执行以下命令连接到 SSH 远程 Spark 集群：

```scala
$./spark-ec2 --key-pair=<name_of_the_key_pair> --identity-file=<path_of_the _key_pair> --region=<region> login <cluster-name> 

```

对于我们的情况，应该是这样的：

```scala
$./spark-ec2 --key-pair=my-key-pair --identity-file=/usr/local/key/my-key-pair.pem --region=eu-west-1 login ec2-spark-cluster-1 

```

现在通过执行以下命令将您的应用程序（我们在 Eclipse 上生成的 Maven 项目的 jar 包）复制到远程实例（在我们的情况下是`ec2-52-48-119-121.eu-west-1.compute.amazonaws.com`）（在新终端中）：

```scala
$ scp -i /usr/local/key/my-key-pair.pem  /usr/local/code/FPGrowth-0.0.1-SNAPSHOT-jar-with-dependencies.jar ec2-user@ec2-52-18-252-59.eu-west-1.compute.amazonaws.com:/home/ec2-user/

```

然后，您需要通过执行以下命令将您的数据（在我们的情况下是`/usr/local/data/input.txt`）复制到同一远程实例：

```scala
$ scp -i /usr/local/key/my-key-pair.pem /usr/local/data/input.txt ec2-user@ec2-52-18-252-59.eu-west-1.compute.amazonaws.com:/home/ec2-user/ 

```

![在 EC2 集群上运行 Spark 应用程序](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00007.jpeg)

图 15：Spark 集群中作业运行状态。

干得好！您已经快完成了！现在，最后您需要提交您的 Spark 作业，让从节点或工作节点进行计算。要这样做，只需执行以下命令：

```scala
$./bin/spark-submit --class com.example.SparkFPGrowth.JavaFPGrowthExample --master spark://ec2-52-48-119-121.eu-west-1.compute.amazonaws.com:7077 /home/ec2-user/FPGrowth-0.0.1-SNAPSHOT-jar-with-dependencies.jar /home/ec2-user/input.txt

```

作业计算成功完成后，您应该在端口 8080 上看到作业的状态，就像*图 15*一样（输出将显示在终端上）。

第四步：暂停和重新启动 Spark 集群

要停止您的集群，请从本地机器执行以下命令：

```scala
$./ec2/spark-ec2 --region=<ec2-region> stop <cluster-name>

```

对于我们的情况，将会是：

```scala
$./ec2/spark-ec2 --region=eu-west-1 stop ec2-spark-cluster-1

```

要稍后重新启动集群，请执行以下命令：

```scala
$./ec2/spark-ec2 -i <key-file> --region=<ec2-region> start <cluster-name>

```

对于我们的情况，将会是以下内容：

```scala
$./ec2/spark-ec2 --identity-file=/usr/local/key/my-key-pair.pem --region=eu-west-1 start ec2-spark-cluster-1

```

### 提示

要终止您的 Spark 集群：`$./spark-ec2 destroy <cluster-name>`

在我们的情况下，将是：`$./spark-ec2 --region=eu-west-1 destroy ec2-spark-cluster-1`

如果您希望您的应用程序针对大规模数据集进行扩展，最快的方法是将它们从 Amazon S3 或 Amazon EBS 设备加载到节点上的 Hadoop 分布式文件系统（HDFS）中。我们将在后面的章节中通过实际的机器学习示例讨论这种技术。

# 参考文献

+   *弹性分布式数据集*：*内存集群计算的容错抽象*，*Zaharia，Mosharaf Chowdhury，Tathagata Das，Ankur Dave，Justin Ma，Murphy McCauley，Michael J*. *Franklin，Scott Shenker，Ion Stoica。NSDI 2012*。2012 年 4 月。

+   *Spark*：*使用工作集进行集群计算*，*Matei Zaharia，Mosharaf Chowdhury，Michael J*. *Franklin，Scott Shenker，Ion Stoica，HotCloud 2010*。2010 年 6 月。

+   *Spark SQL*：*Spark 中的关系数据处理*，*Michael Armbrust，Reynold S. Xin，Cheng Lian，Yin Huai，Davies Liu，Joseph K. Bradley，Xiangrui Meng，Tomer Kaftan，Michael J. Franklin，Ali Ghodsi，Matei Zaharia，SIGMOD 2015*。2015 年 6 月。

+   *离散化流*：*规模化的容错流计算*，*Matei Zaharia，Tathagata Das，Haoyuan Li，Timothy Hunter，Scott Shenker，Ion Stoica。SOSP 2013*。2013 年 11 月。

+   *离散化流*：*大规模集群上流处理的高效容错模型*。*Matei Zaharia，Tathagata Das，Haoyuan Li，Scott Shenker，Ion Stoica。HotCloud 2012*。2012 年 6 月。

+   *GraphX*：*统一数据并行和图并行分析*。*Reynold S. Xin，Daniel Crankshaw，Ankur Dave，Joseph E.* **Gonzalez，Michael J. Franklin**，*Ion Stoica。OSDI 2014*。2014 年 10 月。

+   *MLlib*：*Apache Spark 中的机器学习*，*Meng 等人*。*arXiv:1505.06807v1，[cs.LG]，2015 年 5 月 26 日。

+   *推荐系统*：*协同过滤技术分析*，*Christopher R. Aberger*，*斯坦福出版物，2014 年*。

# 总结

这结束了我们对 Spark 的相当快速的介绍。我们已经尝试涵盖了 Spark 的一些最基本的特性，它的计算范式，并通过安装和配置开始使用 Spark。如果 Spark ML 适合机器学习流水线概念（例如特征提取、转换和选择），则建议使用它，因为它在 DataFrame 和 Dataset 方面更加灵活多变。然而，根据 Apache 的文档，他们将继续支持和贡献 Spark MLib，并与 Spark ML 的积极开发一起。

另一方面，数据科学开发人员应该熟悉使用 Spark MLlib 的特性，并期待将来有更多的特性。然而，一些算法目前尚不可用，或者有待添加到 Spark ML 中，尤其是降维。尽管如此，开发人员可以无缝地将这些在 Spark MLib 中找到的技术实现与 Spark ML 中找到的其他算法结合起来，作为混合或可互操作的机器学习应用。我们还展示了一些在集群和云服务上部署机器学习应用的基本技术，尽管您也可以尝试其他可用的部署选项。

### 提示

有关更多更新，请感兴趣的读者参考 Spark 网站[`spark.apache.org/docs/latest/mllib-guide.html`](http://spark.apache.org/docs/latest/mllib-guide.html)获取发布日期、API 和规范。由于 Spark 的开源社区和来自全球各地的开发人员不断丰富和更新实现，因此最好保持更新。

在下一章（第二章，*机器学习最佳实践*），我们将讨论在使用 Spark 开发高级机器学习时的一些最佳实践，包括机器学习任务和类、一些实际的机器学习问题及其相关讨论、机器学习应用开发中的一些最佳实践、选择适合 ML 应用的正确算法等。


# 第二章：机器学习最佳实践

本章的目的是为那些在典型的统计培训中可能不会接触到这些方法的人提供统计机器学习（ML）技术的概念介绍。本章还旨在通过几个步骤，将新手从对机器学习的最小知识带到了解的实践者。本章的第二部分侧重于根据应用类型和要求选择合适的机器学习算法的一些建议。然后，它将引导人们在应用大规模机器学习流程时遵循一些最佳实践。简而言之，本章将讨论以下主题：

+   什么是机器学习？

+   机器学习任务

+   实际机器学习问题

+   Spark 中的大规模机器学习 API

+   实际机器学习最佳实践

+   为您的应用选择合适的算法

# 什么是机器学习？

在本节中，我们将尝试从计算机科学、统计学和数据分析的角度定义机器学习这个术语。然后我们将展示分析机器学习应用的步骤。最后，我们将讨论一些典型和新兴的机器学习任务，并列举一些需要解决的实际机器学习问题。

## 现代文献中的机器学习

让我们看看机器学习著名教授 Tom Mitchell 是如何定义机器学习这个术语的。他是 CMU 机器学习系主任，也是卡内基梅隆大学的教授。在他的文献中（*Tom M. Mitchell, The Discipline of Machine Learning, CMU-ML-06-108, July 2006*，[`www.cs.cmu.edu/~tom/pubs/MachineLearning.pdf`](http://www.cs.cmu.edu/~tom/pubs/MachineLearning.pdf)）中定义了机器学习这个术语：

> *机器学习是计算机科学和统计学交叉的自然产物。我们可以说，计算机科学的定义性问题是“我们如何构建解决问题的机器，哪些问题本质上是可解的/不可解的？”统计学的定义性问题主要是“在数据加上一组建模假设的情况下，可以推断出什么，以及推断的可靠性是什么？”机器学习的定义性问题建立在这两者之上，但它是一个独特的问题。计算机科学主要关注如何手动编程计算机，而机器学习关注的是如何让计算机自己编程（从经验中加上一些初始结构）。统计学主要关注从数据中可以推断出什么结论，而机器学习还包括关于如何最有效地捕获、存储、索引、检索和合并这些数据的计算架构和算法，以及如何在更大的系统中协调多个学习子任务，以及计算可解性的问题。*

我们相信 Tom 教授的这个定义是不言自明的。然而，我们将在接下来的两个小节中从计算机科学、统计学和数据分析的角度提供对机器学习的更清晰的理解。

### 提示

感兴趣的读者应该查阅其他资源，以获取有关机器学习及其理论视角的更多见解。在这里，我们提供了一些链接如下：*机器学习*：[`en.wikipedia.org/wiki/Machine_learning`](https://en.wikipedia.org/wiki/Machine_learning)。

*机器学习：它是什么，为什么重要* - [`www.sas.com/en_us/insights/analytics/machine-learning.html`](http://www.sas.com/en_us/insights/analytics/machine-learning.html)。

*机器学习的初步介绍*：[`www.youtube.com/watch?v=NOm1zA_Cats`](https://www.youtube.com/watch?v=NOm1zA_Cats)。

*什么是机器学习，它是如何工作的*：[`www.youtube.com/watch?v=elojMnjn4kk`](https://www.youtube.com/watch?v=elojMnjn4kk)。

*使用机器学习进行数据分析入门*：[`www.youtube.com/watch?v=U4IYsLgNgoY`](https://www.youtube.com/watch?v=U4IYsLgNgoY)。

### 机器学习和计算机科学

机器学习是计算机科学的一个分支，研究可以从启发式学习中学习的算法，这通常源自于模式识别和人工智能中的计算学习理论。艾伦·图灵脑海中出现了一个有趣的问题，即*机器能思考吗？*实际上，有一些很好的理由相信一个足够复杂的机器有一天可以通过无限制的图灵测试；让我们推迟这个问题，直到图灵测试通过。然而，机器至少可以学习。随后，阿瑟·塞缪尔是第一个在 1959 年将术语**机器学习**定义为*一种研究领域，使计算机能够在没有明确编程的情况下学习*的人。典型的机器学习任务包括概念学习、预测建模、分类、回归、聚类、降维、推荐系统、深度学习以及从大规模数据集中找到有用模式。

最终目标是通过改进学习方式使其变得自动化，以至于不再需要人类干预，或者尽可能减少人类干预的程度。尽管机器学习有时与**知识发现和数据挖掘**（**KDDM**）混淆，但后者更专注于探索性数据分析，被称为无监督学习 - 例如聚类分析、异常检测、**人工神经网络**（**ANN**）等。

其他机器学习技术包括监督学习，其中学习算法分析训练数据并生成可用于映射新示例进行预测的推断函数。分类和回归分析是监督学习的两个典型示例。另一方面，强化学习受行为主义心理学（参见[`en.wikipedia.org/wiki/Behaviorism`](https://en.wikipedia.org/wiki/Behaviorism)）的启发，通常关注软件代理如何通过最大化`奖励`函数在新的*环境*中执行动作。动态规划和智能代理是强化学习的两个示例。

典型的机器学习应用可以分为科学知识发现和更多商业应用，从机器人或**人机交互**（**HCI**）到反垃圾邮件过滤和推荐系统。

### 统计学和数据分析中的机器学习

机器学习是研究和构建算法的学科（参见[`en.wikipedia.org/wiki/Algorithm`](https://en.wikipedia.org/wiki/Algorithm)），这些算法可以从启发式学习（参见[`en.wikipedia.org/wiki/Learning`](https://en.wikipedia.org/wiki/Learning)）并对数据进行有意义的预测。然而，为了进行数据驱动的预测或决策，这些算法通过从训练数据集中构建模型（参见[`en.wikipedia.org/wiki/Mathematical_model`](https://en.wikipedia.org/wiki/Mathematical_model)）来操作，比严格遵循静态程序或指令更快。机器学习也与计算统计学密切相关并经常重叠。另一方面，计算统计学是统计学的一个应用领域，专注于通过计算机化方法进行预测。此外，它与数学优化有着密切的关系，提供了方法和计算任务以及理论和应用领域。由于对数学背景知识的强烈需求，数学中不可行的任务最适合机器学习，并可以作为替代方法应用。

另一方面，在数据分析领域，机器学习是一种用于设计复杂模型和算法的方法，这些模型和算法朝着预测未来结果的方向发展。这些分析模型允许研究人员、数据科学家、工程师和分析师通过从过去的关系（启发式）和数据中的趋势中学习来产生可靠、可重复和可再现的结果，并挖掘隐藏的见解。我们再次引用 Tom 教授的著名定义，他在文献中解释了从计算机科学的角度来看学习的真正含义（*Tom M. Mitchell, The Discipline of Machine Learning, CMU-ML-06-108, July 2006*, [`www.cs.cmu.edu/~tom/pubs/MachineLearning.pdf`](http://www.cs.cmu.edu/~tom/pubs/MachineLearning.pdf)）：

> *如果一个计算机程序在某类任务 T 上的表现，根据性能度量 P，随着经验 E 的积累而提高，那么就可以说它在任务 T 上从经验 E 中学习。*

因此，我们可以得出结论，计算机程序或机器可以：

+   从数据和历史中学习

+   可以通过经验进行改进

+   交互式地增强模型，以用于预测问题的结果

此外，以下图表帮助我们理解机器学习的整个过程：

![统计学和数据分析中的机器学习](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00109.jpeg)

图 1：一览机器学习。

## 典型的机器学习工作流程

典型的机器学习应用包括从输入、处理到输出的几个步骤，形成了一个科学工作流程，如图 2 所示。典型的机器学习应用涉及以下步骤：

1.  加载样本数据。

1.  将数据解析成算法的输入格式。

1.  预处理数据并处理缺失值。

1.  将数据分成两组，一组用于构建模型（训练数据集），另一组用于测试模型（测试数据集或验证数据集）。

1.  运行算法来构建或训练您的机器学习模型。

1.  使用训练数据进行预测并观察结果。

1.  使用测试数据测试和评估模型，或者使用第三个数据集（验证数据集）使用交叉验证技术验证模型。

1.  调整模型以获得更好的性能和准确性。

1.  扩展模型，以便将来能处理大规模数据集。

1.  在商业化中部署机器学习模型：![典型的机器学习工作流程](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00069.jpeg)

图 2：机器学习工作流程。

通常，机器学习算法有一些方法来处理数据集中的偏斜；这种偏斜有时可能非常严重。在第 4 步中，实验数据集通常被随机分成训练集和测试集，这被称为抽样。训练数据集用于训练模型，而测试数据集用于评估最佳模型的性能。更好的做法是尽可能多地使用训练数据集，以提高泛化性能。另一方面，建议只使用测试数据集一次，以避免在计算预测误差和相关指标时出现过拟合和欠拟合问题。

### 提示

过拟合是一种统计特性，描述了除了正常和基础关系之外的随机误差和噪音。当超参数相对于观察值或特征的数量过多时，它通常会发生。另一方面，欠拟合是指既不能对训练数据建模，也不能对新数据进行泛化，以适应模型评估或适应性。

然而，这些步骤包括几种技术，我们将在第五章中详细讨论这些技术。第 9 步和第 10 步通常被认为是高级步骤，因此它们将在后面的章节中讨论。

# 机器学习任务

机器学习任务或机器学习过程通常根据学习系统可用的学习反馈的性质分为三类。监督学习、无监督学习和强化学习；这三种机器学习任务在*图 3*中显示，并将在本节中讨论：

![机器学习任务](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00112.jpeg)

图 3：机器学习任务。

## 监督学习

**监督学习**应用程序基于一组示例进行预测，其目标是学习将输入映射到与现实世界一致的输出的一般规则。例如，用于垃圾邮件过滤的数据集通常包含垃圾邮件和非垃圾邮件。因此，我们可以知道训练集中哪些消息是垃圾邮件或非垃圾邮件。然而，我们可能有机会使用这些信息来训练我们的模型，以便对新的和未见过的消息进行分类。图 4 显示了监督学习的示意图。

换句话说，在这种情况下，用于训练机器学习模型的数据集带有感兴趣的值标签，并且监督学习算法会寻找这些值标签中的模式。算法找到所需的模式后，这些模式可以用于对未标记的测试数据进行预测。这是最流行和有用的机器学习任务类型，对于 Spark 也不例外，其中大多数算法都是监督学习技术：

![监督学习](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00122.jpeg)

图 4：监督学习实例。

## 无监督学习

在**无监督学习**中，数据点没有相关的标签，或者换句话说，在无监督学习的训练数据集中，正确的类别是未知的，如*图 5*所示。因此，类别必须从非结构化数据集中推断出来，这意味着无监督学习算法的目标是通过描述其结构来对数据进行预处理。

为了克服无监督学习中的这一障碍，通常使用聚类技术来基于某些相似性度量对未标记的样本进行分组，挖掘隐藏模式以进行特征学习。更技术上地说，我们可以编写一个生成模型，然后告诉数据找到解释数据的参数。现在，如果我们对这种阐释的可能性不满意，接下来会发生什么？答案是，我们应该告诉数据再做一次，直到我们使用一些有效的算法或技术为止。

现在你可能会产生一个新的问题，为什么我们必须在数据上贴标签？或者我们不能只欣赏当前顺序的数据，认识到每个数据都是独特的，就像雪花一样？换句话说，通过一点监督，我们的数据可以成长为任何它想成为的东西！那么为什么未标记的数据也应该被考虑进来呢？

嗯，关于这个问题还有一些更深层次的问题。例如，数据中的大部分变化来自于与我们所期望的标记方案无关的现象。一个更现实的例子是 Gmail 如何使用监督学习技术将电子邮件分类为垃圾邮件和正常邮件，其中数据可能使用其参数来解释其语义，而我们关心的只是其句法属性：

![无监督学习](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00134.jpeg)

图 5：无监督学习。

## 强化学习

**强化学习**是一种技术，模型本身从一系列行为或行为中学习。在强化学习中，数据集的复杂性或样本复杂性对于算法成功学习目标函数非常重要。此外，为了实现最终目标，与外部环境互动时应确保最大化奖励函数，如*图 6*所示。为了使最大化更容易，奖励函数可以通过惩罚不良行为或奖励良好行为来利用。

为了获得最高的奖励，算法应该通过策略进行修改，也允许机器或软件代理定期学习其行为。这些行为可以一劳永逸地学习，或者随着时间的推移，机器学习模型可以不断适应：

![强化学习](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00143.jpeg)

图 6：强化学习。

例如，强化学习在机器人技术中很常见；算法必须基于一组传感器读数选择机器人的下一个动作。它也是**物联网**（**IoT**）应用的自然选择，其中计算机程序与动态环境进行交互，必须实现某个目标，而没有明确的导师。另一个例子是游戏**Flappy Bird**，它已经被训练成自己玩。

## 推荐系统

推荐系统是一种新兴应用，是信息过滤系统的子类，用于预测用户通常对项目提供的评分或偏好。最近几年推荐系统的概念变得非常普遍，并随后应用于不同的应用程序。最流行的可能是产品（例如电影、音乐、书籍、研究文章、新闻、搜索查询、社交标签等）。推荐系统通常可以分为四类：

+   协同过滤系统，其中消费者的偏好和对其他用户的推荐是基于行为模式的相似性积累。

+   基于内容的系统，其中使用监督机器学习来说服分类器区分用户感兴趣和不感兴趣的项目。

+   混合推荐系统是最近的研究和混合方法（即，结合协同过滤和基于内容的过滤）。Netflix 是这样一个推荐系统的良好例子，它使用**受限玻尔兹曼机**（**RBM**）和一种矩阵分解算法来处理大型电影数据库，如 IMDb。这种推荐，通过比较相似用户的观看和搜索习惯简单地推荐电影或戏剧或流媒体，被称为评分预测。

+   基于知识的系统，其中使用有关用户和产品的知识来推理满足用户需求的内容，使用感知树、决策支持系统和基于案例的推理。

## 半监督学习

在**监督学习**和**无监督学习**之间，有一个小小的地方是**半监督学习**；在这种情况下，机器学习模型通常接收不完整的训练信号。更具体地说，机器学习模型接收到一组目标输出部分缺失的训练集。半监督学习更多地基于假设，并且通常使用三种假设算法作为未标记数据集的学习算法。使用以下假设：平滑性、聚类和流形假设。

换句话说，半监督学习还可以被称为**弱监督**或**自举**技术，用于利用未标记示例的隐藏财富来增强从少量标记数据中学习。新兴示例包括*半监督期望最小化和人类认知中的概念学习以及传递 SVM*。

# 实际机器学习问题

机器学习到底是什么意思？我们在本章的开头已经看到了一些令人信服的对这个术语的定义，以及术语“学习”的含义。然而，机器学习本身的定义取决于要解决的问题。在本节中，我们将首先强调机器学习的类别，然后列举一些现实世界中广为人知和广泛使用的机器学习问题的例子。典型的类别包括分类、聚类、规则提取和回归，这些都将被讨论。

此外，我们还将讨论基于标准机器学习问题的主要分类法的问题。这很重要，因为了解我们可能面临的问题类型可以让我们考虑我们需要的数据。另一个重要的事实是，在了解一些实际的机器学习问题之前，你可能会在开发机器学习应用程序的想法上遇到困难。换句话说，要知道问题，我们首先需要了解数据。因此，本章将讨论算法的类型及其优化问题；数据处理将在第三章中进行讨论，*通过了解数据来理解问题*。

## 机器学习类别

我们上面提到的问题类别是我们在日常生活中使用和应用机器学习技术时所指的大多数问题的标准。然而，仅仅知道机器学习类别是不够的，我们还需要知道机器正在学习什么类型的问题，因为你会发现许多问题只是简单的问题解决，并没有帮助机器学习模型或代理进行学习。

当你认为一个问题是一个机器学习问题时，更准确地说，你在考虑一个需要从数据中建模的决策问题，这可以被称为一个机器学习问题。换句话说，作为数据科学家或人类专家，如果你有足够的时间通过了解可用的数据集来回答一个特定的问题，你可以或多或少地应用一个合适的机器学习问题。因此，我们可以假设使用一些机器学习算法可以解决的问题主要有两个部分 - 数据本身，可以用来指向问题的特定观察结果，以及可用解决方案的质量的定量测量。一旦你成功地将一个问题确定为机器学习问题，你可能能够思考如何轻松地制定出什么类型的问题，或者你的客户将会要求什么样的后果，或者需要满足什么样的要求。正如上面所述，更常用的机器学习类别包括：分类、聚类、回归和规则提取。我们现在将对每个类别进行简要概述。

### 分类和聚类

如果实验数据集已经标记，这意味着已经为其分配了一个类别。例如，在垃圾邮件检测中的垃圾邮件/非垃圾邮件，或者在信用卡欺诈识别中的欺诈/非欺诈。然而，如果基本决策的数据集是未标记的，新的标签需要手动或算法地制作。这可能很困难，可以被视为一个判断问题。相反，雕刻出几个群体之间的差异或相似之处可能在计算上更加困难。

另一方面，聚类处理的是未标记或无标记的数据。然而，它仍然可以根据相似性和数据中的自然结构的其他度量来分成组。将数字相册中的图片仅按面孔组织起来而不带有姓名可能是一个例子，人类用户必须手动为组分配名称。同样，手动标记多个图像文件可能会产生相同的计算复杂性；我们将在后面的章节中提供一些示例，说明 Spark 如何提供多个 API 来解决这些问题。

## 规则提取和回归

从给定的数据集中，可以通过前提和结论以*if...then*的方式生成命题规则，定义了机器学习代理的行为。这种规则生成技术通常被称为*规则提取*。你可能会想知道这样的规则是否存在，然而，它们通常不是有针对性的。这意味着用于发现数据中属性之间的统计显著或统计相关关系的方法。

规则提取的一个例子是在面向业务的事务性数据库中挖掘项目之间的关联规则。非技术上，一个实际的例子可能是发现啤酒购买和尿布购买之间的关系或关联，这说明了顾客的愿望和机会。然而，可能会出现一些预测不一定直接涉及规则或数据的情况。

现在让我们谈谈回归，其中数据带有实际值的标签。更确切地说，一些浮点值而不是数据中的标签。理解一个例子的最简单方法是时间序列数据，类似于股票或货币随时间变化的价格。在这些类型的数据中，回归任务是通过一些回归建模技术对新的和不可预测的数据进行预测。

# 最广泛使用的机器学习问题

你会发现在日常生活中使用机器学习相关问题的大量例子，因为它们解决了广泛使用的技术或算法中的困难部分。我们经常使用许多桌面或基于网络的应用程序，即使不知道使用了哪些基础技术，也可以解决你的问题。你会惊讶地发现，其中许多实际上使用了广泛使用的机器学习算法，使你的生活更轻松。周围有许多机器学习问题。在这里，我们将提到一些真正代表机器学习的例子问题：

+   **垃圾邮件检测或垃圾邮件过滤**：给定收件箱中的一些电子邮件，任务是识别哪些电子邮件是垃圾邮件，哪些是非垃圾邮件（通常称为正常）电子邮件。现在具有挑战性的部分是开发一个可以应用的 ML 应用，以便它只能识别非垃圾邮件电子邮件留在收件箱中，并将垃圾邮件移动到相应的垃圾邮件文件夹中，或者永久从电子邮件帐户中删除它们。一个典型的例子可能是在使用 Gmail 时手动执行的操作，但如果你有一个 ML 应用程序，该应用程序将自动执行。

+   **异常检测或异常值检测**：异常检测涉及识别数据集中意外或不符合预期模式的项目、事件或观察结果；换句话说，是怀疑模式的识别。最常见的例子是使用一些机器学习应用进行网络异常检测。现在具有挑战性的任务是开发一个可以成功应用于简单识别网络中传播的异常数据点的 ML 应用。

+   信用卡欺诈检测：信用卡欺诈现在非常普遍。从网上购物中窃取信用卡相关信息，并以非法方式使用在许多国家都有发生。假设你有一个客户一个月的交易数据库。现在具有挑战性的任务是开发一个机器学习应用程序，以识别客户自己进行的交易和他人非法进行的交易。

+   语音识别：识别声音并将其转换为相应的文本命令，然后执行一些操作，就像智能代理一样。最常用的应用包括苹果的 Siri，三星的 S-Voice，亚马逊的 Echo（消费领域）和微软的 Cortana（特别是因为 Cortana 具有用于可扩展性和集成等的 SDK）。另一个例子是使用识别的声音来锁定或解锁智能手机。

+   数字/字符识别：假设你有一个手写的邮政编码、地址或信件，现在数字/字符识别的任务是识别和分类每个不同人写的手写字符的数字或字符。一个高效的机器学习应用可以帮助阅读和理解手写的邮政编码或字符，并按地理区域或更技术上的说法，按图像分割对信封内容进行分类。

+   物联网：大规模传感器数据分析，用于实时流数据的预测和分类。例如，智能客厅监控，包括水位检测，室温检测，家用电器控制等。

+   游戏分析：用于预测升级销售和针对应用内购买和修改的体育、游戏和基于控制台的游戏档案分析

+   人脸检测：给定数百或数千张照片的数字相册，任务是识别与给定人相似的照片。在这种情况下，高效的机器学习应用可以帮助按人员组织照片。

+   产品推荐：根据客户的购买历史和大量的产品库存，目标是识别客户可能有兴趣购买的产品。亚马逊、Facebook 和 Google Plus 等商业和科技巨头为用户提供了这一推荐功能。

+   股票交易：根据股票市场的当前和历史价格，预测是否应该买入或卖出股票，以便利用机器学习系统获利。

以下是一些新兴的机器学习示例和当前研究的需求：

+   隐私保护数据挖掘：从面向业务的零售数据库中挖掘最大频繁模式和关联规则，以增加未来的购买

+   作者姓名消歧：使用手动验证从给定出版物集合的作者列表的聚类结果中的随机样本来评估消歧性能

+   推荐系统：基于点击流数据的推荐系统，使用关联规则挖掘

+   文本挖掘：例如，从给定的文本语料库中检查抄袭

+   情感分析：如今很多商业和科技公司的决策都是基于他人的意见，这将是创新机器学习的好地方

+   语音理解：给定用户的话语，目标是识别用户提出的具体请求。这个问题的模型将允许程序理解并尝试满足该请求。例如，iPhone 的 Siri 和三星的语音记录器在会议模式下都实现了这个功能

其中一些问题是人工智能、自然语言处理和计算机视觉中最困难的问题，可以使用机器学习算法来解决。同样，我们将尝试开发一些强调这些问题的机器学习应用程序，在接下来的章节中进行讨论。

# Spark 中的大规模机器学习 API

在本节中，我们将描述 Spark 机器学习库（Spark MLlib 和 Spark ML）引入的两个关键概念，以及与我们在上述部分讨论的监督和无监督学习技术相一致的最常用的实现算法。

## Spark 机器学习库

如前所述，在 Spark 时代之前，大数据建模者通常使用统计语言（如 R、STATA 和 SAS）构建他们的机器学习模型。然后数据工程师通常会重新用 Java 等语言实现相同的模型，以部署在 Hadoop 上。

然而，这种工作流程缺乏效率、可扩展性、吞吐量和准确性，以及延长的执行时间。

使用 Spark，可以重新构建、采用和部署相同的机器学习模型，使整个工作流程更加高效、稳健和快速，从而使您能够提供实时洞察力以提高性能。Spark 机器学习库分为两个包：Spark MLlib（`spark.mllib`）和 Spark ML（`spark.ml`）。

### Spark MLlib

MLlib 是 Spark 的可扩展机器学习库，它是 Spark Core API 的扩展，提供了一系列易于使用的机器学习算法库。算法是用 Java、Scala 和 Python 实现和编写的。Spark 支持存储在单台机器上的本地向量和矩阵数据类型，以及由一个或多个 RDD 支持的分布式矩阵：

| **Spark MLlib** |   |   |
| --- | --- | --- |
| **ML 任务** | **离散** | **连续** |
| 监督 | 分类：逻辑回归及其正则化变体线性支持向量机朴素贝叶斯决策树随机森林梯度提升树 | 回归：线性回归及其正则化变体线性最小二乘 Lasso 和岭回归等距回归 |
| 无监督 | 聚类：K 均值高斯矩阵幂迭代聚类（PIC）潜在狄利克雷分配（LDA）二分 K 均值流式 K 均值 | 降维、矩阵分解：主成分分析奇异值分解交替最小二乘 |
| 强化 | N/A | N/A |
| 推荐系统 | 协同过滤：Netflix 推荐 | N/A |

表 1：一览 Spark MLlib。

+   **图例**：连续：对连续变量进行预测，例如，预测未来几天的最高温度

+   离散：将离散的类标签分配给特定观察结果作为预测的结果，例如，在天气预报中，可以预测晴天、雨天或雪天

Spark MLlib 的美妙之处在于众多。例如，使用 Scala、Java 和 Python 实现的算法具有高度可扩展性，并利用 Spark 处理大量数据的能力。它们设计快速，用于并行计算，基于内存的操作比 MapReduce 数据处理快 100 倍（它们还支持基于磁盘的操作，比 MapReduce 普通数据处理快 10 倍），使用 Dataset、DataFrame 或基于有向无环图（DAG）的 RDD API。

它们也是多样的，因为它们涵盖了用于回归分析、分类、聚类、推荐系统、文本分析、频繁模式挖掘的常见机器学习算法，显然也涵盖了构建可扩展机器学习应用程序所需的所有步骤。

### Spark ML

Spark ML 添加了一组新的机器学习 API，让用户可以快速组装和配置实用的机器学习管道，构建在数据集之上。Spark ML 旨在提供一组统一的高级 API，构建在 DataFrame 而不是 RDD 之上，帮助用户创建和调整实用的机器学习管道。Spark ML API 标准化了机器学习算法，使学习任务更容易将多个算法组合成单个管道或数据工作流，供数据科学家使用。

Spark ML 使用 DataFrame 的概念（尽管在 Java 中已经过时，但仍然是 Python 和 R 中的主要编程接口），这是在 Spark 1.3.0 版本中从 Spark SQL 引入的机器学习数据集。数据集包含各种数据类型，例如存储文本、特征向量和数据的真实标签的列。除此之外，Spark ML 还使用转换器将一个 DataFrame 转换为另一个，反之亦然，其中估计器的概念用于在 DataFrame 上拟合以生成新的转换器。另一方面，管道 API 可以将多个转换器和估计器一起约束，以指定一个 ML 数据工作流。参数的概念是在开发 ML 应用程序期间引入的，用于指定所有转换器和估计器在一个统一的 API 下共享一个公共 API：

| **Spark ML** |   |   |
| --- | --- | --- |
| **ML 任务** | **离散** | **连续** |
| 监督 | 分类：逻辑回归决策树分类器随机森林分类器梯度提升树分类器多层感知分类器一对多分类器 | 回归：线性回归决策树回归随机森林回归梯度提升树回归生存回归 |
| 无监督 | 聚类：K 均值潜在狄利克雷分配（LDA） | 树集成：随机森林梯度提升树 |
| 强化 | N/A | N/A |
| 推荐系统 | N/A | N/A |

表 2：一览 Spark ML（图例与表 1 相同）。

如表 2 所示，Spark ML 还提供了几种分类、回归、决策树和树集成，以及用于在 DataFrame 上开发 ML 管道的聚类算法。正在积极实施的优化算法称为**正交有限内存拟牛顿**（**OWL-QN**），这也是一种高级算法，是 L-BFGS 的扩展，可以有效处理 L1 正则化和弹性网（也请参阅 Spark ML 高级主题，[`spark.apache.org/docs/latest/ml-advanced.html`](https://spark.apache.org/docs/latest/ml-advanced.html)）。

### 从业者的重要说明

然而，目前仅支持 Pearson 和 Spearman 的相关性，并且将在未来的 Spark 版本中添加更多。与其他统计函数不同，Spark 还支持分层抽样，可以在 RDD 上作为键值对执行；但是，一些功能尚未添加到 Python 开发人员。目前在 Spark 机器学习库中没有强化学习算法模块（请参阅*表 1*和*表 2*）。Spark MLlib 的当前实现提供了 FP-growth 的并行实现，用于挖掘频繁模式和关联规则。但是，您将需要根据需要自定义算法来挖掘最大频繁模式。我们将在即将到来的章节中提供一个可扩展的 ML 应用程序，用于挖掘隐私保护的最大频繁模式。

另一个事实是，Spark 中协同推荐系统的当前实现不支持实时流数据的使用，然而，在后面的章节中，我们将尝试基于点击流数据使用关联规则挖掘来展示一个实际的推荐系统（参见 Mitchell, Tom M. *机器学习的学科*，2006 年，[`www.cs.cmu.edu/`](http://www.cs.cmu.edu/)。CMU. Web. 2014 年 12 月）。然而，一些算法尚未添加到 Spark ML 中，最值得注意的是降维是一个例子。

然而，开发人员可以无缝地将 Spark MLlib 中找到的这些技术的实现与 Spark ML 中找到的其他算法结合起来，作为混合或可互操作的 ML 应用程序。 Spark 的神经网络和感知是基于大脑的学习算法，涵盖了多类、双类和回归问题，这些问题在 Spark ML API 中尚未实现。

# 实际机器学习最佳实践

在本节中，我们将描述在开发特定兴趣的机器学习应用程序之前需要遵循的一些良好的机器学习实践，如*图 7*所示：

![实际机器学习最佳实践](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00156.jpeg)

图 7：机器学习系统化流程。

可扩展和准确的 ML 应用需求，需要从问题定义到呈现结果的开发中遵循系统化的方法，可以总结为四个步骤：问题定义和制定、数据准备、寻找适合的机器学习算法，最后，在机器学习模型部署后呈现结果。嗯，这些步骤可以如*图 6*所示。

## 在开发 ML 应用程序之前的最佳实践

机器学习系统的学习可以被公式化为表示、评估和优化的总和。换句话说，根据 Pedro D 等人的说法（Pedro Domingos，*关于机器学习的一些有用的东西*，[`homes.cs.washington.edu/~pedrod/papers/cacm12.pdf`](https://homes.cs.washington.edu/~pedrod/papers/cacm12.pdf)）：

*学习=表示+评估+优化*

考虑到这个公式，我们将在进入 ML 应用程序开发之前为从业者提供一些建议。

### 良好的机器学习和数据科学价值巨大

那么，在开发有效的机器学习应用程序之前，我们需要什么？实际上，在开始开发 ML 应用程序之前，我们需要四种武器，包括：

+   数据基元（或更坦率地说，实验数据）。

+   管道综合工具（用于理解机器学习步骤中的数据和控制流）。

+   有效和健壮的错误分析工具。

+   验证或验证工具（用于验证或验证 ML 模型的预测准确性或性能）。然而，最重要的是，如果没有一些具有良好数据科学的强大理论基础，整个过程将是徒劳的。事实上，许多数据科学家和机器学习专家经常引用类似于这样的声明：*如果你能将你的问题提出为一个简单的优化问题，那么你几乎已经完成了*（见*数据分析与 R*，[`advanceddataanalytics.net/2015/01/31/condensed-news-7/`](http://advanceddataanalytics.net/2015/01/31/condensed-news-7/)）。

这意味着在开始机器学习之前，如果你能确定你的问题是一个机器学习问题，你将能够找到一些合适的算法来一起开发你的 ML 应用。当然，在实践中，大多数机器学习应用无法转化为简单的优化问题。因此，像你这样的数据科学家的职责是管理和维护复杂的数据集。之后，你将不得不处理其他问题，比如在工程化机器学习管道时出现的分析问题，以解决我们之前提到的那些问题。

因此，最佳实践是使用 Spark MLlib、Spark ML、GraphX 和 Spark Core API 以及最佳实践的数据科学启发式方法来共同开发您的机器学习应用程序。现在你可能会想从中获益；是的，好处是显而易见的，它们如下：

+   内置的分布式算法

+   内存和基于磁盘的数据计算和处理

+   迭代工作负载的内存能力

+   算法的准确性和性能

+   更快的数据清理、特征工程和特征选择、训练和测试

+   预测结果的实时可视化

+   朝着更好的性能调整

+   适应新数据集

+   随着数据集的增加而扩展性

### 最佳实践-特征工程和算法性能

在最佳实践中，特征工程应被视为机器学习中最重要的部分之一。关键是在实验数据集中非技术性地找到特征的更好表示。与此同时，使用哪些学习算法或技术也很重要。参数调整当然也很重要，但最终的选择更多取决于您将要开发的 ML 模型的实验。

在实践中，通过“开箱即用”方法（也称为功能性或 OOTB，是指产品安装或配置后立即可用的功能）和良好的数据预处理，轻松掌握天真的性能基线是微不足道的。因此，您可能会不断地这样做，以了解基线在哪里，以及这种性能是否达到了令人满意的水平或足够满足您的要求。

一旦您训练了所有的开箱即用方法，总是建议并且是一个好主意将它们一起尝试。此外，为了解决 ML 问题，您可能经常需要知道计算上困难的问题（例如第二部分中所示）需要领域特定的知识或大量挖掘数据或两者兼而有之。因此，广泛接受的特征工程技术和领域特定知识的结合将有助于您的 ML 算法/应用/系统解决与预测相关的问题。

简而言之，如果您拥有所需的数据集和一个强大的算法，可以利用数据集学习复杂的特征，几乎可以保证您会成功。此外，有时领域专家在选择好的特征时可能会出错；因此，多个领域专家（问题领域专家）、更结构化的数据和 ML 专业知识的整合总是有帮助的。

最后但同样重要的是，有时我们建议考虑错误率而不仅仅是准确性。例如，假设一个 ML 系统的准确率为 99%，错误率为 50%，比起准确率为 90%，错误率为 25%的系统更糟糕。

### 注意过拟合和欠拟合

初学者数据科学家经常犯的一个常见错误是在构建 ML 模型时受到过拟合问题的影响，这可能是由于听而不是泛化。更具体地说，如果您在训练数据上评估模型而不是测试或验证数据，您可能无法确定您的模型是否过拟合。常见的症状包括：

+   用于训练的数据的预测准确性可能过高（有时甚至达到 100%）

+   并且与新数据相比，模型可能会稍微好一些

有时 ML 模型本身对特定调整或数据点变得欠拟合，这意味着模型变得过于简单。我们的建议（我们相信其他人也是如此）如下：

+   将数据集分为两组以检测过拟合情况，第一组用于训练和模型选择，称为训练集；第二组是用于评估模型的测试集，取代了 ML 工作流程部分中所述的模型。

+   或者，您还可以通过使用更简单的模型（例如，线性分类器优先于高斯核 SVM）或通过增加 ML 模型的正则化参数（如果可用）来避免过拟合。

+   调整模型的参数值以避免过拟合和欠拟合

另一方面，Hastie 等人（Hastie Trevor，Tibshirani Robert，Friedman Jerome，《统计学习的要素：数据挖掘、推断和预测》，第二版，2009 年）建议将大规模数据集分为三组：训练集（50%）、验证集（25%）和测试集（25%）（大致）。他们还建议使用训练集构建模型，并使用验证集计算预测误差。建议使用测试集来评估最终模型的泛化误差。

如果在监督学习期间可用的标记数据量较小，则不建议拆分数据集。在这种情况下，使用交叉验证或训练拆分技术（将在第七章中讨论，*调整机器学习模型*，并附有几个示例）。更具体地说，将数据集分为大致相等的 10 部分，然后对这 10 部分中的每一部分进行迭代训练分类器，并使用第十部分来测试模型。

### 保持关注并将 Spark MLlib 与 Spark ML 结合使用

管道设计的第一步是创建构建模块（作为由节点和边组成的有向或无向图）并在这些模块之间建立联系。然而，作为数据科学家，您还应专注于扩展和优化节点（基元），以便在后期处理大规模数据集时能够扩展应用程序，使您的 ML 管道始终保持高性能。管道过程还将帮助您使您的模型适应新数据集。然而，其中一些基元可能会明确定义为特定领域和数据类型（例如文本、图像、视频、音频和时空数据）。

除了这些类型的数据之外，基元还应适用于通用领域的统计学或数学。将您的 ML 模型转换为这些基元的形式将使您的工作流程更加透明、可解释、可访问和可解释。最近的一个例子是 ML-Matrix，它是一个可以在 Spark 之上使用的分布式矩阵库：

![保持关注并将 Spark MLlib 与 Spark ML 结合使用](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00133.jpeg)

图 8：保持关注并使 ML、MLlib 和 GraphX 互操作。

正如我们在前一节中已经提到的，作为开发人员，您可以无缝地将 Spark MLlib 中的实现技术与 Spark ML、Spark SQL、GraphX 和 Spark Streaming 中开发的算法结合起来，作为基于 RDD、DataFrame 和 Datasets 的混合或可互操作的 ML 应用程序，如图 8 所示。例如，可以使用混合模型开发基于物联网的实时应用程序。因此，建议您与您周围的最新技术保持同步，以改进您的 ML 应用程序。

### 使 ML 应用程序模块化并简化管道合成

在构建 ML 管道时的另一个常用做法是使 ML 系统模块化。一些监督学习问题可以使用常称为广义线性模型的非常简单的模型来解决。然而，这取决于您将要使用的数据，有些数据可能不适用于这些模型。

因此，要将一系列简单的线性二元分类器合并成一个轻量级的模块化架构。这可能是在工作流程或算法级别。优势是显而易见的，因为应用程序的模块化架构以并行和分布式的方式处理大量数据流。因此，我们建议您采用文献中提到的三种关键创新机制：加权阈值抽样、逻辑校准和智能数据分区（例如，Yu Jin；Nick Duffield；Jeffrey Erman；Patrick Haffner；Subhabrata Sen；Zhi Li Zhang，《大型网络中基于流级流量分类的模块化机器学习系统》，ACM 数据发现知识交易，V-6，Issue-1，2012 年 3 月）。目标是在实现高吞吐量的同时，实现 ML 应用/系统预测结果的高准确性。虽然原语可以作为构建块，但您仍需要其他工具来使用户能够构建 ML 管道。

随后，工作流程工具如今变得更加普遍，这些工具适用于数据工程师、数据科学家，甚至适用于业务分析师，如 Alteryx、RapidMiner、Alpine Data 和 Dataiku。在这一点上，我们谈论并强调业务分析师，因为在最后阶段，您的目标客户将是一家重视您的 ML 模型的商业公司，对吧？Spark 的最新版本配备了用于构建机器学习管道的 Spark ML API，并制定了领域特定语言（参见[`en.wikipedia.org/wiki/Domain-specific_language`](https://en.wikipedia.org/wiki/Domain-specific_language)）用于管道。

### 思考一个创新的 ML 系统

然而，为了开发算法以利用可用数据持续学习 ML 模型，机器学习背后的观点是自动化分析模型的创建。不断发展的模型产生越来越积极的结果，并减少了对人类干预的需求。这使得 ML 模型能够自动产生可靠且可重复的预测。

更具体地说，假设您计划使用 ML 算法开发推荐系统。那么，开发该推荐系统的目标是什么？在机器学习产品开发方面有哪些创新的想法？这两个问题在您开始开发 ML 应用程序或系统之前应该考虑。持续的创新可能具有挑战性，特别是在推动新想法的同时，理解最大利益所在也可能很困难。机器学习可以通过各种途径提供创新，例如确定当前产品的弱点、预测分析或识别以前隐藏的模式。

因此，您将不得不考虑大规模计算来离线训练您的 ML 模型，随后您的推荐系统必须能够像传统的搜索引擎分析一样进行在线推荐。因此，如果您的系统：

+   可以使用您的机器学习应用程序预测购买商品

+   可以进行产品分析

+   可以作为生产中的新趋势

### 思考并变得更加聪明，以应对大数据的复杂性

如图 9 所示，新的商业模式是可利用数据的不可避免的延伸，因此考虑大数据及其商业价值可以使业务分析师的工作、生活和思维更加智能，从而使您的目标公司为客户提供价值。除此之外，您还需要调查（更准确地说是分析）竞争对手或更好的公司。

现在的问题是，你如何收集和使用企业数据？大数据不仅仅是关于大小（容量），它还与速度、真实性、多样性和价值有关。对于这些类型的复杂性，例如，速度可以使用 Spark Streaming 来解决，因为基于流的数据也是需要实时分析的大数据。其他参数，如容量和多样性，可以使用 Spark Core 和 Spark MLlib/ML 来处理大数据处理。

好吧，你必须想方设法管理数据。如果你能够管理数据，那么从数据中获得的见解可以真正改变企业运营的方式，利用大数据的有用特征：

![思考和更加智能地处理大数据复杂性](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00013.jpeg)

图 9：大数据最佳实践中的机器学习。

在这一点上，仅有数据是不够的（参见 Pedro Domingos，《关于机器学习的一些有用知识》，[`homes.cs.washington.edu/~pedrod/papers/cacm12.pdf`](https://homes.cs.washington.edu/~pedrod/papers/cacm12.pdf)），但是从数据中提取有意义的特征并将数据的语义放入模型更为重要。这就像 LinkedIn 等大多数科技巨头正在通过大规模机器学习框架开发的社区特征定位一样，这多多少少是一种监督学习技术。工作流程如下：

+   获取数据，提取特征，并设置目标

+   特征和目标连接

+   从连接数据创建一个快照

+   将快照分成两部分：训练集和测试集

+   从训练集中，通过采样技术准备样本数据

+   使用采样数据训练模型

+   评分

+   从先前开发的持久模型以及步骤 4 中准备的测试数据中评估模型。

+   如果找到了最佳模型

+   为目标受众部署模型

那么接下来呢？你的模型也应该适应大规模动态数据，比如实时流式物联网数据，而且实时反馈也很重要，这样你的 ML 系统才能从错误中学习。下一小节将讨论这一点。

### 将机器学习应用于动态数据

原因是显而易见的，因为机器学习为物联网项目带来了具体和动态的方面。最近，机器学习在工业公司中的受欢迎程度有所提高，他们从中获利。因此，几乎每个 IT 供应商都在急速宣布物联网平台和咨询服务。但是通过物联网数据实现财务收益并不是一件容易的工作。此外，许多企业未能清楚地确定实施物联网战略将改变哪些领域。

综合考虑这些积极和消极的问题，你的 ML 模型应该适应大规模动态数据，因为大规模数据意味着数十亿条记录、大特征空间和来自稀疏问题的低正率。然而，数据是动态的，因此 ML 模型必须足够适应；否则你将面临糟糕的体验或者迷失在黑洞中。

## 开发 ML 应用程序后的最佳实践

ML 模型/系统开发后的最佳实践步骤包括：可视化以理解预测值，模型验证，错误和准确性分析，模型调整，模型适应和扩展以便轻松处理大规模数据集。

### 如何实现实时 ML 可视化

可视化提供了一个交互界面，以保持 ML 模型本身的关注。因此，如果不可视化预测结果，进一步改善 ML 应用程序的性能将变得困难。最佳实践可能是这样的：

+   为了可视化大规模图形相关数据，可以将一些第三方工具与 GraphX 结合起来（更多内容将在*第九章*中讨论，*流式和图形数据的高级机器学习*)

+   对于非图形数据，Spark ML 算法可以通过集成其他工具如 Apache Kafka 来发送和接收消息的回调接口：

+   算法决定何时发送什么消息

+   算法不关心消息是如何传递的

+   一个任务通道用于处理从 Spark 驱动程序到 Spark 客户端或 Spark 集群节点的消息传递服务。任务通道将使用 Spark 核心在更低的抽象级别进行通信：

+   它不关心消息的内容或消息的接收者

+   消息从 Spark 客户端传递到浏览器或可视化客户端：

+   我们建议同时使用 HTML5 的**服务器发送事件**（SSE）和 HTTP 分块响应（PUSH）。将 Spark 与这种类型的技术结合起来将在第十章中讨论，*配置和使用外部库*

+   拉取是可能的；然而，它需要一个消息队列

+   使用 JavaScript 框架进行可视化，比如`Plot.ly`（请参考[`plot.ly/`](https://plot.ly/)）和`D3.js`（请参考[`d3js.org/`](https://d3js.org/)）

### 进行一些错误分析

随着算法变得更加普遍，我们需要更好的工具来构建复杂的、稳健的和稳定的机器学习系统。像 Apache Spark 这样的流行分布式框架将这些想法应用到了更广泛的大型数据集中。因此，如果我们能够绑定分层管道的近似误差和收敛速度，那将更好。

假设我们可以计算节点的误差范围，下一步将是为这些管道提取误差范围的机制。然而，在实践中，当 ML 模型部署到生产环境时，我们可能需要工具来确认管道将正常工作，不会出现故障或中途停止，并且可以提供一些预期的错误度量。

### 保持你的 ML 应用程序调优

设计一个或两个在简单问题上表现良好的算法可以被认为是一个良好的开端。然而，有时你可能渴望获得最佳的准确性，甚至会牺牲宝贵的时间和可用的计算资源。这将是一个更明智的方式，它不仅可以帮助你挤出额外的性能，还可以改善你之前设计的机器学习算法的准确性结果。为了做到这一点，当你调整模型和相关算法时，你必须对结果有很高的信心。

显然，这些结果将在你指定测试和验证之后可用。这意味着你应该只使用那些减少性能测量方差的技术，以便评估那些运行更顺利的算法。

与大多数数据从业者一样，我们还建议您使用交叉验证技术（也经常称为旋转估计），并且使用相当高数量的折叠（即 K 折交叉验证，其中一个子样本用作验证数据集，用于测试模型本身，其余的 K-1 个子样本用于训练数据）。尽管折叠的确切数量，或 K，取决于你的数据集，但是 10 折交叉验证通常被使用，但是 K 的值通常是不固定的。我们将在这里提到三种策略，你需要调整你的机器学习模型：

+   **算法调优**：使您的机器学习算法参数化。然后，调整这些参数的值（如果它们有多个参数）以影响整个学习过程的结果。

+   **集成**：有时候天真是好的！因此，为了获得改进的结果，不断尝试将多个机器学习方法或算法的结果结合起来。

+   **极端特征工程**：如果您的数据中嵌入了复杂和多维结构，ML 算法知道如何找到并利用它来做出决策。

### 使您的 ML 应用程序适应和扩展

如图 10 所示，自适应学习根据 Rob Munro 的说法，将基于规则的、简单的机器学习和深度学习方法融合到机器智能中。

![使您的 ML 应用程序适应和扩展](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00026.jpeg)

图 10：机器智能的四代（图由 Rob Munro 提供）。

机器学习的第四代：自适应学习，(`http://idibon.com/the-fourth-generation-of-machine-learning-adaptive-learning/#comment-175958`)。

研究还表明，自适应学习在预测人们购买汽车的意图方面准确率达到 95%（请参阅 Rob Munro，《机器学习的第四代：自适应学习》，`http://idibon.com/the-fourth-generation-of-machine-learning-adaptive-learning/#comment-175958`）。此外，如果您的 ML 应用程序能够适应新环境和新数据，那么只要提供足够的基础设施，预计您的 ML 系统可以扩展以处理不断增加的数据负载。

# 为您的应用程序选择正确的算法

*我应该使用什么机器学习算法？*对于天真的机器学习从业者来说，这是一个非常常见的问题，但答案总是*取决于*。更详细地说：

+   这取决于要测试/使用的数据的数量、质量、复杂性和性质

+   这取决于外部环境和参数，例如您的计算系统配置或基础设施

+   这取决于您想要用答案做什么

+   这取决于算法的数学和统计公式如何被转化为计算机的机器指令

+   这取决于你有多少时间

+   *图 11*提供了选择解决 ML 问题的正确算法的完整工作流程。但是，请注意，某些技巧可能会根据数据和问题类型而不起作用：![为您的应用程序选择正确的算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00039.jpeg)

图 11：选择正确算法的工作流程

事实上，即使是最有经验的数据科学家或数据工程师在尝试所有算法之前也无法给出哪种 ML 算法在性能上表现最佳的明确建议。大多数一致/不一致的陈述都以*取决于...嗯...*开始。习惯上，您可能会思考是否有机器学习算法的备忘单，如果有的话，如何使用该备忘单。我们与几位数据科学家交谈时，他们表示找到最佳算法的唯一方法是尝试所有算法；因此，没有捷径！让我们明确一下，假设您有一组数据，并且想要进行一些聚类。因此，从技术上讲，这可能是分类或回归，如果您的数据是标记/未标记的或值或训练集数据。现在，您脑海中首先出现的问题是：

+   在选择适当的算法之前，我应该考虑哪些因素？还是我应该随机选择一个算法？

+   我如何选择可以应用于我的数据的任何数据预处理算法或工具？

+   我应该使用什么样的特征工程技术来提取有用的特征？

+   哪些因素可以提高我的 ML 模型的性能？

+   我如何为新数据类型采用我的 ML 应用程序？

+   我可以将我的 ML 应用程序扩展到大规模数据集吗？等等。

您总是期望得到更合理的最佳答案，并解释应考虑的一切。在本节中，我们将尝试用我们的一点机器学习知识来回答这些问题。

## 在选择算法时的考虑

我们在这里提供的建议或建议是给初学者数据科学家和尝试选择 Spark ML API 的最佳算法的专家数据科学家。这意味着它做了一些概述和过度简化，但它会指引您朝着安全的方向，相信我们！假设您计划开发一个 ML 系统来回答以下问题基于规则：

+   `IF`特征 X 具有属性 Z`THEN`执行 Y

肯定地，应该有这样的规则：

+   如果 X`THEN`，尝试使用属性 Z 并避免 W 是明智的

然而，什么是明智的，什么不是取决于：

+   您的应用程序和问题的预期复杂性。

+   数据集的大小（即有多少行/列，有多少独立案例）。

+   您的数据集是否有标签或无标签？

+   数据类型和测量类型，因为不同类型的数据暗示着不同的顺序或结构，对吧？

+   显然，在实践中，您在应用不同方法时的经验是高效和智能的。

此外，如果您想对一般问题得到一般答案，我们建议初学者从《统计学习的要素》（Hastie Trevor，Tibshirani Robert，Friedman Jerome，*统计学习的要素：数据挖掘、推断和预测*，第二版，2009）开始。然而，我们还建议遵循以下算法属性：

+   展示出色的准确性

+   具有快速的训练时间

+   以及线性的使用

### 准确性

从您的 ML 应用程序中获得最准确的结果并非总是不可或缺的。根据您想要将其用于的情况，有时近似也足够。如果情况是这样，您可以通过合并更好估计的方法来大幅减少处理时间。当您熟悉 Spark 机器学习 API 的工作流程时，您将享受到拥有更多近似方法的优势，因为这些近似方法将自动倾向于避免您的 ML 模型中的过度拟合问题。

### 训练时间

执行时间需要完成数据预处理或构建模型，并且在不同算法、继承复杂性和鲁棒性之间变化很大。训练时间通常与准确性密切相关。此外，您经常会发现，与其他算法相比，您将使用的一些算法对数据点的数量是难以捉摸的。然而，当您的时间足够充裕，特别是当数据集较大时，为了完成所有的程序，选择算法可能会变得轻松。因此，如果您特别关注时间，尝试牺牲准确性或性能，并使用满足您最低要求的简单算法。

### 线性

最近开发了许多利用线性的机器学习算法（也可在 Spark MLlib 和 Spark ML 中使用）。例如，线性分类算法允许通过绘制区分直线或数据集的高维等价物来分离类别。另一方面，线性回归算法假设数据趋势遵循简单的直线。对于一些机器学习问题，这种假设并不天真；然而，在其他一些情况下，准确性可能会下降。尽管存在危险，线性算法对于数据工程师或数据科学家来说是首选。此外，这些算法在整个训练过程中也倾向于算法简单且训练速度快。

## 在选择算法时与您的数据交谈

你可以在[`machinelearningmastery.com/tour-of-real-world-machine-learning-problems/`](http://machinelearningmastery.com/tour-of-real-world-machine-learning-problems/)或 UC Irvine 机器学习库（[`archive.ics.uci.edu/ml/`](http://archive.ics.uci.edu/ml/)）免费找到许多机器学习数据集。还应首先考虑以下数据属性：

+   参数数量

+   特征数量

+   训练数据集的大小

### 参数数量

参数或数据属性是像你这样的数据科学家在设置算法时可以调整的手段。它们是影响算法性能的数字，例如误差容限或迭代次数，或者是算法行为的变体之间的选项。算法的训练时间和准确性有时对于找到合适的设置非常敏感。通常，具有大量参数的算法需要通过试错来找到最佳组合。

尽管这是跨越参数空间的好方法，但随着参数数量的增加，模型构建或训练时间呈指数增长。这既是一个困境，也是一个时间性能的权衡。积极的一面是，拥有许多参数通常表示机器学习算法的更大灵活性。其次，你的机器学习应用可以获得更好的准确性。

### 你的训练集有多大？

如果你的训练集较小，偏差较高且方差较低的分类器（如朴素贝叶斯）比偏差较低且方差较高的分类器（如 kNN）具有优势。因此，后者会过拟合。但是，偏差较低且方差较高的分类器在你的训练集线性或指数增长时开始占优势，因为它们具有更低的渐近误差。这是因为高偏差的分类器不足以提供准确的模型。你也可以将其视为生成模型与判别模型之间的权衡。

### 特征数量

对于某些类型的实验数据集，提取的特征数量可能与数据点数量本身相比非常大。这在基因组学、生物医学或文本数据中经常发生。大量特征可能会淹没一些学习算法，使训练时间变得非常长。支持向量机在这种情况下特别适用，因为它具有高准确性、关于过拟合的良好理论保证以及适当的核函数。

## 广泛使用的机器学习算法的特殊说明

在这一部分，我们将为最常用的机器学习算法或技术提供一些特殊说明。我们将重点介绍的技术包括逻辑回归、线性回归、推荐系统、支持向量机、决策树、随机森林、贝叶斯方法和决策森林、决策丛林以及变种。表 3 显示了一些广泛使用的算法的优缺点，包括何时选择这些算法。

| **算法** | **优点** | **缺点** | **擅长** |
| --- | --- | --- | --- |
| **线性回归（LR）** | 非常快，通常在恒定时间内运行易于理解建模不太容易过拟合和欠拟合本质上简单速度非常快，因此建模时间较短不太容易过拟合和欠拟合方差较低 | 通常无法进行复杂的数据建模无法概念化非线性关系，需要转换输入数据集不适合复杂建模仅适用于单一决策边界需要大样本量才能获得稳定的结果偏差较高 | 具有大量特征的数值数据集广泛用于生物学、行为学和社会科学，以预测变量之间可能的关系对数值和分类变量都有效用于医学和社会科学等各个领域 |
| 决策树（DT） | 模型构建和预测时间较短，对噪声和缺失值具有鲁棒性，准确性高 | 大型和复杂树的解释困难，同一子树内可能出现重复，对角决策边界可能存在问题 | 针对高准确的分类、医学诊断和预后、信用风险分析 |
| 神经网络（NN） | 非常强大和稳健，能够建模非常复杂的关系，可以在不知道基础数据的情况下工作 | 容易过拟合和欠拟合，训练和预测时间长，计算成本高，模型不可读或可重复使用 | 图像处理、视频处理、人工智能、机器人、深度学习 |
| 随机森林（RF） | 适用于装袋树，方差低，准确性高，可以处理过拟合问题 | 不易直观解释，训练和预测时间长 | 处理可能相关的多个特征、生物医学诊断和预后、可用于分类和回归 |
| 支持向量机（SVM） | 准确性高 | 容易过拟合和欠拟合，数值稳定性差，计算成本高，需要大量计算资源 | 图像分类、手写识别 |
| K 最近邻（K-NN） | 简单而强大，需要懒惰训练，可用于多类分类和回归 | 训练和预测时间长，需要准确的距离函数，高维数据集性能低 | 低维数据集、异常检测、半导体故障检测、基因表达、蛋白质相互作用 |
| K-means | 线性执行时间表现优于分层聚类，对超球状聚类效果更好 | 可重复但缺乏一致性，需要先验知识 | 如果数据集中出现的自然聚类是非球状的，则不是一个好选择，适用于大型数据集 |
| 潜在狄利克雷分配（LDA） | 可应用于大规模文本数据集，可以克服 pLSA 的过拟合问题，可用于文档分类和通过主题建模进行聚类 | 不能应用于高维和复杂的文本数据库，需要指定主题数量，无法找到最佳级别，层次狄利克雷过程（HDP）是更好的选择 | 从大规模文本数据集中进行文档分类和通过主题建模进行聚类，可应用于自然语言处理和其他文本分析 |
| 朴素贝叶斯（NB） | 计算速度快，实现简单，适用于高维数据，可以处理缺失值，适应性强，模型可以根据新的训练数据进行修改而无需重建 | 依赖独立性假设，如果假设不成立则表现不佳，准确性相对较低 | 当数据有大量缺失值、特征之间的依赖关系类似、垃圾邮件过滤和分类、对科技、政治或体育新闻文章进行分类、文本挖掘 |
| 奇异值分解（SVD）和主成分分析（PCA） | 反映了关于数据的真实直觉，可以在高维数据中估计概率，数据大小显著减少，两者都基于强大的线性代数 | 对于像 Twitter 和网络分析这样的许多应用来说太昂贵，对于细粒度类别的任务来说灾难性，需要正确理解线性性，复杂度通常是立方的，计算速度较慢 | SVD 用于低秩矩阵逼近、图像处理、生物信息学、信号处理、NLP，PCA 用于利率衍生品投资组合、神经科学等，两者都适用于具有高维和多变量数据的数据集 |

表 3：一些广泛使用算法的优缺点

### 逻辑回归和线性回归

逻辑回归是一种强大的工具，因为它快速且简单，已在全球范围内用于两类和多类分类。事实上，它使用*S*形曲线而不是直线，使其自然适合将数据分成组。它提供线性类边界，因此在使用它时，请确保线性逼近是您可以接受的。与决策树或 SVM 不同，它还具有良好的概率解释，因此您将能够轻松更新模型以适应新数据集。

因此，建议使用它，如果您希望体验概率框架的味道，或者期望将来获得更多的训练数据并将其纳入您的模型。如前所述，线性回归将一条直线、平面或超平面拟合到数据集。它是一个实用、简单且快速的工具，但对于某些问题可能过于简单。

### 推荐系统

我们已经讨论了大多数常用的机器学习算法和工具的准确性和性能问题。然而，除了准确性研究之外，对推荐系统的另一个关注点是寻找其他环境因素和/或参数多样性。因此，一个准确性高且列表内多样性高的推荐系统将是赢家。因此，您的产品将对目标客户非常宝贵。然而，让用户重新对物品进行评分，而不仅仅是显示新物品，可能会更有效。如果您的客户有一些需要满足的额外要求，比如隐私或安全性，您的系统必须能够处理与隐私相关的问题。

这一点特别重要，因为客户必须提供一些个人信息，因此建议不要公开这些敏感信息。

然而，使用一些强大的技术或算法（如协同过滤）来构建用户档案可能会从隐私角度带来问题。此外，该领域的研究发现，用户人口统计信息可能会影响其他用户对推荐的满意程度（另请参阅 Joeran Beel、Stefan Langer、Andreas Nürnberger、Marcel Genzmehr，《人口统计信息（年龄和性别）和其他用户特征对评估推荐系统的影响》，在 Trond Aalberg 和 Milena Dobreva 和 Christos Papatheodorou 和 Giannis Tsakonas 和 Charles Farrugia 的《第 17 届数字图书馆理论与实践国际会议论文集》，Springer，第 400-404 页，2013 年 11 月 1 日检索）。

尽管偶然性是衡量推荐有多么令人惊讶的关键指标，但最终建立信任还是需要通过推荐系统。这可以通过解释它是如何生成推荐的，以及为什么会推荐一个物品，即使用户的人口统计信息很少，来实现。

因此，如果用户根本不信任系统，他们将不会提供任何人口统计信息，也不会重新对物品进行评分。根据*Cowley 等人*（G.C.Cawley 和 N.L.C.Talbot，《模型选择中的过拟合和性能评估中的后续选择偏差》，《机器学习研究杂志》，第 11 卷，第 2079-2107 页，2010 年 7 月），支持向量机有几个优点：

+   您可以通过 SVM 提供的正则化参数来解决过拟合问题

+   SVM 使用核技巧来帮助轻松构建机器学习模型

+   SVM 算法是基于凸优化问题开发、设计和定义的，因此没有局部最小值的概念

+   这是一个对测试错误率的边界的大致估计，其中有一个重要且深入研究的理论可以发挥作用

SVM 的这些有前途的特性确实会帮助您，建议经常使用。另一方面，缺点是：

+   理论只能真正涵盖对给定的正则化和核参数值的参数确定。因此，你只能选择核。

+   也可能存在更糟糕的情况，核模型本身在模型选择标准期间可能非常敏感于过拟合。

### 决策树

决策树很酷，因为它们易于解释和解释围绕机器学习问题。与此同时，它们可以很容易地处理与特征相关的交互。最重要的是，它们通常是非参数的。因此，即使你是一个工作能力有限的普通数据科学家，你也不需要担心异常值、参数设置和调整等问题。有时，基本上，你可以依赖决策树，这样它们将减轻你处理数据线性问题的压力，或者更技术上说，你的数据是否是线性可分的，你不需要担心。相反，也有一些缺点。例如：

+   在某些情况下，决策树可能不合适，有时它们不支持实时数据集的在线学习。在这种情况下，当出现新的示例或数据集时，你必须重新构建你的树；更技术上说，获得模型的适应性是不可能的。

+   其次，如果你没有意识到，它们很容易过拟合。

### 随机森林

随机森林非常受欢迎，对于数据科学家来说是一个赢家，因为它们对于大量分类问题来说是非常好用的。它们通常在可用性方面略领先于支持向量机，并且对于大多数分类问题的操作速度更快。此外，它们在增加可用数据集时也是可扩展的。与此同时，你不需要担心调整一系列参数。相反，当处理数据时，你需要关注许多参数和调整。

### 决策森林、决策丛林和变体

决策森林、决策丛林和提升决策树都是基于决策树的，决策树是一个基础的机器学习概念，使用较少。决策树有许多变体；尽管如此，它们都做同样的事情，即将特征空间细分为具有相同标签的区域。为了避免过拟合问题，使用数学和统计公式构建了大量的树，这些树之间没有任何相关性。

其平均值被称为决策森林；这是一种避免过拟合问题的树，如前所述。然而，决策森林可能会使用大量内存。另一方面，决策丛林是一种通过牺牲略长的训练时间来消耗较少内存的变体。幸运的是，提升决策树通过限制分区的数量和每个区域允许的数据点数量来避免过拟合。

### 贝叶斯方法

当实验或样本数据集规模较大时，贝叶斯方法通常会为参数模型提供与其他经典统计方法产生的结果非常相似的结果。使用贝叶斯方法的一些潜在优势由 Elam 等人总结（W.T. Elam, B. Scruggs, F. Eggert, and J.A. Nicolosi，《获取 XRF NET 强度方法的优缺点》，版权所有©JCPDS-国际衍射数据中心 2011 ISSN 1097-0002）。例如，它提供了一种将先验信息与数据结合的自然方式。因此，作为一名数据科学家，你可以将过去关于参数的信息并入未来分析新数据集的先验分布。它还提供了在不需要算法渐近逼近的情况下，条件于数据的推断。

它为各种模型提供了一些合适的设置，比如层次模型和缺失数据问题。使用贝叶斯分析也有一些缺点。例如，它不告诉你如何选择先验世界模型，甚至没有正确选择先验的方法。因此，如果你不小心进行，你可能会产生许多伪阳性或伪阴性的结果，这往往伴随着高昂的计算成本，如果模型中的参数数量很大的话。

# 总结

这结束了我们对机器学习和需要遵循的最佳实践的相当快速的介绍。虽然我们试图涵盖一些最基本的要点，但合适的数据往往胜过更好的算法和更高的需求。最重要的是，从数据中设计出好的特征可能需要很长时间；然而，这将对你非常有帮助。然而，如果你有一个大规模的数据集要应用到你的机器学习算法或模型中，无论你使用哪种分类、聚类或回归算法，都可能不是关于机器学习类别及其相应的分类性能的事实。

因此，选择一个能够满足速度、内存使用、吞吐量、可扩展性或可用性等要求的合适的机器学习算法将是一个明智的决定。除了我们在上面的部分中所说的内容之外，如果你真的关心准确性，你应该毫无疑问地尝试一组不同的分类器，使用交叉验证技术找到最佳的一个，或者使用集成方法来一起选择它们。

你也可以从 Netflix Prize PLUS 中得到启发并吸取教训。我们详细讨论了 Spark 机器学习 API、ML 应用开发中的一些最佳实践、机器学习任务和类别、一些广泛使用的最佳实践等等。然而，我们并没有深入分析机器学习技术。我们打算在第四章中更详细地讨论这个问题，*通过特征工程提取知识*。

在下一章中，我们将详细介绍 DataFrame、Dataset 和**Resilient Distributed Dataset**（**RDD**）API，以处理结构化数据，旨在提供对可用数据进行机器学习问题的基本理解。因此，最终，你将能够轻松地应用从基本到复杂的数据操作。


# 第三章：通过了解数据来了解问题

本章将详细介绍 DataFrame、Datasets 和**Resilient Distributed Dataset**（**RDD**）API，用于处理结构化数据，旨在提供对可用数据进行机器学习问题的基本理解。在本章结束时，您将能够轻松应用从基本到复杂的数据操作。将提供一些比较，使用 RDD、DataFrame 和 Dataset 进行数据操作的基本抽象，以展示在编程和性能方面的收益。此外，我们将指导您走上正确的道路，以便您能够使用 Spark 将 RDD 或数据对象持久化在内存中，从而在后期的并行操作中高效地重复使用。简而言之，本章将涵盖以下主题：

+   分析和准备您的数据

+   Resilient Distributed Dataset（RDD）基础知识

+   数据集基础知识

+   来自字符串和类型类的数据集

+   Spark 和数据科学家，工作流程

+   深入 Spark

# 分析和准备您的数据

在实践中，有几个因素会影响给定任务上机器学习（ML）应用的成功。因此，实验数据集的表示和质量首先被视为一流实体。拥有更好的数据总是明智的。例如，不相关和冗余的数据，具有空值或嘈杂数据的数据特征会导致不可靠的信息来源。数据集中的不良属性使得在机器学习模型训练阶段的知识发现过程更加繁琐和时间低效。

因此，数据预处理将在总体 ML 工作流程步骤中占据相当大的计算时间。正如我们在上一章中所述，除非您了解可用数据，否则很难理解问题本身。此外，了解数据将帮助您制定问题。同时，更重要的是，在尝试将 ML 算法应用于问题之前，首先您必须确定问题是否真的是一个机器学习问题，以及 ML 算法是否可以直接应用于解决问题。您需要采取的下一步是了解机器学习类别。更具体地说，您需要知道已识别的问题是否属于分类、聚类、规则重构或回归类别。

为了简单起见，我们假设您有一个机器学习问题。现在，您需要进行一些数据预处理，包括一些步骤，如数据清理、归一化、转换、特征提取和选择。数据预处理工作流程步骤的产物通常用于构建/训练 ML 模型的最终训练集。

在上一章中，我们还论证了机器学习算法是从数据和模型构建和反馈活动中学习的。关键是，您需要为您想要解决的问题为算法提供正确的数据。即使您拥有良好的数据（或者更准确地说是结构良好的数据），您也需要确保数据处于适当的规模，并且具有编程语言可以解析的良好格式，最重要的是，是否还包括最有意义的特征。

在本节中，您将学习如何准备数据，使您的机器学习算法对最佳性能变得自发。总体数据处理是一个庞大的主题；然而，我们将尝试覆盖一些基本技术，以便在*第六章*，*构建可扩展的机器学习管道*中进行一些大规模的机器学习应用。

## 数据准备过程

如果您在数据处理和准备步骤中更加专注和纪律，您很可能会在第一时间获得更一致和更好的结果。然而，数据准备是一个包含多个步骤的繁琐过程。然而，为了让数据准备好用于机器学习算法，可以总结为三个步骤：

+   数据选择

+   数据预处理

+   数据转换

### 数据选择

这一步将专注于选择您将在机器学习应用程序开发和部署中使用和处理的所有可用数据集的子集。在机器学习应用程序开发中，总是有一种强烈的冲动，即包含所有可用数据，因为更多的数据将提供更多的特征。换句话说，按照众所周知的格言，*越多越好*。然而，实际上，在所有情况下，这可能并不正确。在实际回答问题之前，您需要考虑需要哪些数据。最终目标是提供特定假设的解决方案。在一开始，您可能对数据做出一些假设。虽然这很困难，但如果您是该问题的领域专家，您可以在应用 ML 算法之前做出一些假设以至少了解一些见解。但是，要小心记录这些假设，以便在需要时在以后的阶段进行测试。我们将提出一些常见问题，以帮助您思考数据选择过程：

+   第一个问题是，*您可用的数据范围是多少？*例如，范围可能是整个时间、数据库表、连接的系统文件等。因此，最好的做法是确保您清楚地了解并低级结构化您可以使用的一切，或者非正式地持有可用资源（当然包括可用的数据和计算资源）。

+   第二个问题有点奇怪！*哪些数据尚未可用，但对解决问题很重要？*在这种情况下，您可能需要等待数据可用，或者您可以至少使用一些生成器或软件生成或模拟这些类型的数据。

+   第三个问题可能是：*您不需要哪些数据来解决问题？*这意味着再次排除冗余数据，因此排除这些冗余或不需要的数据几乎总是比全部包含它更容易。您可能会想知道是否需要记录排除的数据以及原因？我们认为应该是的，因为您可能在以后的阶段需要一些琐碎的数据。

此外，在实践中，对于小问题或游戏，玩具竞赛数据已经为您选择好了；因此，您无需担心！

### 数据预处理

在选择要处理的数据后，您需要考虑如何使用数据和所需的适当利用。这个预处理步骤将解决一些步骤或技术，以便将所选数据转换为您可以在模型构建和验证步骤中使用和应用的形式。最常用的三个数据预处理步骤是格式化、清理和抽样数据：

+   **格式化**：所选数据可能不够完善，因此可能不适合直接使用。您的数据很可能是原始数据格式（如文本格式或较少使用的专有格式的平面文件格式），如果您足够幸运，数据可能是在关系数据库中。如果是这种情况，最好应用一些转换步骤（即，例如将关系数据库转换为其格式，因为使用 Spark 您无法进行任何转换）。正如已经说明的，Spark 的美妙之处在于其对多种文件格式的支持。因此，我们将能够在接下来的部分中利用这一点。

+   **清洗**：您将要使用的数据往往带有许多不需要的记录，有时甚至有缺失的记录。这个清洗过程涉及到删除或修复缺失的数据。可能总会有一些微不足道或不完整的数据对象，处理它们应该是首要任务。因此，这些实例可能需要从数据集中删除、忽略或删除以摆脱这个问题。此外，如果由于某些属性中存在敏感信息的存在而导致隐私或安全成为问题，那么这些属性需要被匿名化或从数据中完全删除（如果适用）。

+   **抽样**：第三步将是在格式化和清理的数据集上进行抽样。由于可用数据量可能很大或记录数量很多，因此通常需要抽样。然而，我们建议尽可能使用数据。另一个原因是更多的数据可能导致整个机器学习过程的执行时间更长。如果是这种情况，这也会增加算法的运行时间，并需要更强大的计算基础设施。因此，您可以对所选数据进行较小的代表性样本，这样在考虑整个数据集之前，探索和原型化机器学习解决方案可能会更快。显然，无论您为机器学习应用开发和商业化应用的机器学习工具，数据都将影响您需要执行的预处理。

### 数据转换

在选择适当的数据源并对这些数据进行预处理后，最后一步是转换已处理的数据。您特定的机器学习算法和对问题领域的了解将在这一步中受到影响。三种常见的数据转换技术是属性缩放、分解和属性聚合。这一步通常也被称为特征工程，在下一章中将更详细地讨论：

+   **缩放**：预处理的数据可能包含具有各种数量和单位的混合比例的属性，例如美元、千克和销售量。然而，机器学习方法要求数据属性在相同的比例内，例如对于给定特征的最小值和最大值之间的 0 到 1 之间。因此，考虑您可能需要执行适当的特征缩放来对已处理的数据进行适当的缩放。

+   **分解**：数据可能具有一些代表复杂概念的特征，当您将数据集分解为基本部分时，可以使机器学习算法产生更强大的响应。例如，考虑一天由 24 小时、1,440 分钟和 86,400 秒组成，这些时间又可以进一步分解。可能一些特定的小时或一天中的小时对于需要调查和解决的问题是相关的。因此，考虑适当的特征提取和选择来执行已处理数据的适当分解。

+   **聚合**：通常，分散或零散的特征可能在其自身上是微不足道的。然而，这些特征可以被聚合成一个更有意义的特征，对您试图解决的问题更有意义。例如，一些数据实例可以在在线购物网站上呈现，每次客户登录网站时都会产生数据对象。这些数据对象可以通过丢弃额外的实例来聚合成登录次数的计数。因此，考虑适当的特征聚合来正确处理数据。

Apache Spark 具有其分布式数据结构，包括 RDD、DataFrame 和 Datasets，您可以使用这些数据结构高效地进行数据预处理。这些数据结构在处理数据时具有不同的优势和性能。在接下来的章节中，我们将分别描述这些数据结构，并展示如何使用它们处理大型数据集的示例。

# 弹性分布式数据集基础知识

在第一章中，*使用 Spark 进行数据分析简介*，我们简要描述了弹性分布式数据集，包括数据转换和操作以及缓存机制。我们还指出 RDD 基本上是一个不可变的记录集合，只能通过 map、filter、group by 等操作来创建。在本章中，我们将使用 Spark 的这种本机数据结构进行数据操作和数据预处理，用于一个常被称为垃圾邮件过滤的实际机器学习应用。Spark 还提供了另外两个更高级别的 API，如 DataFrame 和 Datasets，用于数据操作。

然而，我们将展示包括 RDD 在内的所有 API，因为您可能需要这个 API 来处理更复杂的数据操作。我们已经从 Spark 编程指南中引用了一些关于 Spark 操作和操作的常用定义。

正如我们已经讨论过使用操作和转换的 RDD 操作的一些基础知识。RDD 可以通过稳定的存储（如 Hadoop 分布式文件系统（HDFS））和对现有 RDD 的转换来创建。Spark 定期记录这些转换，而不是实际数据，因此从技术上讲，原始 RDD 和数据集不会发生变化。

可以从现有数据集创建一个转换后的数据集；但是在 Spark 中不可能反过来。在数据集上完成计算后，操作将返回一个值给驱动程序。例如，根据 Spark 编程指南，map 是一种通过函数传递每个数据集元素并返回一个全新的 RDD 来表示和保存结果的转换。相反，reduce 也是一种通过函数聚合 RDD 的所有元素并返回一个全新的 RDD 作为最终结果返回给驱动程序的操作。

更具体地说，假设我们有一个包含以逗号分隔的数字序列的文本文件（即 CSV 文件）。现在在读取完毕后，您将拥有一个 RDD，因此您可能希望计算每个数字的频率。为此，您需要将 RDD 转换为键值对，其中键是数字，值将是每个数字的频率。

另一方面，您可能需要通过一些操作在驱动程序中收集结果。在接下来的几节中，我们将通过基于实际机器学习问题的一些示例，提供有关转换和操作等一些有用主题的更多细节。

## 读取数据集

为了从不同的数据源（如本地文件系统、HDFS、Cassandra、HBase 等）读取数据集，Spark 提供了易于使用的不同 API。它支持包括文本文件、序列文件、Hadoop 输入格式、CSV、TSV、TXT、MD、JSON 和其他数据格式在内的不同数据表示。输入 API 或方法支持在压缩文件、目录和通配符上运行。例如，*表 1*显示了读取格式的列表。`textFile()`方法从目录`/my/directory`中读取不同的文件格式，如`.txt`和`.gz`。

| textFile("/my/directory"),textFile("/my/directory/*.txt"),textFile("/my/directory/*.gz"). |
| --- |

表 1：读取文件格式

### 从文件中读取

您可能需要从本地或 HDFS 读取数据集。以下代码展示了从存储在本地机器或 HDFS 上的给定数据集创建 RDD 的不同方法。

然而，在使用 Spark 进行读取和写入之前，我们需要通过 Spark 会话创建 Spark 入口点，可以通过以下方式实例化：

```scala
static SparkSession spark = SparkSession 
      .builder() 
      .appName("JavaLDAExample") 
      .master("local[*]") 
      .config("spark.sql.warehouse.dir", "E:/Exp/") 
      .getOrCreate(); 

```

在这里，Spark SQL 仓库设置为`E:/Exp/`路径。您应该根据您所在的操作系统类型设置您的路径。好了，现在我们有了变量`spark`作为我们的 Spark 会话，让我们看看如何轻松地使用它来从文本文件中读取。

#### 从文本文件中读取

它使用`SparkContext()`的`textFile()`方法，并返回一个包含行集合的字符串的 RDD。在第一章中，我们解释了什么是 SparkContext。尽管如此，Spark Context 是 Spark 应用程序的入口点。假设我们有一个名为`1.txt`的数据集，其中包含一些推文数据作为非结构化文本。您可以从 Packt 材料中下载数据，并将其存储在`project_path/input/test/`目录下，定义如下：

```scala
String csvFile = "input/test/1.txt"; 
RDD<String> distFile = spark.sparkContext().textFile(csvFile, 2); 

```

在这里，我们已经创建了一个存储在变量`distFile`中的字符串的两个分区的 RDD。但是，要使用 Java，RDD 必须转换为 JavaRDD。通过调用`toJavaRDD()`方法来实现：

```scala
JavaRDD<String> distFile2 = distFile.toJavaRDD(); 

```

#### 从目录中读取多个文本文件

它将返回 RDD 作为（文件名和内容）对。假设我们有多个文件存储在`csvFiles/`目录中以供读取，定义如下：

```scala
RDD<Tuple2<String, String>> distFile = spark.sparkContext().wholeTextFiles("csvFiles/*.txt", 2); 
JavaRDD<Tuple2<String, String>> distFile2 = distFile.toJavaRDD(); 

```

请注意，当 RDD 中的数据对象不存储在主内存或 HDD 中时，我们需要对 RDD 执行分区以增加并行性。

### 从现有集合中读取

创建 RDD 的第二个来源是从驱动程序程序的集合中，例如包含整数的列表。在深入讨论之前，让我们以另一种方式初始化 Spark，如下所示：

```scala
SparkConf conf = new SparkConf().setAppName("SampleAppliation").setMaster("local[*]"); 
JavaSparkContext sc = new JavaSparkContext(conf); 

```

这里 Java Spark 上下文可用作变量`sc`。这一次，我们已经创建了 Spark 上下文，因此我们将能够创建字符串的 Java RDD，而无需使用`toJavaRDD()`方法。

现在，您可以使用 Spark Context 的并行化方法来实现：

+   **读取整数列表**：它返回一个并行化的整数 RDD：

```scala
      List<Integer> list = Arrays.asList(1,2,3,4,5); 
      JavaRDD<Integer> rdd = sc.parallelize(list); 

```

+   **读取成对列表**：它返回一个并行化的`pairRDD`，其中包含成对的整数和字符串：

```scala
      List<Tuple2<Integer, String>> pairs = Arrays.asList( 
                new Tuple2<>(1, "Hello"), 
                new Tuple2<>(2, "World"), 
                new Tuple2<>(3, "How are you?")); 
      JavaPairRDD<Integer, String> pairRDD = sc.parallelizePairs(pairs); 

```

## RDD 的预处理

为了继续讨论我们在上一节开始的数据预处理，我们将在本节中展示一个机器学习问题的示例，以及如何使用 RDD 对数据集进行预处理。

我们正在考虑的是**垃圾邮件过滤器**应用程序，这是一个受欢迎的监督学习问题的典型示例。问题是从传入的电子邮件中预测和识别垃圾邮件消息（请参阅*表 2*）。通常，为了训练模型，您必须使用历史数据（您在几天、几小时或几个月甚至一年内收到的历史电子邮件）来训练模型。预处理任务的最终输出是制作特征向量或提取包括其标签或类别的特征。通常，您可能会执行以下步骤：

+   **停用词去除**：文本文件可能包含一些对于特征向量无用或多余的单词，例如*and*、*the*和*of*，因为这些单词在所有形式的英语句子中都非常常见。另一个原因是它们在决定垃圾邮件或正常邮件状态时没有太多意义，或者它们可能包含微不足道的意义。因此，在进行下一步之前，需要从电子邮件数据集中过滤掉这些单词。

+   **词形还原**：一些具有相同含义但不同结尾的单词需要被调整，以使它们在整个数据集中保持一致，如果它们都具有相同的形式，将更容易将它们转换为特征向量。例如，*attached*、*attachment*和*attach*都可以表示为电子邮件*attachments*。`SMSSpamCollection`数据集可以从 UCI ML 存储库[`archive.ics.uci.edu/ml/machine-learning-databases/00228/`](https://archive.ics.uci.edu/ml/machine-learning-databases/00228/)下载。

请注意，在这个阶段，电子邮件正文中的所有单词通常都会被转换为小写。现在，让我们来看一下下表：

| ham: 你在干什么？你好吗？ham: 好的啦...只是和你开玩笑。ham: 不要这么早说...你已经看到了然后说。ham: 我的号码在卢顿 0125698789，如果你在附近给我打电话！H*spam: 免费信息：短信：拨打 86888 号码，领取您的 3 小时通话时间奖励，现在可以在您的手机上使用！订阅 6 英镑/月，包括 3 小时 16 次停止？txtStop ham: 西瓦在宿舍哈哈。ham: 因为我刚才和达伦出去购物，我给他打电话问他想要什么礼物。然后他开始猜我和谁在一起，最后他猜到了是达伦。spam: 阳光测验！如果你能说出澳大利亚的首都，就赢得一个超级索尼 DVD 录像机！发送 MQUIZ 到 82277\. B |
| --- |

表 2：包含正常邮件和垃圾邮件消息的训练集的测试文件

+   **去除非单词**：数字和标点也必须被去除。然而，由于页面限制和简洁性，我们不会在这里展示所有可能的预处理数据的转换，但我们将尝试展示一些基本的预处理数据的转换和操作，其中包含一些标签数据，如*表 2*中所示。数据集或电子邮件被标记为正常邮件或垃圾邮件，后面跟着消息或电子邮件。正常邮件意味着非垃圾邮件，垃圾邮件被识别为垃圾邮件消息。

使用 RDD 进行的整体预处理可以用以下步骤描述。我们需要的第一步是使用 RDD 操作和转换准备特征向量。其余步骤如下：

+   **读取数据集**：以下代码用于读取数据集，从`SMSSpamCollection`数据集创建一个字符串的`linesRDD`。请从 Packt 材料中下载这个数据集，并将其存储在您的磁盘或 HDFS 中的`Project+path/input/`目录中。稍后将提供有关此数据集的详细描述：

```scala
      String filePath = "input/SMSSpamCollection.txt"; 
      JavaRDD<String> linesRDD = sc.textFile(filePath); 

```

然而，`linesRDD`包含了垃圾邮件和正常邮件消息。因此，我们需要从文件中分离垃圾邮件和正常邮件。

+   **过滤垃圾邮件**：为了从现有的 RDD 中过滤数据，Spark 提供了一个名为`filter()`的方法，它返回一个只包含所选元素的新数据集。在下面的代码中，您可以看到我们已经将`new Function()`作为参数传递给了`filter()`方法，它接受两个类型为 String 和 Boolean 的参数。基本上，Spark API 在集群上运行时大量依赖于将函数传递给驱动程序。有两种方法可以创建包含函数的函数，包括：

+   实现函数接口，无论是创建匿名内部类还是命名内部类，并将其实例传递给 Spark

+   使用 lambda 表达式（尽管您需要安装 Java 8 才能利用 lambda 表达式）

+   以下代码片段说明了我们使用的匿名类概念作为包含`call()`方法的参数，如果行包含单词`spam`，则返回`true`： 

```scala
      JavaRDD<String> spamRDD = linesRDD.filter(new Function<String,   
        Boolean>() { 
        @Override 
        public Boolean call(String line) throws Exception { 
          return line.split("\t")[0].equals("spam");}}); 

```

+   过滤掉正常邮件：同样，我们可以过滤掉正常邮件，如下所示：

```scala
      JavaRDD<String> hamRDD = linesRDD.filter(new Function<String,  
       Boolean>() { 
       @Override 
       public Boolean call(String line) throws Exception { 
         return line.split("\t")[0].equals("ham"); 
        } 
     }); 

```

+   **从行中分割单词**：为了从每行中提取特征和标签，我们需要使用空格或制表符来分割它们。之后，我们可以得到不包含垃圾邮件或正常邮件单词的行。

以下代码段显示了从行中分离垃圾邮件和正常邮件特征。我们使用了`map`转换，它返回一个新的 RDD，通过将现有 RDD 的每一行传递给`call`函数来形成。这里`call`方法总是返回一个单个项目。您将在后面的部分中发现与`flatMap`的区别：

```scala
      JavaRDD<String> spam = spamRDD.map(new Function<String, String>() { 
        @Override 
        public String call(String line) throws Exception {       
         return line.split("\t")[1]; 
        } 
     }); 

```

输出：`ham.collect()`：

![RDD 的预处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00052.jpeg)

图 1：垃圾邮件 RDD 的快照

```scala
      JavaRDD<String> ham = hamRDD.map(new Function<String, String>() { 
        @Override 
        public String call(String line) throws Exception {     
          return line.split("\t")[1]; 
      } 
      }); 

```

输出：`ham.collect()`：

![RDD 的预处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00066.jpeg)

图 2：正常邮件 RDD 的快照

+   **从垃圾邮件 RDD 的行中拆分单词**：在我们分别得到垃圾邮件和正常邮件 RDD 的特征行之后，我们需要拆分单词以便在将来创建特征向量。以下代码通过使用空格进行拆分并返回单词列表 RDD。调用方法返回每行的单词列表：

```scala
      JavaRDD<ArrayList<String>> spamWordList = spam.map(new  
        Function<String, ArrayList<String>>() { 
          @Override 
      public ArrayList<String> call(String line) throws Exception{ 
            ArrayList<String> words = new ArrayList<>(); 
            words.addAll(Arrays.asList(line.split(" "))); 
            return words; 
          }}); 
      JavaRDD<ArrayList<String>> hamWordList = ham.map(new Function<String,  
        ArrayList<String>>() { 
          @Override 
      public ArrayList<String> call(String line) throws Exception{   
            ArrayList<String> words = new ArrayList<>(); 
            words.addAll(Arrays.asList(line.split(" "))); 
            return words;} 
      }); 

```

+   **创建标签和特征对 RDD**：现在我们有了垃圾邮件和正常邮件的两个 RDD。我们想要用 1.0 或 0.0 来标记它们，分别表示垃圾邮件和正常邮件的单词或特征。为了方便使用，我们可以再次创建一个新的 RDD，每行包含一个标签和特征或单词列表的元组。在下面的代码中，我们使用了`Tuple2`来创建一对。您也可以使用`JavaPairRDD`来创建标签和特征的一对：

```scala
      JavaRDD<Tuple2<Double, ArrayList<String>>> spamWordsLabelPair =  
      spamWordList.map(new Function<ArrayList<String>, Tuple2<Double,  
          ArrayList<String>>>() { 
          @Override 
            public Tuple2<Double, ArrayList<String>> call( 
            ArrayList<String> v1) throws Exception {     
            return new Tuple2<Double, ArrayList<String>>(1.0, v1); 
          }}); 
      JavaRDD<Tuple2<Double, ArrayList<String>>> hamWordsLabelPair =  
      hamWordList.map(new Function<ArrayList<String>, Tuple2<Double,  
          ArrayList<String>>>() { 
          @Override 
          public Tuple2<Double, ArrayList<String>> call( 
            ArrayList<String> v1) throws Exception {     
            return new Tuple2<Double, ArrayList<String>>(0.0, v1); 
          }}); 

      [Output: print spamWordsLabelPair2.collect() using for loop] 
      1.0: [FreeMsg:, Txt:, CALL, to, No:, 86888, &, claim, your, reward, 
      of, 3, hours, talk, time, to, use, from, your, phone, now!, 
      ubscribe6GBP/, mnth, inc, 3hrs, 16, stop?txtStop] 
      1.0: [Sunshine, Quiz!, Win, a, super, Sony, DVD, recorder,
      if, you, canname, the, capital, of, Australia?, Text, MQUIZ, 
      to, 82277., B] 

```

+   **两个 RDD 的并集**：现在我们在*表 2*中有数据集的两个标签，即垃圾邮件和正常邮件的特征对 RDD。现在要创建训练数据集，我们可以将这两个 RDD 合并成一个。Spark 有一个`union()`方法可以做到这一点，它返回一个新的 RDD，包含数据集和参数或另一个数据集的并集：

```scala
      JavaRDD<Tuple2<Double, ArrayList<String>>> train_set =  
      spamWordsLabelPair.union(hamWordsLabelPair); 

```

+   对于前面的所有操作，称为转换。这在每种情况下都会从现有的工作节点中返回一个新的数据集。如果您想要将返回结果带回驱动程序或打印结果，那将被称为动作操作。Spark 支持几种内置方法作为动作。`count()`方法用于计算数据集中的元素数量：

```scala
      System.out.println(train_set.count()); 
      The following output is 8

```

+   **打印 RDD**：`collect()`和`take()`也是用于打印或收集数据集作为驱动程序中的数组的动作方法，其中，`take()`接受一个参数，比如*n*，返回数据集的前 n 个元素。以下代码段打印出训练集中的前 10 个元素或元组：

```scala
      for (Tuple2<Double, ArrayList<String>> tt : train_set.collect()) { 
          System.out.println(tt._1 + ": " + tt._2.toString()); } 

```

输出如下：

```scala
      1.0: [FreeMsg:, Txt:, CALL, to, No:, 86888,
       &, claim, your, reward, of, 3, hours, talk, time, to, use, from,
       your, phone, now!, ubscribe6GBP/, mnth, inc, 3hrs, 16, stop?txtStop] 
      1.0: [Sunshine, Quiz!, Win, a, super, Sony, DVD, recorder, if, 
      you, canname, the, capital, of, Australia?, Text, MQUIZ, 
      to, 82277., B] 
      0.0: [What, you, doing?, how, are, you?] 
      0.0: [Ok, lar..., Joking, wif, u, oni...] 
      0.0: [dun, say, so, early, hor..., U, c, already, then, say...] 
      0.0: [MY, NO., IN, LUTON, 0125698789, RING, ME, IF, UR, AROUND!, H*] 
      0.0: [Siva, is, in, hostel, aha:-.] 
      0.0: [Cos, i, was, out, shopping, wif, darren, jus, now,
       n, i, called, 
      him, 2, ask, wat, present, he, wan, lor., Then, he, 
      started, guessing, 
      who, i, was, wif, n, he, finally, guessed, darren, lor.] 

```

+   **将结果保存在本地文件系统中**：有时您可能需要将 RDD 保存在文件系统中。您可以使用以下代码直接保存您的 RDD：

```scala
      train_set.saveAsTextFile("output.txt"); 

```

### 从 SMSSpamCollection 数据集中获取见解

以下源代码显示了基本的正常邮件和垃圾邮件统计信息：

```scala
String path = "input/SMSSpamCollection.txt";     
RDD<String> lines = spark.sparkContext().textFile(path, 2); 
System.out.println(lines.take(10)); 

JavaRDD<Row> rowRDD = lines.toJavaRDD().map( new Function<String, Row>() { 
    public Row call(String line) throws Exception { 
      return RowFactory.create(line); 
      }}); 
System.out.println(rowRDD.collect()); 
List<StructField> fields = new ArrayList<StructField>(); 
fields.add(DataTypes.createStructField("line", DataTypes.StringType, true)); 
org.apache.spark.sql.types.StructType schema = DataTypes.createStructType(fields); 
Dataset<Row> df = spark.sqlContext().createDataFrame(rowRDD, schema); 
df.select("line").show(); 
Dataset<Row> spam = df.filter(df.col("line").like("%spam%")); 
Dataset<Row> ham = df.filter(df.col("line").like("%ham%")); 
System.out.println(spam.count()); 
System.out.println(ham.count()); 
spam.show(); 

```

上述代码生成了以下垃圾邮件和正常邮件计数：

```scala
747 
4831 

```

这意味着在 5578 封电子邮件中，有 747 封是垃圾邮件，4831 封被标记为正常邮件或非垃圾邮件。换句话说，垃圾邮件和正常邮件的比例分别为 13.40%和 86.6%。

## 处理键值对

本小节描述了在数据分析中经常需要的键值对，特别是在文本处理中。

### mapToPair()

这个方法将返回一个(K，V)对的数据集，其中 K 是键，V 是值。例如，如果您有一个包含整数列表的 RDD，然后想要计算列表中重复条目的数量，那么第一步是将每个数字映射为 1。之后您可以对其进行 reduce 操作。该代码产生了如下所示的输出和缓存：

```scala
JavaRDD<Integer> rdd = sc.parallelize(Arrays.asList(1,2,1,3,4,5)); 
JavaPairRDD<Integer, Integer> pairs = rdd.mapToPair( 
  new PairFunction<Integer, Integer, Integer>() { 
    @Override 
    public Tuple2<Integer, Integer> call(Integer x) { 
      return new Tuple2<>(x, 1); 
    } 
}).cache(); 

[Output: pairs.collect()] 
[(1,1), (2,1), (1,1), (3,1), (4,1), (5,1)] 

```

## 更多关于转换的内容

在本节中，您可以了解更多关于转换的内容，包括一些类似方法之间的差异。主要将讨论`map`和`flatMap`，`groupByKey`，`reduceByKey`和`aggregateByKey`，`sortByKey`和`sortBy`。然而，有兴趣的读者可以参考[2]中的 Spark 编程指南了解 RDD 操作。

### map 和 flatMap

`flatMap`类似于我们在前面的示例中展示的`map`，但是每个输入项或每次调用匿名类的`call()`方法都可以映射到零个或多个输出项。因此，`call()`函数返回的是一个序列，而不是像`map`那样返回单个项。例如，对于以下 RDD 的输入，输出应该如下所示：

```scala
JavaRDD<String> rdd = sc.parallelize(Arrays.asList("Hello World!", 
  "How are you.")); 
JavaRDD<String> words = rdd 
  .flatMap(new FlatMapFunction<String, String>() { 
    @Override 
    public Iterable<String> call(String t) throws Exception { 
      return Arrays.asList(t.split(" ")); 
    }}); 

[output: words.collect()] 
[Hello, World!, How, are, you.] 

```

对于前面的示例，您无法执行映射操作，因为`map`的`call()`方法只返回一个对象，而不是一系列对象。

### groupByKey，reduceByKey 和 aggregateByKey

为了在预处理数据集时执行一些操作，您可能需要根据键值进行一些汇总，例如求和和平均值。Spark 提供了一些方法来执行这些类型的操作。假设您有以下 RDD 对，并且您想根据键对值进行分组并进行一些汇总：

```scala
JavaPairRDD<Integer, Integer> rdd_from_integer = sc 
.parallelizePairs(Arrays.asList( new Tuple2<>(1, 1),  
new Tuple2<>(1, 1), new Tuple2<>(3, 2), 
new Tuple2<>(5, 1), new Tuple2<>(5, 3)), 2);  

```

您想要执行的汇总可以通过 Spark 的三种方法来完成，包括`groupByKey`，`reduceByKey`和`aggregateByKey`。但它们在性能、效率和灵活性方面有所不同，可以执行诸如计数、计算摘要统计信息、从数据集中找到唯一元素等操作。`groupByKey`方法返回一个(k，`Iterable<v>`)对的数据集，其中 k 是键，`Iterable<v>`是键 k 的值序列。使用此方法的先前数据集的输出如下所示，显示了每个键的集合值：

```scala
[Output: pairs.groupByKey(2).collect() ] 

```

![groupByKey，reduceByKey 和 aggregateByKey](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00080.jpeg)

图 3：使用 groupBykey 的对

为了对每个唯一键的值进行求和，`groupByKey`在性能上是低效的，因为它不执行组合的映射。您必须进行更多的转换来明确进行这种求和。因此，它会增加网络 I/O 和洗牌大小。通过`reduceByKey`或`aggregateByKey`可以获得更好的性能，因为它们执行映射端的组合。

这些方法返回具有每个键聚合结果的数据集，例如每个键的值的总和。以下代码显示了这些方法的操作，它们返回由给定函数聚合键的值的(k,v)对的数据集。

`reduceByKey`需要一个函数，用于减少每个键的值，而`aggregateByKey`需要两个函数，其中第一个函数用于指定如何在每个分区内进行聚合，第二个函数用于指定如何在分区之间进行聚合：

+   代码：`reduceByKey()`：

```scala
      JavaPairRDD<Integer, Integer> counts = rdd 
        .reduceByKey(new Function2<Integer, Integer, Integer>() { 
          @Override 
          public Integer call(Integer a, Integer b) { 
            return a + b;}}); 

```

+   代码：`aggregateByKey()`：

```scala
      JavaPairRDD<Integer, Integer> counts = pairs.aggregateByKey(0, 
          new Function2<Integer, Integer, Integer>() { 
            @Override 
            public Integer call(Integer v1, Integer v2) { 
              return v1 + v2; 
            } 
            }, new Function2<Integer, Integer, Integer>() { 
            @Override 
            public Integer call(Integer v1, Integer v2) { 
                  return v1 + v2; 
                } 
              }); 

```

对于这两种情况，输出将如下所示：

`counts.collect()`的输出：

![groupByKey，reduceByKey 和 aggregateByKey](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00088.jpeg)

图 4：使用计数的 RDD

### sortByKey 和 sortBy

排序是数据预处理中的常见操作。Spark 提供了两种方法，可以将一个数据集转换为另一个排序的配对数据集，包括`sortByKey`和`sortBy`。例如，我们有一个如下所示的数据集：

```scala
List<Tuple2<Integer, Integer>> pairs = new ArrayList<>(); 
pairs.add(new Tuple2<>(1, 5)); 
pairs.add(new Tuple2<>(4, 2)); 
pairs.add(new Tuple2<>(-1, 1)); 
pairs.add(new Tuple2<>(1, 1)); 

```

`sortByKey()`方法在(k,v)对上执行，并按键的升序或降序返回(k,v)对。您还可以通过提供比较器来自定义排序。以下代码显示了对前面数据集的键进行排序：

+   代码：`sortByKey()`：

```scala
      JavaPairRDD<Integer, Integer> rdd = sc.parallelizePairs(pairs); 
      JavaPairRDD<Integer, Integer> sortedRDD=rdd.sortByKey(Collections.
      <Integer> reverseOrder(), false); 
      [Output: sortedRDD.collect()] 

```

![sortByKey 和 sortBy](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00019.jpeg)

图 5：使用 sortByKey 的对

`sortBy()`方法接受一个函数作为参数，您可以在其中指定排序方法，无论是按键还是按值。以下代码显示了对前面数据集的值进行排序：

+   代码：`sortBy()`：

```scala
      JavaRDD<Tuple2<Integer, Integer>> rdd_new = sc.parallelize(pairs); 
      JavaRDD<Tuple2<Integer, Integer>> sortedRDD=rdd.sortBy( 
      new Function<Tuple2<Integer, Integer>, Integer>() { 
      @Override 
          public Integer call(Tuple2<Integer, Integer> t) { 
              return t._2(); 
          } 
      ,} true, 2);
```

`sortedRDD.collect()`的输出：

![sortByKey 和 sortBy](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00023.jpeg)

图 6：使用 sortBy 的对

# 数据集基础知识

如在第一章中讨论的，*使用 Spark 进行数据分析简介*，在 Spark 2.0.0 发布中，DataFrame 仍然是 Scala、Python 和 R 的主要计算抽象，但在使用 Java 时，将使用 Dataset 替换。因此，本书中将始终使用类型为 Row 的 Dataset。

Dataset 是一个分布式的数据集合，结构化为行。这是与 Spark SQL 模块交互的更方便的方式之一。

换句话说，它可以被视为类似于关系数据库（RDB）格式的等价实体。与 DataFrame 和 RDD 等其他数据抽象一样，Dataset 也可以从各种数据源创建，如结构化数据文件（TSV、CSV、JSON 和 TXT）、Hive 表、辅助存储、外部数据库或现有的 RDD 和 DataFrame。然而，在 Spark 2.0.0 发布后，基于 Java 的计算不支持 DataFrame，但如果您使用 Python、Scala 或 R 开发应用程序，仍然可以使用 DataFrame。

在接下来的几节中，您将找到使用 Dataset 的操作和操作，以及如何从不同的来源创建 Dataset。

## 读取数据集以创建 Dataset

如上所述，Dataset 是从 Spark 1.5.0 版本开始引入的 Spark SQL 模块的一个组件。因此，所有功能的入口都始于初始化 Spark `SQLContext`。基本上，Spark SQL 用于执行 SQL 查询，可以使用基本的 SQL 语法或 HiveQL 编写。

在另一种编程语言中运行 SQL 时，将返回一个 Dataset 对象。以下代码段将在 Spark 上下文中初始化`SQLContext`。另一方面，您可能需要初始化`HiveContext`以从 Hive 中读取数据集。您还可以创建一个不同的上下文，如`HiveContext`，它提供了`SQLContext`基本功能的超集：

```scala
JavaSparkContext sc = new JavaSparkContext("local","DFDemo"); 
SQLContext sqlContext = new org.apache.spark.sql.SQLContext(sc); 

```

### 从文件中读取

例如，您有一个如下所示的 JSON 文件。现在您想要使用 SQL 上下文读取此文件，基本上返回一个 DataFrame，您可以执行所有基本的 SQL 操作和其他 Spark 的 DSL 操作：

```scala
[Input File] 
{"name":"Michael"} 
{"name":"Andy", "age":30} 
{"name":"Justin", "age":19} 
[Code]    
Dataset<Row> df = sqlContext.read().json("people.json");    

[Output: df.show()] 
+----+-------+ 
| age|   name| 
+----+-------+ 
|null|Michael| 
|  30|   Andy| 
|  19| Justin| 
+----+-------+ 

```

### 从 Hive 中读取

以下代码连接到 Hive 上下文，其中创建了一个表，并将 people JSON 文件加载到 Hive 中。DataFrame 的输出将与上述相同：

```scala
The code is as follows:]hiveContext.sql("CREATE TEMPORARY TABLE people USING  
org.apache.spark.sql.json OPTIONS ( path "people.json" )"); 
Dataset<Row> results = hiveContext.sql("SELECT * FROM people "); 
results.show(); 

```

## 使用 Dataset 进行预处理

在前一节中，我们已经描述了在实际机器学习应用程序中使用 RDD 进行预处理。现在我们将使用 DataFrame（DF）API 进行相同的示例。您会发现很容易操作`SMSSpamCollection`数据集（请参阅[`www.dt.fee.unicamp.br/~tiago/smsspamcollection/`](http://www.dt.fee.unicamp.br/~tiago/smsspamcollection/)）。我们将展示相同的示例，通过对垃圾邮件和正常消息进行标记化，以准备一个训练集：

+   **读取数据集**：您可以使用初始化之前的 Spark 会话变量`spark`来读取该数据集。读取文件作为 Dataset 后，输出将是单列的表格格式。此列的默认名称是`value`：

```scala
      Dataset<Row> df = spark.read().load("input/SMSSpamCollection.txt"); 
      df.show(); 

```

输出：

![使用 Dataset 进行预处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00101.jpeg)

图 7：SMS 垃圾邮件数据集的快照

+   **从现有数据集创建 Row RDD**：从前面的输出中，您可以看到一个包含所有行在一起的列。为了使两列，如标签和特征，我们必须将其拆分。由于 Dataset 是不可变的，您无法修改现有的列或 Dataset。因此，您必须使用现有的 Dataset 创建新的 Dataset。这里的代码将 Dataset 转换为 Row 数据集的集合。Row 是一个接口，表示来自关系运算符的输出的一行。您可以使用 Spark 的`RowFactory`类创建一个新的 Row：

```scala
         JavaRDD<Row> rowRDD = df.toJavaRDD(); 

```

+   从现有的行 RDD 创建新的行 RDD：在拥有行 RDD 之后，您可以执行常规的 map 操作，其中包含所有包含两个值的行数据集。以下代码拆分每一行并返回一个新的行：

```scala
      JavaRDD<Row> splitedRDD = rowRDD.map(new Function<Row, Row>() { 
           @Override 
          public Row call(Row r) throws Exception { 
            String[] split = r.getString(0).split("\t"); 
            return RowFactory.create(split[0],split[1]); 
          }}); 

```

+   从行 RDD 创建数据集：现在您有了包含每行两个值的行 RDD。要创建 DF，您必须定义列名或模式及其数据类型。有两种方法可以定义，包括使用反射推断模式和以编程方式指定模式。方法如下：

+   第一种方法基本上使用 POJO 类和字段名称将成为模式

+   第二种方法通过定义数据类型并创建 structype 来创建 StruchFields 列表。在本例中，我们使用了第二种方法来从现有行 RDD 创建 DF，如下所示：

```scala
      List<StructField> fields  = new ArrayList<>(); 
      fields.add(DataTypes.createStructField("labelString", 
      DataTypes.StringType, true)); 
      fields.add(DataTypes.createStructField("featureString",  
      DataTypes.StringType, true)); 
      org.apache.spark.sql.types.StructType schema = DataTypes 
      .createStructType(fields); 
      Dataset<Row> schemaSMSSpamCollection = sqlContext 
      .createDataFrame(splitedRDD, schema); 
      schemaSMSSpamCollection.printSchema(); 
      [Output: schemaSMSSpamCollection.printSchema()] 

```

![使用数据集进行预处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00040.jpeg)

图 8：集合的模式

+   添加新列：现在我们有了两列的 DF。但是我们想要添加新列，将`labledSting`转换为`labedDouble`，将`featureString`转换为`featureTokens`。您可以像以前的代码一样进行操作。在添加新字段后，创建新模式。然后在现有 DF 中进行常规 map 转换后创建新 DF。以下代码给出了具有四列的新 DF 的输出：

```scala
      fields.add(DataTypes.createStructField("labelDouble",  
      DataTypes.DoubleType, true)); 
      fields.add(DataTypes.createStructField("featureTokens",  
      DataTypes.StringType, true)); 
      org.apache.spark.sql.types.StructType schemaUpdated =  
      DataTypes.createStructType(fields); 
      Dataset Row> newColumnsaddedDF = sqlContext 
      .createDataFrame(schemaSMSSpamCollection.javaRDD().map( 
      new Function<Row, Row>() { 
          @Override 
          public Row call(Row row) throws Exception { 
            double label; 
            if(row.getString(0).equalsIgnoreCase("spam")) 
              label = 1.0; 
            else 
              label = 0.0; 
            String[] split = row.getString(1).split(" "); 
            ArrayList<String> tokens = new ArrayList<>(); 
            for(String s:split) 
              tokens.add(s.trim()); 
            return RowFactory.create(row.getString(0), 
       row.getString(1),label, tokens.toString()); 
          }}), schemaUpdated);   
      [Output: newColumnsaddedDF.show()] 

```

![使用数据集进行预处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00058.jpeg)

图 9：添加新列后的数据集

+   一些数据集操作：对于数据操作，DF 提供了 Java、Scala 等领域特定语言。您可以对 DF 进行选择、计数、过滤、`groupBy`等操作。以下代码展示了对上述 DF 的一些操作：

```scala
      newColumnsaddedDF.select(newColumnsaddedDF.col("labelDouble"),
      newColumnsaddedDF.col("featureTokens")).show(); 

```

![使用数据集进行预处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00053.jpeg)

图 10：显示标签和特征的数据集

```scala
      newColumnsaddedDF.filter(newColumnsaddedDF.col
      ("labelDouble").gt(0.0)).show(); 

```

![使用数据集进行预处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00009.jpeg)

图 11：数据集显示标签已转换为双值

```scala
      newColumnsaddedDF.groupBy("labelDouble").count().show(); 

```

![使用数据集进行预处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00001.jpeg)

图 12：显示操作后的数据集统计信息

## 更多关于数据集操作

本节将描述如何在 DF 上使用 SQL 查询以及在数据集之间创建不同方式的数据集。主要讨论在 DataFrame 上运行 SQL 查询以及从 JavaBean 创建 DataFrame。然而，有兴趣的读者可以参考 Spark 编程指南中有关 SQL 操作的内容[3]。

### 在数据集上运行 SQL 查询

Spark 的`SQLContext`具有`sql`方法，使应用程序能够运行 SQL 查询。该方法返回一个 DataFrame 作为结果：

+   [`FilternewColumnsAddedDF.createOrReplaceTempView`(`SMSSpamCollection`)]:

```scala
      Dataset<Row> spam = spark.sqlContext().sql("SELECT * FROM 
      SMSSpamCollection
      WHERE labelDouble=1.0"); 
      spam.show();  

```

以下是上述代码的输出：

![在数据集上运行 SQL 查询](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00077.jpeg)

图 13：使用 SQL 查询检索与图 11 相同的结果

+   计数：

```scala
      Dataset<Row> counts = sqlContext.sql("SELECT labelDouble, COUNT(*)  
      AS count FROM SMSSpamCollection GROUP BY labelDouble"); 
      counts.show(); 

```

输出：

![在数据集上运行 SQL 查询](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00031.jpeg)

图 14：显示数据集统计信息

## 从 Java Bean 创建数据集

您可以从 Java Bean 创建数据集；在这种情况下，您不需要以编程方式定义模式。例如，您可以在以下代码中看到名为 Bean 的**普通旧 Java 对象**（**POJO**）：

```scala
public class SMSSpamBean implements Serializable { 
  private String labelString; 
  private String featureString; 
public SMSSpamBean(String labelString, String featureString) { 
    super(); 
    this.labelString = labelString; 
    this.featureString = featureString; 
  } 
  public String getLabelString() { 
    return labelString; 
  } 
  public void setLabelString(String labelString) { 
    this.labelString = labelString; 
  } 
  public String getFeatureString() { 
    return featureString; 
  }  public void setFeatureString(String featureString) {    this.featureString = featureString; 
  }}  

```

创建 DF：

```scala
JavaRDD<SMSSpamBean> smsSpamBeanRDD =  rowRDD.map(new Function<Row, SMSSpamBean>() { 
      @Override 
    public SMSSpamBean call(Row r) throws Exception { 
        String[] split = r.getString(0).split("\t"); 
        return new SMSSpamBean(split[0],split[1]); 
      }});   
Dataset<Row> SMSSpamDF = spark.sqlContext().createDataFrame(smsSpamBeanRDD, SMSSpamBean.class); 
SMSSpamDF.show();   

```

以下输出如下：

![从 Java Bean 创建数据集](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00064.jpeg)

图 15：相应的特征和标签字符串

# 从字符串和类型化类创建数据集

如前所述，数据集是一组对象的类型化和不可变集合。数据集基本上映射到关系模式。使用数据集抽象，Spark 引入了一个新概念，称为编码器。编码器有助于实体转换，例如 JVM 对象与相应的表格表示之间的转换。您会发现这个 API 与 RDD 的转换非常相似，比如`map、mapToPair、flatMap`或`filter`。

我们将在下一节中展示使用数据集 API 的垃圾邮件过滤示例。它使用文本文件读取并返回数据集作为表格格式。然后执行类似 RDD 的映射转换，以添加额外的编码器参数（标签、令牌列）。在这里，我们使用了`SMSSpamTokenizedBean`类的 bean 编码器。

在本小节中，我们将展示如何从字符串和类型类`SMSSpamTokenizedBean`创建数据集。首先让我们创建 Spark 会话，如下所示：

```scala
static SparkSession spark = SparkSession.builder() 
      .appName("DatasetDemo") 
      .master("local[*]") 
      .config("spark.sql.warehouse.dir", "E:/Exp/") 
      .getOrCreate(); 

```

现在从`smm`过滤数据集创建一个新的 String 类型的数据集，即`Dataset<String>`，并显示结果如下：

```scala
Dataset<String> ds = spark.read().text("input/SMSSpamCollection.txt").as(org.apache.spark.sql.Encoders.STRING()); 
ds.show(); 

```

以下是前面代码的输出：

![从字符串和类型类创建的数据集](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00010.jpeg)

图 16：显示使用数据集进行垃圾邮件过滤的快照

现在让我们通过将我们之前创建的字符串数据集映射为`SMSSpamTokenizedBean`类型的第二个数据集，来创建第二个数据集，如下所示：

```scala
Dataset<SMSSpamTokenizedBean> dsSMSSpam = ds.map( 
new MapFunction<String, SMSSpamTokenizedBean>() { 
          @Override 
public SMSSpamTokenizedBean call(String value) throws Exception { 
      String[] split = value.split("\t"); 
      double label; 
      if(split[0].equalsIgnoreCase("spam")) 
          label = 1.0; 
      else 
          label=0.0; 
ArrayList<String> tokens = new ArrayList<>(); 
  for(String s:split) 
    tokens.add(s.trim());           
      return new SMSSpamTokenizedBean(label, tokens.toString()); 
         } 
}, org.apache.spark.sql.Encoders.bean(SMSSpamTokenizedBean.class)); 

```

现在让我们打印数据集及其模式，如下所示：

```scala
dsSMSSpam.show(); 
dsSMSSpam.printSchema(); 

```

以下输出为：

![从字符串和类型类创建的数据集](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00089.jpeg)

图 17：显示令牌和标签，下方是模式

现在，如果您想将此类型的数据集转换为 Row 类型，那么您可以使用`toDF()`方法，并且可以轻松地使用`createOrReplaceTempView()`方法创建新的`Dataset<Row>`的临时视图，如下所示：

```scala
Dataset<Row> df = dsSMSSpam.toDF(); 
df.createOrReplaceTempView("SMSSpamCollection");      

```

同样，您可能希望通过调用`show()`方法查看相同的数据集，如下所示：

```scala
df.show(); 

```

输出：

![从字符串和类型类创建的数据集](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00128.jpeg)

图 18：相应的标签和令牌。标签转换为双值

现在让我们探索类型类`SMSSpamTokenizedBean`。该类作为用于标记文本的 Java 标记化 bean 类。更具体地说，该类接受输入，然后设置标签，然后获取标签。其次，它还设置和获取用于垃圾邮件过滤的令牌。包括 setter 和方法，以下是该类：

```scala
public class SMSSpamTokenizedBean implements Serializable { 
private Double labelDouble; 
private String tokens;     
public SMSSpamTokenizedBean(Double labelDouble, String tokens) { 
  super(); 
  this.labelDouble = labelDouble; 
  this.tokens = tokens; 
  } 
  public Double getLabelDouble() { 
    return labelDouble; 
  } 
  public void setLabelDouble(Double labelDouble) { 
    this.labelDouble = labelDouble; 
  } 
  public String getTokens() { 
    return tokens; 
  } 
  public void setTokens(String tokens) { 
    this.tokens = tokens; 
  }} 

```

## RDD、DataFrame 和 Dataset 之间的比较

将数据集作为 Spark 的新数据结构带来一些目标。虽然 RDD API 非常灵活，但有时很难优化处理。另一方面，DataFrame API 很容易优化，但缺少 RDD 的一些好特性。因此，数据集的目标是允许用户轻松表达对象上的转换，并提供 Spark SQL 执行引擎的优势（性能和鲁棒性）。

数据集可以执行许多操作，如排序或洗牌，而无需对对象进行反序列化。为此，它需要一个显式的编码器，用于将对象序列化为二进制格式。它能够将给定对象（Bean）的模式映射到 Spark SQL 类型系统。另一方面，RDD 基于运行时反射的序列化，而改变数据集对象类型的操作也需要新类型的编码器。

# Spark 和数据科学家的工作流程

正如已经说明的，数据科学家的一个常见任务是选择数据、数据预处理（格式化、清理和抽样）和数据转换（缩放、分解和聚合）原始数据，以便将其传递到机器学习模型中构建模型。随着实验数据集的增加，传统的单节点数据库将无法处理这些类型的数据集，因此，您需要切换到像 Spark 这样的大数据处理计算。幸运的是，我们有 Spark 作为可扩展的分布式计算系统，可以处理您的数据集。

![Spark 和数据科学家的工作流程](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00090.jpeg)

图 19：数据科学家使用 Spark 的工作流程

现在让我们来到确切的点，作为一名数据科学家，首先你将不得不阅读以各种格式提供的数据集。然后阅读数据集将为你提供我们已经描述的 RDDs、DataFrames 和 Datasets 的概念。你可以将数据集缓存到主内存中；你可以从 DataFrame、SQL 或 Datasets 转换读取的数据集。最后，你将执行一个操作，将数据转储到磁盘、计算节点或集群。我们在这里描述的步骤基本上形成了一个工作流程，你将按照这个工作流程进行使用 Spark 进行基本数据处理，如*图 1*所示。

# 深入了解 Spark

在这一部分，我们将展示 Spark 的高级特性，包括使用共享变量（广播变量和累加器），并讨论它们的基本概念。然而，我们将在后面的章节中讨论数据分区。

## 共享变量

在编程上下文中，共享变量的概念并不新鲜。需要许多函数和方法并行使用的变量称为共享变量。Spark 有一些机制来使用或实现共享变量。在 Spark 中，传递给 Spark 操作的函数（如 map 或 reduce）在远程集群节点上执行。代码或函数在节点上作为变量的独立副本工作，结果的更新不会传播回驱动程序。然而，Spark 提供了两种常见用法模式的共享变量：广播变量和累加器。

### 广播变量

在 Spark API 中有许多类型和方法需要了解。然而，更多和更详细的讨论超出了本书的范围。

```scala
Broadcast<int[]> broadcastVariable=sc.broadcast(new int[] {2,3,4}); 
int[] values = broadcastVariable.value(); 
for(int i:values){ 
  System.out.println(i);} 

```

### 累加器

累加器是另一种共享变量，可以用于实现计数器（如 MapReduce 中）或求和。Spark 只支持累加器为数值类型。然而，你也可以使用现有技术为新的数据类型添加支持[1]。通过调用以下初始值为`val`的方法创建：

```scala
SparkContext. accumulator(val) 

```

以下代码显示了使用累加器将数组元素相加的用法：

```scala
Accumulator<Integer> accumulator = sc.accumulator(0); 
sc.parallelize(Arrays.asList(1, 5, 3, 4)) 
.foreach(x -> accumulator.add(x));   
System.out.println(accumulator.value()); 

```

Spark 编程指南：[`spark.apache.org/docs/latest/programming-guide.html`](http://spark.apache.org/docs/latest/programming-guide.html)。

### 提示

有兴趣的读者应该参考以下网页上关于 Spark 和相关材料的内容：

在本章中，我们使用了 RDDs、Dataset 和 DataFrame API 进行了基本的数据操作。我们还学习了如何通过这些 API 进行一些复杂的数据操作。我们试图专注于数据操作，以理解一个实际的机器学习问题——垃圾邮件过滤。除此之外，我们还展示了如何从不同的来源读取数据。分析和准备你的数据，以理解垃圾邮件过滤作为一个例子。

Spark RDD 操作：[`spark.apache.org/docs/latest/programming-guide.html#rdd-operations`](http://spark.apache.org/docs/latest/programming-guide.html#rdd-operations)。

Spark SQL 操作：[`spark.apache.org/docs/latest/sql-programming-guide.html`](http://spark.apache.org/docs/latest/sql-programming-guide.html)。

# 总结

广播变量提供了将只读变量持久化缓存在本地机器上的功能，而不是将副本发送到计算节点或驱动程序。以一种高效的方式将大型输入数据集的副本提供给 Spark 中的每个节点。它还减少了通信成本，因为 Spark 使用了高效的广播。广播变量可以通过调用`SparkContext.broadcast(v)`从变量`v`创建。以下代码显示了这一点：

然而，我们并没有开发任何完整的机器学习应用程序，因为我们的目标只是向您展示实验数据集上的基本数据操作。我们打算在第六章*构建可扩展的机器学习管道*中开发完整的 ML 应用程序。

创建预测模型应该使用哪些特征不仅是一个重要的问题，而且可能是一个需要深入了解问题领域才能回答的困难问题。可以自动选择数据中对某人正在处理的问题最有用或最相关的特征。考虑到这些问题，下一章将详细介绍特征工程，解释为什么要应用它以及一些特征工程的最佳实践。一些仍不清楚的主题将在下一章中更清晰。
