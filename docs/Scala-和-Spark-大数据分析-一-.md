# Scala 和 Spark 大数据分析（一）

> 原文：[`zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A`](https://zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

数据持续增长，加上对这些数据进行越来越复杂的决策的需求，正在创造巨大的障碍，阻止组织利用传统的分析方法及时获取洞察力。大数据领域与这些框架密切相关，其范围由这些框架能处理的内容来定义。无论您是在审查数百万访问者的点击流以优化在线广告位置，还是在筛选数十亿交易以识别欺诈迹象，对于从海量数据中自动获取洞察力的高级分析（如机器学习和图处理）的需求比以往任何时候都更加明显。

Apache Spark，作为大数据处理、分析和数据科学在所有学术界和行业中的事实标准，提供了机器学习和图处理库，使公司能够轻松应对复杂问题，利用高度可扩展和集群化的计算机的强大能力。Spark 的承诺是进一步推动使用 Scala 编写分布式程序感觉像为 Spark 编写常规程序。Spark 将在提高 ETL 管道性能和减轻一些痛苦方面做得很好，这些痛苦来自 MapReduce 程序员每天对 Hadoop 神明的绝望呼唤。

在本书中，我们使用 Spark 和 Scala 进行努力，将最先进的高级数据分析与机器学习、图处理、流处理和 SQL 引入 Spark，并将它们贡献给 MLlib、ML、SQL、GraphX 和其他库。

我们从 Scala 开始，然后转向 Spark 部分，最后，涵盖了一些关于使用 Spark 和 Scala 进行大数据分析的高级主题。在附录中，我们将看到如何扩展您的 Scala 知识，以用于 SparkR、PySpark、Apache Zeppelin 和内存中的 Alluxio。本书不是要从头到尾阅读的。跳到一个看起来像您要完成的任务或简单激起您兴趣的章节。

祝阅读愉快！

# 本书内容

第一章，*Scala 简介*，将教授使用基于 Scala 的 Spark API 进行大数据分析。Spark 本身是用 Scala 编写的，因此作为起点，我们将讨论 Scala 的简要介绍，例如其历史、目的以及如何在 Windows、Linux 和 Mac OS 上安装 Scala。之后，将简要讨论 Scala web 框架。然后，我们将对 Java 和 Scala 进行比较分析。最后，我们将深入 Scala 编程，开始使用 Scala。

第二章，*面向对象的 Scala*，说道面向对象编程（OOP）范式提供了全新的抽象层。简而言之，本章讨论了面向对象编程语言的一些最大优势：可发现性、模块化和可扩展性。特别是，我们将看到如何处理 Scala 中的变量；Scala 中的方法、类和对象；包和包对象；特征和特征线性化；以及 Java 互操作性。

第三章，*函数式编程概念*，展示了 Scala 中的函数式编程概念。更具体地，我们将学习几个主题，比如为什么 Scala 是数据科学家的武器库，为什么学习 Spark 范式很重要，纯函数和高阶函数（HOFs）。还将展示使用 HOFs 的实际用例。然后，我们将看到如何在 Scala 的标准库中处理高阶函数在集合之外的异常。最后，我们将看看函数式 Scala 如何影响对象的可变性。

第四章《集合 API》介绍了吸引大多数 Scala 用户的功能之一——集合 API。它非常强大和灵活，并且具有许多相关操作。我们还将演示 Scala 集合 API 的功能以及如何使用它来适应不同类型的数据并解决各种不同的问题。在本章中，我们将涵盖 Scala 集合 API、类型和层次结构、一些性能特征、Java 互操作性以及 Scala 隐式。

第五章《应对大数据 - Spark 加入派对》概述了数据分析和大数据；我们看到大数据带来的挑战，以及它们是如何通过分布式计算来处理的，以及函数式编程提出的方法。我们介绍了谷歌的 MapReduce、Apache Hadoop，最后是 Apache Spark，并看到它们是如何采纳这种方法和这些技术的。我们将探讨 Apache Spark 的演变：为什么首先创建了 Apache Spark 以及它如何为大数据分析和处理的挑战带来价值。

第六章《开始使用 Spark - REPL 和 RDDs》涵盖了 Spark 的工作原理；然后，我们介绍了 RDDs，这是 Apache Spark 背后的基本抽象，看到它们只是暴露类似 Scala 的 API 的分布式集合。我们将研究 Apache Spark 的部署选项，并在本地运行它作为 Spark shell。我们将学习 Apache Spark 的内部工作原理，RDD 是什么，RDD 的 DAG 和谱系，转换和操作。

第七章《特殊 RDD 操作》着重介绍了如何定制 RDD 以满足不同的需求，以及这些 RDD 提供了新的功能（和危险！）此外，我们还研究了 Spark 提供的其他有用对象，如广播变量和累加器。我们将学习聚合技术、洗牌。

第八章《引入一点结构 - SparkSQL》教您如何使用 Spark 分析结构化数据，作为 RDD 的高级抽象，以及 Spark SQL 的 API 如何使查询结构化数据变得简单而健壮。此外，我们介绍数据集，并查看数据集、数据框架和 RDD 之间的区别。我们还将学习使用数据框架 API 进行复杂数据分析的连接操作和窗口函数。

第九章《带我上流 - Spark Streaming》带您了解 Spark Streaming 以及我们如何利用它来使用 Spark API 处理数据流。此外，在本章中，读者将学习使用实际示例处理实时数据流的各种方法，以消费和处理来自 Twitter 的推文。我们将研究与 Apache Kafka 的集成以进行实时处理。我们还将研究结构化流，它可以为您的应用程序提供实时查询。

第十章《一切都相连 - GraphX》中，我们将学习许多现实世界的问题可以使用图来建模（和解决）。我们将以 Facebook 为例看图论，Apache Spark 的图处理库 GraphX，VertexRDD 和 EdgeRDDs，图操作符，aggregateMessages，TriangleCounting，Pregel API 以及 PageRank 算法等用例。

第十一章，“学习机器学习-Spark MLlib 和 ML”，本章的目的是提供统计机器学习的概念介绍。我们将重点介绍 Spark 的机器学习 API，称为 Spark MLlib 和 ML。然后我们将讨论如何使用决策树和随机森林算法解决分类任务，以及使用线性回归算法解决回归问题。我们还将展示在训练分类模型之前如何从使用独热编码和降维算法在特征提取中受益。在后面的部分，我们将逐步展示开发基于协同过滤的电影推荐系统的示例。

第十二章，“高级机器学习最佳实践”，提供了一些关于使用 Spark 进行机器学习的高级主题的理论和实践方面。我们将看到如何使用网格搜索、交叉验证和超参数调整来调整机器学习模型以获得最佳性能。在后面的部分，我们将介绍如何使用 ALS 开发可扩展的推荐系统，这是一个基于模型的推荐算法的示例。最后，将演示主题建模应用作为文本聚类技术。

第十三章，“我的名字是贝叶斯，朴素贝叶斯”，指出大数据中的机器学习是一个革命性的组合，对学术界和工业界的研究领域产生了巨大影响。大数据对机器学习、数据分析工具和算法提出了巨大挑战，以找到真正的价值。然而，基于这些庞大数据集进行未来预测从未容易。考虑到这一挑战，在本章中，我们将深入探讨机器学习，了解如何使用简单而强大的方法构建可扩展的分类模型，以及多项式分类、贝叶斯推断、朴素贝叶斯、决策树和朴素贝叶斯与决策树的比较分析等概念。

第十四章，“整理数据的时候到了-Spark MLlib 对数据进行聚类”，让您了解 Spark 在集群模式下的工作原理及其基础架构。在之前的章节中，我们看到了如何使用不同的 Spark API 开发实际应用程序。最后，我们将看到如何在集群上部署完整的 Spark 应用程序，无论是使用现有的 Hadoop 安装还是不使用。

第十五章，“使用 Spark ML 进行文本分析”，概述了使用 Spark ML 进行文本分析的广泛领域。文本分析是机器学习中的一个广泛领域，在许多用例中非常有用，例如情感分析、聊天机器人、电子邮件垃圾邮件检测、自然语言处理等。我们将学习如何使用 Spark 进行文本分析，重点关注使用包含 1 万个样本的 Twitter 数据集进行文本分类的用例。我们还将研究 LDA，这是一种从文档中生成主题的流行技术，而不需要了解实际文本内容，并将在 Twitter 数据上实现文本分类，以了解所有内容是如何结合在一起的。

第十六章，“Spark 调优”，深入挖掘 Apache Spark 内部，并表示虽然 Spark 在让我们感觉好像只是使用另一个 Scala 集合方面做得很好，但我们不应忘记 Spark 实际上是在分布式系统中运行。因此，在本章中，我们将介绍如何监视 Spark 作业、Spark 配置、Spark 应用程序开发中的常见错误以及一些优化技术。

第十七章，*去集群之旅-在集群上部署 Spark*，探讨了 Spark 在集群模式下的工作方式及其基础架构。我们将看到集群中的 Spark 架构，Spark 生态系统和集群管理，以及如何在独立、Mesos、Yarn 和 AWS 集群上部署 Spark。我们还将看到如何在基于云的 AWS 集群上部署您的应用程序。

第十八章，*测试和调试 Spark*，解释了在分布式环境中测试应用程序有多么困难；然后，我们将看到一些解决方法。我们将介绍如何在分布式环境中进行测试，以及测试和调试 Spark 应用程序。

第十九章，*PySpark 和 SparkR*，涵盖了使用 R 和 Python 编写 Spark 代码的另外两种流行 API，即 PySpark 和 SparkR。特别是，我们将介绍如何开始使用 PySpark 并与 PySpark 交互 DataFrame API 和 UDF，然后我们将使用 PySpark 进行一些数据分析。本章的第二部分涵盖了如何开始使用 SparkR。我们还将看到如何进行数据处理和操作，以及如何使用 SparkR 处理 RDD 和 DataFrames，最后，使用 SparkR 进行一些数据可视化。

附录 A，*使用 Alluxio 加速 Spark*，展示了如何使用 Alluxio 与 Spark 来提高处理速度。Alluxio 是一个开源的分布式内存存储系统，可用于提高跨平台的许多应用程序的速度，包括 Apache Spark。我们将探讨使用 Alluxio 的可能性以及 Alluxio 集成如何在运行 Spark 作业时提供更高的性能而无需每次都将数据缓存到内存中。

附录 B，*使用 Apache Zeppelin 进行交互式数据分析*，从数据科学的角度来看，交互式可视化数据分析也很重要。Apache Zeppelin 是一个基于 Web 的笔记本，用于具有多个后端和解释器的交互式和大规模数据分析。在本章中，我们将讨论如何使用 Apache Zeppelin 进行大规模数据分析，使用 Spark 作为后端的解释器。

# 本书所需的内容

所有示例都是在 Ubuntu Linux 64 位上使用 Python 版本 2.7 和 3.5 实现的，包括 TensorFlow 库版本 1.0.1。然而，在本书中，我们只展示了与 Python 2.7 兼容的源代码。与 Python 3.5+兼容的源代码可以从 Packt 存储库下载。您还需要以下 Python 模块（最好是最新版本）：

+   Spark 2.0.0（或更高）

+   Hadoop 2.7（或更高）

+   Java（JDK 和 JRE）1.7+/1.8+

+   Scala 2.11.x（或更高）

+   Python 2.7+/3.4+

+   R 3.1+和 RStudio 1.0.143（或更高）

+   Eclipse Mars，Oxygen 或 Luna（最新）

+   Maven Eclipse 插件（2.9 或更高）

+   Eclipse 的 Maven 编译器插件（2.3.2 或更高）

+   Eclipse 的 Maven 汇编插件（2.4.1 或更高）

**操作系统：**首选 Linux 发行版（包括 Debian，Ubuntu，Fedora，RHEL 和 CentOS），更具体地说，对于 Ubuntu，建议安装完整的 14.04（LTS）64 位（或更高版本），VMWare player 12 或 Virtual box。您可以在 Windows（XP/7/8/10）或 Mac OS X（10.4.7+）上运行 Spark 作业。

**硬件配置：**处理器 Core i3，Core i5（推荐）或 Core i7（以获得最佳结果）。然而，多核处理将提供更快的数据处理和可伸缩性。您至少需要 8-16 GB RAM（推荐）以独立模式运行，至少需要 32 GB RAM 以单个 VM 运行-并且对于集群来说需要更高。您还需要足够的存储空间来运行繁重的作业（取决于您处理的数据集大小），最好至少有 50 GB 的免费磁盘存储空间（用于独立的单词丢失和 SQL 仓库）。

# 这本书适合谁

任何希望通过利用 Spark 的力量来学习数据分析的人都会发现这本书非常有用。我们不假设您具有 Spark 或 Scala 的知识，尽管先前的编程经验（特别是使用其他 JVM 语言）将有助于更快地掌握这些概念。在过去几年中，Scala 的采用率一直在稳步上升，特别是在数据科学和分析领域。与 Scala 齐头并进的是 Apache Spark，它是用 Scala 编程的，并且在分析领域被广泛使用。本书将帮助您利用这两种工具的力量来理解大数据。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些这些样式的示例及其含义的解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“下一行代码读取链接并将其分配给`BeautifulSoup`函数。”

代码块设置如下：

```scala
package com.chapter11.SparkMachineLearning
import org.apache.spark.mllib.feature.StandardScalerModel
import org.apache.spark.mllib.linalg.{ Vector, Vectors }
import org.apache.spark.sql.{ DataFrame }
import org.apache.spark.sql.SparkSession

```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```scala
val spark = SparkSession
                 .builder
                 .master("local[*]")
                 .config("spark.sql.warehouse.dir", "E:/Exp/")
                 .config("spark.kryoserializer.buffer.max", "1024m")
                 .appName("OneVsRestExample")        
           .getOrCreate()

```

任何命令行输入或输出都以以下方式编写：

```scala
$./bin/spark-submit --class com.chapter11.RandomForestDemo \
--master spark://ip-172-31-21-153.us-west-2.compute:7077 \
--executor-memory 2G \
--total-executor-cores 2 \
file:///home/KMeans-0.0.1-SNAPSHOT.jar \
file:///home/mnist.bz2

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“单击“下一步”按钮将您移至下一个屏幕。”

警告或重要说明会以这种方式出现。

提示和技巧会以这种方式出现。


# 第一章：Scala 简介

“我是 Scala。我是一种可扩展的、函数式的、面向对象的编程语言。我可以随着你的成长而成长，你可以通过输入一行表达式来与我互动，并立即观察结果。”

- Scala 引用

在过去的几年里，Scala 在数据科学和分析领域特别是开发人员和从业者中得到了稳步增长和广泛采用。另一方面，使用 Scala 编写的 Apache Spark 是用于大规模数据处理的快速通用引擎。Spark 的成功归功于许多因素：易于使用的 API、清晰的编程模型、性能等等。因此，自然而然地，Spark 对 Scala 的支持更多：与 Python 或 Java 相比，Scala 有更多的 API 可用；尽管如此，新的 Scala API 在 Java、Python 和 R 之前就已经可用。

在我们开始使用 Spark 和 Scala（第二部分）编写数据分析程序之前，我们将首先详细了解 Scala 的函数式编程概念、面向对象的特性和 Scala 集合 API（第一部分）。作为起点，我们将在本章节中简要介绍 Scala。我们将涵盖 Scala 的一些基本方面，包括其历史和目的。然后我们将看到如何在不同平台上安装 Scala，包括 Windows、Linux 和 Mac OS，以便您可以在您喜爱的编辑器和 IDE 上编写数据分析程序。在本章的后面，我们将对 Java 和 Scala 进行比较分析。最后，我们将通过一些示例深入学习 Scala 编程。

简而言之，以下主题将被涵盖：

+   Scala 的历史和目的

+   平台和编辑器

+   安装和设置 Scala

+   Scala：可扩展的语言

+   面向 Java 程序员的 Scala

+   Scala 初学者

+   摘要

# Scala 的历史和目的

Scala 是一种通用编程语言，支持`函数式编程`和强大的`静态类型`系统。Scala 的源代码旨在编译成`Java`字节码，以便生成的可执行代码可以在`Java 虚拟机`（JVM）上运行。

Martin Odersky 于 2001 年在**洛桑联邦理工学院**（**EPFL**）开始设计 Scala。这是他在 Funnel 上的工作的延伸，Funnel 是一种使用函数式编程和 Petri 网的编程语言。首次公开发布是在 2004 年，但只支持 Java 平台。随后，在 2004 年 6 月，.NET 框架也开始支持。

Scala 因不仅支持面向对象的编程范式，而且还包含了函数式编程概念，因此变得非常受欢迎并得到了广泛的采用。此外，尽管 Scala 的符号操作符很难阅读，与 Java 相比，大多数 Scala 代码相对简洁易读——例如，Java 太啰嗦了。

与其他编程语言一样，Scala 是为特定目的而提出和开发的。现在，问题是，为什么创建了 Scala，它解决了什么问题？为了回答这些问题，Odersky 在他的博客中说：

“Scala 的工作源于开发组件软件的更好语言支持的研究工作。我们希望通过 Scala 实验验证两个假设。首先，我们假设组件软件的编程语言需要在描述小部分和大部分时使用相同的概念。因此，我们集中于抽象、组合和分解的机制，而不是添加大量原语，这些原语在某个规模级别上可能对组件有用，但在其他级别上则不是。其次，我们假设组件的可扩展支持可以通过统一和泛化面向对象和函数式编程的编程语言来提供。对于 Scala 这样的静态类型语言，这两种范式到目前为止基本上是分开的。”

然而，Scala 也提供了模式匹配和高阶函数等功能，不是为了填补函数式编程和面向对象编程之间的差距，而是因为它们是函数式编程的典型特征。因此，它具有一些非常强大的模式匹配功能，还有一个基于 actor 的并发框架。此外，它还支持一阶和高阶函数。总之，"Scala"这个名字是可伸缩语言的混成词，意味着它被设计成能够满足用户需求的语言。

# 平台和编辑器

Scala 在**Java 虚拟机**（**JVM**）上运行，这使得 Scala 对于希望在代码中添加函数式编程风格的 Java 程序员来说是一个不错的选择。在编辑器方面有很多选择。最好花一些时间对可用的编辑器进行比较研究，因为熟悉 IDE 是成功编程经验的关键因素之一。以下是一些可供选择的选项：

+   Scala IDE

+   Eclipse 的 Scala 插件

+   IntelliJ IDEA

+   Emacs

+   VIM

Scala 在 Eclipse 上的编程支持使用了许多 beta 插件。Eclipse 提供了一些令人兴奋的功能，如本地、远程和高级调试功能，以及用于 Scala 的语义突出显示和代码补全。您可以使用 Eclipse 同样轻松地进行 Java 和 Scala 应用程序开发。但是，我还建议 Scala IDE（[`scala-ide.org/`](http://scala-ide.org/)）- 这是一个基于 Eclipse 的全功能 Scala 编辑器，并且定制了一系列有趣的功能（例如 Scala 工作表、ScalaTest 支持、Scala 重构等）；

在我看来，第二个最佳选择是 IntelliJ IDEA。第一个版本于 2001 年发布，是第一个具有高级代码导航和重构功能的 Java IDE。根据 InfoWorld 报告（请参阅[`www.infoworld.com/article/2683534/development-environments/infoworld-review--top-java-programming-tools.html`](http://www.infoworld.com/article/2683534/development-environments/infoworld-review--top-java-programming-tools.html)），在四个顶级 Java 编程 IDE（即 Eclipse、IntelliJ IDEA、NetBeans 和 JDeveloper）中，IntelliJ 获得了最高的测试中心评分 8.5 分（满分 10 分）。

相应的评分如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00172.jpeg)**图 1：** Scala/Java 开发人员最佳 IDE

从上面的图中，您可能对使用其他 IDE，如 NetBeans 和 JDeveloper 也感兴趣。最终，选择是开发人员之间永恒的辩论，这意味着最终选择取决于您。

# 安装和设置 Scala

正如我们已经提到的，Scala 使用 JVM，因此请确保您的机器上已安装 Java。如果没有，请参考下一小节，其中介绍了如何在 Ubuntu 上安装 Java。在本节中，首先我们将向您展示如何在 Ubuntu 上安装 Java 8。然后，我们将看到如何在 Windows、Mac OS 和 Linux 上安装 Scala。

# 安装 Java

为简单起见，我们将展示如何在 Ubuntu 14.04 LTS 64 位机器上安装 Java 8。但是对于 Windows 和 Mac OS，最好花一些时间在 Google 上了解一下。对于 Windows 用户的最小线索：请参考此链接获取详细信息[`java.com/en/download/help/windows_manual_download.xml`](https://java.com/en/download/help/windows_manual_download.xml)。

现在，让我们看看如何通过逐步命令和说明在 Ubuntu 上安装 Java 8。首先，检查 Java 是否已安装：

```scala
$ java -version 

```

如果返回`程序 java 在以下包中找不到`，则说明 Java 尚未安装。然后您可以执行以下命令来摆脱这个问题：

```scala
 $ sudo apt-get install default-jre 

```

这将安装**Java Runtime Environment**（**JRE**）。但是，如果您可能需要**Java Development Kit**（**JDK**），通常需要在 Apache Ant、Apache Maven、Eclipse 和 IntelliJ IDEA 上编译 Java 应用程序。

Oracle JDK 是官方 JDK，但是 Oracle 不再将其作为 Ubuntu 的默认安装提供。您仍然可以使用 apt-get 安装它。要安装任何版本，首先执行以下命令：

```scala
$ sudo apt-get install python-software-properties
$ sudo apt-get update
$ sudo add-apt-repository ppa:webupd8team/java
$ sudo apt-get update 

```

然后，根据您要安装的版本，执行以下命令之一：

```scala
$ sudo apt-get install oracle-java8-installer

```

安装完成后，不要忘记设置 Java 主目录环境变量。只需应用以下命令（为简单起见，我们假设 Java 安装在`/usr/lib/jvm/java-8-oracle`）：

```scala
$ echo "export JAVA_HOME=/usr/lib/jvm/java-8-oracle" >> ~/.bashrc  
$ echo "export PATH=$PATH:$JAVA_HOME/bin" >> ~/.bashrc
$ source ~/.bashrc 

```

现在，让我们看一下`Java_HOME`如下：

```scala
$ echo $JAVA_HOME

```

您应该在终端上观察到以下结果：

```scala
 /usr/lib/jvm/java-8-oracle

```

现在，让我们通过输入以下命令来检查 Java 是否已成功安装（您可能会看到最新版本！）：

```scala
$ java -version

```

您将获得以下输出：

```scala
java version "1.8.0_121"
Java(TM) SE Runtime Environment (build 1.8.0_121-b13)
Java HotSpot(TM) 64-Bit Server VM (build 25.121-b13, mixed mode)

```

太棒了！现在您的机器上已经安装了 Java，因此一旦安装了 Scala，您就可以准备好编写 Scala 代码了。让我们在接下来的几个小节中做这个。

# Windows

本部分将重点介绍在 Windows 7 上安装 Scala 的 PC，但最终，您当前运行的 Windows 版本将不重要：

1.  第一步是从官方网站下载 Scala 的压缩文件。您可以在[`www.Scala-lang.org/download/all.html`](https://www.scala-lang.org/download/all.html)找到它。在此页面的其他资源部分，您将找到一个存档文件列表，您可以从中安装 Scala。我们将选择下载 Scala 2.11.8 的压缩文件，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00174.gif)**图 2：** Windows 的 Scala 安装程序

1.  下载完成后，解压文件并将其放在您喜欢的文件夹中。您还可以将文件重命名为 Scala 以提高导航灵活性。最后，需要为 Scala 创建一个`PATH`变量，以便在您的操作系统中全局看到。为此，请转到计算机 | 属性，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00176.jpeg)**图 3：** Windows 上的环境变量选项卡

1.  从中选择环境变量，并获取 Scala 的`bin`文件夹的位置；然后，将其附加到`PATH`环境变量。应用更改，然后按 OK，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00178.jpeg)**图 4：** 为 Scala 添加环境变量

1.  现在，您可以开始进行 Windows 安装。打开 CMD，只需输入`scala`。如果安装过程成功，您应该会看到类似以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00182.jpeg)**图 5：** 从“Scala shell”访问 Scala

# Mac OS

现在是时候在您的 Mac 上安装 Scala 了。有很多种方法可以在 Mac 上安装 Scala，在这里，我们将提到其中两种：

# 使用 Homebrew 安装程序

1.  首先，检查您的系统是否已安装 Xcode，因为这一步骤需要。您可以免费从 Apple App Store 安装它。

1.  接下来，您需要通过在终端中运行以下命令来安装`Homebrew`：

```scala
$ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

```

注意：Homebrew 的前面的命令会不时更改。如果命令似乎无效，请查看 Homebrew 网站获取最新的命令：[`brew.sh/`](http://brew.sh/)。

1.  现在，您已经准备好通过在终端中键入此命令`brew install scala`来安装 Scala。

1.  最后，您只需在终端中输入 Scala，就可以开始了（第二行），您将在终端上看到以下内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00226.jpeg)**图 6：** macOS 上的 Scala shell

# 手动安装

在手动安装 Scala 之前，选择您喜欢的 Scala 版本，并从[`www.scala-lang.org/download/`](http://www.scala-lang.org/download/)下载相应版本的`.tgz`文件`Scala-verion.tgz`。下载您喜欢的 Scala 版本后，按以下步骤提取：

```scala
$ tar xvf scala-2.11.8.tgz

```

然后，将其移动到`/usr/local/share`，如下所示：

```scala
$ sudo mv scala-2.11.8 /usr/local/share

```

现在，要使安装永久生效，请执行以下命令：

```scala
$ echo "export SCALA_HOME=/usr/local/share/scala-2.11.8" >> ~/.bash_profile
$ echo "export PATH=$PATH: $SCALA_HOME/bin" >> ~/.bash_profile 

```

就是这样。现在，让我们看看在下一小节中如何在 Ubuntu 等 Linux 发行版上完成这个过程。

# Linux

在本小节中，我们将向您展示如何在 Linux 的 Ubuntu 发行版上安装 Scala。在开始之前，让我们检查一下确保 Scala 已经正确安装。使用以下命令检查这一点非常简单：

```scala
$ scala -version

```

如果 Scala 已经安装在您的系统上，您应该在终端上收到以下消息：

```scala
Scala code runner version 2.11.8 -- Copyright 2002-2016, LAMP/EPFL

```

请注意，在编写本安装过程时，我们使用了 Scala 的最新版本，即 2.11.8。如果您的系统上没有安装 Scala，请确保在进行下一步之前安装它。您可以从 Scala 网站[`www.scala-lang.org/download/`](http://www.scala-lang.org/download/)下载最新版本的 Scala（更清晰的视图，请参考*图 2*）。为了方便起见，让我们下载 Scala 2.11.8，如下所示：

```scala
$ cd Downloads/
$ wget https://downloads.lightbend.com/scala/2.11.8/scala-2.11.8.tgz

```

下载完成后，您应该在下载文件夹中找到 Scala 的 tar 文件。

用户应该首先使用以下命令进入`Download`目录：`$ cd /Downloads/`。请注意，下载文件夹的名称可能会根据系统选择的语言而变化。

要从其位置提取 Scala 的`tar`文件或更多，请输入以下命令。使用这个命令，Scala 的 tar 文件可以从终端中提取：

```scala
$ tar -xvzf scala-2.11.8.tgz

```

现在，通过以下命令或手动将 Scala 分发到用户的视角（例如，`/usr/local/scala/share`）：

```scala
 $ sudo mv scala-2.11.8 /usr/local/share/

```

进入您的主目录问题使用以下命令：

```scala
$ cd ~

```

然后，使用以下命令设置 Scala 主目录：

```scala
$ echo "export SCALA_HOME=/usr/local/share/scala-2.11.8" >> ~/.bashrc 
$ echo "export PATH=$PATH:$SCALA_HOME/bin" >> ~/.bashrc

```

然后，使用以下命令使更改在会话中永久生效：

```scala
$ source ~/.bashrc

```

安装完成后，最好使用以下命令进行验证：

```scala
$ scala -version

```

如果 Scala 已经成功配置在您的系统上，您应该在终端上收到以下消息：

```scala
Scala code runner version 2.11.8 -- Copyright 2002-2016, LAMP/EPFL

```

干得好！现在，让我们通过在终端上输入`;scala`命令来进入 Scala shell，如下图所示：

**![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00033.jpeg)****图 7：** Linux 上的 Scala shell（Ubuntu 发行版）

最后，您也可以使用 apt-get 命令安装 Scala，如下所示：

```scala
$ sudo apt-get install scala

```

这个命令将下载 Scala 的最新版本（即 2.12.x）。然而，Spark 目前还不支持 Scala 2.12（至少在我们写这一章节时是这样）。因此，我们建议使用前面描述的手动安装。

# Scala：可伸缩语言

Scala 的名称来自于可伸缩语言，因为 Scala 的概念很好地适用于大型程序。其他语言中的一些程序可能需要编写数十行代码，但在 Scala 中，您将获得以简洁而有效的方式表达编程的一般模式和概念的能力。在本节中，我们将描述 Odersky 为我们创建的 Scala 的一些令人兴奋的特性：

# Scala 是面向对象的

Scala 是面向对象语言的一个很好的例子。要为您的对象定义类型或行为，您需要使用类和特征的概念，这将在下一章节中进行解释。Scala 不支持直接的多重继承，但要实现这种结构，您需要使用 Scala 的**子类化**和**基于混合的组合**。这将在后面的章节中讨论。

# Scala 是功能性的

函数式编程将函数视为一等公民。在 Scala 中，通过语法糖和扩展特性（如*Function2*）来实现这一点，但这就是 Scala 中实现函数式编程的方式。此外，Scala 定义了一种简单易行的方法来定义**匿名** **函数**（没有名称的函数）。它还支持高阶函数，并允许嵌套函数**。**这些概念的语法将在接下来的章节中详细解释。

此外，它还可以帮助您以不可变的方式编码，通过这种方式，您可以轻松地将其应用于同步和并发的并行处理。

# Scala 是静态类型的

与 Pascal、Rust 等其他静态类型语言不同，Scala 不要求您提供冗余的类型信息。在大多数情况下，您不必指定类型。最重要的是，您甚至不需要再次重复它们。

如果在编译时知道变量的类型，则编程语言被称为静态类型：这也意味着作为程序员，您必须指定每个变量的类型。例如，Scala、Java、C、OCaml、Haskell、C++等。另一方面，Perl、Ruby、Python 等是动态类型语言，其中类型与变量或字段无关，而与运行时值有关。

Scala 的静态类型特性确保编译器完成了所有类型的检查。Scala 这一极其强大的特性帮助您在执行之前找到/捕获大多数微不足道的错误和错误。

# Scala 在 JVM 上运行

就像 Java 一样，Scala 也被编译成字节码，这可以很容易地由 JVM 执行。这意味着 Scala 和 Java 的运行时平台是相同的，因为两者都生成字节码作为编译输出。因此，您可以轻松地从 Java 切换到 Scala，您也可以轻松地集成两者，甚至在 Android 应用程序中使用 Scala 添加功能风格。

请注意，虽然在 Scala 程序中使用 Java 代码非常容易，但相反的情况非常困难，主要是因为 Scala 的语法糖。

与`javac`命令一样，它将 Java 代码编译成字节码，Scala 也有`scalas`命令，它将 Scala 代码编译成字节码。

# Scala 可以执行 Java 代码

如前所述，Scala 也可以用于执行您的 Java 代码。不仅安装您的 Java 代码；它还使您能够在 Scala 环境中使用 Java SDK 中的所有可用类，甚至您自己预定义的类、项目和包。

# Scala 可以进行并发和同步处理

其他语言中的一些程序可能需要数十行代码，但在 Scala 中，您将获得以简洁有效的方式表达编程的一般模式和概念的能力。此外，它还可以帮助您以不可变的方式编码，通过这种方式，您可以轻松地将其应用于同步和并发的并行处理。

# Java 程序员的 Scala

Scala 具有一组与 Java 完全不同的特性。在本节中，我们将讨论其中一些特性。对于那些来自 Java 背景或至少熟悉基本 Java 语法和语义的人来说，本节将是有帮助的。

# 所有类型都是对象

如前所述，Scala 中的每个值看起来都像一个对象。这意味着一切看起来都像对象，但其中一些实际上并不是对象，您将在接下来的章节中看到这一解释（例如，在 Scala 中，字符串会被隐式转换为字符集合，但在 Java 中不会！）

# 类型推断

如果您不熟悉这个术语，那就是在编译时推断类型。等等，这不就是动态类型的意思吗？嗯，不是。请注意，我说的是类型的推断；这与动态类型语言所做的事情完全不同，另一件事是，它是在编译时而不是运行时完成的。许多语言都内置了这个功能，但实现方式各不相同。这可能在开始时会让人困惑，但通过代码示例将会更加清晰。让我们进入 Scala REPL 进行一些实验。

# 在 Java 中，您只能在代码文件的顶部导入包，就在包语句之后。在 Scala 中情况不同；您几乎可以在源文件的任何地方编写导入语句（例如，甚至可以在类或方法内部编写导入语句）。您只需要注意您的导入语句的作用域，因为它继承了类的成员或方法内部局部变量的作用域。在 Scala 中，`_`（下划线）用于通配符导入，类似于 Java 中您将使用的`*`（星号）：Scala REPL

Scala REPL 是一个强大的功能，使得在 Scala shell 上编写 Scala 代码更加简单和简洁。**REPL**代表**读取-评估-打印-循环**，也称为**交互式解释器**。这意味着它是一个用于：

1.  ;读取您输入的表达式。

1.  使用 Scala 编译器评估第 1 步中的表达式。

1.  打印出第 2 步评估的结果。

1.  等待（循环）您输入更多表达式。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00211.jpeg)**图 8：** Scala REPL 示例 1

从图中可以看出，这并没有什么神奇之处，变量在编译时会自动推断出最适合的类型。如果您仔细观察，当我尝试声明时：

```scala
 i:Int = "hello"

```

然后，Scala shell 会抛出一个错误，显示如下：

```scala
<console>:11: error: type mismatch;
  found   : String("hello")
  required: Int
        val i:Int = "hello"
                    ^

```

根据 Odersky 的说法，“将字符映射到 RichString 上的字符映射应该再次产生一个 RichString，如下与 Scala REP 的交互”。可以使用以下代码来证明前述声明：

```scala
scala> "abc" map (x => (x + 1).toChar) 
res0: String = bcd

```

然而，如果有人将`Char`的方法应用于`Int`到`String`，那会发生什么？在这种情况下，Scala 会将它们转换为整数向量，也称为 Scala 集合的不可变特性，如*图 9*所示。我们将在第四章中详细介绍 Scala 集合 API。

```scala
"abc" map (x => (x + 1)) 
res1: scala.collection.immutable.IndexedSeq[Int] = Vector(98, 99, 100)

```

对象的静态方法和实例方法也都可用。例如，如果您将`x`声明为字符串`hello`，然后尝试访问对象`x`的静态和实例方法，它们是可用的。在 Scala shell 中，键入`x`，然后键入`.`和`<tab>`，然后您将找到可用的方法：

```scala
scala> val x = "hello"
x: java.lang.String = hello
scala> x.re<tab>
reduce             reduceRight         replaceAll            reverse
reduceLeft         reduceRightOption   replaceAllLiterally   reverseIterator
reduceLeftOption   regionMatches       replaceFirst          reverseMap
reduceOption       replace             repr
scala> 

```

由于这一切都是通过反射动态完成的，即使您刚刚定义了匿名类，它们也同样可以访问：

```scala
scala> val x = new AnyRef{def helloWord = "Hello, world!"}
x: AnyRef{def helloWord: String} = $anon$1@58065f0c
 scala> x.helloWord
 def helloWord: String
 scala> x.helloWord
 warning: there was one feature warning; re-run with -feature for details
 res0: String = Hello, world!

```

前两个示例可以在 Scala shell 上显示如下：

嵌套函数

“原来 map 根据传递的函数参数的结果类型产生不同的类型！”

- Odersky

# ;

为什么您需要在编程语言中支持嵌套函数？大多数情况下，我们希望保持我们的方法只有几行，并避免过大的函数。在 Java 中，这个问题的典型解决方案是在类级别上定义所有这些小函数，但是任何其他方法都可以轻松地引用和访问它们，即使它们是辅助方法。在 Scala 中情况不同，您可以在彼此内部定义函数，从而防止任何外部访问这些函数：

```scala
def sum(vector: List[Int]): Int = {
  // Nested helper method (won't be accessed from outside this function
  def helper(acc: Int, remaining: List[Int]): Int = remaining match {
    case Nil => acc
    case _   => helper(acc + remaining.head, remaining.tail)
  }
  // Call the nested method
  helper(0, vector)
}

```

我们不希望您理解这些代码片段，它们展示了 Scala 和 Java 之间的区别。

# 导入语句

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00232.gif)**图 9：** Scala REPL 示例 2

```scala
// Import everything from the package math 
import math._

```

您还可以使用这些`{ }`来指示从同一父包中导入一组导入，只需一行代码。在 Java 中，您需要使用多行代码来实现这一点：

```scala
// Import math.sin and math.cos
import math.{sin, cos}

```

与 Java 不同，Scala 没有静态导入的概念。换句话说，静态的概念在 Scala 中不存在。然而，作为开发人员，显然，您可以使用常规导入语句导入一个对象的一个成员或多个成员。前面的例子已经展示了这一点，我们从名为 math 的包对象中导入了 sin 和 cos 方法。为了演示一个例子，前面的；代码片段可以从 Java 程序员的角度定义如下：

```scala
import static java.lang.Math.sin;
import static java.lang.Math.cos;

```

Scala 的另一个美妙之处在于，在 Scala 中，您还可以重命名导入的包。或者，您可以重命名导入的包以避免与具有相似成员的包发生类型冲突。以下语句在 Scala 中是有效的：

```scala
// Import Scala.collection.mutable.Map as MutableMap 
import Scala.collection.mutable.{Map => MutableMap}

```

最后，您可能希望排除包的成员以避免冲突或其他目的。为此，您可以使用通配符来实现：

```scala
// Import everything from math, but hide cos 
import math.{cos => _, _}

```

# 运算符作为方法

值得一提的是，Scala 不支持运算符重载。您可能会认为 Scala 根本没有运算符。

调用只有一个参数的方法的另一种语法是使用中缀语法。中缀语法为您提供了一种味道，就像您在 C++中进行运算符重载一样。例如：

```scala
val x = 45
val y = 75

```

在下面的情况中，`+`；表示类`Int`中的一个方法。以下；代码是一种非常规的方法调用语法：

```scala
val add1 = x.+(y)

```

更正式地，可以使用中缀语法来完成相同的操作，如下所示：

```scala
val add2 = x + y

```

此外，您可以利用中缀语法。但是，该方法只有一个参数，如下所示：

```scala
val my_result = List(3, 6, 15, 34, 76) contains 5

```

在使用中缀语法时有一个特殊情况。也就是说，如果方法名以`:`（冒号）结尾，那么调用将是右结合的。这意味着该方法在右参数上调用，左侧的表达式作为参数，而不是相反。例如，在 Scala 中以下是有效的：

```scala
val my_list = List(3, 6, 15, 34, 76)

```

前面的；语句表示：`my_list.+:(5)`而不是`5.+:(my_list)`，更正式地说：；

```scala
val my_result = 5 +: my_list

```

现在，让我们在 Scala REPL 上看一下前面的例子：

```scala
scala> val my_list = 5 +: List(3, 6, 15, 34, 76)
 my_list: List[Int] = List(5, 3, 6, 15, 34, 76)
scala> val my_result2 = 5+:my_list
 my_result2: List[Int] = List(5, 5, 3, 6, 15, 34, 76)
scala> println(my_result2)
 List(5, 5, 3, 6, 15, 34, 76)
scala>

```

除了上述之外，这里的运算符只是方法，因此它们可以像方法一样简单地被重写。

# 方法和参数列表

在 Scala 中，一个方法可以有多个参数列表，甚至根本没有参数列表。另一方面，在 Java 中，一个方法总是有一个参数列表，带有零个或多个参数。例如，在 Scala 中，以下是有效的方法定义（以`currie notation`编写），其中一个方法有两个参数列表：

```scala
def sum(x: Int)(y: Int) = x + y     

```

前面的；方法不能被写成：

```scala
def sum(x: Int, y: Int) = x + y

```

一个方法，比如；`sum2`，可以根本没有参数列表，如下所示：

```scala
def sum2 = sum(2) _

```

现在，您可以调用方法`add2`，它返回一个带有一个参数的函数。然后，它使用参数`5`调用该函数，如下所示：

```scala
val result = add2(5)

```

# 方法内部的方法

有时，您可能希望通过避免过长和复杂的方法使您的应用程序、代码模块化。Scala 为您提供了这种便利，以避免您的方法变得过大，以便将它们拆分成几个较小的方法。

另一方面，Java 只允许您在类级别定义方法。例如，假设您有以下方法定义：

```scala
def main_method(xs: List[Int]): Int = {
  // This is the nested helper/auxiliary method
  def auxiliary_method(accu: Int, rest: List[Int]): Int = rest match {
    case Nil => accu
    case _   => auxiliary_method(accu + rest.head, rest.tail)
  }
}

```

现在，您可以按以下方式调用嵌套的辅助/辅助方法：

```scala
auxiliary_method(0, xs)

```

考虑到上述内容，以下是有效的完整代码段：

```scala
def main_method(xs: List[Int]): Int = {
  // This is the nested helper/auxiliary method
  def auxiliary_method(accu: Int, rest: List[Int]): Int = rest match {
    case Nil => accu
    case _   => auxiliary_method(accu + rest.head, rest.tail)
  }
   auxiliary_method(0, xs)
}

```

# Scala 中的构造函数

关于 Scala 的一个令人惊讶的事情是，Scala 类的主体本身就是一个构造函数。然而，Scala 确实这样做；事实上，以一种更明确的方式。之后，该类的一个新实例被创建并执行。此外，您可以在类声明行中指定构造函数的参数。

因此，构造函数参数可以从该类中定义的所有方法中访问。例如，以下类和构造函数定义在 Scala 中是有效的：

```scala
class Hello(name: String) {
  // Statement executed as part of the constructor
  println("New instance with name: " + name)
  // Method which accesses the constructor argument
  def sayHello = println("Hello, " + name + "!")
}

```

等效的 Java 类如下所示：

```scala
public class Hello {
  private final String name;
  public Hello(String name) {
    System.out.println("New instance with name: " + name);
    this.name = name;
  }
  public void sayHello() {
    System.out.println("Hello, " + name + "!");
  }
}

```

# 对象而不是静态方法

如前所述，Scala 中不存在静态。你不能进行静态导入，也不能向类添加静态方法。在 Scala 中，当你在同一源文件中以相同的名称定义一个对象和类时，那么该对象被称为该类的伴生对象。在类的伴生对象中定义的函数就像 Java 类中的静态方法：

```scala
class HelloCity(CityName: String) {
  def sayHelloToCity = println("Hello, " + CityName + "!") 
}

```

这是你可以为类 hello 定义一个伴生对象的方法：

```scala
object HelloCity { 
  // Factory method 
  def apply(CityName: String) = new Hello(CityName) 
}

```

等效的 Java 类如下所示：

```scala
public class HelloCity { 
  private final String CityName; 
  public HelloCity(String CityName) { 
    this.CityName = CityName; 
  }
  public void sayHello() {
    System.out.println("Hello, " + CityName + "!"); 
  }
  public static HelloCity apply(String CityName) { 
    return new Hello(CityName); 
  } 
}

```

所以，这个简单的类中有很多冗长的内容，不是吗？Scala 中的 apply 方法被以一种不同的方式处理，因此你可以找到一种特殊的快捷语法来调用它。这是调用方法的熟悉方式：

```scala
val hello1 = Hello.apply("Dublin")

```

以下是等效于之前的快捷语法：

```scala
 val hello2 = Hello("Dublin")

```

请注意，这仅在你的代码中使用了 apply 方法时才有效，因为 Scala 以不同的方式处理被命名为 apply 的方法。

# 特征

Scala 为你提供了一个很好的功能，以扩展和丰富你的类的行为。这些特征类似于接口，你可以在其中定义函数原型或签名。因此，你可以从不同的特征中获得功能的混合，并丰富你的类的行为。那么，Scala 中的特征有什么好处呢？它们使得从这些特征组合类成为可能，特征是构建块。和往常一样，让我们通过一个例子来看看。这是在 Java 中设置传统日志记录例程的方法：

请注意，尽管你可以混入任意数量的特征，但是和 Java 一样，Scala 不支持多重继承。然而，在 Java 和 Scala 中，子类只能扩展一个父类。例如，在 Java 中：

```scala
class SomeClass {
  //First, to have to log for a class, you must initialize it
  final static Logger log = LoggerFactory.getLogger(this.getClass());
  ...
  //For logging to be efficient, you must always check, if logging level for current message is enabled                
  //BAD, you will waste execution time if the log level is an error, fatal, etc.
  log.debug("Some debug message");
  ...
  //GOOD, it saves execution time for something more useful
  if (log.isDebugEnabled()) { log.debug("Some debug message"); }
  //BUT looks clunky, and it's tiresome to write this construct every time you want to log something.
}

```

有关更详细的讨论，请参阅此 URL [`stackoverflow.com/questions/963492/in-log4j-does-checking-isdebugenabled-before-logging-improve-performance/963681#963681`](https://stackoverflow.com/questions/963492/in-log4j-does-checking-isdebugenabled-before-logging-improve-performance/963681#963681)。

然而，特征是不同的。总是检查日志级别是否启用非常繁琐。如果你能够编写这个例程并在任何类中立即重用它，那就太好了。Scala 中的特征使这一切成为可能。例如：

```scala
trait Logging {
  lazy val log = LoggerFactory.getLogger(this.getClass.getName)     
  //Let's start with info level...
  ...
  //Debug level here...
  def debug() {
    if (log.isDebugEnabled) log.info(s"${msg}")
  }
  def debug(msg: => Any, throwable: => Throwable) {
    if (log.isDebugEnabled) log.info(s"${msg}", throwable)
  }
  ...
  //Repeat it for all log levels you want to use
}

```

如果你看前面的代码，你会看到一个以`s`开头的字符串的使用示例。这种方式，Scala 提供了从数据创建字符串的机制，称为**字符串插值**。

字符串插值允许你直接在处理的字符串文字中嵌入变量引用。例如：

`scala> val name = "John Breslin"`

`scala> println(s"Hello, $name") ; // Hello, John Breslin`。

现在，我们可以以更传统的方式获得一个高效的日志记录例程作为可重用的代码块。要为任何类启用日志记录，我们只需混入我们的`Logging`特征！太棒了！现在，这就是为你的类添加日志记录功能所需的全部内容：

```scala
class SomeClass extends Logging {
  ...
  //With logging trait, no need for declaring a logger manually for every class
  //And now, your logging routine is either efficient and doesn't litter the code!

  log.debug("Some debug message")
  ...
}

```

甚至可以混合多个特征。例如，对于前面的特征（即`Logging`），你可以按以下顺序不断扩展：

```scala
trait Logging  {
  override def toString = "Logging "
}
class A extends Logging  {
  override def toString = "A->" + super.toString
}
trait B extends Logging  {
  override def toString = "B->" + super.toString
}
trait C extends Logging  {
  override def toString = "C->" + super.toString
}
class D extends A with B with C {
  override def toString = "D->" + super.toString
}

```

然而，需要注意的是，Scala 类可以一次扩展多个特征，但 JVM 类只能扩展一个父类。

现在，要调用上述特征和类，可以在 Scala REPL 中使用`new D()`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00220.gif)**图 10**：混合多个特征

到目前为止，本章一切顺利。现在，让我们转到一个新的部分，讨论一些初学者想要进入 Scala 编程领域的主题。

# Scala 初学者

在这一部分，你会发现我们假设你对任何之前的编程语言有基本的了解。如果 Scala 是你进入编程世界的第一步，那么你会发现有很多在线材料甚至课程可以为初学者解释 Scala。正如前面提到的，有很多教程、视频和课程。

在 Coursera 上有一个包含这门课程的整个专业课程：[`www.coursera.org/specializations/scala`](https://www.coursera.org/specializations/scala)。由 Scala 的创始人 Martin Odersky 教授，这个在线课程以一种相当学术的方式教授函数式编程的基础知识。通过解决编程作业，你将学到很多关于 Scala 的知识。此外，这个专业课程还包括一个关于 Apache Spark 的课程。此外，Kojo ([`www.kogics.net/sf:kojo`](http://www.kogics.net/sf:kojo))是一个使用 Scala 编程来探索和玩耍数学、艺术、音乐、动画和游戏的交互式学习环境。

# 你的第一行代码

作为第一个例子，我们将使用非常常见的`Hello, world!`程序来向你展示如何在不太了解它的情况下使用 Scala 及其工具。让我们打开你喜欢的编辑器（这个例子在 Windows 7 上运行，但在 Ubuntu 或 macOS 上也可以类似地运行），比如 Notepad++，并输入以下代码：

```scala
object HelloWorld {
  def main(args: Array[String]){ 
    println("Hello, world!")  
  } 
}

```

现在，保存代码为一个名字，比如`HelloWorld.scala`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00235.jpeg)**图 11：**使用 Notepad++保存你的第一个 Scala 源代码

让我们按照以下方式编译源文件：

```scala
C:\>scalac HelloWorld.scala
 C:\>scala HelloWorld
 Hello, world!
 C:\>

```

# 我是 hello world 程序，好好解释给我听！

这个程序对于有一些编程经验的人来说应该很熟悉。它有一个主方法，打印字符串`Hello, world!`到你的控制台。接下来，为了看到我们如何定义`main`函数，我们使用了`def main()`奇怪的语法来定义它。`def`是 Scala 的关键字，用来声明/定义一个方法，我们将在下一章中更多地涵盖关于方法和不同的写法。所以，我们有一个`Array[String]`作为这个方法的参数，这是一个可以用于程序的初始配置的字符串数组，也可以省略。然后，我们使用常见的`println()`方法，它接受一个字符串（或格式化的字符串）并将其打印到控制台。一个简单的 hello world 打开了许多要学习的话题；特别是三个：

● ; ; ;方法（在后面的章节中涵盖）

● ; ; ;对象和类（在后面的章节中涵盖）

● ; ; ;类型推断 - Scala 是一种静态类型语言的原因 - 之前解释过

# 交互式运行 Scala！

`scala`命令为你启动了交互式 shell，你可以在其中交互地解释 Scala 表达式：

```scala
> scala
Welcome to Scala 2.11.8 (Java HotSpot(TM) 64-Bit Server VM, Java 1.8.0_121).
Type in expressions for evaluation. Or try :help.
scala>
scala> object HelloWorld {
 |   def main(args: Array[String]){
 |     println("Hello, world!")
 |   }
 | }
defined object HelloWorld
scala> HelloWorld.main(Array())
Hello, world!
scala>

```

快捷键`:q`代表内部 shell 命令`:quit`，用于退出解释器。

# 编译它！

`scalac`命令，类似于`javac`命令，编译一个或多个 Scala 源文件，并生成一个字节码作为输出，然后可以在任何 Java 虚拟机上执行。要编译你的 hello world 对象，使用以下命令：

```scala
> scalac HelloWorld.scala

```

默认情况下，`scalac`将类文件生成到当前工作目录。你可以使用`-d`选项指定不同的输出目录：

```scala
> scalac -d classes HelloWorld.scala

```

但是，请注意，在执行这个命令之前必须创建一个名为`classes`的目录。

# 用 Scala 命令执行它

`scala`命令执行由解释器生成的字节码：

```scala
$ scala HelloWorld

```

Scala 允许我们指定命令选项，比如`-classpath`（别名`-cp`）选项：

```scala
$ scala -cp classes HelloWorld

```

在使用`scala`命令执行源文件之前，你应该有一个作为应用程序入口点的主方法。否则，你应该有一个扩展`Trait Scala.App`的`Object`，然后这个对象内的所有代码将被命令执行。以下是相同的`Hello, world!`例子，但使用了`App`特性：

```scala
#!/usr/bin/env Scala 
object HelloWorld extends App {  
  println("Hello, world!") 
}
HelloWorld.main(args)

```

上面的脚本可以直接从命令行运行：

```scala
./script.sh

```

注：我们假设文件`script.sh`具有执行权限：；

```scala
$ sudo chmod +x script.sh

```

然后，在`$PATH`环境变量中指定了`scala`命令的搜索路径。

# 总结

在本章中，您已经学习了 Scala 编程语言的基础知识、特性和可用的编辑器。我们还简要讨论了 Scala 及其语法。我们演示了安装和设置指南，供那些新手学习 Scala 编程的人参考。在本章后面，您将学习如何编写、编译和执行 Scala 代码示例。此外，我们还为那些来自 Java 背景的人提供了 Scala 和 Java 的比较讨论。下面是 Scala 和 Python 的简要比较：

Scala 是静态类型的，而 Python 是动态类型的。Scala（大多数情况下）采用函数式编程范式，而 Python 不是。Python 具有独特的语法，缺少大部分括号，而 Scala（几乎）总是需要它们。在 Scala 中，几乎所有东西都是表达式；而在 Python 中并非如此。然而，有一些看似复杂的优点。类型复杂性大多是可选的。其次，根据[`stackoverflow.com/questions/1065720/what-is-the-purpose-of-scala-programming-language/5828684#5828684`](https://stackoverflow.com/questions/1065720/what-is-the-purpose-of-scala-programming-language/5828684#5828684)提供的文档；*Scala 编译器就像自由测试和文档一样，随着圈复杂度和代码行数的增加。当 Scala 得到恰当实现时，可以在一致和连贯的 API 背后执行几乎不可能的操作。*

在下一章中，我们将讨论如何改进我们对基础知识的理解，了解 Scala 如何实现面向对象的范式，以便构建模块化软件系统。


# 第二章：面向对象的 Scala

*"面向对象的模型使通过增加程序变得容易。实际上，这经常意味着它提供了一种结构化的方式来编写意大利面代码。"*

- Paul Graham

在上一章中，我们看了如何开始使用 Scala 进行编程。如果您正在编写我们在上一章中遵循的过程式程序，可以通过创建过程或函数来强制实现代码的可重用性。但是，如果您继续工作，因此，您的程序会变得更长、更大和更复杂。在某一点上，您甚至可能没有其他更简单的方法来在生产之前组织整个代码。

相反，**面向对象编程**（**OOP**）范式提供了一个全新的抽象层。您可以通过定义具有相关属性和方法的 OOP 实体（如类）来模块化代码。您甚至可以通过使用继承或接口定义这些实体之间的关系。您还可以将具有类似功能的类分组在一起，例如辅助类；因此，使您的项目突然感觉更宽敞和可扩展。简而言之，面向对象编程语言的最大优势在于可发现性、模块化和可扩展性。

考虑到前面介绍的面向对象编程语言的特性，在本章中，我们将讨论 Scala 中的基本面向对象特性。简而言之，本章将涵盖以下主题：

+   Scala 中的变量

+   Scala 中的方法、类和对象

+   包和包对象

+   特征和特征线性化

+   Java 互操作性

然后，我们将讨论模式匹配，这是来自函数式编程概念的一个特性。此外，我们将讨论 Scala 中的一些内置概念，如隐式和泛型。最后，我们将讨论一些广泛使用的构建工具，这些工具对于将我们的 Scala 应用程序构建成 jar 文件是必需的。

# Scala 中的变量

在深入了解面向对象编程特性之前，首先需要了解 Scala 中不同类型的变量和数据类型的详细信息。要在 Scala 中声明变量，您需要使用`var`或`val`关键字。在 Scala 中声明变量的正式语法如下：

```scala
val or var VariableName : DataType = Initial_Value

```

例如，让我们看看如何声明两个数据类型明确指定的变量：

```scala
var myVar : Int = 50
val myVal : String = "Hello World! I've started learning Scala."

```

您甚至可以只声明一个变量而不指定`DataType`。例如，让我们看看如何使用`val`或`var`声明变量，如下所示：

```scala
var myVar = 50
val myVal = "Hello World! I've started learning Scala."

```

Scala 中有两种类型的变量：可变和不可变，可以定义如下：

+   **可变：**其值可以在以后更改的变量

+   **不可变：**一旦设置，其值就无法更改的变量

通常，用`var`关键字声明可变变量。另一方面，为了指定不可变变量，使用`val`关键字。为了展示使用可变和不可变变量的示例，让我们考虑以下代码段：

```scala
package com.chapter3.OOP 
object VariablesDemo {
  def main(args: Array[String]) {
    var myVar : Int = 50 
    valmyVal : String = "Hello World! I've started learning Scala."  
    myVar = 90  
    myVal = "Hello world!"   
    println(myVar) 
    println(myVal) 
  } 
}

```

前面的代码在`myVar = 90`之前都可以正常工作，因为**`myVar`**是一个可变变量。但是，如果您尝试更改不可变变量（即`myVal`）的值，如前所示，您的 IDE 将显示编译错误，指出重新分配给`val`，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00202.jpeg)**图 1：**在 Scala 变量范围内不允许重新分配不可变变量

不要担心看前面的带有对象和方法的代码！我们将在本章后面讨论类、方法和对象，然后事情会变得更清晰。

在 Scala 变量中，我们可以有三种不同的范围，取决于您声明它们的位置：

+   **字段：**这些是属于您 Scala 代码实例的变量。因此，这些字段可以从对象中的每个方法中访问。但是，根据访问修饰符的不同，字段可以被其他类的实例访问。

如前所述，对象字段可以是可变的，也可以是不可变的（根据使用`var`或`val`声明类型）。但是，它们不能同时是两者。

+   **方法参数：**这些是变量，当调用方法时，可以用它们来传递方法内部的值。方法参数只能从方法内部访问。但是，传递的对象可能可以从外部访问。

需要注意的是，方法参数/参数始终是不可变的，无论指定了什么关键字。

+   **局部变量：**这些变量在方法内部声明，并且可以从方法内部访问。但是，调用代码可以访问返回的值。

# 引用与值的不可变性

根据前面的部分，`val`用于声明不可变变量，那么我们可以更改这些变量的值吗？这是否类似于 Java 中的 final 关键字？为了帮助我们更多地了解这一点，我们将使用以下代码片段：

```scala
scala> var testVar = 10
testVar: Int = 10

scala> testVar = testVar + 10
testVar: Int = 20

scala> val testVal = 6
testVal: Int = 6

scala> testVal = testVal + 10
<console>:12: error: reassignment to val
 testVal = testVal + 10
 ^
scala>

```

如果运行上述代码，将会在编译时注意到一个错误，它会告诉您正在尝试重新分配给`val`变量。一般来说，可变变量带来了性能优势。原因是这更接近计算机的行为，因为引入不可变值会迫使计算机在需要对特定实例进行任何更改（无论多么小）时创建一个全新的对象实例

# Scala 中的数据类型

如前所述，Scala 是一种 JVM 语言，因此它与 Java 有很多共同之处。其中一个共同点就是数据类型；Scala 与 Java 共享相同的数据类型。简而言之，Scala 具有与 Java 相同的所有数据类型，具有相同的内存占用和精度。如第一章中所述，*介绍 Scala*，在 Scala 中几乎到处都是对象。所有数据类型都是对象，您可以按如下方式在其中调用方法：

| **Sr.No** | **数据类型和描述** |
| --- | --- |
| 1 | **Byte**：8 位有符号值。范围从-128 到 127 |
| 2 | **Short**：16 位有符号值。范围为-32768 至 32767 |
| 3 | **Int**：32 位有符号值。范围为-2147483648 至 2147483647 |
| 4 | **Long**：64 位有符号值。-9223372036854775808 至 9223372036854775807 |
| 5 | **Float**：32 位 IEEE 754 单精度浮点数 |
| 6 | **Double**：64 位 IEEE 754 双精度浮点数 |
| 7 | **Char**：16 位无符号 Unicode 字符。范围从 U+0000 到 U+FFFF |
| 8 | **String**：一系列字符 |
| 9 | **Boolean**：要么是文字`true`，要么是文字`false` |
| 10 | **Unit**：对应于无值 |
| 11 | **Null**：空值或空引用 |
| 12 | **Nothing**：每种其他类型的子类型；不包括任何值 |
| 13 | **Any**：任何类型的超类型；任何对象都是*Any*类型 |
| 14 | **AnyRef**：任何引用类型的超类型 |

**表 1：**Scala 数据类型、描述和范围

在前面的表中列出的所有数据类型都是对象。但是，请注意，没有原始类型，就像在 Java 中一样。这意味着您可以在`Int`、`Long`等上调用方法。

```scala
val myVal = 20
//use println method to print it to the console; you will also notice that if will be inferred as Int
println(myVal + 10)
val myVal = 40
println(myVal * "test")

```

现在，您可以开始玩弄这些变量。让我们对如何初始化变量和处理类型注释有一些想法。

# 变量初始化

在 Scala 中，初始化变量一旦声明就是一个好习惯。但是，需要注意的是，未初始化的变量不一定是空值（考虑`Int`、`Long`、`Double`、`Char`等类型），而初始化的变量也不一定是非空值（例如`val s: String = null`）。实际原因是：

+   在 Scala 中，类型是从分配的值中推断出来的。这意味着必须为编译器分配一个值才能推断出类型（编译器应该如何考虑这段代码：`val a`？由于没有给出值，编译器无法推断出类型；由于它无法推断出类型，它将不知道如何初始化它）。

+   在 Scala 中，大多数时候，你会使用`val`。由于这些是不可变的，你将无法先声明它们，然后再初始化它们。

尽管 Scala 语言要求你在使用实例变量之前初始化它，但 Scala 不为你的变量提供默认值。相反，你必须手动设置它的值，使用通配符下划线，它就像一个默认值一样，如下所示：

```scala
var name:String = _

```

你可以定义自己的名称，而不是使用`val1`、`val2`等名称：

```scala
scala> val result = 6 * 5 + 8
result: Int = 38

```

你可以在后续的表达式中使用这些名称，如下所示：

```scala
scala> 0.5 * result
res0: Double = 19.0

```

# 类型标注

如果你使用`val`或`var`关键字来声明一个变量，它的数据类型将根据你为这个变量分配的值自动推断。你还可以在声明时明确指定变量的数据类型。

```scala
val myVal : Integer = 10

```

现在，让我们看一些在使用 Scala 中的变量和数据类型时需要的其他方面。我们将看到如何使用类型标注和`lazy`变量。

# 类型标注

类型标注用于告诉编译器你期望从表达式中得到的类型，从所有可能的有效类型中。因此，如果一个类型符合现有的约束，比如变异和类型声明，并且它是表达式所适用的类型之一，或者在范围内有一个适用的转换，那么这个类型就是有效的。因此，从技术上讲，`java.lang.String`扩展了`java.lang.Object`，因此任何`String`也是`Object`。例如：

```scala
scala> val s = "Ahmed Shadman" 
s: String = Ahmed Shadman

scala> val p = s:Object 
p: Object = Ahmed Shadman 

scala>

```

# 延迟值

`lazy val`的主要特点是绑定的表达式不会立即被评估，而是在第一次访问时。这就是`val`和`lazy val`之间的主要区别所在。当初始访问发生时，表达式被评估，并且结果被绑定到标识符，即`lazy val`。在后续访问中，不会发生进一步的评估，而是立即返回存储的结果。让我们看一个有趣的例子：

```scala
scala> lazy val num = 1 / 0
num: Int = <lazy>

```

如果你在 Scala REPL 中查看前面的代码，你会注意到代码运行得很好，即使你将一个整数除以 0 也不会抛出任何错误！让我们看一个更好的例子：

```scala
scala> val x = {println("x"); 20}
x
x: Int = 20

scala> x
res1: Int = 20
scala>

```

这样做后，以后可以在需要时访问变量`x`的值。这些只是使用延迟`val`概念的一些例子。感兴趣的读者应该访问此页面以获取更多详细信息：[`blog.codecentric.de/en/2016/02/lazy-vals-scala-look-hood/.`](https://blog.codecentric.de/en/2016/02/lazy-vals-scala-look-hood/)

# Scala 中的方法、类和对象

在前一节中，我们看到了如何使用 Scala 变量、不同的数据类型以及它们的可变性和不可变性，以及它们的使用范围。然而，在本节中，为了真正理解面向对象编程的概念，我们将处理方法、对象和类。Scala 的这三个特性将帮助我们理解 Scala 的面向对象的特性和其特点。

# Scala 中的方法

在这部分中，我们将讨论 Scala 中的方法。当你深入学习 Scala 时，你会发现有很多种方法来定义 Scala 中的方法。我们将以一些方式来演示它们：

```scala
def min(x1:Int, x2:Int) : Int = {
  if (x1 < x2) x1 else x2
}

```

前面的方法声明接受两个变量并返回它们中的最小值。在 Scala 中，所有方法都必须以 def 关键字开头，然后是这个方法的名称。可选地，你可以决定不向方法传递任何参数，甚至决定不返回任何东西。你可能想知道最小值是如何返回的，但我们稍后会讨论这个问题。此外，在 Scala 中，你可以定义不带大括号的方法：

```scala
def min(x1:Int, x2:Int):Int= if (x1 < x2) x1 else x2

```

如果你的方法体很小，你可以像这样声明你的方法。否则，最好使用大括号以避免混淆。如前所述，如果需要，你可以不传递任何参数给方法：

```scala
def getPiValue(): Double = 3.14159

```

带有或不带有括号的方法表示副作用的存在或不存在。此外，它与统一访问原则有着深刻的联系。因此，您也可以避免使用大括号，如下所示：

```scala
def getValueOfPi : Double = 3.14159

```

还有一些方法通过显式指定返回类型来返回值。例如：

```scala
def sayHello(person :String) = "Hello " + person + "!"

```

应该提到的是，前面的代码之所以能够工作，是因为 Scala 编译器能够推断返回类型，就像值和变量一样。

这将返回`Hello`与传递的人名连接在一起。例如：

```scala
scala> def sayHello(person :String) = "Hello " + person + "!"
sayHello: (person: String)String

scala> sayHello("Asif")
res2: String = Hello Asif!

scala>

```

# Scala 中的返回

在学习 Scala 方法如何返回值之前，让我们回顾一下 Scala 方法的结构：

```scala
def functionName ([list of parameters]) : [return type] = {
  function body
  value_to_return
}

```

对于前面的语法，返回类型可以是任何有效的 Scala 数据类型，参数列表将是用逗号分隔的变量列表，参数列表和返回类型是可选的。现在，让我们定义一个方法，它将两个正整数相加并返回结果，这也是一个整数值：

```scala
scala> def addInt( x:Int, y:Int ) : Int = {
 |       var sum:Int = 0
 |       sum = x + y
 |       sum
 |    }
addInt: (x: Int, y: Int)Int

scala> addInt(20, 34)
res3: Int = 54

scala>

```

如果您现在从`main()`方法中使用真实值调用前面的方法，比如`addInt(10, 30)`，该方法将返回一个整数值和，等于`40`。由于使用关键字`return`是可选的，Scala 编译器设计成在没有`return`关键字的情况下，最后的赋值将被返回。在这种情况下，将返回较大的值：

```scala
scala> def max(x1 : Int , x2: Int)  = {
 |     if (x1>x2) x1 else x2
 | }
max: (x1: Int, x2: Int)Int

scala> max(12, 27)
res4: Int = 27

scala>

```

干得好！我们已经看到了如何在 Scala REPL 中使用变量以及如何声明方法。现在，是时候看看如何将它们封装在 Scala 方法和类中了。下一节将讨论 Scala 对象。

# Scala 中的类

类被认为是一个蓝图，然后你实例化这个类以创建实际上将在内存中表示的东西。它们可以包含方法、值、变量、类型、对象、特征和类，这些统称为**成员**。让我们通过以下示例来演示：

```scala
class Animal {
  var animalName = null
  var animalAge = -1
  def setAnimalName (animalName:String)  {
    this.animalName = animalName
  }
  def setAnaimalAge (animalAge:Int) {
    this.animalAge = animalAge
  }
  def getAnimalName () : String = {
    animalName
  }
  def getAnimalAge () : Int = {
    animalAge
  }
}

```

我们有两个变量`animalName`和`animalAge`以及它们的设置器和获取器。现在，我们如何使用它们来解决我们的目的呢？这就是 Scala 对象的用法。现在，我们将讨论 Scala 对象，然后我们将追溯到我们的下一个讨论。

# Scala 中的对象

Scala 中的**object**的含义与传统的 OOP 有些不同，这种差异应该得到解释。特别是在 OOP 中，对象是类的一个实例，而在 Scala 中，任何声明为对象的东西都不能被实例化！`object`是 Scala 中的一个关键字。在 Scala 中声明对象的基本语法如下：

```scala
object <identifier> [extends <identifier>] [{ fields, methods, and classes }]

```

为了理解前面的语法，让我们重新看一下 hello world 程序：

```scala
object HelloWorld {
  def main(args : Array[String]){
    println("Hello world!")
  }
}

```

这个 hello world 示例与 Java 的示例非常相似。唯一的区别是 main 方法不在一个类中，而是在一个对象中。在 Scala 中，关键字 object 可以表示两种不同的东西：

+   就像在 OOP 中，一个对象可以表示一个类的实例

+   用于描述一种非常不同的实例对象，称为**Singleton**

# 单例和伴生对象

在这一小节中，我们将看到 Scala 和 Java 中的单例对象之间的比较分析。单例模式的理念是确保一个类的实例只能存在一个。以下是 Java 中单例模式的示例：

```scala
public class DBConnection {
  private static DBConnection dbInstance;
  private DBConnection() {
  }
  public static DBConnection getInstance() {
    if (dbInstance == null) {
      dbInstance = new DBConnection();
    }
    return dbInstance;
  }
}

```

Scala 对象也做了类似的事情，并且它由编译器很好地处理。由于只会有一个实例，因此在这里没有对象创建的方式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00215.jpeg)**图 3：**Scala 中的对象创建

# 伴生对象

当一个`singleton object`与一个类同名时，它被称为`companion object`。伴生对象必须在与类相同的源文件中定义。让我们通过这个例子来演示：

```scala
class Animal {
  var animalName:String  = "notset"
  def setAnimalName(name: String) {
    animalName = name
  }
  def getAnimalName: String = {
    animalName
  }
  def isAnimalNameSet: Boolean = {
    if (getAnimalName == "notset") false else true
  }
}

```

以下是通过伴生对象调用方法的方式（最好与相同的名称 - 也就是`Animal`）：

```scala
object Animal{
  def main(args: Array[String]): Unit= {
    val obj: Animal = new Animal
    var flag:Boolean  = false        
    obj.setAnimalName("dog")
    flag = obj.isAnimalNameSet
    println(flag)  // prints true 

    obj.setAnimalName("notset")
    flag = obj.isAnimalNameSet
    println(flag)   // prints false     
  }
}

```

Java 的等价物将非常相似，如下所示：

```scala
public class Animal {
  public String animalName = "null";
  public void setAnimalName(String animalName) {
    this.animalName = animalName;
  }
  public String getAnimalName() {
    return animalName;
  }
  public boolean isAnimalNameSet() {
    if (getAnimalName() == "notset") {
      return false;
    } else {
      return true;
    }
  }

  public static void main(String[] args) {
    Animal obj = new Animal();
    boolean flag = false;         
    obj.setAnimalName("dog");
    flag = obj.isAnimalNameSet();
    System.out.println(flag);        

    obj.setAnimalName("notset");
    flag = obj.isAnimalNameSet();
    System.out.println(flag);
  }
}

```

干得好！到目前为止，我们已经看到了如何使用 Scala 对象和类。然而，使用方法来实现和解决数据分析问题的方法更加重要。因此，我们现在将简要介绍如何使用 Scala 方法。

```scala
object RunAnimalExample {
  val animalObj = new Animal
  println(animalObj.getAnimalName) //prints the initial name
  println(animalObj.getAnimalAge) //prints the initial age
  // Now try setting the values of animal name and age as follows:   
  animalObj.setAnimalName("dog") //setting animal name
  animalObj.setAnaimalAge(10) //seting animal age
  println(animalObj.getAnimalName) //prints the new name of the animal 
  println(animalObj.getAnimalAge) //Prints the new age of the animal
}

```

输出如下：

```scala
notset 
-1 
dog 
10

```

现在，让我们在下一节中简要概述 Scala 类的可访问性和可见性。

# 比较和对比：val 和 final

与 Java 一样，Scala 中也存在 final 关键字，它的工作方式与 val 关键字类似。为了区分 Scala 中的`val`和`final`关键字，让我们声明一个简单的动物类，如下所示：

```scala
class Animal {
  val age = 2  
}

```

如第一章中所述，*Scala 简介*，在列出 Scala 特性时，Scala 可以覆盖 Java 中不存在的变量：

```scala
class Cat extends Animal{
  override val age = 3
  def printAge ={
    println(age)
  }
}

```

现在，在深入讨论之前，关键字`extends`的快速讨论是必需的。有关详细信息，请参阅以下信息框。

使用 Scala，类可以是可扩展的。使用 extends 关键字的子类机制使得可以通过继承给定*超类*的所有成员并定义额外的类成员来*专门化*类。让我们看一个例子，如下所示：

`class Coordinate(xc: Int, yc: Int) {`

`val x: Int = xc`

`val y: Int = yc`

`def move(dx: Int, dy: Int): Coordinate = new Coordinate(x + dx, y + dy)`

`}`

`class ColorCoordinate(u: Int, v: Int, c: String) extends Coordinate(u, v) {`

`val color: String = c`

`def compareWith(pt: ColorCoordinate): Boolean = (pt.x == x) && (pt.y == y) && (pt.color == color)`

`override def move(dx: Int, dy: Int): ColorCoordinate = new ColorCoordinate(x + dy, y + dy, color)`

`}`

但是，如果我们在`Animal`类中将年龄变量声明为 final，那么`Cat`类将无法覆盖它，并且将会出现以下错误。对于这个`Animal`示例，您应该学会何时使用`final`关键字。让我们看一个例子：

```scala
scala> class Animal {
 |     final val age = 3
 | }
defined class Animal
scala> class Cat extends Animal {
 |     override val age = 5
 | }
<console>:13: error: overriding value age in class Animal of type Int(3);
 value age cannot override final member
 override val age = 5
 ^
scala>

```

干得好！为了实现最佳封装-也称为信息隐藏-您应该始终使用最少可见性声明方法。在下一小节中，我们将学习类、伴生对象、包、子类和项目的访问和可见性如何工作。

# 访问和可见性

在本小节中，我们将尝试理解 OOP 范式中 Scala 变量和不同数据类型的访问和可见性。让我们看看 Scala 中的访问修饰符。Scala 的类似之一：

| **修饰符** | **类** | **伴生对象** | **包** | **子类** | **项目** |
| --- | --- | --- | --- | --- | --- |
| 默认/无修饰符 | 是 | 是 | 是 | 是 | 是 |
| 受保护 | 是 | 是 | 是 | 否 | 否 |
| 私有 | 是 | 是 | 否 | 否 | 否 |

**公共成员**：与私有和受保护成员不同，对于公共成员，不需要为公共成员指定 public 关键字。公共成员没有显式的修饰符。这些成员可以从任何地方访问。例如：

```scala
class OuterClass { //Outer class
  class InnerClass {
    def printName() { println("My name is Asif Karim!") }

    class InnerMost { //Inner class
      printName() // OK
    }
  }
  (new InnerClass).printName() // OK because now printName() is public
}

```

**私有成员**：私有成员仅在包含成员定义的类或对象内部可见。让我们看一个例子，如下所示：

```scala
package MyPackage {
  class SuperClass {
    private def printName() { println("Hello world, my name is Asif Karim!") }
  }   
  class SubClass extends SuperClass {
    printName() //ERROR
  }   
  class SubsubClass {
    (new SuperClass).printName() // Error: printName is not accessible
  }
}

```

**受保护成员**：受保护成员只能从定义成员的类的子类中访问。让我们看一个例子，如下所示：

```scala
package MyPackage {
  class SuperClass {
    protected def printName() { println("Hello world, my name is Asif
                                         Karim!") }
  }   
  class SubClass extends SuperClass {
    printName()  //OK
  }   
  class SubsubClass {
    (new SuperClass).printName() // ERROR: printName is not accessible
  }
}

```

Scala 中的访问修饰符可以通过限定符进行增强。形式为`private[X]`或`protected[X]`的修饰符意味着访问是私有的或受保护的，直到`X`，其中`X`指定封闭的包、类或单例对象。让我们看一个例子：

```scala
package Country {
  package Professional {
    class Executive {
      private[Professional] var jobTitle = "Big Data Engineer"
      private[Country] var friend = "Saroar Zahan" 
      protected[this] var secret = "Age"

      def getInfo(another : Executive) {
        println(another.jobTitle)
        println(another.friend)
        println(another.secret) //ERROR
        println(this.secret) // OK
      }
    }
  }
}

```

在前面的代码段中有一个简短的说明：

+   变量`jboTitle`将对封闭包`Professional`中的任何类可访问

+   变量`friend`将对封闭包`Country`中的任何类可访问

+   变量`secret`只能在实例方法（this）中被隐式对象访问

如果您看一下前面的例子，我们使用了关键字`package`。然而，我们到目前为止还没有讨论这个问题。但不要担心；本章后面将有一个专门的部分。构造函数是任何面向对象编程语言的一个强大特性。Scala 也不例外。现在，让我们简要概述一下构造函数。

# 构造函数

在 Scala 中，构造函数的概念和用法与 C#或 Java 中的有些不同。Scala 中有两种类型的构造函数 - 主构造函数和辅助构造函数。主构造函数是类的主体，其参数列表紧跟在类名后面。

例如，以下代码段描述了在 Scala 中使用主构造函数的方法：

```scala
class Animal (animalName:String, animalAge:Int) {
  def getAnimalName () : String = {
    animalName
  }
  def getAnimalAge () : Int = {
    animalAge
  }
}

```

现在，要使用前面的构造函数，这个实现与之前的实现类似，只是没有设置器和获取器。相反，我们可以在这里获取动物的名称和年龄：

```scala
object RunAnimalExample extends App{
  val animalObj = new animal("Cat",-1)
  println(animalObj.getAnimalName)
  println(animalObj.getAnimalAge)
}

```

在类定义时给出参数以表示构造函数。如果我们声明了一个构造函数，那么就不能在不提供构造函数中指定的参数的默认值的情况下创建类。此外，Scala 允许在不提供必要参数给其构造函数的情况下实例化对象：当所有构造函数参数都有默认值定义时会发生这种情况。

尽管使用辅助构造函数有一些限制，但我们可以自由地添加任意数量的额外辅助构造函数。辅助构造函数必须在其主体的第一行调用在其之前声明的另一个辅助构造函数或主构造函数。为了遵守这个规则，每个辅助构造函数最终都会直接或间接地调用主构造函数。

例如，以下代码段演示了在 Scala 中使用辅助构造函数：

```scala
class Hello(primaryMessage: String, secondaryMessage: String) {
  def this(primaryMessage: String) = this(primaryMessage, "")
  // auxilary constructor
  def sayHello() = println(primaryMessage + secondaryMessage)
}
object Constructors {
  def main(args: Array[String]): Unit = {
    val hello = new Hello("Hello world!", " I'm in a trouble,
                          please help me out.")
    hello.sayHello()
  }
}

```

在之前的设置中，我们在主构造函数中包含了一个次要（即第二个）消息。主构造函数将实例化一个新的`Hello`对象。方法`sayHello()`将打印连接的消息。

**辅助构造函数**：在 Scala 中，为 Scala 类定义一个或多个辅助构造函数可以让类的消费者以不同的方式创建对象实例。在类中将辅助构造函数定义为 this 的方法。您可以定义多个辅助构造函数，但它们必须具有不同的签名（参数列表）。此外，每个构造函数必须调用先前定义的构造函数之一。

现在让我们来看一下 Scala 中另一个重要但相对较新的概念，称为**特征**。我们将在下一节中讨论这个问题。

# Scala 中的特征

Scala 中的一个新特性是特征，它与 Java 中接口的概念非常相似，只是它还可以包含具体方法。尽管 Java 8 已经支持这一点。另一方面，特征是 Scala 中的一个新概念。但这个特性已经存在于面向对象编程中。因此，它们看起来像抽象类，只是它们没有构造函数。

# 特征语法

您需要使用`trait`关键字来声明一个特征，后面应该跟着特征名称和主体：

```scala
trait Animal {
  val age : Int
  val gender : String
  val origin : String
 }

```

# 扩展特征

为了扩展特征或类，您需要使用`extend`关键字。特征不能被实例化，因为它可能包含未实现的方法。因此，必须实现特征中的抽象成员：

```scala
trait Cat extends Animal{ }

```

不允许值类扩展特征。为了允许值类扩展特征，引入了通用特征，它扩展了`Any`。例如，假设我们已经定义了以下特征：

```scala
trait EqualityChecking {
  def isEqual(x: Any): Boolean
  def isNotEqual(x: Any): Boolean = !isEqual(x)
}

```

现在，要使用通用特征在 Scala 中扩展前面的特征，我们遵循以下代码段：

```scala
trait EqualityPrinter extends Any {
  def print(): Unit = println(this)
}

```

那么，在 Scala 中抽象类和特征之间有什么区别呢？正如您所见，Scala 中的抽象类可以具有构造参数、类型参数和多个参数。但是，Scala 中的特征只能具有类型参数。

如果一个特征不包含任何实现代码，那么它才是完全可互操作的。此外，Scala 特征在 Scala 2.12 中与 Java 接口完全可互操作。因为 Java 8 也允许在其接口中进行方法实现。

可能还有其他情况适用于特征，例如，抽象类可以扩展特征，或者如果需要，任何普通类（包括 case 类）都可以扩展现有的特征。例如，抽象类也可以扩展特征：

```scala
abstract class Cat extends Animal { }

```

最后，普通的 Scala 类也可以扩展 Scala 特征。由于类是具体的（即可以创建实例），特征的抽象成员应该被实现。在下一节中，我们将讨论 Scala 代码的 Java 互操作性。现在让我们来了解 OOP 中的另一个重要概念，称为**抽象类**。我们将在下一节中讨论这个问题。

# 抽象类

在 Scala 中，抽象类可以具有构造参数以及类型参数。Scala 中的抽象类与 Java 完全可互操作。换句话说，可以在 Java 代码中调用它们，而无需任何中间包装器。

那么，在 Scala 中抽象类和特征之间有什么区别呢？正如您所见，Scala 中的抽象类可以具有构造参数、类型参数和多个参数。但是，Scala 中的特征只能具有类型参数。以下是抽象类的一个简单示例：

```scala
abstract class Animal(animalName:String = "notset") {
  //Method with definition/return type
  def getAnimalAge
  //Method with no definition with String return type
  def getAnimalGender : String
  //Explicit way of saying that no implementation is present
  def getAnimalOrigin () : String {} 
  //Method with its functionality implemented
  //Need not be implemented by subclasses, can be overridden if required
  def getAnimalName : String = {
    animalName
  }
}

```

为了通过另一个类扩展这个类，我们需要实现之前未实现的方法`getAnimalAge`，`getAnimalGender`和`getAnimalOrigin`。对于`getAnimalName`，我们可以覆盖它，也可以不覆盖，因为它的实现已经存在。

# 抽象类和 override 关键字

如果要覆盖父类的具体方法，则需要 override 修饰符。但是，如果要实现抽象方法，则不一定需要添加 override 修饰符。Scala 使用`override`关键字来覆盖父类的方法。例如，假设您有以下抽象类和一个`printContents()`方法来在控制台上打印您的消息：

```scala
abstract class MyWriter {
  var message: String = "null"
  def setMessage(message: String):Unit
  def printMessage():Unit
}

```

现在，添加前面的抽象类的具体实现以在控制台上打印内容，如下所示：

```scala
class ConsolePrinter extends MyWriter {
  def setMessage(contents: String):Unit= {
    this.message = contents
  }

  def printMessage():Unit= {
    println(message)
  }
}

```

其次，如果您想创建一个特征来修改前面的具体类的行为，如下所示：

```scala
trait lowerCase extends MyWriter {
  abstract override def setMessage(contents: String) = printMessage()
}

```

如果您仔细查看前面的代码段，您会发现两个修饰符（即 abstract 和 override）。现在，在前面的设置下，您可以执行以下操作来使用前面的类：

```scala
val printer:ConsolePrinter = new ConsolePrinter()
printer.setMessage("Hello! world!")
printer.printMessage()

```

总之，我们可以在方法前面添加`override`关键字以使其按预期工作。

# Scala 中的 Case 类

**case**类是一个可实例化的类，其中包括几个自动生成的方法。它还包括一个自动生成的伴生对象，其中包括自己的自动生成的方法。Scala 中 case 类的基本语法如下：

```scala
case class <identifier> ([var] <identifier>: <type>[, ... ])[extends <identifier>(<input parameters>)] [{ fields and methods }]

```

Case 类可以进行模式匹配，并且已经实现了以下方法：`hashCode`方法（位置/范围是类），`apply`方法（位置/范围是对象），`copy`方法（位置/范围是类），`equals`方法（位置/范围是类），`toString`方法（位置/范围是类），和`unapply`方法（位置/范围是对象）。

与普通类一样，case 类自动为构造参数定义 getter 方法。为了对前面的特性或 case 类有实际的了解，让我们看下面的代码段：

```scala
package com.chapter3.OOP 
object CaseClass {
  def main(args: Array[String]) {
    case class Character(name: String, isHacker: Boolean) // defining a
                               class if a person is a computer hacker     
    //Nail is a hacker
    val nail = Character("Nail", true)     
    //Now let's return a copy of the instance with any requested changes
    val joyce = nail.copy(name = "Joyce")
    // Let's check if both Nail and Joyce are Hackers
    println(nail == joyce)    
    // Let's check if both Nail and Joyce equal
    println(nail.equals(joyce))        
    // Let's check if both Nail and Nail equal
    println(nail.equals(nail))    
    // Let's the hasing code for nail
    println(nail.hashCode())    
    // Let's the hasing code for nail
    println(nail)
    joyce match {
      case Character(x, true) => s"$x is a hacker"
      case Character(x, false) => s"$x is not a hacker"
    }
  }
}

```

前面的代码产生以下输出：

```scala
false 
false 
true 
-112671915 
Character(Nail,true) 
Joyce is a hacker

```

对于 REPL 和正则表达式匹配的输出，如果您执行前面的代码（除了`Object`和`main`方法），您应该能够看到更多的交互式输出，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00373.jpeg)**图 2：** 用于 case 类的 Scala REPL

# 包和包对象

就像 Java 一样，包是一个特殊的容器或对象，其中包含/定义一组对象、类甚至包。每个 Scala 文件都自动导入以下内容：

+   `java.lang._`

+   `scala._`

+   `scala.Predef._`

以下是基本导入的示例：

```scala
// import only one member of a package
import java.io.File
// Import all members in a specific package
import java.io._
// Import many members in a single import statement
import java.io.{File, IOException, FileNotFoundException}
// Import many members in a multiple import statement
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException

```

您甚至可以在导入时重命名成员，这是为了避免具有相同成员名称的包之间的冲突。这种方法也被称为类`别名`：

```scala
import java.util.{List => UtilList}
import java.awt.{List => AwtList}
// In the code, you can use the alias that you have created
val list = new UtilList

```

正如在第一章中所述，《Scala 简介》，您还可以导入包的所有成员，但有些成员也被称为**成员隐藏**：

```scala
import java.io.{File => _, _}

```

如果您在 REPL 中尝试了这个，它只是告诉编译器定义的类或对象的完整规范名称：

```scala
package fo.ba
class Fo {
  override def toString = "I'm fo.ba.Fo"
}

```

您甚至可以使用大括号定义包的样式。您可以有一个单一的包和嵌套包，即包中的包。例如，以下代码段定义了一个名为`singlePackage`的单一包，其中包含一个名为`Test`的单一类。另一方面，`Test`类包含一个名为`toString()`的单一方法。

```scala
package singlePack {
  class Test { override def toString = "I am SinglePack.Test" }
}

```

现在，您可以将包进行嵌套。换句话说，您可以以嵌套的方式拥有多个包。例如，对于下面的情况，我们有两个包，分别是`NestParentPack`和`NestChildPack`，每个包都包含自己的类。

```scala
package nestParentPack {
  class Test { override def toString = "I am NestParentPack.Test" }

  package nestChildPack {
    class TestChild { override def toString = "I am nestParentPack.nestChildPack.TestChild" }
  }
}

```

让我们创建一个新对象（我们将其命名为`MainProgram`），在其中我们将调用刚刚定义的方法和类：

```scala
object MainProgram {
  def main(args: Array[String]): Unit = {
    println(new nestParentPack.Test())
    println(new nestParentPack.nestChildPack.TestChild())
  }
}

```

您将在互联网上找到更多的例子，描述了包和包对象的复杂用例。在下一节中，我们将讨论 Scala 代码的 Java 互操作性。

# Java 互操作性

Java 是最流行的语言之一，许多程序员将 Java 编程作为他们进入编程世界的第一步。自 1995 年首次发布以来，Java 的受欢迎程度一直在增加。Java 之所以受欢迎有很多原因。其中之一是其平台的设计，使得任何 Java 代码都将被编译为字节码，然后在 JVM 上运行。有了这一绝妙的特性，Java 语言可以编写一次，然后在任何地方运行。因此，Java 是一种跨平台语言。

此外，Java 得到了来自其社区的大量支持和许多包的支持，这些包将帮助您借助这些包实现您的想法。然后是 Scala，它具有许多 Java 所缺乏的特性，例如类型推断和可选的分号，不可变集合直接内置到 Scala 核心中，以及更多功能（在第一章中介绍，《Scala 简介》）。Scala 也像 Java 一样在 JVM 上运行。

**Scala 中的分号：** 分号是完全可选的，当需要在一行上编写多行代码时才需要。这可能是为什么编译器不会抱怨如果在行尾放上一个分号的原因：它被认为是一个代码片段，后面跟着一个空的代码片段，巧合的是，它们都在同一行上。

正如您所看到的，Scala 和 Java 都在 JVM 上运行，因此在同一个程序中同时使用它们是有意义的，而且编译器也不会有任何投诉。让我们通过一个示例来演示这一点。考虑以下 Java 代码：

```scala
ArrayList<String> animals = new ArrayList<String>();
animals.add("cat");
animals.add("dog");
animals.add("rabbit");
for (String animal : animals) {
  System.out.println(animal);
}

```

为了在 Scala 中编写相同的代码，您可以利用 Java 包。让我们借助使用 Java 集合（如`ArrayList`）将前面的示例翻译成 Scala：

```scala
import java.util.ArrayList
val animals = new ArrayList[String]
animals.add("cat")
animals.add("dog")
animals.add("rabbit")
for (animal <- animals) {
  println(animal)
}

```

前面的混合适用于 Java 的标准包，但是如果您想使用未打包在 Java 标准库中的库，甚至想使用自己的类。那么，您需要确保它们位于类路径中。

# 模式匹配

Scala 的一个广泛使用的特性是模式匹配。每个模式匹配都有一组备选项，每个备选项都以关键字`case`开头。每个备选项都有一个模式和表达式，如果模式匹配成功，箭头符号`=>`将模式与表达式分开。以下是一个示例，演示如何匹配整数：

```scala
object PatternMatchingDemo1 {
  def main(args: Array[String]) {
    println(matchInteger(3))
  }   
  def matchInteger(x: Int): String = x match {
    case 1 => "one"
    case 2 => "two"
    case _ => "greater than two"
  }
}

```

您可以通过将此文件保存为`PatternMatchingDemo1.scala`并使用以下命令来运行前面的程序。只需使用以下命令：

```scala
>scalac Test.scala
>scala Test

```

您将获得以下输出：

```scala
Greater than two

```

case 语句用作将整数映射到字符串的函数。以下是另一个示例，用于匹配不同类型：

```scala
object PatternMatchingDemo2 {
  def main(args: Array[String]): Unit = {
    println(comparison("two"))
    println(comparison("test"))
    println(comparison(1))
  }
  def comparison(x: Any): Any = x match {
    case 1 => "one"
    case "five" => 5
    case _ => "nothing else"
  }
}

```

您可以通过对之前的示例执行相同的操作来运行此示例，并将获得以下输出：

```scala
nothing else
nothing else
one

```

模式匹配是一种检查值与模式匹配的机制。成功的匹配还可以将值解构为其组成部分。它是 Java 中 switch 语句的更强大版本，也可以用来代替一系列的`if...else`语句。您可以通过参考 Scala 的官方文档（URL：[`www.scala-lang.org/files/archive/spec/2.11/08-pattern-matching.html`](http://www.scala-lang.org/files/archive/spec/2.11/08-pattern-matching.html)）了解更多关于模式匹配的内容。

在下一节中，我们将讨论 Scala 中的一个重要特性，它使我们能够自动传递一个值，或者说自动进行一种类型到另一种类型的转换。

# Scala 中的隐式

隐式是 Scala 引入的另一个令人兴奋和强大的特性，它可以指两种不同的东西：

+   可以自动传递的值

+   从一种类型自动转换为另一种类型

+   它们可以用于扩展类的功能

实际的自动转换可以通过隐式 def 完成，如下面的示例所示（假设您正在使用 Scala REPL）：

```scala
scala> implicit def stringToInt(s: String) = s.toInt
stringToInt: (s: String)Int

```

现在，在我的范围内有了前面的代码，我可以做类似这样的事情：

```scala
scala> def add(x:Int, y:Int) = x + y
add: (x: Int, y: Int)Int

scala> add(1, "2")
res5: Int = 3
scala>

```

即使传递给`add()`的参数之一是`String`（并且`add()`需要您提供两个整数），在范围内具有隐式转换允许编译器自动从`String`转换为`Int`。显然，这个特性可能非常危险，因为它使代码变得不太可读；而且，一旦定义了隐式转换，就不容易告诉编译器何时使用它，何时避免使用它。

第一种隐式是可以自动传递隐式参数的值。这些参数在调用方法时像任何普通参数一样传递，但 Scala 的编译器会尝试自动填充它们。如果 Scala 的编译器无法自动填充这些参数，它会报错。以下是演示第一种隐式的示例：

```scala
def add(implicit num: Int) = 2 + num

```

通过这样做，您要求编译器查找`num`的隐式值，如果在调用方法时未提供。您可以像这样向编译器定义隐式值：

```scala
implicit val adder = 2

```

然后，我们可以简单地这样调用函数：

```scala
add

```

在这里，没有传递参数，因此 Scala 的编译器将寻找隐式值，即`2`，然后返回方法调用的输出`4`。然而，还有很多其他选项，引发了一些问题，比如：

+   一个方法可以同时包含显式参数和隐式参数吗？答案是可以。让我们在 Scala REPL 上看一个例子：

```scala
 scala> def helloWold(implicit a: Int, b: String) = println(a, b)
 helloWold: (implicit a: Int, implicit b: String)Unit

 scala> val i = 2
 i: Int = 2

 scala> helloWorld(i, implicitly)
 (2,)

 scala>

```

+   一个方法可以包含多个隐式参数吗？答案是可以。让我们在 Scala REPL 上看一个例子：

```scala
 scala> def helloWold(implicit a: Int, b: String) = println(a, b)
 helloWold: (implicit a: Int, implicit b: String)Unit

 scala> helloWold(i, implicitly)
 (1,)

 scala>

```

+   隐式参数可以显式提供吗？答案是可以。让我们在 Scala REPL 上看一个例子：

```scala
 scala> def helloWold(implicit a: Int, b: String) = println(a, b)
 helloWold: (implicit a: Int, implicit b: String)Unit

 scala> helloWold(20, "Hello world!")
 (20,Hello world!)
 scala>

```

如果同一作用域中包含更多的隐式参数，会发生什么，隐式参数是如何解析的？隐式参数的解析顺序是否有任何顺序？要了解这两个问题的答案，请参考此 URL：[`stackoverflow.com/questions/9530893/good-example-of-implicit-parameter-in-scala`](http://stackoverflow.com/questions/9530893/good-example-of-implicit-parameter-in-scala)。

在下一节中，我们将讨论 Scala 中的泛型，并提供一些示例。

# Scala 中的泛型

泛型类是以类型作为参数的类。它们对于集合类特别有用。泛型类可以用于日常数据结构实现，如栈、队列、链表等。我们将看到一些示例。

# 定义一个泛型类

通用类在方括号`[]`内以类型作为参数。一个惯例是使用字母`A`作为类型参数标识符，尽管可以使用任何参数名称。让我们看一个 Scala REPL 的最小示例，如下所示：

```scala
scala> class Stack[A] {
 |       private var elements: List[A] = Nil
 |       def push(x: A) { elements = x :: elements }
 |       def peek: A = elements.head
 |       def pop(): A = {
 |         val currentTop = peek
 |         elements = elements.tail
 |         currentTop
 |       }
 |     }
defined class Stack
scala>

```

前面的`Stack`类的实现将任何类型 A 作为参数。这意味着底层列表`var elements: List[A] = Nil`只能存储类型为`A`的元素。过程 def push 只接受类型为`A`的对象（注意：`elements = x :: elements`重新分配元素到一个新列表，该列表由将`x`前置到当前元素创建）。让我们看一个如何使用前面的类来实现一个栈的示例：

```scala
object ScalaGenericsForStack {
  def main(args: Array[String]) {
    val stack = new Stack[Int]
    stack.push(1)
    stack.push(2)
    stack.push(3)
    stack.push(4)
    println(stack.pop) // prints 4
    println(stack.pop) // prints 3
    println(stack.pop) // prints 2
    println(stack.pop) // prints 1
  }
}

```

输出如下：

```scala
4
3
2
1

```

第二个用例可能也是实现一个链表。例如，如果 Scala 没有一个链表类，而您想要编写自己的链表，您可以像这样编写基本功能：

```scala
class UsingGenericsForLinkedList[X] { // Create a user specific linked list to print heterogenous values
  private class NodeX {
    var next: Node[X] = _
    override def toString = elem.toString
  }

  private var head: Node[X] = _

  def add(elem: X) { //Add element in the linekd list
    val value = new Node(elem)
    value.next = head
    head = value
  }

  private def printNodes(value: Node[X]) { // prining value of the nodes
    if (value != null) {
      println(value)
      printNodes(value.next)
    }
  }
  def printAll() { printNodes(head) } //print all the node values at a time
}

```

现在，让我们看看如何使用前面的链表实现：

```scala
object UsingGenericsForLinkedList {
  def main(args: Array[String]) {
    // To create a list of integers with this class, first create an instance of it, with type Int:
    val ints = new UsingGenericsForLinkedList[Int]()
    // Then populate it with Int values:
    ints.add(1)
    ints.add(2)
    ints.add(3)
    ints.printAll()

    // Because the class uses a generic type, you can also create a LinkedList of String:
    val strings = new UsingGenericsForLinkedList[String]()
    strings.add("Salman Khan")
    strings.add("Xamir Khan")
    strings.add("Shah Rukh Khan")
    strings.printAll()

    // Or any other type such as Double to use:
    val doubles = new UsingGenericsForLinkedList[Double]()
    doubles.add(10.50)
    doubles.add(25.75)
    doubles.add(12.90)
    doubles.printAll()
  }
}

```

输出如下：

```scala
3
2
1
Shah Rukh Khan
Aamir Khan
Salman Khan
12.9
25.75
10.5

```

总之，在 Scala 的基本级别上，创建一个泛型类就像在 Java 中创建一个泛型类一样，只是方括号的例外。好了！到目前为止，我们已经了解了一些基本功能，以便开始使用面向对象的编程语言 Scala。

尽管我们还没有涵盖一些其他方面，但我们仍然认为你可以继续工作。在第一章 *Scala 简介*中，我们讨论了 Scala 的可用编辑器。在接下来的部分，我们将看到如何设置构建环境。具体来说，我们将涵盖三种构建系统，如 Maven、SBT 和 Gradle。

# SBT 和其他构建系统

对于任何企业软件项目，使用构建工具是必要的。有许多构建工具可供选择，例如 Maven、Gradle、Ant 和 SBT。一个好的构建工具选择是让您专注于编码而不是编译复杂性的工具。

# 使用 SBT 构建

在这里，我们将简要介绍 SBT。在继续之前，您需要使用官方安装方法（URL：[`www.scala-sbt.org/release/docs/Setup.html`](http://www.scala-sbt.org/release/docs/Setup.html)）安装 SBT。

因此，让我们从 SBT 开始，在终端中演示 SBT 的使用。对于这个构建工具教程，我们假设您的源代码文件在一个目录中。您需要执行以下操作：

1.  打开终端并使用`cd`命令将路径更改为该目录，

1.  创建一个名为`build.sbt`的构建文件。

1.  然后，使用以下行填充该构建文件：

```scala
           name := "projectname-sbt"
           organization :="org.example"
           scalaVersion :="2.11.8"
           version := "0.0.1-SNAPSHOT"

```

让我们看看这些行的含义：

+   `name`定义了项目的名称。这个名称将在生成的 jar 文件中使用。

+   `organization`是一个命名空间，用于防止具有相似名称的项目之间的冲突。

+   `scalaVersion`设置您要构建的 Scala 版本。

+   `Version`指定了项目的当前构建版本，您可以使用`-SNAPSHOT`来表示尚未发布的版本。

创建此构建文件后，您需要在终端中运行`sbt`命令，然后会为您打开一个以`>`开头的提示符。在此提示符中，您可以输入`compile`以编译您的 Scala 或 Java 源文件。此外，您还可以在 SBT 提示符中输入命令以运行可运行的程序。或者您可以使用 SBT 提示符中的 package 命令生成一个`.jar`文件，该文件将存在一个名为`target`的子目录中。要了解有关 SBT 和更复杂示例的更多信息，您可以参考 SBT 的官方网站。

# Eclipse 中的 Maven

在 Eclipse 中使用 Maven 作为构建工具作为 Scala IDE 非常容易和直接。在本节中，我们将通过截图演示如何在 Eclipse 和 Maven 中使用 Scala。要在 Eclipse 中使用 Maven，您需要安装其插件，这将在不同版本的 Eclipse 中有所不同。安装 Maven 插件后，您会发现它不直接支持 Scala。为了使 Maven 插件支持 Scala 项目，我们需要安装一个名为 m2eclipse-scala 的连接器。

如果您在尝试向 Eclipse 添加新软件时粘贴此 URL（[`alchim31.free.fr/m2e-scala/update-site`](http://alchim31.free.fr/m2e-scala/update-site)），您会发现 Eclipse 理解该 URL 并建议您添加一些插件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00184.jpeg)**图 4：**在 Eclipse 上安装 Maven 插件以启用 Maven 构建

安装 Maven 和 Scala 支持连接器后，我们将创建一个新的 Scala Maven 项目。要创建一个新的 Scala Maven 项目，您需要导航到新建 | 项目 | 其他，然后选择 Maven 项目。之后，选择 net.alchim31.maven 作为 Group Id 的选项：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00186.jpeg)**图 5：**在 Eclipse 上创建一个 Scala Maven 项目

选择后，您需要按照向导输入所需的值，如 Group Id 等。然后，点击完成，这样就在工作区中创建了具有 Maven 支持的第一个 Scala 项目。在项目结构中，您会发现一个名为`pom.xml`的文件，您可以在其中添加所有依赖项和其他内容。

有关如何向项目添加依赖项的更多信息，请参考此链接：[`docs.scala-lang.org/tutorials/scala-with-maven.html`](http://docs.scala-lang.org/tutorials/scala-with-maven.html)。

作为本节的延续，我们将在接下来的章节中展示如何构建用 Scala 编写的 Spark 应用程序。

# Eclipse 中的 Gradle

Gradle Inc.为 Eclipse IDE 提供了 Gradle 工具和插件。该工具允许您在 Eclipse IDE 中创建和导入启用 Gradle 的项目。此外，它允许您运行 Gradle 任务并监视任务的执行。

Eclipse 项目本身称为**Buildship**。该项目的源代码可在 GitHub 上找到：[`github.com/eclipse/Buildship`](https://github.com/eclipse/Buildship)。

在 Eclipse 上安装 Gradle 插件有两个选项。如下所示：

+   通过 Eclipse Marketplace

+   通过 Eclipse 更新管理器

首先，让我们看看如何在 Eclipse 上使用 Marketplace 安装 Grade 构建的 Buildship 插件：Eclipse | 帮助 | Eclipse Marketplace：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00190.jpeg)**图 6：**在 Eclipse 上使用 Marketplace 安装 Grade 构建的 Buildship 插件

在 Eclipse 上安装 Gradle 插件的第二个选项是从帮助 | 安装新软件...菜单路径安装 Gradle 工具，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00192.jpeg)**图 7：**在 Eclipse 上使用安装新软件安装 Grade 构建的 Buildship 插件

例如，可以使用以下 URL 来下载 Eclipse 4.6（Neon）版本：[`download.eclipse.org/releases/neon`](http://download.eclipse.org/releases/neon)。

一旦您按照之前描述的任一方法安装了 Gradle 插件，Eclipse Gradle 将帮助您设置基于 Scala 的 Gradle 项目：文件|新建|项目|选择向导|Gradle|Gradle 项目。

**![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00196.jpeg)****图 8：**在 Eclipse 上创建 Gradle 项目

现在，如果您按下 Next>，您将获得以下向导，以指定项目名称以满足您的目的：

**![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00198.jpeg)****图 9：**在 Eclipse 上创建 Gradle 项目并指定项目名称

最后，按下 Finish 按钮创建项目。按下 Finish 按钮实质上触发了 Gradle `init --type java-library`命令并导入了项目。然而，如果您想在创建之前预览配置，请按 Next>以获得以下向导：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00050.jpeg)**图 10：**在创建之前预览配置

最后，您将在 Eclipse 上看到以下项目结构。然而，我们将在后面的章节中看到如何使用 Maven、SBT 和 Gradle 构建 Spark 应用程序。原因是，在开始项目之前，更重要的是学习 Scala 和 Spark。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00058.jpeg)**图 11：**在 Eclipse 上使用 Gradle 的项目结构

在本节中，我们已经看到了三种构建系统，包括 SBT、Maven 和 Gradle。然而，在接下来的章节中，我将尽量主要使用 Maven，因为它简单且代码兼容性更好。然而，在后面的章节中，我们将使用 SBT 来创建您的 Spark 应用程序的 JARS。

# 摘要

以合理的方式构建代码，使用类和特征增强了您的代码的可重用性，使用泛型创建了一个具有标准和广泛工具的项目。改进基础知识，了解 Scala 如何实现面向对象范式，以允许构建模块化软件系统。在本章中，我们讨论了 Scala 中的基本面向对象特性，如类和对象、包和包对象、特征和特征线性化、Java 互操作性、模式匹配、隐式和泛型。最后，我们讨论了 SBT 和其他构建系统，这些系统将需要在 Eclipse 或其他 IDE 上构建我们的 Spark 应用程序。

在下一章中，我们将讨论函数式编程是什么，以及 Scala 如何支持它。我们将了解为什么它很重要以及使用函数式概念的优势是什么。接下来，您将学习纯函数、高阶函数、Scala 集合基础（map、flatMap、filter）、for - comprehensions、单子处理，以及使用 Scala 标准库在集合之外扩展高阶函数。
