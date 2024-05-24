# 精通 Spark 2.x 机器学习（一）

> 原文：[`zh.annas-archive.org/md5/3BA1121D202F8663BA917C3CD75B60BC`](https://zh.annas-archive.org/md5/3BA1121D202F8663BA917C3CD75B60BC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

大数据-这是我们几年前探索 Spark 机器学习世界的动力。我们希望构建能够利用大量数据训练模型的机器学习应用程序，但一开始并不容易。Spark 仍在不断发展，它并不包含强大的机器学习库，我们仍在努力弄清楚构建机器学习应用程序意味着什么。

但是，逐步地，我们开始探索 Spark 生态系统的不同方面，并跟随 Spark 的发展。对我们来说，关键部分是一个强大的机器学习库，它将提供 R 或 Python 库所提供的功能。对我们来说，这是一项容易的任务，因为我们积极参与了 H2O 的机器学习库及其名为 Sparkling Water 的分支的开发，该分支使得可以从 Spark 应用程序中使用 H2O 库。然而，模型训练只是机器学习冰山的一角。我们还必须探索如何将 Sparkling Water 连接到 Spark RDDs、DataFrames 和 DataSets，如何将 Spark 连接到不同的数据源并读取数据，或者如何导出模型并在不同的应用程序中重用它们。

在我们的旅程中，Spark 也在不断发展。最初作为纯 Scala 项目，它开始提供 Python 和后来的 R 接口。它还将其 Spark API 从低级别的 RDDs 发展到高级别的 DataSet，并提供了类似 SQL 的接口。此外，Spark 还引入了机器学习管道的概念，这是从 Python 中已知的 scikit-learn 库中采用的。所有这些改进使 Spark 成为数据转换和数据处理的强大工具。

基于这种经验，我们决定通过这本书与世界其他地方分享我们的知识。它的目的很简单：通过示例演示构建 Spark 机器学习应用程序的不同方面，并展示如何不仅使用最新的 Spark 功能，还使用低级别的 Spark 接口。在我们的旅程中，我们还发现了许多技巧和捷径，不仅与 Spark 有关，还与开发机器学习应用程序或源代码组织的过程有关。所有这些都在本书中分享，以帮助读者避免我们所犯的错误。

本书采用 Scala 语言作为示例的主要实现语言。在使用 Python 和 Scala 之间做出了艰难的决定，但最终选择了 Scala。使用 Scala 的两个主要原因是：它提供了最成熟的 Spark 接口，大多数生产部署的应用程序都使用 Scala，主要是因为其在 JVM 上的性能优势。此外，本书中显示的所有源代码也都可以在线获取。

希望您喜欢我们的书，并且它能帮助您在 Spark 世界和机器学习应用程序的开发中进行导航。

# 本书涵盖的内容

第一章，*大规模机器学习简介*，邀请读者进入机器学习和大数据的世界，介绍了历史范式，并描述了包括 Apache Spark 和 H2O 在内的当代工具。

第二章，*探测暗物质：希格斯玻色子粒子*，着重介绍了二项模型的训练和评估。

第三章，*多类分类的集成方法*，进入健身房，并尝试基于从身体传感器收集的数据来预测人类活动。

第四章，*使用 NLP 预测电影评论*，介绍了使用 Spark 进行自然语言处理的问题，并展示了它在电影评论情感分析中的强大功能。

第五章，*使用 Word2Vec 进行在线学习*，详细介绍了当代自然语言处理技术。

第六章，*从点击流数据中提取模式*，介绍了频繁模式挖掘的基础知识和 Spark MLlib 中提供的三种算法，然后在 Spark Streaming 应用程序中部署了其中一种算法。

第七章，*使用 GraphX 进行图分析*，使读者熟悉图和图分析的基本概念，解释了 Spark GraphX 的核心功能，并介绍了 PageRank 等图算法。

﻿第八章，*Lending Club Loan Prediction*，结合了前几章介绍的所有技巧，包括数据处理、模型搜索和训练，以及作为 Spark Streaming 应用程序的模型部署的端到端示例。

# 本书所需内容

本书提供的代码示例使用 Apache Spark 2.1 及其 Scala API。此外，我们使用 Sparkling Water 软件包来访问 H2O 机器学习库。在每一章中，我们都会展示如何使用 spark-shell 启动 Spark，以及如何下载运行代码所需的数据。

总之，运行本书提供的代码的基本要求包括：

+   Java 8

+   Spark 2.1

# 本书适合的读者是谁

您是一位具有机器学习和统计背景的开发人员，感到当前的慢速和小数据机器学习工具限制了您的发展吗？那么这本书就是为您而写！在本书中，您将使用 Spark 创建可扩展的机器学习应用程序，以支持现代数据驱动的业务。我们假设您已经了解机器学习的概念和算法，并且已经在 Spark 上运行（无论是在集群上还是本地），并且具有对 Spark 中包含的各种库的基本知识。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“我们还附加了魔术列`row_id`，它唯一标识数据集中的每一行。” 代码块设置如下：

```scala
import org.apache.spark.ml.feature.StopWordsRemover 
val stopWords= StopWordsRemover.loadDefaultStopWords("english") ++ Array("ax", "arent", "re")
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```scala
val MIN_TOKEN_LENGTH = 3
val toTokens= (minTokenLen: Int, stopWords: Array[String], 
```

任何命令行输入或输出都写成如下形式：

```scala
tar -xvf spark-2.1.1-bin-hadoop2.6.tgz 
export SPARK_HOME="$(pwd)/spark-2.1.1-bin-hadoop2.6 
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现：“按照以下截图下载 DECLINED LOAN DATA”

警告或重要提示会以这种形式出现。

技巧会以这种形式出现。


# 第一章：大规模机器学习和 Spark 简介

"信息是 21 世纪的石油，分析是内燃机。"

--彼得·桑德加德，高德纳研究

到 2018 年，预计公司将在大数据相关项目上花费 1140 亿美元，比 2013 年增长了大约 300%（[`www.capgemini-consulting.com/resource-file-access/resource/pdf/big_data_pov_03-02-15.pdf`](https://www.capgemini-consulting.com/resource-file-access/resource/pdf/big_data_pov_03-02-15.pdf)）。支出增加的很大程度上是由于正在创建的数据量以及我们如何更好地利用分布式文件系统（如 Hadoop）来存储这些数据。

然而，收集数据只是一半的战斗；另一半涉及数据提取、转换和加载到计算系统中，利用现代计算机的能力应用各种数学方法，以了解数据和模式，并提取有用信息以做出相关决策。在过去几年里，整个数据工作流程得到了提升，不仅增加了计算能力并提供易于访问和可扩展的云服务（例如，Amazon AWS，Microsoft Azure 和 Heroku），还有一些工具和库，帮助轻松管理、控制和扩展基础设施并构建应用程序。计算能力的增长还有助于处理更大量的数据，并应用以前无法应用的算法。最后，各种计算昂贵的统计或机器学习算法开始帮助从数据中提取信息。

最早被广泛采用的大数据技术之一是 Hadoop，它允许通过将中间结果保存在磁盘上进行 MapReduce 计算。然而，它仍然缺乏适当的大数据工具来进行信息提取。然而，Hadoop 只是一个开始。随着机器内存的增长，出现了新的内存计算框架，它们也开始提供基本支持进行数据分析和建模，例如，SystemML 或 Spark 的 Spark ML 和 Flink 的 FlinkML。这些框架只是冰山一角-大数据生态系统中还有很多，它在不断发展，因为数据量不断增长，需要新的大数据算法和处理方法。例如，物联网代表了一个新的领域，它从各种来源产生大量的流数据（例如，家庭安全系统，Alexa Echo 或重要传感器），不仅带来了从数据中挖掘有用信息的无限潜力，还需要新的数据处理和建模方法。

然而，在本章中，我们将从头开始解释以下主题：

+   数据科学家的基本工作任务

+   分布环境中大数据计算的方面

+   大数据生态系统

+   Spark 及其机器学习支持

# 数据科学

找到数据科学的统一定义，就像品尝葡萄酒并在朋友中比较口味一样-每个人都有自己的定义，没有一个描述比其他更准确。然而，在其核心，数据科学是关于对数据提出智能问题并获得对关键利益相关者有意义的智能答案的艺术。不幸的是，相反的也是真的-对数据提出糟糕的问题会得到糟糕的答案！因此，仔细制定问题是从数据中提取有价值见解的关键。因此，公司现在正在聘请数据科学家来帮助制定并提出这些问题。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00005.jpeg)

图 1 - 大数据和数据科学的增长谷歌趋势

# 21 世纪最性感的角色-数据科学家？

起初，很容易对典型的数据科学家的形象有一个刻板印象：T 恤，运动裤，厚框眼镜，正在用 IntelliJ 调试一段代码……你懂的。除了审美外，数据科学家的一些特质是什么？我们最喜欢的一张海报描述了这个角色，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00006.jpeg)

图 2 - 什么是数据科学家？

数学、统计学和计算机科学的一般知识是必备的，但我们在从业者中看到的一个陷阱与理解业务问题有关，这又回到了对数据提出智能问题。无法再强调：对数据提出更多智能问题取决于数据科学家对业务问题和数据限制的理解；没有这种基本理解，即使是最智能的算法也无法基于摇摇欲坠的基础得出坚实的结论。

# 一个数据科学家的一天

这可能会让你们中的一些人感到震惊——成为一名数据科学家不仅仅是阅读学术论文、研究新工具和模型构建直到清晨，靠浓缩咖啡提神；事实上，这只是数据科学家真正*玩耍*的时间的一小部分（然而，对于每个人来说，咖啡因的部分是 100%真实的）！然而，大部分时间都是在开会中度过的，更好地了解业务问题，分析数据以了解其限制（放心，本书将让您接触到大量不同的特征工程或特征提取任务），以及如何最好地向非数据科学人员呈现发现。这就是真正的*香肠制作*过程所在，最优秀的数据科学家是那些热爱这个过程的人，因为他们更多地了解了成功的要求和基准。事实上，我们可以写一本全新的书来描述这个过程的始终！

那么，关于数据的提问涉及什么（和谁）？有时，这是将数据保存到关系数据库中，并运行 SQL 查询以找到数据的见解的过程：“对于购买了这种特定产品的数百万用户，还购买了哪 3 种其他产品？”其他时候，问题更复杂，比如，“鉴于一部电影的评论，这是一个积极的还是消极的评论？”本书主要关注复杂的问题，比如后者。回答这些类型的问题是企业从其大数据项目中真正获得最大影响的地方，也是我们看到新兴技术大量涌现，旨在使这种问答系统更容易，功能更多。

一些最受欢迎的开源框架，旨在帮助回答数据问题，包括 R、Python、Julia 和 Octave，所有这些框架在小型（X < 100 GB）数据集上表现得相当不错。在这一点上，值得停下来指出大数据与小数据之间的明显区别。我们办公室的一般经验法则如下：

*如果您可以使用 Excel 打开数据集，那么您正在处理小数据。*

# 处理大数据

当所讨论的数据集如此庞大，以至于无法适应单台计算机的内存，并且必须分布在大型计算集群中的多个节点上时，会发生什么？难道我们不能简单地重写一些 R 代码，例如，扩展它以适应多于单节点的计算？如果事情只是那么简单就好了！有许多原因使得算法扩展到更多机器变得困难。想象一个简单的例子，一个文件包含一个名单：

```scala
B
D
X
A
D
A
```

我们想要计算文件中各个单词的出现次数。如果文件适合在一台机器上，您可以轻松地使用 Unix 工具`sort`和`uniq`来计算出现次数：

```scala
bash> sort file | uniq -c
```

输出如下所示：

```scala
2 A
1 B
1 D
1 X
```

然而，如果文件很大并分布在多台机器上，就需要采用略有不同的计算策略。例如，计算每个适合内存的文件部分中各个单词的出现次数，并将结果合并在一起。因此，即使是简单的任务，比如在分布式环境中计算名称的出现次数，也会变得更加复杂。

# 使用分布式环境的机器学习算法

机器学习算法将简单的任务组合成复杂的模式，在分布式环境中更加复杂。例如，让我们以简单的决策树算法为例。这个特定的算法创建一个二叉树，试图拟合训练数据并最小化预测错误。然而，为了做到这一点，它必须决定将每个数据点发送到树的哪个分支（不用担心，我们将在本书的后面介绍这个算法的工作原理以及一些非常有用的参数）。让我们用一个简单的例子来演示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00007.jpeg)

图 3 - 覆盖 2D 空间的红色和蓝色数据点的示例。

考虑前面图中描述的情况。一个二维棋盘，上面有许多点涂成两种颜色：红色和蓝色。决策树的目标是学习和概括数据的形状，并帮助决定一个新点的颜色。在我们的例子中，我们很容易看出这些点几乎遵循着象棋盘的模式。然而，算法必须自己找出结构。它首先要找到一个垂直或水平线的最佳位置，这条线可以将红点与蓝点分开。

找到的决策存储在树根中，并且步骤递归地应用在两个分区上。当分区中只有一个点时，算法结束：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00008.jpeg)

图 4 - 最终的决策树及其预测在原始点空间中的投影。

# 将数据分割成多台机器

现在，让我们假设点的数量很大，无法适应单台机器的内存。因此，我们需要多台机器，并且我们必须以这样的方式对数据进行分区，使得每台机器只包含数据的一个子集。这样，我们解决了内存问题；然而，这也意味着我们需要在机器集群中分布计算。这是与单机计算的第一个不同之处。如果您的数据适合单台机器的内存，那么很容易做出关于数据的决策，因为算法可以一次性访问所有数据，但在分布式算法的情况下，这不再成立，算法必须在访问数据方面变得“聪明”。由于我们的目标是构建一个决策树，以预测棋盘上一个新点的颜色，我们需要找出如何制作与单机上构建的树相同的树。

朴素的解决方案是构建一个基于机器边界分隔点的平凡树。但这显然是一个糟糕的解决方案，因为数据分布根本不反映颜色点。

另一个解决方案尝试在*X*和*Y*轴的方向上尝试所有可能的分割决策，并尽量在分离两种颜色时做得最好，也就是将点分成两组并最小化另一种颜色的点数。想象一下，算法正在通过线*X = 1.6*测试分割。这意味着算法必须询问集群中的每台机器报告分割机器的本地数据的结果，合并结果，并决定是否是正确的分割决策。如果找到了最佳分割，它需要通知所有机器关于决策，以记录每个点属于哪个分区。

与单机场景相比，构建决策树的分布式算法更复杂，需要一种在多台机器之间分配计算的方式。如今，随着对大型数据集分析需求的增加以及对机器群集的轻松访问，这成为了标准要求。

即使这两个简单的例子表明，对于更大的数据，需要适当的计算和分布式基础设施，包括以下内容：

+   分布式数据存储，即，如果数据无法放入单个节点，我们需要一种在多台机器上分发和处理数据的方式

+   一种处理和转换分布式数据并应用数学（和统计）算法和工作流的计算范式

+   支持持久化和重用定义的工作流和模型

+   支持在生产中部署统计模型

简而言之，我们需要一个支持常见数据科学任务的框架。这可能被认为是一个不必要的要求，因为数据科学家更喜欢使用现有工具，如 R、Weka 或 Python 的 scikit。然而，这些工具既不是为大规模分布式处理设计的，也不是为大数据的并行处理设计的。尽管有支持有限并行或分布式编程的 R 或 Python 库，但它们的主要局限是基础平台，即 R 和 Python，不是为这种数据处理和计算设计的。

# 从 Hadoop MapReduce 到 Spark

随着数据量的增长，单机工具无法满足行业需求，因此为新的数据处理方法和工具创造了空间，特别是基于最初在 Google 论文中描述的想法的 Hadoop MapReduce，*MapReduce: Simplified Data Processing on Large Clusters* ([`research.google.com/archive/mapreduce.html`](https://research.google.com/archive/mapreduce.html))。另一方面，它是一个通用框架，没有任何明确支持或库来创建机器学习工作流。经典 MapReduce 的另一个局限是，在计算过程中执行了许多磁盘 I/O 操作，而没有从机器内存中受益。

正如您所见，存在多种现有的机器学习工具和分布式平台，但没有一个完全匹配于在大数据和分布式环境中执行机器学习任务。所有这些说法为 Apache Spark 打开了大门。

进入房间，Apache Spark！

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00009.jpeg)

Apache Spark 项目于 2010 年在加州大学伯克利分校 AMP 实验室（算法、机器、人）创建，其目标是速度、易用性和高级分析。Spark 与 Hadoop 等其他分布式框架的一个关键区别是，数据集可以缓存在内存中，这非常适合机器学习，因为它的迭代性质（稍后会详细介绍！）以及数据科学家经常多次访问相同的数据。

Spark 可以以多种方式运行，例如以下方式：

+   **本地模式：**这涉及在单个主机上执行的单个**Java 虚拟机**（**JVM**）

+   **独立的 Spark 集群：**这涉及多个主机上的多个 JVM

+   **通过资源管理器，如 Yarn/Mesos：**这种应用部署是由资源管理器驱动的，它控制节点、应用程序、分发和部署的分配

# 什么是 Databricks？

如果您了解 Spark 项目，那么很可能您也听说过一个名为*Databricks*的公司。然而，您可能不知道 Databricks 和 Spark 项目之间的关系。简而言之，Databricks 是由 Apache Spark 项目的创建者成立的，并占据了 Spark 项目超过 75%的代码库。除了在开发方面对 Spark 项目有着巨大的影响力之外，Databricks 还为开发人员、管理员、培训师和分析师提供各种 Spark 认证。然而，Databricks 并不是代码库的唯一主要贡献者；像 IBM、Cloudera 和微软这样的公司也积极参与 Apache Spark 的开发。

另外，Databricks 还组织了 Spark Summit（在欧洲和美国举办），这是首屈一指的 Spark 会议，也是了解项目最新发展以及其他人如何在其生态系统中使用 Spark 的绝佳场所。

在本书中，我们将提供推荐的链接，这些链接每天都会提供很好的见解，同时也会介绍关于新版本 Spark 的重要变化。其中最好的资源之一是 Databricks 博客，该博客不断更新着优质内容。一定要定期查看[`databricks.com/blog`](https://databricks.com/blog)。

此外，这里还有一个链接，可以查看过去的 Spark Summit 讲座，可能会对您有所帮助：

[`slideshare.net/databricks`](http://slideshare.net/databricks).

# 盒子里

那么，您已经下载了最新版本的 Spark（取决于您计划如何启动 Spark），并运行了标准的*Hello, World!*示例....现在呢？

Spark 配备了五个库，可以单独使用，也可以根据我们要解决的任务一起使用。请注意，在本书中，我们计划使用各种不同的库，都在同一个应用程序中，以便您能最大程度地接触 Spark 平台，并更好地了解每个库的优势（和局限性）。这五个库如下：

+   **核心**：这是 Spark 的核心基础设施，提供了用于表示和存储数据的原语，称为**弹性分布式数据集**（**RDDs**），并使用任务和作业来操作数据。

+   **SQL**：该库通过引入 DataFrames 和 SQL 来提供用户友好的 API，以操作存储的数据。

+   **MLlib（机器学习库）**：这是 Spark 自己的机器学习库，其中包含了内部开发的算法，可以在 Spark 应用程序中使用。

+   **Graphx**：用于图形和图形计算；我们将在后面的章节中深入探讨这个特定的库。

+   **Streaming**：该库允许从各种来源实时流式传输数据，例如 Kafka、Twitter、Flume 和 TCP 套接字等。本书中许多应用程序将利用 MLlib 和 Streaming 库来构建我们的应用程序。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00010.jpeg)

Spark 平台也可以通过第三方软件包进行扩展。例如，支持读取 CSV 或 Avro 文件，与 Redshift 集成以及 Sparkling Water，它封装了 H2O 机器学习库。

# 介绍 H2O.ai

H2O 是一个开源的机器学习平台，与 Spark 非常兼容；事实上，它是最早被认定为“在 Spark 上认证”的第三方软件包之一。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00011.jpeg)

Sparkling Water（H2O + Spark）是 H2O 在 Spark 项目中集成其平台的一部分，它将 H2O 的机器学习能力与 Spark 的所有功能结合在一起。这意味着用户可以在 Spark RDD/DataFrame 上运行 H2O 算法，用于探索和部署。这是可能的，因为 H2O 和 Spark 共享相同的 JVM，这允许在两个平台之间无缝切换。H2O 将数据存储在 H2O 框架中，这是您的数据集的列压缩表示，可以从 Spark RDD 和/或 DataFrame 创建。在本书的大部分内容中，我们将引用 Spark 的 MLlib 库和 H2O 平台的算法，展示如何使用这两个库来为给定任务获得尽可能好的结果。

以下是 Sparkling Water 配备的功能摘要：

+   在 Spark 工作流中使用 H2O 算法

+   在 Spark 和 H2O 数据结构之间的转换

+   使用 Spark RDD 和/或 DataFrame 作为 H2O 算法的输入

+   将 H2O 框架用作 MLlib 算法的输入（在进行特征工程时会很方便）

+   Sparkling Water 应用程序在 Spark 顶部的透明执行（例如，我们可以在 Spark 流中运行 Sparkling Water 应用程序）

+   探索 Spark 数据的 H2O 用户界面

# Sparkling Water 的设计

Sparkling Water 被设计为可执行的常规 Spark 应用程序。因此，它在提交应用程序后在 Spark 执行器内启动。此时，H2O 启动服务，包括分布式键值（K/V）存储和内存管理器，并将它们编排成一个云。创建的云的拓扑结构遵循底层 Spark 集群的拓扑结构。

如前所述，Sparkling Water 可以在不同类型的 RDD/DataFrame 和 H2O 框架之间进行转换，反之亦然。当从 hex 框架转换为 RDD 时，会在 hex 框架周围创建一个包装器，以提供类似 RDD 的 API。在这种情况下，数据不会被复制，而是直接从底层的 hex 框架提供。从 RDD/DataFrame 转换为 H2O 框架需要数据复制，因为它将数据从 Spark 转换为 H2O 特定的存储。但是，存储在 H2O 框架中的数据被大量压缩，不再需要作为 RDD 保留：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00012.jpeg)

Sparkling Water 和 Spark 之间的数据共享

# H2O 和 Spark 的 MLlib 有什么区别？

如前所述，MLlib 是使用 Spark 构建的流行机器学习算法库。毫不奇怪，H2O 和 MLlib 共享许多相同的算法，但它们在实现和功能上有所不同。H2O 的一个非常方便的功能是允许用户可视化其数据并执行特征工程任务，我们将在后面的章节中深入介绍。数据的可视化是通过一个友好的网络 GUI 完成的，并允许用户在代码 shell 和笔记本友好的环境之间无缝切换。以下是 H2O 笔记本的示例 - 称为 *Flow* - 您很快将熟悉的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00013.jpeg)

另一个很好的补充是，H2O 允许数据科学家对其算法附带的许多超参数进行网格搜索。网格搜索是一种优化算法的所有超参数的方法，使模型配置更加容易。通常，很难知道要更改哪些超参数以及如何更改它们；网格搜索允许我们同时探索许多超参数，测量输出，并根据我们的质量要求帮助选择最佳模型。H2O 网格搜索可以与模型交叉验证和各种停止标准结合使用，从而产生高级策略，例如*从巨大的参数超空间中选择 1000 个随机参数，并找到可以在两分钟内训练且 AUC 大于 0.7 的最佳模型*

# 数据整理

问题的原始数据通常来自多个来源，格式不同且通常不兼容。Spark 编程模型的美妙之处在于其能够定义数据操作，处理传入的数据并将其转换为常规形式，以便用于进一步的特征工程和模型构建。这个过程通常被称为数据整理，这是数据科学项目中取得胜利的关键。我们故意将这一部分简短，因为展示数据整理的力量和必要性最好的方式是通过示例。所以，放心吧；在这本书中，我们有很多实践要做，重点是这个基本过程。

# 数据科学-一个迭代的过程

很多大数据项目的流程是迭代的，这意味着不断地测试新的想法，包括新的特征，调整各种超参数等等，态度是“快速失败”。这些项目的最终结果通常是一个能够回答提出的问题的模型。请注意，我们没有说*准确地*回答提出的问题！如今许多数据科学家的一个缺陷是他们无法将模型泛化到新数据，这意味着他们已经过度拟合了数据，以至于当给出新数据时，模型会提供糟糕的结果。准确性极大地取决于任务，并且通常由业务需求决定，同时进行一些敏感性分析以权衡模型结果的成本效益。然而，在本书中，我们将介绍一些标准的准确性度量，以便您可以比较各种模型，看看对模型的更改如何影响结果。

H2O 经常在美国和欧洲举办见面会，并邀请其他人参加机器学习见面会。每个见面会或会议的幻灯片都可以在 SlideShare（[`www.slideshare.com/0xdata`](http://www.slideshare.com/0xdata)）或 YouTube 上找到。这两个网站不仅是关于机器学习和统计的重要信息来源，也是关于分布式系统和计算的重要信息来源。例如，其中一个最有趣的演示重点介绍了“数据科学家工作中的前 10 个陷阱”（[`www.slideshare.net/0xdata/h2o-world-top-10-data-science-pitfalls-mark-landry`](http://www.slideshare.net/0xdata/h2o-world-top-10-data-science-pitfalls-mark-landry)）。

# 总结

在本章中，我们想要简要地让您了解数据科学家的生活，这意味着什么，以及数据科学家经常面临的一些挑战。鉴于这些挑战，我们认为 Apache Spark 项目理想地定位于帮助解决这些主题，从数据摄入和特征提取/创建到模型构建和部署。我们故意将本章保持简短，言辞轻松，因为我们认为通过示例和不同的用例来工作是比抽象地和冗长地谈论某个数据科学主题更好的利用时间。在本书的其余部分，我们将专注于这个过程，同时给出最佳实践建议和推荐阅读，以供希望学习更多的用户参考。请记住，在着手进行下一个数据科学项目之前，一定要在前期清晰地定义问题，这样您就可以向数据提出一个明智的问题，并（希望）得到一个明智的答案！

一个关于数据科学的很棒的网站是 KDnuggets（[`www.kdnuggets.com`](http://www.kdnuggets.com)）。这里有一篇关于所有数据科学家必须学习的语言的好文章，以便取得成功（[`www.kdnuggets.com/2015/09/one-language-data-scientist-must-master.html`](http://www.kdnuggets.com/2015/09/one-language-data-scientist-must-master.html)）。


# 第二章：探测暗物质 - 弥散子粒子

真或假？积极或消极？通过还是不通过？用户点击广告与不点击广告？如果你以前曾经问过/遇到过这些问题，那么你已经熟悉*二元分类*的概念。

在其核心，二元分类 - 也称为*二项分类* - 试图使用分类规则将一组元素分类为两个不同的组，而在我们的情况下，可以是一个机器学习算法。本章将展示如何在 Spark 和大数据的背景下处理这个问题。我们将解释和演示：

+   Spark MLlib 二元分类模型包括决策树、随机森林和梯度提升机

+   H2O 中的二元分类支持

+   在参数的超空间中寻找最佳模型

+   二项模型的评估指标

# Type I 与 Type II 错误

二元分类器具有直观的解释，因为它们试图将数据点分成两组。这听起来很简单，但我们需要一些衡量这种分离质量的概念。此外，二元分类问题的一个重要特征是，通常一个标签组的比例与另一个标签组的比例可能不成比例。这意味着数据集可能在一个标签方面不平衡，这需要数据科学家仔细解释。

例如，假设我们试图在 1500 万人口中检测特定罕见疾病的存在，并且我们发现 - 使用人口的大子集 - 只有 10,000 或 1 千万人实际上携带疾病。如果不考虑这种巨大的不成比例，最天真的算法会简单地猜测剩下的 500 万人中“没有疾病存在”，仅仅因为子集中有 0.1%的人携带疾病。假设在剩下的 500 万人中，同样的比例，0.1%，携带疾病，那么这 5000 人将无法被正确诊断，因为天真的算法会简单地猜测没有人携带疾病。这种情况下，二元分类所带来的错误的*成本*是需要考虑的一个重要因素，这与所提出的问题有关。

考虑到我们只处理这种类型问题的两种结果，我们可以创建一个二维表示可能的不同类型错误的表示。保持我们之前的例子，即携带/不携带疾病的人，我们可以将我们的分类规则的结果考虑如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00014.jpeg)

图 1 - 预测和实际值之间的关系

从上表中可以看出，绿色区域代表我们在个体中*正确*预测疾病的存在/不存在，而白色区域代表我们的预测是错误的。这些错误的预测分为两类，称为**Type I**和**Type II**错误：

+   **Type I 错误**：当我们拒绝零假设（即一个人没有携带疾病），而实际上，实际上是真的

+   **Type II 错误**：当我们预测个体携带疾病时，实际上个体并没有携带疾病

显然，这两种错误都不好，但在实践中，有些错误比其他错误更可接受。

考虑这样一种情况，即我们的模型产生的 II 型错误明显多于 I 型错误；在这种情况下，我们的模型会预测患病的人数比实际上更多 - 保守的方法可能比我们未能识别疾病存在的 II 型错误更为*可接受*。确定每种错误的*成本*是所提出的问题的函数，这是数据科学家必须考虑的事情。在我们建立第一个尝试预测希格斯玻色子粒子存在/不存在的二元分类模型之后，我们将重新讨论错误和模型质量的一些其他指标。

# 寻找希格斯玻色子粒子

2012 年 7 月 4 日，来自瑞士日内瓦的欧洲 CERN 实验室的科学家们提出了强有力的证据，证明了他们认为是希格斯玻色子的粒子，有时被称为*上帝粒子*。为什么这一发现如此有意义和重要？正如知名物理学家和作家迈克·卡库所写：

"在量子物理学中，是一种类似希格斯的粒子引发了宇宙大爆炸（即大爆炸）。换句话说，我们周围看到的一切，包括星系、恒星、行星和我们自己，都归功于希格斯玻色子。"

用通俗的话来说，希格斯玻色子是赋予物质质量的粒子，并为地球最初的形成提供了可能的解释，因此在主流媒体渠道中备受欢迎。

# LHC 和数据生成

为了检测希格斯玻色子的存在，科学家们建造了人造最大的机器，称为日内瓦附近的**大型强子对撞机**（**LHC**）。LHC 是一个环形隧道，长 27 公里（相当于伦敦地铁的环线），位于地下 100 米。

通过这条隧道，亚原子粒子在磁铁的帮助下以接近光速的速度相反方向发射。一旦达到临界速度，粒子就被放在碰撞轨道上，探测器监视和记录碰撞。有数以百万计的碰撞和亚碰撞！ - 而由此产生的*粒子碎片*有望检测到希格斯玻色子的存在。

# 希格斯玻色子的理论

相当长一段时间以来，物理学家已经知道一些基本粒子具有质量，这与标准模型的数学相矛盾，该模型规定这些粒子应该是无质量的。在 20 世纪 60 年代，彼得·希格斯和他的同事们通过研究大爆炸后的宇宙挑战了这个质量难题。当时，人们普遍认为粒子应该被视为量子果冻中的涟漪，而不是彼此弹来弹去的小台球。希格斯认为，在这个早期时期，所有的粒子果冻都像水一样稀薄；但随着宇宙开始*冷却*，一个粒子果冻，最初被称为*希格斯场*，开始凝结变厚。因此，其他粒子果冻在与希格斯场相互作用时，由于惯性而被吸引；根据艾萨克·牛顿爵士的说法，任何具有惯性的粒子都应该含有质量。这种机制解释了标准模型中的粒子如何获得质量 - 起初是无质量的。因此，每个粒子获得的质量量与其感受到希格斯场影响的强度成正比。

文章[`plus.maths.org/content/particle-hunting-lhc-higgs-boson`](https://plus.maths.org/content/particle-hunting-lhc-higgs-boson)是对好奇读者的一个很好的信息来源。

# 测量希格斯玻色子

测试这个理论回到了粒子果冻波纹的最初概念，特别是希格斯果冻，它 a）可以波动，b）在实验中会类似于一个粒子：臭名昭著的希格斯玻色子。那么科学家们如何利用 LHC 检测这种波纹呢？

为了监测碰撞和碰撞后的结果，科学家们设置了探测器，它们就像三维数字摄像机，测量来自碰撞的粒子轨迹。这些轨迹的属性 - 即它们在磁场中的弯曲程度 - 被用来推断生成它们的粒子的各种属性；一个非常常见的可以测量的属性是电荷，据信希格斯玻色子存在于 120 到 125 吉电子伏特之间。也就是说，如果探测器发现一个电荷存在于这两个范围之间的事件，这将表明可能存在一个新的粒子，这可能是希格斯玻色子的迹象。

# 数据集

2012 年，研究人员向科学界发布了他们的研究结果，随后公开了 LHC 实验的数据，他们观察到并确定了一种信号，这种信号表明存在希格斯玻色子粒子。然而，在积极的发现中存在大量的背景噪音，这导致数据集内部不平衡。我们作为数据科学家的任务是构建一个机器学习模型，能够准确地从背景噪音中识别出希格斯玻色子粒子。你现在应该考虑这个问题的表述方式，这可能表明这是一个二元分类问题（即，这个例子是希格斯玻色子还是背景噪音？）。

您可以从[`archive.ics.uci.edu/ml/datasets/HIGGS`](https://archive.ics.uci.edu/ml/datasets/HIGGS)下载数据集，或者使用本章的`bin`文件夹中的`getdata.sh`脚本。

这个文件有 2.6 吉字节（未压缩），包含了 1100 万个被标记为 0 - 背景噪音和 1 - 希格斯玻色子的例子。首先，您需要解压缩这个文件，然后我们将开始将数据加载到 Spark 中进行处理和分析。数据集总共有 29 个字段：

+   字段 1：类别标签（1 = 希格斯玻色子信号，2 = 背景噪音）

+   字段 2-22：来自碰撞探测器的 21 个“低级”特征

+   字段 23-29：由粒子物理学家手工提取的七个“高级”特征，用于帮助将粒子分类到适当的类别（希格斯或背景噪音）

在本章的后面，我们将介绍一个**深度神经网络**（**DNN**）的例子，它将尝试通过非线性转换层来*学习*这些手工提取的特征。

请注意，为了本章的目的，我们将使用数据的一个子集，即前 100,000 行，但我们展示的所有代码也适用于原始数据集。

# Spark 启动和数据加载

现在是时候启动一个 Spark 集群了，这将为我们提供 Spark 的所有功能，同时还允许我们使用 H2O 算法和可视化我们的数据。和往常一样，我们必须从[`spark.apache.org/downloads.html`](http://spark.apache.org/downloads.html)下载 Spark 2.1 分发版，并在执行之前声明执行环境。例如，如果您从 Spark 下载页面下载了`spark-2.1.1-bin-hadoop2.6.tgz`，您可以按照以下方式准备环境：

```scala
tar -xvf spark-2.1.1-bin-hadoop2.6.tgz 
export SPARK_HOME="$(pwd)/spark-2.1.1-bin-hadoop2.6 
```

当环境准备好后，我们可以使用 Sparkling Water 包和本书包启动交互式 Spark shell：

```scala
export SPARKLING_WATER_VERSION="2.1.12"
export SPARK_PACKAGES=\
"ai.h2o:sparkling-water-core_2.11:${SPARKLING_WATER_VERSION},\
ai.h2o:sparkling-water-repl_2.11:${SPARKLING_WATER_VERSION},\
ai.h2o:sparkling-water-ml_2.11:${SPARKLING_WATER_VERSION},\
com.packtpub:mastering-ml-w-spark-utils:1.0.0"

$SPARK_HOME/bin/spark-shell \      

            --master 'local[*]' \
            --driver-memory 4g \
            --executor-memory 4g \
            --packages "$SPARK_PACKAGES"

```

H2O.ai 一直在与 Spark 项目的最新版本保持同步，以匹配 Sparkling Water 的版本。本书使用 Spark 2.1.1 分发版和 Sparkling Water 2.1.12。您可以在[`h2o.ai/download/`](http://h2o.ai/download/)找到适用于您版本 Spark 的最新版本 Sparkling Water。

本案例使用提供的 Spark shell，该 shell 下载并使用 Sparkling Water 版本 2.1.12 的 Spark 软件包。这些软件包由 Maven 坐标标识 - 在本例中，`ai.h2o`代表组织 ID，`sparkling-water-core`标识 Sparkling Water 实现（对于 Scala 2.11，因为 Scala 版本不兼容），最后，`2.1.12`是软件包的版本。此外，我们正在使用本书特定的软件包，该软件包提供了一些实用工具。

所有已发布的 Sparkling Water 版本列表也可以在 Maven 中央仓库上找到：[`search.maven.org`](http://search.maven.org)

该命令在本地模式下启动 Spark - 也就是说，Spark 集群在您的计算机上运行一个单节点。假设您成功完成了所有这些操作，您应该会看到标准的 Spark shell 输出，就像这样：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00015.jpeg)

图 2 - 注意 shell 启动时显示的 Spark 版本。

提供的书籍源代码为每一章提供了启动 Spark 环境的命令；对于本章，您可以在`chapter2/bin`文件夹中找到它。

Spark shell 是一个基于 Scala 的控制台应用程序，它接受 Scala 代码并以交互方式执行。下一步是通过导入我们将在示例中使用的软件包来准备计算环境。

```scala
import org.apache.spark.mllib 
import org.apache.spark.mllib.regression.LabeledPoint 
import org.apache.spark.mllib.linalg._ 
import org.apache.spark.mllib.linalg.distributed.RowMatrix 
import org.apache.spark.mllib.util.MLUtils 
import org.apache.spark.mllib.evaluation._ 
import org.apache.spark.mllib.tree._ 
import org.apache.spark.mllib.tree.model._ 
import org.apache.spark.rdd._ 
```

让我们首先摄取您应该已经下载的`.csv`文件，并快速计算一下我们的子集中有多少数据。在这里，请注意，代码期望数据文件夹"data"相对于当前进程的工作目录或指定的位置：

```scala
val rawData = sc.textFile(s"${sys.env.get("DATADIR").getOrElse("data")}/higgs100k.csv")
println(s"Number of rows: ${rawData.count}") 

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00016.jpeg)

您可以观察到执行命令`sc.textFile(...)`几乎没有花费时间并立即返回，而执行`rawData.count`花费了大部分时间。这正好展示了 Spark **转换**和**操作**之间的区别。按设计，Spark 采用**惰性评估** - 这意味着如果调用了一个转换，Spark 会直接记录它到所谓的**执行图/计划**中。这非常适合大数据世界，因为用户可以堆叠转换而无需等待。另一方面，操作会评估执行图 - Spark 会实例化每个记录的转换，并将其应用到先前转换的输出上。这个概念还帮助 Spark 在执行之前分析和优化执行图 - 例如，Spark 可以重新组织转换的顺序，或者决定如果它们是独立的话并行运行转换。

现在，我们定义了一个转换，它将数据加载到 Spark 数据结构`RDD[String]`中，其中包含输入数据文件的所有行。因此，让我们看一下前两行：

```scala
rawData.take(2) 
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00017.jpeg)

前两行包含从文件加载的原始数据。您可以看到一行由一个响应列组成，其值为 0,1（行的第一个值），其他列具有实际值。但是，这些行仍然表示为字符串，并且需要解析和转换为常规行。因此，基于对输入数据格式的了解，我们可以定义一个简单的解析器，根据逗号将输入行拆分为数字：

```scala
val data = rawData.map(line => line.split(',').map(_.toDouble)) 

```

现在我们可以提取响应列（数据集中的第一列）和表示输入特征的其余数据：

```scala
val response: RDD[Int] = data.map(row => row(0).toInt)   
val features: RDD[Vector] = data.map(line => Vectors.dense(line.slice(1, line.size))) 
```

进行这个转换之后，我们有两个 RDD：

+   一个代表响应列

+   另一个包含持有单个输入特征的数字的密集向量

接下来，让我们更详细地查看输入特征并进行一些非常基本的数据分析：

```scala
val featuresMatrix = new RowMatrix(features) 
val featuresSummary = featuresMatrix.computeColumnSummaryStatistics() 
```

我们将这个向量转换为分布式*RowMatrix*。这使我们能够执行简单的摘要统计（例如，计算均值、方差等）。

```scala

import org.apache.spark.utils.Tabulizer._ 
println(s"Higgs Features Mean Values = ${table(featuresSummary.mean, 8)}")

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00018.jpeg)

看一下以下代码：

```scala
println(s"Higgs Features Variance Values = ${table(featuresSummary.variance, 8)}") 

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00019.jpeg)

接下来，让我们更详细地探索列。我们可以直接获取每列中非零值的数量，以确定数据是密集还是稀疏。密集数据主要包含非零值，稀疏数据则相反。数据中非零值的数量与所有值的数量之间的比率代表了数据的稀疏度。稀疏度可以驱动我们选择计算方法，因为对于稀疏数据，仅迭代非零值更有效：

```scala
val nonZeros = featuresSummary.numNonzeros 
println(s"Non-zero values count per column: ${table(nonZeros, cols = 8, format = "%.0f")}") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00020.jpeg)

然而，该调用只是给出了所有列的非零值数量，这并不那么有趣。我们更感兴趣的是包含一些零值的列：

```scala
val numRows = featuresMatrix.numRows
 val numCols = featuresMatrix.numCols
 val colsWithZeros = nonZeros
   .toArray
   .zipWithIndex
   .filter { case (rows, idx) => rows != numRows }
 println(s"Columns with zeros:\n${table(Seq("#zeros", "column"), colsWithZeros, Map.empty[Int, String])}")
```

在这种情况下，我们通过每个值的索引增加了原始的非零向量，然后过滤掉原始矩阵中等于行数的所有值。然后我们得到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00021.jpeg)

我们可以看到列 8、12、16 和 20 包含一些零数，但仍然不足以将矩阵视为稀疏。为了确认我们的观察，我们可以计算矩阵的整体稀疏度（剩余部分：矩阵不包括响应列）：

```scala
val sparsity = nonZeros.toArray.sum / (numRows * numCols)
println(f"Data sparsity: ${sparsity}%.2f") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00022.jpeg)

计算出的数字证实了我们之前的观察 - 输入矩阵是密集的。

现在是时候更详细地探索响应列了。作为第一步，我们通过计算响应向量中的唯一值来验证响应是否只包含值`0`和`1`：

```scala
val responseValues = response.distinct.collect
 println(s"Response values: ${responseValues.mkString(", ")}") 
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00023.jpeg)

下一步是探索响应向量中标签的分布。我们可以直接通过 Spark 计算速率：

```scala
val responseDistribution = response.map(v => (v,1)).countByKey
 println(s"Response distribution:\n${table(responseDistribution)}") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00024.jpeg)

在这一步中，我们简单地将每行转换为表示行值的元组，以及表示该值在行中出现一次的`1`。拥有成对 RDDs 后，Spark 方法`countByKey`通过键聚合成对，并给我们提供了键计数的摘要。它显示数据意外地包含了略微更多代表希格斯玻色子的情况，但我们仍然可以认为响应是平衡的。

我们还可以利用 H2O 库以可视化的方式探索标签分布。为此，我们需要启动由`H2OContext`表示的 H2O 服务：

```scala
import org.apache.spark.h2o._ 
val h2oContext = H2OContext.getOrCreate(sc) 

```

该代码初始化了 H2O 库，并在 Spark 集群的每个节点上启动了 H2O 服务。它还提供了一个名为 Flow 的交互式环境，用于数据探索和模型构建。在控制台中，`h2oContext`打印出了暴露的 UI 的位置：

```scala
h2oContext: org.apache.spark.h2o.H2OContext =  
Sparkling Water Context: 
 * H2O name: sparkling-water-user-303296214 
 * number of executors: 1 
 * list of used executors: 
  (executorId, host, port) 
  ------------------------ 
  (driver,192.168.1.65,54321) 
  ------------------------ 
  Open H2O Flow in browser: http://192.168.1.65:54321 (CMD + click in Mac OSX) 
```

现在我们可以直接打开 Flow UI 地址并开始探索数据。但是，在这样做之前，我们需要将 Spark 数据发布为名为`response`的 H2O 框架：

```scala
val h2oResponse = h2oContext.asH2OFrame(response, "response")
```

如果您导入了`H2OContext`公开的隐式转换，您将能够根据赋值左侧的定义类型透明地调用转换：

例如：

```scala
import h2oContext.implicits._ 
val h2oResponse: H2OFrame = response 
```

现在是时候打开 Flow UI 了。您可以通过访问`H2OContext`报告的 URL 直接打开它，或者在 Spark shell 中键入`h2oContext.openFlow`来打开它。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00025.jpeg)

图 3 - 交互式 Flow UI

Flow UI 允许与存储的数据进行交互式工作。让我们通过在突出显示的单元格中键入`getFrames`来查看 Flow 暴露的数据：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00026.jpeg)

图 4 - 获取可用的 H2O 框架列表

通过点击响应字段或键入`getColumnSummary "response", "values"`，我们可以直观地确认响应列中值的分布，并看到问题略微不平衡：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00027.jpeg)

图 5 - 名为“response”的列的统计属性。

# 标记点向量

在使用 Spark MLlib 运行任何监督机器学习算法之前，我们必须将数据集转换为标记点向量，将特征映射到给定的标签/响应；标签存储为双精度，这有助于它们用于分类和回归任务。对于所有二元分类问题，标签应存储为`0`或`1`，我们从前面的摘要统计中确认了这一点对我们的例子成立。

```scala
val higgs = response.zip(features).map {  
case (response, features) =>  
LabeledPoint(response, features) } 

higgs.setName("higgs").cache() 
```

标记点向量的示例如下：

```scala
(1.0, [0.123, 0.456, 0.567, 0.678, ..., 0.789]) 
```

在前面的例子中，括号内的所有双精度数都是特征，括号外的单个数字是我们的标签。请注意，我们尚未告诉 Spark 我们正在执行分类任务而不是回归任务，这将在稍后发生。

在这个例子中，所有输入特征只包含数值，但在许多情况下，数据包含分类值或字符串数据。所有这些非数值表示都需要转换为数字，我们将在本书的后面展示。

# 数据缓存

许多机器学习算法具有迭代性质，因此需要对数据进行多次遍历。然而，默认情况下，存储在 Spark RDD 中的所有数据都是瞬时的，因为 RDD 只存储要执行的转换，而不是实际数据。这意味着每个操作都会通过执行 RDD 中存储的转换重新计算数据。

因此，Spark 提供了一种持久化数据的方式，以便我们需要对其进行迭代。Spark 还发布了几个`StorageLevels`，以允许使用各种选项存储数据：

+   `NONE`：根本不缓存

+   `MEMORY_ONLY`：仅在内存中缓存 RDD 数据

+   `DISK_ONLY`：将缓存的 RDD 数据写入磁盘并释放内存

+   `MEMORY_AND_DISK`：如果无法将数据卸载到磁盘，则在内存中缓存 RDD

+   `OFF_HEAP`：使用不属于 JVM 堆的外部内存存储

此外，Spark 为用户提供了以两种方式缓存数据的能力：*原始*（例如`MEMORY_ONLY`）和*序列化*（例如`MEMORY_ONLY_SER`）。后者使用大型内存缓冲区直接存储 RDD 的序列化内容。使用哪种取决于任务和资源。一个很好的经验法则是，如果你正在处理的数据集小于 10 吉字节，那么原始缓存优于序列化缓存。然而，一旦超过 10 吉字节的软阈值，原始缓存比序列化缓存占用更大的内存空间。

Spark 可以通过在 RDD 上调用`cache()`方法或直接通过调用带有所需持久目标的 persist 方法（例如`persist(StorageLevels.MEMORY_ONLY_SER)`）来强制缓存。有用的是 RDD 只允许我们设置存储级别一次。

决定缓存什么以及如何缓存是 Spark 魔术的一部分；然而，黄金法则是在需要多次访问 RDD 数据并根据应用程序偏好选择目标时使用缓存，尊重速度和存储。一个很棒的博客文章比这里提供的更详细，可以在以下链接找到：

[`sujee.net/2015/01/22/understanding-spark-caching/#.VpU1nJMrLdc`](http://sujee.net/2015/01/22/understanding-spark-caching/#.VpU1nJMrLdc)

缓存的 RDD 也可以通过在 H2O Flow UI 中评估带有`getRDDs`的单元格来访问：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00028.jpeg)

# 创建训练和测试集

与大多数监督学习任务一样，我们将创建数据集的拆分，以便在一个子集上*教*模型，然后测试其对新数据的泛化能力，以便与留出集进行比较。在本例中，我们将数据拆分为 80/20，但是拆分比例没有硬性规定，或者说 - 首先应该有多少拆分：

```scala
// Create Train & Test Splits 
val trainTestSplits = higgs.randomSplit(Array(0.8, 0.2)) 
val (trainingData, testData) = (trainTestSplits(0), trainTestSplits(1)) 
```

通过在数据集上创建 80/20 的拆分，我们随机抽取了 880 万个示例作为训练集，剩下的 220 万个作为测试集。我们也可以随机抽取另一个 80/20 的拆分，并生成一个具有相同数量示例（880 万个）但具有不同数据的新训练集。这种*硬*拆分我们原始数据集的方法引入了抽样偏差，这基本上意味着我们的模型将学会拟合训练数据，但训练数据可能不代表“现实”。鉴于我们已经使用了 1100 万个示例，这种偏差并不像我们的原始数据集只有 100 行的情况那样显著。这通常被称为模型验证的**留出法**。

您还可以使用 H2O Flow 来拆分数据：

1.  将希格斯数据发布为 H2OFrame：

```scala
val higgsHF = h2oContext.asH2OFrame(higgs.toDF, "higgsHF") 
```

1.  在 Flow UI 中使用`splitFrame`命令拆分数据（见*图 07*）。

1.  然后将结果发布回 RDD。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00029.jpeg)

图 7 - 将希格斯数据集拆分为代表 80%和 20%数据的两个 H2O 框架。

与 Spark 的惰性评估相比，H2O 计算模型是急切的。这意味着`splitFrame`调用会立即处理数据并创建两个新框架，可以直接访问。

# 交叉验证呢？

通常，在较小的数据集的情况下，数据科学家会使用一种称为交叉验证的技术，这种技术在 Spark 中也可用。`CrossValidator`类首先将数据集分成 N 折（用户声明），每个折叠被用于训练集 N-1 次，并用于模型验证 1 次。例如，如果我们声明希望使用**5 折交叉验证**，`CrossValidator`类将创建五对（训练和测试）数据集，使用四分之四的数据集创建训练集，最后四分之一作为测试集，如下图所示。

我们的想法是，我们将看到我们的算法在不同的随机抽样数据集上的性能，以考虑我们在 80%的数据上创建训练/测试拆分时固有的抽样偏差。一个不太好泛化的模型的例子是，准确性（例如整体错误）会在不同的错误率上大幅度变化，这表明我们需要重新考虑我们的模型。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00030.jpeg)

图 8 - 5 折交叉验证的概念模式。

关于应该执行多少次交叉验证并没有固定的规则，因为这些问题在很大程度上取决于所使用的数据类型、示例数量等。在某些情况下，进行极端的交叉验证是有意义的，其中 N 等于输入数据集中的数据点数。在这种情况下，**测试**集只包含一行。这种方法称为**留一法**（**LOO**）验证，计算成本更高。

一般来说，建议在模型构建过程中进行一些交叉验证（通常建议使用 5 折或 10 折交叉验证），以验证模型的质量 - 尤其是当数据集很小的时候。

# 我们的第一个模型 - 决策树

我们尝试使用决策树算法来对希格斯玻色子和背景噪音进行分类。我们故意不解释这个算法背后的直觉，因为这已经有大量支持文献供读者消化（[`www.saedsayad.com/decision_tree.htm`](http://www.saedsayad.com/decision_tree.htm), http://spark.apache.org/docs/latest/mllib-decision-tree.html）。相反，我们将专注于超参数以及如何根据特定标准/错误度量来解释模型的有效性。让我们从基本参数开始：

```scala
val numClasses = 2 
val categoricalFeaturesInfo = Map[Int, Int]() 
val impurity = "gini" 
val maxDepth = 5 
val maxBins = 10 
```

现在我们明确告诉 Spark，我们希望构建一个决策树分类器，用于区分两类。让我们更仔细地看看我们决策树的一些超参数，看看它们的含义：

`numClasses`：我们要分类多少类？在这个例子中，我们希望区分希格斯玻色子粒子和背景噪音，因此有四类：

+   `categoricalFeaturesInfo`：一种规范，声明哪些特征是分类特征，不应被视为数字（例如，邮政编码是一个常见的例子）。在这个数据集中，我们不需要担心有分类特征。

+   `杂质`：节点标签同质性的度量。目前在 Spark 中，关于分类有两种杂质度量：基尼和熵，回归有一个杂质度量：方差。

+   `maxDepth`：限制构建树的深度的停止准则。通常，更深的树会导致更准确的结果，但也会有过拟合的风险。

+   `maxBins`：树在进行分裂时考虑的箱数（考虑“值”）。通常，增加箱数允许树考虑更多的值，但也会增加计算时间。

# 基尼与熵

为了确定使用哪种杂质度量，重要的是我们先了解一些基础知识，从**信息增益**的概念开始。

在本质上，信息增益就是它听起来的样子：在两种状态之间移动时的信息增益。更准确地说，某个事件的信息增益是事件发生前后已知信息量的差异。衡量这种信息的一种常见方法是查看**熵**，可以定义为：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00031.jpeg)

其中*p[j]*是节点上标签*j*的频率。

现在您已经了解了信息增益和熵的概念，我们可以继续了解**基尼指数**的含义（与基尼系数完全没有关联）。

**基尼指数**：是一个度量，表示如果随机选择一个元素，根据给定节点的标签分布随机分配标签，它会被错误分类的频率。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00032.jpeg)

与熵的方程相比，由于没有对数计算，基尼指数的计算速度应该稍快一些，这可能是为什么它是许多其他机器学习库（包括 MLlib）的**默认**选项。

但这是否使它成为我们决策树分裂的**更好**度量？事实证明，杂质度量的选择对于单个决策树算法的性能几乎没有影响。根据谭等人在《数据挖掘导论》一书中的说法，原因是：

“...这是因为杂质度量在很大程度上是一致的 [...]. 实际上，用于修剪树的策略对最终树的影响大于杂质度量的选择。”

现在是时候在训练数据上训练我们的决策树分类器了：

```scala
val dtreeModel = DecisionTree.trainClassifier( 
trainingData,  
numClasses,  
categoricalFeaturesInfo, 
impurity,  
maxDepth,  
maxBins) 

// Show the tree 
println("Decision Tree Model:\n" + dtreeModel.toDebugString) 
```

这应该产生一个最终输出，看起来像这样（请注意，由于数据的随机分割，您的结果可能会略有不同）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00033.jpeg)

输出显示决策树的深度为`5`，有`63`个节点按层次化的决策谓词组织。让我们继续解释一下，看看前五个*决策*。它的读法是：“如果特征 25 的值小于或等于 1.0559 并且小于或等于 0.61558 并且特征 27 的值小于或等于 0.87310 并且特征 5 的值小于或等于 0.89683 并且最后，特征 22 的值小于或等于 0.76688，那么预测值为 1.0（希格斯玻色子）。但是，这五个条件必须满足才能成立。”请注意，如果最后一个条件不成立（特征 22 的值大于 0.76688），但前四个条件仍然成立，那么预测将从 1 变为 0，表示背景噪音。

现在，让我们对我们的测试数据集对模型进行评分并打印预测错误：

```scala
val treeLabelAndPreds = testData.map { point =>
   val prediction = dtreeModel.predict(point.features)
   (point.label.toInt, prediction.toInt)
 }

 val treeTestErr = treeLabelAndPreds.filter(r => r._1 != r._2).count.toDouble / testData.count()
 println(f"Tree Model: Test Error = ${treeTestErr}%.3f") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00034.jpeg)

一段时间后，模型将对所有测试集数据进行评分，然后计算一个我们在前面的代码中定义的错误率。同样，你的错误率可能会略有不同，但正如我们所展示的，我们的简单决策树模型的错误率约为 33%。然而，正如你所知，我们可能会犯不同类型的错误，因此值得探索一下通过构建混淆矩阵来了解这些错误类型是什么：

```scala
val cm = treeLabelAndPreds.combineByKey( 
  createCombiner = (label: Int) => if (label == 0) (1,0) else (0,1),  
  mergeValue = (v:(Int,Int), label:Int) => if (label == 0) (v._1 +1, v._2) else (v._1, v._2 + 1), 
  mergeCombiners = (v1:(Int,Int), v2:(Int,Int)) => (v1._1 + v2._1, v1._2 + v2._2)).collect 
```

前面的代码使用了高级的 Spark 方法`combineByKey`，它允许我们将每个(K,V)对映射到一个值，这个值将代表按键操作的输出。在这种情况下，(K,V)对表示实际值 K 和预测值 V。我们通过创建一个组合器（参数`createCombiner`）将每个预测映射到一个元组 - 如果预测值为`0`，则映射为`(1,0)`；否则，映射为`(0,1)`。然后我们需要定义组合器如何接受新值以及如何合并组合器。最后，该方法产生：

```scala
cm: Array[(Int, (Int, Int))] = Array((0,(5402,4131)), (1,(2724,7846))) 
```

生成的数组包含两个元组 - 一个用于实际值`0`，另一个用于实际值`1`。每个元组包含预测`0`和`1`的数量。因此，很容易提取所有必要的内容来呈现一个漂亮的混淆矩阵。

```scala
val (tn, tp, fn, fp) = (cm(0)._2._1, cm(1)._2._2, cm(1)._2._1, cm(0)._2._2) 
println(f"""Confusion Matrix 
  |   ${0}%5d ${1}%5d  ${"Err"}%10s 
  |0  ${tn}%5d ${fp}%5d ${tn+fp}%5d ${fp.toDouble/(tn+fp)}%5.4f 
  |1  ${fn}%5d ${tp}%5d ${fn+tp}%5d ${fn.toDouble/(fn+tp)}%5.4f 
  |   ${tn+fn}%5d ${fp+tp}%5d ${tn+fp+fn+tp}%5d ${(fp+fn).toDouble/(tn+fp+fn+tp)}%5.4f 
  |""".stripMargin) 
```

该代码提取了所有真负和真正的预测，还有错过的预测和基于*图 9*模板的混淆矩阵的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00035.jpeg)

在前面的代码中，我们使用了一个强大的 Scala 特性，称为*字符串插值*：`println(f"...")`。它允许通过组合字符串输出和实际的 Scala 变量来轻松构造所需的输出。Scala 支持不同的字符串“插值器”，但最常用的是*s*和*f*。*s*插值器允许引用任何 Scala 变量甚至代码：`s"True negative: ${tn}"`。而*f*插值器是类型安全的 - 这意味着用户需要指定要显示的变量类型：`f"True negative: ${tn}%5d"` - 并引用变量`tn`作为十进制类型，并要求在五个十进制空间上打印。

回到本章的第一个例子，我们可以看到我们的模型在检测实际的玻色子粒子时出现了大部分错误。在这种情况下，代表玻色子检测的所有数据点都被错误地分类为非玻色子。然而，总体错误率非常低！这是一个很好的例子，说明总体错误率可能会对具有不平衡响应的数据集产生误导。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00036.jpeg)

图 9 - 混淆矩阵模式。

接下来，我们将考虑另一个用于评判分类模型的建模指标，称为**曲线下面积**（受试者工作特征）**AUC**（请参见下图示例）。**受试者工作特征**（**ROC**）曲线是**真正率**与**假正率**的图形表示：

+   真正阳性率：真正阳性的总数除以真正阳性和假阴性的总和。换句话说，它是希格斯玻色子粒子的真实信号（实际标签为 1）与希格斯玻色子的所有预测信号（我们的模型预测标签为 1）的比率。该值显示在*y*轴上。

+   假正率：假阳性的总数除以假阳性和真阴性的总和，这在*x*轴上绘制。

+   有关更多指标，请参见“从混淆矩阵派生的指标”图。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00037.jpeg)

图 10 - 具有 AUC 值 0.94 的样本 AUC 曲线

由此可见，ROC 曲线描绘了我们的模型在给定决策阈值下 TPR 与 FPR 的权衡。因此，ROC 曲线下的面积可以被视为*平均模型准确度*，其中 1.0 代表完美分类，0.5 代表抛硬币（意味着我们的模型在猜测 1 或 0 时做了一半的工作），小于 0.5 的任何值都意味着抛硬币比我们的模型更准确！这是一个非常有用的指标，我们将看到它可以用来与不同的超参数调整和不同的模型进行比较！让我们继续创建一个函数，用于计算我们的决策树模型的 AUC，以便与其他模型进行比较：

```scala
type Predictor = {  
  def predict(features: Vector): Double 
} 

def computeMetrics(model: Predictor, data: RDD[LabeledPoint]): BinaryClassificationMetrics = { 
    val predAndLabels = data.map(newData => (model.predict(newData.features), newData.label)) 
      new BinaryClassificationMetrics(predAndLabels) 
} 

val treeMetrics = computeMetrics(dtreeModel, testData) 
println(f"Tree Model: AUC on Test Data = ${treeMetrics.areaUnderROC()}%.3f") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00038.jpeg)

Spark MLlib 模型没有共同的接口定义；因此，在前面的例子中，我们必须定义类型`Predictor`，公开方法`predict`并在方法`computeMetrics`的定义中使用 Scala 结构化类型。本书的后面部分将展示基于统一管道 API 的 Spark ML 包。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00039.jpeg)

图 11 - 从混淆矩阵派生的指标。

对这个主题感兴趣吗？没有一本圣经是万能的。斯坦福大学著名统计学教授 Trevor Hastie 的书《统计学习的要素》是一个很好的信息来源。这本书为机器学习的初学者和高级实践者提供了有用的信息，强烈推荐。

需要记住的是，由于 Spark 决策树实现在内部使用`RandomForest`算法，如果未指定随机生成器的种子，运行之间的结果可能会略有不同。问题在于 Spark 的 MLLib API`DecisionTree`不允许将种子作为参数传递。

# 下一个模型 - 树集成

随机森林（RF）或梯度提升机（GBM）（也称为梯度提升树）等算法是目前在 MLlib 中可用的集成基于树的模型的两个例子；您可以将集成视为代表基本模型集合的*超级模型*。想要了解集成在幕后的工作原理，最好的方法是考虑一个简单的类比：

“假设你是一家著名足球俱乐部的主教练，你听说了一位来自巴西的不可思议的运动员的传闻，签下这位年轻运动员可能对你的俱乐部有利，但你的日程安排非常繁忙，所以你派了 10 名助理教练去评估这位球员。你的每一位助理教练都根据他/她的教练理念对球员进行评分——也许有一位教练想要测量球员跑 40 码的速度，而另一位教练认为身高和臂展很重要。无论每位教练如何定义“运动员潜力”，你作为主教练，只想知道你是否应该立即签下这位球员或者等待。于是你的教练们飞到巴西，每位教练都做出了评估；到达后，你走到每位教练面前问：“我们现在应该选这位球员还是等一等？”根据多数投票的简单规则，你可以做出决定。这是一个关于集成在分类任务中背后所做的事情的例子。”

您可以将每个教练看作是一棵决策树，因此您将拥有 10 棵树的集合（对应 10 个教练）。每个教练如何评估球员都是非常具体的，我们的树也是如此；对于创建的 10 棵树，每个节点都会随机选择特征（因此 RF 中有随机性，因为有很多树！）。引入这种随机性和其他基本模型的原因是防止过度拟合数据。虽然 RF 和 GBM 都是基于树的集合，但它们训练的方式略有不同，值得一提。

GBM 必须一次训练一棵树，以最小化`loss`函数（例如`log-loss`，平方误差等），通常比 RF 需要更长的时间来训练，因为 RF 可以并行生成多棵树。

然而，在训练 GBM 时，建议制作浅树，这反过来有助于更快的训练。

+   RFs 通常不像 GBM 那样过度拟合数据；也就是说，我们可以向我们的森林中添加更多的树，而不容易过度拟合，而如果我们向我们的 GBM 中添加更多的树，就更容易过度拟合。

+   RF 的超参数调整比 GBM 简单得多。在他的论文《超参数对随机森林准确性的影响》中，Bernard 等人通过实验证明，在每个节点选择的 K 个随机特征数是模型准确性的关键影响因素。相反，GBM 有更多必须考虑的超参数，如`loss`函数、学习率、迭代次数等。

与大多数数据科学中的“哪个更好”问题一样，选择 RF 和 GBM 是开放式的，非常依赖任务和数据集。

# 随机森林模型

现在，让我们尝试使用 10 棵决策树构建一个随机森林。

```scala
val numClasses = 2 
val categoricalFeaturesInfo = Map[Int, Int]() 
val numTrees = 10 
val featureSubsetStrategy = "auto"  
val impurity = "gini" 
val maxDepth = 5 
val maxBins = 10 
val seed = 42 

val rfModel = RandomForest.trainClassifier(trainingData, numClasses, categoricalFeaturesInfo, 
  numTrees, featureSubsetStrategy, impurity, maxDepth, maxBins, seed) 

```

就像我们的单棵决策树模型一样，我们首先声明超参数，其中许多参数您可能已经从决策树示例中熟悉。在前面的代码中，我们将创建一个由 10 棵树解决两类问题的随机森林。一个不同的关键特性是特征子集策略，描述如下：

`featureSubsetStrategy`对象给出了要在每个节点进行分割的候选特征数。可以是一个分数（例如 0.5），也可以是基于数据集中特征数的函数。设置`auto`允许算法为您选择这个数字，但一个常见的软规则是使用您拥有的特征数的平方根。

现在我们已经训练好了我们的模型，让我们对我们的留出集进行评分并计算总误差：

```scala
def computeError(model: Predictor, data: RDD[LabeledPoint]): Double = {  
  val labelAndPreds = data.map { point => 
    val prediction = model.predict(point.features) 
    (point.label, prediction) 
  } 
  labelAndPreds.filter(r => r._1 != r._2).count.toDouble/data.count 
} 
val rfTestErr = computeError(rfModel, testData) 
println(f"RF Model: Test Error = ${rfTestErr}%.3f") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00040.jpeg)

还可以使用已定义的`computeMetrics`方法计算 AUC：

```scala

val rfMetrics = computeMetrics(rfModel, testData) 
println(f"RF Model: AUC on Test Data = ${rfMetrics.areaUnderROC}%.3f") 
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00041.jpeg)

我们的 RF - 在其中硬编码超参数 - 相对于整体模型错误和 AUC 表现得比我们的单棵决策树要好得多。在下一节中，我们将介绍网格搜索的概念以及我们如何尝试变化超参数值/组合并衡量对模型性能的影响。

再次强调，结果在运行之间可能略有不同。但是，与决策树相比，可以通过将种子作为`RandomForest.trainClassifier`方法的参数传递来使运行确定性。

# 网格搜索

在 MLlib 和 H2O 中，与大多数算法一样，有许多可以选择的超参数，这些超参数对模型的性能有显著影响。鉴于可能存在无限数量的组合，我们是否可以以智能的方式开始查看哪些组合比其他组合更有前途？幸运的是，答案是“YES！”解决方案被称为网格搜索，这是运行使用不同超参数组合的许多模型的 ML 术语。

让我们尝试使用 RF 算法运行一个简单的网格搜索。在这种情况下，RF 模型构建器被调用，用于从定义的超参数空间中的每个参数组合：

```scala
val rfGrid =  
    for ( 
    gridNumTrees <- Array(15, 20); 
    gridImpurity <- Array("entropy", "gini"); 
    gridDepth <- Array(20, 30); 
    gridBins <- Array(20, 50)) 
        yield { 
    val gridModel = RandomForest.trainClassifier(trainingData, 2, Map[Int, Int](), gridNumTrees, "auto", gridImpurity, gridDepth, gridBins) 
    val gridAUC = computeMetrics(gridModel, testData).areaUnderROC 
    val gridErr = computeError(gridModel, testData) 
    ((gridNumTrees, gridImpurity, gridDepth, gridBins), gridAUC, gridErr) 
  } 
```

我们刚刚写的是一个`for`循环，它将尝试不同组合的数量，涉及树的数量、不纯度类型、树的深度和 bin 值（即要尝试的值）；然后，对于基于这些超参数排列组合创建的每个模型，我们将对训练模型进行评分，同时计算 AUC 指标和整体错误率。总共我们得到*2*2*2*2=16*个模型。再次强调，您的模型可能与我们在此处展示的模型略有不同，但您的输出应该类似于这样：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00042.jpeg)

查看我们输出的第一个条目：

```scala
|(15,entropy,20,20)|0.697|0.302|
```

我们可以这样解释：对于 15 棵决策树的组合，使用熵作为我们的不纯度度量，以及树深度为 20（对于每棵树）和 bin 值为 20，我们的 AUC 为`0.695`。请注意，结果按照您最初编写它们的顺序显示。对于我们使用 RF 算法的网格搜索，我们可以轻松地获得产生最高 AUC 的超参数组合：

```scala
val rfParamsMaxAUC = rfGrid.maxBy(g => g._2)
println(f"RF Model: Parameters ${rfParamsMaxAUC._1}%s producing max AUC = ${rfParamsMaxAUC._2}%.3f (error = ${rfParamsMaxAUC._3}%.3f)") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00043.jpeg)

# 梯度提升机

到目前为止，我们能够达到的最佳 AUC 是一个 15 棵决策树的 RF，其 AUC 值为`0.698`。现在，让我们通过相同的过程来运行一个使用硬编码超参数的单个梯度提升机，然后对这些参数进行网格搜索，以查看是否可以使用该算法获得更高的 AUC。

回顾一下，由于其迭代性质试图减少我们事先声明的总体`loss`函数，GBM 与 RF 略有不同。在 MLlib 中，截至 1.6.0，有三种不同的损失函数可供选择：

+   **对数损失**：对于分类任务使用这个`loss`函数（请注意，对于 Spark，GBM 仅支持二元分类。如果您希望对多类分类使用 GBM，请使用 H2O 的实现，我们将在下一章中展示）。

+   **平方误差**：对于回归任务使用这个`loss`函数，它是这种类型问题的当前默认`loss`函数。

+   **绝对误差**：另一个可用于回归任务的`loss`函数。鉴于该函数取预测值和实际值之间的绝对差异，它比平方误差更好地控制异常值。

考虑到我们的二元分类任务，我们将使用`log-loss`函数并开始构建一个 10 棵树的 GBM 模型：

```scala
import org.apache.spark.mllib.tree.GradientBoostedTrees
 import org.apache.spark.mllib.tree.configuration.BoostingStrategy
 import org.apache.spark.mllib.tree.configuration.Algo

 val gbmStrategy = BoostingStrategy.defaultParams(Algo.Classification)
 gbmStrategy.setNumIterations(10)
 gbmStrategy.setLearningRate(0.1)
 gbmStrategy.treeStrategy.setNumClasses(2)
 gbmStrategy.treeStrategy.setMaxDepth(10)
 gbmStrategy.treeStrategy.setCategoricalFeaturesInfo(java.util.Collections.emptyMap[Integer, Integer])

 val gbmModel = GradientBoostedTrees.train(trainingData, gbmStrategy)
```

请注意，我们必须在构建模型之前声明一个提升策略。原因是 MLlib 不知道我们要解决什么类型的问题：分类还是回归？因此，这个策略让 Spark 知道这是一个二元分类问题，并使用声明的超参数来构建我们的模型。

以下是一些训练 GBM 时要记住的超参数：

+   `numIterations`：根据定义，GBM 一次构建一棵树，以最小化我们声明的`loss`函数。这个超参数控制要构建的树的数量；要小心不要构建太多的树，因为测试时的性能可能不理想。

+   `loss`：您声明使用哪个`loss`函数取决于所提出的问题和数据集。

+   `learningRate`：优化学习速度。较低的值（<0.1）意味着学习速度较慢，泛化效果更好。然而，它也需要更多的迭代次数，因此计算时间更长。

让我们对保留集对这个模型进行评分，并计算我们的 AUC：

```scala
val gbmTestErr = computeError(gbmModel, testData) 
println(f"GBM Model: Test Error = ${gbmTestErr}%.3f") 
val gbmMetrics = computeMetrics(dtreeModel, testData) 
println(f"GBM Model: AUC on Test Data = ${gbmMetrics.areaUnderROC()}%.3f") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00044.jpeg)

最后，我们将对一些超参数进行网格搜索，并且与我们之前的 RF 网格搜索示例类似，输出组合及其相应的错误和 AUC 计算：

```scala
val gbmGrid =  
for ( 
  gridNumIterations <- Array(5, 10, 50); 
  gridDepth <- Array(2, 3, 5, 7); 
  gridLearningRate <- Array(0.1, 0.01))  
yield { 
  gbmStrategy.numIterations = gridNumIterations 
  gbmStrategy.treeStrategy.maxDepth = gridDepth 
  gbmStrategy.learningRate = gridLearningRate 

  val gridModel = GradientBoostedTrees.train(trainingData, gbmStrategy) 
  val gridAUC = computeMetrics(gridModel, testData).areaUnderROC 
  val gridErr = computeError(gridModel, testData) 
  ((gridNumIterations, gridDepth, gridLearningRate), gridAUC, gridErr) 
} 
```

我们可以打印前 10 行结果，按 AUC 排序：

```scala
println(
s"""GBM Model: Grid results:
      |${table(Seq("iterations, depth, learningRate", "AUC", "error"), gbmGrid.sortBy(-_._2).take(10), format = Map(1 -> "%.3f", 2 -> "%.3f"))}
""".stripMargin)
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00045.jpeg)

而且我们可以很容易地得到产生最大 AUC 的模型：

```scala
val gbmParamsMaxAUC = gbmGrid.maxBy(g => g._2) 
println(f"GBM Model: Parameters ${gbmParamsMaxAUC._1}%s producing max AUC = ${gbmParamsMaxAUC._2}%.3f (error = ${gbmParamsMaxAUC._3}%.3f)") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00046.jpeg)

# 最后一个模型-H2O 深度学习

到目前为止，我们使用 Spark MLlib 构建了不同的模型；然而，我们也可以使用 H2O 算法。所以让我们试试吧！

首先，我们将我们的训练和测试数据集传输到 H2O，并为我们的二元分类问题创建一个 DNN。重申一遍，这是可能的，因为 Spark 和 H2O 共享相同的 JVM，这有助于将 Spark RDD 传递到 H2O 六角框架，反之亦然。

到目前为止，我们运行的所有模型都是在 MLlib 中，但现在我们将使用 H2O 来使用相同的训练和测试集构建一个 DNN，这意味着我们需要将这些数据发送到我们的 H2O 云中，如下所示：

```scala
val trainingHF = h2oContext.asH2OFrame(trainingData.toDF, "trainingHF") 
val testHF = h2oContext.asH2OFrame(testData.toDF, "testHF") 
```

为了验证我们已成功转移我们的训练和测试 RDD（我们转换为数据框），我们可以在我们的 Flow 笔记本中执行这个命令（所有命令都是用*Shift+Enter*执行的）。请注意，我们现在有两个名为`trainingRDD`和`testRDD`的 H2O 框架，您可以通过运行命令`getFrames`在我们的 H2O 笔记本中看到。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00047.jpeg)

图 12 - 通过在 Flow UI 中输入“getFrames”可以查看可用的 H2O 框架列表。

我们可以很容易地探索框架，查看它们的结构，只需在 Flow 单元格中键入`getFrameSummary "trainingHF"`，或者只需点击框架名称（参见*图 13*）。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00048.jpeg)

图 13 - 训练框架的结构。

上图显示了训练框架的结构-它有 80,491 行和 29 列；有名为*features0*、*features1*的数值列，具有实际值，第一列标签包含整数值。

由于我们想进行二元分类，我们需要将“label”列从整数转换为分类类型。您可以通过在 Flow UI 中点击*Convert to enum*操作或在 Spark 控制台中执行以下命令来轻松实现：

```scala
trainingHF.replace(0, trainingHF.vecs()(0).toCategoricalVec).remove() 
trainingHF.update() 

testHF.replace(0, testHF.vecs()(0).toCategoricalVec).remove() 
testHF.update() 
```

该代码将第一个向量替换为转换后的向量，并从内存中删除原始向量。此外，调用`update`将更改传播到共享的分布式存储中，因此它们对集群中的所有节点都是可见的。

# 构建一个 3 层 DNN

H2O 暴露了略有不同的构建模型的方式；然而，它在所有 H2O 模型中是统一的。有三个基本构建模块：

+   **模型参数**：定义输入和特定算法参数

+   **模型构建器**：接受模型参数并生成模型

+   **模型**：包含模型定义，但也包括有关模型构建的技术信息，如每次迭代的得分时间或错误率。

在构建我们的模型之前，我们需要为深度学习算法构建参数：

```scala
import _root_.hex.deeplearning._ 
import DeepLearningParameters.Activation 

val dlParams = new DeepLearningParameters() 
dlParams._train = trainingHF._key 
dlParams._valid = testHF._key 
dlParams._response_column = "label" 
dlParams._epochs = 1 
dlParams._activation = Activation.RectifierWithDropout 
dlParams._hidden = ArrayInt 
```

让我们浏览一下参数，并找出我们刚刚初始化的模型：

+   `train`和`valid`：指定我们创建的训练和测试集。请注意，这些 RDD 实际上是 H2O 框架。

+   `response_column`：指定我们使用的标签，我们之前声明的是每个框架中的第一个元素（从 0 开始索引）。

+   `epochs`：这是一个非常重要的参数，它指定网络应该在训练数据上传递多少次；通常，使用更高`epochs`训练的模型允许网络*学习*新特征并产生更好的模型结果。然而，这种训练时间较长的网络容易出现过拟合，并且可能在新数据上泛化效果不佳。

+   `激活`：这些是将应用于输入数据的各种非线性函数。在 H2O 中，有三种主要的激活函数可供选择：

+   `Rectifier`：有时被称为**整流线性单元**（**ReLU**），这是一个函数，其下限为**0**，但以线性方式达到正无穷大。从生物学的角度来看，这些单元被证明更接近实际的神经元激活。目前，这是 H2O 中默认的激活函数，因为它在图像识别和速度等任务中的结果。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00049.jpeg)

图 14 - 整流器激活函数

+   `Tanh`：一个修改后的逻辑函数，其范围在**-1**和**1**之间，但在(0,0)处通过原点。由于其在**0**周围的对称性，收敛通常更快。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00050.jpeg)

图 15 - 双曲正切激活函数和逻辑函数 - 注意双曲正切之间的差异。

+   `Maxout`：一种函数，其中每个神经元选择来自 k 个单独通道的最大值：

+   **hidden**：另一个非常重要的超参数，这是我们指定两件事的地方：

+   层的数量（您可以使用额外的逗号创建）。请注意，在 GUI 中，默认参数是一个具有每层 200 个隐藏神经元的两层隐藏网络。

+   每层的神经元数量。与大多数关于机器学习的事情一样，关于这个数字应该是多少并没有固定的规则，通常最好进行实验。然而，在下一章中，我们将介绍一些额外的调整参数，这将帮助您考虑这一点，即：L1 和 L2 正则化和丢失。

# 添加更多层

增加网络层的原因来自于我们对人类视觉皮层工作原理的理解。这是大脑后部的一个专门区域，用于识别物体/图案/数字等，并由复杂的神经元层组成，用于编码视觉信息并根据先前的知识进行分类。

毫不奇怪，网络需要多少层才能产生良好的结果并没有固定的规则，强烈建议进行实验！

# 构建模型和检查结果

现在您已经了解了一些关于参数和我们想要运行的模型的信息，是时候继续训练和检查我们的网络了：

```scala
val dl = new DeepLearning(dlParams) 
val dlModel = dl.trainModel.get 
```

代码创建了`DeepLearning`模型构建器并启动了它。默认情况下，`trainModel`的启动是异步的（即它不会阻塞，但会返回一个作业），但可以通过调用`get`方法等待计算结束。您还可以在 UI 中探索作业进度，甚至可以通过在 Flow UI 中键入`getJobs`来探索未完成的模型（参见*图 18*）。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00051.jpeg)

图 18 - 命令 getJobs 提供了一个已执行作业的列表及其状态。

计算的结果是一个深度学习模型 - 我们可以直接从 Spark shell 探索模型及其细节：

```scala
println(s"DL Model: ${dlModel}") 
```

我们还可以通过调用模型的`score`方法直接获得测试数据的预测框架：

```scala
val testPredictions = dlModel.score(testHF) 

testPredictions: water.fvec.Frame = 
Frame _95829d4e695316377f96db3edf0441ee (19912 rows and 3 cols): 
         predict                   p0                    p1 
    min           0.11323123896925524  0.017864442175851737 
   mean            0.4856033079851807    0.5143966920148184 
 stddev            0.1404849885490033   0.14048498854900326 
    max            0.9821355578241482    0.8867687610307448 
missing                           0.0                   0.0 
      0        1   0.3908680007591152    0.6091319992408847 
      1        1   0.3339873797352686    0.6660126202647314 
      2        1   0.2958578897481016    0.7041421102518984 
      3        1   0.2952981947808155    0.7047018052191846 
      4        0   0.7523906949762337   0.24760930502376632 
      5        1   0.53559438105240... 
```

表格包含三列：

+   `predict`：基于默认阈值的预测值

+   `p0`：选择类 0 的概率

+   `p1`：选择类 1 的概率

我们还可以获得测试数据的模型指标：

```scala
import water.app.ModelMetricsSupport._ 
val dlMetrics = binomialMM(dlModel, testHF) 

```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00052.jpeg)

输出直接显示了 AUC 和准确率（相应的错误率）。请注意，该模型在预测希格斯玻色子方面确实很好；另一方面，它的假阳性率很高！

最后，让我们看看如何使用 GUI 构建类似的模型，只是这一次，我们将从模型中排除物理学家手工提取的特征，并在内部层使用更多的神经元：

1.  选择用于 TrainingHF 的模型。

正如您所看到的，H2O 和 MLlib 共享许多相同的算法，但功能级别不同。在这里，我们将选择*深度学习*，然后取消选择最后八个手工提取的特征。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00053.jpeg)

图 19- 选择模型算法

1.  构建 DNN 并排除手工提取的特征。

在这里，我们手动选择忽略特征 21-27，这些特征代表物理学家提取的特征，希望我们的网络能够学习它们。还要注意，如果选择这条路线，还可以执行 k 折交叉验证。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00054.jpeg)

图 20 - 选择输入特征。

1.  指定网络拓扑。

正如您所看到的，我们将使用整流器激活函数构建一个三层 DNN，其中每一层将有 1,024 个隐藏神经元，并且将运行 100 个`epochs`。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00055.jpeg)

图 21 - 配置具有 3 层，每层 1024 个神经元的网络拓扑。

1.  探索模型结果。

运行此模型后，需要一些时间，我们可以单击“查看”按钮来检查训练集和测试集的 AUC：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00056.jpeg)

图 22 - 验证数据的 AUC 曲线。

如果您点击鼠标并在 AUC 曲线的某个部分上拖放，实际上可以放大该曲线的特定部分，并且 H2O 会提供有关所选区域的阈值的准确性和精度的摘要统计信息。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00057.jpeg)

图 23 - ROC 曲线可以轻松探索以找到最佳阈值。

此外，还有一个标有预览**普通的 Java 对象**（**POJO**）的小按钮，我们将在后面的章节中探讨，这是您将模型部署到生产环境中的方式。

好的，我们已经建立了几十个模型；现在是时候开始检查我们的结果，并找出哪一个在整体错误和 AUC 指标下给我们最好的结果。有趣的是，当我们在办公室举办许多聚会并与顶级 kagglers 交谈时，这些显示结果的表格经常被构建，这是一种跟踪 a）什么有效和什么无效的好方法，b）回顾您尝试过的东西作为一种文档形式。

| 模型 | 错误 | AUC |
| --- | --- | --- |
| 决策树 | 0.332 | 0.665 |
| 网格搜索：随机森林 | 0.294 | 0.704 |
| **网格搜索：GBM** | **0.287** | **0.712** |
| 深度学习 - 所有特征 | 0.376 | 0.705 |
| 深度学习 - 子集特征 | 0.301 | 0.716 |

那么我们选择哪一个？在这种情况下，我们喜欢 GBM 模型，因为它提供了第二高的 AUC 值和最低的准确率。但是这个决定总是由建模目标驱动 - 在这个例子中，我们严格受到模型在发现希格斯玻色子方面的准确性的影响；然而，在其他情况下，选择正确的模型或模型可能会受到各种方面的影响 - 例如，找到并构建最佳模型的时间。

# 摘要

本章主要讨论了二元分类问题：真或假，对于我们的示例来说，信号是否表明希格斯玻色子或背景噪音？我们已经探索了四种不同的算法：单决策树、随机森林、梯度提升机和 DNN。对于这个确切的问题，DNN 是当前的世界冠军，因为这些模型可以继续训练更长时间（即增加`epochs`的数量），并且可以添加更多的层。

除了探索四种算法以及如何对许多超参数执行网格搜索之外，我们还研究了一些重要的模型指标，以帮助您更好地区分模型并了解如何定义“好”的方式。我们本章的目标是让您接触到不同算法和 Spark 和 H2O 中的调整，以解决二元分类问题。在下一章中，我们将探讨多类分类以及如何创建模型集成（有时称为超学习者）来找到我们真实示例的良好解决方案。


# 第三章：多类分类的集成方法

我们现代世界已经与许多收集有关人类行为数据的设备相互连接-例如，我们的手机是我们口袋里的小间谍，跟踪步数、路线或我们的饮食习惯。甚至我们现在戴的手表也可以追踪从我们走的步数到我们在任何给定时刻的心率的一切。

在所有这些情况下，这些小工具试图根据收集的数据猜测用户正在做什么，以提供一天中用户活动的报告。从机器学习的角度来看，这个任务可以被视为一个分类问题：在收集的数据中检测模式，并将正确的活动类别分配给它们（即，游泳、跑步、睡觉）。但重要的是，这仍然是一个监督问题-这意味着为了训练模型，我们需要提供由实际类别注释的观察。

在本节中，我们将重点关注集成方法来建模多类分类问题，有时也称为多项分类，使用 UCI 数据集库提供的传感器数据集。

请注意，多类分类不应与多标签分类混淆，多标签分类可以为给定示例预测多个标签。例如，一篇博客文章可以被标记为多个标签，因为一篇博客可以涵盖任意数量的主题；然而，在多类分类中，我们*被迫*选择一个*N*个可能主题中的一个，其中*N >* 2 个可能标签。

读者将在本章学习以下主题：

+   为多类分类准备数据，包括处理缺失值

+   使用 Spark RF 算法进行多类分类

+   使用不同的指标评估 Spark 分类模型的质量

+   构建 H2O 基于树的分类模型并探索其质量

# 数据

在本章中，我们将使用由尔湾大学机器学习库发布的**Physical Activity Monitoring Data Set**（**PAMAP2**）：[`archive.ics.uci.edu/ml/datasets/PAMAP2+Physical+Activity+Monitoring`](https://archive.ics.uci.edu/ml/datasets/PAMAP2+Physical+Activity+Monitoring)

完整的数据集包含**52**个输入特征和**3,850,505**个事件，描述了 18 种不同的身体活动（例如，步行、骑车、跑步、看电视）。数据是由心率监测器和三个惯性测量单元记录的，分别位于手腕、胸部和主侧踝部。每个事件都由描述地面真相的活动标签和时间戳进行注释。数据集包含由值`NaN`表示的缺失值。此外，一些传感器生成的列被标记为无效（“方向”-请参阅数据集描述）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00058.jpeg)

图 1：由尔湾大学机器学习库发布的数据集属性。

该数据集代表了活动识别的完美示例：我们希望训练一个强大的模型，能够根据来自物理传感器的输入数据来预测执行的活动。

此外，数据集分布在多个文件中，每个文件代表一个单个主体的测量，这是由多个数据源产生的数据的另一个现实方面，因此我们需要利用 Spark 从目录中读取并合并文件以创建训练/测试数据集的能力。

以下行显示了数据的一个样本。有几个重要的观察值值得注意：

+   个别值由空格字符分隔

+   每行中的第一个值表示时间戳，而第二个值保存了`activityId`

```scala
199.38 0 NaN 34.1875 1.54285 7.86975 5.88674 1.57679 7.65264 5.84959 -0.0855996 ... 1 0 0 0 
199.39 11 NaN 34.1875 1.46513 7.94554 5.80834 1.5336 7.81914 5.92477 -0.0907069 ...  1 0 0 0 
199.4 11 NaN 34.1875 1.41585 7.82933 5.5001 1.56628 8.03042 6.01488 -0.0399161 ...  1 0 0 0 
```

`activityId`由数字值表示；因此，我们需要一个翻译表来将 ID 转换为相应的活动标签，数据集提供了这个翻译表，我们如下所示：

| 1 躺着 | 2 坐着 |
| --- | --- |
| 3 站立 | 4 步行 |
| 5 跑步 | 6 骑车 |
| 7 挪威步行 | 9 看电视 |
| 10 电脑工作 | 11 开车 |
| 12 上楼梯 | 13 下楼梯 |
| 16 吸尘 | 17 熨烫 |
| 18 叠衣服 | 19 打扫房子 |
| 20 踢足球 | 24 跳绳 |
| 0 其他（瞬态活动） |  |

示例行代表一个“其他活动”，然后是两个代表“开车”的测量值。

第三列包含心率测量，而其余列代表来自三种不同惯性测量单位的数据：列 4-20 来自手部传感器，21-37 包含来自胸部传感器的数据，最后列 38-54 包含踝部传感器的测量数据。每个传感器测量 17 个不同的值，包括温度、3D 加速度计、陀螺仪和磁力计数据以及方向。然而，在这个数据集中，方向列被标记为无效。

输入数据包含两个不同的文件夹 - 协议和可选测量，其中包含一些执行了一些额外活动的受试者的数据。在本章中，我们将只使用可选文件夹中的数据。

# 建模目标

在这个例子中，我们希望基于有关身体活动的信息构建模型，以对未知数据进行分类并用相应的身体活动进行注释。

# 挑战

对于传感器数据，有许多探索和构建模型的方法。在本章中，我们主要关注分类；然而，有几个方面需要更深入的探索，特别是以下方面：

+   训练数据代表了一系列事件的时间顺序流，但我们不打算反映时间信息，而是将数据视为一整个完整的信息

+   测试数据也是一样 - 单个活动事件是在执行活动期间捕获的事件流的一部分，如果了解实际上下文，可能更容易对其进行分类

然而，目前，我们忽略时间维度，并应用分类来探索传感器数据中可能存在的模式，这些模式将表征执行的活动。

# 机器学习工作流程

为了构建初始模型，我们的工作流程包括几个步骤：

1.  数据加载和预处理，通常称为**提取-转换-加载**（**ETL**）。

+   加载

+   解析

+   处理缺失值

1.  将数据统一成算法所期望的形式。

+   模型训练

+   模型评估

+   模型部署

# 启动 Spark shell

第一步是准备 Spark 环境进行分析。与上一章一样，我们将启动 Spark shell；但是，在这种情况下，命令行稍微复杂一些：

```scala
export SPARKLING_WATER_VERSION="2.1.12" 
export SPARK_PACKAGES=\ 
"ai.h2o:sparkling-water-core_2.11:${SPARKLING_WATER_VERSION},\ 
ai.h2o:sparkling-water-repl_2.11:${SPARKLING_WATER_VERSION},\ 
ai.h2o:sparkling-water-ml_2.11:${SPARKLING_WATER_VERSION},\ 
com.packtpub:mastering-ml-w-spark-utils:1.0.0" 

$SPARK_HOME/bin/spark-shell \ 
        --master 'local[*]' \ 
        --driver-memory 8g \ 
        --executor-memory 8g \ 
        --conf spark.executor.extraJavaOptions=-XX:MaxPermSize=384M
        \ 
        --conf spark.driver.extraJavaOptions=-XX:MaxPermSize=384M \ 
        --packages "$SPARK_PACKAGES" 
```

在这种情况下，我们需要更多的内存，因为我们将加载更大的数据。我们还需要增加 PermGen 的大小 - JVM 内存的一部分，它存储有关加载的类的信息。只有在使用 Java 7 时才需要这样做。

Spark 作业的内存设置是作业启动的重要部分。在我们使用的简单的基于`local[*]`的场景中，Spark 驱动程序和执行程序之间没有区别。然而，对于部署在独立或 YARN Spark 集群上的较大作业，驱动程序内存和执行程序内存的配置需要反映数据的大小和执行的转换。

此外，正如我们在上一章中讨论的，您可以通过使用巧妙的缓存策略和正确的缓存目的地（例如磁盘，离堆内存）来减轻内存压力。

# 探索数据

第一步涉及数据加载。在多个文件的情况下，SparkContext 的`wholeTextFiles`方法提供了我们需要的功能。它将每个文件读取为单个记录，并将其作为键值对返回，其中键包含文件的位置，值包含文件内容。我们可以通过通配符模式`data/subject*`直接引用输入文件。这不仅在从本地文件系统加载文件时很有用，而且在从 HDFS 加载文件时尤为重要。

```scala
val path = s"${sys.env.get("DATADIR").getOrElse("data")}/subject*"
val dataFiles = sc.wholeTextFiles(path)
println(s"Number of input files: ${dataFiles.count}")
```

由于名称不是输入数据的一部分，我们定义一个变量来保存列名：

```scala
val allColumnNames = Array( 
  "timestamp", "activityId", "hr") ++ Array( 
  "hand", "chest", "ankle").flatMap(sensor => 
    Array( 
      "temp",  
      "accel1X", "accel1Y", "accel1Z", 
      "accel2X", "accel2Y", "accel2Z", 
      "gyroX", "gyroY", "gyroZ", 
      "magnetX", "magnetY", "magnetZ", 
      "orientX", "orientY", "orientZ"). 
    map(name => s"${sensor}_${name}")) 
```

我们简单地定义了前三个列名，然后是每个三个位置传感器的列名。此外，我们还准备了一个在建模中无用的列索引列表，包括时间戳和方向数据：

```scala
val ignoredColumns =  
  Array(0,  
    3 + 13, 3 + 14, 3 + 15, 3 + 16, 
    20 + 13, 20 + 14, 20 + 15, 20 + 16, 
    37 + 13, 37 + 14, 37 + 15, 37 + 16) 
```

下一步是处理引用文件的内容并创建一个`RDD`，我们将其用作数据探索和建模的输入。由于我们希望多次迭代数据并执行不同的转换，我们将在内存中缓存数据：

```scala
val rawData = dataFiles.flatMap { case (path, content) =>  
  content.split("\n") 
}.map { row =>  
  row.split(" ").map(_.trim). 
  zipWithIndex. 
  map(v => if (v.toUpperCase == "NAN") Double.NaN else v.toDouble). 
  collect {  
    case (cell, idx) if !ignoredColumns.contains(idx) => cell 
  } 
} 
rawData.cache() 

println(s"Number of rows: ${rawData.count}") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00059.jpeg)

在这种情况下，对于每个键值对，我们提取其内容并根据行边界进行拆分。然后我们根据文件分隔符对每行进行转换，该分隔符是特征之间的空格。由于文件只包含数值和字符串值`NaN`作为缺失值的标记，我们可以简单地将所有值转换为 Java 的`Double`，将`Double.NaN`作为缺失值的表示。

我们可以看到我们的输入文件有 977,972 行。在加载过程中，我们还跳过了时间戳列和数据集描述中标记为无效的列（参见`ignoredColumns`数组）。

RDD 的接口遵循函数式编程的设计原则，这个原则也被 Scala 编程语言采用。这个共享的概念为操作数据结构提供了统一的 API；另一方面，了解何时在本地对象（数组、列表、序列）上调用操作，以及何时导致分布操作（`RDD`）是很重要的。

为了保持数据集的一致视图，我们还需要根据在先前步骤中准备的忽略列的列表来过滤列名：

```scala
import org.apache.spark.utils.Tabulizer._
 val columnNames = allColumnNames.
   zipWithIndex.
   filter { case (_, idx) => !ignoredColumns.contains(idx) }.
   map { case (name, _) => name }

 println(s"Column names:${table(columnNames, 4, None)}") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00060.jpeg)

始终要摆脱对建模无用的数据。动机是在计算和建模过程中减轻内存压力。例如，可以删除包含随机 ID、时间戳、常量列或已在数据集中表示的列等的列。

从直觉上讲，例如对建模 ID 术语进行建模并不太有意义，考虑到该领域的性质。特征选择是一个非常重要的话题，我们将在本书的后面花费大量时间来讨论这个话题。

现在让我们看看数据集中个体活动的分布。我们将使用与上一章相同的技巧；但是，我们也希望看到活动的实际名称，而不仅仅是基于数字的表示。因此，首先我们定义了描述活动编号与其名称之间关系的映射：

```scala
val activities = Map( 
  1 -> "lying", 2 -> "sitting", 3 -> "standing", 4 -> "walking",  
  5 -> "running", 6 -> "cycling", 7 -> "Nordic walking",  
  9 -> "watching TV", 10 -> "computer work", 11 -> "car driving", 
 12 -> "ascending stairs", 13 -> "descending stairs",  
 16 -> "vacuum cleaning", 17 -> "ironing", 
 18 -> "folding laundry", 19 -> "house cleaning", 
 20 -> "playing soccer", 24 -> "rope jumping", 0 -> "other") 

```

然后我们使用 Spark 方法`reduceByKey`计算数据中个体活动的数量。

```scala
val dataActivityId = rawData.map(l => l(0).toInt)

 val activityIdCounts = dataActivityId.
   map(n => (n, 1)).
   reduceByKey(_ + _)

 val activityCounts = activityIdCounts.
   collect.
   sortBy { case (activityId, count) =>
     -count
 }.map { case (activityId, count) =>
   (activitiesMap(activityId), count)
 }

 println(s"Activities distribution:${table({activityCounts})}")
```

该命令计算个体活动的数量，将活动编号转换为其标签，并根据计数按降序对结果进行排序：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00061.jpeg)

或者根据活动频率进行可视化，如*图 2*所示。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00062.jpeg)

图 2：输入数据中不同活动的频率。

始终要考虑对数据应用的个体转换的顺序。在前面的例子中，我们在使用 Spark `collect`操作将所有数据收集到本地后应用了`sortBy`转换。在这种情况下，这是有道理的，因为我们知道`collect`操作的结果是相当小的（我们只有 22 个活动标签），而`sortBy`是应用在本地集合上的。另一方面，在`collect`操作之前放置`sortBy`会强制调用 Spark RDD 的转换，并安排排序作为 Spark 分布式任务。

# 缺失数据

数据描述提到用于活动跟踪的传感器并不完全可靠，结果包含缺失数据。我们需要更详细地探索它们，看看这个事实如何影响我们的建模策略。

第一个问题是我们的数据集中有多少缺失值。我们从数据描述中知道，所有缺失值都由字符串`NaN`标记（即，不是一个数字），现在在`RDD` `rawData`中表示为`Double.NaN`。在下一个代码片段中，我们计算每行的缺失值数量和数据集中的总缺失值数量：

```scala
val nanCountPerRow = rawData.map { row => 
  row.foldLeft(0) { case (acc, v) =>  
    acc + (if (v.isNaN) 1 else 0)  
  } 
} 
val nanTotalCount = nanCount.sum 

val ncols = rawData.take(1)(0).length 
val nrows = rawData.count 

val nanRatio = 100.0 * nanTotalCount / (ncols * nrows)  

println(f"""|NaN count = ${nanTotalCount}%.0f 
            |NaN ratio = ${nanRatio}%.2f %%""".stripMargin) 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00063.jpeg)

现在，我们已经对我们的数据中缺失值的数量有了整体的了解。但我们不知道缺失值是如何分布的。它们是均匀分布在整个数据集上吗？还是有包含更多缺失值的行/列？在接下来的文本中，我们将尝试找到这些问题的答案。

一个常见的错误是使用比较运算符比较数值和`Double.NaN`。例如，`if (v == Double.NaN) { ... }`是错误的，因为 Java 规范规定：

"`NaN`是无序的：（1）如果一个或两个操作数是`NaN`，则数值比较运算符`<`、`<=`、`>`和`>=`返回`false`，（2）等式运算符`==`如果任一操作数是`NaN`，则返回`false`。"

因此，`Double.NaN == Double.NaN`总是返回`false`。用正确的方式比较数值和`Double.NaN`是使用`isNaN`方法：`if (v.isNaN) { ... }`（或使用相应的静态方法`java.lang.Double.isNaN`）。

首先，考虑到我们已经计算了上一步中每行的缺失值数量。对它们进行排序并取唯一值，让我们了解到行是如何受缺失值影响的：

```scala
val nanRowDistribution = nanCountPerRow.
   map( count => (count, 1)).
   reduceByKey(_ + _).sortBy(-_._1).collect

 println(s"${table(Seq("#NaN","#Rows"), nanRowDistribution, Map.empty[Int, String])}") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00064.jpeg)

现在我们可以看到大多数行包含一个缺失值。然而，有很多行包含 13 或 14 个缺失值，甚至有 40 行包含 27 个*NaNs*，以及 107 行包含超过 30 个缺失值（104 行包含 40 个缺失值，3 行包含 39 个缺失值）。考虑到数据集包含 41 列，这意味着有 107 行是无用的（大部分值都缺失），剩下 3386 行至少有两个缺失值需要关注，以及 885,494 行有一个缺失值。我们现在可以更详细地查看这些行。我们选择所有包含超过给定阈值的缺失值的行，例如 26。我们还收集行的索引（这是基于零的索引！）：

```scala
val nanRowThreshold = 26 
val badRows = nanCountPerRow.zipWithIndex.zip(rawData).filter(_._1._1 > nanRowThreshold).sortBy(-_._1._1) 
println(s"Bad rows (#NaN, Row Idx, Row):\n${badRows.collect.map(x => (x._1, x._2.mkString(","))).mkString("\n")}") 
```

现在我们确切地知道哪些行是没有用的。我们已经观察到有 107 行是不好的，它们不包含任何有用的信息。此外，我们可以看到有 27 个缺失值的行是在代表手和脚踝 IMU 传感器的位置上。

最后，大多数行都分配了`activityId` 10、19 或 20，分别代表`computer work`、`house cleaning`和`playing soccer`活动，这些是数据集中频率最高的类别。这可能导致我们的理论是“坏”行是由受试者明确拒绝测量设备而产生的。此外，我们还可以看到每行错误的索引，并在输入数据集中验证它们。现在，我们将留下坏行，专注于列。

我们可以问同样的问题关于列 - 是否有任何包含更多缺失值的列？我们可以删除这样的列吗？我们可以开始收集每列的缺失值数量：

```scala
val nanCountPerColumn = rawData.map { row =>
   row.map(v => if (v.isNaN) 1 else 0)
 }.reduce((v1, v2) => v1.indices.map(i => v1(i) + v2(i)).toArray)

 println(s"""Number of missing values per column:
      ^${table(columnNames.zip(nanCountPerColumn).map(t => (t._1, t._2, "%.2f%%".format(100.0 * t._2 / nrows))).sortBy(-_._2))}
      ^""".stripMargin('^')) 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00065.jpeg)

结果显示，第二列（不要忘记我们在数据加载过程中已经删除了无效列），代表受试者心率的列，包含了大量的缺失值。超过 90%的数值被标记为`NaN`，这可能是由实验的测量过程引起的（受试者可能在日常活动中不佩戴心率监测器，只有在进行运动时才佩戴）。

其余的列包含零星的缺失值。

另一个重要的观察是，包含`activityId`的第一列不包含任何缺失值——这是个好消息，意味着所有的观察都被正确注释，我们不需要删除任何观察（例如，没有训练目标，我们就无法训练模型）。

RDD 的`reduce`方法代表动作。这意味着它强制评估`RDD`的结果，并且 reduce 的结果是一个单一的值而不是`RDD`。不要将其与`reduceByKey`混淆，后者是一个`RDD`操作，返回一个新的键值对`RDD`。

下一步是决定如何处理缺失数据。有许多策略可供选择；然而，我们需要保留数据的含义。

我们可以简单地删除包含缺失数据的所有行或列——事实上这是一个非常常见的方法！对于受到太多缺失值污染的行来说是有意义的，但在这种情况下这并不是一个好的全局策略，因为我们观察到缺失值几乎分布在所有的列和行上。因此，我们需要一个更好的策略来处理缺失值。

缺失值来源和插补方法的摘要可以在 A. Gelman 和 J. Hill 的书*Data Analysis Using Regression and Mutlilevel/Hierarchical Models*（[`www.stat.columbia.edu/~gelman/arm/missing.pdf`](http://www.stat.columbia.edu/~gelman/arm/missing.pdf)）或演示文稿[`www.amstat.org/sections/srms/webinarfiles/ModernMethodWebinarMay2012.pdf`](https://www.amstat.org/sections/srms/webinarfiles/ModernMethodWebinarMay2012.pdf)或[`www.utexas.edu/cola/prc/_files/cs/Missing-Data.pdf`](https://www.utexas.edu/cola/prc/_files/cs/Missing-Data.pdf)中找到。

首先考虑心率列，我们不能删除它，因为高心率和运动活动之间存在明显的联系。然而，我们仍然可以用一个合理的常数填充缺失值。在心率的情境下，用列值的平均值替换缺失值——有时被称为*平均计算缺失值*的技术是有意义的。我们可以用以下代码来计算它：

```scala
val heartRateColumn = rawData. 
  map(row => row(1)). 
  filter(_.isNaN). 
  map(_.toInt) 

val heartRateValues = heartRateColumn.collect 
val meanHeartRate = heartRateValues.sum / heartRateValues.count 
scala.util.Sorting.quickSort(heartRateValues) 
val medianHeartRate = heartRateValues(heartRateValues.length / 2) 

println(s"Mean heart rate: ${meanHeartRate}") 
println(s"Median heart rate: ${medianHeartRate}") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00066.jpeg)

我们可以看到`平均心率`是一个相当高的值，这反映了心率测量主要与运动活动相关（读者可以验证）。但是，例如，考虑到`看电视`这项活动，超过 90 的数值略高于预期值，因为平均静息心率在 60 到 100 之间（根据维基百科）。

因此，在这种情况下，我们可以用平均静息心率（80）替换缺失的心率值，或者我们可以采用计算得到的心率的平均值。之后，我们将填补计算得到的平均值并比较或合并结果（这称为多重插补方法）。或者我们可以附加一个标记有缺失值的列（例如，参见[`www.utexas.edu/cola/prc/_files/cs/Missing-Data.pdf`](https://www.utexas.edu/cola/prc/_files/cs/Missing-Data.pdf)）。

下一步是替换其余列中的缺失值。我们应该执行与心率列相同的分析，并查看缺失数据是否存在模式，或者它们只是随机缺失。例如，我们可以探索缺失值与我们的预测目标（在本例中为`activityId`）之间的依赖关系。因此，我们再次收集每列的缺失值数量；但是，现在我们还记住了每个缺失值的`activityId`：

```scala
def incK,V], v: (K, V)) // (3)
             (implicit num: Numeric[V]): Seq[(K,V)] =
 if (l.exists(_._1 == v._1)) l.map(e => e match {
   case (v._1, n) => (v._1, num.plus(n, v._2))
   case t => t
 }) else l ++ Seq(v)

 val distribTemplate = activityIdCounts.collect.map { case (id, _) => (id, 0) }.toSeq
 val nanColumnDistribV1 = rawData.map { row => // (1)
   val activityId = row(0).toInt
   row.drop(1).map { v =>
     if (v.isNaN) inc(distribTemplate, (activityId, 1)) else distribTemplate
   } // Tip: Make sure that we are returning same type
 }.reduce { (v1, v2) =>  // (2)
   v1.indices.map(idx => v1(idx).foldLeft(v2(idx))(inc)).toArray
 }

 println(s"""
         ^NaN Column x Response distribution V1:
         ^${table(Seq(distribTemplate.map(v => activitiesMap(v._1)))
                  ++ columnNames.drop(1).zip(nanColumnDistribV1).map(v => Seq(v._1) ++ v._2.map(_._2)), true)}
           """.stripMargin('^')) 

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00067.jpeg)

前面的代码稍微复杂，值得解释。调用`(1)`将每行中的每个值转换为`(K, V)`对的序列，其中`K`表示存储在行中的`activityId`，如果相应的列包含缺失值，则`V`为`1`，否则为`0`。然后，reduce 方法`(2)`递归地将由序列表示的行值转换为最终结果，其中每列都有一个分布，由`(K,V)`对的序列表示，其中`K`是`activityId`，`V`表示具有`activityId`的行中的缺失值数量。该方法很简单，但使用了一个非平凡的函数`inc` `(3)`，过于复杂。此外，这种天真的解决方案在内存效率上非常低，因为对于每一列，我们都重复了关于`activityId`的信息。

因此，我们可以通过略微改变结果表示来重申天真的解决方案，不是按列计算分布，而是计算所有列，每个`activityId`的缺失值计数：

```scala
val nanColumnDistribV2 = rawData.map(row => {
   val activityId = row(0).toInt
   (activityId, row.drop(1).map(v => if (v.isNaN) 1 else 0))
 }).reduceByKey( (v1, v2) =>
   v1.indices.map(idx => v1(idx) + v2(idx)).toArray
 ).map { case (activityId, d) =>
   (activitiesMap(activityId), d)
 }.collect

 println(s"""
         ^NaN Column x Response distribution V2:
         ^${table(Seq(columnNames.toSeq) ++ nanColumnDistribV2.map(v => Seq(v._1) ++ v._2), true)}
         """.stripMargin('^'))
```

在这种情况下，结果是一个键值对数组，其中键是活动名称，值包含各列中缺失值的分布。通过运行这两个样本，我们可以观察到第一个样本所需的时间比第二个样本长得多。此外，第一个样本具有更高的内存需求，而且更加复杂。

最后，我们可以将结果可视化为热图，其中*x*轴对应列，*y*轴表示活动，如图 3 所示。这样的图形表示给我们提供了一个清晰的概述，说明了缺失值如何与响应列相关：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00068.jpeg)

图 3：热图显示按活动分组的每列缺失值数量。

生成的热图很好地显示了缺失值的相关性。我们可以看到缺失值与传感器相连。如果传感器不可用或发生故障，那么所有测量值都不可用。例如，这在踝传感器和`踢足球`等其他活动中是可见的。另一方面，活动`看电视`并没有显示与传感器相关的任何缺失值模式。

此外，缺失数据与活动之间没有其他直接可见的联系。因此，目前我们可以决定用`0.0`填充缺失值，以表示缺失传感器提供默认值。但是，我们的目标是灵活地尝试不同的插补策略（例如，使用相同`activityId`的观测均值来插补）。 

# 缺失值分析摘要

现在我们可以总结我们对缺失值学到的所有事实：

+   有 107 行是无用的，需要被过滤掉

+   有 44 行有`26`或`27`个缺失值。这些行似乎是无用的，所以我们将它们过滤掉。

+   心率列包含大部分缺失值。由于我们期望该列包含可以帮助区分不同运动活动的重要信息，我们不打算忽略该列。但是，我们将根据不同的策略填补缺失值：

+   基于医学研究的平均静息心率

+   根据可用数据计算的`平均心率`

+   其余列中的缺失值存在一种模式 - 缺失值严格与传感器相关。我们将用值`0.0`替换所有这些缺失值。

# 数据统一

这种探索性分析给了我们关于数据形状和我们需要执行的操作的概述，以处理缺失值。然而，我们仍然需要将数据转换为 Spark 算法所期望的形式。这包括：

+   处理缺失值

+   处理分类值

# 缺失值

缺失值处理步骤很容易，因为我们已经在前一节中执行了缺失值探索，并总结了所需的转换。接下来的步骤将实现它们。

首先，我们定义一个缺失值列表 - 对于每一列，我们分配一个单一的`Double`值：

```scala
val imputedValues = columnNames.map { 
  _ match { 
    case "hr" => 60.0 
    case _ => 0.0 
  } 
} 
```

以及一个允许我们将值注入数据集的函数：

```scala
import org.apache.spark.rdd.RDD 
def imputeNaN( 
  data: RDD[Array[Double]],  
  values: Array[Double]): RDD[Array[Double]] = { 
    data.map { row => 
      row.indices.map { i => 
        if (row(i).isNaN) values(i) 
        else row(i) 
      }.toArray 
    } 
} 
```

定义的函数接受一个 Spark `RDD`，其中每一行都表示为一个`Double`数字数组，以及一个包含每列替换缺失值的值的参数。

在下一步中，我们定义一个行过滤器 - 一个方法，它删除包含的缺失值超过给定阈值的所有行。在这种情况下，我们可以轻松地重用已经计算的值`nanCountPerRow`：

```scala
def filterBadRows( 
  rdd: RDD[Array[Double]], 
  nanCountPerRow: RDD[Int], 
  nanThreshold: Int): RDD[Array[Double]] = { 
    rdd.zip(nanCountPerRow).filter { case (row, nanCount) => 
      nanCount > nanThreshold 
  }.map { case (row, _) => 
        row 
  } 
} 
```

请注意，我们参数化了定义的转换。保持代码足够灵活以允许进一步尝试不同的参数是一个好的做法。另一方面，最好避免构建复杂的框架。经验法则是参数化功能，我们希望在不同上下文中使用，或者我们需要在配置代码常量时具有自由度。

# 分类值

Spark 算法可以处理不同形式的分类特征，但它们需要被转换为算法所期望的形式。例如，决策树可以处理分类特征，而线性回归或神经网络需要将分类值扩展为二进制列。

在这个例子中，好消息是我们数据集中的所有输入特征都是连续的。然而，目标特征 - `activityId` - 表示多类特征。Spark MLlib 分类指南（[`spark.apache.org/docs/latest/mllib-linear-methods.html#classification`](https://spark.apache.org/docs/latest/mllib-linear-methods.html#classification)）说：

“训练数据集在 MLlib 中由 LabeledPoint 的 RDD 表示，其中标签是从零开始的类索引。”

但是我们的数据集包含不同数量的 activityIds - 参见计算的变量`activityIdCounts`。因此，我们需要通过定义从`activityId`到`activityIdx`的映射，将它们转换为 MLlib 所期望的形式：

```scala
val activityId2Idx = activityIdCounts. 
  map(_._1). 
  collect. 
  zipWithIndex. 
  toMap 
```

# 最终转换

最后，我们可以将所有定义的功能组合在一起，为模型构建准备数据。首先，`rawData` `RDD`被过滤，所有不良行都被`filterBadRows`移除，然后结果由`imputeNaN`方法处理，该方法在缺失值的位置注入给定的值：

```scala
val processedRawData = imputeNaN( 
  filterBadRows(rawData, nanCountPerRow, nanThreshold = 26), 
  imputedValues) 
```

最后，通过至少计算行数来验证我们调用了正确的转换：

```scala
println(s"Number of rows before/after: ${rawData.count} / ${ processedRawData.count}") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00069.jpeg)

我们可以看到，我们过滤掉了 151 行，这对应于我们之前的观察。

了解数据是数据科学的关键点。这也包括了解缺失数据。永远不要跳过这个阶段，因为它可能导致产生过于良好结果的偏见模型。而且，正如我们不断强调的那样，不了解你的数据将导致你提出不好的问题，最终导致乏味的答案。

# 用随机森林对数据建模

随机森林是一种可以用于不同问题的算法 - 如我们在上一章中展示的二项式，回归，或者多类分类。随机森林的美妙之处在于它将由决策树表示的多个弱学习器组合成一个整体。

此外，为了减少单个决策树的方差，算法使用了 bagging（自举聚合）的概念。每个决策树都是在通过随机选择并替换生成的数据子集上训练的。

不要混淆装袋和提升。提升通过训练每个新模型来强调先前模型错误分类的观察结果来逐步构建集成。通常，在将弱模型添加到集成后，数据会被重新加权，错误分类的观察结果会增加权重，反之亦然。此外，装袋可以并行调用，而提升是一个顺序过程。然而，提升的目标与装袋的目标相同 - 结合几个弱模型的预测，以改善单个模型的泛化和鲁棒性。

提升方法的一个例子是**梯度提升机**（**GBM**），它使用提升方法将弱模型（决策树）组合成一个集成；然而，它通过允许使用任意损失函数来概括这种方法：而不是试图纠正先前的弱模型错误分类的观察结果，GBM 允许您最小化指定的损失函数（例如，回归的均方误差）。

GBM 有不同的变体 - 例如，将提升与装袋相结合的随机 GBM。常规 GBM 和随机 GBM 都可以在 H2O 的机器学习工具箱中找到。此外，重要的是要提到 GBM（以及 RandomForest）是一种在不需要广泛调整参数的情况下构建相当不错模型的算法。

有关 GBM 的更多信息可以在 J.H. Friedman 的原始论文中找到：*贪婪函数逼近：梯度提升机* [`www-stat.stanford.edu/~jhf/ftp/trebst.pdf`](http://www-stat.stanford.edu/~jhf/ftp/trebst.pdf)。

此外，RandomForest 采用所谓的“特征装袋” - 在构建决策树时，它选择一个随机特征子集来做出分裂决策。动机是构建一个弱学习器并增强泛化能力 - 例如，如果一个特征对于给定的目标变量是一个强预测因子，它将被大多数树选择，导致高度相似的树。然而，通过随机选择特征，算法可以避免强预测因子，并构建能够找到数据更精细结构的树。

RandomForest 还有助于轻松选择最具预测性的特征，因为它允许以不同的方式计算变量重要性。例如，通过计算所有树的整体特征不纯度增益，可以很好地估计强特征的重要性。

从实现的角度来看，RandomForest 可以很容易地并行化，因为*构建树*步骤是独立的。另一方面，分布 RandomForest 计算是一个稍微困难的问题，因为每棵树都需要探索几乎完整的数据集。

RandomForest 的缺点是解释性复杂。得到的集成很难探索和解释个别树之间的交互。然而，如果我们需要获得一个不需要高级参数调整的良好模型，它仍然是最好的模型之一。

RandomForest 的一个很好的信息来源是 Leo Breiman 和 Adele Cutler 的原始论文，例如可以在这里找到：[`www.stat.berkeley.edu/~breiman/RandomForests/cc_home.htm`](https://www.stat.berkeley.edu/~breiman/RandomForests/cc_home.htm)。

# 使用 Spark RandomForest 构建分类模型

在前一节中，我们探索了数据并将其统一成一个没有缺失值的形式。我们仍然需要将数据转换为 Spark MLlib 所期望的形式。如前一章所述，这涉及到创建`LabeledPoints`的`RDD`。每个`LabeledPoint`由一个标签和定义输入特征的向量组成。标签用作模型构建者的训练目标，并引用分类变量的索引（参见准备好的转换`activityId2Idx`）：

```scala
import org.apache.spark.mllib 
import org.apache.spark.mllib.regression.LabeledPoint 
import org.apache.spark.mllib.linalg.Vectors 
import org.apache.spark.mllib.tree.RandomForest 
import org.apache.spark.mllib.util.MLUtils 

val data = processedRawData.map { r =>  
    val activityId = r(0) 
    val activityIdx = activityId2Idx(activityId) 
    val features = r.drop(1) 
    LabeledPoint(activityIdx, Vectors.dense(features)) 
} 

```

下一步是为训练和模型验证准备数据。我们简单地将数据分为两部分：80%用于训练，剩下的 20%用于验证：

```scala
val splits = data.randomSplit(Array(0.8, 0.2)) 
val (trainingData, testData) =  
    (splits(0), splits(1)) 
```

在这一步之后，我们准备调用工作流程的建模部分。构建 Spark RandomForest 模型的策略与我们在上一章中展示的 GBM 相同，通过在对象`RandomForest`上调用静态方法`trainClassifier`来实现：

```scala
import org.apache.spark.mllib.tree.configuration._ 
import org.apache.spark.mllib.tree.impurity._ 
val rfStrategy = new Strategy( 
  algo = Algo.Classification, 
  impurity = Entropy, 
  maxDepth = 10, 
  maxBins = 20, 
  numClasses = activityId2Idx.size, 
  categoricalFeaturesInfo = Map[Int, Int](), 
  subsamplingRate = 0.68) 

val rfModel = RandomForest.trainClassifier( 
    input = trainingData,  
    strategy = rfStrategy, 
    numTrees = 50,  
    featureSubsetStrategy = "auto",  
    seed = 42) 
```

在这个例子中，参数被分成两组：

+   定义构建决策树的常见参数的策略

+   RandomForest 特定参数

策略参数列表与上一章讨论的决策树算法的参数列表重叠：

+   `input`：引用由`LabeledPoints`的`RDD`表示的训练数据。

+   `numClasses`：输出类的数量。在这种情况下，我们仅对输入数据中包含的类建模。

+   `categoricalFeaturesInfo`：分类特征及其度量的映射。我们的输入数据中没有分类特征，因此我们传递一个空映射。

+   `impurity`：用于树节点分裂的不纯度度量。

+   `subsamplingRate`：用于构建单棵决策树的训练数据的分数。

+   `maxDepth`：单棵树的最大深度。深树倾向于对输入数据进行编码和过拟合。另一方面，在 RandomForest 中，通过组装多棵树来平衡过拟合。此外，更大的树意味着更长的训练时间和更高的内存占用。

+   `maxBins`：连续特征被转换为具有最多`maxBins`可能值的有序离散特征。离散化是在每个节点分裂之前完成的。

RandomForest 特定参数如下：

+   `numTrees`：结果森林中的树的数量。增加树的数量会减少模型的方差。

+   `featureSubsetStrategy`：指定一种方法，用于选择用于训练单棵树的特征数量。例如："sqrt"通常用于分类，而"onethird"用于回归问题。查看`RandomForest.supportedFeatureSubsetStrategies`的值以获取可用值。

+   `seed`：用于随机生成器初始化的种子，因为 RandomForest 依赖于特征和行的随机选择。

参数`numTrees`和`maxDepth`经常被引用为停止标准。Spark 还提供了额外的参数来停止树的生长并生成细粒度的树：

+   `minInstancesPerNode`：如果节点提供的左节点或右节点包含的观察次数小于此参数指定的值，则不再分裂节点。默认值为 1，但通常对于回归问题或大树，该值应该更高。

+   `minInfoGain`：分裂必须获得的最小信息增益。默认值为 0.0。

此外，Spark RandomForest 接受影响执行性能的参数（请参阅 Spark 文档）。

RandomForest 在定义上是一个依赖于随机化的算法。然而，如果您试图重现结果或测试边缘情况，那么非确定性运行并不是正确的行为。在这种情况下，seed 参数提供了一种固定执行并提供确定性结果的方法。

这是非确定性算法的常见做法；然而，如果算法是并行化的，并且其结果取决于线程调度，那么这还不够。在这种情况下，需要采用临时方法（例如，通过仅使用一个计算线程限制并行化，通过限制输入分区的数量限制并行化，或切换任务调度程序以提供固定的调度）。

# 分类模型评估

现在，当我们有一个模型时，我们需要评估模型的质量，以决定模型是否足够满足我们的需求。请记住，与模型相关的所有质量指标都需要根据您的特定情况考虑，并与您的目标目标（如销售增长、欺诈检测等）一起评估。

# Spark 模型指标

首先，使用 Spark API 提供的嵌入模型指标。我们将使用与上一章相同的方法。我们首先定义一个方法，用于提取给定模型和数据集的模型指标：

```scala
import org.apache.spark.mllib.evaluation._ 
import org.apache.spark.mllib.tree.model._ 
def getMetrics(model: RandomForestModel, data: RDD[LabeledPoint]): 
    MulticlassMetrics = { 
        val predictionsAndLabels = data.map(example => 
            (model.predict(example.features), example.label) 
        ) 
        new MulticlassMetrics(predictionsAndLabels) 
} 
```

然后我们可以直接计算 Spark 的`MulticlassMetrics`：

```scala
val rfModelMetrics = getMetrics(rfModel, testData) 
```

然后首先查看有趣的分类模型指标，称为`混淆矩阵`。它由类型`org.apache.spark.mllib.linalg.Matrix`表示，允许您执行代数运算：

```scala
println(s"""|Confusion matrix: 
  |${rfModelMetrics.confusionMatrix}""".stripMargin) 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00070.jpeg)

在这种情况下，Spark 在列中打印预测的类。预测的类存储在`rfModelMetrics`对象的`labels`字段中。然而，该字段仅包含已翻译的索引（请参见创建的变量`activityId2Idx`）。尽管如此，我们可以轻松地创建一个函数来将标签索引转换为实际的标签字符串：

```scala
def idx2Activity(idx: Double): String =  
  activityId2Idx. 
  find(e => e._2 == idx.asInstanceOf[Int]). 
  map(e => activitiesMap(e._1)). 
  getOrElse("UNKNOWN") 

val rfCMLabels = rfModelMetrics.labels.map(idx2Activity(_)) 
println(s"""|Labels: 
  |${rfCMLabels.mkString(", ")}""".stripMargin) 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00071.jpeg)

例如，我们可以看到其他活动与其他活动多次被错误预测 - 它在`36455`个案例中被正确预测；然而，在`1261`个案例中，模型预测了`其他`活动，但实际活动是`家务清洁`。另一方面，模型预测了`叠衣服`活动而不是`其他`活动。

您可以直接看到，我们可以基于`混淆矩阵`对角线上正确预测的活动直接计算整体预测准确度：

```scala
val rfCM = rfModelMetrics.confusionMatrix 
val rfCMTotal = rfCM.toArray.sum 
val rfAccuracy = (0 until rfCM.numCols).map(i => rfCM(i,i)).sum / rfCMTotal 
println(f"RandomForest accuracy = ${rfAccuracy*100}%.2f %%") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00072.jpeg)

然而，总体准确度可能会在类别不均匀分布的情况下产生误导（例如，大多数实例由单个类别表示）。在这种情况下，总体准确度可能会令人困惑，因为模型只是预测一个主导类将提供高准确度。因此，我们可以更详细地查看我们的预测，并探索每个单独类别的准确度。然而，首先我们查看实际标签和预测标签的分布，以查看`(1)`是否有主导类，以及`(2)`模型是否保留了类别的输入分布并且没有偏向于预测单一类别：

```scala
import org.apache.spark.mllib.linalg.Matrix
 def colSum(m: Matrix, colIdx: Int) = (0 until m.numRows).map(m(_, colIdx)).sum
 def rowSum(m: Matrix, rowIdx: Int) = (0 until m.numCols).map(m(rowIdx, _)).sum
 val rfCMActDist = (0 until rfCM.numRows).map(rowSum(rfCM, _)/rfCMTotal)
 val rfCMPredDist = (0 until rfCM.numCols).map(colSum(rfCM, _)/rfCMTotal)

 println(s"""^Class distribution
             ^${table(Seq("Class", "Actual", "Predicted"),
                      rfCMLabels.zip(rfCMActDist.zip(rfCMPredDist)).map(p => (p._1, p._2._1, p._2._2)),
                      Map(1 -> "%.2f", 2 -> "%.2f"))}
           """.stripMargin('^')) 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00073.jpeg)

我们很容易看到没有主导类；然而，这些类并不是均匀分布的。值得注意的是，该模型保留了实际类别的分布，并且没有倾向于偏爱单一类别。这只是确认了我们基于`混淆矩阵`的观察。

最后，我们可以查看各个类别并计算精确度（又称阳性预测值）、召回率（或称灵敏度）和`F-1`分数。为了提醒上一章的定义：精确度是给定类别的正确预测的比例（即 TP/TP+TF），而召回率被定义为所有正确预测的类实例的比例（即 TP/TP+FN）。最后，`F-1`分数结合了它们两个，因为它是精确度和召回率的加权调和平均数。我们可以使用我们已经定义的函数轻松计算它们：

```scala
def rfPrecision(m: Matrix, feature: Int) = m(feature, feature) / colSum(m, feature)
 def rfRecall(m: Matrix, feature: Int) = m(feature, feature) / rowSum(m, feature)
 def rfF1(m: Matrix, feature: Int) = 2 * rfPrecision(m, feature) * rfRecall(m, feature) / (rfPrecision(m, feature) + rfRecall(m, feature))

 val rfPerClassSummary = rfCMLabels.indices.map { i =>
   (rfCMLabels(i), rfRecall(rfCM, i), rfPrecision(rfCM, i), rfF1(rfCM, i))
 }

 println(s"""^Per class summary:
             ^${table(Seq("Label", "Recall", "Precision", "F-1"),
                      rfPerClassSummary,
                      Map(1 -> "%.4f", 2 -> "%.4f", 3 -> "%.4f"))}
           """.stripMargin('^')) 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00074.jpeg)

在我们的案例中，我们处理了一个相当不错的模型，因为大多数值都接近于 1.0。这意味着该模型对每个输入类别的表现良好 - 生成了较少的假阳性（精确度）和假阴性（召回）。

Spark API 的一个很好的特性是它已经提供了计算我们手动计算的所有三个指标的方法。我们可以轻松调用`precision`、`recall`、`fMeasure`方法，并使用标签索引获得相同的值。然而，在 Spark 的情况下，每次调用都会收集`混淆矩阵`，从而增加整体计算时间。

在我们的案例中，我们使用已经计算的`混淆矩阵`并直接获得相同的结果。读者可以验证以下代码是否给出了与`rfPerClassSummary`中存储的相同数字：

```scala
val rfPerClassSummary2 = rfCMLabels.indices.map { i =>  
    (rfCMLabels(i), rfModelMetrics.recall(i), rfModelMetrics.precision(i), rfModelMetrics.fMeasure(i))  
} 
```

通过每个类的统计数据，我们可以通过计算每个计算指标的平均值来简单地计算宏平均指标：

```scala
val rfMacroRecall = rfCMLabels.indices.map(i => rfRecall(rfCM, i)).sum/rfCMLabels.size 
val rfMacroPrecision = rfCMLabels.indices.map(i => rfPrecision(rfCM, i)).sum/rfCMLabels.size 
val rfMacroF1 = rfCMLabels.indices.map(i => rfF1(rfCM, i)).sum/rfCMLabels.size 

println(f"""|Macro statistics 
  |Recall, Precision, F-1 
  |${rfMacroRecall}%.4f, ${rfMacroPrecision}%.4f, ${rfMacroF1}%.4f""".stripMargin) 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00075.jpeg)

`Macro`统计数据为我们提供了所有特征统计的整体特征。我们可以看到预期值接近 1.0，因为我们的模型在测试数据上表现相当不错。

此外，Spark ModelMetrics API 还提供了加权精度、召回率和`F-1`分数，这些主要在处理不平衡的类时非常有用：

```scala
println(f"""|Weighted statistics 
  |Recall, Precision, F-1 
  |${rfModelMetrics.weightedRecall}%.4f, ${rfModelMetrics.weightedPrecision}%.4f, ${rfModelMetrics.weightedFMeasure}%.4f 
  |""".stripMargin) 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00076.jpeg)

最后，我们将看一种计算模型指标的方法，这种方法在类别分布不均匀的情况下也很有用。该方法称为一对所有，它提供了分类器相对于一个类的性能。这意味着我们将为每个输出类别计算一个`混淆矩阵` - 我们可以将这种方法视为将分类器视为一个二元分类器，预测一个类作为正例，其他任何类作为负例：

```scala
import org.apache.spark.mllib.linalg.Matrices 
val rfOneVsAll = rfCMLabels.indices.map { i => 
    val icm = rfCM(i,i) 
    val irowSum = rowSum(rfCM, i) 
    val icolSum = colSum(rfCM, i) 
    Matrices.dense(2,2,  
      Array( 
        icm, irowSum - icm, 
        icolSum - icm, rfCMTotal - irowSum - icolSum + icm)) 
  } 
println(rfCMLabels.indices.map(i => s"${rfCMLabels(i)}\n${rfOneVsAll(i)}").mkString("\n")) 
```

这将为我们提供每个类别相对于其他类别的性能，由简单的二进制`混淆矩阵`表示。我们可以总结所有矩阵并得到一个`混淆矩阵`，以计算每个类的平均准确度和微平均指标：

```scala
val rfOneVsAllCM = rfOneVsAll.foldLeft(Matrices.zeros(2,2))((acc, m) => 
  Matrices.dense(2, 2,  
    Array(acc(0, 0) + m(0, 0),  
          acc(1, 0) + m(1, 0), 
          acc(0, 1) + m(0, 1), 
          acc(1, 1) + m(1, 1))) 
) 
println(s"Sum of oneVsAll CM:\n${rfOneVsAllCM}") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00077.jpeg)

有了整体的`混淆矩阵`，我们可以计算每个类的平均准确度：

```scala
println(f"Average accuracy: ${(rfOneVsAllCM(0,0) + rfOneVsAllCM(1,1))/rfOneVsAllCM.toArray.sum}%.4f") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00078.jpeg)

该矩阵还给出了`微平均指标`（召回率、精度、`F-1`）。然而，值得一提的是我们的`rfOneVsAllCM`矩阵是对称的。这意味着`召回率`、`精度`和`F-1`具有相同的值（因为 FP 和 FN 是相同的）：

```scala
println(f"Micro-averaged metrics: ${rfOneVsAllCM(0,0)/(rfOneVsAllCM(0,0)+rfOneVsAllCM(1,0))}%.4f") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00079.jpeg)

Spark ModelMetrics API 的概述由 Spark 文档提供[`spark.apache.org/docs/latest/mllib-evaluation-metrics.html`](https://spark.apache.org/docs/latest/mllib-evaluation-metrics.html)。

此外，了解模型指标，特别是多类分类中`混淆矩阵`的作用是至关重要的，但不仅仅与 Spark API 有关。一个很好的信息来源是 Python scikit 文档（[`scikit-learn.org/stable/modules/model_evaluation.html`](http://scikit-learn.org/stable/modules/model_evaluation.html)）或各种 R 包（例如，[`blog.revolutionanalytics.com/2016/03/com_class_eval_metrics_r.html`](http://blog.revolutionanalytics.com/2016/03/com_class_eval_metrics_r.html)）。

# 使用 H2O RandomForest 构建分类模型

H2O 提供了多种算法来构建分类模型。在本章中，我们将再次专注于树集成，但我们将演示它们在传感器数据问题的背景下的使用。

我们已经准备好了数据，可以直接用来构建 H2O RandomForest 模型。要将它们转换为 H2O 格式，我们需要创建`H2OContext`，然后调用相应的转换：

```scala
import org.apache.spark.h2o._ 
val h2oContext = H2OContext.getOrCreate(sc) 

val trainHF = h2oContext.asH2OFrame(trainingData, "trainHF") 
trainHF.setNames(columnNames) 
trainHF.update() 
val testHF = h2oContext.asH2OFrame(testData, "testHF") 
testHF.setNames(columnNames) 
testHF.update() 
```

我们创建了两个表，分别以`trainHF`和`testHF`命名。代码还通过调用`setNames`方法更新了列的名称，因为输入的`RDD`不包含有关列的信息。重要的一步是调用`update`方法将更改保存到 H2O 的分布式内存存储中。这是 H2O API 暴露的一个重要模式 - 对对象进行的所有更改都是在本地完成的；为了使它们对其他计算节点可见，有必要将它们保存到内存存储中（所谓的**分布式键值存储**（**DKV**））。

将数据存储为 H2O 表后，我们可以通过调用`h2oContext.openFlow`打开 H2O Flow 用户界面，并以图形方式探索数据。例如，数值特征`activityId`列的分布如*图 4*所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00080.jpeg)

图 4：需要转换为分类类型的数值列 activityId 的视图。

我们可以直接比较结果，并通过一段 Spark 代码验证我们观察到正确的分布：

```scala
println(s"""^Distribution of activityId:
             ^${table(Seq("activityId", "Count"),
                      testData.map(row => (row.label, 1)).reduceByKey(_ + _).collect.sortBy(_._1),
                      Map.empty[Int, String])}
             """.stripMargin('^')) 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00081.jpeg)

下一步是准备输入数据来运行 H2O 算法。首先，我们需要验证列类型是否符合算法所期望的形式。H2O Flow UI 提供了带有基本属性的列的列表（*图 5*）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00082.jpeg)

图 5：在 Flow UI 中显示的导入训练数据集的列。

我们可以看到`activityId`列是数值的；然而，为了进行分类，H2O 要求列必须是分类的。因此，我们需要通过在 UI 中点击"转换为枚举"或以编程方式进行转换： 

```scala
trainHF.replace(0, trainHF.vec(0).toCategoricalVec).remove 
trainHF.update 
testHF.replace(0, testHF.vec(0).toCategoricalVec).remove 
testHF.update 
```

再次，我们需要通过调用`update`方法更新内存存储中的修改后的帧。此外，我们正在将一个向量转换为另一个向量类型，我们不再需要原始向量，因此我们可以在`replace`调用的结果上调用`remove`方法。

转换后，`activityId`列是分类的；然而，向量域包含值"0"，"1"，..."6" - 它们存储在字段`trainHF.vec("activityId").domain`中。然而，我们可以使用实际的类别名称更新向量。我们已经准备好了索引到名称转换，称为`idx2Activity` - 因此我们准备一个新的域，并更新训练和测试表的`activityId`向量域：

```scala
val domain = trainHF.vec(0).domain.map(i => idx2Activity(i.toDouble)) 
trainHF.vec(0).setDomain(domain) 
water.DKV.put(trainHF.vec(0)) 
testHF.vec(0).setDomain(domain) 
water.DKV.put(testHF.vec(0)) 
```

在这种情况下，我们还需要更新内存存储中修改后的向量 - 代码不是调用`update`方法，而是显式调用`water.DKV.put`方法，直接将对象保存到内存存储中。

在 UI 中，我们可以再次探索测试数据集的`activityId`列，并将其与计算结果进行比较- *图 6：*

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00083.jpeg)

图 6：测试数据集中的 activityId 值分布。

在这一点上，我们已经准备好执行模型构建的数据。H2O RandomForest 的分类问题配置遵循我们在上一章中介绍的相同模式：

```scala
import _root_.hex.tree.drf.DRF 
import _root_.hex.tree.drf.DRFModel 
import _root_.hex.tree.drf.DRFModel.DRFParameters 
import _root_.hex.ScoreKeeper._ 
import _root_.hex.ConfusionMatrix 
import water.Key.make 

val drfParams = new DRFParameters 
drfParams._train = trainHF._key 
drfParams._valid = testHF._key 
drfParams._response_column = "activityId" 
drfParams._max_depth = 20 
drfParams._ntrees = 50 
drfParams._score_each_iteration = true 
drfParams._stopping_rounds = 2 
drfParams._stopping_metric = StoppingMetric.misclassification 
drfParams._stopping_tolerance = 1e-3 
drfParams._seed = 42 
drfParams._nbins = 20 
drfParams._nbins_cats = 1024 

val drfModel = new DRF(drfParams, makeDRFModel).trainModel.get 
```

H2O 算法与 Spark 之间有几个重要的区别。第一个重要的区别是我们可以直接指定验证数据集作为输入参数（`_valid`字段）。这并不是必需的，因为我们可以在构建模型后进行验证；然而，当指定验证数据集时，我们可以在构建过程中实时跟踪模型的质量，并在我们认为模型已经足够好时停止模型构建（参见*图 7* - "取消作业"操作停止训练，但模型仍然可用于进一步操作）。此外，稍后我们可以继续模型构建并添加更多的树，如果需要的话。参数`_score_each_iteration`控制评分应该多频繁进行：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00084.jpeg)

图 7：在 Flow UI 中可以跟踪模型训练，并通过按下"取消作业"按钮停止。

另一个区别在于参数`_nbins`、`_nbins_top_level`和`_nbins_cats`。Spark RandomForest 实现接受参数`maxBins`来控制连续特征的离散化。在 H2O 的情况下，它对应于参数`_nbins`。然而，H2O 机器学习平台允许对离散化进行更精细的调整。由于顶层分割最重要，并且可能因为离散化而导致信息丢失，H2O 允许通过参数`_nbins_top_level`临时增加离散类别的数量。此外，高值分类特征（> 1,024 个级别）通常会通过强制算法考虑所有可能的分割成两个不同子集来降低计算性能。对于这种情况，H2O 引入了参数`_nbins_cats`，它控制分类级别的数量 - 如果一个特征包含的分类级别多于参数中存储的值，则这些值将重新分组以适应`_nbins_cats`个箱子。

最后一个重要的区别是，我们在集成中指定了额外的停止标准，以及传统的深度和树的数量。该标准限制了在验证数据上计算的误分类的改善 - 在这种情况下，我们指定，如果验证数据上连续两次评分测量（字段`_stopping_rounds`）不提高 0.001（字段`_stopping_tolerance`的值），则模型构建应该停止。如果我们知道模型的预期质量并希望限制模型训练时间，这是一个完美的标准。在我们的情况下，我们可以探索生成集成中的树的数量：

```scala
println(s"Number of trees: ${drfModel._output._ntrees}") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00085.jpeg)

即使我们要求 50 棵树，由于模型训练在给定阈值下未改善误分类率，因此生成的模型只有`14`棵树。

H2O API 公开了多个停止标准，可以被任何算法使用 - 用户可以使用 AUC 值进行二项问题或 MSE 进行回归问题。这是最强大的功能之一，可以让您在探索大量超参数空间时减少计算时间。

模型的质量可以通过两种方式来探索：（1）直接使用 Scala API 并访问模型字段`_output`，其中包含所有输出指标，或者（2）使用图形界面以更用户友好的方式来探索指标。例如，可以在 Flow UI 中的模型视图中直接显示指定验证集上的`混淆矩阵`。参考下图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00086.jpeg)

图 8：由 14 棵树组成的初始 RandomForest 模型的混淆矩阵。

它直接给出了错误率（0.22%）和每个类别的误分类，我们可以直接与使用 Spark 模型计算的准确性进行比较。此外，`混淆矩阵`可以用于计算我们探索的其他指标。

例如，计算每个类别的召回率、精确度和`F-1`指标。我们可以简单地将 H2O 的`混淆矩阵`转换为 Spark 的`混淆矩阵`，并重用所有定义的方法。但是我们必须小心不要混淆结果`混淆矩阵`中的实际值和预测值（Spark 矩阵的预测值在列中，而 H2O 矩阵的预测值在行中）：

```scala
val drfCM = drfModel._output._validation_metrics.cm 
def h2oCM2SparkCM(h2oCM: ConfusionMatrix): Matrix = { 
  Matrices.dense(h2oCM.size, h2oCM.size, h2oCM._cm.flatMap(x => x)) 
} 
val drfSparkCM = h2oCM2SparkCM(drfCM) 
```

您可以看到指定验证数据集的计算指标存储在模型输出字段`_output._validation_metrics`中。它包含`混淆矩阵`，还包括在训练过程中跟踪的模型性能的其他信息。然后我们简单地将 H2O 表示转换为 Spark 矩阵。然后我们可以轻松地计算每个类别的宏性能：

```scala
val drfPerClassSummary = drfCM._domain.indices.map { i =>
   (drfCM._domain(i), rfRecall(drfSparkCM, i), rfPrecision(drfSparkCM, i), rfF1(drfSparkCM, i))
 }

 println(s"""^Per class summary
             ^${table(Seq("Label", "Recall", "Precision", "F-1"),
                      drfPerClassSummary,
                      Map(1 -> "%.4f", 2 -> "%.4f", 3 -> "%.4f"))}
           """.stripMargin('^')) 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00087.jpeg)

您可以看到，结果略优于之前计算的 Spark 结果，尽管 H2O 使用的树较少。解释需要探索 H2O 实现的随机森林算法 - H2O 使用的算法是基于为每个输出类生成一个回归决策树的方法 - 这种方法通常被称为“一对所有”方案。该算法允许针对各个类别进行更精细的优化。因此，在这种情况下，14 个随机森林树在内部由 14*7 = 98 个内部决策树表示。

读者可以在 Ryan Rifkin 和 Aldebaro Klautau 的论文*In Defense of One-Vs-All Classification*中找到更多关于“一对所有”方案在多类分类问题中的好处的解释。作者表明，该方案与其他方法一样准确；另一方面，该算法强制生成更多的决策树，这可能会对计算时间和内存消耗产生负面影响。

我们可以探索关于训练模型的更多属性。随机森林的一个重要指标是变量重要性。它存储在模型的字段`_output._varimp`下。该对象包含原始值，可以通过调用`scaled_values`方法进行缩放，或者通过调用`summary`方法获得相对重要性。然而，它们可以在 Flow UI 中以图形方式进行探索，如*图 9*所示。图表显示，最重要的特征是来自所有三个传感器的测量温度，其次是各种运动数据。令人惊讶的是，与我们的预期相反，心率并未包含在最重要的特征中。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00088.jpeg)

图 9：模型“drfModel”的变量重要性。最重要的特征包括测量温度。

如果我们对模型的质量不满意，可以通过增加更多的树来扩展它。我们可以重用定义的参数，并以以下方式修改它们：

+   设置所需的集成树的数量（例如，20）。

+   禁用早停准则，以避免在达到所需数量的树之前停止模型训练。

+   配置所谓的*模型检查点*，指向先前训练过的模型。模型检查点是 H2O 机器学习平台的独特功能，适用于所有已发布的模型。在需要通过执行更多的训练迭代来改进给定模型的情况下，它非常有用。

之后，我们可以简单地再次启动模型构建。在这种情况下，H2O 平台简单地继续模型训练，重建模型状态，并构建并附加新树到新模型中。

```scala
drfParams._ntrees = 20 
drfParams._stopping_rounds = 0 
drfParams._checkpoint = drfModel._key 

val drfModel20 = new DRF(drfParams, makeDRFModel).trainModel.get 
println(s"Number of trees: ${drfModel20._output._ntrees}") 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00089.jpeg)

在这种情况下，只构建了`6`棵树 - 要查看这一点，用户可以在控制台中探索模型训练输出，并找到一个以模型训练输出和报告结束的行：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00090.jpeg)

第 6 棵树在 2 秒内生成，并且是附加到现有集成中创建新模型的最后一棵树。我们可以再次探索新构建模型的`混淆矩阵`，并看到整体错误率从 0.23 降至 0.2%的改善（见*图 9*）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00091.jpeg)

图 10：具有 20 棵树的随机森林模型的混淆矩阵。

# 总结

本章介绍了几个重要概念，包括数据清理和处理缺失和分类值，使用 Spark 和 H2O 训练多分类模型，以及分类模型的各种评估指标。此外，本章介绍了模型集成的概念，以 RandomForest 作为决策树的集成。

读者应该看到数据准备的重要性，在每个模型训练和评估过程中都起着关键作用。在不了解建模背景的情况下训练和使用模型可能会导致误导性的决策。此外，每个模型都需要根据建模目标进行评估（例如，最小化假阳性）。因此，了解分类模型的不同模型指标的权衡是至关重要的。

在本章中，我们没有涵盖所有可能的分类模型建模技巧，但还有一些对好奇的读者来说仍然是开放的。

我们使用了一个简单的策略来填补心率列中的缺失值，但还有其他可能的解决方案 - 例如，均值插补，或者将插补与额外的二进制列相结合，标记具有缺失值的行。这两种策略都可以提高模型的准确性，我们将在本书的后面部分使用它们。

此外，奥卡姆剃刀原则表明，更倾向于选择一个简单的模型，而不是一个复杂的模型，尽管它们提供相同的准确性是一个好主意。因此，一个好主意是定义一个参数的超空间，并使用探索策略找到最简单的模型（例如，更少的树木，更少的深度），它提供与本章训练的模型相同（或更好）的准确性。

总结本章，重要的是要提到，本章介绍的树集成是集成和超学习器强大概念的一个原始实例，我们将在本书的后面部分介绍。
