# Spark SQL 学习手册（一）

> 原文：[`zh.annas-archive.org/md5/38E33AE602B4FA8FF02AE9F0398CDE84`](https://zh.annas-archive.org/md5/38E33AE602B4FA8FF02AE9F0398CDE84)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

我们将从 Spark SQL 的基础知识和其在 Spark 应用中的作用开始。在对 Spark SQL 进行初步了解之后，我们将专注于使用 Spark SQL 执行所有大数据项目常见的任务，如处理各种类型的数据源、探索性数据分析和数据整理。我们还将看到如何利用 Spark SQL 和 SparkR 来实现典型的大规模数据科学任务。

作为 Spark SQL 核心的 DataFrame/Dataset API 和 Catalyst 优化器，在基于 Spark 技术栈的所有应用中发挥关键作用并不奇怪。这些应用包括大规模机器学习管道、大规模图应用和新兴的基于 Spark 的深度学习应用。此外，我们还将介绍基于 Spark SQL 的结构化流应用，这些应用部署在复杂的生产环境中作为连续应用。

我们还将回顾 Spark SQL 应用中的性能调优，包括 Spark 2.2 中引入的基于成本的优化（CBO）。最后，我们将介绍利用 Spark 模块和 Spark SQL 在实际应用中的应用架构。具体来说，我们将介绍大规模 Spark 应用中的关键架构组件和模式，这些组件和模式对架构师和设计师来说将是有用的构建块，用于他们自己特定用例的构建。

# 本书内容

第一章《开始使用 Spark SQL》概述了 Spark SQL，并通过实践让您熟悉 Spark 环境。

第二章《使用 Spark SQL 处理结构化和半结构化数据》将帮助您使用 Spark 处理关系数据库（MySQL）、NoSQL 数据库（MongoDB）、半结构化数据（JSON）以及 Hadoop 生态系统中常用的数据存储格式（Avro 和 Parquet）。

第三章《使用 Spark SQL 进行数据探索》演示了使用 Spark SQL 来探索数据集，执行基本的数据质量检查，生成样本和数据透视表，并使用 Apache Zeppelin 可视化数据。

第四章《使用 Spark SQL 进行数据整理》使用 Spark SQL 执行一些基本的数据整理/处理任务。它还向您介绍了一些处理缺失数据、错误数据、重复记录等技术。

第五章《在流应用中使用 Spark SQL》提供了使用 Spark SQL DataFrame/Dataset API 构建流应用的几个示例。此外，它还展示了如何在结构化流应用中使用 Kafka。

第六章《在机器学习应用中使用 Spark SQL》专注于在机器学习应用中使用 Spark SQL。在本章中，我们将主要探讨特征工程的关键概念，并实现机器学习管道。

第七章《在图应用中使用 Spark SQL》向您介绍了 GraphFrame 应用。它提供了使用 Spark SQL DataFrame/Dataset API 构建图应用并将各种图算法应用于图应用的示例。

第八章《使用 Spark SQL 与 SparkR》涵盖了 SparkR 架构和 SparkR DataFrames API。它提供了使用 SparkR 进行探索性数据分析（EDA）和数据整理任务、数据可视化和机器学习的代码示例。

第九章，*使用 Spark SQL 开发应用程序*，帮助您使用各种 Spark 模块构建 Spark 应用程序。它提供了将 Spark SQL 与 Spark Streaming、Spark 机器学习等相结合的应用程序示例。

第十章，*在深度学习应用程序中使用 Spark SQL*，向您介绍了 Spark 中的深度学习。在深入使用 BigDL 和 Spark 之前，它涵盖了一些流行的深度学习模型的基本概念。

第十一章，*调整 Spark SQL 组件以提高性能*，向您介绍了与调整 Spark 应用程序相关的基本概念，包括使用编码器进行数据序列化。它还涵盖了在 Spark 2.2 中引入的基于成本的优化器的关键方面，以自动优化 Spark SQL 执行。

第十二章，*大规模应用架构中的 Spark SQL*，教会您识别 Spark SQL 可以在大规模应用架构中实现典型功能和非功能需求的用例。

# 本书所需内容

本书基于 Spark 2.2.0（为 Apache Hadoop 2.7 或更高版本预构建）和 Scala 2.11.8。由于某些库的不可用性和报告的错误（在与 Apache Spark 2.2 一起使用时），也使用了 Spark 2.1.0 来进行一两个小节的讨论。硬件和操作系统规格包括最低 8GB RAM（强烈建议 16GB）、100GB HDD 和 OS X 10.11.6 或更高版本（或建议用于 Spark 开发的适当 Linux 版本）。

# 本书的受众

如果您是开发人员、工程师或架构师，并希望学习如何在大规模网络项目中使用 Apache Spark，那么这本书适合您。假定您具有 SQL 查询的先前知识。使用 Scala、Java、R 或 Python 的基本编程知识就足以开始阅读本书。

# 约定

在本书中，您将找到几种文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和终端命令如下："通过在训练数据集上调用`fit()`方法来训练模型。"

代码块设置如下：

```scala
scala> val inDiaDataDF = spark.read.option("header", true).csv("file:///Users/aurobindosarkar/Downloads/dataset_diabetes/diabetic_data.csv").cache()
```

任何命令行输入或输出都将如下所示：

```scala
head -n 8000 input.txt > val.txt
tail -n +8000 input.txt > train.txt
```

**新术语**和**重要单词**以粗体显示。例如，您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："单击“下一步”按钮将您移至下一个屏幕。"

警告或重要说明会出现如下。

技巧和窍门会出现如下。


# 第一章：开始使用 Spark SQL

Spark SQL 是使用 Spark 开发的所有应用程序的核心。在本书中，我们将详细探讨 Spark SQL 的使用方式，包括其在各种类型的应用程序中的使用以及其内部工作原理。开发人员和架构师将欣赏到每一章中呈现的技术概念和实践会话，因为他们在阅读本书时会逐步进展。

在本章中，我们将向您介绍与 Spark SQL 相关的关键概念。我们将从 SparkSession 开始，这是 Spark 2.0 中 Spark SQL 的新入口点。然后，我们将探索 Spark SQL 的接口 RDDs、DataFrames 和 Dataset APIs。随后，我们将解释有关 Catalyst 优化器和 Project Tungsten 的开发人员级细节。

最后，我们将介绍 Spark 2.0 中针对流应用程序的一项令人兴奋的新功能，称为结构化流。本章中将提供特定的实践练习（使用公开可用的数据集），以便您在阅读各个部分时能够积极参与其中。 

更具体地，本章的各节将涵盖以下主题以及实践会话：

+   什么是 Spark SQL？

+   介绍 SparkSession

+   了解 Spark SQL 概念

+   了解 RDDs、DataFrames 和 Datasets

+   了解 Catalyst 优化器

+   了解 Project Tungsten

+   在连续应用程序中使用 Spark SQL

+   了解结构化流内部

# 什么是 Spark SQL？

Spark SQL 是 Apache Spark 最先进的组件之一。自 Spark 1.0 以来一直是核心分发的一部分，并支持 Python、Scala、Java 和 R 编程 API。如下图所示，Spark SQL 组件为 Spark 机器学习应用程序、流应用程序、图应用程序以及许多其他类型的应用程序架构提供了基础。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00005.jpeg)

这些应用程序通常使用 Spark ML pipelines、结构化流和 GraphFrames，这些都是基于 Spark SQL 接口（DataFrame/Dataset API）的。这些应用程序以及 SQL、DataFrames 和 Datasets API 等构造自动获得 Catalyst 优化器的好处。该优化器还负责根据较低级别的 RDD 接口生成可执行的查询计划。

我们将在第六章中更详细地探讨 ML pipelines，*在机器学习应用程序中使用 Spark SQL*。GraphFrames 将在第七章中介绍，*在图应用程序中使用 Spark SQL*。而在本章中，我们将介绍有关结构化流和 Catalyst 优化器的关键概念，我们将在第五章和第十一章中获得更多关于它们的细节，*在流应用程序中使用 Spark SQL*和*Tuning Spark SQL Components for Performance*。

在 Spark 2.0 中，DataFrame API 已与 Dataset API 合并，从而统一了跨 Spark 库的数据处理能力。这也使开发人员能够使用单一的高级和类型安全的 API。但是，Spark 软件堆栈并不阻止开发人员直接在其应用程序中使用低级别的 RDD 接口。尽管低级别的 RDD API 将继续可用，但预计绝大多数开发人员将（并建议）使用高级 API，即 Dataset 和 DataFrame API。

此外，Spark 2.0 通过包括一个新的 ANSI SQL 解析器扩展了 Spark SQL 的功能，支持子查询和 SQL:2003 标准。更具体地，子查询支持现在包括相关/不相关子查询，以及`IN / NOT IN`和`EXISTS / NOT EXISTS`谓词在`WHERE / HAVING`子句中。

Spark SQL 的核心是 Catalyst 优化器，它利用 Scala 的高级特性（如模式匹配）来提供可扩展的查询优化器。DataFrame、数据集和 SQL 查询共享相同的执行和优化管道；因此，使用这些结构中的任何一个（或使用任何受支持的编程 API）都不会对性能产生影响。开发人员编写的高级基于 DataFrame 的代码被转换为 Catalyst 表达式，然后通过该管道转换为低级 Java 字节码。

`SparkSession`是与 Spark SQL 相关功能的入口点，我们将在下一节中对其进行更详细的描述。

# 介绍 SparkSession

在 Spark 2.0 中，`SparkSession`表示操作 Spark 中数据的统一入口点。它最小化了开发人员在使用 Spark 时必须使用的不同上下文的数量。`SparkSession`取代了多个上下文对象，如`SparkContext`、`SQLContext`和`HiveContext`。这些上下文现在封装在`SparkSession`对象中。

在 Spark 程序中，我们使用构建器设计模式来实例化`SparkSession`对象。但是，在 REPL 环境（即在 Spark shell 会话中），`SparkSession`会自动创建并通过名为**Spark**的实例对象提供给您。

此时，在您的计算机上启动 Spark shell 以交互式地执行本节中的代码片段。随着 shell 的启动，您会注意到屏幕上出现了一堆消息，如下图所示。您应该看到显示`SparkSession`对象（作为 Spark）、Spark 版本为 2.2.0、Scala 版本为 2.11.8 和 Java 版本为 1.8.x 的消息。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00006.jpeg)

`SparkSession`对象可用于配置 Spark 的运行时配置属性。例如，Spark 和 Yarn 管理的两个主要资源是 CPU 和内存。如果要设置 Spark 执行程序的核心数和堆大小，可以分别通过设置`spark.executor.cores`和`spark.executor.memory`属性来实现。在本例中，我们将这些运行时属性分别设置为`2`个核心和`4`GB，如下所示：

```scala
    scala> spark.conf.set("spark.executor.cores", "2")

    scala> spark.conf.set("spark.executor.memory", "4g")
```

`SparkSession`对象可用于从各种来源读取数据，如 CSV、JSON、JDBC、流等。此外，它还可用于执行 SQL 语句、注册用户定义函数（UDFs）以及处理数据集和 DataFrame。以下会话演示了 Spark 中的一些基本操作。

在本例中，我们使用由威斯康星大学医院麦迪逊分校的 William H. Wolberg 博士创建的乳腺癌数据库。您可以从[`archive.ics.uci.edu/ml/datasets/Breast+Cancer+Wisconsin+(Original)`](https://archive.ics.uci.edu/ml/datasets/Breast+Cancer+Wisconsin+(Original))下载原始数据集。数据集中的每一行包含样本编号、乳腺细针抽吸的九个细胞学特征（分级为`1`到`10`）以及`label`类别，即`良性（2）`或`恶性（4）`。

首先，我们为文件中的记录定义一个模式。字段描述可以在数据集的下载站点上找到。

```scala
scala> import org.apache.spark.sql.types._

scala> val recordSchema = new StructType().add("sample", "long").add("cThick", "integer").add("uCSize", "integer").add("uCShape", "integer").add("mAdhes", "integer").add("sECSize", "integer").add("bNuc", "integer").add("bChrom", "integer").add("nNuc", "integer").add("mitosis", "integer").add("clas", "integer")

```

接下来，我们使用在前一步中定义的记录模式从输入 CSV 文件创建一个 DataFrame：

```scala
val df = spark.read.format("csv").option("header", false).schema(recordSchema).load("file:///Users/aurobindosarkar/Downloads/breast-cancer-wisconsin.data")
```

新创建的 DataFrame 可以使用`show()`方法显示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00007.jpeg)

DataFrame 可以使用`createOrReplaceTempView()`方法注册为 SQL 临时视图。这允许应用程序使用 SparkSession 对象的`sql`函数运行 SQL 查询，并将结果作为 DataFrame 返回。

接下来，我们为 DataFrame 创建一个临时视图，并对其执行一个简单的 SQL 语句：

```scala
scala> df.createOrReplaceTempView("cancerTable") 

scala> val sqlDF = spark.sql("SELECT sample, bNuc from cancerTable") 
```

使用`show()`方法显示结果 DataFrame 的内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00008.jpeg)

```scala
case class and the toDS() method. Then, we define a UDF to convert the clas column, currently containing 2's and 4's to  0's and 1's respectively. We register the UDF using the SparkSession object and use it in a SQL statement:
```

```scala
scala> case class CancerClass(sample: Long, cThick: Int, uCSize: Int, uCShape: Int, mAdhes: Int, sECSize: Int, bNuc: Int, bChrom: Int, nNuc: Int, mitosis: Int, clas: Int)

scala> val cancerDS = spark.sparkContext.textFile("file:///Users/aurobindosarkar/Documents/SparkBook/data/breast-cancer-wisconsin.data").map(_.split(",")).map(attributes => CancerClass(attributes(0).trim.toLong, attributes(1).trim.toInt, attributes(2).trim.toInt, attributes(3).trim.toInt, attributes(4).trim.toInt, attributes(5).trim.toInt, attributes(6).trim.toInt, attributes(7).trim.toInt, attributes(8).trim.toInt, attributes(9).trim.toInt, attributes(10).trim.toInt)).toDS()

scala> def binarize(s: Int): Int = s match {case 2 => 0 case 4 => 1 }

scala> spark.udf.register("udfValueToCategory", (arg: Int) => binarize(arg))

scala> val sqlUDF = spark.sql("SELECT *, udfValueToCategory(clas) from cancerTable")

scala> sqlUDF.show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00009.jpeg)

`SparkSession`公开了访问底层元数据的方法（通过 catalog 属性），例如可用数据库和表、注册的 UDF、临时视图等。此外，我们还可以缓存表、删除临时视图和清除缓存。这里展示了一些这些语句及其相应的输出：

```scala
scala> spark.catalog.currentDatabase

res5: String = default

scala> spark.catalog.isCached("cancerTable") 

res6: Boolean = false 

scala> spark.catalog.cacheTable("cancerTable") 

scala> spark.catalog.isCached("cancerTable") 

res8: Boolean = true 

scala> spark.catalog.clearCache 

scala> spark.catalog.isCached("cancerTable") 

res10: Boolean = false 

scala> spark.catalog.listDatabases.show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00010.jpeg)

还可以使用`take`方法在 DataFrame 中显示特定数量的记录：

```scala
scala> spark.catalog.listDatabases.take(1)
res13: Array[org.apache.spark.sql.catalog.Database] = Array(Database[name='default', description='Default Hive database', path='file:/Users/aurobindosarkar/Downloads/spark-2.2.0-bin-hadoop2.7/spark-warehouse'])

scala> spark.catalog.listTables.show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00011.jpeg)

我们可以使用以下语句删除之前创建的临时表：

```scala
scala> spark.catalog.dropTempView("cancerTable")

scala> spark.catalog.listTables.show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00012.jpeg)

在接下来的几节中，我们将更详细地描述 RDD、DataFrame 和 Dataset 的构造。

# 理解 Spark SQL 概念

在本节中，我们将探讨与弹性分布式数据集（RDD）、DataFrame 和 Dataset、Catalyst Optimizer 和 Project Tungsten 相关的关键概念。

# 理解弹性分布式数据集（RDD）

RDD 是 Spark 的主要分布式数据集抽象。它是一个不可变的、分布式的、惰性评估的、类型推断的、可缓存的数据集合。在执行之前，开发人员的代码（使用诸如 SQL、DataFrame 和 Dataset API 等更高级别的构造）被转换为 RDD 的 DAG（准备执行）。

您可以通过并行化现有数据集合或访问存储在外部存储系统中的数据集合（例如文件系统或各种基于 Hadoop 的数据源）来创建 RDD。并行化的集合形成了一个分布式数据集，使得可以对其进行并行操作。

您可以从指定了分区数量的输入文件创建 RDD，如下所示：

```scala
scala> val cancerRDD = sc.textFile("file:///Users/aurobindosarkar/Downloads/breast-cancer-wisconsin.data", 4)

scala> cancerRDD.partitions.size
res37: Int = 4
```

您可以通过导入`spark.implicits`包并使用`toDF()`方法将 RDD 隐式转换为 DataFrame：

```scala
scala> import spark.implicits._scala> 
val cancerDF = cancerRDD.toDF()
```

要创建具有特定模式的 DataFrame，我们为 DataFrame 中包含的行定义一个 Row 对象。此外，我们将逗号分隔的数据拆分，转换为字段列表，然后将其映射到 Row 对象。最后，我们使用`createDataFrame()`创建具有指定模式的 DataFrame：

```scala
def row(line: List[String]): Row = { Row(line(0).toLong, line(1).toInt, line(2).toInt, line(3).toInt, line(4).toInt, line(5).toInt, line(6).toInt, line(7).toInt, line(8).toInt, line(9).toInt, line(10).toInt) }
val data = cancerRDD.map(_.split(",").to[List]).map(row)
val cancerDF = spark.createDataFrame(data, recordSchema)
```

此外，我们可以轻松地使用之前定义的`case`类将前述 DataFrame 转换为数据集：

```scala
scala> val cancerDS = cancerDF.as[CancerClass]
```

RDD 数据在逻辑上被划分为一组分区；此外，所有输入、中间和输出数据也被表示为分区。RDD 分区的数量定义了数据的碎片化程度。这些分区也是并行性的基本单元。Spark 执行作业被分成多个阶段，每个阶段一次操作一个分区，因此调整分区的数量非常重要。比活跃阶段少的分区意味着您的集群可能被低效利用，而过多的分区可能会影响性能，因为会导致更高的磁盘和网络 I/O。

RDD 的编程接口支持两种类型的操作：转换和动作。转换从现有数据集创建一个新的数据集，而动作返回计算结果的值。所有转换都是惰性评估的--实际执行只发生在执行动作以计算结果时。转换形成一个谱系图，而不是实际在多台机器上复制数据。这种基于图的方法实现了高效的容错模型。例如，如果丢失了一个 RDD 分区，那么可以根据谱系图重新计算它。

您可以控制数据持久性（例如缓存）并指定 RDD 分区的放置偏好，然后使用特定的操作符对其进行操作。默认情况下，Spark 将 RDD 持久化在内存中，但如果内存不足，它可以将它们溢出到磁盘。缓存通过几个数量级提高了性能；然而，它通常占用大量内存。其他持久性选项包括将 RDD 存储到磁盘并在集群中的节点之间复制它们。持久 RDD 的内存存储可以是反序列化或序列化的 Java 对象形式。反序列化选项更快，而序列化选项更节省内存（但更慢）。未使用的 RDD 将自动从缓存中删除，但根据您的要求；如果不再需要特定的 RDD，则也可以显式释放它。

# 理解 DataFrames 和 Datasets

DataFrame 类似于关系数据库中的表、pandas dataframe 或 R 中的数据框。它是一个分布式的行集合，组织成列。它使用 RDD 的不可变、内存中、弹性、分布式和并行能力，并对数据应用模式。DataFrames 也是惰性评估的。此外，它们为分布式数据操作提供了领域特定语言（DSL）。

从概念上讲，DataFrame 是一组通用对象`Dataset[Row]`的别名，其中行是通用的无类型对象。这意味着 DataFrame 的语法错误在编译阶段被捕获；然而，分析错误只在运行时被检测到。

DataFrame 可以从各种来源构建，例如结构化数据文件、Hive 表、数据库或 RDD。源数据可以从本地文件系统、HDFS、Amazon S3 和 RDBMS 中读取。此外，还支持其他流行的数据格式，如 CSV、JSON、Avro、Parquet 等。此外，您还可以创建和使用自定义数据源。

DataFrame API 支持 Scala、Java、Python 和 R 编程 API。DataFrame API 是声明式的，并与 Spark 的过程式代码结合使用，为应用程序中的关系和过程式处理提供了更紧密的集成。可以使用 Spark 的过程式 API 或使用关系 API（具有更丰富的优化）来操作 DataFrame。

在 Spark 的早期版本中，您必须编写操作 RDD 的任意 Java、Python 或 Scala 函数。在这种情况下，函数是在不透明的 Java 对象上执行的。因此，用户函数本质上是执行不透明计算的黑匣子，使用不透明对象和数据类型。这种方法非常通用，这样的程序可以完全控制每个数据操作的执行。然而，由于引擎不知道您正在执行的代码或数据的性质，因此无法优化这些任意的 Java 对象。此外，开发人员需要编写依赖于特定工作负载性质的高效程序。

在 Spark 2.0 中，使用 SQL、DataFrames 和 Datasets 的主要好处是，使用这些高级编程接口编程更容易，同时自动获得性能改进的好处。您只需编写更少的代码行，程序就会自动优化，并为您生成高效的代码。这样可以提高性能，同时显著减轻开发人员的负担。现在，开发人员可以专注于“做什么”，而不是“如何完成”。

数据集 API 首次添加到 Spark 1.6 中，以提供 RDD 和 Spark SQL 优化器的优点。数据集可以从 JVM 对象构造，然后使用`map`、`filter`等函数变换进行操作。由于数据集是使用用户定义的 case 类指定的强类型对象的集合，因此可以在编译时检测到语法错误和分析错误。

统一的数据集 API 可以在 Scala 和 Java 中使用。但是 Python 目前还不支持数据集 API。

在下面的示例中，我们介绍了一些基本的 DataFrame/Dataset 操作。为此，我们将使用两个餐厅列表数据集，这些数据集通常用于重复记录检测和记录链接应用。来自 Zagat 和 Fodor 餐厅指南的两个列表之间存在重复记录。为了使这个例子简单，我们手动将输入文件转换为 CSV 格式。您可以从[`www.cs.utexas.edu/users/ml/riddle/data.html`](http://www.cs.utexas.edu/users/ml/riddle/data.html)下载原始数据集。

首先，我们为两个文件中的记录定义一个`case`类：

```scala
scala> case class RestClass(name: String, street: String, city: String, phone: String, cuisine: String)
```

接下来，我们从两个文件创建数据集：

```scala
scala> val rest1DS = spark.sparkContext.textFile("file:///Users/aurobindosarkar/Documents/SparkBook/data/zagats.csv").map(_.split(",")).map(attributes => RestClass(attributes(0).trim, attributes(1).trim, attributes(2).trim, attributes(3).trim, attributes(4).trim)).toDS()

scala> val rest2DS = spark.sparkContext.textFile("file:///Users/aurobindosarkar/Documents/SparkBook/data/fodors.csv").map(_.split(",")).map(attributes => RestClass(attributes(0).trim, attributes(1).trim, attributes(2).trim, attributes(3).trim, attributes(4).trim)).toDS()
```

我们定义一个 UDF 来清理和转换第二个数据集中的电话号码，以匹配第一个文件中的格式：

```scala
scala> def formatPhoneNo(s: String): String = s match {case s if s.contains("/") => s.replaceAll("/", "-").replaceAll("- ", "-").replaceAll("--", "-") case _ => s } 

scala> val udfStandardizePhoneNos = udfString, String ) 

scala> val rest2DSM1 = rest2DS.withColumn("stdphone", udfStandardizePhoneNos(rest2DS.col("phone")))
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00013.jpeg)

接下来，我们从我们的数据集创建临时视图：

```scala
scala> rest1DS.createOrReplaceTempView("rest1Table") 

scala> rest2DSM1.createOrReplaceTempView("rest2Table")
```

我们可以通过在这些表上执行 SQL 语句来获取重复记录的数量：

```scala
scala> spark.sql("SELECT count(*) from rest1Table, rest2Table where rest1Table.phone = rest2Table.stdphone").show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00014.jpeg)

接下来，我们执行一个返回包含匹配电话号码的行的 DataFrame 的 SQL 语句：

```scala
scala> val sqlDF = spark.sql("SELECT a.name, b.name, a.phone, b.stdphone from rest1Table a, rest2Table b where a.phone = b.stdphone")
```

从两个表中列出的名称和电话号码列的结果可以显示，以直观地验证结果是否可能重复：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00015.jpeg)

在下一节中，我们将把重点转移到 Spark SQL 内部，更具体地说，是 Catalyst 优化器和 Project Tungsten。

# 理解 Catalyst 优化器

Catalyst 优化器是 Spark SQL 的核心，用 Scala 实现。它实现了一些关键功能，例如模式推断（从 JSON 数据中），这在数据分析工作中非常有用。

下图显示了从包含 DataFrame/Dataset 的开发人员程序到最终执行计划的高级转换过程：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00016.jpeg)

程序的内部表示是查询计划。查询计划描述诸如聚合、连接和过滤等数据操作，这些操作与查询中定义的内容相匹配。这些操作从输入数据集生成一个新的数据集。在我们有查询计划的初始版本后，Catalyst 优化器将应用一系列转换将其转换为优化的查询计划。最后，Spark SQL 代码生成机制将优化的查询计划转换为准备执行的 RDD 的 DAG。查询计划和优化的查询计划在内部表示为树。因此，在其核心，Catalyst 优化器包含一个用于表示树和应用规则来操作它们的通用库。在这个库之上，还有几个更具体于关系查询处理的其他库。

Catalyst 有两种类型的查询计划：**逻辑**和**物理计划**。逻辑计划描述了数据集上的计算，而没有定义如何执行具体的计算。通常，逻辑计划在生成的行的一组约束下生成属性或列的列表作为输出。物理计划描述了数据集上的计算，并具体定义了如何执行它们（可执行）。

让我们更详细地探讨转换步骤。初始查询计划本质上是一个未解析的逻辑计划，也就是说，在这个阶段我们不知道数据集的来源或数据集中包含的列，我们也不知道列的类型。这个管道的第一步是分析步骤。在分析过程中，使用目录信息将未解析的逻辑计划转换为已解析的逻辑计划。

在下一步中，一组逻辑优化规则被应用于已解析的逻辑计划，从而产生一个优化的逻辑计划。在下一步中，优化器可能生成多个物理计划，并比较它们的成本以选择最佳的一个。建立在 Spark SQL 之上的第一个版本的**基于成本的优化器**（**CBO**）已经在 Spark 2.2 中发布。有关基于成本的优化的更多细节，请参阅第十一章，*调整 Spark SQL 组件以提高性能*。

所有三个--**DataFrame**、**Dataset**和 SQL--都共享如下图所示的相同优化管道：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00017.jpeg)

# 理解 Catalyst 优化

在 Catalyst 中，有两种主要类型的优化：逻辑和物理：

+   **逻辑优化**：这包括优化器将过滤谓词下推到数据源并使执行跳过无关数据的能力。例如，在 Parquet 文件的情况下，整个块可以被跳过，并且字符串的比较可以通过字典编码转换为更便宜的整数比较。在关系型数据库的情况下，谓词被下推到数据库以减少数据流量。

+   **物理优化**：这包括智能地选择广播连接和洗牌连接以减少网络流量，执行更低级别的优化，如消除昂贵的对象分配和减少虚拟函数调用。因此，当在程序中引入 DataFrame 时，性能通常会提高。

规则执行器负责分析和逻辑优化步骤，而一组策略和规则执行器负责物理规划步骤。规则执行器通过批量应用一组规则将一个树转换为另一个相同类型的树。这些规则可以应用一次或多次。此外，每个规则都被实现为一个转换。转换基本上是一个函数，与每个树相关联，并用于实现单个规则。在 Scala 术语中，转换被定义为部分函数（对其可能的参数子集定义的函数）。这些通常被定义为 case 语句，以确定部分函数（使用模式匹配）是否对给定输入定义。

规则执行器使物理计划准备好执行，通过准备标量子查询，确保输入行满足特定操作的要求，并应用物理优化。例如，在排序合并连接操作中，输入行需要根据连接条件进行排序。优化器在执行排序合并连接操作之前插入适当的排序操作，如有必要。

# 理解 Catalyst 转换

在概念上，Catalyst 优化器执行两种类型的转换。第一种将输入树类型转换为相同的树类型（即，不改变树类型）。这种类型的转换包括将一个表达式转换为另一个表达式，一个逻辑计划转换为另一个逻辑计划，一个物理计划转换为另一个物理计划。第二种类型的转换将一个树类型转换为另一个类型，例如，从逻辑计划转换为物理计划。通过应用一组策略，逻辑计划被转换为物理计划。这些策略使用模式匹配将树转换为另一种类型。例如，我们有特定的模式用于匹配逻辑项目和过滤运算符到物理项目和过滤运算符。

一组规则也可以合并成一个单一的规则来完成特定的转换。例如，根据您的查询，诸如过滤器之类的谓词可以被推送下来以减少执行连接操作之前的总行数。此外，如果您的查询中有一个带有常量的表达式，那么常量折叠优化会在编译时一次计算表达式，而不是在运行时为每一行重复计算。此外，如果您的查询需要一部分列，那么列修剪可以帮助减少列到必要的列。所有这些规则可以合并成一个单一的规则，以实现所有三种转换。

在下面的示例中，我们测量了 Spark 1.6 和 Spark 2.2 上的执行时间差异。我们在下一个示例中使用 iPinYou 实时竞价数据集进行计算广告研究。该数据集包含 iPinYou 全球 RTB 竞价算法竞赛的三个赛季的数据。您可以从伦敦大学学院的数据服务器上下载该数据集，网址为[`data.computational-advertising.org/`](http://data.computational-advertising.org/)。

首先，我们为`bid transactions`和`region`文件中的记录定义`case`类：

```scala
scala> case class PinTrans(bidid: String, timestamp: String, ipinyouid: String, useragent: String, IP: String, region: String, city: String, adexchange: String, domain: String, url:String, urlid: String, slotid: String, slotwidth: String, slotheight: String, slotvisibility: String, slotformat: String, slotprice: String, creative: String, bidprice: String) 

scala> case class PinRegion(region: String, regionName: String)
```

接下来，我们从一个`bids`文件和`region`文件创建 DataFrames：

```scala
scala> val pintransDF = spark.sparkContext.textFile("file:///Users/aurobindosarkar/Downloads/make-ipinyou-data-master/original-data/ipinyou.contest.dataset/training1st/bid.20130314.txt").map(_.split("\t")).map(attributes => PinTrans(attributes(0).trim, attributes(1).trim, attributes(2).trim, attributes(3).trim, attributes(4).trim, attributes(5).trim, attributes(6).trim, attributes(7).trim, attributes(8).trim, attributes(9).trim, attributes(10).trim, attributes(11).trim, attributes(12).trim, attributes(13).trim, attributes(14).trim, attributes(15).trim, attributes(16).trim, attributes(17).trim, attributes(18).trim)).toDF() 

scala> val pinregionDF = spark.sparkContext.textFile("file:///Users/aurobindosarkar/Downloads/make-ipinyou-data-master/original-data/ipinyou.contest.dataset/region.en.txt").map(_.split("\t")).map(attributes => PinRegion(attributes(0).trim, attributes(1).trim)).toDF()
```

接下来，我们借用一个简单的基准函数（在几个 Databricks 示例笔记本中可用）来测量执行时间：

```scala
scala> def benchmark(name: String)(f: => Unit) { 
 val startTime = System.nanoTime 
 f 
 val endTime = System.nanoTime 
 println(s"Time taken in $name: " + (endTime - startTime).toDouble / 1000000000 + " seconds") 
}
```

我们使用 SparkSession 对象将整体阶段代码生成参数关闭（这大致相当于 Spark 1.6 环境）。我们还测量了两个 DataFrame 之间的`join`操作的执行时间：

```scala
scala> spark.conf.set("spark.sql.codegen.wholeStage", false) 
scala> benchmark("Spark 1.6") {  
|  pintransDF.join(pinregionDF, "region").count()  
| }
Time taken in Spark 1.6: 3.742190552 seconds 
```

接下来，我们将整体阶段代码生成参数设置为 true，并测量执行时间。我们注意到在 Spark 2.2 中，相同代码的执行时间要低得多：

```scala
scala> spark.conf.set("spark.sql.codegen.wholeStage", true) 
scala> benchmark("Spark 2.2") {  
|  pintransDF.join(pinregionDF, "region").count()  
| }
Time taken in Spark 2.2: 1.881881579 seconds    
```

我们使用`explain()`函数来打印出 Catalyst 转换管道中的各个阶段。我们将在第十一章中更详细地解释以下输出，*调整 Spark SQL 组件以提高性能*：

```scala
scala> pintransDF.join(pinregionDF, "region").selectExpr("count(*)").explain(true) 
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00018.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00019.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00020.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00021.jpeg)

在接下来的部分中，我们将介绍 Project Tungsten 的与开发人员相关的细节。

# 引入 Project Tungsten

Project Tungsten 被吹捧为自项目成立以来对 Spark 执行引擎的最大改变。Project Tungsten 的动机是观察到在大多数 Spark 工作负载中，CPU 和内存而不是 I/O 和网络是瓶颈。

由于硬件改进（例如 SSD 和条带化 HDD 阵列用于存储）、Spark I/O 的优化（例如 shuffle 和网络层实现、输入数据修剪以减少磁盘 I/O 等）和数据格式的改进（例如 Parquet、二进制数据格式等），CPU 现在成为瓶颈。此外，Spark 中的大规模序列化和哈希任务是 CPU 绑定操作。

Spark 1.x 使用基于迭代器模型的查询评估策略（称为 Volcano 模型）。由于查询中的每个运算符都呈现了一个接口，该接口每次返回一个元组给树中的下一个运算符，因此这个接口允许查询执行引擎组合任意组合的运算符。在 Spark 2.0 之前，大部分 CPU 周期都花在无用的工作上，比如进行虚拟函数调用或者读取/写入中间数据到 CPU 缓存或内存。

Tungsten 项目专注于三个领域，以提高内存和 CPU 的效率，将性能推向底层硬件的极限。这三个领域是内存管理和二进制处理、缓存感知计算和代码生成。此外，集成在 Spark 2.0 中的第二代 Tungsten 执行引擎使用一种称为整体代码生成的技术。这种技术使引擎能够消除虚拟函数调度，并将中间数据从内存移动到 CPU 寄存器，并通过循环展开和 SIMD 利用现代 CPU 特性。此外，Spark 2.0 引擎还通过使用另一种称为矢量化的技术加速了被认为对于代码生成过于复杂的操作。

整体代码生成将整个查询折叠成一个单一函数。此外，它消除了虚拟函数调用，并使用 CPU 寄存器存储中间数据。这反过来显著提高了 CPU 效率和运行时性能。它实现了手写代码的性能，同时继续保持通用引擎。

在矢量化中，引擎以列格式批处理多行数据，每个运算符在一个批次内对数据进行迭代。然而，它仍然需要将中间数据放入内存，而不是保留在 CPU 寄存器中。因此，只有在无法进行整体代码生成时才使用矢量化。

Tungsten 内存管理改进侧重于将 Java 对象以紧凑的二进制格式存储，以减少 GC 开销，将内存中的数据格式更加密集，以减少溢出（例如 Parquet 格式），并且对于了解数据类型的运算符（在 DataFrames、Datasets 和 SQL 的情况下）直接针对内存中的二进制格式进行操作，而不是进行序列化/反序列化等操作。

代码生成利用现代编译器和 CPU 来实现改进。这包括更快的表达式评估和 DataFrame/SQL 运算符，以及更快的序列化器。在 JVM 上对表达式的通用评估非常昂贵，因为涉及虚拟函数调用、基于表达式类型的分支、对象创建和由于原始装箱而导致的内存消耗。通过动态生成自定义字节码，这些开销大大减少了。

在这里，我们介绍了启用了整体代码生成的前一节中的投标和地区 DataFrames 之间的连接操作的物理计划。在`explain()`输出中，当一个运算符标有星号`*`时，这意味着该运算符已启用整体代码生成。在以下物理计划中，这包括 Aggregate、Project、`SortMergeJoin`、Filter 和 Sort 运算符。然而，Exchange 不实现整体代码生成，因为它正在通过网络发送数据：

```scala
scala> pintransDF.join(pinregionDF, "region").selectExpr("count(*)").explain() 
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00022.jpeg)

Tungsten 项目极大地改进了 DataFrames 和 Datasets（适用于所有编程 API - Java、Scala、Python 和 R）和 Spark SQL 查询。此外，对于许多数据处理运算符，新引擎的速度提高了数个数量级。

在接下来的部分中，我们将把重点转移到一个名为 Structured Streaming 的新 Spark 2.0 功能，它支持基于 Spark 的流应用程序。

# 在流应用程序中使用 Spark SQL

流应用变得越来越复杂，因为这样的计算不是孤立运行的。它们需要与批处理数据交互，支持交互式分析，支持复杂的机器学习应用等。通常，这样的应用将传入的事件流存储在长期存储中，持续监视事件，并在存储的数据上运行机器学习模型，同时在传入流上启用持续学习。它们还具有交互式查询存储的数据的能力，同时提供精确一次的写入保证，处理延迟到达的数据，执行聚合等。这些类型的应用远不止是简单的流应用，因此被称为连续应用。

在 Spark 2.0 之前，流应用是建立在 DStreams 的概念上的。使用 DStreams 存在一些痛点。在 DStreams 中，时间戳是事件实际进入 Spark 系统的时间；事件中嵌入的时间不被考虑。此外，尽管相同的引擎可以处理批处理和流处理计算，但涉及的 API 虽然在 RDD（批处理）和 DStream（流处理）之间相似，但需要开发人员进行代码更改。DStream 流模型让开发人员承担了处理各种故障条件的负担，并且很难推理数据一致性问题。在 Spark 2.0 中，引入了结构化流处理来解决所有这些痛点。

结构化流处理是一种快速、容错、精确一次的有状态流处理方法。它使流分析无需考虑流的基本机制。在新模型中，输入可以被视为来自一个不断增长的追加表的数据。触发器指定了检查输入以获取新数据到达的时间间隔。如下图所示，查询表示查询或操作，例如 map、filter 和 reduce 在输入上的操作，结果表示根据指定的操作在每个触发间隔更新的最终表。输出定义了每个时间间隔写入数据接收器的结果的部分。

输出模式可以是 complete、delta 或 append，其中 complete 输出模式表示每次写入完整的结果表，delta 输出模式写入前一批次的更改行，append 输出模式分别只写入新行：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00023.jpeg)

在 Spark 2.0 中，除了静态有界的 DataFrame，我们还有连续无界的 DataFrame 的概念。静态和连续的 DataFrame 都使用相同的 API，从而统一了流、交互和批处理查询。例如，您可以在流中聚合数据，然后使用 JDBC 提供服务。高级流 API 建立在 Spark SQL 引擎上，并与 SQL 查询和 DataFrame/Dataset API 紧密集成。主要好处是您可以使用相同的高级 Spark DataFrame 和 Dataset API，Spark 引擎会找出所需的增量和连续执行操作。

此外，还有查询管理 API，您可以使用它来管理多个并发运行的流查询。例如，您可以列出运行中的查询，停止和重新启动查询，在失败的情况下检索异常等。我们将在第五章中详细了解结构化流处理，*在流应用中使用 Spark SQL*。

在下面的示例代码中，我们使用 iPinYou 数据集中的两个出价文件作为我们流数据的来源。首先，我们定义我们的输入记录模式并创建一个流输入 DataFrame：

```scala
scala> import org.apache.spark.sql.types._ 
scala> import org.apache.spark.sql.functions._ 
scala> import scala.concurrent.duration._ 
scala> import org.apache.spark.sql.streaming.ProcessingTime 
scala> import org.apache.spark.sql.streaming.OutputMode.Complete 

scala> val bidSchema = new StructType().add("bidid", StringType).add("timestamp", StringType).add("ipinyouid", StringType).add("useragent", StringType).add("IP", StringType).add("region", IntegerType).add("city", IntegerType).add("adexchange", StringType).add("domain", StringType).add("url:String", StringType).add("urlid: String", StringType).add("slotid: String", StringType).add("slotwidth", StringType).add("slotheight", StringType).add("slotvisibility", StringType).add("slotformat", StringType).add("slotprice", StringType).add("creative", StringType).add("bidprice", StringType) 

scala> val streamingInputDF = spark.readStream.format("csv").schema(bidSchema).option("header", false).option("inferSchema", true).option("sep", "\t").option("maxFilesPerTrigger", 1).load("file:///Users/aurobindosarkar/Downloads/make-ipinyou-data-master/original-data/ipinyou.contest.dataset/bidfiles")
```

接下来，我们定义我们的查询时间间隔为`20 秒`，输出模式为`Complete`：

```scala
scala> val streamingCountsDF = streamingInputDF.groupBy($"city").count() 

scala> val query = streamingCountsDF.writeStream.format("console").trigger(ProcessingTime(20.seconds)).queryName("counts").outputMode(Complete).start()
```

在输出中，您将观察到每个区域的出价数量在每个时间间隔中随着新数据的到达而更新。您需要将新的出价文件（或者从原始数据集中开始使用多个出价文件，它们将根据`maxFilesPerTrigger`的值依次被处理）放入`bidfiles`目录中，以查看更新后的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00024.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00025.jpeg)

此外，您还可以查询系统中的活动流，如下所示：

```scala
scala> spark.streams.active.foreach(println) 
Streaming Query - counts [state = ACTIVE]
```

最后，您可以使用`stop()`方法停止流应用程序的执行，如下所示：

```scala
//Execute the stop() function after you have finished executing the code in the next section.
scala> query.stop()
```

在下一节中，我们将从概念上描述结构化流的内部工作原理。

# 理解结构化流的内部机制

为了启用结构化流功能，规划器会从源中轮询新数据，并在写入到接收器之前对其进行增量计算。此外，应用程序所需的任何运行聚合都将作为由**Write-Ahead Log**（**WAL**）支持的内存状态进行维护。内存状态数据是在增量执行中生成和使用的。这类应用程序的容错需求包括能够恢复和重放系统中的所有数据和元数据。规划器在执行之前将偏移量写入到持久存储（如 HDFS）上的容错 WAL 中，如图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00026.jpeg)

如果规划器在当前的增量执行中失败，重新启动的规划器将从 WAL 中读取并重新执行所需的确切偏移范围。通常，诸如 Kafka 之类的源也是容错的，并且在规划器恢复的适当偏移量的情况下生成原始事务数据。状态数据通常在 Spark 工作节点中以版本化的键值映射形式进行维护，并由 HDFS 上的 WAL 支持。规划器确保使用正确的状态版本来重新执行故障后的事务。此外，接收器在设计上是幂等的，并且可以处理输出的重复执行而不会出现重复提交。因此，偏移跟踪在 WAL 中，状态管理以及容错源和接收器的整体组合提供了端到端的精确一次性保证。

我们可以使用`explain`方法列出结构化流示例的物理计划，如下所示：

```scala
scala> spark.streams.active(0).explain 
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00027.jpeg)

我们将在第十一章中更详细地解释上述输出，*调整 Spark SQL 组件以提高性能*。

# 总结

在本章中，我们向您介绍了 Spark SQL、SparkSession（Spark SQL 的主要入口点）和 Spark SQL 接口（RDD、DataFrames 和 Dataset）。然后，我们描述了 Spark SQL 的一些内部机制，包括基于 Catalyst 和 Project Tungsten 的优化。最后，我们探讨了如何在流应用程序中使用 Spark SQL 以及结构化流的概念。本章的主要目标是让您了解 Spark SQL 的概况，同时通过实际操作（使用公共数据集）让您熟悉 Spark 环境。

在下一章中，我们将详细介绍如何使用 Spark SQL 来探索大数据应用程序中典型的结构化和半结构化数据。


# 第二章：使用 Spark SQL 处理结构化和半结构化数据

在本章中，我们将介绍如何使用 Spark SQL 与不同类型的数据源和数据存储格式。Spark 提供了易于使用的标准结构（即 RDD 和 DataFrame/Datasets），可用于处理结构化和半结构化数据。我们包括一些在大数据应用中最常用的数据源，如关系数据、NoSQL 数据库和文件（CSV、JSON、Parquet 和 Avro）。Spark 还允许您定义和使用自定义数据源。本章中的一系列实践练习将使您能够使用 Spark 处理不同类型的数据源和数据格式。

在本章中，您将学习以下主题：

+   了解 Spark 应用中的数据源

+   使用 JDBC 与关系数据库交互

+   使用 Spark 与 MongoDB（NoSQL 数据库）

+   处理 JSON 数据

+   使用 Spark 与 Avro 和 Parquet 数据集

# 了解 Spark 应用中的数据源

Spark 可以连接到许多不同的数据源，包括文件、SQL 和 NoSQL 数据库。一些更受欢迎的数据源包括文件（CSV、JSON、Parquet、AVRO）、MySQL、MongoDB、HBase 和 Cassandra。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00028.jpeg)

此外，它还可以连接到专用引擎和数据源，如 ElasticSearch、Apache Kafka 和 Redis。这些引擎可以在 Spark 应用中实现特定功能，如搜索、流处理、缓存等。例如，Redis 可以在高性能应用中部署缓存的机器学习模型。我们将在第十二章中讨论更多关于基于 Redis 的应用部署的内容，即*大规模应用架构中的 Spark SQL*。Kafka 在 Spark 流处理应用中非常受欢迎，我们将在第五章和第十二章中详细介绍基于 Kafka 的流处理应用，即*在流处理应用中使用 Spark SQL*和*大规模应用架构中的 Spark SQL*。DataSource API 使 Spark 能够连接到各种数据源，包括自定义数据源。

请参考 Spark 软件包网站[`spark-packages.org/`](https://spark-packages.org/)，以使用各种数据源、算法和专用数据集。

在第一章中，*开始使用 Spark SQL*，我们使用文件系统上的 CSV 和 JSON 文件作为输入数据源，并使用 SQL 进行查询。但是，使用 Spark SQL 查询存储在文件中的数据并不是使用数据库的替代品。最初，一些人使用 HDFS 作为数据源，因为使用 Spark SQL 查询此类数据的简单性和便利性。然而，执行性能可能会根据执行的查询和工作负载的性质而有显著差异。架构师和开发人员需要了解使用哪些数据存储来最好地满足其处理需求。我们将在下面讨论选择 Spark 数据源的一些高级考虑因素。

# 选择 Spark 数据源

文件系统是存储大量数据和支持大型数据集通用处理的理想场所。使用文件的一些好处包括廉价的存储、灵活的处理和可扩展性。将大规模数据存储在文件中的决定通常是由商业数据库存储同样数据的成本限制所驱动的。此外，当数据的性质不适合典型的数据库优化时，例如非结构化数据时，通常也会优先选择文件存储。此外，具有迭代内存处理需求和分布式算法的工作负载，例如机器学习应用，可能更适合在分布式文件系统上运行。

通常在文件系统上存储的数据类型包括归档数据、非结构化数据、大规模社交媒体和其他网络规模数据集，以及主要数据存储的备份副本。最适合在文件上支持的工作负载类型包括批处理工作负载、探索性数据分析、多阶段处理管道和迭代工作负载。使用文件的热门案例包括 ETL 管道、跨多种数据源拼接数据，如日志文件、CSV、Parquet、压缩文件格式等。此外，您可以选择以针对特定处理需求进行优化的多种格式存储相同的数据。

与 Spark 连接到文件系统不太适合的是频繁的随机访问、频繁的插入、频繁/增量更新以及在多用户情况下承受重负载条件下的报告或搜索操作。随着我们的深入，将更详细地讨论这些使用案例。

在 Spark 中支持从分布式存储中选择少量记录的查询，但效率不高，因为通常需要 Spark 浏览所有文件以找到结果行。这对于数据探索任务可能是可以接受的，但对于来自多个并发用户的持续处理负载则不行。如果您需要频繁和随机地访问数据，使用数据库可能是更有效的解决方案。使用传统的 SQL 数据库使数据可用于用户，并在关键列上创建索引可以更好地支持这种使用案例。另外，键值 NoSQL 存储也可以更有效地检索键的值。

每次插入都会创建一个新文件，插入速度相当快，但查询速度较慢，因为 Spark 作业需要打开所有这些文件并从中读取以支持查询。同样，用于支持频繁插入的数据库可能是更好的解决方案。另外，您还可以定期压缩 Spark SQL 表文件，以减少总文件数量。使用`Select *`和`coalesce` DataFrame 命令，将从多个输入文件创建的 DataFrame 中的数据写入单个/组合输出文件。

其他操作和使用案例，如频繁/增量更新、报告和搜索，最好使用数据库或专门的引擎来处理。文件不适合更新随机行。然而，数据库非常适合执行高效的更新操作。您可以将 Spark 连接到 HDFS 并使用 BI 工具，如 Tableau，但最好将数据转储到数据库以为承受负载的并发用户提供服务。通常，最好使用 Spark 读取数据，执行聚合等操作，然后将结果写入为最终用户提供服务的数据库。在搜索使用案例中，Spark 将需要浏览每一行以查找并返回搜索结果，从而影响性能。在这种情况下，使用专门的引擎，如 ElasticSearch 和 Apache Solr，可能比使用 Spark 更好。

在数据严重倾斜的情况下，或者在集群上执行更快的连接时，我们可以使用集群或分桶技术来提高性能。

# 使用 Spark 与关系数据库

关于关系数据库是否适合大数据处理场景存在着巨大的争论。然而，不可否认的是，企业中大量结构化数据存储在这些数据库中，并且组织在关键业务交易中严重依赖现有的关系数据库管理系统。

绝大多数开发人员最喜欢使用关系数据库和主要供应商提供的丰富工具集。越来越多的云服务提供商，如亚马逊 AWS，已经简化了许多组织将其大型关系数据库转移到云端的管理、复制和扩展。

关系数据库的一些很好的大数据使用案例包括以下内容：

+   复杂的 OLTP 事务

+   需要 ACID 合规性的应用程序或功能

+   支持标准 SQL

+   实时自发查询功能

+   实施许多复杂关系的系统

有关 NoSQL 和关系使用情况的出色覆盖，请参阅标题为“你到底在使用 NoSQL 做什么？”的博客[`highscalability.com/blog/2010/12/6/what-the-heck-are-you-actually-using-nosql-for.html`](http://highscalability.com/blog/2010/12/6/what-the-heck-are-you-actually-using-nosql-for.html)。

在 Spark 中，很容易处理关系数据并将其与不同形式和格式的其他数据源结合起来：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00029.jpeg)

作为使用 Spark 与 MySQL 数据库的示例，我们将实现一个用例，其中我们将数据在 HDFS 和 MySQL 之间进行分割。MySQL 数据库将用于支持来自并发用户的交互式查询，而 HDFS 上的数据将用于批处理、运行机器学习应用程序以及向 BI 工具提供数据。在此示例中，我们假设交互式查询仅针对当前月份的数据。因此，我们将只保留当前月份的数据在 MySQL 中，并将其余数据写入 HDFS（以 JSON 格式）。

我们将遵循的实施步骤如下：

1.  创建 MySQL 数据库。

1.  定义一个表。

1.  创建用户 ID 并授予权限。

1.  使用 MySQL JDBC 驱动程序启动 Spark shell。

1.  从输入数据文件创建一个 RDD，分离标题，定义模式并创建一个 DataFrame。

1.  为时间戳创建一个新列。

1.  根据时间戳值（当前月份数据和以前月份的其余数据）将数据分成两个 DataFrame。

1.  删除原始 invoiceDate 列，然后将时间戳列重命名为 invoiceDate。

1.  将包含当前月份数据的 DataFrame 写入 MySQL 表中。

1.  将包含数据（除当前月份数据之外的数据）的 DataFrame 写入 HDFS（以 JSON 格式）。

如果您尚未安装和可用 MySQL，可以从[`www.mysql.com/downloads/`](https://www.mysql.com/downloads/)下载。按照特定操作系统的安装说明安装数据库。此外，从同一网站下载可用的 JDBC 连接器。

在您的 MySQL 数据库服务器运行起来后，启动 MySQL shell。在接下来的步骤中，我们将创建一个新数据库并定义一个交易表。我们使用一个包含所有发生在 2010 年 12 月 1 日至 2011 年 12 月 9 日之间的交易的交易数据集，这是一个基于英国注册的非实体在线零售的数据集。该数据集由伦敦南岸大学工程学院公共分析小组主任 Dr Daqing Chen 贡献，并可在[`archive.ics.uci.edu/ml/datasets/Online+Retail`](https://archive.ics.uci.edu/ml/datasets/Online+Retail)上找到。

当您启动 MySQL shell 时，应该看到类似以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00030.jpeg)

1.  创建一个名为`retailDB`的新数据库来存储我们的客户交易数据：

```scala
      mysql> create database retailDB;
      Connect to retailDB as follows:
      mysql> use retailDB;
```

1.  在这里，我们使用`transactionID`作为主键定义了一个交易表。在生产场景中，您还将在其他字段上创建索引，例如`CustomerID`，以更有效地支持查询：

```scala
      mysql>create table transactions(transactionID integer not null 
      auto_increment, invoiceNovarchar(20), stockCodevarchar(20), 
      description varchar(255), quantity integer, unitPrice double, 
      customerIDvarchar(20), country varchar(100), invoiceDate 
      Timestamp, primary key(transactionID));
```

接下来，使用`describe`命令验证交易表模式，以确保它完全符合我们的要求：

```scala
mysql> describe transactions;
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00031.jpeg)

1.  创建一个名为`retaildbuser`的用户 ID 并授予其所有权限。我们将从我们的 Spark shell 中使用此用户进行连接和执行查询。

```scala
      mysql> CREATE USER 'retaildbuser'@'localhost' IDENTIFIED BY 
             'mypass';
      mysql> GRANT ALL ON retailDB.* TO 'retaildbuser'@'localhost';
```

1.  启动包含 MySQL JDBC 驱动程序路径的 Spark shell，如下所示：

```scala
      SPARK_CLASSPATH=/Users/aurobindosarkar/Downloads/mysql-connector-
      java-5.1.38/mysql-connector-java-5.1.38-bin.jar bin/spark-shell
```

1.  创建一个包含我们下载的数据集中所有行的`RDD`：

```scala
      scala> import org.apache.spark.sql.types._
      scala> import org.apache.spark.sql.Row
      scala> import java.util.Properties

      scala>val inFileRDD =       
      sc.textFile("file:///Users/aurobindosarkar/Downloads/UCI Online  
      Retail.txt")
```

1.  将标题与其余数据分开：

```scala
      scala>val allRowsRDD = inFileRDD.map(line 
      =>line.split("\t").map(_.trim))
      scala>val header = allRowsRDD.first
      scala>val data = allRowsRDD.filter(_(0) != header(0))
```

1.  定义字段并为我们的数据记录定义模式，如下所示：

```scala
      scala>val fields = Seq(
      | StructField("invoiceNo", StringType, true),
      | StructField("stockCode", StringType, true),
      | StructField("description", StringType, true),
      | StructField("quantity", IntegerType, true),
      | StructField("invoiceDate", StringType, true),
      | StructField("unitPrice", DoubleType, true),
      | StructField("customerID", StringType, true),
      | StructField("country", StringType, true)
      | )
      scala>val schema = StructType(fields)
```

1.  创建一个包含 Row 对象的`RDD`，使用先前创建的模式创建一个 DataFrame：

```scala
      scala>val rowRDD = data.map(attributes => Row(attributes(0), 
      attributes(1), attributes(2), attributes(3).toInt, attributes(4), 
      attributes(5).toDouble, attributes(6), attributes(7)))

      scala>val r1DF = spark.createDataFrame(rowRDD, schema)
```

1.  向 DataFrame 添加名为`ts`（时间戳列）的列，如下所示：

```scala
      scala>val ts = 
      unix_timestamp($"invoiceDate","dd/MM/yyHH:mm").cast("timestamp")
      scala>val r2DF = r1DF.withColumn("ts", ts)
      scala>r2DF.show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00032.jpeg)

1.  创建一个表对象，并执行适当的 SQL 将表数据基于时间戳分成两个 DataFrame：

```scala
      scala> r2DF.createOrReplaceTempView("retailTable")
      scala>val r3DF = spark.sql("select * from retailTable where ts< 
      '2011-12-01'")
      scala>val r4DF = spark.sql("select * from retailTable where ts>= 
      '2011-12-01'")
```

1.  删除我们新 DataFrame 中的`invoiceDate`列。

```scala
      scala>val selectData = r4DF.select("invoiceNo", "stockCode", 
      "description", "quantity", "unitPrice", "customerID", "country", 
      "ts")
```

1.  将`ts`列重命名为`invoiceDate`，如下所示：

```scala
      scala>val writeData = selectData.withColumnRenamed("ts", 
      "invoiceDate")
      scala>writeData.show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00033.jpeg)

1.  创建一个指向数据库 URL 的变量。另外，创建一个`Properties`对象来保存连接到`retailDB`所需的用户 ID 和密码。接下来，连接到 MySQL 数据库，并将“当前月份”的记录插入到 transactions 表中：

```scala
      scala>val dbUrl = "jdbc:mysql://localhost:3306/retailDB"
      scala>val prop = new Properties()
      scala>prop.setProperty("user", "retaildbuser")
      scala>prop.setProperty("password", "mypass")
      scala>writeData.write.mode("append").jdbc(dbUrl, "transactions", 
      prop)
```

1.  从 DataFrame 中选择感兴趣的列（包含当前月份以外的数据），并以 JSON 格式将其写入 HDFS 文件系统：

```scala
      scala>val selectData = r3DF.select("invoiceNo", "stockCode", 
      "description", "quantity", "unitPrice", "customerID", "country", 
      "ts")

      scala>val writeData = selectData.withColumnRenamed("ts", 
      "invoiceDate")
      scala>writeData.select("*").write.format("json")
      .save("hdfs://localhost:9000/Users/r3DF")
```

# 使用 Spark 处理 MongoDB（NoSQL 数据库）

在本节中，我们将使用 Spark 与最流行的 NoSQL 数据库之一 - MongoDB。 MongoDB 是一个分布式文档数据库，以类似 JSON 的格式存储数据。与关系数据库中的严格模式不同，MongoDB 中的数据结构更加灵活，存储的文档可以具有任意字段。这种灵活性与高可用性和可扩展性功能结合在一起，使其成为许多应用程序中存储数据的良好选择。它还是免费和开源软件。

如果您尚未安装和可用 MongoDB，则可以从[`www.mongodb.org/downloads`](https://www.mongodb.com/download-center#community)下载。按照特定操作系统的安装说明安装数据库。

本示例的纽约市学校目录数据集来自纽约市开放数据网站，可从[`nycplatform.socrata.com/data?browseSearch=&scope=&agency=&cat=education&type=datasets`](https://nycplatform.socrata.com/data?browseSearch=&scope=&agency=&cat=education&type=datasets)下载。

在您的 MongoDB 数据库服务器运行后，启动 MongoDB shell。在接下来的步骤中，我们将创建一个新数据库，定义一个集合，并使用命令行中的 MongoDB 导入实用程序插入纽约市学校的数据。

当您启动 MongoDB shell 时，应该看到类似以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00034.jpeg)

接下来，执行`use <DATABASE>`命令选择现有数据库或创建一个新数据库（如果不存在）。

如果在创建新集合时出现错误，可以使用`db.dropDatabase()`和/或`db.collection.drop()`命令分别删除数据库和/或集合，然后根据需要重新创建它。

```scala
>use nycschoolsDB
switched to dbnycschoolsDB
```

`mongoimport`实用程序需要从命令提示符（而不是`mongodb` shell）中执行：

```scala

mongoimport --host localhost --port 27017 --username <your user name here> --password "<your password here>" --collection schools --db nycschoolsDB --file <your download file name here>
```

您可以列出导入的集合并打印记录以验证导入操作，如下所示：

```scala
>show collections
 schools
 >db.schools.findOne()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00035.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00036.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00037.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00038.jpeg)

您可以从[`repo1.maven.org/maven2/org/mongodb/spark/mongo-spark-connector_2.11/2.2.0/`](http://repo1.maven.org/maven2/org/mongodb/spark/mongo-spark-connector_2.11/2.2.0/)下载适用于 Spark 2.2 的`mongo-spark-connector jar`（`mongo-spark-connector_2.11-2.2.0-assembly.jar`）。

接下来，使用命令行指定`mongo-spark-connector_2.11-2.2.0-assembly.jar`文件启动 Spark shell：

```scala
./bin/spark-shell --jars /Users/aurobindosarkar/Downloads/mongo-spark-connector_2.11-2.2.0-assembly.jar
scala> import org.apache.spark.sql.SQLContext
scala> import org.apache.spark.{SparkConf, SparkContext}
scala> import com.mongodb.spark.MongoSpark
scala> import com.mongodb.spark.config.{ReadConfig, WriteConfig}
```

接下来，我们定义了从 Spark 进行`read`和`write`操作的 URI：

```scala
scala>val readConfig = ReadConfig(Map("uri" -> "mongodb://localhost:27017/nycschoolsDB.schools?readPreference=primaryPreferred"))

scala>val writeConfig = WriteConfig(Map("uri" -> "mongodb://localhost:27017/nycschoolsDB.outCollection"))
```

定义一个学校记录的`case`类，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00039.jpeg)

接下来，您可以从我们的集合创建一个 DataFrame，并显示新创建的 DataFrame 中的记录。

```scala
scala>val schoolsDF = MongoSpark.load(sc, readConfig).toDF[School]

scala>schoolsDF.take(1).foreach(println)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00040.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00041.jpeg)

注意：以下各节将在稍后使用最新版本的连接器包进行更新。

在接下来的几节中，我们将描述使用 Spark 处理几种流行的大数据文件格式。

# 使用 Spark 处理 JSON 数据

JSON 是一种简单、灵活和紧凑的格式，在 Web 服务中广泛用作数据交换格式。Spark 对 JSON 的支持非常好。不需要为 JSON 数据定义模式，因为模式会自动推断。此外，Spark 极大地简化了访问复杂 JSON 数据结构中字段所需的查询语法。我们将在第十二章《大规模应用架构中的 Spark SQL》中详细介绍 JSON 数据的示例。

此示例的数据集包含大约 169 万条电子产品类别的亚马逊评论，可从以下网址下载：[`jmcauley.ucsd.edu/data/amazon/`](http://jmcauley.ucsd.edu/data/amazon/)。

我们可以直接读取 JSON 数据集以创建 Spark SQL DataFrame。我们将从 JSON 文件中读取一组订单记录的示例集：

```scala
scala>val reviewsDF = spark.read.json("file:///Users/aurobindosarkar/Downloads/reviews_Electronics_5.json")
```

您可以使用`printSchema`方法打印新创建的 DataFrame 的模式，以验证字段及其特性。

```scala
scala> reviewsDF.printSchema()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00042.jpeg)

一旦 JSON 数据集转换为 Spark SQL DataFrame，您可以以标准方式进行大量操作。接下来，我们将执行 SQL 语句，从特定年龄段的客户接收的订单中选择特定列：

```scala
scala>reviewsDF.createOrReplaceTempView("reviewsTable")
scala>val selectedDF = spark.sql("SELECT asin, overall, reviewTime, reviewerID, reviewerName FROM reviewsTable WHERE overall >= 3")
```

使用`show`方法显示 SQL 执行结果（存储在另一个 DataFrame 中），如下所示：

```scala
scala> selectedDF.show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00043.jpeg)

我们可以使用 DSL 访问`reviewDF` DataFrame 中`helpful`列的数组元素，如下所示：

```scala
scala> val selectedJSONArrayElementDF = reviewsDF.select($"asin", $"overall", $"helpful").where($"helpful".getItem(0) < 3)

scala>selectedJSONArrayElementDF.show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00044.jpeg)

在前面的部分中，我们演示了将 DataFrame 写出为 JSON 文件的示例，其中我们从 DataFrame 中选择了感兴趣的列（包含当前月份之外的数据），并将其写出为 JSON 格式到 HDFS 文件系统。

# 使用 Avro 文件的 Spark

Avro 是一个非常流行的数据序列化系统，提供了紧凑和快速的二进制数据格式。Avro 文件是自描述的，因为模式与数据一起存储。

您可以从[`mvnrepository.com/artifact/com.databricks/spark-avro_2.11/3.2.0`](https://mvnrepository.com/artifact/com.databricks/spark-avro_2.11/3.2.0)下载`spark-avro connector` JAR。

我们将在本节切换到 Spark 2.1。在撰写本书时，由于`spark-avro connector`库中的已记录的错误，我们在使用`spark-avro connector 3.2`与 Spark 2.2 时遇到异常。

启动包含 spark-avro JAR 的 Spark shell 会话：

```scala
Aurobindos-MacBook-Pro-2:spark-2.1.0-bin-hadoop2.7 aurobindosarkar$ bin/spark-shell --jars /Users/aurobindosarkar/Downloads/spark-avro_2.11-3.2.0.jar
```

我们将使用前一节中包含亚马逊评论数据的 JSON 文件来创建`Avro`文件。从输入 JSON 文件创建一个 DataFrame，并显示记录数：

```scala
scala> import com.databricks.spark.avro._
scala> val reviewsDF = spark.read.json("file:///Users/aurobindosarkar/Downloads/reviews_Electronics_5.json")

scala> reviewsDF.count()
res4: Long = 1689188  
```

接下来，我们过滤所有评分低于`3`的评论，将输出合并为单个文件，并将结果 DataFrame 写出为`Avro`文件：

```scala
scala> reviewsDF.filter("overall < 3").coalesce(1).write.avro("file:///Users/aurobindosarkar/Downloads/amazon_reviews/avro")

```

接下来，我们展示如何通过从上一步创建的`Avro`文件创建一个 DataFrame 来读取`Avro`文件，并显示其中的记录数：

```scala
scala> val reviewsAvroDF = spark.read.avro("file:///Users/aurobindosarkar/Downloads/amazon_reviews/avro/part-00000-c6b6b423-70d6-440f-acbe-0de65a6a7f2e.avro")

scala> reviewsAvroDF.count()
res5: Long = 190864
```

接下来，我们选择几列，并通过指定`show(5)`显示结果 DataFrame 的前五条记录：

```scala
scala> reviewsAvroDF.select("asin", "helpful", "overall", "reviewTime", "reviewerID", "reviewerName").show(5)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00045.jpeg)

接下来，通过设置 Spark 会话配置值为`Avro`文件指定压缩选项：

```scala
scala> spark.conf.set("spark.sql.avro.compression.codec", "deflate")
scala> spark.conf.set("spark.sql.avro.deflate.level", "5")
```

现在，当我们写入 DataFrame 时，`Avro`文件以压缩格式存储：

```scala
scala> val reviewsAvroDF = spark.read.avro("file:////Users/aurobindosarkar/Downloads/amazon_reviews/avro/part-00000-c6b6b423-70d6-440f-acbe-0de65a6a7f2e.avro")
```

您还可以按特定列对 DataFrame 进行分区。在这里，我们基于`overall`列（每行包含`值<3`）进行分区：

```scala
scala> reviewsAvroDF.write.partitionBy("overall").avro("file:////Users/aurobindosarkar/Downloads/amazon_reviews/avro/partitioned")
```

此会话中 Avro 文件的屏幕截图显示在此处。请注意压缩版本（67 MB）与原始文件（97.4 MB）的大小。此外，请注意为分区（按`overall`值）`Avro`文件创建的两个单独目录。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00046.jpeg)

有关`spark-avro`的更多详细信息，请参阅：[`github.com/databricks/spark-avro`](https://github.com/databricks/spark-avro)

# 使用 Parquet 文件的 Spark

Apache Parquet 是一种流行的列存储格式。它在 Hadoop 生态系统中的许多大数据应用程序中使用。Parquet 支持非常高效的压缩和编码方案，可以显著提高这些应用程序的性能。在本节中，我们向您展示了您可以直接将 Parquet 文件读入标准 Spark SQL DataFrame 的简单性。

在这里，我们使用之前从 Amazon 评论的 JSON 格式文件中创建的 reviewsDF，并将其以 Parquet 格式写出，以创建 Parquet 文件。我们使用`coalesce(1)`来创建一个单一的输出文件：

```scala
scala> reviewsDF.filter("overall < 3").coalesce(1).write.parquet("file:///Users/aurobindosarkar/Downloads/amazon_reviews/parquet")
```

在下一步中，我们使用一个语句从 Parquet 文件创建一个 DataFrame：

```scala
scala> val reviewsParquetDF = spark.read.parquet("file:///Users/aurobindosarkar/Downloads/amazon_reviews/parquet/part-00000-3b512935-ec11-48fa-8720-e52a6a29416b.snappy.parquet")
```

创建 DataFrame 后，您可以像处理来自任何其他数据源创建的 DataFrame 一样对其进行操作。在这里，我们将 DataFrame 注册为临时视图，并使用 SQL 进行查询：

```scala
scala> reviewsParquetDF.createOrReplaceTempView("reviewsTable")
scala> val reviews1RatingsDF = spark.sql("select asin, overall, reviewerID, reviewerName from reviewsTable where overall < 2")
```

在这里，我们指定了两个参数来显示结果 DataFrame 中的记录。第一个参数指定要显示的记录数，第二个参数的值为 false 时显示列中的完整值（不截断）。

```scala
scala> reviews1RatingsDF.show(5, false)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00047.jpeg)

# 在 Spark 中定义和使用自定义数据源

您可以定义自己的数据源，并将这些数据源的数据与其他更标准的数据源（例如关系数据库、Parquet 文件等）的数据结合起来。在第五章中，*在流应用中使用 Spark SQL*，我们为从**伦敦交通**（TfL）网站提供的公共 API 中流式数据定义了一个自定义数据源。

参考视频*Spark DataFrames Simple and Fast Analysis of Structured Data - Michael Armbrust (Databricks)* [`www.youtube.com/watch?v=xWkJCUcD55w`](https://www.youtube.com/watch?v=xWkJCUcD55w) 中定义 Jira 数据源并从中创建 Spark SQL DataFrame 的良好示例。

# 总结

在本章中，我们演示了使用 Spark 与各种数据源和数据格式。我们使用 Spark 来处理关系数据库（MySQL）、NoSQL 数据库（MongoDB）、半结构化数据（JSON）以及在 Hadoop 生态系统中常用的数据存储格式（Avro 和 Parquet）。这为您非常好地准备了接下来更高级的 Spark 应用程序导向章节。

在下一章中，我们将把焦点从处理 Spark 的机制转移到如何使用 Spark SQL 来探索数据、执行数据质量检查和可视化数据。


# 第三章：使用 Spark SQL 进行数据探索

在本章中，我们将介绍如何使用 Spark SQL 进行探索性数据分析。我们将介绍计算一些基本统计数据、识别异常值和可视化、抽样和透视数据的初步技术。本章中的一系列实践练习将使您能够使用 Spark SQL 以及 Apache Zeppelin 等工具来开发对数据的直觉。

在本章中，我们将讨论以下主题：

+   什么是探索性数据分析（EDA）

+   为什么 EDA 很重要？

+   使用 Spark SQL 进行基本数据分析

+   使用 Apache Zeppelin 可视化数据

+   使用 Spark SQL API 对数据进行抽样

+   使用 Spark SQL 创建透视表

# 引入探索性数据分析（EDA）

探索性数据分析（EDA）或初始数据分析（IDA）是一种试图最大程度地洞察数据的数据分析方法。这包括评估数据的质量和结构，计算摘要或描述性统计数据，并绘制适当的图表。它可以揭示潜在的结构，并建议如何对数据进行建模。此外，EDA 帮助我们检测数据中的异常值、错误和异常，并决定如何处理这些数据通常比其他更复杂的分析更重要。EDA 使我们能够测试我们的基本假设，发现数据中的聚类和其他模式，并确定各种变量之间可能的关系。仔细的 EDA 过程对于理解数据至关重要，有时足以揭示数据质量差劣，以至于使用基于模型的更复杂分析是不合理的。

典型情况下，探索性数据分析（EDA）中使用的图形技术是简单的，包括绘制原始数据和简单的统计。重点是数据所揭示的结构和模型，或者最适合数据的模型。EDA 技术包括散点图、箱线图、直方图、概率图等。在大多数 EDA 技术中，我们使用所有数据，而不做任何基本假设。分析师通过这种探索建立直觉或获得对数据集的“感觉”。更具体地说，图形技术使我们能够有效地选择和验证适当的模型，测试我们的假设，识别关系，选择估计量，检测异常值等。

EDA 涉及大量的试错和多次迭代。最好的方法是从简单开始，然后随着进展逐渐增加复杂性。在建模中存在着简单和更准确之间的重大折衷。简单模型可能更容易解释和理解。这些模型可以让您很快达到 90%的准确性，而更复杂的模型可能需要几周甚至几个月才能让您获得额外的 2%的改进。例如，您应该绘制简单的直方图和散点图，以快速开始对数据进行直觉开发。

# 使用 Spark SQL 进行基本数据分析

交互式地处理和可视化大型数据是具有挑战性的，因为查询可能需要很长时间才能执行，而可视化界面无法容纳与数据点一样多的像素。Spark 支持内存计算和高度的并行性，以实现与大规模分布式数据的交互性。此外，Spark 能够处理百万亿字节的数据，并提供一组多功能的编程接口和库。这些包括 SQL、Scala、Python、Java 和 R API，以及用于分布式统计和机器学习的库。

对于适合放入单台计算机的数据，有许多好的工具可用，如 R、MATLAB 等。然而，如果数据不适合放入单台计算机，或者将数据传输到该计算机非常复杂，或者单台计算机无法轻松处理数据，那么本节将提供一些用于数据探索的好工具和技术。

在本节中，我们将进行一些基本的数据探索练习，以了解一个样本数据集。我们将使用一个包含与葡萄牙银行机构的直接营销活动（电话营销）相关数据的数据集。这些营销活动是基于对客户的电话呼叫。我们将使用包含 41,188 条记录和 20 个输入字段的`bank-additional-full.csv`文件，按日期排序（从 2008 年 5 月到 2010 年 11 月）。该数据集由 S. Moro、P. Cortez 和 P. Rita 贡献，并可从[`archive.ics.uci.edu/ml/datasets/Bank+Marketing`](https://archive.ics.uci.edu/ml/datasets/Bank+Marketing)下载。

1.  首先，让我们定义一个模式并读取 CSV 文件以创建一个数据框架。您可以使用`:paste`命令将初始一组语句粘贴到您的 Spark shell 会话中（使用*Ctrl*+*D*退出粘贴模式），如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00048.jpeg)

1.  创建了数据框架之后，我们首先验证记录的数量：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00049.jpeg)

1.  我们还可以为我们的输入记录定义一个名为`Call`的`case`类，然后创建一个强类型的数据集，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00050.jpeg)

在下一节中，我们将通过识别数据集中的缺失数据来开始我们的数据探索。

# 识别缺失数据

数据集中的缺失数据可能是由于从疏忽到受访者拒绝提供特定数据点的原因而导致的。然而，在所有情况下，缺失数据都是真实世界数据集中的常见现象。缺失数据可能会在数据分析中造成问题，有时会导致错误的决策或结论。因此，识别缺失数据并制定有效的处理策略非常重要。

在本节中，我们分析了样本数据集中具有缺失数据字段的记录数量。为了模拟缺失数据，我们将编辑我们的样本数据集，将包含“unknown”值的字段替换为空字符串。

首先，我们从我们编辑的文件中创建了一个数据框架/数据集，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00051.jpeg)

以下两个语句给出了具有某些字段缺失数据的行数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00052.gif)

在第四章中，*使用 Spark SQL 进行数据整理*，我们将探讨处理缺失数据的有效方法。在下一节中，我们将计算样本数据集的一些基本统计数据，以改善我们对数据的理解。

# 计算基本统计数据

计算基本统计数据对于对我们的数据有一个良好的初步了解是至关重要的。首先，为了方便起见，我们创建了一个案例类和一个数据集，其中包含来自我们原始数据框架的一部分字段。在以下示例中，我们选择了一些数值字段和结果字段，即“订阅定期存款”的字段：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00053.jpeg)

接下来，我们使用`describe()`计算数据集中数值列的`count`、`mean`、`stdev`、`min`和`max`值。`describe()`命令提供了一种快速检查数据的方法。例如，所选列的行数与数据框架中的总记录数匹配（没有空值或无效行），年龄列的平均值和值范围是否符合您的预期等。根据平均值和标准差的值，您可以选择某些数据元素进行更深入的分析。例如，假设正态分布，年龄的平均值和标准差值表明大多数年龄值在 30 到 50 岁的范围内，对于其他列，标准差值可能表明数据的偏斜（因为标准差大于平均值）。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00054.jpeg)

此外，我们可以使用 stat 包计算额外的统计数据，如协方差和 Pearson 相关系数。协方差表示两个随机变量的联合变异性。由于我们处于 EDA 阶段，这些测量可以为我们提供有关一个变量如何相对于另一个变量变化的指标。例如，协方差的符号表示两个变量之间变异性的方向。在以下示例中，年龄和最后一次联系的持续时间之间的协方差方向相反，即随着年龄的增加，持续时间减少。相关性给出了这两个变量之间关系强度的大小。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00055.jpeg)

我们可以创建两个变量之间的交叉表或交叉表，以评估它们之间的相互关系。例如，在以下示例中，我们创建了一个代表 2x2 列联表的年龄和婚姻状况的交叉表。从表中，我们了解到，对于给定年龄，各种婚姻状况下的个体总数的分布情况。我们还可以提取数据 DataFrame 列中最频繁出现的项目。在这里，我们选择教育水平作为列，并指定支持水平为`0.3`，即我们希望在 DataFrame 中找到出现频率大于`0.3`（至少观察到 30%的时间）的教育水平。最后，我们还可以计算 DataFrame 中数值列的近似分位数。在这里，我们计算年龄列的分位数概率为`0.25`、`0.5`和`0.75`（值为`0`是最小值，`1`是最大值，`0.5`是中位数）。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00056.jpeg)

接下来，我们使用聚合函数对我们的数据进行汇总，以更好地了解它。在以下语句中，我们按是否订阅定期存款以及联系的客户总数、每位客户平均拨打电话次数、通话平均持续时间和向这些客户拨打的平均上次电话次数进行聚合。结果四舍五入到小数点后两位：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00057.jpeg)

同样，执行以下语句会按客户年龄给出类似的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00058.jpeg)

在通过计算基本统计数据更好地了解我们的数据之后，我们将重点转向识别数据中的异常值。

# 识别数据异常值

异常值或异常值是数据中明显偏离数据集中其他观察值的观察值。这些错误的异常值可能是由于数据收集中的错误或测量的变异性。它们可能会对结果产生重大影响，因此在 EDA 过程中识别它们至关重要。

然而，这些技术将异常值定义为不属于簇的点。用户必须使用统计分布对数据点进行建模，并根据它们在与基础模型的关系中的出现方式来识别异常值。这些方法的主要问题是在 EDA 过程中，用户通常对基础数据分布没有足够的了解。

使用建模和可视化方法进行探索性数据分析（EDA）是获得对数据更深刻理解的好方法。Spark MLlib 支持大量（并不断增加）的分布式机器学习算法，使这项任务变得更简单。例如，我们可以应用聚类算法并可视化结果，以检测组合列中的异常值。在以下示例中，我们使用最后一次联系持续时间（以秒为单位）、在此客户（campaign）的此次活动期间执行的联系次数、在上一次活动期间客户最后一次联系后经过的天数（pdays）和在此客户（prev）的此次活动之前执行的联系次数来应用 k 均值聚类算法在我们的数据中计算两个簇：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00059.jpeg)

用于探索性数据分析的其他分布式算法包括分类、回归、降维、相关性和假设检验。有关使用 Spark SQL 和这些算法的更多细节，请参阅第六章中的*在机器学习应用中使用 Spark SQL*。

# 使用 Apache Zeppelin 可视化数据

通常，我们会生成许多图表来验证我们对数据的直觉。在探索性数据分析期间使用的许多快速而肮脏的图表最终被丢弃。探索性数据可视化对于数据分析和建模至关重要。然而，我们经常因为难以处理而跳过大数据的探索性可视化。例如，浏览器通常无法处理数百万个数据点。因此，我们必须在有效可视化数据之前对数据进行总结、抽样或建模。

传统上，BI 工具提供了广泛的聚合和透视功能来可视化数据。然而，这些工具通常使用夜间作业来总结大量数据。随后，总结的数据被下载并在从业者的工作站上可视化。Spark 可以消除许多这些批处理作业，以支持交互式数据可视化。

在本节中，我们将使用 Apache Zeppelin 探索一些基本的数据可视化技术。Apache Zeppelin 是一个支持交互式数据分析和可视化的基于 Web 的工具。它支持多种语言解释器，并具有内置的 Spark 集成。因此，使用 Apache Zeppelin 进行探索性数据分析是快速而简单的：

1.  您可以从[`zeppelin.apache.org/`](https://zeppelin.apache.org/)下载 Appache Zeppelin。在硬盘上解压缩软件包，并使用以下命令启动 Zeppelin：

```scala
      Aurobindos-MacBook-Pro-2:zeppelin-0.6.2-bin-all aurobindosarkar$ 
      bin/zeppelin-daemon.sh start

```

1.  您应该看到以下消息：

```scala
      Zeppelin start                                           [ OK  ] 
```

1.  您应该能够在`http://localhost:8080/`看到 Zeppelin 主页：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00060.jpeg)

1.  单击“创建新笔记”链接，并指定笔记本的路径和名称，如下所示：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00061.jpeg)

1.  在下一步中，我们将粘贴本章开头的相同代码，以创建我们样本数据集的 DataFrame：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00062.jpeg)

1.  我们可以执行典型的 DataFrame 操作，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00063.jpeg)

1.  接下来，我们从 DataFrame 创建一个表，并对其执行一些 SQL。单击所需的图表类型，可以对 SQL 语句的执行结果进行图表化。在这里，我们创建条形图，作为总结和可视化数据的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00064.jpeg)

1.  我们可以创建散点图，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00065.jpeg)

您还可以读取每个绘制点的坐标值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00066.jpeg)

1.  此外，我们可以创建一个接受输入值的文本框，使体验更加交互式。在下图中，我们创建了一个文本框，可以接受不同的年龄参数值，并相应地更新条形图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00067.jpeg)

1.  同样，我们还可以创建下拉列表，用户可以选择适当的选项：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00068.jpeg)

表格的值或图表会自动更新：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00069.jpeg)

我们将在第八章中使用 Spark SQL 和 SparkR 进行更高级的可视化。在下一节中，我们将探讨用于从数据中生成样本的方法。

# 使用 Spark SQL API 对数据进行抽样

通常，我们需要可视化个别数据点以了解我们数据的性质。统计学家广泛使用抽样技术进行数据分析。Spark 支持近似和精确的样本生成。近似抽样速度更快，在大多数情况下通常足够好。

在本节中，我们将探索用于生成样本的 Spark SQL API。我们将通过一些示例来演示使用 DataFrame/Dataset API 和基于 RDD 的方法生成近似和精确的分层样本，有放回和无放回。

# 使用 DataFrame/Dataset API 进行抽样

我们可以使用`sampleBy`创建一个无放回的分层样本。我们可以指定每个值被选入样本的百分比。

样本的大小和每种类型的记录数如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00070.jpeg)

接下来，我们创建一个有放回的样本，选择总记录的一部分（总记录的 10%），并使用随机种子。使用`sample`不能保证提供数据集中总记录数的确切分数。我们还打印出样本中每种类型的记录数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00071.jpeg)

在下一节中，我们将探索使用 RDD 的抽样方法。

# 使用 RDD API 进行抽样

在本节中，我们使用 RDD 来创建有放回和无放回的分层样本。

首先，我们从 DataFrame 创建一个 RDD：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00072.jpeg)

我们可以指定样本中每种记录类型的分数，如图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00073.jpeg)

在下面的示例中，我们使用`sampleByKey`和`sampleByKeyExact`方法来创建我们的样本。前者是一个近似样本，而后者是一个精确样本。第一个参数指定样本是有放回还是无放回生成的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00074.jpeg)

接下来，我们打印出人口总记录数和每个样本中的记录数。您会注意到`sampleByKeyExact`会给出与指定分数完全相符的记录数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00075.jpeg)

sample 方法可用于创建包含指定记录分数的随机样本。接下来，我们创建一个有放回的样本，包含总记录的 10%：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00076.jpeg)

其他统计操作，如假设检验、随机数据生成、可视化概率分布等，将在后面的章节中介绍。在下一节中，我们将使用 Spark SQL 来创建数据透视表来探索我们的数据。

# 使用 Spark SQL 创建数据透视表

数据透视表创建数据的替代视图，在数据探索过程中通常被使用。在下面的示例中，我们演示了如何使用 Spark DataFrames 进行数据透视：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00077.jpeg)

下面的示例在已经采取的住房贷款上进行数据透视，并按婚姻状况计算数字：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00078.jpeg)

在下一个示例中，我们创建一个 DataFrame，其中包含适当的列名，用于呼叫总数和平均呼叫次数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00079.jpeg)

在下一个示例中，我们创建一个 DataFrame，其中包含适当的列名，用于每个工作类别的呼叫总数和平均持续时间：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00080.jpeg)

在下面的示例中，我们展示了数据透视，计算每个工作类别的平均呼叫持续时间，同时指定了一些婚姻状况的子集：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00081.jpeg)

下一个示例与前一个相同，只是在这种情况下，我们还按住房贷款字段拆分了平均呼叫持续时间值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00082.jpeg)

接下来，我们将展示如何创建一个按月订阅的定期存款数据透视表的 DataFrame，将其保存到磁盘，并将其读取回 RDD：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00083.jpeg)

此外，我们使用前面步骤中的 RDD 来计算订阅和未订阅定期贷款的季度总数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00084.jpeg)

我们将在本书的后面介绍其他类型数据的详细分析，包括流数据、大规模图形、时间序列数据等。

# 总结

在本章中，我们演示了使用 Spark SQL 来探索数据集，执行基本数据质量检查，生成样本和数据透视表，并使用 Apache Zeppelin 可视化数据。

在下一章中，我们将把重点转移到数据处理/整理。我们将介绍处理缺失数据、错误数据、重复记录等技术。我们还将进行大量的实践演练，演示使用 Spark SQL 处理常见数据整理任务。


# 第四章：使用 Spark SQL 进行数据整理

在这个代码密集的章节中，我们将介绍用于将原始数据转换为可用格式进行分析的关键数据整理技术。我们首先介绍适用于各种场景的一些通用数据整理步骤。然后，我们将把重点转移到特定类型的数据，包括时间序列数据、文本和用于 Spark MLlib 机器学习流水线的数据预处理步骤。我们将使用几个数据集来说明这些技术。

在本章中，我们将学习：

+   什么是数据整理？

+   探索数据整理技术

+   使用连接合并数据

+   文本数据整理

+   时间序列数据整理

+   处理可变长度记录

+   为机器学习流水线准备数据

# 介绍数据整理

原始数据通常混乱不堪，需要经过一系列转换才能变得有用，用于建模和分析工作。这样的数据集可能存在缺失数据、重复记录、损坏数据、不完整记录等问题。在其最简单的形式中，数据整理或数据整理基本上是将原始数据转换为可用格式。在大多数项目中，这是最具挑战性和耗时的步骤。

然而，如果没有数据整理，您的项目可能会陷入垃圾进垃圾出的境地。

通常，您将执行一系列函数和过程，如子集、过滤、聚合、排序、合并、重塑等。此外，您还将进行类型转换、添加新字段/列、重命名字段/列等操作。

一个大型项目可能包含各种数据，数据质量不同。可能会混合使用数字、文本、时间序列、结构化和非结构化数据，包括音频和视频数据，一起或分开用于分析。这类项目的一个重要部分包括清洗和转换步骤，结合一些统计分析和可视化。

我们将使用几个数据集来演示为准备数据进行后续建模和分析所需的关键数据整理技术。以下是这些数据集及其来源：

+   **个人家庭电力消耗数据集**：数据集的原始来源是法国 EDF R&D 的高级研究员 Georges Hebrail 和法国 Clamart 的 TELECOM ParisTech 工程师实习生 Alice Berard。该数据集包括近四年内一个家庭每分钟的电力消耗测量。该数据集可以从以下网址下载：

[`archive.ics.uci.edu/ml/datasets/Individual+household+electric+power+consumption`](https://archive.ics.uci.edu/ml/datasets/Individual+household+electric+power+consumption)。

+   **基于机器学习的 ZZAlpha Ltd. 2012-2014 股票推荐数据集**：该数据集包含了在 2012 年 1 月 1 日至 2014 年 12 月 31 日期间，每天早上针对各种美国交易的股票组合所做的推荐。该数据集可以从以下网址下载：

[`archive.ics.uci.edu/ml/datasets/Machine+Learning+based+ZZAlpha+Ltd.+Stock+Recommendations+2012-2014`](https://archive.ics.uci.edu/ml/datasets/Machine+Learning+based+ZZAlpha+Ltd.+Stock+Recommendations+2012-2014)。

+   **巴黎天气历史数据集**：该数据集包含了巴黎的每日天气报告。我们下载了与家庭电力消耗数据集相同时间段的历史数据。该数据集可以从以下网址下载：

[`www.wunderground.com/history/airport/LFPG`](https://www.wunderground.com/history/airport/LFPG)。

+   **原始 20 个新闻组数据**：该数据集包括来自 20 个 Usenet 新闻组的 20,000 条消息。该数据集的原始所有者和捐赠者是 Carnegie Mellon 大学计算机科学学院的 Tom Mitchell。大约每个新闻组中取了一千篇 Usenet 文章。每个新闻组存储在一个子目录中，每篇文章都存储为一个单独的文件。该数据集可以从以下网址下载：

[`kdd.ics.uci.edu/databases/20newsgroups/20newsgroups.html`](http://kdd.ics.uci.edu/databases/20newsgroups/20newsgroups.html).

+   **Yahoo 财务数据**：该数据集包括了为期一年（从 2015 年 12 月 4 日至 2016 年 12 月 4 日）的六只股票的历史每日股价。所选股票符号的数据可以从以下网站下载：

[ ](http://finance.yahoo.com/)[`finance.yahoo.com/`](http://finance.yahoo.com/).

# 探索数据整理技术

在本节中，我们将介绍使用家庭电力消耗和天气数据集的几种数据整理技术。学习这些技术的最佳方法是练习操纵各种公开可用数据集中包含的数据的各种方法（除了这里使用的数据集）。你练习得越多，你就会变得越擅长。在这个过程中，你可能会发展出自己的风格，并开发出几种工具集和技术来实现你的整理目标。至少，你应该非常熟悉并能够在 RDD、DataFrame 和数据集之间进行操作，计算计数、不同计数和各种聚合，以交叉检查你的结果并匹配你对数据集的直觉理解。此外，根据执行任何给定的整理步骤的利弊来做出决策的能力也很重要。

在本节中，我们将尝试实现以下目标：

1.  预处理家庭电力消耗数据集--读取输入数据集，为行定义 case 类，计算记录数，删除标题和包含缺失数据值的行，并创建 DataFrame。

1.  计算基本统计数据和聚合

1.  使用与分析相关的新信息增强数据集

1.  执行其他必要的杂项处理步骤

1.  预处理天气数据集--类似于步骤 1

1.  分析缺失数据

1.  使用 JOIN 合并数据集并分析结果

此时启动 Spark shell，并随着阅读本节和后续节的内容进行操作。

导入本节中使用的所有必需类：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00085.gif)

# 家庭电力消耗数据集的预处理

为家庭电力消耗创建一个名为`HouseholdEPC`的`case`类：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00086.gif)

将输入数据集读入 RDD 并计算其中的行数。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00087.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00088.gif)

接下来，删除标题和包含缺失值的所有其他行（在输入中表示为`?`），如下面的步骤所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00089.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00090.gif)

在下一步中，将`RDD [String]`转换为我们之前定义的`case`类的`RDD`，并将 RDD 转换为`HouseholdEPC`对象的 DataFrame。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00091.gif)

在 DataFrame 中显示一些样本记录，并计算其中的行数，以验证 DataFrame 中的行数是否与输入数据集中预期的行数匹配。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00092.gif)

# 计算基本统计数据和聚合

接下来，计算并显示 DataFrame 中数值列的一些基本统计数据，以了解我们将要处理的数据。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00093.gif)

我们还可以显示一些或所有列的基本统计数据，四舍五入到四位小数。我们还可以通过在列名前加上`r`来重命名每个列，以使它们与原始列名区分开来。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00094.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00095.gif)

此外，我们使用聚合函数计算包含在 DataFrame 中的数据的不同日期的数量：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00096.gif)

# 增强数据集

我们可以为星期几、每月的日期、月份和年份信息在 DataFrame 中增加新的列。例如，我们可能对工作日和周末的用电量感兴趣。这可以通过可视化或基于这些字段的数据透视来更好地理解数据。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00097.gif)

# 执行其他杂项处理步骤

如果需要，我们可以选择执行更多步骤来帮助进一步清洗数据，研究更多的聚合，或者转换为类型安全的数据结构等。

我们可以删除时间列，并使用聚合函数（如 sum 和 average）对各列的值进行聚合，以获取每天读数的值。在这里，我们使用`d`前缀来重命名列，以表示每日值。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00098.gif)

我们从这个 DataFrame 中显示一些样本记录：

```scala
scala> finalDayDf1.show(5)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00099.jpeg)

在这里，我们按年份和月份对读数进行分组，然后计算每个月的读数数量并显示出来。第一个月的读数数量较低，因为数据是在半个月内捕获的。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00100.gif)

我们还可以使用`case`类将 DataFrame 转换为数据集，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00101.gif)

在这个阶段，我们已经完成了预处理家庭电力消耗数据集的所有步骤。现在我们将把重点转移到处理天气数据集上。

# 天气数据集的预处理

首先，我们为天气读数定义一个`case`类。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00102.gif)

接下来，我们读取了四个文件的每日天气读数（从巴黎天气网站下载），大致与家庭电力消耗读数的持续时间相匹配。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00103.gif)

从以下显示的每个输入文件中删除标题。我们已经显示了标题值的输出，以便您了解这些数据集中捕获的各种天气读数参数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00104.gif)

# 分析缺失数据

如果我们想要了解 RDD 中包含一个或多个缺失字段的行数，我们可以创建一个包含这些行的 RDD：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00105.gif)

如果我们的数据以 DataFrame 的形式可用，我们也可以做同样的操作，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00106.gif)

快速检查数据集发现，大多数具有缺失数据的行也在“事件”和“最大阵风速度公里/小时”列中具有缺失值。根据这两列的值进行过滤实际上捕获了所有具有缺失字段值的行。这也与 RDD 中的缺失值的结果相匹配。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00107.gif)

由于有许多行包含一个或多个缺失字段，我们选择保留这些行，以确保不丢失宝贵的信息。在下面的函数中，我们在 RDD 的所有缺失字段中插入`0`。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00108.gif)

我们可以用字符串字段中的`0`替换前一步骤中插入的`NA`，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00109.gif)

在这个阶段，我们可以使用`union`操作将四个数据集的行合并成一个数据集。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00110.gif)

在这个阶段，我们第二个包含天气数据的数据集的处理已经完成。在接下来的部分，我们将使用`join`操作来合并这些预处理的数据集。

# 使用 JOIN 操作合并数据

在这一部分，我们将介绍 JOIN 操作，其中每日家庭电力消耗与天气数据进行了合并。我们假设家庭电力消耗的读数位置和天气读数的位置足够接近，以至于相关。

接下来，我们使用 JOIN 操作将每日家庭电力消耗数据集与天气数据集进行合并。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00111.gif)

验证最终 DataFrame 中的行数是否与`join`操作后预期的行数相匹配，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00112.gif)

您可以计算新连接的数据集中各列之间的一系列相关性，以了解列之间的关系强度和方向，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00113.gif)

同样，您可以连接按年和月分组的数据集，以获得数据的更高级别的总结。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00114.gif)

为了可视化总结的数据，我们可以在 Apache Zeppelin 笔记本中执行前面的语句。例如，我们可以通过将`joinedMonthlyDF`转换为表，并从中选择适当的列来绘制月度**全球反应功率**（**GRP**）值，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00115.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00116.jpeg)

同样，如果您想按星期几分析读数，则按照以下步骤进行：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00117.gif)

最后，我们打印连接的数据集的模式（增加了星期几列），以便您可以进一步探索此数据框架的各个字段之间的关系：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00118.gif)

在下一节中，我们将把重点转移到整理文本数据上。

# 整理文本数据

在本节中，我们将探讨典型文本分析情况下的数据整理技术。许多基于文本的分析任务需要计算词频、去除停用词、词干提取等。此外，我们还将探讨如何逐个处理 HDFS 目录中的多个文件。

首先，我们导入本节中将使用的所有类：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00119.gif)

# 处理多个输入数据文件

在接下来的几个步骤中，我们初始化一组变量，用于定义包含输入文件的目录和一个空的 RDD。我们还从输入 HDFS 目录创建文件名列表。在下面的示例中，我们将处理包含在单个目录中的文件；但是，这些技术可以很容易地扩展到所有 20 个新闻组子目录。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00120.gif)

接下来，我们编写一个函数，计算每个文件的词频，并将结果收集到一个`ArrayBuffer`中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00121.gif)

我们已经包含了一个打印语句，以显示选定的文件名进行处理，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00122.gif)

我们使用`union`操作将行添加到单个 RDD 中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00123.gif)

我们可以直接执行联合步骤，因为每个文件被处理时，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00124.gif)

然而，使用`RDD.union()`会在血统图中创建一个新步骤，需要为每个新 RDD 添加额外的堆栈帧。这很容易导致堆栈溢出。相反，我们使用`SparkContext.union()`，它会一次性执行`union`操作，而不会产生额外的内存开销。

我们可以缓存并打印输出 RDD 中的样本行，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00125.gif)

在下一节中，我们将向您展示过滤停用词的方法。为简单起见，我们只关注文本中格式良好的单词。但是，您可以使用字符串函数和正则表达式轻松添加条件，以过滤数据中的特殊字符和其他异常情况（有关详细示例，请参阅第九章，*使用 Spark SQL 开发应用程序*）。

# 去除停用词

在我们的示例中，我们创建了一组停用词，并从每个文件中的单词中过滤掉它们。通常，在远程节点上执行的 Spark 操作会在函数中使用的变量的单独副本上工作。我们可以使用广播变量在集群中的每个节点上维护一个只读的缓存副本，而不是将其与要在节点上执行的任务一起传输。Spark 尝试有效地分发广播变量，以减少总体通信开销。此外，我们还过滤掉由于我们的过滤过程和停用词移除而返回的空列表。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00126.gif)

我们可以从 RDD 中的每个元组中提取单词，并创建包含它们的 DataFrame，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00127.gif)

在下面的示例中，我们展示了另一种从单词列表中过滤出停用词的方法。为了改善两个列表之间的单词匹配，我们以与从输入文件中提取的单词类似的方式处理停用词文件。我们读取包含停用词的文件，去除开头和结尾的空格，转换为小写，替换特殊字符，过滤掉空单词，最后创建一个包含停用词的 DataFrame。

我们在示例中使用的停用词列表可在[`algs4.cs.princeton.edu/35applications/stopwords.txt`](http://algs4.cs.princeton.edu/35applications/stopwords.txt)中找到。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00128.gif)

在这里，我们使用`regex`来过滤文件中包含的特殊字符。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00129.gif)

接下来，我们比较在去除原始单词列表中的停用词之前和之后列表中单词的数量。剩下的最终单词数量表明我们输入文件中的大部分单词是停用词。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00130.gif)

有关文本数据处理的更详细覆盖范围（包括年度`10-K`财务申报文件和其他文档语料库的处理、识别文档语料库中的主题、使用朴素贝叶斯分类器和开发机器学习应用程序），请参阅第九章，*使用 Spark SQL 开发应用程序*。

在接下来的部分，我们将把重点转移到使用 Cloudera 的`spark-time-series`库对时间序列数据进行整理。

# 整理时间序列数据

时间序列数据是与时间戳相关联的一系列值。在本节中，我们使用 Cloudera 的`spark-ts`包来分析时间序列数据。

有关时间序列数据及其使用`spark-ts`进行处理的更多详细信息，请参阅*Cloudera Engineering Blog*，*使用 Apache Spark 分析时间序列数据的新库*。该博客位于：[`github.com/sryza/spark-timeseries`](https://github.com/sryza/spark-timeseries)。

`spark-ts`包可以通过以下说明进行下载和构建：

[`github.com/sryza/spark-timeseries`](https://github.com/sryza/spark-timeseries)。

在接下来的子部分中，我们将尝试实现以下目标：

+   预处理时间序列数据集

+   处理日期字段

+   持久化和加载数据

+   定义日期时间索引

+   使用`TimeSeriesRDD`对象

+   处理缺失的时间序列数据

+   计算基本统计数据

对于本节，请在启动 Spark shell 时指定包含`spark-ts.jar`文件。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00131.gif)

我们从 Yahoo Finance 网站下载了包含六只股票一年期价格和成交量数据的数据集。在使用`spark-ts`包进行时间序列数据分析之前，我们需要对数据进行预处理。

导入本节所需的类。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00132.gif)

# 预处理时间序列数据集

从输入数据文件中读取数据，并定义一个包含数据集中字段的`case`类 Stock，以及一个用于保存股票代码的字段。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00133.gif)

接下来，我们从每个文件中移除标题，使用`case`类映射我们的 RDD 行，包括一个用于股票代码的字符串，并将 RDD 转换为 DataFrame。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00134.gif)

接下来，我们使用`union`将每个 DataFrame 的行合并起来。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00135.gif)

# 处理日期字段

接下来，我们将日期列分成包含日期、月份和年份信息的三个单独字段。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00136.gif)

# 持久化和加载数据

在这个阶段，我们可以使用`DataFrameWriter`类将我们的 DataFrame 持久化到 CSV 文件中。覆盖模式允许您覆盖文件，如果它已经存在于`write`操作的先前执行中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00137.gif)

为了加载上一步写入磁盘的时间序列数据集，我们定义一个从文件加载观测值并返回 DataFrame 的函数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00138.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00139.gif)

# 定义日期时间索引

我们为我们拥有数据的期间定义一个日期时间索引，以便每条记录（针对特定的股票代码）包括一个时间序列，表示为一年中每一天的`366`个位置的数组（加上额外的一天，因为我们已经从 2015 年 12 月 4 日下载了数据到 2016 年 12 月 4 日）。工作日频率指定数据仅适用于一年中的工作日。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00140.gif)

# 使用`TimeSeriesRDD`对象

`spark-ts`库中的主要抽象是称为`TimeSeriesRDD`的 RDD。数据是一组以元组（时间戳、键、值）表示的观测值。键是用于标识时间序列的标签。在下面的示例中，我们的元组是（时间戳、股票代码、收盘价）。RDD 中的每个系列都将股票代码作为键，将股票的每日收盘价作为值。

```scala
scala> val tickerTsrdd = TimeSeriesRDD.timeSeriesRDDFromObservations(dtIndex, tickerObs, "timestamp", "ticker", "close") 
```

我们可以缓存并显示 RDD 中的行数，这应该等于我们示例中的股票数量：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00141.gif)

显示 RDD 中的几行以查看每行中的数据：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00142.gif)

# 处理缺失的时间序列数据

接下来，我们检查 RDD 中是否有缺失数据。缺失数据标记为`NaN`值。在存在`NaN`值的情况下计算基本统计数据会导致错误。因此，我们需要用近似值替换这些缺失值。我们的示例数据不包含任何缺失字段。但是，作为练习，我们从输入数据集中删除一些值，以模拟 RDD 中的这些`NaN`值，然后使用线性插值来填补这些值。其他可用的近似值包括下一个、上一个和最近的值。

我们填写缺失值的近似值，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00143.gif)

# 计算基本统计数据

最后，我们计算每个系列的均值、标准差、最大值和最小值，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00144.gif)

使用`TimeSeriesRDD`对象进行探索性数据分析和数据整理还有许多其他有用的函数。这些包括将 RDD 收集为本地时间序列、查找特定时间序列、各种过滤和切片功能、对数据进行排序和重新分区、将时间序列写入 CSV 文件等等。

# 处理可变长度记录

在这一部分，我们将探讨处理可变长度记录的方法。我们的方法基本上将每一行转换为等于最大长度记录的固定长度记录。在我们的例子中，由于每行代表一个投资组合并且没有唯一标识符，这种方法对将数据转换为熟悉的固定长度记录情况非常有用。我们将生成所需数量的字段，使其等于最大投资组合中的股票数量。这将导致在股票数量少于任何投资组合中的最大股票数量时出现空字段。处理可变长度记录的另一种方法是使用`explode()`函数为给定投资组合中的每支股票创建新行（有关使用`explode()`函数的示例，请参阅第九章，*使用 Spark SQL 开发应用程序)。*

为了避免重复之前示例中的所有步骤来读取所有文件，我们在本例中将数据合并为一个单独的输入文件。

首先，我们导入所需的类并将输入文件读入 RDD：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00145.gif)

我们计算投资组合的总数，并打印 RDD 中的一些记录。您可以看到，第一个和第二个投资组合各包含一支股票，而第三个投资组合包含两支股票。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00146.gif)

# 将可变长度记录转换为固定长度记录

在我们的示例数据集中，没有缺失的字段，因此，我们可以使用每行逗号的数量来推导出每个投资组合中不同数量的股票相关字段。或者，这些信息可以从 RDD 的最后一个字段中提取出来。

接下来，我们创建一个 UDF 来间接计算每行中逗号的数量，通过计算数据集中所有行中逗号的最大数量来使用`describe`。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00147.gif)

在下一步中，我们用一个包含逗号数量的列来增加 DataFrame。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00148.gif)

然后我们编写一个函数，在适当的位置插入每行中正确数量的逗号：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00149.gif)

接下来，我们去掉逗号数量列，因为在后续步骤中不需要它：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00150.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00151.gif)

在这个阶段，如果你想要去掉 DataFrame 中的重复行，那么你可以使用`dropDuplicates`方法，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00152.gif)

在下一步中，我们为最大投资组合中的最大股票数定义一个`Portfolio`的`case`类。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00153.gif)

接下来，我们将 RDD 转换为 DataFrame。为了方便起见，我们将演示使用较少的与股票相关的列进行操作；然而，同样的操作可以扩展到投资组合中其他股票的字段：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00154.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00155.gif)

我们可以用`NA`替换较小投资组合中股票的空字段，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00156.gif)

# 从“混乱”的列中提取数据

在这一节中，我们将继续上一节的工作，但是我们将只处理一个股票，以演示修改数据字段所需的数据操作，使得最终得到的数据比起开始时更加干净和丰富。

大多数字段包含多个信息，我们将执行一系列语句，将它们分开成独立的列：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00157.gif)

在下一步中，我们将`datestr`列中的第一个下划线替换为一个空格。这样就分离出了日期字段：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00158.gif)

接下来，我们分离股票列中的信息，因为它包含了几个有用的信息，包括股票代码、卖出价格和购买价格的比率，以及卖出价格和购买价格。首先，我们通过用空字符串替换股票列中的`=`来去掉`=`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00159.gif)

接下来，将每列中由空格分隔的值转换为值的数组：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00160.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00161.gif)

接下来，我们使用`UDF`从每列的数组中挑选出特定元素，放到它们自己的独立列中。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00162.gif)

文件列对我们的分析来说并不特别有用，除了提取文件名开头的信息，表示任何给定投资组合的股票池。我们接下来就这样做：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00163.gif)

以下是准备进行进一步分析的 DataFrame 的最终版本。在这个例子中，我们只处理了一个股票，但是你可以很容易地将相同的技术扩展到给定投资组合中的所有股票，得到最终的、干净且丰富的 DataFrame，可以用于查询、建模和分析。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00164.gif)

在下一节中，我们简要介绍了为了使用 Spark MLlib 机器学习算法解决分类问题而准备数据所需的步骤。

# 为机器学习准备数据

在这一节中，我们介绍了在应用 Spark MLlib 算法之前准备输入数据的过程。通常情况下，我们需要有两列，称为标签和特征，用于使用 Spark MLlib 分类算法。我们将用下面描述的例子来说明这一点：

我们导入了本节所需的类：

```scala
scala> import org.apache.spark.ml.Pipeline
scala> import org.apache.spark.ml.classification.{RandomForestClassificationModel, RandomForestClassifier}
scala> import org.apache.spark.ml.evaluation.MulticlassClassificationEvaluator
scala> import org.apache.spark.ml.feature.{IndexToString, StringIndexer, VectorIndexer} 
scala> import org.apache.spark.ml.linalg.Vectors 
```

# 为机器学习预处理数据

我们在本节中定义了一组在本节中使用的`UDF`。这些包括，例如，检查字符串是否包含特定子字符串，并返回`0.0`或`1.0`值以创建标签列。另一个`UDF`用于从 DataFrame 中的数字字段创建特征向量。

例如，我们可以通过以下方式将星期几字段转换为数字值进行分箱显示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00165.gif)

在我们的示例中，我们根据某一天是否下雨，从家庭电力消耗数据集的`Events`列中创建一个`label`。为了说明的目的，我们使用了之前连接的 DataFrame 中的家庭电力消耗读数的列，尽管来自天气数据集的读数可能更好地预测雨水。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00166.gif)

最后，我们还可以将 DataFrame 拆分，创建包含随机选择的 70%和 30%读数的训练和测试数据集。这些数据集用于训练和测试机器学习算法。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00167.gif)

# 创建和运行机器学习管道

在本节中，我们介绍了一个使用索引器和训练数据来训练随机森林模型的机器学习管道的示例。我们不会对步骤进行详细解释，因为我们在这里的主要目的是演示前一节中的准备步骤实际上是如何使用的。

```scala
scala> val rf = new RandomForestClassifier().setLabelCol("indexedLabel").setFeaturesCol("indexedFeatures").setNumTrees(10)

scala> // Convert indexed labels back to original labels.
scala> val labelConverter = new IndexToString().setInputCol("prediction").setOutputCol("predictedLabel").setLabels(labelIndexer.labels)

scala> // Chain indexers and forest in a Pipeline.
scala> val pipeline = new Pipeline().setStages(Array(labelIndexer, featureIndexer, rf, labelConverter))

scala> // Train model. This also runs the indexers.
scala> val model = pipeline.fit(trainingData)

scala> // Make predictions.
scala> val predictions = model.transform(testData)

scala> // Select example rows to display.
scala> predictions.select("predictedLabel", "label", "features").show(5)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00168.jpeg)

```scala
scala> // Select (prediction, true label) and compute test error.
scala> val evaluator = new MulticlassClassificationEvaluator().setLabelCol("indexedLabel").setPredictionCol("prediction").setMetricName("accuracy")

scala> val accuracy = evaluator.evaluate(predictions)
accuracy: Double = 0.5341463414634147                                          

scala> println("Test Error = " + (1.0 - accuracy))
Test Error = 0.46585365853658534

scala> val rfModel = model.stages(2).asInstanceOf[RandomForestClassificationModel]

scala> println("Learned classification forest model:\n" + rfModel.toDebugString)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00169.jpeg)

有关特定数据结构和操作的更多详细信息，包括向量、处理分类变量等等，用于 Spark MLlib 处理的内容，将在第六章中进行介绍，**在机器学习应用中使用 Spark SQL**，以及第九章中进行介绍，*使用 Spark SQL 开发应用程序*。此外，有关为图应用程序准备数据的技术将在第七章中进行介绍，**在图应用程序中使用 Spark SQL**。

# 摘要

在本章中，我们探讨了使用 Spark SQL 执行一些基本的数据整理/处理任务。我们涵盖了整理文本数据，处理可变长度记录，从“混乱”的列中提取数据，使用 JOIN 组合数据，并为机器学习应用程序准备数据。此外，我们使用了`spark-ts`库来处理时间序列数据。

在下一章中，我们将把重点转向 Spark Streaming 应用程序。我们将介绍如何在这些应用程序中使用 Spark SQL。我们还将包括大量的实践课程，演示在 Spark Streaming 应用程序中实现常见用例时如何使用 Spark SQL。


# 第五章：在流应用中使用 Spark SQL

在本章中，我们将介绍在流应用中使用 Spark SQL 的典型用例。我们的重点将放在使用 Spark 2.0 中引入的 Dataset/DataFrame API 进行结构化流处理上。此外，我们还将介绍并使用 Apache Kafka，因为它是许多大规模网络流应用架构的重要组成部分。流应用通常涉及对传入数据或消息进行实时、上下文感知的响应。我们将使用几个示例来说明构建此类应用的关键概念和技术。

在本章中，我们将学习以下主题：

+   什么是流数据应用？

+   典型的流应用用例

+   使用 Spark SQL DataFrame/Dataset API 构建流应用

+   在结构化流应用中使用 Kafka

+   为自定义数据源创建接收器

# 介绍流数据应用

传统的批处理应用通常运行数小时，处理存储在关系数据库中的所有或大部分数据。最近，基于 Hadoop 的系统已被用于支持基于 MapReduce 的批处理作业，以处理非常大量的分布式数据。相比之下，流处理发生在持续生成的流数据上。这种处理在各种分析应用中被使用，用于计算事件之间的相关性、聚合值、对传入数据进行抽样等。

流处理通常会逐步计算统计数据和其他功能，以记录/事件为基础，或者在滑动时间窗口上进行实时计算。

越来越多的流数据应用正在应用机器学习算法和复杂事件处理（CEP）算法，以提供战略洞察和快速、智能地对快速变化的业务条件做出反应。这类应用可以扩展以处理非常大量的流数据，并能够实时做出适当的响应。此外，许多组织正在实施包含实时层和批处理层的架构。在这种实现中，尽可能地保持这两个层的单一代码库非常重要（有关此类架构的示例，请参阅第十二章，*大规模应用架构中的 Spark SQL*）。Spark 结构化流 API 可以帮助我们以可扩展、可靠和容错的方式实现这些目标。

流应用的一些真实用例包括处理物联网应用中的传感器数据、股票市场应用（如风险管理和算法交易）、网络监控、监视应用、电子商务应用中的即时客户参与、欺诈检测等。

因此，许多平台已经出现，提供了构建流数据应用所需的基础设施，包括 Apache Kafka、Apache Spark Streaming、Apache Storm、Amazon Kinesis Streams 等。

在本章中，我们将探讨使用 Apache Spark 和 Apache Kafka 进行流处理。在接下来的几节中，我们将使用 Spark SQL DataFrame/Dataset API 详细探讨 Spark 结构化流。

# 构建 Spark 流应用

在本节中，我们将主要关注新引入的结构化流特性（在 Spark 2.0 中）。结构化流 API 在 Spark 2.2 中已经是 GA，并且使用它们是构建流式 Spark 应用的首选方法。Spark 2.2 还发布了对基于 Kafka 的处理组件的多个更新，包括性能改进。我们在第一章，*开始使用 Spark SQL*中介绍了结构化流，本章中我们将深入探讨这个主题，并提供几个代码示例来展示其能力。

简而言之，结构化流提供了一种快速、可扩展、容错、端到端的精确一次流处理，而开发人员无需考虑底层的流处理机制。

它建立在 Spark SQL 引擎上，流计算可以以与静态数据上的批处理计算相同的方式来表达。它提供了几种数据抽象，包括流查询、流源和流接收器，以简化流应用程序，而不涉及数据流的底层复杂性。编程 API 在 Scala、Java 和 Python 中都可用，您可以使用熟悉的 Dataset / DataFrame API 来实现您的应用程序。

在第一章中，*开始使用 Spark SQL*，我们使用 IPinYou 数据集创建了一个流 DataFrame，然后在其上定义了一个流查询。我们展示了结果在每个时间间隔内得到更新。在这里，我们重新创建我们的流 DataFrame，然后在其上执行各种函数，以展示在流输入数据上可能的计算类型。

首先，我们启动 Spark shell，并导入本章实际操作所需的必要类。在我们的大多数示例中，我们将使用文件源来模拟传入的数据：

```scala
scala> import org.apache.spark.sql.types._
scala> import org.apache.spark.sql.functions._
scala> import scala.concurrent.duration._
scala> import org.apache.spark.sql.streaming.ProcessingTime
scala> import org.apache.spark.sql.streaming.OutputMode.Complete
scala> import spark.implicits._
```

接下来，我们将为源文件中的出价记录定义模式，如下所示：

```scala
scala> val bidSchema = new StructType().add("bidid", StringType).add("timestamp", StringType).add("ipinyouid", StringType).add("useragent", StringType).add("IP", StringType).add("region", IntegerType).add("cityID", IntegerType).add("adexchange", StringType).add("domain", StringType).add("turl", StringType).add("urlid", StringType).add("slotid", StringType).add("slotwidth", StringType).add("slotheight", StringType).add("slotvisibility", StringType).add("slotformat", StringType).add("slotprice", StringType).add("creative", StringType).add("bidprice", StringType)
```

接下来，我们将基于输入的 CSV 文件定义一个流数据源。我们指定在上一步中定义的模式和其他必需的参数（使用选项）。我们还将每批处理的文件数量限制为一个：

```scala
scala> val streamingInputDF = spark.readStream.format("csv").schema(bidSchema).option("header", false).option("inferSchema", true).option("sep", "\t").option("maxFilesPerTrigger", 1).load("file:///Users/aurobindosarkar/Downloads/make-ipinyou-data-master/original-data/ipinyou.contest.dataset/bidfiles")
```

您可以像在静态数据的情况下一样打印流 DataFrame 的模式：

```scala
scala> streamingInputDF.printSchema()
root
|-- bidid: string (nullable = true)
|-- timestamp: string (nullable = true)
|-- ipinyouid: string (nullable = true)
|-- useragent: string (nullable = true)
|-- IP: string (nullable = true)
|-- region: integer (nullable = true)
|-- cityID: integer (nullable = true)
|-- adexchange: string (nullable = true)
|-- domain: string (nullable = true)
|-- turl: string (nullable = true)
|-- urlid: string (nullable = true)
|-- slotid: string (nullable = true)
|-- slotwidth: string (nullable = true)
|-- slotheight: string (nullable = true)
|-- slotvisibility: string (nullable = true)
|-- slotformat: string (nullable = true)
|-- slotprice: string (nullable = true)
|-- creative: string (nullable = true)
|-- bidprice: string (nullable = true)
```

# 实现基于滑动窗口的功能

在本小节中，我们将介绍对流数据进行滑动窗口操作。

由于时间戳数据格式不正确，我们将定义一个新列，并将输入时间戳字符串转换为适合我们处理的正确格式和类型：

```scala
scala> val ts = unix_timestamp($"timestamp", "yyyyMMddHHmmssSSS").cast("timestamp")

scala> val streamingCityTimeDF = streamingInputDF.withColumn("ts", ts).select($"cityID", $"ts")
```

接下来，我们将定义一个流查询，将输出写入标准输出。我们将在滑动窗口上定义聚合，其中我们按窗口和城市 ID 对数据进行分组，并计算每个组的计数。

有关结构化流编程的更详细描述，请参阅[`spark.apache.org/docs/latest/structured-streaming-programming-guide.html.`](http://spark.apache.org/docs/latest/structured-streaming-programming-guide.html)

在这里，我们计算在 10 分钟的窗口内的出价数量，每五分钟更新一次，也就是说，在每五分钟滑动一次的 10 分钟窗口内收到的出价。使用窗口的流查询如下所示：

```scala
scala> val windowedCounts = streamingCityTimeDF.groupBy(window($"ts", "10 minutes", "5 minutes"), $"cityID").count().writeStream.outputMode("complete").format("console").start()
```

输出写入标准输出，因为我们在格式参数中使用了`console`关键字指定了`Console Sink`。输出包含窗口、城市 ID 和计算的计数列，如下所示。我们看到了两批数据，因为我们在输入目录中放置了两个文件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00170.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00171.jpeg)

# 将流数据集与静态数据集进行连接

在本小节中，我们将举例说明如何将流数据集与静态数据集进行连接。我们将基于`cityID`来连接数据集，以实现包含城市名称而不是`cityID`的用户友好输出。首先，我们为我们的城市记录定义一个模式，并从包含城市 ID 及其对应城市名称的 CSV 文件创建静态 DataFrame：

```scala
scala> val citySchema = new StructType().add("cityID", StringType).add("cityName", StringType)

scala> val staticDF = spark.read.format("csv").schema(citySchema).option("header", false).option("inferSchema", true).option("sep", "\t").load("file:///Users/aurobindosarkar/Downloads/make-ipinyou-data-master/original-data/ipinyou.contest.dataset/city.en.txt")
```

接下来，我们将连接流和静态 DataFrame，如下所示：

```scala
scala> val joinedDF = streamingCityTimeDF.join(staticDF, "cityID")
```

我们将执行我们之前的流查询，指定城市名称的列，而不是连接的 DataFrame 中的城市 ID：

```scala
scala> val windowedCityCounts = joinedDF.groupBy(window($"ts", "10 minutes", "5 minutes"), $"cityName").count().writeStream.outputMode("complete").format("console").start()
```

结果如下。在这里，我们看到了一批输出数据，因为我们已经从源目录中删除了一个输入文件。在本章的其余部分，我们将限制处理为单个输入文件，以节省空间：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00172.jpeg)

接下来，我们创建一个带有时间戳列和从先前创建的 DataFrame 中选择的几列的新 DataFrame：

```scala
scala> val streamingCityNameBidsTimeDF = streamingInputDF.withColumn("ts", ts).select($"ts", $"bidid", $"cityID", $"bidprice", $"slotprice").join(staticDF, "cityID") 
```

由于我们不计算聚合，并且只是希望将流式出价附加到结果中，因此我们使用`outputMode`"append"而不是"complete"，如下所示：

```scala
scala> val cityBids = streamingCityNameBidsTimeDF.select($"ts", $"bidid", $"bidprice", $"slotprice", $"cityName").writeStream.outputMode("append").format("console").start()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00173.jpeg)

# 使用结构化流中的数据集 API

到目前为止，我们已经使用了与 DataFrame 不同的未类型化 API。为了使用类型化 API，我们可以从使用 DataFrame 切换到使用数据集。大多数流式操作都受到 DataFrame/Dataset API 的支持；但是，一些操作，如多个流式聚合和不支持的不同操作，尚不受支持。而其他操作，如外连接和排序，是有条件支持的。

有关不受支持和有条件支持的操作的完整列表，请参阅[`spark.apache.org/docs/latest/structured-streaming-programming-guide.html`](http://spark.apache.org/docs/latest/structured-streaming-programming-guide.html)。

在这里，我们提供了一些使用类型化 API 的示例。

首先，我们将定义一个名为`Bid`的`case`类：

```scala
scala> case class Bid(bidid: String, timestamp: String, ipinyouid: String, useragent: String, IP: String, region: Integer, cityID: Integer, adexchange: String, domain: String, turl: String, urlid: String, slotid: String, slotwidth: String, slotheight: String, slotvisibility: String, slotformat: String, slotprice: String, creative: String, bidprice: String)
```

我们可以使用在前一步中定义的`case`类，从流式 DataFrame 中定义一个流式数据集：

```scala
scala> val ds = streamingInputDF.as[Bid]
```

# 使用输出 sink

您可以将流式输出数据定向到各种输出 sink，包括文件、Foreach、控制台和内存 sink。通常，控制台和内存 sink 用于调试目的。由于我们已经在之前的部分中使用了控制台 sink，因此我们将更详细地讨论其他 sink 的用法。

# 使用 Foreach Sink 进行输出上的任意计算

如果您想对输出执行任意计算，那么可以使用`Foreach` Sink。为此，您需要实现`ForeachWriter`接口，如所示。在我们的示例中，我们只是打印记录，但您也可以根据您的要求执行其他计算：

```scala
import org.apache.spark.sql.ForeachWriter

val writer = new ForeachWriter[String] {
   override def open(partitionId: Long, version: Long) = true
   override def process(value: String) = println(value)
   override def close(errorOrNull: Throwable) = {}
}
```

在下一步中，我们将实现一个示例，使用在上一步中定义的`Foreach` sink。如下所示，指定在前一步中实现的`ForeachWriter`：

```scala
scala> val dsForeach = ds.filter(_.adexchange == "3").map(_.useragent).writeStream.foreach(writer).start()
```

结果将显示用户代理信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00174.gif)

# 使用内存 Sink 将输出保存到表

如果您想将输出数据保存为表，可以使用内存 Sink；这对于交互式查询很有用。我们像以前一样定义一个流式 DataFrame。但是，我们将格式参数指定为`memory`，并指定表名。最后，我们对我们的表执行 SQL 查询，如下所示：

```scala
scala> val aggAdexchangeDF = streamingInputDF.groupBy($"adexchange").count()

scala> val aggQuery = aggAdexchangeDF.writeStream.queryName("aggregateTable").outputMode("complete").format("memory").start()

scala> spark.sql("select * from aggregateTable").show()   
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00175.jpeg)

# 使用文件 sink 将输出保存到分区表

我们还可以将输出保存为分区表。例如，我们可以按时间对输出进行分区，并将其存储为 HDFS 上的 Parquet 文件。在这里，我们展示了使用文件 sink 将输出存储为 Parquet 文件的示例。在给定的命令中，必须指定检查点目录位置：

```scala
scala> val cityBidsParquet = streamingCityNameBidsTimeDF.select($"bidid", $"bidprice", $"slotprice", $"cityName").writeStream.outputMode("append").format("parquet").option("path", "hdfs://localhost:9000/pout").option("checkpointLocation", "hdfs://localhost:9000/poutcp").start()
```

您可以检查 HDFS 文件系统，查看输出 Parquet 文件和检查点文件，如下所示：

```scala
Aurobindos-MacBook-Pro-2:~ aurobindosarkar$ hdfs dfs -ls /pout
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00176.jpeg)

```scala
Aurobindos-MacBook-Pro-2:~ aurobindosarkar$ hdfs dfs -ls /poutcp
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00177.jpeg)

在下一节中，我们将探索一些有用的功能，用于管理和监视流式查询。

# 监视流式查询

在这个阶段，如果您列出系统中的活动流查询，您应该会看到以下输出：

```scala
scala> spark.streams.active.foreach(x => println("ID:"+ x.id + "             Run ID:"+ x.runId + "               Status: "+ x.status))

ID:0ebe31f5-6b76-46ea-a328-cd0c637be49c             
Run ID:6f203d14-2a3a-4c9f-9ea0-8a6783d97873               
Status: {
  "message" : "Waiting for data to arrive",
  "isDataAvailable" : false,
  "isTriggerActive" : false
}
ID:519cac9a-9d2f-4a01-9d67-afc15a6b03d2             
Run ID:558590a7-cbd3-42b8-886b-cdc32bb4f6d7               
Status: {
  "message" : "Waiting for data to arrive",
  "isDataAvailable" : false,
  "isTriggerActive" : false
}
ID:1068bc38-8ba9-4d5e-8762-bbd2abffdd51             
Run ID:bf875a27-c4d8-4631-9ea2-d51a0e7cb232               
Status: {
  "message" : "Waiting for data to arrive",
  "isDataAvailable" : false,
  "isTriggerActive" : false
}
ID:d69c4005-21f1-487a-9fe5-d804ca86f0ff             
Run ID:a6969c1b-51da-4986-b5f3-a10cd2397784               
Status: {
  "message" : "Waiting for data to arrive",
  "isDataAvailable" : false,
  "isTriggerActive" : false
}
ID:1fa9e48d-091a-4888-9e69-126a2f1c081a             
Run ID:34dc2c60-eebc-4ed6-bf25-decd6b0ad6c3               
Status: {
  "message" : "Waiting for data to arrive",
  "isDataAvailable" : false,  "isTriggerActive" : false
}
ID:a7ff2807-dc23-4a14-9a9c-9f8f1fa6a6b0             
Run ID:6c8f1a83-bb1c-4dd7-8974
83042a286bae               
Status: {
  "message" : "Waiting for data to arrive",
  "isDataAvailable" : false,
  "isTriggerActive" : false
}
```

我们还可以监视和管理特定的流式查询，例如`windowedCounts`查询（一个`StreamingQuery`对象），如下所示：

```scala
scala> // get the unique identifier of the running query that persists across restarts from checkpoint data
scala> windowedCounts.id          
res6: java.util.UUID = 0ebe31f5-6b76-46ea-a328-cd0c637be49c

scala> // get the unique id of this run of the query, which will be generated at every start/restart
scala> windowedCounts.runId       
res7: java.util.UUID = 6f203d14-2a3a-4c9f-9ea0-8a6783d97873

scala> // the exception if the query has been terminated with error
scala> windowedCounts.exception       
res8: Option[org.apache.spark.sql.streaming.StreamingQueryException] = None

scala> // the most recent progress update of this streaming query
scala> windowedCounts.lastProgress 
res9: org.apache.spark.sql.streaming.StreamingQueryProgress =
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00178.jpeg)

要停止流式查询执行，您可以执行`stop()`命令，如下所示：

```scala
scala> windowedCounts.stop()
```

在下一节中，我们将把重点转移到使用 Kafka 作为结构化流应用程序中传入数据流的来源。

# 使用 Kafka 与 Spark 结构化流

Apache Kafka 是一个分布式流平台。它使您能够发布和订阅数据流，并在其产生时处理和存储它们。Kafka 被业界广泛采用于面向 Web 规模应用程序，因为它具有高吞吐量、低延迟、高可伸缩性、高并发性、可靠性和容错特性。

# 介绍 Kafka 概念

Kafka 通常用于构建实时流数据管道，可在系统之间可靠地移动数据，还可对数据流进行转换和响应。Kafka 作为一个或多个服务器上的集群运行。

这里描述了 Kafka 的一些关键概念：

+   **主题**：用于发布消息的类别或流名称的高级抽象。一个主题可以有`0`、`1`或多个订阅其发布的消息的消费者。用户为每个新类别的消息定义一个新主题。

+   **生产者**：向主题发布消息的客户端。

+   **消费者**：从主题中消费消息的客户端。

+   **Broker**：一个或多个服务器，用于复制和持久化消息数据。

此外，生产者和消费者可以同时写入和读取多个主题。每个 Kafka 主题都被分区，写入每个分区的消息是顺序的。分区中的消息具有唯一标识每条消息的偏移量。

Apache Kafka 安装、教程和示例的参考网站是[`kafka.apache.org/`](https://kafka.apache.org/)。

主题的分区是分布的，每个 Broker 处理一部分分区的请求。每个分区在可配置数量的 Broker 上复制。Kafka 集群保留所有发布的消息一段可配置的时间。Apache Kafka 使用 Apache ZooKeeper 作为其分布式进程的协调服务。

# 介绍 ZooKeeper 概念

ZooKeeper 是一个分布式的开源协调服务，用于分布式应用程序。它使开发人员不必从头开始实现协调服务。它使用共享的分层命名空间，允许分布式进程相互协调，并避免与竞争条件和死锁相关的错误。

Apache ZooKeeper 安装和教程的参考网站是[`zookeeper.apache.org/`](https://zookeeper.apache.org/)。

ZooKeeper 数据保存在内存中，因此具有非常高的吞吐量和低延迟。它在一组主机上复制，以提供高可用性。ZooKeeper 提供一组保证，包括顺序一致性和原子性。

# 介绍 Kafka-Spark 集成

我们在这里提供一个简单的示例，以使您熟悉 Kafka-Spark 集成。本节的环境使用：Apache Spark 2.1.0 和 Apache Kafka 0.10.1.0（下载文件：`kafka_2.11-0.10.1.0.tgz)`。

首先，我们使用 Apache Kafka 分发提供的脚本启动单节点 ZooKeeper，如下所示：

```scala
bin/zookeeper-server-start.sh config/zookeeper.properties
```

Zookeeper 节点启动后，我们使用 Apache Kafka 分发中提供的脚本启动 Kafka 服务器，如下所示：

```scala
bin/kafka-server-start.sh config/server.properties
```

接下来，我们创建一个名为`test`的主题，我们将向其发送消息以供 Spark 流处理。对于我们的简单示例，我们将复制因子和分区数都指定为`1`。我们可以使用为此目的提供的实用脚本，如下所示：

```scala
bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic test
```

我们可以使用此脚本查看主题列表（包括“test”）：

```scala
bin/kafka-topics.sh --list --zookeeper localhost:2181
```

接下来，我们启动一个基于命令行的生产者来向 Kafka 发送消息，如下所示。在这里，每行都作为单独的消息发送。当您输入并按下回车时，您应该在 Spark 流查询中看到每行出现（在不同的窗口中运行）。

```scala
bin/kafka-console-producer.sh --broker-list localhost:9092 --topic test
This is the first message.
This is another message.
```

在一个单独的窗口中，启动 Spark shell，并在命令行中指定适当的 Kafka 包，如下所示：

```scala
Aurobindos-MacBook-Pro-2:spark-2.1.0-bin-hadoop2.7 aurobindosarkar$ ./bin/spark-shell --packages org.apache.spark:spark-streaming-kafka-0-10_2.11:2.1.0,org.apache.spark:spark-sql-kafka-0-10_2.11:2.1.0
```

Spark shell 启动后，我们将创建一个格式指定为"kafka"的流式数据集。此外，我们还将指定 Kafka 服务器和其运行的端口，并明确订阅我们之前创建的主题，如下所示。键和值字段被转换为字符串类型，以使输出易于阅读。

```scala
scala> val ds1 = spark.readStream.format("kafka").option("kafka.bootstrap.servers", "localhost:9092").option("subscribe", "test").load().selectExpr("CAST(key AS STRING)", "CAST(value AS STRING)").as[(String, String)]
```

接下来，我们将启动一个流式查询，将流式数据集输出到标准输出，如下所示：

```scala
scala> val query = ds1.writeStream.outputMode("append").format("console").start()
```

当您在 Kafka 生产者窗口中输入句子时，您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00179.jpeg)

# 介绍 Kafka-Spark 结构化流

然后，我们将提供另一个 Kafka-Spark 结构化流的示例，其中我们将 iPinYou 竞价文件的内容定向到生产者，如下所示：

```scala
Aurobindos-MacBook-Pro-2:kafka_2.11-0.10.1.0 aurobindosarkar$ bin/kafka-console-producer.sh --broker-list localhost:9092 --topic connect-test < /Users/aurobindosarkar/Downloads/make-ipinyou-data-master/original-data/ipinyou.contest.dataset/bidfiles/bid.20130311.txt
```

我们还将创建一个名为`connect-test`的新主题，一个包含文件记录的新流式数据集，以及一个在屏幕上列出它们的新流式查询，如下所示：

```scala
scala> val ds2 = spark.readStream.format("kafka").option("kafka.bootstrap.servers", "localhost:9092").option("subscribe", "connect-test").load().selectExpr("CAST(key AS STRING)", "CAST(value AS STRING)").as[(String, String)]

scala> val query = ds2.writeStream.outputMode("append").format("console").start()
```

截断的输出如下所示。记录分布在多个批次中，因为它们在流中传输：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00180.gif)

在下一节中，我们将创建一个用于访问任意流式数据源的接收器。

# 为自定义数据源编写接收器

到目前为止，我们已经使用了在 Spark 中内置支持的数据源。但是，Spark 流式处理可以从任意源接收数据，但我们需要实现一个接收器来从自定义数据源接收数据。

在本节中，我们将为来自**伦敦交通**（TfL）网站提供的公共 API 定义一个自定义数据源。该网站为伦敦的每种交通方式提供了统一的 API。这些 API 提供对实时数据的访问，例如，铁路到达情况。输出以 XML 和 JSON 格式提供。我们将使用 API 来获取伦敦地铁特定线路的当前到达预测。

TfL 的参考网站是[`tfl.gov.uk`](https://tfl.gov.uk); 在该网站上注册以生成用于访问 API 的应用程序密钥。

我们将首先扩展抽象类`Receiver`并实现`onStart()`和`onStop()`方法。在`onStart()`方法中，我们启动负责接收数据的线程，在`onStop()`中，我们停止这些线程。`receive`方法使用 HTTP 客户端接收数据流，如下所示：

```scala
import org.apache.spark.storage.StorageLevel
import org.apache.spark.streaming.receiver.Receiver
import org.jfarcand.wcs.{TextListener, WebSocket}
import scala.util.parsing.json.JSON
import scalaj.http.Http
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
/**
* Spark Streaming Example TfL Receiver
*/
class TFLArrivalPredictionsByLine() extends ReceiverString with Runnable {
//Replace the app_key parameter with your own key
private val tflUrl = "https://api.tfl.gov.uk/Line/circle/Arrivals?stopPointId=940GZZLUERC&app_id=a73727f3&app_key=xxx"
@transient
private var thread: Thread = _
override def onStart(): Unit = {
   thread = new Thread(this)
   thread.start()
}
override def onStop(): Unit = {
   thread.interrupt()
}
override def run(): Unit = {
   while (true){
     receive();
     Thread.sleep(60*1000);
   }
}
private def receive(): Unit = {
   val httpClient = new DefaultHttpClient();
   val getRequest = new HttpGet(tflUrl);
   getRequest.addHeader("accept", "application/json");
   val response = httpClient.execute(getRequest);
   if (response.getStatusLine().getStatusCode() != 200) {
      throw new RuntimeException("Failed : HTTP error code : "
         + response.getStatusLine().getStatusCode());
   }
   val br = new BufferedReader(
      new InputStreamReader((response.getEntity().getContent())));
   var output=br.readLine();
   while(output!=null){        
      println(output)
      output=br.readLine()
   } 
}
}
```

以下对象创建了`StreamingContext`并启动了应用程序。`awaitTermination()`方法确保应用程序持续运行。

您可以使用*Ctrl *+ *C *来终止应用程序：

```scala
import org.apache.spark.SparkConf
import org.apache.spark.streaming.{Seconds, StreamingContext}
/**
* Spark Streaming Example App
*/
object TFLStreamingApp {
def main(args: Array[String]) {
   val conf = new SparkConf().setAppName("TFLStreaming")
   val ssc = new StreamingContext(conf, Seconds(300))
   val stream = ssc.receiverStream(new TFLArrivalPredictionsByLine())
   stream.print()
   if (args.length > 2) {
      stream.saveAsTextFiles(args(2))
   }
   ssc.start()
   ssc.awaitTermination()
   }
}
```

用于编译和打包应用程序的`sbt`文件如下所示：

```scala
name := "spark-streaming-example"
version := "1.0"
scalaVersion := "2.11.7"
resolvers += "jitpack" at "https://jitpack.io"
libraryDependencies ++= Seq("org.apache.spark" %% "spark-core" % "2.0.0",       "org.apache.spark" %% "spark-streaming" % "2.0.0",
"org.apache.httpcomponents" % "httpclient" % "4.5.2",
"org.scalaj" %% "scalaj-http" % "2.2.1",
"org.jfarcand" % "wcs" % "1.5")
```

我们使用`spark-submit`命令来执行我们的应用程序，如下所示：

```scala
Aurobindos-MacBook-Pro-2:scala-2.11 aurobindosarkar$ /Users/aurobindosarkar/Downloads/spark-2.2.0-bin-hadoop2.7/bin/spark-submit --class TFLStreamingApp --master local[*] spark-streaming-example_2.11-1.0.jar
```

流式程序的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00181.jpeg)

# 总结

在本章中，我们介绍了流式数据应用程序。我们提供了使用 Spark SQL DataFrame/Dataset API 构建流式应用程序的几个示例。此外，我们展示了 Kafka 在结构化流应用程序中的使用。最后，我们提供了一个为自定义数据源创建接收器的示例。

在下一章中，我们将把重点转移到在机器学习应用中使用 Spark SQL。具体来说，我们将探索特征工程和机器学习流水线的关键概念。
