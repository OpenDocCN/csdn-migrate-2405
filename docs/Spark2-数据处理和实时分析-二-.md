# Spark2 数据处理和实时分析（二）

> 原文：[`zh.annas-archive.org/md5/16D84784AD68D8BF20A18AC23C62DD82`](https://zh.annas-archive.org/md5/16D84784AD68D8BF20A18AC23C62DD82)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Apache Spark GraphX

在本章中，我们希望探讨 Apache Spark GraphX 模块和图处理的一般性。因此，本章将涵盖在 GraphX 之上实现图分析工作流程的主题。*GraphX 编码*部分，用 Scala 编写，将提供一系列图编码示例。在用 Scala 编写代码以使用 Spark GraphX 模块之前，我们认为提供关于图处理中图实际是什么的概述将是有用的。以下部分使用几个简单图作为示例，提供了一个简短的介绍。

在本章中，我们将涵盖：

+   从原始数据创建图

+   计数

+   过滤

+   PageRank

+   三角形计数

+   连通组件

# 概述

图可以被视为一种数据结构，由一组顶点和连接它们的边组成。图中的顶点或节点可以是任何对象（例如人），而边则是它们之间的关系。边可以是无向的或有向的，意味着关系从一个节点操作到另一个节点。例如，节点**A**是节点**B**的父母。

在下面的图中，圆圈代表顶点或节点（**A**至**D**），而粗线代表它们之间的边或关系（**E1**至**E6**）。每个节点或边可能具有属性，这些值由相关的灰色方块表示（**P1**至**P7**）：

因此，如果一个图代表了一个物理...

# 使用 GraphX 进行图分析/处理

本节将探讨使用上一节中展示的家庭关系图数据样本，在 Scala 中进行 Apache Spark GraphX 编程。此数据将被访问为一组顶点和边。尽管此数据集较小，但通过这种方式构建的图可能非常庞大。例如，我们仅使用四个 Apache Spark 工作者就能够分析一家大型银行的 30 TB 金融交易数据。

# 原始数据

我们正在处理两个数据文件。它们包含将用于本节的顶点和边数据，这些数据构成了一个图：

```scala
graph1_edges.csvgraph1_vertex.csv
```

`顶点`文件仅包含六行，代表上一节中使用的图。每个`顶点`代表一个人，并具有顶点 ID 号、姓名和年龄值：

```scala
1,Mike,482,Sarah,453,John,254,Jim,535,Kate,226,Flo,52
```

`边`文件包含一组有向`边`值，形式为源顶点 ID、目标顶点 ID 和关系。因此，记录 1 在`Flo`和`Mike`之间形成了一个`姐妹`关系：

```scala
6,1,Sister1,2,Husband2,1,Wife5,1,Daughter5,2,Daughter3,1,Son3,2,Son4,1,Friend1,5,Father1,3,Father2,5,Mother2,3,Mother
```

让我们，检查一些...

# 创建图

本节将解释通用 Scala 代码，直到从数据创建 GraphX 图。这将节省时间，因为相同的代码在每个示例中都被重复使用。一旦解释完毕，我们将专注于每个代码示例中的实际基于图的操作。

1.  通用代码首先导入 Spark 上下文、GraphX 和 RDD 功能，以便在 Scala 代码中使用：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf
import org.apache.spark.graphx._
import org.apache.spark.rdd.RDD
```

1.  然后定义一个应用程序，它`扩展`了`App`类。应用程序名称从`graph1`到`graph5`每个示例都会更改。运行应用程序时将使用此应用程序名称`spark-submit`：

```scala
object graph1 extends App {
```

1.  如前所述，有两个数据文件包含`顶点`和`边`信息：

```scala
val vertexFile = "graph1_vertex.csv"
val edgeFile   = "graph1_edges.csv"
```

1.  **Spark 主 URL**定义为应用程序名称，该名称将在应用程序运行时出现在 Spark 用户界面中。创建一个新的 Spark 配置对象，并将 URL 和名称分配给它：

```scala
val sparkMaster = "spark://localhost:7077"
val appName = "Graph 1"
val conf = new SparkConf()
conf.setMaster(sparkMaster)
conf.setAppName(appName)
```

1.  使用刚刚定义的配置创建一个新的 Spark 上下文：

```scala
val sparkCxt = new SparkContext(conf)
```

1.  然后，使用`sparkCxt.textFile`方法将文件中的`顶点`信息加载到称为顶点的 RDD 基础结构中。数据存储为长`VertexId`和字符串，以表示人的姓名和年龄。数据行按逗号分割，因为这是基于 CSV 的数据：

```scala
val vertices: RDD[(VertexId, (String, String))] =
     sparkCxt.textFile(vertexFile).map { line =>
       val fields = line.split(",")
       ( fields(0).toLong, ( fields(1), fields(2) ) )
}
```

1.  同样，`边`数据加载到称为边的 RDD 基础数据结构中。基于 CSV 的数据再次按逗号值分割。前两个数据值转换为长值，因为它们表示源和目标顶点 ID。最后代表边关系的值保持为`字符串`。请注意，RDD 结构边中的每个记录实际上现在是一个`Edge`记录：

```scala
val edges: RDD[Edge[String]] =
     sparkCxt.textFile(edgeFile).map { line =>
       val fields = line.split(",")
       Edge(fields(0).toLong, fields(1).toLong, fields(2))
}
```

1.  如果缺少连接或`顶点`，则定义默认值；然后从基于 RDD 的结构顶点和边以及`默认`记录构建图：

```scala
val default = ("Unknown", "Missing")
val graph = Graph(vertices, edges, default)
```

1.  这创建了一个基于 GraphX 的结构，称为`图`，现在可以用于每个示例。请记住，尽管这些数据样本可能很小，但您可以使用这种方法创建非常大的图。

这些算法中的许多都是迭代应用，例如 PageRank 和三角计数。因此，程序将生成许多迭代的 Spark 作业。

# 示例 1 – 计数

图已加载，我们知道数据文件中的数据量。但在实际图中，顶点和边的数据内容是什么？使用以下所示的顶点和边`计数`函数提取此信息非常简单：

```scala
println( "vertices : " + graph.vertices.count )println( "edges   : " + graph.edges.count )
```

运行`graph1`示例，使用先前创建的`.jar`文件和示例名称，将提供`计数`信息。主 URL 用于连接到 Spark 集群，并为执行器内存和总执行器核心提供一些默认参数：

```scala
spark-submit \--class graph1 \--master spark://localhost:7077 \--executor-memory 700M \--total-executor-cores ...
```

# 示例 2 – 过滤

如果我们需要从主图中创建一个子图，并根据人物年龄或关系进行过滤，会发生什么？第二个示例 Scala 文件`graph2`中的示例代码展示了如何实现这一点：

```scala
val c1 = graph.vertices.filter { case (id, (name, age)) => age.toLong > 40 }.count
val c2 = graph.edges.filter { case Edge(from, to, property)
   => property == "Father" | property == "Mother" }.count
println( "Vertices count : " + c1 )
println( "Edges   count : " + c2 )
```

已经从主图创建了两个示例计数：第一个仅根据年龄过滤基于人的顶点，选取那些年龄大于四十岁的人。请注意，存储为字符串的`年龄`值已转换为长整型以进行比较。

第二个示例根据`Mother`或`Father`的关系属性过滤边。创建并打印了两个计数值`c1`和`c2`，作为 Spark 运行输出，如下所示：

```scala
Vertices count : 4
Edges   count : 4
```

# 示例 3 – PageRank

PageRank 算法为图中的每个顶点提供一个排名值。它假设连接到最多边的顶点是最重要的。

搜索引擎使用 PageRank 为网页搜索期间的页面显示提供排序，如下面的代码所示：

```scala
val tolerance = 0.0001val ranking = graph.pageRank(tolerance).verticesval rankByPerson = vertices.join(ranking).map {   case (id, ( (person,age) , rank )) => (rank, id, person)}
```

示例代码创建了一个容差值，并使用它调用图的`pageRank`方法。然后，顶点被排名到一个新的值排名中。为了使排名更有意义，排名值与原始值进行了连接...

# 示例 4 – 三角形计数

三角形计数算法提供了一个基于顶点的与该顶点相关的三角形数量的计数。例如，顶点`Mike` (1) 连接到`Kate` (5)，`Kate` 连接到`Sarah` (2)，`Sarah` 连接到`Mike` (1)，从而形成一个三角形。这在需要生成无三角形的最小生成树图进行路线规划时可能很有用。

执行三角形计数并打印它的代码很简单，如下所示。对图的顶点执行`triangleCount`方法。结果保存在值`tCount`中并打印出来：

```scala
val tCount = graph.triangleCount().vertices
println( tCount.collect().mkString("\n") )
```

应用程序作业的结果显示，顶点`Flo` (4) 和`Jim` (6) 没有三角形，而`Mike` (1) 和`Sarah` (2) 如预期那样拥有最多，因为他们有最多的关系：

```scala
(4,0)
(6,0)
(2,4)
(1,4)
(3,2)
(5,2)
```

# 示例 5 – 连通组件

当从数据中创建一个大图时，它可能包含不相连的子图或彼此隔离的子图，并且可能不包含它们之间的桥接或连接边。这些算法提供了一种连接性的度量。根据你的处理需求，了解所有顶点是否连接可能很重要。

此示例的 Scala 代码调用了两个图方法，`connectedComponents`和`stronglyConnectedComponents`。`strong`方法需要一个最大迭代计数，已设置为`1000`。这些计数作用于图的顶点：

```scala
val iterations = 1000val connected = graph.connectedComponents().verticesval connectedS = graph.stronglyConnectedComponents(iterations).vertices ...
```

# 总结

本章通过示例展示了如何使用基于 Scala 的代码调用 Apache Spark 中的 GraphX 算法。使用 Scala 是因为它比 Java 需要更少的代码来开发示例，从而节省时间。请注意，GraphX 不适用于 Python 或 R。可以使用基于 Scala 的 shell，并且代码可以编译成 Spark 应用程序。

已经介绍了最常见的图算法，你现在应该知道如何使用 GraphX 解决任何图问题。特别是，既然你已经理解了 GraphX 中的图仍然由 RDD 表示和支持，那么你已经熟悉使用它们了。本章的配置和代码示例也将随书提供下载。


# 第八章：火花调优

在本章中，我们将深入探讨 Apache Spark 的内部机制，并看到尽管 Spark 让我们感觉像是在使用另一个 Scala 集合，但我们不应忘记 Spark 实际上运行在一个分布式系统中。因此，需要格外小心。简而言之，本章将涵盖以下主题：

+   监控火花作业

+   Spark 配置

+   火花应用开发中的常见错误

+   优化技术

# 监控火花作业

Spark 提供 Web UI 来监控计算节点（驱动程序或执行程序）上运行或完成的全部作业。在本节中，我们将简要讨论如何使用适当的示例通过 Spark Web UI 监控 Spark 作业。我们将看到如何监控作业的进度（包括已提交、排队和运行中的作业）。我们将简要讨论 Spark Web UI 中的所有标签页。最后，我们将讨论 Spark 中的日志记录过程以进行更好的调优。

# Spark Web 界面

Web UI（也称为 Spark UI）是运行 Spark 应用程序的 Web 界面，用于在 Firefox 或 Google Chrome 等 Web 浏览器上监控作业的执行。当 SparkContext 启动时，在独立模式下，一个显示应用程序有用信息的 Web UI 会在端口 4040 上启动。根据应用程序是否仍在运行或已完成执行，Spark Web UI 有不同的访问方式。

此外，您可以在应用程序执行完毕后通过使用`EventLoggingListener`持久化所有事件来使用 Web UI。然而，`EventLoggingListener`不能单独工作，需要结合 Spark 历史服务器。结合这两个功能，...

# 作业

根据 SparkContext，Jobs 标签页显示 Spark 应用程序中所有 Spark 作业的状态。当您通过 Web 浏览器在`http://localhost:4040`（独立模式）访问 Spark UI 的 Jobs 标签页时，您应该会看到以下选项：

+   显示提交 Spark 作业的活跃用户

+   总运行时间：显示作业的总运行时间

+   调度模式：大多数情况下，它是先进先出（FIFO）

+   活跃作业：显示活跃作业的数量

+   已完成作业：显示已完成作业的数量

+   事件时间线：显示已完成执行的作业的时间线

内部，Jobs 标签页由`JobsTab`类表示，这是一个带有 jobs 前缀的自定义 SparkUI 标签页。Jobs 标签页使用`JobProgressListener`来访问 Spark 作业的统计信息，以在页面上显示上述信息。请看以下截图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/bf303fd3-cd31-4810-bd34-b61193c1b848.png)**图 2：**Spark Web UI 中的 Jobs 标签页

如果您在 Jobs 标签页中进一步展开 Active Jobs 选项，您将能够看到该特定作业的执行计划、状态、已完成阶段数和作业 ID，如 DAG 可视化所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/bf74a871-39d8-4be0-b374-ef2554b65faf.png)**图 3：** Spark Web UI 中任务的 DAG 可视化（简略版）

当用户在 Spark 控制台中输入代码时（例如，Spark shell 或使用 Spark submit），Spark Core 会创建一个操作符图。这基本上是用户在特定节点上对 RDD（不可变对象）执行操作（例如，reduce、collect、count、first、take、countByKey、saveAsTextFile）或转换（例如，map、flatMap、filter、mapPartitions、sample、union、intersection、distinct）时发生的情况。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/2f67f963-d847-4179-b308-ac80fee4bf39.png)**图 4：** DAG 调度器将 RDD 血统转换为阶段 DAG

在转换或操作期间，使用**有向无环图**（**DAG**）信息来恢复到最后一个转换和操作的节点（参见*图 4*和*图 5*以获得更清晰的图像），以保持数据弹性。最后，图形被提交给 DAG 调度器。

如何从 RDD 计算 DAG，然后执行任务？

从高层次来看，当对 RDD 调用任何操作时，Spark 会创建 DAG 并将其提交给 DAG 调度器。DAG 调度器将操作符划分为任务阶段。一个阶段根据输入数据的分区包含任务。DAG 调度器将操作符流水线化。例如，可以在一个阶段中调度多个映射操作符。DAG 调度器的最终结果是一组阶段。这些阶段被传递给任务调度器。任务调度器通过集群管理器（Spark Standalone/YARN/Mesos）启动任务。任务调度器不知道阶段的依赖关系。工作节点在阶段上执行任务。

有向无环图（DAG）调度器随后跟踪哪些阶段输出的 RDD 被物化。接着，它找到一个最小调度来运行作业，并将相关操作符划分为任务阶段。根据输入数据的分区，一个阶段包含多个任务。然后，操作符与 DAG 调度器一起流水线化。实际上，一个阶段中可以调度多个映射或归约操作符（例如）。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/f80b883b-bc62-4898-be8f-232d5fe2755b.png)**图 5：** 执行操作导致 DAG 调度器中新的 ResultStage 和 ActiveJob

DAG 调度器中的两个基本概念是作业和阶段。因此，它必须通过内部注册表和计数器来跟踪它们。从技术上讲，DAG 调度器是 SparkContext 初始化的一部分，它专门在驱动程序上工作（在任务调度器和调度器后端准备好之后立即）。DAG 调度器负责 Spark 执行中的三个主要任务。它为作业计算执行 DAG，即阶段的 DAG。它确定运行每个任务的首选节点，并处理由于洗牌输出文件丢失而导致的故障。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/249b0e98-ac9a-4690-9542-3461582235a8.png)**图 6：** SparkContext 创建的 DAGScheduler 与其他服务

DAG 调度器的最终结果是一组阶段。因此，大多数统计数据和作业状态可以通过这种可视化查看，例如执行计划、状态、已完成阶段的数量以及该特定作业的作业 ID。

# 阶段

Spark UI 中的阶段选项卡显示了 Spark 应用程序中所有作业的所有阶段的当前状态，包括一个阶段的任务和统计数据的两个可选页面以及池详细信息。请注意，此信息仅在应用程序以公平调度模式工作时可用。你应该能够通过`http://localhost:4040/stages`访问阶段选项卡。请注意，当没有提交作业时，该选项卡仅显示标题。阶段选项卡显示了 Spark 应用程序中的阶段。以下阶段可以在该选项卡中看到：

+   活跃阶段

+   待处理阶段

+   已完成阶段

例如，当你在本地提交一个 Spark 作业时，你应该能看到以下状态：

**图 7：**Spark 中所有作业的阶段...

# 存储

存储选项卡显示了每个 RDD、DataFrame 或 Dataset 的大小和内存使用情况。你应该能够看到 RDDs、DataFrames 或 Datasets 的存储相关信息。下图显示了存储元数据，如 RDD 名称、存储级别、缓存分区数量、缓存数据的比例以及 RDD 在主内存中的大小：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/bce60273-1b2f-421d-830f-797c3cf2c647.png)**图 9：**存储选项卡显示了磁盘上 RDD 所占用的空间。

请注意，如果 RDD 无法缓存在主内存中，将使用磁盘空间。本章后面将对此进行更详细的讨论。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/79827dae-e0cc-405e-a5c0-b40830657142.png)**图 10：**数据分布以及磁盘上 RDD 使用的存储空间。

# 环境

环境选项卡展示了当前机器（即驱动程序）上设置的环境变量。更具体地说，运行时信息如 Java Home、Java 版本和 Scala 版本可以在运行时信息下查看。Spark 属性如 Spark 应用 ID、应用名称、驱动程序主机信息、驱动程序端口、执行器 ID、主 URL 和调度模式也可以看到。此外，其他与系统相关的属性和作业属性，如 AWT 工具包版本、文件编码类型（例如，UTF-8）和文件编码包信息（例如，sun.io）可以在系统属性下查看。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/e96ff1b2-89ee-450c-ba39-90f3574b04af.png)**图...**

# 执行器

执行器选项卡使用`ExecutorsListener`收集有关 Spark 应用程序执行器的信息。执行器是一种分布式代理，负责执行任务。执行器以不同方式实例化。例如，当`CoarseGrainedExecutorBackend`收到 Spark Standalone 和 YARN 的`RegisteredExecutor`消息时，执行器被实例化。第二种情况是当 Spark 作业提交给 Mesos 时，Mesos 的`MesosExecutorBackend`被注册。第三种情况是当你在本地运行 Spark 作业时，即创建了`LocalEndpoint`。执行器通常在整个 Spark 应用程序生命周期内运行，这称为执行器的静态分配，尽管你也可以选择动态分配。执行器后端专门管理计算节点或集群中的所有执行器。执行器定期向驱动程序上的**HeartbeatReceiver** RPC 端点报告心跳和活动任务的部分指标，并将结果发送给驱动程序。它们还通过块管理器为用户程序缓存的 RDD 提供内存存储。请参考下图以更清晰地了解这一点：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/d0402ed6-9387-4afd-92d0-ba718b425723.png)**图 12**：Spark 驱动程序实例化一个负责处理 HeartbeatReceiver 心跳消息的执行器。

当执行器启动时，它首先向驱动程序注册，并直接通信以执行任务，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/0a0491c0-ba58-42f2-b664-1cf715bff81a.png)**图 13**：使用 TaskRunners 在执行器上启动任务。

你应该能够访问`http://localhost:4040/executors`上的执行器选项卡。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/7c502d08-b8ab-478f-9600-010dbf8890b8.png)**图 14**：Spark Web UI 上的执行器选项卡。

如前图所示，可以查看执行器 ID、地址、状态、RDD 块、存储内存、磁盘使用、核心、活动任务、失败任务、完成任务、总任务、任务时间（GC 时间）、输入、洗牌读取、洗牌写入和关于执行器的线程转储。

# SQL

Spark UI 中的 SQL 选项卡显示每个操作符的所有累加器值。你应该能够访问`http://localhost:4040/SQL/`上的 SQL 选项卡。它默认显示所有 SQL 查询执行及其底层信息。但是，SQL 选项卡仅在选择查询后显示 SQL 查询执行的详细信息。

本章不涉及对 SQL 的详细讨论。感兴趣的读者可参考[Spark SQL 编程指南](http://spark.apache.org/docs/latest/sql-programming-guide.html#sql)，了解如何提交 SQL 查询并查看其结果输出。

# 使用 Web UI 可视化 Spark 应用程序

当提交 Spark 作业执行时，会启动一个 Web 应用程序 UI，显示有关该应用程序的有用信息。事件时间线展示了应用程序事件的相对顺序和交错情况。时间线视图有三个级别：跨所有作业、单个作业和单个阶段。时间线还显示了执行器的分配和解除分配。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/84681c1c-41e5-4ac1-a74a-6702e1401d2b.png)**图 15**：在 Spark Web UI 上以 DAG 形式执行的 Spark 作业

# 观察正在运行和已完成的 Spark 作业

要访问和观察正在运行和已完成的 Spark 作业，请在 Web 浏览器中打开`http://spark_driver_host:4040`。请注意，您需要将`spark_driver_host`替换为相应的 IP 地址或主机名。

请注意，如果同一主机上运行了多个 SparkContext，它们将绑定到从 4040 开始的连续端口，如 4041、4042 等。默认情况下，此信息仅在您的 Spark 应用程序运行期间可用。这意味着当您的 Spark 作业执行完毕后，绑定将不再有效或可访问。

现在，要访问仍在执行的活动作业，请点击“Active Jobs”链接，您将看到与这些作业相关的信息...

# 使用日志调试 Spark 应用程序

查看所有正在运行的 Spark 应用程序的信息取决于您使用的集群管理器。在调试 Spark 应用程序时，应遵循以下说明：

+   **Spark Standalone**：访问`http://master:18080`上的 Spark master UI。master 和每个 worker 都会显示集群和相关作业统计信息。此外，每个作业的详细日志输出也会写入每个 worker 的工作目录。我们将讨论如何使用`log4j`手动启用 Spark 的日志记录。

+   **YARN**：如果您的集群管理器是 YARN，并且假设您在 Cloudera（或其他基于 YARN 的平台）上运行 Spark 作业，则请转到 Cloudera Manager Admin Console 中的 YARN 应用程序页面。现在，要调试在 YARN 上运行的 Spark 应用程序，请查看 Node Manager 角色的日志。为此，打开日志事件查看器，然后过滤事件流以选择时间窗口、日志级别并显示 Node Manager 源。您也可以通过命令访问日志。命令格式如下：

```scala
 yarn logs -applicationId <application ID> [OPTIONS]
```

例如，以下是针对这些 ID 的有效命令：

```scala
 yarn logs -applicationId application_561453090098_0005 
 yarn logs -applicationId application_561453090070_0005 userid
```

请注意，用户 ID 可能不同。但是，仅当`yarn-site.xml`中的`yarn.log-aggregation-enable`为 true 且应用程序已完成执行时，此情况才成立。

# Spark 使用 log4j 进行日志记录

Spark 使用`log4j`进行自身日志记录。所有后端发生的操作都会被记录到 Spark shell 控制台（该控制台已配置到基础存储）。Spark 提供了一个`log4j`的属性文件模板，我们可以扩展和修改该文件以在 Spark 中进行日志记录。转到`SPARK_HOME/conf`目录，您应该会看到`log4j.properties.template`文件。这可以作为我们自己日志系统的起点。

现在，让我们在运行 Spark 作业时创建自己的自定义日志系统。完成后，将文件重命名为`log4j.properties`并将其放在同一目录下（即项目树）。文件的示例快照如下所示：

**图 17:** 快照...

# Spark 配置

有多种方法可以配置您的 Spark 作业。在本节中，我们将讨论这些方法。更具体地说，根据 Spark 2.x 版本，有三个位置可以配置系统：

+   Spark 属性

+   环境变量

+   日志记录

# Spark 属性

如前所述，Spark 属性控制大多数应用程序特定参数，并可以使用`SparkConf`对象设置。或者，这些参数可以通过 Java 系统属性设置。`SparkConf`允许您配置一些常见属性，如下所示：

```scala
setAppName() // App name setMaster() // Master URL setSparkHome() // Set the location where Spark is installed on worker nodes. setExecutorEnv() // Set single or multiple environment variables to be used when launching executors. setJars() // Set JAR files to distribute to the cluster. setAll() // Set multiple parameters together.
```

应用程序可以配置为使用机器上可用的多个核心。例如，我们...

# 环境变量

环境变量可用于设置计算节点或机器设置。例如，IP 地址可以通过每个计算节点上的`conf/spark-env.sh`脚本设置。下表列出了需要设置的环境变量的名称和功能：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/9ed855bc-8bb8-450c-b96c-f8403758e021.png)**图 18:** 环境变量及其含义

# 日志记录

最后，日志可以通过位于 Spark 应用程序树下的`log4j.properties`文件进行配置，如前一节所述。Spark 使用 log4j 进行日志记录。log4j 支持的几个有效日志级别如下：

| **日志级别** | **用途** |
| --- | --- |
| OFF | 这是最具体的，不允许任何日志记录 |
| FATAL | 这是最具体的，显示致命错误，数据量较少 |
| ERROR | 这仅显示一般错误 |
| WARN | 这显示了建议修复但非强制性的警告 |
| INFO | 这显示了 Spark 作业所需的信息 |
| DEBUG | 调试时，这些日志将被打印 |
| TRACE | 这提供了最不具体的错误跟踪，包含大量数据 |
| ALL ... |

# 常见的 Spark 应用程序开发错误

常见且经常发生的错误包括应用程序失败、由于多种因素导致的工作缓慢且卡住、聚合、操作或转换中的错误、主线程中的异常，当然还有**内存溢出**（**OOM**）。

# 应用程序失败

大多数情况下，应用程序失败是因为一个或多个阶段最终失败。如本章前面所述，Spark 作业包含多个阶段。阶段并非独立执行：例如，处理阶段不能在相关输入读取阶段之前进行。因此，假设阶段 1 成功执行，但阶段 2 未能执行，整个应用程序最终会失败。这可以表示如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/ddf18574-e882-40eb-ab58-eb8c9a11da46.png)**图 19：**典型 Spark 作业中的两个阶段

为了举例说明，假设您有以下三个 RDD 操作作为阶段。同样可以如图*20*、*21*等所示：

# 慢作业或无响应

有时，如果 SparkContext 无法连接到 Spark 独立主节点，驱动程序可能会显示以下错误：

```scala
02/05/17 12:44:45 ERROR AppClient$ClientActor: All masters are unresponsive! Giving up. 
02/05/17 12:45:31 ERROR SparkDeploySchedulerBackend: Application has been killed. Reason: All masters are unresponsive! Giving up. 
02/05/17 12:45:35 ERROR TaskSchedulerImpl: Exiting due to error from cluster scheduler: Spark cluster looks down
```

在其他时候，驱动程序能够连接到主节点，但主节点无法与驱动程序通信。然后，尽管驱动程序会报告无法连接到 Master 的日志目录，但仍会进行多次连接尝试。

此外，您可能会经常遇到 Spark 作业性能和进度非常缓慢的情况。这是因为您的驱动程序计算作业的速度不够快。如前所述，有时某个特定阶段可能比平常花费更长时间，因为可能涉及洗牌、映射、连接或聚合操作。即使计算机磁盘存储或主内存耗尽，您也可能会遇到这些问题。例如，如果主节点没有响应，或者在一段时间内计算节点没有响应，您可能会认为 Spark 作业已停止，并在某个阶段停滞不前：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/482c7d9e-b096-418d-8d15-a43d37bd08f7.png)**图 24：**执行器/驱动程序无响应的示例日志

可能的解决方案有多种，包括以下内容：

1.  请确保工作者和驱动程序正确配置以连接到 Spark 主节点上列出的确切地址，并在启动 Spark shell 时明确提供 Spark 集群的主 URL：

```scala
 $ bin/spark-shell --master spark://master-ip:7077
```

1.  将`SPARK_LOCAL_IP`设置为驱动程序、主节点和工作进程的集群可访问主机名。

有时，我们因硬件故障而遇到一些问题。例如，如果计算节点上的文件系统意外关闭，即发生 I/O 异常，您的 Spark 作业最终也会失败。这是显而易见的，因为您的 Spark 作业无法将结果 RDD 或数据写入本地文件系统或 HDFS。这也意味着由于阶段失败，DAG 操作无法执行。

有时，由于底层磁盘故障或其他硬件故障，会发生此 I/O 异常。这通常会提供以下日志：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/b76e59df-f159-4e9e-a174-8e8e8c7885b1.png)**图 25：**文件系统关闭示例

尽管如此，您经常遇到作业计算性能缓慢，因为 Java GC 在处理 GC 时有些繁忙，或者无法快速完成 GC。例如，下图显示任务 0 完成 GC 耗时 10 小时！我在 2014 年刚接触 Spark 时遇到过这个问题。然而，控制这类问题并不在我们手中。因此，我们的建议是您应该让 JVM 空闲，并尝试重新提交作业。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/c73396c2-4006-4cf1-8359-8a6081c4baa5.png)**图 26：**GC 在中间卡顿的一个示例

第四个因素可能是由于缺乏数据序列化导致的响应缓慢或作业性能低下。这一点将在下一节讨论。第五个因素可能是代码中的内存泄漏，这将导致应用程序消耗更多内存，并保持文件或逻辑设备打开状态。因此，务必确保没有可能导致内存泄漏的选项。例如，通过调用`sc.stop()`或`spark.stop()`来结束 Spark 应用程序是一个好习惯。这将确保只有一个 SparkContext 保持打开和活跃状态。否则，您可能会遇到意外的异常或问题。第六个问题是，我们经常保持过多的打开文件，这有时会在洗牌或合并阶段引发`FileNotFoundException`。

# 优化技术

有多种方法可以针对更好的优化技术调整 Spark 应用程序。在本节中，我们将讨论如何通过调整主内存与更好的内存管理相结合，应用数据序列化来进一步优化我们的 Spark 应用程序。我们还可以通过在开发 Spark 应用程序时调整 Scala 代码中的数据结构来优化性能。另一方面，通过利用序列化的 RDD 存储，可以很好地维护存储。

垃圾回收及其调整是 Spark 应用程序使用 Java 或 Scala 编写时最重要的方面之一。我们将探讨如何针对优化性能进行调整。对于分布式环境和基于集群的...

# 数据序列化

序列化是任何分布式计算环境中性能改进和优化的重要调整。Spark 也不例外，但 Spark 作业通常数据和计算密集。因此，如果您的数据对象格式不佳，那么您首先需要将它们转换为序列化数据对象。这需要大量内存字节。最终，整个过程将大大减慢整个处理和计算速度。

因此，您经常遇到计算节点响应缓慢的问题。这意味着我们有时未能充分利用计算资源。确实，Spark 试图在便利性和性能之间保持平衡。这也意味着数据序列化应该是 Spark 调优以提高性能的第一步。

Spark 提供了两种数据序列化选项：Java 序列化和 Kryo 序列化库：

+   **Java 序列化**：Spark 使用 Java 的`ObjectOutputStream`框架来序列化对象。你通过创建任何实现`java.io.Serializable`的类来处理序列化。Java 序列化非常灵活，但通常速度很慢，不适合大型数据对象的序列化。

+   **Kryo 序列化**：你还可以使用 Kryo 库更快地序列化你的数据对象。与 Java 序列化相比，Kryo 序列化快 10 倍，且比 Java 序列化更紧凑。然而，它有一个问题，即不支持所有可序列化类型，但你需要要求你的类被注册。

你可以通过初始化你的 Spark 作业并调用`conf.set(spark.serializer, org.apache.spark.serializer.KryoSerializer)`来开始使用 Kryo。要向 Kryo 注册你自己的自定义类，请使用`registerKryoClasses`方法，如下所示：

```scala
val conf = new SparkConf()
               .setMaster(“local[*]”)
               .setAppName(“MyApp”)
conf.registerKryoClasses(Array(classOf[MyOwnClass1], classOf[MyOwnClass2]))
val sc = new SparkContext(conf)
```

如果你的对象很大，你可能还需要增加`spark.kryoserializer.buffer`配置。这个值需要足够大，以容纳你序列化的最大对象。最后，如果你没有注册你的自定义类，Kryo 仍然可以工作；但是，每个对象都需要存储完整的类名，这确实是浪费的。

例如，在监控 Spark 作业部分的日志记录子部分中，可以使用`Kryo`序列化优化日志记录和计算。首先，只需将`MyMapper`类创建为普通类（即没有任何序列化），如下所示：

```scala
class MyMapper(n: Int) { // without any serialization
  @transient lazy val log = org.apache.log4j.LogManager.getLogger("myLogger")
  def MyMapperDosomething(rdd: RDD[Int]): RDD[String] = rdd.map { i =>
    log.warn("mapping: " + i)
    (i + n).toString
  }
}
```

现在，让我们将这个类注册为`Kyro`序列化类，然后按照以下方式设置`Kyro`序列化：

```scala
conf.registerKryoClasses(Array(classOf[MyMapper])) // register the class with Kyro
conf.set("spark.serializer", "org.apache.spark.serializer.KryoSerializer") // set Kayro serialization
```

这就是你所需要的。以下给出了这个示例的完整源代码。你应该能够运行并观察到相同的输出，但与前一个示例相比，这是一个优化版本：

```scala
package com.chapter14.Serilazition
import org.apache.spark._
import org.apache.spark.rdd.RDD
class MyMapper(n: Int) { // without any serilization
  @transient lazy val log = org.apache.log4j.LogManager.getLogger
                                ("myLogger")
  def MyMapperDosomething(rdd: RDD[Int]): RDD[String] = rdd.map { i =>
    log.warn("mapping: " + i)
    (i + n).toString
  }
}
//Companion object
object MyMapper {
  def apply(n: Int): MyMapper = new MyMapper(n)
}
//Main object
object KyroRegistrationDemo {
  def main(args: Array[String]) {
    val log = LogManager.getRootLogger
    log.setLevel(Level.WARN)
    val conf = new SparkConf()
      .setAppName("My App")
      .setMaster("local[*]")
    conf.registerKryoClasses(Array(classOf[MyMapper2]))
     // register the class with Kyro
    conf.set("spark.serializer", "org.apache.spark.serializer
             .KryoSerializer") // set Kayro serilazation
    val sc = new SparkContext(conf)
    log.warn("Started")
    val data = sc.parallelize(1 to 100000)
    val mapper = MyMapper(1)
    val other = mapper.MyMapperDosomething(data)
    other.collect()
    log.warn("Finished")
  }
}
```

输出如下：

```scala
17/04/29 15:33:43 WARN root: Started 
.
.
17/04/29 15:31:51 WARN myLogger: mapping: 1 
17/04/29 15:31:51 WARN myLogger: mapping: 49992
17/04/29 15:31:51 WARN myLogger: mapping: 49999
17/04/29 15:31:51 WARN myLogger: mapping: 50000 
.
.                                                                                
17/04/29 15:31:51 WARN root: Finished
```

做得好！现在让我们快速了解一下如何调整内存。在下一节中，我们将探讨一些高级策略，以确保主内存的高效使用。

# 内存调优

在本节中，我们将讨论一些高级策略，这些策略可以被像你这样的用户用来确保在执行 Spark 作业时进行高效的内存使用。更具体地说，我们将展示如何计算你的对象的内存使用量。我们将建议一些高级方法来通过优化你的数据结构或通过使用 Kryo 或 Java 序列化器将你的数据对象转换为序列化格式来改进它。最后，我们将探讨如何调整 Spark 的 Java 堆大小、缓存大小和 Java 垃圾收集器。

调整内存使用时有三个考虑因素：

+   你的对象使用的内存量：你可能甚至希望你的整个数据集都能适应内存

+   访问那些...

# 内存使用和管理

你的 Spark 应用程序及其底层计算节点的内存使用可分为执行和存储两类。执行内存用于合并、洗牌、连接、排序和聚合等计算过程中的使用。另一方面，存储内存用于缓存和在集群间传播内部数据。简而言之，这是由于网络间的大量 I/O 造成的。

从技术上讲，Spark 会将网络数据缓存在本地。在迭代或交互式地使用 Spark 时，缓存或持久化是 Spark 中的优化技巧。这两者有助于保存中间部分结果，以便在后续阶段重用。然后，这些中间结果（作为 RDD）可以保存在内存中（默认），或更稳定的存储介质，如磁盘，以及/或进行复制。此外，RDD 也可以通过缓存操作进行缓存。它们还可以使用持久化操作进行持久化。缓存和持久化操作之间的区别纯粹是语法上的。缓存是持久化或持久（`MEMORY_ONLY`）的同义词，即缓存仅以默认存储级别 `MEMORY_ONLY` 进行持久化。

如果你在 Spark 网页界面的存储标签下查看，你应该能看到 RDD、DataFrame 或 Dataset 对象使用的内存/存储，如图 *10* 所示。尽管 Spark 中有两个与内存调优相关的配置，但用户无需调整它们。原因在于配置文件中设置的默认值足以满足你的需求和负载。

spark.memory.fraction 表示统一区域大小占（JVM 堆空间 - 300 MB）的比例（默认值为 0.6）。剩余空间（40%）用于用户数据结构、Spark 内部元数据，以及防范因稀疏和异常大的记录导致的 OOM 错误。另一方面，`spark.memory.storageFraction` 表示 R 存储空间占统一区域的比例（默认值为 0.5）。此参数的默认值为 Java 堆空间的 50%，即 300 MB。

现在，你心中可能浮现一个问题：应该选择哪种存储级别？针对这个问题，Spark 存储级别提供了不同内存使用与 CPU 效率之间的权衡。如果你的 RDD 能舒适地适应默认存储级别（MEMORY_ONLY），就让 Spark 驱动器或主节点采用它。这是最节省内存的选项，能让 RDD 上的操作尽可能快地运行。你应该选择这个，因为它是最节省内存的选项。这也使得 RDD 上的众多操作能以最快速度完成。

如果您的 RDD 不适合主内存，即`MEMORY_ONLY`不起作用，您应该尝试使用`MEMORY_ONLY_SER`。强烈建议不要将 RDD 溢出到磁盘，除非您的**UDF**（即您为处理数据集定义的**用户定义函数**）成本过高。如果您的 UDF 在执行阶段过滤掉大量数据，这也适用。在其他情况下，重新计算分区，即重新分区，可能比从磁盘读取数据对象更快。最后，如果您需要快速故障恢复，请使用复制存储级别。

总之，Spark 2.x 支持以下 StorageLevels：（名称中的数字 _2 表示 2 个副本）：

+   `DISK_ONLY`：这是为 RDD 进行磁盘操作

+   `DISK_ONLY_2`：这是为 RDD 进行磁盘操作，有 2 个副本

+   `MEMORY_ONLY`：这是 RDD 在内存中进行缓存操作的默认设置

+   `MEMORY_ONLY_2`：这是 RDD 在内存中进行缓存操作的默认设置，有 2 个副本

+   `MEMORY_ONLY_SER`：如果您的 RDD 不适合主内存，即`MEMORY_ONLY`不起作用，此选项特别有助于以序列化形式存储数据对象

+   `MEMORY_ONLY_SER_2`：如果您的 RDD 不适合主内存，即`MEMORY_ONLY`在 2 个副本下不起作用，此选项也有助于以序列化形式存储数据对象

+   `MEMORY_AND_DISK`：基于内存和磁盘（即组合）的 RDD 持久化

+   `MEMORY_AND_DISK_2`：基于内存和磁盘（即组合）的 RDD 持久化，有 2 个副本

+   `MEMORY_AND_DISK_SER`：如果`MEMORY_AND_DISK`不起作用，可以使用它

+   `MEMORY_AND_DISK_SER_2`：如果`MEMORY_AND_DISK`在 2 个副本下不起作用，可以使用此选项

+   `OFF_HEAP`：不允许写入 Java 堆空间

请注意，缓存是持久化（`MEMORY_ONLY`）的同义词。这意味着缓存仅以默认存储级别持久化，即`MEMORY_ONLY`。详细信息请参见[`jaceklaskowski.gitbooks.io/mastering-apache-spark/content/spark-rdd-StorageLevel.html`](https://jaceklaskowski.gitbooks.io/mastering-apache-spark/content/spark-rdd-StorageLevel.html)。

# 调整数据结构

减少额外内存使用的第一种方法是避免 Java 数据结构中的一些特性，这些特性会带来额外的开销。例如，基于指针的数据结构和包装对象会导致非平凡的开销。为了使用更好的数据结构调整您的源代码，我们在这里提供了一些建议，这些建议可能会有所帮助。

首先，设计您的数据结构，以便更多地使用对象和基本类型的数组。因此，这也建议更频繁地使用标准 Java 或 Scala 集合类，如`Set`、`List`、`Queue`、`ArrayList`、`Vector`、`LinkedList`、`PriorityQueue`、`HashSet`、`LinkedHashSet`和`TreeSet`。

其次，在可能的情况下，避免使用包含大量小对象和指针的嵌套结构，以便...

# 序列化 RDD 存储

如前所述，尽管有其他类型的内存调整，但当你的对象太大而无法有效地放入主内存或磁盘时，减少内存使用的一个更简单、更好的方法是将其存储在序列化形式中。

这可以通过 RDD 持久化 API 中的序列化存储级别来实现，例如`MEMORY_ONLY_SER`。有关更多信息，请参阅上一节关于内存管理的介绍，并开始探索可用的选项。

如果你指定使用`MEMORY_ONLY_SER`，Spark 将把每个 RDD 分区存储为一个大的字节数组。然而，这种方法的唯一缺点是可能会减慢数据访问时间。这是合理的，也是显而易见的；公平地说，由于每个对象在重用时都需要在回弹时进行反序列化，因此无法避免这一点。

如前所述，我们强烈建议使用 Kryo 序列化而不是 Java 序列化，以使数据访问更快一些。

# 垃圾收集调优

尽管在你的 Java 或 Scala 程序中，只是顺序或随机地读取一次 RDD，然后对其执行大量操作，这并不是一个主要问题，但如果你在驱动程序中存储了大量与 RDD 相关的数据对象，**Java 虚拟机**（**JVM**）GC 可能会成为一个问题且复杂。当 JVM 需要从旧对象中删除过时和未使用的对象，为新对象腾出空间时，必须识别它们并最终从内存中删除它们。然而，这在处理时间和存储方面是一个代价高昂的操作。你可能会想知道，GC 的成本与存储在主内存中的 Java 对象数量成正比。因此，我们强烈建议...

# 并行度级别

虽然你可以通过`SparkContext.text`文件的可选参数来控制要执行的映射任务数量，但 Spark 会根据文件大小自动为每个文件设置相同的数量。此外，对于`groupByKey`和`reduceByKey`等分布式`reduce`操作，Spark 使用最大父 RDD 的分区数。然而，有时我们会犯一个错误，即没有充分利用计算集群中节点的全部计算资源。因此，除非你明确设置并指定 Spark 作业的并行度级别，否则无法充分利用全部计算资源。因此，你应该将并行度级别设置为第二个参数。

关于此选项的更多信息，请参考[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.rdd.PairRDDFunctions`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.rdd.PairRDDFunctions)。

或者，您可以通过设置配置属性 spark.default.parallelism 来更改默认值。对于没有父 RDD 的并行化等操作，并行度取决于集群管理器，即独立、Mesos 或 YARN。对于本地模式，将并行度设置为本地机器上的核心数。对于 Mesos 或 YARN，将细粒度模式设置为 8。在其他情况下，将所有执行器节点上的核心总数或 2 中较大的一个设置为并行度，并建议在集群中每个 CPU 核心上运行 2-3 个任务。

# 广播

广播变量使 Spark 开发者能够在每个驱动程序上缓存一个只读副本的实例或类变量，而不是将副本与其依赖任务一起传输。然而，仅当多个阶段中的任务需要以反序列化形式使用相同数据时，显式创建广播变量才有用。

在 Spark 应用程序开发中，使用 SparkContext 的广播选项可以大幅减少每个序列化任务的大小。这也有助于降低在集群中启动 Spark 作业的成本。如果在 Spark 作业中有一个任务使用了来自驱动程序的大对象，应将其转换为广播变量。

在 Spark 中使用广播变量...

# 数据局部性

数据局部性意味着数据与待处理代码的接近程度。从技术上讲，数据局部性可以对本地或集群模式下执行的 Spark 作业的性能产生显著影响。因此，如果数据和待处理代码紧密相连，计算速度应该会快得多。通常，从驱动程序向执行器发送序列化代码要快得多，因为代码大小远小于数据大小。

在 Spark 应用程序开发和作业执行中，存在多个级别的局部性。从最近到最远，级别取决于您需要处理的数据的当前位置：

| **数据局部性** | **含义** | **特别说明** |
| --- | --- | --- |
| `PROCESS_LOCAL` | 数据和代码位于同一位置 | 最佳局部性 |
| `NODE_LOCAL` | 数据和代码位于同一节点，例如存储在 HDFS 上的数据 | 比 `PROCESS_LOCAL` 稍慢，因为数据需要在进程和网络之间传播 |
| `NO_PREF` | 数据从其他地方等同访问 | 没有局部性偏好 |
| `RACK_LOCAL` | 数据位于同一机架的服务器上 | 适用于大规模数据处理 |
| `ANY` | 数据位于网络上的其他地方，不在同一机架内 | 除非没有其他选择，否则不推荐使用 |

**表 2：** 数据局部性与 Spark

Spark 被设计成倾向于在最佳局部性级别调度所有任务，但这并不能保证，也不总是可能的。因此，根据计算节点的实际情况，如果可用计算资源过于繁忙，Spark 会切换到较低的局部性级别。此外，如果你想获得最佳的数据局部性，你有两个选择：

+   等待繁忙的 CPU 空闲下来，以便在同一服务器或同一节点上启动处理你的数据的任务

+   立即开始一个新的，这需要将数据迁移过去

# 总结

在本章中，我们讨论了使 Spark 作业性能更优的一些高级主题。我们讨论了一些基本技术来调整你的 Spark 作业。我们讨论了如何通过访问 Spark Web UI 来监控你的作业。我们讨论了如何设置 Spark 配置参数。我们还讨论了一些 Spark 用户常犯的错误，并提供了一些建议。最后，我们讨论了一些有助于调整 Spark 应用程序的优化技术。


# 第九章：测试和调试 Spark

在理想世界中，我们编写的 Spark 代码完美无缺，一切总是运行得完美无瑕，对吧？开个玩笑；实际上，我们知道处理大规模数据集几乎从未那么简单，总会有一些数据点暴露出你代码中的边缘情况。

考虑到上述挑战，因此，在本章中，我们将探讨如果应用程序是分布式的，测试它会有多困难；然后，我们将探讨一些应对方法。简而言之，本章将涵盖以下主题：

+   分布式环境下的测试

+   测试 Spark 应用程序

+   调试 Spark 应用程序

# 分布式环境下的测试

Leslie Lamport 将分布式系统定义如下：

"分布式系统是指由于某些我从未听说过的机器崩溃，导致我无法完成任何工作的系统。"

通过**万维网**（又称**WWW**），一个连接的计算机网络（又称集群）共享资源，是分布式系统的一个好例子。这些分布式环境通常很复杂，经常出现大量异质性。在这些异质环境中进行测试也是具有挑战性的。在本节中，首先，我们将观察在处理此类系统时经常出现的一些常见问题。

# 分布式环境

分布式系统有众多定义。让我们看一些定义，然后我们将尝试将上述类别与之关联。Coulouris 将分布式系统定义为*一个系统，其中位于网络计算机上的硬件或软件组件仅通过消息传递进行通信和协调其动作*。另一方面，Tanenbaum 以几种方式定义了这个术语：

+   *一组独立的计算机，对系统用户而言，它们表现为一台单一的计算机。*

+   *由两个或多个独立计算机组成的系统，它们通过同步或异步消息传递协调其处理。*

+   *分布式系统是一组通过网络连接的自主计算机，其软件设计旨在提供一个集成的计算设施。*

现在，基于前面的定义，分布式系统可以分类如下：

+   只有硬件和软件是分布式的：通过 LAN 连接的本地分布式系统。

+   用户是分布式的，但存在运行后端的计算和硬件资源，例如 WWW。

+   用户和硬件/软件都是分布式的：通过 WAN 连接的分布式计算集群。例如，在使用 Amazon AWS、Microsoft Azure、Google Cloud 或 Digital Ocean 的 droplets 时，你可以获得这类计算设施。

# 分布式系统中的问题

我们将在此讨论软件和硬件测试期间需要注意的一些主要问题，以确保 Spark 作业在集群计算中顺畅运行，集群计算本质上是一种分布式计算环境。

请注意，所有这些问题都是不可避免的，但我们可以至少对其进行优化。您应遵循上一章节中给出的指导和建议。根据*卡马尔·希尔·米什拉*和*阿尼尔·库马尔·特里帕蒂*在《国际计算机科学与信息技术杂志》第 5 卷（4），2014 年，4922-4925 页中的《分布式软件系统的某些问题、挑战和问题》，网址为[`pdfs.semanticscholar.org/4c6d/c4d739bad13bcd0398e5180c1513f18275d8.pdf`](https://pdfs.semanticscholar.org/4c6d/c4d739bad13bcd0398e5180c1513f18275d8.pdf)，其中...

# 分布式环境中的软件测试挑战

在敏捷软件开发中，与任务相关的一些常见挑战，在最终部署前在分布式环境中测试软件时变得更加复杂。团队成员经常需要在错误激增后并行合并软件组件。然而，根据紧急程度，合并往往发生在测试阶段之前。有时，许多利益相关者分布在不同的团队中。因此，存在巨大的误解潜力，团队往往在其中迷失。

例如，Cloud Foundry（[`www.cloudfoundry.org/`](https://www.cloudfoundry.org/)）是一个开源的、高度分布式的 PaaS 软件系统，用于管理云中应用程序的部署和可扩展性。它承诺提供诸如可扩展性、可靠性和弹性等特性，这些特性在 Cloud Foundry 上的部署中是固有的，需要底层分布式系统实施措施以确保鲁棒性、弹性和故障转移。

软件测试的过程早已被熟知包括*单元测试*、*集成测试*、*冒烟测试*、*验收测试*、*可扩展性测试*、*性能测试*和*服务质量测试*。在 Cloud Foundry 中，分布式系统的测试过程如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/3c974ded-af48-4a29-a107-4dce0e42a32a.png)**图 1：** 类似 Cloud 的分布式环境中软件测试的一个示例

如前图（第一列）所示，在云这样的分布式环境中进行测试的过程始于对系统中最小的接触点运行单元测试。在所有单元测试成功执行后，运行集成测试以验证作为单个连贯软件系统（第二列）一部分的交互组件的行为，该系统在单个盒子（例如，**虚拟机**（**VM**）或裸机）上运行。然而，虽然这些测试验证了系统作为单体的整体行为，但它们并不能保证系统在分布式部署中的有效性。一旦集成测试通过，下一步（第三列）就是验证系统的分布式部署并运行冒烟测试。

如你所知，软件的成功配置和单元测试的执行使我们能够验证系统行为的可接受性。这种验证是通过运行验收测试（第四列）来完成的。现在，为了克服分布式环境中上述问题和挑战，还有其他隐藏的挑战需要由研究人员和大数据工程师解决，但这些实际上超出了本书的范围。

既然我们知道在分布式环境中软件测试面临的真正挑战是什么，现在让我们开始测试我们的 Spark 代码。下一节专门介绍测试 Spark 应用程序。

# 测试 Spark 应用程序

尝试测试 Spark 代码的方法有很多，取决于它是 Java（你可以进行基本的 JUnit 测试来测试非 Spark 部分）还是 ScalaTest 用于你的 Scala 代码。你还可以通过在本地或小型测试集群上运行 Spark 来进行完整的集成测试。Holden Karau 提供的另一个很棒的选择是使用 Spark-testing base。你可能知道，到目前为止，Spark 还没有原生的单元测试库。尽管如此，我们可以使用以下两个库作为替代方案：

+   ScalaTest

+   Spark-testing base

然而，在开始测试用 Scala 编写的 Spark 应用程序之前，了解单元测试和测试 Scala 方法的一些背景知识是必要的。

# 测试 Scala 方法

在这里，我们将看到一些测试 Scala 方法的简单技巧。对于 Scala 用户来说，这是最熟悉的单元测试框架（你也可以用它来测试 Java 代码，很快也可以用于 JavaScript）。ScalaTest 支持多种不同的测试风格，每种风格都是为了支持特定类型的测试需求而设计的。详情请参阅 ScalaTest 用户指南，网址为[`www.scalatest.org/user_guide/selecting_a_style`](http://www.scalatest.org/user_guide/selecting_a_style)。尽管 ScalaTest 支持多种风格，但最快上手的方法之一是使用以下 ScalaTest 特性，并以**TDD**（**测试驱动开发**）风格编写测试：

1.  `FunSuite`

1.  `Assertions`

1.  `BeforeAndAfter`

欢迎浏览上述 URL 以了解更多关于这些特性的信息，这将使本教程的其余部分顺利进行。

需要注意的是，TDD 是一种开发软件的编程技术，它指出您应该从测试开始开发。因此，它不影响测试的编写方式，而是影响测试的编写时机。在`ScalaTest.FunSuite`、`Assertions`和`BeforeAndAfter`中没有特质或测试风格来强制或鼓励 TDD，它们仅与 xUnit 测试框架更为相似。

在 ScalaTest 的任何风格特质中，有三种断言可用：

+   `assert`：这在您的 Scala 程序中用于通用断言。

+   `assertResult`：这有助于区分预期值与实际值。

+   `assertThrows`：这用于确保一段代码抛出预期的异常。

ScalaTest 的断言定义在特质`Assertions`中，该特质进一步被`Suite`扩展。简而言之，`Suite`特质是所有风格特质的超特质。根据 ScalaTest 文档（[`www.scalatest.org/user_guide/using_assertions`](http://www.scalatest.org/user_guide/using_assertions)），`Assertions`特质还提供了以下功能：

+   `assume` 用于条件性地取消测试

+   `fail` 无条件地使测试失败

+   `cancel` 无条件取消测试

+   `succeed` 使测试无条件成功

+   `intercept` 确保一段代码抛出预期的异常，然后对异常进行断言

+   `assertDoesNotCompile` 确保一段代码无法编译

+   `assertCompiles` 确保一段代码能够编译

+   `assertTypeError` 确保一段代码因类型（非解析）错误而无法编译

+   `withClue` 用于添加有关失败的更多信息

从上述列表中，我们将展示其中几个。在您的 Scala 程序中，您可以通过调用`assert`并传递一个`Boolean`表达式来编写断言。您可以简单地开始编写您的简单单元测试用例，使用`Assertions`。`Predef`是一个对象，其中定义了 assert 的这种行为。请注意，`Predef`的所有成员都会被导入到您的每个 Scala 源文件中。以下源代码将针对以下情况打印`Assertion success`：

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

然而，如果您设置`a = 2`和`b = 1`，例如，断言将失败，您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/7f37e532-3351-4ae6-80a6-4679d0579aec.png)**图 2：**断言失败的示例

如果您传递一个真表达式，assert 将正常返回。然而，如果提供的表达式为假，assert 将以 AssertionError 异常突然终止。与`AssertionError`和`TestFailedException`形式不同，ScalaTest 的 assert 提供了更多信息，它会告诉您确切在哪一行测试用例失败或对于哪个表达式。因此，ScalaTest 的 assert 提供的错误信息比 Scala 的 assert 更优。

例如，对于以下源代码，您应该会遇到`TestFailedException`，它会告诉您 5 不等于 4：

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

下图显示了前述 Scala 测试的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/2ac606f4-4805-4633-a8c5-5a99799c8f3e.png)**图 3：**TestFailedException 的一个示例

以下源代码说明了使用`assertResult`单元测试来测试您方法结果的用法：

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

上述断言将会失败，Scala 将抛出异常`TestFailedException`并打印出`Expected 3 but got 4`（*图 4*）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/1b1bcd86-c72c-494a-b7b0-6ce8c22ddc47.png)**图 4：**TestFailedException 的另一个示例

现在，让我们看一个单元测试，展示预期的异常：

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

如果您尝试访问超出索引范围的数组元素，上述代码将告诉您是否允许访问前述字符串`Hello world!`的第一个字符。如果您的 Scala 程序能够访问索引中的值，断言将会失败。这也意味着测试案例失败了。因此，由于第一个索引包含字符`H`，上述测试案例自然会失败，您应该会遇到以下错误信息（*图 5*）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/53b86f5b-c893-4daa-8061-2a9f025b803b.png)**图 5：**TestFailedException 的第三个示例

然而，现在让我们尝试访问位于`-1`位置的索引，如下所示：

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

现在断言应为真，因此测试案例将会通过。最后，代码将正常终止。现在，让我们检查我们的代码片段是否能编译。很多时候，您可能希望确保代表潜在“用户错误”的特定代码顺序根本不编译。目的是检查库对错误的抵抗力，以防止不希望的结果和行为。ScalaTest 的`Assertions`特质为此目的包括了以下语法：

```scala
assertDoesNotCompile("val a: String = 1")
```

如果您想确保由于类型错误（而非语法错误）某段代码不编译，请使用以下方法：

```scala
assertTypeError("val a: String = 1")
```

语法错误仍会导致抛出`TestFailedException`。最后，如果您想声明某段代码确实编译通过，您可以通过以下方式使其更加明显：

```scala
assertCompiles("val a: Int = 1")
```

完整示例如下所示：

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

上述代码的输出显示在以下图中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/2fbf984e-a29a-4dda-a9ff-389d870142c4.png)**图 6：**多个测试合并进行

由于篇幅限制，我们希望结束基于 Scala 的单元测试。但对于其他单元测试案例，您可以参考[Scala 测试指南](http://www.scalatest.org/user_guide)。

# 单元测试

在软件工程中，通常会对源代码的各个单元进行测试，以确定它们是否适合使用。这种软件测试方法也称为单元测试。这种测试确保软件工程师或开发者编写的源代码符合设计规范并按预期工作。

另一方面，单元测试的目标是将程序的每个部分（即以模块化的方式）分开。然后尝试观察所有单独的部分是否正常工作。单元测试在任何软件系统中都有几个好处：

+   **早期发现问题：** 它在开发周期的早期发现错误或规范中缺失的部分。

+   **便于变更：** 它有助于重构...

# 测试 Spark 应用程序

我们已经看到了如何使用 Scala 内置的`ScalaTest`包测试 Scala 代码。然而，在本小节中，我们将看到如何测试我们用 Scala 编写的 Spark 应用程序。以下三种方法将被讨论：

+   **方法 1：** 使用 JUnit 测试 Spark 应用程序

+   **方法 2：** 使用`ScalaTest`包测试 Spark 应用程序

+   **方法 3：** 使用 Spark 测试基进行 Spark 应用程序测试

方法 1 和 2 将在这里讨论，并附带一些实际代码。然而，方法 3 的详细讨论将在下一小节中提供。为了保持理解简单明了，我们将使用著名的单词计数应用程序来演示方法 1 和 2。

# 方法 1：使用 Scala JUnit 测试

假设你已经编写了一个 Scala 应用程序，它可以告诉你文档或文本文件中有多少单词，如下所示：

```scala
package com.chapter16.SparkTestingimport org.apache.spark._import org.apache.spark.sql.SparkSessionclass wordCounterTestDemo {  val spark = SparkSession    .builder    .master("local[*]")    .config("spark.sql.warehouse.dir", "E:/Exp/")    .appName(s"OneVsRestExample")    .getOrCreate()  def myWordCounter(fileName: String): Long = {    val input = spark.sparkContext.textFile(fileName)    val counts = input.flatMap(_.split(" ")).distinct()    val counter = counts.count()    counter  }}
```

前面的代码简单地解析一个文本文件，并通过简单地分割单词执行`flatMap`操作。然后，它执行...

# 方法 2：使用 FunSuite 测试 Scala 代码

现在，让我们通过仅返回文档中文本的 RDD 来重新设计前面的测试案例，如下所示：

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

因此，前面类中的`prepareWordCountRDD()`方法返回一个字符串和整数值的 RDD。现在，如果我们想要测试`prepareWordCountRDD()`方法的功能，我们可以通过扩展测试类与`FunSuite`和`BeforeAndAfterAll`从 Scala 的`ScalaTest`包来更明确地进行。测试工作的方式如下：

+   通过扩展`FunSuite`和`BeforeAndAfterAll`从 Scala 的`ScalaTest`包来扩展测试类

+   覆盖`beforeAll()`方法以创建 Spark 上下文

+   使用`test()`方法执行测试，并在`test()`方法内部使用`assert()`方法

+   覆盖`afterAll()`方法以停止 Spark 上下文

基于前面的步骤，让我们看一个用于测试前面`prepareWordCountRDD()`方法的类：

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

第一个测试表明，如果两个 RDD 以两种不同的方式实现，内容应该相同。因此，第一个测试应该通过。我们将在下面的例子中看到这一点。现在，对于第二个测试，正如我们之前所见，RDD 的单词计数为 214，但让我们暂时假设它是未知的。如果它恰好是 214，测试案例应该通过，这是其预期行为。

因此，我们期望两个测试都通过。现在，在 Eclipse 中，运行测试套件为`ScalaTest-File`，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/87342913-3a2b-4a9e-8a70-45cffdb44044.png) **图 10:** 以 ScalaTest-File 形式运行测试套件

现在您应该观察到以下输出（*图 11*）。输出显示了我们执行了多少测试案例，以及其中有多少通过了、失败了、被取消了、被忽略了或处于待定状态。它还显示了执行整个测试所需的时间。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/0db3c30f-5d87-43d8-a784-4cbbf13bb513.png)**图 11:** 运行两个测试套件作为 ScalaTest-file 时的测试结果

太棒了！测试案例通过了。现在，让我们尝试在两个单独的测试中通过使用`test()`方法改变断言中的比较值：

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

现在，您应该预料到测试案例会失败。现在运行之前的类作为`ScalaTest-File`（*图 12*）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/7ca0967a-280e-46f0-a6e8-934dbcc0e93f.png)**图 12:** 运行前两个测试套件作为 ScalaTest-File 时的测试结果

做得好！我们已经学会了如何使用 Scala 的 FunSuite 进行单元测试。然而，如果您仔细评估前面的方法，您应该同意存在一些缺点。例如，您需要确保`SparkContext`的创建和销毁有明确的管理。作为开发者或程序员，您需要为测试一个示例方法编写更多行代码。有时，代码重复发生，因为*Before*和*After*步骤必须在所有测试套件中重复。然而，这一点有争议，因为公共代码可以放在一个公共特质中。

现在的问题是我们如何能改善我们的体验？我的建议是使用 Spark 测试基底来使生活更轻松、更直接。我们将讨论如何使用 Spark 测试基底进行单元测试。

# 方法 3：利用 Spark 测试基底简化生活

Spark 测试基底助您轻松测试大部分 Spark 代码。那么，这种方法的优势何在？实际上，优势颇多。例如，使用此方法，代码不会冗长，却能得到非常简洁的代码。其 API 本身比 ScalaTest 或 JUnit 更为丰富。支持多种语言，如 Scala、Java 和 Python。内置 RDD 比较器。还可用于测试流应用程序。最后且最重要的是，它支持本地和集群模式测试。这对于分布式环境中的测试至关重要。

GitHub 仓库位于[`github.com/holdenk/spark-testing-base`](https://github.com/holdenk/spark-testing-base)。

开始之前...

# 在 Windows 上配置 Hadoop 运行时

我们已经看到如何在 Eclipse 或 IntelliJ 上测试用 Scala 编写的 Spark 应用程序，但还有一个潜在问题不容忽视。虽然 Spark 可以在 Windows 上运行，但 Spark 设计为在类 UNIX 操作系统上运行。因此，如果您在 Windows 环境中工作，则需要格外小心。

在使用 Eclipse 或 IntelliJ 为 Windows 上的数据分析、机器学习、数据科学或深度学习应用程序开发 Spark 应用程序时，您可能会遇到 I/O 异常错误，您的应用程序可能无法成功编译或可能被中断。实际上，Spark 期望 Windows 上也有 Hadoop 的运行时环境。例如，如果您第一次在 Eclipse 上运行 Spark 应用程序，比如`KMeansDemo.scala`，您将遇到一个 I/O 异常，如下所示：

```scala
17/02/26 13:22:00 ERROR Shell: Failed to locate the winutils binary in the hadoop binary path java.io.IOException: Could not locate executable null\bin\winutils.exe in the Hadoop binaries.
```

原因是默认情况下，Hadoop 是为 Linux 环境开发的，如果您在 Windows 平台上开发 Spark 应用程序，则需要一个桥梁，为 Spark 提供一个 Hadoop 运行时环境，以便正确执行。I/O 异常的详细信息可以在下图看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/32afa337-6d87-4b24-859d-c30a53ab627f.png)**图 14：**由于未能在 Hadoop 二进制路径中定位 winutils 二进制文件，导致发生了 I/O 异常

那么，如何解决这个问题呢？解决方案很简单。正如错误信息所说，我们需要一个可执行文件，即`winutils.exe`。现在从[`github.com/steveloughran/winutils/tree/master/hadoop-2.7.1/bin`](https://github.com/steveloughran/winutils/tree/master/hadoop-2.7.1/bin)下载`winutils.exe`文件，将其粘贴到 Spark 分发目录中，并配置 Eclipse。更具体地说，假设包含 Hadoop 的 Spark 分发位于`C:/Users/spark-2.1.0-bin-hadoop2.7`。在 Spark 分发中，有一个名为 bin 的目录。现在，将可执行文件粘贴到那里（即`path = C:/Users/spark-2.1.0-binhadoop2.7/bin/`）。

解决方案的第二阶段是前往 Eclipse，然后选择主类（即本例中的`KMeansDemo.scala`），接着进入运行菜单。从运行菜单中，选择运行配置选项，并从那里选择环境标签，如图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/b5e41aab-8cce-4deb-8f05-446767d78561.png)**图 15：**解决因 Hadoop 二进制路径中缺少 winutils 二进制文件而发生的 I/O 异常

如果您选择了该标签，您将有机会使用 JVM 为 Eclipse 创建一个新的环境变量。现在创建一个名为`HADOOP_HOME`的新环境变量，并将其值设置为`C:/Users/spark-2.1.0-bin-hadoop2.7/`。现在点击应用按钮并重新运行您的应用程序，您的问题应该得到解决。

需要注意的是，在使用 PySpark 在 Windows 上运行 Spark 时，也需要`winutils.exe`文件。

请注意，上述解决方案也适用于调试您的应用程序。有时，即使出现上述错误，您的 Spark 应用程序仍能正常运行。然而，如果数据集规模较大，很可能会出现上述错误。

# 调试 Spark 应用程序

在本节中，我们将了解如何调试在本地（在 Eclipse 或 IntelliJ 上）、独立模式或 YARN 或 Mesos 集群模式下运行的 Spark 应用程序。然而，在深入之前，有必要了解 Spark 应用程序中的日志记录。

# Spark 使用 log4j 进行日志记录的回顾

如前所述，Spark 使用 log4j 进行自己的日志记录。如果正确配置了 Spark，所有操作都会记录到 shell 控制台。可以从以下图表中看到文件的示例快照：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/e5aa3075-1e4f-4fd6-8594-01e12076c1ce.png)**图 16：**log4j.properties 文件的快照

将默认的 spark-shell 日志级别设置为 WARN。运行 spark-shell 时，此类的日志级别用于覆盖根日志记录器的日志级别，以便用户可以为 shell 和常规 Spark 应用设置不同的默认值。我们还需要在启动由执行器执行并由驱动程序管理的作业时附加 JVM 参数。为此，您应该编辑`conf/spark-defaults.conf`。简而言之，可以添加以下选项：

```scala
spark.executor.extraJavaOptions=-Dlog4j.configuration=file:/usr/local/spark-2.1.1/conf/log4j.properties spark.driver.extraJavaOptions=-Dlog4j.configuration=file:/usr/local/spark-2.1.1/conf/log4j.properties
```

为了使讨论更清晰，我们需要隐藏所有由 Spark 生成的日志。然后我们可以将它们重定向到文件系统中进行记录。另一方面，我们希望自己的日志记录在 shell 和单独的文件中，以免与 Spark 的日志混淆。从这里开始，我们将指示 Spark 指向存放我们自己日志的文件，在本例中为`/var/log/sparkU.log`。当应用程序启动时，Spark 会拾取这个`log4j.properties`文件，因此我们除了将其放置在提及的位置外，无需做其他事情：

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

在前面的代码中，一旦将日志级别设置为`INFO`，所有内容都会作为 INFO 打印，直到您将级别设置为新的级别，例如`WARN`。然而，在那之后，不会有任何信息、跟踪等被打印出来。此外，log4j 支持 Spark 的几个有效日志级别。成功执行前面的代码应该会产生以下输出：

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

您还可以在`conf/log4j.properties`中设置 Spark shell 的默认日志记录。Spark 提供了一个 log4j 的属性文件模板，我们可以扩展和修改该文件以在 Spark 中进行日志记录。转到`SPARK_HOME/conf`目录，您应该会看到`log4j.properties.template`文件。在重命名后，您应该使用以下`conf/log4j.properties.template`作为`log4j.properties`。在基于 IDE 的环境（如 Eclipse）中开发 Spark 应用程序时，您可以将`log4j.properties`文件放在项目目录下。但是，要完全禁用日志记录，只需将`log4j.logger.org`标志设置为`OFF`，如下所示：

```scala
log4j.logger.org=OFF
```

到目前为止，一切都很容易。然而，我们还没有注意到前述代码段中的一个问题。`org.apache.log4j.Logger`类的一个缺点是它不是可序列化的，这意味着我们在使用 Spark API 的某些部分进行操作时，不能在闭包内部使用它。例如，假设我们在 Spark 代码中执行以下操作：

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

你应该会遇到一个异常，它会说`Task`不可序列化，如下所示：

```scala
org.apache.spark.SparkException: Job aborted due to stage failure: Task not serializable: java.io.NotSerializableException: ...
Exception in thread "main" org.apache.spark.SparkException: Task not serializable 
Caused by: java.io.NotSerializableException: org.apache.log4j.spi.RootLogger
Serialization stack: object not serializable
```

首先，我们可以尝试用一种简单的方法来解决这个问题。你可以做的就是让执行实际操作的 Scala 类`Serializable`，使用`extends Serializable`。例如，代码如下所示：

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

本节旨在进行关于日志记录的讨论。然而，我们借此机会使其更适用于通用 Spark 编程和问题。为了更有效地克服`task not serializable`错误，编译器将尝试发送整个对象（不仅仅是 lambda），使其可序列化，并强制 Spark 接受它。然而，这会显著增加数据混洗，尤其是对于大型对象！其他方法是将整个类设为`Serializable`，或者仅在传递给 map 操作的 lambda 函数中声明实例。有时，在节点之间保留不可`Serializable`的对象可能有效。最后，使用`forEachPartition()`或`mapPartitions()`而不是仅使用`map()`，并创建不可`Serializable`的对象。总之，这些是解决问题的方法：

+   序列化该类

+   仅在传递给 map 的 lambda 函数中声明实例

+   将不可序列化对象设为静态，并在每台机器上创建一次

+   调用`forEachPartition ()`或`mapPartitions()`而不是`map()`，并创建不可序列化对象

在前述代码中，我们使用了注解`@transient lazy`，它标记`Logger`类为非持久性的。另一方面，包含应用方法（即`MyMapperObject`）的对象，用于实例化`MyMapper`类的对象，如下所示：

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

现在，让我们看另一个例子，它提供了更好的洞察力，以继续解决我们正在讨论的问题。假设我们有以下类，用于计算两个整数的乘法：

```scala
class MultiplicaitonOfTwoNumber {
  def multiply(a: Int, b: Int): Int = {
    val product = a * b
    product
  }
}
```

现在，本质上，如果你尝试使用这个类来计算 lambda 闭包中的乘法，使用`map()`，你将会遇到我们之前描述的`Task Not Serializable`错误。现在我们只需简单地使用`foreachPartition()`和内部的 lambda，如下所示：

```scala
val myRDD = spark.sparkContext.parallelize(0 to 1000)
    myRDD.foreachPartition(s => {
      val notSerializable = new MultiplicaitonOfTwoNumber
      println(notSerializable.multiply(s.next(), s.next()))
    })
```

现在，如果你编译它，它应该返回期望的结果。为了方便，包含`main()`方法的完整代码如下：

```scala
package com.chapter16.SparkTesting
import org.apache.spark.sql.SparkSession
class MultiplicaitonOfTwoNumber {
  def multiply(a: Int, b: Int): Int = {
    val product = a * b
    product
  }
}
```

```scala

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

在本节中，我们将讨论如何在本地 Eclipse 或 IntelliJ 上调试运行在独立模式或集群模式（在 YARN 或 Mesos 上）的 Spark 应用程序。在开始之前，您还可以阅读调试文档：[`hortonworks.com/hadoop-tutorial/setting-spark-development-environment-scala/`](https://hortonworks.com/hadoop-tutorial/setting-spark-development-environment-scala/)。

# 在 Eclipse 上以 Scala 调试方式调试 Spark 应用程序

要实现这一目标，只需将您的 Eclipse 配置为将 Spark 应用程序作为常规 Scala 代码进行调试。配置方法为选择运行 | 调试配置 | Scala 应用程序，如图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/eb20cffd-d0b0-4286-96bb-2ebb36b82048.png)**图 17：**配置 Eclipse 以将 Spark 应用程序作为常规 Scala 代码进行调试

假设我们想要调试我们的`KMeansDemo.scala`，并要求 Eclipse（您可以在 InteliJ IDE 中拥有类似选项）从第 56 行开始执行并在第 95 行设置断点。为此，请以调试模式运行您的 Scala 代码，您应该在 Eclipse 上观察到以下场景：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/bb345bf6-ae2b-4a92-9811-37038227fc01.png)**图 18：**在 Eclipse 上调试 Spark 应用程序

然后，Eclipse 将在您要求它停止执行的第 95 行暂停，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/1d4e11ff-3edf-456e-be9f-fa62cacac199.png)**图 19：**在 Eclipse 上调试 Spark 应用程序（断点）

总之，为了简化上述示例，如果在第 56 行和第 95 行之间出现任何错误，Eclipse 将显示错误实际发生的位置。否则，如果没有中断，它将遵循正常的工作流程。

# 调试作为本地和独立模式运行的 Spark 作业

在本地或独立模式下调试您的 Spark 应用程序时，您应该知道调试驱动程序程序和调试其中一个执行程序是不同的，因为使用这两种节点需要向`spark-submit`传递不同的提交参数。在本节中，我将使用端口 4000 作为地址。例如，如果您想调试驱动程序程序，您可以在您的`spark-submit`命令中添加以下内容：

```scala
--driver-java-options -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=4000
```

之后，您应将远程调试器设置为连接到您提交驱动程序程序的节点。对于上述情况，端口号 4000 是...

# 在 YARN 或 Mesos 集群上调试 Spark 应用程序

当您在 YARN 上运行 Spark 应用程序时，有一个选项可以通过修改`yarn-env.sh`来启用：

```scala
YARN_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=4000 $YARN_OPTS"
```

现在，远程调试将通过 Eclipse 或 IntelliJ IDE 上的 4000 端口可用。第二种方法是设置`SPARK_SUBMIT_OPTS`。您可以使用 Eclipse 或 IntelliJ 开发可以提交到远程多节点 YARN 集群执行的 Spark 应用程序。我所做的是在 Eclipse 或 IntelliJ 上创建一个 Maven 项目，将我的 Java 或 Scala 应用程序打包成 jar 文件，然后作为 Spark 作业提交。然而，为了将 IDE（如 Eclipse 或 IntelliJ）调试器附加到您的 Spark 应用程序，您可以使用`SPARK_SUBMIT_OPTS`环境变量定义所有提交参数，如下所示：

```scala
$ export SPARK_SUBMIT_OPTS=-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=4000
```

然后如下提交您的 Spark 作业（请根据您的需求和设置相应地更改值）：

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

执行上述命令后，它将等待您连接调试器，如下所示：`Listening for transport dt_socket at address: 4000`。现在，您可以在 IntelliJ 调试器中配置 Java 远程应用程序（Scala 应用程序也可以），如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/15c30522-5742-4de4-885f-fc568d44748e.png)**图 20：**在 IntelliJ 上配置远程调试器

对于上述情况，10.200.1.101 是远程计算节点上运行 Spark 作业的基本 IP 地址。最后，您需要通过点击 IntelliJ 的运行菜单下的调试来启动调试器。然后，如果调试器连接到您的远程 Spark 应用程序，您将在 IntelliJ 的应用程序控制台中看到日志信息。现在，如果您可以设置断点，其余的调试就是正常的了。

下图展示了在 IntelliJ 中暂停带有断点的 Spark 作业时的示例视图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/2d8b430a-9583-4009-b8ba-bebcc6dfbd13.png)**图 21：**在 IntelliJ 中暂停带有断点的 Spark 作业时的示例视图

尽管效果良好，但有时我发现使用`SPARK_JAVA_OPTS`在 Eclipse 甚至 IntelliJ 的调试过程中帮助不大。相反，在运行 Spark 作业的真实集群（YARN、Mesos 或 AWS）上，使用并导出`SPARK_WORKER_OPTS`和`SPARK_MASTER_OPTS`，如下所示：

```scala
$ export SPARK_WORKER_OPTS="-Xdebug -Xrunjdwp:server=y,transport=dt_socket,address=4000,suspend=n"
$ export SPARK_MASTER_OPTS="-Xdebug -Xrunjdwp:server=y,transport=dt_socket,address=4000,suspend=n"
```

然后如下启动 Master 节点：

```scala
$ SPARKH_HOME/sbin/start-master.sh
```

现在打开一个 SSH 连接到运行 Spark 作业的远程机器，并将本地主机映射到 4000（即`localhost:4000`）到`host_name_to_your_computer.org:5000`，假设集群位于`host_name_to_your_computer.org:5000`并监听端口 5000。现在，您的 Eclipse 将认为您只是在调试本地 Spark 应用程序或进程。然而，要实现这一点，您需要在 Eclipse 上配置远程调试器，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/591d8d5c-0a0a-4e5d-9fd0-d38bf0b71f89.png)**图 22：**在 Eclipse 上连接远程主机以调试 Spark 应用程序

就这样！现在你可以在实时集群上调试，就像在桌面一样。前面的示例是在 Spark Master 设置为 YARN-client 的情况下运行的。然而，在 Mesos 集群上运行时也应该有效。如果你使用的是 YARN-cluster 模式，你可能需要将驱动程序设置为附加到调试器，而不是将调试器附加到驱动程序，因为你事先不一定知道驱动程序将执行的模式。

# 使用 SBT 调试 Spark 应用程序

上述设置主要适用于使用 Maven 项目的 Eclipse 或 IntelliJ。假设你已经完成了应用程序，并正在你喜欢的 IDE（如 IntelliJ 或 Eclipse）中工作，如下所示：

```scala
object DebugTestSBT {  def main(args: Array[String]): Unit = {    val spark = SparkSession      .builder      .master("local[*]")      .config("spark.sql.warehouse.dir", "C:/Exp/")      .appName("Logging")      .getOrCreate()          spark.sparkContext.setCheckpointDir("C:/Exp/")    println("-------------Attach debugger now!--------------")    Thread.sleep(8000)    // code goes here, with breakpoints set on the lines you want to pause  }}
```

现在，如果你想将这项工作部署到本地集群（独立模式），第一步是打包...

# 总结

在本章中，你看到了测试和调试 Spark 应用程序的难度。在分布式环境中，这些甚至可能更为关键。我们还讨论了一些高级方法来全面应对这些问题。总之，你学习了在分布式环境中的测试方法。然后你学习了测试 Spark 应用程序的更好方法。最后，我们讨论了一些调试 Spark 应用程序的高级方法。

这基本上是我们关于 Spark 高级主题的小旅程的结束。现在，我们给读者的一般建议是，如果你是数据科学、数据分析、机器学习、Scala 或 Spark 的相对新手，你应该首先尝试了解你想执行哪种类型的分析。更具体地说，例如，如果你的问题是机器学习问题，尝试猜测哪种学习算法最适合，即分类、聚类、回归、推荐或频繁模式挖掘。然后定义和制定问题，之后你应该根据我们之前讨论的 Spark 特征工程概念生成或下载适当的数据。另一方面，如果你认为你可以使用深度学习算法或 API 解决问题，你应该使用其他第三方算法并与 Spark 集成，直接工作。

我们给读者的最终建议是定期浏览 Spark 官网（位于[`spark.apache.org/`](http://spark.apache.org/)）以获取更新，并尝试将常规的 Spark 提供的 API 与其他第三方应用程序或工具结合使用，以实现最佳的协同效果。


# 第十章：使用 Spark 和 Scala 进行实用机器学习

在本章中，我们将涵盖：

+   配置 IntelliJ 以与 Spark 配合工作并运行 Spark ML 示例代码

+   运行 Spark 中的示例 ML 代码

+   识别实用机器学习的数据源

+   使用 IntelliJ IDE 运行您的第一个 Apache Spark 2.0 程序

+   如何向您的 Spark 程序添加图形

# 简介

随着集群计算的最新进展，以及大数据的兴起，机器学习领域已被推到了计算的前沿。长期以来，人们一直梦想有一个能够实现大规模数据科学的交互式平台，现在这个梦想已成为现实。

以下三个领域的结合使得大规模交互式数据科学得以实现并加速发展：

+   **Apache Spark**：一个统一的数据科学技术平台，它将快速计算引擎和容错数据结构结合成一个设计精良且集成的解决方案

+   **机器学习**：人工智能的一个领域，使机器能够模仿原本专属于人脑的一些任务

+   **Scala**：一种基于现代 JVM 的语言，它建立在传统语言之上，但将函数式和面向对象的概念结合在一起，而不会像其他语言那样冗长

首先，我们需要设置开发环境，它将包括以下组件：

+   Spark

+   IntelliJ 社区版 IDE

+   Scala

本章中的配方将为您提供详细的安装和配置 IntelliJ IDE、Scala 插件和 Spark 的说明。开发环境设置完成后，我们将继续运行一个 Spark ML 示例代码来测试设置。

# Apache Spark

Apache Spark 正成为大数据分析的事实标准平台和行业语言，并作为**Hadoop**范式的补充。Spark 使数据科学家能够以最有利于其工作流程的方式直接开始工作。Spark 的方法是在完全分布式的方式下处理工作负载，无需**MapReduce**（**MR**）或重复将中间结果写入磁盘。

Spark 提供了一个易于使用的统一技术栈中的分布式框架，这使其成为数据科学项目的首选平台，这些项目往往需要一个最终合并到解决方案的迭代算法。由于这些算法的内部工作原理，它们会产生大量的...

# 机器学习

机器学习的目的是制造能够模仿人类智能并自动化一些传统上由人脑完成的任务的机器和设备。机器学习算法旨在在相对较短的时间内处理大量数据集，并近似出人类需要更长时间才能处理出的答案。

（机器学习领域可以分为多种形式，从高层次上可以分为监督学习和无监督学习。监督学习算法是一类使用训练集（即标记数据）来计算概率分布或图形模型的 ML 算法，进而使它们能够在没有进一步人工干预的情况下对新数据点进行分类。无监督学习是一种机器学习算法，用于从没有标签响应的输入数据集中提取推断。）

（Spark 开箱即提供丰富的 ML 算法集合，无需进一步编码即可部署在大型数据集上。下图展示了 Spark 的 MLlib 算法作为思维导图。Spark 的 MLlib 旨在利用并行性，同时拥有容错分布式数据结构。Spark 将此类数据结构称为 **弹性分布式数据集** 或 **RDD**。）

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/2651bc34-49cd-4574-a38e-de98c563668e.png)

# Scala

**Scala** 是一种新兴的现代编程语言，作为传统编程语言如 **Java** 和 **C++** 的替代品而崭露头角。Scala 是一种基于 JVM 的语言，不仅提供简洁的语法，避免了传统的样板代码，还将面向对象和函数式编程融合到一个极其精炼且功能强大的类型安全语言中。

Scala 采用灵活且富有表现力的方法，使其非常适合与 Spark 的 MLlib 交互。Spark 本身是用 Scala 编写的，这一事实有力地证明了 Scala 语言是一种全功能编程语言，可用于创建具有高性能需求的复杂系统代码。

Scala 基于 Java 的传统...

# Software versions and libraries used in this book

The following table provides a detailed list of software versions and libraries used in this book. If you follow the installation instructions covered in this chapter, it will include most of the items listed here. Any other JAR or library files that may be required for specific recipes are covered via additional installation instructions in the respective recipes:

| **Core systems** | **Version** |
| --- | --- |
| Spark | 2.0.0 |
| Java | 1.8 |
| IntelliJ IDEA | 2016.2.4 |
| Scala-sdk | 2.11.8 |

Miscellaneous JARs that will be required are as follows:

| **Miscellaneous JARs** | **Version** |
| --- | --- |
| `bliki-core` | 3.0.19 |
| `breeze-viz` | 0.12 |
| `Cloud9` | 1.5.0 |
| `Hadoop-streaming` | 2.2.0 |
| `JCommon` | 1.0.23 |
| `JFreeChart` | 1.0.19 |
| `lucene-analyzers-common` | 6.0.0 |
| `Lucene-Core` | 6.0.0 |
| `scopt` | 3.3.0 |
| `spark-streaming-flume-assembly` | 2.0.0 |
| `spark-streaming-kafka-0-8-assembly` | 2.0.0 |

We have additionally tested all the recipes in this book on Spark 2.1.1 and found that the programs executed as expected. It is recommended for learning purposes you use the software versions and libraries listed in these tables.

为了跟上快速变化的 Spark 环境和文档，本书中提到的 Spark 文档的 API 链接指向最新的 Spark 2.x.x 版本，但食谱中的 API 参考明确针对 Spark 2.0.0。

本书提供的所有 Spark 文档链接将指向 Spark 网站上的最新文档。如果您希望查找特定版本的 Spark（例如，Spark 2.0.0）的文档，请使用以下 URL 在 Spark 网站上查找相关文档：

[`spark.apache.org/documentation.html`](https://spark.apache.org/documentation.html)

为了清晰起见，我们已尽可能简化代码，而不是展示 Scala 的高级特性。

# 配置 IntelliJ 以配合 Spark 运行 Spark ML 示例代码

在运行 Spark 或本书列出的任何程序提供的示例之前，我们需要进行一些配置以确保项目设置正确。

# 准备就绪

在配置项目结构和全局库时，我们需要特别小心。设置完成后，我们运行 Spark 团队提供的示例 ML 代码以验证安装。示例代码可在 Spark 目录下找到，或通过下载包含示例的 Spark 源代码获取。

# 如何操作...

以下是配置 IntelliJ 以配合 Spark MLlib 工作以及在示例目录中运行 Spark 提供的示例 ML 代码的步骤。示例目录可在您的 Spark 主目录中找到。使用 Scala 示例继续：

1.  点击“项目结构...”选项，如以下截图所示，以配置项目设置：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/0d1ca754-2685-4f65-8e23-80edaf3a3992.png)

1.  验证设置：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/c7b7d942-4e71-4afe-bc92-afee16c93ecb.png)

1.  配置全局库。选择 Scala SDK 作为您的全局库：

1.  选择新的 Scala SDK 的 JAR 文件并允许下载...

# 还有更多...

在 Spark 2.0 之前，我们需要 Google 的另一个库**Guava**来促进 I/O 并提供定义表的一组丰富方法，然后让 Spark 在集群中广播它们。由于难以解决的依赖问题，Spark 2.0 不再使用 Guava 库。如果您使用的是 2.0 之前的 Spark 版本（在 1.5.2 版本中需要），请确保使用 Guava 库。Guava 库可从此 URL 访问：

[`github.com/google/guava/wiki`](https://github.com/google/guava/wiki)

您可能希望使用 Guava 版本 15.0，该版本可在此处找到：

[`mvnrepository.com/artifact/com.google.guava/guava/15.0`](https://mvnrepository.com/artifact/com.google.guava/guava/15.0)

如果您使用的是之前博客中的安装说明，请确保从安装集中排除 Guava 库。

# 另请参见

如果完成 Spark 安装还需要其他第三方库或 JAR，您可以在以下 Maven 仓库中找到它们：

[`repo1.maven.org/maven2/org/apache/spark/`](https://repo1.maven.org/maven2/org/apache/spark/)

# 从 Spark 运行样本 ML 代码

我们可以通过简单地下载 Spark 源树中的样本代码并将其导入 IntelliJ 以确保其运行来验证设置。

# 准备就绪

我们首先运行样本中的逻辑回归代码以验证安装。在下一节中，我们将编写自己的版本并检查输出，以便理解其工作原理。

# 如何操作...

1.  转到源目录并选择一个 ML 样本代码文件运行。我们选择了逻辑回归示例。

如果您在目录中找不到源代码，您可以随时下载 Spark 源码，解压缩，然后相应地提取示例目录。

1.  选择示例后，选择“编辑配置...”，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/b0826b04-9920-401b-a74e-23c650d70b49.png)

1.  在配置选项卡中，定义以下选项：

    +   VM 选项：所示选项允许您运行独立 Spark 集群

    +   程序参数：我们需要传递给程序的内容

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/a74269e6-9e2a-49d7-8971-26c941a19264.png)

1.  通过转到运行'LogisticRegressionExample'来运行逻辑回归，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/fcb89557-0451-4306-b937-972e2c1864bf.png)

1.  验证退出代码，并确保它与下面的截图所示相同：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/64a1a0db-aae3-4870-bbfd-96ba850d663f.png)

# 识别实用机器学习的数据源

过去为机器学习项目获取数据是一个挑战。然而，现在有一系列特别适合机器学习的公共数据源。

# 准备就绪

除了大学和政府来源外，还有许多其他开放数据源可用于学习和编写自己的示例和项目。我们将列出数据源，并向您展示如何最好地获取和下载每章的数据。

# 如何操作...

以下是一些值得探索的开源数据列表，如果您想在此领域开发应用程序：

+   *UCI 机器学习库*：这是一个具有搜索功能的广泛库。在撰写本文时，已有超过 350 个数据集。您可以点击[`archive.ics.uci.edu/ml/index.html`](https://archive.ics.uci.edu/ml/index.html)链接查看所有数据集，或使用简单搜索（*Ctrl* + *F*）查找特定数据集。

+   *Kaggle 数据集*：你需要创建一个账户，但你可以下载任何用于学习和参加机器学习竞赛的数据集。[`www.kaggle.com/competitions`](https://www.kaggle.com/competitions)链接提供了探索和了解更多关于 Kaggle 以及机器学习竞赛内部运作的详细信息。...

# 另请参阅

机器学习数据的其它来源：

+   SMS 垃圾邮件数据：[`www.dt.fee.unicamp.br/~tiago/smsspamcollection/`](http://www.dt.fee.unicamp.br/~tiago/smsspamcollection/)

+   来自 Lending Club 的金融数据集 [`www.lendingclub.com/info/download-data.action`](https://www.lendingclub.com/info/download-data.action)

+   雅虎的研究数据 [`webscope.sandbox.yahoo.com/index.php`](http://webscope.sandbox.yahoo.com/index.php)

+   亚马逊 AWS 公共数据集 [`aws.amazon.com/public-data-sets/`](http://aws.amazon.com/public-data-sets/)

+   来自 ImageNet 的标记视觉数据 [`www.image-net.org`](http://www.image-net.org)

+   人口普查数据集 [`www.census.gov`](http://www.census.gov)

+   编译的 YouTube 数据集 [`netsg.cs.sfu.ca/youtubedata/`](http://netsg.cs.sfu.ca/youtubedata/)

+   来自 MovieLens 网站的收集评分数据 [`grouplens.org/datasets/movielens/`](http://grouplens.org/datasets/movielens/)

+   公开的安然数据集 [`www.cs.cmu.edu/~enron/`](http://www.cs.cmu.edu/~enron/)

+   经典书籍《统计学习要素》的数据集 [`statweb.stanford.edu/~tibs/ElemStatLearn/data.htmlIMDB`](http://statweb.stanford.edu/~tibs/ElemStatLearn/data.htmlIMDB)

+   电影数据集 [`www.imdb.com/interfaces`](http://www.imdb.com/interfaces)

+   百万歌曲数据集 [`labrosa.ee.columbia.edu/millionsong/`](http://labrosa.ee.columbia.edu/millionsong/)

+   语音和音频数据集 [`labrosa.ee.columbia.edu/projects/`](http://labrosa.ee.columbia.edu/projects/)

+   人脸识别数据 [`www.face-rec.org/databases/`](http://www.face-rec.org/databases/)

+   社会科学数据 [`www.icpsr.umich.edu/icpsrweb/ICPSR/studies`](http://www.icpsr.umich.edu/icpsrweb/ICPSR/studies)

+   康奈尔大学的大量数据集 [`arxiv.org/help/bulk_data_s3`](http://arxiv.org/help/bulk_data_s3)

+   古腾堡项目数据集 [`www.gutenberg.org/wiki/Gutenberg:Offline_Catalogs`](http://www.gutenberg.org/wiki/Gutenberg:Offline_Catalogs)

+   世界银行数据集 [`data.worldbank.org`](http://data.worldbank.org)

+   世界词网词汇数据库 [`wordnet.princeton.edu`](http://wordnet.princeton.edu)

+   纽约警察局的碰撞数据 [`nypd.openscrape.com/#/`](http://nypd.openscrape.com/#/)

+   国会唱名表决等数据集 [`voteview.com/dwnl.htm`](http://voteview.com/dwnl.htm)

+   斯坦福大学的大型图数据集 [`snap.stanford.edu/data/index.html`](http://snap.stanford.edu/data/index.html)

+   来自 datahub 的丰富数据集 [`datahub.io/dataset`](https://datahub.io/dataset)

+   Yelp 的学术数据集 [`www.yelp.com/academic_dataset`](https://www.yelp.com/academic_dataset)

+   GitHub 上的数据源 [`github.com/caesar0301/awesome-public-datasets`](https://github.com/caesar0301/awesome-public-datasets)

+   来自 Reddit 的数据集存档 [`www.reddit.com/r/datasets/`](https://www.reddit.com/r/datasets/)

有一些专业数据集（例如，西班牙语文本分析数据集，以及基因和 IMF 数据）可能对您有所帮助：

+   来自哥伦比亚的数据集（西班牙语）：[`www.datos.gov.co/frm/buscador/frmBuscador.aspx`](http://www.datos.gov.co/frm/buscador/frmBuscador.aspx)

+   来自癌症研究的数据集 [`www.broadinstitute.org/cgi-bin/cancer/datasets.cgi`](http://www.broadinstitute.org/cgi-bin/cancer/datasets.cgi)

+   来自皮尤研究中心的研究数据 [`www.pewinternet.org/datasets/`](http://www.pewinternet.org/datasets/)

+   来自美国伊利诺伊州的数据 [`data.illinois.gov`](https://data.illinois.gov)

+   来自 freebase.com 的数据 [`www.freebase.com`](http://www.freebase.com)

+   联合国及其附属机构的数据集 [`data.un.org`](http://data.un.org)

+   国际货币基金组织数据集 [`www.imf.org/external/data.htm`](http://www.imf.org/external/data.htm)

+   英国政府数据 [`data.gov.uk`](https://data.gov.uk)

+   来自爱沙尼亚的开放数据 [`pub.stat.ee/px-web.2001/Dialog/statfile1.asp`](http://pub.stat.ee/px-web.2001/Dialog/statfile1.asp)

+   R 语言中许多包含数据并可导出为 CSV 的 ML 库 [`www.r-project.org`](https://www.r-project.org)

+   基因表达数据集 [`www.ncbi.nlm.nih.gov/geo/`](http://www.ncbi.nlm.nih.gov/geo/)

# 使用 IntelliJ IDE 运行您的第一个 Apache Spark 2.0 程序

本程序的目的是让您熟悉使用刚设置的 Spark 2.0 开发环境编译和运行示例。我们将在后续章节中探讨组件和步骤。

我们将编写自己的 Spark 2.0.0 程序版本，并检查输出，以便理解其工作原理。需要强调的是，这个简短的示例仅是一个简单的 RDD 程序，使用了 Scala 的糖语法，以确保在开始处理更复杂的示例之前，您已正确设置了环境。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含了必要的 JAR 文件。

1.  下载本书的示例代码，找到`myFirstSpark20.scala`文件，并将代码放置在以下目录中。

我们在 Windows 机器上的`C:\spark-2.0.0-bin-hadoop2.7\`目录下安装了 Spark 2.0。

1.  将`myFirstSpark20.scala`文件放置在`C:\spark-2.0.0-bin-hadoop2.7\examples\src\main\scala\spark\ml\cookbook\chapter1`目录下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/c91a16fa-6bd9-4971-b0db-e96b39641279.png)

Mac 用户请注意，我们在 Mac 机器上的`/Users/USERNAME/spark/spark-2.0.0-bin-hadoop2.7/`目录下安装了 Spark 2.0。

将`myFirstSpark20.scala`文件放置在`/Users/USERNAME/spark/spark-2.0.0-bin-hadoop2.7/examples/src/main/scala/spark/ml/cookbook/chapter1`目录下。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter1 
```

1.  为了使 Spark 会话能够访问集群并使用`log4j.Logger`减少 Spark 产生的输出量，导入必要的包：

```scala
import org.apache.spark.sql.SparkSession 
import org.apache.log4j.Logger 
import org.apache.log4j.Level 
```

1.  将输出级别设置为`ERROR`以减少 Spark 的日志输出：

```scala
Logger.getLogger("org").setLevel(Level.ERROR) 
```

1.  通过使用构建器模式指定配置来初始化 Spark 会话，从而为 Spark 集群提供一个入口点：

```scala
val spark = SparkSession 
.builder 
.master("local[*]")
 .appName("myFirstSpark20") 
.config("spark.sql.warehouse.dir", ".") 
.getOrCreate() 
```

`myFirstSpark20`对象将在本地模式下运行。前面的代码块是创建`SparkSession`对象的典型方式。

1.  然后我们创建两个数组变量：

```scala
val x = Array(1.0,5.0,8.0,10.0,15.0,21.0,27.0,30.0,38.0,45.0,50.0,64.0) 
val y = Array(5.0,1.0,4.0,11.0,25.0,18.0,33.0,20.0,30.0,43.0,55.0,57.0) 
```

1.  然后让 Spark 基于之前创建的数组创建两个 RDD：

```scala
val xRDD = spark.sparkContext.parallelize(x) 
val yRDD = spark.sparkContext.parallelize(y) 
```

1.  接下来，我们让 Spark 对`RDD`进行操作；`zip()`函数将从之前提到的两个 RDD 创建一个新的`RDD`：

```scala
val zipedRDD = xRDD.zip(yRDD) 
zipedRDD.collect().foreach(println) 
```

在运行时控制台输出（关于如何在 IntelliJ IDE 中运行程序的更多详细信息将在后续步骤中介绍），您将看到这个：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/9282b5ba-0927-4911-94c5-1cc2ee084d2f.png)

1.  现在，我们汇总`xRDD`和`yRDD`的值，并计算新的`zipedRDD`总和值。我们还计算了`zipedRDD`的项目计数：

```scala
val xSum = zipedRDD.map(_._1).sum() 
val ySum = zipedRDD.map(_._2).sum() 
val xySum= zipedRDD.map(c => c._1 * c._2).sum() 
val n= zipedRDD.count() 
```

1.  我们在控制台上打印出之前计算的值：

```scala
println("RDD X Sum: " +xSum) 
println("RDD Y Sum: " +ySum) 
println("RDD X*Y Sum: "+xySum) 
println("Total count: "+n) 
```

这里是控制台输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/8584177e-8723-4303-af1d-472174b89309.png)

1.  我们通过停止 Spark 会话来关闭程序：

```scala
spark.stop() 
```

1.  程序完成后，`myFirstSpark20.scala`在 IntelliJ 项目资源管理器中的布局将如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/499b8f6b-90d1-4b13-a84b-5b2fed8873a7.png)

1.  确保没有编译错误。您可以通过重建项目来测试这一点：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/65f74350-8ff4-4239-a524-0c9575256308.png)

一旦重建完成，控制台上应该会出现构建完成的消息：

```scala
Information: November 18, 2016, 11:46 AM - Compilation completed successfully with 1 warning in 55s 648ms
```

1.  您可以通过在项目资源管理器中右键点击`myFirstSpark20`对象并选择上下文菜单选项（如下一张截图所示）`运行 myFirstSpark20`来运行前面的程序。

您也可以从菜单栏的“运行”菜单执行相同的操作。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/8b54aab8-e7da-496d-9c2e-73458fc9d172.png)

1.  一旦程序成功执行，您将看到以下消息：

```scala
Process finished with exit code 0
```

这也显示在下面的截图中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/f541842c-fa04-4078-a14d-23fc23f0b625.png)

1.  IntelliJ 的 Mac 用户可以使用相同的上下文菜单执行此操作。

将代码放置在正确的路径上。

# 工作原理...

在本例中，我们编写了第一个 Scala 程序`myFirstSpark20.scala`，并在 IntelliJ 中展示了执行该程序的步骤。我们按照步骤中描述的路径，在 Windows 和 Mac 上都放置了代码。

在`myFirstSpark20`代码中，我们看到了创建`SparkSession`对象的典型方式，以及如何使用`master()`函数配置它以在本地模式下运行。我们从数组对象创建了两个 RDD，并使用简单的`zip()`函数创建了一个新的 RDD。

我们还对创建的 RDD 进行了简单的求和计算，并在控制台中显示了结果。最后，我们通过调用`spark.stop()`退出并释放资源。

# 还有更多...

Spark 可以从[`spark.apache.org/downloads.html`](http://spark.apache.org/downloads.html)下载。

Spark 2.0 关于 RDD 的文档可以在[`spark.apache.org/docs/latest/programming-guide.html#rdd-operations`](http://spark.apache.org/docs/latest/programming-guide.html#rdd-operations)找到。

# 另请参见

+   关于 JetBrain IntelliJ 的更多信息，请访问[`www.jetbrains.com/idea/`](https://www.jetbrains.com/idea/)。

# 如何向你的 Spark 程序添加图形

在本食谱中，我们讨论了如何使用 JFreeChart 向你的 Spark 2.0.0 程序添加图形图表。

# 如何操作...

1.  设置 JFreeChart 库。JFreeChart 的 JAR 文件可以从[`sourceforge.net/projects/jfreechart/files/`](https://sourceforge.net/projects/jfreechart/files/)网站下载。

1.  本书中介绍的 JFreeChart 版本为 JFreeChart 1.0.19，如以下截图所示。它可以从[`sourceforge.net/projects/jfreechart/files/1.%20JFreeChart/1.0.19/jfreechart-1.0.19.zip/download`](https://sourceforge.net/projects/jfreechart/files/1.%20JFreeChart/1.0.19/jfreechart-1.0.19.zip/download)网站下载：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/39158216-47c5-4394-bf11-f9e4d0883505.png)

1.  下载 ZIP 文件后，将其解压。我们在 Windows 机器上的`C:\`下解压了 ZIP 文件，然后继续在解压的目标目录下找到`lib`目录。

1.  接着，我们找到了所需的两个库（JFreeChart...

# 工作原理...

在本例中，我们编写了`MyChart.scala`，并看到了在 IntelliJ 中执行程序的步骤。我们按照步骤中描述的路径在 Windows 和 Mac 上放置了代码。

在代码中，我们看到了创建`SparkSession`对象的典型方法以及如何使用`master()`函数。我们创建了一个 RDD，其元素为 1 到 15 范围内的随机整数数组，并将其与索引进行了压缩。

然后，我们使用 JFreeChart 制作了一个包含简单*x*和*y*轴的基本图表，并提供了我们从前几步中的原始 RDD 生成的数据集。

我们为图表设置了架构，并在 JFreeChart 中调用`show()`函数，以显示一个带有*x*和*y*轴的线性图形图表的框架。

最后，我们通过调用`spark.stop()`退出并释放资源。

# 还有更多...

更多关于 JFreeChart 的信息，请访问：

+   [`www.jfree.org/jfreechart/`](http://www.jfree.org/jfreechart/)

+   [`www.jfree.org/jfreechart/api/javadoc/index.html`](http://www.jfree.org/jfreechart/api/javadoc/index.html)

# 另请参见

关于 JFreeChart 功能和能力的更多示例，请访问以下网站：

[`www.jfree.org/jfreechart/samples.html`](http://www.jfree.org/jfreechart/samples.html)


# 第十一章：Spark 的机器学习三剑客 - 完美结合

本章我们将涵盖以下内容：

+   使用 Spark 2.0 的内部数据源创建 RDD

+   使用 Spark 2.0 的外部数据源创建 RDD

+   使用 Spark 2.0 的 filter() API 转换 RDD

+   使用非常有用的 flatMap() API 转换 RDD

+   使用集合操作 API 转换 RDD

+   使用 groupBy() 和 reduceByKey() 进行 RDD 转换/聚合

+   使用 zip() API 转换 RDD

+   使用配对键值 RDD 进行连接转换

+   使用配对键值 RDD 进行归约和分组转换

+   从 Scala 数据结构创建 DataFrame

+   以编程方式操作 DataFrame 而不使用 SQL

+   从外部源加载 DataFrame 并进行设置...

# 引言

Spark 高效处理大规模数据的三驾马车是 RDD、DataFrames 和 Dataset API。虽然每个都有其独立的价值，但新的范式转变倾向于将 Dataset 作为统一的数据 API，以满足单一接口中的所有数据处理需求。

Spark 2.0 的新 Dataset API 是一种类型安全的领域对象集合，可以通过转换（类似于 RDD 的过滤、`map`、`flatMap()` 等）并行使用函数或关系操作。为了向后兼容，Dataset 有一个名为 **DataFrame** 的视图，它是一个无类型的行集合。在本章中，我们展示了所有三种 API 集。前面的图总结了 Spark 数据处理关键组件的优缺点：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/b88f07c4-3036-4fdf-8d48-86a5b1c8c63f.png)

机器学习的高级开发者必须理解并能够无障碍地使用所有三种 API 集，无论是为了算法增强还是遗留原因。虽然我们建议每位开发者都应向高级 Dataset API 迁移，但你仍需了解 RDD，以便针对 Spark 核心系统编程。例如，投资银行和对冲基金经常阅读机器学习、数学规划、金融、统计学或人工智能领域的领先期刊，然后使用低级 API 编码研究以获得竞争优势。

# RDDs - 一切的起点...

RDD API 是 Spark 开发者的重要工具，因为它在函数式编程范式中提供了对数据底层控制的偏好。RDD 的强大之处同时也使得新程序员更难以使用。虽然理解 RDD API 和手动优化技术（例如，在 `groupBy()` 操作之前使用 `filter()`）可能很容易，但编写高级代码需要持续的练习和熟练度。

当数据文件、块或数据结构转换为 RDD 时，数据被分解为称为 **分区**（类似于 Hadoop 中的拆分）的较小单元，并分布在节点之间，以便它们可以同时并行操作。Spark 直接提供了这种功能...

# 数据帧——通过高级 API 统一 API 和 SQL 的自然演进

Spark 开发者社区始终致力于从伯克利的 AMPlab 时代开始为社区提供易于使用的高级 API。数据 API 的下一个演进是在 Michael Armbrust 向社区提供 SparkSQL 和 Catalyst 优化器时实现的，这使得使用简单且易于理解的 SQL 接口进行数据虚拟化成为可能。数据帧 API 是利用 SparkSQL 的自然演进，通过将数据组织成关系表那样的命名列来实现。

数据帧 API 通过 SQL 使数据整理对众多熟悉 R（data.frame）或 Python/Pandas（pandas.DataFrame）中的数据帧的数据科学家和开发者可用。

# 数据集——一个高级的统一数据 API

数据集是一个不可变的对象集合，这些对象被建模/映射到传统的关系模式。有四个属性使其成为未来首选的方法。我们特别发现数据集 API 具有吸引力，因为它与 RDD 相似，具有常规的转换操作符（例如，`filter()`、`map()`、`flatMap()`等）。数据集将遵循与 RDD 类似的惰性执行范式。尝试调和数据帧和数据集的最佳方式是将数据帧视为可以被认为是`Dataset[Row]`的别名。

+   **强类型安全**：我们现在在统一的数据 API 中既有编译时（语法错误）也有运行时安全，这有助于 ML 开发者...

# 使用 Spark 2.0 通过内部数据源创建 RDD

在 Spark 中创建 RDD 有四种方式，从用于客户端驱动程序中简单测试和调试的`parallelize()`方法，到用于近实时响应的流式 RDD。在本节中，我们将提供多个示例，展示如何使用内部数据源创建 RDD。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter3
```

1.  导入必要的包：

```scala
import breeze.numerics.pow 
import org.apache.spark.sql.SparkSession 
import Array._
```

1.  导入用于设置`log4j`日志级别的包。此步骤是可选的，但我们强烈建议这样做（根据开发周期适当更改级别）。

```scala
import org.apache.log4j.Logger 
import org.apache.log4j.Level 
```

1.  将日志级别设置为警告和错误以减少输出。参见上一步骤了解包要求。

```scala
Logger.getLogger("org").setLevel(Level.ERROR) ...
```

# 工作原理...

客户端驱动程序中的数据通过分区 RDD 的数量（第二个参数）作为指导进行并行化和分布。生成的 RDD 是 Spark 的魔力，它开启了这一切（参阅 Matei Zaharia 的原始白皮书）。

生成的 RDD 现在是具有容错性和血统的完全分布式数据结构，可以使用 Spark 框架并行操作。

我们从[`www.gutenberg.org/`](http://www.gutenberg.org/)读取文本文件`查尔斯·狄更斯的《双城记》`到 Spark RDDs 中。然后我们继续分割和标记化数据，并使用 Spark 的操作符（例如，`map`，`flatMap()`等）打印出总单词数。

# 使用外部数据源创建 Spark 2.0 的 RDDs

在本配方中，我们为您提供了几个示例，以展示使用外部源创建 RDD。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter3 
```

1.  导入必要的包：

```scala
import breeze.numerics.pow 
import org.apache.spark.sql.SparkSession 
import Array._
```

1.  导入用于设置`log4j`日志级别的包。这一步是可选的，但我们强烈建议这样做（根据开发周期适当更改级别）。

```scala
import org.apache.log4j.Logger 
import org.apache.log4j.Level 
```

1.  将日志级别设置为警告和错误，以减少输出。请参阅上一步骤了解包要求。

```scala
Logger.getLogger("org").setLevel(Level.ERROR) 
Logger.getLogger("akka").setLevel(Level.ERROR) 
```

1.  设置 Spark 上下文和应用程序参数，以便 Spark 可以运行。

```scala
val spark = SparkSession 
  .builder 
  .master("local[*]") 
  .appName("myRDD") 
  .config("Spark.sql.warehouse.dir", ".") 
  .getOrCreate()
```

1.  我们从古腾堡项目获取数据。这是一个获取实际文本的绝佳来源，涵盖了从*莎士比亚*全集到*查尔斯·狄更斯*的作品。

1.  从以下来源下载文本并将其存储在本地目录中：

    +   来源：[`www.gutenberg.org`](http://www.gutenberg.org)

    +   选定书籍：*查尔斯·狄更斯的《双城记》*

    +   URL: [`www.gutenberg.org/cache/epub/98/pg98.txt`](http://www.gutenberg.org/cache/epub/98/pg98.txt)

1.  再次，我们使用`SparkContext`，通过`SparkSession`可用，并使用其`textFile()`函数读取外部数据源并在集群上并行化它。值得注意的是，所有工作都是由 Spark 在幕后为开发者完成的，只需一次调用即可加载多种格式（例如，文本、S3 和 HDFS），并使用`protocol:filepath`组合在集群上并行化数据。

1.  为了演示，我们加载了这本书，它以 ASCII 文本形式存储，使用`SparkContext`通过`SparkSession`的`textFile()`方法，后者在幕后工作，并在集群上创建分区 RDDs。

```scala
val book1 = spark.sparkContext.textFile("../data/sparkml2/chapter3/a.txt") 
```

输出将如下所示：

```scala
Number of lines = 16271
```

1.  尽管我们尚未涉及 Spark 转换操作符，我们将查看一小段代码，该代码使用空格作为分隔符将文件分解成单词。在实际情况下，需要一个正则表达式来处理所有边缘情况以及所有空白变化（请参考本章中的*使用 filter() API 的 Spark 中转换 RDDs*配方）。

    +   我们使用 lambda 函数接收每行读取的内容，并使用空格作为分隔符将其分解成单词。

    +   我们使用 flatMap 来分解单词列表的数组（即，每行的一组单词对应于该行的不同数组/列表）。简而言之，我们想要的是每行的单词列表，而不是单词列表的列表。

```scala
val book2 = book1.flatMap(l => l.split(" ")) 
println(book1.count())
```

输出将如下所示：

```scala
Number of words = 143228  
```

# 它是如何工作的...

我们从[`www.gutenberg.org/`](http://www.gutenberg.org/)读取查尔斯·狄更斯的《双城记》文本文件到一个 RDD 中，然后通过使用空格作为分隔符在 lambda 表达式中使用`.split()`和`.flatmap()`方法对 RDD 本身进行单词分词。然后，我们使用 RDD 的`.count()`方法输出单词总数。虽然这很简单，但您必须记住，该操作是在 Spark 的分布式并行框架中进行的，仅用了几行代码。

# 还有更多...

使用外部数据源创建 RDD，无论是文本文件、Hadoop HDFS、序列文件、Casandra 还是 Parquet 文件，都异常简单。再次，我们使用`SparkSession`（Spark 2.0 之前的`SparkContext`）来获取集群的句柄。一旦执行了函数（例如，textFile 协议：文件路径），数据就会被分解成更小的部分（分区），并自动流向集群，这些数据作为可以在并行操作中使用的容错分布式集合变得可用。

1.  在处理实际场景时，必须考虑多种变体。根据我们的经验，最好的建议是在编写自己的函数或连接器之前查阅文档。Spark 要么直接支持您的数据源，要么供应商有一个可下载的连接器来实现相同功能。

1.  我们经常遇到的另一种情况是，许多小文件（通常在`HDFS`目录中生成）需要并行化为 RDD 以供消费。`SparkContext`有一个名为`wholeTextFiles()`的方法，它允许您读取包含多个文件的目录，并将每个文件作为(文件名, 内容)键值对返回。我们发现这在使用 lambda 架构的多阶段机器学习场景中非常有用，其中模型参数作为批处理计算，然后每天在 Spark 中更新。

在此示例中，我们读取多个文件，然后打印第一个文件以供检查。

`spark.sparkContext.wholeTextFiles()`函数用于读取大量小文件，并将它们呈现为(K,V)，即键值对：

```scala
val dirKVrdd = spark.sparkContext.wholeTextFiles("../data/sparkml2/chapter3/*.txt") // place a large number of small files for demo 
println ("files in the directory as RDD ", dirKVrdd) 
println("total number of files ", dirKVrdd.count()) 
println("Keys ", dirKVrdd.keys.count()) 
println("Values ", dirKVrdd.values.count()) 
dirKVrdd.collect() 
println("Values ", dirKVrdd.first()) 
```

运行前面的代码后，您将得到以下输出：

```scala
    files in the directory as RDD ,../data/sparkml2/chapter3/*.txt
    WholeTextFileRDD[10] at wholeTextFiles at myRDD.scala:88)
    total number of files 2
    Keys ,2
    Values ,2
    Values ,(file:/C:/spark-2.0.0-bin-hadoop2.7/data/sparkml2/chapter3/a.txt,
    The Project Gutenberg EBook of A Tale of Two Cities, 
    by Charles Dickens

```

# 参见

Spark 文档中关于`textFile()`和`wholeTextFiles()`函数的说明：

[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.SparkContext`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.SparkContext)

`textFile()`API 是与外部数据源接口的单一抽象。协议/路径的制定足以调用正确的解码器。我们将演示从 ASCII 文本文件、Amazon AWS S3 和 HDFS 读取，用户可以利用这些代码片段来构建自己的系统。

+   路径可以表示为简单路径（例如，本地文本文件）到完整的 URI，包含所需协议（例如，s3n 用于 AWS 存储桶），直至具有服务器和端口配置的完整资源路径（例如，从 Hadoop 集群读取 HDFS 文件）。...

# 使用 Spark 2.0 的 filter() API 转换 RDD

在本食谱中，我们探讨了 RDD 的`filter()`方法，该方法用于选择基础 RDD 的子集并返回新的过滤 RDD。格式类似于`map()`，但 lambda 函数决定哪些成员应包含在结果 RDD 中。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter3
```

1.  导入必要的包：

```scala
import breeze.numerics.pow 
import org.apache.spark.sql.SparkSession 
import Array._
```

1.  导入用于设置`log4j`日志级别的包。此步骤可选，但我们强烈建议执行（根据开发周期调整级别）。

```scala
import org.apache.log4j.Logger 
import org.apache.log4j.Level 
```

1.  将日志级别设置为警告和错误，以减少输出。请参阅上一步骤了解包要求。

```scala
Logger.getLogger("org").setLevel(Level.ERROR) ...
```

# 工作原理...

`filter()` API 通过几个示例进行了演示。在第一个示例中，我们遍历了一个 RDD，并通过使用 lambda 表达式`.filter(i => (i%2) == 1)`输出了奇数，该表达式利用了模（取模）函数。

在第二个示例中，我们通过使用 lambda 表达式`num.map(pow(_,2)).filter(_ %2 == 1)`将结果映射到平方函数，使其变得更有趣。

在第三个示例中，我们遍历文本并使用 lambda 表达式`.filter(_.length < 30).filter(_.length > 0)`过滤掉短行（例如，长度小于 30 个字符的行），以打印短行与总行数的对比（`.count()`）作为输出。

# 还有更多...

`filter()` API 遍历并行分布式集合（即 RDD），并应用作为 lambda 提供给`filter()`的选择标准，以便将元素包含或排除在结果 RDD 中。结合使用`map()`（转换每个元素）和`filter()`（选择子集），在 Spark ML 编程中形成强大组合。

稍后我们将通过`DataFrame` API 看到，如何使用类似`Filter()` API 在 R 和 Python（pandas）中使用的高级框架实现相同效果。

# 另请参阅

+   `.filter()`方法的文档，作为 RDD 的方法调用，可访问[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.JavaRDD`](http://spark.apache.org/docs/2.0.0/api/scala/index.html#org.apache.spark.api.java.JavaRDD)。

+   关于`BloomFilter()`的文档——为了完整性，请注意已存在一个布隆过滤器函数，建议您避免自行编码。相关链接为[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.util.sketch.BloomFilter`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.util.sketch.BloomFilter)。

# 使用极其有用的 flatMap() API 转换 RDD

在本节中，我们探讨了常令初学者困惑的`flatMap()`方法；然而，通过深入分析，我们展示了它是一个清晰的概念，它像 map 一样将 lambda 函数应用于每个元素，然后将结果 RDD 扁平化为单一结构（不再是列表的列表，而是由所有子列表元素构成的单一列表）。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含了必要的 JAR 文件。

1.  设置程序将驻留的包位置

```scala
package spark.ml.cookbook.chapter3 
```

1.  导入必要的包

```scala
import breeze.numerics.pow 
import org.apache.spark.sql.SparkSession 
import Array._
```

1.  导入设置`log4j`日志级别的包。此步骤可选，但我们强烈建议执行（根据开发周期调整级别）。

```scala
import org.apache.log4j.Logger 
import org.apache.log4j.Level 
```

1.  将日志级别设置为警告和错误，以减少输出。请参阅上一步骤了解包需求。

```scala
Logger.getLogger("org").setLevel(Level.ERROR) 
Logger.getLogger("akka").setLevel(Level.ERROR) 
```

1.  设置 Spark 上下文和应用程序参数，以便 Spark 能够运行。

```scala
val spark = SparkSession 
  .builder 
  .master("local[*]") 
  .appName("myRDD") 
  .config("Spark.sql.warehouse.dir", ".") 
  .getOrCreate() 
```

1.  我们使用`textFile()`函数从之前下载的文本文件创建初始（即基础 RDD）：[`www.gutenberg.org/cache/epub/98/pg98.txt`](http://www.gutenberg.org/cache/epub/98/pg98.txt)。

```scala
val book1 = spark.sparkContext.textFile("../data/sparkml2/chapter3/a.txt")
```

1.  我们对 RDD 应用 map 函数以展示`map()`函数的转换。首先，我们错误地尝试仅使用`map()`根据正则表达式*[\s\W]+]*分离所有单词，以说明结果 RDD 是列表的列表，其中每个列表对应一行及其内的分词单词。此例展示了初学者在使用`flatMap()`时可能遇到的困惑。

1.  以下代码行修剪每行并将其分割成单词。结果 RDD（即 wordRDD2）将是单词列表的列表，而不是整个文件的单一单词列表。

```scala
val wordRDD2 = book1.map(_.trim.split("""[\s\W]+""") ).filter(_.length > 0) 
wordRDD2.take(3)foreach(println(_)) 
```

运行上述代码后，您将得到以下输出。

```scala
[Ljava.lang.String;@1e60b459
[Ljava.lang.String;@717d7587
[Ljava.lang.String;@3e906375
```

1.  我们使用`flatMap()`方法不仅进行映射，还扁平化列表的列表，最终得到由单词本身构成的 RDD。我们修剪并分割单词（即分词），然后筛选出长度大于零的单词，并将其映射为大写。

```scala
val wordRDD3 = book1.flatMap(_.trim.split("""[\s\W]+""") ).filter(_.length > 0).map(_.toUpperCase()) 
println("Total number of lines = ", book1.count()) 
println("Number of words = ", wordRDD3.count()) 
```

在此情况下，使用`flatMap()`扁平化列表后，我们能如预期般取回单词列表。

```scala
wordRDD3.take(5)foreach(println(_)) 
```

输出如下：

```scala
Total number of lines = 16271
Number of words = 141603
THE
PROJECT
GUTENBERG
EBOOK
OF  
```

# 它是如何工作的...

在这个简短的示例中，我们读取了一个文本文件，然后使用`flatMap(_.trim.split("""[\s\W]+""")` lambda 表达式对单词进行分割（即，令牌化），以获得一个包含令牌化内容的单一 RDD。此外，我们使用`filter()` API `filter(_.length > 0)`来排除空行，并在输出结果之前使用`.map()` API 中的 lambda 表达式`.map(_.toUpperCase())`映射为大写。

在某些情况下，我们不希望为基 RDD 的每个元素返回一个列表（例如，为对应于一行的单词获取一个列表）。有时我们更倾向于拥有一个单一的扁平列表，该列表对应于文档中的每个单词。简而言之，我们不想要一个列表的列表，而是想要一个包含...的单一列表。

# 还有更多...

`glom()`函数允许你将 RDD 中的每个分区建模为数组，而不是行列表。虽然在大多数情况下可以产生结果，但`glom()`允许你减少分区之间的数据移动。

尽管在表面上，文本中提到的第一种和第二种方法在计算 RDD 中的最小数时看起来相似，但`glom()`函数将通过首先对所有分区应用`min()`，然后发送结果数据，从而在网络上引起更少的数据移动。要看到差异的最佳方式是在 10M+ RDD 上使用此方法，并相应地观察 IO 和 CPU 使用情况。

+   第一种方法是在不使用`glom()`的情况下找到最小值：

```scala
val minValue1= numRDD.reduce(_ min _) 
println("minValue1 = ", minValue1)
```

运行上述代码后，你将得到以下输出：

```scala
minValue1 = 1.0
```

+   第二种方法是通过使用`glom()`来找到最小值，这会导致对一个分区进行本地应用的最小函数，然后通过 shuffle 发送结果。

```scala
val minValue2 = numRDD.glom().map(_.min).reduce(_ min _) 
println("minValue2 = ", minValue2) 
```

运行上述代码后，你将得到以下输出：

```scala
minValue1 = 1.0  
```

# 另请参见

+   `flatMap()`、`PairFlatMap()`及其他 RDD 下的变体的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.JavaRDD`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.JavaRDD)找到。

+   RDD 下`FlatMap()`函数的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.function.FlatMapFunction`](http://spark.apache.org/docs/2.0.0/api/scala/index.html#org.apache.spark.api.java.function.FlatMapFunction)找到。

+   `PairFlatMap()`函数的文档——针对成对数据元素的非常便捷的变体，可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.function.PairFlatMapFunction`](http://spark.apache.org/docs/2.0.0/api/scala/index.html#org.apache.spark.api.java.function.PairFlatMapFunction)找到。

+   `flatMap()`方法将提供的函数（lambda 表达式或通过 def 定义的命名函数）应用于每个元素，展平结构，并生成一个新的 RDD。

# 使用集合操作 API 转换 RDD

在本食谱中，我们探索了 RDD 上的集合操作，如`intersection()`、`union()`、`subtract()`、`distinct()`和`Cartesian()`。让我们以分布式方式实现常规集合操作。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置

```scala
package spark.ml.cookbook.chapter3
```

1.  导入必要的包

```scala
import breeze.numerics.pow 
import org.apache.spark.sql.SparkSession 
import Array._
```

1.  导入用于设置`log4j`日志级别的包。此步骤是可选的，但我们强烈建议您（根据开发周期适当更改级别）。

```scala
import org.apache.log4j.Logger 
import org.apache.log4j.Level 
```

1.  将日志级别设置为警告和错误，以减少输出。请参阅上一步骤了解包要求。

```scala
Logger.getLogger("org").setLevel(Level.ERROR) ...
```

# 它是如何工作的...

在本例中，我们以三组数字数组（奇数、偶数及其组合）开始，然后将它们作为参数传递给集合操作 API。我们介绍了如何使用`intersection()`、`union()`、`subtract()`、`distinct()`和`cartesian()` RDD 操作符。

# 另请参见

虽然 RDD 集合操作符易于使用，但必须注意 Spark 在后台为完成某些操作（例如，交集）而必须进行的数据洗牌。

值得注意的是，union 操作符不会从结果 RDD 集合中删除重复项。

# RDD 转换/聚合与`groupBy()`和`reduceByKey()`

在本食谱中，我们探讨了`groupBy()`和`reduceBy()`方法，这些方法允许我们根据键对值进行分组。由于内部洗牌，这是一个昂贵的操作。我们首先更详细地演示`groupby()`，然后介绍`reduceBy()`，以展示编写这些代码时的相似性，同时强调`reduceBy()`操作符的优势。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter3 
```

1.  导入必要的包：

```scala
import breeze.numerics.pow 
import org.apache.spark.sql.SparkSession 
import Array._
```

1.  导入用于设置`log4j`日志级别的包。此步骤是可选的，但我们强烈建议您（根据开发周期适当更改级别）：

```scala
import org.apache.log4j.Logger 
import org.apache.log4j.Level 
```

1.  将日志级别设置为警告和错误，以减少输出。请参阅上一步骤了解包要求。

```scala
Logger.getLogger("org").setLevel(Level.ERROR) ...
```

# 它是如何工作的...

在本例中，我们创建了数字一到十二，并将它们放置在三个分区中。然后，我们继续使用简单的模运算将它们分解为奇数/偶数。`groupBy()`用于将它们聚合为两个奇数/偶数组。这是一个典型的聚合问题，对于 SQL 用户来说应该很熟悉。在本章后面，我们将使用`DataFrame`重新审视此操作，`DataFrame`也利用了 SparkSQL 引擎提供的更好的优化技术。在后面的部分，我们展示了`groupBy()`和`reduceByKey()`的相似性。我们设置了一个字母数组（即，`a`和`b`），然后将它们转换为 RDD。然后，我们根据键（即，唯一的字母 - 在本例中只有两个）进行聚合，并打印每个组的总数。

# 还有更多...

鉴于 Spark 的发展方向，它更倾向于 Dataset/DataFrame 范式而不是低级 RDD 编码，因此必须认真考虑在 RDD 上执行`groupBy()`的原因。虽然有些情况下确实需要此操作，但建议读者重新制定解决方案，以利用 SparkSQL 子系统和称为**Catalyst**的优化器。

Catalyst 优化器在构建优化查询计划时考虑了 Scala 的强大功能，如**模式匹配**和**准引用**。

+   有关 Scala 模式匹配的文档可在[`docs.scala-lang.org/tutorials/tour/pattern-matching.html`](http://docs.scala-lang.org/tutorials/tour/pattern-matching.html)找到

+   有关 Scala 准引用的文档可在[`docs.scala-lang.org/overviews/quasiquotes/intro.html`](http://docs.scala-lang.org/overviews/quasiquotes/intro.html)找到

# 另请参见

RDD 下的`groupBy()`和`reduceByKey()`操作文档：

[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.JavaRDD`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.JavaRDD)

# 使用 zip() API 转换 RDD

在本配方中，我们探讨了`zip()`函数。对于我们这些在 Python 或 Scala 中工作的人来说，`zip()`是一个熟悉的方法，它允许你在应用内联函数之前配对项目。使用 Spark，它可以用来促进成对 RDD 之间的算术运算。从概念上讲，它以这样的方式组合两个 RDD，即一个 RDD 的每个成员与第二个 RDD 中占据相同位置的成员配对（即，它对齐两个 RDD 并从成员中制作配对）。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置

```scala
package spark.ml.cookbook.chapter3 
```

1.  导入必要的包

```scala
    import org.apache.spark.sql.SparkSession 
```

1.  导入用于设置`log4j`日志级别的包。此步骤是可选的，但我们强烈建议这样做（根据开发周期适当更改级别）。

```scala
import org.apache.log4j.Logger 
import org.apache.log4j.Level 
```

1.  将日志级别设置为警告和错误，以减少输出。请参阅上一步骤了解包要求。

```scala
Logger.getLogger("org").setLevel(Level.ERROR) 
Logger.getLogger("akka").setLevel(Level.ERROR) 
```

1.  设置 Spark 上下文和应用程序参数，以便 Spark 能够运行。

```scala
val spark = SparkSession 
.builder 
.master("local[*]") 
.appName("myRDD") 
.config("Spark.sql.warehouse.dir", ".") 
.getOrCreate() 
```

1.  设置示例的数据结构和 RDD。在本例中，我们创建了两个从`Array[]`生成的 RDD，并让 Spark 决定分区数量（即，`parallize()`方法中的第二个参数未设置）。

```scala
val SignalNoise: Array[Double] = Array(0.2,1.2,0.1,0.4,0.3,0.3,0.1,0.3,0.3,0.9,1.8,0.2,3.5,0.5,0.3,0.3,0.2,0.4,0.5,0.9,0.1) 
val SignalStrength: Array[Double] = Array(6.2,1.2,1.2,6.4,5.5,5.3,4.7,2.4,3.2,9.4,1.8,1.2,3.5,5.5,7.7,9.3,1.1,3.1,2.1,4.1,5.1) 
val parSN=spark.sparkContext.parallelize(SignalNoise) // parallelized signal noise RDD 
val parSS=spark.sparkContext.parallelize(SignalStrength)  // parallelized signal strength 
```

1.  我们对 RDD 应用`zip()`函数以演示转换。在示例中，我们取分区 RDD 的范围，并使用模函数将其标记为奇数/偶数。我们使用`zip()`函数将来自两个 RDD（SignalNoiseRDD 和 SignalStrengthRDD）的元素配对，以便我们可以应用`map()`函数并计算它们的比率（噪声与信号比率）。我们可以使用此技术执行几乎所有类型的算术或非算术操作，涉及两个 RDD 的单个成员。

1.  两个 RDD 成员的配对行为类似于元组或行。通过`zip()`创建的配对中的单个成员可以通过其位置访问（例如，`._1`和`._2`）

```scala
val zipRDD= parSN.zip(parSS).map(r => r._1 / r._2).collect() 
println("zipRDD=") 
zipRDD.foreach(println) 
```

运行前面的代码后，您将得到以下输出：

```scala
zipRDD=
0.03225806451612903
1.0
0.08333333333333334
0.0625
0.05454545454545454  
```

# 工作原理...

在本例中，我们首先设置两个数组，分别代表信号噪声和信号强度。它们只是一系列测量数字，我们可以从物联网平台接收这些数字。然后，我们将两个独立的数组配对，使得每个成员看起来像是原始输入的一对（x, y）。接着，我们通过以下代码片段将配对分割并计算噪声与信号的比率：

```scala
val zipRDD= parSN.zip(parSS).map(r => r._1 / r._2) 
```

`zip()`方法有许多涉及分区的变体。开发者应熟悉带有分区的`zip()`方法的变体（例如，`zipPartitions`）。

# 另请参阅

+   RDD 下的`zip()`和`zipPartitions()`操作的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.JavaRDD`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.JavaRDD)找到。

# 使用配对键值 RDD 的连接转换

在本配方中，我们介绍了`KeyValueRDD`对 RDD 及其支持的连接操作，如`join()`、`leftOuterJoin`、`rightOuterJoin()`和`fullOuterJoin()`，作为通过集合操作 API 提供的更传统且更昂贵的集合操作（如`intersection()`、`union()`、`subtraction()`、`distinct()`、`cartesian()`等）的替代方案。

我们将演示`join()`、`leftOuterJoin`、`rightOuterJoin()`和`fullOuterJoin()`，以解释键值对 RDD 的强大功能和灵活性。

```scala
println("Full Joined RDD = ") 
val fullJoinedRDD = keyValueRDD.fullOuterJoin(keyValueCity2RDD) 
fullJoinedRDD.collect().foreach(println(_)) 
```

# 如何操作...

1.  设置示例的数据结构和 RDD：

```scala
val keyValuePairs = List(("north",1),("south",2),("east",3),("west",4)) 
val keyValueCity1 = List(("north","Madison"),("south","Miami"),("east","NYC"),("west","SanJose")) 
val keyValueCity2 = List(("north","Madison"),("west","SanJose"))
```

1.  将列表转换为 RDD：

```scala
val keyValueRDD = spark.sparkContext.parallelize(keyValuePairs) 
val keyValueCity1RDD = spark.sparkContext.parallelize(keyValueCity1) 
val keyValueCity2RDD = spark.sparkContext.parallelize(keyValueCity2) 
```

1.  我们可以访问配对 RDD 中的`键`和`值`。

```scala
val keys=keyValueRDD.keys 
val values=keyValueRDD.values 
```

1.  我们对配对 RDD 应用`mapValues()`函数来演示这一转换。在此示例中，我们使用 map 函数将值提升，为每个元素增加 100。这是一种向数据引入噪声（即抖动）的流行技术。

```scala
val kvMappedRDD = keyValueRDD.mapValues(_+100) 
kvMappedRDD.collect().foreach(println(_)) 
```

运行上述代码后，您将得到以下输出：

```scala
(north,101)
(south,102)
(east,103)
(west,104)

```

1.  我们对 RDD 应用`join()`函数来演示这一转换。我们使用`join()`来连接两个 RDD。我们基于键（即北、南等）连接两个 RDD。

```scala
println("Joined RDD = ") 
val joinedRDD = keyValueRDD.join(keyValueCity1RDD) 
joinedRDD.collect().foreach(println(_)) 
```

运行上述代码后，您将得到以下输出：

```scala
(south,(2,Miami))
(north,(1,Madison))
(west,(4,SanJose))
(east,(3,NYC))
```

1.  我们对 RDD 应用`leftOuterJoin()`函数来演示这一转换。`leftOuterjoin`的作用类似于关系左外连接。Spark 用`None`替换成员资格的缺失，而不是`NULL`，这在关系系统中很常见。

```scala
println("Left Joined RDD = ") 
val leftJoinedRDD = keyValueRDD.leftOuterJoin(keyValueCity2RDD) 
leftJoinedRDD.collect().foreach(println(_)) 
```

运行上述代码后，您将得到以下输出：

```scala
(south,(2,None))
(north,(1,Some(Madison)))
(west,(4,Some(SanJose)))
(east,(3,None))

```

1.  我们将对 RDD 应用`rightOuterJoin()`来演示这一转换。这与关系系统中的右外连接类似。

```scala
println("Right Joined RDD = ") 
val rightJoinedRDD = keyValueRDD.rightOuterJoin(keyValueCity2RDD) 
rightJoinedRDD.collect().foreach(println(_)) 
```

运行上述代码后，您将得到以下输出：

```scala
(north,(Some(1),Madison))
(west,(Some(4),SanJose))  
```

1.  然后，我们对 RDD 应用`fullOuterJoin()`函数来演示这一转换。这与关系系统中的全外连接类似。

```scala
val fullJoinedRDD = keyValueRDD.fullOuterJoin(keyValueCity2RDD) 
fullJoinedRDD.collect().foreach(println(_)) 
```

运行上述代码后，您将得到以下输出：

```scala
Full Joined RDD = 
(south,(Some(2),None))
(north,(Some(1),Some(Madison)))
(west,(Some(4),Some(SanJose)))
(east,(Some(3),None))
```

# 工作原理...

在本食谱中，我们声明了三个列表，代表关系表中可用的典型数据，这些数据可通过连接器导入 Casandra 或 RedShift（为简化本食谱，此处未展示）。我们使用了三个列表中的两个来表示城市名称（即数据表），并将它们与第一个列表连接，该列表代表方向（例如，定义表）。第一步是定义三个配对值的列表。然后我们将它们并行化为键值 RDD，以便我们可以在第一个 RDD（即方向）和其他两个代表城市名称的 RDD 之间执行连接操作。我们对 RDD 应用了 join 函数来演示这一转换。

我们演示了`join()`、`leftOuterJoin`和`rightOuterJoin()`...

# 还有更多...

RDD 下`join()`及其变体的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.JavaRDD`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.JavaRDD)找到。

# 配对键值 RDD 的 reduce 和分组转换

在本食谱中，我们探讨了 reduce 和按 key 分组。`reduceByKey()`和`groupbyKey()`操作在大多数情况下比`reduce()`和`groupBy()`更高效且更受青睐。这些函数提供了便捷的设施，通过减少洗牌来聚合值并按 key 组合它们，这在大型数据集上是一个问题。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含了必要的 JAR 文件。

1.  设置程序将驻留的包位置

```scala
package spark.ml.cookbook.chapter3
```

1.  导入必要的包

```scala
import org.apache.spark.sql.SparkSession 
```

1.  导入用于设置`log4j`日志级别的包。此步骤可选，但我们强烈建议执行（根据开发周期调整级别）。

```scala
import org.apache.log4j.Logger 
import org.apache.log4j.Level 
```

1.  将日志级别设置为警告和错误以减少输出。请参阅前一步骤了解包要求：

```scala
Logger.getLogger("org").setLevel(Level.ERROR) 
Logger.getLogger("akka").setLevel(Level.ERROR)
```

1.  设置 Spark 上下文和应用程序参数，以便 Spark 能够运行。

```scala
val spark = SparkSession 
  .builder 
  .master("local[*]") 
  .appName("myRDD") 
  .config("Spark.sql.warehouse.dir", ".") 
  .getOrCreate() 
```

1.  设置示例所需的数据结构和 RDD：

```scala
val signaltypeRDD = spark.sparkContext.parallelize(List(("Buy",1000),("Sell",500),("Buy",600),("Sell",800))) 
```

1.  我们应用`groupByKey()`以演示转换。在此示例中，我们在分布式环境中将所有买卖信号分组在一起。

```scala
val signaltypeRDD = spark.sparkContext.parallelize(List(("Buy",1000),("Sell",500),("Buy",600),("Sell",800))) 
val groupedRDD = signaltypeRDD.groupByKey() 
groupedRDD.collect().foreach(println(_)) 
```

运行前面的代码，您将得到以下输出：

```scala
Group By Key RDD = 
(Sell, CompactBuffer(500, 800))
(Buy, CompactBuffer(1000, 600))
```

1.  我们对 RDD 对应用`reduceByKey()`函数以演示转换。在此示例中，该函数用于计算买卖信号的总成交量。Scala 符号`(_+_)`简单表示每次添加两个成员并从中产生单个结果。就像`reduce()`一样，我们可以应用任何函数（即简单函数的内联和更复杂情况下的命名函数）。

```scala
println("Reduce By Key RDD = ") 
val reducedRDD = signaltypeRDD.reduceByKey(_+_) 
reducedRDD.collect().foreach(println(_))   
```

运行前面的代码，您将得到以下输出：

```scala
Reduce By Key RDD = 
(Sell,1300)
(Buy,1600)  
```

# 它是如何工作的...

在此示例中，我们声明了一个商品买卖清单及其对应价格（即典型的商业交易）。然后，我们使用 Scala 简写符号`(_+_)`计算总和。最后一步，我们为每个键组（即`Buy`或`Sell`）提供了总计。键值 RDD 是一个强大的结构，可以在减少代码量的同时提供所需的聚合功能，将配对值分组到聚合桶中。`groupByKey()`和`reduceByKey()`函数模拟了相同的聚合功能，而`reduceByKey()`由于在组装最终结果时数据移动较少，因此更高效。

# 另请参阅

有关 RDD 下的`groupByKey()`和`reduceByKey()`操作的文档，请访问[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.JavaRDD`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.api.java.JavaRDD)。

# 从 Scala 数据结构创建 DataFrames

在本节中，我们探讨了`DataFrame` API，它为处理数据提供了比 RDD 更高的抽象层次。该 API 类似于 R 和 Python 数据帧工具（pandas）。

`DataFrame`简化了编码，并允许您使用标准 SQL 检索和操作数据。Spark 保留了关于 DataFrames 的额外信息，这有助于 API 轻松操作框架。每个`DataFrame`都将有一个模式（从数据推断或显式定义），允许我们像查看 SQL 表一样查看框架。SparkSQL 和 DataFrame 的秘诀在于催化优化器将在幕后工作，通过重新排列管道中的调用来优化访问。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动新项目。确保包含必要的 JAR 文件。

1.  设置程序所在包的位置：

```scala
package spark.ml.cookbook.chapter3 
```

1.  设置与 DataFrames 相关的导入以及所需的数据结构，并根据示例需要创建 RDD：

```scala
import org.apache.spark.sql._
```

1.  为`log4j`设置日志级别导入所需的包。此步骤可选，但我们强烈建议执行（根据开发周期调整级别）。

```scala
import org.apache.log4j.Logger 
import org.apache.log4j.Level 
```

1.  将日志级别设置为警告和错误，以减少输出。有关包要求的详细信息，请参阅前一步骤。

```scala
Logger.getLogger("org").setLevel(Level.ERROR) 
Logger.getLogger("akka").setLevel(Level.ERROR)
```

1.  设置 Spark 上下文和应用程序参数，以便 Spark 可以运行。

```scala
val spark = SparkSession 
  .builder 
  .master("local[*]") 
  .appName("myDataFrame") 
  .config("Spark.sql.warehouse.dir", ".") 
  .getOrCreate() 
```

1.  我们设置了两个`List()`对象和一个序列（即`Seq()`）的 Scala 数据结构。然后，我们将`List`结构转换为 RDD，以便转换为`DataFrames`进行后续步骤：

```scala
val signaltypeRDD = spark.sparkContext.parallelize(List(("Buy",1000),("Sell",500),("Buy",600),("Sell",800))) 
val numList = List(1,2,3,4,5,6,7,8,9) 
val numRDD = spark.sparkContext.parallelize(numList) 
val myseq = Seq( ("Sammy","North",113,46.0),("Sumi","South",110,41.0), ("Sunny","East",111,51.0),("Safron","West",113,2.0 )) 
```

1.  我们取一个列表，使用`parallelize()`方法将其转换为 RDD，并使用 RDD 的`toDF()`方法将其转换为 DataFrame。`show()`方法允许我们查看类似于 SQL 表的 DataFrame。

```scala
val numDF = numRDD.toDF("mylist") 
numDF.show 
```

运行上述代码后，您将获得以下输出：

```scala
+------+
|mylist|
+------+
|     1|
|     2|
|     3|
|     4|
|     5|
|     6|
|     7|
|     8|
|     9|
+------+
```

1.  在以下代码片段中，我们取一个通用的 Scala **Seq**（**序列**）数据结构，并使用`createDataFrame()`显式创建一个 DataFrame，同时命名列。

```scala
val df1 = spark.createDataFrame(myseq).toDF("Name","Region","dept","Hours") 
```

1.  在接下来的两个步骤中，我们使用`show()`方法查看内容，然后使用`printSchema()`方法显示基于类型的推断方案。在此示例中，DataFrame 正确识别了 Seq 中的整数和双精度数作为两个数字列的有效类型。

```scala
df1.show() 
df1.printSchema() 
```

运行上述代码后，您将获得以下输出：

```scala
+------+------+----+-----+
|  Name|Region|dept|Hours|
+------+------+----+-----+
| Sammy| North| 113| 46.0|
|  Sumi| South| 110| 41.0|
| Sunny|  East| 111| 51.0|
|Safron|  West| 113|  2.0|
+------+------+----+-----+

root
|-- Name: string (nullable = true)
|-- Region: string (nullable = true)
|-- dept: integer (nullable = false)
|-- Hours: double (nullable = false) 

```

# 工作原理...

在本示例中，我们取两个列表和一个 Seq 数据结构，将它们转换为 DataFrame，并使用`df1.show()`和`df1.printSchema()`显示表的内容和模式。

DataFrames 可以从内部和外部源创建。与 SQL 表类似，DataFrames 具有与之关联的模式，这些模式可以被推断或使用 Scala case 类或`map()`函数显式转换，同时摄取数据。

# 还有更多...

为确保完整性，我们包含了在 Spark 2.0.0 之前使用的`import`语句以运行代码（即，Spark 1.5.2）：

```scala
import org.apache.spark._
import org.apache.spark.rdd.RDD 
import org.apache.spark.sql.SQLContext 
import org.apache.spark.mllib.linalg 
import org.apache.spark.util 
import Array._
import org.apache.spark.sql._
import org.apache.spark.sql.types 
import org.apache.spark.sql.DataFrame 
import org.apache.spark.sql.Row; 
import org.apache.spark.sql.types.{ StructType, StructField, StringType}; 
```

# 另请参阅

DataFrame 文档可在此处找到：[`spark.apache.org/docs/latest/sql-programming-guide.html`](https://spark.apache.org/docs/latest/sql-programming-guide.html)。

如果遇到隐式转换问题，请确保已包含隐式导入语句。

示例代码适用于 Spark 2.0：

```scala
import sqlContext.implicits 
```

# 以编程方式操作 DataFrames，无需 SQL

在本教程中，我们探索如何仅通过代码和方法调用（不使用 SQL）来操作数据框。数据框拥有自己的方法，允许您使用编程方式执行类似 SQL 的操作。我们展示了一些命令，如`select()`、`show()`和`explain()`，以说明数据框本身能够不使用 SQL 进行数据整理和操作。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置。

```scala
package spark.ml.cookbook.chapter3 
```

1.  设置与数据框相关的导入以及所需的数据结构，并根据示例需要创建 RDD。

```scala
import org.apache.spark.sql._
```

1.  导入设置`log4j`日志级别的包。此步骤可选，但我们强烈建议执行（根据开发周期调整级别）。

```scala
import org.apache.log4j.Logger 
import org.apache.log4j.Level 
```

1.  将日志级别设置为警告和错误，以减少输出。请参阅上一步骤了解包要求。

```scala
Logger.getLogger("org").setLevel(Level.ERROR) ...
```

# 工作原理...

在本例中，我们从文本文件加载数据到 RDD，然后使用`.toDF()`API 将其转换为数据框结构。接着，我们使用内置方法如`select()`、`filter()`、`show()`和`explain()`来模拟 SQL 查询，以编程方式探索数据（无需 SQL）。`explain()`命令显示查询计划，这对于消除瓶颈非常有用。

数据框提供了多种数据整理方法。

对于熟悉数据框 API 和 R 语言包（如[`cran.r-project.org`](https://cran.r-project.org)的 dplyr 或旧版本）的用户，我们提供了一个具有丰富方法集的编程 API，让您可以通过 API 进行所有数据整理。

对于更熟悉 SQL 的用户，您可以简单地使用 SQL 来检索和操作数据，就像使用 Squirrel 或 Toad 查询数据库一样。

# 还有更多...

为确保完整性，我们包含了在 Spark 2.0.0 之前运行代码（即 Spark 1.5.2）所需的`import`语句。

```scala
import org.apache.spark._  import org.apache.spark.rdd.RDD import org.apache.spark.sql.SQLContext import org.apache.spark.mllib.linalg._ import org.apache.spark.util._ import Array._ import org.apache.spark.sql._ import org.apache.spark.sql.types._ import org.apache.spark.sql.DataFrame import org.apache.spark.sql.Row; import org.apache.spark.sql.types.{ StructType, StructField, StringType};
```

# 另请参阅

数据框的文档可在[`spark.apache.org/docs/latest/sql-programming-guide.html`](https://spark.apache.org/docs/latest/sql-programming-guide.html)获取。

如果遇到隐式转换问题，请再次检查以确保您已包含隐式`import`语句。

Spark 2.0 的示例`import`语句：

```scala
import sqlContext.implicits._
```

# 从外部源加载数据框并进行设置

在本教程中，我们探讨使用 SQL 进行数据操作。Spark 提供实用且兼容 SQL 的接口，在生产环境中表现出色，我们不仅需要机器学习，还需要使用 SQL 访问现有数据源，以确保与现有 SQL 系统的兼容性和熟悉度。使用 SQL 的数据框在实际环境中实现集成是一个优雅的过程。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter3
```

1.  设置与 DataFrame 相关的导入和所需的数据结构，并根据示例需要创建 RDD：

```scala
import org.apache.spark.sql._
```

1.  导入设置`log4j`日志级别的包。此步骤是可选的，但我们强烈建议这样做（根据开发周期适当更改级别）。

```scala
import org.apache.log4j.Logger
import org.apache.log4j.Level
```

1.  将日志级别设置为警告和`Error`以减少输出。请参阅前面的步骤了解包要求：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)
Logger.getLogger("akka").setLevel(Level.ERROR)
```

1.  设置 Spark 上下文和应用程序参数，以便 Spark 可以运行。

```scala
val spark = SparkSession
 .builder
 .master("local[*]")
 .appName("myDataFrame")
 .config("Spark.sql.warehouse.dir", ".")
 .getOrCreate()
```

1.  我们创建对应于`customer`文件的 DataFrame。在此步骤中，我们首先创建一个 RDD，然后使用`toDF()`将 RDD 转换为 DataFrame 并命名列。

```scala
val customersRDD = spark.sparkContext.textFile("../data/sparkml2/chapter3/customers13.txt") //Customer file 

val custRDD = customersRDD.map {
   line => val cols = line.trim.split(",")
     (cols(0).toInt, cols(1), cols(2), cols(3).toInt) 
} 
val custDF = custRDD.toDF("custid","name","city","age")   
```

客户数据内容参考：

```scala
custDF.show()
```

运行前面的代码，您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/af5a9571-9dc1-4585-aa7e-1bc87e6ccb83.png)

1.  我们创建对应于`product`文件的 DataFrame。在此步骤中，我们首先创建一个 RDD，然后使用`toDF()`将 RDD 转换为 DataFrame 并命名列。

```scala
val productsRDD = spark.sparkContext.textFile("../data/sparkml2/chapter3/products13.txt") //Product file
 val prodRDD = productsRDD.map {
     line => val cols = line.trim.split(",")
       (cols(0).toInt, cols(1), cols(2), cols(3).toDouble) 
}  
```

1.  我们将`prodRDD`转换为 DataFrame：

```scala
val prodDF = prodRDD.toDF("prodid","category","dept","priceAdvertised")
```

1.  使用 SQL select，我们显示表格内容。

产品数据内容：

```scala
prodDF.show()
```

运行前面的代码，您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/d6567c3b-fd23-443a-a849-5029f7a1bb74.png)

1.  我们创建对应于`sales`文件的 DataFrame。在此步骤中，我们首先创建一个 RDD，然后使用`toDF()`将 RDD 转换为 DataFrame 并命名列。

```scala
val salesRDD = spark.sparkContext.textFile("../data/sparkml2/chapter3/sales13.txt") *//Sales file* val saleRDD = salesRDD.map {
     line => val cols = line.trim.split(",")
       (cols(0).toInt, cols(1).toInt, cols(2).toDouble)
}
```

1.  我们将`saleRDD`转换为 DataFrame：

```scala
val saleDF = saleRDD.toDF("prodid", "custid", "priceSold")  
```

1.  我们使用 SQL select 来显示表格。

销售数据内容：

```scala
saleDF.show()
```

运行前面的代码，您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/e7cfde8b-1d1c-4182-a185-a32bde43e9f7.png)

1.  我们打印客户、产品和销售 DataFrame 的架构，以验证列定义和类型转换后的架构：

```scala
custDF.printSchema()
productDF.printSchema()
salesDF. printSchema()
```

运行前面的代码，您将得到以下输出：

```scala
root
 |-- custid: integer (nullable = false)
 |-- name: string (nullable = true)
 |-- city: string (nullable = true)
 |-- age: integer (nullable = false)
root
 |-- prodid: integer (nullable = false)
 |-- category: string (nullable = true)
 |-- dept: string (nullable = true)
 |-- priceAdvertised: double (nullable = false)
root
 |-- prodid: integer (nullable = false)
 |-- custid: integer (nullable = false)
 |-- priceSold: double (nullable = false)
```

# 它是如何工作的...

在此示例中，我们首先将数据加载到 RDD 中，然后使用`toDF()`方法将其转换为 DataFrame。DataFrame 非常擅长推断类型，但有时需要手动干预。我们在创建 RDD 后使用`map()`函数（应用惰性初始化范式）来处理数据，无论是通过类型转换还是调用更复杂的用户定义函数（在`map()`方法中引用）来进行转换或数据整理。最后，我们继续使用`show()`和`printSchema()`检查三个 DataFrame 的架构。

# 还有更多...

为了确保完整性，我们包含了在 Spark 2.0.0 之前用于运行代码的`import`语句（即，Spark 1.5.2）：

```scala
import org.apache.spark._
 import org.apache.spark.rdd.RDD
 import org.apache.spark.sql.SQLContext
 import org.apache.spark.mllib.linalg._
 import org.apache.spark.util._
 import Array._
 import org.apache.spark.sql._
 import org.apache.spark.sql.types._
 import org.apache.spark.sql.DataFrame
 import org.apache.spark.sql.Row;
 import org.apache.spark.sql.types.{ StructType, StructField, StringType};
```

# 另请参阅

DataFrame 的文档可在[`spark.apache.org/docs/latest/sql-programming-guide.html`](https://spark.apache.org/docs/latest/sql-programming-guide.html)找到。

如果遇到隐式转换问题，请再次检查以确保您已包含 implicits `import`语句。

Spark 1.5.2 的示例`import`语句：

```scala
 import sqlContext.implicits._
```

# 使用标准 SQL 语言与 DataFrames - SparkSQL

在本食谱中，我们展示了如何使用 DataFrame 的 SQL 功能执行基本的 CRUD 操作，但没有任何限制您使用 Spark 提供的 SQL 接口达到所需的任何复杂程度（即 DML）。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置

```scala
package spark.ml.cookbook.chapter3
```

1.  设置与 DataFrames 相关的导入以及所需的数据结构，并根据示例需要创建 RDDs

```scala
import org.apache.spark.sql._
```

1.  导入用于设置`log4j`日志级别的包。此步骤是可选的，但我们强烈建议您根据开发周期的不同阶段适当调整级别。

```scala
import org.apache.log4j.Logger import org.apache.log4j.Level
```

1.  将日志级别设置为警告和`ERROR`以减少输出。请参阅上一步骤了解包要求。

```scala
Logger.getLogger( ...
```

# 工作原理...

使用 SQL 的基本 DataFrame 工作流程是首先通过内部 Scala 数据结构或外部数据源填充 DataFrame，然后使用`createOrReplaceTempView()`调用将 DataFrame 注册为类似 SQL 的工件。

使用 DataFrames 时，您可以利用 Spark 存储的额外元数据（无论是 API 还是 SQL 方法），这可以在编码和执行期间为您带来好处。

虽然 RDD 仍然是核心 Spark 的主力，但趋势是向 DataFrame 方法发展，该方法已成功展示了其在 Python/Pandas 或 R 等语言中的能力。

# 还有更多...

将 DataFrame 注册为表的方式已发生变化。请参考此内容：

+   对于 Spark 2.0.0 之前的版本：`registerTempTable()`

+   对于 Spark 2.0.0 及更早版本：`createOrReplaceTempView()`

在 Spark 2.0.0 之前，将 DataFrame 注册为类似 SQL 表的工件：

在我们能够使用 DataFrame 通过 SQL 进行查询之前，我们必须将 DataFrame 注册为临时表，以便 SQL 语句可以引用它而无需任何 Scala/Spark 语法。这一步骤可能会让许多初学者感到困惑，因为我们并没有创建任何表（临时或永久），但调用`registerTempTable()`在 SQL 领域创建了一个名称，SQL 语句可以引用它而无需额外的 UDF 或无需任何特定领域的查询语言。

+   注册...

# 另请参阅

数据框（DataFrame）的文档可在[此处](https://spark.apache.org/docs/latest/sql-programming-guide.html)获取。

如果遇到隐式转换问题，请再次检查以确保您已包含 implicits `import`语句。

Spark 1.5.2 的示例`import`语句

```scala
 import sqlContext.implicits._
```

DataFrame 是一个广泛的子系统，值得用一整本书来介绍。它使 SQL 程序员能够大规模地进行复杂的数据操作。

# 使用 Scala 序列与数据集 API 协同工作

在本示例中，我们探讨了新的数据集以及它如何与 Scala 数据结构*seq*协同工作。我们经常看到 LabelPoint 数据结构与 ML 库一起使用，以及与数据集配合良好的 Scala 序列（即 seq 数据结构）之间的关系。

数据集正被定位为未来统一的 API。值得注意的是，DataFrame 仍然可用，作为`Dataset[Row]`的别名。我们已经通过 DataFrame 的示例广泛地介绍了 SQL 示例，因此我们将重点放在数据集的其他变体上。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置

```scala
package spark.ml.cookbook.chapter3
```

1.  导入必要的包以获取 Spark 会话访问集群，并导入`Log4j.Logger`以减少 Spark 产生的输出量。

```scala
import org.apache.log4j.{Level, Logger}
import org.apache.spark.sql.SparkSession
```

1.  定义一个 Scala `case class`来建模处理数据，`Car`类将代表电动和混合动力汽车。

```scala
case class Car(make: String, model: String, price: Double,
style: String, kind: String)
```

1.  让我们创建一个 Scala 序列，并用电动和混合动力汽车填充它。

```scala
val *carData* =
*Seq*(
*Car*("Tesla", "Model S", 71000.0, "sedan","electric"),
*Car*("Audi", "A3 E-Tron", 37900.0, "luxury","hybrid"),
*Car*("BMW", "330e", 43700.0, "sedan","hybrid"),
*Car*("BMW", "i3", 43300.0, "sedan","electric"),
*Car*("BMW", "i8", 137000.0, "coupe","hybrid"),
*Car*("BMW", "X5 xdrive40e", 64000.0, "suv","hybrid"),
*Car*("Chevy", "Spark EV", 26000.0, "coupe","electric"),
*Car*("Chevy", "Volt", 34000.0, "sedan","electric"),
*Car*("Fiat", "500e", 32600.0, "coupe","electric"),
*Car*("Ford", "C-Max Energi", 32600.0, "wagon/van","hybrid"),
*Car*("Ford", "Focus Electric", 29200.0, "sedan","electric"),
*Car*("Ford", "Fusion Energi", 33900.0, "sedan","electric"),
*Car*("Hyundai", "Sonata", 35400.0, "sedan","hybrid"),
*Car*("Kia", "Soul EV", 34500.0, "sedan","electric"),
*Car*("Mercedes", "B-Class", 42400.0, "sedan","electric"),
*Car*("Mercedes", "C350", 46400.0, "sedan","hybrid"),
*Car*("Mercedes", "GLE500e", 67000.0, "suv","hybrid"),
*Car*("Mitsubishi", "i-MiEV", 23800.0, "sedan","electric"),
*Car*("Nissan", "LEAF", 29000.0, "sedan","electric"),
*Car*("Porsche", "Cayenne", 78000.0, "suv","hybrid"),
*Car*("Porsche", "Panamera S", 93000.0, "sedan","hybrid"),
*Car*("Tesla", "Model X", 80000.0, "suv","electric"),
*Car*("Tesla", "Model 3", 35000.0, "sedan","electric"),
*Car*("Volvo", "XC90 T8", 69000.0, "suv","hybrid"),
*Car*("Cadillac", "ELR", 76000.0, "coupe","hybrid")
)

```

1.  将输出级别配置为`ERROR`以减少 Spark 的日志输出。

```scala
   Logger.getLogger("org").setLevel(Level.ERROR)
   Logger.getLogger("akka").setLevel(Level.ERROR)
```

1.  创建一个 SparkSession，以访问 Spark 集群，包括底层会话对象属性和功能。

```scala
val spark = SparkSession
.builder
.master("local[*]")
.appName("mydatasetseq")
.config("Spark.sql.warehouse.dir", ".")
.getOrCreate()

```

1.  导入 Spark 隐式，从而仅通过导入添加行为。

```scala
import spark.implicits._
```

1.  接下来，我们将利用 Spark 会话的`createDataset()`方法从汽车数据序列创建一个数据集。

```scala
val cars = spark.createDataset(MyDatasetData.carData) 
// carData is put in a separate scala object MyDatasetData
```

1.  让我们打印出结果，以确认我们的方法调用通过调用 show 方法将序列转换为 Spark 数据集。

```scala
infecars.show(false)
+----------+--------------+--------+---------+--------+
|make |model |price |style |kind |
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/a252a4cf-d0d2-4e9b-ba36-ebe5a76de2f0.png)

1.  打印出数据集的隐含列名。我们现在可以使用类属性名称作为列名。

```scala
cars.columns.foreach(println)
make
model
price
style
kind
```

1.  让我们展示自动生成的模式，并验证推断的数据类型。

```scala
println(cars.schema)
StructType(StructField(make,StringType,true), StructField(model,StringType,true), StructField(price,DoubleType,false), StructField(style,StringType,true), StructField(kind,StringType,true))
```

1.  最后，我们将根据价格对数据集进行过滤，参考`Car`类属性价格作为列，并展示结果。

```scala
cars.filter(cars("price") > 50000.00).show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/99ffee16-3167-451a-8586-308cf4d4321f.png)

1.  我们通过停止 Spark 会话来关闭程序。

```scala
spark.stop()
```

# 工作原理...

在本示例中，我们介绍了 Spark 的数据集功能，该功能首次出现在 Spark 1.6 中，并在后续版本中得到进一步完善。首先，我们借助 Spark 会话的`createDataset()`方法从 Scala 序列创建了一个数据集实例。接下来，我们打印出有关生成数据集的元信息，以确认创建过程如预期进行。最后，我们使用 Spark SQL 片段根据价格列过滤数据集，筛选出价格大于$50,000.00 的记录，并展示最终执行结果。

# 还有更多...

数据集有一个名为[DataFrame](https://spark.apache.org/docs/2.0.0/api/scala/org/apache/spark/sql/package.html#DataFrame=org.apache.spark.sql.Dataset%5Borg.apache.spark.sql.Row%5D)的视图，它是[行](https://spark.apache.org/docs/2.0.0/api/scala/org/apache/spark/sql/Row.html)的未类型化数据集。数据集仍然保留了 RDD 的所有转换能力，如`filter()`、`map()`、`flatMap()`等。这就是为什么如果我们使用 RDD 编程 Spark，我们会发现数据集易于使用的原因之一。

# 另请参阅

+   数据集文档可在[此处](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset)找到。

+   KeyValue 分组数据集文档可在[此处](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.KeyValueGroupedDataset)找到。

+   关系分组数据集文档可在[此处](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.RelationalGroupedDataset)找到。

# 从 RDD 创建和使用数据集，以及反向操作

在本食谱中，我们探讨了如何使用 RDD 与 Dataset 交互，以构建多阶段机器学习管道。尽管 Dataset（概念上被认为是具有强类型安全的 RDD）是未来的方向，但您仍然需要能够与其他机器学习算法或返回/操作 RDD 的代码进行交互，无论是出于遗留还是编码原因。在本食谱中，我们还探讨了如何创建和从 Dataset 转换为 RDD 以及反向操作。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter3
```

1.  为 Spark 会话导入必要的包以访问集群，并使用`Log4j.Logger`来减少 Spark 产生的输出量。

```scala
import org.apache.log4j.{Level, Logger}import org.apache.spark.sql.SparkSession
```

1.  定义一个 Scala 样例类来模拟处理数据。

```scala
case class Car(make: String, model: String, price: Double,style: String, kind: String)
```

1.  让我们创建一个 Scala 序列，并用电动和混合动力汽车填充它。

```scala
val carData =Seq(Car("Tesla", "Model S", 71000.0, "sedan","electric"), ...
```

# 工作原理...

在本节中，我们将 RDD 转换为 Dataset，最终又转换回 RDD。我们从一个 Scala 序列开始，将其转换为 RDD。创建 RDD 后，调用 Spark 会话的`createDataset()`方法，将 RDD 作为参数传递，并接收作为结果的 Dataset。

接下来，数据集按制造商列分组，统计各种汽车制造商的存在情况。下一步涉及对特斯拉制造商的数据集进行过滤，并将结果转换回 RDD。最后，我们通过 RDD 的`foreach()`方法显示了最终的 RDD。

# 还有更多...

Spark 中的数据集源文件仅包含约 2500+行 Scala 代码。这是一段非常优秀的代码，可以在 Apache 许可证下进行专业化利用。我们列出了以下 URL，并鼓励您至少浏览该文件，了解在使用数据集时缓冲是如何发挥作用的。

数据集的源代码托管在 GitHub 上，地址为[`github.com/apache/spark/blob/master/sql/core/src/main/scala/org/apache/spark/sql/Dataset.scala`](https://github.com/apache/spark/blob/master/sql/core/src/main/scala/org/apache/spark/sql/Dataset.scala)。

# 参见

+   数据集的文档可以在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset)找到

+   键值分组的数据集可以在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.KeyValueGroupedDataset`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.KeyValueGroupedDataset)找到

+   关系分组的数据集可以在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.RelationalGroupedDataset`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.RelationalGroupedDataset)找到

# 结合使用数据集 API 和 SQL 处理 JSON

在本节中，我们探讨如何使用 JSON 与数据集。在过去的 5 年中，JSON 格式迅速成为数据互操作性的实际标准。

我们探讨数据集如何使用 JSON 并执行 API 命令，如`select()`。然后，我们通过创建一个视图（即`createOrReplaceTempView()`）并执行 SQL 查询来演示如何使用 API 和 SQL 轻松查询 JSON 文件。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  我们将使用一个名为`cars.json`的 JSON 数据文件，该文件是为这个示例创建的：

```scala
{"make": "Telsa", "model": "Model S", "price": 71000.00, "style": "sedan", "kind": "electric"}
{"make": "Audi", "model": "A3 E-Tron", "price": 37900.00, "style": "luxury", "kind": "hybrid"}
{"make": "BMW", "model": "330e", "price": 43700.00, "style": "sedan", "kind": "hybrid"}
```

1.  设置程序将驻留的包位置

```scala
package spark.ml.cookbook.chapter3
```

1.  为 Spark 会话导入必要的包以访问集群，并使用`Log4j.Logger`来减少 Spark 产生的输出量。

```scala
import org.apache.log4j.{Level, Logger}
import org.apache.spark.sql.SparkSession
```

1.  定义一个 Scala`case class`来建模处理数据。

```scala
case class Car(make: String, model: String, price: Double,
style: String, kind: String)
```

1.  将输出级别设置为`ERROR`，以减少 Spark 的日志输出。

```scala
Logger.getLogger("org").setLevel(Level.ERROR)
Logger.getLogger("akka").setLevel(Level.ERROR)
```

1.  初始化一个 Spark 会话，创建访问 Spark 集群的入口点。

```scala
val spark = SparkSession
.builder
.master("local[*]")
.appName("mydatasmydatasetjsonetrdd")
.config("Spark.sql.warehouse.dir", ".")
.getOrCreate()
```

1.  导入 Spark 隐式，从而仅通过导入添加行为。

```scala
import spark.implicits._
```

1.  现在，我们将 JSON 数据文件加载到内存中，并指定类类型为`Car`。

```scala
val cars = spark.read.json("../data/sparkml2/chapter3/cars.json").as[Car]
```

1.  让我们打印出我们生成的`Car`类型数据集中的数据。

```scala
cars.show(false)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/1aa57574-0e2f-40e9-9892-35f18eaf2b8e.png)

1.  接下来，我们将显示数据集的列名，以验证汽车的 JSON 属性名称是否已正确处理。

```scala
cars.columns.foreach(println)
make
model
price
style
kind
```

1.  让我们查看自动生成的模式并验证推断的数据类型。

```scala
println(cars.schema)
StructType(StructField(make,StringType,true), StructField(model,StringType,true), StructField(price,DoubleType,false), StructField(style,StringType,true), StructField(kind,StringType,true))
```

1.  在这一步中，我们将选择数据集的`make`列，通过应用`distinct`方法去除重复项，并展示结果。

```scala
cars.select("make").distinct().show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/668b4ac1-6bf1-4b53-9db4-8770ce230f53.png)

1.  接下来，在 cars 数据集上创建一个视图，以便我们可以对数据集执行一个字面上的 Spark SQL 查询字符串。

```scala
cars.createOrReplaceTempView("cars")
```

1.  最后，我们执行一个 Spark SQL 查询，筛选数据集中的电动汽车，并仅返回定义的三个列。

```scala
spark.sql("select make, model, kind from cars where kind = 'electric'").show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/ca582e1b-da30-46c7-8371-822fa08704f7.png)

1.  我们通过停止 Spark 会话来结束程序。

```scala
spark.stop() 
```

# 工作原理...

使用 Spark 读取**JavaScript 对象表示法**(**JSON**)数据文件并将其转换为数据集非常简单。JSON 在过去几年中已成为广泛使用的数据格式，Spark 对这种格式的支持非常充分。

在第一部分中，我们展示了通过 Spark 会话内置的 JSON 解析功能将 JSON 加载到数据集的方法。您应该注意 Spark 的内置功能，它将 JSON 数据转换为 car 案例类。

在第二部分中，我们展示了如何将 Spark SQL 应用于数据集，以将所述数据整理成理想状态。我们利用数据集的 select 方法检索`make`列，并应用`distinct`方法去除...

# 还有更多...

要全面理解和掌握数据集 API，务必理解`Row`和`Encoder`的概念。

数据集遵循*惰性执行*范式，意味着执行仅在 Spark 中调用操作时发生。当我们执行一个操作时，Catalyst 查询优化器生成一个逻辑计划，并为并行分布式环境中的优化执行生成物理计划。请参阅引言中的图表了解所有详细步骤。

`Row`的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset)找到。

`Encoder`的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Encoder`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Encoder)找到。

# 参见

+   数据集的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset)找到。

+   KeyValue 分组数据集的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.KeyValueGroupedDataset`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.KeyValueGroupedDataset)找到。

+   关系分组数据集的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.RelationalGroupedDataset`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.RelationalGroupedDataset)找到。

再次确保下载并探索来自 GitHub 的 Dataset 源文件，该文件约有 2500+行。探索 Spark 源代码是学习 Scala、Scala 注解以及 Spark 2.0 本身高级编程的最佳方式。

对于 Spark 2.0 之前的用户值得注意：

+   SparkSession 是单一入口...

# 使用 Dataset API 进行领域对象的函数式编程

在本教程中，我们探讨了如何使用 Dataset 进行函数式编程。我们利用 Dataset 和函数式编程将汽车（领域对象）按其车型进行分类。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  使用包指令提供正确的路径

```scala
package spark.ml.cookbook.chapter3
```

1.  导入必要的包以获取 Spark 上下文对集群的访问权限，并使用`Log4j.Logger`减少 Spark 产生的输出量。

```scala
import org.apache.log4j.{Level, Logger}import org.apache.spark.sql.{Dataset, SparkSession}import spark.ml.cookbook.{Car, mydatasetdata}import scala.collection.mutableimport scala.collection.mutable.ListBufferimport org.apache.log4j.{Level, Logger}import org.apache.spark.sql.SparkSession
```

1.  定义一个 Scala 案例类来包含我们处理的数据，我们的汽车类将代表电动和...

# 工作原理...

在此示例中，我们使用 Scala 序列数据结构来存储原始数据，即一系列汽车及其属性。通过调用`createDataset()`，我们创建了一个 DataSet 并填充了它。接着，我们使用'make'属性配合`groupBy`和`mapGroups()`，以函数式范式列出按车型分类的汽车。在 DataSet 出现之前，使用领域对象进行这种形式的函数式编程并非不可能（例如，使用 RDD 的案例类或 DataFrame 的 UDF），但 DataSet 结构使得这一过程变得简单且自然。

# 还有更多...

确保在所有 DataSet 编码中包含`implicits`声明：

```scala
import spark.implicits._
```

# 参见

Dataset 的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset)访问。
