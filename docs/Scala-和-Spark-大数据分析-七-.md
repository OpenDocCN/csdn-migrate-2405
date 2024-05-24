# Scala 和 Spark 大数据分析（七）

> 原文：[`zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A`](https://zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：是时候整理一下了-用 Spark MLlib 对数据进行聚类

*"如果你拿一个星系并试图让它变得更大，它就会成为一群星系，而不是一个星系。如果你试图让它变得比那小，它似乎会自己爆炸"*

- Jeremiah P. Ostriker

在本章中，我们将深入研究机器学习，并找出如何利用它来对无监督观测数据集中属于某一组或类的记录进行聚类。简而言之，本章将涵盖以下主题：

+   无监督学习

+   聚类技术

+   层次聚类（HC）

+   基于质心的聚类（CC）

+   基于分布的聚类（DC）

+   确定聚类数量

+   聚类算法之间的比较分析

+   在计算集群上提交作业

# 无监督学习

在本节中，我们将用适当的示例简要介绍无监督机器学习技术。让我们从一个实际例子开始讨论。假设你在硬盘上有一个拥挤而庞大的文件夹里有大量非盗版-完全合法的 mp3。现在，如果你可以建立一个预测模型，帮助自动将相似的歌曲分组并组织到你喜欢的类别中，比如乡村音乐、说唱、摇滚等。这种将项目分配到一个组中的行为，例如将 mp3 添加到相应的播放列表，是一种无监督的方式。在之前的章节中，我们假设你有一个正确标记数据的训练数据集。不幸的是，在现实世界中收集数据时，我们并不总是有这种奢侈。例如，假设我们想将大量音乐分成有趣的播放列表。如果我们没有直接访问它们的元数据，我们如何可能将歌曲分组在一起呢？一种可能的方法可能是混合各种机器学习技术，但聚类通常是解决方案的核心。

简而言之，在无监督机器学习问题中，训练数据集的正确类别不可用或未知。因此，类别必须从结构化或非结构化数据集中推导出来，如*图 1*所示。这基本上意味着这种算法的目标是以某种结构化的方式预处理数据。换句话说，无监督学习算法的主要目标是探索未标记的输入数据中的未知/隐藏模式。然而，无监督学习也包括其他技术，以探索性的方式解释数据的关键特征，以找到隐藏的模式。为了克服这一挑战，聚类技术被广泛使用，以无监督的方式基于某些相似性度量对未标记的数据点进行分组。

有关无监督算法工作原理的深入理论知识，请参考以下三本书：*Bousquet*，*O.；von Luxburg*，*U.；Raetsch*，*G.，编辑（2004）。*机器学习的高级讲座*。*Springer-Verlag*。ISBN 978-3540231226。或者*Duda*，*Richard O.*；*Hart*，*Peter E.*；*Stork*，*David G*。（2001）。*无监督学习和聚类*。*模式分类*（第 2 版）。*Wiley*。ISBN 0-471-05669-3 和*Jordan*，*Michael I.*；*Bishop*，*Christopher M*。（2004）*神经网络*。在*Allen B. Tucker* *计算机科学手册，第二版*（第 VII 部分：智能系统）。*博卡拉顿*，FL：查普曼和霍尔/ CRC 出版社。ISBN 1-58488-360-X。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00263.jpeg)**图 1：**使用 Spark 进行无监督学习

# 无监督学习示例

在聚类任务中，算法通过分析输入示例之间的相似性将相关特征分组到类别中，其中相似的特征被聚类并用圆圈标记。聚类的用途包括但不限于以下内容：搜索结果分组，如客户分组，用于发现可疑模式的异常检测，用于在文本中找到有用模式的文本分类，用于找到连贯群体的社交网络分析，用于将相关计算机放在一起的数据中心计算集群，用于基于相似特征识别社区的房地产数据分析。我们将展示一个基于 Spark MLlib 的解决方案，用于最后一种用例。

# 聚类技术

在本节中，我们将讨论聚类技术以及相关挑战和适当的示例。还将提供对层次聚类、基于质心的聚类和基于分布的聚类的简要概述。

# 无监督学习和聚类

聚类分析是关于将数据样本或数据点分成相应的同类或簇的过程。因此，聚类的一个简单定义可以被认为是将对象组织成成员在某种方式上相似的组。

因此，*簇*是一组对象，它们在彼此之间是*相似*的，并且与属于其他簇的对象是*不相似*的。如*图 2*所示，如果给定一组对象，聚类算法会根据相似性将这些对象放入一组中。例如，K 均值这样的聚类算法已经找到了数据点组的质心。然而，为了使聚类准确和有效，算法评估了每个点与簇的质心之间的距离。最终，聚类的目标是确定一组未标记数据中的内在分组。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00059.jpeg)**图 2：** 聚类原始数据

Spark 支持许多聚类算法，如**K 均值**，**高斯混合**，**幂迭代聚类**（**PIC**），**潜在狄利克雷分配**（**LDA**），**二分 K 均值**和**流式 K 均值**。LDA 用于文档分类和文本挖掘中常用的聚类。PIC 用于将具有成对相似性的图的顶点聚类为边属性。然而，为了使本章的目标更清晰和集中，我们将限制我们的讨论在 K 均值，二分 K 均值和高斯混合算法上。

# 层次聚类

层次聚类技术基于一个基本思想，即对象或特征与附近的对象比与远处的对象更相关。二分 K 均值就是这样一种层次聚类算法的例子，它根据它们的相应距离连接数据对象以形成簇。

在层次聚类技术中，一个簇可以通过连接簇的部分所需的最大距离来简单描述。因此，不同的簇将在不同的距离下形成。从图形上看，这些簇可以使用树状图来表示。有趣的是，常见的名字层次聚类来源于树状图的概念。

# 基于质心的聚类

在基于质心的聚类技术中，聚类由一个中心向量表示。然而，这个向量本身不一定是数据点的成员。在这种类型的学习中，必须在训练模型之前提供一些可能的聚类。K 均值是这种学习类型的一个非常著名的例子，如果将聚类的数量设置为一个固定的整数 K，K 均值算法提供了一个正式的定义作为一个优化问题，这是一个单独的问题，需要解决以找到 K 个聚类中心并将数据对象分配给最近的聚类中心。简而言之，这是一个优化问题，其目标是最小化聚类的平方距离。

# 基于分布的聚类

基于分布的聚类算法基于提供更方便的方式将相关数据对象聚类到相同分布的统计分布模型。尽管这些算法的理论基础非常健全，但它们大多数时候会受到过拟合的影响。然而，这种限制可以通过对模型复杂性加以约束来克服。

# 基于质心的聚类（CC）

在本节中，我们将讨论基于质心的聚类技术及其计算挑战。我们将展示使用 Spark MLlib 的 K 均值的示例，以更好地理解基于质心的聚类。

# CC 算法中的挑战

如前所述，在像 K 均值这样的基于质心的聚类算法中，设置聚类数量 K 的最佳值是一个优化问题。这个问题可以被描述为 NP-hard（即非确定性多项式时间难题），具有高算法复杂性，因此常见的方法是尝试只获得一个近似解。因此，解决这些优化问题会带来额外的负担，因此也会带来非平凡的缺点。此外，K 均值算法期望每个聚类的大小大致相似。换句话说，每个聚类中的数据点必须是均匀的，以获得更好的聚类性能。

这个算法的另一个主要缺点是，这个算法试图优化聚类中心，而不是聚类边界，这经常会导致不恰当地切割聚类之间的边界。然而，有时我们可以利用视觉检查的优势，这在超平面或多维数据上通常是不可用的。尽管如此，如何找到 K 的最佳值的完整部分将在本章后面讨论。

# K 均值算法是如何工作的？

假设我们有*n*个数据点*x[i]*，*i=1...n*，需要被分成*k*个聚类。现在目标是为每个数据点分配一个聚类。K 均值的目标是找到最小化数据点到聚类的距离的聚类位置*μ[i],i=1...k*。从数学上讲，K 均值算法试图通过解决以下方程来实现目标，即一个优化问题：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00320.jpeg)

在上述方程中，*c[i]*是分配给聚类*i*的数据点集合，*d(x,μ[i]) =||x−μ[i]||²[2]*是要计算的欧几里德距离（我们将很快解释为什么我们应该使用这个距离测量）。因此，我们可以理解，使用 K 均值进行整体聚类操作不是一个平凡的问题，而是一个 NP-hard 的优化问题。这也意味着 K 均值算法不仅试图找到全局最小值，而且经常陷入不同的解决方案。

现在，让我们看看在将数据提供给 K 均值模型之前，我们如何制定算法。首先，我们需要事先决定试探性聚类的数量*k*。然后，通常情况下，您需要按照以下步骤进行：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00367.jpeg)

这里的*|c|*是*c*中的元素数量。

使用 K-means 算法进行聚类的过程是通过将所有坐标初始化为质心开始的。在算法的每一次迭代中，根据某种距离度量，通常是*欧氏距离*，将每个点分配给其最近的质心。

**距离计算：**请注意，还有其他计算距离的方法，例如：

*切比雪夫距离*可用于仅考虑最显著维度的距离测量。

*Hamming 距离*算法可以识别两个字符串之间的差异。另一方面，为了使距离度量尺度无关，可以使用*马哈拉诺比斯距离*来规范化协方差矩阵。*曼哈顿距离*用于仅考虑轴对齐方向的距离。*闵可夫斯基距离*算法用于计算欧氏距离、曼哈顿距离和切比雪夫距离。*Haversine 距离*用于测量球面上两点之间的大圆距离，即经度和纬度。

考虑到这些距离测量算法，很明显，欧氏距离算法将是解决 K-means 算法中距离计算目的最合适的方法。然后，质心被更新为该迭代中分配给它的所有点的中心。这一过程重复，直到中心发生最小变化。简而言之，K-means 算法是一个迭代算法，分为两个步骤：

+   **聚类分配步骤**：K-means 遍历数据集中的每个 m 个数据点，将其分配给由 k 个质心中最接近的质心表示的聚类。对于每个点，然后计算到每个质心的距离，简单地选择最近的一个。

+   **更新步骤**：对于每个聚类，计算所有点的平均值作为新的聚类中心。从上一步，我们有一组分配给一个聚类的点。现在，对于每个这样的集合，我们计算一个平均值，宣布它为聚类的新中心。

# 使用 Spark MLlib 的 K-means 聚类的示例

为了进一步演示聚类示例，我们将使用从[`course1.winona.edu/bdeppa/Stat%20425/Datasets.html`](http://course1.winona.edu/bdeppa/Stat%20425/Datasets.html)下载的*Saratoga NY Homes*数据集作为使用 Spark MLlib 的无监督学习技术。该数据集包含纽约市郊区房屋的几个特征。例如，价格、地块大小、水景、年龄、土地价值、新建、中央空调、燃料类型、供暖类型、下水道类型、居住面积、大学百分比、卧室、壁炉、浴室和房间数。然而，以下表格中只显示了一些特征：

| **价格** | **地块大小** | **水景** | **年龄** | **土地价值** | **房间数** |
| --- | --- | --- | --- | --- | --- |
| 132,500 | 0.09 | 0 | 42 | 5,000 | 5 |
| 181,115 | 0.92 | 0 | 0 | 22,300 | 6 |
| 109,000 | 0.19 | 0 | 133 | 7,300 | 8 |
| 155,000 | 0.41 | 0 | 13 | 18,700 | 5 |
| 86,060 | 0.11 | 0 | 0 | 15,000 | 3 |
| 120,000 | 0.68 | 0 | 31 | 14,000 | 8 |
| 153,000 | 0.4 | 0 | 33 | 23,300 | 8 |
| 170,000 | 1.21 | 0 | 23 | 146,000 | 9 |
| 90,000 | 0.83 | 0 | 36 | 222,000 | 8 |
| 122,900 | 1.94 | 0 | 4 | 212,000 | 6 |
| 325,000 | 2.29 | 0 | 123 | 126,000 | 12 |

**表 1：**Saratoga NY Homes 数据集的样本数据

这里的聚类技术的目标是基于城市中每栋房屋的特征进行探索性分析，以找到可能的邻近区域。在执行特征提取之前，我们需要加载和解析 Saratoga NY Homes 数据集。这一步还包括加载包和相关依赖项，将数据集读取为 RDD，模型训练，预测，收集本地解析数据以及聚类比较。

**步骤 1**。导入相关的包：

```scala
package com.chapter13.Clustering
import org.apache.spark.{SparkConf, SparkContext}
import org.apache.spark.mllib.clustering.{KMeans, KMeansModel}
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark._
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.functions._
import org.apache.spark.sql.types._
import org.apache.spark.sql._
import org.apache.spark.sql.SQLContext

```

**步骤 2.创建一个 Spark 会话 - 入口点** - 在这里，我们首先通过设置应用程序名称和主 URL 来设置 Spark 配置。为了简单起见，它是独立的，使用您机器上的所有核心：

```scala
val spark = SparkSession
                 .builder
                 .master("local[*]")
                 .config("spark.sql.warehouse.dir", "E:/Exp/")
                 .appName("KMeans")
                 .getOrCreate()

```

**步骤 3.加载和解析数据集** - 从数据集中读取、解析和创建 RDD 如下：

```scala
//Start parsing the dataset
val start = System.currentTimeMillis()
val dataPath = "data/Saratoga NY Homes.txt"
//val dataPath = args(0)
val landDF = parseRDD(spark.sparkContext.textFile(dataPath))
                                 .map(parseLand).toDF().cache()
landDF.show()

```

请注意，为了使前面的代码起作用，您应该导入以下包：

```scala
import spark.sqlContext.implicits._

```

您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00339.jpeg)**图 3：** Saratoga NY Homes 数据集的快照

以下是`parseLand`方法，用于从`Double`数组创建`Land`类如下：

```scala
// function to create a  Land class from an Array of Double
def parseLand(line: Array[Double]): Land = {
  Land(line(0), line(1), line(2), line(3), line(4), line(5),
   line(6), line(7), line(8), line(9), line(10),
   line(11), line(12), line(13), line(14), line(15)
  )
}

```

读取所有特征作为双精度的`Land`类如下：

```scala
case class Land(
  Price: Double, LotSize: Double, Waterfront: Double, Age: Double,
  LandValue: Double, NewConstruct: Double, CentralAir: Double, 
  FuelType: Double, HeatType: Double, SewerType: Double, 
  LivingArea: Double, PctCollege: Double, Bedrooms: Double,
  Fireplaces: Double, Bathrooms: Double, rooms: Double
)

```

正如您已经知道的，为了训练 K 均值模型，我们需要确保所有数据点和特征都是数字。因此，我们进一步需要将所有数据点转换为双精度，如下所示：

```scala
// method to transform an RDD of Strings into an RDD of Double
def parseRDD(rdd: RDD[String]): RDD[Array[Double]] = {
  rdd.map(_.split(",")).map(_.map(_.toDouble))
}

```

**步骤 4.准备训练集** - 首先，我们需要将数据框（即`landDF`）转换为双精度的 RDD，并缓存数据以创建一个新的数据框来链接集群编号如下：

```scala
val rowsRDD = landDF.rdd.map(r => (
  r.getDouble(0), r.getDouble(1), r.getDouble(2),
  r.getDouble(3), r.getDouble(4), r.getDouble(5),
  r.getDouble(6), r.getDouble(7), r.getDouble(8),
  r.getDouble(9), r.getDouble(10), r.getDouble(11),
  r.getDouble(12), r.getDouble(13), r.getDouble(14),
  r.getDouble(15))
)
rowsRDD.cache()

```

现在我们需要将前面的双精度 RDD 转换为密集向量的 RDD 如下：

```scala
// Get the prediction from the model with the ID so we can
   link them back to other information
val predictions = rowsRDD.map{r => (
  r._1, model.predict(Vectors.dense(
    r._2, r._3, r._4, r._5, r._6, r._7, r._8, r._9,
    r._10, r._11, r._12, r._13, r._14, r._15, r._16
  )
))}

```

**步骤 5.训练 K 均值模型** - 通过指定 10 个集群、20 次迭代和 10 次运行来训练模型如下：

```scala
val numClusters = 5
val numIterations = 20
val run = 10
val model = KMeans.train(numericHome, numClusters,numIterations, run,
                         KMeans.K_MEANS_PARALLEL)

```

基于 Spark 的 K 均值实现通过使用*K-means++*算法初始化一组集群中心开始工作，这是由*Bahmani 等人*在 2012 年的*可扩展 K-Means++*中提出的一种 K 均值++的变体。这是一种试图通过从随机中心开始，然后进行更多中心的选择的传递，选择概率与它们到当前集群集的平方距离成比例的方法来找到不同的集群中心。它导致对最佳聚类的可证近似。原始论文可以在[`theory.stanford.edu/~sergei/papers/vldb12-kmpar.pdf`](http://theory.stanford.edu/~sergei/papers/vldb12-kmpar.pdf)找到。

**步骤 6.评估模型的错误率** - 标准的 K 均值算法旨在最小化每个集合点之间的距离的平方和，即平方欧几里得距离，这是 WSSSE 的目标。K 均值算法旨在最小化每个集合点（即集群中心）之间的距离的平方和。然而，如果您真的想要最小化每个集合点之间的距离的平方和，您最终会得到一个模型，其中每个集群都是其自己的集群中心；在这种情况下，该度量将为 0。

因此，一旦您通过指定参数训练了模型，就可以使用**平方误差和**（**WSSE**）来评估结果。从技术上讲，它类似于可以计算如下的每个 K 簇中每个观察的距离之和：

```scala
// Evaluate clustering by computing Within Set Sum of Squared Errors
val WCSSS = model.computeCost(landRDD)
println("Within-Cluster Sum of Squares = " + WCSSS)

```

前面的模型训练集产生了 WCSSS 的值：

```scala
Within-Cluster Sum of Squares = 1.455560123603583E12 

```

**步骤 7.计算并打印集群中心** - 首先，我们从模型中获取带有 ID 的预测，以便我们可以将它们与与每栋房子相关的其他信息联系起来。请注意，我们将使用在步骤 4 中准备的行的 RDD*:* 

```scala
// Get the prediction from the model with the ID so we can link them
   back to other information
val predictions = rowsRDD.map{r => (
  r._1, model.predict(Vectors.dense(
    r._2, r._3, r._4, r._5, r._6, r._7, r._8, r._9, r._10,
    r._11, r._12, r._13, r._14, r._15, r._16
  )
))}

```

然而，当需要关于价格的预测时，应该提供如下：

```scala
val predictions = rowsRDD.map{r => (
  r._1, model.predict(Vectors.dense(
    r._1, r._2, r._3, r._4, r._5, r._6, r._7, r._8, r._9, r._10,
    r._11, r._12, r._13, r._14, r._15, r._16
  )
))}

```

为了更好地可见性和探索性分析，将 RDD 转换为数据框如下：

```scala
import spark.sqlContext.implicits._val predCluster = predictions.toDF("Price", "CLUSTER")
predCluster.show()

```

这应该产生以下图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00044.gif)**图 4：** 预测集群的快照

由于数据集中没有可区分的 ID，我们表示`Price`字段以进行链接。从前面的图中，您可以了解到具有特定价格的房屋属于哪个集群。现在为了更好地可见性，让我们将预测数据框与原始数据框连接起来，以了解每栋房子的个体集群编号：

```scala
val newDF = landDF.join(predCluster, "Price") 
newDF.show()

```

您应该观察以下图中的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00138.jpeg)**图 5：** 预测每个房屋所在集群的快照

为了进行分析，我们将输出转储到 RStudio 中，并生成*图 6*中显示的集群。R 脚本可以在我的 GitHub 存储库[`github.com/rezacsedu/ScalaAndSparkForBigDataAnalytics`](https://github.com/rezacsedu/ScalaAndSparkForBigDataAnalytics)上找到。或者，您可以编写自己的脚本，并相应地进行可视化。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00142.jpeg)**图 6：** 社区的集群

现在，为了进行更广泛的分析和可见性，我们可以观察每个集群的相关统计数据。例如，下面我分别打印了*图 8*和*图 9*中与集群 3 和 4 相关的统计数据：

```scala
newDF.filter("CLUSTER = 0").show() 
newDF.filter("CLUSTER = 1").show()
newDF.filter("CLUSTER = 2").show()
newDF.filter("CLUSTER = 3").show()
newDF.filter("CLUSTER = 4").show()

```

现在获取每个集群的描述性统计数据如下：

```scala
newDF.filter("CLUSTER = 0").describe().show()
newDF.filter("CLUSTER = 1").describe().show()
newDF.filter("CLUSTER = 2").describe().show()
newDF.filter("CLUSTER = 3").describe().show() 
newDF.filter("CLUSTER = 4").describe().show()

```

首先，让我们观察以下图中集群 3 的相关统计数据：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00353.jpeg)**图 7：** 集群 3 的统计数据

现在让我们观察以下图中集群 4 的相关统计数据：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00377.jpeg)**图 8：** 集群 4 的统计数据

请注意，由于原始截图太大，无法放入此页面，因此对原始图像进行了修改，并删除了包含房屋其他变量的列。

由于该算法的随机性质，每次成功迭代可能会得到不同的结果。但是，您可以通过以下方式设置种子来锁定该算法的随机性质：

```scala
val numClusters = 5 
val numIterations = 20 
val seed = 12345 
val model = KMeans.train(landRDD, numClusters, numIterations, seed)

```

**步骤 8. 停止 Spark 会话** - 最后，使用 stop 方法停止 Spark 会话：

```scala
spark.stop()

```

在前面的例子中，我们处理了一组非常小的特征；常识和视觉检查也会导致相同的结论。从上面使用 K 均值算法的例子中，我们可以理解这个算法的一些局限性。例如，很难预测 K 值，并且全局集群效果不佳。此外，不同的初始分区可能导致不同的最终集群，最后，它在不同大小和密度的集群中效果不佳。

为了克服这些局限性，本书中还有一些更健壮的算法，如 MCMC（马尔可夫链蒙特卡洛；也可参见[`en.wikipedia.org/wiki/Markov_chain_Monte_Carlo`](https://en.wikipedia.org/wiki/Markov_chain_Monte_Carlo)）在书中介绍：*Tribble*, *Seth D.*, **Markov chain Monte Carlo** algorithms using completely uniformly distributed driving sequences, Diss. Stanford University, 2007.

# 层次聚类（HC）

在本节中，我们将讨论层次聚类技术及其计算挑战。还将展示使用 Spark MLlib 的层次聚类的双分 K 均值算法的示例，以更好地理解层次聚类。

# HC 算法概述和挑战

层次聚类技术在计算上与基于质心的聚类有所不同，距离的计算方式也不同。这是最受欢迎和广泛使用的聚类分析技术之一，旨在构建一个集群的层次结构。由于一个集群通常包含多个对象，也会有其他候选对象来计算距离。因此，除了通常选择的距离函数之外，您还需要决定要使用的链接标准。简而言之，层次聚类有两种策略：

+   **自底向上方法**：在这种方法中，每个观察开始在自己的集群中。之后，将集群对合并在一起，然后向上移动层次结构。

+   **自顶向下方法**：在这种方法中，所有观察开始在一个集群中，递归地进行分裂，然后向下移动层次结构。

这些自底向上或自顶向下的方法基于**单链接聚类**（**SLINK**）技术，考虑最小对象距离，**完全链接聚类**（**CLINK**），考虑对象距离的最大值，以及**无权重对组平均法**（**UPGMA**）。后者也被称为**平均链接聚类**。从技术上讲，这些方法不会从数据集中产生唯一的分区（即不同的簇）。

关于这三种方法的比较分析可以在[`nlp.stanford.edu/IR-book/completelink.html`](https://nlp.stanford.edu/IR-book/completelink.html)找到。

然而，用户仍然需要从层次结构中选择适当的簇以获得更好的簇预测和分配。尽管像二分 K-means 这类的算法在计算上比 K-means 算法更快，但这种类型的算法有三个缺点：

+   首先，这些方法对异常值或包含噪声或缺失值的数据集不够稳健。这个缺点要么会导致额外的簇，要么甚至会导致其他簇合并。这个问题通常被称为链接现象，特别是对于单链接聚类。

+   其次，从算法分析来看，凝聚式聚类和分裂式聚类的复杂性分别为 O(n³)和 O(n²)，这使它们在处理大型数据集时过于缓慢。

+   第三，SLINK 和 CLINK 以前被广泛用于数据挖掘任务，作为聚类分析的理论基础，但现在被认为是过时的。

# 使用 Spark MLlib 的二分 K-means

二分 K-means 通常比常规 K-means 快得多，但通常会产生不同的聚类。二分 K-means 算法基于*Steinbach*、*Karypis*和*Kumar*的论文《文档聚类技术的比较》，并进行了修改以适应 Spark MLlib。

二分 K-means 是一种分裂算法，从包含所有数据点的单个簇开始。然后，它迭代地在底层找到所有可分的簇，并使用 K-means 将它们中的每一个二分，直到总共有 K 个叶簇或没有可分的叶簇。之后，将同一级别的簇分组在一起以增加并行性。换句话说，二分 K-means 在计算上比常规 K-means 算法更快。请注意，如果在底层二分所有可分的簇导致超过 K 个叶簇，较大的簇将始终优先考虑。

请注意，如果在底层二分所有可分的簇导致超过 K 个叶簇，较大的簇将始终优先考虑。Spark MLlib 实现中使用以下参数：

+   **K**：这是期望的叶簇的数量。然而，如果在计算过程中没有可分的叶簇，则实际数量可能会更小。默认值为 4。

+   **MaxIterations**：这是将簇分裂的 K-means 迭代的最大次数。默认值为 20。

+   **MinDivisibleClusterSize**：这是点的最小数量。默认值设置为 1。

+   **Seed**：这是一个随机种子，禁止随机聚类，并尝试在每次迭代中提供几乎相似的结果。但建议使用长种子值，如 12345 等。

# 使用 Spark MLlib 对邻域进行二分 K-means 聚类

在前一节中，我们看到如何将相似的房屋聚类在一起以确定邻域。二分 K-means 与常规 K-means 类似，只是模型训练采用不同的训练参数，如下所示：

```scala
// Cluster the data into two classes using KMeans 
val bkm = new BisectingKMeans() 
                 .setK(5) // Number of clusters of the similar houses
                 .setMaxIterations(20)// Number of max iteration
                 .setSeed(12345) // Setting seed to disallow randomness 
val model = bkm.run(landRDD)

```

您应该参考前面的示例，只需重复前面的步骤以获得训练数据。现在让我们通过计算 WSSSE 来评估聚类，如下所示：

```scala
val WCSSS = model.computeCost(landRDD)
println("Within-Cluster Sum of Squares = " + WCSSS) // Less is better    

```

您应该观察到以下输出：`Within-Cluster Sum of Squares = 2.096980212594632E11`。现在，要进行更多分析，请参考上一节的第 5 步。

# 基于分布的聚类（DC）

在本节中，我们将讨论基于分布的聚类技术及其计算挑战。将展示使用 Spark MLlib 进行**高斯混合模型**（**GMMs**）的示例，以更好地理解基于分布的聚类。

# DC 算法中的挑战

像 GMM 这样的基于分布的聚类算法是一种期望最大化算法。为了避免过拟合问题，GMM 通常使用固定数量的高斯分布对数据集进行建模。分布是随机初始化的，并且相关参数也经过迭代优化，以更好地适应训练数据集。这是 GMM 最健壮的特性，并有助于模型收敛到局部最优解。然而，多次运行该算法可能会产生不同的结果。

换句话说，与二分 K 均值算法和软聚类不同，GMM 针对硬聚类进行了优化，为了获得这种类型，对象通常被分配到高斯分布中。GMM 的另一个有利特性是，它通过捕获数据点和属性之间的所有必要相关性和依赖关系来产生复杂的聚类模型。

不利的一面是，GMM 对数据的格式和形状有一些假设，这给我们（即用户）增加了额外的负担。更具体地说，如果以下两个标准不满足，性能会急剧下降：

+   非高斯数据集：GMM 算法假设数据集具有潜在的高斯生成分布。然而，许多实际数据集不满足这一假设，这会导致低聚类性能。

+   如果簇的大小不均匀，小簇被大簇主导的可能性很高。

# 高斯混合模型是如何工作的？

使用 GMM 是一种流行的软聚类技术。GMM 试图将所有数据点建模为有限数量的高斯分布的混合物；计算每个点属于每个簇的概率以及与簇相关的统计数据，并表示一个混合分布：其中所有点都来自于*K*个高斯子分布之一，具有自己的概率。简而言之，GMM 的功能可以用三步伪代码来描述：

1.  **目标函数：**使用期望-最大化（EM）作为框架计算和最大化对数似然

1.  **EM 算法：**

+   **E 步：**计算成员的后验概率-即更接近的数据点

+   M 步：优化参数。

1.  分配：在步骤 E 期间执行软分配。

从技术上讲，当给定一个统计模型时，该模型的参数（即应用于数据集时）是使用**最大似然估计**（**MLE**）来估计的。另一方面，**EM**算法是一种找到最大似然的迭代过程。

由于 GMM 是一种无监督算法，GMM 模型取决于推断变量。然后 EM 迭代旋转以执行期望（E）和最大化（M）步骤。

Spark MLlib 实现使用期望最大化算法从给定的一组数据点中诱导最大似然模型。当前的实现使用以下参数：

+   **K**是要对数据点进行聚类的期望簇的数量

+   **ConvergenceTol**是我们认为达到收敛的对数似然的最大变化。

+   **MaxIterations**是在达到收敛点之前执行的最大迭代次数。

+   **InitialModel**是一个可选的起始点，从中开始 EM 算法。如果省略此参数，将从数据构造一个随机起始点。

# 使用 Spark MLlib 进行 GMM 聚类的示例

在前面的部分中，我们看到了如何将相似的房屋聚集在一起以确定邻域。使用 GMM，也可以将房屋聚类以找到邻域，除了模型训练，还需要不同的训练参数，如下所示：

```scala
val K = 5 
val maxIteration = 20 
val model = new GaussianMixture()
                .setK(K)// Number of desired clusters
                .setMaxIterations(maxIteration)//Maximum iterations
                .setConvergenceTol(0.05) // Convergence tolerance. 
                .setSeed(12345) // setting seed to disallow randomness
                .run(landRDD) // fit the model using the training set

```

您应该参考前面的示例，只需重复获取训练数据的先前步骤。现在，为了评估模型的性能，GMM 不提供任何性能指标，如 WCSS 作为成本函数。然而，GMM 提供一些性能指标，如 mu、sigma 和 weight。这些参数表示了不同簇（在我们的情况下为五个簇）之间的最大似然。这可以如下所示：

```scala
// output parameters of max-likelihood model
for (i <- 0 until model.K) {
  println("Cluster " + i)
  println("Weight=%f\nMU=%s\nSigma=\n%s\n" format(model.weights(i),   
           model.gaussians(i).mu, model.gaussians(i).sigma))
}

```

您应该观察以下输出：

图 9：聚类 1 图 10：聚类 2 图 11：聚类 3 图 12：聚类 4 图 13：聚类 5

簇 1 到 4 的权重表明，这些簇是同质的，并且与簇 5 相比显著不同。

# 确定聚类的数量

像 K 均值算法这样的聚类算法的美妙之处在于它可以对具有无限特征的数据进行聚类。当您有原始数据并想了解数据中的模式时，它是一个很好的工具。然而，在进行实验之前决定聚类的数量可能不成功，有时可能会导致过度拟合或拟合不足的问题。另一方面，所有三种算法（即 K 均值、二分 K 均值和高斯混合）的一个共同点是，聚类的数量必须事先确定并作为参数提供给算法。因此，非正式地说，确定聚类的数量是一个要解决的单独优化问题。

在本节中，我们将使用基于 Elbow 方法的一种启发式方法。我们从 K = 2 个簇开始，然后通过增加 K 并观察成本函数**簇内平方和**（**WCSS**）的值来运行相同数据集的 K 均值算法。在某个时候，可以观察到成本函数的大幅下降，但随着 K 值的增加，改进变得微不足道。正如聚类分析文献中建议的那样，我们可以选择 WCSS 的最后一个大幅下降后的 K 作为最佳值。

通过分析以下参数，您可以找出 K 均值的性能：

+   **内部性：**这是平方和之间也称为*簇内相似度*。

+   **内部性：**这是平方和之间也称为*簇内相似度*。

+   **Totwithinss：**这是所有簇的内部性之和，也称为*总簇内相似度*。

需要注意的是，一个健壮而准确的聚类模型将具有较低的内部性值和较高的内部性值。然而，这些值取决于聚类的数量，即在构建模型之前选择的 K。

现在让我们讨论如何利用 Elbow 方法来确定聚类的数量。如下所示，我们计算了作为 K 均值算法应用于所有特征的家庭数据的聚类数量的成本函数 WCSS。可以观察到当 K = 5 时有一个大幅下降。因此，我们选择了 5 个簇的数量，如*图 10*所示。基本上，这是最后一个大幅下降后的一个。

图 14：作为 WCSS 函数的聚类数量

# 聚类算法之间的比较分析

高斯混合主要用于期望最小化，这是优化算法的一个例子。比普通 K-means 更快的 bisecting K-means 也会产生略有不同的聚类结果。下面我们尝试比较这三种算法。我们将展示模型构建时间和每种算法的计算成本的性能比较。如下所示，我们可以计算 WCSS 的成本。以下代码行可用于计算 K-means 和**b**isecting 算法的 WCSS：

```scala
val WCSSS = model.computeCost(landRDD) // land RDD is the training set 
println("Within-Cluster Sum of Squares = " + WCSSS) // Less is better 

```

在本章中我们使用的数据集，我们得到了以下 WCSS 的值：

```scala
Within-Cluster Sum of Squares of Bisecting K-means = 2.096980212594632E11 
Within-Cluster Sum of Squares of K-means = 1.455560123603583E12

```

这意味着 K-means 在计算成本方面表现略好一些。不幸的是，我们没有 GMM 算法的 WCSS 等指标。现在让我们观察这三种算法的模型构建时间。我们可以在开始模型训练之前启动系统时钟，并在训练结束后立即停止，如下所示（对于 K-means）：

```scala
val start = System.currentTimeMillis() 
val numClusters = 5 
val numIterations = 20  
val seed = 12345 
val runs = 50 
val model = KMeans.train(landRDD, numClusters, numIterations, seed) 
val end = System.currentTimeMillis()
println("Model building and prediction time: "+ {end - start} + "ms")

```

在本章中我们使用的训练集，我们得到了以下模型构建时间的值：

```scala
Model building and prediction time for Bisecting K-means: 2680ms 
Model building and prediction time for Gaussian Mixture: 2193ms 
Model building and prediction time for K-means: 3741ms

```

在不同的研究文章中，已经发现，bisecting K-means 算法已经被证明可以更好地为数据点分配聚类。此外，与 K-means 相比，bisecting K-means 也更快地收敛到全局最小值。另一方面，K-means 会陷入局部最小值。换句话说，使用 bisecting K-means 算法，我们可以避免 K-means 可能遭受的局部最小值。

请注意，根据您的机器硬件配置和数据集的随机性质，您可能会观察到前述参数的不同值。

更详细的分析留给读者从理论角度来看。有兴趣的读者还应参考[`spark.apache.org/docs/latest/mllib-clustering.html`](https://spark.apache.org/docs/latest/mllib-clustering.html)中基于 Spark MLlib 的聚类技术，以获得更多见解。

# 提交 Spark 集群分析作业

本章中展示的示例可以扩展到更大的数据集，以满足不同的目的。您可以将所有三种聚类算法与所有必需的依赖项打包，并将它们作为 Spark 作业提交到集群。现在使用以下代码行提交您的 K-means 聚类的 Spark 作业，例如（对其他类使用类似的语法），用于 Saratoga NY Homes 数据集：

```scala
# Run application as standalone mode on 8 cores 
SPARK_HOME/bin/spark-submit \   
--class org.apache.spark.examples.KMeansDemo \   
--master local[8] \   
KMeansDemo-0.1-SNAPSHOT-jar-with-dependencies.jar \   
Saratoga_NY_Homes.txt

# Run on a YARN cluster 
export HADOOP_CONF_DIR=XXX 
SPARK_HOME/bin/spark-submit \   
--class org.apache.spark.examples.KMeansDemo \   
--master yarn \   
--deploy-mode cluster \  # can be client for client mode   
--executor-memory 20G \   
--num-executors 50 \   
KMeansDemo-0.1-SNAPSHOT-jar-with-dependencies.jar \   
Saratoga_NY_Homes.txt

# Run on a Mesos cluster in cluster deploy mode with supervising 
SPARK_HOME/bin/spark-submit \  
--class org.apache.spark.examples.KMeansDemo \  
--master mesos://207.184.161.138:7077 \ # Use your IP aadress   
--deploy-mode cluster \   
--supervise \   
--executor-memory 20G \   
--total-executor-cores 100 \   
KMeansDemo-0.1-SNAPSHOT-jar-with-dependencies.jar \   
Saratoga_NY_Homes.txt

```

# 总结

在本章中，我们更深入地研究了机器学习，并发现了如何利用机器学习来对无监督观测数据集中的记录进行聚类。因此，您学会了在可用数据上快速而有效地应用监督和无监督技术，以解决新问题的实际知识，这些知识是基于前几章的理解的一些广泛使用的示例。我们所说的示例将从 Spark 的角度进行演示。对于 K-means、bisecting K-means 和高斯混合算法中的任何一个，不能保证如果多次运行算法将产生相同的聚类。例如，我们观察到使用相同参数多次运行 K-means 算法会在每次运行时生成略有不同的结果。

有关 K-means 和高斯混合的性能比较，请参阅*Jung. et. al 和聚类分析*讲义。除了 K-means、bisecting K-means 和高斯混合外，MLlib 还提供了另外三种聚类算法的实现，即 PIC、LDA 和流式 K-means。还值得一提的是，为了对聚类分析进行微调，通常需要删除不需要的数据对象，称为离群值或异常值。但是使用基于距离的聚类很难识别这样的数据点。因此，除了欧几里得距离之外，还可以使用其他距离度量。然而，这些链接将是开始的好资源：

1.  [`mapr.com/ebooks/spark/08-unsupervised-anomaly-detection-apache-spark.html`](https://mapr.com/ebooks/spark/08-unsupervised-anomaly-detection-apache-spark.html)

1.  [`github.com/keiraqz/anomaly-detection`](https://github.com/keiraqz/anomaly-detection)

1.  [`www.dcc.fc.up.pt/~ltorgo/Papers/ODCM.pdf`](https://mapr.com/ebooks/spark/08-unsupervised-anomaly-detection-apache-spark.html)

在下一章中，我们将更深入地挖掘调优 Spark 应用程序以获得更好性能的方法。我们将看到一些优化 Spark 应用程序性能的最佳实践。


# 第十五章：使用 Spark ML 进行文本分析

“程序必须为人们阅读而编写，只是偶然为机器执行。”

- Harold Abelson

在本章中，我们将讨论使用 Spark ML 进行文本分析的精彩领域。文本分析是机器学习中的一个广泛领域，在许多用例中非常有用，如情感分析、聊天机器人、电子邮件垃圾邮件检测和自然语言处理。我们将学习如何使用 Spark 进行文本分析，重点关注使用包含 1 万个 Twitter 数据样本的文本分类用例。

简而言之，本章将涵盖以下主题：

+   理解文本分析

+   转换器和估计器

+   标记器

+   StopWordsRemover

+   N-Grams

+   TF-IDF

+   Word2Vec

+   CountVectorizer

+   使用 LDA 进行主题建模

+   实施文本分类

# 理解文本分析

在过去的几章中，我们已经探索了机器学习的世界和 Apache Spark 对机器学习的支持。正如我们讨论的那样，机器学习有一个工作流程，下面解释了以下步骤：

1.  加载或摄取数据。

1.  清洗数据。

1.  从数据中提取特征。

1.  在数据上训练模型，以生成基于特征的期望结果。

1.  根据数据评估或预测某种结果。

典型管道的简化视图如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00310.jpeg)

因此，在模型训练之前和随后部署之前，可能存在多个数据转换阶段。此外，我们应该期望特征和模型属性的改进。我们甚至可以探索完全不同的算法，重复整个任务序列作为新工作流的一部分。

可以使用多个转换步骤创建一个管道，并且为此目的，我们使用特定领域的语言（DSL）来定义节点（数据转换步骤）以创建节点的有向无环图（DAG）。因此，ML 管道是一系列转换器和估计器，用于将管道模型拟合到输入数据集。管道中的每个阶段称为*管道阶段*，列举如下：

+   估计器

+   模型

+   管道

+   变压器

+   预测器

当你看一行文本时，我们看到句子、短语、单词、名词、动词、标点等等，这些放在一起时有意义和目的。人类非常擅长理解句子、单词和俚语，以及注释或上下文。这来自多年的练习和学习如何阅读/写作、正确的语法、标点、感叹号等等。那么，我们如何编写计算机程序来尝试复制这种能力呢？

# 文本分析

文本分析是从一系列文本中解锁含义的方法。通过使用各种技术和算法来处理和分析文本数据，我们可以发现数据中的模式和主题。所有这些的目标是理解非结构化文本，以便推导出上下文的含义和关系。

文本分析利用了几种广泛的技术类别，接下来我们将介绍。

# 情感分析

分析人们在 Facebook、Twitter 和其他社交媒体上的政治观点是情感分析的一个很好的例子。同样，分析 Yelp 上餐厅的评论也是情感分析的另一个很好的例子。

自然语言处理（NLP）框架和库，如 OpenNLP 和 Stanford NLP，通常用于实现情感分析。

# 主题建模

主题建模是一种用于检测语料库中主题或主题的有用技术。这是一种无监督算法，可以在一组文档中找到主题。一个例子是检测新闻文章中涵盖的主题。另一个例子是检测专利申请中的想法。

潜在狄利克雷分配（LDA）是使用无监督算法的流行聚类模型，而潜在语义分析（LSA）使用共现数据的概率模型。

# TF-IDF（词项频率 - 逆文档频率）

TF-IDF 衡量单词在文档中出现的频率以及在文档集中的相对频率。这些信息可以用于构建分类器和预测模型。例如垃圾邮件分类、聊天对话等。

# 命名实体识别（NER）

命名实体识别检测句子中单词和名词的使用，以提取有关个人、组织、位置等信息。这提供了有关文档实际内容的重要上下文信息，而不仅仅将单词视为主要实体。

斯坦福 NLP 和 OpenNLP 都实现了 NER 算法。

# 事件提取

事件提取扩展了 NER，建立了围绕检测到的实体的关系。这可以用于推断两个实体之间的关系。因此，还有一个额外的语义理解层来理解文档内容。

# 变压器和估计器

**变压器**是一个函数对象，通过将变换逻辑（函数）应用于输入数据集，将一个数据集转换为另一个数据集。有两种类型的变压器，标准变压器和估计器变压器。

# 标准变压器

标准变压器将输入数据集显式地转换为输出数据集，应用变换函数到输入数据上。除了读取输入列并生成输出列之外，不依赖于输入数据。

这些变压器如下所示被调用：

```scala
*outputDF = transfomer.*transform*(inputDF)*

```

标准变压器的示例如下，并将在后续部分详细解释：

+   `Tokenizer`：这使用空格作为分隔符将句子分割成单词

+   `RegexTokenizer`：这使用正则表达式将句子分割成单词

+   `StopWordsRemover`：这从单词列表中移除常用的停用词

+   `Binarizer`：这将字符串转换为二进制数字 0/1

+   `NGram`：这从句子中创建 N 个词组

+   `HashingTF`：这使用哈希表创建词项频率计数以索引单词

+   `SQLTransformer`：这实现了由 SQL 语句定义的转换

+   `VectorAssembler`：这将给定的列列表合并成一个单独的向量列

标准变压器的图示如下，其中来自输入数据集的输入列被转换为生成输出数据集的输出列：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00247.jpeg)

# 估计器变压器

估计器变压器通过首先基于输入数据集生成一个变压器，然后变压器处理输入数据，读取输入列并在输出数据集中生成输出列来将输入数据集转换为输出数据集。

这些变压器如下所示被调用：

```scala
*transformer = estimator.*fit*(inputDF)* *outputDF = transformer.*transform*(inputDF)*

```

估计器变压器的示例如下：

+   IDF

+   LDA

+   Word2Vec

估计器变压器的图示如下，其中来自输入数据集的输入列被转换为生成输出数据集的输出列：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00287.jpeg)

在接下来的几节中，我们将深入研究使用一个简单示例数据集进行文本分析，该数据集由文本行（句子）组成，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00330.jpeg)

即将出现的代码用于将文本数据加载到输入数据集中。

使用下面显示的 ID 和文本对序列初始化一个名为 lines 的句子序列。

```scala
val lines = Seq(
 | (1, "Hello there, how do you like the book so far?"),
 | (2, "I am new to Machine Learning"),
 | (3, "Maybe i should get some coffee before starting"),
 | (4, "Coffee is best when you drink it hot"),
 | (5, "Book stores have coffee too so i should go to a book store")
 | )
lines: Seq[(Int, String)] = List((1,Hello there, how do you like the book so far?), (2,I am new to Machine Learning), (3,Maybe i should get some coffee before starting), (4,Coffee is best when you drink it hot), (5,Book stores have coffee too so i should go to a book store))

```

接下来，调用`createDataFrame()`函数从我们之前看到的句子序列创建一个 DataFrame。

```scala
scala> val sentenceDF = spark.createDataFrame(lines).toDF("id", "sentence")
sentenceDF: org.apache.spark.sql.DataFrame = [id: int, sentence: string]

```

现在您可以看到新创建的数据集，其中显示了包含两列 ID 和句子的句子 DataFrame。

```scala
scala> sentenceDF.show(false)
|id|sentence |
|1 |Hello there, how do you like the book so far? |
|2 |I am new to Machine Learning |
|3 |Maybe i should get some coffee before starting |
|4 |Coffee is best when you drink it hot |
|5 |Book stores have coffee too so i should go to a book store|

```

# 标记化

**Tokenizer**将输入字符串转换为小写，然后使用空格将字符串分割为单独的标记。给定的句子被分割成单词，可以使用默认的空格分隔符，也可以使用基于正则表达式的分词器。在任何情况下，输入列都会被转换为输出列。特别是，输入列通常是一个字符串，输出列是一个单词序列。

通过导入下面显示的两个包，可以使用分词器：`Tokenizer`和`RegexTokenize`：

```scala
import org.apache.spark.ml.feature.Tokenizer
import org.apache.spark.ml.feature.RegexTokenizer

```

首先，您需要初始化一个`Tokenizer`，指定输入列和输出列：

```scala
scala> val tokenizer = new Tokenizer().setInputCol("sentence").setOutputCol("words")
tokenizer: org.apache.spark.ml.feature.Tokenizer = tok_942c8332b9d8

```

接下来，在输入数据集上调用`transform()`函数会产生一个输出数据集：

```scala
scala> val wordsDF = tokenizer.transform(sentenceDF)
wordsDF: org.apache.spark.sql.DataFrame = [id: int, sentence: string ... 1 more field]

```

以下是输出数据集，显示了输入列 ID、句子和包含单词序列的输出列 words：

```scala
scala> wordsDF.show(false)
|id|sentence |words |
|1 |Hello there, how do you like the book so far? |[hello, there,, how, do, you, like, the, book, so, far?] |
|2 |I am new to Machine Learning |[i, am, new, to, machine, learning] |
|3 |Maybe i should get some coffee before starting |[maybe, i, should, get, some, coffee, before, starting] |
|4 |Coffee is best when you drink it hot |[coffee, is, best, when, you, drink, it, hot] |
|5 |Book stores have coffee too so i should go to a book store|[book, stores, have, coffee, too, so, i, should, go, to, a, book, store]|

```

另一方面，如果您想要设置基于正则表达式的`Tokenizer`，您需要使用`RegexTokenizer`而不是`Tokenizer`。为此，您需要初始化一个`RegexTokenizer`，指定输入列和输出列，以及要使用的正则表达式模式：

```scala
scala> val regexTokenizer = new RegexTokenizer().setInputCol("sentence").setOutputCol("regexWords").setPattern("\\W")
regexTokenizer: org.apache.spark.ml.feature.RegexTokenizer = regexTok_15045df8ce41

```

接下来，在输入数据集上调用`transform()`函数会产生一个输出数据集：

```scala
scala> val regexWordsDF = regexTokenizer.transform(sentenceDF)
regexWordsDF: org.apache.spark.sql.DataFrame = [id: int, sentence: string ... 1 more field]

```

以下是输出数据集，显示了输入列 ID、句子和包含单词序列的输出列`regexWordsDF`：

```scala
scala> regexWordsDF.show(false)
|id|sentence |regexWords |
|1 |Hello there, how do you like the book so far? |[hello, there, how, do, you, like, the, book, so, far] |
|2 |I am new to Machine Learning |[i, am, new, to, machine, learning] |
|3 |Maybe i should get some coffee before starting |[maybe, i, should, get, some, coffee, before, starting] |
|4 |Coffee is best when you drink it hot |[coffee, is, best, when, you, drink, it, hot] |
|5 |Book stores have coffee too so i should go to a book store|[book, stores, have, coffee, too, so, i, should, go, to, a, book, store]|

```

`Tokenizer`的图示如下，其中来自输入文本的句子使用空格分隔成单词：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00150.jpeg)

# StopWordsRemover

`StopWordsRemover`是一个转换器，它接受一个`String`数组的单词，并在删除所有定义的停用词后返回一个`String`数组。一些停用词的例子是 I，you，my，and，or 等，在英语中非常常用。您可以覆盖或扩展停用词集以适应用例的目的。如果没有进行这种清洗过程，后续的算法可能会因为常用单词而产生偏见。

为了调用`StopWordsRemover`，您需要导入以下包：

```scala
import org.apache.spark.ml.feature.StopWordsRemover

```

首先，您需要初始化一个`StopWordsRemover`，指定输入列和输出列。在这里，我们选择了`Tokenizer`创建的单词列，并生成了一个输出列，用于删除停用词后的过滤单词：

```scala
scala> val remover = new StopWordsRemover().setInputCol("words").setOutputCol("filteredWords")
remover: org.apache.spark.ml.feature.StopWordsRemover = stopWords_48d2cecd3011

```

接下来，在输入数据集上调用`transform()`函数会产生一个输出数据集：

```scala
scala> val noStopWordsDF = remover.transform(wordsDF)
noStopWordsDF: org.apache.spark.sql.DataFrame = [id: int, sentence: string ... 2 more fields]

```

以下是输出数据集，显示了输入列 ID、句子和包含单词序列的输出列`filteredWords`：

```scala
scala> noStopWordsDF.show(false)
|id|sentence |words |filteredWords |
|1 |Hello there, how do you like the book so far? |[hello, there,, how, do, you, like, the, book, so, far?] |[hello, there,, like, book, far?] |
|2 |I am new to Machine Learning |[i, am, new, to, machine, learning] |[new, machine, learning] |
|3 |Maybe i should get some coffee before starting |[maybe, i, should, get, some, coffee, before, starting] |[maybe, get, coffee, starting] |
|4 |Coffee is best when you drink it hot |[coffee, is, best, when, you, drink, it, hot] |[coffee, best, drink, hot] |
|5 |Book stores have coffee too so i should go to a book store|[book, stores, have, coffee, too, so, i, should, go, to, a, book, store]|[book, stores, coffee, go, book, store]|

```

以下是输出数据集，只显示了句子和`filteredWords`，其中包含过滤后的单词序列：

```scala

scala> noStopWordsDF.select("sentence", "filteredWords").show(5,false)
|sentence |filteredWords |
|Hello there, how do you like the book so far? |[hello, there,, like, book, far?] |
|I am new to Machine Learning |[new, machine, learning] |
|Maybe i should get some coffee before starting |[maybe, get, coffee, starting] |
|Coffee is best when you drink it hot |[coffee, best, drink, hot] |
|Book stores have coffee too so i should go to a book store|[book, stores, coffee, go, book, store]|

```

`StopWordsRemover`的图示如下，显示了过滤后的单词，删除了诸如 I，should，some 和 before 等停用词：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00021.jpeg)

停用词默认设置，但可以非常容易地被覆盖或修改，如下面的代码片段所示，在这里我们将从过滤后的单词中删除 hello，将 hello 视为停用词：

```scala
scala> val noHello = Array("hello") ++ remover.getStopWords
noHello: Array[String] = Array(hello, i, me, my, myself, we, our, ours, ourselves, you, your, yours, yourself, yourselves, he, him, his, himself, she, her, hers, herself, it, its, itself, they, them, their, theirs, themselves, what, which, who, whom, this, that, these, those, am, is, are, was, were ...
scala>

//create new transfomer using the amended Stop Words list
scala> val removerCustom = new StopWordsRemover().setInputCol("words").setOutputCol("filteredWords").setStopWords(noHello)
removerCustom: org.apache.spark.ml.feature.StopWordsRemover = stopWords_908b488ac87f

//invoke transform function
scala> val noStopWordsDFCustom = removerCustom.transform(wordsDF)
noStopWordsDFCustom: org.apache.spark.sql.DataFrame = [id: int, sentence: string ... 2 more fields]

//output dataset showing only sentence and filtered words - now will not show hello
scala> noStopWordsDFCustom.select("sentence", "filteredWords").show(5,false)
+----------------------------------------------------------+---------------------------------------+
|sentence |filteredWords |
+----------------------------------------------------------+---------------------------------------+
|Hello there, how do you like the book so far? |[there,, like, book, far?] |
|I am new to Machine Learning |[new, machine, learning] |
|Maybe i should get some coffee before starting |[maybe, get, coffee, starting] |
|Coffee is best when you drink it hot |[coffee, best, drink, hot] |
|Book stores have coffee too so i should go to a book store|[book, stores, coffee, go, book, store]|
+----------------------------------------------------------+---------------------------------------+

```

# NGrams

NGrams 是由单词组合而成的单词序列。N 代表序列中的单词数。例如，2-gram 是两个单词在一起，3-gram 是三个单词在一起。`setN()`用于指定`N`的值。

为了生成 NGrams，您需要导入该包：

```scala
import org.apache.spark.ml.feature.NGram

```

首先，您需要初始化一个`NGram`生成器，指定输入列和输出列。在这里，我们选择了`StopWordsRemover`创建的过滤后的单词列，并生成了一个输出列，用于删除停用词后的过滤单词：

```scala
scala> val ngram = new NGram().setN(2).setInputCol("filteredWords").setOutputCol("ngrams")
ngram: org.apache.spark.ml.feature.NGram = ngram_e7a3d3ab6115

```

接下来，在输入数据集上调用`transform()`函数会产生一个输出数据集：

```scala
scala> val nGramDF = ngram.transform(noStopWordsDF)
nGramDF: org.apache.spark.sql.DataFrame = [id: int, sentence: string ... 3 more fields]

```

以下是输出数据集，显示了输入列 ID、句子和包含 n-gram 序列的输出列`ngram`：

```scala
scala> nGramDF.show(false)
|id|sentence |words |filteredWords |ngrams |
|1 |Hello there, how do you like the book so far? |[hello, there,, how, do, you, like, the, book, so, far?] |[hello, there,, like, book, far?] |[hello there,, there, like, like book, book far?] |
|2 |I am new to Machine Learning |[i, am, new, to, machine, learning] |[new, machine, learning] |[new machine, machine learning] |
|3 |Maybe i should get some coffee before starting |[maybe, i, should, get, some, coffee, before, starting] |[maybe, get, coffee, starting] |[maybe get, get coffee, coffee starting] |
|4 |Coffee is best when you drink it hot |[coffee, is, best, when, you, drink, it, hot] |[coffee, best, drink, hot] |[coffee best, best drink, drink hot] |
|5 |Book stores have coffee too so i should go to a book store|[book, stores, have, coffee, too, so, i, should, go, to, a, book, store]|[book, stores, coffee, go, book, store]|[book stores, stores coffee, coffee go, go book, book store]|

```

以下是输出数据集，显示了句子和 2-gram：

```scala
scala> nGramDF.select("sentence", "ngrams").show(5,false)
|sentence |ngrams |
|Hello there, how do you like the book so far? |[hello there,, there, like, like book, book far?] |
|I am new to Machine Learning |[new machine, machine learning] |
|Maybe i should get some coffee before starting |[maybe get, get coffee, coffee starting] |
|Coffee is best when you drink it hot |[coffee best, best drink, drink hot] |
|Book stores have coffee too so i should go to a book store|[book stores, stores coffee, coffee go, go book, book store]|

```

NGram 的图如下所示，显示了在分词和去除停用词后生成的 2-gram：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00163.jpeg)

# TF-IDF

TF-IDF 代表词项频率-逆文档频率，它衡量了一个词在文档集合中对于一个文档的重要性。它在信息检索中被广泛使用，反映了词在文档中的权重。TF-IDF 值与词的出现次数成正比增加，也就是词频，由词频和逆文档频率两个关键元素组成。

TF 是词项频率，即文档中词/术语的频率。

对于一个术语*t*，*tf*衡量了术语*t*在文档*d*中出现的次数。*tf*在 Spark 中使用哈希实现，其中一个术语通过应用哈希函数映射到一个索引。

IDF 是逆文档频率，代表了一个术语提供的关于该术语在文档中出现倾向的信息。 IDF 是包含该术语的文档的对数缩放的逆函数：

IDF = 总文档数/包含该词的文档数

一旦我们有了*TF*和*IDF*，我们可以通过将它们相乘来计算*TF-IDF*值：

TF-IDF = TF * IDF

我们现在将看一下如何使用 Spark ML 中的 HashingTF Transformer 生成*TF*。

# HashingTF

**HashingTF**是一个 Transformer，它接受一组术语，并通过使用哈希函数对每个术语进行哈希，将它们转换为固定长度的向量。然后，使用哈希表的索引生成词项频率。

在 Spark 中，HashingTF 使用**MurmurHash3**算法对术语进行哈希。

为了使用`HashingTF`，你需要导入以下包：

```scala
import org.apache.spark.ml.feature.HashingTF

```

首先，你需要初始化一个`HashingTF`，指定输入列和输出列。在这里，我们选择了`StopWordsRemover` Transformer 创建的过滤词列，并生成一个输出列`rawFeaturesDF`。我们还选择了 100 个特征：

```scala
scala> val hashingTF = new HashingTF().setInputCol("filteredWords").setOutputCol("rawFeatures").setNumFeatures(100)
hashingTF: org.apache.spark.ml.feature.HashingTF = hashingTF_b05954cb9375

```

接下来，在输入数据集上调用`transform()`函数会产生一个输出数据集：

```scala
scala> val rawFeaturesDF = hashingTF.transform(noStopWordsDF)
rawFeaturesDF: org.apache.spark.sql.DataFrame = [id: int, sentence: string ... 3 more fields]

```

以下是输出数据集，显示了输入列 ID、句子和输出列`rawFeaturesDF`，其中包含由向量表示的特征：

```scala
scala> rawFeaturesDF.show(false)
|id |sentence |words |filteredWords |rawFeatures |
|1 |Hello there, how do you like the book so far? |[hello, there,, how, do, you, like, the, book, so, far?] |[hello, there,, like, book, far?] |(100,[30,48,70,93],[2.0,1.0,1.0,1.0]) |
|2 |I am new to Machine Learning |[i, am, new, to, machine, learning] |[new, machine, learning] |(100,[25,52,72],[1.0,1.0,1.0]) |
|3 |Maybe i should get some coffee before starting |[maybe, i, should, get, some, coffee, before, starting] |[maybe, get, coffee, starting] |(100,[16,51,59,99],[1.0,1.0,1.0,1.0]) |
|4 |Coffee is best when you drink it hot |[coffee, is, best, when, you, drink, it, hot] |[coffee, best, drink, hot] |(100,[31,51,63,72],[1.0,1.0,1.0,1.0]) |
|5 |Book stores have coffee too so i should go to a book store|[book, stores, have, coffee, too, so, i, should, go, to, a, book, store]|[book, stores, coffee, go, book, store]|(100,[43,48,51,77,93],[1.0,1.0,1.0,1.0,2.0])|

```

让我们看一下前面的输出，以便更好地理解。如果你只看`filteredWords`和`rawFeatures`两列，你会发现，

1.  单词数组`[hello, there, like, book, and far]`被转换为原始特征向量`(100,[30,48,70,93],[2.0,1.0,1.0,1.0])`。

1.  单词数组`(book, stores, coffee, go, book, and store)`被转换为原始特征向量`(100,[43,48,51,77,93],[1.0,1.0,1.0,1.0,2.0])`。

那么，这个向量代表什么呢？其基本逻辑是，每个单词被哈希成一个整数，并计算在单词数组中出现的次数。

Spark 在内部使用`mutable.HashMap.empty[Int, Double]`来存储每个单词的哈希值作为`Integer`键和出现次数作为 double 值。使用 Double 是为了能够与 IDF 一起使用（我们将在下一节讨论）。使用这个映射，数组`[book, stores, coffee, go, book, store]`可以看作是`[hashFunc(book), hashFunc(stores), hashFunc(coffee), hashFunc(go), hashFunc(book), hashFunc(store)]`，即`[43,48,51,77,93]`。然后，如果你也计算出现次数，即`book-2, coffee-1,go-1,store-1,stores-1`。

结合前面的信息，我们可以生成一个向量`(numFeatures, hashValues, Frequencies)`，在这种情况下将是`(100,[43,48,51,77,93],[1.0,1.0,1.0,1.0,2.0])`。

# 逆文档频率（IDF）

**逆文档频率**（**IDF**）是一个估计器，它适用于数据集，然后通过缩放输入特征生成特征。因此，IDF 作用于 HashingTF Transformer 的输出。

为了调用 IDF，您需要导入该包：

```scala
import org.apache.spark.ml.feature.IDF

```

首先，您需要初始化一个`IDF`，指定输入列和输出列。在这里，我们选择由 HashingTF 创建的`rawFeatures`单词列，并生成一个输出列特征：

```scala
scala> val idf = new IDF().setInputCol("rawFeatures").setOutputCol("features")
idf: org.apache.spark.ml.feature.IDF = idf_d8f9ab7e398e

```

接下来，在输入数据集上调用`fit()`函数会产生一个输出 Transformer：

```scala
scala> val idfModel = idf.fit(rawFeaturesDF)
idfModel: org.apache.spark.ml.feature.IDFModel = idf_d8f9ab7e398e

```

此外，在输入数据集上调用`transform()`函数会产生一个输出数据集：

```scala
scala> val featuresDF = idfModel.transform(rawFeaturesDF)
featuresDF: org.apache.spark.sql.DataFrame = [id: int, sentence: string ... 4 more fields]

```

以下是显示输入列 ID 和输出列特征的输出数据集，其中包含由前一个转换中的 HashingTF 生成的缩放特征的向量：

```scala
scala> featuresDF.select("id", "features").show(5, false)
|id|features |
|1 |(20,[8,10,13],[0.6931471805599453,3.295836866004329,0.6931471805599453]) |
|2 |(20,[5,12],[1.0986122886681098,1.3862943611198906]) |
|3 |(20,[11,16,19],[0.4054651081081644,1.0986122886681098,2.1972245773362196]) |
|4 |(20,[3,11,12],[0.6931471805599453,0.8109302162163288,0.6931471805599453]) |
|5 |(20,[3,8,11,13,17],[0.6931471805599453,0.6931471805599453,0.4054651081081644,1.3862943611198906,1.0986122886681098])|

```

以下是显示输入列 ID、句子、`rawFeatures`和输出列特征的输出数据集，其中包含由前一个转换中的 HashingTF 生成的缩放特征的向量：

```scala

scala> featuresDF.show(false)
|id|sentence |words |filteredWords |rawFeatures |features |
|1 |Hello there, how do you like the book so far? |[hello, there,, how, do, you, like, the, book, so, far?] |[hello, there,, like, book, far?] |(20,[8,10,13],[1.0,3.0,1.0]) |(20,[8,10,13],[0.6931471805599453,3.295836866004329,0.6931471805599453]) |
|2 |I am new to Machine Learning |[i, am, new, to, machine, learning] |[new, machine, learning] |(20,[5,12],[1.0,2.0]) |(20,[5,12],[1.0986122886681098,1.3862943611198906]) |
|3 |Maybe i should get some coffee before starting |[maybe, i, should, get, some, coffee, before, starting] |[maybe, get, coffee, starting] |(20,[11,16,19],[1.0,1.0,2.0]) |(20,[11,16,19],[0.4054651081081644,1.0986122886681098,2.1972245773362196]) |
|4 |Coffee is best when you drink it hot |[coffee, is, best, when, you, drink, it, hot] |[coffee, best, drink, hot] |(20,[3,11,12],[1.0,2.0,1.0]) |(20,[3,11,12],[0.6931471805599453,0.8109302162163288,0.6931471805599453]) |
|5 |Book stores have coffee too so i should go to a book store|[book, stores, have, coffee, too, so, i, should, go, to, a, book, store]|[book, stores, coffee, go, book, store]|(20,[3,8,11,13,17],[1.0,1.0,1.0,2.0,1.0])|(20,[3,8,11,13,17],[0.6931471805599453,0.6931471805599453,0.4054651081081644,1.3862943611198906,1.0986122886681098])|

```

TF-IDF 的图如下，显示了**TF-IDF 特征**的生成：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00089.jpeg)

# Word2Vec

Word2Vec 是一种复杂的神经网络风格的自然语言处理工具，使用一种称为**skip-grams**的技术将单词句子转换为嵌入式向量表示。让我们看一个关于动物的句子集合的示例：

+   一只狗在吠叫

+   一些奶牛在吃草

+   狗通常会随机吠叫

+   牛喜欢草

使用具有隐藏层的神经网络（在许多无监督学习应用中使用的机器学习算法），我们可以学习（有足够的例子）*dog*和*barking*相关，*cow*和*grass*相关，它们经常一起出现，这是由概率来衡量的。`Word2vec`的输出是`Double`特征的向量。

为了调用`Word2vec`，您需要导入该包：

```scala
import org.apache.spark.ml.feature.Word2Vec

```

首先，您需要初始化一个`Word2vec` Transformer，指定输入列和输出列。在这里，我们选择由`Tokenizer`创建的单词列，并生成大小为 3 的单词向量输出列：

```scala
scala> val word2Vec = new Word2Vec().setInputCol("words").setOutputCol("wordvector").setVectorSize(3).setMinCount(0)
word2Vec: org.apache.spark.ml.feature.Word2Vec = w2v_fe9d488fdb69

```

接下来，在输入数据集上调用`fit()`函数会产生一个输出 Transformer：

```scala
scala> val word2VecModel = word2Vec.fit(noStopWordsDF)
word2VecModel: org.apache.spark.ml.feature.Word2VecModel = w2v_fe9d488fdb69

```

此外，在输入数据集上调用`transform()`函数会产生一个输出数据集：

```scala
scala> val word2VecDF = word2VecModel.transform(noStopWordsDF)
word2VecDF: org.apache.spark.sql.DataFrame = [id: int, sentence: string ... 3 more fields]

```

以下是显示输入列 ID、句子和输出列`wordvector`的输出数据集：

```scala
scala> word2VecDF.show(false)
|id|sentence |words |filteredWords |wordvector |
|1 |Hello there, how do you like the book so far? |[hello, there,, how, do, you, like, the, book, so, far?] |[hello, there,, like, book, far?] |[0.006875938177108765,-0.00819675214588642,0.0040686681866645815]|
|2 |I am new to Machine Learning |[i, am, new, to, machine, learning] |[new, machine, learning] |[0.026012470324834187,0.023195965060343344,-0.10863214979569116] |
|3 |Maybe i should get some coffee before starting |[maybe, i, should, get, some, coffee, before, starting] |[maybe, get, coffee, starting] |[-0.004304863978177309,-0.004591284319758415,0.02117823390290141]|
|4 |Coffee is best when you drink it hot |[coffee, is, best, when, you, drink, it, hot] |[coffee, best, drink, hot] |[0.054064739029854536,-0.003801364451646805,0.06522738828789443] |
|5 |Book stores have coffee too so i should go to a book store|[book, stores, have, coffee, too, so, i, should, go, to, a, book, store]|[book, stores, coffee, go, book, store]|[-0.05887459063281615,-0.07891856770341595,0.07510609552264214] |

```

**Word2Vec 特征**的图如下，显示了单词被转换为向量：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00347.jpeg)

# CountVectorizer

`CountVectorizer`用于将一组文本文档转换为标记计数的向量，从本质上为文档生成稀疏表示。最终结果是一组特征向量，然后可以传递给其他算法。稍后，我们将看到如何在 LDA 算法中使用`CountVectorizer`的输出执行主题检测。

为了调用`CountVectorizer`，您需要导入该包：

```scala
import org.apache.spark.ml.feature.CountVectorizer

```

首先，您需要初始化一个`CountVectorizer` Transformer，指定输入列和输出列。在这里，我们选择由`StopWordRemover`创建的`filteredWords`列，并生成输出列特征：

```scala
scala> val countVectorizer = new CountVectorizer().setInputCol("filteredWords").setOutputCol("features")
countVectorizer: org.apache.spark.ml.feature.CountVectorizer = cntVec_555716178088

```

接下来，在输入数据集上调用`fit()`函数会产生一个输出 Transformer：

```scala
scala> val countVectorizerModel = countVectorizer.fit(noStopWordsDF)
countVectorizerModel: org.apache.spark.ml.feature.CountVectorizerModel = cntVec_555716178088

```

此外，在输入数据集上调用`transform()`函数会产生一个输出数据集。

```scala
scala> val countVectorizerDF = countVectorizerModel.transform(noStopWordsDF)
countVectorizerDF: org.apache.spark.sql.DataFrame = [id: int, sentence: string ... 3 more fields]

```

以下是显示输入列 ID、句子和输出列特征的输出数据集：

```scala
scala> countVectorizerDF.show(false)
|id |sentence |words |filteredWords |features |
|1 |Hello there, how do you like the book so far? |[hello, there,, how, do, you, like, the, book, so, far?] |[hello, there,, like, book, far?] |(18,[1,4,5,13,15],[1.0,1.0,1.0,1.0,1.0])|
|2 |I am new to Machine Learning |[i, am, new, to, machine, learning] |[new, machine, learning] |(18,[6,7,16],[1.0,1.0,1.0]) |
|3 |Maybe i should get some coffee before starting |[maybe, i, should, get, some, coffee, before, starting] |[maybe, get, coffee, starting] |(18,[0,8,9,14],[1.0,1.0,1.0,1.0]) |
|4 |Coffee is best when you drink it hot |[coffee, is, best, when, you, drink, it, hot] |[coffee, best, drink, hot] |(18,[0,3,10,12],[1.0,1.0,1.0,1.0]) |
|5 |Book stores have coffee too so i should go to a book store|[book, stores, have, coffee, too, so, i, should, go, to, a, book, store]|[book, stores, coffee, go, book, store]|(18,[0,1,2,11,17],[1.0,2.0,1.0,1.0,1.0])|

```

`CountVectorizer`的图如下，显示了从`StopWordsRemover`转换生成的特征：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00205.jpeg)

# 使用 LDA 进行主题建模

LDA 是一种主题模型，它从一组文本文档中推断主题。LDA 可以被视为一种无监督的聚类算法，如下所示：

+   主题对应于聚类中心，文档对应于数据集中的行

+   主题和文档都存在于特征空间中，特征向量是单词计数的向量

+   LDA 不是使用传统距离估计聚类，而是使用基于文本文档生成的统计模型的函数

为了调用 LDA，您需要导入该包：

```scala
import org.apache.spark.ml.clustering.LDA

```

**步骤 1.** 首先，您需要初始化一个设置 10 个主题和 10 次聚类的 LDA 模型：

```scala
scala> val lda = new LDA().setK(10).setMaxIter(10)
lda: org.apache.spark.ml.clustering.LDA = lda_18f248b08480

```

**步骤 2.** 在输入数据集上调用`fit()`函数会产生一个输出转换器：

```scala
scala> val ldaModel = lda.fit(countVectorizerDF)
ldaModel: org.apache.spark.ml.clustering.LDAModel = lda_18f248b08480

```

**步骤 3.** 提取`logLikelihood`，它计算了给定推断主题的文档的下限：

```scala
scala> val ll = ldaModel.logLikelihood(countVectorizerDF)
ll: Double = -275.3298948279124

```

**步骤 4.** 提取`logPerplexity`，它计算了给定推断主题的文档的困惑度的上限：

```scala
scala> val lp = ldaModel.logPerplexity(countVectorizerDF)
lp: Double = 12.512670220189033

```

**步骤 5.** 现在，我们可以使用`describeTopics()`来获取 LDA 生成的主题：

```scala
scala> val topics = ldaModel.describeTopics(10)
topics: org.apache.spark.sql.DataFrame = [topic: int, termIndices: array<int> ... 1 more field]

```

**步骤 6.** 以下是 LDA 模型计算的`topic`、`termIndices`和`termWeights`的输出数据集：

```scala
scala> topics.show(10, false)
|topic|termIndices |termWeights |
|0 |[2, 5, 7, 12, 17, 9, 13, 16, 4, 11] |[0.06403877783050851, 0.0638177222807826, 0.06296749987731722, 0.06129482302538905, 0.05906095287220612, 0.0583855194291998, 0.05794181263149175, 0.057342702589298085, 0.05638654243412251, 0.05601913313272188] |
|1 |[15, 5, 13, 8, 1, 6, 9, 16, 2, 14] |[0.06889315890755099, 0.06415969116685549, 0.058990446579892136, 0.05840283223031986, 0.05676844625413551, 0.0566842803396241, 0.05633554021408156, 0.05580861561950114, 0.055116582320533423, 0.05471754535803045] |
|2 |[17, 14, 1, 5, 12, 2, 4, 8, 11, 16] |[0.06230542516700517, 0.06207673834677118, 0.06089143673912089, 0.060721809302399316, 0.06020894045877178, 0.05953822260375286, 0.05897033457363252, 0.057504989644756616, 0.05586725037894327, 0.05562088924566989] |
|3 |[15, 2, 11, 16, 1, 7, 17, 8, 10, 3] |[0.06995373276880751, 0.06249041124300946, 0.061960612781077645, 0.05879695651399876, 0.05816564815895558, 0.05798721645705949, 0.05724374708387087, 0.056034215734402475, 0.05474217418082123, 0.05443850583761207] |
|4 |[16, 9, 5, 7, 1, 12, 14, 10, 13, 4] |[0.06739359010780331, 0.06716438619386095, 0.06391509491709904, 0.062049068666162915, 0.06050715515506004, 0.05925113958472128, 0.057946856127790804, 0.05594837087703049, 0.055000929117413805, 0.053537418286233956]|
|5 |[5, 15, 6, 17, 7, 8, 16, 11, 10, 2] |[0.061611492476326836, 0.06131944264846151, 0.06092975441932787, 0.059812552365763404, 0.05959889552537741, 0.05929123338151455, 0.05899808901872648, 0.05892061664356089, 0.05706951425713708, 0.05636134431063274] |
|6 |[15, 0, 4, 14, 2, 10, 13, 7, 6, 8] |[0.06669864676186414, 0.0613859230159798, 0.05902091745149218, 0.058507882633921676, 0.058373998449322555, 0.05740944364508325, 0.057039150886628136, 0.057021822698594314, 0.05677330199892444, 0.056741558062814376]|
|7 |[12, 9, 8, 15, 16, 4, 7, 13, 17, 10]|[0.06770789917351365, 0.06320078344027158, 0.06225712567900613, 0.058773135159638154, 0.05832535181576588, 0.057727684814461444, 0.056683575112703555, 0.05651178333610803, 0.056202395617563274, 0.05538103218174723]|
|8 |[14, 11, 10, 7, 12, 9, 13, 16, 5, 1]|[0.06757347958335463, 0.06362319365053591, 0.063359294927315, 0.06319462709331332, 0.05969320243218982, 0.058380063437908046, 0.057412693576813126, 0.056710451222381435, 0.056254581639201336, 0.054737785085167814] |
|9 |[3, 16, 5, 7, 0, 2, 10, 15, 1, 13] |[0.06603941595604573, 0.06312775362528278, 0.06248795574460503, 0.06240547032037694, 0.0613859713404773, 0.06017781222489122, 0.05945655694365531, 0.05910351349013983, 0.05751269894725456, 0.05605239791764803] |

```

LDA 的图如下所示，显示了从 TF-IDF 特征创建的主题：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00175.jpeg)

# 实施文本分类

文本分类是机器学习领域中最常用的范例之一，在垃圾邮件检测和电子邮件分类等用例中非常有用，就像任何其他机器学习算法一样，工作流程由转换器和算法构建。在文本处理领域，预处理步骤如去除停用词、词干提取、标记化、n-gram 提取、TF-IDF 特征加权等起着重要作用。一旦所需的处理完成，模型就会被训练来将文档分类为两个或更多类别。

二元分类是将输入分为两个输出类别，例如垃圾邮件/非垃圾邮件和给定的信用卡交易是否欺诈。多类分类可以生成多个输出类别，例如热、冷、冰冻和多雨。还有一种称为多标签分类的技术，可以从汽车特征的描述中生成多个标签，例如速度、安全性和燃油效率。

为此，我们将使用一个包含 10k 条推文的样本数据集，并在该数据集上使用前述技术。然后，我们将将文本行标记为单词，删除停用词，然后使用`CountVectorizer`构建单词（特征）的向量。

然后，我们将数据分为训练（80%）-测试（20%），并训练一个逻辑回归模型。最后，我们将根据测试数据进行评估，并查看其表现如何。

工作流程中的步骤如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00177.jpeg)

**步骤 1.** 加载包含 10k 条推文以及标签和 ID 的输入文本数据：

```scala
scala> val inputText = sc.textFile("Sentiment_Analysis_Dataset10k.csv")
inputText: org.apache.spark.rdd.RDD[String] = Sentiment_Analysis_Dataset10k.csv MapPartitionsRDD[1722] at textFile at <console>:77

```

**步骤 2.** 将输入行转换为 DataFrame：

```scala
scala> val sentenceDF = inputText.map(x => (x.split(",")(0), x.split(",")(1), x.split(",")(2))).toDF("id", "label", "sentence")
sentenceDF: org.apache.spark.sql.DataFrame = [id: string, label: string ... 1 more field]

```

**步骤 3.** 使用带有空格分隔符的`Tokenizer`将数据转换为单词：

```scala
scala> import org.apache.spark.ml.feature.Tokenizer
import org.apache.spark.ml.feature.Tokenizer

scala> val tokenizer = new Tokenizer().setInputCol("sentence").setOutputCol("words")
tokenizer: org.apache.spark.ml.feature.Tokenizer = tok_ebd4c89f166e

scala> val wordsDF = tokenizer.transform(sentenceDF)
wordsDF: org.apache.spark.sql.DataFrame = [id: string, label: string ... 2 more fields]

scala> wordsDF.show(5, true)
| id|label| sentence| words|
| 1| 0|is so sad for my ...|[is, so, sad, for...|
| 2| 0|I missed the New ...|[i, missed, the, ...|
| 3| 1| omg its already ...|[, omg, its, alre...|
| 4| 0| .. Omgaga. Im s...|[, , .., omgaga.,...|
| 5| 0|i think mi bf is ...|[i, think, mi, bf...|

```

**步骤 4.** 删除停用词并创建一个新的 DataFrame，其中包含过滤后的单词：

```scala
scala> import org.apache.spark.ml.feature.StopWordsRemover
import org.apache.spark.ml.feature.StopWordsRemover

scala> val remover = new StopWordsRemover().setInputCol("words").setOutputCol("filteredWords")
remover: org.apache.spark.ml.feature.StopWordsRemover = stopWords_d8dd48c9cdd0

scala> val noStopWordsDF = remover.transform(wordsDF)
noStopWordsDF: org.apache.spark.sql.DataFrame = [id: string, label: string ... 3 more fields]

scala> noStopWordsDF.show(5, true)
| id|label| sentence| words| filteredWords|
| 1| 0|is so sad for my ...|[is, so, sad, for...|[sad, apl, friend...|
| 2| 0|I missed the New ...|[i, missed, the, ...|[missed, new, moo...|
| 3| 1| omg its already ...|[, omg, its, alre...|[, omg, already, ...|
| 4| 0| .. Omgaga. Im s...|[, , .., omgaga.,...|[, , .., omgaga.,...|
| 5| 0|i think mi bf is ...|[i, think, mi, bf...|[think, mi, bf, c...|

```

**步骤 5.** 从过滤后的单词创建特征向量：

```scala
scala> import org.apache.spark.ml.feature.CountVectorizer
import org.apache.spark.ml.feature.CountVectorizer

scala> val countVectorizer = new CountVectorizer().setInputCol("filteredWords").setOutputCol("features")
countVectorizer: org.apache.spark.ml.feature.CountVectorizer = cntVec_fdf1512dfcbd

scala> val countVectorizerModel = countVectorizer.fit(noStopWordsDF)
countVectorizerModel: org.apache.spark.ml.feature.CountVectorizerModel = cntVec_fdf1512dfcbd

scala> val countVectorizerDF = countVectorizerModel.transform(noStopWordsDF)
countVectorizerDF: org.apache.spark.sql.DataFrame = [id: string, label: string ... 4 more fields]

scala> countVectorizerDF.show(5,true)
| id|label| sentence| words| filteredWords| features|
| 1| 0|is so sad for my ...|[is, so, sad, for...|[sad, apl, friend...|(23481,[35,9315,2...|
| 2| 0|I missed the New ...|[i, missed, the, ...|[missed, new, moo...|(23481,[23,175,97...|
| 3| 1| omg its already ...|[, omg, its, alre...|[, omg, already, ...|(23481,[0,143,686...|
| 4| 0| .. Omgaga. Im s...|[, , .., omgaga.,...|[, , .., omgaga.,...|(23481,[0,4,13,27...|
| 5| 0|i think mi bf is ...|[i, think, mi, bf...|[think, mi, bf, c...|(23481,[0,33,731,...|

```

**步骤 6.** 创建只有标签和特征的`inputData` DataFrame：

```scala

scala> val inputData=countVectorizerDF.select("label", "features").withColumn("label", col("label").cast("double"))
inputData: org.apache.spark.sql.DataFrame = [label: double, features: vector]

```

**步骤 7.** 使用随机拆分将数据拆分为 80%的训练数据集和 20%的测试数据集：

```scala
scala> val Array(trainingData, testData) = inputData.randomSplit(Array(0.8, 0.2))
trainingData: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [label: double, features: vector]
testData: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [label: double, features: vector]

```

**步骤 8.** 创建一个逻辑回归模型：

```scala
scala> import org.apache.spark.ml.classification.LogisticRegression
import org.apache.spark.ml.classification.LogisticRegression

scala> val lr = new LogisticRegression()
lr: org.apache.spark.ml.classification.LogisticRegression = logreg_a56accef5728

```

**步骤 9.** 通过拟合`trainingData`创建一个逻辑回归模型：

```scala
scala> var lrModel = lr.fit(trainingData)
lrModel: org.apache.spark.ml.classification.LogisticRegressionModel = logreg_a56accef5728

scala> lrModel.coefficients
res160: org.apache.spark.ml.linalg.Vector = [7.499178040193577,8.794520490564185,4.837543313917086,-5.995818019393418,1.1754740390468577,3.2104594489397584,1.7840290776286476,-1.8391923375331787,1.3427471762591,6.963032309971087,-6.92725055841986,-10.781468845891563,3.9752.836891070557657,3.8758544006087523,-11.760894935576934,-6.252988307540...

scala> lrModel.intercept
res161: Double = -5.397920610780994

```

**步骤 10.** 检查模型摘要，特别是`areaUnderROC`，对于一个好的模型应该是*> 0.90*：

```scala
scala> import org.apache.spark.ml.classification.BinaryLogisticRegressionSummary
import org.apache.spark.ml.classification.BinaryLogisticRegressionSummary

scala> val summary = lrModel.summary
summary: org.apache.spark.ml.classification.LogisticRegressionTrainingSummary = org.apache.spark.ml.classification.BinaryLogisticRegressionTrainingSummary@1dce712c

scala> val bSummary = summary.asInstanceOf[BinaryLogisticRegressionSummary]
bSummary: org.apache.spark.ml.classification.BinaryLogisticRegressionSummary = org.apache.spark.ml.classification.BinaryLogisticRegressionTrainingSummary@1dce712c

scala> bSummary.areaUnderROC
res166: Double = 0.9999231930196596

scala> bSummary.roc
res167: org.apache.spark.sql.DataFrame = [FPR: double, TPR: double]

scala> bSummary.pr.show()
| recall|precision|
| 0.0| 1.0|
| 0.2306543172990738| 1.0|
| 0.2596354944726621| 1.0|
| 0.2832387212429041| 1.0|
|0.30504929787869733| 1.0|
| 0.3304451747833881| 1.0|
|0.35255452644158947| 1.0|
| 0.3740663280549746| 1.0|
| 0.3952793546459516| 1.0|

```

**步骤 11.** 使用训练和测试数据集使用训练好的模型进行转换：

```scala
scala> val training = lrModel.transform(trainingData)
training: org.apache.spark.sql.DataFrame = [label: double, features: vector ... 3 more fields]

scala> val test = lrModel.transform(testData)
test: org.apache.spark.sql.DataFrame = [label: double, features: vector ... 3 more fields]

```

**步骤 12.** 计算具有匹配标签和预测列的记录数。它们应该匹配以进行正确的模型评估，否则它们将不匹配：

```scala
scala> training.filter("label == prediction").count
res162: Long = 8029

scala> training.filter("label != prediction").count
res163: Long = 19

scala> test.filter("label == prediction").count
res164: Long = 1334

scala> test.filter("label != prediction").count
res165: Long = 617

```

结果可以放入下表中：

| **数据集** | **总数** | **标签==预测** | **标签！=预测** |
| --- | --- | --- | --- |
| **训练** | 8048 | 8029 ( 99.76%) | 19 (0.24%) |
| **测试** | 1951 | 1334 (68.35%) | 617 (31.65%) |

虽然训练数据产生了很好的匹配，但测试数据只有 68.35%的匹配。因此，还有改进的空间，可以通过探索模型参数来实现。

逻辑回归是一种易于理解的方法，用于使用输入的线性组合和逻辑随机变量的随机噪声来预测二元结果。因此，可以使用多个参数来调整逻辑回归模型。（本章不涵盖调整此类逻辑回归模型的全部参数及方法。）

可以用于调整模型的一些参数是：

+   模型超参数包括以下参数：

+   `elasticNetParam`：此参数指定您希望如何混合 L1 和 L2 正则化

+   `regParam`：此参数确定输入在传递到模型之前应如何正则化

+   训练参数包括以下参数：

+   `maxIter`：这是停止之前的总交互次数

+   `weightCol`：这是用于对某些行进行加权的权重列的名称

+   预测参数包括以下参数：

+   `threshold`：这是用于二元预测的概率阈值。这决定了预测给定类别的最小概率。

我们现在已经了解了如何构建一个简单的分类模型，因此可以根据训练集对任何新的推文进行标记。逻辑回归只是可以使用的模型之一。

可以用于替代逻辑回归的其他模型如下：

+   决策树

+   随机森林

+   梯度提升树

+   多层感知器

# 摘要

在本章中，我们介绍了使用 Spark ML 进行文本分析的世界，重点是文本分类。我们了解了转换器和估计器。我们看到了如何使用分词器将句子分解为单词，如何去除停用词，并生成 n-gram。我们还看到了如何实现`HashingTF`和`IDF`来生成基于 TF-IDF 的特征。我们还研究了`Word2Vec`如何将单词序列转换为向量。

然后，我们还研究了 LDA，这是一种流行的技术，用于从文档中生成主题，而不需要了解实际文本。最后，我们在 Twitter 数据集的 10k 条推文集上实现了文本分类，以查看如何使用转换器、估计器和逻辑回归模型来执行二元分类。

在下一章中，我们将更深入地探讨调整 Spark 应用程序以获得更好性能。


# 第十六章：Spark 调优

“竖琴手的 90%的时间都在调琴，10%的时间在弹走音。”

- 伊戈尔·斯特拉文斯基

在本章中，我们将深入了解 Apache Spark 的内部，并看到，虽然 Spark 在让我们感觉像是在使用另一个 Scala 集合方面做得很好，但我们不必忘记 Spark 实际上是在分布式系统中运行的。因此，需要额外小心。简而言之，本章将涵盖以下主题：

+   监视 Spark 作业

+   Spark 配置

+   Spark 应用程序开发中的常见错误

+   优化技术

# 监视 Spark 作业

Spark 为监视计算节点（驱动程序或执行程序）上运行或已完成的所有作业提供了 Web UI。在本节中，我们将简要讨论如何使用适当的示例使用 Spark Web UI 监视 Spark 作业的进度。我们将看到如何监视作业的进度（包括已提交、排队和运行的作业）。将简要讨论 Spark Web UI 中的所有选项卡。最后，我们将讨论 Spark 的日志记录过程，以便更好地进行调优。

# Spark Web 界面

Web UI（也称为 Spark UI）是用于在 Web 浏览器（如 Firefox 或 Google Chrome）上监视 Spark 应用程序的执行的 Web 界面。当 SparkContext 启动时，独立模式下将在端口 4040 上启动显示有关应用程序的有用信息的 Web UI。Spark Web UI 的可用性取决于应用程序是否仍在运行或已完成执行。

此外，您可以在应用程序完成执行后使用 Web UI，方法是使用`EventLoggingListener`持久化所有事件。但是，`EventLoggingListener`不能单独工作，需要结合 Spark 历史服务器。结合这两个功能，可以实现以下功能：

+   调度程序阶段和任务的列表

+   RDD 大小的摘要

+   内存使用情况

+   环境信息

+   有关正在运行的执行程序的信息

您可以在 Web 浏览器中访问 UI，网址为`http://<driver-node>:4040`。例如，以独立模式提交并运行的 Spark 作业可以在`http://localhost:4040`上访问。

请注意，如果同一主机上运行多个 SparkContext，则它们将绑定到从 4040 开始的连续端口，如 4040、4041、4042 等。默认情况下，此信息仅在您的 Spark 应用程序运行期间可用。这意味着当您的 Spark 作业完成执行时，绑定将不再有效或可访问。

只要作业正在运行，就可以在 Spark UI 上观察到阶段。但是，要在作业完成执行后查看 Web UI，可以尝试在提交 Spark 作业之前将`spark.eventLog.enabled`设置为 true。这将强制 Spark 记录所有已在存储中持久化的事件，以便在 UI 中显示。

在上一章中，我们看到如何将 Spark 作业提交到集群。让我们重用提交 k 均值聚类的命令之一，如下所示：

```scala
# Run application as standalone mode on 8 cores
SPARK_HOME/bin/spark-submit \
 --class org.apache.spark.examples.KMeansDemo \
 --master local[8] \
 KMeansDemo-0.1-SNAPSHOT-jar-with-dependencies.jar \
 Saratoga_NY_Homes.txt

```

如果使用上述命令提交作业，则将无法查看已完成执行的作业的状态，因此要使更改永久生效，请使用以下两个选项：

```scala
spark.eventLog.enabled=true 
spark.eventLog.dir=file:///home/username/log"

```

通过设置前两个配置变量，我们要求 Spark 驱动程序启用事件记录以保存在`file:///home/username/log`。

总之，通过以下更改，您的提交命令将如下所示：

```scala
# Run application as standalone mode on 8 cores
SPARK_HOME/bin/spark-submit \
 --conf "spark.eventLog.enabled=true" \
 --conf "spark.eventLog.dir=file:///tmp/test" \
 --class org.apache.spark.examples.KMeansDemo \
 --master local[8] \
 KMeansDemo-0.1-SNAPSHOT-jar-with-dependencies.jar \
 Saratoga_NY_Homes.txt

```

图 1：Spark Web UI

如前面的屏幕截图所示，Spark Web UI 提供以下选项卡：

+   作业

+   阶段

+   存储

+   环境

+   执行程序

+   SQL

需要注意的是，并非所有功能都可以一次性显示，因为它们是按需懒惰创建的，例如，在运行流式作业时。

# 作业

根据 SparkContext 的不同，作业选项卡显示了 Spark 应用程序中所有 Spark 作业的状态。当您在 Spark UI 上使用 Web 浏览器访问`http://localhost:4040`的作业选项卡（对于独立模式），您应该观察以下选项：

+   用户：显示已提交 Spark 作业的活跃用户

+   总正常运行时间：显示作业的总正常运行时间

+   调度模式：在大多数情况下，它是先进先出（FIFO）模式

+   活跃作业：显示活跃作业的数量

+   已完成的作业：显示已完成的作业数量

+   事件时间轴：显示已完成执行的作业的时间轴

在内部，作业选项卡由`JobsTab`类表示，它是一个带有作业前缀的自定义 SparkUI 选项卡。作业选项卡使用`JobProgressListener`来访问有关 Spark 作业的统计信息，以在页面上显示上述信息。请查看以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00135.jpeg)**图 2：**Spark Web UI 中的作业选项卡

如果您在作业选项卡中进一步展开“Active Jobs”选项，您将能够看到执行计划、状态、已完成阶段的数量以及该特定作业的作业 ID，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00185.jpeg)**图 3：**Spark Web UI 中任务的 DAG 可视化（摘要）

当用户在 Spark 控制台（例如，Spark shell 或使用 Spark submit）中输入代码时，Spark Core 会创建一个操作符图。这基本上是当用户在特定节点上执行操作（例如，reduce、collect、count、first、take、countByKey、saveAsTextFile）或转换（例如，map、flatMap、filter、mapPartitions、sample、union、intersection、distinct）时发生的情况，这些操作是在 RDD 上进行的（它们是不可变对象）。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00187.jpeg)**图 4：**DAG 调度程序将 RDD 谱系转换为阶段 DAG

在转换或操作期间，使用**有向无环图**（**DAG**）信息来将节点恢复到最后的转换和操作（参见*图 4*和*图 5*以获得更清晰的图像），以维护数据的弹性。最后，图被提交给 DAG 调度程序。

Spark 如何从 RDD 计算 DAG，然后执行任务？

在高层次上，当 RDD 上调用任何操作时，Spark 会创建 DAG 并将其提交给 DAG 调度程序。DAG 调度程序将操作符划分为任务阶段。一个阶段包括基于输入数据的分区的任务。DAG 调度程序将操作符进行流水线处理。例如，可以在单个阶段中安排多个 map 操作符。DAG 调度程序的最终结果是一组阶段。这些阶段被传递给任务调度程序。任务调度程序通过集群管理器（Spark Standalone/YARN/Mesos）启动任务。任务调度程序不知道阶段的依赖关系。工作节点在阶段上执行任务。

然后，DAG 调度程序跟踪阶段输出的 RDDs。然后，它找到运行作业的最小调度，并将相关的操作符划分为任务阶段。基于输入数据的分区，一个阶段包括多个任务。然后，操作符与 DAG 调度程序一起进行流水线处理。实际上，可以在单个阶段中安排多个 map 或 reduce 操作符（例如）。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00191.jpeg)**图 5：**执行操作导致 DAGScheduler 中的新 ResultStage 和 ActiveJob

DAG 调度程序中的两个基本概念是作业和阶段。因此，它必须通过内部注册表和计数器来跟踪它们。从技术上讲，DAG 调度程序是 SparkContext 初始化的一部分，它专门在驱动程序上工作（在任务调度程序和调度程序后端准备就绪后立即进行）。DAG 调度程序在 Spark 执行中负责三项主要任务。它计算作业的执行 DAG，即阶段的 DAG。它确定每个任务运行的首选节点，并处理由于丢失洗牌输出文件而导致的故障。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00193.jpeg)**图 6：** 由 SparkContext 创建的 DAGScheduler 与其他服务

DAG 调度程序的最终结果是一组阶段。因此，大部分统计信息和作业的状态可以使用此可视化来查看，例如执行计划、状态、已完成阶段的数量以及该特定作业的作业 ID。

# 阶段

Spark UI 中的阶段选项卡显示了 Spark 应用程序中所有阶段的当前状态，包括任务和阶段的统计信息以及池详细信息的两个可选页面。请注意，此信息仅在应用程序以公平调度模式运行时才可用。您应该能够在`http://localhost:4040/stages`上访问阶段选项卡。请注意，当没有提交作业时，该选项卡除了标题外什么也不显示。阶段选项卡显示了 Spark 应用程序中的阶段。该选项卡中可以看到以下阶段：

+   活动阶段

+   待处理的阶段

+   已完成的阶段

例如，当您在本地提交一个 Spark 作业时，您应该能够看到以下状态：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00265.jpeg)**图 7：** Spark Web UI 中所有作业的阶段

在这种情况下，只有一个处于活动状态的阶段。然而，在接下来的章节中，当我们将 Spark 作业提交到 AWS EC2 集群时，我们将能够观察到其他阶段。

要进一步了解已完成作业的摘要，请单击描述列中包含的任何链接，您应该能够找到与执行时间相关的统计信息。在以下图中还可以看到指标的最小值、中位数、25th 百分位数、75th 百分位数和最大值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00378.jpeg)**图 8：** Spark Web UI 上已完成作业的摘要

您的情况可能不同，因为在撰写本书期间，我只执行和提交了两个作业以进行演示。您还可以查看有关执行程序的其他统计信息。对于我的情况，我使用 8 个核心和 32GB 的 RAM 在独立模式下提交了这些作业。此外，还显示了与执行程序相关的信息，例如 ID、关联端口号的 IP 地址、任务完成时间、任务数量（包括失败任务、被杀任务和成功任务的数量）以及数据集每条记录的输入大小。

图像中的另一部分显示了与这两个任务相关的其他信息，例如索引、ID、尝试次数、状态、本地级别、主机信息、启动时间、持续时间，垃圾收集（GC）时间等。

# 存储

存储选项卡显示了每个 RDD、DataFrame 或 Dataset 的大小和内存使用情况。您应该能够看到 RDD、DataFrame 或 Dataset 的存储相关信息。以下图显示了存储元数据，如 RDD 名称、存储级别、缓存分区的数量、缓存的数据比例的百分比以及 RDD 在主内存中的大小：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00229.jpeg)**图 9：** 存储选项卡显示 RDD 在磁盘中消耗的空间

请注意，如果 RDD 无法缓存在主内存中，则将使用磁盘空间。本章的后续部分将进行更详细的讨论。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00067.jpeg)**图 10：** 数据分布和 RDD 在磁盘中使用的存储

# 环境

环境选项卡显示了当前设置在您的机器（即驱动程序）上的环境变量。更具体地说，可以在运行时信息下看到 Java Home、Java Version 和 Scala Version 等运行时信息。还可以看到 Spark 属性，如 Spark 应用程序 ID、应用程序名称、驱动程序主机信息、驱动程序端口、执行程序 ID、主 URL 和调度模式。此外，还可以在系统属性下看到其他与系统相关的属性和作业属性，例如 AWT 工具包版本、文件编码类型（例如 UTF-8）和文件编码包信息（例如 sun.io）。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00249.jpeg)**图 11：** Spark Web UI 上的环境选项卡

# 执行程序

执行器选项卡使用`ExecutorsListener`收集有关 Spark 应用程序的执行器信息。执行器是负责执行任务的分布式代理。执行器以不同的方式实例化。例如，当`CoarseGrainedExecutorBackend`接收到 Spark Standalone 和 YARN 的`RegisteredExecutor`消息时，它们可以被实例化。第二种情况是当 Spark 作业提交到 Mesos 时。Mesos 的`MesosExecutorBackend`会被注册。第三种情况是当您在本地运行 Spark 作业时，即创建`LocalEndpoint`。执行器通常在 Spark 应用程序的整个生命周期内运行，这称为执行器的静态分配，尽管您也可以选择动态分配。执行器后端专门管理计算节点或集群中的所有执行器。执行器定期向驱动程序的**HeartbeatReceiver** RPC 端点报告活动任务的心跳和部分指标，并将结果发送给驱动程序。它们还通过块管理器为用户程序缓存的 RDD 提供内存存储。有关此内容的更清晰的想法，请参考以下图：

图 12：Spark 驱动程序实例化一个执行器，负责处理 HeartbeatReceiver 的心跳消息处理程序

当执行器启动时，它首先向驱动程序注册，并直接通信以执行任务，如下图所示：

图 13：使用 TaskRunners 在执行器上启动任务

您应该能够在`http://localhost:4040/executors`访问执行器选项卡。

图 14：Spark Web UI 上的执行器选项卡

如前图所示，可以看到有关执行器的执行器 ID、地址、状态、RDD 块、存储内存、已使用磁盘、核心、活动任务、失败任务、完成任务、总任务、任务时间（GC 时间）、输入、Shuffle 读取、Shuffle 写入以及线程转储的信息。

# SQL

Spark UI 中的 SQL 选项卡显示每个操作符的所有累加器值。您应该能够在`http://localhost:4040/SQL/`访问 SQL 选项卡。它默认显示所有 SQL 查询执行和底层信息。但是，只有在选择查询后，SQL 选项卡才会显示 SQL 查询执行的详细信息。

关于 SQL 的详细讨论超出了本章的范围。感兴趣的读者应参考[`spark.apache.org/docs/latest/sql-programming-guide.html#sql`](http://spark.apache.org/docs/latest/sql-programming-guide.html#sql)了解如何提交 SQL 查询并查看其结果输出。

# 使用 Web UI 可视化 Spark 应用程序

当提交 Spark 作业进行执行时，将启动一个 Web 应用程序 UI，显示有关应用程序的有用信息。事件时间轴显示应用程序事件的相对顺序和交错。时间轴视图可在三个级别上使用：跨所有作业、在一个作业内以及在一个阶段内。时间轴还显示执行器的分配和释放。

图 15：Spark 作业在 Spark Web UI 上以 DAG 形式执行

# 观察正在运行和已完成的 Spark 作业

要访问和观察正在运行和已完成的 Spark 作业，请在 Web 浏览器中打开`http://spark_driver_host:4040`。请注意，您将需要相应地用 IP 地址或主机名替换`spark_driver_host`。

请注意，如果同一主机上运行多个 SparkContexts，它们将绑定到从 4040 开始的连续端口，4040、4041、4042 等。默认情况下，此信息仅在您的 Spark 应用程序运行期间可用。这意味着当您的 Spark 作业完成执行时，绑定将不再有效或可访问。

现在，要访问仍在执行的活动作业，请单击 Active Jobs 链接，您将看到这些作业的相关信息。另一方面，要访问已完成作业的状态，请单击 Completed Jobs，您将看到信息以 DAG 样式显示，如前一节所述。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00129.jpeg)**图 16：**观察正在运行和已完成的 Spark 作业

您可以通过单击 Active Jobs 或 Completed Jobs 下的作业描述链接来实现这些。

# 使用日志调试 Spark 应用程序

查看所有正在运行的 Spark 应用程序的信息取决于您使用的集群管理器。在调试 Spark 应用程序时，应遵循这些说明：

+   **Spark Standalone**：转到`http://master:18080`上的 Spark 主 UI。主节点和每个工作节点显示集群和相关作业统计信息。此外，每个作业的详细日志输出也写入到每个工作节点的工作目录中。我们将讨论如何使用`log4j`手动启用日志记录。

+   **YARN**：如果您的集群管理器是 YARN，并且假设您正在 Cloudera（或任何其他基于 YARN 的平台）上运行 Spark 作业，则转到 Cloudera Manager 管理控制台中的 YARN 应用程序页面。现在，要调试在 YARN 上运行的 Spark 应用程序，请查看 Node Manager 角色的日志。要实现这一点，打开日志事件查看器，然后过滤事件流以选择时间窗口和日志级别，并显示 Node Manager 源。您也可以通过命令访问日志。命令的格式如下：

```scala
 yarn logs -applicationId <application ID> [OPTIONS]

```

例如，以下是这些 ID 的有效命令：

```scala
 yarn logs -applicationId application_561453090098_0005 
 yarn logs -applicationId application_561453090070_0005 userid

```

请注意，用户 ID 是不同的。但是，只有在`yarn-site.xml`中的`yarn.log-aggregation-enable`为 true 并且应用程序已经完成执行时，才是真的。

# 使用 log4j 记录 Spark

Spark 使用`log4j`进行自身的日志记录。发生在后端的所有操作都会记录到 Spark shell 控制台（已配置为基础存储）。Spark 提供了`log4j`的属性文件模板，我们可以扩展和修改该文件以记录 Spark 中的日志。转到`SPARK_HOME/conf`目录，您应该看到`log4j.properties.template`文件。这可以作为我们自己日志系统的起点。

现在，让我们在运行 Spark 作业时创建自己的自定义日志系统。完成后，将文件重命名为`log4j.properties`并将其放在相同的目录（即项目树）下。文件的示例快照如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00112.jpeg)**图 17：**log4j.properties 文件的快照

默认情况下，所有内容都会输出到控制台和文件。但是，如果您想将所有噪音日志绕过并记录到系统文件中，例如`/var/log/sparkU.log`，则可以在`log4j.properties`文件中设置这些属性如下：

```scala
log4j.logger.spark.storage=INFO, RollingAppender
log4j.additivity.spark.storage=false
log4j.logger.spark.scheduler=INFO, RollingAppender
log4j.additivity.spark.scheduler=false
log4j.logger.spark.CacheTracker=INFO, RollingAppender
log4j.additivity.spark.CacheTracker=false
log4j.logger.spark.CacheTrackerActor=INFO, RollingAppender
log4j.additivity.spark.CacheTrackerActor=false
log4j.logger.spark.MapOutputTrackerActor=INFO, RollingAppender
log4j.additivity.spark.MapOutputTrackerActor=false
log4j.logger.spark.MapOutputTracker=INFO, RollingAppender
log4j.additivty.spark.MapOutputTracker=false

```

基本上，我们希望隐藏 Spark 生成的所有日志，以便我们不必在 shell 中处理它们。我们将它们重定向到文件系统中进行记录。另一方面，我们希望我们自己的日志记录在 shell 和单独的文件中进行记录，以便它们不会与 Spark 的日志混在一起。从这里，我们将指向 Splunk 的文件，其中我们自己的日志记录，特别是`/var/log/sparkU.log`*.*

然后，当应用程序启动时，Spark 会读取`log4j.properties`文件，因此我们除了将其放在指定位置外，无需进行其他操作。

现在让我们看看如何创建我们自己的日志记录系统。看看以下代码，并尝试理解这里发生了什么：

```scala
import org.apache.spark.{SparkConf, SparkContext}
import org.apache.log4j.LogManager
import org.apache.log4j.Level
import org.apache.log4j.Logger

object MyLog {
 def main(args: Array[String]):Unit= {
   // Stting logger level as WARN
   val log = LogManager.getRootLogger
   log.setLevel(Level.WARN)

   // Creating Spark Context
   val conf = new SparkConf().setAppName("My App").setMaster("local[*]")
   val sc = new SparkContext(conf)

   //Started the computation and printing the logging information
   log.warn("Started")                        
   val data = sc.parallelize(1 to 100000)
   log.warn("Finished")
 }
}

```

前面的代码概念上仅记录警告消息。它首先打印警告消息，然后通过并行化从 1 到 100,000 的数字创建 RDD。一旦 RDD 作业完成，它会打印另一个警告日志。但是，我们尚未注意到先前代码段中的问题。

`org.apache.log4j.Logger`类的一个缺点是它不可序列化（有关更多详细信息，请参阅优化技术部分），这意味着我们不能在对 Spark API 的某些部分进行操作时在*闭包*内使用它。例如，如果尝试执行以下代码，则应该会遇到一个说任务不可序列化的异常：

```scala
object MyLog {
  def main(args: Array[String]):Unit= {
    // Stting logger level as WARN
    val log = LogManager.getRootLogger
    log.setLevel(Level.WARN)
    // Creating Spark Context
    val conf = new SparkConf().setAppName("My App").setMaster("local[*]")
    val sc = new SparkContext(conf)
    //Started the computation and printing the logging information
    log.warn("Started")
    val i = 0
    val data = sc.parallelize(i to 100000)
    data.foreach(i => log.info("My number"+ i))
    log.warn("Finished")
  }
}

```

解决这个问题也很容易；只需声明带有`extends Serializable`的 Scala 对象，现在代码看起来如下：

```scala
class MyMapper(n: Int) extends Serializable{
  @transient lazy val log = org.apache.log4j.LogManager.getLogger
                                ("myLogger")
  def MyMapperDosomething(rdd: RDD[Int]): RDD[String] =
   rdd.map{ i =>
    log.warn("mapping: " + i)
    (i + n).toString
  }
}

```

在前面的代码中发生的情况是，闭包无法整洁地分布到所有分区，因为它无法关闭记录器；因此，类型为`MyMapper`的整个实例分布到所有分区；一旦完成此操作，每个分区都会创建一个新的记录器并用于记录。

总之，以下是帮助我们摆脱这个问题的完整代码：

```scala
package com.example.Personal
import org.apache.log4j.{Level, LogManager, PropertyConfigurator}
import org.apache.spark._
import org.apache.spark.rdd.RDD

class MyMapper(n: Int) extends Serializable{
  @transient lazy val log = org.apache.log4j.LogManager.getLogger
                                ("myLogger")
  def MyMapperDosomething(rdd: RDD[Int]): RDD[String] =
   rdd.map{ i =>
    log.warn("Serialization of: " + i)
    (i + n).toString
  }
}

object MyMapper{
  def apply(n: Int): MyMapper = new MyMapper(n)
}

object MyLog {
  def main(args: Array[String]) {
    val log = LogManager.getRootLogger
    log.setLevel(Level.WARN)
    val conf = new SparkConf().setAppName("My App").setMaster("local[*]")
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

我们将在下一节讨论 Spark 的内置日志记录。

# Spark 配置

有多种方法可以配置您的 Spark 作业。在本节中，我们将讨论这些方法。更具体地说，根据 Spark 2.x 版本，有三个位置可以配置系统：

+   Spark 属性

+   环境变量

+   日志记录

# Spark 属性

如前所述，Spark 属性控制大部分应用程序特定的参数，并且可以使用 Spark 的`SparkConf`对象进行设置。或者，这些参数可以通过 Java 系统属性进行设置。`SparkConf`允许您配置一些常见属性，如下所示：

```scala
setAppName() // App name 
setMaster() // Master URL 
setSparkHome() // Set the location where Spark is installed on worker nodes. 
setExecutorEnv() // Set single or multiple environment variables to be used when launching executors. 
setJars() // Set JAR files to distribute to the cluster. 
setAll() // Set multiple parameters together.

```

应用程序可以配置为使用计算机上的多个可用核心。例如，我们可以初始化一个具有两个线程的应用程序如下。请注意，我们使用`local [2]`运行，表示两个线程，这代表最小的并行性，并使用`local [*]`，它利用计算机上所有可用的核心。或者，您可以在提交 Spark 作业时使用以下 spark-submit 脚本指定执行程序的数量：

```scala
val conf = new SparkConf() 
             .setMaster("local[2]") 
             .setAppName("SampleApp") 
val sc = new SparkContext(conf)

```

可能会有一些特殊情况，您需要在需要时动态加载 Spark 属性。您可以在通过 spark-submit 脚本提交 Spark 作业时执行此操作。更具体地说，您可能希望避免在`SparkConf`中硬编码某些配置。

Apache Spark 优先级：

Spark 对提交的作业具有以下优先级：来自配置文件的配置具有最低优先级。来自实际代码的配置相对于来自配置文件的配置具有更高的优先级，而通过 Spark-submit 脚本通过 CLI 传递的配置具有更高的优先级。

例如，如果要使用不同的主节点、执行程序或不同数量的内存运行应用程序，Spark 允许您简单地创建一个空配置对象，如下所示：

```scala
val sc = new SparkContext(new SparkConf())

```

然后您可以在运行时为您的 Spark 作业提供配置，如下所示：

```scala
SPARK_HOME/bin/spark-submit 
 --name "SmapleApp" \
 --class org.apache.spark.examples.KMeansDemo \
 --master mesos://207.184.161.138:7077 \ # Use your IP address
 --conf spark.eventLog.enabled=false 
 --conf "spark.executor.extraJavaOptions=-XX:+PrintGCDetails" \ 
 --deploy-mode cluster \
 --supervise \
 --executor-memory 20G \
 myApp.jar

```

`SPARK_HOME/bin/spark-submit`还将从`SPARK_HOME /conf/spark-defaults.conf`中读取配置选项，其中每行由空格分隔的键和值组成。示例如下：

```scala
spark.master  spark://5.6.7.8:7077 
spark.executor.memor y   4g 
spark.eventLog.enabled true 
spark.serializer org.apache.spark.serializer.KryoSerializer

```

在属性文件中指定为标志的值将传递给应用程序，并与通过`SparkConf`指定的值合并。最后，如前所述，应用程序 Web UI 在`http://<driver>:4040`下的环境选项卡下列出所有 Spark 属性。

# 环境变量

环境变量可用于设置计算节点或机器设置中的设置。例如，IP 地址可以通过每个计算节点上的`conf/spark-env.sh`脚本进行设置。以下表列出了需要设置的环境变量的名称和功能：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00116.gif)**图 18：**环境变量及其含义

# 日志记录

最后，可以通过在 Spark 应用程序树下的`log4j.properties`文件中配置日志记录，如前一节所述。Spark 使用 log4j 进行日志记录。log4j 支持几个有效的日志记录级别，它们如下：

| **日志级别** | **用途** |
| --- | --- |
| OFF | 这是最具体的，完全不允许记录日志 |
| FATAL | 这是最具体的，显示了有很少数据的严重错误 |
| ERROR | 这只显示一般错误 |
| WARN | 这显示了建议修复但不是强制的警告 |
| INFO | 这显示了您的 Spark 作业所需的信息 |
| DEBUG | 在调试时，这些日志将被打印 |
| TRACE | 这提供了具有大量数据的最不具体的错误跟踪 |
| ALL | 具有所有数据的最不具体的消息 |

**表 1：** 使用 log4j 和 Spark 的日志级别

您可以在`conf/log4j.properties`中设置 Spark shell 的默认日志记录。在独立的 Spark 应用程序中或在 Spark Shell 会话中，可以使用`conf/log4j.properties.template`作为起点。在本章的前一节中，我们建议您在像 Eclipse 这样的基于 IDE 的环境中将`log4j.properties`文件放在项目目录下。但是，要完全禁用日志记录，您应该将以下`conf/log4j.properties.template`设置为`log4j.properties`。只需将`log4j.logger.org`标志设置为 OFF，如下所示：

```scala
log4j.logger.org=OFF

```

在下一节中，我们将讨论开发和提交 Spark 作业时开发人员或程序员常犯的一些常见错误。

# Spark 应用程序开发中的常见错误

经常发生的常见错误包括应用程序失败、由于多种因素而卡住的作业运行缓慢、聚合操作中的错误、动作或转换中的错误、主线程中的异常，当然还有**内存不足**（**OOM**）。

# 应用程序失败

大多数情况下，应用程序失败是因为一个或多个阶段最终失败。如本章前面所述，Spark 作业包括多个阶段。阶段不是独立执行的：例如，处理阶段无法在相关的输入读取阶段之前发生。因此，假设阶段 1 成功执行，但阶段 2 无法执行，整个应用程序最终将失败。可以如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00119.jpeg)**图 19：** 典型 Spark 作业中的两个阶段

举个例子，假设您有以下三个 RDD 操作作为阶段。可以将其可视化为*图 20*、*图 21*和*图 22*所示：

```scala
val rdd1 = sc.textFile(“hdfs://data/data.csv”)
                       .map(someMethod)
                       .filter(filterMethod)   

```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00157.jpeg)**图 20：** rdd1 的第 1 阶段

```scala
val rdd2 = sc.hadoopFile(“hdfs://data/data2.csv”)
                      .groupByKey()
                      .map(secondMapMethod)

```

从概念上讲，可以如*图 21*所示，首先使用`hadoopFile()`方法解析数据，然后使用`groupByKey()`方法对其进行分组，最后对其进行映射：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00090.jpeg)**图 21：** rdd2 的第 2 阶段

```scala
val rdd3 = rdd1.join(rdd2).map(thirdMapMethod)

```

从概念上讲，可以如*图 22*所示，首先解析数据，然后将其连接，最后映射：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00144.jpeg)**图 22：** rdd3 的第 3 阶段

现在，您可以执行聚合函数，例如 collect，如下所示：

```scala
rdd3.collect()

```

噢！您已经开发了一个包含三个阶段的 Spark 作业。从概念上讲，可以如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00041.jpeg)**图 23：** rdd3.collect()操作的三个阶段

现在，如果其中一个阶段失败，您的作业最终将失败。因此，最终的`rdd3.collect()`语句将抛出有关阶段失败的异常。此外，您可能会遇到以下四个因素的问题：

+   聚合操作中的错误

+   主线程中的异常

+   OOP

+   使用`spark-submit`脚本提交作业时出现类找不到异常

+   Spark 核心库中一些 API/方法的误解

为了摆脱上述问题，我们的一般建议是确保在执行任何 map、flatMap 或 aggregate 操作时没有犯任何错误。其次，在使用 Java 或 Scala 开发应用程序的主方法中确保没有缺陷。有时您在代码中看不到任何语法错误，但重要的是您为应用程序开发了一些小的测试用例。主方法中最常见的异常如下：

+   `java.lang.noclassdeffounderror`

+   `java.lang.nullpointerexception`

+   `java.lang.arrayindexoutofboundsexception`

+   `java.lang.stackoverflowerror`

+   `java.lang.classnotfoundexception`

+   `java.util.inputmismatchexception`

通过谨慎编写 Spark 应用程序可以避免这些异常。或者，广泛使用 Eclipse（或任何其他 IDE）的代码调试功能来消除语义错误以避免异常。对于第三个问题，即 OOM，这是一个非常常见的问题。需要注意的是，Spark 至少需要 8GB 的主内存，并且独立模式下需要足够的磁盘空间。另一方面，为了获得完整的集群计算功能，这个要求通常很高。

准备一个包含所有依赖项的 JAR 文件来执行 Spark 作业非常重要。许多从业者使用谷歌的 Guava；它包含在大多数发行版中，但不能保证向后兼容。这意味着有时即使您明确提供了 Guava 类，您的 Spark 作业也找不到 Guava 类；这是因为 Guava 库的两个版本中的一个优先于另一个，而这个版本可能不包括所需的类。为了解决这个问题，通常会使用 shading。

确保如果您使用 IntelliJ、Vim、Eclipse、记事本等编码，已使用-Xmx 参数设置了 Java 堆空间，并设置了足够大的值。在集群模式下工作时，应在使用 Spark-submit 脚本提交 Spark 作业时指定执行器内存。假设您有一个要解析的 CSV 文件，并使用随机森林分类器进行一些预测分析，您可能需要指定正确的内存量，比如 20GB，如下所示：

```scala
--executor-memory 20G

```

即使收到 OOM 错误，您也可以将此金额增加到 32GB 或更多。由于随机森林计算密集，需要更大的内存，这只是随机森林的一个例子。您可能在仅解析数据时遇到类似的问题。甚至由于此 OOM 错误，特定阶段可能会失败。因此，请确保您知道这个错误。

对于`class not found exception`，请确保您已经在生成的 JAR 文件中包含了主类。JAR 文件应该准备好包含所有依赖项，以便在集群节点上执行您的 Spark 作业。我们将在第十七章中提供一份逐步的 JAR 准备指南，*时候去集群 - 在集群上部署 Spark*。

对于最后一个问题，我们可以提供一些关于 Spark Core 库的一些误解的例子。例如，当您使用`wholeTextFiles`方法从多个文件准备 RDDs 或 DataFrames 时，Spark 不会并行运行；在 YARN 的集群模式下，有时可能会耗尽内存。

有一次，我遇到了一个问题，首先我将六个文件从我的 S3 存储复制到 HDFS。然后，我尝试创建一个 RDD，如下所示：

```scala
sc.wholeTextFiles("/mnt/temp") // note the location of the data files is /mnt/temp/

```

然后，我尝试使用 UDF 逐行处理这些文件。当我查看我的计算节点时，我发现每个文件只有一个执行器在运行。然而，后来我收到了一条错误消息，说 YARN 已经耗尽了内存。为什么呢？原因如下：

+   `wholeTextFiles`的目标是每个要处理的文件只有一个执行器

+   如果您使用`.gz`文件，例如，您将每个文件只有一个执行器，最多

# 慢作业或无响应

有时，如果 SparkContext 无法连接到 Spark 独立主节点，那么驱动程序可能会显示以下错误：

```scala
02/05/17 12:44:45 ERROR AppClient$ClientActor: All masters are unresponsive! Giving up. 
02/05/17 12:45:31 ERROR SparkDeploySchedulerBackend: Application has been killed. Reason: All masters are unresponsive! Giving up. 
02/05/17 12:45:35 ERROR TaskSchedulerImpl: Exiting due to error from cluster scheduler: Spark cluster looks down

```

在其他时候，驱动程序能够连接到主节点，但主节点无法与驱动程序进行通信。然后，尝试多次连接，即使驱动程序会报告无法连接到主节点的日志目录。

此外，您可能经常会在 Spark 作业中经历非常缓慢的性能和进展。这是因为您的驱动程序程序计算速度不够快。正如前面讨论的，有时特定阶段可能需要比平常更长的时间，因为可能涉及洗牌、映射、连接或聚合操作。即使计算机的磁盘存储或主内存用尽，您也可能会遇到这些问题。例如，如果您的主节点没有响应，或者在一定时间内计算节点出现不响应，您可能会认为您的 Spark 作业在某个阶段停滞不前。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00224.jpeg)**图 24：**执行器/驱动程序不响应的示例日志

可能的解决方案可能有几种，包括以下内容：

1.  请确保工作节点和驱动程序正确配置为连接到 Spark 主节点上的确切地址，该地址在 Spark 主节点 web UI/logs 中列出。然后，在启动 Spark shell 时明确提供 Spark 集群的主 URL：

```scala
 $ bin/spark-shell --master spark://master-ip:7077

```

1.  将`SPARK_LOCAL_IP`设置为驱动程序、主节点和工作进程的集群可寻址主机名。

有时，由于硬件故障，我们会遇到一些问题。例如，如果计算节点中的文件系统意外关闭，即 I/O 异常，您的 Spark 作业最终也会失败。这是显而易见的，因为您的 Spark 作业无法将生成的 RDD 或数据写入本地文件系统或 HDFS。这也意味着由于阶段失败，DAG 操作无法执行。

有时，这种 I/O 异常是由底层磁盘故障或其他硬件故障引起的。这通常会提供日志，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00048.jpeg)**图 25：**文件系统关闭示例

然而，您经常会遇到作业计算性能较慢的问题，因为您的 Java GC 有些忙碌，或者无法快速进行 GC。例如，以下图显示了对于任务 0，完成 GC 花了 10 个小时！我在 2014 年遇到了这个问题，当时我刚开始使用 Spark。然而，这些问题的控制并不在我们手中。因此，我们的建议是您应该释放 JVM 并尝试重新提交作业。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00352.jpeg)**图 26：**GC 在中间停滞的示例

第四个因素可能是响应缓慢或作业性能较慢是由于数据序列化不足。这将在下一节中讨论。第五个因素可能是代码中的内存泄漏，这将导致应用程序消耗更多内存，使文件或逻辑设备保持打开状态。因此，请确保没有导致内存泄漏的选项。例如，通过调用`sc.stop()`或`spark.stop()`完成您的 Spark 应用程序是一个好习惯。这将确保一个 SparkContext 仍然是打开和活动的。否则，您可能会遇到不必要的异常或问题。第六个问题是我们经常保持太多的打开文件，有时会在洗牌或合并阶段中创建`FileNotFoundException`。

# 优化技术

有几个方面可以调整 Spark 应用程序以实现更好的优化技术。在本节中，我们将讨论如何通过调整主内存和更好的内存管理来进一步优化我们的 Spark 应用程序，通过应用数据序列化来优化性能。另一方面，通过在开发 Spark 应用程序时调整 Scala 代码中的数据结构，也可以优化性能。另外，通过利用序列化 RDD 存储，可以很好地维护存储。

最重要的一个方面是垃圾收集，以及如果您使用 Java 或 Scala 编写了 Spark 应用程序，则需要调整。我们将看看如何为优化性能调整这一点。对于分布式环境和基于集群的系统，必须确保一定程度的并行性和数据局部性。此外，通过使用广播变量，性能还可以进一步提高。

# 数据序列化

序列化是任何分布式计算环境中性能改进和优化的重要调整。Spark 也不例外，但 Spark 作业通常涉及数据和计算。因此，如果您的数据对象格式不好，那么您首先需要将它们转换为序列化数据对象。这需要大量的内存字节。最终，整个过程将严重减慢整个处理和计算的速度。

因此，您经常会发现计算节点的响应速度很慢。这意味着我们有时无法充分利用计算资源。事实上，Spark 试图在便利性和性能之间保持平衡。这也意味着数据序列化应该是 Spark 调整性能的第一步。

Spark 提供了两种数据序列化选项：Java 序列化和 Kryo 序列化库：

+   **Java 序列化：** Spark 使用 Java 的`ObjectOutputStream`框架对对象进行序列化。您可以通过创建任何实现`java.io.Serializable`的类来处理序列化。Java 序列化非常灵活，但通常相当慢，不适合大数据对象序列化。

+   **Kryo 序列化：** 您还可以使用 Kryo 库更快地序列化数据对象。与 Java 序列化相比，Kryo 序列化速度更快，速度提高了 10 倍，比 Java 更紧凑。但是，它有一个问题，即它不支持所有可序列化类型，但您需要要求您的类进行注册。

您可以通过初始化 Spark 作业并调用`conf.set(spark.serializer, org.apache.spark.serializer.KryoSerializer)`来开始使用 Kryo。要使用 Kryo 注册自定义类，请使用`registerKryoClasses`方法，如下所示：

```scala
val conf = new SparkConf()
               .setMaster(“local[*]”)
               .setAppName(“MyApp”)
conf.registerKryoClasses(Array(classOf[MyOwnClass1], classOf[MyOwnClass2]))
val sc = new SparkContext(conf)

```

如果您的对象很大，您可能还需要增加`spark.kryoserializer.buffer`配置。这个值需要足够大，以容纳您序列化的最大对象。最后，如果您没有注册自定义类，Kryo 仍然可以工作；但是，每个对象的完整类名都需要被存储，这实际上是浪费的。

例如，在监控 Spark 作业部分的日志子部分中，可以使用`Kryo`序列化来优化日志记录和计算。首先，只需创建`MyMapper`类作为普通类（即，不进行任何序列化），如下所示：

```scala
class MyMapper(n: Int) { // without any serialization
  @transient lazy val log = org.apache.log4j.LogManager.getLogger("myLogger")
  def MyMapperDosomething(rdd: RDD[Int]): RDD[String] = rdd.map { i =>
    log.warn("mapping: " + i)
    (i + n).toString
  }
}

```

现在，让我们将这个类注册为`Kyro`序列化类，然后设置`Kyro`序列化如下：

```scala
conf.registerKryoClasses(Array(classOf[MyMapper])) // register the class with Kyro
conf.set("spark.serializer", "org.apache.spark.serializer.KryoSerializer") // set Kayro serialization

```

这就是你需要的全部内容。此示例的完整源代码如下。您应该能够运行并观察相同的输出，但与上一个示例相比是优化的：

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

干得好！现在让我们快速看一下如何调整内存。我们将在下一节中看一些高级策略，以确保主内存的有效使用。

# 内存调整

在本节中，我们将讨论一些高级策略，用户可以使用这些策略来确保在执行 Spark 作业时对内存的有效使用。更具体地说，我们将展示如何计算对象的内存使用情况。我们将建议一些高级方法来通过优化数据结构或将数据对象转换为使用 Kryo 或 Java 序列化的序列化格式来改进它。最后，我们将看看如何调整 Spark 的 Java 堆大小、缓存大小和 Java 垃圾收集器。

调整内存使用时有三个考虑因素：

+   您的对象使用的内存量：甚至可能希望整个数据集都能放入内存中

+   访问这些对象的成本

+   垃圾收集的开销：如果对象的周转率很高

尽管 Java 对象访问速度足够快，但它们很容易消耗实际数据字段的 2 到 5 倍的空间。例如，每个不同的 Java 对象都有 16 字节的开销与对象头。例如，Java 字符串比原始字符串多出近 40 字节的额外开销。此外，还使用了 Java 集合类，如`Set`、`List`、`Queue`、`ArrayList`、`Vector`、`LinkedList`、`PriorityQueue`、`HashSet`、`LinkedHashSet`、`TreeSet`等。另一方面，链式数据结构过于复杂，占用了太多额外的空间，因为数据结构中的每个条目都有一个包装对象。最后，基本类型的集合经常将它们存储在内存中作为装箱对象，例如`java.lang.Double`和`java.lang.Integer`。

# 内存使用和管理

您的 Spark 应用程序和底层计算节点的内存使用可以分为执行和存储。执行内存用于合并、洗牌、连接、排序和聚合计算过程中。另一方面，存储内存用于在集群中缓存和传播内部数据。简而言之，这是由于网络上的大量 I/O。

从技术上讲，Spark 将网络数据缓存在本地。在使用 Spark 进行迭代或交互式工作时，缓存或持久化是 Spark 中的优化技术。这两种技术有助于保存中间部分结果，以便它们可以在后续阶段重复使用。然后这些中间结果（作为 RDD）可以保存在内存（默认）或更可靠的存储介质，如磁盘，并/或复制。此外，RDD 也可以使用缓存操作进行缓存。它们也可以使用持久化操作进行持久化。缓存和持久化操作之间的区别纯粹是语法上的。缓存是持久化或持久化（`MEMORY_ONLY`）的同义词，即缓存仅以默认存储级别`MEMORY_ONLY`进行持久化。

如果您在 Spark web UI 中转到存储选项卡，您应该观察 RDD、DataFrame 或 Dataset 对象使用的内存/存储，如*图 10*所示。尽管在 Spark 中有两个相关的内存调整配置，用户不需要重新调整它们。原因是配置文件中设置的默认值足以满足您的需求和工作负载。

spark.memory.fraction 是统一区域大小占(JVM 堆空间-300 MB)的比例（默认为 0.6）。其余空间（40%）用于用户数据结构、Spark 内部元数据和防止在稀疏和异常大记录的情况下发生 OOM 错误。另一方面，`spark.memory.storageFraction`表示 R 存储空间大小占统一区域的比例（默认为 0.5）。该参数的默认值是 Java 堆空间的 50%，即 300 MB。

有关内存使用和存储的更详细讨论，请参阅第十五章，*使用 Spark ML 进行文本分析*。

现在，您可能会想到一个问题：选择哪种存储级别？为了回答这个问题，Spark 存储级别为您提供了在内存使用和 CPU 效率之间的不同权衡。如果您的 RDD 与默认存储级别（MEMORY_ONLY）相适应，请让您的 Spark driver 或 master 使用它。这是最节省内存的选项，允许对 RDD 进行的操作尽可能快地运行。您应该让它使用这个选项，因为这是最节省内存的选项。这也允许对 RDD 进行的众多操作尽可能快地完成。

如果您的 RDD 不适合主内存，也就是说，如果`MEMORY_ONLY`不起作用，您应该尝试使用`MEMORY_ONLY_SER`。强烈建议不要将 RDD 溢出到磁盘，除非您的**UDF**（即为处理数据集定义的**用户定义函数**）太昂贵。如果您的 UDF 在执行阶段过滤了大量数据，也适用于此。在其他情况下，重新计算分区，即重新分区，可能更快地从磁盘读取数据对象。最后，如果您希望快速故障恢复，请使用复制的存储级别。

总之，在 Spark 2.x 中支持以下 StorageLevels：（名称中的数字 _2 表示 2 个副本）：

+   `DISK_ONLY`: 这是 RDD 的基于磁盘的操作

+   `DISK_ONLY_2`: 这是 RDD 的基于磁盘的操作，带有 2 个副本

+   `MEMORY_ONLY`: 这是 RDD 的内存缓存操作的默认值

+   `MEMORY_ONLY_2`: 这是 RDD 具有 2 个副本的内存缓存操作的默认值

+   `MEMORY_ONLY_SER`: 如果您的 RDD 不适合主内存，也就是说，如果`MEMORY_ONLY`不起作用，这个选项特别有助于以序列化形式存储数据对象

+   `MEMORY_ONLY_SER_2`: 如果您的 RDD 不适合主内存，也就是说，如果`MEMORY_ONLY`不适合 2 个副本，这个选项也有助于以序列化形式存储数据对象

+   `MEMORY_AND_DISK`: 基于内存和磁盘（也称为组合）的 RDD 持久性

+   `MEMORY_AND_DISK_2`: 基于内存和磁盘（也称为组合）的 RDD 持久性，带有 2 个副本

+   `MEMORY_AND_DISK_SER`: 如果`MEMORY_AND_DISK`不起作用，可以使用它

+   `MEMORY_AND_DISK_SER_2`: 如果`MEMORY_AND_DISK`不适用于 2 个副本，可以使用此选项

+   `OFF_HEAP`: 不允许写入 Java 堆空间

请注意，缓存是持久化的同义词（`MEMORY_ONLY`）。这意味着缓存仅使用默认存储级别，即`MEMORY_ONLY`。详细信息可以在[`jaceklaskowski.gitbooks.io/mastering-apache-spark/content/spark-rdd-StorageLevel.html`](https://jaceklaskowski.gitbooks.io/mastering-apache-spark/content/spark-rdd-StorageLevel.html)找到。

# 调整数据结构

减少额外内存使用的第一种方法是避免 Java 数据结构中的一些特性，这些特性会带来额外的开销。例如，基于指针的数据结构和包装对象会导致非常大的开销。为了调整您的源代码以使用更好的数据结构，我们在这里提供了一些建议，这可能会有所帮助。

首先，设计您的数据结构，以便更多地使用对象和基本类型的数组。因此，这也建议更频繁地使用标准的 Java 或 Scala 集合类，如`Set`，`List`，`Queue`，`ArrayList`，`Vector`，`LinkedList`，`PriorityQueue`，`HashSet`，`LinkedHashSet`和`TreeSet`。

其次，尽可能避免使用具有大量小对象和指针的嵌套结构，以使您的源代码更加优化和简洁。第三，尽可能考虑使用数字 ID，有时使用枚举对象而不是使用字符串作为键。这是因为，正如我们已经提到的，单个 Java 字符串对象会产生额外的 40 字节开销。最后，如果您的主内存（即 RAM）少于 32GB，请设置 JVM 标志`-XX:+UseCompressedOops`，以使指针为 4 字节而不是 8 字节。

早期的选项可以在`SPARK_HOME/conf/spark-env.sh.template`中设置。只需将文件重命名为`spark-env.sh`并立即设置值！

# 序列化 RDD 存储

正如前面讨论的，尽管有其他类型的内存调整，但当您的对象太大而无法有效地适应主内存或磁盘时，减少内存使用的一个更简单和更好的方法是以序列化形式存储它们。

这可以通过 RDD 持久性 API 中的序列化存储级别（如`MEMORY_ONLY_SER`）来实现。有关更多信息，请参阅前一节关于内存管理的内容，并开始探索可用的选项。

如果您指定使用`MEMORY_ONLY_SER`，Spark 将把每个 RDD 分区存储为一个大的字节数组。然而，这种方法的唯一缺点是它可能会减慢数据访问速度。这是合理的，也很明显；公平地说，没有办法避免它，因为每个对象都需要在重用时动态反序列化。

如前所述，我们强烈建议使用 Kryo 序列化而不是 Java 序列化，以使数据访问速度更快。

# 垃圾收集调优

尽管在您的 Java 或 Scala 程序中，只是顺序或随机读取 RDD 一次，然后对其执行大量操作并不是一个主要问题，但是如果您的驱动程序中存储了大量数据对象，就会导致**Java 虚拟机**（**JVM**）GC 变得棘手和复杂。当 JVM 需要从旧对象中删除过时和未使用的对象以为新对象腾出空间时，有必要识别它们并最终从内存中删除它们。然而，这在处理时间和存储方面是一项昂贵的操作。您可能会想到 GC 的成本与存储在主内存中的 Java 对象数量成正比。因此，我们强烈建议您调整数据结构。此外，建议减少存储在内存中的对象数量。

GC 调优的第一步是收集有关 JVM 在您的计算机上频繁进行垃圾收集的相关统计信息。在这方面需要的第二个统计数据是 JVM 在您的计算机或计算节点上花费在 GC 上的时间。这可以通过在您的 IDE（如 Eclipse）中的 JVM 启动参数中添加`-verbose:gc -XX:+PrintGCDetails -XX:+PrintGCTimeStamps`来实现，并指定 GC 日志文件的名称和位置，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00213.jpeg)**图 27：**在 Eclipse 上设置 GC 详细信息

或者，您可以在使用 Spark-submit 脚本提交 Spark 作业时指定`verbose:gc`，如下所示：

```scala
--conf “spark.executor.extraJavaOptions = -verbose:gc -XX:-PrintGCDetails -XX:+PrintGCTimeStamps"

```

简而言之，在为 Spark 指定 GC 选项时，您必须确定要在执行程序或驱动程序上指定 GC 选项。当您提交作业时，指定`--driver-java-options -XX:+PrintFlagsFinal -verbose:gc`等。对于执行程序，指定`--conf spark.executor.extraJavaOptions=-XX:+PrintFlagsFinal -verbose:gc`等。

现在，当执行您的 Spark 作业时，每次发生 GC 时，您都可以在工作节点的`/var/log/logs`中看到打印的日志和消息。这种方法的缺点是这些日志不会出现在您的驱动程序上，而是出现在集群的工作节点上。

需要注意的是，`verbose:gc`只会在每次 GC 收集后打印适当的消息或日志。相应地，它会打印有关内存的详细信息。但是，如果您对寻找更严重的问题（如内存泄漏）感兴趣，`verbose:gc`可能不够。在这种情况下，您可以使用一些可视化工具，如 jhat 和 VisualVM。您可以在[`databricks.com/blog/2015/05/28/tuning-java-garbage-collection-for-spark-applications.html`](https://databricks.com/blog/2015/05/28/tuning-java-garbage-collection-for-spark-applications.html)上阅读有关在 Spark 应用程序中进行更好的 GC 调优的信息。

# 并行级别

尽管您可以通过`SparkContext.text`文件的可选参数来控制要执行的映射任务的数量，但 Spark 会根据文件的大小自动设置每个文件的映射任务数量。此外，对于分布式的`reduce`操作，如`groupByKey`和`reduceByKey`，Spark 会使用最大父 RDD 的分区数。然而，有时我们会犯一个错误，即未充分利用计算集群中节点的全部计算资源。因此，除非您明确设置和指定 Spark 作业的并行级别，否则将无法充分利用全部计算资源。因此，您应该将并行级别设置为第二个参数。

有关此选项的更多信息，请参阅[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.rdd.PairRDDFunctions.`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.rdd.PairRDDFunctions)

或者，您可以通过设置配置属性 spark.default.parallelism 来更改默认设置。对于没有父 RDD 的并行操作，并行级别取决于集群管理器，即独立模式、Mesos 或 YARN。对于本地模式，将并行级别设置为本地机器上的核心数。对于 Mesos 或 YARN，将细粒度模式设置为 8。在其他情况下，所有执行程序节点上的总核心数或 2，以较大者为准，通常建议在集群中每个 CPU 核心使用 2-3 个任务。

# 广播

广播变量使 Spark 开发人员能够在每个驱动程序程序上缓存一个实例或类变量的只读副本，而不是将其自己的副本与依赖任务一起传输。但是，只有当多个阶段的任务需要以反序列化形式的相同数据时，显式创建广播变量才有用。

在 Spark 应用程序开发中，使用 SparkContext 的广播选项可以大大减小每个序列化任务的大小。这也有助于减少在集群中启动 Spark 作业的成本。如果您的 Spark 作业中有某个任务使用了驱动程序中的大对象，您应该将其转换为广播变量。

要在 Spark 应用程序中使用广播变量，可以使用`SparkContext.broadcast`进行实例化。然后，使用该类的 value 方法来访问共享值，如下所示：

```scala
val m = 5
val bv = sc.broadcast(m)

```

输出/日志：`bv: org.apache.spark.broadcast.Broadcast[Int] = Broadcast(0)`

```scala
bv.value()

```

输出/日志：`res0: Int = 1`

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00359.jpeg)**图 28：** 从驱动程序向执行程序广播一个值

Spark 的广播功能使用**SparkContext**创建广播值。之后，**BroadcastManager**和**ContextCleaner**用于控制它们的生命周期，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00368.jpeg)**图 29：** SparkContext 使用 BroadcastManager 和 ContextCleaner 广播变量/值

驱动程序中的 Spark 应用程序会自动打印每个任务在驱动程序上的序列化大小。因此，您可以决定您的任务是否过大而无法并行。如果您的任务大于 20 KB，可能值得优化。

# 数据本地性

数据本地性意味着数据与要处理的代码的接近程度。从技术上讲，数据本地性对于在本地或集群模式下执行的 Spark 作业的性能可能会产生重大影响。因此，如果数据和要处理的代码是绑定在一起的，计算速度应该会更快。通常情况下，从驱动程序向执行程序发送序列化代码要快得多，因为代码大小比数据小得多。

在 Spark 应用程序开发和作业执行中，存在几个级别的本地性。从最接近到最远，级别取决于您需要处理的数据的当前位置：

| **数据本地性** | **含义** | **特殊说明** |
| --- | --- | --- |
| `PROCESS_LOCAL` | 数据和代码位于同一位置 | 最佳的位置可能 |
| `NODE_LOCAL` | 数据和代码位于同一节点上，例如，存储在 HDFS 上的数据 | 比`PROCESS_LOCAL`慢一点，因为数据必须在进程和网络之间传播 |
| `NO_PREF` | 数据可以从其他地方平等访问 | 没有位置偏好 |
| `RACK_LOCAL` | 数据位于同一机架上的服务器上 | 适用于大规模数据处理 |
| `ANY` | 数据在网络的其他地方，不在同一机架上 | 除非没有其他选择，否则不建议使用 |

**表 2：** 数据位置和 Spark

Spark 被开发成优先在最佳位置调度所有任务，但这并不是保证的，也并非总是可能的。因此，基于计算节点的情况，如果可用的计算资源过于繁忙，Spark 会切换到较低的位置级别。此外，如果您想要最佳的数据位置，有两种选择：

+   等待繁忙的 CPU 空闲下来，在同一台服务器或同一节点上启动任务

+   立即开始一个新的任务，需要将数据移动到那里

# 总结

在本章中，我们讨论了一些关于 Spark 的高级主题，以使您的 Spark 作业性能更好。我们讨论了一些调整 Spark 作业的基本技术。我们讨论了如何通过访问 Spark web UI 来监视您的作业。我们讨论了如何设置 Spark 配置参数。我们还讨论了一些 Spark 用户常见的错误，并提供了一些建议。最后，我们讨论了一些优化技术，帮助调整 Spark 应用程序。

在下一章中，您将看到如何测试 Spark 应用程序并调试以解决最常见的问题。
