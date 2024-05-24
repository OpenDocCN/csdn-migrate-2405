# Spark 2.x 机器学习秘籍（七）

> 原文：[`zh.annas-archive.org/md5/3C1ECF91245FC64E4B95E8DC509841AB`](https://zh.annas-archive.org/md5/3C1ECF91245FC64E4B95E8DC509841AB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：大数据中的高维度诅咒

在本章中，我们将涵盖以下主题：

+   在 Spark 中摄取和准备 CSV 文件进行处理的两种方法

+   **奇异值分解**（**SVD**）以减少 Spark 中的高维度

+   **主成分分析**（**PCA**）在 Spark 中为机器学习选择最有效的潜在因素

# 介绍

维度诅咒并不是一个新的术语或概念。这个术语最初是由 R.贝尔曼在解决动态规划问题（贝尔曼方程）时创造的。机器学习中的核心概念指的是，随着我们增加维度（轴或特征）的数量，训练数据（样本）的数量保持不变（或相对较低），这导致我们的预测准确性降低。这种现象也被称为*休斯效应*，以 G.休斯的名字命名，它讨论了随着我们在问题空间中引入越来越多的维度，搜索空间的迅速（指数级）增加所导致的问题。这有点违直觉，但如果样本数量的增长速度不如添加更多维度的速度，实际上你最终会得到一个更不准确的模型！

总的来说，大多数机器学习算法本质上是统计学的，它们试图通过在训练期间切割空间并对每个子空间中每个类别的数量进行某种计数来学习目标空间的属性。维度诅咒是由于随着维度的增加，能够帮助算法区分和学习的数据样本变得越来越少。一般来说，如果我们在一个密集的*D*维度中有*N*个样本，那么我们需要*(N)^D*个样本来保持样本密度恒定。

例如，假设你有 10 个患者数据集，这些数据集是沿着两个维度（身高、体重）进行测量的。这导致了一个二维平面上的 10 个数据点。如果我们开始引入其他维度，比如地区、卡路里摄入量、种族、收入等，会发生什么？在这种情况下，我们仍然有 10 个观察点（10 个患者），但是在一个更大的六维空间中。当新的维度被引入时，样本数据（用于训练）无法呈指数级增长，这就是所谓的**维度诅咒**。

让我们看一个图形示例来展示搜索空间与数据样本的增长。下图描述了一组五个数据点，这些数据点在 5 x 5（25 个单元格）中被测量。当我们添加另一个维度时，预测准确性会发生什么变化？我们仍然有五个数据点在 125 个 3D 单元格中，这导致了大量稀疏子空间，这些子空间无法帮助机器学习算法更好地学习（区分），因此导致了更低的准确性：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00254.jpeg)

我们的目标应该是努力朝着一个接近最佳特征或维度的数量，而不是不断添加更多特征（最大特征或维度）。毕竟，如果我们只是不断添加更多特征或维度，难道我们不应该有更好的分类错误吗？起初这似乎是个好主意，但在大多数情况下答案是“不”，除非你能指数级增加样本，而这在几乎所有情况下都是不切实际的也几乎不可能的。

让我们看一下下图，它描述了学习错误与特征总数的关系：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00255.jpeg)

在前一节中，我们研究了维度诅咒背后的核心概念，但我们还没有讨论它的其他副作用或如何处理诅咒本身。正如我们之前所看到的，与普遍观念相反，问题不在于维度本身，而在于样本与搜索空间的比率的减少，随之而来的是更不准确的预测。

想象一个简单的 ML 系统，如下图所示。这里显示的 ML 系统使用 MNIST（[`yann.lecun.com/exdb/mnist/`](http://yann.lecun.com/exdb/mnist/)）类型的手写数据集，并希望对自己进行训练，以便能够预测包裹上使用的六位邮政编码是什么：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00256.jpeg)

来源：MNIST

即使 MNIST 数据是 20 x 20，为了使问题更加明显，让我们假设每个数字有一个 40 x 40 像素的补丁需要存储、分析，然后用于未来的预测。如果我们假设是黑/白，那么“表观”维度是两个（40 x 40）或 21,600，这是很大的。接下来应该问的问题是：给定数据的 21,600 个表观维度，我们需要多少实际维度来完成我们的工作？如果我们看一下从 40 x 40 补丁中抽取的所有可能样本，有多少实际上是在寻找数字？一旦我们仔细看一下这个问题，我们会发现“实际”维度（即限制在一个较小的流形子空间中，这是笔画用来制作数字的空间。实际上，实际子空间要小得多，而且不是随机分布在 40 x 40 的补丁上）实际上要小得多！这里发生的情况是，实际数据（人类绘制的数字）存在于更小的维度中，很可能局限于子空间中的一小组流形（即，数据存在于某个子空间周围）。为了更好地理解这一点，从 40 x 40 的补丁中随机抽取 1,000 个样本，并直观地检查这些样本。有多少样本实际上看起来像 3、6 或 5？

当我们增加维度时，我们可能会无意中增加错误率，因为由于没有足够的样本来准确预测，或者由于测量本身引入了噪声，系统可能会引入噪声。增加更多维度的常见问题如下：

+   更长的计算时间

+   增加噪声

+   需要更多样本以保持相同的学习/预测速率

+   由于稀疏空间中缺乏可操作样本而导致数据过拟合

图片展示可以帮助我们理解“表观维度”与“实际维度”的差异，以及在这种情况下“少即是多”的原因：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00257.jpeg)

我们希望减少维度的原因可以表达为：

+   更好地可视化数据

+   压缩数据并减少存储需求

+   增加信噪比

+   实现更快的运行时间

# 特征选择与特征提取

我们有两个选择，特征选择和特征提取，可以用来将维度减少到一个更易管理的空间。这些技术各自是一个独立的学科，有自己的方法和复杂性。尽管它们听起来相同，但它们是非常不同的，需要单独处理。

下图提供了一个思维导图，比较了特征选择和特征提取。虽然特征选择，也称为特征工程，超出了本书的范围，但我们通过详细的配方介绍了两种最常见的特征提取技术（PCA 和 SVD）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00258.gif)

用于选择 ML 算法的一组特征或输入的两种可用技术是：

+   **特征选择**：在这种技术中，我们利用我们的领域知识选择最能描述数据方差的特征子集。我们试图做的是选择最能帮助我们预测结果的最佳因变量（特征）。这种方法通常被称为“特征工程”，需要数据工程师或领域专业知识才能有效。

例如，我们可能会查看为物流分类器提出的 200 个独立变量（维度、特征），以预测芝加哥市的房屋是否会出售。在与在芝加哥市购买/销售房屋有 20 多年经验的房地产专家交谈后，我们发现最初提出的 200 个维度中只有 4 个是足够的，例如卧室数量、价格、总平方英尺面积和学校质量。虽然这很好，但通常非常昂贵、耗时，并且需要领域专家来分析和提供指导。

+   **特征提取**：这是指一种更算法化的方法，使用映射函数将高维数据映射到低维空间。例如，将三维空间（例如，身高、体重、眼睛颜色）映射到一维空间（例如，潜在因素），可以捕捉数据集中几乎所有的变化。

我们在这里尝试的是提出一组潜在因素，这些因素是原始因素的组合（通常是线性的），可以以准确的方式捕捉和解释数据。例如，我们使用单词来描述文档，通常以 10⁶到 10⁹的空间结束，但是用主题（例如，浪漫、战争、和平、科学、艺术等）来描述文档会更抽象和高层次，这不是很好吗？我们真的需要查看或包含每个单词来更好地进行文本分析吗？以什么代价？

特征提取是一种从“表观维度”到“实际维度”映射的降维算法方法。

# 两种在 Spark 中摄取和准备 CSV 文件进行处理的方法

在这个示例中，我们探讨了读取、解析和准备 CSV 文件用于典型的 ML 程序。**逗号分隔值**（**CSV**）文件通常将表格数据（数字和文本）存储在纯文本文件中。在典型的 CSV 文件中，每一行都是一个数据记录，大多数情况下，第一行也被称为标题行，其中存储了字段的标识符（更常见的是字段的列名）。每个记录由一个或多个字段组成，字段之间用逗号分隔。

# 如何做...

1.  示例 CSV 数据文件来自电影评分。该文件可在[`files.grouplens.org/datasets/movielens/ml-latest-small.zip`](http://files.grouplens.org/datasets/movielens/ml-latest-small.zip)中获取。

1.  文件提取后，我们将使用`ratings.csv`文件来加载数据到 Spark 中。CSV 文件将如下所示：

| **userId** | **movieId** | **rating** | **timestamp** |
| --- | --- | --- | --- |
| 1 | 16 | 4 | 1217897793 |
| 1 | 24 | 1.5 | 1217895807 |
| 1 | 32 | 4 | 1217896246 |
| 1 | 47 | 4 | 1217896556 |
| 1 | 50 | 4 | 1217896523 |
| 1 | 110 | 4 | 1217896150 |
| 1 | 150 | 3 | 1217895940 |
| 1 | 161 | 4 | 1217897864 |
| 1 | 165 | 3 | 1217897135 |
| 1 | 204 | 0.5 | 1217895786 |
| ... | ... | ... | ... |

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

`package spark.ml.cookbook.chapter11`。

1.  导入 Spark 所需的包，以便访问集群和`Log4j.Logger`以减少 Spark 产生的输出量：

```scala
import org.apache.log4j.{Level, Logger}
import org.apache.spark.sql.SparkSession
```

1.  创建 Spark 的配置和 Spark 会话，以便我们可以访问集群：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)

 val spark = SparkSession
 .builder
.master("local[*]")
 .appName("MyCSV")
 .config("spark.sql.warehouse.dir", ".")
 .getOrCreate()
```

1.  我们将 CSV 文件读入为文本文件：

```scala
// 1\. load the csv file as text file
val dataFile = "../data/sparkml2/chapter11/ratings.csv"
val file = spark.sparkContext.textFile(dataFile)
```

1.  我们处理数据集：

```scala
val headerAndData = file.map(line => line.split(",").map(_.trim))
 val header = headerAndData.first
 val data = headerAndData.filter(_(0) != header(0))
 val maps = data.map(splits => header.zip(splits).toMap)
 val result = maps.take(10)
 result.foreach(println)
```

这里应该提到，`split`函数仅用于演示目的，生产中应该使用更健壮的标记技术。

1.  首先，我们修剪行，删除任何空格，并将 CSV 文件加载到`headerAndData` RDD 中，因为`ratings.csv`确实有标题行。

1.  然后我们将第一行读取为标题，将其余数据读入数据 RDD 中。任何进一步的计算都可以使用数据 RDD 来执行机器学习算法。为了演示目的，我们将标题行映射到数据 RDD 并打印出前 10 行。

在应用程序控制台中，您将看到以下内容：

```scala
Map(userId -> 1, movieId -> 16, rating -> 4.0, timestamp -> 1217897793)
Map(userId -> 1, movieId -> 24, rating -> 1.5, timestamp -> 1217895807)
Map(userId -> 1, movieId -> 32, rating -> 4.0, timestamp -> 1217896246)
Map(userId -> 1, movieId -> 47, rating -> 4.0, timestamp -> 1217896556)
Map(userId -> 1, movieId -> 50, rating -> 4.0, timestamp -> 1217896523)
Map(userId -> 1, movieId -> 110, rating -> 4.0, timestamp -> 1217896150)
Map(userId -> 1, movieId -> 150, rating -> 3.0, timestamp -> 1217895940)
Map(userId -> 1, movieId -> 161, rating -> 4.0, timestamp -> 1217897864)
Map(userId -> 1, movieId -> 165, rating -> 3.0, timestamp -> 1217897135)
Map(userId -> 1, movieId -> 204, rating -> 0.5, timestamp -> 1217895786)
```

1.  还有另一种选项可以使用 Spark-CSV 包将 CSV 文件加载到 Spark 中。

要使用此功能，您需要下载以下 JAR 文件并将它们放在类路径上：[`repo1.maven.org/maven2/com/databricks/spark-csv_2.10/1.4.0/spark-csv_2.10-1.4.0.jar`](http://repo1.maven.org/maven2/com/databricks/spark-csv_2.10/1.4.0/spark-csv_2.10-1.4.0.jar)

由于 Spark-CSV 包也依赖于`common-csv`，您需要从以下位置获取`common-csv` JAR 文件：[`commons.apache.org/proper/commons-csv/download_csv.cgi`](https://commons.apache.org/proper/commons-csv/download_csv.cgi)

我们获取`common-csv-1.4-bin.zip`并提取`commons-csv-1.4.jar`，然后将前两个 jar 放在类路径上。

1.  我们使用 Databricks 的`spark-csv`包加载 CSV 文件，使用以下代码。成功加载 CSV 文件后，它将创建一个 DataFrame 对象：

```scala
// 2\. load the csv file using databricks package
val df = spark.read.format("com.databricks.spark.csv").option("header", "true").load(dataFile)
```

1.  我们从 DataFrame 中注册一个名为`ratings`的临时内存视图：

```scala
df.createOrReplaceTempView("ratings")
 val resDF = spark.sql("select * from ratings")
 resDF.show(10, false)
```

然后我们对表使用 SQL 查询并显示 10 行。在控制台上，您将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00259.gif)

1.  进一步的机器学习算法可以在之前创建的 DataFrame 上执行。

1.  然后我们通过停止 Spark 会话来关闭程序：

```scala
spark.stop()
```

# 工作原理...

在旧版本的 Spark 中，我们需要使用特殊包来读取 CSV，但现在我们可以利用`spark.sparkContext.textFile(dataFile)`来摄取文件。开始该语句的`Spark`是 Spark 会话（集群句柄），可以在创建阶段通过任何您喜欢的名称来命名，如下所示：

```scala
val spark = SparkSession
 .builder
.master("local[*]")
 .appName("MyCSV")
 .config("spark.sql.warehouse.dir", ".")
 .getOrCreate()
spark.sparkContext.textFile(dataFile)
spark.sparkContext.textFile(dataFile)
```

Spark 2.0+使用`spark.sql.warehouse.dir`来设置存储表的仓库位置，而不是`hive.metastore.warehouse.dir`。`spark.sql.warehouse.dir`的默认值是`System.getProperty("user.dir")`。

另请参阅`spark-defaults.conf`以获取更多详细信息。

在以后的工作中，我们更喜欢这种方法，而不是按照本示例的第 9 步和第 10 步所解释的获取特殊包和依赖 JAR 的方法：

```scala
spark.read.format("com.databricks.spark.csv").option("header", "true").load(dataFile)
```

这演示了如何使用文件。

# 还有更多...

CSV 文件格式有很多变化。用逗号分隔字段的基本思想是清晰的，但它也可以是制表符或其他特殊字符。有时甚至标题行是可选的。

由于其可移植性和简单性，CSV 文件广泛用于存储原始数据。它可以在不同的应用程序之间进行移植。我们将介绍两种简单而典型的方法来将样本 CSV 文件加载到 Spark 中，并且可以很容易地修改以适应您的用例。

# 另请参阅

+   有关 Spark-CSV 包的更多信息，请访问[`github.com/databricks/spark-csv`](https://github.com/databricks/spark-csv)

# 使用 Singular Value Decomposition（SVD）在 Spark 中降低高维度

在这个示例中，我们将探讨一种直接来自线性代数的降维方法，称为**SVD**（**奇异值分解**）。这里的重点是提出一组低秩矩阵（通常是三个），它们可以近似原始矩阵，但数据量要少得多，而不是选择使用大型*M*乘以*N*矩阵。

SVD 是一种简单的线性代数技术，它将原始数据转换为特征向量/特征值低秩矩阵，可以捕捉大部分属性（原始维度）在一个更有效的低秩矩阵系统中。

以下图示了 SVD 如何用于降低维度，然后使用 S 矩阵来保留或消除从原始数据派生的更高级概念（即，具有比原始数据更少列/特征的低秩矩阵）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00260.jpeg)

# 如何做...

1.  我们将使用电影评分数据进行 SVD 分析。MovieLens 1M 数据集包含大约 100 万条记录，由 6000 个 MovieLens 用户对约 3900 部电影的匿名评分组成。

数据集可以在以下位置检索：[`files.grouplens.org/datasets/movielens/ml-1m.zip`](http://files.grouplens.org/datasets/movielens/ml-1m.zip)

数据集包含以下文件：

+   `ratings.dat`：包含用户 ID、电影 ID、评分和时间戳

+   `movies.dat`：包含电影 ID、标题和类型

+   `users.dat`：包含用户 ID、性别、年龄、职业和邮政编码

1.  我们将使用`ratings.dat`进行 SVD 分析。`ratings.dat`的样本数据如下：

```scala
1::1193::5::978300760
1::661::3::978302109
1::914::3::978301968
1::3408::4::978300275
1::2355::5::978824291
1::1197::3::978302268
1::1287::5::978302039
1::2804::5::978300719
1::594::4::978302268
1::919::4::978301368
1::595::5::978824268
1::938::4::978301752
```

我们将使用以下程序将数据转换为评分矩阵，并将其适应 SVD 算法模型（在本例中，总共有 3953 列）：

|  | **电影 1** | **电影 2** | **电影...** | **电影 3953** |
| --- | --- | --- | --- | --- |
| 用户 1 | 1 | 4 | - | 3 |
| 用户 2 | 5 | - | 2 | 1 |
| 用户... | - | 3 | - | 2 |
| 用户 N | 2 | 4 | - | 5 |

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

`package spark.ml.cookbook.chapter11`。

1.  导入 Spark 会话所需的包：

```scala
import org.apache.log4j.{Level, Logger}
import org.apache.spark.mllib.linalg.distributed.RowMatrix
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.sql.SparkSession
```

1.  创建 Spark 的配置和 Spark 会话，以便我们可以访问集群：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)

val spark = SparkSession
.builder
.master("local[*]")
.appName("MySVD")
.config("spark.sql.warehouse.dir", ".")
.getOrCreate()    

```

1.  我们读取原始的原始数据文件： 

```scala
val dataFile = "../data/sparkml2/chapter11/ratings.dat" //read data file in as a RDD, partition RDD across <partitions> cores
val data = spark.sparkContext.textFile(dataFile)
```

1.  我们预处理数据集：

```scala
//parse data and create (user, item, rating) tuplesval ratingsRDD = data
   .map(line => line.split("::"))
   .map(fields => (fields(0).toInt, fields(1).toInt, fields(2).toDouble))
```

由于我们对评分更感兴趣，我们从数据文件中提取`userId`，`movieId`和评分值，即`fields(0)`，`fields(1)`和`fields(2)`，并基于记录创建一个评分 RDD。

1.  然后我们找出评分数据中有多少部电影，并计算最大电影索引：

```scala
val items = ratingsRDD.map(x => x._2).distinct()
val maxIndex = items.max + 1
```

总共，我们根据数据集得到 3953 部电影。

1.  我们将所有用户的电影项目评分放在一起，使用 RDD 的`groupByKey`函数，所以单个用户的电影评分被分组在一起：

```scala
val userItemRatings = ratingsRDD.map(x => (x._1, ( x._2, x._3))).groupByKey().cache()
 userItemRatings.take(2).foreach(println)
```

然后我们打印出前两条记录以查看集合。由于我们可能有一个大型数据集，我们缓存 RDD 以提高性能。

在控制台中，您将看到以下内容：

```scala
(4904,CompactBuffer((2054,4.0), (588,4.0), (589,5.0), (3000,5.0), (1,5.0), ..., (3788,5.0)))
(1084,CompactBuffer((2058,3.0), (1258,4.0), (588,2.0), (589,4.0), (1,3.0), ..., (1242,4.0)))
```

在上述记录中，用户 ID 为`4904`。对于电影 ID`2054`，评分为`4.0`，电影 ID 为`588`，评分为`4`，依此类推。

1.  然后我们创建一个稀疏向量来存储数据：

```scala
val sparseVectorData = userItemRatings
 .map(a=>(a._1.toLong, Vectors.sparse(maxIndex,a._2.toSeq))).sortByKey()

 sparseVectorData.take(2).foreach(println)
```

然后我们将数据转换为更有用的格式。我们使用`userID`作为键（排序），并创建一个稀疏向量来存储电影评分数据。

在控制台中，您将看到以下内容：

```scala
(1,(3953,[1,48,150,260,527,531,588,...], [5.0,5.0,5.0,4.0,5.0,4.0,4.0...]))
(2,(3953,[21,95,110,163,165,235,265,...],[1.0,2.0,5.0,4.0,3.0,3.0,4.0,...]))
```

在上述打印输出中，对于用户`1`，总共有`3,953`部电影。对于电影 ID`1`，评分为`5.0`。稀疏向量包含一个`movieID`数组和一个评分值数组。

1.  我们只需要评分矩阵进行 SVD 分析：

```scala
val rows = sparseVectorData.map{
 a=> a._2
 }
```

上述代码将提取稀疏向量部分并创建一个行 RDD。

1.  然后我们基于 RDD 创建一个 RowMatrix。一旦创建了 RowMatrix 对象，我们就可以调用 Spark 的`computeSVD`函数来计算矩阵的 SVD：

```scala
val mat = new RowMatrix(rows)
val col = 10 //number of leading singular values
val computeU = true
val svd = mat.computeSVD(col, computeU)
```

1.  上述参数也可以调整以适应我们的需求。一旦我们计算出 SVD，就可以获取模型数据。

1.  我们打印出奇异值：

```scala
println("Singular values are " + svd.s)
println("V:" + svd.V)
```

您将在控制台上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00261.gif)

1.  从 Spark Master（`http://localhost:4040/jobs/`）中，您应该看到如下截图所示的跟踪：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00262.jpeg)

1.  然后我们通过停止 Spark 会话来关闭程序：

```scala
spark.stop()
```

# 它是如何工作的...

工作的核心是声明一个`RowMatrix()`，然后调用`computeSVD()`方法将矩阵分解为更小的子组件，但以惊人的准确度近似原始矩阵：

```scala
valmat = new RowMatrix(rows)
val col = 10 //number of leading singular values
val computeU = true
val svd = mat.computeSVD(col, computeU)
```

SVD 是一个用于实数或复数矩阵的因式分解技术。在其核心，它是一种直接的线性代数，实际上是从 PCA 中导出的。这个概念在推荐系统（ALS，SVD），主题建模（LDA）和文本分析中被广泛使用，以从原始的高维矩阵中推导出概念。让我们尝试概述这个降维的方案及其数据集（`MovieLens`）与 SVD 分解的关系，而不深入讨论 SVD 分解中的数学细节。以下图表描述了这个降维方案及其数据集（`MovieLens`）与 SVD 分解的关系：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00263.jpeg)

# 还有更多...

我们将得到基于原始数据集的更高效（低秩）的矩阵。

以下方程描述了一个*m x n*数组的分解，这个数组很大，很难处理。方程的右边帮助解决了分解问题，这是 SVD 技术的基础。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00264.jpeg)

以下步骤逐步提供了 SVD 分解的具体示例：

+   考虑一个 1,000 x 1,000 的矩阵，提供 1,000,000 个数据点（M=用户，N=电影）。

+   假设有 1,000 行（观测数量）和 1,000 列（电影数量）。

+   假设我们使用 Spark 的 SVD 方法将 A 分解为三个新矩阵。

+   矩阵`U [m x r]`有 1,000 行，但现在只有 5 列（`r=5`；`r`可以被看作是概念）

+   矩阵`S [r x r]`保存了奇异值，它们是每个概念的强度（只对对角线感兴趣）

+   矩阵`V [n x r]`具有右奇异值向量（`n=电影`，`r=概念`，如浪漫，科幻等）

+   假设在分解后，我们得到了五个概念（浪漫，科幻剧，外国，纪录片和冒险）

+   低秩如何帮助？

+   最初我们有 1,000,000 个兴趣点

+   在 SVD 之后，甚至在我们开始使用奇异值（矩阵 S 的对角线）选择我们想要保留的内容之前，我们得到了总的兴趣点数= U（1,000 x 5）+ S（5 x 5）+ V（1,000 x 5）

+   现在我们不再使用 1 百万个数据点（矩阵 A，即 1,000 x 1,000），而是有了 5,000+25+5,000，大约有 10,000 个数据点，这要少得多

+   选择奇异值的行为允许我们决定我们想要保留多少，以及我们想要丢弃多少（你真的想向用户展示最低的 900 部电影推荐吗？这有价值吗？）

# 另见

+   RowMatrix 的文档可以在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.distributed.RowMatrix`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.distributed.RowMatrix)和[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.SingularValueDecomposition`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.SingularValueDecomposition)找到

# 主成分分析（PCA）用于在 Spark 中为机器学习选择最有效的潜在因子

在这个方案中，我们使用**PCA**（主成分分析）将高维数据（表面维度）映射到低维空间（实际维度）。难以置信，但 PCA 的根源早在 1901 年（参见 K. Pearson 的著作）和 1930 年代由 H. Hotelling 独立提出。

PCA 试图以最大化垂直轴上的方差的方式选择新的组件，并有效地将高维原始特征转换为一个具有派生组件的低维空间，这些组件可以以更简洁的形式解释变化（区分类别）。

PCA 背后的直觉如下图所示。现在假设我们的数据有两个维度（x，y），我们要问的问题是，大部分变化（和区分）是否可以用一个维度或更准确地说是原始特征的线性组合来解释：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00265.jpeg)

# 如何做...

1.  克利夫兰心脏病数据库是机器学习研究人员使用的一个已发布的数据集。该数据集包含十几个字段，对克利夫兰数据库的实验主要集中在试图简单地区分疾病的存在（值 1,2,3）和不存在（值 0）（在目标列，第 14 列）。

1.  克利夫兰心脏病数据集可在[`archive.ics.uci.edu/ml/machine-learning-databases/heart-disease/processed.cleveland.data`](http://archive.ics.uci.edu/ml/machine-learning-databases/heart-disease/processed.cleveland.data)找到。

1.  数据集包含以下属性（年龄，性别，cp，trestbps，chol，fbs，restecg，thalach，exang，oldpeak，slope，ca，thal，num），如下表的标题所示：

有关各个属性的详细解释，请参阅：[`archive.ics.uci.edu/ml/datasets/Heart+Disease`](http://archive.ics.uci.edu/ml/datasets/Heart+Disease)

1.  数据集将如下所示：

| **age** | **sex** | **cp** | **trestbps** | **chol** | **fbs** | **restecg** | **thalach** | **exang** | **oldpeak** | **slope** | **ca** | **thal** | **num** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 63 | 1 | 1 | 145 | 233 | 1 | 2 | 150 | 0 | 2.3 | 3 | 0 | 6 | 0 |
| 67 | 1 | 4 | 160 | 286 | 0 | 2 | 108 | 1 | 1.5 | 2 | 3 | 3 | 2 |
| 67 | 1 | 4 | 120 | 229 | 0 | 2 | 129 | 1 | 2.6 | 2 | 2 | 7 | 1 |
| 37 | 1 | 3 | 130 | 250 | 0 | 0 | 187 | 0 | 3.5 | 3 | 0 | 3 | 0 |
| 41 | 0 | 2 | 130 | 204 | 0 | 2 | 172 | 0 | 1.4 | 1 | 0 | 3 | 0 |
| 56 | 1 | 2 | 120 | 236 | 0 | 0 | 178 | 0 | 0.8 | 1 | 0 | 3 | 0 |
| 62 | 0 | 4 | 140 | 268 | 0 | 2 | 160 | 0 | 3.6 | 3 | 2 | 3 | 3 |
| 57 | 0 | 4 | 120 | 354 | 0 | 0 | 163 | 1 | 0.6 | 1 | 0 | 3 | 0 |
| 63 | 1 | 4 | 130 | 254 | 0 | 2 | 147 | 0 | 1.4 | 2 | 1 | 7 | 2 |
| 53 | 1 | 4 | 140 | 203 | 1 | 2 | 155 | 1 | 3.1 | 3 | 0 | 7 | 1 |
| 57 | 1 | 4 | 140 | 192 | 0 | 0 | 148 | 0 | 0.4 | 2 | 0 | 6 | 0 |
| 56 | 0 | 2 | 140 | 294 | 0 | 2 | 153 | 0 | 1.3 | 2 | 0 | 3 | 0 |
| 56 | 1 | 3 | 130 | 256 | 1 | 2 | 142 | 1 | 0.6 | 2 | 1 | 6 | 2 |
| 44 | 1 | 2 | 120 | 263 | 0 | 0 | 173 | 0 | 0 | 1 | 0 | 7 | 0 |
| 52 | 1 | 3 | 172 | 199 | 1 | 0 | 162 | 0 | 0.5 | 1 | 0 | 7 | 0 |
| 57 | 1 | 3 | 150 | 168 | 0 | 0 | 174 | 0 | 1.6 | 1 | 0 | 3 | 0 |
| ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

`package spark.ml.cookbook.chapter11`.

1.  导入 Spark 会话所需的包：

```scala
import org.apache.log4j.{Level, Logger}
import org.apache.spark.ml.feature.PCA
import org.apache.spark.ml.linalg.Vectors
import org.apache.spark.sql.SparkSession
```

1.  创建 Spark 的配置和 Spark 会话，以便我们可以访问集群：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)
val spark = SparkSession
.builder
.master("local[*]")
.appName("MyPCA")
.config("spark.sql.warehouse.dir", ".")
.getOrCreate()
```

1.  我们读取原始数据文件并计算原始数据：

```scala
val dataFile = "../data/sparkml2/chapter11/processed.cleveland.data"
val rawdata = spark.sparkContext.textFile(dataFile).map(_.trim)
println(rawdata.count())
```

在控制台中，我们得到以下内容：

```scala
303
```

1.  我们对数据集进行预处理（详细信息请参见前面的代码）：

```scala
val data = rawdata.filter(text => !(text.isEmpty || text.indexOf("?") > -1))
 .map { line =>
 val values = line.split(',').map(_.toDouble)

 Vectors.dense(values)
 }

 println(data.count())

data.take(2).foreach(println)
```

在前面的代码中，我们过滤了缺失的数据记录，并使用 Spark DenseVector 来托管数据。在过滤缺失数据后，我们在控制台中得到以下数据计数：

```scala
297
```

记录打印，`2`，将如下所示：

```scala
[63.0,1.0,1.0,145.0,233.0,1.0,2.0,150.0,0.0,2.3,3.0,0.0,6.0,0.0]
[67.0,1.0,4.0,160.0,286.0,0.0,2.0,108.0,1.0,1.5,2.0,3.0,3.0,2.0]
```

1.  我们从数据 RDD 创建一个 DataFrame，并创建一个用于计算的 PCA 对象：

```scala
val df = sqlContext.createDataFrame(data.map(Tuple1.apply)).toDF("features")
val pca = new PCA()
.setInputCol("features")
.setOutputCol("pcaFeatures")
.setK(4)
.fit(df)
```

1.  PCA 模型的参数如前面的代码所示。我们将`K`值设置为`4`。`K`代表在完成降维算法后我们感兴趣的前 K 个主成分的数量。

1.  另一种选择也可以通过矩阵 API 实现：`mat.computePrincipalComponents(4)`。在这种情况下，`4`代表了在完成降维后的前 K 个主成分。

1.  我们使用 transform 函数进行计算，并在控制台中显示结果：

```scala
val pcaDF = pca.transform(df)
val result = pcaDF.select("pcaFeatures")
result.show(false)
```

以下内容将显示在控制台上。

您所看到的是四个新的 PCA 组件（PC1、PC2、PC3 和 PC4），可以替代原始的 14 个特征。我们已经成功地将高维空间（14 个维度）映射到了一个低维空间（四个维度）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00266.gif)

1.  从 Spark Master（`http://localhost:4040/jobs`）中，您还可以跟踪作业，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00267.jpeg)

1.  然后通过停止 Spark 会话来关闭程序：

```scala
spark.stop()
```

# 工作原理...

在加载和处理数据之后，通过以下代码完成了 PCA 的核心工作：

```scala
val pca = new PCA()
 .setInputCol("features")
 .setOutputCol("pcaFeatures")
 .setK(4)
 .fit(df)
```

`PCA()`调用允许我们选择需要多少个组件（`setK(4)`）。在这个配方的情况下，我们选择了前四个组件。

目标是从原始的高维数据中找到一个较低维度的空间（降低的 PCA 空间），同时保留结构属性（沿主成分轴的数据方差），以便最大限度地区分带标签的数据，而无需原始的高维空间要求。

下图显示了一个样本 PCA 图表。在降维后，它将看起来像下面这样--在这种情况下，我们可以很容易地看到大部分方差由前四个主成分解释。如果您快速检查图表（红线），您会看到第四个组件后方差如何迅速消失。这种膝盖图（方差与组件数量的关系）帮助我们快速选择所需的组件数量（在这种情况下，四个组件）来解释大部分方差。总之，几乎所有的方差（绿线）可以累积地归因于前四个组件，因为它几乎达到了 1.0，同时可以通过红线追踪每个单独组件的贡献量：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00268.jpeg)

上面的图表是“凯撒法则”的描述，这是选择组件数量最常用的方法。要生成图表，可以使用 R 来绘制特征值与主成分的关系，或者使用 Python 编写自己的代码。

请参见密苏里大学的以下链接以在 R 中绘制图表：

[`web.missouri.edu/~huangf/data/mvnotes/Documents/pca_in_r_2.html`](http://web.missouri.edu/~huangf/data/mvnotes/Documents/pca_in_r_2.html)。

如前所述，图表与凯撒法则有关，凯撒法则指出在特定主成分中加载的更多相关变量，该因子在总结数据方面就越重要。在这种情况下，特征值可以被认为是一种衡量组件在总结数据方面的好坏的指标（在最大方差方向上）。

使用 PCA 类似于其他方法，我们试图学习数据的分布。我们仍然需要每个属性的平均值和 K（要保留的组件数量），这只是一个估计的协方差。简而言之，降维发生是因为我们忽略了具有最小方差的方向（PCA 组件）。请记住，PCA 可能很困难，但您可以控制发生的事情以及保留多少（使用膝盖图表来选择 K 或要保留的组件数量）。

有两种计算 PCA 的方法：

+   协方差方法

+   **奇异值分解**（**SVD**）

我们将在这里概述协方差矩阵方法（直接特征向量和特征值加上居中），但是请随时参考 SVD 配方（*Singular Value Decomposition（SVD）在 Spark 中减少高维度*）以了解 SVD 与 PCA 的内部工作原理。

用协方差矩阵方法进行 PCA 算法，简而言之，涉及以下内容：

1.  给定一个 N 乘以 M 的矩阵：

1.  N = 训练数据的总数

1.  M 是特定的维度（或特征）

1.  M x N 的交集是一个带有样本值的调用

1.  计算平均值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00269.jpeg)

1.  通过从每个观察中减去平均值来对数据进行中心化（标准化）：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00270.jpeg)

1.  构建协方差矩阵：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00271.jpeg)

1.  计算协方差矩阵的特征向量和特征值（这很简单，但要记住并非所有矩阵都可以分解）。

1.  选择具有最大特征值的特征向量。

1.  特征值越大，对组件的方差贡献越大。

# 还有更多...

使用 PCA 在这个案例中的净结果是，原始的 14 维搜索空间（也就是说 14 个特征）被减少到解释原始数据集中几乎所有变化的 4 个维度。

PCA 并不纯粹是一个机器学习概念，在机器学习运动之前，它在金融领域已经使用了很多年。在本质上，PCA 使用正交变换（每个组件都与其他组件垂直）将原始特征（明显的维度）映射到一组新推导的维度，以便删除大部分冗余和共线性属性。推导的（实际的潜在维度）组件是原始属性的线性组合。

虽然使用 RDD 从头开始编程 PCA 很容易，但学习它的最佳方法是尝试使用神经网络实现 PCA，并查看中间结果。您可以在 Café（在 Spark 上）中进行此操作，或者只是 Torch，以查看它是一个直线转换，尽管围绕它存在一些神秘。在本质上，无论您使用协方差矩阵还是 SVD 进行分解，PCA 都是线性代数的基本练习。

Spark 在 GitHub 上提供了 PCA 的源代码示例，分别在降维和特征提取部分。

# 另请参阅

+   PCA 的文档可以在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.PCA`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.PCA)和[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.PCAModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.PCAModel)找到。

关于 PCA 的使用和缺点的一些建议：

+   有些数据集是相互排斥的，因此特征值不会下降（矩阵中每个值都是必需的）。例如，以下向量(.5,0,0), (0,.5,0,0), (0,0,.5,0), and (0,0,0,.5)......不会允许任何特征值下降。

+   PCA 是线性的，试图通过使用均值和协方差矩阵来学习高斯分布。

+   有时，两个彼此平行的高斯分布不会允许 PCA 找到正确的方向。在这种情况下，PCA 最终会终止并找到一些方向并输出它们，但它们是否是最好的呢？


# 第十二章：使用 Spark 2.0 ML 库实现文本分析

在本章中，我们将涵盖以下示例：

+   使用 Spark 进行词频统计-所有都计算

+   使用 Word2Vec 在 Spark 中显示相似的单词

+   下载维基百科的完整转储，用于实际的 Spark ML 项目

+   使用潜在语义分析进行文本分析，使用 Spark 2.0

+   在 Spark 2.0 中使用潜在狄利克雷分配进行主题建模

# 介绍

文本分析处于机器学习、数学、语言学和自然语言处理的交叉点。文本分析，在旧文献中称为文本挖掘，试图从非结构化和半结构化数据中提取信息并推断出更高级别的概念、情感和语义细节。重要的是要注意，传统的关键字搜索无法处理嘈杂、模糊和无关的标记和概念，需要根据实际上下文进行过滤。

最终，我们试图做的是针对一组给定的文档（文本、推文、网络和社交媒体），确定沟通的要点以及它试图传达的概念（主题和概念）。如今，将文档分解为其部分和分类是太原始了，无法被视为文本分析。我们可以做得更好。

Spark 提供了一套工具和设施，使文本分析变得更容易，但用户需要结合技术来构建一个可行的系统（例如 KKN 聚类和主题建模）。

值得一提的是，许多商业系统使用多种技术的组合来得出最终答案。虽然 Spark 拥有足够数量的技术，在规模上运行得非常好，但可以想象，任何文本分析系统都可以从图形模型（即 GraphFrame、GraphX）中受益。下图总结了 Spark 提供的文本分析工具和设施：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00272.gif)

文本分析是一个新兴且重要的领域，因为它适用于许多领域，如安全、客户参与、情感分析、社交媒体和在线学习。使用文本分析技术，可以将传统数据存储（即结构化数据和数据库表）与非结构化数据（即客户评论、情感和社交媒体互动）结合起来，以确定更高级的理解和更全面的业务单位视图，这在以前是不可能的。在处理选择社交媒体和非结构化文本作为其主要沟通方式的千禧一代时，这尤为重要。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00273.jpeg)

非结构化文本的主要挑战在于无法使用传统的数据平台工具，如 ETL 来提取并对数据进行排序。我们需要结合 NLP 技术的新数据整理、ML 和统计方法，可以提取信息和洞察力。社交媒体和客户互动，比如呼叫中心的通话记录，包含了有价值的信息，如果不加以重视就会失去竞争优势。

我们不仅需要文本分析来处理静态的大数据，还必须考虑到动态的大数据，比如推文和数据流，才能有效。

处理非结构化数据有几种方法。下图展示了当今工具包中的技术。虽然基于规则的系统可能适用于有限的文本和领域，但由于其特定的决策边界设计为在特定领域中有效，因此无法推广。新系统使用统计和 NLP 技术以实现更高的准确性和规模。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00274.jpeg)

在本章中，我们涵盖了四个示例和两个实际数据集，以演示 Spark 在规模上处理非结构化文本分析的能力。

首先，我们从一个简单的配方开始，不仅模仿早期的网络搜索（关键词频率），而且还以原始代码格式提供了 TF-IDF 的见解。这个配方试图找出一个单词或短语在文档中出现的频率。尽管听起来难以置信，但实际上美国曾对这种技术发出了专利！

其次，我们使用一个众所周知的算法 Word2Vec，它试图回答这样一个问题，即*如果我给你一个单词，你能告诉我周围的单词，或者它的邻居是什么吗？*这是使用统计技术在文档中寻找同义词的好方法。

第三，我们实现了**潜在语义分析**（**LSA**），这是一种主题提取方法。这种方法是在科罗拉多大学博尔德分校发明的，并且一直是社会科学的主要工具。

第四，我们实现了**潜在狄利克雷分配**（**LDA**）来演示主题建模，其中抽象概念以可扩展和有意义的方式（例如，家庭，幸福，爱情，母亲，家庭宠物，孩子，购物和聚会）提取并与短语或单词相关联。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00275.jpeg)

# 使用 Spark 进行词频统计 - 一切都计算在内

对于这个配方，我们将从 Project Gutenberg 下载一本文本格式的书籍，网址为[`www.gutenberg.org/cache/epub/62/pg62.txt`](http://www.gutenberg.org/cache/epub/62/pg62.txt)。

Project Gutenberg 提供了超过 5 万本各种格式的免费电子书供人类使用。请阅读他们的使用条款；让我们不要使用命令行工具下载任何书籍。

当您查看文件的内容时，您会注意到书的标题和作者是《火星公主》的作者是埃德加·赖斯·伯勒斯。

这本电子书可以供任何人在任何地方免费使用，几乎没有任何限制。您可以复制它，赠送它，或者根据本电子书在线附带的 Project Gutenberg 许可证条款进行重复使用，网址为[`www.gutenberg.org/`](http://www.gutenberg.org/)。

然后我们使用下载的书籍来演示 Scala 和 Spark 的经典单词计数程序。这个例子一开始可能看起来有些简单，但我们正在开始进行文本处理的特征提取过程。此外，对于理解 TF-IDF 的概念，对文档中单词出现次数的一般理解将有所帮助。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中开始一个新项目。确保包含必要的 JAR 文件。

1.  该配方的`package`语句如下：

```scala
package spark.ml.cookbook.chapter12
```

1.  导入 Scala、Spark 和 JFreeChart 所需的包：

```scala
import org.apache.log4j.{Level, Logger}
import org.apache.spark.sql.SQLContext
import org.apache.spark.{SparkConf, SparkContext}
import org.jfree.chart.axis.{CategoryAxis, CategoryLabelPositions}
import org.jfree.chart.{ChartFactory, ChartFrame, JFreeChart}
import org.jfree.chart.plot.{CategoryPlot, PlotOrientation}
import org.jfree.data.category.DefaultCategoryDataset
```

1.  我们将定义一个函数来在窗口中显示我们的 JFreeChart：

```scala
def show(chart: JFreeChart) {
val frame = new ChartFrame("", chart)
   frame.pack()
   frame.setVisible(true)
 }
```

1.  让我们定义我们书籍文件的位置：

```scala
val input = "../data/sparkml2/chapter12/pg62.txt"
```

1.  使用工厂构建器模式创建一个带有配置的 Spark 会话：

```scala
val spark = SparkSession
 .builder .master("local[*]")
 .appName("ProcessWordCount")
 .config("spark.sql.warehouse.dir", ".")
 .getOrCreate()
import spark.implicits._
```

1.  我们应该将日志级别设置为警告，否则输出将难以跟踪：

```scala
Logger.getRootLogger.setLevel(Level.*WARN*)
```

1.  我们读取停用词文件，稍后将用作过滤器：

```scala
val stopwords = scala.io.Source.fromFile("../data/sparkml2/chapter12/stopwords.txt").getLines().toSet
```

1.  停用词文件包含常用词，这些词在匹配或比较文档时没有相关价值，因此它们将被排除在术语池之外。

1.  我们现在加载书籍进行标记化、分析、应用停用词、过滤、计数和排序：

```scala
val lineOfBook = spark.sparkContext.textFile(input)
 .flatMap(line => line.split("\\W+"))
 .map(_.toLowerCase)
 .filter( s => !stopwords.contains(s))
 .filter( s => s.length >= 2)
 .map(word => (word, 1))
 .reduceByKey(_ + _)
 .sortBy(_._2, false)
```

1.  我们取出出现频率最高的 25 个单词：

```scala
val top25 = lineOfBook.take(25)
```

1.  我们循环遍历结果 RDD 中的每个元素，生成一个类别数据集模型来构建我们的单词出现图表：

```scala
val dataset = new DefaultCategoryDataset()
top25.foreach( {case (term: String, count: Int) => dataset.setValue(count, "Count", term) })
```

显示单词计数的条形图：

```scala
val chart = ChartFactory.createBarChart("Term frequency",
 "Words", "Count", dataset, PlotOrientation.VERTICAL,
 false, true, false)

 val plot = chart.getCategoryPlot()
 val domainAxis = plot.getDomainAxis();
 domainAxis.setCategoryLabelPositions(CategoryLabelPositions.DOWN_45);
show(chart)
```

以下图表显示了单词计数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00276.jpeg)

1.  我们通过停止 SparkContext 来关闭程序：

```scala
spark.stop()
```

# 它是如何工作的...

我们首先通过正则表达式加载下载的书籍并对其进行标记化。下一步是将所有标记转换为小写，并从我们的标记列表中排除停用词，然后过滤掉任何少于两个字符长的单词。

去除停用词和特定长度的单词会减少我们需要处理的特征数量。这可能并不明显，但根据各种处理标准去除特定单词会减少我们的机器学习算法后续处理的维度数量。

最后，我们按降序对结果进行了排序，取前 25 个，并为其显示了条形图。

# 还有更多...

在本食谱中，我们有了关键词搜索的基础。重要的是要理解主题建模和关键词搜索之间的区别。在关键词搜索中，我们试图根据出现的次数将短语与给定文档关联起来。在这种情况下，我们将指导用户查看出现次数最多的一组文档。

# 另请参阅

这个算法的演进的下一步，开发者可以尝试作为扩展的一部分，是添加权重并得出加权平均值，但是 Spark 提供了一个我们将在即将到来的食谱中探讨的设施。

# 使用 Word2Vec 在 Spark 中显示相似的单词

在本食谱中，我们将探讨 Word2Vec，这是 Spark 用于评估单词相似性的工具。Word2Vec 算法受到了一般语言学中的*分布假设*的启发。在本质上，它试图表达的是在相同上下文中出现的标记（即，与目标的距离）倾向于支持相同的原始概念/含义。

Word2Vec 算法是由 Google 的一个研究团队发明的。请参考本食谱中*还有更多...*部分提到的一篇白皮书，其中更详细地描述了 Word2Vec。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  本食谱的`package`语句如下：

```scala
package spark.ml.cookbook.chapter12
```

1.  导入 Scala 和 Spark 所需的包：

```scala
import org.apache.log4j.{Level, Logger}
import org.apache.spark.ml.feature.{RegexTokenizer, StopWordsRemover, Word2Vec}
import org.apache.spark.sql.{SQLContext, SparkSession}
import org.apache.spark.{SparkConf, SparkContext}
```

1.  让我们定义我们的书籍文件的位置：

```scala
val input = "../data/sparkml2/chapter12/pg62.txt"
```

1.  使用工厂构建器模式创建具有配置的 Spark 会话：

```scala
val spark = SparkSession
         .builder
.master("local[*]")
         .appName("Word2Vec App")
         .config("spark.sql.warehouse.dir", ".")
         .getOrCreate()
import spark.implicits._
```

1.  我们应该将日志级别设置为警告，否则输出将难以跟踪：

```scala
Logger.getRootLogger.setLevel(Level.WARN)
```

1.  我们加载书籍并将其转换为 DataFrame：

```scala
val df = spark.read.text(input).toDF("text")
```

1.  现在，我们将每一行转换为一个词袋，利用 Spark 的正则表达式标记器，将每个术语转换为小写，并过滤掉任何字符长度少于四个的术语：

```scala
val tokenizer = new RegexTokenizer()
 .setPattern("\\W+")
 .setToLowercase(true)
 .setMinTokenLength(4)
 .setInputCol("text")
 .setOutputCol("raw")
 val rawWords = tokenizer.transform(df)
```

1.  我们使用 Spark 的`StopWordRemover`类来去除停用词：

```scala
val stopWords = new StopWordsRemover()
 .setInputCol("raw")
 .setOutputCol("terms")
 .setCaseSensitive(false)
 val wordTerms = stopWords.transform(rawWords)
```

1.  我们应用 Word2Vec 机器学习算法来提取特征：

```scala
val word2Vec = new Word2Vec()
 .setInputCol("terms")
 .setOutputCol("result")
 .setVectorSize(3)
 .setMinCount(0)
val model = word2Vec.fit(wordTerms)
```

1.  我们从书中找到*火星*的十个同义词：

```scala
val synonyms = model.findSynonyms("martian", 10)
```

1.  显示模型找到的十个同义词的结果：

```scala
synonyms.show(false)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00277.gif)

1.  我们通过停止 SparkContext 来关闭程序：

```scala
spark.stop()
```

# 它是如何工作的...

Spark 中的 Word2Vec 使用 skip-gram 而不是**连续词袋**（**CBOW**），后者更适合**神经网络**（**NN**）。在本质上，我们试图计算单词的表示。强烈建议用户了解局部表示与分布式表示之间的区别，这与单词本身的表面含义非常不同。

如果我们使用分布式向量表示单词，那么相似的单词自然会在向量空间中靠在一起，这是一种理想的模式抽象和操作的泛化技术（即，我们将问题简化为向量运算）。

对于一组经过清理并准备好进行处理的单词*{Word[1,] Word[2, .... ,]Word[n]}*，我们要做的是定义一个最大似然函数（例如，对数似然），然后继续最大化似然（即，典型的 ML）。对于熟悉 NN 的人来说，这是一个简单的多类 softmax 模型。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00278.jpeg)

我们首先将免费书籍加载到内存中，并将其标记为术语。然后将术语转换为小写，并过滤掉任何少于四个字的单词。最后应用停用词，然后进行 Word2Vec 计算。

# 还有更多...

无论如何，你如何找到相似的单词？有多少算法可以解决这个问题，它们又有什么不同？Word2Vec 算法已经存在一段时间了，还有一个叫做 CBOW 的对应算法。请记住，Spark 提供了 skip-gram 方法作为实现技术。

Word2Vec 算法的变体如下：

+   **Continuous Bag of Words (CBOW)**：给定一个中心词，周围的词是什么？

+   **Skip-gram**：如果我们知道周围的单词，我们能猜出缺失的单词吗？

有一种称为**skip-gram 模型与负采样**（**SGNS**）的算法变体，似乎优于其他变体。

共现是 CBOW 和 skip-gram 的基本概念。尽管 skip-gram 没有直接使用共现矩阵，但它间接使用了它。

在这个食谱中，我们使用了 NLP 中的*停用词*技术，在运行算法之前对我们的语料库进行了清理。停用词是英语单词，比如“*the*”，需要被移除，因为它们对结果没有任何改进。

另一个重要的概念是*词干提取*，这里没有涉及，但将在以后的食谱中演示。词干提取去除额外的语言构件，并将单词减少到其根（例如，“工程”、“工程师”和“工程师”变成“Engin”，这是根）。

在以下 URL 找到的白皮书应该对 Word2Vec 提供更深入的解释：

[`arxiv.org/pdf/1301.3781.pdf`](http://arxiv.org/pdf/1301.3781.pdf)

# 另请参阅

Word2Vec 食谱的文档：

+   `Word2Vec()`: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.Word2Vec`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.Word2Vec)

+   `Word2VecModel()`: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.Word2VecModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.Word2VecModel)

+   `StopWordsRemover()`: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.StopWordsRemover`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.StopWordsRemover)

# 下载维基百科的完整转储以进行真实的 Spark ML 项目

在这个食谱中，我们将下载并探索维基百科的转储，以便我们可以有一个现实生活的例子。在这个食谱中，我们将下载的数据集是维基百科文章的转储。您将需要命令行工具**curl**或浏览器来检索一个压缩文件，目前大约为 13.6 GB。由于文件大小，我们建议使用 curl 命令行工具。

# 如何做...

1.  您可以使用以下命令开始下载数据集：

```scala
curl -L -O http://dumps.wikimedia.org/enwiki/latest/enwiki-latest-pages-articles-multistream.xml.bz2
```

1.  现在你想要解压 ZIP 文件：

```scala
bunzip2 enwiki-latest-pages-articles-multistream.xml.bz2
```

这将创建一个名为`enwiki-latest-pages-articles-multistream.xml`的未压缩文件，大约为 56 GB。

1.  让我们来看看维基百科的 XML 文件：

```scala
head -n50 enwiki-latest-pages-articles-multistream.xml
<mediawiki xmlns=http://www.mediawiki.org/xml/export-0.10/  xsi:schemaLocation="http://www.mediawiki.org/xml/export-0.10/ http://www.mediawiki.org/xml/export-0.10.xsd" version="0.10" xml:lang="en"> 

  <siteinfo> 
    <sitename>Wikipedia</sitename> 
    <dbname>enwiki</dbname> 
    <base>https://en.wikipedia.org/wiki/Main_Page</base> 
    <generator>MediaWiki 1.27.0-wmf.22</generator> 
    <case>first-letter</case> 
    <namespaces> 
      <namespace key="-2" case="first-letter">Media</namespace> 
      <namespace key="-1" case="first-letter">Special</namespace> 
      <namespace key="0" case="first-letter" /> 
      <namespace key="1" case="first-letter">Talk</namespace> 
      <namespace key="2" case="first-letter">User</namespace> 
      <namespace key="3" case="first-letter">User talk</namespace> 
      <namespace key="4" case="first-letter">Wikipedia</namespace> 
      <namespace key="5" case="first-letter">Wikipedia talk</namespace> 
      <namespace key="6" case="first-letter">File</namespace> 
      <namespace key="7" case="first-letter">File talk</namespace> 
      <namespace key="8" case="first-letter">MediaWiki</namespace> 
      <namespace key="9" case="first-letter">MediaWiki talk</namespace> 
      <namespace key="10" case="first-letter">Template</namespace> 
      <namespace key="11" case="first-letter">Template talk</namespace> 
      <namespace key="12" case="first-letter">Help</namespace> 
      <namespace key="13" case="first-letter">Help talk</namespace> 
      <namespace key="14" case="first-letter">Category</namespace> 
      <namespace key="15" case="first-letter">Category talk</namespace> 
      <namespace key="100" case="first-letter">Portal</namespace> 
      <namespace key="101" case="first-letter">Portal talk</namespace> 
      <namespace key="108" case="first-letter">Book</namespace> 
      <namespace key="109" case="first-letter">Book talk</namespace> 
      <namespace key="118" case="first-letter">Draft</namespace> 
      <namespace key="119" case="first-letter">Draft talk</namespace> 
      <namespace key="446" case="first-letter">Education Program</namespace> 
      <namespace key="447" case="first-letter">Education Program talk</namespace> 
      <namespace key="710" case="first-letter">TimedText</namespace> 
      <namespace key="711" case="first-letter">TimedText talk</namespace> 
      <namespace key="828" case="first-letter">Module</namespace> 
      <namespace key="829" case="first-letter">Module talk</namespace> 
      <namespace key="2300" case="first-letter">Gadget</namespace> 
      <namespace key="2301" case="first-letter">Gadget talk</namespace> 
      <namespace key="2302" case="case-sensitive">Gadget definition</namespace> 
      <namespace key="2303" case="case-sensitive">Gadget definition talk</namespace> 
      <namespace key="2600" case="first-letter">Topic</namespace> 
    </namespaces> 
  </siteinfo> 
  <page> 
    <title>AccessibleComputing</title> 
    <ns>0</ns> 
    <id>10</id> 
    <redirect title="Computer accessibility" />
```

# 还有更多...

我们建议使用 XML 文件的分块，并对实验使用抽样，直到准备好进行最终的作业提交。这将节省大量的时间和精力。

# 另请参阅

维基下载的文档可在[`en.wikipedia.org/wiki/Wikipedia:Database_download`](https://en.wikipedia.org/wiki/Wikipedia:Database_download)找到。

# 使用 Spark 2.0 进行文本分析的潜在语义分析

在这个食谱中，我们将利用维基百科文章的数据转储来探索 LSA。LSA 意味着分析一系列文档，以找出这些文档中的隐藏含义或概念。

在本章的第一个示例中，我们介绍了 TF（即术语频率）技术的基础知识。在这个示例中，我们使用 HashingTF 来计算 TF，并使用 IDF 将模型拟合到计算的 TF 中。在其核心，LSA 使用**奇异值分解**（**SVD**）对术语频率文档进行降维，从而提取最重要的概念。在我们开始分析之前，还有其他一些清理步骤需要做（例如，停用词和词干处理）来清理词袋。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  该示例的包语句如下：

```scala
package spark.ml.cookbook.chapter12
```

1.  导入 Scala 和 Spark 所需的包：

```scala
import edu.umd.cloud9.collection.wikipedia.WikipediaPage
 import edu.umd.cloud9.collection.wikipedia.language.EnglishWikipediaPage
 import org.apache.hadoop.fs.Path
 import org.apache.hadoop.io.Text
 import org.apache.hadoop.mapred.{FileInputFormat, JobConf}
 import org.apache.log4j.{Level, Logger}
 import org.apache.spark.mllib.feature.{HashingTF, IDF}
 import org.apache.spark.mllib.linalg.distributed.RowMatrix
 import org.apache.spark.sql.SparkSession
 import org.tartarus.snowball.ext.PorterStemmer
```

以下两个语句导入了处理维基百科 XML 转储/对象所需的`Cloud9`库工具包元素。`Cloud9`是一个库工具包，使得开发人员更容易访问、整理和处理维基百科 XML 转储。有关更详细信息，请参阅以下代码行：

```scala
import edu.umd.cloud9.collection.wikipedia.WikipediaPage
import edu.umd.cloud9.collection.wikipedia.language.EnglishWikipediaPage
```

维基百科是一个免费的知识体，可以通过以下维基百科下载链接免费下载为 XML 块/对象的转储：

[`en.wikipedia.org/wiki/Wikipedia:Database_download`](https://en.wikipedia.org/wiki/Wikipedia:Database_download)

文本的复杂性和结构可以通过`Cloud9`工具包轻松处理，该工具包可以使用之前列出的`import`语句来访问和处理文本。

以下链接提供了有关`Cloud9`库的一些信息：

+   主页位于[`lintool.github.io/Cloud9/docs/content/wikipedia.html`](https://lintool.github.io/Cloud9/docs/content/wikipedia.html)。

+   源代码可在[`grepcode.com/file/repo1.maven.org/maven2/edu.umd/cloud9/2.0.0/edu/umd/cloud9/collection/wikipedia/WikipediaPage.java`](http://grepcode.com/file/repo1.maven.org/maven2/edu.umd/cloud9/2.0.0/edu/umd/cloud9/collection/wikipedia/WikipediaPage.java)和[`grepcode.com/file/repo1.maven.org/maven2/edu.umd/cloud9/2.0.1/edu/umd/cloud9/collection/wikipedia/language/EnglishWikipediaPage.java`](http://grepcode.com/file/repo1.maven.org/maven2/edu.umd/cloud9/2.0.1/edu/umd/cloud9/collection/wikipedia/language/EnglishWikipediaPage.java)上找到。

接下来，执行以下步骤：

1.  我们定义一个函数来解析维基百科页面并返回页面的标题和内容文本：

```scala
def parseWikiPage(rawPage: String): Option[(String, String)] = {
 val wikiPage = new EnglishWikipediaPage()
 WikipediaPage.*readPage*(wikiPage, rawPage)

 if (wikiPage.isEmpty
 || wikiPage.isDisambiguation
 || wikiPage.isRedirect
 || !wikiPage.isArticle) {
 None
 } else {
 Some(wikiPage.getTitle, wikiPage.getContent)
 }
 }
```

1.  我们定义一个简短的函数来应用 Porter 词干算法到术语上：

```scala
def wordStem(stem: PorterStemmer, term: String): String = {
 stem.setCurrent(term)
 stem.stem()
 stem.getCurrent
 }
```

1.  我们定义一个函数将页面的内容文本标记为术语：

```scala
def tokenizePage(rawPageText: String, stopWords: Set[String]): Seq[String] = {
 val stem = new PorterStemmer()

 rawPageText.split("\\W+")
 .map(_.toLowerCase)
 .filterNot(s => stopWords.contains(s))
 .map(s => wordStem(stem, s))
 .filter(s => s.length > 3)
 .distinct
 .toSeq
 }
```

1.  让我们定义维基百科数据转储的位置：

```scala
val input = "../data/sparkml2/chapter12/enwiki_dump.xml"
```

1.  为 Hadoop XML 流处理创建一个作业配置：

```scala
val jobConf = new JobConf()
 jobConf.set("stream.recordreader.class", "org.apache.hadoop.streaming.StreamXmlRecordReader")
 jobConf.set("stream.recordreader.begin", "<page>")
 jobConf.set("stream.recordreader.end", "</page>")
```

1.  为 Hadoop XML 流处理设置数据路径：

```scala
FileInputFormat.addInputPath(jobConf, new Path(input))
```

1.  使用工厂构建器模式创建一个带有配置的`SparkSession`：

```scala
val spark = SparkSession
   .builder.master("local[*]")
   .appName("ProcessLSA App")
   .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
   .config("spark.sql.warehouse.dir", ".")
   .getOrCreate()
```

1.  我们应该将日志级别设置为警告，否则输出将难以跟踪：

```scala
Logger.getRootLogger.setLevel(Level.WARN)
```

1.  我们开始处理庞大的维基百科数据转储成文章页面，取样文件：

```scala
val wikiData = spark.sparkContext.hadoopRDD(
 jobConf,
 classOf[org.apache.hadoop.streaming.StreamInputFormat],
 classOf[Text],
 classOf[Text]).sample(false, .1)
```

1.  接下来，我们将样本数据处理成包含标题和页面内容文本的 RDD：

```scala
val wikiPages = wikiData.map(_._1.toString).flatMap(*parseWikiPage*)
```

1.  我们现在输出我们将处理的维基百科文章的数量：

```scala
println("Wiki Page Count: " + wikiPages.count())
```

1.  我们将加载停用词以过滤页面内容文本：

```scala
val stopwords = scala.io.Source.fromFile("../data/sparkml2/chapter12/stopwords.txt").getLines().toSet
```

1.  我们标记化页面内容文本，将其转换为术语以进行进一步处理：

```scala
val wikiTerms = wikiPages.map{ case(title, text) => tokenizePage(text, stopwords) }
```

1.  我们使用 Spark 的`HashingTF`类来计算我们标记化的页面内容文本的术语频率：

```scala
val hashtf = new HashingTF()
 val tf = hashtf.transform(wikiTerms)
```

1.  我们获取术语频率并利用 Spark 的 IDF 类计算逆文档频率：

```scala
val idf = new IDF(minDocFreq=2)
 val idfModel = idf.fit(tf)
 val tfidf = idfModel.transform(tf)
```

1.  使用逆文档频率生成一个`RowMatrix`并计算奇异值分解：

```scala
tfidf.cache()
 val rowMatrix = new RowMatrix(tfidf)
 val svd = rowMatrix.computeSVD(k=25, computeU = true)

 println(svd)
```

**U**：行将是文档，列将是概念。

**S**：元素将是每个概念的变化量。

**V**：行将是术语，列将是概念。

1.  通过停止 SparkContext 来关闭程序：

```scala
spark.stop()
```

# 工作原理...

该示例首先通过使用 Cloud9 Hadoop XML 流处理工具加载维基百科 XML 的转储来开始。一旦我们解析出页面文本，标记化阶段调用将我们的维基百科页面文本流转换为标记。在标记化阶段，我们使用 Porter 词干提取器来帮助将单词减少到一个共同的基本形式。

有关词干处理的更多细节，请参阅[`en.wikipedia.org/wiki/Stemming`](https://en.wikipedia.org/wiki/Stemming)。

下一步是对每个页面标记使用 Spark HashingTF 计算词项频率。完成此阶段后，我们利用了 Spark 的 IDF 生成逆文档频率。

最后，我们使用 TF-IDF API 并应用奇异值分解来处理因子分解和降维。

以下屏幕截图显示了该步骤和配方的流程：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00279.jpeg)

Cloud9 Hadoop XML 工具和其他一些必需的依赖项可以在以下链接找到：

+   `bliki-core-3.0.19.jar`: [`central.maven.org/maven2/info/bliki/wiki/bliki-core/3.0.19/bliki-core-3.0.19.jar`](http://central.maven.org/maven2/info/bliki/wiki/bliki-core/3.0.19/bliki-core-3.0.19.jar)

+   `cloud9-2.0.1.jar`: [`central.maven.org/maven2/edu/umd/cloud9/2.0.1/cloud9-2.0.1.jar`](http://central.maven.org/maven2/edu/umd/cloud9/2.0.1/cloud9-2.0.1.jar)

+   `hadoop-streaming-2.7.4.jar`: [`central.maven.org/maven2/org/apache/hadoop/hadoop-streaming/2.7.4/hadoop-streaming-2.7.4.jar`](http://central.maven.org/maven2/org/apache/hadoop/hadoop-streaming/2.7.4/hadoop-streaming-2.7.4.jar)

+   `lucene-snowball-3.0.3.jar`: [`central.maven.org/maven2/org/apache/lucene/lucene-snowball/3.0.3/lucene-snowball-3.0.3.jar`](http://central.maven.org/maven2/org/apache/lucene/lucene-snowball/3.0.3/lucene-snowball-3.0.3.jar)

# 还有更多...

现在显而易见，即使 Spark 没有提供直接的 LSA 实现，TF-IDF 和 SVD 的组合也能让我们构建然后分解大语料库矩阵为三个矩阵，这可以通过 SVD 的降维来帮助我们解释结果。我们可以集中精力在最有意义的聚类上（类似于推荐算法）。

SVD 将分解词项频率文档（即文档按属性）为三个不同的矩阵，这些矩阵更有效地提取出*N*个概念（在我们的例子中为*N=27*）从一个难以处理且昂贵的大矩阵中。在机器学习中，我们总是更喜欢高瘦的矩阵（在这种情况下是*U*矩阵）而不是其他变体。

以下是 SVD 的技术：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00280.gif)

SVD 的主要目标是降维以获得所需的（即前*N*个）主题或抽象概念。我们将使用以下输入来获得以下部分中所述的输出。

作为输入，我们将采用*m x n*（*m*为文档数，*n*为术语或属性数）的大矩阵。

这是我们应该得到的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00281.gif)

有关 SVD 的更详细示例和简短教程，请参见以下链接：

+   [`home.iitk.ac.in/~crkrish/MLT/PreRequisites/linalgWithSVD.pdf`](http://home.iitk.ac.in/~crkrish/MLT/PreRequisites/linalgWithSVD.pdf)

+   [`davetang.org/file/Singular_Value_Decomposition_Tutorial.pdf`](http://davetang.org/file/Singular_Value_Decomposition_Tutorial.pdf)

您还可以参考 RStudio 的写作，链接如下：

[`rstudio-pubs-static.s3.amazonaws.com/222293_1c40c75d7faa42869cc59df879547c2b.html`](http://rstudio-pubs-static.s3.amazonaws.com/222293_1c40c75d7faa42869cc59df879547c2b.html)

# 另请参阅

SVD 在第十一章中有详细介绍，*大数据中的高维度诅咒*。

有关 SVD 的图示表示，请参阅第十一章中的示例*使用奇异值分解（SVD）解决高维度问题*，*大数据中的高维度问题*。

有关`SingularValueDecomposition()`的更多详细信息，请参考[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.SingularValueDecomposition`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.SingularValueDecomposition)。

有关`RowMatrix()`的更多详细信息，请参考[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.distributed.RowMatrix`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.distributed.RowMatrix)。

# 在 Spark 2.0 中使用潜在狄利克雷分配进行主题建模

在这个示例中，我们将利用潜在狄利克雷分配来演示主题模型生成，以从一系列文档中推断主题。

我们在之前的章节中已经涵盖了 LDA，因为它适用于聚类和主题建模，但在本章中，我们演示了一个更详细的示例，以展示它在文本分析中对更真实和复杂的数据集的应用。

我们还应用 NLP 技术，如词干处理和停用词，以提供更真实的 LDA 问题解决方法。我们试图发现一组潜在因素（即与原始因素不同），可以以更高效的方式在减少的计算空间中解决和描述解决方案。

当使用 LDA 和主题建模时，经常出现的第一个问题是*狄利克雷是什么？* 狄利克雷只是一种分布，没有别的。请参阅明尼苏达大学的以下链接了解详情：[`www.tc.umn.edu/~horte005/docs/Dirichletdistribution.pdf`](http://www.tc.umn.edu/~horte005/docs/Dirichletdistribution.pdf)。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  该示例的`package`语句如下：

```scala
package spark.ml.cookbook.chapter12
```

1.  导入 Scala 和 Spark 所需的包：

```scala
import edu.umd.cloud9.collection.wikipedia.WikipediaPage
 import edu.umd.cloud9.collection.wikipedia.language.EnglishWikipediaPage
 import org.apache.hadoop.fs.Path
 import org.apache.hadoop.io.Text
 import org.apache.hadoop.mapred.{FileInputFormat, JobConf}
 import org.apache.log4j.{Level, Logger}
 import org.apache.spark.ml.clustering.LDA
 import org.apache.spark.ml.feature._
 import org.apache.spark.sql.SparkSession
```

1.  我们定义一个函数来解析维基百科页面，并返回页面的标题和内容文本：

```scala
def parseWikiPage(rawPage: String): Option[(String, String)] = {
 val wikiPage = new EnglishWikipediaPage()
 WikipediaPage.*readPage*(wikiPage, rawPage)

 if (wikiPage.isEmpty
 || wikiPage.isDisambiguation
 || wikiPage.isRedirect
 || !wikiPage.isArticle) {
 None
 } else {
 *Some*(wikiPage.getTitle, wikiPage.getContent)
 }
 }
```

1.  让我们定义维基百科数据转储的位置：

```scala
val input = "../data/sparkml2/chapter12/enwiki_dump.xml" 
```

1.  我们为 Hadoop XML 流创建作业配置：

```scala
val jobConf = new JobConf()
 jobConf.set("stream.recordreader.class", "org.apache.hadoop.streaming.StreamXmlRecordReader")
 jobConf.set("stream.recordreader.begin", "<page>")
 jobConf.set("stream.recordreader.end", "</page>")
```

1.  我们为 Hadoop XML 流处理设置了数据路径：

```scala
FileInputFormat.addInputPath(jobConf, new Path(input))
```

1.  使用工厂构建器模式创建带有配置的`SparkSession`：

```scala
val spark = SparkSession
    .builder
.master("local[*]")
    .appName("ProcessLDA App")
    .config("spark.serializer",   "org.apache.spark.serializer.KryoSerializer")
    .config("spark.sql.warehouse.dir", ".")
    .getOrCreate()
```

1.  我们应该将日志级别设置为警告，否则输出将难以跟踪：

```scala
Logger.getRootLogger.setLevel(Level.WARN)
```

1.  我们开始处理庞大的维基百科数据转储，将其转换为文章页面并对文件进行抽样：

```scala
val wikiData = spark.sparkContext.hadoopRDD(
 jobConf,
 classOf[org.apache.hadoop.streaming.StreamInputFormat],
 classOf[Text],
 classOf[Text]).sample(false, .1)
```

1.  接下来，我们将我们的样本数据处理成包含标题和页面上下文文本的元组的 RDD，最终生成一个 DataFrame：

```scala
val df = wiki.map(_._1.toString)
 .flatMap(parseWikiPage)
 .toDF("title", "text")
```

1.  现在，我们使用 Spark 的`RegexTokenizer`将 DataFrame 的文本列转换为原始单词，以处理每个维基百科页面：

```scala
val tokenizer = new RegexTokenizer()
 .setPattern("\\W+")
 .setToLowercase(true)
 .setMinTokenLength(4)
 .setInputCol("text")
 .setOutputCol("raw")
 val rawWords = tokenizer.transform(df)
```

1.  下一步是通过从标记中删除所有停用词来过滤原始单词：

```scala
val stopWords = new StopWordsRemover()
 .setInputCol("raw")
 .setOutputCol("words")
 .setCaseSensitive(false)

 val wordData = stopWords.transform(rawWords)
```

1.  我们通过使用 Spark 的`CountVectorizer`类为过滤后的标记生成术语计数，从而生成包含特征列的新 DataFrame：

```scala
val cvModel = new CountVectorizer()
 .setInputCol("words")
 .setOutputCol("features")
 .setMinDF(2)
 .fit(wordData)
 val cv = cvModel.transform(wordData)
 cv.cache()
```

"MinDF"指定必须出现的不同文档术语的最小数量，才能包含在词汇表中。

1.  现在，我们调用 Spark 的 LDA 类来生成主题和标记到主题的分布：

```scala
val lda = new LDA()
 .setK(5)
 .setMaxIter(10)
 .setFeaturesCol("features")
 val model = lda.fit(tf)
 val transformed = model.transform(tf)
```

"K"指的是主题数量，"MaxIter"指的是执行的最大迭代次数。

1.  最后，我们描述了生成的前五个主题并显示：

```scala
val topics = model.describeTopics(5)
 topics.show(false)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00282.jpeg)

1.  现在显示，与它们相关的主题和术语：

```scala
val vocaList = cvModel.vocabulary
topics.collect().foreach { r => {
 println("\nTopic: " + r.get(r.fieldIndex("topic")))
 val y = r.getSeqInt).map(vocaList(_))
 .zip(r.getSeqDouble))
 y.foreach(println)

 }
}
```

控制台输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00283.gif)

1.  通过停止 SparkContext 来关闭程序：

```scala
spark.stop()
```

# 它是如何工作的...

我们首先加载了维基百科文章的转储，并使用 Hadoop XML 利用流式处理 API 将页面文本解析为标记。特征提取过程利用了几个类来设置最终由 LDA 类进行处理，让标记从 Spark 的`RegexTokenize`，`StopwordsRemover`和`HashingTF`中流出。一旦我们有了词频，数据就被传递给 LDA 类，以便将文章在几个主题下进行聚类。

Hadoop XML 工具和其他一些必需的依赖项可以在以下位置找到：

+   `bliki-core-3.0.19.jar`: [`central.maven.org/maven2/info/bliki/wiki/bliki-core/3.0.19/bliki-core-3.0.19.jar`](http://central.maven.org/maven2/info/bliki/wiki/bliki-core/3.0.19/bliki-core-3.0.19.jar)

+   `cloud9-2.0.1.jar`: [`central.maven.org/maven2/edu/umd/cloud9/2.0.1/cloud9-2.0.1.jar`](http://central.maven.org/maven2/edu/umd/cloud9/2.0.1/cloud9-2.0.1.jar)

+   `hadoop-streaming-2.7.4.jar`: [`central.maven.org/maven2/org/apache/hadoop/hadoop-streaming/2.7.4/hadoop-streaming-2.7.4.jar`](http://central.maven.org/maven2/org/apache/hadoop/hadoop-streaming/2.7.4/hadoop-streaming-2.7.4.jar)

+   `lucene-snowball-3.0.3.jar`: [`central.maven.org/maven2/org/apache/lucene/lucene-snowball/3.0.3/lucene-snowball-3.0.3.jar`](http://central.maven.org/maven2/org/apache/lucene/lucene-snowball/3.0.3/lucene-snowball-3.0.3.jar)

# 还有更多...

请参阅第八章中的 LDA 配方，了解更多关于 LDA 算法本身的详细解释。*Apache Spark 2.0 无监督聚类*

来自*机器学习研究杂志（JMLR）*的以下白皮书为那些希望进行深入分析的人提供了全面的处理。这是一篇写得很好的论文，具有基本统计和数学背景的人应该能够毫无问题地理解。

有关 JMLR 的更多详细信息，请参阅[`www.jmlr.org/papers/volume3/blei03a/blei03a.pdf`](http://www.jmlr.org/papers/volume3/blei03a/blei03a.pdf)链接；另一个链接是[`www.cs.colorado.edu/~mozer/Teaching/syllabi/ProbabilisticModels/readings/BleiNgJordan2003.pdf`](https://www.cs.colorado.edu/~mozer/Teaching/syllabi/ProbabilisticModels/readings/BleiNgJordan2003.pdf)。

# 还可以参考

+   构造函数的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDA`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDA)找到

+   LDAModel 的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDAModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDAModel)找到

还可以参考 Spark 的 Scala API 文档：

+   DistributedLDAModel

+   EMLDAOptimizer

+   LDAOptimizer

+   LocalLDAModel

+   OnlineLDAOptimizer


# 第十三章：Spark Streaming 和机器学习库

在本章中，我们将涵盖以下内容：

+   结构化流式处理用于近实时机器学习

+   实时机器学习的流式数据框架

+   实时机器学习的流式数据集

+   使用 queueStream 进行流式数据和调试

+   下载和理解著名的鸢尾花数据，用于无监督分类

+   流式 KMeans 用于实时在线分类器

+   下载葡萄酒质量数据进行流式回归

+   流式线性回归用于实时回归

+   下载皮马糖尿病数据进行监督分类

+   流式逻辑回归用于在线分类器

# 介绍

Spark 流式处理是朝着统一和结构化 API 的发展之路，以解决批处理与流处理的问题。自 Spark 1.3 以来，Spark 流式处理一直可用，使用离散流（DStream）。新的方向是使用无界表模型来抽象底层框架，用户可以使用 SQL 或函数式编程查询表，并以多种模式（完整、增量和追加输出）将输出写入另一个输出表。Spark SQL Catalyst 优化器和 Tungsten（堆外内存管理器）现在是 Spark 流式处理的固有部分，这导致了更高效的执行。

在本章中，我们不仅涵盖了 Spark 机器库中提供的流式设施，还提供了四个介绍性的配方，这些配方在我们对 Spark 2.0 的更好理解之旅中非常有用。

以下图表描述了本章涵盖的内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00284.jpeg)

Spark 2.0+通过抽象掉一些框架的内部工作原理，并将其呈现给开发人员，而不必担心端到端的一次写入语义，来构建上一代的成功。这是从基于 RDD 的 DStream 到结构化流处理范式的一次旅程，在这个范式中，您的流处理世界可以被视为具有多种输出模式的无限表。

状态管理已经从`updateStateByKey`（Spark 1.3 到 Spark 1.5）发展到`mapWithState`（Spark 1.6+），再到结构化流处理（Spark 2.0+）的第三代状态管理。

现代 ML 流式系统是一个复杂的连续应用程序，不仅需要将各种 ML 步骤组合成管道，还需要与其他子系统交互，以提供实用的端到端信息系统。

在我们完成这本书时，Databricks，这家支持 Spark 社区的公司，在 Spark Summit West 2017 上宣布了关于 Spark 流处理未来方向的声明（尚未发布）：

“今天，我们很高兴提出一个新的扩展，连续处理，它还消除了执行中的微批处理。正如我们今天早上在 Spark Summit 上展示的那样，这种新的执行模式让用户在许多重要的工作负载中实现亚毫秒的端到端延迟 - 而不需要更改他们的 Spark 应用程序。”

来源：[`databricks.com/blog/2017/06/06/simple-super-fast-streaming-engine-apache-spark.html`](https://databricks.com/blog/2017/06/06/simple-super-fast-streaming-engine-apache-spark.html)

以下图表描述了大多数流式系统的最小可行流式系统（为了演示而过于简化）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00285.jpeg)

如前图所示，任何现实生活中的系统都必须与批处理（例如，模型参数的离线学习）进行交互，而更快的子系统则集中于对外部事件的实时响应（即在线学习）。

Spark 的结构化流处理与 ML 库的完全集成即将到来，但与此同时，我们可以创建和使用流式数据框架和流式数据集来进行补偿，这将在接下来的一些配方中看到。

新的结构化流式处理具有多个优势，例如：

+   批处理和流处理 API 的统一（无需翻译）

+   更简洁的表达式语言的函数式编程

+   容错状态管理（第三代）

+   大大简化的编程模型：

+   触发

+   输入

+   查询

+   结果

+   输出

+   数据流作为无界表

以下图表描述了将数据流建模为无限无界表的基本概念：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00286.jpeg)

在 Spark 2.0 之前的范式中，DStream 构造推进了流作为一组离散数据结构（RDDs）的模型，当我们有延迟到达时，这是非常难处理的。固有的延迟到达问题使得难以构建具有实时回溯模型的系统（在云中非常突出），因为实际费用的不确定性。

以下图表以可视化方式描述了 DStream 模型，以便进行相应比较：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00287.jpeg)

相比之下，使用新模型，开发人员需要担心的概念更少，也不需要将代码从批处理模型（通常是 ETL 类似的代码）转换为实时流模型。

目前，由于时间线和遗留问题，必须在所有 Spark 2.0 之前的代码被替换之前一段时间内了解两种模型（DStream 和结构化流）。我们发现新的结构化流模型特别简单，与 DStream 相比，并尝试在本章涵盖的四个入门配方中展示和突出显示差异。

# 结构化流用于近实时机器学习

在这个配方中，我们探索了 Spark 2.0 引入的新的结构化流范式。我们使用套接字和结构化流 API 进行实时流处理，以进行投票和统计投票。

我们还通过模拟随机生成的投票流来探索新引入的子系统，以选择最不受欢迎的漫画恶棍。

这个配方由两个不同的程序（`VoteCountStream.scala`和`CountStreamproducer.scala`）组成。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

```scala
package spark.ml.cookbook.chapter13
```

1.  导入必要的包以便 Spark 上下文可以访问集群和`log4j.Logger`以减少 Spark 产生的输出量：

```scala
import org.apache.log4j.{Level, Logger}
import org.apache.spark.sql.SparkSession
import java.io.{BufferedOutputStream, PrintWriter}
import java.net.Socket
import java.net.ServerSocket
import java.util.concurrent.TimeUnit
import scala.util.Random
import org.apache.spark.sql.streaming.ProcessingTime
```

1.  定义一个 Scala 类来生成投票数据到客户端套接字：

```scala
class CountSreamThread(socket: Socket) extends Thread
```

1.  定义一个包含人们投票的文字字符串值的数组：

```scala
val villians = Array("Bane", "Thanos", "Loki", "Apocalypse", "Red Skull", "The Governor", "Sinestro", "Galactus",
 "Doctor Doom", "Lex Luthor", "Joker", "Magneto", "Darth Vader")
```

1.  现在我们将覆盖`Threads`类的`run`方法，随机模拟对特定恶棍的投票：

```scala
override def run(): Unit = {

 println("Connection accepted")
 val out = new PrintWriter(new BufferedOutputStream(socket.getOutputStream()))

 println("Producing Data")
 while (true) {
 out.println(villians(Random.nextInt(villians.size)))
 Thread.sleep(10)
 }

 println("Done Producing")
 }
```

1.  接下来，我们定义一个 Scala 单例对象，以接受在定义的端口`9999`上的连接并生成投票数据：

```scala
object CountStreamProducer {

 def main(args: Array[String]): Unit = {

 val ss = new ServerSocket(9999)
 while (true) {
 println("Accepting Connection...")
 new CountSreamThread(ss.accept()).start()
 }
 }
 }
```

1.  不要忘记启动数据生成服务器，这样我们的流式示例就可以处理流式投票数据。

1.  将输出级别设置为`ERROR`以减少 Spark 的输出：

```scala
   Logger.getLogger("org").setLevel(Level.ERROR)
    Logger.getLogger("akka").setLevel(Level.ERROR)
```

1.  创建一个`SparkSession`，以访问 Spark 集群和底层会话对象属性，如`SparkContext`和`SparkSQLContext`：

```scala
val spark = SparkSession
.builder.master("local[*]")
.appName("votecountstream")
.config("spark.sql.warehouse.dir", ".")
.getOrCreate()
```

1.  导入 spark implicits，因此只需导入行为：

```scala
import spark.implicits._
```

1.  通过连接到本地端口`9999`创建一个流 DataFrame，该端口利用 Spark 套接字源作为流数据的来源：

```scala
val stream = spark.readStream
 .format("socket")
 .option("host", "localhost")
 .option("port", 9999)
 .load()
```

1.  在这一步中，我们通过恶棍名称和计数对流数据进行分组，以模拟用户实时投票：

```scala
val villainsVote = stream.groupBy("value").count()
```

1.  现在我们定义一个流查询，每 10 秒触发一次，将整个结果集转储到控制台，并通过调用`start()`方法来调用它：

```scala
val query = villainsVote.orderBy("count").writeStream
 .outputMode("complete")
 .format("console")
 .trigger(ProcessingTime.create(10, TimeUnit.SECONDS))
 .start()
```

第一个输出批次显示在这里作为批次`0`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00288.gif)

额外的批处理结果显示在这里：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00289.gif)

1.  最后，等待流查询的终止或使用`SparkSession` API 停止进程：

```scala
query.awaitTermination()
```

# 它是如何工作的...

在这个配方中，我们创建了一个简单的数据生成服务器来模拟投票数据的流，然后计算了投票。下图提供了这个概念的高级描述：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00290.jpeg)

首先，我们通过执行数据生成服务器来开始。其次，我们定义了一个套接字数据源，允许我们连接到数据生成服务器。第三，我们构建了一个简单的 Spark 表达式，按反派（即坏超级英雄）分组，并计算当前收到的所有选票。最后，我们配置了一个 10 秒的阈值触发器来执行我们的流查询，将累积的结果转储到控制台上。

这个配方涉及两个简短的程序：

+   `CountStreamproducer.scala`:

+   生产者-数据生成服务器

+   模拟为自己投票并广播

+   `VoteCountStream.scala`:

+   消费者-消费和聚合/制表数据

+   接收并计算我们的反派超级英雄的选票

# 还有更多...

如何使用 Spark 流处理和结构化流处理编程的主题超出了本书的范围，但我们认为有必要在深入研究 Spark 的 ML 流处理提供之前分享一些程序来介绍这些概念。

要了解流处理的基本知识，请参阅以下关于 Spark 的文档：

+   Spark 2.0+结构化流的信息可在[`spark.apache.org/docs/latest/structured-streaming-programming-guide.html#api-using-datasets-and-dataframes`](https://spark.apache.org/docs/latest/structured-streaming-programming-guide.html#api-using-datasets-and-dataframes)找到

+   Spark 1.6 流处理的信息可在[`spark.apache.org/docs/latest/streaming-programming-guide.html`](https://spark.apache.org/docs/latest/streaming-programming-guide.html)找到

# 另请参见

+   结构化流处理的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.package`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.package)找到

+   DStream（Spark 2.0 之前）的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.streaming.dstream.DStream`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.streaming.dstream.DStream)找到

+   `DataStreamReader`的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader)找到

+   `DataStreamWriter`的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter)找到

+   `StreamingQuery`的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.StreamingQuery`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.StreamingQuery)找到

# 用于实时机器学习的流 DataFrame

在这个配方中，我们探讨了流 DataFrame 的概念。我们创建了一个由个人的姓名和年龄组成的 DataFrame，我们将通过电线进行流式传输。流 DataFrame 是与 Spark ML 一起使用的一种流行技术，因为在撰写本文时，我们尚未完全集成 Spark 结构化 ML。

我们将此配方限制为仅演示流 DataFrame 的范围，并留给读者将其适应其自定义 ML 管道。虽然在 Spark 2.1.0 中，流 DataFrame 并不是开箱即用的，但在后续版本的 Spark 中，它将是一个自然的演进。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

```scala
package spark.ml.cookbook.chapter13
```

1.  导入必要的包：

```scala
import java.util.concurrent.TimeUnit
import org.apache.log4j.{Level, Logger}
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.streaming.ProcessingTime
```

1.  创建一个`SparkSession`作为连接到 Spark 集群的入口点：

```scala
val spark = SparkSession
.builder.master("local[*]")
.appName("DataFrame Stream")
.config("spark.sql.warehouse.dir", ".")
.getOrCreate()

```

1.  日志消息的交错会导致难以阅读的输出，因此将日志级别设置为警告：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)
Logger.getLogger("akka").setLevel(Level.ERROR)
```

1.  接下来，加载人员数据文件以推断数据模式，而无需手动编写结构类型：

```scala
val df = spark.read .format("json")
.option("inferSchema", "true")
.load("../data/sparkml2/chapter13/person.json")
df.printSchema()
```

从控制台，您将看到以下输出：

```scala
root
|-- age: long (nullable = true)
|-- name: string (nullable = true)
```

1.  现在配置一个用于摄取数据的流 DataFrame：

```scala
val stream = spark.readStream
.schema(df.schema)
.json("../data/sparkml2/chapter13/people/")
```

1.  让我们执行一个简单的数据转换，通过筛选年龄大于`60`：

```scala
val people = stream.select("name", "age").where("age > 60")
```

1.  现在，我们将转换后的流数据输出到控制台，每秒触发一次：

```scala
val query = people.writeStream
.outputMode("append")
.trigger(ProcessingTime(1, TimeUnit.SECONDS))
.format("console")
```

1.  我们启动我们定义的流查询，并等待数据出现在流中：

```scala
query.start().awaitTermination()
```

1.  最后，我们的流查询结果将出现在控制台中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00291.gif)

# 它是如何工作的...

在这个示例中，我们首先使用一个快速方法（使用 JSON 对象）发现一个人对象的基础模式，如第 6 步所述。结果 DataFrame 将知道我们随后对流输入施加的模式（通过模拟流式传输文件）并将其视为流 DataFrame，如第 7 步所示。

将流视为 DataFrame 并使用函数式或 SQL 范式对其进行操作的能力是一个强大的概念，可以在第 8 步中看到。然后，我们使用`writestream()`以`append`模式和 1 秒批处理间隔触发器输出结果。

# 还有更多...

DataFrame 和结构化编程的结合是一个强大的概念，它帮助我们将数据层与流分离，使编程变得更加容易。DStream（Spark 2.0 之前）最大的缺点之一是无法将用户与流/RDD 实现的细节隔离开来。

DataFrames 的文档：

+   `DataFrameReader`: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.DataFrameReader`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.DataFrameReader)

+   `DataFrameWriter`: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.DataFrameWriter`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.DataFrameWriter)

# 另请参阅

Spark 数据流读取器和写入器的文档：

+   DataStreamReader: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader)

+   DataStreamWriter: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter)

# 用于实时机器学习的流数据集

在这个示例中，我们创建一个流数据集来演示在 Spark 2.0 结构化编程范式中使用数据集的方法。我们从文件中流式传输股票价格，并使用数据集应用过滤器来选择当天收盘价高于 100 美元的股票。

该示例演示了如何使用流来过滤和处理传入数据，使用简单的结构化流编程模型。虽然它类似于 DataFrame，但语法上有一些不同。该示例以一种通用的方式编写，因此用户可以根据自己的 Spark ML 编程项目进行自定义。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

```scala
package spark.ml.cookbook.chapter13
```

1.  导入必要的包：

```scala
import java.util.concurrent.TimeUnit
import org.apache.log4j.{Level, Logger}
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.streaming.ProcessingTime

```

1.  定义一个 Scala `case class`来建模流数据：

```scala
case class StockPrice(date: String, open: Double, high: Double, low: Double, close: Double, volume: Integer, adjclose: Double)
```

1.  创建`SparkSession`以用作进入 Spark 集群的入口点：

```scala
val spark = SparkSession
.builder.master("local[*]")
.appName("Dataset Stream")
.config("spark.sql.warehouse.dir", ".")
.getOrCreate()
```

1.  日志消息的交错导致输出难以阅读，因此将日志级别设置为警告：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)
Logger.getLogger("akka").setLevel(Level.ERROR)
```

1.  现在，加载通用电气 CSV 文件并推断模式：

```scala
val s = spark.read
.format("csv")
.option("header", "true")
.option("inferSchema", "true")
.load("../data/sparkml2/chapter13/GE.csv")
s.printSchema()
```

您将在控制台输出中看到以下内容：

```scala
root
|-- date: timestamp (nullable = true)
|-- open: double (nullable = true)
|-- high: double (nullable = true)
|-- low: double (nullable = true)
|-- close: double (nullable = true)
|-- volume: integer (nullable = true)
|-- adjclose: double (nullable = true)
```

1.  接下来，我们将通用电气 CSV 文件加载到类型为`StockPrice`的数据集中：

```scala
val streamDataset = spark.readStream
            .schema(s.schema)
            .option("sep", ",")
            .option("header", "true")
            .csv("../data/sparkml2/chapter13/ge").as[StockPrice]
```

1.  我们将过滤流，以获取任何收盘价大于 100 美元的股票：

```scala
val ge = streamDataset.filter("close > 100.00")
```

1.  现在，我们将转换后的流数据输出到控制台，每秒触发一次：

```scala
val query = ge.writeStream
.outputMode("append")
.trigger(ProcessingTime(1, TimeUnit.SECONDS))
.format("console")

```

1.  我们启动我们定义的流式查询，并等待数据出现在流中：

```scala
query.start().awaitTermination()
```

1.  最后，我们的流式查询结果将出现在控制台中：

！[](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00292.jpeg)

# 它是如何工作的…

在这个示例中，我们将利用追溯到 1972 年的**通用电气**（**GE**）的收盘价格市场数据。为了简化数据，我们已经对此示例进行了预处理。我们使用了上一个示例中的相同方法，*用于实时机器学习的流式数据框架*，通过窥探 JSON 对象来发现模式（步骤 7），然后在步骤 8 中将其强加到流中。

以下代码显示了如何使用模式使流看起来像一个可以即时读取的简单表格。这是一个强大的概念，使流编程对更多程序员可访问。以下代码片段中的`schema(s.schema)`和`as[StockPrice]`是创建具有相关模式的流式数据集所需的：

```scala
val streamDataset = spark.readStream
            .schema(s.schema)
            .option("sep", ",")
            .option("header", "true")
            .csv("../data/sparkml2/chapter13/ge").as[StockPrice]
```

# 还有更多…

有关数据集下所有可用 API 的文档，请访问[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset)网站[.](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset)

# 另请参阅

在探索流式数据集概念时，以下文档很有帮助：

+   `StreamReader`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader)

+   `StreamWriter`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter)

+   `StreamQuery`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.StreamingQuery`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.StreamingQuery)

# 使用 queueStream 流式数据和调试

在这个示例中，我们探讨了`queueStream()`的概念，这是一个有价值的工具，可以在开发周期中尝试使流式程序工作。我们发现`queueStream()`API 非常有用，并且认为其他开发人员可以从完全演示其用法的示例中受益。

我们首先通过使用程序`ClickGenerator.scala`模拟用户浏览与不同网页相关的各种 URL，然后使用`ClickStream.scala`程序消耗和制表数据（用户行为/访问）：

！[](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00293.jpeg)

我们使用 Spark 的流式 API 与`Dstream()`，这将需要使用流式上下文。我们明确指出这一点，以突出 Spark 流和 Spark 结构化流编程模型之间的差异之一。

这个示例由两个不同的程序（`ClickGenerator.scala`和`ClickStream.scala`）组成。

# 如何做到…

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

```scala
package spark.ml.cookbook.chapter13
```

1.  导入必要的包：

```scala
import java.time.LocalDateTime
import scala.util.Random._
```

1.  定义一个 Scala`case class`，用于模拟用户的点击事件，包含用户标识符、IP 地址、事件时间、URL 和 HTTP 状态码：

```scala
case class ClickEvent(userId: String, ipAddress: String, time: String, url: String, statusCode: String)
```

1.  为生成定义状态码：

```scala
val statusCodeData = Seq(200, 404, 500)
```

1.  为生成定义 URL：

```scala
val urlData = Seq("http://www.fakefoo.com",
 "http://www.fakefoo.com/downloads",
 "http://www.fakefoo.com/search",
 "http://www.fakefoo.com/login",
 "http://www.fakefoo.com/settings",
 "http://www.fakefoo.com/news",
 "http://www.fakefoo.com/reports",
 "http://www.fakefoo.com/images",
 "http://www.fakefoo.com/css",
 "http://www.fakefoo.com/sounds",
 "http://www.fakefoo.com/admin",
 "http://www.fakefoo.com/accounts" )
```

1.  为生成定义 IP 地址范围：

```scala
val ipAddressData = generateIpAddress()
def generateIpAddress(): Seq[String] = {
 for (n <- 1 to 255) yield s"127.0.0.$n" }
```

1.  为生成定义时间戳范围：

```scala
val timeStampData = generateTimeStamp()

 def generateTimeStamp(): Seq[String] = {
 val now = LocalDateTime.now()
 for (n <- 1 to 1000) yield LocalDateTime.*of*(now.toLocalDate,
 now.toLocalTime.plusSeconds(n)).toString
 }
```

1.  为生成定义用户标识符范围：

```scala
val userIdData = generateUserId()

 def generateUserId(): Seq[Int] = {
 for (id <- 1 to 1000) yield id
 }
```

1.  定义一个函数来生成一个或多个伪随机事件：

```scala
def generateClicks(clicks: Int = 1): Seq[String] = {
 0.until(clicks).map(i => {
 val statusCode = statusCodeData(nextInt(statusCodeData.size))
 val ipAddress = ipAddressData(nextInt(ipAddressData.size))
 val timeStamp = timeStampData(nextInt(timeStampData.size))
 val url = urlData(nextInt(urlData.size))
 val userId = userIdData(nextInt(userIdData.size))

 s"$userId,$ipAddress,$timeStamp,$url,$statusCode" })
 }
```

1.  定义一个函数，从字符串中解析伪随机的`ClickEvent`：

```scala
def parseClicks(data: String): ClickEvent = {
val fields = data.split(",")
new ClickEvent(fields(0), fields(1), fields(2), fields(3), fields(4))
 }
```

1.  创建 Spark 的配置和具有 1 秒持续时间的 Spark 流上下文：

```scala
val spark = SparkSession
.builder.master("local[*]")
 .appName("Streaming App")
 .config("spark.sql.warehouse.dir", ".")
 .config("spark.executor.memory", "2g")
 .getOrCreate()
val ssc = new StreamingContext(spark.sparkContext, Seconds(1))
```

1.  日志消息的交错导致难以阅读的输出，因此将日志级别设置为警告：

```scala
Logger.getRootLogger.setLevel(Level.WARN)
```

1.  创建一个可变队列，将我们生成的数据附加到上面：

```scala
val rddQueue = new Queue[RDD[String]]()
```

1.  从流上下文中创建一个 Spark 队列流，传入我们数据队列的引用：

```scala
val inputStream = ssc.queueStream(rddQueue)
```

1.  处理队列流接收的任何数据，并计算用户点击每个特定链接的总数：

```scala
val clicks = inputStream.map(data => ClickGenerator.parseClicks(data))
 val clickCounts = clicks.map(c => c.url).countByValue()
```

1.  打印出`12`个 URL 及其总数：

```scala
clickCounts.print(12)
```

1.  启动我们的流上下文以接收微批处理：

```scala
ssc.start()
```

1.  循环 10 次，在每次迭代中生成 100 个伪随机事件，并将它们附加到我们的可变队列中，以便它们在流队列抽象中实现：

```scala
for (i <- 1 to 10) {
 rddQueue += ssc.sparkContext.parallelize(ClickGenerator.*generateClicks*(100))
 Thread.sleep(1000)
 }
```

1.  我们通过停止 Spark 流上下文来关闭程序：

```scala
ssc.stop()
```

# 它是如何工作的...

通过这个配方，我们介绍了使用许多人忽视的技术来引入 Spark Streaming，这使我们能够利用 Spark 的`QueueInputDStream`类来创建流应用程序。`QueueInputDStream`类不仅是理解 Spark 流的有益工具，也是在开发周期中进行调试的有用工具。在最初的步骤中，我们设置了一些数据结构，以便在稍后的阶段为流处理生成伪随机的`clickstream`事件数据。

应该注意，在第 12 步中，我们创建的是一个流上下文而不是 SparkContext。流上下文是我们用于 Spark 流应用程序的。接下来，创建队列和队列流以接收流数据。现在的第 15 步和第 16 步类似于操作 RDD 的一般 Spark 应用程序。下一步是启动流上下文处理。流上下文启动后，我们将数据附加到队列，处理开始以微批处理方式进行。

这里提到了一些相关主题的文档：

+   `StreamingContext`和`queueStream()`: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.streaming.StreamingContext`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.streaming.StreamingContext)

+   `DStream`:[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.streaming.dstream.DStream`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.streaming.dstream.DStream)

+   `InputDStream`: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.streaming.dstream.InputDStream`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.streaming.dstream.InputDStream)

# 另请参阅

在其核心，`queueStream()`只是一个队列，我们在 Spark 流（2.0 之前）转换为 RDD 后拥有的 RDD 队列：

+   结构化流的文档（Spark 2.0+）： [`spark.apache.org/docs/2.1.0/structured-streaming-programming-guide.html`](https://spark.apache.org/docs/2.1.0/structured-streaming-programming-guide.html)

+   流处理的文档（Spark 2.0 之前）： [`spark.apache.org/docs/latest/streaming-programming-guide.html`](https://spark.apache.org/docs/latest/streaming-programming-guide.html)

# 下载并理解著名的鸢尾花数据，用于无监督分类

在这个配方中，我们下载并检查了著名的鸢尾花数据，为即将到来的流式 KMeans 配方做准备，这让您可以实时查看分类/聚类。

数据存储在 UCI 机器学习库中，这是一个很好的原型算法数据来源。您会注意到 R 博客作者倾向于喜欢这个数据集。

# 如何做...

1.  您可以通过以下两个命令之一下载数据集：

```scala
wget https://archive.ics.uci.edu/ml/machine-learning-databases/iris/iris.data
```

您也可以使用以下命令：

```scala
curl https://archive.ics.uci.edu/ml/machine-learning-databases/iris/iris.data -o iris.data
```

您也可以使用以下命令：

```scala
https://archive.ics.uci.edu/ml/machine-learning-databases/iris/iris.data
```

1.  现在我们通过检查`iris.data`中的数据格式来开始数据探索的第一步：

```scala
head -5 iris.data
5.1,3.5,1.4,0.2,Iris-setosa
4.9,3.0,1.4,0.2,Iris-setosa
4.7,3.2,1.3,0.2,Iris-setosa
4.6,3.1,1.5,0.2,Iris-setosa
5.0,3.6,1.4,0.2,Iris-setosa
```

1.  现在我们来看一下鸢尾花数据的格式：

```scala
tail -5 iris.data
6.3,2.5,5.0,1.9,Iris-virginica
6.5,3.0,5.2,2.0,Iris-virginica
6.2,3.4,5.4,2.3,Iris-virginica
5.9,3.0,5.1,1.8,Iris-virginica
```

# 它是如何工作的...

数据由 150 个观测组成。每个观测由四个数值特征（以厘米为单位测量）和一个标签组成，该标签表示每个鸢尾花属于哪个类别：

**特征/属性**：

+   花萼长度（厘米）

+   花萼宽度（厘米）

+   花瓣长度（厘米）

+   花瓣宽度（厘米）

**标签/类别**：

+   Iris Setosa

+   Iris Versicolour

+   Iris Virginic

# 还有更多...

以下图片描述了一朵鸢尾花，标有花瓣和萼片以便清晰显示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00294.jpeg)

# 另请参阅

以下链接更详细地探讨了鸢尾花数据集：

[`en.wikipedia.org/wiki/Iris_flower_data_set`](https://en.wikipedia.org/wiki/Iris_flower_data_set)

# 实时在线分类器的流式 KMeans

在这个配方中，我们探讨了 Spark 中用于无监督学习方案的 KMeans 的流式版本。流式 KMeans 算法的目的是根据它们的相似性因子将一组数据点分类或分组成多个簇。

KMeans 分类方法有两种实现，一种用于静态/离线数据，另一种用于不断到达的实时更新数据。

我们将把鸢尾花数据集作为新数据流流入我们的流式上下文进行聚类。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter13
```

1.  导入必要的包：

```scala
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.rdd.RDD
import org.apache.spark.SparkContext
import scala.collection.mutable.Queue
```

1.  我们首先定义一个函数，将鸢尾花数据加载到内存中，过滤掉空白行，为每个元素附加一个标识符，最后返回类型为字符串和长整型的元组：

```scala
def readFromFile(sc: SparkContext) = {
 sc.textFile("../data/sparkml2/chapter13/iris.data")
 .filter(s => !s.isEmpty)
 .zipWithIndex()
 }
```

1.  创建一个解析器来获取我们元组的字符串部分并创建一个标签点：

```scala
def toLabelPoints(records: (String, Long)): LabeledPoint = {
 val (record, recordId) = records
 val fields = record.split(",")
 LabeledPoint(recordId,
 Vectors.*dense*(fields(0).toDouble, fields(1).toDouble,
 fields(2).toDouble, fields(3).toDouble))
 }
```

1.  创建一个查找映射，将标识符转换回文本标签特征：

```scala
def buildLabelLookup(records: RDD[(String, Long)]) = {
 records.map {
 case (record: String, id: Long) => {
 val fields = record.split(",")
 (id, fields(4))
 }
 }.collect().toMap
 }
```

1.  创建 Spark 的配置和 Spark 流式上下文，持续 1 秒：

```scala
val spark = SparkSession
 .builder.master("local[*]")
 .appName("KMean Streaming App")
 .config("spark.sql.warehouse.dir", ".")
 .config("spark.executor.memory", "2g")
 .getOrCreate()

 val ssc = new StreamingContext(spark.sparkContext, *Seconds*(1))
```

1.  日志消息的交错导致输出难以阅读，因此将日志级别设置为警告：

```scala
Logger.getRootLogger.setLevel(Level.WARN)
```

1.  我们读取鸢尾花数据并构建一个查找映射来显示最终输出：

```scala
val irisData = IrisData.readFromFile(spark.sparkContext)
val lookup = IrisData.buildLabelLookup(irisData)
```

1.  创建可变队列以追加流式数据：

```scala
val trainQueue = new Queue[RDD[LabeledPoint]]()
val testQueue = new Queue[RDD[LabeledPoint]]()
```

1.  创建 Spark 流式队列以接收数据：

```scala
val trainingStream = ssc.queueStream(trainQueue)
 val testStream = ssc.queueStream(testQueue)
```

1.  创建流式 KMeans 对象将数据聚类成三组：

```scala
val model = new StreamingKMeans().setK(3)
 .setDecayFactor(1.0)
 .setRandomCenters(4, 0.0)
```

1.  设置 KMeans 模型以接受流式训练数据来构建模型：

```scala
model.trainOn(trainingStream.map(lp => lp.features))
```

1.  设置 KMeans 模型以预测聚类组值：

```scala
val values = model.predictOnValues(testStream.map(lp => (lp.label, lp.features)))
 values.foreachRDD(n => n.foreach(v => {
 println(v._2, v._1, lookup(v._1.toLong))
 }))
```

1.  启动流式上下文，以便在接收到数据时处理数据：

```scala
  ssc.start()
```

1.  将鸢尾花数据转换为标签点：

```scala
val irisLabelPoints = irisData.map(record => IrisData.toLabelPoints(record))
```

1.  现在将标签点数据分成训练数据集和测试数据集：

```scala
val Array(trainData, test) = irisLabelPoints.randomSplit(Array(.80, .20))
```

1.  将训练数据追加到流式队列进行处理：

```scala
trainQueue += irisLabelPoints
 Thread.sleep(2000)
```

1.  现在将测试数据分成四组，并追加到流式队列进行处理：

```scala
val testGroups = test.randomSplit(*Array*(.25, .25, .25, .25))
 testGroups.foreach(group => {
 testQueue += group
 *println*("-" * 25)
 Thread.sleep(1000)
 })
```

1.  配置的流式队列打印出聚类预测组的以下结果：

```scala
-------------------------
(0,78.0,Iris-versicolor)
(2,14.0,Iris-setosa)
(1,132.0,Iris-virginica)
(0,55.0,Iris-versicolor)
(2,57.0,Iris-versicolor)
-------------------------
(2,3.0,Iris-setosa)
(2,19.0,Iris-setosa)
(2,98.0,Iris-versicolor)
(2,29.0,Iris-setosa)
(1,110.0,Iris-virginica)
(2,39.0,Iris-setosa)
(0,113.0,Iris-virginica)
(1,50.0,Iris-versicolor)
(0,63.0,Iris-versicolor)
(0,74.0,Iris-versicolor)
-------------------------
(2,16.0,Iris-setosa)
(0,106.0,Iris-virginica)
(0,69.0,Iris-versicolor)
(1,115.0,Iris-virginica)
(1,116.0,Iris-virginica)
(1,139.0,Iris-virginica)
-------------------------
(2,1.0,Iris-setosa)
(2,7.0,Iris-setosa)
(2,17.0,Iris-setosa)
(0,99.0,Iris-versicolor)
(2,38.0,Iris-setosa)
(0,59.0,Iris-versicolor)
(1,76.0,Iris-versicolor)
```

1.  通过停止 SparkContext 来关闭程序：

```scala
ssc.stop()
```

# 它是如何工作的...

在这个配方中，我们首先加载鸢尾花数据集，并使用`zip()` API 将数据与唯一标识符配对，以生成用于 KMeans 算法的*标记点*数据结构。

接下来，创建可变队列和`QueueInputDStream`，以便追加数据以模拟流式。一旦`QueueInputDStream`开始接收数据，流式 k 均值聚类就开始动态聚类数据并打印结果。你会注意到的有趣的事情是，我们在一个队列流上流式训练数据，而在另一个队列流上流式测试数据。当我们向我们的队列追加数据时，KMeans 聚类算法正在处理我们的传入数据并动态生成簇。

# 还有更多...

*StreamingKMeans()*的文档：

+   `StreamingKMeans`: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeans`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeans)

+   `StreamingKMeansModel`: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeansModel`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeansModel)

# 另请参阅

通过构建模式或`streamingKMeans`定义的超参数为：

```scala
setDecayFactor()
setK()
setRandomCenters(,)
```

有关更多详细信息，请参阅第八章中的*在 Spark 中构建 KMeans 分类系统*食谱，*使用 Apache Spark 2.0 进行无监督聚类*。

# 下载用于流回归的葡萄酒质量数据

在这个食谱中，我们下载并检查了 UCI 机器学习存储库中的葡萄酒质量数据集，以准备数据用于 Spark 的流线性回归算法。

# 如何做...

您将需要以下命令行工具之一`curl`或`wget`来检索指定的数据：

1.  您可以通过以下三个命令之一开始下载数据集。第一个如下：

```scala
wget http://archive.ics.uci.edu/ml/machine-learning-databases/wine-quality/winequality-white.csv
```

您还可以使用以下命令：

```scala
curl http://archive.ics.uci.edu/ml/machine-learning-databases/wine-quality/winequality-white.csv -o winequality-white.csv
```

这个命令是做同样事情的第三种方式：

```scala
http://archive.ics.uci.edu/ml/machine-learning-databases/wine-quality/winequality-white.csv
```

1.  现在我们开始通过查看`winequality-white.csv`中的数据格式来进行数据探索的第一步：

```scala
head -5 winequality-white.csv

"fixed acidity";"volatile acidity";"citric acid";"residual sugar";"chlorides";"free sulfur dioxide";"total sulfur dioxide";"density";"pH";"sulphates";"alcohol";"quality"
7;0.27;0.36;20.7;0.045;45;170;1.001;3;0.45;8.8;6
6.3;0.3;0.34;1.6;0.049;14;132;0.994;3.3;0.49;9.5;6
8.1;0.28;0.4;6.9;0.05;30;97;0.9951;3.26;0.44;10.1;6
7.2;0.23;0.32;8.5;0.058;47;186;0.9956;3.19;0.4;9.9;6
```

1.  现在我们来看一下葡萄酒质量数据，了解其格式：

```scala
tail -5 winequality-white.csv
6.2;0.21;0.29;1.6;0.039;24;92;0.99114;3.27;0.5;11.2;6
6.6;0.32;0.36;8;0.047;57;168;0.9949;3.15;0.46;9.6;5
6.5;0.24;0.19;1.2;0.041;30;111;0.99254;2.99;0.46;9.4;6
5.5;0.29;0.3;1.1;0.022;20;110;0.98869;3.34;0.38;12.8;7
6;0.21;0.38;0.8;0.02;22;98;0.98941;3.26;0.32;11.8;6
```

# 它是如何工作的...

数据由 1,599 种红葡萄酒和 4,898 种白葡萄酒组成，具有 11 个特征和一个输出标签，可在训练过程中使用。

以下是特征/属性列表：

+   固定酸度

+   挥发性酸度

+   柠檬酸

+   残留糖

+   氯化物

+   游离二氧化硫

+   总二氧化硫

+   密度

+   pH

+   硫酸盐

+   酒精

以下是输出标签：

+   质量（0 到 10 之间的数值）

# 还有更多...

以下链接列出了流行机器学习算法的数据集。可以根据需要选择新的数据集进行实验。

可在[`en.wikipedia.org/wiki/List_of_datasets_for_machine_learning_research`](https://en.wikipedia.org/wiki/List_of_datasets_for_machine_learning_research)找到替代数据集。

我们选择了鸢尾花数据集，因此可以使用连续的数值特征进行线性回归模型。

# 实时回归的流线性回归

在这个食谱中，我们将使用 UCI 的葡萄酒质量数据集和 MLlib 中的 Spark 流线性回归算法来预测葡萄酒的质量。

这个食谱与我们之前看到的传统回归食谱的区别在于使用 Spark ML 流来实时评估葡萄酒的质量，使用线性回归模型。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

```scala
package spark.ml.cookbook.chapter13
```

1.  导入必要的包：

```scala
import org.apache.log4j.{Level, Logger}
 import org.apache.spark.mllib.linalg.Vectors
 import org.apache.spark.mllib.regression.LabeledPoint
 import org.apache.spark.mllib.regression.StreamingLinearRegressionWithSGD
 import org.apache.spark.rdd.RDD
 import org.apache.spark.sql.{Row, SparkSession}
 import org.apache.spark.streaming.{Seconds, StreamingContext}
 import scala.collection.mutable.Queue
```

1.  创建 Spark 的配置和流上下文：

```scala
val spark = SparkSession
 .builder.master("local[*]")
 .appName("Regression Streaming App")
 .config("spark.sql.warehouse.dir", ".")
 .config("spark.executor.memory", "2g")
 .getOrCreate()

 import spark.implicits._

 val ssc = new StreamingContext(spark.sparkContext, *Seconds*(2))
```

1.  日志消息的交错会导致难以阅读的输出，因此将日志级别设置为警告：

```scala
Logger.getRootLogger.setLevel(Level.WARN)
```

1.  使用 Databricks CSV API 将葡萄酒质量 CSV 加载到 DataFrame 中：

```scala
val rawDF = spark.read
 .format("com.databricks.spark.csv")
 .option("inferSchema", "true")
 .option("header", "true")
 .option("delimiter", ";")
 .load("../data/sparkml2/chapter13/winequality-white.csv")
```

1.  将 DataFrame 转换为`rdd`并将唯一标识符`zip`到其中：

```scala
val rdd = rawDF.rdd.zipWithUniqueId()
```

1.  构建查找映射，以便稍后比较预测的质量与实际质量值：

```scala
val lookupQuality = rdd.map{ case (r: Row, id: Long)=> (id, r.getInt(11))}.collect().toMap
```

1.  将葡萄酒质量转换为标签点，以便与机器学习库一起使用：

```scala
val labelPoints = rdd.map{ case (r: Row, id: Long)=> LabeledPoint(id,
 Vectors.dense(r.getDouble(0), r.getDouble(1), r.getDouble(2), r.getDouble(3), r.getDouble(4),
 r.getDouble(5), r.getDouble(6), r.getDouble(7), r.getDouble(8), r.getDouble(9), r.getDouble(10))
 )}
```

1.  创建一个可变队列以追加数据：

```scala
val trainQueue = new Queue[RDD[LabeledPoint]]()
val testQueue = new Queue[RDD[LabeledPoint]]()
```

1.  创建 Spark 流队列以接收流数据：

```scala
val trainingStream = ssc.queueStream(trainQueue)
val testStream = ssc.queueStream(testQueue)
```

1.  配置流线性回归模型：

```scala
val numFeatures = 11
 val model = new StreamingLinearRegressionWithSGD()
 .setInitialWeights(Vectors.zeros(numFeatures))
 .setNumIterations(25)
 .setStepSize(0.1)
 .setMiniBatchFraction(0.25)
```

1.  训练回归模型并预测最终值：

```scala
model.trainOn(trainingStream)
val result = model.predictOnValues(testStream.map(lp => (lp.label, lp.features)))
result.map{ case (id: Double, prediction: Double) => (id, prediction, lookupQuality(id.asInstanceOf[Long])) }.print()

```

1.  启动 Spark 流上下文：

```scala
ssc.start()
```

1.  将标签点数据拆分为训练集和测试集：

```scala
val Array(trainData, test) = labelPoints.randomSplit(Array(.80, .20))
```

1.  将数据追加到训练数据队列以进行处理：

```scala
trainQueue += trainData
 Thread.sleep(4000)
```

1.  现在将测试数据分成两半，并追加到队列以进行处理：

```scala
val testGroups = test.randomSplit(*Array*(.50, .50))
 testGroups.foreach(group => {
 testQueue += group
 Thread.sleep(2000)
 })
```

1.  一旦队列流接收到数据，您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00295.gif)

1.  通过停止 Spark 流上下文来关闭程序：

```scala
ssc.stop()
```

# 它是如何工作的...

我们首先通过 Databrick 的`spark-csv`库将葡萄酒质量数据集加载到 DataFrame 中。接下来的步骤是为数据集中的每一行附加一个唯一标识符，以便稍后将预测的质量与实际质量进行匹配。原始数据被转换为带标签的点，以便用作流线性回归算法的输入。在第 9 步和第 10 步，我们创建了可变队列的实例和 Spark 的`QueueInputDStream`类的实例，以用作进入回归算法的导管。

然后我们创建了流线性回归模型，它将预测我们最终结果的葡萄酒质量。我们通常从原始数据中创建训练和测试数据集，并将它们附加到适当的队列中，以开始我们的模型处理流数据。每个微批处理的最终结果显示了唯一生成的标识符、预测的质量值和原始数据集中包含的质量值。

# 还有更多...

`StreamingLinearRegressionWithSGD()`的文档：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.regression.StreamingLinearRegressionWithSGD`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.regression.StreamingLinearRegressionWithSGD)。

# 另请参阅

`StreamingLinearRegressionWithSGD()`的超参数*：*

+   `setInitialWeights(Vectors.*zeros*())`

+   `setNumIterations()`

+   `setStepSize()`

+   `setMiniBatchFraction()`

还有一个不使用**随机梯度下降**（**SGD**）版本的`StreamingLinearRegression()` API：

[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.regression.StreamingLinearAlgorithm`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.regression.StreamingLinearAlgorithm)

以下链接提供了线性回归的快速参考：

[`en.wikipedia.org/wiki/Linear_regression`](https://en.wikipedia.org/wiki/Linear_regression)

# 下载皮马糖尿病数据进行监督分类

在这个配方中，我们从 UCI 机器学习库下载并检查了皮马糖尿病数据集。我们将稍后使用该数据集与 Spark 的流式逻辑回归算法。

# 如何做...

您将需要以下命令行工具`curl`或`wget`来检索指定的数据：

1.  您可以通过以下两个命令之一开始下载数据集。第一个命令如下：

```scala
http://archive.ics.uci.edu/ml/machine-learning-databases/pima-indians-diabetes/pima-indians-diabetes.data
```

这是您可以使用的另一种选择：

```scala
wget http://archive.ics.uci.edu/ml/machine-learning-databases/pima-indians-diabetes/pima-indians-diabetes.data -o pima-indians-diabetes.data
```

1.  现在我们开始通过查看`pima-indians-diabetes.data`中的数据格式（从 Mac 或 Linux 终端）来探索数据的第一步：

```scala
head -5 pima-indians-diabetes.data
6,148,72,35,0,33.6,0.627,50,1
1,85,66,29,0,26.6,0.351,31,0
8,183,64,0,0,23.3,0.672,32,1
1,89,66,23,94,28.1,0.167,21,0
0,137,40,35,168,43.1,2.288,33,1
```

1.  现在我们来看一下皮马糖尿病数据，以了解其格式：

```scala
tail -5 pima-indians-diabetes.data
10,101,76,48,180,32.9,0.171,63,0
2,122,70,27,0,36.8,0.340,27,0
5,121,72,23,112,26.2,0.245,30,0
1,126,60,0,0,30.1,0.349,47,1
1,93,70,31,0,30.4,0.315,23,0
```

# 它是如何工作的...

我们有 768 个观测值的数据集。每行/记录由 10 个特征和一个标签值组成，可以用于监督学习模型（即逻辑回归）。标签/类别要么是`1`，表示糖尿病检测呈阳性，要么是`0`，表示检测呈阴性。

**特征/属性：**

+   怀孕次数

+   口服葡萄糖耐量试验 2 小时后的血浆葡萄糖浓度

+   舒张压（毫米汞柱）

+   三头肌皮褶厚度（毫米）

+   口服葡萄糖耐量试验 2 小时后的血清胰岛素（mu U/ml）

+   身体质量指数（体重（公斤）/（身高（米）²））

+   糖尿病谱系功能

+   年龄（岁）

+   类变量（0 或 1）

```scala
    Label/Class:
               1 - tested positive
               0 - tested negative
```

# 还有更多...

我们发现普林斯顿大学提供的以下替代数据集非常有帮助：

[`data.princeton.edu/wws509/datasets`](http://data.princeton.edu/wws509/datasets)

# 另请参阅

您可以用来探索此配方的数据集必须以标签（预测类）为二进制（糖尿病检测呈阳性/阴性）的方式进行结构化。

# 在线分类器的流式逻辑回归

在这个示例中，我们将使用在上一个示例中下载的 Pima 糖尿病数据集和 Spark 的流式逻辑回归算法进行预测，以预测具有各种特征的 Pima 是否会测试为糖尿病阳性。这是一种在线分类器，它根据流式数据进行学习和预测。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

```scala
package spark.ml.cookbook.chapter13
```

1.  导入必要的包：

```scala
import org.apache.log4j.{Level, Logger}
import org.apache.spark.mllib.classification.StreamingLogisticRegressionWithSGD
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.{Row, SparkSession}
import org.apache.spark.streaming.{Seconds, StreamingContext}
import scala.collection.mutable.Queue

```

1.  创建一个`SparkSession`对象作为集群的入口点和一个`StreamingContext`：

```scala
val spark = SparkSession
 .builder.master("local[*]")
 .appName("Logistic Regression Streaming App")
 .config("spark.sql.warehouse.dir", ".")
 .getOrCreate()

 import spark.implicits._

 val ssc = new StreamingContext(spark.sparkContext, *Seconds*(2))
```

1.  日志消息的交错导致输出难以阅读，因此将日志级别设置为警告：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)
```

1.  将 Pima 数据文件加载到类型为字符串的数据集中：

```scala
val rawDS = spark.read
.text("../data/sparkml2/chapter13/pima-indians- diabetes.data").as[String]
```

1.  从我们的原始数据集中构建一个 RDD，方法是生成一个元组，其中最后一项作为标签，其他所有内容作为序列：

```scala
val buffer = rawDS.rdd.map(value => {
val data = value.split(",")
(data.init.toSeq, data.last)
})
```

1.  将预处理数据转换为标签点，以便与机器学习库一起使用：

```scala
val lps = buffer.map{ case (feature: Seq[String], label: String) =>
val featureVector = feature.map(_.toDouble).toArray[Double]
LabeledPoint(label.toDouble, Vectors.dense(featureVector))
}

```

1.  创建用于附加数据的可变队列：

```scala
val trainQueue = new Queue[RDD[LabeledPoint]]()
val testQueue = new Queue[RDD[LabeledPoint]]()
```

1.  创建 Spark 流队列以接收流数据：

```scala
val trainingStream = ssc.queueStream(trainQueue)
val testStream = ssc.queueStream(testQueue)
```

1.  配置流式逻辑回归模型：

```scala
val numFeatures = 8
val model = new StreamingLogisticRegressionWithSGD()
.setInitialWeights(Vectors.*zeros*(numFeatures))
.setNumIterations(15)
.setStepSize(0.5)
.setMiniBatchFraction(0.25)
```

1.  训练回归模型并预测最终值：

```scala
model.trainOn(trainingStream)
val result = model.predictOnValues(testStream.map(lp => (lp.label,
lp.features)))
 result.map{ case (label: Double, prediction: Double) => (label, prediction) }.print()
```

1.  启动 Spark 流上下文：

```scala
ssc.start()
```

1.  将标签点数据拆分为训练集和测试集：

```scala
val Array(trainData, test) = lps.randomSplit(*Array*(.80, .20))
```

1.  将数据附加到训练数据队列以进行处理：

```scala
trainQueue += trainData
 Thread.sleep(4000)
```

1.  现在将测试数据分成两半，并附加到队列以进行处理：

```scala
val testGroups = test.randomSplit(*Array*(.50, .50))
 testGroups.foreach(group => {
 testQueue += group
 Thread.sleep(2000)
 })
```

1.  一旦数据被队列流接收，您将看到以下输出：

```scala
-------------------------------------------
Time: 1488571098000 ms
-------------------------------------------
(1.0,1.0)
(1.0,1.0)
(1.0,0.0)
(0.0,1.0)
(1.0,0.0)
(1.0,1.0)
(0.0,0.0)
(1.0,1.0)
(0.0,1.0)
(0.0,1.0)
...
-------------------------------------------
Time: 1488571100000 ms
-------------------------------------------
(1.0,1.0)
(0.0,0.0)
(1.0,1.0)
(1.0,0.0)
(0.0,1.0)
(0.0,1.0)
(0.0,1.0)
(1.0,0.0)
(0.0,0.0)
(1.0,1.0)
...
```

1.  通过停止 Spark 流上下文来关闭程序：

```scala
ssc.stop()
```

# 它是如何工作的...

首先，我们将 Pima 糖尿病数据集加载到一个数据集中，并通过将每个元素作为特征，除了最后一个元素作为标签，将其解析为元组。其次，我们将元组的 RDD 变形为带有标签的点，以便用作流式逻辑回归算法的输入。第三，我们创建了可变队列的实例和 Spark 的`QueueInputDStream`类，以用作逻辑算法的路径。

第四，我们创建了流式逻辑回归模型，它将预测我们最终结果的葡萄酒质量。最后，我们通常从原始数据创建训练和测试数据集，并将其附加到适当的队列中，以触发模型对流数据的处理。每个微批处理的最终结果显示了测试真正阳性的原始标签和预测标签为 1.0，或者真正阴性的标签为 0.0。

# 还有更多...

`StreamingLogisticRegressionWithSGD()`的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.classification.StreamingLogisticRegressionWithSGD`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.classification.StreamingLogisticRegressionWithSGD)上找到

[﻿](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.classification.StreamingLogisticRegressionWithSGD)

# 另请参阅

模型的超参数：

+   `setInitialWeights()`

+   `setNumIterations()`

+   `setStepSize()`

+   `setMiniBatchFraction()`
