# Spark2 数据处理和实时分析（四）

> 原文：[`zh.annas-archive.org/md5/16D84784AD68D8BF20A18AC23C62DD82`](https://zh.annas-archive.org/md5/16D84784AD68D8BF20A18AC23C62DD82)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：使用 Apache Spark 2.0 进行无监督聚类

在本章中，我们将涵盖：

+   在 Spark 2.0 中构建 KMeans 分类系统

+   在 Spark 2.0 中，二分 KMeans 作为新星登场

+   在 Spark 2.0 中使用高斯混合模型和期望最大化（EM）算法进行数据分类

+   在 Spark 2.0 中使用幂迭代聚类（PIC）对图的顶点进行分类

+   使用潜在狄利克雷分配（LDA）将文档和文本分类为主题

+   使用流式 KMeans 在接近实时的情况下对数据进行分类

# 引言

无监督机器学习是一种学习技术，我们试图直接或间接（通过潜在因素）从一组未标记的观察中得出推断。简而言之，我们试图在未对训练数据进行初始标记的情况下，从一组数据中发现隐藏的知识或结构。

尽管大多数机器学习库的实现在大数据集上应用时会崩溃（迭代、多次遍历、大量中间写入），但 Apache Spark 机器学习库通过提供为并行性和极大数据集设计的算法，并默认使用内存进行中间写入，从而取得了成功。

在最抽象的层面上，我们可以将无监督学习视为：

# 在 Spark 2.0 中构建 KMeans 分类系统

在本教程中，我们将使用 LIBSVM 文件加载一组特征（例如，x，y，z 坐标），然后使用`KMeans()`实例化一个对象。接着，我们将设置期望的簇数为三个，并使用`kmeans.fit()`执行算法。最后，我们将打印出我们找到的三个簇的中心。

值得注意的是，Spark*并未*实现 KMeans++，这与流行文献相反，而是实现了 KMeans ||（发音为 KMeans Parallel）。请参阅以下教程以及代码之后的部分，以获得对 Spark 中实现的算法的完整解释。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter8
```

1.  为了获取集群访问权限并使用`Log4j.Logger`减少 Spark 产生的输出量，需要导入必要的 Spark 上下文包：

```scala
import org.apache.log4j.{Level, Logger}import org.apache.spark.ml.clustering.KMeansimport org.apache.spark.sql.SparkSession
```

1.  将输出级别设置为`ERROR`以减少 Spark 的日志输出：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)
```

1.  创建 Spark 的 Session 对象：

```scala
val spark = SparkSession .builder.master("local[*]") .appName("myKMeansCluster") .config("spark.sql.warehouse.dir" ...
```

# 工作原理...

我们读取了一个 LIBSVM 文件，其中包含一组坐标（可以解释为三个数字的元组），然后创建了一个 `KMean()` 对象，但将默认簇数从 2（开箱即用）更改为 3，以便演示。我们使用 `.fit()` 创建模型，然后使用 `model.summary.predictions.show()` 显示哪个元组属于哪个簇。在最后一步中，我们打印了成本和三个簇的中心。从概念上讲，可以将其视为拥有一组 3D 坐标数据，然后使用 KMeans 算法将每个单独的坐标分配给三个簇之一。

KMeans 是一种无监督机器学习算法，其根源在于信号处理（矢量量化）和压缩（将相似的物品矢量分组以实现更高的压缩率）。一般来说，KMeans 算法试图将一系列观察值 {X[1,] X[2], .... , X[n]} 分组到一系列簇 {C[1,] C[2 .....] C[n]} 中，使用一种距离度量（局部优化），该度量以迭代方式进行优化。

目前使用的 KMeans 算法主要有三种类型。在一项简单的调查中，我们发现了 12 种 KMeans 算法的专门变体。值得注意的是，Spark 实现了一个名为 KMeans ||（KMeans 并行）的版本，而不是文献或视频中提到的 KMeans++ 或标准 KMeans。

下图简要描绘了 KMeans 算法：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/870bc634-f412-46c1-9857-83ed6e05183f.png)

来源：Spark 文档

# KMeans（Lloyd 算法）

基本 KMeans 实现（Lloyd 算法）的步骤如下：

1.  从观察结果中随机选择 K 个数据中心作为初始中心。

1.  持续迭代直至满足收敛条件：

    +   测量一个点到每个中心的距离

    +   将每个数据点包含在与其最接近的中心对应的簇中

    +   根据距离公式（作为不相似性的代理）计算新的簇中心

    +   使用新的中心点更新算法

下图描绘了三代算法：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/bc4b1c43-9ed0-4396-a06a-d12c2a3d181d.png)

# KMeans++（亚瑟算法）

对标准 KMeans 的下一个改进是 David Arthur 和 Sergei Vassilvitskii 于 2007 年提出的 KMeans++。亚瑟算法通过在种子过程（初始步骤）中更加挑剔来改进初始的 Lloyd 的 KMeans。

KMeans++并非随机选择初始中心（随机质心），而是随机选取第一个质心，然后逐个选取数据点并计算`D(x)`。接着，它随机选择另一个数据点，并使用比例概率分布`D(x)2`，重复最后两个步骤，直到选出所有*K*个数。初始播种完成后，我们最终运行 KMeans 或其变体，使用新播种的质心。KMeans++算法保证在*Omega= O(log k)*复杂度内找到解决方案。尽管初始播种步骤较多，但准确性提升显著。

# KMeans||（发音为 KMeans Parallel）

KMeans || 经过优化，可并行运行，相较于 Lloyd 的原始算法，性能提升可达一到两个数量级。KMeans++的局限性在于它需要对数据集进行 K 次遍历，这在大规模或极端数据集上运行 KMeans 时会严重限制其性能和实用性。Spark 的 KMeans||并行实现运行更快，因为它通过采样 m 个点并在过程中进行过采样，减少了数据遍历次数（大幅减少）。

算法的核心及数学原理在下图中展示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/e50796d1-a612-4089-b44f-1ffb5c933bab.png)

简而言之，KMeans ||（并行...）的亮点在于...

# 还有更多...

在 Spark 中还有一个流式 KMeans 实现，允许您实时对特征进行分类。

还有一个类帮助您生成 KMeans 的 RDD 数据。我们在应用程序开发过程中发现这非常有用：

```scala
def generateKMeansRDD(sc: SparkContext, numPoints: Int, k: Int, d: Int, r: Double, numPartitions: Int = 2): RDD[Array[Double]] 
```

此调用使用 Spark 上下文创建 RDD，同时允许您指定点数、簇数、维度和分区数。

一个相关的实用 API 是：`generateKMeansRDD()`。关于`generateKMeansRDD`的文档可以在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.util.KMeansDataGenerator$`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.util.KMeansDataGenerator%24)找到，用于生成供 KMeans 使用的测试数据 RDD。

# 另请参阅

我们需要两个对象来编写、测量和操作 Spark 中 KMeans ||算法的参数。这两个对象的详细信息可以在以下网站找到：

+   `KMeans()`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.KMeans`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.KMeans)

+   `KMeansModel()`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.KMeansModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.KMeansModel)

# Bisecting KMeans，Spark 2.0 中的新秀

在本节中，我们将下载玻璃数据集，并尝试使用 Bisecting KMeans 算法来识别和标记每种玻璃。Bisecting KMeans 是 K-Mean 算法的层次化版本，在 Spark 中通过`BisectingKMeans()`API 实现。虽然该算法在概念上类似于 KMeans，但在存在层次路径的情况下，它可以为某些用例提供显著的速度优势。

本节中使用的数据集是玻璃识别数据库。对玻璃类型分类的研究源于犯罪学研究。如果玻璃能被正确识别，它可能被视为证据。数据可在台湾大学（NTU）找到，已采用 LIBSVM 格式。

# 如何操作...

1.  我们从以下链接下载了 LIBSVM 格式的预处理数据文件：[`www.csie.ntu.edu.tw/~cjlin/libsvmtools/datasets/multiclass/glass.scale`](https://www.csie.ntu.edu.tw/~cjlin/libsvmtools/datasets/multiclass/glass.scale)

该数据集包含 11 个特征和 214 行数据。

1.  原始数据集及数据字典亦可在 UCI 网站上获取：[`archive.ics.uci.edu/ml/datasets/Glass+Identification`](http://archive.ics.uci.edu/ml/datasets/Glass+Identification)

    +   ID 号：1 至 214

    +   RI: 折射率

    +   Na: 钠（单位测量：相应氧化物中的重量百分比，属性 4-10 也是如此）

    +   Mg: 镁

    +   Al: 铝

    +   Si: 硅

    +   K: 钾

    +   Ca: 钙

    +   Ba: 钡

    +   Fe: 铁

玻璃类型：我们将使用`BisectingKMeans()`来寻找我们的类别属性或簇：

+   `building_windows_float_processed`

+   `building_windows_non-_float_processed`

+   `vehicle_windows_float_processed`

# 工作原理...

在本节中，我们探讨了 Spark 2.0 中新引入的 Bisecting KMeans 模型。我们利用了玻璃数据集，并尝试使用`BisectingKMeans()`来指定玻璃类型，但将 k 值调整为 6，以便拥有足够的簇。按照惯例，我们使用 Spark 的 libsvm 加载机制将数据加载到数据集中。我们将数据集随机分为 80%和 20%，其中 80%用于训练模型，20%用于测试模型。

我们创建了`BiSectingKmeans()`对象，并使用`fit(x)`函数来构建模型。随后，我们使用`transform(x)`函数对测试数据集进行模型预测，并在控制台输出结果。我们还输出了计算簇的成本（误差平方和），并展示了簇中心。最后，我们打印了特征及其分配的簇编号，并停止操作。

层次聚类的方法包括：

+   **分割型**：自上而下的方法（Apache Spark 实现）

+   **聚合型**：自下而上的方法

# 还有更多...

关于 Bisecting KMeans 的更多信息，请访问：

+   [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.BisectingKMeans`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.BisectingKMeans)

+   [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.BisectingKMeansModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.BisectingKMeansModel)

我们使用聚类来探索数据，并对聚类结果的外观有所了解。二分 K 均值是层次分析与 K 均值聚类的一个有趣案例。

最佳的理解方式是将二分 K 均值视为递归层次的 K 均值。二分 K 均值算法通过类似 K 均值的相似度测量技术分割数据，但采用层次结构以提高准确性。它在...中尤为普遍...

# 参见

实现层次聚类有两种方法——Spark 采用递归自顶向下的方法，在其中选择一个簇，然后在算法向下移动层次时执行分割：

+   关于层次聚类方法的详细信息可在[`en.wikipedia.org/wiki/Hierarchical_clustering`](https://en.wikipedia.org/wiki/Hierarchical_clustering)找到

+   Spark 2.0 关于二分 K-均值的文档可在[`spark.apache.org/docs/latest/ml-clustering.html#bisecting-k-means`](http://spark.apache.org/docs/latest/ml-clustering.html#bisecting-k-means)找到

+   一篇描述如何使用二分 K 均值对网络日志进行分类的论文可在[`research.ijcaonline.org/volume116/number19/pxc3902799.pdf`](http://research.ijcaonline.org/volume116/number19/pxc3902799.pdf)找到

# 在 Spark 中使用高斯混合和期望最大化（EM）进行数据分类

在本食谱中，我们将探讨 Spark 对**期望最大化**（**EM**）的实现`GaussianMixture()`，它计算给定一组特征输入的最大似然。它假设每个点可以从 K 个子分布（簇成员）中采样的高斯混合。

# 操作方法...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter8.
```

1.  导入用于向量和矩阵操作的必要包：

```scala
 import org.apache.log4j.{Level, Logger}
 import org.apache.spark.mllib.clustering.GaussianMixture
 import org.apache.spark.mllib.linalg.Vectors
 import org.apache.spark.sql.SparkSession
```

1.  创建 Spark 的会话对象：

```scala
val spark = SparkSession
 .builder.master("local[*]")
 .appName("myGaussianMixture")
 .config("spark.sql.warehouse.dir", ".")
 .getOrCreate()
```

1.  让我们查看数据集并检查输入文件。模拟的 SOCR 膝痛质心位置数据代表了 1000 名受试者假设的膝痛位置的质心位置。数据包括质心的 X 和 Y 坐标。

此数据集可用于说明高斯混合和期望最大化。数据可在[`wiki.stat.ucla.edu/socr/index.php/SOCR_Data_KneePainData_041409`](http://wiki.stat.ucla.edu/socr/index.php/SOCR_Data_KneePainData_041409)获取

样本数据如下所示：

+   **X**：一个受试者和一个视图的质心位置的*x*坐标。

+   **Y**：一个受试者和一个视图的质心位置的*y*坐标。

X, Y

11 73

20 88

19 73

15 65

21 57

26 101

24 117

35 106

37 96

35 147

41 151

42 137

43 127

41 206

47 213

49 238

40 229

下图基于`wiki.stat.ucla`的 SOCR 数据集描绘了一个膝痛地图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/18ed269a-1079-4fd8-a2c0-6a75e4e93fcb.png)

1.  我们将数据文件放置在一个数据目录中（您可以将数据文件复制到您喜欢的任何位置）。

数据文件包含 8,666 条记录：

```scala
val dataFile ="../data/sparkml2/chapter8/socr_data.txt"
```

1.  接着，我们将数据文件加载到 RDD 中：

```scala
val trainingData = spark.sparkContext.textFile(dataFile).map { line =>
 Vectors.dense(line.trim.split(' ').map(_.toDouble))
 }.cache()
```

1.  现在，我们创建一个高斯混合模型并设置模型参数。我们将 K 值设为 4，因为数据是通过四个视角收集的：**左前**（**LF**）、**左后**（**LB**）、**右前**（**RF**）和**右后**（**RB**）。我们将收敛值设为默认值 0.01，最大迭代次数设为 100：

```scala
val myGM = new GaussianMixture()
 .setK(4 ) // default value is 2, LF, LB, RF, RB
 .setConvergenceTol(0.01) // using the default value
 .setMaxIterations(100) // max 100 iteration
```

1.  我们运行模型算法：

```scala
val model = myGM.run(trainingData)
```

1.  训练后，我们打印出高斯混合模型的关键值：

```scala
println("Model ConvergenceTol: "+ myGM.getConvergenceTol)
 println("Model k:"+myGM.getK)
 println("maxIteration:"+myGM.getMaxIterations)

 for (i <- 0 until model.k) {
 println("weight=%f\nmu=%s\nsigma=\n%s\n" format
 (model.weights(i), model.gaussians(i).mu, model.gaussians(i).sigma))
 }
```

1.  由于我们将 K 值设为 4，因此控制台记录器将打印出四组值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/bc6b63fe-5651-462d-8966-636bec6ba119.png)

1.  我们还根据高斯混合模型预测打印出前 50 个聚类标签：

```scala
println("Cluster labels (first <= 50):")
 val clusterLabels = model.predict(trainingData)
 clusterLabels.take(50).foreach { x =>
 *print*(" " + x)
 }
```

1.  控制台中的样本输出将显示以下内容：

```scala
Cluster labels (first <= 50):
 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
```

1.  然后通过停止 Spark 上下文来关闭程序：

```scala
spark.stop()
```

# 工作原理...

在前一个示例中，我们观察到 KMeans 能够发现并基于迭代方法（如欧几里得距离等）将成员分配到一个且仅一个集群。可以将 KMeans 视为高斯混合模型中 EM 模型的专用版本，其中强制执行离散（硬）成员资格。

但存在重叠情况，这在医学或信号处理中很常见，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/86a123c5-915b-40b8-ae00-55fac3375b57.png)

在这种情况下，我们需要一个能够表达每个子分布中成员资格的概率密度函数。采用**期望最大化**算法的高斯混合模型

# 新建 GaussianMixture()

这构建了一个默认实例。控制模型行为的默认参数如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/46e18b3f-0a38-44c0-bebf-24f741ebe8f6.png)

采用期望最大化算法的**高斯混合模型**是一种软聚类形式，其中可以通过对数最大似然函数推断出成员资格。在此情况下，使用具有均值和协方差的概率密度函数来定义属于 K 个集群的成员资格或似然性。其灵活性在于，成员资格未量化，这允许基于概率（索引到多个子分布）的成员资格重叠。

下图是 EM 算法的一个快照：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/1eac50f4-acad-4b14-a479-aa390fe87a9b.png)

以下是 EM 算法的步骤：

1.  假设有*N*个高斯分布。

1.  迭代直至达到收敛：

    1.  对于每个点 Z，其条件概率为从分布 Xi 中抽取，记作*P(Z | Xi)*

    1.  调整参数的均值和方差，使其适合分配给子分布的点

有关更数学化的解释，包括关于最大似然的详细工作，请参阅以下链接：[`www.ee.iisc.ernet.in/new/people/faculty/prasantg/downloads/GMM_Tutorial_Reynolds.pdf`](http://www.ee.iisc.ernet.in/new/people/faculty/prasantg/downloads/GMM_Tutorial_Reynolds.pdf)

# 还有更多...

下图提供了一个快速参考点，以突出硬聚类与软聚类之间的一些差异：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/f1c9d196-7b32-40ea-9303-66fa819f52f7.png)

# 另请参阅

+   构造器 GaussianMixture 的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.GaussianMixture`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.GaussianMixture)找到

+   构造器 GaussianMixtureModel 的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.GaussianMixtureModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.GaussianMixtureModel)找到

# 在 Spark 2.0 中使用幂迭代聚类（PIC）对图的顶点进行分类

这是一种基于顶点相似性（由边定义）对图的顶点进行分类的方法。它使用随 Spark 一起提供的 GraphX 库来实现算法。幂迭代聚类类似于其他特征向量/特征值分解算法，但没有矩阵分解的开销。当您有一个大型稀疏矩阵（例如，以稀疏矩阵表示的图）时，它很适用。

未来，GraphFrames 将成为 GraphX 库的替代/接口（[`databricks.com/blog/2016/03/03/introducing-graphframes.html`](https://databricks.com/blog/2016/03/03/introducing-graphframes.html)）。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter8
```

1.  为 Spark 上下文导入必要的包以访问集群，并导入`Log4j.Logger`以减少 Spark 产生的输出量：

```scala
 import org.apache.log4j.{Level, Logger}
 import org.apache.spark.mllib.clustering.PowerIterationClustering
 import org.apache.spark.sql.SparkSession
```

1.  将日志级别设置为 ERROR，仅以减少输出：

```scala
Logger.getLogger("org").setLevel(Level.*ERROR*)
```

1.  创建 Spark 配置和 SQL 上下文，以便我们可以访问集群并能够根据需要创建和使用 DataFrame：

```scala
// setup SparkSession to use for interactions with Sparkval spark = SparkSession
 .builder.master("local[*]")
 .appName("myPowerIterationClustering")
 .config("spark.sql.warehouse.dir", ".")
 .getOrCreate()
```

1.  我们使用 Spark 的`sparkContext.parallelize()`函数创建包含一系列数据集的训练数据集，并创建 Spark RDD：

```scala
val trainingData =spark.sparkContext.parallelize(*List*(
 (0L, 1L, 1.0),
 (0L, 2L, 1.0),
 (0L, 3L, 1.0),
 (1L, 2L, 1.0),
 (1L, 3L, 1.0),
 (2L, 3L, 1.0),
 (3L, 4L, 0.1),
 (4L, 5L, 1.0),
 (4L, 15L, 1.0),
 (5L, 6L, 1.0),
 (6L, 7L, 1.0),
 (7L, 8L, 1.0),
 (8L, 9L, 1.0),
 (9L, 10L, 1.0),
 (10L,11L, 1.0),
 (11L, 12L, 1.0),
 (12L, 13L, 1.0),
 (13L,14L, 1.0),
 (14L,15L, 1.0)
 ))
```

1.  我们创建一个`PowerIterationClustering`对象并设置参数。我们将`K`值设置为`3`，最大迭代次数设置为`15`：

```scala
val pic = new PowerIterationClustering()
 .setK(3)
 .setMaxIterations(15)
```

1.  然后让模型运行：

```scala
val model = pic.run(trainingData)
```

1.  我们根据模型打印出训练数据的集群分配情况：

```scala
model.assignments.foreach { a =>
 println(s"${a.id} -> ${a.cluster}")
 }
```

1.  控制台输出将显示以下信息：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/1fbb5236-33c4-443b-b46c-c506f0c66782.png)

1.  我们还为每个聚类在集合中打印出模型分配数据：

```scala
val clusters = model.assignments.collect().groupBy(_.cluster).mapValues(_.map(_.id))
 val assignments = clusters.toList.sortBy { case (k, v) => v.length }
 val assignmentsStr = assignments
 .map { case (k, v) =>
 s"$k -> ${v.sorted.mkString("[", ",", "]")}" }.mkString(", ")
 val sizesStr = assignments.map {
 _._2.length
 }.sorted.mkString("(", ",", ")")
 println(s"Cluster assignments: $assignmentsStr\ncluster sizes: $sizesStr")
```

1.  控制台输出将显示以下信息（总共，我们在前面的参数中设置了三个聚类）：

```scala
Cluster assignments: 1 -> [12,14], 2 -> [4,6,8,10], 0 -> [0,1,2,3,5,7,9,11,13,15]
 cluster sizes: (2,4,10)
```

1.  然后我们通过停止 Spark 上下文来关闭程序：

```scala
spark.stop()
```

# 其工作原理...

我们创建了一个图的边和顶点列表，然后继续创建对象并设置参数：

```scala
new PowerIterationClustering().setK(3).setMaxIterations(15)
```

下一步是训练数据模型：

```scala
val model = pic.run(trainingData)
```

然后输出聚类以供检查。代码末尾附近的代码使用 Spark 转换运算符在集合中为每个聚类打印出模型分配数据。

**PIC**（**幂迭代聚类**）的核心是一种避免矩阵分解的特征值类算法，它通过生成一个特征值加上一个特征向量来满足*Av* = λ*v*。由于 PIC 避免了矩阵 A 的分解，因此它适用于输入矩阵 A（描述图...

# 还有更多...

如需对主题（幂迭代）进行更详细的数学处理，请参阅卡内基梅隆大学提供的以下白皮书：[`www.cs.cmu.edu/~wcohen/postscript/icml2010-pic-final.pdf`](http://www.cs.cmu.edu/~wcohen/postscript/icml2010-pic-final.pdf)

# 另请参阅

+   构造函数`PowerIterationClustering()`的文档可以在以下位置找到：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.PowerIterationClustering`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.PowerIterationClustering)

+   构造函数`PowerIterationClusteringModel()`的文档可以在以下位置找到：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.PowerIterationClusteringModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.PowerIterationClusteringModel)

# 使用潜在狄利克雷分配（LDA）对文档和文本进行主题分类

在本食谱中，我们将探讨 Spark 2.0 中的**潜在狄利克雷分配**（**LDA**）算法。本食谱中使用的 LDA 与线性判别分析完全不同。潜在狄利克雷分配和线性判别分析都称为 LDA，但它们是截然不同的技术。在本食谱中，当我们使用 LDA 时，我们指的是潜在狄利克雷分配。关于文本分析的章节也与理解 LDA 相关。

LDA 常用于自然语言处理，试图将大量文档（例如安然欺诈案中的电子邮件）分类为有限数量的主题或主题，以便于理解。LDA 也是根据个人兴趣选择文章的良好候选方法（例如，当你翻页并花时间在特定主题上时），在给定的杂志文章或页面上。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter8
```

1.  导入必要的包：

```scala
import org.apache.log4j.{Level, Logger}import org.apache.spark.sql.SparkSessionimport org.apache.spark.ml.clustering.LDA
```

1.  我们设置必要的 Spark 会话以访问集群：

```scala
val spark = SparkSession .builder.master("local[*]") .appName("MyLDA") .config("spark.sql.warehouse.dir", ".") .getOrCreate()
```

1.  我们有一个 LDA 样本数据集，位于以下相对路径（您也可以使用绝对路径）。该样本文件随任何 Spark 发行版提供，并且...

# 工作原理...

LDA 假设文档是具有 Dirichlet 先验分布的不同主题的混合体。文档中的单词被认为对特定主题有亲和力，这使得 LDA 能够对整体文档（构成并分配分布）进行分类，以最佳匹配主题。

主题模型是一种生成潜在模型，用于发现文档主体中出现的抽象主题（主题）（通常对于人类来说太大而无法处理）。这些模型是总结、搜索和浏览大量未标记文档及其内容的先驱。一般来说，我们试图找到一起出现的特征（单词、子图像等）的集群。

下图描绘了 LDA 的整体方案：

为了完整性，请务必参考此处引用的白皮书：[`ai.stanford.edu/~ang/papers/nips01-lda.pdf`](http://ai.stanford.edu/~ang/papers/nips01-lda.pdf)

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/a85bbb8a-37a8-4880-ac6f-e8ede49bdb67.png)

LDA 算法的步骤如下：

1.  初始化以下参数（控制集中度和平滑度）：

    1.  Alpha 参数（高 alpha 值使得文档间更为相似，且包含相似的主题）

    1.  Beta 参数（高 beta 值意味着每个主题最可能包含大多数单词的混合）

1.  随机初始化主题分配。

1.  迭代：

    1.  对于每个文档。

        1.  对于文档中的每个单词。

        1.  为每个单词重新采样主题。

            1.  相对于所有其他单词及其当前分配（对于当前迭代）。

1.  获取结果。

1.  模型评估

在统计学中，Dirichlet 分布 Dir(alpha)是一族由正实数向量α参数化的连续多元概率分布。关于 LDA 的更深入探讨，请参阅原始论文：

机器学习杂志上的原论文链接：[`www.jmlr.org/papers/volume3/blei03a/blei03a.pdf`](http://www.jmlr.org/papers/volume3/blei03a/blei03a.pdf)

LDA 不对主题赋予任何语义，也不关心主题的名称。它只是一个生成模型，使用细粒度项（例如，关于猫、狗、鱼、汽车的单词）的分布来分配总体主题，该主题得分最高。它不知道、不关心，也不理解被称为狗或猫的主题。

我们通常需要通过 TF-IDF 对文档进行分词和向量化，然后才能输入到 LDA 算法中。

# 还有更多...

下图简要描绘了 LDA：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/f3315b50-1445-4633-a0d5-ffaf8256afd5.png)

文档分析有两种方法。我们可以简单地使用矩阵分解将大型数据集矩阵分解为较小的矩阵（主题分配）乘以向量（主题本身）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/1f6891f4-b0ce-476a-bda5-d52d10745a60.png)

# 另请参阅

+   **LDA**：构造函数的文档可在 [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDA`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDA)

+   [**LDAModel**：构造函数的文档可在 ](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDA)[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDAModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDAModel)

另请参阅，通过 Spark 的 Scala API，以下文档链接：

+   DistributedLDAModel

+   EMLDAOptimizer

+   LDAOptimizer

+   LocalLDAModel

+   OnlineLDAOptimizer

# 流式 KMeans 用于近实时分类数据

Spark 流式处理是一个强大的功能，它允许您在同一范式中结合近实时和批处理。流式 KMeans 接口位于 ML 聚类和 Spark 流式处理的交叉点，充分利用了 Spark 流式处理本身提供的核心功能（例如，容错、精确一次交付语义等）。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  导入流式 KMeans 所需的包：

`package spark.ml.cookbook.chapter14`.

1.  导入流式 KMeans 所需的包：

```scala
import org.apache.log4j.{Level, Logger}
 import org.apache.spark.mllib.clustering.StreamingKMeans
 import org.apache.spark.mllib.linalg.Vectors
 import org.apache.spark.mllib.regression.LabeledPoint
 import org.apache.spark.sql.SparkSession
 import org.apache.spark.streaming.{Seconds, StreamingContext}
```

1.  我们为流式 KMeans 程序设置了以下参数。训练目录将是发送训练数据文件的目录。KMeans 聚类模型利用训练数据运行算法和计算。`testDirectory`将用于预测的测试数据。`batchDuration`是以秒为单位的批处理运行时间。在以下情况下，程序将每 10 秒检查一次是否有新的数据文件用于重新计算。

1.  集群设置为`2`，数据维度将为`3`：

```scala
val trainingDir = "../data/sparkml2/chapter8/trainingDir" val testDir = "../data/sparkml2/chapter8/testDir" val batchDuration = 10
 val numClusters = 2
 val numDimensions = 3
```

1.  使用上述设置，示例训练数据将包含以下格式的数据（以[*X[1], X[2], ...X[n]*]格式，其中*n*是`numDimensions`）：

[0.0,0.0,0.0]

[0.1,0.1,0.1]

[0.2,0.2,0.2]

[9.0,9.0,9.0]

[9.1,9.1,9.1]

[9.2,9.2,9.2]

[0.1,0.0,0.0]

[0.2,0.1,0.1]

....

测试数据文件将包含以下格式的数据（以（*y, [X1, X2, .. Xn]*）格式，其中*n*是`numDimensions`，`y`是标识符）：

(7,[0.4,0.4,0.4])

(8,[0.1,0.1,0.1])

(9,[0.2,0.2,0.2])

(10,[1.1,1.0,1.0])

(11,[9.2,9.1,9.2])

(12,[9.3,9.2,9.3])

1.  我们设置必要的 Spark 上下文以访问集群：

```scala
val spark = SparkSession
 .builder.master("local[*]")
 .appName("myStreamingKMeans")
 .config("spark.sql.warehouse.dir", ".")
 .getOrCreate()
```

1.  定义流式上下文和微批处理窗口：

```scala
val ssc = new StreamingContext(spark.sparkContext, Seconds(batchDuration.toLong))
```

1.  以下代码将通过解析上述两个目录中的数据文件创建`trainingData`和`testData RDDs`：

```scala
val trainingData = ssc.textFileStream(trainingDir).map(Vectors.parse)
 val testData = ssc.textFileStream(testDir).map(LabeledPoint.parse)
```

1.  我们创建`StreamingKMeans`模型并设置参数：

```scala
val model = new StreamingKMeans()
 .setK(numClusters)
 .setDecayFactor(1.0)
 .setRandomCenters(numDimensions, 0.0)
```

1.  程序将使用训练数据集训练模型，并使用测试数据集进行预测：

```scala
model.trainOn(trainingData)
 model.predictOnValues(testData.map(lp => (lp.label, lp.features))).print()
```

1.  我们启动流式上下文，程序将每 10 秒运行一次批处理，以检查是否有新的训练数据集可用，以及是否有新的测试数据集用于预测。如果收到终止信号（退出批处理运行），程序将退出。

```scala
ssc.start()
 ssc.awaitTermination()
```

1.  我们将`testKStreaming1.txt`数据文件复制到上述`testDir`设置中，并在控制台日志中看到以下打印输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/d39d25e2-be84-46b3-917a-52c3907e3122.png)

1.  对于 Windows 机器，我们将`testKStreaming1.txt`文件复制到了目录：`C:\spark-2.0.0-bin-hadoop2.7\data\sparkml2\chapter8\testDir\`。

1.  我们还可以通过访问`http://localhost:4040/`来检查 SparkUI 以获取更多信息。

作业面板将显示流式作业，如图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/6ef1d102-cb06-48cd-b26c-9f71ac6bbb9d.png)

如图所示，流式面板将显示上述流式 KMeans 矩阵，显示批处理作业每 10 秒运行一次：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/b14bd318-6028-4597-bf45-ca1e5a3dcd9d.png)

您可以通过点击任何批处理，如图所示，获取有关流式批处理的更多详细信息：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/1a690bac-440b-4891-a843-1270709933a4.png)

# 工作原理...

在某些情况下，我们不能使用批处理方法来加载和捕获事件，然后对其做出反应。我们可以使用在内存或着陆数据库中捕获事件的创造性方法，然后快速将其转移到另一个系统进行处理，但大多数这些系统无法作为流式系统运行，并且通常构建成本非常高。

Spark 提供了一种近乎实时的（也称为主观实时）方式，可以接收来自 Twitter feeds、信号等的传入源，通过连接器（例如 Kafka 连接器）进行处理，并以 RDD 接口的形式呈现。

这些是构建和构造 Spark 中流式 KMeans 所需的元素：

1.  使用流式上下文而不是...

# 还有更多...

流式 KMeans 是 KMeans 实现的一种特殊情况，其中数据可以近乎实时地到达，并根据需要被分类到集群（硬分类）中。关于 Voronoi 图的参考，请参见以下 URL：[`en.wikipedia.org/wiki/Voronoi_diagram`](https://en.wikipedia.org/wiki/Voronoi_diagram)

目前，Spark 机器学习库中除了流式 KMeans 外还有其他算法，如图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/7e339c28-5370-47c9-bd81-086eb04f7ca0.png)

# 另请参阅

+   流式 KMeans 文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeans`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeans)找到。

+   流式 KMeans 模型文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.stat.test.StreamingTest`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.stat.test.StreamingTest)找到。

+   流式测试文档——对数据生成非常有用——可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeansModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeansModel)找到。


# 第十五章：使用 Spark 2.0 ML 库实现文本分析

本章中，我们将涵盖以下内容：

+   使用 Spark 进行词频统计 - 一切计数

+   使用 Spark 通过 Word2Vec 显示相似词

+   为实际的 Spark ML 项目下载维基百科的完整数据集

+   使用 Spark 2.0 进行文本分析的潜在语义分析

+   Spark 2.0 中的主题建模与潜在狄利克雷分配

# 引言

文本分析处于机器学习、数学、语言学和自然语言处理的交叉点。文本分析，在较早的文献中称为文本挖掘，试图从未结构化和半结构化数据中提取信息并推断更高级别的概念、情感和语义细节。值得注意的是，传统的关键词搜索不足以处理需要根据实际上下文过滤掉的噪声、模糊和无关的词条和概念。

最终，我们试图做的是对于一组给定的文档（文本、推文、网页和社交媒体），确定沟通的要点以及它试图传达的概念（主题和...

# 使用 Spark 进行词频统计 - 一切计数

对于此示例，我们将从古腾堡项目下载一本文本格式的书籍，网址为[`www.gutenberg.org/cache/epub/62/pg62.txt`](http://www.gutenberg.org/cache/epub/62/pg62.txt)。

古腾堡项目提供超过 50,000 种格式的免费电子书供人类消费。请阅读他们的使用条款；让我们不要使用命令行工具下载任何书籍。

当你查看文件内容时，会注意到该书的标题和作者是*《火星公主》项目古腾堡电子书》*，作者是埃德加·赖斯·巴勒斯。

这本电子书可供任何人免费使用，几乎没有任何限制。你可以复制它、赠送它，或根据古腾堡项目许可证中包含的条款重新使用它，该许可证可在[`www.gutenberg.org/`](http://www.gutenberg.org/)在线获取。

然后，我们使用下载的书籍来演示使用 Scala 和 Spark 的经典词频统计程序。这个例子起初可能看起来有些简单，但我们正在开始文本处理的特征提取过程。此外，对文档中词频计数的一般理解将大大有助于我们理解 TF-IDF 的概念。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  该示例的`包`声明如下：

```scala
package spark.ml.cookbook.chapter12
```

1.  导入 Scala、Spark 和 JFreeChart 所需的必要包：

```scala
import org.apache.log4j.{Level, Logger}import org.apache.spark.sql.SQLContextimport org.apache.spark.{SparkConf, SparkContext}import org.jfree.chart.axis.{CategoryAxis, CategoryLabelPositions}import org.jfree.chart.{ChartFactory, ChartFrame, JFreeChart}import org.jfree.chart.plot.{CategoryPlot, PlotOrientation}import org.jfree.data.category.DefaultCategoryDataset
```

1.  我们将定义一个函数，在窗口中显示我们的 JFreeChart：

```scala
def show(chart: JFreeChart) ...
```

# 其工作原理...

我们首先加载下载的书籍，并通过正则表达式对其进行分词。接下来的步骤是将所有词条转换为小写，并从词条列表中排除停用词，然后过滤掉任何长度小于两个字符的词。

去除停用词和特定长度的词减少了我们需要处理的特征数量。这可能不明显，但根据各种处理标准去除特定单词会减少机器学习算法后续处理的维度数量。

最后，我们对结果的词频进行了降序排序，取前 25 个，并为其展示了一个条形图。

# 还有更多...

在本菜谱中，我们有了关键词搜索的基础。理解主题建模和关键词搜索之间的区别很重要。在关键词搜索中，我们试图根据出现次数将短语与给定文档关联。在这种情况下，我们将向用户指向出现次数最多的文档集。

# 另请参见

该算法的下一步演化，开发者可以尝试作为扩展，将是添加权重并计算加权平均值，但 Spark 提供了我们将在接下来的菜谱中探讨的设施。

# 使用 Spark 的 Word2Vec 展示相似词

在本菜谱中，我们将探讨 Word2Vec，这是 Spark 评估词相似性的工具。Word2Vec 算法受到普通语言学中*分布假设*的启发。其核心思想是，出现在相同上下文（即与目标的距离）中的词倾向于支持相同的原始概念/意义。

谷歌的一组研究人员发明了 Word2Vec 算法。请参考本菜谱中*还有更多...*部分提到的白皮书，该白皮书对 Word2Vec 进行了更详细的描述。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  本菜谱的`package`语句如下：

```scala
package spark.ml.cookbook.chapter12
```

1.  导入 Scala 和 Spark 所需的必要包：

```scala
import org.apache.log4j.{Level, Logger}
import org.apache.spark.ml.feature.{RegexTokenizer, StopWordsRemover, Word2Vec}
import org.apache.spark.sql.{SQLContext, SparkSession}
import org.apache.spark.{SparkConf, SparkContext}
```

1.  让我们定义书籍文件的位置：

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

1.  我们现在利用 Spark 的正则表达式分词器将每行转换为词袋，将每个词转换为小写，并过滤掉任何字符长度小于四的词：

```scala
val tokenizer = new RegexTokenizer()
 .setPattern("\\W+")
 .setToLowercase(true)
 .setMinTokenLength(4)
 .setInputCol("text")
 .setOutputCol("raw")
 val rawWords = tokenizer.transform(df)
```

1.  我们使用 Spark 的`StopWordRemover`类去除停用词：

```scala
val stopWords = new StopWordsRemover()
 .setInputCol("raw")
 .setOutputCol("terms")
 .setCaseSensitive(false)
 val wordTerms = stopWords.transform(rawWords)
```

1.  我们应用 Word2Vec 机器学习算法提取特征：

```scala
val word2Vec = new Word2Vec()
 .setInputCol("terms")
 .setOutputCol("result")
 .setVectorSize(3)
 .setMinCount(0)
val model = word2Vec.fit(wordTerms)
```

1.  我们从书中找出*martian*的十个同义词：

```scala
val synonyms = model.findSynonyms("martian", 10)
```

1.  展示模型找到的十个同义词的结果：

```scala
synonyms.show(false)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/7d3b2158-a771-4656-af50-1a4492e191f7.png)

1.  我们通过停止 SparkContext 来关闭程序：

```scala
spark.stop()
```

# 它是如何工作的...

在 Spark 中，Word2Vec 使用的是跳字模型而非**连续词袋模型**（**CBOW**），后者更适合**神经网络**（**NN**）。其核心在于尝试计算词的表示。强烈建议用户理解局部表示与分布式表示之间的差异，这与词本身的表面意义截然不同。

如果使用分布式向量表示词，自然地，相似的词在向量空间中会彼此靠近，这是一种理想的模式抽象和操作泛化技术（即，我们将问题简化为向量运算）。

对于给定的一组词*{Word[1,] Word[2, .... ...]*，我们想要做的是

# 还有更多...

无论如何，你如何找到相似的词？有多少算法能解决这个问题，它们之间有何不同？Word2Vec 算法已经存在一段时间，并且有一个对应的模型称为 CBOW。请记住，Spark 提供的实现技术是跳字模型。

Word2Vec 算法的变化如下：

+   **连续词袋模型（CBOW）**：给定一个中心词，周围的词是什么？

+   **跳字模型**：如果我们知道周围的词，能否猜出缺失的词？

有一种算法变体称为**带负采样的跳字模型**（**SGNS**），它似乎优于其他变体。

共现是 CBOW 和跳字模型背后的基本概念。尽管跳字模型并不直接使用共现矩阵，但它间接地使用了它。

在本方法中，我们使用了 NLP 中的*停用词*技术，在运行算法前对语料库进行净化。停用词如英语中的"*the*"需要被移除，因为它们对结果的改进没有贡献。

另一个重要概念是*词干提取*，这里未涉及，但将在后续方法中展示。词干提取去除额外的语言特征，将词还原为其词根（例如，*Engineering*、*Engineer*和*Engineers*变为*Engin*，即词根）。

以下 URL 的白皮书应提供对 Word2Vec 更深入的解释：

[`arxiv.org/pdf/1301.3781.pdf`](http://arxiv.org/pdf/1301.3781.pdf)

# 参见

Word2Vec 方法的文档：

+   `Word2Vec()`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.Word2Vec`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.Word2Vec)

+   `Word2VecModel()`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.Word2VecModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.Word2VecModel)

+   `StopWordsRemover()`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.StopWordsRemover`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.feature.StopWordsRemover)

# 为实际的 Spark ML 项目下载完整的维基百科转储

在本示例中，我们将下载并探索维基百科的转储，以便我们有一个实际的示例。本示例中我们将下载的数据集是维基百科文章的转储。您将需要命令行工具**curl**或浏览器来检索压缩文件，目前该文件大小约为 13.6 GB。由于文件较大，我们建议使用 curl 命令行工具。

# 如何操作...

1.  您可以使用以下命令开始下载数据集：

```scala
curl -L -O http://dumps.wikimedia.org/enwiki/latest/enwiki-latest-pages-articles-multistream.xml.bz2
```

1.  现在您想要解压缩 ZIP 文件：

```scala
bunzip2 enwiki-latest-pages-articles-multistream.xml.bz2
```

这将创建一个未压缩的文件，名为`enwiki-latest-pages-articles-multistream.xml`，大小约为 56 GB。

1.  让我们来看看维基百科 XML 文件：

```scala
head -n50 enwiki-latest-pages-articles-multistream.xml<mediawiki xmlns=http://www.mediawiki.org/xml/export-0.10/  xsi:schemaLocation="http://www.mediawiki.org/xml/export-0.10/ http://www.mediawiki.org/xml/export-0.10.xsd" version="0.10" ...
```

# 还有更多...

我们建议将 XML 文件分块处理，并在准备好提交最终作业之前使用抽样进行实验。这将节省大量时间和精力。

# 另请参阅

维基下载文档可在[`en.wikipedia.org/wiki/Wikipedia:Database_download`](https://en.wikipedia.org/wiki/Wikipedia:Database_download)找到。

# 使用 Spark 2.0 进行文本分析的潜在语义分析

在本示例中，我们将利用维基百科文章的数据转储来探索 LSA。LSA 意味着分析文档集合以发现这些文档中的隐藏含义或概念。

本章第一个示例中，我们介绍了 TF（即词频）技术的基本概念。在本示例中，我们使用 HashingTF 计算 TF，并使用 IDF 将模型拟合到计算出的 TF 上。LSA 的核心在于对词频文档进行**奇异值分解**（**SVD**），以降低维度并提取最重要的概念。我们还需要进行其他清理步骤（例如，停用词和词干提取），以在开始分析之前清理词袋。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  本示例的包声明如下：

```scala
package spark.ml.cookbook.chapter12
```

1.  为 Scala 和 Spark 导入必要的包：

```scala
import edu.umd.cloud9.collection.wikipedia.WikipediaPage import edu.umd.cloud9.collection.wikipedia.language.EnglishWikipediaPage import org.apache.hadoop.fs.Path import org.apache.hadoop.io.Text import org.apache.hadoop.mapred.{FileInputFormat, JobConf} import org.apache.log4j.{Level, Logger} import org.apache.spark.mllib.feature.{HashingTF, IDF} import org.apache.spark.mllib.linalg.distributed.RowMatrix import org.apache.spark.sql.SparkSession import org.tartarus.snowball.ext.PorterStemmer ...
```

# 它是如何工作的...

示例首先通过使用 Cloud9 Hadoop XML 流工具加载维基百科 XML 转储来处理庞大的 XML 文档。一旦我们解析出页面文本，分词阶段就会将我们的维基百科页面文本流转换为令牌。在分词阶段，我们使用了 Porter 词干提取器来帮助将单词简化为共同的基本形式。

关于词干提取的更多详细信息，请访问[`en.wikipedia.org/wiki/Stemming`](https://en.wikipedia.org/wiki/Stemming)。

下一步是使用 Spark 的 HashingTF 对每个页面令牌计算词频。在此阶段完成后，我们利用 Spark 的 IDF 生成逆文档频率。

最后，我们采用了 TF-IDF API，并应用奇异值分解来处理因式分解和降维。

以下截图展示了该方法的步骤和流程：

图片：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/ff9337d4-120e-4985-a45a-d4a273732f96.png)

可在以下链接找到 Cloud9 Hadoop XML 工具及其他所需依赖：

+   `bliki-core-3.0.19.jar`：[`central.maven.org/maven2/info/bliki/wiki/bliki-core/3.0.19/bliki-core-3.0.19.jar`](http://central.maven.org/maven2/info/bliki/wiki/bliki-core/3.0.19/bliki-core-3.0.19.jar)

+   `cloud9-2.0.1.jar`：[`central.maven.org/maven2/edu/umd/cloud9/2.0.1/cloud9-2.0.1.jar`](http://central.maven.org/maven2/edu/umd/cloud9/2.0.1/cloud9-2.0.1.jar)

+   `hadoop-streaming-2.7.4.jar`：[`central.maven.org/maven2/org/apache/hadoop/hadoop-streaming/2.7.4/hadoop-streaming-2.7.4.jar`](http://central.maven.org/maven2/org/apache/hadoop/hadoop-streaming/2.7.4/hadoop-streaming-2.7.4.jar)

+   `lucene-snowball-3.0.3.jar`：[`central.maven.org/maven2/org/apache/lucene/lucene-snowball/3.0.3/lucene-snowball-3.0.3.jar`](http://central.maven.org/maven2/org/apache/lucene/lucene-snowball/3.0.3/lucene-snowball-3.0.3.jar)

# 还有更多...

现在应该很明显，尽管 Spark 没有直接提供 LSA 实现，但 TF-IDF 与 SVD 的结合将使我们能够构建并分解大型语料库矩阵为三个矩阵，这有助于我们通过 SVD 进行降维来解释结果。我们可以专注于最有意义的集群（类似于推荐算法）。

SVD 将词频文档（即按属性划分的文档）分解为三个不同的矩阵，这些矩阵更便于从难以处理且成本高昂的大型矩阵中提取*N*个概念（例如，在我们的例子中*N=27*）。在机器学习中，我们总是偏好高瘦矩阵（即本例中的*U*矩阵）...

# 另请参阅

关于`SingularValueDecomposition()`的更多详情，请参阅[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.SingularValueDecomposition`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.SingularValueDecomposition)。

关于`RowMatrix()`的更多详情，请参考[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.distributed.RowMatrix`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.linalg.distributed.RowMatrix)。

# 使用 Spark 2.0 进行主题建模与潜在狄利克雷分配

在本方法中，我们将展示如何利用潜在狄利克雷分配（Latent Dirichlet Allocation）从文档集合中推断主题模型。

我们在前面的章节中已经介绍了 LDA，因为它适用于聚类和主题建模，但在本章中，我们展示了一个更复杂的示例，以展示它如何应用于使用更真实和复杂数据集的文本分析。

我们还应用了诸如词干提取和停用词等 NLP 技术，以提供更真实的 LDA 问题解决方法。我们试图做的是发现一组潜在因素（即与原始因素不同），这些因素可以在减少的...中以更高效的方式解决问题并描述解决方案。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  该配方中的`package`声明如下：

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

1.  我们定义了一个函数来解析 Wikipedia 页面并返回页面的标题和内容文本：

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

1.  让我们定义 Wikipedia 数据转储的位置：

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

1.  我们为 Hadoop XML 流处理设置数据路径：

```scala
FileInputFormat.addInputPath(jobConf, new Path(input))
```

1.  使用工厂构建器模式创建具有配置的`SparkSession`：

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

1.  我们开始处理巨大的 Wikipedia 数据转储成文章页面，从文件中抽取样本：

```scala
val wikiData = spark.sparkContext.hadoopRDD(
 jobConf,
 classOf[org.apache.hadoop.streaming.StreamInputFormat],
 classOf[Text],
 classOf[Text]).sample(false, .1)
```

1.  接下来，我们将示例数据处理成包含标题和页面上下文文本的元组的 RDD，最终生成一个 DataFrame：

```scala
val df = wiki.map(_._1.toString)
 .flatMap(parseWikiPage)
 .toDF("title", "text")
```

1.  我们现在使用 Spark 的`RegexTokenizer`将 DataFrame 的文本列转换为每个 Wikipedia 页面的原始单词：

```scala
val tokenizer = new RegexTokenizer()
 .setPattern("\\W+")
 .setToLowercase(true)
 .setMinTokenLength(4)
 .setInputCol("text")
 .setOutputCol("raw")
 val rawWords = tokenizer.transform(df)
```

1.  下一步是过滤原始单词，通过去除令牌中的所有停用词：

```scala
val stopWords = new StopWordsRemover()
 .setInputCol("raw")
 .setOutputCol("words")
 .setCaseSensitive(false)

 val wordData = stopWords.transform(rawWords)
```

1.  我们使用 Spark 的`CountVectorizer`类为过滤后的令牌生成词频，从而产生包含列特征的新 DataFrame：

```scala
val cvModel = new CountVectorizer()
 .setInputCol("words")
 .setOutputCol("features")
 .setMinDF(2)
 .fit(wordData)
 val cv = cvModel.transform(wordData)
 cv.cache()
```

"MinDF"指定必须出现在词汇表中的不同文档术语的最小数量。

1.  我们现在调用 Spark 的 LDA 类来生成主题以及令牌到主题的分布：

```scala
val lda = new LDA()
 .setK(5)
 .setMaxIter(10)
 .setFeaturesCol("features")
 val model = lda.fit(tf)
 val transformed = model.transform(tf)
```

"K"指的是主题数量，"MaxIter"是执行的最大迭代次数。

1.  我们最终描述了生成的五个顶级主题并显示：

```scala
val topics = model.describeTopics(5)
 topics.show(false)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/65c0cc6a-8015-4bdb-85e2-c753056bb79c.png)

1.  现在显示与主题相关联的主题和术语：

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

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/d6907078-900d-4d60-9db9-7697c384eb19.png)

1.  我们通过停止 SparkContext 来关闭程序：

```scala
spark.stop()
```

# 它是如何工作的...

我们首先加载 Wikipedia 文章的转储，并使用 Hadoop XML 利用流 API 将页面文本解析为令牌。特征提取过程利用了几个类来设置最终由 LDA 类处理的流程，让令牌从 Spark 的`RegexTokenize`、`StopwordsRemover`和`HashingTF`流过。一旦我们有了词频，数据就被传递给 LDA 类，以便在几个主题下将文章聚类在一起。

Hadoop XML 工具和其他几个必需的依赖项可以在以下位置找到：

+   `bliki-core-3.0.19.jar`：[`central.maven.org/maven2/info/bliki/wiki/bliki-core/3.0.19/bliki-core-3.0.19.jar`](http://central.maven.org/maven2/info/bliki/wiki/bliki-core/3.0.19/bliki-core-3.0.19.jar)

+   `cloud9-2.0.1.jar`：[`central.maven.org/maven2/edu/umd/cloud9/2.0.1/cloud9-2.0.1.jar ...`](http://central.maven.org/maven2/edu/umd/cloud9/2.0.1/cloud9-2.0.1.jar)

# 还有更多...

请参阅第八章《Apache Spark 2.0 无监督聚类》中的*LDA 食谱*，以获取有关 LDA 算法本身的更详细解释，该章节介绍了如何将文档和文本分类为主题。

《机器学习研究杂志》(JMLR) 的以下白皮书为希望进行深入分析的人提供了全面的论述。这是一篇写得很好的论文，具有统计和数学基础的人应该能够毫无困难地理解它。

欲了解更多关于 JMLR 的详情，请参考[`www.jmlr.org/papers/volume3/blei03a/blei03a.pdf`](http://www.jmlr.org/papers/volume3/blei03a/blei03a.pdf)链接；另有一替代链接为[`www.cs.colorado.edu/~mozer/Teaching/syllabi/ProbabilisticModels/readings/BleiNgJordan2003.pdf`](https://www.cs.colorado.edu/~mozer/Teaching/syllabi/ProbabilisticModels/readings/BleiNgJordan2003.pdf)。

# 另请参阅

+   构造函数的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDA`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDA)找到。

+   LDAModel 的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDAModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.clustering.LDAModel)找到。

亦可参阅 Spark 的 Scala API 文档，了解以下内容：

+   DistributedLDAModel

+   EMLDAOptimizer

+   LDAOptimizer

+   LocalLDAModel

+   OnlineLDAOptimizer


# 第十六章：Spark 流处理与机器学习库

在本章中，我们将介绍以下内容：

+   结构化流处理，用于近实时机器学习

+   使用流式 DataFrames 进行实时机器学习

+   使用流式数据集进行实时机器学习

+   使用 queueStream 进行流数据和调试

+   下载并理解著名的鸢尾花数据集，用于无监督分类

+   为实时在线分类器实现流式 KMeans

+   下载葡萄酒质量数据，用于流式回归

+   为实时回归实现流式线性回归

+   下载 Pima 糖尿病数据集，用于监督分类

+   为在线分类器实现流式逻辑回归

# 引言

Spark 流处理是一个不断发展的过程，旨在统一和结构化 API，以解决批处理与流处理的关切。自 Spark 1.3 起，Spark 流处理就已提供**离散流**（**DStream**）。新的方向是使用无界表模型抽象底层框架，用户可以使用 SQL 或函数式编程查询表，并将输出写入到另一个输出表中，支持多种模式（完整、增量和追加输出）。Spark SQL Catalyst 优化器和 Tungsten（堆外内存管理器）现已成为 Spark 流处理的核心部分，从而实现更高效的执行。

在本章中，我们不仅涵盖了 Spark 中可用的流处理功能...

# 结构化流处理，用于近实时机器学习

在本节中，我们将探讨 Spark 2.0 引入的新结构化流处理范式。我们通过使用套接字和结构化流 API 进行实时流处理，并相应地投票和统计票数。

我们还通过模拟一系列随机生成的投票来探索新引入的子系统，以选出最不受欢迎的漫画书反派角色。

本节包含两个不同的程序（`VoteCountStream.scala`和`CountStreamproducer.scala`）。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

```scala
package spark.ml.cookbook.chapter13
```

1.  导入必要的包，以便 Spark 上下文可以访问集群，并使用`log4j.Logger`减少 Spark 产生的输出量：

```scala
import org.apache.log4j.{Level, Logger}import org.apache.spark.sql.SparkSessionimport java.io.{BufferedOutputStream, PrintWriter}import java.net.Socketimport java.net.ServerSocketimport java.util.concurrent.TimeUnitimport scala.util.Randomimport org.apache.spark.sql.streaming.ProcessingTime
```

1.  定义一个 Scala 类，用于将投票数据生成到客户端套接字：

```scala
class CountSreamThread(socket: ...
```

# 工作原理...

在本节中，我们创建了一个简单的数据生成服务器，用于模拟投票数据流，并对投票进行计数。下图提供了这一概念的高层次描述：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/cf9e0f2a-e5e9-4b19-af52-bd11232731a3.png)

首先，我们启动了数据生成服务器。其次，我们定义了一个套接字数据源，以便连接到数据生成服务器。接着，我们构建了一个简单的 Spark 表达式，按反派（即坏超级英雄）分组并统计当前收到的所有投票。最后，我们设置了一个 10 秒的阈值触发器来执行我们的流查询，该查询将累积结果输出到控制台。

本方案涉及两个简短的程序：

+   `CountStreamproducer.scala`：

    +   生产者 - 数据生成服务器

    +   模拟投票过程并进行广播

+   `VoteCountStream.scala`：

    +   消费者 - 消费并聚合/制表数据

    +   接收并统计我们反派超级英雄的投票

# 还有更多...

本书不涉及使用 Spark 流处理和结构化流处理的编程主题，但我们认为有必要分享一些程序以引入概念，然后再深入探讨 Spark 的 ML 流处理功能。

如需对流处理进行全面介绍，请参阅 Spark 相关文档：

+   有关 Spark 2.0+结构化流的信息，请访问[`spark.apache.org/docs/latest/structured-streaming-programming-guide.html#api-using-datasets-and-dataframes`](https://spark.apache.org/docs/latest/structured-streaming-programming-guide.html#api-using-datasets-and-dataframes)

+   Spark 1.6 流处理信息可在[`spark.apache.org/docs/latest/streaming-programming-guide.html`](https://spark.apache.org/docs/latest/streaming-programming-guide.html)获取

# 另请参阅

+   结构化流文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.package`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.package)获取

+   DStream（Spark 2.0 之前）文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.streaming.dstream.DStream`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.streaming.dstream.DStream)获取

+   `DataStreamReader`文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader)获取

+   `DataStreamWriter`文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter)获取

+   `StreamingQuery`文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.StreamingQuery`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.StreamingQuery)获取

# 实时机器学习的流数据帧

在本例中，我们探讨了流式 DataFrame 的概念。我们创建了一个包含个人姓名和年龄的 DataFrame，该数据将通过网络流式传输。流式 DataFrame 是与 Spark ML 配合使用的一种流行技术，因为在撰写本文时，Spark 结构化 ML 尚未完全集成。

本例仅限于演示流式 DataFrame，并留给读者将其适配到自己的自定义 ML 管道中。虽然流式 DataFrame 在 Spark 2.1.0 中并非开箱即用，但它将是 Spark 后续版本的自然演进。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

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

1.  创建一个`SparkSession`作为访问 Spark 集群的入口点：

```scala
val spark = SparkSession
.builder.master("local[*]")
.appName("DataFrame Stream")
.config("spark.sql.warehouse.dir", ".")
.getOrCreate()

```

1.  日志消息的交错导致输出难以阅读，因此将日志级别设置为警告：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)
Logger.getLogger("akka").setLevel(Level.ERROR)
```

1.  接下来，加载人员数据文件以推断数据模式，无需手动编码结构类型：

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

1.  现在配置一个流式 DataFrame 以接收数据：

```scala
val stream = spark.readStream
.schema(df.schema)
.json("../data/sparkml2/chapter13/people/")
```

1.  让我们执行一个简单的数据转换，通过筛选年龄大于`60`的记录：

```scala
val people = stream.select("name", "age").where("age > 60")
```

1.  现在我们将转换后的流数据输出到控制台，该操作将每秒触发一次：

```scala
val query = people.writeStream
.outputMode("append")
.trigger(ProcessingTime(1, TimeUnit.SECONDS))
.format("console")
```

1.  我们启动定义的流查询，并等待数据出现在流中：

```scala
query.start().awaitTermination()
```

1.  最终，我们的流查询结果将显示在控制台上：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/d7e4aeb9-e4f9-4cbf-b311-136b78be704a.png)

# 它是如何工作的...

在本例中，我们首先使用快速方法（使用 JSON 对象）发现人员对象的底层模式，如步骤 6 所述。生成的 DataFrame 将了解我们随后对流输入（通过流式传输文件模拟）施加的模式，并作为流式 DataFrame 处理，如步骤 7 所示。

将流视为 DataFrame 并使用函数式或 SQL 范式对其进行操作的能力是一个强大的概念，如步骤 8 所示。然后，我们继续使用`writestream()`以`append`模式和 1 秒批处理间隔触发器输出结果。

# 还有更多...

DataFrames 与结构化编程的结合是一个强大的概念，有助于我们将数据层与流分离，从而使编程变得更加简单。DStream（Spark 2.0 之前）最大的缺点之一是其无法将用户与流/RDD 实现的底层细节隔离。

关于 DataFrames 的文档：

+   `DataFrameReader`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.DataFrameReader`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.DataFrameReader)

+   DataFrameWriter: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.DataFrameWriter`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.DataFrameWriter)

# 另请参阅

Spark 数据流读写器文档：

+   DataStreamReader: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader)

+   DataStreamWriter: [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter)

# 实时机器学习的流式数据集

在本示例中，我们创建了一个流式数据集，以展示在 Spark 2.0 结构化编程范式中使用数据集的方法。我们通过数据集从文件中流式传输股票价格，并应用过滤器选择当日收盘价高于$100 的股票。

本示例展示了如何使用简单的结构化流编程模型来过滤和处理传入数据。虽然它类似于 DataFrame，但在语法上存在一些差异。本示例以通用方式编写，以便用户可以根据自己的 Spark ML 编程项目进行定制。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter13
```

1.  导入必要的包：

```scala
import java.util.concurrent.TimeUnitimport org.apache.log4j.{Level, Logger}import org.apache.spark.sql.SparkSessionimport org.apache.spark.sql.streaming.ProcessingTime
```

1.  定义一个 Scala `case class`来模拟流数据：

```scala
case class StockPrice(date: String, open: Double, high: Double, low: Double, close: Double, volume: Integer, adjclose: Double)
```

1.  创建`SparkSession`作为访问 Spark 集群的入口点：

```scala
val spark = SparkSession.builder.master("local[*]").appName("Dataset ...
```

# 工作原理...

在本示例中，我们将利用**通用电气**（**GE**）自 1972 年以来的收盘价市场数据。为了简化数据，我们已为本次示例预处理了数据。我们采用了上一示例《实时机器学习的流式数据帧》中的方法，通过查看 JSON 对象来发现模式（步骤 7），并在步骤 8 中将其应用于流。

以下代码展示了如何使用模式使流看起来像一个简单的表格，以便实时从中读取数据。这是一个强大的概念，使得流编程对更多程序员来说变得易于访问。以下代码片段中的`schema(s.schema)`和`as[StockPrice]`是创建具有关联模式的流式数据集所必需的：

```scala
val streamDataset = spark.readStream
            .schema(s.schema)
            .option("sep", ",")
            .option("header", "true")
            .csv("../data/sparkml2/chapter13/ge").as[StockPrice]
```

# 还有更多...

所有数据集下可用的 API 文档位于：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.Dataset)

# 另请参阅

以下文档在探索流式数据集概念时很有帮助：

+   `StreamReader`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamReader)

+   `StreamWriter`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.DataStreamWriter)

+   `StreamQuery`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.StreamingQuery`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.sql.streaming.StreamingQuery)

# 使用 queueStream 进行流数据和调试

在本食谱中，我们探讨了`queueStream()`的概念，这是在开发周期中尝试使流式程序工作时的宝贵工具。我们发现`queueStream()` API 非常有用，并认为其他开发人员可以从完全展示其用法的食谱中受益。

我们首先使用`ClickGenerator.scala`程序模拟用户浏览与不同网页关联的各种 URL，然后使用`ClickStream.scala`程序消费和汇总数据（用户行为/访问）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/84401a18-69d7-490d-8946-511151c882b3.png)

我们使用 Spark 的流式 API，`Dstream()`，这将需要使用...

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter13
```

1.  导入必要的包：

```scala
import java.time.LocalDateTime
import scala.util.Random._
```

1.  定义一个 Scala `case class`来模拟用户点击事件，包含用户标识符、IP 地址、事件时间、URL 和 HTTP 状态码：

```scala
case class ClickEvent(userId: String, ipAddress: String, time: String, url: String, statusCode: String)
```

1.  定义生成的状态码：

```scala
val statusCodeData = Seq(200, 404, 500)
```

1.  定义生成的 URL：

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

1.  定义生成的 IP 地址范围：

```scala
val ipAddressData = generateIpAddress()
def generateIpAddress(): Seq[String] = {
 for (n <- 1 to 255) yield s"127.0.0.$n" }
```

1.  定义生成的时间戳范围：

```scala
val timeStampData = generateTimeStamp()

 def generateTimeStamp(): Seq[String] = {
 val now = LocalDateTime.now()
 for (n <- 1 to 1000) yield LocalDateTime.*of*(now.toLocalDate,
 now.toLocalTime.plusSeconds(n)).toString
 }
```

1.  定义生成的用户标识符范围：

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

1.  定义一个函数，从字符串解析伪随机`ClickEvent`：

```scala
def parseClicks(data: String): ClickEvent = {
val fields = data.split(",")
new ClickEvent(fields(0), fields(1), fields(2), fields(3), fields(4))
 }
```

1.  创建 Spark 配置和 Spark 流式上下文，持续时间为 1 秒：

```scala
val spark = SparkSession
.builder.master("local[*]")
 .appName("Streaming App")
 .config("spark.sql.warehouse.dir", ".")
 .config("spark.executor.memory", "2g")
 .getOrCreate()
val ssc = new StreamingContext(spark.sparkContext, Seconds(1))
```

1.  日志消息的交错导致输出难以阅读，因此将日志级别设置为警告：

```scala
Logger.getRootLogger.setLevel(Level.WARN)
```

1.  创建一个可变队列，将我们生成的数据附加到其上：

```scala
val rddQueue = new Queue[RDD[String]]()
```

1.  从流式上下文中创建一个 Spark 队列流，传递我们的数据队列的引用：

```scala
val inputStream = ssc.queueStream(rddQueue)
```

1.  处理队列流接收到的任何数据，并计算用户点击每个特定链接的总次数：

```scala
val clicks = inputStream.map(data => ClickGenerator.parseClicks(data))
 val clickCounts = clicks.map(c => c.url).countByValue()
```

1.  打印出`12`个 URL 及其总数：

```scala
clickCounts.print(12)
```

1.  启动我们的流式上下文以接收微批量：

```scala
ssc.start()
```

1.  循环 10 次，每次迭代生成 100 个伪随机事件，并将它们附加到我们的可变队列，以便它们在流式队列抽象中实现：

```scala
for (i <- 1 to 10) {
 rddQueue += ssc.sparkContext.parallelize(ClickGenerator.*generateClicks*(100))
 Thread.sleep(1000)
 }
```

1.  我们通过停止 Spark 流式上下文来关闭程序：

```scala
ssc.stop()
```

# 工作原理...

通过本教程，我们介绍了使用许多人忽视的技术来引入 Spark Streaming，即利用 Spark 的`QueueInputDStream`类构建流式应用程序。`QueueInputDStream`类不仅有助于理解 Spark 流处理，而且在开发周期中调试也非常有用。在初始步骤中，我们设置了一些数据结构，以便稍后生成用于流处理的伪随机`clickstream`事件数据。

需要注意的是，在第 12 步中，我们创建的是流式上下文而非 SparkContext。流式上下文用于 Spark 流处理应用。接下来，创建队列和队列流以接收流数据。现在步骤...

# 另请参见

本质上，`queueStream()`只是一个 RDD 队列，在 Spark 流处理（2.0 版本之前）转换为 RDD 后形成：

+   结构化流处理文档（Spark 2.0+）：[`spark.apache.org/docs/2.1.0/structured-streaming-programming-guide.html`](https://spark.apache.org/docs/2.1.0/structured-streaming-programming-guide.html)

+   流处理文档（Spark 2.0 之前）：[`spark.apache.org/docs/latest/streaming-programming-guide.html`](https://spark.apache.org/docs/latest/streaming-programming-guide.html)

# 下载并理解著名的鸢尾花数据，用于无监督分类

在本教程中，我们下载并检查了著名的鸢尾花数据集，为即将到来的流式 KMeans 教程做准备，该教程让您实时看到分类/聚类过程。

数据存储在 UCI 机器学习库中，这是一个用于算法原型设计的数据宝库。你会发现 R 语言博客作者们往往钟爱这个数据集。

# 如何操作...

1.  您可以通过以下任一命令开始下载数据集：

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

1.  现在我们通过检查`iris.data`中的数据格式开始数据探索的第一步：

```scala
head -5 iris.data
5.1,3.5,1.4,0.2,Iris-setosa
4.9,3.0,1.4,0.2,Iris-setosa
4.7,3.2,1.3,0.2,Iris-setosa
4.6,3.1,1.5,0.2,Iris-setosa
5.0,3.6,1.4,0.2,Iris-setosa
```

1.  现在我们来看看鸢尾花数据的格式：

```scala
tail -5 iris.data
6.3,2.5,5.0,1.9,Iris-virginica
6.5,3.0,5.2,2.0,Iris-virginica
6.2,3.4,5.4,2.3,Iris-virginica
5.9,3.0,5.1,1.8,Iris-virginica
```

# 工作原理...

数据包含 150 个观测值。每个观测值由四个数值特征（以厘米为单位）和一个标签组成，该标签指示每朵鸢尾花所属的类别：

**特征/属性**：

+   萼片长度（厘米）

+   萼片宽度（厘米）

+   花瓣长度（厘米）

+   花瓣宽度（厘米）

**标签/类别**：

+   山鸢尾

+   变色鸢尾

+   维吉尼亚鸢尾

# 更多内容...

下图清晰地标示了一朵鸢尾花的花瓣和萼片：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/fec7666e-bdb6-48c5-9df0-da2283f1877b.png)

# 另请参见

以下链接更详细地探讨了鸢尾花数据集：

[`en.wikipedia.org/wiki/Iris_flower_data_set`](https://en.wikipedia.org/wiki/Iris_flower_data_set)

# 实时在线分类器的流式 KMeans

在本教程中，我们探索了 Spark 中用于无监督学习方案的流式 KMeans。流式 KMeans 算法的目的在于根据数据点的相似性因子将其分类或分组到多个簇中。

KMeans 分类方法有两种实现，一种用于静态/离线数据，另一种版本用于持续到达的实时更新数据。

我们将对鸢尾花数据集进行流式聚类，因为新数据流入了我们的流式上下文。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter13
```

1.  导入必要的包：

```scala
import org.apache.spark.mllib.linalg.Vectorsimport org.apache.spark.mllib.regression.LabeledPointimport org.apache.spark.rdd.RDDimport org.apache.spark.SparkContextimport scala.collection.mutable.Queue
```

1.  我们首先定义一个函数，将鸢尾花数据加载到内存中，过滤掉空白行，为每个元素附加一个标识符，最后返回一个字符串和长整型的元组：

```scala
def readFromFile(sc: SparkContext) = { sc.textFile("../data/sparkml2/chapter13/iris.data") .filter(s ...
```

# 它是如何工作的...

在本教程中，我们首先加载鸢尾花数据集，并使用`zip()` API 将数据与唯一标识符配对，以生成用于 KMeans 算法的*标记点*数据结构。

接下来，我们创建了可变队列和`QueueInputDStream`，用于追加数据以模拟流式处理。一旦`QueueInputDStream`开始接收数据，流式 k 均值聚类就会开始动态地聚类数据并输出结果。您会注意到的一个有趣之处是，我们正在一个队列流上对训练数据集进行流式处理，而在另一个队列流上对测试数据进行流式处理。当我们向队列追加数据时，KMeans 聚类算法正在处理我们的传入数据，并动态生成簇。

# 还有更多...

关于*StreamingKMeans()*的文档：

+   `StreamingKMeans`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeans`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeans)

+   `StreamingKMeansModel`：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeansModel`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.clustering.StreamingKMeansModel)

# 另请参阅

通过构建器模式或`streamingKMeans`定义的超参数为：

```scala
setDecayFactor()
setK()
setRandomCenters(,)
```

# 下载葡萄酒质量数据以进行流式回归

在本教程中，我们从 UCI 机器学习存储库下载并检查葡萄酒质量数据集，为 Spark 的流式线性回归算法准备数据。

# 如何操作...

您需要以下命令行工具之一`curl`或`wget`来检索指定数据：

1.  您可以从以下三个命令中任选其一下载数据集。第一个命令如下：

```scala
wget http://archive.ics.uci.edu/ml/machine-learning-databases/wine-quality/winequality-white.csv
```

您也可以使用以下命令：

```scala
curl http://archive.ics.uci.edu/ml/machine-learning-databases/wine-quality/winequality-white.csv -o winequality-white.csv
```

此命令是执行相同操作的第三种方式：

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

1.  现在我们来看看葡萄酒质量数据，了解其格式：

```scala
tail -5 winequality-white.csv
6.2;0.21;0.29;1.6;0.039;24;92;0.99114;3.27;0.5;11.2;6
6.6;0.32;0.36;8;0.047;57;168;0.9949;3.15;0.46;9.6;5
6.5;0.24;0.19;1.2;0.041;30;111;0.99254;2.99;0.46;9.4;6
5.5;0.29;0.3;1.1;0.022;20;110;0.98869;3.34;0.38;12.8;7
6;0.21;0.38;0.8;0.02;22;98;0.98941;3.26;0.32;11.8;6
```

# 其工作原理...

数据由 1,599 种红葡萄酒和 4,898 种白葡萄酒组成，具有 11 个特征和一个可用于训练的输出标签。

以下是特征/属性的列表：

+   固定酸度

+   挥发性酸度

+   柠檬酸

+   残余糖分

+   氯化物

+   游离二氧化硫

+   总二氧化硫

+   密度

+   pH

+   硫酸盐

+   酒精

以下是输出标签：

+   质量（介于 0 到 10 之间的数值）

# 还有更多...

以下链接列出了流行的机器学习算法的数据集。根据需要可以选择新数据集进行实验。

其他数据集可在[`en.wikipedia.org/wiki/List_of_datasets_for_machine_learning_research`](https://en.wikipedia.org/wiki/List_of_datasets_for_machine_learning_research)获取。

我们选择了鸢尾花数据集，以便我们可以使用连续数值特征进行线性回归模型。

# 实时回归的流式线性回归

在本配方中，我们将使用 UCI 的葡萄酒质量数据集和 MLlib 的 Spark 流式线性回归算法来基于一组葡萄酒特征预测葡萄酒质量。

此配方与之前看到的传统回归配方之间的区别在于使用 Spark ML 流式传输来实时使用线性回归模型评估葡萄酒质量。

# 如何操作...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

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

1.  创建 Spark 的配置和流式上下文：

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

1.  日志消息的交错导致难以阅读的输出，因此将日志级别设置为警告：

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

1.  将 DataFrame 转换为`rdd`，并将唯一标识符`zip`到其上：

```scala
val rdd = rawDF.rdd.zipWithUniqueId()
```

1.  构建查找映射以稍后比较预测质量与实际质量值：

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

1.  创建 Spark 流式队列以接收流式数据：

```scala
val trainingStream = ssc.queueStream(trainQueue)
val testStream = ssc.queueStream(testQueue)
```

1.  配置流式线性回归模型：

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

1.  启动 Spark 流式上下文：

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

1.  现在将测试数据分成两半并追加到队列以进行处理：

```scala
val testGroups = test.randomSplit(*Array*(.50, .50))
 testGroups.foreach(group => {
 testQueue += group
 Thread.sleep(2000)
 })
```

1.  一旦数据被队列流接收，您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-dt-proc-rt-anls/img/e814ddc2-eebd-43f6-a81a-b84a2b60742c.png)

1.  通过停止 Spark 流式上下文来关闭程序：

```scala
ssc.stop()
```

# 其工作原理...

我们首先通过 Databrick 的`spark-csv`库将葡萄酒质量数据集加载到 DataFrame 中。下一步是为我们数据集中的每一行附加一个唯一标识符，以便稍后将预测质量与实际质量匹配。原始数据被转换为带标签的点，以便它可以作为流式线性回归算法的输入。在步骤 9 和 10 中，我们创建了可变队列和 Spark 的`QueueInputDStream`类的实例，用作进入回归算法的通道。

然后我们创建了流式线性回归模型，该模型将预测我们的最终结果——葡萄酒质量。我们通常从原始数据中创建训练和测试数据集，并将它们附加到适当的队列以开始...

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

# 下载 Pima 糖尿病数据用于监督分类

在本教程中，我们从 UCI 机器学习仓库下载并检查了 Pima 糖尿病数据集。稍后我们将使用该数据集与 Spark 的流式逻辑回归算法。

# 如何操作...

你需要以下命令行工具之一`curl`或`wget`来检索指定数据：

1.  你可以通过以下两个命令之一开始下载数据集。第一个命令如下：

```scala
http://archive.ics.uci.edu/ml/machine-learning-databases/pima-indians-diabetes/pima-indians-diabetes.data
```

这是一个你可以使用的替代方案：

```scala
wget http://archive.ics.uci.edu/ml/machine-learning-databases/pima-indians-diabetes/pima-indians-diabetes.data -o pima-indians-diabetes.data
```

1.  现在我们开始通过查看`pima-indians-diabetes.data`中的数据格式来进行数据探索的第一步（从 Mac 或 Linux 终端）：

```scala
head -5 pima-indians-diabetes.data6,148,72,35,0,33.6,0.627,50,11,85,66,29,0,26.6,0.351,31,0 ...
```

# 它是如何工作的...

该数据集有 768 个观测值。每行/记录包含 10 个特征和一个标签值，可用于监督学习模型（即逻辑回归）。标签/类别为`1`表示检测出糖尿病阳性，`0`表示检测结果为阴性。

**特征/属性：**

+   怀孕次数

+   口服葡萄糖耐量试验 2 小时血浆葡萄糖浓度

+   舒张压（mm Hg）

+   三头肌皮肤褶皱厚度（mm）

+   2 小时血清胰岛素（mu U/ml）

+   身体质量指数（体重（kg）/（身高（m）²））

+   糖尿病遗传函数

+   年龄（岁）

+   类别变量（0 或 1）

```scala
    Label/Class:
               1 - tested positive
               0 - tested negative
```

# 还有更多...

我们发现普林斯顿大学提供的以下替代数据集非常有帮助：

[`data.princeton.edu/wws509/datasets`](http://data.princeton.edu/wws509/datasets)

# 另请参见

您可以用来探索此配方的数据集必须以这样的方式结构化：标签（预测类别）必须是二元的（检测为糖尿病阳性/阴性）。

# 流式逻辑回归用于在线分类器

在本配方中，我们将使用之前配方中下载的 Pima 糖尿病数据集和 Spark 的流式逻辑回归算法与 SGD 来预测具有各种特征的 Pima 是否会检测为糖尿病阳性。它是一个在线分类器，根据流数据进行学习和预测。

# 如何做到这一点...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

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

1.  日志消息的交错导致难以阅读的输出，因此将日志级别设置为警告：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)
```

1.  将 Pima 数据文件加载到字符串类型的数据集中：

```scala
val rawDS = spark.read
.text("../data/sparkml2/chapter13/pima-indians- diabetes.data").as[String]
```

1.  通过生成一个元组，将最后一个项目作为标签，其余所有内容作为序列，从我们的原始数据集构建 RDD：

```scala
val buffer = rawDS.rdd.map(value => {
val data = value.split(",")
(data.init.toSeq, data.last)
})
```

1.  将预处理的数据转换为标签点，以便与机器学习库一起使用：

```scala
val lps = buffer.map{ case (feature: Seq[String], label: String) =>
val featureVector = feature.map(_.toDouble).toArray[Double]
LabeledPoint(label.toDouble, Vectors.dense(featureVector))
}

```

1.  为追加数据创建可变队列：

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

1.  将数据追加到训练数据队列以进行处理：

```scala
trainQueue += trainData
 Thread.sleep(4000)
```

1.  现在将测试数据对半拆分并追加到队列以进行处理：

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

首先，我们将 Pima 糖尿病数据集加载到数据集中，并将其解析为元组，除了最后一个元素外，我们将每个元素作为特征，最后一个元素作为标签。其次，我们将元组 RDD 转换为标记点，以便它可以作为流式逻辑回归算法的输入。第三，我们创建了可变队列和 Spark 的`QueueInputDStream`类的实例，用作逻辑算法的通道。

第四，我们创建了流式逻辑回归模型，该模型将预测我们的最终结果的葡萄酒质量。最后，我们通常从原始数据创建训练和测试数据集，并将其追加到适当的队列以触发模型处理流数据。最终...

# 还有更多...

`StreamingLogisticRegressionWithSGD()`的文档可在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.classification.StreamingLogisticRegressionWithSGD`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.classification.StreamingLogisticRegressionWithSGD)查阅

# 另请参阅

模型的超参数：

+   `setInitialWeights()`

+   `setNumIterations()`

+   `setStepSize()`

+   `setMiniBatchFraction()`
