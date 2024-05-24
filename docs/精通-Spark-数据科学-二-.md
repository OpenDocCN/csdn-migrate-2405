# 精通 Spark 数据科学（二）

> 原文：[`zh.annas-archive.org/md5/6A8ACC3697FE0BCDA4D2C7EE588C4E25`](https://zh.annas-archive.org/md5/6A8ACC3697FE0BCDA4D2C7EE588C4E25)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：地理分析的 Spark

地理处理是 Spark 的一个强大用例，因此本章的目的是解释数据科学家如何使用 Spark 处理地理数据，以产生强大的基于地图的大型数据集视图。我们将演示如何通过 Spark 与 GeoMesa 集成轻松处理时空数据集，这有助于将 Spark 转变为一个复杂的地理处理引擎。随着**物联网**（**IoT**）和其他位置感知数据变得越来越普遍，以及*移动对象*数据量的增加，Spark 将成为一个重要的工具，弥合空间功能和处理可伸缩性之间的地理处理差距。本章揭示了如何通过全球新闻进行高级地缘政治分析，以利用数据分析和进行石油价格数据科学。

在本章中，我们将涵盖以下主题：

+   使用 Spark 摄取和预处理地理定位数据

+   存储适当索引的地理数据，使用 GeoMesa 内部的 Geohash 索引

+   运行复杂的时空查询，跨时间和空间过滤数据

+   使用 Spark 和 GeoMesa 一起执行高级地理处理，以研究随时间的变化

+   使用 Spark 计算密度地图，并可视化这些地图随时间的变化

+   查询和整合跨地图层的空间数据以建立新的见解

# GDELT 和石油

本章的前提是我们可以操纵 GDELT 数据，以更大或更小的程度确定石油价格基于历史事件。我们的预测准确性将取决于许多变量，包括我们事件的细节，使用的数量以及我们关于石油和这些事件之间关系性质的假设。

石油行业非常复杂，受到许多因素的驱动。然而，研究发现，大多数主要的石油价格波动主要是由原油需求的变化所解释的。价格在股票需求增加时也会上涨，并且在中东地区的地缘政治紧张时期价格历史上也很高。特别是政治事件对石油价格有很大影响，我们将集中讨论这一方面。

世界各地有许多国家生产原油；然而，有三个主要的基准价格，供应商用于定价：

+   布伦特：由北海的各种实体生产

+   WTI：**西德克萨斯中质原油**（**WTI**）覆盖北美中西部和墨西哥湾沿岸地区的实体

+   欧佩克：由欧佩克成员国生产：

阿尔及利亚，安哥拉，厄瓜多尔，加蓬，印度尼西亚，伊朗，伊拉克，科威特，利比亚，尼日利亚，卡塔尔，沙特阿拉伯，阿联酋和委内瑞拉

很明显，我们需要做的第一件事是获取三个基准的历史定价数据。通过搜索互联网，可以在许多地方找到可下载的数据，例如：

+   布伦特：[`fred.stlouisfed.org/`](https://fred.stlouisfed.org/series/DCOILBRENTEU)

+   WTI：[`fred.stlouisfed.org/`](https://fred.stlouisfed.org/series/DCOILBRENTEU)

+   欧佩克：[`opec.org`](http://opec.org)

现在我们知道，石油价格主要由供需决定，我们的第一个假设是供需受世界事件的影响更大，因此我们可以预测供需可能是什么。

我们想要确定原油价格在接下来的一天、一周或一个月内是上涨还是下跌，由于我们在整本书中都使用了 GDELT，我们将利用这些知识来运行一些非常大的处理任务。在开始之前，值得讨论我们将采取的路径以及决定的原因。首要关注的是 GDELT 与石油的关系；这将定义最初工作的范围，并为我们以后的工作奠定基础。在这里很重要的是我们决定如何利用 GDELT 以及这个决定的后果；例如，我们可以决定使用所有时间的所有数据，但是所需的处理时间确实非常大，因为仅一天的 GDELT 事件数据平均为 15 MB，GKG 为 1.5 GB。因此，我们应该分析这两组数据的内容，并尝试确定我们的初始数据输入将是什么。

## GDELT 事件

通过查看 GDELT 模式，有一些可能有用的要点；事件模式主要围绕着识别故事中的两个主要参与者并将事件与他们联系起来。还可以查看不同级别的事件，因此我们将有很好的灵活性，可以根据我们的结果在更高或更低的复杂性水平上工作。例如：

`EventCode`字段是一个 CAMEO 动作代码：0251（呼吁放宽行政制裁），也可以在 02（呼吁）和 025（呼吁让步）级别使用。

因此，我们的第二个假设是，事件的详细程度将从我们的算法中提供更好或更差的准确性。

其他有趣的标签包括`GoldsteinScale`、`NumMentions`和`Lat`/`Lon`。`GoldsteinScale`标签是一个从-10 到+10 的数字，它试图捕捉该类型事件对一个国家稳定性的理论潜在影响；这与我们已经确定的关于石油价格稳定性的情况非常匹配。`NumMentions`标签给出了事件在所有来源文件中出现的频率的指示；如果我们发现需要减少我们处理的事件数量，这可能有助于我们为事件分配重要性。例如，我们可以处理数据并找出在过去一小时、一天或一周中出现频率最高的 10、100 或 1000 个事件。最后，`lat`/`lon`标签信息试图为事件分配地理参考点，这在我们想要在 GeoMesa 中制作地图时非常有用。

## GDELT GKG

GKG 模式与总结事件内容和提供特定于该内容的增强信息有关。我们感兴趣的领域包括`Counts`、`Themes`、`GCAM`和`Locations`；`Counts`字段映射任何数字提及，因此可能允许我们计算严重性，例如 KILLS=47。`Themes`字段列出了基于 GDELT 类别列表的所有主题；这可能有助于我们随着时间的推移学习影响石油价格的特定领域。`GCAM`字段是对事件内容的内容分析的结果；快速浏览 GCAM 列表，我们发现有一些可能有用的维度需要注意：

```scala
c9.366  9   366   WORDCOUNT   eng   Roget's Thesaurus 1911 Edition   CLASS III - RELATED TO MATTER/3.2 INORGANIC MATTER/3.2.3 IMPERFECT FLUIDS/366 OIL

c18.172  18   172     WORDCOUNT   eng   GDELT   GKG   Themes   ENV_OIL
c18.314  18   314     WORDCOUNT   eng   GDELT   GKG   Themes   ECON_OILPRICE
```

最后，我们有`Locations`字段，它提供了与事件类似的信息，因此也可以用于制作地图的可视化。

# 制定行动计划

在检查了 GDELT 模式之后，我们现在需要做一些决定，确定我们将使用哪些数据，并确保我们根据我们的假设来证明这种用法。这是一个关键阶段，因为有许多方面需要考虑，至少我们需要：

+   确保我们的假设清晰，这样我们就有一个已知的起点

+   确保我们清楚地了解如何实施假设，并确定一个行动计划

+   确保我们使用足够的适当数据来满足我们的行动计划；限定数据使用范围，以确保我们能够在给定的时间范围内得出结论，例如，使用所有 GDELT 数据将是很好的，但除非有一个大型处理集群可用，否则可能不太合理。另一方面，仅使用一天显然不足以评估任何时间段内的任何模式

+   制定 B 计划，以防我们的初始结果不具有决定性

我们的第二个假设是关于事件的细节；为了清晰起见，在本章中，我们将首先选择一个数据源，以便在模型表现不佳时添加更多复杂性。因此，我们可以选择 GDELT 事件作为上述提到的字段，这些字段为我们的算法提供了一个很好的基础；特别是`gcam`字段将非常有用于确定事件的性质，而`NumMentions`字段在考虑事件的重要性时将很快实施。虽然 GKG 数据看起来也很有用，但我们希望在这个阶段尝试使用一般事件；因此，例如 GCAM 油数据被认为太具体，因为这些领域的文章很可能经常涉及对油价变化的反应，因此对于我们的模型来说考虑太晚了。

我们的初始处理流程（行动计划）将涉及以下步骤：

+   获取过去 5 年的油价数据

+   获取过去 5 年的 GDELT 事件

+   安装 GeoMesa 和相关工具

+   将 GDELT 数据加载到 GeoMesa

+   构建一个可视化，显示世界地图上的一些事件

+   使用适当的机器学习算法来学习事件类型与油价的涨跌

+   使用模型预测油价的涨跌

# GeoMesa

GeoMesa 是一个开源产品，旨在利用存储系统的分布式特性，如 Accumulo 和 Cassandra，来保存分布式时空数据库。有了这个设计，GeoMesa 能够运行大规模的地理空间分析，这对于非常大的数据集，包括 GDELT，是必需的。

我们将使用 GeoMesa 来存储 GDELT 数据，并在其中的大部分数据上运行我们的分析；这应该为我们提供足够的数据来训练我们的模型，以便我们可以预测未来油价的涨跌。此外，GeoMesa 还将使我们能够在地图上绘制大量点，以便我们可以可视化 GDELT 和其他有用的数据。

## 安装

GeoMesa 网站（[www.geomesa.org](http://www.geomesa.org)）上有一个非常好的教程，指导用户完成安装过程。因此，我们在这里并不打算制作另一个操作指南；然而，有几点值得注意，可能会节省您在启动一切时的时间。

+   GeoMesa 有很多组件，其中许多组件有很多版本。确保软件堆栈的所有版本与 GeoMesa maven POMs 中指定的版本完全匹配非常重要。特别感兴趣的是 Hadoop、Zookeeper 和 Accumulo；版本位置可以在 GeoMesa 教程和其他相关下载的根`pom.xml`文件中找到。

+   在撰写本文时，将 GeoMesa 与某些 Hadoop 供应商堆栈集成时存在一些额外问题。如果可能的话，使用 GeoMesa 与您自己的 Hadoop/Accumulo 等堆栈，以确保版本兼容性。

+   GeoMesa 版本依赖标签已从版本 1.3.0 更改。确保所有版本与您选择的 GeoMesa 版本完全匹配非常重要；如果有任何冲突的类，那么在某个时候肯定会出现问题。

+   如果您以前没有使用过 Accumulo，我们在本书的其他章节中已经详细讨论过它。初步熟悉将在使用 GeoMesa 时大有裨益（参见第七章，“建立社区”）。

+   在使用 Accumulo 1.6 或更高版本与 GeoMesa 时，有使用 Accumulo 命名空间的选项。如果您对此不熟悉，则选择不使用命名空间，并将 GeoMesa 运行时 JAR 简单地复制到 Accumulo 根文件夹中的`/lib/text`中。

+   GeoMesa 使用一些 shell 脚本；由于操作系统的性质，运行这些脚本可能会出现一些问题，这取决于您的平台。这些问题很小，可以通过一些快速的互联网搜索来解决；例如，在运行`jai-image.sh`时，在 Mac OSX 上会出现用户确认的小问题。

+   GeoMesa 的 maven 仓库可以在[`repo.locationtech.org/content/repositories/releases/org/locationtech/geomesa/`](https://repo.locationtech.org/content/repositories/releases/org/locationtech/geomesa/)找到

一旦您能够成功地从命令行运行 GeoMesa，我们就可以继续下一节了。

## GDELT 摄入

下一阶段是获取 GDELT 数据并将其加载到 GeoMesa 中。这里有许多选择，取决于您打算如何进行；如果您只是在阅读本章，那么可以使用脚本一次性下载数据：

```scala
$ mkdir gdelt && cd gdelt
$ wget http://data.gdeltproject.org/events/md5sums
$ for file in `cat md5sums | cut -d' ' -f3 | grep '²⁰¹[56]'` ; do wget http://data.gdeltproject.org/events/$file ; done
$ md5sum -c md5sums 2>&1 | grep '²⁰¹[56]'
```

这将下载并验证 2015 年和 2016 年的所有 GDELT 事件数据。在这个阶段，我们需要估计所需的数据量，因为我们不知道我们的算法将如何运行，所以我们选择了两年的数据来开始。

脚本的替代方法是阅读第二章，*数据获取*，其中详细解释了如何配置 Apache NiFi 以实时下载 GDELT 数据，并将其加载到 HDFS 以供使用。否则，可以使用脚本将前述数据传输到 HDFS，如下所示：

```scala
$ ls -1 *.zip | xargs -n 1 unzip
$ rm *.zip
$ hdfs dfs -copyFromLocal *.CSV hdfs:///data/gdelt/
```

### 注意

HDFS 使用数据块；我们希望确保文件存储尽可能高效。编写一个方法来将文件聚合到 HDFS 块大小（默认为 64 MB）将确保 NameNode 内存不会被许多小文件的条目填满，并且还将使处理更加高效。使用多个块（文件大小> 64 MB）的大文件称为分割文件。

我们在 HDFS 中有大量的数据（大约为 2015/16 年的 48 GB）。现在，我们将通过 GeoMesa 将其加载到 Accumulo 中。

## GeoMesa 摄入

GeoMesa 教程讨论了使用`MapReduce`作业从 HDFS 加载数据到 Accumulo 的想法。让我们来看看这个，并创建一个 Spark 等价物。

### MapReduce 到 Spark

由于**MapReduce**（**MR**）通常被认为已经死亡，或者至少正在消亡，因此了解如何从 MR 中创建 Spark 作业非常有用。以下方法可以应用于任何 MR 作业。我们将考虑 GeoMesa 教程中描述的 GeoMesa Accumulo 加载作业（`geomesa-examples-gdelt`）。

MR 作业通常由三部分组成：mapper、reducer 和 driver。GeoMesa 示例是一个仅包含 mapper 的作业，因此不需要 reducer。该作业接收 GDELT 输入行，从空的`Text`对象和创建的 GeoMesa `SimpleFeature`创建一个（Key,Value）对，并使用`GeoMesaOutputFormat`将数据加载到 Accumulo。MR 作业的完整代码可以在我们的仓库中找到；接下来，我们将逐步介绍关键部分并建议 Spark 所需的更改。

作业是从`main`方法启动的；前几行与从命令行解析所需选项有关，例如 Accumulo 用户名和密码。然后我们到达：

```scala
SimpleFeatureType featureType =
    buildGDELTFeatureType(featureName);
DataStore ds = DataStoreFinder.getDataStore(dsConf);
ds.createSchema(featureType);
runMapReduceJob(featureName, dsConf,
    new Path(cmd.getOptionValue(INGEST_FILE)));
```

GeoMesa `SimpleFeatureType`是用于在 GeoMesa 数据存储中存储数据的主要机制，需要初始化一次，以及数据存储初始化。完成这些后，我们执行 MR 作业本身。在 Spark 中，我们可以像以前一样通过命令行传递参数，然后进行一次性设置：

```scala
spark-submit --class io.gzet.geomesa.ingest /
             --master yarn /
             geomesa-ingest.jar <accumulo-instance-id>
...
```

jar 文件的内容包含了一个标准的 Spark 作业：

```scala
val conf = new SparkConf()
val sc = new SparkContext(conf.setAppName("Geomesa Ingest"))
```

像以前一样解析命令行参数，并执行初始化：

```scala
val featureType = buildGDELTFeatureType(featureName)
val ds = DataStoreFinder
   .getDataStore(dsConf)
   .createSchema(featureType)
```

现在我们可以从 HDFS 加载数据，如果需要可以使用通配符。这将为文件的每个块（默认为 64 MB）创建一个分区，从而产生一个`RDD[String]`：

```scala
val distDataRDD = sc.textFile(/data/gdelt/*.CSV)
```

或者我们可以根据可用资源来固定分区的数量：

```scala
val distDataRDD = sc.textFile(/data/gdelt/*.CSV, 20) 
```

然后我们可以执行 map，其中我们可以嵌入函数来替换原始 MR`map`方法中的过程。我们创建一个元组（Text，SimpleFeatureType）来复制一个（Key，Value）对，以便我们可以在下一步中使用`OutputFormat`。当以这种方式创建 Scala 元组时，生成的 RDD 会获得额外的方法，比如`ReduceByKey`，它在功能上等同于 MR Reducer（有关我们真正应该使用的`mapPartitions`的更多信息，请参见下文）：

```scala
val processedRDD = distDataRDD.map(s =>{
   // Processing as before to build the SimpleFeatureType
   (new Text, simpleFeatureType)
})
```

然后，我们最终可以使用原始作业中的`GeomesaOutputFormat`输出到 Accumulo：

```scala
processedRDD.saveAsNewAPIHadoopFile("output/path", classOf[Text], classOf[SimpleFeatureType], classOf[GeomesaOutputFormat])
```

在这个阶段，我们还没有提到 MR 作业中的`setup`方法；这个方法在处理任何输入之前被调用，用来分配一个昂贵的资源，比如数据库连接，或者在我们的情况下，一个可重用的对象，然后使用`cleanup`方法来释放资源，如果它在作用域外持续存在的话。在我们的情况下，`setup`方法用来创建一个`SimpleFeatureBuilder`，它可以在每次调用 mapper 时重复使用来构建输出的`SimpleFeatures`；没有`cleanup`方法，因为当对象超出作用域时，内存会自动释放（代码已经完成）。

Spark 的`map`函数一次只对一个输入进行操作，并且没有办法在转换一批值之前或之后执行代码。在调用`map`之前和之后放置设置和清理代码似乎是合理的。

```scala
// do setup work 
val processedRDD = distDataRDD.map(s =>{ 
   // Processing as before to build the SimpleFeatureType 
   (new Text, simpleFeatureType) 
}) 
// do cleanup work 

```

但是，这失败的原因有几个：

+   它将`map`中使用的任何对象放入 map 函数的闭包中，这要求它是可序列化的（例如，通过实现`java.io.Serializable`）。并非所有对象都是可序列化的，因此可能会抛出异常。

+   `map`函数是一个转换，而不是一个操作，它是惰性评估的。因此，在`map`函数之后的指令不能保证立即执行。

+   即使前面的问题针对特定的实现进行了处理，我们只会在驱动程序上执行代码，而不一定会释放由序列化副本分配的资源。

Spark 中最接近 mapper 的方法是`mapPartitions`方法。这个方法不仅仅是将一个值映射到另一个值，而是将一个值的迭代器映射到另一个值的迭代器，类似于批量映射方法。这意味着`mapPartitions`可以在开始时在本地分配资源：

```scala
val processedRDD = distDataRDD.mapPartitions { valueIterator =>
   // setup code for SimpleFeatureBuilder
   val transformed = valueIterator.map( . . . )
   transformed
}
```

然而，释放资源（`cleanup`）并不简单，因为我们仍然遇到了惰性评估的问题；如果资源在`map`之后被释放，那么在这些资源消失之前，迭代器可能还没有被评估。解决这个问题的一个方法如下：

```scala
val processedRDD = distDataRDD.mapPartitions { valueIterator =>
  if (valueIterator.isEmpty) {
    // return an Iterator
  } else {
    //  setup code for SimpleFeatureBuilder
    valueIterator.map { s =>
// Processing as before to build the SimpleFeatureType
      val simpleFeature =
      if (!valueIterator.hasNext) {
       // cleanup here
      }
      simpleFeature
    }
  }
}
```

现在我们有了用于摄取的 Spark 代码，我们可以进行额外的更改，即添加一个`Geohash`字段（有关如何生成此字段的更多信息，请参见以下内容）。要将此字段插入代码，我们需要在 GDELT 属性列表的末尾添加一个额外的条目：

```scala
Geohash:String 

```

并设置`simpleFeature`类型的值的一行：

```scala
simpleFeature.setAttribute(Geomesa, calculatedGeoHash)
```

最后，我们可以运行我们的 Spark 作业，从 HDFS 加载 GDELT 数据到 GeoMesa Accumulo 实例。GDELT 的两年数据大约有 1 亿条目！您可以通过使用 Accumulo shell 来检查 Accumulo 中有多少数据，从`accumulo/bin`目录运行：

```scala
./accumulo shell -u username -p password -e "scan -t gdelt_records -np" | wc
```

## 地理哈希

地理哈希是由 Gustavo Niemeyer 发明的地理编码系统。它是一种分层的空间数据结构，将空间细分为网格形状的桶，这是所谓的 Z 顺序曲线和一般空间填充曲线的许多应用之一。

地理哈希提供了诸如任意精度和逐渐删除代码末尾的字符以减小其大小（逐渐失去精度）等属性。

由于逐渐精度下降的结果，附近的地理位置通常（但并非总是）会呈现相似的前缀。共享前缀越长，两个位置越接近；这在 GeoMesa 中非常有用，因为我们可以使用前面摄入代码中添加的`Geohash`字段，如果我们想要使用特定区域的点。

Geohashes 的主要用途是：

+   作为唯一标识符

+   例如，在数据库中表示点数据

在数据库中使用时，地理哈希数据的结构具有两个优点。首先，通过 Geohash 索引的数据将在给定矩形区域的所有点在连续的切片中（切片数量取决于所需的精度和 Geohash *故障线*的存在）。这在数据库系统中特别有用，因为单个索引上的查询比多个索引查询更容易或更快：例如，Accumulo。其次，这种索引结构可以用于快速的近似搜索：最接近的点通常是最接近的 Geohashes。这些优势使 Geohashes 非常适合在 GeoMesa 中使用。以下是 David Allsopp 出色的 Geohash scala 实现的代码摘录[`github.com/davidallsopp/geohash-scala`](https://github.com/davidallsopp/geohash-scala)。此代码可用于基于`lat`/`lon`输入生成 Geohashes：

```scala
/** Geohash encoding/decoding as per http://en.wikipedia.org/wiki/Geohash */
object Geohash {

  val LAT_RANGE = (-90.0, 90.0)
  val LON_RANGE = (-180.0, 180.0)

  // Aliases, utility functions
  type Bounds = (Double, Double)
  private def mid(b: Bounds) = (b._1 + b._2) / 2.0
  implicit class BoundedNum(x: Double) { def in(b: Bounds): Boolean = x >= b._1 && x <= b._2 }

  /**
   * Encode lat/long as a base32 geohash.
   *
   * Precision (optional) is the number of base32 chars desired; default is 12, which gives precision well under a meter.
   */
  def encode(lat: Double, lon: Double, precision: Int=12): String = { // scalastyle:ignore
    require(lat in LAT_RANGE, "Latitude out of range")
    require(lon in LON_RANGE, "Longitude out of range")
    require(precision > 0, "Precision must be a positive integer")
    val rem = precision % 2 // if precision is odd, we need an extra bit so the total bits divide by 5
    val numbits = (precision * 5) / 2
    val latBits = findBits(lat, LAT_RANGE, numbits)
    val lonBits = findBits(lon, LON_RANGE, numbits + rem)
    val bits = intercalatelonBits, latBits)
    bits.grouped(5).map(toBase32).mkString // scalastyle:ignore
  }

  private def findBits(part: Double, bounds: Bounds, p: Int): List[Boolean] = {
    if (p == 0) Nil
    else {
      val avg = mid(bounds)
      if (part >= avg) true :: findBits(part, (avg, bounds._2), p - 1)
// >= to match geohash.org encoding
      else false :: findBits(part, (bounds._1, avg), p - 1)
    }
  }

  /**
   * Decode a base32 geohash into a tuple of (lat, lon)
   */
  def decode(hash: String): (Double, Double) = {
    require(isValid(hash), "Not a valid Base32 number")
    val (odd, even) =toBits(hash).foldRight((List[A](), List[A]())) { case (b, (a1, a2)) => (b :: a2, a1) }
    val lon = mid(decodeBits(LON_RANGE, odd))
    val lat = mid(decodeBits(LAT_RANGE, even))
    (lat, lon)
  }

  private def decodeBits(bounds: Bounds, bits: Seq[Boolean]) =
    bits.foldLeft(bounds)((acc, bit) => if (bit) (mid(acc), acc._2) else (acc._1, mid(acc)))
}

def intercalateA: List[A] = a match {
 case h :: t => h :: intercalate(b, t)
 case _ => b
}
```

Geohash 算法的一个局限性在于试图利用它来找到具有共同前缀的相邻点。接近的边缘情况位置，它们彼此靠近，但位于 180 度子午线的对立面，将导致没有共同前缀的 Geohash 代码（接近物理位置的不同经度）。在北极和南极附近的点将具有非常不同的 Geohashes（接近物理位置的不同经度）。

此外，赤道（或格林威治子午线）两侧的两个接近位置将不会有长的公共前缀，因为它们属于世界的不同半球；一个位置的二进制纬度（或经度）将是 011111...，另一个位置将是 100000...，因此它们不会有共同的前缀，大多数位将被翻转。

为了进行近似搜索，我们可以计算一个边界框的西南角（低纬度和经度的低 Geohash）和东北角（高纬度和经度的高 Geohash），并搜索这两者之间的 Geohashes。这将检索两个角之间 Z 顺序曲线上的所有点；这在 180 子午线和极点处也会中断。

最后，由于 Geohash（在此实现中）是基于经度和纬度坐标的，两个 Geohashes 之间的距离反映了两点之间纬度/经度坐标的距离，这并不等同于实际距离。在这种情况下，我们可以使用**Haversine**公式：

![Geohash](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_05_03.jpg)

这给我们提供了考虑到地球曲率的两点之间的实际距离，其中：

+   **r**是球体的半径，

+   **φ1**，**φ2**：点 1 的纬度和点 2 的纬度，以弧度表示

+   **λ1**，**λ2**：点 1 的经度和点 2 的经度，以弧度表示

## GeoServer

现在我们已经成功通过 GeoMesa 将 GDELT 数据加载到 Accumulo 中，我们可以开始在地图上可视化这些数据；例如，这个功能对于在世界地图上绘制分析结果非常有用。GeoMesa 与 GeoServer 很好地集成在一起。GeoServer 是一个符合**开放地理空间联盟**（**OGC**）标准的实现，包括**Web 要素服务**（**WFS**）和**Web 地图服务**（**WMS**）。"它可以发布来自任何主要空间数据源的数据"。

我们将使用 GeoServer 以清晰、可呈现的方式查看我们分析结果。同样，我们不会深入研究如何启动和运行 GeoServer，因为 GeoMesa 文档中有一个非常好的教程，可以实现两者的集成。需要注意的一些常见点如下：

+   系统使用**Java 高级图像**（**JAI**）库；如果您在 Mac 上遇到问题，通常可以通过从默认 Java 安装中删除库来解决这些问题：

```scala
        rm /System/Library/Java/Extensions/jai_*.
```

然后可以使用 GeoServer 版本，位于`$GEOSERVER_HOME/webapps/geoserver/WEB-INF/lib/`

+   再次强调版本的重要性。您必须非常清楚您正在使用的主要模块的版本，例如 Hadoop，Accumulo，Zookeeper，最重要的是 GeoMesa。如果混合使用不同版本，您将遇到问题，而堆栈跟踪通常会掩盖真正的问题。如果确实遇到异常，请检查并反复检查您的版本。

### 地图图层

一旦 GeoServer 运行，我们就可以创建一个用于可视化的图层。GeoServer 使我们能够发布单个或一组图层以生成图形。创建图层时，我们可以指定边界框，查看要素（这是我们之前在 Spark 代码中创建的`SimpleFeature`），甚至运行**通用查询语言**（**CQL**）查询来过滤数据（后面将更多介绍）。创建图层后，选择图层预览和 JPG 选项将生成一个类似以下的图形的 URL；这里的时间边界是 2016 年 1 月，以便地图不会过于拥挤：

![地图图层](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_05_002.jpg)

URL 可以用于通过操作参数生成其他图形。以下是 URL 的简要分解：

具有标准的`geoserver`URL：

```scala
http://localhost:8080/geoserver/geomesa/wms?

```

“请求”类型：

```scala
service=WMS&version=1.1.0&request=GetMap& 

```

“图层”和“样式”：

```scala
layers=geomesa:event&styles=& 

```

如果需要，设置图层的“透明度”：

```scala
transparency=true& 

```

在这种情况下，`cql`语句是任何具有`GoldsteinScale>8`条目的行：

```scala
cql_filter=GoldsteinScale>8& 

```

边界框`bbox`：

```scala
bbox=-180.0,-90.0,180.0,90.0& 

```

图形的“高度”和“宽度”：

```scala
width=768&height=384& 

```

源和“图像”类型：

```scala
srs=EPSG:4326&format=image%2Fjpeg& 

```

通过时间查询边界过滤内容：

```scala
time=2016-01-01T00:00:00.000Z/2016-01-30T23:00:00.000Z 

```

本节的最后一步是将世界地图附加到此图层，以使图像更易读。如果您在互联网上搜索世界地图形状文件，会有许多选项；我们使用了[`thematicmapping.org`](http://thematicmapping.org)上的一个选项。将其中一个添加到 GeoServer 作为形状文件存储，然后创建和发布一个图层，再创建我们的 GDELT 数据和形状文件的图层组，将产生类似于以下图像的图像：

![地图图层](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_05_003.jpg)

为了使事情更有趣，我们根据`FeatureType`中的`GoldsteinScale`字段过滤了事件。通过在 URL 中添加`cql_filter=GoldsteinScale > 8`，我们可以绘制所有`GoldsteinScale`分数大于八的点；因此，上面的图像向我们展示了 2016 年 1 月世界上积极情绪水平最高的地方在哪里！

### CQL

**通用查询语言**（**CQL**）是由 OGC 为[目录 Web 服务规范](http://www.opengeospatial.org/standards/cat)创建的一种纯文本查询语言。它是一种人类可读的查询语言（不像，例如，[OGC 过滤器](http://www.opengeospatial.org/standards/filter)），并且使用与 SQL 类似的语法。尽管与 SQL 类似，但 CQL 的功能要少得多；例如，它在要求属性在任何比较运算符的左侧时非常严格。

以下列出了 CQL 支持的运算符：

+   比较运算符：=，<>，>，>=，<，<=

+   ID、列表和其他运算符：BETWEEN，BEFORE，AFTER，LIKE，IS，EXISTS，NOT，IN

+   算术表达式运算符：+，-，*，/

+   几何运算符：EQUALS，DISJOINT，INTERSECTS，TOUCHES，CROSSES，WITHIN，CONTAINS，OVERLAPS，RELATE，DWITHIN，BEYOND

由于 CQL 的限制，GeoServer 提供了一个名为 ECQL 的 CQL 扩展版本。ECQL 提供了 CQL 的许多缺失功能，提供了一种更灵活的语言，与 SQL 更相似。GeoServer 支持在 WMS 和 WFS 请求中使用 CQL 和 ECQL。

测试 CQL 查询的最快方法是修改图层的 URL，例如我们上面创建的图层，例如使用 JPG，或者在 GeoMesa 的图层选项底部使用 CQL 框。

如果我们在一个 WMS 请求中定义了几个图层，比如：

```scala
http://localhost:8080/geoserver/wms?service=WMS&version=1.1.0&request=GetMap&layers=layer1,layer2,layer3   ...   

```

然后我们可能想要使用 CQL 查询过滤其中一个图层。在这种情况下，CQL 过滤器必须按照图层的顺序进行排序；我们使用`INCLUDE`关键字来表示我们不想过滤的图层，并使用“;”进行分隔。例如，在我们的示例中，要仅过滤`layer2`，WMS 请求将如下所示：

```scala
http://localhost:8080/geoserver/wms?service=WMS&version=1.1.0&request=GetMap&layers=layer1,layer2,layer3&cql_filter=INCLUDE;(LAYER2_COL='value');INCLUDE...   

```

### 注意

在使用`Date`类型的列时要注意；我们需要确定它们的格式，然后再尝试使用 CQL。通常它们将采用 ISO8601 格式；2012-01-01T00:00:00Z。然而，根据数据加载的方式，可能会出现不同的格式。在我们的示例中，我们已确保 SQLDATE 的格式是正确的。

# 测量油价

现在我们的数据存储中有大量数据（我们可以始终使用前面的 Spark 作业添加更多数据），我们将继续查询这些数据，使用 GeoMesa API，准备好行以应用于我们的学习算法。当然，我们可以使用原始 GDELT 文件，但以下方法是一个有用的工具。

## 使用 GeoMesa 查询 API

GeoMesa 查询 API 使我们能够基于时空属性查询结果，同时利用数据存储的并行化，本例中是 Accumulo 和其迭代器。我们可以使用 API 构建`SimpleFeatureCollections`，然后解析以实现 GeoMesa`SimpleFeatures`，最终匹配我们查询的原始数据。

在这个阶段，我们应该构建通用的代码，这样我们可以很容易地改变它，如果我们决定以后没有使用足够的数据，或者也许如果我们需要改变输出字段。最初，我们将提取一些字段；`SQLDATE`，`Actor1Name`，`Actor2Name`和`EventCode`。我们还应该决定我们查询的边界框；因为我们正在查看三种不同的石油指数，所以我们需要决定事件的地理影响如何与石油价格本身相关。这是最难评估的变量之一，因为在价格确定中涉及了很多因素；可以说边界框是整个世界。然而，由于我们使用了三个指数，我们将假设每个指数都有自己的地理限制，这是基于有关石油供应地区和需求地区的研究。如果我们有更多相关信息，或者结果不理想并且需要重新评估，我们随时可以稍后改变这些边界。建议的初始边界框是：

+   布伦特：北海和英国（供应）和中欧（需求）：34.515610，-21.445313 - 69.744748，36.914063

+   WTI：美国（供应）和西欧（需求）：-58.130121，-162.070313，71.381635，-30.585938

+   欧佩克：中东（供应）和欧洲（需求）：-38.350273，-20.390625，38.195022，149.414063

从 GeoMesa 提取结果的代码如下（布伦特原油）：

```scala
object CountByWeek {

   // specify the params for the datastore
   val params = Map(
     "instanceId" -> "accumulo",
     "zookeepers" -> "127.0.0.1:2181",
     "user"       -> "root",
     "password"   -> "accumulo",
     "tableName"  -> "gdelt")

   // matches the params in the datastore loading code
   val typeName      = "event"
   val geom          = "geom"
   val date          = "SQLDATE"
   val actor1        = "Actor1Name"
   val actor2        = "Actor2Name"
   val eventCode     = "EventCode"
   val numArticles   = "NumArticles"

   // specify the geographical bounding
   val bbox   = "34.515610, -21.445313, 69.744748, 36.914063"

  // specify the temporal bounding
  val during = "2016-01-01T00:00:00.000Z/2016-12-30T00:00:00.000Z"

  // create the filter
  val filter = s"bbox($geom, $bbox) AND $date during $during"

  def main(args: Array[String]) {
    // Get a handle to the data store
    val ds = DataStoreFinder
       .getDataStore(params)
       .asInstanceOf[AccumuloDataStore]

    // Construct a CQL query to filter by bounding box
    val q = new Query(typeName, ECQL.toFilter(filter))

    // Configure Spark
    val sc = new SparkContext(GeoMesaSpark.init(
       new SparkConf(true), ds))

     // Create an RDD from the query
     val simpleFeaureRDD = GeoMesaSpark.rdd(new Configuration,
       sc, params, q)

     // Convert RDD[SimpleFeature] to RDD[Row] for DataFrame creation below
     val gdeltAttrRDD = simpleFeaureRDD.mapPartitions { iter =>
       val df = new SimpleDateFormat("yyyy-MM-dd")
       val ff = CommonFactoryFinder.getFilterFactory2
       val dt = ff.property(date)
       val a1n = ff.property(actor1)
       val a2n = ff.property(actor2)
       val ec = ff.property(eventCode)
       val na = ff.property(numArticles)
       iter.map { f =>
         Row(
           df.format(dt.evaluate(f).asInstanceOf[java.util.Date]),
           a1n.evaluate(f),
           a2n.evaluate(f),
           ec.evaluate(f),
           na.evaluate(f)
         )
       }
     }
   }
}
```

`RDD[Row]`集合可以按以下方式写入磁盘以供将来使用：

```scala
gdeltAttrRDD.saveAsTextFile("/data/gdelt/brent-2016-rdd-row)
```

### 注意

我们应该在这一点上尽可能多地读取数据，以便为我们的算法提供大量的训练数据。我们将在以后的阶段将我们的输入数据分为训练和测试数据。因此，没有必要保留任何数据。

## 数据准备

在这个阶段，我们已经根据边界框和日期范围从 GeoMesa 获取了我们的数据，用于特定的石油指数。输出已经被组织起来，以便我们有一系列行，每一行包含一个事件的所谓重要细节。我们不确定我们为每个事件选择的字段是否完全相关，能够提供足够的信息来构建可靠的模型，因此，根据我们的结果，这是我们可能需要在以后进行实验的事情。接下来，我们需要将数据转换为可以被我们的学习过程使用的形式。在这种情况下，我们将数据聚合成为一周的数据块，并将数据转换为典型的“词袋”，首先从上一步加载数据开始：

```scala
val gdeltAttrRDD = sc.textFile("/data/gdelt/brent-2016-rdd-row)
```

在这个 RDD 中，我们有`EventCodes`（CAMEO 代码）：这些将需要转换为它们各自的描述，以便构建词袋。通过从[`gdeltproject.org/data/lookups/CAMEO.eventcodes.txt`](http://gdeltproject.org/data/lookups/CAMEO.eventcodes.txt)下载 CAMEO 代码，我们可以为下一步创建一个`Map`对象：

```scala
var cameoMap = scala.collection.mutable.Map[String, String]()

val linesRDD = sc.textFile("file://CAMEO.eventcodes.txt")
linesRDD.collect.foreach(line => {
  val splitsArr = line.split("\t")
  cameoMap += (splitsArr(0) -> splitsArr(1).
replaceAll("[^A-Za-z0-9 ]", ""))
})
```

请注意，我们通过删除任何非标准字符来规范化输出；这样做的目的是尝试避免错误字符影响我们的训练模型。

现在我们可以通过在`EventCode`映射描述的两侧附加演员代码来创建我们的`bagOfWordsRDD`，并从日期和形成的句子创建一个 DataFrame：

```scala
val bagOfWordsRDD = gdeltAttrRDD.map(f => Row(
   f.get(0),
   f.get(1).toString.replaceAll("\\s","").
     toLowerCase + " " + cameoMap(f.get(3).toString).
     toLowerCase + " " + f.get(2).toString.replaceAll("\\s","").
     toLowerCase)
 )

 val gdeltSentenceStruct = StructType(Array(
   StructField("Date", StringType, true),
   StructField("sentence", StringType, true)
 ))

 val gdeltSentenceDF 
 spark.createDataFrame(bagOfWordsRDD,gdeltSentenceStruct)
 gdeltSentenceDF.show(false)

+----------+-----------------------------------------------------+
|Date      |sentence                                             |
+----------+-----------------------------------------------------+
|2016-01-02|president demand not specified below unitedstates    |
|2016-01-02|vladimirputin engage in negotiation beijing          |
|2016-01-02|northcarolina make pessimistic comment neighborhood  |
+----------+-----------------------------------------------------+
```

我们之前提到过，我们可以在每日、每周甚至每年的水平上处理我们的数据；通过选择每周，我们接下来需要按周对我们的 DataFrame 进行分组。在 Spark 2.0 中，我们可以使用窗口函数轻松实现这一点：

```scala
val windowAgg = gdeltSentenceDF.
    groupBy(window(gdeltSentenceDF.col("Date"),
      "7 days", "7 days", "1 day"))
val sentencesDF = windowAgg.agg(
    collect_list("sentence") as "sentenceArray")
```

由于我们将为每周末生成石油价格数据，因此我们应确保我们的句子数据在周五到周四之间分组，以便稍后可以将其与该周五的价格数据进行连接。这是通过更改`window`函数的第四个参数来实现的；在这种情况下，一天提供了正确的分组。如果我们运行命令`sentencesDF.printSchema`，我们将看到`sentenceArray`列是一个字符串数组，而我们需要的是学习算法的输入的一个字符串。下一个代码片段演示了这种变化，以及生成`commonFriday`列，它为我们每一行工作的日期提供了一个参考，以及一个我们稍后可以连接的唯一键：

```scala
val convertWrappedArrayToStringUDF = udf {(array: WrappedArray[String]) =>
  array.mkString(" ")
 }

val dateConvertUDF = udf {(date: String) =>
  new SimpleDateFormat("yyyy-MM-dd").
    format(new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").
      parse(date))
  }

val aggSentenceDF = sentencesDF.withColumn("text",
 convertWrappedArrayToStringUDF(
   sentencesDF("sentenceArray"))).
      withColumn("commonFriday", dateConvertUDF(sentencesDF("window.end")))

aggSentenceDF.show

+--------------------+-----------------+--------------+-------------+
|              window|    sentenceArray|          text| commonFriday|
+--------------------+-----------------+--------------+-------------+
|[2016-09-09 00:00...|[unitedstates app|unitedstates a|   2016-09-16|
|[2016-06-24 00:00...|[student make emp|student make e|   2016-07-01|
|[2016-03-04 00:00...|[american provide|american provi|   2016-03-11|
+--------------------+-----------------+--------------+-------------+
```

下一步是收集我们的数据并为下一阶段的使用进行标记。为了对其进行标记，我们必须对下载的油价数据进行归一化处理。在本章的前面部分，我们提到了数据点的频率；目前数据包含日期和当天结束时的价格。我们需要将我们的数据转换为元组（日期，变化），其中日期是该周五的日期，变化是基于从上周一开始的每日价格的平均值的上升或下降；如果价格保持不变，我们将把这视为下降，以便稍后可以实现二进制值学习算法。

我们可以再次使用 Spark DataFrames 中的窗口功能轻松地按周对数据进行分组；我们还将重新格式化日期，以便窗口组函数正确执行：

```scala
// define a function to reformat the date field
def convert(date:String) : String = {
  val dt = new SimpleDateFormat("dd/MM/yyyy").parse(date)
  new SimpleDateFormat("yyyy-MM-dd").format(dt)
}

val oilPriceDF = spark
  .read
  .option("header","true")
  .option("inferSchema", "true")
  .csv("oil-prices.csv")

// create a User Defined Function for the date changes
val convertDateUDF = udf {(Date: String) => convert(Date)}

val oilPriceDatedDF = oilPriceDF.withColumn("DATE", convertDateUDF(oilPriceDF("DATE")))

// offset to start at beginning of week, 4 days in this case
val windowDF = oilPriceDatedDF.groupBy(window(oilPriceDatedDF.col("DATE"),"7 days", "7 days", "4 days"))

// find the last value in each window, this is the trading close price for that week
val windowLastDF = windowDF.agg(last("PRICE") as "last(PRICE)"
).sort("window")

windowLastDF.show(20, false)
```

这将产生类似于这样的东西：

```scala
+---------------------------------------------+-----------+
|window                                       |last(PRICE)|
+---------------------------------------------+-----------+
|[2011-11-21 00:00:00.0,2011-11-28 00:00:00.0]|106.08     |
|[2011-11-28 00:00:00.0,2011-12-05 00:00:00.0]|109.59     |
|[2011-12-05 00:00:00.0,2011-12-12 00:00:00.0]|107.91     |
|[2011-12-12 00:00:00.0,2011-12-19 00:00:00.0]|104.0      |
+---------------------------------------------+-----------+
```

现在我们可以计算上周的涨跌幅；首先通过将上周的`last(PRICE)`添加到每一行（使用 Spark 的`lag`函数），然后计算结果：

```scala
val sortedWindow = Window.orderBy("window.start")

// add the previous last value to each row
val lagLastCol = lag(col("last(PRICE)"), 1).over(sortedWindow)
val lagLastColDF = windowLastDF.withColumn("lastPrev(PRICE)", lagLastCol)

// create a UDF to calculate the price rise or fall
val simplePriceChangeFunc = udf{(last : Double, prevLast : Double) =>
  var change = ((last - prevLast) compare 0).signum
  if(change == -1)
    change = 0
  change.toDouble
}

// create a UDF to calculate the date of the Friday for that week
val findDateTwoDaysAgoUDF = udf{(date: String) =>
  val dateFormat = new SimpleDateFormat( "yyyy-MM-dd" )
  val cal = Calendar.getInstance
  cal.setTime( dateFormat.parse(date))
  cal.add( Calendar.DATE, -3 )
  dateFormat.format(cal.getTime)
}

val oilPriceChangeDF = lagLastColDF.withColumn("label", simplePriceChangeFunc(
  lagLastColDF("last(PRICE)"),
  lagLastColDF("lastPrev(PRICE)")
)).withColumn("commonFriday", findDateTwoDaysAgoUDF(lagLastColDF("window.end"))

oilPriceChangeDF.show(20, false)

+--------------------+-----------+---------------+-----+------------+
|              window|last(PRICE)|lastPrev(PRICE)|label|commonFriday|
+--------------------+-----------+---------------+-----+------------+
|[2015-12-28 00:00...|       36.4|           null| null|  2016-01-01|
|[2016-01-04 00:00...|      31.67|           36.4|  0.0|  2016-01-08|
|[2016-01-11 00:00...|       28.8|          31.67|  0.0|  2016-01-15|
+--------------------+-----------+---------------+-----+------------+
```

您会注意到使用了`signum`函数；这对于比较非常有用，因为它产生以下结果：

+   如果第一个值小于第二个值，则输出-1

+   如果第一个值大于第二个值，则输出+1

+   如果两个值相等，则输出 0

现在我们有了两个 DataFrame，`aggSentenceDF`和`oilPriceChangeDF`，我们可以使用`commonFriday`列将这两个数据集连接起来，以产生一个带标签的数据集：

```scala
val changeJoinDF = aggSentenceDF
 .drop("window")
 .drop("sentenceArray")
 .join(oilPriceChangeDF, Seq("commonFriday"))
 .withColumn("id", monotonicallyIncreasingId)
```

我们还删除窗口和`sentenceArray`列，并添加一个 ID 列，以便我们可以唯一引用每一行：

```scala
changeJoinDF,show
+------------+---------+---------+-----------+---------+-----+------+
|commonFriday|     text|   window|last(PRICE)| lastPrev|label|    id|
+------------+---------+---------+-----------+---------+-----+------+
|  2016-09-16|unitedsta|[2016-09-|      45.26|    48.37|  0.0|   121|
|  2016-07-01|student m|[2016-06-|      47.65|    46.69|  1.0|   783|
|  2016-03-11|american |[2016-03-|      39.41|    37.61|  1.0|   356|
+------------+---------+---------+-----------+---------+-----+------+
```

## 机器学习

现在我们有了输入数据和每周的价格变动；接下来，我们将把我们的 GeoMesa 数据转换成机器学习模型可以处理的数值向量。Spark 机器学习库 MLlib 有一个叫做`HashingTF`的实用程序来做到这一点。`HashingTF`通过对每个术语应用哈希函数，将词袋转换为术语频率向量。因为向量有有限数量的元素，可能会出现两个术语映射到相同的哈希术语；哈希化的向量特征可能不完全代表输入文本的实际内容。因此，我们将设置一个相对较大的特征向量，容纳 10,000 个不同的哈希值，以减少这些碰撞的机会。这背后的逻辑是，可能事件只有那么多（不管它们的大小），因此先前看到的事件的重复应该产生类似的结果。当然，事件的组合可能会改变这一点，这是通过最初采取一周的时间块来考虑的。为了正确格式化输入数据以供`HashingTF`使用，我们还将在输入文本上执行一个`Tokenizer`：

```scala
val tokenizer = new Tokenizer().
   setInputCol("text").
   setOutputCol("words")
 val hashingTF = new HashingTF().
   setNumFeatures(10000).
   setInputCol(tokenizer.getOutputCol).
   setOutputCol("rawFeatures")
```

最后的准备步骤是实现**逆文档频率**（**IDF**），这是每个术语提供多少信息的数值度量：

```scala
val idf = new IDF().
  setInputCol(hashingTF.getOutputCol).
  setOutputCol("features")
```

为了这个练习的目的，我们将实现一个朴素贝叶斯实现来执行我们功能的机器学习部分。这个算法是一个很好的初始拟合，可以从一系列输入中学习结果；在我们的情况下，我们希望学习在给定上周一系列事件的情况下，油价的增加或减少。

## 朴素贝叶斯

朴素贝叶斯是一种简单的构建分类器的技术：模型将类标签分配给问题实例，表示为特征值向量，其中类标签来自某个有限集合。朴素贝叶斯在 Spark MLlib 中可用，因此：

```scala
val nb = new NaiveBayes() 

```

我们可以使用 MLlib Pipeline 将所有上述步骤绑在一起；Pipeline 可以被认为是一个简化多个算法组合的工作流程。从 Spark 文档中，一些定义如下：

+   DataFrame：这个 ML API 使用来自 Spark SQL 的 DataFrame 作为 ML 数据集，可以容纳各种数据类型。例如，一个 DataFrame 可以有不同的列存储文本、特征向量、真实标签和预测。

+   转换器：转换器是一种可以将一个 DataFrame 转换为另一个 DataFrame 的算法。例如，一个 ML 模型是一个将带有特征的 DataFrame 转换为带有预测的 DataFrame 的转换器。

+   估计器：估计器是一种可以“拟合”DataFrame 以产生转换器的算法。例如，学习算法是一个可以在 DataFrame 上进行训练并产生模型的估计器。

+   Pipeline：Pipeline 将多个转换器和估计器链接在一起，以指定一个 ML 工作流程。

`pipeline`被声明如下：

```scala
val pipeline = new Pipeline().
  setStages(Array(tokenizer, hashingTF, idf, nb))
```

我们之前注意到，所有可用的数据都应该从 GeoMesa 中读取，因为我们将在后期分割数据，以提供训练和测试数据集。这是在这里执行的：

```scala
val splitDS = changeJoinDF.randomSplit(Array(0.75,0.25))
val (trainingDF,testDF) = (splitDS(0),splitDS(1))
```

最后，我们可以执行完整的模型：

```scala
val model = pipeline.fit(trainingDF)
```

模型可以轻松保存和加载：

```scala
model.save("/data/models/gdelt-naivebayes-2016") 
val naivebayesModel = PipelineModel.load("/data/models/Gdelt-naivebayes-2016") 

```

## 结果

为了测试我们的模型，我们应该执行`model`转换器，如下所述：

```scala
model
  .transform(testDF)
  .select("id", "prediction", "label").
  .collect()
  .foreach {
    case Row(id: Long, pred: Double, label: Double) =>
       println(s"$id --> prediction=$pred --> should be: $label")
  }
```

这为每个输入行提供了一个预测：

```scala
8847632629761 --> prediction=1.0 --> should be: 1.0
1065151889408 --> prediction=0.0 --> should be: 0.0
1451698946048 --> prediction=1.0 --> should be: 1.0
```

结果，从结果 DataFrame 中取出（`model.transform(testDF).select("rawPrediction", "probability", "prediction").show`），如下所示：

```scala
+--------------------+--------------------+----------+
|       rawPrediction|         probability|prediction|
+--------------------+--------------------+----------+
|[-6487.5367247911...|[2.26431216092671...|       1.0|
|[-8366.2851849035...|[2.42791395068146...|       1.0|
|[-4309.9770937765...|[3.18816589322004...|       1.0|
+--------------------+--------------------+----------+
```

## 分析

在像石油价格预测这样的问题领域中，要创建一个真正成功的算法总是非常困难/几乎不可能的，因此本章始终是更多地向演示性质靠拢。然而，我们有了结果，它们的合法性并不无关紧要；我们用石油指数和 GDELT 的几年数据训练了上述算法，然后从模型执行的结果中获取了结果，再将其与正确的标签进行比较。

在测试中，先前的模型显示了 51%的准确性。这比我们从简单地随机选择结果所期望的稍微好一点，但为改进提供了坚实的基础。通过保存数据集和模型的能力，在努力提高准确性的过程中，对模型进行更改将是直截了当的。

有许多可以改进的地方，我们在本章已经提到了其中一些。为了改进我们的模型，我们应该以系统化的方式解决特定领域的问题。由于我们只能就哪些改变会带来改进做出合理猜测，因此重要的是首先尝试解决最关键的问题领域。接下来，我们简要总结一下我们可能如何处理这些改变。我们应该经常检查我们的假设，确定它们是否仍然有效，或者需要做出哪些改变。

假设 1：“石油的供需受世界事件的影响更大，因此我们可以预测供需可能会是什么样。”我们初步尝试建立的模型显示了 51%的准确性；虽然这还不足以确定这个假设是否有效，但在放弃这个假设之前，继续改进模型的其他方面是值得的。

假设 2：“事件的详细程度将从我们的算法中提供更好或更差的准确性。”在这里，我们有很大的改变空间；有几个领域我们可以修改代码并快速重新运行模型，例如：

+   事件数量：增加是否会影响准确性？

+   每日/每周/每月的数据汇总：每周汇总可能永远不会产生良好的结果

+   有限的数据集：我们目前只使用了 GDELT 的少数字段，增加更多字段是否有助于提高准确性？

+   排除其他类型的数据：引入 GKG 数据是否有助于提高准确性？

总之，我们可能比开始时有更多的问题；然而，我们现在已经做好了基础工作，建立了一个初步模型，希望能够提高准确性，并进一步了解数据及其对石油价格的潜在影响。

# 总结

在本章中，我们介绍了将数据以时空方式存储的概念，以便我们可以使用 GeoMesa 和 GeoServer 来创建和运行查询。我们展示了这些查询在这些工具本身以及以编程方式执行的情况，利用 GeoServer 来显示结果。此外，我们还演示了如何合并不同的工件，纯粹从原始的 GDELT 事件中创建见解，而不需要任何后续处理。在 GeoMesa 之后，我们涉及了高度复杂的石油定价世界，并致力于一个简单的算法来估计每周的石油变化。虽然在现有的时间和资源下创建一个准确的模型是不合理的，但我们已经探讨了许多关注领域，并试图至少在高层次上解决这些问题，以便提供可能在这个问题领域中可以采取的方法的见解。

在本章中，我们介绍了一些关键的 Spark 库和函数，其中关键的领域是 MLlib，我们将在本书的其余部分中更详细地了解它。

在下一章，第六章，“抓取基于链接的外部数据”，我们进一步实施 GDELT 数据集，构建一个用于跟踪趋势的网络规模新闻扫描器。


# 第六章：抓取基于链接的外部数据

本章旨在解释一种增强本地数据的常见模式，该模式使用从 URL 或 API 获取的外部内容。例如，当从 GDELT 或 Twitter 接收到 URL 时。我们为读者提供了一个使用 GDELT 新闻索引服务作为新闻 URL 来源的教程，演示如何构建一个从互联网上抓取感兴趣的全球突发新闻的网络规模新闻扫描器。我们解释了如何构建这个专门的网络抓取组件，以克服规模的挑战。在许多用例中，访问原始 HTML 内容是不足以提供对新兴全球事件的更深入洞察的。专业的数据科学家必须能够从原始文本内容中提取实体，以帮助构建跟踪更广泛趋势所需的上下文。

在本章中，我们将涵盖以下主题：

+   使用*Goose*库创建可扩展的网络内容获取器

+   利用 Spark 框架进行自然语言处理（NLP）

+   使用双重音标算法去重名字

+   利用 GeoNames 数据集进行地理坐标查找

# 构建一个网络规模的新闻扫描器

数据科学与统计学的不同之处在于强调可扩展处理以克服围绕收集数据的质量和多样性的复杂问题。而统计学家处理干净数据集的样本，可能来自关系数据库，数据科学家相反，处理来自各种来源的大规模非结构化数据。前者专注于构建具有高精度和准确性的模型，而后者通常专注于构建丰富的集成数据集，提供发现不那么严格定义的见解。数据科学之旅通常涉及折磨初始数据源，连接理论上不应该连接的数据集，丰富内容与公开可用信息，实验，探索，发现，尝试，失败，再次尝试。无论技术或数学技能如何，普通数据科学家与专业数据科学家之间的主要区别在于在提取数据中的潜在价值时所使用的好奇心和创造力的水平。例如，你可以构建一个简单的模型，并为业务团队提供他们要求的最低要求，或者你可以注意并利用数据中提到的所有这些 URL，然后抓取这些内容，并使用这些扩展结果来发现超出业务团队最初问题的新见解。

## 访问网络内容

除非你在 2016 年初非常努力地工作，否则你一定听说过歌手*大卫·鲍伊*于 2016 年 1 月 10 日去世，享年 69 岁。这一消息被所有媒体发布商广泛报道，在社交网络上传播，并得到了世界各地最伟大艺术家的致敬。这可悲地成为了本书内容的一个完美用例，并且是本章的一个很好的例证。我们将使用 BBC 的以下文章作为本节的参考：

![访问网络内容](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_06_001.jpg)

图 1：关于大卫·鲍伊的 BBC 文章，来源：http://www.bbc.co.uk/news/entertainment-arts-35278872

查看这篇文章背后的 HTML 源代码，首先要注意的是大部分内容都不包含任何有价值的信息。这包括标题、页脚、导航面板、侧边栏和所有隐藏的 JavaScript 代码。虽然我们只对标题、一些参考（如发布日期）感兴趣，最多只对文章本身的几十行感兴趣，但分析页面将需要解析超过 1500 行的 HTML 代码。虽然我们可以找到许多用于解析 HTML 文件内容的库，但创建一个足够通用的解析器，可以处理来自随机文章的未知 HTML 结构，可能会成为一个真正的挑战。

### Goose 图书馆

我们将这个逻辑委托给优秀的 Scala 库**Goose**（[`github.com/GravityLabs/goose`](https://github.com/GravityLabs/goose)）。该库打开一个 URL 连接，下载 HTML 内容，清理掉所有的垃圾，使用一些英文停用词的聚类对不同的段落进行评分，最后返回剥离了任何底层 HTML 代码的纯文本内容。通过正确安装*imagemagick*，该库甚至可以检测给定网站的最具代表性的图片（这里不在讨论范围内）。`goose`依赖项可在 Maven 中央库中找到：

```scala
<dependency>
  <groupId>com.gravity</groupId>
  <artifactId>goose</artifactId>
  <version>2.1.23</version>
</dependency>
```

与 Goose API 交互就像使用库本身一样愉快。我们创建一个新的 Goose 配置，禁用图像获取，修改一些可选设置，如用户代理和超时选项，并创建一个新的`Goose`对象：

```scala
def getGooseScraper(): Goose = {
  val conf: Configuration = new Configuration
  conf.setEnableImageFetching(false)
  conf.setBrowserUserAgent(userAgent)
  conf.setConnectionTimeout(connectionTimeout)
  conf.setSocketTimeout(socketTimeout)
  new Goose(conf)
}

val url = "http://www.bbc.co.uk/news/entertainment-arts-35278872"
val goose: Goose = getGooseScraper()
val article: Article = goose.extractContent(url)
```

调用`extractContent`方法返回一个具有以下值的 Article 类：

```scala
val cleanedBody: String = article.cleanedArticleText
val title: String = article.title
val description: String = article.metaDescription
val keywords: String = article.metaKeywords
val domain: String = article.domain
val date: Date = article.publishDate
val tags: Set[String] = article.tags

/*
Body: Singer David Bowie, one of the most influential musicians...
Title: David Bowie dies of cancer aged 69
Description: Tributes are paid to David Bowie...
Domain: www.bbc.co.uk
*/
```

使用这样一个库，打开连接并解析 HTML 内容不会花费我们超过十几行的代码，这种技术可以应用于任意来源或 HTML 结构的文章 URL 列表。最终的输出是一个干净解析的数据集，一致，并且在下游分析中非常有用。

## 与 Spark 集成

下一个逻辑步骤是集成这样一个库，并在可扩展的 Spark 应用程序中提供其 API。一旦集成，我们将解释如何有效地从大量 URL 中检索远程内容，以及如何在 Spark 转换中使用不可序列化的类，并且以高性能的方式。

### Scala 兼容性

Maven 上的 Goose 库已经编译为 Scala 2.9，因此与 Spark 分发不兼容（Spark 2.0+需要 Scala 2.11）。为了使用它，我们不得不为 Scala 2.11 重新编译 Goose 分发，并为了您的方便，我们将其放在了我们的主 GitHub 存储库中。可以使用以下命令快速安装：

```scala
$ git clone git@bitbucket.org:gzet_io/goose.git
$ cd goose && mvn clean install
```

请注意，您将需要修改您的项目`pom.xml`文件以使用这个新的依赖项。

```scala
<dependency>
  <groupId>com.gravity</groupId>
  <artifactId>goose_2.11</artifactId>
  <version>2.1.30</version>
</dependency>
```

### 序列化问题

任何与第三方依赖项一起工作的 Spark 开发人员至少应该遇到过`NotSerializableException`。尽管在一个有很多转换的大型项目中找到确切的根本原因可能是具有挑战性的，但原因是非常简单的。Spark 试图在将它们发送到适当的执行器之前序列化所有的转换。由于`Goose`类不可序列化，并且由于我们在闭包外部构建了一个实例，这段代码是`NotSerializableException`的一个完美例子。

```scala
val goose = getGooseScraper()
def fetchArticles(urlRdd: RDD[String]): RDD[Article] = {
  urlRdd.map(goose.extractContent)
}
```

我们通过在`map`转换中创建一个`Goose`类的实例来简单地克服了这个限制。通过这样做，我们避免了传递任何我们可能创建的非可序列化对象的引用。Spark 将能够将代码*原样*发送到每个执行器，而无需序列化任何引用的对象。

```scala
def fechArticles(urlRdd: RDD[String]): RDD[Article] = {
  urlRdd map { url =>
    val goose = getGooseScraper()
    goose.extractContent(url)
  }
}
```

## 创建一个可扩展的、生产就绪的库

改进简单应用程序的性能在单个服务器上运行有时并不容易；但在并行处理大量数据的分布式应用程序上进行这样的改进通常更加困难，因为有许多其他因素会影响性能。接下来，我们将展示我们用来调整内容获取库的原则，以便它可以在任何规模的集群上自信地运行而不会出现问题。

### 构建一次，多次读取

值得一提的是，在前面的示例中，为每个 URL 创建了一个新的 Goose 实例，这使得我们的代码在大规模运行时特别低效。举个简单的例子来说明这一点，创建一个`Goose`类的新实例可能需要大约 30 毫秒。在我们数百万条记录中的每一条上都这样做将需要在一个 10 节点集群上花费 1 小时，更不用说垃圾回收性能将受到显著影响。使用`mapPartitions`转换可以显著改善这个过程。这个闭包将被发送到 Spark 执行器（就像`map`转换一样），但这种模式允许我们在每个执行器上创建一个单独的 Goose 实例，并为每个执行器的记录调用其`extractContent`方法。

```scala
def fetchArticles(urlRdd: RDD[String]): RDD[Article] = {
  urlRdd mapPartitions { urls =>
    val goose = getGooseScraper()
    urls map goose.extractContent
  }
}
```

### 异常处理

异常处理是正确软件工程的基石。这在分布式计算中尤其如此，因为我们可能与大量直接不受我们控制的外部资源和服务进行交互。例如，如果我们没有正确处理异常，那么在获取外部网站内容时发生的任何错误都会使 Spark 在抛出最终异常并中止作业之前多次重新安排整个任务在其他节点上。在生产级别的、无人值守的网络爬虫操作中，这种问题可能会危及整个服务。我们当然不希望因为一个简单的 404 错误而中止整个网络爬虫内容处理过程。

为了加强我们的代码对这些潜在问题的防范，任何异常都应该被正确捕获，并且我们应该确保所有返回的对象都应该一致地被设置为可选的，对于所有失败的 URL 来说都是未定义的。在这方面，关于 Goose 库唯一不好的一点是其返回值的不一致性：标题和日期可能返回 null，而缺少描述和正文的情况下会返回空字符串。在 Java/Scala 中返回 null 是一个非常糟糕的做法，因为它通常会导致`NullPointerException`，尽管大多数开发人员通常会在旁边写上"This should not happen"的注释。在 Scala 中，建议返回一个选项而不是 null。在我们的示例代码中，我们从远程内容中获取的任何字段都应该以可选的方式返回，因为它可能在原始源页面上不存在。此外，当我们获取数据时，我们还应该处理其他方面的一致性，例如我们可以将日期转换为字符串，因为在调用操作（如**collect**）时可能会导致序列化问题。因为这些原因，我们应该按照以下方式重新设计我们的`mapPartitions`转换。

+   我们测试每个对象的存在并返回可选结果

+   我们将文章内容封装到一个可序列化的`Content`类中

+   我们捕获任何异常并返回一个具有未定义值的默认对象

修改后的代码如下所示：

```scala
case class Content(
     url: String,
     title: Option[String],
     description: Option[String],
     body: Option[String],
     publishDate: Option[String]
)

def fetchArticles(urlRdd: RDD[String]): RDD[Content] = {

  urlRdd mapPartitions { urls =>

    val sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")
    val goose = getGooseScraper()

    urls map { url =>

      try {

        val article = goose.extractContent(url)
        var body = None: Option[String]
        var title = None: Option[String]
        var description = None: Option[String]
        var publishDate = None: Option[String]

        if (StringUtils.isNotEmpty(article.cleanedArticleText))
          body = Some(article.cleanedArticleText)

        if (StringUtils.isNotEmpty(article.title))
          title = Some(article.title)

        if (StringUtils.isNotEmpty(article.metaDescription))
          description = Some(article.metaDescription)

        if (article.publishDate != null)
          publishDate = Some(sdf.format(article.publishDate))

        Content(url, title, description, body, publishDate)

      } catch {
        case e: Throwable => Content(url, None, None, None, None)
      }
    }
  }

}
```

### 性能调优

尽管大多数情况下，Spark 应用程序的性能可以通过对代码本身的更改大大改善（我们已经看到了使用`mapPartitions`而不是`map`函数来实现完全相同目的的概念），但您可能还需要找到总执行器数量、每个执行器的核心数量以及分配给每个容器的内存之间的正确平衡。

在进行这种第二种类型的应用程序调优时，首先要问自己的问题是，您的应用程序是 I/O 绑定（大量读/写访问）、网络绑定（节点之间大量传输）、内存绑定还是 CPU 绑定（您的任务通常需要太长时间才能完成）。

很容易发现我们的网络爬虫应用程序中的主要瓶颈。创建一个`Goose`实例大约需要 30 毫秒，获取给定 URL 的 HTML 大约需要 3 秒才能完成。基本上，我们花费了 99%的时间等待内容块被检索，主要是因为互联网连接和网站的可用性。克服这个问题的唯一方法是大幅增加我们 Spark 作业中使用的执行者数量。请注意，由于执行者通常位于不同的节点上（假设正确的 Hadoop 设置），更高的并行度不会在带宽方面受到网络限制（就像在单个节点上使用多个线程时肯定会发生的那样）。

此外，关键要注意的是，在这个过程的任何阶段都没有涉及减少操作（没有洗牌），因为这个应用是一个仅映射的作业，因此天然具有线性可扩展性。从逻辑上讲，两倍的执行者将使我们的爬虫性能提高两倍。为了反映这些设置在我们的应用程序上，我们需要确保我们的数据集被均匀地分区，至少有与我们定义的执行者数量一样多的分区。如果我们的数据集只能适应一个分区，那么我们的许多执行者中只有一个会被使用，使我们的新 Spark 设置既不足够又高度低效。重新分区我们的集合是一个一次性的操作（尽管是一个昂贵的操作），假设我们正确地缓存和实现我们的 RDD。我们在这里使用了`200`的并行性：

```scala
val urlRdd = getDistinctUrls(gdeltRdd).repartition(200)
urlRdd.cache()
urlRdd.count()

val contentRdd: RDD[Content] = fetchArticles(urlRdd)
contentRdd.persist(StorageLevel.DISK_ONLY)
contentRdd.count()
```

最后要记住的一件事是彻底缓存返回的 RDD，因为这样可以消除所有懒惰定义的转换（包括 HTML 内容获取）可能在我们调用任何进一步的操作时重新评估的风险。为了保险起见，因为我们绝对不想两次从互联网获取 HTML 内容，我们强制这种缓存明确地发生，通过将返回的数据集持久化到`DISK_ONLY`。

# 命名实体识别

构建一个网络爬虫，用外部基于网页的 HTML 内容丰富包含 URL 的输入数据集，在大数据摄入服务中具有很大的商业价值。但是，虽然普通的数据科学家应该能够使用一些基本的聚类和分类技术来研究返回的内容，但专业的数据科学家将把这个数据丰富过程提升到下一个级别，通过进一步丰富和增加价值来进行后续处理。通常，这些增值的后续处理包括消除外部文本内容的歧义，提取实体（如人物、地点和日期），以及将原始文本转换为最简单的语法形式。我们将在本节中解释如何利用 Spark 框架来创建一个可靠的自然语言处理（NLP）管道，其中包括这些有价值的后处理输出，并且可以处理任何规模的英语内容。

## Scala 库

ScalaNLP（http://www.scalanlp.org/）是 breeze（等等）的父项目，并且是在 Spark MLlib 中广泛使用的数值计算框架。如果它没有在不同版本的 breeze 和 epic 之间引起这么多依赖问题，这个库本来是 Spark 上 NLP 的完美候选者。为了克服这些核心依赖不匹配，我们要么重新编译整个 Spark 分发版，要么重新编译整个 ScalaNLP 堆栈，这两者都不是易事。因此，我们更倾向于使用来自计算语言理解实验室的一套自然语言处理器（https://github.com/clulab/processors）。它是用 Scala 2.11 编写的，提供了三种不同的 API：斯坦福 CoreNLP 处理器、快速处理器和用于处理生物医学文本的处理器。在这个库中，我们可以使用`FastNLPProcessor`，它对于基本的命名实体识别功能来说足够准确，并且在 Apache v2 许可下。

```scala
<dependency>
  <groupId>org.clulab</groupId>
  <artifactId>processors-corenlp_2.11</artifactId>
  <version>6.0.1</version>
</dependency>

<dependency>
  <groupId>org.clulab</groupId>
  <artifactId>processors-main_2.11</artifactId>
  <version>6.0.1</version>
</dependency>

<dependency>
  <groupId>org.clulab</groupId>
  <artifactId>processors-models_2.11</artifactId>
  <version>6.0.1</version>
</dependency>
```

## NLP 演练

NLP 处理器注释文档并返回词形的列表（以其最简单的语法形式呈现的单词），命名实体类型的列表，如`[ORGANIZATION]`，`[LOCATION]`，`[PERSON]`，以及标准化实体的列表（如实际日期值）。

### 提取实体

在下面的例子中，我们初始化一个`FastNLPProcessor`对象，注释并标记文档为一个`Sentence`列表，将词形和 NER 类型进行压缩，最后返回每个给定句子的识别实体数组。

```scala
case class Entity(eType: String, eVal: String)

def processSentence(sentence: Sentence): List[Entity] = {
  val entities = sentence.lemmas.get
    .zip(sentence.entities.get)
    .map {
      case (eVal, eType) =>
        Entity(eType, eVal)
    }
}

def extractEntities(processor: Processor, corpus: String) = {
  val doc = processor.annotate(corpus)
  doc.sentences map processSentence
}

val t = "David Bowie was born in London"
val processor: Processor = new FastNLPProcessor()
val sentences = extractEntities(processor, t)

sentences foreach { sentence =>
  sentence foreach println
}

/*
Entity(David,PERSON)
Entity(Bowie,PERSON)
Entity(was,O)
Entity(born,O)
Entity(in,O) 
Entity(London,LOCATION) 
*/
```

从上面的输出中，您可能会注意到所有检索到的实体都没有链接在一起，`David`和`Bowie`都是类型为`[PERSON]`的两个不同实体。我们使用以下方法递归聚合连续相似的实体。

```scala
def aggregate(entities: Array[Entity]) = {
  aggregateEntities(entities.head, entities.tail, List())
}

def aggregateEntity(e1: Entity, e2: Entity) = {
  Entity(e1.eType, e1.eVal + " " + e2.eVal)
}

def aggEntities(current: Entity, entities: Array[Entity], processed : List[Entity]): List[Entity] = {
  if(entities.isEmpty) {
// End of recusion, no additional entity to process
    // Append our last un-processed entity to our list
    current :: processed
  } else {
    val entity = entities.head
    if(entity.eType == current.eType) {
 // Aggregate consecutive values only of a same entity type      val aggEntity = aggregateEntity(current, entity)
*      // Process next record*
      aggEntities(aggEntity, entities.tail, processed)
    } else {
// Add current entity as a candidate for a next aggregation
      // Append our previous un-processed entity to our list      aggEntities(entity, entities.tail, current :: processed)
    }
  }
}

def processSentence(sentence: Sentence): List[Entity] = {
  val entities = sentence.lemmas.get
    .zip(sentence.entities.get)
    .map {
      case (eVal, eType) =>
        Entity(eType, eVal)
    }
  aggregate(entities)
}
```

现在打印相同的内容会给我们一个更一致的输出。

```scala
/*
(PERSON,David Bowie)
(O,was born in)
(LOCATION,London) 
*/
```

### 提示

在函数式编程环境中，尽量限制使用任何可变对象（如使用`var`）。作为一个经验法则，可以通过使用前置递归函数来避免任何可变对象。

### 抽象方法

我们意识到在一组句子（句子本身是一个实体数组）上工作可能听起来很模糊。根据经验，当在大规模运行时，对 RDD 进行简单转换将需要多个`flatMap`函数，这将更加令人困惑。我们将结果封装到一个`Entities`类中，并公开以下方法：

```scala
case class Entities(sentences: Array[List[(String, String)]])
 {

  def getSentences = sentences

  def getEntities(entity: String) = {
    sentences flatMap { sentence =>
      sentence
    } filter { case (entityType, entityValue) =>
      entityType == entity
    } map { case (entityType, entityValue) =>
      entityValue
    } toSeq
  }
```

## 构建可扩展的代码

我们现在已经定义了我们的 NLP 框架，并将大部分复杂逻辑抽象成一组方法和方便的类。下一步是将这段代码集成到 Spark 环境中，并开始大规模处理文本内容。为了编写可扩展的代码，需要特别注意以下几点：

+   在 Spark 作业中使用非可序列化类时，必须在闭包内仔细声明，以避免引发`NotSerializableException`。请参考我们在前一节中讨论的 Goose 库序列化问题。

+   每当我们创建一个`FastNLPProcessor`的新实例（每当我们首次调用其`annotate`方法时，因为它是懒惰定义的），所有所需的模型将从类路径中检索、反序列化并加载到内存中。这个过程大约需要 10 秒钟才能完成。

+   除了实例化过程相当缓慢之外，值得一提的是模型可能非常庞大（大约 1GB），并且将所有这些模型保留在内存中将逐渐消耗我们可用的堆空间。

### 一次构建，多次读取

出于以上所有原因，将我们的代码*原样*嵌入`map`函数中将非常低效（并且可能会耗尽我们所有的可用堆空间）。如下例所示，我们利用`mapPartitions`模式来优化加载和反序列化模型的开销时间，以及减少执行器使用的内存量。使用`mapPartitions`强制处理每个分区的第一条记录以评估引导模型加载和反序列化过程，并且在该执行器上的所有后续调用将重用该分区内的模型，有助于将昂贵的模型传输和初始化成本限制为每个执行器一次。

```scala
def extract(corpusRdd: RDD[String]): RDD[Entities] = {
  corpusRdd mapPartitions {
    case it=>
      val processor = new FastNLPProcessor()
      it map {
        corpus =>
          val entities = extractEntities(processor, corpus)
          new Entities(entities)
      }
    }
  }
```

这个 NLP 可扩展性问题的最终目标是在处理尽可能多的记录时加载尽可能少的模型。对于一个执行器，我们只加载一次模型，但完全失去了并行计算的意义。对于大量的执行器，我们将花费更多的时间反序列化模型，而不是实际处理我们的文本内容。这在性能调优部分有所讨论。

### 可扩展性也是一种思维状态

因为我们在将代码集成到 Spark 之前在本地设计了我们的代码，我们一直记得以最方便的方式编写代码。这很重要，因为可扩展性不仅体现在大数据环境中代码运行的速度上，还体现在人们对其感觉如何，以及开发人员与您的 API 的交互效率如何。作为开发人员，如果你需要链接嵌套的`flatMap`函数来执行本应该是简单转换的操作，那么你的代码根本不具备可扩展性！由于我们的数据结构完全抽象在一个`Entities`类中，从我们的 NLP 提取中派生出不同的 RDD 可以通过一个简单的映射函数完成。

```scala
val entityRdd: RDD[Entities] = extract(corpusRdd)
entityRdd.persist(StorageLevel.DISK_ONLY)
entityRdd.count()

val perRdd = entityRdd.map(_.getEntities("PERSON"))
val locRdd = entityRdd.map(_.getEntities("LOCATION"))
val orgRdd = entityRdd.map(_.getEntities("ORGANIZATION"))
```

### 提示

关键要注意这里使用了`persist`。与之前在 HTML 获取器过程中所做的一样，我们彻底缓存返回的 RDD，以避免在调用任何进一步的操作时重新评估其所有基础转换的情况。NLP 处理是一个非常昂贵的过程，你必须确保它不会被执行两次，因此这里使用了`DISK_ONLY`缓存。

### 性能调优

为了使这个应用程序扩展，你需要问自己同样关键的问题：这个作业是 I/O、内存、CPU 还是网络绑定的？NLP 提取是一个昂贵的任务，加载模型需要大量内存。我们可能需要减少执行器的数量，同时为每个执行器分配更多的内存。为了反映这些设置，我们需要确保我们的数据集将被均匀分区，使用至少与执行器数量相同的分区。我们还需要通过缓存我们的 RDD 并调用一个简单的`count`操作来强制进行这种重新分区，这将评估我们所有先前的转换（包括分区本身）。

```scala
val corpusRdd: RDD[String] = inputRdd.repartition(120)
corpusRdd.cache()
corpusRdd.count()

val entityRdd: RDD[Entities] = extract(corpusRdd)
```

# GIS 查找

在前一节中，我们涵盖了一个有趣的用例，即如何从非结构化数据中提取位置实体。在本节中，我们将通过尝试根据我们能够识别的实体的位置来检索实际的地理坐标信息（如纬度和经度），使我们的丰富过程变得更加智能。给定一个输入字符串`伦敦`，我们能否检测到伦敦-英国的城市以及其相对纬度和经度？我们将讨论如何构建一个高效的地理查找系统，该系统不依赖于任何外部 API，并且可以通过利用 Spark 框架和*Reduce-Side-Join*模式处理任何规模的位置数据。在构建此查找服务时，我们必须牢记世界上许多地方可能共享相同的名称（仅在美国就有大约 50 个名为曼彻斯特的地方），并且输入记录可能不使用所指的地方的官方名称（通常使用的瑞士日内瓦的官方名称是日内瓦）。

## GeoNames 数据集

**GeoNames** ([`www.geonames.org/`](http://www.geonames.org/))是一个涵盖所有国家的地理数据库，包含超过 1000 万个地名和地理坐标，并可免费下载。在这个例子中，我们将使用`AllCountries.zip`数据集（1.5 GB），以及`admin1CodesASCII.txt`参考数据，将我们的位置字符串转换为具有地理坐标的有价值的位置对象。我们将仅保留与大洲、国家、州、地区和城市以及主要海洋、海洋、河流、湖泊和山脉相关的记录，从而将整个数据集减少一半。尽管管理代码数据集很容易放入内存中，但 Geo 名称必须在 RDD 中处理，并且需要转换为以下案例类：

```scala
case class GeoName(
  geoId: Long,
  name: String,
  altNames: Array[String],
  country: Option[String],
  adminCode: Option[String],
  featureClass: Char,
  featureCode: String,
  population: Long,
  timezone: Array[String],
  geoPoint: GeoPoint
)

case class GeoPoint(
  lat: Double,
  lon: Double
)
```

我们将不在这里描述将平面文件解析为`geoNameRDD`的过程。解析器本身非常简单，处理制表符分隔的记录文件，并根据上述案例类定义转换每个值。相反，我们将公开以下静态方法：

```scala
val geoNameRdd: RDD[GeoName] = GeoNameLookup.load(
  sc,
  adminCodesPath,
  allCountriesPath
)
```

## 构建高效的连接

主要的查找策略将依赖于对我们的地理名称和输入数据执行的`join`操作。为了最大限度地提高获取位置匹配的机会，我们将使用`flatMap`函数扩展我们的初始数据，以涵盖所有可能的替代名称，因此将初始大小从 500 万条记录大幅增加到约 2000 万条记录。我们还确保从名称中清除任何可能包含的重音符号、破折号或模糊字符：

```scala
val geoAltNameRdd = geoNameRdd.flatMap {
  geoName =>
    altNames map { altName =>
      (clean(altName), geoName)
    }
} filter { case (altName, geoName) =>
  StringUtils.isNotEmpty(altName.length)
} distinct()

val inputNameRdd = inputRdd.map { name =>
  (clean(name), name)
} filter { case (cleanName, place) =>
  StringUtils.*isNotEmpty*(cleanName.length)
 }
```

最后，剩下的过程是在清理后的输入和清理后的`geoNameRDD`之间进行简单的`join`操作。最后，我们可以将所有匹配的地点分组成一组简单的`GeoName`对象：

```scala
def geoLookup(
  inputNameRdd: RDD[(String, String)],
  geoNameRdd: RDD[(String, GeoName)]
): RDD[(String, Array[GeoName])] = {

  inputNameRdd
    .join(geoNameRdd)
    .map { case (key, (name, geo)) =>
      (name, geo)
    }
    .groupByKey()
    .mapValues(_.toSet)

}
```

这里可以讨论一个有趣的模式。Spark 如何在大型数据集上执行`join`操作？在传统的 MapReduce 中称为*Reduce-Side-Join*模式，它要求框架对来自两个 RDD 的所有键进行哈希，并将具有相同键（相同哈希）的所有元素发送到专用节点，以便在本地`join`它们的值。*Reduce-Side-Join*的原则如下图 2 所示。由于*Reduce-Side-Join*是一项昂贵的任务（受网络限制），我们必须特别注意解决以下两个问题：

+   *GeoNames*数据集比我们的输入 RDD 要大得多。我们将浪费大量精力洗牌数据，而这些数据无论如何都不会匹配，使我们的`join`不仅效率低下，而且主要是无用的。

+   *GeoNames*数据集随时间不会改变。在伪实时系统（如 Spark Streaming）中接收位置事件的批处理中，重新洗牌这个不可变的数据集是没有意义的。

我们可以构建两种不同的策略，一种是离线策略，一种是在线策略。前者将利用*布隆过滤器*大大减少要洗牌的数据量，而后者将按键对我们的 RDD 进行分区，以减少与`join`操作相关的网络成本。

![构建高效的`join`](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_06_002.jpg)

图 2：Reduce-Side-Join

### 离线策略-布隆过滤

**布隆过滤器**是一种空间高效的概率数据结构，用于测试元素是否是有限概率的假阳性成员。在传统的 MapReduce 中被广泛使用，一些实现已经编译为 Scala。我们将使用 breeze 库的布隆过滤器，该库可在 maven 中心获得（与我们之前讨论的 ScalaNLP 模型相比，breeze 本身可以在很大程度上避免依赖不匹配）。

```scala
<dependency>
  <groupId>org.scalanlp</groupId>
  <artifactId>breeze_2.11</artifactId>
  <version>0.12</version>
</dependency>
```

因为我们的输入数据集比`geoNameRDD`要小得多，所以我们将通过利用`mapPartitions`函数对前者训练一个布隆过滤器。每个执行器将构建自己的布隆过滤器，我们可以通过其关联属性将其聚合成一个单一对象，使用`reduce`函数内的位运算符：

```scala
val bfSize = inputRdd.count()
val bf: BloomFilter[String] = inputRdd.mapPartitions { it =>
  val bf = BloomFilter.optimallySizedString
  it.foreach { cleanName =>
    bf += cleanName
  }
  Iterator(bf)
} reduce(_ | _)
```

我们针对完整的`geoNameRDD`测试我们的过滤器，以删除我们知道不会匹配的地点，最后执行相同的`join`操作，但这次处理的数据要少得多：

```scala
val geoNameFilterRdd = geoAltNameRdd filter {
  case(name, geo) =>
    bf.contains(name)
}

val resultRdd = geoLookup(inputNameRdd, geoNameFilterRdd)
```

通过减少`geoNameRDD`的大小，我们已经成功地减轻了洗牌过程的压力，使我们的`join`操作更加高效。产生的*Reduce-Side-Join*如下图 3 所示：

![离线策略-布隆过滤](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_06_003.jpg)

图 3：使用布隆过滤器的 Reduce-Side-Join

### 在线策略-哈希分区

在离线过程中，我们通过预处理我们的`geoNameRDD`来减少要洗牌的数据量。在流处理过程中，因为任何新的数据批次都是不同的，所以不值得一遍又一遍地过滤我们的参考数据。在这种情况下，我们可以通过使用`HashPartitioner`按键预分区我们的`geoNameRDD`数据，使用的分区数至少是执行器的数量，从而大大提高`join`性能。因为 Spark 框架知道重新分区的使用，只有输入 RDD 将被发送到洗牌，使我们的查找服务显着更快。这在*图 4*中有所说明。请注意，使用`cache`和`count`方法来强制分区。最后，我们可以安全地执行我们相同的`join`操作，这次对网络的压力要小得多：

```scala
val geoAltNamePartitionRdd = geoAltNameRdd.partitionBy(
  new HashPartitioner(100)
).cache()

geoAltNamePartitionRdd.count()
val resultRdd = geoLookup(inputNameRdd, geoAltNamePartitionRdd)
```

![在线策略-哈希分区](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_06_004.jpg)

图 4：使用哈希分区的减少端连接

## 内容去重

像曼彻斯特这样的城市在我们的数据集中被发现 100 次，我们需要为类似名称制定去重策略，考虑到一些城市在随机文本内容中被发现的概率可能不如其他城市重要。

### 上下文学习

对于去重地点内容最准确的方法可能是研究地点记录在其上下文中的情况，类似于苹果公司对谷歌和雅虎的关系，苹果水果对香蕉和橙子的关系。通过机器学习地点在其上下文中，我们可能会发现单词*海狸*和*熊*在加拿大安大略省伦敦市的上下文中是相关的。据我们所知，在英国伦敦遇到野生熊的风险是非常小的。假设可以访问文本内容，训练模型不应该很困难，但访问地理坐标将需要建立一个带有每个地方的地理值和最能描述的主题的索引字典。因为我们没有访问这样的数据集（尽管我们可以从*维基百科*上获取），并且我们不想假设有人可以访问文本内容，所以我们将简单地将地点排名为重要性的顺序。

### 地点评分

考虑到我们从 GeoNames 网站获取的不同代码，我们假设一个大陆比一个国家更重要，一个国家比一个州或一个首都更重要，依此类推。这种天真的方法在 80%的时间内是有意义的，但在一些边缘情况下可能会返回不相关的结果。以曼彻斯特为例，我们会发现曼彻斯特是牙买加的一个重要州的教区，而不是英国的一个简单的城市。我们可以通过在评分方面放宽限制并按人口数量降序排序相同评分的地点来解决这个问题。返回最重要和相关的地点是有意义的，大多数在线 API 都是这样做的，但对于不太重要的城市来说公平吗？我们通过向上下文添加唯一的参考 ID 来改进我们的评分引擎，在那里可能会提到几个地点。如果一个文档只关注加拿大的城市，而没有提到英国，那么伦敦很可能是加拿大的地方。如果没有提到国家或州，或者加拿大和英国都被提到，我们将在我们的数据集中将伦敦作为英国的伦敦。通过按照上下文中提到的相似大陆/国家/州进行排序，然后按重要性，最后按人口进行去重。第一个结果将作为我们最佳候选返回。

# 名称去重

由于我们从 NLP 提取过程中提取实体而没有任何验证，我们能够检索到的名称可能以许多不同的方式书写。它们可以按不同的顺序书写，可能包含中间名或缩写，称谓或贵族头衔，昵称，甚至一些拼写错误和拼写错误。尽管我们不打算完全去重内容（比如学习到*Ziggy Stardust*和*David Bowie*代表同一个人），但我们将介绍两种简单的技术，通过结合 MapReduce 范式和函数式编程的概念，以最小的成本去重大量数据。

## 使用 Scalaz 进行函数式编程

本节主要是关于作为摄入管道的一部分丰富数据。因此，我们对使用先进的机器学习技术构建最准确的系统不太感兴趣，而是对构建最可扩展和高效的系统感兴趣。我们希望保留每条记录的替代名称字典，以便快速合并和更新它们，代码尽可能少，并且规模非常大。我们希望这些结构表现得像单子，代数上的可结合结构，适当地支持**Scalaz**（[`github.com/scalaz/scalaz`](https://github.com/scalaz/scalaz)）上的纯函数式编程库：

```scala
<dependency>
  <groupId>org.scalaz</groupId>
  <artifactId>scalaz-core_2.11</artifactId>
  <version>7.2.0</version>
</dependency>
```

### 我们的去重策略

我们在下面使用一个简单的示例来证明使用 Scalaz 编程构建可扩展的去重管道的需求，该管道由多个转换组成。使用人员的 RDD，`personRDD`，作为下面显示的测试数据集：

```scala
personRDD.take(8).foreach(println)

/*
David Bowie
david bowie
david#Bowie
David Bowie
david bowie
David Bowie
David Bowie
Ziggy Stardust
*/
```

在这里，我们首先计算每个条目的出现次数。实际上，这是一个简单的 Wordcount 算法，MapReduce 编程的*101*：

```scala
val wcRDD = personRDD
  .map(_ -> 1)
  .reduceByKey(_+_)

wcRDD.collect.foreach(println)
/*
(David Bowie, 4)
(david bowie, 2)
(david#Bowie, 1)
(Ziggy Stardust, 1)
*/
```

在这里，我们应用第一个转换，比如`lowercase`，并生成一个更新的报告：

```scala
val lcRDD = wcRDD.map { case (p, tf) => 
  (p.lowerCase(), tf) 
} 
.reduceByKey(_+_) 

lcRDD.collect.foreach(println) 

/* 
(david bowie, 6) 
(david#bowie, 1) 
(ziggy stardust, 1) 
*/ 

```

在这里，我们然后应用第二个转换，删除任何特殊字符：

```scala
val reRDD = lcRDD.map { case (p, tf) =>
  (p.replaceAll("[^a-z]", ""), tf)
}
.reduceByKey(_+_)

reRDD.collect.foreach(println)

/*
(david bowie, 7)
(ziggy stardust, 1)
*/
```

我们现在已经将我们的六个条目减少到只有两个，但由于我们在转换过程中丢失了原始记录，我们无法构建一个形式为[原始值]->[新值]的字典。

### 使用 mappend 运算符

而不是使用 Scalaz API，我们预先初始化每个原始记录的名称频率字典（作为 Map，初始化为 1），并使用`mappend`函数（通过`|+|`运算符访问）合并这些字典。在每个转换之后，合并发生在`reduceByKey`函数中，将转换的结果作为键，术语频率映射作为值：

```scala
import scalaz.Scalaz._

def initialize(rdd: RDD[String]) = {
  rdd.map(s => (s, Map(s -> 1)))
     .reduceByKey(_ |+| _)
}

def lcDedup(rdd: RDD[(String, Map[String, Int])]) = {
  rdd.map { case (name, tf) =>
    (name.toLowerCase(), tf)
  }
  .reduceByKey(_ |+| _)
}

def reDedup(rdd: RDD[(String, Map[String, Int])]) = {
  rdd.map { case (name, tf) =>
    (name.replaceAll("\\W", ""), tf)
  }
  .reduceByKey(_ |+| _)
}

val wcTfRdd = initialize(personRDD)
val lcTfRdd = lcDedup(wcTfRdd)
val reTfRdd = reDedup(lcTfRdd)

reTfRdd.values.collect.foreach(println)

/*
Map(David Bowie -> 4, david bowie -> 2, david#Bowie -> 1)
Map(ziggy stardust -> 1)
*/
```

对于每个去重条目，我们找到最频繁的项目，并构建我们的字典 RDD 如下：

```scala
val dicRDD = fuTfRdd.values.flatMap {
  alternatives =>
    val top = alternatives.toList.sortBy(_._2).last._1
    tf.filter(_._1 != top).map { case (alternative, tf) =>
      (alternative, top)
    }
}

dicRDD.collect.foreach(println)

/*
david bowie, David Bowie
david#Bowie, David Bowie
*/
```

为了完全去重我们的人员 RDD，需要将所有`david bowie`和`david#bowie`的出现替换为`David Bowie`。现在我们已经解释了去重策略本身，让我们深入研究一下转换集。

## 简单清理

第一个去重转换显然是从所有模糊字符或额外空格中清理名称。我们用它们匹配的 ASCII 字符替换重音符号，正确处理驼峰大小写，并删除任何停用词，例如[mr, miss, sir]。将此函数应用于汤加总理，[Mr. Sialeʻataongo Tuʻivakanō]，我们返回[siale ataongo tu ivakano]，这是一个更干净的版本，至少在字符串去重的情况下是这样。执行去重本身将是使用 MapReduce 范式和早期引入的单子概念的几行代码：

```scala
def clean(name: String, stopWords: Set[String]) = {

  StringUtils.stripAccents(name)
    .split("\\W+").map(_.trim).filter { case part =>
      !stopWords.contains(part.toLowerCase())
    }
    .mkString(" ")
    .split("(?<=[a-z])(?=[A-Z])")
    .filter(_.length >= 2)
    .mkString(" ")
    .toLowerCase()

}

def simpleDedup(rdd: RDD[(String, Map[String, Int])], stopWords: Set[String]) = {

  rdd.map { case (name, tf) =>
    (clean(name, stopWords), tf)
  }
  .reduceByKey(_ |+| _)

}
```

## DoubleMetaphone

**DoubleMetaphone**是一种有用的算法，可以根据其英语发音索引名称。尽管它不能产生一个名字的精确音标表示，但它创建了一个简单的哈希函数，可以用于将具有相似音素的名称分组。

### 注意

有关 DoubleMetaphone 算法的更多信息，请参阅：*Philips，L.（1990）。Hanging on the Metaphone（Vol. 7）。计算机语言。）*

出于性能原因，我们转向这种算法，因为在大型词典中查找潜在的拼写错误和拼写错误通常是一项昂贵的操作；通常需要将候选姓名与我们正在跟踪的每个其他姓名进行比较。这种类型的比较在大数据环境中是具有挑战性的，因为它通常需要进行笛卡尔`join`，这可能会生成过大的中间数据集。metaphone 算法提供了一个更大、更快的替代方案。

使用 Apache commons 包中的`DoubleMetaphone`类，我们简单地利用 MapReduce 范式，将发音相同的姓名分组。例如，`[david bowie]`、`[david bowi]`和`[davide bowie]`都共享相同的代码`[TFT#P]`，将被分组在一起。在下面的示例中，我们计算每条记录的双元音哈希，并调用`reduceByKey`来合并和更新所有我们姓名的频率映射：

```scala
def metaphone(name: String) = {
  val dm = new DoubleMetaphone()
  name.split("\\s")
    .map(dm.doubleMetaphone)
    .mkString("#")
}

def metaphoneDedup(rdd: RDD[(String, Map[String, Int])]) = {
  rdd.map { case (name, tf) =>
    (metaphone(name), tf)
  }
  .reduceByKey(_ |+| _)
}
```

我们还可以通过保留常见英文昵称（比如 bill、bob、will、beth、al 等）及其对应的主要名称的列表，极大地改进这种简单的技术，这样我们就可以在非音标同义词之间进行匹配。我们可以通过预处理我们的姓名 RDD，将已知昵称的哈希码替换为相关主要名称的哈希码，然后我们可以运行相同的去重算法来解决基于音标和同义词的重复。这将检测拼写错误和替代昵称，如下所示：

```scala
persons.foreach(p => println(p + "\t" + metaphoneAndNickNames(p))

/*
David Bowie  TFT#P
David Bowi   TFT#P
Dave Bowie   TFT#P
*/
```

再次强调，这种算法（以及上面显示的简单清洗例程）将不像适当的模糊字符串匹配方法那样准确，例如计算每对可能的姓名之间的*Levenshtein*距离。然而，通过牺牲准确性，我们创造了一种高度可扩展的方法，以最小的成本找到大多数常见的拼写错误，特别是在无声辅音上的拼写错误。一旦所有替代名称都已根据生成的哈希码分组，我们可以将最佳替代名称输出为我们从我们的词频对象返回的最频繁的名称。通过`join`将这个最佳替代应用于初始名称 RDD，以替换任何记录为其首选替代（如果有的话）：

```scala
def getBestNameRdd(rdd: RDD[(String, Map[String, Int])]) = {
  rdd.flatMap { case (key, tf) =>
    val bestName = tf.toSeq.sortBy(_._2).last._1
    tf.keySet.map { altName =>
      (altName, bestName)
    } 
  }
}

val bestNameRdd = getBestNameRdd(nameTfRdd)

val dedupRdd = nameRdd
  .map(_ -> 1)
  .leftOuterJoin(bestNameRdd)
  .map { case (name, (dummy, optBest)) =>
    optBest.getOrElse(name)
  }
```

# 新闻索引仪表板

由于我们能够丰富输入 URL 中找到的内容，我们自然的下一步是开始可视化我们的数据。虽然探索性数据分析的不同技术已经在第四章中进行了详细讨论，*探索性数据分析*，我们认为值得用 Kibana 中的简单仪表板总结到目前为止我们所涵盖的内容。从大约 50,000 篇文章中，我们能够在 1 月 10 日至 11 日获取并分析，我们过滤掉任何提到*David Bowie*作为 NLP 实体并包含*death*一词的记录。因为我们所有的文本内容都被正确索引在 Elasticsearch 中，我们可以在几秒钟内提取 209 篇匹配的文章及其内容。

![新闻索引仪表板](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_06_5.jpg)

图 5：新闻索引仪表板

我们可以快速获取与**David Bowie**一起提到的前十位人物，包括他的艺名*Ziggy Stardust*、他的儿子*Duncan Jones*、他的前制作人*Tony Visconti*，或者英国首相*David Cameron*。由于我们建立的*GeoLookup*服务，我们展示了所有提到的不同地点，发现了梵蒂冈城国家周围的一个圈子，那里的红衣主教**Gianfranco Ravasi**，文化部主席，发推特提到*David Bowie*的著名歌词*Space Oddity*。

![新闻索引仪表板](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_06_006.jpg)

图 6：梵蒂冈向推特致敬

最后，在争先发布关于*David Bowie*去世的新闻的竞赛中，找到第一个报道的人就像简单的点击一样容易！

# 总结

数据科学不仅仅是关于机器学习。事实上，机器学习只是其中的一小部分。在我们对现代数据科学的理解中，科学往往恰好发生在数据丰富化的过程中。真正的魔力发生在当一个人能够将一个无意义的数据集转化为有价值的信息集，并从中获得新的见解。在本节中，我们已经描述了如何使用简单的 URL 集合（和一点点努力）构建一个完全功能的数据洞察系统。

在本章中，我们演示了如何使用 Goose 库在 Spark 中创建高效的网络爬虫，以及如何使用 NLP 技术和 GeoNames 数据库从原始文本中提取和去重特征。我们还涵盖了一些有趣的设计模式，如*mapPartitions*和*Bloom filters*，这些将在第十四章 *可扩展算法*中进一步讨论。

在下一章中，我们将专注于从所有这些新闻文章中提取出来的人们。我们将描述如何使用简单的联系链技术在它们之间建立联系，如何在 Spark 环境中高效存储和查询大型图表，以及如何使用*GraphX*和*Pregel*来检测社区。


# 第七章：建立社区

随着越来越多的人相互交流和沟通，交换信息，或者只是在不同主题上分享共同的兴趣，大多数数据科学用例都可以使用图形表示来解决。尽管很长一段时间以来，非常大的图仅被互联网巨头、政府和国家安全机构使用，但现在使用包含数百万个顶点的大图变得更加普遍。因此，数据科学家的主要挑战不一定是在图表上检测社区并找到影响者，而是以一种完全分布式和高效的方式来克服规模的限制。本章将通过使用我们在第六章中描述的 NLP 提取识别的人员来构建一个大规模的图表示例。

在本章中，我们将涵盖以下主题：

+   使用 Spark 从 Elasticsearch 中提取内容，构建人员实体的图表，并了解使用 Accumulo 作为安全图数据库的好处

+   使用*GraphX*和三角形优化从 A 到 Z 编写社区检测算法

+   利用 Accumulo 特定功能，包括单元级安全性来观察社区的变化，并使用迭代器提供服务器和客户端计算

这一章节非常技术化，我们期望读者已经熟悉图论、消息传递和*Pregel* API。我们还邀请读者阅读本章中提到的每一篇白皮书。

# 构建人员图表

我们之前使用了 NLP 实体识别来从 HTML 原始文本格式中识别人物。在本章中，我们将尝试推断这些实体之间的关系，并检测围绕它们的可能社区。

## 联系链

在新闻文章的背景下，我们首先需要问自己一个基本问题。什么定义了两个实体之间的关系？最优雅的答案可能是使用斯坦福 NLP 库中描述的单词来研究，详情请参阅第六章中描述的*抓取基于链接的外部数据*。给定以下输入句子，该句子取自[`www.ibtimes.co.uk/david-bowie-yoko-ono-says-starmans-death-has-left-big-empty-space-1545160`](http://www.ibtimes.co.uk/david-bowie-yoko-ono-says-starmans-death-has-left-big-empty-space-1545160)：

> *"Yoko Ono 说她和已故丈夫约翰·列侬与大卫·鲍伊有着密切的关系"*

我们可以轻松提取句法树，这是语言学家用来模拟句子语法结构的结构，其中每个元素都以其类型报告，例如名词（`NN`），动词（`VR`）或限定词（`DT`），以及其在句子中的相对位置。

```scala
val processor = new CoreNLPProcessor()
val document = processor.annotate(text)

document.sentences foreach { sentence =>
  println(sentence.syntacticTree.get)
}

/*
(NNP Yoko)
(NNP Ono)
(VBD said)
        (PRP she)
      (CC and)
        (JJ late)
        (NN husband)
          (NNP John)
          (NNP Lennon)
      (VBD shared)
        (DT a)
        (JJ close)
        (NN relationship)
        (IN with)
          (NNP David)
          (NNP Bowie)
*/
```

对每个元素、其类型、其前驱和后继的彻底研究将有助于构建一个有向图，其中边是存在于所有这三个实体之间关系的真实定义。从这个句子构建的图的示例如下所示：

![联系链](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_07_001.jpg)

图 1：大卫·鲍伊、Yoko Ono 和约翰·列侬的句法图

虽然从语法上讲是完全合理的，但是构建一个句法树图需要大量的编码，可能需要一个完整的章节来讲解，并且并没有带来太多附加值，因为我们建立的大多数关系（在新闻文章的背景下）都不是基于历史书籍中的真实事实，而是需要放在它们的背景中。为了说明这一点，我们有两个句子，这些句子取自[`www.digitalspy.com/music/news/a779577/paul-mccartney-pays-tribute-to-great-star-david-bowie-his-star-will-shine-in-the-sky-forever/`](http://www.digitalspy.com/music/news/a779577/paul-mccartney-pays-tribute-to-great-star-david-bowie-his-star-will-shine-in-the-sky-forever/)：

> *“保罗·麦卡特尼爵士称[大卫·鲍伊]为一颗伟大的星星”*
> 
> *“[保罗·麦卡特尼爵士]珍视他们在一起的时刻”*

它将在[保罗·麦卡特尼]和[大卫·鲍伊]之间创建相同的语法链接，而只有后者假定它们之间存在物理联系（他们实际上在一起度过了一些时间）。

相反，我们使用了一种更快速的方法，即根据它们在文本中的位置对名称进行分组。我们的天真假设是，大多数作者通常首先提到重要人物的名字，然后写有关次要角色的内容，最后是不太重要的人物。因此，我们的联系链接是在给定文章中的所有名称上进行的简单嵌套循环，名称根据它们的实际位置从最重要的到最不重要的进行排序。由于其相对时间复杂度为*O(n²)*，这种方法只对每篇文章的记录数有效，对于提及数以千计不同实体的文本来说，它肯定会成为一个限制因素。

```scala
def buildTuples(p: Array[String]): Array[(String, String)] = {
    for(i <- 0 to p.length - 2; j <- i + 1 to p.length - 1) yield {
      (p(i), p(j))
    }
  }
```

在我们的代码库中，您将看到另一种选择：`Combinations`，这是一个更通用的解决方案，允许指定一个变量`r`；这使我们能够指定每个输出组合中需要出现的实体数量，即本章为 2，但在其他情境中可能更多。使用`Combinations.buildTuples`在功能上等同于之前给出的`buildTuples`代码。

## 从 Elasticsearch 中提取数据

Elasticsearch 是一个存储和索引文本内容及其元数据属性的完美工具，因此它是我们在线数据存储的逻辑选择，使用我们在上一章中提取的文本内容。由于本节更加面向批处理，我们使用出色的 Spark Elasticsearch API 将数据从 Elasticsearch 获取到我们的 Spark 集群中，如下面的代码所示：

```scala
<dependency>
  <groupId>org.elasticsearch</groupId>
  <artifactId>elasticsearch-spark_2.11</artifactId>
  <version>2.4.0<version>
</dependency>
```

给定索引类型和名称，与 Elasticsearch API 交互的一种便捷方式是使用 Spark DataFrame。在大多数用例中效率足够高（下面显示了一个简单的例子），但在处理更复杂和嵌套的模式时可能会成为一个挑战：

```scala
val spark = SparkSession
  .builder()
  .config("es.nodes", "localhost")
  .config("es.port", "9200")
  .appName("communities-es-download")
  .getOrCreate()

spark
  .read
  .format("org.elasticsearch.spark.sql")
  .load("gzet/news")
  .select("title", "url")
  .show(5)

+--------------------+--------------------+
|               title|                 url|
+--------------------+--------------------+
|Sonia Meets Mehbo...|http://www.newind...|
|"A Job Well Done ...|http://daphneanso...|
|New reading progr...|http://www.mailtr...|
|Barrie fire servi...|http://www.simcoe...|
|Paris police stat...|http://www.dailym...|
+--------------------+--------------------+
```

事实上，Elasticsearch API 并不灵活，无法读取嵌套结构和复杂数组。使用最新版本的 Spark，人们很快就会遇到诸如“'persons'字段由数组支持，但相关的 Spark 模式并不反映这一点”之类的错误。通过一些实验，我们可以看到，使用一组标准的 JSON 解析器（例如下面的`json4s`）通常更容易从 Elasticsearch 中访问嵌套和复杂的结构：

```scala
<dependency>
  <groupId>org.json4s</groupId>
  <artifactId>json4s-native_2.11</artifactId>
  <version>3.2.11</version>
</dependency>
```

我们使用隐式的`esJsonRdd`函数从 spark 上下文查询 Elasticsearch：

```scala
import org.elasticsearch.spark._
import org.json4s.native.JsonMethods._
import org.json4s.DefaultFormats

def readFromES(query: String = "?q=*"): RDD[Array[String]] = {

  sc.esJsonRDD("gzet/news", query)
    .values
    . map {
      jsonStr =>
        implicit val format = DefaultFormats
        val json = parse(jsonStr)
        (json \ "persons").extract[Array[String]]
    }

}

readFromEs("?persons='david bowie'")
   .map(_.mkString(","))
   .take(3)
   .foreach(println)

/*
david bowie,yoko ono,john lennon,paul mc cartney
duncan jones,david bowie,tony visconti
david bowie,boris johnson,david cameron
*/
```

使用`query`参数，我们可以访问 Elasticsearch 中的所有数据，其中的一部分数据，或者甚至是与特定查询匹配的所有记录。最后，我们可以使用之前解释的简单联系链接方法来构建我们的元组列表。

```scala
val personRdd = readFromES()
val tupleRdd = personRdd flatMap buildTuples
```

# 使用 Accumulo 数据库

我们已经看到了从 Elasticsearch 读取`personRdd`对象的方法，这为我们的存储需求提供了一个简单而整洁的解决方案。然而，在编写商业应用程序时，我们必须始终牢记安全性，在撰写本文时，Elasticsearch 安全性仍在开发中；因此，在这个阶段引入具有本地安全性的存储机制将是有用的。这是一个重要的考虑因素，因为我们使用的是 GDELT 数据，当然，根据定义，它是开源的。在商业环境中，数据集很常见地是机密的或在某种程度上具有商业敏感性，客户通常会在讨论数据科学方面之前要求了解他们的数据将如何得到安全保护。作者的经验是，许多商业机会由于解决方案提供者无法展示健壮和安全的数据架构而丧失。

**Accumulo** ([`accumulo.apache.org`](http://accumulo.apache.org)) 是一个基于 Google 的 Bigtable 设计（[`research.google.com/archive/bigtable.html`](http://research.google.com/archive/bigtable.html)）的 NoSQL 数据库，最初由美国国家安全局开发，后来在 2011 年释放给 Apache 社区。Accumulo 为我们提供了通常的大数据优势，如批量加载和并行读取，但还具有一些额外的功能，如迭代器，用于高效的服务器和客户端预计算、数据聚合，最重要的是单元格级安全。

在我们的社区检测工作中，我们将使用 Accumulo 来特别利用其迭代器和单元格级安全功能。首先，我们应该设置一个 Accumulo 实例，然后从 Elasticsearch 加载一些数据到 Accumulo，你可以在我们的 GitHub 存储库中找到完整的代码。

## 设置 Accumulo

安装 Accumulo 所需的步骤超出了本书的范围；网上有几个教程可供参考。只需进行一个带有根用户的原始安装即可继续本章，尽管我们需要特别注意 Accumulo 配置中的初始安全设置。一旦成功运行 Accumulo shell，您就可以继续进行。

使用以下代码作为创建用户的指南。目标是创建几个具有不同安全标签的用户，这样当我们加载数据时，用户将有不同的访问权限。

```scala
# set up some users
createuser matt
createuser ant
createuser dave
createuser andy

# create the persons table
createtable persons

# switch to the persons table
table persons

# ensure all of the users can access the table
grant -s System.READ_TABLE -u matt
grant -s System.READ_TABLE -u ant
grant -s System.READ_TABLE -u dave
grant -s System.READ_TABLE -u andy

# allocate security labels to the users
addauths -s unclassified,secret,topsecret -u matt
addauths -s unclassified,secret -u ant
addauths -s unclassified,topsecret -u dave
addauths -s unclassified -u andy

# display user auths
getauths -u matt

# create a server side iterator to sum values
setiter -t persons -p 10 -scan -minc -majc -n sumCombiner -class
org.apache.accumulo.core.iterators.user.SummingCombiner

# list iterators in use
listiter –all

# once the table contains some records ...
user matt

# we'll see all of the records that match security labels for the user
scan
```

## 单元格安全

Accumulo 使用令牌来保护其单元格。令牌由标签组成；在我们的情况下，这些是[`未分类`], [`机密`], 和 [`绝密`], 但你可以使用任何逗号分隔的值。Accumulo 行是用`visibility`字段（参考下面的代码）编写的，它只是对访问行值所需的标签的字符串表示。`visibility`字段可以包含布尔逻辑来组合不同的标签，还允许基本的优先级，例如：

```scala
secret&topsecret (secret AND topsecret)
secret|topsecret (secret OR topsecret)
unclassified&(secret|topsecret) (unclassified AND secret, or unclassified AND topsecret)
```

用户必须至少匹配`visibility`字段才能获得访问权限，并且必须提供标签，这些标签是存储在 Accumulo 中的令牌的子集（否则查询将被拒绝）。任何不匹配的值在用户查询中将不会被返回，这是一个重要的观点，因为如果用户得知数据缺失，往往可以根据周围图的性质得出逻辑上正确（或者更糟糕的是错误）的结论，例如，在一个人的联系链中，如果一些顶点对用户可见而另一些不可见，但不可见的顶点被标记为不可见，那么用户可能能够根据周围的图确定有关这些缺失实体的信息。例如，调查有组织犯罪的政府机构可能允许高级员工查看整个图，但只允许初级员工查看其中的部分。假设图中显示了一些知名人物，并且一个顶点的条目为空白，那么可能很容易推断出缺失的实体是谁；如果这个占位符完全不存在，那么就没有明显的迹象表明链条延伸得更远，从而允许机构控制信息的传播。然而，对于对这些链接一无所知的分析人员来说，图仍然是有用的，并且可以继续在图的特定区域上工作。

## 迭代器

迭代器是 Accumulo 中非常重要的特性，提供了一个实时处理框架，利用 Accumulo 的强大和并行能力，以非常低的延迟产生修改后的数据版本。我们不会在这里详细介绍，因为 Accumulo 文档中有很多例子，但我们将使用一个迭代器来保持相同 Accumulo 行的值的总和，也就是我们看到相同的人员对的次数；这将存储在该行值中。每当扫描表时，这个迭代器就会生效；我们还将演示如何从客户端调用相同的迭代器（当它尚未应用于服务器时）。

## Elasticsearch 到 Accumulo

让我们利用 Spark 能够使用 Hadoop 输入和输出格式的能力，利用本地 Elasticsearch 和 Accumulo 库。值得注意的是，我们在这里可以采取不同的路线，第一种是使用之前提供的 Elasticsearch 代码生成一个字符串元组数组，并将其输入到`AccumuloLoader`（在代码库中找到）；第二种是探索另一种使用额外 Hadoop `InputFormat` 的方法；我们可以编写代码，使用`EsInputFormat` 从 Elasticsearch 读取数据，并使用`AccumuloOutputFormat` 类写入 Accumulo。

### Accumulo 中的图数据模型

在深入代码之前，值得描述一下我们将在 Accumulo 中使用的存储人员图的模式。每个源节点（`person A`）将被存储为行键，关联名称（如“也被称为”）作为列族，目标节点（`person B`）作为列限定符，以及默认值`1`作为列值（这将通过我们的迭代器进行聚合）。如图 2 所示：

![Accumulo 中的图数据模型](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_07_002.jpg)

图 2：Accumulo 上的图数据模型

这种模型的主要优势在于，给定一个输入顶点（一个人的名字），可以通过简单的 GET 查询快速访问所有已知的关系。读者肯定会欣赏单元级别的安全性，我们可以隐藏一个特定的边三元组`[personA] <= [relationB] => [personD]`，对大多数没有[`SECRET`]授权的 Accumulo 用户。

这种模型的缺点是，与图数据库（如 Neo4J 或 OrientDB）相比，遍历查询（如深度优先搜索）将非常低效（我们需要多次递归查询）。我们将任何图处理逻辑委托给本章后面的 GraphX。

### Hadoop 输入和输出格式

我们使用以下 maven 依赖项来构建我们的输入/输出格式和我们的 Spark 客户端。版本显然取决于安装的 Hadoop 和 Accumulo 的发行版。

```scala
<dependency>
  <groupId>org.apache.accumulo</groupId>
  <artifactId>accumulo-core</artifactId>
  <version>1.7.0<version>
</dependency>
```

我们通过`ESInputFormat`类配置从 Elasticsearch 中读取。我们提取了一个`Text`和`MapWritable`的键值对 RDD，其中键包含文档 ID，值包含所有 JSON 文档的可序列化 HashMap 包装在内：

```scala
val spark = SparkSession
  .builder()
  .appName("communities-loader")
  .getOrCreate()

val sc = spark.sparkContext
val hdpConf = sc.hadoopConfiguration

// set the ES entry points
hdpConf.set("es.nodes", "localhost:9200")
hdpConf.set("es.resource", "gzet/articles")

// Read map writable objects
import org.apache.hadoop.io.Text
import org.apache.hadoop.io.MapWritable
import org.elasticsearch.hadoop.mr.EsInputFormat

val esRDD: RDD[MapWritable] = sc.newAPIHadoopRDD(
  hdpConf,
  classOf[EsInputFormat[Text, MapWritable]],
  classOf[Text],
  classOf[MapWritable]
).values
```

Accumulo 的`mutation`类似于 HBase 中的`put`对象，包含表的坐标，如行键，列族，列限定符，列值和可见性。该对象构建如下：

```scala
def buildMutations(value: MapWritable) = {

  // Extract list of persons
  val people = value
    .get("person")
    .asInstanceOf[ArrayWritable]
    .get()
    .map(_.asInstanceOf[Text])
    .map(_.toString)

  // Use a default Visibility
  val visibility = new ColumnVisibility("unclassified")

  // Build mutation on tuples
  buildTuples(people.toArray)
    .map {
      case (src, dst) =>
        val mutation = new Mutation(src)
        mutation.put("associated", dst, visibility, "1")
        (new Text(accumuloTable), mutation)
    }
```

我们使用上述的`buildTuples`方法来计算我们的人员对，并使用 Hadoop 的`AccumuloOutputFormat`将它们写入 Accumulo。请注意，我们可以选择为我们的输出行应用安全标签，使用`ColumnVisibility`；参考*Cell security*，我们之前看到过。

我们配置用于写入 Accumulo。我们的输出 RDD 将是一个`Text`和`Mutation`的键值对 RDD，其中键包含 Accumulo 表，值包含要插入的 mutation：

```scala
// Build Mutations
val accumuloRDD = esRDD flatMap buildMutations

// Save Mutations to Accumulo
accumuloRDD.saveAsNewAPIHadoopFile(
  "",
  classOf[Text],
  classOf[Mutation],
  classOf[AccumuloOutputFormat]
)
```

## 从 Accumulo 读取

现在我们的数据在 Accumulo 中，我们可以使用 shell 来检查它（假设我们选择了一个有足够权限查看数据的用户）。在 Accumulo shell 中使用`scan`命令，我们可以模拟特定用户和查询，从而验证`io.gzet.community.accumulo.AccumuloReader`的结果。在使用 Scala 版本时，我们必须确保使用正确的授权-它通过`String`传递到读取函数中，例如可能是`"secret,topsecret"`。

```scala
def read(
  sc: SparkContext,
  accumuloTable: String,
  authorization: Option[String] = None
)
```

这种应用 Hadoop 输入/输出格式的方法利用了 Java Accumulo 库中的`static`方法（`AbstractInputFormat`是`InputFormatBase`的子类，`InputFormatBase`是`AccumuloInputFormat`的子类）。Spark 用户必须特别注意这些实用方法，通过`Job`对象的实例来修改 Hadoop 配置。可以设置如下：

```scala
val hdpConf = sc.hadoopConfiguration
val job = Job.getInstance(hdpConf)

val clientConfig = new ClientConfiguration()
  .withInstance(accumuloInstance)
  .withZkHosts(zookeeperHosts)

AbstractInputFormat.setConnectorInfo(
  job,
  accumuloUser,
  new PasswordToken(accumuloPassword)
)

AbstractInputFormat.setZooKeeperInstance(
  job,
  clientConfig
)

if(authorization.isDefined) {
  AbstractInputFormat.setScanAuthorizations(
    job,
    new Authorizations(authorization.get)
  )
}

InputFormatBase.addIterator(job, is)
InputFormatBase.setInputTableName(job, accumuloTable)
```

您还会注意到配置了 Accumulo 迭代器：

```scala
val is = new IteratorSetting(
  1,
  "summingCombiner",
  "org.apache.accumulo.core.iterators.user.SummingCombiner"
)

is.addOption("all", "")
is.addOption("columns", "associated")
is.addOption("lossy", "TRUE")
is.addOption("type", "STRING")
```

我们可以使用客户端或服务器端迭代器，之前我们已经在通过 shell 配置 Accumulo 时看到了一个服务器端的例子。关键区别在于客户端迭代器在客户端 JVM 中执行，而不是服务器端迭代器利用 Accumulo 表服务器的功能。在 Accumulo 文档中可以找到完整的解释。然而，选择客户端或服务器端迭代器的许多原因，包括是否应该牺牲表服务器性能，JVM 内存使用等。这些决定应该在创建 Accumulo 架构时进行。在我们的`AccumuloReader`代码的末尾，我们可以看到产生`EdgeWritable`的 RDD 的调用函数：

```scala
val edgeWritableRdd: RDD[EdgeWritable] = sc.newAPIHadoopRDD(
  job.getConfiguration,
  classOf[AccumuloGraphxInputFormat],
  classOf[NullWritable],
  classOf[EdgeWritable]
) values
```

## AccumuloGraphxInputFormat 和 EdgeWritable

我们实现了自己的 Accumulo `InputFormat`，使我们能够读取 Accumulo 行并自动输出我们自己的 Hadoop `Writable`；`EdgeWritable`。这提供了一个方便的包装器，用于保存我们的源顶点，目标顶点和作为边权重的计数，这在构建图时可以使用。这非常有用，因为 Accumulo 使用前面讨论的迭代器来计算每个唯一行的总计数，从而无需手动执行此操作。由于 Accumulo 是用 Java 编写的，我们的`InputFormat`使用 Java 来扩展`InputFormatBase`，从而继承了所有 Accumulo`InputFormat`的默认行为，但输出我们选择的模式。

我们只对输出`EdgeWritables`感兴趣；因此，我们将所有键设置为 null（`NullWritable`），值设置为`EdgeWritable`，另一个优势是 Hadoop 中的值只需要继承自`Writable`接口（尽管我们为了完整性继承了`WritableComparable`，因此如果需要，`EdgeWritable`也可以用作键）。

## 构建图

因为 GraphX 使用长对象作为存储顶点和边的基础类型，所以我们首先需要将从 Accumulo 获取的所有人员翻译成一组唯一的 ID。我们假设我们的唯一人员列表不适合存储在内存中，或者无论如何都不高效，所以我们简单地使用`zipWithIndex`函数构建一个分布式字典，如下面的代码所示：

```scala
val dictionary = edgeWritableRdd
  .flatMap {
    edge =>
      List(edge.getSourceVertex, edge.getDestVertex)
  }
  .distinct()
  .zipWithIndex()
  .mapValues {
    index =>
      index + 1L
  }
}

dictionary.cache()
dictionary.count()

dictionary
  .take(3)
  .foreach(println)

/*
(david bowie, 1L)
(yoko ono, 2L)
(john lennon, 3L)
*/
```

我们使用两次连续的连接操作来创建边 RDD，最终构建包含人员名称的顶点和包含每个元组频率计数的边属性的加权有向图。

```scala
val vertices = dictionary.map(_.swap)

val edges = edgeWritableRdd
  .map {
    edge =>
      (edge.getSourceVertex, edge)
  }
  .join(dictionary)
  .map {
    case (from, (edge, fromId)) =>
      (edge.getDestVertex, (fromId, edge))
  }
  .join(dictionary)
  .map {
    case (to, ((fromId, edge), toId)) =>
      Edge(fromId, toId, edge.getCount.toLong)
  }

val personGraph = Graph.apply(vertices, edges)

personGraph.cache()
personGraph.vertices.count()

personGraph
  .triplets
  .take(2)
  .foreach(println)

/*
((david bowie,1),(yoko ono,2),1)
((david bowie,1),(john lennon,3),1)
((yoko ono,2),(john lennon,3),1)
*/
```

# 社区检测算法

在过去几十年里，社区检测已经成为研究的热门领域。遗憾的是，它没有像真正的数据科学家所处的数字世界一样快速发展，每秒都在收集更多的数据。因此，大多数提出的解决方案对于大数据环境来说根本不合适。

尽管许多算法提出了一种新的可扩展的检测社区的方法，但实际上没有一种是在分布式算法和并行计算方面真正可扩展的。

## Louvain 算法

Louvain 算法可能是检测无向加权图中社区最流行和广泛使用的算法。

### 注意

有关 Louvain 算法的更多信息，请参阅出版物：*大型网络中社区的快速展开。文森特 D.布隆德，让-卢·吉约姆，勒诺·兰比奥特，艾蒂安·勒菲布尔。2008*

这个想法是从每个顶点作为其自己社区的中心开始。在每一步中，我们寻找社区邻居，并检查合并这两个社区是否会导致模块化值的增益。通过每个顶点，我们压缩图形，使得所有属于同一个社区的节点成为一个唯一的社区顶点，所有社区内部边成为具有聚合权重的自边。我们重复这个过程，直到无法再优化模块化。该过程如*图 3*所示：

![Louvain 算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_07_03.jpg)

图 3：大型网络中社区的快速展开-文森特 D.布隆德尔，让-卢·吉约姆，勒诺·兰比奥特，艾蒂安·勒菲布尔，2008

因为每当顶点改变时，模块化都会更新，而且每个顶点的改变都将由全局模块化更新驱动，所以顶点需要按顺序处理；这使得模块化优化成为并行计算性质的一个分界点。最近的研究报告称，随着图的规模过度增加，结果的质量可能会下降，以至于模块化无法检测到小而明确定义的社区。

据我们所知，唯一公开可用的 Louvain 的分布式版本是由国家安全技术供应商 Sotera 创建的（[`github.com/Sotera/distributed-graph-analytics/tree/master/dga-graphx`](https://github.com/Sotera/distributed-graph-analytics/tree/master/dga-graphx)）。他们在 MapReduce、Giraph 或 GraphX 上有不同的实现，他们的想法是同时做出顶点选择，并在每次更改后更新图状态。由于并行性质，一些顶点选择可能是不正确的，因为它们可能无法最大化全局模块化，但在重复迭代后最终变得越来越一致。

这种（可能）略微不准确，但绝对高度可扩展的算法值得研究，但由于社区检测问题没有对错解决方案，而且每个数据科学用例都不同，我们决定构建我们自己的分布式版本的不同算法，而不是描述现有的算法。为了方便起见，我们重新打包了这个分布式版本的 Louvain，并在我们的 GitHub 存储库中提供了它。

## 加权社区聚类（WCC）

通过搜索一些关于图算法的文档材料，我们偶然发现了一份关于可扩展性和并行计算的出色且最新的白皮书。我们邀请我们的读者在继续实施之前先阅读这篇论文。

### 注意

有关**WCC**算法的更多信息，请参阅以下出版物：*A. Prat-Perez, D. Dominguez-Sal, and J.-L. Larriba-Pey, "High quality, scalable and parallel community detection for large real graphs," in Proceedings of the 23rd International Conference on World Wide Web, ser. WWW '14\. New York, NY, USA: ACM, 2014, pp. 225-236*

尽管找不到任何实现，并且作者对他们使用的技术保持低调，但我们对作为图分区度量的启发式方法特别感兴趣，因为检测可以并行进行，而无需重新计算图模块度等全局度量。

### 描述

同样有趣的是他们使用的假设，受到现实生活社交网络的启发，作为检测社区的质量度量。因为社区是紧密连接在一起并与图的其余部分松散连接的顶点组成的群体，所以每个社区内应该有大量的三角形。换句话说，组成社区的顶点应该在自己的社区内关闭的三角形数量要比在外部关闭的要多得多。

![Description](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_07_04.jpg)

根据前述方程，给定顶点**x**在社区**C**中的聚类系数（**WCC**）将在**x**在其社区内部关闭的三角形数量多于外部时达到最大值（社区将被明确定义），和/或者当它与不关闭任何三角形的邻居数量最小时（所有节点相互连接）。如下方程所述，社区**S**的**WCC**将是其每个顶点的平均**WCC**：

![Description](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_07_05.jpg)

同样，图分区**P**的**WCC**将是每个社区**WCC**的加权平均值：

![Description](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_07_06.jpg)

该算法包括三个不同的阶段，下面将对其进行解释。预处理步骤创建初始社区集，社区回传以确保初始社区一致，最后是一个迭代算法，优化全局聚类系数值。

### 预处理阶段

第一步是定义一个图结构，其中顶点包含我们需要在本地计算**WCC**指标的所有变量，包括顶点所属的当前社区，每个顶点在其社区内外关闭的三角形数量，它与其他节点共享三角形的数量以及当前**WCC**指标。所有这些变量将被封装到一个`VState`类中：

```scala
class VState extends Serializable {
  var vId = -1L
  var cId = -1L
  var changed = false
  var txV = 0
  var txC = 0
  var vtxV = 0
  var vtxV_C = 0
  var wcc = 0.0d
}
```

为了计算初始**WCC**，我们首先需要计算任何顶点在其邻域内关闭的三角形数量。通常计算三角形的数量包括为每个顶点聚合邻居的 ID，将此列表发送给每个邻居，并在顶点邻居和顶点邻居的邻居中搜索共同的 ID。给定两个相连的顶点 A 和 B，A 的邻居列表和 B 的邻居列表的交集是顶点 A 与 B 关闭的三角形数量，而 A 中的聚合返回顶点 A 在整个图中关闭的三角形的总数。

在具有高度连接的顶点的大型网络中，向每个邻居发送相邻顶点的列表可能会耗时且网络密集。在 GraphX 中，`triangleCount`函数已经经过优化，因此对于每条边，只有最不重要的顶点（按度数而言）将向其相邻节点发送其列表，从而最小化相关成本。此优化要求图形是规范的（源 ID 小于目标 ID）并且被分区。使用我们的人员图，可以按以下方式完成：

```scala
val cEdges: RDD[Edge[ED]] = graph.edges
  .map { e =>
    if(e.srcId > e.dstId) {
      Edge(e.dstId, e.srcId, e.attr)
    } else e
  }

val canonicalGraph = Graph
  .apply(graph.vertices, cEdges)
  .partitionBy(PartitionStrategy.EdgePartition2D)

canonicalGraph.cache()
canonicalGraph.vertices.count()
```

WCC 优化的先决条件是删除不属于任何三角形的边，因为它们不会对社区做出贡献。因此，我们需要计算三角形的数量，每个顶点的度数，邻居的 ID，最后删除邻居 ID 的交集为空的边。可以使用`subGraph`方法来过滤这些边，该方法接受边三元组的`filter`函数和顶点的`filter`函数作为输入参数：

```scala
val triGraph = graph.triangleCount()
val neighborRdd = graph.collectNeighborIds(EdgeDirection.Either)

val subGraph = triGraph.outerJoinVertices(neighborRdd)({ (vId, triangle, neighbors) =>
  (triangle, neighbors.getOrElse(Array()))
}).subgraph((t: EdgeTriplet[(Int, Array[Long]), ED]) => {
  t.srcAttr._2.intersect(t.dstAttr._2).nonEmpty
}, (vId: VertexId, vStats: (Int, Array[Long])) => {
  vStats._1 > 0
})
```

由于我们删除了没有闭合任何三角形的所有边，因此每个顶点的度数变成了给定顶点与三角形闭合的不同顶点的数量。最后，我们按照以下方式创建我们的初始`VState`图，其中每个顶点都成为其自己社区的中心节点：

```scala
val initGraph: Graph[VState, ED] = subGraph.outerJoinVertices(subGraph.degrees)((vId, vStat, degrees) => {
  val state = new VState()
  state.vId = vId
  state.cId = vId
  state.changed = true
  state.txV = vStat._1
  state.vtxV = degrees.getOrElse(0)
  state.wcc = degrees.getOrElse(0).toDouble / vStat._1 
  state
})

initGraph.cache()
initGraph.vertices.count()

canonicalGraph.unpersist(blocking = false)
```

### 初始社区

这个阶段的第二步是使用这些初始 WCC 值初始化社区。我们定义我们的初始社区集合只有在满足以下三个要求时才是一致的：

+   任何社区必须包含单个中心节点和边界节点，并且所有边界顶点必须连接到社区中心

+   任何社区中心必须具有其社区中最高的聚类系数

+   连接到两个不同中心（因此根据规则 1 属于两个不同社区）的边界顶点必须属于其中心具有最高聚类系数的社区

#### 消息传递

为了定义我们的初始社区，每个顶点都需要向其邻居发送信息，包括其 ID，其聚类系数，其度数和它当前所属的社区。为方便起见，我们将发送主要顶点属性`VState`类作为消息，因为它已经包含了所有这些信息。顶点将从其邻域接收这些消息，将选择具有最高 WCC 分数（在我们的`getBestCid`方法中），最高度数，最高 ID 的最佳消息，并相应地更新其社区。

顶点之间的这种通信是`aggregateMessages`函数的一个完美用例，它相当于 GraphX 中的映射-减少范式。这个函数需要实现两个函数，一个是从一个顶点向其相邻节点发送消息，另一个是在顶点级别聚合多个消息。这个过程被称为*消息传递*，并且描述如下：

```scala
def getBestCid(v: VState, msgs: Array[VState]): VertexId = {

  val candidates = msgs filter {

    msg =>
      msg.wcc > v.wcc ||
      (msg.wcc == v.wcc && msg.vtxV > v.vtxV) ||
      (msg.wcc == v.wcc && msg.vtxV > v.vtxV && msg.cId > v.cId)
    }

  if(candidates.isEmpty) {

    v.cId

  } else {

    candidates
     .sortBy {
       msg =>
         (msg.wcc, msg.vtxV, msg.cId)
      }
      .last
      .cId
  }

}

def sendMsg = (ctx: EdgeContext[VState, ED, Array[VState]]) => {

  ctx.sendToDst(
    Array(ctx.srcAttr)
  )

  ctx.sendToSrc(
    Array(ctx.dstAttr)
  )
}

def mergeMsg = (m1: Array[VState], m2: Array[VState]) => {
  m1 ++ m2
}

def msgs = subGraph.aggregateMessages(sendMsg, mergeMsg)

val initCIdGraph = subGraph.outerJoinVertices(msgs)((vId, vData, msgs) => {
  val newCId = getBestCid(vData, msgs.getOrElse(Array()))
  vData.cId = newCId
  vData
})

initCIdGraph.cache()
initCIdGraph.vertices.count()
initGraph.unpersist(blocking = false)
```

社区初始化过程的一个示例报告在*图 4*中。左图的节点按比例调整大小以反映其真实的 WCC 系数，已经初始化为四个不同的社区，**1**，**11**，**16**和**21**。

![消息传递](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_07_007.jpg)

图 4：WCC 社区初始化

尽管人们肯定会欣赏到一个`aggregateMessages`函数返回了相对一致的社区，但这种初始分区违反了我们之前定义的规则中的第三条。一些顶点（如**2**，**3**，**4**和**5**）属于一个中心不是中心节点的社区（顶点**1**属于社区**21**）。对于社区**11**也存在同样的问题。

#### 社区回传

为了解决这种不一致性并满足我们的第三个要求，任何顶点*x*必须将其更新的社区广播给所有系数较低的邻居，因为根据我们的第二条规则，只有这些排名较低的顶点可能成为*x*的边界节点。任何进一步的更新都将导致向较低排名的顶点传递新消息，依此类推，直到没有顶点会改变社区，此时我们的第三条规则将得到满足。

由于迭代之间不需要图的全局知识（例如计算全局 WCC 值），使用 GraphX 的 Pregel API 可以广泛并行化社区更新。Pregel 最初由 Google 开发，允许顶点接收来自先前迭代的消息，向其邻域发送新消息，并修改自己的状态，直到不能再发送更多消息。

### 注意

有关*Pregel*算法的更多信息，请参阅以下出版物：*G. Malewicz, M. H. Austern, A. J. Bik, J. C. Dehnert, I. Horn, N. Leiser, and G. Czajkowski, "Pregel: A system for large-scale graph processing," in Proceedings of the 2010 ACM SIGMOD International Conference on Management of Data, ser. SIGMOD '10\. New York, NY, USA: ACM, 2010, pp. 135-146\. [Online]. Available: [`doi.acm.org/10.1145/1807167.1807184`](http://doi.acm.org/10.1145/1807167.1807184)*

与之前提到的`aggregateMessages`函数类似，我们将顶点属性`VState`作为消息发送到顶点之间，作为 Pregel 超步的初始消息，使用默认值初始化的新对象（WCC 为 0）。

```scala
val initialMsg = new VState() 

```

当在顶点级别接收到多个消息时，我们只保留具有最高聚类系数的消息，如果系数相同，则保留具有最高度数的消息（然后是最高 ID）。我们为此目的在`VState`上创建了一个隐式排序：

```scala
implicit val VSOrdering: Ordering[VState] = Ordering.by({ state =>
  (state.wcc, state.vtxV, state.vId)
})

def compareState(c1: VState, c2: VState) = {
  List(c1, c2).sorted(VStateOrdering.reverse)
}

val mergeMsg = (c1: VState, c2: VState) => {
  compareState(c1, c2).head
}
```

遵循递归算法的相同原则，我们需要适当地定义一个中断子句，Pregel 应在该点停止发送和处理消息。这将在发送函数中完成，该函数以边三元组作为输入并返回消息的迭代器。如果顶点的社区在上一次迭代中发生了变化，顶点将发送其`VState`属性。在这种情况下，顶点将通知其排名较低的邻居其社区更新，但也会向自己发送信号以确认此成功广播。后者是我们的中断子句，因为它确保不会从给定节点发送更多消息（除非其社区在后续步骤中得到更新）：

```scala
def sendMsg = (t: EdgeTriplet[VState, ED]) => {

  val messages = mutable.Map[Long, VState]()
  val sorted = compareState(t.srcAttr, t.dstAttr)
  val (fromNode, toNode) = (sorted.head, sorted.last)
  if (fromNode.changed) {
    messages.put(fromNode.vId, fromNode)
    messages.put(toNode.vId, fromNode)
  }

  messages.toIterator

}
```

最后要实现的函数是 Pregel 算法的核心函数。在这里，我们定义了在顶点级别应用的逻辑，给定我们从`mergeMsg`函数中选择的唯一消息。我们确定了四种不同的消息可能性，每种消息都定义了应用于顶点状态的逻辑。

1.  如果消息是从 Pregel 发送的初始消息（顶点 ID 未设置，WCC 为空），我们不会更新顶点社区 ID。

1.  如果消息来自顶点本身，这是来自`sendMsg`函数的确认，我们将顶点状态设置为静默。

1.  如果消息（带有更高的 WCC）来自社区的中心节点，我们将更新顶点属性为这个新社区的边界节点。

1.  如果消息（带有更高的 WCC）来自社区的边界节点，这个顶点将成为自己社区的中心，并将进一步将此更新广播给其排名较低的网络。

```scala
def vprog = (vId: VertexId, state: VState, message: VState) => {

  if (message.vId >= 0L) {

    // message comes from myself
    // I stop spamming people
    if (message.vId == vId) {
      state.changed = false
    }

    // Sender is a center of its own community
    // I become a border node of its community
    if (message.cId == message.vId) {
      state.changed = false
      state.cId = message.cId
    }

    // Sender is a border node of a foreign community
    // I become a center of my own community
    // I broadcast this change downstream
    if (message.cId != message.vId) {
      state.changed = true
      state.cId = vId
    }

  }
  state

}
```

最后，我们使用`Pregel`对象的`apply`函数将这三个函数链接在一起。我们将迭代的最大次数设置为无穷大，因为我们依赖于我们使用确认类型消息定义的中断子句：

```scala
val pregelGraph: Graph[VState, ED] = Pregel.apply(
  initCIdGraph, 
  initialMsg, 
  Int.MaxValue 
)(
  vprog,
  sendMsg,
  mergeMsg
)

pregelGraph.cache()
pregelGraph.vertices.count()
```

虽然 Pregel 的概念很迷人，但它的实现确实不是。作为对这一巨大努力的回报，我们在*图 5*中展示了结果图。顶点**1**和**11**仍然属于社区**21**，这仍然有效，但社区**1**和**11**现在分别被替换为社区**15**和**5**，顶点具有最高的聚类系数、度或 ID 在其社区中，因此验证了第三个要求：

![社区反向传播](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_07_008.jpg)

图 5：社区反向传播更新

我们使用 Pregel API 根据之前介绍的规则创建了我们的初始社区集，但我们还没有完成。前面的图表明了一些改进，这些将在下一小节中讨论。然而，在继续之前，可以注意到这里没有使用特定的分区。如果我们要在社区节点之间发送多条消息，并且这些顶点位于不同的分区（因此位于不同的执行器），我们肯定不能优化与消息传递相关的网络流量。GraphX 中存在不同类型的分区，但没有一种允许我们使用顶点属性（如社区 ID）作为分区的度量。

在下面的简单函数中，我们提取所有的图三元组，根据社区元组构建一个哈希码，并使用标准的键值`HashPartitioner`类重新分区这个边 RDD。最后，我们根据这个重新分区的集合构建一个新的图，以确保从社区 C1 连接到社区 C2 的所有顶点都属于同一个分区：

```scala
def repartitionED: ClassTag = {

  val partitionedEdges = graph
    .triplets
    .map {
      e =>
        val cId1 = e.srcAttr.cId
        val cId2 = e.dstAttr.cId
        val hash = math.abs((cId1, cId2).hashCode())
        val partition = hash % partitions
        (partition, e)
    }
    .partitionBy(new HashPartitioner(partitions))
    .map {
      pair =>
        Edge(pair._2.srcId, pair._2.dstId, pair._2.attr)
    }

  Graph(graph.vertices, partitionedEdges)

}
```

### WCC 迭代

这个阶段的目的是让所有顶点在以下三个选项之间进行迭代选择，直到 WCC 值不能再被优化为止，此时我们的社区检测算法将收敛到其最佳图结构：

+   **留下**：留在它的社区里

+   **转移**：从它的社区移动并成为它的邻居的一部分

+   **移除**：离开它的社区，成为自己社区的一部分

对于每个顶点，最佳移动是最大化总 WCC 值的移动。与 Louvain 方法类似，每个移动都取决于要计算的全局分数，但我们转向这个算法的原因是，这个分数可以使用 Arnau Prat-Pérez 等人在*用于大型实际图的高质量、可扩展和并行社区检测*中定义的启发式方法来近似。因为这个启发式方法不需要计算所有内部三角形，顶点可以同时移动，因此这个过程可以设计成完全分散和高度可扩展的。

#### 收集社区统计信息

为了计算这个启发式方法，我们首先需要在社区级别聚合基本统计数据，比如元素数量和入站和出站链接数量，这两者都可以用简单的词频函数来表示。我们将它们组合在内存中，因为社区的数量将远远小于顶点的数量：

```scala
case class CommunityStats(
   r: Int,
   d: Double,
   b: Int
)

def getCommunityStatsED: ClassTag = {

  val cVert = graph
    .vertices
    .map(_._2.cId -> 1)
    .reduceByKey(_+_)
    .collectAsMap()

  val cEdges = graph
    .triplets
    .flatMap { t =>
      if(t.srcAttr.cId == t.dstAttr.cId){
        Iterator((("I", t.srcAttr.cId), 1))
      } else {
        Iterator(
          (("O", t.srcAttr.cId), 1), 
          (("O", t.dstAttr.cId), 1)
        )
      }
    }
    .reduceByKey(_+_)
    .collectAsMap()

  cVert.map {
    case (cId, cCount) =>
      val intEdges = cEdges.getOrElse(("I", cId), 0)
      val extEdges = cEdges.getOrElse(("O", cId), 0)
      val density = 2 * intEdges / math.pow(cCount, 2)
      (cId, CommunityStats(cCount, density, extEdges))
  } 

}
```

最后，我们收集顶点数量和社区统计信息（包括社区边缘密度），并将结果广播到我们所有的 Spark 执行器：

```scala
var communityStats = getCommunityStats(pregelGraph)
val bCommunityStats = sc.broadcast(communityStats)
```

### 提示

在这里理解`broadcast`方法的使用是很重要的。如果社区统计信息在 Spark 转换中使用，这个对象将被发送到执行器，以便后者处理每条记录。我们计算它们一次，将结果广播到执行器的缓存中，以便任何闭包可以在本地使用它们，从而节省大量不必要的网络传输。

#### WCC 计算

根据之前定义的一系列方程，每个顶点必须访问其所属的社区统计数据以及它与社区内任何顶点之间的三角形数量。为此，我们通过简单的消息传递来收集邻居，但只限于同一社区内的顶点，从而限制网络流量：

```scala
def collectCommunityEdgesED: ClassTag = {

  graph.outerJoinVertices(graph.aggregateMessages((e: EdgeContext[VState, ED, Array[VertexId]]) => {
    if(e.dstAttr.cId == e.srcAttr.cId){
      e.sendToDst(Array(e.srcId))
      e.sendToSrc(Array(e.dstId))
    }
  }, (e1: Array[VertexId], e2: Array[VertexId]) => {
    e1 ++ e2
  }))((vid, vState, vNeighbours) => {
    (vState, vNeighbours.getOrElse(Array()))
  })

}
```

同样，我们使用以下函数来计算共享三角形的数量。请注意，我们使用与默认的`triangleCount`方法相同的优化，只使用最小集合向最大集合发送消息。

```scala
def collectCommunityTrianglesED: ClassTag, ED]) = {

  graph.aggregateMessages((ctx: EdgeContext[(VState, Array[Long]), ED, Int]) => {
    if(ctx.srcAttr._1.cId == ctx.dstAttr._1.cId){
      val (smallSet, largeSet) = if (ctx.srcAttr._2.length < ctx.dstAttr._2.length) {
        (ctx.srcAttr._2.toSet, ctx.dstAttr._2.toSet)
      } else {
        (ctx.dstAttr._2.toSet, ctx.srcAttr._2.toSet)
      }
      val it = smallSet.iterator
      var counter: Int = 0
      while (it.hasNext) {
        val vid = it.next()
        if (
          vid != ctx.srcId &&
          vid != ctx.dstId &&
          largeSet.contains(vid)
        ) {
          counter += 1
        }
      }

      ctx.sendToSrc(counter)
      ctx.sendToDst(counter)

    }
  }, (e1: Int, e2: Int) => (e1 + e2))

}
```

我们计算并更新每个顶点的新 WCC 分数，作为社区邻域大小和社区三角形数量的函数。这个方程就是之前介绍 WCC 算法时描述的方程。我们计算一个分数，作为社区 C 内外闭合的三角形的比率，给定一个顶点*x*：

```scala
def updateGraphED: ClassTag = {

  val cNeighbours = collectCommunityEdges(graph)
  val cTriangles = collectCommunityTriangles(cNeighbours)

  cNeighbours.outerJoinVertices(cTriangles)(
    (vId, vData, tri) => {
      val s = vData._1
      val r = stats.value.get(s.cId).get.r

      // Core equation: compute WCC(v,C)
      val a = s.txC * s.vtxV
      val b = (s.txV * (r - 1 + s.vtxV_C).toDouble) 
      val wcc = a / b

      val vtxC = vData._2.length
      s.vtxV_C = s.vtxV – vtxC

      // Triangles are counted twice (incoming / outgoing)
      s.txC = tri.getOrElse(0) / 2
      s.wcc = wcc
      s
  })

}

val wccGraph = updateGraph(pregelGraph, bCommunityStats)
```

全球 WCC 值是每个顶点 WCC 的简单聚合，经过每个社区中元素数量的归一化。这个值也必须广播到 Spark 执行器中，因为它将在 Spark 转换中使用：

```scala
def computeWCCED: ClassTag: Double = {

  val total = graph.vertices
    .map {
      case (vId, vState) =>
        (vState.cId, vState.wcc)
    }
    .reduceByKey(_+_)
    .map {
      case (cId, wcc) =>
        cStats.value.get(cId).get.r * wcc
    }
    .sum

  total / graph.vertices.count

}

val wcc = computeWCC(wccGraph, bCommunityStats)
val bWcc = sc.broadCast(wcc)
```

#### WCC 迭代

考虑到将顶点*x*插入到社区**C**的成本，从/向社区**C**移除/转移*x**的成本可以表示为前者的函数，并且可以从三个参数**Θ[1]**、**Θ[2]**和**Θ[3]**中导出。这个启发式规定，对于每个顶点*x*，需要对其周围的每个社区**C**进行一次计算，并且可以并行进行，假设我们首先收集了所有社区统计数据：

![WCC 迭代](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_07_009.jpg)

**Θ[1]**、**Θ[2]**和**Θ[3]**的计算将不在此处报告（可在我们的 GitHub 上找到），但取决于社区密度、外部边缘和元素数量，所有这些都包含在我们之前定义的广播的`CommunityStats`对象集合中。最后值得一提的是，这个计算具有线性时间复杂度。

在每次迭代中，我们将收集任何顶点周围的不同社区，并使用我们在第六章中介绍的 Scalaz 的`mappend`聚合来聚合边的数量，*抓取基于链接的外部数据*。这有助于我们限制编写的代码量，并避免使用可变对象。

```scala
val cDegrees = itGraph.aggregateMessages((ctx: EdgeContext[VState, ED, Map[VertexId, Int]]) => {

  ctx.sendToDst(
    Map(ctx.srcAttr.cId -> 1)
  )

  ctx.sendToSrc(
    Map(ctx.dstAttr.cId -> 1)
  )

}, (e1: Map[VertexId, Int], e2: Map[VertexId, Int]) => {
  e1 |+| e2
})
```

利用社区统计数据、上一次迭代的 WCC 值、顶点数量和上述边的数量，我们现在可以估算将每个顶点*x*插入到周围社区**C**中的成本。我们找到每个顶点的最佳移动以及其周围社区的最佳移动，最终应用最大化 WCC 值的最佳移动。

最后，我们回调之前定义的一系列方法和函数，以更新每个顶点、每个社区的新 WCC 值，然后更新图分区本身，以查看所有这些变化是否导致了 WCC 的改善。如果 WCC 值无法再进行优化，算法就已经收敛到了最佳结构，最终我们返回一个包含顶点 ID 和该顶点所属的最终社区 ID 的顶点 RDD。

我们的测试社区图已经经过优化（虽然不是没有付出努力），并如*图 6*所示报告：

![WCC 迭代](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_07_010.jpg)

图 6：WCC 优化的社区

我们观察到之前预期的所有变化。顶点**1**和**11**现在分别属于它们预期的社区，分别是**5**和**11**。我们还注意到顶点 16 现在已经包括在其社区 11 中。

# GDELT 数据集

为了验证我们的实现，我们使用了我们在上一章中分析过的 GDELT 数据集。我们提取了所有的社区，并花了一些时间查看人名，以确定我们的社区聚类是否一致。社区的完整图片报告在*图 7*中，并且是使用 Gephi 软件实现的，只导入了前几千个连接。

![GDELT 数据集](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_07_11-1.jpg)

图 7：2021 年 1 月 12 日的社区检测

我们首先观察到，我们检测到的大多数社区与我们在力导向布局中可以直观看到的社区完全一致，这给算法准确性带来了很高的信心水平。

## 鲍伊效应

任何明确定义的社区都已经被正确识别，而不太明显的社区是围绕着像大卫·鲍伊这样的高度连接的顶点而形成的。大卫·鲍伊这个名字在 GDELT 文章中被频繁提及，与许多不同的人一起，以至于在 2016 年 1 月 12 日，它变得太大，无法成为其逻辑社区（音乐行业）的一部分，并形成了一个更广泛的社区，影响了其周围的所有顶点。这里绝对存在一个有趣的模式，因为这种社区结构为我们提供了关于特定人物在特定日期可能成为突发新闻文章的明确见解。

观察大卫·鲍伊在*图 8*中最接近的社区，我们观察到节点之间高度相互连接，这是因为我们将其称为*鲍伊效应*。事实上，来自许多不同社区的许多致敬使得跨不同社区形成的三角形数量异常高。结果是，它将不同的逻辑社区彼此靠近，这些社区在理论上本不应该靠近，比如*70 年代*的摇滚明星偶像与宗教人士之间的接近。

小世界现象是由斯坦利·米尔格拉姆在 60 年代定义的，它指出每个人都通过少数熟人相连。美国演员凯文·贝肯甚至建议他与其他任何演员之间最多只能通过 6 个连接相连，也被称为*贝肯数*（[`oracleofbacon.org/`](https://oracleofbacon.org/)）。

在那一天，教皇弗朗西斯和米克·贾格尔的*凯文·贝肯数*仅为 1，这要归功于主教吉安弗兰科·拉瓦西在推特上提到了大卫·鲍伊。

![鲍伊效应](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_07-12-1.jpg)

图 8：围绕大卫·鲍伊的社区，1 月 12 日

尽管鲍伊效应，由于其作为突发新闻文章的性质，在特定的图结构上是一个真正的模式，但它的影响可以通过基于名称频率计数的加权边来最小化。事实上，来自 GDELT 数据集的一些随机噪音可能足以关闭来自两个不同社区的关键三角形，从而将它们彼此靠近，无论这个关键边的权重如何。这种限制对于所有非加权算法都是普遍存在的，并且需要一个预处理阶段来减少这种不需要的噪音。

## 较小的社区

然而，我们可以观察到一些更明确定义的社区，比如英国政治家托尼·布莱尔、大卫·卡梅伦和鲍里斯·约翰逊，或者电影导演克里斯托弗·诺兰、马丁·斯科塞斯和昆汀·塔伦蒂诺。从更广泛的角度来看，我们可以检测到明确定义的社区，比如网球运动员、足球运动员、艺术家或特定国家的政治家。作为准确性的不容置疑的证据，我们甚至检测到马特·勒布朗、考特尼·考克斯、马修·佩里和詹妮弗·安妮斯顿作为同一个《老友记》社区的一部分，卢克·天行者、阿纳金·天行者、乔巴卡和帕尔帕廷皇帝作为《星球大战》社区的一部分，以及最近失去的女演员凯丽·费雪。职业拳击手社区的一个例子如*图 9*所示：

![较小的社区](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_07_13-1.jpg)

图 9：职业拳击手社区

## 使用 Accumulo 单元格级安全

我们之前已经讨论了 Accumulo 中单元级安全的性质。在这里我们生成的图的背景下，安全性的有用性可以很好地模拟。如果我们配置 Accumulo，使得包含大卫·鲍伊的行与所有其他行标记不同的安全标签，那么我们可以打开和关闭鲍伊的效应。任何具有完全访问权限的 Accumulo 用户将看到之前提供的完整图。然后，如果我们将该用户限制在除了大卫·鲍伊之外的所有内容（在`AccumuloReader`中对授权进行简单更改），那么我们将看到以下图。这个新图非常有趣，因为它具有多种用途：

+   它消除了大卫·鲍伊死亡的社交媒体效应所产生的噪音，从而揭示了真正涉及的社区

+   它消除了实体之间的许多虚假链接，从而增加了它们的 Bacon 数，并显示了它们真正的关系

+   它证明了可以移除图中的一个关键人物，仍然保留大量有用信息，从而证明了之前关于出于安全原因移除关键实体的观点（如*单元安全*中讨论的）。

当然，还必须说，通过移除一个实体，我们也可能移除实体之间的关键关系；也就是说，联系链效应，这在特定试图关联个体实体时是一个负面因素，然而，社区仍然保持完整。

![使用 Accumulo 单元级安全](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_07_14.jpg)

图 10：大卫·鲍伊的受限访问社区

# 总结

我们已经讨论并构建了一个利用安全和稳健架构的图社区的实际实现。我们已经概述了在社区检测问题空间中没有正确或错误的解决方案，因为它严重依赖于使用情况。例如，在社交网络环境中，其中顶点紧密连接在一起（一条边表示两个用户之间的真实连接），边的权重并不重要，而三角形方法可能更重要。在电信行业中，人们可能对基于给定用户 A 对用户 B 的频率呼叫的社区感兴趣，因此转向加权算法，如 Louvain。

我们感谢构建这个社区算法远非易事，也许超出了本书的目标，但它涉及了 Spark 中图处理的所有技术，使 GraphX 成为一个迷人且可扩展的工具。我们介绍了消息传递、Pregel、图分区和变量广播的概念，支持了 Elasticsearch 和 Accumulo 中的实际实现。

在下一章中，我们将应用我们在这里学到的图论概念到音乐行业，学习如何使用音频信号、傅立叶变换和*PageRank*算法构建音乐推荐引擎。
