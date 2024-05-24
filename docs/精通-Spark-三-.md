# 精通 Spark（三）

> 原文：[`zh.annas-archive.org/md5/5211DAC7494A736A2B4617944224CFC3`](https://zh.annas-archive.org/md5/5211DAC7494A736A2B4617944224CFC3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：用 H2O 扩展 Spark

H2O 是一个由[`h2o.ai/`](http://h2o.ai/)开发的开源系统，用于机器学习。它提供了丰富的机器学习算法和基于 Web 的数据处理用户界面。它提供了使用多种语言开发的能力：Java、Scala、Python 和 R。它还具有与 Spark、HDFS、Amazon S3、SQL 和 NoSQL 数据库进行接口的能力。本章将集中讨论 H2O 与 Apache Spark 的集成，使用 H2O 的**Sparkling Water**组件。将使用 Scala 开发一个简单的示例，基于真实数据创建一个深度学习模型。本章将：

+   检查 H2O 功能

+   考虑必要的 Spark H2O 环境

+   检查 Sparkling Water 架构

+   介绍并使用 H2O Flow 界面

+   通过示例介绍深度学习

+   考虑性能调优

+   检查数据质量

下一步将概述 H2O 功能和本章中将使用的 Sparkling Water 架构。

# 概述

由于本章只能检查和使用 H2O 功能的一小部分，我认为提供一个功能区域列表将是有用的。此列表取自[`h2o.ai/`](http://h2o.ai/)网站的[`h2o.ai/product/algorithms/`](http://h2o.ai/product/algorithms/)，基于数据整理、建模和对结果模型进行评分：

| 过程 | 模型 | 评分工具 |
| --- | --- | --- |
| 数据概要分析 | 广义线性模型（GLM） | 预测 |
| 摘要统计 | 决策树 | 混淆矩阵 |
| 聚合、过滤、分箱和派生列 | 梯度提升（GBM） | AUC |
| 切片、对数变换和匿名化 | K 均值 | 命中率 |
| 变量创建 | 异常检测 | PCA 得分 |
| PCA | 深度学习 | 多模型评分 |
| 训练和验证抽样计划 | 朴素贝叶斯 |   |
|   | 网格搜索 |   |

下一节将解释本章中 Spark 和 H2O 示例使用的环境，并解释遇到的一些问题。

# 处理环境

如果你们中有人查看过我的基于 Web 的博客，或者阅读过我的第一本书《大数据简化》，你会发现我对大数据集成和大数据工具的连接很感兴趣。这些系统都不是独立存在的。数据将从上游开始，在 Spark 加上 H2O 中进行处理，然后结果将被存储，或者移动到 ETL 链中的下一步。根据这个想法，在这个示例中，我将使用 Cloudera CDH HDFS 进行存储，并从那里获取我的数据。我也可以很容易地使用 S3、SQL 或 NoSQL 数据库。

在开始本章的开发工作时，我安装并使用了 Cloudera CDH 4.1.3 集群。我还安装了各种 Spark 版本，并可供使用。它们如下：

+   将 Spark 1.0 安装为 CentOS 服务

+   下载并安装的 Spark 1.2 二进制文件

+   从源快照构建的 Spark 1.3

我认为我会进行实验，看看哪些 Spark 和 Hadoop 的组合可以一起工作。我在[`h2o-release.s3.amazonaws.com/sparkling-water/master/98/index.html`](http://h2o-release.s3.amazonaws.com/sparkling-water/master/98/index.html)下载了 Sparkling Water 的 0.2.12-95 版本。我发现 1.0 版本的 Spark 与 H2O 一起工作，但缺少 Spark 库。许多基于 Sparkling Water 的示例中使用的一些功能是可用的。Spark 版本 1.2 和 1.3 导致出现以下错误：

```scala
15/04/25 17:43:06 ERROR netty.NettyTransport: failed to bind to /192.168.1.103:0, shutting down Netty transport
15/04/25 17:43:06 WARN util.Utils: Service 'sparkDriver' could not bind on port 0\. Attempting port 1.

```

尽管 Spark 中正确配置了主端口号，但没有被识别，因此 H2O 应用无法连接到 Spark。在与 H2O 的工作人员讨论了这个问题后，我决定升级到 H2O 认证版本的 Hadoop 和 Spark。应该使用的推荐系统版本可在[`h2o.ai/product/recommended-systems-for-h2o/`](http://h2o.ai/product/recommended-systems-for-h2o/)上找到。

我使用 Cloudera Manager 界面的包管理页面将我的 CDH 集群从版本 5.1.3 升级到版本 5.3。这自动提供了 Spark 1.2——这个版本已经集成到 CDH 集群中。这解决了所有与 H2O 相关的问题，并为我提供了一个经过 H2O 认证的 Hadoop 和 Spark 环境。

# 安装 H2O

为了完整起见，我将向您展示如何下载、安装和使用 H2O。尽管我最终选择了版本 0.2.12-95，但我首先下载并使用了 0.2.12-92。本节基于早期的安装，但用于获取软件的方法是相同的。下载链接会随时间变化，因此请在[`h2o.ai/download/`](http://h2o.ai/download/)上关注 Sparkling Water 下载选项。

这将获取压缩的 Sparkling Water 发布，如下所示的 CentOS Linux 长文件列表：

```scala
[hadoop@hc2r1m2 h2o]$ pwd ; ls -l
/home/hadoop/h2o
total 15892
-rw-r--r-- 1 hadoop hadoop 16272364 Apr 11 12:37 sparkling-water-0.2.12-92.zip

```

这个压缩的发布文件使用 Linux 的`unzip`命令解压，得到一个 Sparkling Water 发布文件树：

```scala
[hadoop@hc2r1m2 h2o]$ unzip sparkling-water-0.2.12-92.zip

[hadoop@hc2r1m2 h2o]$ ls -d sparkling-water*
sparkling-water-0.2.12-92  sparkling-water-0.2.12-92.zip

```

我已将发布树移动到`/usr/local/`目录下，使用 root 账户，并创建了一个名为`h2o`的简单符号链接到发布版本。这意味着我的基于 H2O 的构建可以引用这个链接，并且不需要随着新版本的 Sparkling Water 的获取而更改。我还使用 Linux 的`chmod`命令确保我的开发账户 hadoop 可以访问发布版本。

```scala
[hadoop@hc2r1m2 h2o]$ su -
[root@hc2r1m2 ~]# cd /home/hadoop/h2o
[root@hc2r1m2 h2o]# mv sparkling-water-0.2.12-92 /usr/local
[root@hc2r1m2 h2o]# cd /usr/local

[root@hc2r1m2 local]# chown -R hadoop:hadoop sparkling-water-0.2.12-92
[root@hc2r1m2 local]#  ln –s sparkling-water-0.2.12-92 h2o

[root@hc2r1m2 local]# ls –lrt  | grep sparkling
total 52
drwxr-xr-x   6 hadoop hadoop 4096 Mar 28 02:27 sparkling-water-0.2.12-92
lrwxrwxrwx   1 root   root     25 Apr 11 12:43 h2o -> sparkling-water-0.2.12-92

```

发布已安装在我的 Hadoop CDH 集群的所有节点上。

# 构建环境

从过去的例子中，您会知道我偏爱 SBT 作为开发 Scala 源代码示例的构建工具。我已在 Linux CentOS 6.5 服务器上使用 hadoop 开发账户创建了一个名为`hc2r1m2`的开发环境。开发目录名为`h2o_spark_1_2`。

```scala
[hadoop@hc2r1m2 h2o_spark_1_2]$ pwd
/home/hadoop/spark/h2o_spark_1_2

```

我的 SBT 构建配置文件名为`h2o.sbt`，位于这里；它包含以下内容：

```scala
[hadoop@hc2r1m2 h2o_spark_1_2]$ more h2o.sbt

name := "H 2 O"

version := "1.0"

scalaVersion := "2.10.4"

libraryDependencies += "org.apache.hadoop" % "hadoop-client" % "2.3.0"

libraryDependencies += "org.apache.spark" % "spark-core"  % "1.2.0" from "file:///opt/cloudera/parcels/CDH-5.3.3-1.cdh5.3.3.p0.5/jars/spark-assembly-1.2.0-cdh5.3.3-hadoop2.5.0-cdh5.3.3.jar"

libraryDependencies += "org.apache.spark" % "mllib"  % "1.2.0" from "file:///opt/cloudera/parcels/CDH-5.3-1.cdh5.3.3.p0.5/jars/spark-assembly-1.2.0-cdh5.3.3-hadoop2.5.0-cdh5.3.3.jar"

libraryDependencies += "org.apache.spark" % "sql"  % "1.2.0" from "file:///opt/cloudera/parcels/CDH-5.3.3-1.cdh5.3.3.p0.5/jars/spark-assembly-1.2.0-cdh5.3.3-hadoop2.5.0-cdh5.3.3.jar"

libraryDependencies += "org.apache.spark" % "h2o"  % "0.2.12-95" from "file:///usr/local/h2o/assembly/build/libs/sparkling-water-assembly-0.2.12-95-all.jar"

libraryDependencies += "hex.deeplearning" % "DeepLearningModel"  % "0.2.12-95" from "file:///usr/local/h2o/assembly/build/libs/sparkling-water-assembly-0.2.12-95-all.jar"

libraryDependencies += "hex" % "ModelMetricsBinomial"  % "0.2.12-95" from "file:///usr/local/h2o/assembly/build/libs/sparkling-water-assembly-0.2.12-95-all.jar"

libraryDependencies += "water" % "Key"  % "0.2.12-95" from "file:///usr/local/h2o/assembly/build/libs/sparkling-water-assembly-0.2.12-95-all.jar"

libraryDependencies += "water" % "fvec"  % "0.2.12-95" from "file:///usr/local/h2o/assembly/build/libs/sparkling-water-assembly-0.2.12-95-all.jar"

```

我在之前的章节中提供了 SBT 配置示例，所以我不会在这里逐行详细介绍。我使用基于文件的 URL 来定义库依赖，并从 Cloudera parcel 路径获取 CDH 安装的 Hadoop JAR 文件。Sparkling Water JAR 路径被定义为`/usr/local/h2o/`，这刚刚创建。

我在这个开发目录中使用一个名为`run_h2o.bash`的 Bash 脚本来执行基于 H2O 的示例代码。它将应用程序类名作为参数，并如下所示：

```scala
[hadoop@hc2r1m2 h2o_spark_1_2]$ more run_h2o.bash

#!/bin/bash

SPARK_HOME=/opt/cloudera/parcels/CDH
SPARK_LIB=$SPARK_HOME/lib
SPARK_BIN=$SPARK_HOME/bin
SPARK_SBIN=$SPARK_HOME/sbin
SPARK_JAR=$SPARK_LIB/spark-assembly-1.2.0-cdh5.3.3-hadoop2.5.0-cdh5.3.3.jar

H2O_PATH=/usr/local/h2o/assembly/build/libs
H2O_JAR=$H2O_PATH/sparkling-water-assembly-0.2.12-95-all.jar

PATH=$SPARK_BIN:$PATH
PATH=$SPARK_SBIN:$PATH
export PATH

cd $SPARK_BIN

./spark-submit \
 --class $1 \
 --master spark://hc2nn.semtech-solutions.co.nz:7077  \
 --executor-memory 85m \
 --total-executor-cores 50 \
 --jars $H2O_JAR \
 /home/hadoop/spark/h2o_spark_1_2/target/scala-2.10/h-2-o_2.10-1.0.jar

```

这个 Spark 应用程序提交的示例已经涵盖过了，所以我不会详细介绍。将执行器内存设置为正确的值对避免内存不足问题和性能问题至关重要。这将在*性能调优*部分进行讨论。

与之前的例子一样，应用 Scala 代码位于`development`目录级别下的`src/main/scala`子目录中。下一节将检查 Apache Spark 和 H2O 的架构。

# 架构

本节中的图表来自[`h2o.ai/`](http://h2o.ai/)网站，网址为[`h2o.ai/blog/2014/09/how-sparkling-water-brings-h2o-to-spark/`](http:// http://h2o.ai/blog/2014/09/how-sparkling-water-brings-h2o-to-spark/)，以清晰地描述 H2O Sparkling Water 如何扩展 Apache Spark 的功能。H2O 和 Spark 都是开源系统。Spark MLlib 包含大量功能，而 H2O 通过一系列额外的功能扩展了这一点，包括深度学习。它提供了用于*转换*（转换）、建模和评分数据的工具。它还提供了一个基于 Web 的用户界面进行交互。

下一个图表，来自[`h2o.ai/`](http://h2o.ai/)，显示了 H2O 如何与 Spark 集成。正如我们已经知道的，Spark 有主服务器和工作服务器；工作服务器创建执行器来执行实际工作。运行基于 Sparkling water 的应用程序发生以下步骤：

1.  Spark 的`submit`命令将闪亮的水 JAR 发送到 Spark 主服务器。

1.  Spark 主服务器启动工作服务器，并分发 JAR 文件。

1.  Spark 工作程序启动执行器 JVM 来执行工作。

1.  Spark 执行器启动 H2O 实例。

H2O 实例嵌入了 Executor JVM，因此它与 Spark 共享 JVM 堆空间。当所有 H2O 实例都启动时，H2O 形成一个集群，然后 H2O 流 Web 界面可用。

![架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_01.jpg)

上图解释了 H2O 如何适应 Apache Spark 架构，以及它是如何启动的，但是数据共享呢？数据如何在 Spark 和 H2O 之间传递？下图解释了这一点：

![架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_02.jpg)

为 H2O 和 Sparkling Water 创建了一个新的 H2O RDD 数据结构。它是一个层，位于 H2O 框架的顶部，其中的每一列代表一个数据项，并且独立压缩以提供最佳的压缩比。

在本章后面呈现的深度学习示例中，您将看到已经从 Spark 模式 RDD 和列数据项隐式创建了一个数据框，并且收入已被枚举。我现在不会详细解释这一点，因为稍后会解释，但这是上述架构的一个实际示例：

```scala
  val testFrame:DataFrame = schemaRddTest
  testFrame.replace( testFrame.find("income"), testFrame.vec("income").toEnum)
```

在本章中将处理的基于 Scala 的示例中，将发生以下操作：

1.  数据来自 HDFS，并存储在 Spark RDD 中。

1.  Spark SQL 用于过滤数据。

1.  Spark 模式 RDD 转换为 H2O RDD。

1.  基于 H2O 的处理和建模正在进行。

1.  结果被传递回 Spark 进行准确性检查。

到目前为止，已经检查了 H2O 的一般架构，并且已经获取了用于使用的产品。已经解释了开发环境，并且已经考虑了 H2O 和 Spark 集成的过程。现在，是时候深入了解 H2O 的实际用法了。不过，首先必须获取一些真实世界的数据用于建模。

# 数据来源

自从我已经在第二章中使用了**人工神经网络**（**ANN**）功能，*Apache Spark MLlib*，来对图像进行分类，似乎只有使用 H2O 深度学习来对本章中的数据进行分类才合适。为了做到这一点，我需要获取适合分类的数据集。我需要包含图像标签的图像数据，或者包含向量和标签的数据，以便我可以强制 H2O 使用其分类算法。

MNIST 测试和训练图像数据来自[ann.lecun.com/exdb/mnist/](http://ann.lecun.com/exdb/mnist/)。它包含 50,000 个训练行和 10,000 个测试行。它包含数字 0 到 9 的数字图像和相关标签。

在撰写本文时，我无法使用这些数据，因为 H2O Sparkling water 中存在一个 bug，限制了记录大小为 128 个元素。MNIST 数据的记录大小为*28 x 28 + 1*，包括图像和标签：

```scala
15/05/14 14:05:27 WARN TaskSetManager: Lost task 0.0 in stage 9.0 (TID 256, hc2r1m4.semtech-solutions.co.nz): java.lang.ArrayIndexOutOfBoundsException: -128
```

在您阅读此文时，这个问题应该已经得到解决并发布，但在短期内，我从[`www.cs.toronto.edu/~delve/data/datasets.html`](http://www.cs.toronto.edu/~delve/data/datasets.html)获取了另一个名为 income 的数据集，其中包含了加拿大雇员的收入数据。以下信息显示了属性和数据量。它还显示了数据中的列列表和一行样本数据：

```scala
Number of attributes: 16
Number of cases: 45,225

age workclass fnlwgt education educational-num marital-status occupation relationship race gender capital-gain capital-loss hours-per-week native-country income

39, State-gov, 77516, Bachelors, 13, Never-married, Adm-clerical, Not-in-family, White, Male, 2174, 0, 40, United-States, <=50K

```

我将枚举数据中的最后一列——收入等级，所以`<=50k`将枚举为`0`。这将允许我强制 H2O 深度学习算法进行分类而不是回归。我还将使用 Spark SQL 来限制数据列，并过滤数据。

数据质量在创建本章描述的基于 H2O 的示例时至关重要。下一节将探讨可以采取的步骤来改善数据质量，从而节省时间。

# 数据质量

当我将 HDFS 中的 CSV 数据文件导入到我的 Spark Scala H2O 示例代码时，我可以过滤传入的数据。以下示例代码包含两行过滤器；第一行检查数据行是否为空，而第二行检查每个数据行中的最后一列（收入）是否为空：

```scala
val testRDD  = rawTestData
  .filter(!_.isEmpty)
  .map(_.split(","))
  .filter( rawRow => ! rawRow(14).trim.isEmpty )
```

我还需要清理原始数据。有两个数据集，一个用于训练，一个用于测试。训练和测试数据必须具备以下特点：

+   相同数量的列

+   相同的数据类型

+   代码中必须允许空值

+   枚举类型的值必须匹配——尤其是标签

我遇到了与枚举标签列收入及其包含的值相关的错误。我发现我的测试数据集行以句点字符“。”结尾。处理时，这导致训练和测试数据的值在枚举时不匹配。

因此，我认为应该花费时间和精力来保障数据质量，作为训练和测试机器学习功能的预备步骤，以免浪费时间和产生额外成本。

# 性能调优

如果在 Spark 网络用户界面中看到以下错误，就需要监控 Spark 应用程序错误和标准输出日志：

```scala
05-15 13:55:38.176 192.168.1.105:54321   6375   Thread-10 ERRR: Out of Memory and no swap space left from hc2r1m1.semtech-solutions.co.nz/192.168.1.105:54321

```

如果您遇到应用执行器似乎没有响应的情况，可能需要调整执行器内存。如果您在执行器日志中看到以下错误，就需要这样做：

```scala
05-19 13:46:57.300 192.168.1.105:54321   10044  Thread-11 WARN: Unblock allocations; cache emptied but memory is low:  OOM but cache is emptied:  MEM_MAX = 89.5 MB, DESIRED_CACHE = 96.4 MB, CACHE = N/A, POJO = N/A, this request bytes = 36.4 MB

```

这可能会导致循环，因为应用程序请求的内存超过了可用内存，因此会等待下一次迭代重试。应用程序似乎会挂起，直到执行器被终止，并在备用节点上重新执行任务。由于这些问题，短任务的运行时间可能会大大延长。

监控 Spark 日志以查找这些类型的错误。在前面的示例中，更改`spark-submit`命令中的执行器内存设置可以消除错误，并大大减少运行时间。所请求的内存值已经降低到低于可用内存的水平。

```scala
 --executor-memory 85m

```

# 深度学习

神经网络在第二章中介绍，*Apache Spark MLlib*。本章在此基础上介绍了深度学习，它使用深度神经网络。这些是功能丰富的神经网络，包含额外的隐藏层，因此它们提取数据特征的能力增强。这些网络通常是前馈网络，其中特征特性是输入到输入层神经元的输入。然后这些神经元激活并将激活传播到隐藏层神经元，最终到输出层，应该呈现特征标签值。然后通过网络（至少在反向传播中）传播输出中的错误，调整神经元连接权重矩阵，以便在训练期间减少分类错误。

![深度学习](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_03.jpg)

在[H2O 手册](https://leanpub.com/deeplearning/read)中描述的前面的示例图显示了一个深度学习网络，左侧有四个输入神经元，中间有两个隐藏层，右侧有两个输出神经元。箭头显示了神经元之间的连接以及激活通过网络的方向。

这些网络功能丰富，因为它们提供以下选项：

+   多种训练算法

+   自动网络配置

+   能够配置许多选项

+   结构

隐藏层结构

+   训练

学习率、退火和动量

因此，在对深度学习进行简要介绍之后，现在是时候看一些基于 Scala 的示例代码了。H2O 提供了大量的功能；构建和运行网络所需的类已经为您开发好了。您只需要做以下事情：

+   准备数据和参数

+   创建和训练模型

+   使用第二个数据集验证模型

+   对验证数据集输出进行评分

在评分模型时，您必须希望以百分比形式获得高值。您的模型必须能够准确预测和分类您的数据。

## 示例代码 - 收入

本节将使用之前的加拿大收入数据源，检查基于 Scala 的 H2O Sparkling Water 深度学习示例。首先，导入了 Spark（`Context`、`Conf`、`mllib`和`RDD`）和 H2O（`h2o`、`deeplearning`和`water`）类：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf

import hex.deeplearning.{DeepLearningModel, DeepLearning}
import hex.deeplearning.DeepLearningModel.DeepLearningParameters
import org.apache.spark.h2o._
import org.apache.spark.mllib
import org.apache.spark.mllib.feature.{IDFModel, IDF, HashingTF}
import org.apache.spark.rdd.RDD
import water.Key
```

接下来定义了一个名为`h2o_spark_dl2`的应用程序类，创建了主 URL，然后基于此 URL 创建了一个配置对象和应用程序名称。然后使用配置对象创建 Spark 上下文：

```scala
object h2o_spark_dl2  extends App
{
  val sparkMaster = "spark://hc2nn.semtech-solutions.co.nz:7077"
  val appName = "Spark h2o ex1"
  val conf = new SparkConf()

  conf.setMaster(sparkMaster)
  conf.setAppName(appName)

  val sparkCxt = new SparkContext(conf)
```

从 Spark 上下文创建 H2O 上下文，还有一个 SQL 上下文：

```scala
  import org.apache.spark.h2o._
  implicit val h2oContext = new org.apache.spark.h2o.H2OContext(sparkCxt).start()

  import h2oContext._
  import org.apache.spark.sql._

  implicit val sqlContext = new SQLContext(sparkCxt)
```

使用`openFlow`命令启动 H2O Flow 用户界面：

```scala
  import sqlContext._
  openFlow
```

现在定义了数据文件的训练和测试（在 HDFS 上）使用服务器 URL、路径和文件名：

```scala
  val server    = "hdfs://hc2nn.semtech-solutions.co.nz:8020"
  val path      = "/data/spark/h2o/"

  val train_csv =  server + path + "adult.train.data" // 32,562 rows
  val test_csv  =  server + path + "adult.test.data"  // 16,283 rows
```

使用 Spark 上下文的`textFile`方法加载基于 CSV 的训练和测试数据：

```scala
  val rawTrainData = sparkCxt.textFile(train_csv)
  val rawTestData  = sparkCxt.textFile(test_csv)
```

现在，模式是根据属性字符串定义的。然后，通过使用一系列`StructField`，基于每一列拆分字符串，创建了一个模式变量。数据类型保留为字符串，true 值允许数据中的空值：

```scala
  val schemaString = "age workclass fnlwgt education “ + 
“educationalnum maritalstatus " + "occupation relationship race 
gender “ + “capitalgain capitalloss " + hoursperweek nativecountry income"

  val schema = StructType( schemaString.split(" ")
      .map(fieldName => StructField(fieldName, StringType, true)))
```

原始 CSV 行“训练”和测试数据现在通过逗号分割成列。数据被过滤以确保最后一列（“收入”）不为空。实际数据行是从原始 CSV 数据中的十五个（0-14）修剪的元素创建的。训练和测试数据集都经过处理：

```scala
  val trainRDD  = rawTrainData
         .filter(!_.isEmpty)
         .map(_.split(","))
         .filter( rawRow => ! rawRow(14).trim.isEmpty )
         .map(rawRow => Row(
               rawRow(0).toString.trim,  rawRow(1).toString.trim,
               rawRow(2).toString.trim,  rawRow(3).toString.trim,
               rawRow(4).toString.trim,  rawRow(5).toString.trim,
               rawRow(6).toString.trim,  rawRow(7).toString.trim,
               rawRow(8).toString.trim,  rawRow(9).toString.trim,
               rawRow(10).toString.trim, rawRow(11).toString.trim,
               rawRow(12).toString.trim, rawRow(13).toString.trim,
               rawRow(14).toString.trim
                           )
             )

  val testRDD  = rawTestData
         .filter(!_.isEmpty)
         .map(_.split(","))
         .filter( rawRow => ! rawRow(14).trim.isEmpty )
         .map(rawRow => Row(
               rawRow(0).toString.trim,  rawRow(1).toString.trim,
               rawRow(2).toString.trim,  rawRow(3).toString.trim,
               rawRow(4).toString.trim,  rawRow(5).toString.trim,
               rawRow(6).toString.trim,  rawRow(7).toString.trim,
               rawRow(8).toString.trim,  rawRow(9).toString.trim,
               rawRow(10).toString.trim, rawRow(11).toString.trim,
               rawRow(12).toString.trim, rawRow(13).toString.trim,
               rawRow(14).toString.trim
                           )
             )
```

现在使用 Spark 上下文的`applySchema`方法，为训练和测试数据集创建了 Spark Schema RDD 变量：

```scala
  val trainSchemaRDD = sqlContext.applySchema(trainRDD, schema)
  val testSchemaRDD  = sqlContext.applySchema(testRDD,  schema)
```

为训练和测试数据创建临时表：

```scala
  trainSchemaRDD.registerTempTable("trainingTable")
  testSchemaRDD.registerTempTable("testingTable")
```

现在，对这些临时表运行 SQL，既可以过滤列的数量，也可以潜在地限制数据。我可以添加`WHERE`或`LIMIT`子句。这是一个有用的方法，使我能够操纵基于列和行的数据：

```scala
  val schemaRddTrain = sqlContext.sql(
    """SELECT
         |age,workclass,education,maritalstatus,
         |occupation,relationship,race,
         |gender,hoursperweek,nativecountry,income
         |FROM trainingTable """.stripMargin)

  val schemaRddTest = sqlContext.sql(
    """SELECT
         |age,workclass,education,maritalstatus,
         |occupation,relationship,race,
         |gender,hoursperweek,nativecountry,income
         |FROM testingTable """.stripMargin)
```

现在从数据中创建了 H2O 数据框。每个数据集中的最后一列（收入）是枚举的，因为这是将用于数据的深度学习标签的列。此外，枚举此列会强制深度学习模型进行分类而不是回归：

```scala
  val trainFrame:DataFrame = schemaRddTrain
  trainFrame.replace( trainFrame.find("income"),        trainFrame.vec("income").toEnum)
  trainFrame.update(null)

  val testFrame:DataFrame = schemaRddTest
  testFrame.replace( testFrame.find("income"),        testFrame.vec("income").toEnum)
  testFrame.update(null)
```

现在保存了枚举结果数据收入列，以便可以使用该列中的值对测试模型预测值进行评分：

```scala
  val testResArray = schemaRddTest.collect()
  val sizeResults  = testResArray.length
  var resArray     = new ArrayDouble

  for ( i <- 0 to ( resArray.length - 1)) {
     resArray(i) = testFrame.vec("income").at(i)
  }
```

现在，深度学习模型参数已经设置好，包括迭代次数（或迭代次数）-用于训练和验证的数据集以及标签列收入，这将用于对数据进行分类。此外，我们选择使用变量重要性来确定数据中哪些数据列最重要。然后创建深度学习模型：

```scala
  val dlParams = new DeepLearningParameters()

  dlParams._epochs               = 100
  dlParams._train                = trainFrame
  dlParams._valid                = testFrame
  dlParams._response_column      = 'income
  dlParams._variable_importances = true
  val dl = new DeepLearning(dlParams)
  val dlModel = dl.trainModel.get
```

然后对模型进行针对测试数据集的评分，进行预测，这些收入预测值与先前存储的枚举测试数据收入值进行比较。最后，从测试数据中输出准确率百分比：

```scala
  val testH2oPredict  = dlModel.score(schemaRddTest )('predict)
  val testPredictions  = toRDDDoubleHolder
          .collect.map(_.result.getOrElse(Double.NaN))
  var resAccuracy = 0
  for ( i <- 0 to ( resArray.length - 1)) {
    if (  resArray(i) == testPredictions(i) )
      resAccuracy = resAccuracy + 1
  }

  println()
  println( ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>" )
  println( ">>>>>> Model Test Accuracy = "
       + 100*resAccuracy / resArray.length  + " % " )
  println( ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>" )
  println()
```

在最后一步中，应用程序被停止，通过`shutdown`调用终止 H2O 功能，然后停止 Spark 上下文：

```scala
  water.H2O.shutdown()
  sparkCxt.stop()

  println( " >>>>> Script Finished <<<<< " )

} // end application
```

基于训练数据集的 32,000 条记录和测试数据集的 16,000 条收入记录，这个深度学习模型非常准确。它达到了`83`％的准确度水平，这对于几行代码、小数据集和仅 100 个迭代次数来说是令人印象深刻的，如运行输出所示：

```scala
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
>>>>>> Model Test Accuracy = 83 %
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

```

在下一节中，我将检查处理 MNIST 数据所需的一些编码，尽管由于编码时的 H2O 限制，该示例无法完成。

## 示例代码-MNIST

由于 MNIST 图像数据记录非常庞大，在创建 Spark SQL 模式和处理数据记录时会出现问题。此数据中的记录以 CSV 格式形成，并由 28 x 28 数字图像组成。然后，每行以图像的标签值终止。我通过定义一个函数来创建表示记录的模式字符串，然后调用它来创建我的模式：

```scala
  def getSchema(): String = {

    var schema = ""
    val limit = 28*28

    for (i <- 1 to limit){
      schema += "P" + i.toString + " "
    }
    schema += "Label"

    schema // return value
  }

  val schemaString = getSchema()
  val schema = StructType( schemaString.split(" ")
      .map(fieldName => StructField(fieldName, IntegerType, false)))
```

与先前的示例一样，可以采用与深度学习相同的一般方法来处理数据，除了实际处理原始 CSV 数据。有太多列需要单独处理，并且它们都需要转换为整数以表示它们的数据类型。可以通过两种方式之一来完成。在第一个示例中，可以使用`var args`来处理行中的所有元素：

```scala
val trainRDD  = rawTrainData.map( rawRow => Row( rawRow.split(",").map(_.toInt): _* ))
```

第二个示例使用`fromSeq`方法来处理行元素：

```scala
  val trainRDD  = rawTrainData.map(rawRow => Row.fromSeq(rawRow.split(",") .map(_.toInt)))
```

在下一节中，将检查 H2O Flow 用户界面，以了解如何使用它来监视 H2O 并处理数据。

# H2O 流

H2O Flow 是 H2O 的基于 Web 的开源用户界面，并且由于它与 Spark 一起使用，因此也可以使用 Sparkling Water。这是一个完全功能的 H2O Web 界面，用于监视 H2O Sparkling Water 集群和作业，以及操作数据和训练模型。我已经创建了一些简单的示例代码来启动 H2O 界面。与之前基于 Scala 的代码示例一样，我所需要做的就是创建一个 Spark，一个 H2O 上下文，然后调用`openFlow`命令，这将启动 Flow 界面。

以下 Scala 代码示例仅导入了用于 Spark 上下文、配置和 H2O 的类。然后根据应用程序名称和 Spark 集群 URL 定义配置。然后使用配置对象创建 Spark 上下文：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf
import org.apache.spark.h2o._

object h2o_spark_ex2  extends App
{
  val sparkMaster = "spark://hc2nn.semtech-solutions.co.nz:7077"
  val appName = "Spark h2o ex2"
  val conf = new SparkConf()

  conf.setMaster(sparkMaster)
  conf.setAppName(appName)

  val sparkCxt = new SparkContext(conf)
```

然后创建了一个 H2O 上下文，并使用 Spark 上下文启动了它。导入了 H2O 上下文类，并使用`openFlow`命令启动了 Flow 用户界面：

```scala
  implicit val h2oContext = new org.apache.spark.h2o.H2OContext(sparkCxt).start()

  import h2oContext._

  // Open H2O UI

  openFlow
```

请注意，为了让我能够使用 Flow 应用程序，我已经注释掉了 H2O 关闭和 Spark 上下文停止选项。我通常不会这样做，但我想让这个应用程序长时间运行，这样我就有足够的时间使用界面：

```scala
  // shutdown h20

//  water.H2O.shutdown()
//  sparkCxt.stop()

  println( " >>>>> Script Finished <<<<< " )

} // end application
```

我使用我的 Bash 脚本`run_h2o.bash`，并将应用程序类名称为`h2o_spark_ex2`作为参数。这个脚本包含对`spark-submit`命令的调用，它将执行编译后的应用程序：

```scala
[hadoop@hc2r1m2 h2o_spark_1_2]$ ./run_h2o.bash h2o_spark_ex2

```

当应用程序运行时，它会列出 H2O 集群的状态，并提供一个 URL，通过该 URL 可以访问 H2O Flow 浏览器：

```scala
15/05/20 13:00:21 INFO H2OContext: Sparkling Water started, status of context:
Sparkling Water Context:
 * number of executors: 4
 * list of used executors:
 (executorId, host, port)
 ------------------------
 (1,hc2r1m4.semtech-solutions.co.nz,54321)
 (3,hc2r1m2.semtech-solutions.co.nz,54321)
 (0,hc2r1m3.semtech-solutions.co.nz,54321)
 (2,hc2r1m1.semtech-solutions.co.nz,54321)
 ------------------------

 Open H2O Flow in browser: http://192.168.1.108:54323 (CMD + click in Mac OSX)

```

前面的例子表明，我可以使用主机 IP 地址`192.168.1.108`上的端口号`54323`访问 H2O 界面。我可以简单地检查我的主机文件，确认主机名是`hc2r1m2`：

```scala
[hadoop@hc2nn ~]$ cat /etc/hosts | grep hc2
192.168.1.103 hc2nn.semtech-solutions.co.nz   hc2nn
192.168.1.105 hc2r1m1.semtech-solutions.co.nz   hc2r1m1
192.168.1.108 hc2r1m2.semtech-solutions.co.nz   hc2r1m2
192.168.1.109 hc2r1m3.semtech-solutions.co.nz   hc2r1m3
192.168.1.110 hc2r1m4.semtech-solutions.co.nz   hc2r1m4

```

因此，我可以使用`hc2r1m2:54323`的 URL 访问界面。下面的截图显示了 Flow 界面没有加载数据。页面顶部有数据处理和管理菜单选项和按钮。右侧有帮助选项，让您可以更多地了解 H2O：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_04.jpg)

以下截图更详细地显示了菜单选项和按钮。在接下来的章节中，我将使用一个实际的例子来解释其中一些选项，但在本章中没有足够的空间来涵盖所有的功能。请查看[`h2o.ai/`](http://h2o.ai/)网站，详细了解 Flow 应用程序，可在[`h2o.ai/product/flow/`](http://h2o.ai/product/flow/)找到：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_05.jpg)

更详细地说，前面的菜单选项和按钮允许您管理您的 H2O Spark 集群，并操纵您希望处理的数据。下面的截图显示了可用的帮助选项的重新格式化列表，这样，如果遇到问题，您可以在同一个界面上调查解决问题：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_06.jpg)

如果我使用菜单选项**Admin** | **Cluster Status**，我将获得以下截图，显示了每个集群服务器的内存、磁盘、负载和核心状态。这是一个有用的快照，为我提供了状态的彩色指示：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_07.jpg)

菜单选项**Admin** | **Jobs**提供了当前集群作业的详细信息，包括开始、结束和运行时间，以及状态。单击作业名称会提供更多详细信息，包括数据处理细节和估计的运行时间，这是很有用的。此外，如果选择**Refresh**按钮，显示将持续刷新，直到取消选择为止：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_08.jpg)

**Admin** | **Water Meter**选项提供了集群中每个节点的 CPU 使用情况的可视化显示。如下截图所示，我的仪表显示我的集群处于空闲状态：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_09.jpg)

使用菜单选项**Flow** | **Upload File**，我已经上传了之前基于 Scala 的深度学习示例中使用的一些训练数据。数据已加载到数据预览窗格中；我可以看到数据的样本已经组织成单元格。还对数据类型进行了准确的猜测，这样我就可以看到哪些列可以被列举。如果我想考虑分类，这是很有用的：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_10.jpg)

加载完数据后，我现在看到了一个**Frame**显示，它让我能够查看、检查、构建模型、创建预测或下载数据。数据显示了最小值、最大值和平均值等信息。它显示了数据类型、标签和零数据计数，如下截图所示：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_11.jpg)

我认为基于这些数据创建深度学习分类模型，以比较基于 Scala 的方法和 H2O 用户界面会很有用。使用查看和检查选项，可以直观地交互式地检查数据，并创建与数据相关的图表。例如，使用先前的检查选项，然后选择绘制列选项，我能够创建一个数据标签与列数据中零计数的图表。以下截图显示了结果：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_12.jpg)

通过选择构建模型选项，会提供一个菜单选项，让我选择模型类型。我将选择深度学习，因为我已经知道这些数据适合这种分类方法。先前基于 Scala 的模型的准确度达到了 83%：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_13.jpg)

我选择了深度学习选项。选择了这个选项后，我可以设置模型参数，如训练和验证数据集，以及选择模型应该使用的数据列（显然，两个数据集应该包含相同的列）。以下截图显示了被选择的数据集和模型列：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_14.jpg)

有大量基本和高级模型选项可供选择。其中一些显示在以下截图中。我已将响应列设置为 15 作为收入列。我还设置了**VARIABLE_IMPORTANCES**选项。请注意，我不需要枚举响应列，因为它已经自动完成了：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_15.jpg)

还要注意，迭代选项设置为**100**与之前一样。此外，隐藏层的`200,200`表示网络有两个隐藏层，每个隐藏层有 200 个神经元。选择构建模型选项会根据这些参数创建模型。以下截图显示了正在训练的模型，包括训练时间的估计和迄今为止处理的数据的指示。

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_16.jpg)

一旦训练完成，查看模型会显示训练和验证指标，以及重要训练参数的列表：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_17.jpg)

选择**预测**选项可以指定另一个验证数据集。使用新数据集选择**预测**选项会导致已经训练的模型针对新的测试数据集进行验证：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_18.jpg)

选择**预测**选项会导致深度学习模型和数据集的预测细节显示如下截图所示：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_19.jpg)

前面的截图显示了测试数据框架和模型类别，以及 AUC、GINI 和 MSE 的验证统计数据。

AUC 值，即曲线下面积，与 ROC 曲线相关，ROC 曲线也显示在以下截图中。TPR 表示**真正率**，FPR 表示**假正率**。AUC 是一个准确度的度量，值为 1 表示完美。因此，蓝线显示的准确度比红线高：

![H2O Flow](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_07_20.jpg)

这个界面中有很多功能，我没有解释，但我希望我已经让您感受到了它的强大和潜力。您可以使用这个界面来检查数据，并在尝试开发代码之前创建报告，或者作为一个独立的应用程序来深入研究您的数据。

# 摘要

当我检查 Apache Hadoop 和 Spark 时，我的持续主题是，这些系统都不是独立的。它们需要集成在一起形成基于 ETL 的处理系统。数据需要在 Spark 中进行源和处理，然后传递到 ETL 链中的下一个链接，或者存储起来。我希望本章已经向您展示了，Spark 功能可以通过额外的库和 H2O 等系统进行扩展。

尽管 Apache Spark MLlib（机器学习库）具有许多功能，但 H2O Sparkling Water 和 Flow web 界面的组合提供了额外丰富的数据分析建模选项。使用 Flow，您还可以直观、交互式地处理数据。希望本章能向您展示，尽管无法涵盖 H2O 提供的所有内容，但 Spark 和 H2O 的组合扩大了您的数据处理可能性。

希望您觉得本章内容有用。作为下一步，您可以考虑查看[`h2o.ai/`](http://h2o.ai/)网站或 H2O Google 小组，该小组可在[`groups.google.com/forum/#!forum/h2ostream`](https://groups.google.com/forum/#!forum/h2ostream)上找到。

下一章将审查基于 Spark 的服务[`databricks.com/`](https://databricks.com/)，该服务将在云中使用 Amazon AWS 存储来创建 Spark 集群。


# 第八章：Spark Databricks

创建大数据分析集群，导入数据，创建 ETL 流以清洗和处理数据是困难且昂贵的。Databricks 的目标是降低复杂性，使集群创建和数据处理过程更加简单。他们创建了一个基于 Apache Spark 的云平台，自动化了集群创建，并简化了数据导入、处理和可视化。目前，存储基于 AWS，但未来他们计划扩展到其他云提供商。

设计 Apache Spark 的同一批人参与了 Databricks 系统。在撰写本书时，该服务只能通过注册访问。我获得了 30 天的试用期。在接下来的两章中，我将检查该服务及其组件，并提供一些示例代码来展示其工作原理。本章将涵盖以下主题：

+   安装 Databricks

+   AWS 配置

+   帐户管理

+   菜单系统

+   笔记本和文件夹

+   通过库导入作业

+   开发环境

+   Databricks 表

+   Databricks DbUtils 包

鉴于本书以静态格式提供，完全检查流式等功能将会很困难。

# 概述

Databricks 服务，可在[`databricks.com/`](https://databricks.com/)网站上获得，基于集群的概念。这类似于 Spark 集群，在之前的章节中已经进行了检查和使用。它包含一个主节点、工作节点和执行器。但是，集群的配置和大小是自动化的，取决于您指定的内存量。诸如安全性、隔离、进程监控和资源管理等功能都会自动为您管理。如果您有一个短时间内需要使用 200GB 内存的基于 Spark 的集群，这项服务可以动态创建它，并处理您的数据。处理完成后，您可以终止集群以减少成本。

在集群中，引入了笔记本的概念，以及一个位置供您创建脚本和运行程序。可以在笔记本中创建基于 Scala、Python 或 SQL 的文件夹。可以创建作业来执行功能，并可以从笔记本代码或导入的库中调用。笔记本可以调用笔记本功能。此外，还提供了根据时间或事件安排作业的功能。

这为您提供了 Databricks 服务提供的感觉。接下来的章节将解释每个引入的主要项目。请记住，这里呈现的内容是新的并且正在发展。此外，我在这个演示中使用了 AWS US East (North Virginia)地区，因为亚洲悉尼地区目前存在限制，导致 Databricks 安装失败。

# 安装 Databricks

为了创建这个演示，我使用了 AWS 提供的一年免费访问，该访问可在[`aws.amazon.com/free/`](http://aws.amazon.com/free/)上获得。这有一些限制，比如 5GB 的 S3 存储和 750 小时的 Amazon Elastic Compute Cloud (EC2)，但它让我以较低成本访问并减少了我的整体 EC2 成本。AWS 账户提供以下内容：

+   帐户 ID

+   一个访问密钥 ID

+   一个秘密访问密钥

这些信息项目被 Databricks 用来访问您的 AWS 存储，安装 Databricks 系统，并创建您指定的集群组件。从安装开始，您就开始产生 AWS EC2 成本，因为 Databricks 系统使用至少两个运行实例而没有任何集群。一旦您成功输入了 AWS 和计费信息，您将被提示启动 Databricks 云。

![安装 Databricks](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_01.jpg)

完成这些操作后，您将获得一个 URL 来访问您的云、一个管理员账户和密码。这将允许您访问 Databricks 基于 Web 的用户界面，如下面的截图所示：

![安装 Databricks](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_02.jpg)

这是欢迎界面。它显示了图像顶部的菜单栏，从左到右依次包括菜单、搜索、帮助和账户图标。在使用系统时，还可能有一个显示最近活动的时钟图标。通过这个单一界面，您可以在创建自己的集群和代码之前搜索帮助屏幕和使用示例。

# AWS 计费

请注意，一旦安装了 Databricks 系统，您将开始产生 AWS EC2 存储成本。Databricks 试图通过保持 EC2 资源活动来最小化您的成本，以便进行完整的计费周期。例如，如果终止 Databricks 集群，基于集群的 EC2 实例仍将存在于 AWS 为其计费的一个小时内。通过这种方式，如果您创建一个新的集群，Databricks 可以重用它们。下面的截图显示，尽管我正在使用一个免费的 AWS 账户，并且我已经仔细减少了我的资源使用，但我在短时间内产生了 AWS EC2 成本：

![AWS 计费](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_03.jpg)

您需要了解您创建的 Databricks 集群，并了解，当它们存在并被使用时，将产生 AWS 成本。只保留您真正需要的集群，并终止其他任何集群。

为了检查 Databricks 数据导入功能，我还创建了一个 AWS S3 存储桶，并将数据文件上传到其中。这将在本章后面进行解释。

# Databricks 菜单

通过选择 Databricks Web 界面上的左上角菜单图标，可以展开菜单系统。下面的截图显示了顶级菜单选项，以及**工作区**选项，展开到`/folder1/folder2/`的文件夹层次结构。最后，它显示了可以在`folder2`上执行的操作，即创建一个笔记本、创建一个仪表板等。

![Databricks 菜单](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_04.jpg)

所有这些操作将在以后的章节中扩展。下一节将介绍账户管理，然后转到集群。

# 账户管理

在 Databricks 中，账户管理非常简化。有一个默认的管理员账户，可以创建后续账户，但您需要知道管理员密码才能这样做。密码需要超过八个字符；它们应该包含至少一个数字、一个大写字母和一个非字母数字字符。**账户**选项可以从右上角的菜单选项中访问，如下面的截图所示：

账户管理

这也允许用户注销。通过选择账户设置，您可以更改密码。通过选择**账户**菜单选项，将生成一个**账户**列表。在那里，您将找到一个**添加账户**的选项，并且每个账户行都可以通过每个账户行上的**X**选项进行删除，如下面的截图所示：

![账户管理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_06.jpg)

还可以从账户列表重置账户密码。选择**添加账户**选项会创建一个新的账户窗口，需要一个电子邮件地址、全名、管理员密码和用户密码。因此，如果您想创建一个新用户，您需要知道您的 Databricks 实例管理员密码。您还必须遵循新密码的规则，如下所示：

+   至少八个字符

+   必须包含 0-9 范围内的至少一个数字

+   必须包含 A-Z 范围内的至少一个大写字母

+   必须包含至少一个非字母数字字符：!@#$%![账户管理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_07.jpg)

下一节将介绍**集群**菜单选项，并使您能够管理自己的 Databricks Spark 集群。

# 集群管理

选择**集群**菜单选项会提供您当前的 Databricks 集群及其状态的列表。当然，当前您还没有。选择**添加集群**选项允许您创建一个。请注意，您指定的内存量决定了您的集群的大小。创建具有单个主节点和工作节点的集群需要至少 54GB。对于每增加的 54GB，将添加一个工作节点。

![集群管理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_08.jpg)

下面的截图是一个连接的图像，显示了一个名为`semclust1`的新集群正在创建中，处于**Pending**状态。在**Pending**状态下，集群没有仪表板，集群节点也无法访问。

![集群管理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_09.jpg)

创建后，集群内存会被列出，并且其状态会从**Pending**变为**Running**。默认情况下会自动附加一个仪表板，并且可以访问 Spark 主节点和工作节点用户界面。这里需要注意的是，Databricks 会自动启动和管理集群进程。在显示的右侧还有一个**Option**列，提供了**配置**、**重启**或**终止**集群的能力，如下面的截图所示：

![集群管理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_10.jpg)

通过重新配置集群，可以改变其大小。通过增加内存，可以增加工作节点。下面的截图显示了一个集群，创建时默认大小为 54GB，其内存扩展到了`108`GB。

![集群管理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_11.jpg)

终止集群会将其删除，无法恢复。因此，您需要确保删除是正确的操作。在终止实际发生之前，Databricks 会提示您确认您的操作。

![集群管理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_12.jpg)

创建和终止集群都需要时间。在终止期间，集群会被标记为橙色横幅，并显示**终止**状态，如下面的截图所示：

![集群管理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_13.jpg)

请注意，前面截图中的集群类型显示为**按需**。创建集群时，可以选择一个名为**使用竞价实例创建竞价集群**的复选框。这些集群比按需集群更便宜，因为它们出价更低的 AWS 竞价。但是，它们启动可能比按需集群慢。

Spark 用户界面与您在非 Databricks Spark 集群上期望的一样。您可以检查工作节点、执行器、配置和日志文件。创建集群时，它们将被添加到您的集群列表中。其中一个集群将被用作运行仪表板的集群。可以通过使用**创建仪表板集群**选项来更改这一点。当您向集群添加库和笔记本时，集群详细信息条目将更新为添加的数量。

我现在唯一想说的关于 Databricks Spark 用户界面选项，因为它很熟悉，就是它显示了使用的 Spark 版本。下面的截图从主用户界面中提取，显示了正在使用的 Spark 版本（1.3.0）非常新。在撰写本文时，最新的 Apache Spark 版本是 1.3.1，日期为 2015 年 4 月 17 日。

![集群管理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_14.jpg)

下一节将介绍 Databricks 笔记本和文件夹——如何创建它们以及它们的用途。

# 笔记本和文件夹

笔记本是一种特殊类型的 Databricks 文件夹，可用于创建 Spark 脚本。笔记本可以调用笔记本脚本来创建功能层次结构。创建时，必须指定笔记本的类型（Python、Scala 或 SQL），然后可以指定集群可以运行笔记本功能。下面的截图显示了笔记本的创建。

![笔记本和文件夹](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_15.jpg)

请注意，笔记本会话右侧的菜单选项允许更改笔记本的类型。下面的示例显示了 Python 笔记本可以更改为**Scala**、**SQL**或**Markdown**：

![笔记本和文件夹](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_16.jpg)

请注意，Scala 笔记本无法更改为 Python，Python 笔记本也无法更改为 Scala。Python、Scala 和 SQL 这些术语作为开发语言是众所周知的，然而，**Markdown**是新的。Markdown 允许从文本中的格式化命令创建格式化文档。可以在[`forums.databricks.com/static/markdown/help.html`](https://forums.databricks.com/static/markdown/help.html)找到一个简单的参考。

这意味着在创建脚本时，格式化的注释可以添加到笔记本会话中。笔记本进一步细分为单元格，其中包含要执行的命令。可以通过悬停在左上角并将其拖放到位置来在笔记本中移动单元格。可以在笔记本中的单元格列表中插入新单元格。

此外，在 Scala 或 Python 笔记本单元格中使用`%sql`命令允许使用 SQL 语法。通常，*Shift* + *Enter*的组合会导致笔记本或文件夹中的文本块被执行。使用`%md`命令允许在单元格内添加 Markdown 注释。还可以向笔记本单元格添加注释。在笔记本单元格的右上部分显示的菜单选项显示了注释以及最小化和最大化选项：

![笔记本和文件夹](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_17.jpg)

多个基于 Web 的会话可以共享一个笔记本。在笔记本中发生的操作将被填充到查看它的每个 Web 界面中。此外，Markdown 和注释选项可用于启用用户之间的通信，以帮助分布式组之间的交互式数据调查。

![笔记本和文件夹](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_18.jpg)

上面的屏幕截图显示了**notebook1**的笔记本会话的标题。它显示了笔记本名称和类型（**Scala**）。它还显示了将笔记本锁定以使其只读的选项，以及将其从其集群中分离的选项。下面的屏幕截图显示了在笔记本工作区内创建文件夹的过程：

![笔记本和文件夹](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_19.jpg)

从**工作区**主菜单选项的下拉菜单中，可以创建一个文件夹，例如`folder1`。稍后的部分将描述此菜单中的其他选项。创建并选择后，从名为`folder1`的新文件夹的下拉菜单中，显示了与其关联的操作，如下面的屏幕截图所示：

![笔记本和文件夹](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_20.jpg)

因此，文件夹可以导出为 DBC 存档。它可以被锁定，或者克隆以创建副本。也可以重命名或删除。可以将项目导入其中；例如，稍后将通过示例解释文件。还可以在其中创建新的笔记本、仪表板、库和文件夹。

与文件夹一样，笔记本也有一组可能的操作。下面的屏幕截图显示了通过下拉菜单可用的操作，用于名为`notebook1`的笔记本，它当前附加到名为`semclust1`的运行集群。可以重命名、删除、锁定或克隆笔记本。还可以将其从当前集群中分离，或者如果它被分离，则可以附加它。还可以将笔记本导出到文件或 DBC 存档。

![笔记本和文件夹](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_21.jpg)

从文件夹**导入**选项，文件可以导入到文件夹中。下面的屏幕截图显示了如果选择此选项将调用的文件拖放选项窗口。可以将文件拖放到本地服务器上的上传窗格上，也可以单击该窗格以打开导航浏览器，以搜索要上传的文件。

![笔记本和文件夹](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_22.jpg)

需要上传的文件需要是特定类型。以下截图显示了支持的文件类型。这是从文件浏览器中浏览要上传的文件时拍摄的截图。这也是有道理的。支持的文件类型包括 Scala、SQL 和 Python；以及 DBC 存档和 JAR 文件库。

![笔记本和文件夹](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_23.jpg)

在离开这一部分之前，还应该注意到，可以拖放笔记本和文件夹来改变它们的位置。下一节将通过简单的示例来检查 Databricks 作业和库。

# 工作和图书馆

在 Databricks 中，可以导入 JAR 库并在集群上运行其中的类。我将创建一个非常简单的 Scala 代码片段，以在我的 Centos Linux 服务器上本地打印出斐波那契数列的前 100 个元素作为`BigInt`值。我将使用 SBT 将我的类编译成一个 JAR 文件，在本地运行以检查结果，然后在我的 Databricks 集群上运行以比较结果。代码如下所示：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf

object db_ex1  extends App
{
  val appName = "Databricks example 1"
  val conf = new SparkConf()

  conf.setAppName(appName)

  val sparkCxt = new SparkContext(conf)

  var seed1:BigInt = 1
  var seed2:BigInt = 1
  val limit = 100
  var resultStr = seed1 + " " + seed2 + " "

  for( i <- 1 to limit ){

    val fib:BigInt = seed1 + seed2
    resultStr += fib.toString + " "

    seed1 = seed2
    seed2 = fib
  }

  println()
  println( "Result : " + resultStr )
  println()

  sparkCxt.stop()

} // end application
```

并不是最优雅的代码片段，也不是创建斐波那契数列的最佳方式，但我只是想要一个用于 Databricks 的示例 JAR 和类。在本地运行时，我得到了前 100 个项，如下所示（我已剪辑了这些数据以节省空间）：

```scala
Result : 1 1 2 3 5 8 13 21 34 55 89 144 233 377 610 987 1597 2584 4181 6765 10946 17711 28657 46368 75025 121393 196418 317811 514229 832040 1346269 2178309 3524578 5702887 9227465 14930352 24157817 39088169 63245986 102334155 165580141 267914296 433494437 701408733 1134903170 1836311903 2971215073 4807526976 7778742049 12586269025 20365011074 32951280099 53316291173

4660046610375530309 7540113804746346429 12200160415121876738 19740274219868223167 31940434634990099905 51680708854858323072 83621143489848422977 135301852344706746049 218922995834555169026 354224848179261915075 573147844013817084101 927372692193078999176

```

已创建的库名为`data-bricks_2.10-1.0.jar`。从我的文件夹菜单中，我可以使用下拉菜单选项创建一个新的库。这允许我指定库源为一个 JAR 文件，命名新库，并从我的本地服务器加载库 JAR 文件。以下截图显示了这个过程的一个例子：

![工作和图书馆](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_24.jpg)

创建库后，可以使用**附加**选项将其附加到名为`semclust1`的集群，即我的 Databricks 集群。以下截图显示了正在附加新库的过程：

![工作和图书馆](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_25.jpg)

在下面的例子中，通过在**任务**项目上选择**jar**选项创建了一个名为**job2**的作业。对于该作业，已加载了相同的 JAR 文件，并将类`db_ex1`分配到库中运行。集群已被指定为按需，这意味着将自动创建一个集群来运行作业。**活动运行**部分显示了作业在以下截图中的运行情况：

![工作和图书馆](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_26.jpg)

运行后，作业将移至显示的**已完成运行**部分。对于相同的作业，以下截图显示了它运行了`47`秒，是手动启动的，并且成功了。

![工作和图书馆](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_27.jpg)

通过在前面的截图中选择名为**Run 1**的运行，可以查看运行输出。以下截图显示了与本地运行相同的结果，显示了来自我的本地服务器执行的结果。我已剪辑输出文本以使其在此页面上呈现和阅读，但您可以看到输出是相同的。

![工作和图书馆](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_28.jpg)

因此，即使从这个非常简单的例子中，很明显可以远程开发应用程序，并将它们作为 JAR 文件加载到 Databricks 集群中以执行。然而，每次在 AWS EC2 存储上创建 Databricks 集群时，Spark URL 都会发生变化，因此应用程序不应该硬编码诸如 Spark 主 URL 之类的细节。Databricks 将自动设置 Spark URL。

以这种方式运行 JAR 文件类时，也可以定义类参数。作业可以被安排在特定时间运行，或定期运行。还可以指定作业超时和警报电子邮件地址。

# 开发环境

已经证明可以在 Scala、Python 或 SQL 的笔记本中创建脚本，但也可以使用诸如 IntelliJ 或 Eclipse 之类的 IDE 来开发代码。通过在开发环境中安装 SBT 插件，可以为 Databricks 环境开发代码。在我写这本书的时候，Databricks 的当前版本是 1.3.2d。在起始页面的**新功能**下的**发布说明**链接中包含了 IDE 集成的链接，即`https://dbc-xxxxxxx-xxxx.cloud.databricks.com/#shell/1547`。

URL 将采用这种形式，以`dbc`开头的部分将更改以匹配您将创建的 Databricks 云的 URL。我不会在这里展开，而是留给您去调查。在下一节中，我将调查 Databricks 表数据处理功能。

# Databricks 表

Databricks 的**表**菜单选项允许您以表格形式存储数据，并附带模式。**表**菜单选项允许您创建表格，并刷新表格列表，如下面的截图所示：

![Databricks 表](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_29.jpg)

## 数据导入

您可以通过数据导入创建表，并同时指定列名和类型的表结构。如果要导入的数据具有标题，则可以从中获取列名，尽管所有列类型都被假定为字符串。下面的截图显示了在创建表时可用的数据导入选项和表单的连接视图。导入文件位置选项包括**S3**、**DBFS**、**JDBC**和**文件**。

![数据导入](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_30.jpg)

前面的截图显示了选择了**S3**。为了浏览我的**S3**存储桶以将文件导入表中，我需要输入**AWS Key ID**、**Secret Access Key**和**AWS S3 Bucket Name**。然后，我可以浏览、选择文件，并通过预览创建表。在下面的截图中，我选择了**文件**选项：

![数据导入](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_31.jpg)

我可以将要导入的文件拖放到下面截图中的上传框中，或者单击框以浏览本地服务器以选择要上传的文件。选择文件后，可以定义数据列分隔符，以及数据是否包含标题行。可以预览数据，并更改列名和数据类型。还可以指定新表名和文件类型。下面的截图显示了加载示例文件数据以创建名为`shuttle`的表：

![数据导入](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_32.jpg)

创建后，菜单表列表可以刷新，并且可以查看表模式以确认列名和类型。通过这种方式，还可以预览表数据的样本。现在可以从 SQL 会话中查看和访问表。下面的截图显示了使用`show tables`命令可见**shuttle**表：

![数据导入](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_33.jpg)

一旦导入，此表中的数据也可以通过 SQL 会话访问。下面的截图显示了一个简单的 SQL 会话语句，显示了从新的**shuttle**表中提取的数据：

![数据导入](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_34.jpg)

因此，这提供了从各种数据源导入多个表格，并创建复杂模式以通过列和行过滤和连接数据的手段，就像在传统的关系数据库中一样。它提供了一种熟悉的大数据处理方法。

本节描述了可以通过数据导入创建表的过程，但是如何通过编程方式创建表，或者创建外部对象作为表呢？接下来的部分将提供这种表管理方法的示例。

## 外部表

Databricks 允许您针对外部资源（如 AWS S3 文件或本地文件系统文件）创建表。在本节中，我将针对基于 S3 的存储桶、路径和一组文件创建外部表。我还将检查 AWS 中所需的权限和使用的访问策略。以下截图显示了一个名为**dbawss3test2**的 AWS S3 存储桶的创建。已授予所有人访问列表的权限。我并不建议您这样做，但请确保您的组可以访问您的存储桶。

![外部表](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_35.jpg)

此外，还添加了一个策略以帮助访问。在这种情况下，匿名用户已被授予对存储桶和子内容的只读访问权限。您可以创建一个更复杂的策略，以限制对您的组和各种文件的访问。以下截图显示了新策略：

![外部表](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_36.jpg)

有了访问策略和使用正确访问策略创建的存储桶，我现在可以创建文件夹并上传文件以供 Databricks 外部表使用。如下截图所示，我已经做到了。上传的文件以 CSV 文件格式有十列：

![外部表](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_37.jpg)

现在，AWS S3 资源已设置好，需要将其挂载到 Databricks，如下面基于 Scala 的示例所示。出于安全目的，我已从脚本中删除了我的 AWS 和秘密密钥。您的挂载目录将需要以`/mnt`和任何`/`字符开头，并且您的秘密密钥值将需要替换为`%2F`。使用`dbutils.fs`类来创建挂载，代码在一秒内执行，如下结果所示：

![外部表](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_38.jpg)

现在，可以使用基于笔记本的 SQL 会话针对此挂载路径和其中包含的文件创建外部表，如下截图所示。名为`s3test1`的表已针对挂载目录包含的文件创建，并指定逗号作为分隔符，以解析基于 CSV 的内容。

![外部表](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_39.jpg)

**表**菜单选项现在显示**s3test1**表存在，如下截图所示。因此，应该可以针对此表运行一些 SQL：

![外部表](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_40.jpg)

我在基于 SQL 的笔记本会话中运行了一个`SELECT`语句，使用`COUNT(*)`函数从外部表中获取行数，如下截图所示。可以看到表包含**14500**行。

![外部表](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_41.jpg)

我现在将向基于 S3 的文件夹添加另一个文件。在这种情况下，它只是第一个文件的 CSV 格式副本，因此外部表中的行数应该加倍。以下截图显示了添加的文件：

![外部表](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_42.jpg)

对外部表运行相同的`SELECT`语句确实提供了**29000**行的加倍行数。以下截图显示了 SQL 语句和输出：

![外部表](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_43.jpg)

因此，在 Databricks 内部很容易创建外部表，并对动态更改的内容运行 SQL。文件结构需要是统一的，如果使用 AWS，则必须定义 S3 存储桶访问权限。下一节将检查 Databricks 提供的 DbUtils 包。

# DbUtils 包

之前基于 Scala 的脚本使用了 DbUtils 包，并在最后一节中创建了挂载点，只使用了该包的一小部分功能。在本节中，我想介绍一些 DbUtils 包和**Databricks 文件系统**（**DBFS**）的更多功能。在连接到 Databricks 集群的笔记本中，可以调用 DbUtils 包中的帮助选项，以了解其结构和功能。正如下面的截图所示，在 Scala 笔记本中执行`dbutils.fs.help()`可以提供有关 fsutils、cache 和基于挂载的功能的帮助：

![DbUtils 包](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_44.jpg)

也可以获取关于单个函数的帮助，就像之前截图中的文本所示。下面的截图中的示例解释了**cacheTable**函数，提供了描述性文本和带有参数和返回类型的示例函数调用：

![DbUtils 包](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_45.jpg)

下一节将简要介绍 DBFS，然后继续检查更多的`dbutils`功能。

## Databricks 文件系统

可以使用`dbfs:/*`形式的 URL 访问 DBFS，并使用`dbutils.fs`中可用的函数。

![Databricks file system](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_46.jpg)

之前的截图显示了使用`ls`函数检查`/mnt`文件系统，然后显示挂载目录——`s3data`和`s3data1`。这些是在之前的 Scala S3 挂载示例中创建的目录。

## Dbutils fsutils

`dbutils`包中的`fsutils`函数组包括`cp`、`head`、`mkdirs`、`mv`、`put`和`rm`等函数。之前显示的帮助调用可以提供更多关于它们的信息。您可以使用`mkdirs`调用在 DBFS 上创建一个目录，如下所示。请注意，我在这个会话中在`dbfs:/`下创建了许多名为`data*`的目录。下面的例子创建了一个名为`data2`的目录：

![Dbutils fsutils](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_47.jpg)

之前的截图通过执行`ls`显示了 DBFS 上已经存在许多默认目录。例如，参见以下内容：

+   `/tmp`是一个临时区域

+   `/mnt`是远程目录的挂载点，即 S3

+   `/user`是一个用户存储区域，目前包含 Hive

+   `/mount`是一个空目录

+   `/FileStore`是用于存储表、JAR 和作业 JAR 的存储区域

+   `/databricks-datasets`是 Databricks 提供的数据集

接下来显示的`dbutils`复制命令允许将文件复制到 DBFS 位置。在这个例子中，`external1.txt`文件已经被复制到`/data2`目录，如下面的截图所示：

![Dbutils fsutils](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_48.jpg)

`head`函数可用于从 DBFS 文件的开头返回前 maxBytes 个字符。下面的例子显示了`external1.txt`文件的格式。这很有用，因为它告诉我这是一个 CSV 文件，因此告诉我如何处理它。

![Dbutils fsutils](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_49.jpg)

也可以在 DBFS 内部移动文件。下面的截图显示了使用`mv`命令将`external1.txt`文件从`data2`目录移动到名为`data1`的目录。然后使用`ls`命令确认移动。

![Dbutils fsutils](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_50.jpg)

最后，使用 remove 函数（`rm`）来删除刚刚移动的名为`external1.txt`的文件。以下的`ls`函数调用显示，该文件不再存在于`data1`目录中，因为在函数输出中没有`FileInfo`记录：

![Dbutils fsutils](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_51.jpg)

## DbUtils 缓存

在 DbUtils 中的缓存功能提供了缓存（和取消缓存）表和文件到 DBFS 的方法。实际上，表也被保存为文件到名为`/FileStore`的 DBFS 目录。下面的截图显示了缓存功能是可用的：

![DbUtils 缓存](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_52.jpg)

## DbUtils 挂载

挂载功能允许您挂载远程文件系统，刷新挂载，显示挂载详细信息，并卸载特定的已挂载目录。在前几节中已经给出了 S3 挂载的示例，所以我在这里不会重复了。以下截图显示了`mounts`函数的输出。`s3data`和`s3data1`挂载是我创建的。根目录和数据集的另外两个挂载已经存在。挂载按`MountInfo`对象的顺序列出。我重新排列了文本，使其更有意义，并更好地呈现在页面上。

![DbUtils 挂载](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_08_53.jpg)

# 总结

本章介绍了 Databricks。它展示了如何访问该服务，以及它如何使用 AWS 资源。请记住，未来，发明 Databricks 的人计划支持其他基于云的平台，如 Microsoft Azure。我认为介绍 Databricks 很重要，因为参与 Apache Spark 开发的人也参与了这个系统。自然的发展似乎是 Hadoop，Spark，然后是 Databricks。

我将在下一章继续对 Databricks 进行调查，因为重要的功能，如可视化，尚未被审查。此外，Databricks 术语中尚未介绍的主要 Spark 功能模块称为 GraphX，流式处理，MLlib 和 SQL。在 Databricks 中使用这些模块处理真实数据有多容易？继续阅读以了解更多。


# 第九章：Databricks 可视化

本章是在第八章*Spark Databricks*中完成的工作的基础上继续研究基于 Apache Spark 的服务的功能[`databricks.com/`](https://databricks.com/)。尽管我在本章中将使用基于 Scala 的代码示例，但我希望集中在 Databricks 功能上，而不是传统的 Spark 处理模块：MLlib、GraphX、Streaming 和 SQL。本章将解释以下 Databricks 领域：

+   使用仪表板的数据可视化

+   基于 RDD 的报告

+   基于数据流的报告

+   Databricks Rest 接口

+   使用 Databricks 移动数据

因此，本章将审查 Databricks 中通过报告和仪表板进行数据分析可视化的功能。它还将检查 REST 接口，因为我认为它是远程访问和集成目的的有用工具。最后，它将检查将数据和库移动到 Databricks 云实例的选项。

# 数据可视化

Databricks 提供了访问 S3 和基于本地文件系统的文件的工具。它提供了将数据导入表格的能力，如已经显示的。在上一章中，原始数据被导入到航天飞机表中，以提供可以针对其运行 SQL 的表格数据，以针对行和列进行过滤，允许数据进行排序，然后进行聚合。这非常有用，但当图像和报告呈现可以更容易和直观地解释的信息时，我们仍然在查看原始数据输出。

Databricks 提供了一个可视化界面，基于您的 SQL 会话产生的表格结果数据。以下截图显示了一些已经运行的 SQL。生成的数据和数据下面的可视化下拉菜单显示了可能的选项。

![数据可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_01.jpg)

这里有一系列的可视化选项，从更熟悉的**柱状图**和**饼图**到**分位数**和**箱线图**。我将更改我的 SQL，以便获得更多绘制图形的选项，如下所示：

![数据可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_02.jpg)

然后，在选择了可视化选项；**柱状图**后，我将选择**绘图**选项，这将允许我选择图形顶点的数据。它还将允许我选择要在其上进行数据列的数据列。以下截图显示了我选择的值。

![数据可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_03.jpg)

**绘图**选项显示的**所有字段**部分显示了可以从 SQL 语句结果数据中用于图形显示的所有字段。**键**和**值**部分定义了将形成图形轴的数据字段。**系列分组**字段允许我定义一个值，教育，进行数据透视。通过选择**应用**，我现在可以创建一个根据教育类型分组的工作类型的总余额图表，如下截图所示：

![数据可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_04.jpg)

如果我是一名会计师，试图确定影响工资成本的因素，以及公司内成本最高的员工群体，那么我将看到上一个图表中的绿色峰值。它似乎表明具有高等教育的**管理**员工是数据中成本最高的群体。这可以通过更改 SQL 以过滤**高等教育**来确认，按余额降序排序结果，并创建一个新的柱状图。

![数据可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_05.jpg)

显然，**管理**分组约为**1400 万**。将显示选项更改为**饼图**，将数据表示为饼图，具有清晰大小的分段和颜色，从视觉上清晰地呈现数据和最重要的项目。

![数据可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_06.jpg)

我无法在这个小章节中检查所有的显示选项，但我想展示的是可以使用地理信息创建的世界地图图表。我已从[`download.geonames.org/export/dump/`](http://download.geonames.org/export/dump/)下载了`Countries.zip`文件。

这将提供一个约 281MB 压缩的庞大数据集，可用于创建新表。它显示为世界地图图表。我还获取了一个 ISO2 到 ISO3 的映射数据集，并将其存储在一个名为`cmap`的 Databricks 表中。这使我能够将数据中的 ISO2 国家代码（例如“AU”）转换为 ISO3 国家代码（例如“AUS”）（地图图表所需）。我们将用于地图图表的数据的第一列必须包含地理位置数据。在这种情况下，ISO 3 格式的国家代码。因此，从国家数据中，我将按 ISO3 代码为每个国家创建记录计数。还要确保正确设置绘图选项的键和值。我已将下载的基于国家的数据存储在一个名为`geo1`的表中。以下截图显示了使用的 SQL：

![数据可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_07.jpg)

如前所示，这给出了两列数据，一个基于 ISO3 的值称为`country`，和一个称为`value`的数字计数。将显示选项设置为`地图`会创建一个彩色世界地图，如下截图所示：

![数据可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_08.jpg)

这些图表展示了数据可以以各种形式进行视觉呈现，但如果需要为外部客户生成报告或需要仪表板怎么办？所有这些将在下一节中介绍。

## 仪表板

在本节中，我将使用上一节中创建的名为`geo1`的表中的数据进行地图显示。它被用来创建一个简单的仪表板，并将仪表板发布给外部客户。从**工作区**菜单中，我创建了一个名为`dash1`的新仪表板。如果我编辑此仪表板的控件选项卡，我可以开始输入 SQL，并创建图表，如下截图所示。每个图表都表示为一个视图，并可以通过 SQL 定义。它可以通过绘图选项调整大小和配置，就像每个图表一样。使用**添加**下拉菜单添加一个视图。以下截图显示`view1`已经创建，并添加到`dash1`。`view2`正在被定义。

![仪表板](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_09.jpg)

一旦所有视图都被添加、定位和调整大小，可以选择编辑选项卡来呈现最终的仪表板。以下截图现在显示了名为`dash1`的最终仪表板，其中包含三种不同形式的图表和数据的部分：

![仪表板](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_10.jpg)

这对于展示数据非常有用，但这个仪表板是在 Databricks 云环境中。如果我想让客户看到呢？仪表板屏幕右上角有一个**发布**菜单选项，允许您发布仪表板。这将在新的公开发布的 URL 下显示仪表板，如下截图所示。请注意以下截图顶部的新 URL。您现在可以与客户分享此 URL 以呈现结果。还有定期更新显示以表示基础数据更新的选项。

![仪表板](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_11.jpg)

这给出了可用的显示选项的概念。到目前为止，所有创建的报告和仪表板都是基于 SQL 和返回的数据。在下一节中，我将展示可以使用基于 Scala 的 Spark RDD 和流数据以编程方式创建报告。

## 基于 RDD 的报告

以下基于 Scala 的示例使用了一个名为`birdType`的用户定义类类型，基于鸟的名称和遇到的数量。 创建了一个鸟类记录的 RDD，然后转换为数据框架。 然后显示数据框架。 Databricks 允许将显示的数据呈现为表格或使用绘图选项呈现为图形。 以下图片显示了使用的 Scala：

![基于 RDD 的报告](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_12.jpg)

这个 Scala 示例允许创建的条形图显示在以下截图中。 前面的 Scala 代码和下面的截图不如这个图表是通过数据框架以编程方式创建的这一事实重要：

![基于 RDD 的报告](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_13.jpg)

这打开了以编程方式从基于计算的数据源创建数据框架和临时表的可能性。 它还允许处理流数据，并使用仪表板的刷新功能，以不断呈现流数据的窗口。 下一节将介绍基于流的报告生成示例。

## 基于流的报告

在本节中，我将使用 Databricks 的能力上传基于 JAR 的库，以便我们可以运行基于 Twitter 的流式 Apache Spark 示例。 为了做到这一点，我必须首先在[`apps.twitter.com/`](https://apps.twitter.com/)上创建一个 Twitter 帐户和一个示例应用程序。

以下截图显示我创建了一个名为`My example app`的应用程序。 这是必要的，因为我需要创建必要的访问密钥和令牌来创建基于 Scala 的 Twitter feed。

![基于流的报告](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_14.jpg)

如果我现在选择应用程序名称，我可以看到应用程序详细信息。 这提供了一个菜单选项，该选项提供对应用程序详细信息、设置、访问令牌和权限的访问。 还有一个按钮，上面写着**测试 OAuth**，这使得将要创建的访问和令牌密钥可以进行测试。 以下截图显示了应用程序菜单选项：

![基于流的报告](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_15.jpg)

通过选择**密钥和访问令牌**菜单选项，可以为应用程序生成访问密钥和访问令牌。 在本节中，每个应用程序设置和令牌都有一个 API 密钥和一个秘密密钥。 在以下截图的表单顶部显示了消费者密钥和消费者秘钥（当然，出于安全原因，这些图像中的密钥和帐户详细信息已被删除）。

![基于流的报告](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_16.jpg)

在上一张截图中还有重新生成密钥和设置权限的选项。 下一张截图显示了应用程序访问令牌的详细信息。 有一个访问令牌和一个访问令牌秘钥。 还有重新生成值和撤销访问的选项：

![基于流的报告](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_17.jpg)

使用这四个字母数字值字符串，可以编写一个 Scala 示例来访问 Twitter 流。 需要的值如下：

+   消费者密钥

+   消费者秘钥

+   访问令牌

+   访问令牌秘钥

在以下代码示例中，出于安全原因，我将删除自己的密钥值。 您只需要添加自己的值即可使代码正常工作。 我已经开发了自己的库，并在本地运行代码以检查它是否能正常工作。 我在将其加载到 Databricks 之前就这样做了，以减少调试所需的时间和成本。 我的 Scala 代码示例如下。 首先，我定义一个包，导入 Spark 流和 Twitter 资源。 然后，我定义了一个名为`twitter1`的对象类，并创建了一个主函数：

```scala
package nz.co.semtechsolutions

import org.apache.spark._
import org.apache.spark.SparkContext._
import org.apache.spark.streaming._
import org.apache.spark.streaming.twitter._
import org.apache.spark.streaming.StreamingContext._
import org.apache.spark.sql._
import org.apache.spark.sql.types.{StructType,StructField,StringType}

object twitter1 {

  def main(args: Array[String]) {
```

接下来，我使用应用程序名称创建一个 Spark 配置对象。 我没有使用 Spark 主 URL，因为我将让`spark-submit`和 Databricks 分配默认 URL。 从这里，我将创建一个 Spark 上下文，并定义 Twitter 消费者和访问值：

```scala
    val appName = "Twitter example 1"
    val conf    = new SparkConf()

    conf.setAppName(appName)
    val sc = new SparkContext(conf)

    val consumerKey       = "QQpl8xx"
    val consumerSecret    = "0HFzxx"
    val accessToken       = "323xx"
    val accessTokenSecret = "Ilxx"
```

我使用`System.setProperty`调用设置了 Twitter 访问属性，并使用它来设置四个`twitter4j` `oauth`访问属性，使用之前生成的访问密钥：

```scala
    System.setProperty("twitter4j.oauth.consumerKey", consumerKey)
    System.setProperty("twitter4j.oauth.consumerSecret",
       consumerSecret)
    System.setProperty("twitter4j.oauth.accessToken", accessToken)
    System.setProperty("twitter4j.oauth.accessTokenSecret",
       accessTokenSecret)
```

从 Spark 上下文创建了一个流上下文，用于创建基于 Twitter 的 Spark DStream。流被空格分割以创建单词，并且通过以`#`开头的单词进行过滤，以选择哈希标签：

```scala
    val ssc    = new StreamingContext(sc, Seconds(5) )
    val stream = TwitterUtils.createStream(ssc,None)
       .window( Seconds(60) )

    // split out the hash tags from the stream

    val hashTags = stream.flatMap( status => status.getText.split(" ").filter(_.startsWith("#")))
```

下面用于获取单例 SQL 上下文的函数在本示例的末尾定义。因此，对于哈希标签流中的每个 RDD，都会创建一个单独的 SQL 上下文。这用于导入隐式，允许 RDD 通过`toDF`隐式转换为数据框。从每个`rdd`创建了一个名为`dfHashTags`的数据框，然后用它注册了一个临时表。然后我对表运行了一些 SQL 以获取行数。然后打印出行数。代码中的横幅只是用来在使用`spark-submit`时更容易查看输出结果：

```scala
hashTags.foreachRDD{ rdd =>

val sqlContext = SQLContextSingleton.getInstance(rdd.sparkContext)
import sqlContext.implicits._

val dfHashTags = rdd.map(hashT => hashRow(hashT) ).toDF()

dfHashTags.registerTempTable("tweets")

val tweetcount = sqlContext.sql("select count(*) from tweets")

println("\n============================================")
println(  "============================================\n")

println("Count of hash tags in stream table : "
   + tweetcount.toString )

tweetcount.map(c => "Count of hash tags in stream table : "
   + c(0).toString ).collect().foreach(println)

println("\n============================================")
println(  "============================================\n")

} // for each hash tags rdd
```

我还输出了当前推文流数据窗口中前五条推文的列表。你可能会认出以下代码示例。这是来自 GitHub 上 Spark 示例。同样，我使用了横幅来帮助输出结果的查看：

```scala
val topCounts60 = hashTags.map((_, 1))
   .reduceByKeyAndWindow(_ + _, Seconds(60))
.map{case (topic, count) => (count, topic)}
.transform(_.sortByKey(false))

topCounts60.foreachRDD(rdd => {

  val topList = rdd.take(5)

  println("\n===========================================")
  println(  "===========================================\n")
  println("\nPopular topics in last 60 seconds (%s total):"
     .format(rdd.count()))
  topList.foreach{case (count, tag) => println("%s (%s tweets)"
     .format(tag, count))}
  println("\n===========================================")
  println(  "==========================================\n")
})
```

然后，我使用 Spark 流上下文`ssc`的`start`和`awaitTermination`来启动应用程序，并保持其运行直到停止：

```scala
    ssc.start()
    ssc.awaitTermination()

  } // end main
} // end twitter1
```

最后，我已经定义了单例 SQL 上下文函数，并且为哈希标签数据流`rdd`中的每一行定义了`dataframe` `case` `class`：

```scala
object SQLContextSingleton {
  @transient private var instance: SQLContext = null

  def getInstance(sparkContext: SparkContext):
    SQLContext = synchronized {
    if (instance == null) {
      instance = new SQLContext(sparkContext)
    }
    instance
  }
}
case class hashRow( hashTag: String)
```

我使用 SBT 编译了这个 Scala 应用程序代码，生成了一个名为`data-bricks_2.10-1.0.jar`的 JAR 文件。我的`SBT`文件如下：

```scala
[hadoop@hc2nn twitter1]$  cat twitter.sbt

name := "Databricks"
version := "1.0"
scalaVersion := "2.10.4"
libraryDependencies += "org.apache.spark" % "streaming" % "1.3.1" from "file:///usr/local/spark/lib/spark-assembly-1.3.1-hadoop2.3.0.jar"
libraryDependencies += "org.apache.spark" % "sql" % "1.3.1" from "file:///usr/local/spark/lib/spark-assembly-1.3.1-hadoop2.3.0.jar"
libraryDependencies += "org.apache.spark.streaming" % "twitter" % "1.3.1" from file:///usr/local/spark/lib/spark-examples-1.3.1-hadoop2.3.0.jar

```

我下载了正确版本的 Apache Spark 到我的集群上，以匹配 Databricks 当前使用的版本（1.3.1）。然后我在集群中的每个节点下安装了它，并以 spark 作为集群管理器在本地模式下运行。我的`spark-submit`脚本如下：

```scala
[hadoop@hc2nn twitter1]$ more run_twitter.bash
#!/bin/bash

SPARK_HOME=/usr/local/spark
SPARK_BIN=$SPARK_HOME/bin
SPARK_SBIN=$SPARK_HOME/sbin

JAR_PATH=/home/hadoop/spark/twitter1/target/scala-2.10/data-bricks_2.10-1.0.jar
CLASS_VAL=nz.co.semtechsolutions.twitter1

TWITTER_JAR=/usr/local/spark/lib/spark-examples-1.3.1-hadoop2.3.0.jar

cd $SPARK_BIN

./spark-submit \
 --class $CLASS_VAL \
 --master spark://hc2nn.semtech-solutions.co.nz:7077  \
 --executor-memory 100M \
 --total-executor-cores 50 \
 --jars $TWITTER_JAR \
 $JAR_PATH

```

我不会详细介绍，因为已经涵盖了很多次，除了注意现在类值是`nz.co.semtechsolutions.twitter1`。这是包类名，加上应用对象类名。所以，当我在本地运行时，我得到以下输出：

```scala
======================================
Count of hash tags in stream table : 707
======================================
Popular topics in last 60 seconds (704 total):
#KCAMÉXICO (139 tweets)
#BE3 (115 tweets)
#Fallout4 (98 tweets)
#OrianaSabatini (69 tweets)
#MartinaStoessel (61 tweets)
======================================

```

这告诉我应用程序库起作用了。它连接到 Twitter，创建数据流，能够将数据过滤为哈希标签，并使用数据创建临时表。因此，创建了一个用于 Twitter 数据流的 JAR 库，并证明它有效后，我现在可以将其加载到 Databricks 云上。以下截图显示了从 Databricks 云作业菜单创建了一个名为`joblib1`的作业。**设置 Jar**选项已用于上传刚刚创建的 JAR 库。已指定了到`twitter1`应用对象类的完整基于包的名称。

![基于流的报告](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_18.jpg)

以下截图显示了名为`joblib1`的作业，已准备就绪。基于 Spark 的集群将根据需要创建，一旦使用**立即运行**选项执行作业，将在**活动运行**部分下立即执行。虽然没有指定调度选项，但可以定义作业在特定日期和时间运行。

![基于流的报告](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_19.jpg)

我选择了**立即运行**选项来启动作业运行，如下截图所示。这显示现在有一个名为`Run 1`的活动运行。它已经运行了六秒。它是手动启动的，正在等待创建按需集群。通过选择运行名称`Run 1`，我可以查看有关作业的详细信息，特别是已记录的输出。

![基于流的报告](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_20.jpg)

以下截图显示了`joblib1`的`Run 1`输出的示例。它显示了开始时间和持续时间，还显示了运行状态和作业详细信息，包括类和 JAR 文件。它本应该显示类参数，但在这种情况下没有。它还显示了 54GB 按需集群的详细信息。更重要的是，它显示了前五个推文哈希标签值的列表。

![基于流的报告](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_21.jpg)

以下截图显示了 Databricks 云实例中相同作业运行输出窗口。但这显示了来自 SQL `count(*)`的输出，显示了当前数据流推文窗口中临时表中的推文哈希标签数量。

![基于流的报告](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_22.jpg)

因此，这证明了我可以在本地创建一个应用程序库，使用基于 Twitter 的 Apache Spark 流处理，并将数据流转换为数据框架和临时表。它表明我可以通过在本地开发，然后将我的库移植到 Databricks 云来降低成本。我知道在这个例子中我既没有将临时表可视化，也没有将 DataFrame 可视化为 Databricks 图表，但时间不允许我这样做。另外，如果有时间，我会做的另一件事是在应用程序失败时进行检查点或定期保存流到文件。然而，这个主题在第三章中有所涵盖，*Apache Spark Streaming*中有一个例子，所以如果您感兴趣，可以在那里看一下。在下一节中，我将检查 Databricks REST API，它将允许您的外部应用程序与 Databricks 云实例更好地集成。

# REST 接口

Databricks 为基于 Spark 集群的操作提供了 REST 接口。它允许集群管理、库管理、命令执行和上下文的执行。要能够访问 REST API，AWS EC2 基础的 Databricks 云中的实例必须能够访问端口`34563`。以下是尝试访问我 Databricks 云实例端口`34563`的 Telnet 命令。请注意，Telnet 尝试已成功：

```scala
[hadoop@hc2nn ~]$ telnet dbc-bff687af-08b7.cloud.databricks.com 34563
Trying 52.6.229.109...
Connected to dbc-bff687af-08b7.cloud.databricks.com.
Escape character is '^]'.

```

如果您没有收到 Telnet 会话，请通过`<help@databricks.com>`联系 Databricks。接下来的部分提供了访问 Databricks 云实例的 REST 接口示例。

## 配置

为了使用接口，我需要将我用于访问 Databricks 集群实例的 IP 地址加入白名单。这是我将运行 REST API 命令的机器的 IP 地址。通过将 IP 地址加入白名单，Databricks 可以确保每个 Databricks 云实例都有一个安全的用户访问列表。

我通过之前的帮助电子邮件地址联系了 Databricks 支持，但在您的云实例的**工作区**菜单中还有一个白名单 IP 指南：

**工作区** | **databricks_guide** | **DevOps 工具** | **白名单 IP**。

现在可以使用 Linux `curl`命令从 Linux 命令行向我的 Databricks 云实例提交 REST API 调用。下面显示了`curl`命令的示例通用形式，使用了我的 Databricks 云实例用户名、密码、云实例 URL、REST API 路径和参数。

Databricks 论坛和之前的帮助电子邮件地址可用于获取更多信息。接下来的部分将提供一些 REST API 的工作示例：

```scala
curl –u  '<user>:<paswd>' <dbc url> -d "<parameters>"

```

## 集群管理

您仍然需要从您的云实例用户界面创建 Databricks Spark 集群。列表 REST API 命令如下：

```scala
/api/1.0/clusters/list

```

它不需要任何参数。此命令将提供您的集群列表、它们的状态、IP 地址、名称以及它们运行的端口号。以下输出显示，集群`semclust1`处于挂起状态，正在创建过程中：

```scala
curl -u 'xxxx:yyyyy' 'https://dbc-bff687af-08b7.cloud.databricks.com:34563/api/1.0/clusters/list'

 [{"id":"0611-014057-waist9","name":"semclust1","status":"Pending","driverIp":"","jdbcPort":10000,"numWorkers":0}]

```

当集群可用时运行相同的 REST API 命令，显示名为`semcust1`的集群正在运行，并且有一个 worker：

```scala
[{"id":"0611-014057-waist9","name":"semclust1","status":"Running","driverIp":"10.0.196.161","jdbcPort":10000,"numWorkers":1}]

```

终止此集群，并创建一个名为`semclust`的新集群，将更改 REST API 调用的结果，如下所示：

```scala
curl -u 'xxxx:yyyy' 'https://dbc-bff687af-08b7.cloud.databricks.com:34563/api/1.0/clusters/list'

[{"id":"0611-023105-moms10","name":"semclust", "status":"Pending","driverIp":"","jdbcPort":10000,"numWorkers":0},
 {"id":"0611-014057-waist9","name":"semclust1","status":"Terminated","driverIp":"10.0.196.161","jdbcPort":10000,"numWorkers":1}]

```

## 执行上下文

使用这些 API 调用，您可以创建、显示或删除执行上下文。REST API 调用如下：

+   `/api/1.0/contexts/create`

+   `/api/1.0/contexts/status`

+   `/api/1.0/contexts/destroy`

在以下 REST API 调用示例中，通过`curl`提交，为标识为其集群 ID 的`semclust`创建了一个 Scala 上下文。

```scala
curl -u 'xxxx:yyyy' https://dbc-bff687af-08b7.cloud.databricks.com:34563/api/1.0/contexts/create -d "language=scala&clusterId=0611-023105-moms10"

```

返回的结果要么是错误，要么是上下文 ID。以下三个示例返回值显示了由无效 URL 引起的错误，以及两个成功调用返回的上下文 ID：

```scala
{"error":"ClusterNotFoundException: Cluster not found: semclust1"}
{"id":"8689178710930730361"}
{"id":"2876384417314129043"}

```

## 命令执行

这些命令允许您运行命令、列出命令状态、取消命令或显示命令的结果。REST API 调用如下：

+   /api/1.0/commands/execute

+   /api/1.0/commands/cancel

+   /api/1.0/commands/status

下面的示例显示了针对名为`cmap`的现有表运行的 SQL 语句。上下文必须存在，并且必须是 SQL 类型。参数已通过`-d`选项传递给 HTTP GET 调用。参数是语言、集群 ID、上下文 ID 和 SQL 命令。命令 ID 返回如下：

```scala
curl -u 'admin:FirmWare1$34' https://dbc-bff687af-08b7.cloud.databricks.com:34563/api/1.0/commands/execute -d
"language=sql&clusterId=0611-023105-moms10&contextId=7690632266172649068&command=select count(*) from cmap"

{"id":"d8ec4989557d4a4ea271d991a603a3af"}

```

## 库

REST API 还允许上传库到集群并检查它们的状态。REST API 调用路径如下：

+   `/api/1.0/libraries/upload`

+   `/api/1.0/libraries/list`

接下来给出了一个上传到名为`semclust`的集群实例的库的示例。通过`-d`选项将参数传递给 HTTP GET API 调用的语言、集群 ID、库名称和 URI。成功的调用将返回库的名称和 URI，如下所示：

```scala
curl -u 'xxxx:yyyy' https://dbc-bff687af-08b7.cloud.databricks.com:34563/api/1.0/libraries/upload
 -d "language=scala&clusterId=0611-023105-moms10&name=lib1&uri=file:///home/hadoop/spark/ann/target/scala-2.10/a-n-n_2.10-1.0.jar"

{"name":"lib1","uri":"file:///home/hadoop/spark/ann/target/scala-2.10/a-n-n_2.10-1.0.jar"}

```

请注意，此 REST API 可能会随内容和版本而更改，因此请在 Databricks 论坛中检查，并使用以前的帮助电子邮件地址与 Databricks 支持检查 API 详细信息。我认为，通过这些简单的示例调用，很明显这个 REST API 可以用于将 Databricks 与外部系统和 ETL 链集成。在下一节中，我将概述 Databricks 云内的数据移动。

# 数据移动

有关在 Databricks 中移动数据的一些方法已经在第八章 *Spark Databricks*和第九章 *Databricks Visualization*中进行了解释。我想在本节中概述所有可用的移动数据方法。我将研究表、工作区、作业和 Spark 代码的选项。

## 表数据

Databricks 云的表导入功能允许从 AWS **S3**存储桶、**Databricks 文件系统**（**DBFS**）、通过 JDBC 以及从本地文件导入数据。本节概述了每种类型的导入，从**S3**开始。从 AWS **S3**导入表数据需要 AWS 密钥、AWS 秘钥和**S3**存储桶名称。以下屏幕截图显示了一个示例。我已经提供了一个**S3**存储桶创建的示例，包括添加访问策略，因此我不会再次介绍它。

![表数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_23.jpg)

一旦添加了表单详细信息，您就可以浏览您的**S3**存储桶以获取数据源。选择`DBFS`作为表数据源可以浏览您的`DBFS`文件夹和文件。选择数据源后，可以显示预览，如下面的屏幕截图所示：

![表数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_24.jpg)

选择`JDBC`作为表格数据源允许您指定远程 SQL 数据库作为数据源。只需添加一个访问**URL**、**用户名**和**密码**。还可以添加一些 SQL 来定义表和源列。还有一个通过**添加属性**按钮添加额外属性的选项，如下面的屏幕截图所示：

![表格数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_25.jpg)

选择**文件**选项以从文件中填充 Databricks 云实例表，创建一个下拉或浏览。此上传方法先前用于将基于 CSV 的数据上传到表中。一旦指定了数据源，就可以指定数据分隔符字符串或标题行，定义列名或列类型，并在创建表之前预览数据。

![表格数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_26.jpg)

## 文件夹导入

从工作区或文件夹下拉菜单中，可以导入项目。以下屏幕截图显示了**导入项目**菜单选项的复合图像：

![文件夹导入](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_27.jpg)

这将创建一个文件拖放或浏览窗口，当点击时，允许您浏览本地服务器以导入项目。选择“所有支持的类型”选项显示可以导入的项目可以是 JAR 文件、dbc 存档、Scala、Python 或 SQL 文件。

## 库导入

以下屏幕截图显示了来自 Workspace 和文件夹菜单选项的**新库**功能。这允许将外部创建和测试的库加载到您的 Databricks 云实例中。该库可以是 Java 或 Scala JAR 文件、Python Egg 或用于访问存储库的 Maven 坐标。在下面的屏幕截图中，正在从本地服务器通过浏览窗口选择一个 JAR 文件。本章中使用了此功能来测试基于流的 Scala 编程：

![库导入](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_09_28.jpg)

# 进一步阅读

在总结本章之前，也是 Databricks 云端使用 Apache Spark 的最后一章，我想提及一些关于 Apache Spark 和 Databricks 的额外信息资源。首先，有 Databricks 论坛可供访问：[forums.databricks.com/](http://forums.databricks.com/)，用于与[`databricks.com/`](https://databricks.com/)的使用相关的问题和答案。此外，在您的 Databricks 实例中，在 Workspace 菜单选项下，将有一个包含许多有用信息的 Databricks 指南。Apache Spark 网站[`spark.apache.org/`](http://spark.apache.org/)也包含许多有用信息，以及基于模块的 API 文档。最后，还有 Spark 邮件列表，`<user@spark.apache.org>`，提供了大量关于 Spark 使用信息和问题解决的信息。

# 摘要

第八章、*Spark Databricks*和第九章、*Databricks 可视化*，已经介绍了 Databricks 在云安装方面的情况，以及 Notebooks 和文件夹的使用。已经检查了帐户和集群管理。还检查了作业创建、远程库创建的概念以及导入。解释了 Databricks `dbutils`包的功能，以及 Databricks 文件系统在第八章、*Spark Databricks*中。还展示了表格和数据导入的示例，以便对数据集运行 SQL。

已经检查了数据可视化的概念，并创建了各种图表。已经创建了仪表板，以展示创建和共享这种数据呈现的简易性。通过示例展示了 Databricks REST 接口，作为远程使用 Databricks 云实例并将其与外部系统集成的辅助。最后，已经检查了关于工作区、文件夹和表的数据和库移动选项。

您可能会问为什么我要把两章内容都献给像 Databricks 这样的基于云的服务。原因是 Databricks 似乎是从 Apache Spark 发展而来的一个逻辑上的基于云的进展。它得到了最初开发 Apache Spark 的人的支持，尽管作为一个服务还处于初期阶段，可能会发生变化，但仍然能够提供基于 Spark 的云生产服务。这意味着一家希望使用 Spark 的公司可以使用 Databricks，并随着需求增长而扩展他们的云，并且可以访问动态的基于 Spark 的机器学习、图处理、SQL、流处理和可视化功能。

正如以往一样，这些 Databricks 章节只是触及了功能的表面。下一步将是自己创建一个 AWS 和 Databricks 账户，并使用这里提供的信息来获得实际经验。

由于这是最后一章，我将再次提供我的联系方式。我对人们如何使用 Apache Spark 感兴趣。我对您创建的集群规模以及您处理的数据感兴趣。您是将 Spark 作为处理引擎使用吗？还是在其上构建系统？您可以在 LinkedIn 上与我联系：[linkedin.com/profile/view?id=73219349](http://linkedin.com/profile/view?id=73219349)。

您可以通过我的网站`semtech-solutions.co.nz`或最后通过电子邮件联系我：`<info@semtech-solutions.co.nz>`。

最后，我在有空的时候会维护一个与开源软件相关的演示文稿列表。任何人都可以免费使用和下载它们。它们可以在 SlideShare 上找到：[`www.slideshare.net/mikejf12/presentations`](http://www.slideshare.net/mikejf12/presentations)。

如果您有任何具有挑战性的机会或问题，请随时使用上述联系方式与我联系。
