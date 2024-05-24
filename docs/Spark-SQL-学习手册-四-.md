# Spark SQL 学习手册（四）

> 原文：[`zh.annas-archive.org/md5/38E33AE602B4FA8FF02AE9F0398CDE84`](https://zh.annas-archive.org/md5/38E33AE602B4FA8FF02AE9F0398CDE84)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：在深度学习应用中使用 Spark SQL

在过去的十年中，深度学习已经成为解决机器学习中几个困难问题的优越解决方案。我们听说深度学习被部署到许多不同领域，包括计算机视觉、语音识别、自然语言处理、音频识别、社交媒体应用、机器翻译和生物学。通常，使用深度学习方法产生的结果与或优于人类专家产生的结果。

已经有几种不同类型的深度学习模型被应用到不同的问题上。我们将回顾这些模型的基本概念并呈现一些代码。这是 Spark 中一个新兴的领域，所以尽管有几种不同的库可用，但很多都还处于早期版本或者每天都在不断发展。我们将简要概述其中一些库，包括使用 Spark 2.1.0、Scala 和 BigDL 的一些代码示例。我们选择 BigDL 是因为它是少数几个直接在 Spark Core 上运行的库之一（类似于其他 Spark 包），并且使用 Scala API 与 Spark SQL DataFrame API 和 ML pipelines 一起工作。

更具体地，在本章中，您将学习以下内容：

+   什么是深度学习？

+   了解各种深度学习模型的关键概念

+   了解 Spark 中的深度学习

+   使用 BigDL 和 Spark

# 神经网络介绍

神经网络，或者人工神经网络（ANN），是一组松散模拟人脑的算法或实际硬件。它们本质上是一组相互连接的处理节点，旨在识别模式。它们适应于或从一组训练模式中学习，如图像、声音、文本、时间序列等。

神经网络通常组织成由相互连接的节点组成的层。这些节点通过连接彼此进行通信。模式通过输入层呈现给网络，然后传递给一个或多个隐藏层。实际的计算是在这些隐藏层中执行的。最后一个隐藏层连接到一个输出层，输出最终答案。

特定节点的总输入通常是连接节点的每个输出的函数。这些输入对节点的贡献可以是兴奋的或抑制的，并最终有助于确定信号是否以及在多大程度上通过网络进一步传播（通过激活函数）。通常，Sigmoid 激活函数非常受欢迎。在一些应用中，也使用了线性、半线性或双曲正切（`Tanh`）函数。在节点的输出是总输入的随机函数的情况下，输入决定了给定节点获得高激活值的概率。

网络内部连接的权重根据学习规则进行修改；例如，当神经网络最初呈现一种模式时，它会猜测权重可能是什么。然后，它评估其答案与实际答案的差距，并对其连接权重进行适当调整。

有关神经网络基础知识的良好介绍，请参考：Bolo 的《神经网络基础介绍》，网址：[`pages.cs.wisc.edu/~bolo/shipyard/neural/local.html`](http://pages.cs.wisc.edu/~bolo/shipyard/neural/local.html)。

在接下来的章节中，我们将介绍各种类型的神经网络的更具体细节。

# 了解深度学习

深度学习是将人工神经网络应用于学习任务。深度学习方法基于学习数据表示，而不是特定于任务的算法。尽管学习可以是监督的或无监督的，但最近的重点是创建能够从大规模未标记数据集中学习这些表示的高效系统。

下图描述了一个具有两个隐藏层的简单深度学习神经网络：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00282.jpeg)

深度学习通常包括多层处理单元，每一层都在其中学习特征表示。这些层形成特征的层次结构，深度学习假设这种层次结构对应于抽象级别。因此，它利用了分层解释因素的思想，更高级别的更抽象的概念是从更低级别的概念中学习的。通过改变层数和层大小，可以提供不同数量的抽象，根据使用情况的需要。

# 理解表示学习

深度学习方法是具有多个抽象层次的表示学习方法。在这里，非线性模块将原始输入转换为更高、稍微更抽象级别的表示。最终，通过组合足够数量的这样的层，可以学习非常复杂的函数。

有关深度学习的综述论文，请参阅 Yann LeCun、Yoshua Bengio 和 Geoffrey Hinton 的《深度学习》，可在[`www.nature.com/nature/journal/v521/n7553/full/nature14539.html?foxtrotcallback=true`](http://www.nature.com/nature/journal/v521/n7553/full/nature14539.html?foxtrotcallback=true)上找到。

现在，我们将说明在传统模式识别任务中学习表示和特征的过程：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00283.jpeg)

传统的机器学习技术在处理自然数据的原始形式时受到限制。构建这样的机器学习系统需要深入的领域专业知识和大量的努力，以识别（并保持更新）学习子系统，通常是分类器，可以从中检测或分类输入中的模式的特征。

许多传统的机器学习应用程序使用手工制作的特征上的线性分类器。这样的分类器通常需要一个良好的特征提取器，产生对图像方面有选择性的表示。然而，如果可以使用通用学习程序自动学习良好的特征，那么所有这些努力都是不必要的。深度学习的这一特定方面代表了深度学习的一个关键优势。

与早期的机器学习技术相比，深度学习中的高级过程通常是，其中端到端的学习过程还涉及从数据中学习的特征。这在这里有所说明：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00284.jpeg)

在下一节中，我们将简要讨论一种最常用的函数，即随机梯度下降，用于调整网络中的权重。

# 理解随机梯度下降

深度学习系统可以包括数百万个可调整的权重，并且使用数百万个标记的示例来训练机器。在实践中，**随机梯度下降**（**SGD**）优化被广泛应用于许多不同的情况。在 SGD 中，梯度描述了网络的错误与单个权重之间的关系，即当调整权重时错误如何变化。

这种优化方法包括：

+   为一些示例呈现输入向量

+   计算输出和错误

+   计算示例的平均梯度

+   适当调整权重

这个过程对许多小的训练示例集重复进行。当目标函数的平均值停止减少时，过程停止。

与更复杂的优化技术相比，这个简单的过程通常能够非常有效地产生一组良好的权重。此外，训练过程所需的时间也要短得多。训练过程完成后，通过在测试数据集上运行经过训练的模型来衡量系统的性能。测试集包含机器之前在训练阶段未见过的新输入。

在深度学习神经网络中，激活函数通常设置在层级，并应用于特定层中的所有神经元或节点。此外，多层深度学习神经网络的输出层起着特定的作用；例如，在监督学习（带有标记的输入）中，它基于从前一层接收到的信号应用最可能的标签。输出层上的每个节点代表一个标签，并且该节点产生两种可能的结果之一，即`0`或`1`。虽然这样的神经网络产生二进制输出，但它们接收的输入通常是连续的；例如，推荐引擎的输入可以包括客户上个月的消费金额和过去一个月每周平均客户访问次数等因素。输出层必须将这些信号处理成给定输入的概率度量。

# 在 Spark 中介绍深度学习

在本节中，我们将回顾一些使用 Spark 的更受欢迎的深度学习库。这些包括 CaffeOnSpark、DL4J、TensorFrames 和 BigDL。

# 介绍 CaffeOnSpark

CaffeOnSpark 是 Yahoo 为 Hadoop 集群上的大规模分布式深度学习开发的。通过将深度学习框架 Caffe 的特性与 Apache Spark（和 Apache Hadoop）结合，CaffeOnSpark 实现了在 GPU 和 CPU 服务器集群上的分布式深度学习。

有关 CaffeOnSpark 的更多详细信息，请参阅[`github.com/yahoo/CaffeOnSpark`](https://github.com/yahoo/CaffeOnSpark)。

CaffeOnSpark 支持神经网络模型的训练、测试和特征提取。它是非深度学习库 Spark MLlib 和 Spark SQL 的补充。CaffeOnSpark 的 Scala API 为 Spark 应用程序提供了一种简单的机制，以在分布式数据集上调用深度学习算法。在这里，深度学习通常是在现有数据处理流水线的同一集群中进行，以支持特征工程和传统的机器学习应用。因此，CaffeOnSpark 允许将深度学习训练和测试过程嵌入到 Spark 应用程序中。

# 介绍 DL4J

DL4J 支持在 Spark 集群上训练神经网络，以加速网络训练。当前版本的 DL4J 在每个集群节点上使用参数平均化的过程来训练网络。当主节点拥有训练好的网络的副本时，训练就完成了。

有关 DL4J 的更多详细信息，请参阅[`deeplearning4j.org/spark`](https://deeplearning4j.org/spark)。

# 介绍 TensorFrames

实验性的 Scala 和 Apache Spark 的 TensorFlow 绑定目前在 GitHub 上可用。TensorFrames 本质上是 Spark Dataframes 上的 TensorFlow，它允许您使用 TensorFlow 程序操作 Apache Spark 的 DataFrames。目前，Scala 支持比 Python 更有限--Scala DSL 具有 TensorFlow 变换的子集。

有关 TensorFrames 的更多详细信息，请访问[`github.com/databricks/tensorframes`](https://github.com/databricks/tensorframes)。

在 Scala 中，操作可以从以`ProtocolBuffers`格式定义的现有图形中加载，也可以使用简单的 Scala DSL。然而，鉴于 TensorFlow 的整体流行，这个库正在受到关注，并且在 Python 社区中更受欢迎。

# 使用 BigDL

BigDL 是 Apache Spark 的开源分布式深度学习库。最初由英特尔开发并开源。使用 BigDL，开发人员可以将深度学习应用程序编写为标准的 Spark 程序。这些程序直接在现有的 Spark 或 Hadoop 集群上运行，如图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00285.jpeg)

BigDL 是基于 Torch 建模的，它支持深度学习，包括数值计算（通过张量）和[神经网络](https://github.com/intel-analytics/BigDL/tree/master/spark/dl/src/main/scala/com/intel/analytics/bigdl/nn)。此外，开发人员可以将预训练的[Caffe](http://caffe.berkeleyvision.org/)或[Torch](http://torch.ch/)模型加载到 BigDL-Spark 程序中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00286.jpeg)

为了实现高性能，BigDL 在每个 Spark 任务中使用[Intel MKL](https://software.intel.com/en-us/intel-mkl)和多线程编程。

有关 BigDL 文档、示例和 API 指南，请访问[`bigdl-project.github.io/master/`](https://bigdl-project.github.io/master/)。

下图显示了 BigDL 程序在 Spark 集群上的高级执行方式。借助集群管理器和驱动程序，Spark 任务分布在 Spark 工作节点或容器（执行器）上：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00287.jpeg)

我们将在本章的后面几节中执行 BigDL 分发中提供的几个深度神经网络的示例。目前，这是少数几个与 Spark SQL DataFrame API 和 ML 管道一起使用的库之一。

在下一节中，我们将重点介绍如何利用 Spark 并行调整超参数。

# 调整深度学习模型的超参数

构建神经网络时，有许多重要的超参数需要仔细选择。考虑以下示例：

+   每层神经元的数量：很少的神经元会降低网络的表达能力，但太多的神经元会大大增加运行时间并返回嘈杂的估计值

+   学习率：如果学习率太高，神经网络将只关注最近看到的几个样本，并忽略之前积累的所有经验；如果学习率太低，将需要很长时间才能达到良好的状态

超参数调整过程是“尴尬并行”的，可以使用 Spark 进行分布。

有关更多详细信息，请参阅 Tim Hunter 的*Deep Learning with Apache Spark and TensorFlow*，网址为[`databricks.com/blog/2016/01/25/deep-learning-with-apache-spark-and-tensorflow.html`](https://databricks.com/blog/2016/01/25/deep-learning-with-apache-spark-and-tensorflow.html)。

# 介绍深度学习管道

Spark 中有一个新兴的库，用于支持深度学习管道，它提供了用于 Python 中可扩展深度学习的高级 API。目前支持 TensorFlow 和基于 TensorFlow 的 Keras 工作流程，重点是在规模化图像数据上进行模型推断/评分和迁移学习。

要关注 Spark 中深度学习管道的发展，请访问[`github.com/databricks/spark-deep-learning`](https://github.com/databricks/spark-deep-learning)。

此外，它为数据科学家和机器学习专家提供了工具，可以将深度学习模型转换为 SQL UDF，这样更广泛的用户群体就可以使用。这也是生产深度学习模型的一种好方法。

在下一节中，我们将把重点转移到监督学习上。

# 理解监督学习

最常见的机器学习形式是监督学习；例如，如果我们正在构建一个用于分类特定图像集的系统，我们首先收集来自相同类别的大量图像数据集。在训练期间，机器显示一幅图像，并产生一个以每个类别为一个分数的向量形式的输出。作为训练的结果，我们期望所需的类别在所有类别中具有最高的分数。

深度网络的一种特殊类型——卷积神经网络（ConvNet/CNN）——比全连接网络更容易训练，泛化能力也更好。在监督学习场景中，深度卷积网络显著改善了图像、视频、语音和音频数据的处理结果。同样，循环网络也为顺序数据（如文本和语音）带来了曙光。我们将在接下来的部分探讨这些类型的神经网络。

# 理解卷积神经网络

卷积神经网络是一种特殊类型的多层神经网络，它们被设计来直接从像素图像中识别视觉模式，需要最少的预处理。它们可以识别具有广泛变化的模式，并且可以有效地处理扭曲和简单的几何变换。CNN 也是使用反向传播算法的一种版本进行训练。

典型 ConvNet 的架构被构造为一系列包含多个堆叠卷积、非线性和池化层的阶段，然后是额外的卷积和全连接层。非线性函数通常是**修正线性单元**（ReLU）函数，池化层的作用是将相似特征语义地合并为一个。因此，池化允许表示在前一层的元素在位置和外观上变化很少时也能变化很小。

LeNet-5 是一个专为手写和机器打印字符识别设计的卷积网络。在这里，我们介绍了 BigDL 分发中可用的 Lenet-5 的一个例子。

该示例的完整源代码可在[`github.com/intel-analytics/BigDL/tree/master/spark/dl/src/main/scala/com/intel/analytics/bigdl/models/lenet`](https://github.com/intel-analytics/BigDL/tree/master/spark/dl/src/main/scala/com/intel/analytics/bigdl/models/lenet)找到。

在这里，我们将使用 Spark shell 执行相同的代码。请注意，常量的值都取自上述网站提供的源代码。

首先，执行`bigdl` shell 脚本来设置环境：

```scala
source /Users/aurobindosarkar/Downloads/BigDL-master/scripts/bigdl.sh
```

然后，我们使用适当指定 BigDL JAR 启动 Spark shell：

```scala
bin/spark-shell --properties-file /Users/aurobindosarkar/Downloads/BigDL-master/spark/dist/target/bigdl-0.2.0-SNAPSHOT-spark-2.0.0-scala-2.11.8-mac-dist/conf/spark-bigdl.conf --jars /Users/aurobindosarkar/Downloads/BigDL-master/spark/dist/target/bigdl-0.2.0-SNAPSHOT-spark-2.0.0-scala-2.11.8-mac-dist/lib/bigdl-0.2.0-SNAPSHOT-jar-with-dependencies.jar
```

这个例子的数据集可以从[`yann.lecun.com/exdb/mnist/`](http://yann.lecun.com/exdb/mnist/)下载。

本例的 Spark shell 会话如下所示：

```scala
scala> import com.intel.analytics.bigdl._
scala> import com.intel.analytics.bigdl.dataset.DataSet
scala> import com.intel.analytics.bigdl.dataset.image.{BytesToGreyImg, GreyImgNormalizer, GreyImgToBatch, GreyImgToSample}
scala> import com.intel.analytics.bigdl.nn.{ClassNLLCriterion, Module}
scala> import com.intel.analytics.bigdl.numeric.NumericFloat
scala> import com.intel.analytics.bigdl.optim._
scala> import com.intel.analytics.bigdl.utils.{Engine, T,
scala> import com.intel.analytics.bigdl.nn._
scala> import java.nio.ByteBuffer
scala> import java.nio.file.{Files, Path, Paths}
scala> import com.intel.analytics.bigdl.dataset.ByteRecord
scala> import com.intel.analytics.bigdl.utils.File

scala> val trainData = "/Users/aurobindosarkar/Downloads/mnist/train-images-idx3-ubyte"
scala> val trainLabel = "/Users/aurobindosarkar/Downloads/mnist/train-labels-idx1-ubyte"
scala> val validationData = "/Users/aurobindosarkar/Downloads/mnist/t10k-images-idx3-ubyte"
scala> val validationLabel = "/Users/aurobindosarkar/Downloads/mnist/t10k-labels-idx1-ubyte"

scala> val nodeNumber = 1 //Number of nodes
scala> val coreNumber = 2 //Number of cores

scala> Engine.init

scala> val model = Sequential[Float]()
model: com.intel.analytics.bigdl.nn.Sequential[Float] =
nn.Sequential {
[input -> -> output]
}

scala> val classNum = 10 //Number of classes (digits)
scala> val batchSize = 12
//The model uses the Tanh function for non-linearity.
//It has two sets layers comprising of Convolution-Non-Linearity-Pooling
//It uses a Softmax function to output the results

scala> model.add(Reshape(Array(1, 28, 28))).add(SpatialConvolution(1, 6, 5, 5)).add(Tanh()).add(SpatialMaxPooling(2, 2, 2, 2)).add(Tanh()).add(SpatialConvolution(6, 12, 5, 5)).add(SpatialMaxPooling(2, 2, 2, 2)).add(Reshape(Array(12 * 4 * 4))).add(Linear(12 * 4 * 4, 100)).add(Tanh()).add(Linear(100, classNum)).add(LogSoftMax())

res1: model.type =
nn.Sequential {
[input -> (1) -> (2) -> (3) -> (4) -> (5) -> (6) -> (7) -> (8) -> (9) -> (10) -> (11) -> (12) -> output]
(1): nn.Reshape(1x28x28)
(2): nn.SpatialConvolution(1 -> 6, 5 x 5, 1, 1, 0, 0)
(3): nn.Tanh
(4): nn.SpatialMaxPooling(2, 2, 2, 2, 0, 0)
(5): nn.Tanh
(6): nn.SpatialConvolution(6 -> 12, 5 x 5, 1, 1, 0, 0)
(7): nn.SpatialMaxPooling(2, 2, 2, 2, 0, 0)
(8): nn.Reshape(192)
(9): nn.Linear(192 -> 100)
(10): nn.Tanh
(11): nn.Linear(100 -> 10)
(12): nn.LogSoftMax
}

//The following is a private function in Utils.
scala> def load(featureFile: String, labelFile: String): Array[ByteRecord] = {
|    val featureBuffer = ByteBuffer.wrap(Files.readAllBytes(Paths.get(featureFile)))
|    val labelBuffer = ByteBuffer.wrap(Files.readAllBytes(Paths.get(labelFile)));
|    val labelMagicNumber = labelBuffer.getInt();
|    require(labelMagicNumber == 2049);
|    val featureMagicNumber = featureBuffer.getInt();
|    require(featureMagicNumber == 2051);
|    val labelCount = labelBuffer.getInt();
|    val featureCount = featureBuffer.getInt();
|    require(labelCount == featureCount);
|    val rowNum = featureBuffer.getInt();
|    val colNum = featureBuffer.getInt();
|    val result = new ArrayByteRecord;
|    var i = 0;
|    while (i < featureCount) {
|       val img = new ArrayByte);
|       var y = 0;
|       while (y < rowNum) {
|          var x = 0;
|          while (x < colNum) {
|             img(x + y * colNum) = featureBuffer.get();
|             x += 1;
|          }
|          y += 1;
|       }
|       result(i) = ByteRecord(img, labelBuffer.get().toFloat + 1.0f);
|       i += 1;
|    }
|    result;
| }

scala> val trainMean = 0.13066047740239506
scala> val trainStd = 0.3081078

scala> val trainSet = DataSet.array(load(trainData, trainLabel), sc) -> BytesToGreyImg(28, 28) -> GreyImgNormalizer(trainMean, trainStd) -> GreyImgToBatch(batchSize)

scala> val optimizer = Optimizer(model = model, dataset = trainSet, criterion = ClassNLLCriterion[Float]())

scala> val testMean = 0.13251460696903547
scala> val testStd = 0.31048024
scala> val maxEpoch = 2

scala> val validationSet = DataSet.array(load(validationData, validationLabel), sc) -> BytesToGreyImg(28, 28) -> GreyImgNormalizer(testMean, testStd) -> GreyImgToBatch(batchSize)

scala> optimizer.setEndWhen(Trigger.maxEpoch(2))
scala> optimizer.setState(T("learningRate" -> 0.05, "learningRateDecay" -> 0.0))
scala> optimizer.setCheckpoint("/Users/aurobindosarkar/Downloads/mnist/checkpoint", Trigger.severalIteration(500))
scala> optimizer.setValidation(trigger = Trigger.everyEpoch, dataset = validationSet, vMethods = Array(new Top1Accuracy, new Top5Accuracy[Float], new Loss[Float]))

scala> optimizer.optimize()

scala> model.save("/Users/aurobindosarkar/Downloads/mnist/model") //Save the trained model to disk.
scala> val model = Module.loadFloat //Retrieve the model from the disk
scala> val partitionNum = 2
scala> val rddData = sc.parallelize(load(validationData, validationLabel), partitionNum)

scala> val transformer = BytesToGreyImg(28, 28) -> GreyImgNormalizer(testMean, testStd) -> GreyImgToSample()

scala> val evaluationSet = transformer(rddData)

scala> val result = model.evaluate(evaluationSet, Array(new Top1Accuracy[Float]), Some(batchSize))

scala> result.foreach(r => println(s"${r._2} is ${r._1}"))
Top1Accuracy is Accuracy(correct: 9831, count: 10000, accuracy: 0.9831)
```

在下一节中，我们将介绍一个文本分类的例子。

# 使用神经网络进行文本分类

其他越来越重要的应用包括自然语言理解和语音识别。

本节中的示例作为 BigDL 分发的一部分可用，完整的源代码可在[`github.com/intel-analytics/BigDL/tree/master/spark/dl/src/main/scala/com/intel/analytics/bigdl/example/textclassification`](https://github.com/intel-analytics/BigDL/tree/master/spark/dl/src/main/scala/com/intel/analytics/bigdl/example/textclassification)找到。

它使用预训练的 GloVe 嵌入将单词转换为向量，然后用它在包含二十个不同类别的二十个新闻组数据集上训练文本分类模型。这个模型在只训练两个时期后就可以达到 90%以上的准确率。

这里呈现了定义 CNN 模型和优化器的关键部分代码：

```scala
val model = Sequential[Float]()

//The model has 3 sets of Convolution and Pooling layers.
model.add(Reshape(Array(param.embeddingDim, 1, param.maxSequenceLength)))
model.add(SpatialConvolution(param.embeddingDim, 128, 5, 1))
model.add(ReLU())
model.add(SpatialMaxPooling(5, 1, 5, 1))
model.add(SpatialConvolution(128, 128, 5, 1))
model.add(ReLU())
model.add(SpatialMaxPooling(5, 1, 5, 1))
model.add(SpatialConvolution(128, 128, 5, 1))
model.add(ReLU())
model.add(SpatialMaxPooling(35, 1, 35, 1))
model.add(Reshape(Array(128)))
model.add(Linear(128, 100))
model.add(Linear(100, classNum))
model.add(LogSoftMax())

//The optimizer uses the Adagrad method
val optimizer = Optimizer(
model = buildModel(classNum),
sampleRDD = trainingRDD,
criterion = new ClassNLLCriterion[Float](),
batchSize = param.batchSize
)

optimizer
.setOptimMethod(new Adagrad(learningRate = 0.01, learningRateDecay = 0.0002))
.setValidation(Trigger.everyEpoch, valRDD, Array(new Top1Accuracy[Float]), param.batchSize)
.setEndWhen(Trigger.maxEpoch(20))
.optimize()
```

输入数据集的描述如下，以及它们的下载 URL：

+   **嵌入**：400k 个单词的 100 维预训练 GloVe 嵌入，训练于 2014 年英文维基百科的转储数据。从[`nlp.stanford.edu/data/glove.6B.zip`](http://nlp.stanford.edu/data/glove.6B.zip)下载预训练的 GloVe 单词嵌入。

+   **训练数据**：“20 Newsgroup 数据集”，包含 20 个类别，共 19,997 个文本。从[`www.cs.cmu.edu/afs/cs.cmu.edu/project/theo-20/www/data/news20.tar.gz`](http://www.cs.cmu.edu/afs/cs.cmu.edu/project/theo-20/www/data/news20.tar.gz)下载 20 Newsgroup 数据集作为训练数据。

在我们的示例中，我们将类别数量减少到八个，以避免在内存小于 16GB 的笔记本电脑上出现`内存不足`异常。将这些数据集放在`BASE_DIR`中；最终的目录结构应如图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00288.jpeg)

使用以下命令执行文本分类器：

```scala
Aurobindos-MacBook-Pro-2:BigDL aurobindosarkar$ /Users/aurobindosarkar/Downloads/BigDL-master/scripts/bigdl.sh -- /Users/aurobindosarkar/Downloads/spark-2.1.0-bin-hadoop2.7/bin/spark-submit --master "local[2]" --driver-memory 14g --class com.intel.analytics.bigdl.example.textclassification.TextClassifier /Users/aurobindosarkar/Downloads/BigDL-master/spark/dist/target/bigdl-0.2.0-SNAPSHOT-spark-2.0.0-scala-2.11.8-mac-dist/lib/bigdl-0.2.0-SNAPSHOT-jar-with-dependencies.jar --batchSize 128 -b /Users/aurobindosarkar/Downloads/textclassification -p 4
```

这里给出了示例输出以供参考：

```scala
17/08/16 14:50:07 INFO textclassification.TextClassifier$: Current parameters: TextClassificationParams(/Users/aurobindosarkar/Downloads/textclassification,1000,20000,0.8,128,100,4)
17/08/16 14:50:07 INFO utils.ThreadPool$: Set mkl threads to 1 on thread 1
17/08/16 14:50:09 INFO utils.Engine$: Auto detect executor number and executor cores number
17/08/16 14:50:09 INFO utils.Engine$: Executor number is 1 and executor cores number is 2
17/08/16 14:50:09 INFO utils.Engine$: Find existing spark context. Checking the spark conf...
17/08/16 14:50:10 INFO utils.TextClassifier: Found 8000 texts.
17/08/16 14:50:10 INFO utils.TextClassifier: Found 8 classes
17/08/16 14:50:13 INFO utils.TextClassifier: Indexing word vectors.
17/08/16 14:50:16 INFO utils.TextClassifier: Found 17424 word vectors.
17/08/16 14:50:16 INFO optim.DistriOptimizer$: caching training rdd ...
17/08/16 14:50:37 INFO optim.DistriOptimizer$: Cache thread models...
17/08/16 14:50:37 INFO optim.DistriOptimizer$: model thread pool size is 1
17/08/16 14:50:37 INFO optim.DistriOptimizer$: Cache thread models... done
17/08/16 14:50:37 INFO optim.DistriOptimizer$: config {
learningRate: 0.01
maxDropPercentage: 0.0
computeThresholdbatchSize: 100
warmupIterationNum: 200
learningRateDecay: 2.0E-4
dropPercentage: 0.0
}
17/08/16 14:50:37 INFO optim.DistriOptimizer$: Shuffle data
17/08/16 14:50:37 INFO optim.DistriOptimizer$: Shuffle data complete. Takes 0.012679728s
17/08/16 14:50:38 INFO optim.DistriOptimizer$: [Epoch 1 0/6458][Iteration 1][Wall Clock 0.0s] Train 128 in 0.962042186seconds. Throughput is 133.0503 records/second. Loss is 2.0774076.
17/08/16 14:50:40 INFO optim.DistriOptimizer$: [Epoch 1 128/6458][Iteration 2][Wall Clock 0.962042186s] Train 128 in 1.320501728seconds. Throughput is 96.93285 records/second. Loss is 4.793501.
17/08/16 14:50:40 INFO optim.DistriOptimizer$: [Epoch 1 256/6458][Iteration 3][Wall Clock 2.282543914s] Train 128 in 0.610049842seconds. Throughput is 209.81892 records/second. Loss is 2.1110187.
17/08/16 14:50:41 INFO optim.DistriOptimizer$: [Epoch 1 384/6458][Iteration 4][Wall Clock 2.892593756s] Train 128 in 0.609548069seconds. Throughput is 209.99164 records/second. Loss is 2.0820618.
17/08/16 14:50:42 INFO optim.DistriOptimizer$: [Epoch 1 512/6458][Iteration 5][Wall Clock 3.502141825s] Train 128 in 0.607720212seconds. Throughput is 210.62325 records/second. Loss is 2.0860045.
17/08/16 14:50:42 INFO optim.DistriOptimizer$: [Epoch 1 640/6458][Iteration 6][Wall Clock 4.109862037s] Train 128 in 0.607034064seconds. Throughput is 210.86131 records/second. Loss is 2.086178.
.
.
.
17/08/16 15:04:57 INFO optim.DistriOptimizer$: [Epoch 20 6144/6458][Iteration 1018][Wall Clock 855.715191033s] Train 128 in 0.771615991seconds. Throughput is 165.88562 records/second. Loss is 2.4244189E-4.
17/08/16 15:04:58 INFO optim.DistriOptimizer$: [Epoch 20 6272/6458][Iteration 1019][Wall Clock 856.486807024s] Train 128 in 0.770584628seconds. Throughput is 166.10765 records/second. Loss is 0.04117684.
17/08/16 15:04:59 INFO optim.DistriOptimizer$: [Epoch 20 6400/6458][Iteration 1020][Wall Clock 857.257391652s] Train 128 in 0.783425485seconds. Throughput is 163.38503 records/second. Loss is 3.2506883E-4.
17/08/16 15:04:59 INFO optim.DistriOptimizer$: [Epoch 20 6400/6458][Iteration 1020][Wall Clock 857.257391652s] Epoch finished. Wall clock time is 861322.002763ms
17/08/16 15:04:59 INFO optim.DistriOptimizer$: [Wall Clock 861.322002763s] Validate model...
17/08/16 15:05:02 INFO optim.DistriOptimizer$: Top1Accuracy is Accuracy(correct: 1537, count: 1542, accuracy: 0.996757457846952)
```

在下一节中，我们将探讨使用深度神经网络进行语言处理。

# 使用深度神经网络进行语言处理

如第九章中所讨论的，*使用 Spark SQL 开发应用程序*，语言的统计建模通常基于 n-grams 的出现频率。在大多数实际用例中，这通常需要非常大的训练语料库。此外，n-grams 将每个单词视为独立单元，因此它们无法概括语义相关的单词序列。相比之下，神经语言模型将每个单词与一组实值特征向量相关联，因此语义相关的单词在该向量空间中靠近。学习单词向量在单词序列来自大型真实文本语料库时也非常有效。这些单词向量由神经网络自动发现的学习特征组成。

从文本中学习的单词的向量表示现在在自然语言应用中被广泛使用。在下一节中，我们将探讨递归神经网络及其在文本分类任务中的应用。

# 理解递归神经网络

通常，对于涉及顺序输入的任务，建议使用**递归神经网络**（**RNNs**）。这样的输入一次处理一个元素，同时保持一个“状态向量”（在隐藏单元中）。状态隐含地包含有关序列中所有过去元素的信息。

通常，在传统的 RNN 中，很难长时间存储信息。为了长时间记住输入，网络可以增加显式内存。这也是**长短期记忆**（**LSTM**）网络中使用的方法；它们使用可以记住输入的隐藏单元。LSTM 网络已被证明比传统的 RNN 更有效。

在本节中，我们将探讨用于建模序列数据的递归神经网络。下图说明了一个简单的递归神经网络或 Elman 网络：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00289.jpeg)

这可能是最简单的递归神经网络的版本，易于实现和训练。网络有一个输入层，一个隐藏层（也称为上下文层或状态），和一个输出层。网络在时间`t`的输入是**Input(t)**，输出表示为**Output(t)**，**Context(t)**是网络的状态（隐藏层）。输入向量是通过连接表示当前单词的向量和时间`t-1`的上下文层中神经元的输出来形成的。

这些网络在几个时期内进行训练，其中训练语料库中的所有数据都被顺序呈现。为了训练网络，我们可以使用随机梯度下降的标准反向传播算法。每个时期后，网络都会在验证数据上进行测试。如果验证数据的对数似然性增加，训练将在新的时期继续。如果没有观察到显著的改善，学习率可以在每个新时期开始时减半。如果改变学习率没有显著改善，训练就结束了。这样的网络通常在 10-20 个时期后收敛。

这里，输出层表示在给定上一个单词和**Context(t − 1)**时下一个单词的概率分布。Softmax 确保概率分布是有效的。在每个训练步骤中，计算错误向量，并使用标准的反向传播算法更新权重，如下所示：

*error(t) = desired(t) − Output(t)*

这里，desired 是使用`1-of-N`编码的向量，表示在特定上下文中应该被预测的单词，**Output(t)**是网络的实际输出。

为了提高性能，我们可以将在训练文本中出现次数少于给定阈值的所有单词合并为一个特殊的稀有标记。因此，所有稀有单词都被平等对待，即它们之间的概率均匀分布。

现在，我们执行 BigDL 库中提供的一个简单的 RNN 示例。该网络是一个全连接的 RNN，其中输出被反馈到输入中。该示例模型支持序列到序列处理，并且是用于语言建模的简单循环神经网络的实现。

有关此示例的完整源代码，请参阅[`github.com/intel-analytics/BigDL/tree/master/spark/dl/src/main/scala/com/intel/analytics/bigdl/models/rnn`](https://github.com/intel-analytics/BigDL/tree/master/spark/dl/src/main/scala/com/intel/analytics/bigdl/models/rnn)。

输入数据集 Tiny Shakespeare Texts 可以从[`raw.githubusercontent.com/karpathy/char-rnn/master/data/tinyshakespeare/input.txt`](https://raw.githubusercontent.com/karpathy/char-rnn/master/data/tinyshakespeare/input.txt)下载。

下载文本后，将其放入适当的目录。我们将输入数据集拆分为单独的`train.txt`和`val.txt`文件。在我们的示例中，我们选择 80%的输入作为训练数据集，剩下的 20%作为验证数据集。

通过执行以下命令将输入数据集拆分：

```scala
head -n 8000 input.txt > val.txt
tail -n +8000 input.txt > train.txt
```

`SentenceSplitter`和`SentenceTokenizer`类使用`Apache OpenNLP`库。训练模型文件--`en-token.bin`和`en-sent.bin`--可以从[`opennlp.sourceforge.net/models-1.5/`](http://opennlp.sourceforge.net/models-1.5/)下载。

与模型和优化器相关的关键部分代码如下：

```scala
val model = Sequential[Float]()
//The RNN is created with the time-related parameter.
model.add(Recurrent[Float]()
.add(RnnCellFloat)))
.add(TimeDistributedFloat))

//The optimization method used is SGD.
val optimMethod = if (param.stateSnapshot.isDefined) {
OptimMethod.loadFloat
} else {
   new SGDFloat
}

val optimizer = Optimizer(
model = model,
dataset = trainSet,
criterion = TimeDistributedCriterionFloat, sizeAverage = true)
)

optimizer
.setValidation(Trigger.everyEpoch, validationSet, Array(new LossFloat, sizeAverage = true))))
.setOptimMethod(optimMethod)
.setEndWhen(Trigger.maxEpoch(param.nEpochs))
.setCheckpoint(param.checkpoint.get, Trigger.everyEpoch)
.optimize()
```

以下命令执行训练程序。修改特定于您的环境的参数：

```scala
Aurobindos-MacBook-Pro-2:bigdl-rnn aurobindosarkar$ /Users/aurobindosarkar/Downloads/BigDL-master/scripts/bigdl.sh -- \
> /Users/aurobindosarkar/Downloads/spark-2.1.0-bin-hadoop2.7/bin/spark-submit \
> --master local[2] \
> --executor-cores 2 \
> --total-executor-cores 2 \
> --class com.intel.analytics.bigdl.models.rnn.Train \
> /Users/aurobindosarkar/Downloads/dist-spark-2.1.1-scala-2.11.8-mac-0.3.0-20170813.202825-21-dist/lib/bigdl-SPARK_2.1-0.3.0-SNAPSHOT-jar-with-dependencies.jar \
> -f /Users/aurobindosarkar/Downloads/bigdl-rnn/inputdata/ -s /Users/aurobindosarkar/Downloads/bigdl-rnn/saveDict/ --checkpoint /Users/aurobindosarkar/Downloads/bigdl-rnn/model/ --batchSize 12 -e 2
```

下面是训练过程中生成的输出的一部分：

```scala
17/08/16 21:32:38 INFO utils.ThreadPool$: Set mkl threads to 1 on thread 1
17/08/16 21:32:39 INFO utils.Engine$: Auto detect executor number and executor cores number
17/08/16 21:32:39 INFO utils.Engine$: Executor number is 1 and executor cores number is 2
17/08/16 21:32:39 INFO utils.Engine$: Find existing spark context. Checking the spark conf...
17/08/16 21:32:41 INFO text.Dictionary: 272304 words and32885 sentences processed
17/08/16 21:32:41 INFO text.Dictionary: save created dictionary.txt and discard.txt to/Users/aurobindosarkar/Downloads/bigdl-rnn/saveDict
17/08/16 21:32:41 INFO rnn.Train$: maxTrain length = 25, maxVal = 22
17/08/16 21:32:42 INFO optim.DistriOptimizer$: caching training rdd ...
17/08/16 21:32:42 INFO optim.DistriOptimizer$: Cache thread models...
17/08/16 21:32:42 INFO optim.DistriOptimizer$: model thread pool size is 1
17/08/16 21:32:42 INFO optim.DistriOptimizer$: Cache thread models... done
17/08/16 21:32:42 INFO optim.DistriOptimizer$: config {
maxDropPercentage: 0.0
computeThresholdbatchSize: 100
warmupIterationNum: 200
isLayerwiseScaled: false
dropPercentage: 0.0
}
17/08/16 21:32:42 INFO optim.DistriOptimizer$: Shuffle data
17/08/16 21:32:42 INFO optim.DistriOptimizer$: Shuffle data complete. 
Takes 0.011933988s
17/08/16 21:32:43 INFO optim.DistriOptimizer$: [Epoch 1 0/32885][Iteration 1][Wall Clock 0.0s] Train 12 in 0.642820037seconds. Throughput is 18.667744 records/second. Loss is 8.302014\. Current learning rate is 0.1.
17/08/16 21:32:43 INFO optim.DistriOptimizer$: [Epoch 1 12/32885][Iteration 2][Wall Clock 0.642820037s] Train 12 in 0.211497603seconds. Throughput is 56.73823 records/second. Loss is 8.134232\. Current learning rate is 0.1.
17/08/16 21:32:44 INFO optim.DistriOptimizer$: [Epoch 1 24/32885][Iteration 3][Wall Clock 0.85431764s] Train 12 in 0.337422962seconds. Throughput is 35.56367 records/second. Loss is 7.924248\. Current learning rate is 0.1.
17/08/16 21:32:44 INFO optim.DistriOptimizer$: [Epoch 1 36/32885][Iteration 4][Wall Clock 1.191740602s] Train 12 in 0.189710956seconds. Throughput is 63.25412 records/second. Loss is 7.6132483\. Current learning rate is 0.1.
17/08/16 21:32:44 INFO optim.DistriOptimizer$: [Epoch 1 48/32885][Iteration 5][Wall Clock 1.381451558s] Train 12 in 0.180944071seconds. Throughput is 66.31883 records/second. Loss is 7.095647\. Current learning rate is 0.1.
17/08/16 21:32:44 INFO optim.DistriOptimizer$: [Epoch 1 60/32885][Iteration 6][Wall Clock 1.562395629s] Train 12 in 0.184258125seconds. Throughput is 65.12603 records/second. Loss is 6.3607793\. Current learning rate is 0.1..
.
.
17/08/16 21:50:00 INFO optim.DistriOptimizer$: [Epoch 2 32856/32885][Iteration 5480][Wall Clock 989.905619531s] Train 12 in 0.19739412seconds. Throughput is 60.792084 records/second. Loss is 1.5389917\. Current learning rate is 0.1.
17/08/16 21:50:00 INFO optim.DistriOptimizer$: [Epoch 2 32868/32885][Iteration 5481][Wall Clock 990.103013651s] Train 12 in 0.192780994seconds. Throughput is 62.2468 records/second. Loss is 1.3890615\. Current learning rate is 0.1.
17/08/16 21:50:01 INFO optim.DistriOptimizer$: [Epoch 2 32880/32885][Iteration 5482][Wall Clock 990.295794645s] Train 12 in 0.197826032seconds. Throughput is 60.65936 records/second. Loss is 1.5320908\. Current learning rate is 0.1.
17/08/16 21:50:01 INFO optim.DistriOptimizer$: [Epoch 2 32880/32885][Iteration 5482][Wall Clock 990.295794645s] Epoch finished. Wall clock time is 1038274.610521ms
17/08/16 21:50:01 INFO optim.DistriOptimizer$: [Wall Clock 1038.274610521s] Validate model...
17/08/16 21:50:52 INFO optim.DistriOptimizer$: Loss is (Loss: 1923.4493, count: 1388, Average Loss: 1.3857704)
[Wall Clock 1038.274610521s] Save model to /Users/aurobindosarkar/Downloads/bigdl-rnn/model//20170816_213242
```

接下来，我们使用保存的模型在测试数据集上运行，如下所示：

```scala
Aurobindos-MacBook-Pro-2:bigdl-rnn aurobindosarkar$ /Users/aurobindosarkar/Downloads/BigDL-master/scripts/bigdl.sh -- \
> /Users/aurobindosarkar/Downloads/spark-2.1.0-bin-hadoop2.7/bin/spark-submit \
> --master local[2] \
> --executor-cores 1 \
> --total-executor-cores 2 \
> --class com.intel.analytics.bigdl.models.rnn.Test \
> /Users/aurobindosarkar/Downloads/dist-spark-2.1.1-scala-2.11.8-mac-0.3.0-20170813.202825-21-dist/lib/bigdl-SPARK_2.1-0.3.0-SNAPSHOT-jar-with-dependencies.jar \
> -f /Users/aurobindosarkar/Downloads/bigdl-rnn/saveDict --model /Users/aurobindosarkar/Downloads/bigdl-rnn/model/20170816_213242/model.5483 --words 20 --batchSize 12
17/08/16 21:53:21 INFO utils.ThreadPool$: Set mkl threads to 1 on thread 1
17/08/16 21:53:22 INFO utils.Engine$: Auto detect executor number and executor cores number
17/08/16 21:53:22 INFO utils.Engine$: Executor number is 1 and executor cores number is 2
17/08/16 21:53:22 INFO utils.Engine$: Find existing spark context. Checking the spark conf...
17/08/16 21:53:24 WARN optim.Validator$: Validator(model, dataset) is deprecated. 
17/08/16 21:53:24 INFO optim.LocalValidator$: model thread pool size is 1
17/08/16 21:53:24 INFO optim.LocalValidator$: [Validation] 12/13 Throughput is 84.44181986758397 record / sec
17/08/16 21:53:24 INFO optim.LocalValidator$: [Validation] 13/13 Throughput is 115.81166197957567 record / sec
Loss is (Loss: 11.877369, count: 3, Average Loss: 3.959123)
```

# 引入自动编码器

自动编码器神经网络是一种无监督学习算法，它将目标值设置为等于输入值。因此，自动编码器试图学习一个恒等函数的近似。

学习一个恒等函数似乎并不是一项值得的练习；然而，通过对网络施加约束，比如限制隐藏单元的数量，我们可以发现关于数据的有趣结构。自动编码器的关键组件如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00290.jpeg)

原始输入，压缩表示以及自动编码器的输出层也在下图中进行了说明。更具体地说，该图表示了一个情况，例如，输入图像具有来自 10×10 图像（100 像素）的像素强度值，并且在第二层中有`50`个隐藏单元。在这里，网络被迫学习输入的“压缩”表示，其中它必须尝试使用`50`个隐藏单元“重建”100 像素的输入：

！[](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00291.jpeg)

有关自动编码器的更多细节，请参阅 G.E. Hinton 和 R.R. Salakhutdinov 的《使用神经网络降低数据的维度》，可在[`www.cs.toronto.edu/~hinton/science.pdf`](https://www.cs.toronto.edu/~hinton/science.pdf)上获得。

现在，我们展示了 BigDL 分发中针对 MNIST 数据集的自动编码器示例。

要训练自动编码器，您需要从[`yann.lecun.com/exdb/mnist/`](http://yann.lecun.com/exdb/mnist/)下载 MNIST 数据集。

您需要下载以下内容：

```scala
train-images-idx3-ubyte.gz
train-labels-idx1-ubyte.gz (the labels file is not actually used in this example)
```

然后，您需要解压它们以获得以下文件：

```scala
train-images-idx3-ubyte
train-labels-idx1-ubyte
```

对于我们的实现，ReLU 被用作激活函数，均方误差被用作损失函数。此示例中使用的模型和优化器代码的关键部分如下所示：

```scala
val rowN = 28
val colN = 28
val featureSize = rowN * colN
val classNum = 32
//The following model uses ReLU

val model = Sequential[Float]()
model.add(new Reshape(Array(featureSize)))
model.add(new Linear(featureSize, classNum))
model.add(new ReLU[Float]())
model.add(new Linear(classNum, featureSize))
model.add(new Sigmoid[Float]())

val optimMethod = new AdagradFloat

val optimizer = Optimizer(
   model = model,
   dataset = trainDataSet,
   criterion = new MSECriterion[Float]()
)
optimizer.setOptimMethod(optimMethod).setEndWhen(Trigger.maxEpoch(param.maxEpoch)).optimize()
```

以下是执行自动编码器示例的命令：

```scala
Aurobindos-MacBook-Pro-2:bigdl-rnn aurobindosarkar$ /Users/aurobindosarkar/Downloads/BigDL-master/scripts/bigdl.sh -- /Users/aurobindosarkar/Downloads/spark-2.1.0-bin-hadoop2.7/bin/spark-submit --master local[2] --class com.intel.analytics.bigdl.models.autoencoder.Train /Users/aurobindosarkar/Downloads/BigDL-master/spark/dist/target/bigdl-0.2.0-SNAPSHOT-spark-2.0.0-scala-2.11.8-mac-dist/lib/bigdl-0.2.0-SNAPSHOT-jar-with-dependencies.jar -b 150 -f /Users/aurobindosarkar/Downloads/mnist --maxEpoch 2 --checkpoint /Users/aurobindosarkar/Downloads/mnist
```

示例生成的输出如下：

```scala
17/08/16 22:52:16 INFO utils.ThreadPool$: Set mkl threads to 1 on thread 1
17/08/16 22:52:17 INFO utils.Engine$: Auto detect executor number and executor cores number
17/08/16 22:52:17 INFO utils.Engine$: Executor number is 1 and executor cores number is 2
17/08/16 22:52:17 INFO utils.Engine$: Find existing spark context. Checking the spark conf...
17/08/16 22:52:18 INFO optim.DistriOptimizer$: caching training rdd ...
17/08/16 22:52:19 INFO optim.DistriOptimizer$: Cache thread models...
17/08/16 22:52:19 INFO optim.DistriOptimizer$: model thread pool size is 1
17/08/16 22:52:19 INFO optim.DistriOptimizer$: Cache thread models... done
17/08/16 22:52:19 INFO optim.DistriOptimizer$: config {
weightDecay: 5.0E-4
learningRate: 0.01
maxDropPercentage: 0.0
computeThresholdbatchSize: 100
momentum: 0.9
warmupIterationNum: 200
dampening: 0.0
dropPercentage: 0.0
}
17/08/16 22:52:19 INFO optim.DistriOptimizer$: Shuffle data
17/08/16 22:52:19 INFO optim.DistriOptimizer$: Shuffle data complete. Takes 0.013076416s
17/08/16 22:52:19 INFO optim.DistriOptimizer$: [Epoch 1 0/60000][Iteration 1][Wall Clock 0.0s] Train 150 in 0.217233789seconds. Throughput is 690.5003 records/second. Loss is 1.2499084.
17/08/16 22:52:20 INFO optim.DistriOptimizer$: [Epoch 1 150/60000][Iteration 2][Wall Clock 0.217233789s] Train 150 in 0.210093679seconds. Throughput is 713.9672 records/second. Loss is 1.1829382.
17/08/16 22:52:20 INFO optim.DistriOptimizer$: [Epoch 1 300/60000][Iteration 3][Wall Clock 0.427327468s] Train 150 in 0.05808109seconds. Throughput is 2582.5962 records/second. Loss is 1.089432.
17/08/16 22:52:20 INFO optim.DistriOptimizer$: [Epoch 1 450/60000][Iteration 4][Wall Clock 0.485408558s] Train 150 in 0.053720011seconds. Throughput is 2792.2556 records/second. Loss is 0.96986365.
17/08/16 22:52:20 INFO optim.DistriOptimizer$: [Epoch 1 600/60000][Iteration 5][Wall Clock 0.539128569s] Train 150 in 0.052071024seconds. Throughput is 2880.681 records/second. Loss is 0.9202304.
.
.
.
17/08/16 22:52:45 INFO optim.DistriOptimizer$: [Epoch 2 59400/60000][Iteration 797][Wall Clock 26.151645532s] Train 150 in 0.026734804seconds. Throughput is 5610.6636 records/second. Loss is 0.5562006.
17/08/16 22:52:45 INFO optim.DistriOptimizer$: [Epoch 2 59550/60000][Iteration 798][Wall Clock 26.178380336s] Train 150 in 0.031001227seconds. Throughput is 4838.518 records/second. Loss is 0.55211174.
17/08/16 22:52:45 INFO optim.DistriOptimizer$: [Epoch 2 59700/60000][Iteration 799][Wall Clock 26.209381563s] Train 150 in 0.027455972seconds. Throughput is 5463.292 records/second. Loss is 0.5566905.
17/08/16 22:52:45 INFO optim.DistriOptimizer$: [Epoch 2 59850/60000][Iteration 800][Wall Clock 26.236837535s] Train 150 in 0.037863017seconds. Throughput is 3961.6494 records/second. Loss is 0.55880654.
17/08/16 22:52:45 INFO optim.DistriOptimizer$: [Epoch 2 59850/60000][Iteration 800][Wall Clock 26.236837535s] Epoch finished. Wall clock time is 26374.372173ms
[Wall Clock 26.374372173s] Save model to /Users/aurobindosarkar/Downloads/mnist/20170816_225219
```

# 总结

在本章中，我们介绍了 Spark 中的深度学习。我们讨论了各种类型的深度神经网络及其应用。我们还探索了 BigDL 分发中提供的一些代码示例。由于这是 Spark 中一个快速发展的领域，目前，我们期望这些库能够提供更多使用 Spark SQL 和 DataFrame/Dataset API 的功能。此外，我们还期望它们在未来几个月内变得更加成熟和稳定。

在下一章中，我们将把重点转向调整 Spark SQL 应用程序。我们将涵盖关于使用编码器进行序列化/反序列化以及与查询执行相关的逻辑和物理计划的关键基础知识，然后介绍 Spark 2.2 中发布的**基于成本的优化**（**CBO**）功能的详细信息。此外，我们还将介绍开发人员可以使用的一些技巧和窍门来提高其应用程序的性能。


# 第十一章：调优 Spark SQL 组件以提高性能

在本章中，我们将重点关注基于 Spark SQL 的组件的性能调优方面。Spark SQL Catalyst 优化器是许多 Spark 应用程序（包括**ML Pipelines**、**Structured Streaming**和**GraphFrames**）高效执行的核心。我们将首先解释与查询执行相关的序列化/反序列化使用编码器的逻辑和物理计划的关键基础方面，然后介绍 Spark 2.2 中发布的**基于成本的优化**（**CBO**）功能的详细信息。此外，我们将在整个章节中提供一些开发人员可以使用的技巧和窍门，以改善其应用程序的性能。

更具体地说，在本章中，您将学习以下内容：

+   理解性能调优的基本概念

+   理解驱动性能的 Spark 内部原理

+   理解基于成本的优化

+   理解启用整体代码生成的性能影响

# 介绍 Spark SQL 中的性能调优

Spark 计算通常是内存中的，并且可能受到集群资源的限制：CPU、网络带宽或内存。此外，即使数据适合内存，网络带宽可能也是一个挑战。

调优 Spark 应用程序是减少网络传输的数据数量和大小和/或减少计算的整体内存占用的必要步骤。

在本章中，我们将把注意力集中在 Spark SQL Catalyst 上，因为它对从整套应用程序组件中获益至关重要。

Spark SQL 是最近对 Spark 进行的重大增强的核心，包括**ML Pipelines**、**Structured Streaming**和**GraphFrames**。下图说明了**Spark SQL**在**Spark Core**和构建在其之上的高级 API 之间发挥的关键作用：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00292.jpeg)

在接下来的几节中，我们将介绍调优 Spark SQL 应用程序所需的基本理解。我们将从**DataFrame/Dataset** API 开始。

# 理解 DataFrame/Dataset API

**数据集**是一种强类型的领域特定对象的集合，可以使用函数或关系操作并行转换。每个数据集还有一个称为**DataFrame**的视图，它不是强类型的，本质上是一组行对象的数据集。

Spark SQL 将结构化视图应用于来自不同数据格式的不同源系统的数据。结构化 API（如 DataFrame/Dataset API）允许开发人员使用高级 API 编写程序。这些 API 允许他们专注于数据处理所需的“是什么”，而不是“如何”。

尽管应用结构可能会限制可以表达的内容，但实际上，结构化 API 可以容纳应用开发中所需的绝大多数计算。此外，正是这些由结构化 API 所施加的限制，提供了一些主要的优化机会。

在下一节中，我们将探讨编码器及其在高效序列化和反序列化中的作用。

# 优化数据序列化

编码器是 Spark SQL 2.0 中**序列化**和**反序列化**（**SerDe**）框架中的基本概念。Spark SQL 使用 SerDe 框架进行 I/O，从而实现更高的时间和空间效率。数据集使用专门的编码器来序列化对象，以便在处理或通过网络传输时使用，而不是使用 Java 序列化或 Kryo。

编码器需要有效地支持领域对象。这些编码器将领域对象类型`T`映射到 Spark 的内部类型系统，`Encoder [T]`用于将类型`T`的对象或原语转换为 Spark SQL 的内部二进制行格式表示（使用 Catalyst 表达式和代码生成）。结果的二进制结构通常具有更低的内存占用，并且针对数据处理的效率进行了优化（例如，以列格式）。

高效的序列化是实现分布式应用程序良好性能的关键。序列化对象速度慢的格式将显著影响性能。通常，这将是您调优以优化 Spark 应用程序的第一步。

编码器经过高度优化，并使用运行时代码生成来构建用于序列化和反序列化的自定义字节码。此外，它们使用一种格式，允许 Spark 执行许多操作，如过滤和排序，而无需将其反序列化为对象。由于编码器知道记录的模式，它们可以提供显著更快的序列化和反序列化（与默认的 Java 或 Kryo 序列化器相比）。

除了速度之外，编码器输出的序列化大小也可以显著减小，从而降低网络传输的成本。此外，序列化数据已经是钨丝二进制格式，这意味着许多操作可以就地执行，而无需实例化对象。Spark 内置支持自动生成原始类型（如 String 和 Integer）和案例类的编码器。

在这里，我们展示了从第一章*，*Getting Started with Spark SQL**中为 Bid 记录创建自定义编码器的示例。请注意，通过导入`spark.implicits._`，大多数常见类型的编码器都会自动提供，并且默认的编码器已经在 Spark shell 中导入。

首先，让我们导入本章代码所需的所有类：

```scala
scala> import org.apache.spark.sql._ 
scala> import org.apache.spark.sql.types._ 
scala> import org.apache.spark.sql.functions._ 
scala> import org.apache.spark.sql.streaming._ 
scala> import spark.implicits._ 
scala> import spark.sessionState.conf 
scala> import org.apache.spark.sql.internal.SQLConf.SHUFFLE_PARTITIONS 
scala> import org.apache.spark.sql.Encoders 
scala> import org.apache.spark.sql.catalyst.encoders.ExpressionEncoder 
```

接下来，我们将为输入数据集中`Bid`记录的领域对象定义一个`case`类：

```scala
scala> case class Bid(bidid: String, timestamp: String, ipinyouid: String, useragent: String, IP: String, region: Integer, cityID: Integer, adexchange: String, domain: String, turl: String, urlid: String, slotid: String, slotwidth: String, slotheight: String, slotvisibility: String, slotformat: String, slotprice: String, creative: String, bidprice: String) 
```

接下来，我们将使用上一步的`case`类创建一个`Encoder`对象，如下所示：

```scala
scala> val bidEncoder = Encoders.product[Bid] 
```

可以使用 schema 属性访问模式，如下所示：

```scala
scala> bidEncoder.schema
```

我们使用了`ExpressionEncoder`的实现（这是 Spark SQL 2 中唯一可用的编码器特性的实现）：

```scala
scala> val bidExprEncoder = bidEncoder.asInstanceOf[ExpressionEncoder[Bid]] 
```

以下是编码器的序列化器和反序列化器部分：

```scala
scala> bidExprEncoder.serializer 

scala> bidExprEncoder.namedExpressions 
```

接下来，我们将演示如何读取我们的输入数据集：

```scala
scala> val bidsDF = spark.read.format("csv").schema(bidEncoder.schema).option("sep", "\t").option("header", false).load("file:///Users/aurobindosarkar/Downloads/make-ipinyou-data-master/original-data/ipinyou.contest.dataset/bidfiles") 
```

然后，我们将从我们新创建的 DataFrame 中显示一个`Bid`记录，如下所示：

```scala
scala> bidsDF.take(1).foreach(println) 

[e3d962536ef3ac7096b31fdd1c1c24b0,20130311172101557,37a6259cc0c1dae299a7866489dff0bd,Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; QQDownload 734; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; eSobiSubscriber 2.0.4.16; MAAR),gzip(gfe),gzip(gfe),219.232.120.*,1,1,2,DF9blS9bQqsIFYB4uA5R,b6c5272dfc63032f659be9b786c5f8da,null,2006366309,728,90,1,0,5,5aca4c5f29e59e425c7ea657fdaac91e,300] 
```

为了方便起见，我们可以使用上一步的记录创建一个新记录，如在`Dataset[Bid]`中：

```scala
scala> val bid = Bid("e3d962536ef3ac7096b31fdd1c1c24b0","20130311172101557","37a6259cc0c1dae299a7866489dff0bd","Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; QQDownload 734; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; eSobiSubscriber 2.0.4.16; MAAR),gzip(gfe),gzip(gfe)","219.232.120.*",1,1,"2","","DF9blS9bQqsIFYB4uA5R,b6c5272dfc63032f659be9b786c5f8da",null,"2006366309","728","90","1","0","5","5aca4c5f29e59e425c7ea657fdaac91e","300") 
```

然后，我们将记录序列化为内部表示，如下所示：

```scala
scala> val row = bidExprEncoder.toRow(bid)  
```

Spark 在 I/O 中内部使用`InternalRows`。因此，我们将字节反序列化为 JVM 对象，即`Scala`对象，如下所示。但是，我们需要导入`Dsl`表达式，并明确指定`DslSymbol`，因为在 Spark shell 中存在竞争的隐式：

```scala
scala> import org.apache.spark.sql.catalyst.dsl.expressions._ 

scala> val attrs = Seq(DslSymbol('bidid).string, DslSymbol('timestamp).string, DslSymbol('ipinyouid).string, DslSymbol('useragent).string, DslSymbol('IP).string, DslSymbol('region).int, DslSymbol('cityID).int, DslSymbol('adexchange).string, DslSymbol('domain).string, DslSymbol('turl).string, DslSymbol('urlid).string, DslSymbol('slotid).string, DslSymbol('slotwidth).string, DslSymbol('slotheight).string, DslSymbol('slotvisibility).string, DslSymbol('slotformat).string, DslSymbol('slotprice).string, DslSymbol('creative).string, DslSymbol('bidprice).string) 
```

在这里，我们检索序列化的`Bid`对象：

```scala
scala> val getBackBid = bidExprEncoder.resolveAndBind(attrs).fromRow(row) 
```

我们可以验证两个对象是否相同，如下所示：

```scala
scala> bid == getBackBid 
res30: Boolean = true 
```

在下一节中，我们将把重点转移到 Spark SQL 的 Catalyst 优化。

# 理解 Catalyst 优化

我们在第一章* **使用 Spark SQL 入门**中简要探讨了 Catalyst 优化器。基本上，Catalyst 具有用户程序的内部表示，称为**查询计划**。一组转换在初始查询计划上执行，以产生优化的查询计划。最后，通过 Spark SQL 的代码生成机制，优化的查询计划转换为 RDD 的 DAG，准备执行。在其核心，Catalyst 优化器定义了用户程序的抽象为树，以及从一棵树到另一棵树的转换。

为了利用优化机会，我们需要一个优化器，它可以自动找到执行数据操作的最有效计划（在用户程序中指定）。在本章的上下文中，Spark SQL 的 Catalyst 优化器充当用户高级编程构造和低级执行计划之间的接口。

# 理解数据集/DataFrame API

数据集或 DataFrame 通常是通过从数据源读取或执行查询而创建的。在内部，查询由运算符树表示，例如逻辑和物理树。数据集表示描述生成数据所需的逻辑计划。当调用动作时，Spark 的查询优化器会优化逻辑计划，并生成用于并行和分布式执行的物理计划。

查询计划用于描述数据操作，例如聚合、连接或过滤，以使用不同类型的输入数据集生成新的数据集。

第一种查询计划是逻辑计划，它描述了在数据集上所需的计算，而不具体定义实际计算的机制。它给我们提供了用户程序的抽象，并允许我们自由地转换查询计划，而不用担心执行细节。

查询计划是 Catalyst 的一部分，它对关系运算符树进行建模，即结构化查询。查询计划具有`statePrefix`，在显示计划时使用`!`表示无效计划，使用`'`表示未解析计划。如果存在缺少的输入属性并且子节点非空，则查询计划无效；如果列名尚未经过验证并且列类型尚未在目录中查找，则查询计划未解析。

作为优化的一部分，Catalyst 优化器应用各种规则来在阶段中操作这些树。我们可以使用 explain 函数来探索逻辑计划以及优化后的物理计划。

现在，我们将以三个数据集的简单示例，并使用`explain()`函数显示它们的优化计划：

```scala
scala> val t1 = spark.range(7) 
scala> val t2 = spark.range(13) 
scala> val t3 = spark.range(19) 

scala> t1.explain() 
== Physical Plan == 
*Range (0, 7, step=1, splits=8) 

scala> t1.explain(extended=true) 
== Parsed Logical Plan == 
Range (0, 7, step=1, splits=Some(8)) 

== Analyzed Logical Plan == 
id: bigint 
Range (0, 7, step=1, splits=Some(8)) 

== Optimized Logical Plan == 
Range (0, 7, step=1, splits=Some(8)) 

== Physical Plan == 
*Range (0, 7, step=1, splits=8) 

scala> t1.filter("id != 0").filter("id != 2").explain(true) 
== Parsed Logical Plan == 
'Filter NOT ('id = 2) 
+- Filter NOT (id#0L = cast(0 as bigint)) 
   +- Range (0, 7, step=1, splits=Some(8)) 

== Analyzed Logical Plan == 
id: bigint 
Filter NOT (id#0L = cast(2 as bigint)) 
+- Filter NOT (id#0L = cast(0 as bigint)) 
   +- Range (0, 7, step=1, splits=Some(8)) 

== Optimized Logical Plan == 
Filter (NOT (id#0L = 0) && NOT (id#0L = 2)) 
+- Range (0, 7, step=1, splits=Some(8)) 

== Physical Plan == 
*Filter (NOT (id#0L = 0) && NOT (id#0L = 2)) 
+- *Range (0, 7, step=1, splits=8) 
```

分析逻辑计划是在初始解析计划上应用分析器的检查规则的结果。分析器是 Spark SQL 中的逻辑查询计划分析器，它在语义上验证和转换未解析的逻辑计划为分析的逻辑计划（使用逻辑评估规则）：

```scala
scala> spark.sessionState.analyzer 
res30: org.apache.spark.sql.catalyst.analysis.Analyzer = org.apache.spark.sql.hive.HiveSessionStateBuilder$$anon$1@21358f6c 
```

启用会话特定记录器的`TRACE`或`DEBUG`日志级别，以查看分析器内部发生的情况。例如，将以下行添加到`conf/log4j`属性中：

```scala
log4j.logger.org.apache.spark.sql.hive.HiveSessionStateBuilder$$anon$1=DEBUG scala> val t1 = spark.range(7) 
17/07/13 10:25:38 DEBUG HiveSessionStateBuilder$$anon$1:  
=== Result of Batch Resolution === 
!'DeserializeToObject unresolveddeserializer(staticinvoke(class java.lang.Long, ObjectType(class java.lang.Long), valueOf, upcast(getcolumnbyordinal(0, LongType), LongType, - root class: "java.lang.Long"), true)), obj#2: java.lang.Long   DeserializeToObject staticinvoke(class java.lang.Long, ObjectType(class java.lang.Long), valueOf, cast(id#0L as bigint), true), obj#2: java.lang.Long 
 +- LocalRelation <empty>, [id#0L]                                                                                                                                                                                                            +- LocalRelation <empty>, [id#0L] 

t1: org.apache.spark.sql.Dataset[Long] = [id: bigint] 
```

分析器是一个规则执行器，定义了解析和修改逻辑计划评估规则。它使用会话目录解析未解析的关系和函数。固定点的优化规则和批处理中的一次性规则（一次策略）也在这里定义。

在逻辑计划优化阶段，执行以下一系列操作：

+   规则将逻辑计划转换为语义上等效的计划，以获得更好的性能

+   启发式规则用于推送下推断列，删除未引用的列等

+   较早的规则使后续规则的应用成为可能；例如，合并查询块使全局连接重新排序

`SparkPlan`是用于构建物理查询计划的 Catalyst 查询计划的物理运算符。在执行时，物理运算符会产生行的 RDD。可用的逻辑计划优化可以扩展，并且可以注册额外的规则作为实验方法。

```scala
scala> t1.filter("id != 0").filter("id != 2") 
17/07/13 10:43:17 DEBUG HiveSessionStateBuilder$$anon$1:  
=== Result of Batch Resolution === 
!'Filter NOT ('id = 0)                      
Filter NOT (id#0L = cast(0 as bigint)) 
 +- Range (0, 7, step=1, splits=Some(8))    
+- Range (0, 7, step=1, splits=Some(8)) 
... 

17/07/13 10:43:17 DEBUG HiveSessionStateBuilder$$anon$1:  
=== Result of Batch Resolution === 
!'Filter NOT ('id = 2)                         
Filter NOT (id#0L = cast(2 as bigint)) 
 +- Filter NOT (id#0L = cast(0 as bigint))     
   +- Filter NOT (id#0L = cast(0 as bigint)) 
    +- Range (0, 7, step=1, splits=Some(8))       
   +- Range (0, 7, step=1, splits=Some(8)) 
```

# 理解 Catalyst 转换

在这一部分，我们将详细探讨 Catalyst 转换。在 Spark 中，转换是纯函数，也就是说，在转换过程中不会改变树的结构（而是生成一个新的树）。在 Catalyst 中，有两种类型的转换：

+   在第一种类型中，转换不会改变树的类型。使用这种转换，我们可以将一个表达式转换为另一个表达式，一个逻辑计划转换为另一个逻辑计划，或者一个物理计划转换为另一个物理计划。

+   第二种类型的转换将一个树从一种类型转换为另一种类型。例如，这种类型的转换用于将逻辑计划转换为物理计划。

一个函数（与给定树相关联）用于实现单个规则。例如，在表达式中，这可以用于常量折叠优化。转换被定义为部分函数。（回想一下，部分函数是为其可能的参数子集定义的函数。）通常，case 语句会判断规则是否被触发；例如，谓词过滤器被推到`JOIN`节点下面，因为它减少了`JOIN`的输入大小；这被称为**谓词下推**。类似地，投影仅针对查询中使用的所需列执行。这样，我们可以避免读取不必要的数据。

通常，我们需要结合不同类型的转换规则。规则执行器用于组合多个规则。它通过应用许多规则（批处理中定义的）将一个树转换为相同类型的另一个树。

有两种方法用于应用规则：

+   在第一种方法中，我们重复应用规则，直到树不再发生变化（称为固定点）

+   在第二种类型中，我们一次批处理应用所有规则（一次策略）

接下来，我们将看看第二种类型的转换，即从一种树转换为另一种树：更具体地说，Spark 如何将逻辑计划转换为物理计划。通过应用一组策略，可以将逻辑计划转换为物理计划。主要是采用模式匹配的方法进行这些转换。例如，一个策略将逻辑投影节点转换为物理投影节点，逻辑过滤节点转换为物理过滤节点，依此类推。策略可能无法转换所有内容，因此在代码的特定点内置了触发其他策略的机制（例如`planLater`方法）。

优化过程包括三个步骤：

1.  分析（规则执行器）：这将一个未解析的逻辑计划转换为已解析的逻辑计划。未解析到已解析的状态使用目录来查找数据集和列的来源以及列的类型。

1.  逻辑优化（规则执行器）：这将一个已解析的逻辑计划转换为优化的逻辑计划。

1.  物理规划（策略+规则执行器）：包括两个阶段：

+   将优化的逻辑计划转换为物理计划。

+   规则执行器用于调整物理计划，使其准备好执行。这包括我们如何洗牌数据以及如何对其进行分区。

如下例所示，表达式表示一个新值，并且它是基于其输入值计算的，例如，将一个常量添加到列中的每个元素，例如`1 + t1.normal`。类似地，属性是数据集中的一列（例如，`t1.id`）或者由特定数据操作生成的列，例如 v。

输出中列出了由此逻辑计划生成的属性列表，例如 id 和 v。逻辑计划还具有关于此计划生成的行的一组不变量，例如，`t2.id > 5000000`。最后，我们有统计信息，行/字节中计划的大小，每列统计信息，例如最小值、最大值和不同值的数量，以及空值的数量。

第二种查询计划是物理计划，它描述了对具有特定定义的数据集进行计算所需的计算。物理计划实际上是可执行的：

```scala
scala> val t0 = spark.range(0, 10000000) 
scala> val df1 = t0.withColumn("uniform", rand(seed=10)) 
scala> val df2 = t0.withColumn("normal", randn(seed=27)) 
scala> df1.createOrReplaceTempView("t1") 
scala> df2.createOrReplaceTempView("t2") 

scala> spark.sql("SELECT sum(v) FROM (SELECT t1.id, 1 + t1.normal AS v FROM t1 JOIN t2 WHERE t1.id = t2.id AND t2.id > 5000000) tmp").explain(true) 
```

前述查询的所有计划都显示在以下代码块中。请注意我们在解析逻辑计划中的注释，反映了原始 SQL 查询的部分内容：

```scala
== Parsed Logical Plan == 
'Project [unresolvedalias('sum('v), None)] ------------------> SELECT sum(v) 
+- 'SubqueryAlias tmp 
   +- 'Project ['t1.id, (1 + 't1.normal) AS v#79] ----------->       SELECT t1.id,  
                                                               1 + t1.normal as v 
      +- 'Filter (('t1.id = 't2.id) && ('t2.id > 5000000))---> WHERE t1.id = t2.id,  
                                                                    t2.id > 5000000 
         +- 'Join Inner -------------------------------------> t1 JOIN t2 
            :- 'UnresolvedRelation `t1` 
            +- 'UnresolvedRelation `t2` 

== Analyzed Logical Plan == 
sum(v): double 
Aggregate [sum(v#79) AS sum(v)#86] 
+- SubqueryAlias tmp 
   +- Project [id#10L, (cast(1 as double) + normal#13) AS v#79] 
      +- Filter ((id#10L = id#51L) && (id#51L > cast(5000000 as bigint))) 
         +- Join Inner 
            :- SubqueryAlias t1 
            :  +- Project [id#10L, randn(27) AS normal#13] 
            :     +- Range (0, 10000000, step=1, splits=Some(8)) 
            +- SubqueryAlias t2 
               +- Project [id#51L, rand(10) AS uniform#54] 
                  +- Range (0, 10000000, step=1, splits=Some(8)) 

== Optimized Logical Plan == 
Aggregate [sum(v#79) AS sum(v)#86] 
+- Project [(1.0 + normal#13) AS v#79] 
   +- Join Inner, (id#10L = id#51L) 
      :- Filter (id#10L > 5000000) 
      :  +- Project [id#10L, randn(27) AS normal#13] 
      :     +- Range (0, 10000000, step=1, splits=Some(8)) 
      +- Filter (id#51L > 5000000) 
         +- Range (0, 10000000, step=1, splits=Some(8)) 

== Physical Plan == 
*HashAggregate(keys=[], functions=[sum(v#79)], output=[sum(v)#86]) 
+- Exchange SinglePartition 
   +- *HashAggregate(keys=[], functions=[partial_sum(v#79)], output=[sum#88]) 
      +- *Project [(1.0 + normal#13) AS v#79] 
         +- *SortMergeJoin [id#10L], [id#51L], Inner 
            :- *Sort [id#10L ASC NULLS FIRST], false, 0 
            :  +- Exchange hashpartitioning(id#10L, 200) 
            :     +- *Filter (id#10L > 5000000) 
            :        +- *Project [id#10L, randn(27) AS normal#13] 
            :           +- *Range (0, 10000000, step=1, splits=8) 
            +- *Sort [id#51L ASC NULLS FIRST], false, 0 
               +- Exchange hashpartitioning(id#51L, 200) 
                  +- *Filter (id#51L > 5000000) 
                     +- *Range (0, 10000000, step=1, splits=8) 
```

您可以使用 Catalyst 的 API 自定义 Spark 以推出自己的计划规则。

有关 Spark SQL Catalyst 优化器的更多详细信息，请参阅[`spark-summit.org/2017/events/a-deep-dive-into-spark-sqls-catalyst-optimizer/`](https://spark-summit.org/2017/events/a-deep-dive-into-spark-sqls-catalyst-optimizer/)。

# 可视化 Spark 应用程序执行

在本节中，我们将介绍 SparkUI 界面的关键细节，这对于调整任务至关重要。监视 Spark 应用程序有几种方法，例如使用 Web UI、指标和外部仪表。显示的信息包括调度器阶段和任务列表、RDD 大小和内存使用摘要、环境信息以及有关正在运行的执行器的信息。

可以通过简单地在 Web 浏览器中打开`http://<driver-node>:4040`（`http://localhost:4040`）来访问此界面。在同一主机上运行的其他`SparkContexts`绑定到连续的端口：4041、4042 等。

有关 Spark 监控和仪表的更详细覆盖范围，请参阅[`spark.apache.org/docs/latest/monitoring.html`](https://spark.apache.org/docs/latest/monitoring.html)。

我们将使用两个示例可视化地探索 Spark SQL 执行。首先，我们创建两组数据集。第一组（`t1`、`t2`和`t3`）与第二组（`t4`、`t5`和`t6`）的`Dataset[Long]`之间的区别在于大小：

```scala
scala> val t1 = spark.range(7) 
scala> val t2 = spark.range(13) 
scala> val t3 = spark.range(19) 
scala> val t4 = spark.range(1e8.toLong) 
scala> val t5 = spark.range(1e8.toLong) 
scala> val t6 = spark.range(1e3.toLong)  
```

我们将执行以下`JOIN`查询，针对两组数据集，以可视化 SparkUI 仪表板中的 Spark 作业信息：

```scala
scala> val query = t1.join(t2).where(t1("id") === t2("id")).join(t3).where(t3("id") === t1("id")).explain() 
== Physical Plan == 
*BroadcastHashJoin [id#6L], [id#12L], Inner, BuildRight 
:- *BroadcastHashJoin [id#6L], [id#9L], Inner, BuildRight 
:  :- *Range (0, 7, step=1, splits=8) 
:  +- BroadcastExchange HashedRelationBroadcastMode(List(input[0, bigint, false])) 
:     +- *Range (0, 13, step=1, splits=8) 
+- BroadcastExchange HashedRelationBroadcastMode(List(input[0, bigint, false])) 
   +- *Range (0, 19, step=1, splits=8) 
query: Unit = () 

scala> val query = t1.join(t2).where(t1("id") === t2("id")).join(t3).where(t3("id") === t1("id")).count() 
query: Long = 7 
```

以下屏幕截图显示了事件时间轴：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00293.jpeg)

生成的**DAG 可视化**显示了阶段和洗牌（**Exchange**）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00294.jpeg)

作业摘要，包括执行持续时间、成功任务和总任务数等，显示在此处：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00295.jpeg)

单击 SQL 选项卡以查看详细的执行流程，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00296.jpeg)

接下来，我们将在更大的数据集上运行相同的查询。请注意，由于输入数据集的增加，第一个示例中的`BroadcastHashJoin`现在变为`SortMergeJoin`：

```scala
scala> val query = t4.join(t5).where(t4("id") === t5("id")).join(t6).where(t4("id") === t6("id")).explain() 
== Physical Plan == 
*BroadcastHashJoin [id#72L], [id#78L], Inner, BuildRight 
:- *SortMergeJoin [id#72L], [id#75L], Inner 
:  :- *Sort [id#72L ASC NULLS FIRST], false, 0 
:  :  +- Exchange hashpartitioning(id#72L, 200) 
:  :     +- *Range (0, 100000000, step=1, splits=8) 
:  +- *Sort [id#75L ASC NULLS FIRST], false, 0 
:     +- ReusedExchange [id#75L], Exchange hashpartitioning(id#72L, 200) 
+- BroadcastExchange HashedRelationBroadcastMode(List(input[0, bigint, false])) 
   +- *Range (0, 1000, step=1, splits=8) 
query: Unit = () 
```

执行 DAG 如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00297.jpeg)

作业执行摘要如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00298.jpeg)

SQL 执行详细信息如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00299.jpeg)

除了在 UI 中显示，指标也可用作 JSON 数据。这为开发人员提供了一个很好的方式来为 Spark 创建新的可视化和监控工具。REST 端点挂载在`/api/v1`；例如，它们通常可以在`http://localhost:4040/api/v1`上访问。这些端点已经强烈版本化，以便更容易地使用它们开发应用程序。

# 探索 Spark 应用程序执行指标

Spark 具有基于`Dropwizard Metrics`库的可配置度量系统。这允许用户将 Spark 指标报告给各种接收器，包括`HTTP`，`JMX`和`CSV`文件。与 Spark 组件对应的 Spark 指标包括 Spark 独立主进程，主进程中报告各种应用程序的应用程序，Spark 独立工作进程，Spark 执行程序，Spark 驱动程序进程和 Spark 洗牌服务。

下一系列的屏幕截图包含详细信息，包括摘要指标和针对较大数据集的 JOIN 查询的一个阶段的执行程序的聚合指标：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00300.jpeg)

已完成任务的摘要指标如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00301.jpeg)

按执行程序聚合的指标如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00302.jpeg)

# 使用外部工具进行性能调优

通常使用外部监视工具来分析大型`Spark 集群`中 Spark 作业的性能。例如，Ganglia 可以提供有关整体集群利用率和资源瓶颈的见解。此外，`OS profiling`工具和`JVM`实用程序可以提供有关单个节点的细粒度分析和用于处理`JVM`内部的工具。

有关可视化 Spark 应用程序执行的更多详细信息，请参阅[`databricks.com/blog/2015/06/22/understanding-your-spark-application-through-visualization.html`](https://databricks.com/blog/2015/06/22/understanding-your-spark-application-through-visualization.html)。

在下一节中，我们将把焦点转移到 Spark 2.2 中发布的新成本优化器。

# Apache Spark 2.2 中的成本优化器

在 Spark 中，优化器的目标是最小化端到端查询响应时间。它基于两个关键思想：

尽早剪枝不必要的数据，例如，过滤器下推和列修剪。

最小化每个操作员的成本，例如广播与洗牌和最佳连接顺序。

直到 Spark 2.1，Catalyst 本质上是一个基于规则的优化器。大多数 Spark SQL 优化器规则都是启发式规则：`PushDownPredicate`，`ColumnPruning`，`ConstantFolding`等。它们在估计`JOIN`关系大小时不考虑每个操作员的成本或选择性。因此，`JOIN`顺序大多由其在`SQL 查询`中的位置决定，并且基于启发式规则决定物理连接实现。这可能导致生成次优计划。然而，如果基数事先已知，就可以获得更有效的查询。CBO 优化器的目标正是自动执行这一点。

华为最初在 Spark SQL 中实施了 CBO；在他们开源了他们的工作之后，包括 Databricks 在内的许多其他贡献者致力于完成其第一个版本。与 Spark SQL 相关的 CBO 更改，特别是进入 Spark SQL 数据结构和工作流的主要入口点，已经以一种非侵入性的方式进行了设计和实施。

配置参数`spark.sql.cbo`可用于启用/禁用此功能。目前（在 Spark 2.2 中），默认值为 false。

有关更多详细信息，请参阅华为的设计文档，网址为[`issues.apache.org/jira/browse/SPARK-16026`](https://issues.apache.org/jira/browse/SPARK-16026)。

Spark SQL 的 Catalyst 优化器实施了许多基于规则的优化技术，例如谓词下推以减少连接操作执行之前的符合记录数量，以及项目修剪以减少进一步处理之前参与的列数量。然而，如果没有关于数据分布的详细列统计信息，就很难准确估计过滤因子和基数，从而难以准确估计数据库操作员的输出大小。使用不准确和/或误导性的统计信息，优化器最终可能会选择次优的查询执行计划。

为了改进查询执行计划的质量，Spark SQL 优化器已经增强了详细的统计信息。更好地估计输出记录的数量和输出大小（对于每个数据库运算符）有助于优化器选择更好的查询计划。CBO 实现收集、推断和传播`源/中间`数据的`表/列`统计信息。查询树被注释了这些统计信息。此外，它还计算每个运算符的成本，例如输出行数、输出大小等。基于这些成本计算，它选择最优的查询执行计划。

# 了解 CBO 统计收集

`Statistics`类是保存统计信息的关键数据结构。当我们执行统计收集 SQL 语句以将信息保存到系统目录中时，会引用这个数据结构。当我们从系统目录中获取统计信息以优化查询计划时，也会引用这个数据结构。

CBO 依赖于详细的统计信息来优化查询执行计划。以下 SQL 语句可用于收集`表级`统计信息，例如行数、文件数（或 HDFS 数据块数）和表大小（以字节为单位）。它收集`表级`统计信息并将其保存在`元数据存储`中。在 2.2 版本之前，我们只有表大小，而没有行数：

```scala
ANALYZE TABLE table_name COMPUTE STATISTICS 
```

类似地，以下 SQL 语句可用于收集指定列的列级统计信息。收集的信息包括最大列值、最小列值、不同值的数量、空值的数量等。它收集列级统计信息并将其保存在`元数据存储`中。通常，它仅针对`WHERE`和`GROUP BY`子句中的列执行：

```scala
ANALYZE TABLE table_name COMPUTE STATISTICS FOR COLUMNS column-name1, column-name2, .... 
```

给定的 SQL 语句以扩展格式显示表的元数据，包括表级统计信息：

```scala
DESCRIBE EXTENDED table_name 
```

`customers`表是在本章的后面部分创建的：

```scala
scala> sql("DESCRIBE EXTENDED customers").collect.foreach(println) 
[# col_name,data_type,comment] 
[id,bigint,null] 
[name,string,null] 
[,,] 
[# Detailed Table Information,,] 
[Database,default,] 
[Table,customers,] 
[Owner,aurobindosarkar,] 
[Created,Sun Jul 09 23:16:38 IST 2017,] 
[Last Access,Thu Jan 01 05:30:00 IST 1970,] 
[Type,MANAGED,] 
[Provider,parquet,] 
[Properties,[serialization.format=1],] 
[Statistics,1728063103 bytes, 200000000 rows,] 
[Location,file:/Users/aurobindosarkar/Downloads/spark-2.2.0-bin-hadoop2.7/spark-warehouse/customers,] 
[Serde Library,org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe,] 
[InputFormat,org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat,] 
[OutputFormat,org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat,] 
```

以下 SQL 语句可用于显示优化后的逻辑计划中的统计信息：

```scala
EXPLAIN COST SELECT * FROM table_name WHERE condition 
```

# 统计收集函数

统计信息是使用一组函数收集的，例如，行数实际上是通过运行 SQL 语句获得的，例如`select count(1) from table_name`。使用 SQL 语句获取行数是快速的，因为我们利用了 Spark SQL 的执行并行性。类似地，`analyzeColumns`函数获取给定列的基本统计信息。基本统计信息，如`最大值`、`最小值`和`不同值的数量`，也是通过运行 SQL 语句获得的。

# 过滤运算符

过滤条件是 SQL select 语句的`WHERE`子句中指定的谓词表达式。当我们评估整体过滤因子时，谓词表达式可能非常复杂。

有几个运算符执行过滤基数估计，例如，在`AND`、`OR`和`NOT`逻辑表达式之间，以及逻辑表达式如`=`、`<`、`<=`、`>`、`>=`和`in`。

对于过滤运算符，我们的目标是计算过滤条件，以找出应用过滤条件后前一个（或子）运算符输出的部分。过滤因子是一个介于`0.0`和`1.0`之间的双精度数。过滤运算符的输出行数基本上是其`子节点`的输出行数乘以过滤因子。其输出大小是其`子节点`的输出大小乘以过滤因子。

# 连接运算符

在计算两个表连接输出的基数之前，我们应该已经有其两侧`子节点`的输出基数。每个连接侧的基数不再是原始连接表中的记录数。相反，它是在此连接运算符之前应用所有执行运算符后合格记录的数量。

如果用户收集`join column`统计信息，那么我们就知道每个`join column`的不同值的数量。由于我们还知道连接关系上的记录数量，我们可以判断`join column`是否是唯一键。我们可以计算`join column`上不同值的数量与连接关系中记录数量的比率。如果比率接近`1.0`（比如大于`0.95`），那么我们可以假设`join column`是唯一的。因此，如果`join column`是唯一的，我们可以精确确定每个不同值的记录数量。

# 构建侧选择

CBO 可以为执行操作符选择一个良好的物理策略。例如，CBO 可以选择`hash join`操作的`build side`选择。对于双向哈希连接，我们需要选择一个操作数作为`build side`，另一个作为`probe side`。该方法选择成本较低的子节点作为`hash join`的`build side`。

在 Spark 2.2 之前，构建侧是基于原始表大小选择的。对于以下 Join 查询示例，早期的方法会选择`BuildRight`。然而，使用 CBO，构建侧是基于连接之前各种操作符的估计成本选择的。在这里，会选择`BuildLeft`。它还可以决定是否执行广播连接。此外，可以重新排列给定查询的数据库操作符的执行顺序。`cbo`可以在给定查询的多个候选计划中选择最佳计划。目标是选择具有最低成本的候选计划：

```scala
scala> spark.sql("DROP TABLE IF EXISTS t1") 
scala> spark.sql("DROP TABLE IF EXISTS t2") 
scala> spark.sql("CREATE TABLE IF NOT EXISTS t1(id long, value long) USING parquet") 
scala> spark.sql("CREATE TABLE IF NOT EXISTS t2(id long, value string) USING parquet") 

scala> spark.range(5E8.toLong).select('id, (rand(17) * 1E6) cast "long").write.mode("overwrite").insertInto("t1") 
scala> spark.range(1E8.toLong).select('id, 'id cast "string").write.mode("overwrite").insertInto("t2") 

scala> sql("SELECT t1.id FROM t1, t2 WHERE t1.id = t2.id AND t1.value = 100").explain() 
== Physical Plan == 
*Project [id#79L] 
+- *SortMergeJoin [id#79L], [id#81L], Inner 
   :- *Sort [id#79L ASC NULLS FIRST], false, 0 
   :  +- Exchange hashpartitioning(id#79L, 200) 
   :     +- *Project [id#79L] 
   :        +- *Filter ((isnotnull(value#80L) && (value#80L = 100)) && isnotnull(id#79L)) 
   :           +- *FileScan parquet default.t1[id#79L,value#80L] Batched: true, Format: Parquet, Location: InMemoryFileIndex[file:/Users/aurobindosarkar/Downloads/spark-2.2.0-bin-hadoop2.7/spark-warehouse..., PartitionFilters: [], PushedFilters: [IsNotNull(value), EqualTo(value,100), IsNotNull(id)], ReadSchema: struct<id:bigint,value:bigint> 
   +- *Sort [id#81L ASC NULLS FIRST], false, 0 
      +- Exchange hashpartitioning(id#81L, 200) 
         +- *Project [id#81L] 
            +- *Filter isnotnull(id#81L) 
               +- *FileScan parquet default.t2[id#81L] Batched: true, Format: Parquet, Location: InMemoryFileIndex[file:/Users/aurobindosarkar/Downloads/spark-2.2.0-bin-hadoop2.7/spark-warehouse..., PartitionFilters: [], PushedFilters: [IsNotNull(id)], ReadSchema: struct<id:bigint> 
```

在下一节中，我们将探讨多向连接中的 CBO 优化。

# 理解多向连接排序优化

Spark SQL 优化器的启发式规则可以将`SELECT`语句转换为具有以下特征的查询计划：

+   过滤操作符和投影操作符被推送到连接操作符下面，也就是说，过滤和投影操作符在连接操作符之前执行。

+   没有子查询块时，连接操作符被推送到聚合操作符下面，也就是说，连接操作符通常在聚合操作符之前执行。

通过这一观察，我们从 CBO 中可以获得的最大好处是多向连接排序优化。使用动态规划技术，我们尝试为多向连接查询获得全局最优的连接顺序。

有关 Spark 2.2 中多向连接重新排序的更多详细信息，请参阅[`spark-summit.org/2017/events/cost-based-optimizer-in-apache-spark-22/`](https://spark-summit.org/2017/events/cost-based-optimizer-in-apache-spark-22/)。

显然，连接成本是选择最佳连接顺序的主要因素。成本公式取决于 Spark SQL 执行引擎的实现。

Spark 中的连接成本公式如下：

*权重*基数+大小*（1-权重）*

公式中的权重是通过`spark.sql.cbo.joinReorder.card.weight`参数配置的调整参数（默认值为`0.7`）。计划的成本是所有中间表的成本之和。请注意，当前的成本公式非常粗糙，预计 Spark 的后续版本将具有更精细的公式。

有关使用动态规划算法重新排序连接的更多详细信息，请参阅 Selinger 等人的论文，网址为[`citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.129.5879&rep=rep1&type=pdf`](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.129.5879&rep=rep1&type=pdf)。

首先，我们将所有项目（基本连接节点）放入级别 1，然后从级别 1 的计划（单个项目）构建级别 2 的所有双向连接，然后从先前级别的计划（双向连接和单个项目）构建所有三向连接，然后是四向连接，依此类推，直到我们构建了所有 n 向连接，并在每个阶段选择最佳计划。

在构建 m 路连接时，我们只保留相同 m 个项目集的最佳计划（成本最低）。例如，对于三路连接，我们只保留项目集`{A, B, C}`的最佳计划，包括`(A J B) J C`、`(A J C) J B`和`(B J C) J A`。

这个算法的一个缺点是假设最低成本的计划只能在其前一级的最低成本计划中生成。此外，由于选择排序合并连接（保留其输入顺序）与其他连接方法的决定是在查询规划阶段完成的，因此我们没有这些信息来在优化器中做出良好的决策。

接下来，我们展示了一个扩展的例子，展示了关闭和打开`cbo`和`joinReorder`参数后的速度改进：

```scala
scala> sql("CREATE TABLE IF NOT EXISTS customers(id long, name string) USING parquet") 
scala> sql("CREATE TABLE IF NOT EXISTS goods(id long, price long) USING parquet") 
scala> sql("CREATE TABLE IF NOT EXISTS orders(customer_id long, good_id long) USING parquet") 

scala> import org.apache.spark.sql.functions.rand 

scala> spark.sql("CREATE TABLE IF NOT EXISTS customers(id long, name string) USING parquet") 
scala> spark.sql("CREATE TABLE IF NOT EXISTS goods(id long, price long) USING parquet") 
scala> spark.sql("CREATE TABLE IF NOT EXISTS orders(customer_id long, good_id long) USING parquet") 

scala> spark.range(2E8.toLong).select('id, 'id cast "string").write.mode("overwrite").insertInto("customers") 

scala> spark.range(1E8.toLong).select('id, (rand(17) * 1E6 + 2) cast "long").write.mode("overwrite").insertInto("goods") 
spark.range(1E7.toLong).select(rand(3) * 2E8 cast "long", (rand(5) * 1E8) cast "long").write.mode("overwrite").insertInto("orders") 
```

我们定义了一个 benchmark 函数来测量我们查询的执行时间：

```scala
scala> def benchmark(name: String)(f: => Unit) { 
     |      val startTime = System.nanoTime 
     |      f 
     |      val endTime = System.nanoTime 
     |      println(s"Time taken with $name: " + (endTime - 
                    startTime).toDouble / 1000000000 + " seconds") 
     | } 

```

在第一个例子中，如所示，我们关闭了`cbo`和`joinReorder`参数：

```scala

scala> val conf = spark.sessionState.conf 

scala> spark.conf.set("spark.sql.cbo.enabled", false) 

scala> conf.cboEnabled 
res1: Boolean = false 

scala> conf.joinReorderEnabled 
res2: Boolean = false 

scala> benchmark("CBO OFF & JOIN REORDER DISABLED"){ sql("SELECT name FROM customers, orders, goods WHERE customers.id = orders.customer_id AND orders.good_id = goods.id AND goods.price > 1000000").show() } 
```

以下是在命令行上的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00303.jpeg)

在下一个例子中，我们打开了`cbo`但保持`joinReorder`参数禁用：

```scala
scala> spark.conf.set("spark.sql.cbo.enabled", true) 
scala> conf.cboEnabled 
res11: Boolean = true 
scala> conf.joinReorderEnabled 
res12: Boolean = false 

scala> benchmark("CBO ON & JOIN REORDER DIABLED"){ sql("SELECT name FROM customers, orders, goods WHERE customers.id = orders.customer_id AND orders.good_id = goods.id AND goods.price > 1000000").show()} 
```

以下是在命令行上的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00304.jpeg)

请注意，在启用`cbo`参数的情况下，查询的执行时间略有改善。

在最后一个例子中，我们同时打开了`cbo`和`joinReorder`参数：

```scala
scala> spark.conf.set("spark.sql.cbo.enabled", true) 
scala> spark.conf.set("spark.sql.cbo.joinReorder.enabled", true) 
scala> conf.cboEnabled 
res2: Boolean = true 
scala> conf.joinReorderEnabled 
res3: Boolean = true 

scala> benchmark("CBO ON & JOIN REORDER ENABLED"){ sql("SELECT name FROM customers, orders, goods WHERE customers.id = orders.customer_id AND orders.good_id = goods.id AND goods.price > 1000000").show()} 
```

以下是在命令行上的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00305.jpeg)

请注意，在启用了这两个参数的情况下，查询的执行时间有了显著的改进。

在接下来的部分中，我们将检查使用整体代码生成实现的各种`JOINs`的性能改进。

# 使用整体代码生成理解性能改进

在本节中，我们首先概述了 Spark SQL 中整体代码生成的高级概述，然后通过一系列示例展示了使用 Catalyst 的代码生成功能改进各种`JOINs`的性能。

在我们有了优化的查询计划之后，需要将其转换为 RDD 的 DAG，以在集群上执行。我们使用这个例子来解释 Spark SQL 整体代码生成的基本概念：

```scala
scala> sql("select count(*) from orders where customer_id = 26333955").explain() 

== Optimized Logical Plan == 
Aggregate [count(1) AS count(1)#45L] 
+- Project 
   +- Filter (isnotnull(customer_id#42L) && (customer_id#42L = 
              26333955)) 
      +- Relation[customer_id#42L,good_id#43L] parquet 
```

优化的逻辑计划可以看作是一系列的**扫描**、**过滤**、**投影**和**聚合**操作，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00306.jpeg)

传统数据库通常基于 Volcano 迭代器模型执行前面的查询，其中每个操作符实现一个迭代器接口，并从其输入操作符消耗记录，并向其后顺序的操作符输出记录。这个模型使得可以轻松添加新的操作符，而不受其与其他操作符的交互影响。它还促进了操作符的可组合性。然而，Volcano 模型效率低下，因为它涉及执行许多虚拟函数调用，例如，每个记录在`Aggregate`函数中执行三次调用。此外，它需要大量的内存访问（由于按照迭代器接口在每个操作符中的读/写）。在 Volcano 模型上利用现代 CPU 特性（如流水线处理、预取和分支预测）也是具有挑战性的。

Spark SQL 不是为每个操作符生成迭代器代码，而是尝试为 SQL 语句中的操作符集生成一个单一函数。例如，前面查询的伪代码可能看起来像下面这样。这里，`for`循环遍历所有行（扫描操作），if 条件大致对应于过滤条件，而聚合本质上是计数：

```scala
long count = 0; 
for (customer_id in orders) {  
   if (customer_id == 26333955) { 
         count += 1; 
   } 
} 
```

请注意，简单的代码中没有虚拟函数调用，而且增加的计数变量存储在 CPU 寄存器中。这段代码易于编译器理解，因此现代硬件可以利用来加速这样的查询。

整个阶段代码生成的关键思想包括将操作符融合在一起，识别操作符链（阶段），并将每个阶段编译成单个函数。这导致生成的代码模仿手写优化代码来执行查询。

有关在现代硬件上编译查询计划的更多详细信息，请参阅[`www.vldb.org/pvldb/vol4/p539-neumann.pdf`](http://www.vldb.org/pvldb/vol4/p539-neumann.pdf)。

我们可以使用`EXPLAIN CODEGEN`来探索为查询生成的代码，如下所示：

```scala
scala> sql("EXPLAIN CODEGEN SELECT name FROM customers, orders, goods WHERE customers.id = orders.customer_id AND orders.good_id = goods.id AND goods.price > 1000000").take(1).foreach(println) 
[Found 6 WholeStageCodegen subtrees.                                             
== Subtree 1 / 6 == 
*Project [id#11738L] 
+- *Filter ((isnotnull(price#11739L) && (price#11739L > 1000000)) && isnotnull(id#11738L)) 
   +- *FileScan parquet default.goods[id#11738L,price#11739L] Batched: true, Format: Parquet, Location: InMemoryFileIndex[file:/Users/aurobindosarkar/Downloads/spark-2.2.0-bin-hadoop2.7/spark-warehouse..., PartitionFilters: [], PushedFilters: [IsNotNull(price), GreaterThan(price,1000000), IsNotNull(id)], ReadSchema: struct<id:bigint,price:bigint> 

Generated code: 
/* 001 */ public Object generate(Object[] references) { 
/* 002 */   return new GeneratedIterator(references); 
/* 003 */ } 
... 
== Subtree 6 / 6 == 
*Sort [id#11734L ASC NULLS FIRST], false, 0 
+- Exchange hashpartitioning(id#11734L, 200) 
   +- *Project [id#11734L, name#11735] 
      +- *Filter isnotnull(id#11734L) 
         +- *FileScan parquet default.customers[id#11734L,name#11735] Batched: true, Format: Parquet, Location: InMemoryFileIndex[file:/Users/aurobindosarkar/Downloads/spark-2.2.0-bin-hadoop2.7/spark-warehouse..., PartitionFilters: [], PushedFilters: [IsNotNull(id)], ReadSchema: struct<id:bigint,name:string> 

Generated code: 
/* 001 */ public Object generate(Object[] references) { 
/* 002 */   return new GeneratedIterator(references); 
/* 003 */ } 
... 
] 
```

在这里，我们提供了一系列使用关闭和随后打开整个阶段代码生成的`JOIN`示例，以查看对执行性能的显着影响。

本节中的示例取自[`github.com/apache/spark/blob/master/sql/core/src/test/scala/org/apache/spark/sql/execution/benchmark/JoinBenchmark.scala`](https://github.com/apache/spark/blob/master/sql/core/src/test/scala/org/apache/spark/sql/execution/benchmark/JoinBenchmark.scala)中可用的`JoinBenchmark.scala`类。

在以下示例中，我们介绍了获取使用长值进行 JOIN 操作的执行时间的详细信息：

```scala
scala> spark.conf.set("spark.sql.codegen.wholeStage", false) 

scala> conf.wholeStageEnabled 
res77: Boolean = false 

scala> val N = 20 << 20 
N: Int = 20971520 

scala> val M = 1 << 16 
M: Int = 65536 

scala> val dim = broadcast(spark.range(M).selectExpr("id as k", "cast(id as string) as v")) 

scala> benchmark("Join w long") { 
     |   spark.range(N).join(dim, (col("id") % M) === col("k")).count() 
     | } 
Time taken in Join w long: 2.612163207 seconds                                   

scala> spark.conf.set("spark.sql.codegen.wholeStage", true) 

scala> conf.wholeStageEnabled 
res80: Boolean = true 

scala> val dim = broadcast(spark.range(M).selectExpr("id as k", "cast(id as string) as v")) 

scala> benchmark("Join w long") { 
     |   spark.range(N).join(dim, (col("id") % M) === col("k")).count() 
     | } 
Time taken in Join w long: 0.777796256 seconds 
```

对于以下一组示例，我们仅呈现获取其执行时间的基本要素，包括是否使用整个阶段代码生成。请参考前面的示例，并按照相同的步骤顺序复制以下示例：

```scala
scala> val dim = broadcast(spark.range(M).selectExpr("id as k", "cast(id as string) as v")) 
scala> benchmark("Join w long duplicated") { 
     |     val dim = broadcast(spark.range(M).selectExpr("cast(id/10 as long) as k")) 
     |     spark.range(N).join(dim, (col("id") % M) === col("k")).count() 
     | } 
Time taken in Join w long duplicated: 1.514799811 seconds           
Time taken in Join w long duplicated: 0.278705816 seconds 

scala> val dim3 = broadcast(spark.range(M).selectExpr("id as k1", "id as k2", "cast(id as string) as v")) 
scala> benchmark("Join w 2 longs") { 
     |     spark.range(N).join(dim3, (col("id") % M) === col("k1") && (col("id") % M) === col("k2")).count() 
     | } 
Time taken in Join w 2 longs: 2.048950962 seconds       
Time taken in Join w 2 longs: 0.681936701 seconds 

scala> val dim4 = broadcast(spark.range(M).selectExpr("cast(id/10 as long) as k1", "cast(id/10 as long) as k2")) 
scala> benchmark("Join w 2 longs duplicated") { 
     |     spark.range(N).join(dim4, (col("id") bitwiseAND M) === col("k1") && (col("id") bitwiseAND M) === col("k2")).count() 
     | } 
Time taken in Join w 2 longs duplicated: 4.924196601 seconds      
Time taken in Join w 2 longs duplicated: 0.818748429 seconds      

scala> val dim = broadcast(spark.range(M).selectExpr("id as k", "cast(id as string) as v")) 
scala> benchmark("outer join w long") { 
     |     spark.range(N).join(dim, (col("id") % M) === col("k"), "left").count() 
     | } 
Time taken in outer join w long: 1.580664228 seconds        
Time taken in outer join w long: 0.280608235 seconds 

scala> val dim = broadcast(spark.range(M).selectExpr("id as k", "cast(id as string) as v")) 
scala> benchmark("semi join w long") { 
     |     spark.range(N).join(dim, (col("id") % M) === col("k"), "leftsemi").count() 
     | } 
Time taken in semi join w long: 1.027175143 seconds             
Time taken in semi join w long: 0.180771478 seconds 

scala> val N = 2 << 20 
N: Int = 2097152 
scala> benchmark("merge join") { 
     |     val df1 = spark.range(N).selectExpr(s"id * 2 as k1") 
     |     val df2 = spark.range(N).selectExpr(s"id * 3 as k2") 
     |     df1.join(df2, col("k1") === col("k2")).count() 
     | } 
Time taken in merge join: 2.260524298 seconds          
Time taken in merge join: 2.053497825 seconds             

scala> val N = 2 << 20 
N: Int = 2097152 
scala> benchmark("sort merge join") { 
     |     val df1 = spark.range(N).selectExpr(s"(id * 15485863) % ${N*10} as k1") 
     |     val df2 = spark.range(N).selectExpr(s"(id * 15485867) % ${N*10} as k2") 
     |     df1.join(df2, col("k1") === col("k2")).count() 
     | } 
Time taken in sort merge join: 2.481585466 seconds                
Time taken in sort merge join: 1.992168281 seconds                
```

作为练习，请使用本节中的示例来探索它们的逻辑和物理计划，并使用 SparkUI 查看和理解它们的执行。

在调整任务中使用了几个 Spark SQL 参数设置。`SQLConf`是 Spark SQL 中用于参数和提示的内部键值配置存储。要打印出这些参数的所有当前值，请使用以下语句：

```scala
scala> conf.getAllConfs.foreach(println) 
(spark.driver.host,192.168.1.103) 
(spark.sql.autoBroadcastJoinThreshold,1000000) 
(spark.driver.port,57085) 
(spark.repl.class.uri,spark://192.168.1.103:57085/classes) 
(spark.jars,) 
(spark.repl.class.outputDir,/private/var/folders/tj/prwqrjj16jn4k5jh6g91rwtc0000gn/T/spark-9f8b5ba4-e8f4-4c60-b01b-30c4b71a06e1/repl-ae75dedc-703a-41b8-b949-b91ed3b362f1) 
(spark.app.name,Spark shell) 
(spark.driver.memory,14g) 
(spark.sql.codegen.wholeStage,true) 
(spark.executor.id,driver) 
(spark.sql.cbo.enabled,true) 
(spark.sql.join.preferSortMergeJoin,false) 
(spark.submit.deployMode,client) 
(spark.master,local[*]) 
(spark.home,/Users/aurobindosarkar/Downloads/spark-2.2.0-bin-hadoop2.7) 
(spark.sql.catalogImplementation,hive) 
(spark.app.id,local-1499953390374) 
(spark.sql.shuffle.partitions,2) 
```

您还可以使用以下语句列出所有已定义配置参数的扩展集：

```scala
scala> conf.getAllDefinedConfs.foreach(println) 
```

# 摘要

在本章中，我们介绍了与调整 Spark 应用程序相关的基本概念，包括使用编码器进行数据序列化。我们还介绍了在 Spark 2.2 中引入的基于成本的优化器的关键方面，以自动优化 Spark SQL 执行。最后，我们提供了一些`JOIN`操作的示例，以及使用整个阶段代码生成导致执行时间改进的情况。

在下一章中，我们将探讨利用 Spark 模块和 Spark SQL 的应用程序架构在实际应用中的应用。我们还将描述用于批处理、流处理应用和机器学习流水线的一些主要处理模型的部署。


# 第十二章：Spark SQL 在大规模应用程序架构中的应用

在本书中，我们从 Spark SQL 及其组件的基础知识开始，以及它在 Spark 应用程序中的作用。随后，我们提出了一系列关于其在各种类型应用程序中的使用的章节。作为 Spark SQL 的核心，DataFrame/Dataset API 和 Catalyst 优化器在所有基于 Spark 技术栈的应用程序中发挥关键作用，这并不奇怪。这些应用程序包括大规模机器学习、大规模图形和深度学习应用程序。此外，我们提出了基于 Spark SQL 的结构化流应用程序，这些应用程序作为连续应用程序在复杂环境中运行。在本章中，我们将探讨在现实世界应用程序中利用 Spark 模块和 Spark SQL 的应用程序架构。

更具体地，我们将涵盖大规模应用程序中的关键架构组件和模式，这些对架构师和设计师来说将作为特定用例的起点。我们将描述一些用于批处理、流处理应用程序和机器学习管道的主要处理模型的部署。这些处理模型的基础架构需要支持在一端到达高速的各种类型数据的大量数据，同时在另一端使输出数据可供分析工具、报告和建模软件使用。此外，我们将使用 Spark SQL 提供支持代码，用于监控、故障排除和收集/报告指标。

我们将在本章中涵盖以下主题：

+   理解基于 Spark 的批处理和流处理架构

+   理解 Lambda 和 Kappa 架构

+   使用结构化流实现可扩展的流处理

+   使用 Spark SQL 构建强大的 ETL 管道

+   使用 Spark SQL 实现可扩展的监控解决方案

+   部署 Spark 机器学习管道

+   使用集群管理器：Mesos 和 Kubernetes

# 理解基于 Spark 的应用程序架构

Apache Spark 是一个新兴的平台，利用分布式存储和处理框架来支持规模化的查询、报告、分析和智能应用。Spark SQL 具有必要的功能，并支持所需的关键机制，以访问各种数据源和格式的数据，并为下游应用程序做准备，无论是低延迟的流数据还是高吞吐量的历史数据存储。下图显示了典型的基于 Spark 的批处理和流处理应用程序中包含这些要求的高级架构：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00307.jpeg)

此外，随着组织开始在许多项目中采用大数据和 NoSQL 解决方案，仅由 RDBMS 组成的数据层不再被认为是现代企业应用程序所有用例的最佳选择。仅基于 RDBMS 的架构在下图所示的行业中迅速消失，以满足典型大数据应用程序的要求：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00308.jpeg)

下图显示了一个更典型的场景，其中包含多种类型的数据存储。如今的应用程序使用多种数据存储类型，这些类型最适合特定的用例。根据应用程序使用数据的方式选择多种数据存储技术，称为多语言持久性。Spark SQL 在云端或本地部署中是这种和其他类似持久性策略的极好的实现者：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00309.jpeg)

此外，我们观察到，现实世界中只有一小部分 ML 系统由 ML 代码组成（下图中最小的方框）。然而，围绕这些 ML 代码的基础设施是庞大且复杂的。在本章的后面，我们将使用 Spark SQL 来创建这些应用程序中的一些关键部分，包括可扩展的 ETL 管道和监控解决方案。随后，我们还将讨论机器学习管道的生产部署，以及使用 Mesos 和 Kubernetes 等集群管理器：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00310.gif)

参考：“机器学习系统中的隐藏技术债务”，Google NIPS 2015

在下一节中，我们将讨论基于 Spark 的批处理和流处理架构中的关键概念和挑战。

# 使用 Apache Spark 进行批处理

通常，批处理是针对大量数据进行的，以创建批量视图，以支持特定查询和 MIS 报告功能，和/或应用可扩展的机器学习算法，如分类、聚类、协同过滤和分析应用。

由于批处理涉及的数据量较大，这些应用通常是长时间运行的作业，并且很容易延长到几个小时、几天或几周，例如，聚合查询，如每日访问者数量、网站的独立访问者和每周总销售额。

越来越多的人开始将 Apache Spark 作为大规模数据处理的引擎。它可以在内存中运行程序，比 Hadoop MapReduce 快 100 倍，或者在磁盘上快 10 倍。Spark 被迅速采用的一个重要原因是，它需要相似的编码来满足批处理和流处理的需求。

在下一节中，我们将介绍流处理的关键特征和概念。

# 使用 Apache Spark 进行流处理

大多数现代企业都在努力处理大量数据（以及相关数据的快速和无限增长），同时还需要低延迟的处理需求。此外，与传统的批处理 MIS 报告相比，从实时流数据中获得的近实时业务洞察力被赋予了更高的价值。与流处理系统相反，传统的批处理系统旨在处理一组有界数据的大量数据。这些系统在执行开始时就提供了它们所需的所有数据。随着输入数据的不断增长，这些批处理系统提供的结果很快就会过时。

通常，在流处理中，数据在触发所需处理之前不会在显著的时间段内收集。通常，传入的数据被移动到排队系统，例如 Apache Kafka 或 Amazon Kinesis。然后，流处理器访问这些数据，并对其执行某些计算以生成结果输出。典型的流处理管道创建增量视图，这些视图通常根据流入系统的增量数据进行更新。

增量视图通过**Serving Layer**提供，以支持查询和实时分析需求，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00311.jpeg)

在流处理系统中有两种重要的时间类型：事件时间和处理时间。事件时间是事件实际发生的时间（在源头），而处理时间是事件在处理系统中被观察到的时间。事件时间通常嵌入在数据本身中，对于许多用例来说，这是您想要操作的时间。然而，从数据中提取事件时间，并处理延迟或乱序数据在流处理应用程序中可能会带来重大挑战。此外，由于资源限制、分布式处理模型等原因，事件时间和处理时间之间存在偏差。有许多用例需要按事件时间进行聚合；例如，在一个小时的窗口中系统错误的数量。

还可能存在其他问题；例如，在窗口功能中，我们需要确定是否已观察到给定事件时间的所有数据。这些系统需要设计成能够在不确定的环境中良好运行。例如，在 Spark 结构化流处理中，可以为数据流一致地定义基于事件时间的窗口聚合查询，因为它可以处理延迟到达的数据，并适当更新旧的聚合。

在处理大数据流应用程序时，容错性至关重要，例如，一个流处理作业可以统计到目前为止看到的所有元组的数量。在这里，每个元组可能代表用户活动的流，应用程序可能希望报告到目前为止看到的总活动。在这样的系统中，节点故障可能导致计数不准确，因为有未处理的元组（在失败的节点上）。

从这种情况中恢复的一个天真的方法是重新播放整个数据集。考虑到涉及的数据规模，这是一个昂贵的操作。检查点是一种常用的技术，用于避免重新处理整个数据集。在发生故障的情况下，应用程序数据状态将恢复到最后一个检查点，并且从那一点开始重新播放元组。为了防止 Spark Streaming 应用程序中的数据丢失，使用了**预写式日志**（**WAL**），在故障后可以从中重新播放数据。

在下一节中，我们将介绍 Lambda 架构，这是在 Spark 中心应用程序中实施的一种流行模式，因为它可以使用非常相似的代码满足批处理和流处理的要求。

# 理解 Lambda 架构

Lambda 架构模式试图结合批处理和流处理的优点。该模式由几个层组成：**批处理层**（在持久存储上摄取和处理数据，如 HDFS 和 S3），**速度层**（摄取和处理尚未被**批处理层**处理的流数据），以及**服务层**（将**批处理**和**速度层**的输出合并以呈现合并结果）。这是 Spark 环境中非常流行的架构，因为它可以支持**批处理**和**速度层**的实现，两者之间的代码差异很小。

给定的图表描述了 Lambda 架构作为批处理和流处理的组合：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00312.jpeg)

下图显示了使用 AWS 云服务（**Amazon Kinesis**，**Amazon S3**存储，**Amazon EMR**，**Amazon DynamoDB**等）和 Spark 实现 Lambda 架构：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00313.jpeg)

有关 AWS 实施 Lambda 架构的更多详细信息，请参阅[`d0.awsstatic.com/whitepapers/lambda-architecure-on-for-batch-aws.pdf`](https://d0.awsstatic.com/whitepapers/lambda-architecure-on-for-batch-aws.pdf)。

在下一节中，我们将讨论一个更简单的架构，称为 Kappa 架构，它完全放弃了**批处理层**，只在**速度层**中进行流处理。

# 理解 Kappa 架构

**Kappa 架构**比 Lambda 模式更简单，因为它只包括速度层和服务层。所有计算都作为流处理进行，不会对完整数据集进行批量重新计算。重新计算仅用于支持更改和新需求。

通常，传入的实时数据流在内存中进行处理，并持久化在数据库或 HDFS 中以支持查询，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00314.jpeg)

Kappa 架构可以通过使用 Apache Spark 结合排队解决方案（如 Apache Kafka）来实现。如果数据保留时间限制在几天到几周，那么 Kafka 也可以用来保留数据一段有限的时间。

在接下来的几节中，我们将介绍一些使用 Apache Spark、Scala 和 Apache Kafka 的实际应用开发环境中非常有用的实践练习。我们将首先使用 Spark SQL 和结构化流来实现一些流式使用案例。

# 构建可扩展流处理应用的设计考虑

构建健壮的流处理应用是具有挑战性的。与流处理相关的典型复杂性包括以下内容：

+   **复杂数据**：多样化的数据格式和数据质量在流应用中带来了重大挑战。通常，数据以各种格式可用，如 JSON、CSV、AVRO 和二进制。此外，脏数据、延迟到达和乱序数据会使这类应用的设计变得极其复杂。

+   **复杂工作负载**：流应用需要支持多样化的应用需求，包括交互式查询、机器学习流水线等。

+   **复杂系统**：具有包括 Kafka、S3、Kinesis 等多样化存储系统，系统故障可能导致重大的重新处理或错误结果。

使用 Spark SQL 进行流处理可以快速、可扩展和容错。它提供了一套高级 API 来处理复杂数据和工作负载。例如，数据源 API 可以与许多存储系统和数据格式集成。

有关构建可扩展和容错的结构化流处理应用的详细覆盖范围，请参阅[`spark-summit.org/2017/events/easy-scalable-fault-tolerant-stream-processing-with-structured-streaming-in-apache-spark/`](https://spark-summit.org/2017/events/easy-scalable-fault-tolerant-stream-processing-with-structured-streaming-in-apache-spark/)。

流查询允许我们指定一个或多个数据源，使用 DataFrame/Dataset API 或 SQL 转换数据，并指定各种接收器来输出结果。内置支持多种数据源，如文件、Kafka 和套接字，如果需要，还可以组合多个数据源。

Spark SQL Catalyst 优化器可以找出增量执行转换的机制。查询被转换为一系列对新数据批次进行操作的增量执行计划。接收器接受每个批次的输出，并在事务上下文中完成更新。您还可以指定各种输出模式（**完整**、**更新**或**追加**）和触发器来控制何时输出结果。如果未指定触发器，则结果将持续更新。通过持久化检查点来管理给定查询的进度和故障后的重启。

选择适当的数据格式

有关结构化流内部的详细说明，请查看[`spark.apache.org/docs/latest/structured-streaming-programming-guide.html`](http://spark.apache.org/docs/latest/structured-streaming-programming-guide.html)。

Spark 结构化流使得流式分析变得简单，无需担心使流式工作的复杂底层机制。在这个模型中，输入可以被视为来自一个不断增长的追加表的数据。触发器指定了检查输入是否到达新数据的时间间隔，查询表示对输入进行的操作，如映射、过滤和减少。结果表示在每个触发间隔中更新的最终表（根据指定的查询操作）。

在下一节中，我们将讨论 Spark SQL 功能，这些功能可以帮助构建强大的 ETL 管道。

# 使用 Spark SQL 构建强大的 ETL 管道

ETL 管道在源数据上执行一系列转换，以生成经过清洗、结构化并准备好供后续处理组件使用的输出。需要应用在源数据上的转换将取决于数据的性质。输入或源数据可以是结构化的（关系型数据库，Parquet 等），半结构化的（CSV，JSON 等）或非结构化数据（文本，音频，视频等）。通过这样的管道处理后，数据就可以用于下游数据处理、建模、分析、报告等。

下图说明了一个应用架构，其中来自 Kafka 和其他来源（如应用程序和服务器日志）的输入数据在存储到企业数据存储之前经过清洗和转换（使用 ETL 管道）。这个数据存储最终可以供其他应用程序使用（通过 Kafka），支持交互式查询，将数据的子集或视图存储在服务数据库中，训练 ML 模型，支持报告应用程序等。

在下一节中，我们将介绍一些标准，可以帮助您选择适当的数据格式，以满足特定用例的要求。

正如缩写（ETL）所示，我们需要从各种来源检索数据（提取），转换数据以供下游使用（转换），并将其传输到不同的目的地（加载）。

在接下来的几节中，我们将使用 Spark SQL 功能来访问和处理各种数据源和数据格式，以实现 ETL 的目的。Spark SQL 灵活的 API，结合 Catalyst 优化器和 tungsten 执行引擎，使其非常适合构建端到端的 ETL 管道。

在下面的代码块中，我们提供了一个简单的单个 ETL 查询的框架，结合了所有三个（提取、转换和加载）功能。这些查询也可以扩展到执行包含来自多个来源和来源格式的数据的表之间的复杂连接：

```scala
spark.read.json("/source/path") //Extract
.filter(...) //Transform
.agg(...) //Transform
.write.mode("append") .parquet("/output/path") //Load
```

我们还可以对流数据执行滑动窗口操作。在这里，我们定义了对滑动窗口的聚合，其中我们对数据进行分组并计算适当的聚合（对于每个组）。

# ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00315.jpeg)

在企业设置中，数据以许多不同的数据源和格式可用。Spark SQL 支持一组内置和第三方连接器。此外，我们还可以定义自定义数据源连接器。数据格式包括结构化、半结构化和非结构化格式，如纯文本、JSON、XML、CSV、关系型数据库记录、图像和视频。最近，Parquet、ORC 和 Avro 等大数据格式变得越来越受欢迎。一般来说，纯文本文件等非结构化格式更灵活，而 Parquet 和 AVRO 等结构化格式在存储和性能方面更有效率。

在结构化数据格式的情况下，数据具有严格的、明确定义的模式或结构。例如，列式数据格式使得从列中提取值更加高效。然而，这种严格性可能会使对模式或结构的更改变得具有挑战性。相比之下，非结构化数据源，如自由格式文本，不包含 CSV 或 TSV 文件中的标记或分隔符。这样的数据源通常需要一些关于数据的上下文；例如，你需要知道文件的内容包含来自博客的文本。

通常，我们需要许多转换和特征提取技术来解释不同的数据集。半结构化数据在记录级别上是结构化的，但不一定在所有记录上都是结构化的。因此，每个数据记录都包含相关的模式信息。

JSON 格式可能是半结构化数据最常见的例子。JSON 记录以人类可读的形式呈现，这对于开发和调试来说更加方便。然而，这些格式受到解析相关的开销的影响，通常不是支持特定查询功能的最佳选择。

通常，应用程序需要设计成能够跨越各种数据源和格式高效存储和处理数据。例如，当需要访问完整的数据行时，Avro 是一个很好的选择，就像在 ML 管道中访问特征的情况一样。在需要模式的灵活性的情况下，使用 JSON 可能是数据格式的最合适选择。此外，在数据没有固定模式的情况下，最好使用纯文本文件格式。

# ETL 管道中的数据转换

通常，诸如 JSON 之类的半结构化格式包含 struct、map 和 array 数据类型；例如，REST Web 服务的请求和/或响应负载包含具有嵌套字段和数组的 JSON 数据。

在这一部分，我们将展示基于 Spark SQL 的 Twitter 数据转换的示例。输入数据集是一个文件（`cache-0.json.gz`），其中包含了在 2012 年美国总统选举前三个月内收集的超过`1.7 亿`条推文中的`1 千万`条推文。这个文件可以从[`datahub.io/dataset/twitter-2012-presidential-election`](https://datahub.io/dataset/twitter-2012-presidential-election)下载。

在开始以下示例之前，按照第五章中描述的方式启动 Zookeeper 和 Kafka 代理。另外，创建一个名为 tweetsa 的新 Kafka 主题。我们从输入 JSON 数据集生成模式，如下所示。这个模式定义将在本节后面使用：

```scala
scala> val jsonDF = spark.read.json("file:///Users/aurobindosarkar/Downloads/cache-0-json")

scala> jsonDF.printSchema()

scala> val rawTweetsSchema = jsonDF.schema

scala> val jsonString = rawTweetsSchema.json

scala> val schema = DataType.fromJson(jsonString).asInstanceOf[StructType]
```

设置从 Kafka 主题（*tweetsa*）中读取流式推文，并使用上一步的模式解析 JSON 数据。

在这个声明中，我们通过`指定数据.*`来选择推文中的所有字段：

```scala
scala> val rawTweets = spark.readStream.format("kafka").option("kafka.bootstrap.servers", "localhost:9092").option("subscribe", "tweetsa").load()

scala> val parsedTweets = rawTweets.selectExpr("cast (value as string) as json").select(from_json($"json", schema).as("data")).select("data.*")
```

在你通过示例工作时，你需要反复使用以下命令将输入文件中包含的推文传输到 Kafka 主题中，如下所示：

```scala
Aurobindos-MacBook-Pro-2:kafka_2.11-0.10.2.1 aurobindosarkar$ bin/kafka-console-producer.sh --broker-list localhost:9092 --topic tweetsa < /Users/aurobindosarkar/Downloads/cache-0-json
```

考虑到输入文件的大小，这可能会导致您的计算机出现空间相关的问题。如果发生这种情况，请使用适当的 Kafka 命令来删除并重新创建主题（参考[`kafka.apache.org/0102/documentation.html`](https://kafka.apache.org/0102/documentation.html)）。

在这里，我们重现了一个模式的部分，以帮助理解我们在接下来的几个示例中要处理的结构：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00316.jpeg)

我们可以从 JSON 字符串中的嵌套列中选择特定字段。我们使用`.`（点）运算符来选择嵌套字段，如下所示：

```scala
scala> val selectFields = parsedTweets.select("place.country").where($"place.country".isNotNull)
```

接下来，我们将输出流写入屏幕以查看结果。您需要在每个转换之后执行以下语句，以查看和评估结果。此外，为了节省时间，您应该在看到足够的屏幕输出后执行`s5.stop()`。或者，您可以选择使用从原始输入文件中提取的较小数据集进行工作：

```scala
scala> val s5 = selectFields.writeStream.outputMode("append").format("console").start()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00317.gif)

在下一个示例中，我们将使用星号（*）展平一个 struct 以选择 struct 中的所有子字段：

```scala
scala> val selectFields = parsedTweets.select("place.*").where($"place.country".isNotNull)
```

可以通过编写输出流来查看结果，如前面的示例所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00318.gif)

我们可以使用 struct 函数创建一个新的 struct（用于嵌套列），如下面的代码片段所示。我们可以选择特定字段或字段来创建新的 struct。如果需要，我们还可以使用星号（*）嵌套所有列。

在这里，我们重现了此示例中使用的模式部分：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00319.jpeg)

```scala
scala> val selectFields = parsedTweets.select(struct("place.country_code", "place.name") as 'locationInfo).where($"locationInfo.country_code".isNotNull)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00320.gif)

在下一个示例中，我们使用`getItem()`选择单个数组（或映射）元素。在这里，我们正在操作模式的以下部分：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00321.jpeg)

```scala
scala> val selectFields = parsedTweets.select($"entities.hashtags" as 'tags).select('tags.getItem(0) as 'x).select($"x.indices" as 'y).select($"y".getItem(0) as 'z).where($"z".isNotNull)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00322.jpeg)

```scala
scala> val selectFields = parsedTweets.select($"entities.hashtags" as 'tags).select('tags.getItem(0) as 'x).select($"x.text" as 'y).where($"y".isNotNull)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00323.gif)

我们可以使用`explode()`函数为数组中的每个元素创建新行，如所示。为了说明`explode()`的结果，我们首先展示包含数组的行，然后展示应用 explode 函数的结果：

```scala
scala> val selectFields = parsedTweets.select($"entities.hashtags.indices" as 'tags).select(explode('tags))
```

获得以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00324.jpeg)

请注意，在应用 explode 函数后，为数组元素创建了单独的行：

```scala
scala> val selectFields = parsedTweets.select($"entities.hashtags.indices".getItem(0) as 'tags).select(explode('tags))
```

获得的输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00325.jpeg)

Spark SQL 还具有诸如`to_json()`之类的函数，用于将`struct`转换为 JSON 字符串，以及`from_json()`，用于将 JSON 字符串转换为`struct`。这些函数对于从 Kafka 主题读取或写入非常有用。例如，如果“value”字段包含 JSON 字符串中的数据，则我们可以使用`from_json()`函数提取数据，转换数据，然后将其推送到不同的 Kafka 主题，并/或将其写入 Parquet 文件或服务数据库。

在以下示例中，我们使用`to_json()`函数将 struct 转换为 JSON 字符串：

```scala
scala> val selectFields = parsedTweets.select(struct($"entities.media.type" as 'x, $"entities.media.url" as 'y) as 'z).where($"z.x".isNotNull).select(to_json('z) as 'c)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00326.gif)

我们可以使用`from_json()`函数将包含 JSON 数据的列转换为`struct`数据类型。此外，我们可以将前述结构展平为单独的列。我们在后面的部分中展示了使用此函数的示例。

有关转换函数的更详细覆盖范围，请参阅[`databricks.com/blog/2017/02/23/working-complex-data-formats-structured-streaming-apache-spark-2-1.html`](https://databricks.com/blog/2017/02/23/working-complex-data-formats-structured-streaming-apache-spark-2-1.html)。

# 解决 ETL 管道中的错误

ETL 任务通常被认为是复杂、昂贵、缓慢和容易出错的。在这里，我们将研究 ETL 过程中的典型挑战，以及 Spark SQL 功能如何帮助解决这些挑战。

Spark 可以自动从 JSON 文件中推断模式。例如，对于以下 JSON 数据，推断的模式包括基于内容的所有标签和数据类型。在这里，输入数据中所有元素的数据类型默认为长整型：

**test1.json**

```scala
{"a":1, "b":2, "c":3}
{"a":2, "d":5, "e":3}
{"d":1, "c":4, "f":6}
{"a":7, "b":8}
{"c":5, "e":4, "d":3}
{"f":3, "e":3, "d":4}
{"a":1, "b":2, "c":3, "f":3, "e":3, "d":4}
```

您可以打印模式以验证数据类型，如下所示：

```scala
scala> spark.read.json("file:///Users/aurobindosarkar/Downloads/test1.json").printSchema()
root
|-- a: long (nullable = true)
|-- b: long (nullable = true)
|-- c: long (nullable = true)
|-- d: long (nullable = true)
|-- e: long (nullable = true)
|-- f: long (nullable = true)
```

然而，在以下 JSON 数据中，如果第三行中的`e`的值和最后一行中的`b`的值被更改以包含分数，并且倒数第二行中的`f`的值被包含在引号中，那么推断的模式将更改`b`和`e`的数据类型为 double，`f`的数据类型为字符串：

```scala
{"a":1, "b":2, "c":3}
{"a":2, "d":5, "e":3}
{"d":1, "c":4, "f":6}
{"a":7, "b":8}
{"c":5, "e":4.5, "d":3}
{"f":"3", "e":3, "d":4}
{"a":1, "b":2.1, "c":3, "f":3, "e":3, "d":4}

scala> spark.read.json("file:///Users/aurobindosarkar/Downloads/test1.json").printSchema()
root
|-- a: long (nullable = true)
|-- b: double (nullable = true)
|-- c: long (nullable = true)
|-- d: long (nullable = true)
|-- e: double (nullable = true)
|-- f: string (nullable = true)
```

如果我们想要将特定结构或数据类型与元素关联起来，我们需要使用用户指定的模式。在下一个示例中，我们使用包含字段名称的标题的 CSV 文件。模式中的字段名称来自标题，并且用户定义的模式中指定的数据类型将用于它们，如下所示：

```scala
a,b,c,d,e,f
1,2,3,,,
2,,,5,3,
,,4,1,,,6
7,8,,,,f
,,5,3,4.5,
,,,4,3,"3"
1,2.1,3,3,3,4

scala> val schema = new StructType().add("a", "int").add("b", "double")

scala> spark.read.option("header", true).schema(schema).csv("file:///Users/aurobindosarkar/Downloads/test1.csv").show()
```

获取以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00327.jpeg)

由于文件和数据损坏，ETL 管道中也可能出现问题。如果数据不是关键任务，并且损坏的文件可以安全地忽略，我们可以设置`config property spark.sql.files.ignoreCorruptFiles = true`。此设置允许 Spark 作业继续运行，即使遇到损坏的文件。请注意，成功读取的内容将继续返回。

在下一个示例中，第 4 行的`b`存在错误数据。我们仍然可以使用`PERMISSIVE`模式读取数据。在这种情况下，DataFrame 中会添加一个名为`_corrupt_record`的新列，并且损坏行的内容将出现在该列中，其余字段初始化为 null。我们可以通过查看该列中的数据来关注数据问题，并采取适当的措施来修复它们。通过设置`spark.sql.columnNameOfCorruptRecord`属性，我们可以配置损坏内容列的默认名称：

```scala
{"a":1, "b":2, "c":3}
{"a":2, "d":5, "e":3}
{"d":1, "c":4, "f":6}
{"a":7, "b":{}
{"c":5, "e":4.5, "d":3}
{"f":"3", "e":3, "d":4}
{"a":1, "b":2.1, "c":3, "f":3, "e":3, "d":4}

scala> spark.read.option("mode", "PERMISSIVE").option("columnNameOfCorruptRecord", "_corrupt_record").json("file:///Users/aurobindosarkar/Downloads/test1.json").show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00328.gif)

现在，我们使用`DROPMALFORMED`选项来删除所有格式不正确的记录。在这里，由于`b`的坏值，第四行被删除：

```scala
scala> spark.read.option("mode", "DROPMALFORMED").json("file:///Users/aurobindosarkar/Downloads/test1.json").show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00329.gif)

对于关键数据，我们可以使用`FAILFAST`选项，在遇到坏记录时立即失败。例如，在以下示例中，由于第四行中`b`的值，操作会抛出异常并立即退出：

```scala
{"a":1, "b":2, "c":3}
{"a":2, "d":5, "e":3}
{"d":1, "c":4, "f":6}
{"a":7, "b":$}
{"c":5, "e":4.5, "d":3}
{"f":"3", "e":3, "d":4}
{"a":1, "b":2.1, "c":3, "f":3, "e":3, "d":4}

scala> spark.read.option("mode", "FAILFAST").json("file:///Users/aurobindosarkar/Downloads/test1.json").show()
```

在下一个示例中，我们有一条跨越两行的记录；我们可以通过将`wholeFile`选项设置为 true 来读取此记录：

```scala
{"a":{"a1":2, "a2":8},
"b":5, "c":3}

scala> spark.read.option("wholeFile",true).option("mode", "PERMISSIVE").option("columnNameOfCorruptRecord", "_corrupt_record").json("file:///Users/aurobindosarkar/Downloads/testMultiLine.json").show()
+-----+---+---+
|    a|  b|  c|
+-----+---+---+
|[2,8]|  5|  3|
+-----+---+---+
```

有关基于 Spark SQL 的 ETL 管道和路线图的更多详细信息，请访问[`spark-summit.org/2017/events/building-robust-etl-pipelines-with-apache-spark/`](https://spark-summit.org/2017/events/building-robust-etl-pipelines-with-apache-spark/)。

上述参考介绍了几个高阶 SQL 转换函数，DataframeWriter API 的新格式以及 Spark 2.2 和 2.3-Snapshot 中的统一`Create Table`（作为`Select`）构造。

Spark SQL 解决的其他要求包括可扩展性和使用结构化流进行持续 ETL。我们可以使用结构化流来使原始数据尽快可用作结构化数据，以进行分析、报告和决策，而不是产生通常与运行周期性批处理作业相关的几小时延迟。这种处理在应用程序中尤为重要，例如异常检测、欺诈检测等，时间至关重要。

在下一节中，我们将把重点转移到使用 Spark SQL 构建可扩展的监控解决方案。

# 实施可扩展的监控解决方案

为大规模部署构建可扩展的监控功能可能具有挑战性，因为每天可能捕获数十亿个数据点。此外，日志的数量和指标的数量可能难以管理，如果没有适当的具有流式处理和可视化支持的大数据平台。

从应用程序、服务器、网络设备等收集的大量日志被处理，以提供实时监控，帮助检测错误、警告、故障和其他问题。通常，各种守护程序、服务和工具用于收集/发送日志记录到监控系统。例如，以 JSON 格式的日志条目可以发送到 Kafka 队列或 Amazon Kinesis。然后，这些 JSON 记录可以存储在 S3 上作为文件和/或流式传输以实时分析（在 Lambda 架构实现中）。通常，会运行 ETL 管道来清理日志数据，将其转换为更结构化的形式，然后加载到 Parquet 文件或数据库中，以进行查询、警报和报告。

下图说明了一个使用**Spark Streaming Jobs**、**可扩展的时间序列数据库**（如 OpenTSDB 或 Graphite）和**可视化工具**（如 Grafana）的平台：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00330.jpeg)

有关此解决方案的更多详细信息，请参阅[`spark-summit.org/2017/events/scalable-monitoring-using-apache-spark-and-friends/`](https://spark-summit.org/2017/events/scalable-monitoring-using-apache-spark-and-friends/)。

在由多个具有不同配置和版本、运行不同类型工作负载的 Spark 集群组成的大型分布式环境中，监控和故障排除问题是具有挑战性的任务。在这些环境中，可能会收到数十万条指标。此外，每秒生成数百 MB 的日志。这些指标需要被跟踪，日志需要被分析以发现异常、故障、错误、环境问题等，以支持警报和故障排除功能。

下图说明了一个基于 AWS 的数据管道，将所有指标和日志（结构化和非结构化）推送到 Kinesis。结构化流作业可以从 Kinesis 读取原始日志，并将数据保存为 S3 上的 Parquet 文件。

结构化流查询可以剥离已知的错误模式，并在观察到新的错误类型时提出适当的警报。其他 Spark 批处理和流处理应用程序可以使用这些 Parquet 文件进行额外处理，并将其结果输出为 S3 上的新 Parquet 文件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00331.jpeg)

在这种架构中，可能需要从非结构化日志中发现问题，以确定其范围、持续时间和影响。**原始日志**通常包含许多近似重复的错误消息。为了有效处理这些日志，我们需要对其进行规范化、去重和过滤已知的错误条件，以发现和揭示新的错误。

有关处理原始日志的管道的详细信息，请参阅[`spark-summit.org/2017/events/lessons-learned-from-managing-thousands-of-production-apache-spark-clusters-daily/`](https://spark-summit.org/2017/events/lessons-learned-from-managing-thousands-of-production-apache-spark-clusters-daily/)。

在本节中，我们将探讨 Spark SQL 和结构化流提供的一些功能，以创建可扩展的监控解决方案。

首先，使用 Kafka 包启动 Spark shell：

```scala
Aurobindos-MacBook-Pro-2:spark-2.2.0-bin-hadoop2.7 aurobindosarkar$ ./bin/spark-shell --packages org.apache.spark:spark-streaming-kafka-0-10_2.11:2.1.1,org.apache.spark:spark-sql-kafka-0-10_2.11:2.1.1 --driver-memory 12g
```

下载 1995 年 7 月的痕迹，其中包含了对佛罗里达州 NASA 肯尼迪航天中心 WWW 服务器的 HTTP 请求[`ita.ee.lbl.gov/html/contrib/NASA-HTTP.html`](http://ita.ee.lbl.gov/html/contrib/NASA-HTTP.html)。

在本章的实践练习中，导入以下包：

```scala
scala> import org.apache.spark.sql.types._
scala> import org.apache.spark.sql.functions._
scala> import spark.implicits._
scala> import org.apache.spark.sql.streaming._
```

接下来，为文件中的记录定义模式：

```scala
scala> val schema = new StructType().add("clientIpAddress", "string").add("rfc1413ClientIdentity", "string").add("remoteUser", "string").add("dateTime", "string").add("zone", "string").add("request","string").add("httpStatusCode", "string").add("bytesSent", "string").add("referer", "string").add("userAgent", "string")
```

为简单起见，我们将输入文件读取为以空格分隔的 CSV 文件，如下所示：

```scala
scala> val rawRecords = spark.readStream.option("header", false).schema(schema).option("sep", " ").format("csv").load("file:///Users/aurobindosarkar/Downloads/NASA")

scala> val ts = unix_timestamp(concat($"dateTime", lit(" "), $"zone"), "[dd/MMM/yyyy:HH:mm:ss Z]").cast("timestamp")
```

接下来，我们创建一个包含日志事件的 DataFrame。由于时间戳在前面的步骤中更改为本地时区（默认情况下），我们还在`original_dateTime`列中保留了带有时区信息的原始时间戳，如下所示：

```scala
scala> val logEvents = rawRecords.withColumn("ts", ts).withColumn("date", ts.cast(DateType)).select($"ts", $"date", $"clientIpAddress", concat($"dateTime", lit(" "), $"zone").as("original_dateTime"), $"request", $"httpStatusCode", $"bytesSent")
```

我们可以检查流式读取的结果，如下所示：

```scala
scala> val query = logEvents.writeStream.outputMode("append").format("console").start()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00332.gif)

我们可以将流输入保存为 Parquet 文件，按日期分区以更有效地支持查询，如下所示：

```scala
scala> val streamingETLQuery = logEvents.writeStream.trigger(Trigger.ProcessingTime("2 minutes")).format("parquet").partitionBy("date").option("path", "file:///Users/aurobindosarkar/Downloads/NASALogs").option("checkpointLocation", "file:///Users/aurobindosarkar/Downloads/NASALogs/checkpoint/").start()
```

我们可以通过指定`latestFirst`选项来读取输入，以便最新的记录首先可用：

```scala
val rawCSV = spark.readStream.schema(schema).option("latestFirst", "true").option("maxFilesPerTrigger", "5").option("header", false).option("sep", " ").format("csv").load("file:///Users/aurobindosarkar/Downloads/NASA")
```

我们还可以按日期将输出以 JSON 格式输出，如下所示：

```scala
val streamingETLQuery = logEvents.writeStream.trigger(Trigger.ProcessingTime("2 minutes")).format("json").partitionBy("date").option("path", "file:///Users/aurobindosarkar/Downloads/NASALogs").option("checkpointLocation", "file:///Users/aurobindosarkar/Downloads/NASALogs/checkpoint/").start()
```

现在，我们展示了在流式 Spark 应用程序中使用 Kafka 进行输入和输出的示例。在这里，我们必须将格式参数指定为`kafka`，并指定 kafka 代理和主题：

```scala
scala> val kafkaQuery = logEvents.selectExpr("CAST(ts AS STRING) AS key", "to_json(struct(*)) AS value").writeStream.format("kafka").option("kafka.bootstrap.servers", "localhost:9092").option("topic", "topica").option("checkpointLocation", "file:///Users/aurobindosarkar/Downloads/NASALogs/kafkacheckpoint/").start()
```

现在，我们正在从 Kafka 中读取 JSON 数据流。将起始偏移设置为最早以指定查询的起始点。这仅适用于启动新的流式查询时：

```scala
scala> val kafkaDF = spark.readStream.format("kafka").option("kafka.bootstrap.servers", "localhost:9092").option("subscribe", "topica").option("startingOffsets", "earliest").load()
```

我们可以按以下方式打印从 Kafka 读取的记录的模式：

```scala
scala> kafkaDF.printSchema()
root
|-- key: binary (nullable = true)
|-- value: binary (nullable = true)
|-- topic: string (nullable = true)
|-- partition: integer (nullable = true)
|-- offset: long (nullable = true)
|-- timestamp: timestamp (nullable = true)
|-- timestampType: integer (nullable = true)
```

接下来，我们定义输入记录的模式，如下所示：

```scala
scala> val kafkaSchema = new StructType().add("ts", "timestamp").add("date", "string").add("clientIpAddress", "string").add("rfc1413ClientIdentity", "string").add("remoteUser", "string").add("original_dateTime", "string").add("request", "string").add("httpStatusCode", "string").add("bytesSent", "string")
```

接下来，我们可以指定模式，如所示。星号`*`运算符用于选择`struct`中的所有`subfields`：

```scala
scala> val kafkaDF1 = kafkaDF.select(col("key").cast("string"), from_json(col("value").cast("string"), kafkaSchema).as("data")).select("data.*")
```

接下来，我们展示选择特定字段的示例。在这里，我们将`outputMode`设置为 append，以便只有追加到结果表的新行被写入外部存储。这仅适用于查询结果表中现有行不会发生变化的情况：

```scala
scala> val kafkaQuery1 = kafkaDF1.select($"ts", $"date", $"clientIpAddress", $"original_dateTime", $"request", $"httpStatusCode", $"bytesSent").writeStream.outputMode("append").format("console").start()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00333.gif)

我们还可以指定`read`（而不是`readStream`）将记录读入常规 DataFrame 中：

```scala
scala> val kafkaDF2 = spark.read.format("kafka").option("kafka.bootstrap.servers","localhost:9092").option("subscribe", "topica").load().selectExpr("CAST(value AS STRING) as myvalue")
```

现在，我们可以对这个 DataFrame 执行所有标准的 DataFrame 操作；例如，我们创建一个表并查询它，如下所示：

```scala
scala> kafkaDF2.registerTempTable("topicData3")

scala> spark.sql("select myvalue from topicData3").take(3).foreach(println)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00334.jpeg)

然后，我们从 Kafka 中读取记录并应用模式：

```scala
scala> val parsed = spark.readStream.format("kafka").option("kafka.bootstrap.servers", "localhost:9092").option("subscribe", "topica").option("startingOffsets", "earliest").load().select(from_json(col("value").cast("string"), kafkaSchema).alias("parsed_value"))
```

我们可以执行以下查询来检查记录的内容：

```scala
scala> val query = parsed.writeStream.outputMode("append").format("console").start()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00335.gif)

我们可以从记录中选择所有字段，如下所示：

```scala
scala> val selectAllParsed = parsed.select("parsed_value.*")
```

我们还可以从 DataFrame 中选择感兴趣的特定字段：

```scala
scala> val selectFieldsParsed = selectAllParsed.select("ts", "clientIpAddress", "request", "httpStatusCode")
```

接下来，我们可以使用窗口操作，并为各种 HTTP 代码维护计数，如所示。在这里，我们将`outputMode`设置为`complete`，因为我们希望将整个更新后的结果表写入外部存储：

```scala
scala> val s1 = selectFieldsParsed.groupBy(window($"ts", "10 minutes", "5 minutes"), $"httpStatusCode").count().writeStream.outputMode("complete").format("console").start()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00336.gif)

接下来，我们展示了另一个使用`groupBy`和计算各窗口中各种页面请求计数的示例。这可用于计算和报告访问类型指标中的热门页面：

```scala
scala> val s2 = selectFieldsParsed.groupBy(window($"ts", "10 minutes", "5 minutes"), $"request").count().writeStream.outputMode("complete").format("console").start()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00337.gif)

请注意，前面提到的示例是有状态处理的实例。计数必须保存为触发器之间的分布式状态。每个触发器读取先前的状态并写入更新后的状态。此状态存储在内存中，并由持久的 WAL 支持，通常位于 HDFS 或 S3 存储上。这使得流式应用程序可以自动处理延迟到达的数据。保留此状态允许延迟数据更新旧窗口的计数。

然而，如果不丢弃旧窗口，状态的大小可能会无限增加。水印方法用于解决此问题。水印是预期数据延迟的移动阈值，以及何时丢弃旧状态。它落后于最大观察到的事件时间。水印之后的数据可能会延迟，但允许进入聚合，而水印之前的数据被认为是“太晚”，并被丢弃。此外，水印之前的窗口会自动删除，以限制系统需要维护的中间状态的数量。

在前一个查询中指定的水印在这里给出：

```scala
scala> val s4 = selectFieldsParsed.withWatermark("ts", "10 minutes").groupBy(window($"ts", "10 minutes", "5 minutes"), $"request").count().writeStream.outputMode("complete").format("console").start()
```

有关水印的更多详细信息，请参阅[`databricks.com/blog/2017/05/08/event-time-aggregation-watermarking-apache-sparks-structured-streaming.html`](https://databricks.com/blog/2017/05/08/event-time-aggregation-watermarking-apache-sparks-structured-streaming.html)。

在下一节中，我们将把重点转移到在生产环境中部署基于 Spark 的机器学习管道。

# 部署 Spark 机器学习管道

下图以概念级别说明了机器学习管道。然而，现实生活中的 ML 管道要复杂得多，有多个模型被训练、调整、组合等：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00338.jpeg)

下图显示了典型机器学习应用程序的核心元素分为两部分：建模，包括模型训练，以及部署的模型（用于流数据以输出结果）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00339.jpeg)

通常，数据科学家在 Python 和/或 R 中进行实验或建模工作。然后在部署到生产环境之前，他们的工作会在 Java/Scala 中重新实现。企业生产环境通常包括 Web 服务器、应用服务器、数据库、中间件等。将原型模型转换为生产就绪模型会导致额外的设计和开发工作，从而导致更新模型的推出延迟。

我们可以使用 Spark MLlib 2.x 模型序列化直接在生产环境中加载数据科学家保存的模型和管道（到磁盘）的模型文件。

在以下示例中（来源：[`spark.apache.org/docs/latest/ml-pipeline.html`](https://spark.apache.org/docs/latest/ml-pipeline.html)），我们将演示在 Python 中创建和保存 ML 管道（使用`pyspark` shell），然后在 Scala 环境中检索它。

启动`pyspark` shell 并执行以下 Python 语句序列：

```scala
>>> from pyspark.ml import Pipeline
>>> from pyspark.ml.classification import LogisticRegression
>>> from pyspark.ml.feature import HashingTF, Tokenizer
>>> training = spark.createDataFrame([
... (0, "a b c d e spark", 1.0),
... (1, "b d", 0.0),
... (2, "spark f g h", 1.0),
... (3, "hadoop mapreduce", 0.0)
... ], ["id", "text", "label"])
>>> tokenizer = Tokenizer(inputCol="text", outputCol="words")
>>> hashingTF = HashingTF(inputCol=tokenizer.getOutputCol(), outputCol="features")
>>> lr = LogisticRegression(maxIter=10, regParam=0.001)
>>> pipeline = Pipeline(stages=[tokenizer, hashingTF, lr])
>>> model = pipeline.fit(training)
>>> model.save("file:///Users/aurobindosarkar/Downloads/spark-logistic-regression-model")
>>> quit()
```

启动 Spark shell 并执行以下 Scala 语句序列：

```scala
scala> import org.apache.spark.ml.{Pipeline, PipelineModel}
scala> import org.apache.spark.ml.classification.LogisticRegression
scala> import org.apache.spark.ml.feature.{HashingTF, Tokenizer}
scala> import org.apache.spark.ml.linalg.Vector
scala> import org.apache.spark.sql.Row

scala> val sameModel = PipelineModel.load("file:///Users/aurobindosarkar/Downloads/spark-logistic-regression-model")
```

接下来，我们创建一个`test`数据集，并通过 ML 管道运行它：

```scala
scala> val test = spark.createDataFrame(Seq(
| (4L, "spark i j k"),
| (5L, "l m n"),
| (6L, "spark hadoop spark"),
| (7L, "apache hadoop")
| )).toDF("id", "text")
```

在`test`数据集上运行模型的结果如下：

```scala
scala> sameModel.transform(test).select("id", "text", "probability", "prediction").collect().foreach { case Row(id: Long, text: String, prob: Vector, prediction: Double) => println(s"($id, $text) --> prob=$prob, prediction=$prediction")}

(4, spark i j k) --> prob=[0.15554371384424398,0.844456286155756], prediction=1.0
(5, l m n) --> prob=[0.8307077352111738,0.16929226478882617], prediction=0.0
(6, spark hadoop spark) --> prob=[0.06962184061952888,0.9303781593804711], prediction=1.0
(7, apache hadoop) --> prob=[0.9815183503510166,0.018481649648983405], prediction=0.0
```

保存的逻辑回归模型的关键参数被读入 DataFrame，如下面的代码块所示。在之前，当模型在`pyspark` shell 中保存时，这些参数被保存到与我们管道的最终阶段相关的子目录中的 Parquet 文件中：

```scala
scala> val df = spark.read.parquet("file:///Users/aurobindosarkar/Downloads/spark-logistic-regression-model/stages/2_LogisticRegression_4abda37bdde1ddf65ea0/data/part-00000-415bf215-207a-4a49-985e-190eaf7253a7-c000.snappy.parquet")

scala> df.show()
```

获得以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00340.jpeg)

```scala
scala> df.collect.foreach(println)
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00341.jpeg)

有关如何将 ML 模型投入生产的更多详细信息，请参阅[`spark-summit.org/2017/events/how-to-productionize-your-machine-learning-models-using-apache-spark-mllib-2x/`](https://spark-summit.org/2017/events/how-to-productionize-your-machine-learning-models-using-apache-spark-mllib-2x/)。

# 了解典型 ML 部署环境中的挑战

ML 模型的生产部署环境可能非常多样化和复杂。例如，模型可能需要部署在 Web 应用程序、门户、实时和批处理系统中，以及作为 API 或 REST 服务，嵌入设备或大型遗留环境中。

此外，企业技术堆栈可以包括 Java 企业、C/C++、遗留主机环境、关系数据库等。与响应时间、吞吐量、可用性和正常运行时间相关的非功能性要求和客户 SLA 也可能差异很大。然而，在几乎所有情况下，我们的部署过程需要支持 A/B 测试、实验、模型性能评估，并且需要灵活和响应业务需求。

通常，从业者使用各种方法来对新模型或更新模型进行基准测试和逐步推出，以避免高风险、大规模的生产部署。

在下一节中，我们将探讨一些模型部署架构。

# 了解模型评分架构的类型

最简单的模型是使用 Spark（批处理）预计算模型结果，将结果保存到数据库，然后从数据库为 Web 和移动应用程序提供结果。许多大规模的推荐引擎和搜索引擎使用这种架构：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00342.jpeg)

第二种模型评分架构使用 Spark Streaming 计算特征并运行预测算法。预测结果可以使用缓存解决方案（如 Redis）进行缓存，并可以通过 API 提供。其他应用程序可以使用这些 API 从部署的模型中获取预测结果。此选项在此图中有所说明：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00343.jpeg)

在第三种架构模型中，我们可以仅使用 Spark 进行模型训练。然后将模型复制到生产环境中。例如，我们可以从 JSON 文件中加载逻辑回归模型的系数和截距。这种方法资源高效，并且会产生高性能的系统。在现有或复杂环境中部署也更加容易。

如图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00344.jpeg)

继续我们之前的例子，我们可以从 Parquet 文件中读取保存的模型参数，并将其转换为 JSON 格式，然后可以方便地导入到任何应用程序（在 Spark 环境内部或外部）并应用于新数据：

```scala
scala> spark.read.parquet("file:///Users/aurobindosarkar/Downloads/spark-logistic-regression-model/stages/2_LogisticRegression_4abda37bdde1ddf65ea0/data/part-00000-415bf215-207a-4a49-985e-190eaf7253a7-c000.snappy.parquet").write.mode("overwrite").json("file:///Users/aurobindosarkar/Downloads/lr-model-json")
```

我们可以使用标准操作系统命令显示截距、系数和其他关键参数，如下所示：

```scala
Aurobindos-MacBook-Pro-2:lr-model-json aurobindosarkar$ more part-00000-e2b14eb8-724d-4262-8ea5-7c23f846fed0-c000.json
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00345.jpeg)

随着模型变得越来越大和复杂，部署和提供服务可能会变得具有挑战性。模型可能无法很好地扩展，其资源需求可能变得非常昂贵。Databricks 和 Redis-ML 提供了部署训练模型的解决方案。

在 Redis-ML 解决方案中，模型直接应用于 Redis 环境中的新数据。

这可以以比在 Spark 环境中运行模型的价格更低的价格提供所需的整体性能、可伸缩性和可用性。

下图显示了 Redis-ML 作为服务引擎的使用情况（实现了先前描述的第三种模型评分架构模式）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00346.jpeg)

在下一节中，我们将简要讨论在生产环境中使用 Mesos 和 Kubernetes 作为集群管理器。

# 使用集群管理器

在本节中，我们将在概念层面简要讨论 Mesos 和 Kubernetes。Spark 框架可以通过 Apache Mesos、YARN、Spark Standalone 或 Kubernetes 集群管理器进行部署，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00347.jpeg)

Mesos 可以实现数据的轻松扩展和复制，并且是异构工作负载的良好统一集群管理解决方案。

要从 Spark 使用 Mesos，Spark 二进制文件应该可以被 Mesos 访问，并且 Spark 驱动程序配置为连接到 Mesos。或者，您也可以在所有 Mesos 从属节点上安装 Spark 二进制文件。驱动程序创建作业，然后发出任务进行调度，而 Mesos 确定处理它们的机器。

Spark 可以在 Mesos 上以两种模式运行：粗粒度（默认）和细粒度（在 Spark 2.0.0 中已弃用）。在粗粒度模式下，每个 Spark 执行器都作为单个 Mesos 任务运行。这种模式具有显着较低的启动开销，但会为应用程序的持续时间保留 Mesos 资源。Mesos 还支持根据应用程序的统计数据调整执行器数量的动态分配。

下图说明了将 Mesos Master 和 Zookeeper 节点放置在一起的部署。Mesos Slave 和 Cassandra 节点也放置在一起，以获得更好的数据局部性。此外，Spark 二进制文件部署在所有工作节点上：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00348.jpeg)

另一个新兴的 Spark 集群管理解决方案是 Kubernetes，它正在作为 Spark 的本机集群管理器进行开发。它是一个开源系统，可用于自动化容器化 Spark 应用程序的部署、扩展和管理。

下图描述了 Kubernetes 的高层视图。每个节点都包含一个名为 Kublet 的守护程序，它与 Master 节点通信。用户还可以与 Master 节点通信，以声明性地指定他们想要运行的内容。例如，用户可以请求运行特定数量的 Web 服务器实例。Master 将接受用户的请求并在节点上安排工作负载：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00349.jpeg)

节点运行一个或多个 pod。Pod 是容器的更高级抽象，每个 pod 可以包含一组共同放置的容器。每个 pod 都有自己的 IP 地址，并且可以与其他节点中的 pod 进行通信。存储卷可以是本地的或网络附加的。这可以在下图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00350.jpeg)

Kubernetes 促进不同类型的 Spark 工作负载之间的资源共享，以减少运营成本并提高基础设施利用率。此外，可以使用几个附加服务与 Spark 应用程序一起使用，包括日志记录、监视、安全性、容器间通信等。

有关在 Kubernetes 上使用 Spark 的更多详细信息，请访问[`github.com/apache-spark-on-k8s/spark`](https://github.com/apache-spark-on-k8s/spark)。

在下图中，虚线将 Kubernetes 与 Spark 分隔开。Spark Core 负责获取新的执行器、推送新的配置、移除执行器等。**Kubernetes 调度器后端**接受 Spark Core 的请求，并将其转换为 Kubernetes 可以理解的原语。此外，它处理所有资源请求和与 Kubernetes 的所有通信。

其他服务，如文件暂存服务器，可以使您的本地文件和 JAR 文件可用于 Spark 集群，Spark 洗牌服务可以存储动态分配资源的洗牌数据；例如，它可以实现弹性地改变特定阶段的执行器数量。您还可以扩展 Kubernetes API 以包括自定义或特定于应用程序的资源；例如，您可以创建仪表板来显示作业的进度。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-spark-sql/img/00351.jpeg)

Kubernetes 还提供了一些有用的管理功能，以帮助管理集群，例如 RBAC 和命名空间级别的资源配额、审计日志记录、监视节点、pod、集群级别的指标等。

# 总结

在本章中，我们介绍了几种基于 Spark SQL 的应用程序架构，用于构建高度可扩展的应用程序。我们探讨了批处理和流处理中的主要概念和挑战。我们讨论了 Spark SQL 的特性，可以帮助构建强大的 ETL 流水线。我们还介绍了一些构建可扩展监控应用程序的代码。此外，我们探讨了一种用于机器学习流水线的高效部署技术，以及使用 Mesos 和 Kubernetes 等集群管理器的一些基本概念。

总之，本书试图帮助您在 Spark SQL 和 Scala 方面建立坚实的基础。然而，仍然有许多领域可以深入探索，以建立更深入的专业知识。根据您的特定领域，数据的性质和问题可能差异很大，您解决问题的方法通常会涵盖本书中描述的一个或多个领域。然而，在所有情况下，都需要 EDA 和数据整理技能，而您练习得越多，就会变得越熟练。尝试下载并处理不同类型的数据，包括结构化、半结构化和非结构化数据。此外，阅读各章节中提到的参考资料，以深入了解其他数据科学从业者如何解决问题。参考 Apache Spark 网站获取软件的最新版本，并探索您可以在 ML 流水线中使用的其他机器学习算法。最后，诸如深度学习和基于成本的优化等主题在 Spark 中仍在不断发展，尝试跟上这些领域的发展，因为它们将是解决未来许多有趣问题的关键。
