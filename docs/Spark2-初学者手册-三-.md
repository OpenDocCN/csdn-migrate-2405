# Spark2 初学者手册（三）

> 原文：[`zh.annas-archive.org/md5/4803F9F0B1A27EADC7FE0DFBB64A3594`](https://zh.annas-archive.org/md5/4803F9F0B1A27EADC7FE0DFBB64A3594)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Spark 机器学习

自古以来，基于公式或算法的计算就被广泛用于根据给定输入求得输出。然而，在不了解这些公式或算法的情况下，计算机科学家和数学家设计了方法，通过现有的输入/输出数据集来生成公式或算法，并基于这些生成的公式或算法预测新输入数据的输出。通常，这种从数据集中学习并基于学习进行预测的过程被称为机器学习。机器学习起源于计算机科学中的人工智能研究。

实际的机器学习有众多应用，这些应用正被普通民众日常消费。YouTube 用户现在根据他们当前观看的视频获得播放列表中下一个项目的推荐。流行的电影评级网站根据用户对电影类型的偏好给出评级和推荐。社交媒体网站如 Facebook 会提供用户好友的名单，以便于图片标记。Facebook 在这里所做的是通过现有相册中已有的名称对图片进行分类，并检查新添加的图片是否与现有图片有任何相似之处。如果发现相似之处，它会推荐该名称。这种图片识别的应用是多方面的。所有这些应用的工作方式都是基于已经收集的大量输入/输出数据集以及基于这些数据集所进行的学习。当一个新的输入数据集到来时，通过利用计算机或机器已经完成的学习来进行预测。

本章我们将涵盖以下主题：

+   使用 Spark 进行机器学习

+   模型持久化

+   垃圾邮件过滤

+   特征算法

+   寻找同义词

# 理解机器学习

在传统计算中，输入数据被输入程序以生成输出。但在机器学习中，输入数据和输出数据被输入机器学习算法，以生成一个函数或程序，该函数或程序可以根据输入/输出数据集对机器学习算法的学习来预测输入的输出。

野外可用的数据可能被分类成组，可能形成集群，或者可能符合某些关系。这些都是不同类型的机器学习问题。例如，如果有一个二手汽车销售价格及其相关属性或特征的数据库，只需了解相关属性或特征，就有可能预测汽车的价格。回归算法用于解决这类问题。如果有一个垃圾邮件和非垃圾邮件的电子邮件数据库，那么当一封新电子邮件到来时，就有可能预测该新电子邮件是垃圾邮件还是非垃圾邮件。分类算法用于解决这类问题。

这些只是机器学习算法的几种类型。但一般来说，在使用数据集时，如果需要应用机器学习算法并使用该模型进行预测，则应将数据分为特征和输出。例如，在汽车价格预测问题中，价格是输出，以下是数据可能的一些特征：

+   汽车品牌

+   汽车型号

+   生产年份

+   里程

+   燃料类型

+   变速箱类型

因此，无论使用哪种机器学习算法，都会有一组特征和一个或多个输出。

### 注意

许多书籍和出版物使用*标签*一词来指代输出。换句话说，*特征*是输入，而*标签*是输出。

*图 1*展示了机器学习算法如何处理底层数据以实现预测。

![理解机器学习](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_07_001.jpg)

图 1

数据以各种形式呈现。根据所使用的机器学习算法，训练数据必须经过预处理，以确保特征和标签以正确的格式输入到机器学习算法中。这反过来又生成了适当的假设函数，该函数以特征作为输入并产生预测标签。

### 提示

假设一词的词典定义是一种基于有限证据的假设或提议解释，作为进一步调查的起点。在这里，由机器学习算法生成的函数或程序基于有限的证据，即输入到机器学习算法的训练数据，因此它被广泛称为假设函数。

换句话说，这个假设函数并不是一个能始终对所有类型的输入数据产生一致结果的确定性函数。它更多是基于训练数据的函数。当新的数据添加到训练数据集中时，需要重新学习，届时生成的假设函数也会相应改变。

实际上，*图 1*所示流程并不像看起来那么简单。模型训练完成后，需要对模型进行大量测试，以使用已知标签测试预测。训练和测试过程的链条是一个迭代过程，每次迭代都会调整算法的参数以提高预测质量。一旦模型产生了可接受的测试结果，就可以将其部署到生产环境中以满足实时预测需求。Spark 自带的机器学习库功能丰富，使得实际应用机器学习成为可能。

# 为什么选择 Spark 进行机器学习？

前几章详细介绍了 Spark 的各种数据处理功能。Spark 的机器学习库不仅使用了 Spark 核心的许多功能，还使用了 Spark SQL 等 Spark 库。Spark 机器学习库通过在统一的框架中结合数据处理和机器学习算法实现，使得机器学习应用开发变得简单，该框架能够在集群节点上进行数据处理，并能够读写各种数据格式。

Spark 提供了两种机器学习库：`spark.mllib`和`spark.ml`。前者基于 Spark 的 RDD 抽象开发，后者基于 Spark 的 DataFrame 抽象开发。建议在未来的机器学习应用开发中使用 spark.ml 库。

本章将专注于 spark.ml 机器学习库。以下列表解释了本章中反复使用的术语和概念：

+   **估计器**：这是一种算法，它作用于包含特征和标签的 Spark DataFrame 之上。它对 Spark DataFrame 中提供的数据进行训练，并创建一个模型。该模型用于未来的预测。

+   **转换器**：它将包含特征的 Spark DataFrame 转换为包含预测的另一个 Spark DataFrame。由 Estimator 创建的模型就是一个 Transformer。

+   **参数**：这是供 Estimators 和 Transformers 使用的。通常，它特定于机器学习算法。Spark 机器学习库提供了一个统一的 API，用于为算法指定正确的参数。

+   **流水线**：这是一系列 Estimators 和 Transformers 协同工作，形成机器学习工作流程。

从理论角度看，这些新术语略显晦涩，但若辅以实例，概念便会清晰许多。

# 葡萄酒质量预测

加州大学欧文分校机器学习资料库（[`archive.ics.uci.edu/ml/index.html`](http://archive.ics.uci.edu/ml/index.html)）为对机器学习感兴趣的人提供了大量数据集。葡萄酒质量数据集（[`archive.ics.uci.edu/ml/datasets/Wine+Quality`](http://archive.ics.uci.edu/ml/datasets/Wine+Quality)）在此用于展示一些机器学习应用。它包含两个数据集，分别描述了葡萄牙白葡萄酒和红葡萄酒的各种特征。

### 注意

葡萄酒质量数据集下载链接允许您下载红葡萄酒和白葡萄酒的两个单独 CSV 文件。下载这些文件后，编辑两个数据集以删除包含列名的第一行标题。这是为了让程序无误地解析数值数据。为了专注于机器学习功能，故意避免了详细的错误处理和排除标题记录。

本案例中用于葡萄酒质量预测的数据集包含了红葡萄酒的各种特征。以下是数据集的特征：

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

基于这些特征，确定质量（分数介于 0 和 10 之间）。在这里，质量是此数据集的标签。使用此数据集，将训练一个模型，然后使用训练好的模型进行测试并做出预测。这是一个回归问题。使用线性回归算法来训练模型。线性回归算法生成一个线性假设函数。在数学术语中，线性函数是一次或更低次的多项式。在这个机器学习应用案例中，它涉及建模因变量（葡萄酒质量）和一组自变量（葡萄酒的特征）之间的关系。

在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> import org.apache.spark.ml.regression.LinearRegression
      import org.apache.spark.ml.regression.LinearRegression

	scala> import org.apache.spark.ml.param.ParamMap

      import org.apache.spark.ml.param.ParamMap

	scala> import org.apache.spark.ml.linalg.{Vector, Vectors}

      import org.apache.spark.ml.linalg.{Vector, Vectors}

	scala> import org.apache.spark.sql.Row

      import org.apache.spark.sql.Row

	scala> // TODO - Change this directory to the right location where the data
    is stored
	scala> val dataDir = "/Users/RajT/Downloads/wine-quality/"

      dataDir: String = /Users/RajT/Downloads/wine-quality/

	scala> // Define the case class that holds the wine data
	scala> case class Wine(FixedAcidity: Double, VolatileAcidity: Double, CitricAcid: Double, ResidualSugar: Double, Chlorides: Double, FreeSulfurDioxide: Double, TotalSulfurDioxide: Double, Density: Double, PH: Double, Sulphates: Double, Alcohol: Double, Quality: Double)

      defined class Wine

	scala> // Create the the RDD by reading the wine data from the disk 
	scala> //TODO - The wine data has to be downloaded to the appropriate working directory in the system where this is being run and the following line of code should use that path
	scala> val wineDataRDD = sc.textFile(dataDir + "winequality-red.csv").map(_.split(";")).map(w => Wine(w(0).toDouble, w(1).toDouble, w(2).toDouble, w(3).toDouble, w(4).toDouble, w(5).toDouble, w(6).toDouble, w(7).toDouble, w(8).toDouble, w(9).toDouble, w(10).toDouble, w(11).toDouble))

      wineDataRDD: org.apache.spark.rdd.RDD[Wine] = MapPartitionsRDD[3] at map at <console>:32

	scala> // Create the data frame containing the training data having two columns. 1) The actual output or label of the data 2) The vector containing the features
	scala> //Vector is a data type with 0 based indices and double-typed values. In that there are two types namely dense and sparse.
	scala> //A dense vector is backed by a double array representing its entry values 
	scala> //A sparse vector is backed by two parallel arrays: indices and values
	scala> val trainingDF = wineDataRDD.map(w => (w.Quality, Vectors.dense(w.FixedAcidity, w.VolatileAcidity, w.CitricAcid, w.ResidualSugar, w.Chlorides, w.FreeSulfurDioxide, w.TotalSulfurDioxide, w.Density, w.PH, w.Sulphates, w.Alcohol))).toDF("label", "features")

      trainingDF: org.apache.spark.sql.DataFrame = [label: double, features: vector]
    scala> trainingDF.show()

      +-----+--------------------+

      |label|            features|

      +-----+--------------------+

      |  5.0|[7.4,0.7,0.0,1.9,...|

      |  5.0|[7.8,0.88,0.0,2.6...|

      |  5.0|[7.8,0.76,0.04,2....|

      |  6.0|[11.2,0.28,0.56,1...|

      |  5.0|[7.4,0.7,0.0,1.9,...|

      |  5.0|[7.4,0.66,0.0,1.8...|

      |  5.0|[7.9,0.6,0.06,1.6...|

      |  7.0|[7.3,0.65,0.0,1.2...|

      |  7.0|[7.8,0.58,0.02,2....|

      |  5.0|[7.5,0.5,0.36,6.1...|

      |  5.0|[6.7,0.58,0.08,1....|

      |  5.0|[7.5,0.5,0.36,6.1...|

      |  5.0|[5.6,0.615,0.0,1....|

      |  5.0|[7.8,0.61,0.29,1....|

      |  5.0|[8.9,0.62,0.18,3....|

      |  5.0|[8.9,0.62,0.19,3....|

      |  7.0|[8.5,0.28,0.56,1....|

      |  5.0|[8.1,0.56,0.28,1....|

      |  4.0|[7.4,0.59,0.08,4....|

      |  6.0|[7.9,0.32,0.51,1....|

      +-----+--------------------+

      only showing top 20 rows
    scala> // Create the object of the algorithm which is the Linear Regression
	scala> val lr = new LinearRegression()
      lr: org.apache.spark.ml.regression.LinearRegression = linReg_f810f0c1617b
    scala> // Linear regression parameter to make lr.fit() use at most 10 iterations
	scala> lr.setMaxIter(10)
      res1: lr.type = linReg_f810f0c1617b
    scala> // Create a trained model by fitting the parameters using the training data
	scala> val model = lr.fit(trainingDF)
      model: org.apache.spark.ml.regression.LinearRegressionModel = linReg_f810f0c1617b
    scala> // Once the model is prepared, to test the model, prepare the test data containing the labels and feature vectors
	scala> val testDF = spark.createDataFrame(Seq((5.0, Vectors.dense(7.4, 0.7, 0.0, 1.9, 0.076, 25.0, 67.0, 0.9968, 3.2, 0.68,9.8)),(5.0, Vectors.dense(7.8, 0.88, 0.0, 2.6, 0.098, 11.0, 34.0, 0.9978, 3.51, 0.56, 9.4)),(7.0, Vectors.dense(7.3, 0.65, 0.0, 1.2, 0.065, 15.0, 18.0, 0.9968, 3.36, 0.57, 9.5)))).toDF("label", "features")
      testDF: org.apache.spark.sql.DataFrame = [label: double, features: vector]
    scala> testDF.show()
      +-----+--------------------+

      |label|            features|

      +-----+--------------------+

      |  5.0|[7.4,0.7,0.0,1.9,...|

      |  5.0|[7.8,0.88,0.0,2.6...|

      |  7.0|[7.3,0.65,0.0,1.2...|

      +-----+--------------------+
    scala> testDF.createOrReplaceTempView("test")scala> // Do the transformation of the test data using the model and predict the output values or lables. This is to compare the predicted value and the actual label value
	scala> val tested = model.transform(testDF).select("features", "label", "prediction")
      tested: org.apache.spark.sql.DataFrame = [features: vector, label: double ... 1 more field]
    scala> tested.show()
      +--------------------+-----+-----------------+

      |            features|label|       prediction|

      +--------------------+-----+-----------------+

      |[7.4,0.7,0.0,1.9,...|  5.0|5.352730835898477|

      |[7.8,0.88,0.0,2.6...|  5.0|4.817999362011964|

      |[7.3,0.65,0.0,1.2...|  7.0|5.280106355653388|

      +--------------------+-----+-----------------+
    scala> // Prepare a dataset without the output/lables to predict the output using the trained model
	scala> val predictDF = spark.sql("SELECT features FROM test")predictDF: org.apache.spark.sql.DataFrame = [features: vector]
	scala> predictDF.show()
      +--------------------+

      |            features|

      +--------------------+

      |[7.4,0.7,0.0,1.9,...|

      |[7.8,0.88,0.0,2.6...|

      |[7.3,0.65,0.0,1.2...|

      +--------------------+
    scala> // Do the transformation with the predict dataset and display the predictions
	scala> val predicted = model.transform(predictDF).select("features", "prediction")
      predicted: org.apache.spark.sql.DataFrame = [features: vector, prediction: double]
    scala> predicted.show()
      +--------------------+-----------------+

      |            features|       prediction|

      +--------------------+-----------------+

      |7.4,0.7,0.0,1.9,...|5.352730835898477|

      |[7.8,0.88,0.0,2.6...|4.817999362011964|

      |[7.3,0.65,0.0,1.2...|5.280106355653388|

      +--------------------+-----------------+
    scala> //IMPORTANT - To continue with the model persistence coming in the next section, keep this session on.

```

上述代码做了很多事情。它在管道中执行以下一系列活动：

1.  它从数据文件读取葡萄酒数据以形成训练 DataFrame。

1.  然后创建一个`LinearRegression`对象并设置参数。

1.  它使用训练数据拟合模型，从而完成了估计器管道。

1.  它创建了一个包含测试数据的 DataFrame。通常，测试数据将同时包含特征和标签。这是为了确保模型的正确性，并用于比较预测标签和实际标签。

1.  使用创建的模型，它对测试数据进行转换，并从生成的 DataFrame 中提取特征、输入标签和预测结果。注意，在使用模型进行转换时，不需要标签。换句话说，标签将完全不被使用。

1.  使用创建的模型，它对预测数据进行转换，并从生成的 DataFrame 中提取特征和预测结果。注意，在使用模型进行转换时，不使用标签。换句话说，在进行预测时，不使用标签。这完成了转换器管道。

### 提示

上述代码片段中的管道是单阶段管道，因此无需使用 Pipeline 对象。多阶段管道将在后续部分讨论。

在实际应用中，拟合/测试阶段会迭代重复，直到模型在进行预测时给出期望的结果。图 2 通过代码阐明了演示的管道概念：

![葡萄酒质量预测

图 2

以下代码使用 Python 演示了相同的用例。在 Python REPL 提示符下，尝试以下语句：

```scala
 >>> from pyspark.ml.linalg import Vectors
	>>> from pyspark.ml.regression import LinearRegression
	>>> from pyspark.ml.param import Param, Params
	>>> from pyspark.sql import Row
	>>> # TODO - Change this directory to the right location where the data is stored
	>>> dataDir = "/Users/RajT/Downloads/wine-quality/"
	>>> # Create the the RDD by reading the wine data from the disk 
	>>> lines = sc.textFile(dataDir + "winequality-red.csv")
	>>> splitLines = lines.map(lambda l: l.split(";"))
	>>> # Vector is a data type with 0 based indices and double-typed values. In that there are two types namely dense and sparse.
	>>> # A dense vector is backed by a double array representing its entry values
	>>> # A sparse vector is backed by two parallel arrays: indices and values
	>>> wineDataRDD = splitLines.map(lambda p: (float(p[11]), Vectors.dense([float(p[0]), float(p[1]), float(p[2]), float(p[3]), float(p[4]), float(p[5]), float(p[6]), float(p[7]), float(p[8]), float(p[9]), float(p[10])])))
	>>> # Create the data frame containing the training data having two columns. 1) The actula output or label of the data 2) The vector containing the features
	>>> trainingDF = spark.createDataFrame(wineDataRDD, ['label', 'features'])
	>>> trainingDF.show()

      +-----+--------------------+

      |label|            features|

      +-----+--------------------+

      |  5.0|[7.4,0.7,0.0,1.9,...|

      |  5.0|[7.8,0.88,0.0,2.6...|

      |  5.0|[7.8,0.76,0.04,2....|

      |  6.0|[11.2,0.28,0.56,1...|

      |  5.0|[7.4,0.7,0.0,1.9,...|

      |  5.0|[7.4,0.66,0.0,1.8...|

      |  5.0|[7.9,0.6,0.06,1.6...|

      |  7.0|[7.3,0.65,0.0,1.2...|

      |  7.0|[7.8,0.58,0.02,2....|

      |  5.0|[7.5,0.5,0.36,6.1...|

      |  5.0|[6.7,0.58,0.08,1....|

      |  5.0|[7.5,0.5,0.36,6.1...|

      |  5.0|[5.6,0.615,0.0,1....|

      |  5.0|[7.8,0.61,0.29,1....|

      |  5.0|[8.9,0.62,0.18,3....|

      |  5.0|[8.9,0.62,0.19,3....|

      |  7.0|[8.5,0.28,0.56,1....|

      |  5.0|[8.1,0.56,0.28,1....|

      |  4.0|[7.4,0.59,0.08,4....|

      |  6.0|[7.9,0.32,0.51,1....|

      +-----+--------------------+

      only showing top 20 rows

	>>> # Create the object of the algorithm which is the Linear Regression with the parameters
	>>> # Linear regression parameter to make lr.fit() use at most 10 iterations
	>>> lr = LinearRegression(maxIter=10)
	>>> # Create a trained model by fitting the parameters using the training data
	>>> model = lr.fit(trainingDF)
	>>> # Once the model is prepared, to test the model, prepare the test data containing the labels and feature vectors 
	>>> testDF = spark.createDataFrame([(5.0, Vectors.dense([7.4, 0.7, 0.0, 1.9, 0.076, 25.0, 67.0, 0.9968, 3.2, 0.68,9.8])),(5.0,Vectors.dense([7.8, 0.88, 0.0, 2.6, 0.098, 11.0, 34.0, 0.9978, 3.51, 0.56, 9.4])),(7.0, Vectors.dense([7.3, 0.65, 0.0, 1.2, 0.065, 15.0, 18.0, 0.9968, 3.36, 0.57, 9.5]))], ["label", "features"])
	>>> testDF.createOrReplaceTempView("test")
	>>> testDF.show()

      +-----+--------------------+

      |label|            features|

      +-----+--------------------+

      |  5.0|[7.4,0.7,0.0,1.9,...|

      |  5.0|[7.8,0.88,0.0,2.6...|

      |  7.0|[7.3,0.65,0.0,1.2...|

      +-----+--------------------+
    >>> # Do the transformation of the test data using the model and predict the output values or lables. This is to compare the predicted value and the actual label value
	>>> testTransform = model.transform(testDF)
	>>> tested = testTransform.select("features", "label", "prediction")
	>>> tested.show()

      +--------------------+-----+-----------------+

      |            features|label|       prediction|

      +--------------------+-----+-----------------+

      |[7.4,0.7,0.0,1.9,...|  5.0|5.352730835898477|

      |[7.8,0.88,0.0,2.6...|  5.0|4.817999362011964|

      |[7.3,0.65,0.0,1.2...|  7.0|5.280106355653388|

      +--------------------+-----+-----------------+

	>>> # Prepare a dataset without the output/lables to predict the output using the trained model
	>>> predictDF = spark.sql("SELECT features FROM test")
	>>> predictDF.show()

      +--------------------+

      |            features|

      +--------------------+

      |[7.4,0.7,0.0,1.9,...|

      |[7.8,0.88,0.0,2.6...|

      |[7.3,0.65,0.0,1.2...|

      +--------------------+

	>>> # Do the transformation with the predict dataset and display the predictions
	>>> predictTransform = model.transform(predictDF)
	>>> predicted = predictTransform.select("features", "prediction")
	>>> predicted.show()

      +--------------------+-----------------+

      |            features|       prediction|

      +--------------------+-----------------+

      |[7.4,0.7,0.0,1.9,...|5.352730835898477|

      |[7.8,0.88,0.0,2.6...|4.817999362011964|

      |[7.3,0.65,0.0,1.2...|5.280106355653388|

      +--------------------+-----------------+

	>>> #IMPORTANT - To continue with the model persistence coming in the next section, keep this session on.

```

如前所述，线性回归是一种统计模型，用于模拟两种变量之间的关系。一种是自变量，另一种是因变量。因变量由自变量计算得出。在许多情况下，如果只有一个自变量，那么回归将是简单线性回归。但在现实世界的实际应用中，通常会有多个自变量，正如葡萄酒数据集所示。这属于多元线性回归的情况。不应将其与多元线性回归混淆。在多元回归中，预测的是多个且相关的因变量。

在讨论的用例中，预测仅针对一个变量，即葡萄酒的质量，因此这是一个多元线性回归问题，而不是多元线性回归问题。一些学校甚至将多元线性回归称为单变量线性回归。换句话说，无论自变量的数量如何，如果只有一个因变量，则称为单变量线性回归。

# 模型持久性

Spark 2.0 具有跨编程语言轻松保存和加载机器学习模型的能力。换句话说，您可以在 Scala 中创建一个机器学习模型，并在 Python 中加载它。这使我们能够在一个系统中创建模型，保存它，复制它，并在其他系统中使用它。继续使用相同的 Scala REPL 提示符，尝试以下语句：

```scala
 scala> // Assuming that the model definition line "val model = 
    lr.fit(trainingDF)" is still in context
	scala> import org.apache.spark.ml.regression.LinearRegressionModel

      import org.apache.spark.ml.regression.LinearRegressionModel

	scala> model.save("wineLRModelPath")
	scala> val newModel = LinearRegressionModel.load("wineLRModelPath")

      newModel: org.apache.spark.ml.regression.LinearRegressionModel = 
      linReg_6a880215ab96 

```

现在加载的模型可以用于测试或预测，就像原始模型一样。继续使用相同的 Python REPL 提示符，尝试以下语句以加载使用 Scala 程序保存的模型：

```scala
 >>> from pyspark.ml.regression import LinearRegressionModel
	>>> newModel = LinearRegressionModel.load("wineLRModelPath")
	>>> newPredictTransform = newModel.transform(predictDF) 
	>>> newPredicted = newPredictTransform.select("features", "prediction")
	>>> newPredicted.show()

      +--------------------+-----------------+

      |            features|       prediction|

      +--------------------+-----------------+

      |[7.4,0.7,0.0,1.9,...|5.352730835898477|

      |[7.8,0.88,0.0,2.6...|4.817999362011964|

      |[7.3,0.65,0.0,1.2...|5.280106355653388|

      +--------------------+-----------------+ 

```

# 葡萄酒分类

在此葡萄酒质量分类用例中，使用了包含白葡萄酒各种特征的数据集。以下是数据集的特征：

+   固定酸度

+   挥发性酸度

+   柠檬酸

+   残糖

+   氯化物

+   游离二氧化硫

+   总二氧化硫

+   密度

+   pH 值

+   硫酸盐

+   酒精

基于这些特征，确定质量（分数介于 0 和 10 之间）。如果质量低于 7，则将其归类为差，并将标签赋值为 0。如果质量为 7 或以上，则将其归类为好，并将标签赋值为 1。换句话说，分类值是此数据集的标签。使用此数据集，将训练一个模型，然后使用训练好的模型进行测试并做出预测。这是一个分类问题。使用逻辑回归算法来训练模型。在这个机器学习应用案例中，它涉及建模因变量（葡萄酒质量）与一组自变量（葡萄酒的特征）之间的关系。在 Scala REPL 提示符下，尝试以下语句：

```scala
	 scala> import org.apache.spark.ml.classification.LogisticRegression

      import org.apache.spark.ml.classification.LogisticRegression

	scala> import org.apache.spark.ml.param.ParamMap

      import org.apache.spark.ml.param.ParamMap

	scala> import org.apache.spark.ml.linalg.{Vector, Vectors}

      import org.apache.spark.ml.linalg.{Vector, Vectors}
    scala> import org.apache.spark.sql.Row

      import org.apache.spark.sql.Row

	scala> // TODO - Change this directory to the right location where the data is stored
	scala> val dataDir = "/Users/RajT/Downloads/wine-quality/"

      dataDir: String = /Users/RajT/Downloads/wine-quality/

	scala> // Define the case class that holds the wine data
	scala> case class Wine(FixedAcidity: Double, VolatileAcidity: Double, CitricAcid: Double, ResidualSugar: Double, Chlorides: Double, FreeSulfurDioxide: Double, TotalSulfurDioxide: Double, Density: Double, PH: Double, Sulphates: Double, Alcohol: Double, Quality: Double)

      defined class Wine

	scala> // Create the the RDD by reading the wine data from the disk 
	scala> val wineDataRDD = sc.textFile(dataDir + "winequality-white.csv").map(_.split(";")).map(w => Wine(w(0).toDouble, w(1).toDouble, w(2).toDouble, w(3).toDouble, w(4).toDouble, w(5).toDouble, w(6).toDouble, w(7).toDouble, w(8).toDouble, w(9).toDouble, w(10).toDouble, w(11).toDouble))

      wineDataRDD: org.apache.spark.rdd.RDD[Wine] = MapPartitionsRDD[35] at map at <console>:36

	scala> // Create the data frame containing the training data having two columns. 1) The actula output or label of the data 2) The vector containing the features
	scala> val trainingDF = wineDataRDD.map(w => (if(w.Quality < 7) 0D else 1D, Vectors.dense(w.FixedAcidity, w.VolatileAcidity, w.CitricAcid, w.ResidualSugar, w.Chlorides, w.FreeSulfurDioxide, w.TotalSulfurDioxide, w.Density, w.PH, w.Sulphates, w.Alcohol))).toDF("label", "features")

      trainingDF: org.apache.spark.sql.DataFrame = [label: double, features: vector]

	scala> trainingDF.show()

      +-----+--------------------+

      |label|            features|

      +-----+--------------------+

      |  0.0|[7.0,0.27,0.36,20...|

      |  0.0|[6.3,0.3,0.34,1.6...|

      |  0.0|[8.1,0.28,0.4,6.9...|

      |  0.0|[7.2,0.23,0.32,8....|

      |  0.0|[7.2,0.23,0.32,8....|

      |  0.0|[8.1,0.28,0.4,6.9...|

      |  0.0|[6.2,0.32,0.16,7....|

      |  0.0|[7.0,0.27,0.36,20...|

      |  0.0|[6.3,0.3,0.34,1.6...|

      |  0.0|[8.1,0.22,0.43,1....|

      |  0.0|[8.1,0.27,0.41,1....|

      |  0.0|[8.6,0.23,0.4,4.2...|

      |  0.0|[7.9,0.18,0.37,1....|

      |  1.0|[6.6,0.16,0.4,1.5...|

      |  0.0|[8.3,0.42,0.62,19...|

      |  1.0|[6.6,0.17,0.38,1....|

      |  0.0|[6.3,0.48,0.04,1....|

      |  1.0|[6.2,0.66,0.48,1....|

      |  0.0|[7.4,0.34,0.42,1....|

      |  0.0|[6.5,0.31,0.14,7....|

      +-----+--------------------+

      only showing top 20 rows

	scala> // Create the object of the algorithm which is the Logistic Regression
	scala> val lr = new LogisticRegression()

      lr: org.apache.spark.ml.classification.LogisticRegression = logreg_a7e219daf3e1

	scala> // LogisticRegression parameter to make lr.fit() use at most 10 iterations and the regularization parameter.
	scala> // When a higher degree polynomial used by the algorithm to fit a set of points in a linear regression model, to prevent overfitting, regularization is used and this parameter is just for that
	scala> lr.setMaxIter(10).setRegParam(0.01)

      res8: lr.type = logreg_a7e219daf3e1

	scala> // Create a trained model by fitting the parameters using the training data
	scala> val model = lr.fit(trainingDF)

      model: org.apache.spark.ml.classification.LogisticRegressionModel = logreg_a7e219daf3e1

	scala> // Once the model is prepared, to test the model, prepare the test data containing the labels and feature vectors
	scala> val testDF = spark.createDataFrame(Seq((1.0, Vectors.dense(6.1,0.32,0.24,1.5,0.036,43,140,0.9894,3.36,0.64,10.7)),(0.0, Vectors.dense(5.2,0.44,0.04,1.4,0.036,38,124,0.9898,3.29,0.42,12.4)),(0.0, Vectors.dense(7.2,0.32,0.47,5.1,0.044,19,65,0.9951,3.38,0.36,9)),(0.0,Vectors.dense(6.4,0.595,0.14,5.2,0.058,15,97,0.991,3.03,0.41,12.6)))).toDF("label", "features")

      testDF: org.apache.spark.sql.DataFrame = [label: double, features: vector]

	scala> testDF.show()

      +-----+--------------------+

      |label|            features|

      +-----+--------------------+

      |  1.0|[6.1,0.32,0.24,1....|

      |  0.0|[5.2,0.44,0.04,1....|

      |  0.0|[7.2,0.32,0.47,5....|

      |  0.0|[6.4,0.595,0.14,5...|

      +-----+--------------------+
    scala> testDF.createOrReplaceTempView("test")
	scala> // Do the transformation of the test data using the model and predict the output values or labels. This is to compare the predicted value and the actual label value
	scala> val tested = model.transform(testDF).select("features", "label", "prediction")
      tested: org.apache.spark.sql.DataFrame = [features: vector, label: double ... 1 more field]

	scala> tested.show()
      +--------------------+-----+----------+

      |            features|label|prediction|

      +--------------------+-----+----------+

      |[6.1,0.32,0.24,1....|  1.0|       0.0|

      |[5.2,0.44,0.04,1....|  0.0|       0.0|

      |[7.2,0.32,0.47,5....|  0.0|       0.0|

      |[6.4,0.595,0.14,5...|  0.0|       0.0|

      +--------------------+-----+----------+

	scala> // Prepare a dataset without the output/lables to predict the output using the trained model
	scala> val predictDF = spark.sql("SELECT features FROM test")

      predictDF: org.apache.spark.sql.DataFrame = [features: vector]

	scala> predictDF.show()

      +--------------------+

      |            features|

      +--------------------+

      |[6.1,0.32,0.24,1....|

      |[5.2,0.44,0.04,1....|

      |[7.2,0.32,0.47,5....|

      |[6.4,0.595,0.14,5...|

      +--------------------+

	scala> // Do the transformation with the predict dataset and display the predictions
	scala> val predicted = model.transform(predictDF).select("features", "prediction")

      predicted: org.apache.spark.sql.DataFrame = [features: vector, prediction: double]

	scala> predicted.show()

      +--------------------+----------+

      |            features|prediction|

      +--------------------+----------+

      |[6.1,0.32,0.24,1....|       0.0|

      |[5.2,0.44,0.04,1....|       0.0|

      |[7.2,0.32,0.47,5....|       0.0|

      |[6.4,0.595,0.14,5...|       0.0|

      +--------------------+----------+ 

```

上述代码片段的工作原理与线性回归用例完全相同，只是所用的模型不同。此处使用的模型是逻辑回归，其标签仅取两个值，0 和 1。创建模型、测试模型以及进行预测的过程在此都非常相似。换句话说，流程看起来非常相似。

以下代码使用 Python 演示了相同的用例。在 Python REPL 提示符下，尝试以下语句：

```scala
 >>> from pyspark.ml.linalg import Vectors
	  >>> from pyspark.ml.classification import LogisticRegression
	  >>> from pyspark.ml.param import Param, Params
	  >>> from pyspark.sql import Row
	  >>> # TODO - Change this directory to the right location where the data is stored
	  >>> dataDir = "/Users/RajT/Downloads/wine-quality/"
	  >>> # Create the the RDD by reading the wine data from the disk 
	  >>> lines = sc.textFile(dataDir + "winequality-white.csv")
	  >>> splitLines = lines.map(lambda l: l.split(";"))
	  >>> wineDataRDD = splitLines.map(lambda p: (float(0) if (float(p[11]) < 7) else float(1), Vectors.dense([float(p[0]), float(p[1]), float(p[2]), float(p[3]), float(p[4]), float(p[5]), float(p[6]), float(p[7]), float(p[8]), float(p[9]), float(p[10])])))
	  >>> # Create the data frame containing the training data having two columns. 1) The actula output or label of the data 2) The vector containing the features
	  >>> trainingDF = spark.createDataFrame(wineDataRDD, ['label', 'features'])
	  >>> trainingDF.show()
	  +-----+--------------------+
	  |label|            features|

      +-----+--------------------+

      |  0.0|[7.0,0.27,0.36,20...|

      |  0.0|[6.3,0.3,0.34,1.6...|

      |  0.0|[8.1,0.28,0.4,6.9...|

      |  0.0|[7.2,0.23,0.32,8....|

      |  0.0|[7.2,0.23,0.32,8....|

      |  0.0|[8.1,0.28,0.4,6.9...|

      |  0.0|[6.2,0.32,0.16,7....|

      |  0.0|[7.0,0.27,0.36,20...|

      |  0.0|[6.3,0.3,0.34,1.6...|

      |  0.0|[8.1,0.22,0.43,1....|

      |  0.0|[8.1,0.27,0.41,1....|

      |  0.0|[8.6,0.23,0.4,4.2...|

      |  0.0|[7.9,0.18,0.37,1....|

      |  1.0|[6.6,0.16,0.4,1.5...|

      |  0.0|[8.3,0.42,0.62,19...|

      |  1.0|[6.6,0.17,0.38,1....|

      |  0.0|[6.3,0.48,0.04,1....|

      |  1.0|[6.2,0.66,0.48,1....|

      |  0.0|[7.4,0.34,0.42,1....|

      |  0.0|[6.5,0.31,0.14,7....|

      +-----+--------------------+

      only showing top 20 rows

	>>> # Create the object of the algorithm which is the Logistic Regression with the parameters
	>>> # LogisticRegression parameter to make lr.fit() use at most 10 iterations and the regularization parameter.
	>>> # When a higher degree polynomial used by the algorithm to fit a set of points in a linear regression model, to prevent overfitting, regularization is used and this parameter is just for that
	>>> lr = LogisticRegression(maxIter=10, regParam=0.01)
	>>> # Create a trained model by fitting the parameters using the training data>>> model = lr.fit(trainingDF)
	>>> # Once the model is prepared, to test the model, prepare the test data containing the labels and feature vectors
	>>> testDF = spark.createDataFrame([(1.0, Vectors.dense([6.1,0.32,0.24,1.5,0.036,43,140,0.9894,3.36,0.64,10.7])),(0.0, Vectors.dense([5.2,0.44,0.04,1.4,0.036,38,124,0.9898,3.29,0.42,12.4])),(0.0, Vectors.dense([7.2,0.32,0.47,5.1,0.044,19,65,0.9951,3.38,0.36,9])),(0.0, Vectors.dense([6.4,0.595,0.14,5.2,0.058,15,97,0.991,3.03,0.41,12.6]))], ["label", "features"])
	>>> testDF.createOrReplaceTempView("test")
	>>> testDF.show()

      +-----+--------------------+

      |label|            features|

      +-----+--------------------+

      |  1.0|[6.1,0.32,0.24,1....|

      |  0.0|[5.2,0.44,0.04,1....|

      |  0.0|[7.2,0.32,0.47,5....|

      |  0.0|[6.4,0.595,0.14,5...|

      +-----+--------------------+

	>>> # Do the transformation of the test data using the model and predict the output values or lables. This is to compare the predicted value and the actual label value
	>>> testTransform = model.transform(testDF)
	>>> tested = testTransform.select("features", "label", "prediction")
	>>> tested.show()

      +--------------------+-----+----------+

      |            features|label|prediction|

      +--------------------+-----+----------+

      |[6.1,0.32,0.24,1....|  1.0|       0.0|

      |[5.2,0.44,0.04,1....|  0.0|       0.0|

      |[7.2,0.32,0.47,5....|  0.0|       0.0|

      |[6.4,0.595,0.14,5...|  0.0|       0.0|

      +--------------------+-----+----------+

	>>> # Prepare a dataset without the output/lables to predict the output using the trained model
	>>> predictDF = spark.sql("SELECT features FROM test")
	>>> predictDF.show()

      +--------------------+

      |            features|

      +--------------------+

      |[6.1,0.32,0.24,1....|

      |[5.2,0.44,0.04,1....|

      |[7.2,0.32,0.47,5....|

      |[6.4,0.595,0.14,5...|

      +--------------------+

	>>> # Do the transformation with the predict dataset and display the predictions
	>>> predictTransform = model.transform(predictDF)
	>>> predicted = testTransform.select("features", "prediction")
	>>> predicted.show()
      +--------------------+----------+

      |            features|prediction|

      +--------------------+----------+

      |[6.1,0.32,0.24,1....|       0.0|

      |[5.2,0.44,0.04,1....|       0.0|

      |[7.2,0.32,0.47,5....|       0.0|

      |[6.4,0.595,0.14,5...|       0.0|

      +--------------------+----------+

```

逻辑回归与线性回归非常相似。逻辑回归的主要区别在于其因变量是分类变量。换句话说，因变量仅取一组选定值。在本用例中，这些值为 0 或 1。值 0 表示葡萄酒质量差，值 1 表示葡萄酒质量好。更准确地说，此处使用的因变量是二元因变量。

到目前为止所涵盖的用例仅涉及少量特征。但在现实世界的用例中，特征数量将非常庞大，尤其是在涉及大量文本处理的机器学习用例中。下一节将讨论这样一个用例。

# 垃圾邮件过滤

垃圾邮件过滤是一个极为常见的用例，广泛应用于多种应用中，尤其在电子邮件应用中无处不在。它是使用最广泛的分类问题之一。在典型的邮件服务器中，会处理大量的电子邮件。垃圾邮件过滤在邮件送达收件人邮箱之前进行。对于任何机器学习算法，在做出预测之前必须先训练模型。训练模型需要训练数据。训练数据是如何收集的呢？一个简单的方法是用户自行将收到的部分邮件标记为垃圾邮件。使用邮件服务器中的所有邮件作为训练数据，并定期更新模型。这包括垃圾邮件和非垃圾邮件。当模型拥有两类邮件的良好样本时，预测效果将会很好。

此处介绍的垃圾邮件过滤用例并非一个完全成熟的生产就绪应用程序，但它提供了构建此类应用的良好洞见。在此，为了简化，我们仅使用电子邮件中的一行文本，而非整封邮件内容。若要扩展至处理真实邮件，则需将整封邮件内容读取为一个字符串，并按照本应用中的逻辑进行处理。

与本章前面用例中涉及的数值特征不同，这里的输入是纯文本，选择特征并不像那些用例那样简单。文本被分割成单词以形成词袋，单词被选作特征。由于处理数值特征较为容易，这些单词被转换为哈希词频向量。换句话说，文本行中的单词或术语序列通过哈希方法转换为其词频。因此，即使在小型文本处理用例中，也会有数千个特征。这就是为什么需要对它们进行哈希处理以便于比较。

如前所述，在典型的机器学习应用程序中，输入数据需要经过大量预处理才能将其转换为正确的特征和标签形式，以便构建模型。这通常形成一个转换和估计的管道。在这个用例中，传入的文本行被分割成单词，这些单词使用 HashingTF 算法进行转换，然后训练一个 LogisticRegression 模型进行预测。这是使用 Spark 机器学习库中的 Pipeline 抽象完成的。在 Scala REPL 提示符下，尝试以下语句：

```scala
 scala> import org.apache.spark.ml.classification.LogisticRegression

      import org.apache.spark.ml.classification.LogisticRegression

	scala> import org.apache.spark.ml.param.ParamMap

      import org.apache.spark.ml.param.ParamMap

	scala> import org.apache.spark.ml.linalg.{Vector, Vectors}

      import org.apache.spark.ml.linalg.{Vector, Vectors}

	scala> import org.apache.spark.sql.Row

      import org.apache.spark.sql.Row

	scala> import org.apache.spark.ml.Pipeline

      import org.apache.spark.ml.Pipeline

	scala> import org.apache.spark.ml.feature.{HashingTF, Tokenizer, RegexTokenizer, Word2Vec, StopWordsRemover}

      import org.apache.spark.ml.feature.{HashingTF, Tokenizer, RegexTokenizer, Word2Vec, StopWordsRemover}

	scala> // Prepare training documents from a list of messages from emails used to filter them as spam or not spam
	scala> // If the original message is a spam then the label is 1 and if the message is genuine then the label is 0
	scala> val training = spark.createDataFrame(Seq(("you@example.com", "hope you are well", 0.0),("raj@example.com", "nice to hear from you", 0.0),("thomas@example.com", "happy holidays", 0.0),("mark@example.com", "see you tomorrow", 0.0),("xyz@example.com", "save money", 1.0),("top10@example.com", "low interest rate", 1.0),("marketing@example.com", "cheap loan", 1.0))).toDF("email", "message", "label")

      training: org.apache.spark.sql.DataFrame = [email: string, message: string ... 1 more field]

	scala> training.show()

      +--------------------+--------------------+-----+

      |               email|             message|label|

      +--------------------+--------------------+-----+

      |     you@example.com|   hope you are well|  0.0|

      |     raj@example.com|nice to hear from...|  0.0|

      |  thomas@example.com|      happy holidays|  0.0|

      |    mark@example.com|    see you tomorrow|  0.0|

      |     xyz@example.com|          save money|  1.0|

      |   top10@example.com|   low interest rate|  1.0|

      |marketing@example...|          cheap loan|  1.0|

      +--------------------+--------------------+-----+

	scala>  // Configure an Spark machine learning pipeline, consisting of three stages: tokenizer, hashingTF, and lr.
	scala> val tokenizer = new Tokenizer().setInputCol("message").setOutputCol("words")

      tokenizer: org.apache.spark.ml.feature.Tokenizer = tok_166809bf629c

	scala> val hashingTF = new HashingTF().setNumFeatures(1000).setInputCol("words").setOutputCol("features")

      hashingTF: org.apache.spark.ml.feature.HashingTF = hashingTF_e43616e13d19

	scala> // LogisticRegression parameter to make lr.fit() use at most 10 iterations and the regularization parameter.
	scala> // When a higher degree polynomial used by the algorithm to fit a set of points in a linear regression model, to prevent overfitting, regularization is used and this parameter is just for that
	scala> val lr = new LogisticRegression().setMaxIter(10).setRegParam(0.01)

      lr: org.apache.spark.ml.classification.LogisticRegression = logreg_ef3042fc75a3

	scala> val pipeline = new Pipeline().setStages(Array(tokenizer, hashingTF, lr))

      pipeline: org.apache.spark.ml.Pipeline = pipeline_658b5edef0f2

	scala> // Fit the pipeline to train the model to study the messages
	scala> val model = pipeline.fit(training)

      model: org.apache.spark.ml.PipelineModel = pipeline_658b5edef0f2

	scala> // Prepare messages for prediction, which are not categorized and leaving upto the algorithm to predict
	scala> val test = spark.createDataFrame(Seq(("you@example.com", "how are you"),("jain@example.com", "hope doing well"),("caren@example.com", "want some money"),("zhou@example.com", "secure loan"),("ted@example.com","need loan"))).toDF("email", "message")

      test: org.apache.spark.sql.DataFrame = [email: string, message: string]

	scala> test.show()

      +-----------------+---------------+

      |            email|        message|

      +-----------------+---------------+

      |  you@example.com|    how are you|

      | jain@example.com|hope doing well|

      |caren@example.com|want some money|

      | zhou@example.com|    secure loan|

      |  ted@example.com|      need loan|

      +-----------------+---------------+

	scala> // Make predictions on the new messages
	scala> val prediction = model.transform(test).select("email", "message", "prediction")

      prediction: org.apache.spark.sql.DataFrame = [email: string, message: string ... 1 more field]

	scala> prediction.show()

      +-----------------+---------------+----------+

      |            email|        message|prediction|

      +-----------------+---------------+----------+

      |  you@example.com|    how are you|       0.0|

      | jain@example.com|hope doing well|       0.0|

      |caren@example.com|want some money|       1.0|

      | zhou@example.com|    secure loan|       1.0|

      |  ted@example.com|      need loan|       1.0|

      +-----------------+---------------+----------+ 

```

前面的代码片段执行了典型的活动链：准备训练数据，使用 Pipeline 抽象创建模型，然后使用测试数据进行预测。它没有揭示特征是如何创建和处理的。从应用程序开发的角度来看，Spark 机器学习库承担了繁重的工作，并使用 Pipeline 抽象在幕后完成所有工作。如果不使用 Pipeline 方法，则需要将分词和哈希作为单独的 DataFrame 转换来完成。以下代码片段作为前面命令的延续执行，将提供一个洞察，了解如何通过简单的转换来直观地查看特征：

```scala
 scala> val wordsDF = tokenizer.transform(training)

      wordsDF: org.apache.spark.sql.DataFrame = [email: string, message: string ... 2 more fields]

	scala> wordsDF.createOrReplaceTempView("word")
	scala> val selectedFieldstDF = spark.sql("SELECT message, words FROM word")

      selectedFieldstDF: org.apache.spark.sql.DataFrame = [message: string, words: array<string>]

	scala> selectedFieldstDF.show()

      +--------------------+--------------------+

      |             message|               words|

      +--------------------+--------------------+

      |   hope you are well|[hope, you, are, ...|

      |nice to hear from...|[nice, to, hear, ...|

      |      happy holidays|   [happy, holidays]|

      |    see you tomorrow|[see, you, tomorrow]|

      |          save money|       [save, money]|

      |   low interest rate|[low, interest, r...|

      |          cheap loan|       [cheap, loan]|

      +--------------------+--------------------+
    scala> val featurizedDF = hashingTF.transform(wordsDF)

      featurizedDF: org.apache.spark.sql.DataFrame = [email: string, message: string ... 3 more fields]

	scala> featurizedDF.createOrReplaceTempView("featurized")
	scala> val selectedFeaturizedFieldstDF = spark.sql("SELECT words, features FROM featurized")

      selectedFeaturizedFieldstDF: org.apache.spark.sql.DataFrame = [words: array<string>, features: vector]

	scala> selectedFeaturizedFieldstDF.show()

      +--------------------+--------------------+

      |               words|            features|

      +--------------------+--------------------+

      |[hope, you, are, ...|(1000,[0,138,157,...|

      |[nice, to, hear, ...|(1000,[370,388,42...|

      |   [happy, holidays]|(1000,[141,457],[...|

      |[see, you, tomorrow]|(1000,[25,425,515...|

      |       [save, money]|(1000,[242,520],[...|

      |[low, interest, r...|(1000,[70,253,618...|

      |       [cheap, loan]|(1000,[410,666],[...| 
	 +--------------------+--------------------+ 

```

在 Python 中实现的相同用例如下。在 Python REPL 提示符下，尝试以下语句：

```scala
	  >>> from pyspark.ml import Pipeline
	  >>> from pyspark.ml.classification import LogisticRegression
	  >>> from pyspark.ml.feature import HashingTF, Tokenizer
	  >>> from pyspark.sql import Row
	  >>> # Prepare training documents from a list of messages from emails used to filter them as spam or not spam
	  >>> # If the original message is a spam then the label is 1 and if the message is genuine then the label is 0
	  >>> LabeledDocument = Row("email", "message", "label")
	  >>> training = spark.createDataFrame([("you@example.com", "hope you are well", 0.0),("raj@example.com", "nice to hear from you", 0.0),("thomas@example.com", "happy holidays", 0.0),("mark@example.com", "see you tomorrow", 0.0),("xyz@example.com", "save money", 1.0),("top10@example.com", "low interest rate", 1.0),("marketing@example.com", "cheap loan", 1.0)], ["email", "message", "label"])
	  >>> training.show()

      +--------------------+--------------------+-----+

      |               email|             message|label|

      +--------------------+--------------------+-----+

      |     you@example.com|   hope you are well|  0.0|

      |     raj@example.com|nice to hear from...|  0.0|

      |  thomas@example.com|      happy holidays|  0.0|

      |    mark@example.com|    see you tomorrow|  0.0|

      |     xyz@example.com|          save money|  1.0|

      |   top10@example.com|   low interest rate|  1.0|

      |marketing@example...|          cheap loan|  1.0|

      +--------------------+--------------------+-----+

	>>> # Configure an Spark machin learning pipeline, consisting of three stages: tokenizer, hashingTF, and lr.
	>>> tokenizer = Tokenizer(inputCol="message", outputCol="words")
	>>> hashingTF = HashingTF(inputCol="words", outputCol="features")
	>>> # LogisticRegression parameter to make lr.fit() use at most 10 iterations and the regularization parameter.
	>>> # When a higher degree polynomial used by the algorithm to fit a set of points in a linear regression model, to prevent overfitting, regularization is used and this parameter is just for that
	>>> lr = LogisticRegression(maxIter=10, regParam=0.01)
	>>> pipeline = Pipeline(stages=[tokenizer, hashingTF, lr])
	>>> # Fit the pipeline to train the model to study the messages
	>>> model = pipeline.fit(training)
	>>> # Prepare messages for prediction, which are not categorized and leaving upto the algorithm to predict
	>>> test = spark.createDataFrame([("you@example.com", "how are you"),("jain@example.com", "hope doing well"),("caren@example.com", "want some money"),("zhou@example.com", "secure loan"),("ted@example.com","need loan")], ["email", "message"])
	>>> test.show()

      +-----------------+---------------+

      |            email|        message|

      +-----------------+---------------+

      |  you@example.com|    how are you|

      | jain@example.com|hope doing well|

      |caren@example.com|want some money|

      | zhou@example.com|    secure loan|

      |  ted@example.com|      need loan|

      +-----------------+---------------+

	>>> # Make predictions on the new messages
	>>> prediction = model.transform(test).select("email", "message", "prediction")
	>>> prediction.show()

      +-----------------+---------------+----------+

      |            email|        message|prediction|

      +-----------------+---------------+----------+

      |  you@example.com|    how are you|       0.0|

      | jain@example.com|hope doing well|       0.0|

      |caren@example.com|want some money|       1.0|

      | zhou@example.com|    secure loan|       1.0|

      |  ted@example.com|      need loan|       1.0|    

      +-----------------+---------------+----------+ 

```

如前所述，Pipeline 抽象的转换在 Python 中明确阐述如下。以下代码片段作为前面命令的延续执行，将提供一个洞察，了解如何通过简单的转换来直观地查看特征：

```scala
	  >>> wordsDF = tokenizer.transform(training)
	  >>> wordsDF.createOrReplaceTempView("word")
	  >>> selectedFieldstDF = spark.sql("SELECT message, words FROM word")
	  >>> selectedFieldstDF.show()

      +--------------------+--------------------+

      |             message|               words|

      +--------------------+--------------------+

      |   hope you are well|[hope, you, are, ...|

      |nice to hear from...|[nice, to, hear, ...|

      |      happy holidays|   [happy, holidays]|

      |    see you tomorrow|[see, you, tomorrow]|

      |          save money|       [save, money]|

      |   low interest rate|[low, interest, r...|

      |          cheap loan|       [cheap, loan]|

      +--------------------+--------------------+

	>>> featurizedDF = hashingTF.transform(wordsDF)
	>>> featurizedDF.createOrReplaceTempView("featurized")
	>>> selectedFeaturizedFieldstDF = spark.sql("SELECT words, features FROM featurized")
	>>> selectedFeaturizedFieldstDF.show()

      +--------------------+--------------------+

      |               words|            features|

      +--------------------+--------------------+

      |[hope, you, are, ...|(262144,[128160,1...|

      |[nice, to, hear, ...|(262144,[22346,10...|

      |   [happy, holidays]|(262144,[86293,23...|

      |[see, you, tomorrow]|(262144,[29129,21...|

      |       [save, money]|(262144,[199496,2...|

      |[low, interest, r...|(262144,[68685,13...|

      |       [cheap, loan]|(262144,[12946,16...|

      +--------------------+--------------------+

```

基于前面用例中提供的洞察，可以通过抽象掉许多转换来使用 Spark 机器学习库 Pipelines 开发大量的文本处理机器学习应用程序。

### 提示

正如机器学习模型可以持久化到介质一样，所有 Spark 机器学习库 Pipelines 也可以持久化到介质，并由其他程序重新加载。

# 特征算法

在现实世界的用例中，要获得适合特征和标签形式的原始数据以训练模型并不容易。进行大量预处理是很常见的。与其他数据处理范式不同，Spark 与 Spark 机器学习库结合提供了一套全面的工具和算法来实现这一目的。这些预处理算法可以分为三类：

+   特征提取

+   特征转换

+   特征选择

从原始数据中提取特征的过程称为特征提取。在前述用例中使用的 HashingTF 就是一个很好的例子，它是一种将文本数据的术语转换为特征向量的算法。将特征转换为不同格式的过程称为特征转换。从超集中选择特征子集的过程称为特征选择。涵盖所有这些内容超出了本章的范围，但下一节将讨论一个 Estimator，它是一种用于提取特征的算法，用于在文档中查找单词的同义词。这些并不是单词的实际同义词，而是在给定上下文中与某个单词相关的单词。

# 查找同义词

同义词是指与另一个单词具有完全相同或非常接近意义的单词或短语。从纯粹的文学角度来看，这个解释是正确的，但从更广泛的角度来看，在给定的上下文中，一些单词之间会有非常密切的关系，这种关系在这个上下文中也被称为同义词。例如，罗杰·费德勒与网球*同义*。在上下文中找到这种同义词是实体识别、机器翻译等领域非常常见的需求。**Word2Vec**算法从给定文档或单词集合的单词中计算出单词的分布式向量表示。如果采用这个向量空间，具有相似性或同义性的单词将彼此接近。

加州大学欧文分校机器学习库([`archive.ics.uci.edu/ml/index.html`](http://archive.ics.uci.edu/ml/index.html))为那些对机器学习感兴趣的人提供了大量数据集。Twenty Newsgroups 数据集([`archive.ics.uci.edu/ml/datasets/Twenty+Newsgroups`](http://archive.ics.uci.edu/ml/datasets/Twenty+Newsgroups))被用于在上下文中查找单词的同义词。它包含一个由 20 个新闻组中的 20,000 条消息组成的数据集。

### 注意

二十个新闻组数据集下载链接允许您下载此处讨论的数据集。文件 `20_newsgroups.tar.gz` 需要下载并解压缩。以下代码片段中使用的数据目录应指向数据以解压缩形式可用的目录。如果 Spark 驱动程序因数据量巨大而出现内存不足错误，请删除一些不感兴趣的新闻组数据，并对数据子集进行实验。在这里，为了训练模型，仅使用了以下新闻组数据：talk.politics.guns、talk.politics.mideast、talk.politics.misc 和 talk.religion.misc。

在 Scala REPL 提示符下，尝试以下语句：

```scala

	  scala> import org.apache.spark.ml.feature.{HashingTF, Tokenizer, RegexTokenizer, Word2Vec, StopWordsRemover}

      import org.apache.spark.ml.feature.{HashingTF, Tokenizer, RegexTokenizer, Word2Vec, StopWordsRemover}

	scala> // TODO - Change this directory to the right location where the data is stored
	scala> val dataDir = "/Users/RajT/Downloads/20_newsgroups/*"

      dataDir: String = /Users/RajT/Downloads/20_newsgroups/*

	scala> //Read the entire text into a DataFrame
	scala> // Only the following directories under the data directory has benn considered for running this program talk.politics.guns, talk.politics.mideast, talk.politics.misc, talk.religion.misc. All other directories have been removed before running this program. There is no harm in retaining all the data. The only difference will be in the output.
	scala>  val textDF = sc.wholeTextFiles(dataDir).map{case(file, text) => text}.map(Tuple1.apply).toDF("sentence")

      textDF: org.apache.spark.sql.DataFrame = [sentence: string]

	scala>  // Tokenize the sentences to words
	scala>  val regexTokenizer = new RegexTokenizer().setInputCol("sentence").setOutputCol("words").setPattern("\\w+").setGaps(false)

      regexTokenizer: org.apache.spark.ml.feature.RegexTokenizer = regexTok_ba7ce8ec2333

	scala> val tokenizedDF = regexTokenizer.transform(textDF)

      tokenizedDF: org.apache.spark.sql.DataFrame = [sentence: string, words: array<string>]

	scala>  // Remove the stop words such as a, an the, I etc which doesn't have any specific relevance to the synonyms
	scala> val remover = new StopWordsRemover().setInputCol("words").setOutputCol("filtered")

      remover: org.apache.spark.ml.feature.StopWordsRemover = stopWords_775db995b8e8

	scala> //Remove the stop words from the text
	scala> val filteredDF = remover.transform(tokenizedDF)

      filteredDF: org.apache.spark.sql.DataFrame = [sentence: string, words: array<string> ... 1 more field]

	scala> //Prepare the Estimator
	scala> //It sets the vector size, and the method setMinCount sets the minimum number of times a token must appear to be included in the word2vec model's vocabulary.
	scala> val word2Vec = new Word2Vec().setInputCol("filtered").setOutputCol("result").setVectorSize(3).setMinCount(0)

      word2Vec: org.apache.spark.ml.feature.Word2Vec = w2v_bb03091c4439

	scala> //Train the model
	scala> val model = word2Vec.fit(filteredDF)

      model: org.apache.spark.ml.feature.Word2VecModel = w2v_bb03091c4439   

	scala> //Find 10 synonyms of a given word
	scala> val synonyms1 = model.findSynonyms("gun", 10)

      synonyms1: org.apache.spark.sql.DataFrame = [word: string, similarity: double]

	scala> synonyms1.show()

      +---------+------------------+

      |     word|        similarity|

      +---------+------------------+

      |      twa|0.9999976163843671|

      |cigarette|0.9999943935045497|

      |    sorts|0.9999885527530025|

      |       jj|0.9999827967650881|

      |presently|0.9999792188771406|

      |    laden|0.9999775888361028|

      |   notion|0.9999775296680583|

      | settlers|0.9999746245431419|

      |motivated|0.9999694932468436|

      |qualified|0.9999678135106314|

      +---------+------------------+

	scala> //Find 10 synonyms of a different word
	scala> val synonyms2 = model.findSynonyms("crime", 10)

      synonyms2: org.apache.spark.sql.DataFrame = [word: string, similarity: double]

	scala> synonyms2.show()

      +-----------+------------------+

      |       word|        similarity|

      +-----------+------------------+

      | abominable|0.9999997331058447|

      |authorities|0.9999946968941679|

      |cooperation|0.9999892536435327|

      |  mortazavi| 0.999986396931714|

      |herzegovina|0.9999861828226779|

      |  important|0.9999853354260315|

      |      1950s|0.9999832312575262|

      |    analogy|0.9999828272311249|

      |       bits|0.9999820987679822|

      |technically|0.9999808208936487|

      +-----------+------------------+

```

上述代码片段包含了许多功能。数据集从文件系统读入 DataFrame，作为给定文件中的一句文本。接着进行分词处理，使用正则表达式将句子转换为单词并去除空格。然后，从这些单词中移除停用词，以便我们只保留相关词汇。最后，使用**Word2Vec**估计器，利用准备好的数据训练模型。从训练好的模型中，确定同义词。

以下代码使用 Python 演示了相同的用例。在 Python REPL 提示符下，尝试以下语句：

```scala
 >>> from pyspark.ml.feature import Word2Vec
	  >>> from pyspark.ml.feature import RegexTokenizer
	  >>> from pyspark.sql import Row
	  >>> # TODO - Change this directory to the right location where the data is stored
	  >>> dataDir = "/Users/RajT/Downloads/20_newsgroups/*"
	  >>> # Read the entire text into a DataFrame. Only the following directories under the data directory has benn considered for running this program talk.politics.guns, talk.politics.mideast, talk.politics.misc, talk.religion.misc. All other directories have been removed before running this program. There is no harm in retaining all the data. The only difference will be in the output.
	  >>> textRDD = sc.wholeTextFiles(dataDir).map(lambda recs: Row(sentence=recs[1]))
	  >>> textDF = spark.createDataFrame(textRDD)
	  >>> # Tokenize the sentences to words
	  >>> regexTokenizer = RegexTokenizer(inputCol="sentence", outputCol="words", gaps=False, pattern="\\w+")
	  >>> tokenizedDF = regexTokenizer.transform(textDF)
	  >>> # Prepare the Estimator
	  >>> # It sets the vector size, and the parameter minCount sets the minimum number of times a token must appear to be included in the word2vec model's vocabulary.
	  >>> word2Vec = Word2Vec(vectorSize=3, minCount=0, inputCol="words", outputCol="result")
	  >>> # Train the model
	  >>> model = word2Vec.fit(tokenizedDF)
	  >>> # Find 10 synonyms of a given word
	  >>> synonyms1 = model.findSynonyms("gun", 10)
	  >>> synonyms1.show()

      +---------+------------------+

      |     word|        similarity|

      +---------+------------------+

      | strapped|0.9999918504219028|

      |    bingo|0.9999909957939888|

      |collected|0.9999907658056393|

      |  kingdom|0.9999896797527402|

      | presumed|0.9999806586578037|

      | patients|0.9999778970248504|

      |    azats|0.9999718388241235|

      |  opening| 0.999969723774294|

      |  holdout|0.9999685636131942|

      | contrast|0.9999677676714386|

      +---------+------------------+

	>>> # Find 10 synonyms of a different word
	>>> synonyms2 = model.findSynonyms("crime", 10)
	>>> synonyms2.show()

      +-----------+------------------+

      |       word|        similarity|

      +-----------+------------------+

      |   peaceful|0.9999983523475047|

      |  democracy|0.9999964568156694|

      |      areas| 0.999994036518118|

      |  miniscule|0.9999920828755365|

      |       lame|0.9999877327660102|

      |    strikes|0.9999877253180771|

      |terminology|0.9999839393584438|

      |      wrath|0.9999829348358952|

      |    divided| 0.999982619125983|

      |    hillary|0.9999795817857984|

      +-----------+------------------+ 

```

Scala 实现与 Python 实现的主要区别在于，在 Python 实现中，停用词未被移除。这是因为 Spark 机器学习库的 Python API 中没有提供此功能。因此，Scala 程序和 Python 程序生成的同义词列表会有所不同。

# 参考资料

更多信息请参考以下链接：

+   [UCI 机器学习仓库](http://archive.ics.uci.edu/ml/index.html)

+   [葡萄酒质量数据集](http://archive.ics.uci.edu/ml/datasets/Wine+Quality)

+   [二十个新闻组数据集](http://archive.ics.uci.edu/ml/datasets/Twenty+Newsgroups)

# 总结

Spark 提供了一个非常强大的核心数据处理框架，而 Spark 机器学习库则利用了 Spark 及其库（如 Spark SQL）的所有核心特性，并拥有丰富的机器学习算法集合。本章涵盖了一些常见的预测和分类用例，使用 Scala 和 Python 通过 Spark 机器学习库实现，仅用几行代码。这些葡萄酒质量预测、葡萄酒分类、垃圾邮件过滤器和同义词查找器等机器学习用例具有巨大的潜力，可以发展成为完整的现实世界应用。Spark 2.0 通过启用模型和管道持久化，为模型创建、管道创建及其在不同语言编写的不同程序中的使用带来了灵活性。

成对关系在现实世界的用例中非常普遍。基于强大的数学理论基础，计算机科学家们开发了多种数据结构及其配套算法，这些都属于图论的研究范畴。这些数据结构和算法在社交网络网站、调度问题以及许多其他应用中具有广泛的应用价值。图处理计算量巨大，而分布式数据处理范式如 Spark 非常适合进行此类计算。建立在 Spark 之上的 Spark GraphX 库是一套图处理 API 集合。下一章将探讨 Spark GraphX。


# 第八章：Spark 图处理

图是数学概念，也是计算机科学中的数据结构。它在许多现实世界的应用场景中有着广泛的应用。图用于建模实体之间的成对关系。这里的实体称为顶点，两个顶点通过一条边相连。图由一组顶点和连接它们的边组成。

从概念上讲，这是一种看似简单的抽象，但当涉及到处理大量顶点和边时，它计算密集，消耗大量处理时间和计算资源。以下是一个具有四个顶点和三条边的图的表示：

![Spark 图处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/B05289_08_01_new.jpg)

图 1

本章我们将涵盖以下主题：

+   图及其用途

+   图计算库 GraphX

+   网页排名算法 PageRank

+   连通组件算法

+   图框架 GraphFrames

+   图查询

# 理解图及其用途

有许多应用程序结构可以被建模为图。在社交网络应用中，用户之间的关系可以被建模为一个图，其中用户构成图的顶点，用户之间的关系构成图的边。在多阶段作业调度应用中，各个任务构成图的顶点，任务的排序构成图的边。在道路交通建模系统中，城镇构成图的顶点，连接城镇的道路构成图的边。

给定图的边有一个非常重要的属性，即*连接的方向*。在许多应用场景中，连接的方向并不重要。城市间道路连接的情况就是这样一个例子。但如果应用场景是在城市内提供驾驶方向，那么交通路口之间的连接就有方向。任意两个交通路口之间都有道路连接，但也可能是一条单行道。因此，这都取决于交通流向的方向。如果道路允许从交通路口 J1 到 J2 的交通，但不允许从 J2 到 J1，那么驾驶方向的图将显示从 J1 到 J2 的连接，而不是从 J2 到 J1。在这种情况下，连接 J1 和 J2 的边有方向。如果 J2 和 J3 之间的道路在两个方向都开放，那么连接 J2 和 J3 的边没有方向。所有边都有方向的图称为**有向图**。

### 提示

在图形表示中，对于有向图，必须给出边的方向。如果不是有向图，则可以不带任何方向地表示边，或者向两个方向表示边，这取决于个人选择。*图 1*不是有向图，但表示时向连接的两个顶点都给出了方向。

*图 2*中，社交网络应用用例中两个用户之间的关系被表示为一个图。用户构成顶点，用户之间的关系构成边。用户 A 关注用户 B。同时，用户 A 是用户 B 的儿子。在这个图中，有两条平行边共享相同的源和目标顶点。包含平行边的图称为多图。*图 2*所示的图也是一个有向图。这是一个**有向多图**的好例子。

![理解图及其用途](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_08_002.jpg)

图 2

在现实世界的用例中，图的顶点和边代表了现实世界的实体。这些实体具有属性。例如，在社交网络应用的用户社交连接图中，用户构成顶点，并拥有诸如姓名、电子邮件、电话号码等属性。同样，用户之间的关系构成图的边，连接用户顶点的边可以具有如关系等属性。任何图处理应用库都应足够灵活，以便为图的顶点和边附加任何类型的属性。

# 火花图 X 库

在开源世界中，有许多用于图处理的库，如 Giraph、Pregel、GraphLab 和 Spark GraphX 等。Spark GraphX 是近期进入这一领域的新成员。

Spark GraphX 有何特别之处？Spark GraphX 是一个建立在 Spark 数据处理框架之上的图处理库。与其他图处理库相比，Spark GraphX 具有真正的优势。它可以利用 Spark 的所有数据处理能力。然而，在现实中，图处理算法的性能并不是唯一需要考虑的方面。

在许多应用中，需要建模为图的数据并不自然地以那种形式存在。在很多情况下，为了使图处理算法能够应用，需要花费大量的处理器时间和计算资源来将数据转换为正确的格式。这正是 Spark 数据处理框架与 Spark GraphX 库结合发挥价值的地方。使用 Spark 工具包中众多的工具，可以轻松完成使数据准备好供 Spark GraphX 消费的数据处理任务。总之，作为 Spark 家族一部分的 Spark GraphX 库，结合了 Spark 核心数据处理能力的强大功能和一个非常易于使用的图处理库。

再次回顾*图 3*所示的更大画面，以设定背景并了解正在讨论的内容，然后再深入到用例中。与其他章节不同，本章中的代码示例将仅使用 Scala，因为 Spark GraphX 库目前仅提供 Scala API。

![Spark GraphX 库](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_08_003.jpg)

*图 3*

## GraphX 概览

在任何现实世界的用例中，理解由顶点和边组成的图的概念很容易。但当涉及到实现时，即使是优秀的设计师和程序员也不太了解这种数据结构。原因很简单：与其他无处不在的数据结构（如列表、集合、映射、队列等）不同，图在大多数应用程序中并不常用。考虑到这一点，概念被逐步引入，一步一个脚印，通过简单和微不足道的例子，然后才涉及一些现实世界的用例。

Spark GraphX 库最重要的方面是一种数据类型，Graph，它扩展了 Spark **弹性分布式数据集**（**RDD**）并引入了一种新的图抽象。Spark GraphX 中的图抽象是有向多图，其所有顶点和边都附有属性。这些顶点和边的每个属性可以是 Scala 类型系统支持的用户定义类型。这些类型在 Graph 类型中参数化。给定的图可能需要为顶点或边使用不同的数据类型。这是通过使用继承层次结构相关的类型系统实现的。除了所有这些基本规则外，该库还包括一组图构建器和算法。

图中的一个顶点由一个唯一的 64 位长标识符 `org.apache.spark.graphx.VertexId` 标识。除了 VertexId 类型，简单的 Scala 类型 Long 也可以使用。此外，顶点可以采用任何类型作为属性。图中的边应具有源顶点标识符、目标顶点标识符和任何类型的属性。

*图 4* 展示了一个图，其顶点属性为字符串类型，边属性也为字符串类型。除了属性外，每个顶点都有一个唯一标识符，每条边都有源顶点编号和目标顶点编号。

![GraphX 概览](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_08_004.jpg)

*图 4*

在处理图时，有方法获取顶点和边。但这些孤立的图对象在处理时可能不足以满足需求。

如前所述，一个顶点具有其唯一的标识符和属性。一条边由其源顶点和目标顶点唯一标识。为了便于在图处理应用中处理每条边，Spark GraphX 库的三元组抽象提供了一种简便的方法，通过单个对象访问源顶点、目标顶点和边的属性。

以下 Scala 代码片段用于使用 Spark GraphX 库创建*图 4*中所示的图。创建图后，会调用图上的许多方法，这些方法展示了图的各种属性。在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> import org.apache.spark._
  import org.apache.spark._
    scala> import org.apache.spark.graphx._

	import org.apache.spark.graphx._
	scala> import org.apache.spark.rdd.RDD
	import org.apache.spark.rdd.RDD
  scala> //Create an RDD of users containing tuple values with a mandatory
  Long and another String type as the property of the vertex
  scala> val users: RDD[(Long, String)] = sc.parallelize(Array((1L,
  "Thomas"), (2L, "Krish"),(3L, "Mathew")))
  users: org.apache.spark.rdd.RDD[(Long, String)] = ParallelCollectionRDD[0]
  at parallelize at <console>:31
  scala> //Created an RDD of Edge type with String type as the property of the edge
  scala> val userRelationships: RDD[Edge[String]] = sc.parallelize(Array(Edge(1L, 2L, "Follows"),    Edge(1L, 2L, "Son"),Edge(2L, 3L, "Follows")))
userRelationships: org.apache.spark.rdd.RDD[org.apache.spark.graphx.Edge[String]] = ParallelCollectionRDD[1] at parallelize at <console>:31
    scala> //Create a graph containing the vertex and edge RDDs as created beforescala> val userGraph = Graph(users, userRelationships)
	userGraph: org.apache.spark.graphx.Graph[String,String] = org.apache.spark.graphx.impl.GraphImpl@ed5cf29

	scala> //Number of edges in the graph
	scala> userGraph.numEdges
      res3: Long = 3
    scala> //Number of vertices in the graph
	scala> userGraph.numVertices
      res4: Long = 3
	  scala> //Number of edges coming to each of the vertex. 
	  scala> userGraph.inDegrees
res7: org.apache.spark.graphx.VertexRDD[Int] = VertexRDDImpl[19] at RDD at
 VertexRDD.scala:57
scala> //The first element in the tuple is the vertex id and the second
 element in the tuple is the number of edges coming to that vertex
 scala> userGraph.inDegrees.foreach(println)
      (3,1)

      (2,2)
    scala> //Number of edges going out of each of the vertex. scala> userGraph.outDegrees
	res9: org.apache.spark.graphx.VertexRDD[Int] = VertexRDDImpl[23] at RDD at VertexRDD.scala:57
    scala> //The first element in the tuple is the vertex id and the second
	element in the tuple is the number of edges going out of that vertex
	scala> userGraph.outDegrees.foreach(println)
      (1,2)

      (2,1)
    scala> //Total number of edges coming in and going out of each vertex. 
	scala> userGraph.degrees
res12: org.apache.spark.graphx.VertexRDD[Int] = VertexRDDImpl[27] at RDD at
 VertexRDD.scala:57
    scala> //The first element in the tuple is the vertex id and the second 
	element in the tuple is the total number of edges coming in and going out of that vertex.
	scala> userGraph.degrees.foreach(println)
      (1,2)

      (2,3)

      (3,1)
    scala> //Get the vertices of the graph
	scala> userGraph.vertices
res11: org.apache.spark.graphx.VertexRDD[String] = VertexRDDImpl[11] at RDD at VertexRDD.scala:57
    scala> //Get all the vertices with the vertex number and the property as a tuplescala> userGraph.vertices.foreach(println)
      (1,Thomas)

      (3,Mathew)

      (2,Krish)
    scala> //Get the edges of the graph
	scala> userGraph.edges
res15: org.apache.spark.graphx.EdgeRDD[String] = EdgeRDDImpl[13] at RDD at
 EdgeRDD.scala:41
    scala> //Get all the edges properties with source and destination vertex numbers
	scala> userGraph.edges.foreach(println)
      Edge(1,2,Follows)

      Edge(1,2,Son)

      Edge(2,3,Follows)
    scala> //Get the triplets of the graph
	scala> userGraph.triplets
res18: org.apache.spark.rdd.RDD[org.apache.spark.graphx.EdgeTriplet[String,String]]
 = MapPartitionsRDD[32] at mapPartitions at GraphImpl.scala:48
    scala> userGraph.triplets.foreach(println)
	((1,Thomas),(2,Krish),Follows)
	((1,Thomas),(2,Krish),Son)
	((2,Krish),(3,Mathew),Follows)

```

读者将熟悉使用 RDD 进行 Spark 编程。上述代码片段阐明了使用 RDD 构建图的顶点和边的过程。RDD 可以使用各种数据存储中持久化的数据构建。在现实世界的用例中，大多数情况下数据将来自外部源，如 NoSQL 数据存储，并且有方法使用此类数据构建 RDD。一旦构建了 RDD，就可以使用它们来构建图。

上述代码片段还解释了图提供的各种方法，以获取给定图的所有必要详细信息。这里涉及的示例用例是一个规模非常小的图。在现实世界的用例中，图的顶点和边的数量可能达到数百万。由于所有这些抽象都作为 RDD 实现，因此固有的不可变性、分区、分布和并行处理的开箱即用特性使得图处理高度可扩展。最后，以下表格展示了顶点和边的表示方式：

**顶点表**：

| **顶点 ID** | **顶点属性** |
| --- | --- |
| 1 | Thomas |
| 2 | Krish |
| 3 | Mathew |

**边表**：

| **源顶点 ID** | **目标顶点 ID** | **边属性** |
| --- | --- | --- |
| 1 | 2 | Follows |
| 1 | 2 | Son |
| 2 | 3 | Follows |

**三元组表**：

| **源顶点 ID** | **目标顶点 ID** | **源顶点属性** | **边属性** | **目标顶点属性** |
| --- | --- | --- | --- | --- |
| 1 | 2 | Thomas | Follows | Krish |
| 1 | 2 | Thomas | Son | Krish |
| 2 | 3 | Krish | Follows | Mathew |

### 注意

需要注意的是，这些表格仅用于解释目的。实际的内部表示遵循 RDD 表示的规则和规定。

如果任何内容表示为 RDD，它必然会被分区并分布。但如果分区分布不受图的控制，那么在图处理性能方面将是次优的。因此，Spark GraphX 库的创建者提前充分考虑了这个问题，并实施了图分区策略，以便以 RDD 形式获得优化的图表示。

## 图分区

了解图 RDD 如何分区并在各个分区之间分布是很重要的。这对于确定图的各个组成部分 RDD 的分区和分布的高级优化非常有用。

通常，给定图有三个 RDD。除了顶点 RDD 和边 RDD 之外，还有一个内部使用的路由 RDD。为了获得最佳性能，构成给定边所需的所有顶点都保持在存储该边的同一分区中。如果某个顶点参与了多个边，并且这些边位于不同的分区中，那么该特定顶点可以存储在多个分区中。

为了跟踪给定顶点冗余存储的分区，还维护了一个路由 RDD，其中包含顶点详细信息以及每个顶点可用的分区。

*图 5*对此进行了解释：

![图分区](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_08_005.jpg)

图 5

*图 5*中，假设边被划分为分区 1 和 2。同样假设顶点被划分为分区 1 和 2。

在分区 1 中，所有边所需的顶点都可在本地获取。但在分区 2 中，只有一个边的顶点可在本地获取。因此，缺失的顶点也存储在分区 2 中，以便所有所需的顶点都可在本地获取。

为了跟踪复制情况，顶点路由 RDD 维护了给定顶点可用的分区编号。在*图 5*中，在顶点路由 RDD 中，使用标注符号来显示这些顶点被复制的分区。这样，在处理边或三元组时，所有与组成顶点相关的信息都可在本地获取，性能将高度优化。由于 RDD 是不可变的，即使它们存储在多个分区中，与信息更改相关的问题也被消除。

## 图处理

向用户展示的图的组成元素是顶点 RDD 和边 RDD。就像任何其他数据结构一样，由于底层数据的变化，图也会经历许多变化。为了使所需的图操作支持各种用例，有许多算法可用，使用这些算法可以处理图数据结构中隐藏的数据，以产生所需的业务成果。在深入了解处理图的算法之前，了解一些使用航空旅行用例的图处理基础知识是很有帮助的。

假设有人试图寻找从曼彻斯特到班加罗尔的廉价返程机票。在旅行偏好中，此人提到他/她不在乎中转次数，但价格应为最低。假设机票预订系统为往返旅程选择了相同的中转站，并生成了以下具有最低价格的路线或航段：

曼彻斯特 → 伦敦 → 科伦坡 → 班加罗尔

班加罗尔 → 科伦坡 → 伦敦 → 曼彻斯特

该路线规划是一个图的完美示例。如果将前行旅程视为一个图，将返程视为另一个图，那么返程图可以通过反转前行旅程图来生成。在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> import org.apache.spark._
import org.apache.spark._
scala> import org.apache.spark.graphx._
import org.apache.spark.graphx._
scala> import org.apache.spark.rdd.RDD
import org.apache.spark.rdd.RDD
scala> //Create the vertices with the stops
scala> val stops: RDD[(Long, String)] = sc.parallelize(Array((1L, "Manchester"), (2L, "London"),(3L, "Colombo"), (4L, "Bangalore")))
stops: org.apache.spark.rdd.RDD[(Long, String)] = ParallelCollectionRDD[33] at parallelize at <console>:38
scala> //Create the edges with travel legs
scala> val legs: RDD[Edge[String]] = sc.parallelize(Array(Edge(1L, 2L, "air"),    Edge(2L, 3L, "air"),Edge(3L, 4L, "air"))) 
legs: org.apache.spark.rdd.RDD[org.apache.spark.graphx.Edge[String]] = ParallelCollectionRDD[34] at parallelize at <console>:38 
scala> //Create the onward journey graph
scala> val onwardJourney = Graph(stops, legs)onwardJourney: org.apache.spark.graphx.Graph[String,String] = org.apache.spark.graphx.impl.GraphImpl@190ec769scala> onwardJourney.triplets.map(triplet => (triplet.srcId, (triplet.srcAttr, triplet.dstAttr))).sortByKey().collect().foreach(println)
(1,(Manchester,London))
(2,(London,Colombo))
(3,(Colombo,Bangalore))
scala> val returnJourney = onwardJourney.reversereturnJourney: org.apache.spark.graphx.Graph[String,String] = org.apache.spark.graphx.impl.GraphImpl@60035f1e
scala> returnJourney.triplets.map(triplet => (triplet.srcId, (triplet.srcAttr,triplet.dstAttr))).sortByKey(ascending=false).collect().foreach(println)
(4,(Bangalore,Colombo))
(3,(Colombo,London))
(2,(London,Manchester))

```

前行旅程航段的起点和终点在返程航段中被反转。当图被反转时，只有边的起点和终点顶点被反转，顶点的身份保持不变。

换言之，每个顶点的标识符保持不变。在处理图时，了解三元组属性的名称很重要。它们对于编写程序和处理图很有用。在同一个 Scala REPL 会话中，尝试以下语句：

```scala
scala> returnJourney.triplets.map(triplet => (triplet.srcId,triplet.dstId,triplet.attr,triplet.srcAttr,triplet.dstAttr)).foreach(println) 
(2,1,air,London,Manchester) 
(3,2,air,Colombo,London) 
(4,3,air,Bangalore,Colombo) 

```

下表列出了可用于处理图并从图中提取所需数据的三元组属性。前面的代码片段和下表可以交叉验证，以便完全理解：

| **三元组属性** | **描述** |
| --- | --- |
| `srcId` | 源顶点标识符 |
| `dstId` | 目标顶点标识符 |
| `attr` | 边属性 |
| `srcAttr` | 源顶点属性 |
| `dstAttr` | 目标顶点属性 |

在图中，顶点是 RDD，边是 RDD，仅凭这一点，就可以进行转换。

现在，为了演示图转换，我们使用相同的用例，但稍作改动。假设一个旅行社从航空公司获得了某些路线的特别折扣价格。旅行社决定保留折扣，并向客户提供市场价格，为此，他们将航空公司给出的价格提高了 10%。这个旅行社注意到机场名称显示不一致，并希望确保在整个网站上显示时有一致的表示，因此决定将所有停靠点名称改为大写。在同一个 Scala REPL 会话中，尝试以下语句：

```scala
 scala> // Create the vertices 
scala> val stops: RDD[(Long, String)] = sc.parallelize(Array((1L,
 "Manchester"), (2L, "London"),(3L, "Colombo"), (4L, "Bangalore"))) 
stops: org.apache.spark.rdd.RDD[(Long, String)] = ParallelCollectionRDD[66] at parallelize at <console>:38 
scala> //Create the edges 
scala> val legs: RDD[Edge[Long]] = sc.parallelize(Array(Edge(1L, 2L, 50L),    Edge(2L, 3L, 100L),Edge(3L, 4L, 80L))) 
legs: org.apache.spark.rdd.RDD[org.apache.spark.graphx.Edge[Long]] = ParallelCollectionRDD[67] at parallelize at <console>:38 
scala> //Create the graph using the vertices and edges 
scala> val journey = Graph(stops, legs) 
journey: org.apache.spark.graphx.Graph[String,Long] = org.apache.spark.graphx.impl.GraphImpl@8746ad5 
scala> //Convert the stop names to upper case 
scala> val newStops = journey.vertices.map {case (id, name) => (id, name.toUpperCase)} 
newStops: org.apache.spark.rdd.RDD[(org.apache.spark.graphx.VertexId, String)] = MapPartitionsRDD[80] at map at <console>:44 
scala> //Get the edges from the selected journey and add 10% price to the original price 
scala> val newLegs = journey.edges.map { case Edge(src, dst, prop) => Edge(src, dst, (prop + (0.1*prop))) } 
newLegs: org.apache.spark.rdd.RDD[org.apache.spark.graphx.Edge[Double]] = MapPartitionsRDD[81] at map at <console>:44 
scala> //Create a new graph with the original vertices and the new edges 
scala> val newJourney = Graph(newStops, newLegs) 
newJourney: org.apache.spark.graphx.Graph[String,Double]
 = org.apache.spark.graphx.impl.GraphImpl@3c929623 
scala> //Print the contents of the original graph 
scala> journey.triplets.foreach(println) 
((1,Manchester),(2,London),50) 
((3,Colombo),(4,Bangalore),80) 
((2,London),(3,Colombo),100) 
scala> //Print the contents of the transformed graph 
scala>  newJourney.triplets.foreach(println) 
((2,LONDON),(3,COLOMBO),110.0) 
((3,COLOMBO),(4,BANGALORE),88.0) 
((1,MANCHESTER),(2,LONDON),55.0) 

```

实质上，这些转换确实是 RDD 转换。如果有关于这些不同的 RDD 如何组合在一起形成图的概念理解，任何具有 RDD 编程熟练度的程序员都能很好地进行图处理。这是 Spark 统一编程模型的另一个证明。

前面的用例对顶点和边 RDD 进行了映射转换。类似地，过滤转换是另一种常用的有用类型。除了这些，所有转换和操作都可以用于处理顶点和边 RDD。

## 图结构处理

在前一节中，通过单独处理所需的顶点或边完成了一种图处理。这种方法的一个缺点是处理过程分为三个不同的阶段，如下：

+   从图中提取顶点或边

+   处理顶点或边

+   使用处理过的顶点和边重新创建一个新图

这种方法繁琐且容易出错。为了解决这个问题，Spark GraphX 库提供了一些结构化操作符，允许用户将图作为一个单独的单元进行处理，从而生成一个新的图。

前一节已经讨论了一个重要的结构化操作，即图的反转，它生成一个所有边方向反转的新图。另一个常用的结构化操作是从给定图中提取子图。所得子图可以是整个父图，也可以是父图的子集，具体取决于对父图执行的操作。

当从外部数据源创建图时，边可能包含无效顶点。如果顶点和边来自两个不同的数据源或应用程序，这种情况非常可能发生。使用这些顶点和边创建的图，其中一些边将包含无效顶点，处理结果将出现意外。以下是一个用例，其中一些包含无效顶点的边通过结构化操作进行修剪以消除这种情况。在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> import org.apache.spark._
  import org.apache.spark._    scala> import org.apache.spark.graphx._
  import org.apache.spark.graphx._    scala> import org.apache.spark.rdd.RDD
  import org.apache.spark.rdd.RDD    scala> //Create an RDD of users containing tuple values with a mandatory
  Long and another String type as the property of the vertex
  scala> val users: RDD[(Long, String)] = sc.parallelize(Array((1L,
  "Thomas"), (2L, "Krish"),(3L, "Mathew")))
users: org.apache.spark.rdd.RDD[(Long, String)] = ParallelCollectionRDD[104]
 at parallelize at <console>:45
    scala> //Created an RDD of Edge type with String type as the property of
	the edge
	scala> val userRelationships: RDD[Edge[String]] =
	sc.parallelize(Array(Edge(1L, 2L, "Follows"), Edge(1L, 2L,
	"Son"),Edge(2L, 3L, "Follows"), Edge(1L, 4L, "Follows"), Edge(3L, 4L, "Follows")))
	userRelationships:
	org.apache.spark.rdd.RDD[org.apache.spark.graphx.Edge[String]] =
	ParallelCollectionRDD[105] at parallelize at <console>:45
    scala> //Create a vertex property object to fill in if an invalid vertex id is given in the edge
	scala> val missingUser = "Missing"
missingUser: String = Missing
    scala> //Create a graph containing the vertex and edge RDDs as created
	before
	scala> val userGraph = Graph(users, userRelationships, missingUser)
userGraph: org.apache.spark.graphx.Graph[String,String] = org.apache.spark.graphx.impl.GraphImpl@43baf0b9
    scala> //List the graph triplets and find some of the invalid vertex ids given and for them the missing vertex property is assigned with the value "Missing"scala> userGraph.triplets.foreach(println)
      ((3,Mathew),(4,Missing),Follows)  
      ((1,Thomas),(2,Krish),Son)    
      ((2,Krish),(3,Mathew),Follows)    
      ((1,Thomas),(2,Krish),Follows)    
      ((1,Thomas),(4,Missing),Follows)
    scala> //Since the edges with the invalid vertices are invalid too, filter out
	those vertices and create a valid graph. The vertex predicate here can be any valid filter condition of a vertex. Similar to vertex predicate, if the filtering is to be done on the edges, instead of the vpred, use epred as the edge predicate.
	scala> val fixedUserGraph = userGraph.subgraph(vpred = (vertexId, attribute) => attribute != "Missing")
fixedUserGraph: org.apache.spark.graphx.Graph[String,String] = org.apache.spark.graphx.impl.GraphImpl@233b5c71 
 scala> fixedUserGraph.triplets.foreach(println)
  ((2,Krish),(3,Mathew),Follows)
  ((1,Thomas),(2,Krish),Follows)
  ((1,Thomas),(2,Krish),Son)

```

在大型图中，根据具体用例，有时可能存在大量平行边。在某些用例中，可以将平行边的数据合并并仅保留一条边，而不是维护许多平行边。在前述用例中，最终没有无效边的图，存在平行边，一条具有属性`Follows`，另一条具有`Son`，它们具有相同的源和目标顶点。

将这些平行边合并为一条具有从平行边串联属性的单一边是可行的，这将减少边的数量而不丢失信息。这是通过图的 groupEdges 结构化操作实现的。在同一 Scala REPL 会话中，尝试以下语句：

```scala
scala> // Import the partition strategy classes 
scala> import org.apache.spark.graphx.PartitionStrategy._ 
import org.apache.spark.graphx.PartitionStrategy._ 
scala> // Partition the user graph. This is required to group the edges 
scala> val partitionedUserGraph = fixedUserGraph.partitionBy(CanonicalRandomVertexCut) 
partitionedUserGraph: org.apache.spark.graphx.Graph[String,String] = org.apache.spark.graphx.impl.GraphImpl@5749147e 
scala> // Generate the graph without parallel edges and combine the properties of duplicate edges 
scala> val graphWithoutParallelEdges = partitionedUserGraph.groupEdges((e1, e2) => e1 + " and " + e2) 
graphWithoutParallelEdges: org.apache.spark.graphx.Graph[String,String] = org.apache.spark.graphx.impl.GraphImpl@16a4961f 
scala> // Print the details 
scala> graphWithoutParallelEdges.triplets.foreach(println) 
((1,Thomas),(2,Krish),Follows and Son) 
((2,Krish),(3,Mathew),Follows) 

```

之前的图结构变化通过聚合边减少了边的数量。当边属性为数值型且通过聚合进行合并有意义时，也可以通过移除平行边来减少边的数量，这能显著减少图处理时间。

### 注意

本代码片段中一个重要点是，在边上执行 group-by 操作之前，图已经进行了分区。

默认情况下，给定图的边及其组成顶点无需位于同一分区。为了使 group-by 操作生效，所有平行边必须位于同一分区。CanonicalRandomVertexCut 分区策略确保两个顶点之间的所有边，无论方向如何，都能实现共置。

在 Spark GraphX 库中还有更多结构化操作符可供使用，查阅 Spark 文档可以深入了解这些操作符，它们可根据具体用例进行应用。

# 网球锦标赛分析

既然基本的图处理基础已经就位，现在是时候采用一个使用图的现实世界用例了。这里，我们使用图来模拟一场网球锦标赛的结果。使用图来模拟 2015 年巴克莱 ATP 世界巡回赛单打比赛的结果。顶点包含球员详情，边包含个人比赛记录。边的形成方式是，源顶点是赢得比赛的球员，目标顶点是输掉比赛的球员。边属性包含比赛类型、赢家在比赛中获得的分数以及球员之间的交锋次数。这里使用的积分系统是虚构的，仅仅是赢家在那场比赛中获得的权重。小组赛初赛权重最低，半决赛权重更高，决赛权重最高。通过这种方式模拟结果，处理图表以找出以下详细信息：

+   列出所有比赛详情。

+   列出所有比赛，包括球员姓名、比赛类型和结果。

+   列出所有小组 1 的获胜者及其比赛中的积分。

+   列出所有小组 2 的获胜者及其比赛中的积分。

+   列出所有半决赛获胜者及其比赛中的积分。

+   列出决赛获胜者及其比赛中的积分。

+   列出球员在整个锦标赛中获得的总积分。

+   通过找出得分最高的球员来列出比赛获胜者。

+   在小组赛阶段，由于循环赛制，同一组球员可能会多次相遇。查找是否有任何球员在这场锦标赛中相互比赛超过一次。

+   列出至少赢得一场比赛的球员。

+   列出至少输掉一场比赛的球员。

+   列出至少赢得一场比赛且至少输掉一场比赛的球员。

+   列出完全没有获胜的球员。

+   列出完全没有输掉比赛的球员。

对于不熟悉网球比赛的人来说，无需担心，因为这里不讨论比赛规则，也不需要理解这个用例。实际上，我们只将其视为两人之间的比赛，其中一人获胜，另一人输掉。在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> import org.apache.spark._
  import org.apache.spark._    
  scala> import org.apache.spark.graphx._
  import org.apache.spark.graphx._    
  scala> import org.apache.spark.rdd.RDD
  import org.apache.spark.rdd.RDD
    scala> //Define a property class that is going to hold all the properties of the vertex which is nothing but player information
	scala> case class Player(name: String, country: String)
      defined class Player
    scala> // Create the player vertices
	scala> val players: RDD[(Long, Player)] = sc.parallelize(Array((1L, Player("Novak Djokovic", "SRB")), (3L, Player("Roger Federer", "SUI")),(5L, Player("Tomas Berdych", "CZE")), (7L, Player("Kei Nishikori", "JPN")), (11L, Player("Andy Murray", "GBR")),(15L, Player("Stan Wawrinka", "SUI")),(17L, Player("Rafael Nadal", "ESP")),(19L, Player("David Ferrer", "ESP"))))
players: org.apache.spark.rdd.RDD[(Long, Player)] = ParallelCollectionRDD[145] at parallelize at <console>:57
    scala> //Define a property class that is going to hold all the properties of the edge which is nothing but match informationscala> case class Match(matchType: String, points: Int, head2HeadCount: Int)
      defined class Match
    scala> // Create the match edgesscala> val matches: RDD[Edge[Match]] = sc.parallelize(Array(Edge(1L, 5L, Match("G1", 1,1)), Edge(1L, 7L, Match("G1", 1,1)), Edge(3L, 1L, Match("G1", 1,1)), Edge(3L, 5L, Match("G1", 1,1)), Edge(3L, 7L, Match("G1", 1,1)), Edge(7L, 5L, Match("G1", 1,1)), Edge(11L, 19L, Match("G2", 1,1)), Edge(15L, 11L, Match("G2", 1, 1)), Edge(15L, 19L, Match("G2", 1, 1)), Edge(17L, 11L, Match("G2", 1, 1)), Edge(17L, 15L, Match("G2", 1, 1)), Edge(17L, 19L, Match("G2", 1, 1)), Edge(3L, 15L, Match("S", 5, 1)), Edge(1L, 17L, Match("S", 5, 1)), Edge(1L, 3L, Match("F", 11, 1))))
matches: org.apache.spark.rdd.RDD[org.apache.spark.graphx.Edge[Match]] = ParallelCollectionRDD[146] at parallelize at <console>:57
    scala> //Create a graph with the vertices and edges
	scala> val playGraph = Graph(players, matches)
playGraph: org.apache.spark.graphx.Graph[Player,Match] = org.apache.spark.graphx.impl.GraphImpl@30d4d6fb 

```

包含网球锦标赛的图已经创建，从现在开始，所有要做的是处理这个基础图并从中提取信息以满足用例需求：

```scala
scala> //Print the match details
	scala> playGraph.triplets.foreach(println)
((15,Player(Stan Wawrinka,SUI)),(11,Player(Andy Murray,GBR)),Match(G2,1,1))    
((15,Player(Stan Wawrinka,SUI)),(19,Player(David Ferrer,ESP)),Match(G2,1,1))    
((7,Player(Kei Nishikori,JPN)),(5,Player(Tomas Berdych,CZE)),Match(G1,1,1))    
((1,Player(Novak Djokovic,SRB)),(7,Player(Kei Nishikori,JPN)),Match(G1,1,1))    
((3,Player(Roger Federer,SUI)),(1,Player(Novak Djokovic,SRB)),Match(G1,1,1))    
((1,Player(Novak Djokovic,SRB)),(3,Player(Roger Federer,SUI)),Match(F,11,1))    
((1,Player(Novak Djokovic,SRB)),(17,Player(Rafael Nadal,ESP)),Match(S,5,1))    
((3,Player(Roger Federer,SUI)),(5,Player(Tomas Berdych,CZE)),Match(G1,1,1))    
((17,Player(Rafael Nadal,ESP)),(11,Player(Andy Murray,GBR)),Match(G2,1,1))    
((3,Player(Roger Federer,SUI)),(7,Player(Kei Nishikori,JPN)),Match(G1,1,1))    
((1,Player(Novak Djokovic,SRB)),(5,Player(Tomas Berdych,CZE)),Match(G1,1,1))    
((17,Player(Rafael Nadal,ESP)),(15,Player(Stan Wawrinka,SUI)),Match(G2,1,1))    
((11,Player(Andy Murray,GBR)),(19,Player(David Ferrer,ESP)),Match(G2,1,1))    
((3,Player(Roger Federer,SUI)),(15,Player(Stan Wawrinka,SUI)),Match(S,5,1))    
((17,Player(Rafael Nadal,ESP)),(19,Player(David Ferrer,ESP)),Match(G2,1,1))
    scala> //Print matches with player names and the match type and the resultscala> playGraph.triplets.map(triplet => triplet.srcAttr.name + " won over " + triplet.dstAttr.name + " in  " + triplet.attr.matchType + " match").foreach(println)
      Roger Federer won over Tomas Berdych in  G1 match    
      Roger Federer won over Kei Nishikori in  G1 match    
      Novak Djokovic won over Roger Federer in  F match    
      Novak Djokovic won over Rafael Nadal in  S match    
      Roger Federer won over Stan Wawrinka in  S match    
      Rafael Nadal won over David Ferrer in  G2 match    
      Kei Nishikori won over Tomas Berdych in  G1 match    
      Andy Murray won over David Ferrer in  G2 match    
      Stan Wawrinka won over Andy Murray in  G2 match    
      Stan Wawrinka won over David Ferrer in  G2 match    
      Novak Djokovic won over Kei Nishikori in  G1 match    
      Roger Federer won over Novak Djokovic in  G1 match    
      Rafael Nadal won over Andy Murray in  G2 match    
      Rafael Nadal won over Stan Wawrinka in  G2 match    
      Novak Djokovic won over Tomas Berdych in  G1 match 

```

值得注意的是，在图形中使用三元组对于提取给定网球比赛的所有必需数据元素非常方便，包括谁在比赛、谁获胜以及比赛类型，这些都可以从一个对象中获取。以下分析用例的实现涉及筛选锦标赛的网球比赛记录。这里仅使用了简单的筛选逻辑，但在实际用例中，任何复杂的逻辑都可以在函数中实现，并作为参数传递给筛选转换：

```scala
scala> //Group 1 winners with their group total points
scala> playGraph.triplets.filter(triplet => triplet.attr.matchType == "G1").map(triplet => (triplet.srcAttr.name, triplet.attr.points)).foreach(println)
      (Kei Nishikori,1)    
      (Roger Federer,1)    
      (Roger Federer,1)    
      (Novak Djokovic,1)    
      (Novak Djokovic,1)    
      (Roger Federer,1)
    scala> //Find the group total of the players
	scala> playGraph.triplets.filter(triplet => triplet.attr.matchType == "G1").map(triplet => (triplet.srcAttr.name, triplet.attr.points)).reduceByKey(_+_).foreach(println)
      (Roger Federer,3)    
      (Novak Djokovic,2)    
      (Kei Nishikori,1)
    scala> //Group 2 winners with their group total points
	scala> playGraph.triplets.filter(triplet => triplet.attr.matchType == "G2").map(triplet => (triplet.srcAttr.name, triplet.attr.points)).foreach(println)
      (Rafael Nadal,1)    
      (Rafael Nadal,1)    
      (Andy Murray,1)    
      (Stan Wawrinka,1)    
      (Stan Wawrinka,1)    
      (Rafael Nadal,1) 

```

以下分析用例的实现涉及按键分组并进行汇总计算。它不仅限于查找网球比赛记录点的总和，如以下用例实现所示；实际上，可以使用用户定义的函数进行计算：

```scala
scala> //Find the group total of the players
	scala> playGraph.triplets.filter(triplet => triplet.attr.matchType == "G2").map(triplet => (triplet.srcAttr.name, triplet.attr.points)).reduceByKey(_+_).foreach(println)
      (Stan Wawrinka,2)    
      (Andy Murray,1)    
      (Rafael Nadal,3)
    scala> //Semi final winners with their group total points
	scala> playGraph.triplets.filter(triplet => triplet.attr.matchType == "S").map(triplet => (triplet.srcAttr.name, triplet.attr.points)).foreach(println)
      (Novak Djokovic,5)    
      (Roger Federer,5)
    scala> //Find the group total of the players
	scala> playGraph.triplets.filter(triplet => triplet.attr.matchType == "S").map(triplet => (triplet.srcAttr.name, triplet.attr.points)).reduceByKey(_+_).foreach(println)
      (Novak Djokovic,5)    
      (Roger Federer,5)
    scala> //Final winner with the group total points
	scala> playGraph.triplets.filter(triplet => triplet.attr.matchType == "F").map(triplet => (triplet.srcAttr.name, triplet.attr.points)).foreach(println)
      (Novak Djokovic,11)
    scala> //Tournament total point standing
	scala> playGraph.triplets.map(triplet => (triplet.srcAttr.name, triplet.attr.points)).reduceByKey(_+_).foreach(println)
      (Stan Wawrinka,2)

      (Rafael Nadal,3)    
      (Kei Nishikori,1)    
      (Andy Murray,1)    
      (Roger Federer,8)    
      (Novak Djokovic,18)
    scala> //Find the winner of the tournament by finding the top scorer of the tournament
	scala> playGraph.triplets.map(triplet => (triplet.srcAttr.name, triplet.attr.points)).reduceByKey(_+_).map{ case (k,v) => (v,k)}.sortByKey(ascending=false).take(1).map{ case (k,v) => (v,k)}.foreach(println)
      (Novak Djokovic,18)
    scala> //Find how many head to head matches held for a given set of players in the descending order of head2head count
	scala> playGraph.triplets.map(triplet => (Set(triplet.srcAttr.name , triplet.dstAttr.name) , triplet.attr.head2HeadCount)).reduceByKey(_+_).map{case (k,v) => (k.mkString(" and "), v)}.map{ case (k,v) => (v,k)}.sortByKey().map{ case (k,v) => v + " played " + k + " time(s)"}.foreach(println)
      Roger Federer and Novak Djokovic played 2 time(s)    
      Roger Federer and Tomas Berdych played 1 time(s)    
      Kei Nishikori and Tomas Berdych played 1 time(s)    
      Novak Djokovic and Tomas Berdych played 1 time(s)    
      Rafael Nadal and Andy Murray played 1 time(s)    
      Rafael Nadal and Stan Wawrinka played 1 time(s)    
      Andy Murray and David Ferrer played 1 time(s)    
      Rafael Nadal and David Ferrer played 1 time(s)    
      Stan Wawrinka and David Ferrer played 1 time(s)    
      Stan Wawrinka and Andy Murray played 1 time(s)    
      Roger Federer and Stan Wawrinka played 1 time(s)    
      Roger Federer and Kei Nishikori played 1 time(s)    
      Novak Djokovic and Kei Nishikori played 1 time(s)    
      Novak Djokovic and Rafael Nadal played 1 time(s) 

```

以下分析用例的实现涉及从查询中查找唯一记录。Spark 的 distinct 转换可以实现这一点：

```scala
 scala> //List of players who have won at least one match
	scala> val winners = playGraph.triplets.map(triplet => triplet.srcAttr.name).distinct
winners: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[201] at distinct at <console>:65
    scala> winners.foreach(println)
      Kei Nishikori    
      Stan Wawrinka    
      Andy Murray    
      Roger Federer    
      Rafael Nadal    
      Novak Djokovic
    scala> //List of players who have lost at least one match
	scala> val loosers = playGraph.triplets.map(triplet => triplet.dstAttr.name).distinct
loosers: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[205] at distinct at <console>:65
    scala> loosers.foreach(println)
      Novak Djokovic    
      Kei Nishikori    
      David Ferrer    
      Stan Wawrinka    
      Andy Murray    
      Roger Federer    
      Rafael Nadal    
      Tomas Berdych
    scala> //List of players who have won at least one match and lost at least one match
	scala> val wonAndLost = winners.intersection(loosers)
wonAndLost: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[211] at intersection at <console>:69
    scala> wonAndLost.foreach(println)
      Novak Djokovic    
      Rafael Nadal    
      Andy Murray    
      Roger Federer    
      Kei Nishikori    
      Stan Wawrinka 
    scala> //List of players who have no wins at all
	scala> val lostAndNoWins = loosers.collect().toSet -- wonAndLost.collect().toSet
lostAndNoWins: 
scala.collection.immutable.Set[String] = Set(David Ferrer, Tomas Berdych)
    scala> lostAndNoWins.foreach(println)
      David Ferrer    
      Tomas Berdych
    scala> //List of players who have no loss at all
	scala> val wonAndNoLosses = winners.collect().toSet -- loosers.collect().toSet
 wonAndNoLosses: 
	  scala.collection.immutable.Set[String] = Set() 
scala> //The val wonAndNoLosses returned an empty set which means that there is no single player in this tournament who have only wins
scala> wonAndNoLosses.foreach(println)

```

在这个用例中，并没有花费太多精力来美化结果，因为它们被简化为简单的 RDD 结构，可以使用本书前几章已经介绍的 RDD 编程技术根据需要进行操作。

Spark 的高度简洁和统一的编程模型，结合 Spark GraphX 库，帮助开发者用很少的代码构建实际用例。这也表明，一旦使用相关数据构建了正确的图形结构，并使用支持的图形操作，就可以揭示隐藏在底层数据中的许多真相。

# 应用 PageRank 算法

由 Sergey Brin 和 Lawrence Page 撰写的研究论文，题为*The Anatomy of a Large-Scale Hypertextual Web Search Engine*，彻底改变了网络搜索，Google 基于这一 PageRank 概念构建了其搜索引擎，并主导了其他网络搜索引擎。

使用 Google 搜索网页时，其算法排名高的页面会被显示。在图形的上下文中，如果基于相同的算法对顶点进行排名，可以得出许多新的推断。从表面上看，这个 PageRank 算法似乎只对网络搜索有用。但它具有巨大的潜力，可以应用于许多其他领域。

在图形术语中，如果存在一条边 E，连接两个顶点，从 V1 到 V2，根据 PageRank 算法，V2 比 V1 更重要。在一个包含大量顶点和边的巨大图形中，可以计算出每个顶点的 PageRank。

上一节中提到的网球锦标赛分析用例，PageRank 算法可以很好地应用于此。在此采用的图表示中，每场比赛都表示为一个边。源顶点包含获胜者的详细信息，而目标顶点包含失败者的详细信息。在网球比赛中，如果可以将这称为某种虚构的重要性排名，那么在一场比赛中，获胜者的重要性排名高于失败者。

如果在前述用例中采用的图来演示 PageRank 算法，那么该图必须反转，使得每场比赛的获胜者成为每个边的目标顶点。在 Scala REPL 提示符下，尝试以下语句：

```scala
scala> import org.apache.spark._
  import org.apache.spark._ 
  scala> import org.apache.spark.graphx._
  import org.apache.spark.graphx._    
  scala> import org.apache.spark.rdd.RDD
  import org.apache.spark.rdd.RDD
    scala> //Define a property class that is going to hold all the properties of the vertex which is nothing but player informationscala> case class Player(name: String, country: String)
      defined class Player
    scala> // Create the player verticesscala> val players: RDD[(Long, Player)] = sc.parallelize(Array((1L, Player("Novak Djokovic", "SRB")), (3L, Player("Roger Federer", "SUI")),(5L, Player("Tomas Berdych", "CZE")), (7L, Player("Kei Nishikori", "JPN")), (11L, Player("Andy Murray", "GBR")),(15L, Player("Stan Wawrinka", "SUI")),(17L, Player("Rafael Nadal", "ESP")),(19L, Player("David Ferrer", "ESP"))))
players: org.apache.spark.rdd.RDD[(Long, Player)] = ParallelCollectionRDD[212] at parallelize at <console>:64
    scala> //Define a property class that is going to hold all the properties of the edge which is nothing but match informationscala> case class Match(matchType: String, points: Int, head2HeadCount: Int)
      defined class Match
    scala> // Create the match edgesscala> val matches: RDD[Edge[Match]] = sc.parallelize(Array(Edge(1L, 5L, Match("G1", 1,1)), Edge(1L, 7L, Match("G1", 1,1)), Edge(3L, 1L, Match("G1", 1,1)), Edge(3L, 5L, Match("G1", 1,1)), Edge(3L, 7L, Match("G1", 1,1)), Edge(7L, 5L, Match("G1", 1,1)), Edge(11L, 19L, Match("G2", 1,1)), Edge(15L, 11L, Match("G2", 1, 1)), Edge(15L, 19L, Match("G2", 1, 1)), Edge(17L, 11L, Match("G2", 1, 1)), Edge(17L, 15L, Match("G2", 1, 1)), Edge(17L, 19L, Match("G2", 1, 1)), Edge(3L, 15L, Match("S", 5, 1)), Edge(1L, 17L, Match("S", 5, 1)), Edge(1L, 3L, Match("F", 11, 1))))
matches: org.apache.spark.rdd.RDD[org.apache.spark.graphx.Edge[Match]] = ParallelCollectionRDD[213] at parallelize at <console>:64
    scala> //Create a graph with the vertices and edgesscala> val playGraph = Graph(players, matches)
playGraph: org.apache.spark.graphx.Graph[Player,Match] = org.apache.spark.graphx.impl.GraphImpl@263cd0e2
    scala> //Reverse this graph to have the winning player coming in the destination vertex
	scala> val rankGraph = playGraph.reverse
rankGraph: org.apache.spark.graphx.Graph[Player,Match] = org.apache.spark.graphx.impl.GraphImpl@7bb131fb
    scala> //Run the PageRank algorithm to calculate the rank of each vertex
	scala> val rankedVertices = rankGraph.pageRank(0.0001).vertices
rankedVertices: org.apache.spark.graphx.VertexRDD[Double] = VertexRDDImpl[1184] at RDD at VertexRDD.scala:57
    scala> //Extract the vertices sorted by the rank
	scala> val rankedPlayers = rankedVertices.join(players).map{case 
	(id,(importanceRank,Player(name,country))) => (importanceRank,
	name)}.sortByKey(ascending=false)

	rankedPlayers: org.apache.spark.rdd.RDD[(Double, String)] = ShuffledRDD[1193] at sortByKey at <console>:76

	scala> rankedPlayers.collect().foreach(println)
      (3.382662570589846,Novak Djokovic)    
      (3.266079758089846,Roger Federer)    
      (0.3908953124999999,Rafael Nadal)    
      (0.27431249999999996,Stan Wawrinka)    
      (0.1925,Andy Murray)    
      (0.1925,Kei Nishikori)    
      (0.15,David Ferrer)    
      (0.15,Tomas Berdych) 

```

如果仔细审查上述代码，可以看出排名最高的玩家赢得了最多的比赛。

# 连通分量算法

在图中，寻找由相连顶点组成的子图是一个非常常见的需求，具有广泛的应用。在任何图中，两个通过一条或多条边组成的路径相连的顶点，并且不与同一图中的任何其他顶点相连，被称为连通分量。例如，在图 G 中，顶点 V1 通过一条边与 V2 相连，V2 通过另一条边与 V3 相连。在同一图 G 中，顶点 V4 通过另一条边与 V5 相连。在这种情况下，V1 和 V3 相连，V4 和 V5 相连，而 V1 和 V5 不相连。在图 G 中，有两个连通分量。Spark GraphX 库实现了连通分量算法。

在社交网络应用中，如果用户之间的连接被建模为图，那么检查给定用户是否与另一用户相连，可以通过检查这两个顶点是否存在连通分量来实现。在计算机游戏中，从点 A 到点 B 的迷宫穿越可以通过将迷宫交汇点建模为顶点，将连接交汇点的路径建模为图中的边，并使用连通分量算法来实现。

在计算机网络中，检查数据包是否可以从一个 IP 地址发送到另一个 IP 地址，是通过使用连通分量算法实现的。在物流应用中，例如快递服务，检查包裹是否可以从点 A 发送到点 B，也是通过使用连通分量算法实现的。*图 6*展示了一个具有三个连通分量的图：

![连通分量算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_08_006.jpg)

图 6

*图 6*是图的图形表示。其中，有三个*簇*的顶点通过边相连。换句话说，该图中有三个连通分量。

这里再次以社交网络应用中用户相互关注的用例为例，以阐明其原理。通过提取图的连通分量，可以查看任意两个用户是否相连。*图 7* 展示了用户图：

![连通分量算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_08_007.jpg)

图 7

在 *图 7* 所示的图中，很明显可以看出存在两个连通分量。可以轻松判断 Thomas 和 Mathew 相连，而 Thomas 和 Martin 不相连。如果提取连通分量图，可以看到 Thomas 和 Martin 将具有相同的连通分量标识符，同时 Thomas 和 Martin 将具有不同的连通分量标识符。在 Scala REPL 提示符下，尝试以下语句：

```scala
	 scala> import org.apache.spark._

  import org.apache.spark._    
  scala> import org.apache.spark.graphx._

  import org.apache.spark.graphx._    
  scala> import org.apache.spark.rdd.RDD

  import org.apache.spark.rdd.RDD    

  scala> // Create the RDD with users as the vertices
  scala> val users: RDD[(Long, String)] = sc.parallelize(Array((1L, "Thomas"), (2L, "Krish"),(3L, "Mathew"), (4L, "Martin"), (5L, "George"), (6L, "James")))

users: org.apache.spark.rdd.RDD[(Long, String)] = ParallelCollectionRDD[1194] at parallelize at <console>:69

	scala> // Create the edges connecting the users
	scala> val userRelationships: RDD[Edge[String]] = sc.parallelize(Array(Edge(1L, 2L, "Follows"),Edge(2L, 3L, "Follows"), Edge(4L, 5L, "Follows"), Edge(5L, 6L, "Follows")))

userRelationships: org.apache.spark.rdd.RDD[org.apache.spark.graphx.Edge[String]] = ParallelCollectionRDD[1195] at parallelize at <console>:69

	scala> // Create a graph
	scala> val userGraph = Graph(users, userRelationships)

userGraph: org.apache.spark.graphx.Graph[String,String] = org.apache.spark.graphx.impl.GraphImpl@805e363

	scala> // Find the connected components of the graph
	scala> val cc = userGraph.connectedComponents()

cc: org.apache.spark.graphx.Graph[org.apache.spark.graphx.VertexId,String] = org.apache.spark.graphx.impl.GraphImpl@13f4a9a9

	scala> // Extract the triplets of the connected components
	scala> val ccTriplets = cc.triplets

ccTriplets: org.apache.spark.rdd.RDD[org.apache.spark.graphx.EdgeTriplet[org.apache.spark.graphx.VertexId,String]] = MapPartitionsRDD[1263] at mapPartitions at GraphImpl.scala:48

	scala> // Print the structure of the tripletsscala> ccTriplets.foreach(println)
      ((1,1),(2,1),Follows)    

      ((4,4),(5,4),Follows)    

      ((5,4),(6,4),Follows)    

      ((2,1),(3,1),Follows)

	scala> //Print the vertex numbers and the corresponding connected component id. The connected component id is generated by the system and it is to be taken only as a unique identifier for the connected component
	scala> val ccProperties = ccTriplets.map(triplet => "Vertex " + triplet.srcId + " and " + triplet.dstId + " are part of the CC with id " + triplet.srcAttr)

ccProperties: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[1264] at map at <console>:79

	scala> ccProperties.foreach(println)

      Vertex 1 and 2 are part of the CC with id 1    

      Vertex 5 and 6 are part of the CC with id 4    

      Vertex 2 and 3 are part of the CC with id 1    

      Vertex 4 and 5 are part of the CC with id 4

	scala> //Find the users in the source vertex with their CC id
	scala> val srcUsersAndTheirCC = ccTriplets.map(triplet => (triplet.srcId, triplet.srcAttr))

srcUsersAndTheirCC: org.apache.spark.rdd.RDD[(org.apache.spark.graphx.VertexId, org.apache.spark.graphx.VertexId)] = MapPartitionsRDD[1265] at map at <console>:79

	scala> //Find the users in the destination vertex with their CC id
	scala> val dstUsersAndTheirCC = ccTriplets.map(triplet => (triplet.dstId, triplet.dstAttr))

dstUsersAndTheirCC: org.apache.spark.rdd.RDD[(org.apache.spark.graphx.VertexId, org.apache.spark.graphx.VertexId)] = MapPartitionsRDD[1266] at map at <console>:79

	scala> //Find the union
	scala> val usersAndTheirCC = srcUsersAndTheirCC.union(dstUsersAndTheirCC)

usersAndTheirCC: org.apache.spark.rdd.RDD[(org.apache.spark.graphx.VertexId, org.apache.spark.graphx.VertexId)] = UnionRDD[1267] at union at <console>:83

	scala> //Join with the name of the users
	scala> val usersAndTheirCCWithName = usersAndTheirCC.join(users).map{case (userId,(ccId,userName)) => (ccId, userName)}.distinct.sortByKey()

usersAndTheirCCWithName: org.apache.spark.rdd.RDD[(org.apache.spark.graphx.VertexId, String)] = ShuffledRDD[1277] at sortByKey at <console>:85

	scala> //Print the user names with their CC component id. If two users share the same CC id, then they are connected
	scala> usersAndTheirCCWithName.collect().foreach(println)

      (1,Thomas)    

      (1,Mathew)    

      (1,Krish)    

      (4,Martin)    

      (4,James)    

      (4,George) 

```

Spark GraphX 库中还有一些其他的图处理算法，对完整算法集的详细讨论足以写成一本书。关键在于，Spark GraphX 库提供了非常易于使用的图算法，这些算法很好地融入了 Spark 的统一编程模型。

# 理解 GraphFrames

Spark GraphX 库是支持编程语言最少的图处理库。Scala 是 Spark GraphX 库唯一支持的编程语言。GraphFrames 是由 Databricks、加州大学伯克利分校和麻省理工学院开发的新图处理库，作为外部 Spark 包提供，建立在 Spark DataFrames 之上。由于它是基于 DataFrames 构建的，因此所有可以在 DataFrames 上执行的操作都可能适用于 GraphFrames，支持 Scala、Java、Python 和 R 等编程语言，并具有统一的 API。由于 GraphFrames 基于 DataFrames，因此数据的持久性、对多种数据源的支持以及在 Spark SQL 中强大的图查询功能是用户免费获得的额外好处。

与 Spark GraphX 库类似，在 GraphFrames 中，数据存储在顶点和边中。顶点和边使用 DataFrames 作为数据结构。本章开头介绍的第一个用例再次用于阐明基于 GraphFrames 的图处理。

### 注意

**注意**：GraphFrames 是外部 Spark 包。它与 Spark 2.0 存在一些不兼容。因此，以下代码片段不适用于 Spark 2.0。它们适用于 Spark 1.6。请访问他们的网站以检查 Spark 2.0 支持情况。

在 Spark 1.6 的 Scala REPL 提示符下，尝试以下语句。由于 GraphFrames 是外部 Spark 包，在启动相应的 REPL 时，需要导入库，并在终端提示符下使用以下命令启动 REPL，确保库加载无误：

```scala
	 $ cd $SPARK_1.6__HOME 
	$ ./bin/spark-shell --packages graphframes:graphframes:0.1.0-spark1.6 
	Ivy Default Cache set to: /Users/RajT/.ivy2/cache 
	The jars for the packages stored in: /Users/RajT/.ivy2/jars 
	:: loading settings :: url = jar:file:/Users/RajT/source-code/spark-source/spark-1.6.1
	/assembly/target/scala-2.10/spark-assembly-1.6.2-SNAPSHOT-hadoop2.2.0.jar!
	/org/apache/ivy/core/settings/ivysettings.xml 
	graphframes#graphframes added as a dependency 
	:: resolving dependencies :: org.apache.spark#spark-submit-parent;1.0 
	confs: [default] 
	found graphframes#graphframes;0.1.0-spark1.6 in list 
	:: resolution report :: resolve 153ms :: artifacts dl 2ms 
	:: modules in use: 
	graphframes#graphframes;0.1.0-spark1.6 from list in [default] 
   --------------------------------------------------------------------- 
   |                  |            modules            ||   artifacts   | 
   |       conf       | number| search|dwnlded|evicted|| number|dwnlded| 
   --------------------------------------------------------------------- 
   |      default     |   1   |   0   |   0   |   0   ||   1   |   0   | 
   --------------------------------------------------------------------- 
   :: retrieving :: org.apache.spark#spark-submit-parent 
   confs: [default] 
   0 artifacts copied, 1 already retrieved (0kB/5ms) 
   16/07/31 09:22:11 WARN NativeCodeLoader: Unable to load native-hadoop library for your platform... using builtin-java classes where applicable 
   Welcome to 
      ____              __ 
     / __/__  ___ _____/ /__ 
    _\ \/ _ \/ _ `/ __/  '_/ 
   /___/ .__/\_,_/_/ /_/\_\   version 1.6.1 
       /_/ 

	  Using Scala version 2.10.5 (Java HotSpot(TM) 64-Bit Server VM, Java 1.8.0_66) 
	  Type in expressions to have them evaluated. 
	  Type :help for more information. 
	  Spark context available as sc. 
	  SQL context available as sqlContext. 
	  scala> import org.graphframes._ 
	  import org.graphframes._ 
	  scala> import org.apache.spark.rdd.RDD 
	  import org.apache.spark.rdd.RDD 
	  scala> import org.apache.spark.sql.Row 
	  import org.apache.spark.sql.Row 
	  scala> import org.apache.spark.graphx._ 
	  import org.apache.spark.graphx._ 
	  scala> //Create a DataFrame of users containing tuple values with a mandatory Long and another String type as the property of the vertex 
	  scala> val users = sqlContext.createDataFrame(List((1L, "Thomas"),(2L, "Krish"),(3L, "Mathew"))).toDF("id", "name") 
	  users: org.apache.spark.sql.DataFrame = [id: bigint, name: string] 
	  scala> //Created a DataFrame for Edge with String type as the property of the edge 
	  scala> val userRelationships = sqlContext.createDataFrame(List((1L, 2L, "Follows"),(1L, 2L, "Son"),(2L, 3L, "Follows"))).toDF("src", "dst", "relationship") 
	  userRelationships: org.apache.spark.sql.DataFrame = [src: bigint, dst: bigint, relationship: string] 
	  scala> val userGraph = GraphFrame(users, userRelationships) 
	  userGraph: org.graphframes.GraphFrame = GraphFrame(v:[id: bigint, name: string], e:[src: bigint, dst: bigint, relationship: string]) 
	  scala> // Vertices in the graph 
	  scala> userGraph.vertices.show() 
	  +---+------+ 
	  | id|  name| 
	  +---+------+ 
	  |  1|Thomas| 
	  |  2| Krish| 
	  |  3|Mathew| 
	  +---+------+ 
	  scala> // Edges in the graph 
	  scala> userGraph.edges.show() 
	  +---+---+------------+ 
	  |src|dst|relationship| 
	  +---+---+------------+ 
	  |  1|  2|     Follows| 
	  |  1|  2|         Son| 
	  |  2|  3|     Follows| 
	  +---+---+------------+ 
	  scala> //Number of edges in the graph 
	  scala> val edgeCount = userGraph.edges.count() 
	  edgeCount: Long = 3 
	  scala> //Number of vertices in the graph 
	  scala> val vertexCount = userGraph.vertices.count() 
	  vertexCount: Long = 3 
	  scala> //Number of edges coming to each of the vertex.  
	  scala> userGraph.inDegrees.show() 
	  +---+--------+ 
	  | id|inDegree| 
	  +---+--------+ 
	  |  2|       2| 
	  |  3|       1| 
	  +---+--------+ 
	  scala> //Number of edges going out of each of the vertex.  
	  scala> userGraph.outDegrees.show() 
	  +---+---------+ 
	  | id|outDegree| 
	  +---+---------+ 
	  |  1|        2| 
	  |  2|        1| 
	  +---+---------+ 
	  scala> //Total number of edges coming in and going out of each vertex.  
	  scala> userGraph.degrees.show() 
	  +---+------+ 
	  | id|degree| 
	  +---+------+ 
	  |  1|     2| 
	  |  2|     3| 
	  |  3|     1| 
	  +---+------+ 
	  scala> //Get the triplets of the graph 
	  scala> userGraph.triplets.show() 
	  +-------------+----------+----------+ 
	  |         edge|       src|       dst| 
	  +-------------+----------+----------+ 
	  |[1,2,Follows]|[1,Thomas]| [2,Krish]| 
	  |    [1,2,Son]|[1,Thomas]| [2,Krish]| 
	  |[2,3,Follows]| [2,Krish]|[3,Mathew]| 
	  +-------------+----------+----------+ 
	  scala> //Using the DataFrame API, apply filter and select only the needed edges 
	  scala> val numFollows = userGraph.edges.filter("relationship = 'Follows'").count() 
	  numFollows: Long = 2 
	  scala> //Create an RDD of users containing tuple values with a mandatory Long and another String type as the property of the vertex 
	  scala> val usersRDD: RDD[(Long, String)] = sc.parallelize(Array((1L, "Thomas"), (2L, "Krish"),(3L, "Mathew"))) 
	  usersRDD: org.apache.spark.rdd.RDD[(Long, String)] = ParallelCollectionRDD[54] at parallelize at <console>:35 
	  scala> //Created an RDD of Edge type with String type as the property of the edge 
	  scala> val userRelationshipsRDD: RDD[Edge[String]] = sc.parallelize(Array(Edge(1L, 2L, "Follows"),    Edge(1L, 2L, "Son"),Edge(2L, 3L, "Follows"))) 
	  userRelationshipsRDD: org.apache.spark.rdd.RDD[org.apache.spark.graphx.Edge[String]] = ParallelCollectionRDD[55] at parallelize at <console>:35 
	  scala> //Create a graph containing the vertex and edge RDDs as created before 
	  scala> val userGraphXFromRDD = Graph(usersRDD, userRelationshipsRDD) 
	  userGraphXFromRDD: org.apache.spark.graphx.Graph[String,String] = 
	  org.apache.spark.graphx.impl.GraphImpl@77a3c614 
	  scala> //Create the GraphFrame based graph from Spark GraphX based graph 
	  scala> val userGraphFrameFromGraphX: GraphFrame = GraphFrame.fromGraphX(userGraphXFromRDD) 
	  userGraphFrameFromGraphX: org.graphframes.GraphFrame = GraphFrame(v:[id: bigint, attr: string], e:[src: bigint, dst: bigint, attr: string]) 
	  scala> userGraphFrameFromGraphX.triplets.show() 
	  +-------------+----------+----------+
	  |         edge|       src|       dst| 
	  +-------------+----------+----------+ 
	  |[1,2,Follows]|[1,Thomas]| [2,Krish]| 
	  |    [1,2,Son]|[1,Thomas]| [2,Krish]| 
	  |[2,3,Follows]| [2,Krish]|[3,Mathew]| 
	  +-------------+----------+----------+ 
	  scala> // Convert the GraphFrame based graph to a Spark GraphX based graph 
	  scala> val userGraphXFromGraphFrame: Graph[Row, Row] = userGraphFrameFromGraphX.toGraphX 
	  userGraphXFromGraphFrame: org.apache.spark.graphx.Graph[org.apache.spark.sql.Row,org.apache.spark.sql.Row] = org.apache.spark.graphx.impl.GraphImpl@238d6aa2 

```

在为 GraphFrame 创建 DataFrames 时，唯一需要注意的是，对于顶点和边有一些强制性列。在顶点的 DataFrame 中，id 列是强制性的。在边的 DataFrame 中，src 和 dst 列是强制性的。除此之外，可以在 GraphFrame 的顶点和边上存储任意数量的任意列。在 Spark GraphX 库中，顶点标识符必须是长整型，但 GraphFrame 没有这样的限制，任何类型都可以作为顶点标识符。读者应该已经熟悉 DataFrames；任何可以在 DataFrame 上执行的操作都可以在 GraphFrame 的顶点和边上执行。

### 提示

所有 Spark GraphX 支持的图处理算法，GraphFrames 也同样支持。

GraphFrames 的 Python 版本功能较少。由于 Python 不是 Spark GraphX 库支持的编程语言，因此在 Python 中不支持 GraphFrame 与 GraphX 之间的转换。鉴于读者熟悉使用 Python 在 Spark 中创建 DataFrames，此处省略了 Python 示例。此外，GraphFrames API 的 Python 版本存在一些待解决的缺陷，并且在撰写本文时，并非所有之前在 Scala 中演示的功能都能在 Python 中正常工作。

# 理解 GraphFrames 查询

Spark GraphX 库是基于 RDD 的图处理库，而 GraphFrames 是作为外部包提供的基于 Spark DataFrame 的图处理库。Spark GraphX 支持多种图处理算法，但 GraphFrames 不仅支持图处理算法，还支持图查询。图处理算法与图查询之间的主要区别在于，图处理算法用于处理图数据结构中隐藏的数据，而图查询用于搜索图数据结构中隐藏的数据中的模式。在 GraphFrame 术语中，图查询也称为模式查找。这在涉及序列模式的遗传学和其他生物科学中具有巨大的应用价值。

从用例角度出发，以社交媒体应用中用户相互关注为例。用户之间存在关系。在前述章节中，这些关系被建模为图。在现实世界的用例中，此类图可能变得非常庞大，如果需要找到在两个方向上存在关系的用户，这可以通过图查询中的模式来表达，并使用简单的编程结构来找到这些关系。以下演示模型展示了用户间关系在 GraphFrame 中的表示，并利用该模型进行了模式搜索。

在 Spark 1.6 的 Scala REPL 提示符下，尝试以下语句：

```scala
 $ cd $SPARK_1.6_HOME 
	  $ ./bin/spark-shell --packages graphframes:graphframes:0.1.0-spark1.6 
	  Ivy Default Cache set to: /Users/RajT/.ivy2/cache 
	  The jars for the packages stored in: /Users/RajT/.ivy2/jars 
	  :: loading settings :: url = jar:file:/Users/RajT/source-code/spark-source/spark-1.6.1/assembly/target/scala-2.10/spark-assembly-1.6.2-SNAPSHOT-hadoop2.2.0.jar!/org/apache/ivy/core/settings/ivysettings.xml 
	  graphframes#graphframes added as a dependency 
	  :: resolving dependencies :: org.apache.spark#spark-submit-parent;1.0 
	  confs: [default] 
	  found graphframes#graphframes;0.1.0-spark1.6 in list 
	  :: resolution report :: resolve 145ms :: artifacts dl 2ms 
	  :: modules in use: 
	  graphframes#graphframes;0.1.0-spark1.6 from list in [default] 
	  --------------------------------------------------------------------- 
	  |                  |            modules            ||   artifacts   | 
	  |       conf       | number| search|dwnlded|evicted|| number|dwnlded| 
	  --------------------------------------------------------------------- 
	  |      default     |   1   |   0   |   0   |   0   ||   1   |   0   | 
	  --------------------------------------------------------------------- 
	  :: retrieving :: org.apache.spark#spark-submit-parent 
	  confs: [default] 
	  0 artifacts copied, 1 already retrieved (0kB/5ms) 
	  16/07/29 07:09:08 WARN NativeCodeLoader: 
	  Unable to load native-hadoop library for your platform... using builtin-java classes where applicable 
	  Welcome to 
      ____              __ 
     / __/__  ___ _____/ /__ 
    _\ \/ _ \/ _ `/ __/  '_/ 
   /___/ .__/\_,_/_/ /_/\_\   version 1.6.1 
      /_/ 

	  Using Scala version 2.10.5 (Java HotSpot(TM) 64-Bit Server VM, Java 1.8.0_66) 
	  Type in expressions to have them evaluated. 
	  Type :help for more information. 
	  Spark context available as sc. 
	  SQL context available as sqlContext. 
	  scala> import org.graphframes._ 
	  import org.graphframes._ 
	  scala> import org.apache.spark.rdd.RDD 
	  import org.apache.spark.rdd.RDD 
	  scala> import org.apache.spark.sql.Row 
	  import org.apache.spark.sql.Row 
	  scala> import org.apache.spark.graphx._ 
	  import org.apache.spark.graphx._ 
	  scala> //Create a DataFrame of users containing tuple values with a mandatory String field as id and another String type as the property of the vertex. Here it can be seen that the vertex identifier is no longer a long integer. 
	  scala> val users = sqlContext.createDataFrame(List(("1", "Thomas"),("2", "Krish"),("3", "Mathew"))).toDF("id", "name") 
	  users: org.apache.spark.sql.DataFrame = [id: string, name: string] 
	  scala> //Create a DataFrame for Edge with String type as the property of the edge 
	  scala> val userRelationships = sqlContext.createDataFrame(List(("1", "2", "Follows"),("2", "1", "Follows"),("2", "3", "Follows"))).toDF("src", "dst", "relationship") 
	  userRelationships: org.apache.spark.sql.DataFrame = [src: string, dst: string, relationship: string] 
	  scala> //Create the GraphFrame 
	  scala> val userGraph = GraphFrame(users, userRelationships) 
	  userGraph: org.graphframes.GraphFrame = GraphFrame(v:[id: string, name: string], e:[src: string, dst: string, relationship: string]) 
	  scala> // Search for pairs of users who are following each other 
	  scala> // In other words the query can be read like this. Find the list of users having a pattern such that user u1 is related to user u2 using the edge e1 and user u2 is related to the user u1 using the edge e2\. When a query is formed like this, the result will list with columns u1, u2, e1 and e2\. When modelling real-world use cases, more meaningful variables can be used suitable for the use case. 
	  scala> val graphQuery = userGraph.find("(u1)-[e1]->(u2); (u2)-[e2]->(u1)") 
	  graphQuery: org.apache.spark.sql.DataFrame = [e1: struct<src:string,dst:string,relationship:string>, u1: struct<
	  d:string,name:string>, u2: struct<id:string,name:string>, e2: struct<src:string,dst:string,relationship:string>] 
	  scala> graphQuery.show() 
	  +-------------+----------+----------+-------------+

	  |           e1|        u1|        u2|           e2| 
	  +-------------+----------+----------+-------------+ 
	  |[1,2,Follows]|[1,Thomas]| [2,Krish]|[2,1,Follows]| 
	  |[2,1,Follows]| [2,Krish]|[1,Thomas]|[1,2,Follows]| 
	  +-------------+----------+----------+-------------+

```

请注意，图查询结果中的列是由搜索模式中给出的元素构成的。形成模式的方式没有限制。

### 注意

注意图查询结果的数据类型。它是一个 DataFrame 对象。这为使用熟悉的 Spark SQL 库处理查询结果带来了极大的灵活性。

Spark GraphX 库的最大限制是其 API 目前不支持 Python 和 R 等编程语言。由于 GraphFrames 是基于 DataFrame 的库，一旦成熟，它将使所有支持 DataFrame 的编程语言都能进行图处理。这个 Spark 外部包无疑是未来可能被纳入 Spark 的一部分的有力候选。

# 参考文献

如需了解更多信息，请访问以下链接：

+   [`spark.apache.org/docs/1.5.2/graphx-programming-guide.html`](https://spark.apache.org/docs/1.5.2/graphx-programming-guide.html)

+   [`en.wikipedia.org/wiki/2015_ATP_World_Tour_Finals_%E2%80%93_Singles`](https://en.wikipedia.org/wiki/2015_ATP_World_Tour_Finals_%E2%80%93_Singles)

+   [`www.protennislive.com/posting/2015/605/mds.pdf`](http://www.protennislive.com/posting/2015/605/mds.pdf)

+   [`infolab.stanford.edu/~backrub/google.html`](http://infolab.stanford.edu/~backrub/google.html)

+   [`graphframes.github.io/index.html`](http://graphframes.github.io/index.html)

+   [`github.com/graphframes/graphframes`](https://github.com/graphframes/graphframes)

+   [`spark-packages.org/package/graphframes/graphframes`](https://spark-packages.org/package/graphframes/graphframes)

# 总结

图是一种非常有用的数据结构，具有广泛的应用潜力。尽管在大多数应用中不常使用，但在某些独特的应用场景中，使用图作为数据结构是必不可少的。只有当数据结构与经过充分测试和高度优化的算法结合使用时，才能有效地使用它。数学家和计算机科学家已经提出了许多处理图数据结构中数据的算法。Spark GraphX 库在 Spark 核心之上实现了大量此类算法。本章通过入门级别的用例对 Spark GraphX 库进行了快速概览，并介绍了一些基础知识。

基于 DataFrame 的图抽象名为 GraphFrames，它是 Spark 的一个外部包，可单独获取，在图处理和图查询方面具有巨大潜力。为了进行图查询以发现图中的模式，已提供了对该外部 Spark 包的简要介绍。

任何教授新技术的书籍都应以一个涵盖其显著特点的应用案例作为结尾。Spark 也不例外。到目前为止，本书已经介绍了 Spark 作为下一代数据处理平台的特性。现在是时候收尾并构建一个端到端应用了。下一章将涵盖使用 Spark 及其上层构建的库家族设计和开发数据处理应用的内容。
