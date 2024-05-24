# Spark 机器学习（四）

> 原文：[`zh.annas-archive.org/md5/7A35D303E4132E910DFC5ADB5679B82A`](https://zh.annas-archive.org/md5/7A35D303E4132E910DFC5ADB5679B82A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 Spark 构建回归模型

在本章中，我们将继续探讨第六章中涵盖的内容，*使用 Spark 构建分类模型*。虽然分类模型处理代表离散类别的结果，但回归模型涉及可以取任何实际值的目标变量。基本原理非常相似--我们希望找到一个将输入特征映射到预测目标变量的模型。与分类一样，回归也是一种监督学习形式。

回归模型可用于预测几乎任何感兴趣的变量。一些例子包括以下内容：

+   预测股票回报和其他经济变量

+   预测贷款违约损失金额（这可以与预测违约概率的分类模型相结合，而回归模型则在违约情况下预测金额）

+   推荐（来自第五章的交替最小二乘因子化模型，*使用 Spark 构建推荐引擎*，在每次迭代中使用线性回归）

+   基于用户行为和消费模式，在零售、移动或其他业务中预测**客户终身价值**（**CLTV**）

在本章的不同部分，我们将做以下工作：

+   介绍 ML 中可用的各种回归模型

+   探索回归模型的特征提取和目标变量转换

+   使用 ML 训练多个回归模型

+   查看如何使用训练好的模型进行预测

+   使用交叉验证调查回归的各种参数设置对性能的影响

# 回归模型的类型

线性模型（或广义线性模型）的核心思想是，我们将感兴趣的预测结果（通常称为目标或因变量）建模为应用于输入变量（也称为特征或自变量）的简单线性预测器的函数。

*y = f(w^Tx)*

在这里，*y*是目标变量，*w*是参数向量（称为权重向量），*x*是输入特征向量。

*w^Tx*是权重向量*w*和特征向量*x*的线性预测器（或向量点积）。对于这个线性预测器，我们应用了一个函数*f*（称为链接函数）。

线性模型实际上可以通过改变链接函数来用于分类和回归，标准线性回归使用恒等链接（即*y = w^Tx*直接），而二元分类使用其他链接函数，如本文所述。

Spark 的 ML 库提供了不同的回归模型，如下所示：

+   线性回归

+   广义线性回归

+   逻辑回归

+   决策树

+   随机森林回归

+   梯度提升树

+   生存回归

+   等温回归

+   岭回归

回归模型定义了因变量和一个或多个自变量之间的关系。它构建了最适合独立变量或特征值的模型。

与支持向量机和逻辑回归等分类模型不同，线性回归用于预测具有广义值的因变量的值，而不是预测确切的类标签。

线性回归模型本质上与其分类对应物相同，唯一的区别是线性回归模型使用不同的损失函数、相关链接函数和决策函数。Spark ML 提供了标准的最小二乘回归模型（尽管计划使用其他类型的广义线性回归模型进行回归）。

# 最小二乘回归

你可能还记得第六章《使用 Spark 构建分类模型》中提到，广义线性模型可以应用各种损失函数。最小二乘法使用的损失函数是平方损失，定义如下：

*½ (w^Tx - y)²*

在这里，与分类设置一样，*y*是目标变量（这次是实值），*w*是权重向量，*x*是特征向量。

相关的链接函数是恒等链接，决策函数也是恒等函数，通常在回归中不会应用阈值。因此，模型的预测简单地是*y = w^Tx*。

ML 库中的标准最小二乘回归不使用正则化。正则化用于解决过拟合问题。观察平方损失函数，我们可以看到对于错误预测的点，损失会被放大，因为损失被平方了。这意味着最小二乘回归容易受到数据集中的异常值和过拟合的影响。通常，对于分类问题，我们应该在实践中应用一定程度的正则化。

带有 L2 正则化的线性回归通常称为岭回归，而应用 L1 正则化称为套索。

当数据集较小或示例数量较少时，模型过拟合的倾向非常高，因此强烈建议使用 L1、L2 或弹性网络等正则化器。

有关 Spark MLlib 文档中线性最小二乘法的部分，请参阅[`spark.apache.org/docs/latest/mllib-linear-methods.html#linear-least-squares-lasso-and-ridge-regression`](http://spark.apache.org/docs/latest/mllib-linear-methods.html#linear-least-squares-lasso-and-ridge-regression)以获取更多信息。

# 回归的决策树

就像使用线性模型进行回归任务需要改变使用的损失函数一样，使用决策树进行回归需要改变使用的节点不纯度度量。不纯度度量称为**方差**，定义方式与最小二乘线性回归的平方损失相同。

有关决策树算法和回归不纯度度量的更多详细信息，请参阅 Spark 文档中的*MLlib - 决策树*部分[`spark.apache.org/docs/latest/mllib-decision-tree.html`](http://spark.apache.org/docs/latest/mllib-decision-tree.html)。

现在，我们将绘制一个只有一个输入变量的回归问题的简单示例，横轴显示在*x*轴上，目标变量显示在*y*轴上。线性模型的预测函数由红色虚线表示，而决策树的预测函数由绿色虚线表示。我们可以看到决策树允许将更复杂、非线性的模型拟合到数据中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_001.png)

# 评估回归模型的性能

我们在第六章《使用 Spark 构建分类模型》中看到，分类模型的评估方法通常侧重于与实际类成员关联的预测类成员相关的测量。这些是二元结果（预测类是否正确），模型是否刚好预测正确并不那么重要；我们最关心的是正确和错误预测的数量。

在处理回归模型时，我们很少能够精确预测目标变量，因为目标变量可以取任意实值。然而，我们自然希望了解我们的预测值与真实值的偏差有多大，因此我们将利用一个考虑整体偏差的度量。

用于衡量回归模型性能的一些标准评估指标包括**均方误差**（**MSE**）和**均方根误差**（**RMSE**），**平均绝对误差**（**MAE**），R 平方系数等等。

# 均方误差和均方根误差

MSE 是用作最小二乘回归的损失函数的平方误差的平均值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_002.jpg)

它是所有数据点的预测值和实际目标变量之间差异的平方之和，除以数据点的数量。

RMSE 是 MSE 的平方根。MSE 以目标变量的平方为单位进行测量，而 RMSE 以与目标变量相同的单位进行测量。由于其公式，MSE，就像它导出的平方损失函数一样，有效地严厉地惩罚更大的误差。

为了评估基于误差度量的平均预测，我们将首先对`LabeledPoint`实例的 RDD 中的每个输入特征向量进行预测，通过使用一个函数计算每个记录的误差，该函数将预测值和真实目标值作为输入。这将返回一个包含误差值的`[Double]` RDD。然后我们可以使用包含双精度值的 RDD 的平均方法找到平均值。

让我们定义我们的平方误差函数如下：

```scala
Scala  
def squaredError(actual:Double, pred : Double) : Double = { 
  return Math.pow( (pred - actual), 2.0) 
} 

```

# 平均绝对误差

MAE 是预测值和实际目标之间绝对差异的平均值，表示如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_003.png)

MAE 在原则上类似于 MSE，但它不像 MSE 那样严厉地惩罚大偏差。

我们计算 MAE 的函数如下：

```scala
Scala 
def absError(actual:Double, pred: Double) : Double = { 
  return Math.abs( (pred - actual)) 
} 

```

# 均方根对数误差

这个测量并不像 MSE 和 MAE 那样被广泛使用，但它被用作使用自行车共享数据集的 Kaggle 竞赛的度量标准。实际上，它是对预测值和目标值进行对数变换后的 RMSE。当目标变量的范围很大，并且在预测值和目标值本身很高时，您不一定希望惩罚大误差时，这个测量是有用的。当您关心百分比误差而不是绝对误差的值时，它也是有效的。

Kaggle 竞赛评估页面可以在[`www.kaggle.com/c/bike-sharing-demand/details/evaluation`](https://www.kaggle.com/c/bike-sharing-demand/details/evaluation)找到。

计算 RMSLE 的函数如下所示：

```scala
Scala 
def squaredLogError(actual:Double, pred : Double) : Double = { 
  return Math.pow( (Math.log(pred +1) - Math.log(actual +1)), 2.0) 
} 

```

# R 平方系数

R 平方系数，也称为确定系数，是衡量模型拟合数据集的程度的指标。它通常用于统计学。它衡量目标变量的变化程度;这是由输入特征的变化来解释的。R 平方系数通常取 0 到 1 之间的值，其中 1 等于模型的完美拟合。

# 从数据中提取正确的特征

由于回归的基础模型与分类情况相同，我们可以使用相同的方法来创建输入特征。唯一的实际区别是目标现在是一个实值变量，而不是一个分类变量。ML 库中的`LabeledPoint`类已经考虑到了这一点，因为`label`字段是`Double`类型，所以它可以处理这两种情况。

# 从自行车共享数据集中提取特征

为了说明本章中的概念，我们将使用自行车共享数据集。该数据集包含自行车共享系统中每小时自行车租赁数量的记录。它还包含与日期、时间、天气、季节和假日信息相关的变量。

数据集可在[`archive.ics.uci.edu/ml/datasets/Bike+Sharing+Dataset`](http://archive.ics.uci.edu/ml/datasets/Bike+Sharing+Dataset)找到。

点击数据文件夹链接，然后下载`Bike-Sharing-Dataset.zip`文件。

自行车共享数据是由波尔图大学的 Hadi Fanaee-T 丰富了天气和季节数据，并在以下论文中使用：

Fanaee-T，Hadi 和 Gama Joao，事件标签组合集成检测器和背景知识，*人工智能进展*，第 1-15 页，斯普林格柏林海德堡，2013 年。

该论文可在[`link.springer.com/article/10.1007%2Fs13748-013-0040-3`](http://link.springer.com/article/10.1007%2Fs13748-013-0040-3)找到。

一旦你下载了`Bike-Sharing-Dataset.zip`文件，解压它。这将创建一个名为`Bike-Sharing-Dataset`的目录，其中包含`day.csv`、`hour.csv`和`Readme.txt`文件。

`Readme.txt`文件包含有关数据集的信息，包括变量名称和描述。看一下文件，你会发现我们有以下可用的变量：

+   `instant`：这是记录 ID

+   `dteday`：这是原始日期

+   `season`：这指的是不同的季节，如春季、夏季、冬季和秋季

+   `yr`：这是年份（2011 或 2012）

+   `mnth`：这是一年中的月份

+   `hr`：这是一天中的小时

+   `holiday`：这显示这一天是否是假日

+   `weekday`：这是一周的某一天

+   `workingday`：这指的是这一天是否是工作日

+   `weathersit`：这是描述特定时间天气的分类变量

+   `temp`：这是标准化的温度

+   `atemp`：这是标准化的体感温度

+   `hum`：这是标准化的湿度

+   风速：这是标准化的风速

+   `cnt`：这是目标变量，即该小时的自行车租赁次数

我们将使用`hour.csv`中包含的每小时数据。如果你看一下数据集的第一行，你会发现它包含列名作为标题。以下代码片段打印标题和前 20 条记录：

```scala
val spark = SparkSession 
  .builder 
  .appName("BikeSharing") 
  .master("local[1]") 
  .getOrCreate() 

// read from csv 
val df = spark.read.format("csv").option("header", 
   "true").load("/dataset/BikeSharing/hour.csv") 
df.cache() 

df.registerTempTable("BikeSharing") 
print(df.count()) 

spark.sql("SELECT * FROM BikeSharing").show() 

```

前面的代码片段应该输出以下结果：

```scala
 root
 |-- instant: integer (nullable = true)
 |-- dteday: timestamp (nullable = true)
 |-- season: integer (nullable = true)
 |-- yr: integer (nullable = true)
 |-- mnth: integer (nullable = true)
 |-- hr: integer (nullable = true)
 |-- holiday: integer (nullable = true)
 |-- weekday: integer (nullable = true)
 |-- workingday: integer (nullable = true)
 |-- weathersit: integer (nullable = true)
 |-- temp: double (nullable = true)
 |-- atemp: double (nullable = true)
 |-- hum: double (nullable = true)
 |-- windspeed: double (nullable = true)
 |-- casual: integer (nullable = true)
 |-- registered: integer (nullable = true)
 |-- cnt: integer (nullable = true)

```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_004.png)

我们将使用 Scala 来演示本章的示例。本章的源代码可以在以下位置找到[`github.com/ml-resources/spark-ml/tree/branch-ed2/Chapter_07`](https://github.com/ml-resources/spark-ml/tree/branch-ed2/Chapter_07)。

我们将像往常一样加载数据集并对其进行检查；从前一个数据框中获取记录计数如下：

```scala
print(df.count()) 

```

这应该输出以下结果：

```scala
    17,379

```

所以，我们的数据集中有 17,379 条每小时的记录。我们已经检查了列名。我们将忽略记录 ID 和原始日期列。我们还将忽略`casual`和`registered`计数目标变量，并专注于总计变量`cnt`（这是其他两个计数的总和）。我们剩下 12 个变量。前 8 个是分类的，而最后 4 个是标准化的实值变量。

```scala
// drop record id, date, casual and registered columns 
val df1 = 
   df.drop("instant").drop("dteday").drop("casual")
   .drop("registered") 
df1.printSchema() 

```

这段代码的最后一部分应该输出以下结果：

```scala
 root
 |-- season: integer (nullable = true)
 |-- yr: integer (nullable = true)
 |-- mnth: integer (nullable = true)
 |-- hr: integer (nullable = true)
 |-- holiday: integer (nullable = true)
 |-- weekday: integer (nullable = true)
 |-- workingday: integer (nullable = true)
 |-- weathersit: integer (nullable = true)
 |-- temp: double (nullable = true)
 |-- atemp: double (nullable = true)
 |-- hum: double (nullable = true)
 |-- windspeed: double (nullable = true)
 |-- cnt: integer (nullable = true)

```

所有列都被转换为 double；以下代码片段显示了如何做到这一点：

```scala
// convert to double: season,yr,mnth,hr,holiday,weekday,workingday,weathersit,temp,atemp,hum,windspeed,casual,registered,cnt 
val df2 = df1.withColumn("season", 
   df1("season").cast("double")).withColumn("yr", 
   df1("yr").cast("double")) 
  .withColumn("mnth", df1("mnth").cast("double")).withColumn("hr", 
     df1("hr").cast("double")).withColumn("holiday", 
     df1("holiday").cast("double")) 
  .withColumn("weekday", 
     df1("weekday").cast("double")).withColumn("workingday", 
     df1("workingday").cast("double")).withColumn("weathersit", 
     df1("weathersit").cast("double")) 
  .withColumn("temp", 
     df1("temp").cast("double")).withColumn("atemp", 
     df1("atemp").cast("double")).withColumn("hum", 
     df1("hum").cast("double")) 
  .withColumn("windspeed", 
     df1("windspeed").cast("double")).withColumn("label", 
     df1("label").cast("double")) 

df2.printSchema() 

```

前面的代码应该输出以下结果：

```scala
 root
 |-- season: double (nullable = true)
 |-- yr: double (nullable = true)
 |-- mnth: double (nullable = true)
 |-- hr: double (nullable = true)
 |-- holiday: double (nullable = true)
 |-- weekday: double (nullable = true)
 |-- workingday: double (nullable = true)
 |-- weathersit: double (nullable = true)
 |-- temp: double (nullable = true)
 |-- atemp: double (nullable = true)
 |-- hum: double (nullable = true)
 |-- windspeed: double (nullable = true)
 |-- label: double (nullable = true)

```

自行车共享数据集是分类的，需要使用**向量组装器**和**向量索引器**进行处理，如下所述：

+   向量组装器是一个转换器，它将一系列列组合成单个向量列。它将原始特征组合成特征向量，以便训练线性回归和决策树等 ML 模型。

+   向量索引器索引从向量组装器传递的分类特征。它会自动决定哪些特征是分类的，并将实际值转换为类别索引。

在我们的情况下，df2 中除了`label`之外的所有列都被`VectorAssembler`转换为`rawFeatures`。

给定类型为`Vector`的输入列和名为`maxCategories`的`param`，它根据不同的值决定哪些特征应该是分类的，其中最多有`maxCategories`的特征被声明为分类的。

```scala
// drop label and create feature vector 
val df3 = df2.drop("label") 
val featureCols = df3.columns 

val vectorAssembler = new 
   VectorAssembler().setInputCols(featureCols)
   .setOutputCol("rawFeatures") 
val vectorIndexer = new 
   VectorIndexer().setInputCol("rawFeatures")
   .setOutputCol("features").setMaxCategories(4) 

```

完整的代码清单可在[`github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/BikeSharingExecutor.scala`](https://github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/BikeSharingExecutor.scala)找到。

# 训练和使用回归模型

回归模型的训练遵循与分类模型相同的程序。我们只需将训练数据传递给相关的训练方法。

# BikeSharingExecutor

`BikeSharingExecutor`对象可用于选择和运行相应的回归模型，例如，要运行`LinearRegression`并执行线性回归管道，将程序参数设置为`LR_<type>`，其中`type`是数据格式；对于其他命令，请参考以下代码片段：

```scala
def executeCommand(arg: String, vectorAssembler: VectorAssembler, 
   vectorIndexer: VectorIndexer, dataFrame: DataFrame, spark: 
   SparkSession) = arg match { 
    case "LR_Vectors" => 
     LinearRegressionPipeline.linearRegressionWithVectorFormat
     (vectorAssembler, vectorIndexer, dataFrame) 
    case "LR_SVM" => 
     LinearRegressionPipeline.linearRegressionWithSVMFormat(spark) 

    case "GLR_Vectors" => 
     GeneralizedLinearRegressionPipeline
     .genLinearRegressionWithVectorFormat(vectorAssembler, 
      vectorIndexer, dataFrame) 
    case "GLR_SVM"=> 
     GeneralizedLinearRegressionPipeline
     .genLinearRegressionWithSVMFormat(spark) 

    case "DT_Vectors" => DecisionTreeRegressionPipeline
     .decTreeRegressionWithVectorFormat(vectorAssembler, 
     vectorIndexer, dataFrame) 
    case "DT_SVM"=> 
     GeneralizedLinearRegressionPipeline
     .genLinearRegressionWithSVMFormat(spark) 

    case "RF_Vectors" => 
     RandomForestRegressionPipeline
     .randForestRegressionWithVectorFormat(vectorAssembler, 
     vectorIndexer, dataFrame) 
    case "RF_SVM"=> 
     RandomForestRegressionPipeline
     .randForestRegressionWithSVMFormat(spark) 

    case "GBT_Vectors" => 
     GradientBoostedTreeRegressorPipeline
     .gbtRegressionWithVectorFormat(vectorAssembler, vectorIndexer, 
     dataFrame) 
    case "GBT_SVM"=> 
     GradientBoostedTreeRegressorPipeline
     .gbtRegressionWithSVMFormat(spark) 

} 

```

代码清单可在此链接找到：

[`github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/BikeSharingExecutor.scala`](https://github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/BikeSharingExecutor.scala)

# 在自行车共享数据集上训练回归模型

### 线性回归

线性回归是最常用的算法。回归分析的核心是通过数据图拟合一条直线的任务。线性方程式由*y = c + b*x*描述，其中*y* = 估计的因变量，*c* = 常数，*b* = 回归系数，*x* = 自变量。

让我们通过将自行车共享数据集分为 80%的训练和 20%的测试，使用 Spark 的回归评估器使用`LinearRegression`构建模型，并获得关于测试数据的评估指标。`linearRegressionWithVectorFormat`方法使用分类数据，而`linearRegressionWithSVMFormat`使用`Bike-sharing`数据集的`libsvm`格式。

```scala
def linearRegressionWithVectorFormat(vectorAssembler: 
   VectorAssembler, vectorIndexer: VectorIndexer, dataFrame: 
   DataFrame) = { 
  val lr = new LinearRegression() 
    .setFeaturesCol("features") 
    .setLabelCol("label") 
    .setRegParam(0.1) 
    .setElasticNetParam(1.0) 
    .setMaxIter(10) 

  val pipeline = new Pipeline().setStages(Array(vectorAssembler, 
   vectorIndexer, lr)) 

  val Array(training, test) = dataFrame.randomSplit(Array(0.8, 
   0.2), seed = 12345) 

  val model = pipeline.fit(training) 

  val fullPredictions = model.transform(test).cache() 
  val predictions = 
   fullPredictions.select("prediction").rdd.map(_.getDouble(0)) 
  val labels = 
   fullPredictions.select("label").rdd.map(_.getDouble(0)) 
  val RMSE = new 
   RegressionMetrics(predictions.zip(labels)).rootMeanSquaredError 
  println(s"  Root mean squared error (RMSE): $RMSE") 
} 

def linearRegressionWithSVMFormat(spark: SparkSession) = { 
  // Load training data 
  val training = spark.read.format("libsvm") 
    .load("/dataset/BikeSharing/lsvmHours.txt") 

  val lr = new LinearRegression() 
    .setMaxIter(10) 
    .setRegParam(0.3) 
    .setElasticNetParam(0.8) 

  // Fit the model 
  val lrModel = lr.fit(training) 

  // Print the coefficients and intercept for linear regression 
  println(s"Coefficients: ${lrModel.coefficients} Intercept: 
   ${lrModel.intercept}") 

  // Summarize the model over the training set and print out some 
   metrics 
  val trainingSummary = lrModel.summary 
  println(s"numIterations: ${trainingSummary.totalIterations}") 
  println(s"objectiveHistory: 
   ${trainingSummary.objectiveHistory.toList}") 
  trainingSummary.residuals.show() 
  println(s"RMSE: ${trainingSummary.rootMeanSquaredError}") 
  println(s"r2: ${trainingSummary.r2}") 
} 

```

前面的代码应该显示以下输出。请注意，残差代表表达式残差：（标签-预测值）

```scala
+-------------------+
|          residuals|
+-------------------+
|  32.92325797801143|
|  59.97614044359903|
|  35.80737062786482|
|-12.509886468051075|
|-25.979774633117792|
|-29.352862474201224|
|-5.9517346926691435|
| 18.453701019500947|
|-24.859327293384787|
| -47.14282080103287|
| -27.50652100848832|
| 21.865309097336535|
|  4.037722798853395|
|-25.691348213368343|
| -13.59830538387368|
|  9.336691727080336|
|  12.83461983259582|
|  -20.5026155752185|
| -34.83240621318937|
| -34.30229437825615|
+-------------------+
only showing top 20 rows
RMSE: 149.54567868651284
r2: 0.3202369690447968

```

代码清单可在[`github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/LinearRegressionPipeline.scala`](https://github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/LinearRegressionPipeline.scala)找到。

# 广义线性回归

线性回归遵循高斯分布，而**广义线性模型**（**GLM**）是线性模型的规范，其中响应变量`Y`遵循指数分布族中的某个分布。

让我们通过将自行车共享数据集分为 80%的训练和 20%的测试，使用 Spark 的回归评估器使用`GeneralizedLinearRegression`构建模型，并获得关于测试数据的评估指标。

```scala
@transient lazy val logger = Logger.getLogger(getClass.getName) 

def genLinearRegressionWithVectorFormat(vectorAssembler: 
   VectorAssembler, vectorIndexer: VectorIndexer, dataFrame: 
   DataFrame) = { 
   val lr = new GeneralizedLinearRegression() 
    .setFeaturesCol("features") 
    .setLabelCol("label") 
    .setFamily("gaussian") 
    .setLink("identity") 
    .setMaxIter(10) 
    .setRegParam(0.3) 

  val pipeline = new Pipeline().setStages(Array(vectorAssembler, 
   vectorIndexer, lr)) 

  val Array(training, test) = dataFrame.randomSplit(Array(0.8, 
   0.2), seed = 12345) 

  val model = pipeline.fit(training) 

  val fullPredictions = model.transform(test).cache() 
  val predictions = 
   fullPredictions.select("prediction").rdd.map(_.getDouble(0)) 
  val labels = 
   fullPredictions.select("label").rdd.map(_.getDouble(0)) 
  val RMSE = new 
   RegressionMetrics(predictions.zip(labels)).rootMeanSquaredError 
  println(s"  Root mean squared error (RMSE): $RMSE") 
} 

def genLinearRegressionWithSVMFormat(spark: SparkSession) = { 
  // Load training data 
  val training = spark.read.format("libsvm") 
    .load("/dataset/BikeSharing/lsvmHours.txt") 

  val lr = new GeneralizedLinearRegression() 
    .setFamily("gaussian") 
    .setLink("identity") 
    .setMaxIter(10) 
    .setRegParam(0.3) 

  // Fit the model 
  val model = lr.fit(training) 

  // Print the coefficients and intercept for generalized linear 
   regression model 
  println(s"Coefficients: ${model.coefficients}") 
  println(s"Intercept: ${model.intercept}") 

  // Summarize the model over the training set and print out some 
   metrics 
  val summary = model.summary 
  println(s"Coefficient Standard Errors: 
   ${summary.coefficientStandardErrors.mkString(",")}") 
  println(s"T Values: ${summary.tValues.mkString(",")}") 
  println(s"P Values: ${summary.pValues.mkString(",")}") 
  println(s"Dispersion: ${summary.dispersion}") 
  println(s"Null Deviance: ${summary.nullDeviance}") 
  println(s"Residual Degree Of Freedom Null: 
   ${summary.residualDegreeOfFreedomNull}") 
  println(s"Deviance: ${summary.deviance}") 
  println(s"Residual Degree Of Freedom: 
   ${summary.residualDegreeOfFreedom}") 
  println(s"AIC: ${summary.aic}") 
  println("Deviance Residuals: ") 
  summary.residuals().show()   
} 

```

这应该输出以下结果：

估计系数和截距的标准误差。

如果`[GeneralizedLinearRegression.fitIntercept]`设置为 true，则返回的最后一个元素对应于截距。

前面代码中的系数标准误差如下：

```scala
1.1353970394903834,2.2827202289405677,0.5060828045490352,0.1735367945
   7103457,7.062338310890969,0.5694233355369813,2.5250738792716176,
2.0099641224706573,0.7596421898012983,0.6228803024758551,0.0735818071
   8894239,0.30550603737503224,12.369537640641184

```

估计系数和截距的 T 统计量如下：

```scala
T Values: 15.186791802016964,33.26578339676457,-
   11.27632316133038,8.658129103690262,-
   3.8034120518318013,2.6451862430890807,0.9799958329796699,
3.731755243874297,4.957582264860384,6.02053185645345,-
   39.290272209592864,5.5283417898112726,-0.7966500413552742

```

估计系数和截距的双侧 p 值如下：

```scala
P Values: 0.0,0.0,0.0,0.0,1.4320532622846827E-
   4,0.008171946193283652,0.3271018275330657,1.907562616410008E-
   4,7.204877614519489E-7,
1.773422964035376E-9,0.0,3.2792739856901676E-8,0.42566519676340153

```

离散度如下：

```scala
Dispersion: 22378.414478769333

```

拟合模型的离散度对于“二项式”和“泊松”族取 1.0，否则由残差 Pearson 卡方统计量（定义为 Pearson 残差的平方和）除以残差自由度估计。

前面代码的空偏差输出如下：

```scala
Null Deviance: 5.717615910707208E8

```

残差自由度如下：

```scala
Residual Degree Of Freedom Null: 17378

```

在逻辑回归分析中，偏差用来代替平方和的计算。偏差类似于线性回归中的平方和计算，是对逻辑回归模型中数据拟合不足的度量。当“饱和”模型可用时（具有理论上完美的拟合模型），通过将给定模型与饱和模型进行比较来计算偏差。

偏差：`3.886235458383082E8`

参考：[`en.wikipedia.org/wiki/Logistic_regression`](https://en.wikipedia.org/wiki/Logistic_regression)

**自由度**：

自由度的概念是从样本中估计总体统计量的原则的核心。 “自由度”通常缩写为 df。

将 df 视为在从另一个估计值中估计一个统计量时需要放置的数学限制。前面的代码将产生以下输出：

```scala
Residual Degree Of Freedom: 17366

```

阿凯克信息准则（AIC）是对给定数据集的统计模型相对质量的度量。给定数据的一组模型，AIC 估计每个模型相对于其他模型的质量。因此，AIC 提供了模型选择的一种方法。

参考：[`en.wikipedia.org/wiki/Akaike_information_criterion`](https://en.wikipedia.org/wiki/Akaike_information_criterion)

拟合模型输出的 AIC 如下：

```scala
AIC: 223399.95490762248
+-------------------+
|  devianceResiduals|
+-------------------+
| 32.385412453563546|
|   59.5079185994115|
|  34.98037491140896|
|-13.503450469022432|
|-27.005954440659032|
|-30.197952952158246|
| -7.039656861683778|
| 17.320193923055445|
|  -26.0159703272054|
| -48.69166247116218|
| -29.50984967584955|
| 20.520222192742004|
| 1.6551311183207815|
|-28.524373674665213|
|-16.337935852841838|
|  6.441923904310045|
|   9.91072545492193|
|-23.418896074866524|
|-37.870797650696346|
|-37.373301622332946|
+-------------------+
only showing top 20 rows

```

完整的代码清单可在此链接找到：

[`github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/GeneralizedLinearRegressionPipeline.scala`](https://github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/GeneralizedLinearRegressionPipeline.scala)

# 决策树回归

决策树模型是一种强大的、非概率的技术，可以捕捉更复杂的非线性模式和特征交互。它们已被证明在许多任务上表现良好，相对容易理解和解释，可以处理分类和数值特征，并且不需要输入数据进行缩放或标准化。它们非常适合包含在集成方法中（例如，决策树模型的集成，称为决策森林）。

决策树算法是一种自顶向下的方法，从根节点（或特征）开始，然后在每一步选择一个特征，该特征通过信息增益来衡量数据集的最佳拆分。信息增益是从节点不纯度（标签在节点上相似或同质的程度）减去由拆分创建的两个子节点的不纯度的加权和来计算的。

让我们通过将自行车共享数据集分成 80%的训练和 20%的测试，使用 Spark 中的`DecisionTreeRegression`和回归评估器来构建模型，并获得测试数据周围的评估指标。

```scala
@transient lazy val logger = Logger.getLogger(getClass.getName) 

def decTreeRegressionWithVectorFormat(vectorAssembler: 
   VectorAssembler, vectorIndexer: VectorIndexer, dataFrame: 
   DataFrame) = { 
  val lr = new DecisionTreeRegressor() 
    .setFeaturesCol("features") 
    .setLabelCol("label") 

  val pipeline = new Pipeline().setStages(Array(vectorAssembler, 
   vectorIndexer, lr)) 

  val Array(training, test) = dataFrame.randomSplit(Array(0.8, 
   0.2), seed = 12345) 

  val model = pipeline.fit(training) 

  // Make predictions. 
  val predictions = model.transform(test) 

  // Select example rows to display. 
  predictions.select("prediction", "label", "features").show(5) 

  // Select (prediction, true label) and compute test error. 
  val evaluator = new RegressionEvaluator() 
    .setLabelCol("label") 
    .setPredictionCol("prediction") 
    .setMetricName("rmse") 
  val rmse = evaluator.evaluate(predictions) 
  println("Root Mean Squared Error (RMSE) on test data = " + rmse) 

  val treeModel = 
   model.stages(1).asInstanceOf[DecisionTreeRegressionModel] 
  println("Learned regression tree model:\n" + 
   treeModel.toDebugString)  } 

def decTreeRegressionWithSVMFormat(spark: SparkSession) = { 
  // Load training data 
  val training = spark.read.format("libsvm") 
    .load("/dataset/BikeSharing/lsvmHours.txt") 

  // Automatically identify categorical features, and index them. 
  // Here, we treat features with > 4 distinct values as 
   continuous. 
  val featureIndexer = new VectorIndexer() 
    .setInputCol("features") 
    .setOutputCol("indexedFeatures") 
    .setMaxCategories(4) 
    .fit(training) 

  // Split the data into training and test sets (30% held out for 
   testing). 
  val Array(trainingData, testData) = 
   training.randomSplit(Array(0.7, 0.3)) 

  // Train a DecisionTree model. 
  val dt = new DecisionTreeRegressor() 
    .setLabelCol("label") 
    .setFeaturesCol("indexedFeatures") 

  // Chain indexer and tree in a Pipeline. 
  val pipeline = new Pipeline() 
    .setStages(Array(featureIndexer, dt)) 

  // Train model. This also runs the indexer. 
  val model = pipeline.fit(trainingData) 

  // Make predictions. 
  val predictions = model.transform(testData) 

  // Select example rows to display. 
  predictions.select("prediction", "label", "features").show(5) 

  // Select (prediction, true label) and compute test error. 
  val evaluator = new RegressionEvaluator() 
    .setLabelCol("label") 
    .setPredictionCol("prediction") 
    .setMetricName("rmse") 
  val rmse = evaluator.evaluate(predictions) 
  println("Root Mean Squared Error (RMSE) on test data = " + rmse) 

  val treeModel = 
   model.stages(1).asInstanceOf[DecisionTreeRegressionModel] 
  println("Learned regression tree model:\n" + 
   treeModel.toDebugString) 
} 

```

这应该输出以下结果：

```scala
Coefficients: [17.243038451366886,75.93647669134975,-5.7067532504873215,1.5025039716365927,-26.86098264575616,1.5062307736563205,2.4745618796519953,7.500694154029075,3.7659886477986215,3.7500707038132464,-2.8910492341273235,1.6889417934600353]
Intercept: -9.85419267296242

Coefficient Standard Errors: 1.1353970394903834,2.2827202289405677,0.5060828045490352,0.17353679457103457,7.062338310890969,0.5694233355369813,2.5250738792716176,2.0099641224706573,0.7596421898012983,0.6228803024758551,0.07358180718894239,0.30550603737503224,12.369537640641184
T Values: 15.186791802016964,33.26578339676457,-11.27632316133038,8.658129103690262,-3.8034120518318013,2.6451862430890807,0.9799958329796699,3.731755243874297,4.957582264860384,6.02053185645345,-39.290272209592864,5.5283417898112726,-0.7966500413552742
P Values: 0.0,0.0,0.0,0.0,1.4320532622846827E-4,0.008171946193283652,0.3271018275330657,1.907562616410008E-4,7.204877614519489E-7,1.773422964035376E-9,0.0,3.2792739856901676E-8,0.42566519676340153
Dispersion: 22378.414478769333

Null Deviance: 5.717615910707208E8
Residual Degree Of Freedom Null: 17378
Deviance: 3.886235458383082E8
Residual Degree Of Freedom: 17366

AIC: 223399.95490762248
Deviance Residuals:
+-------------------+
|  devianceResiduals|
+-------------------+
| 32.385412453563546|
|   59.5079185994115|
|  34.98037491140896|
|-13.503450469022432|
|-27.005954440659032|
|-30.197952952158246|
| -7.039656861683778|
| 17.320193923055445|
|  -26.0159703272054|
| -48.69166247116218|
| -29.50984967584955|
| 20.520222192742004|
| 1.6551311183207815|
|-28.524373674665213|
|-16.337935852841838|
|  6.441923904310045|
|   9.91072545492193|
|-23.418896074866524|
|-37.870797650696346|
|-37.373301622332946|
+-------------------+
only showing top 20 rows

```

请参考前一节（广义线性回归）以了解如何解释结果。

代码清单可在[`github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/DecisionTreeRegressionPipeline.scala`](https://github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/DecisionTreeRegressionPipeline.scala)找到。

# 树的集成

集成方法是一种机器学习算法，它创建由一组其他基本模型组成的模型。Spark 机器学习支持两种主要的集成算法：`RandomForest`和`GradientBoostedTrees`。

# 随机森林回归

随机森林被称为决策树的集成，由许多决策树组成。与决策树一样，随机森林可以处理分类特征，支持多类别，并且不需要特征缩放。

让我们通过将自行车共享数据集分为 80%的训练和 20%的测试，使用 Spark 中的`RandomForestRegressor`和回归评估器构建模型，并获得关于测试数据的评估指标。

```scala
@transient lazy val logger = Logger.getLogger(getClass.getName) 

def randForestRegressionWithVectorFormat(vectorAssembler: 
  VectorAssembler, vectorIndexer: VectorIndexer, dataFrame: 
   DataFrame) = { 
   val lr = new RandomForestRegressor() 
    .setFeaturesCol("features") 
    .setLabelCol("label") 

  val pipeline = new Pipeline().setStages(Array(vectorAssembler, 
   vectorIndexer, lr)) 

  val Array(training, test) = dataFrame.randomSplit(Array(0.8, 
   0.2), seed = 12345) 

  val model = pipeline.fit(training) 

  // Make predictions. 
  val predictions = model.transform(test) 

  // Select example rows to display. 
  predictions.select("prediction", "label", "features").show(5) 

  // Select (prediction, true label) and compute test error. 
  val evaluator = new RegressionEvaluator() 
    .setLabelCol("label") 
    .setPredictionCol("prediction") 
    .setMetricName("rmse") 
  val rmse = evaluator.evaluate(predictions) 
  println("Root Mean Squared Error (RMSE) on test data = " + rmse) 

  val treeModel = 
   model.stages(1).asInstanceOf[RandomForestRegressionModel] 
  println("Learned regression tree model:\n" + treeModel.toDebugString)  } 

def randForestRegressionWithSVMFormat(spark: SparkSession) = { 
  // Load training data 
  val training = spark.read.format("libsvm") 
    .load("/dataset/BikeSharing/lsvmHours.txt") 

  // Automatically identify categorical features, and index them. 
  // Set maxCategories so features with > 4 distinct values are 
   treated as continuous. 
  val featureIndexer = new VectorIndexer() 
    .setInputCol("features") 
    .setOutputCol("indexedFeatures") 
    .setMaxCategories(4) 
    .fit(training) 

  // Split the data into training and test sets (30% held out for 
   testing). 
  val Array(trainingData, testData) = 
   training.randomSplit(Array(0.7, 0.3)) 

  // Train a RandomForest model. 
  val rf = new RandomForestRegressor() 
    .setLabelCol("label") 
    .setFeaturesCol("indexedFeatures") 

  // Chain indexer and forest in a Pipeline. 
  val pipeline = new Pipeline() 
    .setStages(Array(featureIndexer, rf)) 

  // Train model. This also runs the indexer. 
  val model = pipeline.fit(trainingData) 

  // Make predictions. 
  val predictions = model.transform(testData) 

  // Select example rows to display. 
  predictions.select("prediction", "label", "features").show(5) 

  // Select (prediction, true label) and compute test error. 
  val evaluator = new RegressionEvaluator() 
    .setLabelCol("label") 
    .setPredictionCol("prediction") 
    .setMetricName("rmse") 
  val rmse = evaluator.evaluate(predictions) 
  println("Root Mean Squared Error (RMSE) on test data = " + rmse) 

  val rfModel = 
   model.stages(1).asInstanceOf[RandomForestRegressionModel] 
  println("Learned regression forest model:\n" + 
   rfModel.toDebugString) 
} 

```

这应该输出以下结果：

```scala
RandomForest:   init: 2.114590873
total: 3.343042855
findSplits: 1.387490192
findBestSplits: 1.191715923
chooseSplits: 1.176991821

+------------------+-----+--------------------+
|        prediction|label|            features|
+------------------+-----+--------------------+
| 70.75171441904584|  1.0|(12,[0,1,2,3,4,5,...|
| 53.43733657257549|  1.0|(12,[0,1,2,3,4,5,...|
| 57.18242812368521|  1.0|(12,[0,1,2,3,4,5,...|
| 49.73744636247659|  1.0|(12,[0,1,2,3,4,5,...|
|56.433579398691144|  1.0|(12,[0,1,2,3,4,5,...|

Root Mean Squared Error (RMSE) on test data = 123.03866156451954
Learned regression forest model:
RandomForestRegressionModel (uid=rfr_bd974271ffe6) with 20 trees
 Tree 0 (weight 1.0):
 If (feature 9 <= 40.0)
 If (feature 9 <= 22.0)
 If (feature 8 <= 13.0)
 If (feature 6 in {0.0})
 If (feature 1 in {0.0})
 Predict: 35.0945945945946
 Else (feature 1 not in {0.0})
 Predict: 63.3921568627451
 Else (feature 6 not in {0.0})
 If (feature 0 in {0.0,1.0})
 Predict: 83.05714285714286
 Else (feature 0 not in {0.0,1.0})
 Predict: 120.76608187134502
 Else (feature 8 > 13.0)
 If (feature 3 <= 21.0)
 If (feature 3 <= 12.0)
 Predict: 149.56363636363636
 Else (feature 3 > 12.0)
 Predict: 54.73593073593074
 Else (feature 3 > 21.0)
 If (feature 6 in {0.0})
 Predict: 89.63333333333334
 Else (feature 6 not in {0.0})
 Predict: 305.6588235294118

```

前面的代码使用各种特征及其值创建决策树。

代码清单可在[`github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/RandomForestRegressionPipeline.scala`](https://github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/RandomForestRegressionPipeline.scala)找到。

# 梯度提升树回归

梯度提升树是决策树的集成。梯度提升树迭代训练决策树以最小化损失函数。梯度提升树处理分类特征，支持多类别，并且不需要特征缩放。

Spark ML 使用现有的决策树实现梯度提升树。它支持分类和回归。

让我们通过将自行车共享数据集分为 80%的训练和 20%的测试，使用 Spark 中的 GBTRegressor 和回归评估器构建模型，并获得关于测试数据的评估指标。

```scala
@transient lazy val logger = Logger.getLogger(getClass.getName) 

def gbtRegressionWithVectorFormat(vectorAssembler: 
   VectorAssembler, vectorIndexer: VectorIndexer, dataFrame: 
   DataFrame) = { 
  val lr = new GBTRegressor() 
    .setFeaturesCol("features") 
    .setLabelCol("label") 
    .setMaxIter(10) 

  val pipeline = new Pipeline().setStages(Array(vectorAssembler, 
   vectorIndexer, lr)) 

  val Array(training, test) = dataFrame.randomSplit(Array(0.8, 
   0.2), seed = 12345) 

  val model = pipeline.fit(training) 

  // Make predictions. 
  val predictions = model.transform(test) 

  // Select example rows to display. 
  predictions.select("prediction", "label", "features").show(5) 

  // Select (prediction, true label) and compute test error. 
  val evaluator = new RegressionEvaluator() 
    .setLabelCol("label") 
    .setPredictionCol("prediction") 
    .setMetricName("rmse") 
  val rmse = evaluator.evaluate(predictions) 
  println("Root Mean Squared Error (RMSE) on test data = " + rmse) 

  val treeModel = model.stages(1).asInstanceOf[GBTRegressionModel] 
  println("Learned regression tree model:\n" + 
   treeModel.toDebugString)  } 

def gbtRegressionWithSVMFormat(spark: SparkSession) = { 
  // Load training data 
  val training = spark.read.format("libsvm") 
    .load("/dataset/BikeSharing/lsvmHours.txt") 

  // Automatically identify categorical features, and index them. 
  // Set maxCategories so features with > 4 distinct values are 
   treated as continuous. 
  val featureIndexer = new VectorIndexer() 
    .setInputCol("features") 
    .setOutputCol("indexedFeatures") 
    .setMaxCategories(4) 
    .fit(training) 

  // Split the data into training and test sets (30% held out for 
   testing). 
  val Array(trainingData, testData) = 
   training.randomSplit(Array(0.7, 0.3)) 

  // Train a GBT model. 
  val gbt = new GBTRegressor() 
    .setLabelCol("label") 
    .setFeaturesCol("indexedFeatures") 
    .setMaxIter(10) 

  // Chain indexer and GBT in a Pipeline. 
  val pipeline = new Pipeline() 
    .setStages(Array(featureIndexer, gbt)) 

  // Train model. This also runs the indexer. 
  val model = pipeline.fit(trainingData) 

  // Make predictions 
  val predictions = model.transform(testData) 

  // Select example rows to display.
   predictions.select("prediction", "label", "features").show(5) 

  // Select (prediction, true label) and compute test error. 
  val evaluator = new RegressionEvaluator() 
    .setLabelCol("label") 
    .setPredictionCol("prediction") 
    .setMetricName("rmse") 
  val rmse = evaluator.evaluate(predictions) 
  println("Root Mean Squared Error (RMSE) on test data = " + rmse) 

  val gbtModel = model.stages(1).asInstanceOf[GBTRegressionModel] 
  println("Learned regression GBT model:\n" + 
   gbtModel.toDebugString) 
} 

```

这应该输出以下结果：

```scala
RandomForest:   init: 1.366356823
total: 1.883186039
findSplits: 1.0378687
findBestSplits: 0.501171071
chooseSplits: 0.495084674

+-------------------+-----+--------------------+
|         prediction|label|            features|
+-------------------+-----+--------------------+
|-20.753742348814352|  1.0|(12,[0,1,2,3,4,5,...|
|-20.760717579684087|  1.0|(12,[0,1,2,3,4,5,...|
| -17.73182527714976|  1.0|(12,[0,1,2,3,4,5,...|
| -17.73182527714976|  1.0|(12,[0,1,2,3,4,5,...|
|   -21.397094071362|  1.0|(12,[0,1,2,3,4,5,...|
+-------------------+-----+--------------------+
only showing top 5 rows

Root Mean Squared Error (RMSE) on test data = 73.62468541448783
Learned regression GBT model:
GBTRegressionModel (uid=gbtr_24c6ef8f52a7) with 10 trees
 Tree 0 (weight 1.0):
 If (feature 9 <= 41.0)
 If (feature 3 <= 12.0)
 If (feature 3 <= 3.0)
 If (feature 3 <= 2.0)
 If (feature 6 in {1.0})
 Predict: 24.50709219858156
 Else (feature 6 not in {1.0})
 Predict: 74.94945848375451
 Else (feature 3 > 2.0)
 If (feature 6 in {1.0})
 Predict: 122.1732283464567
 Else (feature 6 not in {1.0})
 Predict: 206.3304347826087
 Else (feature 3 > 3.0)
 If (feature 8 <= 18.0)
 If (feature 0 in {0.0,1.0})
 Predict: 137.29818181818183
 Else (feature 0 not in {0.0,1.0})
 Predict: 257.90157480314963

```

代码清单可在[`github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/GradientBoostedTreeRegressorPipeline.scala`](https://github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/bikesharing/GradientBoostedTreeRegressorPipeline.scala)找到。

# 改进模型性能和调整参数

在第六章中，*使用 Spark 构建分类模型*，我们展示了特征转换和选择如何对模型的性能产生很大影响。在本章中，我们将专注于可以应用于数据集的另一种转换类型：转换目标变量本身。

# 转换目标变量

请记住，许多机器学习模型，包括线性模型，对输入数据和目标变量的分布做出假设。特别是，线性回归假设正态分布。

在许多实际情况下，线性回归的分布假设并不成立。例如，在这种情况下，我们知道自行车租赁数量永远不会是负数。这一点就应该表明正态分布的假设可能存在问题。为了更好地了解目标分布，通常最好绘制目标值的直方图。

我们现在将创建目标变量分布的图表如下所示：

Scala

绘制原始数据的代码可以在[`github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/1.6.2/scala-spark-app/src/main/scala/org/sparksamples/PlotRawData.scala`](https://github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_07/scala/1.6.2/scala-spark-app/src/main/scala/org/sparksamples/PlotRawData.scala)找到。

```scala
object PlotRawData { 

  def main(args: Array[String]) { 
    val records = Util.getRecords()._1 
    val records_x = records.map(r => r(r.length -1)) 
    var records_int = new ArrayInt.length) 
    print(records_x.first()) 
    val records_collect = records_x.collect() 

    for (i <- 0 until records_collect.length){ 
      records_int(i) = records_collect(i).toInt 
    } 
    val min_1 = records_int.min 
    val max_1 = records_int.max 

    val min = min_1 
    val max = max_1 
    val bins = 40 
    val step = (max/bins).toInt 

    var mx = Map(0 -> 0) 
    for (i <- step until (max + step) by step) { 
      mx += (i -> 0); 
    } 

    for(i <- 0 until records_collect.length){ 
      for (j <- 0 until (max + step) by step) { 
        if(records_int(i) >= (j) && records_int(i) < (j + step)){ 
          mx = mx + (j -> (mx(j) + 1)) 
        } 
      } 
    } 
    val mx_sorted = ListMap(mx.toSeq.sortBy(_._1):_*) 
    val ds = new org.jfree.data.category.DefaultCategoryDataset 
    var i = 0 
    mx_sorted.foreach{ case (k,v) => ds.addValue(v,"", k)} 

    val chart = ChartFactories.BarChart(ds) 
    val font = new Font("Dialog", Font.PLAIN,4); 

    chart.peer.getCategoryPlot.getDomainAxis(). 
      setCategoryLabelPositions(CategoryLabelPositions.UP_90); 
    chart.peer.getCategoryPlot.getDomainAxis.setLabelFont(font) 
    chart.show() 
    Util.sc.stop() 
  } 
} 

```

前述输出的图如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_005.png)

我们处理这种情况的一种方法是对目标变量应用转换，即我们取目标值的对数而不是原始值。这通常被称为对目标变量进行对数转换（此转换也可以应用于特征值）。

我们将对以下目标变量应用对数变换，并使用以下代码绘制对数变换后的值的直方图：

Scala

```scala
object PlotLogData { 

  def main(args: Array[String]) { 
    val records = Util.getRecords()._1 
    val records_x = records.map( 
      r => Math.log(r(r.length -1).toDouble)) 
    var records_int = new ArrayInt.length) 
    print(records_x.first()) 
    val records_collect = records_x.collect() 

    for (i <- 0 until records_collect.length){ 
      records_int(i) = records_collect(i).toInt 
    } 
    val min_1 = records_int.min 
    val max_1 = records_int.max 

    val min = min_1.toFloat 
    val max = max_1.toFloat 
    val bins = 10 
    val step = (max/bins).toFloat 

    var mx = Map(0.0.toString -> 0) 
    for (i <- step until (max + step) by step) { 
      mx += (i.toString -> 0); 
    } 

    for(i <- 0 until records_collect.length){ 
      for (j <- 0.0 until (max + step) by step) { 
        if(records_int(i) >= (j) && records_int(i) < (j + step)){ 
          mx = mx + (j.toString -> (mx(j.toString) + 1)) 
        } 
      } 
    } 
    val mx_sorted = ListMap(mx.toSeq.sortBy(_._1.toFloat):_*) 
    val ds = new org.jfree.data.category.DefaultCategoryDataset 
    var i = 0 
    mx_sorted.foreach{ case (k,v) => ds.addValue(v,"", k)} 

    val chart = ChartFactories.BarChart(ds) 
    val font = new Font("Dialog", Font.PLAIN,4); 

    chart.peer.getCategoryPlot.getDomainAxis(). 
      setCategoryLabelPositions(CategoryLabelPositions.UP_90); 
    chart.peer.getCategoryPlot.getDomainAxis.setLabelFont(font) 
    chart.show() 
    Util.sc.stop() 
  } 
} 

```

前面输出的图表如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_006.png)

第二种转换类型在目标值不取负值，并且可能取值范围非常广泛的情况下非常有用，那就是对变量取平方根。

我们将在以下代码中应用平方根变换，再次绘制结果目标变量的分布：

从对数和平方根变换的图表中，我们可以看到两者都相对于原始值产生了更均匀的分布。虽然它们仍然不是正态分布，但与原始目标变量相比，它们更接近正态分布。

# 对对数变换目标的训练影响

那么，应用这些转换对模型性能有影响吗？让我们以对数变换数据为例，评估我们之前使用的各种指标。

我们将首先对线性模型进行操作，通过对每个`LabeledPoint` RDD 的`label`字段应用对数函数。在这里，我们只会对目标变量进行转换，不会对特征进行任何转换。

然后，我们将在转换后的数据上训练模型，并形成预测值与真实值的 RDD。

请注意，现在我们已经转换了目标变量，模型的预测将在对数尺度上，转换后数据集的目标值也将在对数尺度上。因此，为了使用我们的模型并评估其性能，我们必须首先通过使用`numpy exp`函数将对数数据转换回原始尺度，对预测值和真实值都进行指数化。

最后，我们将计算模型的 MSE、MAE 和 RMSLE 指标：

Scala

```scala
object LinearRegressionWithLog{ 

  def main(args: Array[String]) { 

    val recordsArray = Util.getRecords() 
    val records = recordsArray._1 
    val first = records.first() 
    val numData = recordsArray._2 

    println(numData.toString()) 
    records.cache()
     print("Mapping of first categorical feature column: " + 
       Util.get_mapping(records, 2)) 
    var list = new ListBuffer[Map[String, Long]]() 
    for( i <- 2 to 9){ 
      val m =  Util.get_mapping(records, i) 
      list += m 
    } 
    val mappings = list.toList 
    var catLen = 0 
    mappings.foreach( m => (catLen +=m.size)) 

    val numLen = records.first().slice(11, 15).size 
    val totalLen = catLen + numLen
    print("Feature vector length for categorical features:"+ 
       catLen)
     print("Feature vector length for numerical features:" +
       numLen)
     print("Total feature vector length: " + totalLen) 

    val data = { 
      records.map(r => LabeledPoint(Math.log(Util.extractLabel(r)),
         Util.extractFeatures(r, catLen, mappings)))
    } 
    val first_point = data.first() 
    println("Linear Model feature vector:" + 
       first_point.features.toString) 
    println("Linear Model feature vector length: " + 
       first_point.features.size) 

    val iterations = 10 
    val step = 0.025 
    val intercept =true 
    val linear_model = LinearRegressionWithSGD.train(data, 
       iterations, step) 
    val x = linear_model.predict(data.first().features) 
    val true_vs_predicted = data.map(p => (Math.exp(p.label), 
       Math.exp(linear_model.predict(p.features)))) 
    val true_vs_predicted_csv = data.map(p => p.label + " ," + 
       linear_model.predict(p.features)) 
    val format = new java.text.SimpleDateFormat(
       "dd-MM-yyyy-hh-mm-ss") 
    val date = format.format(new java.util.Date()) 
    val save = false 
    if (save){ 
         true_vs_predicted_csv.saveAsTextFile( 
           "./output/linear_model_" + date + ".csv") 
    } 
    val true_vs_predicted_take5 = true_vs_predicted.take(5) 
    for(i <- 0 until 5) { 
      println("True vs Predicted: " + "i :" + 
         true_vs_predicted_take5(i)) 
    } 

    Util.calculatePrintMetrics(true_vs_predicted, 
       "LinearRegressioWithSGD Log")
  } 
} 

```

前面代码的输出将类似于以下内容：

```scala
LinearRegressioWithSGD Log - Mean Squared Error: 5055.089410453301
LinearRegressioWithSGD Log - Mean Absolute Error: 51.56719871511336
LinearRegressioWithSGD Log - Root Mean Squared Log 
   Error:1.7785399629180894

```

代码清单可在以下链接找到：

+   [`github.com/ml-resources/spark-ml/tree/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/ linearregression/LinearRegressionWithLog.scala`](https://github.com/ml-resources/spark-ml/tree/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/%20linearregression/LinearRegressionWithLog.scala)

+   [`github.com/ml-resources/spark-ml/tree/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/ linearregression/LinearRegression.scala`](https://github.com/ml-resources/spark-ml/tree/branch-ed2/Chapter_07/scala/2.0.0/scala-spark-app/src/main/scala/org/sparksamples/regression/%20linearregression/LinearRegression.scala)

如果我们将这些前面的结果与原始目标变量的结果进行比较，我们会发现所有三个值都变得更糟。

```scala
LinearRegressioWithSGD - Mean Squared Error: 35817.9777663029
LinearRegressioWithSGD - Mean Absolute Error: 136.94887209426008
LinearRegressioWithSGD - Root Mean Squared Log Error: 
    1.4482391780194306
LinearRegressioWithSGD Log - Mean Squared Error: 60192.54096079104
LinearRegressioWithSGD Log - Mean Absolute Error: 
    170.82191606911752
LinearRegressioWithSGD Log - Root Mean Squared Log Error: 
    1.9587586971094555

```

# 调整模型参数

到目前为止，在本章中，我们已经通过在相同数据集上进行训练和测试来说明了 MLlib 回归模型的模型训练和评估的概念。现在，我们将使用与之前类似的交叉验证方法来评估不同参数设置对模型性能的影响。

# 创建训练和测试集以评估参数。

第一步是为交叉验证目的创建测试和训练集。

在 Scala 中，拆分更容易实现，并且`randomSplit`函数可用：

```scala
val splits = data.randomSplit(Array(0.8, 0.2), seed = 11L) 
val training = splits(0).cache() 
val test = splits(1) 

```

# 决策树的数据拆分

最后一步是对决策树模型提取的特征应用相同的方法。

Scala

```scala
val splits = data_dt.randomSplit(Array(0.8, 0.2), seed = 11L) 
val training = splits(0).cache() 
val test = splits(1) 

```

# 线性模型参数设置的影响

现在我们已经准备好了我们的训练和测试集，我们准备研究不同参数设置对模型性能的影响。我们将首先对线性模型进行评估。我们将创建一个方便的函数，通过在训练集上训练模型，并在不同的参数设置下在测试集上评估相关性能指标。

我们将使用 RMSLE 评估指标，因为这是 Kaggle 竞赛中使用的指标，这样可以让我们将模型结果与竞赛排行榜进行比较，看看我们的表现如何。

评估函数在这里定义：

Scala

```scala
def evaluate(train: RDD[LabeledPoint],test: RDD[LabeledPoint], 
  iterations:Int,step:Double, 
  intercept:Boolean): Double ={ 
  val linReg =  
    new LinearRegressionWithSGD().setIntercept(intercept) 

  linReg.optimizer.setNumIterations(iterations).setStepSize(step) 
  val linear_model = linReg.run(train) 

  val true_vs_predicted = test.map(p => (p.label,  
    linear_model.predict(p.features))) 
  val rmsle = Math.sqrt(true_vs_predicted.map{  
    case(t, p) => Util.squaredLogError(t, p)}.mean()) 
  return rmsle 
} 

```

请注意，在接下来的部分，由于 SGD 的一些随机初始化，您可能会得到略有不同的结果。但是，您的结果是可以比较的。

# 迭代

正如我们在评估分类模型时看到的，通常情况下，我们期望使用 SGD 训练的模型随着迭代次数的增加而获得更好的性能，尽管随着迭代次数超过某个最小值，性能的提高将放缓。请注意，在这里，我们将步长设置为 0.01，以更好地说明在较高的迭代次数下的影响。

我们使用不同的迭代次数在 Scala 中实现了相同的功能，如下所示：

```scala
val data = LinearRegressionUtil.getTrainTestData() 
val train_data = data._1 
val test_data = data._2 
val iterations = 10 
//LinearRegressionCrossValidationStep$ 
//params = [1, 5, 10, 20, 50, 100, 200] 
val iterations_param = Array(1, 5, 10, 20, 50, 100, 200) 
val step =0.01 
//val steps_param = Array(0.01, 0.025, 0.05, 0.1, 1.0) 
val intercept =false 

val i = 0 
val results = new ArrayString 
val resultsMap = new scala.collection.mutable.HashMap[String, 
   String] 
val dataset = new DefaultCategoryDataset() 
for(i <- 0 until iterations_param.length) { 
  val iteration = iterations_param(i) 
  val rmsle = LinearRegressionUtil.evaluate(train_data, 
   test_data,iteration,step,intercept) 
  //results(i) = step + ":" + rmsle 
  resultsMap.put(iteration.toString,rmsle.toString) 
  dataset.addValue(rmsle, "RMSLE", iteration) 
} 

```

对于 Scala 实现，我们使用了 JfreeChart 的 Scala 版本。实现在 20 次迭代时达到最小的 RMSLE：

```scala
  Map(5 -> 0.8403179051522236, 200 -> 0.35682322830872604, 50 -> 
   0.07224447567763903, 1 -> 1.6381266770967882, 20 -> 
   0.23992956602621263, 100 -> 0.2525579338412989, 10 -> 
   0.5236271681647611) 

```

前面输出的图如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_007.png)

# 步长

我们将在下面的代码中对步长执行类似的分析：

Scala

```scala
val steps_param = Array(0.01, 0.025, 0.05, 0.1, 1.0) 
val intercept =false 

val i = 0 
val results = new ArrayString 
val resultsMap = new scala.collection.mutable.HashMap[String, String] 
val dataset = new DefaultCategoryDataset() 
for(i <- 0 until steps_param.length) { 
  val step = steps_param(i) 
  val rmsle = LinearRegressionUtil.evaluate(train_data, 
         test_data,iterations,step,intercept) 
  resultsMap.put(step.toString,rmsle.toString) 
  dataset.addValue(rmsle, "RMSLE", step) 
} 

```

前面代码的输出如下：

```scala
    [1.7904244862988534, 1.4241062778987466, 1.3840130355866163, 
   1.4560061007109475, nan]

```

前面输出的图如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_008.png)

现在我们可以看到为什么在最初训练线性模型时避免使用默认步长。默认值设置为*1.0*，在这种情况下，导致 RMSLE 指标输出为`nan`。这通常意味着 SGD 模型已经收敛到了一个非常糟糕的局部最小值，这是优化算法容易超过好的解决方案的情况。 

我们还可以看到，对于较低的步长和相对较少的迭代次数（这里我们使用了 10 次），模型性能略差。然而，在前面的*迭代*部分，我们看到对于较低的步长设置，更多的迭代次数通常会收敛到更好的解决方案。

一般来说，设置步长和迭代次数涉及权衡。较低的步长意味着收敛速度较慢，但稍微更有保证。然而，它需要更多的迭代次数，在计算和时间方面更加昂贵，特别是在非常大规模的情况下。

选择最佳参数设置可能是一个密集的过程，涉及在许多参数设置的组合上训练模型并选择最佳结果。每个模型训练实例都涉及一定数量的迭代，因此当在非常大的数据集上执行时，这个过程可能非常昂贵和耗时。模型初始化也会对结果产生影响，无论是达到全局最小值，还是在梯度下降图中达到次优局部最小值。

# L2 正则化

在第六章中，*使用 Spark 构建分类模型*，我们看到正则化会惩罚模型复杂性，形式上是一个额外的损失项，是模型权重向量的函数。L2 正则化惩罚权重向量的 L2 范数，而 L1 正则化惩罚权重向量的 L1 范数。

我们预计随着正则化的增加，训练集性能会下降，因为模型无法很好地拟合数据集。然而，我们也期望一定程度的正则化将导致最佳的泛化性能，这可以通过测试集上的最佳性能来证明。

# L1 正则化

我们可以对不同水平的 L1 正则化应用相同的方法，如下所示：

```scala
params = [0.0, 0.01, 0.1, 1.0, 10.0, 100.0, 1000.0] 
metrics = [evaluate(train_data, test_data, 10, 0.1, param, 'l1', 
   False) for param in params] 
print params 
print metrics 
plot(params, metrics) 
fig = matplotlib.pyplot.gcf() 
pyplot.xscale('log') 

```

再次，当以图表形式绘制时，结果更加清晰。我们看到 RMSLE 有一个更加微妙的下降，需要一个非常高的值才会导致反弹。在这里，所需的 L1 正则化水平比 L2 形式要高得多；然而，整体性能较差：

```scala
[0.0, 0.01, 0.1, 1.0, 10.0, 100.0, 1000.0]
[1.5384660954019971, 1.5384518080419873, 1.5383237472930684, 
    1.5372017600929164, 1.5303809928601677, 1.4352494587433793, 
    4.7551250073268614]

```

使用 L1 正则化可以鼓励稀疏的权重向量。在这种情况下是否成立？我们可以通过检查权重向量中零的条目数来找出答案，随着正则化水平的增加，零的条目数也在增加。

```scala
model_l1 = LinearRegressionWithSGD.train(train_data, 10, 0.1, 
   regParam=1.0, regType='l1', intercept=False) 
model_l1_10 = LinearRegressionWithSGD.train(train_data, 10, 0.1, 
   regParam=10.0, regType='l1', intercept=False) 
model_l1_100 = LinearRegressionWithSGD.train(train_data, 10, 0.1, 
   regParam=100.0, regType='l1', intercept=False) 
print "L1 (1.0) number of zero weights: " + 
   str(sum(model_l1.weights.array == 0)) 
print "L1 (10.0) number of zeros weights: " + 
   str(sum(model_l1_10.weights.array == 0)) 
print "L1 (100.0) number of zeros weights: " + 
   str(sum(model_l1_100.weights.array == 0)) 

```

从结果中可以看出，正如我们所预期的，随着 L1 正则化水平的增加，模型权重向量中零特征权重的数量也在增加。

```scala
L1 (1.0) number of zero weights: 4
L1 (10.0) number of zeros weights: 20
L1 (100.0) number of zeros weights: 55

```

# 截距

线性模型的最终参数选项是是否使用截距。截距是添加到权重向量的常数项，有效地解释了目标变量的平均值。如果数据已经居中或标准化，则不需要截距；然而，在任何情况下使用截距通常也不会有坏处。

我们将评估在模型中添加截距项的影响：

Scala

```scala
object LinearRegressionCrossValidationIntercept{ 
  def main(args: Array[String]) { 
    val data = LinearRegressionUtil.getTrainTestData() 
    val train_data = data._1 
    val test_data = data._2 

    val iterations = 10 
    val step = 0.1 
    val paramsArray = new ArrayBoolean 
    paramsArray(0) = true 
    paramsArray(1) = false 
    val i = 0 
    val results = new ArrayString 
    val resultsMap = new scala.collection.mutable.HashMap[ 
    String, String] 
    val dataset = new DefaultCategoryDataset() 
    for(i <- 0 until 2) { 
      val intercept = paramsArray(i) 
      val rmsle = LinearRegressionUtil.evaluate(train_data,  
        test_data,iterations,step,intercept) 
      results(i) = intercept + ":" + rmsle 
      resultsMap.put(intercept.toString,rmsle.toString) 
      dataset.addValue(rmsle, "RMSLE", intercept.toString) 
    } 
    val chart = new LineChart( 
      "Steps" , 
      "LinearRegressionWithSGD : RMSLE vs Intercept") 
    chart.exec("Steps","RMSLE",dataset) 
    chart.lineChart.getCategoryPlot().getRangeAxis().setRange( 
    1.56, 1.57) 
    chart.pack( ) 
    RefineryUtilities.centerFrameOnScreen( chart ) 
    chart.setVisible( true ) 
    println(results) 
  } 
} 

```

上述输出的图表如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_009.png)

如前图所示，当截距为 true 时，RMSLE 值略高于截距为 false 时。

# 决策树参数设置的影响

决策树提供两个主要参数：最大树深度和最大箱数。我们现在将对决策树模型的参数设置效果进行相同的评估。我们的起点是创建一个模型的评估函数，类似于之前用于线性回归的函数。该函数如下所示：

Scala

```scala
def evaluate(train: RDD[LabeledPoint],test: RDD[LabeledPoint], 
  categoricalFeaturesInfo: scala.Predef.Map[Int, Int], 
  maxDepth :Int, maxBins: Int): Double = { 
    val impurity = "variance" 
    val decisionTreeModel = DecisionTree.trainRegressor(train, 
      categoricalFeaturesInfo, 
      impurity, maxDepth, maxBins) 
    val true_vs_predicted = test.map(p => (p.label,  
      decisionTreeModel.predict(p.features))) 
    val rmsle = Math.sqrt(true_vs_predicted.map{  
      case(t, p) => Util.squaredLogError(t, p)}.mean()) 
      return rmsle 
  } 

```

# 树深度

通常我们期望性能会随着更复杂的树（即更深的树）而提高。较低的树深度起到一种正则化的作用，可能会出现与线性模型中的 L2 或 L1 正则化类似的情况，即存在一个最优的树深度与测试集性能相关。

在这里，我们将尝试增加树的深度，以查看它们对测试集 RMSLE 的影响，保持箱数的默认水平为`32`：

Scala

```scala
val data = DecisionTreeUtil.getTrainTestData() 
  val train_data = data._1 
  val test_data = data._2 
  val iterations = 10 
  val bins_param = Array(2, 4, 8, 16, 32, 64, 100) 
  val depth_param = Array(1, 2, 3, 4, 5, 10, 20) 
  val bin = 32 
  val categoricalFeaturesInfo = scala.Predef.Map[Int, Int]() 
  val i = 0 
  val results = new ArrayString 
  val resultsMap = new scala.collection.mutable.HashMap[ 
    String, String] 
  val dataset = new DefaultCategoryDataset() 
  for(i <- 0 until depth_param.length) { 
    val depth = depth_param(i) 
    val rmsle = DecisionTreeUtil.evaluate( 
    train_data, test_data, categoricalFeaturesInfo, depth, bin) 

    resultsMap.put(depth.toString,rmsle.toString) 
    dataset.addValue(rmsle, "RMSLE", depth) 
  } 
  val chart = new LineChart( 
    "MaxDepth" , 
    "DecisionTree : RMSLE vs MaxDepth") 
  chart.exec("MaxDepth","RMSLE",dataset) 
  chart.pack() 
  RefineryUtilities.centerFrameOnScreen( chart ) 
  chart.setVisible( true ) 
  print(resultsMap) 
} 

```

上述输出的图表如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_010.png)

# 最大箱数

最后，我们将评估决策树箱数设置的影响。与树深度一样，更多的箱数应该允许模型变得更复杂，并可能有助于处理更大的特征维度。在一定程度之后，它不太可能再有帮助，实际上可能会由于过拟合而影响测试集的性能。

Scala

```scala
object DecisionTreeMaxBins{ 
  def main(args: Array[String]) { 
    val data = DecisionTreeUtil.getTrainTestData() 
    val train_data = data._1 
    val test_data = data._2 
    val iterations = 10 
    val bins_param = Array(2, 4, 8, 16, 32, 64, 100) 
    val maxDepth = 5 
    val categoricalFeaturesInfo = scala.Predef.Map[Int, Int]() 
    val i = 0 
    val results = new ArrayString 
    val resultsMap = new scala.collection.mutable.HashMap[ 
        String, String] 
    val dataset = new DefaultCategoryDataset() 
    for(i <- 0 until bins_param.length) { 
      val bin = bins_param(i) 
      val rmsle = { 
        DecisionTreeUtil.evaluate(train_data, test_data, 
         categoricalFeaturesInfo, 5, bin) 
      } 
      resultsMap.put(bin.toString,rmsle.toString) 
      dataset.addValue(rmsle, "RMSLE", bin) 
    } 
    val chart = new LineChart( 
      "MaxBins" , 
      "DecisionTree : RMSLE vs MaxBins") 
    chart.exec("MaxBins","RMSLE",dataset) 
    chart.pack( ) 
    RefineryUtilities.centerFrameOnScreen( chart ) 
    chart.setVisible( true ) 
    print(resultsMap) 
  } 

```

上述输出的图表如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_011.png)

# 梯度提升树的参数设置影响

梯度提升树有两个主要参数：迭代次数和最大深度。我们将对这些进行变化并观察效果。

# 迭代

Scala

```scala
object GradientBoostedTreesIterations{ 

  def main(args: Array[String]) { 
    val data = GradientBoostedTreesUtil.getTrainTestData() 
    val train_data = data._1 
    val test_data = data._2 

    val iterations_param = Array(1, 5, 10, 15, 18) 

    val i = 0 
    val resultsMap = new scala.collection.mutable.HashMap[ 
        String, String] 
    val dataset = new DefaultCategoryDataset() 
    for(i <- 0 until iterations_param.length) { 
      val iteration = iterations_param(i) 
      val rmsle = GradientBoostedTreesUtil.evaluate(train_data,  
        test_data,iteration,maxDepth) 
      resultsMap.put(iteration.toString,rmsle.toString) 
      dataset.addValue(rmsle, "RMSLE", iteration) 
    } 
    val chart = new LineChart( 
      "Iterations" , 
      "GradientBoostedTrees : RMSLE vs Iterations") 
    chart.exec("Iterations","RMSLE",dataset) 
    chart.pack( ) 
    chart.lineChart.getCategoryPlot().
       getRangeAxis().setRange(1.32, 1.37) 
    RefineryUtilities.centerFrameOnScreen( chart ) 
    chart.setVisible( true ) 
    print(resultsMap) 
  } 
} 

```

上述输出的图表如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_012.png)

# MaxBins

接下来我们看一下改变最大箱数如何影响 RMSLE 值。

Scala

让我们看一下 Scala 中的示例实现。我们将计算最大箱数为`10`、`16`、`32`和`64`时的 RMSLE 值。

```scala
object GradientBoostedTreesMaxBins{ 

  def main(args: Array[String]) { 
    val data = GradientBoostedTreesUtil.getTrainTestData() 
    val train_data = data._1 
    val test_data = data._2 

    val maxBins_param = Array(10,16,32,64) 
    val iteration = 10 
    val maxDepth = 3 

    val i = 0 
    val resultsMap =  
    new scala.collection.mutable.HashMap[String, String] 
    val dataset = new DefaultCategoryDataset() 
    for(i <- 0 until maxBins_param.length) { 
      val maxBin = maxBins_param(i) 
      val rmsle = GradientBoostedTreesUtil.evaluate(train_data, 
         test_data,iteration,maxDepth, maxBin) 

      resultsMap.put(maxBin.toString,rmsle.toString) 
      dataset.addValue(rmsle, "RMSLE", maxBin) 
    } 
    val chart = new LineChart( 
      "Max Bin" , 
      "GradientBoostedTrees : RMSLE vs MaxBin") 
    chart.exec("MaxBins","RMSLE",dataset) 
    chart.pack( ) 
    chart.lineChart.getCategoryPlot(). 
        getRangeAxis().setRange(1.35, 1.37) 
    RefineryUtilities.centerFrameOnScreen( chart ) 
    chart.setVisible(true) 
    print(resultsMap) 
  } 

```

上述输出的图表如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_07_013.png)

# 总结

在本章中，您看到了如何在回归模型的背景下使用 ML 库的线性模型、决策树、梯度提升树、岭回归和等温回归功能。我们探讨了分类特征提取，以及在回归问题中应用转换对目标变量的影响。最后，我们实现了各种性能评估指标，并使用它们来实施交叉验证练习，探讨线性模型和决策树中各种参数设置对测试集模型性能的影响。

在下一章中，我们将介绍一种不同的机器学习方法，即无监督学习，特别是聚类模型。


# 第八章：使用 Spark 构建聚类模型

在过去的几章中，我们涵盖了监督学习方法，其中训练数据带有我们想要预测的真实结果的标签（例如，推荐的评级和分类的类分配，或者在回归的情况下是真实目标变量）。

接下来，我们将考虑没有可用标记数据的情况。这被称为**无监督学习**，因为模型没有受到真实目标标签的监督。无监督情况在实践中非常常见，因为在许多真实场景中获取标记的训练数据可能非常困难或昂贵（例如，让人类为分类标签标记训练数据）。然而，我们仍然希望学习数据中的一些潜在结构，并使用这些结构进行预测。

这就是无监督学习方法可以发挥作用的地方。无监督学习模型也经常与监督模型结合使用；例如，应用无监督技术为监督模型创建新的输入特征。

聚类模型在许多方面类似于分类模型的无监督等价物。在分类中，我们试图学习一个模型，可以预测给定训练示例属于哪个类。该模型本质上是从一组特征到类的映射。

在聚类中，我们希望对数据进行分段，以便将每个训练示例分配给一个称为**簇**的段。这些簇的作用很像类，只是真实的类分配是未知的。

聚类模型有许多与分类相同的用例；其中包括以下内容：

+   根据行为特征和元数据将用户或客户分成不同的群体

+   在网站上对内容进行分组或在零售业务中对产品进行分组

+   寻找相似基因的簇

+   在生态学中对社区进行分割

+   创建图像段，用于图像分析应用，如目标检测

在本章中，我们将：

+   简要探讨几种聚类模型

+   从数据中提取特征，特别是使用一个模型的输出作为我们聚类模型的输入特征

+   训练一个聚类模型并使用它进行预测

+   应用性能评估和参数选择技术来选择要使用的最佳簇数

# 聚类模型的类型

有许多不同形式的聚类模型可用，从简单到极其复杂。Spark MLlib 目前提供 k-means 聚类，这是最简单的方法之一。然而，它通常非常有效，而且其简单性意味着相对容易理解并且可扩展。

# k-means 聚类

k-means 试图将一组数据点分成*K*个不同的簇（其中*K*是模型的输入参数）。

更正式地说，k-means 试图找到簇，以便最小化每个簇内的平方误差（或距离）。这个目标函数被称为**簇内平方误差和**（**WCSS**）。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_001.png)

它是每个簇中每个点与簇中心之间的平方误差的总和。

从一组*K*个初始簇中心开始（这些中心是计算为簇中所有数据点的平均向量），K-means 的标准方法在两个步骤之间进行迭代：

1.  将每个数据点分配给最小化 WCSS 的簇。平方和等于平方欧氏距离；因此，这相当于根据欧氏距离度量将每个点分配给**最接近**的簇中心。

1.  根据第一步的簇分配计算新的簇中心。

该算法进行到达到最大迭代次数或收敛为止。**收敛**意味着在第一步期间簇分配不再改变；因此，WCSS 目标函数的值也不再改变。

有关更多详细信息，请参考 Spark 关于聚类的文档[`spark.apache.org/docs/latest/mllib-clustering.html`](http://spark.apache.org/docs/latest/mllib-clustering.html)或参考[`en.wikipedia.org/wiki/K-means_clustering`](http://en.wikipedia.org/wiki/K-means_clustering)。

为了说明 K-means 的基础知识，我们将使用我们在第六章中展示的多类分类示例中所示的简单数据集，*使用 Spark 构建分类模型*。回想一下，我们有五个类别，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_002.png)

多类数据集

然而，假设我们实际上不知道真实的类别。如果我们使用五个簇的 k-means，那么在第一步之后，模型的簇分配可能是这样的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_003.png)

第一次 K-means 迭代后的簇分配

我们可以看到，k-means 已经相当好地挑选出了每个簇的中心。在下一次迭代之后，分配可能看起来像下图所示的那样：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_004.png)

第二次 K-means 迭代后的簇分配

事情开始稳定下来，但总体簇分配与第一次迭代后基本相同。一旦模型收敛，最终的分配可能看起来像这样：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_005.png)

K-means 的最终簇分配

正如我们所看到的，模型已经相当好地分离了这五个簇。最左边的三个相当准确（有一些错误的点）。然而，右下角的两个簇不太准确。

这说明：

+   K-means 的迭代性质

+   模型对于最初选择簇中心的方法的依赖性（这里，我们将使用随机方法）

+   最终的簇分配对于分离良好的数据可能非常好，但对于更困难的数据可能较差

# 初始化方法

k-means 的标准初始化方法通常简称为随机方法，它首先随机将每个数据点分配给一个簇，然后进行第一个更新步骤。

Spark ML 提供了这种初始化方法的并行变体，称为**K-means++**，这是默认的初始化方法。

有关更多信息，请参阅[`en.wikipedia.org/wiki/K-means_clustering#Initialization_methods`](http://en.wikipedia.org/wiki/K-means_clustering#Initialization_methods)和[`en.wikipedia.org/wiki/K-means%2B%2B`](http://en.wikipedia.org/wiki/K-means%2B%2B)。

使用 K-means++的结果如下所示。请注意，这一次，困难的右下角点大部分被正确地聚类了：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_006.png)

K-means++的最终簇分配

还有许多其他的 K-means 变体；它们侧重于初始化方法或核心模型。其中一个更常见的变体是**模糊 K-means**。这个模型不像 K-means 那样将每个点分配给一个簇（所谓的硬分配）。相反，它是 K-means 的软版本，其中每个点可以属于许多簇，并且由相对于每个簇的成员资格表示。因此，对于*K*个簇，每个点被表示为一个 K 维成员资格向量，向量中的每个条目表示在每个簇中的成员资格比例。

# 混合模型

**混合模型**本质上是模糊 K 均值背后思想的延伸；然而，它假设存在一个生成数据的潜在概率分布。例如，我们可能假设数据点是从一组 K 个独立的高斯（正态）概率分布中抽取的。簇分配也是软的，因此每个点在 K 个潜在概率分布中都由*K*成员权重表示。

有关混合模型的更多详细信息和混合模型的数学处理，请参见[`en.wikipedia.org/wiki/Mixture_model`](http://en.wikipedia.org/wiki/Mixture_model)。

# 分层聚类

**分层聚类**是一种结构化的聚类方法，它会产生一个多级别的簇层次结构，其中每个簇可能包含许多子簇。因此，每个子簇都与父簇相关联。这种形式的聚类通常也被称为**树状聚类**。

凝聚聚类是一种自下而上的方法：

+   每个数据点都开始在自己的簇中

+   评估每对簇之间的相似性（或距离）

+   找到最相似的一对簇；然后将这对簇合并成一个新的簇

+   该过程重复进行，直到只剩下一个顶层簇

**分裂聚类**是一种自上而下的方法，从一个簇开始，然后在每个阶段将一个簇分裂成两个，直到所有数据点都被分配到自己的底层簇中。

**自上而下聚类**比自下而上聚类更复杂，因为需要第二个平面聚类算法作为“子程序”。如果我们不生成完整的层次结构到单个文档叶子，自上而下聚类具有更高的效率。

您可以在[`en.wikipedia.org/wiki/Hierarchical_clustering`](http://en.wikipedia.org/wiki/Hierarchical_clustering)找到更多信息。

# 从数据中提取正确的特征

与迄今为止遇到的大多数机器学习模型一样，k 均值聚类需要数值向量作为输入。我们已经看到的用于分类和回归的相同特征提取和转换方法也适用于聚类。

与最小二乘回归一样，由于 k 均值使用平方误差函数作为优化目标，它往往会受到异常值和具有大方差的特征的影响。

聚类可以用来检测异常值，因为它们可能会引起很多问题。

对于回归和分类情况，输入数据可以被标准化和规范化以克服这一问题，这可能会提高准确性。然而，在某些情况下，如果例如目标是根据某些特定特征找到分割，可能不希望标准化数据。

# 从 MovieLens 数据集中提取特征

在使用聚类算法之前，我们将使用 ALS 算法获取用户和项目（电影）的数值特征：

1.  首先将数据`u.data`加载到 DataFrame 中：

```scala
      val ratings = spark.sparkContext 
      .textFile(DATA_PATH + "/u.data") 
      .map(_.split("\t")) 
      .map(lineSplit => Rating(lineSplit(0).toInt, 
        lineSplit(1).toInt,  lineSplit(2).toFloat, 
        lineSplit(3).toLong)) 
      .toDF()

```

1.  然后我们将其按 80:20 的比例分割，得到训练和测试数据：

```scala
      val Array(training, test) =  
        ratings.randomSplit(Array(0.8, 0.2))

```

1.  我们实例化`ALS`类，将最大迭代次数设置为`5`，正则化参数设置为`0.01`：

```scala
      val als = new ALS() 
        .setMaxIter(5) 
        .setRegParam(0.01) 
        .setUserCol("userId") 
        .setItemCol("movieId") 
        .setRatingCol("rating")

```

1.  然后我们创建一个模型，然后计算预测：

```scala
      val model = als.fit(training) 
      val predictions = model.transform(test)

```

1.  接着计算`userFactors`和`itemFactors`：

```scala
      val itemFactors = model.itemFactors 
      itemFactors.show() 

      val userFactors = model.userFactors 
      userFactors.show()

```

1.  我们将它们转换为 libsvm 格式并将它们持久化在一个文件中。请注意，我们持久化所有特征以及两个特征：

```scala
      val itemFactorsOrdererd = itemFactors.orderBy("id") 
      val itemFactorLibSVMFormat = 
        itemFactorsOrdererd.rdd.map(x => x(0) + " " + 
        getDetails(x(1).asInstanceOf
          [scala.collection.mutable.WrappedArray[Float]])) 
      println("itemFactorLibSVMFormat.count() : " + 
        itemFactorLibSVMFormat.count()) 
      print("itemFactorLibSVMFormat.first() : " + 
        itemFactorLibSVMFormat.first()) 

      itemFactorLibSVMFormat.coalesce(1)
        .saveAsTextFile(output + "/" + date_time + 
        "/movie_lens_items_libsvm")

```

`movie_lens_items_libsvm`的输出将如下所示：

```scala
          1 1:0.44353345 2:-0.7453435 3:-0.55146646 4:-0.40894786 
          5:-0.9921601 6:1.2012635 7:0.50330496 8:-0.23256435     
          9:0.55483425 10:-1.4781344
 2 1:0.34384087 2:-1.0242497 3:-0.20907198 4:-0.102892995 
          5:-1.0616653 6:1.1338154 7:0.5742042 8:-0.46505615  
          9:0.3823278 10:-1.0695107 3 1:-0.04743084 2:-0.6035447  
          3:-0.7999673 4:0.16897096    
          5:-1.0216197 6:0.3304353 7:1.5495727 8:0.2972699  
          9:-0.6855238 
          10:-1.5391738
 4 1:0.24745995 2:-0.33971268 3:0.025664425 4:0.16798466 
          5:-0.8462472 6:0.6734541 7:0.7537076 8:-0.7119413  
          9:0.7475001 
          10:-1.965572
 5 1:0.30903652 2:-0.8523586 3:-0.54090345 4:-0.7004097 
          5:-1.0383878 6:1.1784278 7:0.5125761 8:0.2566347         
          9:-0.020201845   
          10:-1.118083
 ....
 1681 1:-0.14603947 2:-0.4475343 3:-0.50514024 4:-0.7221697 
          5:-0.7997808 6:0.21069092 7:0.22631708 8:-0.32458723 
          9:0.20187362 10:-1.2734087
 1682 1:0.21975909 2:0.45303428 3:-0.73912954 4:-0.40584692 
          5:-0.5299451 6:0.79586357 7:0.5154468 8:-0.4033669  
          9:0.2220822 
          10:-0.70235217

```

1.  接下来，我们持久化前两个特征（具有最大变化）并将它们持久化在一个文件中：

```scala
      var itemFactorsXY = itemFactorsOrdererd.rdd.map( 
        x => getXY(x(1).asInstanceOf
        [scala.collection.mutable.WrappedArray[Float]])) 
      itemFactorsXY.first() 
      itemFactorsXY.coalesce(1).saveAsTextFile(output + "/" + 
        date_time + "/movie_lens_items_xy")

```

`movie_lens_items_xy`的输出将如下所示：

```scala
          2.254384458065033, 0.5487040132284164
          -2.0540390759706497, 0.5557805597782135
          -2.303591560572386, -0.047419726848602295
          -0.7448508385568857, -0.5028514862060547
          -2.8230229914188385, 0.8093537855893373
          -1.4274845123291016, 1.4835840165615082
          -1.3214656114578247, 0.09438827633857727
          -2.028286747634411, 1.0806758720427752
          -0.798517256975174, 0.8371041417121887
          -1.556841880083084, -0.8985426127910614
          -1.0867036543786526, 1.7443277575075626
          -1.4234793484210968, 0.6246072947978973
          -0.04958712309598923, 0.14585793018341064

```

1.  接下来我们计算`userFactors`的 libsvm 格式：

```scala
      val userFactorsOrdererd = userFactors.orderBy("id") 
      val userFactorLibSVMFormat = 
        userFactorsOrdererd.rdd.map(x => x(0) + " " + 
        getDetails(x(1).asInstanceOf
          [scala.collection.mutable.WrappedArray[Float]])) 
      println("userFactorLibSVMFormat.count() : " + 
        userFactorLibSVMFormat.count()) 
      print("userFactorLibSVMFormat.first() : " + 
        userFactorLibSVMFormat.first()) 

      userFactorLibSVMFormat.coalesce(1)
        .saveAsTextFile(output + "/" + date_time + 
        "/movie_lens_users_libsvm")

```

`movie_lens_users_libsvm`的输出将如下所示：

```scala
 1 1:0.75239724 2:0.31830165 3:0.031550772 4:-0.63495475 
          5:-0.719721 6:0.5437525 7:0.59800273 8:-0.4264512  
          9:0.6661331 
          10:-0.9702077
 2 1:-0.053673547 2:-0.24080916 3:-0.6896337 4:-0.3918436   
          5:-0.4108574 6:0.663401 7:0.1975566 8:0.43086317 9:1.0833738 
          10:-0.9398713
 3 1:0.6261427 2:0.58282375 3:-0.48752788 4:-0.36584544 
          5:-1.1869227 6:0.14955235 7:-0.17821303 8:0.3922112 
          9:0.5596394 10:-0.83293504
 4 1:1.0485783 2:0.2569924 3:-0.48094323 4:-1.8882223 
          5:-1.4912299 6:0.50734115 7:1.2781366 8:0.028034585 
          9:1.1323715 10:0.4267411
 5 1:0.31982875 2:0.13479441 3:0.5392742 4:0.33915272 
          5:-1.1892766 6:0.33669636 7:0.38314193 8:-0.9331541 
          9:0.531006 10:-1.0546529
 6 1:-0.5351592 2:0.1995535 3:-0.9234565 4:-0.5741345 
          5:-0.4506062 6:0.35505387 7:0.41615438 8:-0.32665777 
          9:0.22966743 10:-1.1040379
 7 1:0.41014928 2:-0.32102737 3:-0.73221415 4:-0.4017513 
          5:-0.87815255 6:0.3717881 7:-0.070220165 8:-0.5443932 
          9:0.24361002 10:-1.2957898
 8 1:0.2991327 2:0.3574251 3:-0.03855041 4:-0.1719838 
          5:-0.840421 6:0.89891523 7:0.024321048 8:-0.9811069 
          9:0.57676667 10:-1.2015694
 9 1:-1.4988179 2:0.42335498 3:0.5973782 4:-0.11305857 
          5:-1.3311529 6:0.91228217 7:1.461522 8:1.4502159 9:0.5554214 
          10:-1.5014526
 10 1:0.5876411 2:-0.26684982 3:-0.30273324 4:-0.78348076 
          5:-0.61448336 6:0.5506227 7:0.2809167 8:-0.08864456 
          9:0.57811487 10:-1.1085391

```

1.  接下来我们提取前两个特征并将它们持久化在一个文件中：

```scala
      var userFactorsXY = userFactorsOrdererd.rdd.map( 
        x => getXY(x(1).asInstanceOf
        [scala.collection.mutable.WrappedArray[Float]])) 
      userFactorsXY.first() 
      userFactorsXY.coalesce(1).saveAsTextFile(output + "/" + 
        date_time + "/movie_lens_user_xy")

```

`movie_lens_user_xy`的输出将如下所示：

```scala
          -0.2524261102080345, 0.4112294316291809
 -1.7868174277245998, 1.435323253273964
 -0.8313295543193817, 0.09025487303733826
 -2.55482479929924, 3.3726249802857637
 0.14377352595329285, -0.736962765455246
 -2.283802881836891, -0.4298199713230133
 -1.9229961037635803, -1.2950050458312035
 -0.39439742639660835, -0.682673366740346
 -1.9222962260246277, 2.8779889345169067
 -1.3799060583114624, 0.21247059851884842

```

我们将需要*xy*特征来对两个特征进行聚类，以便我们可以创建一个二维图。

# K-means - 训练聚类模型

在 Spark ML 中，对 K-means 进行训练采用了与其他模型类似的方法——我们将包含训练数据的 DataFrame 传递给`KMeans`对象的 fit 方法。

在这里，我们使用 libsvm 数据格式。

# 在 MovieLens 数据集上训练聚类模型

我们将为我们通过运行推荐模型生成的电影和用户因子训练模型。

我们需要传入簇的数量*K*和算法运行的最大迭代次数。如果从一次迭代到下一次迭代的目标函数的变化小于容差水平（默认容差为 0.0001），则模型训练可能会运行少于最大迭代次数。

Spark ML 的 k-means 提供了随机和 K-means ||初始化，其中默认为 K-means ||。由于这两种初始化方法在某种程度上都是基于随机选择的，因此每次模型训练运行都会返回不同的结果。

K-means 通常不会收敛到全局最优模型，因此进行多次训练运行并从这些运行中选择最优模型是一种常见做法。MLlib 的训练方法公开了一个选项，可以完成多个模型训练运行。通过评估损失函数的评估，选择最佳训练运行作为最终模型。

1.  首先，我们创建一个`SparkSession`实例，并使用它来加载`movie_lens_users_libsvm`数据：

```scala
      val spConfig = (new 
        SparkConf).setMaster("local[1]").setAppName("SparkApp"). 
        set("spark.driver.allowMultipleContexts", "true") 

      val spark = SparkSession 
        .builder() 
        .appName("Spark SQL Example") 
        .config(spConfig) 
        .getOrCreate() 

      val datasetUsers = spark.read.format("libsvm").load( 
        "./OUTPUT/11_10_2016_10_28_56/movie_lens_users_libsvm/part-
        00000") 
      datasetUsers.show(3)

```

输出是：

```scala
          +-----+--------------------+
 |label|            features|
 +-----+--------------------+
 |  1.0|(10,[0,1,2,3,4,5,...|
 |  2.0|(10,[0,1,2,3,4,5,...|
 |  3.0|(10,[0,1,2,3,4,5,...|
 +-----+--------------------+
 only showing top 3 rows

```

1.  然后我们创建一个模型：

```scala
      val kmeans = new KMeans().setK(5).setSeed(1L) 
      val modelUsers = kmeans.fit(datasetUsers)

```

1.  最后，我们使用用户向量数据集训练一个 K-means 模型：

```scala
      val modelUsers = kmeans.fit(datasetUsers)

```

**K-means**：使用聚类模型进行预测。

使用训练好的 K-means 模型是简单的，并且类似于我们迄今为止遇到的其他模型，如分类和回归。

通过将 DataFrame 传递给模型的 transform 方法，我们可以对多个输入进行预测：

```scala
      val predictedUserClusters = modelUsers.transform(datasetUsers) 
      predictedUserClusters.show(5)

```

结果输出是预测列中每个数据点的聚类分配：

```scala
+-----+--------------------+----------+
|label|            features|prediction|
+-----+--------------------+----------+
|  1.0|(10,[0,1,2,3,4,5,...|         2|
|  2.0|(10,[0,1,2,3,4,5,...|         0|
|  3.0|(10,[0,1,2,3,4,5,...|         0|
|  4.0|(10,[0,1,2,3,4,5,...|         2|
|  5.0|(10,[0,1,2,3,4,5,...|         2|
+-----+--------------------+----------+
only showing top 5 rows

```

由于随机初始化，聚类分配可能会从模型的一次运行到另一次运行发生变化，因此您的结果可能与之前显示的结果不同。聚类 ID 本身没有固有含义；它们只是从 0 开始的任意标记。

# K-means - 解释 MovieLens 数据集上的簇预测

我们已经介绍了如何对一组输入向量进行预测，但是我们如何评估预测的好坏呢？我们稍后将介绍性能指标；但是在这里，我们将看到如何手动检查和解释我们的 k-means 模型所做的聚类分配。

虽然无监督技术的优点是不需要我们提供标记的训练数据，但缺点是通常需要手动解释结果。通常，我们希望进一步检查找到的簇，并可能尝试解释它们并为它们分配某种标签或分类。

例如，我们可以检查我们找到的电影的聚类，尝试看看是否有一些有意义的解释，比如在聚类中的电影中是否有共同的流派或主题。我们可以使用许多方法，但我们将从每个聚类中取几部最接近聚类中心的电影开始。我们假设这些电影最不可能在其聚类分配方面边缘化，因此它们应该是最具代表性的电影之一。通过检查这些电影集，我们可以看到每个聚类中的电影共享哪些属性。

# 解释电影簇

我们将尝试通过将数据集与预测输出数据集中的电影名称进行连接，列出与每个聚类相关联的电影：

```scala
Cluster : 0
--------------------------
+--------------------+
|                name|
+--------------------+
|    GoldenEye (1995)|
|   Four Rooms (1995)|
|Shanghai Triad (Y...|
|Twelve Monkeys (1...|
|Dead Man Walking ...|
|Usual Suspects, T...|
|Mighty Aphrodite ...|
|Antonia's Line (1...|
|   Braveheart (1995)|
|  Taxi Driver (1976)|
+--------------------+
only showing top 10 rows

Cluster : 1
--------------------------
+--------------------+
|                name|
+--------------------+
|     Bad Boys (1995)|
|Free Willy 2: The...|
|        Nadja (1994)|
|     Net, The (1995)|
|       Priest (1994)|
|While You Were Sl...|
|Ace Ventura: Pet ...|
|   Free Willy (1993)|
|Remains of the Da...|
|Sleepless in Seat...|
+--------------------+
only showing top 10 rows

Cluster : 2
--------------------------
+--------------------+
|                name|
+--------------------+
|    Toy Story (1995)|
|   Get Shorty (1995)|
|      Copycat (1995)|
|  Richard III (1995)|
|Seven (Se7en) (1995)|
|Mr. Holland's Opu...|
|From Dusk Till Da...|
|Brothers McMullen...|
|Batman Forever (1...|
|   Disclosure (1994)|
+--------------------+
only showing top 10 rows

Cluster : 3
--------------------------
+--------------------+
|                name|
+--------------------+
|         Babe (1995)|
|  Postino, Il (1994)|
|White Balloon, Th...|
|Muppet Treasure I...|
|Rumble in the Bro...|
|Birdcage, The (1996)|
|    Apollo 13 (1995)|
|Belle de jour (1967)|
| Crimson Tide (1995)|
|To Wong Foo, Than...|
+--------------------+
only showing top 10 rows

```

# 解释电影簇

在本节中，我们将回顾代码，其中我们获取每个标签的预测并将它们保存在文本文件中，并绘制二维散点图。

我们将创建两个散点图，一个用于用户，另一个用于项目（在这种情况下是电影）：

```scala
object MovieLensKMeansPersist { 

  val BASE= "./data/movie_lens_libsvm_2f" 
  val time = System.currentTimeMillis() 
  val formatter = new SimpleDateFormat("dd_MM_yyyy_hh_mm_ss") 

  import java.util.Calendar 
  val calendar = Calendar.getInstance() 
  calendar.setTimeInMillis(time) 
  val date_time = formatter.format(calendar.getTime()) 

  def main(args: Array[String]): Unit = { 

    val spConfig = ( 
    new SparkConf).setMaster("local[1]"). 
    setAppName("SparkApp"). 
      set("spark.driver.allowMultipleContexts", "true") 

    val spark = SparkSession 
      .builder() 
      .appName("Spark SQL Example") 
      .config(spConfig) 
      .getOrCreate() 

    val datasetUsers = spark.read.format("libsvm").load( 
      BASE + "/movie_lens_2f_users_libsvm/part-00000") 
    datasetUsers.show(3) 

    val kmeans = new KMeans().setK(5).setSeed(1L) 
    val modelUsers = kmeans.fit(datasetUsers) 

    // Evaluate clustering by computing Within  
    //Set Sum of Squared Errors. 

    val predictedDataSetUsers = modelUsers.transform(datasetUsers) 
    print(predictedDataSetUsers.first()) 
    print(predictedDataSetUsers.count()) 
    val predictionsUsers = 
    predictedDataSetUsers.select("prediction"). 
    rdd.map(x=> x(0)) 
    predictionsUsers.saveAsTextFile( 
    BASE + "/prediction/" + date_time + "/users") 

    val datasetItems = spark.read.format("libsvm").load( 
      BASE + "/movie_lens_2f_items_libsvm/part-00000") 
    datasetItems.show(3) 

    val kmeansItems = new KMeans().setK(5).setSeed(1L) 
    val modelItems = kmeansItems.fit(datasetItems) 
    // Evaluate clustering by computing Within  
    //Set Sum of Squared Errors. 
    val WSSSEItems = modelItems.computeCost(datasetItems) 
    println(s"Items :  Within Set Sum of Squared Errors = 
      $WSSSEItems") 

    // Shows the result. 
    println("Items - Cluster Centers: ") 
    modelUsers.clusterCenters.foreach(println) 
    val predictedDataSetItems = modelItems.transform(datasetItems) 
    val predictionsItems = predictedDataSetItems. 
      select("prediction").rdd.map(x=> x(0)) 
    predictionsItems.saveAsTextFile(BASE + "/prediction/" +  
      date_time + "/items") 
    spark.stop() 
  }

```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_007.png)

具有用户数据的 K 均值聚类

上图显示了用户数据的 K 均值聚类。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_008.png)

具有项目数据的 K 均值聚类图

上图显示了项目数据的 K 均值聚类。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_009.png)

K 均值绘制聚类数的效果

上图显示了具有两个特征和一个迭代的用户数据的 K 均值聚类。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_010.png)

上图显示了具有两个特征和 10 次迭代的用户数据的 K 均值聚类。请注意聚类边界的移动。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_011.png)

上图显示了具有两个特征和 10 次迭代的用户数据的 K 均值聚类。请注意聚类边界的移动。

# K 均值-评估聚类模型的性能

使用回归、分类和推荐引擎等模型，可以应用许多评估指标来分析聚类模型的性能和数据点的聚类好坏。聚类评估通常分为内部评估和外部评估。内部评估是指使用相同的数据来训练模型和进行评估的情况。外部评估是指使用训练数据之外的数据进行评估。

# 内部评估指标

常见的内部评估指标包括我们之前介绍的 WCSS（这恰好是 K 均值的目标函数）、Davies-Bouldin 指数、Dunn 指数和轮廓系数。所有这些指标都倾向于奖励集群，其中集群内的元素相对较近，而不同集群中的元素相对较远。

聚类评估的维基百科页面[`en.wikipedia.org/wiki/Cluster_analysis#Internal_evaluation`](http://en.wikipedia.org/wiki/Cluster_analysis)有更多细节。

# 外部评估指标

由于聚类可以被视为无监督分类，如果有某种标记（或部分标记）的数据可用，我们可以使用这些标签来评估聚类模型。我们可以使用模型对集群（即类标签）进行预测，并使用类似于分类评估的指标来评估预测（即基于真正和假负率）。

这些包括 Rand 指标、F 指标、Jaccard 指数等。

有关聚类外部评估的更多信息，请参见[`en.wikipedia.org/wiki/Cluster_analysis#External_evaluation`](http://en.wikipedia.org/wiki/Cluster_analysis)。

# 在 MovieLens 数据集上计算性能指标

Spark ML 提供了一个方便的`computeCost`函数，用于计算给定 DataFrame 的 WSSS 目标函数。我们将为以下项目和用户训练数据计算此指标：

```scala
val WSSSEUsers = modelUsers.computeCost(datasetUsers) 
println(s"Users :  Within Set Sum of Squared Errors = $WSSSEUsers") 
val WSSSEItems = modelItems.computeCost(datasetItems)   
println(s"Items :  Within Set Sum of Squared Errors = $WSSSEItems")

```

这应该输出类似于以下结果：

```scala
Users :  Within Set Sum of Squared Errors = 2261.3086181660324
Items :  Within Set Sum of Squared Errors = 5647.825222497311

```

衡量 WSSSE 有效性的最佳方法是如下部分所示的迭代次数。

# 迭代对 WSSSE 的影响

让我们找出迭代对 MovieLens 数据集的 WSSSE 的影响。我们将计算各种迭代值的 WSSSE 并绘制输出。

代码清单如下：

```scala
object MovieLensKMeansMetrics { 
  case class RatingX(userId: Int, movieId: Int, rating: Float, 
    timestamp: Long) 
  val DATA_PATH= "../../../data/ml-100k" 
  val PATH_MOVIES = DATA_PATH + "/u.item" 
  val dataSetUsers = null 

  def main(args: Array[String]): Unit = { 

    val spConfig = (new 
      SparkConf).setMaster("local[1]").setAppName("SparkApp"). 
      set("spark.driver.allowMultipleContexts", "true") 

    val spark = SparkSession 
      .builder() 
      .appName("Spark SQL Example") 
      .config(spConfig) 
      .getOrCreate() 

    val datasetUsers = spark.read.format("libsvm").load( 
      "./data/movie_lens_libsvm/movie_lens_users_libsvm/part-
      00000") 
    datasetUsers.show(3) 

    val k = 5 
    val itr = Array(1,10,20,50,75,100) 
    val result = new ArrayString 
    for(i <- 0 until itr.length){ 
      val w = calculateWSSSE(spark,datasetUsers,itr(i),5,1L) 
      result(i) = itr(i) + "," + w 
    } 
    println("----------Users----------") 
    for(j <- 0 until itr.length) { 
      println(result(j)) 
    } 
    println("-------------------------") 

    val datasetItems = spark.read.format("libsvm").load( 
      "./data/movie_lens_libsvm/movie_lens_items_libsvm/"+     
      "part-00000") 

    val resultItems = new ArrayString 
    for(i <- 0 until itr.length){ 
      val w = calculateWSSSE(spark,datasetItems,itr(i),5,1L) 
      resultItems(i) = itr(i) + "," + w 
    } 

    println("----------Items----------") 
    for(j <- 0 until itr.length) { 
      println(resultItems(j)) 
    } 
    println("-------------------------") 

    spark.stop() 
  } 

  import org.apache.spark.sql.DataFrame 

  def calculateWSSSE(spark : SparkSession, dataset : DataFrame,  
    iterations : Int, k : Int, seed : Long) : Double = { 
    val x = dataset.columns 

    val kmeans =  
      new KMeans().setK(k).setSeed(seed).setMaxIter(iterations) 

    val model = kmeans.fit(dataset) 
    val WSSSEUsers = model.computeCost(dataset) 
    return WSSSEUsers 

  }

```

输出是：

```scala
----------Users----------
1,2429.214784372865
10,2274.362593105573
20,2261.3086181660324
50,2261.015660051977
75,2261.015660051977
100,2261.015660051977
-------------------------

----------Items----------
1,5851.444935665099
10,5720.505597821477
20,5647.825222497311
50,5637.7439669472005
75,5637.7439669472005
100,5637.7439669472005

```

让我们绘制这些数字以更好地了解：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_012.png)

用户 WSSSE 与迭代次数

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_013.png)

项目 WSSSE 与迭代次数

# 二分 KMeans

这是通用 KMeans 的变体。

参考：[`www.siam.org/meetings/sdm01/pdf/sdm01_05.pdf`](http://www.siam.org/meetings/sdm01/pdf/sdm01_05.pdf)

算法的步骤是：

1.  通过随机选择一个点，比如 ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/B05184_08_x11.png) 然后计算*M*的质心*w*并计算：

*![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/B05184_08_x2.png)*

**质心**是聚类的中心。质心是一个包含每个变量的一个数字的向量，其中每个数字是该聚类中观察值的平均值。

1.  将*M =[x1, x2, ... xn]*分成两个子聚类*M[L]*和*M[R]*，根据以下规则：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/B05184_08_x3.png)

1.  计算*M[L]*和*M[R]*的质心*w[L]*和*w[R]*，如第 2 步所示。

1.  如果 *w[L] = c[L]* 和 *w[R] = c[R]*，则停止。

否则，让 c[L]= w[L] c[R] = w[R]，转到第 2 步。

# 二分 K 均值-训练聚类模型

在 Spark ML 中进行二分 K 均值的训练涉及采用类似其他模型的方法--我们将包含训练数据的 DataFrame 传递给`KMeans`对象的 fit 方法。请注意，这里我们使用 libsvm 数据格式：

1.  实例化聚类对象：

```scala
        val spConfig = (new                         
        SparkConf).setMaster("local[1]").setAppName("SparkApp"). 
        set("spark.driver.allowMultipleContexts", "true") 

        val spark = SparkSession 
          .builder() 
          .appName("Spark SQL Example") 
          .config(spConfig) 
          .getOrCreate() 

        val datasetUsers = spark.read.format("libsvm").load( 
          BASE + "/movie_lens_2f_users_libsvm/part-00000") 
        datasetUsers.show(3)

```

命令`show(3)`的输出如下所示：

```scala
 +-----+--------------------+
 |label|            features|
 +-----+--------------------+
 |  1.0|(2,[0,1],[0.37140...|
 |  2.0|(2,[0,1],[-0.2131...|
 |  3.0|(2,[0,1],[0.28579...|
 +-----+--------------------+
 only showing top 3 rows

```

创建`BisectingKMeans`对象并设置参数：

```scala
          val bKMeansUsers = new BisectingKMeans() 
          bKMeansUsers.setMaxIter(10) 
          bKMeansUsers.setMinDivisibleClusterSize(5)

```

1.  训练数据：

```scala
          val modelUsers = bKMeansUsers.fit(datasetUsers) 

          val movieDF = Util.getMovieDataDF(spark) 
          val predictedUserClusters = 
            modelUsers.transform(datasetUsers) 
          predictedUserClusters.show(5)

```

输出是：

```scala
          +-----+--------------------+----------+
 |label|            features|prediction|
 +-----+--------------------+----------+
 |  1.0|(2,[0,1],[0.37140...|         3|
 |  2.0|(2,[0,1],[-0.2131...|         3|
 |  3.0|(2,[0,1],[0.28579...|         3|
 |  4.0|(2,[0,1],[-0.6541...|         1|
 |  5.0|(2,[0,1],[0.90333...|         2|
 +-----+--------------------+----------+
 only showing top 5 rows

```

1.  按聚类显示电影：

```scala
        val joinedMovieDFAndPredictedCluster = 
          movieDF.join(predictedUserClusters,predictedUserClusters
          ("label") === movieDF("id")) 
        print(joinedMovieDFAndPredictedCluster.first()) 
        joinedMovieDFAndPredictedCluster.show(5)

```

输出是：

```scala
 +--+---------------+-----------+-----+--------------------+----------+
 |id|          name|       date|label|      features|prediction|
 +--+---------------+-----------+-----+--------------------+----------+
 | 1| Toy Story (1995)  |01-Jan-1995|  1.0|(2,[0,1],[0.37140...|3|
 | 2| GoldenEye (1995)  |01-Jan-1995|  2.0|(2,[0,1],[-0.2131...|3|
 | 3|Four Rooms (1995)  |01-Jan-1995|  3.0|(2,[0,1],[0.28579...|3|
 | 4| Get Shorty (1995) |01-Jan-1995|  4.0|(2,[0,1],[-0.6541...|1|
 | 5| Copycat (1995)    |01-Jan-1995|  5.0|(2,[0,1],[0.90333...|2|
 +--+----------------+-----------+-----+--------------------+----------+
 only showing top 5 rows

```

让我们按照聚类编号打印电影：

```scala
        for(i <- 0 until 5) { 
          val prediction0 =     
          joinedMovieDFAndPredictedCluster.filter("prediction == " + i) 
          println("Cluster : " + i) 
          println("--------------------------") 
          prediction0.select("name").show(10) 
        }

```

输出是：

```scala
          Cluster : 0
 +--------------------+
 |                name|
 +--------------------+
 |Antonia's Line (1...|
 |Angels and Insect...|
 |Rumble in the Bro...|
 |Doom Generation, ...|
 |     Mad Love (1995)|
 | Strange Days (1995)|
 |       Clerks (1994)|
 |  Hoop Dreams (1994)|
 |Legends of the Fa...|
 |Professional, The...|
 +--------------------+
 only showing top 10 rows

 Cluster : 1
 --------------------------

 +--------------------+
 |                name|
 +--------------------+
 |   Get Shorty (1995)|
 |Dead Man Walking ...|
 |  Richard III (1995)|
 |Seven (Se7en) (1995)|
 |Usual Suspects, T...|
 |Mighty Aphrodite ...|
 |French Twist (Gaz...|
 |Birdcage, The (1996)|
 |    Desperado (1995)|
 |Free Willy 2: The...|
 +--------------------+
 only showing top 10 rows

 Cluster : 2
 --------------------------
 +--------------------+
          |                name|
 +--------------------+
          |      Copycat (1995)|
          |Shanghai Triad (Y...|
 |  Postino, Il (1994)|
          |From Dusk Till Da...|
          |   Braveheart (1995)|
 |Batman Forever (1...|
 |        Crumb (1994)|
          |To Wong Foo, Than...|
 |Billy Madison (1995)|
 |Dolores Claiborne...|
          +--------------------+
 only showing top 10 rows

          Cluster : 3
          --------------------------
          +--------------------+
 |                name|
          +--------------------+
          |    Toy Story (1995)|
 |    GoldenEye (1995)|
 |   Four Rooms (1995)|
 |Twelve Monkeys (1...|
          |         Babe (1995)|
 |Mr. Holland's Opu...|
 |White Balloon, Th...|
 |Muppet Treasure I...|
          |  Taxi Driver (1976)|
          |Brothers McMullen...|
 +--------------------+
          only showing top 10 rows

```

让我们计算 WSSSE：

```scala
          val WSSSEUsers = modelUsers.computeCost(datasetUsers) 
          println(s"Users : Within Set Sum of Squared Errors =                      $WSSSEUsers") 

          println("Users : Cluster Centers: ") 
          modelUsers.clusterCenters.foreach(println)

```

输出是：

```scala
          Users : Within Set Sum of Squared Errors = 220.213984126387
          Users : Cluster Centers: 
          [-0.5152650631965345,-0.17908608684257435]
          [-0.7330009110582011,0.5699292831746033]
          [0.4657482296168242,0.07541218866995708]
          [0.07297392612510972,0.7292946749843259]

```

接下来我们对物品进行预测：

```scala
          val datasetItems = spark.read.format("libsvm").load( 
            BASE + "/movie_lens_2f_items_libsvm/part-00000") 
          datasetItems.show(3) 

          val kmeansItems = new BisectingKMeans().setK(5).setSeed(1L) 
          val modelItems = kmeansItems.fit(datasetItems) 

          // Evaluate clustering by computing Within Set 
          // Sum of Squared Errors. 
          val WSSSEItems = modelItems.computeCost(datasetItems) 
          println(s"Items : Within Set Sum of Squared Errors = 
            $WSSSEItems") 

          // Shows the result. 
          println("Items - Cluster Centers: ") 
          modelUsers.clusterCenters.foreach(println) 

          Items: within Set Sum of Squared Errors = 538.4272487824393 
          Items - Cluster Centers:  
            [-0.5152650631965345,-0.17908608684257435] 
            [-0.7330009110582011,0.5699292831746033] 
            [0.4657482296168242,0.07541218866995708] 
            [0.07297392612510972,0.7292946749843259]

```

源代码：

[`github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_08/scala/2.0.0/src/main/scala/org/sparksamples/kmeans/BisectingKMeans.scala`](https://github.com/ml-resources/spark-ml/blob/branch-ed2/Chapter_08/scala/2.0.0/src/main/scala/org/sparksamples/kmeans/BisectingKMeans.scala)

1.  绘制用户和物品聚类。

接下来，让我们选择两个特征，并绘制用户和物品聚类及其各自的聚类：

```scala
          object BisectingKMeansPersist { 
            val PATH = "/home/ubuntu/work/spark-2.0.0-bin-hadoop2.7/" 
            val BASE = "./data/movie_lens_libsvm_2f" 

            val time = System.currentTimeMillis() 
            val formatter = new 
              SimpleDateFormat("dd_MM_yyyy_hh_mm_ss") 

            import java.util.Calendar 
            val calendar = Calendar.getInstance() 
            calendar.setTimeInMillis(time) 
            val date_time = formatter.format(calendar.getTime()) 

            def main(args: Array[String]): Unit = { 

              val spConfig = (new     
                SparkConf).setMaster("local[1]")
                .setAppName("SparkApp"). 
              set("spark.driver.allowMultipleContexts", "true") 

              val spark = SparkSession 
                .builder() 
                .appName("Spark SQL Example") 
                .config(spConfig) 
                .getOrCreate() 

              val datasetUsers = spark.read.format("libsvm").load( 
                BASE + "/movie_lens_2f_users_libsvm/part-00000") 

              val bKMeansUsers = new BisectingKMeans() 
              bKMeansUsers.setMaxIter(10) 
              bKMeansUsers.setMinDivisibleClusterSize(5) 

              val modelUsers = bKMeansUsers.fit(datasetUsers) 
              val predictedUserClusters = 
                modelUsers.transform(datasetUsers) 

              modelUsers.clusterCenters.foreach(println) 
              val predictedDataSetUsers = 
                modelUsers.transform(datasetUsers) 
              val predictionsUsers =       
                predictedDataSetUsers.select("prediction")
                .rdd.map(x=> x(0)) 
               predictionsUsers.saveAsTextFile(BASE + 
                 "/prediction/" +      
               date_time + "/bkmeans_2f_users")    

               val datasetItems = 
                 spark.read.format("libsvm").load(BASE + 
                 "/movie_lens_2f_items_libsvm/part-00000") 

               val kmeansItems = new 
                 BisectingKMeans().setK(5).setSeed(1L) 
               val modelItems = kmeansItems.fit(datasetItems) 

               val predictedDataSetItems = 
                 modelItems.transform(datasetItems) 
               val predictionsItems =      
                 predictedDataSetItems.select("prediction")
                 .rdd.map(x=> x(0)) 
                 predictionsItems.saveAsTextFile(BASE + 
                 "/prediction/" +         
               date_time + "/bkmeans_2f_items") 
               spark.stop() 
            } 
          }

```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_014.png)

用聚类绘制 MovieLens 用户数据

上述图表显示了两个特征的用户聚类的样子。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_015.png)

用聚类绘制 MovieLens 物品（电影）数据

上述图表显示了两个特征的物品聚类的样子。

# WSSSE 和迭代

在本节中，我们评估了对 K 均值算法进行二分时迭代次数对 WSSSE 的影响。

源代码是：

```scala
object BisectingKMeansMetrics { 
  case class RatingX(userId: Int, movieId: Int,  
    rating: Float, timestamp: Long) 
  val DATA_PATH= "../../../data/ml-100k" 
  val PATH_MOVIES = DATA_PATH + "/u.item" 
  val dataSetUsers = null 

  def main(args: Array[String]): Unit = { 

    val spConfig = ( 
      new SparkConf).setMaster("local[1]").setAppName("SparkApp"). 
      set("spark.driver.allowMultipleContexts", "true") 

    val spark = SparkSession 
      .builder() 
      .appName("Spark SQL Example") 
      .config(spConfig) 
      .getOrCreate() 

    val datasetUsers = spark.read.format("libsvm").load( 
      "./data/movie_lens_libsvm/movie_lens_users_libsvm/part-
      00000") 
    datasetUsers.show(3) 

    val k = 5 
    val itr = Array(1,10,20,50,75,100) 
    val result = new ArrayString 
    for(i <- 0 until itr.length){ 
      val w = calculateWSSSE(spark,datasetUsers,itr(i),5) 
      result(i) = itr(i) + "," + w 
    } 
    println("----------Users----------") 
    for(j <- 0 until itr.length) { 
      println(result(j)) 
    } 
    println("-------------------------") 

    val datasetItems = spark.read.format("libsvm").load( 
      "./data/movie_lens_libsvm/movie_lens_items_libsvm/part-
      00000") 
    val resultItems = new ArrayString 
    for(i <- 0 until itr.length){ 
      val w = calculateWSSSE(spark,datasetItems,itr(i),5) 
      resultItems(i) = itr(i) + "," + w 
    } 

    println("----------Items----------") 
    for(j <- 0 until itr.length) { 
      println(resultItems(j)) 
    } 
    println("-------------------------") 

    spark.stop() 
  } 

  import org.apache.spark.sql.DataFrame 

  def calculateWSSSE(spark : SparkSession, dataset : DataFrame, 
    iterations : Int, k : Int) : Double = 
  { 
    val x = dataset.columns 

    val bKMeans = new BisectingKMeans() 
    bKMeans.setMaxIter(iterations) 
    bKMeans.setMinDivisibleClusterSize(k) 

    val model = bKMeans.fit(dataset) 
    val WSSSE = model.computeCost(dataset) 
    return WSSSE 

  } 
}

```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_016.png)

图：用户迭代的 WSSSE

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_017.png)

图：在二分 K 均值情况下物品的 WSSSE 与迭代次数

很明显，该算法在 20 次迭代后对用户和物品都达到了最佳的 WSSSE。

# 高斯混合模型

混合模型是一个人口中子群体的概率模型。这些模型用于对子群体的统计推断，给定汇总人口的观察结果。

**高斯混合模型**（**GMM**）是一个以高斯分量密度的加权和表示的混合模型。它的模型系数是使用迭代的**期望最大化**（**EM**）算法或从训练模型的**最大后验**（**MAP**）估计的。

`spark.ml`的实现使用 EM 算法。

它具有以下参数：

+   **k**：期望的聚类数量

+   **convergenceTol**：在认为收敛达到的对数似然的最大变化

+   **maxIterations**：执行而不收敛的最大迭代次数

+   **initialModel**：可选的起始点，从这里开始 EM 算法

（如果省略此参数，将从数据中构造一个随机起始点）

# 使用 GMM 进行聚类

我们将为用户和物品（在这种情况下是电影）创建聚类，以更好地了解算法如何对用户和物品进行分组。

执行以下步骤：

1.  加载用户的`libsvm`文件。

1.  创建一个高斯混合实例。该实例具有以下可配置的参数：

```scala
       final val featuresCol: Param[String] 
       Param for features column name. 
       final val k: IntParam 
       Number of independent Gaussians in the mixture model. 
       final val 
       maxIter: IntParam 
       Param for maximum number of iterations (>= 0). 
       final val predictionCol: Param[String] 
       Param for prediction column name. 
       final val probabilityCol: Param[String] 
       Param for Column name for predicted class conditional 
       probabilities. 
       final val seed: LongParam 
       Param for random seed. 
       final val tol: DoubleParam

```

1.  在我们的情况下，我们将只设置高斯分布的数量和种子数：

```scala
       val gmmUsers = new GaussianMixture().setK(5).setSeed(1L)

```

1.  创建一个用户模型：

```scala
       Print Covariance and Mean
      for (i <- 0 until modelUsers.gaussians.length) { 
        println("Users: weight=%f\ncov=%s\nmean=\n%s\n" format 
          (modelUsers.weights(i), modelUsers.gaussians(i).cov,                           
          modelUsers.gaussians(i).mean)) 
      }

```

完整的代码清单是：

```scala
          object GMMClustering { 

            def main(args: Array[String]): Unit = { 
              val spConfig = (new SparkConf).setMaster("local[1]"). 
                setAppName("SparkApp"). 
                set("spark.driver.allowMultipleContexts", "true") 

              val spark = SparkSession 
                .builder() 
                .appName("Spark SQL Example") 
                .config(spConfig) 
                .getOrCreate() 

              val datasetUsers = spark.read.format("libsvm").                
               load("./data/movie_lens_libsvm/movie_lens_users_libsvm/"
               + "part-00000") 
              datasetUsers.show(3) 

              val gmmUsers = new GaussianMixture().setK(5).setSeed(1L) 
              val modelUsers = gmmUsers.fit(datasetUsers) 

              for (i <- 0 until modelUsers.gaussians.length) { 
                println("Users : weight=%f\ncov=%s\nmean=\n%s\n" 
                   format (modelUsers.weights(i),  
                   modelUsers.gaussians(i).cov,  
                   modelUsers.gaussians(i).mean)) 
                } 

              val dataSetItems = spark.read.format("libsvm").load( 
                "./data/movie_lens_libsvm/movie_lens_items_libsvm/" + 
                "part-00000") 

              val gmmItems = new 
                  GaussianMixture().setK(5).setSeed(1L) 
              val modelItems = gmmItems.fit(dataSetItems) 

              for (i <- 0 until modelItems.gaussians.length) { 
                println("Items : weight=%f\ncov=%s\nmean=\n%s\n" 
                   format (modelUsers.weights(i), 
                   modelUsers.gaussians(i).cov, 
                   modelUsers.gaussians(i).mean)) 
              } 
              spark.stop() 
            }

```

# 用 GMM 聚类绘制用户和物品数据

在这一部分，我们将看一下基于 GMM 的聚类边界随着迭代次数的增加而移动：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_018.png)

MovieLens 用户数据通过 GMM 分配的聚类图

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_019.png)

MovieLens 项目数据通过 GMM 分配的聚类图

# GMM - 迭代次数对聚类边界的影响

让我们看一下随着 GMM 迭代次数的增加，聚类边界如何变化：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_020.png)

使用一次迭代的用户数据的 GMM 聚类图

上图显示了使用一次迭代的用户数据的 GMM 聚类。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_021.png)

使用 10 次迭代的用户数据的 GMM 聚类图

上图显示了使用 10 次迭代的用户数据的 GMM 聚类。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ml-spark/img/image_08_022.png)

使用 20 次迭代的用户数据的 GMM 聚类图

上图显示了使用 20 次迭代的用户数据的 GMM 聚类。

# 总结

在本章中，我们探讨了一种从未标记数据中学习结构的新模型类别 -- 无监督学习。我们通过所需的输入数据和特征提取进行了工作，并看到如何使用一个模型的输出（在我们的例子中是推荐模型）作为另一个模型的输入（我们的 k-means 聚类模型）。最后，我们评估了聚类模型的性能，既使用了对聚类分配的手动解释，也使用了数学性能指标。

在下一章中，我们将介绍另一种无监督学习方法，用于将数据减少到其最重要的特征或组件 -- 降维模型。
