# Spark 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/BF1FAE88E839F4D0A5A0FD250CEC5835`](https://zh.annas-archive.org/md5/BF1FAE88E839F4D0A5A0FD250CEC5835)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 MLlib 进行监督学习 - 回归

本章分为以下几个部分：

+   使用线性回归

+   理解成本函数

+   使用套索进行线性回归

+   进行岭回归

# 介绍

以下是维基百科对监督学习的定义：

> *“监督学习是从标记的训练数据中推断函数的机器学习任务。”*

监督学习有两个步骤：

+   使用训练数据集训练算法；这就像是先提出问题和它们的答案

+   使用测试数据集向训练好的算法提出另一组问题。

有两种监督学习算法：

+   **回归**：这预测连续值输出，比如房价。

+   **分类**：这预测离散值输出（0 或 1）称为标签，比如一封电子邮件是否是垃圾邮件。分类不仅限于两个值；它可以有多个值，比如标记一封电子邮件为重要、不重要、紧急等等（0, 1, 2…）。

### 注意

本章将介绍回归，下一章将介绍分类。

作为回归的示例数据集，我们将使用加利福尼亚州萨拉托加市最近售出的房屋数据作为训练集来训练算法。一旦算法训练好了，我们将要求它根据房屋的尺寸来预测房价。下图说明了工作流程：

![介绍](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_01.jpg)

这里的假设，对于它的作用来说，可能听起来像一个误称，你可能会认为预测函数可能是一个更好的名字，但是假设这个词是出于历史原因而使用的。

如果我们只使用一个特征来预测结果，就称为**双变量分析**。当我们有多个特征时，就称为**多变量分析**。事实上，我们可以有任意多个特征。其中一种算法，**支持向量机**（**SVM**），我们将在下一章中介绍，实际上允许你拥有无限数量的特征。

本章将介绍如何使用 MLlib，Spark 的机器学习库进行监督学习。

### 注意

数学解释已尽可能简单地提供，但你可以随意跳过数学，直接转到*如何做……*部分。

# 使用线性回归

线性回归是一种基于一个或多个预测变量或特征*x*来建模响应变量*y*值的方法。

## 准备工作

让我们使用一些房屋数据来预测房屋的价格，基于它的大小。以下是 2014 年初加利福尼亚州萨拉托加市房屋的大小和价格：

| 房屋大小（平方英尺） | 价格 |
| --- | --- |
| 2100 | $ 1,620,000 |
| 2300 | $ 1,690,000 |
| 2046 | $ 1,400,000 |
| 4314 | $ 2,000,000 |
| 1244 | $ 1,060,000 |
| 4608 | $ 3,830,000 |
| 2173 | $ 1,230,000 |
| 2750 | $ 2,400,000 |
| 4010 | $ 3,380,000 |
| 1959 | $ 1,480,000 |

这里有一个相同的图形表示：

![准备工作](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_04.jpg)

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  导入统计和相关类：

```scala
scala> import org.apache.spark.mllib.linalg.Vectors
scala> import org.apache.spark.mllib.regression.LabeledPoint
scala> import org.apache.spark.mllib.regression.LinearRegressionWithSGD

```

1.  创建`LabeledPoint`数组，房价作为标签：

```scala
scala> val points = Array(
LabeledPoint(1620000,Vectors.dense(2100)),
LabeledPoint(1690000,Vectors.dense(2300)),
LabeledPoint(1400000,Vectors.dense(2046)),
LabeledPoint(2000000,Vectors.dense(4314)),
LabeledPoint(1060000,Vectors.dense(1244)),
LabeledPoint(3830000,Vectors.dense(4608)),
LabeledPoint(1230000,Vectors.dense(2173)),
LabeledPoint(2400000,Vectors.dense(2750)),
LabeledPoint(3380000,Vectors.dense(4010)),
LabeledPoint(1480000,Vectors.dense(1959))
)

```

1.  创建上述数据的 RDD：

```scala
scala> val pricesRDD = sc.parallelize(points)

```

1.  使用这些数据训练模型，进行 100 次迭代。这里，步长被保持得很小，以适应响应变量的非常大的值，也就是房价。第四个参数是每次迭代使用的数据集的一部分，最后一个参数是要使用的初始权重集（不同特征的权重）：

```scala
scala> val model = LinearRegressionWithSGD.train(pricesRDD,100,0.0000006,1.0,Vectors.zeros(1))

```

1.  预测一个 2500 平方英尺的房屋的价格：

```scala
scala> val prediction = model.predict(Vectors.dense(2500))

```

房屋大小只是一个预测变量。房价取决于其他变量，比如地块大小，房屋年龄等等。你拥有的变量越多，你的预测就会越准确。

# 理解成本函数

成本函数或损失函数在机器学习算法中非常重要。大多数算法都有某种形式的成本函数，目标是最小化它。影响成本函数的参数，比如上一个步骤中的`stepSize`，需要手动设置。因此，理解成本函数的整个概念非常重要。

在这个步骤中，我们将分析线性回归的成本函数。线性回归是一个简单的算法，可以帮助读者理解成本函数对于复杂算法的作用。

让我们回到线性回归。目标是找到最佳拟合线，使得误差的均方最小。这里，我们将误差定义为最佳拟合线的值与训练数据集中响应变量的实际值之间的差异。

对于单个自变量的简单情况，最佳拟合线可以写成：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_02.jpg)

这个函数也被称为**假设函数**，可以写成：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_03.jpg)

线性回归的目标是找到最佳拟合线。在这条线上，θ[0]代表*y*轴上的截距，θ[1]代表线的斜率，如下方程所示：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_05.jpg)

我们必须选择θ[0]和θ[1]，使得*h(x)*对于训练数据集中的*y*最接近。因此，对于第*i*个数据点，线与数据点之间的距离的平方为：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_06.jpg)

换句话说，这是预测房价与房屋实际售价之间的差的平方。现在，让我们计算训练数据集中这个值的平均值：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_07.jpg)

上述方程被称为线性回归的成本函数*J*。目标是最小化这个成本函数。

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_08.jpg)

这个成本函数也被称为**平方误差函数**。如果它们分别针对*J*绘制，θ[0]和θ[1]都会遵循凸曲线。

让我们举一个非常简单的数据集的例子，包括三个值，(1,1), (2,2), 和 (3,3)，以便计算更容易：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_09.jpg)

假设θ[1]为 0，也就是说，最佳拟合线与*x*轴平行。在第一种情况下，假设最佳拟合线是*x*轴，也就是*y=0*。那么，成本函数的值将如下：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_10.jpg)

现在，让我们把这条线稍微移动到*y=1*。那么，成本函数的值将如下：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_11.jpg)

现在，让我们把这条线进一步移动到*y=2*。那么，成本函数的值将如下：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_12.jpg)

现在，当我们把这条线进一步移动到*y=3*，成本函数的值将如下：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_13.jpg)

现在，让我们把这条线进一步移动到*y=4*。那么，成本函数的值将如下：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_14.jpg)

所以，你看到成本函数的值先减少，然后再次增加，就像这样：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_15.jpg)

现在，让我们通过将θ[0]设为 0 并使用不同的θ[1]值来重复这个练习。

在第一种情况下，假设最佳拟合线是*x*轴，也就是*y=0*。那么，成本函数的值将如下：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_16.jpg)

现在，让我们使用斜率为 0.5。那么，成本函数的值将如下：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_17.jpg)

现在，让我们使用斜率为 1。那么，成本函数的值将如下：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_18.jpg)

现在，当我们使用斜率为 1.5 时，以下将是成本函数的值：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_19.jpg)

现在，让我们使用斜率为 2.0。以下将是成本函数的值：

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_20.jpg)

如您在两个图中所见，当斜率或曲线的梯度为 0 时，*J*的最小值是。

![理解成本函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_07_21.jpg)

当θ[0]和θ[1]都映射到 3D 空间时，它就像一个碗的形状，成本函数的最小值在其底部。

到达最小值的这种方法称为**梯度下降**。在 Spark 中，实现是随机梯度下降。

# 使用套索进行线性回归

套索是线性回归的收缩和选择方法。它最小化了通常的平方误差和系数绝对值之和的边界。它基于原始套索论文，可在[`statweb.stanford.edu/~tibs/lasso/lasso.pdf`](http://statweb.stanford.edu/~tibs/lasso/lasso.pdf)找到。

我们在上一个示例中使用的最小二乘法也称为**普通最小二乘法**（**OLS**）。OLS 有两个挑战：

+   **预测准确性**：使用 OLS 进行的预测通常具有较低的预测偏差和较高的方差。通过缩小一些系数（甚至使它们为零），可以提高预测准确性。偏差会有所增加，但整体预测准确性会提高。

+   **解释**：对于预测变量的数量较多，希望找到其中表现最强的子集（相关性）。

### 注意

偏差与方差

预测误差背后有两个主要原因：偏差和方差。理解偏差和方差的最佳方法是看一个情况，我们在同一数据集上多次进行预测。

偏差是预测结果与实际值之间的估计差距，方差是不同预测值之间的差异的估计。

通常，添加更多的特征有助于减少偏差，这是很容易理解的。如果在构建预测模型时，我们遗漏了一些具有显著相关性的特征，这将导致显著的误差。

如果您的模型方差很高，可以删除特征以减少它。更大的数据集也有助于减少方差。

在这里，我们将使用一个简单的数据集，这是一个不适当的数据集。不适当的数据集是指样本数据量小于预测变量的数量。

| y | x0 | x1 | x2 | x3 | x4 | x5 | x6 | x7 | x8 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 5 | 3 | 1 | 2 | 1 | 3 | 2 | 2 | 1 |
| 2 | 9 | 8 | 8 | 9 | 7 | 9 | 8 | 7 | 9 |

您可以很容易地猜到，在这里，九个预测变量中，只有两个与*y*有强相关性，即*x0*和*x1*。我们将使用这个数据集和套索算法来验证其有效性。

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  导入统计和相关类：

```scala
scala> import org.apache.spark.mllib.linalg.Vectors
scala> import org.apache.spark.mllib.regression.LabeledPoint
scala> import org.apache.spark.mllib.regression.LassoWithSGD

```

1.  创建带有房价作为标签的`LabeledPoint`数组：

```scala
scala> val points = Array(
LabeledPoint(1,Vectors.dense(5,3,1,2,1,3,2,2,1)),
LabeledPoint(2,Vectors.dense(9,8,8,9,7,9,8,7,9))
)

```

1.  创建一个 RDD 的前述数据：

```scala
scala> val rdd = sc.parallelize(points)

```

1.  使用这些数据训练一个模型，使用 100 次迭代。在这里，步长和正则化参数已经手动设置：

```scala
scala> val model = LassoWithSGD.train(rdd,100,0.02,2.0)

```

1.  检查有多少预测变量的系数被设置为零：

```scala
scala> model.weights
org.apache.spark.mllib.linalg.Vector = [0.13455106581619633,0.02240732644670294,0.0,0.0,0.0,0.01360995990267153,0.0,0.0,0.0]

```

如您所见，九个预测变量中有六个的系数被设置为零。这是套索的主要特征：它认为不实用的任何预测变量，通过将它们的系数设置为零，从方程中移除它们。

# 进行岭回归

改进预测质量的套索的另一种方法是岭回归。在套索中，许多特征的系数被设置为零，因此从方程中消除，在岭回归中，预测变量或特征受到惩罚，但永远不会被设置为零。

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  导入统计和相关类：

```scala
scala> import org.apache.spark.mllib.linalg.Vectors
scala> import org.apache.spark.mllib.regression.LabeledPoint
scala> import org.apache.spark.mllib.regression.RidgeRegressionWithSGD

```

1.  创建带有房价作为标签的`LabeledPoint`数组：

```scala
scala> val points = Array(
LabeledPoint(1,Vectors.dense(5,3,1,2,1,3,2,2,1)),
LabeledPoint(2,Vectors.dense(9,8,8,9,7,9,8,7,9))
)

```

1.  创建一个包含上述数据的 RDD：

```scala
scala> val rdd = sc.parallelize(points)

```

1.  使用这些数据训练一个模型，进行 100 次迭代。在这里，步长和正则化参数已经手动设置：

```scala
scala> val model = RidgeRegressionWithSGD.train(rdd,100,0.02,2.0)

```

1.  检查有多少预测变量的系数被设为零：

```scala
scala> model.weights
org.apache.spark.mllib.linalg.Vector = [0.049805969577244584,0.029883581746346748,0.009961193915448916,0.019922387830897833,0.009961193915448916,0.029883581746346748,0.019922387830897833,0.019922387830897833,0.009961193915448916]

```

如您所见，与套索不同，岭回归不会将任何预测变量的系数设为零，但它确实使一些系数非常接近于零。


# 第八章：监督学习与 MLlib – 分类

本章分为以下几个部分：

+   使用逻辑回归进行分类

+   使用支持向量机进行二元分类

+   使用决策树进行分类

+   使用随机森林进行分类

+   使用梯度提升树进行分类

+   使用朴素贝叶斯进行分类

# 介绍

分类问题类似于上一章讨论的回归问题，只是结果变量 *y* 只取少数离散值。在二元分类中，*y* 只取两个值：0 或 1。你也可以将分类中响应变量可以取的值看作代表类别。

# 使用逻辑回归进行分类

在分类中，响应变量 *y* 具有离散值，而不是连续值。一些例子包括电子邮件（垃圾邮件/非垃圾邮件）、交易（安全/欺诈）等。

下面方程中的 *y* 变量可以取两个值，0 或 1：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_01.jpg)

这里，0 被称为负类，1 表示正类。虽然我们称它们为正类或负类，但这只是为了方便起见。算法对这种分配持中立态度。

线性回归，虽然对于回归任务效果很好，但对于分类任务存在一些限制。这些包括：

+   拟合过程对异常值非常敏感

+   不能保证假设函数 *h(x)* 将适合于 0（负类）到 1（正类）的范围内

逻辑回归保证 *h(x)* 将适合于 0 到 1 之间。尽管逻辑回归中有回归一词，但这更像是一个误称，它实际上是一个分类算法：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_02.jpg)

在线性回归中，假设函数如下：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_03.jpg)

在逻辑回归中，我们稍微修改假设方程如下：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_04.jpg)

*g* 函数被称为**Sigmoid 函数**或**逻辑函数**，对于实数 *t* 定义如下：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_05.jpg)

这是 Sigmoid 函数的图形：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_06.jpg)

正如你所看到的，当 *t* 接近负无穷时，*g(t)* 接近 0，当 *t* 接近无穷时，*g(t)* 接近 1。因此，这保证了假设函数的输出永远不会超出 0 到 1 的范围。

现在假设函数可以重写为：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_07.jpg)

*h(x)* 是给定预测变量 *x* 的 *y = 1* 的估计概率，因此 *h(x)* 也可以重写为：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_08.jpg)

换句话说，假设函数显示了在给定特征矩阵 *x* 的情况下 *y* 为 1 的概率，由 ![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_09.jpg) 参数化。这个概率可以是 0 到 1 之间的任意实数，但我们的分类目标不允许我们有连续值；我们只能有两个值 0 或 1，表示负类或正类。

假设我们预测 *y = 1* 如果

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_10.jpg)

并且 *y = 0* 否则。如果我们再次看一下 S 形函数图，我们会意识到，当 ![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_11.jpg) S 形函数是 ![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_12.jpg)，也就是说，对于 *t* 的正值，它将预测为正类：

自从使用逻辑回归进行分类，这意味着对于使用逻辑回归进行分类的情况下，将会预测正类。为了更好地说明这一点，让我们将其扩展到双变量情况的非矩阵形式：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_15.jpg)

由方程![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_16.jpg)表示的平面将决定给定向量属于正类还是负类。这条线被称为决策边界。

这个边界不一定是线性的，取决于训练集。如果训练数据不能在线性边界上分离，可以添加更高级别的多项式特征来促进它。一个例子是通过平方 x1 和 x2 来添加两个新特征，如下所示：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_17.jpg)

请注意，对于学习算法来说，这种增强与以下方程式完全相同：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_18.jpg)

学习算法将把多项式的引入视为另一个特征。这给了你在拟合过程中很大的权力。这意味着通过正确选择多项式和参数，可以创建任何复杂的决策边界。

让我们花一些时间来理解如何选择参数的正确值，就像我们在线性回归的情况下所做的那样。线性回归的成本函数*J*是：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_19.jpg)

正如你所知，我们在这个成本函数中对成本进行了平均。让我们用成本项来表示这一点：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_20.jpg)

换句话说，成本项是算法在预测*h(x)*的真实响应变量值*y*时必须支付的成本：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_21.jpg)

这个成本对于线性回归来说效果很好，但是对于逻辑回归来说，这个成本函数是非凸的（也就是说，它会导致多个局部最小值），我们需要找到一个更好的凸方式来估计成本。

逻辑回归中效果很好的成本函数如下：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_22.jpg)

让我们通过结合这两个成本函数将它们合并成一个：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_23.jpg)

让我们将这个成本函数重新放回到*J*中：

![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_24.jpg)

目标是最小化成本，也就是最小化![使用逻辑回归进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_25.jpg)的值。这是通过梯度下降算法来实现的。Spark 有两个支持逻辑回归的类：

+   `LogisticRegressionWithSGD`

+   `LogisticRegressionWithLBFGS`

`LogisticRegressionWithLBFGS`类更受欢迎，因为它消除了优化步长的步骤。

## 准备工作

2006 年，铃木、鹤崎和光岡在日本不同海滩上对一种濒临灭绝的穴居蜘蛛的分布进行了一些研究。

让我们看一些关于颗粒大小和蜘蛛存在的数据：

| 颗粒大小（mm） | 蜘蛛存在 |
| --- | --- |
| 0.245 | 不存在 |
| 0.247 | 不存在 |
| 0.285 | 存在 |
| 0.299 | 存在 |
| 0.327 | 存在 |
| 0.347 | 存在 |
| 0.356 | 不存在 |
| 0.36 | 存在 |
| 0.363 | 不存在 |
| 0.364 | 存在 |
| 0.398 | 不存在 |
| 0.4 | 存在 |
| 0.409 | 不存在 |
| 0.421 | 存在 |
| 0.432 | 不存在 |
| 0.473 | 存在 |
| 0.509 | 存在 |
| 0.529 | 存在 |
| 0.561 | 不存在 |
| 0.569 | 不存在 |
| 0.594 | 存在 |
| 0.638 | 存在 |
| 0.656 | 存在 |
| 0.816 | 存在 |
| 0.853 | 存在 |
| 0.938 | 存在 |
| 1.036 | 存在 |
| 1.045 | 存在 |

我们将使用这些数据来训练算法。缺席将表示为 0，存在将表示为 1。

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  导入统计和相关类：

```scala
scala> import org.apache.spark.mllib.linalg.Vectors
scala> import org.apache.spark.mllib.regression.LabeledPoint
scala> import org.apache.spark.mllib.classification.LogisticRegressionWithLBFGS

```

1.  创建一个带有蜘蛛存在或不存在的`LabeledPoint`数组作为标签：

```scala
scala> val points = Array(
LabeledPoint(0.0,Vectors.dense(0.245)),
LabeledPoint(0.0,Vectors.dense(0.247)),
LabeledPoint(1.0,Vectors.dense(0.285)),
LabeledPoint(1.0,Vectors.dense(0.299)),
LabeledPoint(1.0,Vectors.dense(0.327)),
LabeledPoint(1.0,Vectors.dense(0.347)),
LabeledPoint(0.0,Vectors.dense(0.356)),
LabeledPoint(1.0,Vectors.dense(0.36)),
LabeledPoint(0.0,Vectors.dense(0.363)),
LabeledPoint(1.0,Vectors.dense(0.364)),
LabeledPoint(0.0,Vectors.dense(0.398)),
LabeledPoint(1.0,Vectors.dense(0.4)),
LabeledPoint(0.0,Vectors.dense(0.409)),
LabeledPoint(1.0,Vectors.dense(0.421)),
LabeledPoint(0.0,Vectors.dense(0.432)),
LabeledPoint(1.0,Vectors.dense(0.473)),
LabeledPoint(1.0,Vectors.dense(0.509)),
LabeledPoint(1.0,Vectors.dense(0.529)),
LabeledPoint(0.0,Vectors.dense(0.561)),
LabeledPoint(0.0,Vectors.dense(0.569)),
LabeledPoint(1.0,Vectors.dense(0.594)),
LabeledPoint(1.0,Vectors.dense(0.638)),
LabeledPoint(1.0,Vectors.dense(0.656)),
LabeledPoint(1.0,Vectors.dense(0.816)),
LabeledPoint(1.0,Vectors.dense(0.853)),
LabeledPoint(1.0,Vectors.dense(0.938)),
LabeledPoint(1.0,Vectors.dense(1.036)),
LabeledPoint(1.0,Vectors.dense(1.045)))

```

1.  创建前述数据的 RDD：

```scala
scala> val spiderRDD = sc.parallelize(points)

```

1.  使用这些数据训练模型（当所有预测因子为零时，截距是该值）：

```scala
scala> val lr = new LogisticRegressionWithLBFGS().setIntercept(true)
scala> val model = lr.run(spiderRDD)

```

1.  预测粒度为`0.938`的蜘蛛的存在：

```scala
scala> val predict = model.predict(Vectors.dense(0.938))

```

# 使用 SVM 进行二元分类

分类是一种根据其效用将数据分为不同类别的技术。例如，电子商务公司可以对潜在访客应用两个标签“会购买”或“不会购买”。

这种分类是通过向机器学习算法提供一些已经标记的数据来完成的，称为**训练数据**。挑战在于如何标记两个类之间的边界。让我们以下图所示的简单示例为例：

![使用 SVM 进行二元分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_26.jpg)

在前面的案例中，我们将灰色和黑色指定为“不会购买”和“会购买”标签。在这里，画一条线将两个类别分开就像下面这样简单：

![使用 SVM 进行二元分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_27.jpg)

这是我们能做到的最好吗？实际上并不是，让我们试着做得更好。黑色分类器与“会购买”和“不会购买”车辆并不是真正等距的。让我们尝试做得更好，就像下面这样：

![使用 SVM 进行二元分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_28.jpg)

现在看起来不错。实际上，这正是 SVM 算法所做的。您可以在前面的图中看到，实际上只有三辆车决定了线的斜率：线上方的两辆黑色车和线下方的一辆灰色车。这些车被称为**支持向量**，而其余的车，即向量，是无关紧要的。

有时候画一条线并不容易，可能需要一条曲线来分开两个类别，就像下面这样：

![使用 SVM 进行二元分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_29.jpg)

有时甚至这还不够。在这种情况下，我们需要超过两个维度来解决问题。我们需要的不是分类线，而是一个超平面。实际上，每当数据过于混乱时，增加额外的维度有助于找到一个分离类别的超平面。下图说明了这一点：

![使用 SVM 进行二元分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_30.jpg)

这并不意味着增加额外的维度总是一个好主意。大多数情况下，我们的目标是减少维度，只保留相关的维度/特征。有一整套算法专门用于降维；我们将在后面的章节中介绍这些算法。

## 如何做…

1.  Spark 库中加载了示例`libsvm`数据。我们将使用这些数据并将其加载到 HDFS 中：

```scala
$ hdfs dfs -put /opt/infoobjects/spark/data/mllib/sample_libsvm_data.txt /user/hduser/sample_libsvm_data.txt

```

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  执行所需的导入：

```scala
scala> import org.apache.spark.mllib.classification.SVMWithSGD
scala> import org.apache.spark.mllib.evaluation.BinaryClassificationMetrics
scala> import org.apache.spark.mllib.regression.LabeledPoint
scala> import org.apache.spark.mllib.linalg.Vectors
scala> import org.apache.spark.mllib.util.MLUtils

```

1.  将数据加载为 RDD：

```scala
scala> val svmData = MLUtils.loadLibSVMFile(sc,"sample_libsvm_data.txt")

```

1.  记录的数量：

```scala
scala> svmData.count

```

1.  现在让我们将数据集分成一半训练数据和一半测试数据：

```scala
scala> val trainingAndTest = svmData.randomSplit(Array(0.5,0.5))

```

1.  分配`training`和`test`数据：

```scala
scala> val trainingData = trainingAndTest(0)
scala> val testData = trainingAndTest(1)

```

1.  训练算法并构建模型进行 100 次迭代（您可以尝试不同的迭代次数，但您会发现，在某个时候，结果开始收敛，这是一个不错的选择）：

```scala
scala> val model = SVMWithSGD.train(trainingData,100)

```

1.  现在我们可以使用这个模型来预测任何数据集的标签。让我们预测测试数据中第一个点的标签：

```scala
scala> val label = model.predict(testData.first.features)

```

1.  让我们创建一个元组，第一个值是测试数据的预测值，第二个值是实际标签，这将帮助我们计算算法的准确性：

```scala
scala> val predictionsAndLabels = testData.map( r => (model.predict(r.features),r.label))

```

1.  您可以计算有多少记录预测和实际标签不匹配：

```scala
scala> predictionsAndLabels.filter(p => p._1 != p._2).count

```

# 使用决策树进行分类

决策树是机器学习算法中最直观的。我们经常在日常生活中使用决策树。

决策树算法有很多有用的特性：

+   易于理解和解释

+   处理分类和连续特征

+   处理缺失的特征

+   不需要特征缩放

决策树算法以倒序方式工作，其中包含特征的表达式在每个级别进行评估，并将数据集分成两个类别。我们将通过一个简单的哑剧的例子来帮助您理解这一点，大多数人在大学时都玩过。我猜了一个动物，然后让我的同事问我问题来猜出我的选择。她的提问是这样的：

Q1：这是一只大动物吗？

A：是的

Q2：这种动物是否活了 40 年以上？

A：是的

Q3：这种动物是大象吗？

A：是的

这显然是一个过于简化的情况，她知道我假设了一只大象（在大数据世界中你还能猜到什么？）。让我们扩展这个例子，包括一些更多的动物，如下图所示（灰色框是类）：

![使用决策树进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_31.jpg)

前面的例子是多类分类的一个案例。在这个配方中，我们将专注于二元分类。 

## 准备就绪

每当我们的儿子早上要上网球课时，前一天晚上教练会查看天气预报，并决定第二天早上是否适合打网球。这个配方将使用这个例子来构建一个决策树。

让我们决定影响早上是否打网球的天气特征：

+   雨

+   风速

+   温度

让我们建立一个不同组合的表：

| 雨 | 有风 | 温度 | 打网球？ |
| --- | --- | --- | --- |
| 是 | 是 | 炎热 | 否 |
| 是 | 是 | 正常 | 否 |
| 是 | 是 | 凉爽 | 否 |
| 否 | 是 | 炎热 | 否 |
| 否 | 是 | 凉爽 | 否 |
| 否 | 否 | 炎热 | 是 |
| 否 | 否 | 正常 | 是 |
| 否 | 否 | 凉爽 | 否 |

现在我们如何构建决策树呢？我们可以从雨、有风或温度中的一个开始。规则是从一个特征开始，以便最大化信息增益。

在雨天，正如你在表中看到的，其他特征并不重要，也不会打网球。对于风速很高的情况也是如此。

决策树，像大多数其他算法一样，只接受特征值作为双精度值。所以，让我们进行映射：

![准备就绪](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_32.jpg)

正类是 1.0，负类是 0.0。让我们使用 CSV 格式加载数据，使用第一个值作为标签：

```scala
$vi tennis.csv
0.0,1.0,1.0,2.0
0.0,1.0,1.0,1.0
0.0,1.0,1.0,0.0
0.0,0.0,1.0,2.0
0.0,0.0,1.0,0.0
1.0,0.0,0.0,2.0
1.0,0.0,0.0,1.0
0.0,0.0,0.0,0.0

```

## 如何做...

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  执行所需的导入：

```scala
scala> import org.apache.spark.mllib.tree.DecisionTree
scala> import org.apache.spark.mllib.regression.LabeledPoint
scala> import org.apache.spark.mllib.linalg.Vectors
scala> import org.apache.spark.mllib.tree.configuration.Algo._
scala> import org.apache.spark.mllib.tree.impurity.Entropy

```

1.  加载文件：

```scala
scala> val data = sc.textFile("tennis.csv")
```

1.  解析数据并将其加载到`LabeledPoint`中：

```scala
scala> val parsedData = data.map {
line =>  val parts = line.split(',').map(_.toDouble)
 LabeledPoint(parts(0), Vectors.dense(parts.tail)) }

```

1.  用这些数据训练算法：

```scala
scala> val model = DecisionTree.train(parsedData, Classification, Entropy, 3)

```

1.  为无雨、大风和凉爽的温度创建一个向量：

```scala
scala> val v=Vectors.dense(0.0,1.0,0.0)

```

1.  预测是否应该打网球：

```scala
scala> model.predict(v)

```

## 工作原理...

让我们为这个配方中创建的网球决策树绘制决策树：

![工作原理...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_33.jpg)

这个模型有三个级别的深度。选择哪个属性取决于我们如何最大化信息增益。它的衡量方式是通过衡量分裂的纯度。纯度意味着，无论确定性是否增加，那么给定的数据集将被视为正面或负面。在这个例子中，这相当于是否打网球的机会在增加，还是不打网球的机会在增加。

纯度是用熵来衡量的。熵是系统中混乱程度的度量。在这种情况下，更容易理解它是一种不确定性的度量：

![工作原理...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_34.jpg)

纯度的最高级别是 0，最低级别是 1。让我们尝试使用公式来确定纯度。

当雨是是的时候，打网球的概率是*p+*为 0/3 = 0。不打网球的概率*p_*为 3/3 = 1：

![工作原理...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_35.jpg)

这是一个纯净的集合。

当雨不下时，打网球的概率*p+*为 2/5 = 0.4。不打网球的概率*p_*为 3/5 = 0.6：

![工作原理...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_36.jpg)

这几乎是一个不纯的集合。最不纯的情况是概率为 0.5 的情况。

Spark 使用三种方法来确定不纯度：

+   基尼不纯度（分类）

+   熵（分类）

+   方差（回归）

信息增益是父节点杂质与两个子节点杂质的加权和之差。让我们看一下第一个分裂，将大小为 8 的数据分成大小为 3（左）和 5（右）的两个数据集。让我们称第一个分裂为*s1*，父节点为*rain*，左子节点为*no rain*，右子节点为*wind*。所以信息增益将是：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_37.jpg)

由于我们已经为*no rain*和*wind*计算了熵的杂质，现在让我们计算*rain*的熵：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_38.jpg)

现在让我们计算信息增益：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_39.jpg)

所以在第一个分裂中，信息增益为 0.2。这是我们能达到的最好效果吗？让我们看看我们的算法得出了什么。首先，让我们找出树的深度：

```scala
scala> model.depth
Int = 2

```

在这里，深度是`2`，而我们直观地构建的是`3`，所以这个模型似乎更优化。让我们看看树的结构：

```scala
scala> model.toDebugString
String =  "DecisionTreeModel classifier of depth 2 with 5 nodes
If (feature 1 <= 0.0)
 If (feature 2 <= 0.0)
 Predict: 0.0
 Else (feature 2 > 0.0)
 Predict: 1.0
Else (feature 1 > 0.0)
 Predict: 0.0

```

让我们以可视化的方式构建它，以便更好地理解：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_40.jpg)

我们不会在这里详细介绍，因为我们已经在之前的模型中做过了。我们将直接计算信息增益：0.44

正如你在这种情况下所看到的，信息增益为 0.44，是第一个模型的两倍多。

如果你看第二级节点，杂质为零。在这种情况下，这是很好的，因为我们在深度为 2 的情况下得到了它。想象一种情况，深度为 50。在那种情况下，决策树对训练数据效果很好，但对测试数据效果很差。这种情况被称为**过拟合**。

避免过拟合的一个解决方案是修剪。你将训练数据分成两组：训练集和验证集。你使用训练集训练模型。现在你用模型对验证集进行测试，逐渐移除左节点。如果移除叶节点（通常是单例节点，即只包含一个数据点）改善了模型的性能，那么这个叶节点就从模型中被修剪掉。

# 使用随机森林进行分类

有时一个决策树是不够的，所以会使用一组决策树来产生更强大的模型。这些被称为**集成学习算法**。集成学习算法不仅限于使用决策树作为基本模型。

集成学习算法中最受欢迎的是随机森林。在随机森林中，不是生长单一树，而是生长*K*棵树。每棵树都被赋予训练数据的一个随机子集*S*。更有趣的是，每棵树只使用特征的一个子集。在进行预测时，对树进行多数投票，这就成为了预测。

让我们用一个例子来解释这一点。目标是对一个给定的人做出预测，判断他/她的信用是好还是坏。

为了做到这一点，我们将提供带有标签的训练数据，也就是说，在这种情况下，一个带有特征和标签的人。现在我们不想创建特征偏差，所以我们将提供一个随机选择的特征集。提供一个随机选择的特征子集的另一个原因是，大多数真实世界的数据具有数百甚至数千个特征。例如，文本分类算法通常具有 50k-100k 个特征。

在这种情况下，为了给故事增添趣味，我们不会提供特征，而是会问不同的人为什么他们认为一个人信用好或坏。现在根据定义，不同的人暴露于一个人的不同特征（有时是重叠的），这给了我们与随机选择特征相同的功能。

我们的第一个例子是 Jack，他被贴上了“坏信用”的标签。我们将从 Jack 最喜欢的酒吧——大象酒吧的 Joey 开始。一个人能够推断为什么给定一个标签的唯一方法是通过问是/否的问题。让我们看看 Joey 说了什么：

Q1: Jack 是否慷慨地给小费？（特征：慷慨）

A: 不

Q2：杰克每次至少花 60 美元吗？（特征：挥霍）

A：是的

Q3：他是否倾向于在最小的挑衅下卷入酒吧斗殴？（特征：易怒）

A：是的

这就解释了为什么杰克信用不好。

现在我们问杰克的女朋友斯泰西：

Q1：我们一起出去玩时，杰克是否总是买单？（特征：慷慨）

A：不

Q2：杰克是否还我 500 美元？（特征：责任）

A：不

Q3：他是否有时为了炫耀而过度花钱？（特征：挥霍）

A：是的

这就解释了为什么杰克信用不好。

现在我们问杰克的好朋友乔治：

Q1：当杰克和我在我的公寓里玩时，他会自己清理吗？（特征：有组织）

A：不

Q2：杰克在我超级碗聚餐时是空手而来吗？（特征：关心）

A：是的

Q3：他是否曾经用“我忘了在家里带钱包”这个借口让我付他在餐馆的账单？（特征：责任）

A：是的

这就解释了为什么杰克信用不好。

现在我们谈谈信用良好的杰西卡。让我们问杰西卡的姐姐斯泰西：

Q1：每当我钱不够时，杰西卡是否会主动帮忙？（特征：慷慨）

A：是的

Q2：杰西卡是否按时支付账单？（特征：责任）

A：是的

Q3：杰西卡是否愿意帮我照顾孩子？（特征：关心）

A：是的

这就解释了为什么杰西卡信用良好。

现在我们问乔治，他碰巧是她的丈夫：

Q1：杰西卡是否保持房子整洁？（特征：有组织）

A：是的

Q2：她是否期望昂贵的礼物？（特征：挥霍）

A：不

Q3：当你忘记割草时，她会生气吗？（特征：易怒）

A：不

这就解释了为什么杰西卡信用良好。

现在让我们问大象酒吧的调酒师乔伊：

Q1：每当她和朋友一起来酒吧时，她是否大多是指定司机？（特征：负责）

A：是的

Q2：她是否总是带剩菜回家？（特征：挥霍）

A：是的

Q3：她是否慷慨地给小费？（特征：慷慨）

A：是的

随机森林的工作方式是在两个级别上进行随机选择：

+   数据的一个子集

+   一些特征的子集来分割数据

这两个子集可能会重叠。

在我们的例子中，我们有六个特征，我们将为每棵树分配三个特征。这样，我们有很大的机会会有重叠。

让我们将另外八个人添加到我们的训练数据集中：

| 名字 | 标签 | 慷慨 | 责任 | 关心 | 组织 | 挥霍 | 易怒 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 杰克 | 0 | 0 | 0 | 0 | 0 | 1 | 1 |
| 杰西卡 | 1 | 1 | 1 | 1 | 1 | 0 | 0 |
| 珍妮 | 0 | 0 | 0 | 1 | 0 | 1 | 1 |
| 瑞克 | 1 | 1 | 1 | 0 | 1 | 0 | 0 |
| 帕特 | 0 | 0 | 0 | 0 | 0 | 1 | 1 |
| 杰布：1 | 1 | 1 | 1 | 0 | 0 | 0 |
| 杰伊 | 1 | 0 | 1 | 1 | 1 | 0 | 0 |
| 纳特 | 0 | 1 | 0 | 0 | 0 | 1 | 1 |
| 罗恩 | 1 | 0 | 1 | 1 | 1 | 0 | 0 |
| 马特 | 0 | 1 | 0 | 0 | 0 | 1 | 1 |

## 准备好了

让我们将创建的数据放入以下文件的`libsvm`格式中：

```scala
rf_libsvm_data.txt
0 5:1 6:1
1 1:1 2:1 3:1 4:1
0 3:1 5:1 6:1
1 1:1 2:1 4:1
0 5:1 6:1
1 1:1 2:1 3:1 4:1
0 1:1 5:1 6:1
1 2:1 3:1 4:1
0 1:1 5:1 6:1

```

现在将其上传到 HDFS：

```scala
$ hdfs dfs -put rf_libsvm_data.txt

```

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  执行所需的导入：

```scala
scala> import org.apache.spark.mllib.tree.RandomForest
scala> import org.apache.spark.mllib.tree.configuration.Strategy
scala> import org.apache.spark.mllib.util.MLUtils

```

1.  加载和解析数据：

```scala
scala> val data =
 MLUtils.loadLibSVMFile(sc, "rf_libsvm_data.txt")

```

1.  将数据分割成“训练”和“测试”数据集：

```scala
scala> val splits = data.randomSplit(Array(0.7, 0.3))
scala> val (trainingData, testData) = (splits(0), splits(1))

```

1.  创建分类作为树策略（随机森林也支持回归）：

```scala
scala> val treeStrategy = Strategy.defaultStrategy("Classification")

```

1.  训练模型：

```scala
scala> val model = RandomForest.trainClassifier(trainingData,
 treeStrategy, numTrees=3, featureSubsetStrategy="auto", seed = 12345)

```

1.  在测试实例上评估模型并计算测试错误：

```scala
scala> val testErr = testData.map { point =>
 val prediction = model.predict(point.features)
 if (point.label == prediction) 1.0 else 0.0
}.mean()
scala> println("Test Error = " + testErr)

```

1.  检查模型：

```scala
scala> println("Learned Random Forest:n" + model.toDebugString)
Learned Random Forest:nTreeEnsembleModel classifier with 3 trees
 Tree 0:
 If (feature 5 <= 0.0)
 Predict: 1.0
 Else (feature 5 > 0.0)
 Predict: 0.0
 Tree 1:
 If (feature 3 <= 0.0)
 Predict: 0.0
 Else (feature 3 > 0.0)
 Predict: 1.0
 Tree 2:
 If (feature 0 <= 0.0)
 Predict: 0.0
 Else (feature 0 > 0.0)
 Predict: 1.0

```

## 它是如何工作的…

正如您在这个小例子中所看到的，三棵树使用了不同的特征。在具有数千个特征和训练数据的实际用例中，这种情况不会发生，但大多数树在如何看待特征和多数票的情况下会有所不同。请记住，在回归的情况下，树的平均值会得到最终值。

# 使用梯度提升树进行分类

另一个集成学习算法是**梯度提升树**（**GBTs**）。GBTs 一次训练一棵树，每棵新树都改进了先前训练树的缺点。

由于 GBTs 一次训练一棵树，所以它们可能比随机森林需要更长的时间。

## 准备好了

我们将使用前一个配方中使用的相同数据。

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  执行所需的导入操作：

```scala
scala> import org.apache.spark.mllib.tree.GradientBoostedTrees
scala> import org.apache.spark.mllib.tree.configuration.BoostingStrategy
scala> import org.apache.spark.mllib.util.MLUtils

```

1.  加载并解析数据：

```scala
scala> val data =
 MLUtils.loadLibSVMFile(sc, "rf_libsvm_data.txt")

```

1.  将数据分成“训练”和“测试”数据集：

```scala
scala> val splits = data.randomSplit(Array(0.7, 0.3))
scala> val (trainingData, testData) = (splits(0), splits(1))

```

1.  创建一个分类作为增强策略，并将迭代次数设置为`3`：

```scala
scala> val boostingStrategy =
 BoostingStrategy.defaultParams("Classification")
scala> boostingStrategy.numIterations = 3

```

1.  训练模型：

```scala
scala> val model = GradientBoostedTrees.train(trainingData, boostingStrategy)

```

1.  在测试实例上评估模型并计算测试误差：

```scala
scala> val testErr = testData.map { point =>
 val prediction = model.predict(point.features)
 if (point.label == prediction) 1.0 else 0.0
}.mean()
scala> println("Test Error = " + testErr)

```

1.  检查模型：

```scala
scala> println("Learned Random Forest:n" + model.toDebugString)

```

在这种情况下，模型的准确率为 0.9，低于我们在随机森林情况下得到的准确率。

# 使用朴素贝叶斯进行分类

让我们考虑使用机器学习构建电子邮件垃圾邮件过滤器。在这里，我们对两类感兴趣：垃圾邮件表示未经请求的消息，非垃圾邮件表示常规电子邮件：

![使用朴素贝叶斯进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_42.jpg)

第一个挑战是，当给定一封电子邮件时，我们如何将其表示为特征向量*x*。一封电子邮件只是一堆文本或一组单词（因此，这个问题领域属于更广泛的**文本分类**类别）。让我们用一个长度等于字典大小的特征向量来表示一封电子邮件。如果字典中的给定单词出现在电子邮件中，则值为 1；否则为 0。让我们构建一个表示内容为*在线药店销售*的电子邮件的向量：

![使用朴素贝叶斯进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_08_43.jpg)

该特征向量中的单词字典称为*词汇表*，向量的维度与词汇表的大小相同。如果词汇表大小为 10,000，则该特征向量中的可能值将为 210,000。

我们的目标是对*y*给定*x*的概率进行建模。为了对*P(x|y)*进行建模，我们将做出一个强烈的假设，即*x*是有条件独立的。这个假设被称为**朴素贝叶斯假设**，基于这个假设的算法被称为**朴素贝叶斯分类器**。

例如，对于*y=1*，表示垃圾邮件，出现“在线”和“药店”这两个词的概率是独立的。这是一个与现实无关的强烈假设，但在获得良好预测时效果非常好。

## 准备就绪

Spark 自带一个用于朴素贝叶斯的示例数据集。让我们将这个数据集加载到 HDFS 中：

```scala
$ hdfs dfs -put /opt/infoobjects/spark/data/mllib/sample_naive_bayes_data.txt
 sample_naive_bayes_data.txt

```

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  执行所需的导入操作：

```scala
scala> import org.apache.spark.mllib.classification.NaiveBayes
scala> import org.apache.spark.mllib.linalg.Vectors
scala> import org.apache.spark.mllib.regression.LabeledPoint

```

1.  将数据加载到 RDD 中：

```scala
scala> val data = sc.textFile("sample_naive_bayes_data.txt")

```

1.  将数据解析为`LabeledPoint`：

```scala
scala> val parsedData = data.map { line =>
 val parts = line.split(',')
 LabeledPoint(parts(0).toDouble, Vectors.dense(parts(1).split(' ').map(_.toDouble)))
}

```

1.  将数据一分为二，分别放入“训练”和“测试”数据集中：

```scala
scala> val splits = parsedData.randomSplit(Array(0.5, 0.5), seed = 11L)
scala> val training = splits(0)
scala> val test = splits(1)

```

1.  使用“训练”数据集训练模型：

```scala
val model = NaiveBayes.train(training, lambda = 1.0)

```

1.  预测“测试”数据集的标签：

```scala
val predictionAndLabel = test.map(p => (model.predict(p.features), p.label))

```


# 第九章：使用 MLlib 进行无监督学习

本章将介绍如何使用 MLlib、Spark 的机器学习库进行无监督学习。

本章分为以下几个部分：

+   使用 k-means 进行聚类

+   使用主成分分析进行降维

+   使用奇异值分解进行降维

# 介绍

以下是维基百科对无监督学习的定义：

> *"在机器学习中，无监督学习的问题是尝试在未标记的数据中找到隐藏的结构。"*

与监督学习相比，我们有标记数据来训练算法，在无监督学习中，我们要求算法自行找到结构。让我们来看下面的样本数据集：

![介绍](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_01.jpg)

从上图可以看出，数据点形成了两个簇，如下所示：

![介绍](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_02.jpg)

事实上，聚类是最常见的无监督学习算法类型。

# 使用 k-means 进行聚类

聚类分析或聚类是将数据分成多个组的过程，使得一组中的数据类似于其他组中的数据。

以下是聚类使用的一些示例：

+   **市场细分**：将目标市场分成多个细分，以便更好地满足每个细分的需求

+   **社交网络分析**：通过社交网络网站（如 Facebook）找到社交网络中一致的人群进行广告定位

+   **数据中心计算集群**：将一组计算机放在一起以提高性能

+   **天文数据分析**：理解天文数据和事件，如星系形成

+   **房地产**：根据相似特征识别社区

+   **文本分析**：将小说或散文等文本文档分成流派

k-means 算法最好通过图像来说明，所以让我们再次看看我们的样本图：

![使用 k-means 进行聚类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_01.jpg)

k-means 的第一步是随机选择两个点，称为**聚类中心**：

![使用 k-means 进行聚类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_03.jpg)

k-means 算法是一个迭代算法，分为两个步骤：

+   **簇分配步骤**：该算法将遍历每个数据点，并根据其距离更近的质心，将其分配给该质心，从而分配给它代表的簇

+   **移动质心步骤**：该算法将取每个质心并将其移动到簇中数据点的平均值

让我们看看在簇分配后我们的数据是什么样子：

![使用 k-means 进行聚类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_04.jpg)

现在让我们将聚类中心移动到簇中数据点的平均值，如下所示：

![使用 k-means 进行聚类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_05.jpg)

在这种情况下，一次迭代就足够了，进一步的迭代不会移动聚类中心。对于大多数真实数据，需要多次迭代才能将质心移动到最终位置。

k-means 算法需要输入一定数量的簇。

## 准备工作

让我们使用加利福尼亚州萨拉托加市的一些不同的住房数据。这次，我们将考虑地块面积和房价：

| 地块面积 | 房价（以千美元计） |
| --- | --- |
| --- | --- |
| 12839 | 2405 |
| 10000 | 2200 |
| 8040 | 1400 |
| 13104 | 1800 |
| 10000 | 2351 |
| 3049 | 795 |
| 38768 | 2725 |
| 16250 | 2150 |
| 43026 | 2724 |
| 44431 | 2675 |
| 40000 | 2930 |
| 1260 | 870 |
| 15000 | 2210 |
| 10032 | 1145 |
| 12420 | 2419 |
| 69696 | 2750 |
| 12600 | 2035 |
| 10240 | 1150 |
| 876 | 665 |
| 8125 | 1430 |
| 11792 | 1920 |
| 1512 | 1230 |
| 1276 | 975 |
| 67518 | 2400 |
| 9810 | 1725 |
| 6324 | 2300 |
| 12510 | 1700 |
| 15616 | 1915 |
| 15476 | 2278 |
| 13390 | 2497.5 |
| 1158 | 725 |
| 2000 | 870 |
| 2614 | 730 |
| 13433 | 2050 |
| 12500 | 3330 |
| 15750 | 1120 |
| 13996 | 4100 |
| 10450 | 1655 |
| 7500 | 1550 |
| 12125 | 2100 |
| 14500 | 2100 |
| 10000 | 1175 |
| 10019 | 2047.5 |
| 48787 | 3998 |
| 53579 | 2688 |
| 10788 | 2251 |
| 11865 | 1906 |

让我们将这些数据转换为一个名为`saratoga.c` `sv`的逗号分隔值（CSV）文件，并将其绘制为散点图：

![准备工作](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_06.jpg)

找到簇的数量是一项棘手的任务。在这里，我们有视觉检查的优势，而对于超平面上的数据（超过三个维度），这是不可用的。让我们粗略地将数据分成四个簇，如下所示：

![准备工作](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_07.jpg)

我们将运行 k-means 算法来做同样的事情，并看看我们的结果有多接近。

## 如何做…

1.  将`sarataga.csv`加载到 HDFS：

```scala
$ hdfs dfs -put saratoga.csv saratoga.csv

```

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  导入统计和相关类：

```scala
scala> import org.apache.spark.mllib.linalg.Vectors
scala> import org.apache.spark.mllib.clustering.KMeans

```

1.  将`saratoga.csv`作为 RDD 加载：

```scala
scala> val data = sc.textFile("saratoga.csv")

```

1.  将数据转换为密集向量的 RDD：

```scala
scala> val parsedData = data.map( line => Vectors.dense(line.split(',').map(_.toDouble)))

```

1.  为四个簇和五次迭代训练模型：

```scala
scala> val kmmodel= KMeans.train(parsedData,4,5)

```

1.  将`parsedData`收集为本地 scala 集合：

```scala
scala> val houses = parsedData.collect

```

1.  预测第 0 个元素的簇：

```scala
scala> val prediction = kmmodel.predict(houses(0))

```

1.  现在让我们比较 k-means 与我们单独完成的簇分配。k-means 算法从 0 开始给出簇 ID。一旦你检查数据，你会发现我们给出的 A 到 D 簇 ID 与 k-means 之间的以下映射：A=>3, B=>1, C=>0, D=>2。

1.  现在，让我们从图表的不同部分挑选一些数据，并预测它属于哪个簇。

1.  让我们看看房屋（18）的数据，占地面积为 876 平方英尺，售价为 665K 美元：

```scala
scala> val prediction = kmmodel.predict(houses(18))
resxx: Int = 3

```

1.  现在，看看占地面积为 15,750 平方英尺，价格为 1.12 百万美元的房屋（35）的数据：

```scala
scala> val prediction = kmmodel.predict(houses(35))
resxx: Int = 1

```

1.  现在看看房屋（6）的数据，占地面积为 38,768 平方英尺，售价为 2.725 百万美元：

```scala
scala> val prediction = kmmodel.predict(houses(6))
resxx: Int = 0

```

1.  现在看看房屋（15）的数据，占地面积为 69,696 平方英尺，售价为 275 万美元：

```scala
scala>  val prediction = kmmodel.predict(houses(15))
resxx: Int = 2

```

你可以用更多的数据测试预测能力。让我们进行一些邻域分析，看看这些簇承载着什么含义。簇 3 中的大多数房屋都靠近市中心。簇 2 中的房屋位于多山的地形上。

在这个例子中，我们处理了一组非常小的特征；常识和视觉检查也会导致相同的结论。k-means 算法的美妙之处在于它可以对具有无限数量特征的数据进行聚类。当你有原始数据并想了解数据中的模式时，它是一个很好的工具。

# 使用主成分分析进行降维

降维是减少维度或特征数量的过程。很多真实数据包含非常多的特征。拥有成千上万个特征并不罕见。现在，我们需要深入研究重要的特征。

降维有几个目的，比如：

+   数据压缩

+   可视化

当维度减少时，它会减少磁盘占用和内存占用。最后但同样重要的是；它可以帮助算法运行得更快。它还可以将高度相关的维度减少到一个维度。

人类只能可视化三个维度，但数据可以拥有更高的维度。可视化可以帮助发现数据中隐藏的模式。降维可以通过将多个特征压缩成一个特征来帮助可视化。

降维最流行的算法是主成分分析（PCA）。

让我们看看以下数据集：

![使用主成分分析进行降维](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_08.jpg)

假设目标是将这个二维数据分成一维。做法是找到一条我们可以将这些数据投影到的线。让我们找一条适合将这些数据投影的线：

![使用主成分分析进行降维](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_09.jpg)

这是与数据点具有最短投影距离的线。让我们通过从每个数据点到这条投影线的最短线来进一步解释：

![使用主成分分析进行降维](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_10.jpg)

另一种看待的方式是，我们必须找到一条线来投影数据，使得数据点到这条线的平方距离之和最小化。这些灰色线段也被称为**投影误差**。

## 准备好了

让我们来看看萨拉托加市的房屋数据的三个特征，即房屋大小、地块大小和价格。使用 PCA，我们将房屋大小和地块大小特征合并为一个特征—*z*。让我们称这个特征为**房屋密度**。

值得注意的是，并不总是可能赋予新特征以意义。在这种情况下，很容易，因为我们只有两个特征要合并，我们可以用常识来结合这两者的效果。在更实际的情况下，您可能有 1000 个特征要投影到 100 个特征。可能不可能给这 100 个特征中的每一个赋予现实生活中的意义。

在这个练习中，我们将使用 PCA 推导出房屋密度，然后我们将进行线性回归，看看这个密度如何影响房价。

在我们深入 PCA 之前有一个预处理阶段：**特征缩放**。当两个特征的范围相差很大时，特征缩放就会出现。在这里，房屋大小的范围在 800 平方英尺到 7000 平方英尺之间变化，而地块大小在 800 平方英尺到几英亩之间变化。

为什么我们之前不需要进行特征缩放？答案是我们真的不需要让特征处于一个公平的水平上。梯度下降是另一个特征缩放非常有用的领域。

有不同的特征缩放方法：

+   将特征值除以最大值，这将使每个特征处于![Getting ready](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_22.jpg)范围内

+   将特征值除以范围，即最大值减最小值

+   通过减去特征值的平均值，然后除以范围

+   通过减去特征值的平均值，然后除以标准差

我们将使用最佳的第四种选择来进行缩放。以下是我们将用于此示例的数据：

| 房屋大小 | 地块大小 | 缩放后的房屋大小 | 缩放后的地块大小 | 房屋价格（以 1000 美元计） |
| --- | --- | --- | --- | --- |
| 2524 | 12839 | -0.025 | -0.231 | 2405 |
| 2937 | 10000 | 0.323 | -0.4 | 2200 |
| 1778 | 8040 | -0.654 | -0.517 | 1400 |
| 1242 | 13104 | -1.105 | -0.215 | 1800 |
| 2900 | 10000 | 0.291 | -0.4 | 2351 |
| 1218 | 3049 | -1.126 | -0.814 | 795 |
| 2722 | 38768 | 0.142 | 1.312 | 2725 |
| 2553 | 16250 | -0.001 | -0.028 | 2150 |
| 3681 | 43026 | 0.949 | 1.566 | 2724 |
| 3032 | 44431 | 0.403 | 1.649 | 2675 |
| 3437 | 40000 | 0.744 | 1.385 | 2930 |
| 1680 | 1260 | -0.736 | -0.92 | 870 |
| 2260 | 15000 | -0.248 | -0.103 | 2210 |
| 1660 | 10032 | -0.753 | -0.398 | 1145 |
| 3251 | 12420 | 0.587 | -0.256 | 2419 |
| 3039 | 69696 | 0.409 | 3.153 | 2750 |
| 3401 | 12600 | 0.714 | -0.245 | 2035 |
| 1620 | 10240 | -0.787 | -0.386 | 1150 |
| 876 | 876 | -1.414 | -0.943 | 665 |
| 1889 | 8125 | -0.56 | -0.512 | 1430 |
| 4406 | 11792 | 1.56 | -0.294 | 1920 |
| 1885 | 1512 | -0.564 | -0.905 | 1230 |
| 1276 | 1276 | -1.077 | -0.92 | 975 |
| 3053 | 67518 | 0.42 | 3.023 | 2400 |
| 2323 | 9810 | -0.195 | -0.412 | 1725 |
| 3139 | 6324 | 0.493 | -0.619 | 2300 |
| 2293 | 12510 | -0.22 | -0.251 | 1700 |
| 2635 | 15616 | 0.068 | -0.066 | 1915 |
| 2298 | 15476 | -0.216 | -0.074 | 2278 |
| 2656 | 13390 | 0.086 | -0.198 | 2497.5 |
| 1158 | 1158 | -1.176 | -0.927 | 725 |
| 1511 | 2000 | -0.879 | -0.876 | 870 |
| 1252 | 2614 | -1.097 | -0.84 | 730 |
| 2141 | 13433 | -0.348 | -0.196 | 2050 |
| 3565 | 12500 | 0.852 | -0.251 | 3330 |
| 1368 | 15750 | -0.999 | -0.058 | 1120 |
| 5726 | 13996 | 2.672 | -0.162 | 4100 |
| 2563 | 10450 | 0.008 | -0.373 | 1655 |
| 1551 | 7500 | -0.845 | -0.549 | 1550 |
| 1993 | 12125 | -0.473 | -0.274 | 2100 |
| 2555 | 14500 | 0.001 | -0.132 | 2100 |
| 1572 | 10000 | -0.827 | -0.4 | 1175 |
| 2764 | 10019 | 0.177 | -0.399 | 2047.5 |
| 7168 | 48787 | 3.887 | 1.909 | 3998 |
| 4392 | 53579 | 1.548 | 2.194 | 2688 |
| 3096 | 10788 | 0.457 | -0.353 | 2251 |
| 2003 | 11865 | -0.464 | -0.289 | 1906 |

让我们将经过缩放的房屋大小和经过缩放的房价数据保存为`scaledhousedata.csv`。 

## 如何做到这一点…

1.  将`scaledhousedata.csv`加载到 HDFS：

```scala
$ hdfs dfs -put scaledhousedata.csv scaledhousedata.csv

```

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  导入统计和相关类：

```scala
scala> import org.apache.spark.mllib.linalg.Vectors
scala> import org.apache.spark.mllib.linalg.distributed.RowMatrix

```

1.  将`saratoga.csv`加载为一个 RDD：

```scala
scala> val data = sc.textFile("scaledhousedata.csv")

```

1.  将数据转换为密集向量的 RDD：

```scala
scala> val parsedData = data.map( line => Vectors.dense(line.split(',').map(_.toDouble)))

```

1.  从`parsedData`创建一个`RowMatrix`：

```scala
scala> val mat = new RowMatrix(parsedData)

```

1.  计算一个主成分：

```scala
scala> val pc= mat.computePrincipalComponents(1)

```

1.  将行投影到由主成分张成的线性空间：

```scala
scala> val projected = mat.multiply(pc)

```

1.  将投影的`RowMatrix`转换回 RDD：

```scala
scala> val projectedRDD = projected.rows

```

1.  将`projectedRDD`保存回 HDFS：

```scala
scala> projectedRDD.saveAsTextFile("phdata")

```

现在我们将使用这个投影特征，我们决定称之为住房密度，将其与房价绘制在一起，看看是否出现任何新的模式：

1.  将 HDFS 目录`phdata`下载到本地目录`phdata`：

```scala
scala> hdfs dfs -get phdata phdata

```

1.  修剪数据中的起始和结束括号，并将数据加载到 MS Excel 中，放在房价旁边。

以下是房价与住房密度的图表：

![如何做到这一点…](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_11.jpg)

让我们按照以下数据画一些模式：

![如何做到这一点…](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_12.jpg)

我们在这里看到了什么模式？从高密度到低密度住房的转移，人们愿意支付高昂的溢价。随着住房密度的降低，这种溢价趋于平稳。例如，人们愿意支付高额溢价，从公寓和联排别墅搬到独栋住宅，但是在一个可比的建成区域内，拥有 3 英亩地块大小的独栋住宅与拥有 2 英亩地块大小的独栋住宅的溢价并不会有太大的不同。

# 奇异值分解降维

通常，原始维度并不能最好地表示数据。正如我们在 PCA 中看到的，有时可以将数据投影到更少的维度，仍然保留大部分有用的信息。

有时，最好的方法是沿着展现大部分变化的特征对齐维度。这种方法有助于消除不代表数据的维度。

让我们再次看一下下图，它显示了两个维度上的最佳拟合线：

![奇异值分解降维](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_10.jpg)

投影线显示了对原始数据的最佳近似，使用了一个维度。如果我们取灰线与黑线相交的点，并隔离黑线，我们将得到原始数据的减少表示，尽可能保留了尽可能多的变化，如下图所示：

![奇异值分解降维](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_13.jpg)

让我们画一条垂直于第一投影线的线，如下图所示：

![奇异值分解降维](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_14.jpg)

这条线尽可能多地捕捉了原始数据集的第二维度上的变化。它在近似原始数据方面做得不好，因为这个维度本来就变化较少。可以使用这些投影线来生成一组不相关的数据点，这些数据点将显示原始数据中一开始看不到的子分组。

这就是 SVD 的基本思想。将高维度、高变异性的数据点集合减少到一个更低维度的空间，更清晰地展现原始数据的结构，并按照变化最大到最小的顺序排列。SVD 非常有用的地方，尤其是对于 NLP 应用，是可以简单地忽略某个阈值以下的变化，从而大幅减少原始数据，确保保留原始关系的兴趣。

现在让我们稍微深入理论。SVD 基于线性代数中的一个定理，即一个矩阵 A 可以分解为三个矩阵的乘积——一个正交矩阵 U，一个对角矩阵 S，和一个正交矩阵 V 的转置。我们可以如下展示：

![奇异值分解降维](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_15.jpg)

*U*和*V*是正交矩阵：

![奇异值分解降维](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_16.jpg)![奇异值分解降维](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_17.jpg)

*U*的列是![奇异值分解降维](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_18.jpg)的正交归一化特征向量，*V*的列是![奇异值分解降维](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_19.jpg)的正交归一化特征向量。*S*是一个对角矩阵，按降序包含来自*U*或*V*的特征值的平方根。

## 准备就绪

让我们看一个术语-文档矩阵的例子。我们将看两篇关于美国总统选举的新闻。以下是两篇文章的链接：

+   **Fox**: [`www.foxnews.com/politics/2015/03/08/top-2016-gop-presidential-hopefuls-return-to-iowa-to-hone-message-including/`](http://www.foxnews.com/politics/2015/03/08/top-2016-gop-presidential-hopefuls-return-to-iowa-to-hone-message-including/)

+   **Npr**: [`www.npr.org/blogs/itsallpolitics/2015/03/09/391704815/in-iowa-2016-has-begun-at-least-for-the-republican-party`](http://www.npr.org/blogs/itsallpolitics/2015/03/09/391704815/in-iowa-2016-has-begun-at-least-for-the-republican-party)

让我们用这两条新闻构建总统候选人矩阵：

![准备就绪](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_20.jpg)![准备就绪](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_09_21.jpg)

让我们把这个矩阵放在一个 CSV 文件中，然后把它放在 HDFS 中。我们将对这个矩阵应用 SVD 并分析结果。

## 如何做…

1.  将`scaledhousedata.csv`加载到 HDFS 中：

```scala
$ hdfs dfs -put pres.csv scaledhousedata.csv

```

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  导入统计和相关类：

```scala
scala> import org.apache.spark.mllib.linalg.Vectors
scala> import org.apache.spark.mllib.linalg.distributed.RowMatrix

```

1.  将`pres.csv`加载为 RDD：

```scala
scala> val data = sc.textFile("pres.csv")

```

1.  将数据转换为密集向量的 RDD：

```scala
scala> val parsedData = data.map( line => Vectors.dense(line.split(',').map(_.toDouble)))

```

1.  从`parsedData`创建`RowMatrix`：

```scala
scala> val mat = new RowMatrix(parsedData)

```

1.  计算`svd`：

```scala
scala> val svd = mat.computeSVD(2,true)

```

1.  计算`U`因子（特征向量）：

```scala
scala> val U = svd.U

```

1.  计算奇异值（特征值）矩阵：

```scala
scala> val s = svd.s

```

1.  计算`V`因子（特征向量）：

```scala
scala> val s = svd.s

```

如果你看`S`，你会意识到它给 Npr 文章的评分比 Fox 文章高得多。


# 第十章：推荐系统

在本章中，我们将介绍以下内容：

+   使用显式反馈的协同过滤

+   使用隐式反馈的协同过滤

# 介绍

以下是维基百科对推荐系统的定义：

> “推荐系统是信息过滤系统的一个子类，旨在预测用户对物品的‘评分’或‘偏好’。”

推荐系统近年来变得非常受欢迎。亚马逊用它们来推荐书籍，Netflix 用来推荐电影，Google 新闻用来推荐新闻故事。以下是一些推荐的影响的例子（来源：Celma，Lamere，2008）：

+   Netflix 上观看的电影有三分之二是推荐的

+   谷歌新闻点击量的 38%是推荐的

+   亚马逊销售额的 35%是推荐的结果

正如我们在前几章中看到的，特征和特征选择在机器学习算法的有效性中起着重要作用。推荐引擎算法会自动发现这些特征，称为**潜在特征**。简而言之，有一些潜在特征决定了用户喜欢一部电影而不喜欢另一部电影。如果另一个用户具有相应的潜在特征，那么这个人也很可能对电影有相似的口味。

为了更好地理解这一点，让我们看一些样本电影评分：

| 电影 | Rich | Bob | Peter | Chris |
| --- | --- | --- | --- | --- |
| *Titanic* | 5 | 3 | 5 | ? |
| *GoldenEye* | 3 | 2 | 1 | 5 |
| *Toy Story* | 1 | ? | 2 | 2 |
| *Disclosure* | 4 | 4 | ? | 4 |
| *Ace Ventura* | 4 | ? | 4 | ? |

我们的目标是预测用?符号表示的缺失条目。让我们看看是否能找到一些与电影相关的特征。首先，您将查看电影类型，如下所示：

| 电影 | 类型 |
| --- | --- |
| *Titanic* | 动作，爱情 |
| *GoldenEye* | 动作，冒险，惊悚 |
| *Toy Story* | 动画，儿童，喜剧 |
| *Disclosure* | 戏剧，惊悚 |
| *Ace Ventura* | 喜剧 |

现在每部电影可以根据每种类型进行评分，评分范围从 0 到 1。例如，*GoldenEye*不是一部主要的爱情片，所以它可能在爱情方面的评分为 0.1，但在动作方面的评分为 0.98。因此，每部电影可以被表示为一个特征向量。

### 注意

在本章中，我们将使用[grouplens.org/datasets/movielens/](http://grouplens.org/datasets/movielens/)的 MovieLens 数据集。

InfoObjects 大数据沙箱中加载了 100k 部电影评分。您还可以从 GroupLens 下载 100 万甚至高达 1000 万的评分，以便分析更大的数据集以获得更好的预测。

我们将使用这个数据集中的两个文件：

+   `u.data`：这是一个以制表符分隔的电影评分列表，格式如下：

```scala
user id | item id | rating | epoch time
```

由于我们不需要时间戳，我们将从我们的配方数据中将其过滤掉

+   `u.item`：这是一个以制表符分隔的电影列表，格式如下：

```scala
movie id | movie title | release date | video release date |               IMDb URL | unknown | Action | Adventure | Animation |               Children's | Comedy | Crime | Documentary | Drama | Fantasy |               Film-Noir | Horror | Musical | Mystery | Romance | Sci-Fi |               Thriller | War | Western |
```

本章将介绍如何使用 MLlib 进行推荐，MLlib 是 Spark 的机器学习库。

# 使用显式反馈的协同过滤

协同过滤是推荐系统中最常用的技术。它有一个有趣的特性——它自己学习特征。因此，在电影评分的情况下，我们不需要提供有关电影是浪漫还是动作的实际人类反馈。

正如我们在*介绍*部分看到的，电影有一些潜在特征，比如类型，同样用户也有一些潜在特征，比如年龄，性别等。协同过滤不需要它们，并且自己找出潜在特征。

在这个例子中，我们将使用一种名为**交替最小二乘法**（**ALS**）的算法。该算法基于少量潜在特征解释电影和用户之间的关联。它使用三个训练参数：秩、迭代次数和 lambda（在本章后面解释）。找出这三个参数的最佳值的最佳方法是尝试不同的值，看哪个值的**均方根误差**（**RMSE**）最小。这个误差类似于标准差，但是它是基于模型结果而不是实际数据的。

## 准备工作

将从 GroupLens 下载的`moviedata`上传到`hdfs`中的`moviedata`文件夹：

```scala
$ hdfs dfs -put moviedata moviedata

```

我们将向这个数据库添加一些个性化评分，以便测试推荐的准确性。

你可以查看`u.item`来挑选一些电影并对其进行评分。以下是我选择的一些电影，以及我的评分。随意选择你想评分的电影并提供你自己的评分。

| 电影 ID | 电影名称 | 评分（1-5） |
| --- | --- | --- |
| 313 | *泰坦尼克号* | 5 |
| 2 | *黄金眼* | 3 |
| 1 | *玩具总动员* | 1 |
| 43 | *揭秘* | 4 |
| 67 | *玩具总动员* | 4 |
| 82 | *侏罗纪公园* | 5 |
| 96 | *终结者 2* | 5 |
| 121 | *独立日* | 4 |
| 148 | *鬼与黑暗* | 4 |

最高的用户 ID 是 943，所以我们将把新用户添加为 944。让我们创建一个新的逗号分隔的文件`p.data`，其中包含以下数据：

```scala
944,313,5
944,2,3
944,1,1
944,43,4
944,67,4
944,82,5
944,96,5
944,121,4
944,148,4
```

## 如何做…

1.  将个性化电影数据上传到`hdfs`：

```scala
$ hdfs dfs -put p.data p.data

```

1.  导入 ALS 和评分类：

```scala
scala> import org.apache.spark.mllib.recommendation.ALS
scala> import org.apache.spark.mllib.recommendation.Rating

```

1.  将评分数据加载到 RDD 中：

```scala
scala> val data = sc.textFile("moviedata/u.data")

```

1.  将`val data`转换为评分的 RDD：

```scala
scala> val ratings = data.map { line => 
 val Array(userId, itemId, rating, _) = line.split("\t") 
 Rating(userId.toInt, itemId.toInt, rating.toDouble) 
}

```

1.  将个性化评分数据加载到 RDD 中：

```scala
scala> val pdata = sc.textFile("p.data")

```

1.  将数据转换为个性化评分的 RDD：

```scala
scala> val pratings = pdata.map { line => 
 val Array(userId, itemId, rating) = line.split(",")
 Rating(userId.toInt, itemId.toInt, rating.toDouble) 
}

```

1.  将评分与个性化评分结合：

```scala
scala> val movieratings = ratings.union(pratings)

```

1.  使用秩为 5 和 10 次迭代以及 0.01 作为 lambda 构建 ALS 模型：

```scala
scala> val model = ALS.train(movieratings, 10, 10, 0.01)

```

1.  让我们根据这个模型预测我对给定电影的评分会是多少。

1.  让我们从原始的*终结者*开始，电影 ID 为 195：

```scala
scala> model.predict(sc.parallelize(Array((944,195)))).collect.foreach(println)
Rating(944,195,4.198642954004738)

```

由于我给*终结者 2*评了 5 分，这是一个合理的预测。

1.  让我们尝试一下*鬼*，电影 ID 为 402：

```scala
scala> model.predict(sc.parallelize(Array((944,402)))).collect.foreach(println)
Rating(944,402,2.982213836456829)

```

这是一个合理的猜测。

1.  让我们尝试一下*鬼与黑暗*，这是我已经评分的电影，ID 为 148：

```scala
scala> model.predict(sc.parallelize(Array((944,402)))).collect.foreach(println)
Rating(944,148,3.8629938805450035)

```

非常接近的预测，知道我给这部电影评了 4 分。

你可以将更多电影添加到`train`数据集中。还有 100 万和 1000 万的评分数据集可用，这将进一步完善算法。

# 使用隐式反馈的协同过滤

有时，可用的反馈不是评分的形式，而是音轨播放、观看的电影等形式。这些数据乍一看可能不如用户的明确评分好，但这更加详尽。

## 准备工作

我们将使用来自[`www.kaggle.com/c/msdchallenge/data`](http://www.kaggle.com/c/msdchallenge/data)的百万首歌数据。你需要下载三个文件：

+   `kaggle_visible_evaluation_triplets`

+   `kaggle_users.txt`

+   `kaggle_songs.txt`

现在执行以下步骤：

1.  在`hdfs`中创建一个`songdata`文件夹，并将所有三个文件放在这里：

```scala
$ hdfs dfs -mkdir songdata

```

1.  将歌曲数据上传到`hdfs`：

```scala
$ hdfs dfs -put kaggle_visible_evaluation_triplets.txt songdata/
$ hdfs dfs -put kaggle_users.txt songdata/
$ hdfs dfs -put kaggle_songs.txt songdata/

```

我们仍然需要做一些预处理。MLlib 中的 ALS 需要用户和产品 ID 都是整数。`Kaggle_songs.txt`文件有歌曲 ID 和其后的序列号，而`Kaggle_users.txt`文件没有。我们的目标是用相应的整数序列号替换`triplets`数据中的`userid`和`songid`。为此，请按照以下步骤操作：

1.  将`kaggle_songs`数据加载为 RDD：

```scala
scala> val songs = sc.textFile("songdata/kaggle_songs.txt")

```

1.  将用户数据加载为 RDD：

```scala
scala> val users = sc.textFile("songdata/kaggle_users.txt")

```

1.  将三元组（用户、歌曲、播放次数）数据加载为 RDD：

```scala
scala> val triplets = sc.textFile("songdata/kaggle_visible_evaluation_triplets.txt")

```

1.  将歌曲数据转换为`PairRDD`：

```scala
scala> val songIndex = songs.map(_.split("\\W+")).map(v => (v(0),v(1).toInt))

```

1.  收集`songIndex`作为 Map：

```scala
scala> val songMap = songIndex.collectAsMap

```

1.  将用户数据转换为`PairRDD`：

```scala
scala> val userIndex = users.zipWithIndex.map( t => (t._1,t._2.toInt))

```

1.  收集`userIndex`作为 Map：

```scala
scala> val userMap = userIndex.collectAsMap

```

我们需要`songMap`和`userMap`来替换三元组中的`userId`和`songId`。Spark 会根据需要自动在集群上提供这两个映射。这样做效果很好，但每次需要发送到集群时都很昂贵。

更好的方法是使用 Spark 的一个特性叫做`broadcast`变量。`broadcast`变量允许 Spark 作业在每台机器上保留一个只读副本的变量缓存，而不是在每个任务中传输一个副本。Spark 使用高效的广播算法来分发广播变量，因此网络上的通信成本可以忽略不计。

正如你可以猜到的，`songMap`和`userMap`都是很好的候选对象，可以包装在`broadcast`变量周围。执行以下步骤：

1.  广播`userMap`：

```scala
scala> val broadcastUserMap = sc.broadcast(userMap)

```

1.  广播`songMap`：

```scala
scala> val broadcastSongMap = sc.broadcast(songMap)

```

1.  将`triplet`转换为数组：

```scala
scala> val tripArray = triplets.map(_.split("\\W+"))

```

1.  导入评分：

```scala
scala> import org.apache.spark.mllib.recommendation.Rating

```

1.  将`triplet`数组转换为评分对象的 RDD：

```scala
scala> val ratings = tripArray.map { case Array(user, song, plays) =>
 val userId = broadcastUserMap.value.getOrElse(user, 0)
 val songId = broadcastUserMap.value.getOrElse(song, 0)
 Rating(userId, songId, plays.toDouble)
}

```

现在，我们的数据已经准备好进行建模和预测。

## 如何做…

1.  导入 ALS：

```scala
scala> import org.apache.spark.mllib.recommendation.ALS

```

1.  使用 ALS 构建一个具有 rank 10 和 10 次迭代的模型：

```scala
scala> val model = ALS.trainImplicit(ratings, 10, 10)

```

1.  从三元组中提取用户和歌曲元组：

```scala
scala> val usersSongs = ratings.map( r => (r.user, r.product) )

```

1.  为用户和歌曲元组做出预测：

```scala
scala> val predictions = model.predict(usersSongs)

```

## 它是如何工作的…

我们的模型需要四个参数才能工作，如下所示：

| 参数名称 | 描述 |
| --- | --- |
| Rank | 模型中的潜在特征数 |
| Iterations | 用于运行此因子分解的迭代次数 |
| Lambda | 过拟合参数 |
| Alpha | 观察交互的相对权重 |

正如你在梯度下降的情况下看到的，这些参数需要手动设置。我们可以尝试不同的值，但最好的值是 rank=50，iterations=30，lambda=0.00001，alpha=40。

## 还有更多…

快速测试不同参数的一种方法是在 Amazon EC2 上生成一个 Spark 集群。这样可以灵活地选择一个强大的实例来快速测试这些参数。我已经创建了一个名为`com.infoobjects.songdata`的公共 s3 存储桶，以便将数据传输到 Spark。

以下是您需要遵循的步骤，从 S3 加载数据并运行 ALS：

```scala
sc.hadoopConfiguration.set("fs.s3n.awsAccessKeyId", "<your access key>")
sc.hadoopConfiguration.set("fs.s3n.awsSecretAccessKey","<your secret key>")
val songs = sc.textFile("s3n://com.infoobjects.songdata/kaggle_songs.txt")
val users = sc.textFile("s3n://com.infoobjects.songdata/kaggle_users.txt")
val triplets = sc.textFile("s3n://com.infoobjects.songdata/kaggle_visible_evaluation_triplets.txt")
val songIndex = songs.map(_.split("\\W+")).map(v => (v(0),v(1).toInt))
val songMap = songIndex.collectAsMap
val userIndex = users.zipWithIndex.map( t => (t._1,t._2.toInt))
val userMap = userIndex.collectAsMap
val broadcastUserMap = sc.broadcast(userMap)
val broadcastSongMap = sc.broadcast(songMap)
val tripArray = triplets.map(_.split("\\W+"))
import org.apache.spark.mllib.recommendation.Rating
val ratings = tripArray.map{ v =>
 val userId: Int = broadcastUserMap.value.get(v(0)).fold(0)(num => num)
 val songId: Int = broadcastSongMap.value.get(v(1)).fold(0)(num => num)
 Rating(userId,songId,v(2).toDouble)
 }
import org.apache.spark.mllib.recommendation.ALS
val model = ALS.trainImplicit(ratings, 50, 30, 0.000001, 40)
val usersSongs = ratings.map( r => (r.user, r.product) )
val predictions =model.predict(usersSongs)

```

这些是在`usersSongs`矩阵上做出的预测。
