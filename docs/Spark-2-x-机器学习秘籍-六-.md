# Spark 2.x 机器学习秘籍（六）

> 原文：[`zh.annas-archive.org/md5/3C1ECF91245FC64E4B95E8DC509841AB`](https://zh.annas-archive.org/md5/3C1ECF91245FC64E4B95E8DC509841AB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：优化-使用梯度下降下山

在本章中，我们将涵盖：

+   通过数学优化二次成本函数并找到最小值来获得洞察

+   从头开始编码二次成本函数优化，使用梯度下降（GD）

+   编码梯度下降优化以从头解决线性回归

+   在 Spark 2.0 中，正规方程作为解决线性回归的替代方法

# 介绍

了解优化的工作原理对于成功的机器学习职业至关重要。我们选择了**梯度下降**（**GD**）方法进行端到端的深入挖掘，以演示优化技术的内部工作原理。我们将使用三个配方来开发这个概念，从头开始到完全开发的代码，以解决实际问题和真实世界数据。第四个配方探讨了使用 Spark 和正规方程（大数据问题的有限扩展）来解决回归问题的 GD 的替代方法。

让我们开始吧。机器到底是如何学习的？它真的能从错误中学习吗？当机器使用优化找到解决方案时，这意味着什么？

在高层次上，机器学习基于以下五种技术之一：

+   **基于错误的学习**：在这种技术中，我们搜索领域空间，寻找最小化训练数据上总误差（预测与实际）的参数值组合（权重）。

+   **信息论学习**：这种方法使用经典香农信息论中的熵和信息增益等概念。基于树的 ML 系统，在 ID3 算法中经典地根植于这一类别。集成树模型将是这一类别的巅峰成就。我们将在第十章中讨论树模型，*使用决策树和集成模型构建机器学习系统*。

+   **概率空间学习**：这个机器学习分支基于贝叶斯定理（[`en.wikipedia.org/wiki/Bayes'_theorem)`](https://en.wikipedia.org/wiki/Bayes'_theorem)）。机器学习中最著名的方法是朴素贝叶斯（多种变体）。朴素贝叶斯以引入贝叶斯网络而告终，这允许对模型进行更多控制。

+   **相似度测量学习**：这种方法通过尝试定义相似度度量，然后根据该度量来拟合观察的分组。最著名的方法是 KNN（最近邻），这是任何 ML 工具包中的标准。 Spark ML 实现了带有并行性的 K-means++，称为 K-Means||（K 均值并行）。

+   **遗传算法（GA）和进化学习**：这可以被视为达尔文的理论（物种的起源）应用于优化和机器学习。 GA 背后的想法是使用递归生成算法创建一组初始候选者，然后使用反馈（适应性景观）来消除远距离的候选者，折叠相似的候选者，同时随机引入突变（数值或符号抖动）到不太可能的候选者，然后重复直到找到解决方案。

一些数据科学家和 ML 工程师更喜欢将优化视为最大化对数似然，而不是最小化成本函数-它们实际上是同一枚硬币的两面！在本章中，我们将专注于基于错误的学习，特别是**梯度下降**。

为了提供扎实的理解，我们将深入研究梯度下降（GD），通过三个 GD 配方来了解它们如何应用于优化。然后，我们将提供 Spark 的正规方程配方作为数值优化方法的替代方法，例如梯度下降（GD）或**有限内存的 Broyden-Fletcher-Goldfarb-Shanno**（**LBFGS**）算法。

Apache Spark 为所有类别提供了出色的覆盖范围。以下图表描述了一个分类法，将指导您在数值优化领域的旅程，这对于在机器学习中取得卓越成就至关重要。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00188.gif)

# 机器如何使用基于错误的系统学习？

机器学习的学习方式与我们大致相同-它们从错误中学习。首先，它们首先进行初始猜测（参数的随机权重）。其次，它们使用自己的模型（例如 GLM、RRN、等温回归）进行预测（例如一个数字）。第三，它们查看答案应该是什么（训练集）。第四，它们使用各种技术（如最小二乘法、相似性等）来衡量实际与预测答案之间的差异。

一旦所有这些机制都就位，它们将在整个训练数据集上重复这个过程，同时试图提出一种参数组合，当考虑整个训练数据集时具有最小误差。有趣的是，机器学习的每个分支都使用数学或领域已知事实，以避免蛮力组合方法，这种方法在现实世界的环境中不会终止。

基于错误的机器学习优化是数学规划（MP）的一个分支，它是通过算法实现的，但精度有限（精度变化为 10^(-2)到 10^(-6)）。这一类别中的大多数方法，如果不是全部，都利用简单的微积分事实，如一阶导数（斜率）（例如 GD 技术）和二阶导数（曲率）（例如 BFGS 技术），以最小化成本函数。在 BFGS 的情况下，隐形的手是更新器函数（L1 更新器）、秩（二阶秩更新器），使用无 Hessian 矩阵的 Hessian 自由技术来近似最终答案/解决方案([`en.wikipedia.org/wiki/Hessian_matrix`](https://en.wikipedia.org/wiki/Hessian_matrix))。

以下图表描述了 Spark 中涉及优化的一些设施：

**![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00189.gif)**

Spark 中有用于执行 SGD 和 LBFGS 优化的函数。要使用它们，您应该能够编写并提供自己的成本函数。这些函数，如`runMiniBatchSGD()`，不仅标记为私有，而且需要对两种算法的实现有很好的理解。

由于这是一本食谱，我们无法深入研究优化理论，因此我们建议从我们的图书馆中参考以下书籍：

+   **优化（2013）**：[`www.amazon.com/Optimization-Springer-Texts-Statistics-Kenneth/dp/1461458374/ref=sr_1_8?ie=UTF8&qid=1485744639&sr=8-8&keywords=optimization`](https://www.amazon.com/Optimization-Springer-Texts-Statistics-Kenneth/dp/1461458374/ref=sr_1_8?ie=UTF8&qid=1485744639&sr=8-8&keywords=optimization)

+   **机器学习优化（2011）**：[`www.amazon.com/Optimization-Machine-Learning-Information-Processing/dp/026201646X/ref=sr_1_1?ie=UTF8&qid=1485744817&sr=8-1&keywords=optimization+for+machine+learning`](https://www.amazon.com/Optimization-Machine-Learning-Information-Processing/dp/026201646X/ref=sr_1_1?ie=UTF8&qid=1485744817&sr=8-1&keywords=optimization+for+machine+learning)

+   **凸优化（2004）**：[`www.amazon.com/Convex-Optimization-Stephen-Boyd/dp/0521833787/ref=pd_sim_14_2?_encoding=UTF8&psc=1&refRID=7T88DJY5ZWBEREGJ4WT4`](https://www.amazon.com/Convex-Optimization-Stephen-Boyd/dp/0521833787/ref=pd_sim_14_2?_encoding=UTF8&psc=1&refRID=7T88DJY5ZWBEREGJ4WT4)

+   **遗传算法在搜索、优化和机器学习中（1989）-经典！**：[`www.amazon.com/Genetic-Algorithms-Optimization-Machine-Learning/dp/0201157675/ref=sr_1_5?s=books&ie=UTF8&qid=1485745151&sr=1-5&keywords=genetic+programming`](https://www.amazon.com/Genetic-Algorithms-Optimization-Machine-Learning/dp/0201157675/ref=sr_1_5?s=books&ie=UTF8&qid=1485745151&sr=1-5&keywords=genetic+programming)

+   **《从自然到人工系统的群体智能》（1999）**：[`www.amazon.com/Swarm-Intelligence-Artificial-Institute-Complexity/dp/0195131592/ref=sr_1_3?s=books&ie=UTF8&qid=1485745559&sr=1-3&keywords=swarm+intelligence`](https://www.amazon.com/Swarm-Intelligence-Artificial-Institute-Complexity/dp/0195131592/ref=sr_1_3?s=books&ie=UTF8&qid=1485745559&sr=1-3&keywords=swarm+intelligence)

# 通过数学来优化二次成本函数并找到最小值

在本教程中，我们将在介绍梯度下降（一阶导数）和 L-BFGS（一种无 Hessian 的拟牛顿方法）之前，探索数学优化背后的基本概念。

我们将研究一个样本二次成本/误差函数，并展示如何仅通过数学找到最小值或最大值。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00190.jpeg)

我们将使用顶点公式和导数方法来找到最小值，但我们将在本章的后续教程中介绍数值优化技术，如梯度下降及其在回归中的应用。

# 如何操作...

1.  假设我们有一个二次成本函数，我们找到它的最小值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00191.gif)

1.  在统计机器学习算法中，成本函数充当我们在搜索空间中移动时的难度级别、能量消耗或总误差的代理。

1.  我们要做的第一件事是绘制函数并进行直观检查。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00192.jpeg)

1.  通过直观检查，我们看到 ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00193.gif) 是一个凹函数，其最小值在 (2,1) 处。

1.  我们的下一步将是通过优化函数来找到最小值。在机器学习中，呈现成本或误差函数的一些示例可能是平方误差、欧几里得距离、MSSE，或者任何其他能够捕捉我们离最佳数值答案有多远的相似度度量。

1.  下一步是寻找最小化误差（例如成本）的最佳参数值。例如，通过优化线性回归成本函数（平方误差的总和），我们得到其参数的最佳值。

+   导数方法：将一阶导数设为 0 并解出

+   顶点方法：使用封闭代数形式

1.  首先，我们通过计算一阶导数，将其设为 0，并解出 *x* 和 *y* 来使用导数方法求解最小值。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00194.jpeg)

给定 f(x) = 2x² - 8x +9 作为我们的成本/误差函数，导数可以计算如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00195.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00196.gif)

幂规则：![]

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00198.gif) 我们将导数设为 0 并解出![]

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00200.jpeg)

我们现在使用顶点公式方法验证最小值。要使用代数方法计算最小值，请参见以下步骤。

1.  给定函数 ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00201.gif)，顶点可以在以下位置找到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00202.jpeg)

1.  让我们使用顶点代数公式来计算最小值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00203.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00204.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00205.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00206.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00207.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00208.gif)2(2)2 + (-8) (2) +9![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00209.gif)

1.  作为最后一步，我们检查步骤 4 和 5 的结果，以确保我们使用封闭代数形式得出的最小值 (2, 1) 与导数方法得出的 (2, 1) 一致。

1.  在最后一步，我们在左侧面板中展示 *f(x)* 的图形，右侧面板中展示其导数，这样您可以直观地检查答案。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00210.jpeg)

1.  正如您所看到的，随意检查显示最小值顶点在左侧为 (2,1) *{ x=2, f(x)=1 }*，而右侧图表显示函数关于 *X*（仅参数）的导数在 *X=2* 处取得最小值。如前面的步骤所示，我们将函数的导数设为零并解出 *X*，结果为数字 2。您还可以直观地检查两个面板和方程，以确保 *X=2* 在两种情况下都是正确的并且有意义。

# 工作原理...

我们有两种技术可以用来找到二次函数的最小值，而不使用数值方法。在现实生活中的统计机器学习优化中，我们使用导数来找到凸函数的最小值。如果函数是凸的（或者优化是有界的），那么只有一个局部最小值，所以工作比在深度学习中出现的非线性/非凸问题要简单得多。

在前面的配方中使用导数方法：

+   首先，我们通过应用导数规则（例如指数）找到了导数。

+   其次，我们利用了这样一个事实，对于给定的简单二次函数（凸优化），当第一导数的斜率为零时，最小值出现。

+   第三，我们简单地通过遵循和应用机械微积分规则找到了导数。

+   第四，我们将函数的导数设置为零！[](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00211.gif)并解出 x

+   第五，我们使用 x 值并将其代入原方程以找到 y。通过步骤 1 到 5，我们最终得到了点（2，1）处的最小值。

# 还有更多...

大多数统计机器学习算法在定义和搜索域空间时使用成本或误差函数来得到最佳的数值近似解（例如，回归的参数）。函数达到最小值（最小化成本/误差）或最大值（最大化对数似然）的点是最佳解（最佳近似）存在的地方，误差最小。

可以在以下网址找到微分规则的快速复习：[`en.wikipedia.org/wiki/Differentiation_rules`](https://en.wikipedia.org/wiki/Differentiation_rules) [和](https://en.wikipedia.org/wiki/Differentiation_rules)[`www.math.ucdavis.edu/~kouba/Math17BHWDIRECTORY/Derivatives.pdf`](https://www.math.ucdavis.edu/~kouba/Math17BHWDIRECTORY/Derivatives.pdf)

可以在以下网址找到有关最小化二次函数的更多数学写作：[`www.cis.upenn.edu/~cis515/cis515-11-sl12.pdf`](http://www.cis.upenn.edu/~cis515/cis515-11-sl12.pdf)

可以在 MIT 找到有关二次函数优化和形式的科学写作：[`ocw.mit.edu/courses/sloan-school-of-management/15-084j-nonlinear-programming-spring-2004/lecture-notes/lec4_quad_form.pdf`](https://ocw.mit.edu/courses/sloan-school-of-management/15-084j-nonlinear-programming-spring-2004/lecture-notes/lec4_quad_form.pdf)

# 另见

+   可以在 UCSC 找到有关二次方程的详细写作：[`people.ucsc.edu/~miglior/chapter%20pdf/Ch08_SE.pdf`](https://people.ucsc.edu/~miglior/chapter%20pdf/Ch08_SE.pdf)

+   二次函数可以表示为以下形式之一：

| **二次函数 ax² + bx + c 形式** | **二次函数的标准形式** |
| --- | --- |
| ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00212.gif) | ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00213.gif) |

其中*a，b*和*c*是实数。

下图提供了最小值/最大值和参数的快速参考，这些参数调节了函数的凸/凹外观和感觉：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00214.jpeg)

# 从头开始编写使用梯度下降（GD）的二次成本函数优化

在这个配方中，我们将编写一个名为梯度下降（GD）的迭代数值优化技术，以找到二次函数*f(x) = 2x² - 8x +9*的最小值。

这里的重点从使用数学来解决最小值（将第一导数设置为零）转移到了一种名为梯度下降（GD）的迭代数值方法，该方法从一个猜测开始，然后在每次迭代中使用成本/误差函数作为指导方针逐渐接近解决方案。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  使用包指令设置路径：`package spark.ml.cookbook.chapter9`。

1.  导入必要的包。

`scala.util.control.Breaks`将允许我们跳出程序。我们仅在调试阶段使用它，当程序无法收敛或陷入永无止境的过程中（例如，当步长过大时）。

```scala
import scala.collection.mutable.ArrayBuffer
import scala.util.control.Breaks._
```

1.  这一步定义了我们试图最小化的实际二次函数：

```scala
def quadratic_function_itself(x:Double):Double = {
// the function being differentiated
// f(x) = 2x² - 8x + 9
return 2 * math.pow(x,2) - (8*x) + 9
}
```

1.  这一步定义了函数的导数。这被称为点 x 处的梯度。这是函数*f(x) = 2x² - 8x + 9*的一阶导数。

```scala
def derivative_of_function(x:Double):Double = {
// The derivative of f(x)
return 4 * x - 8
}
```

1.  在这一步中，我们设置一个随机起始点（这里设置为 13）。这将成为我们在*x*轴上的初始起始点。

```scala
var currentMinimumValue = 13.0 // just pick up a random value
```

1.  我们继续设置从上一个配方*优化二次成本函数并仅使用数学来获得洞察力找到最小值*计算出的实际最小值，以便我们可以计算我们的估计与实际的每次迭代。

```scala
val actualMinima = 2.0 // proxy for a label in training phase
```

这一点试图充当您在 ML 算法的训练阶段提供的标签。在现实生活中，我们会有一个带有标签的训练数据集，并让算法进行训练并相应地调整其参数。

1.  设置记录变量并声明`ArrayBuffer`数据结构以存储成本（错误）加上估计的最小值，以便进行检查和绘图：

```scala
var oldMinimumValue = 0.0
var iteration = 0;
var minimumVector = ArrayBuffer[Double]()
var costVector = ArrayBuffer[Double]()
```

1.  梯度下降算法的内部控制变量在这一步中设置：

```scala
val stepSize = .01
val tolerance = 0.0001
```

`stepSize`，也被称为学习率，指导程序每次移动多少，而容差帮助算法在接近最小值时停止。

1.  我们首先设置一个循环来迭代，并在接近最小值时停止，基于期望的容差：

```scala
while (math.abs(currentMinimumValue - oldMinimumValue) > tolerance) {
iteration +=1 //= iteration + 1 for debugging when non-convergence
```

1.  我们每次更新最小值并调用函数计算并返回当前更新点的导数值：

```scala
oldMinimumValue = currentMinimumValue
val gradient_value_at_point = derivative_of_function(oldMinimumValue)
```

1.  我们决定移动多少，首先通过取上一步返回的导数值，然后将其乘以步长（即，我们对其进行缩放）。然后我们继续更新当前最小值并减少它的移动（导数值 x 步长）：

```scala
val move_by_amount = gradient_value_at_point * stepSize
currentMinimumValue = oldMinimumValue - move_by_amount
```

1.  我们通过使用一个非常简单的平方距离公式来计算我们的成本函数值（错误）。在现实生活中，实际的最小值将从训练中得出，但在这里我们使用上一个配方*优化二次成本函数并仅使用数学来获得洞察力找到最小值*中的值。

```scala
costVector += math.pow(actualMinima - currentMinimumValue, 2)
minimumVector += currentMinimumValue
```

1.  我们生成一些中间输出结果，以便您观察每次迭代时 currentMinimum 的行为：

```scala
print("Iteration= ",iteration," currentMinimumValue= ", currentMinimumValue)
print("\n")
```

输出将如下所示：

```scala
(Iteration= ,1, currentMinimumValue= ,12.56)
(Iteration= ,2, currentMinimumValue= ,12.1376)
(Iteration= ,3, currentMinimumValue= ,11.732096)
(Iteration= ,4, currentMinimumValue= ,11.342812160000001)
(Iteration= ,5, currentMinimumValue= ,10.9690996736)
(Iteration= ,6, currentMinimumValue= ,10.610335686656)
(Iteration= ,7, currentMinimumValue= ,10.265922259189761)
(Iteration= ,8, currentMinimumValue= ,9.935285368822171)
..........
..........
..........
(Iteration= ,203, currentMinimumValue= ,2.0027698292180602)
(Iteration= ,204, currentMinimumValue= ,2.0026590360493377)
(Iteration= ,205, currentMinimumValue= ,2.0025526746073643)
(Iteration= ,206, currentMinimumValue= ,2.00245056762307)
(Iteration= ,207, currentMinimumValue= ,2.002352544918147)
```

1.  以下声明包括一个提醒，即使优化算法如何实现，它也应始终提供退出非收敛算法的手段（即，它应防范用户输入和边缘情况）：

```scala
if (iteration == 1000000) break //break if non-convergence - debugging
}
```

1.  我们在每次迭代中收集的成本和最小值向量的输出，以供以后分析和绘图：

```scala
print("\n Cost Vector: "+ costVector)
print("\n Minimum Vactor" + minimumVector)
```

输出是：

```scala
Cost vector: ArrayBuffer(111.51360000000001, 102.77093376000002, 94.713692553216, 87.28813905704389, ........7.0704727116774655E-6, 6.516147651082496E-6, 6.005281675238673E-6, 5.534467591900128E-6)

Minimum VactorArrayBuffer(12.56, 12.1376, 11.732096, 11.342812160000001, 10.9690996736, 10.610335686656, 10.265922259189761, 9.935285368822171, ........2.0026590360493377, 2.0025526746073643, 2.00245056762307, 2.002352544918147)

```

1.  我们定义并设置最终最小值和实际函数值*f(minima)*的变量。它们充当最小值的(X,Y)位置：

```scala
var minimaXvalue= currentMinimumValue
var minimaYvalue= quadratic_function_itself(currentMinimumValue)
```

1.  我们打印出最终结果，与我们在配方中的计算匹配，*优化二次成本函数并仅使用数学来获得洞察力找到最小值*，使用迭代方法。最终输出应该是我们的最小值位于(2,1)，可以通过视觉或计算通过配方*优化二次成本函数并仅使用数学来获得洞察力找到最小值*进行检查。

```scala
print("\n\nGD Algo: Local minimum found at X="+f"$minimaXvalue%1.2f")
print("\nGD Algo: Y=f(x)= : "+f"$minimaYvalue%1.2f")
}
```

输出是：

```scala
GD Algo: Local minimum found at X = : 2.00 GD Algo: Y=f(x)= : 1.00
```

该过程以退出码 0 完成

# 工作原理...

梯度下降技术利用了函数的梯度（在这种情况下是一阶导数）指向下降方向的事实。概念上，梯度下降（GD）优化成本或错误函数以搜索模型的最佳参数。下图展示了梯度下降的迭代性质：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00215.jpeg)

我们通过定义步长（学习率）、容差、要进行微分的函数以及函数的一阶导数来开始配方，然后继续迭代并从初始猜测（在这种情况下为 13）接近目标最小值 0。

在每次迭代中，我们计算了点的梯度（该点的一阶导数），然后使用步长对其进行缩放，以调节每次移动的量。由于我们在下降，我们从旧点中减去了缩放的梯度，以找到下一个更接近解决方案的点（以最小化误差）。

关于梯度值是应该加还是减以到达新点存在一些混淆，我们将在下面尝试澄清。指导原则应该是斜率是负还是正。为了朝着正确的方向移动，您必须朝着第一导数（梯度）的方向移动。

以下表格和图表提供了 GD 更新步骤的指南：

| ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00216.gif) ***< 0****负梯度* | ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00217.gif) ***> 0****正梯度* |
| --- | --- |
| ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00218.gif) | ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00219.gif) |

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00220.jpeg)

以下图表描述了单个步骤（负斜率）的内部工作，我们要么从起始点减去梯度，要么加上梯度，以到达下一个点，使我们离二次函数的最小值更近一步。例如，在这个配方中，我们从 13 开始，经过 200 多次迭代（取决于学习率），最终到达（2,1）的最小值，这与本章中的配方*优化二次成本函数并仅使用数学来获得洞察*中找到的解决方案相匹配。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00221.jpeg)

为了更好地理解这些步骤，让我们尝试从前图的左侧跟随一个步骤，对于一个简单的![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00222.gif)函数。在这种情况下，我们位于曲线的左侧（原始猜测是负数），并且我们试图在每次迭代中向下爬升并增加 X，朝着梯度（一阶导数）的方向。

以下步骤将引导您浏览下一个图表，以演示核心概念和配方中的步骤：

1.  在给定点计算导数--梯度。

1.  使用步骤 1 中的梯度，并按步长进行缩放--移动的量。

1.  通过减去移动量找到新位置：

+   **负梯度情况**：在下图中，我们减去负梯度（有效地加上梯度）到原始点，以便向下爬升到![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00223.gif)的最小值 0。图中所示的曲线符合这种情况。

+   **正梯度情况**：如果我们在曲线的另一侧，梯度为正，那么我们从先前位置减去正梯度数（有效减小梯度）以向下爬向最小值。本配方中的代码符合这种情况，我们试图从正数 13（初始猜测）开始，并以迭代方式向 0 的最小值移动。

1.  更新参数并移动到新点。

1.  我们不断重复这些步骤，直到收敛到解决方案，从而最小化函数。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00224.jpeg)

1.  重要的是要注意，梯度下降（GD）及其变体使用一阶导数，这意味着它们忽略曲率，而牛顿或拟牛顿（BFGS，LBFGS）方法等二阶导数算法使用梯度和曲率，有时还使用海森矩阵（相对于每个变量的部分导数矩阵）。

GD 的替代方案将是在整个域空间中搜索最佳设置，这既不切实际，也永远不会在实际意义上终止，因为真实大数据机器学习问题的规模和范围。

# 还有更多...

当你刚开始使用 GD 时，掌握步长或学习率非常重要。如果步长太小，会导致计算浪费，并给人一种梯度下降不收敛到解决方案的错觉。虽然对于演示和小项目来说设置步长是微不足道的，但将其设置为错误的值可能会导致大型 ML 项目的高计算损失。另一方面，如果步长太大，我们就会陷入乒乓情况或远离收敛，通常表现为误差曲线爆炸，意味着误差随着每次迭代而增加，而不是减少。

根据我们的经验，最好查看误差与迭代图表，并使用拐点来确定正确的值。另一种方法是尝试 .01, .001,......0001，并观察每次迭代的收敛情况（步长太小或太大）。值得记住的是，步长只是一个缩放因子，因为在某一点的实际梯度可能太大而无法移动（它会跳过最小值）。

总结：

+   如果步长太小，收敛速度就会很慢。

+   如果步长太大，你会跳过最小值（过冲），导致计算缓慢或出现乒乓效应（卡住）。

下图显示了基于不同步长的变化，以演示前面提到的要点。

+   **场景 1**：步长= .01 - 步长适中 - 只是稍微有点小，但在大约 200 次迭代中完成了任务。我们不希望看到任何少于 200 的情况，因为它必须足够通用以在现实生活中生存。

+   **场景 2**：步长= .001 - 步长太小，导致收敛速度缓慢。虽然看起来并不那么糟糕（1,500+次迭代），但可能被认为太细粒度了。

+   **场景 3**：步长= .05 - 步长太大了。在这种情况下，算法会陷入困境，来回徘徊而无法收敛。不能再强调了，你必须考虑在现实生活中出现这种情况时的退出策略（数据的性质和分布会发生很大变化，所以要有所准备）。

+   **场景 4**：步长= .06 - 步长太大，导致不收敛和爆炸。误差曲线爆炸（以非线性方式增加），意味着误差随着每次迭代而变大，而不是变小。在实践中，我们看到这种情况（场景 4）比之前的情况更多，但两种情况都可能发生，所以你应该为两种情况做好准备。正如你所看到的，场景 3 和场景 4 之间步长的微小差异造成了梯度下降行为的不同。这也是使算法交易困难的相同问题（优化）。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00225.jpeg)

值得一提的是，对于这种光滑凸优化问题，局部最小值通常与全局最小值相同。你可以将局部最小值/最大值视为给定范围内的极值。对于同一函数，全局最小值/最大值指的是函数整个范围内的全局或最绝对值。

# 另见

随机梯度下降：梯度下降（GD）有多种变体，其中随机梯度下降（SGD）是最受关注的。Apache Spark 支持随机梯度下降（SGD）变体，其中我们使用训练数据的子集来更新参数 - 这有点具有挑战性，因为我们需要同时更新参数。SGD 与 GD 之间有两个主要区别。第一个区别是 SGD 是一种在线学习/优化技术，而 GD 更多是一种离线学习/优化技术。SGD 与 GD 之间的第二个区别是由于不需要在更新任何参数之前检查整个数据集，因此收敛速度更快。这一区别在下图中有所体现：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00226.jpeg)

我们可以在 Apache Spark 中设置批处理窗口大小，以使算法对大规模数据集更具响应性（无需一次遍历整个数据集）。SGD 会有一些与之相关的随机性，但总体上它是当今使用的“事实标准”方法。它速度更快，收敛速度更快。

在 GD 和 SGD 的情况下，您通过更新原始参数来寻找模型的最佳参数。不同之处在于，在核心 GD 中，您必须遍历所有数据点以在给定迭代中对参数进行单次更新，而在 SGD 中，您需要查看来自训练数据集的每个单个（或小批量）样本以更新参数。

对于简短的通用写作，一个好的起点是以下内容：

+   GD :[`en.wikipedia.org/wiki/Gradient_descent`](https://en.wikipedia.org/wiki/Gradient_descent)

+   SGD:[`en.wikipedia.org/wiki/Stochastic_gradient_descent`](https://en.wikipedia.org/wiki/Stochastic_gradient_descent)

可以在 CMU、微软和统计软件杂志中找到更多数学处理：

+   CMU: [`www.cs.cmu.edu/~ggordon/10725-F12/slides/05-gd-revisited.pdf`](https://www.cs.cmu.edu/~ggordon/10725-F12/slides/05-gd-revisited.pdf)

+   [MS :](https://www.cs.cmu.edu/~ggordon/10725-F12/slides/05-gd-revisited.pdf) [`cilvr.cs.nyu.edu/diglib/lsml/bottou-sgd-tricks-2012.pdf`](http://cilvr.cs.nyu.edu/diglib/lsml/bottou-sgd-tricks-2012.pdf)

+   Jstat:[`arxiv.org/pdf/1509.06459v1.pdf`](https://arxiv.org/pdf/1509.06459v1.pdf)

# 编写梯度下降优化来解决线性回归问题

在这个示例中，我们将探讨如何编写梯度下降来解决线性回归问题。在上一个示例中，我们演示了如何编写 GD 来找到二次函数的最小值。

这个示例演示了一个更现实的优化问题，我们通过 Scala 在 Apache Spark 2.0+上优化（最小化）最小二乘成本函数来解决线性回归问题。我们将使用真实数据运行我们的算法，并将结果与一流的商业统计软件进行比较，以展示准确性和速度。

# 如何做...

1.  我们首先从普林斯顿大学下载包含以下数据的文件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00227.jpeg)

来源：普林斯顿大学

1.  下载源码：[`data.princeton.edu/wws509/datasets/#salary`](http://data.princeton.edu/wws509/datasets/#salary).

1.  为了简化问题，我们选择`yr`和`sl`来研究年级对薪水的影响。为了减少数据整理代码，我们将这两列保存在一个文件中（`Year_Salary.csv`），如下表所示，以研究它们的线性关系：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00228.gif)

1.  我们使用 IBM SPSS 软件的散点图来直观地检查数据。不能再次强调，视觉检查应该是任何数据科学项目的第一步。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00229.jpeg)

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  我们使用 import 包将代码放在所需的位置：

`package spark.ml.cookbook.chapter9`.

前四个语句导入了 JFree 图表包的必要包，以便我们可以在同一代码库中绘制 GD 错误和收敛。第五个导入处理`ArrayBuffer`，我们用它来存储中间结果：

```scala
import java.awt.Color
import org.jfree.chart.plot.{XYPlot, PlotOrientation}
import org.jfree.chart.{ChartFactory, ChartFrame, JFreeChart}
import org.jfree.data.xy.{XYSeries, XYSeriesCollection}
import scala.collection.mutable.ArrayBuffer
```

1.  定义数据结构以保存中间结果，因为我们最小化错误并收敛到斜率（`mStep`）和截距（`bStep`）的解决方案：

```scala
val gradientStepError = ArrayBuffer[(Int, Double)]()
val bStep = ArrayBuffer[(Int, Double)]()
val mStep = ArrayBuffer[(Int, Double)]()
```

1.  定义通过 JFree 图表进行绘图的函数。第一个函数只显示图表，第二个函数设置图表属性。这是一个模板代码，您可以根据自己的喜好进行自定义：

```scala
def show(chart: JFreeChart) {
val frame = new ChartFrame("plot", chart)
frame.pack()
frame.setVisible(true)
}
def configurePlot(plot: XYPlot): Unit = {
plot.setBackgroundPaint(Color.WHITE)
plot.setDomainGridlinePaint(Color.BLACK)
plot.setRangeGridlinePaint(Color.BLACK)
plot.setOutlineVisible(false)
}
```

1.  该函数基于最小二乘原理计算错误，我们最小化该错误以找到最佳拟合解决方案。该函数找到我们预测的值与训练数据中实际值（薪水）之间的差异。找到差异后，对其进行平方以计算总错误。pow()函数是一个 Scala 数学函数，用于计算平方。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00230.jpeg)

来源：维基百科

```scala
Beta : Slope (m variable)
Alpha : Intercept b variable)

def compute_error_for_line_given_points(b:Double, m:Double, points: Array[Array[Double]]):Double = {
var totalError = 0.0
for( point <- points ) {
var x = point(0)
var y = point(1)
totalError += math.pow(y - (m * x + b), 2)
}
return totalError / points.length
}
```

1.  下一个函数计算*f(x)= b + mx*的两个梯度（一阶导数），并在整个定义域（所有点）上对它们进行平均。这与第二个配方中的过程相同，只是我们需要偏导数（梯度），因为我们要最小化两个参数`m`和`b`（斜率和截距），而不仅仅是一个参数。

在最后两行中，我们通过学习率（步长）将梯度进行缩放。我们这样做的原因是为了确保我们不会得到很大的步长，并超过最小值，导致出现乒乓情景或错误膨胀，正如前面的配方中所讨论的那样。

```scala
def step_gradient(b_current:Double, m_current:Double, points:Array[Array[Double]], learningRate:Double): Array[Double]= {
var b_gradient= 0.0
var m_gradient= 0.0
var N = points.length.toDouble
for (point <- points) {
var x = point(0)
var y = point(1)
b_gradient += -(2 / N) * (y - ((m_current * x) + b_current))
m_gradient += -(2 / N) * x * (y - ((m_current * x) + b_current))
}
var result = new ArrayDouble
result(0) = b_current - (learningRate * b_gradient)
result(1) = m_current - (learningRate * m_gradient)
return result
}
```

1.  该函数读取并解析 CSV 文件：

```scala
def readCSV(inputFile: String) : Array[Array[Double]] = {scala.io.Source.fromFile(inputFile)
.getLines()
.map(_.split(",").map(_.trim.toDouble))
.toArray
}
```

1.  以下是一个包装函数，它循环 N 次迭代，并调用`step_gradient()`函数来计算给定点的梯度。然后，我们继续逐步存储每一步的结果，以便以后处理（例如绘图）。

值得注意的是使用`Tuple2()`来保存`step_gradient()`函数的返回值。

在函数的最后几步中，我们调用`compute_error_for_line_given_points()`函数来计算给定斜率和截距组合的错误，并将其存储在`gradientStepError`中。

```scala
def gradient_descent_runner(points:Array[Array[Double]], starting_b:Double, starting_m:Double, learning_rate:Double, num_iterations:Int):Array[Double]= {
var b = starting_b
var m = starting_m
var result = new ArrayDouble
var error = 0.0
result(0) =b
result(1) =m
for (i <-0 to num_iterations) {
result = step_gradient(result(0), result(1), points, learning_rate)
bStep += Tuple2(i, result(0))
mStep += Tuple2(i, result(1))
error = compute_error_for_line_given_points(result(0), result(1), points)
gradientStepError += Tuple2(i, error)
}
```

1.  最后一步是主程序，它设置了斜率、截距、迭代次数和学习率的初始起点。我们故意选择了较小的学习率和较大的迭代次数，以展示准确性和速度。

1.  首先，我们从初始化 GD 的关键控制变量开始（学习率、迭代次数和起始点）。

1.  其次，我们继续显示起始点（0,0），并调用`compute_error_for_line_given_points()`来显示起始错误。值得注意的是，经过 GD 运行后，错误应该更低，并在最后一步显示结果。

1.  1.  第三，我们为 JFree 图表设置必要的调用和结构，以显示两个图表，描述斜率、截距和错误的行为，当我们朝着优化解决方案（最小化错误的最佳斜率和截距组合）合并时。

```scala
def main(args: Array[String]): Unit = {
val input = "../data/sparkml2/chapter9/Year_Salary.csv"
val points = readCSV(input)
val learning_rate = 0.001
val initial_b = 0
val initial_m = 0
val num_iterations = 30000
println(s"Starting gradient descent at b = $initial_b, m =$initial_m, error = "+ compute_error_for_line_given_points(initial_b, initial_m, points))
println("Running...")
val result= gradient_descent_runner(points, initial_b, initial_m, learning_rate, num_iterations)
var b= result(0)
var m = result(1)
println( s"After $num_iterations iterations b = $b, m = $m, error = "+ compute_error_for_line_given_points(b, m, points))
val xy = new XYSeries("")
gradientStepError.foreach{ case (x: Int,y: Double) => xy.add(x,y) }
val dataset = new XYSeriesCollection(xy)
val chart = ChartFactory.createXYLineChart(
"Gradient Descent", // chart title
"Iteration", // x axis label
"Error", // y axis label
dataset, // data
PlotOrientation.VERTICAL,
false, // include legend
true, // tooltips
false // urls)
val plot = chart.getXYPlot()
configurePlot(plot)
show(chart)
val bxy = new XYSeries("b")
bStep.foreach{ case (x: Int,y: Double) => bxy.add(x,y) }
val mxy = new XYSeries("m")
mStep.foreach{ case (x: Int,y: Double) => mxy.add(x,y) }
val stepDataset = new XYSeriesCollection()
stepDataset.addSeries(bxy)
stepDataset.addSeries(mxy)
val stepChart = ChartFactory.createXYLineChart(
"Gradient Descent Steps", // chart title
"Iteration", // x axis label
"Steps", // y axis label
stepDataset, // data
PlotOrientation.VERTICAL,
true, // include legend
true, // tooltips
false // urls
)
val stepPlot = stepChart.getXYPlot()
configurePlot(stepPlot)
show(stepChart)
}
```

1.  以下是此配方的输出。

首先，我们显示起始点为 0,0，错误为 6.006，然后允许算法运行，并在完成迭代次数后显示结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00231.jpeg)

值得注意的是起始和结束的错误数字以及由于优化而随时间减少。

1.  我们使用 IBM SPSS 作为控制点，以显示我们组合的 GD 算法与 SPSS 软件生成的结果（几乎 1:1）几乎完全相同！

下图显示了 IBM SPSS 的输出，用于比较结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00232.jpeg)

1.  在最后一步，程序并排生成了两个图表。

下图显示了斜率（*m*）和截距（*b*）是如何朝着最小化错误的最佳组合收敛的，当我们通过迭代运行时。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00233.jpeg)

下图显示了斜率（*m*）和截距（*b*）是如何朝着最小化错误的最佳组合收敛的，当我们通过迭代运行时。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00234.jpeg)

# 工作原理...

梯度下降是一种迭代的数值方法，它从一个初始猜测开始，然后通过查看一个错误函数来询问自己，我做得有多糟糕，这个错误函数是训练文件中预测数据与实际数据的平方距离。

在这个程序中，我们选择了一个简单的线性方程*f(x) = b + mx*作为我们的模型。为了优化并找出最佳的斜率 m 和截距 b 的组合，我们有 52 对实际数据(年龄，工资)可以代入我们的线性模型(*预测工资=斜率 x 年龄+截距*)。简而言之，我们想要找到最佳的斜率和截距的组合，帮助我们拟合一个最小化平方距离的线性线。平方函数给我们所有正值，并让我们只关注错误的大小。

+   `ReadCSV()`: 读取和解析数据文件到我们的数据集中：

*(x[1], y[1]), (x[2], y[2]), (x[3], y[4]), ... (x[52], y[52])*

+   `Compute_error_for_line_given_points()`: 这个函数实现了成本或错误函数。我们使用一个线性模型(一条直线的方程)来预测，然后测量与实际数字的平方距离。在添加错误后，我们平均并返回总错误：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00235.gif)

y[i] = mx[i] + b：对于所有数据对(*x, y)*

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00236.jpeg)

函数内值得注意的代码：第一行代码计算了预测值(*m * x + b*)与实际值(*y*)之间的平方距离。第二行代码对其进行平均并返回：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00237.gif)*totalError += math.pow(y - (m * x + b), 2)**....**return totalError / points.length*

下图显示了最小二乘法的基本概念。简而言之，我们取实际训练数据与我们的模型预测之间的距离，然后对它们进行平方，然后相加。我们平方的原因是为了避免使用绝对值函数`abs()`，这在计算上是不可取的。平方差具有更好的数学性质，提供了连续可微的性质，这在想要最小化它时是更可取的。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00238.jpeg)

+   `step_gradient()`: 这个函数是计算梯度(一阶导数)的地方，使用我们正在迭代的当前点(*x[i],y[i])*。需要注意的是，与之前的方法不同，我们有两个参数，所以我们需要计算截距(`b_gradient`)和斜率(`m_gradient`)的偏导数。然后我们需要除以点的数量来求平均。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00239.jpeg)

+   使用对截距(*b*)的偏导数：

*b_gradient += -(2 / N) * (y - ((m_current * x) + b_current))*

+   使用对斜率(*m*)的偏导数：

*m_gradient += -(2 / N) * x * (y - ((m_current * x) + b_current))*

+   最后一步是通过学习率(步长)来缩放计算出的梯度，然后移动到斜率(m_current)和截距(b_current)的新估计位置：*result(0) = b_current - (learningRate * b_gradient)**result(1) = m_current - (learningRate * m_gradient)*

+   `gradient_descent_runner()`: 这是执行`step_gradient()`和`compute_error_for_line_given_points()`的驱动程序，执行定义的迭代次数：

```scala
r (i <-0 to num_iterations) {
step_gradient()
...
compute_error_for_line_given_points()
...
}
```

# 还有更多...

虽然这个方法能够处理现实生活中的数据并与商业软件的估计相匹配，但在实践中，您需要实现随机梯度下降。

Spark 2.0 提供了带有小批量窗口的随机梯度下降(SGD)。

Spark 提供了两种利用 SGD 的方法。第一种选择是使用独立的优化技术，您可以通过传入优化函数来使用。参见以下链接：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.optimization.Optimizer`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.optimization.Optimizer)和[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.optimization.GradientDescent`](https://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.optimization.GradientDescent)

第二种选择是使用已经内置了 SGD 的专门 API 作为它们的优化技术：

+   `LogisticRegressionWithSGD()`

+   `StreamingLogisticRegressionWithSGD()`

+   `LassoWithSGD()`

+   `LinearRegressionWithSGD()`

+   `RidgeRegressionWithSGD()`

+   `SVMWithSGD()`

截至 Spark 2.0，所有基于 RDD 的回归只处于维护模式。

# 另请参阅

+   Spark 2.0 的优化：[`spark.apache.org/docs/latest/mllib-optimization.html#stochastic-gradient-descent-sgd`](https://spark.apache.org/docs/latest/mllib-optimization.html#stochastic-gradient-descent-sgd)

# 正规方程作为解决 Spark 2.0 中线性回归的替代方法

在这个示例中，我们提供了使用正规方程来解决线性回归的梯度下降（GD）和 LBFGS 的替代方法。在正规方程的情况下，您正在将回归设置为特征矩阵和标签向量（因变量），同时尝试通过使用矩阵运算（如逆、转置等）来解决它。

重点在于强调 Spark 使用正规方程来解决线性回归的便利性，而不是模型或生成系数的细节。

# 如何操作...

1.  我们使用了在第五章和第六章中广泛涵盖的相同的房屋数据集，这些章节分别是*Spark 2.0 中的回归和分类的实际机器学习-第 I 部分*和*Spark 2.0 中的回归和分类的实际机器学习-第 II 部分*，它们将各种属性（例如房间数量等）与房屋价格相关联。

数据可在`Chapter 9`数据目录下的`housing8.csv`中找到。

1.  我们使用 package 指令来处理放置：

```scala
package spark.ml.cookbook.chapter9
```

1.  然后导入必要的库：

```scala
import org.apache.spark.ml.feature.LabeledPoint
import org.apache.spark.ml.linalg.Vectors
import org.apache.spark.ml.regression.LinearRegression
import org.apache.spark.sql.SparkSession
import org.apache.log4j.{Level, Logger}
import spark.implicits._
```

1.  将 Spark 生成的额外输出减少，将 Logger 信息级别设置为`Level.ERROR`：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)
Logger.getLogger("akka").setLevel(Level.ERROR)
```

1.  使用适当的属性设置 SparkSession：

```scala
val spark = SparkSession
.builder
.master("local[*]")
.appName("myRegressNormal")
.config("spark.sql.warehouse.dir", ".")
.getOrCreate()
```

1.  读取输入文件并将其解析为数据集：

```scala
val data = spark.read.text("../data/sparkml2/housing8.csv").as[String]
val RegressionDataSet = data.map { line => val columns = line.split(',')
LabeledPoint(columns(13).toDouble , Vectors.dense(columns(0).toDouble,columns(1).toDouble, columns(2).toDouble, columns(3).toDouble,columns(4).toDouble,
columns(5).toDouble,columns(6).toDouble, columns(7).toDouble
))
}
```

1.  显示以下数据集内容，但限制为前三行以供检查：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00240.gif)

1.  我们创建一个 LinearRegression 对象，并设置迭代次数、ElasticNet 和正则化参数。最后一步是通过选择`setSolver("normal")`来设置正确的求解器方法：

```scala
val lr = new LinearRegression()                                      
  .setMaxIter(1000)                                   
  .setElasticNetParam(0.0)  
  .setRegParam(0.01)                                    
  .setSolver("normal")
```

请确保将 ElasticNet 参数设置为 0.0，以便"normal"求解器正常工作。

1.  使用以下内容将`LinearRegressionModel`拟合到数据中：

```scala
val myModel = lr.fit(RegressionDataSet)
Extract the model summary:
val summary = myModel.summary
```

运行程序时会生成以下输出：

```scala
training Mean Squared Error = 13.609079490110766
training Root Mean Squared Error = 3.6890485887435482
```

读者可以输出更多信息，但模型摘要已在第五章和第六章中进行了覆盖，*Spark 2.0 中的回归和分类的实际机器学习-第 I 部分*和*Spark 2.0 中的回归和分类的实际机器学习-第 II 部分*，通过其他技术。

# 它是如何工作的...

我们最终尝试使用封闭形式公式解决线性回归的以下方程：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00241.jpeg)

Spark 通过允许您设置`setSolver("normal")`提供了一个完全并行的解决这个方程的方法。

# 还有更多...

如果未将 ElasticNet 参数设置为 0.0，则会出现错误，因为在 Spark 中通过正规方程求解时使用了 L2 正则化（截至目前）。

有关 Spark 2.0 中等稳定回归的文档可以在以下网址找到：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.regression.LinearRegression`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.regression.LinearRegression) 和 [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.regression.LinearRegressionModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.regression.LinearRegressionModel)

模型摘要可以在以下链接找到：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.regression.LinearRegressionSummary`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.regression.LinearRegressionSummary)

[﻿](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.ml.regression.LinearRegressionSummary)

# 另请参阅

还可以参考以下表格：

| 迭代方法（SGD，LBFGS） | 闭合形式正规方程 |
| --- | --- |
| 选择学习率 | 无参数 |
| 迭代次数可能很大 | 不迭代 |
| 在大特征集上表现良好 | 在大特征集上速度慢且不实用 |
| 容易出错：由于参数选择不当而卡住 | (x^Tx)^(-1)的计算代价高 - 复杂度为 n³ |

以下是关于 LinearRegression 对象配置的快速参考，但是请查看第五章，*Spark 2.0 中的回归和分类的实用机器学习-第 I 部分*和第六章，*Spark 2.0 中的回归和分类的实用机器学习-第 II 部分*以获取更多细节。

+   L1：套索回归

+   L2：岭回归

+   L1 - L2：弹性网络，可以调整参数

以下链接是哥伦比亚大学的一篇文章，解释了正规方程与解决线性回归问题的关系：

+   [`www.stat.columbia.edu/~fwood/Teaching/w4315/Fall2009/lecture_11`](http://www.stat.columbia.edu/~fwood/Teaching/w4315/Fall2009/lecture_11)

+   [GNU 的 Octave（](http://www.stat.columbia.edu/~fwood/Teaching/w4315/Fall2009/lecture_11) [`www.gnu.org/software/octave/`](https://www.gnu.org/software/octave/)[)是一种流行的矩阵操作软件，你应该在工具包中拥有它。](http://www.stat.columbia.edu/~fwood/Teaching/w4315/Fall2009/lecture_11)

+   以下链接包含一个快速教程，帮助你入门：[`www.lauradhamilton.com/tutorial-linear-regression-with-octave`](http://www.lauradhamilton.com/tutorial-linear-regression-with-octave)


# 第十章：使用决策树和集成模型构建机器学习系统

在本章中，我们将涵盖：

+   获取和准备真实世界的医疗数据，以探索 Spark 2.0 中的决策树和集成模型

+   在 Spark 2.0 中使用决策树构建分类系统

+   在 Spark 2.0 中使用决策树解决回归问题

+   在 Spark 2.0 中使用随机森林树构建分类系统

+   在 Spark 2.0 中使用随机森林树解决回归问题

+   在 Spark 2.0 中使用梯度提升树（GBT）构建分类系统

+   在 Spark 2.0 中使用梯度提升树（GBT）解决回归问题

# 介绍

决策树是商业中最古老和广泛使用的机器学习方法之一。它们受欢迎的原因不仅在于它们处理更复杂的分区和分割的能力（它们比线性模型更灵活），还在于它们解释我们是如何得出解决方案以及“为什么”结果被预测或分类为类/标签的能力。

Apache Spark 提供了一系列基于决策树的算法，完全能够利用 Spark 中的并行性。实现范围从直接的单决策树（CART 类型算法）到集成树，例如随机森林树和梯度提升树（GBT）。它们都有变体风味，以便进行分类（例如，分类，例如，身高=矮/高）或回归（例如，连续，例如，身高=2.5 米）的便利。

以下图描述了一个思维导图，显示了决策树算法在 Spark ML 库中的覆盖范围，截至撰写时：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00242.jpeg)

快速理解决策树算法的一种方法是将其视为一种智能分区算法，它试图最小化损失函数（例如，L2 或最小二乘），因为它将范围划分为最适合数据的分段空间。通过对数据进行采样并尝试组合特征，该算法变得更加复杂，从而组装出更复杂的集成模型，其中每个学习者（部分样本或特征组合）都对最终结果进行投票。

以下图描述了一个简化版本，其中一个简单的二叉树（树桩）被训练为将数据分类为属于两种不同颜色的段（例如，健康患者/患病患者）。该图描述了一个简单的算法，每次建立决策边界（因此分类）时，它只是将 x/y 特征空间分成一半，同时最小化错误的数量（例如，L2 最小二乘测量）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00243.jpeg)

以下图提供了相应的树，以便我们可以可视化算法（在这种情况下，简单的分而治之）针对提出的分割空间。决策树算法受欢迎的原因是它们能够以一种易于向业务用户沟通的语言显示其分类结果，而无需太多数学：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00244.gif)

Spark 中的决策树是一种并行算法，旨在将单个树拟合和生长到可以是分类（分类）或连续（回归）的数据集中。它是一种贪婪算法，基于树桩（二进制分割等），通过递归地划分解空间，尝试使用信息增益最大化（基于熵）来选择所有可能分割中的最佳分割。

# 集成模型

观察 Spark 对决策树的另一种方式是将算法视为属于两个阵营。第一个阵营，我们在介绍中看到过，关注于试图找到各种技术来为数据集找到最佳的单棵树。虽然这对许多数据集来说是可以的，但算法的贪婪性质可能会导致意想不到的后果，比如过拟合和过度深入以能够捕捉训练数据中的所有边界（即过度优化）。

为了克服过拟合问题并提高准确性和预测质量，Spark 实现了两类集成决策树模型，试图创建许多不完美的学习器，这些学习器要么看到数据的子集（有或没有替换地采样），要么看到特征的子集。虽然每棵单独的树不太准确，但树的集合组装的投票（或在连续变量的情况下的平均概率）和由此产生的平均值比任何单独的树更准确：

+   **随机森林**：这种方法并行创建许多树，然后投票/平均结果以最小化单棵树算法中容易出现的过拟合问题。它们能够捕捉非线性和特征交互而无需任何缩放。它们应该至少被认真考虑为用于解剖数据并了解其构成的第一工具集之一。以下图提供了 Spark 中此实现的可视化指南：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00245.gif)

+   **梯度提升树**：这种方法是另一种集成模型，通过许多树的平均值（即使它们不太完美）来提高预测的准确性和质量。它们与随机森林的不同之处在于，它们一次构建一棵树，每棵树都试图从前一棵树的缺点中学习，通过最小化损失函数来改进。它们类似于梯度下降的概念，但它们使用最小化（类似于梯度）来选择和改进下一棵树（它们沿着创建最佳准确性的树的方向前进）。

损失函数的三个选项是：

+   **对数损失**：分类的负对数似然

+   **L2**：回归的最小二乘

+   **L1**：回归的绝对误差

以下图提供了一个易于使用的可视化参考：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00246.gif)

Spark 中决策树的主要包在 ML 中，如下所示：

```scala
org.apache.spark.mllib.tree
org.apache.spark.mllib.tree.configuration
org.apache.spark.mllib.tree.impurity
org.apache.spark.mllib.tree.model
```

# 不纯度的度量

对于所有的机器学习算法，我们都试图最小化一组成本函数，这些函数帮助我们选择最佳的移动。Spark 使用三种可能的最大化函数选择。以下图描述了这些替代方案：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00247.gif)

在本节中，我们将讨论三种可能的替代方案：

+   **信息增益**：粗略地说，这是根据熵的概念来衡量群体中不纯度的水平--参见香农信息理论，然后后来由 Quinlan 在他的 ID3 算法中建议。

熵的计算如下方程所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00248.jpeg)

信息增益帮助我们在每个特征向量空间中选择一个属性，这个属性可以最好地帮助我们将类别彼此分开。我们使用这个属性来决定如何对节点中的属性进行排序（从而影响决策边界）。

以下图形以易于理解的方式描述了计算。在第一步中，我们希望选择一个属性，以便在根节点或父节点中最大化 IG（信息增益），然后为所选属性的每个值构建我们的子节点（它们的关联向量）。我们不断递归地重复算法，直到我们再也看不到任何收益：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00249.gif)

+   **基尼指数：** 这试图通过隔离类别来改进信息增益（IG），以便最大的类别与总体分离。基尼指数与熵有些不同，因为您尝试实现 50/50 的分割，然后应用进一步的分割来推断解决方案。它旨在反映一个变量的影响，并且不会扩展其影响到多属性状态。它使用简单的频率计数来对总体进行评估。用于更高维度和更多噪音数据的基尼指数。

在您拥有复杂的多维数据并且正在尝试从中解剖简单信号的情况下，请使用基尼不纯度。

另一方面，在您拥有更清洁和低维数据集的情况下，可以使用信息增益（或任何基于熵的系统），但您正在寻找更复杂（在准确性和质量方面）的数据集：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00250.gif)

+   **方差**：方差用于信号树算法的回归模型。简而言之，我们仍然试图最小化 L2 函数，但不同之处在于这里我们试图最小化观察值与被考虑的节点（段）的平均值之间的距离的平方。

以下图表描述了可视化的简化版本：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00251.jpeg)

用于评估树模型的 Spark 模型评估工具包括以下内容：

混淆矩阵是用来描述分类模型性能的表格，其中真实值已知的测试数据集。混淆矩阵本身相对简单；它是一个 2x2 的矩阵：

|  |  | **预测** | **值** |
| --- | --- | --- | --- |
|  |  | 是 | 否 |
| **实际** | 是 | 真正例（TP） | 假反例（FN） |
| **值** | 否 | 假正例（FP） | 真反例（TN） |

对于我们的癌症数据集：

+   **真正例（TP）：** 预测为是，且他们确实患有乳腺癌

+   **真反例（TN）：** 预测为否，且他们没有乳腺癌

+   **假正例（FP）：** 我们预测为是，但他们没有乳腺癌

+   **假反例（FN）：** 我们预测为否，但他们确实患有乳腺癌

一个良好的分类系统应该与现实情况密切匹配，具有良好的 TP 和 TN 值，同时具有较少的 FP 和 FN 值。

总的来说，以下术语也被用作分类模型的标记：

1.  **准确性**：模型的正确率：

+   *(TP + TN)/总数*

1.  **错误**：总体上，模型错误的百分比：

+   *(FP+FN)/总数*

+   也等于 1-准确性

在 Spark 机器学习库中，有一个实用程序类来处理上述常见矩阵的计算：

```scala
   org.apache.spark.mllib.evaluation.MulticlassMetrics 
```

我们将在以下示例代码中使用实用程序类。

同样，对于回归算法，**均方误差（MSE）** 或误差平方的平均值，被广泛用作模型测量的关键参数。在 Spark 机器学习库中，也有一个实用程序类，它将提供回归模型的关键指标：

```scala
   org.apache.spark.mllib.evaluation.RegressionMetrics 
```

Spark 矩阵评估器的文档可以在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.MulticlassMetrics`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.MulticlassMetrics)和[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.RegressionMetrics`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.RegressionMetrics)找到。

# 获取和准备真实世界的医学数据，以探索 Spark 2.0 中的决策树和集成模型

使用决策树在机器学习中的真实应用。我们使用了一个癌症数据集来预测患者病例是恶性还是良性。为了探索决策树的真正威力，我们使用了一个展现真实生活非线性和复杂误差表面的医学数据集。

# 如何做...

**威斯康星乳腺癌**数据集是从威斯康星大学医院的 William H Wolberg 博士处获得的。该数据集是定期获得的，因为 Wolberg 博士报告了他的临床病例。

该数据集可以从多个来源检索，并且可以直接从加州大学尔湾分校的网络服务器 [`archive.ics.uci.edu/ml/machine-learning-databases/breast-cancer-wisconsin/breast-cancer-wisconsin.data`](http://archive.ics.uci.edu/ml/machine-learning-databases/breast-cancer-wisconsin/breast-cancer-wisconsin.data) 获取。

数据也可以从威斯康星大学的网络服务器 ftp://ftp.cs.wisc.edu/math-prog/cpo-dataset/machine-learn/cancer/cancer1/datacum 获取。

该数据集目前包含 1989 年至 1991 年的临床病例。它有 699 个实例，其中 458 个被分类为良性肿瘤，241 个被分类为恶性病例。每个实例由九个属性描述，属性值在 1 到 10 的范围内，并带有二进制类标签。在这 699 个实例中，有 16 个实例缺少一些属性。

我们将从内存中删除这 16 个实例，并处理其余的（总共 683 个实例）进行模型计算。

样本原始数据如下所示：

```scala
1000025,5,1,1,1,2,1,3,1,1,2
1002945,5,4,4,5,7,10,3,2,1,2
1015425,3,1,1,1,2,2,3,1,1,2
1016277,6,8,8,1,3,4,3,7,1,2
1017023,4,1,1,3,2,1,3,1,1,2
1017122,8,10,10,8,7,10,9,7,1,4
...
```

属性信息如下：

| **#** | **属性** | **域** |
| --- | --- | --- |
| 1 | 样本编号 | ID 编号 |
| 2 | 块厚度 | 1 - 10 |
| 3 | 细胞大小的均匀性 | 1 - 10 |
| 4 | 细胞形态的均匀性 | 1 - 10 |
| 5 | 边缘粘附 | 1 - 10 |
| 6 | 单个上皮细胞大小 | 1 - 10 |
| 7 | 裸核 | 1 - 10 |
| 8 | 淡染色质 | 1 - 10 |
| 9 | 正常核仁 | 1 - 10 |
| 10 | 有丝分裂 | 1 - 10 |
| 11 | 类别 | (2 表示良性，4 表示恶性) |

如果以正确的列呈现，将如下所示：

| **ID 编号** | **块厚度** | **细胞大小的均匀性** | **细胞形态的均匀性** | **边缘粘附** | **单个上皮细胞大小** | **裸核** | **淡染色质** | **正常核仁** | **有丝分裂** | **类别** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1000025 | 5 | 1 | 1 | 1 | 2 | 1 | 3 | 1 | 1 | 2 |
| 1002945 | 5 | 4 | 4 | 5 | 7 | 10 | 3 | 2 | 1 | 2 |
| 1015425 | 3 | 1 | 1 | 1 | 2 | 2 | 3 | 1 | 1 | 2 |
| 1016277 | 6 | 8 | 8 | 1 | 3 | 4 | 3 | 7 | 1 | 2 |
| 1017023 | 4 | 1 | 1 | 3 | 2 | 1 | 3 | 1 | 1 | 2 |
| 1017122 | 8 | 10 | 10 | 8 | 7 | 10 | 9 | 7 | 1 | 4 |
| 1018099 | 1 | 1 | 1 | 1 | 2 | 10 | 3 | 1 | 1 | 2 |
| 1018561 | 2 | 1 | 2 | 1 | 2 | 1 | 3 | 1 | 1 | 2 |
| 1033078 | 2 | 1 | 1 | 1 | 2 | 1 | 1 | 1 | 5 | 2 |
| 1033078 | 4 | 2 | 1 | 1 | 2 | 1 | 2 | 1 | 1 | 2 |
| 1035283 | 1 | 1 | 1 | 1 | 1 | 1 | 3 | 1 | 1 | 2 |
| 1036172 | 2 | 1 | 1 | 1 | 2 | 1 | 2 | 1 | 1 | 2 |
| 1041801 | 5 | 3 | 3 | 3 | 2 | 3 | 4 | 4 | 1 | 4 |
| 1043999 | 1 | 1 | 1 | 1 | 2 | 3 | 3 | 1 | 1 | 2 |
| 1044572 | 8 | 7 | 5 | 10 | 7 | 9 | 5 | 5 | 4 | 4 |
| ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |

# 还有更多...

威斯康星乳腺癌数据集在机器学习社区中被广泛使用。该数据集包含有限的属性，其中大部分是离散数字。非常容易将分类算法和回归模型应用于该数据集。

已经有 20 多篇研究论文和出版物引用了这个数据集，它是公开可用的，非常容易使用。

该数据集具有多变量数据类型，其中属性为整数，属性数量仅为 10。这使得它成为本章分类和回归分析的典型数据集之一。

# 在 Spark 2.0 中构建决策树分类系统

在本示例中，我们将使用乳腺癌数据并使用分类来演示 Spark 中的决策树实施。我们将使用 IG 和 Gini 来展示如何使用 Spark 已经提供的设施，以避免冗余编码。此示例尝试使用二进制分类来拟合单棵树，以训练和预测数据集的标签（良性（0.0）和恶性（1.0））。

# 如何做到这一点

1.  在 IntelliJ 或您选择的 IDE 中启动新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

```scala
package spark.ml.cookbook.chapter10
```

1.  导入 Spark 上下文所需的必要包，以便访问集群和`Log4j.Logger`以减少 Spark 产生的输出量：

```scala
import org.apache.spark.mllib.evaluation.MulticlassMetrics
import org.apache.spark.mllib.tree.DecisionTree
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.mllib.tree.model.DecisionTreeModel
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.SparkSession
import org.apache.log4j.{Level, Logger} 
```

1.  创建 Spark 的配置和 Spark 会话，以便我们可以访问集群：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)

 val spark = SparkSession
 .builder.master("local[*]")
 .appName("MyDecisionTreeClassification")
 .config("spark.sql.warehouse.dir", ".")
 .getOrCreate()
```

1.  我们读取原始原始数据文件：

```scala
val rawData = spark.sparkContext.textFile("../data/sparkml2/chapter10/breast-cancer-wisconsin.data")
```

1.  我们预处理数据集：

```scala
val data = rawData.map(_.trim)
 .filter(text => !(text.isEmpty || text.startsWith("#") || text.indexOf("?") > -1))
 .map { line =>
 val values = line.split(',').map(_.toDouble)
 val slicedValues = values.slice(1, values.size)
 val featureVector = Vectors.dense(slicedValues.init)
 val label = values.last / 2 -1
 LabeledPoint(label, featureVector)
 }
```

首先，我们修剪行并删除任何空格。一旦行准备好进行下一步，如果行为空或包含缺失值（“?”），则删除行。在此步骤之后，内存中的数据集将删除 16 行缺失数据。

然后我们将逗号分隔的值读入 RDD。由于数据集中的第一列只包含实例的 ID 号，最好将此列从实际计算中删除。我们使用以下命令切片，将从 RDD 中删除第一列：

```scala
val slicedValues = values.slice(1, values.size)
```

然后我们将其余数字放入密集向量。

由于威斯康星州乳腺癌数据集的分类器要么是良性病例（最后一列值=2），要么是恶性病例（最后一列值=4），我们使用以下命令转换前面的值：

```scala
val label = values.last / 2 -1
```

因此，良性病例 2 转换为 0，恶性病例值 4 转换为 1，这将使后续计算更容易。然后将前一行放入`Labeled Points`：

```scala
    Raw data: 1000025,5,1,1,1,2,1,3,1,1,2
    Processed Data: 5,1,1,1,2,1,3,1,1,0
    Labeled Points: (0.0, [5.0,1.0,1.0,1.0,2.0,1.0,3.0,1.0,1.0])
```

1.  我们验证原始数据计数并处理数据计数：

```scala
println(rawData.count())
println(data.count())
```

然后您将在控制台上看到以下内容：

```scala
699
683
```

1.  我们将整个数据集随机分成训练数据（70%）和测试数据（30%）。请注意，随机拆分将生成大约 211 个测试数据集。这大约是但并非完全是数据集的 30%：

```scala
val splits = data.randomSplit(Array(0.7, 0.3))
val (trainingData, testData) = (splits(0), splits(1))
```

1.  我们定义一个度量计算函数，它利用 Spark 的`MulticlassMetrics`：

```scala
def getMetrics(model: DecisionTreeModel, data: RDD[LabeledPoint]): MulticlassMetrics = {
 val predictionsAndLabels = data.map(example =>
 (model.predict(example.features), example.label)
 )
 new MulticlassMetrics(predictionsAndLabels)
 }
```

此函数将读取模型和测试数据集，并创建一个包含前面提到的混淆矩阵的度量。它将包含模型准确性，这是分类模型的指标之一。

1.  我们定义一个评估函数，它可以接受一些可调参数用于决策树模型，并对数据集进行训练：

```scala
def evaluate(
 trainingData: RDD[LabeledPoint],
 testData: RDD[LabeledPoint],
 numClasses: Int,
 categoricalFeaturesInfo: Map[Int,Int],

 impurity: String,
 maxDepth: Int,
 maxBins:Int
 ) :Unit = {

 val model = DecisionTree.*trainClassifier*(trainingData, numClasses,
 categoricalFeaturesInfo,
 impurity, maxDepth, maxBins)
 val metrics = getMetrics(model, testData)
 println("Using Impurity :"+ impurity)
 println("Confusion Matrix :")
 println(metrics.confusionMatrix)
 println("Decision Tree Accuracy: "+metrics.*precision*)
 println("Decision Tree Error: "+ (1-metrics.*precision*))

 }
```

评估函数将读取几个参数，包括不纯度类型（模型的基尼或熵）并生成评估指标。

1.  我们设置以下参数：

```scala
val numClasses = 2
 val categoricalFeaturesInfo = *Map*[Int, Int]()
 val maxDepth = 5
 val maxBins = 32
```

由于我们只有良性（0.0）和恶性（1.0），我们将 numClasses 设置为 2。其他参数是可调的，其中一些是算法停止标准。

1.  首先我们评估基尼不纯度：

```scala
evaluate(trainingData, testData, numClasses, categoricalFeaturesInfo,
"gini", maxDepth, maxBins)
```

从控制台输出：

```scala
Using Impurity :gini
Confusion Matrix :
115.0 5.0
0 88.0
Decision Tree Accuracy: 0.9620853080568721
Decision Tree Error: 0.03791469194312791
To interpret the above Confusion metrics, Accuracy is equal to (115+ 88)/ 211 all test cases, and error is equal to 1 -accuracy
```

1.  我们评估熵不纯度：

```scala
evaluate(trainingData, testData, numClasses, categoricalFeaturesInfo,
"entropy", maxDepth, maxBins)
```

从控制台输出：

```scala
Using Impurity:entropy
Confusion Matrix:
116.0 4.0
9.0 82.0
Decision Tree Accuracy: 0.9383886255924171
Decision Tree Error: 0.06161137440758291
To interpret the preceding confusion metrics, accuracy is equal to (116+ 82)/ 211 for all test cases, and error is equal to 1 - accuracy
```

1.  然后通过停止会话来关闭程序：

```scala
spark.stop()
```

# 它是如何工作的... 

数据集比通常更复杂，但除了一些额外步骤外，解析它与前几章介绍的其他示例相同。解析将数据以原始形式转换为中间格式，最终将成为 Spark ML 方案中常见的 LabelPoint 数据结构：

```scala
     Raw data: 1000025,5,1,1,1,2,1,3,1,1,2
     Processed Data: 5,1,1,1,2,1,3,1,1,0
     Labeled Points: (0.0, [5.0,1.0,1.0,1.0,2.0,1.0,3.0,1.0,1.0])
```

我们使用`DecisionTree.trainClassifier()`在训练集上训练分类器树。然后通过检查各种不纯度和混淆矩阵测量来演示如何衡量树模型的有效性。

鼓励读者查看输出并参考其他机器学习书籍，以了解混淆矩阵和不纯度测量的概念，以掌握 Spark 中决策树和变体。

# 还有更多...

为了更好地可视化，我们在 Spark 中包含了一个样本决策树工作流程，它将首先将数据读入 Spark。在我们的情况下，我们从文件创建 RDD。然后我们使用随机抽样函数将数据集分为训练数据和测试数据。

数据集分割后，我们使用训练数据集来训练模型，然后使用测试数据来测试模型的准确性。一个好的模型应该有一个有意义的准确度值（接近 1）。下图描述了工作流程：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00252.jpeg)

基于威斯康星乳腺癌数据集生成了一棵样本树。红点代表恶性病例，蓝点代表良性病例。我们可以在下图中直观地检查这棵树：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-2x-ml-cb/img/00253.jpeg)

# 另请参阅

+   构造函数的文档可以在以下网址找到：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.DecisionTree`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.DecisionTree) 和 [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.DecisionTreeModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.DecisionTreeModel)

+   Spark 矩阵评估器的文档可以在以下网址找到：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.MulticlassMetrics`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.MulticlassMetrics)

# 在 Spark 2.0 中使用决策树解决回归问题

与之前的示例类似，我们将使用`DecisionTree()`类来训练和预测使用回归树模型的结果。刷新所有这些模型是**CART**（**分类和回归树**）的一个变体，有两种模式。在这个示例中，我们探索了 Spark 中决策树实现的回归 API。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

```scala
package spark.ml.cookbook.chapter10
```

1.  导入 Spark 上下文所需的必要包，以便访问集群和`Log4j.Logger`以减少 Spark 产生的输出量：

```scala
import org.apache.spark.mllib.evaluation.RegressionMetrics
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.mllib.tree.DecisionTree
import org.apache.spark.mllib.tree.model.DecisionTreeModel
import org.apache.spark.rdd.RDD

import org.apache.spark.sql.SparkSession
import org.apache.log4j.{Level, Logger}
```

1.  创建 Spark 的配置和 Spark 会话，以便我们可以访问集群：

```scala
Logger.getLogger("org").setLevel(Level.*ERROR*)

 val spark = SparkSession
 .builder.master("local[*]")
 .appName("MyDecisionTreeRegression")
 .config("spark.sql.warehouse.dir", ".")
 .getOrCreate()
```

1.  我们读取原始的原始数据文件：

```scala
val rawData = spark.sparkContext.textFile("../data/sparkml2/chapter10/breast-cancer-wisconsin.data")
```

1.  我们预处理数据集（详细信息请参见前面的代码）：

```scala
val data = rawData.map(_.trim)
 .filter(text => !(text.isEmpty || text.startsWith("#") || text.indexOf("?") > -1))
 .map { line =>
 val values = line.split(',').map(_.toDouble)
 val slicedValues = values.slice(1, values.size)
 val featureVector = Vectors.dense(slicedValues.init)
 val label = values.last / 2 -1
 LabeledPoint(label, featureVector)
 }
```

1.  我们验证原始数据计数并处理数据计数：

```scala
println(rawData.count())
println(data.count())
```

在控制台上你会看到以下内容：

```scala
699
683
```

1.  我们将整个数据集分为训练数据（70%）和测试数据（30%）集：

```scala
val splits = data.randomSplit(Array(0.7, 0.3))
val (trainingData, testData) = (splits(0), splits(1))
```

1.  我们定义一个度量计算函数，该函数利用 Spark 的`RegressionMetrics`：

```scala
def getMetrics(model: DecisionTreeModel, data: RDD[LabeledPoint]): RegressionMetrics = {
 val predictionsAndLabels = data.map(example =>
 (model.predict(example.features), example.label)
 )
 new RegressionMetrics(predictionsAndLabels)
 }
```

1.  我们设置以下参数：

```scala
val categoricalFeaturesInfo = Map[Int, Int]()
val impurity = "variance" val maxDepth = 5
val maxBins = 32
```

1.  我们首先评估基尼不纯度：

```scala
val model = DecisionTree.trainRegressor(trainingData, categoricalFeaturesInfo, impurity, maxDepth, maxBins)
val metrics = getMetrics(model, testData)
println("Test Mean Squared Error = " + metrics.meanSquaredError)
println("My regression tree model:\n" + model.toDebugString)

```

从控制台输出：

```scala
Test Mean Squared Error = 0.037363769271664016
My regression tree model:
DecisionTreeModel regressor of depth 5 with 37 nodes
If (feature 1 <= 3.0)
   If (feature 5 <= 3.0)
    If (feature 0 <= 6.0)
     If (feature 7 <= 3.0)
      Predict: 0.0
     Else (feature 7 > 3.0)
      If (feature 0 <= 4.0)
       Predict: 0.0
      Else (feature 0 > 4.0)
       Predict: 1.0
    Else (feature 0 > 6.0)
     If (feature 2 <= 2.0)
      Predict: 0.0
     Else (feature 2 > 2.0)
      If (feature 4 <= 2.0)
       Predict: 0.0
      Else (feature 4 > 2.0)
       Predict: 1.0
   Else (feature 5 > 3.0)
    If (feature 1 <= 1.0)
     If (feature 0 <= 5.0)
      Predict: 0.0
     Else (feature 0 > 5.0)
      Predict: 1.0
    Else (feature 1 > 1.0)
     If (feature 0 <= 6.0)
      If (feature 7 <= 4.0)
       Predict: 0.875
      Else (feature 7 > 4.0)
       Predict: 0.3333333333333333
     Else (feature 0 > 6.0)
      Predict: 1.0
  Else (feature 1 > 3.0)
   If (feature 1 <= 4.0)
    If (feature 4 <= 6.0)
     If (feature 5 <= 7.0)
      If (feature 0 <= 8.0)
       Predict: 0.3333333333333333
      Else (feature 0 > 8.0)
       Predict: 1.0
     Else (feature 5 > 7.0)
      Predict: 1.0
    Else (feature 4 > 6.0)
     Predict: 0.0
   Else (feature 1 > 4.0)
    If (feature 3 <= 1.0)
     If (feature 0 <= 6.0)
      If (feature 0 <= 5.0)
       Predict: 1.0
      Else (feature 0 > 5.0)
       Predict: 0.0
     Else (feature 0 > 6.0)
      Predict: 1.0
    Else (feature 3 > 1.0)
     Predict: 1.0
```

1.  然后通过停止 Spark 会话来关闭程序：

```scala
spark.stop()
```

# 工作原理...

我们使用相同的数据集，但这次我们使用决策树来解决数据的回归问题。值得注意的是创建一个度量计算函数，该函数利用 Spark 的`RegressionMetrics()`：

```scala
def getMetrics(model: DecisionTreeModel, data: RDD[LabeledPoint]): RegressionMetrics = {
 val predictionsAndLabels = data.map(example =>
 (model.predict(example.features), example.label)
 )
 new RegressionMetrics(predictionsAndLabels)
 }
```

然后我们继续使用`DecisionTree.trainRegressor()`来执行实际的回归，并获得不纯度测量（GINI）。然后我们继续输出实际的回归，这是一系列决策节点/分支和用于在给定分支上做出决策的值：

```scala
If (feature 0 <= 4.0)
       Predict: 0.0
      Else (feature 0 > 4.0)
       Predict: 1.0
    Else (feature 0 > 6.0)
     If (feature 2 <= 2.0)
      Predict: 0.0
     Else (feature 2 > 2.0)
      If (feature 4 <= 2.0)
........
........
.......
```

# 另请参阅

+   构造函数的文档可以在以下网址找到：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.DecisionTree`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.DecisionTree) 和 [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.DecisionTreeModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.DecisionTreeModel)

+   Spark Matrix Evaluator 的文档可以在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.RegressionMetrics`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.RegressionMetrics)找到。

# 在 Spark 2.0 中使用随机森林树构建分类系统

在这个示例中，我们将探讨 Spark 中随机森林的实现。我们将使用随机森林技术来解决离散分类问题。由于 Spark 利用并行性（同时生长许多树），我们发现随机森林的实现非常快。我们也不需要太担心超参数，技术上我们只需设置树的数量。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序将驻留的包位置：

```scala
package spark.ml.cookbook.chapter10
```

1.  导入 Spark 上下文所需的包，以便访问集群和`Log4j.Logger`以减少 Spark 产生的输出量：

```scala
import org.apache.spark.mllib.evaluation.MulticlassMetrics
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.mllib.tree.model.RandomForestModel
import org.apache.spark.rdd.RDD
import org.apache.spark.mllib.tree.RandomForest

import org.apache.spark.sql.SparkSession
import org.apache.log4j.{Level, Logger}

```

1.  创建 Spark 的配置和 Spark 会话，以便我们可以访问集群：

```scala
Logger.getLogger("org").setLevel(Level.*ERROR*)

 val spark = SparkSession
 .builder.master("local[*]")
 .appName("MyRandomForestClassification")
 .config("spark.sql.warehouse.dir", ".")
 .getOrCreate()
```

1.  我们读取原始原始数据文件：

```scala
val rawData = spark.sparkContext.textFile("../data/sparkml2/chapter10/breast-cancer-wisconsin.data")
```

1.  我们对数据集进行预处理（有关详细信息，请参见前面的部分）：

```scala
val data = rawData.map(_.trim)
 .filter(text => !(text.isEmpty || text.startsWith("#") || text.indexOf("?") > -1))
 .map { line =>
 val values = line.split(',').map(_.toDouble)
 val slicedValues = values.slice(1, values.size)
 val featureVector = Vectors.*dense*(slicedValues.init)
 val label = values.last / 2 -1
 LabeledPoint(label, featureVector)
 }
```

1.  我们验证原始数据计数并处理数据计数：

```scala
println("Training Data count:"+trainingData.count())
println("Test Data Count:"+testData.count())
```

您将在控制台中看到以下内容：

```scala
Training Data count: 501 
Test Data Count: 182
```

1.  我们将整个数据集随机分为训练数据（70%）和测试数据（30%）：

```scala
val splits = data.randomSplit(Array(0.7, 0.3))
val (trainingData, testData) = (splits(0), splits(1))
```

1.  我们定义了一个度量计算函数，它利用了 Spark 的`MulticlassMetrics`：

```scala
def getMetrics(model: RandomForestModel, data: RDD[LabeledPoint]): MulticlassMetrics = {
 val predictionsAndLabels = data.map(example =>
 (model.predict(example.features), example.label)
 )
 new MulticlassMetrics(predictionsAndLabels)
 }
```

此函数将读取模型和测试数据集，并创建包含先前提到的混淆矩阵的度量。它将包含模型准确性，这是分类模型的指标之一。

1.  我们定义了一个评估函数，该函数可以接受一些可调参数，用于随机森林模型，并对数据集进行训练：

```scala
def evaluate(
 trainingData: RDD[LabeledPoint],
 testData: RDD[LabeledPoint],
 numClasses: Int,
 categoricalFeaturesInfo: Map[Int,Int],
 numTrees: Int,
 featureSubsetStrategy: String,
 impurity: String,
 maxDepth: Int,
 maxBins:Int
 ) :Unit = {
val model = RandomForest.*trainClassifier*(trainingData, numClasses, categoricalFeaturesInfo, numTrees, featureSubsetStrategy,impurity, maxDepth, maxBins)
val metrics = *getMetrics*(model, testData)
println("Using Impurity :"+ impurity)
println("Confusion Matrix :")
println(metrics.confusionMatrix)
println("Model Accuracy: "+metrics.*precision*)
println("Model Error: "+ (1-metrics.*precision*))
 }

```

评估函数将读取几个参数，包括不纯度类型（模型的基尼或熵）并生成用于评估的度量。

1.  我们设置了以下参数：

```scala
val numClasses = 2
 val categoricalFeaturesInfo = *Map*[Int, Int]()
 val numTrees = 3 *// Use more in practice.* val featureSubsetStrategy = "auto" *// Let the algorithm choose.

* val maxDepth = 4
 val maxBins = 32
```

1.  我们首先评估基尼不纯度：

```scala
evaluate(trainingData, testData, numClasses,categoricalFeaturesInfo,numTrees,
featureSubsetStrategy, "gini", maxDepth, maxBins)
```

从控制台输出：

```scala
Using Impurity :gini
Confusion Matrix :
118.0 1.0
4.0 59.0
Model Accuracy: 0.9725274725274725
Model Error: 0.027472527472527486
To interpret the above Confusion metrics, Accuracy is equal to (118+ 59)/ 182 all test cases, and error is equal to 1 -accuracy
```

1.  我们评估熵不纯度：

```scala
evaluate(trainingData, testData, numClasses, categoricalFeaturesInfo,
 "entropy", maxDepth, maxBins)
```

从控制台输出：

```scala
Using Impurity :entropy
Confusion Matrix :
115.0  4.0   
0.0    63.0
Model Accuracy: 0.978021978021978
Model Error: 0.02197802197802201             
To interpret the above Confusion metrics, Accuracy is equal to (115+ 63)/ 182 all test cases, and error is equal to 1 -accuracy
```

1.  然后通过停止 Spark 会话来关闭程序：

```scala
spark.stop()
```

# 它是如何工作的...

数据与前一个示例中的数据相同，但我们使用随机森林和多指标 API 来解决分类问题：

+   `RandomForest.trainClassifier()`

+   `MulticlassMetrics()`

我们有很多选项可以调整随机森林树，以获得分类复杂表面的正确边缘。这里列出了一些参数：

```scala
 val numClasses = 2
 val categoricalFeaturesInfo = *Map*[Int, Int]()
 val numTrees = 3 // Use more in practice. val featureSubsetStrategy = "auto" // Let the algorithm choose. val maxDepth = 4
 val maxBins = 32
```

值得注意的是这个示例中的混淆矩阵。混淆矩阵是通过`MulticlassMetrics()` API 调用获得的。要解释前面的混淆度量，准确度等于（118+ 59）/ 182，对于所有测试案例，错误等于 1-准确度：

```scala
Confusion Matrix :
118.0 1.0
4.0 59.0
Model Accuracy: 0.9725274725274725
Model Error: 0.027472527472527486
```

# 另请参阅

+   构造函数的文档可以在以下 URL 中找到 [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.RandomForest$`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.RandomForest%24) [和 ](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.RandomForest%24)[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.RandomForestModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.RandomForestModel)

+   Spark Matrix Evaluator 的文档可以在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.MulticlassMetrics`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.MulticlassMetrics)找到。

# 在 Spark 2.0 中使用随机森林树解决回归问题

这与之前的步骤类似，但我们使用随机森林树来解决回归问题（连续）。以下参数用于指导算法应用回归而不是分类。我们再次将类的数量限制为两个：

```scala
val impurity = "variance" // USE variance for regression
```

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

```scala
package spark.ml.cookbook.chapter10
```

1.  从 Spark 中导入必要的包：

```scala
import org.apache.spark.mllib.evaluation.RegressionMetrics
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.mllib.tree.model.RandomForestModel
import org.apache.spark.rdd.RDD
import org.apache.spark.mllib.tree.RandomForest

import org.apache.spark.sql.SparkSession
import org.apache.log4j.{Level, Logger}

```

1.  创建 Spark 的配置和 Spark 会话：

```scala
Logger.getLogger("org").setLevel(Level.*ERROR*)

val spark = SparkSession
.builder.master("local[*]")
.appName("MyRandomForestRegression")
.config("spark.sql.warehouse.dir", ".")
.getOrCreate()
```

1.  我们读取原始的原始数据文件：

```scala
val rawData = spark.sparkContext.textFile("../data/sparkml2/chapter10/breast-cancer-wisconsin.data")
```

1.  我们预处理数据集（详情请参阅前面的部分）：

```scala
val data = rawData.map(_.trim)
 .filter(text => !(text.isEmpty || text.startsWith("#") || text.indexOf("?") > -1))
 .map { line =>
 val values = line.split(',').map(_.toDouble)
 val slicedValues = values.slice(1, values.size)
 val featureVector = Vectors.dense(slicedValues.init)
 val label = values.last / 2 -1
 LabeledPoint(label, featureVector)
 }
```

1.  我们随机将整个数据集分为训练数据（70%）和测试数据（30%）：

```scala
val splits = data.randomSplit(Array(0.7, 0.3))
val (trainingData, testData) = (splits(0), splits(1))
println("Training Data count:"+trainingData.count())
println("Test Data Count:"+testData.count())
```

您将在控制台上看到以下内容：

```scala
Training Data count:473
Test Data Count:210
```

1.  我们定义一个度量计算函数，它利用 Spark 的`RegressionMetrics`：

```scala
def getMetrics(model: RandomForestModel, data: RDD[LabeledPoint]): RegressionMetrics = {
val predictionsAndLabels = data.map(example =>
 (model.predict(example.features), example.label)
 )
new RegressionMetrics(predictionsAndLabels)
 }

```

1.  我们设置以下参数：

```scala
val numClasses = 2
val categoricalFeaturesInfo = Map[Int, Int]()
val numTrees = 3 // Use more in practice.val featureSubsetStrategy = "auto" // Let the algorithm choose.val impurity = "variance"
 val maxDepth = 4
val maxBins = 32
val model = RandomForest.trainRegressor(trainingData, categoricalFeaturesInfo,
numTrees, featureSubsetStrategy, impurity, maxDepth, maxBins)
val metrics = getMetrics(model, testData)
println("Test Mean Squared Error = " + metrics.meanSquaredError)
println("My Random Forest model:\n" + model.toDebugString)
```

从控制台输出：

```scala
Test Mean Squared Error = 0.028681825568809653
My Random Forest model:
TreeEnsembleModel regressor with 3 trees
  Tree 0:
    If (feature 2 <= 3.0)
     If (feature 7 <= 3.0)
      If (feature 4 <= 5.0)
       If (feature 0 <= 8.0)
        Predict: 0.006825938566552901
       Else (feature 0 > 8.0)
        Predict: 1.0
      Else (feature 4 > 5.0)
       Predict: 1.0
     Else (feature 7 > 3.0)
      If (feature 6 <= 3.0)
       If (feature 0 <= 6.0)
        Predict: 0.0
       Else (feature 0 > 6.0)
        Predict: 1.0
      Else (feature 6 > 3.0)
       Predict: 1.0
    Else (feature 2 > 3.0)
     If (feature 5 <= 3.0)
      If (feature 4 <= 3.0)
       If (feature 7 <= 3.0)
        Predict: 0.1
       Else (feature 7 > 3.0)
        Predict: 1.0
      Else (feature 4 > 3.0)
       If (feature 3 <= 3.0)
        Predict: 0.8571428571428571
       Else (feature 3 > 3.0)
        Predict: 1.0
     Else (feature 5 > 3.0)
      If (feature 5 <= 5.0)
       If (feature 1 <= 4.0)
        Predict: 0.75
       Else (feature 1 > 4.0)
        Predict: 1.0
      Else (feature 5 > 5.0)
       Predict: 1.0
  Tree 1:
...
```

1.  然后通过停止 Spark 会话来关闭程序：

```scala
spark.stop()
```

# 工作原理...

我们使用数据集和随机森林树来解决数据的回归问题。解析和分离的机制仍然相同，但我们使用以下两个 API 来进行树回归和评估结果：

+   `RandomForest.trainRegressor()`

+   `RegressionMetrics()`

值得注意的是定义`getMetrics()`函数以利用 Spark 中的`RegressionMetrics()`功能：

```scala
def getMetrics(model: RandomForestModel, data: RDD[LabeledPoint]): RegressionMetrics = {
val predictionsAndLabels = data.map(example =>
 (model.predict(example.features), example.label)
 )
new RegressionMetrics(predictionsAndLabels)
}

```

我们还将杂质值设置为“方差”，以便我们可以使用方差来测量错误：

```scala
val impurity = "variance" // use variance for regression
```

# 另请参阅

+   构造函数的文档可以在以下网址找到：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.RandomForest$`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.RandomForest%24) 和 [`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.RandomForestModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.RandomForestModel)

+   Spark 矩阵评估器的文档：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.RegressionMetrics`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.RegressionMetrics)

# 在 Spark 2.0 中构建使用梯度提升树（GBT）的分类系统

在这个步骤中，我们将探讨 Spark 中梯度提升树（GBT）分类的实现。GBT 在决定最终结果之前需要更多的超参数和多次尝试。必须记住，如果使用 GBT，完全可以种植较短的树。

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

```scala
package spark.ml.cookbook.chapter10
```

1.  为 Spark 上下文导入必要的包：

```scala
import org.apache.spark.mllib.evaluation.MulticlassMetrics
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.mllib.tree.model.GradientBoostedTreesModel
import org.apache.spark.rdd.RDD
import org.apache.spark.mllib.tree.GradientBoostedTrees
import org.apache.spark.mllib.tree.configuration.BoostingStrategy
import org.apache.spark.sql.SparkSession
import org.apache.log4j.{Level, Logger}

```

1.  创建 Spark 的配置和 Spark 会话，以便我们可以访问集群：

```scala
Logger.getLogger("org").setLevel(Level.*ERROR*)

val spark = SparkSession
   .builder.master("local[*]")
   .appName("MyGradientBoostedTreesClassification")
   .config("spark.sql.warehouse.dir", ".")
   .getOrCreate()
```

1.  我们读取原始的原始数据文件：

```scala
val rawData = spark.sparkContext.textFile("../data/sparkml2/chapter10/breast-cancer-wisconsin.data")
```

1.  我们预处理数据集（详情请参阅前面的部分）：

```scala
val data = rawData.map(_.trim)
 .filter(text => !(text.isEmpty || text.startsWith("#") || text.indexOf("?") > -1))
 .map { line =>
 val values = line.split(',').map(_.toDouble)
 val slicedValues = values.slice(1, values.size)
 val featureVector = Vectors.*dense*(slicedValues.init)
 val label = values.last / 2 -1
 LabeledPoint(label, featureVector)
 }
```

1.  我们随机将整个数据集分为训练数据（70%）和测试数据（30%）。请注意，随机分割将生成大约 211 个测试数据集。这大约但并非完全是数据集的 30%：

```scala
val splits = data.randomSplit(Array(0.7, 0.3))
val (trainingData, testData) = (splits(0), splits(1))
println("Training Data count:"+trainingData.count())
println("Test Data Count:"+testData.count())
```

您将在控制台上看到：

```scala
Training Data count:491
Test Data Count:192
```

1.  我们定义一个度量计算函数，它利用 Spark 的`MulticlassMetrics`：

```scala
def getMetrics(model: GradientBoostedTreesModel, data: RDD[LabeledPoint]): MulticlassMetrics = {
 val predictionsAndLabels = data.map(example =>
 (model.predict(example.features), example.label)
 )
 new MulticlassMetrics(predictionsAndLabels)
 }
```

1.  我们定义一个评估函数，该函数可以接受一些可调参数用于梯度提升树模型，并对数据集进行训练：

```scala
def evaluate(
 trainingData: RDD[LabeledPoint],
 testData: RDD[LabeledPoint],
 boostingStrategy : BoostingStrategy
 ) :Unit = {

 val model = GradientBoostedTrees.*train*(trainingData, boostingStrategy)

 val metrics = getMetrics(model, testData)
 println("Confusion Matrix :")
 println(metrics.confusionMatrix)
 println("Model Accuracy: "+metrics.*precision*)
 println("Model Error: "+ (1-metrics.*precision*))
 }
```

1.  我们设置以下参数：

```scala
val algo = "Classification" val numIterations = 3
val numClasses = 2
val maxDepth = 5
val maxBins = 32
val categoricalFeatureInfo = *Map*[Int,Int]()
val boostingStrategy = BoostingStrategy.*defaultParams*(algo)
boostingStrategy.setNumIterations(numIterations)
boostingStrategy.treeStrategy.setNumClasses(numClasses) 
boostingStrategy.treeStrategy.setMaxDepth(maxDepth)
boostingStrategy.treeStrategy.setMaxBins(maxBins) boostingStrategy.treeStrategy.categoricalFeaturesInfo = categoricalFeatureInfo
```

1.  我们使用前面的策略参数评估模型：

```scala
evaluate(trainingData, testData, boostingStrategy)
```

从控制台输出：

```scala
Confusion Matrix :
124.0 2.0
2.0 64.0
Model Accuracy: 0.9791666666666666
Model Error: 0.02083333333333337

To interpret the above Confusion metrics, Accuracy is equal to (124+ 64)/ 192 all test cases, and error is equal to 1 -accuracy
```

1.  然后通过停止 Spark 会话来关闭程序：

```scala
spark.stop()
```

# 工作原理...

我们跳过数据摄取和解析，因为这与之前的步骤类似，但不同的是我们如何设置参数，特别是将“classification”作为参数传递给`BoostingStrategy.defaultParams()`：

```scala
val algo = "Classification"
 val numIterations = 3
 val numClasses = 2
 val maxDepth = 5
 val maxBins = 32
 val categoricalFeatureInfo = Map[Int,Int]()

 val boostingStrategy = BoostingStrategy.*defaultParams*(algo)
```

我们还使用`evaluate()`函数通过查看不纯度和混淆矩阵来评估参数：

```scala
evaluate(trainingData, testData, boostingStrategy)
```

```scala
Confusion Matrix :
124.0 2.0
2.0 64.0
Model Accuracy: 0.9791666666666666
Model Error: 0.02083333333333337
```

# 还有更多...

重要的是要记住 GBT 是一个多代算法，我们一次生长一棵树，从错误中学习，然后以迭代的方式构建下一棵树。

# 另请参阅

+   构造函数的文档可以在以下网址找到：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.GradientBoostedTrees`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.GradientBoostedTrees)、[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.configuration.BoostingStrategy`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.configuration.BoostingStrategy)和[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.GradientBoostedTreesModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.GradientBoostedTreesModel)

+   Spark 矩阵评估器的文档可以在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.MulticlassMetrics`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.MulticlassMetrics)找到

# 在 Spark 2.0 中使用 Gradient Boosted Trees（GBT）解决回归问题

这个示例与 GBT 分类问题类似，但我们将使用回归。我们将使用`BoostingStrategy.defaultParams()`来指示 GBT 使用回归：

```scala
algo = "Regression" val boostingStrategy = BoostingStrategy.defaultParams(algo)
```

# 如何做...

1.  在 IntelliJ 或您选择的 IDE 中启动一个新项目。确保包含必要的 JAR 文件。

1.  设置程序所在的包位置：

``package spark.ml.cookbook.chapter10``。

1.  导入 Spark 上下文所需的包：

```scala
import org.apache.spark.mllib.evaluation.RegressionMetrics
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.mllib.tree.model.GradientBoostedTreesModel
import org.apache.spark.rdd.RDD
import org.apache.spark.mllib.tree.GradientBoostedTrees
import org.apache.spark.mllib.tree.configuration.BoostingStrategy

import org.apache.spark.sql.SparkSession
import org.apache.log4j.{Level, Logger}

```

1.  创建 Spark 的配置和 Spark 会话：

```scala
Logger.getLogger("org").setLevel(Level.ERROR)

val spark = SparkSession
   .builder   .master("local[*]")
   .appName("MyGradientBoostedTreesRegression")
   .config("spark.sql.warehouse.dir", ".")
   .getOrCreate()
```

1.  我们在原始的原始数据文件中阅读：

```scala
val rawData = spark.sparkContext.textFile("../data/sparkml2/chapter10/breast-cancer-wisconsin.data")
```

1.  我们对数据集进行预处理（有关详细信息，请参见前面的会话）：

```scala
val data = rawData.map(_.trim)
 .filter(text => !(text.isEmpty || text.startsWith("#") || text.indexOf("?") > -1))
 .map { line =>
 val values = line.split(',').map(_.toDouble)
 val slicedValues = values.slice(1, values.size)
 val featureVector = Vectors.*dense*(slicedValues.init)
 val label = values.last / 2 -1
 *LabeledPoint*(label, featureVector)
 }
```

1.  我们将整个数据集随机分为训练数据（70%）和测试数据（30%）：

```scala
val splits = data.randomSplit(Array(0.7, 0.3))
val (trainingData, testData) = (splits(0), splits(1))
println("Training Data count:"+trainingData.count())
println("Test Data Count:"+testData.count())
```

您将在控制台中看到以下内容：

```scala
Training Data count:469
Test Data Count:214
```

1.  我们定义一个度量计算函数，它利用 Spark 的`RegressionMetrics`：

```scala
def getMetrics(model: GradientBoostedTreesModel, data: RDD[LabeledPoint]): RegressionMetrics = {
 val predictionsAndLabels = data.map(example =>
 (model.predict(example.features), example.label)
 )
 new RegressionMetrics(predictionsAndLabels)
 }
```

1.  我们设置以下参数：

```scala
val algo = "Regression" val numIterations = 3
val maxDepth = 5
val maxBins = 32
val categoricalFeatureInfo = Map[Int,Int]()
val boostingStrategy = BoostingStrategy.defaultParams(algo)
boostingStrategy.setNumIterations(numIterations)
boostingStrategy.treeStrategy.setMaxDepth(maxDepth) 
boostingStrategy.treeStrategy.setMaxBins(maxBins) boostingStrategy.treeStrategy.categoricalFeaturesInfo = categoricalFeatureInfo
```

1.  我们使用前面的策略参数评估模型：

```scala
val model = GradientBoostedTrees.train(trainingData, boostingStrategy)
val metrics = getMetrics(model, testData)

 println("Test Mean Squared Error = " + metrics.meanSquaredError)
 println("My regression GBT model:\n" + model.toDebugString)
```

从控制台输出：

```scala
Test Mean Squared Error = 0.05370763765769276
My regression GBT model:
TreeEnsembleModel regressor with 3 trees
Tree 0:
If (feature 1 <= 2.0)
If (feature 0 <= 6.0)
If (feature 5 <= 5.0)
If (feature 5 <= 4.0)
Predict: 0.0
Else (feature 5 > 4.0)
...
```

1.  然后我们通过停止 Spark 会话来关闭程序：

```scala
spark.stop()
```

# 它是如何工作的...

我们使用与上一个示例相同的 GBT 树，但我们调整了参数，以指示 GBT API 执行回归而不是分类。值得注意的是将以下代码与上一个示例进行比较。 "回归"用于指示 GBT 对数据执行回归：

```scala
 val algo = "Regression"
 val numIterations = 3
 val maxDepth = 5
 val maxBins = 32
 val categoricalFeatureInfo = *Map*[Int,Int]()

 val boostingStrategy = BoostingStrategy.*defaultParams*(algo)
```

我们使用以下 API 来训练和评估模型的指标：

+   `GradientBoostedTrees.train()`

+   `getMetrics()`

以下代码片段显示了检查模型所需的典型输出：

```scala
Test Mean Squared Error = 0.05370763765769276
My regression GBT model:
Tree 0:
If (feature 1 <= 2.0)
If (feature 0 <= 6.0)
If (feature 5 <= 5.0)
If (feature 5 <= 4.0)
Predict: 0.0
Else (feature 5 > 4.0)
...
```

# 还有更多...

GBT 可以像随机森林一样捕捉非线性和变量交互，并且可以处理多类标签。

# 另请参阅

+   构造函数的文档可以在以下网址找到：[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.GradientBoostedTrees`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.GradientBoostedTrees)、[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.configuration.BoostingStrategy`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.configuration.BoostingStrategy)和[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.GradientBoostedTreesModel`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.tree.model.GradientBoostedTreesModel)

+   Spark Matrix Evaluator 的文档可以在[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.RegressionMetrics`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.evaluation.RegressionMetrics)找到。
