# Spark 大规模机器学习（二）

> 原文：[`zh.annas-archive.org/md5/7A35D303E4132E910DFC5ADB5679B82A`](https://zh.annas-archive.org/md5/7A35D303E4132E910DFC5ADB5679B82A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：通过特征工程提取知识

应该使用哪些特征来创建预测模型不仅是一个重要问题，而且可能是一个需要深入了解问题领域才能回答的难题。可以自动选择数据中对某人正在处理的问题最有用或最相关的特征。考虑到这些问题，本章详细介绍了特征工程，解释了为什么要应用它以及一些特征工程的最佳实践。

除此之外，我们还将提供特征提取、转换和选择的理论描述和示例，这些示例应用于大规模机器学习技术，使用 Spark MLlib 和 Spark ML API。此外，本章还涵盖了高级特征工程的基本思想（也称为极端特征工程）。

请注意，在继续本章之前，您需要在计算机上安装 R 和 RStudio，因为将使用 R 来展示探索性数据分析的示例。

简而言之，本章将涵盖以下主题：

+   特征工程的最新技术

+   特征工程的最佳实践

+   使用 Spark 进行特征工程

+   高级特征工程

# 特征工程的最新技术

尽管特征工程是一个非正式的话题，但它被认为是应用机器学习中的一个重要部分。安德鲁·吴（Andrew Ng）是机器学习领域的领先科学家之一，他在他的书《通过大脑模拟的机器学习和人工智能》中定义了特征工程这个术语（另请参见：[`en.wikipedia.org/wiki/Andrew_Nghttps://en.wikipedia.org/wiki/Andrew_Ng`](https://en.wikipedia.org/wiki/Andrew_Nghttps://en.wikipedia.org/wiki/Andrew_Ng)）。如下所示：

> *提出特征是困难的，耗时的，需要专业知识。应用机器学习基本上就是特征工程。*

基于前述定义，我们可以认为特征工程实际上是人类智慧，而不是人工智能。此外，我们将从其他角度解释特征工程是什么。特征工程还可以被定义为将原始数据转换为有用特征（通常称为特征向量）的过程。这些特征有助于更好地表示基本问题，最终用于预测模型；因此，预测建模可以应用于新数据类型，以获得高预测准确性。

或者，我们可以将特征工程定义为使用或重复使用某人对基本问题和可用数据的高级领域知识的软件工程过程，以创建使机器学习算法轻松工作的特征。

这就是我们如何定义特征工程的术语。如果您仔细阅读，您会发现这些定义中有四个依赖关系：

+   问题本身

+   你将使用的原始数据来找出有用的模式或特征

+   机器学习问题或类别的类型

+   您将使用的预测模型

现在基于这四个依赖关系，我们可以得出一个工作流程。首先，您必须了解您的问题本身，然后您必须了解您的数据以及它是否有序，如果没有，处理您的数据以找到某种模式或特征，以便您可以构建您的模型。

一旦您确定了特征，您需要知道您的问题属于哪些类别。换句话说，您必须能够根据特征确定它是分类、聚类还是回归问题。最后，您将使用诸如随机森林或**支持向量机**（**SVMs**）等著名方法在测试集或验证集上构建模型进行预测。

在本章中，你将看到并论证特征工程是一门处理不确定和常常无结构数据的艺术。也是真实的，有许多明确定义的程序可以应用于分类、聚类、回归模型，或者像 SVM 这样的方法，这些程序既有条理又可证明；然而，数据是一个变量，经常在不同时间具有各种特征。

## 特征提取与特征选择

你将会知道何时以及如何通过经验学徒的实践来决定应该遵循哪些程序。特征工程涉及的主要任务是：

+   **数据探索和特征提取**：这是揭示原始数据中隐藏宝藏的过程。一般来说，这个过程在消耗特征的算法中并不会有太大变化。然而，在这方面，对实际经验、业务领域和直觉的更好理解起着至关重要的作用。

+   **特征选择**：这是根据你所处理的机器学习问题决定选择哪些特征的过程。你可以使用不同的技术来选择特征；然而，它可能会因算法和使用特征而有所不同。

## 特征工程的重要性

当最终目标是从预测模型中获得最准确和可靠的结果时，你必须投入你所拥有的最好的东西。在这种情况下，最好的投资将是三个参数：时间和耐心，数据和可用性，以及最佳算法。然而，“如何从数据中获取最有价值的宝藏用于预测建模？”是特征工程的过程和实践以新兴方式解决的问题。

事实上，大多数机器学习算法的成功取决于你如何正确和智能地利用价值并呈现你的数据。通常认为，从你的数据中挖掘出的隐藏宝藏（即特征或模式）将直接刺激预测模型的结果。

因此，更好的特征（即你从数据集中提取和选择的内容）意味着更好的结果（即你将从模型中获得的结果）。然而，在你为你的机器学习模型概括之前，请记住一件事，你需要一个很好的特征，尽管具有描述数据固有结构的属性。

总之，更好的特征意味着三个优点：灵活性、调整和更好的结果：

+   **更好的特征（更好的灵活性）**：如果你成功地提取和选择了更好的特征，你肯定会获得更好的结果，即使你选择了一个非最佳或错误的模型。事实上，可以根据你拥有的原始数据的良好结构来选择或挑选最佳或最合适的模型。此外，良好的特征将使你能够最终使用更简单但高效、更快速、易于理解和易于维护的模型。

+   **更好的特征（更好的调整）**：正如我们已经提到的，如果你没有聪明地选择你的机器学习模型，或者如果你的特征不够好，你很可能会从 ML 模型中获得更糟糕的结果。然而，即使在构建模型过程中选择了一些错误的参数，如果你有一些经过良好设计的特征，你仍然可以期望从模型中获得更好的结果。此外，你不需要过多担心或者更加努力地选择最优模型和相关参数。原因很简单，那就是好的特征，你实际上已经很好地理解了问题，并准备使用更好地代表问题本身的所有数据。

+   **更好的特征（更好的结果）**：即使你把大部分精力投入到更好的特征选择上，你很可能会获得更好的结果。

我们还建议读者不要过分自信地只依赖特征。前面的陈述通常是正确的；然而，有时它们会误导。我们想进一步澄清前面的陈述。实际上，如果你从一个模型中获得了最佳的预测结果，实际上是由三个因素决定的：你选择的模型，你拥有的数据，以及你准备的特征。

因此，如果你有足够的时间和计算资源，总是尝试使用标准模型，因为通常简单并不意味着更好的准确性。尽管如此，更好的特征将在这三个因素中做出最大的贡献。你应该知道的一件事是，不幸的是，即使你掌握了许多实践经验和研究其他人在最新技术领域做得很好的特征工程，一些机器学习项目最终也会失败。

## 特征工程和数据探索

很多时候，对训练和测试样本进行智能选择，选择更好的特征会导致更好的解决方案。尽管在前一节中我们认为特征工程有两个任务：从原始数据中提取特征和特征选择。然而，特征工程没有明确或固定的路径。

相反，特征工程中的整个步骤很大程度上受到可用原始数据的指导。如果数据结构良好，你会感到幸运。然而，现实往往是原始数据来自多种格式的多源数据。因此，在进行特征提取和特征选择之前，探索这些数据非常重要。

### 提示

我们建议您使用直方图和箱线图来找出数据的偏度和峰度，并使用数据辅助技术（由 Abe Gong 介绍）对数据进行自举（参见：[`curiosity.com/paths/abe-gong-building-for-resilience-solid-2014-keynote-oreilly/#abe-gong-building-for-resilience-solid-2014-keynote-oreilly`](https://curiosity.com/paths/abe-gong-building-for-resilience-solid-2014-keynote-oreilly/#abe-gong-building-for-resilience-solid-2014-keynote-oreilly)）。

在应用特征工程之前，需要通过数据探索来回答和了解以下问题：

+   对于所有可用字段，总数据的百分比是存在还是不存在空值或缺失值？然后尝试处理这些缺失值，并在不丢失数据语义的情况下进行解释。

+   字段之间的相关性是多少？每个字段与预测变量的相关性是多少？它们取什么值（即，是分类还是非分类，是数值还是字母数字，等等）？

+   然后找出数据分布是否倾斜。你可以通过查看离群值或长尾（略微向右倾斜或正向倾斜，略微向左倾斜或负向倾斜，如*图 1*所示）来确定偏斜程度。现在确定离群值是否有助于预测。

+   之后，观察数据的峰度。更技术性地，检查你的峰度是否是 mesokurtic（小于但几乎等于 3），leptokurtic（大于 3），或者 platykurtic（小于 3）。请注意，任何一元正态分布的峰度被认为是 3。

+   现在尝试调整尾部并观察（预测是否变得更好？）当你去除长尾时会发生什么？

图 1：数据分布的偏斜（x 轴=数据，y 轴=密度）。

你可以使用简单的可视化工具，如密度图来做到这一点，如下例所示。

示例 1\. 假设您对健身步行感兴趣，并且在过去的四周（不包括周末）在体育场或乡村散步。您花费了以下时间（以分钟为单位完成 4 公里步行道）：15, 16, 18, 17.16, 16.5, 18.6, 19.0, 20.4, 20.6, 25.15, 27.27, 25.24, 21.05, 21.65, 20.92, 22.61, 23.71, 35, 39 和 50。现在让我们使用 R 计算和解释这些值的偏度和峰度。

### 提示

我们将展示如何在第十章中配置和使用 SparkR，*配置和使用外部库*并展示如何在 SparkR 上执行相同的代码。这样做的原因是一些绘图包，如`ggplot2`，在当前用于 SparkR 的版本中仍未直接实现。但是，`ggplot2`在 GitHub 上作为名为`ggplot2.SparkR`的组合包可用，可以使用以下命令安装和配置：

**`devtools::install_github("SKKU-SKT/ggplot2.SparkR")`**

然而，在配置过程中需要确保许多依赖项。因此，我们应该在以后的章节中解决这个问题。目前，我们假设您具有使用 R 的基本知识，如果您已经在计算机上安装和配置了 R，则请按照以下步骤操作。然而，将在第十章中逐步演示如何使用 RStudio 安装和配置 SparkR。

现在只需复制以下代码片段并尝试执行，以确保您有 Skewness 和 Kurtosis 的正确值。

安装`moments`包以计算 Skewness 和 Kurtosis：

```scala
install.packages("moments")  

```

使用`moments`包：

```scala
library(moments) 

```

在锻炼期间所花费的时间制作一个向量：

```scala
time_taken <- c (15, 16, 18, 17.16, 16.5, 18.6, 19.0, 20.4, 20.6, 25.15, 27.27, 25.24, 21.05, 21.65, 20.92, 22.61, 23.71, 35, 39, 50) 

```

将时间转换为 DataFrame：

```scala
df<- data.frame(time_taken) 

```

现在计算`skewness`：

```scala
skewness(df) 
[1]1.769592  

```

现在计算`kurtosis`：

```scala
> kurtosis(df) 
[1]5.650427  

```

**结果的解释**：您的锻炼时间的偏度为 1.769592，这意味着您的数据向右倾斜或呈正偏态。另一方面，峰度为 5.650427，这意味着数据的分布是尖峰的。现在检查异常值或尾部，请查看以下直方图。同样，为了简单起见，我们将使用 R 来绘制解释您的锻炼时间的密度图。

安装`ggplot2package`以绘制直方图：

```scala
install.packages("ggplot2") 

```

使用`moments`包：

```scala
library(ggplot2)

```

现在使用`ggplot2`的`qplot()`方法绘制直方图：

```scala
ggplot(df, aes(x = time_taken)) + stat_density(geom="line", col=  
"green", size = 1, bw = 4) + theme_bw() 

```

![特征工程和数据探索](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00144.jpeg)

图 2\. 锻炼时间的直方图（右偏）。

在数据（锻炼时间）的*图 2*中呈现的解释显示密度图向右倾斜，因此是尖峰。除了密度图，您还可以查看每个特征的箱线图。箱线图根据五数总结显示数据分布：**最小值**，**第一四分位数**，中位数，**第三四分位数**和**最大值**，如*图 3*所示，我们可以查找超出三（3）个**四分位距**（**IQR**）的异常值：

![特征工程和数据探索](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00120.jpeg)

图 3\. 锻炼时间的直方图（图表由箱线图提供，[`www.physics.csbsju.edu/stats/box2.htmlhttp://www.physics.csbsju.edu/stats/box2.html`](http://www.physics.csbsju.edu/stats/box2.htmlhttp://www.physics.csbsju.edu/stats/box2.html)）。

有时，对数据集进行自举也可以提供有关异常值的见解。如果数据量太大（即大数据），进行数据辅助、评估和预测也是有用的。数据辅助的想法是利用可用数据的一小部分来确定可以从数据集中得出什么见解，这也通常被称为“使用小数据来放大大数据的价值”。

这对大规模文本分析非常有用。例如，假设您有大量文本语料库，当然您可以使用其中的一小部分来测试各种情感分析模型，并选择在性能方面效果最好的模型（计算时间、内存使用、可扩展性和吞吐量）。

现在我们想要引起您对特征工程的其他方面的注意。此外，将连续变量转换为分类变量（具有一定特征组合）会产生更好的预测变量。

### 提示

在统计语言中，数据中的变量要么代表某些连续尺度上的测量，要么代表某些分类或离散特征。例如，运动员的体重、身高和年龄代表连续变量。另外，以时间为标准的生存或失败也被视为连续变量。另一方面，一个人的性别、职业或婚姻状况是分类或离散变量。从统计学上讲，某些变量可以以两种方式考虑。例如，电影观众对电影的评分可能被视为连续变量，也可以被视为具有 10 个类别的离散变量。时间序列数据或实时流数据通常用于连续变量直到某个时间点。

同时，考虑特征的平方或立方甚至使用非线性模型也可以提供更好的见解。此外，明智地考虑前向选择或后向选择，因为它们都需要大量计算。

最后，当特征数量变得显著大时，使用主成分分析（PCA）或奇异值分解（SVD）技术找到正确的特征组合是明智的决定。

## 特征提取 - 从数据中创建特征

特征提取是从您已有或将要收集的原始数据中自动构建新特征的方式。在特征提取过程中，通常通过将观察结果自动转换为可以在后续阶段建模的更小的集合来降低复杂原始数据的维度。投影方法，如 PCA 和无监督聚类方法，用于 TXT、CSV、TSV 或 RDB 格式的表格数据。然而，从另一种数据格式中提取特征非常复杂。特别是解析诸如 XML 和 SDRF 之类的许多数据格式，如果要提取的字段数量很大，这是一个繁琐的过程。

对于诸如图像数据之类的多媒体数据，最常见的技术类型包括线条或边缘检测或图像分割。然而，受限于领域和图像，视频和音频观察本身也适用于许多相同类型的数字信号处理（DSP）方法，其中通常模拟观察结果以数字格式存储。

特征提取的最大优点和关键在于，已经开发和可用的方法是自动的；因此，它们可以解决高维数据难以处理的问题。正如我们在第三章中所述，*通过了解数据来理解问题*，更多的数据探索和更好的特征提取最终会提高您的 ML 模型的性能（因为特征提取也涉及特征选择）。事实上，更多的数据最终将提供更多关于预测模型性能的见解。然而，数据必须是有用的，丢弃不需要的数据将浪费宝贵的时间；因此，在收集数据之前，请考虑这个陈述的意义。

特征提取过程涉及几个步骤，包括数据转换和特征转换。正如我们多次提到的，如果模型能够从原始数据中提取更好的特征，那么机器学习模型很可能会提供更好的结果。优化学习和泛化是好数据的关键特征。因此，通过一些数据处理步骤（如清洗、处理缺失值以及从文本文档到单词转换等中间转换），将数据以最佳格式组合起来的过程是通过一些数据处理步骤实现的。

帮助创建新特征作为预测变量的方法被称为特征转换，实际上是一组方法。特征转换基本上是为了降维。通常，当转换后的特征具有描述性维度时，与原始特征相比，可能会有更好的顺序。

因此，在构建机器学习模型时，可以从训练或测试样本中删除较少描述性的特征。特征转换中最常见的任务包括非负矩阵分解、主成分分析和使用缩放、分解和聚合操作的因子分析。

特征提取的例子包括图像中轮廓的提取、从文本中提取图表、从口语文本录音中提取音素等。特征提取涉及特征的转换，通常是不可逆的，因为在降维过程中最终会丢失一些信息。

## 特征选择 - 从数据中筛选特征

特征选择是为了为预测建模和分析准备训练数据集或验证数据集的过程。特征选择在大多数机器学习问题类型中都有实际意义，包括分类、聚类、降维、协同过滤、回归等。

因此，最终目标是从原始数据集的大量特征中选择一个子集。通常会应用降维算法，如**奇异值分解**（**SVD**）和**主成分分析**（**PCA**）。

特征选择技术的一个有趣的能力是，最小的特征集可以被应用来表示可用数据中的最大方差。换句话说，特征的最小子集足以有效地训练您的机器学习模型。

这个特征子集用于训练模型。特征选择技术有两种类型，即前向选择和后向选择。前向选择从最强的特征开始，不断添加更多特征。相反，后向选择从所有特征开始，删除最弱的特征。然而，这两种技术都需要大量计算。

### 特征选择的重要性

由于并非所有特征都同等重要；因此，您会发现一些特征比其他特征更重要，以使模型更准确。因此，这些属性可以被视为与问题无关。因此，您需要在准备训练和测试集之前删除这些特征。有时，相同的技术可能会应用于验证集。

与重要性并行的是，您总是会发现一些特征在其他特征的背景下是多余的。特征选择不仅涉及消除不相关或多余的特征，还有其他重要目的，可以增加模型的准确性，如下所述：

+   特征选择通过消除不相关、空/缺失和冗余特征来提高模型的预测准确性。它还处理高度相关的特征。

+   特征选择技术通过减少特征数量，使模型训练过程更加稳健和快速。

### 特征选择与降维

虽然通过使用特征选择技术可以在数据集中选择某些特征来减少特征数量。然后，使用子集来训练模型。然而，整个过程通常不能与术语**降维**互换使用。

事实上，特征选择方法用于从数据中提取子集，而不改变其基本属性。

另一方面，降维方法利用已经设计好的特征，可以通过减少变量的数量来将原始特征转换为相应的特征向量，以满足机器学习问题的特定考虑和要求。

因此，它实际上修改了基础数据，通过压缩数据从原始和嘈杂的特征中提取原始特征，但保持了原始结构，大多数情况下是不可逆的。降维方法的典型例子包括主成分分析（PCA）、典型相关分析（CCA）和奇异值分解（SVD）。

其他特征选择技术使用基于过滤器的、包装器方法和嵌入方法的特征选择，通过在监督上下文中评估每个特征与目标属性之间的相关性。这些方法应用一些统计量来为每个特征分配一个得分，也被称为过滤方法。

然后基于评分系统对特征进行排名，可以帮助消除特定特征。这些技术的例子包括信息增益、相关系数得分和卡方检验。作为特征选择过程的包装器方法的一个例子是递归特征消除算法。另一方面，最小绝对值收缩和选择算子（LASSO）、弹性网络和岭回归是特征选择的嵌入方法的典型例子，也被称为正则化方法。

Spark MLlib 的当前实现仅为`RowMatrix`类提供了对 SVD 和 PCA 的降维支持。另一方面，从原始数据收集到特征选择的一些典型步骤包括特征提取、特征转换和特征选择。

### 提示

建议感兴趣的读者阅读特征选择和降维的 API 文档：[`spark.apache.org/docs/latest/mllib-dimensionality-reduction.html`](http://spark.apache.org/docs/latest/mllib-dimensionality-reduction.html)。

# 特征工程的最佳实践

在这一部分，我们已经找出了在可用数据上进行特征工程时的一些良好做法。机器学习的一些最佳实践在第二章中进行了描述，*机器学习最佳实践*。然而，这些对于整体机器学习的最新技术来说还是太笼统了。当然，这些最佳实践在特征工程中也会很有用。此外，我们将在接下来的子章节中提供更多关于特征工程的具体示例。

## 理解数据

尽管术语“特征工程”更加技术化，但它是一门艺术，可以帮助你理解特征的来源。现在也出现了一些重要的问题，需要在理解数据之前回答：

+   这些特征的来源是什么？数据是实时的还是来自静态来源？

+   这些特征是连续的、离散的还是其他的？

+   特征的分布是什么样的？分布在很大程度上取决于正在考虑的示例子集是什么样的吗？

+   这些特征是否包含缺失值（即 NULL）？如果是，是否可能处理这些值？是否可能在当前、未来或即将到来的数据中消除它们？

+   是否存在重复或冗余条目？

+   我们是否应该进行手动特征创建，这样会证明有用吗？如果是，将这些特征纳入模型训练阶段会有多难？

+   是否有可以用作标准特征的特征？

了解前面的问题的答案很重要。因为数据来源可以帮助你更快地准备特征工程技术。你需要知道你的特征是离散的还是连续的，或者请求是否是实时响应。此外，你需要了解数据的分布以及它们的偏斜和峰度，以处理异常值。

你需要为缺失或空值做好准备，无论是将它们移除还是需要用替代值填充。此外，你需要首先移除重复的条目，这非常重要，因为重复的数据点可能会严重影响模型验证的结果，如果不适当地排除的话。最后，你需要了解你的机器学习问题本身，因为了解问题类型将帮助你相应地标记你的数据。

## 创新的特征提取方式

在提取和选择特征时要有创新性。在这里，我们总共提供了八条提示，这些提示将帮助你在机器学习应用开发过程中进行泛化。

### 提示

通过将现有数据字段汇总到更广泛的级别或类别来创建输入。

更具体地说，让我们给你一些例子。显然，你可以根据同事的职称将他们分类为战略或战术。例如，你可以将*副总裁或 VP*及以上职位的员工编码为战略，*总监*及以下职位的员工编码为战术。

将几个行业整合到更高级别的行业可能是这种分类的另一个例子。将石油和天然气公司与大宗商品公司整合在一起；黄金、白银或铂金作为贵金属公司；高科技巨头和电信行业作为*技术*；将营收超过 10 亿美元的公司定义为*大型*，而净资产 100 万美元以下的公司定义为*小型*。

### 提示

将数据分成单独的类别或区间。

更具体地说，让我们举几个例子。假设你正在对年收入在 5000 万美元到 10 亿美元以上的公司进行一些分析。因此，显然，你可以将收入分成一些连续的区间，比如 5000 万美元至 2 亿美元，2.01 亿美元至 5 亿美元，5.01 亿美元至 10 亿美元，以及 10 亿美元以上。现在，如何以一种可呈现的格式表示这些特征？很简单，尝试在公司落入收入区间时将值设为 1；否则，值为 0。现在从年收入字段中创建了四个新的数据字段，对吧？

### 提示

想出一种创新的方法将现有数据字段组合成新的字段。

更具体地说，让我们举几个例子。在第一个提示中，我们讨论了如何通过将现有字段合并成更广泛的字段来创建新的输入。现在，假设你想创建一个布尔标志，用于识别是否有人在拥有 10 年以上经验的情况下属于 VP 或更高级别。因此，在这种情况下，你实际上是通过将一个数据字段与另一个数据字段相乘、相除、相加或相减来创建新的字段。

### 提示

同时考虑手头的问题，并且要有创造性。

在之前的提示中，假设你已经创建了足够的箱子和字段或输入。现在，不要太担心一开始创建太多的变量。最好就让头脑风暴自然地进行特征选择步骤。

### 提示

不要愚蠢。

谨慎创建不必要的字段；因为从少量数据中创建太多特征可能会导致模型过拟合，从而产生虚假结果。当面对数据相关性时，记住相关性并不总是意味着因果关系。我们对这个常见观点的逻辑是，对观测数据进行建模只能告诉我们两个变量之间的关系，但不能告诉我们原因。

《奇迹经济学》一书中的研究文章（也可参见*史蒂文·D·莱维特，斯蒂芬·J·杜布纳，《奇迹经济学：一位流氓经济学家探索一切的隐藏面》，[`www.barnesandnoble.com/w/freakonomics-steven-d-levitt/1100550563http://www.barnesandnoble.com/w/freakonomics-steven-d-levitt/1100550563`](http://www.barnesandnoble.com/w/freakonomics-steven-d-levitt/1100550563http://www.barnesandnoble.com/w/freakonomics-steven-d-levitt/1100550563)）发现，公立学校的考试成绩数据表明，家中拥有更多书籍的孩子倾向于比家中书籍较少的孩子有更高的标准化考试成绩。

因此，在创建和构建不必要的特征之前要谨慎，这意味着不要愚蠢。

### 提示

不要过度设计。

在特征工程阶段，判断迭代花费几分钟还是半天的时间差异是微不足道的。因为特征工程阶段最有效的时间通常是在白板上度过的。因此，确保做得正确的最有效的方法是向你的数据提出正确的问题。如今，“大数据”这个词正在取代“特征工程”这个词。没有空间进行黑客攻击，所以不要过度设计：

![特征提取的创新方式](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00127.jpeg)

图 4：对假阳性和假阴性的真实解释。

### 提示

谨防假阳性和假阴性。

另一个重要的方面是比较假阴性和假阳性。根据问题，获得其中一个更高的准确性是重要的。例如，如果你在医疗领域进行研究，试图开发一个机器学习模型来预测疾病，那么获得假阳性可能比获得假阴性结果更好。因此，我们在这方面的建议是查看混淆矩阵，这将帮助你以一种可视化的方式查看分类器的预测结果。

行表示每个观察的真实类别，而列对应于模型本身预测的类别，如*图 4*所示。然而，*图 5*将提供更多的见解。请注意，对角线元素，也称为正确决策，用粗体标记。最后一列**Acc**表示每个关键的准确性如下：

![特征提取的创新方式](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00060.jpeg)

图 5：一个简单的混淆矩阵。

### 提示

在选择特征之前考虑精确度和召回率。

最后，还有两个重要的量需要考虑，即精确度和召回率。更技术性地说，您的分类器正确预测正值结果的频率称为召回率。相反，当您的分类器预测正值输出时，它实际上是真实的频率称为精确度。

预测这两个值确实非常困难。然而，仔细的特征选择将有助于在最后一个位置更好地获得这两个值。

您将在*Matthew Shardlow*撰写的研究论文中找到更多有趣和优秀的特征选择描述（也可参见 Matthew Shardlow，*特征选择技术分析*，[`studentnet.cs.manchester.ac.uk/pgt/COMP61011/goodProjects/Shardlow.pdf`](https://studentnet.cs.manchester.ac.uk/pgt/COMP61011/goodProjects/Shardlow.pdf)）。现在让我们在下一节中探索 Spark 的特征工程功能。

# 使用 Spark 进行特征工程

基于大数据的机器学习是一个深度和广泛的领域，它需要一个新的配方，其中的成分将是特征工程和对数据模型的稳定优化。优化后的模型可以称为大模型（也可参见*S. Martinez*，*A. Chen*，*G. I. Webb*和*N. A. Zaidi*，*Bayesian network classifiers 的可扩展学习*，已被接受发表在*Journal of Machine Learning Research*中），它可以从大数据中学习，并且是突破的关键，而不仅仅是大数据。

大模型还表示，您从多样化和复杂的大数据中得到的结果将具有低偏差（请参见*D. Brain 和 G. I. Webb*，*分类学习中对小数据集需要低偏差算法*，*在 PKDD*，*pp. 62, 73, 2002*），并且可以使用多类机器学习算法进行外部核心学习（请参见外部核心学习定义，[`en.wikipedia.org/wiki/Out-of-core_algorithm`](https://en.wikipedia.org/wiki/Out-of-core_algorithm)和[`en.wikipedia.org/wiki/Out-of-core_algorithm`](https://en.wikipedia.org/wiki/Out-of-core_algorithm)）并且具有最小的调整参数。

Spark 为我们引入了这个大模型，以便我们能够规模化部署我们的机器学习应用。在本节中，我们将描述 Spark 如何开发机器学习库和 Spark 核心来有效处理大规模数据集和不同数据结构的高级特征工程功能。

正如我们已经提到的，Spark 的机器学习模块包含两个 API，包括`spark.mllib`和`spark.ml`。MLlib 包建立在 RDD 之上，而 ML 包建立在 DataFrame 和 Dataset 之上，为构建 ML 流水线提供了更高级别的 API。接下来的几节将向您展示 ML 的细节（MLlib 将在第五章中讨论，*通过示例进行监督和无监督学习*），其中包括一个实际的机器学习问题。

## 机器学习流水线-概述

Spark 的 ML 包提供了一组统一的高级 API，帮助创建一个实用的机器学习流水线。这个流水线的主要概念是将多个机器学习算法组合在一起，形成一个完整的工作流程。在机器学习领域，经常会运行一系列算法来处理和学习可用的数据。

例如，假设您想要开发一个文本分析机器学习应用程序。对于一系列简单的文本文档，总体过程可以分为几个阶段。自然地，处理工作流程可能包括几个阶段。在第一步中，您需要从每个文档中将文本拆分为单词。一旦您拆分了单词，您应该将这些单词转换为每个文档的数值特征向量。

最后，您可能希望使用第 2 阶段得到的特征向量学习预测模型，并且还想要为使用监督机器学习算法的每个向量进行标记。简而言之，这四个阶段可以总结如下。对于每个文档，执行以下操作：

+   拆分文本=>单词

+   将单词转换为数值特征向量

+   数值特征向量=>标记

+   使用向量和标签构建 ML 模型作为预测模型

这四个阶段可以被视为一个工作流程。Spark ML 将这些类型的工作流程表示为由一系列 PipelineStages 组成的管道，其中转换器和估计器在管道的每个阶段中以特定顺序运行。转换器实际上是一个将一个数据集转换为另一个数据集的算法。

另一方面，估计器也是一种算法，负责在数据集上进行拟合以生成一个转换器。从技术上讲，估计器实现了一个称为`fit()`的方法，它接受一个数据集并生成一个模型，这是一个转换器。

### 提示

有兴趣的读者应该参考此网址[`spark.apache.org/docs/latest/ml-pipeline.html`](http://spark.apache.org/docs/latest/ml-pipeline.html)了解有关管道中转换器和估计器的更多详细信息。

![机器学习管道-概述](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00005.jpeg)

图 6：管道是一个估计器。

更具体地说，让我们举个例子，假设使用诸如逻辑回归（或线性回归）之类的机器学习算法作为估计器。现在通过调用`fit()`方法，训练一个**逻辑回归模型**（它本身也是一个模型，因此是一个转换器）。从技术上讲，转换器实现了一种方法，即`transform()`，它将一个数据集转换为另一个数据集。

在转换过程中，还会有一个列取决于选择和列位置。需要注意的是，Spark 开发的管道概念大多受到 Scikit-learn 项目的启发，这是一个用于数据挖掘和数据分析的简单高效的工具（也可以参见 Scikit-learn 项目，[`scikit-learn.org/stable/`](http://scikit-learn.org/stable/)）。

如第一章中所讨论的，Spark 已将 RDD 操作实现为**有向无环图**（**DAG**）风格。同样的方式也适用于管道，其中每个 DAG 管道的阶段都被指定为一个有序数组。我们之前描述的具有四个阶段的文本处理管道实际上是一个线性管道；在这种管道中，每个阶段都消耗前一阶段产生的数据。只要特征工程图的数据流以 DAG 样式形成和对齐，也可以创建非线性管道。

需要注意的是，如果管道形成一个 DAG，那么阶段需要按拓扑顺序指定。我们所讨论的管道可以在包括各种文件类型的数据集上运行，因此需要对管道一致性进行运行时和编译时检查。不幸的是，Spark 管道的当前实现不提供使用编译时类型检查。但是，Spark 提供了运行时检查，由管道和管道模型使用，使用数据集模式进行。

由于 RDD 的概念是不可变的，这意味着一旦创建了 RDD，就不可能更改 RDD 的内容，同样，流水线阶段的唯一性应该是持久的（请参考*图 6*和*图 7*以获得清晰的视图）具有唯一的 ID。为简单起见，前述文本处理工作流程可以像图 5 一样进行可视化；我们展示了具有三个阶段的文本处理流水线。**Tokenizer**和**HashingTF**是两个独特的转换器。

另一方面，LogisticRegression 是一个估计器。在底部一行，一个圆柱表示一个数据集。在原始包含带有标签的文本文档的数据集上调用了 pipeline 的`fit()`方法。现在`Tokenizer.transform()`方法将原始文本文档分割成单词，而`HashingTF.transform()`方法则将单词列转换为特征向量。

请注意，在每种情况下，数据集上都添加了一列。现在调用`LogisticRegression.fit()`方法来生成`LogisticRegressionModel`：

![机器学习流水线-概述](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00162.jpeg)

图 7：Pipeline 是一个估计器。

在*图 7*中，PipelineModel 具有与原始 Pipeline 相同数量的阶段。然而，在这种情况下，原始 Pipeline 中的所有估计器都需要转换为转换器。

当在测试数据集（即数值特征向量）上调用**PipelineModel**的`transform()`方法时，数据按特定顺序通过已安装的流水线传递。

总之，流水线和 PipelineModel 有助于确保训练和测试数据经过相同的特征处理步骤。以下部分展示了我们描述的前述流水线过程的实际示例。

## 流水线-使用 Spark ML 的示例

本节将展示一个名为**垃圾邮件过滤**的实际机器学习问题，该问题在第三章中介绍了，*通过了解数据来理解问题*，使用 Spark 的流水线。我们将使用从[`archive.ics.uci.edu/ml/datasets/SMS+Spam+Collection`](https://archive.ics.uci.edu/ml/datasets/SMS+Spam+Collection)下载的`SMSSpamCollection`数据集来展示 Spark 中的特征工程。以下代码使用**普通的旧 Java 对象**（**POJO**）类将样本数据集读取为数据集（更多信息请参见[`en.wikipedia.org/wiki/Plain_Old_Java_Object`](https://en.wikipedia.org/wiki/Plain_Old_Java_Object)）。请注意，`SMSSpamHamLabelDocument`类包含标签（`label: double`）和短信行（`text: String`）。

要运行代码，只需在 Eclipse IDE 中创建一个 Maven 项目，指定提供的`pom.xml`文件下的 Maven 项目和包的依赖关系，并将应用程序打包为 jar 文件。或者，作为独立的 Java 应用程序在 Eclipse 上运行示例。

Spark 会话创建的代码如下：

```scala
  static SparkSession spark = SparkSession 
      .builder().appName("JavaLDAExample") 
      .master("local[*]") 
      .config("spark.sql.warehouse.dir", "E:/Exp/") 
      .getOrCreate(); 

```

在这里，Spark SQL 仓库设置为`E:/Exp/`目录，用于 Windows。根据操作系统类型设置您的路径。

`smsspamdataset`样本的代码如下：

```scala
public static void main(String[] args) { 
 // Prepare training documents, which are labelled. 
 Dataset<Row> smsspamdataset = spark.createDataFrame(Arrays.asList( 
      new SMSSpamHamLabelDocument(0.0, "What you doing how are you"), 
      new SMSSpamHamLabelDocument(0.0, "Ok lar Joking wif u oni"), 
      new SMSSpamHamLabelDocument(1.0, "FreeMsg Txt CALL to No 86888 & claim your reward of 3 hours talk time to use from your phone now ubscribe6GBP mnth inc 3hrs 16 stop txtStop"), 
      new SMSSpamHamLabelDocument(0.0, "dun say so early hor U c already then say"), 
      new SMSSpamHamLabelDocument(0.0, "MY NO IN LUTON 0125698789 RING ME IF UR AROUND H"), 
      new SMSSpamHamLabelDocument(1.0, "Sunshine Quiz Win a super Sony DVD recorder if you canname the capital of Australia Text MQUIZ to 82277 B") 
    ), SMSSpamHamLabelDocument.class); 

```

现在，通过调用`show()`方法来查看数据集的结构：

```scala
Smsspamdataset.show(); 

```

输出如下所示：

![流水线-使用 Spark ML 的示例](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00099.jpeg)

POJO 类的代码如下：

```scala
public class SMSSpamHamLabelDocument implements Serializable { 
    private double label; 
    private String wordText; 
    public SMSSpamHamLabelDocument(double label, String wordText) { 
      this.label = label; 
      this.wordText = wordText; 
    } 
    public double getLabel() { return this.label; } 
    public void setLabel(double id) { this.label = label; } 
    public String getWordText() { return this.wordText; }    public void setWordText(String wordText) { this.wordText = wordText; } 
}  } 

```

现在，让我们将数据集分割为`trainingData`（60%）和`testData`（40%）以进行模型训练。

分割的代码如下：

```scala
Dataset<Row>[] splits = smsspamdataset.randomSplit(new double[] { 0.6, 0.4 }); 
Dataset<Row> trainingData = splits[0]; 
Dataset<Row> testData = splits[1]; 

```

数据集的目标是使用分类算法构建预测模型，我们从数据集中知道，有两种类型的消息。一种是垃圾邮件，表示为 1.0，另一种是正常邮件，表示为 0.0 标签。我们可以考虑使用 LogisticRegression 或线性回归算法来训练模型以简化训练和使用。

然而，使用回归等更复杂的分类器，如广义回归，将在第八章, *调整您的机器学习模型*中进行讨论。因此，根据我们的数据集，我们的工作流程或管道将如下所示：

+   将训练数据的文本行标记为单词

+   使用哈希技术提取特征

+   应用逻辑回归估计器构建模型

前面的三个步骤可以通过 Spark 的管道组件轻松完成。您可以将所有阶段定义为单个 Pipeline 类，该类将以高效的方式构建模型。以下代码显示了构建预测模型的整个管道。分词器类定义了输入和输出列（例如，`wordText`到单词），`HashTF`类定义了如何从分词器类的单词中提取特征。

`LogisticRegression`类配置其参数。最后，您可以看到 Pipeline 类，该类将前面的方法作为 PipelineStage 数组，并返回一个估计器。在训练集上应用`fit()`方法后，它将返回最终模型，该模型已准备好进行预测。您可以在应用模型进行预测后看到测试数据的输出。

管道的代码如下：

```scala
Tokenizer tokenizer = new Tokenizer() 
      .setInputCol("wordText") 
      .setOutputCol("words"); 
HashingTF hashingTF = new HashingTF() 
      .setNumFeatures(100) 
      .setInputCol(tokenizer.getOutputCol()) 
      .setOutputCol("features"); 
LogisticRegression logisticRegression = new LogisticRegression() 
      .setMaxIter(10) 
      .setRegParam(0.01); 
Pipeline pipeline = new Pipeline().setStages(new PipelineStage[] {tokenizer, hashingTF, logisticRegression}); 
    // Fit the pipeline to training documents. 
PipelineModel model = pipeline.fit(trainingData); 
Dataset<Row> predictions = model.transform(testData); 
for (Row r: predictions.select("label", "wordText", "prediction").collectAsList()) { 
  System.out.println("(" + r.get(0) + ", " + r.get(1) + ") --> prediction=" + r.get(2)); 
    } } 

```

输出如下：

```scala
(0.0, What you doing how are you)  
--> prediction=0.0 
(0.0, MY NO IN LUTON 0125698789 RING ME IF UR AROUND H)  
--> prediction=0.0 
(1.0, Sunshine Quiz Win a super Sony DVD recorder if you canname the capital of Australia Text MQUIZ to 82277 B)  
--> prediction=0.0 

```

## 特征转换、提取和选择

前面的部分向您展示了管道的整体流程。这个管道或工作流基本上是一些操作的集合，例如将一个数据集转换为另一个数据集，提取特征和选择特征。这些是我们在前几节中已经描述过的特征工程的基本操作符。本节将向您展示如何使用 Spark 机器学习包中的这些操作符的详细信息。Spark 提供了一些高效的特征工程 API，包括 MLlib 和 ML。

在本节中，我们将继续使用垃圾邮件过滤器示例开始 ML 包。让我们从文本文件中读取一个大型数据集作为数据集，其中包含以 ham 或 spam 单词开头的行。此数据集的示例输出如下。现在我们将使用此数据集来提取特征并使用 Spark 的 API 构建模型。

`Input DF`的代码如下：

```scala
Dataset<Row> df = spark.read().text("input/SMSSpamCollection.txt"); 
df.show();  

```

输出如下：

![特征转换、提取和选择](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00059.jpeg)

### 转换 - RegexTokenizer

从前面的输出中，您可以看到我们必须将其转换为两列以识别垃圾邮件和 ham 消息。为此，我们可以使用`RegexTokenizer`转换器，该转换器可以从正则表达式（`regex`）中获取输入并将其转换为新数据集。此代码生成`labelFeatured`。例如，请参阅以下输出中显示的数据集：

```scala
// Feature Transformers (RegexTokenizer) 
RegexTokenizer regexTokenizer1 = new RegexTokenizer() 
        .setInputCol("value") 
        .setOutputCol("labelText") 
        .setPattern("\\t.*$");     
Dataset<Row> labelTextDataFrame = regexTokenizer1.transform(df); 
RegexTokenizer regexTokenizer2 = new RegexTokenizer() 
        .setInputCol("value").setOutputCol("text").setPattern("\\W"); 
Dataset<Row> labelFeatureDataFrame = regexTokenizer2 
        .transform(labelTextDataFrame); 
for (Row r : labelFeatureDataFrame.select("text", "labelText").collectAsList()) { 
      System.out.println( r.getAs(1) + ": " + r.getAs(0)); 
    } 

```

以下是`labelFeature`数据集的输出：

```scala
WrappedArray(ham): WrappedArray(ham, what, you, doing, how, are, you) 
WrappedArray(ham): WrappedArray(ham, ok, lar, joking, wif, u, oni) 
WrappedArray(ham): WrappedArray(ham, dun, say, so, early, hor, u, c, already, then, say) 
WrappedArray(ham): WrappedArray(ham, my, no, in, luton, 0125698789, ring, me, if, ur, around, h) 
WrappedArray(spam): WrappedArray(spam, freemsg, txt, call, to, no, 86888, claim, your, reward, of, 3, hours, talk, time, to, use, from, your, phone, now, ubscribe6gbp, mnth, inc, 3hrs, 16, stop, txtstop) 
WrappedArray(ham): WrappedArray(ham, siva, is, in, hostel, aha) 
WrappedArray(ham): WrappedArray(ham, cos, i, was, out, shopping, wif, darren, jus, now, n, i, called, him, 2, ask, wat, present, he, wan, lor, then, he, started, guessing, who, i, was, wif, n, he, finally, guessed, darren, lor) 
WrappedArray(spam): WrappedArray(spam, sunshine, quiz, win, a, super, sony, dvd, recorder, if, you, canname, the, capital, of, australia, text, mquiz, to, 82277, b) 

```

现在让我们通过以下方式从我们刚刚创建的`labelFeatured`数据集创建一个新的数据集，选择标签文本：

```scala
Dataset<Row> newDF = labelFeatureDataFrame.withColumn("labelTextTemp",        labelFeatureDataFrame.col("labelText").cast(DataTypes.StringType))        .drop(labelFeatureDataFrame.col("labelText"))        .withColumnRenamed("labelTextTemp", "labelText"); 

```

现在让我们通过调用`show()`方法进一步探索新数据集中的内容：

![转换 - RegexTokenizer](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00116.jpeg)

### 转换 - 字符串索引器

前面的输出显示了 ham 和 spam 消息的分类，但我们必须将 ham 和 spam 文本转换为双精度值。`StringIndexer`转换器可以轻松完成此操作。它可以将标签的字符串列编码为另一列中的索引。索引按标签频率排序。`StringIndexer`为我们的数据集生成了两个索引，0.0 和 1.0：

```scala
// Feature Transformer (StringIndexer) 
StringIndexer indexer = new StringIndexer().setInputCol("labelText") 
        .setOutputCol("label"); 
Dataset<Row> indexed = indexer.fit(newDF).transform(newDF); 
    indexed.select(indexed.col("labelText"), indexed.col("label"), indexed.col("text")).show();  

```

`indexed.show()`函数的输出如下：

![转换 - 字符串索引器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00011.jpeg)

### 转换 - 停用词移除器

前述输出包含单词或标记，但有些单词并不像特征那样重要。因此，我们需要删除这些单词。为了使这项任务更容易，Spark 通过`StopWordsRemover`类提供了停用词列表，这将在第六章中更多地讨论，*构建可扩展的机器学习管道*。

我们可以使用这些单词来过滤不需要的单词。此外，我们将从文本列中删除垃圾邮件和垃圾邮件单词。`StopWordsRemover`类将通过删除特征中的停用词将前述数据集转换为过滤后的数据集。下面的输出将显示没有垃圾邮件和垃圾邮件单词标记的单词：

```scala
// Feature Transformers (StopWordsRemover) 
StopWordsRemover remover = new StopWordsRemover(); 
String[] stopwords = remover.getStopWords(); 
String[] newStopworks = new String[stopwords.length+2]; 
newStopworks[0]="spam"; 
newStopworks[1]="ham"; 
for(int i=2;i<stopwords.length;i++){ 
      newStopworks[i]=stopwords[i];}   
remover.setStopWords(newStopworks).setInputCol("text").setOutputCol("filteredWords"); 
Dataset<Row> filteredDF = remover.transform(indexed); 
filteredDF.select(filteredDF.col("label"), filteredDF.col("filteredWords")).show();  

```

输出如下：

![转换 - StopWordsRemover](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00114.jpeg)

### TF 提取

现在我们有了包含双精度值标签和过滤后的单词或标记的数据集。下一个任务是对特征进行向量化（使其成为数值）或从单词或标记中提取特征。

**TF-IDF**（`HashingTF`和`IDF`；也称为**词频-逆文档频率**）是一种广泛用于提取特征的特征向量化方法，基本上计算了术语在语料库中对文档的重要性。

`TF`计算文档或行中术语的频率，`IDF`计算文档或行的频率，即包含特定术语的文档或行的数量。以下代码使用 Spark 的高效`HashingTF`类解释了前述数据集的词频。`HashingTF`是一个将术语集合转换为固定长度特征向量的转换器。还显示了特征数据的输出：

```scala
// Feature Extractors (HashingTF transformer) 
int numFeatures = 100; 
HashingTF hashingTF = new HashingTF().setInputCol("filteredWords") 
        .setOutputCol("rawFeatures").setNumFeatures(numFeatures); 
Dataset<Row> featurizedData = hashingTF.transform(filteredDF); 
    for (Row r : featurizedData.select("rawFeatures", "label").collectAsList()) { 
Vector features = r.getAs(0); ////Problematic line 
Double label = r.getDouble(1); 
System.out.println(label + "," + features); 
    }  

```

输出如下：

```scala
0.0,(100,[19],[1.0]) 
0.0,(100,[9,16,17,48,86,96],[1.0,1.0,1.0,1.0,1.0,1.0]) 
0.0,(100,[17,37,43,71,99],[1.0,1.0,2.0,1.0,2.0]) 
0.0,(100,[4,41,42,47,92],[1.0,1.0,1.0,1.0,1.0]) 
1.0,(100,[3,12,19,26,28,29,34,41,46,51,71,73,88,93,94,98],[1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,2.0]) 
0.0,(100,[19,25,38],[1.0,1.0,1.0]) 
0.0,(100,[8,10,16,30,37,43,48,49,50,55,76,82,89,95,99],[1.0,4.0,2.0,1.0,1.0,2.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,2.0]) 
1.0,(100,[0,24,36,39,42,48,53,58,67,86,95,97,98],[1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,2.0,1.0,1.0,2.0,1.0]) 

```

### 提取 - IDF

同样，我们可以将`IDF`应用于特征数据以计算文档频率。`IDF`是一个适合于前述数据集的估计器，并产生一个将转换为包含特征和标签的重新缩放数据集的`IDFModel`：

```scala
// Feature Extractors (IDF Estimator) 
IDF idf = new IDF().setInputCol("rawFeatures").setOutputCol("features"); 
IDFModel idfModel = idf.fit(featurizedData); 
Dataset<Row> rescaledData = idfModel.transform(featurizedData); 
for (Row r : rescaledData.select("features", "label").collectAsList()) { 
Vector features = r.getAs(0); 
Double label = r.getDouble(1); 
System.out.println(label + "," + features); 
    }  

```

输出如下：

```scala
0.0,(100,[19],[0.8109302162163288]) 
0.0,(100,[9,16,17,48,86,96],[1.5040773967762742,1.0986122886681098,1.0986122886681098,0.8109302162163288,1.0986122886681098,1.5040773967762742]) 
0.0,(100,[17,37,43,71,99],[1.0986122886681098,1.0986122886681098,2.1972245773362196,1.0986122886681098,2.1972245773362196]) 
0.0,(100,[4,41,42,47,92],[1.5040773967762742,1.0986122886681098,1.0986122886681098,1.5040773967762742,1.5040773967762742]) 
1.0,(100,[3,12,19,26,28,29,34,41,46,51,71,73,88,93,94,98],[1.5040773967762742,1.5040773967762742,0.8109302162163288,1.5040773967762742,1.5040773967762742,1.5040773967762742,1.5040773967762742,1.0986122886681098,1.5040773967762742,1.5040773967762742,1.0986122886681098,1.5040773967762742,1.5040773967762742,1.5040773967762742,1.5040773967762742,2.1972245773362196]) 
0.0,(100,[19,25,38],[0.8109302162163288,1.5040773967762742,1.5040773967762742]) 
0.0,(100,[8,10,16,30,37,43,48,49,50,55,76,82,89,95,99],[1.5040773967762742,6.016309587105097,2.1972245773362196,1.5040773967762742,1.0986122886681098,2.1972245773362196,0.8109302162163288,1.5040773967762742,1.5040773967762742,1.5040773967762742,1.5040773967762742,1.5040773967762742,1.5040773967762742,1.0986122886681098,2.1972245773362196]) 
1.0,(100,[0,24,36,39,42,48,53,58,67,86,95,97,98],[1.5040773967762742,1.5040773967762742,1.5040773967762742,1.5040773967762742,1.0986122886681098,0.8109302162163288,1.5040773967762742,1.5040773967762742,3.0081547935525483,1.0986122886681098,1.0986122886681098,3.0081547935525483,1.0986122886681098]) 

```

前述输出从原始文本中提取特征。第一个条目是标签，其余是提取的特征向量。

### 选择 - ChiSqSelector

前述输出已准备好使用分类算法进行训练，例如`LogisticRegression`。但是我们可以从分类特征中使用更重要的特征。为此，Spark 提供了一些特征选择器 API，如`ChiSqSelector`。`ChiSqSelector`被称为**卡方特征选择**。

它在具有分类特征的标记数据上运行。它根据卡方检验对特征进行排序，该检验独立于类，并过滤出类标签最依赖的前几个特征。此选择器对提高模型的预测能力很有用。以下代码将从特征向量中选择前三个特征，以及给出的输出：

```scala
org.apache.spark.ml.feature.ChiSqSelector selector = new org.apache.spark.ml.feature.ChiSqSelector(); 
selector.setNumTopFeatures(3).setFeaturesCol("features") 
        .setLabelCol("label").setOutputCol("selectedFeatures"); 
Dataset<Row> result = selector.fit(rescaledData).transform(rescaledData); 
    for (Row r : result.select("selectedFeatures", "label").collectAsList()) { 
  Vector features = r.getAs(0); 
  Double label = r.getDouble(1); 
  System.out.println(label + "," + features); 
    } 

```

### 提示

我们将在第六章中更多地讨论`ChiSqSelector`，`IDFModel`，`IDF`，`StopWordsRemover`和`RegexTokenizer`类，*构建可扩展的机器学习管道*。

输出如下：

```scala
0.0,(3,[],[]) 
0.0,(3,[],[]) 
0.0,(3,[],[]) 
0.0,(3,[],[]) 
1.0,(3,[1,2],[1.5040773967762742,2.1972245773362196]) 
0.0,(3,[],[]) 
0.0,(3,[],[]) 
1.0,(3,[0,2],[1.5040773967762742,1.0986122886681098]) 

```

现在，当构建具有特征向量的模型时，您可以应用`LogisticRegression`。Spark 提供了许多不同的特征工程 API。但是，出于简洁和页面限制的原因，我们没有使用 Spark 的其他机器学习（即 Spark MLlib）。我们将在未来的章节中逐渐讨论使用`spark.mllib`进行特征工程的示例。

# 高级特征工程

在本节中，我们将讨论一些高级特性，这些特性也涉及到特征工程过程，如手动特征构建，特征学习，特征工程的迭代过程和深度学习。

## 特征构建

最好的结果来自于您通过手动特征工程或特征构建。因此，手动构建是从原始数据中创建新特征的过程。基于特征重要性的特征选择可以告诉您有关特征的客观效用；然而，这些特征必须来自其他地方。事实上，有时候，您需要手动创建它们。

与特征选择相比，特征构建技术需要花费大量的精力和时间，不是在聚合或挑选特征上，而是在实际的原始数据上，以便新特征能够有助于提高模型的预测准确性。因此，它还涉及思考数据的潜在结构以及机器学习问题。

在这方面，要从复杂和高维数据集中构建新特征，您需要了解数据的整体结构。除此之外，还需要知道如何在预测建模算法中使用和应用它们。在表格、文本和多媒体数据方面将有三个方面：

+   处理和手动创建表格数据通常意味着混合组合特征以创建新特征。您可能还需要分解或拆分一些原始特征以创建新特征。

+   对于文本数据，通常意味着设计文档或上下文特定的指标与问题相关。例如，当您在大型原始数据上应用文本分析，比如来自 Twitter 标签的数据。

+   对于多媒体数据，比如图像数据，通常需要花费大量时间以手动方式挑选出相关结构。

不幸的是，特征构建技术不仅是手动的，整个过程也更慢，需要人类像你和我们一样进行大量的研究。然而，从长远来看，它可能会产生重大影响。事实上，特征工程和特征选择并不是互斥的；然而，在机器学习领域，它们都很重要。

## 特征学习

是否可能避免手动指定如何从原始数据中构建或提取特征的过程？特征学习可以帮助您摆脱这一点。因此，特征学习是一个高级过程；或者说是从原始数据中自动识别和使用特征的过程。这也被称为表示学习，有助于您的机器学习算法识别有用的特征。

特征学习技术通常用于深度学习算法。因此，最近的深度学习技术在这一领域取得了一些成功。自动编码器和受限玻尔兹曼机就是使用特征学习概念的例子。特征学习的关键思想是使用无监督或半监督学习算法以压缩形式自动和抽象地表示特征。

语音识别、图像分类和物体识别是一些成功的例子；研究人员在这些领域取得了最新的支持结果。由于篇幅有限，本书中无法详细介绍更多细节。

不幸的是，Spark 还没有实现任何自动特征提取或构建的 API。

## 特征工程的迭代过程

特征工程的整个过程不是独立的，而是更多或少是迭代的。因为您实际上是在数据选择到模型评估之间反复交互，直到您完全满意或时间用尽。迭代可以想象为一个随时间迭代运行的四步工作流程。当您聚合或收集原始数据时，您可能没有进行足够的头脑风暴。然而，当您开始探索数据时，您真的深入了解问题。

之后，您将会看到大量数据，研究特征工程的最佳技术以及现有技术中提出的相关问题，您将看到自己能够偷取多少。当您进行了足够的头脑风暴后，您将开始设计所需的特征或根据问题类型或类别提取特征。您可以使用自动特征提取或手动特征构建（有时两者都有）。如果对性能不满意，您可能需要重新进行特征提取以改进。请参考*图 7*，以清晰地了解特征工程的迭代过程：

![特征工程的迭代过程](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00163.jpeg)

图 8：特征工程中的迭代处理。

当您设计或提取了特征后，您需要选择特征。您可以根据特征重要性应用不同的评分或排名机制。同样，您可能需要迭代相同的过程，如设计特征以改进模型。最后，您将评估模型，以估计模型在新数据上的准确性，使您的模型具有适应性。

您还需要一个明确定义的问题，这将帮助您停止整个迭代。完成后，您可以继续尝试其他模型。一旦您在想法或准确性增量上达到平台，未来将有收益等待着您的 ML 管道。

## 深度学习

我们可以说，数据表示中最有趣和有前途的举措之一是深度学习。它在张量计算应用和**人工智能神经网络**（**AINN**）系统中非常受欢迎。使用深度学习技术，网络学习如何在不同层次表示数据。

因此，您将具有表示您拥有的线性数据的指数能力。Spark 可以利用这一优势，用于改进深度学习。有关更一般的讨论，请参阅以下网址[`en.wikipedia.org/wiki/Deep_learning`](https://en.wikipedia.org/wiki/Deep_learning)，要了解如何在 TensorFlow 集群上部署管道，请参见[`www.tensorflow.org/`](https://www.tensorflow.org/)。

Databricks 最近的研究和开发（也请参阅[`databricks.com/`](https://databricks.com/)）表明，Spark 也可以用于找到 AINN 训练的最佳超参数集。优势在于，Spark 的计算速度比普通的深度学习或神经网络算法快 10 倍。

因此，您的模型训练时间将大幅减少多达 10 倍，错误率将降低 34%。此外，Spark 可以应用于大量数据上训练的 AINN 模型，因此您可以大规模部署您的 ML 模型。我们将在后面的章节中更多地讨论深度学习作为高级机器学习。

# 总结

特征工程、特征选择和特征构建是准备训练和测试集以构建机器学习模型时最常用的三个步骤。通常，首先应用特征工程从可用数据集中生成额外的特征。之后，应用特征选择技术来消除不相关、缺失或空值、冗余或高度相关的特征，以便获得高预测准确性。

相比之下，特征构建是一种高级技术，用于构建在原始数据集中要么不存在要么微不足道的新特征。

请注意，并不总是需要进行特征工程或特征选择。是否进行特征选择和构建取决于您拥有或收集的数据，您选择了什么样的 ML 算法，以及实验本身的目标。

在本章中，我们已经详细描述了所有三个步骤，并提供了实际的 Spark 示例。在下一章中，我们将详细描述使用两个机器学习 API（Spark MLlib 和 Spark ML）的监督学习和无监督学习的一些实际示例。


# 第五章：通过示例进行监督和无监督学习

在第二章中，《机器学习最佳实践》读者学习了一些基本机器学习技术的理论基础。而第三章中，《通过了解数据来理解问题》，描述了使用 Spark 的 API（如 RDD、DataFrame 和 Datasets）进行基本数据操作。另一方面，第四章描述了特征工程的理论和实践。然而，在本章中，读者将学习到快速而强大地在可用数据上应用监督和无监督技术以解决新问题所需的实际知识，这些知识是基于前几章的理解，并且将从 Spark 的角度演示这些例子。简而言之，本章将涵盖以下主题：

+   机器学习课程

+   监督学习

+   无监督学习

+   推荐系统

+   高级学习和泛化

# 机器学习课程

正如在第一章中所述，《使用 Spark 进行数据分析简介》和第二章中，《机器学习最佳实践》，机器学习技术可以进一步分为三类主要算法：监督学习、无监督学习和推荐系统。分类和回归算法在监督学习应用开发中被广泛使用，而聚类则属于无监督学习的范畴。在本节中，我们将描述一些监督学习技术的示例。

接下来我们将提供一些使用 Spark 呈现的相同示例的例子。另一方面，聚类技术的示例将在“无监督学习”部分中讨论，回归技术经常模拟变量之间的过去关系，以预测它们的未来变化（上升或下降）。在这里，我们分别展示了分类和回归算法的两个现实生活中的例子。相比之下，分类技术接受一组带有已知标签的数据，并学习如何基于该信息为新记录打上标签：

+   **示例（分类）**：Gmail 使用一种称为分类的机器学习技术，根据电子邮件的数据来确定电子邮件是否为垃圾邮件。

+   **示例（回归）**：举个例子，假设你是一名在线货币交易员，你在外汇或 Fortrade 上工作。现在你心里有两个货币对要买入或卖出，比如：GBP/USD 和 USD/JPY。如果你仔细观察这两对货币，USD 是这两对货币的共同点。现在，如果你观察 USD、GBP 或 JPY 的历史价格，你可以预测未来的结果，即你应该开仓买入还是卖出。这些问题可以通过使用回归分析的监督学习技术来解决：![机器学习课程](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00164.jpeg)

图 1：分类、聚类和协同过滤-大局观

另一方面，聚类和降维常用于无监督学习。以下是一些示例：

+   **示例（聚类）**：Google 新闻使用一种称为聚类的技术，根据标题和内容将新闻文章分成不同的类别。聚类算法发现数据集中出现的分组。

+   **示例（协同过滤）**：协同过滤算法经常用于推荐系统的开发。像亚马逊和 Netflix 这样的知名公司使用一种称为协同过滤的机器学习技术，根据用户的历史和与其他用户的相似性来确定用户会喜欢哪些产品。

+   **示例（降维）**：降维通常用于使高维数据集变得更加可用。例如，假设您有一张尺寸为 2048x1920 的图像，并且希望将其降维到 1080x720，而不会牺牲太多质量。在这种情况下，可以使用流行的算法，如**主成分分析**（**PCA**）或**奇异值分解**（**SVD**），尽管您也可以实现 SVD 来实现 PCA。这就是为什么 SVD 更广泛使用的原因。

## 监督学习

正如已经说明的，监督学习应用程序基于一组示例进行预测，其目标是学习将输入与与现实世界相一致的输出相映射的一般规则。例如，垃圾邮件过滤的数据集通常包含垃圾邮件和非垃圾邮件。因此，我们可以知道训练集中哪些消息是垃圾邮件或非垃圾邮件。因此，监督学习是从标记的训练数据中推断函数的机器学习技术。监督学习任务涉及以下步骤：

+   使用训练数据集训练 ML 模型

+   使用测试数据集测试模型性能

因此，在这种情况下，用于训练 ML 模型的数据集被标记为感兴趣的值，监督学习算法会寻找这些值标签中的模式。算法找到所需的模式后，这些模式可以用于对未标记的测试数据进行预测。

监督学习的典型用途多种多样，通常用于生物信息学、化学信息学、数据库营销、手写识别、信息检索、计算机视觉中的对象识别、光学字符识别、垃圾邮件检测、模式识别、语音识别等应用中，这些应用中主要使用分类技术。另一方面，监督学习是生物系统中向下因果关系的特例。

### 提示

有关监督学习技术如何从理论角度工作的更多信息可以在以下书籍中找到：Vapnik, V. N. *统计学习理论的本质（第二版）*，Springer Verlag，2000 年；以及 Mehryar M.，Afshin R. Ameet T.（2012）机器学习基础，麻省理工学院出版社 ISBN 9780262018258。

### 监督学习示例

分类是一类监督机器学习算法，将输入指定为预定义类别之一。分类的一些常见用例包括：

+   信用卡欺诈检测

+   电子邮件垃圾邮件检测

分类数据被标记，例如垃圾邮件/非垃圾邮件或欺诈/非欺诈。机器学习为新数据分配标签或类别。您根据预先确定的特征对某物进行分类。特征是您提出的“如果问题”。标签是这些问题的答案。例如，如果一个对象像鸭子一样走路，游泳和呱呱叫，那么标签将是*鸭子*。或者假设航班延误超过 1 小时，那么它将是延误；否则不是延误。

# 使用 Spark 进行监督学习-一个例子

我们将通过分析航班延误来演示一个示例。将使用美国交通部网站上的名为`On_Time_Performance_2016_1.csv`的数据集[`www.transtats.bts.gov/`](http://www.transtats.bts.gov/)。

## 使用 Spark 进行航班延误分析

我们使用 2016 年的航班信息。对于每次航班，我们在*表 1*中提供了以下信息（截至 2016 年 5 月 17 日，共 444,827 行和 110 列）：

| **数据字段** | **描述** | **示例值** |
| --- | --- | --- |
| `DayofMonth` | 月份 | 2 |
| `DayOfWeek` | 星期几 | 5 |
| `TailNum` | 飞机尾号 | N505NK |
| `FlightNum` | 航班号 | 48 |
| `AirlineID` | 航空公司 ID | 19805 |
| `OriginAirportID` | 起飞机场 ID | JFK |
| `DestAirportID` | 目的地机场 ID | LAX |
| `Dest` | 目的地机场代码 | 1424 |
| `CRSDepTime` | 计划起飞时间 | 10:00 |
| `DepTime` | 实际起飞时间 | 10:30 |
| `DepDelayMinutes` | 起飞延误时间 | 30 |
| `CRSArrTime` | 计划到达时间 | 22:45 |
| `ArrTime` | 实际到达时间 | 23:45 |
| `ArrDelayMinutes` | 到达延误时间 | 60 |
| `CRSElapsedTime` | 飞行时间 | 825 |
| `Distance` | 总距离 | 6200 |

表 1：来自“准时表现 2016_1”数据集的样本数据

在这种情况下，我们将构建一棵树，根据图中显示的以下特征来预测延误或未延误的标签，这是航班数据集的一个小快照。这里`ArrDelayMinutes`为 113，应该被分类为延误（1.0），其他行的延误时间少于 60 分钟，因此标签应为 0.0（未延误）。从这个数据集中，我们将进行一些操作，如特征提取、转换和选择。*表 2*显示了我们将在此示例中考虑的与特征相关的前五行：

+   **标签**：延误和未延误 - 如果延误>60 分钟，则为延误

+   **特征**：{`DayOfMonth`, `WeekOfday`, `CRSdeptime`, `CRSarrtime`, `Carrier`, `CRSelapsedtime`, `Origin`, `Dest`, `ArrDelayMinutes`}![使用 Spark 进行航班延误分析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00004.jpeg)

图 2：用于航班延误预测的选定特征

### 加载和解析数据集

在执行特征提取之前，我们需要加载和解析数据集。这一步还包括：加载包和相关依赖项，将数据集读取为 DataFrame，创建 POJO 或 Bean 类，并根据要求添加新的标签列。

**步骤 1：加载所需的包和依赖项**

为了读取 csv 文件，我们使用了 Databricks 提供的 csv 读取器：

```scala
import org.apache.log4j.Level; 
import org.apache.log4j.Logger; 
import org.apache.spark.api.java.JavaRDD; 
import org.apache.spark.api.java.function.Function; 
import org.apache.spark.ml.Pipeline; 
import org.apache.spark.ml.PipelineModel; 
import org.apache.spark.ml.PipelineStage; 
import org.apache.spark.ml.classification.DecisionTreeClassificationModel; 
import org.apache.spark.ml.classification.DecisionTreeClassifier; 
import org.apache.spark.ml.evaluation.MulticlassClassificationEvaluator; 
import org.apache.spark.ml.feature.IndexToString; 
import org.apache.spark.ml.feature.LabeledPoint; 
import org.apache.spark.ml.feature.StringIndexer; 
import org.apache.spark.ml.feature.StringIndexerModel; 
import org.apache.spark.ml.feature.VectorAssembler; 
import org.apache.spark.ml.feature.VectorIndexer; 
import org.apache.spark.ml.feature.VectorIndexerModel; 
import org.apache.spark.ml.linalg.Vector; 
import org.apache.spark.rdd.RDD; 
import org.apache.spark.sql.Dataset; 
import org.apache.spark.sql.Row; 
import org.apache.spark.sql.SparkSession; 
import scala.Tuple2; 

```

**步骤 2：创建 Spark 会话**

以下是创建 Spark 会话的代码：

```scala
  static SparkSession spark = SparkSession 
      .builder() 
      .appName("JavaLDAExample") 
      .master("local[*]") 
      .config("spark.sql.warehouse.dir", "E:/Exp/") 
      .getOrCreate(); 

```

**步骤 3：使用数据集读取和解析 csv 文件**

这个数据集包含许多列，我们在这个示例中不会将其作为特征。因此，我们将从 DataFrame 中仅选择我们之前提到的特征。这个 DataFrame 的输出已经在*图 2*中显示过了：

```scala
String csvFile = "input/On_Time_On_Time_Performance_2016_1.csv"; 
Dataset<Row> df = spark.read().format("com.databricks.spark.csv").option("header", "true").load(csvFile);  
RDD<Tuple2<String, String>> distFile = spark.sparkContext().wholeTextFiles("input/test/*.txt", 2); 
JavaRDD<Tuple2<String, String>> distFile2 = distFile.toJavaRDD(); 
JavaRDD<Row> rowRDD = df.toJavaRDD(); 
Dataset<Row> newDF = df.select(df.col("ArrDelayMinutes"), 
df.col("DayofMonth"), df.col("DayOfWeek"), 
df.col("CRSDepTime"), df.col("CRSArrTime"), df.col("Carrier"), 
df.col("CRSElapsedTime"), df.col("Origin"), df.col("Dest")); 
newDF.show(5); 

```

以下是前 5 行的输出：

![加载和解析数据集](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00081.jpeg)

**步骤 4：创建 POJO 或 Bean 类**

我们开发的 POJO 类名为`Flight`，其中将使用相应的 setter 和 getter 定义所需的特征和标签字段。

```scala
public class Flight implements Serializable { 
  double label; 
  double monthDay; 
  double weekDay; 
  double crsdeptime; 
  double crsarrtime; 
  String carrier; 
  double crselapsedtime; 
  String origin; 
  String dest; 

public Flight(double label, double monthDay, double weekDay, double crsdeptime, double crsarrtime, String carrier, 
      double crselapsedtime, String origin, String dest) { 
    super(); 
    this.label = label; 
    this.monthDay = monthDay; 
    this.weekDay = weekDay; 
    this.crsdeptime = crsdeptime; 
    this.crsarrtime = crsarrtime; 
    this.carrier = carrier; 
    this.crselapsedtime = crselapsedtime; 
    this.origin = origin; 
    this.dest = dest; 
  } 
  public double getLabel() { 
    return label; 
  } 
  public void setLabel(double label) { 
    this.label = label; 
  } 
  public double getMonthDay() { 
    return monthDay; 
  } 
  public void setMonthDay(double monthDay) { 
    this.monthDay = monthDay; 
  } 
  public double getWeekDay() { 
    return weekDay; 
  } 
  public void setWeekDay(double weekDay) { 
    this.weekDay = weekDay; 
  } 
  public double getCrsdeptime() { 
    return crsdeptime; 
  } 
  public void setCrsdeptime(double crsdeptime) { 
    this.crsdeptime = crsdeptime; 
  } 
  public double getCrsarrtime() { 
    return crsarrtime; 
  } 
  public void setCrsarrtime(double crsarrtime) { 
    this.crsarrtime = crsarrtime; 
  } 
  public String getCarrier() { 
    return carrier; 
  } 
  public void setCarrier(String carrier) { 
    this.carrier = carrier; 
  } 
  public double getCrselapsedtime() { 
    return crselapsedtime; 
  } 
  public void setCrselapsedtime(double crselapsedtime) { 
    this.crselapsedtime = crselapsedtime; 
  } 
  public String getOrigin() { 
    return origin; 
  } 
  public void setOrigin(String origin) { 
    this.origin = origin; 
  } 
  public String getDest() { 
    return dest; 
  } 
  public void setDest(String dest) { 
    this.dest = dest; 
  } 
  @Override 
  public String toString() { 
    return "Flight [label=" + label + ", monthDay=" + monthDay + ", weekDay="
       + weekDay + ", crsdeptime=" 
        + crsdeptime + ", crsarrtime=" + crsarrtime + ", carrier=" + 
      carrier + ", crselapsedtime=" 
        + crselapsedtime + ", origin=" + origin + ", dest=" +
       dest + "]"; 
  } 

```

我们相信前面的类是不言自明的，它用于从原始数据集中设置和获取特征值。

**步骤 5：根据延误列添加新的标签列**

如果延误超过 40 分钟，则标签应为 1，否则应为 0。使用 Flight bean 类创建一个新的数据集。这个数据集可以在`ArrDelayMinutes`列中包含空字符串。因此，在映射之前，我们从数据集中过滤掉包含空字符串的行：

```scala
JavaRDD<Flight> flightsRDD = newDF.toJavaRDD().filter(new Function<Row, Boolean>() { 
          @Override 
          public Boolean call(Row v1) throws Exception { 
            return !v1.getString(0).isEmpty(); 
          } 
        }).map(new Function<Row, Flight>() { 
          @Override 
          public Flight call(Row r) throws Exception { 
            double label; 
            double delay = Double.parseDouble(r.getString(0)); 
            if (delay > 60) 
              label = 1.0; 
else 
      label = 0.0; 
double monthday = Double.parseDouble(r.getString(1)) - 1; 
double weekday = Double.parseDouble(r.getString(2)) - 1; 
double crsdeptime = Double.parseDouble(r.getString(3)); 
double crsarrtime = Double.parseDouble(r.getString(4)); 
String carrier = r.getString(5); 
double crselapsedtime1 = Double.parseDouble(r.getString(6)); 
String origin = r.getString(7); 
String dest = r.getString(8); 
Flight flight = new Flight(label, monthday, weekday,crsdeptime, crsarrtime, carrier,crselapsedtime1, origin, dest); 
        return flight; 
    }}); 

```

现在从上面创建的 RDD 中创建一个新的数据集：

```scala
Dataset<Row> flightDelayData = spark.sqlContext().createDataFrame(flightsRDD,Flight.class); 
flightDelayData.printSchema(); 

```

现在在下面的*图 3*中显示数据帧`flightDelayData`的前 5 行：

```scala
flightDelayData.show(5); 

```

[输出：]

![加载和解析数据集](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00030.jpeg)

图 3：显示新标签列的 DataFrame

### 特征提取

为了提取特征，我们必须制作数值，并且如果有任何文本值，那么我们必须制作一个标记向量，以应用机器学习算法。

第 1 步：转向特征提取

在这里，我们将把包含文本的列转换为双值列。在这里，我们使用`StringIndexer`为每个唯一的文本制作一个唯一的索引：

```scala
StringIndexer carrierIndexer = new StringIndexer().setInputCol("carrier").setOutputCol("carrierIndex"); 
Dataset<Row> carrierIndexed = carrierIndexer.fit(flightDelayData).transform(flightDelayData); 
StringIndexer originIndexer = new StringIndexer().setInputCol("origin").setOutputCol("originIndex"); 
Dataset<Row> originIndexed = originIndexer.fit(carrierIndexed).transform(carrierIndexed); 
StringIndexer destIndexer = new StringIndexer().setInputCol("dest").setOutputCol("destIndex"); 
Dataset<Row> destIndexed = destIndexer.fit(originIndexed).transform(originIndexed); 
destIndexed.show(5); 

```

[输出]：

![特征提取](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00043.jpeg)

图 4：每个唯一文本的唯一索引

第 2 步：使用向量组装器制作特征向量

使用向量组装器制作特征向量，并将其转换为标记向量，以应用机器学习算法（决策树）。请注意，这里我们使用决策树只是举个例子，因为它显示了更好的分类准确性。根据算法和模型的选择和调整，您将能够进一步探索和使用其他分类器：

```scala
VectorAssembler assembler = new VectorAssembler().setInputCols( 
        new String[] { "monthDay", "weekDay", "crsdeptime", 
            "crsarrtime", "carrierIndex", "crselapsedtime", 
            "originIndex", "destIndex" }).setOutputCol( 
        "assembeledVector"); 

```

现在将组装器转换为行数据集，如下所示：

```scala
Dataset<Row> assembledFeatures = assembler.transform(destIndexed); 

```

现在将数据集转换为`JavaRDD`，以制作特征向量，如下所示：

```scala
JavaRDD<Row> rescaledRDD = assembledFeatures.select("label","assembeledVector").toJavaRDD(); 

```

按如下方式将 RDD 映射为`LabeledPoint`：

```scala
JavaRDD<LabeledPoint> mlData = rescaledRDD.map(new Function<Row, LabeledPoint>() { 
          @Override 
          public LabeledPoint call(Row row) throws Exception { 
            double label = row.getDouble(0); 
            Vector v = row.getAs(1); 
            return new LabeledPoint(label, v); 
          } 
        }); 

```

现在按如下方式打印前五个值：

```scala
System.out.println(mlData.take(5));  

```

[输出]：

![特征提取](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00025.jpeg)

图 5：相应的组装向量

### 准备训练和测试集

在这里，我们将从标记向量的数据集中准备训练数据集。最初，我们将制作一个训练集，其中 15%的记录将是非延迟记录，85%将是延迟记录。最后，训练和测试数据集将分别准备为 70%和 30%。

第 1 步：从整个数据集中制作训练和测试集

首先，根据之前创建的标签（即 1 和 0）来过滤 RDD，创建一个新的 RDD，如下所示：

```scala
JavaRDD<LabeledPoint> splitedData0 = mlData.filter(new Function<LabeledPoint, Boolean>() { 
          @Override 
          public Boolean call(LabeledPoint r) throws Exception { 
              return r.label() == 0; 
          } 
        }).randomSplit(new double[] { 0.85, 0.15 })[1]; 

    JavaRDD<LabeledPoint> splitedData1 = mlData.filter(new Function<LabeledPoint, Boolean>() { 
          @Override 
          public Boolean call(LabeledPoint r) throws Exception { 
            return r.label() == 1; 
          } 
        }); 

    JavaRDD<LabeledPoint> splitedData2 = splitedData1.union(splitedData0); 
    System.out.println(splitedData2.take(1)); 

```

现在使用`union()`方法将两个 RDD 联合起来，如下所示：

```scala
JavaRDD<LabeledPoint> splitedData2 = splitedData1.union(splitedData0); 
System.out.println(splitedData2.take(1)); 

```

现在将合并的 RDD 进一步转换为行数据集，如下所示（最大类别设置为 4）：

```scala
Dataset<Row> data = spark.sqlContext().createDataFrame(splitedData2, LabeledPoint.class); 
data.show(100); 

```

现在我们需要对分类变量进行向量索引，如下所示：

```scala
VectorIndexerModel featureIndexer = new VectorIndexer() 
          .setInputCol("features") 
          .setOutputCol("indexedFeatures") 
          .setMaxCategories(4) 
          .fit(data); 

```

现在我们已经使用`VectorIndexerModel`估计器进行了特征索引。现在下一个任务是使用`StringIndexerModel`估计器进行字符串索引，如下所示：

```scala
StringIndexerModel labelIndexer = new StringIndexer() 
          .setInputCol("label") 
          .setOutputCol("indexedLabel") 
          .fit(data); 

```

最后，将行数据集分割为训练和测试集（分别为 70%和 30%，但您应根据您的需求调整值），如下所示：

```scala
Dataset<Row>[] splits = data.randomSplit(new double[]{0.7, 0.3}); 
Dataset<Row> trainingData = splits[0]; 
Dataset<Row> testData = splits[1]; 

```

干得好！现在我们的数据集已经准备好训练模型了，对吧？暂时，我们会天真地选择一个分类器，比如说让我们使用决策树分类器来解决我们的目的。您可以根据第六章, *构建可扩展的机器学习管道*，第七章, *调整机器学习模型*，和 第八章, *调整您的机器学习模型*中提供的示例尝试其他多类分类器。

### 训练模型

如*图 2*所示，训练和测试数据将从原始数据中收集。在特征工程过程完成后，带有标签或评级的特征向量的 RDD 将在构建预测模型之前通过分类算法进行处理（如*图 6*所示），最后测试数据将用于测试模型的性能：

![训练模型](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00070.jpeg)

图 6：使用 Spark 进行监督学习

接下来，我们为决策树所需的参数值做准备。也许你会想为什么我们要谈论决策树。原因很简单，因为我们观察到使用决策树（即**二叉决策树**）相比朴素贝叶斯方法有更好的预测准确度。参考*表 2*，描述了分类特征及其重要性如下：

| **分类特征** | **映射** | **重要性** |
| --- | --- | --- |
| categoricalFeaturesInfo | 0 -> 31 | 指定特征索引 0（代表月份的天数）有 31 个类别[值{0，...，31}] |
| categoricalFeaturesInfo | 1 -> 7 | 表示一周的天数，并指定特征索引 1 有七个类别 |
| Carrier | 0 -> N | N 表示从 0 到不同航空公司的数量 |

表 2：分类特征及其重要性

现在我们将简要描述决策树构建的方法。我们将使用 CategoricalFeaturesInfo 来指定哪些特征是分类的，以及在树构建过程中每个特征可以取多少个分类值。这是一个从特征索引到该特征的类别数的映射。

然而，该模型是通过将输入特征与与这些特征相关联的标记输出进行关联来训练的。我们使用`DecisionTreeClassifier`方法训练模型，最终返回一个`DecisionTreeModel`，如*图 7*所示。构建树的详细源代码将在本节后面显示。

![训练模型](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00084.jpeg)

图 7：为航班延误分析生成的二叉决策树（部分显示）

**步骤 1：训练决策树模型**

要训练决策树分类器模型，我们需要有必要的标签和特征：

```scala
DecisionTreeClassifier dt = new DecisionTreeClassifier() 
      .setLabelCol("indexedLabel") 
      .setFeaturesCol("indexedFeatures"); 

```

**步骤 2：将索引标签转换回原始标签**

要创建决策树管道，我们需要除了索引标签之外的原始标签。因此，让我们按照以下方式进行：

```scala
IndexToString labelConverter = new IndexToString() 
      .setInputCol("prediction") 
      .setOutputCol("predictedLabel")         
        .setLabels(labelIndexer.labels());  

```

**步骤 3：将索引器和树链接成一个单一管道**

创建一个新的管道，其中阶段如下：`labelIndexer`，`featureIndexer`，`dt`，`labelConverter`如下：

```scala
Pipeline pipeline = new Pipeline() 
      .setStages(new PipelineStage[]{labelIndexer,  
        featureIndexer, dt, labelConverter}); 

```

现在使用我们在*步骤 8*中创建的训练集来拟合管道如下：

```scala
PipelineModel model = pipeline.fit(trainingData); 

```

### 测试模型

在接下来的步骤中，我们将测试模型：

**步骤 1：对测试数据集进行预测**

通过转换`PipelineModel`对测试集进行预测，并显示性能参数如下：

```scala
Dataset<Row> predictions = model.transform(testData); 
predictions.select("predictedLabel", "label", "features").show(5); 

```

**步骤 2：评估模型**

通过多类分类评估器评估模型，并打印准确度和测试错误如下：

```scala
MulticlassClassificationEvaluator evaluator = new MulticlassClassificationEvaluator() 
      .setLabelCol("indexedLabel") 
      .setPredictionCol("prediction") 
      .setMetricName("accuracy"); 
    double accuracy = evaluator.evaluate(predictions); 
    System.out.println("accuracy: "+accuracy); 
    System.out.println("Test Error = " + (1.0 - accuracy)); 

```

前面的代码段生成了分类准确度和测试错误如下：

```scala
Accuracy: 0.7540472721385786 
Test Error = 0.24595272786142142 

```

请注意，由于我们随机将数据集分成训练集和测试集，你可能会得到不同的结果。分类准确度为 75.40%，这并不好，我们认为。

现在轮到你使用不同的分类器和调整模型了。有关调整 ML 模型的更多详细讨论将在第七章中进行，*调整机器学习模型*。

**步骤 3：打印决策树**

以下是打印决策树的代码：

```scala
DecisionTreeClassificationModel treeModel = 
      (DecisionTreeClassificationModel) (model.stages()[2]); 
System.out.println("Learned classification tree model:\n" + treeModel.toDebugString()); 

```

此代码段生成一个决策树，如*图 7*所示。

**步骤 4：停止 Spark 会话**

使用 Spark 的`stop()`方法停止 Spark 会话如下：

```scala
spark.stop();
```

这是一个很好的做法，你要正确启动和关闭或停止 Spark 会话，以避免应用程序中的内存泄漏。

# 无监督学习

在无监督学习中，数据点没有与之相关的标签；因此，我们需要通过算法给它们贴上标签。换句话说，在无监督学习中，训练数据集的正确类别是未知的。

因此，必须从非结构化数据集中推断出类别，这意味着无监督学习算法的目标是通过描述其结构以某种结构化方式预处理数据。无监督学习算法或技术的主要目标是探索大多数未标记的输入数据的未知模式。这样，它与理论和应用统计学中使用的密度估计问题密切相关。

然而，无监督学习还包括许多其他技术，以总结和解释数据的关键特征，包括用于发现这些隐藏模式的探索性数据分析，甚至对数据点或特征进行分组，并根据数据挖掘方法应用无监督学习技术进行数据预处理。

为了克服无监督学习中的这一障碍，通常使用聚类技术根据某些相似性度量对未标记的样本进行分组，挖掘隐藏的模式以进行特征学习。

### 提示

要深入了解理论知识，了解无监督算法的工作原理，请参考以下三本书：Bousquet, O.; von Luxburg, U.; Raetsch, G., eds. (2004). *Advanced Lectures on Machine Learning*. Springer-Verlag. ISBN 978-3540231226。或者 Duda, Richard O.; Hart, Peter E.; Stork, David G. (2001). *Unsupervised Learning and Clustering*. *Pattern Classification (2nd Ed.)*. Wiley. ISBN 0-471-05669-3 和 Jordan, Michael I.; Bishop, Christopher M. (2004). *Neural Networks*. In Allen B. Tucker. Computer *Science Handbook, Second Edition (Section VII: Intelligent Systems)*. Boca Raton, FL: Chapman & Hall/CRC Press LLC. ISBN 1-58488-360-X。

## 无监督学习示例

在聚类中，算法通过分析输入示例之间的相似性将对象分组到类别中，其中相似的对象或特征被聚类并用圆圈标记。

聚类的用途包括：**搜索结果分组**，如客户分组，**异常检测**用于发现可疑模式，**文本分类**用于在测试中发现有用的模式，**社交网络分析**用于找到连贯的群体，**数据中心计算集群**用于找到将相关计算机放在一起以提高性能的方法，**天文数据分析**用于星系形成，以及**房地产数据分析**用于基于相似特征识别社区。此外，聚类使用无监督算法，事先没有输出。

使用 K 均值算法进行聚类是通过将所有坐标初始化为质心开始的。请注意，Spark 还支持其他聚类算法，如**高斯混合**，**幂迭代聚类**（**PIC**），**潜在狄利克雷分配**（**LDA**），二分 K 均值和流式 K 均值。而高斯混合主要用于期望最小化作为优化算法，另一方面，LDA 用于文档分类和聚类。PIC 用于根据边属性的成对相似性对图的顶点进行聚类。二分 K 均值比常规 K 均值更快，但通常会产生不同的聚类。因此，为了使讨论更简单，我们将在我们的目的中使用 K 均值算法。

有兴趣的读者应该参考 Spark ML 和基于 Spark MLlib 的聚类技术，分别在[`spark.apache.org/docs/latest/ml-clustering.html`](https://spark.apache.org/docs/latest/ml-clustering.html)和[`spark.apache.org/docs/latest/mllib-clustering.html`](https://spark.apache.org/docs/latest/mllib-clustering.html)网页上获取更多见解。在算法的每次迭代中，根据某种距离度量，通常是**欧几里得距离**，每个点都被分配到其最近的质心。

请注意，还有其他计算距离的方法，例如，**切比雪夫距离**用于仅考虑最重要的维度来测量距离。**汉明距离算法**用于逐位识别两个字符串的不同。**马哈 alanobis 距离**用于将协方差矩阵标准化，使距离度量在尺度上不变。

**曼哈顿距离**用于仅遵循轴对齐方向的距离。**闵可夫斯基距离算法**用于使欧几里德距离、曼哈顿距离和切比雪夫距离泛化。**Haversine 距离**用于测量球面上两点之间的大圆距离，根据它们的经度和纬度。考虑这些距离测量算法，很明显，欧几里得距离算法将是解决我们问题最合适的方法。

然后更新质心为该通行中分配给它的所有点的中心。这一过程重复，直到中心发生最小变化。K 均值算法是一个迭代算法，分为两步：

+   **簇分配步骤**：该算法将遍历每个数据点，并根据它离哪个质心更近来分配该质心，进而分配它代表的簇。

+   **移动质心步骤**：该算法将取每个质心并将其移动到簇中数据点的平均值

### 使用 Spark 进行无监督学习-一个例子

我们将使用从 URL [`course1.winona.edu/bdeppa/Stat%20425/Datasets.html`](http://course1.winona.edu/bdeppa/Stat%20425/Datasets.html) 下载的*Saratoga NY Homes*来演示使用 Java 中的 Spark 作为无监督学习技术的聚类的一个例子。数据集包含以下几个特征：价格、地块大小、水边、年龄、土地价值、新建、中央空调、燃料类型、加热类型、下水道类型、居住面积、大学百分比、卧室、壁炉、浴室和房间数量。然而，在这些列中，我们只在*表 3*中显示了一些选择的列。请注意，原始数据集是下载的，后来转换为相应的文本文件作为制表符分隔符：

| **价格** | **地块大小** | **水边** | **年龄** | **土地价值** | **房间** |
| --- | --- | --- | --- | --- | --- |
| 132500 | 0.09 | 0 | 42 | 5000 | 5 |
| 181115 | 0.92 | 0 | 0 | 22300 | 6 |
| 109000 | 0.19 | 0 | 133 | 7300 | 8 |
| 155000 | 0.41 | 0 | 13 | 18700 | 5 |
| 86060 | 0.11 | 0 | 0 | 15000 | 3 |
| 120000 | 0.68 | 0 | 31 | 14000 | 8 |
| 153000 | 0.4 | 0 | 33 | 23300 | 8 |
| 170000 | 1.21 | 0 | 23 | 146000 | 9 |
| 90000 | 0.83 | 0 | 36 | 222000 | 8 |
| 122900 | 1.94 | 0 | 4 | 212000 | 6 |
| 325000 | 2.29 | 0 | 123 | 126000 | 12 |

表 3：来自“Saratoga NY Homes”数据集的样本数据

我们进一步仅使用前两个特征（即价格和地块大小），以简化前一章中介绍的 Spark 特征学习算法。我们的目标是基于这两个特征对位于同一区域的房屋可能的邻域进行探索性分析。首先，看一下基于数据集中的值的基本散点图：

![使用 Spark 进行无监督学习-一个例子](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00014.jpeg)

图 8：邻域的簇

很明显，在*图 8*中标有圆圈的图中有四个簇。然而，确定簇的数量是一项棘手的任务。在这里，我们有视觉检查的优势，这对于超平面或多维数据上的数据是不可用的。现在我们需要使用 Spark 找到相同的结果。为简单起见，我们将使用 Spark 的 K 均值聚类 API。原始数据的使用和查找特征向量如*图 9*所示：

![使用 Spark 进行无监督学习-一个例子](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00015.jpeg)

图 9：使用 Spark 进行无监督学习

### 邻域的 K 均值聚类

在执行特征提取之前，我们需要加载和解析 Saratoga NY Homes 数据集。这一步还包括：加载包和相关依赖项，将数据集读取为 RDD，模型训练和预测，收集本地解析的数据，并进行聚类比较。

**步骤 1：导入统计和相关类**

以下是导入统计和相关类的代码：

```scala
import java.io.Serializable; 
import java.util.List; 
import org.apache.spark.api.java.JavaRDD; 
import org.apache.spark.api.java.function.Function; 
import org.apache.spark.mllib.clustering.KMeans; 
import org.apache.spark.mllib.clustering.KMeansModel; 
import org.apache.spark.mllib.linalg.Vector; 
import org.apache.spark.mllib.linalg.Vectors; 
import org.apache.spark.rdd.RDD; 
import org.apache.spark.sql.SparkSession;  

```

**步骤 2：创建 Spark 会话**

以下是创建 Spark 会话的代码：

```scala
  static SparkSession spark = SparkSession 
      .builder().appName("JavaLDAExample") 
      .master("local[*]") 
      .config("spark.sql.warehouse.dir", "E:/Exp/") 
      .getOrCreate(); 

```

**步骤 3：加载 Saratoga NY Homes.txt**

从数据集中读取、解析和创建 RDD：

```scala
RDD<String> data = spark.sparkContext().textFile("input/Saratoga_ NY_Homes.txt", 2); 

```

**步骤 4：将数据转换为密集向量的 RDD**

如果您仔细遵循前面的步骤，实际上我们已经创建了普通的 RDD。因此，在将其映射为密集向量之前，该 RDD 必须转换为相应的`JavaRDD`：

```scala
JavaRDD<Vector> parsedData = data.toJavaRDD().map(new Function<String, Vector>() { 
      @Override 
      public Vector call(String s) throws Exception { 
        String[] sarray = s.split(","); 
        double[] values = new double[sarray.length]; 
        for (int i = 0; i < sarray.length; i++) 
          values[i] = Double.parseDouble(sarray[i]); 
        return Vectors.dense(values); 
      } 
    });  

```

**步骤 5：训练模型**

通过指定四个聚类和五次迭代来训练模型。只需参考以下代码来执行：

```scala
int numClusters = 4; 
int numIterations = 10; 
int runs = 2; 
KMeansModel clusters = KMeans.train(parsedData.rdd(), numClusters, numIterations, runs , KMeans.K_MEANS_PARALLEL());  
Now estimate the cost to compute the clsuters as follows: 
double cost = clusters.computeCost(parsedData.rdd()); 
System.out.println("Cost: " + cost);  

```

您应该收到以下结果：

```scala
Cost: 3.60148995801542E12   

```

**步骤 6：显示聚类中心**

```scala
Vector[] centers = clusters.clusterCenters(); 
System.out.println("Cluster Centers: "); 
for (Vector center : centers)  
{ 
  System.out.println(center); 
} 

```

前面的代码应该产生如下的聚类中心：

```scala
[545360.4081632652,0.9008163265306122,0.1020408163265306,21.73469387755102,111630.61224489794,0.061224489795918366,0.7551020408163265,2.3061224489795915,2.1632653061224487,2.714285714285714,2860.755102040816,59.346938775510196,3.510204081632653,1.1020408163265305,2.714285714285714,10.061224489795917] 
[134073.06845637583,0.3820000000000002,0.0026845637583892616,33.72617449664429,19230.76510067114,0.012080536912751677,0.22818791946308722,2.621476510067114,2.7234899328859057,2.6630872483221477,1332.9234899328858,52.86040268456375,2.7395973154362414,0.38120805369127514,1.4946308724832214,5.806711409395973] 
[218726.0625,0.5419711538461538,0.0,25.495192307692307,32579.647435897434,0.041666666666666664,0.3830128205128205,2.3205128205128203,2.4615384615384617,2.692307692307692,1862.3076923076922,57.4599358974359,3.3894230769230766,0.7019230769230769,2.032852564102564,7.44551282051282] 
[332859.0580645161,0.6369354838709671,0.025806451612903226,19.803225806451614,63188.06451612903,0.13870967741935483,0.6096774193548387,2.2225806451612904,2.2483870967741937,2.774193548387097,2378.4290322580646,57.66774193548387,3.6225806451612903,0.8516129032258064,2.479032258064516,8.719354838709677] 

```

**步骤 7：评估模型错误率**

```scala
double WSSSE = clusters.computeCost(parsedData.rdd()); 
System.out.println("Within Set Sum of Squared Errors = " + WSSSE); 

```

这应该产生如下结果：

```scala
Within Set Sum of Squared Errors = 3.60148995801542E12 

```

**步骤 8：预测第二个元素的聚类**

```scala
List<Vector> houses = parsedData.collect(); 
int prediction  = clusters.predict(houses.get(18)); 
System.out.println("Prediction: "+prediction);  

```

输出预测：0

**步骤 9：停止 Spark 会话**

使用`stop()`方法停止 Spark 会话如下：

```scala
spark.stop(); 

```

**步骤 10：聚类比较**

现在让我们比较 k-means 与我们单独完成的聚类分配。k-means 算法从 0 开始给出聚类 ID。一旦您检查数据，您会发现我们在表 4 中给出的 A 到 D 聚类 ID 与 k-means 之间的以下映射：

| **聚类名称** | **聚类编号** | **聚类分配** |
| --- | --- | --- |
| A | 3 | A=>3 |
| B | 1 | B=>1 |
| C | 0 | C=>0 |
| D | 2 | D=>2 |

表 4：邻域 k-means 聚类示例的聚类分配

现在，让我们从图表的不同部分挑选一些数据，并预测它属于哪个聚类。让我们看一下房屋（以 1 为例）的数据，它的占地面积为 876 平方英尺，售价为 65.5 万美元：

```scala
int prediction  = clusters.predict(houses.get(18)); 
    System.out.println("Prediction: "+prediction); 

```

[输出] 预测：2

这意味着具有前述属性的房屋属于聚类 2。当然，您可以通过更多数据测试预测能力。让我们进行一些邻域分析，看看这些聚类承载着什么含义。我们可以假设聚类 3 中的大多数房屋都靠近市中心。例如，聚类 2 中的房屋位于多山的地形上。

在这个例子中，我们处理了一组非常少的特征；常识和视觉检查也会导致我们得出相同的结论。然而，如果您想获得更准确的结果，当然，您应该构建更有意义的特征，不仅考虑占地面积和房价，还要考虑其他特征，如房间数量、房龄、土地价值、供暖类型等。

然而，将*滨水*作为一个有意义的特征是不明智的，因为在这个例子中没有房子的前面有水上花园。我们将在下一章节中对更准确地预测的更有意义的特征的准确性进行详细分析。

k-means 算法的美妙之处在于它可以对具有无限特征的数据进行聚类。当您有原始数据并想了解数据中的模式时，这是一个很好的工具。然而，在进行实验之前决定聚类的数量可能不成功，有时可能会导致过拟合问题或欠拟合问题。

### 提示

为了克服 K 均值的上述局限性，我们有一些更健壮的算法，如**马尔可夫链蒙特卡洛**（MCMC，也见[`en.wikipedia.org/wiki/Markov_chain_Monte_Carlo`](https://en.wikipedia.org/wiki/Markov_chain_Monte_Carlo)）在 Tribble, Seth D.，*Markov chain Monte Carlo algorithms using completely uniformly distributed driving sequences*，2007 年斯坦福大学博士论文中提出。此外，更多技术讨论可以在[`www.autonlab.org/tutorials/kmeans11.pdf`](http://www.autonlab.org/tutorials/kmeans11.pdf)的网址中找到。

# 推荐系统

推荐系统是一种原始的杀手级应用程序，是信息过滤系统的一个子类，旨在预测用户通常对项目提供的评分或偏好。推荐系统的概念近年来变得非常普遍，并随后被应用于不同的应用程序。最流行的可能是产品（例如电影、音乐、书籍、研究文章）、新闻、搜索查询、社交标签等。推荐系统可以分为四类，如第二章中所述，*机器学习最佳实践*。这些显示在*图 10*中：

+   **协同过滤系统**：这是根据行为模式的相似性累积消费者的偏好和对其他用户的推荐**基于内容的系统**：这里使用监督机器学习来说服分类器区分用户感兴趣和不感兴趣的项目

+   **混合推荐系统**：这是最近的研究和混合方法（即，结合协同过滤和基于内容的过滤）

+   **基于知识的系统**：这里使用关于用户和产品的知识来理解用户的需求，使用感知树、决策支持系统和基于案例的推理：![推荐系统](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00028.jpeg)

图 10：推荐系统的层次结构

从技术角度来看，我们可以进一步将它们分类如下：

+   物品**层次结构**是最弱的，它天真地假设一个物品与另一个物品相关，例如，如果你买了打印机，你更有可能购买墨水。之前**BestBuy**使用过这种方法

+   **基于属性的推荐**：假设你喜欢史泰龙主演的动作电影，因此你可能会喜欢兰博系列。Netflix 曾经使用过这种方法

+   **协同过滤**（用户-用户相似性）：假设并且举例说，那些像你一样购买了婴儿奶粉的人也购买了尿布。Target 使用这种方法

+   **协同过滤**（物品-物品相似性）：假设并且举例说，喜欢教父系列的人也喜欢《疤面煞星》。Netflix 目前使用这种方法

+   **社交、兴趣和基于图的方法**：例如，假设喜欢迈克尔·杰克逊的朋友也会喜欢《Just Beat It》。像**LinkedIn**和**Facebook**这样的科技巨头使用这种方法

+   **基于模型的方法**：这使用高级算法，如**SVM**、**LDA**和**SVD**基于隐含特征

如*图 11*所示，基于模型的推荐系统广泛使用高级算法，如 SVM、LDA 或 SVD，是推荐系统类中最健壮的方法：

![推荐系统](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00029.jpeg)

图 11：从技术角度看的推荐系统

## Spark 中的协同过滤

如前所述，协同过滤技术通常用于推荐系统。然而，Spark MLlib 目前仅支持基于模型的协同过滤。在这里，用户和产品由一小组潜在因素描述。这些潜在因素后来用于预测缺失的条目。根据 Spark API 参考协同过滤[`spark.apache.org/docs/latest/mllib-collaborative-filtering.html`](http://spark.apache.org/docs/latest/mllib-collaborative-filtering.html)：**交替最小二乘法**（**ALS**）（也称为非线性最小二乘法，即 NLS；更多信息请参见[`en.wikipedia.org/wiki/Non-linear_least_squares`](https://en.wikipedia.org/wiki/Non-linear_least_squares)）算法用于通过考虑以下参数来学习这些潜在因素：

+   `numBlocks`是使用本机 LAPACK 进行并行计算的块数

+   `rank`是在构建机器学习模型期间的潜在因素的数量

+   `iterations`是需要进行更准确预测的迭代次数

+   `lambda`表示 ALS 算法的正则化参数

+   `implicitPrefs`指定要使用的反馈（显式反馈 ALS 变体或适用于隐式反馈数据的变体）

+   `alpha`指定 ALS 算法中偏好观察的基线置信度

首先，ALS 是一种迭代算法，用于将评分矩阵建模为低秩用户和产品因子的乘积。之后，通过最小化观察到的评分的重建误差来使用这些因子进行学习任务。

然而，未知的评分可以通过将这些因素相乘来逐步计算。在 Spark MLlib 中使用的协同过滤技术进行的移动推荐或其他推荐的方法已被证明是一个高性能的方法，具有高预测准确性，并且可扩展到像 Netflix 这样的公司使用的商品集群上的数十亿个评分。按照这种方式，Netflix 这样的公司可以根据预测的评分向其订阅者推荐电影。最终目标是增加销售额，当然也包括客户满意度。

为了简洁和页面限制，我们将不在本章中展示使用协同过滤方法进行电影推荐。但是，将在第九章中展示使用 Spark 的逐步示例，*流式数据和图数据的高级机器学习*。

### 提示

目前，建议感兴趣的读者访问 Spark 网站获取最新的 API 和相同代码，网址为：[`spark.apache.org/docs/latest/mllib-collaborative-filtering.html`](http://spark.apache.org/docs/latest/mllib-collaborative-filtering.html)，其中提供了一个示例，展示了使用 ALS 算法进行样本电影推荐。

# 高级学习和泛化

在本节中，我们将讨论一些学习的高级方面，例如如何将监督学习技术泛化为半监督学习、主动学习、结构化预测和强化学习。此外，将简要讨论强化学习和半监督学习。

## 监督学习的泛化

标准监督学习问题可以泛化的几种方式：

+   **半监督学习**：在这种泛化技术中，仅为所选特征的一部分训练数据提供所需的输出值，以构建和评估机器学习模型。另一方面，其余数据保持不变或未标记。

+   **主动学习**：相比之下，在主动学习中，算法通常通过向人类用户提出查询来交互地收集新特征，而不是假设所有训练特征都已给出。因此，这里使用的查询是基于未标记数据的。有趣的是，这也是将半监督学习与主动学习相结合的一个例子。

+   **结构化预测**：有时需要从复杂对象（如解析树或带标签的图）中提取或选择所需的特征，然后必须改进标准监督或无监督方法以使其适应于泛化。更准确地说，例如，当监督机器学习技术尝试预测结构化或非结构化文本时，如将自然语言处理句子翻译成句法表示时，需要处理大规模解析树的结构化预测。为了简化这个任务，通常使用结构化 SVM 或马尔可夫逻辑网络或受限条件模型，这些技术上扩展和更新了经典的监督学习算法。

+   **学习排名**：当输入本身是对象的子集并且期望的输出是这些对象的排名时，必须类似于结构预测技术来扩展或改进标准方法。

### 提示

感兴趣的读者可以参考以下两个网址：[`en.wikipedia.org/wiki/Learning_to_rank`](https://en.wikipedia.org/wiki/Learning_to_rank) 和 [`en.wikipedia.org/wiki/Structured_prediction`](https://en.wikipedia.org/wiki/Structured_prediction)，在这里可以找到更详细的讨论。

# 总结

我们已经从理论和 Spark 的角度讨论了一些监督、无监督和推荐系统。然而，监督、无监督、强化或推荐系统也有许多例子。尽管如此，我们已经尽力提供一些简单的例子以求简单。

我们将在第六章*构建可扩展的机器学习管道*中提供更多关于这些示例的见解。还将讨论使用 Spark ML 和 Spark MLlib 管道进行更多特征合并、提取、选择、模型扩展和调整。我们还打算提供一些包括数据收集到模型构建和预测的示例。


# 第六章： 构建可扩展的机器学习管道

机器学习的最终目标是使机器能够自动从数据中构建模型，而无需繁琐和耗时的人类参与和交互。 因此，本章将指导读者通过使用 Spark MLlib 和 Spark ML 创建一些实用和广泛使用的机器学习管道和应用。 将详细描述这两个 API，并且还将为两者都涵盖一个基线用例。 然后，我们将专注于扩展 ML 应用程序，以便它可以应对不断增加的数据负载。 阅读本章的所有部分后，读者将能够区分这两个 API，并选择最适合其要求的 API。 简而言之，本章将涵盖以下主题：

+   Spark 机器学习管道 API

+   使用 Spark Core 进行癌症诊断管道

+   使用 Spark 进行癌症预后管道

+   使用 Spark Core 进行市场篮子分析

+   Spark 中的 OCR 管道

+   使用 Spark MLlib 和 ML 进行主题建模

+   使用 Spark 进行信用风险分析管道

+   扩展 ML 管道

+   提示和性能考虑

# Spark 机器学习管道 API

MLlib 的目标是使实用的机器学习（ML）可扩展且易于使用。 Spark 引入了管道 API，用于轻松创建和调整实用的 ML 管道。 如第四章中所讨论的，实用的 ML 管道涉及一系列数据收集，预处理，特征提取，特征选择，模型拟合，验证和模型评估阶段。 例如，对文档进行分类可能涉及文本分割和清理，提取特征以及使用交叉验证训练分类模型。 大多数 ML 库都不是为分布式计算而设计的，或者它们不提供管道创建和调整的本地支持。

## 数据集抽象

如第一章中所述，当在另一种编程语言中运行 SQL 时，结果将返回为 DataFrame。 DataFrame 是一个分布式的数据集合，组织成命名列。 另一方面，数据集是一种接口，试图提供 Spark SQL 中 RDD 的好处。

数据集可以由 JVM 对象构建，这些对象可以在 Scala 和 Java 中使用。 在 Spark 管道设计中，数据集由 Spark SQL 的数据集表示。 ML 管道涉及一系列数据集转换和模型。 每个转换都接受输入数据集并输出转换后的数据集，这成为下一阶段的输入。

因此，数据导入和导出是 ML 管道的起点和终点。 为了使这些更容易，Spark MLlib 和 Spark ML 提供了一些特定于应用程序的类型的数据集，DataFrame，RDD 和模型的导入和导出实用程序，包括：

+   用于分类和回归的 LabeledPoint

+   用于交叉验证和潜在狄利克雷分配（LDA）的 LabeledDocument

+   协同过滤的评分和排名

然而，真实数据集通常包含许多类型，例如用户 ID，项目 ID，标签，时间戳和原始记录。

不幸的是，当前的 Spark 实现工具无法轻松处理包含这些类型的数据集，特别是时间序列数据集。如果您回忆起第四章中的*机器学习管道-概述*部分，*通过特征工程提取特征*，特征转换通常占据实际 ML 管道的大部分。特征转换可以被视为从现有列创建新列或删除新列。

在*图 1*中，*用于机器学习模型的文本处理*，您将看到文本标记器将文档分解为一袋词。之后，TF-IDF 算法将一袋词转换为特征向量。在转换过程中，标签需要被保留以用于模型拟合阶段：

![数据集抽象](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00034.jpeg)

图 1：用于机器学习模型的文本处理（DS 表示数据源）

如果您回忆起第四章中的*图 5*和*图 6*，*通过特征工程提取特征*，在转换步骤中，ID、文本和单词都被让步。它们在进行预测和模型检查时非常有用。但是，它们实际上对于模型拟合来说是不必要的。根据 Databricks 关于 ML 管道的博客[`databricks.com/blog/2015/01/07/ml-pipelines-a-new-high-level-api-for-mllib.html`](https://databricks.com/blog/2015/01/07/ml-pipelines-a-new-high-level-api-for-mllib.html)，如果预测数据集只包含预测标签，它并没有提供太多信息。

因此，如果您想检查预测指标，如准确性、精确度、召回率、加权真正例和加权假正例，查看预测标签以及原始输入文本和标记化单词是非常有用的。相同的建议也适用于使用 Spark ML 和 Spark MLlib 的其他机器学习应用。

因此，已经实现了在内存、磁盘或外部数据源（如 Hive 和 Avro）之间进行 RDD、数据集和数据框之间的简单转换。虽然使用用户定义的函数从现有列创建新列很容易，但数据集的表现是一种延迟操作。

相比之下，数据集仅支持一些标准数据类型。然而，为了增加可用性并使其更适合机器学习模型，Spark 还添加了对向量类型的支持，作为一种支持密集和稀疏特征向量的用户定义类型，支持`mllib.linalg.DenseVector`和`mllib.linalg.Vector`。

### 提示

可以在 Spark 分发的`examples/src/main/`文件夹下找到 Java、Scala 和 Python 的完整 DataFrame、Dataset 和 RDD 示例。感兴趣的读者可以参考 Spark SQL 的用户指南[`spark.apache.org/docs/latest/sql-programming-guide.html`](http://spark.apache.org/docs/latest/sql-programming-guide.html)了解更多关于 DataFrame、Dataset 以及它们支持的操作。

## 管道

Spark 在 Spark ML 下提供了管道 API。如前所述，管道由一系列阶段组成，包括转换器和估计器。管道阶段有两种基本类型，称为转换器和估计器。

转换器将数据集作为输入，并产生增强的数据集作为输出，以便将输出馈送到下一步。例如，**Tokenizer**和**H**ashingTF****是两个转换器。 Tokenizer 将具有文本的数据集转换为具有标记化单词的数据集。另一方面，HashingTF 产生术语频率。标记化和 HashingTF 的概念通常用于文本挖掘和文本分析。

相反，估计器必须是输入数据集的第一个，以产生模型。在这种情况下，模型本身将被用作转换器，将输入数据集转换为增强的输出数据集。例如，在拟合训练数据集与相应的标签和特征之后，可以使用**逻辑回归**或线性回归作为估计器。

之后，它产生一个逻辑或线性回归模型。这意味着开发管道是简单而容易的。好吧，你所需要做的就是声明所需的阶段，然后配置相关阶段的参数；最后，将它们链接在一个管道对象中，如*图 2*所示：

![管道](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00068.jpeg)

图 2：使用逻辑回归估计器的 Spark ML 管道模型（DS 表示数据存储，虚线内的步骤仅在管道拟合期间发生）

如果您看一下*图 2*，拟合模型由分词器、哈希 TF 特征提取器和拟合的逻辑回归模型组成。拟合的管道模型充当了可以用于预测、模型验证、模型检查和最终模型部署的转换器。然而，为了提高预测准确性，模型本身需要进行调整。我们将在第七章*调整机器学习模型*中更多地讨论如何调整机器学习模型。

为了更实际地展示流水线技术，以下部分展示了如何使用 Spark ML 和 MLlib 创建癌症诊断的实际管道。

# 使用 Spark 的癌症诊断管道

在本节中，我们将看看如何使用 Spark ML 和 MLlib 开发癌症诊断管道。将使用真实数据集来预测乳腺癌的概率，这种癌症几乎是可以治愈的，因为这种癌症类型的罪魁祸首基因已经成功地被确定。然而，我们想要讨论一下这种癌症类型，因为在非洲和亚洲的第三世界国家，它仍然是一种致命疾病。

### 提示

我们建议读者对这种疾病的结果或状态保持开放的态度，因为我们将展示 Spark ML API 如何通过整合和组合来自威斯康星乳腺癌（原始）、威斯康星诊断乳腺癌（WDBC）和威斯康星预后乳腺癌（WPBC）数据集的数据来预测癌症，这些数据集来自以下网站：[`archive.ics.uci.edu/ml`](http://archive.ics.uci.edu/ml)。

## Spark 乳腺癌诊断管道

在本小节中，我们将开发一个逐步的癌症诊断管道。步骤包括对乳腺癌的背景研究、数据集收集、数据探索、问题形式化和基于 Spark 的实现。

### 背景研究

根据 Salama 等人的研究（*使用多分类器在三个不同数据集上进行乳腺癌诊断，国际计算机和信息技术杂志*（*2277-0764*）*第 01-01 期，2012 年 9 月*），乳腺癌在 20 至 29 岁的女性中排名第四，仅次于甲状腺癌、黑色素瘤和淋巴瘤。

乳腺癌是由乳腺组织突变引起的，原因包括性别、肥胖、酒精、家族史、缺乏体育锻炼等。此外，根据**疾病控制和预防中心**（**TCDCP**）的统计数据（[`www.cdc.gov/cancer/breast/statistics/`](https://www.cdc.gov/cancer/breast/statistics/)），2013 年，美国共有 230,815 名妇女和 2,109 名男性被诊断出患有乳腺癌。不幸的是，40,860 名妇女和 464 名男性死于此病。

研究发现，约 5-10%的病例是由父母的一些遗传因素引起的，包括 BRCA1 和 BRCA2 基因突变等。早期诊断可以帮助拯救全球数千名乳腺癌患者。尽管罪魁祸首基因已经被确定，但化疗并不十分有效。基因沉默正在变得流行，但需要更多的研究。

正如前面提到的，机器学习中的学习任务严重依赖分类、回归和聚类技术。此外，传统的数据挖掘技术正在与这些机器学习技术一起应用，这是最基本和重要的任务。因此，通过与 Spark 集成，这些应用技术在生物医学数据分析领域得到了广泛的接受和应用。此外，正在使用多类和多级分类器和特征选择技术对生物医学数据集进行大量实验，以进行癌症诊断和预后。

### 数据集收集

**癌症基因组图谱**（**TCGA**），**癌症体细胞突变目录**（**COSMIC**），**国际癌症基因组联盟**（**ICGC**）是最广泛使用的癌症和肿瘤相关数据集，用于研究目的。这些数据来源已经从麻省理工学院、哈佛大学、牛津大学等世界知名研究所进行了整理。然而，这些可用的数据集是非结构化的、复杂的和多维的。因此，我们不能直接使用它们来展示如何将大规模机器学习技术应用于它们。原因是这些数据集需要大量的预处理和清洗，这需要大量的页面。

通过练习这个应用程序，我们相信读者将能够将相同的技术应用于任何类型的生物医学数据集，用于癌症诊断。由于页面限制，我们应该使用结构化和手动策划的简单数据集，用于机器学习应用开发，当然，其中许多显示出良好的分类准确性。

例如，来自 UCI 机器学习库的威斯康星州乳腺癌数据集，可在[`archive.ics.uci.edu/ml`](http://archive.ics.uci.edu/ml)上找到，这些数据是由威斯康星大学的研究人员捐赠的，并包括来自乳腺肿块细针穿刺的数字图像的测量。这些值代表数字图像中细胞核的特征，如下一小节所述。

### 提示

关于威斯康星州乳腺癌数据的更多信息，请参考作者的出版物：*乳腺肿瘤诊断的核特征提取。IS＆T/SPIE 1993 年国际电子成像研讨会：科学与技术，卷 1905，第 861-870 页，作者为 W.N. Street，W.H. Wolberg 和 O.L. Mangasarian，1993 年*。

### 数据集描述和准备

如**威斯康星州乳腺癌数据集**（**WDBC**）手册所示，可在[`archive.ics.uci.edu/ml/machine-learning-databases/breast-cancer-wisconsin/wdbc.names`](https://archive.ics.uci.edu/ml/machine-learning-databases/breast-cancer-wisconsin/wdbc.names)上找到，肿块厚度良性细胞往往成片状分组，而癌细胞通常成多层分组。因此，在应用机器学习技术之前，手册中提到的所有特征和字段都很重要，因为这些特征将有助于确定特定细胞是否患癌。

乳腺癌数据包括 569 个癌症活检样本，每个样本有 32 个特征。一个特征是患者的识别号码，另一个是癌症诊断，标记为良性或恶性，其余的是数值型的生物测定，是在分子实验室工作中确定的。诊断编码为 M 表示恶性或 B 表示良性。

类别分布如下：良性：357（62.74%）和恶性：212（37.25%）。训练和测试数据集将按照此处给出的数据集描述进行准备。30 个数值测量包括均值、标准误差和最坏值，即三个最大值的均值。字段 3 是均值半径，13 是半径 SE，23 是最坏半径。通过对数字化的细胞核的不同特征进行计算，为每个细胞核计算了 10 个实值特征，这些特征描述在*表 1，10 个实值特征及其描述*中：

| **编号** | **数值** | **解释** |
| --- | --- | --- |
| 1 | 半径 | 中心到周边点的距离的平均值 |
| 2 | 纹理 | 灰度值的标准偏差 |
| 3 | 周长 | 细胞核的周长 |
| 4 | 面积 | 细胞核覆盖周长的面积 |
| 5 | 光滑度 | 半径长度的局部变化 |
| 6 | 紧凑性 | 计算如下：(周长)² / 面积 - 1.0 |
| 7 | 凹度 | 轮廓凹陷部分的严重程度 |
| 8 | 凹点 | 轮廓的凹陷部分的数量 |
| 9 | 对称性 | 表示细胞结构是否对称 |
| 10 | 分形维数 | 计算如下：海岸线近似 - 1 |

表 1：10 个实值特征及其描述

所有特征值都记录了四个有效数字，没有缺失或空值。因此，我们不需要进行任何数据清理。但是，从前面的描述中，很难让某人获得有关数据的任何良好知识。例如，除非您是肿瘤学家，否则您不太可能知道每个字段与良性或恶性肿块的关系。随着我们继续进行机器学习过程，这些模式将被揭示。数据集的样本快照如*图 3*所示：

![数据集描述和准备](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00115.jpeg)

图 3：数据快照（部分）

### 问题形式化

*图 4*，*乳腺癌诊断和预后管道模型*，描述了提出的乳腺癌诊断模型。该模型包括两个阶段，即训练和测试阶段：

+   训练阶段包括四个步骤：数据收集、预处理、特征提取和特征选择

+   测试阶段包括与训练阶段相同的四个步骤，另外还有分类步骤

在数据收集步骤中，首先进行预处理，以检查是否存在不需要的值或任何缺失值。我们已经提到没有缺失值。但是，检查是一种良好的做法，因为即使特殊字符的不需要值也可能中断整个训练过程。之后，通过特征提取和选择过程进行特征工程步骤，以确定适用于后续逻辑或线性回归分类器的正确输入向量：

![问题形式化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00105.jpeg)

图 4：乳腺癌诊断和预后管道模型

这有助于对与模式向量相关联的类做出决定。基于特征选择或特征提取，完成了降维技术。但是，请注意，我们不会使用任何正式的降维算法来开发这个应用程序。有关降维的更多信息，您可以参考第四章中的*降维*部分，*通过特征工程提取知识*。

在分类步骤中，应用逻辑回归分类器以获得肿瘤诊断和预后的最佳结果。

### 使用 Spark ML 开发癌症诊断管道

如前所述，在 WDBC 数据集中找到的属性的详细信息在[`archive.ics.uci.edu/ml/machine-learning-databases/breast-cancer-wisconsin/breast-cancer-wisconsin.names`](https://archive.ics.uci.edu/ml/machine-learning-databases/breast-cancer-wisconsin/breast-cancer-wisconsin.names)包括患者 ID、诊断（M = 恶性，B = 良性）和为每个细胞核计算的 10 个实值特征，如*表 1*、*10 个实值特征及其描述*所述。

这些特征是从乳腺肿块的**细针穿刺**（**FNA**）的数字化图像计算出来的，因为我们对数据集有足够的了解。在本小节中，我们将逐步看看如何开发乳腺癌诊断机器学习流水线，包括在*图 4*中描述的 10 个步骤中从数据集输入到预测的数据工作流程。

第 1 步：导入必要的包/库/API

这是导入包的代码：

```scala
import org.apache.spark.api.java.JavaRDD; 
import org.apache.spark.api.java.function.Function; 
import org.apache.spark.ml.Pipeline; 
import org.apache.spark.ml.PipelineModel; 
import org.apache.spark.ml.PipelineStage; 
import org.apache.spark.ml.classification.LogisticRegression; 
import org.apache.spark.ml.feature.LabeledPoint; 
import org.apache.spark.ml.linalg.DenseVector; 
import org.apache.spark.ml.linalg.Vector; 
import org.apache.spark.sql.Dataset; 
import org.apache.spark.sql.Row; 
import org.apache.spark.sql.SparkSession; 

```

第 2 步：初始化 Spark 会话

可以使用以下代码初始化 Spark 会话：

```scala
static SparkSession spark = SparkSession 
        .builder() 
        .appName("BreastCancerDetectionDiagnosis") 
       .master("local[*]") 
       .config("spark.sql.warehouse.dir", "E:/Exp/") 
       .getOrCreate();
```

在这里，我们将应用程序名称设置为`BreastCancerDetectionDiagnosis`，主 URL 设置为`local`。Spark 上下文是程序的入口点。请相应地设置这些参数。

第 3 步：将乳腺癌数据作为输入并准备 JavaRDD

这是准备`JavaRDD`的代码：

```scala
  String path = "input/wdbc.data"; 
  JavaRDD<String> lines = spark.sparkContext().textFile(path, 3).toJavaRDD();
```

要了解更多关于数据的信息，请参考*图 3*：*数据快照（部分）*。

第 4 步：为回归创建标记点 RDD

为诊断（B = 良性，M = 恶性）创建`LabeledPoint` RDDs：

```scala
JavaRDD<LabeledPoint> linesRDD = lines 
        .map(new Function<String, LabeledPoint>() { 
          public LabeledPoint call(String lines) { 
            String[] tokens = lines.split(","); 
            double[] features = new double[30]; 
            for (int i = 2; i < features.length; i++) { 
              features[i - 2] = Double.parseDouble(tokens[i]); 
            } 
            Vector v = new DenseVector(features); 
            if (tokens[1].equals("B")) { 
              return new LabeledPoint(1.0, v); // benign 
            } else { 
              return new LabeledPoint(0.0, v); // malignant 
            } 
          } 
        }); 

```

第 5 步：从 linesRDD 创建 Row 数据集并显示顶部特征

这是所示代码：

```scala
Dataset<Row> data = spark.createDataFrame(linesRDD,LabeledPoint.class); 
data.show(); 

```

以下图显示了顶部特征及其对应的标签：

![使用 Spark ML 开发癌症诊断流水线](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00161.jpeg)

图 5：顶部特征及其对应的标签

第 6 步：拆分数据集以准备训练和测试集

在这里，我们将原始数据框拆分为训练集和测试集，比例分别为 60%和 40%。在这里，`12345L`是种子值。这个值表示每次拆分都是相同的，这样 ML 模型在每次迭代中都会产生相同的结果。我们在每一章中都遵循相同的转换来准备测试和训练集：

```scala
Dataset<Row>[] splits = data.randomSplit(new double[] { 0.6, 0.4 }, 12345L); 
Dataset<Row> trainingData = splits[0]; 
Dataset<Row> testData = splits[1]; 

```

要快速查看这两个集合的快照，只需写`trainingData.show()`和`testData.show()`分别用于训练和测试集。

第 7 步：创建一个逻辑回归分类器

通过指定最大迭代次数和回归参数创建一个逻辑回归分类器：

```scala
LogisticRegression logisticRegression = new LogisticRegression() 
                          .setMaxIter(100) 
                             .setRegParam(0.01) 
                             .setElasticNetParam(0.4); 

```

### 提示

逻辑回归通常需要三个参数：最大迭代次数、回归参数和弹性网络正则化。请参考以下行以更清楚地了解：

```scala
      LogisticRegression lr = new 
      LogisticRegression().setMaxIter(100)
      .setRegParam(0.01).setElasticNetParam(0.4); 

```

### 提示

上述语句创建了一个逻辑回归模型`lr`，最大迭代次数为`100`，回归参数为`0.01`，弹性网络参数为`0.4`。

第 8 步：创建和训练流水线模型

这是所示代码：

```scala
Pipeline pipeline = new Pipeline().setStages(new PipelineStage[] {logisticRegression}); 
PipelineModel model = pipeline.fit(trainingData); 

```

在这里，我们创建了一个流水线，其阶段由逻辑回归阶段定义，这也是我们刚刚创建的一个估计器。请注意，如果您处理的是文本数据集，可以尝试创建分词器和 HashingTF 阶段。

然而，在这个癌症数据集中，所有的值都是数字。因此，我们不创建这样的阶段来链接到流水线。

第 9 步：创建数据集，转换模型和预测

创建一个类型为 Row 的数据集，并根据测试数据集进行预测转换模型：

```scala
Dataset<Row> predictions=model.transform(testData); 

```

第 10 步：显示预测及预测精度

```scala
predictions.show(); 
long count = 0; 
for (Row r : predictions.select("features", "label", "prediction").collectAsList()) { 
    System.out.println("(" + r.get(0) + ", " + r.get(1) + r.get(2) + ", prediction=" + r.get(2)); 
      count++; 
    } 

```

![使用 Spark ML 开发癌症诊断流水线](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00037.jpeg)

图 6：预测及预测精度

*图 7*显示了测试集的预测数据集。所示的打印方法本质上生成输出，就像下面的例子一样：

![使用 Spark ML 开发癌症诊断管道](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00155.jpeg)

图 7：朝向预测的样本输出。第一个值是特征，第二个是标签，最后一个值是预测值

现在让我们计算精度分数。我们通过将计数器乘以 100，然后除以完成的预测数量来做到这一点，如下所示：

```scala
System.out.println("precision: " + (double) (count * 100) / predictions.count()); 
Precision - 100.0 

```

因此，精度为 100%，这是很棒的。但是，如果您仍然不满意或有任何困惑，下一章将演示如何调整几个参数，以提高预测准确性，因为可能有许多假阴性预测。

此外，由于随机拆分的性质和您一侧的数据集处理，结果可能会有所不同。

# 使用 Spark 的癌症预后管道

在上一节中，我们展示了如何开发一个癌症诊断管道，用于基于两个标签（良性和恶性）预测癌症。在本节中，我们将看看如何使用 Spark ML 和 MLlib API 开发癌症预后管道。**威斯康星预后乳腺癌**（**WPBC**）数据集将用于预测乳腺癌的概率，以预测复发和非复发的肿瘤细胞。同样，数据集是从[`archive.ics.uci.edu/ml/datasets/Breast+Cancer+Wisconsin+(Prognostic)`](https://archive.ics.uci.edu/ml/datasets/Breast+Cancer+Wisconsin+(Prognostic))下载的。要了解问题的形式化，请再次参考*图 1*，因为在癌症预后管道开发过程中，我们将几乎遵循相同的阶段。

## 数据集探索

在[`archive.ics.uci.edu/ml/machine-learning-databases/breast-cancer-wisconsin/wpbc.names`](https://archive.ics.uci.edu/ml/machine-learning-databases/breast-cancer-wisconsin/wpbc.names)中找到的 WPBC 数据集的属性详细信息如下：

+   ID 编号

+   结果（R = 复发，N = 非复发）

+   时间（如果字段 2 => R，则为复发时间，如果字段 2 => N，则为无病时间）

+   3 到 33：为每个细胞核计算了十个实值特征：半径、纹理、周长、面积、光滑度、紧凑性、凹度、凹点、对称性和分形维度。三十四是肿瘤大小，三十五是淋巴结状态，如下所示：

+   肿瘤大小：切除肿瘤的直径（厘米）

+   淋巴结状态：阳性腋窝淋巴结的数量

如果您比较*图 3*和*图 9*，您会发现诊断和预后具有相同的特征，但预后有两个额外的特征（如前面提到的 34 和 35）。请注意，这些是在 1988 年至 1995 年手术时观察到的，在 198 个实例中，有 151 个是非复发（N），47 个是复发（R），如*图 8*所示。

当然，今天的真实癌症诊断和预后数据集以结构化或非结构化的方式包含许多其他特征和字段：

![数据集探索](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00079.jpeg)

图 8：数据快照（部分）

### 提示

对于更详细的讨论和有意义的见解，感兴趣的读者可以参考以下研究论文：*威斯康星乳腺癌问题：使用概率和广义回归神经分类器进行诊断和 DFS 时间预后，2005 年第四季度 Ioannis A.等人在以下链接中找到：*[`citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.65.2463&rep=rep1&type=pdf`](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.65.2463&rep=rep1&type=pdf)。

## 使用 Spark ML/MLlib 的乳腺癌预后管道

在本小节中，我们将逐步介绍如何开发乳腺癌预后机器学习管道，包括从数据集输入到预测的 10 个不同步骤，这些步骤在*图 1*中有描述，作为数据工作流。

### 提示

建议读者从 Packt 材料中下载数据集和项目文件，以及 Maven 项目配置的`pom.xml`文件。我们已经在之前的章节中介绍了如何使代码工作，例如第一章，*Spark 数据分析简介*。

**步骤 1：导入必要的包/库/API**

```scala
import org.apache.spark.api.java.JavaRDD; 
import org.apache.spark.api.java.function.Function; 
import org.apache.spark.ml.Pipeline; 
import org.apache.spark.ml.PipelineModel; 
import org.apache.spark.ml.PipelineStage; 
import org.apache.spark.ml.classification.LogisticRegression; 
import org.apache.spark.ml.feature.LabeledPoint; 
import org.apache.spark.ml.linalg.DenseVector; 
import org.apache.spark.ml.linalg.Vector; 
import org.apache.spark.sql.Dataset; 
import org.apache.spark.sql.Row; 
import org.apache.spark.sql.SparkSession; 

```

**步骤 2：初始化必要的 Spark 环境**

```scala
static SparkSession spark = SparkSession 
        .builder() 
        .appName("BreastCancerDetectionPrognosis") 
       .master("local[*]") 
       .config("spark.sql.warehouse.dir", "E:/Exp/") 
       .getOrCreate(); 

```

在这里，我们将应用程序名称设置为`BreastCancerDetectionPrognosis`，主 URL 设置为`local[*]`。Spark Context 是程序的入口点。请相应地设置这些参数。

**步骤 3：将乳腺癌数据作为输入并准备 JavaRDD 数据**

```scala
String path = "input/wpbc.data"; 
JavaRDD<String> lines = spark.sparkContext().textFile(path, 3).toJavaRDD(); 

```

### 提示

要了解更多关于数据的信息，请参考*图 5*及其描述以及数据集探索子部分。

**步骤 4：创建带标签的点 RDD**

使用以下代码段为 N=复发和 R=非复发的预后创建`LabeledPoint` RDD：

```scala
JavaRDD<LabeledPoint> linesRDD = lines.map(new Function<String, LabeledPoint>() { 
      public LabeledPoint call(String lines) { 
        String[] tokens = lines.split(","); 
        double[] features = new double[30]; 
        for (int i = 2; i < features.length; i++) { 
          features[i - 2] = Double.parseDouble(tokens[i]); 
        } 
        Vector v = new DenseVector(features); 
        if (tokens[1].equals("N")) { 
          return new LabeledPoint(1.0, v); // recurrent 
        } else { 
          return new LabeledPoint(0.0, v); // non-recurrent 
        } 
      } 
    });  

```

**步骤 5：从行 RDD 创建数据集并显示顶部特征**

```scala
Dataset<Row> data = spark.createDataFrame(linesRDD,LabeledPoint.class); 
data.show(); 

```

顶部特征及其相应标签显示在*图 9*中：

![使用 Spark ML/MLlib 进行乳腺癌预后管道](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00012.jpeg)

图 9：顶部特征及其相应标签

**步骤 6：将数据集拆分为训练集和测试集**

在这里，我们将数据集分为测试集和训练集，比例分别为 60%和 40%。请根据您的要求进行调整：

```scala
Dataset<Row>[] splits = data.randomSplit(new double[] { 0.6, 0.4 }, 12345L); 
Dataset<Row> trainingData = splits[0];   
Dataset<Row> testData = splits[1]; 

```

要快速查看这两个集合的快照，只需编写`trainingData.show()`和`testData.show()`，分别用于训练和测试集。

**步骤 7：创建逻辑回归分类器**

通过指定最大迭代次数和回归参数创建逻辑回归分类器：

```scala
LogisticRegression logisticRegression = new LogisticRegression() 
.setMaxIter(100) 
.setRegParam(0.01) 
.setElasticNetParam(0.4); 

```

**步骤 8：创建管道并训练管道模型**

```scala
Pipeline pipeline = new Pipeline().setStages(new PipelineStage[]{logisticRegression}); 
PipelineModel model=pipeline.fit(trainingData); 

```

在这里，类似于诊断管道，我们创建了预后管道，其阶段仅由逻辑回归定义，这又是一个估计器，当然也是一个阶段。

**步骤 9：创建数据集并转换模型**

创建数据集并进行转换，以基于测试数据集进行预测：

```scala
Dataset<Row> predictions=model.transform(testData); 

```

**步骤 10：显示预测及其精度**

```scala
predictions.show(); 

```

![使用 Spark ML/MLlib 进行乳腺癌预后管道](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00092.jpeg)

图 10：预测精度

```scala
long count = 0; 
for (Row r : predictions.select("features", "label", "prediction").collectAsList()) { 
      System.out.println("(" + r.get(0) + ", " + r.get(1) + r.get(2) + ", prediction=" + r.get(2)); 
      count++; 
    } 

```

这段代码将产生类似于*图 7*的输出，其中包含不同的特征、标签和预测：

```scala
System.out.println("precision: " + (double) (count * 100) / predictions.count());  
Precision: 100.0  

```

因此，精度几乎达到 100%，这是非常棒的。然而，根据数据准备的不同，你可能会得到不同的结果。

如果您有任何困惑，下一章将演示如何调整参数，以提高预测准确性，因为可能会有许多假阴性预测。

### 提示

在他们的书中《Machine Learning with R, Packt Publishing, 2015》，Brett Lantz 等人认为，通过将每个肿块分类为恶性、良性、复发或非复发，可以完全消除假阴性。显然，这不是一个现实的策略。但是，这说明了预测涉及在假阳性率和假阴性率之间取得平衡的事实。

如果您仍然不满意，我们将在第七章中调整多个参数，*调整机器学习模型*，以便预测准确性朝着更复杂的测量预测准确性的方法增加，这些方法可以用于确定可以根据每种错误类型的成本来优化错误率的地方。

# 使用 Spark Core 进行市场篮分析

在本节中，我们将探讨如何开发大规模机器学习管道，以进行市场篮分析。除了使用 Spark ML 和 MLlib 之外，我们还将演示如何使用 Spark Core 来开发这样的应用程序。

## 背景

在一篇早期的论文《在 Hadoop 上改进的 MapReduce 框架上的高效市场篮分析技术：电子商务视角》（可在[`onlinepresent.org/proceedings/vol6_2012/8.pdf`](http://onlinepresent.org/proceedings/vol6_2012/8.pdf)获取），作者们认为**市场篮分析**（MBA）技术对于日常业务决策非常重要，因为可以通过发现顾客频繁购买和一起购买的物品来提取顾客的购买规则。因此，可以根据这些关联规则为经常购物的顾客揭示购买规则。

您可能仍然想知道为什么我们需要市场篮分析，为什么它很重要，以及为什么它在计算上很昂贵。如果您能够识别高度特定的关联规则，例如，如果顾客喜欢芒果或橙子果酱以及牛奶或黄油，您需要有大规模的交易数据进行分析和处理。此外，一些大型连锁零售商或超市，例如 E-mart（英国）、HomePlus（韩国）、Aldi（德国）或 Dunnes Stores（爱尔兰）使用数百万甚至数十亿的交易数据库，以找到特定物品之间的关联，例如品牌、颜色、原产地甚至口味，以增加销售和利润的可能性。

在本节中，我们将探讨使用 Spark 库进行大规模市场篮分析的高效方法。阅读并实践后，您将能够展示 Spark 框架如何将现有的单节点管道提升到可在多节点数据挖掘集群上使用的管道。结果是我们提出的关联规则挖掘算法可以以相同的好处并行重复使用。

我们使用 SAMBA 作为 Spark-based Market Basket Analysis 的缩写，*min_sup*表示最小支持度，*min_conf*表示最小置信度。我们还将频繁模式和频繁项集这两个术语互换使用。

## 动机

传统的主存储器或基于磁盘的计算和关系型数据库管理系统无法处理不断增加的大规模交易数据。此外，正如第一章中讨论的，*使用 Spark 进行数据分析简介*，MapReduce 在 I/O 操作、算法复杂性、低延迟和完全基于磁盘的操作方面存在一些问题。因此，找到空交易并随后从未来方案中消除它们是这种方法的初始部分。

通过识别那些不出现在至少一个频繁 1 项集中的交易，很可能找到所有的空交易。正如前面提到的，Spark 将中间数据缓存到内存中，并提供**弹性分布式数据集**（RDDs）的抽象，可以通过这种方式克服这些问题，过去三年在处理分布式计算系统中的大规模数据方面取得了巨大成功。这些成功是有希望的，也是激励人的例子，可以探索将 Spark 应用于市场篮分析的研究工作。

## 探索数据集

请从[`github.com/stedy/Machine-Learning-with-R-datasets/blob/master/groceries.csv`](https://github.com/stedy/Machine-Learning-with-R-datasets/blob/master/groceries.csv)下载购物篮分析的杂货数据集。原始`grocery.csv`数据的前五行如*图 11*所示。这些行表示 10 个独立的杂货店交易。第一笔交易包括四件商品：柑橘类水果、半成品面包、人造黄油和即食汤。相比之下，第三笔交易只包括一件商品，全脂牛奶：

![Exploring the dataset](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00008.jpeg)

图 11：杂货数据集的快照

## 问题陈述

我们相信我们有足够的动机和理由来分析使用事务或零售数据集的购物篮。现在，让我们讨论一些背景研究，这些研究需要应用我们基于 Spark 的购物篮分析技术。

假设您有一组不同的项目*I = {i1, i2...in}*，*n*是不同项目的数量。事务数据库*T = {t1, t2...tN}*是一组*N*个事务，*|N|*是总事务数。集合*X*![Problem statements](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00067.jpeg)称为模式或项集。我们假设输入是作为事务序列给出的，其中项目用逗号分隔，如*表 1*所示。

为了简单起见描述背景研究，相同的交易在*表 2*中用单个字符表示：

| 交易 1 交易 2 交易 3 交易 4... | 饼干，冰淇淋，可乐，橙子，牛肉，比萨，可乐，面包法棍，苏打水，洗发水，饼干，百事可乐汉堡，奶酪，尿布，牛奶... |
| --- | --- |

表 1. 顾客的样本交易

| **TID** | **Itemset (Sequence of items)** |
| --- | --- |
| 10 | A, B, C, F |
| 20 | C, D, E |
| 30 | A, C, E, D |
| 40 | A |
| 50 | D, E, G |
| 60 | B, D |
| 70 | B |
| 80 | A, E, C |
| 90 | A, C, D |
| 100 | B, E, D |

表 2. 事务数据库

如果![Problem statements](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00117.jpeg)，则称*X*发生在*t*中或*t*包含*X*。支持计数是项集在所有事务中出现的频率，可以描述如下：

![Problem statements](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00093.jpeg)

换句话说，如果*支持*![Problem statements](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00033.jpeg)，我们说*X*是频繁项集。例如，在*表 2*中，项集*CD*、*DE*和*CDE*的出现次数分别为*3*、*3*和*2*，如果*min_sup*为*2*，所有这些都是频繁项集。

另一方面，关联规则是形式为![Problem statements](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00151.jpeg)或更正式地：

![Problem statements](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00110.jpeg)

因此，我们可以说关联规则是一种模式，它陈述了当*X*发生时，*Y*以一定概率发生。方程 1 中定义的关联规则的置信度可以表示为*Y*中的项目在包含*X*的事务中出现的频率，如下所示：

![Problem statements](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00032.jpeg)

现在我们需要引入一个称为`lift`的新参数，作为一个度量，它衡量了一个项目相对于其典型购买率更有可能被购买的程度，假设您知道另一个项目已被购买。这由以下方程定义：

![Problem statements](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00018.jpeg)

简而言之，给定一个事务数据库，现在购物篮分析的问题是通过关联规则找到支持和置信度都不低于*min_sup*和*min_conf*阈值的频繁项集的完整一组顾客购买规则。

## 使用 Spark 进行大规模购物篮分析

如*图 12*所示，我们假设事务数据库以分布方式存储在一组 DB 服务器的集群中。DB 服务器是具有大存储和主存储器的计算节点。因此，它可以存储大型数据集，因此可以计算分配给它的任何任务。驱动 PC 也是一个计算节点，主要作为客户端并控制整个过程。

显然，它需要有大内存来处理和保存 Spark 代码，以便发送到计算节点。这些代码包括 DB 服务器 ID、最小支持度、最小置信度和挖掘算法：

![使用 Spark 进行大规模市场篮分析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00078.jpeg)

图 12：使用 Spark 的 SAMBA 算法的工作流程

从模式中，使用 reduce 阶段 1 生成频繁模式，满足约束条件*min_sup*。在计算频繁模式上应用 map 阶段，以生成最终帮助生成关联规则的子模式。从子模式中，应用 reduce 阶段 2 生成满足约束条件*min_conf*的关联规则。

由于 Spark 生态系统对 Spark 核心和相关 API 的支持，可以实现两个 Map 和 Reduce 阶段的结合。最终结果是完整的关联规则集，以及它们各自的支持计数和置信度。

这些商店根据商品之间的关联关系，有完整的形式来放置它们的商品，以增加对频繁和非频繁购物者的销售。由于空间限制，我们无法展示*表 2*中呈现的样本交易数据库的逐步示例。

然而，我们相信工作流程和伪代码足以理解整个情景。DB 服务器接收来自驱动 PC 的代码输入并开始计算。从环境变量 Spark 会话中，我们创建一些初始数据引用或 RDD 对象。然后，初始 RDD 对象被转换以在 DB 服务器中创建更多和全新的 RDD 对象。首先，它以纯文本（或其他支持的格式）读取数据集，并使用窄/宽转换（即`flatMap`、`mapToPair`和`reduceByKey`）来处理空事务。

因此，过滤连接 RDD 操作提供了一个没有空事务的数据段。然后，RDD 对象被实现以将 RDD 转储到 DB 服务器的存储中作为筛选后的数据集。Spark 的间 RDD 连接操作允许在单个数据节点内合并多个 RDD 的内容。总之，在获得筛选后的数据集之前，我们遵循这里给出的步骤：

1.  将分布式处理模型和集群管理器（即 Mesos）的系统属性设置为 true。这个值可以保存在你的应用开发中作为标准的 Spark 代码。

1.  设置 SparkConf、AppName、Master URL、Spark 本地 IP、Spark 驱动主机 IP、Spark 执行器内存和 Spark 驱动内存。

1.  使用`SparkConf`创建`JavaSparkContext`。

1.  创建`JavaRDD`并将数据集作为纯文本读取，作为事务，并执行必要的分区。

1.  对 RDD 执行`flatMap`操作以将事务拆分为项目。

1.  执行`mapToPair`操作以便于查找项目的键/值对。

1.  执行过滤操作以删除所有空事务。

当我们有了筛选后的数据库时，我们会实现一个动作间 RDD 连接操作，将数据集保存在 DB 服务器或分区上，如果单台机器的存储空间不够，或者缓存，如果内存不够。

*图 12*显示了使用 Spark 的 API 获取关联规则作为最终结果的完整工作流程。另一方面，图 13 显示了该算法的伪代码，即**基于 Spark 的市场篮分析**（**SAMBA**）。这里实际上有两个 Map 和 Reduce 操作：

+   **Map/Reduce 阶段 1**：映射器从 HDFS 服务器读取交易并将交易转换为模式。另一方面，减速器找到频繁模式。

+   **Map/Reduce 阶段 2**：映射器将频繁模式转换为子模式。另一方面，减速器根据给定的约束条件（`min_conf`和`lift`）生成关联规则：![使用 Spark 进行大规模购物篮分析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00140.jpeg)

图 13：SAMBA 算法

之后，SAMBA 算法读取**过滤数据库**（**FTDB**），并应用映射阶段 1 生成模式的所有可能组合。然后`mapToPair()`方法将它们作为具有相应支持的模式。

## 使用 Spark Core 的算法解决方案

在这里，我们将看看如何使用 Spark Core 进行购物篮分析。请注意，我们将不使用 Spark ML 或 MLlib，因为虽然 MLlib 提供了计算关联规则的技术，但它不显示如何计算其他参数，例如计算置信度，支持和提升，这些参数对于完整分析杂货数据集非常重要。因此，我们将逐步展示一个完整的示例，从数据探索到关联规则生成。

第 1 步：导入必要的包和 API

以下是导入包和 API 的代码：

```scala
import java.util.ArrayList; 
import java.util.Iterator; 
import java.util.List; 
import org.apache.spark.api.java.JavaPairRDD; 
import org.apache.spark.api.java.JavaRDD; 
import org.apache.spark.api.java.function.Function; 
import org.apache.spark.api.java.function.Function2; 
import org.apache.spark.api.java.function.PairFlatMapFunction; 
import org.apache.spark.rdd.RDD; 
import org.apache.spark.sql.SparkSession; 
import scala.Tuple2;  
import scala.Tuple4; 

```

第 2 步：通过指定 Spark 会话创建入口点

可以使用以下代码创建入口点：

```scala
SparkSession spark = SparkSession 
.builder() 
.appName("MarketBasketAnalysis") 
.master("local[*]") 
.config("spark.sql.warehouse.dir", "E:/Exp/") 
.getOrCreate(); 

```

第 3 步：为交易创建 Java RDD

可以使用以下代码创建交易的 Java RDD：

```scala
String transactionsFileName = "Input/groceries.data"; 
RDD<String> transactions = spark.sparkContext().textFile(transactionsFileName, 1); 
transactions.saveAsTextFile("output/transactions"); 

```

第 4 步：创建创建列表的方法

创建一个名为`toList`的方法，从创建的交易 RDD 中添加所有交易中的项目：

```scala
  static List<String> toList(String transaction) { 
    String[] items = transaction.trim().split(","); 
    List<String>list = new ArrayList<String>(); 
    for (String item :items) { 
      list.add(item); 
    } 
    returnlist; 
  } 

```

第 5 步：删除不频繁的项目和空交易

创建一个名为`removeOneItemAndNullTransactions`的方法，以删除不频繁的项目和空交易：

```scala
static List<String> removeOneItemAndNullTransactions(List<String>list, int i) { 
    if ((list == null) || (list.isEmpty())) { 
      returnlist; 
    } 
    if ((i< 0) || (i> (list.size() - 1))) { 
      returnlist; 
    } 
    List<String>cloned = new ArrayList<String>(list); 
    cloned.remove(i); 
    return cloned; 
  } 

```

第 6 步：扁平映射和创建 1 项集（映射阶段 1）

进行`flatmap`并创建 1 项集。最后，保存模式：

```scala
JavaPairRDD<List<String>, Integer> patterns = transactions.toJavaRDD() 
        .flatMapToPair(new PairFlatMapFunction<String, List<String>, Integer>() { 
          @Override 
  public Iterator<Tuple2<List<String>, Integer>> call(String transaction) { 
  List<String> list = toList(transaction); 
  List<List<String>> combinations = Combination.findSortedCombinations(list); 
  List<Tuple2<List<String>, Integer>> result = new ArrayList<Tuple2<List<String>, Integer>>(); 
for (List<String> combList : combinations) { 
  if (combList.size() > 0) { 
  result.add(new Tuple2<List<String>, Integer>(combList, 1)); 
              } 
            } 
    return result.iterator(); 
          } 
        }); 
    patterns.saveAsTextFile("output/1itemsets"); 

```

### 注意

请注意，模式 RDD 的最后保存是为了可选的参考目的，以便您可以查看 RDD 的内容。

以下是 1 项集的屏幕截图：

![使用 Spark Core 的算法解决方案](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00152.jpeg)

图 14：1 项集

第 7 步：组合和减少频繁模式（减少阶段 1）

组合和减少所有频繁模式，并保存它们：

```scala
JavaPairRDD<List<String>, Integer> combined = patterns.reduceByKey(new Function2<Integer, Integer, Integer>() { 
      public Integer call(Integer i1, Integer i2) { 
        int support = 0; 
        if (i1 + i2 >= 2) { 
          support = i1 + i2; 
        } 
        // if(support >= 2) 
        return support; 
      } 
    }); 
  combined.saveAsTextFile("output/frequent_patterns"); 

```

以下是具有相应支持的频繁模式的快照（*图 15*）：

![使用 Spark Core 的算法解决方案](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00073.jpeg)

图 15：具有相应支持的频繁模式（频率）

第 8 步：生成所有候选频繁模式（映射阶段 2）

通过从频繁模式中删除 1 项集来生成所有候选频繁模式或子模式，并最终保存候选模式：

```scala
JavaPairRDD<List<String>, Tuple2<List<String>, Integer>> candidate-patterns = combined.flatMapToPair( 
new PairFlatMapFunction<Tuple2<List<String>, Integer>, List<String>, Tuple2<List<String>, Integer>>() { 
          @Override 
public Iterator<Tuple2<List<String>, Tuple2<List<String>, Integer>>> call( 
Tuple2<List<String>, Integer> pattern) { 
List<Tuple2<List<String>, Tuple2<List<String>, Integer>>> result = new ArrayList<Tuple2<List<String>, Tuple2<List<String>, Integer>>>(); 
  List<String> list = pattern._1; 
  frequency = pattern._2; 
  result.add(new Tuple2(list, new Tuple2(null, frequency))); 
            if (list.size() == 1) { 
              return result.iterator(); 
            } 

  // pattern has more than one item 
  // result.add(new Tuple2(list, new Tuple2(null,size))); 
    for (int i = 0; i < list.size(); i++) { 
    List<String> sublist = removeOneItem(list, i); 
              result.add(new Tuple2<List<String>, Tuple2<List<String>, Integer>>(sublist, 
                  new Tuple2(list, frequency))); 
            } 
            return result.iterator(); 
          } 
        }); 
candidate-patterns.saveAsTextFile("output/sub_patterns"); 

```

以下是子模式的快照：

![使用 Spark Core 的算法解决方案](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00054.jpeg)

图 16：项目的子模式

第 9 步：组合所有子模式

组合所有子模式并将它们保存在磁盘上或持久保存在内存中：

```scala
JavaPairRDD<List<String>, Iterable<Tuple2<List<String>, Integer>>>rules = candidate_patterns.groupByKey(); 
rules.saveAsTextFile("Output/combined_subpatterns"); 

```

以下是组合形式的候选模式（子模式）的屏幕截图：

![使用 Spark Core 的算法解决方案](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00020.jpeg)

图 17：组合形式的候选模式（子模式）

第 10 步：生成关联规则

通过指定`置信度`和`提升`从子模式生成所有关联规则（减少阶段 2）：

```scala
JavaRDD<List<Tuple4<List<String>, List<String>, Double, Double>>> assocRules = rules.map( 
        new Function<Tuple2<List<String>, Iterable<Tuple2<List<String>, Integer>>>, List<Tuple4<List<String>, List<String>, Double, Double>>>() { 
          @Override 
public List<Tuple4<List<String>, List<String>, Double, Double>> call( 
Tuple2<List<String>, Iterable<Tuple2<List<String>, Integer>>> in) throws Exception { 

List<Tuple4<List<String>, List<String>, Double, Double>> result = new ArrayList<Tuple4<List<String>, List<String>, Double, Double>>(); 
  List<String> fromList = in._1; 
  Iterable<Tuple2<List<String>, Integer>> to = in._2; 
  List<Tuple2<List<String>, Integer>> toList = new ArrayList<Tuple2<List<String>, Integer>>(); 
Tuple2<List<String>, Integer> fromCount = null; 
      for (Tuple2<List<String>, Integer> t2 : to) { 
        // find the "count" object 
      if (t2._1 == null) { 
                fromCount = t2; 
              } else { 
                toList.add(t2); 
              } 
            } 
            if (toList.isEmpty()) { 
              return result; 
            } 
for (Tuple2<List<String>, Integer> t2 : toList) { 
  double confidence = (double) t2._2 / (double) fromCount._2; 
double lift = confidence / (double) t2._2; 
double support = (double) fromCount._2; 
List<String> t2List = new ArrayList<String>(t2._1); 
t2List.removeAll(fromList); 
if (support >= 2.0 && fromList != null && t2List != null) { 
  result.add(new Tuple4(fromList, t2List, support, confidence)); 
System.out.println(fromList + "=>" + t2List + "," + support + "," + confidence + "," + lift); 
              } 
            } 
            return result; 
          } 
        }); 
assocRules.saveAsTextFile("output/association_rules_with_conf_lift"); 

```

以下是包括置信度和提升的关联规则的输出。有关支持，置信度和提升的更多详细信息，请参阅问题说明部分。

[前提=>结论]，支持，置信度，提升：

![使用 Spark Core 的算法解决方案](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00094.jpeg)

图 18：包括置信度和提升的关联规则

## 在 SAMBA 中调整和设置正确的参数

请注意，如果您尝试使用默认参数设置，如支持=0.1 和置信度=0.6，可能会得到空规则，或者从技术上讲，没有规则生成。您可能会想知道为什么。实际上，0.1 的默认支持意味着为了生成关联规则，一个项目必须至少出现在*0.1 * 9385 = 938.5*交易中，或者 938.5 次（对于我们使用的数据集，|N| = 9385）。

然而，在这方面，在他们的书中，Brett Lantz 等人认为有一种方法可以解决这个问题，同时设置支持。他们建议考虑在您认为模式有趣之前需要的最小交易数量。此外，例如，您还可以认为，如果一个项目每天购买两次（大约每月 60 次），那么考虑该交易可能是非平凡的。

从这个角度来看，可以估计如何设置支持值，以便仅找到至少匹配那么多交易的规则。因此，您可以将最小支持值设置为 0.006，因为 9,835 中的 60 等于 0.006；我们将首先尝试设置支持值。

另一方面，设置最小置信度也需要一个棘手的平衡，在这方面，我们再次想参考 Brett Lantz 等人的书，题为*Machine Learning with R, Packt Publishing, 2015*。如果置信度太低，显然我们可能会对相当多的不可靠规则产生怀疑的假阳性结果。

因此，最小置信度阈值的最佳值严重取决于您分析的目标。因此，如果您从保守值开始，可以随时将其降低以扩大搜索，如果您找不到可操作的情报。如果将最小置信度阈值设置为 0.25，这意味着为了包含在结果中，规则必须至少有 25%的时间是正确的。这将消除最不可靠的规则，同时为我们留出一些空间，以通过有针对性的产品促销来修改行为。

现在，让我们谈谈第三个参数，“提升”。在建议如何设置“提升”的值之前，让我们先看一个实际例子，看看它可能如何影响首次生成关联规则。这是第三次，我们参考了 Brett Lantz 等人的书，题为*Machine Learning with R, Packt Publishing, 2015*。

例如，假设在超市里，很多人经常一起购买牛奶和面包。因此，自然地，您期望找到许多包含牛奶和面包的交易。然而，如果`提升`（牛奶=>面包）大于 1，则意味着这两种物品一起出现的频率比预期的要高。因此，较大的`提升`值是规则重要性的强烈指标，并反映了交易中物品之间的真实联系。

总之，我们需要仔细考虑这些参数的值，考虑前面的例子。然而，作为一个独立的模型，算法可能需要几个小时才能完成。因此，请花足够的时间运行应用程序。或者，减少长交易以减少时间开销。

# Spark 的 OCR 流水线

图像处理和计算机视觉是两个经典但仍在不断发展的研究领域，它们经常充分利用许多类型的机器学习算法。有几种用例，其中将图像像素的模式与更高概念的关系联系起来是极其复杂且难以定义的，当然，也是计算上费时的。

从实际角度来看，人类相对容易识别物体是脸、狗，还是字母或字符。然而，在某些情况下定义这些模式是困难的。此外，与图像相关的数据集通常存在噪音。

在本节中，我们将开发一个类似于用于**光学字符识别**（**OCR**）的核心的模型，用于将打印或手写文本转换为电子形式以保存在数据库中，以便处理基于纸张的文档。

当 OCR 软件首次处理文档时，它将纸张或任何对象分成一个矩阵，以便网格中的每个单元格包含一个单个字形（也称为不同的图形形状），这只是一种指代字母、符号、数字或来自纸张或对象的任何上下文信息的复杂方式。

为了演示 OCR 流水线，我们将假设文档只包含英文的字母，与 26 个字母 A 到 Z 中的一个匹配的字形。我们将使用 UCI 机器学习数据存储库（[`archive.ics.uci.edu/ml`](http://archive.ics.uci.edu/ml)）中的 OCR 字母数据集。该数据集是由 W. Frey 和 D. J. Slate 等人捐赠的。我们已经发现数据集包含 20,000 个例子，使用 20 种不同的随机重塑和扭曲的黑白字体作为不同形状的字形的 26 个英文字母大写字母。

### 提示

有关这些数据的更多信息，请参阅 W. Frey 和 D.J. Slate（1991 年）的文章《使用荷兰式自适应分类器进行字母识别，机器学习，第 6 卷，第 161-182 页》。

*图 19*中显示的图像是由 Frey 和 Slate 发表的，提供了一些印刷字形的示例。以这种方式扭曲，这些字母对计算机来说很具挑战性，但对人类来说很容易识别。前 20 行的统计属性显示在*图 20*中：

![使用 Spark 的 OCR 流水线](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00119.jpeg)

图 19：一些印刷字形[由 W. Frey 和 D.J. Slate（1991 年）的文章《使用荷兰式自适应分类器进行字母识别，机器学习，第 6 卷，第 161-182 页》提供]

## 探索和准备数据

根据 Frey 和 Slate 提供的文档，当使用 OCR 阅读器扫描字形到计算机时，它们会自动转换为像素。因此，提到的 16 个统计属性也被记录到计算机中。

请注意，字符所在的方框各个区域的黑色像素的浓度应该提供一种区分字母表中的 26 个字母的方法，使用 OCR 或机器学习算法进行训练。

### 提示

要跟随本示例，从 Packt Publishing 网站下载`letterdata.data`文件，并将其保存到您的项目目录中的一个或另一个目录中。

在从 Spark 工作目录中读取数据之前，我们确认已收到定义每个字母类的 16 个特征的数据。如预期的那样，字母有 26 个级别，如*图 20*所示：

![探索和准备数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00138.jpeg)

图 20：显示为数据框的数据集的快照

请记住，SVM、朴素贝叶斯分类器或任何其他分类器算法以及它们的相关学习器都需要所有特征都是数字。此外，每个特征都被缩放到一个相当小的区间。

此外，SVM 在密集向量化特征上表现良好，因此在稀疏向量化特征上表现不佳。在我们的情况下，每个特征都是整数。因此，我们不需要将任何值转换为数字。另一方面，这些整数变量的一些范围似乎相当宽。

在实际情况下，可能需要对所有少数特征点对数据进行归一化。

## 使用 Spark ML 和 Spark MLlib 的 OCR 流水线

由于其准确性和健壮性，让我们看看 SVM 是否能胜任。正如您在*图 17*中所看到的，我们有一个多类 OCR 数据集（具体来说有 26 个类）；因此，我们需要一个多类分类算法，例如逻辑回归模型，因为 Spark 中的线性 SVM 的当前实现不支持多类分类。

### 提示

有关更多详细信息，请参阅以下网址：[`spark.apache.org/docs/latest/mllib-linear-methods.html#linear-support-vector-machines-svms`](http://spark.apache.org/docs/latest/mllib-linear-methods.html#linear-support-vector-machines-svms)。

**步骤 1：导入必要的包/库/接口**

以下是导入必要包的代码：

```scala
import java.util.HashMap; 
import java.util.Map; 
import org.apache.spark.api.java.JavaRDD; 
import org.apache.spark.api.java.function.Function; 
import org.apache.spark.mllib.classification.LogisticRegressionWithLBFGS; 
import org.apache.spark.mllib.evaluation.MulticlassMetrics; 
import org.apache.spark.mllib.evaluation.MultilabelMetrics; 
import org.apache.spark.mllib.linalg.DenseVector; 
import org.apache.spark.mllib.linalg.Vector; 
import org.apache.spark.mllib.regression.LabeledPoint; 
import org.apache.spark.sql.Dataset; 
import org.apache.spark.sql.Row; 
import org.apache.spark.sql.SparkSession; 
import scala.Tuple2; 

```

**步骤 2：初始化必要的 Spark 环境**

以下是初始化 Spark 环境的代码：

```scala
  static SparkSession spark = SparkSession 
        .builder() 
        .appName("OCRPrediction") 
            .master("local[*]") 
            .config("spark.sql.warehouse.dir", "E:/Exp/"). 
            getOrCreate(); 

```

在这里，我们将应用程序名称设置为`OCRPrediction`，主 URL 设置为`local`。Spark 会话是程序的入口点。请相应地设置这些参数。

**步骤 3：读取数据文件并创建相应的数据集，并显示前 20 行**

以下是读取数据文件的代码：

```scala
String input = "input/letterdata.data"; 
Dataset<Row> df = spark.read().format("com.databricks.spark.csv").option("header", "true").load(input);  
  df.show();  

```

对于前 20 行，请参阅*图 5*。正如我们所看到的，有 26 个字符呈现为需要预测的单个字符；因此，我们需要为每个字符分配一个随机双精度值，以使该值与其他特征对齐。因此，在下一步中，这就是我们要做的。

**步骤 4：创建一个字典，为每个字符分配一个随机双精度值**

以下代码是为每个字符分配一个随机双精度值的字典：

```scala
final Map<String, Integer>alpha = newHashMap(); 
    intcount = 0; 
    for(chari = 'A'; i<= 'Z'; i++){ 
      alpha.put(i + "", count++); 
      System.out.println(alpha); 
    } 

```

以下是从前面的代码段生成的映射输出：

![使用 Spark ML 和 Spark MLlib 的 OCR 管道](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00048.jpeg)

图 21：映射分配

**步骤 5：创建标记点和特征向量**

为来自 16 个特征（即 16 列）的组合特征创建标记点和特征向量。还将它们保存为 Java RDD，并将其转储或缓存在磁盘或内存中，并显示样本输出：

```scala
JavaRDD<LabeledPoint> dataRDD = df.toJavaRDD().map(new Function<Row, LabeledPoint>() { 
      @Override 
      public LabeledPoint call(Row row) throws Exception { 

        String letter = row.getString(0); 
        double label = alpha.get(letter); 
        double[] features= new double [row.size()]; 
        for(int i = 1; i < row.size(); i++){ 
          features[i-1] = Double.parseDouble(row.getString(i)); 
        } 
        Vector v = new DenseVector(features);         
        return new LabeledPoint(label, v); 
      } 
    }); 

dataRDD.saveAsTextFile("Output/dataRDD"); 
System.out.println(dataRDD.collect()); 

```

如果您仔细观察前面的代码段，我们已经创建了一个名为 features 的数组，其中包含 16 个特征，并创建了密集向量表示，因为密集向量表示是一种更紧凑的表示，其中内容可以显示如下截图所示：

![使用 Spark ML 和 Spark MLlib 的 OCR 管道](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00041.jpeg)

图 22：相应标签和特征的 Java RDD

**步骤 6：生成训练和测试集**

以下是生成测试集的代码：

```scala
JavaRDD<LabeledPoint>[] splits = dataRDD.randomSplit(new double[] {0.7, 0.3}, 12345L); 
JavaRDD<LabeledPoint> training = splits[0]; 
JavaRDD<LabeledPoint> test = splits[1];  

```

如果您希望查看训练或测试数据集的快照，您应该将它们转储或缓存。以下是一个示例代码：

```scala
training.saveAsTextFile("Output/training"); 
test.saveAsTextFile("Output/test"); 

```

### 提示

我们已随机生成了要训练和测试的模型的训练集和测试集。在我们的案例中，分别为 70%和 30%，长种子为 11L。根据您的数据集重新调整这些值。请注意，如果向随机数添加种子，每次运行代码时都会获得相同的结果，这些结果一直为质数，最多为 1062348。

**步骤 7：训练模型**

正如您所看到的，我们有一个包含 26 个类的多类数据集；因此，我们需要一个多类分类算法，例如逻辑回归模型：

```scala
Boolean useFeatureScaling= true; 
final LogisticRegressionModel model = new LogisticRegressionWithLBFGS() 
  .setNumClasses(26).setFeatureScaling(useFeatureScaling) 
  .run(training.rdd()); 

```

前面的代码段通过指定类别数（即`26`）和特征缩放为`Boolean true`来使用训练数据集构建模型。正如您所看到的，我们使用了训练数据集的 RDD 版本，使用`training.rdd()`，因为训练数据集是以正常向量格式的。

### 提示

Spark 支持多类逻辑回归算法，支持**有限内存 Broyden-Fletcher-Goldfarb-Shanno**（**LBFGS**）算法。在数值优化中，**Broyden-Fletcher-Goldfarb-Shanno**（**BFGS**）算法是用于解决无约束非线性优化问题的迭代方法。

步骤 8：计算测试数据集上的原始分数

以下是计算原始分数的代码：

```scala
JavaRDD<Tuple2<Object, Object>> predictionAndLabels = test.map( 
    new Function<LabeledPoint, Tuple2<Object, Object>>() { 
    public Tuple2<Object, Object> call(LabeledPoint p) { 
    Double prediction = model.predict(p.features()); 
    return new Tuple2<Object, Object>(prediction, p.label()); 
          } 
        } 
      );  
predictionAndLabels.saveAsTextFile("output/prd2");  

```

如果您仔细查看前面的代码，您会发现我们实际上是通过将它们作为 Java RDD 来计算模型中创建的预测特征，从而计算出*步骤 7*中的预测特征。

步骤 9：预测标签为 8.0（即 I）的结果并获取评估指标

以下代码说明了如何预测结果：

```scala
MulticlassMetrics metrics = new MulticlassMetrics(predictionAndLabels.rdd()); 
MultilabelMetrics(predictionAndLabels.rdd()); 
System.out.println(metrics.confusionMatrix()); 
double precision = metrics.precision(metrics.labels()[0]); 
double recall = metrics.recall(metrics.labels()[0]); 
double tp = 8.0; 
double TP = metrics.truePositiveRate(tp); 
double FP = metrics.falsePositiveRate(tp); 
double WTP = metrics.weightedTruePositiveRate(); 
double WFP =  metrics.weightedFalsePositiveRate(); 
System.out.println("Precision = " + precision); 
System.out.println("Recall = " + recall); 
System.out.println("True Positive Rate = " + TP); 
System.out.println("False Positive Rate = " + FP); 
System.out.println("Weighted True Positive Rate = " + WTP); 
System.out.println("Weighted False Positive Rate = " + WFP); 

```

![使用 Spark ML 和 Spark MLlib 的 OCR 流水线](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00050.jpeg)

图 23：精度和召回率的性能指标

因此，精度为 75%，显然不令人满意。然而，如果您仍然不满意，下一章将讨论如何调整参数以提高预测准确性。

### 提示

要了解如何计算精度、召回率、真正率和真负率，请参阅维基百科页面[`en.wikipedia.org/wiki/Sensitivity_and_specificity`](https://en.wikipedia.org/wiki/Sensitivity_and_specificity)，其中详细讨论了敏感性和特异性。您还可以参考*Powers, David M W (2011). Evaluation: From Precision, Recall and F-Measure to ROC, Informedness, Markedness & Correlation(PDF). Journal of Machine Learning Technologies 2 (1): 37-63*。

# 使用 Spark MLlib 和 ML 进行主题建模

主题建模技术广泛用于从大量文档中挖掘文本的任务。这些主题可以用来总结和组织包括主题术语及其相对权重的文档。自 Spark 1.3 发布以来，MLlib 支持 LDA，这是文本挖掘和自然语言处理领域中最成功使用的主题建模技术之一。此外，LDA 也是第一个采用 Spark GraphX 的 MLlib 算法。

### 提示

要了解 LDA 背后的理论如何工作，请参考*David M. Blei, Andrew Y. Ng and Michael I. Jordan, Latent Dirichlet Allocation, Journal of Machine Learning Research 3 (2003) 993-1022*。

*图 24*显示了从随机生成的推文文本中的主题分布的输出，将在第九章中进一步讨论，*使用流式和图数据进行高级机器学习*。此外，我们将进一步解释为什么我们在第九章中使用 LDA 而不是其他主题建模算法。

![使用 Spark MLlib 和 ML 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00159.jpeg)

图 24：主题分布及其外观

在本节中，我们将介绍使用 Spark MLlib 的 LDA 算法处理非结构化原始推文数据集的主题建模示例。

## 使用 Spark MLlib 进行主题建模

在这一小节中，我们使用 Spark 表示了一种半自动的主题建模技术。以下步骤展示了从数据读取到打印主题及其术语权重的主题建模，同时使用其他选项作为默认值，我们在从 GitHub URL 下载的数据集上训练 LDA，网址为[`github.com/minghui/Twitter-LDA/tree/master/data/Data4Model/test`](https://github.com/minghui/Twitter-LDA/tree/master/data/Data4Model/test)。

步骤 1：加载所需的软件包和 API

以下是加载所需软件包的代码：

```scala
import java.io.File; 
import java.io.FileNotFoundException; 
import java.io.Serializable; 
import java.util.ArrayList; 
import java.util.List; 
import java.util.Scanner; 
import org.apache.spark.ml.clustering.LDA; 
import org.apache.spark.ml.clustering.LDAModel; 
import org.apache.spark.ml.feature.ChiSqSelector; 
import org.apache.spark.ml.feature.HashingTF; 
import org.apache.spark.ml.feature.IDF; 
import org.apache.spark.ml.feature.IDFModel; 
import org.apache.spark.ml.feature.RegexTokenizer; 
import org.apache.spark.ml.feature.StopWordsRemover; 
import org.apache.spark.ml.feature.StringIndexer; 
import org.apache.spark.sql.Dataset; 
import org.apache.spark.sql.Row; 
import org.apache.spark.sql.SparkSession; 
import org.apache.spark.sql.types.DataTypes; 

```

步骤 2：创建 Spark 会话

以下是创建 Spark 会话的代码：

```scala
static SparkSession spark = SparkSession 
        .builder() 
        .appName("JavaLDAExample") 
        .master("local[*]") 
        .config("spark.sql.warehouse.dir", "E:/Exp/") 
        .getOrCreate(); 

```

**步骤 3：读取和查看数据集的内容**

以下代码说明了如何读取和查看数据集的内容：

```scala
Dataset<Row> df = spark.read().text("input/test/*.txt"); 

```

请注意，使用字符`***`表示读取项目路径中 input/text 目录中的所有文本文件。如果要打印前 20 行，只需使用以下代码，您将看到以下文本：

```scala
df.show(); 

```

![使用 Spark MLlib 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00006.jpeg)

图 25：文本的前 20 行

从前面的屏幕截图可以清楚地看出，我们使用的文本文件只是包含列名标签的非常不规则的文本。因此，我们需要使用正则表达式分词器进行特征转换预处理，然后才能用于我们的目的。

**步骤 4：使用 RegexTokenizer 进行特征转换**

以下是`RegexTokenizer`的代码：

```scala
RegexTokenizer regexTokenizer1 = new RegexTokenizer().setInputCol("value").setOutputCol("labelText").setPattern("\\t.*$"); 

```

仔细观察前面的代码段，您会发现我们指定了输入列名为`value`，输出列名为`labelText`和模式。现在使用以下代码段使用刚刚标记的正则表达式分词器创建另一个数据框：

```scala
Dataset<Row> labelTextDataFrame = regexTokenizer1.transform(df); 

```

现在，让我们使用以下语句查看新数据框`labelTextDataFrame`包含什么：

```scala
labelTextDataFrame.show(); 

```

![使用 Spark MLlib 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00095.jpeg)

图 26：一个新列，其中的字符转换为相应的小写字符

在前面的屏幕截图（*图 26*）中显示，分词器创建了一个新列，大多数大写单词或字符已转换为相应的小写字符。由于主题建模关心每个输入词的词权重和频率，我们需要从标签文本中分离单词，这是通过使用以下代码段完成的：

```scala
RegexTokenizer regexTokenizer2 = new RegexTokenizer().setInputCol("value").setOutputCol("text").setPattern("\\W"); 

```

现在让我们创建另一个数据框，并使用以下代码查看转换的结果：

```scala
Dataset<Row> labelFeatureDataFrame = regexTokenizer2.transform(labelTextDataFrame); 
labelFeaturedDataFrame.show(); 

```

![使用 Spark MLlib 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00055.jpeg)

图 27：标签文本作为逗号分隔的单词

从前面的屏幕截图（*图 27*）中，我们可以看到添加了一个新列`label`，其中显示标签文本作为逗号分隔的单词。

现在，由于我们有一堆文本可用，为了使预测和主题建模更容易，我们需要对我们分割的单词进行索引。但在此之前，我们需要在新数据框中交换`labelText`和`text`，如*图 28*所示。要检查是否真的发生了这种情况，只需打印新创建的数据框：

```scala
Dataset<Row> newDF = labelFeatureDataFrame 
        .withColumn("labelTextTemp",          labelFeatureDataFrame.col("labelText") 
          .cast(DataTypes.StringType))        .drop(labelFeatureDataFrame.col("labelText")).withColumnRenamed("labelTextTemp", "labelText"); 
newDF.show(); 

```

![使用 Spark MLlib 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00049.jpeg)

图 28：在新数据框中交换 labelText 和 text

**步骤 5：通过字符串索引器进行特征转换**

以下是特征转换的代码：

```scala
StringIndexer indexer = new StringIndexer().setInputCol("labelText").setOutputCol("label"); 

```

现在为*步骤 2*中创建的数据框`newDF`创建一个新数据框，并查看数据框的内容。请注意，我们选择了旧列`labelText`，并将新列简单设置为`label`：

```scala
Dataset<Row> indexed = indexer.fit(newDF).transform(newDF); 
indexed.select(indexed.col("labelText"), indexed.col("label"), indexed.col("text")).show(); 
Indexed.show(); 

```

![使用 Spark MLlib 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00131.jpeg)

图 29：与 labelText 列相对应的标签

因此，如*图 29*所示，我们得到了一个新列`label`，其中包含与`labelText`列相对应的标签。接下来的步骤是去除停用词。

**步骤 6：特征转换（去除停用词）**

以下是去除停用词的特征转换的代码：

```scala
StopWordsRemover remover = new StopWordsRemover(); 
String[] stopwords = remover.getStopWords(); 
remover.setStopWords(stopwords).setInputCol("text").setOutputCol("filteredWords"); 

```

Spark 的`StopWordsRemover`类的当前实现包含以下单词作为停用词。由于我们没有任何先决条件，我们直接使用了这些单词：

![使用 Spark MLlib 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00074.jpeg)

图 30：Spark 提供的用于文本分析的一些停用词

**步骤 7：通过去除停用词创建一个过滤后的数据集**

以下是通过去除停用词创建过滤后数据集的代码：

```scala
Dataset<Row> filteredDF = remover.transform(indexed); 
filteredDF.show(); 
filteredDF.select(filteredDF.col("label"), filteredDF.col("filteredWords")).show(); 

```

现在为过滤后的单词（即不包括停用词）创建一个新数据框。让我们查看过滤后数据集的内容： 

```scala
Dataset<Row> featurizedData = hashingTF.transform(filteredDF); 
featurizedData.show(); 

```

![使用 Spark MLlib 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00107.jpeg)

图 31：排除停用词的过滤词

第 8 步：使用 HashingTF 进行特征提取

以下是使用 HashingTF 进行特征提取的代码：

```scala
int numFeatures = 5; 
HashingTF hashingTF = new HashingTF().setInputCol("filteredWords").setOutputCol("rawFeatures").setNumFeatures(numFeatures); 

```

在前面的代码中，我们只对五个特征进行了 HashingTF，以简化操作。现在从旧数据框架（即`filteredDF`）中提取特征创建另一个数据框架，并显示相同的输出：

```scala
Dataset<Row> featurizedData = hashingTF.transform(filteredDF); 
       featurizedData.show();   

```

![使用 Spark MLlib 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00024.jpeg)

图 32：从旧数据框架`filteredDF`中提取特征创建的数据框架

### 提示

有关特征转换、估计器和哈希的更多信息和 API 文档细节，请参考 Spark 网站[`spark.apache.org/docs/latest/ml-features.html`](https://spark.apache.org/docs/latest/ml-features.html)。

第 9 步：使用 IDF 估计器进行特征提取

```scala
IDF idf = new IDF().setInputCol("rawFeatures").setOutputCol("features"); 
IDFModel idfModel = idf.fit(featurizedData); 

```

前面的代码通过拟合`idfModel`从原始特征中创建新特征，该模型接受第 5 步中的特征数据框架（即`featurizedData`）。现在让我们创建并显示使用我们刚刚创建的估计器（即`idfModel`）的重新缩放数据的新数据框架，该估计器消耗了用于特征化数据的旧数据框架（即`featurizedData`）：

```scala
Dataset<Row> rescaledData = idfModel.transform(featurizedData); 
rescaledData.show(). 

```

![使用 Spark MLlib 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00137.jpeg)

图 33：使用估计器重新缩放的数据

第 10 步：卡方特征选择

卡方特征选择选择要用于预测分类标签的分类特征。以下代码段执行此选择：

```scala
ChiSqSelector selector = new org.apache.spark.ml.feature.ChiSqSelector(); 
selector.setNumTopFeatures(5).setFeaturesCol("features").setLabelCol("label").setOutputCol("selectedFeatures"); 

```

现在创建另一个选定特征的数据框架，如下所示：

```scala
Dataset<Row> result = selector.fit(rescaledData).transform(rescaledData); 
result.show(); 

```

![使用 Spark MLlib 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00130.jpeg)

图 34：卡方特征选择

您可以从前面的输出/屏幕截图中看到，我们的数据已准备好用于训练 LDA 模型并进行主题建模。

第 11 步：创建并训练 LDA 模型

使用训练数据集（即数据框架结果）创建并训练 LDA 模型，指定*K*（主题建模必须大于 1 的聚类数，其中默认值为 10）和最大迭代次数：

```scala
long value = 5;     
LDA lda = new LDA().setK(10).setMaxIter(10).setSeed(value); 
LDAModel model = lda.fit(result); 

```

现在我们已经训练、拟合并准备好用于我们目的的模型，让我们来看看我们的输出。但在这之前，我们需要有一个能够捕获与主题相关的指标的数据框架。使用以下代码：

```scala
System.out.println(model.vocabSize()); 
Dataset<Row> topics = model.describeTopics(5); 
org.apache.spark.ml.linalg.Matrix metric = model.topicsMatrix(); 

```

现在让我们看一下主题分布。看看前面的数据集：

```scala
System.out.println(metric); 
topics.show(false); 

```

![使用 Spark MLlib 进行主题建模](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00003.jpeg)

图 35：相应的术语权重、主题名称和术语索引

仔细观察前面的输出，我们找到了相应的术语权重、主题名称和术语索引。前述术语及其相应的权重将在第九章中使用，*使用流式和图数据进行高级机器学习*，用于使用 GraphX 和 Scala 查找连接组件。

但是，我们还需要实际的术语。我们将在第九章中展示检索术语的详细技术，*使用流式和图数据进行高级机器学习*，这在很大程度上取决于需要开发或生成的术语词汇的概念。

## 可扩展性

前面的例子展示了如何使用 LDA 算法进行主题建模作为独立应用。然而，根据 Joseph B.在 Databricks 博客中的一篇文章[`databricks.com/blog/2015/03/25/topic-modeling-with-lda-mllib-meets-graphx.html`](https://databricks.com/blog/2015/03/25/topic-modeling-with-lda-mllib-meets-graphx.html)，LDA 的并行化并不直接，已经有许多研究论文提出了不同的策略。在这方面的关键障碍是所有方法都涉及大量的通信。根据 Databricks 网站上的博客，以下是在实验过程中使用的数据集和相关训练和测试集的统计数据：

+   训练集大小：460 万份文件

+   词汇量：110 万个术语

+   训练集大小：11 亿个标记（~每份文件 239 个单词）

+   100 个主题

+   16 个工作节点的 EC2 集群，例如 M4.large 或 M3.medium，具体取决于预算和要求

+   时间结果：平均每次迭代 176 秒/次

# 使用 Spark 进行信用风险分析流程

在本节中，我们将开发一个信用风险流程，这在银行和信用合作社等金融机构中通常使用。首先，我们将讨论信用风险分析是什么以及为什么它很重要，然后使用基于 Spark ML 的流程开发基于随机森林的分类器。最后，我们将提供一些建议以提高性能。

## 什么是信用风险分析？为什么它很重要？

当申请人申请贷款并且银行收到申请时，基于申请人的资料，银行必须决定是否批准贷款申请。

在这方面，银行对贷款申请的决定涉及两种风险：

+   **申请人是良好的信用风险**：这意味着客户或申请人更有可能偿还贷款。那么，如果贷款未获批准，银行可能会遭受业务损失。

+   **申请人是不良的信用风险**：这意味着客户或申请人很可能无法偿还贷款。在这种情况下，向客户批准贷款将导致银行财务损失。

我们的常识告诉我们，第二种风险是更大的风险，因为银行更有可能无法收回借款金额。

因此，大多数银行或信用合作社评估向客户、申请人或顾客放贷所涉及的风险。在商业分析中，最小化风险往往会最大化银行自身的利润。换句话说，从财务角度来看，最大化利润和最小化损失是重要的。

通常，银行会根据申请人的不同因素和参数对贷款申请做出决定。例如，他们的贷款申请的人口统计和社会经济状况。

## 使用 Spark ML 开发信用风险分析流程

在本节中，我们将首先详细讨论信用风险数据集，以便获得一些见解。之后，我们将看看如何开发大规模的信用风险流程。最后，我们将提供一些性能改进建议，以提高预测准确性。

### 数据集探索

德国信用数据集是从 UCI 机器学习库[`archive.ics.uci.edu/ml/machine-learning-databases/statlog/german/`](https://archive.ics.uci.edu/ml/machine-learning-databases/statlog/german/)下载的。尽管链接中提供了数据集的详细描述，但我们在*表 3*中提供了一些简要见解。数据包含 21 个变量的与信用有关的数据，以及 1000 个贷款申请人被认为是良好还是不良信用风险的分类。*表 3*显示了在将数据集提供在线之前考虑的每个变量的详细信息：

| **条目** | **变量** | **解释** |
| --- | --- | --- |
| 1 | `creditability` | 有偿还能力 |
| 2 | `balance` | 当前余额 |
| 3 | `duration` | 申请贷款的期限 |
| 4 | `history` | 是否有不良贷款历史？ |
| 5 | `purpose` | 贷款目的 |
| 6 | `amount` | 申请金额 |
| 7 | `savings` | 每月储蓄 |
| 8 | `employment` | 就业状态 |
| 9 | `instPercent` | 利息百分比 |
| 10 | `sexMarried` | 性别和婚姻状况 |
| 11 | `guarantors` | 是否有担保人？ |
| 12 | `residenceDuration` | 目前地址居住时间 |
| 13 | `assets` | 净资产 |
| 14 | `age` | 申请人年龄 |
| 15 | `concCredit` | 并发信用 |
| 16 | `apartment` | 住宅状况 |
| 17 | `credits` | 当前信用 |
| 18 | `occupation` | 职业 |
| 19 | `dependents` | 受抚养人数 |
| 20 | `hasPhone` | 申请人是否使用电话 |
| 21 | `foreign` | 申请人是否是外国人 |

表 3：德国信用数据集属性

请注意，尽管*表 3*描述了数据集中的变量，但没有相关的标题。在*表 3*中，我们显示了每个变量的位置和相关重要性。

## Spark ML 的信用风险流程

涉及到几个步骤，从数据加载、解析、数据准备、训练测试集准备、模型训练、模型评估和结果解释。让我们逐步进行这些步骤。

**步骤 1：加载所需的 API 和库**

以下是加载所需 API 和库的代码：

```scala
import org.apache.spark.api.java.JavaRDD; 
import org.apache.spark.api.java.function.Function; 
import org.apache.spark.ml.classification.RandomForestClassificationModel; 
import org.apache.spark.ml.classification.RandomForestClassifier; 
import org.apache.spark.ml.evaluation.BinaryClassificationEvaluator; 
import org.apache.spark.ml.feature.StringIndexer; 
import org.apache.spark.ml.feature.VectorAssembler; 
import org.apache.spark.mllib.evaluation.RegressionMetrics; 
import org.apache.spark.sql.Dataset; 
import org.apache.spark.sql.Row; 
import org.apache.spark.sql.SparkSession; 

```

**步骤 2：创建 Spark 会话**

以下是另一个创建 Spark 会话的代码：

```scala
  static SparkSession spark = SparkSession.builder() 
      .appName("CreditRiskAnalysis") 
      .master("local[*]") 
      .config("spark.sql.warehouse.dir", "E:/Exp/") 
      .getOrCreate();  

```

**步骤 3：加载和解析信用风险数据集**

请注意，数据集采用**逗号分隔值**（**CSV**）格式。现在使用 Databricks 提供的 CSV 读取器加载和解析数据集，并准备一个 Row 数据集，如下所示：

```scala
String csvFile = "input/german_credit.data"; 
Dataset<Row> df = spark.read().format("com.databricks.spark.csv").option("header", "false").load(csvFile); 

```

现在，显示数据集以了解确切的结构，如下所示：

```scala
df.show(); 

```

![Spark ML 的信用风险流程](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00104.jpeg)

图 36：信用风险数据集快照

**步骤 4：创建 Credit 类型的 RDD**

创建一个类型为`Credit`的 RDD，如下所示：

```scala
JavaRDD<Credit> creditRDD = df.toJavaRDD().map(new Function<Row, Credit>() { 
      @Override 
      public Credit call(Row r) throws Exception { 
        return new Credit(parseDouble(r.getString(0)), parseDouble(r.getString(1)) - 1, 
            parseDouble(r.getString(2)), parseDouble(r.getString(3)), parseDouble(r.getString(4)), 
            parseDouble(r.getString(5)), parseDouble(r.getString(6)) - 1, parseDouble(r.getString(7)) - 1, 
            parseDouble(r.getString(8)), parseDouble(r.getString(9)) - 1, parseDouble(r.getString(10)) - 1, 
            parseDouble(r.getString(11)) - 1, parseDouble(r.getString(12)) - 1, 
            parseDouble(r.getString(13)), parseDouble(r.getString(14)) - 1, 
            parseDouble(r.getString(15)) - 1, parseDouble(r.getString(16)) - 1, 
            parseDouble(r.getString(17)) - 1, parseDouble(r.getString(18)) - 1, 
            parseDouble(r.getString(19)) - 1, parseDouble(r.getString(20)) - 1); 
      } 
    }); 

```

前面的代码段在使用`parseDouble()`方法将变量作为双精度值创建了一个`Credit`类型的 RDD，该方法接受一个字符串并以`Double`格式返回相应的值。`parseDouble()`方法如下所示：

```scala
  public static double parseDouble(String str) { 
    return Double.parseDouble(str); 
  } 

```

现在我们需要了解`Credit`类的结构，以便结构本身有助于使用类型化类创建 RDD。

嗯，`Credit`类基本上是一个单例类，通过构造函数初始化数据集中的 21 个变量的所有 setter 和 getter 方法。以下是该类：

```scala
public class Credit { 
  private double creditability; 
  private double balance; 
  private double duration; 
  private double history; 
  private double purpose; 
  private double amount; 
  private double savings; 
  private double employment; 
  private double instPercent; 
  private double sexMarried; 
  private double guarantors; 
  private double residenceDuration; 
  private double assets; 
  private double age; 
  private double concCredit; 
  private double apartment; 
  private double credits; 
  private double occupation; 
  private double dependents; 
  private double hasPhone; 
  private double foreign; 

  public Credit(double creditability, double balance, double duration, 
  double history, double purpose, double amount, 
      double savings, double employment, double instPercent, 
      double sexMarried, double guarantors, 
      double residenceDuration, double assets, double age, 
      double concCredit, double apartment, double credits, 
      double occupation, double dependents, double hasPhone, double foreign) { 
    super(); 
    this.creditability = creditability; 
    this.balance = balance; 
    this.duration = duration; 
    this.history = history; 
    this.purpose = purpose; 
    this.amount = amount; 
    this.savings = savings; 
    this.employment = employment; 
    this.instPercent = instPercent; 
    this.sexMarried = sexMarried; 
    this.guarantors = guarantors; 
    this.residenceDuration = residenceDuration; 
    this.assets = assets; 
    this.age = age; 
    this.concCredit = concCredit; 
    this.apartment = apartment; 
    this.credits = credits; 
    this.occupation = occupation; 
    this.dependents = dependents; 
    this.hasPhone = hasPhone; 
    this.foreign = foreign; 
  } 

  public double getCreditability() { 
    return creditability; 
  } 

  public void setCreditability(double creditability) { 
    this.creditability = creditability; 
  } 

  public double getBalance() { 
    return balance; 
  } 

  public void setBalance(double balance) { 
    this.balance = balance; 
  } 

  public double getDuration() { 
    return duration; 
  } 

  public void setDuration(double duration) { 
    this.duration = duration; 
  } 

  public double getHistory() { 
    return history; 
  } 

  public void setHistory(double history) { 
    this.history = history; 
  } 

  public double getPurpose() { 
    return purpose; 
  } 

  public void setPurpose(double purpose) { 
    this.purpose = purpose; 
  } 

  public double getAmount() { 
    return amount; 
  } 

  public void setAmount(double amount) { 
    this.amount = amount; 
  } 

  public double getSavings() { 
    return savings; 
  } 

  public void setSavings(double savings) { 
    this.savings = savings; 
  } 

  public double getEmployment() { 
    return employment; 
  } 

  public void setEmployment(double employment) { 
    this.employment = employment; 
  } 

  public double getInstPercent() { 
    return instPercent; 
  } 

  public void setInstPercent(double instPercent) { 
    this.instPercent = instPercent; 
  } 

  public double getSexMarried() { 
    return sexMarried; 
  } 

  public void setSexMarried(double sexMarried) { 
    this.sexMarried = sexMarried; 
  } 

  public double getGuarantors() { 
    return guarantors; 
  } 

  public void setGuarantors(double guarantors) { 
    this.guarantors = guarantors; 
  } 

  public double getResidenceDuration() { 
    return residenceDuration; 
  } 

  public void setResidenceDuration(double residenceDuration) { 
    this.residenceDuration = residenceDuration; 
  } 

  public double getAssets() { 
    return assets; 
  } 

  public void setAssets(double assets) { 
    this.assets = assets; 
  } 

  public double getAge() { 
    return age; 
  } 

  public void setAge(double age) { 
    this.age = age; 
  } 

  public double getConcCredit() { 
    return concCredit; 
  } 

  public void setConcCredit(double concCredit) { 
    this.concCredit = concCredit; 
  } 

  public double getApartment() { 
    return apartment; 
  } 

  public void setApartment(double apartment) { 
    this.apartment = apartment; 
  } 

  public double getCredits() { 
    return credits; 
  } 

  public void setCredits(double credits) { 
    this.credits = credits; 
  } 

  public double getOccupation() { 
    return occupation; 
  } 

  public void setOccupation(double occupation) { 
    this.occupation = occupation; 
  } 

  public double getDependents() { 
    return dependents; 
  } 

  public void setDependents(double dependents) { 
    this.dependents = dependents; 
  } 

  public double getHasPhone() { 
    return hasPhone; 
  } 

  public void setHasPhone(double hasPhone) { 
    this.hasPhone = hasPhone; 
  } 

  public double getForeign() { 
    return foreign; 
  } 

  public void setForeign(double foreign) { 
    this.foreign = foreign; 
  } 
} 

```

如果您查看类的流程，首先它声明了 21 个变量，对应数据集中的 21 个特征。然后使用构造函数对它们进行初始化。其余的是简单的 setter 和 getter 方法。

**步骤 5：从 Credit 类型的 RDD 创建类型为 Row 的数据集**

以下代码显示如何创建类型为 Row 的数据集：

```scala
Dataset<Row> creditData = spark.sqlContext().createDataFrame(creditRDD, Credit.class); 

```

现在将数据集保存为临时视图，或更正式地说，保存为内存中的表以供查询，如下所示：

```scala
creditData.createOrReplaceTempView("credit"); 

```

现在让我们了解表的模式，如下所示：

```scala
creditData.printSchema(); 

```

![Spark ML 的信用风险流程](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00102.jpeg)

图 37：数据集的模式

**步骤 6：使用 VectorAssembler 创建特征向量**

使用 Spark 的`VectorAssembler`类为 21 个变量创建一个新的特征向量，如下所示：

```scala
VectorAssembler assembler = new VectorAssembler() 
        .setInputCols(new String[] { "balance", "duration", "history", "purpose", "amount", "savings", 
            "employment", "instPercent", "sexMarried", "guarantors", "residenceDuration", "assets", "age", 
            "concCredit", "apartment", "credits", "occupation", "dependents", "hasPhone", "foreign" }) 
        .setOutputCol("features"); 

```

**步骤 7：通过组合和转换组装器创建数据集**

通过使用先前创建的`creditData`数据集转换组装器来创建一个数据集，并打印数据集的前 20 行，如下所示：

```scala
Dataset<Row> assembledFeatures = assembler.transform(creditData); 
assembledFeatures.show(); 

```

![Spark ML 的信用风险流程](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00087.jpeg)

图 38：新创建的特色信用数据集

**步骤 8：创建用于预测的标签**

从前面的数据集（*图 38*）的信用度列创建一个标签列，如下所示：

```scala
StringIndexer creditabilityIndexer = new StringIndexer().setInputCol("creditability").setOutputCol("label"); 
Dataset<Row> creditabilityIndexed = creditabilityIndexer.fit(assembledFeatures).transform(assembledFeatures); 

```

现在让我们使用`show()`方法来探索新的数据集，如下所示：

```scala
creditabilityIndexed.show(); 

```

![使用 Spark ML 的信用风险管道](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00056.jpeg)

图 39：带有新标签列的数据集

从前面的图中，我们可以了解到与数据集相关的标签只有两个，分别是 1.0 和 0.0。这表明问题是一个二元分类问题。

**步骤 9：准备训练和测试集**

按以下方式准备训练和测试集：

```scala
long splitSeed = 12345L; 
Dataset<Row>[] splits = creditabilityIndexed.randomSplit(new double[] { 0.7, 0.3 }, splitSeed); 
Dataset<Row> trainingData = splits[0]; 
Dataset<Row> testData = splits[1]; 

```

在这里，训练集和测试集的比例分别为 70%和 30%，种子值较长，以防止在每次迭代中生成随机结果。

**步骤 10：训练随机森林模型**

要训练随机森林模型，请使用以下代码：

```scala
RandomForestClassifier classifier = new RandomForestClassifier() 
        .setImpurity("gini") 
        .setMaxDepth(3) 
        .setNumTrees(20) 
        .setFeatureSubsetStrategy("auto") 
        .setSeed(splitSeed); 

```

如前所述，问题是一个二元分类问题。因此，我们将使用二元评估器对`label`列评估随机森林模型，如下所示：

```scala
RandomForestClassificationModel model = classifier.fit(trainingData); 
BinaryClassificationEvaluator evaluator = new BinaryClassificationEvaluator().setLabelCol("label"); 

```

现在我们需要在测试集上收集模型性能指标，如下所示：

```scala
Dataset<Row> predictions = model.transform(testData); 
model.toDebugString(); 

```

**步骤 11：打印性能参数**

我们将观察二元评估器的几个性能参数，例如拟合模型后的准确性，**均方误差**（**MSE**），**平均绝对误差**（**MAE**），**均方根误差**（**RMSE**），R 平方和解释变量等。让我们按照以下方式进行：

```scala
double accuracy = evaluator.evaluate(predictions); 
System.out.println("Accuracy after pipeline fitting: " + accuracy); 
RegressionMetrics rm = new RegressionMetrics(predictions); 
System.out.println("MSE: " + rm.meanSquaredError()); 
System.out.println("MAE: " + rm.meanAbsoluteError()); 
System.out.println("RMSE Squared: " + rm.rootMeanSquaredError()); 
System.out.println("R Squared: " + rm.r2()); 
System.out.println("Explained Variance: " + rm.explainedVariance() + "\n"); 

```

前面的代码段生成了以下输出：

```scala
Accuracy after pipeline fitting: 0.7622000403307129 
MSE: 1.926235109206349E7 
MAE: 3338.3492063492063 
RMSE Squared: 4388.8895055655585 
R Squared: -1.372326447615067 
Explained Variance: 1.1144695981899707E7 

```

### 性能调优和建议

如果您查看第 11 步的性能指标，显然信用风险预测不尽如人意，特别是在准确性方面，只有 76.22%。这意味着对于给定的测试数据，我们的模型可以以 76.22%的精度预测是否存在信用风险。由于我们需要对这些敏感的金融领域更加小心，因此无疑需要更高的准确性。

现在，如果您想提高预测性能，您应该尝试使用除基于随机森林的分类器之外的其他模型进行模型训练。例如，逻辑回归或朴素贝叶斯分类器。

此外，您可以使用基于 SVM 的分类器或基于神经网络的多层感知器分类器。在第七章中，*调整机器学习模型*，我们将看看如何调整超参数以选择最佳模型。

# 扩展 ML 管道

数据挖掘和机器学习算法对并行和分布式计算平台提出了巨大挑战。此外，并行化机器学习算法高度依赖于任务的特定性，并且通常取决于前面提到的问题。在第一章中，*使用 Spark 进行数据分析简介*，我们讨论并展示了如何在集群或云计算基础设施（即 Amazon AWS/EC2）上部署相同的机器学习应用。

按照这种方法，我们可以处理具有巨大批量大小或实时处理的数据集。除此之外，扩展机器学习应用还涉及到成本、复杂性、运行时间和技术要求等其他权衡。此外，为了进行大规模机器学习的任务，需要了解可用选项的优势、权衡和约束，以做出适合任务的算法和平台选择。

为了解决这些问题，在本节中，我们将提供一些处理大型数据集以部署大规模机器学习应用的理论方面。然而，在进一步进行之前，我们需要知道一些问题的答案。例如：

+   我们如何收集大型数据集以满足我们的需求？

+   大数据集有多大，我们如何处理它们？

+   有多少训练数据足以扩展大型数据集上的 ML 应用？

+   如果我们没有足够的训练数据，有什么替代方法？

+   应该使用什么样的机器学习算法来满足我们的需求？

+   应选择哪种平台进行并行学习？

在这里，我们讨论了部署和扩展处理前述大数据挑战的机器学习应用的一些重要方面，包括大小、数据偏斜、成本和基础设施。

## 大小很重要

大数据是指量、种类、真实性、速度和价值都太大，以至于传统的内存计算机系统无法处理。通过处理大数据来扩展机器学习应用涉及任务，如分类、聚类、回归、特征选择、提升决策树和支持向量机。我们如何处理 10 亿或 1 万亿的数据实例？此外，50 亿部手机、Twitter 等社交网络以前所未有的方式产生大数据集。另一方面，众包是现实，即在一周内标记 10 万个以上的数据实例。

就稀疏性而言，大数据集不能太稀疏，而从内容角度来看要密集。从机器学习的角度来看，为了证明这一点，让我们想象一个数据标记的例子。例如，100 万个数据实例不可能属于 100 万个类别，因为拥有 100 万个类别是不切实际的，而且多个数据实例属于特定类别。因此，基于如此大规模数据集的稀疏性和大小，进行预测分析是另一个需要考虑和处理的挑战。

## 大小与偏斜度考虑

机器学习还取决于标记数据的可用性，其可信度取决于学习任务，如监督、无监督或半监督。您可能拥有结构化数据，但存在极端的偏斜。更具体地说，假设您有 1K 个标记和 1M 个未标记的数据点，因此标记和未标记的比例为 0.1%。

因此，您认为只有 1K 标签点足以训练监督模型吗？再举一个例子，假设您有 1M 个标记和 1B 个未标记的数据点，其中标记和未标记的比例也是 0.1%。同样，又出现了同样的问题，即，仅有 1M 个标签足以训练监督模型吗？

现在的问题是，使用现有标签作为半监督聚类、分类或回归的指导而不是指令，可以采取什么措施或方法。或者，标记更多的数据，要么手动标记，要么在众包的帮助下。例如，假设有人想对某种疾病进行聚类或分类分析。更具体地说，假设我们想对推文进行分类，看特定的推文是否指示出与埃博拉或流感相关的疾病。在这种情况下，我们应该使用半监督方法来标记推文。

然而，在这种情况下，数据集可能非常偏斜，或者标记可能存在偏见。通常，训练数据来自不同的用户，其中显式用户反馈可能经常具有误导性。

因此，从隐式反馈中学习是一个更好的主意；例如，通过点击网络搜索结果收集数据。在这些类型的大规模数据集中，训练数据的偏斜很难检测到，如在第四章中讨论的，*通过特征工程提取知识*。因此，在大数据集中要警惕这种偏斜。

## 成本和基础设施

要扩展您的机器学习应用，您将需要更好的基础设施和计算能力来处理如此庞大的数据集。最初，您可能希望利用本地集群。然而，有时，如果数据集呈指数增长，集群可能不足以扩展您的机器学习应用。

在部署 ML 管道到强大基础设施（如亚马逊 AWS 云计算，如 EC2）的章节中，您将不得不选择按使用量付费，以享受云作为平台即服务和基础设施即服务，即使您使用自己的 ML 应用作为软件即服务。

# 提示和性能考虑

Spark 还支持用于超参数调整的交叉验证，这将在下一章中广泛讨论。Spark 将交叉验证视为一种元算法，它使用用户指定的参数组合来拟合底层估计器，交叉评估拟合模型并输出最佳模型。

然而，对于底层估计器并没有特定的要求，它可以是一个管道，只要它能够与一个评估器配对，输出预测的标量度量，如精度和召回率。

让我们回顾 OCR 预测，我们发现精度为 75%，显然是不令人满意的。现在让我们进一步调查原因，打印出标签 8.0 或“I”的混淆矩阵。如果您查看*图 40*中的矩阵，您会发现正确预测的实例数量很少：

![提示和性能考虑](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00045.jpeg)

图 40：标签 8.0 或“I”的混淆矩阵

现在让我们尝试使用随机森林模型进行预测。但在进入模型训练步骤之前，让我们对随机森林分类器所需的参数进行一些初始化，它也支持多类分类，如 LBFGS 的逻辑回归模型：

```scala
Integer numClasses = 26; 
HashMap<Integer, Integer>categoricalFeaturesInfo = new HashMap<Integer, Integer>(); 
Integer numTrees = 5; // Use more in practice. 
String featureSubsetStrategy = "auto"; // Let the algorithm choose. 
String impurity = "gini"; 
Integer maxDepth = 20; 
Integer maxBins = 40; 
Integer seed = 12345; 

```

现在通过指定先前的参数来训练模型，如下所示：

```scala
final RandomForestModelmodel = RandomForest.trainClassifier(training, numClasses, categoricalFeaturesInfo, numTrees, featureSubsetStrategy, impurity, maxDepth, maxBins, seed); 

```

现在让我们看看它的表现。我们将重用我们在第 9 步中使用的相同代码段。请参考以下截图：

![提示和性能考虑](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00027.jpeg)

图 41：精度和召回率的性能指标

![提示和性能考虑](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lgscl-ml-spark/img/00154.jpeg)

图 42：标签 8.0 或“I”的改进混淆矩阵

如果您查看*图 42*，您会发现在所有打印的参数方面有显著的改善，精度已从 75.30%提高到 89.20%。这背后的原因是随机森林模型对于全局最大值计算的改进解释，以及混淆矩阵，如*图 38*所示；您会发现由对角箭头标记的预测实例数量有显著改善。

通过反复试验，您可以确定一组显示潜力的算法，但是您如何知道哪个是最好的呢？此外，如前所述，很难为您的数据集找到表现良好的机器学习算法。因此，如果您对 89.20%的准确性仍然不满意，我建议您调整参数值并查看精度和召回率。

# 总结

在本章中，我们展示了几个机器学习应用，并试图区分 Spark MLlib 和 Spark ML。我们还表明，仅使用 Spark ML 或 Spark MLlib 开发完整的机器学习应用是非常困难的。

然而，我们想要提出一个结合的方法，或者说这两个 API 之间的互操作性，对于这些目的来说是最好的。此外，我们学习了如何使用 Spark ML 库构建 ML 管道，以及如何通过考虑一些性能考虑因素来扩展基本模型。

调整算法或机器学习应用可以简单地被认为是一个过程，通过这个过程，您可以优化影响模型的参数，以使算法在其最佳状态下运行（就运行时间和内存使用而言）。

在第七章中，*调整机器学习模型*，我们将更多地讨论调整机器学习模型的内容。我们将尝试重用本章和第五章中的一些应用，通过调整几个参数来提高性能。
