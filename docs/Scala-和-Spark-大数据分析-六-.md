# Scala 和 Spark 大数据分析（六）

> 原文：[`zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A`](https://zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：高级机器学习最佳实践

“超参数优化或模型选择是选择学习算法的一组超参数[何时定义为？]的问题，通常目标是优化算法在独立数据集上的性能度量。”

- 机器学习模型调整报价

在本章中，我们将提供一些关于使用 Spark 进行机器学习（ML）的一些高级主题的理论和实践方面。我们将看到如何使用网格搜索、交叉验证和超参数调整来调整机器学习模型，以获得更好和优化的性能。在后面的部分，我们将介绍如何使用 ALS 开发可扩展的推荐系统，这是一个基于模型的推荐算法的示例。最后，将演示一种文本聚类技术作为主题建模应用。

简而言之，本章中我们将涵盖以下主题：

+   机器学习最佳实践

+   ML 模型的超参数调整

+   使用潜在狄利克雷分配（LDA）进行主题建模

+   使用协同过滤的推荐系统

# 机器学习最佳实践

有时，建议考虑错误率而不仅仅是准确性。例如，假设一个 ML 系统的准确率为 99%，错误率为 50%，比一个准确率为 90%，错误率为 25%的系统更差。到目前为止，我们已经讨论了以下机器学习主题：

+   **回归**：用于预测线性可分离的值

+   **异常检测**：用于发现异常数据点，通常使用聚类算法进行

+   **聚类**：用于发现数据集中同质数据点的隐藏结构

+   **二元分类**：用于预测两个类别

+   **多类分类**：用于预测三个或更多类别

好吧，我们也看到了一些适合这些任务的好算法。然而，选择适合您问题类型的正确算法是实现 ML 算法更高和更出色准确性的棘手任务。为此，我们需要通过从数据收集、特征工程、模型构建、评估、调整和部署的阶段采用一些良好的实践。考虑到这些，在本节中，我们将在使用 Spark 开发 ML 应用程序时提供一些建议。

# 注意过拟合和欠拟合

一条直线穿过一个弯曲的散点图将是欠拟合的一个很好的例子，正如我们在这里的图表中所看到的。然而，如果线条过于贴合数据，就会出现一个相反的问题，称为**过拟合**。当我们说一个模型过拟合了数据集，我们的意思是它可能在训练数据上有低错误率，但在整体数据中不能很好地泛化。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00148.jpeg)**图 1**：过拟合-欠拟合权衡（来源：亚当吉布森，乔什帕特森的书《深度学习》）

更具体地说，如果您在训练数据上评估模型而不是测试或验证数据，您可能无法确定您的模型是否过拟合。常见的症状如下：

+   用于训练的数据的预测准确性可能过于准确（即有时甚至达到 100%）。

+   与随机预测相比，模型可能在新数据上表现更好。

+   我们喜欢将数据集拟合到分布中，因为如果数据集与分布相当接近，我们可以基于理论分布对我们如何处理数据进行假设。因此，数据中的正态分布使我们能够假设在指定条件下统计的抽样分布是正态分布的。正态分布由其均值和标准差定义，并且在所有变化中通常具有相同的形状。

**图 2**：数据中的正态分布有助于克服过度拟合和拟合不足（来源：Adam Gibson、Josh Patterson 的《深度学习》一书）

有时，ML 模型本身对特定调整或数据点拟合不足，这意味着模型变得过于简单。我们的建议（我们相信其他人也是如此）如下：

+   将数据集分为两组以检测过度拟合情况——第一组用于训练和模型选择的训练集，第二组是用于评估模型的测试集，开始替代 ML 工作流程部分。

+   或者，您还可以通过使用更简单的模型（例如，线性分类器而不是高斯核 SVM）或增加 ML 模型的正则化参数（如果可用）来避免过度拟合。

+   调整模型的正确数据值参数，以避免过度拟合和拟合不足。

+   因此，解决拟合不足是首要任务，但大多数机器学习从业者建议花更多时间和精力尝试不要过度拟合数据。另一方面，许多机器学习从业者建议将大规模数据集分为三组：训练集（50%）、验证集（25%）和测试集（25%）。他们还建议使用训练集构建模型，并使用验证集计算预测误差。测试集被推荐用于评估最终模型的泛化误差。然而，在监督学习期间，如果可用的标记数据量较小，则不建议拆分数据集。在这种情况下，使用交叉验证。更具体地说，将数据集分为大致相等的 10 个部分；然后，对这 10 个部分中的每一个，迭代训练分类器，并使用第 10 个部分来测试模型。

# 请继续关注 Spark MLlib 和 Spark ML

管道设计的第一步是创建构件块（作为由节点和边组成的有向或无向图），并在这些块之间建立联系。然而，作为一名数据科学家，您还应该专注于扩展和优化节点（原语），以便在后期处理大规模数据集时能够扩展应用程序，使您的 ML 管道能够持续执行。管道过程还将帮助您使模型适应新数据集。然而，其中一些原语可能会明确定义为特定领域和数据类型（例如文本、图像和视频、音频和时空）。

除了这些类型的数据之外，原语还应该适用于通用领域统计或数学。将您的 ML 模型转换为这些原语将使您的工作流程更加透明、可解释、可访问和可解释。

最近的一个例子是 ML-matrix，它是一个可以在 Spark 之上使用的分布式矩阵库。请参阅[JIRA 问题](https://issues.apache.org/jira/browse/SPARK-3434)。

**图 3**：保持关注并相互操作 ML 和 MLlib

正如我们在前一节中已经提到的，作为开发人员，您可以无缝地将 Spark MLlib 中的实现技术与 Spark ML、Spark SQL、GraphX 和 Spark Streaming 中开发的算法结合起来，作为 RDD、DataFrame 和数据集的混合或可互操作的 ML 应用程序，如*图 3*所示。因此，这里的建议是与您周围的最新技术保持同步，以改善您的 ML 应用程序。

# 为您的应用程序选择正确的算法

“我应该使用什么机器学习算法？”是一个非常常见的问题，但答案总是“这取决于”。更详细地说：

+   这取决于你要测试/使用的数据的数量、质量、复杂性和性质

+   这取决于外部环境和参数，比如你的计算系统配置或基础设施

+   这取决于你想要用答案做什么

+   这取决于算法的数学和统计公式如何被转化为计算机的机器指令

+   这取决于你有多少时间

事实上，即使是最有经验的数据科学家或数据工程师在尝试所有算法之前也无法直接推荐哪种机器学习算法会表现最好。大多数同意/不同意的陈述都以“这取决于...嗯...”开始。习惯上，你可能会想知道是否有机器学习算法的备忘单，如果有的话，你应该如何使用？一些数据科学家表示，找到最佳算法的唯一方法是尝试所有算法；因此，没有捷径！让我们更清楚地说明一下；假设你有一组数据，你想做一些聚类。从技术上讲，如果你的数据有标签，这可能是一个分类或回归问题。然而，如果你有一个无标签的数据集，你将使用聚类技术。现在，你脑海中出现的问题如下：

+   在选择适当的算法之前，我应该考虑哪些因素？还是应该随机选择一个算法？

+   我如何选择适用于我的数据的任何数据预处理算法或工具？

+   我应该使用什么样的特征工程技术来提取有用的特征？

+   什么因素可以提高我的机器学习模型的性能？

+   我如何适应新的数据类型？

+   我能否扩展我的机器学习应用以处理大规模数据集？等等。

在本节中，我们将尝试用我们有限的机器学习知识来回答这些问题。

# 选择算法时的考虑因素

我们在这里提供的建议或建议是给那些刚开始学习机器学习的新手数据科学家。这些对于试图选择一个最佳算法来开始使用 Spark ML API 的专家数据科学家也会有用。不用担心，我们会指导你的方向！我们还建议在选择算法时考虑以下算法属性：

+   **准确性**：是否达到最佳分数是目标，还是在精确度、召回率、f1 分数或 AUC 等方面进行权衡，得到一个近似解（足够好），同时避免过拟合。

+   **训练时间**：训练模型的可用时间（包括模型构建、评估和训练时间）。

+   **线性度**：模型复杂性的一个方面，涉及问题建模的方式。由于大多数非线性模型通常更复杂，难以理解和调整。

+   **参数数量**

+   **特征数量**：拥有的属性比实例多的问题，即*p>>n*问题。这通常需要专门处理或使用降维或更好的特征工程方法。

# 准确性

从你的机器学习应用中获得最准确的结果并非总是必不可少的。根据你想要使用它的情况，有时近似解就足够了。如果情况是这样的，你可以通过采用更好的估计方法大大减少处理时间。当你熟悉了 Spark 机器学习 API 的工作流程后，你将享受到更多的近似方法的优势，因为这些近似方法将自动避免你的机器学习模型的过拟合问题。现在，假设你有两个二元分类算法的表现如下：

| **分类器** | **精确度** | **召回率** |
| --- | --- | --- |
| X | 96% | 89% |
| Y | 99% | 84% |

在这里，没有一个分类器显然优于其他分类器，因此它不会立即指导您选择最佳的分类器。F1 分数是精确度和召回率的调和平均值，它可以帮助您。让我们计算一下，并将其放在表中：

| **分类器** | **精度** | **召回率** | **F1 分数** |
| --- | --- | --- | --- |
| X | 96% | 89% | 92.36% |
| Y | 99% | 84% | 90.885% |

因此，具有 F1 分数有助于从大量分类器中进行选择。它为所有分类器提供了清晰的偏好排序，因此也为进展提供了明确的方向--即分类器**X**。

# 训练时间

训练时间通常与模型训练和准确性密切相关。此外，通常您会发现，与其他算法相比，有些算法对数据点的数量更加难以捉摸。然而，当您的时间不足但训练集又很大且具有许多特征时，您可以选择最简单的算法。在这种情况下，您可能需要牺牲准确性。但至少它将满足您的最低要求。

# 线性

最近开发了许多利用线性的机器学习算法（也可在 Spark MLlib 和 Spark ML 中使用）。例如，线性分类算法假设类别可以通过绘制不同的直线或使用高维等价物来分离。另一方面，线性回归算法假设数据趋势简单地遵循一条直线。对于一些机器学习问题，这种假设并不天真；然而，在某些其他情况下，准确性可能会下降。尽管存在危险，线性算法在数据工程师和数据科学家中非常受欢迎，作为爆发的第一线。此外，这些算法还倾向于简单和快速，以在整个过程中训练您的模型。

# 在选择算法时检查您的数据

您将在 UC Irvine 机器学习库中找到许多机器学习数据集。以下数据属性也应该优先考虑：

+   参数数量

+   特征数量

+   训练数据集的大小

# 参数数量

参数或数据属性是数据科学家在设置算法时的抓手。它们是影响算法性能的数字，如误差容限或迭代次数，或者是算法行为变体之间的选项。算法的训练时间和准确性有时可能非常敏感，这使得难以找到正确的设置。通常，具有大量参数的算法需要更多的试错来找到最佳组合。

尽管这是跨越参数空间的一个很好的方法，但随着参数数量的增加，模型构建或训练时间呈指数增长。这既是一个困境，也是一个时间性能的权衡。积极的方面是：

+   具有许多参数特征性地表明了 ML 算法的更大灵活性

+   您的 ML 应用程序实现了更高的准确性

# 你的训练集有多大？

如果您的训练集较小，具有低方差的高偏差分类器，如朴素贝叶斯，比具有高方差的低偏差分类器（也可用于回归）如**k 最近邻算法**（**kNN**）更有优势。

**偏差、方差和 kNN 模型：**实际上，*增加 k*会*减少方差*，但会*增加偏差*。另一方面，*减少 k*会*增加方差*，*减少偏差*。随着*k*的增加，这种变异性减少。但如果我们增加*k*太多，那么我们就不再遵循真实的边界线，我们会观察到高偏差。这就是偏差-方差权衡的本质。

我们已经看到了过拟合和欠拟合的问题。现在，可以假设处理偏差和方差就像处理过拟合和欠拟合一样。随着模型复杂性的增加，偏差减小，方差增加。随着模型中添加更多参数，模型的复杂性增加，方差成为我们关注的主要问题，而偏差稳步下降。换句话说，偏差对模型复杂性的响应具有负的一阶导数，而方差具有正的斜率。请参考以下图表以更好地理解：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00077.jpeg)**图 4：** 偏差和方差对总误差的影响

因此，后者会过拟合。但是低偏差高方差的分类器，在训练集线性或指数增长时，开始获胜，因为它们具有更低的渐近误差。高偏差分类器不足以提供准确的模型。

# 特征数

对于某些类型的实验数据集，提取的特征数量可能与数据点本身的数量相比非常大。这在基因组学、生物医学或文本数据中经常发生。大量的特征可能会淹没一些学习算法，使训练时间变得非常长。**支持向量机**（**SVM**）特别适用于这种情况，因为它具有高准确性，对过拟合有良好的理论保证，并且具有适当的核函数。

**支持向量机和核函数：** 任务是找到一组权重和偏差，使间隔最大化函数：

y = w*¥(x) +b,

其中*w*是权重，*¥*是特征向量，*b*是偏差。现在如果*y> 0*，那么我们将数据分类到类*1*，否则到类*0*，而特征向量*¥(x)*使数据线性可分。然而，使用核函数可以使计算过程更快、更容易，特别是当特征向量*¥*包含非常高维的数据时。让我们看一个具体的例子。假设我们有以下值*x*和*y*：*x = (x1, x2, x3)*和*y = (y1, y2, y3)*，那么对于函数*f(x) = (x1x1, x1x2, x1x3, x2x1, x2x2, x2x3, x3x1, x3x2, x3x3)*，核函数是*K(x, y ) = (<x, y>)²*。根据上述，如果*x* *= (1, 2, 3)*和*y = (4, 5, 6)*，那么我们有以下值：

f(x) = (1, 2, 3, 2, 4, 6, 3, 6, 9)

f(y) = (16, 20, 24, 20, 25, 30, 24, 30, 36)

<f(x), f(y)> = 16 + 40 + 72 + 40 + 100+ 180 + 72 + 180 + 324 = 1024

这是一个简单的线性代数，将一个 3 维空间映射到一个 9 维空间。另一方面，核函数是用于支持向量机的相似性度量。因此，建议根据对不变性的先验知识选择适当的核值。核和正则化参数的选择可以通过优化基于交叉验证的模型选择来自动化。

然而，自动选择核和核参数是一个棘手的问题，因为很容易过度拟合模型选择标准。这可能导致比开始时更糟糕的模型。现在，如果我们使用核函数*K(x, y)*，这将给出相同的值，但计算更简单 - 即(4 + 10 + 18) ² = 32² = 1024。

# 机器学习模型的超参数调整

调整算法只是一个过程，通过这个过程，使算法在运行时间和内存使用方面表现最佳。在贝叶斯统计中，超参数是先验分布的参数。在机器学习方面，超参数指的是那些不能直接从常规训练过程中学习到的参数。超参数通常在实际训练过程开始之前固定。这是通过为这些超参数设置不同的值，训练不同的模型，并通过测试来决定哪些模型效果最好来完成的。以下是一些典型的超参数示例：

+   叶子节点数、箱数或树的深度

+   迭代次数

+   矩阵分解中的潜在因子数量

+   学习率

+   深度神经网络中的隐藏层数量

+   k 均值聚类中的簇数量等。

在本节中，我们将讨论如何使用交叉验证技术和网格搜索进行超参数调整。

# 超参数调整

超参数调整是一种根据呈现数据的性能选择正确的超参数组合的技术。这是从实践中获得机器学习算法的有意义和准确结果的基本要求之一。下图显示了模型调整过程、考虑因素和工作流程：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00343.jpeg)**图 5**：模型调整过程、考虑因素和工作流程

例如，假设我们有两个要为管道调整的超参数，该管道在第十一章中的*图 17*中呈现，使用逻辑回归估计器的 Spark ML 管道模型（虚线只会在管道拟合期间出现）。我们可以看到我们为每个参数放置了三个候选值。因此，总共会有九种组合。但是，在图中只显示了四种，即 Tokenizer、HashingTF、Transformer 和 Logistic Regression（LR）。现在，我们要找到最终会导致具有最佳评估结果的模型。拟合的模型包括 Tokenizer、HashingTF 特征提取器和拟合的逻辑回归模型：

如果您回忆起第十一章中的*图 17*，*学习机器学习 - Spark MLlib 和 Spark ML*，虚线只会在管道拟合期间出现。正如前面提到的，拟合的管道模型是一个 Transformer。Transformer 可用于预测、模型验证和模型检查。此外，我们还认为 ML 算法的一个不幸的特点是，它们通常有许多需要调整以获得更好性能的超参数。例如，这些超参数中的正则化程度与 Spark MLlib 优化的模型参数有所不同。

因此，如果没有对数据和要使用的算法的专业知识，很难猜测或衡量最佳超参数组合。由于复杂数据集基于 ML 问题类型，管道的大小和超参数的数量可能会呈指数级增长（或线性增长）；即使对于 ML 专家来说，超参数调整也会变得繁琐，更不用说调整参数的结果可能会变得不可靠。

根据 Spark API 文档，用于指定 Spark ML 估计器和 Transformer 的是一个独特且统一的 API。`ParamMap`是一组(参数，值)对，其中 Param 是由 Spark 提供的具有自包含文档的命名参数。从技术上讲，有两种方法可以将参数传递给算法，如下所示：

+   **设置参数**：如果 LR 是逻辑回归的实例（即估计器），则可以调用`setMaxIter()`方法，如下所示：`LR.setMaxIter(5)`。它基本上将模型拟合到回归实例，如下所示：`LR.fit()`。在这个特定的例子中，最多会有五次迭代。

+   **第二个选项**：这涉及将`ParamMaps`传递给`fit()`或`transform()`（有关详细信息，请参见*图 5*）。在这种情况下，任何参数都将被先前通过 ML 应用程序特定代码或算法中的 setter 方法指定的`ParamMaps`覆盖。

# 网格搜索参数调整

假设您在必要的特征工程之后选择了您的超参数。在这方面，对超参数和特征空间进行完整的网格搜索计算量太大。因此，您需要执行 K 折交叉验证的折叠，而不是进行完整的网格搜索：

+   在折叠的训练集上使用交叉验证来调整所需的超参数，使用所有可用的特征

+   使用这些超参数选择所需的特征

+   对 K 中的每个折叠重复计算

+   最终模型是使用从每个 CV 折叠中选择的 N 个最常见特征构建的所有数据

有趣的是，超参数也将在交叉验证循环中再次进行调整。与完整的网格搜索相比，这种方法会有很大的不利因素吗？实质上，我在每个自由参数的维度上进行线性搜索（找到一个维度中的最佳值，将其保持恒定，然后找到下一个维度中的最佳值），而不是每个参数设置的所有组合。沿着单个参数搜索而不是一起优化它们的最重要的不利因素是，您忽略了相互作用。

例如，很常见的是，不止一个参数影响模型复杂性。在这种情况下，您需要查看它们的相互作用，以成功地优化超参数。根据您的数据集有多大以及您比较了多少个模型，返回最大观察性能的优化策略可能会遇到麻烦（这对网格搜索和您的策略都是如此）。

原因是在大量性能估计中寻找最大值会削弱性能估计的方差：您可能最终只得到一个模型和训练/测试分割组合，碰巧看起来不错。更糟糕的是，您可能会得到几个看起来完美的组合，然后优化无法知道选择哪个模型，因此变得不稳定。

# 交叉验证

交叉验证（也称为**旋转估计**（**RE**））是一种模型验证技术，用于评估统计分析和结果的质量。目标是使模型向独立测试集泛化。交叉验证技术的一个完美用途是从机器学习模型中进行预测。如果您想要估计在实践中部署为 ML 应用时预测模型的准确性，这将有所帮助。在交叉验证过程中，模型通常是使用已知类型的数据集进行训练的。相反，它是使用未知类型的数据集进行测试的。

在这方面，交叉验证有助于描述数据集，以便在训练阶段使用验证集测试模型。有两种类型的交叉验证，可以如下分类：

+   **穷举交叉验证**：这包括留 p-out 交叉验证和留一出交叉验证。

+   **非穷尽交叉验证**：这包括 K 折交叉验证和重复随机子采样交叉验证。

在大多数情况下，研究人员/数据科学家/数据工程师使用 10 折交叉验证，而不是在验证集上进行测试。这是最广泛使用的交叉验证技术，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00372.gif)**图 6：**交叉验证基本上将您的完整可用训练数据分成多个折叠。可以指定此参数。然后，整个流程对每个折叠运行一次，并为每个折叠训练一个机器学习模型。最后，通过分类器的投票方案或回归的平均值将获得的不同机器学习模型结合起来

此外，为了减少变异性，使用不同分区进行多次交叉验证迭代；最后，将验证结果在各轮上进行平均。下图显示了使用逻辑回归进行超参数调整的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00046.jpeg)**图 7：**使用逻辑回归进行超参数调整的示例

使用交叉验证而不是传统验证有以下两个主要优点：

+   首先，如果没有足够的数据可用于在单独的训练和测试集之间进行分区，就有可能失去重要的建模或测试能力。

+   其次，K 折交叉验证估计器的方差低于单个留出集估计器。这种低方差限制了变异性，如果可用数据量有限，这也是非常重要的。

在这些情况下，一个公平的方法来正确估计模型预测和相关性能是使用交叉验证作为模型选择和验证的强大通用技术。如果我们需要对模型调整进行手动特征和参数选择，然后，我们可以在整个数据集上进行 10 折交叉验证的模型评估。什么是最佳策略？我们建议您选择提供乐观分数的策略如下：

+   将数据集分为训练集（80%）和测试集（20%）或您选择的其他比例

+   在训练集上使用 K 折交叉验证来调整您的模型

+   重复 CV，直到找到优化并调整您的模型。

现在，使用您的模型在测试集上进行预测，以获得模型外误差的估计。

# 信用风险分析-超参数调整的一个例子

在本节中，我们将展示一个实际的机器学习超参数调整的示例，涉及网格搜索和交叉验证技术。更具体地说，首先，我们将开发一个信用风险管道，这在金融机构如银行和信用合作社中常用。随后，我们将看看如何通过超参数调整来提高预测准确性。在深入示例之前，让我们快速概述一下信用风险分析是什么，以及为什么它很重要？

# 什么是信用风险分析？为什么它很重要？

当申请人申请贷款并且银行收到该申请时，根据申请人的资料，银行必须决定是否批准贷款申请。在这方面，银行对贷款申请的决定存在两种风险：

+   **申请人是一个良好的信用风险**：这意味着客户或申请人更有可能偿还贷款。然后，如果贷款未获批准，银行可能会遭受业务损失。

+   **申请人是一个不良的信用风险**：这意味着客户或申请人很可能不会偿还贷款。在这种情况下，向客户批准贷款将导致银行的财务损失。

该机构表示第二个风险比第一个更高，因为银行有更高的机会无法收回借款金额。因此，大多数银行或信用合作社评估向客户、申请人或顾客放贷所涉及的风险。在业务分析中，最小化风险往往会最大化银行自身的利润。

换句话说，从财务角度来看，最大化利润和最小化损失是重要的。通常，银行根据申请人的不同因素和参数，如贷款申请的人口统计和社会经济状况，来决定是否批准贷款申请。

# 数据集探索

德国信用数据集是从 UCI 机器学习库[`archive.ics.uci.edu/ml/machine-learning-databases/statlog/german/`](https://archive.ics.uci.edu/ml/machine-learning-databases/statlog/german/)下载的。尽管链接中提供了数据集的详细描述，但我们在**表 3**中提供了一些简要的见解。数据包含 21 个变量的与信用相关的数据，以及对于 1000 个贷款申请人是否被认为是良好还是不良的信用风险的分类（即二元分类问题）。

以下表格显示了在将数据集提供在线之前考虑的每个变量的详细信息：

| **条目** | **变量** | **解释** |
| --- | --- | --- |
| 1 | creditability | 有能力偿还：值为 1.0 或 0.0 |
| 2 | balance | 当前余额 |
| 3 | duration | 申请贷款的期限 |
| 4 | history | 是否有不良贷款历史？ |
| 5 | purpose | 贷款目的 |
| 6 | amount | 申请金额 |
| 7 | savings | 每月储蓄 |
| 8 | employment | 就业状况 |
| 9 | instPercent | 利息百分比 |
| 10 | sexMarried | 性别和婚姻状况 |
| 11 | guarantors | 是否有担保人？ |
| 12 | residenceDuration | 目前地址的居住时间 |
| 13 | assets | 净资产 |
| 14 | age | 申请人年龄 |
| 15 | concCredit | 并发信用 |
| 16 | apartment | 住房状况 |
| 17 | credits | 当前信用 |
| 18 | occupation | 职业 |
| 19 | dependents | 受抚养人数 |
| 20 | hasPhone | 申请人是否使用电话 |
| 21 | foreign | 申请人是否是外国人 |

请注意，尽管*表 3*描述了具有相关标题的变量，但数据集中没有相关标题。在*表 3*中，我们展示了每个变量的变量、位置和相关重要性。

# 使用 Spark ML 的逐步示例

在这里，我们将提供使用随机森林分类器进行信用风险预测的逐步示例。步骤包括数据摄入、一些统计分析、训练集准备，最后是模型评估：

**步骤 1.** 加载并解析数据集为 RDD：

```scala
val creditRDD = parseRDD(sc.textFile("data/germancredit.csv")).map(parseCredit) 

```

对于前一行，`parseRDD()`方法用于使用`,`拆分条目，然后将它们全部转换为`Double`值（即数值）。该方法如下：

```scala
def parseRDD(rdd: RDD[String]): RDD[Array[Double]] = { 
rdd.map(_.split(",")).map(_.map(_.toDouble)) 
  } 

```

另一方面，`parseCredit()`方法用于基于`Credit` case 类解析数据集：

```scala
def parseCredit(line: Array[Double]): Credit = { 
Credit( 
line(0), line(1) - 1, line(2), line(3), line(4), line(5), 
line(6) - 1, line(7) - 1, line(8), line(9) - 1, line(10) - 1, 
line(11) - 1, line(12) - 1, line(13), line(14) - 1, line(15) - 1, 
line(16) - 1, line(17) - 1, line(18) - 1, line(19) - 1, line(20) - 1) 
  } 

```

`Credit` case 类如下所示：

```scala
case class Credit( 
creditability: Double, 
balance: Double, duration: Double, history: Double, purpose: Double, amount: Double, 
savings: Double, employment: Double, instPercent: Double, sexMarried: Double, guarantors: Double, 
residenceDuration: Double, assets: Double, age: Double, concCredit: Double, apartment: Double, 
credits: Double, occupation: Double, dependents: Double, hasPhone: Double, foreign: Double) 

```

**步骤 2.准备 ML 管道的 DataFrame** - 获取 ML 管道的 DataFrame

```scala
val sqlContext = new SQLContext(sc) 
import sqlContext._ 
import sqlContext.implicits._ 
val creditDF = creditRDD.toDF().cache() 

```

将它们保存为临时视图，以便更容易进行查询：

```scala
creditDF.createOrReplaceTempView("credit") 

```

让我们来看一下 DataFrame 的快照：

```scala
creditDF.show

```

前面的`show()`方法打印了信用 DataFrame：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00124.gif)**图 8：**信用数据集的快照

**步骤 3.观察相关统计数据** - 首先，让我们看一些聚合值：

```scala
sqlContext.sql("SELECT creditability, avg(balance) as avgbalance, avg(amount) as avgamt, avg(duration) as avgdur  FROM credit GROUP BY creditability ").show 

```

让我们看一下余额的统计信息：

```scala
creditDF.describe("balance").show 

```

现在，让我们看一下平均余额的信用性：

```scala
creditDF.groupBy("creditability").avg("balance").show 

```

三行的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00030.gif)**图 9：**数据集的一些统计信息

**步骤 4.特征向量和标签的创建** - 如您所见，可信度列是响应列，为了得到结果，我们需要创建不考虑此列的特征向量。现在，让我们创建特征列如下：

```scala
val featureCols = Array("balance", "duration", "history", "purpose", "amount", "savings", "employment", "instPercent", "sexMarried",
"guarantors", "residenceDuration", "assets", "age", "concCredit",
"apartment", "credits", "occupation", "dependents", "hasPhone",
"foreign") 

```

让我们使用`VectorAssembler()` API 组装这些选定列的所有特征：

```scala
val assembler = new VectorAssembler().setInputCols(featureCols).setOutputCol("features") 
val df2 = assembler.transform(creditDF) 

```

现在让我们看一下特征向量的样子：

```scala
df2.select("features").show

```

前一行显示了由 VectorAssembler 转换器创建的特征：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00360.gif)**图 10：**使用 VectorAssembler 为 ML 模型生成特征

现在，让我们使用`StringIndexer`从旧的响应列 creditability 创建一个新的标签列，如下所示：

```scala
val labelIndexer = new StringIndexer().setInputCol("creditability").setOutputCol("label") 
val df3 = labelIndexer.fit(df2).transform(df2) 
df3.select("label", "features").show

```

前一行显示了`VectorAssembler`转换器创建的特征和标签：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00274.gif)**图 11：** 使用 VectorAssembler 的 ML 模型的相应标签和特征

**步骤 5.** 准备训练集和测试集：

```scala
val splitSeed = 5043 
val Array(trainingData, testData) = df3.randomSplit(Array(0.80, 0.20), splitSeed) 

```

**步骤 6. 训练随机森林模型** - 首先，实例化模型：

```scala
val classifier = new RandomForestClassifier() 
      .setImpurity("gini") 
      .setMaxDepth(30) 
      .setNumTrees(30) 
      .setFeatureSubsetStrategy("auto") 
      .setSeed(1234567) 
      .setMaxBins(40) 
      .setMinInfoGain(0.001) 

```

有关上述参数的解释，请参阅本章中的随机森林算法部分。现在，让我们使用训练集训练模型：

```scala
val model = classifier.fit(trainingData)

```

**步骤 7.** 计算测试集的原始预测：

```scala
val predictions = model.transform(testData) 

```

让我们看看这个 DataFrame 的前 20 行：

```scala
predictions.select("label","rawPrediction", "probability", "prediction").show()

```

前一行显示了包含标签、原始预测、概率和实际预测的 DataFrame：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00040.gif)**图 12：** 包含测试集的原始和实际预测的 DataFrame

现在，在看到最后一列的预测之后，银行可以对申请做出决定，决定是否接受申请。

**步骤 8. 模型调优前的模型评估** - 实例化二元评估器：

```scala
val binaryClassificationEvaluator = new BinaryClassificationEvaluator() 
      .setLabelCol("label") 
      .setRawPredictionCol("rawPrediction") 

```

计算测试集的预测准确率如下：

```scala
val accuracy = binaryClassificationEvaluator.evaluate(predictions) 
println("The accuracy before pipeline fitting: " + accuracy) 

```

管道拟合前的准确率：`0.751921784149243`

这一次，准确率是 75%，并不是很好。让我们计算二元分类器的其他重要性能指标，比如**接收器操作特征下面积**（**AUROC**）和**精确度召回曲线下面积**（**AUPRC**）：

```scala
println("Area Under ROC before tuning: " + printlnMetric("areaUnderROC"))         
println("Area Under PRC before tuning: "+  printlnMetric("areaUnderPR")) 
Area Under ROC before tuning: 0.8453079178885631 Area Under PRC before tuning: 0.751921784149243

```

`printlnMetric()` 方法如下：

```scala
def printlnMetric(metricName: String): Double = { 
  val metrics = binaryClassificationEvaluator.setMetricName(metricName)
                                             .evaluate(predictions) 
  metrics 
} 

```

最后，让我们使用训练过程中使用的随机森林模型的`RegressionMetrics()` API 计算一些额外的性能指标：

```scala
val rm = new RegressionMetrics( 
predictions.select("prediction", "label").rdd.map(x => 
        (x(0).asInstanceOf[Double], x(1).asInstanceOf[Double]))) 

```

现在，让我们看看我们的模型如何：

```scala
println("MSE: " + rm.meanSquaredError) 
println("MAE: " + rm.meanAbsoluteError) 
println("RMSE Squared: " + rm.rootMeanSquaredError) 
println("R Squared: " + rm.r2) 
println("Explained Variance: " + rm.explainedVariance + "\n") 

```

我们得到以下输出：

```scala
MSE: 0.2578947368421053
MAE: 0.2578947368421053
RMSE Squared: 0.5078333750770082
R Squared: -0.13758553274682295
Explained Variance: 0.16083102493074794

```

不算太糟！但也不尽如人意，对吧？让我们使用网格搜索和交叉验证技术调优模型。

**步骤 9. 使用网格搜索和交叉验证进行模型调优** - 首先，让我们使用`ParamGridBuilder` API 构建一个参数网格，搜索 20 到 70 棵树，`maxBins`在 25 到 30 之间，`maxDepth`在 5 到 10 之间，以及熵和基尼作为不纯度：

```scala
val paramGrid = new ParamGridBuilder()
                    .addGrid(classifier.maxBins, Array(25, 30))
                    .addGrid(classifier.maxDepth, Array(5, 10))
                    .addGrid(classifier.numTrees, Array(20, 70))
                    .addGrid(classifier.impurity, Array("entropy", "gini"))
                    .build()

```

让我们使用训练集训练交叉验证模型：

```scala
val cv = new CrossValidator()
             .setEstimator(pipeline)
             .setEvaluator(binaryClassificationEvaluator)
             .setEstimatorParamMaps(paramGrid)
             .setNumFolds(10)
val pipelineFittedModel = cv.fit(trainingData)

```

按以下方式计算测试集的原始预测：

```scala
val predictions2 = pipelineFittedModel.transform(testData) 

```

**步骤 10. 调优后模型的评估** - 让我们看看准确率：

```scala
val accuracy2 = binaryClassificationEvaluator.evaluate(predictions2)
println("The accuracy after pipeline fitting: " + accuracy2)

```

我们得到以下输出：

```scala
The accuracy after pipeline fitting: 0.8313782991202348

```

现在，准确率超过 83%。确实有很大的改进！让我们看看计算 AUROC 和 AUPRC 的另外两个指标：

```scala
def printlnMetricAfter(metricName: String): Double = { 
val metrics = binaryClassificationEvaluator.setMetricName(metricName).evaluate(predictions2) 
metrics 
    } 
println("Area Under ROC after tuning: " + printlnMetricAfter("areaUnderROC"))     
println("Area Under PRC after tuning: "+  printlnMetricAfter("areaUnderPR"))

```

我们得到以下输出：

```scala
Area Under ROC after tuning: 0.8313782991202345
 Area Under PRC after tuning: 0.7460301367852662

```

现在基于`RegressionMetrics` API，计算其他指标：

```scala
val rm2 = new RegressionMetrics(predictions2.select("prediction", "label").rdd.map(x => (x(0).asInstanceOf[Double], x(1).asInstanceOf[Double]))) 
 println("MSE: " + rm2.meanSquaredError) 
println("MAE: " + rm2.meanAbsoluteError) 
println("RMSE Squared: " + rm2.rootMeanSquaredError) 
println("R Squared: " + rm2.r2) 
println("Explained Variance: " + rm2.explainedVariance + "\n")  

```

我们得到以下输出：

```scala
MSE: 0.268421052631579
 MAE: 0.26842105263157895
 RMSE Squared: 0.5180936716768301
 R Squared: -0.18401759530791795
 Explained Variance: 0.16404432132963992

```

**步骤 11. 寻找最佳的交叉验证模型** - 最后，让我们找到最佳的交叉验证模型信息：

```scala
pipelineFittedModel 
      .bestModel.asInstanceOf[org.apache.spark.ml.PipelineModel] 
      .stages(0) 
      .extractParamMap 
println("The best fitted model:" + pipelineFittedModel.bestModel.asInstanceOf[org.apache.spark.ml.PipelineModel].stages(0)) 

```

我们得到以下输出：

```scala
The best fitted model:RandomForestClassificationModel (uid=rfc_1fcac012b37c) with 70 trees

```

# 使用 Spark 的推荐系统

推荐系统试图根据其他用户的历史来预测用户可能感兴趣的潜在项目。基于模型的协同过滤在许多公司中被广泛使用，如 Netflix。需要注意的是，Netflix 是一家美国娱乐公司，由里德·黑斯廷斯和马克·兰道夫于 1997 年 8 月 29 日在加利福尼亚州斯科茨谷成立。它专门提供流媒体和在线点播以及 DVD 邮寄服务。2013 年，Netflix 扩展到了电影和电视制作，以及在线发行。截至 2017 年，该公司总部位于加利福尼亚州洛斯加托斯（来源：维基百科）。Netflix 是一个实时电影推荐系统。在本节中，我们将看到一个完整的示例，说明它是如何为新用户推荐电影的。

# 使用 Spark 进行基于模型的推荐

Spark MLlib 中的实现支持基于模型的协同过滤。在基于模型的协同过滤技术中，用户和产品由一小组因子描述，也称为**潜在因子**（**LFs**）。从下图中，您可以对不同的推荐系统有一些了解。*图 13* 说明了为什么我们将在电影推荐示例中使用基于模型的协同过滤：

图 13：不同推荐系统的比较视图

然后使用 LFs 来预测缺失的条目。Spark API 提供了交替最小二乘（也称为 ALS 广泛）算法的实现，该算法通过考虑六个参数来学习这些潜在因素，包括：

+   *numBlocks*：这是用于并行计算的块数（设置为-1 以自动配置）。

+   *rank*：这是模型中潜在因素的数量。

+   *iterations*：这是运行 ALS 的迭代次数。ALS 通常在 20 次迭代或更少的情况下收敛到一个合理的解决方案。

+   *lambda*：这指定 ALS 中的正则化参数。

+   *implicitPrefs*：这指定是否使用*显式反馈*ALS 变体或适用于*隐式反馈*数据的变体。

+   *alpha*：这是适用于 ALS 隐式反馈变体的参数，它控制对偏好观察的*基线*置信度。

请注意，要使用默认参数构建 ALS 实例，您可以根据自己的需求设置值。默认值如下：`numBlocks: -1`，`rank: 10`，`iterations: 10`，`lambda: 0.01`，`implicitPrefs: false`，和`alpha: 1.0`。

# 数据探索

电影和相应的评分数据集是从 MovieLens 网站（[`movielens.org`](https://movielens.org)）下载的。根据 MovieLens 网站上的数据描述，所有评分都在`ratings.csv`文件中描述。该文件的每一行在标题之后表示一个用户对一部电影的评分。

CSV 数据集有以下列：**userId**，**movieId**，**rating**和**timestamp**，如*图 14*所示。行首先按**userId**排序，然后按**movieId**排序。评分是在五星级评分上进行的，可以增加半星（0.5 星至 5.0 星）。时间戳表示自 1970 年 1 月 1 日协调世界时（UTC）午夜以来的秒数，我们有来自 668 个用户对 10325 部电影的 105339 个评分：

图 14：评分数据集的快照

另一方面，电影信息包含在`movies.csv`文件中。除了标题信息之外，每一行代表一个包含列：movieId，title 和 genres 的电影（见*图 14*）。电影标题可以手动创建或插入，也可以从电影数据库网站[`www.themoviedb.org/`](https://www.themoviedb.org/)导入。然而，发行年份显示在括号中。由于电影标题是手动插入的，因此这些标题可能存在一些错误或不一致。因此，建议读者检查 IMDb 数据库（[`www.ibdb.com/`](https://www.ibdb.com/)）以确保没有不一致或不正确的标题与其对应的发行年份。

类型是一个分开的列表，可以从以下类型类别中选择：

+   动作，冒险，动画，儿童，喜剧，犯罪

+   纪录片，戏剧，奇幻，黑色电影，恐怖，音乐

+   神秘，浪漫，科幻，惊悚，西部，战争

图 15：前 20 部电影的标题和类型

# 使用 ALS 进行电影推荐

在本小节中，我们将通过从数据收集到电影推荐的逐步示例向您展示如何为其他用户推荐电影。

**步骤 1. 加载、解析和探索电影和评分数据集** - 以下是示例代码：

```scala
val ratigsFile = "data/ratings.csv"
val df1 = spark.read.format("com.databricks.spark.csv").option("header", true).load(ratigsFile)
val ratingsDF = df1.select(df1.col("userId"), df1.col("movieId"), df1.col("rating"), df1.col("timestamp"))
ratingsDF.show(false)

```

这段代码应该返回您的评分数据框。另一方面，以下代码段显示了电影的数据框：

```scala
val moviesFile = "data/movies.csv"
val df2 = spark.read.format("com.databricks.spark.csv").option("header", "true").load(moviesFile)
val moviesDF = df2.select(df2.col("movieId"), df2.col("title"), df2.col("genres"))

```

**步骤 2. 注册两个数据框为临时表，以便更轻松地查询** - 要注册两个数据集，我们可以使用以下代码：

```scala
ratingsDF.createOrReplaceTempView("ratings")
moviesDF.createOrReplaceTempView("movies")

```

这将通过在内存中创建一个临时视图作为表来加快内存中的查询速度。使用`createOrReplaceTempView()`方法创建的临时表的生命周期与用于创建此 DataFrame 的`[[SparkSession]]`相关联。

**步骤 3. 探索和查询相关统计数据** - 让我们检查与评分相关的统计数据。只需使用以下代码行：

```scala
val numRatings = ratingsDF.count()
val numUsers = ratingsDF.select(ratingsDF.col("userId")).distinct().count()
val numMovies = ratingsDF.select(ratingsDF.col("movieId")).distinct().count()
println("Got " + numRatings + " ratings from " + numUsers + " users on " + numMovies + " movies.")

```

你应该找到来自 668 个用户对 10325 部电影进行了 105339 次评分。现在，让我们获取最大和最小评分，以及对电影进行评分的用户数量。然而，你需要在我们在上一步中在内存中创建的评分表上执行 SQL 查询。在这里进行查询很简单，类似于从 MySQL 数据库或 RDBMS 进行查询。然而，如果你不熟悉基于 SQL 的查询，建议查看 SQL 查询规范，了解如何使用`SELECT`从特定表中进行选择，如何使用`ORDER`进行排序，以及如何使用`JOIN`关键字进行连接操作。

嗯，如果你知道 SQL 查询，你应该通过使用以下复杂的 SQL 查询来获得一个新的数据集：

```scala
// Get the max, min ratings along with the count of users who have rated a movie.
val results = spark.sql("select movies.title, movierates.maxr, movierates.minr, movierates.cntu "
       + "from(SELECT ratings.movieId,max(ratings.rating) as maxr,"
       + "min(ratings.rating) as minr,count(distinct userId) as cntu "
       + "FROM ratings group by ratings.movieId) movierates "
       + "join movies on movierates.movieId=movies.movieId "
       + "order by movierates.cntu desc") 
results.show(false) 

```

我们得到以下输出：

图 16：最大、最小评分以及对电影进行评分的用户数量

为了更深入地了解，我们需要了解更多关于用户和他们的评分。现在，让我们找出最活跃的用户以及他们对电影进行评分的次数：

```scala
// Show the top 10 mostactive users and how many times they rated a movie
val mostActiveUsersSchemaRDD = spark.sql("SELECT ratings.userId, count(*) as ct from ratings "
               + "group by ratings.userId order by ct desc limit 10")
mostActiveUsersSchemaRDD.show(false)

```

图 17：前 10 名最活跃用户以及他们对电影进行评分的次数

让我们看看一个特定的用户，并找出，比如说用户 668，对哪些电影进行了高于 4 的评分：

```scala
// Find the movies that user 668 rated higher than 4
val results2 = spark.sql(
"SELECT ratings.userId, ratings.movieId,"
         + "ratings.rating, movies.title FROM ratings JOIN movies"
         + "ON movies.movieId=ratings.movieId"
         + "where ratings.userId=668 and ratings.rating > 4")
results2.show(false)

```

图 18：用户 668 对评分高于 4 的电影

**步骤 4. 准备训练和测试评分数据并查看计数** - 以下代码将评分 RDD 分割为训练数据 RDD（75%）和测试数据 RDD（25%）。这里的种子是可选的，但是出于可重现性的目的是必需的：

```scala
// Split ratings RDD into training RDD (75%) & test RDD (25%)
val splits = ratingsDF.randomSplit(Array(0.75, 0.25), seed = 12345L)
val (trainingData, testData) = (splits(0), splits(1))
val numTraining = trainingData.count()
val numTest = testData.count()
println("Training: " + numTraining + " test: " + numTest)

```

你应该发现训练中有 78792 个评分，测试中有 26547 个评分

DataFrame。

**步骤 5. 准备数据以构建使用 ALS 的推荐模型** - ALS 算法使用训练目的的`Rating`的 RDD。以下代码说明了使用 API 构建推荐模型的过程：

```scala
val ratingsRDD = trainingData.rdd.map(row => {
  val userId = row.getString(0)
  val movieId = row.getString(1)
  val ratings = row.getString(2)
  Rating(userId.toInt, movieId.toInt, ratings.toDouble)
})

```

`ratingsRDD`是一个包含来自我们在上一步准备的训练数据集的`userId`、`movieId`和相应评分的评分的 RDD。另一方面，还需要一个测试 RDD 来评估模型。以下`testRDD`也包含了来自我们在上一步准备的测试 DataFrame 的相同信息：

```scala
val testRDD = testData.rdd.map(row => {
  val userId = row.getString(0)
  val movieId = row.getString(1)
  val ratings = row.getString(2)
  Rating(userId.toInt, movieId.toInt, ratings.toDouble)
}) 

```

**步骤 6. 构建 ALS 用户产品矩阵** - 基于`ratingsRDD`构建 ALS 用户矩阵模型，指定最大迭代次数、块数、alpha、rank、lambda、种子和`implicitPrefs`。基本上，这种技术根据其他用户对其他电影的评分来预测特定用户对特定电影的缺失评分。

```scala
val rank = 20
val numIterations = 15
val lambda = 0.10
val alpha = 1.00
val block = -1
val seed = 12345L
val implicitPrefs = false
val model = new ALS()
           .setIterations(numIterations)
           .setBlocks(block)
           .setAlpha(alpha)
           .setLambda(lambda)
           .setRank(rank)
           .setSeed(seed)
           .setImplicitPrefs(implicitPrefs)
           .run(ratingsRDD) 

```

最后，我们对模型进行了 15 次学习迭代。通过这个设置，我们得到了良好的预测准确性。建议读者对超参数进行调整，以了解这些参数的最佳值。此外，设置用户块和产品块的块数以将计算并行化为一次传递-1 以进行自动配置的块数。该值为-1。

**步骤 7. 进行预测** - 让我们为用户 668 获取前六部电影的预测。以下源代码可用于进行预测：

```scala
// Making Predictions. Get the top 6 movie predictions for user 668
println("Rating:(UserID, MovieID, Rating)")
println("----------------------------------")
val topRecsForUser = model.recommendProducts(668, 6)
for (rating <- topRecsForUser) {
  println(rating.toString())
}
println("----------------------------------")

```

前面的代码段产生了包含`UserID`、`MovieID`和相应`Rating`的评分预测的输出：

图 19：用户 668 的前六部电影预测

**第 8 步。评估模型** - 为了验证模型的质量，使用**均方根误差**（**RMSE**）来衡量模型预测值与实际观察值之间的差异。默认情况下，计算出的误差越小，模型越好。为了测试模型的质量，使用测试数据（在第 4 步中拆分）进行测试。根据许多机器学习从业者的说法，RMSE 是衡量准确性的一个很好的指标，但只能用于比较特定变量的不同模型的预测误差，而不能用于变量之间的比较，因为它依赖于比例。以下代码行计算了使用训练集训练的模型的 RMSE 值。

```scala
var rmseTest = computeRmse(model, testRDD, true)
println("Test RMSE: = " + rmseTest) //Less is better 

```

需要注意的是`computeRmse()`是一个 UDF，其步骤如下：

```scala
  def computeRmse(model: MatrixFactorizationModel, data: RDD[Rating], implicitPrefs: Boolean): Double = {
    val predictions: RDD[Rating] = model.predict(data.map(x => (x.user, x.product)))
    val predictionsAndRatings = predictions.map { x => ((x.user, x.product), x.rating)
  }.join(data.map(x => ((x.user, x.product), x.rating))).values
  if (implicitPrefs) {
    println("(Prediction, Rating)")
    println(predictionsAndRatings.take(5).mkString("\n"))
  }
  math.sqrt(predictionsAndRatings.map(x => (x._1 - x._2) * (x._1 - x._2)).mean())
}

```

前面的方法计算了 RMSE 以评估模型。RMSE 越小，模型及其预测能力就越好。

对于先前的设置，我们得到了以下输出：

```scala
Test RMSE: = 0.9019872589764073

```

我们相信前面模型的性能可以进一步提高。感兴趣的读者应该参考此网址，了解有关调整基于 ML 的 ALS 模型的更多信息[`spark.apache.org/docs/preview/ml-collaborative-filtering.html`](https://spark.apache.org/docs/preview/ml-collaborative-filtering.html)。

主题建模技术广泛用于从大量文档中挖掘文本的任务。然后可以使用这些主题来总结和组织包括主题术语及其相对权重的文档。在下一节中，我们将展示使用**潜在狄利克雷分配**（**LDA**）算法进行主题建模的示例。

# 主题建模-文本聚类的最佳实践

主题建模技术广泛用于从大量文档中挖掘文本的任务。然后可以使用这些主题来总结和组织包括主题术语及其相对权重的文档。将用于此示例的数据集只是以纯文本的形式存在，但是以非结构化格式存在。现在具有挑战性的部分是使用称为主题建模的 LDA 找到有关数据的有用模式。

# LDA 是如何工作的？

LDA 是一种主题模型，它从一系列文本文档中推断主题。LDA 可以被视为一种聚类算法，其中主题对应于簇中心，文档对应于数据集中的示例（行）。主题和文档都存在于特征空间中，其中特征向量是词频的向量（词袋）。LDA 不是使用传统距离来估计聚类，而是使用基于文本文档生成的统计模型的函数。

LDA 通过`setOptimizer`函数支持不同的推断算法。`EMLDAOptimizer`使用期望最大化来学习聚类，并产生全面的结果，而`OnlineLDAOptimizer`使用迭代小批量抽样进行在线变分推断，并且通常对内存友好。LDA 接受一系列文档作为词频向量以及以下参数（使用构建器模式设置）：

+   `k`：主题数（即，簇中心）。

+   `optimizer`：用于学习 LDA 模型的优化器，可以是`EMLDAOptimizer`或`OnlineLDAOptimizer`。

+   `docConcentration`：文档分布在主题上的 Dirichlet 先验参数。较大的值鼓励更平滑的推断分布。

+   `topicConcentration`：主题分布在术语（词）上的 Dirichlet 先验参数。较大的值鼓励更平滑的推断分布。

+   `maxIterations`：迭代次数上限。

+   `checkpointInterval`：如果使用检查点（在 Spark 配置中设置），此参数指定将创建检查点的频率。如果`maxIterations`很大，使用检查点可以帮助减少磁盘上的洗牌文件大小，并有助于故障恢复。

特别是，我们想讨论人们在大量文本中谈论的主题。自 Spark 1.3 发布以来，MLlib 支持 LDA，这是文本挖掘和**自然语言处理**（**NLP**）领域中最成功使用的主题建模技术之一。此外，LDA 也是第一个采用 Spark GraphX 的 MLlib 算法。

要了解 LDA 背后的理论如何工作的更多信息，请参考 David M. Blei，Andrew Y. Ng 和 Michael I. Jordan，Latent，Dirichlet Allocation，*Journal of Machine Learning Research 3*（2003）993-1022。

以下图显示了从随机生成的推文文本中的主题分布：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00165.jpeg)

**图 20**：主题分布及其外观

在本节中，我们将看一个使用 Spark MLlib 的 LDA 算法对非结构化原始推文数据集进行主题建模的示例。请注意，这里我们使用了 LDA，这是最常用于文本挖掘的主题建模算法之一。我们可以使用更健壮的主题建模算法，如**概率潜在情感分析**（**pLSA**）、**赌博分配模型**（**PAM**）或**分层狄利克雷过程**（**HDP**）算法。

然而，pLSA 存在过拟合问题。另一方面，HDP 和 PAM 是更复杂的主题建模算法，用于复杂的文本挖掘，如从高维文本数据或非结构化文档中挖掘主题。此外，迄今为止，Spark 只实现了一个主题建模算法，即 LDA。因此，我们必须合理使用 LDA。

# 使用 Spark MLlib 进行主题建模

在这个小节中，我们使用 Spark 表示了一种半自动的主题建模技术。使用其他选项作为默认值，我们在从 GitHub URL 下载的数据集上训练 LDA，网址为[`github.com/minghui/Twitter-LDA/tree/master/data/Data4Model/test`](https://github.com/minghui/Twitter-LDA/tree/master/data/Data4Model/test)。以下步骤展示了从数据读取到打印主题及其词权重的主题建模过程。以下是主题建模流程的简要工作流程：

```scala
object topicModellingwithLDA {
  def main(args: Array[String]): Unit = {
    val lda = new LDAforTM() // actual computations are done here
    val defaultParams = Params().copy(input = "data/docs/") 
    // Loading the parameters
    lda.run(defaultParams) // Training the LDA model with the default
                              parameters.
  }
} 

```

主题建模的实际计算是在`LDAforTM`类中完成的。`Params`是一个案例类，用于加载参数以训练 LDA 模型。最后，我们使用`Params`类设置的参数来训练 LDA 模型。现在，我们将逐步解释每个步骤的源代码：

**步骤 1\. 创建一个 Spark 会话** - 让我们通过定义计算核心数量、SQL 仓库和应用程序名称来创建一个 Spark 会话，如下所示：

```scala
val spark = SparkSession
    .builder
    .master("local[*]")
    .config("spark.sql.warehouse.dir", "E:/Exp/")
    .appName("LDA for topic modelling")
    .getOrCreate() 

```

**步骤 2\. 创建词汇表，标记计数以在文本预处理后训练 LDA** - 首先，加载文档，并准备好 LDA，如下所示：

```scala
// Load documents, and prepare them for LDA.

val preprocessStart = System.nanoTime()
val (corpus, vocabArray, actualNumTokens) = preprocess(params.input, params.vocabSize, params.stopwordFile)  

```

预处理方法用于处理原始文本。首先，让我们使用`wholeTextFiles()`方法读取整个文本，如下所示：

```scala
val initialrdd = spark.sparkContext.wholeTextFiles(paths).map(_._2)
initialrdd.cache()  

```

在上述代码中，paths 是文本文件的路径。然后，我们需要根据词形文本准备一个形态学 RDD，如下所示：

```scala
val rdd = initialrdd.mapPartitions { partition =>
  val morphology = new Morphology()
  partition.map { value => helperForLDA.getLemmaText(value, morphology) }
}.map(helperForLDA.filterSpecialCharacters)

```

在这里，`helperForLDA`类中的`getLemmaText()`方法在使用`filterSpaecialChatacters()`方法过滤特殊字符（例如`("""[! @ # $ % ^ & * ( ) _ + - − , " ' ; : . ` ? --]`）后提供了词形文本。

需要注意的是，`Morphology()`类计算英语单词的基本形式，只删除屈折（不是派生形态）。也就是说，它只处理名词复数、代词格和动词词尾，而不处理比较级形容词或派生名词等。这来自于斯坦福 NLP 组。要使用这个，你应该在主类文件中包含以下导入：`edu.stanford.nlp.process.Morphology`。在`pom.xml`文件中，你将需要包含以下条目作为依赖项：

```scala
<dependency>
    <groupId>edu.stanford.nlp</groupId>
    <artifactId>stanford-corenlp</artifactId>
    <version>3.6.0</version>
</dependency>
<dependency>
    <groupId>edu.stanford.nlp</groupId>
    <artifactId>stanford-corenlp</artifactId>
    <version>3.6.0</version>
    <classifier>models</classifier>
</dependency>

```

方法如下：

```scala
def getLemmaText(document: String, morphology: Morphology) = {
  val string = new StringBuilder()
  val value = new Document(document).sentences().toList.flatMap { a =>
  val words = a.words().toList
  val tags = a.posTags().toList
  (words zip tags).toMap.map { a =>
    val newWord = morphology.lemma(a._1, a._2)
    val addedWoed = if (newWord.length > 3) {
      newWord
    } else { "" }
      string.append(addedWoed + " ")
    }
  }
  string.toString()
} 

```

`filterSpecialCharacters()`如下所示：

`def filterSpecialCharacters(document: String) = document.replaceAll("""[! @ # $ % ^ & * ( ) _ + - − , " ' ; : . ` ? --]""", " ")`。一旦我们手头有去除特殊字符的 RDD，我们就可以创建一个用于构建文本分析管道的 DataFrame：

```scala
rdd.cache()
initialrdd.unpersist()
val df = rdd.toDF("docs")
df.show() 

```

因此，DataFrame 仅包含文档标签。DataFrame 的快照如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00332.gif)**图 21**：原始文本

现在，如果您仔细检查前面的 DataFrame，您会发现我们仍然需要对项目进行标记。此外，在这样的 DataFrame 中还有停用词，因此我们也需要将它们删除。首先，让我们使用`RegexTokenizer` API 对它们进行标记如下：

```scala
val tokenizer = new RegexTokenizer().setInputCol("docs").setOutputCol("rawTokens") 

```

现在，让我们按如下方式删除所有停用词：

```scala
val stopWordsRemover = new StopWordsRemover().setInputCol("rawTokens").setOutputCol("tokens")
stopWordsRemover.setStopWords(stopWordsRemover.getStopWords ++ customizedStopWords)

```

此外，我们还需要应用计数胜利以仅从标记中找到重要特征。这将有助于使管道在管道阶段链接。让我们按如下方式做：

```scala
val countVectorizer = new CountVectorizer().setVocabSize(vocabSize).setInputCol("tokens").setOutputCol("features") 

```

现在，通过链接转换器（`tokenizer`、`stopWordsRemover`和`countVectorizer`）创建管道如下：

```scala
val pipeline = new Pipeline().setStages(Array(tokenizer, stopWordsRemover, countVectorizer))

```

让我们拟合和转换管道以适应词汇和标记数：

```scala
val model = pipeline.fit(df)
val documents = model.transform(df).select("features").rdd.map {
  case Row(features: MLVector) =>Vectors.fromML(features)
}.zipWithIndex().map(_.swap)

```

最后，返回词汇和标记计数对如下：

```scala
(documents, model.stages(2).asInstanceOf[CountVectorizerModel].vocabulary, documents.map(_._2.numActives).sum().toLong)

```

现在，让我们看看训练数据的统计信息：

```scala
println()
println("Training corpus summary:")
println("-------------------------------")
println("Training set size: " + actualCorpusSize + " documents")
println("Vocabulary size: " + actualVocabSize + " terms")
println("Number of tockens: " + actualNumTokens + " tokens")
println("Preprocessing time: " + preprocessElapsed + " sec")
println("-------------------------------")
println()

```

我们得到以下输出：

```scala
Training corpus summary:
 -------------------------------
 Training set size: 18 documents
 Vocabulary size: 21607 terms
 Number of tockens: 75758 tokens
 Preprocessing time: 39.768580981 sec
 **-------------------------------**

```

**步骤 4. 在训练之前实例化 LDA 模型**

```scala
val lda = new LDA()

```

步骤 5：设置 NLP 优化器

为了从 LDA 模型获得更好和优化的结果，我们需要为 LDA 模型设置优化器。这里我们使用`EMLDAOPtimizer`优化器。您还可以使用`OnlineLDAOptimizer()`优化器。但是，您需要将(1.0/actualCorpusSize)添加到`MiniBatchFraction`中，以使其在小型数据集上更加稳健。整个操作如下。首先，实例化`EMLDAOptimizer`如下：

```scala
val optimizer = params.algorithm.toLowerCase match {
  case "em" => new EMLDAOptimizer
  case "online" => new OnlineLDAOptimizer().setMiniBatchFraction(0.05 + 1.0 / actualCorpusSize)
  case _ => throw new IllegalArgumentException("Only em is supported, got ${params.algorithm}.")
}

```

现在使用 LDA API 的`setOptimizer()`方法设置优化器如下：

```scala
lda.setOptimizer(optimizer)
  .setK(params.k)
  .setMaxIterations(params.maxIterations)
  .setDocConcentration(params.docConcentration)
  .setTopicConcentration(params.topicConcentration)
  .setCheckpointInterval(params.checkpointInterval)

```

`Params` case 类用于定义训练 LDA 模型的参数。具体如下：

```scala
 //Setting the parameters before training the LDA model
case class Params(input: String = "",
                  k: Int = 5,
                  maxIterations: Int = 20,
                  docConcentration: Double = -1,
                  topicConcentration: Double = -1,
                  vocabSize: Int = 2900000,
                  stopwordFile: String = "data/stopWords.txt",
                  algorithm: String = "em",
                  checkpointDir: Option[String] = None,
                  checkpointInterval: Int = 10)

```

为了获得更好的结果，您可以以一种天真的方式设置这些参数。或者，您应该进行交叉验证以获得更好的性能。现在，如果您想要对当前参数进行检查点，请使用以下代码行：

```scala
if (params.checkpointDir.nonEmpty) {
  spark.sparkContext.setCheckpointDir(params.checkpointDir.get)
}

```

**步骤 6.** 训练 LDA 模型：

```scala
val startTime = System.nanoTime()
//Start training the LDA model using the training corpus 
val ldaModel = lda.run(corpus)
val elapsed = (System.nanoTime() - startTime) / 1e9
println(s"Finished training LDA model.  Summary:") 
println(s"t Training time: $elapsed sec")

```

对于我们拥有的文本，LDA 模型花费了 6.309715286 秒进行训练。请注意，这些时间代码是可选的。我们提供它们仅供参考，只是为了了解训练时间。

**步骤 7.** 测量数据的可能性 - 现在，为了获得有关数据的更多统计信息，如最大似然或对数似然，我们可以使用以下代码：

```scala
if (ldaModel.isInstanceOf[DistributedLDAModel]) {
  val distLDAModel = ldaModel.asInstanceOf[DistributedLDAModel]
  val avgLogLikelihood = distLDAModel.logLikelihood / actualCorpusSize.toDouble
  println("The average log likelihood of the training data: " +  avgLogLikelihood)
  println()
}

```

前面的代码计算了平均对数似然性，如果 LDA 模型是分布式版本的 LDA 模型的实例。我们得到以下输出：

```scala
The average log-likelihood of the training data: -208599.21351837728  

```

似然性在数据可用后用于描述给定结果的参数（或参数向量）的函数。这对于从一组统计数据中估计参数特别有帮助。有关似然性测量的更多信息，感兴趣的读者应参考[`en.wikipedia.org/wiki/Likelihood_function`](https://en.wikipedia.org/wiki/Likelihood_function)。

**步骤 8. 准备感兴趣的主题** - 准备前五个主题，每个主题有 10 个术语。包括术语及其相应的权重。

```scala
val topicIndices = ldaModel.describeTopics(maxTermsPerTopic = 10)
println(topicIndices.length)
val topics = topicIndices.map {case (terms, termWeights) => terms.zip(termWeights).map { case (term, weight) => (vocabArray(term.toInt), weight) } }

```

**步骤 9. 主题建模** - 打印前十个主题，显示每个主题的权重最高的术语。还包括每个主题的总权重如下：

```scala
var sum = 0.0
println(s"${params.k} topics:")
topics.zipWithIndex.foreach {
  case (topic, i) =>
  println(s"TOPIC $i")
  println("------------------------------")
  topic.foreach {
    case (term, weight) =>
    println(s"$termt$weight")
    sum = sum + weight
  }
  println("----------------------------")
  println("weight: " + sum)
  println()

```

现在，让我们看看我们的 LDA 模型对主题建模的输出：

```scala
    5 topics:
    TOPIC 0
    ------------------------------
    think 0.0105511077762379
    look  0.010393384083882656
    know  0.010121680765600402
    come  0.009999416569525854
    little      0.009880422850906338
    make  0.008982740529851225
    take  0.007061048216197747
    good  0.007040301924830752
    much  0.006273732732002744
    well  0.0062484438391950895
    ----------------------------
    weight: 0.0865522792882307

    TOPIC 1
    ------------------------------
    look  0.008658099588372216
    come  0.007972622171954474
    little      0.007596460821298818
    hand  0.0065409990798624565
    know  0.006314616294309573
    lorry 0.005843633203040061
    upon  0.005545300032552888
    make  0.005391780686824741
    take  0.00537353581562707
    time  0.005030870790464942
    ----------------------------
    weight: 0.15082019777253794

    TOPIC 2
    ------------------------------
    captain     0.006865463831587792
    nautilus    0.005175561004431676
    make  0.004910586984657019
    hepzibah    0.004378298053191463
    water 0.004063096964497903
    take  0.003959626037381751
    nemo  0.0037687537789531005
    phoebe      0.0037683642100062313
    pyncheon    0.003678496229955977
    seem  0.0034594205003318193
    ----------------------------
    weight: 0.19484786536753268

    TOPIC 3
    ------------------------------
    fogg  0.009552022075897986
    rodney      0.008705705501603078
    make  0.007016635545801613
    take  0.00676049232003675
    passepartout      0.006295907851484774
    leave 0.005565220660514245
    find  0.005077555215275536
    time  0.004852923943330551
    luke  0.004729546554304362
    upon  0.004707181805179265
    ----------------------------
    weight: 0.2581110568409608

    TOPIC 4
    ------------------------------
    dick  0.013754147765988699
    thus  0.006231933402776328
    ring  0.0052746290878481926
    bear  0.005181637978658836
    fate  0.004739983892853129
    shall 0.0046221874997173906
    hand  0.004610810387565958
    stand 0.004121100025638923
    name  0.0036093879729237
    trojan      0.0033792362039766505
    ----------------------------
    weight: 0.31363611105890865

```

从前面的输出中，我们可以看到输入文档的主题是主题 5，其权重最高为`0.31363611105890865`。该主题讨论了爱、长、海岸、淋浴、戒指、带来、承担等术语。现在，为了更好地理解流程，这是完整的源代码：

```scala
package com.chapter11.SparkMachineLearning

import edu.stanford.nlp.process.Morphology
import edu.stanford.nlp.simple.Document
import org.apache.log4j.{ Level, Logger }
import scala.collection.JavaConversions._
import org.apache.spark.{ SparkConf, SparkContext }
import org.apache.spark.ml.Pipeline
import org.apache.spark.ml.feature._
import org.apache.spark.ml.linalg.{ Vector => MLVector }
import org.apache.spark.mllib.clustering.{ DistributedLDAModel, EMLDAOptimizer, LDA, OnlineLDAOptimizer }
import org.apache.spark.mllib.linalg.{ Vector, Vectors }
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.{ Row, SparkSession }

object topicModellingwithLDA {
  def main(args: Array[String]): Unit = {
    val lda = new LDAforTM() // actual computations are done here
    val defaultParams = Params().copy(input = "data/docs/") 
    // Loading the parameters to train the LDA model
    lda.run(defaultParams) // Training the LDA model with the default
                              parameters.
  }
}
//Setting the parameters before training the LDA model
caseclass Params(input: String = "",
                 k: Int = 5,
                 maxIterations: Int = 20,
                 docConcentration: Double = -1,
                 topicConcentration: Double = -1,
                 vocabSize: Int = 2900000,
                 stopwordFile: String = "data/docs/stopWords.txt",
                 algorithm: String = "em",
                 checkpointDir: Option[String] = None,
                 checkpointInterval: Int = 10)

// actual computations for topic modeling are done here
class LDAforTM() {
  val spark = SparkSession
              .builder
              .master("local[*]")
              .config("spark.sql.warehouse.dir", "E:/Exp/")
              .appName("LDA for topic modelling")
              .getOrCreate()

  def run(params: Params): Unit = {
    Logger.getRootLogger.setLevel(Level.WARN)
    // Load documents, and prepare them for LDA.
    val preprocessStart = System.nanoTime()
    val (corpus, vocabArray, actualNumTokens) = preprocess(params
                      .input, params.vocabSize, params.stopwordFile)
    val actualCorpusSize = corpus.count()
    val actualVocabSize = vocabArray.length
    val preprocessElapsed = (System.nanoTime() - preprocessStart) / 1e9
    corpus.cache() //will be reused later steps
    println()
    println("Training corpus summary:")
    println("-------------------------------")
    println("Training set size: " + actualCorpusSize + " documents")
    println("Vocabulary size: " + actualVocabSize + " terms")
    println("Number of tockens: " + actualNumTokens + " tokens")
    println("Preprocessing time: " + preprocessElapsed + " sec")
    println("-------------------------------")
    println()
    // Instantiate an LDA model
    val lda = new LDA()
    val optimizer = params.algorithm.toLowerCase match {
      case "em" => new EMLDAOptimizer
      // add (1.0 / actualCorpusSize) to MiniBatchFraction be more
         robust on tiny datasets.
     case "online" => new OnlineLDAOptimizer()
                  .setMiniBatchFraction(0.05 + 1.0 / actualCorpusSize)
      case _ => thrownew IllegalArgumentException("Only em, online are
                             supported but got ${params.algorithm}.")
    }
    lda.setOptimizer(optimizer)
      .setK(params.k)
      .setMaxIterations(params.maxIterations)
      .setDocConcentration(params.docConcentration)
      .setTopicConcentration(params.topicConcentration)
      .setCheckpointInterval(params.checkpointInterval)
    if (params.checkpointDir.nonEmpty) {
      spark.sparkContext.setCheckpointDir(params.checkpointDir.get)
    }
    val startTime = System.nanoTime()
    //Start training the LDA model using the training corpus
    val ldaModel = lda.run(corpus)
    val elapsed = (System.nanoTime() - startTime) / 1e9
    println("Finished training LDA model. Summary:")
    println("Training time: " + elapsed + " sec")
    if (ldaModel.isInstanceOf[DistributedLDAModel]) {
      val distLDAModel = ldaModel.asInstanceOf[DistributedLDAModel]
      val avgLogLikelihood = distLDAModel.logLikelihood /
                             actualCorpusSize.toDouble
      println("The average log likelihood of the training data: " +
              avgLogLikelihood)
      println()
    }
    // Print the topics, showing the top-weighted terms for each topic.
    val topicIndices = ldaModel.describeTopics(maxTermsPerTopic = 10)
    println(topicIndices.length)
    val topics = topicIndices.map {case (terms, termWeights) =>
                 terms.zip(termWeights).map { case (term, weight) =>
                 (vocabArray(term.toInt), weight) } }
    var sum = 0.0
    println(s"${params.k} topics:")
    topics.zipWithIndex.foreach {
      case (topic, i) =>
      println(s"TOPIC $i")
      println("------------------------------")
      topic.foreach {
        case (term, weight) =>
        term.replaceAll("\\s", "")
        println(s"$term\t$weight")
        sum = sum + weight
      }
      println("----------------------------")
      println("weight: " + sum)
      println()
    }
    spark.stop()
  }
  //Pre-processing of the raw texts
import org.apache.spark.sql.functions._
def preprocess(paths: String, vocabSize: Int, stopwordFile: String): (RDD[(Long, Vector)], Array[String], Long) = {
  import spark.implicits._
  //Reading the Whole Text Files
  val initialrdd = spark.sparkContext.wholeTextFiles(paths).map(_._2)
  initialrdd.cache()
  val rdd = initialrdd.mapPartitions { partition =>
    val morphology = new Morphology()
    partition.map {value => helperForLDA.getLemmaText(value,
                                                      morphology)}
  }.map(helperForLDA.filterSpecialCharacters)
    rdd.cache()
    initialrdd.unpersist()
    val df = rdd.toDF("docs")
    df.show()
    //Customizing the stop words
    val customizedStopWords: Array[String] = if(stopwordFile.isEmpty) {
      Array.empty[String]
    } else {
      val stopWordText = spark.sparkContext.textFile(stopwordFile)
                            .collect()
      stopWordText.flatMap(_.stripMargin.split(","))
    }
    //Tokenizing using the RegexTokenizer
    val tokenizer = new RegexTokenizer().setInputCol("docs")
                                       .setOutputCol("rawTokens")
    //Removing the Stop-words using the Stop Words remover
    val stopWordsRemover = new StopWordsRemover()
                       .setInputCol("rawTokens").setOutputCol("tokens")
    stopWordsRemover.setStopWords(stopWordsRemover.getStopWords ++
                                  customizedStopWords)
    //Converting the Tokens into the CountVector
    val countVectorizer = new CountVectorizer().setVocabSize(vocabSize)
                        .setInputCol("tokens").setOutputCol("features")
    val pipeline = new Pipeline().setStages(Array(tokenizer,
                                    stopWordsRemover, countVectorizer))
    val model = pipeline.fit(df)
    val documents = model.transform(df).select("features").rdd.map {
      case Row(features: MLVector) => Vectors.fromML(features)
    }.zipWithIndex().map(_.swap)
    //Returning the vocabulary and tocken count pairs
    (documents, model.stages(2).asInstanceOf[CountVectorizerModel]
     .vocabulary, documents.map(_._2.numActives).sum().toLong)
    }
  }
  object helperForLDA {
    def filterSpecialCharacters(document: String) = 
      document.replaceAll("""[! @ # $ % ^ & * ( ) _ + - − ,
                          " ' ; : . ` ? --]""", " ")
    def getLemmaText(document: String, morphology: Morphology) = {
      val string = new StringBuilder()
      val value =new Document(document).sentences().toList.flatMap{a =>
      val words = a.words().toList
      val tags = a.posTags().toList
      (words zip tags).toMap.map { a =>
        val newWord = morphology.lemma(a._1, a._2)
        val addedWoed = if (newWord.length > 3) {
          newWord
        } else { "" }
        string.append(addedWoed + " ")
      }
    }
    string.toString()
  }
}

```

# LDA 的可扩展性

前面的示例展示了如何使用 LDA 算法进行主题建模作为独立应用程序。LDA 的并行化并不直接，已经有许多研究论文提出了不同的策略。在这方面的关键障碍是所有方法都涉及大量的通信。根据 Databricks 网站上的博客([`databricks.com/blog/2015/03/25/topic-modeling-with-lda-mllib-meets-graphx.html`](https://databricks.com/blog/2015/03/25/topic-modeling-with-lda-mllib-meets-graphx.html))，以下是在实验过程中使用的数据集和相关训练和测试集的统计数据：

+   训练集大小：460 万个文档

+   词汇量：110 万个术语

+   训练集大小：110 亿个标记（~每个文档 239 个词）

+   100 个主题

+   16 个 worker 的 EC2 集群，例如 M4.large 或 M3.medium，具体取决于预算和要求

对于前述设置，平均每次迭代的时间结果为 176 秒/迭代，共进行了 10 次迭代。从这些统计数据可以清楚地看出，对于非常大量的语料库，LDA 是相当可扩展的。

# 摘要

在本章中，我们提供了有关 Spark 机器学习一些高级主题的理论和实践方面。我们还提供了一些关于机器学习最佳实践的建议。在此之后，我们已经看到如何使用网格搜索、交叉验证和超参数调整来调整机器学习模型，以获得更好和优化的性能。在后面的部分，我们看到了如何使用 ALS 开发可扩展的推荐系统，这是使用基于模型的协同过滤方法的基于模型的推荐系统的一个示例。最后，我们看到了如何开发主题建模应用作为文本聚类技术。

对于机器学习最佳实践的其他方面和主题，感兴趣的读者可以参考名为*Large Scale Machine Learning with Spark*的书籍[`www.packtpub.com/big-data-and-business-intelligence/large-scale-machine-learning-spark.`](https://www.packtpub.com/big-data-and-business-intelligence/large-scale-machine-learning-spark)

在下一章中，我们将进入更高级的 Spark 使用。虽然我们已经讨论并提供了关于二元和多类分类的比较分析，但我们将更多地了解 Spark 中的其他多项式分类算法，如朴素贝叶斯、决策树和一对多分类器。


# 第十三章：我的名字是贝叶斯，朴素贝叶斯

“预测是非常困难的，尤其是关于未来的预测”

-尼尔斯·玻尔

**机器学习（ML）**与大数据的结合是一种革命性的组合，对学术界和工业界的研究产生了巨大影响。此外，许多研究领域也进入了大数据领域，因为数据集以前所未有的方式从各种来源和技术产生和生成，通常被称为**数据洪流**。这给机器学习、数据分析工具和算法带来了巨大挑战，以从大数据的诸如容量、速度和多样性等标准中找到真正的**价值**。然而，从这些庞大数据集中进行预测从来都不容易。

考虑到这一挑战，在本章中我们将深入探讨机器学习，并了解如何使用一种简单而强大的方法来构建可扩展的分类模型，甚至更多。简而言之，本章将涵盖以下主题：

+   多项式分类

+   贝叶斯推断

+   朴素贝叶斯

+   决策树

+   朴素贝叶斯与决策树

# 多项式分类

在机器学习中，多项式（也称为多类）分类是将数据对象或实例分类为两个以上类别的任务，即具有两个以上标签或类别。将数据对象或实例分类为两个类别称为二进制分类。更具体地说，在多项式分类中，每个训练实例属于 N 个不同类别中的一个，其中`N >=2`。目标是构建一个能够正确预测新实例所属类别的模型。可能存在许多情景，其中数据点属于多个类别。然而，如果给定点属于多个类别，这个问题可以轻松地分解为一组不相关的二进制问题，可以使用二进制分类算法自然地解决。

建议读者不要混淆多类分类和多标签分类，多标签分类是要为每个实例预测多个标签。对于基于 Spark 的多标签分类的实现，感兴趣的读者应参考[`spark.apache.org/docs/latest/mllib-evaluation-metrics.html#multilabel-classification`](https://spark.apache.org/docs/latest/mllib-evaluation-metrics.html#multilabel-classification)。

多类分类技术可以分为以下几类：

+   转换为二进制

+   从二进制扩展

+   分层分类

# 转换为二进制

使用转换为二进制的技术，多类分类问题可以转化为多个二进制分类问题的等效策略。换句话说，这种技术可以称为*问题转换技术*。从理论和实践角度进行详细讨论超出了本章的范围。因此，这里我们只讨论问题转换技术的一个例子，即代表这一类别的**一对多**（OVTR）算法。

# 使用一对多方法进行分类

在这一小节中，我们将通过将问题转化为等效的多个二进制分类问题，来描述使用 OVTR 算法进行多类分类的示例。OVTR 策略将问题分解，并针对每个类训练每个二进制分类器。换句话说，OVTR 分类器策略包括为每个类拟合一个二进制分类器。然后将当前类的所有样本视为正样本，因此其他分类器的样本被视为负样本。

毫无疑问，这是一种模块化的机器学习技术。然而，这种策略的缺点是需要来自多类家族的基本分类器。原因是分类器必须产生一个实值，也称为*置信分数*，而不是实际标签的预测。这种策略的第二个缺点是，如果数据集（也称为训练集）包含离散的类标签，这最终会导致模糊的预测结果。在这种情况下，一个样本可能被预测为多个类。为了使前面的讨论更清晰，现在让我们看一个例子。

假设我们有一组 50 个观察结果，分为三类。因此，我们将使用与之前相同的逻辑来选择负例。对于训练阶段，让我们有以下设置：

+   **分类器 1**有 30 个正例和 20 个负例

+   **分类器 2**有 36 个正例和 14 个负例

+   **分类器 3**有 14 个正例和 24 个负例

另一方面，在测试阶段，假设我有一个新实例需要分类到之前的某个类别中。当然，每个分类器都会产生一个关于估计的概率。这是一个实例属于分类器中的负面或正面示例的估计？在这种情况下，我们应该总是比较一个类中的正面概率与其他类。现在对于*N*个类，我们将有*N*个正面类的概率估计值。比较它们，无论哪个概率是*N*个概率中的最大值，都属于那个特定的类。Spark 提供了 OVTR 算法的多类到二进制的缩减，其中**逻辑回归**算法被用作基本分类器。

现在让我们看另一个真实数据集的例子，以演示 Spark 如何使用 OVTR 算法对所有特征进行分类。OVTR 分类器最终预测来自**光学字符识别**（OCR）数据集的手写字符。然而，在深入演示之前，让我们先探索 OCR 数据集，以了解数据的探索性质。需要注意的是，当 OCR 软件首次处理文档时，它将纸张或任何对象分成一个矩阵，以便网格中的每个单元格包含一个单一的字形（也称为不同的图形形状），这只是一种指代字母、符号、数字或来自纸张或对象的任何上下文信息的复杂方式。

为了演示 OCR 管道，假设文档只包含与 26 个大写字母中的一个匹配的英文 alpha 字符，即*A*到*Z*。我们将使用来自*UCI 机器学习数据存储库*的 OCR 字母数据集。该数据集由 W*. Frey*和*D. J. Slate.*标记。在探索数据集时，您应该观察到 20,000 个例子，其中包含 26 个英文大写字母。大写字母以 20 种不同的、随机重塑和扭曲的黑白字体作为不同形状的字形打印。简而言之，从 26 个字母中预测所有字符将问题本身转变为一个具有 26 个类的多类分类问题。因此，二元分类器将无法满足我们的目的。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00362.gif)**图 1：** 一些印刷字形（来源：使用 Holland 风格自适应分类器进行字母识别，ML，V. 6，p. 161-182，作者 W. Frey 和 D.J. Slate [1991])

前面的图显示了我之前解释过的图像。*数据集*提供了一些以这种方式扭曲的印刷字形的示例；因此，这些字母对计算机来说是具有挑战性的。然而，这些字形对人类来说很容易识别。下图显示了前 20 行的统计属性：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00020.jpeg)**图 2：** 数据框架显示的数据集快照

# OCR 数据集的探索和准备

根据数据集描述，字形是使用 OCR 阅读器扫描到计算机上，然后它们自动转换为像素。因此，所有 16 个统计属性（在**图 2**中）也记录到计算机中。盒子各个区域的黑色像素的浓度提供了一种区分 26 个字母的方法，使用 OCR 或机器学习算法进行训练。

回想一下，**支持向量机**（**SVM**），逻辑回归，朴素贝叶斯分类器，或者任何其他分类器算法（以及它们关联的学习器）都要求所有特征都是数字。LIBSVM 允许您使用非常规格式的稀疏训练数据集。在将正常训练数据集转换为 LIBSVM 格式时，只有数据集中包含的非零值存储在稀疏数组/矩阵形式中。索引指定实例数据的列（特征索引）。但是，任何缺失的数据也被视为零值。索引用作区分特征/参数的一种方式。例如，对于三个特征，索引 1、2 和 3 分别对应于*x*、*y*和*z*坐标。不同数据实例的相同索引值之间的对应仅在构建超平面时是数学的；这些用作坐标。如果您在中间跳过任何索引，它应该被分配一个默认值为零。

在大多数实际情况下，我们可能需要对所有特征点进行数据归一化。简而言之，我们需要将当前的制表符分隔的 OCR 数据转换为 LIBSVM 格式，以使训练步骤更容易。因此，我假设您已经下载了数据并使用它们自己的脚本转换为 LIBSVM 格式。转换为 LIBSVM 格式的结果数据集包括标签和特征，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00223.gif)**图 3：**LIBSVM 格式的 OCR 数据集的 20 行快照

感兴趣的读者可以参考以下研究文章以获得深入的知识：*Chih-Chung Chang*和*Chih-Jen Lin*，*LIBSVM：支持向量机库*，*ACM 智能系统与技术交易*，2:27:1--27:27，2011 年。您还可以参考我在 GitHub 存储库上提供的公共脚本，该脚本直接将 CSV 中的 OCR 数据转换为 LIBSVM 格式。我读取了所有字母的数据，并为每个字母分配了唯一的数值。您只需要显示输入和输出文件路径并运行脚本。

现在让我们来看一个例子。我将演示的例子包括 11 个步骤，包括数据解析、Spark 会话创建、模型构建和模型评估。

**步骤 1. 创建 Spark 会话** - 通过指定主 URL、Spark SQL 仓库和应用程序名称来创建 Spark 会话，如下所示：

```scala
val spark = SparkSession.builder
                     .master("local[*]") //change acordingly
                     .config("spark.sql.warehouse.dir", "/home/exp/")
                     .appName("OneVsRestExample") 
                     .getOrCreate()

```

**步骤 2. 加载、解析和创建数据框** - 从 HDFS 或本地磁盘加载数据文件，并创建数据框，最后显示数据框结构如下：

```scala
val inputData = spark.read.format("libsvm")
                     .load("data/Letterdata_libsvm.data")
inputData.show()

```

**步骤 3. 生成训练和测试集以训练模型** - 让我们通过将 70%用于训练和 30%用于测试来生成训练和测试集：

```scala
val Array(train, test) = inputData.randomSplit(Array(0.7, 0.3))

```

**步骤 4. 实例化基本分类器** - 这里基本分类器充当多类分类器。在这种情况下，可以通过指定最大迭代次数、容差、回归参数和弹性网参数来实例化逻辑回归算法。

请注意，当因变量是二元的时，逻辑回归是适当的回归分析。与所有回归分析一样，逻辑回归是一种预测性分析。逻辑回归用于描述数据并解释一个因变量二进制变量和一个或多个名义，有序，间隔或比率水平自变量之间的关系。

对于基于 Spark 的逻辑回归算法的实现，感兴趣的读者可以参考[`spark.apache.org/docs/latest/mllib-linear-methods.html#logistic-regression`](https://spark.apache.org/docs/latest/mllib-linear-methods.html#logistic-regression)。

简而言之，以下参数用于训练逻辑回归分类器：

+   `MaxIter`：这指定了最大迭代次数。一般来说，越多越好。

+   `Tol`：这是停止标准的公差。一般来说，越少越好，这有助于更加强烈地训练模型。默认值为 1E-4。

+   `FirIntercept`：这表示是否在生成概率解释时拦截决策函数。

+   `Standardization`：这表示一个布尔值，取决于是否要对训练进行标准化。

+   `AggregationDepth`：越多越好。

+   `RegParam`：这表示回归参数。在大多数情况下，越少越好。

+   `ElasticNetParam`：这表示更先进的回归参数。在大多数情况下，越少越好。

然而，您可以指定拟合拦截作为`Boolean`值，取决于您的问题类型和数据集属性：

```scala
 val classifier = new LogisticRegression()
                        .setMaxIter(500)          
                        .setTol(1E-4)                                                                                                  
                        .setFitIntercept(true)
                        .setStandardization(true) 
                        .setAggregationDepth(50) 
                        .setRegParam(0.0001) 
                        .setElasticNetParam(0.01)

```

第 5 步。 实例化 OVTR 分类器 - 现在实例化一个 OVTR 分类器，将多类分类问题转换为多个二进制分类问题如下：

```scala
val ovr = new OneVsRest().setClassifier(classifier)

```

这里`classifier`是逻辑回归估计器。现在是训练模型的时候了。

第 6 步。 训练多类模型 - 让我们使用训练集来训练模型如下：

```scala
val ovrModel = ovr.fit(train)

```

第 7 步。 在测试集上对模型进行评分 - 我们可以使用转换器（即`ovrModel`）对测试数据进行评分如下：

```scala
val predictions = ovrModel.transform(test)

```

第 8 步。 评估模型 - 在这一步中，我们将预测第一列中字符的标签。但在此之前，我们需要实例化一个`evaluator`来计算分类性能指标，如准确性，精确度，召回率和`f1`度量如下：

```scala
val evaluator = new MulticlassClassificationEvaluator()
                           .setLabelCol("label")
                           .setPredictionCol("prediction")    
val evaluator1 = evaluator.setMetricName("accuracy")
val evaluator2 = evaluator.setMetricName("weightedPrecision")
val evaluator3 = evaluator.setMetricName("weightedRecall")
val evaluator4 = evaluator.setMetricName("f1")

```

第 9 步。 计算性能指标 - 计算测试数据的分类准确性，精确度，召回率，`f1`度量和错误如下：

```scala
val accuracy = evaluator1.evaluate(predictions)
val precision = evaluator2.evaluate(predictions)
val recall = evaluator3.evaluate(predictions)
val f1 = evaluator4.evaluate(predictions)

```

第 10 步。 打印性能指标：

```scala
println("Accuracy = " + accuracy)
println("Precision = " + precision)
println("Recall = " + recall)
println("F1 = " + f1)
println(s"Test Error = ${1 - accuracy}")

```

您应该观察到以下值：

```scala
Accuracy = 0.5217246545696688
Precision = 0.488360500637862
Recall = 0.5217246545696688
F1 = 0.4695649096879411
Test Error = 0.47827534543033123

```

第 11 步。 停止 Spark 会话：

```scala
spark.stop() // Stop Spark session

```

通过这种方式，我们可以将多项分类问题转换为多个二进制分类问题，而不会牺牲问题类型。然而，从第 10 步可以观察到分类准确性并不好。这可能是由于多种原因，例如我们用来训练模型的数据集的性质。而且更重要的是，在训练逻辑回归模型时，我们没有调整超参数。此外，在执行转换时，OVTR 不得不牺牲一些准确性。

# 分层分类

在分层分类任务中，分类问题可以通过将输出空间划分为树来解决。在该树中，父节点被划分为多个子节点。该过程持续进行，直到每个子节点表示一个单一类别。基于分层分类技术提出了几种方法。计算机视觉是这样的领域的一个例子，其中识别图片或书面文本是使用分层处理的内容。本章对这个分类器的广泛讨论超出了范围。

# 从二进制扩展

这是一种将现有的二元分类器扩展为解决多类分类问题的技术。为了解决多类分类问题，基于神经网络、决策树、随机森林、k-最近邻、朴素贝叶斯和支持向量机等算法已经被提出和发展。在接下来的部分中，我们将讨论朴素贝叶斯和决策树算法作为这一类别的代表。

现在，在开始使用朴素贝叶斯算法解决多类分类问题之前，让我们在下一节简要概述贝叶斯推断。

# 贝叶斯推断

在本节中，我们将简要讨论**贝叶斯推断**（**BI**）及其基本理论。读者将从理论和计算的角度熟悉这个概念。

# 贝叶斯推断概述

贝叶斯推断是一种基于贝叶斯定理的统计方法。它用于更新假设的概率（作为强有力的统计证据），以便统计模型可以反复更新以实现更准确的学习。换句话说，在贝叶斯推断方法中，所有类型的不确定性都以统计概率的形式显现出来。这是理论统计学和数学统计学中的重要技术。我们将在后面的部分广泛讨论贝叶斯定理。

此外，贝叶斯更新在数据集序列的增量学习和动态分析中占据主导地位。例如，在时间序列分析、生物医学数据分析中的基因组测序、科学、工程、哲学和法律等领域，广泛使用贝叶斯推断。从哲学和决策理论的角度来看，贝叶斯推断与预测概率密切相关。然而，这个理论更正式地被称为**贝叶斯概率**。

# 什么是推断？

推断或模型评估是更新模型得出的结果的概率的过程。因此，所有的概率证据最终都会根据手头的观察结果得知，以便在使用贝叶斯模型进行分类分析时更新观察结果。随后，这些信息通过将一致性实例化到数据集中的所有观察结果中，被提取到贝叶斯模型中。被提取到模型中的规则被称为先验概率，其中在参考某些相关观察结果之前评估概率，特别是主观地或者假设所有可能的结果具有相同的概率。然后，当所有证据都已知时，信念就会被计算为后验概率。这些后验概率反映了基于更新的证据计算出的假设水平。

贝叶斯定理用于计算表示两个前提的结果的后验概率。基于这些前提，从统计模型中推导出先验概率和似然函数，用于新数据的模型适应性。我们将在后面的部分进一步讨论贝叶斯定理。

# 它是如何工作的？

在这里，我们讨论了统计推断问题的一般设置。首先，从数据中估计所需的数量，可能还有一些未知的数量，我们也想要估计。它可能只是一个响应变量或预测变量，一个类别，一个标签，或者只是一个数字。如果您熟悉*频率主义*方法，您可能知道在这种方法中，假设未知的数量θ被假定为一个固定的（非随机的）数量，它将由观察到的数据来估计。

然而，在贝叶斯框架中，一个未知的量θ被视为一个随机变量。更具体地说，假设我们对θ的分布有一个初始猜测，通常称为**先验分布**。现在，在观察到一些数据后，θ的分布被更新。通常使用贝叶斯定理来执行这一步骤（有关更多细节，请参阅下一节）。这就是为什么这种方法被称为贝叶斯方法。然而，简而言之，从先验分布中，我们可以计算未来观察的预测分布。

这种不矫揉造作的过程可以通过许多论据来证明是不确定推理的适当方法。然而，这些论据的合理性原则是保持一致的。尽管有这些强有力的数学证据，许多机器学习从业者对使用贝叶斯方法感到不舒服，有些不情愿。其背后的原因是他们经常认为选择后验概率或先验是任意和主观的；然而，实际上这是主观的但不是任意的。

不恰当地，许多贝叶斯派并不真正以真正的贝叶斯方式思考。因此，人们可以在文献中找到许多伪贝叶斯程序，其中使用的模型和先验不能被认真地看作是先验信念的表达。贝叶斯方法也可能存在计算困难。其中许多可以通过**马尔可夫链蒙特卡洛**方法来解决，这也是我研究的另一个主要焦点。随着您阅读本章，这种方法的细节将更加清晰。

# 朴素贝叶斯

在机器学习中，**朴素贝叶斯**（**NB**）是一个基于著名的贝叶斯定理和特征之间强独立假设的概率分类器的例子。我们将在本节详细讨论朴素贝叶斯。

# 贝叶斯定理概述

在概率论中，**贝叶斯定理**描述了基于与某一事件相关的先验条件的先验知识来计算该事件的概率。这是由托马斯·贝叶斯牧师最初陈述的概率定理。换句话说，它可以被看作是一种理解概率论如何受新信息影响的方式。例如，如果癌症与年龄有关，关于*年龄*的信息可以用来更准确地评估一个人可能患癌症的概率*。*

贝叶斯定理在数学上陈述如下方程：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00241.gif)

在上述方程中，*A*和*B*是具有*P (B) ≠ 0*的事件，其他项可以描述如下：

+   *P*(*A*)和*P*(*B*)是观察到*A*和*B*的概率，而不考虑彼此（即独立性）

+   *P*(*A* | *B*)是在*B*为真的情况下观察到事件*A*的条件概率

+   *P*(*B*| *A*)是在*A*为真的情况下观察到事件*B*的条件概率

您可能知道，一项著名的哈佛大学研究显示，只有 10%的快乐人群是富裕的。然而，您可能认为这个统计数据非常有说服力，但您可能对知道富裕人群中也真的很快乐的百分比感兴趣*。*贝叶斯定理可以帮助您计算这个逆转统计，使用两个额外线索：

1.  总体上快乐的人的百分比，即*P(A).*

1.  总体上富裕的人的百分比，即*P(B).*

贝叶斯定理背后的关键思想是逆转统计考虑整体比率**。**假设以下信息作为先验可用：

1.  40%的人是快乐的*=> P(A).*

1.  5%的人是富裕的*=> P(B).*

现在让我们假设哈佛大学的研究是正确的，即*P(B|A) = 10%*。现在富裕人群中快乐的人的比例，即*P(A | B),* 可以计算如下：

*P(A|B) = {P(A)* P(B| A)}/ P(B) = (40%*10%)/5% = 80%*

因此，大多数人也很高兴！很好。为了更清楚，现在让我们假设整个世界的人口为 1,000，以便简化。然后，根据我们的计算，存在两个事实：

+   事实 1：这告诉我们有 400 人很高兴，哈佛的研究告诉我们这些快乐的人中有 40 个也很富有。

+   事实 2：总共有 50 个富人，所以快乐的比例是 40/50 = 80%。

这证明了贝叶斯定理及其有效性。然而，更全面的例子可以在[`onlinecourses.science.psu.edu/stat414/node/43`](https://onlinecourses.science.psu.edu/stat414/node/43)找到。

# 我的名字是贝叶斯，朴素贝叶斯

我是贝叶斯，朴素贝叶斯（NB）。我是一个成功的分类器，基于**最大后验概率**（**MAP**）原理。作为一个分类器，我具有高度可扩展性，需要的参数数量与学习问题中的变量（特征/预测器）数量成正比。我有几个特性，例如，我在计算上更快，如果你雇佣我来分类一些东西，我很容易实现，并且我可以很好地处理高维数据集。此外，我可以处理数据集中的缺失值。然而，我是适应性的，因为模型可以通过新的训练数据进行修改而无需重建模型。

在贝叶斯统计学中，MAP 估计是未知数量的估计，等于后验分布的模。MAP 估计可用于根据经验数据获得未观察到的数量的点估计。

听起来有点像詹姆斯·邦德电影？好吧，你/我们可以把分类器看作是 007 特工，对吧？开玩笑。我相信我不像朴素贝叶斯分类器的参数，例如先验和条件概率是通过一组确定的步骤学习或确定的：这涉及两个非常微不足道的操作，在现代计算机上可以非常快速，即计数和除法。没有*迭代*。没有*时代*。没有*优化成本方程*（这可能是复杂的，平均为三次方或至少为二次方复杂度）。没有*错误反向传播*。没有涉及*解矩阵方程*的操作。这使得朴素贝叶斯及其整体训练更快。

然而，在雇佣这个代理之前，你/我们可以发现他的优缺点，这样我们才能像使用王牌一样利用它的优势。好吧，下面是总结这个代理的优缺点的表格：

| **代理** | **优点** | **缺点** | **擅长** |
| --- | --- | --- | --- |
| **朴素贝叶斯（NB）** | - 计算速度快- 实现简单- 在高维度下工作良好- 可处理缺失值- 需要少量数据来训练模型- 可扩展- 适应性强，因为模型可以通过新的训练数据进行修改而无需重建模型 | - 依赖独立假设，如果假设不成立则性能较差- 相对较低的准确性- 如果类标签和某个属性值没有出现在一起，则基于频率的概率估计将为零 | - 当数据有很多缺失值时- 当特征之间的依赖关系相似- 垃圾邮件过滤和分类- 对科技、政治、体育等新闻文章进行分类- 文本挖掘 |

**表 1：**朴素贝叶斯算法的优缺点

# 使用 NB 构建可扩展的分类器

在这一部分，我们将看到使用**朴素贝叶斯**（**NB**）算法的逐步示例。如前所述，NB 具有高度可扩展性，需要的参数数量与学习问题中的变量（特征/预测器）数量成正比。这种可扩展性使得 Spark 社区能够使用这种算法对大规模数据集进行预测分析。Spark MLlib 中 NB 的当前实现支持多项式 NB 和伯努利 NB。

如果特征向量是二进制的，伯努利 NB 是有用的。一个应用可能是使用词袋（BOW）方法进行文本分类。另一方面，多项式 NB 通常用于离散计数。例如，如果我们有一个文本分类问题，我们可以进一步采用伯努利试验的想法，而不是在文档中使用 BOW，我们可以使用文档中的频率计数。

在本节中，我们将看到如何通过整合 Spark 机器学习 API（包括 Spark MLlib、Spark ML 和 Spark SQL）来预测**基于笔的手写数字识别**数据集中的数字：

**步骤 1. 数据收集、预处理和探索** - 从 UCI 机器学习库[`www.csie.ntu.edu.tw/~cjlin/libsvmtools/datasets/multiclass/pendigits`](https://www.csie.ntu.edu.tw/~cjlin/libsvmtools/datasets/multiclass/pendigits)下载了基于笔的手写数字数据集。该数据集是在从 44 位作者那里收集了大约 250 个数字样本后生成的，这些数字样本与笔在 100 毫秒的固定时间间隔内的位置相关。然后，每个数字都写在一个 500 x 500 像素的框内。最后，这些图像被缩放到 0 到 100 之间的整数值，以创建每个观察之间的一致缩放。一个众所周知的空间重采样技术被用来获得弧轨迹上的 3 和 8 个等间距点。可以通过根据它们的（x，y）坐标绘制 3 或 8 个采样点来可视化一个样本图像以及点与点之间的线；它看起来像下表所示：

| 集合 | '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | 总计 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 训练 | 780 | 779 | 780 | 719 | 780 | 720 | 720 | 778 | 718 | 719 | 7493 |
| 测试 | 363 | 364 | 364 | 336 | 364 | 335 | 336 | 364 | 335 | 336 | 3497 |

表 2：用于训练和测试集的数字数量

如前表所示，训练集由 30 位作者撰写的样本组成，测试集由 14 位作者撰写的样本组成。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00130.jpeg)

图 4：数字 3 和 8 的示例

有关该数据集的更多信息可以在[`archive.ics.uci.edu/ml/machine-learning-databases/pendigits/pendigits-orig.names`](http://archive.ics.uci.edu/ml/machine-learning-databases/pendigits/pendigits-orig.names)找到。数据集的一个样本快照的数字表示如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00149.gif)

图 5：手写数字数据集的 20 行快照

现在，为了使用独立变量（即特征）预测因变量（即标签），我们需要训练一个多类分类器，因为如前所示，数据集现在有九个类别，即九个手写数字。对于预测，我们将使用朴素贝叶斯分类器并评估模型的性能。

**步骤 2.** 加载所需的库和包：

```scala
import org.apache.spark.ml.classification.NaiveBayes
import org.apache.spark.ml.evaluation
                                 .MulticlassClassificationEvaluator
import org.apache.spark.sql.SparkSession

```

**步骤 3.** 创建一个活跃的 Spark 会话：

```scala
val spark = SparkSession
              .builder
              .master("local[*]")
              .config("spark.sql.warehouse.dir", "/home/exp/")
              .appName(s"NaiveBayes")
              .getOrCreate()

```

请注意，这里的主 URL 已设置为`local[*]`，这意味着您的计算机的所有核心将用于处理 Spark 作业。您应该根据要求相应地设置 SQL 数据仓库和其他配置参数。

**步骤 4. 创建 DataFrame** - 将以 LIBSVM 格式存储的数据加载为 DataFrame：

```scala
val data = spark.read.format("libsvm")
                     .load("data/pendigits.data")

```

对于数字分类，输入特征向量通常是稀疏的，应该将稀疏向量作为输入以利用稀疏性。由于训练数据只使用一次，而且数据集的大小相对较小（即几 MB），如果您多次使用 DataFrame，可以将其缓存。

**步骤 5. 准备训练和测试集** - 将数据分割为训练集和测试集（25%用于测试）：

```scala
val Array(trainingData, testData) = data
                  .randomSplit(Array(0.75, 0.25), seed = 12345L)

```

**步骤 6. 训练朴素贝叶斯模型** - 使用训练集训练朴素贝叶斯模型如下：

```scala
val nb = new NaiveBayes()
val model = nb.fit(trainingData)

```

**步骤 7：** 计算测试集上的预测 - 使用模型变换器计算预测，最后显示针对每个标签的预测，如下所示：

```scala
val predictions = model.transform(testData)
predictions.show()

```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00189.jpeg)**图 6：** 针对每个标签（即每个数字）的预测

如前图所示，一些标签被准确预测，而另一些标签则错误。再次，我们需要了解加权准确性、精确度、召回率和 F1 度量，而不是简单地评估模型。

**步骤 8：** 评估模型 - 选择预测和真实标签来计算测试错误和分类性能指标，如准确性、精确度、召回率和 F1 度量，如下所示：

```scala
val evaluator = new MulticlassClassificationEvaluator()
                           .setLabelCol("label")
                           .setPredictionCol("prediction")    
val evaluator1 = evaluator.setMetricName("accuracy")
val evaluator2 = evaluator.setMetricName("weightedPrecision")
val evaluator3 = evaluator.setMetricName("weightedRecall")
val evaluator4 = evaluator.setMetricName("f1")

```

**步骤 9：** 计算性能指标 - 计算测试数据的分类准确性、精确度、召回率、F1 度量和错误，如下所示：

```scala
val accuracy = evaluator1.evaluate(predictions)
val precision = evaluator2.evaluate(predictions)
val recall = evaluator3.evaluate(predictions)
val f1 = evaluator4.evaluate(predictions)

```

**步骤 10：** 打印性能指标：

```scala
println("Accuracy = " + accuracy)
println("Precision = " + precision)
println("Recall = " + recall)
println("F1 = " + f1)
println(s"Test Error = ${1 - accuracy}")

```

您应该观察到以下值：

```scala
Accuracy = 0.8284365162644282
Precision = 0.8361211320692463
Recall = 0.828436516264428
F1 = 0.8271828540349192
Test Error = 0.17156348373557184

```

性能并不是那么糟糕。但是，您仍然可以通过进行超参数调整来提高分类准确性。通过交叉验证和训练集拆分，可以进一步提高预测准确性，这将在下一节中讨论。

# 调整我！

您已经了解我的优缺点，我的一个缺点是，我的分类准确性相对较低。但是，如果您调整我，我可以表现得更好。好吧，我们应该相信朴素贝叶斯吗？如果是这样，我们不应该看看如何提高这家伙的预测性能吗？比如使用 WebSpam 数据集。首先，我们应该观察 NB 模型的性能，然后再看如何使用交叉验证技术提高性能。

从[`www.csie.ntu.edu.tw/~cjlin/libsvmtools/datasets/binary/webspam_wc_normalized_trigram.svm.bz2`](http://www.csie.ntu.edu.tw/~cjlin/libsvmtools/datasets/binary/webspam_wc_normalized_trigram.svm.bz2)下载的 WebSpam 数据集包含特征和相应的标签，即垃圾邮件或正常邮件。因此，这是一个监督式机器学习问题，这里的任务是预测给定消息是垃圾邮件还是正常邮件（即非垃圾邮件）。原始数据集大小为 23.5 GB，类别标签为+1 或-1（即二元分类问题）。后来，我们将-1 替换为 0.0，+1 替换为 1.0，因为朴素贝叶斯不允许使用有符号整数。修改后的数据集如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00054.gif)**图 7：** WebSpam 数据集的 20 行快照

首先，我们需要导入必要的包，如下所示：

```scala
import org.apache.spark.ml.classification.NaiveBayes
import org.apache.spark.ml.evaluation.MulticlassClassificationEvaluator
import org.apache.spark.sql.SparkSession
import org.apache.spark.ml.Pipeline;
import org.apache.spark.ml.PipelineStage;
import org.apache.spark.ml.classification.LogisticRegression
import org.apache.spark.ml.evaluation.BinaryClassificationEvaluator
import org.apache.spark.ml.feature.{HashingTF, Tokenizer}
import org.apache.spark.ml.linalg.Vector
import org.apache.spark.ml.tuning.{CrossValidator, ParamGridBuilder}

```

现在创建 Spark 会话作为代码的入口点，如下所示：

```scala
val spark = SparkSession
      .builder
      .master("local[*]")
      .config("spark.sql.warehouse.dir", "/home/exp/")
      .appName("Tuned NaiveBayes")
      .getOrCreate()

```

让我们加载 WebSpam 数据集并准备训练集来训练朴素贝叶斯模型，如下所示：

```scala
// Load the data stored in LIBSVM format as a DataFrame.
 val data = spark.read.format("libsvm").load("hdfs://data/ webspam_wc_normalized_trigram.svm")
 // Split the data into training and test sets (30% held out for testing)
 val Array(trainingData, testData) = data.randomSplit(Array(0.75, 0.25), seed = 12345L)
 // Train a NaiveBayes model with using the training set
 val nb = new NaiveBayes().setSmoothing(0.00001)
 val model = nb.fit(trainingData)

```

在前面的代码中，设置种子是为了可重现性。现在让我们在验证集上进行预测，如下所示：

```scala
val predictions = model.transform(testData)
predictions.show()

```

现在让我们获取`evaluator`并计算分类性能指标，如准确性、精确度、召回率和`f1`度量，如下所示：

```scala
val evaluator = new MulticlassClassificationEvaluator()
                    .setLabelCol("label")
                    .setPredictionCol("prediction")    
val evaluator1 = evaluator.setMetricName("accuracy")
val evaluator2 = evaluator.setMetricName("weightedPrecision")
val evaluator3 = evaluator.setMetricName("weightedRecall")
val evaluator4 = evaluator.setMetricName("f1")

```

现在让我们计算并打印性能指标：

```scala
val accuracy = evaluator1.evaluate(predictions)
val precision = evaluator2.evaluate(predictions)
val recall = evaluator3.evaluate(predictions)
val f1 = evaluator4.evaluate(predictions)   
// Print the performance metrics
println("Accuracy = " + accuracy)
println("Precision = " + precision)
println("Recall = " + recall)
println("F1 = " + f1)
println(s"Test Error = ${1 - accuracy}")

```

您应该收到以下输出：

```scala
Accuracy = 0.8839357429715676
Precision = 0.86393574297188752
Recall = 0.8739357429718876
F1 = 0.8739357429718876
Test Error = 0.11606425702843237

```

尽管准确性达到了令人满意的水平，但我们可以通过应用交叉验证技术进一步提高它。该技术的步骤如下：

+   通过链接一个 NB 估计器作为管道的唯一阶段来创建管道

+   现在为调整准备参数网格

+   执行 10 折交叉验证

+   现在使用训练集拟合模型

+   计算验证集上的预测

诸如交叉验证之类的模型调整技术的第一步是创建管道。可以通过链接变换器、估计器和相关参数来创建管道。

**步骤 1：** 创建管道 - 让我们创建一个朴素贝叶斯估计器（在下面的情况中`nb`是一个估计器），并通过链接估计器来创建管道，如下所示：

```scala
val nb = new NaiveBayes().setSmoothing(00001)
val pipeline = new Pipeline().setStages(Array(nb))

```

管道可以被视为用于训练和预测的数据工作流系统。ML 管道提供了一组统一的高级 API，构建在[DataFrames](https://spark.apache.org/docs/latest/sql-programming-guide.html)之上，帮助用户创建和调整实用的机器学习管道。DataFrame、转换器、估计器、管道和参数是管道创建中最重要的五个组件。有兴趣的读者可以参考[`spark.apache.org/docs/latest/ml-pipeline.html`](https://spark.apache.org/docs/latest/ml-pipeline.html)了解更多关于管道的信息。

在早期情况下，我们管道中的唯一阶段是一个估计器，它是用于在 DataFrame 上拟合的算法，以产生一个转换器，以确保训练成功进行。

**步骤 2. 创建网格参数** - 让我们使用`ParamGridBuilder`构建一个参数网格进行搜索：

```scala
val paramGrid = new ParamGridBuilder()
              .addGrid(nb.smoothing, Array(0.001, 0.0001))
              .build()

```

**步骤 3. 执行 10 折交叉验证** - 现在我们将管道视为一个估计器，将其包装在一个交叉验证实例中。这将允许我们共同选择所有管道阶段的参数。`CrossValidator`需要一个估计器、一组估计器`ParamMaps`和一个评估器。请注意，这里的评估器是`BinaryClassificationEvaluator`，其默认指标是`areaUnderROC`。但是，如果您将评估器用作`MultiClassClassificationEvaluator`，您将能够使用其他性能指标：

```scala
val cv = new CrossValidator()
            .setEstimator(pipeline)
            .setEvaluator(new BinaryClassificationEvaluator)
            .setEstimatorParamMaps(paramGrid)
            .setNumFolds(10)  // Use 3+ in practice

```

**步骤 4.** 按以下方式使用训练集拟合交叉验证模型：

```scala
val model = cv.fit(trainingData)

```

**步骤 5.** 按以下方式计算性能：

```scala
val predictions = model.transform(validationData)
predictions.show()

```

**步骤 6.** 获取评估器，计算性能指标并显示结果。现在让我们获取`evaluator`并计算分类性能指标，如准确度、精确度、召回率和 f1 度量。这里将使用`MultiClassClassificationEvaluator`来计算准确度、精确度、召回率和 f1 度量：

```scala
val evaluator = new MulticlassClassificationEvaluator()
                            .setLabelCol("label")
                            .setPredictionCol("prediction")    
val evaluator1 = evaluator.setMetricName("accuracy")
val evaluator2 = evaluator.setMetricName("weightedPrecision")
val evaluator3 = evaluator.setMetricName("weightedRecall")
val evaluator4 = evaluator.setMetricName("f1")

```

现在按照以下步骤计算测试数据的分类准确度、精确度、召回率、f1 度量和错误：

```scala
val accuracy = evaluator1.evaluate(predictions)
val precision = evaluator2.evaluate(predictions)
val recall = evaluator3.evaluate(predictions)
val f1 = evaluator4.evaluate(predictions)

```

现在让我们打印性能指标：

```scala
println("Accuracy = " + accuracy)
println("Precision = " + precision)
println("Recall = " + recall)
println("F1 = " + f1)
println(s"Test Error = ${1 - accuracy}")

```

您现在应该收到以下结果：

```scala
Accuracy = 0.9678714859437751
Precision = 0.9686742518830365
Recall = 0.9678714859437751
F1 = 0.9676697179934564
Test Error = 0.032128514056224855

```

现在这比之前的好多了，对吧？请注意，由于数据集的随机分割和您的平台，您可能会收到略有不同的结果。

# 决策树

在本节中，我们将详细讨论决策树算法。还将讨论朴素贝叶斯和决策树的比较分析。决策树通常被认为是一种用于解决分类和回归任务的监督学习技术。决策树简单地说是一种决策支持工具，它使用树状图（或决策模型）及其可能的后果，包括机会事件结果、资源成本和效用。更技术性地说，决策树中的每个分支代表了一个可能的决策、发生或反应，以统计概率的形式。

与朴素贝叶斯相比，决策树是一种更加健壮的分类技术。原因在于决策树首先将特征分为训练集和测试集。然后它产生了一个很好的泛化来推断预测的标签或类。最有趣的是，决策树算法可以处理二元和多类分类问题。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00081.jpeg)**图 8：** 使用 Rattle 软件包在入学测试数据集上的一个样本决策树

例如，在前面的示例图中，决策树从入学数据中学习，用一组`if...else`决策规则来逼近正弦曲线。数据集包含每个申请入学的学生的记录，比如申请美国大学。每条记录包含研究生入学考试成绩、CGPA 成绩和列的排名。现在我们需要根据这三个特征（变量）来预测谁是胜任的。在训练决策树模型并修剪树的不需要的分支后，决策树可以用来解决这种问题。一般来说，树越深，决策规则越复杂，模型拟合得越好。因此，树越深，决策规则越复杂，模型拟合得越好。

如果你想绘制前面的图，只需运行我的 R 脚本，在 RStudio 上执行，并提供入学数据。脚本和数据集可以在我的 GitHub 存储库中找到[`github.com/rezacsedu/AdmissionUsingDecisionTree`](https://github.com/rezacsedu/AdmissionUsingDecisionTree)。

# 使用决策树的优缺点

在雇佣我之前，你可以从表 3 中了解我的优缺点以及我最擅长的工作时间，这样你就不会有任何迟来的后悔！

| **代理** | **优点** | **缺点** | **擅长** |
| --- | --- | --- | --- |
| **决策树（DTs）** | -简单实现、训练和解释-树可以可视化-准备数据很少-模型构建和预测时间少-可以处理数值和分类数据-可以使用统计测试验证模型-对噪声和缺失值很健壮-高准确性 | -大型和复杂树的解释很困难-同一子树内可能会出现重复-可能出现对角决策边界问题-DT 学习者可能会创建不能很好泛化数据的过于复杂的树-有时由于数据的微小变化，决策树可能不稳定-学习决策树本身是一个 NP 完全问题-如果某些类占主导地位，DT 学习者会创建有偏见的树 | -针对高准确性分类-医学诊断和预后-信用风险分析 |

**表 3：** 决策树的优缺点

# 决策树与朴素贝叶斯

如前表所述，由于其对训练数据的灵活性，决策树非常容易理解和调试。它们可以处理分类问题和回归问题。

如果你想要预测分类值或连续值，决策树都可以处理。因此，如果你只有表格数据，将其提供给决策树，它将构建模型以对数据进行分类，而无需任何额外的前期或手动干预。总之，决策树非常简单实现、训练和解释。准备数据很少，决策树就可以用更少的预测时间构建模型。正如前面所说，它们可以处理数值和分类数据，并且对噪声和缺失值非常健壮。使用统计测试非常容易验证模型。更有趣的是，构建的树可以可视化。总的来说，它们提供了非常高的准确性。

然而，决策树有时倾向于过拟合训练数据的问题。这意味着通常需要修剪树，并找到一个更好的分类或回归准确性的最佳树。此外，同一子树内可能会出现重复。有时它还会在对角决策边界问题上出现问题，导致过拟合和欠拟合。此外，DT 学习者可能会创建不能很好泛化数据的过于复杂的树，这使得整体解释很困难。由于数据的微小变化，决策树可能不稳定，因此学习决策树本身是一个 NP 完全问题。最后，如果某些类占主导地位，DT 学习者会创建有偏见的树。

建议读者参考*表 1*和*3*，以获得朴素贝叶斯和 DT 之间的比较摘要。

另一方面，在使用朴素贝叶斯时有一句话：*NB 需要您手动构建分类*。无法将大量表格数据输入其中，然后选择最佳的特征进行分类。然而，在这种情况下，选择正确的特征和重要的特征取决于用户，也就是您。另一方面，DT 将从表格数据中选择最佳的特征。鉴于这一事实，您可能需要将朴素贝叶斯与其他统计技术结合起来，以帮助进行最佳特征提取并稍后对其进行分类。或者，使用 DT 以获得更好的精度、召回率和 f1 度量的准确性。朴素贝叶斯的另一个优点是它将作为连续分类器进行回答。然而，缺点是它们更难调试和理解。当训练数据没有良好特征且数据量较小时，朴素贝叶斯表现得相当不错。

总之，如果您试图从这两者中选择更好的分类器，通常最好的方法是测试每个来解决问题。我的建议是使用您拥有的训练数据构建 DT 和朴素贝叶斯分类器，然后使用可用的性能指标比较性能，然后决定哪一个最适合解决您的问题，取决于数据集的性质。

# 使用 DT 算法构建可扩展分类器

正如您已经看到的，使用 OVTR 分类器，我们观察到 OCR 数据集上性能指标的以下值：

```scala
Accuracy = 0.5217246545696688
Precision = 0.488360500637862
Recall = 0.5217246545696688
F1 = 0.4695649096879411
Test Error = 0.47827534543033123

```

这表明该数据集上模型的准确性非常低。在本节中，我们将看到如何使用 DT 分类器来提高性能。将使用相同的 OCR 数据集展示 Spark 2.1.0 的示例。该示例将包括数据加载、解析、模型训练以及最终的模型评估等多个步骤。

由于我们将使用相同的数据集，为了避免冗余，我们将跳过数据集探索步骤，直接进入示例：

**步骤 1.** 加载所需的库和包如下：

```scala
import org.apache.spark.ml.Pipeline // for Pipeline creation
import org.apache.spark.ml.classification
                         .DecisionTreeClassificationModel 
import org.apache.spark.ml.classification.DecisionTreeClassifier 
import org.apache.spark.ml.evaluation
                         .MulticlassClassificationEvaluator 
import org.apache.spark.ml.feature
                         .{IndexToString, StringIndexer, VectorIndexer} 
import org.apache.spark.sql.SparkSession //For a Spark session

```

**步骤 2.** 创建一个活跃的 Spark 会话如下：

```scala
val spark = SparkSession
              .builder
              .master("local[*]")
              .config("spark.sql.warehouse.dir", "/home/exp/")
              .appName("DecisionTreeClassifier")
              .getOrCreate()

```

请注意，这里将主 URL 设置为`local[*]`，这意味着您的计算机的所有核心将用于处理 Spark 作业。您应该根据要求设置 SQL 仓库和其他配置参数。

**步骤 3.** 创建 DataFrame - 加载以 LIBSVM 格式存储的数据作为 DataFrame 如下：

```scala
val data = spark.read.format("libsvm").load("datab
                             /Letterdata_libsvm.data")

```

对于数字的分类，输入特征向量通常是稀疏的，应该提供稀疏向量作为输入以利用稀疏性。由于训练数据只使用一次，而且数据集的大小相对较小（即几 MB），如果您多次使用 DataFrame，可以将其缓存起来。

**步骤 4.** 标签索引 - 对标签进行索引，为标签列添加元数据。然后让我们在整个数据集上进行拟合，以包含索引中的所有标签：

```scala
val labelIndexer = new StringIndexer()
               .setInputCol("label")
               .setOutputCol("indexedLabel")
               .fit(data)

```

**步骤 5.** 识别分类特征 - 以下代码段自动识别分类特征并对其进行索引：

```scala
val featureIndexer = new VectorIndexer()
              .setInputCol("features")
              .setOutputCol("indexedFeatures")
              .setMaxCategories(4)
              .fit(data)

```

对于这种情况，如果特征的数量超过四个不同的值，它们将被视为连续的。

**步骤 6.** 准备训练和测试集 - 将数据分割为训练集和测试集（25%用于测试）：

```scala
val Array(trainingData, testData) = data.randomSplit
                                      (Array(0.75, 0.25), 12345L)

```

**步骤 7.** 训练 DT 模型如下：

```scala
val dt = new DecisionTreeClassifier()
                     .setLabelCol("indexedLabel")
                     .setFeaturesCol("indexedFeatures")

```

**步骤 8.** 将索引的标签转换回原始标签如下：

```scala
val labelConverter = new IndexToString()
                .setInputCol("prediction")
                .setOutputCol("predictedLabel")
                .setLabels(labelIndexer.labels)

```

**步骤 9.** 创建 DT 管道 - 让我们通过更改索引器、标签转换器和树来创建一个 DT 管道：

```scala
val pipeline = new Pipeline().setStages(Array(labelIndexer,
                              featureIndexer, dt, labelconverter))

```

**步骤 10.** 运行索引器 - 使用转换器训练模型并运行索引器：

```scala
val model = pipeline.fit(trainingData)

```

**步骤 11.** 计算测试集上的预测 - 使用模型转换器计算预测，最后显示每个标签的预测如下：

```scala
val predictions = model.transform(testData)
predictions.show()

```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00344.jpeg)**图 9：** 预测与每个标签（即每个字母）相对应

从上图可以看出，一些标签被准确预测，而另一些则被错误预测。然而，我们知道加权准确性、精确度、召回率和 f1 度量，但我们需要先评估模型。

**步骤 12. 评估模型** - 选择预测和真实标签来计算测试错误和分类性能指标，如准确性、精确度、召回率和 f1 度量，如下所示：

```scala
val evaluator = new MulticlassClassificationEvaluator()
                             .setLabelCol("label")
                             .setPredictionCol("prediction")    
val evaluator1 = evaluator.setMetricName("accuracy")
val evaluator2 = evaluator.setMetricName("weightedPrecision")
val evaluator3 = evaluator.setMetricName("weightedRecall")
val evaluator4 = evaluator.setMetricName("f1")

```

**步骤 13. 计算性能指标** - 计算测试数据的分类准确性、精确度、召回率、f1 度量和错误，如下所示：

```scala
val accuracy = evaluator1.evaluate(predictions)
val precision = evaluator2.evaluate(predictions)
val recall = evaluator3.evaluate(predictions)
val f1 = evaluator4.evaluate(predictions)

```

**步骤 14.** 打印性能指标：

```scala
println("Accuracy = " + accuracy)
println("Precision = " + precision)
println("Recall = " + recall)
println("F1 = " + f1)
println(s"Test Error = ${1 - accuracy}")

```

您应该按以下数值观察：

```scala
Accuracy = 0.994277821625888
Precision = 0.9904583933020722
Recall = 0.994277821625888
F1 = 0.9919966504321712
Test Error = 0.005722178374112041

```

现在性能很好，对吧？然而，您仍然可以通过执行超参数调整来提高分类准确性。通过交叉验证和训练集拆分，可以进一步提高预测准确性，选择适当的算法（即分类器或回归器）。

**步骤 15.** 打印决策树节点：

```scala
val treeModel = model.stages(2).asInstanceOf
                                [DecisionTreeClassificationModel]
println("Learned classification tree model:\n" + treeModel
                 .toDebugString)

```

最后，我们将打印决策树中的一些节点，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00199.gif)**图 10：** 在模型构建过程中生成的一些决策树节点

# 总结

在本章中，我们讨论了一些机器学习中的高级算法，并发现了如何使用一种简单而强大的贝叶斯推断方法来构建另一种分类模型，即多项式分类算法。此外，从理论和技术角度广泛讨论了朴素贝叶斯算法。最后，讨论了决策树和朴素贝叶斯算法之间的比较分析，并提供了一些指导方针。

在下一章中，我们将更深入地研究机器学习，并找出如何利用机器学习来对属于无监督观测数据集的记录进行聚类。
