# Python 数据科学与机器学习实用手册（三）

> 原文：[`zh.annas-archive.org/md5/92E2CBA50423C2D275EEE8125598FF8B`](https://zh.annas-archive.org/md5/92E2CBA50423C2D275EEE8125598FF8B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：处理真实世界的数据

在本章中，我们将讨论处理真实世界数据的挑战，以及你可能遇到的一些怪癖。本章首先讨论了偏差-方差的权衡，这是一种更有原则的谈论你可能过拟合和欠拟合数据的不同方式的方式，以及它们如何相互关联。然后我们讨论了 k 折交叉验证技术，这是你用来对抗过拟合的重要工具，并看看如何使用 Python 实现它。

接下来，我们分析了在实际应用任何算法之前清理和归一化数据的重要性。我们看了一个示例来确定网站上最受欢迎的页面，这将展示清理数据的重要性。本章还涵盖了记住归一化数值数据的重要性。最后，我们看看如何检测异常值并处理它们。

具体来说，本章涵盖以下主题：

+   分析偏差/方差的权衡

+   k 折交叉验证的概念及其实现

+   清理和归一化数据的重要性

+   确定网站的热门页面的示例

+   归一化数值数据

+   检测异常值并处理它们

# 偏差/方差的权衡

在处理真实世界数据时面临的一个基本挑战是过拟合与欠拟合你的回归数据，或者你的模型，或者你的预测。当我们谈论欠拟合和过拟合时，我们经常可以在偏差和方差的背景下谈论这一点，以及偏差-方差的权衡。所以，让我们谈谈这意味着什么。

从概念上讲，偏差和方差非常简单。偏差就是你离正确值有多远，也就是说，你的预测在整体上预测正确的值有多好。如果你取所有预测的平均值，它们是否更多或更少在正确的位置上？或者你的错误是一直偏向某个方向？如果是这样，那么你的预测就有某个方向的偏差。

方差只是衡量你的预测有多分散、多散乱的一个指标。所以，如果你的预测到处都是，那就是高方差。但是，如果它们非常集中在正确的值上，甚至在高偏差的情况下也是如此，那么你的方差就很小。

让我们看一些例子。假设以下飞镖板代表我们正在做的一堆预测，我们试图预测的真实值在靶心的中心：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/fae2cf23-43e6-4526-b005-39df58463d04.png)

+   从左上角的飞镖板开始，你可以看到我们的点都散落在中心周围。所以总体上，你知道平均误差非常接近实际情况。我们的偏差实际上非常低，因为我们的预测都在同一个正确的点周围。然而，我们的方差非常高，因为这些点散布在各个地方。所以，这是一个低偏差和高方差的例子。

+   如果我们转移到右上角的飞镖板，我们会看到我们的点都一直偏离了正确的位置，向西北方向。所以这是我们预测中高偏差的一个例子，它们一直偏离了一定的距离。我们的方差很低，因为它们都紧密地聚集在错误的位置周围，但至少它们是紧密在一起的，所以我们在预测中是一致的。这是低方差。但是，偏差很高。所以再次，这是高偏差，低方差。

+   在左下角的飞镖板上，你可以看到我们的预测散布在错误的平均点周围。所以，我们有很高的偏差；一切都偏向了不应该去的地方。但我们的方差也很高。所以，这在这个例子中是最糟糕的情况；我们既有高偏差又有高方差。

+   最后，在一个完美的世界中，你会有一个像右下方飞镖板那样的例子，那里我们有低偏差，一切都集中在应该的位置，以及低方差，事物都紧密地聚集在应该的位置。所以，在一个完美的世界中，这就是你最终得到的结果。

实际上，你经常需要在偏差和方差之间做出选择。这归结为过拟合与欠拟合数据。让我们看看以下例子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/7a856ab7-9d88-404c-8cfb-97365495b525.png) ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/0386221c-18f7-4cc9-88aa-9139c77d4ba5.png)

这是一种对偏差和方差的不同思考方式。所以，在左边的图表中，我们有一条直线，你可以认为相对于这些观察结果，它具有非常低的方差。所以，这条线的方差不大，也就是说，它具有低方差。但是偏差，每个单独点的误差，实际上是很高的。

现在，对比一下右边图表中过拟合的数据，我们已经努力去拟合这些观察结果。这条线具有高方差，但低偏差，因为每个单独的点都非常接近它应该在的位置。所以，这就是我们用方差换取偏差的一个例子。

最终，你不是为了只减少偏差或只减少方差，你想要减少错误。这才是真正重要的，结果表明你可以将错误表达为偏差和方差的函数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/459a0f30-4b0c-4dfd-a4fb-91b39c005369.png)

看这个，错误等于偏差的平方加上方差。所以，这两个因素都会对总体错误产生影响，实际上偏差的影响更大。但要记住，你真正想要最小化的是错误，而不是偏差或方差特别，一个过于复杂的模型最终可能会产生高方差和低偏差，而一个过于简单的模型会产生低方差和高偏差。然而，它们最终可能都会产生类似的错误项。当你试图拟合你的数据时，你只需要找到这两个因素的正确平衡点。我们将在接下来的部分讨论一些更有原则的方法来避免过拟合。但是，我只是想传达偏差和方差的概念，因为人们确实会谈论它，你会被期望知道它的含义。

现在让我们把它与本书中一些早期的概念联系起来。例如，在 K 最近邻中，如果我们增加 K 的值，我们开始扩大我们要平均的邻域到一个更大的区域。这会减少方差，因为我们在更大的空间上平滑了事物，但它可能会增加我们的偏差，因为我们可能会选择一个更大的人口，这个人口可能与我们起始的点越来越不相关。通过在更多的邻居上平滑 KNN，我们可以减少方差，因为我们在更多的值上平滑了事物。但是，我们可能会引入偏差，因为我们引入了越来越不相关于我们起始点的点。

决策树就是另一个例子。我们知道单个决策树容易过拟合，这可能意味着它具有高方差。但是，随机森林试图通过拥有多个随机变体的树并将它们的解决方案平均在一起来换取一些偏差减少的方差，就像我们通过增加 K 值来平均 KNN 的结果一样：我们可以通过使用多个决策树来平均决策树的结果，使用随机森林类似的想法。

这就是偏差-方差折衷。你知道你必须在整体准确度和散布程度或紧密聚集程度之间做出决定。这就是偏差-方差折衷，它们都对总体错误产生影响，而你真正关心的是最小化这个错误。所以，记住这些术语！

# K 折交叉验证以避免过拟合

在本书的前面，我们谈到了训练和测试作为防止过拟合并实际测量模型在从未见过的数据上的表现的好方法。我们可以通过一种称为 k 折交叉验证的技术将其提升到一个新的水平。因此，让我们谈谈这个强大的工具，用于对抗过拟合；k 折交叉验证，并了解它的工作原理。

回想一下训练/测试，其思想是我们将构建机器学习模型的所有数据分成两部分：一个训练数据集和一个测试数据集。我们只使用训练数据集来训练模型，然后使用我们保留的测试数据集来评估其性能。这样可以防止我们对已有数据过拟合，因为我们正在测试模型对其从未见过的数据的表现。

然而，训练/测试仍然有其局限性：你仍然可能会对特定的训练/测试分割过拟合。也许你的训练数据集并不真正代表整个数据集，太多的东西最终进入了你的训练数据集，导致了偏差。这就是 k 折交叉验证发挥作用的地方，它将训练/测试提升到一个新的水平。

尽管听起来很复杂，但其实思想相当简单：

1.  我们将数据分成 K 个桶，而不是两个桶，一个用于训练，一个用于测试。

1.  我们保留其中一个桶用于测试目的，用于评估我们模型的结果。

1.  我们对剩下的桶（K-1）进行模型训练，然后我们拿出我们的测试数据集，用它来评估我们的模型在所有这些不同的训练数据集中的表现如何。

1.  我们将这些结果的误差指标（即 R 平方值）进行平均，得到 k 折交叉验证的最终误差指标。

就是这样。这是一种更健壮的训练/测试方法，这是一种方法。

现在，你可能会想，如果我对我保留的那个测试数据集过拟合了怎么办？我仍然对每一个训练数据集使用相同的测试数据集。如果那个测试数据集也不真正代表实际情况呢？

还有一些 k 折交叉验证的变体，也会对此进行随机化。因此，你也可以每次随机选择训练数据集，并将不同的数据随机分配到不同的桶中进行测量。但通常，当人们谈论 k 折交叉验证时，他们指的是这种特定的技术，其中你保留一个桶用于测试，其余桶用于训练，并在构建每个模型时使用测试数据集评估所有训练数据集。

# 使用 scikit-learn 进行 k 折交叉验证的示例

幸运的是，scikit-learn 使这变得非常容易，甚至比普通的训练/测试更容易！进行 k 折交叉验证非常简单，所以你可能会选择这样做。

现在，在实践中，这一切是如何运作的是，你会有一个你想要调整的模型，以及该模型的不同变体，你可能想要对其进行微调的不同参数，对吧？

比如，多项式拟合的多项式程度。因此，想法是尝试模型的不同值，不同的变体，使用 k 折交叉验证对它们进行测量，并找到最小化与测试数据集的误差的值。这就是你的最佳选择。在实践中，你想使用 k 折交叉验证来衡量模型对测试数据集的准确性，并不断完善模型，尝试其中的不同值，尝试模型的不同变体，甚至可能是完全不同的模型，直到找到最大程度减少误差的技术，使用 k 折交叉验证。

让我们来看一个例子，看看它是如何工作的。我们将再次将其应用于我们的鸢尾花数据集，重新审视 SVC，并且我们将使用 k-fold 交叉验证来尝试一下，看看它是多么简单。实际上，让我们将 k-fold 交叉验证和训练/测试应用到实践中，使用一些真正的 Python 代码。你会发现它实际上非常容易使用，这是一件好事，因为这是一种你应该使用来衡量监督学习模型准确性和有效性的技术。

请继续打开`KFoldCrossValidation.ipynb`，如果愿意的话可以跟着做。我们将再次看看鸢尾花数据集；还记得我们在谈论降维时介绍过它吗？

为了让你记起来，鸢尾花数据集包含了 150 个鸢尾花的测量数据，每朵花都有其花瓣和萼片的长度和宽度。我们还知道每朵花属于 3 种不同的鸢尾花中的哪一种。这里的挑战是创建一个能够成功预测鸢尾花种类的模型，仅仅基于其花瓣和萼片的长度和宽度。所以，让我们继续做这件事。

我们将使用 SVC 模型。如果你还记得，这只是一种对数据进行分类的相当强大的方法。如果需要，可以查看相关部分来复习一下：

```py
import numpy as np 
from sklearn import cross_validation 
from sklearn import datasets 
from sklearn import svm 

iris = datasets.load_iris() 

# Split the iris data into train/test data sets with 
#40% reserved for testing 
X_train, X_test, y_train, y_test = cross_validation.train_test_split(iris.data, 
                                    iris.target, test_size=0.4, random_state=0) 

# Build an SVC model for predicting iris classifications 
#using training data 
clf = svm.SVC(kernel='linear', C=1).fit(X_train, y_train) 

# Now measure its performance with the test data 
clf.score(X_test, y_test) 

```

我们使用 scikit-learn 中的`cross_validation`库，首先进行传统的训练测试分割，只是一个单一的训练/测试分割，看看它的效果如何。

为此，我们有一个`train_test_split()`函数，使得这变得相当容易。这样的工作方式是，我们将一组特征数据输入到`train_test_split()`中。`iris.data`只包含每朵花的实际测量数据。`iris.target`基本上是我们要预测的东西。

在这种情况下，它包含了每朵花的所有种类。`test_size`表示我们想要训练与测试的百分比。因此，0.4 表示我们将随机提取 40%的数据进行测试，并使用 60%进行训练。这给我们带来的是 4 个数据集，基本上是一个用于训练的数据集和一个用于测试的数据集，分别用于特征数据和目标数据。因此，`X_train`最终包含了我们鸢尾花测量的 60%，而`X_test`包含了用于测试我们模型结果的测量的 40%。`y_train`和`y_test`包含了每个部分的实际种类。

然后我们继续构建一个 SVC 模型，用于预测鸢尾花的种类，只使用训练数据。我们使用线性核来拟合这个 SVC 模型，只使用训练的特征数据和训练的种类数据，也就是目标数据。我们将该模型称为`clf`。然后，我们在`clf`上调用`score()`函数，只是为了衡量它在我们的测试数据集上的表现。因此，我们将这个模型与我们为鸢尾花测量保留的测试数据集以及测试鸢尾花种类进行比分，看看它的表现如何：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/7d9b6519-0e08-4385-af2a-4dc643935313.jpg)

结果表明它表现得非常好！超过 96%的时间，我们的模型能够基于那些鸢尾花的测量结果，准确预测出它们的种类，即使是它之前从未见过的鸢尾花。所以这很酷！

但是，这是一个相当小的数据集，大约有 150 朵花，如果我没记错的话。因此，我们只使用 150 朵花的 60%进行训练，只使用 150 朵花的 40%进行测试。这些数字仍然相当小，所以我们仍然可能会过度拟合我们所做的特定训练/测试分割。因此，让我们使用 k-fold 交叉验证来防止这种情况发生。事实证明，使用 k-fold 交叉验证，即使它是一种更强大的技术，实际上比训练/测试更容易使用。所以，这很酷！那么，让我们看看它是如何工作的：

```py
# We give cross_val_score a model, the entire data set and its "real" values, and the number of folds: 
scores = cross_validation.cross_val_score(clf, iris.data, iris.target, cv=5) 

# Print the accuracy for each fold: 
print scores 

# And the mean accuracy of all 5 folds: 
print scores.mean() 

```

我们已经有了一个模型，即我们为这个预测定义的 SVC 模型，你所需要做的就是在`cross_validation`包上调用`cross_val_score()`。因此，您需要向这个函数传递一个给定类型的模型（`clf`），您拥有的所有测量数据集，也就是所有的特征数据（`iris.data`）和所有的目标数据（所有的物种），`iris.target`。

我想要 `cv=5`，这意味着它实际上会使用 5 个不同的训练数据集，同时保留 `1` 用于测试。基本上，它会运行 5 次，这就是我们需要做的全部。这将自动评估我们的模型针对整个数据集，分成五种不同的方式，并将结果返回给我们。

如果我们打印出来，它会给我们返回一个实际错误指标的列表，即每个迭代的错误指标，也就是每个折叠的错误指标。我们可以将这些平均起来，得到基于 k 折交叉验证的总体错误指标：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/705c48f3-a3b4-4d63-ae15-c4159c0e5c76.png)

当我们在 5 个折叠上进行时，我们会发现我们的结果甚至比我们想象的要好！98%的准确率。这非常棒！事实上，在几次运行中我们都获得了完美的准确率。这真是令人惊讶的事情。

现在让我们看看是否可以做得更好。我们之前使用了线性核，如果我们使用多项式核并变得更加花哨会怎样呢？那会是过拟合还是实际上更好地拟合了我们的数据？这取决于这些花瓣测量和实际物种之间是否实际上存在线性关系或多项式关系。所以，让我们试一试：

```py
clf = svm.SVC(kernel='poly', C=1).fit(X_train, y_train)
scores = cross_validation.cross_val_score(clf, iris.data, iris.target, cv=5)
print scores
print scores.mean()

```

我们将再次运行所有这些，使用相同的技术。但这次，我们使用多项式核。我们将将其拟合到我们的训练数据集上，而在这种情况下，拟合到哪里并不重要，因为`cross_val_score()`会为您不断重新运行它：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/705c48f3-a3b4-4d63-ae15-c4159c0e5c76.png)

事实证明，当我们使用多项式拟合时，最终得分甚至比我们原始运行的得分还要低。这告诉我们多项式核可能是过拟合的。当我们使用 k 折交叉验证时，它显示出的得分比线性核还要低。

这里的重要一点是，如果我们只使用了单一的训练/测试拆分，我们就不会意识到我们过拟合了。如果我们只是在这里进行了单一的训练/测试拆分，我们实际上会得到与线性核相同的结果。因此，我们可能会无意中过拟合我们的数据，并且甚至不知道我们没有使用 k 折交叉验证时。因此，这是 k 折交叉验证拯救的一个很好的例子，并警告您过拟合，而单一的训练/测试拆分可能无法发现。因此，请将其放入您的工具箱。

如果您想进一步尝试，可以尝试不同的次数。因此，您实际上可以指定不同的次数。多项式核的默认次数是 3 次，但您可以尝试不同的次数，可以尝试两次。

这样做会更好吗？如果你降到一次，基本上就会退化为线性核，对吧？所以，也许仍然存在多项式关系，也许只是二次多项式。试一试，看看你得到什么。这就是 k 折交叉验证。正如你所看到的，由于 scikit-learn 的便利性，它非常容易使用。这是衡量模型质量的重要方式。

# 数据清洗和归一化

现在，这是最简单的部分之一，但它可能是整本书中最重要的部分。我们将讨论清理输入数据，这将占用您大部分的时间。

您清理输入数据的程度以及了解原始输入数据将对您的结果质量产生巨大影响 - 甚至可能比您选择的模型或调整模型的效果更大。所以，请注意；这很重要！

清理原始输入数据通常是数据科学家工作中最重要且耗时的部分！

让我们谈谈数据科学的一个不便之真相，那就是你实际上大部分时间都在清理和准备数据，而相对较少的时间用于分析和尝试新的算法。这并不像人们经常说的那样光彩夺目。但是，这是一个非常重要的事情需要注意。

原始数据中可能会有很多不同的问题。送到你手上的原始数据会非常肮脏，以许多不同的方式被污染。如果你不处理它，它将会扭曲你的结果，并最终导致你的业务做出错误的决定。

如果最终发现你犯了一个错误，即摄入了大量错误数据却没有考虑清理它，然后基于这些结果告诉你的业务做一些后来被证明完全错误的事情，你将会陷入麻烦！所以，请注意！

有很多不同类型的问题和数据需要注意：

+   **异常值**：也许你的数据中有一些行为看起来有点奇怪，当你深入挖掘时，发现这些数据根本不应该被看到。一个很好的例子是，如果你在查看网络日志数据时，发现一个会话 ID 一次又一次地重复出现，并且以一个人类无法做到的速度进行某些操作。你可能看到的是一个机器人，一个在某处运行的脚本实际上在抓取你的网站。甚至可能是某种恶意攻击。但无论如何，你不希望这些行为数据影响你的模型，这些模型旨在预测真正使用你的网站的人类的行为。因此，观察异常值是一种识别在构建模型时可能需要剔除的数据类型的方法。

+   **缺失数据**：当数据不在那里时，你该怎么办？回到网络日志的例子，那一行可能有一个引荐者，也可能没有。如果没有怎么办？你是创建一个新的分类来表示缺失，还是完全丢弃那一行？你必须考虑在那里做什么才是正确的。

+   **恶意数据**：可能有人试图操纵你的系统，可能有人试图欺骗系统，你不希望这些人得逞。比如说你正在制作一个推荐系统。可能有人试图捏造行为数据以推广他们的新项目，对吧？因此，你需要警惕这种情况，并确保你能识别出操纵攻击或其他类型的攻击，过滤掉它们的结果，不让它们得逞。

+   **错误数据**：如果在某个系统中有软件错误，导致在某些情况下写入了错误的值，该怎么办？这种情况可能发生。不幸的是，你无法知道这一点。但是，如果你看到的数据看起来可疑，或者结果对你来说毫无意义，深入挖掘有时可以发现潜在的错误，导致错误数据首先被写入。也许在某个地方没有正确地组合事物。也许会话没有在整个会话期间保持。例如，人们可能在浏览网站时丢失他们的会话 ID，并获得新的会话 ID。

+   无关数据：这里有一个非常简单的例子。也许你只对来自纽约市的人的数据感兴趣，或者出于某种原因。在这种情况下，来自世界其他地方的人的所有数据对于你想要找出的内容都是无关的。你首先要做的就是抛弃所有这些数据，并限制你的数据，将其减少到你真正关心的数据。

+   不一致的数据：这是一个巨大的问题。例如，在地址中，人们可以用许多不同的方式写相同的地址：他们可能缩写街道，也可能不缩写街道，他们可能根本不在街道名称后面加上“街”。他们可能以不同的方式组合行，可能拼写不同的东西，可能在美国使用邮政编码或美国的邮政编码加 4 位，可能在上面有一个国家，也可能没有国家。你需要想办法弄清楚你看到的变化是什么，以及如何将它们全部规范化在一起。

+   也许我在研究有关电影的数据。一部电影在不同国家可能有不同的名称，或者一本书在不同国家可能有不同的名称，但它们意思相同。因此，你需要注意这些地方，需要对数据进行规范化处理，同样的数据可能以许多不同的方式表示，你需要将它们组合在一起以获得正确的结果。

+   格式化：这也可能是一个问题；事物可能格式不一致。以日期为例：在美国，我们总是按月、日、年（MM/DD/YY）的顺序，但在其他国家，他们可能按日、月、年（DD/MM/YY）的顺序，谁知道呢。你需要注意这些格式上的差异。也许电话号码的区号周围有括号，也许没有；也许数字的每个部分之间有破折号，也许没有；也许社会保障号码有破折号，也许没有。这些都是你需要注意的事情，你需要确保格式上的变化不会在处理过程中被视为不同的实体或不同的分类。

因此，有很多需要注意的事情，前面的列表只是需要注意的主要事项。记住：垃圾进，垃圾出。你的模型只有你给它的数据那么好，这是极其真实的！如果你给它大量干净的数据，甚至一个非常简单的模型也可以表现得非常好，而且实际上可能会胜过一个更复杂的模型在一个更脏的数据集上。

因此，确保你有足够的数据和高质量的数据通常是大部分工作。你会惊讶于现实世界中一些最成功的算法有多简单。它们之所以成功，仅仅是因为输入的数据质量和数量。你并不总是需要花哨的技术来获得好的结果。通常情况下，你的数据的质量和数量同其他任何因素一样重要。

始终质疑你的结果！你不希望在得到不喜欢的结果时才回头查看你的输入数据中的异常。这将在你的结果中引入一种无意识的偏见，你让你喜欢或期望的结果不经质疑地通过了，对吧？你需要一直质疑事物，以确保你一直留意这些事情，因为即使你找到了一个你喜欢的结果，如果结果是错误的，它仍然是错误的，它仍然会让你的公司朝错误的方向发展。这可能会在以后给你带来麻烦。

举个例子，我有一个名为 No-Hate News 的网站。这是一个非营利性网站，所以我并不是在告诉你它来赚钱。假设我只想找到我拥有的这个网站上最受欢迎的页面。这听起来是一个相当简单的问题，不是吗？我应该只需要浏览我的网络日志，计算每个页面的点击次数，并对它们进行排序，对吧？有多难呢？嗯，事实证明这真的很难！所以，让我们深入探讨这个例子，看看为什么它很困难，并看看一些必须进行的真实世界数据清理的例子。

# 清理网络日志数据

我们将展示清理数据的重要性。我有一些来自我拥有的小网站的网络日志数据。我们只是尝试找到该网站上最受欢迎的页面。听起来很简单，但正如您将看到的，实际上相当具有挑战性！所以，如果您想跟着做，`TopPages.ipynb`是我们在这里工作的笔记本。让我们开始吧！

我实际上有一个从我的实际网站中获取的访问日志。这是 Apache 的真实 HTTP 访问日志，包含在您的书籍材料中。所以，如果您想参与其中，请确保更新路径，将访问日志移动到您保存书籍材料的位置：

```py
logPath = "E:\\sundog-consult\\Packt\\DataScience\\access_log.txt" 

```

# 在网络日志上应用正则表达式

所以，我去网上找了下面的一小段代码，它可以将 Apache 访问日志行解析成一堆字段：

```py
format_pat= re.compile( 
    r"(?P<host>[\d\.]+)\s" 
    r"(?P<identity>\S*)\s" 
    r"(?P<user>\S*)\s" 
    r"\[(?P<time>.*?)\]\s" 
    r'"(?P<request>.*?)"\s' 
    r"(?P<status>\d+)\s" 
    r"(?P<bytes>\S*)\s" 
    r'"(?P<referer>.*?)"\s' 
    r'"(?P<user_agent>.*?)"\s*' 
) 

```

这段代码包含主机、用户、时间、实际页面请求、状态、引用者、`user_agent`（表示用于查看此页面的浏览器）。它构建了一个称为正则表达式的东西，我们使用`re`库来使用它。这基本上是一种在大字符串上进行模式匹配的非常强大的语言。因此，我们可以将这个正则表达式应用到我们访问日志的每一行上，并自动将访问日志行中的信息部分分组到这些不同的字段中。让我们继续运行这个。

在这里要做的明显的事情是，让我们编写一个小脚本，计算我们遇到的每个 URL 被请求的次数，并记录它被请求的次数。然后我们可以对列表进行排序，得到我们的热门页面，对吧？听起来足够简单！

因此，我们将构建一个名为`URLCounts`的小 Python 字典。我们将打开我们的日志文件，对于每一行，我们将应用我们的正则表达式。如果它实际上返回了成功匹配我们试图匹配的模式，我们会说，好的，这看起来像是我们访问日志中的一个不错的行。

让我们从中提取请求字段，也就是浏览器实际请求的实际 HTTP 请求的页面。我们将把它分成三个部分：它包括一个动作，比如 get 或 post；实际请求的 URL；以及使用的协议。在得到这些信息后，我们可以看看该 URL 是否已经存在于我的字典中。如果是，我将增加该 URL 已经被遇到的次数`1`；否则，我将为该 URL 引入一个新的字典条目，并将其初始化为值`1`。我对日志中的每一行都这样做，以数字逆序排序结果，并将其打印出来：

```py
URLCounts = {}
with open(logPath, "r") as f:
    for line in (l.rstrip() for l in f):
        match= format_pat.match(line)
        if match:
            access = match.groupdict()
            request = access['request']
            (action, URL, protocol) = request.split()
            if URLCounts.has_key(URL):
                URLCounts[URL] = URLCounts[URL] + 1
            else:
                URLCounts[URL] = 1
results = sorted(URLCounts, key=lambda i: int(URLCounts[i]), reverse=True)

for result in results[:20]:
    print result + ": " + str(URLCounts[result])

```

所以，让我们继续运行：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/5299efb0-51ac-451c-b6ac-43d72797555d.png)

哎呀！我们遇到了一个大错误。它告诉我们，我们需要多于`1`个值来解包。所以显然，我们得到了一些不包含动作、URL 和协议的请求字段，而包含其他内容。

让我们看看那里发生了什么！所以，如果我们打印出所有不包含三个项目的请求，我们就会看到实际显示的内容。所以，我们要做的是一个类似的小代码片段，但我们要在请求字段上实际执行拆分，并打印出我们没有得到预期的三个字段的情况。

```py
URLCounts = {}

with open(logPath, "r") as f:
    for line in (l.rstrip() for l in f):
        match= format_pat.match(line)
        if match:
            access = match.groupdict()
            request = access['request']
            fields = request.split()
            if (len(fields) != 3):
                print fields

```

让我们看看实际上有什么：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/2e3d1bcb-e929-4fa6-a80f-8616c134b54d.png)

所以，我们有一堆空字段。这是我们的第一个问题。但是，然后我们有第一个字段是完全垃圾。谁知道那是从哪里来的，但显然是错误的数据。好吧，让我们修改我们的脚本。

# 修改一 - 过滤请求字段

我们实际上会丢弃任何没有预期的 3 个字段的行。这似乎是一个合理的做法，因为事实上这确实包含了完全无用的数据，这样做并不会让我们错过任何东西。所以，我们将修改我们的脚本来做到这一点。我们在实际尝试处理之前引入了一个`if (len(fields) == 3)`行。我们将运行它：

```py
URLCounts = {}

with open(logPath, "r") as f:
    for line in (l.rstrip() for l in f):
        match= format_pat.match(line)
        if match:
            access = match.groupdict()
            request = access['request']
            fields = request.split()
            if (len(fields) == 3):
                URL = fields[1]
                if URLCounts.has_key(URL):
                    URLCounts[URL] = URLCounts[URL] + 1
                else:
                    URLCounts[URL] = 1

results = sorted(URLCounts, key=lambda i: int(URLCounts[i]), reverse=True)

for result in results[:20]:
    print result + ": " + str(URLCounts[result])

```

嘿，我们得到了一个结果！

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/0f8ec1d7-97ce-4c7c-b1ed-ff868e626183.png)

但这看起来并不像是我网站上的热门页面。记住，这是一个新闻网站。所以，我们得到了一堆 PHP 文件点击，那是 Perl 脚本。那是怎么回事？我们的最佳结果是这个`xmlrpc.php`脚本，然后是`WP_login.php`，然后是主页。所以，没有什么用。然后是`robots.txt`，然后是一堆 XML 文件。

你知道，当我后来调查这个问题时，结果发现我的网站实际上受到了恶意攻击；有人试图侵入。这个`xmlrpc.php`脚本是他们试图猜测我的密码的方式，他们试图使用登录脚本登录。幸运的是，在他们真正进入这个网站之前，我就把他们关掉了。

这是一个恶意数据被引入到我的数据流中，我必须过滤掉的例子。所以，通过观察，我们可以看到这次恶意攻击不仅查看了 PHP 文件，而且还试图执行一些东西。它不仅仅是一个 get 请求，它是对脚本的 post 请求，实际上试图在我的网站上执行代码。

# 修改二 - 过滤 post 请求

现在，我知道我关心的数据，你知道我试图弄清楚的事情的精神是，人们从我的网站获取网页。所以，我可以合理地做的一件事是，过滤掉这些日志中不是 get 请求的任何内容。所以，让我们接着做这个。我们将再次检查我们的请求字段中是否有三个字段，然后我们还将检查操作是否是 get。如果不是，我们将完全忽略该行：

```py
URLCounts = {}

with open(logPath, "r") as f:
    for line in (l.rstrip() for l in f):
        match= format_pat.match(line)
        if match:
            access = match.groupdict()
            request = access['request']
            fields = request.split()
            if (len(fields) == 3):
                (action, URL, protocol) = fields
                if (action == 'GET'):
                    if URLCounts.has_key(URL):
                        URLCounts[URL] = URLCounts[URL] + 1
                    else:
                        URLCounts[URL] = 1

results = sorted(URLCounts, key=lambda i: int(URLCounts[i]), reverse=True)

for result in results[:20]:
    print result + ": " + str(URLCounts[result])

```

现在我们应该更接近我们想要的东西了，以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/49ea2d9a-f169-429a-8873-46b8e18fbbf0.png)

是的，这开始看起来更合理了。但是，它仍然没有真正通过合理性检查。这是一个新闻网站；人们去那里是为了阅读新闻。他们真的在看我那个只有几篇文章的小博客吗？我不这么认为！这似乎有点可疑。所以，让我们深入一点，看看到底是谁在看那些博客页面。如果你真的去查看那个文件并手动检查，你会发现很多这些博客请求实际上根本没有任何用户代理。它们只有一个用户代理是`-`，这是非常不寻常的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/b4326ae3-6106-4c4d-8aff-af6acc33730a.png)

如果一个真正的人类和一个真正的浏览器试图获取这个页面，它会显示类似 Mozilla、Internet Explorer、Chrome 或其他类似的东西。所以，看起来这些请求来自某种刮取器。同样，可能是一种恶意流量，没有标识出是谁。

# 修改三 - 检查用户代理

也许，我们应该也看看用户代理，看看这些是不是真正的人在发出请求。让我们继续打印出我们遇到的所有不同的用户代理。所以，按照实际总结我们看到的不同 URL 的代码精神，我们可以查看我们看到的所有不同用户代理，并按照日志中最流行的`user_agent`字符串对它们进行排序：

```py
UserAgents = {}

with open(logPath, "r") as f:
    for line in (l.rstrip() for l in f):
        match= format_pat.match(line)
        if match:
            access = match.groupdict()
            agent = access['user_agent']
            if UserAgents.has_key(agent):
                UserAgents[agent] = UserAgents[agent] + 1
            else:
                UserAgents[agent] = 1

results = sorted(UserAgents, key=lambda i: int(UserAgents[i]), reverse=True)

for result in results:
    print result + ": " + str(UserAgents[result])

```

我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/bd809047-195b-4c82-b51a-b55840e01965.png)

你可以看到大部分看起来都是合法的。所以，如果是一个刮取器，而在这种情况下实际上是一次恶意攻击，但他们实际上是在假装成一个合法的浏览器。但这个破折号`user_agent`也经常出现。所以，我不知道那是什么，但我知道那不是一个真正的浏览器。

我看到的另一件事是有很多来自蜘蛛、网络爬虫的流量。所以，有百度，这是中国的搜索引擎，有 Googlebot 在爬网页。我想我也在那里看到了 Yandex，一个俄罗斯的搜索引擎。所以，我们的数据被很多只是为了挖掘我们网站的搜索引擎目的而爬行的爬虫所污染。再次强调，这些流量不应计入我分析的预期目的，即查看实际人类在我的网站上查看的页面。这些都是自动脚本。

# 过滤蜘蛛/机器人的活动

好了，这变得有点棘手。仅仅根据用户字符串来识别蜘蛛或机器人没有真正好的方法。但我们至少可以试一试，过滤掉任何包含“bot”这个词的东西，或者来自我的缓存插件的可能提前请求页面的东西。我们还将去除我们的朋友单破折号。所以，我们将再次完善我们的脚本，除了其他一切，还要去除任何看起来可疑的 UserAgents：

```py
URLCounts = {}

with open(logPath, "r") as f:
    for line in (l.rstrip() for l in f):
        match= format_pat.match(line)
        if match:
            access = match.groupdict()
            agent = access['user_agent']
            if (not('bot' in agent or 'spider' in agent or 
                    'Bot' in agent or 'Spider' in agent or
                    'W3 Total Cache' in agent or agent =='-')):
                request = access['request']
                fields = request.split()
                if (len(fields) == 3):
                    (action, URL, protocol) = fields
                    if (action == 'GET'):
                        if URLCounts.has_key(URL):
                            URLCounts[URL] = URLCounts[URL] + 1
                        else:
                            URLCounts[URL] = 1

results = sorted(URLCounts, key=lambda i: int(URLCounts[i]), reverse=True)

for result in results[:20]:
    print result + ": " + str(URLCounts[result])

```

```py
URLCounts = {}

with open(logPath, "r") as f:
    for line in (l.rstrip() for l in f):
        match= format_pat.match(line)
        if match:
            access = match.groupdict()
            agent = access['user_agent']
            if (not('bot' in agent or 'spider' in agent or 
                    'Bot' in agent or 'Spider' in agent or
                    'W3 Total Cache' in agent or agent =='-')):
                request = access['request']
                fields = request.split()
                if (len(fields) == 3):
                    (action, URL, protocol) = fields
                    if (URL.endswith("/")):
                        if (action == 'GET'):
                            if URLCounts.has_key(URL):
                                URLCounts[URL] = URLCounts[URL] + 1
                            else:
                                URLCounts[URL] = 1

results = sorted(URLCounts, key=lambda i: int(URLCounts[i]), reverse=True)

for result in results[:20]:
    print result + ": " + str(URLCounts[result])

```

我们得到了什么？

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/c8f00b0c-8e18-4276-8046-548376597f18.png)

好了，我们开始了！前两个条目看起来更合理了，主页最受欢迎，这是预料之中的。奥兰多头条也很受欢迎，因为我比其他人更多地使用这个网站，而且我住在奥兰多。但之后，我们得到了一堆根本不是网页的东西：一堆脚本，一堆 CSS 文件。这些都不是网页。

# 修改四 - 应用特定于网站的过滤器

我只需应用一些关于我的网站的知识，我碰巧知道我的网站上所有合法的页面都以它们的 URL 结尾斜杠。所以，让我们继续修改一下，去掉任何不以斜杠结尾的东西：

```py
URLCounts = {}

with open (logPath, "r") as f:
    for line in (l.rstrip() for 1 in f):
        match= format_pat.match(line)
        if match:
            access = match.groupdict()
            agent = access['user_agent']
            if (not('bot' in agent or 'spider' in agent or
                    'Bot' in agent or 'Spider' in agent or
                    'W3 Total Cache' in agent or agent =='-')):
                request = access['request']
                fields = request.split()
                if (len(fields) == 3):
                    (action, URL, protocol) = fields
                    if (URL.endswith("/")):
                        if (action == 'GET'):
                            if URLCounts.has_key(URL):
                                URLCounts[URL] = URLCounts[URL] + 1
                            else:
                                URLCounts[URL] = 1

results = sorted(URLCounts, key=lambda i: int(URLCounts[i]), reverse=True)

for result in results[:20]:
    print result + ": " + str(URLCounts[result])

```

让我们运行一下！

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/a5aa652b-c518-403f-821e-576828f6d14a.png)

最后，我们得到了一些看起来合理的结果！看起来，从我小小的 No-Hate News 网站上实际人类请求的顶级页面是主页，然后是`orlando-headlines`，然后是世界新闻，然后是漫画，然后是天气，然后是关于页面。所以，这开始看起来更合理了。

如果你再深入一点，你会发现这个分析还存在问题。例如，那些 feed 页面仍然来自只是想从我的网站获取 RSS 数据的机器人。所以，这是一个很好的寓言，说明一个看似简单的分析需要大量的预处理和清理源数据，才能得到任何有意义的结果。

再次确保你在清理数据时所做的事情是有原则的，而不是只是挑选与你先入为主观念不符的问题。所以，始终质疑你的结果，始终查看你的源数据，并寻找其中的奇怪之处。

# 网络日志数据的活动

好了，如果你想再深入研究一下，你可以解决那个 feed 问题。继续去除包括 feed 的东西，因为我们知道那不是一个真正的网页，只是为了熟悉代码。或者，更仔细地查看日志，了解那些 feed 页面实际来自哪里。

也许有一种更好、更健壮的方法来识别那些流量作为一个更大的类别。所以，随意尝试一下。但我希望你已经学到了教训：数据清理 - 非常重要，而且会花费你大量的时间！

所以，令人惊讶的是，要在一个简单的问题上获得一些合理的结果，比如“我的网站上哪些页面被浏览次数最多？”竟然是多么困难。你可以想象，如果为了解决这样一个简单的问题需要做这么多工作，那么想想脏数据可能会如何影响更复杂问题和复杂算法的结果。

非常重要的是要了解你的数据源，查看它，查看它的代表样本，确保你了解数据输入系统。始终质疑你的结果，并将其与原始数据源联系起来，看看可疑的结果是从哪里来的。

# 数值数据的标准化

这是一个非常快速的部分：我只是想提醒你关于标准化数据的重要性，确保你的各种输入特征数据在同一尺度上，并且是可比较的。有时很重要，有时不重要。但是，你必须意识到什么时候重要。只要记住这一点，因为有时如果你不这样做，它会影响你的结果的质量。

有时候模型将基于几个不同的数值属性。如果你记得多变量模型，我们可能有不同的汽车属性，它们可能不是直接可比较的测量。或者，例如，如果我们正在研究年龄和收入之间的关系，年龄可能从 0 到 100 不等，但以美元计的收入可能从 0 到数十亿不等，根据货币的不同，范围可能更大！有些模型可以接受这种情况。

如果你在做回归，通常这不是什么大问题。但是，其他模型在这些值被缩放到一个公共尺度之前表现得不那么好。如果你不小心，你可能会发现一些属性比其他属性更重要。也许收入最终会比年龄更重要，如果你试图将这两个值作为模型中可比较的值来处理的话。

这也可能导致属性的偏差，这也可能是一个问题。也许你的数据集中的一组数据是倾斜的，你知道，有时你需要对事物进行标准化，而不仅仅是将其标准化到 0 到最大值的范围。没有固定的规则来决定何时应该做这种标准化。我只能说的是，无论你使用什么技术，都要始终阅读文档。

例如，在 scikit-learn 中，他们的 PCA 实现有一个`whiten`选项，它会自动为你标准化你的数据。你应该使用它。它还有一些预处理模块可用，可以自动为你标准化和缩放事物。

还要注意文本数据实际上应该以数字或顺序方式表示。如果你有`yes`或`no`的数据，你可能需要将其转换为`1`或`0`，并以一致的方式进行转换。所以再次，只需阅读文档。大多数技术在使用原始、未标准化的数据时都能很好地工作，但在第一次使用新技术之前，只需阅读文档，了解输入是否应该首先进行缩放、标准化或白化。如果是这样，scikit-learn 可能会让你很容易地做到，你只需要记得这样做！在完成后不要忘记重新缩放你的结果，如果你正在缩放输入数据的话。

如果你想要解释你得到的结果，有时你需要在完成后将它们重新缩放到原始范围。如果你在输入模型之前缩放事物，甚至可能使它们倾向于某个特定数量，确保在向某人呈现这些结果之前，你将它们重新缩放和去偏。否则它们就毫无意义了！还有一个小提醒，一个寓言，你应该始终检查是否应该在将数据传递到给定模型之前对其进行标准化或白化。

本节与运动无关；这只是我想让你记住的事情。我只是想强调一下。有些算法需要白化或标准化，有些则不需要。所以，请务必阅读文档！如果您确实需要对输入算法的数据进行标准化，它通常会告诉您如何做，而且会使这一过程变得非常容易。请注意这一点！

# 检测异常值

真实世界数据的一个常见问题是异常值。您总会有一些奇怪的用户，或者一些奇怪的代理，它们会污染您的数据，表现出与典型用户不同的异常和非典型行为。它们可能是合法的异常值；它们可能是由真实人员而不是某种恶意流量或虚假数据引起的。因此，有时候适当地将它们移除，有时候则不适当。确保您负责任地做出这个决定。因此，让我们深入一些处理异常值的示例。

例如，如果我正在进行协同过滤，并且试图进行电影推荐之类的事情，您可能会有一些超级用户，他们观看了每部电影，并对每部电影进行了评分。他们可能对每个人的推荐产生了不成比例的影响。

您真的不希望少数人在您的系统中拥有如此大的权力。因此，这可能是一个例子，您可以合理地过滤掉异常值，并通过他们实际放入系统的评分数量来识别它们。或者，异常值可能是那些没有足够评分的人。

我们可能正在查看网络日志数据，就像我们在之前的示例中看到的那样，当我们进行数据清理时，异常值可能会告诉您，从一开始您的数据就存在很大问题。这可能是恶意流量，可能是机器人，或者其他应该被丢弃的代理，它们并不代表您试图建模的实际人类。

如果有人真的想知道美国的平均收入（而不是中位数），您不应该仅仅因为您不喜欢他而丢弃唐纳德·特朗普。事实是，即使他的数十亿美元并没有改变中位数，但它们会推高平均数。因此，不要通过丢弃异常值来篡改您的数据。但如果它与您首先尝试建模的内容不一致，那么就丢弃异常值。

现在，我们如何识别异常值？嗯，还记得我们的老朋友标准差吗？我们在这本书的早期就讨论过这个问题。这是一个非常有用的工具，用于检测异常值。您可以以一种非常有原则的方式计算应该具有更或多或少正态分布的数据集的标准差。如果您看到一个数据点超出了一个或两个标准差，那么您就有一个异常值。

记住，我们之前也谈到了箱线图和须状图，它们也有一种内置的方法来检测和可视化异常值。这些图表将异常值定义为位于 1.5 倍四分位距之外的值。

您选择什么倍数？嗯，您必须运用常识，您知道，没有硬性规定什么是异常值。您必须查看您的数据，用眼睛观察，查看分布，查看直方图。看看是否有明显的异常值，并在丢弃它们之前了解它们是什么。

# 处理异常值

因此，让我们看一些示例代码，看看您如何在实践中处理异常值。让我们玩弄一些异常值。这是一个非常简单的部分。实际上是一点点复习。如果您想跟着做，我们在`Outliers.ipynb`中。所以，如果您愿意，请打开它：

```py
import numpy as np

incomes = np.random.normal(27000, 15000, 10000)
incomes = np.append(incomes, [1000000000])

import matplotlib.pyplot as plt
plt.hist(incomes, 50)
plt.show()

```

我们在书的早期做过非常类似的事情，那里我们创建了美国收入分布的假直方图。我们要做的是从这里开始，用一个年收入平均为 27000 美元，标准偏差为 15000 美元的正态分布收入。我将创建 10000 个在该分布中有收入的假美国人。顺便说一句，这完全是虚构的数据，尽管它与现实并不那么遥远。

然后，我要插入一个异常值 - 叫它唐纳德·特朗普，他有十亿美元。我们将把这个家伙插入到我们数据集的末尾。所以，我们有一个围绕着 27000 美元的正态分布数据集，然后我们要在最后插入唐纳德·特朗普。

我们将继续将其绘制为直方图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/206367db-3697-4fa7-9c12-35da52e11457.png)

哇！这并不是很有帮助！我们把全国其他人的整个正态分布挤进了直方图的一个桶里。另一方面，我们把唐纳德·特朗普放在右边，以十亿美元搞乱了整个事情。

另一个问题是，如果我试图回答典型美国人赚多少钱这个问题。如果我用平均值来尝试弄清楚这个问题，那将不会是一个很好的、有用的数字：

```py
incomes.mean ()

```

前面代码的输出如下：

```py
126892.66469341301

```

唐纳德·特朗普独自把这个数字推高到了 126000 美元，而我知道，不包括唐纳德·特朗普的正态分布数据的真实均值只有 27000 美元。所以，在这种情况下，正确的做法是使用中位数而不是平均值。

但是，假设我们不得不出于某种原因使用平均值，正确的处理方式是排除像唐纳德·特朗普这样的异常值。所以，我们需要弄清楚如何识别这些人。嗯，你可以随意选择一个截断点，然后说，“我要抛弃所有亿万富翁”，但这不是一个很有原则的做法。10 亿是从哪里来的？

这只是我们如何计算数字的一些意外。所以，更好的做法是实际测量数据集的标准偏差，并将异常值定义为距离平均值的某个标准偏差的倍数。

接下来是我写的一个小函数，它就是`reject_outliers()`：

```py
def reject_outliers(data): 
    u = np.median(data) 
    s = np.std(data) 
    filtered = [e for e in data if (u - 2 * s < e < u + 2 * s)] 
    return filtered 

filtered = reject_outliers(incomes) 

plt.hist(filtered, 50) 
plt.show() 

```

它接收一个数据列表并找到中位数。它还找到该数据集的标准偏差。所以，我对此进行了过滤，只保留了在我的数据中距离中位数两个标准偏差之内的数据点。所以，我可以在我的收入数据上使用这个方便的`reject_outliers()`函数，自动剔除奇怪的异常值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/2e37aa6a-afb1-4ae4-97a3-2af86b800d90.png)

果然，它奏效了！现在我得到了一个更漂亮的图表，排除了唐纳德·特朗普，聚焦于中心的更典型的数据集。所以，非常酷！

所以，这是一个识别异常值并自动删除它们或以任何你认为合适的方式处理它们的例子。记住，一定要以原则的方式做这件事。不要只是因为它们不方便就抛弃异常值。要理解它们来自何处，以及它们实际上如何影响你试图在精神上衡量的事物。

顺便说一句，现在我们的平均值也更有意义了；现在我们已经摆脱了那个异常值，它更接近应该是的 27000。

# 异常值的活动

所以，如果你想玩玩这个，你知道，就像我通常要求你做的那样，试着用标准偏差的不同倍数，试着添加更多的异常值，试着添加不那么像唐纳德·特朗普那样的异常值。你知道，只是编造一些额外的假数据，然后玩弄一下，看看你是否能成功地识别出这些人。

就是这样！异常值；非常简单的概念。所以，这是一个通过查看标准偏差来识别异常值的示例，只需查看与平均值或中位数相差的标准偏差的数量。实际上，中位数可能是一个更好的选择，因为异常值可能会使平均值产生偏差，对吧？因此，使用标准偏差是一种比仅仅选择一些任意截断更有原则的识别异常值的方法。再次强调，您需要决定如何处理这些异常值。您实际上想要衡量什么？是否适合实际丢弃它们？所以，请记住这一点！

# 总结

在本章中，我们谈到了在偏差和方差之间取得平衡以及最小化误差的重要性。接下来，我们了解了 k 折交叉验证的概念以及如何在 Python 中实现它以防止过拟合。我们学到了在处理数据之前清洁数据和对数据进行归一化的重要性。然后我们看到了一个示例，用于确定网站的热门页面。在第九章中，《Apache Spark - 大数据上的机器学习》，我们将学习如何使用 Apache Spark 进行大数据上的机器学习。


# 第九章：Apache Spark - 大数据上的机器学习

到目前为止，在这本书中，我们已经讨论了许多通用的数据挖掘和机器学习技术，你可以在数据科学职业中使用，但它们都在你的桌面上运行。因此，你只能使用诸如 Python 和 scikit-learn 等技术来处理单台机器可以处理的数据量。

现在，每个人都在谈论大数据，很可能你正在为一家实际上有大数据需要处理的公司工作。大数据意味着你实际上无法控制所有数据，你无法在一个系统上处理所有数据。你需要使用整个云、一组计算资源的集群来计算它。这就是 Apache Spark 的用武之地。Apache Spark 是一个非常强大的工具，用于管理大数据，并在大规模数据集上进行机器学习。到本章结束时，你将对以下主题有深入的了解：

+   安装和使用 Spark

+   **弹性分布式数据集**（**RDDs**）

+   **MLlib**（**机器学习库**）

+   Spark 中的决策树

+   Spark 中的 K 均值聚类

# 安装 Spark

在这一部分，我将帮助你使用 Apache Spark，并向你展示一些实际使用 Apache Spark 解决与本书中过去在单台计算机上解决的相同问题的示例。我们需要做的第一件事是在你的计算机上设置 Spark。因此，我们将在接下来的几节中为你介绍如何做到这一点。这是相当简单的事情，但有一些需要特别注意的地方。所以，不要只是跳过这些部分；有一些东西你需要特别注意，才能成功地运行 Spark，尤其是在 Windows 系统上。让我们在你的系统上设置 Apache Spark，这样你就可以真正地投入其中并开始尝试一些东西。

我们现在将在你自己的桌面上运行这个。但是，我们在本章中要编写的相同程序可以在实际的 Hadoop 集群上运行。因此，你可以将我们正在编写并在 Spark 独立模式下在你的桌面上运行的这些脚本，实际上从实际的 Hadoop 集群的主节点上运行它们，然后让它扩展到整个 Hadoop 集群的强大处理大规模数据集的能力。即使我们要在你自己的计算机上本地运行这些东西，也要记住这些相同的概念也可以扩展到在集群上运行。

# 在 Windows 上安装 Spark

在 Windows 上安装 Spark 涉及几个步骤，我们将在这里为你逐步介绍。我假设你在 Windows 上，因为大多数人在家里使用这本书。我们稍后会谈一下如何处理其他操作系统。如果你已经熟悉在计算机上安装东西和处理环境变量，那么你可以使用以下简短的提示表并开始操作。如果你对 Windows 内部不太熟悉，我将在接下来的几节中逐步为你介绍。以下是那些 Windows 专家的快速步骤：

1.  **安装 JDK**：你需要首先安装 JDK，即 Java 开发工具包。如果需要，你可以直接去 Sun 的网站下载并安装。我们需要 JDK，因为即使在这门课程中我们将使用 Python 进行开发，但在底层，它会被转换为 Scala 代码，而 Spark 就是用 Scala 原生开发的。而 Scala 又是在 Java 解释器之上运行的。因此，为了运行 Python 代码，你需要一个 Scala 系统，这将作为 Spark 的一部分默认安装。此外，我们需要 Java，或者更具体地说，需要 Java 的解释器来实际运行那些 Scala 代码。就像是一个技术层的蛋糕。

1.  **安装 Python**：显然，你需要 Python，但如果你已经阅读到这本书的这一部分，你应该已经设置好了 Python 环境，希望是 Enthought Canopy。所以，我们可以跳过这一步。

1.  **安装 Hadoop 的预编译版本的 Spark**：幸运的是，Apache 网站提供了预编译版本的 Spark，可以直接运行，已经为最新的 Hadoop 版本进行了预编译。您不需要构建任何东西，只需将其下载到计算机上并放在正确的位置，大部分情况下就可以使用了。

1.  **创建 conf/log4j.properties 文件**：我们有一些配置要处理。我们想要做的一件事是调整警告级别，以便在运行作业时不会收到大量警告信息。我们将介绍如何做到这一点。基本上，您需要重命名一个属性文件，然后在其中调整错误设置。

1.  **添加 SPARK_HOME 环境变量**：接下来，我们需要设置一些环境变量，以确保您可以从任何路径运行 Spark。我们将添加一个指向安装 Spark 的 SPARK_HOME 环境变量，然后将`%SPARK_HOME%\bin`添加到系统路径中，这样当您运行 Spark Submit、PySpark 或其他 Spark 命令时，Windows 就知道在哪里找到它。

1.  **设置 HADOOP_HOME 变量**：在 Windows 上，我们还需要做一件事，那就是设置`HADOOP_HOME`变量，因为即使在独立系统上不使用 Hadoop，它也会期望找到 Hadoop 的一小部分。

1.  **安装 winutils.exe**：最后，我们需要安装一个名为`winutils.exe`的文件。本书的资源中有`winutils.exe`的链接，您可以从那里获取。

如果您想更详细地了解步骤，可以参考接下来的部分。

# 在其他操作系统上安装 Spark

关于在其他操作系统上安装 Spark 的快速说明：基本上，这些步骤也适用于它们。主要区别在于如何在系统上设置环境变量，以便在您登录时自动应用。这将因操作系统而异。macOS 的做法与各种 Linux 的做法不同，因此您至少需要稍微熟悉使用 Unix 终端命令提示符，以及如何操纵您的环境来做到这一点。但是，大多数已经掌握这些基本原理的 macOS 或 Linux 用户都不需要`winutils.exe`。因此，这些是在不同操作系统上安装的主要区别。

# 安装 Java 开发工具包

要安装 Java 开发工具包，返回浏览器，打开一个新标签页，然后搜索`jdk`（Java 开发工具包的简称）。这将带您到 Oracle 网站，从那里您可以下载 Java。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/dfda3f71-6e92-47de-8042-5809c986c13b.png)

在 Oracle 网站上，点击 JDK DOWNLOAD。现在，点击 Accept License Agreement，然后您可以选择适用于您操作系统的下载选项：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/874e8bfe-a3b6-413a-a33f-c477b3acb6f3.png)

对我来说，这将是 Windows 64 位，等待 198MB 的好东西下载：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/4fa3b0cf-a3f7-4032-89e9-81b98807069a.png)

下载完成后，找到安装程序并运行它。请注意，我们不能在 Windows 安装程序中接受默认设置。因此，这是一个特定于 Windows 的解决方法，但在撰写本书时，当前版本的 Spark 是 2.1.1，结果表明 Spark 2.1.1 在 Windows 上与 Java 存在问题。问题在于，如果您将 Java 安装到带有空格的路径中，它将无法工作，因此我们需要确保 Java 安装到没有空格的路径中。这意味着即使您已经安装了 Java，也不能跳过此步骤，所以让我向您展示如何做到这一点。在安装程序上，点击下一步，您将看到如下屏幕，它默认要安装到`C:\Program Files\Java\jdk`路径，无论版本是什么：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/e23f5481-70e9-419a-a294-9d84965a3314.png)

`Program Files`路径中的空格会引起麻烦，因此让我们单击“更改...”按钮并安装到`c:\jdk`，一个简单的路径，易于记忆，并且其中没有空格：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/b84c94ed-6ede-43cb-82cb-fdee49f881b5.png)

现在，它还希望安装 Java 运行时环境，因此为了安全起见，我也将其安装到没有空格的路径。

在 JDK 安装的第二步，我们应该在屏幕上看到这个：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/7023d123-557d-4ad3-afcc-126c9ca354e0.png)

我也将更改目标文件夹，并为其创建一个名为`C:\jre`的新文件夹：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/05f43aab-96ee-4ed9-acbe-e6c5323e0a8e.png)

好了，安装成功。哇呼！

现在，您需要记住我们安装 JDK 的路径，我们的情况下是`C:\jdk`。我们还有一些步骤要走。接下来，我们需要安装 Spark 本身。

# 安装 Spark

让我们回到一个新的浏览器选项卡，转到[spark.apache.org](http://spark.apache.org)，并单击“下载 Spark”按钮：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/86baa4bb-df53-4641-ae95-0e5de592efc2.png)

现在，我们在本书中使用的是 Spark 2.1.1，但超过 2.0 的任何版本都应该可以正常工作。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/7b1ca113-5535-438e-88fd-dea58a24ef55.png)

确保您获得了预构建版本，并选择直接下载选项，因此所有这些默认设置都非常好。继续并单击第 4 条指示旁边的链接以下载该软件包。

现在，它下载了一个**TGZ**（**Tar in GZip**）文件，您可能不熟悉。坦率地说，Windows 实际上对 Spark 来说有点事后诸葛亮，因为在 Windows 上，您将没有内置的实用程序来实际解压缩 TGZ 文件。这意味着您可能需要安装一个，如果您还没有的话。我使用的是 WinRAR，您可以从[www.rarlab.com](http://www.rarlab.com)获取。如果需要，转到下载页面，并下载 WinRAR 32 位或 64 位的安装程序，具体取决于您的操作系统。像平常一样安装 WinRAR，这将允许您在 Windows 上实际解压缩 TGZ 文件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/a3e884d4-be31-4274-b858-9c7ed7e14ed6.jpg)

所以，让我们继续解压缩 TGZ 文件。我将打开我的“下载”文件夹，找到我们下载的 Spark 存档，然后右键单击该存档，并将其提取到我选择的文件夹中-我现在只是将其放在我的“下载”文件夹中。同样，此时 WinRAR 正在为我执行此操作：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/edaa679b-44dd-4811-bbed-52b39f6488bc.png)

所以，我现在应该在我的“下载”文件夹中有一个与该软件包相关联的文件夹。让我们打开它，里面就是 Spark 本身。您应该看到类似下面显示的文件夹内容。因此，您需要将其安装在您可以记住的某个地方：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/417d9e6f-4b8c-4a51-bb1c-694e1cf23530.png)

显然，您不希望将其留在“下载”文件夹中，所以让我们打开一个新的文件资源管理器窗口。我转到我的 C 驱动器并创建一个新文件夹，让我们称之为`spark`。所以，我的 Spark 安装将位于`C:\spark`中。再次，很容易记住。打开该文件夹。现在，我回到下载的`spark`文件夹，并使用*Ctrl* + *A*选择 Spark 分发中的所有内容，*Ctrl* + *C*将其复制，然后返回到`C:\spark`，*Ctrl* + *V*将其粘贴进去：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/e5a2e48a-10c4-4849-9ef2-11833945eaa8.png)

非常重要的是要记住粘贴`spark`文件夹的内容，而不是`spark`文件夹本身。因此，我现在应该有一个包含 Spark 分发中所有文件和文件夹的`C`驱动器中的`spark`文件夹。

好吧，还有一些东西我们需要配置。所以，当我们在`C:\spark`中时，让我们打开`conf`文件夹，为了确保我们不会被日志消息淹没，我们将在这里更改日志级别设置。因此，右键单击`log4j.properties.template`文件，然后选择重命名：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/82bf6b9d-9ba1-40c3-b8e0-c60efbc92f77.png)

删除文件名中的`.template`部分，使其成为一个真正的`log4j.properties`文件。Spark 将使用这个文件来配置它的日志记录：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/9277e9dc-cb05-4d4c-95ef-415e6c0ed53d.png)

现在，用某种文本编辑器打开这个文件。在 Windows 上，你可能需要右键单击，然后选择“打开方式”，然后选择“WordPad”。在文件中，找到`log4j.rootCategory=INFO`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/36f4f644-c41d-4647-a05d-2c54a8151c23.png)

让我们把这个改成`log4j.rootCategory=ERROR`，这样就可以消除运行时打印出的所有日志垃圾。保存文件，然后退出编辑器。

到目前为止，我们安装了 Python、Java 和 Spark。现在我们需要做的下一件事是安装一些东西，让你的电脑认为 Hadoop 是存在的，这一步在 Windows 上是必要的。所以，如果你在 Mac 或 Linux 上，可以跳过这一步。

我有一个小文件可以解决问题。让我们去[`media.sundog-soft.com/winutils.exe`](http://media.sundog-soft.com/winutils.exe)。下载`winutils.exe`将给你一个可执行文件的一小部分副本，可以用来欺骗 Spark，让它认为你实际上安装了 Hadoop：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/6257dac5-b9be-45d2-a9dc-58ad1ac9d705.png)

现在，因为我们将在我们的桌面上本地运行我们的脚本，这并不是什么大不了的事，我们不需要真正安装 Hadoop。这只是绕过在 Windows 上运行 Spark 的另一个怪癖。所以，现在我们有了这个，让我们在“下载”文件夹中找到它，*Ctrl* + *C*复制它，然后让我们去我们的`C`驱动器，为它创建一个位置。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/dccddda5-a8d8-47c0-b4ec-d9c636fe4513.png)

所以，在`C`驱动器的根目录中再次创建一个新文件夹，我们将称之为`winutils`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/ca38647b-576c-4e16-ba62-027fdf776511.png)

现在让我们打开这个`winutils`文件夹，并在其中创建一个`bin`文件夹：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/240ed035-0eef-48dc-b8b7-a0ff9e7bbc98.png)

现在在这个`bin`文件夹中，我希望你把我们下载的`winutils.exe`文件粘贴进去。所以你应该有`C:\winutils\bin`，然后`winutils.exe`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/329665c8-62c3-4959-88f5-6f7a64587d6c.png)

这个下一步只在一些系统上需要，但为了安全起见，在 Windows 上打开命令提示符。你可以通过转到开始菜单，然后转到 Windows 系统，然后点击命令提示符来做到这一点。在这里，我希望你输入`cd c:\winutils\bin`，这是我们放置`winutils.exe`文件的地方。现在如果你输入`dir`，你应该会看到那个文件。现在输入`winutils.exe chmod 777 \tmp\hive`。这只是确保你需要成功运行 Spark 的所有文件权限都已经放置好，没有任何错误。现在你可以关闭命令提示符了，因为你已经完成了这一步。哇，我们几乎完成了，信不信由你。

现在我们需要设置一些环境变量才能让事情正常运行。我将向你展示如何在 Windows 上做到这一点。在 Windows 10 上，你需要打开开始菜单，然后转到 Windows 系统 | 控制面板来打开控制面板：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/a2776899-1253-46d2-9de2-19bb4e45e982.png)

在控制面板中，点击系统和安全：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/a0db3138-5c95-463d-be21-087a8b379cfc.png)

然后，点击系统：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/b19bf633-a93e-45f9-9614-dae791b66324.png)

然后从左侧的列表中点击高级系统设置：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/a07b0a50-a59b-4438-9d8a-7d876d861c14.png)

从这里，点击环境变量...：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/4ded259c-ba10-44cf-acdb-da295c9959c2.png)

我们将得到这些选项：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/bbce5217-fcad-4153-a54c-c5ac2fc3a5c7.png)

现在，这是一个非常特定于 Windows 的设置环境变量的方法。 在其他操作系统上，您将使用不同的进程，因此您需要查看如何在它们上安装 Spark。 在这里，我们将设置一些新的用户变量。 单击第一个 New...按钮以创建一个新的用户变量，并将其命名为`SPARK_HOME`，如下所示，全部大写。 这将指向我们安装 Spark 的位置，对我们来说是`c:\spark`，因此在变量值中键入它，然后单击确定：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/99ecb254-bc78-45ff-9608-c74514df43f9.png)

我们还需要设置`JAVA_HOME`，因此再次单击新建...，并键入`JAVA_HOME`作为变量名。 我们需要将其指向我们安装 Java 的位置，对我们来说是`c:\jdk`。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/f84bdcce-2d85-4a17-888e-6e7020a1d3ed.png)

我们还需要设置`HADOOP_HOME`，这是我们安装`winutils`软件包的位置，因此我们将其指向`c:\winutils`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/65b2e661-efd4-4c80-b6a6-d7ad02f60df2.png)

到目前为止，一切都很好。 我们需要做的最后一件事是修改我们的路径。 您应该在这里有一个 PATH 环境变量：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/24ed1020-3dc3-4d51-b234-8dcb95deb08c.png)

单击 PATH 环境变量，然后单击编辑...，并添加一个新路径。 这将是`%SPARK_HOME%\bin`，我将添加另一个，`%JAVA_HOME%\bin`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/cdba2eb0-1f24-483c-a034-b7128e4e0e2d.png)

基本上，这使得 Spark 的所有二进制可执行文件都可以在 Windows 上运行。 单击此菜单上的确定以及前两个菜单上的确定。 我们最终设置好了一切。

# Spark 介绍

让我们从高层次概述 Apache Spark 开始，看看它是什么，它适用于什么，以及它是如何工作的。

什么是 Spark？嗯，如果你去 Spark 的网站，他们会给你一个非常高层次的，模糊的答案，“一个用于大规模数据处理的快速通用引擎。” 它切片，切块，它可以洗你的衣服。 嗯，不是真的。 但它是一个用于编写可以处理大量数据的作业或脚本的框架，并且它管理将该处理分布到计算集群中。 基本上，Spark 通过让你将数据加载到称为弹性分布式数据存储的大型对象中来工作，RDDs。 它可以自动执行转换和创建基于这些 RDD 的操作，你可以将其视为大型数据框架。

它的美妙之处在于，Spark 将自动地并且最优地将处理分布在整个计算机集群中，如果您有一个可用的话。 您不再受限于在单台计算机或单台计算机的内存上可以做什么。 您实际上可以将其扩展到整个机器集群可用的所有处理能力和内存，而且在今天这个时代，计算是相当便宜的。 您实际上可以通过像亚马逊的弹性 MapReduce 服务这样的服务租用集群上的时间，并且只需花费几美元就可以在整个计算机集群上租用一些时间，并运行您无法在自己的桌面上运行的作业。

# 它是可扩展的

Spark 如何实现可扩展性？ 好吧，让我们在这里更具体一点看看它是如何工作的。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/3e61f40b-aae0-4ce4-a3bf-9ae6e2948d6c.png)

它的工作原理是，您编写一个驱动程序，它只是一个看起来与任何其他 Python 脚本非常相似的小脚本，并且它使用 Spark 库来实际编写您的脚本。 在该库中，您定义了所谓的 Spark 上下文，这在您在 Spark 中开发时是您要使用的根对象。

从那里开始，Spark 框架会接管并为您分配任务。因此，如果您在自己的计算机上以独立模式运行，就像我们将在接下来的部分中进行的那样，所有任务都会留在您的计算机上。然而，如果您在集群管理器上运行，Spark 可以识别并自动利用它。Spark 实际上有自己内置的集群管理器，您甚至可以在没有安装 Hadoop 的情况下单独使用它，但如果您有可用的 Hadoop 集群，它也可以使用。

Hadoop 不仅仅是 MapReduce；实际上，Hadoop 有一个名为 YARN 的组件，它将 Hadoop 的整个集群管理部分分离出来。Spark 可以与 YARN 接口，实际上使用它来在 Hadoop 集群中有效地分配处理组件的资源。

在集群中，您可能有正在运行的个别执行器任务。这些可能在不同的计算机上运行，也可能在同一台计算机的不同核心上运行。它们各自有自己的缓存和自己的任务。驱动程序、Spark Context 和集群管理器共同协调所有这些工作，并将最终结果返回给您。

它的美妙之处在于，您只需要编写最初的小脚本，即驱动程序，它使用 Spark Context 在高层次上描述您想要对这些数据进行的处理。Spark 与您使用的集群管理器一起工作，找出如何分散和分发，因此您不必担心所有这些细节。当然，如果不起作用，显然，您可能需要进行一些故障排除，以找出您手头的任务是否有足够的资源可用，但理论上，这都只是魔术。

# 它很快

Spark 有什么了不起的？我的意思是，有类似的技术，比如 MapReduce 已经存在很长时间了。不过，Spark 很快，网站上声称 Spark 在内存中运行作业时比 MapReduce 快 100 倍，或者在磁盘上快 10 倍。当然，这里的关键词是“最多”，您的情况可能有所不同。我从来没有见过任何东西实际上比 MapReduce 快那么多。一些精心设计的 MapReduce 代码实际上仍然可以非常高效。但我会说，Spark 确实使许多常见操作更容易。MapReduce 迫使您真正将事情分解为映射器和减速器，而 Spark 则更高级一些。您不必总是那么费心地使用 Spark 做正确的事情。

这部分原因之一是 Spark 为何如此快的原因。它有一个 DAG 引擎，即有向无环图。哇，这是另一个花哨的词。这是什么意思？Spark 的工作方式是，您编写一个描述如何处理数据的脚本，您可能有一个 RDD，基本上就像一个数据框架。您可能对其进行某种转换或某种操作。但直到您对该数据执行某种操作之前，实际上什么都不会发生。在那一点上发生的是，Spark 会说“嗯，好吧。所以，这是您在这些数据上想要的最终结果。我为了达到这一点必须做的所有其他事情是什么，以及达到这一点的最佳策略是什么？”因此，在幕后，它将找出最佳的方式来分割处理，并分发信息以获得您所寻找的最终结果。因此，这里的关键是，Spark 等到您告诉它实际产生结果，只有在那一点上它才会去找出如何产生那个结果。因此，这是一个很酷的概念，这是它效率的关键。

# 它很年轻

Spark 是一种非常炙手可热的技术，而且相对年轻，所以它仍然在不断发展和迅速变化，但很多大公司都在使用它。例如，亚马逊声称他们在使用它，eBay，NASA 的喷气推进实验室，Groupon，TripAdvisor，雅虎，还有许多其他公司也在使用。我相信有很多公司在使用它，但他们不会承认，但如果你去 Spark Apache Wiki 页面[`spark.apache.org/powered-by.html`](http://spark.apache.org/powered-by.html)。

实际上有一个你可以查阅的已知大公司使用 Spark 解决实际数据问题的列表。如果你担心自己正在接触最前沿的技术，不用担心，有一些非常大的公司正在使用 Spark 来解决实际问题，你是和一些非常重要的人一起使用 Spark 来解决实际问题。在这一点上，它是相当稳定的东西。

# 这并不困难

这也不难。你可以选择用 Python、Java 或 Scala 编程，它们都是围绕我之前描述的相同概念构建的，即弹性分布式数据集，简称 RDD。我们将在本章的后续部分详细讨论这一点。

# Spark 的组件

Spark 实际上有许多不同的组件构成。因此，有一个 Spark 核心，只需使用 Spark 核心功能就可以做出几乎任何你可以想象的事情，但还有其他一些构建在 Spark 之上的东西也很有用。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/ed75debb-a33c-49d3-99f3-e69d183abf4f.png)

+   **Spark Streaming**：Spark Streaming 是一个库，它让你实际上可以实时处理数据。数据可以持续地流入服务器，比如来自网络日志，Spark Streaming 可以帮助你实时处理数据，一直进行下去。

+   **Spark SQL**：这让你实际上可以将数据视为 SQL 数据库，并在其上发出 SQL 查询，如果你已经熟悉 SQL，这是很酷的。

+   **MLlib**：这是我们在本节中要重点关注的内容。它实际上是一个机器学习库，让你可以执行常见的机器学习算法，底层使用 Spark 来实际分布式处理集群中的数据。你可以对比以前能处理的更大的数据集进行机器学习。

+   **GraphX**：这不是用来制作漂亮的图表和图形的。它是指网络理论意义上的图。想想一个社交网络；这就是图的一个例子。GraphX 只有一些函数，让你分析信息图的属性。

# Python 与 Scala 在 Spark 中的比较

有时候我在教授 Apache Spark 时会遇到一些批评，因为我使用 Python，但我的做法是有道理的。的确，很多人在编写 Spark 代码时使用 Scala，因为 Spark 是本地开发的。因此，通过强制 Spark 将你的 Python 代码转换为 Scala，然后在最后一天转换为 Java 解释器命令，你会增加一些开销。

然而，Python 要容易得多，而且你不需要编译东西。管理依赖项也要容易得多。你可以真正把时间集中在算法和你正在做的事情上，而不是在实际构建、运行、编译和所有那些废话上。此外，显然，这本书到目前为止一直都在关注 Python，继续使用我们学到的东西并在这些讲座中坚持使用 Python 是有意义的。以下是两种语言的优缺点的快速总结：

| **Python** | **Scala** |
| --- | --- |

|

+   无需编译、管理依赖等

+   编码开销更少

+   你已经了解 Python

+   让我们专注于概念而不是新语言

|

+   Scala 可能是 Spark 的更受欢迎的选择

+   Spark 是用 Scala 构建的，所以在 Scala 中编码对于 Spark 来说是“本地”的

+   新功能、库往往是首先使用 Scala

|

然而，我要说的是，如果您在现实世界中进行一些 Spark 编程，很有可能人们正在使用 Scala。不过不要太担心，因为在 Spark 中，Python 和 Scala 代码最终看起来非常相似，因为它们都围绕着相同的 RDD 概念。语法略有不同，但并不是很大的不同。如果您能够弄清楚如何使用 Python 进行 Spark 编程，学习如何在 Scala 中使用它并不是一个很大的飞跃。这里有两种语言中相同代码的快速示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/6a204753-e6f0-415f-a359-b8d9a68c5a8e.png)

因此，这就是 Spark 本身的基本概念，为什么它如此重要，以及它如何在让您在非常大的数据集上运行机器学习算法或任何算法方面如此强大。现在让我们更详细地讨论一下它是如何做到这一点的，以及弹性分布式数据集的核心概念。

# Spark 和弹性分布式数据集（RDD）

让我们深入了解一下 Spark 的工作原理。我们将谈论弹性分布式数据集，即 RDD。这是您在 Spark 编程中使用的核心，我们将提供一些代码片段来尝试使其变得真实。我们将在这里为您提供 Apache Spark 的速成课程。比我们接下来要涵盖的内容更加深入，但我只会为您提供实际理解这些示例所需的基础知识，并希望能够让您开始并指向正确的方向。

如前所述，Spark 最基本的部分称为弹性分布式数据集，即 RDD，这将是您实际用来加载、转换和获取您想要的数据的对象。这是一个非常重要的理解。RDD 中的最后一个字母代表数据集，最终它只是一堆包含几乎任何内容的信息行。但关键是 R 和第一个 D。

+   **弹性**：它是弹性的，因为 Spark 确保如果您在集群上运行此任务并且其中一个集群出现故障，它可以自动从中恢复并重试。不过，请注意，这种弹性是有限的。如果您没有足够的资源可用于您要运行的作业，它仍然会失败，您将不得不为其添加更多资源。它只能从许多事情中恢复；它会尝试多少次重新尝试给定的任务是有限的。但它会尽最大努力确保在面对不稳定的集群或不稳定的网络时，仍然会继续尽最大努力运行到完成。

+   **分布式**：显然，它是分布式的。使用 Spark 的整个目的是，您可以将其用于可以横向分布到整个计算机集群的 CPU 和内存功率的大数据问题。这可以水平分布，因此您可以将尽可能多的计算机投入到给定的问题中。问题越大，使用的计算机就越多；在这方面真的没有上限。

# SparkContext 对象

您始终通过获取 SparkContext 对象来启动 Spark 脚本，这个对象体现了 Spark 的核心。它将为您提供要在其上处理的 RDD，因此它生成了您在处理中使用的对象。

你知道吗，当你实际编写 Spark 程序时，你并不会非常关注 SparkContext，但它实际上是在幕后为你运行它们的基础。如果你在 Spark shell 中交互式运行，它已经为你提供了一个`sc`对象，你可以用它来创建 RDD。然而，在独立脚本中，你将不得不显式创建 SparkContext，并且你将不得不注意你使用的参数，因为你实际上可以告诉 Spark 上下文你希望它如何分布。我应该利用我可用的每个核心吗？我应该在集群上运行还是只在我的本地计算机上独立运行？所以，这就是你设置 Spark 操作的基本设置的地方。

# 创建 RDD

让我们看一些实际创建 RDD 的小代码片段，我认为这一切都会开始变得更加清晰。

# 使用 Python 列表创建 RDD

以下是一个非常简单的例子：

```py
nums = parallelize([1, 2, 3, 4]) 

```

如果我只想从一个普通的 Python 列表中创建 RDD，我可以在 Spark 中调用`parallelize()`函数。这将把一系列东西，比如这里的数字 1、2、3、4，转换为一个名为`nums`的 RDD 对象。

这是创建 RDD 的最简单情况，只是从一个硬编码的列表中创建。该列表可以来自任何地方；它也不必是硬编码的，但这有点违背了大数据的目的。我的意思是，如果我必须在创建 RDD 之前将整个数据集加载到内存中，那还有什么意义呢？

# 从文本文件加载 RDD

我还可以从文本文件中加载 RDD，它可以是任何地方。

```py
sc.textFile("file:///c:/users/frank/gobs-o-text.txt")  

```

在这个例子中，我有一个巨大的文本文件，整个百科全书之类的东西。我正在从我的本地磁盘读取它，但如果我想要将这个文件托管在分布式的 AmazonS3 存储桶上，我也可以使用 s3n，或者如果我想引用存储在分布式 HDFS 集群上的数据，我可以使用 hdfs（如果您对 HDFS 不熟悉，它代表 Hadoop 分布式文件系统）。当你处理大数据并使用 Hadoop 集群时，通常你的数据会存储在那里。

这行代码实际上会将文本文件的每一行转换为 RDD 中的一行。所以，你可以把 RDD 看作是一行的数据库，在这个例子中，它将我的文本文件加载到一个 RDD 中，其中每一行，每一行，包含一行文本。然后我可以在那个 RDD 中进行进一步的处理，解析或分解数据中的分隔符。但这是我开始的地方。

还记得我们之前在书中讨论 ETL 和 ELT 吗？这是一个很好的例子，你可能实际上正在将原始数据加载到系统中，并在系统本身上进行转换，用于查询数据的系统。你可以拿未经任何处理的原始文本文件，并利用 Spark 的强大功能将其转换为更结构化的数据。

它还可以与 Hive 等东西通信，所以如果你的公司已经设置了现有的 Hive 数据库，你可以创建一个基于你的 Spark 上下文的 Hive 上下文。这是多么酷啊？看看这个例子代码：

```py
hiveCtx = HiveContext(sc)  rows = hiveCtx.sql("SELECT name, age FROM users")  

```

你实际上可以创建一个 RDD，这里称为 rows，它是通过在你的 Hive 数据库上实际执行 SQL 查询来生成的。

# 创建 RDD 的更多方法

还有更多创建 RDD 的方法。您可以从 JDBC 连接创建它们。基本上，任何支持 JDBC 的数据库也可以与 Spark 通信，并从中创建 RDD。Cassandra、HBase、Elasticsearch，还有 JSON 格式、CSV 格式、序列文件对象文件以及一堆其他压缩文件（如 ORC）都可以用来创建 RDD。我不想深入讨论所有这些细节，如果需要，您可以找一本书查看，但重点是很容易从数据中创建 RDD，无论数据是在本地文件系统还是分布式数据存储中。

再次强调，RDD 只是一种加载和维护大量数据并一次跟踪所有数据的方法。但是，在脚本中，概念上，RDD 只是包含大量数据的对象。您不必考虑规模，因为 Spark 会为您处理。

# RDD 操作

现在，一旦您拥有 RDD，您可以对其执行两种不同类型的操作，即转换和操作。

# 转换

让我们先谈谈转换。转换就是它听起来的样子。这是一种将 RDD 中的每一行根据您提供的函数转换为新值的方法。让我们看看其中一些函数：

+   **map() 和 flatmap()**: `map`和`flatmap`是您经常看到的函数。这两个函数都将接受您可以想象的任何函数，该函数将以 RDD 的一行作为输入，并输出一个转换后的行。例如，您可以从 CSV 文件中获取原始输入，您的`map`操作可能会将该输入根据逗号分隔符拆分为单独的字段，并返回一个包含以更结构化格式的数据的 Python 列表，以便您可以进行进一步的处理。您可以链接 map 操作，因此一个`map`的输出可能最终创建一个新的 RDD，然后您可以对其进行另一个转换，依此类推。再次强调，关键是，Spark 可以在集群上分发这些转换，因此它可能会在一台机器上转换 RDD 的一部分，然后在另一台机器上转换 RDD 的另一部分。

就像我说的，`map`和`flatmap`是您将看到的最常见的转换。唯一的区别是`map`只允许您为每一行输出一个值，而`flatmap`将允许您实际上为给定的行输出多个新行。因此，您实际上可以使用`flatmap`创建一个比您开始时更大或更小的 RDD。

+   **filter()**: 如果您只想创建一个布尔函数来判断“是否应该保留此行？是或否。”

+   **distinct()**: `distinct`是一个不太常用的转换，它将仅返回 RDD 中的不同值。

+   **sample()**: 此函数允许您从 RDD 中随机抽取样本

+   **union(), intersection(), subtract() 和 Cartesian()**: 您可以执行诸如并集、交集、差集，甚至生成 RDD 中存在的每个笛卡尔组合的操作。

# 使用 map()

以下是您如何在工作中使用 map 函数的一个小例子：

```py
rdd = sc.parallelize([1, 2, 3, 4]) 
rdd.map(lambda x: x*x) 

```

假设我只是从列表 1、2、3、4 创建了一个 RDD。然后我可以使用一个 lambda 函数 x 调用`rdd.map()`，该函数接受每一行，也就是 RDD 的每个值，将其称为 x，然后将函数 x 乘以 x 应用于平方。如果我然后收集此 RDD 的输出，它将是 1、4、9 和 16，因为它将获取该 RDD 的每个单独条目并对其进行平方，然后将其放入新的 RDD 中。

如果您不记得 lambda 函数是什么，我们在本书的前面稍微谈到过，但是作为提醒，lambda 函数只是定义一个内联函数的简写。因此，`rdd.map(lambda x: x*x)`与一个单独的函数`def squareIt(x): return x*x`是完全相同的，并且说`rdd.map(squareIt)`。

这只是一个非常简单的函数的简写，您希望将其作为转换传递。它消除了实际将其声明为自己的单独命名函数的需要。这就是函数式编程的整个理念。所以你现在可以说你理解函数式编程了！但实际上，这只是定义一个内联函数作为`map()`函数的参数之一，或者任何转换的简写符号。

# 行动

您还可以对 RDD 执行操作，当您真正想要获得结果时。以下是一些您可以执行的示例：

+   `collect()`: 您可以在 RDD 上调用 collect()，这将为您提供一个普通的 Python 对象，然后您可以遍历并打印结果，或将其保存到文件，或者您想做的任何其他事情。

+   `count()`: 您还可以调用`count()`，这将强制其实际上计算此时 RDD 中有多少条目。

+   `countByValue()`: 此函数将为您提供 RDD 中每个唯一值出现的次数的统计。

+   `take()`: 您还可以使用`take()`从 RDD 中进行抽样，它将从 RDD 中获取随机数量的条目。

+   `top()`: 如果您只想为了调试目的查看 RDD 中的前几个条目，`top()`将为您提供这些条目。

+   `reduce()`: 更强大的操作是`reduce()`，它实际上允许您将相同的公共键值的值组合在一起。您还可以在键-值数据的上下文中使用 RDD。`reduce()`函数允许您定义一种将给定键的所有值组合在一起的方式。它在精神上与 MapReduce 非常相似。`reduce()`基本上是 MapReduce 中`reducer()`的类似操作，而`map()`类似于`mapper()`。因此，通过使用这些函数，实际上很容易将 MapReduce 作业转换为 Spark。

还记得，在 Spark 中实际上什么都不会发生，直到您调用一个操作。一旦调用其中一个操作方法，Spark 就会出去并使用有向无环图进行其魔术，并实际计算获得所需答案的最佳方式。但请记住，直到发生那个操作，实际上什么都不会发生。因此，当您编写 Spark 脚本时，有时可能会遇到问题，因为您可能在其中有一个小的打印语句，并且您可能期望得到一个答案，但实际上直到执行操作时才会出现。

这就是 Spark 编程的基础。基本上，什么是 RDD 以及您可以对 RDD 执行哪些操作。一旦掌握了这些概念，您就可以编写一些 Spark 代码。现在让我们改变方向，谈谈 MLlib，以及 Spark 中一些特定的功能，让您可以使用 Spark 进行机器学习算法。

# 介绍 MLlib

幸运的是，在进行机器学习时，您不必在 Spark 中以困难的方式进行操作。它有一个名为 MLlib 的内置组件，它位于 Spark Core 之上，这使得使用大规模数据集执行复杂的机器学习算法变得非常容易，并将该处理分布到整个计算机集群中。非常令人兴奋的事情。让我们更多地了解它可以做什么。

# 一些 MLlib 功能

那么，MLlib 可以做些什么？其中之一是特征提取。

您可以在规模上执行词频和逆文档频率等操作，这对于创建搜索索引非常有用。我们稍后将实际上通过本章的一个示例来进行说明。关键是，它可以使用大规模数据集在整个集群中执行此操作，因此您可以使用它来为网络创建自己的搜索引擎。它还提供基本的统计函数，卡方检验，皮尔逊或斯皮尔曼相关性，以及一些更简单的东西，如最小值，最大值，平均值和方差。这些本身并不是非常令人兴奋，但令人兴奋的是，您实际上可以计算大规模数据集的方差或平均值，或者相关性得分，如果必要，它实际上会将该数据集分解成各种块，并在整个集群中运行。

因此，即使其中一些操作并不是非常有趣，有趣的是它可以操作的规模。它还支持诸如线性回归和逻辑回归之类的东西，因此如果您需要将函数拟合到大量数据集并用于预测，您也可以这样做。它还支持支持向量机。我们正在进入一些更高级的算法，一些更高级的东西，这也可以使用 Spark 的 MLlib 扩展到大规模数据集。MLlib 中内置了朴素贝叶斯分类器，因此，还记得我们在本书前面构建的垃圾邮件分类器吗？您实际上可以使用 Spark 为整个电子邮件系统执行此操作，并根据需要扩展。

决策树，机器学习中我最喜欢的东西之一，也受到 Spark 的支持，我们稍后在本章中将有一个示例。我们还将研究 K 均值聚类，您可以使用 Spark 和 MLlib 对大规模数据集进行聚类。甚至主成分分析和奇异值分解也可以使用 Spark 进行，我们也将有一个示例。最后，MLlib 中内置了一种名为交替最小二乘法的推荐算法。就我个人而言，我对它的效果有些参差不齐，您知道，对于我来说，它有点太神秘了，但我是一个推荐系统的挑剔者，所以请带着一颗谨慎的心来看待这一点！

# 特殊的 MLlib 数据类型

使用 MLlib 通常非常简单，只需要调用一些库函数。但是，它确实引入了一些新的数据类型，您需要了解一下，其中之一就是向量。

# 向量数据类型

还记得我们在本书前面做电影相似性和电影推荐时吗？向量的一个例子可能是给定用户评分的所有电影的列表。有两种类型的向量，稀疏和密集。让我们看看这两种的例子。世界上有很多很多电影，密集向量实际上会表示每部电影的数据，无论用户是否真的观看了它。所以，例如，假设我有一个用户观看了《玩具总动员》，显然我会存储他们对《玩具总动员》的评分，但如果他们没有观看电影《星球大战》，我实际上会存储没有《星球大战》的数字这一事实。因此，我们最终会占用所有这些缺失数据点的空间。稀疏向量只存储存在的数据，因此不会浪费任何内存空间在缺失数据上。因此，它是一种更紧凑的内部向量表示形式，但显然在处理时会引入一些复杂性。因此，如果您知道您的向量中将有很多缺失数据，这是一种节省内存的好方法。

# 带标签的点数据类型

还有一个`LabeledPoint`数据类型，它就像它听起来的那样，一个带有某种标签的点，以人类可读的方式传达这些数据的含义。

# 评级数据类型

最后，如果您在使用 MLlib 进行推荐，您将遇到`Rating`数据类型。这种数据类型可以接受代表 1-5 或 1-10 的评级，无论一个人可能有什么星级评价，并使用它来自动提供产品推荐。

因此，我认为您终于有了开始的一切，让我们深入实际查看一些真正的 MLlib 代码并运行它，然后它将变得更加清晰。

# 在 Spark 中使用 MLlib 的决策树

好了，让我们使用 Spark 和 MLlib 库实际构建一些决策树，这是非常酷的东西。无论你把这本书的课程材料放在哪里，我希望你现在就去那个文件夹。确保你完全关闭了 Canopy，或者你用于 Python 开发的任何环境，因为我想确保你是从这个目录开始的，好吗？然后找到`SparkDecisionTree`脚本，双击打开 Canopy：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/ad29a0a7-b494-4b34-9ab7-0430ffb3c225.png)

现在，在这一点上，我们一直在使用 IPython 笔记本来编写我们的代码，但是你不能真正很好地使用它们与 Spark。对于 Spark 脚本，你需要实际将它们提交到 Spark 基础设施并以非常特殊的方式运行它们，我们很快就会看到它是如何工作的。

# 探索决策树代码

所以，现在我们只是看一个原始的 Python 脚本文件，没有 IPython 笔记本的通常修饰。让我们来看看脚本中发生了什么。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/6d667f6b-c68c-489a-a94b-5582b37634f0.png)

我们会慢慢来，因为这是你在本书中看到的第一个 Spark 脚本。

首先，我们将从`pyspark.mllib`中导入我们在 Spark 机器学习库中需要的部分。

```py
from pyspark.mllib.regression import LabeledPoint 
from pyspark.mllib.tree import DecisionTree 

```

我们需要`LabeledPoint`类，这是`DecisionTree`类所需的数据类型，以及从`mllib.tree`导入的`DecisionTree`类本身。

接下来，你会看到几乎每个 Spark 脚本都会包含这一行，我们在其中导入`SparkConf`和`SparkContext`：

```py
from pyspark import SparkConf, SparkContext 

```

这是创建`SparkContext`对象所需的，它是你在 Spark 中做任何事情的根本。

最后，我们将从`numpy`中导入数组库：

```py
from numpy import array 

```

是的，你仍然可以在 Spark 脚本中使用`NumPy`、`scikit-learn`或者任何你想要的东西。你只需要确保首先这些库在你打算在其上运行的每台机器上都已安装好。

如果你在集群上运行，你需要确保这些 Python 库已经以某种方式安装好了，并且你还需要明白，Spark 不会使 scikit-learn 的方法等变得可扩展。你仍然可以在给定 map 函数的上下文中调用这些函数，但它只会在那一个机器的一个进程中运行。不要过分依赖这些东西，但是对于像管理数组这样的简单事情，这是完全可以的。

# 创建 SparkContext

现在，我们将开始设置我们的`SparkContext`，并给它一个`SparkConf`，一个配置。

```py
conf = SparkConf().setMaster("local").setAppName("SparkDecisionTree") 

```

这个配置对象表示，我将把主节点设置为"`local`"，这意味着我只是在自己的本地桌面上运行，我实际上根本不是在集群上运行，我只会在一个进程中运行。我还会给它一个应用程序名称"`SparkDecisionTree`"，你可以随意命名它，Fred、Bob、Tim，随你喜欢。这只是当你稍后在 Spark 控制台中查看时，这个作业将显示为什么。

然后，我们将使用该配置创建我们的`SparkContext`对象：

```py
sc = SparkContext(conf = conf) 

```

这给了我们一个`sc`对象，我们可以用它来创建 RDDs。

接下来，我们有一堆函数：

```py
# Some functions that convert our CSV input data into numerical 
# features for each job candidate 
def binary(YN): 
    if (YN == 'Y'): 
        return 1 
    else: 
        return 0 

def mapEducation(degree): 
    if (degree == 'BS'): 
        return 1 
    elif (degree =='MS'): 
        return 2 
    elif (degree == 'PhD'): 
        return 3 
    else: 
        return 0 

# Convert a list of raw fields from our CSV file to a 
# LabeledPoint that MLLib can use. All data must be numerical... 
def createLabeledPoints(fields): 
    yearsExperience = int(fields[0]) 
    employed = binary(fields[1]) 
    previousEmployers = int(fields[2]) 
    educationLevel = mapEducation(fields[3]) 
    topTier = binary(fields[4]) 
    interned = binary(fields[5]) 
    hired = binary(fields[6]) 

    return LabeledPoint(hired, array([yearsExperience, employed, 
        previousEmployers, educationLevel, topTier, interned])) 

```

现在先记住这些函数，稍后我们会回来再讨论它们。

# 导入和清理我们的数据

让我们来看一下这个脚本中实际执行的第一部分 Python 代码。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/ba509b70-e811-4149-b770-49de93e80b5b.png)

我们要做的第一件事是加载`PastHires.csv`文件，这是我们在本书早期做决策树练习时使用的同一个文件。

让我们暂停一下，回顾一下那个文件的内容。如果你记得的话，我们有一堆求职者的属性，还有一个字段，表示我们是否雇佣了这些人。我们要做的是建立一个决策树，来预测 - 根据这些属性，我们是否会雇佣这个人。

现在，让我们快速查看一下`PastHires.csv`，这将是一个 Excel 文件。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/26da7937-34a5-4c2b-9f83-e42cb12a44ab.png)

您可以看到 Excel 实际上将其导入为一个表，但如果您查看原始文本，您会发现它由逗号分隔的值组成。

第一行是每列的实际标题，所以上面的内容是先前经验年数，候选人当前是否在职，以及之前的雇主数量，教育水平，是否就读于顶尖学校，是否在学校期间有实习，最后，我们试图在最后一天预测的目标，即他们是否得到了工作机会。现在，我们需要将这些信息读入 RDD，以便我们可以对其进行处理。

让我们回到我们的脚本：

```py
rawData = sc.textFile("e:/sundog-consult/udemy/datascience/PastHires.csv") 
header = rawData.first() 
rawData = rawData.filter(lambda x:x != header) 

```

我们需要做的第一件事是读取 CSV 数据，并且我们将丢弃第一行，因为那是我们的标题信息，记住。这里有一个小技巧。我们首先从文件中导入每一行到一个原始数据 RDD 中，我可以随意命名它，但我们称它为`sc.textFile`。SparkContext 有一个`textFile`函数，它将获取一个文本文件并创建一个新的 RDD，其中每个条目，RDD 的每一行，都包含一个输入行。

确保将文件的路径更改为您实际安装的位置，否则它将无法工作。

现在，我将使用`first`函数从 RDD 中提取第一行，也就是第一行列标题。现在，头部 RDD 将包含一个条目，即列标题的那一行。现在，看看上面的代码，我在包含 CSV 文件中的原始数据上使用`filter`，并定义了一个`filter`函数，只有当该行不等于初始标题行的内容时，才允许该行通过。我在这里所做的是，我从我的原始 CSV 文件中剥离出了第一行，只允许不等于第一行的行通过，并将其返回给`rawData` RDD 变量。所以，我从`rawData`中过滤掉了第一行，并创建了一个只包含数据本身的新`rawData`。到目前为止明白了吗？并不复杂。

现在，我们要使用`map`函数。接下来，我们需要开始对这些信息进行更多的结构化处理。现在，我的 RDD 的每一行都只是一行文本，它是逗号分隔的文本，但它仍然只是一行巨大的文本，我想将逗号分隔的值列表实际分割成单独的字段。最终，我希望每个 RDD 都从一行文本转换为一个 Python 列表，其中包含我拥有的每个信息列的实际单独字段。这就是这个 lambda 函数的作用：

```py
csvData = rawData.map(lambda x: x.split(",")) 

```

它调用了内置的 Python 函数`split`，该函数将获取一行输入，并在逗号字符上进行拆分，并将其分成一个由逗号分隔的每个字段的列表。

这个`map`函数的输出，我传入了一个 lambda 函数，它只是根据逗号将每一行拆分成字段，得到了一个名为`csvData`的新 RDD。此时，`csvData`是一个 RDD，其中每一行都包含一个列表，其中每个元素都是源数据中的列。现在，我们接近了。

事实证明，为了在 MLlib 中使用决策树，需要满足一些条件。首先，输入必须是 LabeledPoint 数据类型，并且所有数据都必须是数字性质的。因此，我们需要将所有原始数据转换为实际可以被 MLlib 消耗的数据，这就是我们之前跳过的`createLabeledPoints`函数所做的事情。我们马上就会讲到，首先是对它的调用：

```py
trainingData = csvData.map(createLabeledPoints) 

```

我们将在`csvData`上调用 map，并将其传递给`createLabeledPoints`函数，该函数将将每个输入行转换为最终我们想要的东西。所以，让我们看看`createLabeledPoints`做了什么：

```py
def createLabeledPoints(fields): 
    yearsExperience = int(fields[0]) 
    employed = binary(fields[1]) 
    previousEmployers = int(fields[2]) 
    educationLevel = mapEducation(fields[3]) 
    topTier = binary(fields[4]) 
    interned = binary(fields[5]) 
    hired = binary(fields[6]) 

    return LabeledPoint(hired, array([yearsExperience, employed, 
        previousEmployers, educationLevel, topTier, interned])) 

```

它接受一个字段列表，再次提醒您一下它是什么样子，让我们再次打开那个`.csv`的 Excel 文件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/1a544f69-91c3-4053-9c95-790c728122e3.png)

因此，此时每个 RDD 条目都有一个字段，它是一个 Python 列表，其中第一个元素是工作经验，第二个元素是就业情况，依此类推。问题在于我们希望将这些列表转换为 Labeled Points，并且我们希望将所有内容转换为数值数据。因此，所有这些 yes 和 no 答案都需要转换为 1 和 0。这些经验水平需要从学位名称转换为某些数值序数值。也许我们将值 0 分配给没有教育，1 表示学士学位，2 表示硕士学位，3 表示博士学位，例如。同样，所有这些 yes/no 值都需要转换为 0 和 1，因为归根结底，进入我们的决策树的一切都需要是数值的，这就是`createLabeledPoints`的作用。现在，让我们回到代码并运行它：

```py
def createLabeledPoints(fields): 
    yearsExperience = int(fields[0]) 
    employed = binary(fields[1]) 
    previousEmployers = int(fields[2]) 
    educationLevel = mapEducation(fields[3]) 
    topTier = binary(fields[4]) 
    interned = binary(fields[5]) 
    hired = binary(fields[6]) 

    return LabeledPoint(hired, array([yearsExperience, employed, 
        previousEmployers, educationLevel, topTier, interned])) 

```

首先，它接受我们的`StringFields`列表，准备将其转换为`LabeledPoints`，其中标签是目标值-这个人是否被雇佣？0 或 1-后面是由我们关心的所有其他字段组成的数组。因此，这就是您创建`DecisionTree MLlib`类可以使用的`LabeledPoint`的方式。因此，您可以在上面的代码中看到，我们将工作经验从字符串转换为整数值，并且对于所有的 yes/no 字段，我们调用了我在代码顶部定义的`binary`函数，但我们还没有讨论过：

```py
def binary(YN): 
    if (YN == 'Y'): 
        return 1 
    else: 
        return 0 

```

它只是将字符 yes 转换为 1，否则返回 0。所以，Y 将变为 1，N 将变为 0。同样，我有一个`mapEducation`函数：

```py
def mapEducation(degree): 
    if (degree == 'BS'): 
        return 1 
    elif (degree =='MS'): 
        return 2 
    elif (degree == 'PhD'): 
        return 3 
    else: 
        return 0 

```

正如我们之前讨论的，这只是将不同类型的学位转换为与我们的 yes/no 字段完全相同的序数数值。

作为提醒，这是让我们通过这些函数的代码行：

```py
trainingData = csvData.map(createLabeledPoints) 

```

在使用`createLabeledPoints`函数映射我们的 RDD 之后，我们现在有了一个`trainingData` RDD，这正是 MLlib 构建决策树所需要的。

# 创建测试候选人并构建我们的决策树

让我们创建一个小的测试候选人，这样我们就可以使用我们的模型来预测是否会雇佣某个新人。我们要做的是创建一个测试候选人，其中包含与 CSV 文件中每个字段相同的值的数组：

```py
testCandidates = [ array([10, 1, 3, 1, 0, 0])] 

```

让我们快速将该代码与 Excel 文档进行比较，以便您可以看到数组映射：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/d0370539-6f0f-49a4-b9c0-5adc827ce00c.png)

同样，我们需要将它们映射回它们的原始列表示，以便 10、1、3、1、0、0 表示 10 年的工作经验，目前就业，三个以前的雇主，学士学位，没有上过一流学校，也没有做实习。如果我们愿意，我们实际上可以创建一个完整的 RDD 候选人，但现在我们只做一个。

接下来，我们将使用 parallelize 将该列表转换为 RDD：

```py
testData = sc.parallelize(testCandidates) 

```

没有新东西。好了，现在让我们移动到下一个代码块：

```py
model = DecisionTree.trainClassifier(trainingData, numClasses=2, 
                    categoricalFeaturesInfo={1:2, 3:4, 4:2, 5:2}, 
                    impurity='gini', maxDepth=5, maxBins=32) 

```

我们将调用`DecisionTree.trainClassifier`，这将实际构建我们的决策树本身。我们传入我们的`trainingData`，这只是一个充满`LabeledPoint`数组的 RDD，`numClasses=2`，因为我们基本上是在做一个是或否的预测，这个人会被雇佣吗？下一个参数叫做`categoricalFeaturesInfo`，这是一个 Python 字典，将字段映射到每个字段中的类别数。因此，如果某个字段有一个连续的范围可用，比如工作经验的年数，你就不需要在这里指定它，但对于那些具有分类特性的字段，比如他们拥有什么学位，例如，那会说字段 ID3，映射到所获得的学位，有四种不同的可能性：没有教育、学士、硕士和博士。对于所有的是/否字段，我们将它们映射到 2 种可能的类别，是/否或 0/1 是我们将它们转换成的。

继续通过我们的`DecisionTree.trainClassifier`调用，我们将使用'gini'不纯度度量作为我们测量熵的指标。我们有一个最大深度为 5，这只是我们将要走多远的一个上限，如果你愿意，它可以更大。最后，`maxBins`只是一种权衡计算开销的方式，如果可以的话，它只需要至少是每个特征中你拥有的最大类别数。记住，直到我们调用一个操作之前，什么都不会发生，因此我们将实际使用这个模型来为我们的测试候选人做出预测。

我们使用我们的`DecisionTree`模型，其中包含了在我们的测试训练数据上训练的决策树，并告诉它对我们的测试数据进行预测：

```py
predictions = model.predict(testData) 
print ('Hire prediction:') 
results = predictions.collect() 
for result in results: 
     print (result) 

```

我们将得到一个预测列表，然后我们可以进行迭代。因此，`predict`返回一个普通的 Python 对象，是我可以`collect`的一个操作。让我稍微改一下：`collect`将返回我们预测的 Python 对象，然后我们可以迭代遍历列表中的每个项目并打印出预测的结果。

我们还可以通过使用`toDebugString`打印出决策树本身：

```py
print('Learned classification tree model:') 
print(model.toDebugString()) 

```

这将实际打印出它内部创建的决策树的一个小表示，你可以在自己的头脑中跟踪。所以，这也很酷。

# 运行脚本

好了，随意花点时间，多看一下这个脚本，消化一下正在发生的事情，但是，如果你准备好了，让我们继续并实际运行这个程序。因此，你不能直接从 Canopy 运行它。我们将转到工具菜单，打开 Canopy 命令提示符，这只是打开一个 Windows 命令提示符，其中包含运行 Canopy 中 Python 脚本所需的所有必要环境变量。确保工作目录是你安装所有课程材料的目录。

我们需要做的就是调用`spark-submit`，这是一个脚本，可以让你从 Python 运行 Spark 脚本，然后是脚本的名称`SparkDecisionTree.py`。这就是我需要做的全部。

```py
spark-submit SparkDecisionTree.py 

```

按回车键，然后它就会运行。再次强调，如果我在集群上进行操作，并且相应地创建了我的`SparkConf`，这实际上会分发到整个集群，但是现在，我们只是在我的电脑上运行它。完成后，你应该会看到下面的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/5982c23d-99f3-4cb4-818a-6d9b5041176f.png)

因此，在上面的图像中，你可以看到我们上面输入的测试人员的预测是这个人会被雇佣，我也打印出了决策树本身，所以这很酷。现在，让我们再次打开那个 Excel 文档，这样我们就可以将其与输出进行比较：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/ad3fb46a-ef3e-442a-91c1-1971c3616db4.png)

我们可以逐步进行并看看它的意思。所以，在我们的输出决策树中，实际上我们最终得到了一个深度为四的树，有九个不同的节点，再次提醒一下，这些不同的字段是如何相关的，阅读的方式是：如果（特征 1 为 0），这意味着如果受雇者为否，那么我们就会下降到特征 5。这个列表是从 0 开始的，所以在我们的 Excel 文档中，特征 5 是实习。我们可以像这样遍历整个树：这个人目前没有工作，没有做实习，没有工作经验，有学士学位，我们不会雇佣这个人。然后我们来到了 Else 子句。如果这个人有高级学位，我们会雇用他们，仅仅基于我们训练的数据。所以，你可以根据这些不同的特征 ID 回溯到你的原始数据源，记住，你总是从 0 开始计数，并据此进行解释。请注意，在这个可能的类别列表中，所有的分类特征都是用布尔值表示的，而连续数据则是用数字表示小于或大于的关系。

就是这样，使用 Spark 和 MLlib 构建的实际决策树确实有效且有意义。非常棒的东西。

# Spark 中的 K-Means 聚类

好了，让我们看看在 MLlib 中使用 Spark 的另一个例子，这一次我们将看看 k-means 聚类，就像我们使用决策树一样，我们将采用与使用 scikit-learn 相同的例子，但这次我们将在 Spark 中进行，这样它就可以扩展到大规模数据集。所以，我已经确保关闭了其他所有东西，然后我将进入我的书籍材料，打开`SparkKMeans`Python 脚本，让我们来研究一下其中的内容。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/375a2436-ca5b-41bf-94d4-a80bedf814e1.png)

好了，再次开始一些样板文件。

```py
from pyspark.mllib.clustering import KMeans 
from numpy import array, random 
from math import sqrt 
from pyspark import SparkConf, SparkContext 
from sklearn.preprocessing import scale 

```

我们将从聚类`MLlib`包中导入`KMeans`包，我们将从`numpy`中导入数组和随机数，因为，再次强调，你可以自由使用任何你想要的东西，这是一个 Python 脚本，`MLlib`通常需要`numpy`数组作为输入。我们将导入`sqrt`函数和通常的样板文件，我们需要从`pyspark`中几乎每次都导入`SparkConf`和`SparkContext`。我们还将从`scikit-learn`中导入缩放函数。再次强调，只要确保在你要运行这个作业的每台机器上都安装了`scikit-learn`，并且不要假设`scikit-learn`会因为在 Spark 上运行就会自动扩展。但是，因为我只是用它来进行缩放函数，所以没问题。好了，让我们开始设置吧。

我将首先创建一个全局变量：

```py
 K=5 

```

在这个例子中，我将使用 K 为 5 来运行 k-means 聚类，意味着有五个不同的簇。然后我将设置一个本地的`SparkConf`，只在我的桌面上运行：

```py
conf = SparkConf().setMaster("local").setAppName("SparkKMeans") 
sc = SparkContext(conf = conf) 

```

我将把我的应用程序的名称设置为`SparkKMeans`，并创建一个`SparkContext`对象，然后我可以使用它来创建在我的本地机器上运行的 RDD。我们暂时跳过`createClusteredData`函数，直接到第一行被运行的代码。

```py
data = sc.parallelize(scale(createClusteredData(100, K)))  

```

1.  我们要做的第一件事是通过并行化一些我创建的假数据来创建一个 RDD，这就是`createClusteredData`函数所做的。基本上，我告诉你创建 100 个围绕 K 个质心聚集的数据点，这与我们在本书早期玩 k-means 聚类时看到的代码几乎完全相同。如果你需要复习，可以回头看看那一章。基本上，我们要做的是创建一堆随机的质心，围绕它们通常分布一些年龄和收入数据。所以，我们正在尝试根据他们的年龄和收入对人进行聚类，并且我们正在制造一些数据点来做到这一点。这将返回我们的假数据的`numpy`数组。

1.  一旦`createClusteredData`返回结果，我会在其上调用`scale`，这将确保我的年龄和收入在可比较的尺度上。现在，记住我们学过的关于数据归一化的部分吗？这是一个重要的例子，所以我们正在使用`scale`对数据进行归一化，以便我们从 k-means 中得到好的结果。

1.  最后，我们使用`parallelize`将结果数组列表并行化为 RDD。现在我们的数据 RDD 包含了所有的假数据。我们所要做的，甚至比决策树还要简单，就是在我们的训练数据上调用`KMeans.train`。

```py
clusters = KMeans.train(data, K, maxIterations=10, 
        initializationMode="random") 

```

我们传入我们想要的簇的数量，我们的 K 值，一个参数，它对它要处理的量设置了一个上限；然后告诉它使用 k-means 的默认初始化模式，在我们开始迭代之前，我们只是随机选择我们的簇的初始质心，然后我们可以使用返回的模型。我们将称之为`clusters`。

好了，现在我们可以玩玩那个簇。

让我们从打印出每一个点的簇分配开始。所以，我们将使用一个 lambda 函数来对我们的原始数据进行转换：

```py
resultRDD = data.map(lambda point: clusters.predict(point)).cache() 

```

这个函数只是将每个点转换为从我们的模型预测的簇编号。同样，我们只是拿着我们的数据点的 RDD。我们调用`clusters.predict`来找出我们的 k-means 模型分配给它们的簇，然后我们将结果放入我们的`resultRDD`中。现在，我想在上面的代码中指出的一件事是这个缓存调用。

在做 Spark 时一个重要的事情是，每当你要在 RDD 上调用多个操作时，首先将其缓存起来是很重要的，因为当你在 RDD 上调用一个操作时，Spark 会去计算它的 DAG，以及如何最优地得到结果。

它将去执行一切以得到结果。所以，如果我在同一个 RDD 上调用两个不同的操作，它实际上会评估那个 RDD 两次，如果你想避免所有这些额外的工作，你可以缓存你的 RDD，以确保它不会被计算超过一次。

通过这样做，我们确保这两个后续操作做了正确的事情：

```py
print ("Counts by value:") 
counts = resultRDD.countByValue() 
print (counts) 

print ("Cluster assignments:") 
results = resultRDD.collect() 
print (results) 

```

为了得到实际的结果，我们将使用`countByValue`，它将给我们一个包含每个簇中有多少点的 RDD。记住，`resultRDD`目前已经将每个单独的点映射到它最终所在的簇，所以现在我们可以使用`countByValue`来计算每个给定簇 ID 看到多少个值。然后我们可以轻松地打印出那个列表。我们也可以通过在其上调用`collect`来实际查看该 RDD 的原始结果，并打印出所有的结果。

# 在一组平方误差和（WSSSE）内

现在，我们如何衡量我们的簇有多好呢？嗯，其中一个度量标准就是被称为簇内平方和误差（WSSSE），哇，听起来很高级！这个术语如此之大，以至于我们需要一个缩写，WSSSE。它就是我们看每个点到它所在簇的质心的距离，每个簇的最终质心，取这个误差的平方并对整个数据集进行求和。它只是衡量每个点距离它所在簇的质心有多远。显然，如果我们的模型中有很多误差，那么它们很可能会远离可能适用的质心，因此我们需要更高的 K 值。我们可以继续计算这个值，并用以下代码打印出来：

```py
def error(point): 
    center = clusters.centers[clusters.predict(point)] 
    return sqrt(sum([x**2 for x in (point - center)])) 

WSSSE = data.map(lambda point: error(point)).reduce(lambda x, y: x + y) 
print("Within Set Sum of Squared Error = " + str(WSSSE)) 

```

首先，我们定义了这个`error`函数，它计算每个点的平方误差。它只是取每个点到每个簇的质心的距离，并将它们相加。为了做到这一点，我们取我们的源数据，在其上调用一个 lambda 函数，实际上计算每个质心中心点的误差，然后我们可以在这里链接不同的操作。

首先，我们调用`map`来计算每个点的误差。然后为了得到代表整个数据集的最终总和，我们对该结果调用`reduce`。所以，我们使用`data.map`来计算每个点的误差，然后使用`reduce`将所有这些误差相加在一起。这就是这个小 lambda 函数的作用。基本上就是一种高级的说法，即“我希望你把这个 RDD 中的所有东西加起来得到一个最终结果”。`reduce`会一次取整个 RDD 的两个元素，并使用你提供的任何函数将它们组合在一起。我上面提供的函数是“取我要组合在一起的两行，然后把它们加起来”。

如果我们在 RDD 的每个条目中都这样做，最终我们会得到一个总和的总数。这可能看起来有点绕，但通过这种方式做，我们能够确保如果需要的话，我们实际上可以分发这个操作。我们实际上可能会在一台机器上计算数据的总和，而在另一台机器上计算不同部分的总和，然后将这两个总和组合在一起得到最终结果。这个`reduce`函数是在问，我如何将这个操作的任何两个中间结果组合在一起？

同样，如果你想让它深入你的脑海中，可以随意花点时间盯着它看一会儿。这里没有什么特别复杂的东西，但有一些重要的要点：

+   我们介绍了缓存的使用，如果你想确保在一个你将要多次使用的 RDD 上不进行不必要的重新计算。

+   我们介绍了`reduce`函数的使用。

+   我们还有一些有趣的映射函数在这里，所以这个例子中有很多可以学习的地方。

最后，它只会执行 k 均值聚类，所以让我们继续运行它。

# 运行代码

转到工具菜单，Canopy 命令提示符，然后输入：

```py
spark-submit SparkKMeans.py  

```

按回车，然后它就会运行。在这种情况下，你可能需要等待一段时间才能看到输出，但你应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/eebf988f-bcec-4c78-ab13-d495aba80c3a.png)

它起作用了，太棒了！所以记住，我们要求的输出首先是每个簇中有多少点的计数。这告诉我们，簇 0 中有 21 个点，簇 1 中有 20 个点，依此类推。它最终分布得相当均匀，这是一个好迹象。

接下来，我们打印出了每个点的聚类分配，如果你还记得，生成这些数据的原始数据是顺序的，所以看到所有的 3 都在一起，所有的 1 都在一起，所有的 4 都在一起，看起来它开始对 0 和 2 有点困惑，但总的来说，它似乎已经很好地揭示了我们最初创建数据的聚类。

最后，我们计算了 WSSSE 指标，在这个例子中为 19.97。所以，如果你想玩一下，我鼓励你这样做。你可以看到当你增加或减少 K 的值时，错误指标会发生什么变化，并思考为什么会这样。你也可以尝试一下如果不对所有数据进行归一化会发生什么，这实际上是否会以一种有意义的方式影响你的结果？这实际上是否是一件重要的事情？你还可以尝试一下在模型本身上调整`maxIterations`参数，了解它对最终结果的实际影响以及它的重要性。所以，随意尝试并进行实验。这是使用 MLlib 和 Spark 进行可扩展的 k 均值聚类。非常酷。

# TF-IDF

所以，我们 MLlib 的最后一个例子将使用一种称为词项频率逆文档频率（TF-IDF）的东西，这是许多搜索算法的基本构建块。像往常一样，听起来很复杂，但实际上并没有听起来那么糟糕。

所以，首先，让我们谈谈 TF-IDF 的概念，以及我们如何使用它来解决搜索问题。我们实际上要用 TF-IDF 来为维基百科创建一个基本的搜索引擎，使用 Apache Spark 中的 MLlib。多么棒啊？让我们开始吧。

TF-IDF 代表词项频率和逆文档频率，这基本上是两个密切相关的指标，用于进行搜索并确定给定单词与文档的相关性，给定更大的文档集。所以，例如，维基百科上的每篇文章可能都有与之关联的词项频率，互联网上的每个页面可能都有与之关联的词项频率，对于出现在该文档中的每个单词。听起来很花哨，但是，正如你将看到的那样，这是一个相当简单的概念。

+   **所有词项频率**的意思就是给定单词在给定文档中出现的频率。所以，在一个网页内，在一个维基百科文章内，在一个任何地方，给定单词在该文档内有多常见？你知道，该单词在该文档中所有单词中出现率的比率是多少？就是这样。这就是词项频率的全部。

+   **文档频率**，是相同的概念，但这次是该单词在整个文档语料库中的频率。所以，这个单词在我拥有的所有文档，所有网页，所有维基百科文章中出现的频率有多高。例如，像"a"或"the"这样的常见词汇会有很高的文档频率，我也期望它们在特定文档中也有很高的词项频率，但这并不一定意味着它们与给定文档相关。

你可以看出我们要做什么。所以，假设我们有一个给定单词的词项频率很高，文档频率很低。这两者的比率可以给我一个衡量该单词与文档相关性的指标。所以，如果我看到一个单词在给定文档中经常出现，但在整个文档空间中并不经常出现，那么我知道这个单词可能对这个特定文档传达了一些特殊的含义。它可能传达了这个文档实际上是关于什么。

所以，这就是 TF-IDF。它只是词频 x 逆文档频率的缩写，这只是一种说词频除以文档频率的花哨方式，这只是一种说这个词在这个文档中出现的频率与它在整个文档体中出现的频率相比有多频繁的花哨方式。就是这么简单。

# 实践中的 TF-IDF

在实践中，我们在使用这个方法时有一些小细节。例如，我们使用逆文档频率的实际对数值，而不是原始值，这是因为实际上单词频率往往呈指数分布。因此，通过取对数，我们最终得到了对单词的稍微更好的加权，考虑到它们的整体流行度。显然，这种方法也有一些局限性，其中之一是我们基本上假设一个文档只是一袋词，我们假设词之间没有关系。显然，这并不总是事实，实际上解析它们可能是工作的一大部分，因为你必须处理同义词和各种时态的词、缩写、大写、拼写错误等。这又回到了清理数据作为数据科学家工作的一个重要部分的想法，特别是当你处理自然语言处理的东西时。幸运的是，有一些库可以帮助你解决这个问题，但这确实是一个真正的问题，它会影响你的结果的质量。

我们在 TF-IDF 中使用的另一个实现技巧是，我们不是存储实际的字符串词及其词频和逆文档频率，为了节省空间并使事情更有效率，我们实际上将每个词映射到一个数值，我们称之为哈希值。这个想法是我们有一个函数，可以取任何词，查看它的字母，并以一种相当均匀分布的方式将其分配给一个数字范围内的一组数字。这样，我们可以用“10”来代表“represented”。现在，如果你的哈希值空间不够大，你可能会得到不同的词被同一个数字表示，这听起来比实际情况要糟糕。但是，你要确保你有一个相当大的哈希空间，这样才不太可能发生。这些被称为哈希冲突。它们可能会引起问题，但实际上，人们在英语中常用的词并不多。你可以用 10 万左右就可以了。

在规模上做到这一点是困难的。如果你想在整个维基百科上做到这一点，那么你将不得不在一个集群上运行这个。但是为了论证，我们现在只是在我们自己的桌面上运行这个，使用维基百科数据的一个小样本。

# 使用 TF-IDF

我们如何将这转化为一个实际的搜索问题？一旦我们有了 TF-IDF，我们就有了每个词对每个文档相关性的度量。我们该怎么处理呢？嗯，你可以做的一件事是为我们遇到的整个文档体中的每个词计算 TF-IDF，然后，假设我们想搜索一个给定的术语，一个给定的词。比如说我们想搜索“在我的维基百科文章集中，哪篇文章与葛底斯堡最相关？”我可以按照它们对葛底斯堡的 TF-IDF 得分对所有文档进行排序，然后只取前几个结果，这些就是我对葛底斯堡的搜索结果。就是这样。只需取你的搜索词，计算 TF-IDF，取前几个结果。就这样。

显然，在现实世界中，搜索的内容要比这多得多。谷歌有大批人在解决这个问题，实际上这个问题要复杂得多，但这实际上会给你一个能产生合理结果的工作搜索引擎算法。让我们继续深入了解它是如何工作的。

# 使用 Spark MLlib 搜索维基百科

我们将使用 Apache Spark 在 MLlib 中为维基百科的一部分构建一个实际工作的搜索算法，并且我们将在不到 50 行的代码中完成所有工作。这可能是我们在整本书中做的最酷的事情！

进入您的课程材料，打开`TF-IDF.py`脚本，这将打开 Canopy，并显示以下代码：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/87797105-16f4-4546-bb34-a435f27ece1f.png)

现在，暂停一下，让它沉淀下来，我们实际上正在创建一个工作的搜索算法，以及在不到 50 行的代码中使用它的一些示例，而且它是可扩展的。我可以在集群上运行这个。这有点令人惊讶。让我们逐步了解代码。

# 导入语句

我们将首先导入我们在 Python 中运行任何 Spark 脚本所需的`SparkConf`和`SparkContext`库，然后使用以下命令导入`HashingTF`和`IDF`。

```py
from pyspark import SparkConf, SparkContext 
from pyspark.mllib.feature import HashingTF 
from pyspark.mllib.feature import IDF 

```

所以，这就是计算我们文档中的词项频率（`TF`）和逆文档频率（`IDF`）的方法。

# 创建初始 RDD

我们将从创建本地`SparkConfiguration`和`SparkContext`的样板 Spark 内容开始，然后我们可以从中创建我们的初始 RDD。

```py
conf = SparkConf().setMaster("local").setAppName("SparkTFIDF") 
sc = SparkContext(conf = conf) 

```

接下来，我们将使用我们的`SparkContext`从`subset-small.tsv`创建一个 RDD。

```py
rawData = sc.textFile("e:/sundog-consult/Udemy/DataScience/subset-small.tsv") 

```

这是一个包含制表符分隔值的文件，它代表了维基百科文章的一个小样本。同样，您需要根据前面的代码所示更改路径，以适应您在本书课程材料安装的位置。

这给我返回了一个 RDD，其中每个文档都在 RDD 的每一行中。`tsv`文件中的每一行都包含一个完整的维基百科文档，我知道每个文档都分成了包含有关每篇文章的各种元数据的表字段。 

接下来我要做的是将它们分开：

```py
fields = rawData.map(lambda x: x.split("\t")) 

```

我将根据它们的制表符分隔符将每个文档分割成一个 Python 列表，并创建一个新的`fields` RDD，该 RDD 不再包含原始输入数据，而是包含该输入数据中每个字段的 Python 列表。

最后，我将映射这些数据，接收每个字段列表，提取字段编号三`x[3]`，我碰巧知道这是文章正文，实际的文章文本，然后我将根据空格拆分它：

```py
documents = fields.map(lambda x: x[3].split(" ")) 

```

`x[3]`的作用是从每篇维基百科文章中提取文本内容，并将其拆分成一个单词列表。我的新`documents` RDD 中每个文档都有一个条目，该 RDD 中的每个条目都包含该文档中出现的单词列表。现在，我们实际上知道在评估结果时如何称呼这些文档。

我还将创建一个新的 RDD 来存储文档名称：

```py
documentNames = fields.map(lambda x: x[1]) 

```

所有它做的就是使用这个`map`函数从相同的`fields` RDD 中提取文档名称，我碰巧知道它在字段编号一中。

所以，我现在有两个 RDD，`documents`，其中包含每个文档中出现的单词列表，以及`documentNames`，其中包含每个文档的名称。我也知道它们是按顺序排列的，所以我实际上可以稍后将它们组合在一起，以便查找给定文档的名称。

# 创建和转换 HashingTF 对象

现在，魔术发生了。我们要做的第一件事是创建一个`HashingTF`对象，并传入一个参数 100,000。这意味着我要将每个单词哈希成 100,000 个数字值中的一个：

```py
hashingTF = HashingTF(100000)  

```

它不是将单词内部表示为字符串，这样效率很低，而是尝试尽可能均匀地将每个单词分配给唯一的哈希值。我给了它多达 100,000 个哈希值可供选择。基本上，这是将单词映射到数字。

接下来，我将在实际的文档 RDD 上调用`hashingTF`的`transform`：

```py
tf = hashingTF.transform(documents) 

```

这将把每个文档中的单词列表转换为哈希值列表，代表每个单词的数字列表。

此时，实际上是以稀疏向量的形式表示，以节省更多的空间。因此，我们不仅将所有单词转换为数字，还剥离了任何缺失的数据。如果一个单词在文档中不存在，您不需要显式存储该单词不存在的事实，这样可以节省更多的空间。

# 计算 TF-IDF 分数

要计算每个文档中每个单词的 TF-IDF 分数，我们首先缓存这个`tf` RDD。

```py
tf.cache() 

```

我们这样做是因为我们将使用它不止一次。接下来，我们使用`IDF(minDocFreq=2)`，这意味着我们将忽略任何出现次数不到两次的单词：

```py
idf = IDF(minDocFreq=2).fit(tf) 

```

我们在`tf`上调用`fit`，然后在下一行上调用`transform`：

```py
tfidf = idf.transform(tf) 

```

我们最终得到的是每个文档中每个单词的 TF-IDF 分数的 RDD。

# 使用维基百科搜索引擎算法

让我们尝试并使用该算法。让我们尝试查找单词**Gettysburg**的最佳文章。如果您对美国历史不熟悉，那就是亚伯拉罕·林肯发表著名演讲的地方。因此，我们可以使用以下代码将单词 Gettysburg 转换为其哈希值：

```py
gettysburgTF = hashingTF.transform(["Gettysburg"]) 
gettysburgHashValue = int(gettysburgTF.indices[0]) 

```

然后，我们将从该哈希值中提取 TF-IDF 分数到每个文档的新 RDD 中：

```py
gettysburgRelevance = tfidf.map(lambda x: x[gettysburgHashValue])  

```

这样做的目的是从映射到每个文档的哈希值中提取 Gettysburg 的 TF-IDF 分数，并将其存储在`gettysburgRelevance` RDD 中。

然后，我们将其与`documentNames`结合起来，以便查看结果：

```py
zippedResults = gettysburgRelevance.zip(documentNames)  

```

最后，我们可以打印出答案：

```py
print ("Best document for Gettysburg is:") 
print (zippedResults.max()) 

```

# 运行算法

因此，让我们运行一下，看看会发生什么。通常情况下，要运行 Spark 脚本，我们不会只是点击播放图标。我们需要转到工具>Canopy 命令提示符。在打开的命令提示符中，我们将输入`spark-submit TF-IDF.py`，然后就可以运行了。

尽管这只是维基百科的一个小样本，但我们要求它处理相当多的数据，因此可能需要一些时间。让我们看看为 Gettysburg 找到的最佳文档匹配是什么，哪个文档具有最高的 TF-IDF 分数？

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/b7dfb9f6-8d3a-4af9-a230-6d0fccb02e54.png)

这是亚伯拉罕·林肯！这不是很棒吗？我们只需几行代码就制作了一个真正有效的搜索引擎。

这就是使用 Spark 在 MLlib 和 TF-IDF 中实际工作的搜索算法。美妙的是，如果我们有足够大的集群来运行它，我们实际上可以将其扩展到整个维基百科。

希望我们引起了您对 Spark 的兴趣，您可以看到它如何应用于以分布式方式解决相当复杂的机器学习问题。因此，这是一个非常重要的工具，我希望您在阅读本数据科学书籍时，至少要了解 Spark 如何应用于大数据问题的概念。因此，当您需要超越单台计算机的能力时，请记住，Spark 可以为您提供帮助。

# 使用 Spark 2.0 DataFrame API 进行 MLlib

本章最初是为 Spark 1 制作的，因此让我们谈谈 Spark 2 中的新功能以及 MLlib 现在存在的新功能。

因此，Spark 2 的主要特点是它越来越向 Dataframes 和 Datasets 迈进。有时 Datasets 和 Dataframes 有点交替使用。从技术上讲，Dataframe 是一组行对象的 Dataset，它们有点像 RDD，但唯一的区别在于，RDD 只包含非结构化数据，而 Dataset 具有定义的模式。

Dataset 提前知道每行中存在的信息列以及这些信息的类型。因为它提前知道该 Dataset 的实际结构，所以它可以更有效地优化事物。它还让我们将该 Dataset 的内容视为一个小型数据库，实际上，如果它在集群上，那就是一个非常大的数据库。这意味着我们可以对其执行 SQL 查询等操作。

这创建了一个更高级的 API，我们可以在 Spark 集群上查询和分析大型数据集。这是相当酷的东西。它更快，有更多的优化机会，并且有一个更高级的 API，通常更容易使用。

# Spark 2.0 MLlib 的工作原理

在 Spark 2.0 中，MLlib 正在将数据框架作为其主要 API。这是未来的发展方向，所以让我们看看它是如何工作的。我已经打开了 Canopy 中的`SparkLinearRegression.py`文件，如下图所示，让我们来看一下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/99003c6b-bbd0-4c0a-84c5-9c12af88be01.png)

正如你所看到的，首先，我们使用`ml`而不是`MLlib`，这是因为新的基于数据框架的 API 在其中。

# 实施线性回归

在这个例子中，我们要做的是实现线性回归，线性回归只是一种将一条线拟合到一组数据的方法。在这个练习中，我们将使用两个维度中的一堆虚构数据，并尝试用线性模型拟合一条线。

我们将数据分成两组，一组用于构建模型，一组用于评估模型，并比较这个线性模型在实际预测真实值时的表现。首先，在 Spark 2 中，如果要使用`SparkSQL`接口并使用数据集，你必须使用`SparkSession`对象而不是`SparkContext`。要设置一个，你可以这样做：

```py
spark = SparkSession.builder.config("spark.sql.warehouse.dir", "file:///C:/temp").appName("LinearRegression").getOrCreate() 

```

请注意，中间部分只在 Windows 和 Spark 2.0 中才需要。说实话，这是为了解决一个小 bug。所以，如果你在 Windows 上，请确保你有一个`C:/temp`文件夹。如果你想运行这个程序，如果需要的话现在就创建它。如果你不在 Windows 上，你可以删除整个中间部分，留下：`spark = SparkSession.builder.appName("LinearRegression").getOrCreate()`。

好的，所以你可以说`spark`，给它一个`appName`和`getOrCreate()`。

这很有趣，因为一旦你创建了一个 Spark 会话，如果它意外终止，你实际上可以在下次运行时从中恢复。所以，如果我们有一个检查点目录，它可以使用`getOrCreate`在上次中断的地方重新启动。

现在，我们将使用我提供的`regression.txt`文件：

```py
inputLines = spark.sparkContext.textFile("regression.txt")  

```

这只是一个文本文件，其中有两列逗号分隔的值，它们只是两列，或多或少地，线性相关的数据。它可以代表任何你想要的东西。比如，我们可以想象它代表身高和体重。所以，第一列可能代表身高，第二列可能代表体重。

在机器学习的术语中，我们谈论标签和特征，其中标签通常是你要预测的东西，而特征是数据的一组已知属性，你用它来进行预测。

在这个例子中，也许身高是标签，体重是特征。也许我们试图根据你的体重来预测身高。它可以是任何东西，都无所谓。这一切都被归一化到-1 到 1 之间的数据。数据的规模没有真正的意义，你可以假装它代表任何你想要的东西。

要在 MLlib 中使用这个，我们需要将我们的数据转换成它期望的格式：

```py
data = inputLines.map(lambda x: x.split(",")).map(lambda x: (float(x[0]), Vectors.dense(float(x[1]))))  

```

我们要做的第一件事是使用`map`函数将数据拆分成两个不同的值列表，然后将其映射到 MLlib 期望的格式。这将是一个浮点标签，然后是特征数据的密集向量。

在这种情况下，我们只有一个特征数据，即重量，所以我们有一个只包含一个元素的向量，但即使只有一个元素，MLlib 线性回归模型也需要一个密集向量。这就像旧 API 中的`labeledPoint`，但我们必须用更麻烦的方式来做。

接下来，我们需要为这些列实际分配名称。以下是执行此操作的语法：

```py
colNames = ["label", "features"] 
df = data.toDF(colNames) 

```

我们将告诉 MLlib，结果 RDD 中的这两列实际上对应于标签和特征，然后我可以将该 RDD 转换为 DataFrame 对象。此时，我有一个实际的数据框，或者说，一个包含两列标签和特征的数据集，其中标签是浮点高度，特征列是浮点权重的密集向量。这是 MLlib 所需的格式，而 MLlib 对此可能会很挑剔，因此重要的是您注意这些格式。

现在，就像我说的，我们要把我们的数据分成两半。

```py
trainTest = df.randomSplit([0.5, 0.5]) 
trainingDF = trainTest[0] 
testDF = trainTest[1] 

```

我们将在训练数据和测试数据之间进行 50/50 的拆分。这将返回两个数据框，一个用于创建模型，一个用于评估模型。

接下来，我将使用一些标准参数创建我的实际线性回归模型。

```py
lir = LinearRegression(maxIter=10, regParam=0.3, elasticNetParam=0.8) 

```

我们将调用`lir = LinearRegression`，然后我将把该模型拟合到我留出用于训练的数据集上，即训练数据框：

```py
model = lir.fit(trainingDF) 

```

这将使我得到一个模型，我可以用它来进行预测。

让我们继续做吧。

```py
fullPredictions = model.transform(testDF).cache() 

```

我将调用`model.transform(testDF)`，这将根据我的测试数据集中的权重预测身高。我实际上有已知的标签，即实际的正确身高，这将在该数据框中添加一个名为预测的新列，其中包含基于该线性模型的预测值。

我将缓存这些结果，现在我可以提取它们并将它们进行比较。因此，让我们提取预测列，就像在 SQL 中使用`select`一样，然后我将实际转换该数据框并从中提取 RDD，并使用它将其映射到这种情况下的一组浮点高度：

```py
predictions = fullPredictions.select("prediction").rdd.map(lambda x: x[0]) 

```

这些是预测的身高。接下来，我们将从标签列中获取实际的身高：

```py
labels = fullPredictions.select("label").rdd.map(lambda x: x[0]) 

```

最后，我们可以将它们重新组合在一起，然后将它们并排打印出来，看看效果如何：

```py
predictionAndLabel = predictions.zip(labels).collect() 

for prediction in predictionAndLabel: 
    print(prediction) 

spark.stop() 

```

这种方法有点复杂；我之所以这样做是为了与之前的示例保持一致，但更简单的方法是实际上选择预测和标签，将它们合并成一个 RDD，将这两列一起映射出来，然后我就不必将它们合并在一起，但无论哪种方法都可以。您还会注意到，在最后，我们需要停止 Spark 会话。

让我们看看它是否有效。让我们转到工具，Canopy 命令提示符，然后输入`spark-submit SparkLinearRegression.py`，看看会发生什么。

实际上，使用数据集运行这些 API 需要更多的前期时间，但一旦开始，它们就非常快。好了，就是这样。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/93ec3caf-319d-47fa-8712-266370ee6bcb.png)

在这里，我们将实际值和预测值并排放在一起，您可以看到它们并不太糟糕。它们往往在同一范围内。就是这样，使用 Spark 2.0 进行线性回归模型，使用 MLlib 的基于新数据框的 API。今后，您将越来越多地使用这些 API 来进行 Spark 中的 MLlib，因此请尽量选择这些 API。好了，这就是 Spark 中的 MLlib，一种实际上可以在整个集群上分发大规模计算任务以处理大型数据集的机器学习方法。这是一个很好的技能。让我们继续。

# 总结

在本章中，我们从安装 Spark 开始，然后深入介绍了 Spark，同时了解了 Spark 与 RDD 的结合工作原理。我们还通过探索不同的操作方式，介绍了创建 RDD 的各种方法。然后我们介绍了 MLlib，并详细介绍了 Spark 中决策树和 K-Means 聚类的一些示例。然后我们通过使用 TF-IDF 仅需几行代码就创建了一个搜索引擎。最后，我们看了一下 Spark 2.0 的新功能。

在下一章中，我们将介绍 A/B 测试和实验设计。


# 第十章：测试和实验设计

在本章中，我们将了解 A/B 测试的概念。我们将深入研究 t 检验、t 统计量和 p 值，这些都是用于确定结果是否真实或是随机变化结果的有用工具。我们将深入一些真实的例子，并用一些 Python 代码进行实践，并计算 t 统计量和 p 值。

接下来，我们将探讨在达成结论之前应该运行实验多长时间。最后，我们将讨论可能影响实验结果并导致您得出错误结论的潜在问题。

我们将涵盖以下主题：

+   A/B 测试概念

+   T 检验和 p 值

+   使用 Python 测量 t 统计量和 p 值

+   确定实验运行时间

+   A/B 测试的陷阱

# A/B 测试概念

如果您在一家网络公司担任数据科学家，您可能会被要求花一些时间分析 A/B 测试的结果。这些基本上是网站上的受控实验，用于衡量给定更改的影响。因此，让我们谈谈 A/B 测试是什么以及它们是如何工作的。

# A/B 测试

如果您将成为一家大型科技网络公司的数据科学家，这是您肯定会参与的事情，因为人们需要进行实验，尝试网站上的不同事物，并衡量其结果，这实际上并不像大多数人认为的那样简单。

什么是 A/B 测试？嗯，这是一个通常在网站上进行的受控实验，也可以应用于其他情境，但通常我们谈论的是网站，并且我们将测试对网站的某些更改的性能，与之前的方式进行比较。

基本上，您有一组*控制*看到旧网站的人，还有一组*测试*看到网站更改的人，这个想法是测量这两组人之间的行为差异，并使用这些数据来实际决定这个更改是否有益。

例如，我拥有一家有网站的企业，我们向人们许可软件，现在我有一个友好的橙色按钮，人们在想购买许可证时点击它，如下图左侧所示。但是，如果我将该按钮的颜色更改为蓝色，如右侧所示，会发生什么？

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/7ec84f37-58d0-43d6-9ffc-29e792d95830.jpg)

因此，在这个例子中，如果我想找出蓝色是否更好。我怎么知道呢？

我的意思是，直觉上，也许那可能更能吸引人们的注意，或者直觉上，也许人们更习惯于看到橙色的购买按钮，并更有可能点击它，我可以两种方式来解释，对吧？因此，我的内在偏见或先入之见并不重要。重要的是人们如何对我网站上的这种更改做出反应，这就是 A/B 测试的作用。

A/B 测试将人们分为看到橙色按钮的人和看到蓝色按钮的人，然后我可以测量这两组人之间的行为以及它们可能有何不同，并根据这些数据做出关于按钮颜色的决定。

您可以使用 A/B 测试测试各种事物。这些包括：

+   **设计更改**：这些可以是按钮颜色的更改、按钮的放置位置或页面的布局。

+   **用户界面流程**：因此，也许您实际上正在更改购买流程的方式以及人们在网站上结账的方式，您实际上可以衡量其影响。

+   **算法变更**：让我们考虑在第六章中讨论的电影推荐的例子，*推荐系统*。也许我想测试一个算法与另一个算法。我真正关心的不是依赖于错误指标和我的训练测试能力，而是关心如何在网站上推动购买或租赁或其他任何事情。

+   A/B 测试可以让我直接衡量这种算法对我真正关心的最终结果的影响，而不仅仅是我预测其他人已经看过的电影的能力。

+   还有其他任何您能想到的事情，任何影响用户与您的网站互动的变化都值得测试。也许甚至是使网站更快，或者任何其他事情。

+   **定价变化**：这个有点具有争议性。理论上，您可以使用 A/B 测试尝试不同的价格点，并查看它是否实际增加了销量以抵消价格差异，但是要谨慎使用这个方法。

+   如果顾客得知其他人因为没有好的原因而得到了更优惠的价格，他们就不会对您感到满意。请记住，进行定价实验可能会产生负面反弹，您不希望陷入这种情况。

# A/B 测试的转化测量

在设计网站实验时，您需要弄清楚的第一件事是，您试图优化什么？您真正想通过这个变化推动什么？这并不总是一个非常明显的事情。也许是人们的花费金额，收入的数量。我们已经讨论了使用花费金额的方差问题，但是如果您有足够的数据，很多时候您仍然可以收敛于这个指标。

然而，也许这并不是您真正想要优化的。也许您实际上是故意以亏损的价格销售某些商品，只是为了占领市场份额。您的定价策略比仅仅是顶线收入更加复杂。

也许您真正想要衡量的是利润，这可能是一个非常棘手的事情，因为许多因素会影响产品的盈利，而这些因素可能并不总是显而易见的。如果您有亏损产品，这个实验将忽略这些产品本应产生的效果。也许您只关心在网站上推动广告点击，或者订单数量以减少方差，也许人们对此无所谓。

最重要的是，您必须与正在进行测试的业务所有者交谈，并弄清楚他们试图优化什么。他们被衡量在什么上？他们的成功是如何衡量的？他们的关键绩效指标或者无论 NBAs 想称呼它什么？并确保我们正在衡量对他们来说最重要的事情。

您也可以同时测量多个指标，不必选择一个，实际上可以报告许多不同事物的影响：

+   收入

+   利润

+   点击

+   广告展示次数

如果所有这些事情都朝着正确的方向发展，那就是这种变化在多方面产生了积极影响的非常强有力的迹象。那么，为什么要限制自己只关注一个指标呢？只需确保您知道在实验成功的标准中哪个指标最重要。

# 如何归因转化

另一件需要注意的事情是将转化归因于下游的变化。如果您试图推动的行为不是用户立即在体验到您正在测试的事物后发生的，情况就会变得有些棘手。

假设我改变了 A 页面上按钮的颜色，用户然后转到 B 页面并做了其他事情，最终从 C 页面购买了东西。

那么，谁应该得到这次购买的功劳？是 A 页面，还是 B 页面，还是介于两者之间的某个页面？我是否应根据用户点击次数来折扣转化的功劳？我是否应该丢弃任何不是在看到变化后立即发生的转化行为？这些都是复杂的事情，通过调整您对转化和您正在测量的变化之间的不同距离的计算方式，很容易产生误导性的结果。

# 方差是您的敌人

另一件你需要真正内化的事情是，方差是你进行 A/B 测试时的敌人。

一个非常常见的错误是，那些不懂得如何运用数据科学的人会在网页上进行测试，比如蓝色按钮对比橙色按钮，然后运行一周，然后从每个组中得到平均花费金额。然后他们会说：“哦看！平均而言，点击蓝色按钮的人比点击橙色按钮的人多花了一美元；蓝色太棒了，我喜欢蓝色，我要在整个网站上都用蓝色了！”

但实际上，他们可能只是看到了购买的随机变化。他们没有足够大的样本，因为人们不倾向于购买很多。你的网站可能有很多浏览量，但与此相比，你可能没有很多购买量，而且这些购买金额可能有很大的差异，因为不同的产品成本不同。

因此，如果你不了解这些结果对方差的影响，你很容易做出错误的决定，最终会让你的公司损失金钱，而不是赚钱。我们将在本章后面讨论一些测量和考虑这一点的主要方法。

你需要确保你的业务所有者明白这是一个重要的影响，你需要在进行 A/B 测试或者在网站上进行的任何实验之后，做出商业决策之前，对其进行量化和理解。

有时候你需要选择一个方差较小的转化指标。可能是你网站上的数字意味着你必须运行多年的实验才能得到一个基于收入或花费金额的显著结果。

有时，如果你正在观察多个指标，比如订单金额或订单数量，它的方差较小，你可能会在订单数量上看到信号，而在收入上看不到信号，例如。最终，这取决于判断。如果你看到订单数量有显著增加，而收入增长不那么显著，那么你必须说：“嗯，我认为这里可能有一些真实和有益的事情发生。”

然而，统计和数据大小能告诉你的唯一的是，一个效应是真实的概率。最终，你必须决定它是否是真实的。所以，让我们更详细地讨论如何做到这一点。

这里的关键是，仅仅看平均值的差异是不够的。当你试图评估实验结果时，你需要考虑方差。

# t 检验和 p 值

A/B 测试产生的变化是否真的是你所改变的结果，还是只是随机变化？嗯，我们有一些统计工具可以使用，叫做 t 检验或 t 统计量，以及 p 值。让我们更多地了解一下它们是什么，以及它们如何帮助你确定一个实验是否有效。

目标是弄清楚一个结果是否是真实的。这只是数据本身固有的随机变化的结果，还是我们看到了控制组和测试组之间的实际、统计显著的行为变化？t 检验和 p 值是计算这一点的一种方法。

记住，“统计显著性”并没有一个具体的含义。最终，这必须是一个判断。你必须选择一个概率值，你会接受一个结果是真实的或不真实的。但仍然会有可能是随机变化的结果，你必须确保你的利益相关者明白这一点。

# t 统计量或 t 检验。

让我们从**t-统计**开始，也被称为 t-检验。它基本上是衡量这两组行为之间的差异的一种方式，即你的控制组和处理组之间的差异，以标准误差的单位表示。它基于标准误差，考虑了数据本身固有的方差，因此通过将一切都标准化为标准误差，我们得到了一些考虑到方差的这两组行为变化的度量。

解释 t-统计的方法是，高 t 值意味着这两组之间可能存在真正的差异，而低 t 值意味着差异不大。你必须决定你愿意接受的门槛是多少？t-统计的符号将告诉你这是一个正向还是负向的变化。

如果你将你的控制组与处理组进行比较，最终得到一个负的 t-统计，这意味着这是一个不好的改变。你最终希望 t-统计的绝对值很大。什么样的 t-统计值被认为是大的？这是有争议的。我们很快会看一些例子。

现在，这假设了你有一个正态分布的行为，当我们谈论人们在网站上的花费时，这通常是一个合理的假设。人们的花费往往有一个正态分布。

然而，还有更精细的 t-统计的版本，你可能想要针对其他特定情况进行研究。例如，当你谈论点击率时，有一种叫做**费舍尔精确检验**的东西，当你谈论每个用户的交易时，比如他们看了多少网页，有**E-检验**，还有**卡方检验**，通常与订单数量有关。有时你会想要查看给定实验的所有这些统计数据，并选择最适合你所尝试做的事情的那个。

# p 值

现在，谈论 p 值比 t-统计要容易得多，因为你不必考虑，我们谈论多少个标准偏差？实际值是什么意思？p 值对人们来说更容易理解，这使得它成为一个更好的工具，用来向你业务中的利益相关者传达实验结果。

p 值基本上是这个实验满足零假设的概率，也就是说，控制组和处理组的行为之间没有真正的差异的概率。低 p 值意味着它没有影响的概率很低，有点双重否定的意思，所以这有点反直觉，但最终你只需要明白，低 p 值意味着你的改变有真正的影响的概率很高。

你想要看到的是高 t-统计和低 p-值，这将意味着显著的结果。现在，在你开始实验之前，你需要决定你的成功门槛是多少，并且这意味着与业务负责人一起决定门槛。

那么，你愿意接受什么样的 p 值作为成功的衡量标准？是 1%？是 5%？再次强调，这基本上是没有真正效应的可能性，只是随机方差的结果。这最终是一个判断。很多时候人们使用 1%，有时如果他们感觉有点冒险，他们会使用 5%，但总会有那种可能性，你的结果只是偶然的，是随机数据。

然而，你可以选择愿意接受的概率，认为这是一个真正的效应，值得投入生产。

当你的实验结束时，我们稍后会讨论何时宣布实验结束，你需要测量你的 p 值。如果它小于你决定的阈值，那么你可以拒绝零假设，并且可以说“嗯，有很高的可能性，这种变化产生了真正的正面或负面结果。”

如果结果是正面的，那么你可以将这种变化推广到整个网站，它不再是一个实验，而是你网站的一部分，希望随着时间的推移能给你带来更多的收入，如果结果是负面的，你希望在它给你造成更多损失之前摆脱它。

记住，当你的实验结果是负面的时候，运行 A/B 测试是有真正成本的。所以，你不想运行太长时间，因为有可能会亏钱。

这就是为什么你要每天监控实验结果，所以如果有早期迹象表明这种变化对网站造成了可怕的影响，也许有 bug 或者其他可怕的东西，你可以在必要时提前终止它，并限制损失。

让我们看一个实际的例子，看看如何使用 Python 测量 t 统计量和 p 值。

# 使用 Python 测量 t 统计量和 p 值

让我们制造一些实验数据，并使用 t 统计量和 p 值来确定给定实验结果是否是真实效果。我们将实际制造一些假的实验数据，并对它们进行 t 统计量和 p 值的计算，看看它是如何工作的，以及如何在 Python 中计算它。

# 在一些实验数据上运行 A/B 测试

假设我们在一个网站上运行 A/B 测试，我们已经随机将用户分为两组，A 组和 B 组。A 组将成为我们的测试对象，我们的处理组，而 B 组将成为我们的对照组，基本上是网站以前的样子。我们将使用以下代码设置这个：

```py
import numpy as np 
from scipy import stats 

A = np.random.normal(25.0, 5.0, 10000) 
B = np.random.normal(26.0, 5.0, 10000) 

stats.ttest_ind(A, B) 

```

在这个代码示例中，我们的处理组（A）将具有随机分布的购买行为，他们平均每笔交易花费 25 美元，标准差为五，样本量为一万，而旧网站的平均每笔交易为 26 美元，标准差和样本量相同。我们基本上在看一个实验结果是负面的实验。要计算 t 统计量和 p 值，你只需要使用 `scipy` 中的 `stats.ttest_ind` 方法。你只需要将处理组和对照组传递给它，就会得到 t 统计量，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/fe9d3310-3841-482e-b97a-098ff9084522.jpg)

在这种情况下，我们有一个 t 统计量为 -14。负号表示这是一个负面的变化，这是一件坏事。而 p 值非常非常小。因此，这意味着这种变化是由随机机会产生的可能性极低。

记住，为了宣布显著性，我们需要看到一个高 t 值 t 统计量和一个低 p 值。

这正是我们在这里看到的，我们看到 -14，这是一个非常高的 t 统计量的绝对值，负号表示这是一件坏事，而极低的 P 值告诉我们，几乎没有可能这只是随机变化的结果。

如果你在现实世界中看到这些结果，你会尽快终止这个实验。

# 当两组之间没有真正的差异时

作为一个理智的检查，让我们改变一下，使得这两组之间没有真正的差异。所以，我要改变 B 组，在这种情况下是对照组，使其与处理组相同，其中均值为 25，标准差不变，样本量也不变，如下所示：

```py
B = np.random.normal(25.0, 5.0, 10000) 

stats.ttest_ind(A, B) 

```

如果我们继续运行这个实验，你会看到我们的 t 检验结果现在低于一： 

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/81066228-b08e-4aa3-85af-015efe4ac2b3.jpg)

请记住，这是标准差的问题。因此，这意味着除非我们的 p 值更高，超过 30%，否则那里可能没有真正的变化。

现在，这些仍然是相对较高的数字。您可以看到随机变化可能是一种隐匿的东西。这就是为什么您需要提前决定 p 值的可接受限制。

您知道，您事后可能会看到这一点并说，“30%的几率，你知道，那还不错，我们可以接受”，但是，实际上，您希望看到的是低于 5%的 p 值，理想情况下是低于 1%，而 30%的值意味着实际上并不是一个强有力的结果。因此，不要在事后为其辩护，进入实验时要知道您的阈值是多少。

# 样本量是否有影响？

让我们对样本量进行一些更改。我们在相同条件下创建这些集合。让我们看看通过增加样本量是否实际上会在行为上产生差异。

# 样本量增加到六位数

所以，我们将从`10000`增加到`100000`个样本，如下所示：

```py
A = np.random.normal(25.0, 5.0, 100000) 
B = np.random.normal(25.0, 5.0, 100000) 

stats.ttest_ind(A, B) 

```

在以下输出中，您可以看到实际上 p 值略低，t 检验略高，但仍不足以宣布真正的差异。它实际上是朝着你不希望的方向发展的？挺有趣的！

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/f580eba5-7fdb-41e9-a9fd-303797a27454.jpg)

但这些仍然是高值。再次强调，这只是随机变异的影响，它可能比您意识到的要大。特别是在网站上，当您谈论订单金额时。

# 样本量增加到七位数

让我们将样本量实际增加到`1000000`，如下所示：

```py
A = np.random.normal(25.0, 5.0, 1000000) 
B = np.random.normal(25.0, 5.0, 1000000) 

stats.ttest_ind(A, B) 

```

这是结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/7b3983dd-a665-431d-adee-6de6bb8b15ee.jpg)

那会有什么影响呢？现在，我们的 t 统计量又低于 1，而我们的值约为 35%。

随着样本量的增加，我们会看到这种波动在某种程度上有所变化。这意味着从 10000 个样本增加到 100000 个样本再到 1000000 个样本，最终结果不会改变。进行这种实验是了解您可能需要运行实验的时间的一种好方法。需要多少样本才能得到显著结果？如果您事先了解数据的分布情况，您实际上可以运行这些模型。

# A/A 测试

如果我们将集合与自身进行比较，这被称为 A/A 测试，如下面的代码示例所示：

```py
stats.ttest_ind(A, A) 

```

我们可以在以下输出中看到，t 统计量为`0`，p 值为`1.0`，因为实际上这些集合之间根本没有任何差异。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-ds-py-ml/img/8cd38bc5-b4f5-49db-8149-bad83224a650.jpg)

现在，如果您使用真实的网站数据进行运行，您观察到相同的人群并且看到不同的值，这表明您运行测试的系统本身存在问题。归根结底，就像我说的，这都是一种判断。

继续尝试，看看不同标准差对初始数据集或均值差异以及不同样本量的影响。我只是希望您深入研究，尝试运行这些不同的数据集，看看它们对 t 统计量和 p 值的影响。希望这能让您更直观地理解如何解释这些结果。

再次强调的重要一点是，您要寻找一个较大的 t 统计量和一个较小的 p 值。P 值可能是您想要向业务传达的内容。记住，p 值越低越好，最好在单个数字以下，理想情况下在 1%以下，然后再宣布胜利。

我们将在本章的其余部分更多地讨论 A/B 测试。SciPy 使得计算给定数据集的 t 统计量和 p 值变得非常容易，因此你可以非常容易地比较控制组和处理组之间的行为，并测量这种效果是真实的概率还是仅仅是随机变化的结果。确保你关注这些指标，并且在进行比较时测量你关心的转化指标。

# 确定运行实验的时间长短

你运行实验多长时间？实际上要得到结果需要多长时间？在什么时候放弃？让我们更详细地讨论一下。

如果你公司的某人开发了一个新的实验，一个他们想要测试的新变化，那么他们对于看到它成功有着切身利益。他们投入了大量的工作和时间，他们希望它能够成功。也许你已经进行了几周的测试，但仍然没有在这个实验上取得显著的结果，无论是积极的还是消极的。你知道他们会希望继续无限期地运行它，希望最终能够显示出积极的结果。你需要决定你愿意运行这个实验多长时间。

我怎么知道何时结束 A/B 测试？我的意思是，预测在你能够取得显著结果之前需要多长时间并不总是直截了当的，但显然，如果你取得了显著结果，如果你的 p 值已经低于 1%或 5%或你选择的任何阈值，那么你就结束了。

在那一点上，你可以中止实验，要么更广泛地推出变化，要么移除它，因为它实际上产生了负面影响。你总是可以告诉人们重新尝试，利用他们从实验中学到的东西，也许做一些改变再试一次，减轻一点打击。

另一种可能发生的情况是根本没有收敛。如果你在 p 值上没有看到任何趋势，那可能是一个好迹象，表明你不会很快看到这种收敛。无论你运行多长时间，它都不会对行为产生足够的影响，甚至无法测量。

在这些情况下，你每天想做的是为给定实验绘制一个图表，显示 p 值、t 统计量，或者你用来衡量这个实验成功的任何东西，如果你看到一些有希望的东西，你会发现 p 值随着时间的推移而下降。因此，它获得的数据越多，你的结果就应该变得更加显著。

现在，如果你看到的是一条平直的线，或者一条到处都是的线，那就告诉你 p 值不会有任何变化，无论你运行这个实验多长时间，它都不会发生。你需要事先达成一致，即在你没有看到 p 值的任何趋势的情况下，你愿意运行这个实验多长时间？是两周？还是一个月？

另一件需要记住的事情是，同时在网站上运行多个实验可能会混淆你的结果。

实验所花费的时间是一种宝贵的资源，你无法在世界上创造更多的时间。在一年内，你只能运行尽可能多的实验。因此，如果你花费太多时间运行一个几乎没有机会收敛到结果的实验，那么你就错过了在这段时间内运行另一个潜在更有价值的实验的机会。

在实验链接上划清界限是很重要的，因为当你在网站上进行 A/B 测试时，时间是非常宝贵的，至少在你有更多的想法而没有时间的情况下，这种情况希望是存在的。确保你在进行给定实验测试的时间上设定了上限，如果你没有看到 p 值中令人鼓舞的趋势，那么就是时候停止实验了。

# A/B 测试的陷阱

我想要强调的一个重要观点是，即使你使用 p 值以一种合理的方式来衡量 A/B 测试的结果，这也不是绝对的。有很多因素实际上可能会扭曲你实验的结果，并导致你做出错误的决定。让我们来看看 A/B 测试中的一些陷阱，以及如何注意避免它们。让我们谈谈 A/B 测试的一些陷阱。

说一个实验的 p 值为 1%，听起来很正式，意味着某个实验结果是由偶然结果或随机变化引起的可能性只有 1%，但这仍然不是衡量实验成功的全部和终极标准。有很多因素可能会扭曲或混淆你的结果，你需要意识到这一点。所以，即使你看到一个非常令人鼓舞的 p 值，你的实验仍然可能在欺骗你，你需要了解可能导致这种情况发生的因素，以免做出错误的决定。

记住，相关性不意味着因果关系。

即使进行了精心设计的实验，你只能说这种效果有一定的概率是由你所做的改变引起的。

最终，总会有可能没有真正的效果，或者你甚至可能在测量错误的效果。这可能仍然是随机事件，可能还有其他事情发生，你有责任确保业主明白这些实验结果需要被解释，它们只是决策的一部分。

它们不能成为他们决策的全部和终极标准，因为结果中存在误差，并且有可能扭曲这些结果。如果这种改变还有一些更大的商业目标，而不仅仅是驱动短期收入，那么这也需要考虑在内。

# 新奇效应

一个问题是新奇效应。A/B 测试的一个主要弱点是它们倾向于运行的短时间范围，这会导致一些问题。首先，改变可能会产生长期效果，而你无法测量到这些效果，但也有一定效果，因为网站上的某些东西变得与众不同。

例如，也许你的客户习惯于在网站上一直看到橙色按钮，如果出现蓝色按钮，它会因为与众不同而吸引他们的注意。然而，随着新客户的到来，他们从未见过你的网站，他们不会注意到这种不同，随着时间的推移，即使是你的老客户也会习惯新的蓝色按钮。很可能，如果你在一年后进行同样的测试，结果可能没有任何差异，或者可能会相反。

我很容易能想象到这样一种情况：你测试橙色按钮和蓝色按钮，前两周蓝色按钮获胜。人们购买更多，因为他们更喜欢它，因为它与众不同。但一年过去了，我可能可以再次进行实验，将蓝色按钮与橙色按钮对比，橙色按钮会再次获胜，仅仅因为橙色按钮与众不同，新颖，吸引人们的注意力。

因此，如果你做出了一些有争议的改变，最好的办法是稍后重新运行实验，看看是否能够复制其结果。这实际上是我知道的唯一解决新奇效应的方法；当它不再新奇时再次进行测量，当它不再只是因为不同而吸引人们注意的改变时。

我真的无法低估理解这一点的重要性。这可能会扭曲很多结果，使你倾向于将积极的变化归因于那些实际上并不值得的事情。在这种情况下，仅仅因为与众不同并不是一种美德。

# 季节性影响

如果你在圣诞节期间进行实验，人们的行为不会像在其他时间一样。他们在那个季节的花钱方式肯定不同，他们在家里花更多时间，可能有点放松，所以人们的心态不同。

这甚至可能与天气有关，夏天人们的行为会有所不同，因为天气炎热，他们感到有点懒散，更经常度假。也许如果你碰巧在高人口密集地区的一次可怕风暴期间进行实验，这也可能会扭曲你的结果。

再次，只需注意潜在的季节性影响，节假日是需要注意的重要因素，如果实验是在已知具有季节性的时间段运行的，那么始终要以一颗谨慎的心对待你的经验。

你可以通过定量方法来确定这一点，实际上观察你试图衡量的指标作为成功指标的行为，无论你称之为什么，你的转化指标，然后观察它在去年同一时间段的行为。你是否看到每年都有季节性波动？如果是这样，你就要尽量避免在这些高峰或低谷期间进行实验。

# 选择偏差

另一个可能会扭曲你的结果的潜在问题是选择偏差。非常重要的是，顾客被随机分配到你的对照组或处理组，你的 A 组或 B 组。

然而，有微妙的方式使得那种随机分配实际上可能并不那么随机。例如，假设你正在对顾客 ID 进行哈希处理，以将它们放入一个桶中。也许在哈希函数如何影响较低顾客 ID 和较高顾客 ID 的人之间存在一些微妙的偏差。这可能导致将所有长期忠诚的顾客放入对照组，将那些不太了解你的新顾客放入处理组。

那时你所测量的只是老客户和新客户之间的行为差异。审计你的系统非常重要，以确保在将人们分配到对照组或处理组时没有选择偏差。

你还需要确保分配是固定的。如果你在整个会话期间测量了一项变化的影响，你需要测量他们是否在 A 页面看到了变化，但是在 C 页面上他们实际上进行了转化，你必须确保他们在这些点击之间没有切换组。因此，你需要确保在给定的会话中，人们保持在同一组中，而如何定义一个会话也可能变得有点模糊。

这些都是使用像 Google 实验、Optimizely 或类似公司的成熟现成框架可以帮助解决的问题，这样你就不必在所有这些问题上重新发明轮子。如果你的公司有自己开发的内部解决方案，因为他们不愿意与外部公司分享数据，那么审计是否存在选择偏差是值得的。

# 审计选择偏差问题

审计选择偏差问题的一种方法是运行所谓的 A/A 测试，就像我们之前看到的那样。因此，如果你实际上进行了一个实验，处理组和对照组之间没有差异，你不应该在最终结果中看到差异。当你比较这两个事物时，行为不应该有任何改变。

A/A 测试可以是测试你的 A/B 框架本身的好方法，并确保没有固有的偏见或其他问题，例如会话泄漏等，这些都需要解决。

# 数据污染

另一个大问题是数据污染。我们详细讨论了清理输入数据的重要性，尤其是在 A/B 测试的背景下。如果你的网站上有一个机器人，一个恶意的网络爬虫一直在爬取你的网站，进行不自然的交易量，会发生什么？如果那个机器人最终被分配到处理组或对照组呢？

一个机器人可能会扭曲你实验的结果。研究进入你的实验的输入非常重要，寻找异常值，然后分析这些异常值，以及它们是否应该被排除。你是否真的让一些机器人泄漏到你的测量中，并且它们是否扭曲了你实验的结果？这是一个非常常见的问题，你需要意识到这一点。

有恶意的机器人存在，有人试图入侵你的网站，也有善意的爬虫只是为了搜索引擎或其他目的爬取你的网站。网站上存在各种奇怪的行为，你需要过滤掉这些行为，找到真正的客户，而不是这些自动脚本。这实际上可能是一个非常具有挑战性的问题。这也是使用像 Google Analytics 这样的现成框架的另一个原因，如果你可以的话。

# 归因错误

我们之前简要谈到了归因错误。如果你实际上使用了变化的下游行为，那就会涉及到一个灰色地带。

你需要了解如何根据距离的函数来计算这些转化，并与你的业务利益相关者事先达成一致，以确定你将如何衡量这些影响。你还需要意识到，如果你同时运行多个实验，它们是否会相互冲突？是否存在页面流，使得某人可能在同一会话中遇到两个不同的实验？

如果是这样，那将是一个问题，你必须根据自己的判断力来判断这些变化是否会以某种有意义的方式相互干扰，并以某种有意义的方式影响客户的行为。同样，你需要对这些结果持保留态度。有很多因素可能会使结果产生偏差，你需要意识到这一点。只要意识到这一点，并确保你的业务所有者也意识到 A/B 测试的局限性，一切都会没问题的。

此外，如果你没有足够长的时间来进行实验，你需要对这些结果持保留态度，并在以后的不同时间段进行重新测试。

# 总结

在本章中，我们讨论了什么是 A/B 测试以及围绕它们的挑战。我们举了一些例子，说明了如何使用 t 统计量和 p 值指标来测量方差的影响，并介绍了使用 Python 进行 t 检验的编码和测量。然后我们讨论了 A/B 测试的短期性质及其局限性，例如新奇效应或季节效应。

这也是我们在这本书中的时间。恭喜你走到这一步，这是一个严肃的成就，你应该为自己感到自豪。我们在这里涵盖了很多材料，我希望你至少理解了这些概念，并且对今天数据科学中使用的大多数技术有一些实际经验。这是一个非常广泛的领域，所以我们触及了一点点所有的东西。所以，再次恭喜。

如果你想在这个领域进一步发展你的职业，我真的鼓励你和你的老板谈谈。如果你在一家公司工作，这家公司有自己的一些有趣的数据集，看看你能否玩弄一下。显然，在你使用公司拥有的任何数据之前，你需要先和老板谈一下，因为可能会有一些围绕它的隐私限制。你要确保你没有侵犯公司客户的隐私，这可能意味着你只能在工作场所的受控环境中使用或查看这些数据。所以，在你这样做的时候要小心。

如果你能得到实际在工作中加班几天，并且玩弄一些这些数据集，看看你能做些什么，这不仅表明你有主动性让自己成为一个更好的员工，你可能会发现一些对你的公司有价值的东西，这可能会让你看起来更好，甚至可能导致内部调动，也许是进入一个与你想要发展职业方向更直接相关的领域。

所以，如果你想从我这里得到一些职业建议，我经常被问到的一个常见问题是，“嘿，我是一名工程师，我想更多地涉足数据科学，我该怎么做？”最好的方法就是去做，你知道，实际做一些副业项目，并展示你能做到，并从中展示一些有意义的结果。向你的老板展示，并看看它会带你去哪里。祝你好运。
