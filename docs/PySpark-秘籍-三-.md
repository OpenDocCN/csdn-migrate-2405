# PySpark 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/226400CAE1A4CC3FBFCCD639AAB45F06`](https://zh.annas-archive.org/md5/226400CAE1A4CC3FBFCCD639AAB45F06)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用 MLlib 进行机器学习

在本章中，我们将介绍如何使用 PySpark 的 MLlib 模块构建机器学习模型。尽管它现在已经被弃用，大多数模型现在都被移动到 ML 模块，但如果您将数据存储在 RDD 中，您可以使用 MLlib 进行机器学习。您将学习以下示例：

+   加载数据

+   探索数据

+   测试数据

+   转换数据

+   标准化数据

+   创建用于训练的 RDD

+   预测人口普查受访者的工作小时数

+   预测人口普查受访者的收入水平

+   构建聚类模型

+   计算性能统计

# 加载数据

为了构建一个机器学习模型，我们需要数据。因此，在开始之前，我们需要读取一些数据。在这个示例中，以及在本章的整个过程中，我们将使用 1994 年的人口普查收入数据。

# 准备工作

要执行这个示例，您需要一个可用的 Spark 环境。如果没有，您可能需要回到第一章，*安装和配置 Spark*，并按照那里找到的示例进行操作。

数据集来自[`archive.ics.uci.edu/ml/datasets/Census+Income`](http://archive.ics.uci.edu/ml/datasets/Census+Income)。

数据集位于本书的 GitHub 存储库的`data`文件夹中。

本章中您需要的所有代码都可以在我们为本书设置的 GitHub 存储库中找到：[`bit.ly/2ArlBck`](http://bit.ly/2ArlBck)；转到`Chapter05`，打开`5\. Machine Learning with MLlib.ipynb`笔记本。

不需要其他先决条件。

# 如何做...

我们将数据读入 DataFrame，这样我们就可以更容易地处理。稍后，我们将把它转换成带标签的 RDD。要读取数据，请执行以下操作：

```py
census_path = '../data/census_income.csv'

census = spark.read.csv(
    census_path
    , header=True
    , inferSchema=True
)
```

# 它是如何工作的...

首先，我们指定了我们数据集的路径。在我们的情况下，与本书中使用的所有其他数据集一样，`census_income.csv`位于`data`文件夹中，可以从父文件夹中访问。

接下来，我们使用`SparkSession`的`.read`属性，它返回`DataFrameReader`对象。`.csv(...)`方法的第一个参数指定了数据的路径。我们的数据集在第一行中有列名，因此我们使用`header`选项指示读取器使用第一行作为列名。`inferSchema`参数指示`DataFrameReader`自动检测每列的数据类型。

让我们检查数据类型推断是否正确：

```py
census.printSchema()
```

上述代码产生以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00107.jpeg)

正如您所看到的，某些列的数据类型被正确地检测到了；如果没有`inferSchema`参数，所有列将默认为字符串。

# 还有更多...

然而，我们的数据集存在一个小问题：大多数字符串列都有前导或尾随空格。以下是您可以纠正此问题的方法：

```py
import pyspark.sql.functions as func

for col, typ in census.dtypes:
    if typ == 'string':
        census = census.withColumn(
            col
            , func.ltrim(func.rtrim(census[col]))
        )
```

我们循环遍历`census` DataFrame 中的所有列。

DataFrame 的`.dtypes`属性是一个元组列表，其中第一个元素是列名，第二个元素是数据类型。

如果列的类型等于字符串，我们应用两个函数：`.ltrim(...)`，它删除字符串中的任何前导空格，以及`.rtrim(...)`，它删除字符串中的任何尾随空格。`.withColumn(...)`方法不会附加任何新列，因为我们重用相同的列名：`col`。

# 探索数据

直接进入对数据建模是几乎每个新数据科学家都会犯的错误；我们太急于获得回报阶段，所以忘记了大部分时间实际上都花在清理数据和熟悉数据上。在这个示例中，我们将探索人口普查数据集。

# 准备工作

要执行这个示例，您需要一个可用的 Spark 环境。您应该已经完成了之前的示例，其中我们将人口普查数据加载到了 DataFrame 中。

不需要其他先决条件。

# 如何做...

首先，我们列出我们想要保留的所有列：

```py
cols_to_keep = census.dtypes

cols_to_keep = (
    ['label','age'
     ,'capital-gain'
     ,'capital-loss'
     ,'hours-per-week'
    ] + [
        e[0] for e in cols_to_keep[:-1] 
        if e[1] == 'string'
    ]
)
```

接下来，我们选择数值和分类特征，因为我们将分别探索这些特征：

```py
census_subset = census.select(cols_to_keep)

cols_num = [
    e[0] for e in census_subset.dtypes 
    if e[1] == 'int'
]
cols_cat = [
    e[0] for e in census_subset.dtypes[1:] 
    if e[1] == 'string'
]
```

# 工作原理...

首先，我们提取所有带有相应数据类型的列。

我们已经在上一节中讨论了 DataFrame 存储的`.dtypes`属性。

我们将只保留`label`，这是一个包含有关一个人是否赚超过 5 万美元的标识符的列，以及其他一些数字列。此外，我们保留所有的字符串特征。

接下来，我们创建一个仅包含所选列的 DataFrame，并提取所有的数值和分类列；我们分别将它们存储在`cols_num`和`cols_cat`列表中。

# 数值特征

让我们探索数值特征。就像在第四章中的*为建模准备数据*一样，对于数值变量，我们将计算一些基本的描述性统计：

```py
import pyspark.mllib.stat as st
import numpy as np

rdd_num = (
    census_subset
    .select(cols_num)
    .rdd
    .map(lambda row: [e for e in row])
)

stats_num = st.Statistics.colStats(rdd_num)

for col, min_, mean_, max_, var_ in zip(
      cols_num
    , stats_num.min()
    , stats_num.mean()
    , stats_num.max()
    , stats_num.variance()
):
    print('{0}: min->{1:.1f}, mean->{2:.1f}, max->{3:.1f}, stdev->{4:.1f}'
          .format(col, min_, mean_, max_, np.sqrt(var_)))
```

首先，我们进一步将我们的`census_subset`子集化为仅包含数值列。接下来，我们提取底层 RDD。由于此 RDD 的每个元素都是一行，因此我们首先需要创建一个列表，以便我们可以使用它；我们使用`.map(...)`方法实现这一点。

有关`Row`类的文档，请查看[`spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.Row`](http://spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.Row)。

现在我们的 RDD 准备好了，我们只需从 MLlib 的统计模块中调用`.colStats(...)`方法。`.colStats(...)`接受一个数值值的 RDD；这些可以是列表或向量（密集或稀疏，参见`pyspark.mllib.linalg.Vectors`的文档[`spark.apache.org/docs/latest/api/python/pyspark.mllib.html#pyspark.mllib.linalg.Vectors`](http://spark.apache.org/docs/latest/api/python/pyspark.mllib.html#pyspark.mllib.linalg.Vectors)）。返回一个`MultivariateStatisticalSummary`特征，其中包含计数、最大值、平均值、最小值、L1 和 L2 范数、非零观测数和方差等数据。

如果您熟悉 C++或 Java，traits 可以被视为虚拟类（C++）或接口（Java）。您可以在[`docs.scala-lang.org/tour/traits.html`](https://docs.scala-lang.org/tour/traits.html)上阅读更多关于 traits 的信息。

在我们的示例中，我们只选择了最小值、平均值、最大值和方差。这是我们得到的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00108.jpeg)

因此，平均年龄约为 39 岁。但是，我们的数据集中有一个 90 岁的异常值。就资本收益或损失而言，人口普查调查对象似乎赚的比亏的多。平均而言，受访者每周工作 40 小时，但我们有人工作接近 100 小时。

# 分类特征

对于分类数据，我们无法计算简单的描述性统计。因此，我们将计算每个分类列中每个不同值的频率。以下是一个可以实现这一目标的代码片段：

```py
rdd_cat = (
    census_subset
    .select(cols_cat + ['label'])
    .rdd
    .map(lambda row: [e for e in row])
)

results_cat = {}

for i, col in enumerate(cols_cat + ['label']):
    results_cat[col] = (
        rdd_cat
        .groupBy(lambda row: row[i])
        .map(lambda el: (el[0], len(el[1])))
        .collect()
    )
```

首先，我们重复了我们刚刚为数值列所做的工作，但是对于分类列：我们将`census_subset`子集化为仅包含分类列和标签，访问底层 RDD，并将每行转换为列表。我们将结果存储在`results_cat`字典中。我们遍历所有分类列，并使用`.groupBy(...)`转换来聚合数据。最后，我们创建一个元组列表，其中第一个元素是值（`el[0]`），第二个元素是频率（`len(el[1])`）。

“`.groupBy(...)`”转换输出一个列表，其中第一个元素是值，第二个元素是一个`pyspark.resultIterable.ResultIterable`对象，实际上是包含该值的 RDD 中的所有元素的列表。

现在我们已经聚合了我们的数据，让我们看看我们要处理的内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00109.jpeg)

上述列表为简洁起见进行了缩写。检查（或运行代码）我们的 GitHub 存储库中的`5\. Machine Learning with MLlib.ipynb`笔记本。

正如你所看到的，我们处理的是一个不平衡的样本：它严重偏向男性，大部分是白人。此外，在 1994 年，收入超过 50000 美元的人并不多，只有大约四分之一。

# 还有更多...

你可能想要检查的另一个重要指标是数值变量之间的相关性。使用 MLlib 计算相关性非常容易：

```py
correlations = st.Statistics.corr(rdd_num)
```

`.corr(...)`操作返回一个 NumPy 数组或数组，换句话说，一个矩阵，其中每个元素都是皮尔逊（默认）或斯皮尔曼相关系数。

要打印出来，我们只需循环遍历所有元素：

```py
for i, el_i in enumerate(abs(correlations) > 0.05):
    print(cols_num[i])

    for j, el_j in enumerate(el_i):
        if el_j and j != i:
            print(
                '    '
```

```py
                , cols_num[j]
                , correlations[i][j]
            )

    print()
```

我们只打印矩阵的上三角部分，不包括对角线。使用 enumerate 允许我们打印出列名，因为相关性 NumPy 矩阵没有列出它们。这是我们得到的内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00110.jpeg)

正如你所看到的，我们的数值变量之间并没有太多的相关性。这实际上是件好事，因为我们可以在我们的模型中使用它们，因为我们不会遭受太多的多重共线性。

如果你不知道什么是多重共线性，请查看这个讲座：[`onlinecourses.science.psu.edu/stat501/node/343`](https://onlinecourses.science.psu.edu/stat501/node/343)。

# 另请参阅

+   您可能还想查看伯克利大学的这个教程：[`ampcamp.berkeley.edu/big-data-mini-course/data-exploration-using-spark.html`](http://ampcamp.berkeley.edu/big-data-mini-course/data-exploration-using-spark.html)

# 测试数据

为了构建一个成功的统计或机器学习模型，我们需要遵循一个简单（但困难！）的规则：尽可能简单（这样它才能很好地概括被建模的现象），但不要太简单（这样它就失去了预测的主要能力）。这种情况的视觉示例如下（来自[`bit.ly/2GpRybB`](http://bit.ly/2GpRybB)）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00111.jpeg)

中间的图表显示了一个很好的拟合：模型线很好地跟随了真实函数。左侧图表上的模型线过分简化了现象，几乎没有预测能力（除了少数几点）——这是欠拟合的完美例子。右侧的模型线几乎完美地跟随了训练数据，但如果出现新数据，它很可能会错误地表示——这是一种称为过拟合的概念，即它不能很好地概括。从这三个图表中可以看出，模型的复杂性需要恰到好处，这样它才能很好地模拟现象。

一些机器学习模型有过度训练的倾向。例如，任何试图在输入数据和独立变量（或标签）之间找到映射（函数）的模型都有过拟合的倾向；这些模型包括参数回归模型，如线性或广义回归模型，以及最近（再次！）流行的神经网络（或深度学习模型）。另一方面，一些基于决策树的模型（如随机森林）即使是更复杂的模型也不太容易过拟合。

那么，我们如何才能得到恰到好处的模型呢？有四个经验法则：

+   明智地选择你的特征

+   不要过度训练，或选择不太容易过拟合的模型

+   用从数据集中随机选择的数据运行多个模型估计

+   调整超参数

在这个示例中，我们将专注于第一个要点，其余要点将在本章和下两章的一些示例中涵盖。

# 准备工作

要执行此示例，您需要一个可用的 Spark 环境。您可能已经完成了*加载数据*示例，其中我们将人口普查数据加载到了一个 DataFrame 中。

不需要其他先决条件。

# 如何做...

为了找到问题的最佳特征，我们首先需要了解我们正在处理的问题，因为不同的方法将用于选择回归问题或分类器中的特征：

+   **回归**：在回归中，您的目标（或地面真相）是*连续*变量（例如每周工作小时数）。您有两种方法来选择最佳特征：

+   **皮尔逊相关系数**：我们在上一个示例中已经涵盖了这个。如前所述，相关性只能在两个数值（连续）特征之间计算。

+   **方差分析（ANOVA）**：这是一个解释（或测试）观察结果分布的工具，条件是某些类别。因此，它可以用来选择连续因变量的最具歧视性（分类）特征。

+   **分类**：在分类中，您的目标（或标签）是两个（二项式）或多个（多项式）级别的离散变量。还有两种方法可以帮助选择最佳特征：

+   **线性判别分析（LDA）**：这有助于找到最能解释分类标签方差的连续特征的线性组合

+   ***χ²* 检验**：测试两个分类变量之间的独立性

目前，Spark 允许我们在可比较的变量之间测试（或选择）最佳特征；它只实现了相关性（我们之前涵盖的`pyspark.mllib.stat.Statistics.corr(...)`）和χ²检验（`pyspark.mllib.stat.Statistics.chiSqTest(...)`或`pyspark.mllib.feature.ChiSqSelector(...)`方法）。

在这个示例中，我们将使用`.chiSqTest(...)`来测试我们的标签（即指示某人是否赚取超过 5 万美元的指标）和人口普查回答者的职业之间的独立性。以下是一个为我们执行此操作的片段：

```py
import pyspark.mllib.linalg as ln

census_occupation = (
    census
    .groupby('label')
    .pivot('occupation')
    .count()
)

census_occupation_coll = (
    census_occupation
    .rdd
    .map(lambda row: (row[1:]))
    .flatMap(lambda row: row)
    .collect()
)

len_row = census_occupation.count()
dense_mat = ln.DenseMatrix(
    len_row
    , 2
    , census_occupation_coll
    , True)
chi_sq = st.Statistics.chiSqTest(dense_mat)

print(chi_sq.pValue)
```

# 它是如何工作的...

首先，我们导入 MLlib 的线性代数部分；稍后我们将使用一些矩阵表示。

接下来，我们建立一个数据透视表，其中我们按`occupation`特征进行分组，并按`label`列（`<=50K`或`>50K`）进行数据透视。每次出现都会被计算，结果如下表所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00112.jpeg)

接下来，我们通过访问底层 RDD 并仅选择具有映射转换的计数来展平输出：`.map(lambda row: (row[1:]))`。`.flatMap(...)`转换创建了我们需要的所有值的长列表。我们在驱动程序上收集所有数据，以便稍后创建`DenseMatrix`。

您应该谨慎使用`.collect(...)`操作，因为它会将所有数据带到驱动程序。正如您所看到的，我们只带来了数据集的高度聚合表示。

一旦我们在驱动程序上拥有所有数字，我们就可以创建它们的矩阵表示；我们将有一个 15 行 2 列的矩阵。首先，我们通过检查`census_occupation`元素的计数来检查有多少个不同的职业值。接下来，我们调用`DenseMatrix(...)`构造函数来创建我们的矩阵。第一个参数指定行数，第二个参数指定列数。第三个参数指定数据，最后一个指示数据是否被转置。密集表示如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00113.jpeg)

以更易读的格式（作为 NumPy 矩阵）呈现如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00114.jpeg)

现在，我们只需调用`.chiSqTest(...)`并将我们的矩阵作为其唯一参数传递。剩下的就是检查`pValue`以及是否拒绝了`nullHypothesis`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00115.jpeg)

因此，正如您所看到的，`pValue`是`0.0`，因此我们可以拒绝空假设，即宣称赚取 5 万美元以上和赚取 5 万美元以下的人之间的职业分布相同。因此，我们可以得出结论，正如 Spark 告诉我们的那样，结果的发生是统计独立的，也就是说，职业应该是某人赚取 5 万美元以上的强有力指标。

# 另请参阅...

+   有许多统计测试可以帮助确定两个总体（或样本）是否相似，或者它们是否遵循某些分布。为了获得良好的概述，我们建议阅读以下文档：[`www.statstutor.ac.uk/resources/uploaded/tutorsquickguidetostatistics.pdf`](http://www.statstutor.ac.uk/resources/uploaded/tutorsquickguidetostatistics.pdf)。

# 转换数据

**机器学习**（**ML**）是一个旨在使用机器（计算机）来理解世界现象并预测其行为的研究领域。为了构建一个 ML 模型，我们所有的数据都需要是数字。由于我们几乎所有的特征都是分类的，我们需要转换我们的特征。在这个示例中，我们将学习如何使用哈希技巧和虚拟编码。

# 做好准备

要执行此示例，您需要有一个可用的 Spark 环境。您可能已经完成了*加载数据*示例，其中我们将人口普查数据加载到了 DataFrame 中。

不需要其他先决条件。

# 如何做...

我们将将数据集的维度大致减少一半，因此首先我们需要提取每列中不同值的总数：

```py
len_ftrs = []

for col in cols_cat:
    (
        len_ftrs
        .append(
            (col
             , census
                 .select(col)
                 .distinct()
                 .count()
            )
        )
    )

len_ftrs = dict(len_ftrs)
```

接下来，对于每个特征，我们将使用`.HashingTF（...）`方法来对我们的数据进行编码：

```py
import pyspark.mllib.feature as feat
```

```py
final_data = (    census
    .select(cols_to_keep)
    .rdd
    .map(lambda row: [
        list(
            feat.HashingTF(int(len_ftrs[col] / 2.0))
            .transform(row[i])
            .toArray()
        ) if i >= 5
        else [row[i]] 
        for i, col in enumerate(cols_to_keep)]
    )
)

final_data.take(3)
```

# 它是如何工作的...

首先，我们循环遍历所有的分类变量，并附加一个元组，其中包括列名（`col`）和在该列中找到的不同值的计数。后者是通过选择感兴趣的列，运行`.distinct（）`转换，并计算结果值的数量来实现的。`len_ftrs`现在是一个元组列表。通过调用`dict（...）`方法，Python 将创建一个字典，该字典将第一个元组元素作为键，第二个元素作为相应的值。生成的字典如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00116.jpeg)

现在我们知道了每个特征中不同值的总数，我们可以使用哈希技巧。首先，我们导入 MLlib 的特征组件，因为那里有`.HashingTF（...）`。接下来，我们将 census DataFrame 子集化为我们想要保留的列。然后，我们在基础 RDD 上使用`.map（...）`转换：对于每个元素，我们枚举所有列，如果列的索引大于或等于五，我们创建一个新的`.HashingTF（...）`实例，然后用它来转换值并将其转换为 NumPy 数组。对于`.HashingTF（...）`方法，您唯一需要指定的是输出元素的数量；在我们的情况下，我们大致将不同值的数量减半，因此我们将有一些哈希碰撞，但这没关系。

供您参考，我们的`cols_to_keep`如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00117.jpeg)

在对我们当前的数据集`final_data`进行上述操作之后，它看起来如下；请注意，格式可能看起来有点奇怪，但我们很快将准备好创建训练 RDD：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00118.jpeg)

# 还有更多...

唯一剩下的就是处理我们的标签；如您所见，它仍然是一个分类变量。但是，由于它只有两个值，我们可以将其编码如下：

```py
def labelEncode(label):
    return [int(label[0] == '>50K')]

final_data = (
    final_data
    .map(lambda row: labelEncode(row[0]) 
         + [item 
            for sublist in row[1:] 
            for item in sublist]
        )
)
```

`labelEncode（...）`方法获取标签并检查它是否为`'>50k'`；如果是，我们得到一个布尔值 true，否则我们得到 false。我们可以通过简单地将布尔数据包装在 Python 的`int（...）`方法中来表示布尔数据为整数。

最后，我们再次使用`.map（...）`，在那里我们将`row`的第一个元素（标签）传递给`labelEncode（...）`方法。然后，我们循环遍历所有剩余的列表并将它们组合在一起。代码的这部分一开始可能看起来有点奇怪，但实际上很容易理解。我们循环遍历所有剩余的元素（`row[1:]`），并且由于每个元素都是一个列表（因此我们将其命名为`sublist`），我们创建另一个循环（`for item in sublist`部分）来提取单个项目。生成的 RDD 如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00119.jpeg)

# 另请参阅...

+   查看此链接，了解如何在 Python 中处理分类特征的概述：[`pbpython.com/categorical-encoding.html`](http://pbpython.com/categorical-encoding.html)

# 数据标准化

数据标准化（或归一化）对许多原因都很重要：

+   某些算法在标准化（或归一化）数据上收敛得更快

+   如果您的输入变量在不同的尺度上，系数的可解释性可能很难或得出的结论可能是错误的

+   对于某些模型，如果不进行标准化，最优解可能是错误的

在这个操作中，我们将向您展示如何标准化数据，因此如果您的建模项目需要标准化数据，您将知道如何操作。

# 准备工作

要执行此操作，您需要拥有一个可用的 Spark 环境。您可能已经完成了之前的操作，其中我们对人口普查数据进行了编码。

不需要其他先决条件。

# 操作步骤...

MLlib 提供了一个方法来为我们完成大部分工作。尽管以下代码一开始可能会令人困惑，但我们将逐步介绍它：

```py
standardizer = feat.StandardScaler(True, True)
sModel = standardizer.fit(final_data.map(lambda row: row[1:]))
final_data_scaled = sModel.transform(final_data.map(lambda row: row[1:]))

final_data = (
    final_data
    .map(lambda row: row[0])
    .zipWithIndex()
    .map(lambda row: (row[1], row[0]))
    .join(
        final_data_scaled
        .zipWithIndex()
        .map(lambda row: (row[1], row[0]))
    )
    .map(lambda row: row[1])
)

final_data.take(1)
```

# 工作原理...

首先，我们创建`StandardScaler(...)`对象。设置为`True`的两个参数——前者代表均值，后者代表标准差——表示我们希望模型使用 Z 分数对特征进行标准化：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00120.jpeg)，其中![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00121.jpeg)是*f*特征的第*i*^(th)观察值，μ^(*f*)是*f*特征中所有观察值的均值，σ^(*f*)是*f*特征中所有观察值的标准差。

接下来，我们使用`StandardScaler(...)`对数据进行`.fit(...)`。请注意，我们不会对第一个特征进行标准化，因为它实际上是我们的标签。最后，我们对数据集进行`.transform(...)`，以获得经过缩放的特征。

然而，由于我们不对标签进行缩放，我们需要以某种方式将其带回我们的缩放数据集。因此，首先从`final_data`中提取标签（使用`.map(lamba row: row[0])`转换）。然而，我们将无法将其与`final_data_scaled`直接连接，因为没有键可以连接。请注意，我们实际上希望以逐行方式进行连接。因此，我们使用`.zipWithIndex()`方法，它会返回一个元组，第一个元素是数据，第二个元素是行号。由于我们希望根据行号进行连接，我们需要将其带到元组的第一个位置，因为这是 RDD 的`.join(...)`的工作方式；我们通过第二个`.map(...)`操作实现这一点。

在 RDD 中，`.join(...)`操作不能明确指定键；两个 RDD 都需要是两个元素的元组，其中第一个元素是键，第二个元素是数据。

一旦连接完成，我们只需使用`.map(lambda row: row[1])`转换来提取连接的数据。

现在我们的数据看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00122.jpeg)

我们还可以查看`sModel`，以了解用于转换我们的数据的均值和标准差：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00123.jpeg)

# 创建用于训练的 RDD

在我们可以训练 ML 模型之前，我们需要创建一个 RDD，其中每个元素都是一个标记点。在这个操作中，我们将使用之前操作中创建的`final_data` RDD 来准备我们的训练 RDD。

# 准备工作

要执行此操作，您需要拥有一个可用的 Spark 环境。您可能已经完成了之前的操作，当时我们对编码的人口普查数据进行了标准化。

不需要其他先决条件。

# 操作步骤...

许多 MLlib 模型需要一个标记点的 RDD 进行训练。下一个代码片段将为我们创建这样的 RDD，以构建分类和回归模型。

# 分类

以下是创建分类标记点 RDD 的片段，我们将使用它来预测某人是否赚取超过$50,000：

```py
final_data_income = (
    final_data
    .map(lambda row: reg.LabeledPoint(
        row[0]
        , row[1:]
        )
)
```

# 回归

以下是创建用于预测人们工作小时数的回归标记点 RDD 的片段：

```py
mu, std = sModel.mean[3], sModel.std[3]

final_data_hours = (
    final_data
    .map(lambda row: reg.LabeledPoint(
        row[1][3] * std + mu
        , ln.Vectors.dense([row[0]] + list(row[1][0:3]) + list(row[1][4:]))
        )
)
```

# 工作原理...

在创建 RDD 之前，我们必须导入`pyspark.mllib.regression`子模块，因为那里可以访问`LabeledPoint`类：

```py
import pyspark.mllib.regression as reg
```

接下来，我们只需循环遍历`final_data` RDD 的所有元素，并使用`.map(...)`转换为每个元素创建一个带标签的点。

`LabeledPoint(...)`的第一个参数是标签。如果您查看这两个代码片段，它们之间唯一的区别是我们认为标签和特征是什么。

作为提醒，分类问题旨在找到观察结果属于特定类别的概率；因此，标签通常是分类的，换句话说，是离散的。另一方面，回归问题旨在预测给定观察结果的值；因此，标签通常是数值的，或者连续的。

因此，在`final_data_income`的情况下，我们使用二进制指示符，表示人口普查受访者是否赚得更多（值为 1）还是更少（标签等于 0）50,000 美元，而在`final_data_hours`中，我们使用`hours-per-week`特征（请参阅*加载数据*示例），在我们的情况下，它是`final_data` RDD 的每个元素的第五部分。请注意，对于此标签，我们需要将其缩放回来，因此我们需要乘以标准差并加上均值。

我们在这里假设您正在通过`5\. Machine Learning with MLlib.ipynb`笔记本进行工作，并且已经创建了`sModel`对象。如果没有，请返回到上一个示例，并按照那里概述的步骤进行操作。

`LabeledPoint(...)`的第二个参数是所有特征的向量。您可以传递 NumPy 数组、列表、`scipy.sparse`列矩阵或`pyspark.mllib.linalg.SparseVector`或`pyspark.mllib.linalg.DenseVector`；在我们的情况下，我们使用哈希技巧对所有特征进行了编码，因此我们将特征编码为`DenseVector`。

# 还有更多...

我们可以使用完整数据集来训练我们的模型，但是我们会遇到另一个问题：我们如何评估我们的模型有多好？因此，任何数据科学家通常都会将数据拆分为两个子集：训练和测试。

请参阅此示例的*另请参阅*部分，了解为什么这通常还不够好，您实际上应该将数据拆分为训练、测试和验证数据集。

以下是两个代码片段，显示了在 PySpark 中如何轻松完成此操作：

```py
(
    final_data_income_train
    , final_data_income_test
) = (
    final_data_income.randomSplit([0.7, 0.3])
)
```

这是第二个：

```py
(
    final_data_hours_train
    , final_data_hours_test
) = (
    final_data_hours.randomSplit([0.7, 0.3])
)
```

通过简单调用 RDD 的`.randomSplit(...)`方法，我们可以快速将 RDD 分成训练和测试子集。`.randomSplit(...)`方法的唯一必需参数是一个列表，其中每个元素指定要随机选择的数据集的比例。请注意，这些比例需要加起来等于 1。

如果我们想要获取训练、测试和验证子集，我们可以传递一个包含三个元素的列表。

# 另请参阅

+   为什么应该将数据拆分为三个数据集，而不是两个，可以在这里很好地解释：[`bit.ly/2GFyvtY`](http://bit.ly/2GFyvtY)

# 预测人口普查受访者的工作小时数

在这个示例中，我们将构建一个简单的线性回归模型，旨在预测人口普查受访者每周工作的小时数。

# 准备工作

要执行此示例，您需要一个可用的 Spark 环境。您可能已经通过之前的示例创建了用于估计回归模型的训练和测试数据集。

不需要其他先决条件。

# 如何做...

使用 MLlib 训练模型非常简单。请参阅以下代码片段：

```py
workhours_model_lm = reg.LinearRegressionWithSGD.train(final_data_hours_train)
```

# 它是如何工作的...

正如您所看到的，我们首先创建`LinearRegressionWithSGD`对象，并调用其`.train(...)`方法。

对于随机梯度下降的不同派生的很好的概述，请查看这个链接：[`ruder.io/optimizing-gradient-descent/`](http://ruder.io/optimizing-gradient-descent/)。

我们传递给方法的第一个，也是唯一需要的参数是我们之前创建的带有标记点的 RDD。不过，您可以指定一系列参数：

+   迭代次数；默认值为`100`

+   步长是 SGD 中使用的参数；默认值为`1.0`

+   `miniBatchFraction`指定在每个 SGD 迭代中使用的数据比例；默认值为`1.0`

+   `initialWeights`参数允许我们将系数初始化为特定值；它没有默认值，算法将从权重等于`0.0`开始

+   正则化类型参数`regType`允许我们指定所使用的正则化类型：`'l1'`表示 L1 正则化，`'l2'`表示 L2 正则化；默认值为`None`，无正则化

+   `regParam`参数指定正则化参数；默认值为`0.0`

+   该模型也可以拟合截距，但默认情况下未设置；默认值为 false

+   在训练之前，默认情况下，模型可以验证数据

+   您还可以指定`convergenceTol`；默认值为`0.001`

现在让我们看看我们的模型预测工作小时的效果如何：

```py
small_sample_hours = sc.parallelize(final_data_hours_test.take(10))

for t,p in zip(
    small_sample_hours
        .map(lambda row: row.label)
        .collect()
    , workhours_model_lm.predict(
        small_sample_hours
            .map(lambda row: row.features)
    ).collect()):
    print(t,p)
```

首先，从我们的完整测试数据集中，我们选择 10 个观察值（这样我们可以在屏幕上打印出来）。接下来，我们从测试数据集中提取真实值，而对于预测，我们只需调用`workhours_model_lm`模型的`.predict(...)`方法，并传递`.features`向量。这是我们得到的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00124.jpeg)

如您所见，我们的模型效果不佳，因此需要进一步改进。然而，这超出了本章和本书的范围。

# 预测人口普查受访者的收入水平

在本示例中，我们将向您展示如何使用 MLlib 解决分类问题，方法是构建两个模型：无处不在的逻辑回归和稍微复杂一些的模型，即**SVM**（**支持向量机**）。

# 准备工作

要执行此示例，您需要一个可用的 Spark 环境。您可能已经完成了*为训练创建 RDD*示例，在那里我们为估计分类模型创建了训练和测试数据集。

不需要其他先决条件。

# 如何做...

就像线性回归一样，构建逻辑回归始于创建`LogisticRegressionWithSGD`对象：

```py
import pyspark.mllib.classification as cl

income_model_lr = cl.LogisticRegressionWithSGD.train(final_data_income_train)
```

# 工作原理...

与`LinearRegressionWithSGD`模型一样，唯一需要的参数是带有标记点的 RDD。此外，您可以指定相同的一组参数：

+   迭代次数；默认值为`100`

+   步长是 SGD 中使用的参数；默认值为`1.0`

+   `miniBatchFraction`指定在每个 SGD 迭代中使用的数据比例；默认值为`1.0`

+   `initialWeights`参数允许我们将系数初始化为特定值；它没有默认值，算法将从权重等于`0.0`开始

+   正则化类型参数`regType`允许我们指定所使用的正则化类型：`l1`表示 L1 正则化，`l2`表示 L2 正则化；默认值为`None`，无正则化

+   `regParam`参数指定正则化参数；默认值为`0.0`

+   该模型也可以拟合截距，但默认情况下未设置；默认值为 false

+   在训练之前，默认情况下，模型可以验证数据

+   您还可以指定`convergenceTol`；默认值为`0.001`

在完成训练后返回的`LogisticRegressionModel(...)`对象允许我们利用该模型。通过将特征向量传递给`.predict(...)`方法，我们可以预测观察值最可能关联的类别。

任何分类模型都会产生一组概率，逻辑回归也不例外。在二元情况下，我们可以指定一个阈值，一旦突破该阈值，就会表明观察结果将被分配为等于 1 的类，而不是 0；此阈值通常设置为`0.5`。`LogisticRegressionModel(...)`默认情况下假定为`0.5`，但您可以通过调用`.setThreshold(...)`方法并传递介于 0 和 1 之间（不包括）的所需阈值值来更改它。

让我们看看我们的模型表现如何：

```py
small_sample_income = sc.parallelize(final_data_income_test.take(10))

for t,p in zip(
    small_sample_income
        .map(lambda row: row.label)
        .collect()
    , income_model_lr.predict(
        small_sample_income
            .map(lambda row: row.features)
    ).collect()):
    print(t,p)
```

与线性回归示例一样，我们首先从测试数据集中提取 10 条记录，以便我们可以在屏幕上适应它们。接下来，我们提取所需的标签，并调用`.predict(...)`类的`income_model_lr`模型。这是我们得到的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00125.jpeg)

因此，在 10 条记录中，我们得到了 9 条正确的。还不错。

在*计算性能统计*配方中，我们将学习如何使用完整的测试数据集更正式地评估我们的模型。

# 还有更多...

逻辑回归通常是用于评估其他分类模型相对性能的基准，即它们是表现更好还是更差。然而，逻辑回归的缺点是它无法处理两个类无法通过一条线分开的情况。SVM 没有这种问题，因为它们的核可以以非常灵活的方式表达：

```py
income_model_svm = cl.SVMWithSGD.train(
    final_data_income
    , miniBatchFraction=1/2.0
)
```

在这个例子中，就像`LogisticRegressionWithSGD`模型一样，我们可以指定一系列参数（我们不会在这里重复它们）。但是，`miniBatchFraction`参数指示 SVM 模型在每次迭代中仅使用一半的数据；这有助于防止过拟合。

从`small_sample_income` RDD 中计算的 10 个观察结果与逻辑回归模型的计算方式相同：

```py
for t,p in zip(
    small_sample_income
        .map(lambda row: row.label)
        .collect()
    , income_model_svm.predict(
        small_sample_income
            .map(lambda row: row.features)
    ).collect()):
    print(t,p)
```

该模型产生与逻辑回归模型相同的结果，因此我们不会在这里重复它们。但是，在*计算性能统计*配方中，我们将看到它们的不同。

# 构建聚类模型

通常，很难获得有标签的数据。而且，有时您可能希望在数据集中找到潜在的模式。在这个配方中，我们将学习如何在 Spark 中构建流行的 k-means 聚类模型。

# 准备工作

要执行此配方，您需要拥有一个可用的 Spark 环境。您应该已经完成了*标准化数据*配方，其中我们对编码的人口普查数据进行了标准化。

不需要其他先决条件。

# 如何做...

就像分类或回归模型一样，在 Spark 中构建聚类模型非常简单。以下是旨在在人口普查数据中查找模式的代码：

```py
import pyspark.mllib.clustering as clu

model = clu.KMeans.train(
```

```py
    final_data.map(lambda row: row[1])
    , 2
    , initializationMode='random'
    , seed=666
)
```

# 它是如何工作的...

首先，我们需要导入 MLlib 的聚类子模块。就像以前一样，我们首先创建聚类估计器对象`KMeans`。`.train(...)`方法需要两个参数：我们要在其中找到集群的 RDD，以及我们期望的集群数。我们还选择通过指定`initializationMode`来随机初始化集群的质心；这个的默认值是`k-means||`。其他参数包括：

+   `maxIterations`指定估计应在多少次迭代后停止；默认值为`100`

+   `initializationSteps`仅在使用默认初始化模式时有用；此参数的默认值为`2`

+   `epsilon`是一个停止标准-如果所有质心的中心移动（以欧几里德距离表示）小于此值，则迭代停止；默认值为`0.0001`

+   `initialModel`允许您指定以`KMeansModel`形式先前估计的中心；默认值为`None`

# 还有更多...

一旦估计出模型，我们就可以使用它来预测聚类，并查看我们的模型实际上有多好。但是，目前，Spark 并没有提供评估聚类模型的手段。因此，我们将使用 scikit-learn 提供的度量标准：

```py
import sklearn.metrics as m

predicted = (
    model
        .predict(
            final_data.map(lambda row: row[1])
        )
)
predicted = predicted.collect()
```

```py
true = final_data.map(lambda row: row[0]).collect()

print(m.homogeneity_score(true, predicted))
print(m.completeness_score(true, predicted))
```

聚类指标位于 scikit-learn 的`.metrics`子模块中。我们使用了两个可用的指标：同质性和完整性。同质性衡量了一个簇中的所有点是否来自同一类，而完整性得分估计了对于给定的类，所有点是否最终在同一个簇中；任一得分为 1 表示一个完美的模型。

让我们看看我们得到了什么：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00126.jpeg)

嗯，我们的聚类模型表现不佳：15%的同质性得分意味着剩下的 85%观察值被错误地聚类，我们只正确地聚类了∼12%属于同一类的所有观察值。

# 另请参阅

+   有关聚类模型评估的更多信息，您可能想查看：[`nlp.stanford.edu/IR-book/html/htmledition/evaluation-of-clustering-1.html`](https://nlp.stanford.edu/IR-book/html/htmledition/evaluation-of-clustering-1.html)

# 计算性能统计

在之前的示例中，我们已经看到了我们的分类和回归模型预测的一些值，以及它们与原始值的差距。在这个示例中，我们将学习如何完全计算这些模型的性能统计数据。

# 准备工作

为了执行这个示例，您需要有一个可用的 Spark 环境，并且您应该已经完成了本章前面介绍的*预测人口普查受访者的工作小时数*和*预测人口普查受访者的收入水平*的示例。

不需要其他先决条件。

# 如何做...

在 Spark 中获取回归和分类的性能指标非常简单：

```py
import pyspark.mllib.evaluation as ev

(...)

metrics_lm = ev.RegressionMetrics(true_pred_reg)

(...)

metrics_lr = ev.BinaryClassificationMetrics(true_pred_class_lr)
```

# 它是如何工作的...

首先，我们加载评估模块；这样做会暴露`.RegressionMetrics(...)`和`.BinaryClassificationMetrics(...)`方法，我们可以使用它们。

# 回归指标

`true_pred_reg`是一个元组的 RDD，其中第一个元素是我们线性回归模型的预测值，第二个元素是期望值（每周工作小时数）。以下是我们创建它的方法：

```py
true_pred_reg = (
    final_data_hours_test
    .map(lambda row: (
         float(workhours_model_lm.predict(row.features))
         , row.label))
)
```

`metrics_lm`对象包含各种指标：`解释方差`、`平均绝对误差`、`均方误差`、`r2`和`均方根误差`。在这里，我们只打印其中的一些：

```py
print('R²: ', metrics_lm.r2)
print('Explained Variance: ', metrics_lm.explainedVariance)
print('meanAbsoluteError: ', metrics_lm.meanAbsoluteError)
```

让我们看看线性回归模型的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00127.jpeg)

毫不意外，考虑到我们已经看到的内容，模型表现非常糟糕。不要对负的 R 平方感到太惊讶；如果模型的预测是荒谬的，R 平方可以变成负值，也就是说，R 平方的值是不合理的。

# 分类指标

我们将评估我们之前构建的两个模型；这是逻辑回归模型：

```py
true_pred_class_lr = (
    final_data_income_test
    .map(lambda row: (
        float(income_model_lr.predict(row.features))
        , row.label))
)

metrics_lr = ev.BinaryClassificationMetrics(true_pred_class_lr)

print('areaUnderPR: ', metrics_lr.areaUnderPR)
print('areaUnderROC: ', metrics_lr.areaUnderROC)
```

这是 SVM 模型：

```py
true_pred_class_svm = (
    final_data_income_test
    .map(lambda row: (
        float(income_model_svm.predict(row.features))
        , row.label))
)

metrics_svm = ev.BinaryClassificationMetrics(true_pred_class_svm)

print('areaUnderPR: ', metrics_svm.areaUnderPR)
print('areaUnderROC: ', metrics_svm.areaUnderROC)
```

两个指标——**精确率-召回率**（**PR**）曲线下的面积和**接收者操作特征**（**ROC**）曲线下的面积——允许我们比较这两个模型。

查看关于这两个指标的有趣讨论：[`stats.stackexchange.com/questions/7207/roc-vs-precision-and-recall-curves`](https://stats.stackexchange.com/questions/7207/roc-vs-precision-and-recall-curves)。

让我们看看我们得到了什么。对于逻辑回归，我们有：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00128.jpeg)

对于 SVM，我们有：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00129.jpeg)

有点令人惊讶的是，SVM 的表现比逻辑回归稍差。让我们看看混淆矩阵，看看这两个模型的区别在哪里。对于逻辑回归，我们可以用以下代码实现：

```py
(
    true_pred_class_lr
    .map(lambda el: ((el), 1))
    .reduceByKey(lambda x,y: x+y)
    .take(4)
)

```

然后我们得到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00130.jpeg)

对于 SVM，代码看起来基本相同，唯一的区别是输入 RDD：

```py
(
    true_pred_class_svm
    .map(lambda el: ((el), 1))
    .reduceByKey(lambda x,y: x+y)
    .take(4)
)
```

通过上述步骤，我们得到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00131.jpeg)

正如你所看到的，逻辑回归在预测正例和负例时更准确，因此实现了更少的误分类（假阳性和假阴性）观察。然而，差异并不是那么明显。

要计算总体错误率，我们可以使用以下代码：

```py
trainErr = (
    true_pred_class_lr
    .filter(lambda lp: lp[0] != lp[1]).count() 
    / float(true_pred_class_lr.count())
)
print("Training Error = " + str(trainErr))
```

对于 SVM，前面的代码看起来一样，唯一的区别是使用`true_pred_class_svm`而不是`true_pred_class_lr`。前面的产生了以下结果。对于逻辑回归，我们得到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00132.jpeg)

对于 SVM，结果如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00133.jpeg)

SVM 的误差略高，但仍然是一个相当合理的模型。

# 另请参阅

+   如果您想了解更多有关各种性能指标的信息，我们建议您访问以下网址：[`machinelearningmastery.com/metrics-evaluate-machine-learning-algorithms-python/`](https://machinelearningmastery.com/metrics-evaluate-machine-learning-algorithms-python/)


# 第六章：使用 ML 模块进行机器学习

在本章中，我们将继续使用 PySpark 当前支持的机器学习模块——ML 模块。ML 模块像 MLLib 一样，暴露了大量的机器学习模型，几乎完全覆盖了最常用（和可用）的模型。然而，ML 模块是在 Spark DataFrames 上运行的，因此它的性能更高，因为它可以利用钨执行优化。

在本章中，您将学习以下教程：

+   引入变压器

+   引入估计器

+   引入管道

+   选择最可预测的特征

+   预测森林覆盖类型

+   估算森林海拔

+   聚类森林覆盖类型

+   调整超参数

+   从文本中提取特征

+   离散化连续变量

+   标准化连续变量

+   主题挖掘

在本章中，我们将使用从 [`archive.ics.uci.edu/ml/datasets/covertype`](https://archive.ics.uci.edu/ml/datasets/covertype) 下载的数据。数据集位于本书的 GitHub 仓库中：`/data/forest_coverage_type.csv`。

我们以与之前相同的方式加载数据：

```py
forest_path = '../data/forest_coverage_type.csv'

forest = spark.read.csv(
    forest_path
    , header=True
    , inferSchema=True
)
```

# 引入变压器

`Transformer` 类是在 Spark 1.3 中引入的，它通过通常将一个或多个列附加到现有的 DataFrame 来将一个数据集转换为另一个数据集。变压器是围绕实际转换特征的方法的抽象；这个抽象还包括训练好的机器学习模型（正如我们将在接下来的教程中看到的）。

在本教程中，我们将介绍两个变压器：`Bucketizer` 和 `VectorAssembler`。

我们不会介绍所有的变压器；在本章的其余部分，最有用的变压器将会出现。至于其余的，Spark 文档是学习它们的功能和如何使用它们的好地方。

以下是将一个特征转换为另一个特征的所有变压器的列表：

+   `Binarizer` 是一种方法，给定一个阈值，将连续的数值特征转换为二进制特征。

+   `Bucketizer` 与 `Binarizer` 类似，它使用一组阈值将连续数值变量转换为离散变量（级别数与阈值列表长度加一相同）。

+   `ChiSqSelector` 帮助选择解释分类目标（分类模型）方差大部分的预定义数量的特征。

+   `CountVectorizer` 将许多字符串列表转换为计数的 `SparseVector`，其中每一列都是列表中每个不同字符串的标志，值表示当前列表中找到该字符串的次数。

+   `DCT` 代表**离散余弦变换**。它接受一组实值向量，并返回以不同频率振荡的余弦函数向量。

+   `ElementwiseProduct` 可以用于缩放您的数值特征，因为它接受一个值向量，并将其（如其名称所示，逐元素）乘以另一个具有每个值权重的向量。

+   `HashingTF` 是一个哈希技巧变压器，返回一个指定长度的标记文本表示的向量。

+   `IDF` 计算记录列表的**逆文档频率**，其中每个记录都是文本主体的数值表示（请参阅 `CountVectorizer` 或 `HashingTF`）。

+   `IndexToString` 使用 `StringIndexerModel` 对象的编码将字符串索引反转为原始值。

+   `MaxAbsScaler` 将数据重新缩放为 `-1` 到 `1` 的范围内。

+   `MinMaxScaler` 将数据重新缩放为 `0` 到 `1` 的范围内。

+   `NGram` 返回一对、三元组或 *n* 个连续单词的标记文本。

+   `Normalizer` 将数据缩放为单位范数（默认为 `L2`）。

+   `OneHotEncoder` 将分类变量编码为向量表示，其中只有一个元素是热的，即等于 `1`（其他都是 `0`）。

+   `PCA` 是一种从数据中提取主成分的降维方法。

+   `PolynomialExpansion` 返回输入向量的多项式展开。

+   `QuantileDiscretizer`是类似于`Bucketizer`的方法，但不是定义阈值，而是需要指定返回的箱数；该方法将使用分位数来决定阈值。

+   `RegexTokenizer` 是一个使用正则表达式处理文本的字符串标记器。

+   `RFormula`是一种传递 R 语法公式以转换数据的方法。

+   `SQLTransformer`是一种传递 SQL 语法公式以转换数据的方法。

+   `StandardScaler` 将数值特征转换为均值为 0，标准差为 1。

+   `StopWordsRemover` 用于从标记化文本中删除诸如 `a` 或 `the` 等单词。

+   `StringIndexer`根据列中所有单词的列表生成一个索引向量。

+   `Tokenizer`是一个默认的标记器，它接受一个句子（一个字符串），在空格上分割它，并对单词进行规范化。

+   `VectorAssembler`将指定的（单独的）特征组合成一个特征。

+   `VectorIndexer`接受一个分类变量（已经编码为数字）并返回一个索引向量。

+   `VectorSlicer` 可以被认为是`VectorAssembler`的相反，因为它根据索引从特征向量中提取数据。

+   `Word2Vec`将一个句子（或字符串）转换为`{string，vector}`表示的映射。

# 准备工作

要执行此操作，您需要一个可用的 Spark 环境，并且您已经将数据加载到 forest DataFrame 中。

无需其他先决条件。

# 如何做...

```py
Horizontal_Distance_To_Hydrology column into 10 equidistant buckets:
```

```py
import pyspark.sql.functions as f
import pyspark.ml.feature as feat
import numpy as np

buckets_no = 10

dist_min_max = (
    forest.agg(
          f.min('Horizontal_Distance_To_Hydrology')
            .alias('min')
        , f.max('Horizontal_Distance_To_Hydrology')
            .alias('max')
    )
    .rdd
    .map(lambda row: (row.min, row.max))
    .collect()[0]
)

rng = dist_min_max[1] - dist_min_max[0]

splits = list(np.arange(
    dist_min_max[0]
    , dist_min_max[1]
    , rng / (buckets_no + 1)))

bucketizer = feat.Bucketizer(
    splits=splits
    , inputCol= 'Horizontal_Distance_To_Hydrology'
    , outputCol='Horizontal_Distance_To_Hydrology_Bkt'
)

(
    bucketizer
    .transform(forest)
    .select(
         'Horizontal_Distance_To_Hydrology'
        ,'Horizontal_Distance_To_Hydrology_Bkt'
    ).show(5)
)
```

有没有想法为什么我们不能使用`.QuantileDiscretizer(...)`来实现这一点？

# 它是如何工作的...

与往常一样，我们首先加载我们将在整个过程中使用的必要模块，`pyspark.sql.functions`，它将允许我们计算`Horizontal_Distance_To_Hydrology`特征的最小值和最大值。`pyspark.ml.feature`为我们提供了`.Bucketizer(...)`转换器供我们使用，而 NumPy 将帮助我们创建一个等间距的阈值列表。

我们想要将我们的数值变量分成 10 个桶，因此我们的`buckets_no`等于`10`。接下来，我们计算`Horizontal_Distance_To_Hydrology`特征的最小值和最大值，并将这两个值返回给驱动程序。在驱动程序上，我们创建阈值列表（`splits`列表）；`np.arange(...)`方法的第一个参数是最小值，第二个参数是最大值，第三个参数定义了每个步长的大小。

现在我们已经定义了拆分列表，我们将其传递给`.Bucketizer(...)`方法。

每个转换器（估计器的工作方式类似）都有一个非常相似的 API，但始终需要两个参数：`inputCol`和`outputCol`，它们分别定义要消耗的输入列和它们的输出列。这两个类——`Transformer`和`Estimator`——也普遍实现了`.getOutputCol()`方法，该方法返回输出列的名称。

最后，我们使用`bucketizer`对象来转换我们的 DataFrame。这是我们期望看到的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00134.jpeg)

# 还有更多...

几乎所有在 ML 模块中找到的估计器（或者换句话说，ML 模型）都期望看到一个*单一*列作为输入；该列应包含数据科学家希望这样一个模型使用的所有特征。正如其名称所示，`.VectorAssembler(...)`方法将多个特征汇总到一个单独的列中。

考虑以下示例：

```py
vectorAssembler = (
    feat.VectorAssembler(
        inputCols=forest.columns, 
        outputCol='feat'
    )
)

pca = (
    feat.PCA(
        k=5
        , inputCol=vectorAssembler.getOutputCol()
        , outputCol='pca_feat'
    )
)

(
    pca
    .fit(vectorAssembler.transform(forest))
    .transform(vectorAssembler.transform(forest))
    .select('feat','pca_feat')
    .take(1)
)
```

首先，我们使用`.VectorAssembler(...)`方法从我们的`forest` DataFrame 中汇总所有列。

请注意，与其他转换器不同，`.VectorAssembler(...)`方法具有`inputCols`参数，而不是`inputCol`，因为它接受一个列的列表，而不仅仅是一个单独的列。

然后，我们在`PCA(...)`方法中使用`feat`列（现在是所有特征的`SparseVector`）来提取前五个最重要的主成分。

注意我们现在如何可以使用`.getOutputCol()`方法来获取输出列的名称？当我们介绍管道时，为什么这样做会变得更明显？

上述代码的输出应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00135.jpeg)

# 另请参阅

+   有关变换器（以及更多内容）的示例，请查看此博文：[`blog.insightdatascience.com/spark-pipelines-elegant-yet-powerful-7be93afcdd42`](https://blog.insightdatascience.com/spark-pipelines-elegant-yet-powerful-7be93afcdd42)

# 介绍 Estimators

`Estimator`类，就像`Transformer`类一样，是在 Spark 1.3 中引入的。Estimators，顾名思义，用于估计模型的参数，或者换句话说，将模型拟合到数据。

在本文中，我们将介绍两个模型：作为分类模型的线性 SVM，以及预测森林海拔的线性回归模型。

以下是 ML 模块中所有 Estimators 或机器学习模型的列表：

+   分类：

+   `LinearSVC` 是用于线性可分问题的 SVM 模型。SVM 的核心具有![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00136.jpeg)形式（超平面），其中![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00137.jpeg)是系数（或超平面的法向量），![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00138.jpeg)是记录，*b*是偏移量。

+   `LogisticRegression` 是线性可分问题的默认*go-to*分类模型。它使用 logit 函数来计算记录属于特定类的概率。

+   `DecisionTreeClassifier` 是用于分类目的的基于决策树的模型。它构建一个二叉树，其中终端节点中类别的比例确定了类的成员资格。

+   `GBTClassifier` 是集成模型组中的一员。**梯度提升树**（**GBT**）构建了几个弱模型，当组合在一起时形成一个强分类器。该模型也可以应用于解决回归问题。

+   `RandomForestClassifier` 也是集成模型组中的一员。与 GBT 不同，随机森林完全生长决策树，并通过减少方差来实现总误差减少（而 GBT 减少偏差）。就像 GBT 一样，这些模型也可以用来解决回归问题。

+   `NaiveBayes` 使用贝叶斯条件概率理论，![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00139.jpeg)，根据关于概率和可能性的证据和先验假设对观察结果进行分类。

+   `MultilayerPerceptronClassifier` 源自人工智能领域，更狭义地说是人工神经网络。该模型由模拟（在某种程度上）大脑的基本构建模块的人工神经元组成的有向图。

+   `OneVsRest` 是一种在多项式场景中只选择一个类的缩减技术。

+   回归：

+   `AFTSurvivalRegression` 是一种参数模型，用于预测寿命，并假设特征之一的边际效应加速或减缓过程失败。

+   `DecisionTreeRegressor`，`DecisionTreeClassifier`的对应物，适用于回归问题。

+   `GBTRegressor`，`GBTClassifier`的对应物，适用于回归问题。

+   `GeneralizedLinearRegression` 是一类允许我们指定不同核函数（或链接函数）的线性模型。与假设误差项正态分布的线性回归不同，**广义线性模型**（**GLM**）允许模型具有其他误差项分布。

+   `IsotonicRegression` 将自由形式和非递减线拟合到数据。

+   `LinearRegression` 是回归模型的基准。它通过数据拟合一条直线（或用线性术语定义的平面）。

+   `RandomForestRegressor`，`RandomForestClassifier`的对应物，适用于回归问题。

+   聚类：

+   `BisectingKMeans` 是一个模型，它从一个单一聚类开始，然后迭代地将数据分成*k*个聚类。

+   `Kmeans` 通过迭代找到聚类的质心，通过移动聚类边界来最小化数据点与聚类质心之间的距离总和，将数据分成*k*（定义）个聚类。

+   `GaussianMixture` 使用*k*个高斯分布将数据集分解成聚类。

+   `LDA`：**潜在狄利克雷分配**是主题挖掘中经常使用的模型。它是一个统计模型，利用一些未观察到的（或未命名的）组来对观察结果进行聚类。例如，一个`PLANE_linked`集群可以包括诸如 engine、flaps 或 wings 等词语。

# 准备工作

执行此配方，您需要一个可用的 Spark 环境，并且您已经将数据加载到`forest` DataFrame 中。

不需要其他先决条件。

# 如何做...

首先，让我们学习如何构建一个 SVM 模型：

```py
import pyspark.ml.classification as cl

vectorAssembler = feat.VectorAssembler(
    inputCols=forest.columns[0:-1]
    , outputCol='features')

fir_dataset = (
    vectorAssembler
    .transform(forest)
    .withColumn(
        'label'
        , (f.col('CoverType') == 1).cast('integer'))
    .select('label', 'features')
)

svc_obj = cl.LinearSVC(maxIter=10, regParam=0.01)
svc_model = svc_obj.fit(fir_dataset)
```

# 它是如何工作的...

`.LinearSVC(...)`方法来自`pyspark.ml.classification`，因此我们首先加载它。

接下来，我们使用`.VectorAssembler(...)`从`forest` DataFrame 中获取所有列，但最后一列（`CoverType`）将用作标签。我们将预测等于`1`的森林覆盖类型，也就是说，森林是否是云杉冷杉类型；我们通过检查`CoverType`是否等于`1`并将结果布尔值转换为整数来实现这一点。最后，我们只选择`label`和`features`。

接下来，我们创建`LinearSVC`对象。我们将最大迭代次数设置为 10，并将正则化参数（L2 类型或岭）设置为 1%。

如果您对机器学习中的正则化不熟悉，请查看此网站：[`enhancedatascience.com/2017/07/04/machine-learning-explained-regularization/`](http://enhancedatascience.com/2017/07/04/machine-learning-explained-regularization/)。

其他参数包括：

+   `featuresCol`：默认情况下设置为特征列的名称为`features`（就像在我们的数据集中一样）

+   `labelCol`：如果有其他名称而不是`label`，则设置为标签列的名称

+   `predictionCol`：如果要将其重命名为除`prediction`之外的其他内容，则设置为预测列的名称

+   `tol`：这是一个停止参数，它定义了成本函数在迭代之间的最小变化：如果变化（默认情况下）小于 10^(-6)，算法将假定它已经收敛

+   `rawPredictionCol`：这返回生成函数的原始值（在应用阈值之前）；您可以指定一个不同的名称而不是`rawPrediction`

+   `fitIntercept`：这指示模型拟合截距（常数），而不仅仅是模型系数；默认设置为`True`

+   `standardization`：默认设置为`True`，它在拟合模型之前对特征进行标准化

+   `threshold`：默认设置为`0.0`；这是一个决定什么被分类为`1`或`0`的参数

+   `weightCol`：如果每个观察结果的权重不同，则这是一个列名

+   `aggregationDepth`：这是用于聚合的树深度参数

最后，我们使用对象`.fit(...)`数据集；对象返回一个`.LinearSVCModel(...)`。一旦模型被估计，我们可以这样提取估计模型的系数：`svc_model.coefficients`。这是我们得到的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00140.jpeg)

# 还有更多...

现在，让我们看看线性回归模型是否可以合理准确地估计森林海拔：

```py
import pyspark.ml.regression as rg

vectorAssembler = feat.VectorAssembler(
    inputCols=forest.columns[1:]
    , outputCol='features')

elevation_dataset = (
    vectorAssembler
    .transform(forest)
    .withColumn(
        'label'
        , f.col('Elevation').cast('float'))
    .select('label', 'features')
)

lr_obj = rg.LinearRegression(
    maxIter=10
    , regParam=0.01
    , elasticNetParam=1.00)
lr_model = lr_obj.fit(elevation_dataset)
```

上述代码与之前介绍的代码非常相似。顺便说一句，这对于几乎所有的 ML 模块模型都是正确的，因此测试各种模型非常简单。

区别在于`label`列-现在，我们使用`Elevation`并将其转换为`float`（因为这是一个回归问题）。

同样，线性回归对象`lr_obj`实例化了`.LinearRegression(...)`对象。

有关`.LinearRegression(...)`的完整参数列表，请参阅文档：[`bit.ly/2J9OvEJ`](http://bit.ly/2J9OvEJ)。

一旦模型被估计，我们可以通过调用`lr_model.coefficients`来检查其系数。这是我们得到的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00141.jpeg)

此外，`.LinearRegressionModel(...)`计算一个返回基本性能统计信息的摘要：

```py
summary = lr_model.summary

print(
    summary.r2
    , summary.rootMeanSquaredError
    , summary.meanAbsoluteError
)
```

上述代码将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00142.jpeg)

令人惊讶的是，线性回归在这个应用中表现不错：78%的 R 平方并不是一个坏结果。

# 介绍管道

`Pipeline`类有助于对导致估计模型的单独块的执行进行排序或简化；它将多个 Transformer 和 Estimator 链接在一起，形成一个顺序执行的工作流程。

管道很有用，因为它们避免了在整体数据转换和模型估计过程中通过不同部分推送数据时显式创建多个转换数据集。相反，管道通过自动化数据流程来抽象不同的中间阶段。这使得代码更易读和可维护，因为它创建了系统的更高抽象，并有助于代码调试。

在这个操作步骤中，我们将简化广义线性回归模型的执行。

# 准备工作

要执行此操作步骤，您需要一个可用的 Spark 环境，并且您已经将数据加载到`forest` DataFrame 中。

不需要其他先决条件。

# 操作步骤...

以下代码提供了通过 GLM 估计线性回归模型的执行的简化版本：

```py
from pyspark.ml import Pipeline

vectorAssembler = feat.VectorAssembler(
    inputCols=forest.columns[1:]
    , outputCol='features')

lr_obj = rg.GeneralizedLinearRegression(
    labelCol='Elevation'
    , maxIter=10
    , regParam=0.01
    , link='identity'
    , linkPredictionCol="p"
)

pip = Pipeline(stages=[vectorAssembler, lr_obj])

(
    pip
    .fit(forest)
    .transform(forest)
    .select('Elevation', 'prediction')
    .show(5)
)
```

# 工作原理...

整个代码比我们在上一个示例中使用的代码要短得多，因为我们不需要做以下工作：

```py
elevation_dataset = (
    vectorAssembler
    .transform(forest)
    .withColumn(
        'label'
        , f.col('Elevation').cast('float'))
    .select('label', 'features')
)
```

然而，与之前一样，我们指定了`vectorAssembler`和`lr_obj`（`.GeneralizedLinearRegression（...）`对象）。`.GeneralizedLinearRegression（...）`允许我们不仅指定模型的 family，还可以指定 link 函数。为了决定选择什么样的 link 函数和 family，我们可以查看我们的`Elevation`列的分布：

```py
import matplotlib.pyplot as plt

transformed_df = forest.select('Elevation')
transformed_df.toPandas().hist()

plt.savefig('Elevation_histogram.png')

plt.close('all')
```

这是运行上述代码后得到的图表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00143.jpeg)

分布有点偏斜，但在一定程度上，我们可以假设它遵循正态分布。因此，我们可以使用`family = 'gaussian'`（默认）和`link = 'identity'`。

创建了 Transformer（`vectorAssembler`）和 Estimator（`lr_obj`）之后，我们将它们放入管道中。`stages`参数是一个有序列表，用于将数据推送到我们的数据中；在我们的情况下，`vectorAssembler`首先进行，因为我们需要整理所有的特征，然后我们使用`lr_obj`估计我们的模型。

最后，我们使用管道同时估计模型。管道的`.fit（...）`方法调用`.transform（...）`方法（如果对象是 Transformer），或者`.fit（...）`方法（如果对象是 Estimator）。因此，在`PipelineModel`上调用`.transform（...）`方法会调用 Transformer 和 Estimator 对象的`.transform（...）`方法。

最终结果如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00144.jpeg)

正如你所看到的，结果与实际结果并没有太大不同。

# 另请参阅

+   查看此博文（尽管它是特定于 Scala 的）以获取有关管道的概述：[`databricks.com/blog/2015/01/07/ml-pipelines-a-new-high-level-api-for-mllib.html`](https://databricks.com/blog/2015/01/07/ml-pipelines-a-new-high-level-api-for-mllib.html)

# 选择最可预测的特征

（几乎）每个数据科学家的口头禅是：构建一个简单的模型，同时尽可能解释目标中的方差。换句话说，您可以使用所有特征构建模型，但模型可能非常复杂且容易过拟合。而且，如果其中一个变量缺失，整个模型可能会产生错误的输出，有些变量可能根本不必要，因为其他变量已经解释了相同部分的方差（称为*共线性*）。

在这个操作步骤中，我们将学习如何在构建分类或回归模型时选择最佳的预测模型。我们将在接下来的操作步骤中重复使用本操作步骤中学到的内容。

# 准备工作

要执行此操作，您需要一个可用的 Spark 环境，并且您已经将数据加载到`forest` DataFrame 中。

不需要其他先决条件。

# 如何做...

让我们从一段代码开始，这段代码将帮助选择具有最强预测能力的前 10 个特征，以找到`forest` DataFrame 中观察结果的最佳类别：

```py
vectorAssembler = feat.VectorAssembler(
    inputCols=forest.columns[0:-1]
    , outputCol='features'
)

selector = feat.ChiSqSelector(
    labelCol='CoverType'
    , numTopFeatures=10
    , outputCol='selected')

pipeline_sel = Pipeline(stages=[vectorAssembler, selector])
```

# 它是如何工作的...

首先，我们使用`.VectorAssembler(...)`方法将所有特征组装成一个单一向量。请注意，我们不使用最后一列，因为它是`CoverType`特征，这是我们的目标。

接下来，我们使用`.ChiSqSelector(...)`方法基于每个变量与目标之间的成对卡方检验来选择最佳特征。根据测试的值，选择`numTopFeatures`个最可预测的特征。`selected`向量将包含前 10 个（在这种情况下）最可预测的特征。`labelCol`指定目标列。

你可以在这里了解更多关于卡方检验的信息：[`learntech.uwe.ac.uk/da/Default.aspx?pageid=1440`](http://learntech.uwe.ac.uk/da/Default.aspx?pageid=1440)。

让我们来看看：

```py
(
    pipeline_sel
    .fit(forest)
    .transform(forest)
    .select(selector.getOutputCol())
    .show(5)
)
```

从运行前面的代码段中，你应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00145.jpeg)

正如你所看到的，生成的`SparseVector`长度为 10，只包括最可预测的特征。

# 还有更多...

我们不能使用`.ChiSqSelector(...)`方法来选择连续的目标特征，也就是回归问题。选择最佳特征的一种方法是检查每个特征与目标之间的相关性，并选择那些与目标高度相关但与其他特征几乎没有相关性的特征：

```py
import pyspark.ml.stat as st

features_and_label = feat.VectorAssembler(
    inputCols=forest.columns
    , outputCol='features'
)

corr = st.Correlation.corr(
    features_and_label.transform(forest), 
    'features', 
    'pearson'
)

print(str(corr.collect()[0][0]))
```

在 Spark 中没有自动执行此操作的方法，但是从 Spark 2.2 开始，我们现在可以计算数据框中特征之间的相关性。

`.Correlation(...)`方法是`pyspark.ml.stat`模块的一部分，所以我们首先导入它。

接下来，我们创建`.VectorAssembler(...)`，它汇总`forest` DataFrame 的所有列。现在我们可以使用 Transformer，并将结果 DataFrame 传递给`Correlation`类。`Correlation`类的`.corr(...)`方法接受 DataFrame 作为其第一个参数，具有所有特征的列的名称作为第二个参数，要计算的相关性类型作为第三个参数；可用的值是`pearson`（默认值）和`spearman`。

查看这个网站，了解更多关于这两种相关性方法的信息：[`bit.ly/2xm49s7`](http://bit.ly/2xm49s7)。

从运行该方法中，我们期望看到的内容如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00146.jpeg)

现在我们有了相关矩阵，我们可以提取与我们的标签最相关的前 10 个特征：

```py
num_of_features = 10
cols = dict([
    (i, e) 
    for i, e 
    in enumerate(forest.columns)
])

corr_matrix = corr.collect()[0][0]
label_corr_with_idx = [
    (i[0], e) 
    for i, e 
    in np.ndenumerate(corr_matrix.toArray()[:,0])
][1:]

label_corr_with_idx_sorted = sorted(
    label_corr_with_idx
    , key=lambda el: -abs(el[1])
)

features_selected = np.array([
    cols[el[0]] 
    for el 
    in label_corr_with_idx_sorted
])[0:num_of_features]
```

首先，我们指定要提取的特征数量，并创建一个包含`forest` DataFrame 的所有列的字典；请注意，我们将其与索引一起压缩，因为相关矩阵不会传播特征名称，只传播索引。

接下来，我们从`corr_matrix`中提取第一列（因为这是我们的目标，即 Elevation 特征）；`.toArray()`方法将 DenseMatrix 转换为 NumPy 数组表示。请注意，我们还将索引附加到此数组的元素，以便我们知道哪个元素与我们的目标最相关。

接下来，我们按相关系数的绝对值降序排序列表。

最后，我们循环遍历结果列表的前 10 个元素（在这种情况下），并从`cols`字典中选择与所选索引对应的列。

对于我们旨在估计森林海拔的问题，这是我们得到的特征列表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00147.jpeg)

# 另请参阅

+   如果你想了解更多关于特征选择的信息，可以查看这篇论文：[`www.stat.wisc.edu/~loh/treeprogs/guide/lchen.pdf`](http://www.stat.wisc.edu/~loh/treeprogs/guide/lchen.pdf)

# 预测森林覆盖类型

在本示例中，我们将学习如何处理数据并构建两个旨在预测森林覆盖类型的分类模型：基准逻辑回归模型和随机森林分类器。我们手头的问题是*多项式*，也就是说，我们有超过两个类别，我们希望将我们的观察结果分类到其中。

# 准备工作

要执行此示例，您需要一个可用的 Spark 环境，并且您已经将数据加载到`forest` DataFrame 中。

不需要其他先决条件。

# 如何做...

这是帮助我们构建逻辑回归模型的代码：

```py
forest_train, forest_test = (
    forest
    .randomSplit([0.7, 0.3], seed=666)
)

vectorAssembler = feat.VectorAssembler(
    inputCols=forest.columns[0:-1]
    , outputCol='features'
)

selector = feat.ChiSqSelector(
    labelCol='CoverType'
    , numTopFeatures=10
    , outputCol='selected'
)

logReg_obj = cl.LogisticRegression(
    labelCol='CoverType'
    , featuresCol=selector.getOutputCol()
    , regParam=0.01
    , elasticNetParam=1.0
    , family='multinomial'
)

pipeline = Pipeline(
    stages=[
        vectorAssembler
        , selector
        , logReg_obj
    ])

pModel = pipeline.fit(forest_train)
```

# 它是如何工作的...

首先，我们将数据分成两个子集：第一个`forest_train`，我们将用于训练模型，而`forest_test`将用于测试模型的性能。

接下来，我们构建了本章前面已经看到的通常阶段：我们使用`.VectorAssembler（...）`整理我们要用来构建模型的所有特征，然后通过`.ChiSqSelector（...）`方法选择前 10 个最具预测性的特征。

在构建 Pipeline 之前的最后一步，我们创建了`logReg_obj`：我们将用它来拟合我们的数据的`.LogisticRegression（...）`对象。在这个模型中，我们使用弹性网络类型的正则化：`regParam`参数中定义了 L2 部分，`elasticNetParam`中定义了 L1 部分。请注意，我们指定模型的 family 为`multinomial`，因为我们正在处理多项式分类问题。

如果要模型自动选择，或者如果您有一个二进制变量，还可以指定`family`参数为`auto`或`binomial`。

最后，我们构建了 Pipeline，并将这三个对象作为阶段列表传递。接下来，我们使用`.fit（...）`方法将我们的数据通过管道传递。

现在我们已经估计了模型，我们可以检查它的性能如何：

```py
import pyspark.ml.evaluation as ev

results_logReg = (
    pModel
    .transform(forest_test)
    .select('CoverType', 'probability', 'prediction')
)

evaluator = ev.MulticlassClassificationEvaluator(
    predictionCol='prediction'
    , labelCol='CoverType')

(
    evaluator.evaluate(results_logReg)
    , evaluator.evaluate(
        results_logReg
        , {evaluator.metricName: 'weightedPrecision'}
    ) 
    , evaluator.evaluate(
        results_logReg
        , {evaluator.metricName: 'accuracy'}
    )
)
```

首先，我们加载`pyspark.ml.evaluation`模块，因为它包含了我们将在本章其余部分中使用的所有评估方法。

接下来，我们将`forest_test`通过我们的`pModel`，以便我们可以获得模型以前从未见过的数据集的预测。

最后，我们创建了`MulticlassClassificationEvaluator（...）`对象，它将计算我们模型的性能指标。`predictionCol`指定包含观察的预测类的列的名称，`labelCol`指定真实标签。

如果评估器的`.evaluate（...）`方法没有传递其他参数，而只返回模型的结果，则将返回 F1 分数。如果要检索精确度、召回率或准确度，则需要分别调用`weightedPrecision`、`weightedRecall`或`accuracy`。

如果您对分类指标不熟悉，可以在此处找到很好的解释：[`turi.com/learn/userguide/evaluation/classification.html`](https://turi.com/learn/userguide/evaluation/classification.html)。

这是我们的逻辑回归模型的表现：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00148.jpeg)

几乎 70%的准确率表明这不是一个非常糟糕的模型。

# 还有更多...

让我们看看随机森林模型是否能做得更好：

```py
rf_obj = cl.RandomForestClassifier(
    labelCol='CoverType'
    , featuresCol=selector.getOutputCol()
    , minInstancesPerNode=10
    , numTrees=10
)

pipeline = Pipeline(
    stages=[vectorAssembler, selector, rf_obj]
)

pModel = pipeline.fit(forest_train)
```

从前面的代码中可以看出，我们将重用我们已经为逻辑回归模型创建的大多数对象；我们在这里引入的是`.RandomForestClassifier（...）`，我们可以重用`vectorAssembler`和`selector`对象。这是与管道一起工作的简单示例之一。

`.RandomForestClassifier（...）`对象将为我们构建随机森林模型。在此示例中，我们仅指定了四个参数，其中大多数您可能已经熟悉，例如`labelCol`和`featuresCol`。`minInstancesPerNode`指定允许将节点拆分为两个子节点的最小记录数，而`numTrees`指定要估计的森林中的树木数量。其他值得注意的参数包括：

+   `impurity`: 指定用于信息增益的标准。默认情况下，它设置为 `gini`，但也可以是 `entropy`。

+   `maxDepth`: 指定任何树的最大深度。

+   `maxBins`: 指定任何树中的最大箱数。

+   `minInfoGain`: 指定迭代之间的最小信息增益水平。

有关该类的完整规范，请参阅 [`bit.ly/2sgQAFa`](http://bit.ly/2sgQAFa)。

估计了模型后，让我们看看它的表现，以便与逻辑回归进行比较：

```py
results_rf = (
    pModel
    .transform(forest_test)
    .select('CoverType', 'probability', 'prediction')
)

(
    evaluator.evaluate(results_rf)
    , evaluator.evaluate(
        results_rf
        , {evaluator.metricName: 'weightedPrecision'}
    )
    , evaluator.evaluate(
        results_rf
        , {evaluator.metricName: 'accuracy'}
    )
)
```

上述代码应该产生类似以下的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00149.jpeg)

结果完全相同，表明两个模型表现一样好，我们可能希望在选择阶段增加所选特征的数量，以潜在地获得更好的结果。

# 估计森林海拔

在这个示例中，我们将构建两个回归模型，用于预测森林海拔：随机森林回归模型和梯度提升树回归器。

# 准备工作

要执行此示例，您需要一个可用的 Spark 环境，并且您已经将数据加载到 `forest` DataFrame 中。

不需要其他先决条件。

# 如何做...

在这个示例中，我们将只构建一个两阶段的管道，使用 `.VectorAssembler(...)` 和 `.RandomForestRegressor(...)` 阶段。我们将跳过特征选择阶段，因为目前这不是一个自动化的过程。

您可以手动执行此操作。只需在本章中稍早的 *选择最可预测的特征* 示例中检查。

以下是完整的代码：

```py
vectorAssembler = feat.VectorAssembler(
    inputCols=forest.columns[1:]
    , outputCol='features')

rf_obj = rg.RandomForestRegressor(
    labelCol='Elevation'
    , maxDepth=10
    , minInstancesPerNode=10
    , minInfoGain=0.1
    , numTrees=10
)

pip = Pipeline(stages=[vectorAssembler, rf_obj])
```

# 工作原理...

首先，像往常一样，我们使用 `.VectorAssembler(...)` 方法收集我们想要在模型中使用的所有特征。请注意，我们只使用从第二列开始的列，因为第一列是我们的目标——海拔特征。

接下来，我们指定 `.RandomForestRegressor(...)` 对象。该对象使用的参数列表几乎与 `.RandomForestClassifier(...)` 相同。

查看上一个示例，了解其他显著参数的列表。

最后一步是构建管道对象；`pip` 只有两个阶段：`vectorAssembler` 和 `rf_obj`。

接下来，让我们看看我们的模型与我们在 *介绍估计器* 示例中估计的线性回归模型相比表现如何：

```py
results = (
    pip
    .fit(forest)
    .transform(forest)
    .select('Elevation', 'prediction')
)

evaluator = ev.RegressionEvaluator(labelCol='Elevation')
evaluator.evaluate(results, {evaluator.metricName: 'r2'})
```

`.RegressionEvaluator(...)` 计算回归模型的性能指标。默认情况下，它返回 `rmse`，即均方根误差，但也可以返回：

+   `mse`: 这是均方误差

+   `r2`: 这是 *R²* 指标

+   `mae`: 这是平均绝对误差

从上述代码中，我们得到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00150.jpeg)

这比我们之前构建的线性回归模型要好，这意味着我们的模型可能不像我们最初认为的那样线性可分。

查看此网站，了解有关不同类型回归指标的更多信息：[`bit.ly/2sgpONr`](http://bit.ly/2sgpONr)。

# 还有更多...

让我们看看梯度提升树模型是否能击败先前的结果：

```py
gbt_obj = rg.GBTRegressor(
    labelCol='Elevation'
    , minInstancesPerNode=10
    , minInfoGain=0.1
)

pip = Pipeline(stages=[vectorAssembler, gbt_obj])
```

与随机森林回归器相比唯一的变化是，我们现在使用 `.GBTRegressor(...)` 类来将梯度提升树模型拟合到我们的数据中。这个类的最显著参数包括：

+   `maxDepth`: 指定构建树的最大深度，默认设置为 `5`

+   `maxBins`: 指定最大箱数

+   `minInfoGain`: 指定迭代之间的最小信息增益水平

+   `minInstancesPerNode`: 当树仍然执行分裂时，指定实例的最小数量

+   `lossType`: 指定损失类型，并接受 `squared` 或 `absolute` 值

+   `impurity`: 默认设置为 `variance`，目前（在 Spark 2.3 中）是唯一允许的选项

+   `maxIter`: 指定最大迭代次数——算法的停止准则

现在让我们检查性能：

```py
results = (
    pip
    .fit(forest)
    .transform(forest)
    .select('Elevation', 'prediction')
)

evaluator = ev.RegressionEvaluator(labelCol='Elevation')
evaluator.evaluate(results, {evaluator.metricName: 'r2'})
```

以下是我们得到的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00151.jpeg)

如您所见，即使我们略微改进了随机森林回归器。

# 聚类森林覆盖类型

聚类是一种无监督的方法，试图在没有任何类别指示的情况下找到数据中的模式。换句话说，聚类方法找到记录之间的共同点，并根据它们彼此的相似程度以及与其他聚类中发现的记录的不相似程度将它们分组成聚类。

在本教程中，我们将构建最基本的模型之一——k-means 模型。

# 准备工作

要执行此教程，您需要一个可用的 Spark 环境，并且您已经将数据加载到`forest` DataFrame 中。

不需要其他先决条件。

# 如何做...

在 Spark 中构建聚类模型的过程与我们在分类或回归示例中已经看到的过程没有明显的偏差：

```py
import pyspark.ml.clustering as clust

vectorAssembler = feat.VectorAssembler(
    inputCols=forest.columns[:-1]
    , outputCol='features')

kmeans_obj = clust.KMeans(k=7, seed=666)

pip = Pipeline(stages=[vectorAssembler, kmeans_obj])
```

# 它是如何工作的...

像往常一样，我们首先导入相关模块；在这种情况下，是`pyspark.ml.clustering`模块。

接下来，我们将汇总所有要在构建模型中使用的特征，使用众所周知的`.VectorAssembler（...）`转换器。

然后实例化`.KMeans（...）`对象。我们只指定了两个参数，但最显著的参数列表如下：

+   `k`：指定预期的聚类数，是构建 k-means 模型的唯一必需参数

+   `initMode`：指定聚类中心的初始化类型；`k-means||`使用 k-means 的并行变体，或`random`选择随机的聚类中心点

+   `initSteps`：指定初始化步骤

+   `maxIter`：指定算法停止的最大迭代次数，即使它尚未收敛

最后，我们只构建了包含两个阶段的管道。

一旦计算出结果，我们可以看看我们得到了什么。我们的目标是看看是否在森林覆盖类型中找到了任何潜在模式：

```py
results = (
    pip
    .fit(forest)
    .transform(forest)
    .select('features', 'CoverType', 'prediction')
)

results.show(5)
```

这是我们从运行上述代码中得到的结果：

！[](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00152.jpeg)

如您所见，似乎没有许多模式可以区分森林覆盖类型。但是，让我们看看我们的分割是否表现不佳，这就是为什么我们找不到任何模式的原因，还是我们找到的模式根本不与`CoverType`对齐：

```py
clustering_ev = ev.ClusteringEvaluator()
clustering_ev.evaluate(results)
```

`.ClusteringEvaluator（...）`是自 Spark 2.3 以来可用的新评估器，仍处于实验阶段。它计算聚类结果的轮廓度量。

要了解更多有关轮廓度量的信息，请查看[`scikit-learn.org/stable/modules/generated/sklearn.metrics.silhouette_score.html`](http://scikit-learn.org/stable/modules/generated/sklearn.metrics.silhouette_score.html)。

这是我们的 k-means 模型：

！[](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00153.jpeg)

如您所见，我们得到了一个不错的模型，因为 0.5 左右的任何值都表示聚类分离良好。

# 另请参阅

+   查看[`scikit-learn.org/stable/modules/clustering.html`](http://scikit-learn.org/stable/modules/clustering.html)以全面了解聚类模型。请注意，其中许多模型在 Spark 中不可用。

# 调整超参数

本章中已经提到的许多模型都有多个参数，这些参数决定了模型的性能。选择一些相对简单，但有许多参数是我们无法直观设置的。这就是超参数调整方法的作用。超参数调整方法帮助我们选择最佳（或接近最佳）的参数集，以最大化我们定义的某个度量标准。

在本教程中，我们将向您展示超参数调整的两种方法。

# 准备工作

要执行此操作，您需要一个可用的 Spark 环境，并且已经将数据加载到`forest` DataFrame 中。我们还假设您已经熟悉了转换器、估计器、管道和一些回归模型。

不需要其他先决条件。

# 如何做...

我们从网格搜索开始。这是一种蛮力方法，简单地循环遍历参数的特定值，构建新模型并比较它们的性能，给定一些客观的评估器：

```py
import pyspark.ml.tuning as tune

vectorAssembler = feat.VectorAssembler(
    inputCols=forest.columns[0:-1]
    , outputCol='features')

selector = feat.ChiSqSelector(
    labelCol='CoverType'
    , numTopFeatures=5
    , outputCol='selected')

logReg_obj = cl.LogisticRegression(
    labelCol='CoverType'
    , featuresCol=selector.getOutputCol()
    , family='multinomial'
)

logReg_grid = (
    tune.ParamGridBuilder()
    .addGrid(logReg_obj.regParam
            , [0.01, 0.1]
        )
    .addGrid(logReg_obj.elasticNetParam
            , [1.0, 0.5]
        )
    .build()
)

logReg_ev = ev.MulticlassClassificationEvaluator(
    predictionCol='prediction'
    , labelCol='CoverType')

cross_v = tune.CrossValidator(
    estimator=logReg_obj
    , estimatorParamMaps=logReg_grid
    , evaluator=logReg_ev
)

pipeline = Pipeline(stages=[vectorAssembler, selector])
data_trans = pipeline.fit(forest_train)

logReg_modelTest = cross_v.fit(
    data_trans.transform(forest_train)
)
```

# 它是如何工作的...

这里发生了很多事情，让我们一步一步地解开它。

我们已经了解了`.VectorAssembler(...)`、`.ChiSqSelector(...)`和`.LogisticRegression(...)`类，因此我们在这里不会重复。

如果您对前面的概念不熟悉，请查看以前的配方。

这个配方的核心从`logReg_grid`对象开始。这是`.ParamGridBuilder()`类，它允许我们向网格中添加元素，算法将循环遍历并估计所有参数和指定值的组合的模型。

警告：您包含的参数越多，指定的级别越多，您将需要估计的模型就越多。模型的数量在参数数量和为这些参数指定的级别数量上呈指数增长。当心！

在这个例子中，我们循环遍历两个参数：`regParam`和`elasticNetParam`。对于每个参数，我们指定两个级别，因此我们需要构建四个模型。

作为评估器，我们再次使用`.MulticlassClassificationEvaluator(...)`。

接下来，我们指定`.CrossValidator(...)`对象，它将所有这些东西绑定在一起：我们的`estimator`将是`logReg_obj`，`estimatorParamMaps`将等于构建的`logReg_grid`，而`evaluator`将是`logReg_ev`。

`.CrossValidator(...)`对象将训练数据拆分为一组折叠（默认为`3`），并将它们用作单独的训练和测试数据集来拟合模型。因此，我们不仅需要根据要遍历的参数网格拟合四个模型，而且对于这四个模型中的每一个，我们都要构建三个具有不同训练和验证数据集的模型。

请注意，我们首先构建的管道是纯数据转换的，即，它只将特征汇总到完整的特征向量中，然后选择具有最大预测能力的前五个特征；我们在这个阶段不拟合`logReg_obj`。

当我们使用`cross_v`对象拟合转换后的数据时，模型拟合开始。只有在这时，Spark 才会估计四个不同的模型并选择表现最佳的模型。

现在已经估计了模型并选择了表现最佳的模型，让我们看看所选的模型是否比我们在*预测森林覆盖类型*配方中估计的模型表现更好：

```py
data_trans_test = data_trans.transform(forest_test)
results = logReg_modelTest.transform(data_trans_test)

print(logReg_ev.evaluate(results, {logReg_ev.metricName: 'weightedPrecision'}))
print(logReg_ev.evaluate(results, {logReg_ev.metricName: 'weightedRecall'}))
print(logReg_ev.evaluate(results, {logReg_ev.metricName: 'accuracy'}))
```

借助前面的代码，我们得到了以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00154.jpeg)

正如您所看到的，我们的表现略逊于之前的模型，但这很可能是因为我们只选择了前 5 个（而不是之前的 10 个）特征与我们的选择器。

# 还有更多...

另一种旨在找到表现最佳模型的方法称为**训练验证拆分**。该方法将训练数据拆分为两个较小的子集：一个用于训练模型，另一个用于验证模型是否过拟合。拆分只进行一次，因此与交叉验证相比，成本较低：

```py
train_v = tune.TrainValidationSplit(
    estimator=logReg_obj
    , estimatorParamMaps=logReg_grid
    , evaluator=logReg_ev
    , parallelism=4
)

logReg_modelTrainV = (
    train_v
    .fit(data_trans.transform(forest_train))

results = logReg_modelTrainV.transform(data_trans_test)

print(logReg_ev.evaluate(results, {logReg_ev.metricName: 'weightedPrecision'}))
print(logReg_ev.evaluate(results, {logReg_ev.metricName: 'weightedRecall'}))
print(logReg_ev.evaluate(results, {logReg_ev.metricName: 'accuracy'}))
```

前面的代码与`.CrossValidator(...)`所看到的并没有太大不同。我们为`.TrainValidationSplit(...)`方法指定的唯一附加参数是控制在选择最佳模型时会启动多少线程的并行级别。

使用`.TrainValidationSplit(...)`方法产生与`.CrossValidator(...)`方法相同的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00155.jpeg)

# 从文本中提取特征

通常，数据科学家需要处理非结构化数据，比如自由流动的文本：公司收到客户的反馈或建议（以及其他内容），这可能是预测客户下一步行动或他们对品牌情感的宝藏。

在这个步骤中，我们将学习如何从文本中提取特征。

# 准备工作

要执行这个步骤，你需要一个可用的 Spark 环境。

不需要其他先决条件。

# 如何做...

一个通用的过程旨在从文本中提取数据并将其转换为机器学习模型可以使用的内容，首先从自由流动的文本开始。第一步是取出文本的每个句子，并在空格字符上进行分割（通常是）。接下来，移除所有的停用词。最后，简单地计算文本中不同单词的数量或使用哈希技巧将我们带入自由流动文本的数值表示领域。

以下是如何使用 Spark 的 ML 模块来实现这一点：

```py
some_text = spark.createDataFrame([
    ['''
    Apache Spark achieves high performance for both batch
    and streaming data, using a state-of-the-art DAG scheduler, 
    a query optimizer, and a physical execution engine.
    ''']
    , ['''
    Apache Spark is a fast and general-purpose cluster computing 
    system. It provides high-level APIs in Java, Scala, Python 
    and R, and an optimized engine that supports general execution 
    graphs. It also supports a rich set of higher-level tools including 
    Spark SQL for SQL and structured data processing, MLlib for machine 
    learning, GraphX for graph processing, and Spark Streaming.
    ''']
    , ['''
    Machine learning is a field of computer science that often uses 
    statistical techniques to give computers the ability to "learn" 
    (i.e., progressively improve performance on a specific task) 
    with data, without being explicitly programmed.
    ''']
], ['text'])

splitter = feat.RegexTokenizer(
    inputCol='text'
    , outputCol='text_split'
    , pattern='\s+|[,.\"]'
)

sw_remover = feat.StopWordsRemover(
    inputCol=splitter.getOutputCol()
    , outputCol='no_stopWords'
)

hasher = feat.HashingTF(
    inputCol=sw_remover.getOutputCol()
    , outputCol='hashed'
    , numFeatures=20
)

idf = feat.IDF(
    inputCol=hasher.getOutputCol()
    , outputCol='features'
)

pipeline = Pipeline(stages=[splitter, sw_remover, hasher, idf])

pipelineModel = pipeline.fit(some_text)
```

# 它是如何工作的...

正如前面提到的，我们从一些文本开始。在我们的例子中，我们使用了一些从 Spark 文档中提取的内容。

`.RegexTokenizer(...)`是使用正则表达式来分割句子的文本分词器。在我们的例子中，我们在至少一个（或多个）空格上分割句子——这是`\s+`表达式。然而，我们的模式还会在逗号、句号或引号上进行分割——这是`[,.\"]`部分。管道符`|`表示在空格或标点符号上进行分割。通过`.RegexTokenizer(...)`处理后的文本将如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00156.jpeg)

接下来，我们使用`.StopWordsRemover(...)`方法来移除停用词，正如其名称所示。

查看 NLTK 的最常见停用词列表：[`gist.github.com/sebleier/554280`](https://gist.github.com/sebleier/554280)。

`.StopWordsRemover(...)`简单地扫描标记化文本，并丢弃它遇到的任何停用词。移除停用词后，我们的文本将如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00157.jpeg)

正如你所看到的，剩下的是句子的基本含义；人类可以阅读这些词，并且在一定程度上理解它。

哈希技巧（或特征哈希）是一种将任意特征列表转换为向量形式的方法。这是一种高效利用空间的方法，用于标记文本，并同时将文本转换为数值表示。哈希技巧使用哈希函数将一种表示转换为另一种表示。哈希函数本质上是任何将一种表示转换为另一种表示的映射函数。通常，它是一种有损和单向的映射（或转换）；不同的输入可以被哈希成相同的哈希值（称为**冲突**），一旦被哈希，几乎总是极其困难来重构输入。`.HashingTF(...)`方法接受`sq_remover`对象的输入列，并将标记化文本转换（或编码）为一个包含 20 个特征的向量。在经过哈希处理后，我们的文本将如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00158.jpeg)

现在我们已经对特征进行了哈希处理，我们可能可以使用这些特征来训练一个机器学习模型。然而，简单地计算单词出现的次数可能会导致误导性的结论。一个更好的度量是**词频-逆文档频率**（**TF-IDF**）。这是一个度量，它计算一个词在整个语料库中出现的次数，然后计算一个句子中该词出现次数与整个语料库中出现次数的比例。这个度量有助于评估一个词对整个文档集合中的一个文档有多重要。在 Spark 中，我们使用`.IDF(...)`方法来实现这一点。

在通过整个管道后，我们的文本将如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00159.jpeg)

因此，实际上，我们已经将 Spark 文档中的内容编码成了一个包含 20 个元素的向量，现在我们可以用它来训练一个机器学习模型。

# 还有更多...

将文本编码成数字形式的另一种方法是使用 Word2Vec 算法。该算法计算单词的分布式表示，优势在于相似的单词在向量空间中被放在一起。

查看这个教程，了解更多关于 Word2Vec 和 skip-gram 模型的信息：[`mccormickml.com/2016/04/19/word2vec-tutorial-the-skip-gram-model/`](http://mccormickml.com/2016/04/19/word2vec-tutorial-the-skip-gram-model/)。

在 Spark 中我们是这样做的：

```py
w2v = feat.Word2Vec(
    vectorSize=5
    , minCount=2
    , inputCol=sw_remover.getOutputCol()
    , outputCol='vector'
)
```

我们将从`.Word2Vec(...)`方法中得到一个包含五个元素的向量。此外，只有在语料库中至少出现两次的单词才会被用来创建单词嵌入。以下是结果向量的样子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00160.jpeg)

# 另请参阅

+   要了解更多关于文本特征工程的信息，请查看 Packt 的这个位置：[`bit.ly/2IZ7ZZA`](http://bit.ly/2IZ7ZZA)

# 离散化连续变量

有时，将连续变量离散化表示实际上是有用的。

在这个配方中，我们将学习如何使用傅立叶级数中的一个例子离散化数值特征。

# 准备工作

要执行这个配方，你需要一个可用的 Spark 环境。

不需要其他先决条件。

# 如何做...

在这个配方中，我们将使用位于`data`文件夹中的一个小数据集，即`fourier_signal.csv`：

```py
signal_df = spark.read.csv(
    '../data/fourier_signal.csv'
    , header=True
    , inferSchema=True
)

steps = feat.QuantileDiscretizer(
       numBuckets=10,
       inputCol='signal',
       outputCol='discretized')

transformed = (
    steps
    .fit(signal_df)
    .transform(signal_df)
)
```

# 工作原理...

首先，我们将数据读入`signal_df`。`fourier_signal.csv`包含一个名为`signal`的单独列。

接下来，我们使用`.QuantileDiscretizer(...)`方法将信号离散为 10 个桶。桶的范围是基于分位数选择的，也就是说，每个桶将有相同数量的观察值。

这是原始信号的样子（黑线），以及它的离散表示的样子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00161.jpeg)

# 标准化连续变量

使用具有显著不同范围和分辨率的特征（如年龄和工资）构建机器学习模型可能不仅会带来计算问题，还会带来模型收敛和系数可解释性问题。

在这个配方中，我们将学习如何标准化连续变量，使它们的平均值为 0，标准差为 1。

# 准备工作

要执行这个配方，你需要一个可用的 Spark 环境。你还必须执行前面的配方。

不需要其他先决条件。

# 如何做...

为了标准化我们在前面的配方中引入的`signal`列，我们将使用`.StandardScaler(...)`方法：

```py
vec = feat.VectorAssembler(
    inputCols=['signal']
    , outputCol='signal_vec'
)

norm = feat.StandardScaler(
    inputCol=vec.getOutputCol()
    , outputCol='signal_norm'
    , withMean=True
    , withStd=True
)

norm_pipeline = Pipeline(stages=[vec, norm])
signal_norm = (
    norm_pipeline
    .fit(signal_df)
    .transform(signal_df)
)
```

# 工作原理...

首先，我们需要将单个特征转换为向量表示，因为`.StandardScaler(...)`方法只接受向量化的特征。

接下来，我们实例化`.StandardScaler(...)`对象。`withMean`参数指示方法将数据居中到平均值，而`withStd`参数将数据缩放到标准差等于 1。

这是我们信号的标准化表示的样子。请注意两条线的不同刻度：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00162.jpeg)

# 主题挖掘

有时，有必要根据其内容将文本文档聚类到桶中。

在这个配方中，我们将通过一个例子来为从维基百科提取的一组短段落分配一个主题。

# 准备工作

要执行这个配方，你需要一个可用的 Spark 环境。

不需要其他先决条件。

# 如何做...

为了对文档进行聚类，我们首先需要从我们的文章中提取特征。请注意，以下文本由于空间限制而被缩写，有关完整代码，请参考 GitHub 存储库：

```py
articles = spark.createDataFrame([
    ('''
        The Andromeda Galaxy, named after the mythological 
        Princess Andromeda, also known as Messier 31, M31, 
        or NGC 224, is a spiral galaxy approximately 780 
        kiloparsecs (2.5 million light-years) from Earth, 
        and the nearest major galaxy to the Milky Way. 
        Its name stems from the area of the sky in which it 
        appears, the constellation of Andromeda. The 2006 
        observations by the Spitzer Space Telescope revealed 
        that the Andromeda Galaxy contains approximately one 
        trillion stars, more than twice the number of the 
        Milky Way’s estimated 200-400 billion stars. The 
        Andromeda Galaxy, spanning approximately 220,000 light 
        years, is the largest galaxy in our Local Group, 
        which is also home to the Triangulum Galaxy and 
        other minor galaxies. The Andromeda Galaxy's mass is 
        estimated to be around 1.76 times that of the Milky 
        Way Galaxy (~0.8-1.5×1012 solar masses vs the Milky 
        Way's 8.5×1011 solar masses).
    ''','Galaxy', 'Andromeda')
    (...) 
    , ('''
        Washington, officially the State of Washington, is a state in the Pacific 
        Northwest region of the United States. Named after George Washington, 
        the first president of the United States, the state was made out of the 
        western part of the Washington Territory, which was ceded by Britain in 
        1846 in accordance with the Oregon Treaty in the settlement of the 
        Oregon boundary dispute. It was admitted to the Union as the 42nd state 
        in 1889\. Olympia is the state capital. Washington is sometimes referred 
        to as Washington State, to distinguish it from Washington, D.C., the 
        capital of the United States, which is often shortened to Washington.
    ''','Geography', 'Washington State') 
], ['articles', 'Topic', 'Object'])

splitter = feat.RegexTokenizer(
    inputCol='articles'
    , outputCol='articles_split'
    , pattern='\s+|[,.\"]'
)

sw_remover = feat.StopWordsRemover(
    inputCol=splitter.getOutputCol()
    , outputCol='no_stopWords'
)

count_vec = feat.CountVectorizer(
    inputCol=sw_remover.getOutputCol()
    , outputCol='vector'
)

lda_clusters = clust.LDA(
    k=3
    , optimizer='online'
    , featuresCol=count_vec.getOutputCol()
)

topic_pipeline = Pipeline(
    stages=[
        splitter
        , sw_remover
        , count_vec
        , lda_clusters
    ]
)
```

# 工作原理...

首先，我们创建一个包含我们文章的 DataFrame。

接下来，我们将几乎按照*从文本中提取特征*配方中的步骤进行操作：

1.  我们使用`.RegexTokenizer(...)`拆分句子

1.  我们使用`.StopWordsRemover(...)`去除停用词

1.  我们使用`.CountVectorizer(...)`计算每个单词的出现次数

为了在我们的数据中找到聚类，我们将使用**潜在狄利克雷分配**（**LDA**）模型。在我们的情况下，我们知道我们希望有三个聚类，但如果你不知道你可能有多少聚类，你可以使用我们在本章前面介绍的*调整超参数*配方之一。

最后，我们把所有东西都放在管道中以方便我们使用。

一旦模型被估计，让我们看看它的表现。这里有一段代码可以帮助我们做到这一点；注意 NumPy 的`.argmax(...)`方法，它可以帮助我们找到最高值的索引：

```py
for topic in ( 
        topic_pipeline
        .fit(articles)
        .transform(articles)
        .select('Topic','Object','topicDistribution')
        .take(10)
):
    print(
        topic.Topic
        , topic.Object
        , np.argmax(topic.topicDistribution)
        , topic.topicDistribution
    )
```

这就是我们得到的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00163.jpeg)

正如你所看到的，通过适当的处理，我们可以从文章中正确提取主题；关于星系的文章被分组在第 2 个聚类中，地理信息在第 1 个聚类中，动物在第 0 个聚类中。
