# 面向 Python 开发者的 Spark（二）

> 原文：[`zh.annas-archive.org/md5/1F2AF128A0828F73EE5EA24057C01070`](https://zh.annas-archive.org/md5/1F2AF128A0828F73EE5EA24057C01070)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Spark 从数据中学习

在上一章中，我们已经为数据的收集奠定了基础，现在我们准备从数据中学习。机器学习是关于从数据中获取见解。我们的目标是概述 Spark MLlib（简称机器学习库）并将适当的算法应用于我们的数据集，以便得出见解。从 Twitter 数据集中，我们将应用无监督的聚类算法，以区分 Apache Spark 相关的推文和其他推文。我们首先需要预处理数据，以提取相关特征，然后将机器学习算法应用于我们的数据集，最后评估模型的结果和性能。

在本章中，我们将涵盖以下内容：

+   提供 Spark MLlib 模块及其算法以及典型的机器学习工作流程的概述。

+   预处理 Twitter 收集的数据集，以提取相关特征，应用无监督的聚类算法来识别 Apache Spark 相关的推文。然后，评估模型和获得的结果。

+   描述 Spark 机器学习管道。

# 在应用架构中定位 Spark MLlib

让我们首先将本章的重点放在数据密集型应用架构上。我们将集中精力放在分析层，更确切地说是机器学习上。这将为流应用提供基础，因为我们希望将从数据的批处理中学到的知识应用于流分析的推理规则。

以下图表设置了本章重点的上下文，突出了分析层内的机器学习模块，同时使用了探索性数据分析、Spark SQL 和 Pandas 工具。

![在应用架构中定位 Spark MLlib](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_04_01.jpg)

# 对 Spark MLlib 算法进行分类

Spark MLlib 是 Spark 的一个快速发展模块，每次 Spark 发布都会添加新的算法。

以下图表提供了 Spark MLlib 算法的高级概述，分为传统的广义机器学习技术和数据的分类或连续性特性：

![对 Spark MLlib 算法进行分类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_04_02.jpg)

我们将 Spark MLlib 算法分为两列，根据数据类型分为分类或连续。我们区分分类或更具有定性特征的数据与连续数据，后者是定量的。定性数据的一个例子是预测天气；给定大气压、温度和云的存在和类型，天气将是晴天、干燥、多雨或阴天。这些是离散值。另一方面，假设我们想要预测房价，给定位置、平方米和床的数量；可以使用线性回归来预测房地产价值。在这种情况下，我们谈论的是连续或定量值。

水平分组反映了所使用的机器学习方法的类型。无监督与监督机器学习技术取决于训练数据是否带有标签。在无监督学习挑战中，学习算法没有标签。目标是找到输入中的隐藏结构。在监督学习的情况下，数据是有标签的。重点是使用回归进行预测，如果数据是连续的，或者使用分类，如果数据是分类的。

机器学习的一个重要类别是推荐系统，它利用协同过滤技术。亚马逊网店和 Netflix 拥有非常强大的推荐系统来支持他们的推荐。

随机梯度下降是一种适合 Spark 分布式计算的机器学习优化技术之一。

对于处理大量文本，Spark 提供了关键的特征提取和转换库，如**TF-IDF**（**词项频率-逆文档频率**），Word2Vec，标准缩放器和归一化器。

## 监督和无监督学习

我们在这里更深入地探讨了 Spark MLlib 提供的传统机器学习算法。我们根据数据是否有标签来区分监督学习和无监督学习。我们根据数据是离散的还是连续的来区分分类或连续。

以下图表解释了 Spark MLlib 监督和无监督机器学习算法以及预处理技术：

![监督和无监督学习](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_04_03.jpg)

以下监督和无监督的 MLlib 算法和预处理技术目前在 Spark 中可用：

+   **聚类**：这是一种无监督的机器学习技术，其中数据没有标记。目的是从数据中提取结构：

+   **K 均值**：这将数据分区为 K 个不同的簇

+   **高斯混合**：根据组件的最大后验概率分配簇

+   **幂迭代聚类（PIC）**：这基于图的顶点之间的成对边相似性进行分组

+   **潜在狄利克雷分配**（**LDA**）：这用于将文本文档集合分组成主题

+   **流式 K 均值**：这意味着使用传入数据的窗口函数动态地对流式数据进行聚类

+   **降维**：这旨在减少考虑的特征数量。基本上，这减少了数据中的噪音，并专注于关键特征：

+   **奇异值分解**（**SVD**）：这将包含数据的矩阵分解为更简单的有意义的部分。它将初始矩阵分解为三个矩阵。

+   **主成分分析**（**PCA**）：这将高维数据集近似为低维子空间。

+   **回归和分类**：回归使用标记的训练数据预测输出值，而分类将结果分组成类别。分类具有分类或无序的因变量，而回归具有连续和有序的因变量：

+   **线性回归模型**（线性回归，逻辑回归和支持向量机）：线性回归算法可以表示为旨在最小化基于权重变量向量的目标函数的凸优化问题。目标函数通过函数的正则化部分和损失函数控制模型的复杂性和模型的误差。

+   **朴素贝叶斯**：这基于给定观察的标签的条件概率分布进行预测。它假设特征之间是相互独立的。

+   **决策树**：这执行特征空间的递归二元分区。在树节点级别上最大化信息增益，以确定分区的最佳拆分。

+   **树的集成**（随机森林和梯度提升树）：树集成算法将基本决策树模型组合在一起，以构建一个高性能的模型。它们对于分类和回归任务非常直观和成功。

+   **保序回归**：这最小化给定数据和观察响应之间的均方误差。

## 附加学习算法

Spark MLlib 提供的算法比监督和无监督学习算法更多。我们还有三种额外类型的机器学习方法：推荐系统，优化算法和特征提取。

![附加学习算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_04_04.jpg)

以下附加的 MLlib 算法目前在 Spark 中可用：

+   **协同过滤**：这是推荐系统的基础。它创建一个用户-项目关联矩阵，并旨在填补空白。基于其他用户和项目以及它们的评分，它推荐目标用户尚未评分的项目。在分布式计算中，最成功的算法之一是**ALS**（**交替最小二乘法**的缩写）：

+   **交替最小二乘法**：这种矩阵分解技术结合了隐式反馈、时间效应和置信水平。它将大型用户项目矩阵分解为较低维度的用户和项目因子。它通过交替固定其因子来最小化二次损失函数。

+   **特征提取和转换**：这些是大型文本文档处理的基本技术。它包括以下技术：

+   **词频**：搜索引擎使用 TF-IDF 对大量语料库中的文档相关性进行评分和排名。它还用于机器学习，以确定文档或语料库中单词的重要性。词频统计上确定了术语相对于语料库中的频率的权重。单独的词频可能会产生误导，因为它过分强调了诸如*the*、*of*或*and*这样提供很少信息的词语。逆文档频率提供了特定性或术语在语料库中所有文档中是罕见还是常见的度量。

+   **Word2Vec**：这包括两种模型，**Skip-Gram**和**连续词袋**。Skip-Gram 根据单词的滑动窗口预测给定单词的相邻单词，而连续词袋根据相邻单词预测当前单词。

+   **标准缩放器**：作为预处理的一部分，数据集通常必须通过均值去除和方差缩放进行标准化。我们计算训练数据的均值和标准差，并将相同的转换应用于测试数据。

+   **标准化器**：我们将样本缩放为单位范数。它对于二次形式（如点积或核方法）非常有用。

+   **特征选择**：通过选择模型中最相关的特征来减少向量空间的维度。

+   **卡方选择器**：这是一种衡量两个事件独立性的统计方法。

+   **优化**：这些特定的 Spark MLlib 优化算法专注于梯度下降的各种技术。Spark 提供了非常高效的梯度下降实现，可以在分布式机器集群上进行。它通过迭代沿着最陡的下降方向寻找局部最小值。由于需要迭代处理所有可用数据，因此计算密集型：

+   **随机梯度下降**：我们最小化一个可微函数的总和。随机梯度下降仅使用训练数据的样本来更新特定迭代中的参数。它用于大规模和稀疏的机器学习问题，如文本分类。

+   **有限内存 BFGS**（**L-BFGS**）：顾名思义，L-BFGS 使用有限内存，适用于 Spark MLlib 的分布式优化算法实现。

# Spark MLlib 数据类型

MLlib 支持四种基本数据类型：**本地向量**、**标记点**、**本地矩阵**和**分布式矩阵**。这些数据类型在 Spark MLlib 算法中被广泛使用：

+   **本地向量**：这存在于单个机器中。它可以是密集的或稀疏的：

+   密集向量是传统的双精度数组。密集向量的一个示例是`[5.0, 0.0, 1.0, 7.0]`。

+   稀疏向量使用整数索引和双精度值。因此，向量`[5.0, 0.0, 1.0, 7.0]`的稀疏表示将是`(4, [0, 2, 3], [5.0, 1.0, 7.0])`，其中表示向量的维度。

以下是 PySpark 中本地向量的示例：

```py
import numpy as np
import scipy.sparse as sps
from pyspark.mllib.linalg import Vectors

# NumPy array for dense vector.
dvect1 = np.array([5.0, 0.0, 1.0, 7.0])
# Python list for dense vector.
dvect2 = [5.0, 0.0, 1.0, 7.0]
# SparseVector creation
svect1 = Vectors.sparse(4, [0, 2, 3], [5.0, 1.0, 7.0])
# Sparse vector using a single-column SciPy csc_matrix
svect2 = sps.csc_matrix((np.array([5.0, 1.0, 7.0]), np.array([0, 2, 3])), shape = (4, 1))
```

+   **标记点**。标记点是在监督学习中使用的带有标签的稠密或稀疏向量。在二元标签的情况下，0.0 表示负标签，而 1.0 表示正值。

这是 PySpark 中标记点的一个示例：

```py
from pyspark.mllib.linalg import SparseVector
from pyspark.mllib.regression import LabeledPoint

# Labeled point with a positive label and a dense feature vector.
lp_pos = LabeledPoint(1.0, [5.0, 0.0, 1.0, 7.0])

# Labeled point with a negative label and a sparse feature vector.
lp_neg = LabeledPoint(0.0, SparseVector(4, [0, 2, 3], [5.0, 1.0, 7.0]))
```

+   **本地矩阵**：这个本地矩阵位于单个机器上，具有整数类型的索引和双精度类型的值。

这是 PySpark 中本地矩阵的一个示例：

```py
from pyspark.mllib.linalg import Matrix, Matrices

# Dense matrix ((1.0, 2.0, 3.0), (4.0, 5.0, 6.0))
dMatrix = Matrices.dense(2, 3, [1, 2, 3, 4, 5, 6])

# Sparse matrix ((9.0, 0.0), (0.0, 8.0), (0.0, 6.0))
sMatrix = Matrices.sparse(3, 2, [0, 1, 3], [0, 2, 1], [9, 6, 8])
```

+   **分布式矩阵**：利用 RDD 的分布式特性，分布式矩阵可以在一组机器的集群中共享。我们区分四种分布式矩阵类型：`RowMatrix`、`IndexedRowMatrix`、`CoordinateMatrix`和`BlockMatrix`。

+   `RowMatrix`：这需要一个向量的 RDD，并从向量的 RDD 创建一个带有无意义索引的行的分布式矩阵，称为`RowMatrix`。

+   `IndexedRowMatrix`：在这种情况下，行索引是有意义的。首先，我们使用`IndexedRow`类创建索引行的 RDD，然后创建`IndexedRowMatrix`。

+   `CoordinateMatrix`：这对于表示非常大和非常稀疏的矩阵很有用。`CoordinateMatrix`是从`MatrixEntry`点的 RDD 创建的，由(long, long, float)类型的元组表示。

+   `BlockMatrix`：这些是从子矩阵块的 RDD 创建的，其中子矩阵块是`((blockRowIndex, blockColIndex), sub-matrix)`。

# 机器学习工作流程和数据流程

除了算法，机器学习还涉及到流程。我们将讨论监督和无监督机器学习的典型工作流程和数据流程。

## 监督机器学习工作流程

在监督机器学习中，输入训练数据集是有标签的。一个关键的数据实践是将输入数据分为训练集和测试集，并相应地验证模型。

在监督学习中，我们通常会经历一个六步的流程：

+   **收集数据**：这一步基本上与前一章相关，并确保我们收集正确数量和粒度的数据，以使机器学习算法能够提供可靠的答案。

+   **预处理数据**：这一步是关于通过抽样检查数据质量，填补缺失值（如果有的话），对数据进行缩放和归一化。我们还定义特征提取过程。通常，在大型基于文本的数据集的情况下，我们应用标记化、停用词去除、词干提取和 TF-IDF。

在监督学习中，我们将输入数据分为训练集和测试集。我们还可以实施各种采样和数据集拆分策略，以进行交叉验证。

+   **准备数据**：在这一步中，我们将数据格式化或转换为算法所期望的格式或数据类型。在 Spark MLlib 中，这包括本地向量、稠密或稀疏向量、标记点、本地矩阵、带有行矩阵、索引行矩阵、坐标矩阵和块矩阵的分布式矩阵。

+   **模型**：在这一步中，我们应用适合问题的算法，并获得评估步骤中最适合算法的结果。我们可能有多个适合问题的算法；它们在评估步骤中的性能将被评分以选择最佳的性能。我们可以实施模型的集成或组合，以达到最佳结果。

+   **优化**：我们可能需要对某些算法的最佳参数进行网格搜索。这些参数在训练期间确定，并在测试和生产阶段进行微调。

+   **评估**：最终我们对模型进行评分，并选择在准确性、性能、可靠性和可扩展性方面最好的模型。我们将最佳性能的模型移至测试集，以确定模型的预测准确性。一旦对经过微调的模型满意，我们将其移至生产环境以处理实时数据。

监督机器学习的工作流程和数据流程如下图所示：

![监督机器学习工作流程](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_04_05.jpg)

## 无监督机器学习工作流

与监督学习相反，在无监督学习的情况下，我们的初始数据没有标签，这在现实生活中是最常见的情况。我们将使用聚类或降维算法从数据中提取结构。在无监督学习的情况下，我们不会将数据分为训练和测试，因为我们无法进行任何预测，因为数据没有标签。我们将对数据进行六个步骤的训练，类似于监督学习。一旦模型训练完成，我们将评估结果并微调模型，然后将其投入生产。

无监督学习可以作为监督学习的初步步骤。换句话说，我们在进入学习阶段之前看一下如何降低数据的维度。

无监督机器学习工作流和数据流如下所示：

![无监督机器学习工作流程](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_04_06.jpg)

# 对 Twitter 数据集进行聚类

让我们先从 Twitter 中提取的数据中了解一下，并了解数据结构，以便准备并通过 K-Means 聚类算法运行。我们的攻击计划使用了前面描述的无监督学习的过程和数据流。步骤如下：

1.  将所有推文文件合并为单个数据框。

1.  解析推文，删除停用词，提取表情符号，提取 URL，最后规范化单词（例如，将它们映射为小写并删除标点和数字）。

1.  特征提取包括以下内容：

+   **标记化**：这将解析推文文本为单个单词或标记

+   **TF-IDF**：这将应用 TF-IDF 算法从标记化的推文文本中创建特征向量

+   **哈希 TF-IDF**：这将对标记向量应用哈希函数

1.  运行 K-Means 聚类算法。

1.  评估 K-Means 聚类的结果：

+   识别推文归属于聚类

+   使用多维缩放或主成分分析算法将维度降低到两个维度

+   绘制聚类

1.  管道：

+   微调相关聚类 K 的数量

+   测量模型成本

+   选择最佳模型

## 在 Twitter 数据集上应用 Scikit-Learn

Python 自带的 Scikit-Learn 机器学习库是最可靠、直观和强大的工具之一。在使用 Pandas 和 Scikit-Learn 进行预处理和无监督学习之前，通常有利于使用 Scikit-Learn 探索数据的样本。在使用 Spark MLlib 分离聚类之前，我们经常使用 Scikit-Learn 探索数据的样本。

我们有一袋杂货的 7540 条推文。它包含与 Apache Spark、Python、即将到来的总统选举以及 Lady Gaga 和 Justin Bieber 相关的时尚和音乐推文。我们正在使用 Python Scikit-Learn 对 Twitter 数据集进行 K-Means 聚类算法。我们首先将样本数据加载到 Pandas 数据框中：

```py
import pandas as pd

csv_in = 'C:\\Users\\Amit\\Documents\\IPython Notebooks\\AN00_Data\\unq_tweetstxt.csv'
twts_df01 = pd.read_csv(csv_in, sep =';', encoding='utf-8')

In [24]:

twts_df01.count()
Out[24]:
Unnamed: 0    7540
id            7540
created_at    7540
user_id       7540
user_name     7538
tweet_text    7540
dtype: int64

#
# Introspecting the tweets text
#
In [82]:

twtstxt_ls01[6910:6920]
Out[82]:
['RT @deroach_Ismoke: I am NOT voting for #hilaryclinton http://t.co/jaZZpcHkkJ',
 'RT @AnimalRightsJen: #HilaryClinton What do Bernie Sanders and Donald Trump Have in Common?: He has so far been th... http://t.co/t2YRcGCh6…',
 'I understand why Bill was out banging other chicks........I mean look at what he is married to.....\n@HilaryClinton',
 '#HilaryClinton What do Bernie Sanders and Donald Trump Have in Common?: He has so far been th... http://t.co/t2YRcGCh67 #Tcot #UniteBlue']
```

我们首先从推文文本中进行特征提取。我们使用具有 10,000 个特征和英语停用词的 TF-IDF 向量化器对数据集应用稀疏矢量化器：

```py
In [37]:

print("Extracting features from the training dataset using a sparse vectorizer")
t0 = time()
Extracting features from the training dataset using a sparse vectorizer
In [38]:

vectorizer = TfidfVectorizer(max_df=0.5, max_features=10000,
                                 min_df=2, stop_words='english',
                                 use_idf=True)
X = vectorizer.fit_transform(twtstxt_ls01)
#
# Output of the TFIDF Feature vectorizer
#
print("done in %fs" % (time() - t0))
print("n_samples: %d, n_features: %d" % X.shape)
print()
done in 5.232165s
n_samples: 7540, n_features: 6638
```

由于数据集现在被分成了 7540 个样本，每个样本有 6638 个特征向量，我们准备将这个稀疏矩阵输入 K-Means 聚类算法。我们最初选择七个聚类和 100 次最大迭代：

```py
In [47]:

km = KMeans(n_clusters=7, init='k-means++', max_iter=100, n_init=1,
            verbose=1)

print("Clustering sparse data with %s" % km)
t0 = time()
km.fit(X)
print("done in %0.3fs" % (time() - t0))

Clustering sparse data with KMeans(copy_x=True, init='k-means++', max_iter=100, n_clusters=7, n_init=1,
    n_jobs=1, precompute_distances='auto', random_state=None, tol=0.0001,
    verbose=1)
Initialization complete
Iteration  0, inertia 13635.141
Iteration  1, inertia 6943.485
Iteration  2, inertia 6924.093
Iteration  3, inertia 6915.004
Iteration  4, inertia 6909.212
Iteration  5, inertia 6903.848
Iteration  6, inertia 6888.606
Iteration  7, inertia 6863.226
Iteration  8, inertia 6860.026
Iteration  9, inertia 6859.338
Iteration 10, inertia 6859.213
Iteration 11, inertia 6859.102
Iteration 12, inertia 6859.080
Iteration 13, inertia 6859.060
Iteration 14, inertia 6859.047
Iteration 15, inertia 6859.039
Iteration 16, inertia 6859.032
Iteration 17, inertia 6859.031
Iteration 18, inertia 6859.029
Converged at iteration 18
done in 1.701s
```

K-Means 聚类算法在 18 次迭代后收敛。在以下结果中，我们看到了七个聚类及其各自的关键词。聚类`0`和`6`是关于贾斯汀·比伯和 Lady Gaga 相关推文的音乐和时尚。聚类`1`和`5`与美国总统选举有关，包括唐纳德·特朗普和希拉里·克林顿相关的推文。聚类`2`和`3`是我们感兴趣的，因为它们涉及 Apache Spark 和 Python。聚类`4`包含泰国相关的推文：

```py
#
# Introspect top terms per cluster
#

In [49]:

print("Top terms per cluster:")
order_centroids = km.cluster_centers_.argsort()[:, ::-1]
terms = vectorizer.get_feature_names()
for i in range(7):
    print("Cluster %d:" % i, end='')
    for ind in order_centroids[i, :20]:
        print(' %s' % terms[ind], end='')
    print()
Top terms per cluster:
Cluster 0: justinbieber love mean rt follow thank hi https whatdoyoumean video wanna hear whatdoyoumeanviral rorykramer happy lol making person dream justin
Cluster 1: donaldtrump hilaryclinton rt https trump2016 realdonaldtrump trump gop amp justinbieber president clinton emails oy8ltkstze tcot like berniesanders hilary people email
Cluster 2: bigdata apachespark hadoop analytics rt spark training chennai ibm datascience apache processing cloudera mapreduce data sap https vora transforming development
Cluster 3: apachespark python https rt spark data amp databricks using new learn hadoop ibm big apache continuumio bluemix learning join open
Cluster 4: ernestsgantt simbata3 jdhm2015 elsahel12 phuketdailynews dreamintentions beyhiveinfrance almtorta18 civipartnership 9_a_6 25whu72ep0 k7erhvu7wn fdmxxxcm3h osxuh2fxnt 5o5rmb0xhp jnbgkqn0dj ovap57ujdh dtzsz3lb6x sunnysai12345 sdcvulih6g
Cluster 5: trump donald donaldtrump starbucks trumpquote trumpforpresident oy8ltkstze https zfns7pxysx silly goy stump trump2016 news jeremy coffee corbyn ok7vc8aetz rt tonight
Cluster 6: ladygaga gaga lady rt https love follow horror cd story ahshotel american japan hotel human trafficking music fashion diet queen ahs
```

我们将通过绘制聚类来可视化结果。我们有 7,540 个样本，6,638 个特征。不可能可视化那么多维度。我们将使用**多维缩放**（**MDS**）算法将聚类的多维特征降低到两个可处理的维度，以便能够将它们呈现出来：

```py
import matplotlib.pyplot as plt
import matplotlib as mpl
from sklearn.manifold import MDS

MDS()

#
# Bring down the MDS to two dimensions (components) as we will plot 
# the clusters
#
mds = MDS(n_components=2, dissimilarity="precomputed", random_state=1)

pos = mds.fit_transform(dist)  # shape (n_components, n_samples)

xs, ys = pos[:, 0], pos[:, 1]

In [67]:

#
# Set up colors per clusters using a dict
#
cluster_colors = {0: '#1b9e77', 1: '#d95f02', 2: '#7570b3', 3: '#e7298a', 4: '#66a61e', 5: '#9990b3', 6: '#e8888a'}

#
#set up cluster names using a dict
#
cluster_names = {0: 'Music, Pop', 
                 1: 'USA Politics, Election', 
                 2: 'BigData, Spark', 
                 3: 'Spark, Python',
                 4: 'Thailand', 
                 5: 'USA Politics, Election', 
                 6: 'Music, Pop'}
In [115]:
#
# ipython magic to show the matplotlib plots inline
#
%matplotlib inline 

#
# Create data frame which includes MDS results, cluster numbers and tweet texts to be displayed
#
df = pd.DataFrame(dict(x=xs, y=ys, label=clusters, txt=twtstxt_ls02_utf8))
ix_start = 2000
ix_stop  = 2050
df01 = df[ix_start:ix_stop]

print(df01[['label','txt']])
print(len(df01))
print()

# Group by cluster

groups = df.groupby('label')
groups01 = df01.groupby('label')

# Set up the plot

fig, ax = plt.subplots(figsize=(17, 10)) 
ax.margins(0.05) 

#
# Build the plot object
#
for name, group in groups01:
    ax.plot(group.x, group.y, marker='o', linestyle='', ms=12, 
            label=cluster_names[name], color=cluster_colors[name], 
            mec='none')
    ax.set_aspect('auto')
    ax.tick_params(\
        axis= 'x',         # settings for x-axis
        which='both',      # 
        bottom='off',      # 
        top='off',         # 
        labelbottom='off')
    ax.tick_params(\
        axis= 'y',         # settings for y-axis
        which='both',      # 
        left='off',        # 
        top='off',         # 
        labelleft='off')

ax.legend(numpoints=1)     #
#
# Add label in x,y position with tweet text
#
for i in range(ix_start, ix_stop):
    ax.text(df01.ix[i]['x'], df01.ix[i]['y'], df01.ix[i]['txt'], size=10)  

plt.show()                 # Display the plot

      label       text
2000      2       b'RT @BigDataTechCon: '
2001      3       b"@4Quant 's presentat"
2002      2       b'Cassandra Summit 201'
```

这是聚类`2`的绘图，*大数据*和*Spark*用蓝色点表示，聚类`3`的*Spark*和*Python*用红色点表示，以及一些与各自聚类相关的示例推文：

![在 Twitter 数据集上应用 Scikit-Learn](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_04_07.jpg)

通过对 Scikit-Learn 进行探索和处理，我们对数据获得了一些有益的见解。现在我们将把注意力集中在 Spark MLlib 上，并在 Twitter 数据集上进行尝试。

## 预处理数据集

现在，我们将专注于特征提取和工程，以准备数据进行聚类算法运行。我们实例化 Spark 上下文，并将 Twitter 数据集读入 Spark 数据框。然后我们将逐步对推文文本数据进行标记化，对标记应用哈希词频算法，最后应用逆文档频率算法并重新调整数据。代码如下：

```py
In [3]:
#
# Read csv in a Panda DF
#
#
import pandas as pd
csv_in = '/home/an/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark/data/unq_tweetstxt.csv'
pddf_in = pd.read_csv(csv_in, index_col=None, header=0, sep=';', encoding='utf-8')

In [4]:

sqlContext = SQLContext(sc)

In [5]:

#
# Convert a Panda DF to a Spark DF
#
#

spdf_02 = sqlContext.createDataFrame(pddf_in[['id', 'user_id', 'user_name', 'tweet_text']])

In [8]:

spdf_02.show()

In [7]:

spdf_02.take(3)

Out[7]:

[Row(id=638830426971181057, user_id=3276255125, user_name=u'True Equality', tweet_text=u'ernestsgantt: BeyHiveInFrance: 9_A_6: dreamintentions: elsahel12: simbata3: JDHM2015: almtorta18: dreamintentions:\u2026 http://t.co/VpD7FoqMr0'),
 Row(id=638830426727911424, user_id=3276255125, user_name=u'True Equality', tweet_text=u'ernestsgantt: BeyHiveInFrance: PhuketDailyNews: dreamintentions: elsahel12: simbata3: JDHM2015: almtorta18: CiviPa\u2026 http://t.co/VpD7FoqMr0'),
 Row(id=638830425402556417, user_id=3276255125, user_name=u'True Equality', tweet_text=u'ernestsgantt: BeyHiveInFrance: 9_A_6: ernestsgantt: elsahel12: simbata3: JDHM2015: almtorta18: CiviPartnership: dr\u2026 http://t.co/EMDOn8chPK')]

In [9]:

from pyspark.ml.feature import HashingTF, IDF, Tokenizer

In [10]:

#
# Tokenize the tweet_text 
#
tokenizer = Tokenizer(inputCol="tweet_text", outputCol="tokens")
tokensData = tokenizer.transform(spdf_02)

In [11]:

tokensData.take(1)

Out[11]:

[Row(id=638830426971181057, user_id=3276255125, user_name=u'True Equality', tweet_text=u'ernestsgantt: BeyHiveInFrance: 9_A_6: dreamintentions: elsahel12: simbata3: JDHM2015: almtorta18: dreamintentions:\u2026 http://t.co/VpD7FoqMr0', tokens=[u'ernestsgantt:', u'beyhiveinfrance:', u'9_a_6:', u'dreamintentions:', u'elsahel12:', u'simbata3:', u'jdhm2015:', u'almtorta18:', u'dreamintentions:\u2026', u'http://t.co/vpd7foqmr0'])]

In [14]:

#
# Apply Hashing TF to the tokens
#
hashingTF = HashingTF(inputCol="tokens", outputCol="rawFeatures", numFeatures=2000)
featuresData = hashingTF.transform(tokensData)

In [15]:

featuresData.take(1)

Out[15]:

[Row(id=638830426971181057, user_id=3276255125, user_name=u'True Equality', tweet_text=u'ernestsgantt: BeyHiveInFrance: 9_A_6: dreamintentions: elsahel12: simbata3: JDHM2015: almtorta18: dreamintentions:\u2026 http://t.co/VpD7FoqMr0', tokens=[u'ernestsgantt:', u'beyhiveinfrance:', u'9_a_6:', u'dreamintentions:', u'elsahel12:', u'simbata3:', u'jdhm2015:', u'almtorta18:', u'dreamintentions:\u2026', u'http://t.co/vpd7foqmr0'], rawFeatures=SparseVector(2000, {74: 1.0, 97: 1.0, 100: 1.0, 160: 1.0, 185: 1.0, 742: 1.0, 856: 1.0, 991: 1.0, 1383: 1.0, 1620: 1.0}))]

In [16]:

#
# Apply IDF to the raw features and rescale the data
#
idf = IDF(inputCol="rawFeatures", outputCol="features")
idfModel = idf.fit(featuresData)
rescaledData = idfModel.transform(featuresData)

for features in rescaledData.select("features").take(3):
  print(features)

In [17]:

rescaledData.take(2)

Out[17]:

[Row(id=638830426971181057, user_id=3276255125, user_name=u'True Equality', tweet_text=u'ernestsgantt: BeyHiveInFrance: 9_A_6: dreamintentions: elsahel12: simbata3: JDHM2015: almtorta18: dreamintentions:\u2026 http://t.co/VpD7FoqMr0', tokens=[u'ernestsgantt:', u'beyhiveinfrance:', u'9_a_6:', u'dreamintentions:', u'elsahel12:', u'simbata3:', u'jdhm2015:', u'almtorta18:', u'dreamintentions:\u2026', u'http://t.co/vpd7foqmr0'], rawFeatures=SparseVector(2000, {74: 1.0, 97: 1.0, 100: 1.0, 160: 1.0, 185: 1.0, 742: 1.0, 856: 1.0, 991: 1.0, 1383: 1.0, 1620: 1.0}), features=SparseVector(2000, {74: 2.6762, 97: 1.8625, 100: 2.6384, 160: 2.9985, 185: 2.7481, 742: 5.5269, 856: 4.1406, 991: 2.9518, 1383: 4.694, 1620: 3.073})),
 Row(id=638830426727911424, user_id=3276255125, user_name=u'True Equality', tweet_text=u'ernestsgantt: BeyHiveInFrance: PhuketDailyNews: dreamintentions: elsahel12: simbata3: JDHM2015: almtorta18: CiviPa\u2026 http://t.co/VpD7FoqMr0', tokens=[u'ernestsgantt:', u'beyhiveinfrance:', u'phuketdailynews:', u'dreamintentions:', u'elsahel12:', u'simbata3:', u'jdhm2015:', u'almtorta18:', u'civipa\u2026', u'http://t.co/vpd7foqmr0'], rawFeatures=SparseVector(2000, {74: 1.0, 97: 1.0, 100: 1.0, 160: 1.0, 185: 1.0, 460: 1.0, 987: 1.0, 991: 1.0, 1383: 1.0, 1620: 1.0}), features=SparseVector(2000, {74: 2.6762, 97: 1.8625, 100: 2.6384, 160: 2.9985, 185: 2.7481, 460: 6.4432, 987: 2.9959, 991: 2.9518, 1383: 4.694, 1620: 3.073}))]

In [21]:

rs_pddf = rescaledData.toPandas()

In [22]:

rs_pddf.count()

Out[22]:

id             7540
user_id        7540
user_name      7540
tweet_text     7540
tokens         7540
rawFeatures    7540
features       7540
dtype: int64

In [27]:

feat_lst = rs_pddf.features.tolist()

In [28]:

feat_lst[:2]

Out[28]:

[SparseVector(2000, {74: 2.6762, 97: 1.8625, 100: 2.6384, 160: 2.9985, 185: 2.7481, 742: 5.5269, 856: 4.1406, 991: 2.9518, 1383: 4.694, 1620: 3.073}),
 SparseVector(2000, {74: 2.6762, 97: 1.8625, 100: 2.6384, 160: 2.9985, 185: 2.7481, 460: 6.4432, 987: 2.9959, 991: 2.9518, 1383: 4.694, 1620: 3.073})]
```

## 运行聚类算法

我们将使用 K-Means 算法对 Twitter 数据集进行处理。作为一个未标记和洗牌的推文包，我们想看看*Apache Spark*的推文是否被分组到一个单独的聚类中。从之前的步骤中，TF-IDF 稀疏特征向量被转换为将成为 Spark MLlib 程序输入的 RDD。我们用 5 个聚类、10 次迭代和 10 次运行来初始化 K-Means 模型：

```py
In [32]:

from pyspark.mllib.clustering import KMeans, KMeansModel
from numpy import array
from math import sqrt

In [34]:

# Load and parse the data

in_Data = sc.parallelize(feat_lst)

In [35]:

in_Data.take(3)

Out[35]:

[SparseVector(2000, {74: 2.6762, 97: 1.8625, 100: 2.6384, 160: 2.9985, 185: 2.7481, 742: 5.5269, 856: 4.1406, 991: 2.9518, 1383: 4.694, 1620: 3.073}),
 SparseVector(2000, {74: 2.6762, 97: 1.8625, 100: 2.6384, 160: 2.9985, 185: 2.7481, 460: 6.4432, 987: 2.9959, 991: 2.9518, 1383: 4.694, 1620: 3.073}),
 SparseVector(2000, {20: 4.3534, 74: 2.6762, 97: 1.8625, 100: 5.2768, 185: 2.7481, 856: 4.1406, 991: 2.9518, 1039: 3.073, 1620: 3.073, 1864: 4.6377})]

In [37]:

in_Data.count()

Out[37]:

7540

In [38]:

# Build the model (cluster the data)

clusters = KMeans.train(in_Data, 5, maxIterations=10,
        runs=10, initializationMode="random")

In [53]:

# Evaluate clustering by computing Within Set Sum of Squared Errors

def error(point):
    center = clusters.centers[clusters.predict(point)]
    return sqrt(sum([x**2 for x in (point - center)]))

WSSSE = in_Data.map(lambda point: error(point)).reduce(lambda x, y: x + y)
print("Within Set Sum of Squared Error = " + str(WSSSE))
```

## 评估模型和结果

微调聚类算法的一种方法是改变聚类的数量并验证输出。让我们检查一下聚类，并对迄今为止的聚类结果有所了解：

```py
In [43]:

cluster_membership = in_Data.map(lambda x: clusters.predict(x))

In [54]:

cluster_idx = cluster_membership.zipWithIndex()

In [55]:

type(cluster_idx)

Out[55]:

pyspark.rdd.PipelinedRDD

In [58]:

cluster_idx.take(20)

Out[58]:

[(3, 0),
 (3, 1),
 (3, 2),
 (3, 3),
 (3, 4),
 (3, 5),
 (1, 6),
 (3, 7),
 (3, 8),
 (3, 9),
 (3, 10),
 (3, 11),
 (3, 12),
 (3, 13),
 (3, 14),
 (1, 15),
 (3, 16),
 (3, 17),
 (1, 18),
 (1, 19)]

In [59]:

cluster_df = cluster_idx.toDF()

In [65]:

pddf_with_cluster = pd.concat([pddf_in, cluster_pddf],axis=1)

In [76]:

pddf_with_cluster._1.unique()

Out[76]:

array([3, 1, 4, 0, 2])

In [79]:

pddf_with_cluster[pddf_with_cluster['_1'] == 0].head(10)

Out[79]:
  Unnamed: 0   id   created_at   user_id   user_name   tweet_text   _1   _2
6227   3   642418116819988480   Fri Sep 11 19:23:09 +0000 2015   49693598   Ajinkya Kale   RT @bigdata: Distributed Matrix Computations i...   0   6227
6257   45   642391207205859328   Fri Sep 11 17:36:13 +0000 2015   937467860   Angela Bassa   [Auto] I'm reading ""Distributed Matrix Comput...   0   6257
6297   119   642348577147064320   Fri Sep 11 14:46:49 +0000 2015   18318677   Ben Lorica   Distributed Matrix Computations in @ApacheSpar...   0   6297
In [80]:

pddf_with_cluster[pddf_with_cluster['_1'] == 1].head(10)

Out[80]:
  Unnamed: 0   id   created_at   user_id   user_name   tweet_text   _1   _2
6   6   638830419090079746   Tue Sep 01 21:46:55 +0000 2015   2241040634   Massimo Carrisi   Python:Python: Removing \xa0 from string? - I ...   1   6
15   17   638830380578045953   Tue Sep 01 21:46:46 +0000 2015   57699376   Rafael Monnerat   RT @ramalhoorg: Noite de autógrafos do Fluent ...   1   15
18   41   638830280988426250   Tue Sep 01 21:46:22 +0000 2015   951081582   Jack Baldwin   RT @cloudaus: We are 3/4 full! 2-day @swcarpen...   1   18
19   42   638830276626399232   Tue Sep 01 21:46:21 +0000 2015   6525302   Masayoshi Nakamura   PynamoDB #AWS #DynamoDB #Python http://...   1   19
20   43   638830213288235008   Tue Sep 01 21:46:06 +0000 2015   3153874869   Baltimore Python   Flexx: Python UI tookit based on web technolog...   1   20
21   44   638830117645516800   Tue Sep 01 21:45:43 +0000 2015   48474625   Radio Free Denali   Hmm, emerge --depclean wants to remove somethi...   1   21
22   46   638829977014636544   Tue Sep 01 21:45:10 +0000 2015   154915461   Luciano Ramalho   Noite de autógrafos do Fluent Python no Garoa ...   1   22
23   47   638829882928070656   Tue Sep 01 21:44:47 +0000 2015   917320920   bsbafflesbrains   @DanSWright Harper channeling Monty Python. "...   1   23
24   48   638829868679954432   Tue Sep 01 21:44:44 +0000 2015   134280898   Lannick Technology   RT @SergeyKalnish: I am #hiring: Senior Back e...   1   24
25   49   638829707484508161   Tue Sep 01 21:44:05 +0000 2015   2839203454   Joshua Jones   RT @LindseyPelas: Surviving Monty Python in Fl...   1   25
In [81]:

pddf_with_cluster[pddf_with_cluster['_1'] == 2].head(10)

Out[81]:
  Unnamed: 0   id   created_at   user_id   user_name   tweet_text   _1   _2
7280   688   639056941592014848   Wed Sep 02 12:47:02 +0000 2015   2735137484   Chris   A true gay icon when will @ladygaga @Madonna @...   2   7280
In [82]:

pddf_with_cluster[pddf_with_cluster['_1'] == 3].head(10)

Out[82]:
  Unnamed: 0   id   created_at   user_id   user_name   tweet_text   _1   _2
0   0   638830426971181057   Tue Sep 01 21:46:57 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: 9_A_6: dreamint...   3   0
1   1   638830426727911424   Tue Sep 01 21:46:57 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: PhuketDailyNews...   3   1
2   2   638830425402556417   Tue Sep 01 21:46:56 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: 9_A_6: ernestsg...   3   2
3   3   638830424563716097   Tue Sep 01 21:46:56 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: PhuketDailyNews...   3   3
4   4   638830422256816132   Tue Sep 01 21:46:56 +0000 2015   3276255125   True Equality   ernestsgantt: elsahel12: 9_A_6: dreamintention...   3   4
5   5   638830420159655936   Tue Sep 01 21:46:55 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: PhuketDailyNews...   3   5
7   7   638830418330980352   Tue Sep 01 21:46:55 +0000 2015   3276255125   True Equality   ernestsgantt: elsahel12: 9_A_6: dreamintention...   3   7
8   8   638830397648822272   Tue Sep 01 21:46:50 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: PhuketDailyNews...   3   8
9   9   638830395375529984   Tue Sep 01 21:46:49 +0000 2015   3276255125   True Equality   ernestsgantt: elsahel12: 9_A_6: dreamintention...   3   9
10   10   638830392389177344   Tue Sep 01 21:46:49 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: PhuketDailyNews...   3   10
In [83]:

pddf_with_cluster[pddf_with_cluster['_1'] == 4].head(10)

Out[83]:
  Unnamed: 0   id   created_at   user_id   user_name   tweet_text   _1   _2
1361   882   642648214454317056   Sat Sep 12 10:37:28 +0000 2015   27415756   Raymond Enisuoh   LA Chosen For US 2024 Olympic Bid - LA2016 See...   4   1361
1363   885   642647848744583168   Sat Sep 12 10:36:01 +0000 2015   27415756   Raymond Enisuoh   Prison See: https://t.co/x3EKAExeFi … … … … … ...   4   1363
5412   11   640480770369286144   Sun Sep 06 11:04:49 +0000 2015   3242403023   Donald Trump 2016   " igiboooy! @ Starbucks https://t.co/97wdL...   4   5412
5428   27   640477140660518912   Sun Sep 06 10:50:24 +0000 2015   3242403023   Donald Trump 2016   "  @ Starbucks https://t.co/wsEYFIefk7 " - D...   4   5428
5455   61   640469542272110592   Sun Sep 06 10:20:12 +0000 2015   3242403023   Donald Trump 2016   " starbucks @ Starbucks Mam Plaza https://t.co...   4   5455
5456   62   640469541370372096   Sun Sep 06 10:20:12 +0000 2015   3242403023   Donald Trump 2016   " Aaahhh the pumpkin spice latte is back, fall...   4   5456
5457   63   640469539524898817   Sun Sep 06 10:20:12 +0000 2015   3242403023   Donald Trump 2016   " RT kayyleighferry: Oh my goddd Harry Potter ...   4   5457
5458   64   640469537176031232   Sun Sep 06 10:20:11 +0000 2015   3242403023   Donald Trump 2016   " Starbucks https://t.co/3xYYXlwNkf " - Donald...   4   5458
5459   65   640469536119070720   Sun Sep 06 10:20:11 +0000 2015   3242403023   Donald Trump 2016   " A Starbucks is under construction in my neig...   4   5459
5460   66   640469530435813376   Sun Sep 06 10:20:10 +0000 2015   3242403023   Donald Trump 2016   " Babam starbucks'tan fotogtaf atıyor bende du...   4   5460
```

我们用一些示例推文对`5`个聚类进行了映射。聚类`0`是关于 Spark 的。聚类`1`是关于 Python 的。聚类`2`是关于 Lady Gaga 的。聚类`3`是关于泰国普吉岛新闻的。聚类`4`是关于唐纳德·特朗普的。

# 构建机器学习管道

我们希望在优化最佳调整参数的同时，组合特征提取、准备活动、训练、测试和预测活动，以获得最佳性能模型。

以下推文完美地捕捉了在 Spark MLlib 中实现的强大机器学习管道的五行代码：

![构建机器学习管道](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03986_04_08.jpg)

Spark ML 管道受 Python 的 Scikit-Learn 启发，并创建了一个简洁的、声明性的语句，用于对数据进行连续转换，以快速交付可调整的模型。

# 摘要

在本章中，我们概述了 Spark MLlib 不断扩展的算法库。我们讨论了监督学习和无监督学习、推荐系统、优化和特征提取算法。然后，我们将从 Twitter 中收集的数据放入机器学习过程、算法和评估中，以从数据中获取见解。我们通过 Python Scikit-Learn 和 Spark MLlib 的 K-means 聚类对 Twitter 收集的数据集进行了处理，以将与*Apache Spark*相关的推文分离出来。我们还评估了模型的性能。

这让我们为下一章做好准备，下一章将涵盖使用 Spark 进行流式分析。让我们马上开始吧。


# 第五章：使用 Spark 进行实时数据流

在本章中，我们将专注于流入 Spark 并进行处理的实时流数据。到目前为止，我们已经讨论了批处理的机器学习和数据挖掘。现在我们正在处理持续流动的数据，并在飞行中检测事实和模式。我们正在从湖泊转向河流。

我们将首先调查在这样一个动态和不断变化的环境中出现的挑战。在奠定流应用的先决条件的基础上，我们将调查使用实时数据源（如 TCP 套接字到 Twitter firehose）进行各种实现，并建立一个低延迟、高吞吐量和可扩展的数据管道，结合 Spark、Kafka 和 Flume。

在本章中，我们将涵盖以下几点：

+   分析流应用的架构挑战、约束和要求

+   使用 Spark Streaming 从 TCP 套接字处理实时数据

+   直接连接到 Twitter firehose 以准实时解析推文

+   建立一个可靠、容错、可扩展、高吞吐量、低延迟的集成应用，使用 Spark、Kafka 和 Flume

+   关于 Lambda 和 Kappa 架构范式的结束语

# 奠定流架构的基础

按照惯例，让我们首先回到我们最初的数据密集型应用架构蓝图，并突出 Spark Streaming 模块，这将是我们感兴趣的主题。

以下图表通过突出 Spark Streaming 模块及其与整体数据密集型应用框架中的 Spark SQL 和 Spark MLlib 的交互来设定上下文。

![奠定流架构的基础](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_01.jpg)

数据来自股市时间序列、企业交易、互动、事件、网站流量、点击流和传感器。所有事件都是时间戳数据且紧急。这适用于欺诈检测和预防、移动交叉销售和升级，或者交通警报。这些数据流需要立即处理以进行监控，例如检测异常、异常值、垃圾邮件、欺诈和入侵；同时也需要提供基本统计数据、见解、趋势和建议。在某些情况下，汇总的聚合信息足以存储以供以后使用。从架构范式的角度来看，我们正在从面向服务的架构转向事件驱动的架构。

有两种模型用于处理数据流：

+   按照记录的实时到达一个接一个地处理记录。在处理之前，我们不会将传入的记录缓冲在容器中。这是 Twitter 的 Storm、Yahoo 的 S4 和 Google 的 MillWheel 的情况。

+   微批处理或在小时间间隔上进行批处理计算，如 Spark Streaming 和 Storm Trident 所执行的。在这种情况下，我们根据微批处理设置中规定的时间窗口将传入的记录缓冲在一个容器中。

Spark Streaming 经常与 Storm 进行比较。它们是两种不同的流数据模型。Spark Streaming 基于微批处理。Storm 基于处理记录的实时到达。Storm 还提供了微批处理选项，即其 Storm Trident 选项。

流应用中的驱动因素是延迟。延迟范围从**RPC**（远程过程调用的缩写）的毫秒级到微批处理解决方案（如 Spark Streaming）的几秒或几分钟。

RPC 允许请求程序之间的同步操作，等待远程服务器过程的结果。线程允许对服务器进行多个 RPC 调用的并发。

实现分布式 RPC 模型的软件示例是 Apache Storm。

Storm 使用拓扑结构或有向无环图来实现无界元组的无状态亚毫秒延迟处理，结合了作为数据流源的喷口和用于过滤、连接、聚合和转换等操作的螺栓。Storm 还实现了一个称为**Trident**的更高级抽象，类似于 Spark，可以处理微批次数据流。

因此，从亚毫秒到秒的延迟连续性来看，Storm 是一个很好的选择。对于秒到分钟的规模，Spark Streaming 和 Storm Trident 都是很好的选择。对于几分钟以上的范围，Spark 和诸如 Cassandra 或 HBase 的 NoSQL 数据库都是合适的解决方案。对于超过一小时且数据量大的范围，Hadoop 是理想的竞争者。

尽管吞吐量与延迟相关，但它并不是简单的反比线性关系。如果处理一条消息需要 2 毫秒，这决定了延迟，那么人们会认为吞吐量受限于每秒 500 条消息。如果我们允许消息缓冲 8 毫秒，批处理消息可以实现更高的吞吐量。在延迟为 10 毫秒的情况下，系统可以缓冲高达 10,000 条消息。通过容忍可接受的延迟增加，我们大大提高了吞吐量。这就是 Spark Streaming 利用的微批处理的魔力。

## Spark Streaming 内部工作

Spark Streaming 架构利用了 Spark 核心架构。它在**SparkContext**上叠加了一个**StreamingContext**作为流功能的入口点。集群管理器将至少一个工作节点指定为接收器，这将是一个执行器，具有处理传入流的*长任务*。执行器从输入数据流创建离散化流或 DStreams，并默认情况下将 DStream 复制到另一个工作节点的缓存中。一个接收器服务于一个输入数据流。多个接收器提高了并行性，并生成多个 Spark 可以合并或连接的离散分布式数据集（RDD）。

下图概述了 Spark Streaming 的内部工作。客户端通过集群管理器与 Spark 集群交互，而 Spark Streaming 有一个专用的工作节点，运行长时间的任务，摄取输入数据流并将其转换为离散化流或 DStreams。数据由接收器收集、缓冲和复制，然后推送到一系列 RDD 的流中。

![Spark Streaming 内部工作](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_02.jpg)

Spark 接收器可以从许多来源获取数据。核心输入来源包括 TCP 套接字和 HDFS/Amazon S3 到 Akka Actors。其他来源包括 Apache Kafka、Apache Flume、Amazon Kinesis、ZeroMQ、Twitter 和自定义或用户定义的接收器。

我们区分了可靠的资源，它们确认接收到数据并进行复制以便可能的重发，与不确认消息接收的不可靠接收者。Spark 在工作节点、分区和接收者方面进行了扩展。

下图概述了 Spark Streaming 的内部工作，以及可能的来源和持久性选项：

![Spark Streaming 内部工作](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_03.jpg)

## 深入了解 Spark Streaming

Spark Streaming 由接收器组成，并由离散化流和用于持久性的 Spark 连接器提供支持。

至于 Spark Core，其基本数据结构是 RDD，而 Spark Streaming 的基本编程抽象是离散化流或 DStream。

下图说明了离散化流作为 RDD 的连续序列。DStream 的批次间隔是可配置的。

![深入了解 Spark Streaming](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_04.jpg)

DStreams 在批次间隔中快照传入的数据。这些时间步骤通常在 500 毫秒到几秒之间。DStream 的基本结构是 RDD。

DStream 本质上是一系列连续的 RDD。这很强大，因为它允许我们利用 Spark Streaming 中所有传统的函数、转换和 Spark Core 中可用的操作，并允许我们与 Spark SQL 对话，对传入的数据流执行 SQL 查询，并使用 Spark MLlib。类似于通用和键值对 RDD 上的转换是适用的。DStreams 受益于内部 RDD 的谱系和容错性。离散流操作还存在其他转换和输出操作。大多数 DStream 上的通用操作是**transform**和**foreachRDD**。

以下图表概述了 DStreams 的生命周期。从创建消息的微批处理到应用`transformation`函数和触发 Spark 作业的 RDD。分解图表中的步骤，我们从上到下阅读图表：

1.  在输入流中，传入的消息根据微批处理的时间窗口分配在容器中进行缓冲。

1.  在离散化流步骤中，缓冲的微批处理被转换为 DStream RDD。

1.  映射的 DStream 步骤是通过将转换函数应用于原始 DStream 而获得的。这前三个步骤构成了在预定义时间窗口中接收到的原始数据的转换。由于底层数据结构是 RDD，我们保留了转换的数据谱系。

1.  最后一步是对 RDD 的操作。它触发 Spark 作业。

![深入了解 Spark Streaming](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_05.jpg)

转换可以是无状态的或有状态的。*无状态*意味着程序不维护状态，而*有状态*意味着程序保持状态，这种情况下，先前的事务被记住并可能影响当前事务。有状态操作修改或需要系统的某些状态，而无状态操作则不需要。

无状态转换一次处理 DStream 中的每个批处理。有状态转换处理多个批次以获得结果。有状态转换需要配置检查点目录。检查点是 Spark Streaming 中容错的主要机制，用于定期保存有关应用程序的数据和元数据。

Spark Streaming 有两种类型的有状态转换：`updateStateByKey`和窗口转换。

`updateStateByKey`是维护流中每个键的状态的转换。它返回一个新的*state* DStream，其中每个键的状态都通过将给定函数应用于键的先前状态和每个键的新值来更新。一个示例是在推文流中给定标签的运行计数。

窗口转换在滑动窗口中跨多个批次进行。窗口具有指定的长度或持续时间，以时间单位指定。它必须是 DStream 批处理间隔的倍数。它定义了窗口转换中包括多少批次。

窗口具有指定的滑动间隔或滑动持续时间。它必须是 DStream 批处理间隔的倍数。它定义了滑动窗口或计算窗口转换的频率。

以下模式描述了在 DStreams 上进行窗口操作，以获得具有给定长度和滑动间隔的窗口 DStreams：

![深入了解 Spark Streaming](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_06.jpg)

一个示例函数是`countByWindow`（`windowLength`，`slideInterval`）。它返回一个新的 DStream，其中每个 RDD 都有一个由计算此 DStream 上的滑动窗口中的元素数量生成的单个元素。在这种情况下，一个示例是在推文流中每 60 秒对给定标签的运行计数。窗口时间范围是指定的。

分钟级窗口长度是合理的。小时级窗口长度不建议，因为它会消耗大量计算和内存。更方便的做法是在诸如 Cassandra 或 HBase 之类的数据库中聚合数据。

窗口转换根据窗口长度和窗口滑动间隔计算结果。Spark 的性能主要受窗口长度、窗口滑动间隔和持久性的影响。

## 建立容错

实时流处理系统必须 24/7 运行。它们需要对系统中的各种故障具有弹性。Spark 及其 RDD 抽象设计成无缝处理集群中任何工作节点的故障。

主要的 Spark Streaming 容错机制是检查点、自动驱动程序重启和自动故障转移。Spark 通过检查点实现了从驱动程序故障中恢复，从而保留了应用程序状态。

写前日志、可靠的接收器和文件流保证了从 Spark 版本 1.2 开始的零数据丢失。写前日志代表了一个容错的存储接收到的数据。

故障需要重新计算结果。DStream 操作具有精确一次的语义。转换可以多次重新计算，但结果将是相同的。DStream 输出操作具有至少一次的语义。输出操作可能会被执行多次。

# 使用 TCP 套接字处理实时数据

作为对流操作整体理解的一个基础，我们将首先尝试使用 TCP 套接字进行实验。TCP 套接字在客户端和服务器之间建立双向通信，可以通过已建立的连接交换数据。WebSocket 连接是长期存在的，不像典型的 HTTP 连接。HTTP 不适用于保持从服务器到 Web 浏览器的开放连接以持续推送数据。因此，大多数 Web 应用程序通过频繁的**异步 JavaScript**（**AJAX**）和 XML 请求采用了长轮询。WebSocket 在 HTML5 中标准化和实现，正在超越 Web 浏览器，成为客户端和服务器之间实时通信的跨平台标准。

## 设置 TCP 套接字

我们通过运行`netcat`创建一个 TCP 套接字服务器，`netcat`是大多数 Linux 系统中的一个小型实用程序，作为数据服务器使用命令`> nc -lk 9999`，其中`9999`是我们发送数据的端口：

```py
#
# Socket Server
#
an@an-VB:~$ nc -lk 9999
hello world
how are you
hello  world
cool it works
```

一旦 netcat 运行起来，我们将打开第二个控制台，使用我们的 Spark Streaming 客户端接收和处理数据。一旦 Spark Streaming 客户端控制台开始监听，我们就开始输入要处理的单词，即`hello world`。

## 处理实时数据

我们将使用 Spark 捆绑包中提供的 Spark Streaming 示例程序`network_wordcount.py`。它可以在 GitHub 存储库[`github.com/apache/spark/blob/master/examples/src/main/python/streaming/network_wordcount.py`](https://github.com/apache/spark/blob/master/examples/src/main/python/streaming/network_wordcount.py)中找到。代码如下：

```py
"""
 Counts words in UTF8 encoded, '\n' delimited text received from the network every second.
 Usage: network_wordcount.py <hostname> <port>
   <hostname> and <port> describe the TCP server that Spark Streaming would connect to receive data.
 To run this on your local machine, you need to first run a Netcat server
    `$ nc -lk 9999`
 and then run the example
    `$ bin/spark-submit examples/src/main/python/streaming/network_wordcount.py localhost 9999`
"""
from __future__ import print_function

import sys

from pyspark import SparkContext
from pyspark.streaming import StreamingContext

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: network_wordcount.py <hostname> <port>", file=sys.stderr)
        exit(-1)
    sc = SparkContext(appName="PythonStreamingNetworkWordCount")
    ssc = StreamingContext(sc, 1)

    lines = ssc.socketTextStream(sys.argv[1], int(sys.argv[2]))
    counts = lines.flatMap(lambda line: line.split(" "))\
                  .map(lambda word: (word, 1))\
                  .reduceByKey(lambda a, b: a+b)
    counts.pprint()

    ssc.start()
    ssc.awaitTermination()
```

在这里，我们解释了程序的步骤：

1.  代码首先使用以下命令初始化 Spark Streaming 上下文：

```py
ssc = StreamingContext(sc, 1)

```

1.  接下来，设置流计算。

1.  定义了一个或多个接收数据的 DStream 对象，以连接到本地主机或`127.0.0.1`上的`端口 9999`：

```py
stream = ssc.socketTextStream("127.0.0.1", 9999)

```

1.  已定义 DStream 计算：转换和输出操作：

```py
stream.map(x: lambda (x,1))
.reduce(a+b)
.print()
```

1.  计算已经开始：

```py
ssc.start()

```

1.  程序终止等待手动或错误处理完成：

```py
ssc.awaitTermination()

```

1.  手动完成是一个选项，当已知完成条件时：

```py
ssc.stop()

```

我们可以通过访问 Spark 监控主页`localhost:4040`来监视 Spark Streaming 应用程序。

这是运行程序并在`netcat`服务器控制台上输入单词的结果：

```py
#
# Socket Client
# an@an-VB:~/spark/spark-1.5.0-bin-hadoop2.6$ ./bin/spark-submit examples/src/main/python/streaming/network_wordcount.py localhost 9999
```

通过连接到`端口 9999`上的本地主机运行 Spark Streaming `network_count`程序：

```py
an@an-VB:~/spark/spark-1.5.0-bin-hadoop2.6$ ./bin/spark-submit examples/src/main/python/streaming/network_wordcount.py localhost 9999
-------------------------------------------
Time: 2015-10-18 20:06:06
-------------------------------------------
(u'world', 1)
(u'hello', 1)

-------------------------------------------
Time: 2015-10-18 20:06:07
-------------------------------------------
. . .
-------------------------------------------
Time: 2015-10-18 20:06:17
-------------------------------------------
(u'you', 1)
(u'how', 1)
(u'are', 1)

-------------------------------------------
Time: 2015-10-18 20:06:18
-------------------------------------------

. . .

-------------------------------------------
Time: 2015-10-18 20:06:26
-------------------------------------------
(u'', 1)
(u'world', 1)
(u'hello', 1)

-------------------------------------------
Time: 2015-10-18 20:06:27
-------------------------------------------
. . .
-------------------------------------------
Time: 2015-10-18 20:06:37
-------------------------------------------
(u'works', 1)
(u'it', 1)
(u'cool', 1)

-------------------------------------------
Time: 2015-10-18 20:06:38
-------------------------------------------

```

因此，我们已经通过`端口 9999`上的套接字建立了连接，流式传输了`netcat`服务器发送的数据，并对发送的消息进行了字数统计。

# 实时操作 Twitter 数据

Twitter 提供两种 API。一种是搜索 API，基本上允许我们根据搜索词检索过去的 tweets。这就是我们在本书的前几章中从 Twitter 收集数据的方式。有趣的是，对于我们当前的目的，Twitter 提供了一个实时流 API，允许我们摄取博客圈中发布的 tweets。

## 实时处理来自 Twitter firehose 的 Tweets

以下程序连接到 Twitter firehose 并处理传入的 tweets，排除已删除或无效的 tweets，并实时解析只提取`screen name`，实际 tweet 或`tweet text`，`retweet`计数，`geo-location`信息。处理后的 tweets 由 Spark Streaming 收集到 RDD 队列中，然后以一秒的间隔显示在控制台上：

```py
"""
Twitter Streaming API Spark Streaming into an RDD-Queue to process tweets live

 Create a queue of RDDs that will be mapped/reduced one at a time in
 1 second intervals.

 To run this example use
    '$ bin/spark-submit examples/AN_Spark/AN_Spark_Code/s07_twitterstreaming.py'

"""
#
import time
from pyspark import SparkContext
from pyspark.streaming import StreamingContext
import twitter
import dateutil.parser
import json

# Connecting Streaming Twitter with Streaming Spark via Queue
class Tweet(dict):
    def __init__(self, tweet_in):
        super(Tweet, self).__init__(self)
        if tweet_in and 'delete' not in tweet_in:
            self['timestamp'] = dateutil.parser.parse(tweet_in[u'created_at']
                                ).replace(tzinfo=None).isoformat()
            self['text'] = tweet_in['text'].encode('utf-8')
            #self['text'] = tweet_in['text']
            self['hashtags'] = [x['text'].encode('utf-8') for x in tweet_in['entities']['hashtags']]
            #self['hashtags'] = [x['text'] for x in tweet_in['entities']['hashtags']]
            self['geo'] = tweet_in['geo']['coordinates'] if tweet_in['geo'] else None
            self['id'] = tweet_in['id']
            self['screen_name'] = tweet_in['user']['screen_name'].encode('utf-8')
            #self['screen_name'] = tweet_in['user']['screen_name']
            self['user_id'] = tweet_in['user']['id']

def connect_twitter():
    twitter_stream = twitter.TwitterStream(auth=twitter.OAuth(
        token = "get_your_own_credentials",
        token_secret = "get_your_own_credentials",
        consumer_key = "get_your_own_credentials",
        consumer_secret = "get_your_own_credentials"))
    return twitter_stream

def get_next_tweet(twitter_stream):
    stream = twitter_stream.statuses.sample(block=True)
    tweet_in = None
    while not tweet_in or 'delete' in tweet_in:
        tweet_in = stream.next()
        tweet_parsed = Tweet(tweet_in)
    return json.dumps(tweet_parsed)

def process_rdd_queue(twitter_stream):
    # Create the queue through which RDDs can be pushed to
    # a QueueInputDStream
    rddQueue = []
    for i in range(3):
        rddQueue += [ssc.sparkContext.parallelize([get_next_tweet(twitter_stream)], 5)]

    lines = ssc.queueStream(rddQueue)
    lines.pprint()

if __name__ == "__main__":
    sc = SparkContext(appName="PythonStreamingQueueStream")
    ssc = StreamingContext(sc, 1)

    # Instantiate the twitter_stream
    twitter_stream = connect_twitter()
    # Get RDD queue of the streams json or parsed
    process_rdd_queue(twitter_stream)

    ssc.start()
    time.sleep(2)
    ssc.stop(stopSparkContext=True, stopGraceFully=True)
```

当我们运行这个程序时，它会产生以下输出：

```py
an@an-VB:~/spark/spark-1.5.0-bin-hadoop2.6$ bin/spark-submit examples/AN_Spark/AN_Spark_Code/s07_twitterstreaming.py
-------------------------------------------
Time: 2015-11-03 21:53:14
-------------------------------------------
{"user_id": 3242732207, "screen_name": "cypuqygoducu", "timestamp": "2015-11-03T20:53:04", "hashtags": [], "text": "RT @VIralBuzzNewss: Our Distinctive Edition Holiday break Challenge Is In this article! Hooray!... -  https://t.co/9d8wumrd5v https://t.co/\u2026", "geo": null, "id": 661647303678259200}

-------------------------------------------
Time: 2015-11-03 21:53:15
-------------------------------------------
{"user_id": 352673159, "screen_name": "melly_boo_orig", "timestamp": "2015-11-03T20:53:05", "hashtags": ["eminem"], "text": "#eminem https://t.co/GlEjPJnwxy", "geo": null, "id": 661647307847409668}

-------------------------------------------
Time: 2015-11-03 21:53:16
-------------------------------------------
{"user_id": 500620889, "screen_name": "NBAtheist", "timestamp": "2015-11-03T20:53:06", "hashtags": ["tehInterwebbies", "Nutters"], "text": "See? That didn't take long or any actual effort. This is #tehInterwebbies ... #Nutters Abound! https://t.co/QS8gLStYFO", "geo": null, "id": 661647312062709761}

```

因此，我们得到了使用 Spark 流处理实时 tweets 并实时处理它们的示例。

# 构建可靠且可扩展的流媒体应用程序

摄取数据是从各种来源获取数据并立即或以后进行处理的过程。数据消费系统分散并且可能在物理上和架构上远离来源。数据摄取通常使用脚本和基本自动化手段手动实现。实际上需要像 Flume 和 Kafka 这样的更高级框架。

数据摄取的挑战在于数据来源分散且瞬息万变，这使得集成变得脆弱。天气、交通、社交媒体、网络活动、车间传感器、安全和监控的数据生产是持续不断的。不断增加的数据量和速率，再加上不断变化的数据结构和语义，使得数据摄取变得临时性和容易出错。

目标是变得更加敏捷、可靠和可扩展。数据摄取的敏捷性、可靠性和可扩展性决定了管道的整体健康状况。敏捷性意味着随着新来源的出现进行集成，并根据需要对现有来源进行更改。为了确保安全性和可靠性，我们需要保护基础设施免受数据丢失的影响，并防止数据入口处对下游应用程序造成静默数据损坏。可扩展性可以避免摄取瓶颈，同时保持成本可控。

| 摄取模式 | 描述 | 示例 |
| --- | --- | --- |
| 手动或脚本 | 使用命令行界面或图形界面进行文件复制 | HDFS 客户端，Cloudera Hue |
| 批量数据传输 | 使用工具进行批量数据传输 | DistCp，Sqoop |
| 微批处理 | 小批量数据传输 | Sqoop，Sqoop2Storm |
| 流水线 | 流式事件传输 | Flume Scribe |
| 消息队列 | 发布订阅事件总线 | Kafka，Kinesis |

为了实现能够摄取多个数据流、在飞行中处理数据并理解所有内容以做出快速决策的事件驱动业务，统一日志是关键驱动因素。

统一日志是一个集中的企业结构化日志，可供实时订阅。所有组织的数据都放在一个中央日志中进行订阅。记录按照它们被写入的顺序从零开始编号。它也被称为提交日志或日志。*统一日志*的概念是 Kappa 架构的核心原则。

统一日志的属性如下：

+   **统一的**：整个组织只有一个部署

+   **仅追加的**：事件是不可变的并且是追加的

+   **有序的**：每个事件在分片内具有唯一的偏移量

+   **分布式的**：为了容错目的，统一日志在计算机集群上进行冗余分布

+   **快速的**：系统每秒摄取数千条消息

## 设置 Kafka

为了将数据的下游特定消费与数据的上游发射隔离开来，我们需要将数据的提供者与数据的接收者或消费者解耦。 由于它们生活在两个不同的世界，具有不同的周期和约束条件，Kafka 解耦了数据管道。

Apache Kafka 是一个经过重新构想的分布式发布订阅消息系统，被重新构想为分布式提交日志。 消息按主题存储。

Apache Kafka 具有以下属性。 它支持：

+   高吞吐量，适用于大量事件源

+   实时处理新的和派生的数据源

+   大数据积压和离线消费的持久性

+   低延迟作为企业范围的消息传递系统

+   由于其分布式性质，具有容错能力

消息存储在具有唯一顺序 ID 的分区中，称为“偏移量”。 消费者通过元组（“偏移量”，“分区”，“主题”）跟踪它们的指针。

让我们深入了解 Kafka 的结构。

Kafka 基本上有三个组件：*生产者*，*消费者*和*代理*。 生产者将数据推送并写入代理。 消费者从代理中拉取和读取数据。 代理不会将消息推送给消费者。 消费者从代理中拉取消息。 设置是由 Apache Zookeeper 分布和协调的。

代理在主题中管理和存储数据。 主题分为复制分区。 数据在代理中持久存在，但在消费之前不会被删除，而是在保留期间。 如果消费者失败，它可以随时返回代理以获取数据。

Kafka 需要 Apache ZooKeeper。 ZooKeeper 是分布式应用程序的高性能协调服务。 它集中管理配置，注册表或命名服务，组成员资格，锁定以及服务器之间的协调同步。 它提供具有元数据，监视统计信息和集群状态的分层命名空间。 ZooKeeper 可以动态引入代理和消费者，然后重新平衡集群。

Kafka 生产者不需要 ZooKeeper。 Kafka 代理使用 ZooKeeper 提供一般状态信息，并在故障时选举领导者。 Kafka 消费者使用 ZooKeeper 跟踪消息偏移量。 较新版本的 Kafka 将保存消费者通过 ZooKeeper 并可以检索 Kafka 特殊主题信息。 Kafka 为生产者提供自动负载平衡。

以下图表概述了 Kafka 的设置：

![设置 Kafka](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_07.jpg)

### 安装和测试 Kafka

我们将从专用网页[`kafka.apache.org/downloads.html`](http://kafka.apache.org/downloads.html)下载 Apache Kafka 二进制文件，并使用以下步骤在我们的机器上安装软件：

1.  下载代码。

1.  下载 0.8.2.0 版本并“解压”它：

```py
> tar -xzf kafka_2.10-0.8.2.0.tgz
> cd kafka_2.10-0.8.2.0

```

1.  启动`zooeeper`。 Kafka 使用 ZooKeeper，因此我们需要首先启动 ZooKeeper 服务器。 我们将使用 Kafka 打包的便利脚本来获取单节点 ZooKeeper 实例。

```py
> bin/zookeeper-server-start.sh config/zookeeper.properties
an@an-VB:~/kafka/kafka_2.10-0.8.2.0$ bin/zookeeper-server-start.sh config/zookeeper.properties

[2015-10-31 22:49:14,808] INFO Reading configuration from: config/zookeeper.properties (org.apache.zookeeper.server.quorum.QuorumPeerConfig)
[2015-10-31 22:49:14,816] INFO autopurge.snapRetainCount set to 3 (org.apache.zookeeper.server.DatadirCleanupManager)...

```

1.  现在启动 Kafka 服务器：

```py
> bin/kafka-server-start.sh config/server.properties

an@an-VB:~/kafka/kafka_2.10-0.8.2.0$ bin/kafka-server-start.sh config/server.properties
[2015-10-31 22:52:04,643] INFO Verifying properties (kafka.utils.VerifiableProperties)
[2015-10-31 22:52:04,714] INFO Property broker.id is overridden to 0 (kafka.utils.VerifiableProperties)
[2015-10-31 22:52:04,715] INFO Property log.cleaner.enable is overridden to false (kafka.utils.VerifiableProperties)
[2015-10-31 22:52:04,715] INFO Property log.dirs is overridden to /tmp/kafka-logs (kafka.utils.VerifiableProperties) [2013-04-22 15:01:47,051] INFO Property socket.send.buffer.bytes is overridden to 1048576 (kafka.utils.VerifiableProperties)

```

1.  创建一个主题。 让我们创建一个名为 test 的主题，其中只有一个分区和一个副本：

```py
> bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic test

```

1.  如果我们运行`list`主题命令，我们现在可以看到该主题：

```py
> bin/kafka-topics.sh --list --zookeeper localhost:2181
Test
an@an-VB:~/kafka/kafka_2.10-0.8.2.0$ bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic test
Created topic "test".
an@an-VB:~/kafka/kafka_2.10-0.8.2.0$ bin/kafka-topics.sh --list --zookeeper localhost:2181
test

```

1.  通过创建生产者和消费者来检查 Kafka 安装。 我们首先启动一个“生产者”并在控制台中输入消息：

```py
an@an-VB:~/kafka/kafka_2.10-0.8.2.0$ bin/kafka-console-producer.sh --broker-list localhost:9092 --topic test
[2015-10-31 22:54:43,698] WARN Property topic is not valid (kafka.utils.VerifiableProperties)
This is a message
This is another message

```

1.  然后我们启动一个消费者来检查我们是否收到消息：

```py
an@an-VB:~$ cd kafka/
an@an-VB:~/kafka$ cd kafka_2.10-0.8.2.0/
an@an-VB:~/kafka/kafka_2.10-0.8.2.0$ bin/kafka-console-consumer.sh --zookeeper localhost:2181 --topic test --from-beginning
This is a message
This is another message

```

消息已被消费者正确接收：

1.  检查 Kafka 和 Spark Streaming 消费者。 我们将使用 Spark 捆绑包中提供的 Spark Streaming Kafka 单词计数示例。 警告：当我们提交 Spark 作业时，我们必须绑定 Kafka 软件包`--packages org.apache.spark:spark-streaming-kafka_2.10:1.5.0`。 命令如下：

```py
./bin/spark-submit --packages org.apache.spark:spark-streaming-kafka_2.10:1.5.0 \ examples/src/main/python/streaming/kafka_wordcount.py \

localhost:2181 test

```

1.  当我们使用 Kafka 启动 Spark Streaming 单词计数程序时，我们会得到以下输出：

```py
an@an-VB:~/spark/spark-1.5.0-bin-hadoop2.6$ ./bin/spark-submit --packages org.apache.spark:spark-streaming-kafka_2.10:1.5.0 examples/src/main/python/streaming/kafka_wordcount.py 
localhost:2181 test

-------------------------------------------
Time: 2015-10-31 23:46:33
-------------------------------------------
(u'', 1)
(u'from', 2)
(u'Hello', 2)
(u'Kafka', 2)

-------------------------------------------
Time: 2015-10-31 23:46:34
-------------------------------------------

-------------------------------------------
Time: 2015-10-31 23:46:35
-------------------------------------------

```

1.  安装 Kafka Python 驱动程序，以便能够以编程方式开发生产者和消费者，并使用 Python 与 Kafka 和 Spark 进行交互。我们将使用 David Arthur 的经过测试的库，也就是 GitHub 上的 Mumrah（[`github.com/mumrah`](https://github.com/mumrah)）。我们可以使用 pip 进行安装，如下所示：

```py
> pip install kafka-python
an@an-VB:~$ pip install kafka-python
Collecting kafka-python
 Downloading kafka-python-0.9.4.tar.gz (63kB)
...
Successfully installed kafka-python-0.9.4

```

### 开发生产者

以下程序创建了一个简单的 Kafka 生产者，它将发送消息*this is a message sent from the Kafka producer:*五次，然后每秒跟一个时间戳：

```py
#
# kafka producer
#
#
import time
from kafka.common import LeaderNotAvailableError
from kafka.client import KafkaClient
from kafka.producer import SimpleProducer
from datetime import datetime

def print_response(response=None):
    if response:
        print('Error: {0}'.format(response[0].error))
        print('Offset: {0}'.format(response[0].offset))

def main():
    kafka = KafkaClient("localhost:9092")
    producer = SimpleProducer(kafka)
    try:
        time.sleep(5)
        topic = 'test'
        for i in range(5):
            time.sleep(1)
            msg = 'This is a message sent from the kafka producer: ' \
                  + str(datetime.now().time()) + ' -- '\
                  + str(datetime.now().strftime("%A, %d %B %Y %I:%M%p"))
            print_response(producer.send_messages(topic, msg))
    except LeaderNotAvailableError:
        # https://github.com/mumrah/kafka-python/issues/249
        time.sleep(1)
        print_response(producer.send_messages(topic, msg))

    kafka.close()

if __name__ == "__main__":
    main()
```

当我们运行此程序时，会生成以下输出：

```py
an@an-VB:~/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark/AN_Spark_Code$ python s08_kafka_producer_01.py
Error: 0
Offset: 13
Error: 0
Offset: 14
Error: 0
Offset: 15
Error: 0
Offset: 16
Error: 0
Offset: 17
an@an-VB:~/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark/AN_Spark_Code$

```

它告诉我们没有错误，并给出了 Kafka 代理给出的消息的偏移量。

### 开发消费者

为了从 Kafka 代理获取消息，我们开发了一个 Kafka 消费者：

```py
# kafka consumer
# consumes messages from "test" topic and writes them to console.
#
from kafka.client import KafkaClient
from kafka.consumer import SimpleConsumer

def main():
  kafka = KafkaClient("localhost:9092")
  print("Consumer established connection to kafka")
  consumer = SimpleConsumer(kafka, "my-group", "test")
  for message in consumer:
    # This will wait and print messages as they become available
    print(message)

if __name__ == "__main__":
    main()
```

当我们运行此程序时，我们有效地确认消费者接收了所有消息：

```py
an@an-VB:~$ cd ~/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark/AN_Spark_Code/
an@an-VB:~/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark/AN_Spark_Code$ python s08_kafka_consumer_01.py
Consumer established connection to kafka
OffsetAndMessage(offset=13, message=Message(magic=0, attributes=0, key=None, value='This is a message sent from the kafka producer: 11:50:17.867309Sunday, 01 November 2015 11:50AM'))
...
OffsetAndMessage(offset=17, message=Message(magic=0, attributes=0, key=None, value='This is a message sent from the kafka producer: 11:50:22.051423Sunday, 01 November 2015 11:50AM'))

```

### 为 Kafka 开发 Spark Streaming 消费者

根据 Spark Streaming 包中提供的示例代码，我们将为 Kafka 创建一个 Spark Streaming 消费者，并对存储在代理中的消息进行词频统计：

```py
#
# Kafka Spark Streaming Consumer    
#
from __future__ import print_function

import sys

from pyspark import SparkContext
from pyspark.streaming import StreamingContext
from pyspark.streaming.kafka import KafkaUtils

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: kafka_spark_consumer_01.py <zk> <topic>", file=sys.stderr)
        exit(-1)

    sc = SparkContext(appName="PythonStreamingKafkaWordCount")
    ssc = StreamingContext(sc, 1)

    zkQuorum, topic = sys.argv[1:]
    kvs = KafkaUtils.createStream(ssc, zkQuorum, "spark-streaming-consumer", {topic: 1})
    lines = kvs.map(lambda x: x[1])
    counts = lines.flatMap(lambda line: line.split(" ")) \
        .map(lambda word: (word, 1)) \
        .reduceByKey(lambda a, b: a+b)
    counts.pprint()

    ssc.start()
    ssc.awaitTermination()
```

使用以下 Spark 提交命令运行此程序：

```py
./bin/spark-submit --packages org.apache.spark:spark-streaming-kafka_2.10:1.5.0 examples/AN_Spark/AN_Spark_Code/s08_kafka_spark_consumer_01.py localhost:2181 test
```

我们得到以下输出：

```py
an@an-VB:~$ cd spark/spark-1.5.0-bin-hadoop2.6/
an@an-VB:~/spark/spark-1.5.0-bin-hadoop2.6$ ./bin/spark-submit \
>     --packages org.apache.spark:spark-streaming-kafka_2.10:1.5.0 \
>     examples/AN_Spark/AN_Spark_Code/s08_kafka_spark_consumer_01.py localhost:2181 test
...
:: retrieving :: org.apache.spark#spark-submit-parent
  confs: [default]
  0 artifacts copied, 10 already retrieved (0kB/18ms)
-------------------------------------------
Time: 2015-11-01 12:13:16
-------------------------------------------

-------------------------------------------
Time: 2015-11-01 12:13:17
-------------------------------------------

-------------------------------------------
Time: 2015-11-01 12:13:18
-------------------------------------------

-------------------------------------------
Time: 2015-11-01 12:13:19
-------------------------------------------
(u'a', 5)
(u'the', 5)
(u'11:50AM', 5)
(u'from', 5)
(u'This', 5)
(u'11:50:21.044374Sunday,', 1)
(u'message', 5)
(u'11:50:20.036422Sunday,', 1)
(u'11:50:22.051423Sunday,', 1)
(u'11:50:17.867309Sunday,', 1)
...

-------------------------------------------
Time: 2015-11-01 12:13:20
-------------------------------------------

-------------------------------------------
Time: 2015-11-01 12:13:21
-------------------------------------------
```

## 探索 flume

Flume 是一个持续的摄入系统。最初设计为日志聚合系统，但它发展到处理任何类型的流式事件数据。

Flume 是一个分布式、可靠、可扩展和可用的管道系统，用于高效地收集、聚合和传输大量数据。它内置支持上下文路由、过滤复制和多路复用。它是强大且容错的，具有可调节的可靠性机制和许多故障转移和恢复机制。它使用简单可扩展的数据模型，允许实时分析应用。

Flume 提供以下内容：

+   保证交付语义

+   低延迟可靠数据传输

+   无需编码的声明性配置

+   可扩展和可定制的设置

+   与最常用的端点集成

Flume 的结构包括以下元素：

+   **Event**：事件是由 Flume 从源到目的地传输的基本数据单元。它类似于一个带有字节数组有效负载的消息，对 Flume 不透明，并且可选的标头用于上下文路由。

+   **Client**：客户端生成并传输事件。客户端将 Flume 与数据消费者解耦。它是生成事件并将其发送到一个或多个代理的实体。自定义客户端或 Flume log4J 附加程序或嵌入式应用代理可以是客户端。

+   **Agent**：代理是承载源、通道、sink 和其他元素的容器，使事件从一个地方传输到另一个地方。它为托管组件提供配置、生命周期管理和监控。代理是运行 Flume 的物理 Java 虚拟机。

+   **Source**：源是 Flume 接收事件的实体。源至少需要一个通道才能工作，以主动轮询数据或被动等待数据传递给它们。各种源允许收集数据，例如 log4j 日志和 syslogs。

+   **Sink**：Sink 是从通道中排出数据并将其传递到下一个目的地的实体。各种不同的 sink 允许数据流向各种目的地。Sink 支持序列化为用户的格式。一个例子是将事件写入 HDFS 的 HDFS sink。

+   **通道**：通道是源和汇之间的导管，缓冲传入事件，直到被汇耗尽。源将事件馈送到通道，而汇则耗尽通道。通道解耦了上游和下游系统的阻抗。上游的数据突发通过通道被抑制。下游的故障被通道透明地吸收。调整通道容量以应对这些事件是实现这些好处的关键。通道提供两种持久性级别：内存通道，如果 JVM 崩溃则是易失性的，或者由预写日志支持的文件通道，将信息存储到磁盘上。通道是完全事务性的。

让我们说明所有这些概念：

![探索水槽](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_08.jpg)

## 使用 Flume、Kafka 和 Spark 开发数据管道

构建具有弹性的数据管道利用了前几节的经验。我们正在使用 Flume 将数据摄取和传输，使用 Kafka 作为可靠和复杂的发布和订阅消息系统进行数据经纪，最后使用 Spark Streaming 进行实时处理计算。

以下图示了流数据管道的组成，作为*connect*、*collect*、*conduct*、*compose*、*consume*、*consign*和*control*活动的序列。这些活动根据用例进行配置：

+   连接建立与流式 API 的绑定。

+   收集创建收集线程。

+   Conduct 通过创建缓冲队列或发布-订阅机制将数据生产者与消费者解耦。

+   Compose 专注于处理数据。

+   Consume 为消费系统提供处理后的数据。Consign 负责数据持久性。

+   控制满足系统、数据和应用程序的治理和监控。

![使用 Flume、Kafka 和 Spark 开发数据管道](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_09.jpg)

以下图示了流数据管道的概念及其关键组件：Spark Streaming、Kafka、Flume 和低延迟数据库。在消费或控制应用程序中，我们正在实时监控我们的系统（由监视器表示），或者在某些阈值被突破时发送实时警报（由红灯表示）。

![使用 Flume、Kafka 和 Spark 开发数据管道](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_10.jpg)

以下图示了 Spark 在单一平台上处理运动数据和静态数据的独特能力，同时根据用例要求与多个持久性数据存储无缝接口。

这张图将到目前为止讨论的所有概念统一在一起。顶部描述了流处理管道，底部描述了批处理管道。它们都在图中间共享一个持久性层，描述了各种持久性和序列化模式。

![使用 Flume、Kafka 和 Spark 开发数据管道](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_11.jpg)

# 关于 Lambda 和 Kappa 架构的结束语

目前流行的有两种架构范式：Lambda 和 Kappa 架构。

Lambda 是 Storm 的创始人和主要贡献者 Nathan Marz 的心血结晶。它基本上主张在所有数据上构建一个功能架构。该架构有两个分支。第一个是批处理分支，旨在由 Hadoop 提供动力，其中历史、高延迟、高吞吐量的数据被预处理并准备好供消费。实时分支旨在由 Storm 提供动力，它处理增量流数据，实时推导见解，并将聚合信息反馈到批处理存储。

Kappa 是 Kafka 的主要贡献者之一 Jay Kreps 及其在 Confluent（以前在 LinkedIn）的同事的心血结晶。它主张一个完整的流水线，有效地在企业级别实现了前几页中所述的统一日志。

## 理解 Lambda 架构

Lambda 架构将批处理和流式数据结合，以提供对所有可用数据的统一查询机制。Lambda 架构设想了三个层次：批处理层存储预先计算的信息，速度层处理实时增量信息作为数据流，最后是服务层，将批处理和实时视图合并用于自由查询。以下图表概述了 Lambda 架构：

![理解 Lambda 架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_12.jpg)

## 理解 Kappa 架构

Kappa 架构提议以流式模式驱动整个企业。Kappa 架构起源于 LinkedIn 的 Jay Kreps 及其同事的批评。自那时起，他们转移并创建了以 Apache Kafka 为主要支持者的 Confluent，以实现 Kappa 架构愿景。其基本原则是以统一日志作为企业信息架构的主要支撑，在全流式模式下运行。

统一日志是一个集中的企业结构化日志，可供实时订阅。所有组织的数据都放在一个中央日志中进行订阅。记录从零开始编号，以便写入。它也被称为提交日志或日志。统一日志的概念是 Kappa 架构的核心原则。

统一日志的属性如下：

+   **统一的**：整个组织只有一个部署

+   **仅追加**：事件是不可变的，会被追加

+   **有序的**：每个事件在一个分片内有唯一的偏移量

+   **分布式**：为了容错目的，统一日志在计算机集群上进行冗余分布

+   **快速的**：系统每秒摄入数千条消息

以下截图捕捉了 Jay Kreps 对 Lambda 架构的保留意见。他对 Lambda 架构的主要保留意见是在两个不同的系统 Hadoop 和 Storm 中实现相同的作业，每个系统都有其特定的特点，并伴随着所有相关的复杂性。Kappa 架构在由 Apache Kafka 提供支持的同一框架中处理实时数据并重新处理历史数据。

![理解 Kappa 架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_05_13.jpg)

# 总结

在本章中，我们阐述了流式架构应用程序的基础，并描述了它们的挑战、约束和好处。我们深入探讨了 Spark Streaming 的内部工作方式，以及它如何与 Spark Core 对话，并与 Spark SQL 和 Spark MLlib 配合。我们通过 TCP 套接字、直播推文摄入以及直接从 Twitter firehose 处理的方式来阐述流式概念。我们讨论了使用 Kafka 将上游数据发布与下游数据订阅和消费解耦的概念，以最大程度地提高整体流式架构的弹性。我们还讨论了 Flume——一个可靠、灵活和可扩展的数据摄入和传输管道系统。Flume、Kafka 和 Spark 的结合在不断变化的环境中提供了无与伦比的稳健性、速度和灵活性。我们在本章中还对两种流式架构范式——Lambda 和 Kappa 架构进行了一些评论和观察。

Lambda 架构将批处理和流式数据结合在一个通用的查询前端。最初它是以 Hadoop 和 Storm 为目标构想的。Spark 具有自己的批处理和流式范例，并提供了一个共同的代码库的单一环境，有效地将这种架构范式实现。

Kappa 架构宣扬了统一日志的概念，它创建了一个面向事件的架构，企业中的所有事件都被导入到一个中央提交日志中，并且实时提供给所有消费系统。

现在我们准备对迄今为止收集和处理的数据进行可视化。


# 第六章：可视化见解和趋势

到目前为止，我们已经专注于从 Twitter 收集、分析和处理数据。我们已经为使用我们的数据进行可视化呈现和提取见解和趋势做好了准备。我们将简要介绍 Python 生态系统中的可视化工具。我们将强调 Bokeh 作为渲染和查看大型数据集的强大工具。Bokeh 是 Python Anaconda Distribution 生态系统的一部分。

在本章中，我们将涵盖以下几点：

+   通过图表和词云来衡量社交网络社区中的关键词和模因

+   映射最活跃的地点，社区围绕特定主题或话题增长

# 重新审视数据密集型应用架构

我们已经达到了数据密集型应用架构的最终层：参与层。这一层关注如何综合、强调和可视化数据消费者的关键上下文相关信息。在控制台中的一堆数字不足以吸引最终用户。将大量信息以快速、易消化和有吸引力的方式呈现是至关重要的。

以下图表设置了本章重点的背景，突出了参与层。

![重新审视数据密集型应用架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_06_01.jpg)

对于 Python 绘图和可视化，我们有很多工具和库。对于我们的目的，最有趣和相关的是以下几个：

+   **Matplotlib** 是 Python 绘图库的鼻祖。Matplotlib 最初是 *John Hunter* 的创意，他是开源软件的支持者，并将 Matplotlib 建立为学术界和数据科学界最流行的绘图库之一。Matplotlib 允许生成图表、直方图、功率谱、条形图、误差图、散点图等。示例可以在 Matplotlib 专用网站 [`matplotlib.org/examples/index.html`](http://matplotlib.org/examples/index.html) 上找到。

+   **Seaborn**，由 *Michael Waskom* 开发，是一个快速可视化统计信息的优秀库。它建立在 Matplotlib 之上，并与 Pandas 和 Python 数据堆栈（包括 Numpy）无缝集成。Seaborn 的图库展示了该库的潜力，网址为 [`stanford.edu/~mwaskom/software/seaborn/examples/index.html`](http://stanford.edu/~mwaskom/software/seaborn/examples/index.html)。

+   **ggplot** 相对较新，旨在为 Python 数据处理者提供 R 生态系统中著名的 ggplot2 的等价物。它具有与 ggplot2 相同的外观和感觉，并使用 Hadley Wickham 阐述的相同图形语法。ggplot 的 Python 版本由 `yhat` 团队开发。更多信息可以在 [`ggplot.yhathq.com`](http://ggplot.yhathq.com) 找到。

+   **D3.js** 是由 *Mike Bostock* 开发的非常流行的 JavaScript 库。**D3** 代表 **数据驱动文档**，利用 HTML、SVG 和 CSS 在任何现代浏览器上为数据赋予生命。它通过操作 DOM（文档对象模型）提供动态、强大、交互式的可视化效果。Python 社区迫不及待地想要将 D3 与 Matplotlib 集成。在 Jake Vanderplas 的推动下，mpld3 被创建，旨在将 `matplotlib` 带到浏览器中。示例图形托管在以下地址：[`mpld3.github.io/index.html`](http://mpld3.github.io/index.html)。

+   **Bokeh**旨在在非常大或流式数据集上提供高性能的交互性，同时利用`D3.js`的许多概念，而不需要编写一些令人生畏的`javascript`和`css`代码。Bokeh 在浏览器上提供动态可视化，无论是否有服务器。它与 Matplotlib、Seaborn 和 ggplot 无缝集成，并在 IPython 笔记本或 Jupyter 笔记本中呈现出色。Bokeh 由 Continuum.io 团队积极开发，并是 Anaconda Python 数据堆栈的一个重要组成部分。

Bokeh 服务器提供了一个完整的、动态的绘图引擎，可以从 JSON 中实现一个反应式场景图。它使用 Web 套接字来保持状态，并使用 Backbone.js 和 Coffee-script 更新 HTML5 画布。由于 Bokeh 是由 JSON 中的数据驱动的，因此它为其他语言（如 R、Scala 和 Julia）创建了简单的绑定。

这提供了主要绘图和可视化库的高级概述。这并不是详尽无遗的。让我们转向可视化的具体示例。

# 为可视化预处理数据

在进行可视化之前，我们将对收集到的数据进行一些准备工作：

```py
In [16]:
# Read harvested data stored in csv in a Panda DF
import pandas as pd
csv_in = '/home/an/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark/data/unq_tweetstxt.csv'
pddf_in = pd.read_csv(csv_in, index_col=None, header=0, sep=';', encoding='utf-8')
In [20]:
print('tweets pandas dataframe - count:', pddf_in.count())
print('tweets pandas dataframe - shape:', pddf_in.shape)
print('tweets pandas dataframe - colns:', pddf_in.columns)
('tweets pandas dataframe - count:', Unnamed: 0    7540
id            7540
created_at    7540
user_id       7540
user_name     7538
tweet_text    7540
dtype: int64)
('tweets pandas dataframe - shape:', (7540, 6))
('tweets pandas dataframe - colns:', Index([u'Unnamed: 0', u'id', u'created_at', u'user_id', u'user_name', u'tweet_text'], dtype='object'))
```

为了进行我们的可视化活动，我们将使用一组包含 7,540 条推文的数据集。关键信息存储在`tweet_text`列中。我们通过在数据框上调用`head()`函数来预览存储在数据框中的数据：

```py
In [21]:
pddf_in.head()
Out[21]:
  Unnamed: 0   id   created_at   user_id   user_name   tweet_text
0   0   638830426971181057   Tue Sep 01 21:46:57 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: 9_A_6: dreamint...
1   1   638830426727911424   Tue Sep 01 21:46:57 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: PhuketDailyNews...
2   2   638830425402556417   Tue Sep 01 21:46:56 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: 9_A_6: ernestsg...
3   3   638830424563716097   Tue Sep 01 21:46:56 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: PhuketDailyNews...
4   4   638830422256816132   Tue Sep 01 21:46:56 +0000 2015   3276255125   True Equality   ernestsgantt: elsahel12: 9_A_6: dreamintention...
```

我们现在将创建一些实用程序函数来清理推文文本并解析推特日期。首先，我们导入 Python 正则表达式 regex 库`re`和时间库来解析日期和时间：

```py
In [72]:
import re
import time
```

我们创建一个正则表达式的字典，将对其进行编译，然后作为函数传递：

+   **RT**：带有关键字`RT`的第一个正则表达式在推文文本开头寻找关键字`RT`：

```py
re.compile(r'^RT'),
```

+   **ALNUM**：第二个带有关键字`ALNUM`的正则表达式寻找包括字母数字字符和下划线符号在内的单词，这些单词前面有`@`符号在推文文本中：

```py
re.compile(r'(@[a-zA-Z0-9_]+)'),
```

+   **HASHTAG**：带有关键字`HASHTAG`的第三个正则表达式在推文文本中寻找包括`#`符号在内的单词：

```py
re.compile(r'(#[\w\d]+)'),
```

+   **SPACES**：带有关键字`SPACES`的第四个正则表达式在推文文本中寻找空格或换行符：

```py
re.compile(r'\s+'), 
```

+   **URL**：带有关键字`URL`的第五个正则表达式在推文文本中寻找包括以`https://`或`http://`标记开头的`url`地址：

```py
re.compile(r'([https://|http://]?[a-zA-Z\d\/]+[\.]+[a-zA-Z\d\/\.]+)')
In [24]:
regexp = {"RT": "^RT", "ALNUM": r"(@[a-zA-Z0-9_]+)",
          "HASHTAG": r"(#[\w\d]+)", "URL": r"([https://|http://]?[a-zA-Z\d\/]+[\.]+[a-zA-Z\d\/\.]+)",
          "SPACES":r"\s+"}
regexp = dict((key, re.compile(value)) for key, value in regexp.items())
In [25]:
regexp
Out[25]:
{'ALNUM': re.compile(r'(@[a-zA-Z0-9_]+)'),
 'HASHTAG': re.compile(r'(#[\w\d]+)'),
 'RT': re.compile(r'^RT'),
 'SPACES': re.compile(r'\s+'),
 'URL': re.compile(r'([https://|http://]?[a-zA-Z\d\/]+[\.]+[a-zA-Z\d\/\.]+)')}
```

我们创建一个实用程序函数来识别推文是转发还是原始推文：

```py
In [77]:
def getAttributeRT(tweet):
    """ see if tweet is a RT """
    return re.search(regexp["RT"], tweet.strip()) != None
```

然后，我们提取推文中的所有用户句柄：

```py
def getUserHandles(tweet):
    """ given a tweet we try and extract all user handles"""
    return re.findall(regexp["ALNUM"], tweet)
```

我们还提取推文中的所有标签：

```py
def getHashtags(tweet):
    """ return all hashtags"""
    return re.findall(regexp["HASHTAG"], tweet)
```

提取推文中的所有 URL 链接如下：

```py
def getURLs(tweet):
    """ URL : [http://]?[\w\.?/]+"""
    return re.findall(regexp["URL"], tweet)
```

我们剥离推文文本中以`@`符号开头的所有 URL 链接和用户句柄。这个函数将成为我们即将构建的词云的基础：

```py
def getTextNoURLsUsers(tweet):
    """ return parsed text terms stripped of URLs and User Names in tweet text
        ' '.join(re.sub("(@[A-Za-z0-9]+)|([⁰-9A-Za-z \t])|(\w+:\/\/\S+)"," ",x).split()) """
    return ' '.join(re.sub("(@[A-Za-z0-9]+)|([⁰-9A-Za-z \t])|(\w+:\/\/\S+)|(RT)"," ", tweet).lower().split())
```

我们对数据进行标记，以便我们可以创建词云的数据集组：

```py
def setTag(tweet):
    """ set tags to tweet_text based on search terms from tags_list"""
    tags_list = ['spark', 'python', 'clinton', 'trump', 'gaga', 'bieber']
    lower_text = tweet.lower()
    return filter(lambda x:x.lower() in lower_text,tags_list)
```

我们以`yyyy-mm-dd hh:mm:ss`格式解析推特日期：

```py
def decode_date(s):
    """ parse Twitter date into format yyyy-mm-dd hh:mm:ss"""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.strptime(s,'%a %b %d %H:%M:%S +0000 %Y'))
```

我们在处理之前预览数据：

```py
In [43]:
pddf_in.columns
Out[43]:
Index([u'Unnamed: 0', u'id', u'created_at', u'user_id', u'user_name', u'tweet_text'], dtype='object')
In [45]:
# df.drop([Column Name or list],inplace=True,axis=1)
pddf_in.drop(['Unnamed: 0'], inplace=True, axis=1)
In [46]:
pddf_in.head()
Out[46]:
  id   created_at   user_id   user_name   tweet_text
0   638830426971181057   Tue Sep 01 21:46:57 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: 9_A_6: dreamint...
1   638830426727911424   Tue Sep 01 21:46:57 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: PhuketDailyNews...
2   638830425402556417   Tue Sep 01 21:46:56 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: 9_A_6: ernestsg...
3   638830424563716097   Tue Sep 01 21:46:56 +0000 2015   3276255125   True Equality   ernestsgantt: BeyHiveInFrance: PhuketDailyNews...
4   638830422256816132   Tue Sep 01 21:46:56 +0000 2015   3276255125   True Equality   ernestsgantt: elsahel12: 9_A_6: dreamintention...
```

我们通过应用所描述的实用程序函数来创建新的数据框列。我们为`htag`、用户句柄、URL、从 URL 中剥离的文本术语和不需要的字符以及标签创建一个新列。最后我们解析日期：

```py
In [82]:
pddf_in['htag'] = pddf_in.tweet_text.apply(getHashtags)
pddf_in['user_handles'] = pddf_in.tweet_text.apply(getUserHandles)
pddf_in['urls'] = pddf_in.tweet_text.apply(getURLs)
pddf_in['txt_terms'] = pddf_in.tweet_text.apply(getTextNoURLsUsers)
pddf_in['search_grp'] = pddf_in.tweet_text.apply(setTag)
pddf_in['date'] = pddf_in.created_at.apply(decode_date)
```

以下代码快速展示了新生成的数据框的情况：

```py
In [83]:
pddf_in[2200:2210]
Out[83]:
  id   created_at   user_id   user_name   tweet_text   htag   urls   ptxt   tgrp   date   user_handles   txt_terms   search_grp
2200   638242693374681088   Mon Aug 31 06:51:30 +0000 2015   19525954   CENATIC   El impacto de @ApacheSpark en el procesamiento...   [#sparkSpecial]   [://t.co/4PQmJNuEJB]   el impacto de en el procesamiento de datos y e...   [spark]   2015-08-31 06:51:30   [@ApacheSpark]   el impacto de en el procesamiento de datos y e...   [spark]
2201   638238014695575552   Mon Aug 31 06:32:55 +0000 2015   51115854   Nawfal   Real Time Streaming with Apache Spark\nhttp://...   [#IoT, #SmartMelboune, #BigData, #Apachespark]   [://t.co/GW5PaqwVab]   real time streaming with apache spark iot smar...   [spark]   2015-08-31 06:32:55   []   real time streaming with apache spark iot smar...   [spark]
2202   638236084124516352   Mon Aug 31 06:25:14 +0000 2015   62885987   Mithun Katti   RT @differentsachin: Spark the flame of digita...   [#IBMHackathon, #SparkHackathon, #ISLconnectIN...   []   spark the flame of digital india ibmhackathon ...   [spark]   2015-08-31 06:25:14   [@differentsachin, @ApacheSpark]   spark the flame of digital india ibmhackathon ...   [spark]
2203   638234734649176064   Mon Aug 31 06:19:53 +0000 2015   140462395   solaimurugan v   Installing @ApacheMahout with @ApacheSpark 1.4...   []   [1.4.1, ://t.co/3c5dGbfaZe.]   installing with 1 4 1 got many more issue whil...   [spark]   2015-08-31 06:19:53   [@ApacheMahout, @ApacheSpark]   installing with 1 4 1 got many more issue whil...   [spark]
2204   638233517307072512   Mon Aug 31 06:15:02 +0000 2015   2428473836   Ralf Heineke   RT @RomeoKienzler: Join me @velocityconf on #m...   [#machinelearning, #devOps, #Bl]   [://t.co/U5xL7pYEmF]   join me on machinelearning based devops operat...   [spark]   2015-08-31 06:15:02   [@RomeoKienzler, @velocityconf, @ApacheSpark]   join me on machinelearning based devops operat...   [spark]
2205   638230184848687106   Mon Aug 31 06:01:48 +0000 2015   289355748   Akim Boyko   RT @databricks: Watch live today at 10am PT is...   []   [1.5, ://t.co/16cix6ASti]   watch live today at 10am pt is 1 5 presented b...   [spark]   2015-08-31 06:01:48   [@databricks, @ApacheSpark, @databricks, @pwen...   watch live today at 10am pt is 1 5 presented b...   [spark]
2206   638227830443110400   Mon Aug 31 05:52:27 +0000 2015   145001241   sachin aggarwal   Spark the flame of digital India @ #IBMHackath...   [#IBMHackathon, #SparkHackathon, #ISLconnectIN...   [://t.co/C1AO3uNexe]   spark the flame of digital india ibmhackathon ...   [spark]   2015-08-31 05:52:27   [@ApacheSpark]   spark the flame of digital india ibmhackathon ...   [spark]
2207   638227031268810752   Mon Aug 31 05:49:16 +0000 2015   145001241   sachin aggarwal   RT @pravin_gadakh: Imagine, innovate and Igni...   [#IBMHackathon, #ISLconnectIN2015]   []   gadakh imagine innovate and ignite digital ind...   [spark]   2015-08-31 05:49:16   [@pravin_gadakh, @ApacheSpark]   gadakh imagine innovate and ignite digital ind...   [spark]
2208   638224591920336896   Mon Aug 31 05:39:35 +0000 2015   494725634   IBM Asia Pacific   RT @sachinparmar: Passionate about Spark?? Hav...   [#IBMHackathon, #ISLconnectIN]   [India..]   passionate about spark have dreams of clean sa...   [spark]   2015-08-31 05:39:35   [@sachinparmar]   passionate about spark have dreams of clean sa...   [spark]
2209   638223327467692032   Mon Aug 31 05:34:33 +0000 2015   3158070968   Open Source India   "Game Changer" #ApacheSpark speeds up #bigdata...   [#ApacheSpark, #bigdata]   [://t.co/ieTQ9ocMim]   game changer apachespark speeds up bigdata pro...   [spark]   2015-08-31 05:34:33   []   game changer apachespark speeds up bigdata pro...   [spark]
```

我们以 CSV 格式保存处理过的信息。我们有 7,540 条记录和 13 列。在您的情况下，输出将根据您选择的数据集而有所不同：

```py
In [84]:
f_name = '/home/an/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark/data/unq_tweets_processed.csv'
pddf_in.to_csv(f_name, sep=';', encoding='utf-8', index=False)
In [85]:
pddf_in.shape
Out[85]:
(7540, 13)
```

# 一瞥词语、情绪和迷因

我们现在准备构建词云，这将让我们了解这些推文中携带的重要词语。我们将为收集的数据集创建词云。词云提取单词列表中的前几个词，并创建单词的散点图，其中单词的大小与其频率相关。数据集中单词的频率越高，词云呈现的字体大小就越大。它们包括三个非常不同的主题和两个竞争或类似的实体。我们的第一个主题显然是数据处理和分析，其中 Apache Spark 和 Python 是我们的实体。我们的第二个主题是 2016 年总统竞选活动，有两位竞争者：希拉里·克林顿和唐纳德·特朗普。我们最后的主题是流行音乐界，贾斯汀·比伯和 Lady Gaga 是两位代表。

## 设置词云

我们将通过分析与 Spark 相关的推文来说明编程步骤。我们加载数据并预览数据框：

```py
In [21]:
import pandas as pd
csv_in = '/home/an/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark/data/spark_tweets.csv'
tspark_df = pd.read_csv(csv_in, index_col=None, header=0, sep=',', encoding='utf-8')
In [3]:
tspark_df.head(3)
Out[3]:
  id   created_at   user_id   user_name   tweet_text   htag   urls   ptxt   tgrp   date   user_handles   txt_terms   search_grp
0   638818911773856000   Tue Sep 01 21:01:11 +0000 2015   2511247075   Noor Din   RT @kdnuggets: R leads RapidMiner, Python catc...   [#KDN]   [://t.co/3bsaTT7eUs]   r leads rapidminer python catches up big data ...   [spark, python]   2015-09-01 21:01:11   [@kdnuggets]   r leads rapidminer python catches up big data ...   [spark, python]
1   622142176768737000   Fri Jul 17 20:33:48 +0000 2015   24537879   IBM Cloudant   Be one of the first to sign-up for IBM Analyti...   [#ApacheSpark, #SparkInsight]   [://t.co/C5TZpetVA6, ://t.co/R1L29DePaQ]   be one of the first to sign up for ibm analyti...   [spark]   2015-07-17 20:33:48   []   be one of the first to sign up for ibm analyti...   [spark]
2   622140453069169000   Fri Jul 17 20:26:57 +0000 2015   515145898   Arno Candel   Nice article on #apachespark, #hadoop and #dat...   [#apachespark, #hadoop, #datascience]   [://t.co/IyF44pV0f3]   nice article on apachespark hadoop and datasci...   [spark]   2015-07-17 20:26:57   [@h2oai]   nice article on apachespark hadoop and datasci...   [spark]
```

### 注意

我们将使用的词云库是由 Andreas Mueller 开发的，并托管在他的 GitHub 帐户上[`github.com/amueller/word_cloud`](https://github.com/amueller/word_cloud)。

该库需要**PIL**（即**Python Imaging Library**的缩写）。PIL 可以通过调用`conda install pil`轻松安装。PIL 是一个复杂的库，尚未移植到 Python 3.4，因此我们需要运行 Python 2.7+环境才能看到我们的词云：

```py
#
# Install PIL (does not work with Python 3.4)
#
an@an-VB:~$ conda install pil

Fetching package metadata: ....
Solving package specifications: ..................
Package plan for installation in environment /home/an/anaconda:
```

将下载以下软件包：

```py
    package                    |            build
    ---------------------------|-----------------
    libpng-1.6.17              |                0         214 KB
    freetype-2.5.5             |                0         2.2 MB
    conda-env-2.4.4            |           py27_0          24 KB
    pil-1.1.7                  |           py27_2         650 KB
    ------------------------------------------------------------
                                           Total:         3.0 MB
```

将更新以下软件包：

```py
    conda-env: 2.4.2-py27_0 --> 2.4.4-py27_0
    freetype:  2.5.2-0      --> 2.5.5-0     
    libpng:    1.5.13-1     --> 1.6.17-0    
    pil:       1.1.7-py27_1 --> 1.1.7-py27_2

Proceed ([y]/n)? y
```

接下来，我们安装词云库：

```py
#
# Install wordcloud
# Andreas Mueller
# https://github.com/amueller/word_cloud/blob/master/wordcloud/wordcloud.py
#

an@an-VB:~$ pip install wordcloud
Collecting wordcloud
  Downloading wordcloud-1.1.3.tar.gz (163kB)
    100% |████████████████████████████████| 163kB 548kB/s 
Building wheels for collected packages: wordcloud
  Running setup.py bdist_wheel for wordcloud
  Stored in directory: /home/an/.cache/pip/wheels/32/a9/74/58e379e5dc614bfd9dd9832d67608faac9b2bc6c194d6f6df5
Successfully built wordcloud
Installing collected packages: wordcloud
Successfully installed wordcloud-1.1.3
```

## 创建词云

在这个阶段，我们准备使用推文文本生成的术语列表调用词云程序。

让我们通过首先调用`％matplotlib` inline 来开始词云程序，以在我们的笔记本中显示词云：

```py
In [4]:
%matplotlib inline
In [11]:
```

我们将数据框`txt_terms`列转换为单词列表。我们确保将其全部转换为`str`类型，以避免任何意外，并检查列表的前四条记录：

```py
len(tspark_df['txt_terms'].tolist())
Out[11]:
2024
In [22]:
tspark_ls_str = [str(t) for t in tspark_df['txt_terms'].tolist()]
In [14]:
len(tspark_ls_str)
Out[14]:
2024
In [15]:
tspark_ls_str[:4]
Out[15]:
['r leads rapidminer python catches up big data tools grow spark ignites kdn',
 'be one of the first to sign up for ibm analytics for apachespark today sparkinsight',
 'nice article on apachespark hadoop and datascience',
 'spark 101 running spark and mapreduce together in production hadoopsummit2015 apachespark altiscale']
```

我们首先调用 Matplotlib 和词云库：

```py
import matplotlib.pyplot as plt
from wordcloud import WordCloud, STOPWORDS
```

从输入的术语列表中，我们创建一个由空格分隔的术语统一字符串作为词云程序的输入。词云程序会删除停用词：

```py
# join tweets to a single string
words = ' '.join(tspark_ls_str)

# create wordcloud 
wordcloud = WordCloud(
                      # remove stopwords
                      stopwords=STOPWORDS,
                      background_color='black',
                      width=1800,
                      height=1400
                     ).generate(words)

# render wordcloud image
plt.imshow(wordcloud)
plt.axis('off')

# save wordcloud image on disk
plt.savefig('./spark_tweets_wordcloud_1.png', dpi=300)

# display image in Jupyter notebook
plt.show()
```

在这里，我们可以看到 Apache Spark 和 Python 的词云。显然，在 Spark 的情况下，“Hadoop”、“大数据”和“分析”是主题词，而 Python 则回顾了其名称 Monty Python 的根源，专注于“开发人员”、“apache spark”和一些涉及到 java 和 ruby 的编程。

![创建词云](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_06_02.jpg)

我们还可以从以下词云中看到北美 2016 年总统候选人希拉里·克林顿和唐纳德·特朗普所关注的词语。看起来希拉里·克林顿被她的对手唐纳德·特朗普和伯尼·桑德斯所掩盖，而特朗普则只关注自己：

![创建词云](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_06_03.jpg)

有趣的是，在贾斯汀·比伯和 Lady Gaga 的情况下，出现了“爱”这个词。在比伯的情况下，“关注”和“belieber”是关键词，而在 Lady Gaga 的情况下，“节食”、“减肥”和“时尚”是她的关注点。

![创建词云](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_06_04.jpg)

# 地理定位推文和标记聚会

现在，我们将深入使用 Bokeh 创建交互地图。首先，我们创建一个世界地图，在地图上标出样本推文的地理位置，当我们的鼠标移动到这些位置时，我们可以在悬停框中看到用户及其相应的推文。

第二张地图专注于标记伦敦即将举行的聚会。它可以是一个交互式地图，作为特定城市即将举行的聚会的日期、时间和地点的提醒。

## 地理定位推文

目标是在地图上创建重要推文位置的世界地图散点图，悬停在这些点上可以显示推文和作者。我们将通过三个步骤来构建这个交互式可视化：

1.  首先通过加载包含各个世界国家边界的字典，定义它们的经度和纬度，创建背景世界地图。

1.  加载我们希望通过其相应坐标和作者进行地理定位的重要推文。

1.  最后，在世界地图上绘制推文坐标的散点图，并激活悬停工具，以交互方式可视化地图上突出点的推文和作者。

在第一步中，我们创建了一个名为 data 的 Python 列表，其中包含所有世界国家边界及其相应的纬度和经度：

```py
In [4]:
#
# This module exposes geometry data for World Country Boundaries.
#
import csv
import codecs
import gzip
import xml.etree.cElementTree as et
import os
from os.path import dirname, join

nan = float('NaN')
__file__ = os.getcwd()

data = {}
with gzip.open(join(dirname(__file__), 'AN_Spark/data/World_Country_Boundaries.csv.gz')) as f:
    decoded = codecs.iterdecode(f, "utf-8")
    next(decoded)
    reader = csv.reader(decoded, delimiter=',', quotechar='"')
    for row in reader:
        geometry, code, name = row
        xml = et.fromstring(geometry)
        lats = []
        lons = []
        for i, poly in enumerate(xml.findall('.//outerBoundaryIs/LinearRing/coordinates')):
            if i > 0:
                lats.append(nan)
                lons.append(nan)
            coords = (c.split(',')[:2] for c in poly.text.split())
            lat, lon = list(zip(*[(float(lat), float(lon)) for lon, lat in
                coords]))
            lats.extend(lat)
            lons.extend(lon)
        data[code] = {
            'name'   : name,
            'lats'   : lats,
            'lons'   : lons,
        }
In [5]:
len(data)
Out[5]:
235
```

在第二步中，我们加载了一组希望可视化的重要推文样本及其相应的地理位置信息：

```py
In [69]:
# data
#
#
In [8]:
import pandas as pd
csv_in = '/home/an/spark/spark-1.5.0-bin-hadoop2.6/examples/AN_Spark/data/spark_tweets_20.csv'
t20_df = pd.read_csv(csv_in, index_col=None, header=0, sep=',', encoding='utf-8')
In [9]:
t20_df.head(3)
Out[9]:
    id  created_at  user_id     user_name   tweet_text  htag    urls    ptxt    tgrp    date    user_handles    txt_terms   search_grp  lat     lon
0   638818911773856000  Tue Sep 01 21:01:11 +0000 2015  2511247075  Noor Din    RT @kdnuggets: R leads RapidMiner, Python catc...   [#KDN]  [://t.co/3bsaTT7eUs]    r leads rapidminer python catches up big data ...   [spark, python]     2015-09-01 21:01:11     [@kdnuggets]    r leads rapidminer python catches up big data ...   [spark, python]     37.279518   -121.867905
1   622142176768737000  Fri Jul 17 20:33:48 +0000 2015  24537879    IBM Cloudant    Be one of the first to sign-up for IBM Analyti...   [#ApacheSpark, #SparkInsight]   [://t.co/C5TZpetVA6, ://t.co/R1L29DePaQ]    be one of the first to sign up for ibm analyti...   [spark]     2015-07-17 20:33:48     []  be one of the first to sign up for ibm analyti...   [spark]     37.774930   -122.419420
2   622140453069169000  Fri Jul 17 20:26:57 +0000 2015  515145898   Arno Candel     Nice article on #apachespark, #hadoop and #dat...   [#apachespark, #hadoop, #datascience]   [://t.co/IyF44pV0f3]    nice article on apachespark hadoop and datasci...   [spark]     2015-07-17 20:26:57     [@h2oai]    nice article on apachespark hadoop and datasci...   [spark]     51.500130   -0.126305
In [98]:
len(t20_df.user_id.unique())
Out[98]:
19
In [17]:
t20_geo = t20_df[['date', 'lat', 'lon', 'user_name', 'tweet_text']]
In [24]:
# 
t20_geo.rename(columns={'user_name':'user', 'tweet_text':'text' }, inplace=True)
In [25]:
t20_geo.head(4)
Out[25]:
    date    lat     lon     user    text
0   2015-09-01 21:01:11     37.279518   -121.867905     Noor Din    RT @kdnuggets: R leads RapidMiner, Python catc...
1   2015-07-17 20:33:48     37.774930   -122.419420     IBM Cloudant    Be one of the first to sign-up for IBM Analyti...
2   2015-07-17 20:26:57     51.500130   -0.126305   Arno Candel     Nice article on #apachespark, #hadoop and #dat...
3   2015-07-17 19:35:31     51.500130   -0.126305   Ira Michael Blonder     Spark 101: Running Spark and #MapReduce togeth...
In [22]:
df = t20_geo
#
```

在第三步中，我们首先导入了所有必要的 Bokeh 库。我们将在 Jupyter Notebook 中实例化输出。我们加载了世界各国的边界信息。我们获取了地理定位的推文数据。我们实例化了 Bokeh 交互工具，如滚动和框选放大，以及悬停工具。

```py
In [29]:
#
# Bokeh Visualization of tweets on world map
#
from bokeh.plotting import *
from bokeh.models import HoverTool, ColumnDataSource
from collections import OrderedDict

# Output in Jupiter Notebook
output_notebook()

# Get the world map
world_countries = data.copy()

# Get the tweet data
tweets_source = ColumnDataSource(df)

# Create world map 
countries_source = ColumnDataSource(data= dict(
    countries_xs=[world_countries[code]['lons'] for code in world_countries],
    countries_ys=[world_countries[code]['lats'] for code in world_countries],
    country = [world_countries[code]['name'] for code in world_countries],
))

# Instantiate the bokeh interactive tools 
TOOLS="pan,wheel_zoom,box_zoom,reset,resize,hover,save"
```

现在，我们已经准备好将收集到的各种元素层叠到一个名为**p**的对象图中。定义**p**的标题、宽度和高度。附加工具。通过具有浅色背景和边界的补丁创建世界地图背景。根据其相应的地理坐标绘制推文的散点图。然后，激活悬停工具，显示用户及其相应的推文。最后，在浏览器上渲染图片。代码如下：

```py
# Instantiante the figure object
p = figure(
    title="%s tweets " %(str(len(df.index))),
    title_text_font_size="20pt",
    plot_width=1000,
    plot_height=600,
    tools=TOOLS)

# Create world patches background
p.patches(xs="countries_xs", ys="countries_ys", source = countries_source, fill_color="#F1EEF6", fill_alpha=0.3,
        line_color="#999999", line_width=0.5)

# Scatter plots by longitude and latitude
p.scatter(x="lon", y="lat", source=tweets_source, fill_color="#FF0000", line_color="#FF0000")
# 

# Activate hover tool with user and corresponding tweet information
hover = p.select(dict(type=HoverTool))
hover.point_policy = "follow_mouse"
hover.tooltips = OrderedDict([
    ("user", "@user"),
   ("tweet", "@text"),
])

# Render the figure on the browser
show(p)
BokehJS successfully loaded.

inspect

#
#
```

以下代码概述了世界地图，红点代表推文来源的位置：

![地理定位推文](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_06_05.jpg)

我们可以悬停在特定的点上，以显示该位置的推文：

![地理定位推文](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_06_06.jpg)

我们可以放大到特定位置：

![地理定位推文](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_06_07.jpg)

最后，我们可以在给定的放大位置中显示推文：

![地理定位推文](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_06_08.jpg)

## 在 Google 地图上显示即将举行的聚会

现在，我们的目标是专注于伦敦即将举行的聚会。我们正在对**Data Science London**、**Apache Spark**和**Machine Learning**三次聚会进行地图绘制。我们在 Bokeh 可视化中嵌入了 Google 地图，并根据它们的坐标进行地理定位，并使用悬停工具获取每次聚会的名称等信息。

首先，导入所有必要的 Bokeh 库：

```py
In [ ]:
#
# Bokeh Google Map Visualization of London with hover on specific points
#
#
from __future__ import print_function

from bokeh.browserlib import view
from bokeh.document import Document
from bokeh.embed import file_html
from bokeh.models.glyphs import Circle
from bokeh.models import (
    GMapPlot, Range1d, ColumnDataSource,
    PanTool, WheelZoomTool, BoxSelectTool,
    HoverTool, ResetTool,
    BoxSelectionOverlay, GMapOptions)
from bokeh.resources import INLINE

x_range = Range1d()
y_range = Range1d()
```

我们将实例化 Google 地图，它将作为我们的 Bokeh 可视化的基础：

```py
# JSON style string taken from: https://snazzymaps.com/style/1/pale-dawn
map_options = GMapOptions(lat=51.50013, lng=-0.126305, map_type="roadmap", zoom=13, styles="""
[{"featureType":"administrative","elementType":"all","stylers":[{"visibility":"on"},{"lightness":33}]},
 {"featureType":"landscape","elementType":"all","stylers":[{"color":"#f2e5d4"}]},
 {"featureType":"poi.park","elementType":"geometry","stylers":[{"color":"#c5dac6"}]},
 {"featureType":"poi.park","elementType":"labels","stylers":[{"visibility":"on"},{"lightness":20}]},
 {"featureType":"road","elementType":"all","stylers":[{"lightness":20}]},
 {"featureType":"road.highway","elementType":"geometry","stylers":[{"color":"#c5c6c6"}]},
 {"featureType":"road.arterial","elementType":"geometry","stylers":[{"color":"#e4d7c6"}]},
 {"featureType":"road.local","elementType":"geometry","stylers":[{"color":"#fbfaf7"}]},
 {"featureType":"water","elementType":"all","stylers":[{"visibility":"on"},{"color":"#acbcc9"}]}]
""")
```

从上一步的类`GMapPlot`中实例化 Bokeh 对象绘图，使用先前步骤的尺寸和地图选项：

```py
# Instantiate Google Map Plot
plot = GMapPlot(
    x_range=x_range, y_range=y_range,
    map_options=map_options,
    title="London Meetups"
)
```

引入我们希望绘制的三次聚会的信息，并通过悬停在相应坐标上获取信息：

```py
source = ColumnDataSource(
    data=dict(
        lat=[51.49013, 51.50013, 51.51013],
        lon=[-0.130305, -0.126305, -0.120305],
        fill=['orange', 'blue', 'green'],
        name=['LondonDataScience', 'Spark', 'MachineLearning'],
        text=['Graph Data & Algorithms','Spark Internals','Deep Learning on Spark']
    )
)
```

定义要在 Google 地图上绘制的点：

```py
circle = Circle(x="lon", y="lat", size=15, fill_color="fill", line_color=None)
plot.add_glyph(source, circle)
```

定义要在此可视化中使用的 Bokeh 工具的字符串：

```py
# TOOLS="pan,wheel_zoom,box_zoom,reset,hover,save"
pan = PanTool()
wheel_zoom = WheelZoomTool()
box_select = BoxSelectTool()
reset = ResetTool()
hover = HoverTool()
# save = SaveTool()

plot.add_tools(pan, wheel_zoom, box_select, reset, hover)
overlay = BoxSelectionOverlay(tool=box_select)
plot.add_layout(overlay)
```

激活`hover`工具，并携带信息：

```py
hover = plot.select(dict(type=HoverTool))
hover.point_policy = "follow_mouse"
hover.tooltips = OrderedDict([
    ("Name", "@name"),
    ("Text", "@text"),
    ("(Long, Lat)", "(@lon, @lat)"),
])

show(plot)
```

渲染给出伦敦相当不错的视图的绘图：

![在 Google 地图上显示即将举行的聚会](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_06_09.jpg)

一旦我们悬停在突出显示的点上，我们就可以获取给定聚会的信息：

![在 Google 地图上显示即将举行的聚会](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_06_10.jpg)

完整的平滑缩放功能得到保留，如下面的截图所示：

![在 Google 地图上显示即将举行的聚会](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-py-dev/img/B03968_06_11.jpg)

# 总结

在本章中，我们专注于一些可视化技术。我们看到了如何构建词云及其直观的力量，一眼就可以揭示成千上万条推文中的关键词、情绪和流行词。

然后我们讨论了使用 Bokeh 进行交互式地图可视化。我们从零开始构建了一张世界地图，并创建了一个关键推文的散点图。一旦地图在浏览器上呈现出来，我们就可以交互式地从一个点悬停到另一个点，并显示来自世界各地不同地区的推文。

我们最终的可视化重点是在 Spark、数据科学和机器学习上映射伦敦即将举行的聚会，以及它们各自的主题，使用实际的谷歌地图制作了一个美丽的交互式可视化。
