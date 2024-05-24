# 精通 Spark 2.x 机器学习（二）

> 原文：[`zh.annas-archive.org/md5/3BA1121D202F8663BA917C3CD75B60BC`](https://zh.annas-archive.org/md5/3BA1121D202F8663BA917C3CD75B60BC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 NLP 和 Spark 流处理预测电影评论

在本章中，我们将深入研究**自然语言处理**（**NLP**）领域，不要与神经语言编程混淆！NLP 有助于分析原始文本数据并提取有用信息，如句子结构、文本情感，甚至不同语言之间的翻译。由于许多数据源包含原始文本（例如评论、新闻文章和医疗记录），NLP 变得越来越受欢迎，因为它提供了对文本的洞察，并有助于更轻松地做出自动化决策。

在幕后，NLP 通常使用机器学习算法来提取和建模文本的结构。如果将 NLP 应用于另一个机器方法的背景下，例如文本可以代表输入特征之一，NLP 的力量就更加明显。

在本章中，我们将应用 NLP 来分析电影评论的*情感*。基于标注的训练数据，我们将构建一个分类模型，用于区分正面和负面的电影评论。重要的是要提到，我们不直接从文本中提取情感（基于诸如爱、恨等词语），而是利用我们在上一章中已经探讨过的二元分类。

为了实现这一目标，我们将采用事先手动评分的原始电影评论，并训练一个集成模型-一组模型-如下所示：

1.  处理电影评论以合成我们模型的特征。

在这里，我们将探讨使用文本数据创建各种特征的方法，从词袋模型到加权词袋模型（例如 TF-IDF），然后简要探讨 word2vec 算法，我们将在第五章中详细探讨，即预测和聚类的 Word2vec。

与此同时，我们将研究一些基本的特征选择/省略方法，包括去除停用词和标点，或者词干提取。

1.  利用生成的特征，我们将运行各种监督的二元分类算法，帮助我们对正面和负面的评论进行分类，其中包括以下内容：

+   分类决策树

+   朴素贝叶斯

+   随机森林

+   梯度提升树

1.  利用四种不同学习算法的综合预测能力，我们将创建一个超级学习模型，该模型将四种模型的所有“猜测”作为元特征，训练一个深度神经网络输出最终预测。

1.  最后，我们将为此过程创建一个 Spark 机器学习管道，该管道执行以下操作：

+   从新的电影评论中提取特征

+   提出一个预测

+   在 Spark 流应用程序中输出这个预测（是的，你将在本书的剩余章节中构建你的第一个机器学习应用程序！）

如果这听起来有点雄心勃勃，那就放心吧！我们将以一种有条理和有目的的方式逐步完成这些任务，这样你就可以有信心构建自己的 NLP 应用；但首先，让我们简要了解一下这个令人兴奋的领域的一些背景历史和理论。

# NLP - 简要介绍

就像人工神经网络一样，NLP 是一个相对“古老”的主题，但最近由于计算能力的提升和机器学习算法在包括但不限于以下任务中的各种应用，它引起了大量关注：

+   机器翻译（MT）：在其最简单的形式中，这是机器将一种语言的词翻译成另一种语言的词的能力。有趣的是，机器翻译系统的提议早于数字计算机的创建。第一个自然语言处理应用之一是在二战期间由美国科学家沃伦·韦弗（Warren Weaver）创建的，他的工作是试图破译德国密码。如今，我们有高度复杂的应用程序，可以将一段文本翻译成我们想要的任意数量的不同语言！

+   语音识别（SR）：这些方法和技术试图利用机器识别和翻译口语到文本。我们现在在智能手机中看到这些技术，这些手机使用语音识别系统来帮助我们找到最近的加油站的方向，或者查询谷歌周末的天气预报。当我们对着手机说话时，机器能够识别我们说的话，然后将这些话翻译成计算机可以识别并执行某些任务的文本。

+   信息检索（IR）：你是否曾经阅读过一篇文章，比如新闻网站上的一篇文章，然后想看看与你刚刚阅读的文章类似的新闻文章？这只是信息检索系统的一个例子，它以一段文本作为“输入”，并寻求获取与输入文本类似的其他相关文本。也许最简单和最常见的信息检索系统的例子是在基于网络的搜索引擎上进行搜索。我们提供一些我们想要“了解更多”的词（这是“输入”），输出是搜索结果，希望这些结果与我们的输入搜索查询相关。

+   信息提取（IE）：这是从非结构化数据（如文本、视频和图片）中提取结构化信息的任务。例如，当你阅读某个网站上的博客文章时，通常会给这篇文章打上几个描述这篇文章一般主题的关键词，这可以使用信息提取系统进行分类。信息提取的一个极其受欢迎的领域是称为*视觉信息提取*，它试图从网页的视觉布局中识别复杂实体，这在典型的自然语言处理方法中无法捕捉到。

+   文本摘要（该项没有缩写！）：这是一个非常受欢迎的研究领域。这是通过识别主题等方式，对各种长度的文本进行摘要的任务。在下一章中，我们将通过主题模型（如潜在狄利克雷分配（LDA）和潜在语义分析（LSA））来探讨文本摘要的两种流行方法。

在本章中，我们将使用自然语言处理技术来帮助我们解决来自国际电影数据库（IMDb）的电影评论的二元分类问题。现在让我们将注意力转移到我们将使用的数据集，并学习更多关于使用 Spark 进行特征提取的技术。

# 数据集

最初发表在 Andrew L. Maas 等人的论文《为情感分析学习词向量》中的《大型电影评论数据库》可以从[`ai.stanford.edu/~amaas/data/sentiment/`](http://ai.stanford.edu/~amaas/data/sentiment/)下载。

下载的存档包含两个标记为*train*和*test*的文件夹。对于训练，有 12,500 条正面评价和 12,500 条负面评价，我们将在这些上训练一个分类器。测试数据集包含相同数量的正面和负面评价，总共有 50,000 条正面和负面评价在这两个文件中。

让我们看一个评论的例子，看看数据是什么样子的：

“Bromwell High”简直太棒了。剧本写得精彩，表演完美，这部对南伦敦公立学校的学生和老师进行讽刺的喜剧让你捧腹大笑。它粗俗、挑衅、机智而敏锐。角色们是对英国社会（或者更准确地说，是对任何社会）的绝妙夸张。跟随凯莎、拉特丽娜和娜特拉的冒险，我们的三位“主角”，这部节目毫不避讳地对每一个可以想象的主题进行了讽刺。政治正确在每一集中都被抛在了窗外。如果你喜欢那些不怕拿每一个禁忌话题开玩笑的节目，那么《布朗韦尔高中》绝对不会让你失望！

看起来我们唯一需要处理的是来自电影评论的原始文本和评论情感；除了文本之外，我们对发布日期、评论者以及其他可能有用的数据一无所知。

# 数据集准备

在运行任何数据操作之前，我们需要像在前几章中那样准备好 Spark 环境。让我们启动 Spark shell，并请求足够的内存来处理下载的数据集：

```scala
export SPARK_HOME="<path to your Spark2.0 distribution"
export SPARKLING_WATER_VERSION="2.1.12"
export SPARK_PACKAGES=\
"ai.h2o:sparkling-water-core_2.11:${SPARKLING_WATER_VERSION},\
ai.h2o:sparkling-water-repl_2.11:${SPARKLING_WATER_VERSION},\
ai.h2o:sparkling-water-ml_2.11:${SPARKLING_WATER_VERSION},\
com.packtpub:mastering-ml-w-spark-utils:1.0.0"
$SPARK_HOME/bin/spark-shell \
--master 'local[*]' \
--driver-memory 10g \
--executor-memory 10g \
--confspark.executor.extraJavaOptions=-XX:MaxPermSize=384M \
--confspark.driver.extraJavaOptions=-XX:MaxPermSize=384M \
--packages "$SPARK_PACKAGES" "$@"
```

为了避免 Spark 产生过多的日志输出，可以通过在 SparkContext 上调用`setLogLevel`来直接控制运行时的日志级别：

`sc.setLogLevel("WARN")`

该命令减少了 Spark 输出的冗长程度。

下一个挑战是读取训练数据集，它由 25,000 条积极和消极的电影评论组成。以下代码将读取这些文件，然后创建我们的二进制标签，0 表示消极评论，1 表示积极评论。

我们直接利用了暴露的 Spark `sqlContext`方法`textFile`，它允许读取多个文件并返回 Dataset[String]。这与前几章提到的方法不同，前几章使用的是`wholeTextFiles`方法，产生的是 RDD[String]：

```scala
val positiveReviews= spark.sqlContext.read.textFile("../data/aclImdb/train/pos/*.txt") 
   .toDF("reviewText") 
println(s"Number of positive reviews: ${positiveReviews.count}") 
Number of positive reviews: 12500
```

我们可以直接使用数据集方法`show`来显示前五行（您可以修改截断参数以显示评论的完整文本）：

```scala
println("Positive reviews:")
positiveReviews.show(5, truncate = true)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00092.jpeg)

接下来，我们将对消极评论做同样的处理：

```scala
val negativeReviews= spark.sqlContext.read.textFile("../data/aclImdb/train/neg/*.txt")
                .toDF("reviewText")
println(s"Number of negative reviews: ${negativeReviews.count}")
```

看一下以下的截图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00093.jpeg)

现在，*positiveReview*和*negativeReviews*变量分别表示加载的评论的 RDD。数据集的每一行包含一个表示单个评论的字符串。然而，我们仍然需要生成相应的标签，并将加载的两个数据集合并在一起。

标记很容易，因为我们将消极和积极的评论加载为分开的 Spark 数据框。我们可以直接添加一个表示消极评论的标签 0 和表示积极评论的标签 1 的常量列：

```scala
import org.apache.spark.sql.functions._
val pos= positiveReviews.withColumn("label", lit(1.0))
val neg= negativeReviews.withColumn("label", lit(0.0))
var movieReviews= pos.union(neg).withColumn("row_id", monotonically_increasing_id)
println("All reviews:")
movieReviews.show(5)
```

看一下以下的截图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00094.jpeg)

在这种情况下，我们使用了`withColumn`方法，它会在现有数据集中添加一个新列。新列`lit(1.0)`的定义意味着一个由数字文字*1.0*定义的常量列。我们需要使用一个实数来定义目标值，因为 Spark API 需要它。最后，我们使用`union`方法将这两个数据集合并在一起。

我们还添加了魔术列`row_id`，它唯一标识数据集中的每一行。这个技巧简化了我们在需要合并多个算法的输出时的工作流程。

为什么我们使用双精度值而不是字符串标签表示？在代码标记单个评论时，我们使用了表示双精度数字的数字文字来定义一个常量列。我们也可以使用*lit("positive")*来标记积极的评论，但是使用纯文本标签会迫使我们在后续步骤中将字符串值转换为数值。因此，在这个例子中，我们将直接使用双精度值标签来简化我们的生活。此外，我们直接使用双精度值，因为 Spark API 要求这样做。

# 特征提取

在这个阶段，我们只有一个代表评论的原始文本，这不足以运行任何机器学习算法。我们需要将文本转换为数字格式，也就是进行所谓的“特征提取”（就像它听起来的那样；我们正在提取输入数据并提取特征，这些特征将用于训练模型）。该方法基于输入特征生成一些新特征。有许多方法可以将文本转换为数字特征。我们可以计算单词的数量、文本的长度或标点符号的数量。然而，为了以一种系统化的方式表示文本，反映文本结构，我们需要更复杂的方法。

# 特征提取方法-词袋模型

现在我们已经摄取了我们的数据并创建了我们的标签，是时候提取我们的特征来构建我们的二元分类模型了。顾名思义，词袋模型方法是一种非常常见的特征提取技术，我们通过这种方法将一段文本，比如一部电影评论，表示为它的单词和语法标记的袋子（也称为多重集）。让我们通过几个电影评论的例子来看一个例子： 

**评论 1：** *《侏罗纪世界》真是个失败！*

**评论 2：** *《泰坦尼克号》……一个经典。摄影和表演一样出色！*

对于每个标记（可以是一个单词和/或标点符号），我们将创建一个特征，然后计算该标记在整个文档中的出现次数。我们的词袋数据集对于第一条评论将如下所示：

| **评论 ID** | **a** | **失败** | **侏罗纪** | **如此** | **世界** | **!** |
| --- | --- | --- | --- | --- | --- | --- |
| 评论 1 | 1 | 1 | 1 | 1 | 1 | 1 |

首先，注意到这个数据集的排列方式，通常称为*文档-术语矩阵*（每个文档[行]由一定的一组单词[术语]组成，构成了这个二维矩阵）。我们也可以以不同的方式排列它，并转置行和列，创建-你猜对了-一个*术语-文档矩阵*，其中列现在显示具有该特定术语的文档，单元格内的数字是计数。还要意识到单词的顺序是按字母顺序排列的，这意味着我们失去了任何单词顺序的意义。这意味着“失败”一词与“侏罗纪”一词的相似度是相等的，虽然我们知道这不是真的，但这突显了词袋模型方法的一个局限性：*单词顺序丢失了，有时，不同的文档可以有相同的表示，但意思完全不同。*

在下一章中，您将了解到一种在谷歌开发并包含在 Spark 中的极其强大的学习算法，称为**word-to-vector**（**word2vec**），它本质上是将术语数字化以“编码”它们的含义。

其次，注意到对于我们给定的包括标点符号在内的六个标记的评论，我们有六列。假设我们将第二条评论添加到我们的文档-术语-矩阵中；我们原始的词袋模型会如何改变？

| **评论 ID** | **a** | **表演** | **一个** | **和** | **摄影** | **经典** | **失败** | **出色** | **瞬间** | **侏罗纪** | **如此** | **泰坦尼克号** | **是** | **世界** | **.** | **!** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 评论 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 1 | 0 | 1 |
| 评论 2 | 0 | 1 | 1 | 2 | 1 | 1 | 0 | 1 | 1 | 0 | 0 | 1 | 1 | 0 | 1 | 2 |

我们将我们原始的特征数量从五个增加到 16 个标记，这带来了这种方法的另一个考虑。鉴于我们必须为每个标记创建一个特征，很容易看出我们很快将拥有一个非常宽且非常稀疏的矩阵表示（稀疏是因为一个文档肯定不会包含每个单词/符号/表情符号等，因此大多数单元格输入将为零）。这对于我们的算法的维度来说提出了一些有趣的问题。

考虑这样一种情况，我们试图在文本文档上使用词袋方法训练一个随机森林，其中有 200,000 多个标记，其中大多数输入将为零。请记住，在基于树的学习器中，它要做出“向左还是向右”的决定，这取决于特征类型。在词袋示例中，我们可以将特征计数为真或假（即，文档是否具有该术语）或术语的出现次数（即，文档具有该术语的次数）。对于我们树中的每个后续分支，算法必须考虑所有这些特征（或者至少考虑特征数量的平方根，例如在随机森林的情况下），这可能是非常宽泛和稀疏的，并且做出影响整体结果的决定。

幸运的是，您将要学习 Spark 如何处理这种类型的维度和稀疏性，以及我们可以在下一节中采取的一些步骤来减少特征数量。

# 文本标记化

要执行特征提取，我们仍然需要提供组成原始文本的单词标记。但是，我们不需要考虑所有的单词或字符。例如，我们可以直接跳过标点符号或不重要的单词，如介词或冠词，这些单词大多不会带来任何有用的信息。

此外，常见做法是将标记规范化为通用表示。这可以包括诸如统一字符（例如，仅使用小写字符，删除变音符号，使用常见字符编码，如 utf8 等）或将单词放入通用形式（所谓的词干提取，例如，“cry”/“cries”/“cried”表示为“cry”）的方法。

在我们的示例中，我们将使用以下步骤执行此过程：

1.  将所有单词转换为小写（“Because”和“because”是相同的单词）。

1.  使用正则表达式函数删除标点符号。

1.  删除停用词。这些基本上是没有上下文意义的禁令和连接词，例如*in*，*at*，*the*，*and*，*etc*，等等，这些词对我们想要分类的评论没有任何上下文意义。

1.  查找在我们的评论语料库中出现次数少于三次的“稀有标记”。

1.  最后，删除所有“稀有标记”。

前述序列中的每个步骤都代表了我们在对文本进行情感分类时的最佳实践。对于您的情况，您可能不希望将所有单词转换为小写（例如，“Python”语言和“python”蛇类是一个重要的区别！）。此外，您的停用词列表（如果选择包含）可能会有所不同，并且会根据您的任务融入更多的业务逻辑。一个收集停用词列表做得很好的网站是[`www.ranks.nl/stopwords`](http://www.ranks.nl/stopwords)。

# 声明我们的停用词列表

在这里，我们可以直接重用 Spark 提供的通用英语停用词列表。但是，我们可以通过我们特定的停用词来丰富它：

```scala
import org.apache.spark.ml.feature.StopWordsRemover 
val stopWords= StopWordsRemover.loadDefaultStopWords("english") ++ Array("ax", "arent", "re")
```

正如前面所述，这是一项非常微妙的任务，严重依赖于您要解决的业务问题。您可能希望在此列表中添加与您的领域相关的术语，这些术语不会帮助预测任务。

声明一个标记器，对评论进行标记，并省略所有停用词和长度太短的单词：

```scala
val *MIN_TOKEN_LENGTH* = 3
val *toTokens*= (minTokenLen: Int, stopWords: Array[String], 
    review: String) =>
      review.split("""\W+""")
            .map(_.toLowerCase.replaceAll("[^\\p{IsAlphabetic}]", ""))
            .filter(w =>w.length>minTokenLen)
            .filter(w => !stopWords.contains(w))
```

让我们逐步查看这个函数，看看它在做什么。它接受单个评论作为输入，然后调用以下函数：

+   `.split("""\W+""")`：这将电影评论文本拆分为仅由字母数字字符表示的标记。

+   `.map(_.toLowerCase.replaceAll("[^\\p{IsAlphabetic}]", ""))`: 作为最佳实践，我们将标记转换为小写，以便在索引时*Java = JAVA = java*。然而，这种统一并不总是成立，你需要意识到将文本数据转换为小写可能会对模型产生的影响。例如，计算语言"Python"转换为小写后是"python"，这也是一种蛇。显然，这两个标记不相同；然而，转换为小写会使它们相同！我们还将过滤掉所有的数字字符。

+   `.filter(w =>w.length>minTokenLen)`: 只保留长度大于指定限制的标记（在我们的例子中，是三个字符）。

+   `.filter(w => !stopWords.contains(w))`: 使用之前声明的停用词列表，我们可以从我们的标记化数据中删除这些术语。

现在我们可以直接将定义的函数应用于评论的语料库：

```scala
import spark.implicits._ 
val toTokensUDF= udf(toTokens.curried(MIN_TOKEN_LENGTH)(stopWords)) 
movieReviews= movieReviews.withColumn("reviewTokens", 
                                      toTokensUDF('reviewText)) 
```

在这种情况下，我们通过调用`udf`标记将函数`toTokens`标记为 Spark 用户定义的函数，这将公共 Scala 函数暴露给在 Spark DataFrame 上下文中使用。之后，我们可以直接将定义的`udf`函数应用于加载的数据集中的`reviewText`列。函数的输出创建了一个名为`reviewTokens`的新列。

我们将`toTokens`和`toTokensUDF`的定义分开，因为在一个表达式中定义它们会更容易。这是一个常见的做法，可以让你在不使用和了解 Spark 基础设施的情况下单独测试`toTokens`方法。

此外，你可以在不一定需要基于 Spark 的不同项目中重用定义的`toTokens`方法。

以下代码找到了所有的稀有标记：

```scala
val RARE_TOKEN = 2
val rareTokens= movieReviews.select("reviewTokens")
               .flatMap(r =>r.getAs[Seq[String]]("reviewTokens"))
               .map((v:String) => (v, 1))
               .groupByKey(t => t._1)
               .reduceGroups((a,b) => (a._1, a._2 + b._2))
               .map(_._2)
               .filter(t => t._2 <RARE_TOKEN)
               .map(_._1)
               .collect()
```

稀有标记的计算是一个复杂的操作。在我们的例子中，输入由包含标记列表的行表示。然而，我们需要计算所有唯一标记及其出现次数。

因此，我们使用`flatMap`方法将结构展平为一个新的数据集，其中每行表示一个标记。

然后，我们可以使用在前几章中使用的相同策略。我们可以为每个单词生成键值对*(word, 1)*。

这对表示了给定单词的出现次数。然后，我们只需将所有具有相同单词的对分组在一起（`groupByKey`方法），并计算代表一组的单词的总出现次数（`reduceGroups`）。接下来的步骤只是过滤掉所有太频繁的单词，最后将结果收集为单词列表。

下一个目标是找到稀有标记。在我们的例子中，我们将考虑出现次数少于三次的每个标记：

```scala
println(s"Rare tokens count: ${rareTokens.size}")
println(s"Rare tokens: ${rareTokens.take(10).mkString(", ")}")
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00095.jpeg)

现在我们有了我们的标记化函数，是时候通过定义另一个 Spark UDF 来过滤出稀有标记了，我们将直接应用于`reviewTokens`输入数据列：

```scala
val rareTokensFilter= (rareTokens: Array[String], tokens: Seq[String]) =>tokens.filter(token => !rareTokens.contains(token)) 
val rareTokensFilterUDF= udf(rareTokensFilter.curried(rareTokens)) 

movieReviews= movieReviews.withColumn("reviewTokens", rareTokensFilterUDF('reviewTokens)) 

println("Movie reviews tokens:") 
movieReviews.show(5) 
```

电影评论的标记如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00096.jpeg)

根据你的特定任务，你可能希望添加或删除一些停用词，或者探索不同的正则表达式模式（例如，使用正则表达式挖掘电子邮件地址是非常常见的）。现在，我们将使用我们拥有的标记构建我们的数据集。

# 还原和词形还原

在 NLP 中一个非常流行的步骤是将单词还原为它们的词根形式。例如，"accounts"和"accounting"都会被还原为"account"，乍一看似乎非常合理。然而，还原会出现以下两个问题，你应该注意：

1\. **过度还原**：这是指还原未能将具有不同含义的两个单词区分开。例如，还原("general," "genetic") = "gene"。

2. **欠词干化**：这是无法将具有相同含义的单词减少到它们的根形式的能力。例如，stem（"jumping"，"jumpiness"）= *jumpi*，但 stem（"jumped"，"jumps"）= "jump"。在这个例子中，我们知道前面的每个术语只是根词"jump"的一个变形；然而，根据您选择使用的词干提取器（最常见的两种词干提取器是 Porter [最古老和最常见]和 Lancaster），您可能会陷入这种错误。

考虑到语料库中单词的过度和不足词干化的可能性，自然语言处理从业者提出了词形还原的概念来帮助解决这些已知问题。单词"lemming"是根据单词的上下文，以*一组相关单词*的规范（词典）形式。例如，lemma（"paying"，"pays"，"paid"）= "pay"。与词干提取类似，词形还原试图将相关单词分组，但它进一步尝试通过它们的词义来分组单词，因为毕竟，相同的两个单词在不同的上下文中可能有完全不同的含义！考虑到本章已经很深入和复杂，我们将避免执行任何词形还原技术，但感兴趣的人可以在[`stanfordnlp.github.io/CoreNLP/`](http://stanfordnlp.github.io/CoreNLP/)上进一步阅读有关这个主题的内容。

# 特征化-特征哈希

现在，是时候将字符串表示转换为数字表示了。我们采用词袋方法；然而，我们使用了一个叫做特征哈希的技巧。让我们更详细地看一下 Spark 如何使用这种强大的技术来帮助我们高效地构建和访问我们的标记数据集。我们使用特征哈希作为词袋的时间高效实现，正如前面所解释的。

在其核心，特征哈希是一种快速和空间高效的方法，用于处理高维数据-在处理文本时很典型-通过将任意特征转换为向量或矩阵中的索引。这最好用一个例子来描述。假设我们有以下两条电影评论：

1.  *电影《好家伙》物有所值。演技精湛！*

1.  *《好家伙》是一部扣人心弦的电影，拥有一流的演员阵容和精彩的情节-所有电影爱好者必看！*

对于这些评论中的每个标记，我们可以应用"哈希技巧"，从而为不同的标记分配一个数字。因此，前面两条评论中唯一标记的集合（在小写+文本处理后）将按字母顺序排列：

```scala
{"acting": 1, "all": 2, "brilliant": 3, "cast": 4, "goodfellas": 5, "great": 6, "lover": 7, "money": 8, "movie": 9, "must": 10, "plot": 11, "riveting": 12, "see": 13, "spent": 14, "well": 15, "with": 16, "worth": 17}
```

然后，我们将应用哈希来创建以下矩阵：

```scala
[[1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1]
[0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0]]
```

特征哈希的矩阵构造如下：

+   行*代表*电影评论编号。

+   列*代表*特征（而不是实际单词！）。特征空间由一系列使用的哈希函数表示。请注意，对于每一行，列的数量是相同的，而不仅仅是一个不断增长的宽矩阵。

+   因此，矩阵中的每个条目（*i，j*）= *k*表示在第*i*行，特征*j*出现*k*次。例如，标记"movie"被哈希到特征 9 上，在第二条评论中出现了两次；因此，矩阵（2，9）= 2。

+   使用的哈希函数会产生间隙。如果哈希函数将一小组单词哈希到大的数字空间中，得到的矩阵将具有很高的稀疏性。

+   重要的一点是要考虑的是哈希碰撞的概念，即两个不同的特征（在这种情况下是标记）被哈希到我们的特征矩阵中的相同索引号。防范这种情况的方法是选择大量要哈希的特征，这是我们可以在 Spark 中控制的参数（Spark 中的默认设置是 2²⁰〜100 万个特征）。

现在，我们可以使用 Spark 的哈希函数，它将每个标记映射到一个哈希索引，这将组成我们的特征向量/矩阵。与往常一样，我们将从我们需要的类的导入开始，然后将创建哈希的特征的默认值更改为大约 4096（2¹²）。

在代码中，我们将使用 Spark ML 包中的`HashingTF`转换器（您将在本章后面学习更多关于转换的内容）。它需要输入和输出列的名称。对于我们的数据集`movieReviews`，输入列是`reviewTokens`，其中包含在前面步骤中创建的标记。转换的结果存储在一个名为`tf`的新列中：

```scala
val hashingTF= new HashingTF hashingTF.setInputCol("reviewTokens")
                   .setOutputCol("tf")
                   .setNumFeatures(1 <<12) // 2¹²
                   .setBinary(false)
val tfTokens= hashingTF.transform(movieReviews)
println("Vectorized movie reviews:")
tfTokens.show(5)
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00097.jpeg)

调用转换后，生成的`tfTokens`数据集中除了原始数据之外，还包含一个名为`tf`的新列，该列保存了每个输入行的`org.apache.spark.ml.linalg`实例。向量。在我们的情况下，向量是稀疏向量（因为哈希空间远大于唯一标记的数量）。

# 术语频率-逆文档频率（TF-IDF）加权方案

现在，我们将使用 Spark ML 应用一个非常常见的加权方案，称为 TF-IDF，将我们的标记化评论转换为向量，这将成为我们机器学习模型的输入。这种转换背后的数学相对简单：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00098.jpeg)

对于每个标记：

1.  找到给定文档（在我们的情况下是电影评论）内的术语频率。

1.  将此计数乘以查看标记在所有文档中出现的频率的对数的逆文档频率（通常称为语料库）。

1.  取逆是有用的，因为它将惩罚在文档中出现太频繁的标记（例如，“电影”），并提升那些不太频繁出现的标记。

现在，我们可以根据先前解释的逆文档频率公式来缩放术语。首先，我们需要计算一个模型-关于如何缩放术语频率的规定。在这种情况下，我们使用 Spark `IDF` 估计器基于前一步`hashingTF`生成的输入数据创建模型：

```scala
import org.apache.spark.ml.feature.IDF
val idf= new IDF idf.setInputCol(hashingTF.getOutputCol)
                    .setOutputCol("tf-idf")
val idfModel= idf.fit(tfTokens)
```

现在，我们将构建一个 Spark 估计器，该估计器在输入数据（=上一步转换的输出）上进行了训练（拟合）。IDF 估计器计算单个标记的权重。有了模型，就可以将其应用于包含在拟合期间定义的列的任何数据：

```scala
val tfIdfTokens= idfModel.transform(tfTokens)
println("Vectorized and scaled movie reviews:")
tfIdfTokens.show(5)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00099.jpeg)

让我们更详细地看一下单个行和`hashingTF`和`IDF`输出之间的差异。这两个操作都产生了相同长度的稀疏向量。我们可以查看非零元素，并验证这两行在相同位置包含非零值：

```scala
import org.apache.spark.ml.linalg.Vector
val vecTf= tfTokens.take(1)(0).getAsVector.toSparse
val vecTfIdf= tfIdfTokens.take(1)(0).getAsVector.toSparse
println(s"Both vectors contains the same layout of non-zeros: ${java.util.Arrays.equals(vecTf.indices, vecTfIdf.indices)}")
```

我们还可以打印一些非零值：

```scala
println(s"${vecTf.values.zip(vecTfIdf.values).take(5).mkString("\n")}")
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00100.jpeg)

您可以直接看到，在句子中具有相同频率的标记根据它们在所有句子中的频率而产生不同的分数。

# 让我们进行一些（模型）训练！

此时，我们已经对文本数据进行了数值表示，以简单的方式捕捉了评论的结构。现在是建模的时候了。首先，我们将选择需要用于训练的列，并拆分生成的数据集。我们将保留数据集中生成的`row_id`列。但是，我们不会将其用作输入特征，而只会将其用作简单的唯一行标识符：

```scala
valsplits = tfIdfTokens.select("row_id", "label", idf.getOutputCol).randomSplit(Array(0.7, 0.1, 0.1, 0.1), seed = 42)
val(trainData, testData, transferData, validationData) = (splits(0), splits(1), splits(2), splits(3))
Seq(trainData, testData, transferData, validationData).foreach(_.cache())
```

请注意，我们已经创建了数据的四个不同子集：训练数据集、测试数据集、转移数据集和最终验证数据集。转移数据集将在本章后面进行解释，但其他所有内容应该已经非常熟悉了。

此外，缓存调用很重要，因为大多数算法将迭代地查询数据集数据，我们希望避免重复评估所有数据准备操作。

# Spark 决策树模型

首先，让我们从一个简单的决策树开始，并对一些超参数进行网格搜索。我们将遵循第二章中的代码，*探测暗物质：希格斯玻色子粒子*来构建我们的模型，这些模型经过训练以最大化 AUC 统计量。然而，我们将不再使用 MLlib 库中的模型，而是采用 Spark ML 包中的模型。在后面需要将模型组合成管道时，使用 ML 包的动机将更加清晰。然而，在下面的代码中，我们将使用`DecisionTreeClassifier`，将其拟合到`trainData`，为`testData`生成预测，并借助`BinaryClassificationEvaluato`评估模型的 AUC 性能：

```scala
import org.apache.spark.ml.classification.DecisionTreeClassifier
import org.apache.spark.ml.classification.DecisionTreeClassificationModel
import org.apache.spark.ml.evaluation.BinaryClassificationEvaluator
import java.io.File
val dtModelPath = s" $ MODELS_DIR /dtModel"
val dtModel= {
  val dtGridSearch = for (
    dtImpurity<- Array("entropy", "gini");
    dtDepth<- Array(3, 5))
    yield {
      println(s"Training decision tree: impurity $dtImpurity,
              depth: $dtDepth")
      val dtModel = new DecisionTreeClassifier()
          .setFeaturesCol(idf.getOutputCol)
          .setLabelCol("label")
          .setImpurity(dtImpurity)
          .setMaxDepth(dtDepth)
          .setMaxBins(10)
          .setSeed(42)
          .setCacheNodeIds(true)
          .fit(trainData)
      val dtPrediction = dtModel.transform(testData)
      val dtAUC = new BinaryClassificationEvaluator().setLabelCol("label")
          .evaluate(dtPrediction)
      println(s" DT AUC on test data: $dtAUC")
      ((dtImpurity, dtDepth), dtModel, dtAUC)
    }
    println(dtGridSearch.sortBy(-_._3).take(5).mkString("\n"))
    val bestModel = dtGridSearch.sortBy(-_._3).head._2
    bestModel.write.overwrite.save(dtModelPath)
    bestModel
  }
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00101.jpeg)

在选择最佳模型之后，我们将把它写入文件。这是一个有用的技巧，因为模型训练可能会耗费时间和资源，下一次，我们可以直接从文件中加载模型，而不是重新训练它：

```scala
val dtModel= if (new File(dtModelPath).exists()) {
  DecisionTreeClassificationModel.load(dtModelPath)
} else { /* do training */ }
```

# Spark 朴素贝叶斯模型

接下来，让我们来使用 Spark 的朴素贝叶斯实现。作为提醒，我们故意避免深入算法本身，因为这在许多机器学习书籍中已经涵盖过；相反，我们将专注于模型的参数，最终，我们将在本章后面的 Spark 流应用中“部署”这些模型。

Spark 对朴素贝叶斯的实现相对简单，我们只需要记住一些参数。它们主要如下：

+   **getLambda**：有时被称为“加法平滑”或“拉普拉斯平滑”，这个参数允许我们平滑观察到的分类变量的比例，以创建更均匀的分布。当你尝试预测的类别数量非常低，而你不希望由于低采样而错过整个类别时，这个参数尤为重要。输入 lambda 参数可以通过引入一些类别的最小表示来“帮助”你解决这个问题。

+   **getModelType**：这里有两个选项：“*multinomial*”（默认）或“*Bernoulli*”。*Bernoulli*模型类型会假设我们的特征是二进制的，在我们的文本示例中将是“*评论中是否有单词 _____？是或否？*”然而，*multinomial*模型类型采用离散的词频。另一个目前在 Spark 中朴素贝叶斯中没有实现但你需要知道的模型类型是高斯模型类型。这使我们的模型特征可以来自正态分布。

考虑到在这种情况下我们只有一个超参数要处理，我们将简单地使用我们的 lamda 的默认值，但是你也可以尝试网格搜索方法以获得最佳结果：

```scala
import org.apache.spark.ml.classification.{NaiveBayes, NaiveBayesModel}
val nbModelPath= s"$MODELS_DIR/nbModel"
val nbModel= {
  val model = new NaiveBayes()
      .setFeaturesCol(idf.getOutputCol)
      .setLabelCol("label")
      .setSmoothing(1.0)
      .setModelType("multinomial") // Note: input data are multinomial
      .fit(trainData)
  val nbPrediction = model.transform(testData)
  val nbAUC = new BinaryClassificationEvaluator().setLabelCol("label")
                 .evaluate(nbPrediction)
  println(s"Naive Bayes AUC: $nbAUC")
  model.write.overwrite.save(nbModelPath)
  model
}
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00102.jpeg)

比较不同模型在相同输入数据集上的性能是很有趣的。通常情况下，即使是简单的朴素贝叶斯算法也非常适合文本分类任务。部分原因在于该算法的第一个形容词：“朴素”。具体来说，这个特定的算法假设我们的特征——在这种情况下是全局加权的词项频率——是相互独立的。在现实世界中这是真的吗？更常见的情况是这个假设经常被违反；然而，这个算法仍然可以表现得和更复杂的模型一样好，甚至更好。

# Spark 随机森林模型

接下来，我们将转向我们的随机森林算法，正如你从前面的章节中记得的那样，它是各种决策树的集成，我们将再次进行网格搜索，交替使用不同的深度和其他超参数，这将是熟悉的：

```scala
import org.apache.spark.ml.classification.{RandomForestClassifier, RandomForestClassificationModel}
val rfModelPath= s"$MODELS_DIR/rfModel"
val rfModel= {
  val rfGridSearch = for (
    rfNumTrees<- Array(10, 15);
    rfImpurity<- Array("entropy", "gini");
    rfDepth<- Array(3, 5))
    yield {
      println( s"Training random forest: numTrees: $rfNumTrees, 
              impurity $rfImpurity, depth: $rfDepth")
     val rfModel = new RandomForestClassifier()
         .setFeaturesCol(idf.getOutputCol)
         .setLabelCol("label")
         .setNumTrees(rfNumTrees)
         .setImpurity(rfImpurity)
         .setMaxDepth(rfDepth)
         .setMaxBins(10)
         .setSubsamplingRate(0.67)
         .setSeed(42)
         .setCacheNodeIds(true)
         .fit(trainData)
     val rfPrediction = rfModel.transform(testData)
     val rfAUC = new BinaryClassificationEvaluator()
                 .setLabelCol("label")
                 .evaluate(rfPrediction)
     println(s" RF AUC on test data: $rfAUC")
     ((rfNumTrees, rfImpurity, rfDepth), rfModel, rfAUC)
   }
   println(rfGridSearch.sortBy(-_._3).take(5).mkString("\n"))
   val bestModel = rfGridSearch.sortBy(-_._3).head._2 
   // Stress that the model is minimal because of defined gird space^
   bestModel.write.overwrite.save(rfModelPath)
   bestModel
}
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00103.jpeg)

从我们的网格搜索中，我们看到的最高 AUC 是`0.769`。

# Spark GBM 模型

最后，我们将继续使用**梯度提升机**（**GBM**），这将是我们模型集成中的最终模型。请注意，在之前的章节中，我们使用了 H2O 的 GBM 版本，但现在，我们将坚持使用 Spark，并使用 Spark 的 GBM 实现如下：

```scala
import org.apache.spark.ml.classification.{GBTClassifier, GBTClassificationModel}
val gbmModelPath= s"$MODELS_DIR/gbmModel"
val gbmModel= {
  val model = new GBTClassifier()
      .setFeaturesCol(idf.getOutputCol)
      .setLabelCol("label")
      .setMaxIter(20)
      .setMaxDepth(6)
      .setCacheNodeIds(true)
      .fit(trainData)
  val gbmPrediction = model.transform(testData)
  gbmPrediction.show()
  val gbmAUC = new BinaryClassificationEvaluator()
      .setLabelCol("label")
      .setRawPredictionCol(model.getPredictionCol)
      .evaluate(gbmPrediction)
  println(s" GBM AUC on test data: $gbmAUC")
  model.write.overwrite.save(gbmModelPath)
  model
}
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00104.jpeg)

现在，我们已经训练了四种不同的学习算法：（单个）决策树、随机森林、朴素贝叶斯和梯度提升机。每个模型提供了不同的 AUC，如表中所总结的。我们可以看到表现最好的模型是随机森林，其次是 GBM。然而，公平地说，我们并没有对 GBM 模型进行详尽的搜索，也没有使用通常建议的高数量的迭代：

| 决策树 | 0.659 |
| --- | --- |
| 朴素贝叶斯 | 0.484 |
| 随机森林 | 0.769 |
| GBM | 0.755 |

# 超级学习者模型

现在，我们将结合所有这些算法的预测能力，借助神经网络生成一个“超级学习者”，该神经网络将每个模型的预测作为输入，然后尝试给出更好的预测，考虑到各个单独训练模型的猜测。在高层次上，架构会看起来像这样：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00105.jpeg)

我们将进一步解释构建“超级学习者”的直觉和这种方法的好处，并教您如何构建您的 Spark 流应用程序，该应用程序将接收您的文本（即，您将写的电影评论）并将其通过每个模型的预测引擎。使用这些预测作为输入到您的神经网络，我们将利用各种算法的综合能力产生积极或消极的情绪。

# 超级学习者

在前面的章节中，我们训练了几个模型。现在，我们将使用深度学习模型将它们组合成一个称为超级学习者的集成。构建超级学习者的过程很简单（见前面的图）：

1.  选择基本算法（例如，GLM、随机森林、GBM 等）。

1.  选择一个元学习算法（例如，深度学习）。

1.  在训练集上训练每个基本算法。

1.  对这些学习者进行 K 折交叉验证，并收集每个基本算法的交叉验证预测值。

1.  从每个 L 基本算法中交叉验证预测的 N 个值可以组合成一个新的 NxL 矩阵。这个矩阵连同原始响应向量被称为“一级”数据。

1.  在一级数据上训练元学习算法。

1.  超级学习者（或所谓的“集成模型”）由 L 个基本学习模型和元学习模型组成，然后可以用于在测试集上生成预测。

集成的关键技巧是将一组不同的强学习者组合在一起。我们已经在随机森林算法的上下文中讨论了类似的技巧。

Erin LeDell 的博士论文包含了关于超级学习者及其可扩展性的更详细信息。您可以在[`www.stat.berkeley.edu/~ledell/papers/ledell-phd-thesis.pdf`](http://www.stat.berkeley.edu/~ledell/papers/ledell-phd-thesis.pdf)找到它。

在我们的示例中，我们将通过跳过交叉验证但使用单个留出数据集来简化整个过程。重要的是要提到，这不是推荐的方法！

作为第一步，我们使用训练好的模型和一个转移数据集来获得预测，并将它们组合成一个新的数据集，通过实际标签来增强它。

这听起来很容易；然而，我们不能直接使用*DataFrame#withColumn*方法并从不同数据集的多个列创建一个新的`DataFrame`，因为该方法只接受左侧`DataFrame`或常量列的列。

然而，我们已经通过为每一行分配一个唯一的 ID 来为这种情况准备了数据集。在这种情况下，我们将使用它，并根据`row_id`来合并各个模型的预测。我们还需要重命名每个模型预测列，以便在数据集中唯一标识模型预测：

```scala
import org.apache.spark.ml.PredictionModel 
import org.apache.spark.sql.DataFrame 

val models = Seq(("NB", nbModel), ("DT", dtModel), ("RF", rfModel), ("GBM", gbmModel)) 
def mlData(inputData: DataFrame, responseColumn: String, baseModels: Seq[(String, PredictionModel[_, _])]): DataFrame= { 
baseModels.map{ case(name, model) => 
model.transform(inputData) 
     .select("row_id", model.getPredictionCol ) 
     .withColumnRenamed("prediction", s"${name}_prediction") 
  }.reduceLeft((a, b) =>a.join(b, Seq("row_id"), "inner")) 
   .join(inputData.select("row_id", responseColumn), Seq("row_id"), "inner") 
} 
val mlTrainData= mlData(transferData, "label", models).drop("row_id") 
mlTrainData.show() 
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00106.jpeg)

该表由模型的预测组成，并由实际标签注释。看到个体模型在预测值上的一致性/不一致性是很有趣的。

我们可以使用相同的转换来准备超级学习器的验证数据集：

```scala
val mlTestData = mlData(validationData, "label", models).drop("row_id") 
```

现在，我们可以构建我们的元学习算法。在这种情况下，我们将使用 H2O 机器学习库提供的深度学习算法。但是，它需要一点准备-我们需要将准备好的训练和测试数据发布为 H2O 框架：

```scala
import org.apache.spark.h2o._ 
val hc= H2OContext.getOrCreate(sc) 
val mlTrainHF= hc.asH2OFrame(mlTrainData, "metaLearnerTrain") 
val mlTestHF= hc.asH2OFrame(mlTestData, "metaLearnerTest") 
```

我们还需要将`label`列转换为分类列。这是必要的；否则，H2O 深度学习算法将执行回归，因为`label`列是数值型的：

```scala
importwater.fvec.Vec
val toEnumUDF= (name: String, vec: Vec) =>vec.toCategoricalVec
mlTrainHF(toEnumUDF, 'label).update()
mlTestHF(toEnumUDF, 'label).update()
```

现在，我们可以构建一个 H2O 深度学习模型。我们可以直接使用该算法的 Java API；但是，由于我们希望将所有步骤组合成一个单独的 Spark 管道，因此我们将利用一个暴露 Spark 估计器 API 的包装器：

```scala
val metaLearningModel= new H2ODeepLearning()(hc, spark.sqlContext)
      .setTrainKey(mlTrainHF.key)
      .setValidKey(mlTestHF.key)
      .setResponseColumn("label")
      .setEpochs(10)
      .setHidden(Array(100, 100, 50))
      .fit(null)
```

由于我们直接指定了验证数据集，我们可以探索模型的性能：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00107.jpeg)

或者，我们可以打开 H2O Flow UI（通过调用`hc.openFlow`）并以可视化形式探索其性能：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00108.jpeg)

您可以轻松地看到该模型在验证数据集上的 AUC 为 0.868619-高于所有个体模型的 AUC 值。

# 将所有转换组合在一起

在前一节中，我们使用了 Spark 原语（即 UDF、本地 Spark 算法和 H2O 算法）开发了个别步骤。但是，要在未知数据上调用所有这些转换需要大量的手动工作。因此，Spark 引入了管道的概念，主要受到 Python scikit 管道的启发（[`scikit-learn.org/stable/modules/generated/sklearn.pipeline.Pipeline.html`](http://scikit-learn.org/stable/modules/generated/sklearn.pipeline.Pipeline.html)）。

要了解 Python 背后的设计决策更多信息，我们建议您阅读 Lars Buitinck 等人的优秀论文"API design for machine learning software: experiences from the scikit-learn project"（[`arxiv.org/abs/1309.0238`](https://arxiv.org/abs/1309.0238)）。

管道由由估计器和转换器表示的阶段组成：

+   **估计器**：这些是核心元素，公开了一个创建模型的 fit 方法。大多数分类和回归算法都表示为估计器。

+   **转换器**：这些将输入数据集转换为新数据集。转换器公开了`transform`方法，该方法实现了转换的逻辑。转换器可以生成单个或多个向量。大多数估计器生成的模型都是转换器-它们将输入数据集转换为表示预测的新数据集。本节中使用的 TF 转换器就是一个例子。

管道本身公开了与估计器相同的接口。它有 fit 方法，因此可以进行训练并生成"管道模型"，该模型可用于数据转换（它具有与转换器相同的接口）。因此，管道可以按层次结合在一起。此外，单个管道阶段按顺序调用；但是，它们仍然可以表示有向无环图（例如，一个阶段可以有两个输入列，每个列由不同的阶段产生）。在这种情况下，顺序必须遵循图的拓扑排序。

在我们的示例中，我们将把所有的转换组合在一起。然而，我们不会定义一个训练管道（即，一个将训练所有模型的管道），而是使用已经训练好的模型来设置管道阶段。我们的动机是定义一个可以用来对新的电影评论进行评分的管道。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00109.jpeg)

因此，让我们从我们示例的开始开始-我们在输入数据上应用的第一个操作是一个简单的分词器。它是由一个 Scala 函数定义的，我们将其包装成了 Spark UDF 的形式。然而，为了将其作为管道的一部分使用，我们需要将定义的 Scala 函数包装成一个转换。Spark 没有提供任何简单的包装器来做到这一点，因此需要从头开始定义一个通用的转换。我们知道我们将把一个列转换成一个新列。在这种情况下，我们可以使用`UnaryTransformer`，它确切地定义了一对一的列转换。我们可以更加通用一些，定义一个 Scala 函数（也就是 Spark UDFs）的通用包装器：

```scala
import org.apache.spark.ml.{Pipeline, UnaryTransformer} 
import org.apache.spark.sql.types._ 
import org.apache.spark.ml.param.ParamMap
import org.apache.spark.ml.util.{MLWritable, MLWriter} 

class UDFTransformerT, U 
extendsUnaryTransformer[T, U, UDFTransformer[T, U]] with MLWritable { 

override protected defcreateTransformFunc: T =>U = f 

override protected defvalidateInputType(inputType: DataType): Unit = require(inputType == inType) 

override protected defoutputDataType: DataType = outType 

override defwrite: MLWriter = new MLWriter { 
override protected defsaveImpl(path: String): Unit = {} 
 } 
} 
```

`UDFTransformer`类包装了一个函数`f`，该函数接受一个通用类型`T`，并产生类型`U`。在 Spark 数据集级别上，它将一个输入列（参见`UnaryTransformer`）的类型`inType`转换为一个新的输出列（同样，该字段由`UnaryTransformer`定义）的`outType`类型。该类还具有特质`MLWritable`的虚拟实现，支持将转换器序列化到文件中。

现在，我们只需要定义我们的分词器转换器：

```scala
val tokenizerTransformer= new UDFTransformer[String, Array[String]](
  "tokenizer", toTokens.curried(MIN_TOKEN_LENGTH)(stopWords),
  StringType, new ArrayType(StringType, true))
```

定义的转换器接受一个字符串列（即电影评论），并产生一个包含表示电影评论标记的字符串数组的新列。该转换器直接使用了我们在本章开头使用的`toTokens`函数。

接下来的转换应该是删除稀有单词。在这种情况下，我们将使用与上一步类似的方法，并利用定义的`UDFTransformer`函数：

```scala
val rareTokensFilterTransformer= new UDFTransformer[Seq[String], Seq[String]](
  "rareWordsRemover",
  rareTokensFilter.curried(rareTokens),
  newArrayType(StringType, true), new ArrayType(StringType, true))
```

这个转换器接受一个包含标记数组的列，并产生一个包含过滤后标记数组的新列。它使用了已经定义的`rareTokensFilter` Scala 函数。

到目前为止，我们还没有指定任何输入数据依赖关系，包括输入列的名称。我们将把它留到最终的管道定义中。

接下来的步骤包括使用`TF`方法进行向量化，将字符串标记哈希成一个大的数字空间，然后基于构建的`IDF`模型进行转换。这两个转换已经以期望的形式定义好了-第一个`hashingTF`转换已经是一个将一组标记转换为数值向量的转换器，第二个`idfModel`接受数值向量并根据计算的系数对其进行缩放。

这些步骤为训练好的二项模型提供了输入。每个基础模型代表一个产生多个新列的转换器，例如预测、原始预测和概率。然而，重要的是要提到，并非所有模型都提供完整的列集。例如，Spark GBM 目前（Spark 版本 2.0.0）只提供预测列。尽管如此，对于我们的示例来说已经足够了。

生成预测后，我们的数据集包含许多列；例如，输入列、带有标记的列、转换后的标记等等。然而，为了应用生成的元学习器，我们只需要基础模型生成的预测列。因此，我们将定义一个列选择器转换，删除所有不必要的列。在这种情况下，我们有一个接受 N 列并产生一个新的 M 列数据集的转换。因此，我们不能使用之前定义的`UnaryTransformer`，我们需要定义一个名为`ColumnSelector`的新的特定转换：

```scala
import org.apache.spark.ml.Transformer 
class ColumnSelector(override valuid: String, valcolumnsToSelect: Array[String]) extends Transformer with MLWritable { 

  override deftransform(dataset: Dataset[_]): DataFrame= { 
    dataset.select(columnsToSelect.map(dataset.col): _*) 
  } 

  override deftransformSchema(schema: StructType): StructType = { 
    StructType(schema.fields.filter(col=>columnsToSelect
                            .contains(col.name))) 
  } 

  override defcopy(extra: ParamMap): ColumnSelector = defaultCopy(extra) 

  override defwrite: MLWriter = new MLWriter { 
    override protected defsaveImpl(path: String): Unit = {} 
  } 
} 
```

`ColumnSelector`表示一个通用的转换器，它从输入数据集中仅选择给定的列。重要的是要提到整体的两阶段概念-第一阶段转换模式（即，与每个数据集相关联的元数据）和第二阶段转换实际数据集。这种分离允许 Spark 在调用实际数据转换之前对转换器进行早期检查，以查找不兼容之处。

我们需要通过创建`columnSelector`的实例来定义实际的列选择器转换器-请注意指定要保留的正确列：

```scala
val columnSelector= new ColumnSelector( 
  "columnSelector",  Array(s"DT_${dtModel.getPredictionCol}", 
  s"NB_${nbModel.getPredictionCol}", 
  s"RF_${rfModel.getPredictionCol}", 
  s"GBM_${gbmModel.getPredictionCol}") 
```

在这一点上，我们的转换器已经准备好组成最终的“超级学习”管道。管道的 API 很简单-它接受按顺序调用的单个阶段。然而，我们仍然需要指定单个阶段之间的依赖关系。大多数情况下，依赖关系是由输入和输出列名描述的：

```scala
val superLearnerPipeline = new Pipeline() 
 .setStages(Array( 
// Tokenize 
tokenizerTransformer 
     .setInputCol("reviewText") 
     .setOutputCol("allReviewTokens"), 
// Remove rare items 
rareTokensFilterTransformer 
     .setInputCol("allReviewTokens") 
     .setOutputCol("reviewTokens"), 
hashingTF, 
idfModel, 
dtModel 
     .setPredictionCol(s"DT_${dtModel.getPredictionCol}") 
     .setRawPredictionCol(s"DT_${dtModel.getRawPredictionCol}") 
     .setProbabilityCol(s"DT_${dtModel.getProbabilityCol}"), 
nbModel 
     .setPredictionCol(s"NB_${nbModel.getPredictionCol}") 
     .setRawPredictionCol(s"NB_${nbModel.getRawPredictionCol}") 
     .setProbabilityCol(s"NB_${nbModel.getProbabilityCol}"), 
rfModel 
     .setPredictionCol(s"RF_${rfModel.getPredictionCol}") 
     .setRawPredictionCol(s"RF_${rfModel.getRawPredictionCol}") 
     .setProbabilityCol(s"RF_${rfModel.getProbabilityCol}"), 
gbmModel// Note: GBM does not have full API of PredictionModel 
.setPredictionCol(s"GBM_${gbmModel.getPredictionCol}"), 
columnSelector, 
metaLearningModel 
 )) 
```

有一些值得一提的重要概念：

+   `tokenizerTransformer`和`rareTokensFilterTransformer`通过列`allReviewTokens`连接-第一个是列生产者，第二个是列消费者。

+   `dtModel`、`nbModel`、`rfModel`和`gbmModel`模型都将相同的输入列定义为`idf.getOutputColumn`。在这种情况下，我们有效地使用了计算 DAG，它是按拓扑顺序排列成一个序列

+   所有模型都具有相同的输出列（在 GBM 的情况下有一些例外），由于管道期望列的唯一名称，因此不能将所有模型的输出列一起追加到结果数据集中。因此，我们需要通过调用`setPredictionCol`、`setRawPredictionCol`和`setProbabilityCol`来重命名模型的输出列。重要的是要提到，GBM 目前不会产生原始预测和概率列。

现在，我们可以拟合管道以获得管道模型。实际上，这是一个空操作，因为我们的管道只由转换器组成。然而，我们仍然需要调用`fit`方法：

```scala
val superLearnerModel= superLearnerPipeline.fit(pos)
```

哇，我们有了我们的超级学习模型，由多个 Spark 模型组成，并由 H2O 深度学习模型编排。现在是使用模型进行预测的时候了！

# 使用超级学习模型

模型的使用很简单-我们需要提供一个名为`reviewText`的单列数据集，并用`superLearnerModel`进行转换：

```scala
val review = "Although I love this movie, I can barely watch it, it is so real....."
val reviewToScore= sc.parallelize(Seq(review)).toDF("reviewText")
val reviewPrediction= superLearnerModel.transform(reviewToScore)
```

返回的预测`reviewPrediction`是一个具有以下结构的数据集：

```scala
reviewPrediction.printSchema()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00110.jpeg)

第一列包含基于 F1 阈值决定的预测值。列`p0`和`p1`表示各个预测类别的概率。

如果我们探索返回的数据集的内容，它包含一行：

```scala
reviewPrediction.show()
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00111.jpeg)

# 总结

本章演示了三个强大的概念：文本处理、Spark 管道和超级学习者。

文本处理是一个强大的概念，正在等待被行业广泛采用。因此，我们将在接下来的章节中深入探讨这个主题，并看看自然语言处理的其他方法。

对于 Spark 管道也是一样，它们已经成为 Spark 的固有部分和 Spark ML 包的核心。它们提供了一种优雅的方式，在训练和评分时重复使用相同的概念。因此，我们也希望在接下来的章节中使用这个概念。

最后，通过超级学习者，也就是集成学习，您学会了如何通过元学习器的帮助从多个模型中获益的基本概念。这提供了一种简单但强大的方式来构建强大的学习者，这些学习者仍然足够简单易懂。


# 第五章：用于预测和聚类的 Word2vec

在前几章中，我们涵盖了一些基本的 NLP 步骤，比如分词、停用词移除和特征创建，通过创建一个**词频-逆文档频率**（**TF-IDF**）矩阵，我们执行了一个监督学习任务，预测电影评论的情感。在本章中，我们将扩展我们之前的例子，现在包括由 Google 研究人员 Tomas Mikolov 和 Ilya Sutskever 推广的词向量的惊人力量，他们在论文*Distributed Representations of Words and Phrases and their Compositionality*中提出。

我们将从词向量背后的动机进行简要概述，借鉴我们对之前 NLP 特征提取技术的理解，然后解释代表 word2vec 框架的一系列算法的概念（确实，word2vec 不仅仅是一个单一的算法）。然后，我们将讨论 word2vec 的一个非常流行的扩展，称为 doc2vec，我们在其中对整个文档进行*向量化*，转换为一个固定长度的 N 个数字的数组。我们将进一步研究这个极其流行的 NLP 领域，或认知计算研究。接下来，我们将把 word2vec 算法应用到我们的电影评论数据集中，检查生成的词向量，并通过取个别词向量的平均值来创建文档向量，以执行一个监督学习任务。最后，我们将使用这些文档向量来运行一个聚类算法，看看我们的电影评论向量有多好地聚集在一起。

词向量的力量是一个爆炸性的研究领域，谷歌和 Facebook 等公司都在这方面进行了大量投资，因为它具有对个别单词的语义和句法含义进行编码的能力，我们将很快讨论。不是巧合的是，Spark 实现了自己的 word2vec 版本，这也可以在谷歌的 Tensorflow 库和 Facebook 的 Torch 中找到。最近，Facebook 宣布了一个名为 deep text 的新的实时文本处理，使用他们预训练的词向量，他们展示了他们对这一惊人技术的信念以及它对他们的业务应用产生的或正在产生的影响。然而，在本章中，我们将只涵盖这个激动人心领域的一小部分，包括以下内容：

+   解释 word2vec 算法

+   word2vec 思想的泛化，导致 doc2vec

+   两种算法在电影评论数据集上的应用

# 词向量的动机

与我们在上一章中所做的工作类似，传统的 NLP 方法依赖于将通过分词创建的个别单词转换为计算机算法可以学习的格式（即，预测电影情感）。这需要我们将*N*个标记的单个评论转换为一个固定的表示，通过创建一个 TF-IDF 矩阵。这样做在*幕后*做了两件重要的事情：

1.  个别的单词被分配了一个整数 ID（例如，一个哈希）。例如，单词*friend*可能被分配为 39,584，而单词*bestie*可能被分配为 99,928,472。认知上，我们知道*friend*和*bestie*非常相似；然而，通过将这些标记转换为整数 ID，任何相似性的概念都会丢失。

1.  通过将每个标记转换为整数 ID，我们因此失去了标记使用的上下文。这很重要，因为为了理解单词的认知含义，从而训练计算机学习*friend*和*bestie*是相似的，我们需要理解这两个标记是如何使用的（例如，它们各自的上下文）。

考虑到传统 NLP 技术在编码单词的语义和句法含义方面的有限功能，托马斯·米科洛夫和其他研究人员探索了利用神经网络来更好地将单词的含义编码为*N*个数字的向量的方法（例如，向量*好朋友* = [0.574, 0.821, 0.756, ... , 0.156]）。当正确计算时，我们会发现*好朋友*和*朋友*的向量在空间中是接近的，其中接近是指余弦相似度。事实证明，这些向量表示（通常称为*单词嵌入*）使我们能够更丰富地理解文本。

有趣的是，使用单词嵌入还使我们能够学习跨多种语言的相同语义，尽管书面形式有所不同（例如，日语和英语）。例如，电影的日语单词是*eiga*（![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00112.jpeg)）；因此，使用单词向量，这两个单词，*movie*和![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00113.jpeg)*，在向量空间中应该是接近的，尽管它们在外观上有所不同。因此，单词嵌入允许应用程序是语言无关的——这也是为什么这项技术非常受欢迎的另一个原因！

# word2vec 解释

首先要明确的是，word2vec 并不代表*单一*算法，而是一系列试图将单词的语义和句法*含义*编码为*N*个数字的向量的算法（因此，word-to-vector = word2vec）。我们将在本章中深入探讨这些算法的每一个，同时也给您机会阅读/研究文本*向量化*的其他领域，这可能会对您有所帮助。

# 什么是单词向量？

在其最简单的形式中，单词向量仅仅是一种独热编码，其中向量中的每个元素代表词汇中的一个单词，给定的单词被编码为`1`，而所有其他单词元素被编码为`0`。假设我们的词汇表只包含以下电影术语：**爆米花**，**糖果**，**苏打水**，**电影票**和**票房大片**。

根据我们刚刚解释的逻辑，我们可以将术语**电影票**编码如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00114.jpeg)

使用这种简单的编码形式，也就是我们创建词袋矩阵时所做的，我们无法对单词进行有意义的比较（例如，*爆米花是否与苏打水相关；糖果是否类似于电影票？*）。

考虑到这些明显的限制，word2vec 试图通过为单词提供分布式表示来解决这个问题。假设对于每个单词，我们有一个分布式向量，比如说，由 300 个数字表示一个单词，其中我们词汇表中的每个单词也由这 300 个元素中的权重分布来表示。现在，我们的情况将会发生显著变化，看起来会像这样：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00115.jpeg)

现在，鉴于将单词的分布式表示为 300 个数字值，我们可以使用余弦相似度等方法在单词之间进行有意义的比较。也就是说，使用**电影票**和**苏打水**的向量，我们可以确定这两个术语不相关，根据它们的向量表示和它们之间的余弦相似度。这还不是全部！在他们具有突破性的论文中，米科洛夫等人还对单词向量进行了数学函数的运算，得出了一些令人难以置信的发现；特别是，作者向他们的 word2vec 字典提出了以下*数学问题*：

*V(国王) - V(男人) + V(女人) ~ V(皇后)*

事实证明，与传统 NLP 技术相比，这些单词的分布式向量表示在比较问题（例如，A 是否与 B 相关？）方面非常强大，这在考虑到这些语义和句法学习知识是来自观察大量单词及其上下文而无需其他信息时显得更加令人惊讶。也就是说，我们不需要告诉我们的机器*爆米花*是一种食物，名词，单数等等。

这是如何实现的呢？Word2vec 以一种受监督的方式利用神经网络的力量来学习单词的向量表示（这是一项无监督的任务）。如果一开始听起来有点像矛盾，不用担心！通过一些示例，一切都会变得更清晰，首先从**连续词袋**模型开始，通常简称为**CBOW**模型。

# CBOW 模型

首先，让我们考虑一个简单的电影评论，这将成为接下来几节中的基本示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00116.jpeg)

现在，想象我们有一个窗口，它就像一个滑块，包括当前焦点单词（在下图中用红色突出显示），以及焦点单词前后的五个单词（在下图中用黄色突出显示）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00117.jpeg)

黄色的单词形成了围绕当前焦点单词*ideas*的上下文。这些上下文单词作为输入传递到我们的前馈神经网络，每个单词通过单热编码（其他元素被清零）编码，具有一个隐藏层和一个输出层：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00118.jpeg)

在上图中，我们的词汇表的总大小（例如，分词后）由大写 C 表示，我们对上下文窗口中的每个单词进行单热编码--在这种情况下，是焦点单词*ideas*前后的五个单词。在这一点上，我们通过加权和将编码向量传播到我们的隐藏层，就像*正常*的前馈神经网络一样--在这里，我们预先指定了隐藏层中的权重数量。最后，我们将一个 sigmoid 函数应用于单隐藏层到输出层，试图预测当前焦点单词。这是通过最大化观察到焦点单词（*idea*）在其周围单词的上下文（**film**，**with**，**plenty**，**of**，**smart**，**regarding**，**the**，**impact**，**of**和**alien**）的条件概率来实现的。请注意，输出层的大小也与我们最初的词汇表 C 相同。

这就是 word2vec 算法族的有趣特性所在：它本质上是一种无监督学习算法，并依赖于监督学习来学习单词向量。这对于 CBOW 模型和跳字模型都是如此，接下来我们将介绍跳字模型。需要注意的是，在撰写本书时，Spark 的 MLlib 仅包含了 word2vec 的跳字模型。

# 跳字模型

在先前的模型中，我们使用了焦点词前后的单词窗口来预测焦点词。跳字模型采用了类似的方法，但是颠倒了神经网络的架构。也就是说，我们将以焦点词作为输入到我们的网络中，然后尝试使用单隐藏层来预测周围的上下文单词：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00119.jpeg)

正如您所看到的，跳字模型与 CBOW 模型完全相反。网络的训练目标是最小化输出层中所有上下文单词的预测误差之和，在我们的示例中，输入是*ideas*，输出层预测*film*，*with*，*plenty*，*of*，*smart*，*regarding*，*the*，*impact*，*of*和*alien*。

在前一章中，您看到我们使用了一个分词函数，该函数删除了停用词，例如*the*，*with*，*to*等，我们故意没有在这里展示，以便清楚地传达我们的例子，而不让读者迷失。在接下来的示例中，我们将执行与第四章相同的分词函数，*使用 NLP 和 Spark Streaming 预测电影评论*，它将删除停用词。

# 单词向量的有趣玩法

现在我们已经将单词（标记）压缩成数字向量，我们可以对它们进行一些有趣的操作。您可以尝试一些来自原始 Google 论文的经典示例，例如：

+   **数学运算**：正如前面提到的，其中一个经典的例子是*v(国王) - v(男人) + v(女人) ~ v(皇后)*。使用简单的加法，比如*v(软件) + v(工程师)*，我们可以得出一些迷人的关系；以下是一些更多的例子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00120.jpeg)

+   **相似性**：鉴于我们正在处理一个向量空间，我们可以使用余弦相似度来比较一个标记与许多其他标记，以查看相似的标记。例如，与*v(Spark)*相似的单词可能是*v(MLlib)*、*v(scala)*、*v(graphex)*等等。

+   **匹配/不匹配**：给定一个单词列表，哪些单词是不匹配的？例如，*doesn't_match[v(午餐, 晚餐, 早餐, 东京)] == v(东京)*。

+   **A 对 B 就像 C 对？**：根据 Google 的论文，以下是通过使用 word2vec 的 skip-gram 实现可能实现的单词比较列表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00121.jpeg)

# 余弦相似度

通过余弦相似度来衡量单词的相似性/不相似性，这个方法的一个很好的特性是它的取值范围在`-1`和`1`之间。两个单词之间的完全相似将产生一个得分为`1`，没有关系将产生`0`，而`-1`表示它们是相反的。

请注意，word2vec 算法的余弦相似度函数（目前仅在 Spark 中的 CBOW 实现中）已经内置到 MLlib 中，我们很快就会看到。

看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00122.jpeg)

对于那些对其他相似性度量感兴趣的人，最近发表了一项研究，强烈建议使用**Earth-Mover's Distance**（**EMD**），这是一种与余弦相似度不同的方法，需要一些额外的计算，但显示出了有希望的早期结果。

# 解释 doc2vec

正如我们在本章介绍中提到的，有一个 word2vec 的扩展，它编码整个*文档*而不是单个单词。在这种情况下，文档可以是句子、段落、文章、散文等等。毫不奇怪，这篇论文是在原始 word2vec 论文之后发表的，但同样也是由 Tomas Mikolov 和 Quoc Le 合著的。尽管 MLlib 尚未将 doc2vec 引入其算法库，但我们认为数据科学从业者有必要了解这个 word2vec 的扩展，因为它在监督学习和信息检索任务中具有很大的潜力和结果。

与 word2vec 一样，doc2vec（有时称为*段落向量*）依赖于监督学习任务，以学习基于上下文单词的文档的分布式表示。Doc2vec 也是一类算法，其架构将与你在前几节学到的 word2vec 的 CBOW 和 skip-gram 模型非常相似。接下来你会看到，实现 doc2vec 将需要并行训练单词向量和代表我们所谓的*文档*的文档向量。

# 分布式记忆模型

这种特定的 doc2vec 模型与 word2vec 的 CBOW 模型非常相似，算法试图预测一个*焦点单词*，给定其周围的*上下文单词*，但增加了一个段落 ID。可以将其视为另一个帮助预测任务的上下文单词向量，但在我们认为的文档中是恒定的。继续我们之前的例子，如果我们有这个电影评论（我们定义一个文档为一个电影评论），我们的焦点单词是*ideas*，那么我们现在将有以下架构：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00123.jpeg)

请注意，当我们在文档中向下移动并将*焦点单词*从*ideas*更改为*regarding*时，我们的上下文单词显然会改变；然而，**文档 ID：456**保持不变。这是 doc2vec 中的一个关键点，因为文档 ID 在预测任务中被使用：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00124.jpeg)

# 分布式词袋模型

doc2vec 中的最后一个算法是模仿 word2vec 跳字模型，唯一的区别是--我们现在将文档 ID 作为输入，尝试预测文档中*随机抽样*的单词，而不是使用*焦点*单词作为输入。也就是说，我们将完全忽略输出中的上下文单词：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00125.jpeg)

与 word2vec 一样，我们可以使用这些*段落向量*对 N 个单词的文档进行相似性比较，在监督和无监督任务中都取得了巨大成功。以下是 Mikolov 等人在最后两章中使用的相同数据集进行的一些实验！

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00126.jpeg)

信息检索任务（三段，第一段应该*听起来*比第三段更接近第二段）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00127.jpeg)

在接下来的章节中，我们将通过取个别词向量的平均值来创建一个*穷人的文档向量*，以将 n 长度的整个电影评论编码为 300 维的向量。

在撰写本书时，Spark 的 MLlib 没有 doc2vec 的实现；然而，有许多项目正在利用这项技术，这些项目处于孵化阶段，您可以测试。

# 应用 word2vec 并使用向量探索我们的数据

现在您已经对 word2vec、doc2vec 以及词向量的强大功能有了很好的理解，是时候将我们的注意力转向原始的 IMDB 数据集，我们将进行以下预处理：

+   在每个电影评论中按空格拆分单词

+   删除标点符号

+   删除停用词和所有字母数字单词

+   使用我们从上一章的标记化函数，最终得到一个逗号分隔的单词数组

因为我们已经在第四章中涵盖了前面的步骤，*使用 NLP 和 Spark Streaming 预测电影评论*，我们将在本节中快速重现它们。

像往常一样，我们从启动 Spark shell 开始，这是我们的工作环境：

```scala
export SPARKLING_WATER_VERSION="2.1.12" 
export SPARK_PACKAGES=\ 
"ai.h2o:sparkling-water-core_2.11:${SPARKLING_WATER_VERSION},\ 
ai.h2o:sparkling-water-repl_2.11:${SPARKLING_WATER_VERSION},\ 
ai.h2o:sparkling-water-ml_2.11:${SPARKLING_WATER_VERSION},\ 
com.packtpub:mastering-ml-w-spark-utils:1.0.0" 

$SPARK_HOME/bin/spark-shell \ 
        --master 'local[*]' \ 
        --driver-memory 8g \ 
        --executor-memory 8g \ 
        --conf spark.executor.extraJavaOptions=-XX:MaxPermSize=384M \ 
        --conf spark.driver.extraJavaOptions=-XX:MaxPermSize=384M \ 
        --packages "$SPARK_PACKAGES" "$@"
```

在准备好的环境中，我们可以直接加载数据：

```scala
val DATASET_DIR = s"${sys.env.get("DATADIR").getOrElse("data")}/aclImdb/train"
 val FILE_SELECTOR = "*.txt" 

case class Review(label: Int, reviewText: String) 

 val positiveReviews = spark.read.textFile(s"$DATASET_DIR/pos/$FILE_SELECTOR")
     .map(line => Review(1, line)).toDF
 val negativeReviews = spark.read.textFile(s"$DATASET_DIR/neg/$FILE_SELECTOR")
   .map(line => Review(0, line)).toDF
 var movieReviews = positiveReviews.union(negativeReviews)
```

我们还可以定义标记化函数，将评论分割成标记，删除所有常见单词：

```scala
import org.apache.spark.ml.feature.StopWordsRemover
 val stopWords = StopWordsRemover.loadDefaultStopWords("english") ++ Array("ax", "arent", "re")

 val MIN_TOKEN_LENGTH = 3
 val toTokens = (minTokenLen: Int, stopWords: Array[String], review: String) =>
   review.split("""\W+""")
     .map(_.toLowerCase.replaceAll("[^\\p{IsAlphabetic}]", ""))
     .filter(w => w.length > minTokenLen)
     .filter(w => !stopWords.contains(w))
```

所有构建块准备就绪后，我们只需将它们应用于加载的输入数据，通过一个新列`reviewTokens`对它们进行增强，该列保存从评论中提取的单词列表：

```scala

 val toTokensUDF = udf(toTokens.curried(MIN_TOKEN_LENGTH)(stopWords))
 movieReviews = movieReviews.withColumn("reviewTokens", toTokensUDF('reviewText))
```

`reviewTokens`列是 word2vec 模型的完美输入。我们可以使用 Spark ML 库构建它：

```scala
val word2vec = new Word2Vec()
   .setInputCol("reviewTokens")
   .setOutputCol("reviewVector")
   .setMinCount(1)
val w2vModel = word2vec.fit(movieReviews)
```

Spark 实现具有几个额外的超参数：

+   `setMinCount`：这是我们可以创建单词的最小频率。这是另一个处理步骤，以便模型不会在低计数的超级稀有术语上运行。

+   `setNumIterations`：通常，我们看到更多的迭代次数会导致更*准确*的词向量（将这些视为传统前馈神经网络中的时代数）。默认值设置为`1`。

+   `setVectorSize`：这是我们声明向量大小的地方。它可以是任何整数，默认大小为`100`。许多*公共*预训练的单词向量倾向于更大的向量大小；然而，这纯粹取决于应用。

+   `setLearningRate`：就像我们在第二章中学到的*常规*神经网络一样，数据科学家需要谨慎--学习率太低，模型将永远无法收敛。然而，如果学习率太大，就会有风险在网络中得到一组非最优的学习权重。默认值为`0`。

现在我们的模型已经完成，是时候检查一些我们的词向量了！请记住，每当您不确定您的模型可以产生什么值时，总是按*tab*按钮，如下所示：

```scala
w2vModel.findSynonyms("funny", 5).show()

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00128.jpeg)

让我们退一步考虑我们刚刚做的事情。首先，我们将单词*funny*压缩为由 100 个浮点数组成的向量（回想一下，这是 Spark 实现的 word2vec 算法的默认值）。因为我们已经将评论语料库中的所有单词都减少到了相同的分布表示形式，即 100 个数字，我们可以使用余弦相似度进行比较，这就是结果集中的第二个数字所反映的（在这种情况下，最高的余弦相似度是*nutty*一词）*.*

请注意，我们还可以使用`getVectors`函数访问*funny*或字典中的任何其他单词的向量，如下所示：

```scala
w2vModel.getVectors.where("word = 'funny'").show(truncate = false)
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00129.jpeg)

基于这些表示，已经进行了许多有趣的研究，将相似的单词聚类在一起。在本章后面，当我们在下一节执行 doc2vec 的破解版本后，我们将重新讨论聚类。

# 创建文档向量

所以，现在我们可以创建编码单词*含义*的向量，并且我们知道任何给定的电影评论在标记化后是一个由*N*个单词组成的数组，我们可以开始创建一个简易的 doc2vec，方法是取出构成评论的所有单词的平均值。也就是说，对于每个评论，通过对个别单词向量求平均值，我们失去了单词的具体顺序，这取决于您的应用程序的敏感性，可能会产生差异：

*v(word_1) + v(word_2) + v(word_3) ... v(word_Z) / count(words in review)*

理想情况下，人们会使用 doc2vec 的一种变体来创建文档向量；然而，截至撰写本书时，MLlib 尚未实现 doc2vec，因此，我们暂时使用这个简单版本，正如您将看到的那样，它产生了令人惊讶的结果。幸运的是，如果模型包含一个标记列表，Spark ML 实现的 word2vec 模型已经对单词向量进行了平均。例如，我们可以展示短语*funny movie*的向量等于`funny`和`movie`标记的向量的平均值：

```scala
val testDf = Seq(Seq("funny"), Seq("movie"), Seq("funny", "movie")).toDF("reviewTokens")
 w2vModel.transform(testDf).show(truncate=false)
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00130.jpeg)

因此，我们可以通过简单的模型转换准备我们的简易版本 doc2vec：

```scala
val inputData = w2vModel.transform(movieReviews)
```

作为这个领域的从业者，我们有机会与各种文档向量的不同变体一起工作，包括单词平均、doc2vec、LSTM 自动编码器和跳跃思想向量。我们发现，对于单词片段较小的情况，单词的顺序并不重要，简单的单词平均作为监督学习任务效果出奇的好。也就是说，并不是说它不能通过 doc2vec 和其他变体来改进，而是基于我们在各种客户应用程序中看到的许多用例的观察结果。

# 监督学习任务

就像在前一章中一样，我们需要准备训练和验证数据。在这种情况下，我们将重用 Spark API 来拆分数据：

```scala
val trainValidSplits = inputData.randomSplit(Array(0.8, 0.2))
val (trainData, validData) = (trainValidSplits(0), trainValidSplits(1))
```

现在，让我们使用一个简单的决策树和一些超参数进行网格搜索：

```scala
val gridSearch =
for (
     hpImpurity <- Array("entropy", "gini");
     hpDepth <- Array(5, 20);
     hpBins <- Array(10, 50))
yield {
println(s"Building model with: impurity=${hpImpurity}, depth=${hpDepth}, bins=${hpBins}")
val model = new DecisionTreeClassifier()
         .setFeaturesCol("reviewVector")
         .setLabelCol("label")
         .setImpurity(hpImpurity)
         .setMaxDepth(hpDepth)
         .setMaxBins(hpBins)
         .fit(trainData)

val preds = model.transform(validData)
val auc = new BinaryClassificationEvaluator().setLabelCol("label")
         .evaluate(preds)
       (hpImpurity, hpDepth, hpBins, auc)
     }
```

我们现在可以检查结果并显示最佳模型 AUC：

```scala
import com.packtpub.mmlwspark.utils.Tabulizer.table
println(table(Seq("Impurity", "Depth", "Bins", "AUC"),
               gridSearch.sortBy(_._4).reverse,
Map.empty[Int,String]))
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00131.jpeg)

使用这个简单的决策树网格搜索，我们可以看到我们的*简易 doc2vec*产生了 0.7054 的 AUC。让我们还将我们的确切训练和测试数据暴露给 H2O，并尝试使用 Flow UI 运行深度学习算法：

```scala
import org.apache.spark.h2o._
val hc = H2OContext.getOrCreate(sc)
val trainHf = hc.asH2OFrame(trainData, "trainData")
val validHf = hc.asH2OFrame(validData, "validData")
```

现在我们已经成功将我们的数据集发布为 H2O 框架，让我们打开 Flow UI 并运行深度学习算法：

```scala
hc.openFlow()
```

首先，请注意，如果我们运行`getFrames`命令，我们将看到我们无缝从 Spark 传递到 H2O 的两个 RDD：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00132.jpeg)

我们需要通过单击 Convert to enum 将标签列的类型从数值列更改为分类列，对两个框架都进行操作：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00133.jpeg)

接下来，我们将运行一个深度学习模型，所有超参数都设置为默认值，并将第一列设置为我们的标签：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00134.jpeg)

如果您没有明确创建训练/测试数据集，您还可以使用先前的*nfolds*超参数执行*n 折交叉验证*：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00135.jpeg)

运行模型训练后，我们可以点击“查看”查看训练和验证数据集上的 AUC：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00136.jpeg)

我们看到我们简单的深度学习模型的 AUC 更高，约为 0.8289。这是没有任何调整或超参数搜索的结果。

我们可以执行哪些其他步骤来进一步改进 AUC？我们当然可以尝试使用网格搜索超参数来尝试新算法，但更有趣的是，我们可以调整文档向量吗？答案是肯定和否定！这部分是否定的，因为正如您所记得的，word2vec 本质上是一个无监督学习任务；但是，通过观察返回的一些相似单词，我们可以了解我们的向量的强度。例如，让我们看看单词`drama`：

```scala
w2vModel.findSynonyms("drama", 5).show()
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00137.jpeg)

直观地，我们可以查看结果，并询问这五个单词是否*真的是*单词*drama*的最佳同义词（即最佳余弦相似性）。现在让我们尝试通过修改其输入参数重新运行我们的 word2vec 模型：

```scala
val newW2VModel = new Word2Vec()
   .setInputCol("reviewTokens")
   .setOutputCol("reviewVector")
   .setMinCount(3)
   .setMaxIter(250)
   .setStepSize(0.02)
   .fit(movieReviews)
    newW2VModel.findSynonyms("drama", 5).show()
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00138.jpeg)

您应该立即注意到同义词在相似性方面*更好*，但也要注意余弦相似性对这些术语来说显着更高。请记住，word2vec 的默认迭代次数为 1，现在我们已将其设置为`250`，允许我们的网络真正定位一些高质量的词向量，这可以通过更多的预处理步骤和进一步调整 word2vec 的超参数来进一步改进，这应该产生更好质量的文档向量。

# 总结

许多公司（如谷歌）免费提供预训练的词向量（在 Google News 的子集上训练，包括前三百万个单词/短语）以供各种向量维度使用：例如，25d、50d、100d、300d 等。您可以在此处找到代码（以及生成的词向量）。除了 Google News，还有其他来源的训练词向量，使用维基百科和各种语言。您可能会有一个问题，即如果谷歌等公司免费提供预训练的词向量，为什么还要自己构建？这个问题的答案当然是应用相关的；谷歌的预训练词典对于单词*java*有三个不同的向量，基于大小写（JAVA、Java 和 java 表示不同的含义），但也许，您的应用只涉及咖啡，因此只需要一个*版本*的 java。

本章的目标是为您清晰简洁地解释 word2vec 算法以及该算法的非常流行的扩展，如 doc2vec 和序列到序列学习模型，这些模型采用各种风格的循环神经网络。正如总是一章的时间远远不足以涵盖自然语言处理这个极其激动人心的领域，但希望这足以激发您的兴趣！

作为这一领域的从业者和研究人员，我们（作者）不断思考将文档表示为固定向量的新方法，有很多论文致力于解决这个问题。您可以考虑*LDA2vec*和*Skip-thought Vectors*以进一步阅读该主题。

其他一些博客可添加到您的阅读列表，涉及**自然语言处理**（**NLP**）和*向量化*，如下所示：

+   谷歌的研究博客（[`research.googleblog.com/`](https://research.googleblog.com/)）

+   NLP 博客（始终考虑周到的帖子，带有大量链接供进一步阅读，）（[`nlpers.blogspot.com/`](http://nlpers.blogspot.com/)）

+   斯坦福 NLP 博客（[`nlp.stanford.edu/blog/`](http://nlp.stanford.edu/blog/)）

在下一章中，我们将再次看到词向量，我们将结合到目前为止学到的所有知识来解决一个需要在各种处理任务和模型输入方面“应有尽有”的问题。 敬请关注！


# 第六章：从点击流数据中提取模式

在收集个别测量或事件之间的真实世界数据时，通常会有非常复杂和高度复杂的关系需要观察。本章的指导示例是用户在网站及其子域上生成的点击事件的观察。这样的数据既有趣又具有挑战性。它有趣，因为通常有许多*模式*显示出用户在其浏览行为中的行为和某些*规则*。至少对于运行网站的公司和可能成为他们数据科学团队的焦点，了解用户群体的见解是有趣的。方法论方面，建立一个能够实时检测模式的生产系统，例如查找恶意行为，技术上可能非常具有挑战性。能够理解和实施算法和技术两方面是非常有价值的。

在本章中，我们将深入研究两个主题：在 Spark 中进行*模式挖掘*和处理*流数据*。本章分为两个主要部分。在第一部分中，我们将介绍 Spark 目前提供的三种可用模式挖掘算法，并将它们应用于一个有趣的数据集。在第二部分中，我们将更加技术化地看待问题，并解决使用第一部分算法部署流数据应用时出现的核心问题。特别是，您将学习以下内容：

+   频繁模式挖掘的基本原则。

+   应用程序的有用和相关数据格式。

+   如何加载和分析用户在[`MSNBC.com`](http://MSNBC.com)上生成的点击流数据集。

+   在 Spark 中了解和比较三种模式挖掘算法，即*FP-growth，关联规则*和**前缀跨度**。

+   如何将这些算法应用于 MSNBC 点击数据和其他示例以识别相关模式。

+   *Spark Streaming*的基础知识以及它可以涵盖哪些用例。

+   如何通过使用 Spark Streaming 将任何先前的算法投入生产。

+   使用实时聚合的点击事件实现更实际的流应用程序。

通过构建，本章在技术上更加涉及到了末尾，但是通过*Spark Streaming*，它也允许我们介绍 Spark 生态系统中另一个非常重要的工具。我们首先介绍模式挖掘的一些基本问题，然后讨论如何解决这些问题。

# 频繁模式挖掘

当面对一个新的数据集时，一个自然的问题序列是：

+   我们看什么样的数据；也就是说，它有什么结构？

+   数据中可以经常发现哪些观察结果；也就是说，我们可以在数据中识别出哪些模式或规则？

+   我们如何评估什么是频繁的；也就是说，什么是良好的相关性度量，我们如何测试它？

在非常高的层次上，频繁模式挖掘正是在解决这些问题。虽然很容易立即深入研究更高级的机器学习技术，但这些模式挖掘算法可以提供相当多的信息，并帮助建立对数据的直觉。

为了介绍频繁模式挖掘的一些关键概念，让我们首先考虑一个典型的例子，即购物车。对顾客对某些产品感兴趣并购买的研究长期以来一直是全球营销人员的主要关注点。虽然在线商店确实有助于进一步分析顾客行为，例如通过跟踪购物会话中的浏览数据，但已购买的物品以及购买行为中的模式的问题也适用于纯线下场景。我们很快将看到在网站上积累的点击流数据的更复杂的例子；目前，我们将在假设我们可以跟踪的事件中只有物品的实际支付交易的情况下进行工作。

例如，对于超市或在线杂货购物车的给定数据，会引发一些有趣的问题，我们主要关注以下三个问题：

+   *哪些物品经常一起购买？*例如，有传闻证据表明啤酒和尿布经常在同一次购物会话中一起购买。发现经常一起购买的产品的模式可能允许商店将这些产品放在彼此更近的位置，以增加购物体验或促销价值，即使它们乍一看并不属于一起。在在线商店的情况下，这种分析可能是简单推荐系统的基础。

+   基于前面的问题，*在购物行为中是否有任何有趣的影响或规则？*继续以购物车为例，我们是否可以建立关联，比如*如果购买了面包和黄油，我们也经常在购物车中找到奶酪*？发现这样的关联规则可能非常有趣，但也需要更多澄清我们认为的*经常*是什么意思，也就是，频繁意味着什么。

+   注意，到目前为止，我们的购物车只是被简单地视为一个*物品袋*，没有额外的结构。至少在在线购物的情况下，我们可以为数据提供更多信息。我们将关注物品的*顺序性*;也就是说，我们将注意产品被放入购物车的顺序。考虑到这一点，类似于第一个问题，人们可能会问，*我们的交易数据中经常可以找到哪些物品序列？*例如，购买大型电子设备后可能会跟随购买额外的实用物品。

我们之所以特别关注这三个问题，是因为 Spark MLlib 正好配备了三种模式挖掘算法，它们大致对应于前面提到的问题，能够回答这些问题。具体来说，我们将仔细介绍*FP-growth*、*关联规则*和*前缀跨度*，以解决这些问题，并展示如何使用 Spark 解决这些问题。在这样做之前，让我们退一步，正式介绍到目前为止我们已经为之努力的概念，以及一个运行的例子。我们将在接下来的小节中提到前面的三个问题。

# 模式挖掘术语

我们将从一组项目*I = {a[1], ..., a[n]}*开始，这将作为所有以下概念的基础。*事务* T 只是 I 中的一组项目，如果它包含*l*个项目，则我们说 T 是长度为*l*的事务。*事务数据库* D 是事务 ID 和它们对应的事务的数据库。

为了给出一个具体的例子，考虑以下情况。假设要购物的完整物品集由*I = {面包，奶酪，菠萝，鸡蛋，甜甜圈，鱼，猪肉，牛奶，大蒜，冰淇淋，柠檬，油，蜂蜜，果酱，羽衣甘蓝，盐}*给出。由于我们将查看很多物品子集，为了使以后的事情更容易阅读，我们将简单地用它们的第一个字母缩写这些物品，也就是说，我们将写*I = {b，c，a，e，d，f，p，m，g，i，l，o，h，j，k，s}*。给定这些物品，一个小的交易数据库 D 可能如下所示：

| 交易 ID | 交易 |
| --- | --- |
| 1 | a, c, d, f, g, i, m, p |
| 2 | a, b, c, f, l, m, o |
| 3 | b, f, h, j, o |
| 4 | b, c, k, s, p |
| 5 | a, c, e, f, l, m, n, p |

表 1：一个包含五个交易的小购物车数据库

# 频繁模式挖掘问题

鉴于交易数据库的定义，*模式*P 是包含在 D 中的交易，模式的支持*supp(P)*是这个为真的交易数量，除以或归一化为 D 中的交易数量：

*supp(s) = suppD = |{ s' ∈ S | s <s'}| / |D|*

我们使用*<*符号来表示*s*作为*s'*的子模式，或者反过来，称*s'*为*s*的超模式。请注意，在文献中，您有时也会找到一个略有不同的支持版本，它不会对值进行归一化。例如，模式*{a，c，f}*可以在交易 1、2 和 5 中找到。这意味着*{a，c，f}*是我们数据库 D 中支持为 0.6 的模式的模式。

支持是一个重要的概念，因为它给了我们一个测量模式频率的第一个例子，这正是我们追求的。在这种情况下，对于给定的最小支持阈值*t*，我们说*P*是一个频繁模式，当且仅当*supp(P)*至少为*t*。在我们的运行示例中，长度为 1 且最小支持*0.6*的频繁模式是*{a}，{b}，{c}，{p}，和{m}*，支持为 0.6，以及*{f}*，支持为 0.8。在接下来的内容中，我们经常会省略项目或模式的括号，并写*f*代替*{f}*，例如。

给定最小支持阈值，找到所有频繁模式的问题被称为*频繁模式挖掘问题*，实际上，这是前面提到的第一个问题的形式化版本。继续我们的例子，我们已经找到了*t = 0.6*的长度为 1 的所有频繁模式。我们如何找到更长的模式？在理论上，鉴于资源是无限的，这并不是什么大问题，因为我们所需要做的就是计算项目的出现次数。然而，在实际层面上，我们需要聪明地处理这个问题，以保持计算的高效性。特别是对于足够大以至于 Spark 能派上用场的数据库来说，解决频繁模式挖掘问题可能会非常计算密集。

一个直观的解决方法是这样的：

1.  找到所有长度为 1 的频繁模式，这需要进行一次完整的数据库扫描。这就是我们在前面的例子中开始的方式。

1.  对于长度为 2 的模式，生成所有频繁 1-模式的组合，即所谓的候选项，并通过对 D 的另一次扫描来测试它们是否超过最小支持。

1.  重要的是，我们不必考虑不频繁模式的组合，因为包含不频繁模式的模式不能变得频繁。这种推理被称为**先验原则**。

1.  对于更长的模式，迭代地继续这个过程，直到没有更多的模式可以组合。

这种算法使用生成和测试方法进行模式挖掘，并利用先验原则来限制组合，称为先验算法。这种基线算法有许多变体，它们在可扩展性方面存在类似的缺点。例如，需要进行多次完整的数据库扫描来执行迭代，这对于庞大的数据集可能已经成本过高。此外，生成候选本身已经很昂贵，但计算它们的组合可能根本不可行。在下一节中，我们将看到 Spark 中的*FP-growth*算法的并行版本如何克服刚才讨论的大部分问题。

# 关联规则挖掘问题

为了进一步介绍概念，让我们接下来转向*关联规则*，这是首次在*大型数据库中挖掘项集之间的关联规则*中引入的，可在[`arbor.ee.ntu.edu.tw/~chyun/dmpaper/agrama93.pdf`](http://arbor.ee.ntu.edu.tw/~chyun/dmpaper/agrama93.pdf)上找到。与仅计算数据库中项的出现次数相反，我们现在想要理解模式的规则或推论。我的意思是，给定模式*P[1]*和另一个模式*P[2]*，我们想知道在*D*中可以找到*P[1]*时，*P[2]*是否经常出现，我们用*P[1 ]⇒ P[2]*来表示这一点。为了更加明确，我们需要一个类似于模式支持的规则频率的概念，即*置信度*。对于规则*P[1 ]⇒ P[2]*，置信度定义如下：

*conf(P[1] ⇒ P[2]) = supp(P[1] ∪ P[2]) / supp(P[1])*

这可以解释为*P[1]*给出*P[2]*的条件支持；也就是说，如果将*D*限制为支持*P[1]*的所有交易，那么在这个受限制的数据库中，*P[2]*的支持将等于*conf(P[1 ]⇒ P[2])*。如果它超过最小置信度阈值*t*，我们称*P[1 ]⇒ P[2]*为*D*中的规则，就像频繁模式的情况一样。找到置信度阈值的所有规则代表了第二个问题*关联规则挖掘*的正式答案。此外，在这种情况下，我们称*P[1 ]*为*前提*，*P[2]*为*结论*。通常，对前提或结论的结构没有限制。但在接下来的内容中，为简单起见，我们将假设结论的长度为 1。

在我们的运行示例中，模式*{f，m}*出现了三次，而*{f，m，p}*只出现了两次，这意味着规则*{f，m}⇒{p}*的置信度为*2/3*。如果我们将最小置信度阈值设置为*t = 0.6*，我们可以轻松地检查以下具有长度为 1 的前提和结论的关联规则对我们的情况有效：

*{a}⇒{c}，{a}⇒{f}，{a}⇒{m}，{a}⇒{p}，{c}⇒{a}，{c}⇒{f}，{c}⇒{m}，{c}⇒{p}，{f}⇒{a}，{f}⇒{c}，{f}⇒{m}，{m}⇒{a}，{m}⇒{c}，{m}⇒{f}，{m}⇒{p}，{p}⇒{a}，{p}⇒{c}，{p}⇒{f}，{p}⇒{m}*

从置信度的前面定义可以清楚地看出，一旦我们有了所有频繁模式的支持值，计算关联规则就相对简单。实际上，正如我们将很快看到的那样，Spark 对关联规则的实现是基于预先计算频繁模式的。

此时应该指出的是，虽然我们将限制自己在支持和置信度的度量上，但还有许多其他有趣的标准可用，我们无法在本书中讨论；例如，*信念、杠杆、*或*提升*的概念。有关其他度量的深入比较，请参阅[`www.cse.msu.edu/~ptan/papers/IS.pdf`](http://www.cse.msu.edu/~ptan/papers/IS.pdf)。

# 顺序模式挖掘问题

让我们继续正式化，这是我们在本章中处理的第三个也是最后一个模式匹配问题。让我们更详细地看一下*序列*。序列与我们之前看到的交易不同，因为现在顺序很重要。对于给定的项目集*I*，长度为*l*的序列*S*在*I*中定义如下：

*s = <s[1,] s[2],..., s[l]>*

在这里，每个单独的*s[i]*都是项目的连接，即*s[i] = (a[i1] ... a[im)]*，其中*a[ij]*是*I*中的一个项目。请注意，我们关心序列项*s[i]*的顺序，但不关心*s[i]*中各个*a[ij]*的内部顺序。序列数据库*S*由序列 ID 和序列的成对组成，类似于我们之前的内容。这样的数据库示例可以在下表中找到，其中的字母代表与我们之前的购物车示例中相同的项目：

| **序列 ID** | **序列** |
| --- | --- |
| 1 | *<a(abc)(ac)d(cf)>* |
| 2 | *<(ad)c(bc)(ae)>* |
| 3 | *<(ef)(ab)(df)cb>* |
| 4 | *<eg(af)cbc>* |

表 2：一个包含四个短序列的小序列数据库。

在示例序列中，注意圆括号将单个项目分组为序列项。还要注意，如果序列项由单个项目组成，我们会省略这些冗余的大括号。重要的是，子序列的概念需要比无序结构更加小心。我们称*u = (u[1], ..., u[n])*为*s = (s[1],..., s[l])*的*子序列*，并写为*u <s*，如果存在索引*1 **≤ i1 < i2 < ... < in ≤ m*，使得我们有以下关系：

*u[1] < s[i1], ..., u[n] <s[in]*

在这里，最后一行中的*< *符号表示*u[j]*是*s[ij]*的子模式。粗略地说，如果*u*的所有元素按给定顺序是*s*的子模式，那么*u*就是*s*的子序列。同样地，我们称*s*为*u*的超序列。在前面的例子中，我们看到*<a(ab)ac>*和*a(cb)(ac)dc>*是*<a(abc)(ac)d(cf)>*的子序列的例子，而*<(fa)c>*是*<eg(af)cbc>*的子序列的例子。

借助超序列的概念，我们现在可以定义给定序列数据库*S*中序列*s*的*支持度*如下：

*suppS = supp(s) = |{ s' ∈ S | s <s'}| / |S|*

请注意，结构上，这与无序模式的定义相同，但*<*符号表示的是另一种含义，即子序列。与以前一样，如果上下文中的信息清楚，我们在*支持度*的表示法中省略数据库下标。具备了*支持度*的概念，顺序模式的定义完全类似于之前的定义。给定最小支持度阈值*t*，序列*S*中的序列*s*如果*supp(s)*大于或等于*t*，则称为*顺序模式*。第三个问题的形式化被称为*顺序模式挖掘问题*，即找到在给定阈值*t*下*S*中的所有顺序模式的完整集合。

即使在我们只有四个序列的小例子中，手动检查所有顺序模式也可能是具有挑战性的。举一个*支持度为 1.0*的顺序模式的例子，所有四个序列的长度为 2 的子序列是*<ac>*。找到所有顺序模式是一个有趣的问题，我们将在下一节学习 Spark 使用的所谓*前缀 span*算法来解决这个问题。

# 使用 Spark MLlib 进行模式挖掘

在激发和介绍了三个模式挖掘问题以及必要的符号来正确讨论它们之后，我们将讨论如何使用 Spark MLlib 中可用的算法解决这些问题。通常情况下，由于 Spark MLlib 为大多数算法提供了方便的`run`方法，实际应用算法本身相当简单。更具挑战性的是理解算法及其随之而来的复杂性。为此，我们将逐一解释这三种模式挖掘算法，并研究它们是如何实现以及如何在玩具示例中使用它们。只有在完成所有这些之后，我们才会将这些算法应用于从[`MSNBC.com`](http://MSNBC.com)检索到的点击事件的真实数据集。

Spark 中模式挖掘算法的文档可以在[`spark.apache.org/docs/2.1.0/mllib-frequent-pattern-mining.html`](https://spark.apache.org/docs/2.1.0/mllib-frequent-pattern-mining.html)找到。它为希望立即深入了解的用户提供了一个很好的入口点。

# 使用 FP-growth 进行频繁模式挖掘

当我们介绍频繁模式挖掘问题时，我们还快速讨论了一种基于 apriori 原则来解决它的策略。这种方法是基于一遍又一遍地扫描整个交易数据库，昂贵地生成不断增长长度的模式候选项并检查它们的支持。我们指出，这种策略对于非常大的数据可能是不可行的。

所谓的*FP-growth 算法*，其中**FP**代表**频繁模式**，为这个数据挖掘问题提供了一个有趣的解决方案。该算法最初是在*Mining Frequent Patterns without Candidate Generation*中描述的，可在[`www.cs.sfu.ca/~jpei/publications/sigmod00.pdf`](https://www.cs.sfu.ca/~jpei/publications/sigmod00.pdf)找到。我们将首先解释这个算法的基础知识，然后继续讨论其分布式版本*parallel FP-growth*，该版本在*PFP: Parallel FP-Growth for Query Recommendation*中介绍，可在[`static.googleusercontent.com/media/research.google.com/en//pubs/archive/34668.pdf`](https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/34668.pdf)找到。虽然 Spark 的实现是基于后一篇论文，但最好先了解基线算法，然后再进行扩展。

FP-growth 的核心思想是在开始时精确地扫描感兴趣的交易数据库 D 一次，找到所有长度为 1 的频繁模式，并从这些模式构建一个称为*FP-tree*的特殊树结构。一旦完成了这一步，我们不再使用 D，而是仅对通常要小得多的 FP-tree 进行递归计算。这一步被称为算法的*FP-growth 步骤*，因为它从原始树的子树递归构造树来识别模式。我们将称这个过程为*片段模式增长*，它不需要我们生成候选项，而是建立在*分而治之*策略上，大大减少了每个递归步骤中的工作量。

更准确地说，让我们首先定义 FP 树是什么，以及在示例中它是什么样子。回想一下我们在上一节中使用的示例数据库，显示在*表 1*中。我们的项目集包括以下 15 个杂货项目，用它们的第一个字母表示：*b*，*c*，*a*，*e*，*d*，*f*，*p*，*m*，*i*，*l*，*o*，*h*，*j*，*k*，*s*。我们还讨论了频繁项目；也就是说，长度为 1 的模式，对于最小支持阈值*t = 0.6*，由*{f, c, b, a, m, p}*给出。在 FP-growth 中，我们首先利用了一个事实，即项目的排序对于频繁模式挖掘问题并不重要；也就是说，我们可以选择呈现频繁项目的顺序。我们通过按频率递减的顺序对它们进行排序。总结一下情况，让我们看一下下表：

| **交易 ID** | **交易** | **有序频繁项** |
| --- | --- | --- |
| 1 | *a, c, d, f, g, i, m, p* | *f, c, a, m, p* |
| 2 | *a, b, c, f, l, m, o* | *f, c, a, b, m* |
| 3 | *b, f, h, j, o* | *f, b* |
| 4 | *b, c, k, s, p* | *c, b, p* |
| 5 | *a, c, e, f, l, m, n, p* | *f, c, a, m, p* |

表 3：继续使用表 1 开始的示例，通过有序频繁项扩充表格。

正如我们所看到的，像这样有序的频繁项已经帮助我们识别一些结构。例如，我们看到项集*{f, c, a, m, p}*出现了两次，并且稍微改变为*{f, c, a, b, m}*。FP 增长的关键思想是利用这种表示来构建树，从有序频繁项中反映出项在*表 3*的第三列中的结构和相互依赖关系。每个 FP 树都有一个所谓的*根*节点，用作连接构造的有序频繁项的基础。在以下图表的右侧，我们可以看到这是什么意思：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00139.jpeg)

图 1：FP 树和我们频繁模式挖掘的运行示例的表头表。

*图 1*的左侧显示了我们将在稍后解释和正式化的表头表，右侧显示了实际的 FP 树。对于我们示例中的每个有序频繁项，都有一条从根开始的有向路径，从而表示它。树的每个节点不仅跟踪频繁项本身，还跟踪通过该节点的路径数。例如，五个有序频繁项集中有四个以字母*f*开头，一个以*c*开头。因此，在 FP 树中，我们在顶层看到`f: 4`和`c: 1`。这个事实的另一个解释是，*f*是四个项集的*前缀*，*c*是一个。对于这种推理的另一个例子，让我们将注意力转向树的左下部，即叶节点`p: 2`。两次*p*的出现告诉我们，恰好有两条相同的路径到此结束，我们已经知道：*{f, c, a, m, p}*出现了两次。这个观察很有趣，因为它已经暗示了 FP 增长中使用的一种技术--从树的叶节点开始，或者项集的后缀，我们可以追溯每个频繁项集，所有这些不同根节点路径的并集产生所有路径--这对于并行化是一个重要的想法。

*图 1*左侧的表头表是一种存储项的聪明方式。请注意，通过树的构造，一个节点不同于一个频繁项，而是，项可以并且通常会多次出现，即每个它们所属的不同路径都会出现一次。为了跟踪项及其关系，表头表本质上是项的*链表*，即每个项的出现都通过这个表与下一个项相连。我们在*图 1*中用水平虚线表示每个频繁项的链接，仅用于说明目的。

有了这个例子，现在让我们给出 FP 树的正式定义。FP 树*T*是一棵树，由根节点和从根节点开始的频繁项前缀子树以及频繁项表头表组成。树的每个节点由一个三元组组成，即项名称、出现次数和一个节点链接，指向相同名称的下一个节点，如果没有这样的下一个节点，则为`null`。

为了快速回顾，构建*T*，我们首先计算给定最小支持阈值*t*的频繁项，然后，从根开始，将每个由事务的排序频繁模式列表表示的路径插入树中。现在，我们从中获得了什么？要考虑的最重要的属性是，解决频繁模式挖掘问题所需的所有信息都被编码在 FP 树*T*中，因为我们有效地编码了所有频繁项的重复共现。由于*T*的节点数最多与频繁项的出现次数一样多，*T*通常比我们的原始数据库 D 小得多。这意味着我们已经将挖掘问题映射到了一个较小的数据集上，这本身就降低了与之前草率方法相比的计算复杂性。

接下来，我们将讨论如何从构建的 FP 树中递归地从片段中生长模式。为此，让我们做出以下观察。对于任何给定的频繁项*x*，我们可以通过跟随*x*的节点链接，从*x*的头表条目开始，通过分析相应的子树来获得涉及*x*的所有模式。为了解释具体方法，我们进一步研究我们的例子，并从头表的底部开始，分析包含*p*的模式。从我们的 FP 树*T*来看，*p*出现在两条路径中：*(f:4, c:3, a:3, m:3, p:2)*和*(c:1, b:1, p:1)*，跟随*p*的节点链接。现在，在第一条路径中，*p*只出现了两次，也就是说，在原始数据库 D 中*{f, c, a, m, p}*模式的总出现次数最多为两次。因此，在*p*存在的条件下，涉及*p*的路径实际上如下：*(f:2, c:2, a:2, m:2)*和*(c:1, b:1)*。事实上，由于我们知道我们想要分析模式，给定*p*，我们可以简化符号，简单地写成*(f:2, c:2, a:2, m:2)*和*(c:1, b:1)*。这就是我们所说的**p 的条件模式基**。再进一步，我们可以从这个条件数据库构建一个新的 FP 树。在*p*出现三次的条件下，这棵新树只包含一个节点，即*(c:3)*。这意味着我们最终得到了*{c, p}*作为涉及*p*的单一模式，除了*p*本身。为了更好地讨论这种情况，我们引入以下符号：*p*的条件 FP 树用*{(c:3)}|p*表示。

为了更直观，让我们考虑另一个频繁项并讨论它的条件模式基。继续从底部到顶部并分析*m*，我们再次看到两条相关的路径：*(f:4, c:3, a:3, m:2)*和*(f:4, c:3, a:3, b:1, m:1)*。请注意，在第一条路径中，我们舍弃了末尾的*p:2*，因为我们已经涵盖了*p*的情况。按照相同的逻辑，将所有其他计数减少到所讨论项的计数，并在*m*的条件下，我们得到了条件模式基*{(f:2, c:2, a:2), (f:1, c:1, a:1, b:1)}*。因此，在这种情况下，条件 FP 树由*{f:3, c:3, a:3}|m*给出。现在很容易看出，实际上每个*m*与*f*、*c*和*a*的每种可能组合都形成了一个频繁模式。给定*m*，完整的模式集合是*{m}*、*{am}*、*{cm}*、*{fm}*、*{cam}*、*{fam}*、*{fcm}*和*{fcam}*。到目前为止，应该清楚如何继续了，我们不会完全进行这个练习，而是总结其结果如下表所示：

| **频繁模式** | **条件模式基** | **条件 FP 树** |
| --- | --- | --- |
| *p* | *{(f:2, c:2, a:2, m:2), (c:1, b:1)}* | *{(c:3)}&#124;p* |
| *m* | *{(f :2, c:2, a:2), (f :1, c:1, a:1, b:1)}* | *{f:3, c:3, a:3}&#124;m* |
| *b* | *{(f :1, c:1, a:1), (f :1), (c:1)}* | null |
| *a* | *{(f:3, c:3)}* | *{(f:3, c:3)}&#124;a* |
| *c* | *{(f:3)}* | *{(f:3)}&#124;c* |
| *f* | null | null |

表 4：我们运行示例的条件 FP 树和条件模式基的完整列表。

由于这种推导需要非常仔细的注意，让我们退一步总结一下到目前为止的情况：

1.  从原始 FP 树*T*开始，我们使用节点链接迭代所有项目。

1.  对于每个项目*x*，我们构建了它的条件模式基和条件 FP 树。这样做，我们使用了以下两个属性：

+   在每个潜在模式中，我们丢弃了跟随*x*之后的所有项目，即我们只保留了*x*的*前缀*。

+   我们修改了条件模式基中的项目计数，以匹配*x*的计数。

1.  使用后两个属性修改路径，我们称*x*的转换前缀路径。

最后，要说明算法的 FP 增长步骤，我们需要两个在示例中已经隐含使用的基本观察结果。首先，在条件模式基中项目的支持与其在原始数据库中的表示相同。其次，从原始数据库中的频繁模式*x*和任意一组项目*y*开始，我们知道如果且仅当*y*是频繁模式时*xy*也是频繁模式。这两个事实可以很容易地一般推导出来，但在前面的示例中应该清楚地证明。

这意味着我们可以完全专注于在条件模式基中查找模式，因为将它们与频繁模式连接又是一种模式，这样，我们可以找到所有模式。因此，通过计算条件模式基递归地增长模式的机制被称为模式增长，这就是为什么 FP 增长以此命名。考虑到所有这些，我们现在可以用伪代码总结 FP 增长过程，如下所示：

```scala
def fpGrowth(tree: FPTree, i: Item):
    if (tree consists of a single path P){
        compute transformed prefix path P' of P
        return all combinations p in P' joined with i
    }
    else{
        for each item in tree {
            newI = i joined with item
            construct conditional pattern base and conditional FP-tree newTree
            call fpGrowth(newTree, newI)
        }
    }
```

通过这个过程，我们可以总结完整的 FP 增长算法的描述如下：

1.  从 D 计算频繁项，并从中计算原始 FP 树*T*（*FP 树计算*）。

1.  运行`fpGrowth(T, null)`（*FP 增长计算*）。

在理解了基本构造之后，我们现在可以继续讨论基于 Spark 实现的 FP 增长的并行扩展，即 Spark 实现的基础。**并行 FP 增长**，或简称**PFP**，是 FP 增长在诸如 Spark 之类的并行计算引擎中的自然演变。它解决了基线算法的以下问题：

+   *分布式存储：*对于频繁模式挖掘，我们的数据库 D 可能无法适应内存，这已经使得原始形式的 FP 增长不适用。出于明显的原因，Spark 在这方面确实有所帮助。

+   *分布式计算：*有了分布式存储，我们将不得不适当地并行化算法的所有步骤，并且 PFP 正是这样做的。

+   *适当的支持值*：在处理查找频繁模式时，我们通常不希望将最小支持阈值*t*设置得太高，以便在长尾中找到有趣的模式。然而，一个小的*t*可能会导致 FP 树无法适应足够大的 D 而强制我们增加*t*。PFP 也成功地解决了这个问题，我们将看到。

考虑到 Spark 的实现，PFP 的基本概述如下：

+   **分片**：我们将数据库 D 分布到多个分区，而不是将其存储在单个机器上。无论特定的存储层如何，使用 Spark，我们可以创建一个 RDD 来加载 D。

+   **并行频繁项计数**：计算 D 的频繁项的第一步可以自然地作为 RDD 上的映射-归约操作执行。

+   **构建频繁项组**：频繁项集被划分为多个组，每个组都有唯一的组 ID。

+   **并行 FP 增长**：FP 增长步骤分为两步，以利用并行性：

+   **映射阶段**：映射器的输出是一对，包括组 ID 和相应的交易。

+   **减少阶段**：Reducer 根据组 ID 收集数据，并对这些组相关的交易进行 FP 增长。

+   **聚合**：算法的最后一步是对组 ID 的结果进行聚合。

鉴于我们已经花了很多时间研究 FP-growth 本身，而不是深入了解 Spark 中 PFP 的太多实现细节，让我们看看如何在我们一直在使用的玩具示例上使用实际算法：

```scala
import org.apache.spark.mllib.fpm.FPGrowth
import org.apache.spark.rdd.RDD

val transactions: RDD[Array[String]] = sc.parallelize(Array(
  Array("a", "c", "d", "f", "g", "i", "m", "p"),
  Array("a", "b", "c", "f", "l", "m", "o"),
  Array("b", "f", "h", "j", "o"),
  Array("b", "c", "k", "s", "p"),
  Array("a", "c", "e", "f", "l", "m", "n", "p")
))

val fpGrowth = new FPGrowth()
  .setMinSupport(0.6)
  .setNumPartitions(5)
val model = fpGrowth.run(transactions)

model.freqItemsets.collect().foreach { itemset =>
  println(itemset.items.mkString("[", ",", "]") + ", " + itemset.freq)
}
```

代码很简单。我们将数据加载到`transactions`中，并使用最小支持值为*0.6*和*5*个分区初始化 Spark 的`FPGrowth`实现。这将返回一个模型，我们可以在之前构建的交易上运行。这样做可以让我们访问指定最小支持的模式或频繁项集，通过调用`freqItemsets`，以格式化的方式打印出来，总共有 18 个模式的输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00140.jpeg)

请记住，我们已经将交易定义为“集合”，我们通常称它们为项目集。这意味着在这样的项目集中，特定项目只能出现一次，`FPGrowth`依赖于此。例如，如果我们将前面示例中的第三个交易替换为`Array("b", "b", "h", "j", "o")`，在这些交易上调用`run`将会抛出错误消息。我们将在后面看到如何处理这种情况。

在类似于我们刚刚在 FP-growth 中所做的方式中已经解释了关联规则和前缀跨度之后，我们将转向在真实数据集上应用这些算法。

# 关联规则挖掘

回想一下关联规则介绍中，在计算关联规则时，一旦我们有了频繁项集，也就是指定最小阈值的模式，我们就已经完成了大约一半。事实上，Spark 的关联规则实现假设我们提供了一个`FreqItemsets[Item]`的 RDD，我们已经在之前调用`model.freqItemsets`中看到了一个例子。除此之外，计算关联规则不仅作为一个独立的算法可用，而且还可以通过`FPGrowth`使用。

在展示如何在我们的运行示例上运行相应算法之前，让我们快速解释一下 Spark 中如何实现关联规则：

1.  该算法已经提供了频繁项集，因此我们不需要再计算它们了。

1.  对于每一对模式 X 和*Y*，计算同时出现的 X 和 Y 的频率，并存储（*X*，（*Y*，supp（*X* ∪ *Y*））。我们称这样的模式对为“候选对”，其中*X*充当潜在的前提，*Y*充当结论。

1.  将所有模式与候选对连接起来，以获得形式为（X，（（Y，supp（*X* ∪ *Y*）），supp（*X*）））的语句。

1.  然后，我们可以通过所需的最小置信度值过滤形式为（X，（（Y，supp（*X* ∪ *Y*）），supp（*X*）））的表达式，以返回所有具有该置信度水平的规则*X ⇒ Y*。

假设我们在上一节中没有通过 FP-growth 计算模式，而是只给出了这些项目集的完整列表，我们可以从头开始创建一个 RDD，然后在其上运行`AssociationRules`的新实例：

```scala
import org.apache.spark.mllib.fpm.AssociationRules
import org.apache.spark.mllib.fpm.FPGrowth.FreqItemset

val patterns: RDD[FreqItemset[String]] = sc.parallelize(Seq(
  new FreqItemset(Array("m"), 3L),
  new FreqItemset(Array("m", "c"), 3L),
  new FreqItemset(Array("m", "c", "f"), 3L), 
  new FreqItemset(Array("m", "a"), 3L), 
  new FreqItemset(Array("m", "a", "c"), 3L),
  new FreqItemset(Array("m", "a", "c", "f"), 3L),  
  new FreqItemset(Array("m", "a", "f"), 3L), 
  new FreqItemset(Array("m", "f"), 3L), 
  new FreqItemset(Array("f"), 4L), 
  new FreqItemset(Array("c"), 4L), 
  new FreqItemset(Array("c", "f"), 3L), 
  new FreqItemset(Array("p"), 3L), 
  new FreqItemset(Array("p", "c"), 3L), 
  new FreqItemset(Array("a"), 3L), 
  new FreqItemset(Array("a", "c"), 3L), 
  new FreqItemset(Array("a", "c", "f"), 3L), 
  new FreqItemset(Array("a", "f"), 3L), 
  new FreqItemset(Array("b"), 3L)
))

val associationRules = new AssociationRules().setMinConfidence(0.7)
val rules = associationRules.run(patterns)

rules.collect().foreach { rule =>
  println("[" + rule.antecedent.mkString(",") + "=>"
    + rule.consequent.mkString(",") + "]," + rule.confidence)
}
```

请注意，在初始化算法后，我们将最小置信度设置为`0.7`，然后收集结果。此外，运行`AssociationRules`将返回一个`Rule`类型的规则 RDD。这些规则对象具有`antecedent`、`consequent`和`confidence`的访问器，我们使用这些访问器来收集结果，结果如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00141.jpeg)

我们从头开始展示这个例子的原因是为了传达关联规则在 Spark 中确实是一个独立的算法。由于目前在 Spark 中计算模式的唯一内置方式是通过 FP-growth，而且关联规则无论如何都依赖于`FreqItemset`的概念（从`FPGrowth`子模块导入），这似乎有点不切实际。使用我们从之前的 FP-growth 示例中得到的结果，我们完全可以编写以下内容来实现相同的效果：

```scala
val patterns = model.freqItemsets
```

有趣的是，关联规则也可以直接通过`FPGrowth`的接口进行计算。继续使用之前示例中的符号，我们可以简单地写出以下内容，以得到与之前相同的一组规则：

```scala
val rules = model.generateAssociationRules(confidence = 0.7)
```

在实际情况下，虽然这两种表述都有用，但后一种肯定会更简洁。

# 使用前缀跨度进行顺序模式挖掘

转向顺序模式匹配，前缀跨度算法比关联规则稍微复杂一些，因此我们需要退一步，首先解释基础知识。前缀跨度首次在[`hanj.cs.illinois.edu/pdf/tkde04_spgjn.pdf`](http://hanj.cs.illinois.edu/pdf/tkde04_spgjn.pdf)中被描述为所谓的 FreeSpan 算法的自然扩展。该算法本身相对于其他方法（如**广义顺序模式**（GSP））来说是一个显著的改进。后者基于先验原则，我们之前讨论的关于许多基于它的算法的缺点也适用于顺序挖掘，即昂贵的候选生成，多次数据库扫描等。

前缀跨度，在其基本形式中，使用与 FP-growth 相同的基本思想，即将原始数据库投影到通常较小的结构中进行分析。而在 FP-growth 中，我们递归地为原始 FP 树中的每个分支的后缀构建新的 FP 树，前缀跨度通过考虑前缀来增长或跨越新的结构，正如其名称所示。

让我们首先在序列的上下文中正确定义前缀和后缀的直观概念。在接下来的内容中，我们将始终假设序列项内的项目按字母顺序排列，也就是说，如果 s = <s[1,] s[2],..., s[l]>是 S 中的一个序列，每个 s[i]都是项目的连接，也就是 s[i] = (a[i1] ... a[im])，其中 a[ij]是 I 中的项目，我们假设 s[i]中的所有 a[ij]都按字母顺序排列。在这种情况下，如果 s' = <s'[1,] s'[2],..., s'm>是 s 的前缀，当且仅当满足以下三个属性时，s'被称为 s 的前缀：

+   对于所有 i < m，我们有序列项的相等，也就是 s'[i] = s[i]

+   s'[m] < s[m]，也就是说，s'的最后一项是 s[m]的子模式

+   如果我们从 s[m]中减去 s'[m]，也就是从 s[m]中删除子模式 s'[m]，那么 s[m] - s'[m]中剩下的所有频繁项都必须在 s'[m]中的所有元素之后按字母顺序排列

前两点都相当自然，最后一点可能看起来有点奇怪，所以让我们通过一个例子来解释。给定一个序列< a(abc)>，来自数据库 D，其中 a，b 和 c 确实频繁，那么< aa>和< a(ab)>是< a(abc)>的前缀，但< ab>不是，因为在最后序列项的差异中，<(abc)> - <b> = <(ac)>，字母 a 并不按字母表顺序在<ab>后面。基本上，第三个属性告诉我们，前缀只能在它影响的最后序列项的开头切除部分。

有了前缀的概念，现在很容易说出后缀是什么。使用与之前相同的符号，如果 s'是 s 的前缀，那么 s'' = <(s[m] - s'[m]), s[m+1], ..., s[l]>就是这个前缀的后缀，我们将其表示为 s'' = s / s'。此外，我们将 s = s's''写成乘积符号。例如，假设< a(abc)>是原始序列，< aa>是前缀，我们将此前缀的后缀表示如下：

<(_bc)> = <a(abc)> / <aa>

请注意，我们使用下划线符号来表示前缀对序列的剩余部分。

前缀和后缀的概念都有助于将原始的顺序模式挖掘问题分割成更小的部分，如下所示。让{<p[1]>, ...,<p[n]>}成为长度为 1 的完整顺序模式集。然后，我们可以得出以下观察结果：

+   所有的顺序模式都以*p[i]*中的一个开头。这意味着我们可以将所有的顺序模式分成*n*个不相交的集合，即以*p[i]*开头的那些，其中*i*在*1*和*n*之间。

+   应用这种推理递归地，我们得到以下的陈述：如果*s*是一个给定的长度为 1 的顺序模式，*{s¹, ..., s^m}*是长度为*l+1*的*s*的完整顺序超模式列表，那么所有具有前缀*s*的顺序模式可以被分成*m*个由*s^i*为前缀的集合。

这两个陈述都很容易得出，但提供了一个强大的工具，将原始问题集合划分为不相交的较小问题。这种策略被称为“分而治之”。有了这个想法，我们现在可以非常类似于 FP-growth 中对条件数据库所做的事情，即根据给定的前缀对数据库进行投影。给定一个顺序模式数据库 S 和一个前缀*s*，**s-投影数据库**，*S|[s]*，是 S 中所有*s*的后缀的集合。

我们需要最后一个定义来陈述和分析前缀跨度算法。如果*s*是 S 中的一个顺序模式，*x*是一个具有前缀*s*的模式，那么在*S|[s]*中*x*的*支持计数*，用*suppS|s*表示，是*S|[s]*中序列*y*的数量，使得*x < sy*；也就是说，我们简单地将支持的概念延续到了 s-投影数据库。我们可以从这个定义中得出一些有趣的性质，使得我们的情况变得更容易。例如，根据定义，我们看到对于任何具有前缀*s*的序列*x*，我们有以下关系：

*suppS = suppS|s*

也就是说，在这种情况下，无论我们在原始数据库中还是在投影数据库中计算支持度都没有关系。此外，如果*s'*是*s*的前缀，很明显*S|[s] = (S|[s'])|[s]*，这意味着我们可以连续地添加前缀而不会丢失信息。从计算复杂性的角度来看，最后一个最重要的陈述是，投影数据库的大小不会超过其原始大小。这个性质应该再次从定义中清楚地看出来，但它对于证明前缀跨度的递归性质是极其有帮助的。

有了所有这些信息，我们现在可以用伪代码勾勒出前缀跨度算法，如下所示。请注意，我们区分一个项目`s'`被附加到顺序模式`s`的末尾和从`s'`生成的序列`<s'>`被添加到`s`的末尾。举个例子，我们可以将字母*e*添加到*<a(abc)>*形成*<a(abce)>*，或者在末尾添加*<e>*形成*<a(abc)e>*：

```scala
def prefixSpan(s: Prefix, l: Length, S: ProjectedDatabase):
  S' = set of all s' in S|s if {
    (s' appended to s is a sequential pattern) or
    (<s'> appended to s is a sequential pattern)
  }
  for s' in S' {
    s'' = s' appended to s
    output s''
    call prefixSpan(s'', l+1, S|s'')
  }
}
call prefixSpan(<>, 0, S)
```

如所述，前缀跨度算法找到所有的顺序模式；也就是说，它代表了解决顺序模式挖掘问题的解决方案。我们无法在这里概述这个陈述的证明，但我们希望已经为您提供了足够的直觉来看到它是如何以及为什么它有效的。

以 Spark 为例，注意我们没有讨论如何有效地并行化基线算法。如果您对实现细节感兴趣，请参阅[`github.com/apache/spark/blob/v2.2.0/mllib/src/main/scala/org/apache/spark/mllib/fpm/PrefixSpan.scala`](https://github.com/apache/spark/blob/v2.2.0/mllib/src/main/scala/org/apache/spark/mllib/fpm/PrefixSpan.scala)，因为并行版本涉及的内容有点太多，不适合在这里介绍。我们将首先研究*表 2*中提供的示例，即四个序列*<a(abc)(ac)d(cf)>*，*<(ad)c(bc)(ae)>*，*<(ef)(ab)(df)cb>*和*<eg(af)cbc>*。为了编码序列的嵌套结构，我们使用字符串的数组数组，并将它们并行化以创建 RDD。初始化和运行`PrefixSpan`的实例的方式与其他两个算法基本相同。这里唯一值得注意的是，除了通过`setMinSupport`将最小支持阈值设置为`0.7`之外，我们还通过`setMaxPatternLength`将模式的最大长度指定为`5`。最后一个参数用于限制递归深度。尽管实现很巧妙，但算法（特别是计算数据库投影）可能需要很长时间：

```scala
import org.apache.spark.mllib.fpm.PrefixSpan

val sequences:RDD[Array[Array[String]]] = sc.parallelize(Seq(
  Array(Array("a"), Array("a", "b", "c"), Array("a", "c"), Array("d"), Array("c", "f")),
 Array(Array("a", "d"), Array("c"), Array("b", "c"), Array("a", "e")),
 Array(Array("e", "f"), Array("a", "b"), Array("d", "f"), Array("c"), Array("b")),
 Array(Array("e"), Array("g"), Array("a", "f"), Array("c"), Array("b"), Array("c")) ))
val prefixSpan = new PrefixSpan()
  .setMinSupport(0.7)
  .setMaxPatternLength(5)
val model = prefixSpan.run(sequences)
model.freqSequences.collect().foreach {
  freqSequence => println(freqSequence.sequence.map(_.mkString("[", ", ", "]")).mkString("[", ", ", "]") + ", " + freqSequence.freq) }
```

在您的 Spark shell 中运行此代码应该产生 14 个顺序模式的以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00142.jpeg)

# MSNBC 点击流数据的模式挖掘

在花费了相当多的时间来解释模式挖掘的基础知识之后，让我们最终转向一个更现实的应用。我们接下来要讨论的数据来自[`msnbc.com`](http://msnbc.com)的服务器日志（部分来自[`msn.com`](http://msn.com)，与新闻相关），代表了这些网站用户的页面浏览活动的整整一天。这些数据是在 1999 年 9 月收集的，并且已经可以在[`archive.ics.uci.edu/ml/machine-learning-databases/msnbc-mld/msnbc990928.seq.gz`](http://archive.ics.uci.edu/ml/machine-learning-databases/msnbc-mld/msnbc990928.seq.gz)上下载。将此文件存储在本地并解压缩，`msnbc990928.seq`文件基本上由标题和长度不等的整数的空格分隔行组成。以下是文件的前几行：

```scala
% Different categories found in input file:

frontpage news tech local opinion on-air misc weather msn-news health living business msn-sports sports summary bbs travel

% Sequences:

1 1 
2 
3 2 2 4 2 2 2 3 3 
5 
1 
6 
1 1 
6 
6 7 7 7 6 6 8 8 8 8 
```

这个文件中的每一行都是用户当天的编码页面访问*序列*。页面访问并没有被收集到最精细的级别，而是被分成了 17 个与新闻相关的类别，这些类别被编码为整数。与这些类别对应的类别名称列在前面的标题中，大多数都是不言自明的（除了`bbs`，它代表**公告板服务**）。此列表中的第 n 个项目对应于第 n 个类别；例如，`1`代表`frontpage`，而`travel`被编码为`17`。例如，这个文件中的第四个用户点击了`opinion`一次，而第三个用户总共有九次页面浏览，从`tech`开始，以`tech`结束。

重要的是要注意，每行中的页面访问确实已经按*时间顺序*存储，也就是说，这确实是关于页面访问顺序的顺序数据。总共收集了 989,818 个用户的数据；也就是说，数据集确实有这么多序列。不幸的是，我们不知道有多少个 URL 已经分组成每个类别，但我们确实知道它的范围相当广，从 10 到 5,000。有关更多信息，请参阅[`archive.ics.uci.edu/ml/machine-learning-databases/msnbc-mld/msnbc.data.html`](http://archive.ics.uci.edu/ml/machine-learning-databases/msnbc-mld/msnbc.data.html)上提供的描述。

仅从这个数据集的描述中，就应该清楚到目前为止我们讨论过的所有三种模式挖掘问题都可以应用于这些数据--我们可以在这个序列数据库中搜索顺序模式，并且忽略顺序性，分析频繁模式和关联规则。为此，让我们首先使用 Spark 加载数据。接下来，我们将假设文件的标题已被删除，并且已经从存储序列文件的文件夹创建了一个 Spark shell 会话：

```scala
val transactions: RDD[Array[Int]] = sc.textFile("./msnbc990928.seq") map { line =>
  line.split(" ").map(_.toInt)
}
```

首先将序列文件加载到整数值数组的 RDD 中。回想一下，频繁模式挖掘中交易的一个假设是项目集实际上是集合，因此不包含重复项。因此，为了应用 FP-growth 和关联规则挖掘，我们必须删除重复的条目，如下所示：

```scala
val uniqueTransactions: RDD[Array[Int]] = transactions.map(_.distinct).cache()
```

请注意，我们不仅限制了每个交易的不同项目，而且缓存了生成的 RDD，这是所有三种模式挖掘算法的推荐做法。这使我们能够在这些数据上运行 FP-growth，为此我们必须找到一个合适的最小支持阈值*t*。到目前为止，在玩具示例中，我们选择了*t*相当大（在 0.6 和 0.8 之间）。在更大的数据库中，不现实地期望*任何*模式具有如此大的支持值。尽管我们只需要处理 17 个类别，但用户的浏览行为可能会因人而异。因此，我们选择支持值只有 5%来获得一些见解：

```scala
val fpGrowth = new FPGrowth().setMinSupport(0.05)
val model = fpGrowth.run(uniqueTransactions)
val count = uniqueTransactions.count()

model.freqItemsets.collect().foreach { itemset =>
    println(itemset.items.mkString("[", ",", "]") + ", " + itemset.freq / count.toDouble )
}
```

这个计算的输出显示，对于*t=0.05*，我们只恢复了 14 个频繁模式，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00143.jpeg)

不仅模式可能比您预期的要少，而且在这些模式中，除了一个之外，所有模式的长度都为*1*。不足为奇的是，*front page*被最频繁地访问，占 31%，其次是*on-air*和*news*类别。*front page*和*news*站点只有 7%的用户在当天访问过，没有其他一对站点类别被超过 5%的用户群体访问。类别 5、15、16 和 17 甚至都没有进入列表。如果我们将实验重复一次，将*t*值改为 1%，模式的数量将增加到总共 74 个。

让我们看看其中有多少长度为 3 的模式：

```scala
model.freqItemsets.collect().foreach { itemset =>
  if (itemset.items.length >= 3)
    println(itemset.items.mkString("[", ",", "]") + ", " + itemset.freq / count.toDouble )
}
```

使用最小支持值*t=0.01*的`FPGrowth`实例运行这个操作将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00144.jpeg)

正如人们可能猜到的那样，最频繁的长度为 1 的模式也是 3 模式中占主导地位的。在这 11 个模式中，有 10 个涉及*front page*，而九个涉及*news*。有趣的是，根据先前的分析，*misc*类别虽然只有 7%的访问量，但在总共的四个 3 模式中出现。如果我们对潜在的用户群有更多的信息，跟进这个模式将是有趣的。可以推测，对许多*杂项*主题感兴趣的用户最终会进入这个混合类别，以及其他一些类别。

接下来进行关联规则的分析在技术上很容易；我们只需运行以下代码来从现有的 FP-growth `model`中获取所有置信度为`0.4`的规则：

```scala
val rules = model.generateAssociationRules(confidence = 0.4)
rules.collect().foreach { rule =>
  println("[" + rule.antecedent.mkString(",") + "=>"
    + rule.consequent.mkString(",") + "]," + (100 * rule.confidence).round / 100.0)
}
```

请注意，我们可以方便地访问相应规则的前提、结果和置信度。这次输出的结果如下；这次将置信度四舍五入到两位小数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00145.jpeg)

同样，自然地，最频繁的长度为 1 的模式出现在许多规则中，尤其是*frontpage*作为结果。在这个例子中，我们选择了支持和置信度的值，以便输出简短且计数容易手动验证，但是让我们对规则集进行一些自动计算，不受限制：

```scala
rules.count
val frontPageConseqRules = rules.filter(_.consequent.head == 1)
frontPageConseqRules.count
frontPageConseqRules.filter(_.antecedent.contains(2)).count
```

执行这些语句，我们看到大约三分之二的规则都有*front page*作为结果，即总共 22 条规则中的 14 条，其中有九条包含*news*在它们的前提中。

接下来是针对这个数据集的序列挖掘问题，我们需要将原始的`transactions`转换为`Array[Array[Int]]`类型的 RDD，因为嵌套数组是 Spark 中用于对前缀 span 编码序列的方式，正如我们之前所见。虽然有些显而易见，但仍然很重要指出，对于序列，我们不必丢弃重复项目的附加信息，就像我们刚刚对 FP-growth 所做的那样。

事实上，通过对单个记录施加顺序性，我们甚至可以获得更多的结构。要进行刚刚指示的转换，我们只需执行以下操作：

```scala
val sequences: RDD[Array[Array[Int]]] = transactions.map(_.map(Array(_))).cache()
```

再次，我们缓存结果以提高算法的性能，这次是`prefixspan`。运行算法本身与以前一样：

```scala
val prefixSpan = new PrefixSpan().setMinSupport(0.005).setMaxPatternLength(15)
val psModel = prefixSpan.run(sequences)
```

我们将最小支持值设置得非常低，为 0.5%，这样这次可以得到一个稍微更大的结果集。请注意，我们还搜索不超过 15 个序列项的模式。通过运行以下操作来分析频繁序列长度的分布：

```scala
psModel.freqSequences.map(fs => (fs.sequence.length, 1))
  .reduceByKey(_ + _)
  .sortByKey()
  .collect()
  .foreach(fs => println(s"${fs._1}: ${fs._2}"))
```

在这一系列操作中，我们首先将每个序列映射到一个由其长度和计数 1 组成的键值对。然后进行一个 reduce 操作，通过键对值进行求和，也就是说，我们计算这个长度出现的次数。其余的只是排序和格式化，得到以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00146.jpeg)

正如我们所看到的，最长的序列长度为 14，这特别意味着我们的最大值 15 并没有限制搜索空间，我们找到了所选支持阈值`t=0.005`的所有顺序模式。有趣的是，大多数用户的频繁顺序访问在[`msnbc.com`](http://msnbc.com)上的触点数量在两到六个之间。

为了完成这个例子，让我们看看每个长度的最频繁模式是什么，以及最长的顺序模式实际上是什么样的。回答第二个问题也会给我们第一个答案，因为只有一个长度为 14 的模式。计算这个可以这样做：

```scala
psModel.freqSequences
  .map(fs => (fs.sequence.length, fs))
  .groupByKey()
  .map(group => group._2.reduce((f1, f2) => if (f1.freq > f2.freq) f1 else f2))
  .map(_.sequence.map(_.mkString("[", ", ", "]")).mkString("[", ", ", "]"))
  .collect.foreach(println)
```

由于这是我们迄今为止考虑的比较复杂的 RDD 操作之一，让我们讨论一下涉及的所有步骤。我们首先将每个频繁序列映射到一个由其长度和序列本身组成的对。这一开始可能看起来有点奇怪，但它允许我们按长度对所有序列进行分组，这是我们在下一步中要做的。每个组由其键和频繁序列的迭代器组成。我们将每个组映射到其迭代器，并通过仅保留具有最大频率的序列来减少序列。然后，为了正确显示此操作的结果，我们两次使用`mkString`来从否则不可读的嵌套数组（在打印时）中创建字符串。前述链的结果如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00147.jpeg)

我们之前讨论过*首页*是迄今为止最频繁的项目，这在直觉上是有很多意义的，因为它是网站的自然入口点。然而，令人惊讶的是，在所选阈值下，所有长度最频繁的序列都只包括*首页*点击。显然，许多用户在首页及其周围花费了大量时间和点击，这可能是它相对于其他类别页面的广告价值的第一个迹象。正如我们在本章的介绍中所指出的，分析这样的数据，特别是如果结合其他数据源，对于各自网站的所有者来说可能具有巨大的价值，我们希望已经展示了频繁模式挖掘技术如何在其中发挥作用。

# 部署模式挖掘应用

在上一节中开发的示例是一个有趣的实验场，可以应用我们在整章中精心制定的算法，但我们必须承认一个事实，那就是我们只是被交给了数据。在撰写本书时，构建数据产品的文化往往在实时数据收集和聚合之间，以及（通常是离线的）数据分析之间划清界限，然后将获得的见解反馈到生产系统中。虽然这种方法有其价值，但也有一定的缺点。不考虑整体情况，我们可能不会准确了解数据的收集细节。缺少这样的信息可能导致错误的假设，最终得出错误的结论。虽然专业化在一定程度上既有用又必要，但至少从业者应该努力获得对应用程序的基本理解。

当我们在上一节介绍 MSNBC 数据集时，我们说它是从网站的服务器日志中检索出来的。我们大大简化了这意味着什么，让我们仔细看一看：

+   高可用性和容错性：网站上的点击事件需要在一天中的任何时间点进行跟踪，而不会出现停机。一些企业，特别是在涉及任何形式的支付交易时，例如在线商店，不能承受丢失某些事件的风险。

+   实时数据的高吞吐量和可扩展性：我们需要一个系统，可以实时存储和处理这些事件，并且可以在不减速的情况下处理一定的负载。例如，MSNBC 数据集中大约一百万个独立用户意味着平均每秒大约有 11 个用户的活动。还有许多事件需要跟踪，特别是要记住我们只测量了页面浏览。

+   流数据和批处理：原则上，前两点可以通过将事件写入足够复杂的日志来解决。然而，我们甚至还没有涉及聚合数据的话题，我们更需要一个在线处理系统来做到这一点。首先，每个事件都必须归因于一个用户，该用户将必须配备某种 ID。接下来，我们将不得不考虑用户会话的概念。虽然 MSNBC 数据集中的用户数据已经在日常级别上进行了聚合，但这对于许多目的来说还不够细粒度。分析用户的行为在他们实际活跃的时间段内是有意义的。因此，习惯上考虑活动窗口，并根据这些窗口聚合点击和其他事件。

+   流数据分析：假设我们有一个像我们刚刚描述的系统，并且实时访问聚合的用户会话数据，我们可以希望实现什么？我们需要一个分析平台，允许我们应用算法并从这些数据中获得见解。

Spark 解决这些问题的提议是其 Spark Streaming 模块，我们将在下文简要介绍。使用 Spark Streaming，我们将构建一个应用程序，至少可以模拟生成和聚合事件，然后应用我们研究的模式挖掘算法到事件流中。

# Spark Streaming 模块

在这里没有足够的时间对 Spark Streaming 进行深入介绍，但至少我们可以涉及一些关键概念，提供一些示例，并为更高级的主题提供一些指导。

Spark Streaming 是 Spark 的流数据处理模块，它确实具备我们在前面列表中解释的所有属性：它是一个高度容错、可扩展和高吞吐量的系统，用于处理和分析实时数据流。它的 API 是 Spark 本身的自然扩展，许多可用于 RDD 和 DataFrame 的工具也适用于 Spark Streaming。

Spark Streaming 应用程序的核心抽象是“DStream”的概念，它代表“离散流”。为了解释这个术语，我们经常将数据流想象为连续的事件流，当然，这是一个理想化的想法，因为我们所能测量的只是离散的事件。无论如何，这连续的数据流将进入我们的系统，为了进一步处理它，我们将其离散化为不相交的数据批次。这个离散数据批次流在 Spark Streaming 中被实现为 DStream，并且在内部被实现为一系列 RDD。

以下图表概述了 Spark Streaming 的数据流和转换：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00148.jpeg)

图 2：输入数据被馈入 Spark Streaming，它将这个流离散化为所谓的 DStream。然后，这些 RDD 序列可以通过 Spark 和其任何模块进一步转换和处理。

正如图表所示，数据通过输入数据流进入 Spark Streaming。这些数据可以从许多不同的来源产生和摄入，我们将在后面进一步讨论。我们称生成事件的系统为 Spark Streaming 可以处理的“来源”。输入 DStreams 通过这些来源的“接收器”从来源获取数据。一旦创建了输入 DStream，它可以通过丰富的 API 进行处理，这个 API 允许进行许多有趣的转换。将 DStreams 视为 RDD 的序列或集合，并通过与 Spark 核心中 RDD 非常接近的接口对其进行操作是一个很好的思维模型。例如，map-reduce 和 filter 等操作也适用于 DStreams，并且可以将相应功能从单个 RDD 转移到 RDD 序列。我们将更详细地讨论所有这些内容，但首先让我们转向一个基本示例。

作为开始使用 Spark Streaming 的第一个示例，让我们考虑以下情景。假设我们已经从先前加载了 MSNBC 数据集，并从中计算出了前缀跨度模型（`psModel`）。这个模型是用来自单日用户活动的数据拟合的，比如昨天的数据。今天，新的用户活动事件进来了。我们将创建一个简单的 Spark Streaming 应用程序，其中包含一个基本的源，精确地生成用户数据，其模式与我们在 MSNBC 数据中的模式相同；也就是说，我们得到了包含 1 到 17 之间数字的空格分隔字符串。然后，我们的应用程序将接收这些事件并从中创建`DStream`。然后，我们可以将我们的前缀跨度模型应用于`DStream`的数据，以找出新输入到系统中的序列是否确实是根据`psModel`频繁的序列。

首先，我们需要创建一个所谓的`StreamingContext`API，按照惯例，它将被实例化为`ssc`。假设我们从头开始启动一个应用程序，我们创建以下上下文：

```scala
import org.apache.spark.streaming.{Seconds, StreamingContext}
import org.apache.spark.{SparkConf, SparkContext}

val conf = new SparkConf()
  .setAppName("MSNBC data first streaming example")
  .setMaster("local[2]")
val sc = new SparkContext(conf)
val ssc = new StreamingContext(sc, batchDuration = Seconds(10))
```

如果您使用 Spark shell，除了第一行和最后一行之外，其他行都是不必要的，因为在这种情况下，您将已经提供了一个 Spark 上下文（`sc`）。我们包括后者的创建，因为我们的目标是一个独立的应用程序。创建一个新的`StreamingContext`API 需要两个参数，即`SparkContext`和一个名为`batchDuration`的参数，我们将其设置为 10 秒。批处理持续时间是告诉我们*如何离散化*`DStream`数据的值，通过指定流数据应该收集多长时间来形成`DStream`中的批处理，即序列中的一个 RDD。我们还想要吸引您的注意的另一个细节是，通过设置`local[2]`，Spark 主节点设置为两个核心。由于我们假设您是在本地工作，将至少分配两个核心给应用程序是很重要的。原因是一个线程将用于接收输入数据，而另一个线程将空闲以处理数据。在更高级的应用程序中，如果有更多的接收器，您需要为每个接收器保留一个核心。

接下来，我们基本上重复了前缀跨度模型的部分，以完善这个应用程序。与之前一样，序列是从本地文本文件加载的。请注意，这次我们假设文件在项目的资源文件夹中，但您可以选择将其存储在任何位置：

```scala
val transactions: RDD[Array[Int]] = sc.textFile("src/main/resources/msnbc990928.seq") map { line =>
  line.split(" ").map(_.toInt)
}
val trainSequences = transactions.map(_.map(Array(_))).cache()
val prefixSpan = new PrefixSpan().setMinSupport(0.005).setMaxPatternLength(15)
val psModel = prefixSpan.run(trainSequences)
val freqSequences = psModel.freqSequences.map(_.sequence).collect()
```

在前面计算的最后一步中，我们在主节点上收集所有频繁序列，并将它们存储为`freqSequences`。我们这样做的原因是要将这些数据与传入的数据进行比较，以查看新数据的序列是否与当前模型（`psModel`）相对频繁。不幸的是，与 MLlib 中的许多算法不同，Spark 中的三个可用的模式挖掘模型都不是在训练后接受新数据的，因此我们必须自己使用`freqSequences`进行比较。

接下来，我们最终可以创建一个`String`类型的`DStream`对象。为此，我们在流处理上下文中调用`socketTextStream`，这将允许我们从运行在`localhost`端口`8000`上的服务器上接收数据，监听 TCP 套接字：

```scala
val rawSequences: DStream[String] = ssc.socketTextStream("localhost", 8000)
```

我们称之为`rawSequences`的数据是通过该连接接收的，离散为 10 秒的间隔。在讨论*如何实际发送数据*之前，让我们先继续处理一旦接收到数据的示例。请记住，输入数据的格式与之前相同，因此我们需要以完全相同的方式对其进行预处理，如下所示：

```scala
val sequences: DStream[Array[Array[Int]]] = rawSequences
 .map(line => line.split(" ").map(_.toInt))
 .map(_.map(Array(_)))
```

我们在这里使用的两个`map`操作在原始 MSNBC 数据上在结构上与之前相同，但请记住，这次`map`具有不同的上下文，因为我们使用的是 DStreams 而不是 RDDs。定义了`sequences`，一个`Array[Array[Int]]`类型的 RDD 序列，我们可以使用它与`freqSequences`进行匹配。我们通过迭代 sequences 中的每个 RDD，然后再次迭代这些 RDD 中包含的每个数组来做到这一点。接下来，我们计算`freqSequences`中相应数组的出现频率，如果找到了，我们打印出与`array`对应的序列确实是频繁的：

```scala
print(">>> Analyzing new batch of data")
sequences.foreachRDD(
 rdd => rdd.foreach(
   array => {
     println(">>> Sequence: ")
     println(array.map(_.mkString("[", ", ", "]")).mkString("[", ", ", "]"))
     freqSequences.count(_.deep == array.deep) match {
       case count if count > 0 => println("is frequent!")
       case _ => println("is not frequent.")
     }
   }
 )
)
print(">>> done")
```

请注意，在前面的代码中，我们需要比较数组的深层副本，因为嵌套数组不能直接比较。更准确地说，可以检查它们是否相等，但结果将始终为 false。

完成转换后，应用程序接收端唯一剩下的事情就是实际告诉它开始监听传入的数据：

```scala
ssc.start()
ssc.awaitTermination()
```

通过流上下文`ssc`，我们告诉应用程序启动并等待其终止。请注意，在我们特定的上下文中，以及对于这种类型的大多数其他应用程序，我们很少想要终止程序。按设计，该应用程序旨在作为*长时间运行的作业*，因为原则上，我们希望它无限期地监听和分析新数据。当然，会有维护的情况，但我们也可能希望定期使用新获取的数据更新（重新训练）`psModel`。

我们已经看到了一些关于 DStreams 的操作，并建议您参考最新的 Spark Streaming 文档（[`spark.apache.org/docs/latest/streaming-programming-guide.html`](http://spark.apache.org/docs/latest/streaming-programming-guide.html)）以获取更多详细信息。基本上，许多（功能性）编程功能在基本的 Scala 集合上都是可用的，我们也从 RDD 中知道，它们也可以无缝地转移到 DStreams。举几个例子，这些是`filter`、`flatMap`、`map`、`reduce`和`reduceByKey`。其他类似 SQL 的功能，如 cogroup、`count`、`countByValue`、`join`或`union`，也都可以使用。我们将在第二个例子中看到一些更高级的功能。

现在我们已经涵盖了接收端，让我们简要讨论一下如何为我们的应用程序创建数据源。从命令行通过 TCP 套接字发送输入数据的最简单方法之一是使用*Netcat*，它适用于大多数操作系统，通常是预安装的。要在本地端口`8000`上启动 Netcat，在与您的 Spark 应用程序或 shell 分开的终端中运行以下命令：

```scala
nc -lk 8000
```

假设您已经启动了用于接收数据的 Spark Streaming 应用程序，现在我们可以在 Netcat 终端窗口中输入新的序列，并通过按*Enter*键确认每个序列。例如，在*10 秒内*输入以下四个序列：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00149.jpeg)

你会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00150.jpeg)

如果你打字速度很慢，或者在 10 秒窗口快要结束时开始打字，输出可能会分成更多部分。看看实际的输出，你会发现经常讨论的*首页*和*新闻*，由类别 1 和 2 表示，是频繁的。此外，由于 23 不是原始数据集中包含的序列项，它不能是频繁的。最后，序列<4, 5>显然也不频繁，这是我们以前不知道的。

选择 Netcat 作为本例的示例是一个自然的选择，但在严肃的生产环境中，你永远不会看到它用于这个目的。一般来说，Spark Streaming 有两种类型的可用源：基本和高级。基本源还可以是 RDD 队列和其他自定义源，除了文件流，前面的例子就是代表。在高级源方面，Spark Streaming 有许多有趣的连接器可供选择：Kafka、Kinesis、Flume 和高级自定义源。这种广泛的高级源的多样性使其成为将 Spark Streaming 作为生产组件并入其他基础架构组件的吸引力所在。

退后几步，考虑一下我们通过讨论这个例子所取得的成就，你可能会倾向于说，除了介绍 Spark Streaming 本身并与数据生产者和接收者一起工作之外，应用程序本身并没有解决我们之前提到的许多问题。这种批评是有效的，在第二个例子中，我们希望解决我们方法中的以下剩余问题：

+   我们的 DStreams 的输入数据与我们的离线数据具有相同的结构，也就是说，它已经针对用户进行了预聚合，这并不是非常现实的。

+   除了两次对`map`的调用和一次对`foreachRDD`的调用之外，我们在操作 DStreams 方面并没有看到太多功能和附加值

+   我们没有对数据流进行任何分析，只是将它们与预先计算的模式列表进行了检查

为了解决这些问题，让我们稍微重新定义我们的示例设置。这一次，让我们假设一个事件由一个用户点击一个站点来表示，其中每个站点都属于 1-17 中的一个类别，就像以前一样。现在，我们不可能模拟一个完整的生产环境，所以我们做出了简化的假设，即每个唯一的用户已经被分配了一个 ID。有了这些信息，让我们假设事件以用户 ID 和此点击事件的类别组成的键值对的形式出现。

有了这个设置，我们必须考虑如何对这些事件进行聚合，以生成序列。为此，我们需要在给定的*窗口*中为每个用户 ID 收集数据点。在原始数据集中，这个窗口显然是一整天，但根据应用程序的不同，选择一个更小的窗口可能是有意义的。如果我们考虑用户浏览他最喜欢的在线商店的情景，点击和其他事件可能会影响他或她当前的购买欲望。因此，在在线营销和相关领域做出的一个合理假设是将感兴趣的窗口限制在大约 20-30 分钟，即所谓的*用户会话*。为了让我们更快地看到结果，我们将在我们的应用程序中使用一个更小的 20 秒窗口。我们称之为**窗口长度**。

现在我们知道了我们想要从给定时间点分析数据的时间跨度，我们还必须定义*多久*我们想要进行聚合步骤，我们将其称为*滑动间隔*。一个自然的选择是将两者都设置为相同的时间，导致不相交的聚合窗口，即每 20 秒。然而，选择一个更短的 10 秒滑动窗口也可能很有趣，这将导致每 10 秒重叠的聚合数据。以下图表说明了我们刚刚讨论的概念：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00151.jpeg)

图 3：将 DStream 转换为另一个的窗口操作的可视化。在这个例子中，Spark Streaming 应用程序的批处理持续时间设置为 10 秒。用于对数据批次进行转换的窗口长度为 40 秒，我们每 20 秒进行一次窗口操作，导致每次重叠 20 秒，并得到一个以 20 秒为一块的 DStream。

要将这些知识转化为具体示例，我们假设事件数据的形式为*键:值*，也就是说，这样的一个事件可能是`137: 2`，意味着 ID 为`137`的用户点击了一个类别为*新闻*的页面。为了处理这些事件，我们必须修改我们的预处理如下：

```scala
val rawEvents: DStream[String] = ssc.socketTextStream("localhost", 9999)
val events: DStream[(Int, String)] = rawEvents.map(line => line.split(": "))
 .map(kv => (kv(0).toInt, kv(1)))
```

有了这些键值对，我们现在可以着手进行必要的聚合，以便按用户 ID 对事件进行分组。如前所述，我们通过在给定的 20 秒窗口上进行聚合，并设置 10 秒的滑动间隔来实现这一点：

```scala
val duration = Seconds(20)
val slide = Seconds(10)

val rawSequencesWithIds: DStream[(Int, String)] = events
  .reduceByKeyAndWindow((v1: String, v2: String) => v1 + " " + v2, duration, slide)
val rawSequences = rawSequencesWithIds.map(_.2)
// remainder as in previous example
```

在前面的代码中，我们使用了更高级的 DStreams 操作，即`reduceByKeyAndWindow`，其中我们指定了键值对的值的聚合函数，以及窗口持续时间和滑动间隔。在计算的最后一步中，我们剥离了用户 ID，使`rawSequences`的结构与之前的示例相同。这意味着我们已成功将我们的示例转换为在未处理的事件上运行，并且它仍将检查我们基线模型的频繁序列。我们不会展示此应用程序输出的更多示例，但我们鼓励您尝试一下这个应用程序，并看看如何对键值对进行聚合。

为了结束这个示例和本章，让我们再看一种有趣的聚合事件数据的方法。假设我们想要动态计算某个 ID 在事件流中出现的频率，也就是说，用户生成了多少次页面点击。我们已经定义了我们之前的`events` DStream，所以我们可以按照以下方式处理计数：

```scala
val countIds = events.map(e => (e._1, 1))
val counts: DStream[(Int, Int)] = countIds.reduceByKey(_ + _)
```

在某种程度上，这符合我们的意图；它计算了 ID 的事件数量。但是，请注意，返回的是一个 DStream，也就是说，我们实际上没有在流式窗口之间进行聚合，而只是在 RDD 序列内进行聚合。为了在整个事件流中进行聚合，我们需要从一开始就跟踪计数状态。Spark Streaming 提供了一个用于此目的的 DStreams 方法，即`updateStateByKey`。通过提供`updateFunction`，它可以使用当前状态和新值作为输入，并返回更新后的状态。让我们看看它在实践中如何为我们的事件计数工作：

```scala
def updateFunction(newValues: Seq[Int], runningCount: Option[Int]): Option[Int] = {
  Some(runningCount.getOrElse(0) + newValues.sum)
}
val runningCounts = countIds.updateStateByKeyInt
```

我们首先定义了我们的更新函数本身。请注意，`updateStateByKey`的签名要求我们返回一个`Option`，但实质上，我们只是计算状态和传入值的运行总和。接下来，我们为`updateStateByKey`提供了一个`Int`类型的签名和先前创建的`updateFunction`方法。这样做，我们就得到了我们最初想要的聚合。

总结一下，我们介绍了事件聚合、DStreams 上的两个更复杂的操作（`reduceByKeyAndWindow`和`updateStateByKey`），并使用这个示例在流中计算了事件的数量。虽然这个示例在所做的事情上仍然很简单，但我们希望为读者提供了更高级应用的良好入口点。例如，可以扩展这个示例以计算事件流上的移动平均值，或者改变它以在每个窗口基础上计算频繁模式。

# 总结

在本章中，我们介绍了一类新的算法，即频繁模式挖掘应用，并向您展示了如何在实际场景中部署它们。我们首先讨论了模式挖掘的基础知识以及可以使用这些技术解决的问题。特别是，我们看到了如何在 Spark 中实现三种可用的算法，即 FP-growth、关联规则和前缀跨度。作为我们应用的运行示例，我们使用了 MSNBC 提供的点击流数据，这也帮助我们在质量上比较了这些算法。

接下来，我们介绍了 Spark Streaming 的基本术语和入口点，并考虑了一些实际场景。我们首先讨论了如何首先部署和评估频繁模式挖掘算法与流上下文。之后，我们解决了从原始流数据中聚合用户会话数据的问题。为此，我们必须找到一种解决方案来模拟提供点击数据作为流事件。
